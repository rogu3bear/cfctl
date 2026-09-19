#![allow(clippy::expect_used, clippy::unwrap_used)]
use super::*;
use rusqlite::Connection;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
};

fn snapshot(versions: usize) -> Value {
    let revisions: Vec<_> = (1..=versions)
        .map(|version| {
            json!({"version":version,
        "schema_version":1,"fields_json":r#"{"hero":{"segments":[{"kind":"text","text":"private owner value"},{"kind":"bold","text":"emphasis"},{"kind":"break"}]}}"#,
        "saved_by":"private owner@example.invalid","saved_at":"2026-09-14"})
        })
        .collect();
    json!({"site_content":[{"id":1,"schema_version":1,"version":versions,
        "fields_json":r#"{"hero":{"segments":[{"kind":"text","text":"private owner value"},{"kind":"bold","text":"emphasis"},{"kind":"break"}]}}"#,
        "updated_by":"private owner@example.invalid","updated_at":"2026-09-14"}],
        "site_content_revisions":revisions})
}

fn response(snapshot: &Value) -> Vec<u8> {
    serde_json::to_vec(
        &json!({"success":true,"errors":[],"result":[{"success":true,
        "meta":{"changed_db":false},"results":[{"snapshot_json":snapshot.to_string()}]}]}),
    )
    .unwrap()
}

#[test]
fn complete_private_history_and_boundaries() {
    for count in [0, 2, MAX_REVISIONS] {
        let read = decode(&response(&snapshot(count))).unwrap();
        assert_eq!(read.metadata()["revision_count"], count);
        let private: Value = serde_json::from_slice(read.private_bytes()).unwrap();
        assert_eq!(private["snapshot"], snapshot(count));
        let public = read.metadata().to_string();
        for secret in [
            "owner@example",
            "private owner value",
            "saved_at",
            "fields_json",
        ] {
            assert!(!public.contains(secret));
        }
    }
    assert!(decode(&response(&snapshot(MAX_REVISIONS + 1))).is_err());
    assert!(
        decode(&vec![
            b' ';
            usize::try_from(MAX_RESPONSE_BYTES).unwrap() + 1
        ])
        .is_err()
    );
}

#[test]
fn rejects_incomplete_drifted_or_malformed_history_without_echo() {
    for pointer in [
        "/site_content/0/id",
        "/site_content/0/schema_version",
        "/site_content/0/version",
        "/site_content_revisions/1/version",
        "/site_content_revisions/0/schema_version",
    ] {
        let mut data = snapshot(2);
        *data.pointer_mut(pointer).unwrap() = json!(55);
        assert!(decode(&response(&data)).is_err(), "{pointer}");
    }
    for pointer in [
        "/site_content/0/fields_json",
        "/site_content/0/updated_by",
        "/site_content/0/updated_at",
        "/site_content_revisions/1/fields_json",
        "/site_content_revisions/1/saved_by",
        "/site_content_revisions/1/saved_at",
    ] {
        let mut data = snapshot(2);
        *data.pointer_mut(pointer).unwrap() = json!("secret malformed changed data");
        let error = decode(&response(&data)).err().unwrap().to_string();
        assert!(!error.contains("secret malformed"));
    }
    let mut data = snapshot(2);
    data["site_content_revisions"]
        .as_array_mut()
        .unwrap()
        .remove(0);
    assert!(decode(&response(&data)).is_err());
    for bytes in [
        b"private invalid json".to_vec(),
        b"{\"success\":false}".to_vec(),
    ] {
        assert!(decode(&bytes).is_err());
    }
    let mut provider: Value = serde_json::from_slice(&response(&snapshot(2))).unwrap();
    provider["result"][0]["meta"]["changed_db"] = json!(true);
    assert!(decode(&serde_json::to_vec(&provider).unwrap()).is_err());
}

#[test]
fn fixed_statement_reads_only_two_tables_and_keeps_order() {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch("CREATE TABLE site_content(id INTEGER PRIMARY KEY,schema_version INTEGER,version INTEGER,fields_json TEXT,updated_by TEXT,updated_at TEXT);
        CREATE TABLE site_content_revisions(version INTEGER PRIMARY KEY,schema_version INTEGER,fields_json TEXT,saved_by TEXT,saved_at TEXT);
        INSERT INTO site_content VALUES(1,1,2,'{}','owner','today');
        INSERT INTO site_content_revisions VALUES(2,1,'{}','owner','today'),(1,1,'{}','owner','yesterday');").unwrap();
    db.authorizer(Some(|ctx: rusqlite::hooks::AuthContext<'_>| {
        use rusqlite::hooks::{AuthAction, Authorization};
        match ctx.action {
            AuthAction::Read {
                table_name: "site_content" | "site_content_revisions",
                ..
            }
            | AuthAction::Select
            | AuthAction::Function { .. } => Authorization::Allow,
            _ => Authorization::Deny,
        }
    }))
    .unwrap();
    let statement = db.prepare(SNAPSHOT_SQL).unwrap();
    assert!(statement.readonly());
    let serialized: String = db.query_row(SNAPSHOT_SQL, [], |r| r.get(0)).unwrap();
    let data: Value = serde_json::from_str(&serialized).unwrap();
    assert_eq!(data["site_content_revisions"][0]["version"], 1);
    assert_eq!(data["site_content_revisions"][1]["version"], 2);
    decode(&response(&data)).unwrap();
    assert_eq!(db.total_changes(), 3);
}

async fn server(
    body: Vec<u8>,
    status: u16,
    delay: Duration,
) -> (Executor, tokio::task::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        loop {
            let mut buffer = [0; 4096];
            let count = stream.read(&mut buffer).await.unwrap();
            bytes.extend_from_slice(&buffer[..count]);
            if let Some(split) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&bytes[..split]).to_ascii_lowercase();
                let length: usize = headers
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length: "))
                    .unwrap()
                    .parse()
                    .unwrap();
                if bytes.len() >= split + 4 + length {
                    break;
                }
            }
        }
        tokio::time::sleep(delay).await;
        let header = format!(
            "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(header.as_bytes()).await;
        let _ = stream.write_all(&body).await;
        String::from_utf8(bytes).unwrap()
    });
    (
        Executor::new(
            reqwest::Client::new(),
            &format!("http://{address}/client/v4"),
        )
        .unwrap(),
        task,
    )
}

#[tokio::test]
async fn executor_sends_exact_read_once_and_redacts_provider_failures() {
    let credential = AuthCredential::Bearer {
        token: "synthetic-token".into(),
    };
    let (executor, task) = server(response(&snapshot(2)), 200, Duration::ZERO).await;
    executor
        .read_farm_content_snapshot(&credential)
        .await
        .unwrap();
    let request = task.await.unwrap();
    assert!(request.starts_with(&format!(
        "POST /client/v4/accounts/{ACCOUNT_ID}/d1/database/{DATABASE_ID}/query "
    )));
    let body: Value = serde_json::from_str(request.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert_eq!(body, json!({"sql":SNAPSHOT_SQL,"params":[]}));
    for status in [302, 403, 500] {
        let (executor, task) =
            server(b"private echoed data".to_vec(), status, Duration::ZERO).await;
        let error = executor
            .read_farm_content_snapshot(&credential)
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(!error.contains("private echoed"));
        task.await.unwrap();
    }
    let (executor, task) = server(
        response(&snapshot(2)),
        200,
        Duration::from_secs(TIMEOUT_SECONDS + 5),
    )
    .await;
    let before = std::time::Instant::now();
    assert!(
        executor
            .read_farm_content_snapshot(&credential)
            .await
            .is_err()
    );
    assert!(before.elapsed() < Duration::from_secs(TIMEOUT_SECONDS + 3));
    task.abort();
    let global = AuthCredential::GlobalKey {
        email: "private".into(),
        key: "private".into(),
    };
    assert!(executor.read_farm_content_snapshot(&global).await.is_err());
}
