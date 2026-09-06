use super::*;
use crate::{Executor, parse_response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn signed_url(host: &str) -> String {
    format!(
        "https://{host}/bucket/import.sql?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=fixture&X-Amz-Date=20260905T000000Z&X-Amz-Expires=60&X-Amz-SignedHeaders=host&X-Amz-Signature={}",
        "a".repeat(64)
    )
}

#[test]
fn delegated_r2_account_is_allowed_but_authority_confusion_is_not() {
    let customer = "a".repeat(32);
    let storage = format!("{}.r2.cloudflarestorage.com", "b".repeat(32));
    assert!(
        classify_d1_import_upload_url(
            &signed_url(&storage),
            &customer,
            ".r2.cloudflarestorage.com"
        )
        .is_ok()
    );
    for host in [
        format!("{storage}:443"),
        format!("{storage}:8443"),
        format!("{storage}.evil.example"),
        format!("bucket.{storage}"),
        format!("{storage}."),
        format!("user:pass@{storage}"),
        format!("{storage}@localhost"),
        storage.replace('.', "%2e"),
        "127.0.0.1".to_owned(),
        "[::1]".to_owned(),
        format!("{}.r2.cloudflarestorage.com", "b".repeat(31)),
        format!("{}.r2.cloudflarestorage.com", "g".repeat(32)),
    ] {
        assert!(
            classify_d1_import_upload_url(
                &signed_url(&host),
                &customer,
                ".r2.cloudflarestorage.com"
            )
            .is_err(),
            "{host}"
        );
    }
    assert!(
        classify_d1_import_upload_url(&signed_url(&storage), &customer, ".evil.example").is_err()
    );
}

fn response(status: &str, final_bookmark: Value) -> CloudflareResponseV1 {
    parse_response(
        200,
        &serde_json::json!({"success":true,"result":{
            "type":"import","status":status,"success":true,"at_bookmark":"start",
            "result":{"final_bookmark":final_bookmark}
        }}),
        None,
        None,
    )
}

#[test]
fn ingest_completion_requires_validated_terminal_bookmark_and_preserves_pending() {
    assert_eq!(
        classify_d1_import_ingest_response(&response("complete", Value::from("finish"))),
        Ok(D1ImportIngestOutcome::Complete {
            at_bookmark: "start".to_owned(),
            final_bookmark: "finish".to_owned()
        })
    );
    for malformed in [
        Value::Null,
        Value::from(""),
        Value::from(4),
        serde_json::json!({"value":"finish"}),
    ] {
        assert!(classify_d1_import_ingest_response(&response("complete", malformed)).is_err());
    }
    for status in ["active", "pending"] {
        assert_eq!(
            classify_d1_import_ingest_response(&response(status, Value::Null)),
            Ok(D1ImportIngestOutcome::InProgress("start".to_owned()))
        );
    }
    for pointer in ["/success", "/result/success"] {
        let mut invalid = response("complete", Value::from("finish"));
        if pointer == "/success" {
            invalid.success = false;
        } else {
            invalid.result["success"] = Value::Bool(false);
        }
        assert!(classify_d1_import_ingest_response(&invalid).is_err());
    }
    let mut invalid = response("complete", Value::from("finish"));
    invalid.result["at_bookmark"] = Value::Null;
    assert!(classify_d1_import_ingest_response(&invalid).is_err());
}

#[tokio::test]
async fn executor_upload_client_never_forwards_provider_headers_or_follows_redirects() {
    let destination = TcpListener::bind("127.0.0.1:0").await.expect("destination");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("upload");
    let address = listener.local_addr().expect("address");
    let redirect = destination.local_addr().expect("redirect address");
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("upload request");
        let mut bytes = Vec::new();
        loop {
            let mut chunk = [0_u8; 1024];
            let n = socket.read(&mut chunk).await.expect("request bytes");
            assert!(n > 0);
            bytes.extend_from_slice(&chunk[..n]);
            if bytes.ends_with(b"reviewed SQL") {
                break;
            }
        }
        socket.write_all(format!("HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{redirect}/stolen\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await.expect("redirect response");
        bytes
    });
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        reqwest::header::HeaderValue::from_static("Bearer fixture-provider-secret"),
    );
    let provider_client = reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .expect("provider client");
    let executor =
        Executor::new(provider_client, "https://api.cloudflare.com/client/v4").expect("executor");
    let (status, _) = bounded_d1_import_upload(
        &executor.upload_client,
        format!("http://{address}/upload")
            .parse()
            .expect("local URL"),
        b"reviewed SQL".to_vec(),
        2,
        1024,
    )
    .await
    .expect("upload response");
    assert_eq!(status.as_u16(), 307);
    let request = String::from_utf8(server.await.expect("server")).expect("request");
    assert!(request.starts_with("PUT /upload HTTP/1.1"));
    assert!(!request.to_lowercase().contains("authorization"));
    assert!(!request.contains("fixture-provider-secret"));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), destination.accept())
            .await
            .is_err()
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "terminal persistence regression checks both durable receipts and all source bindings"
)]
fn completed_ingest_persists_terminal_source_target_and_bookmarks_before_return() {
    let capability = cfctl_core::CapabilityV1::new(
        "d1-import-database",
        "Import",
        "POST",
        "/accounts/{account_id}/d1/database/{database_id}/import",
    );
    let input = CallInput {
        body: Some(serde_json::json!({"pre_recovery_anchor_operation_id":"anchor"})),
        ..CallInput::default()
    };
    let mut plan = PlanV1::draft(
        "fixture",
        "account",
        "sha256:catalog",
        capability,
        serde_json::json!({}),
    )
    .expect("plan");
    plan.input = serde_json::to_value(&input).expect("input");
    plan.targets = serde_json::json!({"adapter":{"approved_mln_import":{
        "migration_id":"0001", "target":{"account_id":"account","database_id":"database"},
        "source_authority_hash":"sha256:authority"
    }}});
    let source = D1ImportSourceBinding {
        migration_id: "0001".to_owned(),
        basename: "0001.sql".to_owned(),
        bytes: 12,
        sha256: "a".repeat(64),
        md5: "b".repeat(32),
        account_id: "account".to_owned(),
        database_id: "database".to_owned(),
    };
    let ingest = response("complete", Value::from("finish"));
    let D1ImportIngestOutcome::Complete {
        at_bookmark,
        final_bookmark,
    } = classify_d1_import_ingest_response(&ingest).expect("complete")
    else {
        panic!("must finish")
    };
    let mut checkpoints = Vec::new();
    let mut persist = |checkpoint: &D1ImportCheckpointV1| {
        checkpoints.push(serde_json::to_value(checkpoint).expect("checkpoint"));
        Ok(())
    };
    persist_import_response(
        &mut persist,
        &plan,
        "ingest_response",
        &ingest,
        None,
        None,
        true,
    )
    .expect("ingest persisted");
    let completed = persist_import_complete(
        &mut persist,
        &mut plan,
        &input,
        &source,
        &ingest,
        "ingest",
        &at_bookmark,
        &final_bookmark,
    )
    .expect("completion persisted");
    assert_eq!(checkpoints.len(), 2);
    assert_eq!(
        checkpoints[0]["receipt"]["effect"],
        "d1_import_ingest_accepted"
    );
    assert_eq!(checkpoints[0]["receipt"]["no_replay"], true);
    assert_eq!(
        checkpoints[0]["receipt"]["result"]["result"]["final_bookmark"],
        "finish"
    );
    assert_eq!(checkpoints[1]["step"], "provider_complete");
    let terminal = &checkpoints[1]["receipt"];
    assert_eq!(terminal["response_action"], "ingest");
    assert_eq!(terminal["at_bookmark"], "start");
    assert_eq!(terminal["final_bookmark"], "finish");
    assert_eq!(
        terminal["source_sha256"],
        format!("sha256:{}", source.sha256)
    );
    assert_eq!(
        terminal["target"],
        serde_json::json!({"account_id":"account","database_id":"database"})
    );
    assert_eq!(
        terminal["plan_input_hash"],
        hash_value(&plan.input).expect("hash")
    );
    assert_eq!(completed.result["_cfctl"], *terminal);
    let mut fail = |_checkpoint: &D1ImportCheckpointV1| Err("disk full".to_owned());
    assert!(
        persist_import_complete(
            &mut fail,
            &mut plan,
            &input,
            &source,
            &ingest,
            "ingest",
            &at_bookmark,
            &final_bookmark
        )
        .is_err()
    );
}

#[tokio::test]
async fn post_upload_state_machine_never_polls_complete_rejected_or_unpersisted_ingest() {
    for scenario in ["complete", "malformed", "error", "disk_failure", "pending"] {
        let capability = cfctl_core::CapabilityV1::new(
            "d1-import-database",
            "Import",
            "POST",
            "/accounts/{account_id}/d1/database/{database_id}/import",
        );
        let input = CallInput::default();
        let mut plan = PlanV1::draft(
            "fixture",
            "account",
            "sha256:catalog",
            capability,
            serde_json::json!({}),
        )
        .expect("plan");
        plan.input = serde_json::to_value(&input).expect("input");
        plan.targets = serde_json::json!({"adapter":{"approved_mln_import":{
            "migration_id":"0001","target":{"account_id":"account","database_id":"database"},"source_authority_hash":"sha256:authority"
        }}});
        let source = D1ImportSourceBinding {
            migration_id: "0001".to_owned(),
            basename: "0001.sql".to_owned(),
            bytes: 12,
            sha256: "a".repeat(64),
            md5: "b".repeat(32),
            account_id: "account".to_owned(),
            database_id: "database".to_owned(),
        };
        let requests = std::cell::RefCell::new(Vec::new());
        let sender = |body: Value| {
            let action = body["action"].as_str().expect("action").to_owned();
            requests.borrow_mut().push(body);
            let result = match (scenario, action.as_str()) {
                ("pending", "ingest") => response("pending", Value::Null),
                ("malformed", _) => response("complete", Value::Null),
                ("error", _) => {
                    let mut value = response("error", Value::Null);
                    value.result["success"] = Value::Bool(false);
                    value
                }
                _ => response("complete", Value::from("finish")),
            };
            std::future::ready(Ok(result))
        };
        let mut checkpoints = Vec::new();
        let mut persist = |value: &D1ImportCheckpointV1| {
            checkpoints.push(value.step.clone());
            if scenario == "disk_failure" {
                Err("disk full".to_owned())
            } else {
                Ok(())
            }
        };
        let result = finish_d1_import(
            &mut plan,
            &input,
            &source,
            "uploaded.sql",
            3,
            sender,
            &mut persist,
        )
        .await;
        let requests = requests.into_inner();
        assert_eq!(
            requests[0],
            serde_json::json!({"action":"ingest","filename":"uploaded.sql","etag":source.md5})
        );
        assert_eq!(
            requests.len(),
            if scenario == "pending" { 2 } else { 1 },
            "{scenario}"
        );
        if matches!(scenario, "complete" | "pending") {
            assert_eq!(
                result.expect("completed").result["_cfctl"]["final_bookmark"],
                "finish"
            );
            assert_eq!(
                checkpoints.last().map(String::as_str),
                Some("provider_complete")
            );
        } else {
            assert!(result.is_err(), "{scenario}");
        }
        if scenario == "pending" {
            assert_eq!(
                requests[1],
                serde_json::json!({"action":"poll","current_bookmark":"start"})
            );
        }
    }
}
