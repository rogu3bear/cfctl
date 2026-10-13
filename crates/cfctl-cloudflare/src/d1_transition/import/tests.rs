#![allow(clippy::expect_used, clippy::unwrap_used, clippy::wildcard_imports)]
use super::*;

#[tokio::test]
async fn native_upload_sends_one_complete_file_without_statement_or_format_rewriting() {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    let sql = b"-- comment; retain  spaces\nCREATE INDEX \"exact\"\n ON \"rows\" (\n  \"value\" /* inner; comment */\n );\nINSERT INTO \"rows\" VALUES('semi;colon');\n".to_vec();
    let expected = sql.clone();
    let etag = hex::encode(Md5::digest(&sql));
    let response_etag = etag.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut received = Vec::new();
        let (header_end, length) = loop {
            let mut chunk = [0; 4096];
            let n = stream.read(&mut chunk).await.unwrap();
            assert!(n > 0);
            received.extend_from_slice(&chunk[..n]);
            if let Some(index) = received.windows(4).position(|v| v == b"\r\n\r\n") {
                let header = std::str::from_utf8(&received[..index]).unwrap();
                assert!(header.starts_with("PUT /immutable.sql "));
                assert!(!header.to_ascii_lowercase().contains("authorization:"));
                let length = header
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .map(|n| n.parse::<usize>().unwrap())
                    })
                    .unwrap();
                break (index + 4, length);
            }
        };
        while received.len() < header_end + length {
            let mut chunk = [0; 4096];
            let n = stream.read(&mut chunk).await.unwrap();
            assert!(n > 0);
            received.extend_from_slice(&chunk[..n]);
        }
        assert_eq!(&received[header_end..], expected);
        stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nETag: \"{response_etag}\"\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
        drop(stream);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
    });
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let (status, headers) = bounded_d1_import_upload(
        &client,
        format!("http://{address}/immutable.sql").parse().unwrap(),
        sql,
        5,
        65536,
    )
    .await
    .unwrap();
    assert!(status.is_success());
    assert_eq!(
        validated_d1_import_upload_etag(&headers, &etag).unwrap(),
        etag
    );
    server.await.unwrap();
}

#[test]
fn native_completion_keeps_bookmark_private_and_requires_durable_receipt_identity() {
    let binding = ValidatedImport {
        checkpoint: crate::d1_transition::tests::prepared(),
        database_id: "11111111-1111-4111-8111-111111111111".into(),
        execution_length: 10,
        continuation: None,
    };
    let mut writes = 0;
    let terminal = complete(
        &binding,
        "private-before",
        "private-final",
        &mut |progress| {
            writes += 1;
            assert_eq!(progress.at_bookmark.as_deref(), Some("private-before"));
            assert_eq!(progress.terminal_bookmark.as_deref(), Some("private-final"));
            let receipt = progress.terminal.as_ref().unwrap();
            let body = serde_json::to_string(receipt).unwrap();
            assert!(!body.contains("private-before"));
            assert!(!body.contains("private-final"));
            Ok(format!("sha256:{}", "f".repeat(64)))
        },
    )
    .unwrap();
    assert_eq!(writes, 1);
    assert!(matches!(terminal, Terminal::Committed { .. }));
    assert!(
        complete(&binding, "private-before", "private-final", &mut |_| Ok(
            "invalid".into()
        ))
        .is_err()
    );
    assert!(
        complete(
            &binding,
            "private-before",
            "private-final",
            &mut |_| Err(())
        )
        .is_err()
    );
}

#[tokio::test]
async fn failed_checkpoint_prevents_even_native_import_init() {
    let executor = Executor::new(reqwest::Client::new(), "http://127.0.0.1:1").unwrap();
    let binding = ValidatedImport {
        checkpoint: crate::d1_transition::tests::prepared(),
        database_id: "11111111-1111-4111-8111-111111111111".into(),
        execution_length: 10,
        continuation: None,
    };
    let credential = AuthCredential::Bearer {
        token: "synthetic-token".into(),
    };
    let result = executor
        .execute_transition_import(
            &binding,
            b"SELECT 1;\n",
            &credential,
            |_| Err(()),
            |_| panic!("no transport progress expected"),
        )
        .await
        .unwrap_err();
    assert_eq!(result.classification, "prepared_checkpoint_not_durable");
}

#[tokio::test]
async fn native_provider_failure_is_uncertain_and_not_retried_or_called_rollback() {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buffer = [0_u8; 8192];
        let n = stream.read(&mut buffer).await.unwrap();
        let request = String::from_utf8_lossy(&buffer[..n]);
        assert!(request.starts_with("POST /accounts/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/d1/database/11111111-1111-4111-8111-111111111111/import "));
        let body = r#"{"success":false,"errors":[{"code":1,"message":"synthetic rejection"}],"messages":[],"result":null}"#;
        stream.write_all(format!("HTTP/1.1 503 Service Unavailable\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",body.len(),body).as_bytes()).await.unwrap();
        drop(stream);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(200), listener.accept())
                .await
                .is_err()
        );
    });
    let executor = Executor::new(reqwest::Client::new(), &format!("http://{address}")).unwrap();
    let binding = ValidatedImport {
        checkpoint: crate::d1_transition::tests::prepared(),
        database_id: "11111111-1111-4111-8111-111111111111".into(),
        execution_length: 10,
        continuation: None,
    };
    let credential = AuthCredential::Bearer {
        token: "synthetic-token".into(),
    };
    let terminal = executor
        .execute_transition_import(
            &binding,
            b"SELECT 1;\n",
            &credential,
            |_| Ok(()),
            |_| Ok(format!("sha256:{}", "f".repeat(64))),
        )
        .await
        .unwrap();
    assert_eq!(terminal.stage, Stage::Uncertain);
    server.await.unwrap();
}
