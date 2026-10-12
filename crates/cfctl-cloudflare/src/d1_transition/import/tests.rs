#![allow(clippy::expect_used, clippy::unwrap_used, clippy::wildcard_imports)]
use super::*;

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
