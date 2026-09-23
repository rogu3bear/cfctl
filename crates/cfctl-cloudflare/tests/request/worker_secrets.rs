use super::{
    AsyncReadExt, AsyncWriteExt, AuthCredential, Executor, PlanStatus, TcpListener, json,
    workers_secret_put_plan,
};

#[tokio::test]
async fn handoff_secret_put_never_retries_version_creating_requests() {
    for status in [429, 503] {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let mut requests = Vec::new();
            loop {
                let Ok(Ok((mut socket, _))) =
                    tokio::time::timeout(std::time::Duration::from_secs(2), listener.accept())
                        .await
                else {
                    break;
                };
                let mut bytes = vec![0; 8192];
                let count = socket.read(&mut bytes).await.expect("request");
                requests.push(String::from_utf8_lossy(&bytes[..count]).to_string());
                let body = r#"{"success":false,"result":null,"errors":[]}"#;
                let wire = format!(
                    "HTTP/1.1 {status} Failed\r\nContent-Type: application/json\r\nContent-Length: {}\r\nRetry-After: 0\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(wire.as_bytes()).await.expect("response");
                if requests.len() == 2 {
                    break;
                }
            }
            requests
        });
        let mut plan = workers_secret_put_plan(
            json!({"name":"DATABASE_TOKEN","type":"secret_text","text":"synthetic-secret"}),
        );
        plan.status = PlanStatus::Consumed;
        let executor = Executor::new(
            reqwest::Client::new(),
            &format!("http://{address}/client/v4"),
        )
        .expect("executor")
        .with_max_retries(1);
        let hash = plan.catalog_hash.clone();
        let response = executor
            .execute_consumed_plan(
                &mut plan,
                &hash,
                &AuthCredential::Bearer {
                    token: "test-token".into(),
                },
            )
            .await
            .expect("response");
        assert_eq!(response.status, status);
        assert_eq!(plan.status, PlanStatus::RectificationRequired);
        let requests = server.await.expect("server");
        assert_eq!(requests.len(), 1);
        assert!(requests[0].starts_with(
            "PUT /client/v4/accounts/account-1/workers/scripts/example-worker/secrets "
        ));
        assert!(!requests[0].to_ascii_lowercase().contains("idempotency-key"));
    }
}

#[tokio::test]
async fn handoff_secret_put_transport_failure_preserves_uncertainty() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("address");
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut bytes = [0; 8192];
        let count = socket.read(&mut bytes).await.expect("request");
        assert!(count > 0, "connection dropped only after request arrived");
    });
    let mut plan = workers_secret_put_plan(
        json!({"name":"DATABASE_TOKEN","type":"secret_text","text":"synthetic-secret"}),
    );
    plan.status = PlanStatus::Consumed;
    let hash = plan.catalog_hash.clone();
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");
    assert!(
        executor
            .execute_consumed_plan(
                &mut plan,
                &hash,
                &AuthCredential::Bearer {
                    token: "test-token".into()
                }
            )
            .await
            .is_err()
    );
    assert_eq!(plan.status, PlanStatus::RectificationRequired);
    server.await.expect("server");
}
