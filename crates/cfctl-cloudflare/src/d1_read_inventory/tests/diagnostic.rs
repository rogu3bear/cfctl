use super::*;

#[tokio::test]
async fn diagnostic_retains_error_bytes_and_dispatches_only_the_exact_registered_query_once() {
    let fixture = inventory();
    let query = fixture.queries[1].clone();
    let (capability, input) = prepared(fixture);
    let validated = validate(&capability, &input).expect("validated");
    let body = json!({"success":false,"errors":[{"code":7500,"message":"private SQL detail"}]});
    let service = server(vec![(400, body.clone())]).await;
    let executor = crate::Executor::new(reqwest::Client::new(), &service.url).expect("executor");
    let credential = AuthCredential::Bearer {
        token: "synthetic-token".into(),
    };
    let result = executor
        .diagnose_registered_d1_query(&validated, &query.id, &credential)
        .await
        .expect("diagnostic");
    assert_eq!(result.http_status, 400);
    assert_eq!(result.provider_error_codes, vec![7500]);
    assert_eq!(result.bytes, serde_json::to_vec(&body).expect("bytes"));
    assert!(!result.truncated);
    assert_eq!(service.count.load(Ordering::SeqCst), 1);
    assert_eq!(
        *service.requests.lock().expect("requests"),
        vec![json!({"sql":query.sql,"params":[]})]
    );
    service.handle.abort();
}

#[tokio::test]
async fn diagnostic_refuses_unknown_query_without_network_and_bounds_private_bytes() {
    let fixture = inventory();
    let query_id = fixture.queries[1].id.clone();
    let (capability, input) = prepared(fixture);
    let validated = validate(&capability, &input).expect("validated");
    let service = server(vec![(
        400,
        json!({"errors":[{"message":"x".repeat(70_000)}]}),
    )])
    .await;
    let executor = crate::Executor::new(reqwest::Client::new(), &service.url).expect("executor");
    let credential = AuthCredential::Bearer {
        token: "synthetic-token".into(),
    };
    assert!(
        executor
            .diagnose_registered_d1_query(&validated, "unregistered", &credential)
            .await
            .is_err()
    );
    assert_eq!(service.count.load(Ordering::SeqCst), 0);
    let result = executor
        .diagnose_registered_d1_query(&validated, &query_id, &credential)
        .await
        .expect("bounded result");
    assert!(result.truncated);
    assert!(result.bytes.len() <= 65_536);
    assert!(result.provider_error_codes.is_empty());
    assert_eq!(service.count.load(Ordering::SeqCst), 1);
    service.handle.abort();
}
