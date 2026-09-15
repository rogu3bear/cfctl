use super::*;

fn private_inventory_value() -> Value {
    let mut value = serde_json::to_value(inventory()).expect("inventory");
    value["query_count"] = json!(1);
    value["witness_count"] = json!(1);
    value["queries"]
        .as_array_mut()
        .expect("queries")
        .truncate(1);
    value["queries"][0]["output"]["min_rows"] = json!(1);
    value["queries"][0]["output"]["max_rows"] = json!(1);
    value["queries"][0]["output"]["max_bytes"] = json!(131_072);
    value["queries"][0]["output"]["columns"][0]["max_bytes"] = json!(65_536);
    value["limits"]["max_total_response_bytes"] = json!(131_072);
    value["limits"]["max_elapsed_seconds"] = json!(30);
    value["private_output"] = json!({"schema_version":1,
        "format":"workspace_d1_private_read_v1", "max_artifact_bytes":262_144,
        "require_primary":true});
    value
}

#[test]
fn committed_private_disposition_admits_only_its_separate_finite_limits() {
    let value = private_inventory_value();
    let private: D1ReadInventoryV1 =
        serde_json::from_value(value.clone()).expect("committed private disposition");
    validate_inventory(&private).expect("bounded private inventory");
    let mut ordinary = value;
    ordinary
        .as_object_mut()
        .expect("object")
        .remove("private_output");
    let ordinary = serde_json::from_value(ordinary).expect("ordinary inventory");
    assert!(
        validate_inventory(&ordinary).is_err(),
        "ordinary ceilings unchanged"
    );
}

#[test]
fn private_disposition_rejects_unknown_fields_and_all_bound_widening() {
    for (pointer, value) in [
        ("/private_output/schema_version", json!(2)),
        ("/private_output/format", json!("other")),
        ("/private_output/require_primary", json!(false)),
        ("/private_output/max_artifact_bytes", json!(8_388_609)),
        ("/private_output/max_artifact_bytes", json!(0)),
        ("/limits/max_elapsed_seconds", json!(31)),
        ("/limits/max_total_response_bytes", json!(131_073)),
        ("/queries/0/output/max_rows", json!(2)),
        ("/queries/0/output/min_rows", json!(0)),
        ("/queries/0/output/columns/0/max_bytes", json!(131_073)),
    ] {
        let mut fixture = private_inventory_value();
        *fixture.pointer_mut(pointer).expect("field") = value;
        let decoded = serde_json::from_value(fixture).expect("typed inventory");
        assert!(validate_inventory(&decoded).is_err(), "{pointer}");
    }
    let mut fixture = private_inventory_value();
    fixture["private_output"]["unexpected"] = json!(true);
    assert!(serde_json::from_value::<D1ReadInventoryV1>(fixture).is_err());
}

fn private_provider(text: &str) -> Value {
    let mut body = provider(json!([{"name":text}]));
    body["result"][0]["meta"]["served_by_primary"] = json!(true);
    body
}

#[tokio::test]
async fn ordinary_and_private_execution_cannot_substitute_for_each_other() {
    let credential = AuthCredential::Bearer {
        token: "synthetic-token".into(),
    };
    let executor =
        crate::Executor::new(reqwest::Client::new(), "http://127.0.0.1:1").expect("executor");
    let (capability, input) =
        prepared(serde_json::from_value(private_inventory_value()).expect("private"));
    let private = validate(&capability, &input).expect("validated private");
    assert!(
        executor
            .execute_d1_read_inventory(&private, &credential, || Ok(()))
            .await
            .is_err()
    );
    let (capability, input) = prepared(inventory());
    let ordinary = validate(&capability, &input).expect("validated ordinary");
    assert!(
        executor
            .execute_private_d1_read(&ordinary, &credential, || Ok(()))
            .await
            .is_err()
    );
}

async fn private_run(
    body: String,
    status: u16,
    extra: &str,
    bound: u64,
    seconds: u64,
    delay_ms: u64,
) -> super::super::PrivateD1ReadResult {
    let mut fixture = private_inventory_value();
    fixture["queries"][0]["output"]["max_bytes"] = json!(bound);
    fixture["queries"][0]["output"]["columns"][0]["max_bytes"] = json!(bound);
    fixture["limits"]["max_total_response_bytes"] = json!(bound);
    fixture["limits"]["max_elapsed_seconds"] = json!(seconds);
    let (capability, input) = prepared(serde_json::from_value(fixture).expect("inventory"));
    let validated = validate(&capability, &input).expect("validated");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("address");
    let response = format!(
        "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n{body}",
        body.len()
    );
    let count = Arc::new(AtomicUsize::new(0));
    let counted = count.clone();
    let handle = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        counted.fetch_add(1, Ordering::SeqCst);
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            headers.push(socket.read_u8().await.expect("header"));
        }
        assert!(
            String::from_utf8_lossy(&headers)
                .to_ascii_lowercase()
                .contains("accept-encoding: identity")
        );
        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        let _ = socket.write_all(response.as_bytes()).await;
        while let Ok(Ok((_socket, _))) =
            tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept()).await
        {
            counted.fetch_add(1, Ordering::SeqCst);
        }
    });
    let executor = crate::Executor::new(reqwest::Client::new(), &format!("http://{address}"))
        .expect("executor");
    let result = executor
        .execute_private_d1_read(
            &validated,
            &AuthCredential::Bearer {
                token: "synthetic-token".into(),
            },
            || Ok(()),
        )
        .await
        .expect("private read");
    handle.await.expect("server");
    assert_eq!(count.load(Ordering::SeqCst), 1, "no retry or redirect");
    result
}

#[tokio::test]
async fn private_transport_preserves_inner_text_and_qualifies_the_complete_envelope() {
    let text = " {\"duplicate\":1,\"duplicate\":2, malformed 雪 ";
    let body = private_provider(text);
    let result = private_run(body.to_string(), 200, "", 131_072, 30, 0).await;
    assert_eq!(result.classification, "complete_read");
    assert_eq!(result.provider_response, Some(body));
}

#[tokio::test]
async fn private_transport_rejects_duplicates_trailing_primary_encoding_and_failure_bodies() {
    let good = private_provider("PRIVATE_ROW_CANARY").to_string();
    let mut absent = private_provider("PRIVATE_ROW_CANARY");
    absent["result"][0]["meta"]
        .as_object_mut()
        .expect("meta")
        .remove("served_by_primary");
    let mut replica = private_provider("PRIVATE_ROW_CANARY");
    replica["result"][0]["meta"]["served_by_primary"] = json!(false);
    for (body, status, extra) in [
        (good.replacen('{', "{\"success\":true,", 1), 200, ""),
        (
            good.replace("\"name\":", "\"name\":\"duplicate\",\"name\":"),
            200,
            "",
        ),
        (format!("{good} {{}}"), 200, ""),
        (absent.to_string(), 200, ""),
        (replica.to_string(), 200, ""),
        (good.clone(), 200, "Content-Encoding: gzip\r\n"),
        (good.clone(), 503, ""),
        (good, 302, "Location: /retry\r\n"),
    ] {
        let result = private_run(body, status, extra, 131_072, 30, 0).await;
        assert!(result.provider_response.is_none());
        assert!(!result.classification.contains("PRIVATE_ROW_CANARY"));
    }
}

#[tokio::test]
async fn private_response_limit_counts_framing_multibyte_and_the_first_excess_byte() {
    let good = private_provider(&"雪\\\"".repeat(1000)).to_string();
    let bytes = good.len() as u64;
    assert!(
        private_run(good.clone(), 200, "", bytes, 30, 0)
            .await
            .provider_response
            .is_some()
    );
    assert!(
        private_run(format!("{good} "), 200, "", bytes, 30, 0)
            .await
            .provider_response
            .is_none()
    );
    assert!(
        private_run(good, 200, "", bytes - 1, 30, 0)
            .await
            .provider_response
            .is_none()
    );
}

#[tokio::test]
async fn private_deadline_cancels_delayed_response_without_retry() {
    let result = private_run(
        private_provider("private").to_string(),
        200,
        "",
        131_072,
        1,
        1200,
    )
    .await;
    assert_eq!(result.classification, "run_deadline");
    assert!(result.provider_response.is_none());
}
