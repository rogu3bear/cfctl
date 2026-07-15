#![allow(clippy::expect_used, clippy::unwrap_used)]

use cfctl_auth::AuthCredential;
use cfctl_cloudflare::{
    CallInput, CloudflareError, CloudflareResponseV1, Executor, RequestBuilder,
};
use cfctl_core::{
    CapabilityV1, CreatedCollectionResourceContractV1, CreatedResourceContractV1,
    DeletedResourceContractV1, PlanStatus, PlanV1, SamePathReadContractV1, SelectorV1,
    UpdatedResourceContractV1,
};
use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[test]
fn request_builder_resolves_path_and_query_selectors_without_leaking_auth() {
    let mut capability = CapabilityV1::new(
        "dns-records-list",
        "List DNS records",
        "GET",
        "/zones/{zone_id}/dns_records",
    );
    capability.selectors = vec![];
    let request = RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("valid base URL")
        .build(
            &capability,
            &CallInput {
                selectors: json!({"zone_id":"zone a"}),
                query: json!({"name":"www.example.com"}),
                body: None,
                if_none_match: Some("etag-1".to_owned()),
                ..CallInput::default()
            },
        )
        .expect("request should build");

    assert_eq!(
        request.url.as_str(),
        "https://api.cloudflare.com/client/v4/zones/zone%20a/dns_records?name=www.example.com"
    );
    assert!(request.headers.get("authorization").is_none());
    assert_eq!(
        request
            .headers
            .get("if-none-match")
            .and_then(|value| value.to_str().ok()),
        Some("etag-1")
    );
}

#[test]
fn request_builder_sends_only_catalog_declared_header_selectors() {
    let mut capability = CapabilityV1::new(
        "r2-get-bucket",
        "Get R2 bucket",
        "GET",
        "/accounts/{account_id}/r2/buckets/{bucket_name}",
    );
    capability.selectors = vec![SelectorV1 {
        name: "cf-r2-jurisdiction".to_owned(),
        location: "header".to_owned(),
        required: false,
        value_type: "unknown".to_owned(),
        description: None,
    }];
    let request = RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("valid base URL")
        .build(
            &capability,
            &CallInput {
                selectors: json!({
                    "account_id":"account-1",
                    "bucket_name":"bucket-1",
                    "cf-r2-jurisdiction":"eu",
                    "authorization":"must-not-be-forwarded"
                }),
                ..CallInput::default()
            },
        )
        .expect("declared header should build");

    assert_eq!(
        request
            .headers
            .get("cf-r2-jurisdiction")
            .and_then(|value| value.to_str().ok()),
        Some("eu")
    );
    assert!(request.headers.get("authorization").is_none());

    let error = RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("valid base URL")
        .build(
            &capability,
            &CallInput {
                selectors: json!({
                    "account_id":"account-1",
                    "bucket_name":"bucket-1",
                    "cf-r2-jurisdiction":true
                }),
                ..CallInput::default()
            },
        )
        .expect_err("R2 jurisdiction must remain a string")
        .to_string();
    assert!(error.contains("cf-r2-jurisdiction"));
}

#[test]
fn request_builder_rejects_missing_required_or_reserved_header_selectors() {
    let mut capability = CapabilityV1::new("header-read", "Header read", "GET", "/header-read");
    capability.selectors = vec![SelectorV1 {
        name: "Tus-Resumable".to_owned(),
        location: "header".to_owned(),
        required: true,
        value_type: "string".to_owned(),
        description: None,
    }];
    let builder = RequestBuilder::new("https://api.cloudflare.com/client/v4").expect("builder");
    let missing = builder
        .build(&capability, &CallInput::default())
        .expect_err("required header must fail closed");
    assert!(
        matches!(missing, CloudflareError::MissingHeaderSelector(name) if name == "Tus-Resumable")
    );

    capability.selectors[0].name = "Authorization".to_owned();
    let reserved = builder
        .build(
            &capability,
            &CallInput {
                selectors: json!({"Authorization":"must-not-be-forwarded"}),
                ..CallInput::default()
            },
        )
        .expect_err("auth headers must be reserved");
    assert!(
        matches!(reserved, CloudflareError::ReservedHeaderSelector(name) if name == "Authorization")
    );
}

#[test]
fn mutating_request_requires_a_consumable_approved_plan() {
    let capability = CapabilityV1::new(
        "dns-records-delete",
        "Delete DNS record",
        "DELETE",
        "/zones/{zone_id}/dns_records/{record_id}",
    );
    let result = RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("valid base URL")
        .build(
            &capability,
            &CallInput {
                selectors: json!({"zone_id":"z","record_id":"r"}),
                query: json!({}),
                body: None,
                ..CallInput::default()
            },
        );
    assert!(result.is_err());
}

#[test]
fn unchecked_request_validates_required_body_shape_from_pinned_schema() {
    let mut capability = CapabilityV1::new("record-create", "Create record", "POST", "/records");
    capability.request_schema = Some(json!({
        "type": "object",
        "required": ["name"],
        "properties": {"name": {"type": "string"}, "ttl": {"type": "integer"}},
        "x-cfctl-body-required": true
    }));
    let builder = RequestBuilder::new("https://api.cloudflare.com/client/v4").expect("builder");
    assert!(
        builder
            .build_unchecked(&capability, &CallInput::default())
            .is_err()
    );
    let wrong = CallInput {
        body: Some(json!({"name": "www", "ttl": "automatic"})),
        ..CallInput::default()
    };
    assert!(builder.build_unchecked(&capability, &wrong).is_err());
    let valid = CallInput {
        body: Some(json!({"name": "www", "ttl": 300})),
        ..CallInput::default()
    };
    assert!(builder.build_unchecked(&capability, &valid).is_ok());
}

#[tokio::test]
async fn executor_retries_rate_limits_and_applies_only_the_selected_credential() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let mut requests = Vec::new();
        for attempt in 0..2 {
            let (mut stream, _) = listener.accept().await.expect("accept request");
            let mut buffer = vec![0_u8; 8192];
            let read = stream.read(&mut buffer).await.expect("read request");
            requests.push(String::from_utf8_lossy(&buffer[..read]).to_string());
            let (status, body) = if attempt == 0 {
                (
                    "429 Too Many Requests",
                    r#"{"success":false,"errors":[{"code":10000,"message":"retry"}]}"#,
                )
            } else {
                (
                    "200 OK",
                    r#"{"success":true,"result":[{"id":"zone-1"}],"errors":[]}"#,
                )
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nRetry-After: 0\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write response");
        }
        requests
    });
    let capability = CapabilityV1::new("zones-list", "List zones", "GET", "/zones");
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");
    let response = executor
        .execute_read(
            &capability,
            &CallInput::default(),
            &AuthCredential::Bearer {
                token: "selected-token".to_owned(),
            },
        )
        .await
        .expect("eventual response");
    assert!(response.success);
    let requests = server.await.expect("fake server joins");
    assert_eq!(requests.len(), 2);
    assert!(
        requests
            .iter()
            .all(|request| request.contains("authorization: Bearer selected-token"))
    );
    assert!(
        requests
            .iter()
            .all(|request| !request.contains("x-auth-key"))
    );
}

#[tokio::test]
async fn executor_refuses_a_plan_that_was_not_durably_marked_consumed() {
    let capability = CapabilityV1::new("zones-delete", "Delete zone", "DELETE", "/zones/{zone_id}");
    let mut plan = PlanV1::draft(
        "profile",
        "account",
        "sha256:catalog",
        capability,
        json!({"zone_id":"zone"}),
    )
    .expect("draft plan");
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"zone_id":"zone"}),
        query: json!({}),
        body: None,
        ..CallInput::default()
    })
    .expect("input");
    plan.refresh_hash().expect("refresh hash");
    plan.approve(true, None).expect("approve");
    let executor = Executor::new(reqwest::Client::new(), "http://127.0.0.1:9").expect("executor");
    let error = executor
        .execute_consumed_plan(
            &mut plan,
            "sha256:catalog",
            &AuthCredential::Bearer {
                token: "token".to_owned(),
            },
        )
        .await
        .expect_err("unconsumed plan must fail before network");
    assert!(
        error
            .to_string()
            .contains("durably persisted consumed plan")
    );
}

#[tokio::test]
async fn executor_rejects_a_grafted_verifier_before_the_mutation_boundary() {
    let mut capability = CapabilityV1::new(
        "widgets-create",
        "Create widget",
        "POST",
        "/accounts/{account_id}/widgets",
    );
    capability.verification.strategy =
        "api_token_details_match_created_id_and_active_status".to_owned();
    let mut plan = PlanV1::draft(
        "profile",
        "account",
        "sha256:catalog",
        capability,
        json!({}),
    )
    .expect("draft plan");
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account"}),
        query: json!({}),
        body: Some(json!({"name":"test"})),
        ..CallInput::default()
    })
    .expect("input");
    plan.refresh_hash().expect("refresh hash");
    plan.approve(true, None).expect("approve");
    plan.mark_consumed().expect("consume");
    let executor = Executor::new(reqwest::Client::new(), "http://127.0.0.1:9").expect("executor");

    let error = executor
        .execute_consumed_plan(
            &mut plan,
            "sha256:catalog",
            &AuthCredential::Bearer {
                token: "token".to_owned(),
            },
        )
        .await
        .expect_err("unsupported verifier must fail before network");

    assert!(matches!(
        error,
        CloudflareError::UnsupportedVerificationStrategy(strategy)
            if strategy == "api_token_details_match_created_id_and_active_status"
    ));
}

#[tokio::test]
async fn executor_collects_all_cloudflare_result_pages() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let mut requests = Vec::new();
        for page in 1..=2 {
            let (mut stream, _) = listener.accept().await.expect("accept request");
            let mut buffer = vec![0_u8; 8192];
            let read = stream.read(&mut buffer).await.expect("read request");
            requests.push(String::from_utf8_lossy(&buffer[..read]).to_string());
            let body = format!(
                r#"{{"success":true,"result":[{{"id":"zone-{page}"}}],"errors":[],"result_info":{{"page":{page},"total_pages":2,"total_count":2}}}}"#
            );
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nETag: page-{page}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write response");
        }
        requests
    });
    let capability = CapabilityV1::new("zones-list", "List zones", "GET", "/zones");
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");
    let response = executor
        .execute_read(
            &capability,
            &CallInput::default(),
            &AuthCredential::Bearer {
                token: "token".to_owned(),
            },
        )
        .await
        .expect("paginated response");
    assert_eq!(response.result.as_array().expect("result array").len(), 2);
    assert_eq!(response.etag.as_deref(), Some("page-2"));
    let requests = server.await.expect("server joins");
    assert_eq!(requests.len(), 2);
    assert!(requests[1].contains("page=2"));
}

#[tokio::test]
async fn consumed_mutation_carries_plan_id_as_idempotency_key() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept request");
        let mut buffer = vec![0_u8; 8192];
        let read = stream.read(&mut buffer).await.expect("read request");
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let body = r#"{"success":true,"result":{"id":"record-1"},"errors":[]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCF-Ray: test-ray\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write response");
        request
    });
    let mut capability =
        CapabilityV1::new("zone-delete", "Delete zone", "DELETE", "/zones/{zone_id}");
    capability.verification.strategy = "same_resource_returns_not_found_after_delete".to_owned();
    capability.same_path_read = Some(SamePathReadContractV1 {
        path: "/zones/{zone_id}".to_owned(),
        read_capability_id: "zone-get".to_owned(),
        verified_response_fields: Vec::new(),
    });
    let mut plan = PlanV1::draft(
        "profile",
        "account",
        "sha256:catalog",
        capability,
        json!({}),
    )
    .expect("draft plan");
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"zone_id":"zone-1"}),
        query: json!({}),
        body: None,
        ..CallInput::default()
    })
    .expect("serialize input");
    plan.refresh_hash().expect("refresh hash");
    plan.approve(true, None).expect("approve");
    plan.mark_consumed().expect("consume");
    let operation_id = plan.operation_id.clone();
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");
    let response = executor
        .execute_consumed_plan(
            &mut plan,
            "sha256:catalog",
            &AuthCredential::Bearer {
                token: "token".to_owned(),
            },
        )
        .await
        .expect("mutation response");
    assert_eq!(response.cf_ray.as_deref(), Some("test-ray"));
    let request = server.await.expect("server joins");
    assert!(request.contains(&format!("idempotency-key: {operation_id}")));
}

#[tokio::test]
async fn account_token_creation_is_verified_by_id_and_active_readback() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let read = stream.read(&mut buffer).await.expect("read verification");
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let body = r#"{"success":true,"result":{"id":"token-1","status":"active"},"errors":[]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
        request
    });
    let plan = token_plan(
        "account-api-tokens-create-token",
        "POST",
        "/accounts/{account_id}/tokens",
        "api_token_details_match_created_id_and_active_status",
        json!({"account_id":"account-1"}),
    );
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"token-1","status":"active","value":"one-time-secret"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed);
    assert!(verification.basis.contains("token-1"));
    let request = server.await.expect("server joins");
    assert!(
        request.starts_with("GET /client/v4/accounts/account-1/tokens/token-1 "),
        "{request}"
    );
    assert!(request.contains("authorization: Bearer governing-token"));
}

#[tokio::test]
async fn account_token_revocation_is_verified_by_not_found_readback() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let read = stream.read(&mut buffer).await.expect("read verification");
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let body =
            r#"{"success":false,"result":null,"errors":[{"code":1001,"message":"not found"}]}"#;
        let response = format!(
            "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
        request
    });
    let plan = token_plan(
        "account-api-tokens-delete-token",
        "DELETE",
        "/accounts/{account_id}/tokens/{token_id}",
        "api_token_details_returns_not_found_after_revoke",
        json!({"account_id":"account-1", "token_id":"token-1"}),
    );
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"token-1"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed);
    let request = server.await.expect("server joins");
    assert!(
        request.starts_with("GET /client/v4/accounts/account-1/tokens/token-1 "),
        "{request}"
    );
}

#[tokio::test]
async fn dns_record_creation_is_verified_by_created_id_and_planned_fields() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let read = stream.read(&mut buffer).await.expect("read verification");
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let body = r#"{"success":true,"result":{"id":"record-1","type":"A","name":"www.example.com","content":"192.0.2.1","ttl":300},"errors":[]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
        request
    });
    let planned_fields = json!({
        "type":"A",
        "name":"www.example.com",
        "content":"192.0.2.1",
        "ttl":300
    });
    let plan = dns_record_plan(
        "dns-records-for-a-zone-create-dns-record",
        "POST",
        "/zones/{zone_id}/dns_records",
        "dns_record_details_match_created_id_and_planned_fields",
        json!({"zone_id":"zone-1"}),
        Some(planned_fields.clone()),
    );
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"record-1", "type":"A", "name":"www.example.com", "content":"192.0.2.1", "ttl":300}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed, "{}", verification.basis);
    let request = server.await.expect("server joins");
    assert!(
        request.starts_with("GET /client/v4/zones/zone-1/dns_records/record-1 "),
        "{request}"
    );
}

#[tokio::test]
async fn dns_record_deletion_is_verified_by_not_found_readback() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let read = stream.read(&mut buffer).await.expect("read verification");
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let body =
            r#"{"success":false,"result":null,"errors":[{"code":81044,"message":"not found"}]}"#;
        let response = format!(
            "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
        request
    });
    let plan = dns_record_plan(
        "dns-records-for-a-zone-delete-dns-record",
        "DELETE",
        "/zones/{zone_id}/dns_records/{dns_record_id}",
        "dns_record_details_returns_not_found_after_delete",
        json!({"zone_id":"zone-1", "dns_record_id":"record-1"}),
        None,
    );
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"record-1"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed, "{}", verification.basis);
    let request = server.await.expect("server joins");
    assert!(
        request.starts_with("GET /client/v4/zones/zone-1/dns_records/record-1 "),
        "{request}"
    );
}

#[tokio::test]
async fn exact_resource_deletion_is_verified_by_same_path_not_found_readback() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let read = stream.read(&mut buffer).await.expect("read verification");
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let body =
            r#"{"success":false,"result":null,"errors":[{"code":1001,"message":"not found"}]}"#;
        let response = format!(
            "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
        request
    });
    let mut plan = dns_record_plan(
        "widgets-delete",
        "DELETE",
        "/accounts/{account_id}/widgets/{widget_id}",
        "same_resource_returns_not_found_after_delete",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        None,
    );
    plan.capability.product = "R2 Bucket".to_owned();
    plan.capability.selectors.push(SelectorV1 {
        name: "cf-r2-jurisdiction".to_owned(),
        location: "header".to_owned(),
        required: false,
        value_type: "unknown".to_owned(),
        description: None,
    });
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({
            "account_id":"account-1",
            "widget_id":"widget-1",
            "cf-r2-jurisdiction":"eu"
        }),
        query: json!({}),
        body: None,
        if_match: Some("mutation-only-etag".to_owned()),
        ..CallInput::default()
    })
    .expect("input");
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"widget-1"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed, "{}", verification.basis);
    let request = server.await.expect("server joins");
    assert!(
        request.starts_with("GET /client/v4/accounts/account-1/widgets/widget-1 "),
        "{request}"
    );
    assert!(!request.contains("mutation-only"));
    assert!(request.contains("cf-r2-jurisdiction: eu\r\n"));
}

#[tokio::test]
async fn exact_resource_deletion_rejects_a_still_present_readback_without_echoing_values() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let _ = stream.read(&mut buffer).await.expect("read verification");
        let body = r#"{"success":true,"result":{"id":"secret-widget-id"},"errors":[]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
    });
    let plan = dns_record_plan(
        "widgets-delete",
        "DELETE",
        "/accounts/{account_id}/widgets/{widget_id}",
        "same_resource_returns_not_found_after_delete",
        json!({"account_id":"account-1", "widget_id":"secret-widget-id"}),
        None,
    );
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"secret-widget-id"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(!verification.passed);
    assert!(verification.basis.contains("readback HTTP 200"));
    assert!(!verification.basis.contains("secret-widget-id"));
    server.await.expect("server joins");
}

#[tokio::test]
async fn exact_resource_deletion_is_verified_by_complete_parent_collection_absence() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let mut requests = Vec::new();
        for page in 1..=2 {
            let (mut stream, _) = listener.accept().await.expect("accept verification");
            let mut buffer = vec![0_u8; 8192];
            let read = stream.read(&mut buffer).await.expect("read verification");
            requests.push(String::from_utf8_lossy(&buffer[..read]).to_string());
            let body = if page == 1 {
                r#"{"success":true,"result":[{"id":"widget-2"}],"result_info":{"page":1,"total_pages":2}}"#
            } else {
                r#"{"success":true,"result":[{"id":"widget-3"}],"result_info":{"page":2,"total_pages":2}}"#
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write verification");
        }
        requests
    });
    let mut plan = dns_record_plan(
        "widgets-delete",
        "DELETE",
        "/accounts/{account_id}/widgets/{widget_id}",
        "parent_collection_omits_deleted_resource_id",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        None,
    );
    plan.capability.deleted_resource = Some(DeletedResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        requires_page_number_completion: true,
    });
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"widget-1"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed, "{}", verification.basis);
    let requests = server.await.expect("server joins");
    assert!(requests[0].starts_with("GET /client/v4/accounts/account-1/widgets "));
    assert!(requests[1].starts_with("GET /client/v4/accounts/account-1/widgets?page=2 "));
    assert!(requests.iter().all(|request| !request.contains("widget-1")));
}

#[tokio::test]
async fn paginated_parent_collection_verification_requires_live_completion_metadata() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let _ = stream.read(&mut buffer).await.expect("read verification");
        let body = r#"{"success":true,"result":[{"id":"widget-2"}]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
    });
    let mut plan = dns_record_plan(
        "widgets-delete",
        "DELETE",
        "/accounts/{account_id}/widgets/{widget_id}",
        "parent_collection_omits_deleted_resource_id",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        None,
    );
    plan.capability.deleted_resource = Some(DeletedResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        requires_page_number_completion: true,
    });
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"widget-1"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(!verification.passed);
    assert!(verification.basis.contains("pagination complete=false"));
    assert!(verification.basis.contains("deleted identity absent=true"));
    server.await.expect("server joins");
}

#[tokio::test]
async fn parent_collection_verifier_rejects_a_present_deleted_identity_without_echoing_it() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let _ = stream.read(&mut buffer).await.expect("read verification");
        let body = r#"{"success":true,"result":[{"id":"secret-widget-id"}]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
    });
    let mut plan = dns_record_plan(
        "widgets-delete",
        "DELETE",
        "/accounts/{account_id}/widgets/{widget_id}",
        "parent_collection_omits_deleted_resource_id",
        json!({"account_id":"account-1", "widget_id":"secret-widget-id"}),
        None,
    );
    plan.capability.deleted_resource = Some(DeletedResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        requires_page_number_completion: false,
    });
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"secret-widget-id"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(!verification.passed);
    assert!(verification.basis.contains("deleted identity absent=false"));
    assert!(!verification.basis.contains("secret-widget-id"));
    server.await.expect("server joins");
}

#[tokio::test]
async fn exact_resource_update_is_verified_by_complete_parent_collection_fields() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let mut requests = Vec::new();
        for page in 1..=2 {
            let (mut stream, _) = listener.accept().await.expect("accept verification");
            let mut buffer = vec![0_u8; 8192];
            let read = stream.read(&mut buffer).await.expect("read verification");
            requests.push(String::from_utf8_lossy(&buffer[..read]).to_string());
            let body = if page == 1 {
                r#"{"success":true,"result":[{"id":"widget-2","name":"other","enabled":false}],"result_info":{"page":1,"total_pages":2}}"#
            } else {
                r#"{"success":true,"result":[{"id":"widget-1","name":"after","enabled":true}],"result_info":{"page":2,"total_pages":2}}"#
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write verification");
        }
        requests
    });
    let mut plan = dns_record_plan(
        "widgets-update",
        "PATCH",
        "/accounts/{account_id}/widgets/{widget_id}",
        "parent_collection_item_contains_planned_fields_after_update",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        Some(json!({"name":"after", "enabled":true})),
    );
    plan.capability.updated_resource = Some(UpdatedResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        verified_response_fields: vec!["enabled".to_owned(), "name".to_owned()],
        requires_page_number_completion: true,
    });
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed, "{}", verification.basis);
    let requests = server.await.expect("server joins");
    assert!(requests[0].starts_with("GET /client/v4/accounts/account-1/widgets "));
    assert!(requests[1].starts_with("GET /client/v4/accounts/account-1/widgets?page=2 "));
    assert!(requests.iter().all(|request| !request.contains("widget-1")));
}

#[tokio::test]
async fn parent_collection_update_rejects_field_drift_without_echoing_values() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let _ = stream.read(&mut buffer).await.expect("read verification");
        let body =
            r#"{"success":true,"result":[{"id":"widget-1","name":"unexpected-live-value"}]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
    });
    let mut plan = dns_record_plan(
        "widgets-update",
        "PATCH",
        "/accounts/{account_id}/widgets/{widget_id}",
        "parent_collection_item_contains_planned_fields_after_update",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        Some(json!({"name":"planned-secret-like-value"})),
    );
    plan.capability.updated_resource = Some(UpdatedResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
        requires_page_number_completion: false,
    });
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(!verification.passed);
    assert!(verification.basis.contains("planned fields match=false"));
    assert!(!verification.basis.contains("planned-secret-like-value"));
    assert!(!verification.basis.contains("unexpected-live-value"));
    server.await.expect("server joins");
}

#[tokio::test]
async fn parent_collection_update_rejects_unbound_fields_before_the_mutation_boundary() {
    let mut plan = dns_record_plan(
        "widgets-update",
        "PATCH",
        "/accounts/{account_id}/widgets/{widget_id}",
        "parent_collection_item_contains_planned_fields_after_update",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        Some(json!({"name":"planned"})),
    );
    plan.capability.updated_resource = Some(UpdatedResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
        requires_page_number_completion: false,
    });
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-1", "widget_id":"widget-1"}),
        query: json!({}),
        body: Some(json!({"name":"planned", "hidden":true})),
        ..CallInput::default()
    })
    .expect("input");
    plan.status = PlanStatus::Consumed;
    let input: CallInput = serde_json::from_value(plan.input.clone()).expect("input");
    let catalog_hash = plan.catalog_hash.clone();
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .execute_consumed_plan_with_input(
            &mut plan,
            &catalog_hash,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
            &input,
        )
        .await
        .expect_err("unbound field must fail before network execution")
        .to_string();

    assert!(error.contains("outside the hash-bound collection readback fields"));
    assert_eq!(plan.status, PlanStatus::Consumed);
}

#[tokio::test]
async fn parent_collection_update_rejects_query_controls_before_the_mutation_boundary() {
    let mut plan = dns_record_plan(
        "widgets-update",
        "PATCH",
        "/accounts/{account_id}/widgets/{widget_id}",
        "parent_collection_item_contains_planned_fields_after_update",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        Some(json!({"name":"planned"})),
    );
    plan.capability.updated_resource = Some(UpdatedResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
        requires_page_number_completion: false,
    });
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-1", "widget_id":"widget-1"}),
        query: json!({"mode":"must-not-cross-boundary"}),
        body: Some(json!({"name":"planned"})),
        ..CallInput::default()
    })
    .expect("input");
    plan.status = PlanStatus::Consumed;
    let input: CallInput = serde_json::from_value(plan.input.clone()).expect("input");
    let catalog_hash = plan.catalog_hash.clone();
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .execute_consumed_plan_with_input(
            &mut plan,
            &catalog_hash,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
            &input,
        )
        .await
        .expect_err("query controls must fail before network execution")
        .to_string();

    assert!(error.contains("query controls outside the hash-bound collection readback contract"));
    assert!(!error.contains("must-not-cross-boundary"));
    assert_eq!(plan.status, PlanStatus::Consumed);
}

#[tokio::test]
async fn parent_collection_delete_rejects_broadening_inputs_before_the_mutation_boundary() {
    let mut plan = dns_record_plan(
        "widgets-delete",
        "DELETE",
        "/accounts/{account_id}/widgets/{widget_id}",
        "parent_collection_omits_deleted_resource_id",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        None,
    );
    plan.capability.deleted_resource = Some(DeletedResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        requires_page_number_completion: false,
    });
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-1", "widget_id":"widget-1"}),
        query: json!({"cascade":true}),
        body: Some(json!({"reason":"must-not-cross-boundary"})),
        ..CallInput::default()
    })
    .expect("input");
    plan.status = PlanStatus::Consumed;
    let input: CallInput = serde_json::from_value(plan.input.clone()).expect("input");
    let catalog_hash = plan.catalog_hash.clone();
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .execute_consumed_plan_with_input(
            &mut plan,
            &catalog_hash,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
            &input,
        )
        .await
        .expect_err("broadening inputs must fail before network execution")
        .to_string();

    assert!(error.contains("outside the hash-bound collection readback contract"));
    assert!(!error.contains("must-not-cross-boundary"));
    assert_eq!(plan.status, PlanStatus::Consumed);
}

#[tokio::test]
async fn created_resource_is_verified_through_a_complete_parent_collection() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let mut requests = Vec::new();
        for page in 1..=2 {
            let (mut stream, _) = listener.accept().await.expect("accept verification");
            let mut buffer = vec![0_u8; 8192];
            let read = stream.read(&mut buffer).await.expect("read verification");
            requests.push(String::from_utf8_lossy(&buffer[..read]).to_string());
            let body = if page == 1 {
                r#"{"success":true,"result":[{"id":"widget-other","name":"other","enabled":false}],"result_info":{"page":1,"total_pages":2}}"#
            } else {
                r#"{"success":true,"result":[{"id":"secret-created-id","name":"planned-secret-like-name","enabled":true}],"result_info":{"page":2,"total_pages":2}}"#
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write verification");
        }
        requests
    });
    let mut plan = dns_record_plan(
        "widgets-create",
        "POST",
        "/accounts/{account_id}/widgets",
        "parent_collection_contains_created_resource_id_and_planned_fields",
        json!({"account_id":"account-1"}),
        Some(json!({"name":"planned-secret-like-name", "enabled":true})),
    );
    plan.capability.created_collection_resource = Some(CreatedCollectionResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        delete_capability_id: "widgets-delete".to_owned(),
        verified_response_fields: vec!["enabled".to_owned(), "name".to_owned()],
        requires_page_number_completion: true,
    });
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-1"}),
        query: json!({}),
        body: Some(json!({"name":"planned-secret-like-name", "enabled":true})),
        if_match: Some("mutation-etag".to_owned()),
        ..CallInput::default()
    })
    .expect("input");
    let apply = CloudflareResponseV1 {
        status: 201,
        success: true,
        result: json!({"id":"secret-created-id"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed, "{}", verification.basis);
    let requests = server.await.expect("server joins");
    assert!(requests[0].starts_with("GET /client/v4/accounts/account-1/widgets "));
    assert!(requests[1].starts_with("GET /client/v4/accounts/account-1/widgets?page=2 "));
    assert!(requests.iter().all(|request| {
        !request.contains("secret-created-id")
            && !request.contains("planned-secret-like-name")
            && !request.contains("mutation_mode")
            && !request.contains("mutation-etag")
    }));
}

#[tokio::test]
async fn parent_collection_create_rejects_field_drift_without_echoing_values() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let _ = stream.read(&mut buffer).await.expect("read verification");
        let body = r#"{"success":true,"result":[{"id":"secret-created-id","name":"unexpected-live-value"}]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
    });
    let mut plan = dns_record_plan(
        "widgets-create",
        "POST",
        "/accounts/{account_id}/widgets",
        "parent_collection_contains_created_resource_id_and_planned_fields",
        json!({"account_id":"account-1"}),
        Some(json!({"name":"planned-secret-like-name"})),
    );
    plan.capability.created_collection_resource = Some(CreatedCollectionResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        delete_capability_id: "widgets-delete".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
        requires_page_number_completion: false,
    });
    let apply = CloudflareResponseV1 {
        status: 201,
        success: true,
        result: json!({"id":"secret-created-id"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(!verification.passed);
    assert!(verification.basis.contains("planned fields match=false"));
    assert!(!verification.basis.contains("secret-created-id"));
    assert!(!verification.basis.contains("planned-secret-like-name"));
    assert!(!verification.basis.contains("unexpected-live-value"));
    server.await.expect("server joins");
}

#[tokio::test]
async fn parent_collection_create_rejects_unbound_fields_before_the_mutation_boundary() {
    let mut plan = dns_record_plan(
        "widgets-create",
        "POST",
        "/accounts/{account_id}/widgets",
        "parent_collection_contains_created_resource_id_and_planned_fields",
        json!({"account_id":"account-1"}),
        Some(json!({"hidden":true})),
    );
    plan.capability.created_collection_resource = Some(CreatedCollectionResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        delete_capability_id: "widgets-delete".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
        requires_page_number_completion: false,
    });
    plan.status = PlanStatus::Consumed;
    let input: CallInput = serde_json::from_value(plan.input.clone()).expect("input");
    let catalog_hash = plan.catalog_hash.clone();
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .execute_consumed_plan_with_input(
            &mut plan,
            &catalog_hash,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
            &input,
        )
        .await
        .expect_err("unbound field must fail before network execution")
        .to_string();

    assert!(error.contains("outside the hash-bound collection readback fields"));
    assert_eq!(plan.status, PlanStatus::Consumed);
}

#[tokio::test]
async fn exact_resource_update_is_verified_by_same_path_planned_fields() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let read = stream.read(&mut buffer).await.expect("read verification");
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let body = r#"{"success":true,"result":{"id":"widget-1","name":"after","settings":{"enabled":true,"mode":"strict"},"server_default":"kept"},"errors":[]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
        request
    });
    let mut plan = dns_record_plan(
        "widgets-update",
        "PATCH",
        "/accounts/{account_id}/widgets/{widget_id}",
        "same_resource_contains_planned_fields_after_update",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        Some(json!({
            "name":"after",
            "settings":{"enabled":true,"mode":"strict"}
        })),
    );
    plan.capability.product = "R2 Object".to_owned();
    plan.capability.selectors.push(SelectorV1 {
        name: "cf-r2-jurisdiction".to_owned(),
        location: "header".to_owned(),
        required: false,
        value_type: "unknown".to_owned(),
        description: None,
    });
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({
            "account_id":"account-1",
            "widget_id":"widget-1",
            "cf-r2-jurisdiction":"fedramp"
        }),
        query: json!({}),
        body: Some(json!({
            "name":"after",
            "settings":{"enabled":true,"mode":"strict"}
        })),
        if_match: Some("mutation-etag".to_owned()),
        ..CallInput::default()
    })
    .expect("input");
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"widget-1"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed, "{}", verification.basis);
    let request = server.await.expect("server joins");
    assert!(request.starts_with("GET /client/v4/accounts/account-1/widgets/widget-1 "));
    assert!(!request.contains("mutation_mode"));
    assert!(!request.contains("mutation-etag"));
    assert!(request.contains("cf-r2-jurisdiction: fedramp\r\n"));
}

#[tokio::test]
async fn created_resource_is_read_back_by_schema_proven_id_and_planned_fields() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let read = stream.read(&mut buffer).await.expect("read verification");
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let body = r#"{"success":true,"result":{"id":"widget-1","name":"created","settings":{"enabled":true},"server_default":"kept"},"errors":[]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
        request
    });
    let mut plan = dns_record_plan(
        "widgets-create",
        "POST",
        "/accounts/{account_id}/widgets",
        "created_resource_contains_planned_fields_by_returned_id",
        json!({"account_id":"account-1"}),
        Some(json!({"name":"created", "settings":{"enabled":true}})),
    );
    plan.capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: "/accounts/{account_id}/widgets/{widget_id}".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-get".to_owned(),
        delete_capability_id: "widgets-delete".to_owned(),
        verified_response_fields: vec!["name".to_owned(), "settings".to_owned()],
    });
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-1"}),
        query: json!({}),
        body: Some(json!({"name":"created", "settings":{"enabled":true}})),
        if_match: Some("mutation-etag".to_owned()),
        ..CallInput::default()
    })
    .expect("input");
    let apply = CloudflareResponseV1 {
        status: 201,
        success: true,
        result: json!({"id":"widget-1"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed, "{}", verification.basis);
    let request = server.await.expect("server joins");
    assert!(request.starts_with("GET /client/v4/accounts/account-1/widgets/widget-1 "));
    assert!(!request.contains("mutation_mode"));
    assert!(!request.contains("mutation-etag"));
    assert!(!request.contains("\"name\":\"created\""));
}

#[tokio::test]
async fn created_resource_verification_fails_closed_without_returned_identity() {
    let mut plan = dns_record_plan(
        "widgets-create",
        "POST",
        "/accounts/{account_id}/widgets",
        "created_resource_contains_planned_fields_by_returned_id",
        json!({"account_id":"account-1"}),
        Some(json!({"name":"secret-like-planned-name"})),
    );
    plan.capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: "/accounts/{account_id}/widgets/{widget_id}".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-get".to_owned(),
        delete_capability_id: "widgets-delete".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
    });
    let apply = CloudflareResponseV1 {
        status: 201,
        success: true,
        result: json!({"name":"secret-like-live-name"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect_err("missing identity must fail closed")
        .to_string();

    assert!(error.contains("identity"));
    assert!(!error.contains("secret-like-planned-name"));
    assert!(!error.contains("secret-like-live-name"));
}

#[tokio::test]
async fn created_resource_without_planned_fields_is_rejected_before_the_mutation_boundary() {
    let mut plan = dns_record_plan(
        "widgets-create",
        "POST",
        "/accounts/{account_id}/widgets",
        "created_resource_contains_planned_fields_by_returned_id",
        json!({"account_id":"account-1"}),
        Some(json!({})),
    );
    plan.capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: "/accounts/{account_id}/widgets/{widget_id}".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-get".to_owned(),
        delete_capability_id: "widgets-delete".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
    });
    plan.status = PlanStatus::Consumed;
    let input: CallInput = serde_json::from_value(plan.input.clone()).expect("input");
    let catalog_hash = plan.catalog_hash.clone();
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .execute_consumed_plan_with_input(
            &mut plan,
            &catalog_hash,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
            &input,
        )
        .await
        .expect_err("empty planned fields must fail before network execution")
        .to_string();

    assert!(error.contains("planned create body"));
    assert_eq!(plan.status, PlanStatus::Consumed);
}

#[tokio::test]
async fn created_resource_with_an_unbound_field_is_rejected_before_the_mutation_boundary() {
    let mut plan = dns_record_plan(
        "widgets-create",
        "POST",
        "/accounts/{account_id}/widgets",
        "created_resource_contains_planned_fields_by_returned_id",
        json!({"account_id":"account-1"}),
        Some(json!({"name":"created", "secret":"must-not-cross-boundary"})),
    );
    plan.capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: "/accounts/{account_id}/widgets/{widget_id}".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-get".to_owned(),
        delete_capability_id: "widgets-delete".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
    });
    plan.status = PlanStatus::Consumed;
    let input: CallInput = serde_json::from_value(plan.input.clone()).expect("input");
    let catalog_hash = plan.catalog_hash.clone();
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .execute_consumed_plan_with_input(
            &mut plan,
            &catalog_hash,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
            &input,
        )
        .await
        .expect_err("an unbound field must fail before network execution")
        .to_string();

    assert!(error.contains("outside the hash-bound exact readback fields"));
    assert!(!error.contains("must-not-cross-boundary"));
    assert_eq!(plan.status, PlanStatus::Consumed);
}

#[tokio::test]
async fn exact_create_rejects_query_controls_before_the_mutation_boundary() {
    let mut plan = dns_record_plan(
        "widgets-create",
        "POST",
        "/accounts/{account_id}/widgets",
        "created_resource_contains_planned_fields_by_returned_id",
        json!({"account_id":"account-1"}),
        Some(json!({"name":"created"})),
    );
    plan.capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: "/accounts/{account_id}/widgets/{widget_id}".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-get".to_owned(),
        delete_capability_id: "widgets-delete".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
    });
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-1"}),
        query: json!({"deploy":"must-not-cross-boundary"}),
        body: Some(json!({"name":"created"})),
        ..CallInput::default()
    })
    .expect("input");
    plan.status = PlanStatus::Consumed;
    let input: CallInput = serde_json::from_value(plan.input.clone()).expect("input");
    let catalog_hash = plan.catalog_hash.clone();
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .execute_consumed_plan_with_input(
            &mut plan,
            &catalog_hash,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
            &input,
        )
        .await
        .expect_err("query controls must fail before network execution")
        .to_string();

    assert!(error.contains("query controls outside the hash-bound exact readback contract"));
    assert!(!error.contains("must-not-cross-boundary"));
    assert_eq!(plan.status, PlanStatus::Consumed);
}

#[tokio::test]
async fn collection_create_rejects_query_controls_before_the_mutation_boundary() {
    let mut plan = dns_record_plan(
        "widgets-create",
        "POST",
        "/accounts/{account_id}/widgets",
        "parent_collection_contains_created_resource_id_and_planned_fields",
        json!({"account_id":"account-1"}),
        Some(json!({"name":"created"})),
    );
    plan.capability.created_collection_resource = Some(CreatedCollectionResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        delete_capability_id: "widgets-delete".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
        requires_page_number_completion: false,
    });
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-1"}),
        query: json!({"mode":"must-not-cross-boundary"}),
        body: Some(json!({"name":"created"})),
        ..CallInput::default()
    })
    .expect("input");
    plan.status = PlanStatus::Consumed;
    let input: CallInput = serde_json::from_value(plan.input.clone()).expect("input");
    let catalog_hash = plan.catalog_hash.clone();
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .execute_consumed_plan_with_input(
            &mut plan,
            &catalog_hash,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
            &input,
        )
        .await
        .expect_err("query controls must fail before network execution")
        .to_string();

    assert!(error.contains("query controls outside the hash-bound collection readback contract"));
    assert!(!error.contains("must-not-cross-boundary"));
    assert_eq!(plan.status, PlanStatus::Consumed);
}

#[tokio::test]
async fn same_path_delete_rejects_broadening_inputs_before_the_mutation_boundary() {
    let mut plan = dns_record_plan(
        "widgets-delete",
        "DELETE",
        "/accounts/{account_id}/widgets/{widget_id}",
        "same_resource_returns_not_found_after_delete",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        None,
    );
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-1", "widget_id":"widget-1"}),
        query: json!({"cascade":true}),
        body: Some(json!({"reason":"must-not-cross-boundary"})),
        ..CallInput::default()
    })
    .expect("input");
    plan.status = PlanStatus::Consumed;
    let input: CallInput = serde_json::from_value(plan.input.clone()).expect("input");
    let catalog_hash = plan.catalog_hash.clone();
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .execute_consumed_plan_with_input(
            &mut plan,
            &catalog_hash,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
            &input,
        )
        .await
        .expect_err("broadening delete inputs must fail before network execution")
        .to_string();

    assert!(error.contains("outside its hash-bound same-path readback contract"));
    assert!(!error.contains("must-not-cross-boundary"));
    assert_eq!(plan.status, PlanStatus::Consumed);
}

#[tokio::test]
async fn same_path_delete_rejects_query_controls_before_the_mutation_boundary() {
    let mut plan = dns_record_plan(
        "widgets-delete",
        "DELETE",
        "/accounts/{account_id}/widgets/{widget_id}",
        "same_resource_returns_not_found_after_delete",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        None,
    );
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-1", "widget_id":"widget-1"}),
        query: json!({"cascade":"must-not-cross-boundary"}),
        ..CallInput::default()
    })
    .expect("input");
    plan.status = PlanStatus::Consumed;
    let input: CallInput = serde_json::from_value(plan.input.clone()).expect("input");
    let catalog_hash = plan.catalog_hash.clone();
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .execute_consumed_plan_with_input(
            &mut plan,
            &catalog_hash,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
            &input,
        )
        .await
        .expect_err("query controls must fail before network execution")
        .to_string();

    assert!(error.contains("query controls outside the hash-bound same-path readback contract"));
    assert!(!error.contains("must-not-cross-boundary"));
    assert_eq!(plan.status, PlanStatus::Consumed);
}

#[tokio::test]
async fn same_path_update_rejects_unbound_fields_before_the_mutation_boundary() {
    let mut plan = dns_record_plan(
        "widgets-update",
        "PATCH",
        "/accounts/{account_id}/widgets/{widget_id}",
        "same_resource_contains_planned_fields_after_update",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        Some(json!({"name":"planned"})),
    );
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-1", "widget_id":"widget-1"}),
        query: json!({}),
        body: Some(json!({"name":"planned", "secret":"must-not-cross-boundary"})),
        ..CallInput::default()
    })
    .expect("input");
    plan.status = PlanStatus::Consumed;
    let input: CallInput = serde_json::from_value(plan.input.clone()).expect("input");
    let catalog_hash = plan.catalog_hash.clone();
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .execute_consumed_plan_with_input(
            &mut plan,
            &catalog_hash,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
            &input,
        )
        .await
        .expect_err("an unbound update field must fail before network execution")
        .to_string();

    assert!(error.contains("outside the hash-bound same-path readback fields"));
    assert!(!error.contains("must-not-cross-boundary"));
    assert_eq!(plan.status, PlanStatus::Consumed);
}

#[tokio::test]
async fn same_path_update_rejects_query_controls_before_the_mutation_boundary() {
    let mut plan = dns_record_plan(
        "widgets-update",
        "PATCH",
        "/accounts/{account_id}/widgets/{widget_id}",
        "same_resource_contains_planned_fields_after_update",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        Some(json!({"name":"planned"})),
    );
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-1", "widget_id":"widget-1"}),
        query: json!({"mode":"must-not-cross-boundary"}),
        body: Some(json!({"name":"planned"})),
        ..CallInput::default()
    })
    .expect("input");
    plan.status = PlanStatus::Consumed;
    let input: CallInput = serde_json::from_value(plan.input.clone()).expect("input");
    let catalog_hash = plan.catalog_hash.clone();
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .execute_consumed_plan_with_input(
            &mut plan,
            &catalog_hash,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
            &input,
        )
        .await
        .expect_err("query controls must fail before network execution")
        .to_string();

    assert!(error.contains("query controls outside the hash-bound same-path readback contract"));
    assert!(!error.contains("must-not-cross-boundary"));
    assert_eq!(plan.status, PlanStatus::Consumed);
}

#[tokio::test]
async fn exact_resource_update_rejects_field_drift_without_echoing_values() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let _ = stream.read(&mut buffer).await.expect("read verification");
        let body = r#"{"success":true,"result":{"settings":{"mode":"unexpected-live-value"}},"errors":[]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
    });
    let plan = dns_record_plan(
        "widgets-update",
        "PUT",
        "/accounts/{account_id}/widgets/{widget_id}",
        "same_resource_contains_planned_fields_after_update",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        Some(json!({"settings":{"mode":"planned-secret-like-value"}})),
    );
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(!verification.passed);
    assert!(verification.basis.contains("settings"));
    assert!(!verification.basis.contains("planned-secret-like-value"));
    assert!(!verification.basis.contains("unexpected-live-value"));
    server.await.expect("server joins");
}

#[tokio::test]
async fn same_path_object_update_verifies_schema_proven_fields_with_a_clean_get() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let read = stream.read(&mut buffer).await.expect("read verification");
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let body = r#"{"success":true,"result":{"mode":"strict","nested":{"enabled":true},"server_default":"kept"},"errors":[]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
        request
    });
    let mut plan = dns_record_plan(
        "settings-update",
        "PUT",
        "/zones/{zone_id}/settings/example",
        "same_path_result_contains_planned_fields_after_update",
        json!({"zone_id":"zone-1"}),
        Some(json!({"mode":"strict", "nested":{"enabled":true}})),
    );
    plan.capability.request_schema = Some(json!({
        "type":"object",
        "properties":{"mode":{"type":"string"},"nested":{"type":"object"}}
    }));
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"zone_id":"zone-1"}),
        query: json!({}),
        body: Some(json!({"mode":"strict", "nested":{"enabled":true}})),
        if_match: Some("mutation-etag".to_owned()),
        ..CallInput::default()
    })
    .expect("input");
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed, "{}", verification.basis);
    let request = server.await.expect("server joins");
    assert!(request.starts_with("GET /client/v4/zones/zone-1/settings/example "));
    assert!(!request.contains("mutation_mode"));
    assert!(!request.contains("mutation-etag"));
}

#[tokio::test]
async fn dns_record_verification_rejects_live_field_drift_without_echoing_values() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let _ = stream.read(&mut buffer).await.expect("read verification");
        let body = r#"{"success":true,"result":{"id":"record-1","type":"TXT","name":"www.example.com","content":"unexpected-live-value","ttl":300},"errors":[]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
    });
    let plan = dns_record_plan(
        "dns-records-for-a-zone-patch-dns-record",
        "PATCH",
        "/zones/{zone_id}/dns_records/{dns_record_id}",
        "dns_record_details_match_planned_id_and_fields",
        json!({"zone_id":"zone-1", "dns_record_id":"record-1"}),
        Some(json!({
            "type":"TXT",
            "name":"www.example.com",
            "content":"planned-secret-like-value",
            "ttl":300
        })),
    );
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({
            "id":"record-1",
            "type":"TXT",
            "name":"www.example.com",
            "content":"planned-secret-like-value",
            "ttl":300
        }),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(!verification.passed);
    assert!(verification.basis.contains("content"));
    assert!(!verification.basis.contains("planned-secret-like-value"));
    assert!(!verification.basis.contains("unexpected-live-value"));
    server.await.expect("server joins");
}

fn dns_record_plan(
    id: &str,
    method: &str,
    path: &str,
    verification_strategy: &str,
    selectors: serde_json::Value,
    body: Option<serde_json::Value>,
) -> PlanV1 {
    let mut capability = CapabilityV1::new(id, id, method, path);
    verification_strategy.clone_into(&mut capability.verification.strategy);
    if matches!(
        verification_strategy,
        "same_resource_returns_not_found_after_delete"
    ) {
        capability.same_path_read = Some(SamePathReadContractV1 {
            path: path.to_owned(),
            read_capability_id: format!("{id}-readback"),
            verified_response_fields: Vec::new(),
        });
    } else if matches!(
        verification_strategy,
        "same_resource_contains_planned_fields_after_update"
            | "same_path_result_contains_planned_fields_after_update"
            | "parent_collection_item_contains_planned_fields_after_update"
    ) {
        let mut fields = body
            .as_ref()
            .and_then(serde_json::Value::as_object)
            .map(|body| body.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        fields.sort();
        fields.dedup();
        let properties = fields
            .iter()
            .map(|field| (field.clone(), json!({})))
            .collect::<serde_json::Map<_, _>>();
        capability.request_schema = Some(json!({
            "type":"object",
            "properties": properties
        }));
        capability.same_path_read = Some(SamePathReadContractV1 {
            path: path.to_owned(),
            read_capability_id: format!("{id}-readback"),
            verified_response_fields: fields,
        });
    }
    let mut plan = PlanV1::draft(
        "profile",
        "account-1",
        "sha256:catalog",
        capability,
        json!({}),
    )
    .expect("plan");
    plan.input = serde_json::to_value(CallInput {
        selectors,
        query: json!({}),
        body,
        ..CallInput::default()
    })
    .expect("input");
    plan
}

fn token_plan(
    id: &str,
    method: &str,
    path: &str,
    verification_strategy: &str,
    selectors: serde_json::Value,
) -> PlanV1 {
    let mut capability = CapabilityV1::new(id, id, method, path);
    verification_strategy.clone_into(&mut capability.verification.strategy);
    let mut plan = PlanV1::draft(
        "profile",
        "account-1",
        "sha256:catalog",
        capability,
        json!({}),
    )
    .expect("plan");
    plan.input = serde_json::to_value(CallInput {
        selectors,
        query: json!({}),
        body: Some(json!({})),
        ..CallInput::default()
    })
    .expect("input");
    plan
}
