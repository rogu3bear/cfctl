use cfctl_auth::AuthCredential;
use cfctl_catalog::normalize_openapi;
use cfctl_cloudflare::{
    CallInput, CloudflareError, Executor, RequestBuilder, validate_request_contract,
};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

fn catalog() -> cfctl_catalog::CatalogSnapshot {
    let document: Value = serde_json::from_str(include_str!(
        "../../../../cfctl-catalog/tests/fixtures/referenced-json-operations.json"
    ))
    .expect("official schema fixture");
    normalize_openapi(&document).expect("fixture normalizes")
}

fn oauth_r2_catalog() -> cfctl_catalog::CatalogSnapshot {
    let document: Value = serde_json::from_str(include_str!(
        "../../../../cfctl-catalog/tests/fixtures/oauth-r2-operations.json"
    ))
    .expect("official schema fixture");
    normalize_openapi(&document).expect("fixture normalizes")
}

#[test]
fn oauth_optional_scopes_flow_from_catalog_through_snapshot_and_receipt_validation() {
    use super::*;
    let snapshot = oauth_r2_catalog();
    let create = snapshot
        .get("oauth-clients-create")
        .expect("OAuth create exists");
    assert!(is_oauth_client_create_capability(create));
    let capability = snapshot
        .get("oauth-clients-update")
        .expect("OAuth update exists");
    assert!(is_oauth_client_update_capability(capability));
    let mut input = oauth_client_update_input(json!({
        "scopes":["account.read","account.write"],"optional_scopes":["account.write"]
    }));
    input.selectors["account_id"] = json!("a".repeat(32));
    validate_request_contract(capability, &input).expect("optional grants validate");
    let mut response = oauth_client_update_response("private");
    response.result["scopes"] = json!(["account.read"]);
    response.result["optional_scopes"] = json!([]);
    let receipt =
        apply_oauth_client_update_state_response(capability, &input, &"a".repeat(32), &response)
            .expect("snapshot captures optional grants");
    assert_eq!(receipt["prior_state"]["optional_scopes"], json!([]));
    let mut plan = PlanV1::draft(
        "fixture-profile",
        &"a".repeat(32),
        "catalog-hash",
        capability.clone(),
        json!({"selectors":input.selectors}),
    )
    .expect("draft fixture plan");
    plan.input = serde_json::to_value(&input).expect("serialize fixture input");
    validate_oauth_client_update_state_receipt(&plan, &receipt)
        .expect("exact snapshot receipt validates");
    let mut missing = receipt.clone();
    missing["prior_state"]
        .as_object_mut()
        .expect("snapshot prior state is an object")
        .remove("optional_scopes");
    assert!(validate_oauth_client_update_state_receipt(&plan, &missing).is_err());

    response.result["optional_scopes"] = json!(["account.read"]);
    input.body = Some(json!({"scopes":["account.write"]}));
    assert!(
        apply_oauth_client_update_state_response(capability, &input, &"a".repeat(32), &response)
            .is_err(),
        "scope removal cannot silently leave an invalid optional grant"
    );
    for body in [
        json!({"scopes":["account.read"],"optional_scopes":["account.write"]}),
        json!({"scopes":["openid"],"optional_scopes":["openid"]}),
        json!({"scopes":["offline"],"optional_scopes":["offline"]}),
        json!({"scopes":["offline_access"],"optional_scopes":["offline_access"]}),
        json!({"optional_scopes":["account.read"]}),
    ] {
        input.body = Some(body);
        assert!(validate_request_contract(capability, &input).is_err());
    }
}

#[test]
fn r2_us_requests_require_the_reviewed_jurisdiction_and_full_billing_bound() {
    let snapshot = oauth_r2_catalog();
    let capability = snapshot.get("r2-create-bucket").expect("R2 create exists");
    assert_eq!(capability.cost.maximum, Some(9.0));
    let mut input = CallInput {
        selectors: json!({"account_id":"a".repeat(32),"cf-r2-jurisdiction":"us"}),
        body: Some(json!({"name":"fixture-bucket","storageClass":"Standard"})),
        ..CallInput::default()
    };
    validate_request_contract(capability, &input).expect("US create request validates");
    let builder = RequestBuilder::new("https://api.example.invalid/client/v4")
        .expect("fixture request builder");
    assert!(matches!(
        builder.build(capability, &input),
        Err(CloudflareError::ApprovedPlanRequired(_))
    ));
    let read = snapshot
        .get("r2-get-bucket")
        .expect("R2 detail read exists");
    let read_input = CallInput {
        selectors: json!({"account_id":"a".repeat(32),"bucket_name":"fixture-bucket","cf-r2-jurisdiction":"us"}),
        ..CallInput::default()
    };
    let request = RequestBuilder::new("https://api.example.invalid/client/v4")
        .expect("fixture request builder")
        .build(read, &read_input)
        .expect("US read request builds");
    assert_eq!(request.headers["cf-r2-jurisdiction"], "us");
    input.selectors["cf-r2-jurisdiction"] = json!("fedramp");
    assert!(validate_request_contract(capability, &input).is_err());
}

#[test]
fn deliberate_restrictions_route_to_their_governed_workflows_before_pricing_search() {
    use super::*;
    for (id, method, path, alternative) in [
        (
            "queues-ack-messages",
            "POST",
            "/accounts/{account_id}/queues/{queue_id}/messages/ack",
            "events-consume-queue-batch",
        ),
        (
            "createZoneRuleset",
            "POST",
            "/zones/{zone_id}/rulesets",
            "security-response-create-empty-custom-ruleset",
        ),
        (
            "analytics-engine-sql-query-post",
            "POST",
            "/accounts/{account_id}/analytics_engine/sql",
            "analytics-engine-sql-query-get",
        ),
        (
            "put-accounts-account_id-logpush-jobs-job_id",
            "PUT",
            "/accounts/{account_id}/logpush/jobs/{job_id}",
            "logpush-account-job-settings-update",
        ),
    ] {
        let mut capability = CapabilityV1::new(id, id, method, path);
        capability.adapter_status = AdapterStatus::Blocked;
        capability.blocked_reason = Some(
            "blocked by design: reserved to its governed workflow; cost remains unresolved"
                .to_owned(),
        );
        let guide = guide_document(&capability);
        assert_eq!(
            guide.next_action.argv,
            ["cfctl", "guide", alternative, "--json"]
        );
        assert!(!guide.next_action.summary.contains("Run the exact"));
        capability.path.push_str("/changed");
        assert_ne!(
            guide_document(&capability).next_action.argv,
            ["cfctl", "guide", alternative, "--json"]
        );
    }
}

#[test]
fn referenced_request_validation_does_not_bypass_operation_admission() {
    let snapshot = catalog();
    let capability = snapshot
        .get("updateUrlNormalization")
        .expect("URL normalization");
    let mut input = CallInput {
        selectors: json!({"zone_id":"zone-a"}),
        body: Some(json!({"scope":"incoming","type":"cloudflare"})),
        ..CallInput::default()
    };
    validate_request_contract(capability, &input).expect("declared body validates");
    assert!(
        RequestBuilder::new("https://api.example.invalid/client/v4")
            .expect("builder")
            .build(capability, &input)
            .is_err(),
        "missing cost and risk still block execution"
    );
    input.body = None;
    assert!(matches!(
        validate_request_contract(capability, &input),
        Err(CloudflareError::MissingRequestBody(_))
    ));
    input.body = Some(json!({"scope":"everywhere","type":"cloudflare"}));
    assert!(matches!(
        validate_request_contract(capability, &input),
        Err(CloudflareError::InvalidRequestBody(_))
    ));
}

#[test]
fn email_preview_schema_does_not_admit_recipient_delivery_changes() {
    let document: Value = serde_json::from_str(include_str!(
        "../../../../cfctl-catalog/tests/fixtures/email-preview-operations.json"
    ))
    .expect("official Email fixture parses");
    let snapshot = normalize_openapi(&document).expect("Email catalog normalizes");
    let capability = snapshot
        .get("email-sending-subdomains-update-sending-subdomain")
        .expect("Email preview update exists");
    let mut input = CallInput {
        selectors: json!({"zone_id":"a".repeat(32),"subdomain_id":"b".repeat(32)}),
        body: Some(json!({"preview_enabled":false})),
        ..CallInput::default()
    };
    validate_request_contract(capability, &input).expect("preview-only body validates");
    input.body = Some(json!({"preview_enabled":false,"drop_suppressed_recipients":true}));
    assert!(validate_request_contract(capability, &input).is_err());
    assert_eq!(capability.entitlement.available, None);
    assert!(capability.entitlement.requires_live_resolution);
}

#[tokio::test]
async fn queue_metrics_uses_json_accept_and_rejects_stream_or_malformed_envelope() {
    let snapshot = catalog();
    let capability = snapshot.get("queues-get-metrics").expect("Queue metrics");
    let input = CallInput {
        selectors: json!({"account_id":"account-a","queue_id":"queue-a"}),
        ..CallInput::default()
    };
    for (media, body, success) in [
        (
            "application/json",
            r#"{"success":true,"result":{"backlog_count":4}}"#,
            true,
        ),
        (
            "text/event-stream",
            "data: private-stream-marker\n\n",
            false,
        ),
        (
            "application/json",
            r#"{"result":{"private":"private-json-marker"}}"#,
            false,
        ),
    ] {
        let (response, request) = read_from_fixture(capability, &input, 200, media, body).await;
        if success {
            let response = response.expect("JSON snapshot");
            assert!(response.success);
            assert_eq!(response.result, json!({"backlog_count":4}));
        } else {
            let error =
                response.expect_err("stream and malformed JSON cannot become a metrics snapshot");
            assert!(!error.to_string().contains("private-"));
        }
        assert!(request.starts_with("GET /client/v4/accounts/account-a/queues/queue-a/metrics "));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("accept: application/json\r\n")
        );
    }
}

async fn read_from_fixture(
    capability: &cfctl_core::CapabilityV1,
    input: &CallInput,
    status: u16,
    media: &'static str,
    body: &'static str,
) -> (
    std::result::Result<cfctl_cloudflare::CloudflareResponseV1, CloudflareError>,
    String,
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener");
    let base = format!(
        "http://{}/client/v4",
        listener.local_addr().expect("bound loopback address")
    );
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept fixture request");
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            assert!(bytes.len() < 8192, "bounded request headers");
            bytes.push(socket.read_u8().await.expect("read bounded request header"));
        }
        socket.write_all(format!("HTTP/1.1 {status} Fixture\r\nContent-Type: {media}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.expect("write fixture response");
        String::from_utf8(bytes).expect("HTTP request is UTF-8")
    });
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("bounded fixture client");
    let result = Executor::new(client, &base)
        .expect("fixture executor")
        .execute_read(
            capability,
            input,
            &AuthCredential::Bearer {
                token: "fixture-token".to_owned(),
            },
        )
        .await;
    let request = tokio::time::timeout(std::time::Duration::from_secs(5), server)
        .await
        .expect("fixture server completes within timeout")
        .expect("fixture server joins");
    (result, request)
}

#[tokio::test]
async fn entitlement_read_cancellation_cannot_become_a_successful_empty_inventory() {
    let snapshot = catalog();
    for (id, selector) in [
        ("entitlements-get-account-entitlements", "account_id"),
        ("entitlements-get-zone-entitlements", "zone_id"),
    ] {
        let capability = snapshot.get(id).expect("entitlement capability exists");
        let input = CallInput {
            selectors: json!({selector:"a".repeat(32)}),
            ..CallInput::default()
        };
        let (response, _) = read_from_fixture(
            capability,
            &input,
            200,
            "application/json",
            r#"{"success":true,"result":[]}"#,
        )
        .await;
        assert_eq!(
            response
                .expect("successful empty entitlement response")
                .result,
            json!([])
        );
        let (response, _) =
            read_from_fixture(capability, &input, 204, "application/json", "").await;
        assert!(response.is_err(), "cancellation is incomplete evidence");
    }
}
