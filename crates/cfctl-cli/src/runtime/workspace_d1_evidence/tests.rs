#![allow(clippy::wildcard_imports, reason = "white-box domain tests")]

use super::*;

fn contract() -> WorkspaceD1EvidenceContractV1 {
    WorkspaceD1EvidenceContractV1 {
        repository_root: "/tmp/repository".to_owned(),
        repository_head: "a".repeat(40),
        repository_origin: "https://example.com/repository.git".to_owned(),
        operation_pack_path: ".cfctl/operations/d1-evidence.toml".to_owned(),
        operation_pack_sha256: format!("sha256:{}", "a".repeat(64)),
        config_template_path: "wrangler.toml".to_owned(),
        config_template_sha256: format!("sha256:{}", "b".repeat(64)),
        production_config_path: "wrangler.production.toml".to_owned(),
        database_binding: "DB".to_owned(),
        wrangler_version: "4.120.1".to_owned(),
        projection: "maildesk_v1".to_owned(),
        query_sha256: sha256(MAILDESK_D1_EVIDENCE_SQL_V1.as_bytes()),
    }
}

fn row() -> Map<String, Value> {
    let route_health_rows = json!([
        {
            "route_id":"route-security-example",
            "domain":"example.com",
            "policy_sha256":"a".repeat(64),
            "route_kind":"role_alias",
            "enabled":1,
            "desired_provider":"cloudflare_email_routing",
            "observed_provider":"cloudflare_email_routing",
            "inbound_status":"inbox_verified",
            "reply_status":"provider_accepted",
            "provider_accepted_at":"2026-08-23 12:00:00",
            "inbox_received_at":"2026-08-23T12:01:00Z",
            "reply_provider_accepted_at":"2026-08-23 12:02:00",
            "reply_proven_at":null,
            "last_error_code":null,
            "updated_at":"2026-08-23 12:02:00"
        }
    ]);
    serde_json::from_value::<Map<String, Value>>(json!({
        "active_policy_digest":format!("sha256:{}", "a".repeat(64)),
        "desired_state_digest":format!("sha256:{}", "b".repeat(64)),
        "semantic_projection_digest":format!("sha256:{}", "c".repeat(64)),
        "immutable_policy_object_key":format!("config/policy/{}.json", "a".repeat(64)),
        "expected_domain_count":2,
        "projected_domain_count":2,
        "expected_route_count":1,
        "projected_route_count":1,
        "approved_schema_present":1,
        "approved_table_presence_json":serde_json::to_string(&APPROVED_TABLE_KEYS.iter().map(|key| (*key, true)).collect::<BTreeMap<_, _>>()).expect("table map"),
        "audit_event_counts_json":serde_json::to_string(&AUDIT_EVENT_KEYS.iter().map(|key| (*key, 0_u64)).collect::<BTreeMap<_, _>>()).expect("audit map"),
        "queue_correlation_count":0,
        "dlq_correlation_count":0,
        "active_route_health_count":1,
        "route_health_rows_json":serde_json::to_string(&route_health_rows).expect("route-health JSON")
    }))
    .expect("row")
}

#[test]
fn projects_only_the_typed_body_free_evidence_contract() {
    let (evidence, route_health) = project_evidence(&contract(), vec![row()]).expect("evidence");
    assert_eq!(evidence.schema_version, 1);
    assert_eq!(evidence.projected_route_count, 1);
    assert!(evidence.approved_table_presence["alias_routes"]);
    assert!(!evidence.body_returned);
    assert_eq!(route_health.schema_version, 2);
    assert!(route_health.complete);
    assert_eq!(route_health.record_count, 1);
    assert_eq!(
        route_health.records[0].route_ref_sha256,
        sha256(b"route-security-example")
    );
    assert_eq!(
        route_health.records[0].domain_sha256,
        sha256(b"example.com")
    );
    assert!(!route_health.body_returned);
    assert!(!route_health.provider_output_retained);
    let encoded = serde_json::to_value(&evidence).expect("evidence JSON");
    let top_level = encoded.as_object().expect("typed evidence object");
    for private in ["email", "subject", "recipient", "message_content"] {
        assert!(
            !top_level.contains_key(private),
            "typed evidence must not expose private field `{private}`"
        );
    }
    let encoded_routes = serde_json::to_string(&route_health).expect("route-health JSON");
    for private in [
        "route-security-example",
        "example.com",
        "operator@example.com",
        "subject",
        "recipient",
    ] {
        assert!(
            !encoded_routes.contains(private),
            "typed route evidence must not expose private field `{private}`"
        );
    }
}

#[test]
fn provider_typed_error_codes_remain_body_free_evidence() {
    let mut evidence_row = row();
    let mut records = serde_json::from_str::<Vec<Value>>(
        evidence_row["route_health_rows_json"]
            .as_str()
            .expect("route-health JSON"),
    )
    .expect("route rows");
    records[0]["last_error_code"] = json!("E_HEADER_NOT_ALLOWED");
    evidence_row.insert(
        "route_health_rows_json".to_owned(),
        json!(serde_json::to_string(&records).expect("route rows")),
    );

    let (_, route_health) =
        project_evidence(&contract(), vec![evidence_row]).expect("typed provider error");

    assert_eq!(
        route_health.records[0].last_error_code.as_deref(),
        Some("E_HEADER_NOT_ALLOWED")
    );
}

#[test]
fn column_order_is_irrelevant_but_extra_private_columns_fail_closed() {
    let mut private = row();
    private.insert("recipient".to_owned(), json!("operator@example.com"));
    let error = project_evidence(&contract(), vec![private]).expect_err("private column");
    assert!(error.to_string().contains("private, missing, or arbitrary"));
}

#[test]
fn missing_invalid_and_unbounded_values_fail_closed() {
    let mut missing = row();
    missing.remove("active_policy_digest");
    assert!(project_evidence(&contract(), vec![missing]).is_err());

    let mut invalid_digest = row();
    invalid_digest.insert("active_policy_digest".to_owned(), json!("sha256:ABC"));
    assert!(project_evidence(&contract(), vec![invalid_digest]).is_err());

    let mut negative = row();
    negative.insert("expected_route_count".to_owned(), json!(-1));
    assert!(project_evidence(&contract(), vec![negative]).is_err());

    let mut unbounded = row();
    unbounded.insert("expected_route_count".to_owned(), json!(MAX_COUNT + 1));
    assert!(project_evidence(&contract(), vec![unbounded]).is_err());

    let mut invalid_boolean_map = row();
    invalid_boolean_map.insert(
        "approved_table_presence_json".to_owned(),
        json!("{\"alias_routes\":1}"),
    );
    assert!(project_evidence(&contract(), vec![invalid_boolean_map]).is_err());

    let mut invalid_count_map = row();
    invalid_count_map.insert(
        "audit_event_counts_json".to_owned(),
        json!("{\"route_decision\":-1}"),
    );
    assert!(project_evidence(&contract(), vec![invalid_count_map]).is_err());

    let mut key_smuggling = row();
    key_smuggling.insert(
        "audit_event_counts_json".to_owned(),
        json!("{\"recipient_private_value\":1}"),
    );
    assert!(project_evidence(&contract(), vec![key_smuggling]).is_err());

    let mut value_smuggling = row();
    value_smuggling.insert(
        "immutable_policy_object_key".to_owned(),
        json!("operator@example.com"),
    );
    assert!(project_evidence(&contract(), vec![value_smuggling]).is_err());

    let mut malformed_error = row();
    let mut records = serde_json::from_str::<Vec<Value>>(
        malformed_error["route_health_rows_json"]
            .as_str()
            .expect("route-health JSON"),
    )
    .expect("route rows");
    records[0]["last_error_code"] = json!("E_HEADER_NOT_ALLOWED: private detail");
    malformed_error.insert(
        "route_health_rows_json".to_owned(),
        json!(serde_json::to_string(&records).expect("route rows")),
    );
    assert!(project_evidence(&contract(), vec![malformed_error]).is_err());
}

#[test]
fn multiple_or_empty_rows_fail_closed() {
    assert!(project_evidence(&contract(), Vec::new()).is_err());
    assert!(project_evidence(&contract(), vec![row(), row()]).is_err());
}

#[test]
fn partial_oversized_duplicate_and_malformed_route_inventory_fail_closed() {
    let mut partial = row();
    partial.insert("active_route_health_count".to_owned(), json!(0));
    assert!(project_evidence(&contract(), vec![partial]).is_err());

    let mut oversized = row();
    oversized.insert(
        "active_route_health_count".to_owned(),
        json!(MAX_ROUTE_HEALTH_RECORDS as u64 + 1),
    );
    oversized.insert(
        "projected_route_count".to_owned(),
        json!(MAX_ROUTE_HEALTH_RECORDS as u64 + 1),
    );
    assert!(project_evidence(&contract(), vec![oversized]).is_err());

    let mut duplicate = row();
    let raw = duplicate["route_health_rows_json"]
        .as_str()
        .expect("route-health JSON");
    let record = serde_json::from_str::<Vec<Value>>(raw).expect("route rows")[0].clone();
    duplicate.insert(
        "route_health_rows_json".to_owned(),
        json!(serde_json::to_string(&vec![record.clone(), record]).expect("duplicate rows")),
    );
    duplicate.insert("active_route_health_count".to_owned(), json!(2));
    duplicate.insert("projected_route_count".to_owned(), json!(2));
    assert!(project_evidence(&contract(), vec![duplicate]).is_err());

    let mut unknown_provider = row();
    let mut records = serde_json::from_str::<Vec<Value>>(
        unknown_provider["route_health_rows_json"]
            .as_str()
            .expect("route-health JSON"),
    )
    .expect("route rows");
    records[0]["observed_provider"] = json!("unknown_provider");
    unknown_provider.insert(
        "route_health_rows_json".to_owned(),
        json!(serde_json::to_string(&records).expect("route rows")),
    );
    assert!(project_evidence(&contract(), vec![unknown_provider]).is_err());

    let mut wrong_policy = row();
    let mut records = serde_json::from_str::<Vec<Value>>(
        wrong_policy["route_health_rows_json"]
            .as_str()
            .expect("route-health JSON"),
    )
    .expect("route rows");
    records[0]["policy_sha256"] = json!("d".repeat(64));
    wrong_policy.insert(
        "route_health_rows_json".to_owned(),
        json!(serde_json::to_string(&records).expect("route rows")),
    );
    assert!(project_evidence(&contract(), vec![wrong_policy]).is_err());

    let mut disabled = row();
    let mut records = serde_json::from_str::<Vec<Value>>(
        disabled["route_health_rows_json"]
            .as_str()
            .expect("route-health JSON"),
    )
    .expect("route rows");
    records[0]["enabled"] = json!(false);
    disabled.insert(
        "route_health_rows_json".to_owned(),
        json!(serde_json::to_string(&records).expect("route rows")),
    );
    assert!(project_evidence(&contract(), vec![disabled]).is_err());

    let mut raw_address = row();
    let mut records = serde_json::from_str::<Vec<Value>>(
        raw_address["route_health_rows_json"]
            .as_str()
            .expect("route-health JSON"),
    )
    .expect("route rows");
    records[0]["route_address"] = json!("security@example.com");
    raw_address.insert(
        "route_health_rows_json".to_owned(),
        json!(serde_json::to_string(&records).expect("route rows")),
    );
    assert!(project_evidence(&contract(), vec![raw_address]).is_err());
}

#[test]
fn execution_argv_is_exact_and_contains_only_the_compiler_query() {
    let arguments = compiler_query_arguments("maildesk-production", "/private/config.toml");
    assert_eq!(
        arguments,
        [
            "d1",
            "execute",
            "maildesk-production",
            "--remote",
            "--config",
            "/private/config.toml",
            "--command",
            MAILDESK_D1_EVIDENCE_SQL_V1,
            "--json",
        ]
    );
    assert!(!arguments.iter().any(|argument| argument == "--file"));
    assert_eq!(
        arguments
            .iter()
            .filter(|argument| argument.as_str() == MAILDESK_D1_EVIDENCE_SQL_V1)
            .count(),
        1
    );
}

#[test]
fn failure_receipts_preserve_stage_and_boundary_without_source_material() {
    let private_source = "subject=private recipient=operator@example.com provider_payload=raw";
    let cases = [
        (
            WorkspaceD1EvidenceFailure::before_boundary(
                FailureStage::Preflight,
                CliError::Input(private_source.to_owned()),
            ),
            "CFCTL_WORKSPACE_D1_EVIDENCE_PREFLIGHT_FAILED",
            "preflight",
            false,
        ),
        (
            WorkspaceD1EvidenceFailure::after_boundary(
                FailureStage::ProviderQuery,
                CliError::Input(private_source.to_owned()),
            ),
            "CFCTL_WORKSPACE_D1_EVIDENCE_PROVIDER_READ_FAILED",
            "provider_query",
            true,
        ),
    ];

    for (failure, code, stage, boundary_crossed) in cases {
        let receipt = failure.receipt();
        assert_eq!(receipt["failure_code"], code);
        assert_eq!(receipt["failure_stage"], stage);
        assert_eq!(receipt["boundary_crossed"], boundary_crossed);
        assert_eq!(receipt["provider_output_retained"], false);
        assert_eq!(receipt["body_returned"], false);
        assert_eq!(failure.boundary_crossed(), boundary_crossed);
        let encoded = serde_json::to_string(&receipt).expect("failure receipt JSON");
        assert!(!encoded.contains(private_source));
        assert!(!encoded.contains("operator@example.com"));
        assert!(!encoded.contains("provider_payload"));
    }
}
