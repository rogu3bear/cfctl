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

fn inbound_contract() -> WorkspaceD1EvidenceContractV1 {
    WorkspaceD1EvidenceContractV1 {
        projection: MAILDESK_INBOUND_ACCEPTANCE_PROJECTION_V1.to_owned(),
        query_sha256: sha256(MAILDESK_INBOUND_ACCEPTANCE_SQL_V1.as_bytes()),
        ..contract()
    }
}

fn inbound_input() -> CallInput {
    CallInput {
        query: json!({
            "config":"wrangler.production.toml",
            "binding":"DB",
            "delivery_fingerprint_sha256":format!("sha256:{}", "a".repeat(64)),
            "route_id":"route:example.com:security",
            "policy_sha256":format!("sha256:{}", "b".repeat(64)),
        }),
        ..CallInput::default()
    }
}

fn inbound_row() -> Map<String, Value> {
    serde_json::from_value::<Map<String, Value>>(json!({
        "inbound_delivery_id":format!("inbound:{}", "a".repeat(64)),
        "relay_id":format!("relay:{}", "a".repeat(64)),
        "thread_id":format!("thread:{}", "c".repeat(64)),
        "route_id":"route:example.com:security",
        "policy_sha256":"b".repeat(64),
        "provider_accepted_at":"2026-08-26 22:06:57",
        "status":"provider_accepted",
        "recipient_count":2,
        "provider_accepted_count":2,
    }))
    .expect("inbound row")
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
        "revision_r2_key":format!("config/policy/{}.json", "a".repeat(64)),
        "projection_policy_sha256":format!("sha256:{}", "a".repeat(64)),
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
fn shared_private_projector_reuses_the_exact_evidence_owner() {
    let evidence_row = row();
    assert!(
        project_private_query_rows(
            MAILDESK_D1_EVIDENCE_SQL_V1,
            std::slice::from_ref(&evidence_row),
        )
        .expect("owned evidence query")
        .is_ok()
    );

    for private in [
        json!("73656e6465722e707269766174652e6578616d706c65"),
        json!("c2VuZGVyLnByaXZhdGUuZXhhbXBsZQ=="),
        json!({"name":"private"}),
        json!(["private"]),
        json!("MAILDESK_VERIFIED_SENDER_DOMAINS\nsender.private.example"),
    ] {
        let mut smuggled = evidence_row.clone();
        smuggled.insert("immutable_policy_object_key".to_owned(), private);
        assert!(
            project_private_query_rows(MAILDESK_D1_EVIDENCE_SQL_V1, &[smuggled])
                .expect("owned evidence query")
                .is_err(),
            "private-shaped values must fail before typed evidence retention"
        );
    }

    for private_shaped in [
        "sender.private.example",
        "73656e6465722e707269766174652e6578616d706c65",
        "c2VuZGVyLnByaXZhdGUuZXhhbXBsZQ",
        "name=sender.private.example",
        "{\"name\":\"sender.private.example\"}",
        "[\"sender.private.example\"]",
        "name\nsender.private.example",
    ] {
        let mut smuggled = evidence_row.clone();
        let mut records = serde_json::from_str::<Vec<Value>>(
            smuggled["route_health_rows_json"]
                .as_str()
                .expect("route-health JSON"),
        )
        .expect("route rows");
        records[0]["last_error_code"] = json!(private_shaped);
        smuggled.insert(
            "route_health_rows_json".to_owned(),
            json!(serde_json::to_string(&records).expect("route rows")),
        );
        assert!(
            project_private_query_rows(MAILDESK_D1_EVIDENCE_SQL_V1, &[smuggled])
                .expect("owned evidence query")
                .is_err(),
            "private-shaped last_error_code must fail before serialization"
        );
    }

    let mut extra = evidence_row;
    extra.insert("name".to_owned(), json!("private"));
    assert!(
        project_private_query_rows(MAILDESK_D1_EVIDENCE_SQL_V1, &[extra])
            .expect("owned evidence query")
            .is_err()
    );
    assert!(project_private_query_rows("SELECT arbitrary", &[]).is_none());
}

#[test]
fn inbound_private_projector_accepts_only_compiler_owned_shape_and_values() {
    let query = compiler_query(&inbound_contract(), &inbound_input()).expect("compiler query");
    assert!(
        project_private_query_rows(&query.sql, &[inbound_row()])
            .expect("owned inbound query")
            .is_ok()
    );
    for mutation in [
        ("status", json!("c2VuZGVyLnByaXZhdGUuZXhhbXBsZQ==")),
        ("policy_sha256", json!("A".repeat(64))),
        ("recipient_count", json!({"private":1})),
        ("provider_accepted_count", json!([1])),
        ("thread_id", json!("thread:73656e646572")),
    ] {
        let mut rejected = inbound_row();
        rejected.insert(mutation.0.to_owned(), mutation.1);
        assert!(
            project_private_query_rows(&query.sql, &[rejected])
                .expect("owned inbound query")
                .is_err()
        );
    }
    let mut extra = inbound_row();
    extra.insert("name".to_owned(), json!("private"));
    assert!(
        project_private_query_rows(&query.sql, &[extra])
            .expect("owned inbound query")
            .is_err()
    );
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

    for private_shaped in [
        "sender.private.example",
        "73656e6465722e707269766174652e6578616d706c65",
        "c2VuZGVyLnByaXZhdGUuZXhhbXBsZQ",
        "name=sender.private.example",
        "{\"name\":\"sender.private.example\"}",
        "[\"sender.private.example\"]",
        "name\nsender.private.example",
    ] {
        let mut rejected = row();
        let mut records = serde_json::from_str::<Vec<Value>>(
            rejected["route_health_rows_json"]
                .as_str()
                .expect("route-health JSON"),
        )
        .expect("route rows");
        records[0]["last_error_code"] = json!(private_shaped);
        rejected.insert(
            "route_health_rows_json".to_owned(),
            json!(serde_json::to_string(&records).expect("route rows")),
        );
        assert!(
            project_evidence(&contract(), vec![rejected]).is_err(),
            "private-shaped last_error_code must fail closed"
        );
    }
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
    let arguments = compiler_query_arguments(
        "maildesk-production",
        "/private/config.toml",
        MAILDESK_D1_EVIDENCE_SQL_V1,
    );
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
fn inbound_acceptance_query_is_compiler_owned_and_projects_one_exact_binding() {
    let input = inbound_input();
    let query = compiler_query(&inbound_contract(), &input).expect("compiler query");
    assert_eq!(query.template, MAILDESK_INBOUND_ACCEPTANCE_SQL_V1);
    assert!(query.sql.contains(&"a".repeat(64)));
    assert!(query.sql.contains("route:example.com:security"));
    assert!(!query.sql.contains("__MAILDESK_"));

    let row = inbound_row();
    let config = workspace_d1_migration::ValidatedConfig {
        path: "wrangler.production.toml".to_owned(),
        sha256: format!("sha256:{}", "d".repeat(64)),
        database_name: "maildesk-production".to_owned(),
        database_id: "database-private".to_owned(),
    };
    let receipt =
        project_inbound_acceptance(&inbound_contract(), &input, vec![row], "4.120.1", &config)
            .expect("receipt");
    assert!(inbound_acceptance_receipt_is_complete(&receipt));
    assert_eq!(receipt["status"], "accepted");
    let encoded = serde_json::to_string(&receipt).expect("receipt JSON");
    for forbidden in [
        "database-private",
        "operator@example.com",
        "subject",
        "body_content",
    ] {
        assert!(!encoded.contains(forbidden));
    }
}

#[test]
fn inbound_acceptance_zero_multiple_and_mismatched_rows_fail_closed() {
    let input = inbound_input();
    let config = workspace_d1_migration::ValidatedConfig {
        path: "wrangler.production.toml".to_owned(),
        sha256: format!("sha256:{}", "d".repeat(64)),
        database_name: "maildesk-production".to_owned(),
        database_id: "database-private".to_owned(),
    };
    for rows in [Vec::new(), vec![inbound_row(), inbound_row()]] {
        let receipt =
            project_inbound_acceptance(&inbound_contract(), &input, rows, "4.120.1", &config)
                .expect("typed failure receipt");
        assert!(!inbound_acceptance_receipt_is_complete(&receipt));
        assert_eq!(receipt["success"], false);
    }

    let drift_cases = [
        (
            "inbound_delivery_id",
            json!(format!("inbound:{}", "f".repeat(64))),
        ),
        ("relay_id", json!(format!("relay:{}", "f".repeat(64)))),
        ("thread_id", json!("thread:not-a-digest")),
        ("route_id", json!("route:example.net:security")),
        ("policy_sha256", json!("f".repeat(64))),
        ("status", json!("received")),
        ("recipient_count", json!(0)),
        ("provider_accepted_count", json!(1)),
        ("provider_accepted_at", json!("not-a-timestamp")),
    ];
    for (field, value) in drift_cases {
        let mut drifted_row = inbound_row();
        drifted_row.insert(field.to_owned(), value);
        if let Ok(receipt) = project_inbound_acceptance(
            &inbound_contract(),
            &input,
            vec![drifted_row],
            "4.120.1",
            &config,
        ) {
            assert!(
                !inbound_acceptance_receipt_is_complete(&receipt),
                "{field} drift must not produce a complete receipt",
            );
            assert_eq!(receipt["success"], false);
        }
    }

    let mut expanded = inbound_row();
    expanded.insert("subject".to_owned(), json!("must not be projected"));
    assert!(
        project_inbound_acceptance(
            &inbound_contract(),
            &input,
            vec![expanded],
            "4.120.1",
            &config,
        )
        .is_err()
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

#[test]
fn independent_policy_sources_preserve_disagreement_without_substitution() {
    let mut evidence_row = row();
    let revision = format!("config/policy/{}.json", "d".repeat(64));
    let projection = format!("sha256:{}", "e".repeat(64));
    evidence_row.insert("revision_r2_key".to_owned(), json!(revision));
    evidence_row.insert("projection_policy_sha256".to_owned(), json!(projection));
    let (evidence, _) =
        project_evidence(&contract(), vec![evidence_row]).expect("independent observations");
    assert_eq!(evidence.revision_r2_key.as_deref(), Some(revision.as_str()));
    assert_eq!(
        evidence.projection_policy_sha256.as_deref(),
        Some(projection.as_str())
    );
    assert_ne!(
        evidence.projection_policy_sha256.as_deref(),
        Some(evidence.active_policy_digest.as_str())
    );
    for (field, invalid) in [
        ("revision_r2_key", json!("private@example.com")),
        ("revision_r2_key", json!("x".repeat(1025))),
        ("projection_policy_sha256", json!("sha256:invalid")),
        ("projection_policy_sha256", Value::Null),
    ] {
        let mut invalid_row = row();
        invalid_row.insert(field.to_owned(), invalid);
        assert!(project_evidence(&contract(), vec![invalid_row]).is_err());
    }
}

#[test]
fn historical_policy_aggregate_does_not_fabricate_new_observations() {
    let (evidence, _) = project_evidence(&contract(), vec![row()]).expect("current evidence");
    let mut historical = serde_json::to_value(evidence).expect("encoded evidence");
    let fields = historical.as_object_mut().expect("evidence fields");
    fields.remove("revision_r2_key");
    fields.remove("projection_policy_sha256");
    let restored: MaildeskD1EvidenceV1 =
        serde_json::from_value(historical).expect("historical compatibility");
    assert!(restored.revision_r2_key.is_none());
    assert!(restored.projection_policy_sha256.is_none());
}
