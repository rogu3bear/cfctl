use super::*;

pub(super) fn security_action_create_capability() -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        SECURITY_IP_RULE_CREATE_ID,
        "Create expiring security action",
        "POST",
        SECURITY_IP_RULE_COLLECTION_PATH,
    );
    capability.product = "IP Access rules for a zone".to_owned();
    capability.permissions = vec![
        "Firewall Services Read".to_owned(),
        "Firewall Services Write".to_owned(),
    ];
    capability.selectors = vec![SelectorV1 {
        name: "zone_id".to_owned(),
        location: "path".to_owned(),
        required: true,
        value_type: "string".to_owned(),
        description: None,
        contract: None,
    }];
    capability.request_schema = Some(json!({
        "type":"object",
        "additionalProperties":false,
        "required":["configuration","mode","notes"],
        "properties":{
            "configuration":{"type":"object"},
            "mode":{"type":"string","enum":["managed_challenge","block"]},
            "notes":{"type":"string","maxLength":500}
        },
        "x-cfctl-body-required":true
    }));
    capability.risk = RiskClass::IdentityOrOwnership;
    capability.effect = EffectClass::ReversibleWrite;
    capability.verification.strategy =
        "parent_collection_contains_created_resource_id_and_planned_fields".to_owned();
    capability.created_collection_resource = Some(CreatedCollectionResourceContractV1 {
        collection_path: SECURITY_IP_RULE_COLLECTION_PATH.to_owned(),
        identity_selector: "rule_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: SECURITY_IP_RULE_STATE_CAPABILITY_ID.to_owned(),
        delete_capability_id: "ip-access-rules-for-a-zone-delete-an-ip-access-rule".to_owned(),
        verified_response_fields: vec![
            "configuration".to_owned(),
            "mode".to_owned(),
            "notes".to_owned(),
        ],
        requires_page_number_completion: true,
    });
    capability.rollback.supported = true;
    capability.rollback.strategy = Some("delete_created_resource_by_returned_id".to_owned());
    capability.security_action = Some(SecurityActionContractV1 {
        kind: SecurityActionKindV1::CreateExpiring,
        input_schema: json!({
            "type":"object",
            "additionalProperties":false,
            "required":["actor","evidence_ref","reason","target"],
            "properties":{
                "action":{"type":"string","enum":["managed_challenge","block"]},
                "actor":{"type":"string","minLength":1,"maxLength":80},
                "evidence_ref":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},
                "expires_at":{"type":"string","format":"date-time"},
                "reason":{"type":"string","minLength":4,"maxLength":160},
                "target":{"type":"object","additionalProperties":false,"required":["type","value"],"properties":{"type":{"type":"string","enum":["ip","ip_range","asn","country"]},"value":{"type":"string"}}},
                "operator_ip":{"type":"string"},
                "confirm_broad_scope":{"type":"boolean"},
                "confirm_block":{"type":"boolean"}
            },
            "x-cfctl-body-required":true
        }),
        default_action: Some("managed_challenge".to_owned()),
        allowed_actions: vec!["managed_challenge".to_owned(), "block".to_owned()],
        allowed_target_types: vec![
            "asn".to_owned(),
            "country".to_owned(),
            "ip".to_owned(),
            "ip_range".to_owned(),
        ],
        default_ttl_seconds: 86_400,
        max_ttl_seconds: 604_800,
        current_state_capability_id: SECURITY_IP_RULE_STATE_CAPABILITY_ID.to_owned(),
        safety_profile: SecurityActionSafetyProfileV1::TelemetryDerivedStrict,
    });
    capability
}

pub(super) fn list_security_action_create_capability() -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        SECURITY_LIST_MEMBER_CREATE_ID,
        "Add expiring List member",
        "POST",
        SECURITY_LIST_MEMBER_COLLECTION_PATH,
    );
    capability.product = "Lists".to_owned();
    capability.account_scope = "account".to_owned();
    capability.permissions = vec![
        "Account Filter Lists Edit".to_owned(),
        "Account Filter Lists Read".to_owned(),
    ];
    capability.selectors = ["account_id", "list_id"]
        .into_iter()
        .map(|name| SelectorV1 {
            name: name.to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        })
        .collect();
    capability.request_schema = Some(json!({
        "type":"array",
        "minItems":1,
        "maxItems":1,
        "items":{"type":"object"},
        "x-cfctl-body-required":true
    }));
    capability.risk = RiskClass::IdentityOrOwnership;
    capability.effect = EffectClass::ReversibleWrite;
    capability.verification.strategy =
        "async_list_operation_completes_and_correlated_member_exists".to_owned();
    capability.async_collection_mutation = Some(AsyncCollectionMutationContractV1 {
        operation_status_path: "/accounts/{account_id}/rules/lists/bulk_operations/{operation_id}"
            .to_owned(),
        operation_status_capability_id: "lists-get-bulk-operation-status".to_owned(),
        operation_id_selector: "operation_id".to_owned(),
        apply_operation_id_pointer: "/operation_id".to_owned(),
        status_operation_id_pointer: "/id".to_owned(),
        status_state_pointer: "/status".to_owned(),
        pending_states: vec!["pending".to_owned(), "running".to_owned()],
        completed_state: "completed".to_owned(),
        failed_state: "failed".to_owned(),
        max_poll_attempts: 30,
        poll_interval_ms: 1_000,
        collection_path: SECURITY_LIST_MEMBER_COLLECTION_PATH.to_owned(),
        collection_capability_id: "lists-get-list-items".to_owned(),
        collection_metadata_path: "/accounts/{account_id}/rules/lists/{list_id}".to_owned(),
        collection_metadata_capability_id: "lists-get-a-list".to_owned(),
        collection_item_identity_pointer: "/id".to_owned(),
        correlation_field: Some("comment".to_owned()),
        remove_capability_id: Some(SECURITY_LIST_MEMBER_REMOVE_ID.to_owned()),
        requires_cursor_completion: true,
    });
    capability.rollback.supported = true;
    capability.rollback.strategy =
        Some("remove_async_created_list_member_by_correlated_id".to_owned());
    capability.security_action = Some(SecurityActionContractV1 {
        kind: SecurityActionKindV1::AddExpiringListMember,
        input_schema: json!({
            "type":"object",
            "additionalProperties":false,
            "required":["actor","confirm_consumer_scope","evidence_ref","reason","target"],
            "properties":{
                "action":{"type":"string","enum":["managed_challenge","block"]},
                "actor":{"type":"string","minLength":1,"maxLength":80},
                "confirm_block":{"type":"boolean"},
                "confirm_broad_scope":{"type":"boolean"},
                "confirm_consumer_scope":{"type":"boolean"},
                "evidence_ref":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},
                "expires_at":{"type":"string","format":"date-time"},
                "operator_ip":{"type":"string"},
                "reason":{"type":"string","minLength":4,"maxLength":160},
                "target":{"type":"object","additionalProperties":false,"required":["type","value"],"properties":{"type":{"type":"string","enum":["asn","hostname","ip","ip_range"]},"value":{"type":"string"}}}
            },
            "x-cfctl-body-required":true
        }),
        default_action: Some("managed_challenge".to_owned()),
        allowed_actions: vec!["managed_challenge".to_owned(), "block".to_owned()],
        allowed_target_types: vec![
            "asn".to_owned(),
            "hostname".to_owned(),
            "ip".to_owned(),
            "ip_range".to_owned(),
        ],
        default_ttl_seconds: 86_400,
        max_ttl_seconds: 604_800,
        current_state_capability_id: "lists-get-list-items".to_owned(),
        safety_profile: SecurityActionSafetyProfileV1::TelemetryDerivedStrict,
    });
    capability
}

#[test]
pub(super) fn list_security_action_requires_consumer_review_and_renders_one_correlated_item() {
    let capability = list_security_action_create_capability();
    assert!(capability.security_action_contract_supported());
    let mut input = CallInput {
        selectors: json!({
            "account_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "list_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        }),
        body: Some(json!({
            "actor":"operator@example.test",
            "confirm_consumer_scope":true,
            "evidence_ref":format!("sha256:{}", "a".repeat(64)),
            "reason":"Repeated malicious requests in a bounded telemetry window",
            "target":{"type":"hostname","value":"Example.COM"}
        })),
        ..CallInput::default()
    };
    let receipt = prepare_security_action_input(&capability, &mut input)
        .expect("safe List action")
        .expect("governance receipt");
    assert_eq!(receipt["kind"], "add_expiring_list_member");
    assert_eq!(receipt["expected_consumer_action"], "managed_challenge");
    assert_eq!(receipt["target"]["value"], "example.com");
    let wire = input
        .body
        .as_ref()
        .and_then(Value::as_array)
        .expect("wire array");
    assert_eq!(wire.len(), 1);
    assert_eq!(wire[0]["hostname"]["url_hostname"], "example.com");
    assert!(wire[0]["comment"].as_str().is_some_and(|comment| {
        comment.contains("cfctl_list_security_v1") && !comment.contains("example.com")
    }));

    let mut unreviewed = CallInput {
        selectors: input.selectors.clone(),
        body: Some(json!({
            "actor":"operator@example.test",
            "evidence_ref":format!("sha256:{}", "b".repeat(64)),
            "reason":"Suspicious source",
            "target":{"type":"ip","value":"1.1.1.1"}
        })),
        ..CallInput::default()
    };
    assert!(
        prepare_security_action_input(&capability, &mut unreviewed)
            .expect_err("consumer scope must be explicit")
            .to_string()
            .contains("confirm_consumer_scope")
    );

    let mut self_block = CallInput {
        selectors: input.selectors,
        body: Some(json!({
            "action":"block",
            "actor":"operator@example.test",
            "confirm_block":true,
            "confirm_consumer_scope":true,
            "evidence_ref":format!("sha256:{}", "c".repeat(64)),
            "operator_ip":"1.1.1.1",
            "reason":"Confirmed malicious source",
            "target":{"type":"ip","value":"1.1.1.1"}
        })),
        ..CallInput::default()
    };
    assert!(
        prepare_security_action_input(&capability, &mut self_block)
            .expect_err("self block must fail")
            .to_string()
            .contains("operator IP")
    );
}

#[test]
pub(super) fn list_security_preflight_rejects_live_duplicates_and_proves_cursor_completion() {
    let root = tempfile::tempdir().expect("runtime root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let capability = list_security_action_create_capability();
    let mut input = CallInput {
        selectors: json!({
            "account_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "list_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        }),
        body: Some(json!({
            "actor":"operator@example.test",
            "confirm_consumer_scope":true,
            "evidence_ref":format!("sha256:{}", "e".repeat(64)),
            "reason":"Repeated malicious requests in a bounded telemetry window",
            "target":{"type":"ip","value":"1.1.1.1"}
        })),
        ..CallInput::default()
    };
    let receipt = prepare_security_action_input(&capability, &mut input)
        .expect("safe List action")
        .expect("governance receipt");
    let adapter_targets = json!({"security_action":receipt});
    let metadata = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","kind":"ip"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let duplicate = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!([{
            "id":"cccccccccccccccccccccccccccccccc",
            "comment":"preexisting",
            "ip":"1.1.1.1"
        }]),
        errors: Vec::new(),
        result_info: Some(json!({"cfctl_cursor_complete":true})),
        etag: None,
        cf_ray: None,
    };
    assert!(
        list_security_action_state_receipt(
            &store,
            &capability,
            &input,
            &adapter_targets,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &metadata,
            &duplicate,
        )
        .expect_err("duplicate target must fail")
        .to_string()
        .contains("already has 1")
    );

    let empty = CloudflareResponseV1 {
        result: json!([]),
        ..duplicate
    };
    let state = list_security_action_state_receipt(
        &store,
        &capability,
        &input,
        &adapter_targets,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        &metadata,
        &empty,
    )
    .expect("complete empty List state");
    assert_eq!(state["state"]["matching_member_count"], 0);
    assert_eq!(state["list_kind"], "ip");
    assert!(!state.to_string().contains("1.1.1.1"));
}

#[test]
pub(super) fn list_rectification_uses_only_correlated_verification_identity() {
    let capability = list_security_action_create_capability();
    let evidence_ref = format!("sha256:{}", "d".repeat(64));
    let expires_at = (Utc::now() + ChronoDuration::hours(1)).to_rfc3339();
    let security_action = json!({
        "schema_version":1,
        "kind":"add_expiring_list_member",
        "actor":"operator@example.test",
        "evidence_ref":evidence_ref,
        "expires_at":expires_at,
        "reason":"Bounded suspicious source",
    });
    let selectors = json!({
        "account_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "list_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    });
    let mut plan = PlanV1::draft(
        "profile-a",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "catalog-sha",
        capability,
        json!({"selectors":selectors,"adapter":{"security_action":security_action}}),
    )
    .expect("plan");
    plan.input = serde_json::to_value(CallInput {
        selectors,
        query: json!({}),
        body: Some(json!([{
            "comment":"correlated-audit-comment",
            "ip":"1.1.1.1"
        }])),
        ..CallInput::default()
    })
    .expect("input");
    plan.refresh_hash()
        .expect("refresh hash after binding input");
    plan.approve(true, None).expect("approve");
    plan.mark_consumed().expect("consume");
    plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("attempt");
    plan.record_transaction_stage_with_artifact(
        TransactionStageV1::BoundaryResponsePersisted,
        json!({"success":true,"operation_id":"bulk-1"}),
    )
    .expect("boundary");
    plan.record_transaction_stage_with_artifact(
        TransactionStageV1::SecretSinkPersisted,
        json!({"completed":true}),
    )
    .expect("sink checkpoint");
    plan.record_transaction_stage(TransactionStageV1::VerificationAttemptPersisted)
        .expect("verification attempt");
    let member_id = "cccccccccccccccccccccccccccccccc";
    plan.record_transaction_stage_with_artifact(
        TransactionStageV1::VerificationResponsePersisted,
        json!({"state":"passed","resource_id":member_id}),
    )
    .expect("verification response");
    plan.status = PlanStatus::RectificationRequired;

    let request = compensation_request(&plan)
        .expect("request resolves")
        .expect("correlated compensation");
    assert_eq!(request.capability_id, SECURITY_LIST_MEMBER_REMOVE_ID);
    assert_eq!(request.expected_method, "DELETE");
    assert_eq!(
        request.input.body,
        Some(json!({"items":[{"id":member_id}]}))
    );
    assert_eq!(
        request
            .adapter_targets
            .pointer("/security_action/member_id"),
        Some(&json!(member_id))
    );
    assert_eq!(
        request
            .adapter_targets
            .pointer("/security_action/source_operation_id"),
        Some(&json!(plan.operation_id))
    );
}

pub(super) fn waf_security_action_create_capability() -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        SECURITY_WAF_RULE_CREATE_ID,
        "Create expiring WAF action",
        "POST",
        "/zones/{zone_id}/rulesets/{ruleset_id}/rules",
    );
    capability.product = "WAF custom rules".to_owned();
    capability.permissions = vec!["Zone WAF Read".to_owned(), "Zone WAF Write".to_owned()];
    capability.request_schema = Some(json!({
        "type":"object",
        "additionalProperties":false,
        "required":["action","description","enabled","expression","ref"],
        "properties":{
            "action":{"type":"string","enum":["block","js_challenge","log","managed_challenge","skip"]},
            "action_parameters":{"type":"object"},
            "description":{"type":"string"},
            "enabled":{"type":"boolean","const":true},
            "expression":{"type":"string"},
            "ref":{"type":"string"}
        },
        "x-cfctl-body-required":true
    }));
    capability.risk = RiskClass::IdentityOrOwnership;
    capability.effect = EffectClass::ReversibleWrite;
    capability.cost.known = true;
    capability.cost.maximum = Some(0.0);
    capability.verification.required = true;
    capability.verification.strategy =
        "parent_object_contains_created_nested_resource_by_correlation".to_owned();
    capability.created_nested_resource = Some(CreatedNestedResourceContractV1 {
        parent_path: SECURITY_WAF_RULE_PARENT_PATH.to_owned(),
        items_pointer: "/rules".to_owned(),
        identity_selector: "rule_id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        correlation_field: "ref".to_owned(),
        read_capability_id: SECURITY_WAF_RULE_STATE_CAPABILITY_ID.to_owned(),
        delete_capability_id: "deleteZoneRulesetRule".to_owned(),
        delete_path: "/zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}".to_owned(),
        verified_response_fields: vec![
            "action".to_owned(),
            "action_parameters".to_owned(),
            "description".to_owned(),
            "enabled".to_owned(),
            "expression".to_owned(),
            "ref".to_owned(),
        ],
    });
    capability.rollback.supported = true;
    capability.rollback.strategy = Some("delete_created_resource_by_returned_id".to_owned());
    capability.security_action = Some(SecurityActionContractV1 {
        kind: SecurityActionKindV1::CreateExpiring,
        input_schema: json!({
            "type":"object",
            "additionalProperties":false,
            "required":["actor","evidence_ref","reason","target"],
            "properties":{
                "action":{"type":"string","enum":["block","js_challenge","log","managed_challenge","skip"]},
                "actor":{"type":"string"},
                "evidence_ref":{"type":"string"},
                "expires_at":{"type":"string"},
                "reason":{"type":"string"},
                "target":{"type":"object","additionalProperties":false,"required":["type","value"],"properties":{"type":{"type":"string"},"value":{"type":"string"}}},
                "operator_ip":{"type":"string"},
                "confirm_broad_scope":{"type":"boolean"},
                "confirm_block":{"type":"boolean"},
                "confirm_skip":{"type":"boolean"},
                "confirm_enterprise_bot_management":{"type":"boolean"}
            },
            "x-cfctl-body-required":true
        }),
        default_action: Some("managed_challenge".to_owned()),
        allowed_actions: vec![
            "block".to_owned(),
            "js_challenge".to_owned(),
            "log".to_owned(),
            "managed_challenge".to_owned(),
            "skip".to_owned(),
        ],
        allowed_target_types: vec![
            "asn".to_owned(),
            "country".to_owned(),
            "hostname".to_owned(),
            "ip".to_owned(),
            "ip_range".to_owned(),
            "ja4".to_owned(),
            "path".to_owned(),
        ],
        default_ttl_seconds: 86_400,
        max_ttl_seconds: 604_800,
        current_state_capability_id: SECURITY_WAF_RULE_STATE_CAPABILITY_ID.to_owned(),
        safety_profile: SecurityActionSafetyProfileV1::TelemetryDerivedStrict,
    });
    capability
}

#[test]
pub(super) fn security_action_defaults_to_expiring_managed_challenge_and_compiles_exact_wire_body()
{
    let capability = security_action_create_capability();
    let mut input = CallInput {
        selectors: json!({"zone_id":"zone-a"}),
        body: Some(json!({
            "actor":"operator@example.test",
            "evidence_ref":format!("sha256:{}", "a".repeat(64)),
            "reason":"Repeated malicious requests in a bounded telemetry window",
            "target":{"type":"ip","value":"1.1.1.1"}
        })),
        ..CallInput::default()
    };
    let receipt = prepare_security_action_input(&capability, &mut input)
        .expect("safe action")
        .expect("governance receipt");
    assert_eq!(
        input.body.as_ref().and_then(|body| body.get("mode")),
        Some(&json!("managed_challenge"))
    );
    assert_eq!(
        input
            .body
            .as_ref()
            .and_then(|body| body.pointer("/configuration/value")),
        Some(&json!("1.1.1.1"))
    );
    assert_eq!(receipt.get("permanent_action"), Some(&json!(false)));
    assert_eq!(
        receipt.get("anonymous_identity_inferred"),
        Some(&json!(false))
    );
    assert!(receipt.get("expires_at").and_then(Value::as_str).is_some());
    validate_request_contract(&capability, &input).expect("compiled wire body");
}

#[test]
pub(super) fn security_action_rejects_self_block_broad_unconfirmed_scope_and_reserved_targets() {
    let capability = security_action_create_capability();
    let body = |action_target: Value| {
        json!({
            "action":"block",
            "actor":"operator@example.test",
            "evidence_ref":format!("sha256:{}", "b".repeat(64)),
            "reason":"Confirmed source abuse",
            "target":action_target,
            "operator_ip":"1.1.1.1",
            "confirm_block":true
        })
    };
    let mut self_block = CallInput {
        selectors: json!({"zone_id":"zone-a"}),
        body: Some(body(json!({"type":"ip","value":"1.1.1.1"}))),
        ..CallInput::default()
    };
    assert!(prepare_security_action_input(&capability, &mut self_block).is_err());

    let mut broad = CallInput {
        selectors: json!({"zone_id":"zone-a"}),
        body: Some(json!({
            "actor":"operator@example.test",
            "evidence_ref":format!("sha256:{}", "c".repeat(64)),
            "reason":"Suspicious ASN classification",
            "target":{"type":"asn","value":"AS13335"}
        })),
        ..CallInput::default()
    };
    assert!(prepare_security_action_input(&capability, &mut broad).is_err());

    let mut reserved = CallInput {
        selectors: json!({"zone_id":"zone-a"}),
        body: Some(json!({
            "actor":"operator@example.test",
            "evidence_ref":format!("sha256:{}", "d".repeat(64)),
            "reason":"Invalid private target",
            "target":{"type":"ip","value":"127.0.0.1"}
        })),
        ..CallInput::default()
    };
    assert!(prepare_security_action_input(&capability, &mut reserved).is_err());
}

#[test]
pub(super) fn waf_security_action_compiles_typed_target_and_rejects_unsafe_escalation() {
    let capability = waf_security_action_create_capability();
    assert!(
        capability.security_action_contract_supported(),
        "{:?}",
        capability.mutation_contract_gaps()
    );
    let mut input = CallInput {
        selectors: json!({"zone_id":"zone","ruleset_id":"ruleset"}),
        body: Some(json!({
            "actor":"operator@example.com",
            "evidence_ref":format!("sha256:{}", "a".repeat(64)),
            "reason":"suspicious repeated source",
            "target":{"type":"hostname","value":"EXAMPLE.COM"}
        })),
        ..CallInput::default()
    };
    let receipt = prepare_security_action_input(&capability, &mut input)
        .expect("bounded WAF action")
        .expect("security receipt");
    assert_eq!(receipt["kind"], "create_expiring_waf");
    assert_eq!(receipt["action"], "managed_challenge");
    assert_eq!(receipt["target"]["value"], "example.com");
    assert_eq!(
        input.body.as_ref().and_then(|body| body.get("expression")),
        Some(&json!("http.host eq \"example.com\""))
    );
    assert!(
        input
            .body
            .as_ref()
            .and_then(|body| body.get("ref"))
            .and_then(Value::as_str)
            .is_some_and(|reference| {
                reference.starts_with("cfctl_security_") && reference.len() == 39
            })
    );

    let mut unsafe_block = CallInput {
        selectors: json!({"zone_id":"zone","ruleset_id":"ruleset"}),
        body: Some(json!({
            "action":"block",
            "actor":"operator@example.com",
            "evidence_ref":format!("sha256:{}", "b".repeat(64)),
            "reason":"broad host block",
            "target":{"type":"hostname","value":"example.com"},
            "operator_ip":"8.8.8.8",
            "confirm_block":true
        })),
        ..CallInput::default()
    };
    assert!(prepare_security_action_input(&capability, &mut unsafe_block).is_err());

    let mut unsafe_skip = CallInput {
        selectors: json!({"zone_id":"zone","ruleset_id":"ruleset"}),
        body: Some(json!({
            "action":"skip",
            "actor":"operator@example.com",
            "evidence_ref":format!("sha256:{}", "c".repeat(64)),
            "reason":"skip managed WAF",
            "target":{"type":"ip","value":"8.8.4.4"}
        })),
        ..CallInput::default()
    };
    assert!(prepare_security_action_input(&capability, &mut unsafe_skip).is_err());

    let mut ja4_without_entitlement_ack = CallInput {
        selectors: json!({"zone_id":"zone","ruleset_id":"ruleset"}),
        body: Some(json!({
            "actor":"operator@example.com",
            "evidence_ref":format!("sha256:{}", "d".repeat(64)),
            "reason":"suspicious JA4 fingerprint",
            "target":{"type":"ja4","value":"t13d1516h2_8daaf6152771_02713d6af862"}
        })),
        ..CallInput::default()
    };
    assert!(prepare_security_action_input(&capability, &mut ja4_without_entitlement_ack).is_err());
}

#[test]
pub(super) fn waf_nested_creation_receipt_lifts_only_correlated_id_and_derives_exact_removal() {
    let capability = waf_security_action_create_capability();
    let reference = "cfctl_security_0123456789abcdef01234567";
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
        json!({}),
    )
    .expect("plan");
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"zone_id":"zone-a", "ruleset_id":"ruleset-a"}),
        body: Some(json!({
            "action":"managed_challenge",
            "description":"bounded action",
            "enabled":true,
            "expression":"ip.src eq 1.1.1.1",
            "ref":reference
        })),
        ..CallInput::default()
    })
    .expect("call input");
    plan.refresh_hash().expect("bind call input");
    plan.approve(true, None).expect("approve");
    plan.mark_consumed().expect("consume");
    plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("attempt");
    let response = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({
            "id":"ruleset-a",
            "rules":[{
                "id":"rule-a",
                "action":"managed_challenge",
                "description":"bounded action",
                "enabled":true,
                "expression":"ip.src eq 1.1.1.1",
                "ref":reference
            }]
        }),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let apply_evidence = EvidenceV1::new(
        EvidenceClass::Apply,
        "sha256:waf-create-apply-receipt",
        "/tmp/waf-create-apply-receipt.json",
    );
    let artifact = boundary_response_artifact(&plan, &response, Some(&apply_evidence));
    assert_eq!(artifact["resource_id"], "rule-a");
    assert!(!artifact.to_string().contains(reference));
    plan.record_transaction_stage_with_artifact(
        TransactionStageV1::BoundaryResponsePersisted,
        artifact,
    )
    .expect("response receipt");
    plan.status = PlanStatus::RectificationRequired;

    let request = compensation_request(&plan)
        .expect("request resolves")
        .expect("compensation is supported");

    assert_eq!(request.capability_id, "deleteZoneRulesetRule");
    assert_eq!(request.expected_method, "DELETE");
    assert_eq!(
        request.expected_path,
        "/zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}"
    );
    assert_eq!(
        request.input.selectors,
        json!({
            "zone_id":"zone-a",
            "ruleset_id":"ruleset-a",
            "rule_id":"rule-a"
        })
    );
    assert_eq!(request.input.query, json!({}));
    assert!(request.input.body.is_none());
    assert_eq!(request.requested_account.as_deref(), Some("account-a"));
}

#[test]
pub(super) fn wrangler_deploy_receipt_and_status_bind_the_promoted_version() {
    let version_id = "11111111-2222-3333-4444-555555555555";
    let receipt = json!({
        "stdout": format!("Uploaded jkca-web-home\nCurrent Version ID: {version_id}\n")
    });
    assert_eq!(
        wrangler_deploy_version_id(&receipt).as_deref(),
        Some(version_id)
    );

    let promoted = json!([{
        "strategy": "percentage",
        "versions": [{"version_id": version_id, "percentage": 100}]
    }]);
    assert!(wrangler_status_has_promoted_version(&promoted, version_id));

    let partial = json!([{
        "versions": [{"version_id": version_id, "percentage": 25}]
    }]);
    assert!(!wrangler_status_has_promoted_version(&partial, version_id));
    let unbound = json!({"version_id": version_id});
    assert!(!wrangler_status_has_promoted_version(&unbound, version_id));
    assert!(!wrangler_status_has_promoted_version(
        &promoted,
        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    ));
}

#[test]
pub(super) fn wrangler_worker_versions_receipts_and_targets_are_exact() {
    let version_id = "11111111-2222-3333-4444-555555555555";
    let receipt = json!({
        "stdout": format!("Uploaded leakbar\nWorker Version ID: {version_id}\n")
    });
    assert_eq!(
        wrangler_worker_version_id(&receipt).as_deref(),
        Some(version_id)
    );
    assert_eq!(
        wrangler_versions_deploy_version_id(&format!("{version_id}@100")).as_deref(),
        Some(version_id)
    );
    assert!(wrangler_versions_deploy_version_id(&format!("{version_id}@25")).is_none());
    assert!(wrangler_versions_deploy_version_id("not-a-version@100").is_none());
    assert!(wrangler_versions_deploy_version_id(&format!("{version_id}@100@100")).is_none());

    let readback = json!({
        "id": version_id,
        "annotations": {"workers/message": "release 88ef60c"}
    });
    assert!(wrangler_version_readback_matches(
        &readback,
        version_id,
        "release 88ef60c"
    ));
    assert!(!wrangler_version_readback_matches(
        &readback,
        version_id,
        "release other"
    ));
}

#[test]
pub(super) fn wrangler_worker_versions_inputs_require_absolute_config_and_full_traffic() {
    let mut upload = CapabilityV1::new(
        "wrangler.versions-upload",
        "upload",
        "POST",
        "wrangler versions upload",
    );
    upload.adapter_status = AdapterStatus::DelegatedCli;
    validate_wrangler_worker_versions_input(
        &upload,
        &json!({"config": "/srv/leakbar/web/wrangler.toml"}),
    )
    .expect("absolute upload config");
    assert!(
        validate_wrangler_worker_versions_input(&upload, &json!({"config": "web/wrangler.toml"}),)
            .is_err()
    );

    let mut deploy = upload;
    deploy.id = "wrangler.versions-deploy".to_owned();
    validate_wrangler_worker_versions_input(
        &deploy,
        &json!({
            "config": "/srv/leakbar/web/wrangler.toml",
            "argument": "11111111-2222-3333-4444-555555555555@100"
        }),
    )
    .expect("one exact full-traffic target");
    assert!(
        validate_wrangler_worker_versions_input(
            &deploy,
            &json!({
                "config": "/srv/leakbar/web/wrangler.toml",
                "argument": "11111111-2222-3333-4444-555555555555@50"
            }),
        )
        .is_err()
    );
}

#[test]
pub(super) fn wrangler_pages_artifact_admission_rejects_empty_and_symlinked_roots() {
    let mut capability = CapabilityV1::new(
        "wrangler.pages-deploy",
        "deploy Pages artifact",
        "POST",
        "wrangler pages deploy",
    );
    capability.method = "CLI".to_owned();
    capability.adapter_status = AdapterStatus::DelegatedCli;
    let root = tempfile::tempdir().expect("artifact parent");
    let artifact = root.path().join("site");
    std::fs::create_dir(&artifact).expect("empty artifact");
    let input = CallInput {
        query: json!({"argument": artifact}),
        ..CallInput::default()
    };
    assert!(
        plan_local_artifact_paths(&capability, &input).is_err(),
        "an empty Pages root cannot construct the required provider manifest"
    );

    std::fs::write(artifact.join("index.html"), b"ok").expect("artifact file");
    #[cfg(unix)]
    {
        let alias = root.path().join("site-alias");
        std::os::unix::fs::symlink(&artifact, &alias).expect("artifact root symlink");
        let input = CallInput {
            query: json!({"argument": alias}),
            ..CallInput::default()
        };
        assert!(
            plan_local_artifact_paths(&capability, &input).is_err(),
            "canonicalization must not erase Pages artifact symlink provenance"
        );
    }
}

#[test]
pub(super) fn pages_omitted_source_admission_is_hash_bound_to_exact_direct_evidence() {
    let mut capability = CapabilityV1::new(
        "wrangler.pages-deploy",
        "deploy Pages artifact",
        "POST",
        "wrangler pages deploy",
    );
    capability.method = "CLI".to_owned();
    capability.adapter_status = AdapterStatus::DelegatedCli;
    let input = CallInput {
        query: json!({
            "project_name":"aos-web",
            "branch":"main",
            "commit_hash":"0a2c0165ab176f744539be371314dea086b80933"
        }),
        ..CallInput::default()
    };
    let deployment_id = "ff88ab4a-f284-4f06-86e0-c8ae3b459b60";
    let receipt = json!({
        "schema_version":1,
        "source_capability_id":pages_deployment::PROJECT_READ_CAPABILITY_ID,
        "source_path":pages_deployment::PROJECT_DETAIL_PATH,
        "target_capability_id":"wrangler.pages-deploy",
        "account_id":"account-a",
        "project_name":"aos-web",
        "production_branch":"main",
        "source_mode":"direct_upload",
        "source_mode_basis":"omitted_source_exact_direct_deployment",
        "corroborating_deployment_id":deployment_id,
        "prior_deployment_ids":[deployment_id],
        "prior_exact_identity_count":0,
        "deployment_list_source_capability_id":pages_deployment::DEPLOYMENT_LIST_CAPABILITY_ID,
    });
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-a",
        capability,
        serde_json::to_value(&input).expect("input"),
    )
    .expect("Pages plan");
    plan.input = serde_json::to_value(input).expect("plan input");
    plan.targets = json!({
        "live_preconditions":{
            pages_deployment::PROJECT_STATE_PRECONDITION:receipt.clone()
        }
    });
    plan.precondition_hashes.insert(
        pages_deployment::PROJECT_STATE_PRECONDITION.to_owned(),
        hash_value(&receipt).expect("receipt hash"),
    );
    assert_eq!(
        required_pages_deployment_project_state_precondition(&plan)
            .expect("exact omitted-source receipt"),
        plan.precondition_hashes
            .get(pages_deployment::PROJECT_STATE_PRECONDITION)
            .map(String::as_str)
    );

    plan.targets["live_preconditions"][pages_deployment::PROJECT_STATE_PRECONDITION]["corroborating_deployment_id"] =
        Value::Null;
    assert!(
        required_pages_deployment_project_state_precondition(&plan).is_err(),
        "the omitted-source basis cannot survive without its exact deployment identity"
    );
}

#[cfg(unix)]
#[tokio::test]
pub(super) async fn wrangler_pages_boundary_requires_governed_structured_output() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().expect("boundary root");
    let program = root.path().join("wrangler");
    let id = "22222222-2222-4222-8222-222222222222";
    std::fs::write(
            &program,
            format!(
                "#!/bin/sh\nprintf '%s\\n' '{{\"type\":\"pages-deploy\",\"version\":1,\"pages_project\":\"aos-web\",\"deployment_id\":\"{id}\",\"url\":\"https://example.pages.dev\"}}' '{{\"type\":\"pages-deploy-detailed\",\"version\":1,\"pages_project\":\"aos-web\",\"deployment_id\":\"{id}\",\"url\":\"https://example.pages.dev\",\"environment\":\"production\",\"production_branch\":\"main\",\"deployment_trigger\":{{\"metadata\":{{\"commit_hash\":\"{}\"}}}}}}' > \"$WRANGLER_OUTPUT_FILE_PATH\"\n",
                "a".repeat(40)
            ),
        )
        .expect("fake Wrangler");
    let mut permissions = std::fs::metadata(&program)
        .expect("fake Wrangler metadata")
        .permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&program, permissions).expect("fake Wrangler mode");
    let cache = root.path().join("cache");
    std::fs::create_dir(&cache).expect("cache");
    let mut capability = CapabilityV1::new(
        "wrangler.pages-deploy",
        "deploy Pages artifact",
        "POST",
        "wrangler pages deploy",
    );
    capability.method = "CLI".to_owned();
    capability.adapter_status = AdapterStatus::DelegatedCli;
    let receipt = super::run_delegated_cli(
            &capability,
            &CallInput {
                selectors: json!({}),
                query: json!({"argument": root.path(), "project_name":"aos-web", "branch":"main", "commit_hash":"a".repeat(40)}),
                ..CallInput::default()
            },
            &cfctl_auth::AuthCredential::Bearer {
                token: "fixture-token".to_owned(),
            },
            Some("fixture-account"),
            &cache,
            Some(&program),
            Some(Path::new("/bin/sh")),
        )
        .await
        .expect("governed boundary receipt");
    assert_eq!(receipt["success"], true);
    assert_eq!(receipt["structured_output"]["deployment_id"], id);

    std::fs::write(&program, "#!/bin/sh\nexit 0\n").expect("missing-output Wrangler");
    let mut permissions = std::fs::metadata(&program)
        .expect("missing-output metadata")
        .permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&program, permissions).expect("missing-output mode");
    let receipt = super::run_delegated_cli(
        &capability,
        &CallInput {
            selectors: json!({}),
            query: json!({"argument": root.path()}),
            ..CallInput::default()
        },
        &cfctl_auth::AuthCredential::Bearer {
            token: "fixture-token".to_owned(),
        },
        Some("fixture-account"),
        &cache,
        Some(&program),
        Some(Path::new("/bin/sh")),
    )
    .await
    .expect("missing output remains a truthful receipt");
    assert_eq!(receipt["success"], false);
    assert!(receipt["structured_output_error"].is_string());
}
