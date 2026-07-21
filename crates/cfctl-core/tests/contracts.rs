#![allow(clippy::expect_used, clippy::unwrap_used)]

use cfctl_core::{
    AdapterStatus, AnalyticsQueryContractV1, AnalyticsQueryKindV1,
    AsyncCollectionMutationContractV1, CapabilityGuideStageV1, CapabilityGuideV1, CapabilityV1,
    CostV1, CreatedCollectionResourceContractV1, CreatedNestedResourceContractV1,
    CreatedResourceContractV1, DeletedNestedResourceContractV1, EffectClass, EntitlementProbeV1,
    EvidenceClass, EvidenceV1, GraphqlAnalyticsContractV1, GuideActionV1, GuideCloudflareEffectV1,
    GuideContractStateV1, GuideStage, GuideTopicV1, OperationalProofFreshnessV1,
    OperationalProofOutcomeV1, OperationalProofScopeV1, OperationalProofV1, OutputFormatV1,
    PaginationModeV1, PlanStatus, PlanV1, R2LogRetrievalContractV1, ResultEnvelopeV2, RiskClass,
    SamePathReadContractV1, SecurityActionContractV1, SecurityActionKindV1,
    SecurityActionSafetyProfileV1, SelectorContractV1, SelectorV1, StandingAuthorityStatus,
    StandingAuthorityV1, TimeRangeContractV1, TimestampFormatV1, TransactionStageV1,
    UpdatedResourceContractV1, guide_stages, guide_topic_document, hash_value, redact_json,
    render_guide_topic_markdown,
};
use chrono::{Duration, Utc};
use serde_json::{Value, json};

fn uncontracted_selector(name: &str, location: &str, value_type: &str) -> SelectorV1 {
    SelectorV1 {
        name: name.to_owned(),
        location: location.to_owned(),
        required: false,
        value_type: value_type.to_owned(),
        description: None,
        contract: None,
    }
}

#[test]
fn operational_proof_freshness_is_contract_and_catalog_bound() {
    let now = Utc::now();
    let evidence = EvidenceV1::new(
        EvidenceClass::LiveRead,
        "sha256:evidence",
        "/tmp/evidence.json",
    );
    let proof = OperationalProofV1::new(
        now - Duration::seconds(30),
        "telemetry.query",
        "sha256:catalog-a",
        "sha256:input",
        OperationalProofScopeV1::new(Some("default"), Some("account-a")),
        OperationalProofOutcomeV1::Succeeded,
        evidence,
    );
    assert_eq!(
        proof.freshness(now, "sha256:catalog-a", 60),
        OperationalProofFreshnessV1::Fresh
    );
    assert_eq!(
        proof.freshness(now, "sha256:catalog-a", 10),
        OperationalProofFreshnessV1::Stale
    );
    assert_eq!(
        proof.freshness(now, "sha256:catalog-b", 60),
        OperationalProofFreshnessV1::CatalogDrifted
    );
    assert_eq!(
        proof.freshness(now, "sha256:catalog-a", 0),
        OperationalProofFreshnessV1::Stale
    );

    let mut failed = proof.clone();
    failed.outcome = OperationalProofOutcomeV1::Failed;
    assert_eq!(
        failed.freshness(now, "sha256:catalog-a", 60),
        OperationalProofFreshnessV1::Failed
    );

    let mut future = proof;
    future.observed_at = now + Duration::seconds(1);
    assert_eq!(
        future.freshness(now, "sha256:catalog-a", 60),
        OperationalProofFreshnessV1::Stale
    );
}

#[test]
fn r2_log_retrieval_contract_round_trips_without_credential_values() {
    let mut capability = CapabilityV1::new(
        "logpull-retrieve-logs",
        "Retrieve logs",
        "GET",
        "/accounts/{account_id}/logs/retrieve",
    );
    capability.r2_log_retrieval = Some(R2LogRetrievalContractV1 {
        access_key_input_field: "access_key_id".to_owned(),
        secret_access_key_input_field: "secret_access_key".to_owned(),
        access_key_header: "R2-Access-Key-Id".to_owned(),
        secret_access_key_header: "R2-Secret-Access-Key".to_owned(),
        start_query_selector: "start".to_owned(),
        end_query_selector: "end".to_owned(),
        bucket_query_selector: "bucket".to_owned(),
        prefix_query_selector: "prefix".to_owned(),
        max_lookback_seconds: 315_360_000,
        max_window_seconds: 3_600,
        max_bytes: 268_435_456,
        max_timeout_seconds: 120,
        output_media_types: vec!["application/json".to_owned()],
        requires_new_mode_0600_file: true,
    });
    let encoded = serde_json::to_value(&capability).expect("serialize contract");
    assert!(encoded.get("r2_log_retrieval").is_some());
    assert!(!encoded.to_string().contains("credential-value"));
    let decoded: CapabilityV1 = serde_json::from_value(encoded).expect("deserialize contract");
    assert_eq!(decoded, capability);

    let ordinary = CapabilityV1::new("accounts-list", "List", "GET", "/accounts");
    let ordinary = serde_json::to_value(ordinary).expect("ordinary capability");
    assert!(ordinary.get("r2_log_retrieval").is_none());
}

fn workers_secret_put_capability() -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        "worker-put-script-secret",
        "Add script secret",
        "PUT",
        "/accounts/{account_id}/workers/scripts/{script_name}/secrets",
    );
    "Worker Script".clone_into(&mut capability.product);
    capability.permissions = vec!["Workers Scripts Write".to_owned()];
    capability.selectors = [
        ("account_id", json!({"maxLength":32,"type":"string"})),
        ("script_name", json!({"type":"string"})),
    ]
    .into_iter()
    .map(|(name, schema)| SelectorV1 {
        name: name.to_owned(),
        location: "path".to_owned(),
        required: true,
        value_type: "string".to_owned(),
        description: None,
        contract: Some(SelectorContractV1 {
            schema,
            query: None,
        }),
    })
    .collect();
    capability.request_schema = Some(json!({
        "type":"object",
        "oneOf":[
            {
                "type":"object",
                "required":["name","type","text"],
                "properties":{
                    "name":{"type":"string"},
                    "type":{"type":"string","enum":["secret_text"]},
                    "text":{"type":"string","writeOnly":true}
                }
            },
            {
                "type":"object",
                "required":["name","type","format","algorithm","usages"],
                "properties":{
                    "name":{"type":"string"},
                    "type":{"type":"string","enum":["secret_key"]},
                    "format":{"type":"string","enum":["raw","pkcs8","spki","jwk"]},
                    "algorithm":{"type":"object"},
                    "usages":{"type":"array","items":{"type":"string","enum":["encrypt","decrypt","sign","verify","deriveKey","deriveBits","wrapKey","unwrapKey"]}},
                    "key_base64":{"type":"string","writeOnly":true},
                    "key_jwk":{"type":"object","writeOnly":true}
                }
            }
        ],
        "x-cfctl-body-required":true
    }));
    "worker_script_secret_reports_planned_name_and_type_after_put"
        .clone_into(&mut capability.verification.strategy);
    capability.same_path_read = Some(SamePathReadContractV1 {
        path: "/accounts/{account_id}/workers/scripts/{script_name}/secrets/{secret_name}"
            .to_owned(),
        read_capability_id: "worker-get-script-secret".to_owned(),
        verified_response_fields: vec!["name".to_owned(), "type".to_owned()],
    });
    capability
}

#[test]
fn workers_secret_put_verifier_is_bound_to_exact_secret_safe_contract() {
    let capability = workers_secret_put_capability();
    assert!(capability.verification_contract_supported());

    let mut wrong_read = capability.clone();
    wrong_read
        .same_path_read
        .as_mut()
        .expect("read contract")
        .read_capability_id = "worker-list-script-secrets".to_owned();
    assert!(!wrong_read.verification_contract_supported());

    let mut leaked_text = capability.clone();
    leaked_text.request_schema.as_mut().expect("request schema")["oneOf"][0]["properties"]["text"]
        .as_object_mut()
        .expect("text schema")
        .remove("writeOnly");
    assert!(!leaked_text.verification_contract_supported());

    let mut extra_selector = capability;
    extra_selector
        .selectors
        .push(uncontracted_selector("url_encoded", "query", "boolean"));
    assert!(!extra_selector.verification_contract_supported());
}

#[test]
fn every_capability_guide_has_the_exact_fifteen_lifecycle_stages() {
    let stages = guide_stages();
    assert_eq!(stages.len(), 15);
    assert_eq!(stages.first(), Some(&GuideStage::Discover));
    assert_eq!(stages.last(), Some(&GuideStage::CloseWithEvidence));
    assert_eq!(GuideStage::CheckEntitlement.as_str(), "check_entitlement");
    assert_eq!(
        GuideStage::CloseWithEvidence.as_str(),
        "close_with_evidence"
    );
}

#[test]
fn typed_capability_guide_preserves_the_existing_json_shape() {
    let capability = CapabilityV1::new(
        "dns.records.list",
        "List DNS records",
        "GET",
        "/zones/{zone_id}/dns_records",
    );
    let guide = CapabilityGuideV1 {
        capability: capability.clone(),
        contract_state: GuideContractStateV1::Available,
        blocking_gaps: Vec::new(),
        blocked_reason: None,
        call_argv: Some(vec![
            "cfctl".to_owned(),
            "call".to_owned(),
            capability.id.clone(),
        ]),
        post_resolution_call_argv: vec![
            "cfctl".to_owned(),
            "call".to_owned(),
            capability.id.clone(),
        ],
        next_action: GuideActionV1 {
            summary: "Read live state.".to_owned(),
            argv: vec!["cfctl".to_owned(), "call".to_owned(), capability.id.clone()],
        },
        stages: vec![CapabilityGuideStageV1 {
            stage: 1,
            name: GuideStage::Discover,
            capability_id: capability.id.clone(),
            required: true,
            contract_state: GuideContractStateV1::Available,
            summary: "Inspect the catalog contract.".to_owned(),
            evidence_class: EvidenceClass::SourceConfig,
            commands: vec![vec![
                "cfctl".to_owned(),
                "catalog".to_owned(),
                "show".to_owned(),
                capability.id,
            ]],
        }],
    };

    let value = serde_json::to_value(guide).expect("typed guide JSON");
    assert_eq!(value["contract_state"], "available");
    assert_eq!(value["stages"][0]["name"], "discover");
    assert_eq!(value["stages"][0]["evidence_class"], "source_config");
    assert!(value.get("schema_version").is_none());
}

#[test]
fn system_and_standing_topics_answer_the_operator_questions_from_one_contract() {
    let system = guide_topic_document(GuideTopicV1::System);
    assert_eq!(system.schema_version, 1);
    assert_eq!(system.answers.len(), 5);
    assert!(
        system
            .flow
            .iter()
            .any(|step| step.cloudflare_effect == GuideCloudflareEffectV1::Write)
    );
    assert!(
        system
            .commands
            .iter()
            .any(|command| command == &["cfctl", "plans", "run", "<operation-id>", "--json"])
    );
    assert!(
        system
            .commands
            .iter()
            .any(|command| command == &["cfctl", "version", "--json"])
    );
    assert!(system.commands.iter().any(|command| {
        command
            == &[
                "cfctl",
                "keys",
                "permissions",
                "--account",
                "<account-id>",
                "--json",
            ]
    }));
    assert!(system.answers.iter().any(|answer| {
        answer
            .answer
            .contains("fixture directories are opt-in roots")
            && answer.answer.contains("PATH-build")
    }));

    let standing = guide_topic_document(GuideTopicV1::StandingAuthority);
    assert_eq!(standing.schema_version, 1);
    assert!(standing.summary.contains("token-lifecycle"));
    assert!(standing.answers.iter().any(|answer| {
        answer.answer.contains("durably admitted") && answer.answer.contains("never replay")
    }));
    assert!(standing.commands.iter().any(|command| {
        command
            .windows(2)
            .any(|pair| pair == ["--under-policy", "<authority-id>"])
    }));
}

#[test]
fn canonical_topic_markdown_is_complete_and_status_free() {
    let system = render_guide_topic_markdown(GuideTopicV1::System);
    assert!(system.starts_with("## How cfctl works\n"));
    assert!(system.contains("**Will this mutate Cloudflare now?**"));
    assert!(system.contains("cfctl version --json"));
    assert!(system.contains("cfctl keys permissions --account <account-id> --json"));
    assert!(system.contains("fixture directories are opt-in roots"));
    assert!(system.contains("cfctl guide <capability-id> --json"));

    let standing = render_guide_topic_markdown(GuideTopicV1::StandingAuthority);
    assert!(standing.starts_with("## Standing authority lifecycle\n"));
    assert!(standing.contains("cfctl keys policy approve <authority-id> --yes --json"));
    assert!(standing.contains("cfctl keys policy revoke <authority-id> --json"));
    assert!(!standing.contains("pending merge"));
}

#[test]
fn capability_contract_exposes_coverage_and_safety_metadata() {
    let capability = CapabilityV1::new(
        "dns.records.list",
        "List DNS records",
        "GET",
        "/zones/{zone_id}/dns_records",
    );

    assert_eq!(capability.schema_version, 1);
    assert_eq!(capability.adapter_status, AdapterStatus::DynamicApi);
    assert_eq!(capability.risk, RiskClass::Read);
    assert_eq!(capability.effect, EffectClass::ReadOnly);
    assert!(!capability.verification.required);
}

#[test]
fn mutation_contract_gaps_name_every_missing_execution_guard() {
    let capability = CapabilityV1::new(
        "dns.records.create",
        "Create DNS record",
        "POST",
        "/zones/{zone_id}/dns_records",
    );

    let gaps = capability.mutation_contract_gaps();

    assert!(gaps.iter().any(|gap| gap.contains("risk classification")));
    assert!(gaps.iter().any(|gap| gap.contains("effect classification")));
    assert!(gaps.iter().any(|gap| gap.contains("cost")));
    assert!(gaps.iter().any(|gap| gap.contains("verification")));
    assert!(gaps.iter().any(|gap| gap.contains("rollback")));
}

#[test]
fn known_incremental_cost_requires_a_valid_executable_ceiling() {
    let mut capability = CapabilityV1::new(
        "paid.widgets.create",
        "Create a paid widget",
        "POST",
        "/accounts/{account_id}/widgets",
    );
    capability.cost.incremental = true;
    capability.cost.known = true;

    for (currency, maximum, expected) in [
        (
            None,
            Some(10.0),
            "known incremental cost has no valid three-letter currency",
        ),
        (
            Some("US".to_owned()),
            Some(10.0),
            "known incremental cost has no valid three-letter currency",
        ),
        (
            Some("USD".to_owned()),
            None,
            "known incremental cost has no finite non-negative maximum",
        ),
        (
            Some("USD".to_owned()),
            Some(f64::NAN),
            "known incremental cost has no finite non-negative maximum",
        ),
        (
            Some("USD".to_owned()),
            Some(-1.0),
            "known incremental cost has no finite non-negative maximum",
        ),
    ] {
        capability.cost.currency = currency;
        capability.cost.maximum = maximum;
        assert!(
            capability
                .mutation_contract_gaps()
                .contains(&expected.to_owned())
        );
    }

    capability.cost.currency = Some("usd".to_owned());
    capability.cost.maximum = Some(10.0);
    assert!(
        capability
            .mutation_contract_gaps()
            .iter()
            .all(|gap| !gap.starts_with("known incremental cost"))
    );
}

#[test]
fn explicit_entitlement_blocker_is_enforced_without_a_plan_matrix() {
    let mut capability = CapabilityV1::new(
        "paid.widgets.create",
        "Create a paid widget",
        "POST",
        "/accounts/{account_id}/widgets",
    );
    let blocker = "live paid add-on entitlement is unresolved for the selected account".to_owned();
    capability.entitlement.blocker = Some(blocker.clone());

    assert!(capability.entitlement.plans.is_empty());
    assert!(capability.mutation_contract_gaps().contains(&blocker));

    capability.entitlement.available = Some(true);
    assert!(!capability.mutation_contract_gaps().contains(&blocker));
}

#[test]
fn mutation_contracts_reject_declared_but_unimplemented_strategies() {
    let mut capability = CapabilityV1::new(
        "widgets.create",
        "Create widget",
        "POST",
        "/accounts/{account_id}/widgets",
    );
    capability.risk = RiskClass::ScopedWrite;
    capability.effect = EffectClass::ReversibleWrite;
    capability.cost = CostV1::default();
    capability.permissions = vec!["Widgets Write".to_owned()];
    capability.verification.strategy = "phantom_readback".to_owned();
    capability.rollback.supported = true;
    capability.rollback.strategy = Some("phantom_restore".to_owned());

    let gaps = capability.mutation_contract_gaps();

    assert!(
        gaps.iter().any(|gap| {
            gap == "declared verification strategy is unsupported: phantom_readback"
        })
    );
    assert!(
        gaps.iter()
            .any(|gap| gap == "declared rollback strategy is unsupported: phantom_restore")
    );

    capability.verification.strategy =
        "api_token_details_match_created_id_and_active_status".to_owned();
    capability.rollback.strategy =
        Some("revoke_created_api_token_by_returned_id_if_downstream_installation_fails".to_owned());
    let grafted_gaps = capability.mutation_contract_gaps();
    assert!(grafted_gaps.iter().any(|gap| {
        gap == "declared verification strategy is unsupported: api_token_details_match_created_id_and_active_status"
    }));
    assert!(grafted_gaps.iter().any(|gap| {
        gap == "declared rollback strategy is unsupported: revoke_created_api_token_by_returned_id_if_downstream_installation_fails"
    }));

    capability.verification.required = false;
    capability.verification.strategy = "not_applicable".to_owned();
    capability.rollback.supported = false;
    capability.rollback.strategy = None;
    capability.rollback.warning = Some("no automatic rollback is available".to_owned());
    assert!(
        capability
            .mutation_contract_gaps()
            .iter()
            .any(|gap| { gap == "declared verification strategy is unsupported: not_applicable" })
    );
}

#[test]
fn access_service_token_refresh_verifier_is_bound_to_the_exact_expiry_contract() {
    let mut capability = CapabilityV1::new(
        "access-service-tokens-refresh-a-service-token",
        "Refresh a service token",
        "POST",
        "/accounts/{account_id}/access/service_tokens/{service_token_id}/refresh",
    );
    "Access service tokens".clone_into(&mut capability.product);
    capability.permissions = vec!["Access: Service Tokens Write".to_owned()];
    capability.selectors = vec![
        SelectorV1 {
            name: "service_token_id".to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: Some(SelectorContractV1 {
                schema: json!({"maxLength":36,"type":"string"}),
                query: None,
            }),
        },
        SelectorV1 {
            name: "account_id".to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: Some(SelectorContractV1 {
                schema: json!({"maxLength":32,"type":"string"}),
                query: None,
            }),
        },
    ];
    "access_service_token_reports_refreshed_expiration"
        .clone_into(&mut capability.verification.strategy);
    capability.same_path_read = Some(SamePathReadContractV1 {
        path: "/accounts/{account_id}/access/service_tokens/{service_token_id}".to_owned(),
        read_capability_id: "access-service-tokens-get-a-service-token".to_owned(),
        verified_response_fields: vec!["expires_at".to_owned(), "id".to_owned()],
    });

    assert!(capability.verification_contract_supported());

    let mut grafted = capability.clone();
    grafted.permissions = vec!["Account Settings Write".to_owned()];
    assert!(!grafted.verification_contract_supported());

    let mut broadened = capability;
    broadened.selectors[0]
        .contract
        .as_mut()
        .expect("service token selector contract")
        .schema["maxLength"] = json!(64);
    assert!(!broadened.verification_contract_supported());
}

#[test]
fn access_application_create_strategy_binds_a_curated_field_set() {
    let mut capability = CapabilityV1::new(
        "access-applications-add-an-application",
        "Add an Access application",
        "POST",
        "/accounts/{account_id}/access/apps",
    );
    capability.selectors = vec![SelectorV1 {
        name: "account_id".to_owned(),
        location: "path".to_owned(),
        required: true,
        value_type: "string".to_owned(),
        description: None,
        contract: None,
    }];
    // A polymorphic body with no universally required field — the union would
    // not be an honest verified set.
    capability.request_schema = Some(json!({
        "anyOf": [
            {"type":"object","required":["type"],"properties":{
                "name":{"type":"string"},"type":{"type":"string","enum":["self_hosted"]},
                "domain":{"type":"string"}}},
            {"type":"object","required":["type"],"properties":{
                "name":{"type":"string"},"type":{"type":"string","enum":["saas"]},
                "saas_app":{"type":"object"}}}
        ]
    }));
    capability.verification.strategy =
        "created_access_application_contains_planned_fields_by_returned_id".to_owned();
    capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: "/accounts/{account_id}/access/apps/{app_id}".to_owned(),
        identity_selector: "app_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        read_capability_id: "access-applications-get-an-access-application".to_owned(),
        delete_capability_id: "access-applications-delete-an-access-application".to_owned(),
        verified_response_fields: vec!["name".to_owned(), "type".to_owned()],
    });
    assert!(
        capability.verification_contract_supported(),
        "the curated Access create contract must be accepted"
    );

    // The generic union strategy must NOT accept this contract — the curated
    // fields do not equal the request-field union.
    let mut generic = capability.clone();
    generic.verification.strategy =
        "created_resource_contains_planned_fields_by_returned_id".to_owned();
    assert!(
        !generic.verification_contract_supported(),
        "the generic union binder must reject a curated subset"
    );

    // The curated strategy is identity-bound: another id cannot borrow it.
    let mut wrong_id = capability.clone();
    "some-other-create".clone_into(&mut wrong_id.id);
    assert!(!wrong_id.verification_contract_supported());

    // A non-curated field set is rejected even for the right id.
    let mut wrong_fields = capability.clone();
    if let Some(target) = wrong_fields.created_resource.as_mut() {
        target.verified_response_fields = vec!["domain".to_owned(), "name".to_owned()];
    }
    assert!(!wrong_fields.verification_contract_supported());
}

#[test]
fn worker_script_delete_strategy_is_bound_to_the_exact_settings_readback() {
    let mut capability = CapabilityV1::new(
        "worker-script-delete-worker",
        "Delete Worker",
        "DELETE",
        "/accounts/{account_id}/workers/scripts/{script_name}",
    );
    capability.selectors = ["account_id", "script_name"]
        .iter()
        .map(|name| SelectorV1 {
            name: (*name).to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        })
        .collect();
    capability.verification.strategy =
        "worker_script_settings_returns_not_found_after_delete".to_owned();
    capability.same_path_read = Some(SamePathReadContractV1 {
        path: "/accounts/{account_id}/workers/scripts/{script_name}/settings".to_owned(),
        read_capability_id: "worker-script-get-settings".to_owned(),
        verified_response_fields: Vec::new(),
    });
    assert!(
        capability.verification_contract_supported(),
        "the exact settings-readback contract must be accepted"
    );

    let mut wrong_id = capability.clone();
    "worker-script-download-worker".clone_into(&mut wrong_id.id);
    assert!(!wrong_id.verification_contract_supported());

    let mut with_force = capability.clone();
    with_force.selectors.push(SelectorV1 {
        name: "force".to_owned(),
        location: "query".to_owned(),
        required: false,
        value_type: "boolean".to_owned(),
        description: None,
        contract: None,
    });
    assert!(!with_force.verification_contract_supported());

    let mut wrong_readback = capability.clone();
    wrong_readback.same_path_read = Some(SamePathReadContractV1 {
        path: "/accounts/{account_id}/workers/scripts/{script_name}".to_owned(),
        read_capability_id: "worker-script-download-worker".to_owned(),
        verified_response_fields: Vec::new(),
    });
    assert!(!wrong_readback.verification_contract_supported());
}

#[test]
fn global_warp_restore_strategy_is_bound_to_the_exact_account_state_contract() {
    let mut capability = CapabilityV1::new(
        "devices-resilience-set-global-warp-override",
        "Set Global WARP override state",
        "POST",
        "/accounts/{account_id}/devices/resilience/disconnect",
    );
    capability.mutating = true;
    capability.account_scope = "account".to_owned();
    capability.rollback.supported = true;
    capability.rollback.strategy =
        Some("restore_global_warp_override_prior_disconnect_state".to_owned());
    capability.request_schema = Some(json!({
        "type":"object",
        "required":["disconnect"],
        "additionalProperties":false,
        "properties":{
            "disconnect":{"type":"boolean"},
            "justification":{
                "type":"string",
                "x-cfctl-verification-observable":false
            }
        }
    }));
    capability.verification.strategy =
        "same_path_result_contains_planned_fields_after_mutation".to_owned();
    capability.same_path_read = Some(SamePathReadContractV1 {
        path: "/accounts/{account_id}/devices/resilience/disconnect".to_owned(),
        read_capability_id: "devices-resilience-retrieve-global-warp-override".to_owned(),
        verified_response_fields: vec!["disconnect".to_owned()],
    });

    assert!(capability.rollback_contract_supported());

    let mut grafted = capability.clone();
    grafted.id = "widgets-set-global-state".to_owned();
    assert!(!grafted.rollback_contract_supported());

    let mut broadened = capability;
    broadened
        .request_schema
        .as_mut()
        .and_then(Value::as_object_mut)
        .and_then(|schema| schema.get_mut("properties"))
        .and_then(Value::as_object_mut)
        .expect("request properties")
        .insert("unverified".to_owned(), json!({"type":"string"}));
    assert!(!broadened.rollback_contract_supported());
}

#[test]
fn d1_read_replication_restore_strategy_is_bound_to_the_exact_database_contract() {
    let mut capability = CapabilityV1::new(
        "d1-update-partial-database",
        "Update D1 Database partially",
        "PATCH",
        "/accounts/{account_id}/d1/database/{database_id}",
    );
    capability.mutating = true;
    capability.account_scope = "account".to_owned();
    capability.product = "D1".to_owned();
    capability.rollback.supported = true;
    capability.rollback.strategy = Some("restore_d1_read_replication_prior_mode".to_owned());
    capability.request_schema = Some(json!({
        "type":"object",
        "properties":{
            "read_replication":{
                "type":"object",
                "required":["mode"],
                "properties":{
                    "mode":{"type":"string","enum":["auto","disabled"]}
                }
            }
        }
    }));
    capability.verification.strategy =
        "same_resource_contains_planned_fields_after_update".to_owned();
    capability.same_path_read = Some(SamePathReadContractV1 {
        path: "/accounts/{account_id}/d1/database/{database_id}".to_owned(),
        read_capability_id: "d1-get-database".to_owned(),
        verified_response_fields: vec!["read_replication".to_owned()],
    });

    assert!(capability.rollback_contract_supported());

    let mut put = capability.clone();
    put.id = "d1-update-database".to_owned();
    put.method = "PUT".to_owned();
    put.request_schema.as_mut().expect("request schema")["required"] = json!(["read_replication"]);
    assert!(put.rollback_contract_supported());

    let mut grafted = capability.clone();
    grafted.id = "widgets-update".to_owned();
    assert!(!grafted.rollback_contract_supported());

    let mut broadened = capability;
    broadened.request_schema.as_mut().expect("request schema")["properties"]["read_replication"]
        ["properties"]["mode"]["enum"] = json!(["auto", "disabled", "experimental"]);
    assert!(!broadened.rollback_contract_supported());
}

#[test]
fn cloudflare_tunnel_configuration_restore_strategy_is_bound_to_exact_routing_contract() {
    let request_schema = serde_json::from_str(include_str!(
        "fixtures/cloudflare-tunnel-configuration-put-request-schema.json"
    ))
    .expect("pinned Cloudflare Tunnel configuration PUT schema");
    let mut capability = CapabilityV1::new(
        "cloudflare-tunnel-configuration-put-configuration",
        "Put configuration",
        "PUT",
        "/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations",
    );
    capability.mutating = true;
    capability.account_scope = "account".to_owned();
    capability.product = "Cloudflare Tunnel Configuration".to_owned();
    capability.rollback.supported = true;
    capability.rollback.strategy =
        Some("restore_cloudflare_tunnel_configuration_prior_snapshot".to_owned());
    capability.request_schema = Some(request_schema);
    capability.verification.strategy =
        "same_path_result_contains_planned_fields_after_update".to_owned();
    capability.same_path_read = Some(SamePathReadContractV1 {
        path: "/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations".to_owned(),
        read_capability_id: "cloudflare-tunnel-configuration-get-configuration".to_owned(),
        verified_response_fields: vec!["config".to_owned()],
    });

    assert!(capability.rollback_contract_supported());

    let mut grafted = capability.clone();
    grafted.path = "/accounts/{account_id}/cfd_tunnel/{other_id}/configurations".to_owned();
    assert!(!grafted.rollback_contract_supported());

    let mut broadened = capability.clone();
    broadened.request_schema.as_mut().expect("request schema")["properties"]["config"]["properties"]
        ["ingress"]["items"]["properties"]["unreviewed"] = json!({"type":"string"});
    assert!(!broadened.rollback_contract_supported());

    let mut wrong_read = capability;
    wrong_read
        .same_path_read
        .as_mut()
        .expect("same-path read")
        .read_capability_id = "widgets-get-configuration".to_owned();
    assert!(!wrong_read.rollback_contract_supported());
}

#[test]
fn warp_connector_configuration_restore_strategy_is_bound_to_exact_mesh_ha_contract() {
    let request_schema = serde_json::from_str(include_str!(
        "fixtures/warp-connector-configuration-update-request-schema.json"
    ))
    .expect("pinned WARP Connector configuration schema");
    let mut capability = CapabilityV1::new(
        "cloudflare-tunnel-configuration-update-warp-connector-configuration",
        "Update WARP Connector configuration",
        "PUT",
        "/accounts/{account_id}/warp_connector/{tunnel_id}/configurations",
    );
    capability.mutating = true;
    capability.account_scope = "account".to_owned();
    capability.product = "Cloudflare Tunnel Configuration".to_owned();
    capability.rollback.supported = true;
    capability.rollback.strategy =
        Some("restore_warp_connector_configuration_prior_snapshot".to_owned());
    capability.request_schema = Some(request_schema);
    capability.verification.strategy =
        "same_path_result_contains_planned_fields_after_update".to_owned();
    capability.same_path_read = Some(SamePathReadContractV1 {
        path: "/accounts/{account_id}/warp_connector/{tunnel_id}/configurations".to_owned(),
        read_capability_id: "cloudflare-tunnel-configuration-get-warp-connector-configuration"
            .to_owned(),
        verified_response_fields: vec!["config".to_owned(), "ha_mode".to_owned()],
    });

    assert!(capability.rollback_contract_supported());

    let mut grafted = capability.clone();
    grafted.id = "widgets-update".to_owned();
    assert!(!grafted.rollback_contract_supported());

    let mut broadened = capability.clone();
    broadened.request_schema.as_mut().expect("request schema")["properties"]["config"]["oneOf"]
        [1]["properties"]["routing_table"] = json!({"type":"string"});
    assert!(!broadened.rollback_contract_supported());

    let mut wrong_read = capability;
    wrong_read
        .same_path_read
        .as_mut()
        .expect("same-path read")
        .verified_response_fields = vec!["ha_mode".to_owned()];
    assert!(!wrong_read.rollback_contract_supported());
}

#[test]
fn web_analytics_rum_restore_strategy_is_bound_to_exact_toggle_contract() {
    let request_schema = serde_json::from_str(include_str!(
        "fixtures/web-analytics-rum-toggle-request-schema.json"
    ))
    .expect("pinned Web Analytics RUM toggle schema");
    let mut capability = CapabilityV1::new(
        "web-analytics-toggle-rum",
        "Toggle RUM on/off for a zone",
        "PATCH",
        "/zones/{zone_id}/settings/rum",
    );
    capability.mutating = true;
    capability.account_scope = "zone".to_owned();
    capability.product = "Web Analytics".to_owned();
    capability.rollback.supported = true;
    capability.rollback.strategy = Some("restore_web_analytics_rum_prior_value".to_owned());
    capability.request_schema = Some(request_schema);
    capability.verification.strategy =
        "same_path_result_contains_planned_fields_after_update".to_owned();
    capability.same_path_read = Some(SamePathReadContractV1 {
        path: "/zones/{zone_id}/settings/rum".to_owned(),
        read_capability_id: "web-analytics-get-rum-status".to_owned(),
        verified_response_fields: vec!["value".to_owned()],
    });

    assert!(capability.rollback_contract_supported());

    let mut grafted = capability.clone();
    grafted.id = "widgets-update".to_owned();
    assert!(!grafted.rollback_contract_supported());

    let mut broadened = capability.clone();
    broadened.request_schema.as_mut().expect("request schema")["properties"]["value"]["enum"] =
        json!(["on", "off", "manual"]);
    assert!(!broadened.rollback_contract_supported());

    let mut wrong_read = capability;
    wrong_read
        .same_path_read
        .as_mut()
        .expect("same-path read")
        .read_capability_id = "settings-get".to_owned();
    assert!(!wrong_read.rollback_contract_supported());
}

#[test]
fn dns_record_restore_strategy_is_bound_to_the_exact_official_update_contract() {
    let request_schema = serde_json::from_str(include_str!(
        "fixtures/dns-record-update-request-schema.json"
    ))
    .expect("pinned DNS record update schema");
    let mut capability = CapabilityV1::new(
        "dns-records-for-a-zone-update-dns-record",
        "Overwrite DNS Record",
        "PUT",
        "/zones/{zone_id}/dns_records/{dns_record_id}",
    );
    capability.mutating = true;
    capability.account_scope = "zone".to_owned();
    capability.product = "DNS Records for a Zone".to_owned();
    capability.rollback.supported = true;
    capability.rollback.strategy = Some("restore_dns_record_prior_snapshot_with_put".to_owned());
    capability.request_schema = Some(request_schema);
    capability.verification.strategy = "dns_record_details_match_planned_id_and_fields".to_owned();
    capability.same_path_read = Some(SamePathReadContractV1 {
        path: "/zones/{zone_id}/dns_records/{dns_record_id}".to_owned(),
        read_capability_id: "dns-records-for-a-zone-dns-record-details".to_owned(),
        verified_response_fields: vec![
            "comment".to_owned(),
            "content".to_owned(),
            "data".to_owned(),
            "name".to_owned(),
            "priority".to_owned(),
            "private_routing".to_owned(),
            "proxied".to_owned(),
            "settings".to_owned(),
            "tags".to_owned(),
            "ttl".to_owned(),
            "type".to_owned(),
        ],
    });

    assert!(capability.rollback_contract_supported());

    let mut patch = capability.clone();
    patch.id = "dns-records-for-a-zone-patch-dns-record".to_owned();
    patch.method = "PATCH".to_owned();
    assert!(patch.rollback_contract_supported());

    let mut grafted = capability.clone();
    grafted.path = "/zones/{zone_id}/widgets/{dns_record_id}".to_owned();
    assert!(!grafted.rollback_contract_supported());

    let mut broadened = capability;
    broadened
        .request_schema
        .as_mut()
        .and_then(Value::as_object_mut)
        .expect("request schema")
        .insert("x-unreviewed".to_owned(), json!(true));
    assert!(!broadened.rollback_contract_supported());
}

#[test]
fn generic_same_path_restore_is_bound_to_an_exact_verified_update() {
    let mut capability = CapabilityV1::new(
        "workers-observability-settings-update",
        "Update observability",
        "PATCH",
        "/accounts/{account_id}/workers/scripts/{script_name}/script-settings",
    );
    capability.mutating = true;
    capability.selectors = ["account_id", "script_name"]
        .iter()
        .map(|name| SelectorV1 {
            name: (*name).to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        })
        .collect();
    capability.request_schema = Some(json!({
        "type":"object",
        "additionalProperties":false,
        "minProperties":1,
        "properties":{"observability":{"type":"object"}}
    }));
    capability.verification.strategy =
        "same_path_result_contains_planned_fields_after_update".to_owned();
    capability.same_path_read = Some(SamePathReadContractV1 {
        path: capability.path.clone(),
        read_capability_id: "worker-script-settings-get-settings".to_owned(),
        verified_response_fields: vec!["observability".to_owned()],
    });
    capability.rollback.supported = true;
    capability.rollback.strategy = Some("restore_same_path_prior_snapshot".to_owned());

    assert!(capability.verification_contract_supported());
    assert!(capability.rollback_contract_supported());

    let mut query_broadened = capability.clone();
    query_broadened.selectors.push(SelectorV1 {
        name: "unsafe".to_owned(),
        location: "query".to_owned(),
        required: false,
        value_type: "string".to_owned(),
        description: None,
        contract: None,
    });
    assert!(!query_broadened.rollback_contract_supported());

    let mut unverified = capability;
    unverified.verification.strategy = "post_change_read_or_operation_specific_verifier".to_owned();
    assert!(!unverified.rollback_contract_supported());
}

#[test]
fn discriminated_request_paths_preserve_dns_branch_specific_nested_fields() {
    let mut capability = CapabilityV1::new("dns-update", "DNS update", "PUT", "/dns");
    capability.request_schema = Some(
        serde_json::from_str(include_str!(
            "fixtures/dns-record-update-request-schema.json"
        ))
        .expect("pinned DNS record update schema"),
    );

    let branches = capability
        .request_object_paths_by_discriminator("type")
        .expect("bounded discriminated request paths");
    assert_eq!(branches.len(), 21);
    assert_eq!(
        branches.get("A").expect("A paths"),
        &vec![
            "comment".to_owned(),
            "content".to_owned(),
            "name".to_owned(),
            "private_routing".to_owned(),
            "proxied".to_owned(),
            "settings.ipv4_only".to_owned(),
            "settings.ipv6_only".to_owned(),
            "tags".to_owned(),
            "ttl".to_owned(),
            "type".to_owned(),
        ]
    );
    assert!(
        branches
            .get("CNAME")
            .expect("CNAME paths")
            .contains(&"settings.flatten_cname".to_owned())
    );
    assert!(
        branches
            .get("LOC")
            .expect("LOC paths")
            .contains(&"data.precision_vert".to_owned())
    );
    assert_eq!(
        branches
            .get("TXT")
            .expect("TXT paths")
            .iter()
            .filter(|path| path.starts_with("data."))
            .count(),
        0
    );
}

#[test]
fn same_path_post_state_contract_requires_the_exact_post_method_and_readback() {
    let mut capability = CapabilityV1::new(
        "settings-apply",
        "Apply settings",
        "POST",
        "/accounts/{account_id}/settings/example",
    );
    capability.verification.strategy =
        "same_path_result_contains_planned_fields_after_mutation".to_owned();
    capability.request_schema = Some(json!({
        "type":"object",
        "properties":{"enabled":{"type":"boolean"},"mode":{"type":"string"}}
    }));
    capability.same_path_read = Some(SamePathReadContractV1 {
        path: capability.path.clone(),
        read_capability_id: "settings-get".to_owned(),
        verified_response_fields: vec!["enabled".to_owned(), "mode".to_owned()],
    });

    assert!(capability.verification_contract_supported());

    capability.method = "PUT".to_owned();
    assert!(!capability.verification_contract_supported());

    capability.method = "POST".to_owned();
    capability
        .same_path_read
        .as_mut()
        .expect("same-path contract")
        .verified_response_fields = vec!["mode".to_owned()];
    assert!(!capability.verification_contract_supported());
}

#[test]
fn same_path_state_contract_can_omit_an_explicitly_unobservable_request_field() {
    let mut capability = CapabilityV1::new(
        "settings-apply",
        "Apply settings",
        "POST",
        "/accounts/{account_id}/settings/example",
    );
    capability.verification.strategy =
        "same_path_result_contains_planned_fields_after_mutation".to_owned();
    capability.request_schema = Some(json!({
        "type":"object",
        "properties":{
            "enabled":{"type":"boolean"},
            "justification":{
                "type":"string",
                "x-cfctl-verification-observable":false
            }
        }
    }));
    capability.same_path_read = Some(SamePathReadContractV1 {
        path: capability.path.clone(),
        read_capability_id: "settings-get".to_owned(),
        verified_response_fields: vec!["enabled".to_owned()],
    });

    assert_eq!(
        capability.verifiable_request_object_fields(),
        Some(vec!["enabled".to_owned()])
    );
    assert!(capability.request_object_field_is_verification_omitted("justification"));
    assert!(capability.verification_contract_supported());

    capability.request_schema.as_mut().expect("request schema")["properties"]["justification"]
        .as_object_mut()
        .expect("justification schema")
        .remove("x-cfctl-verification-observable");
    assert!(!capability.request_object_field_is_verification_omitted("justification"));
    assert!(!capability.verification_contract_supported());
}

#[test]
fn request_field_can_bind_an_explicit_response_field_name() {
    let mut capability = CapabilityV1::new(
        "r2-create-bucket",
        "Create Bucket",
        "POST",
        "/accounts/{account_id}/r2/buckets",
    );
    capability.request_schema = Some(json!({
        "type":"object",
        "properties":{
            "name":{"type":"string"},
            "storageClass":{
                "type":"string",
                "x-cfctl-verification-response-field":"storage_class"
            }
        }
    }));

    assert_eq!(
        capability.request_object_field_verification_response_field("storageClass"),
        Some("storage_class".to_owned())
    );
    assert_eq!(
        capability.request_object_field_verification_response_field("name"),
        None
    );
}

#[test]
fn updated_resource_contract_rejects_noncanonical_field_allowlists() {
    let mut capability = CapabilityV1::new(
        "widgets-update",
        "Update widget",
        "PATCH",
        "/accounts/{account_id}/widgets/{widget_id}",
    );
    capability.verification.strategy =
        "parent_collection_item_contains_planned_fields_after_update".to_owned();
    capability.request_schema = Some(json!({
        "type": "object",
        "properties": {
            "name": {"type":"string"},
            "enabled": {"type":"boolean"},
            "secret": {"type":"string", "writeOnly":true}
        }
    }));
    capability.updated_resource = Some(UpdatedResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        verified_response_fields: vec!["name".to_owned(), "enabled".to_owned()],
        requires_page_number_completion: false,
    });

    assert!(!capability.verification_contract_supported());

    capability
        .updated_resource
        .as_mut()
        .expect("updated-resource contract")
        .verified_response_fields = vec!["enabled".to_owned(), "name".to_owned()];
    assert!(capability.verification_contract_supported());

    capability
        .updated_resource
        .as_mut()
        .expect("updated-resource contract")
        .verified_response_fields
        .push("secret".to_owned());
    assert!(!capability.verification_contract_supported());
    capability
        .updated_resource
        .as_mut()
        .expect("updated-resource contract")
        .verified_response_fields
        .pop();

    capability
        .selectors
        .push(uncontracted_selector("mode", "query", "string"));
    assert!(!capability.verification_contract_supported());

    capability.selectors.clear();
    capability.request_schema = Some(json!({
        "type": "object",
        "properties": {
            "name": {"type":"string"},
            "enabled": {"type":"boolean"},
            "hidden": {"type":"boolean"}
        }
    }));
    assert!(!capability.verification_contract_supported());
}

#[test]
fn deleted_resource_contract_rejects_body_and_nonpath_controls() {
    let mut capability = CapabilityV1::new(
        "widgets-delete",
        "Delete widget",
        "DELETE",
        "/accounts/{account_id}/widgets/{widget_id}",
    );
    capability.verification.strategy = "parent_collection_omits_deleted_resource_id".to_owned();
    capability.deleted_resource = Some(cfctl_core::DeletedResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        requires_page_number_completion: false,
    });
    assert!(capability.verification_contract_supported());

    capability.request_schema = Some(json!({"type":"object"}));
    assert!(!capability.verification_contract_supported());

    capability.request_schema = None;
    capability
        .selectors
        .push(uncontracted_selector("cascade", "query", "boolean"));
    assert!(!capability.verification_contract_supported());
}

#[test]
fn collection_resource_contracts_require_an_exact_safe_identity_pointer() {
    let mut deletion = CapabilityV1::new(
        "widgets-delete",
        "Delete widget",
        "DELETE",
        "/accounts/{account_id}/widgets/{slug}",
    );
    deletion.verification.strategy = "parent_collection_omits_deleted_resource_id".to_owned();
    deletion.deleted_resource = Some(cfctl_core::DeletedResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "slug".to_owned(),
        response_item_identity_pointer: "/slug".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        requires_page_number_completion: false,
    });
    assert!(deletion.verification_contract_supported());

    deletion
        .deleted_resource
        .as_mut()
        .expect("deleted-resource contract")
        .response_item_identity_pointer = "/id".to_owned();
    assert!(!deletion.verification_contract_supported());

    let mut update = CapabilityV1::new(
        "widgets-update",
        "Update widget",
        "PATCH",
        "/accounts/{account_id}/widgets/{slug}",
    );
    update.verification.strategy =
        "parent_collection_item_contains_planned_fields_after_update".to_owned();
    update.request_schema = Some(json!({
        "type": "object",
        "properties": {"name": {"type": "string"}}
    }));
    update.updated_resource = Some(UpdatedResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "slug".to_owned(),
        response_item_identity_pointer: "/slug".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
        requires_page_number_completion: false,
    });
    assert!(update.verification_contract_supported());

    update
        .updated_resource
        .as_mut()
        .expect("updated-resource contract")
        .response_item_identity_pointer = "/slug/nested".to_owned();
    assert!(!update.verification_contract_supported());
}

#[test]
fn same_path_read_contracts_require_hash_bound_canonical_fields() {
    let mut update = CapabilityV1::new(
        "widgets-update",
        "Update widget",
        "PATCH",
        "/accounts/{account_id}/widgets/{widget_id}",
    );
    update.verification.strategy = "same_resource_contains_planned_fields_after_update".to_owned();
    update.request_schema = Some(json!({
        "type": "object",
        "properties": {
            "name": {"type":"string"},
            "enabled": {"type":"boolean"},
            "secret": {"type":"string", "writeOnly":true}
        }
    }));
    update.same_path_read = Some(SamePathReadContractV1 {
        path: update.path.clone(),
        read_capability_id: "widgets-get".to_owned(),
        verified_response_fields: vec!["name".to_owned(), "enabled".to_owned()],
    });

    assert!(!update.verification_contract_supported());

    update
        .same_path_read
        .as_mut()
        .expect("same-path contract")
        .verified_response_fields = vec!["enabled".to_owned(), "name".to_owned()];
    assert!(update.verification_contract_supported());

    update
        .request_schema
        .as_mut()
        .and_then(serde_json::Value::as_object_mut)
        .expect("request schema")
        .remove("type");
    assert!(update.verification_contract_supported());
    update.request_schema.as_mut().expect("request schema")["type"] = json!("string");
    assert!(!update.verification_contract_supported());
    update.request_schema.as_mut().expect("request schema")["type"] = json!("object");

    update
        .same_path_read
        .as_mut()
        .expect("same-path contract")
        .verified_response_fields
        .push("secret".to_owned());
    assert!(!update.verification_contract_supported());
    update
        .same_path_read
        .as_mut()
        .expect("same-path contract")
        .verified_response_fields
        .pop();

    update.selectors.push(uncontracted_selector(
        "cf-r2-jurisdiction",
        "header",
        "string",
    ));
    assert!(!update.verification_contract_supported());

    update.product = "R2 Bucket".to_owned();
    assert!(update.verification_contract_supported());

    update.selectors[0].name = "x-unbound-routing-control".to_owned();
    assert!(!update.verification_contract_supported());
    update.selectors.clear();

    let mut legacy_value = serde_json::to_value(&update).expect("serialize capability");
    legacy_value
        .as_object_mut()
        .expect("capability object")
        .remove("same_path_read");
    let legacy: CapabilityV1 =
        serde_json::from_value(legacy_value).expect("deserialize legacy capability");
    assert!(!legacy.verification_contract_supported());
}

#[test]
fn same_path_delete_contracts_accept_only_hash_bound_empty_bodies_and_routing_headers() {
    let mut delete = CapabilityV1::new(
        "widgets-delete",
        "Delete widget",
        "DELETE",
        "/accounts/{account_id}/widgets/{widget_id}",
    );
    delete.verification.strategy = "same_resource_returns_not_found_after_delete".to_owned();
    delete.same_path_read = Some(SamePathReadContractV1 {
        path: delete.path.clone(),
        read_capability_id: "widgets-get".to_owned(),
        verified_response_fields: Vec::new(),
    });
    assert!(delete.verification_contract_supported());

    delete.request_schema = Some(json!({
        "type":"object",
        "properties":{},
        "additionalProperties":false,
        "x-cfctl-body-required":true
    }));
    assert!(delete.verification_contract_supported());
    delete.request_schema.as_mut().expect("request schema")["properties"] =
        json!({"cascade":{"type":"boolean"}});
    assert!(!delete.verification_contract_supported());
    delete.request_schema = None;

    delete.product = "R2 Object".to_owned();
    delete.selectors.push(uncontracted_selector(
        "cf-r2-jurisdiction",
        "header",
        "string",
    ));
    assert!(delete.verification_contract_supported());

    delete
        .same_path_read
        .as_mut()
        .expect("same-path contract")
        .verified_response_fields = vec!["id".to_owned()];
    assert!(!delete.verification_contract_supported());
}

#[test]
fn same_path_read_contracts_union_all_of_object_fields_without_exposing_secrets() {
    let mut update = CapabilityV1::new(
        "widgets-update",
        "Update widget",
        "PATCH",
        "/accounts/{account_id}/widgets/{widget_id}",
    );
    update.verification.strategy = "same_resource_contains_planned_fields_after_update".to_owned();
    update.request_schema = Some(json!({
        "allOf": [
            {
                "type": "object",
                "properties": {
                    "name": {"type":"string"},
                    "secret": {"type":"string", "writeOnly":true},
                    "shared": {"type":"string", "writeOnly":true}
                }
            },
            {
                "properties": {
                    "enabled": {"type":"boolean"},
                    "shared": {"type":"string"}
                }
            }
        ]
    }));
    update.same_path_read = Some(SamePathReadContractV1 {
        path: update.path.clone(),
        read_capability_id: "widgets-get".to_owned(),
        verified_response_fields: vec![
            "enabled".to_owned(),
            "name".to_owned(),
            "shared".to_owned(),
        ],
    });

    assert_eq!(
        update.verifiable_request_object_fields(),
        Some(vec![
            "enabled".to_owned(),
            "name".to_owned(),
            "shared".to_owned(),
        ])
    );
    assert!(update.request_object_field_is_write_only("secret"));
    assert!(!update.request_object_field_is_write_only("shared"));
    assert!(update.verification_contract_supported());

    update
        .same_path_read
        .as_mut()
        .expect("same-path contract")
        .verified_response_fields
        .push("secret".to_owned());
    assert!(!update.verification_contract_supported());
    update
        .same_path_read
        .as_mut()
        .expect("same-path contract")
        .verified_response_fields
        .pop();

    update.request_schema.as_mut().expect("request schema")["allOf"][1]["type"] = json!("string");
    assert_eq!(update.verifiable_request_object_fields(), None);
    assert!(!update.verification_contract_supported());
}

#[test]
fn same_path_read_contracts_union_object_alternative_fields() {
    let mut update = CapabilityV1::new(
        "widgets-update",
        "Update widget",
        "PATCH",
        "/accounts/{account_id}/widgets/{widget_id}",
    );
    update.verification.strategy = "same_resource_contains_planned_fields_after_update".to_owned();
    update.same_path_read = Some(SamePathReadContractV1 {
        path: update.path.clone(),
        read_capability_id: "widgets-get".to_owned(),
        verified_response_fields: Vec::new(),
    });

    update.request_schema = Some(json!({
        "oneOf": [
            {"type":"object", "properties":{"name":{"type":"string"}}},
            {"type":"object", "properties":{"enabled":{"type":"boolean"}}}
        ]
    }));
    update
        .same_path_read
        .as_mut()
        .expect("same-path contract")
        .verified_response_fields = vec!["enabled".to_owned(), "name".to_owned()];
    assert_eq!(
        update.verifiable_request_object_fields(),
        Some(vec!["enabled".to_owned(), "name".to_owned()])
    );
    assert!(update.verification_contract_supported());

    update.request_schema = Some(json!({
        "properties": {"kind":{"type":"string"}},
        "oneOf": [
            {"type":"object", "properties":{"kind":{"enum":["ip"]},"name":{"type":"string"}}},
            {"type":"object", "properties":{"kind":{"enum":["identity"]},"email":{"type":"string"}}}
        ]
    }));
    assert_eq!(
        update.verifiable_request_object_fields(),
        Some(vec![
            "email".to_owned(),
            "kind".to_owned(),
            "name".to_owned()
        ])
    );

    update.request_schema = Some(json!({
        "anyOf": [
            {
                "type":"object",
                "properties": {
                    "name":{"type":"string"},
                    "secret":{"type":"string", "writeOnly":true}
                }
            },
            {
                "type":"object",
                "properties": {
                    "enabled":{"type":"boolean"},
                    "token":{"type":"string", "writeOnly":true}
                }
            }
        ]
    }));
    assert_eq!(
        update.verifiable_request_object_fields(),
        Some(vec!["enabled".to_owned(), "name".to_owned()])
    );
    assert!(update.request_object_field_is_write_only("secret"));
    assert!(update.request_object_field_is_write_only("token"));

    update.request_schema = Some(json!({
        "properties": {"kind":{"type":"string"}},
        "oneOf": [
            {"type":"object", "properties":{"kind":{"enum":["object"]}}},
            {"type":"string"}
        ]
    }));
    assert_eq!(
        update.verifiable_request_object_fields(),
        Some(vec!["kind".to_owned()])
    );

    update.request_schema = Some(json!({
        "oneOf": [
            {"type":"object", "properties":{"kind":{"enum":["object"]}}},
            {"type":"string"}
        ]
    }));
    assert_eq!(update.verifiable_request_object_fields(), None);
}

#[test]
fn request_object_field_extraction_is_width_bounded() {
    let branches = (0..5_000)
        .map(|value| {
            json!({
                "type":"object",
                "properties":{"value":{"const":value}}
            })
        })
        .collect::<Vec<_>>();
    let mut capability = CapabilityV1::new(
        "widgets-update",
        "Update widget",
        "PATCH",
        "/accounts/{account_id}/widgets/{widget_id}",
    );
    capability.request_schema = Some(json!({
        "properties":{
            "direct":{"type":"string"},
            "secret":{"type":"string", "writeOnly":true}
        },
        "oneOf":branches
    }));

    assert_eq!(capability.request_object_fields(), None);
    assert_eq!(capability.verifiable_request_object_fields(), None);
    assert!(!capability.request_object_field_is_write_only("secret"));
}

fn worker_tail_create_capability() -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        "worker-tail-logs-start-tail",
        "Start Tail",
        "POST",
        "/accounts/{account_id}/workers/scripts/{script_name}/tails",
    );
    "Worker Tail Logs".clone_into(&mut capability.product);
    "account".clone_into(&mut capability.account_scope);
    capability.permissions = vec![
        "Workers Tail Read".to_owned(),
        "Workers Scripts Write".to_owned(),
    ];
    capability.selectors = ["account_id", "script_name"]
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
    capability.risk = RiskClass::SecretSensitive;
    capability.effect = EffectClass::ReversibleWrite;
    capability.verification.required = true;
    "worker_tail_collection_contains_created_lease_id"
        .clone_into(&mut capability.verification.strategy);
    capability.created_collection_resource = Some(CreatedCollectionResourceContractV1 {
        collection_path: capability.path.clone(),
        identity_selector: "id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "worker-tail-logs-list-tails".to_owned(),
        delete_capability_id: "worker-tail-logs-delete-tail".to_owned(),
        verified_response_fields: Vec::new(),
        requires_page_number_completion: false,
    });
    capability.rollback.supported = true;
    capability.rollback.strategy = Some("delete_created_resource_by_returned_id".to_owned());
    capability
}

#[test]
fn worker_tail_lease_verifier_and_rollback_are_exact_and_bodyless() {
    let capability = worker_tail_create_capability();
    assert!(capability.verification_contract_supported());
    assert!(capability.rollback_contract_supported());

    let mut grafted = capability.clone();
    grafted.product = "Workers Scripts".to_owned();
    assert!(!grafted.verification_contract_supported());

    let mut body_added = capability.clone();
    body_added.request_schema = Some(json!({"type":"object"}));
    assert!(!body_added.verification_contract_supported());

    let mut readback_fields_invented = capability.clone();
    readback_fields_invented
        .created_collection_resource
        .as_mut()
        .expect("tail collection contract")
        .verified_response_fields = vec!["expires_at".to_owned()];
    assert!(!readback_fields_invented.verification_contract_supported());

    let mut broad_delete = capability;
    broad_delete
        .created_collection_resource
        .as_mut()
        .expect("tail collection contract")
        .delete_capability_id = "workers-delete-all-tails".to_owned();
    assert!(!broad_delete.rollback_contract_supported());
}

#[test]
fn created_resource_contract_rejects_noncanonical_field_allowlists() {
    let mut capability = CapabilityV1::new(
        "widgets-create",
        "Create widget",
        "POST",
        "/accounts/{account_id}/widgets",
    );
    capability.verification.strategy =
        "created_resource_contains_planned_fields_by_returned_id".to_owned();
    capability.request_schema = Some(json!({
        "type": "object",
        "properties": {
            "name": {"type":"string"},
            "enabled": {"type":"boolean"},
            "secret": {"type":"string", "writeOnly":true}
        }
    }));
    capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: "/accounts/{account_id}/widgets/{widget_id}".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-get".to_owned(),
        delete_capability_id: "widgets-delete".to_owned(),
        verified_response_fields: vec!["name".to_owned(), "enabled".to_owned()],
    });

    assert!(!capability.verification_contract_supported());

    capability
        .created_resource
        .as_mut()
        .expect("created-resource contract")
        .verified_response_fields = vec!["enabled".to_owned(), "name".to_owned()];
    assert!(capability.verification_contract_supported());

    capability
        .created_resource
        .as_mut()
        .expect("created-resource contract")
        .verified_response_fields
        .push("secret".to_owned());
    assert!(!capability.verification_contract_supported());
    capability
        .created_resource
        .as_mut()
        .expect("created-resource contract")
        .verified_response_fields
        .pop();
    capability.rollback.supported = true;
    capability.rollback.strategy = Some("delete_created_resource_by_returned_id".to_owned());
    assert!(capability.rollback_contract_supported());

    let mut legacy_value = serde_json::to_value(&capability).expect("serialize capability");
    legacy_value["created_resource"]
        .as_object_mut()
        .expect("created-resource object")
        .remove("verified_response_fields");
    let legacy: CapabilityV1 =
        serde_json::from_value(legacy_value).expect("deserialize legacy capability");
    assert!(!legacy.verification_contract_supported());
    assert!(!legacy.rollback_contract_supported());
}

#[test]
fn created_resource_contracts_require_exact_identity_pointers() {
    let mut exact = CapabilityV1::new(
        "widgets-create",
        "Create widget",
        "POST",
        "/accounts/{account_id}/widgets",
    );
    exact.verification.strategy =
        "created_resource_contains_planned_fields_by_returned_id".to_owned();
    exact.request_schema = Some(json!({
        "type":"object",
        "properties":{"name":{"type":"string"}}
    }));
    exact.created_resource = Some(CreatedResourceContractV1 {
        detail_path: "/accounts/{account_id}/widgets/{slug}".to_owned(),
        identity_selector: "slug".to_owned(),
        response_result_identity_pointer: "/slug".to_owned(),
        read_capability_id: "widgets-get".to_owned(),
        delete_capability_id: "widgets-delete".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
    });
    assert!(exact.verification_contract_supported());

    exact
        .created_resource
        .as_mut()
        .expect("created-resource contract")
        .response_result_identity_pointer = "/id".to_owned();
    assert!(!exact.verification_contract_supported());

    let mut collection = CapabilityV1::new(
        "widgets-create",
        "Create widget",
        "POST",
        "/accounts/{account_id}/widgets",
    );
    collection.verification.strategy =
        "parent_collection_contains_created_resource_id_and_planned_fields".to_owned();
    collection.request_schema = exact.request_schema.clone();
    collection.created_collection_resource = Some(CreatedCollectionResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "slug".to_owned(),
        response_result_identity_pointer: "/slug".to_owned(),
        response_item_identity_pointer: "/slug".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        delete_capability_id: "widgets-delete".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
        requires_page_number_completion: false,
    });
    assert!(collection.verification_contract_supported());

    collection
        .created_collection_resource
        .as_mut()
        .expect("created-collection contract")
        .response_item_identity_pointer = "/id".to_owned();
    assert!(!collection.verification_contract_supported());
}

#[test]
fn nested_resource_contracts_bind_correlation_exact_delete_and_parent_absence() {
    let collection_path = "/zones/{zone_id}/rulesets/{ruleset_id}/rules";
    let mut create = CapabilityV1::new(
        "ruleset-rule-create",
        "Create ruleset rule",
        "POST",
        collection_path,
    );
    create.verification.strategy =
        "parent_object_contains_created_nested_resource_by_correlation".to_owned();
    create.request_schema = Some(json!({
        "type":"object",
        "properties":{
            "action":{"type":"string"},
            "enabled":{"type":"boolean"},
            "expression":{"type":"string"},
            "ref":{"type":"string"}
        }
    }));
    create.created_nested_resource = Some(CreatedNestedResourceContractV1 {
        parent_path: "/zones/{zone_id}/rulesets/{ruleset_id}".to_owned(),
        items_pointer: "/rules".to_owned(),
        identity_selector: "rule_id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        correlation_field: "ref".to_owned(),
        read_capability_id: "ruleset-get".to_owned(),
        delete_capability_id: "ruleset-rule-delete".to_owned(),
        delete_path: format!("{collection_path}/{{rule_id}}"),
        verified_response_fields: vec![
            "action".to_owned(),
            "enabled".to_owned(),
            "expression".to_owned(),
            "ref".to_owned(),
        ],
    });
    create.rollback.supported = true;
    create.rollback.strategy = Some("delete_created_resource_by_returned_id".to_owned());

    assert!(create.verification_contract_supported());
    assert!(create.rollback_contract_supported());

    let mut missing_correlation = create.clone();
    missing_correlation
        .created_nested_resource
        .as_mut()
        .expect("nested create")
        .correlation_field = "undeclared_ref".to_owned();
    assert!(!missing_correlation.verification_contract_supported());
    assert!(!missing_correlation.rollback_contract_supported());

    let mut broad_delete = create;
    broad_delete
        .created_nested_resource
        .as_mut()
        .expect("nested create")
        .delete_path = collection_path.to_owned();
    assert!(!broad_delete.verification_contract_supported());
    assert!(!broad_delete.rollback_contract_supported());

    let mut delete = CapabilityV1::new(
        "ruleset-rule-delete",
        "Delete ruleset rule",
        "DELETE",
        &format!("{collection_path}/{{rule_id}}"),
    );
    delete.verification.strategy = "parent_object_omits_deleted_nested_resource_id".to_owned();
    delete.selectors = vec![
        uncontracted_selector("zone_id", "path", "string"),
        uncontracted_selector("ruleset_id", "path", "string"),
        uncontracted_selector("rule_id", "path", "string"),
    ];
    delete.deleted_nested_resource = Some(DeletedNestedResourceContractV1 {
        parent_path: "/zones/{zone_id}/rulesets/{ruleset_id}".to_owned(),
        collection_path: collection_path.to_owned(),
        items_pointer: "/rules".to_owned(),
        identity_selector: "rule_id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "ruleset-get".to_owned(),
    });
    assert!(delete.verification_contract_supported());

    delete
        .deleted_nested_resource
        .as_mut()
        .expect("nested delete")
        .response_item_identity_pointer = "/name".to_owned();
    assert!(!delete.verification_contract_supported());
}

#[test]
fn declared_live_read_entitlement_probe_completes_the_plan_time_contract() {
    let mut capability = CapabilityV1::new(
        "widgets-create",
        "Create widget",
        "POST",
        "/accounts/{account_id}/widgets",
    );
    capability.selectors = vec![uncontracted_selector("account_id", "path", "string")];
    capability.selectors[0].required = true;
    capability.account_scope = "account".to_owned();
    capability.permissions = vec!["Widgets Read".to_owned(), "Widgets Write".to_owned()];
    capability.risk = RiskClass::ScopedWrite;
    capability.effect = EffectClass::ReversibleWrite;
    capability.cost = CostV1::default();
    capability.request_schema = Some(json!({
        "type":"object",
        "properties":{"name":{"type":"string"}}
    }));
    capability.verification.strategy =
        "created_resource_contains_planned_fields_by_returned_id".to_owned();
    capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: "/accounts/{account_id}/widgets/{widget_id}".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-get".to_owned(),
        delete_capability_id: "widgets-delete".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
    });
    capability.rollback.supported = true;
    capability.rollback.strategy = Some("delete_created_resource_by_returned_id".to_owned());
    capability
        .entitlement
        .plans
        .insert("free".to_owned(), false);
    capability
        .entitlement
        .plans
        .insert("enterprise".to_owned(), true);
    capability.entitlement.requires_live_resolution = true;
    capability.entitlement.probe = Some(EntitlementProbeV1 {
        capability_id: "widgets-list".to_owned(),
        path: "/accounts/{account_id}/widgets".to_owned(),
        selector_names: vec!["account_id".to_owned()],
    });

    assert!(
        capability.mutation_contract_gaps().is_empty(),
        "{:?}",
        capability.mutation_contract_gaps()
    );

    capability
        .entitlement
        .probe
        .as_mut()
        .expect("probe")
        .selector_names = vec!["missing_id".to_owned()];
    assert!(
        capability
            .mutation_contract_gaps()
            .iter()
            .any(|gap| gap == "declared live entitlement probe is malformed")
    );
}

#[test]
fn web_analytics_site_tag_is_an_explicit_non_secret_identity_mapping() {
    let mut capability = CapabilityV1::new(
        "web-analytics-create-site",
        "Create site",
        "POST",
        "/accounts/{account_id}/rum/site_info",
    );
    capability.verification.strategy =
        "created_resource_contains_planned_fields_by_returned_id".to_owned();
    capability.request_schema = Some(json!({
        "type":"object",
        "properties":{"host":{"type":"string"}}
    }));
    capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: "/accounts/{account_id}/rum/site_info/{site_id}".to_owned(),
        identity_selector: "site_id".to_owned(),
        response_result_identity_pointer: "/site_tag".to_owned(),
        read_capability_id: "web-analytics-get-site".to_owned(),
        delete_capability_id: "web-analytics-delete-site".to_owned(),
        verified_response_fields: vec!["host".to_owned()],
    });
    assert!(capability.verification_contract_supported());

    capability
        .created_resource
        .as_mut()
        .expect("created site")
        .response_result_identity_pointer = "/site_token".to_owned();
    assert!(!capability.verification_contract_supported());
}

#[test]
fn pointer_names_secret_field_flags_only_secret_leaves() {
    for secret in cfctl_core::SECRET_FIELD_NAMES {
        assert!(
            cfctl_core::pointer_names_secret_field(&format!("/{secret}")),
            "expected /{secret} to be flagged"
        );
        // Nested leaf is flagged too — the guard reads the last segment.
        assert!(cfctl_core::pointer_names_secret_field(&format!(
            "/result/{secret}"
        )));
    }
    for safe in ["/id", "/name", "/uuid", "/slug", "/account_id", ""] {
        assert!(
            !cfctl_core::pointer_names_secret_field(safe),
            "expected {safe} not to be flagged"
        );
    }
}

#[test]
fn secret_sink_value_keys_are_a_subset_of_secret_field_names() {
    for key in cfctl_core::SECRET_SINK_VALUE_KEYS {
        assert!(
            cfctl_core::SECRET_FIELD_NAMES.contains(key),
            "{key} is extractable as a sink value but not redactable"
        );
    }
    // The exclusions are doctrine, not oversight: credential bundles have
    // dedicated extractors and worker-secret fields are write-only inputs.
    for excluded in [
        "accessKeyId",
        "secretAccessKey",
        "sessionToken",
        "text",
        "key_base64",
        "key_jwk",
    ] {
        assert!(
            !cfctl_core::SECRET_SINK_VALUE_KEYS.contains(&excluded),
            "{excluded} must stay out of the generic single-scalar sink scan"
        );
    }
}

#[test]
fn dns_record_detail_constants_pin_the_wire_contract() {
    // The one place these literals survive: every other site derives from the
    // constants, so this test is what a Cloudflare path change has to break.
    assert_eq!(
        cfctl_core::DNS_RECORD_DETAIL_PATH,
        "/zones/{zone_id}/dns_records/{dns_record_id}"
    );
    assert_eq!(
        cfctl_core::DNS_RECORD_DETAIL_READ_CAPABILITY_ID,
        "dns-records-for-a-zone-dns-record-details"
    );
}

#[test]
fn identity_pointer_naming_a_secret_field_is_never_supported() {
    // A well-formed created-resource contract whose identity selector/pointer
    // both name a secret field (`value`) would satisfy the loose selector==leaf
    // branch, but the secret-field guard must fail it closed so no verifier
    // dereferences the secret as an identity.
    let mut capability = CapabilityV1::new(
        "tokens-create",
        "Create token",
        "POST",
        "/accounts/{account_id}/tokens",
    );
    capability.verification.strategy =
        "created_resource_contains_planned_fields_by_returned_id".to_owned();
    capability.request_schema = Some(json!({
        "type":"object",
        "properties":{"name":{"type":"string"}}
    }));
    capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: "/accounts/{account_id}/tokens/{value}".to_owned(),
        identity_selector: "value".to_owned(),
        response_result_identity_pointer: "/value".to_owned(),
        read_capability_id: "tokens-get".to_owned(),
        delete_capability_id: "tokens-delete".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
    });
    assert!(!capability.verification_contract_supported());

    // Swapping the identity back to a non-secret field restores support,
    // proving the guard is what rejected it (not some unrelated mismatch).
    if let Some(contract) = capability.created_resource.as_mut() {
        "/id".clone_into(&mut contract.response_result_identity_pointer);
        "id".clone_into(&mut contract.identity_selector);
        "/accounts/{account_id}/tokens/{id}".clone_into(&mut contract.detail_path);
    }
    assert!(capability.verification_contract_supported());
}

#[test]
fn d1_create_rollback_is_bound_to_returned_uuid_and_empty_database_compensation() {
    let mut capability = CapabilityV1::new(
        "d1-create-database",
        "Create D1 Database",
        "POST",
        "/accounts/{account_id}/d1/database",
    );
    capability.mutating = true;
    capability.product = "D1".to_owned();
    capability.account_scope = "account".to_owned();
    capability.permissions = vec!["D1 Write".to_owned()];
    capability.risk = RiskClass::ScopedWrite;
    capability.effect = EffectClass::ReversibleWrite;
    capability.request_schema = Some(json!({
        "type":"object",
        "required":["name"],
        "x-cfctl-body-required":true,
        "properties":{
            "jurisdiction":{"type":"string","enum":["eu","fedramp"]},
            "name":{"type":"string"},
            "primary_location_hint":{
                "type":"string",
                "enum":["wnam","enam","weur","eeur","apac","oc"],
                "x-cfctl-verification-observable":false
            },
            "read_replication":{
                "type":"object",
                "required":["mode"],
                "properties":{"mode":{"type":"string","enum":["auto","disabled"]}}
            }
        }
    }));
    capability.verification.strategy =
        "created_resource_contains_planned_fields_by_returned_id".to_owned();
    capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: "/accounts/{account_id}/d1/database/{database_id}".to_owned(),
        identity_selector: "database_id".to_owned(),
        response_result_identity_pointer: "/uuid".to_owned(),
        read_capability_id: "d1-get-database".to_owned(),
        delete_capability_id: "d1-delete-database".to_owned(),
        verified_response_fields: vec![
            "jurisdiction".to_owned(),
            "name".to_owned(),
            "read_replication".to_owned(),
        ],
    });
    capability.rollback.supported = true;
    capability.rollback.strategy =
        Some("delete_created_empty_d1_database_by_returned_uuid_if_unchanged".to_owned());

    assert!(capability.verification_contract_supported());
    assert!(capability.rollback_contract_supported());

    let mut generic = capability.clone();
    generic.rollback.strategy = Some("delete_created_resource_by_returned_id".to_owned());
    assert!(!generic.rollback_contract_supported());

    let mut grafted = capability.clone();
    grafted.id = "widgets-create".to_owned();
    assert!(!grafted.rollback_contract_supported());

    let mut broadened = capability.clone();
    broadened
        .request_schema
        .as_mut()
        .expect("D1 request schema")["properties"]["read_replication"]["properties"]["mode"]["enum"] =
        json!(["auto", "disabled", "future"]);
    assert!(!broadened.rollback_contract_supported());

    let mut wrong_pointer = capability;
    wrong_pointer
        .created_resource
        .as_mut()
        .expect("created D1 resource")
        .response_result_identity_pointer = "/id".to_owned();
    assert!(!wrong_pointer.rollback_contract_supported());
}

#[test]
fn created_collection_contract_excludes_write_only_fields_from_its_allowlist() {
    let mut capability = CapabilityV1::new(
        "widgets-create",
        "Create widget",
        "POST",
        "/accounts/{account_id}/widgets",
    );
    capability.verification.strategy =
        "parent_collection_contains_created_resource_id_and_planned_fields".to_owned();
    capability.request_schema = Some(json!({
        "type": "object",
        "properties": {
            "name": {"type":"string"},
            "secret": {"type":"string", "writeOnly":true}
        }
    }));
    capability.created_collection_resource = Some(CreatedCollectionResourceContractV1 {
        collection_path: capability.path.clone(),
        identity_selector: "widget_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        delete_capability_id: "widgets-delete".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
        requires_page_number_completion: true,
    });

    assert!(capability.verification_contract_supported());

    capability
        .created_collection_resource
        .as_mut()
        .expect("created collection contract")
        .verified_response_fields
        .push("secret".to_owned());
    assert!(!capability.verification_contract_supported());
}

#[test]
fn blocked_dynamic_api_contract_keeps_its_missing_permission_gap() {
    let mut capability = CapabilityV1::new(
        "widgets.delete",
        "Delete widget",
        "DELETE",
        "/accounts/{account_id}/widgets/{widget_id}",
    );
    capability.risk = RiskClass::Destructive;
    capability.effect = EffectClass::Destructive;
    capability.cost = CostV1::default();
    capability.verification.strategy = "same_resource_returns_not_found_after_delete".to_owned();
    capability.rollback.warning =
        Some("deletion is irreversible without a prior resource snapshot".to_owned());
    capability.adapter_status = AdapterStatus::Blocked;
    capability.blocked_reason = Some(
        "operation contract incomplete: required Cloudflare permission lane is not declared"
            .to_owned(),
    );

    assert!(
        capability
            .mutation_contract_gaps()
            .iter()
            .any(|gap| gap.contains("permission lane"))
    );
}

#[test]
fn entitlement_resolution_is_required_only_when_plan_availability_differs() {
    let mut capability = CapabilityV1::new(
        "account-api-tokens-create-token",
        "Create account token",
        "POST",
        "/accounts/{account_id}/tokens",
    );
    capability.risk = RiskClass::SecretSensitive;
    capability.effect = EffectClass::IdentityOrOwnership;
    capability.cost.known = true;
    capability.permissions = vec!["Account API Tokens Write".to_owned()];
    capability.verification.strategy =
        "api_token_details_match_created_id_and_active_status".to_owned();
    capability.rollback.supported = true;
    capability.rollback.strategy =
        Some("revoke_created_api_token_by_returned_id_if_downstream_installation_fails".to_owned());
    capability.entitlement.plans = [
        ("free".to_owned(), true),
        ("pro".to_owned(), true),
        ("business".to_owned(), true),
        ("enterprise".to_owned(), true),
    ]
    .into_iter()
    .collect();

    assert!(
        capability
            .mutation_contract_gaps()
            .iter()
            .all(|gap| !gap.contains("entitlement"))
    );

    capability
        .entitlement
        .plans
        .insert("free".to_owned(), false);
    assert!(
        capability
            .mutation_contract_gaps()
            .iter()
            .any(|gap| gap.contains("entitlement"))
    );
}

#[test]
fn plan_hash_binds_all_reviewed_content_and_is_not_replayable_after_consumption() {
    let capability = CapabilityV1::new(
        "dns.records.update",
        "Update DNS record",
        "PUT",
        "/zones/{zone_id}/dns_records/{record_id}",
    );
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "schema-sha",
        capability,
        json!({"zone_id":"zone-a","record_id":"record-a"}),
    )
    .expect("test fixture must be valid");

    let original = plan.content_hash.clone();
    plan.precondition_hashes.insert(
        "source_config:/repo/wrangler.toml".to_owned(),
        "sha256:a".to_owned(),
    );
    plan.refresh_hash().expect("precondition must rehash");
    assert_ne!(original, plan.content_hash);
    let with_precondition = plan.content_hash.clone();
    plan.capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: "/zones/{zone_id}/dns_records/{record_id}".to_owned(),
        identity_selector: "record_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        read_capability_id: "dns.records.get".to_owned(),
        delete_capability_id: "dns.records.delete".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
    });
    plan.refresh_hash()
        .expect("created-resource contract must rehash");
    assert_ne!(with_precondition, plan.content_hash);
    let with_created_resource_contract = plan.content_hash.clone();
    plan.capability.updated_resource = Some(UpdatedResourceContractV1 {
        collection_path: "/zones/{zone_id}/dns_records".to_owned(),
        identity_selector: "record_id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "dns.records.list".to_owned(),
        verified_response_fields: vec!["content".to_owned(), "type".to_owned()],
        requires_page_number_completion: true,
    });
    plan.refresh_hash()
        .expect("updated-resource contract must rehash");
    assert_ne!(with_created_resource_contract, plan.content_hash);
    let with_updated_resource_contract = plan.content_hash.clone();
    plan.capability.same_path_read = Some(SamePathReadContractV1 {
        path: "/zones/{zone_id}/dns_records/{record_id}".to_owned(),
        read_capability_id: "dns.records.get".to_owned(),
        verified_response_fields: vec!["content".to_owned(), "type".to_owned()],
    });
    plan.refresh_hash()
        .expect("same-path read contract must rehash");
    assert_ne!(with_updated_resource_contract, plan.content_hash);
    let with_same_path_read_contract = plan.content_hash.clone();
    plan.targets = json!({"zone_id":"zone-a","record_id":"record-b"});
    plan.refresh_hash().expect("test fixture must rehash");

    assert_ne!(with_same_path_read_contract, plan.content_hash);
    assert_eq!(plan.status, PlanStatus::Draft);
    plan.approve(true, None)
        .expect("test fixture must approve with explicit yes");
    plan.mark_consumed()
        .expect("draft plan can be consumed once");
    assert!(plan.mark_consumed().is_err());
}

#[test]
fn every_transaction_checkpoint_survives_crash_reload_and_detects_tampering() {
    let capability = CapabilityV1::new(
        "dns.records.update",
        "Update DNS record",
        "PUT",
        "/zones/{zone_id}/dns_records/{record_id}",
    );
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "schema-sha",
        capability,
        json!({"zone_id":"zone-a","record_id":"record-a"}),
    )
    .expect("plan");
    plan.approve(true, None).expect("approve");
    plan.mark_consumed().expect("consume");

    for stage in [
        TransactionStageV1::BoundaryAttemptPersisted,
        TransactionStageV1::BoundaryResponsePersisted,
        TransactionStageV1::SecretSinkPersisted,
        TransactionStageV1::VerificationAttemptPersisted,
        TransactionStageV1::VerificationResponsePersisted,
        TransactionStageV1::CompensationAttemptPersisted,
        TransactionStageV1::CompensationResponsePersisted,
        TransactionStageV1::Closed,
    ] {
        plan.record_transaction_stage(stage).expect("checkpoint");
        let encoded = serde_json::to_vec(&plan).expect("crash snapshot");
        plan = serde_json::from_slice(&encoded).expect("crash reload");
        plan.validate_transaction_journal()
            .expect("journal remains valid after crash reload");
        assert_eq!(plan.transaction_stage, stage);
    }

    plan.transaction_journal[3].checkpoint_hash = "sha256:tampered".to_owned();
    assert!(plan.validate_transaction_journal().is_err());
}

#[test]
fn transaction_artifacts_survive_crash_reload_and_detect_tampering() {
    let capability = CapabilityV1::new(
        "account-api-tokens-create-token",
        "Create account token",
        "POST",
        "/accounts/{account_id}/tokens",
    );
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "schema-sha",
        capability,
        json!({"account_id":"account-a"}),
    )
    .expect("plan");
    plan.approve(true, None).expect("approve");
    plan.mark_consumed().expect("consume");
    plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("attempt checkpoint");
    plan.record_transaction_stage_with_artifact(
        TransactionStageV1::BoundaryResponsePersisted,
        json!({
            "apply_evidence_hash": "sha256:apply",
            "resource_id": "token-id",
            "status": 200,
            "success": true
        }),
    )
    .expect("response receipt checkpoint");

    let encoded = serde_json::to_vec(&plan).expect("crash snapshot");
    let mut reloaded: PlanV1 = serde_json::from_slice(&encoded).expect("crash reload");
    reloaded
        .validate_transaction_journal()
        .expect("receipt remains hash-bound after reload");
    assert_eq!(
        reloaded
            .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
            .and_then(|artifact| artifact.get("resource_id"))
            .and_then(serde_json::Value::as_str),
        Some("token-id")
    );

    reloaded
        .transaction_artifacts
        .get_mut("boundary_response_persisted")
        .expect("response receipt")["resource_id"] = json!("tampered-token-id");
    assert!(reloaded.validate_transaction_journal().is_err());
}

#[test]
fn transaction_journal_rejects_an_uncheckpointed_status_change() {
    let capability = CapabilityV1::new(
        "account-api-tokens-create-token",
        "Create account token",
        "POST",
        "/accounts/{account_id}/tokens",
    );
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "schema-sha",
        capability,
        json!({"account_id":"account-a"}),
    )
    .expect("plan");
    plan.approve(true, None).expect("approve");
    plan.mark_consumed().expect("consume");
    plan.status = PlanStatus::Verified;

    assert!(plan.validate_transaction_journal().is_err());
}

#[test]
fn evidence_and_envelopes_do_not_conflate_artifact_presence_with_verification() {
    let evidence = EvidenceV1::new(EvidenceClass::Preview, "sha256:abc", "/tmp/evidence.json");
    let envelope =
        ResultEnvelopeV2::success("plans.show", json!({"status":"draft"})).with_evidence(evidence);

    assert!(envelope.ok);
    assert!(!envelope.performed);
    assert_eq!(envelope.verification.state.as_str(), "not_applicable");
}

#[test]
fn paid_plan_rejects_a_ceiling_below_the_declared_maximum() {
    let mut capability = CapabilityV1::new(
        "paid",
        "Paid operation",
        "POST",
        "/accounts/{account_id}/paid",
    );
    capability.cost.incremental = true;
    capability.cost.known = true;
    capability.cost.currency = Some("USD".to_owned());
    capability.cost.maximum = Some(10.0);
    let mut plan = PlanV1::draft("p", "a", "sha256:c", capability, json!({})).expect("plan");
    plan.policy.requires_cost_ceiling = true;
    plan.refresh_hash().expect("hash");
    assert!(
        plan.approve(
            true,
            Some(cfctl_core::MoneyV1 {
                currency: "USD".to_owned(),
                amount: 9.99,
            }),
        )
        .is_err()
    );
}

#[test]
fn cancellation_retires_latent_authority_immediately_and_monotonically() {
    let capability = CapabilityV1::new("op", "Operation", "POST", "/accounts/{account_id}/op");

    // A draft is latent authority (auto-execute and standing-authority
    // consumption both start from drafts) and is cancellable.
    let mut draft =
        PlanV1::draft("p", "a", "sha256:c", capability.clone(), json!({})).expect("draft");
    draft.cancel().expect("draft cancels");
    assert_eq!(draft.status, PlanStatus::Cancelled);
    let first_stamp = draft.cancelled_at.expect("cancellation is timestamped");

    // Re-cancel is a no-op success and keeps the original timestamp, so a
    // retried cancel never reads as failure or rewrites the record.
    draft.cancel().expect("re-cancel is idempotent");
    assert_eq!(draft.cancelled_at, Some(first_stamp));

    // A cancelled plan is dead: it can be neither approved nor consumed.
    assert!(
        draft.approve(true, None).is_err(),
        "cancelled refuses approval"
    );
    assert!(
        draft.mark_consumed().is_err(),
        "cancelled refuses consumption"
    );

    // An approved plan — the audit finding's actual subject — cancels too.
    let mut approved =
        PlanV1::draft("p", "a", "sha256:c", capability.clone(), json!({})).expect("draft");
    approved.approve(true, None).expect("approve");
    approved.cancel().expect("approved cancels");
    assert_eq!(approved.status, PlanStatus::Cancelled);
    assert!(approved.mark_consumed().is_err(), "cancelled refuses run");

    // Cancellation is unconditional within its states: a drifted approved
    // plan must still cancel, because refusing to de-authorize tampered
    // content would preserve exactly the authority being retired.
    let mut drifted =
        PlanV1::draft("p", "a", "sha256:c", capability.clone(), json!({})).expect("draft");
    drifted.approve(true, None).expect("approve");
    drifted.input = json!({"tampered": true});
    assert!(
        drifted.mark_consumed().is_err(),
        "drifted content cannot run"
    );
    drifted.cancel().expect("drifted content still cancels");
    assert_eq!(drifted.status, PlanStatus::Cancelled);

    // History is not authority: a consumed plan refuses cancellation.
    let mut consumed = PlanV1::draft("p", "a", "sha256:c", capability, json!({})).expect("draft");
    consumed.approve(true, None).expect("approve");
    consumed.mark_consumed().expect("consume");
    assert!(
        consumed.cancel().is_err(),
        "consumed plans are immutable history"
    );
    assert_eq!(consumed.status, PlanStatus::Consumed);
}

#[test]
fn approval_checkpoint_binds_the_exact_cost_ceiling_across_crash_reload() {
    let mut capability = CapabilityV1::new(
        "paid",
        "Paid operation",
        "POST",
        "/accounts/{account_id}/paid",
    );
    capability.cost.incremental = true;
    capability.cost.known = true;
    capability.cost.currency = Some("USD".to_owned());
    capability.cost.maximum = Some(10.0);
    let mut plan = PlanV1::draft("p", "a", "sha256:c", capability, json!({})).expect("plan");
    plan.policy.requires_cost_ceiling = true;
    plan.refresh_hash().expect("hash");
    plan.approve(
        true,
        Some(cfctl_core::MoneyV1 {
            currency: "USD".to_owned(),
            amount: 20.0,
        }),
    )
    .expect("approve");

    let receipt = plan
        .transaction_artifact(TransactionStageV1::ApprovalPersisted)
        .expect("hash-bound approval receipt");
    assert_eq!(receipt["max_cost"]["currency"], "USD");
    assert_eq!(receipt["max_cost"]["amount"], 20.0);

    let encoded = serde_json::to_vec(&plan).expect("crash snapshot");
    let mut reloaded: PlanV1 = serde_json::from_slice(&encoded).expect("crash reload");
    reloaded
        .validate_transaction_journal()
        .expect("approval remains bound after reload");
    reloaded
        .approval
        .as_mut()
        .and_then(|approval| approval.max_cost.as_mut())
        .expect("approved ceiling")
        .amount = 200.0;
    assert!(reloaded.validate_transaction_journal().is_err());
    assert!(reloaded.mark_consumed().is_err());
}

#[test]
fn core_approval_rejects_invalid_money_without_relying_on_the_cli_parser() {
    let mut capability = CapabilityV1::new(
        "paid",
        "Paid operation",
        "POST",
        "/accounts/{account_id}/paid",
    );
    capability.cost.incremental = true;
    capability.cost.known = true;
    capability.cost.currency = Some("USD".to_owned());
    capability.cost.maximum = Some(10.0);
    let mut plan = PlanV1::draft("p", "a", "sha256:c", capability, json!({})).expect("plan");
    plan.policy.requires_cost_ceiling = true;
    plan.refresh_hash().expect("hash");

    for max_cost in [
        cfctl_core::MoneyV1 {
            currency: "USD".to_owned(),
            amount: f64::NAN,
        },
        cfctl_core::MoneyV1 {
            currency: "USD".to_owned(),
            amount: f64::INFINITY,
        },
        cfctl_core::MoneyV1 {
            currency: "USD".to_owned(),
            amount: -1.0,
        },
        cfctl_core::MoneyV1 {
            currency: "US".to_owned(),
            amount: 20.0,
        },
    ] {
        let mut candidate = plan.clone();
        assert!(candidate.approve(true, Some(max_cost)).is_err());
        assert_eq!(candidate.status, PlanStatus::Draft);
        assert!(candidate.approval.is_none());
    }
}

#[test]
fn approval_requires_explicit_yes_and_rejects_chat_intent_alone() {
    let capability = CapabilityV1::new(
        "dns.records.update",
        "Update DNS record",
        "PUT",
        "/zones/{zone_id}/dns_records/{record_id}",
    );
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "schema-sha",
        capability,
        json!({"zone_id":"zone-a","record_id":"record-a"}),
    )
    .expect("plan");

    let error = plan
        .approve(false, None)
        .expect_err("chat/intent yes without --yes is not authority");
    assert!(
        error
            .to_string()
            .contains("approval must be an explicit yes bound to the operation id"),
        "{error}"
    );
    assert_eq!(plan.status, PlanStatus::Draft);
    assert!(plan.approval.is_none());
}

#[test]
fn approval_rejects_a_hash_drifted_draft_before_granting_authority() {
    let capability = CapabilityV1::new(
        "dns.records.update",
        "Update DNS record",
        "PUT",
        "/zones/{zone_id}/dns_records/{record_id}",
    );
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "schema-sha",
        capability,
        json!({"zone_id":"zone-a","record_id":"record-a"}),
    )
    .expect("plan");
    let bound_hash = plan.content_hash.clone();

    // Operator-visible targets change without rebinding the reviewed content hash.
    plan.targets = json!({"zone_id":"zone-b","record_id":"record-a"});
    assert_eq!(plan.content_hash, bound_hash);

    let error = plan
        .approve(true, None)
        .expect_err("hash-drifted draft must not approve");
    assert!(
        error.to_string().contains("unchanged hash-bound draft"),
        "{error}"
    );
    assert_eq!(plan.status, PlanStatus::Draft);
    assert!(plan.approval.is_none());

    plan.refresh_hash()
        .expect("rebind after intentional review");
    plan.approve(true, None)
        .expect("rehashed draft may approve with explicit yes");
    assert_eq!(plan.status, PlanStatus::Approved);
    assert_eq!(
        plan.approval
            .as_ref()
            .map(|approval| approval.approved_content_hash.as_str()),
        Some(plan.content_hash.as_str())
    );
}

#[test]
fn redaction_recurses_through_objects_and_arrays() {
    let value = json!({
        "access_token": "secret-a",
        "nested": [{"client_secret": "secret-b"}],
        "destination_conf": "r2://bucket?secret=not-for-a-receipt",
        "ownership_challenge": "challenge-secret",
        "safe": "visible"
    });

    let redacted = redact_json(&value);
    assert_eq!(redacted["access_token"], "[REDACTED]");
    assert_eq!(redacted["nested"][0]["client_secret"], "[REDACTED]");
    assert_eq!(redacted["destination_conf"], "[REDACTED]");
    assert_eq!(redacted["ownership_challenge"], "[REDACTED]");
    assert_eq!(redacted["safe"], "visible");
}

fn standing_authority_fixture() -> StandingAuthorityV1 {
    StandingAuthorityV1::draft(
        "account-a",
        None,
        vec![
            "account-api-tokens-create-token".to_owned(),
            "account-api-tokens-delete-token".to_owned(),
        ],
        vec!["group-a".to_owned(), "group-b".to_owned()],
        "sha256:inventory-binding",
        24,
        "cf-rotation-",
        4,
        Utc::now() + Duration::days(30),
    )
    .expect("authority fixture must be valid")
}

fn standing_authority_zone_fixture(zone_id: &str) -> StandingAuthorityV1 {
    StandingAuthorityV1::draft(
        "account-a",
        Some(zone_id),
        vec![
            "account-api-tokens-create-token".to_owned(),
            "account-api-tokens-delete-token".to_owned(),
        ],
        vec!["group-a".to_owned(), "group-b".to_owned()],
        "sha256:inventory-binding",
        24,
        "cf-rotation-",
        4,
        Utc::now() + Duration::days(30),
    )
    .expect("zone-bounded authority fixture must be valid")
}

fn standing_authority_with_permission_inventory(
    permission_inventory: &Value,
    max_runs_per_day: u32,
) -> StandingAuthorityV1 {
    StandingAuthorityV1::draft(
        "account-a",
        None,
        vec![
            "account-api-tokens-create-token".to_owned(),
            "account-api-tokens-delete-token".to_owned(),
        ],
        vec!["group-a".to_owned(), "group-b".to_owned()],
        &hash_value(permission_inventory).expect("permission inventory hash"),
        24,
        "cf-rotation-",
        max_runs_per_day,
        Utc::now() + Duration::days(30),
    )
    .expect("authority fixture must be valid")
}

#[test]
fn standing_authority_grants_require_explicit_yes_and_bind_the_content_hash() {
    let mut authority = standing_authority_fixture();
    assert_eq!(authority.status, StandingAuthorityStatus::PendingApproval);
    assert!(
        authority.approve(false).is_err(),
        "chat/intent alone must never activate a standing grant"
    );
    assert!(
        authority.ensure_operational().is_err(),
        "a pending grant authorizes nothing"
    );

    authority.approve(true).expect("explicit grant activates");
    assert_eq!(authority.status, StandingAuthorityStatus::Active);
    authority
        .ensure_operational()
        .expect("active grant is operational");
    assert_eq!(
        authority
            .approval
            .as_ref()
            .expect("approval recorded")
            .approved_content_hash,
        authority.content_hash
    );

    authority.max_runs_per_day = 10_000;
    assert!(
        authority.ensure_operational().is_err(),
        "post-approval bound drift must fail closed"
    );
}

#[test]
fn standing_authority_run_accounting_never_drifts_the_approved_hash() {
    let mut authority = standing_authority_fixture();
    authority.approve(true).expect("grant");
    authority
        .reserve_run(Utc::now(), "op-1", "account-api-tokens-create-token")
        .expect("run reservation");
    authority.record_minted_token("token-child-1");
    authority
        .ensure_operational()
        .expect("bookkeeping is outside the reviewed grant content");
    assert_eq!(authority.runs_in_last_day(Utc::now()), 1);
    assert_eq!(authority.minted_token_ids, vec!["token-child-1".to_owned()]);
}

#[test]
fn standing_authority_permission_inventory_must_match_the_approved_hash() {
    let approved_inventory = json!([
        {
            "id": "group-a",
            "name": "Account API Tokens Write",
            "scopes": ["com.cloudflare.api.account"],
            "category": "Account API Tokens"
        },
        {
            "id": "group-b",
            "name": "Account Settings Read",
            "scopes": ["com.cloudflare.api.account"]
        }
    ]);
    let mut authority = standing_authority_with_permission_inventory(&approved_inventory, 4);
    authority.approve(true).expect("grant");

    authority
        .validate_permission_inventory(&approved_inventory)
        .expect("the exact normalized approved allowlist remains valid");

    for drifted_inventory in [
        json!([
            {
                "id": "group-a",
                "name": "Renamed permission",
                "scopes": ["com.cloudflare.api.account"],
                "category": "Account API Tokens"
            },
            {
                "id": "group-b",
                "name": "Account Settings Read",
                "scopes": ["com.cloudflare.api.account"]
            }
        ]),
        json!([
            {
                "id": "group-a",
                "name": "Account API Tokens Write",
                "scopes": ["com.cloudflare.api.user"],
                "category": "Account API Tokens"
            },
            {
                "id": "group-b",
                "name": "Account Settings Read",
                "scopes": ["com.cloudflare.api.account"]
            }
        ]),
        json!([
            {
                "id": "group-a",
                "name": "Account API Tokens Write",
                "scopes": ["com.cloudflare.api.account"],
                "category": "Different category"
            },
            {
                "id": "group-b",
                "name": "Account Settings Read",
                "scopes": ["com.cloudflare.api.account"]
            }
        ]),
        json!([
            {
                "id": "group-a",
                "name": "Account API Tokens Write",
                "scopes": ["com.cloudflare.api.account"],
                "category": "Account API Tokens"
            }
        ]),
    ] {
        let error = authority
            .validate_permission_inventory(&drifted_inventory)
            .expect_err("metadata drift must invalidate the standing mint");
        assert!(
            error
                .to_string()
                .contains("complete permission allowlist metadata drifted"),
            "{error}"
        );
    }
}

#[test]
fn standing_run_reservation_rechecks_state_budget_and_operation_identity() {
    let now = Utc::now();
    let mut authority = standing_authority_with_permission_inventory(&json!([]), 1);
    authority.approve(true).expect("grant");

    authority
        .reserve_run(now, "op-1", "account-api-tokens-create-token")
        .expect("first run reserves the only budget slot");
    assert_eq!(authority.run_log.len(), 1);
    assert_eq!(authority.run_log[0].at, now);

    let duplicate = authority
        .reserve_run(
            now + Duration::minutes(1),
            "op-1",
            "account-api-tokens-create-token",
        )
        .expect_err("an operation id can only be reserved once");
    assert!(
        duplicate.to_string().contains("already reserved"),
        "{duplicate}"
    );
    assert_eq!(authority.run_log.len(), 1);

    let exhausted = authority
        .reserve_run(
            now + Duration::minutes(1),
            "op-2",
            "account-api-tokens-create-token",
        )
        .expect_err("the run budget is checked before append");
    assert!(
        exhausted.to_string().contains("run budget exhausted"),
        "{exhausted}"
    );
    assert_eq!(authority.run_log.len(), 1);

    authority.revoke();
    let revoked = authority
        .reserve_run(
            now + Duration::hours(25),
            "op-3",
            "account-api-tokens-create-token",
        )
        .expect_err("revocation is rechecked before append");
    assert!(revoked.to_string().contains("is revoked"), "{revoked}");
    assert_eq!(authority.run_log.len(), 1);
}

#[test]
fn standing_run_reservation_uses_the_supplied_time_for_expiry() {
    let mut authority = standing_authority_fixture();
    authority.approve(true).expect("grant");
    let after_expiry = authority.expires_at + Duration::seconds(1);

    let expired = authority
        .reserve_run(
            after_expiry,
            "op-after-expiry",
            "account-api-tokens-create-token",
        )
        .expect_err("an expired authority cannot reserve a run");
    assert!(expired.to_string().contains("expired at"), "{expired}");
    assert!(authority.run_log.is_empty());
}

#[test]
fn standing_lineage_reconciliation_is_idempotent_and_preserves_revocation() {
    let mut authority = standing_authority_fixture();
    authority.approve(true).expect("grant");
    authority.revoke();

    authority.record_minted_token("token-child");
    authority.record_minted_token("token-child");

    assert_eq!(authority.status, StandingAuthorityStatus::Revoked);
    assert_eq!(authority.minted_token_ids, vec!["token-child".to_owned()]);
}

#[test]
fn standing_authority_reports_expiry_without_changing_schema_v1_status() {
    let mut authority = standing_authority_fixture();
    authority.approve(true).expect("grant");

    assert_eq!(
        authority.effective_status(authority.expires_at - Duration::seconds(1)),
        "active"
    );
    assert_eq!(
        authority.effective_status(authority.expires_at + Duration::seconds(1)),
        "expired"
    );
    assert_eq!(authority.status, StandingAuthorityStatus::Active);
    assert_eq!(
        serde_json::to_value(&authority).expect("authority JSON")["status"],
        json!("active")
    );

    authority.revoke();
    assert_eq!(
        authority.effective_status(authority.expires_at + Duration::seconds(1)),
        "revoked",
        "revocation remains the monotonic durable status"
    );
}

#[test]
fn standing_authority_bounds_child_tokens_to_its_pinned_resources() {
    let now = Utc::now();
    let expiry = Some(now + Duration::hours(12));
    let group = vec!["group-a".to_owned()];
    let account_resource = "com.cloudflare.api.account.account-a".to_owned();
    let zone_resource =
        "com.cloudflare.api.account.zone.4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b".to_owned();

    // Account-only authority: the zone resource is out of bounds.
    let mut account_only = standing_authority_fixture();
    account_only.approve(true).expect("grant");
    assert_eq!(
        account_only.allowed_token_resources(),
        vec![account_resource.clone()]
    );
    account_only
        .authorize_token_create(
            now,
            "cf-rotation-x",
            &group,
            std::slice::from_ref(&account_resource),
            expiry,
        )
        .expect("the pinned account resource is in bounds");
    assert!(
        account_only
            .authorize_token_create(
                now,
                "cf-rotation-x",
                &group,
                std::slice::from_ref(&zone_resource),
                expiry
            )
            .is_err(),
        "an account-scoped authority must not mint a zone-bound child"
    );

    // Zone-bounded authority: both its account and its one zone are in bounds,
    // but a different zone is not.
    let mut zone_bound = standing_authority_zone_fixture("4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b");
    zone_bound.approve(true).expect("grant");
    zone_bound
        .authorize_token_create(
            now,
            "cf-rotation-x",
            &group,
            std::slice::from_ref(&zone_resource),
            expiry,
        )
        .expect("the pinned zone resource is in bounds");
    zone_bound
        .authorize_token_create(
            now,
            "cf-rotation-x",
            &group,
            std::slice::from_ref(&account_resource),
            expiry,
        )
        .expect("the pinned account resource stays in bounds");
    assert!(
        zone_bound
            .authorize_token_create(
                now,
                "cf-rotation-x",
                &group,
                &["com.cloudflare.api.account.zone.ffffffffffffffffffffffffffffffff".to_owned()],
                expiry
            )
            .is_err(),
        "a zone other than the pinned one is refused"
    );
    assert!(
        zone_bound
            .authorize_token_create(
                now,
                "cf-rotation-x",
                &group,
                &["com.cloudflare.api.account.other-account".to_owned()],
                expiry
            )
            .is_err(),
        "another account's resource is refused"
    );
    assert!(
        zone_bound
            .authorize_token_create(now, "cf-rotation-x", &group, &[], expiry)
            .is_err(),
        "a child binding no resource at all is refused"
    );
    assert!(
        zone_bound
            .authorize_token_create(
                now,
                "cf-rotation-x",
                &group,
                &[
                    zone_resource,
                    "com.cloudflare.api.account.other-account".to_owned()
                ],
                expiry
            )
            .is_err(),
        "one out-of-bounds resource poisons an otherwise valid set"
    );
}

#[test]
fn zone_binding_is_additive_to_the_approved_authority_hash() {
    // An account-scoped authority must hash exactly as it did before zone
    // support existed, or every previously approved authority breaks.
    let account_only = standing_authority_fixture();
    let serialized = serde_json::to_value(&account_only).expect("serialize");
    assert!(
        serialized.get("zone_id").is_none(),
        "an account-scoped authority must not serialize a zone_id at all"
    );

    let zone_bound = standing_authority_zone_fixture("4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b");
    assert_ne!(
        account_only.content_hash, zone_bound.content_hash,
        "a zone bound must be part of the reviewed, hash-bound grant content"
    );

    // A stored authority written before zone support deserializes as
    // account-scoped rather than failing.
    let mut legacy = serialized.clone();
    legacy.as_object_mut().expect("object").remove("zone_id");
    let restored: StandingAuthorityV1 =
        serde_json::from_value(legacy).expect("legacy authority still loads");
    assert_eq!(restored.zone_id, None);
    assert_eq!(restored.content_hash, account_only.content_hash);
}

#[test]
fn standing_mints_fail_closed_on_prefix_groups_expiry_ttl_and_rate() {
    let mut authority = standing_authority_fixture();
    authority.approve(true).expect("grant");
    let now = Utc::now();
    let in_bounds_expiry = Some(now + Duration::hours(12));
    let group = vec!["group-a".to_owned()];
    let resource = vec!["com.cloudflare.api.account.account-a".to_owned()];

    authority
        .authorize_token_create(
            now,
            "cf-rotation-web-deploy",
            &group,
            &resource,
            in_bounds_expiry,
        )
        .expect("in-bounds mint authorized");

    assert!(
        authority
            .authorize_token_create(now, "unprefixed-name", &group, &resource, in_bounds_expiry)
            .is_err(),
        "name prefix is mandatory"
    );
    assert!(
        authority
            .authorize_token_create(
                now,
                "cf-rotation-x",
                &["group-outside".to_owned()],
                &resource,
                in_bounds_expiry
            )
            .is_err(),
        "permission groups outside the allowlist are refused"
    );
    assert!(
        authority
            .authorize_token_create(now, "cf-rotation-x", &[], &resource, in_bounds_expiry)
            .is_err(),
        "a child with no permission groups is refused"
    );
    assert!(
        authority
            .authorize_token_create(now, "cf-rotation-x", &group, &resource, None)
            .is_err(),
        "children must declare an expiry"
    );
    assert!(
        authority
            .authorize_token_create(
                now,
                "cf-rotation-x",
                &group,
                &resource,
                Some(now + Duration::hours(48))
            )
            .is_err(),
        "children must stay within the maximum child TTL"
    );

    for run in 0..4 {
        authority
            .reserve_run(now, &format!("op-{run}"), "account-api-tokens-create-token")
            .expect("run reservation within budget");
    }
    assert!(
        authority
            .authorize_token_create(now, "cf-rotation-x", &group, &resource, in_bounds_expiry)
            .is_err(),
        "the daily run budget limits attempts"
    );
}

#[test]
fn standing_revocation_is_immediate_and_deletion_is_lineage_bound() {
    let mut authority = standing_authority_fixture();
    authority.approve(true).expect("grant");
    let now = Utc::now();

    assert!(
        authority
            .authorize_token_delete(now, "token-foreign")
            .is_err(),
        "an authority may only revoke tokens it minted"
    );
    authority.record_minted_token("token-child");
    authority
        .authorize_token_delete(now, "token-child")
        .expect("own child may be revoked");

    authority.revoke();
    assert!(
        authority
            .authorize_token_delete(now, "token-child")
            .is_err(),
        "revocation takes effect immediately"
    );
    assert!(
        authority.approve(true).is_err(),
        "a revoked grant cannot be re-approved"
    );
}

#[test]
fn standing_consumption_accepts_only_in_scope_unapproved_drafts_and_records_the_binding() {
    let mut authority = standing_authority_fixture();
    authority.approve(true).expect("grant");
    let capability = CapabilityV1::new(
        "account-api-tokens-create-token",
        "Create token",
        "POST",
        "/accounts/{account_id}/tokens",
    );
    let plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "schema-sha",
        capability.clone(),
        json!({"account_id": "account-a"}),
    )
    .expect("plan fixture");

    let pending = standing_authority_fixture();
    assert!(
        plan.clone()
            .mark_consumed_via_standing_authority(&pending)
            .is_err(),
        "a pending grant consumes nothing"
    );

    let mut foreign_account = plan.clone();
    foreign_account.account_id = "account-b".to_owned();
    foreign_account.refresh_hash().expect("rehash");
    assert!(
        foreign_account
            .mark_consumed_via_standing_authority(&authority)
            .is_err(),
        "the account pin is enforced at consumption"
    );

    let out_of_scope = CapabilityV1::new("zones-get", "Read zone", "GET", "/zones/{zone_id}");
    let unlisted = PlanV1::draft(
        "profile-a",
        "account-a",
        "schema-sha",
        out_of_scope,
        json!({}),
    )
    .expect("plan fixture");
    assert!(
        unlisted
            .clone()
            .mark_consumed_via_standing_authority(&authority)
            .is_err(),
        "capabilities outside the allowlist are refused"
    );

    let mut approved = plan.clone();
    approved.approve(true, None).expect("ordinary approval");
    assert!(
        approved
            .mark_consumed_via_standing_authority(&authority)
            .is_err(),
        "approved plans must use the ordinary consumption lane"
    );

    let mut consumed = plan;
    consumed
        .mark_consumed_via_standing_authority(&authority)
        .expect("in-scope unapproved draft consumes under the grant");
    assert_eq!(consumed.status, PlanStatus::Consumed);
    let binding = consumed
        .transaction_artifact(TransactionStageV1::ConsumptionPersisted)
        .expect("consumption records the authority binding");
    assert_eq!(
        binding["standing_authority_id"],
        json!(authority.authority_id)
    );
    assert_eq!(
        binding["standing_authority_content_hash"],
        json!(authority.content_hash)
    );
    assert!(
        consumed
            .mark_consumed_via_standing_authority(&authority)
            .is_err(),
        "standing consumption is not replayable"
    );
}

fn zone_cache_purge_capability(id: &str, path: &str) -> CapabilityV1 {
    let mut capability = CapabilityV1::new(id, "Purge Cached Content", "POST", path);
    "Zone".clone_into(&mut capability.product);
    capability.permissions = vec!["Cache Purge".to_owned()];
    capability.risk = RiskClass::Destructive;
    capability.effect = EffectClass::Destructive;
    capability.cost = CostV1::default();
    capability.cost.known = true;
    capability.cost.incremental = false;
    capability.cost.maximum = Some(0.0);
    capability.entitlement.available = Some(true);
    capability.entitlement.plans = ["free", "pro", "business", "enterprise"]
        .into_iter()
        .map(|plan| (plan.to_owned(), true))
        .collect();
    capability.verification.required = true;
    "cache_purge_response_reports_target_zone_id".clone_into(&mut capability.verification.strategy);
    capability.rollback.supported = false;
    capability.rollback.strategy = None;
    capability.rollback.warning = Some(
        "a cache purge is irreversible — content is re-fetched from origin on next request; no snapshot restores prior cache state"
            .to_owned(),
    );
    capability.request_schema = Some(json!({
        "anyOf": [{"type": "object", "properties": {"purge_everything": {"type": "boolean"}}}],
        "x-cfctl-body-required": true
    }));
    capability
}

#[test]
fn zone_cache_purge_verifier_is_bound_to_purge_ids_and_post() {
    for id in [
        "zone-purge",
        "zone-purge-tagged",
        "zone-environment-purge",
        "zone-environment-purge-tagged",
    ] {
        let capability = zone_cache_purge_capability(id, "/zones/{zone_id}/purge_cache");
        assert!(
            capability.verification_contract_supported(),
            "{id} should support the purge verifier"
        );
        assert!(
            capability.mutation_contract_gaps().is_empty(),
            "{id} gaps: {:?}",
            capability.mutation_contract_gaps()
        );
    }

    let mut wrong_method =
        zone_cache_purge_capability("zone-purge", "/zones/{zone_id}/purge_cache");
    "PUT".clone_into(&mut wrong_method.method);
    assert!(
        !wrong_method.verification_contract_supported(),
        "the purge verifier must be bound to POST"
    );

    let wrong_id =
        zone_cache_purge_capability("zone-settings-edit", "/zones/{zone_id}/purge_cache");
    assert!(
        !wrong_id.verification_contract_supported(),
        "the purge verifier must be bound to the purge ids"
    );
}

#[test]
fn graphql_contract_fingerprint_detects_document_or_shape_drift() {
    let mut contract = GraphqlAnalyticsContractV1 {
        operation_name: "CfctlZoneHttp".to_owned(),
        document: "query CfctlZoneHttp($zoneTag: string) { viewer { zones(filter: {zoneTag: $zoneTag}) { series: httpRequestsAdaptiveGroups(limit: 10) { count } } } }".to_owned(),
        dataset: "httpRequestsAdaptiveGroups".to_owned(),
        selector_variables: [("zone_id".to_owned(), "zoneTag".to_owned())]
            .into_iter()
            .collect(),
        body_variables: [("start".to_owned(), "start".to_owned())]
            .into_iter()
            .collect(),
        response_data_pointer: "/viewer/zones/0/series".to_owned(),
        expected_row_fields: vec!["count".to_owned()],
        cursor_fields: Vec::new(),
        cursor_input_pointer: None,
        cursor_input_pointers: std::collections::BTreeMap::new(),
        schema_fingerprint: String::new(),
    };
    contract.refresh_schema_fingerprint().expect("fingerprint");
    assert!(contract.validate_schema_fingerprint().is_ok());

    let mut document_drift = contract.clone();
    document_drift.document.push_str(" # changed");
    assert!(document_drift.validate_schema_fingerprint().is_err());

    let mut response_drift = contract;
    response_drift.expected_row_fields.push("sum".to_owned());
    assert!(response_drift.validate_schema_fingerprint().is_err());

    let mut cursor_contract = response_drift;
    cursor_contract.cursor_fields = vec!["datetime".to_owned(), "rayName".to_owned()];
    cursor_contract.cursor_input_pointers = [
        ("datetime".to_owned(), "/after".to_owned()),
        ("rayName".to_owned(), "/after_ray_name".to_owned()),
    ]
    .into_iter()
    .collect();
    cursor_contract
        .refresh_schema_fingerprint()
        .expect("cursor fingerprint");
    cursor_contract
        .cursor_input_pointers
        .insert("rayName".to_owned(), "/wrong_input".to_owned());
    assert!(cursor_contract.validate_schema_fingerprint().is_err());
}

#[test]
fn bounded_analytics_contract_round_trips_without_changing_rest_defaults() {
    let mut capability = CapabilityV1::new(
        "analytics-engine-sql-query-get",
        "Run a bounded Analytics Engine query",
        "GET",
        "/accounts/{account_id}/analytics_engine/sql",
    );
    capability.aliases = vec!["analytics engine".to_owned(), "telemetry SQL".to_owned()];
    capability.analytics_query = Some(AnalyticsQueryContractV1 {
        kind: AnalyticsQueryKindV1::StructuredSql,
        dataset: None,
        dataset_pointer: Some("/dataset".to_owned()),
        time_range: Some(TimeRangeContractV1 {
            start_pointer: "/start".to_owned(),
            end_pointer: "/end".to_owned(),
            timestamp_format: TimestampFormatV1::Rfc3339,
            max_lookback_seconds: 2_592_000,
            max_window_seconds: 86_400,
        }),
        row_limit_pointer: Some("/limit".to_owned()),
        max_rows: 10_000,
        max_bytes: 16 * 1024 * 1024,
        max_timeout_seconds: 60,
        allowed_output_formats: vec![
            OutputFormatV1::Json,
            OutputFormatV1::Ndjson,
            OutputFormatV1::Csv,
        ],
        default_output_format: OutputFormatV1::Ndjson,
        pagination: PaginationModeV1::BoundedResult,
        read_only: true,
        freshness: Some("reported by the upstream dataset".to_owned()),
        sampling: Some("reported in query metadata when available".to_owned()),
    });

    let encoded = serde_json::to_value(&capability).expect("serialize capability");
    let decoded: CapabilityV1 = serde_json::from_value(encoded).expect("deserialize capability");
    assert_eq!(decoded, capability);
    assert!(decoded.graphql.is_none());
    assert!(decoded.workflow.is_none());
    assert!(decoded.security_action.is_none());

    let ordinary = CapabilityV1::new("zones-list", "List zones", "GET", "/zones");
    assert!(ordinary.aliases.is_empty());
    assert!(ordinary.analytics_query.is_none());
    assert!(ordinary.graphql.is_none());
    assert!(ordinary.workflow.is_none());
    assert!(ordinary.security_action.is_none());
}

#[test]
fn security_action_contract_requires_evidence_expiry_and_exact_rollback_lifecycle() {
    let mut capability = CapabilityV1::new(
        "security-response-create-expiring-ip-access-rule",
        "Create expiring security action",
        "POST",
        "/zones/{zone_id}/firewall/access_rules/rules",
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
            "mode":{"type":"string"},
            "notes":{"type":"string"}
        },
        "x-cfctl-body-required":true
    }));
    capability.risk = RiskClass::IdentityOrOwnership;
    capability.effect = EffectClass::ReversibleWrite;
    capability.cost.known = true;
    capability.cost.maximum = Some(0.0);
    capability.verification.strategy =
        "parent_collection_contains_created_resource_id_and_planned_fields".to_owned();
    capability.created_collection_resource = Some(CreatedCollectionResourceContractV1 {
        collection_path: capability.path.clone(),
        identity_selector: "rule_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "ip-access-rules-for-a-zone-list-ip-access-rules".to_owned(),
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
            "properties":{}
        }),
        default_action: Some("managed_challenge".to_owned()),
        allowed_actions: vec!["managed_challenge".to_owned(), "block".to_owned()],
        allowed_target_types: vec!["ip".to_owned()],
        default_ttl_seconds: 86_400,
        max_ttl_seconds: 604_800,
        current_state_capability_id: "ip-access-rules-for-a-zone-list-ip-access-rules".to_owned(),
        safety_profile: SecurityActionSafetyProfileV1::TelemetryDerivedStrict,
    });

    assert!(capability.security_action_contract_supported());
    assert!(
        capability.mutation_contract_gaps().is_empty(),
        "{:?}",
        capability.mutation_contract_gaps()
    );

    capability
        .security_action
        .as_mut()
        .expect("security contract")
        .default_action = Some("block".to_owned());
    assert!(!capability.security_action_contract_supported());
    assert!(
        capability
            .mutation_contract_gaps()
            .iter()
            .any(|gap| gap.contains("security action"))
    );
}

#[test]
fn legacy_security_action_contract_defaults_to_the_strict_indivisible_profile() {
    let contract: SecurityActionContractV1 = serde_json::from_value(json!({
        "kind": "create_expiring",
        "input_schema": {
            "type": "object",
            "required": ["actor", "evidence_ref", "reason"],
            "additionalProperties": false,
            "properties": {}
        },
        "default_action": "managed_challenge",
        "allowed_actions": ["managed_challenge"],
        "allowed_target_types": ["ip"],
        "default_ttl_seconds": 86_400,
        "max_ttl_seconds": 604_800,
        "current_state_capability_id": "ip-access-rules-for-a-zone-list-ip-access-rules",
        "evidence_required": true,
        "actor_required": true,
        "reason_required": true,
        "anonymous_identity_inference_forbidden": true
    }))
    .expect("legacy v2 security action contract should deserialize");

    assert_eq!(
        contract.safety_profile,
        SecurityActionSafetyProfileV1::TelemetryDerivedStrict
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one lifecycle scenario keeps polling, correlation, verification, and rollback assertions together"
)]
fn asynchronous_list_security_action_pins_poll_correlation_and_exact_removal() {
    let mut capability = CapabilityV1::new(
        "security-response-add-expiring-list-member",
        "Add expiring List member",
        "POST",
        "/accounts/{account_id}/rules/lists/{list_id}/items",
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
    capability.cost.known = true;
    capability.cost.maximum = Some(0.0);
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
        collection_path: "/accounts/{account_id}/rules/lists/{list_id}/items".to_owned(),
        collection_capability_id: "lists-get-list-items".to_owned(),
        collection_metadata_path: "/accounts/{account_id}/rules/lists/{list_id}".to_owned(),
        collection_metadata_capability_id: "lists-get-a-list".to_owned(),
        collection_item_identity_pointer: "/id".to_owned(),
        correlation_field: Some("comment".to_owned()),
        remove_capability_id: Some("security-response-remove-expired-list-member".to_owned()),
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
            "properties":{}
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

    assert!(capability.verification_contract_supported());
    assert!(capability.rollback_contract_supported());
    assert!(capability.security_action_contract_supported());
    assert!(
        capability.mutation_contract_gaps().is_empty(),
        "{:?}",
        capability.mutation_contract_gaps()
    );

    capability
        .async_collection_mutation
        .as_mut()
        .expect("async contract")
        .max_poll_attempts = 31;
    assert!(!capability.verification_contract_supported());
    assert!(!capability.rollback_contract_supported());
    assert!(
        capability
            .mutation_contract_gaps()
            .iter()
            .any(|gap| gap.contains("verification strategy"))
    );
}
