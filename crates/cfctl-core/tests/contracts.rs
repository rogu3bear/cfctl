#![allow(clippy::expect_used, clippy::unwrap_used)]

use cfctl_core::{
    AdapterStatus, CapabilityV1, CostV1, CreatedResourceContractV1, EffectClass, EvidenceClass,
    EvidenceV1, GuideStage, PlanStatus, PlanV1, ResultEnvelopeV2, RiskClass,
    SamePathReadContractV1, TransactionStageV1, UpdatedResourceContractV1, guide_stages,
    redact_json,
};
use serde_json::json;

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
fn updated_resource_contract_rejects_noncanonical_field_allowlists() {
    let mut capability = CapabilityV1::new(
        "widgets-update",
        "Update widget",
        "PATCH",
        "/accounts/{account_id}/widgets/{widget_id}",
    );
    capability.verification.strategy =
        "parent_collection_item_contains_planned_fields_after_update".to_owned();
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
            "enabled": {"type":"boolean"}
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

    let mut legacy_value = serde_json::to_value(&update).expect("serialize capability");
    legacy_value
        .as_object_mut()
        .expect("capability object")
        .remove("same_path_read");
    let legacy: CapabilityV1 =
        serde_json::from_value(legacy_value).expect("deserialize legacy capability");
    assert!(!legacy.verification_contract_supported());

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

    delete
        .same_path_read
        .as_mut()
        .expect("same-path contract")
        .verified_response_fields = vec!["id".to_owned()];
    assert!(!delete.verification_contract_supported());
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
fn redaction_recurses_through_objects_and_arrays() {
    let value = json!({
        "access_token": "secret-a",
        "nested": [{"client_secret": "secret-b"}],
        "safe": "visible"
    });

    let redacted = redact_json(&value);
    assert_eq!(redacted["access_token"], "[REDACTED]");
    assert_eq!(redacted["nested"][0]["client_secret"], "[REDACTED]");
    assert_eq!(redacted["safe"], "visible");
}
