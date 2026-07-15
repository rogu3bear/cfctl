#![allow(clippy::expect_used, clippy::unwrap_used)]

use cfctl_core::{
    CapabilityV1, CostV1, CreatedResourceContractV1, DeletedResourceContractV1, EffectClass,
    PolicyDisposition, RiskClass,
};
use cfctl_planner::{ImpactContext, PolicyEngine};

fn capability(method: &str) -> CapabilityV1 {
    CapabilityV1::new(
        "test.operation",
        "Test operation",
        method,
        "/accounts/{account_id}/test",
    )
}

fn reversible_write() -> CapabilityV1 {
    let mut write = CapabilityV1::new(
        "widgets-create",
        "Create widget",
        "POST",
        "/accounts/{account_id}/widgets",
    );
    write.risk = RiskClass::ScopedWrite;
    write.effect = EffectClass::ReversibleWrite;
    write.cost = CostV1::default();
    write.permissions = vec!["Widgets Write".to_owned()];
    "created_resource_contains_planned_fields_by_returned_id"
        .clone_into(&mut write.verification.strategy);
    write.rollback.supported = true;
    write.rollback.strategy = Some("delete_created_resource_by_returned_id".to_owned());
    write.created_resource = Some(CreatedResourceContractV1 {
        detail_path: "/accounts/{account_id}/widgets/{widget_id}".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-get".to_owned(),
        delete_capability_id: "widgets-delete".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
    });
    write
}

#[test]
fn reads_and_known_reversible_isolated_writes_can_auto_execute() {
    let engine = PolicyEngine;
    let read = engine.evaluate(&capability("GET"), &ImpactContext::default());
    assert_eq!(read.disposition, PolicyDisposition::AutoExecute);

    let write = reversible_write();
    let decision = engine.evaluate(&write, &ImpactContext::default());
    assert_eq!(decision.disposition, PolicyDisposition::AutoExecute);
}

#[test]
fn blast_radius_and_real_world_effects_require_approval() {
    let engine = PolicyEngine;
    let mut write = reversible_write();

    let cross_repo = ImpactContext {
        affected_repositories: 2,
        ..ImpactContext::default()
    };
    assert_eq!(
        engine.evaluate(&write, &cross_repo).disposition,
        PolicyDisposition::ApprovalRequired
    );

    for effect in [
        EffectClass::Destructive,
        EffectClass::ExternalCommunication,
        EffectClass::IdentityOrOwnership,
        EffectClass::Spend,
        EffectClass::Irreversible,
    ] {
        write.effect = effect;
        assert_eq!(
            engine
                .evaluate(&write, &ImpactContext::default())
                .disposition,
            PolicyDisposition::ApprovalRequired
        );
    }

    write.effect = EffectClass::Unknown;
    assert_eq!(
        engine
            .evaluate(&write, &ImpactContext::default())
            .disposition,
        PolicyDisposition::Blocked
    );
}

#[test]
fn paid_operations_with_unknown_cost_are_blocked() {
    let engine = PolicyEngine;
    let mut paid = capability("POST");
    paid.risk = RiskClass::Spend;
    paid.effect = EffectClass::Spend;
    paid.cost.incremental = true;
    paid.cost.known = false;

    let decision = engine.evaluate(&paid, &ImpactContext::default());
    assert_eq!(decision.disposition, PolicyDisposition::Blocked);
    assert!(decision.requires_cost_ceiling);
}

#[test]
fn destructive_subscription_deletes_always_require_exact_approval() {
    let mut delete = CapabilityV1::new(
        "account-subscriptions-delete-subscription",
        "Delete Subscription",
        "DELETE",
        "/accounts/{account_id}/subscriptions/{subscription_identifier}",
    );
    delete.risk = RiskClass::Destructive;
    delete.effect = EffectClass::Destructive;
    delete.cost = CostV1::default();
    delete.permissions = vec!["Billing Write".to_owned()];
    "parent_collection_omits_deleted_resource_id".clone_into(&mut delete.verification.strategy);
    delete.deleted_resource = Some(DeletedResourceContractV1 {
        collection_path: "/accounts/{account_id}/subscriptions".to_owned(),
        identity_selector: "subscription_identifier".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "account-subscriptions-list-subscriptions".to_owned(),
        requires_page_number_completion: false,
    });
    delete.rollback.warning = Some(
        "subscription deletion is irreversible without a separately reviewed recreation plan"
            .to_owned(),
    );

    let decision = PolicyEngine.evaluate(&delete, &ImpactContext::default());

    assert_eq!(decision.disposition, PolicyDisposition::ApprovalRequired);
    assert!(
        decision
            .reasons
            .iter()
            .any(|reason| reason.contains("Destructive"))
    );
}

#[test]
fn incomplete_mutation_contracts_are_blocked_before_approval() {
    let engine = PolicyEngine;
    let unknown = capability("POST");

    let decision = engine.evaluate(&unknown, &ImpactContext::default());

    assert_eq!(decision.disposition, PolicyDisposition::Blocked);
    assert!(
        decision
            .reasons
            .iter()
            .any(|reason| reason.contains("risk classification"))
    );
    assert!(
        decision
            .reasons
            .iter()
            .any(|reason| reason.contains("cost"))
    );
    assert!(
        decision
            .reasons
            .iter()
            .any(|reason| reason.contains("verification"))
    );
    assert!(
        decision
            .reasons
            .iter()
            .any(|reason| reason.contains("rollback"))
    );
}

#[test]
fn declared_but_unimplemented_runtime_contracts_are_blocked() {
    let engine = PolicyEngine;
    let mut write = capability("POST");
    write.risk = RiskClass::ScopedWrite;
    write.effect = EffectClass::ReversibleWrite;
    write.cost = cfctl_core::CostV1::default();
    write.permissions = vec!["Test Write".to_owned()];
    write.verification.strategy = "phantom_readback".to_owned();
    write.rollback.supported = true;
    write.rollback.strategy = Some("phantom_restore".to_owned());

    let decision = engine.evaluate(&write, &ImpactContext::default());

    assert_eq!(decision.disposition, PolicyDisposition::Blocked);
    assert!(
        decision
            .reasons
            .iter()
            .any(|reason| reason.contains("verification strategy is unsupported"))
    );
    assert!(
        decision
            .reasons
            .iter()
            .any(|reason| reason.contains("rollback strategy is unsupported"))
    );
}
