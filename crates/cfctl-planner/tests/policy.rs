#![allow(clippy::expect_used, clippy::unwrap_used)]

use cfctl_core::{CapabilityV1, EffectClass, PolicyDisposition, RiskClass};
use cfctl_planner::{ImpactContext, PolicyEngine};

fn capability(method: &str) -> CapabilityV1 {
    CapabilityV1::new(
        "test.operation",
        "Test operation",
        method,
        "/accounts/{account_id}/test",
    )
}

#[test]
fn reads_and_known_reversible_isolated_writes_can_auto_execute() {
    let engine = PolicyEngine;
    let read = engine.evaluate(&capability("GET"), &ImpactContext::default());
    assert_eq!(read.disposition, PolicyDisposition::AutoExecute);

    let mut write = capability("PUT");
    write.risk = RiskClass::ScopedWrite;
    write.effect = EffectClass::ReversibleWrite;
    write.rollback.supported = true;
    write.rollback.strategy = Some("restore captured resource state".to_owned());
    write.cost.known = true;
    write.cost.incremental = false;
    write.verification.strategy = "resource_readback_matches_requested_state".to_owned();
    write.permissions = vec!["Test Write".to_owned()];
    let decision = engine.evaluate(&write, &ImpactContext::default());
    assert_eq!(decision.disposition, PolicyDisposition::AutoExecute);
}

#[test]
fn blast_radius_and_real_world_effects_require_approval() {
    let engine = PolicyEngine;
    let mut write = capability("PUT");
    write.risk = RiskClass::ScopedWrite;
    write.effect = EffectClass::ReversibleWrite;
    write.rollback.supported = true;
    write.rollback.strategy = Some("restore captured resource state".to_owned());
    write.cost.known = true;
    write.verification.strategy = "resource_readback_matches_requested_state".to_owned();
    write.permissions = vec!["Test Write".to_owned()];

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
