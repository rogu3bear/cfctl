#![allow(clippy::expect_used, clippy::unwrap_used)]

use cfctl_core::{
    AdapterStatus, CapabilityV1, CostV1, CreatedResourceContractV1, DeletedResourceContractV1,
    EffectClass, PolicyDecisionV1, PolicyDisposition, RiskClass,
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
fn known_incremental_cost_requires_a_ceiling_even_for_a_reversible_write() {
    let engine = PolicyEngine;
    let mut paid = reversible_write();
    paid.cost.incremental = true;
    paid.cost.known = true;
    paid.cost.currency = Some("USD".to_owned());
    paid.cost.maximum = Some(0.000_009);

    let decision = engine.evaluate(&paid, &ImpactContext::default());
    assert_eq!(decision.disposition, PolicyDisposition::ApprovalRequired);
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

// The CLI hashes the complete compiled decision when preparing and checking a
// plan. Pin reasons and their order as well as the disposition and cost flag.
fn assert_policy(
    capability: &CapabilityV1,
    impact: &ImpactContext,
    disposition: PolicyDisposition,
    reasons: &[&str],
    requires_cost_ceiling: bool,
) {
    assert_eq!(
        PolicyEngine.evaluate(capability, impact),
        PolicyDecisionV1 {
            schema_version: 1,
            disposition,
            reasons: reasons.iter().map(|reason| (*reason).to_owned()).collect(),
            requires_cost_ceiling,
        },
        "capability: {capability:?}; impact: {impact:?}"
    );
}

#[test]
fn selector_dirty_and_adapter_blocks_precede_contract_and_cost_checks() {
    let mut write = capability("POST");
    write.cost.incremental = true;
    write.adapter_status = AdapterStatus::Blocked;
    assert!(!write.mutation_contract_gaps().is_empty());

    for (selector_ambiguous, has_dirty_overlap, reason) in [
        (true, true, "selectors resolve ambiguously"),
        (
            false,
            true,
            "a proposed repository patch overlaps uncommitted work",
        ),
        (false, false, "the capability adapter is blocked"),
    ] {
        assert_policy(
            &write,
            &ImpactContext {
                selector_ambiguous,
                has_dirty_overlap,
                ..ImpactContext::default()
            },
            PolicyDisposition::Blocked,
            &[reason],
            false,
        );
    }
}

#[test]
fn mutation_contract_gaps_keep_their_order_and_unknown_cost_flag() {
    let mut write = reversible_write();
    write.cost.known = false;
    write.permissions.clear();
    write.verification.strategy = "phantom_readback".to_owned();
    write.rollback.strategy = Some("phantom_restore".to_owned());

    for incremental in [false, true] {
        write.cost.incremental = incremental;
        assert_policy(
            &write,
            &ImpactContext {
                affected_repositories: 2,
                has_unmanaged_dependencies: true,
                ..ImpactContext::default()
            },
            PolicyDisposition::Blocked,
            &[
                "operation-specific incremental cost is unknown",
                "declared verification strategy is unsupported: phantom_readback",
                "declared rollback strategy is unsupported: phantom_restore",
                "required Cloudflare permission lane is not declared",
            ],
            incremental,
        );
    }
}

#[test]
fn uncharged_reads_ignore_approval_only_impact_metadata() {
    let impact = ImpactContext {
        affected_repositories: usize::MAX,
        affected_resources: usize::MAX,
        dependent_configurations: usize::MAX,
        has_unmanaged_dependencies: true,
        ..ImpactContext::default()
    };
    for method in ["GET", "HEAD", "OPTIONS"] {
        assert_policy(
            &capability(method),
            &impact,
            PolicyDisposition::AutoExecute,
            &["read-only operation"],
            false,
        );
    }
}

#[test]
fn reads_still_obey_selector_dirty_and_adapter_blocks() {
    let mut read = capability("GET");
    for (impact, reason) in [
        (
            ImpactContext {
                selector_ambiguous: true,
                ..ImpactContext::default()
            },
            "selectors resolve ambiguously",
        ),
        (
            ImpactContext {
                has_dirty_overlap: true,
                ..ImpactContext::default()
            },
            "a proposed repository patch overlaps uncommitted work",
        ),
    ] {
        assert_policy(&read, &impact, PolicyDisposition::Blocked, &[reason], false);
    }
    read.adapter_status = AdapterStatus::Blocked;
    assert_policy(
        &read,
        &ImpactContext::default(),
        PolicyDisposition::Blocked,
        &["the capability adapter is blocked"],
        false,
    );
}

#[test]
fn isolated_write_impact_thresholds_and_dependency_reasons_are_stable() {
    let write = reversible_write();
    assert!(write.mutation_contract_gaps().is_empty());
    for affected_repositories in [0, 1, 2] {
        let (disposition, reason) = if affected_repositories == 2 {
            (
                PolicyDisposition::ApprovalRequired,
                "operation affects multiple repositories",
            )
        } else {
            (
                PolicyDisposition::AutoExecute,
                "known scoped reversible write",
            )
        };
        assert_policy(
            &write,
            &ImpactContext {
                affected_repositories,
                affected_resources: usize::MAX,
                ..ImpactContext::default()
            },
            disposition,
            &[reason],
            false,
        );
    }
    for (dependent_configurations, has_unmanaged_dependencies) in [(1, false), (0, true), (1, true)]
    {
        assert_policy(
            &write,
            &ImpactContext {
                dependent_configurations,
                has_unmanaged_dependencies,
                ..ImpactContext::default()
            },
            PolicyDisposition::ApprovalRequired,
            &["operation has dependent or unmanaged configuration"],
            false,
        );
    }
}

#[test]
fn complete_write_contract_keeps_effect_specific_decisions() {
    for (effect, disposition, reason, ceiling) in [
        (
            EffectClass::ReversibleWrite,
            PolicyDisposition::AutoExecute,
            "known scoped reversible write",
            false,
        ),
        (
            EffectClass::DataWrite,
            PolicyDisposition::ApprovalRequired,
            "operation writes database state",
            false,
        ),
        (
            EffectClass::Spend,
            PolicyDisposition::ApprovalRequired,
            "operation can incur incremental cost",
            true,
        ),
        (
            EffectClass::Destructive,
            PolicyDisposition::ApprovalRequired,
            "operation has Destructive effects",
            false,
        ),
        (
            EffectClass::ExternalCommunication,
            PolicyDisposition::ApprovalRequired,
            "operation has ExternalCommunication effects",
            false,
        ),
        (
            EffectClass::IdentityOrOwnership,
            PolicyDisposition::ApprovalRequired,
            "operation has IdentityOrOwnership effects",
            false,
        ),
        (
            EffectClass::Irreversible,
            PolicyDisposition::ApprovalRequired,
            "operation has Irreversible effects",
            false,
        ),
    ] {
        let mut write = reversible_write();
        write.effect = effect;
        assert!(write.mutation_contract_gaps().is_empty());
        assert_policy(
            &write,
            &ImpactContext::default(),
            disposition,
            &[reason],
            ceiling,
        );
    }
}

#[test]
fn reversible_write_risk_classes_keep_their_existing_approval_floor() {
    for risk in [
        RiskClass::Read,
        RiskClass::Recovery,
        RiskClass::SecretSensitive,
        RiskClass::Destructive,
        RiskClass::ExternalCommunication,
        RiskClass::IdentityOrOwnership,
        RiskClass::Spend,
        RiskClass::Irreversible,
    ] {
        let mut write = reversible_write();
        write.risk = risk;
        assert!(write.mutation_contract_gaps().is_empty());
        assert_policy(
            &write,
            &ImpactContext::default(),
            PolicyDisposition::ApprovalRequired,
            &["write is not both known-scoped and backed by a declared rollback"],
            false,
        );
    }
    let mut write = reversible_write();
    write.risk = RiskClass::Unknown;
    assert_policy(
        &write,
        &ImpactContext::default(),
        PolicyDisposition::Blocked,
        &["operation-specific risk classification is missing"],
        false,
    );
}

#[test]
fn incremental_spend_has_one_cost_reason() {
    let mut write = reversible_write();
    write.effect = EffectClass::Spend;
    write.cost.incremental = true;
    write.cost.currency = Some("USD".to_owned());
    write.cost.maximum = Some(0.0);
    assert!(write.mutation_contract_gaps().is_empty());
    assert_policy(
        &write,
        &ImpactContext::default(),
        PolicyDisposition::ApprovalRequired,
        &["operation can incur incremental cost"],
        true,
    );
}

#[test]
fn approval_reasons_accumulate_in_policy_hash_order() {
    let mut write = reversible_write();
    write.risk = RiskClass::CrossConfig;
    write.effect = EffectClass::DataWrite;
    write.cost.incremental = true;
    write.cost.currency = Some("USD".to_owned());
    write.cost.maximum = Some(1.0);
    assert!(write.mutation_contract_gaps().is_empty());
    assert_policy(
        &write,
        &ImpactContext {
            affected_repositories: 2,
            dependent_configurations: 1,
            has_unmanaged_dependencies: true,
            ..ImpactContext::default()
        },
        PolicyDisposition::ApprovalRequired,
        &[
            "operation can incur incremental cost",
            "operation affects multiple repositories",
            "operation has dependent or unmanaged configuration",
            "operation writes database state",
            "risk is unknown or crosses configuration boundaries",
        ],
        true,
    );
}

#[test]
fn supported_adapter_classes_share_the_same_isolated_write_policy() {
    for adapter in [
        AdapterStatus::Native,
        AdapterStatus::DynamicApi,
        AdapterStatus::DelegatedCli,
        AdapterStatus::GovernedUi,
    ] {
        let mut write = reversible_write();
        write.adapter_status = adapter;
        assert!(write.mutation_contract_gaps().is_empty());
        assert_policy(
            &write,
            &ImpactContext::default(),
            PolicyDisposition::AutoExecute,
            &["known scoped reversible write"],
            false,
        );
    }
}

#[test]
fn read_metadata_keeps_cost_risk_and_impact_decisions() {
    for (known, incremental, risk, cross_repository, disposition, reasons, ceiling) in [
        (
            false,
            false,
            RiskClass::Read,
            true,
            PolicyDisposition::AutoExecute,
            vec!["read-only operation"],
            false,
        ),
        (
            true,
            false,
            RiskClass::ScopedWrite,
            false,
            PolicyDisposition::AutoExecute,
            vec!["known scoped reversible write"],
            false,
        ),
        (
            true,
            false,
            RiskClass::Unknown,
            false,
            PolicyDisposition::ApprovalRequired,
            vec!["risk is unknown or crosses configuration boundaries"],
            false,
        ),
        (
            true,
            true,
            RiskClass::Read,
            false,
            PolicyDisposition::ApprovalRequired,
            vec!["operation can incur incremental cost"],
            true,
        ),
        (
            false,
            true,
            RiskClass::Read,
            false,
            PolicyDisposition::ApprovalRequired,
            vec!["operation can incur incremental cost"],
            true,
        ),
        (
            true,
            true,
            RiskClass::CrossConfig,
            true,
            PolicyDisposition::ApprovalRequired,
            vec![
                "operation can incur incremental cost",
                "operation affects multiple repositories",
                "operation has dependent or unmanaged configuration",
                "risk is unknown or crosses configuration boundaries",
            ],
            true,
        ),
        (
            false,
            true,
            RiskClass::Unknown,
            true,
            PolicyDisposition::ApprovalRequired,
            vec![
                "operation can incur incremental cost",
                "operation affects multiple repositories",
                "operation has dependent or unmanaged configuration",
                "risk is unknown or crosses configuration boundaries",
            ],
            true,
        ),
    ] {
        let mut read = capability("GET");
        read.cost.known = known;
        read.cost.incremental = incremental;
        read.risk = risk;
        assert!(read.mutation_contract_gaps().is_empty());
        let impact = if cross_repository {
            ImpactContext {
                affected_repositories: 2,
                dependent_configurations: 1,
                has_unmanaged_dependencies: true,
                ..ImpactContext::default()
            }
        } else {
            ImpactContext::default()
        };
        assert_policy(&read, &impact, disposition, &reasons, ceiling);
    }
}

#[test]
fn charged_reads_keep_early_block_precedence_and_clear_ceiling() {
    for known in [false, true] {
        for (selector_ambiguous, has_dirty_overlap, reason) in [
            (true, true, "selectors resolve ambiguously"),
            (
                false,
                true,
                "a proposed repository patch overlaps uncommitted work",
            ),
            (false, false, "the capability adapter is blocked"),
        ] {
            let mut read = capability("GET");
            read.cost.known = known;
            read.cost.incremental = true;
            read.adapter_status = AdapterStatus::Blocked;
            assert_policy(
                &read,
                &ImpactContext {
                    selector_ambiguous,
                    has_dirty_overlap,
                    ..ImpactContext::default()
                },
                PolicyDisposition::Blocked,
                &[reason],
                false,
            );
        }
    }
}

#[test]
fn non_mutating_spend_keeps_cost_guard_and_reason_order() {
    // Exercise metadata accepted by the pure planner, without claiming that
    // these synthetic GET/Spend combinations are executable capabilities.
    for (known, incremental, disposition, reasons) in [
        (
            true,
            false,
            PolicyDisposition::ApprovalRequired,
            vec![
                "operation affects multiple repositories",
                "operation has dependent or unmanaged configuration",
                "operation can incur incremental cost",
                "risk is unknown or crosses configuration boundaries",
            ],
        ),
        (
            false,
            false,
            PolicyDisposition::ApprovalRequired,
            vec![
                "operation affects multiple repositories",
                "operation has dependent or unmanaged configuration",
                "operation can incur incremental cost",
                "risk is unknown or crosses configuration boundaries",
            ],
        ),
        (
            true,
            true,
            PolicyDisposition::ApprovalRequired,
            vec![
                "operation can incur incremental cost",
                "operation affects multiple repositories",
                "operation has dependent or unmanaged configuration",
                "risk is unknown or crosses configuration boundaries",
            ],
        ),
        (
            false,
            true,
            PolicyDisposition::Blocked,
            vec!["incremental cost is unknown and cannot satisfy a hard ceiling"],
        ),
    ] {
        let mut spend = capability("GET");
        spend.effect = EffectClass::Spend;
        spend.risk = RiskClass::Unknown;
        spend.cost.known = known;
        spend.cost.incremental = incremental;
        assert!(spend.mutation_contract_gaps().is_empty());
        assert_policy(
            &spend,
            &ImpactContext {
                affected_repositories: 2,
                dependent_configurations: 1,
                has_unmanaged_dependencies: true,
                ..ImpactContext::default()
            },
            disposition,
            &reasons,
            true,
        );
    }
}

#[test]
fn missing_rollback_declaration_blocks_before_known_cost_approval() {
    for incremental in [false, true] {
        for (supported, warning) in [
            (true, None),
            (false, None),
            (false, Some("rollback semantics have not been declared")),
        ] {
            let mut write = reversible_write();
            write.rollback.supported = supported;
            write.rollback.strategy = None;
            write.rollback.warning = warning.map(str::to_owned);
            write.cost.incremental = incremental;
            write.cost.currency = Some("USD".to_owned());
            write.cost.maximum = Some(1.0);
            assert_policy(
                &write,
                &ImpactContext::default(),
                PolicyDisposition::Blocked,
                &["operation-specific rollback or irreversibility behavior is not declared"],
                false,
            );
        }
    }
}

#[test]
fn declared_manual_rollback_keeps_reversible_write_approval_and_order() {
    for (risk, risk_reasons) in [
        (RiskClass::ScopedWrite, vec![]),
        (RiskClass::Read, vec![]),
        (
            RiskClass::CrossConfig,
            vec!["risk is unknown or crosses configuration boundaries"],
        ),
    ] {
        for incremental in [false, true] {
            let mut write = reversible_write();
            write.risk = risk;
            write.rollback.supported = false;
            write.rollback.strategy = None;
            write.rollback.warning = Some("restore the prior state manually".to_owned());
            write.cost.incremental = incremental;
            write.cost.currency = Some("USD".to_owned());
            write.cost.maximum = Some(1.0);
            assert!(write.mutation_contract_gaps().is_empty());
            let mut reasons = if incremental {
                vec!["operation can incur incremental cost"]
            } else {
                vec![]
            };
            reasons.extend([
                "operation affects multiple repositories",
                "operation has dependent or unmanaged configuration",
                "write is not both known-scoped and backed by a declared rollback",
            ]);
            reasons.extend_from_slice(&risk_reasons);
            assert_policy(
                &write,
                &ImpactContext {
                    affected_repositories: 2,
                    has_unmanaged_dependencies: true,
                    ..ImpactContext::default()
                },
                PolicyDisposition::ApprovalRequired,
                &reasons,
                incremental,
            );
        }
    }
}

#[test]
fn non_mutating_unknown_effect_keeps_effect_and_risk_reasons() {
    // Unknown mutating metadata is rejected by core admission instead. This
    // fixture pins the planner branch reachable only past that boundary.
    for incremental in [false, true] {
        let mut unknown = capability("GET");
        unknown.effect = EffectClass::Unknown;
        unknown.risk = RiskClass::Unknown;
        unknown.cost.incremental = incremental;
        assert!(unknown.mutation_contract_gaps().is_empty());
        let mut reasons = if incremental {
            vec!["operation can incur incremental cost"]
        } else {
            vec![]
        };
        reasons.extend([
            "operation has Unknown effects",
            "risk is unknown or crosses configuration boundaries",
        ]);
        assert_policy(
            &unknown,
            &ImpactContext::default(),
            PolicyDisposition::ApprovalRequired,
            &reasons,
            incremental,
        );
    }
}
