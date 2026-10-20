//! Deterministic risk, approval, and transaction policy.

use cfctl_core::{
    AdapterStatus, CapabilityV1, EffectClass, PolicyDecisionV1, PolicyDisposition, RiskClass,
};
use serde::{Deserialize, Serialize};

const INCREMENTAL_COST_REASON: &str = "operation can incur incremental cost";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImpactContext {
    pub affected_repositories: usize,
    pub affected_resources: usize,
    pub dependent_configurations: usize,
    pub has_unmanaged_dependencies: bool,
    pub has_dirty_overlap: bool,
    pub selector_ambiguous: bool,
}

#[derive(Debug, Clone, Default)]
pub struct PolicyEngine;

impl PolicyEngine {
    #[must_use]
    pub fn evaluate(&self, capability: &CapabilityV1, impact: &ImpactContext) -> PolicyDecisionV1 {
        // Blocking checks precede approval policy; their order selects the reason.
        if impact.selector_ambiguous {
            return decision(
                PolicyDisposition::Blocked,
                ["selectors resolve ambiguously"],
                false,
            );
        }
        if impact.has_dirty_overlap {
            return decision(
                PolicyDisposition::Blocked,
                ["a proposed repository patch overlaps uncommitted work"],
                false,
            );
        }
        if capability.adapter_status == AdapterStatus::Blocked {
            return decision(
                PolicyDisposition::Blocked,
                ["the capability adapter is blocked"],
                false,
            );
        }
        let contract_gaps = capability.mutation_contract_gaps();
        if !contract_gaps.is_empty() {
            return PolicyDecisionV1 {
                schema_version: 1,
                disposition: PolicyDisposition::Blocked,
                reasons: contract_gaps,
                requires_cost_ceiling: capability.cost.incremental && !capability.cost.known,
            };
        }
        if capability.effect == EffectClass::Spend
            && capability.cost.incremental
            && !capability.cost.known
        {
            return decision(
                PolicyDisposition::Blocked,
                ["incremental cost is unknown and cannot satisfy a hard ceiling"],
                true,
            );
        }

        // Reasons retain insertion order because the CLI hashes the full decision.
        let mut policy = decision(PolicyDisposition::AutoExecute, [], false);

        require_incremental_cost_approval(capability, &mut policy);

        if capability.effect == EffectClass::ReadOnly
            && capability.risk == RiskClass::Read
            && !capability.cost.incremental
        {
            return decision(
                PolicyDisposition::AutoExecute,
                ["read-only operation"],
                false,
            );
        }

        if impact.affected_repositories > 1 {
            policy.disposition = PolicyDisposition::ApprovalRequired;
            policy
                .reasons
                .push("operation affects multiple repositories".to_owned());
        }
        if impact.dependent_configurations > 0 || impact.has_unmanaged_dependencies {
            policy.disposition = PolicyDisposition::ApprovalRequired;
            policy
                .reasons
                .push("operation has dependent or unmanaged configuration".to_owned());
        }

        apply_effect_policy(capability, &mut policy);

        if matches!(capability.risk, RiskClass::Unknown | RiskClass::CrossConfig) {
            policy.disposition = PolicyDisposition::ApprovalRequired;
            policy
                .reasons
                .push("risk is unknown or crosses configuration boundaries".to_owned());
        }
        if policy.reasons.is_empty() {
            policy
                .reasons
                .push("known scoped reversible write".to_owned());
        }

        policy
    }
}

fn require_incremental_cost_approval(capability: &CapabilityV1, policy: &mut PolicyDecisionV1) {
    if capability.cost.incremental {
        policy.disposition = PolicyDisposition::ApprovalRequired;
        policy.requires_cost_ceiling = true;
        policy.reasons.push(INCREMENTAL_COST_REASON.to_owned());
    }
}

fn apply_effect_policy(capability: &CapabilityV1, policy: &mut PolicyDecisionV1) {
    match capability.effect {
        EffectClass::ReadOnly => {}
        EffectClass::DataWrite => {
            policy.disposition = PolicyDisposition::ApprovalRequired;
            policy
                .reasons
                .push("operation writes database state".to_owned());
        }
        EffectClass::ReversibleWrite => {
            if capability.risk != RiskClass::ScopedWrite || !capability.rollback.supported {
                policy.disposition = PolicyDisposition::ApprovalRequired;
                policy.reasons.push(
                    "write is not both known-scoped and backed by a declared rollback".to_owned(),
                );
            }
        }
        EffectClass::Spend => {
            policy.disposition = PolicyDisposition::ApprovalRequired;
            policy.requires_cost_ceiling = true;
            if !policy
                .reasons
                .iter()
                .any(|reason| reason == INCREMENTAL_COST_REASON)
            {
                policy.reasons.push(INCREMENTAL_COST_REASON.to_owned());
            }
        }
        EffectClass::Destructive
        | EffectClass::ExternalCommunication
        | EffectClass::IdentityOrOwnership
        | EffectClass::Irreversible
        | EffectClass::Unknown => {
            policy.disposition = PolicyDisposition::ApprovalRequired;
            policy
                .reasons
                .push(format!("operation has {:?} effects", capability.effect));
        }
    }
}

fn decision<const N: usize>(
    disposition: PolicyDisposition,
    reasons: [&str; N],
    requires_cost_ceiling: bool,
) -> PolicyDecisionV1 {
    PolicyDecisionV1 {
        schema_version: 1,
        disposition,
        reasons: reasons.into_iter().map(str::to_owned).collect(),
        requires_cost_ceiling,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfctl_core::{
        AdapterStatus, D1RestoreExactBookmarkContractV1, PolicyDisposition, RollbackSpecV1,
        VerificationSpecV1,
    };

    #[test]
    fn d1_recovery_data_write_requires_explicit_approval_without_cost_ceiling() {
        let mut capability = CapabilityV1::new(
            "d1-restore-exact-bookmark",
            "Restore D1 database to exact bookmark",
            "POST",
            "/accounts/{account_id}/d1/database/{database_id}/time_travel/restore",
        );
        capability.product = "D1".to_owned();
        capability.account_scope = "account".to_owned();
        capability.adapter_status = AdapterStatus::Native;
        capability.risk = RiskClass::Recovery;
        capability.effect = EffectClass::DataWrite;
        capability.cost.known = true;
        capability.cost.incremental = false;
        capability.verification = VerificationSpecV1 {
            required: true,
            strategy: "d1_current_bookmark_equals_restore_result_bookmark".to_owned(),
        };
        capability.rollback = RollbackSpecV1 {
            supported: true,
            strategy: Some("new_approved_exact_bookmark_restore_from_previous_bookmark".to_owned()),
            warning: Some("recovery is a new approved plan".to_owned()),
        };
        capability.d1_restore_exact_bookmark = Some(D1RestoreExactBookmarkContractV1 {
            bookmark_path: "/accounts/{account_id}/d1/database/{database_id}/time_travel/bookmark"
                .to_owned(),
            restore_path: "/accounts/{account_id}/d1/database/{database_id}/time_travel/restore"
                .to_owned(),
            max_response_bytes: 64 * 1024,
            max_timeout_seconds: 30,
            post_retry_count: 0,
        });
        let decision = PolicyEngine.evaluate(&capability, &ImpactContext::default());
        assert_eq!(decision.disposition, PolicyDisposition::ApprovalRequired);
        assert!(!decision.requires_cost_ceiling);
        assert!(
            decision
                .reasons
                .iter()
                .any(|reason| reason == "operation writes database state")
        );
    }
}
