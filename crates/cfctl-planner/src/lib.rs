//! Deterministic risk, approval, and transaction policy.

use cfctl_core::{CapabilityV1, EffectClass, PolicyDecisionV1, PolicyDisposition, RiskClass};
use serde::{Deserialize, Serialize};

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
        let mut reasons = Vec::new();
        let mut disposition = PolicyDisposition::AutoExecute;
        let mut requires_cost_ceiling = false;

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
        if capability.adapter_status == cfctl_core::AdapterStatus::Blocked {
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

        require_incremental_cost_approval(
            capability,
            &mut disposition,
            &mut requires_cost_ceiling,
            &mut reasons,
        );

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
            disposition = PolicyDisposition::ApprovalRequired;
            reasons.push("operation affects multiple repositories".to_owned());
        }
        if impact.dependent_configurations > 0 || impact.has_unmanaged_dependencies {
            disposition = PolicyDisposition::ApprovalRequired;
            reasons.push("operation has dependent or unmanaged configuration".to_owned());
        }

        apply_effect_policy(
            capability,
            &mut disposition,
            &mut requires_cost_ceiling,
            &mut reasons,
        );

        if matches!(capability.risk, RiskClass::Unknown | RiskClass::CrossConfig) {
            disposition = PolicyDisposition::ApprovalRequired;
            reasons.push("risk is unknown or crosses configuration boundaries".to_owned());
        }
        if reasons.is_empty() {
            reasons.push("known scoped reversible write".to_owned());
        }

        PolicyDecisionV1 {
            schema_version: 1,
            disposition,
            reasons,
            requires_cost_ceiling,
        }
    }
}

fn require_incremental_cost_approval(
    capability: &CapabilityV1,
    disposition: &mut PolicyDisposition,
    requires_cost_ceiling: &mut bool,
    reasons: &mut Vec<String>,
) {
    if capability.cost.incremental {
        *disposition = PolicyDisposition::ApprovalRequired;
        *requires_cost_ceiling = true;
        reasons.push("operation can incur incremental cost".to_owned());
    }
}

fn apply_effect_policy(
    capability: &CapabilityV1,
    disposition: &mut PolicyDisposition,
    requires_cost_ceiling: &mut bool,
    reasons: &mut Vec<String>,
) {
    match capability.effect {
        EffectClass::ReadOnly => {}
        EffectClass::ReversibleWrite => {
            if capability.risk != RiskClass::ScopedWrite || !capability.rollback.supported {
                *disposition = PolicyDisposition::ApprovalRequired;
                reasons.push(
                    "write is not both known-scoped and backed by a declared rollback".to_owned(),
                );
            }
        }
        EffectClass::Spend => {
            *disposition = PolicyDisposition::ApprovalRequired;
            *requires_cost_ceiling = true;
            if !reasons
                .iter()
                .any(|reason| reason == "operation can incur incremental cost")
            {
                reasons.push("operation can incur incremental cost".to_owned());
            }
        }
        EffectClass::Destructive
        | EffectClass::ExternalCommunication
        | EffectClass::IdentityOrOwnership
        | EffectClass::Irreversible
        | EffectClass::Unknown => {
            *disposition = PolicyDisposition::ApprovalRequired;
            reasons.push(format!("operation has {:?} effects", capability.effect));
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
