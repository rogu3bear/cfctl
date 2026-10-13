//! Native application-state proofs derived from authenticated boundary reads.
//! These types contain references and identities, never caller-supplied verdicts.
use serde::{Deserialize, Serialize};

use super::{
    ProofRef, canonical_digest,
    proofs::{CaseRef, Identity, PopulationPhase, Qualification, VerifiedExecutionRecord},
};

pub const PRODUCER_ID: &str = "workspace-d1-transition-produce-proof";
pub const APPLICATION_KIND: &str = "workspace_d1_transition_application_verification_v1";
pub const TARGET_KIND: &str = "workspace_d1_transition_native_target_v1";

/// Recognizes the native typed verifier without activating a blocked adapter.
#[must_use]
pub fn contract_supported(capability: &crate::CapabilityV1) -> bool {
    capability.authority_scope == Some(crate::CapabilityAuthorityScopeV1::WorkspaceOwned)
        && capability.adapter_status == crate::AdapterStatus::Native
        && capability.path == "workspace:d1-transition-envelope-v3"
        && capability.method == "POST"
        && capability.mutating
        && capability.risk == crate::RiskClass::Irreversible
        && capability.effect == crate::EffectClass::DataWrite
        && capability
            .workspace_d1_migration
            .as_ref()
            .is_some_and(|contract| {
                Identity::from_contract(contract).is_ok_and(|identity| identity.validate().is_ok())
                    && contract.transition.as_ref().is_some_and(|compiled| {
                        compiled.compiler_id == super::COMPILER_ID
                            && compiled.execution.compiler_id == super::EXECUTION_COMPILER_ID
                            && compiled.execution.execution_length <= super::MAX_ENVELOPE_BYTES
                            && compiled.declaration.assurance.is_some()
                            && compiled.declaration.observations.is_some()
                    })
            })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationVerification {
    pub schema_version: u8,
    pub kind: String,
    pub identity: Identity,
    pub verified_execution: VerifiedExecutionRecord,
    pub terminal_assertions: ProofRef,
    pub diagnostic: ProofRef,
}

impl ApplicationVerification {
    pub fn validate(&self) -> Result<(), &'static str> {
        self.identity.validate()?;
        self.verified_execution.validate()?;
        let terminal = self.verified_execution.execution.terminal()?;
        if self.schema_version != 1
            || self.kind != APPLICATION_KIND
            || self.identity != terminal.identity
            || terminal.stage != super::execution::Stage::Committed
            || [&self.terminal_assertions, &self.diagnostic]
                .iter()
                .any(|reference| {
                    !canonical_digest(&reference.proof_hash)
                        || !canonical_digest(&reference.evidence_hash)
                })
        {
            return Err("application verification source, terminal or read references differ");
        }
        Ok(())
    }
}

/// A local producer authenticates every referenced native record again. The
/// `capability_id` selects a registered source owner, not arbitrary source paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProofRequest {
    Application {
        operation_id: String,
        terminal_assertions: ProofRef,
        diagnostic: ProofRef,
    },
    Population {
        capability_id: String,
        case: Box<CaseRef>,
        phase: PopulationPhase,
        source: ProofRef,
    },
    Case {
        capability_id: String,
        case: Box<CaseRef>,
    },
    Writer {
        capability_id: String,
        case: Box<CaseRef>,
    },
    Poll {
        capability_id: String,
        case: Box<CaseRef>,
    },
    Aggregate {
        capability_id: String,
        qualification: Box<Qualification>,
    },
}
