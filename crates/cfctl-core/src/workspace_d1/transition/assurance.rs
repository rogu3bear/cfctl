//! Explicit V3 assurance proposals. Parsing never activates an operator decision.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{EffectRef, Observation, ProofRef, Source, Target, canonical_digest};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum Declaration {
    FullIntegrityV1 {
        diagnostic: Observation,
    },
    ManagedD1ApplicationV1 {
        policy: Source,
        diagnostic: Observation,
    },
}

impl Declaration {
    #[must_use]
    pub const fn diagnostic(&self) -> &Observation {
        match self {
            Self::FullIntegrityV1 { diagnostic }
            | Self::ManagedD1ApplicationV1 { diagnostic, .. } => diagnostic,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnobservedProperty {
    GlobalIndexConsistency,
    GlobalUniquenessStorageConsistency,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Control {
    PrimaryQuickCheck,
    ExactSchema,
    FullScanTypedPopulationPreservation,
    ForeignKeyCheck,
    AtomicFailureRollback,
    TargetOnceLedger,
    FinalScratchCleanup,
}

/// Source-owned decision target, not an approval and not a full database certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedPolicyV1 {
    pub schema_version: u8,
    pub mode: String,
    pub release_id: String,
    pub account_id: String,
    pub database_id: String,
    pub target_sequence: u64,
    pub migration_sha256: String,
    pub accepted_unobserved_properties: Vec<UnobservedProperty>,
    pub required_controls: Vec<Control>,
}

impl ManagedPolicyV1 {
    pub fn validate(
        &self,
        account: &str,
        database: &str,
        target: &Target,
    ) -> Result<(), &'static str> {
        use Control::{
            AtomicFailureRollback, ExactSchema, FinalScratchCleanup, ForeignKeyCheck,
            FullScanTypedPopulationPreservation, PrimaryQuickCheck, TargetOnceLedger,
        };
        use UnobservedProperty::{GlobalIndexConsistency, GlobalUniquenessStorageConsistency};
        let gaps: BTreeSet<_> = self
            .accepted_unobserved_properties
            .iter()
            .copied()
            .collect();
        let controls: BTreeSet<_> = self.required_controls.iter().copied().collect();
        if self.schema_version != 1
            || self.mode != "managed_d1_application_v1"
            || self.release_id.trim().is_empty()
            || self.account_id != account
            || self.database_id != database
            || self.target_sequence != target.sequence
            || self.migration_sha256 != target.source.sha256
            || !canonical_digest(&self.migration_sha256)
            || gaps.len() != self.accepted_unobserved_properties.len()
            || gaps != BTreeSet::from([GlobalIndexConsistency, GlobalUniquenessStorageConsistency])
            || controls.len() != self.required_controls.len()
            || controls
                != BTreeSet::from([
                    PrimaryQuickCheck,
                    ExactSchema,
                    FullScanTypedPopulationPreservation,
                    ForeignKeyCheck,
                    AtomicFailureRollback,
                    TargetOnceLedger,
                    FinalScratchCleanup,
                ])
        {
            return Err("managed assurance policy scope, version or cumulative controls differ");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum Binding {
    FullIntegrityV1 {
        diagnostic: ProofRef,
    },
    ManagedD1ApplicationV1 {
        diagnostic: ProofRef,
        policy_decision: EffectRef,
    },
}

impl Binding {
    pub fn validate_mode(&self, expected: &Declaration) -> Result<(), &'static str> {
        match (self, expected) {
            (Self::FullIntegrityV1 { .. }, Declaration::FullIntegrityV1 { .. })
            | (Self::ManagedD1ApplicationV1 { .. }, Declaration::ManagedD1ApplicationV1 { .. }) => {
                Ok(())
            }
            _ => Err("source and runtime assurance modes differ"),
        }
    }

    #[must_use]
    pub const fn diagnostic(&self) -> &ProofRef {
        match self {
            Self::FullIntegrityV1 { diagnostic }
            | Self::ManagedD1ApplicationV1 { diagnostic, .. } => diagnostic,
        }
    }
}
