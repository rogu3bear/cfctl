//! Synthetic targets derived from authenticated native effects, never pack UUIDs.
//! Shape/source validation here does not authenticate receipts or authorize effects.
use serde::{Deserialize, Serialize};

use super::{CaseSource, Pack};
use crate::workspace_d1::transition::{
    EffectRef, Observation, Source, canonical_digest,
    proofs::{Case, CaseRef, Identity},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    pub schema_version: u8,
    pub identity: Identity,
    pub qualification_pack_sha256: String,
    pub case: Case,
    pub resource_name: String,
    pub create: EffectRef,
    pub create_plan_sha256: String,
    pub database_id: String,
}

fn canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| id.to_string() == value)
}

fn effect(reference: &EffectRef) -> bool {
    canonical_uuid(&reference.operation_id) && canonical_digest(&reference.evidence_hash)
}

impl Resource {
    pub fn validate<'a>(
        &self,
        pack: &'a Pack,
        expected: &Identity,
        qualification_pack_sha256: &str,
    ) -> Result<&'a CaseSource, &'static str> {
        pack.validate()?;
        expected.validate()?;
        let source = pack
            .cases
            .iter()
            .find(|source| source.case == self.case)
            .ok_or("synthetic case is not in the frozen pack")?;
        if self.schema_version != 1
            || &self.identity != expected
            || self.qualification_pack_sha256 != qualification_pack_sha256
            || !canonical_digest(qualification_pack_sha256)
            || !canonical_digest(&self.create_plan_sha256)
            || !effect(&self.create)
            || !canonical_uuid(&self.database_id)
            || self.database_id == expected.database_id
            || self.resource_name != source.resource_name
        {
            return Err("synthetic resource source, create lineage or isolation differs");
        }
        Ok(source)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadPhase {
    Before,
    After,
    PostWriter,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PopulationBinding {
    pub resource: Resource,
    pub phase: ReadPhase,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PopulationRequest {
    pub schema_version: u8,
    pub case: Case,
    pub phase: ReadPhase,
    pub create: EffectRef,
    pub expected_credential_generation_id: String,
}

impl PopulationRequest {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != 1
            || !effect(&self.create)
            || !canonical_uuid(&self.expected_credential_generation_id)
        {
            return Err(
                "synthetic population request version, create or credential generation differs",
            );
        }
        Ok(())
    }
}

impl From<crate::workspace_d1::transition::proofs::PopulationPhase> for ReadPhase {
    fn from(value: crate::workspace_d1::transition::proofs::PopulationPhase) -> Self {
        match value {
            crate::workspace_d1::transition::proofs::PopulationPhase::Before => Self::Before,
            crate::workspace_d1::transition::proofs::PopulationPhase::After => Self::After,
        }
    }
}

impl ReadPhase {
    pub fn observation(self, source: &CaseSource) -> Result<&Observation, &'static str> {
        match self {
            Self::Before => Ok(&source.before),
            Self::After => Ok(&source.after),
            Self::PostWriter => source
                .concurrent_source
                .as_ref()
                .map(|writer| &writer.post_writer_inventory)
                .ok_or("post-writer reads require the committed concurrent case"),
        }
    }

    pub fn expected_state(self, source: &CaseSource) -> Result<&str, &'static str> {
        match self {
            Self::Before => Ok(&source.expected_before_state_sha256),
            Self::After => Ok(&source.expected_after_state_sha256),
            Self::PostWriter => source
                .concurrent_source
                .as_ref()
                .map(|writer| writer.expected_post_writer_state_sha256.as_str())
                .ok_or("post-writer oracle requires the committed concurrent case"),
        }
    }
}

/// A separate proposed deletion target after seed and terminal case verification.
/// It is not empty-create compensation and is not deletion approval or absence proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeededCleanupTarget {
    pub schema_version: u8,
    pub resource: Resource,
    pub seed: EffectRef,
    pub terminal: CaseRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedTarget {
    pub resource: Resource,
    pub source: Source,
    pub bytes: usize,
}

impl SeedTarget {
    pub fn validate(
        &self,
        pack: &Pack,
        identity: &Identity,
        pack_sha256: &str,
        seed_bytes: usize,
    ) -> Result<(), &'static str> {
        let case = self.resource.validate(pack, identity, pack_sha256)?;
        if self.source != case.seed
            || self.bytes != seed_bytes
            || seed_bytes == 0
            || seed_bytes > super::super::MAX_ENVELOPE_BYTES
        {
            return Err("seed target substituted committed source or byte length");
        }
        Ok(())
    }
}

impl SeededCleanupTarget {
    pub fn validate(
        &self,
        pack: &Pack,
        identity: &Identity,
        pack_sha256: &str,
        execution_bytes: usize,
    ) -> Result<(), &'static str> {
        let source = self.resource.validate(pack, identity, pack_sha256)?;
        let case = &self.terminal;
        if self.schema_version != 1
            || !effect(&self.seed)
            || !effect(&case.effect)
            || self.resource.create.operation_id == self.seed.operation_id
            || self.resource.create.operation_id == case.effect.operation_id
            || self.seed.operation_id == case.effect.operation_id
            || case.case != source.case
            || case.synthetic_database_id != self.resource.database_id
            || case.fixture_sha256 != source.execution.sha256
            || case.fixture_bytes != execution_bytes
            || case.before_population_inventory != source.before
            || case.after_population_inventory != source.after
            || case.expected_after_state_sha256 != source.expected_after_state_sha256
            || case.failure_sentinel != source.failure_sentinel
            || case.performance_max_seconds != source.performance_max_seconds
            || case.concurrency.as_ref().map(|value| &value.source)
                != source.concurrent_source.as_ref()
        {
            return Err("seeded cleanup substituted a resource, source or terminal case");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
