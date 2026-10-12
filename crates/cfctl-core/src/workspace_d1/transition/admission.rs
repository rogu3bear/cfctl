//! Committed synthetic qualification inputs, separate from production permission.
//! Resource UUIDs and operation/evidence references are resolved at runtime.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{
    Observation, Source, canonical_digest, lower_hex,
    proofs::{Case, ConcurrentSource},
};

pub const PACK_PATH: &str = ".cfctl/operations/d1-transition-qualification.toml";
pub const CONTRACT: &str = "workspace_d1_transition_qualification_v1";

pub mod resource;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Create,
    Seed,
    Execute,
    Writer,
    Poll,
    Cleanup,
    Population,
    Aggregate,
    Policy,
}

impl Role {
    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            Self::Create => "workspace:d1-transition-create-v1",
            Self::Seed => "workspace:d1-transition-seed-v1",
            Self::Execute => "workspace:d1-transition-qualification-v1",
            Self::Writer => "workspace:d1-transition-writer-v1",
            Self::Poll => "workspace:d1-transition-poll-v1",
            Self::Cleanup => "workspace:d1-transition-cleanup-v1",
            Self::Population => "workspace:d1-transition-population-v1",
            Self::Aggregate => "workspace:d1-transition-aggregate-v1",
            Self::Policy => "workspace:d1-assurance-policy-v1",
        }
    }

    #[must_use]
    pub const fn mutates(self) -> bool {
        !matches!(self, Self::Population | Self::Aggregate)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub id: String,
    pub title: String,
    pub description: String,
    pub role: Role,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseSource {
    pub case: Case,
    pub resource_name: String,
    pub seed: Source,
    pub execution: Source,
    pub before: Observation,
    pub after: Observation,
    pub before_oracle: Source,
    pub after_oracle: Source,
    pub expected_before_state_sha256: String,
    pub expected_after_state_sha256: String,
    pub failure_sentinel: Option<String>,
    pub performance_max_seconds: Option<u64>,
    pub concurrent_source: Option<ConcurrentSource>,
    pub post_writer_oracle: Option<Source>,
}

/// Names and source bytes are frozen before the first resource is created.
/// A resource's runtime identity must derive from its separately approved create
/// plan, so ten sequential lifetimes never require changing the committed pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pack {
    pub schema_version: u8,
    pub contract: String,
    pub transition_operation_id: String,
    pub maximum_live_databases: u8,
    pub maximum_database_lifetimes: u8,
    pub resets_allowed: bool,
    pub operation: Vec<Operation>,
    pub cases: Vec<CaseSource>,
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 160
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn source(value: &Source) -> bool {
    !value.path.is_empty()
        && !value.path.starts_with('/')
        && !value.path.contains('\\')
        && value
            .path
            .split('/')
            .all(|p| !p.is_empty() && p != "." && p != "..")
        && canonical_digest(&value.sha256)
        && lower_hex(&value.git_blob_oid, 40)
}

impl Pack {
    pub fn validate(&self) -> Result<(), &'static str> {
        use Role::{Aggregate, Cleanup, Create, Execute, Policy, Poll, Population, Seed, Writer};
        let roles: BTreeSet<_> = self.operation.iter().map(|op| op.role).collect();
        let ids: BTreeSet<_> = self.operation.iter().map(|op| op.id.as_str()).collect();
        if self.schema_version != 1
            || self.contract != CONTRACT
            || !valid_id(&self.transition_operation_id)
            || self.maximum_live_databases != 1
            || self.maximum_database_lifetimes != 10
            || self.resets_allowed
            || self.operation.len() != 9
            || roles
                != BTreeSet::from([
                    Create, Seed, Execute, Writer, Poll, Cleanup, Population, Aggregate, Policy,
                ])
            || ids.len() != self.operation.len()
            || self.operation.iter().any(|op| {
                !valid_id(&op.id)
                    || op.id == self.transition_operation_id
                    || op.title.trim().is_empty()
                    || op.description.trim().is_empty()
            })
        {
            return Err("qualification pack version, identity, roles or resource bounds differ");
        }
        let population = self
            .operation
            .iter()
            .find(|op| op.role == Population)
            .ok_or("qualification population operation missing")?;
        let required = BTreeSet::from([
            Case::Success,
            Case::MigrationFailure,
            Case::LedgerFailure,
            Case::CleanupFailure,
            Case::ConcurrentPopulation,
            Case::InterruptedResponse,
            Case::FullScanAccessPath,
            Case::ExactSchemaFormat,
            Case::PerformanceBound,
            Case::PreservationFailure,
        ]);
        let cases: BTreeSet<_> = self.cases.iter().map(|case| case.case).collect();
        let names: BTreeSet<_> = self
            .cases
            .iter()
            .map(|case| case.resource_name.as_str())
            .collect();
        if self.cases.len() != 10 || cases != required || names.len() != 10 {
            return Err("qualification pack requires ten distinct case resource lifetimes");
        }
        for case in &self.cases {
            case.validate(&population.id)?;
        }
        Ok(())
    }
}

impl CaseSource {
    fn validate(&self, population_id: &str) -> Result<(), &'static str> {
        let safe_name = !self.resource_name.is_empty()
            && self.resource_name.len() <= 64
            && self
                .resource_name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !safe_name
            || [
                &self.seed,
                &self.execution,
                &self.before.inventory,
                &self.after.inventory,
                &self.before_oracle,
                &self.after_oracle,
            ]
            .iter()
            .any(|value| !source(value))
            || self.before.capability_id != population_id
            || self.after.capability_id != population_id
            || !canonical_digest(&self.expected_before_state_sha256)
            || !canonical_digest(&self.expected_after_state_sha256)
            || (self.case.is_failure()
                && (self.before.inventory != self.after.inventory
                    || self.expected_before_state_sha256 != self.expected_after_state_sha256))
            || self.case.is_failure() != self.failure_sentinel.is_some()
            || self.failure_sentinel.as_ref().is_some_and(|value| {
                value.len() < 16
                    || value.len() > 128
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
            })
            || (self.case == Case::PerformanceBound) != self.performance_max_seconds.is_some()
            || self
                .performance_max_seconds
                .is_some_and(|seconds| seconds == 0 || seconds > 600)
            || (self.case == Case::ConcurrentPopulation) != self.concurrent_source.is_some()
            || self.concurrent_source.is_some() != self.post_writer_oracle.is_some()
            || self
                .post_writer_oracle
                .as_ref()
                .is_some_and(|value| !source(value))
        {
            return Err("qualification case source, oracle, fault or bounded lifetime is invalid");
        }
        if let Some(writer) = &self.concurrent_source {
            writer.validate()?;
            if writer.post_writer_inventory.capability_id != population_id
                || !source(&writer.writer)
                || !source(&writer.post_writer_inventory.inventory)
            {
                return Err("qualification writer source or population binding differs");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
