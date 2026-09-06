//! Source and receipt identities for the disabled-by-default V3 transition lane.
//! Historical membership is never a claim about the observed provider database.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

pub const MAX_HISTORY: usize = 256;
pub const MAX_ENVELOPE_BYTES: usize = 1024 * 1024;
pub const COMPILER_ID: &str = "workspace-d1-envelope-v3.1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    PreDeploy,
    PostDeploy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub path: String,
    pub sha256: String,
    pub git_blob_oid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub sequence: u64,
    pub file: String,
    pub source: Source,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    pub sequence: u64,
    pub phase: Phase,
    pub required_completed_transition_sequences: Vec<u64>,
    pub deferred_sequences: Vec<u64>,
}

/// The migration itself is a separate immutable source between capture and preservation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assertions {
    pub preconditions: Source,
    pub capture: Source,
    pub preservation: Source,
    pub cleanup: Source,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Declaration {
    pub id: String,
    pub title: String,
    pub description: String,
    pub manifest: Source,
    pub historical_ledger: Source,
    pub config_template: String,
    pub account_id: String,
    pub profile_id: String,
    pub database_id: String,
    pub database_binding: String,
    pub migrations_dir: String,
    pub target: Target,
    pub transition_schedule: Vec<Step>,
    pub assertions: Assertions,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Segment {
    pub source: Source,
    pub offset: usize,
    pub length: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Compiled {
    pub declaration: Declaration,
    pub compiler_id: String,
    pub envelope_sha256: String,
    pub envelope_length: usize,
    pub segments: Vec<Segment>,
    pub historical_sequences: Vec<u64>,
    pub scheduled_targets: Vec<Target>,
}

impl Compiled {
    pub fn step(&self) -> Result<&Step, &'static str> {
        self.declaration
            .transition_schedule
            .iter()
            .find(|step| step.sequence == self.declaration.target.sequence)
            .ok_or("target is absent from transition schedule")
    }

    /// A completed set is an exact schedule prefix, not an arbitrary subset.
    pub fn validate_completed(&self, completed: &[u64]) -> Result<(), &'static str> {
        let position = self
            .declaration
            .transition_schedule
            .iter()
            .position(|step| step.sequence == self.declaration.target.sequence)
            .ok_or("target is absent from transition schedule")?;
        let prefix: Vec<_> = self.declaration.transition_schedule[..position]
            .iter()
            .map(|step| step.sequence)
            .collect();
        if prefix != completed {
            return Err("completed transitions are not the exact schedule prefix");
        }
        Ok(())
    }
}

#[must_use]
pub fn canonical_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|v| lower_hex(v, 64))
}

#[must_use]
pub fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn validate_schedule(schedule: &[Step], pending: &[u64]) -> Result<(), &'static str> {
    if pending.is_empty() || pending.len() > MAX_HISTORY || schedule.len() != pending.len() {
        return Err(
            "transition schedule has an invalid bound or does not cover pending source identities",
        );
    }
    let pending_set: BTreeSet<_> = pending.iter().copied().collect();
    let scheduled: BTreeSet<_> = schedule.iter().map(|s| s.sequence).collect();
    if pending_set.len() != pending.len()
        || scheduled != pending_set
        || scheduled.len() != schedule.len()
    {
        return Err("transition schedule duplicates or omits pending source identities");
    }
    let mut before = BTreeSet::new();
    let mut post_started = false;
    for step in schedule {
        if post_started && step.phase == Phase::PreDeploy {
            return Err("pre-deploy transition follows post-deploy phase");
        }
        post_started |= step.phase == Phase::PostDeploy;
        let required: BTreeSet<_> = step
            .required_completed_transition_sequences
            .iter()
            .copied()
            .collect();
        let deferred: BTreeSet<_> = step.deferred_sequences.iter().copied().collect();
        let gaps: BTreeSet<_> = pending_set
            .iter()
            .copied()
            .filter(|s| *s < step.sequence && !before.contains(s))
            .collect();
        if required.len() != step.required_completed_transition_sequences.len()
            || !required.is_subset(&before)
            || deferred.len() != step.deferred_sequences.len()
            || deferred != gaps
        {
            return Err("prerequisites or exact deferred gaps do not match the schedule prefix");
        }
        before.insert(step.sequence);
    }
    Ok(())
}

/// References are resolved through authenticated native state; they contain no verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofRef {
    pub proof_hash: String,
    pub evidence_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectRef {
    pub operation_id: String,
    pub evidence_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompletedRef {
    pub sequence: u64,
    pub baseline_evidence_hash: String,
    pub predecessor_evidence_hash: String,
    pub envelope_sha256: String,
    pub effect: EffectRef,
    pub preservation: ProofRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationRef {
    pub effect: EffectRef,
    pub verification: ProofRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBinding {
    pub schema_version: u8,
    pub observed_baseline: ProofRef,
    pub baseline_assertions: ProofRef,
    pub completed: Vec<CompletedRef>,
    pub recovery: ProofRef,
    pub provider_qualification: EffectRef,
    pub publication: Option<PublicationRef>,
}
