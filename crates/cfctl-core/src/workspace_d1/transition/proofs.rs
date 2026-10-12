//! Closed, source-bound V4 receipts. Authentication is the storage consumer's job.
use serde::{Deserialize, Serialize};

use super::{Compiled, EffectRef, ProofRef, PublicationRef, assurance, canonical_digest};
use crate::{WorkspaceD1MigrationContractV1, hash_value};

pub const QUALIFICATION_KIND: &str = "workspace_d1_transition_qualification_v2";
pub const QUALIFICATION_SCHEMA_VERSION: u8 = 2;
pub const EXECUTION_KIND: &str = "workspace_d1_transition_execution_v1";
pub const POLICY_KIND: &str = "workspace_d1_assurance_decision_v1";
pub const TRANSPORT: &str = "native_d1_file_import_v1";
pub const TRANSPORT_RECEIPT_KIND: &str = "workspace_d1_transition_import_terminal_v1";
pub const POPULATION_KIND: &str = "workspace_d1_transition_population_v1";
pub const POPULATION_CAPABILITY: &str = "workspace-d1-transition-population-observe-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub repository_head: String,
    pub operation_pack_sha256: String,
    pub declaration_sha256: String,
    pub source_envelope_sha256: String,
    pub execution_sha256: String,
    pub account_id: String,
    pub database_id: String,
    pub target_sequence: u64,
    pub migration_sha256: String,
}

impl Identity {
    pub fn from_contract(contract: &WorkspaceD1MigrationContractV1) -> crate::Result<Self> {
        let compiled = contract.transition.as_ref().ok_or_else(|| {
            crate::CoreError::InvalidOperationalProofBinding("V3 transition is missing".into())
        })?;
        Self::new(
            &contract.repository_head,
            &contract.operation_pack_sha256,
            compiled,
        )
    }

    pub fn new(head: &str, pack: &str, compiled: &Compiled) -> crate::Result<Self> {
        Ok(Self {
            repository_head: head.into(),
            operation_pack_sha256: pack.into(),
            declaration_sha256: hash_value(&serde_json::to_value(&compiled.declaration)?)?,
            source_envelope_sha256: compiled.envelope_sha256.clone(),
            execution_sha256: compiled.execution.execution_sha256.clone(),
            account_id: compiled.declaration.account_id.clone(),
            database_id: compiled.declaration.database_id.clone(),
            target_sequence: compiled.declaration.target.sequence,
            migration_sha256: compiled.declaration.target.source.sha256.clone(),
        })
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if !super::lower_hex(&self.repository_head, 40)
            || !super::lower_hex(&self.account_id, 32)
            || uuid::Uuid::parse_str(&self.database_id).is_err()
            || self.target_sequence == 0
            || [
                &self.operation_pack_sha256,
                &self.declaration_sha256,
                &self.source_envelope_sha256,
                &self.execution_sha256,
                &self.migration_sha256,
            ]
            .iter()
            .any(|hash| !canonical_digest(hash))
        {
            return Err("transition identity is not canonical");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Case {
    Success,
    MigrationFailure,
    LedgerFailure,
    CleanupFailure,
    ConcurrentPopulation,
    InterruptedResponse,
    FullScanAccessPath,
    ExactSchemaFormat,
    PerformanceBound,
    PreservationFailure,
}

impl Case {
    #[must_use]
    pub const fn is_failure(self) -> bool {
        matches!(
            self,
            Self::MigrationFailure
                | Self::LedgerFailure
                | Self::CleanupFailure
                | Self::PreservationFailure
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PopulationPhase {
    Before,
    After,
}

pub const REQUIRED_CASES: [Case; 10] = [
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
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseRef {
    pub case: Case,
    pub effect: EffectRef,
    pub before: ProofRef,
    pub after: ProofRef,
    pub synthetic_database_id: String,
    pub fixture_sha256: String,
    pub fixture_bytes: usize,
    pub failure_sentinel: Option<String>,
    pub performance_max_seconds: Option<u64>,
    pub concurrency: Option<ConcurrentCase>,
    pub before_population_inventory: super::Observation,
    pub after_population_inventory: super::Observation,
    pub expected_after_state_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConcurrentSource {
    pub writer: super::Source,
    pub writer_bytes: usize,
    pub post_writer_inventory: super::Observation,
    pub expected_post_writer_state_sha256: String,
}
impl ConcurrentSource {
    pub fn validate(&self) -> Result<(), &'static str> {
        if !canonical_digest(&self.writer.sha256)
            || !super::lower_hex(&self.writer.git_blob_oid, 40)
            || self.writer_bytes == 0
            || self.writer_bytes > super::MAX_ENVELOPE_BYTES
            || !canonical_digest(&self.post_writer_inventory.inventory.sha256)
            || !super::lower_hex(&self.post_writer_inventory.inventory.git_blob_oid, 40)
            || self.post_writer_inventory.capability_id.is_empty()
            || !canonical_digest(&self.expected_post_writer_state_sha256)
        {
            return Err(
                "concurrent writer source and complete post-writer observation must be bound",
            );
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConcurrentCase {
    pub source: ConcurrentSource,
    pub writer: EffectRef,
    pub post_writer_observation: ProofRef,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriterTarget {
    pub parent: QualificationTarget,
}

impl CaseRef {
    #[must_use]
    pub const fn inventory(&self, phase: PopulationPhase) -> &super::Observation {
        match phase {
            PopulationPhase::Before => &self.before_population_inventory,
            PopulationPhase::After => &self.after_population_inventory,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Qualification {
    pub schema_version: u8,
    pub kind: String,
    pub identity: Identity,
    pub transport: String,
    pub max_execution_bytes: usize,
    pub cases: Vec<CaseRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationTarget {
    pub identity: Identity,
    pub case: Case,
    pub synthetic_database_id: String,
    pub fixture_sha256: String,
    pub fixture_bytes: usize,
    pub failure_sentinel: Option<String>,
    pub performance_max_seconds: Option<u64>,
    pub concurrent_source: Option<ConcurrentSource>,
    pub before_population_inventory: super::Observation,
    pub after_population_inventory: super::Observation,
    pub expected_after_state_sha256: String,
}

impl QualificationTarget {
    #[must_use]
    pub fn from_case(identity: &Identity, case: &CaseRef) -> Self {
        Self {
            identity: identity.clone(),
            case: case.case,
            synthetic_database_id: case.synthetic_database_id.clone(),
            fixture_sha256: case.fixture_sha256.clone(),
            fixture_bytes: case.fixture_bytes,
            failure_sentinel: case.failure_sentinel.clone(),
            performance_max_seconds: case.performance_max_seconds,
            concurrent_source: case.concurrency.as_ref().map(|proof| proof.source.clone()),
            before_population_inventory: case.before_population_inventory.clone(),
            after_population_inventory: case.after_population_inventory.clone(),
            expected_after_state_sha256: case.expected_after_state_sha256.clone(),
        }
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        self.identity.validate()?;
        if self.case.is_failure() != self.failure_sentinel.is_some()
            || self.failure_sentinel.as_ref().is_some_and(|sentinel| {
                sentinel.len() < 16
                    || sentinel.len() > 128
                    || !sentinel.bytes().all(|byte| {
                        byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'
                    })
            })
            || (self.case == Case::PerformanceBound) != self.performance_max_seconds.is_some()
            || self
                .performance_max_seconds
                .is_some_and(|seconds| seconds == 0 || seconds > 600)
            || (self.case == Case::ConcurrentPopulation) != self.concurrent_source.is_some()
            || self
                .concurrent_source
                .as_ref()
                .is_some_and(|source| source.validate().is_err())
        {
            return Err(
                "case-specific source requirements are missing or contradict the selected case",
            );
        }
        if self.synthetic_database_id == self.identity.database_id
            || uuid::Uuid::parse_str(&self.synthetic_database_id).is_err()
            || self.fixture_bytes == 0
            || self.fixture_bytes > super::MAX_ENVELOPE_BYTES
            || !canonical_digest(&self.fixture_sha256)
            || !canonical_digest(&self.expected_after_state_sha256)
            || [
                &self.before_population_inventory,
                &self.after_population_inventory,
            ]
            .iter()
            .any(|observation| {
                !canonical_digest(&observation.inventory.sha256)
                    || !super::lower_hex(&observation.inventory.git_blob_oid, 40)
                    || observation.capability_id.is_empty()
            })
            || (self.case.is_failure()
                && self.before_population_inventory != self.after_population_inventory)
        {
            return Err("synthetic qualification target is malformed or selects production");
        }
        Ok(())
    }
}

impl Qualification {
    pub fn validate(&self, expected: &Identity, bytes: usize) -> Result<(), &'static str> {
        use std::collections::BTreeSet;
        let cases: BTreeSet<_> = self.cases.iter().map(|case| case.case).collect();
        if self.schema_version != QUALIFICATION_SCHEMA_VERSION
            || self.kind != QUALIFICATION_KIND
            || &self.identity != expected
            || self.transport != TRANSPORT
            || self.max_execution_bytes < bytes
            || self.max_execution_bytes > super::MAX_ENVELOPE_BYTES
            || self.cases.iter().map(|case| case.fixture_bytes).max()
                != Some(self.max_execution_bytes)
            || cases != BTreeSet::from(REQUIRED_CASES)
            || cases.len() != self.cases.len()
            || self.cases.iter().any(|case| {
                QualificationTarget::from_case(expected, case)
                    .validate()
                    .is_err()
                    || case.synthetic_database_id == expected.database_id
                    || uuid::Uuid::parse_str(&case.synthetic_database_id).is_err()
                    || case.fixture_bytes == 0
                    || case.fixture_bytes > super::MAX_ENVELOPE_BYTES
                    || (case.case == Case::PerformanceBound && case.fixture_bytes < bytes)
                    || !canonical_digest(&case.fixture_sha256)
                    || !canonical_digest(&case.expected_after_state_sha256)
                    || case.before == case.after
            })
        {
            return Err(
                "qualification identity, bounded transport or exact synthetic matrix differs",
            );
        }
        expected.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Completed {
    pub sequence: u64,
    pub effect: EffectRef,
    pub atomic_execution_evidence_hash: String,
    pub preservation: ProofRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRecord {
    pub schema_version: u8,
    pub kind: String,
    pub checkpoints: Vec<super::execution::Checkpoint>,
    /// Actual authenticated storage body hashes, distinct from canonical lineage hashes.
    pub checkpoint_evidence_hashes: Vec<String>,
}

pub const VERIFIED_EXECUTION_KIND: &str = "workspace_d1_transition_verified_execution_v1";
pub const VERIFIED_TRANSPORT_KIND: &str = "workspace_d1_transition_verified_transport_v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedExecutionRecord {
    pub schema_version: u8,
    pub kind: String,
    pub apply_evidence_hash: String,
    pub execution: ExecutionRecord,
}
impl VerifiedExecutionRecord {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != 1
            || self.kind != VERIFIED_EXECUTION_KIND
            || !canonical_digest(&self.apply_evidence_hash)
        {
            return Err("verified execution lacks its distinct kind and exact apply identity");
        }
        self.execution.terminal().map(|_| ())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedTransportReceipt {
    pub schema_version: u8,
    pub kind: String,
    pub apply_evidence_hash: String,
    pub receipt: TransportReceipt,
}
impl VerifiedTransportReceipt {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != 1
            || self.kind != VERIFIED_TRANSPORT_KIND
            || !canonical_digest(&self.apply_evidence_hash)
        {
            return Err("verified transport lacks its distinct kind and exact apply identity");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PollContinuation {
    pub operation_id: String,
    pub plan_hash: String,
    pub parent_checkpoint_sha256: String,
    pub bookmark_sha256: String,
}
impl PollContinuation {
    pub fn validate(&self) -> Result<(), &'static str> {
        if uuid::Uuid::parse_str(&self.operation_id).is_err()
            || [
                &self.plan_hash,
                &self.parent_checkpoint_sha256,
                &self.bookmark_sha256,
            ]
            .iter()
            .any(|hash| !canonical_digest(hash))
        {
            return Err("poll continuation identity is malformed");
        }
        Ok(())
    }
}

/// Redacted authenticated terminal artifact from the still-unregistered native adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportReceipt {
    pub schema_version: u8,
    pub kind: String,
    pub operation_id: String,
    pub database_id: String,
    pub transport: String,
    pub execution_sha256: String,
    pub stage: super::execution::Stage,
    pub bookmark_sha256: String,
    pub provider_error_evidence_hash: Option<String>,
    pub continuation: Option<PollContinuation>,
}

impl TransportReceipt {
    pub fn validate(
        &self,
        terminal: &super::execution::Checkpoint,
        database: &str,
    ) -> Result<(), &'static str> {
        if self.schema_version != 1
            || self.kind != TRANSPORT_RECEIPT_KIND
            || self.operation_id != terminal.operation_id
            || self.database_id != database
            || self.transport != TRANSPORT
            || self.execution_sha256 != terminal.identity.execution_sha256
            || self.continuation.as_ref().is_some_and(|continuation| {
                continuation.validate().is_err() || continuation.operation_id == self.operation_id
            })
            || self.stage != terminal.stage
            || match self.stage {
                super::execution::Stage::Committed => self.provider_error_evidence_hash.is_some(),
                super::execution::Stage::RolledBack => self
                    .provider_error_evidence_hash
                    .as_deref()
                    .is_none_or(|hash| !canonical_digest(hash)),
                _ => true,
            }
            || terminal.bookmark_sha256.as_deref() != Some(self.bookmark_sha256.as_str())
        {
            return Err("native import terminal artifact differs from atomic checkpoint");
        }
        terminal.validate()
    }
}

impl ExecutionRecord {
    pub fn terminal(&self) -> Result<&super::execution::Checkpoint, &'static str> {
        use super::execution::{Event, Stage};
        if self.schema_version != 1
            || self.kind != EXECUTION_KIND
            || self.checkpoints.len() < 3
            || self.checkpoints.len() > 8
            || self.checkpoints[0].stage != Stage::Prepared
            || self.checkpoint_evidence_hashes.len() != self.checkpoints.len()
            || self
                .checkpoint_evidence_hashes
                .iter()
                .any(|hash| !canonical_digest(hash))
            || self
                .checkpoint_evidence_hashes
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.checkpoints.len()
        {
            return Err("atomic execution record has invalid kind, bound or initial stage");
        }
        for checkpoint in &self.checkpoints {
            checkpoint.validate()?;
        }
        for pair in self.checkpoints.windows(2) {
            let next = &pair[1];
            let event = match (pair[0].stage, next.stage) {
                (Stage::Prepared, Stage::DispatchIntent) => Event::Dispatch,
                (Stage::DispatchIntent, Stage::AwaitingTerminal) => Event::Accepted,
                (Stage::DispatchIntent | Stage::AwaitingTerminal, Stage::Committed) => {
                    Event::Commit
                }
                (Stage::DispatchIntent | Stage::AwaitingTerminal, Stage::RolledBack) => {
                    Event::Rollback
                }
                (Stage::DispatchIntent | Stage::AwaitingTerminal, Stage::Uncertain) => {
                    Event::Ambiguous
                }
                (Stage::Uncertain, Stage::Committed) => Event::ReconciledCommit,
                (Stage::Uncertain, Stage::RolledBack) => Event::ReconciledRollback,
                _ => {
                    return Err(
                        "atomic checkpoint chain contains a replay or impossible transition",
                    );
                }
            };
            let expected = pair[0]
                .advance(
                    event,
                    next.provider_receipt_sha256.as_deref(),
                    next.bookmark_sha256.as_deref(),
                )
                .map_err(|_| "atomic checkpoint chain is invalid")?;
            if &expected != next {
                return Err("atomic checkpoint identity or predecessor was substituted");
            }
        }
        let terminal = self
            .checkpoints
            .last()
            .ok_or("atomic execution has no terminal")?;
        if !matches!(terminal.stage, Stage::Committed | Stage::RolledBack) {
            return Err("atomic execution remains uncertain or incomplete");
        }
        Ok(terminal)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDecision {
    pub schema_version: u8,
    pub kind: String,
    pub identity: Identity,
    pub policy_sha256: String,
    pub assurance_sha256: String,
    pub release_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Population {
    pub schema_version: u8,
    pub phase: PopulationPhase,
    pub kind: String,
    pub attempted_operation_id: String,
    pub database_id: String,
    pub fixture_sha256: String,
    pub source_inventory: super::Observation,
    pub source: ProofRef,
    pub semantic_state_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBindingV4 {
    pub schema_version: u8,
    pub observed_baseline: ProofRef,
    pub baseline_assertions: ProofRef,
    pub completed: Vec<Completed>,
    pub recovery: ProofRef,
    /// Authenticated native aggregate; each child is independently re-resolved.
    pub qualification_evidence_hash: String,
    pub assurance: assurance::Binding,
    pub publication: Option<PublicationRef>,
}
