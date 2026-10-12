//! Durable one-dispatch state machine. An ambiguous send can only be reconciled.
use serde::{Deserialize, Serialize};

use super::{canonical_digest, proofs::Identity};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Prepared,
    DispatchIntent,
    AwaitingTerminal,
    Committed,
    RolledBack,
    Uncertain,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub schema_version: u8,
    pub operation_id: String,
    pub identity: Identity,
    pub plan_hash: String,
    pub qualification_evidence_hash: String,
    pub assurance_sha256: String,
    pub baseline_evidence_hash: String,
    pub predecessor_evidence_hash: String,
    pub stage: Stage,
    pub previous_checkpoint_sha256: Option<String>,
    pub provider_receipt_sha256: Option<String>,
    pub bookmark_sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Dispatch,
    Accepted,
    Commit,
    Rollback,
    Ambiguous,
    ReconciledCommit,
    ReconciledRollback,
}

impl Checkpoint {
    pub fn validate(&self) -> Result<(), &'static str> {
        self.identity.validate()?;
        if self.schema_version != 1
            || uuid::Uuid::parse_str(&self.operation_id).is_err()
            || [
                &self.plan_hash,
                &self.qualification_evidence_hash,
                &self.assurance_sha256,
                &self.baseline_evidence_hash,
                &self.predecessor_evidence_hash,
            ]
            .iter()
            .any(|hash| !canonical_digest(hash))
            || self
                .previous_checkpoint_sha256
                .as_deref()
                .is_some_and(|hash| !canonical_digest(hash))
            || self
                .provider_receipt_sha256
                .as_deref()
                .is_some_and(|hash| !canonical_digest(hash))
            || self
                .bookmark_sha256
                .as_deref()
                .is_some_and(|hash| !canonical_digest(hash))
            || (self.stage == Stage::Prepared && self.previous_checkpoint_sha256.is_some())
            || (self.stage != Stage::Prepared && self.previous_checkpoint_sha256.is_none())
            || (matches!(
                self.stage,
                Stage::Prepared | Stage::DispatchIntent | Stage::Uncertain
            ) && (self.provider_receipt_sha256.is_some() || self.bookmark_sha256.is_some()))
            || (matches!(self.stage, Stage::Committed | Stage::RolledBack)
                && (self.provider_receipt_sha256.is_none() || self.bookmark_sha256.is_none()))
        {
            return Err("atomic checkpoint is malformed or lacks terminal evidence");
        }
        Ok(())
    }

    pub fn advance(
        &self,
        event: Event,
        receipt: Option<&str>,
        bookmark: Option<&str>,
    ) -> crate::Result<Self> {
        self.validate().map_err(invalid)?;
        let stage = match (self.stage, event) {
            (Stage::Prepared, Event::Dispatch) => Stage::DispatchIntent,
            (Stage::DispatchIntent, Event::Accepted) => Stage::AwaitingTerminal,
            (Stage::DispatchIntent | Stage::AwaitingTerminal, Event::Commit)
            | (Stage::Uncertain, Event::ReconciledCommit) => Stage::Committed,
            (Stage::DispatchIntent | Stage::AwaitingTerminal, Event::Rollback)
            | (Stage::Uncertain, Event::ReconciledRollback) => Stage::RolledBack,
            (Stage::DispatchIntent | Stage::AwaitingTerminal, Event::Ambiguous) => Stage::Uncertain,
            _ => {
                return Err(invalid(
                    "atomic execution cannot replay or advance this stage",
                ));
            }
        };
        let mut next = self.clone();
        next.stage = stage;
        next.previous_checkpoint_sha256 = Some(crate::hash_value(&serde_json::to_value(self)?)?);
        next.provider_receipt_sha256 = receipt.map(str::to_owned);
        next.bookmark_sha256 = bookmark.map(str::to_owned);
        next.validate().map_err(invalid)?;
        Ok(next)
    }
}

fn invalid(message: &str) -> crate::CoreError {
    crate::CoreError::InvalidOperationalProofBinding(message.into())
}
