//! One-dispatch executor orchestration, not a registered provider adapter.
//! The CLI still blocks V3. A native import transport must be separately qualified.
use std::future::Future;

use cfctl_core::workspace_d1::transition::{
    MAX_ENVELOPE_BYTES,
    execution::{Checkpoint, Event, Stage},
};
use sha2::{Digest, Sha256};

pub mod import;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Terminal {
    Committed {
        receipt_sha256: String,
        bookmark_sha256: String,
    },
    RolledBack {
        receipt_sha256: String,
        bookmark_sha256: String,
    },
    Uncertain,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    /// Last durable checkpoint. `DispatchIntent` means the effect may have happened.
    pub durable: Box<Checkpoint>,
    pub classification: &'static str,
}

/// The source caller must authenticate `PlanV2`, qualification and assurance first.
/// `persist` must durably publish the exact checkpoint before returning success.
/// `dispatch` is called at most once with all immutable execution bytes; no
/// statement splitting, retry, restore or automatic compensation is performed.
pub async fn execute_once<P, D, F>(
    prepared: &Checkpoint,
    execution: &[u8],
    mut persist: P,
    dispatch: D,
) -> Result<Checkpoint, Failure>
where
    P: FnMut(&Checkpoint) -> Result<(), ()>,
    D: FnOnce(Vec<u8>) -> F,
    F: Future<Output = Terminal>,
{
    let fail = |classification| Failure {
        durable: Box::new(prepared.clone()),
        classification,
    };
    if prepared.validate().is_err()
        || prepared.stage != Stage::Prepared
        || execution.is_empty()
        || execution.len() > MAX_ENVELOPE_BYTES
        || prepared.identity.execution_sha256
            != format!("sha256:{}", hex::encode(Sha256::digest(execution)))
    {
        return Err(fail("invalid_prepared_execution"));
    }
    persist(prepared).map_err(|()| fail("prepared_checkpoint_not_durable"))?;
    let intent = prepared
        .advance(Event::Dispatch, None, None)
        .map_err(|_| fail("invalid_dispatch_intent"))?;
    persist(&intent).map_err(|()| fail("dispatch_intent_not_durable"))?;
    // From this line onward even a crash, malformed response or sink failure
    // cannot return a Prepared state or permit another dispatch.
    let next = match dispatch(execution.to_vec()).await {
        Terminal::Committed {
            receipt_sha256,
            bookmark_sha256,
        } => intent.advance(Event::Commit, Some(&receipt_sha256), Some(&bookmark_sha256)),
        Terminal::RolledBack {
            receipt_sha256,
            bookmark_sha256,
        } => intent.advance(
            Event::Rollback,
            Some(&receipt_sha256),
            Some(&bookmark_sha256),
        ),
        Terminal::Uncertain => intent.advance(Event::Ambiguous, None, None),
    }
    .map_err(|_| Failure {
        durable: Box::new(intent.clone()),
        classification: "terminal_unqualified",
    })?;
    persist(&next).map_err(|()| Failure {
        durable: Box::new(intent),
        classification: "terminal_checkpoint_not_durable_no_replay",
    })?;
    Ok(next)
}

/// Reconciliation records an authenticated provider disposition; it never sends
/// execution bytes. The caller must join provider status and terminal assertions.
pub fn reconcile<P>(
    uncertain: &Checkpoint,
    terminal: Terminal,
    mut persist: P,
) -> Result<Checkpoint, Failure>
where
    P: FnMut(&Checkpoint) -> Result<(), ()>,
{
    let error = |classification| Failure {
        durable: Box::new(uncertain.clone()),
        classification,
    };
    // Intent recovered after a crash is conservatively uncertain.
    let base = match uncertain.stage {
        Stage::DispatchIntent | Stage::AwaitingTerminal => uncertain
            .advance(Event::Ambiguous, None, None)
            .map_err(|_| error("invalid_uncertain_checkpoint"))?,
        Stage::Uncertain => uncertain.clone(),
        _ => return Err(error("reconciliation_requires_ambiguous_dispatch")),
    };
    if base != *uncertain {
        persist(&base).map_err(|()| error("uncertain_checkpoint_not_durable"))?;
    }
    let result = match terminal {
        Terminal::Committed {
            receipt_sha256,
            bookmark_sha256,
        } => base.advance(
            Event::ReconciledCommit,
            Some(&receipt_sha256),
            Some(&bookmark_sha256),
        ),
        Terminal::RolledBack {
            receipt_sha256,
            bookmark_sha256,
        } => base.advance(
            Event::ReconciledRollback,
            Some(&receipt_sha256),
            Some(&bookmark_sha256),
        ),
        Terminal::Uncertain => return Err(error("provider_disposition_still_uncertain")),
    }
    .map_err(|_| error("reconciliation_disposition_unqualified"))?;
    persist(&result).map_err(|()| Failure {
        durable: Box::new(base),
        classification: "reconciliation_checkpoint_not_durable",
    })?;
    Ok(result)
}

#[cfg(test)]
mod tests;
