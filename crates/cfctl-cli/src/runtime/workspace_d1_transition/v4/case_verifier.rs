//! Case-specific native joins. A case label never supplies its missing evidence.
use super::{Result, Scope, StateStore, invalid, producers, read};
use cfctl_core::{
    EvidenceClass, PlanV2,
    workspace_d1::transition::{
        execution::Stage,
        proofs::{Case, CaseRef, ExecutionRecord, Identity, TransportReceipt},
    },
};
use chrono::{DateTime, Utc};
use serde_json::Value;
pub(super) mod actors;
mod audit;
mod fault;

pub(super) struct Join<'a, 's> {
    pub store: &'a StateStore,
    pub plan: &'a PlanV2,
    pub case: &'a CaseRef,
    pub identity: &'a Identity,
    pub record: &'a ExecutionRecord,
    pub scope: &'a Scope<'s>,
    pub not_after: DateTime<Utc>,
}
#[derive(Clone, Copy)]
pub(super) struct Times {
    pub dispatch: DateTime<Utc>,
    pub terminal: DateTime<Utc>,
}

pub(super) fn verify(join: &Join<'_, '_>) -> Result<Times> {
    join.plan.validate()?;
    apply_record(join.store, join.plan, join.record, join.not_after)?;
    let times = checkpoint_times(join.store, join.record, join.not_after)?;
    let terminal = join.record.terminal().map_err(invalid)?;
    let reference = terminal
        .provider_receipt_sha256
        .as_deref()
        .ok_or_else(|| invalid("native case terminal receipt missing"))?;
    let receipt: TransportReceipt =
        serde_json::from_value(join.store.read_evidence_value(reference)?)
            .map_err(|_| invalid("native case transport receipt malformed"))?;
    receipt
        .validate(terminal, &join.case.synthetic_database_id)
        .map_err(invalid)?;
    match join.case.case {
        Case::Success => {}
        Case::MigrationFailure
        | Case::LedgerFailure
        | Case::CleanupFailure
        | Case::PreservationFailure => {
            fault::verify(join, &receipt)?;
        }
        Case::ConcurrentPopulation => actors::writer(join, times)?,
        Case::InterruptedResponse => actors::poll(join, &receipt)?,
        Case::FullScanAccessPath => audit::population(join, true)?,
        Case::ExactSchemaFormat => audit::population(join, false)?,
        Case::PerformanceBound => {
            let maximum = join
                .case
                .performance_max_seconds
                .ok_or_else(|| invalid("performance bound not approved"))?;
            if times.terminal - times.dispatch
                > chrono::Duration::seconds(
                    i64::try_from(maximum).map_err(|_| invalid("performance bound invalid"))?,
                )
            {
                return Err(invalid(
                    "native execution exceeded its approved performance window",
                ));
            }
        }
    }
    let baseline = read(join.store, &join.case.before, join.scope, join.not_after)?;
    if baseline.observed_at >= times.dispatch {
        return Err(invalid("native case baseline follows dispatch intent"));
    }
    Ok(times)
}

pub(super) fn apply_record(
    store: &StateStore,
    plan: &PlanV2,
    record: &ExecutionRecord,
    not_after: DateTime<Utc>,
) -> Result<()> {
    let hash = plan
        .plan
        .transaction_artifact(cfctl_core::TransactionStageV1::BoundaryResponsePersisted)
        .and_then(|artifact| artifact.get("evidence_hash"))
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("native case lacks its plan-bound apply record"))?;
    let evidence = store.load_evidence(hash)?;
    let actual: ExecutionRecord = serde_json::from_value(store.read_evidence_value(hash)?)
        .map_err(|_| invalid("native apply record malformed"))?;
    if evidence.class != EvidenceClass::Apply
        || evidence.generated_at > not_after
        || &actual != record
    {
        return Err(invalid(
            "case verification substituted its authenticated apply record",
        ));
    }
    Ok(())
}

pub(super) fn checkpoint_times(
    store: &StateStore,
    record: &ExecutionRecord,
    not_after: DateTime<Utc>,
) -> Result<Times> {
    record.terminal().map_err(invalid)?;
    let mut previous = None;
    let mut dispatch = None;
    for (checkpoint, hash) in record
        .checkpoints
        .iter()
        .zip(&record.checkpoint_evidence_hashes)
    {
        let value = serde_json::to_value(checkpoint)?;
        let evidence = store.load_evidence(hash)?;
        if evidence.class != EvidenceClass::Apply
            || evidence.generated_at > not_after
            || previous.is_some_and(|time| time > evidence.generated_at)
            || store.read_evidence_value(hash)? != value
        {
            return Err(invalid(
                "checkpoint time is not derived from its exact authenticated apply artifact",
            ));
        }
        previous = Some(evidence.generated_at);
        if checkpoint.stage == Stage::DispatchIntent {
            dispatch = Some(evidence.generated_at);
        }
    }
    Ok(Times {
        dispatch: dispatch.ok_or_else(|| invalid("dispatch checkpoint time missing"))?,
        terminal: previous.ok_or_else(|| invalid("terminal checkpoint time missing"))?,
    })
}

pub(super) fn plan_scope(plan: &PlanV2, scope: &Scope<'_>) -> Result<()> {
    plan.validate()?;
    if plan.plan.account_id != scope.account
        || plan.plan.profile_id != scope.profile
        || plan.plan.catalog_hash != scope.catalog
        || plan.pins.catalog_hash != scope.catalog
        || plan.pins.build_identity_hash != scope.build
        || plan.pins.credential_generation_id != scope.generation
    {
        return Err(invalid("native case actor scope or build differs"));
    }
    Ok(())
}

pub(super) fn verified_execution(
    store: &StateStore,
    plan: &PlanV2,
    hash: &str,
    not_after: DateTime<Utc>,
) -> Result<ExecutionRecord> {
    let evidence = store.load_evidence(hash)?;
    let verified: cfctl_core::workspace_d1::transition::proofs::VerifiedExecutionRecord =
        serde_json::from_value(store.read_evidence_value(hash)?)
            .map_err(|_| invalid("native execution verification wrapper malformed"))?;
    verified.validate().map_err(invalid)?;
    let apply = plan
        .plan
        .transaction_artifact(cfctl_core::TransactionStageV1::BoundaryResponsePersisted)
        .and_then(|value| value.get("evidence_hash"))
        .and_then(Value::as_str);
    if evidence.class != EvidenceClass::PostChangeVerification
        || evidence.generated_at > not_after
        || apply != Some(verified.apply_evidence_hash.as_str())
    {
        return Err(invalid(
            "verified execution substituted its exact apply identity",
        ));
    }
    apply_record(store, plan, &verified.execution, not_after)?;
    Ok(verified.execution)
}

#[cfg(test)]
mod tests;
