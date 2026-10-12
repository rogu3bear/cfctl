//! Authenticate each completed atomic effect before admitting schedule lineage.
use super::{
    CallInput, CompletedRef, EvidenceClass, ExecutionRecord, Identity, Result, RuntimeBindingV4,
    Scope, Stage, StateStore, Utc, Value, effect, hash_value, invalid, qualification,
    transport_receipt,
};
use cfctl_core::workspace_d1::transition::proofs::Completed;

pub(super) fn validate(
    store: &StateStore,
    binding: &RuntimeBindingV4,
    scope: &Scope<'_>,
    now: chrono::DateTime<Utc>,
) -> Result<Vec<CompletedRef>> {
    let mut predecessor = binding.observed_baseline.evidence_hash.clone();
    let mut completed = Vec::new();
    for item in &binding.completed {
        let plan = effect(store, &item.effect, scope)?;
        let prior = plan
            .plan
            .capability
            .workspace_d1_migration
            .as_ref()
            .ok_or_else(|| invalid("completed V4 plan is not a transition"))?;
        let record = authenticate(
            store,
            item,
            &plan,
            &binding.observed_baseline.evidence_hash,
            &predecessor,
        )?;
        let terminal = record.terminal().map_err(invalid)?;
        let prior_input: CallInput = serde_json::from_value(plan.plan.input.clone())
            .map_err(|_| invalid("prior V4 input malformed"))?;
        let prior_binding: RuntimeBindingV4 = serde_json::from_value(
            prior_input
                .body
                .ok_or_else(|| invalid("prior V4 binding missing"))?,
        )
        .map_err(|_| invalid("prior V4 binding malformed"))?;
        if prior_binding.schema_version != 4
            || terminal.qualification_evidence_hash != prior_binding.qualification_evidence_hash
        {
            return Err(invalid(
                "prior atomic execution substituted its qualification",
            ));
        }
        qualification(
            store,
            &prior_binding.qualification_evidence_hash,
            &terminal.identity,
            prior
                .transition
                .as_ref()
                .ok_or_else(|| invalid("prior transition missing"))?
                .execution
                .execution_length,
            scope,
            now,
        )?;
        completed.push(CompletedRef {
            sequence: item.sequence,
            effect: item.effect.clone(),
            baseline_evidence_hash: binding.observed_baseline.evidence_hash.clone(),
            predecessor_evidence_hash: std::mem::replace(
                &mut predecessor,
                item.preservation.evidence_hash.clone(),
            ),
            envelope_sha256: terminal.identity.source_envelope_sha256.clone(),
            preservation: item.preservation.clone(),
        });
    }
    Ok(completed)
}

fn authenticate(
    store: &StateStore,
    item: &Completed,
    plan: &cfctl_core::PlanV2,
    baseline: &str,
    predecessor: &str,
) -> Result<ExecutionRecord> {
    let prior = plan
        .plan
        .capability
        .workspace_d1_migration
        .as_ref()
        .ok_or_else(|| invalid("completed V4 plan is not a transition"))?;
    let evidence = store.load_evidence(&item.atomic_execution_evidence_hash)?;
    if evidence.class != EvidenceClass::Apply {
        return Err(invalid(
            "completed V4 execution lacks native apply evidence",
        ));
    }
    let record: ExecutionRecord =
        serde_json::from_value(store.read_evidence_value(&item.atomic_execution_evidence_hash)?)
            .map_err(|_| invalid("completed V4 execution record is malformed"))?;
    let terminal = record.terminal().map_err(invalid)?;
    if terminal.identity != Identity::from_contract(prior)?
        || terminal.stage != Stage::Committed
        || terminal.operation_id != item.effect.operation_id
        || terminal.plan_hash != plan.plan.content_hash
        || terminal.baseline_evidence_hash != baseline
        || terminal.predecessor_evidence_hash != predecessor
        || terminal.assurance_sha256
            != hash_value(&serde_json::to_value(
                prior
                    .transition
                    .as_ref()
                    .and_then(|compiled| compiled.declaration.assurance.as_ref())
                    .ok_or_else(|| invalid("prior transition assurance missing"))?,
            )?)?
        || plan
            .plan
            .transaction_artifact(cfctl_core::TransactionStageV1::BoundaryResponsePersisted)
            .and_then(|value| value.get("evidence_hash"))
            .and_then(Value::as_str)
            != Some(item.atomic_execution_evidence_hash.as_str())
    {
        return Err(invalid(
            "completed V4 atomic effect substituted identity or lineage",
        ));
    }
    let verified = store.load_evidence(&item.effect.evidence_hash)?;
    let verified_record = super::case_verifier::verified_execution(
        store,
        plan,
        &item.effect.evidence_hash,
        verified.generated_at,
    )?;
    if verified_record != record {
        return Err(invalid(
            "completed verification substituted its atomic apply record",
        ));
    }
    super::case_verifier::checkpoint_times(store, &record, verified.generated_at)?;
    if evidence.generated_at > verified.generated_at {
        return Err(invalid("atomic execution artifact follows verification"));
    }
    transport_receipt(
        store,
        terminal,
        &terminal.identity.database_id,
        evidence.generated_at,
    )?;
    Ok(record)
}
