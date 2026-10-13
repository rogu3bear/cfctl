//! Join an atomic native effect with exact application assertions and diagnostics.
use super::{
    EvidenceClass, Identity, Result, Scope, Stage, StateStore, Utc, Value, case_verifier,
    diagnostic, invalid, observations, transport_receipt,
};
use cfctl_core::{
    EvidenceV1, PlanStatus, PlanV2, TransactionStageV1,
    workspace_d1::transition::{
        ProofRef,
        application::{APPLICATION_KIND, ApplicationVerification},
        proofs::{
            ExecutionRecord, RuntimeBindingV4, VERIFIED_EXECUTION_KIND, VerifiedExecutionRecord,
        },
    },
};

/// Authentication and predicate evaluation are re-run by producer and consumer.
pub(super) fn validate(
    store: &StateStore,
    plan: &PlanV2,
    record: &ApplicationVerification,
    scope: &Scope<'_>,
    not_after: chrono::DateTime<Utc>,
) -> Result<ExecutionRecord> {
    validate_cached(
        store,
        plan,
        record,
        scope,
        not_after,
        &mut super::AdmissionCache::default(),
    )
}

#[expect(
    clippy::too_many_lines,
    reason = "one authenticated application join binds approval, atomic execution, original admission and both terminal read predicates"
)]
pub(super) fn validate_cached(
    store: &StateStore,
    plan: &PlanV2,
    record: &ApplicationVerification,
    scope: &Scope<'_>,
    not_after: chrono::DateTime<Utc>,
    cache: &mut super::AdmissionCache,
) -> Result<ExecutionRecord> {
    plan.validate()?;
    record.validate().map_err(invalid)?;
    case_verifier::plan_scope(plan, scope)?;
    let contract = plan
        .plan
        .capability
        .workspace_d1_migration
        .as_ref()
        .ok_or_else(|| invalid("application proof is not a source transition"))?;
    let identity = Identity::from_contract(contract)?;
    let execution = &record.verified_execution.execution;
    let terminal = execution.terminal().map_err(invalid)?;
    if plan.plan.capability.path != "workspace:d1-transition-envelope-v3"
        || plan
            .plan
            .approval
            .as_ref()
            .map(|a| a.approved_content_hash.as_str())
            != Some(plan.plan.content_hash.as_str())
        || record.identity != identity
        || terminal.identity != identity
        || terminal.plan_hash != plan.plan.content_hash
        || terminal.operation_id != plan.plan.operation_id
        || plan
            .plan
            .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
            .and_then(|value| value.get("evidence_hash"))
            .and_then(Value::as_str)
            != Some(record.verified_execution.apply_evidence_hash.as_str())
    {
        return Err(invalid(
            "application proof substituted its approved source, plan or apply identity",
        ));
    }
    case_verifier::apply_record(store, plan, execution, not_after)?;
    let times = case_verifier::checkpoint_times(store, execution, not_after)?;
    let boundary = transport_receipt(store, terminal, &identity.database_id, not_after)?;
    let binding: RuntimeBindingV4 = serde_json::from_value(
        plan.plan
            .input
            .get("body")
            .cloned()
            .ok_or_else(|| invalid("application input binding missing"))?,
    )?;
    let admitted = super::admit_cached(store, contract, &binding, scope, times.dispatch, cache)?;
    if plan.plan.targets.pointer("/adapter/workspace_d1_migration")
        != Some(&serde_json::to_value(admitted)?)
    {
        return Err(invalid(
            "application proof changed its exact admitted runtime target",
        ));
    }
    let initial = execution
        .checkpoints
        .first()
        .ok_or_else(|| invalid("application initial state missing"))?;
    let assurance = contract
        .transition
        .as_ref()
        .and_then(|c| c.declaration.assurance.as_ref())
        .ok_or_else(|| invalid("application assurance missing"))?;
    let predecessor = binding
        .completed
        .last()
        .map_or(&binding.observed_baseline.evidence_hash, |c| {
            &c.preservation.evidence_hash
        });
    if initial.qualification_evidence_hash != binding.qualification_evidence_hash
        || initial.baseline_evidence_hash != binding.observed_baseline.evidence_hash
        || &initial.predecessor_evidence_hash != predecessor
        || initial.assurance_sha256 != super::hash_value(&serde_json::to_value(assurance)?)?
        || terminal.stage != Stage::Committed
    {
        return Err(invalid(
            "application atomic record changed qualification, assurance or lineage",
        ));
    }
    let declared = contract
        .transition
        .as_ref()
        .and_then(|c| c.declaration.observations.as_ref())
        .ok_or_else(|| invalid("application terminal assertions missing"))?;
    observations::read(
        store,
        contract,
        &declared.terminal,
        &record.terminal_assertions,
        scope,
        boundary.max(times.terminal),
        not_after,
    )?;
    diagnostic::read(
        store,
        contract,
        assurance,
        &record.diagnostic,
        scope,
        boundary.max(times.terminal),
        not_after,
    )?;
    Ok(execution.clone())
}

pub(super) fn produce(
    store: &StateStore,
    operation_id: &str,
    terminal_assertions: &ProofRef,
    diagnostic: &ProofRef,
    scope: &Scope<'_>,
) -> Result<EvidenceV1> {
    let plan = store.load_plan_v2(operation_id)?;
    if !matches!(
        plan.plan.status,
        PlanStatus::Running | PlanStatus::RectificationRequired
    ) || !matches!(
        plan.plan.transaction_stage,
        TransactionStageV1::BoundaryResponsePersisted
            | TransactionStageV1::VerificationAttemptPersisted
    ) {
        return Err(invalid(
            "application producer requires its pending native boundary response",
        ));
    }
    let hash = plan
        .plan
        .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
        .and_then(|v| v.get("evidence_hash"))
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("application apply record missing"))?;
    let execution: ExecutionRecord = serde_json::from_value(store.read_evidence_value(hash)?)?;
    let record = ApplicationVerification {
        schema_version: 1,
        kind: APPLICATION_KIND.into(),
        identity: Identity::from_contract(
            plan.plan
                .capability
                .workspace_d1_migration
                .as_ref()
                .ok_or_else(|| invalid("application source missing"))?,
        )?,
        verified_execution: VerifiedExecutionRecord {
            schema_version: 1,
            kind: VERIFIED_EXECUTION_KIND.into(),
            apply_evidence_hash: hash.into(),
            execution,
        },
        terminal_assertions: terminal_assertions.clone(),
        diagnostic: diagnostic.clone(),
    };
    validate(store, &plan, &record, scope, Utc::now())?;
    let evidence = store.write_evidence(
        EvidenceClass::PostChangeVerification,
        &serde_json::to_value(record)?,
    )?;
    // Verification closes only this new native operation after the complete
    // proof join. It never approves, redispatches or changes a legacy import.
    super::verification_producers::record_verification(store, &plan, &evidence, false)?;
    Ok(evidence)
}
