//! Local typed verification producers; no provider execution is exposed.
use super::{
    EvidenceClass, ExecutionRecord, Identity, PlanStatus, Result, Scope, StateStore,
    TransportReceipt, Utc, Value, case_validation, case_verifier, invalid, producers, read,
};
use crate::runtime::plan_commands::{
    persist_transaction_stage, persist_transaction_stage_with_artifact,
};
use cfctl_core::{
    EvidenceV1, PlanV2, TransactionStageV1,
    workspace_d1::transition::proofs::{
        CaseRef, QualificationTarget, VERIFIED_EXECUTION_KIND, VERIFIED_TRANSPORT_KIND,
        VerifiedExecutionRecord, VerifiedTransportReceipt,
    },
};

fn pending(plan: &PlanV2) -> Result<()> {
    plan.validate()?;
    if !matches!(
        plan.plan.status,
        PlanStatus::Running | PlanStatus::RectificationRequired
    ) || !matches!(
        plan.plan.transaction_stage,
        TransactionStageV1::BoundaryResponsePersisted
            | TransactionStageV1::VerificationAttemptPersisted
    ) || plan
        .plan
        .approval
        .as_ref()
        .map(|approval| approval.approved_content_hash.as_str())
        != Some(plan.plan.content_hash.as_str())
    {
        return Err(invalid(
            "verification producer requires its consumed approved native boundary response",
        ));
    }
    Ok(())
}
fn applied(store: &StateStore, plan: &PlanV2) -> Result<ExecutionRecord> {
    let hash = plan
        .plan
        .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
        .and_then(|value| value.get("evidence_hash"))
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("native execution apply artifact missing"))?;
    serde_json::from_value(store.read_evidence_value(hash)?)
        .map_err(|_| invalid("native execution apply artifact malformed"))
}
pub(super) fn produce_case(
    store: &StateStore,
    case: &CaseRef,
    identity: &Identity,
    scope: &Scope<'_>,
) -> Result<EvidenceV1> {
    let plan = store.load_plan_v2(&case.effect.operation_id)?;
    pending(&plan)?;
    let record = applied(store, &plan)?;
    let now = Utc::now();
    case_validation::verify(
        store,
        &plan,
        case,
        identity,
        &record,
        scope,
        (now, now),
        None,
    )?;
    write_verified_execution(store, &plan, record)
}
pub(super) fn produce_writer(
    store: &StateStore,
    case: &CaseRef,
    identity: &Identity,
    scope: &Scope<'_>,
) -> Result<EvidenceV1> {
    let actor = case
        .concurrency
        .as_ref()
        .ok_or_else(|| invalid("concurrent writer proposal missing"))?;
    let plan = store.load_plan_v2(&actor.writer.operation_id)?;
    pending(&plan)?;
    let parent = store.load_plan_v2(&case.effect.operation_id)?;
    QualificationTarget::from_case(identity, case)
        .validate()
        .map_err(invalid)?;
    let record = applied(store, &plan)?;
    let now = Utc::now();
    let join = case_verifier::Join {
        store,
        plan: &parent,
        case,
        identity,
        record: &record,
        scope,
        not_after: now,
    };
    let times = case_verifier::actors::writer_record(&join, &plan, &record)?;
    let baseline = read(store, &case.before, scope, now)?;
    let (observation, state) = producers::population_source(
        store,
        identity,
        &case.synthetic_database_id,
        (
            &actor.source.post_writer_inventory,
            cfctl_core::workspace_d1::transition::admission::resource::ReadPhase::PostWriter,
        ),
        &actor.post_writer_observation,
        scope,
        now,
    )?;
    if baseline.observed_at >= times.dispatch
        || observation.observed_at <= times.terminal
        || state != actor.source.expected_post_writer_state_sha256
    {
        return Err(invalid(
            "native writer population does not bracket its exact committed source",
        ));
    }
    write_verified_execution(store, &plan, record)
}
pub(super) fn produce_poll(
    store: &StateStore,
    case: &CaseRef,
    identity: &Identity,
    scope: &Scope<'_>,
) -> Result<EvidenceV1> {
    let parent = store.load_plan_v2(&case.effect.operation_id)?;
    let target = QualificationTarget::from_case(identity, case);
    target.validate().map_err(invalid)?;
    case_verifier::plan_scope(&parent, scope)?;
    if case.case != cfctl_core::workspace_d1::transition::proofs::Case::InterruptedResponse
        || parent.plan.capability.path != "workspace:d1-transition-qualification-v1"
        || parent
            .plan
            .targets
            .pointer("/adapter/workspace_d1_transition_qualification")
            != Some(&serde_json::to_value(target)?)
    {
        return Err(invalid(
            "poll parent does not select the exact interrupted case source",
        ));
    }
    let record = applied(store, &parent)?;
    let terminal = record.terminal().map_err(invalid)?;
    let hash = terminal
        .provider_receipt_sha256
        .as_deref()
        .ok_or_else(|| invalid("poll terminal missing"))?;
    let receipt: TransportReceipt = serde_json::from_value(store.read_evidence_value(hash)?)
        .map_err(|_| invalid("poll native receipt malformed"))?;
    receipt
        .validate(terminal, &case.synthetic_database_id)
        .map_err(invalid)?;
    let continuation = receipt
        .continuation
        .as_ref()
        .ok_or_else(|| invalid("poll continuation missing"))?;
    let plan = store.load_plan_v2(&continuation.operation_id)?;
    pending(&plan)?;
    let now = Utc::now();
    let join = case_verifier::Join {
        store,
        plan: &parent,
        case,
        identity,
        record: &record,
        scope,
        not_after: now,
    };
    case_verifier::apply_record(store, &parent, &record, now)?;
    case_verifier::actors::poll_source(&join, &receipt, &plan)?;
    let verified = VerifiedTransportReceipt {
        schema_version: 1,
        kind: VERIFIED_TRANSPORT_KIND.into(),
        apply_evidence_hash: hash.into(),
        receipt,
    };
    verified.validate().map_err(invalid)?;
    let evidence = store.write_evidence(
        EvidenceClass::PostChangeVerification,
        &serde_json::to_value(verified)?,
    )?;
    record_verification(store, &plan, &evidence, false)?;
    Ok(evidence)
}

fn write_verified_execution(
    store: &StateStore,
    plan: &PlanV2,
    record: ExecutionRecord,
) -> Result<EvidenceV1> {
    let apply_hash = plan
        .plan
        .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
        .and_then(|value| value.get("evidence_hash"))
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("verified execution apply hash missing"))?;
    let rolled_back = record.terminal().map_err(invalid)?.stage == super::Stage::RolledBack;
    let verified = VerifiedExecutionRecord {
        schema_version: 1,
        kind: VERIFIED_EXECUTION_KIND.into(),
        apply_evidence_hash: apply_hash.into(),
        execution: record,
    };
    verified.validate().map_err(invalid)?;
    let evidence = store.write_evidence(
        EvidenceClass::PostChangeVerification,
        &serde_json::to_value(verified)?,
    )?;
    record_verification(store, plan, &evidence, rolled_back)?;
    Ok(evidence)
}

pub(super) fn record_verification(
    store: &StateStore,
    plan: &PlanV2,
    evidence: &EvidenceV1,
    rolled_back: bool,
) -> Result<()> {
    pending(plan)?;
    if evidence.class != EvidenceClass::PostChangeVerification {
        return Err(invalid(
            "native verification requires its typed verification evidence",
        ));
    }
    let mut pending = plan.plan.clone();
    if pending.transaction_stage == TransactionStageV1::BoundaryResponsePersisted {
        persist_transaction_stage(
            store,
            &mut pending,
            TransactionStageV1::VerificationAttemptPersisted,
        )?;
    }
    pending.status = if rolled_back {
        PlanStatus::RectificationRequired
    } else {
        PlanStatus::Verified
    };
    persist_transaction_stage_with_artifact(
        store,
        &mut pending,
        TransactionStageV1::VerificationResponsePersisted,
        serde_json::json!({"state":"passed","evidence_hash":evidence.content_hash,
            "native_typed_verification":true,"rolled_back":rolled_back,"no_replay":true}),
    )?;
    persist_transaction_stage(store, &mut pending, TransactionStageV1::Closed)
}
