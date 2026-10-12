use super::{
    ExecutionRecord, Join, Result, Stage, Times, TransportReceipt, Value, apply_record,
    checkpoint_times, invalid, plan_scope, producers, read,
};
use cfctl_core::{
    PlanStatus, TransactionStageV1, hash_value, workspace_d1::transition::proofs::WriterTarget,
};

pub(super) fn writer(join: &Join<'_, '_>, main: Times) -> Result<()> {
    let proof = join
        .case
        .concurrency
        .as_ref()
        .ok_or_else(|| invalid("concurrent writer source and evidence missing"))?;
    let plan = super::super::super::effect(join.store, &proof.writer, join.scope)?;
    plan_scope(&plan, join.scope)?;
    let expected = serde_json::to_value(WriterTarget {
        parent: cfctl_core::workspace_d1::transition::proofs::QualificationTarget::from_case(
            join.identity,
            join.case,
        ),
    })?;
    if plan.plan.operation_id == join.plan.plan.operation_id
        || plan.plan.capability.path != "workspace:d1-transition-writer-v1"
        || plan
            .plan
            .targets
            .pointer("/adapter/workspace_d1_transition_writer")
            != Some(&expected)
    {
        return Err(invalid(
            "concurrent writer is not its distinct exact approved source plan",
        ));
    }
    let record = super::verified_execution(
        join.store,
        &plan,
        &proof.writer.evidence_hash,
        join.not_after,
    )?;
    let writer = writer_record(join, &plan, &record)?;
    let before = read(join.store, &join.case.before, join.scope, join.not_after)?;
    let observation = read(
        join.store,
        &proof.post_writer_observation,
        join.scope,
        join.not_after,
    )?;
    let (_, state) = producers::population_source(
        join.store,
        join.identity,
        &join.case.synthetic_database_id,
        (
            &proof.source.post_writer_inventory,
            cfctl_core::workspace_d1::transition::admission::resource::ReadPhase::PostWriter,
        ),
        &proof.post_writer_observation,
        join.scope,
        join.not_after,
    )?;
    if before.observed_at >= writer.dispatch
        || writer.terminal >= observation.observed_at
        || observation.observed_at >= main.dispatch
        || state != proof.source.expected_post_writer_state_sha256
    {
        return Err(invalid(
            "writer and complete new population do not precede atomic capture after baseline",
        ));
    }
    Ok(())
}

pub(in super::super) fn writer_record(
    join: &Join<'_, '_>,
    plan: &cfctl_core::PlanV2,
    record: &ExecutionRecord,
) -> Result<Times> {
    plan_scope(plan, join.scope)?;
    let expected = serde_json::to_value(WriterTarget {
        parent: cfctl_core::workspace_d1::transition::proofs::QualificationTarget::from_case(
            join.identity,
            join.case,
        ),
    })?;
    if plan.plan.operation_id == join.plan.plan.operation_id
        || plan.plan.capability.path != "workspace:d1-transition-writer-v1"
        || plan
            .plan
            .targets
            .pointer("/adapter/workspace_d1_transition_writer")
            != Some(&expected)
        || plan
            .plan
            .approval
            .as_ref()
            .map(|approval| approval.approved_content_hash.as_str())
            != Some(plan.plan.content_hash.as_str())
        || plan
            .plan
            .input
            .pointer("/selectors/account_id")
            .and_then(Value::as_str)
            != Some(join.scope.account)
        || plan
            .plan
            .input
            .pointer("/selectors/database_id")
            .and_then(Value::as_str)
            != Some(join.case.synthetic_database_id.as_str())
    {
        return Err(invalid(
            "native writer approval, selectors or exact source differs",
        ));
    }
    apply_record(join.store, plan, record, join.not_after)?;
    let proof = join
        .case
        .concurrency
        .as_ref()
        .ok_or_else(|| invalid("concurrent writer source missing"))?;
    let capability = crate::runtime::support::load_workspace_capability(
        join.store,
        &proof.source.post_writer_inventory.capability_id,
    )?
    .ok_or_else(|| invalid("writer source repository is not registered"))?;
    let contract = capability
        .workspace_d1_read_inventory
        .as_ref()
        .ok_or_else(|| invalid("writer source native inventory missing"))?;
    if contract.repository_head != join.identity.repository_head {
        return Err(invalid("writer source repository revision differs"));
    }
    let bytes = cfctl_workspace::materialize_workspace_d1_transition_source(
        std::path::Path::new(&contract.repository_root),
        &join.identity.repository_head,
        &proof.source.writer,
    )
    .map_err(|_| invalid("writer source bytes or Git blob changed"))?;
    if bytes.len() != proof.source.writer_bytes {
        return Err(invalid("writer source byte length differs"));
    }
    let terminal = record.terminal().map_err(invalid)?;
    let mut identity = join.identity.clone();
    identity
        .execution_sha256
        .clone_from(&proof.source.writer.sha256);
    if terminal.stage != Stage::Committed
        || terminal.identity != identity
        || terminal.operation_id != plan.plan.operation_id
        || terminal.plan_hash != plan.plan.content_hash
    {
        return Err(invalid(
            "native concurrent writer did not commit its exact source",
        ));
    }
    super::super::transport_receipt(
        join.store,
        terminal,
        &join.case.synthetic_database_id,
        join.not_after,
    )?;
    checkpoint_times(join.store, record, join.not_after)
}

pub(super) fn poll(join: &Join<'_, '_>, receipt: &TransportReceipt) -> Result<()> {
    let continuation = receipt
        .continuation
        .as_ref()
        .ok_or_else(|| invalid("interrupted case has no approved poll-only continuation"))?;
    let plan = join.store.load_plan_v2(&continuation.operation_id)?;
    plan_scope(&plan, join.scope)?;
    if plan.plan.status != PlanStatus::Verified {
        return Err(invalid("native poll plan is not verified"));
    }
    poll_source(join, receipt, &plan)?;
    let verification = plan
        .plan
        .transaction_artifact(TransactionStageV1::VerificationResponsePersisted)
        .and_then(|value| value.get("evidence_hash"))
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("poll verification missing"))?;
    let evidence = join.store.load_evidence(verification)?;
    let verified: cfctl_core::workspace_d1::transition::proofs::VerifiedTransportReceipt =
        serde_json::from_value(join.store.read_evidence_value(verification)?)
            .map_err(|_| invalid("poll verification is not the exact native receipt"))?;
    verified.validate().map_err(invalid)?;
    if evidence.class != cfctl_core::EvidenceClass::PostChangeVerification
        || evidence.generated_at > join.not_after
        || verified.apply_evidence_hash != terminal_apply_hash(join)?
        || &verified.receipt != receipt
    {
        return Err(invalid("poll verification substituted terminal evidence"));
    }
    Ok(())
}

pub(in super::super) fn poll_source(
    join: &Join<'_, '_>,
    receipt: &TransportReceipt,
    plan: &cfctl_core::PlanV2,
) -> Result<()> {
    plan_scope(plan, join.scope)?;
    let continuation = receipt
        .continuation
        .as_ref()
        .ok_or_else(|| invalid("poll continuation missing"))?;
    let parent = join
        .record
        .checkpoints
        .iter()
        .find(|checkpoint| {
            checkpoint.stage == Stage::Uncertain
                && serde_json::to_value(checkpoint)
                    .ok()
                    .and_then(|value| hash_value(&value).ok())
                    .as_deref()
                    == Some(continuation.parent_checkpoint_sha256.as_str())
        })
        .ok_or_else(|| invalid("native uncertain parent missing"))?;
    let expected = serde_json::json!({"parent_operation_id":join.plan.plan.operation_id,
        "parent_plan_hash":join.plan.plan.content_hash,"checkpoint_sha256":continuation.parent_checkpoint_sha256,
        "bookmark_sha256":continuation.bookmark_sha256,"database_id":join.case.synthetic_database_id,"identity":parent.identity});
    if plan.plan.operation_id != continuation.operation_id
        || plan
            .plan
            .input
            .pointer("/selectors/account_id")
            .and_then(Value::as_str)
            != Some(join.scope.account)
        || plan
            .plan
            .input
            .pointer("/selectors/database_id")
            .and_then(Value::as_str)
            != Some(join.case.synthetic_database_id.as_str())
        || plan.plan.content_hash != continuation.plan_hash
        || plan.plan.capability.path != "workspace:d1-transition-poll-v1"
        || plan
            .plan
            .approval
            .as_ref()
            .map(|approval| approval.approved_content_hash.as_str())
            != Some(plan.plan.content_hash.as_str())
        || plan
            .plan
            .targets
            .pointer("/adapter/workspace_d1_transition_poll")
            != Some(&expected)
    {
        return Err(invalid(
            "poll-only continuation approval, source or parent differs",
        ));
    }
    let terminal_hash = join
        .record
        .terminal()
        .map_err(invalid)?
        .provider_receipt_sha256
        .as_deref()
        .ok_or_else(|| invalid("poll terminal missing"))?;
    if plan
        .plan
        .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
        .and_then(|value| value.get("evidence_hash"))
        .and_then(Value::as_str)
        != Some(terminal_hash)
    {
        return Err(invalid(
            "poll plan did not persist this native terminal response",
        ));
    }
    let evidence = join.store.load_evidence(terminal_hash)?;
    if evidence.class != cfctl_core::EvidenceClass::Apply
        || evidence.generated_at > join.not_after
        || join.store.read_evidence_value(terminal_hash)? != serde_json::to_value(receipt)?
    {
        return Err(invalid("poll apply receipt authentication differs"));
    }
    checkpoint_times(join.store, join.record, join.not_after)?;
    Ok(())
}

fn terminal_apply_hash<'a>(join: &'a Join<'_, '_>) -> Result<&'a str> {
    join.record
        .terminal()
        .map_err(invalid)?
        .provider_receipt_sha256
        .as_deref()
        .ok_or_else(|| invalid("native terminal apply receipt missing"))
}
