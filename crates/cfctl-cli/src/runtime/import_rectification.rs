use super::api_boundary::{
    boundary_response_artifact, secret_sink_artifact, verification_outcome,
    verification_response_artifact,
};
use super::import_lineage::exact_completed_reviewed_import_boundary;
use super::plan_commands::{persist_transaction_stage, persist_transaction_stage_with_artifact};
use super::prelude::{
    CliError, CloudflareResponseV1, PlanStatus, PlanV1, Result, ResultEnvelopeV2, StateStore,
    TransactionStageV1, Value, VerificationState, json,
};
use cfctl_cloudflare::verify_reviewed_git_import_completion;

/// Reconciles only durable provider completion. This path has no executor or credentials.
pub(super) fn rectify_completed_reviewed_import(
    store: &StateStore,
    plan: &mut PlanV1,
) -> Result<ResultEnvelopeV2> {
    let awaiting_verification = matches!(
        plan.status,
        PlanStatus::Running | PlanStatus::RectificationRequired
    ) && matches!(
        plan.transaction_stage,
        TransactionStageV1::SecretSinkPersisted | TransactionStageV1::VerificationAttemptPersisted
    );
    let verified = plan.status == PlanStatus::Verified
        && matches!(
            plan.transaction_stage,
            TransactionStageV1::VerificationResponsePersisted | TransactionStageV1::Closed
        );
    if plan.capability.id != "d1-import-database"
        || !(awaiting_verification || verified)
        || store.load_plan_v2(&plan.operation_id)?.plan != *plan
    {
        return Err(CliError::Input(
            "reviewed import is not at an authentic recoverable completion boundary".to_owned(),
        ));
    }
    let completion = exact_completed_reviewed_import_boundary(store, &plan.operation_id)?;
    let boundary = plan
        .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
        .ok_or_else(|| CliError::Input("import apply boundary is missing".to_owned()))?;
    let apply_hash = boundary
        .get("apply_evidence_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("import apply evidence binding is missing".to_owned()))?;
    let response: CloudflareResponseV1 =
        serde_json::from_value(store.read_evidence_value(apply_hash)?)?;
    let mut expected_boundary = boundary_response_artifact(plan, &response, None);
    expected_boundary["apply_evidence_hash"] = json!(apply_hash);
    if *boundary != expected_boundary
        || response.result.get("_cfctl") != completion.checkpoint.get("receipt")
        || plan.transaction_artifact(TransactionStageV1::SecretSinkPersisted)
            != Some(&secret_sink_artifact(
                plan, None, false, true, false, None, None,
            ))
    {
        return Err(CliError::Input(
            "import apply response, provider completion, or completed sink binding differs"
                .to_owned(),
        ));
    }
    let verification = verify_reviewed_git_import_completion(plan, &response)?;
    if !verification.passed {
        return Err(CliError::Input(verification.basis));
    }
    let basis = verification.basis.clone();
    let mut result = serde_json::to_value(&verification)?;
    result["operation_id"] = json!(plan.operation_id);
    result["provider_complete_evidence_hash"] = json!(completion.evidence_hash);
    result["apply_evidence_hash"] = json!(apply_hash);
    if plan.transaction_stage == TransactionStageV1::SecretSinkPersisted {
        persist_transaction_stage(
            store,
            plan,
            TransactionStageV1::VerificationAttemptPersisted,
        )?;
    }
    let outcome = verification_outcome(store, plan, verification)?;
    let verification_artifact = verification_response_artifact(&outcome)?;
    if verified {
        if plan.transaction_artifact(TransactionStageV1::VerificationResponsePersisted)
            != Some(&verification_artifact)
        {
            return Err(CliError::Input(
                "saved import verification differs from authenticated completion".to_owned(),
            ));
        }
    } else {
        persist_transaction_stage_with_artifact(
            store,
            plan,
            TransactionStageV1::VerificationResponsePersisted,
            verification_artifact,
        )?;
    }
    if plan.transaction_stage != TransactionStageV1::Closed {
        persist_transaction_stage(store, plan, TransactionStageV1::Closed)?;
    }
    let mut envelope = ResultEnvelopeV2::success("plans rectify", result);
    envelope.evidence.extend(outcome.evidence);
    envelope.performed = false;
    envelope.operation_id = Some(plan.operation_id.clone());
    envelope.capability_id = Some(plan.capability.id.clone());
    envelope.profile_id = Some(plan.profile_id.clone());
    envelope.account_id = Some(plan.account_id.clone());
    envelope.policy_decision = Some(plan.policy.clone());
    envelope.verification.state = VerificationState::Passed;
    envelope.verification.basis = Some(basis);
    Ok(envelope)
}
