//! Operation-bound D1 restore provenance and local historical inspection.
use super::api_boundary::boundary_response_artifact;
use super::prelude::{
    CallInput, CliError, CloudflareResponseV1, EvidenceClass, EvidenceV1, OperationVerificationV1,
    PlanStatus, PlanV1, PlanV2, Result, StateStore, StoredPlanRecord, TransactionStageV1, Value,
    VerificationState, json,
};
use cfctl_cloudflare::validate_request_contract;
use cfctl_core::{TransactionCheckpointV1, hash_value};
use chrono::Utc;

pub(super) const RESTORE_ID: &str = "d1-restore-exact-bookmark";
const STRATEGY: &str = "d1_current_bookmark_equals_restore_result_bookmark";
pub(super) const CONTEXT: &str = "d1_restore_execution";
/// Rejections that mean the verification body itself violates its contract.
/// These are refused outright; only store and lineage failures are recorded.
const BODY_CONTRACT_REJECTIONS: [&str; 3] = [
    "unsupported_restore_verification_strategy",
    "invalid_verification_failure",
    "invalid_verification_body",
];
type Checked<T> = std::result::Result<T, &'static str>;

/// Only store and lineage rejections are recorded. A malformed verification
/// body is refused outright, and a passing verification is never kept without
/// its binding.
pub(super) fn recordable(reason: &str, passed: bool) -> bool {
    !passed && !BODY_CONTRACT_REJECTIONS.contains(&reason)
}

fn checkpoint(plan: &PlanV1, stage: TransactionStageV1) -> Checked<&TransactionCheckpointV1> {
    plan.transaction_journal
        .iter()
        .find(|entry| entry.stage == stage)
        .ok_or("missing_transaction_checkpoint")
}

fn execution_prefix(plan: &PlanV1) -> Checked<&TransactionCheckpointV1> {
    let now = Utc::now();
    let mut previous = plan.created_at;
    for entry in &plan.transaction_journal {
        if entry.recorded_at < previous || entry.recorded_at > now {
            return Err("invalid_restore_chronology");
        }
        previous = entry.recorded_at;
    }
    for (stage, status) in [
        (TransactionStageV1::ApprovalPersisted, PlanStatus::Approved),
        (
            TransactionStageV1::ConsumptionPersisted,
            PlanStatus::Consumed,
        ),
        (
            TransactionStageV1::BoundaryAttemptPersisted,
            PlanStatus::Consumed,
        ),
        (
            TransactionStageV1::BoundaryResponsePersisted,
            PlanStatus::Running,
        ),
        (
            TransactionStageV1::VerificationAttemptPersisted,
            PlanStatus::Running,
        ),
    ] {
        let entry = checkpoint(plan, stage)?;
        if entry.plan_content_hash != plan.content_hash || entry.plan_status != status {
            return Err("invalid_restore_execution_prefix");
        }
    }
    let approval = plan.approval.as_ref().ok_or("missing_restore_approval")?;
    if approval.approved_at < plan.created_at
        || approval.approved_at
            > checkpoint(plan, TransactionStageV1::ApprovalPersisted)?.recorded_at
    {
        return Err("invalid_restore_approval_order");
    }
    checkpoint(plan, TransactionStageV1::VerificationAttemptPersisted)
}

fn plan_input(plan: &PlanV2) -> Checked<CallInput> {
    plan.validate().map_err(|_| "invalid_plan_v2")?;
    let mut recomputed = plan.plan.clone();
    recomputed
        .refresh_hash()
        .map_err(|_| "invalid_plan_content")?;
    if recomputed.content_hash != plan.plan.content_hash {
        return Err("plan_content_mismatch");
    }
    let capability = &plan.plan.capability;
    if capability.id != RESTORE_ID
        || capability.d1_restore_exact_bookmark.is_none()
        || !capability.verification.required
        || capability.verification.strategy != STRATEGY
        || !capability.verification_contract_supported()
    {
        return Err("unsupported_restore_plan");
    }
    let input: CallInput =
        serde_json::from_value(plan.plan.input.clone()).map_err(|_| "invalid_restore_input")?;
    validate_request_contract(capability, &input).map_err(|_| "invalid_restore_input")?;
    if input.selectors["account_id"] != plan.plan.account_id {
        return Err("restore_account_mismatch");
    }
    Ok(input)
}

fn provenance(plan: &PlanV2, apply_hash: &str) -> Checked<Value> {
    let input = plan_input(plan)?;
    let digest = |value: &Value| hash_value(value).map_err(|_| "invalid_binding_hash");
    let pins = serde_json::to_value(&plan.pins).map_err(|_| "invalid_plan_pins")?;
    let capability =
        serde_json::to_value(&plan.plan.capability).map_err(|_| "invalid_restore_capability")?;
    let body = input.body.as_ref().ok_or("missing_restore_input")?;
    let attempt = execution_prefix(&plan.plan)?;
    Ok(json!({
        "schema_version":1,
        "operation_id":plan.plan.operation_id,
        "capability_id":plan.plan.capability.id,
        "capability_hash":digest(&capability)?,
        "plan_content_hash":plan.plan.content_hash,
        "pins_hash":digest(&pins)?,
        "profile_id":plan.plan.profile_id,
        "credential_generation_id":plan.pins.credential_generation_id,
        "account_id":plan.plan.account_id,
        "database_id":input.selectors["database_id"],
        "catalog_hash":plan.pins.catalog_hash,
        "build_identity_hash":plan.pins.build_identity_hash,
        "targets_hash":digest(&plan.plan.targets)?,
        "request_hash":digest(&plan.plan.input)?,
        "request_digest":digest(body)?,
        "caller_inputs":body,
        "apply_evidence_hash":apply_hash,
        "verification_attempt_checkpoint_hash":attempt.checkpoint_hash,
    }))
}

fn successful(response: &CloudflareResponseV1) -> bool {
    response.success && (200..300).contains(&response.status) && response.errors.is_empty()
}

fn restore_receipt(plan: &PlanV2, apply: &CloudflareResponseV1) -> Checked<Value> {
    for field in ["bookmark", "previous_bookmark", "message"] {
        if apply.result[field].as_str().is_none_or(str::is_empty) {
            return Err("incomplete_restore_response");
        }
    }
    let input = plan_input(plan)?;
    let body = input.body.as_ref().ok_or("missing_restore_input")?;
    Ok(json!({
        "target_bookmark":body["target_bookmark"],
        "expected_current_bookmark":body["expected_current_bookmark"],
        "pre_restore_bookmark":body["expected_current_bookmark"],
        "returned_bookmark":apply.result["bookmark"],
        "previous_bookmark":apply.result["previous_bookmark"],
        "source_operation_id":body["source_operation_id"],
        "source_evidence_hash":body["source_evidence_hash"],
        "request_digest":hash_value(body).map_err(|_| "invalid_request_digest")?,
        "provider_message":apply.result["message"],
        "post_retry_count":0,"performed":true,"verified":false,
    }))
}

fn bookmarks(
    plan: &PlanV2,
    apply: &CloudflareResponseV1,
    verification: &OperationVerificationV1,
) -> Checked<Value> {
    if !successful(apply)
        || !successful(&verification.readback)
        || !verification.passed
        || verification.strategy != STRATEGY
        || verification.correlated_resource_id.is_some()
    {
        return Err("restore_verification_did_not_pass");
    }
    let input = plan_input(plan)?;
    let body = input.body.as_ref().ok_or("missing_restore_input")?;
    let receipt = restore_receipt(plan, apply)?;
    let mut readback_receipt = receipt.clone();
    readback_receipt["post_restore_bookmark"] = verification.readback.result["bookmark"].clone();
    readback_receipt["verified"] = json!(true);
    if apply.result["_cfctl"] != receipt
        || verification.readback.result["_cfctl"] != readback_receipt
        || verification.readback.result["bookmark"] != apply.result["bookmark"]
    {
        return Err("restore_bookmark_or_input_mismatch");
    }
    Ok(json!({
        "target_bookmark":body["target_bookmark"],
        "expected_current_bookmark":body["expected_current_bookmark"],
        "pre_restore_bookmark":receipt["pre_restore_bookmark"],
        "returned_bookmark":apply.result["bookmark"],
        "previous_bookmark":apply.result["previous_bookmark"],
        "post_restore_bookmark":verification.readback.result["bookmark"],
    }))
}

fn authenticated_apply(
    store: &StateStore,
    plan: &PlanV1,
) -> Checked<(EvidenceV1, CloudflareResponseV1)> {
    let boundary = plan
        .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
        .ok_or("missing_apply_reference")?;
    let hash = boundary["apply_evidence_hash"]
        .as_str()
        .ok_or("missing_apply_evidence")?;
    let (descriptor, body) = store
        .load_evidence_value(hash)
        .map_err(|_| "apply_evidence_unavailable_or_unauthenticated")?;
    if descriptor.class != EvidenceClass::Apply {
        return Err("wrong_apply_evidence_class");
    }
    let response: CloudflareResponseV1 =
        serde_json::from_value(body).map_err(|_| "invalid_apply_body")?;
    if *boundary != boundary_response_artifact(plan, &response, Some(&descriptor)) {
        return Err("apply_reference_mismatch");
    }
    checkpoint(plan, TransactionStageV1::BoundaryAttemptPersisted)?;
    let persisted = checkpoint(plan, TransactionStageV1::BoundaryResponsePersisted)?;
    // Identical response bytes reuse an immutable content-addressed descriptor.
    // The freshly signed verification context binds this execution to those
    // exact bytes; the apply descriptor need not have been created this time.
    if descriptor.generated_at > persisted.recorded_at {
        return Err("apply_evidence_order_mismatch");
    }
    Ok((descriptor, response))
}

/// Runs at the existing native verification producer, before the evidence MAC.
/// The signed checkpoint prefix binds approval, consumption and the exact apply
/// reference. Source IDs remain caller inputs, not authenticated export lineage.
pub(super) fn attach_verification_context(
    store: &StateStore,
    plan: &PlanV1,
    verification: &mut Value,
) -> Result<()> {
    if plan.capability.id != RESTORE_ID {
        return Ok(());
    }
    let bind = || -> Checked<Value> {
        let StoredPlanRecord::Current(current) = store
            .load_stored_plan_record(&plan.operation_id)
            .map_err(|_| "restore_plan_unavailable")?
        else {
            return Err("restore_plan_unavailable_or_drifted");
        };
        // verification_outcome has changed only the in-memory terminal status.
        let mut before_verification = plan.clone();
        before_verification.status = current.plan.status;
        if current.plan != before_verification
            || current.plan.status != PlanStatus::Running
            || current.plan.transaction_stage != TransactionStageV1::VerificationAttemptPersisted
        {
            return Err("restore_verification_producer_mismatch");
        }
        let (descriptor, apply) = authenticated_apply(store, &current.plan)?;
        if verification["strategy"] != STRATEGY {
            return Err("unsupported_restore_verification_strategy");
        }
        // Authentication records what this execution observed, including a
        // failure. It does not turn failure into a qualified restore.
        if verification.get("readback").is_some() {
            let observed: OperationVerificationV1 = serde_json::from_value(verification.clone())
                .map_err(|_| "invalid_verification_body")?;
            if observed.passed {
                bookmarks(&current, &apply, &observed)?;
            }
        } else if verification["passed"] != false
            || verification["error"].as_str().is_none_or(str::is_empty)
        {
            return Err("invalid_verification_failure");
        }
        provenance(&current, &descriptor.content_hash)
    };
    match bind() {
        Ok(context) => verification[CONTEXT] = context,
        // A failure stays durable even when its execution cannot be bound. The
        // record is discriminated so every consumer reports this rejection
        // instead of mistaking it for an unbound record from an older build.
        Err(reason) if recordable(reason, verification["passed"] == true) => {
            verification[CONTEXT] = json!({"bound": false, "reason": reason});
        }
        Err(reason) => {
            return Err(CliError::Input(format!(
                "D1 restore verification context is unqualified: {reason}"
            )));
        }
    }
    Ok(())
}

/// The recorded rejection when a failure was preserved without its binding.
/// Qualification never reads this; it exists so callers can report the cause.
pub(super) fn unqualified_reason(verification: &Value) -> Option<&str> {
    let context = verification.get(CONTEXT)?;
    if context.get("bound") != Some(&json!(false)) {
        return None;
    }
    context.get("reason").and_then(Value::as_str)
}

/// The rejection recorded against a preserved failure, for reporting after the
/// execution itself. Qualification never consults it.
pub(super) fn recorded_binding_rejection(store: &StateStore, plan: &PlanV1) -> Option<String> {
    let hash = plan
        .transaction_artifact(TransactionStageV1::VerificationResponsePersisted)?
        .get("evidence_hash")?
        .as_str()?;
    let (_, value) = store.load_evidence_value(hash).ok()?;
    unqualified_reason(&value).map(str::to_owned)
}

fn evidence_projection(evidence: &EvidenceV1) -> Value {
    json!({"content_hash":evidence.content_hash,"class":evidence.class,
        "generated_at":evidence.generated_at})
}

/// Authenticate the failed historical execution without changing its outcome.
/// Used only by the separate complete-content reconciliation producer.
#[expect(
    clippy::too_many_lines,
    reason = "the failed historical execution gate explicitly joins signed context, response annotations and journal chronology"
)]
pub(super) fn failed_reconciliation_history(store: &StateStore, plan: &PlanV2) -> Result<Value> {
    let bind = || -> Checked<Value> {
        let input = plan_input(plan)?;
        let body = input.body.as_ref().ok_or("missing_restore_input")?;
        if plan.plan.status != PlanStatus::RectificationRequired
            || plan.plan.cancelled_at.is_some()
            || plan
                .plan
                .approval
                .as_ref()
                .is_none_or(|approval| approval.approved_content_hash != plan.plan.content_hash)
            || body["target_bookmark"] != body["expected_current_bookmark"]
        {
            return Err("not_a_failed_same_checkpoint_restore");
        }
        for stage in [
            TransactionStageV1::BoundaryAttemptPersisted,
            TransactionStageV1::BoundaryResponsePersisted,
            TransactionStageV1::VerificationAttemptPersisted,
            TransactionStageV1::VerificationResponsePersisted,
        ] {
            if plan
                .plan
                .transaction_journal
                .iter()
                .filter(|entry| entry.stage == stage)
                .count()
                != 1
            {
                return Err("ambiguous_restore_execution");
            }
        }
        let (apply_descriptor, apply) = authenticated_apply(store, &plan.plan)?;
        let terminal = plan
            .plan
            .transaction_artifact(TransactionStageV1::VerificationResponsePersisted)
            .ok_or("missing_verification_reference")?;
        let hash = terminal["evidence_hash"]
            .as_str()
            .ok_or("missing_verification_evidence")?;
        let (descriptor, value) = store
            .load_evidence_value(hash)
            .map_err(|_| "verification_evidence_unavailable_or_unauthenticated")?;
        // A binding this producer rejected at execution is not the same thing
        // as one an older build never wrote; report them apart.
        if unqualified_reason(&value).is_some() {
            return Err("historical_failed_restore_execution_binding_rejected_at_execution");
        }
        // Failed records from older builds omitted this MAC-covered binding.
        // Self-hashed plans and source-export receipts cannot recreate it.
        if value.get(CONTEXT) != Some(&provenance(plan, &apply_descriptor.content_hash)?) {
            return Err("historical_failed_restore_missing_authenticated_execution_binding");
        }
        let verification: OperationVerificationV1 =
            serde_json::from_value(value).map_err(|_| "invalid_verification_body")?;
        if !successful(&apply)
            || !successful(&verification.readback)
            || verification.passed
            || verification.strategy != STRATEGY
            || verification.correlated_resource_id.is_some()
            || descriptor.class != EvidenceClass::PostChangeVerification
            || terminal["state"] != "failed"
            || !terminal["resource_id"].is_null()
            || terminal["basis_hash"]
                != hash_value(&json!(verification.basis)).map_err(|_| "invalid_basis")?
        {
            return Err("not_an_authenticated_failed_bookmark_verification");
        }
        let receipt = restore_receipt(plan, &apply)?;
        let post = verification.readback.result["bookmark"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or("missing_post_restore_bookmark")?;
        let mut expected_readback = receipt.clone();
        expected_readback["post_restore_bookmark"] = json!(post);
        if apply.result["_cfctl"] != receipt
            || verification.readback.result["_cfctl"] != expected_readback
        {
            return Err("failed_readback_annotation_mismatch");
        }
        let observed = json!({
            "target_bookmark":body["target_bookmark"],
            "expected_current_bookmark":body["expected_current_bookmark"],
            "pre_restore_bookmark":receipt["pre_restore_bookmark"],
            "returned_bookmark":apply.result["bookmark"],
            "previous_bookmark":apply.result["previous_bookmark"],
            "post_restore_bookmark":post,
        });
        let attempt = execution_prefix(&plan.plan)?;
        let persisted = checkpoint(
            &plan.plan,
            TransactionStageV1::VerificationResponsePersisted,
        )?;
        if descriptor.generated_at < attempt.recorded_at
            || descriptor.generated_at > persisted.recorded_at
            || persisted.plan_status != PlanStatus::RectificationRequired
        {
            return Err("failed_verification_chronology_mismatch");
        }
        Ok(
            json!({"binding":provenance(plan, &apply_descriptor.content_hash)?,
            "bookmarks":observed,"original_verification_state":"failed",
            "evidence":{"apply":evidence_projection(&apply_descriptor),"verification":evidence_projection(&descriptor)},
            "boundary_at":checkpoint(&plan.plan, TransactionStageV1::BoundaryAttemptPersisted)?.recorded_at,
            "verification_at":descriptor.generated_at}),
        )
    };
    bind().map_err(|reason| {
        CliError::Input(format!("D1 historical reconciliation rejected: {reason}"))
    })
}

fn historical_proof(store: &StateStore, plan: &PlanV2) -> Checked<Value> {
    plan_input(plan)?;
    if plan.plan.status != PlanStatus::Verified
        || plan.plan.transaction_stage != TransactionStageV1::Closed
        || plan.plan.approval.is_none()
        || plan.plan.cancelled_at.is_some()
    {
        return Err("restore_lifecycle_not_verified_closed");
    }
    let (apply_descriptor, apply) = authenticated_apply(store, &plan.plan)?;
    let terminal = plan
        .plan
        .transaction_artifact(TransactionStageV1::VerificationResponsePersisted)
        .ok_or("missing_verification_reference")?;
    let hash = terminal["evidence_hash"]
        .as_str()
        .ok_or("missing_verification_evidence")?;
    let (descriptor, body) = store
        .load_evidence_value(hash)
        .map_err(|_| "verification_evidence_unavailable_or_unauthenticated")?;
    if descriptor.class != EvidenceClass::PostChangeVerification {
        return Err("wrong_verification_evidence_class");
    }
    let binding = body.get(CONTEXT).ok_or("historical_unbound_verification")?;
    if *binding != provenance(plan, &apply_descriptor.content_hash)? {
        return Err("restore_execution_binding_mismatch");
    }
    let verification: OperationVerificationV1 =
        serde_json::from_value(body.clone()).map_err(|_| "invalid_verification_body")?;
    let bookmarks = bookmarks(plan, &apply, &verification)?;
    let attempt = checkpoint(&plan.plan, TransactionStageV1::VerificationAttemptPersisted)?;
    let persisted = checkpoint(
        &plan.plan,
        TransactionStageV1::VerificationResponsePersisted,
    )?;
    if terminal["state"] != "passed"
        || !terminal["resource_id"].is_null()
        || terminal["basis_hash"]
            != hash_value(&json!(verification.basis)).map_err(|_| "invalid_verification_basis")?
        || attempt.plan_status != PlanStatus::Running
        || persisted.plan_status != PlanStatus::Verified
        || descriptor.generated_at < attempt.recorded_at
        || descriptor.generated_at > persisted.recorded_at
        || descriptor.generated_at > Utc::now()
    {
        return Err("verification_reference_mismatch");
    }
    Ok(json!({
        "qualification":"authenticated_restore_verification","qualified":true,
        "readback_passed":true,"verification_strategy":STRATEGY,
        "binding":binding,"bookmarks":bookmarks,
        "evidence":{"apply":evidence_projection(&apply_descriptor),
            "verification":evidence_projection(&descriptor)},
    }))
}

/// Authenticated historical inspection only: no catalog refresh, credentials,
/// provider requests, source export reads, journal writes or current authority.
pub(super) fn inspect(
    store: &StateStore,
    plan: &PlanV1,
    current: Option<&PlanV2>,
    projection_drift: bool,
) -> (Value, VerificationState) {
    let proof = if projection_drift {
        Err("plan_projection_drift")
    } else if let Some(current) = current.filter(|current| current.plan == *plan) {
        historical_proof(store, current)
    } else {
        Err("current_plan_v2_unavailable")
    };
    let (mut value, state) = match proof {
        Ok(value) => (value, VerificationState::Passed),
        Err(reason) => (
            json!({"qualification":"unqualified","qualified":false,"reason":reason}),
            VerificationState::Failed,
        ),
    };
    for (key, field) in [
        ("schema_version", json!(1)),
        ("operation_id", json!(plan.operation_id)),
        ("plan_content_hash", json!(plan.content_hash)),
        ("request_hash", json!(hash_value(&plan.input).ok())),
        ("provider_requests", json!(0)),
        ("historical_observation", json!(true)),
        ("current_provider_state_qualified", json!(false)),
        ("source_export_lineage_qualified", json!(false)),
        ("changed_state_rollback_qualified", json!(false)),
        ("write_authority_granted", json!(false)),
    ] {
        value[key] = field;
    }
    (value, state)
}
