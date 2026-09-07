//! Bind native restore observations before authentication; inspect them locally.
use super::api_boundary::{self, ApiVerificationOutcome};
use super::prelude::{
    CallInput, CliError, EvidenceClass, PlanV1, Result, StateStore, TransactionStageV1, Value,
    VerificationState, json,
};
use cfctl_cloudflare::OperationVerificationV1;
use cfctl_core::{
    hash_value,
    r2_recovery::{
        CaptureReceiptV1, CaptureWindowV1, MAX_BYTES, MAX_OBJECTS, MAX_PAGES, is_sha256,
    },
    r2_restore::{
        self as contract, CaptureRefV1, CurrentExpectationV1,
        RestoreObjectResultV1 as ObjectResult, RestoreObservationKindV1 as ObservationKind,
        RestoreRequestV1, RestoreSelectionV1, RestoreVerificationBindingV1 as RestoreBinding,
    },
};
use chrono::{DateTime, Utc};

const TARGET: &str = "/adapter/r2_private_restore";
const BINDING: &str = "restore_binding";

type Checked<T> = std::result::Result<T, &'static str>;

fn content_hash(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(is_sha256)
}

fn plan_request(plan: &PlanV1) -> Checked<(CallInput, RestoreRequestV1)> {
    if !contract::capability_matches(&plan.capability) || plan.permission_lane != "api_token" {
        return Err("unsupported_restore_plan");
    }
    let mut recomputed = plan.clone();
    recomputed
        .refresh_hash()
        .map_err(|_| "invalid_plan_content")?;
    if recomputed.content_hash != plan.content_hash {
        return Err("plan_content_mismatch");
    }
    let input: CallInput =
        serde_json::from_value(plan.input.clone()).map_err(|_| "invalid_restore_request")?;
    let request: RestoreRequestV1 =
        serde_json::from_value(input.body.clone().ok_or("missing_restore_request")?)
            .map_err(|_| "invalid_restore_request")?;
    request.validate().map_err(|_| "invalid_restore_request")?;
    if input.if_match.is_some()
        || input.if_none_match.is_some()
        || input.query.as_object().is_none_or(|q| !q.is_empty())
    {
        return Err("invalid_restore_request");
    }
    Ok((input, request))
}

/// The caller supplies observation kind explicitly. The existing evidence writer
/// authenticates this binding together with the actual provider readback.
pub(super) fn persist_observation(
    store: &StateStore,
    plan: &mut PlanV1,
    selection: &RestoreSelectionV1,
    source_window: &CaptureWindowV1,
    mut verification: OperationVerificationV1,
    kind: ObservationKind,
) -> Result<ApiVerificationOutcome> {
    let bind = || -> Checked<RestoreBinding> {
        let (input, request) = plan_request(plan)?;
        selection
            .validate(selection.window.opened_at)
            .map_err(|_| "invalid_selection")?;
        source_window
            .validate(source_window.opened_at)
            .map_err(|_| "invalid_source_window")?;
        if request != selection.request
            || plan.account_id != selection.account_id
            || input.selectors
                != json!({"account_id":selection.account_id,"bucket_name":selection.bucket_name})
        {
            return Err("selection_request_mismatch");
        }
        let binding = RestoreBinding {
            schema_version: 1,
            operation_id: plan.operation_id.clone(),
            plan_content_hash: plan.content_hash.clone(),
            request_hash: hash_value(&plan.input).map_err(|_| "invalid_request_hash")?,
            selection_sha256: hash_value(
                &serde_json::to_value(selection).map_err(|_| "invalid_selection")?,
            )
            .map_err(|_| "invalid_selection")?,
            source_capture: request.source_capture,
            source_object_index: request.source_object_index,
            current_capture: request.current_capture,
            expected_current: request.expected_current,
            account_id: selection.account_id.clone(),
            bucket_name: selection.bucket_name.clone(),
            object_key_sha256: selection.object_key_sha256()?,
            source_window: source_window.clone(),
            current_window: selection.window.clone(),
            expected: selection.expected_result()?,
            observation_kind: kind,
        };
        match_binding(plan, &binding)?;
        let (_, observed_at) = observed(&verification, &binding)?;
        let checkpoint = plan
            .transaction_journal
            .last()
            .ok_or("missing_verification_attempt")?;
        if !matches!(
            checkpoint.stage,
            TransactionStageV1::VerificationAttemptPersisted
                | TransactionStageV1::VerificationResponsePersisted
        ) || (checkpoint.stage == TransactionStageV1::VerificationResponsePersisted
            && kind != ObservationKind::ReadOnlyRectification)
            || observed_at < checkpoint.recorded_at
        {
            return Err("invalid_observation_order");
        }
        Ok(binding)
    };
    let binding = bind().map_err(|reason| {
        CliError::Input(format!(
            "private restore observation is unqualified: {reason}"
        ))
    })?;
    verification
        .readback
        .result
        .as_object_mut()
        .ok_or_else(|| CliError::Input("private restore readback is not an object".into()))?
        .insert(BINDING.into(), serde_json::to_value(binding)?);
    api_boundary::verification_outcome(store, plan, verification)
}

fn match_binding(plan: &PlanV1, binding: &RestoreBinding) -> Checked<()> {
    let (input, request) = plan_request(plan)?;
    let target = plan
        .targets
        .pointer(TARGET)
        .ok_or("missing_restore_target")?;
    let window: CaptureWindowV1 =
        serde_json::from_value(target["window"].clone()).map_err(|_| "invalid_current_window")?;
    if binding.schema_version != 1
        || binding.operation_id != plan.operation_id
        || binding.plan_content_hash != plan.content_hash
        || binding.request_hash != hash_value(&plan.input).map_err(|_| "invalid_request_hash")?
        || target["selection_sha256"] != binding.selection_sha256
        || binding.source_capture != request.source_capture
        || binding.source_object_index != request.source_object_index
        || binding.current_capture != request.current_capture
        || binding.expected_current != request.expected_current
        || binding.account_id != plan.account_id
        || input.selectors
            != json!({"account_id":binding.account_id,"bucket_name":binding.bucket_name})
        || binding.current_window != window
        || target["object_key_sha256"] != binding.object_key_sha256
        || target["source_sha256"] != binding.expected.sha256
        || target["source_bytes"].as_u64() != Some(binding.expected.byte_count)
        || target["source_semantic_metadata_sha256"] != binding.expected.semantic_metadata_sha256
        || !is_sha256(&binding.object_key_sha256)
        || !is_sha256(&binding.expected.sha256)
        || !content_hash(&binding.expected.semantic_metadata_sha256)
        || !content_hash(&binding.selection_sha256)
        || binding.expected.byte_count > MAX_BYTES
    {
        return Err("restore_binding_mismatch");
    }
    binding
        .source_window
        .validate(binding.source_window.opened_at)
        .map_err(|_| "invalid_source_window")?;
    binding
        .current_window
        .validate(binding.current_window.opened_at)
        .map_err(|_| "invalid_current_window")?;
    Ok(())
}

fn observed(
    verification: &OperationVerificationV1,
    binding: &RestoreBinding,
) -> Checked<(ObjectResult, DateTime<Utc>)> {
    let readback = &verification.readback;
    let value = &readback.result;
    let result = ObjectResult {
        sha256: value["sha256"]
            .as_str()
            .ok_or("invalid_observed_bytes")?
            .into(),
        byte_count: value["byte_count"]
            .as_u64()
            .ok_or("invalid_observed_bytes")?,
        semantic_metadata_sha256: value["metadata_sha256"]
            .as_str()
            .ok_or("invalid_observed_metadata")?
            .into(),
    };
    let observed_at: DateTime<Utc> = serde_json::from_value(value["observed_at"].clone())
        .map_err(|_| "invalid_observation_time")?;
    if verification.strategy != contract::STRATEGY
        || readback.status != 200
        || !readback.success
        || !readback.errors.is_empty()
        || readback.result_info.is_some()
        || value["schema_version"] != 1
        || value["account_id"] != binding.account_id
        || value["bucket_name"] != binding.bucket_name
        || value["object_key_sha256"] != binding.object_key_sha256
        || value["bytes_and_metadata_match"] != verification.passed
        || !is_sha256(&result.sha256)
        || !content_hash(&result.semantic_metadata_sha256)
        || result.byte_count > MAX_BYTES
        || observed_at > Utc::now()
        || (verification.passed && result != binding.expected)
        || [
            "body_returned",
            "put_replayed",
            "metadata_atomic_precondition",
            "writer_exclusion_qualified",
            "retention_qualified",
            "combined_recovery_ready",
        ]
        .iter()
        .any(|field| value[*field] != false)
        || (binding.observation_kind == ObservationKind::ImmediatePostWrite
            && binding.current_window.validate(observed_at).is_err())
    {
        return Err("restore_readback_mismatch");
    }
    Ok((result, observed_at))
}

fn capture_window(
    store: &StateStore,
    reference: &CaptureRefV1,
    binding: &RestoreBinding,
    source: bool,
    observed_at: DateTime<Utc>,
) -> Checked<()> {
    let (evidence, body) = store
        .load_evidence_value(&reference.evidence_hash)
        .map_err(|_| "capture_evidence_unavailable_or_unauthenticated")?;
    let receipt: CaptureReceiptV1 =
        serde_json::from_value(body["result"].clone()).map_err(|_| "invalid_capture_evidence")?;
    let expected = if source {
        &binding.source_window
    } else {
        &binding.current_window
    };
    if evidence.class != EvidenceClass::LiveRead
        || body["success"] != true
        || body["status"] != 200
        || receipt.schema_version != 1
        || receipt.run_id != reference.run_id
        || receipt.account_id != binding.account_id
        || receipt.bucket_name != binding.bucket_name
        || receipt.window != *expected
        || !receipt.capture_complete
        || receipt.body_returned
        || receipt.recovery_ready
        || !is_sha256(&receipt.manifest_sha256)
        || receipt.list_pages < 2
        || receipt.list_pages > MAX_PAGES
        || receipt.object_count > MAX_OBJECTS
        || receipt.total_bytes > MAX_BYTES
        || receipt.started_at < expected.opened_at
        || receipt.completed_at < receipt.started_at
        || receipt.completed_at >= expected.expires_at
        || receipt.completed_at > observed_at
        || evidence.generated_at < receipt.completed_at
        || evidence.generated_at > observed_at
        || (source && binding.source_object_index >= receipt.object_count)
        || (!source
            && matches!(binding.expected_current, CurrentExpectationV1::Present {object_index} if object_index >= receipt.object_count))
    {
        return Err("capture_window_binding_mismatch");
    }
    Ok(())
}

fn verification_reference(plan: &PlanV1) -> Checked<(&Value, TransactionStageV1, bool)> {
    plan.validate_transaction_journal()
        .map_err(|_| "invalid_transaction_journal")?;
    if !plan
        .transaction_journal
        .iter()
        .any(|c| c.stage == TransactionStageV1::BoundaryAttemptPersisted)
    {
        return Err("missing_consumed_boundary");
    }
    let first = plan
        .transaction_artifact(TransactionStageV1::VerificationResponsePersisted)
        .ok_or("missing_verification_reference")?;
    let closure = plan.transaction_artifact(TransactionStageV1::Closed);
    let (reference, stage, rectified) = if let Some(closure) = closure {
        let reference = closure
            .get("rectification_verification")
            .ok_or("unsupported_closure_reference")?;
        if closure["put_replayed"] != false || closure["historical_put_outcome_proven"] != false {
            return Err("invalid_rectification_closure");
        }
        (reference, TransactionStageV1::Closed, true)
    } else {
        (
            first,
            TransactionStageV1::VerificationResponsePersisted,
            false,
        )
    };
    if !matches!(reference["state"].as_str(), Some("passed" | "failed"))
        || !reference["resource_id"].is_null()
    {
        return Err("invalid_verification_reference");
    }
    Ok((reference, stage, rectified))
}

fn verification_started_at(
    plan: &PlanV1,
    reference: &Value,
    rectified: bool,
) -> Checked<DateTime<Utc>> {
    let attempt = plan
        .transaction_journal
        .iter()
        .find(|c| c.stage == TransactionStageV1::VerificationAttemptPersisted)
        .ok_or("missing_verification_attempt")?;
    let first = plan
        .transaction_artifact(TransactionStageV1::VerificationResponsePersisted)
        .ok_or("missing_verification_reference")?;
    if rectified && first["evidence_hash"] != reference["evidence_hash"] {
        return plan
            .transaction_journal
            .iter()
            .find(|c| c.stage == TransactionStageV1::VerificationResponsePersisted)
            .map(|c| c.recorded_at)
            .ok_or("missing_verification_checkpoint");
    }
    Ok(attempt.recorded_at)
}

fn observation_projection(store: &StateStore, plan: &PlanV1) -> Checked<Value> {
    let (reference, stage, rectified) = verification_reference(plan)?;
    let evidence_hash = reference["evidence_hash"]
        .as_str()
        .ok_or("missing_verification_evidence")?;
    let (evidence, body) = store
        .load_evidence_value(evidence_hash)
        .map_err(|_| "verification_evidence_unavailable_or_unauthenticated")?;
    if evidence.class != EvidenceClass::PostChangeVerification {
        return Err("wrong_verification_evidence_class");
    }
    let verification: OperationVerificationV1 =
        serde_json::from_value(body).map_err(|_| "invalid_verification_body")?;
    let binding: RestoreBinding = serde_json::from_value(
        verification
            .readback
            .result
            .get(BINDING)
            .ok_or("historical_unbound_verification")?
            .clone(),
    )
    .map_err(|_| "invalid_restore_binding")?;
    match_binding(plan, &binding)?;
    let (result, observed_at) = observed(&verification, &binding)?;
    let checkpoint = plan
        .transaction_journal
        .iter()
        .find(|c| c.stage == stage)
        .ok_or("missing_verification_checkpoint")?;
    let expected_state = if verification.passed {
        "passed"
    } else {
        "failed"
    };
    if reference["state"] != expected_state
        || verification.correlated_resource_id.is_some()
        || reference["basis_hash"]
            != hash_value(&json!(verification.basis)).map_err(|_| "invalid_verification_basis")?
        || observed_at < verification_started_at(plan, reference, rectified)?
        || evidence.generated_at < observed_at
        || evidence.generated_at > checkpoint.recorded_at
        || (rectified && binding.observation_kind != ObservationKind::ReadOnlyRectification)
        || (verification.passed
            && !rectified
            && binding.observation_kind != ObservationKind::ImmediatePostWrite)
    {
        return Err("verification_reference_mismatch");
    }
    capture_window(store, &binding.source_capture, &binding, true, observed_at)?;
    capture_window(
        store,
        &binding.current_capture,
        &binding,
        false,
        observed_at,
    )?;
    let mut projection = json!({"qualification":if verification.passed {"authenticated_restore_verification"} else {"unqualified"},
        "qualified":verification.passed,"readback_passed":verification.passed,
        "binding":binding,"expected":binding.expected,"observed":result,"observed_at":observed_at,
        "bytes_match":result.sha256 == binding.expected.sha256 && result.byte_count == binding.expected.byte_count,
        "stored_semantic_metadata_match":result.semantic_metadata_sha256 == binding.expected.semantic_metadata_sha256,
        "evidence":{"content_hash":evidence.content_hash,"class":evidence.class,"generated_at":evidence.generated_at},
        "verification_reference_stage":stage});
    if !verification.passed {
        projection["reason"] = json!("verification_did_not_pass");
    }
    Ok(projection)
}

/// No credentials, private object files, provider reads or journal mutations.
pub(super) fn inspect(
    store: &StateStore,
    plan: &PlanV1,
    projection_drift: bool,
) -> (Value, VerificationState) {
    let result = if projection_drift {
        Err("plan_projection_drift")
    } else {
        observation_projection(store, plan)
    };
    let (mut value, state) = match result {
        Ok(value) => {
            let state = if value["qualified"] == true {
                VerificationState::Passed
            } else {
                VerificationState::Failed
            };
            (value, state)
        }
        Err(reason) => (
            json!({"qualification":"unqualified","qualified":false,"reason":reason}),
            VerificationState::Failed,
        ),
    };
    for (key, value_to_add) in [
        ("schema_version", json!(1)),
        ("operation_id", json!(plan.operation_id)),
        ("plan_content_hash", json!(plan.content_hash)),
        ("request_hash", json!(hash_value(&plan.input).ok())),
        ("body_returned", json!(false)),
        ("provider_requests", json!(0)),
        ("historical_observation", json!(true)),
        ("freshness_qualified", json!(false)),
        ("current_provider_state_qualified", json!(false)),
        ("present_retained_file_custody_qualified", json!(false)),
        ("write_authority_granted", json!(false)),
        ("historical_put_outcome_proven", json!(false)),
        ("metadata_atomic_precondition", json!(false)),
        ("writer_exclusion_qualified", json!(false)),
        ("d1_recovery_qualified", json!(false)),
        ("retention_qualified", json!(false)),
        ("combined_recovery_ready", json!(false)),
    ] {
        value[key] = value_to_add;
    }
    (value, state)
}
