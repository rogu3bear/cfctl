use super::oauth_state::is_oauth_client_create_capability;
use super::oauth_state::is_oauth_client_create_operation_identity;
use super::plan_commands::persist_transaction_stage;
use super::plan_commands::persist_transaction_stage_with_artifact;
use super::plan_commands::reconcile_standing_lineage_from_plan;
use super::plan_secret::delete_plan_secret;
use super::prelude::{
    AuthCredential, CallInput, CapabilityV1, CliError, CloudflareError, CloudflareResponseV1,
    ErrorV1, EvidenceClass, EvidenceV1, Executor, OperationVerificationV1, Path, PathBuf,
    PlanStatus, PlanV1, Result, ResultEnvelopeV2, SecretStore, StateStore, TransactionStageV1,
    Value, VerificationState, json,
};
use super::secret_io::is_secret_output_plan;
use super::secret_io::plan_secret_body_ref;
use super::secret_io::redact_response_for_capability;
use super::secret_io::secret_sink_format;
use super::secret_io::should_redact_secret_response;
use super::secret_io::sink_secret_result;
use super::worker_deployment;
use cfctl_core::{hash_value, redact_json};

pub(super) enum ApiBoundaryResponseOutcome {
    Ready {
        response_value: Value,
        apply_evidence: EvidenceV1,
        lineage_evidence: Option<EvidenceV1>,
    },
    Recovery(ResultEnvelopeV2),
}

/// Persists the non-secret response receipt, always attempts the one-time
/// secret sink, and reconciles lineage only when the boundary receipt was
/// durably saved. Any local failure after a successful response returns a
/// no-replay recovery envelope instead of losing boundary truth through the
/// generic top-level error path.
pub(super) fn process_api_boundary_response(
    store: &StateStore,
    plan: &mut PlanV1,
    response: &CloudflareResponseV1,
    secrets: &dyn SecretStore,
) -> Result<ApiBoundaryResponseOutcome> {
    let response_value =
        redact_response_for_capability(&plan.capability, &serde_json::to_value(response)?);
    let mut failures = Vec::new();
    let apply_evidence =
        match store.write_observation_evidence(EvidenceClass::Apply, &response_value) {
            Ok(evidence) => Some(evidence),
            Err(error) => {
                plan.status = PlanStatus::RectificationRequired;
                failures.push(format!("apply evidence persistence failed: {error}"));
                None
            }
        };
    let boundary_response_persisted = match persist_transaction_stage_with_artifact(
        store,
        plan,
        TransactionStageV1::BoundaryResponsePersisted,
        boundary_response_artifact(plan, response, apply_evidence.as_ref()),
    ) {
        Ok(()) => true,
        Err(error) => {
            plan.status = PlanStatus::RectificationRequired;
            failures.push(format!("boundary response persistence failed: {error}"));
            false
        }
    };
    let lifecycle = persist_secret_lifecycle_and_reconcile_lineage(
        store,
        plan,
        response.success,
        Some(&response.result),
        secrets,
        boundary_response_persisted,
    );
    if let Some(error) = lifecycle.error {
        failures.push(error.to_string());
    }
    if !failures.is_empty() {
        let error = CliError::Input(failures.join("; "));
        let verification_basis = if boundary_response_persisted {
            "the Cloudflare boundary response is durable, but local post-boundary recovery is required before verification can be trusted"
        } else {
            "Cloudflare returned a mutation response, but the boundary receipt is not durably validated; the one-time secret sink was still attempted and the mutation must not be replayed"
        };
        return Ok(ApiBoundaryResponseOutcome::Recovery(
            post_boundary_failure_envelope(
                plan,
                response_value,
                apply_evidence,
                lifecycle.lineage_evidence,
                &error,
                response.success,
                verification_basis,
            ),
        ));
    }
    let Some(apply_evidence) = apply_evidence else {
        return Err(CliError::Input(
            "post-boundary response handling lost its apply evidence without recording a recovery failure"
                .to_owned(),
        ));
    };
    Ok(ApiBoundaryResponseOutcome::Ready {
        response_value,
        apply_evidence,
        lineage_evidence: lifecycle.lineage_evidence,
    })
}

/// A transport error after `BoundaryAttemptPersisted` cannot prove that the
/// remote mutation did not happen. Persist as much local recovery state as
/// possible and return an operation-bound unknown-outcome envelope.
pub(super) fn process_api_transport_failure(
    store: &StateStore,
    plan: &mut PlanV1,
    transport_error: &CliError,
    secrets: &dyn SecretStore,
) -> ResultEnvelopeV2 {
    plan.status = PlanStatus::RectificationRequired;
    let mut failures = vec![format!(
        "Cloudflare mutation outcome is unknown after the request crossed the boundary: {transport_error}"
    )];
    if let Err(error) = persist_transaction_stage_with_artifact(
        store,
        plan,
        TransactionStageV1::BoundaryResponsePersisted,
        boundary_failure_artifact("dynamic_api", "transport_error"),
    ) {
        failures.push(format!(
            "unknown-outcome boundary receipt persistence failed: {error}"
        ));
    }
    if let Err(error) = persist_secret_lifecycle(store, plan, false, None, secrets) {
        failures.push(format!(
            "unknown-outcome secret lifecycle persistence failed: {error}"
        ));
    }
    let error = CliError::Input(failures.join("; "));
    post_boundary_failure_envelope(
        plan,
        json!({
            "success": false,
            "outcome": "unknown",
            "receipt_available": false,
        }),
        None,
        None,
        &error,
        false,
        "the mutation request was sent, but no Cloudflare response was received; the remote outcome is unknown and must be rectified without replay",
    )
}

pub(super) fn api_plan_result_envelope(
    plan: &PlanV1,
    mut result: Value,
    apply_evidence: EvidenceV1,
    lineage_evidence: Option<EvidenceV1>,
    verification: ApiVerificationOutcome,
    performed: bool,
    finalization_error: Option<&CliError>,
) -> ResultEnvelopeV2 {
    if let Some(resource_id) = verification.correlated_resource_id.as_ref()
        && let Some(object) = result.as_object_mut()
    {
        object.insert(
            "cfctl_correlated_resource_id".to_owned(),
            resource_id.clone(),
        );
    }
    if let Some(error) = finalization_error {
        let mut envelope = post_boundary_failure_envelope(
            plan,
            result,
            Some(apply_evidence),
            lineage_evidence,
            error,
            performed,
            "the Cloudflare boundary response is durable, but the final local checkpoint requires recovery",
        );
        envelope.verification.state = verification.state;
        envelope.verification.basis = Some(format!(
            "{}; the final plan checkpoint could not be persisted",
            verification.basis
        ));
        if let Some(evidence) = verification.evidence {
            envelope.evidence.push(evidence);
        }
        return envelope;
    }
    let mut envelope = ResultEnvelopeV2::success("plans run", result).with_evidence(apply_evidence);
    if let Some(evidence) = lineage_evidence {
        envelope.evidence.push(evidence);
    }
    if let Some(evidence) = verification.evidence {
        envelope.evidence.push(evidence);
    }
    envelope.ok = performed && plan.status == PlanStatus::Verified;
    envelope.performed = performed;
    envelope.operation_id = Some(plan.operation_id.clone());
    envelope.capability_id = Some(plan.capability.id.clone());
    envelope.profile_id = Some(plan.profile_id.clone());
    envelope.account_id = Some(plan.account_id.clone());
    envelope.policy_decision = Some(plan.policy.clone());
    envelope.verification.state = verification.state;
    envelope.verification.basis = Some(verification.basis);
    envelope.error = verification.error;
    envelope
}

pub(super) struct ApiVerificationOutcome {
    pub(super) state: VerificationState,
    pub(super) basis: String,
    pub(super) evidence: Option<EvidenceV1>,
    pub(super) error: Option<ErrorV1>,
    pub(super) correlated_resource_id: Option<Value>,
}

pub(super) fn blocked_capability_envelope(
    command: &str,
    capability: &cfctl_core::CapabilityV1,
    reason: &str,
) -> ResultEnvelopeV2 {
    let next_step = format!(
        "Run `cfctl guide {} --json` and follow next_action; never bypass the blocker.",
        capability.id
    );
    let mut envelope = ResultEnvelopeV2::failure(
        command,
        "CFCTL_CAPABILITY_BLOCKED",
        &format!("capability is blocked: {reason}"),
        Some(&next_step),
    );
    envelope.capability_id = Some(capability.id.clone());
    envelope.result = json!({ "blocking_gaps": capability.mutation_contract_gaps() });
    envelope
}

pub(super) fn post_boundary_failure_envelope(
    plan: &PlanV1,
    result: Value,
    apply_evidence: Option<EvidenceV1>,
    lineage_evidence: Option<EvidenceV1>,
    error: &CliError,
    performed: bool,
    verification_basis: &str,
) -> ResultEnvelopeV2 {
    let next_step = format!(
        "Do not replay the mutation; run `cfctl plans rectify {}`.",
        plan.operation_id
    );
    let mut envelope = ResultEnvelopeV2::failure(
        "plans run",
        "CFCTL_POST_BOUNDARY_RECOVERY_REQUIRED",
        &error.to_string(),
        Some(&next_step),
    );
    envelope.result = redact_json(&result);
    envelope.performed = performed;
    envelope.operation_id = Some(plan.operation_id.clone());
    envelope.capability_id = Some(plan.capability.id.clone());
    envelope.profile_id = Some(plan.profile_id.clone());
    envelope.account_id = Some(plan.account_id.clone());
    envelope.policy_decision = Some(plan.policy.clone());
    envelope.verification.state = VerificationState::Pending;
    envelope.verification.basis = Some(verification_basis.to_owned());
    if let Some(evidence) = apply_evidence {
        envelope.evidence.push(evidence);
    }
    if let Some(evidence) = lineage_evidence {
        envelope.evidence.push(evidence);
    }
    envelope
}

pub(super) fn boundary_response_artifact(
    plan: &PlanV1,
    response: &CloudflareResponseV1,
    apply_evidence: Option<&EvidenceV1>,
) -> Value {
    let nested_resource_id = plan
        .capability
        .created_nested_resource
        .as_ref()
        .and_then(|target| {
            let correlation = plan
                .input
                .pointer(&format!("/body/{}", target.correlation_field))
                .and_then(Value::as_str)?;
            let items = response
                .result
                .pointer(&target.items_pointer)
                .and_then(Value::as_array)?;
            let matching = items
                .iter()
                .filter(|item| {
                    item.get(&target.correlation_field).and_then(Value::as_str) == Some(correlation)
                })
                .collect::<Vec<_>>();
            (matching.len() == 1)
                .then(|| {
                    matching[0]
                        .pointer(&target.response_item_identity_pointer)
                        .filter(|identity| {
                            identity.as_str().is_some_and(|value| !value.is_empty())
                                || identity.as_u64().is_some()
                                || identity.as_i64().is_some()
                        })
                        .cloned()
                })
                .flatten()
        });
    let identity_pointer = plan
        .capability
        .created_resource
        .as_ref()
        .map(|target| target.response_result_identity_pointer.as_str())
        .or_else(|| {
            plan.capability
                .created_collection_resource
                .as_ref()
                .map(|target| target.response_result_identity_pointer.as_str())
        })
        .unwrap_or("/id");
    // Fail closed: never lift a secret field into the journal's `resource_id`.
    // The core contract gate already refuses a secret-named identity pointer, so
    // this is belt-and-suspenders against a pointer that slipped through.
    let resource_id = if nested_resource_id.is_some() {
        nested_resource_id
    } else if cfctl_core::pointer_names_secret_field(identity_pointer) {
        None
    } else {
        response
            .result
            .pointer(identity_pointer)
            .filter(|identity| {
                identity.as_str().is_some_and(|value| !value.is_empty())
                    || identity.as_u64().is_some()
                    || identity.as_i64().is_some()
            })
            .cloned()
    };
    json!({
        "apply_evidence_hash": apply_evidence.map(|evidence| evidence.content_hash.as_str()),
        "http_status": response.status,
        "success": response.success,
        "resource_id": resource_id,
        "resource_status": response.result.get("status").and_then(Value::as_str),
        "etag": response.etag,
        "cf_ray": response.cf_ray,
    })
}

pub(super) fn boundary_failure_artifact(adapter: &str, outcome: &str) -> Value {
    json!({
        "adapter": adapter,
        "outcome": outcome,
        "receipt_available": false,
        "success": false,
    })
}

pub(super) fn oauth_client_secret_output_state(
    plan: &PlanV1,
    response_success: bool,
    response_result: Option<&Value>,
) -> Result<(bool, Option<bool>)> {
    if !is_oauth_client_create_operation_identity(&plan.capability) {
        return Ok((response_success && is_secret_output_plan(plan), None));
    }
    if !is_oauth_client_create_capability(&plan.capability) {
        return Err(CliError::Input(
            "OAuth client creation drifted from its governed identity, entitlement, verification, or secret-output contract"
                .to_owned(),
        ));
    }
    if !response_success {
        return Ok((false, None));
    }
    let result = response_result.ok_or_else(|| {
        CliError::Input(
            "Cloudflare reported OAuth client creation success without a response result"
                .to_owned(),
        )
    })?;
    let secret_returned = match result.get("client_secret") {
        None | Some(Value::Null) => false,
        Some(Value::String(secret)) if !secret.is_empty() => true,
        Some(_) => {
            return Err(CliError::Input(
                "Cloudflare returned a malformed OAuth client_secret; the operation requires rectification"
                    .to_owned(),
            ));
        }
    };
    let auth_method = plan
        .input
        .pointer("/body/token_endpoint_auth_method")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "OAuth client creation plan omitted token_endpoint_auth_method".to_owned(),
            )
        })?;
    let output_required = match auth_method {
        "none" => secret_returned,
        "client_secret_basic" | "client_secret_post" => true,
        _ => {
            return Err(CliError::Input(
                "OAuth client creation plan contains an unsupported token authentication method"
                    .to_owned(),
            ));
        }
    };
    Ok((output_required, Some(secret_returned)))
}

pub(super) fn secret_sink_artifact(
    plan: &PlanV1,
    path: Option<&Path>,
    input_cleanup_required: bool,
    input_cleanup_completed: bool,
    output_required: bool,
    secret_returned: Option<bool>,
    failure: Option<&str>,
) -> Value {
    let output_completed = !output_required || path.is_some();
    let mut artifact = json!({
        "completed": input_cleanup_completed && output_completed && failure.is_none(),
        "failure": failure,
        "input_cleanup": {
            "required": input_cleanup_required,
            "completed": input_cleanup_completed,
        },
        "output_sink": {
            "required": output_required,
            "completed": output_completed,
            "create_new": output_required,
            "format": secret_sink_format(&plan.capability),
            "unix_mode": cfg!(unix).then_some("0600"),
        },
        "path": path.map(|path| path.display().to_string()),
    });
    if is_oauth_client_create_operation_identity(&plan.capability) {
        artifact["secret_returned"] = secret_returned.map_or(Value::Null, Value::Bool);
        artifact["output_sink"]["requested"] = Value::Bool(is_secret_output_plan(plan));
        artifact["path"] = Value::Null;
    }
    artifact
}

/// Persists the secret-sink outcome and then reconciles token lineage from the
/// already-durable boundary receipt regardless of whether the sink succeeded.
/// A post-boundary error always directs the operator to rectification; replay
/// is never an acceptable recovery path.
pub(super) struct PostBoundaryLifecycleOutcome {
    pub(super) lineage_evidence: Option<EvidenceV1>,
    pub(super) error: Option<CliError>,
}

pub(super) fn persist_secret_lifecycle_and_reconcile_lineage(
    store: &StateStore,
    plan: &mut PlanV1,
    response_success: bool,
    response_result: Option<&Value>,
    secrets: &dyn SecretStore,
    boundary_response_durable: bool,
) -> PostBoundaryLifecycleOutcome {
    let secret_sink_result =
        persist_secret_lifecycle(store, plan, response_success, response_result, secrets);
    let lineage_result = if boundary_response_durable {
        reconcile_standing_lineage_from_plan(store, plan)
    } else {
        Ok(None)
    };
    match (secret_sink_result, lineage_result) {
        (Ok(_sink_path), Ok(lineage_evidence)) => PostBoundaryLifecycleOutcome {
            lineage_evidence,
            error: None,
        },
        (Err(sink_error), Ok(lineage_evidence)) => PostBoundaryLifecycleOutcome {
            lineage_evidence,
            error: Some(CliError::Input(format!(
                "the Cloudflare boundary response was persisted, but the secret sink failed: {sink_error}. Do not replay the mutation; run `cfctl plans rectify {}`",
                plan.operation_id
            ))),
        },
        (Ok(_), Err(lineage_error)) => PostBoundaryLifecycleOutcome {
            lineage_evidence: None,
            error: Some(CliError::Input(format!(
                "the Cloudflare boundary response was persisted, but standing token lineage reconciliation failed: {lineage_error}. Do not replay the mutation; run `cfctl plans rectify {}`",
                plan.operation_id
            ))),
        },
        (Err(sink_error), Err(lineage_error)) => PostBoundaryLifecycleOutcome {
            lineage_evidence: None,
            error: Some(CliError::Input(format!(
                "the Cloudflare boundary response was persisted, but both the secret sink and standing token lineage reconciliation failed (sink: {sink_error}; lineage: {lineage_error}). Do not replay the mutation; run `cfctl plans rectify {}`",
                plan.operation_id
            ))),
        },
    }
}

pub(super) fn persist_secret_lifecycle(
    store: &StateStore,
    plan: &mut PlanV1,
    response_success: bool,
    response_result: Option<&Value>,
    secrets: &dyn SecretStore,
) -> Result<Option<PathBuf>> {
    let input_cleanup_required = plan_secret_body_ref(plan).is_some();
    let (output_required, secret_returned) = initialize_secret_output_state(
        store,
        plan,
        response_success,
        response_result,
        input_cleanup_required,
    )?;
    let input_cleanup_completed = match delete_plan_secret(plan, secrets) {
        Ok(deleted) => !input_cleanup_required || deleted,
        Err(error) => {
            plan.status = PlanStatus::RectificationRequired;
            persist_transaction_stage_with_artifact(
                store,
                plan,
                TransactionStageV1::SecretSinkPersisted,
                secret_sink_artifact(
                    plan,
                    None,
                    input_cleanup_required,
                    false,
                    output_required,
                    secret_returned,
                    Some("input_cleanup_failed"),
                ),
            )?;
            return Err(error);
        }
    };
    let sink_path = if output_required {
        let Some(result) = response_result else {
            plan.status = PlanStatus::RectificationRequired;
            persist_transaction_stage_with_artifact(
                store,
                plan,
                TransactionStageV1::SecretSinkPersisted,
                secret_sink_artifact(
                    plan,
                    None,
                    input_cleanup_required,
                    input_cleanup_completed,
                    output_required,
                    secret_returned,
                    Some("output_missing"),
                ),
            )?;
            return Err(CliError::Input(
                "the adapter reported success without returning the required sink-only value; do not replay the mutation"
                    .to_owned(),
            ));
        };
        match sink_secret_result(plan, result) {
            Ok(path) => Some(path),
            Err(error) => {
                plan.status = PlanStatus::RectificationRequired;
                persist_transaction_stage_with_artifact(
                    store,
                    plan,
                    TransactionStageV1::SecretSinkPersisted,
                    secret_sink_artifact(
                        plan,
                        None,
                        input_cleanup_required,
                        input_cleanup_completed,
                        output_required,
                        secret_returned,
                        Some("output_sink_failed"),
                    ),
                )?;
                return Err(error);
            }
        }
    } else {
        None
    };
    persist_transaction_stage_with_artifact(
        store,
        plan,
        TransactionStageV1::SecretSinkPersisted,
        secret_sink_artifact(
            plan,
            sink_path.as_deref(),
            input_cleanup_required,
            input_cleanup_completed,
            output_required,
            secret_returned,
            None,
        ),
    )?;
    Ok(sink_path)
}

pub(super) fn initialize_secret_output_state(
    store: &StateStore,
    plan: &mut PlanV1,
    response_success: bool,
    response_result: Option<&Value>,
    input_cleanup_required: bool,
) -> Result<(bool, Option<bool>)> {
    match oauth_client_secret_output_state(plan, response_success, response_result) {
        Ok(state) => Ok(state),
        Err(error) => {
            plan.status = PlanStatus::RectificationRequired;
            persist_transaction_stage_with_artifact(
                store,
                plan,
                TransactionStageV1::SecretSinkPersisted,
                secret_sink_artifact(
                    plan,
                    None,
                    input_cleanup_required,
                    !input_cleanup_required,
                    response_success && is_secret_output_plan(plan),
                    None,
                    Some("output_contract_invalid"),
                ),
            )?;
            Err(error)
        }
    }
}

pub(super) fn verification_response_artifact(outcome: &ApiVerificationOutcome) -> Result<Value> {
    Ok(json!({
        "state": outcome.state.as_str(),
        "basis_hash": hash_value(&json!(outcome.basis))?,
        "evidence_hash": outcome.evidence.as_ref().map(|evidence| evidence.content_hash.as_str()),
        "resource_id":outcome.correlated_resource_id,
    }))
}

pub(super) async fn verify_api_plan(
    store: &StateStore,
    executor: &Executor,
    plan: &mut PlanV1,
    response: &CloudflareResponseV1,
    execution_input: &CallInput,
    credential: &AuthCredential,
) -> Result<ApiVerificationOutcome> {
    if !response.success {
        if plan.capability.id == worker_deployment::ROLLBACK_CAPABILITY_ID
            && (response.status == 429 || response.status >= 500)
        {
            plan.status = PlanStatus::RectificationRequired;
            persist_transaction_stage(
                store,
                plan,
                TransactionStageV1::VerificationAttemptPersisted,
            )?;
            let outcome = ApiVerificationOutcome {
                state: VerificationState::Pending,
                basis: format!(
                    "Cloudflare returned HTTP {} after the one permitted rollback POST; the remote outcome is ambiguous and must be reconciled by GET without replay",
                    response.status
                ),
                evidence: None,
                error: Some(ErrorV1 {
                    code: "CFCTL_ROLLBACK_OUTCOME_AMBIGUOUS".to_owned(),
                    message: "The Worker rollback response does not prove whether the deployment was committed"
                        .to_owned(),
                    next_step: Some(format!(
                        "Keep the deployment lane frozen and run `cfctl plans rectify {}`; never replay the POST.",
                        plan.operation_id
                    )),
                }),
                correlated_resource_id: None,
            };
            persist_transaction_stage_with_artifact(
                store,
                plan,
                TransactionStageV1::VerificationResponsePersisted,
                verification_response_artifact(&outcome)?,
            )?;
            return Ok(outcome);
        }
        plan.status = PlanStatus::Failed;
        return Ok(ApiVerificationOutcome {
            state: VerificationState::NotApplicable,
            basis: "Cloudflare rejected the mutation before verification".to_owned(),
            evidence: None,
            error: None,
            correlated_resource_id: None,
        });
    }
    persist_transaction_stage(
        store,
        plan,
        TransactionStageV1::VerificationAttemptPersisted,
    )?;
    if !plan.capability.verification.required {
        plan.status = PlanStatus::Verified;
        let outcome = ApiVerificationOutcome {
            state: VerificationState::Passed,
            basis: non_readback_verification_basis(&plan.capability),
            evidence: None,
            error: None,
            correlated_resource_id: None,
        };
        persist_transaction_stage_with_artifact(
            store,
            plan,
            TransactionStageV1::VerificationResponsePersisted,
            verification_response_artifact(&outcome)?,
        )?;
        return Ok(outcome);
    }
    let outcome = match executor
        .verify_plan_with_input(plan, response, execution_input, credential)
        .await
    {
        Ok(verification) => verification_outcome(store, plan, verification)?,
        Err(error) => verification_error_outcome(store, plan, &error)?,
    };
    persist_transaction_stage_with_artifact(
        store,
        plan,
        TransactionStageV1::VerificationResponsePersisted,
        verification_response_artifact(&outcome)?,
    )?;
    Ok(outcome)
}

pub(super) fn non_readback_verification_basis(capability: &CapabilityV1) -> String {
    if capability.verification.strategy == "sink_write_and_source_response_status" {
        "Cloudflare returned success and the required sink-only secret output was durably persisted"
            .to_owned()
    } else {
        "operation declares no post-change verifier".to_owned()
    }
}

pub(super) fn verification_outcome(
    store: &StateStore,
    plan: &mut PlanV1,
    verification: OperationVerificationV1,
) -> Result<ApiVerificationOutcome> {
    let state = if verification.passed {
        VerificationState::Passed
    } else {
        VerificationState::Failed
    };
    plan.status = if verification.passed {
        PlanStatus::Verified
    } else {
        PlanStatus::RectificationRequired
    };
    // Defense in depth: the verifier readback is the full Cloudflare response,
    // which for a secret-sensitive capability can carry secret material. Apply
    // the same secret-aware redaction the Apply receipt gets before this reaches
    // evidence — the storage-layer `redact_json` alone misses camelCase/bare
    // secret fields (e.g. `secretAccessKey`, `sessionToken`, `value`).
    let mut verification_value = serde_json::to_value(&verification)?;
    if should_redact_secret_response(&plan.capability)
        && let Some(readback) = verification_value.get("readback")
    {
        let redacted = redact_response_for_capability(&plan.capability, readback);
        if let Some(object) = verification_value.as_object_mut() {
            object.insert("readback".to_owned(), redacted);
        }
    }
    let evidence =
        Some(store.write_observation_evidence(
            EvidenceClass::PostChangeVerification,
            &verification_value,
        )?);
    let error = (!verification.passed).then(|| ErrorV1 {
        code: "CFCTL_VERIFICATION_FAILED".to_owned(),
        message: verification.basis.clone(),
        next_step: Some(format!(
            "Inspect live state with `cfctl plans rectify {}` before any compensation.",
            plan.operation_id
        )),
    });
    Ok(ApiVerificationOutcome {
        state,
        basis: verification.basis,
        evidence,
        error,
        correlated_resource_id: verification.correlated_resource_id,
    })
}

pub(super) fn verification_error_outcome(
    store: &StateStore,
    plan: &mut PlanV1,
    verification_error: &CloudflareError,
) -> Result<ApiVerificationOutcome> {
    let basis = format!("operation-specific verifier failed: {verification_error}");
    plan.status = PlanStatus::RectificationRequired;
    let evidence = Some(store.write_observation_evidence(
        EvidenceClass::PostChangeVerification,
        &json!({
            "strategy": plan.capability.verification.strategy,
            "passed": false,
            "error": verification_error.to_string(),
        }),
    )?);
    Ok(ApiVerificationOutcome {
        state: VerificationState::Failed,
        basis: basis.clone(),
        evidence,
        error: Some(ErrorV1 {
            code: "CFCTL_VERIFICATION_ERROR".to_owned(),
            message: basis,
            next_step: Some(format!(
                "Do not replay the mutation; run `cfctl plans rectify {}`.",
                plan.operation_id
            )),
        }),
        correlated_resource_id: None,
    })
}
