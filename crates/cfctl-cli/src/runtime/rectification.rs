use super::api_boundary::secret_sink_artifact;
use super::cloudflare_api::BASE_URL as API_BASE_URL;
use super::compensation::bind_required_empty_compensation_body;
use super::compensation::compensation_request;
use super::credential_resolution::ensure_catalog;
use super::credential_resolution::fresh_credential;
use super::credential_resolution::platform_secrets;
use super::import_failures::exact_durable_init_response_failure;
use super::import_lineage::exact_durable_provider_complete_boundary;
use super::import_planning::SECURITY_ACTION_STATE_PRECONDITION;
use super::plan_commands::persist_transaction_stage;
use super::plan_commands::persist_transaction_stage_with_artifact;
use super::plan_commands::reconcile_standing_lineage_from_plan;
use super::plan_commands::{ensure_plan_execution_contract, load_validated_plan};
use super::plan_create::create_plan;
use super::plan_create::exact_worker_deployment_read_capability;
use super::plan_secret::D1_READ_REPLICATION_PRECONDITION;
use super::plan_secret::DNS_RECORD_STATE_PRECONDITION;
use super::prelude::{
    CallInput, CliError, CloudflareResponseV1, ErrorV1, EvidenceClass, Executor,
    OperationVerificationV1, PlanSelector, PlanStatus, PlanV1, ProfilesConfig, Result,
    ResultEnvelopeV2, StateStore, TransactionStageV1, Value, VerificationState, json,
};
use super::support::capability_missing;
use super::support::http_client;
use super::{
    r2_private_upload, worker_deployment, workspace_d1_migration, workspace_d1_projection,
};
use cfctl_cloudflare::{
    project_worker_version_rollback_readback, worker_version_rollback_annotation,
};
use cfctl_core::hash_value;

#[expect(
    clippy::too_many_lines,
    reason = "rectification must keep transaction-journal, boundary, verification, compensation, and terminal-state decisions visible as one recovery state machine"
)]
pub(super) async fn rectify_plan(
    store: &StateStore,
    selector: &PlanSelector,
) -> Result<ResultEnvelopeV2> {
    let _plan_lock = store.lock_plan(&selector.operation_id)?;
    let mut plan = load_validated_plan(store, &selector.operation_id)?;
    ensure_plan_execution_contract(store, &plan)?;
    if plan.capability.d1_approved_mln_import.is_some() {
        return rectify_approved_mln_import(store, &mut plan);
    }
    if r2_private_upload_rectification_eligible(&plan) {
        return rectify_r2_private_upload(store, &mut plan).await;
    }
    if email_routing_subdomain_dns_rectification_eligible(&plan) {
        return rectify_email_routing_subdomain_dns(store, &mut plan).await;
    }
    if worker_version_rollback_rectification_eligible(&plan) {
        return rectify_worker_version_rollback(store, &mut plan).await;
    }
    if workspace_d1_migration_rectification_eligible(&plan) {
        return rectify_workspace_d1_migration(store, &mut plan).await;
    }
    if workspace_d1_projection_rectification_eligible(&plan) {
        return rectify_workspace_d1_projection(store, &mut plan).await;
    }
    let lineage_evidence = reconcile_standing_lineage_from_plan(store, &plan)?;
    if let Some(mut request) = compensation_request(&plan)? {
        let catalog = ensure_catalog(store).await?;
        let capability = catalog
            .get(&request.capability_id)
            .cloned()
            .ok_or_else(|| capability_missing(&request.capability_id))?;
        if capability.method != request.expected_method || capability.path != request.expected_path
        {
            return Err(CliError::Input(format!(
                "compensation target `{}` no longer resolves to the hash-bound {} path; inspect live resource state before creating a replacement plan",
                request.capability_id, request.expected_method
            )));
        }
        bind_required_empty_compensation_body(&mut request, &capability);
        let source_receipt_hash = plan
            .transaction_journal
            .iter()
            .find(|checkpoint| checkpoint.stage == TransactionStageV1::BoundaryResponsePersisted)
            .and_then(|checkpoint| checkpoint.artifact_hash.as_deref());
        let mut compensation_targets = request
            .adapter_targets
            .as_object()
            .cloned()
            .unwrap_or_default();
        compensation_targets.insert(
            "compensates_operation_id".to_owned(),
            Value::String(plan.operation_id.clone()),
        );
        compensation_targets.insert(
            "compensates_capability_id".to_owned(),
            Value::String(plan.capability.id.clone()),
        );
        compensation_targets.insert(
            "compensation_strategy".to_owned(),
            serde_json::to_value(&plan.capability.rollback.strategy)?,
        );
        compensation_targets.insert(
            "source_receipt_hash".to_owned(),
            serde_json::to_value(source_receipt_hash)?,
        );
        compensation_targets.insert(
            "source_precondition_hash".to_owned(),
            serde_json::to_value(
                plan.precondition_hashes
                    .get("global_warp_override_state")
                    .or_else(|| {
                        plan.precondition_hashes
                            .get(D1_READ_REPLICATION_PRECONDITION)
                    })
                    .or_else(|| plan.precondition_hashes.get(DNS_RECORD_STATE_PRECONDITION))
                    .or_else(|| {
                        plan.precondition_hashes
                            .get(SECURITY_ACTION_STATE_PRECONDITION)
                    }),
            )?,
        );
        let mut envelope = Box::pin(create_plan(
            store,
            &catalog,
            capability,
            request.input,
            Some(&plan.profile_id),
            request.requested_account.as_deref(),
            Value::Object(compensation_targets),
        ))
        .await?;
        "plans rectify".clone_into(&mut envelope.command);
        if let Some(result) = envelope.result.as_object_mut() {
            result.insert(
                "compensates_operation_id".to_owned(),
                Value::String(plan.operation_id.clone()),
            );
            result.insert(
                "message".to_owned(),
                Value::String(
                    "A separate hash-bound compensation plan was created from the source plan receipts. It has not run; review and explicitly approve its operation ID."
                        .to_owned(),
                ),
            );
        }
        if let Some(evidence) = lineage_evidence {
            envelope.evidence.push(evidence);
        }
        return Ok(envelope);
    }
    let mut envelope = ResultEnvelopeV2::success(
        "plans rectify",
        json!({
            "operation_id": plan.operation_id,
            "status": plan.status,
            "compensation_steps": plan.compensation_steps,
            "verification_steps": plan.verification_steps,
            "non_reversible_warnings": plan.non_reversible_warnings,
            "message": "No safe automatic compensation plan can be derived from the hash-bound receipts for this capability. Inspect live state with the catalog, then create a new hash-bound plan."
        }),
    );
    if let Some(evidence) = lineage_evidence {
        envelope.evidence.push(evidence);
    }
    Ok(envelope)
}

pub(super) fn workspace_d1_migration_rectification_eligible(plan: &PlanV1) -> bool {
    plan.capability.workspace_d1_migration.is_some()
        && plan.status == PlanStatus::RectificationRequired
        && matches!(
            plan.transaction_stage,
            TransactionStageV1::BoundaryResponsePersisted
                | TransactionStageV1::SecretSinkPersisted
                | TransactionStageV1::VerificationAttemptPersisted
                | TransactionStageV1::VerificationResponsePersisted
        )
        && plan.transaction_journal.iter().any(|checkpoint| {
            checkpoint.stage == TransactionStageV1::BoundaryResponsePersisted
                && checkpoint.artifact_hash.is_some()
        })
}

pub(super) fn worker_version_rollback_rectification_eligible(plan: &PlanV1) -> bool {
    plan.capability.id == worker_deployment::ROLLBACK_CAPABILITY_ID
        && plan.status == PlanStatus::RectificationRequired
        && plan
            .transaction_journal
            .iter()
            .any(|checkpoint| checkpoint.stage == TransactionStageV1::BoundaryAttemptPersisted)
}

pub(super) async fn rectify_worker_version_rollback(
    store: &StateStore,
    plan: &mut PlanV1,
) -> Result<ResultEnvelopeV2> {
    let secrets = platform_secrets(store);
    let profiles = ProfilesConfig::load(store)?;
    let profile = profiles.selected(Some(&plan.profile_id))?;
    if profile.account_id.as_deref() != Some(plan.account_id.as_str()) {
        return Err(CliError::Input(
            "Worker rollback rectification profile no longer belongs to the plan account"
                .to_owned(),
        ));
    }
    let input: CallInput = serde_json::from_value(plan.input.clone())?;
    let script_name = input
        .selectors
        .get("script_name")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input("Worker rollback rectification omitted script_name".to_owned())
        })?;
    if input.selectors.get("account_id").and_then(Value::as_str) != Some(plan.account_id.as_str()) {
        return Err(CliError::Input(
            "Worker rollback rectification account selector drifted".to_owned(),
        ));
    }
    let target_version_id = input
        .body
        .as_ref()
        .and_then(|body| body.get("target_version_id"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input("Worker rollback rectification target version is missing".to_owned())
        })?;
    let reason = input
        .body
        .as_ref()
        .and_then(|body| body.get("message"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input("Worker rollback rectification reason is missing".to_owned())
        })?;
    let annotation = worker_version_rollback_annotation(reason, &plan.operation_id)?;
    let _worker_deployment_lock = store
        .lock_worker_deployment(&plan.account_id, script_name)
        .map_err(CliError::Storage)?;
    let catalog = ensure_catalog(store).await?;
    let read = exact_worker_deployment_read_capability(
        &catalog,
        worker_deployment::DEPLOYMENTS_CAPABILITY_ID,
        worker_deployment::DEPLOYMENTS_PATH,
    )?;
    let credential = fresh_credential(profile, &secrets).await?;
    let read_input = CallInput {
        selectors: json!({
            "account_id":plan.account_id,
            "script_name":script_name,
        }),
        query: json!({}),
        body: None,
        ..CallInput::default()
    };
    let readback = Executor::new(http_client()?, API_BASE_URL)?
        .execute_read(read, &read_input, &credential)
        .await?;
    persist_worker_version_rollback_rectification(
        store,
        plan,
        target_version_id,
        &annotation,
        &readback,
    )
}

/// Applies one already-completed GET-only rollback readback to the durable
/// plan. Kept separate from transport so tests can prove closure and retained
/// evidence without constructing any mutation-capable client.
pub(super) fn persist_worker_version_rollback_rectification(
    store: &StateStore,
    plan: &mut PlanV1,
    target_version_id: &str,
    annotation: &str,
    readback: &CloudflareResponseV1,
) -> Result<ResultEnvelopeV2> {
    let (passed, latest_deployment_id, projected) =
        project_worker_version_rollback_readback(target_version_id, annotation, readback)?;
    let basis = if passed {
        "the GET-only deployment read found exactly one operation marker on the current deployment with the exact target at 100 percent"
    } else {
        "the GET-only deployment read did not prove this operation marker on the current exact target; the POST was not replayed"
    };
    let verification = json!({
        "strategy":"worker_version_rollback_get_only_rectification",
        "passed":passed,
        "basis":basis,
        "latest_deployment_id":latest_deployment_id,
        "readback":projected,
        "verification_only":true,
        "boundary_replayed":false,
    });
    let evidence = store.write_evidence(EvidenceClass::PostChangeVerification, &verification)?;
    if passed {
        plan.status = PlanStatus::Verified;
        persist_transaction_stage_with_artifact(
            store,
            plan,
            TransactionStageV1::Closed,
            json!({
                "rectification_verification_hash":evidence.content_hash,
                "retry":false,
                "boundary_replayed":false,
            }),
        )?;
    } else {
        plan.status = PlanStatus::RectificationRequired;
        store.save_plan(plan)?;
    }
    let mut envelope = ResultEnvelopeV2::success(
        "plans rectify",
        json!({
            "operation_id":plan.operation_id,
            "status":plan.status,
            "verification_only":true,
            "boundary_replayed":false,
            "message":basis,
        }),
    )
    .with_evidence(evidence);
    envelope.ok = passed;
    envelope.performed = false;
    envelope.operation_id = Some(plan.operation_id.clone());
    envelope.capability_id = Some(plan.capability.id.clone());
    envelope.profile_id = Some(plan.profile_id.clone());
    envelope.account_id = Some(plan.account_id.clone());
    envelope.verification.state = if passed {
        VerificationState::Passed
    } else {
        VerificationState::Failed
    };
    envelope.verification.basis = Some(basis.to_owned());
    if !passed {
        envelope.error = Some(ErrorV1 {
            code: "CFCTL_VERIFICATION_FAILED".to_owned(),
            message: basis.to_owned(),
            next_step: Some(
                "Keep the Worker deployment lane frozen, inspect the projected readback, and create a new reviewed plan only after current authority is rebound."
                    .to_owned(),
            ),
        });
    }
    Ok(envelope)
}

pub(super) fn r2_private_upload_rectification_eligible(plan: &PlanV1) -> bool {
    let boundary = plan.transaction_artifact(TransactionStageV1::BoundaryResponsePersisted);
    plan.capability.r2_private_file_upload.is_some()
        && plan.status == PlanStatus::RectificationRequired
        && plan.transaction_stage == TransactionStageV1::VerificationResponsePersisted
        && boundary.is_some_and(|receipt| {
            receipt.get("http_status").and_then(Value::as_u64) == Some(200)
                && receipt.get("success").and_then(Value::as_bool) == Some(true)
                && receipt.get("etag").is_none_or(Value::is_null)
        })
}

pub(super) fn r2_private_upload_digest_matches(
    plan: &PlanV1,
    response: &CloudflareResponseV1,
) -> Result<bool> {
    let target = plan
        .targets
        .pointer("/adapter/r2_private_file_upload")
        .ok_or_else(|| CliError::Input("private R2 upload target is missing".to_owned()))?;
    let source_sha256 = target
        .get("source_sha256")
        .and_then(Value::as_str)
        .filter(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or_else(|| CliError::Input("private R2 upload source digest is invalid".to_owned()))?;
    let source_bytes = target
        .get("source_bytes")
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .ok_or_else(|| CliError::Input("private R2 upload source size is invalid".to_owned()))?;
    let input: CallInput = serde_json::from_value(plan.input.clone())?;
    let selector = |name: &str| {
        input
            .selectors
            .get(name)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                CliError::Input(format!(
                    "private R2 upload rectification selector `{name}` is missing"
                ))
            })
    };
    let result = response
        .result
        .as_object()
        .ok_or_else(|| CliError::Input("private R2 digest readback is not an object".to_owned()))?;
    Ok(response.status == 200
        && response.success
        && response.errors.is_empty()
        && result.len() == 8
        && result.get("schema_version").and_then(Value::as_u64) == Some(1)
        && result.get("account_id").and_then(Value::as_str) == Some(selector("account_id")?)
        && result.get("bucket_name").and_then(Value::as_str) == Some(selector("bucket_name")?)
        && result.get("object_key").and_then(Value::as_str) == Some(selector("object_key")?)
        && result.get("byte_count").and_then(Value::as_u64) == Some(source_bytes)
        && result.get("sha256").and_then(Value::as_str)
            == Some(format!("sha256:{source_sha256}").as_str())
        && result
            .get("etag")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty())
        && result.get("body_returned").and_then(Value::as_bool) == Some(false))
}

#[expect(
    clippy::too_many_lines,
    reason = "private R2 rectification keeps exact staged authority, digest-only provider readback, no-replay evidence, and closure in one auditable state machine"
)]
pub(super) async fn rectify_r2_private_upload(
    store: &StateStore,
    plan: &mut PlanV1,
) -> Result<ResultEnvelopeV2> {
    let secrets = platform_secrets(store);
    let target = r2_private_upload::rectification_target(store, plan, &secrets)?;
    let profiles = ProfilesConfig::load(store)?;
    let profile = profiles.selected(Some(&plan.profile_id))?;
    if profile.account_id.as_deref() != Some(plan.account_id.as_str()) {
        return Err(CliError::Input(
            "private R2 upload rectification profile no longer belongs to the plan account"
                .to_owned(),
        ));
    }
    let credential = fresh_credential(profile, &secrets).await?;
    let catalog = ensure_catalog(store).await?;
    let read = catalog
        .get(target.rectification_read_capability_id)
        .filter(|capability| capability.r2_private_object_digest.is_some())
        .ok_or_else(|| {
            CliError::Input(
                "private R2 upload rectification digest capability is unavailable or drifted"
                    .to_owned(),
            )
        })?;
    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let digest = executor
        .execute_r2_private_object_digest(read, &target.input, &credential)
        .await?;
    let passed = r2_private_upload_digest_matches(plan, &digest)?;
    let observed_sha256 = digest.result.get("sha256").cloned().unwrap_or(Value::Null);
    let observed_bytes = digest
        .result
        .get("byte_count")
        .cloned()
        .unwrap_or(Value::Null);
    let target_hash = hash_value(&target.input.selectors)?;
    let basis = if passed {
        "the native digest-only R2 read matched the exact staged source SHA-256, byte count, account, bucket, and object key"
    } else {
        "the native digest-only R2 read did not match the exact staged source or object target"
    };
    let verification = json!({
        "strategy":"r2_private_upload_digest_rectification",
        "passed":passed,
        "basis":basis,
        "expected_sha256":target.source_sha256,
        "expected_bytes":target.source_bytes,
        "observed_sha256":observed_sha256,
        "observed_bytes":observed_bytes,
        "target_hash":target_hash,
        "body_returned":false,
        "verification_only":true,
        "boundary_replayed":false,
    });
    let evidence = store.write_evidence(EvidenceClass::PostChangeVerification, &verification)?;
    let receipt = json!({
        "state":if passed { "passed" } else { "failed" },
        "evidence_hash":evidence.content_hash,
        "reconciliation":true,
        "verification_only":true,
        "boundary_replayed":false,
    });
    if passed {
        r2_private_upload::discard(store, plan, &secrets)?;
    }
    persist_r2_private_upload_rectification_result(store, plan, receipt, passed)?;

    let mut envelope = ResultEnvelopeV2::success(
        "plans rectify",
        json!({
            "operation_id":plan.operation_id,
            "status":plan.status,
            "verification_only":true,
            "boundary_replayed":false,
            "message":if passed {
                "The already-crossed create-only R2 upload was verified by an exact native digest read without replaying PUT."
            } else {
                "The native digest read did not match the staged source and exact target; the upload remains rectification_required and PUT was not replayed."
            },
        }),
    )
    .with_evidence(evidence);
    envelope.ok = passed;
    envelope.performed = false;
    envelope.operation_id = Some(plan.operation_id.clone());
    envelope.capability_id = Some(plan.capability.id.clone());
    envelope.profile_id = Some(plan.profile_id.clone());
    envelope.account_id = Some(plan.account_id.clone());
    envelope.verification.state = if passed {
        VerificationState::Passed
    } else {
        VerificationState::Failed
    };
    envelope.verification.basis = Some(basis.to_owned());
    if !passed {
        envelope.error = Some(ErrorV1 {
            code: "CFCTL_VERIFICATION_FAILED".to_owned(),
            message: basis.to_owned(),
            next_step: Some(
                "Inspect the body-free digest evidence and repair target drift; do not replay the create-only upload plan."
                    .to_owned(),
            ),
        });
    }
    Ok(envelope)
}

pub(super) fn persist_r2_private_upload_rectification_result(
    store: &StateStore,
    plan: &mut PlanV1,
    verification_receipt: Value,
    passed: bool,
) -> Result<()> {
    if !passed {
        plan.status = PlanStatus::RectificationRequired;
        store.save_plan(plan)?;
        return Ok(());
    }
    plan.status = PlanStatus::Verified;
    persist_transaction_stage_with_artifact(
        store,
        plan,
        TransactionStageV1::Closed,
        json!({
            "rectification_verification":verification_receipt,
            "retry":true,
        }),
    )
}

pub(super) fn email_routing_subdomain_dns_rectification_eligible(plan: &PlanV1) -> bool {
    let boundary = plan.transaction_artifact(TransactionStageV1::BoundaryResponsePersisted);
    plan.capability.verification.required
        && plan.capability.verification.strategy == "email_routing_subdomain_dns_records_match"
        && plan.capability.email_routing_subdomain_dns.is_some()
        && plan.status == PlanStatus::RectificationRequired
        && plan.transaction_stage == TransactionStageV1::VerificationResponsePersisted
        && boundary.is_some_and(|receipt| {
            receipt.get("http_status").and_then(Value::as_u64) == Some(200)
                && receipt.get("success").and_then(Value::as_bool) == Some(true)
        })
}

pub(super) async fn rectify_email_routing_subdomain_dns(
    store: &StateStore,
    plan: &mut PlanV1,
) -> Result<ResultEnvelopeV2> {
    let profiles = ProfilesConfig::load(store)?;
    let profile = profiles.selected(Some(&plan.profile_id))?;
    if profile.account_id.as_deref() != Some(plan.account_id.as_str()) {
        return Err(CliError::Input(
            "Email Routing subdomain rectification profile no longer belongs to the plan account"
                .to_owned(),
        ));
    }
    let input: CallInput = serde_json::from_value(plan.input.clone())?;
    let boundary = plan
        .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
        .ok_or_else(|| {
            CliError::Input(
                "Email Routing subdomain rectification omitted the successful boundary receipt"
                    .to_owned(),
            )
        })?;
    let status = boundary
        .get("http_status")
        .and_then(Value::as_u64)
        .and_then(|status| u16::try_from(status).ok())
        .filter(|status| *status == 200)
        .ok_or_else(|| {
            CliError::Input(
                "Email Routing subdomain rectification boundary status is not exactly 200"
                    .to_owned(),
            )
        })?;
    let credential = fresh_credential(profile, &platform_secrets(store)).await?;
    let apply_response = CloudflareResponseV1 {
        status,
        success: true,
        result: json!({}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let verification = Executor::new(http_client()?, API_BASE_URL)?
        .verify_plan_with_input(plan, &apply_response, &input, &credential)
        .await?;
    persist_email_routing_subdomain_dns_rectification(store, plan, verification)
}

pub(super) fn persist_email_routing_subdomain_dns_rectification(
    store: &StateStore,
    plan: &mut PlanV1,
    verification: OperationVerificationV1,
) -> Result<ResultEnvelopeV2> {
    if !email_routing_subdomain_dns_rectification_eligible(plan)
        || verification.strategy != "email_routing_subdomain_dns_records_match"
    {
        return Err(CliError::Input(
            "Email Routing subdomain DNS rectification is not bound to one eligible consumed operation"
                .to_owned(),
        ));
    }
    let passed = verification.passed;
    let basis = verification.basis.clone();
    let mut projected = serde_json::to_value(verification)?;
    let object = projected.as_object_mut().ok_or_else(|| {
        CliError::Input("Email Routing subdomain verification projection is malformed".to_owned())
    })?;
    object.insert("verification_only".to_owned(), Value::Bool(true));
    object.insert("boundary_replayed".to_owned(), Value::Bool(false));
    let evidence = store.write_evidence(EvidenceClass::PostChangeVerification, &projected)?;
    if passed {
        plan.status = PlanStatus::Verified;
        persist_transaction_stage_with_artifact(
            store,
            plan,
            TransactionStageV1::Closed,
            json!({
                "rectification_verification_hash":evidence.content_hash,
                "retry":false,
                "boundary_replayed":false,
            }),
        )?;
    } else {
        plan.status = PlanStatus::RectificationRequired;
        store.save_plan(plan)?;
    }
    let mut envelope = ResultEnvelopeV2::success(
        "plans rectify",
        json!({
            "operation_id":plan.operation_id,
            "status":plan.status,
            "verification_only":true,
            "boundary_replayed":false,
            "message":basis,
        }),
    )
    .with_evidence(evidence);
    envelope.ok = passed;
    envelope.performed = false;
    envelope.operation_id = Some(plan.operation_id.clone());
    envelope.capability_id = Some(plan.capability.id.clone());
    envelope.profile_id = Some(plan.profile_id.clone());
    envelope.account_id = Some(plan.account_id.clone());
    envelope.verification.state = if passed {
        VerificationState::Passed
    } else {
        VerificationState::Failed
    };
    envelope.verification.basis = Some(basis.clone());
    if !passed {
        envelope.error = Some(ErrorV1 {
            code: "CFCTL_VERIFICATION_FAILED".to_owned(),
            message: basis,
            next_step: Some(
                "Keep the Email Routing operation frozen, inspect the projected DNS readback, and do not replay the POST."
                    .to_owned(),
            ),
        });
    }
    Ok(envelope)
}

pub(super) fn workspace_d1_projection_rectification_eligible(plan: &PlanV1) -> bool {
    plan.capability.workspace_d1_policy_projection.is_some()
        && plan.status == PlanStatus::RectificationRequired
        && matches!(
            plan.transaction_stage,
            TransactionStageV1::BoundaryResponsePersisted
                | TransactionStageV1::SecretSinkPersisted
                | TransactionStageV1::VerificationAttemptPersisted
                | TransactionStageV1::VerificationResponsePersisted
        )
        && plan.transaction_journal.iter().any(|checkpoint| {
            checkpoint.stage == TransactionStageV1::BoundaryResponsePersisted
                && checkpoint.artifact_hash.is_some()
        })
}

pub(super) async fn rectify_workspace_d1_projection(
    store: &StateStore,
    plan: &mut PlanV1,
) -> Result<ResultEnvelopeV2> {
    workspace_d1_projection::validate_bound_plan_for_rectification(store, plan)?;
    let profiles = ProfilesConfig::load(store)?;
    let profile = profiles.selected(Some(&plan.profile_id))?;
    if profile.account_id.as_deref() != Some(plan.account_id.as_str()) {
        return Err(CliError::Input(
            "workspace D1 policy projection rectification profile no longer belongs to the plan account"
                .to_owned(),
        ));
    }
    let credential = fresh_credential(profile, &platform_secrets(store)).await?;
    let retrying_after_verification_response =
        plan.transaction_stage == TransactionStageV1::VerificationResponsePersisted;
    if matches!(
        plan.transaction_stage,
        TransactionStageV1::BoundaryResponsePersisted | TransactionStageV1::SecretSinkPersisted
    ) {
        persist_transaction_stage(
            store,
            plan,
            TransactionStageV1::VerificationAttemptPersisted,
        )?;
    }
    let verification =
        workspace_d1_projection::verify_rectification(store, plan, &credential).await;
    let verification_evidence =
        store.write_evidence(EvidenceClass::PostChangeVerification, &verification)?;
    let passed = verification
        .get("passed")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let basis = verification
        .get("basis")
        .and_then(Value::as_str)
        .unwrap_or("workspace D1 policy projection reconciliation did not return a basis")
        .to_owned();
    let verification_receipt = json!({
        "state": if passed { "passed" } else { "failed" },
        "basis_hash": hash_value(&json!(basis))?,
        "evidence_hash": verification_evidence.content_hash,
        "reconciliation": true,
        "boundary_replayed": false,
    });

    persist_workspace_d1_projection_rectification_result(
        store,
        plan,
        verification_receipt,
        passed,
        retrying_after_verification_response,
    )?;

    let mut envelope = ResultEnvelopeV2::success(
        "plans rectify",
        json!({
            "operation_id": plan.operation_id,
            "status": plan.status,
            "verification_only": true,
            "boundary_replayed": false,
            "message": if passed {
                "The already-crossed workspace D1 policy projection boundary was reconciled from fresh route-count and digest readback without replaying the projection apply."
            } else {
                "Fresh workspace D1 route-count and digest readback did not verify; the plan remains rectification_required and the projection was not replayed."
            },
        }),
    )
    .with_evidence(verification_evidence);
    envelope.ok = passed;
    envelope.performed = false;
    envelope.operation_id = Some(plan.operation_id.clone());
    envelope.capability_id = Some(plan.capability.id.clone());
    envelope.profile_id = Some(plan.profile_id.clone());
    envelope.account_id = Some(plan.account_id.clone());
    envelope.verification.state = if passed {
        VerificationState::Passed
    } else {
        VerificationState::Failed
    };
    envelope.verification.basis = Some(basis.clone());
    if !passed {
        envelope.error = Some(ErrorV1 {
            code: "CFCTL_VERIFICATION_FAILED".to_owned(),
            message: basis,
            next_step: Some(
                "Inspect the fresh route-count/digest evidence and repair the observed state; do not replay the projection plan."
                    .to_owned(),
            ),
        });
    }
    Ok(envelope)
}

pub(super) fn persist_workspace_d1_projection_rectification_result(
    store: &StateStore,
    plan: &mut PlanV1,
    verification_receipt: Value,
    passed: bool,
    retrying_after_verification_response: bool,
) -> Result<()> {
    if plan.transaction_stage == TransactionStageV1::VerificationAttemptPersisted {
        persist_transaction_stage_with_artifact(
            store,
            plan,
            TransactionStageV1::VerificationResponsePersisted,
            verification_receipt.clone(),
        )?;
    }
    if !passed {
        plan.status = PlanStatus::RectificationRequired;
        store.save_plan(plan)?;
        return Ok(());
    }

    plan.status = PlanStatus::Verified;
    if retrying_after_verification_response {
        persist_transaction_stage_with_artifact(
            store,
            plan,
            TransactionStageV1::Closed,
            json!({
                "rectification_verification": verification_receipt,
                "retry": true,
            }),
        )
    } else {
        persist_transaction_stage(store, plan, TransactionStageV1::Closed)
    }
}

pub(super) async fn rectify_workspace_d1_migration(
    store: &StateStore,
    plan: &mut PlanV1,
) -> Result<ResultEnvelopeV2> {
    workspace_d1_migration::validate_bound_plan_for_rectification(store, plan)?;
    let profiles = ProfilesConfig::load(store)?;
    let profile = profiles.selected(Some(&plan.profile_id))?;
    if profile.account_id.as_deref() != Some(plan.account_id.as_str()) {
        return Err(CliError::Input(
            "workspace D1 migration rectification profile no longer belongs to the plan account"
                .to_owned(),
        ));
    }
    let credential = fresh_credential(profile, &platform_secrets(store)).await?;
    let retrying_after_verification_response =
        plan.transaction_stage == TransactionStageV1::VerificationResponsePersisted;
    if matches!(
        plan.transaction_stage,
        TransactionStageV1::BoundaryResponsePersisted | TransactionStageV1::SecretSinkPersisted
    ) {
        persist_transaction_stage(
            store,
            plan,
            TransactionStageV1::VerificationAttemptPersisted,
        )?;
    }
    let verification = workspace_d1_migration::verify_rectification(store, plan, &credential).await;
    let verification_evidence =
        store.write_evidence(EvidenceClass::PostChangeVerification, &verification)?;
    let passed = verification
        .get("passed")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let basis = verification
        .get("basis")
        .and_then(Value::as_str)
        .unwrap_or("workspace D1 migration reconciliation did not return a basis")
        .to_owned();
    let verification_receipt = json!({
        "state": if passed { "passed" } else { "failed" },
        "basis_hash": hash_value(&json!(basis))?,
        "evidence_hash": verification_evidence.content_hash,
        "reconciliation": true,
        "boundary_replayed": false,
    });

    persist_workspace_d1_rectification_result(
        store,
        plan,
        verification_receipt,
        passed,
        retrying_after_verification_response,
    )?;

    let mut envelope = ResultEnvelopeV2::success(
        "plans rectify",
        json!({
            "operation_id": plan.operation_id,
            "status": plan.status,
            "verification_only": true,
            "boundary_replayed": false,
            "message": if passed {
                "The already-crossed workspace D1 migration boundary was reconciled from fresh ledger and schema readback without replaying Wrangler apply."
            } else {
                "Fresh workspace D1 ledger and schema readback did not verify; the plan remains rectification_required and the mutation was not replayed."
            },
        }),
    )
    .with_evidence(verification_evidence);
    envelope.ok = passed;
    envelope.performed = false;
    envelope.operation_id = Some(plan.operation_id.clone());
    envelope.capability_id = Some(plan.capability.id.clone());
    envelope.profile_id = Some(plan.profile_id.clone());
    envelope.account_id = Some(plan.account_id.clone());
    envelope.verification.state = if passed {
        VerificationState::Passed
    } else {
        VerificationState::Failed
    };
    envelope.verification.basis = Some(basis.clone());
    if !passed {
        envelope.error = Some(ErrorV1 {
            code: "CFCTL_VERIFICATION_FAILED".to_owned(),
            message: basis,
            next_step: Some(
                "Inspect the fresh ledger/schema evidence and repair the observed state; do not replay the migration plan."
                    .to_owned(),
            ),
        });
    }
    Ok(envelope)
}

pub(super) fn persist_workspace_d1_rectification_result(
    store: &StateStore,
    plan: &mut PlanV1,
    verification_receipt: Value,
    passed: bool,
    retrying_after_verification_response: bool,
) -> Result<()> {
    if plan.transaction_stage == TransactionStageV1::VerificationAttemptPersisted {
        persist_transaction_stage_with_artifact(
            store,
            plan,
            TransactionStageV1::VerificationResponsePersisted,
            verification_receipt.clone(),
        )?;
    }
    if !passed {
        plan.status = PlanStatus::RectificationRequired;
        store.save_plan(plan)?;
        return Ok(());
    }

    plan.status = PlanStatus::Verified;
    if retrying_after_verification_response {
        persist_transaction_stage_with_artifact(
            store,
            plan,
            TransactionStageV1::Closed,
            json!({
                "rectification_verification": verification_receipt,
                "retry": true,
            }),
        )
    } else {
        persist_transaction_stage(store, plan, TransactionStageV1::Closed)
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "rectification is one no-replay verified-state transition"
)]
pub(super) fn rectify_approved_mln_import(
    store: &StateStore,
    plan: &mut PlanV1,
) -> Result<ResultEnvelopeV2> {
    let resume_from_init_attempt = plan.status == PlanStatus::Consumed
        && plan.transaction_stage == TransactionStageV1::BoundaryAttemptPersisted;
    let resume_from_init_response = plan.status == PlanStatus::RectificationRequired
        && plan.transaction_stage == TransactionStageV1::BoundaryResponsePersisted;
    if resume_from_init_attempt || resume_from_init_response {
        let checkpoints = store.read_d1_import_checkpoints(&plan.operation_id)?;
        if checkpoints.len() == 1
            && checkpoints[0].1.get("step").and_then(Value::as_str) == Some("init_response")
        {
            let (init_evidence, _) = exact_durable_init_response_failure(store, plan)?;
            let boundary_artifact = json!({
                "adapter":"dynamic_api",
                "performed":true,
                "success":false,
                "outcome":"invalid_provider_response",
                "receipt_available":true,
                "init_response_evidence_hash":init_evidence.content_hash,
            });
            if resume_from_init_attempt {
                plan.status = PlanStatus::RectificationRequired;
                persist_transaction_stage_with_artifact(
                    store,
                    plan,
                    TransactionStageV1::BoundaryResponsePersisted,
                    boundary_artifact,
                )?;
            } else if plan.transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
                != Some(&boundary_artifact)
            {
                return Err(CliError::Input(
                    "init-only recovery boundary artifact drifted from its exact durable checkpoint"
                        .to_owned(),
                ));
            }
            let sink_artifact = secret_sink_artifact(plan, None, false, true, false, None, None);
            persist_transaction_stage_with_artifact(
                store,
                plan,
                TransactionStageV1::SecretSinkPersisted,
                sink_artifact,
            )?;
        }
    }
    if plan.status == PlanStatus::RectificationRequired
        && plan.transaction_stage == TransactionStageV1::SecretSinkPersisted
    {
        let checkpoints = store.read_d1_import_checkpoints(&plan.operation_id)?;
        if checkpoints.len() != 1
            || checkpoints[0].1.get("step").and_then(Value::as_str) != Some("init_response")
        {
            return Err(CliError::Input(
                "init-only rectification requires exactly one durable init response and no upload, ingest, poll, or provider-complete checkpoint"
                    .to_owned(),
            ));
        }
        let (init_evidence, checkpoint) = exact_durable_init_response_failure(store, plan)?;
        let valid_abandoned_session = checkpoint
            .pointer("/receipt/success")
            .and_then(Value::as_bool)
            == Some(true)
            && checkpoint
                .pointer("/receipt/result/success")
                .and_then(Value::as_bool)
                == Some(true)
            && checkpoint
                .pointer("/receipt/result/upload_url_present")
                .and_then(Value::as_bool)
                == Some(true)
            && checkpoint
                .pointer("/receipt/result/filename_present")
                .and_then(Value::as_bool)
                == Some(true)
            && checkpoint
                .pointer("/receipt/provider_errors_present")
                .and_then(Value::as_bool)
                == Some(false)
            && checkpoint
                .pointer("/receipt/result/provider_error_present")
                .and_then(Value::as_bool)
                == Some(false)
            && checkpoint
                .pointer("/receipt/errors")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
            && checkpoint
                .pointer("/receipt/result/type")
                .is_some_and(Value::is_null)
            && checkpoint
                .pointer("/receipt/result/status")
                .is_some_and(Value::is_null);
        if !valid_abandoned_session {
            return Err(CliError::Input(
                "init-only rectification requires one successful redacted upload-session receipt; provider rejection or uncertainty remains unresolved"
                    .to_owned(),
            ));
        }
        persist_transaction_stage(
            store,
            plan,
            TransactionStageV1::VerificationAttemptPersisted,
        )?;
        plan.status = PlanStatus::Rectified;
        let completion = json!({
            "schema_version":1,
            "state":"rectified",
            "operation_id":plan.operation_id,
            "init_response_evidence_hash":init_evidence.content_hash,
            "upload_performed":false,
            "database_write_performed":false,
            "disposition":"abandoned_unuploaded_provider_init_session",
        });
        let verification_evidence =
            store.write_evidence(EvidenceClass::PostChangeVerification, &completion)?;
        persist_transaction_stage_with_artifact(
            store,
            plan,
            TransactionStageV1::VerificationResponsePersisted,
            json!({
                "state":"passed",
                "evidence_hash":verification_evidence.content_hash,
                "init_response_evidence_hash":init_evidence.content_hash,
            }),
        )?;
        persist_transaction_stage(store, plan, TransactionStageV1::Closed)?;
        let mut envelope = ResultEnvelopeV2::success("plans rectify", completion)
            .with_evidence(verification_evidence);
        envelope.evidence.push(init_evidence);
        envelope.performed = false;
        envelope.operation_id = Some(plan.operation_id.clone());
        envelope.capability_id = Some(plan.capability.id.clone());
        envelope.profile_id = Some(plan.profile_id.clone());
        envelope.account_id = Some(plan.account_id.clone());
        envelope.policy_decision = Some(plan.policy.clone());
        envelope.verification.state = VerificationState::Passed;
        envelope.verification.basis = Some(
            "the operation has exactly one durable successful init-session receipt and no upload, ingest, poll, or provider-complete checkpoint; rectification abandoned that unuploaded session without replay or provider mutation"
                .to_owned(),
        );
        return Ok(envelope);
    }
    if plan.status != PlanStatus::Running
        || plan.transaction_stage != TransactionStageV1::SecretSinkPersisted
    {
        return Err(CliError::Input(
            "approved MLN import is not at the durable provider_complete boundary".to_owned(),
        ));
    }
    let staged = plan
        .targets
        .pointer("/adapter/approved_mln_import")
        .cloned()
        .ok_or_else(|| CliError::Input("import stage binding is missing".to_owned()))?;
    let source_sha256 = staged
        .get("sha256")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| CliError::Input("import source SHA-256 is missing".to_owned()))?;
    let provider_boundary =
        exact_durable_provider_complete_boundary(store, plan.operation_id.as_str())?;
    let provider_complete_hash = &provider_boundary.evidence_hash;
    let import_input: CallInput = serde_json::from_value(plan.input.clone())?;
    let migration_id = import_input
        .body
        .as_ref()
        .and_then(|body| body.get("migration_id"))
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("import migration identity is missing".to_owned()))?;
    let matching = store
        .list_operational_proofs()?
        .into_iter()
        .filter_map(|proof| {
            if migration_id == "0142" {
                let binding = proof.mln_0142_governed_execution()?;
                let final_bookmark_hash = provider_boundary
                    .checkpoint
                    .pointer("/receipt/final_bookmark")
                    .and_then(Value::as_str)
                    .and_then(|bookmark| hash_value(&Value::String(bookmark.to_owned())).ok())?;
                let exact = proof.capability_id == "mln-0142-post-import-schema"
                    && binding.completion_status == "completed"
                    && binding.import_operation_id == plan.operation_id
                    && binding.import_boundary_evidence_hash == *provider_complete_hash
                    && binding.import_source_sha256 == source_sha256
                    && binding.import_plan_hash == plan.content_hash
                    && binding.final_bookmark_hash == final_bookmark_hash
                    && binding.target_scope_hash == hash_value(staged.get("target")?).ok()?;
                return exact.then_some(proof);
            }
            let binding = proof.mln_0143_governed_execution()?;
            if proof.capability_id != "mln-0143-data-invariants"
                || binding.phase != "post_import"
                || binding.completion_status != "completed"
                || binding.cross_operation_lineage_hash.is_none()
            {
                return None;
            }
            let evidence = store
                .read_evidence_value(&proof.evidence.content_hash)
                .ok()?;
            let manifest = evidence.get("result").unwrap_or(&evidence);
            let lineage = manifest.get("lineage")?;
            let exact = lineage.get("import_operation_id").and_then(Value::as_str)
                == Some(plan.operation_id.as_str())
                && lineage
                    .get("import_boundary_evidence_hash")
                    .and_then(Value::as_str)
                    == Some(provider_complete_hash.as_str())
                && lineage.get("import_source_sha256").and_then(Value::as_str)
                    == Some(source_sha256.as_str())
                && lineage.get("import_plan_hash").and_then(Value::as_str)
                    == Some(plan.content_hash.as_str())
                && binding.cross_operation_lineage_hash.as_deref()
                    == hash_value(lineage).ok().as_deref();
            exact.then_some(proof)
        })
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err(CliError::Input(
            "import verification requires exactly one governed post_import proof bound to this plan, source, target, and provider boundary"
                .to_owned(),
        ));
    }
    let proof = &matching[0];
    persist_transaction_stage(
        store,
        plan,
        TransactionStageV1::VerificationAttemptPersisted,
    )?;
    plan.status = PlanStatus::Verified;
    let completion = json!({
        "schema_version":1,
        "state":"verified",
        "operation_id":plan.operation_id,
        "provider_complete_evidence_hash":provider_complete_hash,
        "post_import_operation_id":proof.mln_0143_governed_execution().map(|binding| binding.operation_id.as_str()).or_else(|| proof.mln_0142_governed_execution().map(|binding| binding.operation_id.as_str())),
        "post_import_evidence_hash":proof.evidence.content_hash,
        "source_sha256":source_sha256,
        "target":staged.get("target"),
    });
    let verification_evidence =
        store.write_evidence(EvidenceClass::PostChangeVerification, &completion)?;
    persist_transaction_stage_with_artifact(
        store,
        plan,
        TransactionStageV1::VerificationResponsePersisted,
        json!({
            "state":"passed",
            "evidence_hash":verification_evidence.content_hash,
            "provider_complete_evidence_hash":provider_complete_hash,
        }),
    )?;
    persist_transaction_stage(store, plan, TransactionStageV1::Closed)?;
    let mut envelope =
        ResultEnvelopeV2::success("plans rectify", completion).with_evidence(verification_evidence);
    envelope.performed = false;
    envelope.operation_id = Some(plan.operation_id.clone());
    envelope.capability_id = Some(plan.capability.id.clone());
    envelope.profile_id = Some(plan.profile_id.clone());
    envelope.account_id = Some(plan.account_id.clone());
    envelope.policy_decision = Some(plan.policy.clone());
    envelope.verification.state = VerificationState::Passed;
    envelope.verification.basis = Some(
        "the exact provider_complete import boundary is joined to one governed migration-specific post-import proof; this local transition performed no additional provider mutation"
            .to_owned(),
    );
    Ok(envelope)
}
