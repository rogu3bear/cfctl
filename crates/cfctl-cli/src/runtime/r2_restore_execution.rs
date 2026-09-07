//! Existing consumed-plan lifecycle for the native private object primitive.
use super::api_boundary::{
    ApiBoundaryResponseOutcome, ApiVerificationOutcome, api_plan_result_envelope,
    persist_secret_lifecycle, post_boundary_failure_envelope, process_api_boundary_response,
    verification_error_outcome, verification_response_artifact, verify_api_plan,
};
use super::plan_commands::{persist_transaction_stage, persist_transaction_stage_with_artifact};
use super::prelude::{
    AuthCredential, CallInput, CatalogSnapshot, CliError, Executor, PlanStatus, PlanV1,
    ProfilesConfig, Result, ResultEnvelopeV2, SecretStore, StateStore, TransactionStageV1, Utc,
    json,
};
use super::r2_restore_projection;
use cfctl_cloudflare::{CloudflareError, OperationVerificationV1, r2_restore::RestoreProgress};
use cfctl_core::r2_restore::{
    RESTORE_ID, RestoreObservationKindV1 as ObservationKind, RestoreSelectionV1,
};

pub(super) async fn execute(
    store: &StateStore,
    catalog_hash: &str,
    plan: &mut PlanV1,
    input: &CallInput,
    credential: &AuthCredential,
    secrets: &dyn SecretStore,
) -> Result<ResultEnvelopeV2> {
    let progress = RestoreProgress::default();
    let (loaded, executor) = match prepare_consumed_execution(store, plan, secrets) {
        Ok(prepared) => prepared,
        Err(error) => return Ok(no_response(store, plan, &error, &progress, secrets)),
    };
    let token_id = loaded
        .token_id
        .as_deref()
        .ok_or_else(super::r2_restore::rejected)?;
    let response = match executor
        .execute_r2_private_restore(
            plan,
            catalog_hash,
            input,
            &loaded.selection,
            loaded.source_bytes,
            token_id,
            credential,
            &progress,
        )
        .await
    {
        Ok(response) => response,
        Err(error) => {
            let error = CliError::from(error);
            return Ok(no_response(store, plan, &error, &progress, secrets));
        }
    };
    let (response_value, apply_evidence, lineage_evidence) =
        match process_api_boundary_response(store, plan, &response, secrets)? {
            ApiBoundaryResponseOutcome::Ready {
                response_value,
                apply_evidence,
                lineage_evidence,
            } => (response_value, apply_evidence, lineage_evidence),
            ApiBoundaryResponseOutcome::Recovery(envelope) => return Ok(envelope),
        };
    let verification = if response.success {
        persist_transaction_stage(
            store,
            plan,
            TransactionStageV1::VerificationAttemptPersisted,
        )?;
        let result = readback_within_window(
            &executor,
            plan,
            input,
            &loaded.selection,
            token_id,
            credential,
        )
        .await;
        let outcome = match result {
            Ok(verification) => r2_restore_projection::persist_observation(
                store,
                plan,
                &loaded.selection,
                &loaded.source_window,
                verification,
                ObservationKind::ImmediatePostWrite,
            )?,
            Err(error) => verification_error_outcome(store, plan, &error)?,
        };
        persist_transaction_stage_with_artifact(
            store,
            plan,
            TransactionStageV1::VerificationResponsePersisted,
            verification_response_artifact(&outcome)?,
        )?;
        outcome
    } else {
        verify_api_plan(store, &executor, plan, &response, input, credential).await?
    };
    let finalization = if matches!(plan.status, PlanStatus::Verified | PlanStatus::Failed) {
        persist_transaction_stage(store, plan, TransactionStageV1::Closed)
    } else {
        store.save_plan(plan).map_err(CliError::from)
    };
    let mut envelope = api_plan_result_envelope(
        plan,
        response_value,
        apply_evidence,
        lineage_evidence,
        verification,
        response.success,
        finalization.err().as_ref(),
    );
    envelope.result["native_restore_limits"] = json!({"max_put_attempts":1,"max_provider_requests":5,
        "max_download_bytes":600_000_000_u64,"max_upload_bytes":300_000_000_u64,"max_metadata_bytes":4*1024*1024,"max_put_response_bytes":16*1024,
        "window_expires_at":loaded.selection.window.expires_at,"private_files_retained":true,
        "metadata_atomic_precondition":false,"writer_exclusion_qualified":false,"combined_recovery_ready":false});
    Ok(envelope)
}

async fn readback_within_window(
    executor: &Executor,
    plan: &PlanV1,
    input: &CallInput,
    selection: &RestoreSelectionV1,
    token_id: &str,
    credential: &AuthCredential,
) -> std::result::Result<OperationVerificationV1, CloudflareError> {
    let remaining = (selection.window.expires_at - Utc::now())
        .to_std()
        .map_err(|_| window_failure())?;
    tokio::time::timeout(
        remaining,
        executor.verify_r2_private_restore(plan, input, selection, token_id, credential),
    )
    .await
    .map_err(|_| window_failure())?
}

fn prepare_consumed_execution(
    store: &StateStore,
    plan: &PlanV1,
    secrets: &dyn SecretStore,
) -> Result<(super::r2_restore::LoadedRestore, Executor)> {
    let loaded = super::r2_restore::load_with_secrets(store, plan, true, secrets)?;
    if loaded.token_id.is_none() {
        return Err(super::r2_restore::rejected());
    }
    let executor = Executor::new(
        super::support::private_capture_http_client()?,
        super::cloudflare_api::BASE_URL,
    )?
    .with_max_retries(0);
    Ok((loaded, executor))
}

fn no_response(
    store: &StateStore,
    plan: &mut PlanV1,
    error: &CliError,
    progress: &RestoreProgress,
    secrets: &dyn SecretStore,
) -> ResultEnvelopeV2 {
    plan.status = PlanStatus::RectificationRequired;
    let outcome = if progress.put_attempted() {
        "unknown"
    } else {
        "not_attempted"
    };
    let receipt = json!({"adapter":"native_private_r2_restore", "put_attempted":progress.put_attempted(),
        "provider_requests":progress.requests(), "outcome":outcome,
        "put_replayed":false, "body_returned":false, "private_files_retained":true,
        "metadata_atomic_precondition":false, "writer_exclusion_qualified":false,
        "combined_recovery_ready":false, "retention_qualified":false});
    let mut failures = vec![error.to_string()];
    if let Err(error) = persist_transaction_stage_with_artifact(
        store,
        plan,
        TransactionStageV1::BoundaryResponsePersisted,
        receipt.clone(),
    ) {
        failures.push(format!("restore outcome persistence failed: {error}"));
    }
    if let Err(error) = persist_secret_lifecycle(store, plan, false, None, secrets) {
        failures.push(format!("restore lifecycle persistence failed: {error}"));
    }
    let basis = if progress.put_attempted() {
        "The conditional PUT outcome is uncertain. Preserve private recovery files and rectify by reads without replay."
    } else {
        "The consumed restore stopped before PUT. Preserve private recovery files; this operation can only be rectified by reads."
    };
    post_boundary_failure_envelope(
        plan,
        receipt,
        None,
        None,
        &CliError::Input(failures.join("; ")),
        false,
        basis,
    )
}

fn window_failure() -> CloudflareError {
    CloudflareError::InvalidRequestBody("private restore verification exceeded its window; preserve the managed files and rectify without replay".into())
}

pub(super) async fn rectify(store: &StateStore, plan: &mut PlanV1) -> Result<ResultEnvelopeV2> {
    tokio::time::timeout(
        std::time::Duration::from_mins(15),
        rectify_inner(store, plan),
    )
    .await
    .map_err(|_| CliError::from(window_failure()))?
}

async fn rectify_inner(store: &StateStore, plan: &mut PlanV1) -> Result<ResultEnvelopeV2> {
    if plan.capability.id != RESTORE_ID
        || !matches!(
            plan.status,
            PlanStatus::Consumed | PlanStatus::Running | PlanStatus::RectificationRequired
        )
        || !matches!(
            plan.transaction_stage,
            TransactionStageV1::BoundaryAttemptPersisted
                | TransactionStageV1::BoundaryResponsePersisted
                | TransactionStageV1::SecretSinkPersisted
                | TransactionStageV1::VerificationAttemptPersisted
                | TransactionStageV1::VerificationResponsePersisted
        )
        || !plan
            .transaction_journal
            .iter()
            .any(|c| c.stage == TransactionStageV1::BoundaryAttemptPersisted)
    {
        return Err(super::r2_restore::rejected());
    }
    let loaded = super::r2_restore::load(store, plan, false)?;
    let catalog = CatalogSnapshot::load(&store.paths().catalog_file())?;
    let profiles = ProfilesConfig::load(store)?;
    let profile = profiles.selected(Some(&plan.profile_id))?;
    let credential = super::credential_resolution::fresh_credential(
        profile,
        &super::credential_resolution::platform_secrets(store),
    )
    .await?;
    let (token_id, token_evidence) = super::r2_restore_credentials::qualify_read_only(
        store,
        &catalog,
        profile,
        &plan.account_id,
        &credential,
    )
    .await?;
    let input: CallInput = serde_json::from_value(plan.input.clone())?;
    let executor = Executor::new(
        super::support::private_capture_http_client()?,
        super::cloudflare_api::BASE_URL,
    )?
    .with_max_retries(0);
    begin_rectification_observation(store, plan)?;
    let outcome = match executor
        .verify_r2_private_restore(plan, &input, &loaded.selection, &token_id, &credential)
        .await
    {
        Ok(verification) => r2_restore_projection::persist_observation(
            store,
            plan,
            &loaded.selection,
            &loaded.source_window,
            verification,
            ObservationKind::ReadOnlyRectification,
        )?,
        Err(error) => verification_error_outcome(store, plan, &error)?,
    };
    persist_rectification(store, plan, &outcome)?;
    let mut envelope = ResultEnvelopeV2::success(
        "plans rectify",
        json!({"operation_id":plan.operation_id,
        "state":plan.status,"kind":"private_restore_read_only_rectification",
        "put_replayed":false,"historical_put_outcome_proven":false,"private_files_retained":true,
        "metadata_atomic_precondition":false,"writer_exclusion_qualified":false,"combined_recovery_ready":false,
        "current_credential_generation_id":profile.credential_generation_id,
        "max_provider_requests":3,"max_download_bytes":300_000_000_u64,
        "max_metadata_bytes":2*1024*1024 + cfctl_core::r2_restore::TOKEN_READ_MAX_BYTES,"max_seconds":900}),
    );
    envelope.ok = plan.status == PlanStatus::Verified;
    envelope.performed = true;
    envelope.operation_id = Some(plan.operation_id.clone());
    envelope.capability_id = Some(RESTORE_ID.into());
    envelope.account_id = Some(plan.account_id.clone());
    envelope.profile_id = Some(plan.profile_id.clone());
    envelope.verification.state = outcome.state;
    envelope.verification.basis = Some(outcome.basis);
    envelope.error = outcome.error;
    envelope.evidence.push(token_evidence);
    if let Some(evidence) = outcome.evidence {
        envelope.evidence.push(evidence);
    }
    Ok(envelope)
}

pub(super) fn begin_rectification_observation(store: &StateStore, plan: &mut PlanV1) -> Result<()> {
    if !matches!(
        plan.transaction_stage,
        TransactionStageV1::VerificationAttemptPersisted
            | TransactionStageV1::VerificationResponsePersisted
    ) {
        persist_transaction_stage(
            store,
            plan,
            TransactionStageV1::VerificationAttemptPersisted,
        )?;
    }
    Ok(())
}

/// Preserve the first verification checkpoint. Later read-only observations
/// have their own authenticated evidence and may append closure, never rewind
/// or replace a checkpoint in the existing one-use mutation journal.
pub(super) fn persist_rectification(
    store: &StateStore,
    plan: &mut PlanV1,
    outcome: &ApiVerificationOutcome,
) -> Result<()> {
    let receipt = verification_response_artifact(outcome)?;
    if plan.transaction_stage == TransactionStageV1::VerificationAttemptPersisted {
        persist_transaction_stage_with_artifact(
            store,
            plan,
            TransactionStageV1::VerificationResponsePersisted,
            receipt.clone(),
        )?;
    }
    if plan.status == PlanStatus::Verified {
        persist_transaction_stage_with_artifact(
            store,
            plan,
            TransactionStageV1::Closed,
            json!({"rectification_verification":receipt,"put_replayed":false,"historical_put_outcome_proven":false}),
        )?;
    } else {
        store.save_plan(plan)?;
    }
    Ok(())
}
