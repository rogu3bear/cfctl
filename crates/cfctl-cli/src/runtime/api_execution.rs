use super::api_boundary::ApiBoundaryResponseOutcome;
use super::api_boundary::api_plan_result_envelope;
use super::api_boundary::post_boundary_failure_envelope;
use super::api_boundary::process_api_boundary_response;
use super::api_boundary::process_api_transport_failure;
use super::api_boundary::verify_api_plan;
use super::cloudflare_api::BASE_URL as API_BASE_URL;
use super::import_resume::approved_mln_import_execution_error_envelope;
use super::import_resume::exact_durable_resume_provider_complete_boundary;
use super::import_resume::execute_approved_mln_import_plan;
use super::import_resume::persist_d1_import_checkpoint;
use super::import_resume::validate_managed_reviewed_git_stage_authority;
use super::plan_commands::persist_transaction_stage;
use super::prelude::{
    AuthCredential, CallInput, CliError, ErrorV1, Executor, PlanStatus, PlanV1,
    R2PrivateUploadPayload, Result, ResultEnvelopeV2, SecretStore, StateStore, TransactionStageV1,
    Value, VerificationState,
};
use super::r2_private_upload;
use super::secret_io::preflight_secret_sink;
use super::support::mutation_http_client;

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FinalizationTestStage {
    Response,
    Verification,
    Closure,
}

#[cfg(test)]
tokio::task_local! {
    pub(super) static FINALIZATION_TEST_HOOK: std::sync::Arc<dyn Fn(FinalizationTestStage) + Send + Sync>;
}

#[cfg(test)]
fn finalization_test_stage(stage: FinalizationTestStage) {
    let _ = FINALIZATION_TEST_HOOK.try_with(|hook| hook(stage));
}

pub(super) async fn execute_api_plan(
    store: &StateStore,
    catalog_hash: &str,
    plan: &mut PlanV1,
    execution_input: &CallInput,
    credential: &AuthCredential,
    secrets: &dyn SecretStore,
) -> Result<ResultEnvelopeV2> {
    let executor = match mutation_http_client()
        .and_then(|client| Executor::new(client, API_BASE_URL).map_err(CliError::from))
    {
        Ok(executor) => executor,
        Err(error) => {
            return Ok(process_api_transport_failure(
                store, plan, &error, secrets, false,
            ));
        }
    };
    execute_api_plan_with_executor(
        store,
        &executor,
        catalog_hash,
        plan,
        execution_input,
        credential,
        secrets,
    )
    .await
}

/// Keep transport injection at the existing execution owner so loopback tests
/// exercise the same dispatch, receipt persistence and finalization as the CLI.
#[expect(
    clippy::too_many_lines,
    reason = "one consumed-plan executor keeps preparation, actual dispatch, retained response and finalization in one auditable sequence"
)]
pub(super) async fn execute_api_plan_with_executor(
    store: &StateStore,
    executor: &Executor,
    catalog_hash: &str,
    plan: &mut PlanV1,
    execution_input: &CallInput,
    credential: &AuthCredential,
    secrets: &dyn SecretStore,
) -> Result<ResultEnvelopeV2> {
    if plan.capability.path == "workspace:d1-transition-envelope-v3" {
        return Box::pin(super::workspace_d1_transition::execute(
            store, plan, credential,
        ))
        .await;
    }
    if plan.capability.id == cfctl_core::r2_restore::RESTORE_ID {
        return super::r2_restore_execution::execute(
            store,
            catalog_hash,
            plan,
            execution_input,
            credential,
            secrets,
        )
        .await;
    }
    let boundary = cfctl_core::BoundaryObservation::default();
    let executor = executor.clone().with_boundary_observation(boundary.clone());
    let is_reviewed_schema_migration = plan.capability.id == "d1-apply-reviewed-schema-migration";
    let preparation = preflight_secret_sink(plan).and_then(|()| {
        if is_reviewed_schema_migration {
            validate_managed_reviewed_git_stage_authority(plan)?;
        }
        Ok(())
    });
    if let Err(error) = preparation {
        return Ok(process_api_transport_failure(
            store, plan, &error, secrets, false,
        ));
    }
    if plan.capability.d1_approved_mln_import_poll_resume.is_some() {
        let result = execute_approved_mln_import_poll_resume_plan(
            store,
            &executor,
            plan,
            execution_input,
            credential,
            secrets,
            &boundary,
        )
        .await;
        return Ok(result.unwrap_or_else(|error| {
            process_api_transport_failure(store, plan, &error, secrets, boundary.attempted())
        }));
    }
    if plan.capability.d1_approved_mln_import.is_some() && !is_reviewed_schema_migration {
        let result = Box::pin(execute_approved_mln_import_plan(
            store,
            &executor,
            plan,
            execution_input,
            credential,
            secrets,
            &boundary,
        ))
        .await;
        return Ok(result.unwrap_or_else(|error| {
            process_api_transport_failure(store, plan, &error, secrets, boundary.attempted())
        }));
    }
    let response_result = if plan.capability.r2_private_file_upload.is_some() {
        let upload = match r2_private_upload::load(store, plan, secrets) {
            Ok(upload) => upload,
            Err(error) => {
                return Ok(process_api_transport_failure(
                    store, plan, &error, secrets, false,
                ));
            }
        };
        executor
            .execute_r2_private_file_upload(
                plan,
                catalog_hash,
                credential,
                execution_input,
                R2PrivateUploadPayload {
                    bytes: upload.bytes,
                    expected_md5: upload.md5,
                    content_type: upload.content_type,
                },
            )
            .await
    } else {
        executor
            .execute_consumed_plan_with_input(plan, catalog_hash, credential, execution_input)
            .await
    };
    let response = match response_result {
        Ok(response) => response,
        Err(error) => {
            let error = CliError::from(error);
            return Ok(process_api_transport_failure(
                store,
                plan,
                &error,
                secrets,
                boundary.mutation_attempted(),
            ));
        }
    };
    #[cfg(test)]
    finalization_test_stage(FinalizationTestStage::Response);
    let (response_value, apply_evidence, lineage_evidence) = match process_api_boundary_response(
        store,
        plan,
        &response,
        secrets,
        boundary.mutation_attempted(),
    )? {
        ApiBoundaryResponseOutcome::Ready {
            response_value,
            apply_evidence,
            lineage_evidence,
        } => (response_value, apply_evidence, lineage_evidence),
        ApiBoundaryResponseOutcome::Recovery(envelope) => return Ok(envelope),
    };
    let performed = boundary.mutation_attempted();
    #[cfg(test)]
    finalization_test_stage(FinalizationTestStage::Verification);
    let verification = match verify_api_plan(
        store,
        &executor,
        plan,
        &response,
        execution_input,
        credential,
    )
    .await
    {
        Ok(verification) => verification,
        Err(error) => {
            return Ok(post_boundary_failure_envelope(
                plan,
                response_value,
                Some(apply_evidence),
                lineage_evidence,
                &error,
                performed,
                "the Cloudflare boundary response and secret lifecycle are durable, but verification could not complete",
            ));
        }
    };
    let finalization: Result<()> = (|| {
        #[cfg(test)]
        finalization_test_stage(FinalizationTestStage::Closure);
        if matches!(plan.status, PlanStatus::Verified | PlanStatus::Failed) {
            persist_transaction_stage(store, plan, TransactionStageV1::Closed)?;
        } else {
            store.save_plan(plan)?;
        }
        // The private stage is discarded only after the closed result is
        // durable; rectification of an unsaved result still needs it.
        if plan.status == PlanStatus::Verified && plan.capability.r2_private_file_upload.is_some() {
            r2_private_upload::discard(store, plan, secrets)?;
        }
        Ok(())
    })();
    let finalization_error = finalization.err();
    Ok(api_plan_result_envelope(
        plan,
        response_value,
        apply_evidence,
        lineage_evidence,
        verification,
        performed,
        finalization_error.as_ref(),
    ))
}

#[expect(
    clippy::too_many_lines,
    reason = "poll continuation execution keeps lineage admission, journal persistence, bounded provider polling, and terminal proof visible as one no-replay state machine"
)]
pub(super) async fn execute_approved_mln_import_poll_resume_plan(
    store: &StateStore,
    executor: &Executor,
    plan: &mut PlanV1,
    execution_input: &CallInput,
    credential: &AuthCredential,
    secrets: &dyn SecretStore,
    boundary: &cfctl_core::BoundaryObservation,
) -> Result<ResultEnvelopeV2> {
    let bookmark = plan
        .targets
        .pointer("/adapter/approved_mln_import_poll_resume/accepted_bookmark")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CliError::Input("poll continuation bookmark is missing".to_owned()))?
        .to_owned();
    let checkpoint_operation_id = plan.operation_id.clone();
    let response = match executor
        .execute_d1_approved_mln_import_poll_resume(
            plan,
            execution_input,
            credential,
            &bookmark,
            |checkpoint| persist_d1_import_checkpoint(store, &checkpoint_operation_id, checkpoint),
        )
        .await
    {
        Ok(response) => response,
        Err(error) => {
            return Ok(approved_mln_import_execution_error_envelope(
                store,
                plan,
                error,
                secrets,
                boundary.attempted(),
            ));
        }
    };
    let (response_value, apply_evidence, lineage_evidence) =
        match process_api_boundary_response(store, plan, &response, secrets, boundary.attempted())?
        {
            ApiBoundaryResponseOutcome::Ready {
                response_value,
                apply_evidence,
                lineage_evidence,
            } => (response_value, apply_evidence, lineage_evidence),
            ApiBoundaryResponseOutcome::Recovery(envelope) => return Ok(envelope),
        };
    if !response.success {
        return Ok(post_boundary_failure_envelope(
            plan,
            response_value,
            Some(apply_evidence),
            lineage_evidence,
            &CliError::Input(
                "Cloudflare did not complete the approved poll continuation".to_owned(),
            ),
            boundary.attempted(),
            "the poll-only boundary was crossed but provider completion was not proven",
        ));
    }
    if let Err(error) = exact_durable_resume_provider_complete_boundary(store, plan) {
        plan.status = PlanStatus::RectificationRequired;
        if let Err(error) = store.save_plan(plan) {
            return Ok(post_boundary_failure_envelope(
                plan,
                response_value,
                Some(apply_evidence),
                lineage_evidence,
                &CliError::from(error),
                boundary.attempted(),
                "the import response was received, but its local checkpoint failed; preserve the consumed operation and rectify without replay",
            ));
        }
        return Ok(post_boundary_failure_envelope(
            plan,
            response_value,
            Some(apply_evidence),
            lineage_evidence,
            &error,
            boundary.attempted(),
            "the poll-only boundary was crossed but exact durable provider completion was not proven",
        ));
    }
    if plan.capability.id == "d1-resume-database-import-poll" {
        let verification = match verify_api_plan(
            store,
            executor,
            plan,
            &response,
            execution_input,
            credential,
        )
        .await
        {
            Ok(verification) => verification,
            Err(error) => {
                return Ok(post_boundary_failure_envelope(
                    plan,
                    response_value,
                    Some(apply_evidence),
                    lineage_evidence,
                    &error,
                    boundary.attempted(),
                    "the reviewed-Git D1 import completed through a poll child, but its exact source receipt could not be persisted",
                ));
            }
        };
        let finalization: Result<()> =
            if matches!(plan.status, PlanStatus::Verified | PlanStatus::Failed) {
                persist_transaction_stage(store, plan, TransactionStageV1::Closed)
            } else {
                store.save_plan(plan).map_err(CliError::from)
            };
        let finalization_error = finalization.err();
        return Ok(api_plan_result_envelope(
            plan,
            response_value,
            apply_evidence,
            lineage_evidence,
            verification,
            boundary.attempted(),
            finalization_error.as_ref(),
        ));
    }
    plan.status = PlanStatus::Running;
    if let Err(error) = store.save_plan(plan) {
        return Ok(post_boundary_failure_envelope(
            plan,
            response_value,
            Some(apply_evidence),
            lineage_evidence,
            &CliError::from(error),
            boundary.attempted(),
            "the import response was received, but its local checkpoint failed; preserve the consumed operation and rectify without replay",
        ));
    }
    let mut envelope =
        ResultEnvelopeV2::success("plans run", response_value).with_evidence(apply_evidence);
    envelope.ok = false;
    envelope.performed = boundary.attempted();
    envelope.operation_id = Some(plan.operation_id.clone());
    envelope.capability_id = Some(plan.capability.id.clone());
    envelope.profile_id = Some(plan.profile_id.clone());
    envelope.account_id = Some(plan.account_id.clone());
    envelope.policy_decision = Some(plan.policy.clone());
    envelope.verification.state = VerificationState::Pending;
    envelope.verification.basis = Some(
        "poll-child provider_complete is durable and joined to the root import; governed post-import proof remains required"
            .to_owned(),
    );
    envelope.error = Some(ErrorV1 {
        code: "CFCTL_D1_IMPORT_POST_IMPORT_PROOF_REQUIRED".to_owned(),
        message: "D1 import completed through a poll child but is not publication proof".to_owned(),
        next_step: plan
            .targets
            .pointer("/adapter/approved_mln_import_poll_resume/root_operation_id")
            .and_then(Value::as_str)
            .map(|root| {
                format!(
                    "Run the governed migration-specific post_import read bound to root operation {root}, then run `cfctl plans rectify {root}`."
                )
            }),
    });
    if let Some(evidence) = lineage_evidence {
        envelope.evidence.push(evidence);
    }
    Ok(envelope)
}
