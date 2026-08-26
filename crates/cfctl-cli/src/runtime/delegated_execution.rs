use super::api_boundary::persist_secret_lifecycle;
use super::cloudflare_api::BASE_URL as API_BASE_URL;
use super::governed_cli::governed_cli_workspace_env;
use super::governed_cli::redact_subprocess_text;
use super::governed_cli::run_delegated_cli;
use super::governed_cli::run_quick_tunnel;
use super::governed_cli::verify_quick_tunnel_plan;
use super::plan_commands::persist_transaction_stage;
use super::plan_commands::persist_transaction_stage_with_artifact;
use super::prelude::{
    AuthCredential, BTreeSet, CallInput, CatalogSnapshot, CliError, Duration, ErrorV1,
    EvidenceClass, EvidenceV1, Executor, Path, PathBuf, PlanStatus, PlanV1, ProcessCommand, Result,
    ResultEnvelopeV2, SecretStore, StateStore, Stdio, TransactionStageV1, Uuid, Value,
    VerificationState, env, json,
};
use super::support::cli_io;
use super::support::http_client;
use super::{
    pages_deployment, worker_deployment, workspace_d1_migration, workspace_d1_projection,
    workspace_d1_reply_admission, workspace_reply_subdomain_ingress,
};
use cfctl_core::hash_value;

pub(super) async fn execute_delegated_plan(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    plan: &mut PlanV1,
    input: &CallInput,
    credential: &AuthCredential,
    secrets: &dyn SecretStore,
) -> Result<ResultEnvelopeV2> {
    let mut receipt = Box::pin(run_delegated_plan_boundary(store, plan, input, credential)).await?;
    let success = receipt
        .get("success")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let evidence = store.write_evidence(EvidenceClass::Apply, &receipt)?;
    persist_delegated_boundary_result(store, plan, success, &receipt, &evidence, secrets)?;
    if !success {
        if workspace_reply_subdomain_ingress::is_unperformed_fresh_precondition_failure(&receipt) {
            return Ok(reply_subdomain_fresh_precondition_failure_envelope(
                plan, receipt, evidence,
            ));
        }
        // A delegated CLI can fail after applying part of a mutation (Wrangler
        // may upload and promote a Worker before a trigger update fails). Keep
        // the transaction open for rectification and report that the boundary
        // was performed; a non-zero exit is not proof of zero side effects.
        return Ok(delegated_cli_failure_envelope(plan, receipt, evidence));
    }

    persist_transaction_stage(
        store,
        plan,
        TransactionStageV1::VerificationAttemptPersisted,
    )?;
    let verification =
        verify_delegated_cli_plan(store, catalog, plan, input, &receipt, credential).await;
    if let Some(deployment_id) = verification.get("deployment_id").and_then(Value::as_str) {
        receipt["deployment_id"] = Value::String(deployment_id.to_owned());
    }
    let verification_evidence =
        store.write_evidence(EvidenceClass::PostChangeVerification, &verification)?;
    let passed = verification
        .get("passed")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let basis = verification
        .get("basis")
        .and_then(Value::as_str)
        .unwrap_or("delegated CLI verification did not return a basis")
        .to_owned();
    plan.status = if passed {
        PlanStatus::Verified
    } else {
        PlanStatus::RectificationRequired
    };
    persist_transaction_stage_with_artifact(
        store,
        plan,
        TransactionStageV1::VerificationResponsePersisted,
        json!({
            "state": if passed { "passed" } else { "failed" },
            "basis_hash": hash_value(&json!(basis))?,
            "evidence_hash": verification_evidence.content_hash,
        }),
    )?;
    if passed {
        persist_transaction_stage(store, plan, TransactionStageV1::Closed)?;
    } else {
        store.save_plan(plan)?;
    }

    let mut envelope = ResultEnvelopeV2::success("plans run", receipt).with_evidence(evidence);
    envelope.evidence.push(verification_evidence);
    envelope.ok = passed;
    envelope.performed = true;
    envelope.operation_id = Some(plan.operation_id.clone());
    envelope.capability_id = Some(plan.capability.id.clone());
    envelope.profile_id = Some(plan.profile_id.clone());
    envelope.account_id = Some(plan.account_id.clone());
    envelope.policy_decision = Some(plan.policy.clone());
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
            next_step: Some(format!(
                "Do not replay the deployment; inspect live state with `cfctl plans rectify {}`.",
                plan.operation_id
            )),
        });
    }
    Ok(envelope)
}

pub(super) fn persist_delegated_boundary_result(
    store: &StateStore,
    plan: &mut PlanV1,
    success: bool,
    receipt: &Value,
    evidence: &EvidenceV1,
    secrets: &dyn SecretStore,
) -> Result<()> {
    // The status recorded by each checkpoint is part of the journal hash. A
    // failing delegated command can have crossed a mutation boundary, so bind
    // rectification_required before persisting either post-boundary receipt.
    // Changing status afterward makes the otherwise valid journal unreadable.
    if !success {
        plan.status = PlanStatus::RectificationRequired;
    }
    persist_transaction_stage_with_artifact(
        store,
        plan,
        TransactionStageV1::BoundaryResponsePersisted,
        json!({
            "adapter": "delegated_cli",
            "apply_evidence_hash": evidence.content_hash,
            "success": success,
            "boundary_crossed": receipt.get("boundary_crossed").and_then(Value::as_bool),
        }),
    )?;
    persist_secret_lifecycle(store, plan, success, Some(receipt), secrets).map(|_| ())
}

pub(super) async fn run_delegated_plan_boundary(
    store: &StateStore,
    plan: &PlanV1,
    input: &CallInput,
    credential: &AuthCredential,
) -> Result<Value> {
    if plan
        .capability
        .workspace_reply_subdomain_ingress
        .as_ref()
        .is_some_and(|contract| contract.operation_kind == "activate")
    {
        return Box::pin(workspace_reply_subdomain_ingress::run(
            store, plan, credential,
        ))
        .await;
    }
    if plan.capability.workspace_d1_migration.is_some() {
        return workspace_d1_migration::run(store, plan, credential).await;
    }
    if plan.capability.workspace_d1_policy_projection.is_some() {
        return workspace_d1_projection::run(store, plan, credential).await;
    }
    if plan.capability.workspace_d1_reply_admission.is_some() {
        return Box::pin(workspace_d1_reply_admission::run(store, plan, credential)).await;
    }
    let adapter_targets = plan.targets.get("adapter").unwrap_or(&Value::Null);
    let mut delegated_input =
        worker_deployment::delegated_execution_input(&plan.capability, input, adapter_targets)?;
    let (bound_program, bound_interpreter) = if pages_deployment::binds_artifact(&plan.capability) {
        (
            Some(pages_deployment::bound_wrangler_executable(
                adapter_targets,
            )?),
            pages_deployment::bound_wrangler_interpreter(adapter_targets)?,
        )
    } else {
        (None, None)
    };
    let _staged_pages_artifact = if pages_deployment::binds_artifact(&plan.capability) {
        Some(pages_deployment::stage_bound_artifact(
            adapter_targets,
            &mut delegated_input,
        )?)
    } else {
        None
    };
    if pages_deployment::binds_artifact(&plan.capability) {
        // Staging may be proportional to the admitted artifact. Recheck the
        // private staged bytes first, then make the complete mutable producer
        // closure the final check immediately before subprocess construction.
        pages_deployment::validate_staged_artifact(adapter_targets, &delegated_input)?;
        pages_deployment::validate_bound_producer(&plan.capability, adapter_targets)?;
    }
    let receipt = if plan.capability.id == "cloudflared.tunnel" {
        run_quick_tunnel(store, plan, input).await?
    } else {
        run_delegated_cli(
            &plan.capability,
            &delegated_input,
            credential,
            Some(&plan.account_id),
            &store.paths().cache_dir,
            bound_program.as_deref(),
            bound_interpreter.as_deref(),
        )
        .await?
    };
    Ok(receipt)
}

pub(super) fn delegated_cli_failure_envelope(
    plan: &PlanV1,
    receipt: Value,
    evidence: EvidenceV1,
) -> ResultEnvelopeV2 {
    let mut envelope = ResultEnvelopeV2::success("plans run", receipt).with_evidence(evidence);
    envelope.ok = false;
    envelope.performed = true;
    envelope.operation_id = Some(plan.operation_id.clone());
    envelope.capability_id = Some(plan.capability.id.clone());
    envelope.profile_id = Some(plan.profile_id.clone());
    envelope.account_id = Some(plan.account_id.clone());
    envelope.policy_decision = Some(plan.policy.clone());
    envelope.verification.state = VerificationState::Failed;
    envelope.verification.basis =
        Some("the governed subprocess returned a failing exit status".to_owned());
    envelope.error = Some(ErrorV1 {
        code: "CFCTL_DELEGATED_CLI_FAILED".to_owned(),
        message:
            "the governed subprocess returned a failing exit status; partial mutation is possible"
                .to_owned(),
        next_step: Some(format!(
            "Do not replay automatically; inspect the receipt and use `cfctl plans rectify {}`.",
            plan.operation_id
        )),
    });
    envelope
}

pub(super) fn reply_subdomain_fresh_precondition_failure_envelope(
    plan: &PlanV1,
    receipt: Value,
    evidence: EvidenceV1,
) -> ResultEnvelopeV2 {
    let status = receipt
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("fresh_provider_precondition_unproved")
        .to_owned();
    let mut envelope = ResultEnvelopeV2::success("plans run", receipt).with_evidence(evidence);
    envelope.ok = false;
    envelope.performed = false;
    envelope.operation_id = Some(plan.operation_id.clone());
    envelope.capability_id = Some(plan.capability.id.clone());
    envelope.profile_id = Some(plan.profile_id.clone());
    envelope.account_id = Some(plan.account_id.clone());
    envelope.policy_decision = Some(plan.policy.clone());
    envelope.verification.state = VerificationState::Failed;
    envelope.verification.basis = Some(format!(
        "fresh reply-subdomain provider precondition `{status}` stopped before the catch-all PUT"
    ));
    envelope.error = Some(ErrorV1 {
        code: "CFCTL_WORKSPACE_REPLY_SUBDOMAIN_FRESH_PRECONDITION_FAILED".to_owned(),
        message: format!(
            "fresh reply-subdomain provider state `{status}` no longer matches the approved plan; the catch-all PUT was not attempted"
        ),
        next_step: Some(format!(
            "The plan is consumed and must not be replayed. Inspect `cfctl plans status {} --json`, reconcile `{status}`, and create a fresh PlanV2.",
            plan.operation_id
        )),
    });
    envelope
}

#[expect(
    clippy::too_many_lines,
    reason = "the delegated verification dispatcher keeps every closed strategy explicit and fails unknown strategies without an implicit fallback"
)]
pub(super) async fn verify_delegated_cli_plan(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    plan: &PlanV1,
    input: &CallInput,
    receipt: &Value,
    credential: &AuthCredential,
) -> Value {
    if plan
        .capability
        .workspace_reply_subdomain_ingress
        .as_ref()
        .is_some_and(|contract| contract.operation_kind == "activate")
    {
        return workspace_reply_subdomain_ingress::verify(store, plan, credential).await;
    }
    if plan.capability.workspace_d1_migration.is_some() {
        return workspace_d1_migration::verify(store, plan, credential).await;
    }
    if plan.capability.workspace_d1_policy_projection.is_some() {
        return workspace_d1_projection::verify(store, plan, credential).await;
    }
    if plan.capability.workspace_d1_reply_admission.is_some() {
        return Box::pin(workspace_d1_reply_admission::verify(
            store, plan, credential,
        ))
        .await;
    }
    if plan.capability.verification.strategy == "trycloudflare_https_url_reaches_reviewed_origin" {
        return verify_quick_tunnel_plan(input, receipt).await;
    }
    if plan.capability.verification.strategy
        == "wrangler_pages_new_deployment_succeeds_by_returned_id"
    {
        let Some(project_name) = input
            .query
            .get("project_name")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        else {
            return json!({
                "passed": false,
                "basis": "the Pages deployment plan omitted its required project_name selector",
            });
        };
        let Some(branch) = input
            .query
            .get("branch")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        else {
            return json!({
                "passed": false,
                "basis": "the Pages deployment plan omitted its required branch selector",
                "project_name": project_name,
            });
        };
        let Some(commit_hash) = input
            .query
            .get("commit_hash")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        else {
            return json!({
                "passed": false,
                "basis": "the Pages deployment plan omitted its required commit_hash selector",
                "project_name": project_name,
                "branch": branch,
            });
        };
        return verify_wrangler_pages_production_deployment(
            catalog,
            plan,
            project_name,
            branch,
            commit_hash,
            receipt,
            credential,
        )
        .await;
    }

    if plan.capability.verification.strategy == "wrangler_worker_version_reports_expected_message" {
        return verify_wrangler_worker_version_upload_plan(store, plan, input, receipt, credential)
            .await;
    }

    if plan.capability.verification.strategy
        == "wrangler_worker_versions_deployment_reports_expected_traffic"
    {
        return verify_wrangler_worker_versions_deploy_plan(store, plan, input, credential).await;
    }

    if plan.capability.verification.strategy
        != "wrangler_deployment_status_reports_promoted_version"
    {
        return json!({
            "passed": false,
            "basis": format!(
                "delegated CLI verification strategy `{}` is not implemented",
                plan.capability.verification.strategy
            ),
        });
    }
    let Some(version_id) = wrangler_deploy_version_id(receipt) else {
        return json!({
            "passed": false,
            "basis": "Wrangler reported deploy success without a parseable Current Version ID",
        });
    };
    let Some(config) = input
        .query
        .get("config")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    else {
        return json!({
            "passed": false,
            "basis": "the deployment plan omitted its required Wrangler config selector",
            "version_id": version_id,
        });
    };

    verify_wrangler_deployment_status(
        WranglerDeploymentStatusTarget::Config(config),
        &version_id,
        credential,
        &plan.account_id,
        &store.paths().cache_dir,
    )
    .await
}

pub(super) async fn verify_wrangler_worker_version_upload_plan(
    store: &StateStore,
    plan: &PlanV1,
    input: &CallInput,
    receipt: &Value,
    credential: &AuthCredential,
) -> Value {
    let Some(version_id) = wrangler_worker_version_id(receipt) else {
        return json!({
            "passed": false,
            "basis": "Wrangler reported upload success without a parseable Worker Version ID",
        });
    };
    let Some(config) = input.query.get("config").and_then(Value::as_str) else {
        return json!({
            "passed": false,
            "basis": "the version upload plan omitted its required Wrangler config selector",
            "version_id": version_id,
        });
    };
    let Some(message) = input.query.get("message").and_then(Value::as_str) else {
        return json!({
            "passed": false,
            "basis": "the version upload plan omitted its required message selector",
            "version_id": version_id,
        });
    };
    verify_wrangler_worker_version(
        config,
        &version_id,
        message,
        credential,
        &plan.account_id,
        &store.paths().cache_dir,
    )
    .await
}

pub(super) async fn verify_wrangler_worker_versions_deploy_plan(
    store: &StateStore,
    plan: &PlanV1,
    input: &CallInput,
    credential: &AuthCredential,
) -> Value {
    let Some(version_id) = input
        .query
        .get("argument")
        .and_then(Value::as_str)
        .and_then(wrangler_versions_deploy_version_id)
    else {
        return json!({
            "passed": false,
            "basis": "the versions deployment plan did not contain exactly one UUID@100 traffic target",
        });
    };
    let adapter_targets = plan.targets.get("adapter").unwrap_or(&Value::Null);
    let Ok(service_name) = worker_deployment::service_name(adapter_targets) else {
        return json!({
            "passed": false,
            "basis": "the versions deployment plan omitted its exact reviewed service identity",
            "version_id": version_id,
        });
    };
    verify_wrangler_deployment_status(
        WranglerDeploymentStatusTarget::Service(service_name),
        &version_id,
        credential,
        &plan.account_id,
        &store.paths().cache_dir,
    )
    .await
}

#[expect(
    clippy::too_many_lines,
    reason = "the Pages verifier keeps returned identity, collection visibility, and exact terminal polling as one fail-closed lifecycle"
)]
pub(super) async fn verify_wrangler_pages_production_deployment(
    catalog: &CatalogSnapshot,
    plan: &PlanV1,
    project_name: &str,
    branch: &str,
    commit_hash: &str,
    receipt: &Value,
    credential: &AuthCredential,
) -> Value {
    const MAX_DISCOVERY_ATTEMPTS: usize = 30;
    const MAX_POLL_ATTEMPTS: usize = 120;
    const POLL_INTERVAL: Duration = Duration::from_secs(1);
    let Some(prior_ids) = plan
        .targets
        .pointer(&format!(
            "/live_preconditions/{}/prior_deployment_ids",
            pages_deployment::PROJECT_STATE_PRECONDITION
        ))
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<BTreeSet<_>>()
        })
    else {
        return json!({
            "passed": false,
            "basis": "the Pages direct-upload plan omitted its pre-bound deployment identity set",
        });
    };
    let Some(deployment_id) = receipt
        .pointer("/structured_output/deployment_id")
        .and_then(Value::as_str)
        .filter(|id| Uuid::parse_str(id).is_ok_and(|parsed| parsed.hyphenated().to_string() == *id))
        .map(str::to_owned)
    else {
        return json!({
            "passed": false,
            "basis": "Wrangler did not return one canonical deployment ID in its governed structured output",
        });
    };
    let structured = receipt.get("structured_output").unwrap_or(&Value::Null);
    if !pages_deployment::structured_output_matches(structured, project_name, branch, commit_hash) {
        return json!({
            "passed": false,
            "basis": "Wrangler returned a deployment ID with a different project, environment, branch, or commit identity",
            "deployment_id": deployment_id,
            "structured_output": structured,
        });
    }
    if prior_ids.contains(&deployment_id) {
        return json!({
            "passed": false,
            "basis": "Wrangler returned a deployment ID that existed before the upload boundary",
            "deployment_id": deployment_id,
        });
    }
    let Some(list) = catalog.get(pages_deployment::DEPLOYMENT_LIST_CAPABILITY_ID) else {
        return json!({
            "passed": false,
            "basis": "the Pages deployment collection read is absent from the bound catalog",
        });
    };
    let Some(details) = catalog.get(pages_deployment::DEPLOYMENT_READ_CAPABILITY_ID) else {
        return json!({
            "passed": false,
            "basis": "the exact Pages deployment detail read is absent from the bound catalog",
        });
    };
    if list.method != "GET"
        || list.path != pages_deployment::DEPLOYMENT_LIST_PATH
        || list.mutating
        || details.method != "GET"
        || details.path != pages_deployment::DEPLOYMENT_DETAIL_PATH
        || details.mutating
    {
        return json!({
            "passed": false,
            "basis": "the Pages deployment verification read contracts drifted from their exact collection/detail identities",
        });
    }
    let client = match http_client() {
        Ok(client) => client,
        Err(error) => {
            return json!({"passed":false,"basis":format!("Pages verifier could not construct its HTTP client: {error}")});
        }
    };
    let executor = match Executor::new(client, API_BASE_URL) {
        Ok(executor) => executor,
        Err(error) => {
            return json!({"passed":false,"basis":format!("Pages verifier could not initialize: {error}")});
        }
    };
    let mut collection_readback = Value::Null;
    let mut discovered = false;
    for attempt in 0..MAX_DISCOVERY_ATTEMPTS {
        let list_response = match executor
            .execute_read(
                list,
                &CallInput {
                    selectors: json!({
                        "account_id": plan.account_id,
                        "project_name": project_name,
                    }),
                    query: json!({}),
                    body: None,
                    ..CallInput::default()
                },
                credential,
            )
            .await
        {
            Ok(response) if response.success && response.status == 200 => response,
            Ok(response) => {
                return json!({
                    "passed": false,
                    "basis": format!("Pages deployment collection read returned HTTP {} after the upload boundary", response.status),
                    "deployment_id": deployment_id,
                    "readback": response,
                });
            }
            Err(error) => {
                return json!({
                    "passed": false,
                    "basis": format!("Pages deployment collection read failed after the upload boundary: {error}"),
                    "deployment_id": deployment_id,
                });
            }
        };
        discovered = pages_deployment::deployment_matches_returned_id(
            &list_response.result,
            &deployment_id,
            project_name,
            branch,
            commit_hash,
        );
        collection_readback = json!(list_response);
        if discovered {
            break;
        }
        if attempt + 1 < MAX_DISCOVERY_ATTEMPTS {
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }
    if !discovered {
        return json!({
            "passed": false,
            "basis": format!("the provider-returned Pages deployment {deployment_id} was not visible with the exact reviewed project, branch, and commit after {MAX_DISCOVERY_ATTEMPTS} bounded attempts"),
            "deployment_id": deployment_id,
            "readback": collection_readback,
        });
    }
    for attempt in 0..MAX_POLL_ATTEMPTS {
        let readback = match executor
            .execute_read(
                details,
                &CallInput {
                    selectors: json!({
                        "account_id": plan.account_id,
                        "project_name": project_name,
                        "deployment_id": deployment_id,
                    }),
                    query: json!({}),
                    body: None,
                    ..CallInput::default()
                },
                credential,
            )
            .await
        {
            Ok(response) => response,
            Err(error) => {
                return json!({
                    "passed": false,
                    "basis": format!("exact Pages deployment read failed after the upload boundary: {error}"),
                    "deployment_id": deployment_id,
                });
            }
        };
        let identity_matches =
            readback.result.get("id").and_then(Value::as_str) == Some(deployment_id.as_str());
        let project_matches =
            readback.result.get("project_name").and_then(Value::as_str) == Some(project_name);
        let production =
            readback.result.get("environment").and_then(Value::as_str) == Some("production");
        let observed_branch = readback
            .result
            .pointer("/deployment_trigger/metadata/branch")
            .and_then(Value::as_str);
        let observed_commit = readback
            .result
            .pointer("/deployment_trigger/metadata/commit_hash")
            .and_then(Value::as_str);
        let stage = readback
            .result
            .pointer("/latest_stage/status")
            .and_then(Value::as_str);
        let invariant_matches = readback.status == 200
            && readback.success
            && identity_matches
            && project_matches
            && production
            && observed_branch == Some(branch)
            && observed_commit == Some(commit_hash);
        if invariant_matches && stage == Some("success") {
            return json!({
                "passed": true,
                "basis": format!("the exact new Pages deployment {deployment_id} for project {project_name} reached terminal production success"),
                "deployment_id": deployment_id,
                "readback": readback,
            });
        }
        let remains_active = invariant_matches && matches!(stage, Some("active" | "idle"));
        if remains_active && attempt + 1 < MAX_POLL_ATTEMPTS {
            tokio::time::sleep(POLL_INTERVAL).await;
            continue;
        }
        return json!({
            "passed": false,
            "basis": if remains_active {
                format!("the exact new Pages deployment {deployment_id} remained {stage:?} after {MAX_POLL_ATTEMPTS} bounded attempts")
            } else {
                format!("the exact new Pages deployment was not proven (HTTP {}, success={}, identity={}, project={}, production={}, branch={observed_branch:?}, commit={observed_commit:?}, stage={stage:?})", readback.status, readback.success, identity_matches, project_matches, production)
            },
            "deployment_id": deployment_id,
            "readback": readback,
        });
    }
    json!({
        "passed": false,
        "basis": "the Pages deployment verifier exhausted its bounded poll loop without a terminal receipt",
        "deployment_id": deployment_id,
    })
}

/// Wrangler discovers dotenv credentials relative to its process working
/// directory. A plan reviewed against one Worker config could therefore pass
/// its account checks and then resolve a different account token when cfctl
/// ran from somewhere else, so every governed Wrangler subprocess is pinned to
/// the reviewed config's own directory.
pub(super) fn wrangler_config_directory(config: &str) -> Result<PathBuf> {
    let parent = Path::new(config)
        .parent()
        .ok_or_else(|| CliError::Input("Wrangler config path has no parent".to_owned()))?;
    if parent.as_os_str().is_empty() {
        Ok(PathBuf::from("."))
    } else {
        Ok(parent.to_path_buf())
    }
}

pub(super) enum WranglerDeploymentStatusTarget<'a> {
    Config(&'a str),
    Service(&'a str),
}

pub(super) struct WranglerDeploymentStatusCommand<'a> {
    pub(super) command: ProcessCommand,
    pub(super) isolated_directory: Option<tempfile::TempDir>,
    pub(super) exact_service_name: Option<&'a str>,
}

pub(super) fn prepare_wrangler_deployment_status_command<'a>(
    target: WranglerDeploymentStatusTarget<'a>,
    account_id: &str,
    cache_dir: &Path,
) -> Result<WranglerDeploymentStatusCommand<'a>> {
    let mut command = ProcessCommand::new("wrangler");
    command.args(["deployments", "status"]);
    let (isolated_directory, exact_service_name) = match target {
        WranglerDeploymentStatusTarget::Config(config) => {
            command
                .args(["--config", config])
                .current_dir(wrangler_config_directory(config)?);
            (None, None)
        }
        WranglerDeploymentStatusTarget::Service(service_name) => {
            command.args(["--name", service_name]);
            let directory = tempfile::Builder::new()
                .prefix("configless-worker-readback-")
                .tempdir()
                .map_err(|source| cli_io(cache_dir, source))?;
            command.current_dir(directory.path());
            (Some(directory), Some(service_name))
        }
    };
    command
        .arg("--json")
        .env_clear()
        .env("PATH", env::var_os("PATH").unwrap_or_default())
        .env("HOME", env::var_os("HOME").unwrap_or_default())
        .env("NO_COLOR", "1")
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in governed_cli_workspace_env("wrangler", Some(account_id), cache_dir) {
        command.env(name, value);
    }
    Ok(WranglerDeploymentStatusCommand {
        command,
        isolated_directory,
        exact_service_name,
    })
}

pub(super) async fn verify_wrangler_deployment_status(
    target: WranglerDeploymentStatusTarget<'_>,
    version_id: &str,
    credential: &AuthCredential,
    account_id: &str,
    cache_dir: &Path,
) -> Value {
    let prepared = match prepare_wrangler_deployment_status_command(target, account_id, cache_dir) {
        Ok(prepared) => prepared,
        Err(error) => {
            return json!({
                "passed": false,
                "basis": format!("Wrangler deployment-status verification could not prepare its exact target: {error}"),
                "version_id": version_id,
            });
        }
    };
    let WranglerDeploymentStatusCommand {
        mut command,
        isolated_directory: _isolated_directory,
        exact_service_name,
    } = prepared;
    match credential {
        AuthCredential::Bearer { token } => {
            command.env("CLOUDFLARE_API_TOKEN", token);
        }
        AuthCredential::GlobalKey { email, key } => {
            command
                .env("CLOUDFLARE_EMAIL", email)
                .env("CLOUDFLARE_API_KEY", key);
        }
    }
    let output = match tokio::time::timeout(Duration::from_mins(2), command.output()).await {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => {
            return json!({
                "passed": false,
                "basis": format!("Wrangler deployment-status verification could not start: {error}"),
                "version_id": version_id,
            });
        }
        Err(_) => {
            return json!({
                "passed": false,
                "basis": "Wrangler deployment-status verification timed out",
                "version_id": version_id,
            });
        }
    };
    let stdout = redact_subprocess_text(&String::from_utf8_lossy(&output.stdout), credential);
    let stderr = redact_subprocess_text(&String::from_utf8_lossy(&output.stderr), credential);
    if !output.status.success() {
        return json!({
            "passed": false,
            "basis": "Wrangler deployment-status verification returned a failing exit status",
            "version_id": version_id,
            "exit_status": output.status.code(),
            "stdout": stdout,
            "stderr": stderr,
        });
    }
    let status = match serde_json::from_str::<Value>(stdout.trim()) {
        Ok(status) => status,
        Err(error) => {
            return json!({
                "passed": false,
                "basis": format!("Wrangler deployment-status output was not JSON: {error}"),
                "version_id": version_id,
                "stdout": stdout,
                "stderr": stderr,
            });
        }
    };
    let passed = wrangler_status_has_promoted_version(&status, version_id);
    json!({
        "passed": passed,
        "basis": if passed {
            exact_service_name.map_or_else(
                || format!("Wrangler production deployment reports promoted version {version_id}"),
                |service_name| format!("Wrangler production deployment for exact service {service_name} reports promoted version {version_id}"),
            )
        } else {
            exact_service_name.map_or_else(
                || format!("Wrangler production deployment does not report version {version_id} at 100 percent"),
                |service_name| format!("Wrangler production deployment for exact service {service_name} does not report version {version_id} at 100 percent"),
            )
        },
        "version_id": version_id,
        "service_name": exact_service_name,
        "readback": status,
        "stderr": stderr,
    })
}

pub(super) async fn verify_wrangler_worker_version(
    config: &str,
    version_id: &str,
    expected_message: &str,
    credential: &AuthCredential,
    account_id: &str,
    cache_dir: &Path,
) -> Value {
    let working_directory = match wrangler_config_directory(config) {
        Ok(directory) => directory,
        Err(error) => {
            return json!({
                "passed": false,
                "basis": format!("Wrangler version verification could not resolve the reviewed config directory: {error}"),
                "version_id": version_id,
            });
        }
    };
    let mut command = ProcessCommand::new("wrangler");
    command
        .args(["versions", "view", version_id, "--config", config, "--json"])
        .current_dir(working_directory)
        .env_clear()
        .env("PATH", env::var_os("PATH").unwrap_or_default())
        .env("HOME", env::var_os("HOME").unwrap_or_default())
        .env("NO_COLOR", "1")
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in governed_cli_workspace_env("wrangler", Some(account_id), cache_dir) {
        command.env(name, value);
    }
    match credential {
        AuthCredential::Bearer { token } => {
            command.env("CLOUDFLARE_API_TOKEN", token);
        }
        AuthCredential::GlobalKey { email, key } => {
            command
                .env("CLOUDFLARE_EMAIL", email)
                .env("CLOUDFLARE_API_KEY", key);
        }
    }
    let output = match tokio::time::timeout(Duration::from_mins(2), command.output()).await {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => {
            return json!({
                "passed": false,
                "basis": format!("Wrangler version verification could not start: {error}"),
                "version_id": version_id,
            });
        }
        Err(_) => {
            return json!({
                "passed": false,
                "basis": "Wrangler version verification timed out",
                "version_id": version_id,
            });
        }
    };
    let stdout = redact_subprocess_text(&String::from_utf8_lossy(&output.stdout), credential);
    let stderr = redact_subprocess_text(&String::from_utf8_lossy(&output.stderr), credential);
    if !output.status.success() {
        return json!({
            "passed": false,
            "basis": "Wrangler version verification returned a failing exit status",
            "version_id": version_id,
            "exit_status": output.status.code(),
            "stdout": stdout,
            "stderr": stderr,
        });
    }
    let version = match serde_json::from_str::<Value>(stdout.trim()) {
        Ok(version) => version,
        Err(error) => {
            return json!({
                "passed": false,
                "basis": format!("Wrangler version output was not JSON: {error}"),
                "version_id": version_id,
                "stdout": stdout,
                "stderr": stderr,
            });
        }
    };
    let passed = wrangler_version_readback_matches(&version, version_id, expected_message);
    json!({
        "passed": passed,
        "basis": if passed {
            format!("Wrangler reports uploaded version {version_id} with the reviewed message")
        } else {
            format!("Wrangler version readback did not bind {version_id} to the reviewed message")
        },
        "version_id": version_id,
        "readback": version,
        "stderr": stderr,
    })
}

pub(super) fn wrangler_deploy_version_id(receipt: &Value) -> Option<String> {
    receipt
        .get("stdout")
        .and_then(Value::as_str)?
        .lines()
        .find_map(|line| line.trim().strip_prefix("Current Version ID:"))
        .map(str::trim)
        .filter(|value| {
            !value.is_empty()
                && value
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
        })
        .map(str::to_owned)
}

pub(super) fn wrangler_worker_version_id(receipt: &Value) -> Option<String> {
    receipt
        .get("stdout")
        .and_then(Value::as_str)?
        .lines()
        .find_map(|line| line.trim().strip_prefix("Worker Version ID:"))
        .map(str::trim)
        .filter(|value| Uuid::parse_str(value).is_ok())
        .map(str::to_owned)
}

pub(super) fn wrangler_versions_deploy_version_id(spec: &str) -> Option<String> {
    let (version_id, percentage) = spec.split_once('@')?;
    if percentage == "100" && Uuid::parse_str(version_id).is_ok() {
        Some(version_id.to_owned())
    } else {
        None
    }
}

pub(super) fn wrangler_version_readback_matches(
    value: &Value,
    expected_version_id: &str,
    expected_message: &str,
) -> bool {
    value.get("id").and_then(Value::as_str) == Some(expected_version_id)
        && value
            .pointer("/annotations/workers~1message")
            .and_then(Value::as_str)
            == Some(expected_message)
}

pub(super) fn wrangler_status_has_promoted_version(
    value: &Value,
    expected_version_id: &str,
) -> bool {
    match value {
        Value::Array(items) => items
            .iter()
            .any(|item| wrangler_status_has_promoted_version(item, expected_version_id)),
        Value::Object(fields) => {
            let matches = fields
                .get("version_id")
                .and_then(Value::as_str)
                .is_some_and(|version_id| version_id == expected_version_id);
            let promoted = fields.get("percentage").is_some_and(|percentage| {
                percentage
                    .as_f64()
                    .is_some_and(|percentage| (percentage - 100.0).abs() < f64::EPSILON)
                    || percentage.as_str() == Some("100")
            });
            (matches && promoted)
                || fields
                    .values()
                    .any(|value| wrangler_status_has_promoted_version(value, expected_version_id))
        }
        _ => false,
    }
}
