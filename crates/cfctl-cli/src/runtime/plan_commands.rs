use super::api_boundary::blocked_capability_envelope;
use super::api_boundary::boundary_failure_artifact;
use super::api_boundary::persist_secret_lifecycle;
use super::api_execution::execute_api_plan;
use super::call_input::parse_money;
use super::call_input::verification_for_status;
use super::compensation::resume_plan;
use super::credential_resolution::ensure_catalog;
use super::credential_resolution::fresh_credential;
use super::credential_resolution::platform_secrets;
use super::delegated_execution::execute_delegated_plan;
use super::error::plan_status_label;
use super::governed_cli::execute_governed_ui_plan;
use super::import_planning::ImportPrerequisiteContext;
use super::import_planning::validate_approved_mln_import_prerequisites;
use super::import_resume::validate_and_derive_resume_poll_authority;
use super::pages_source::plan_impact;
use super::plan_create::validate_live_kv_empty_namespace_state_precondition;
use super::plan_prepare::validate_api_token_creation_contract;
use super::policy_commands::active_admission_policy;
use super::preconditions_authority::validate_live_access_operator_group_policy_ownership_precondition;
use super::preconditions_authority::validate_live_entitlement_precondition;
use super::preconditions_authority::validate_live_permission_inventory_precondition;
use super::preconditions_authority::validate_live_security_action_state_precondition;
use super::preconditions_authority::validate_live_zone_account_precondition;
use super::preconditions_core::validate_live_cloudflare_tunnel_configuration_state_precondition;
use super::preconditions_core::validate_live_d1_empty_database_state_precondition;
use super::preconditions_core::validate_live_d1_read_replication_state_precondition;
use super::preconditions_core::validate_live_global_warp_override_state_precondition;
use super::preconditions_core::validate_live_pages_deployment_project_state_precondition;
use super::preconditions_core::validate_live_pages_project_absence_precondition;
use super::preconditions_core::validate_live_r2_parent_token_precondition;
use super::preconditions_core::validate_live_worker_deployment_state_precondition;
use super::preconditions_extended::validate_live_dns_record_state_precondition;
use super::preconditions_extended::validate_live_oauth_client_secret_state_precondition;
use super::preconditions_extended::validate_live_oauth_client_update_state_precondition;
use super::preconditions_extended::validate_live_same_path_prior_state_precondition;
use super::preconditions_extended::validate_live_warp_connector_configuration_state_precondition;
use super::preconditions_extended::validate_live_web_analytics_rum_state_precondition;
use super::prelude::{
    AdapterStatus, AuthCredential, CallInput, CatalogSnapshot, CliError, DeploymentPlanSetCommand,
    EvidenceClass, EvidenceV1, PlanApproveArgs, PlanSelector, PlanStatus, PlanV1, PlansCommand,
    PolicyEngine, ProfileKind, ProfileMetadata, ProfilesConfig, Result, ResultEnvelopeV2,
    SecretStore, StandingAuthorityV1, StateStore, StoredPlanRecord, TransactionStageV1, Utc, Value,
    VerificationState, json,
};
use super::r2_credentials::is_r2_temporary_credentials_operation_identity;
use super::rectification::rectify_plan;
use super::secret_io::preflight_secret_sink;
use super::secret_io::resolved_plan_input;
use super::workspace_state::discover_registered;
use super::workspace_state::validate_plan_preconditions;
use super::workspace_state::validate_worker_deployment_local_authority;
use super::{
    event_batch, pages_deployment, plan_set, worker_custom_domain, worker_deployment,
    workspace_reply_subdomain_ingress,
};
use crate::build_identity::current_build_info;
use cfctl_cloudflare::validate_request_contract;
use cfctl_core::AttestationStatusV1;
use cfctl_core::hash_value;

pub(super) async fn plans_command(
    store: &StateStore,
    command: PlansCommand,
) -> Result<ResultEnvelopeV2> {
    match command {
        PlansCommand::Show(selector) | PlansCommand::Status(selector) => {
            show_plan(store, &selector)
        }
        PlansCommand::Approve(arguments) => approve_plan(store, &arguments),
        PlansCommand::Run(selector) => Box::pin(run_plan(store, &selector)).await,
        PlansCommand::Resume(selector) => Box::pin(resume_plan(store, &selector)).await,
        PlansCommand::Rectify(selector) => Box::pin(rectify_plan(store, &selector)).await,
        PlansCommand::Cancel(selector) => cancel_plan(store, &selector),
        PlansCommand::Bundle(arguments) => match arguments.command {
            DeploymentPlanSetCommand::Create(arguments) => plan_set::create(store, &arguments),
            DeploymentPlanSetCommand::Show(selector) => plan_set::show(store, &selector),
            DeploymentPlanSetCommand::Verify(selector) => {
                Box::pin(plan_set::verify(store, &selector)).await
            }
        },
    }
}

pub(super) fn load_validated_plan(store: &StateStore, operation_id: &str) -> Result<PlanV1> {
    let record = store.load_stored_plan_record(operation_id)?;
    let plan = match record {
        StoredPlanRecord::Current(plan) => plan.plan,
        StoredPlanRecord::LegacyReadable(plan) | StoredPlanRecord::RequiredSidecarMissing(plan) => {
            *plan
        }
        StoredPlanRecord::ProjectionDrift { .. } => {
            return Err(CliError::guided(
                "CFCTL_PLAN_V2_DRIFT",
                format!(
                    "PlanV2 `{operation_id}` disagrees with its PlanV1 compatibility projection"
                ),
                "Do not approve, run, or resume this plan. Inspect the canonical PlanV2 and repair its compatibility projection before proceeding.",
            ));
        }
        StoredPlanRecord::Corrupt { reason, .. } => {
            return Err(CliError::guided(
                "CFCTL_PLAN_CORRUPT",
                format!("plan `{operation_id}` is corrupt: {reason}"),
                "Do not replay or replace the plan in place. Preserve the files and inspect the exact durable record before recovery.",
            ));
        }
    };
    plan.validate_transaction_journal()?;
    Ok(plan)
}

pub(super) fn ensure_capability_execution_supported(plan: &PlanV1) -> Result<()> {
    if !plan.capability.execution_supported {
        return Err(CliError::guided(
            "CFCTL_PLAN_EXECUTION_UNSUPPORTED",
            format!(
                "capability `{}` compiles reviewable PlanV2 previews but has no execution authority",
                plan.capability.id
            ),
            "Keep this plan as a source-qualified child receipt. Do not approve, run, resume, or rectify it; introduce and qualify a separate native execution capability before any provider effect.",
        ));
    }
    Ok(())
}

pub(super) fn ensure_plan_execution_contract(store: &StateStore, plan: &PlanV1) -> Result<()> {
    ensure_capability_execution_supported(plan)?;
    match store.load_stored_plan_record(&plan.operation_id)? {
        StoredPlanRecord::Current(_) => Ok(()),
        StoredPlanRecord::LegacyReadable(_) => Err(CliError::guided(
            "CFCTL_PLAN_REPLAN_REQUIRED",
            format!(
                "historical PlanV1 mutation `{}` remains readable but cannot be approved or executed",
                plan.operation_id
            ),
            format!(
                "Re-run `cfctl call {}` with the original reviewed selectors and body to create a fully pinned PlanV2.",
                plan.capability.id
            ),
        )),
        StoredPlanRecord::RequiredSidecarMissing(_) => Err(CliError::guided(
            "CFCTL_PLAN_V2_MISSING",
            format!(
                "current mutation plan `{}` is missing its required canonical PlanV2 document",
                plan.operation_id
            ),
            format!(
                "Do not approve or execute this incomplete plan. Re-run `cfctl call {}` to create a new fully pinned PlanV2.",
                plan.capability.id
            ),
        )),
        StoredPlanRecord::ProjectionDrift { .. } => Err(CliError::guided(
            "CFCTL_PLAN_V2_DRIFT",
            "the canonical PlanV2 disagrees with its PlanV1 compatibility projection",
            "Do not approve, run, or resume this plan until its durable projection is repaired.",
        )),
        StoredPlanRecord::Corrupt { reason, .. } => Err(CliError::guided(
            "CFCTL_PLAN_CORRUPT",
            reason,
            "Preserve the durable files and inspect the exact plan record before recovery.",
        )),
    }
}

pub(super) fn validate_plan_v2_runtime_pins(
    store: &StateStore,
    plan: &PlanV1,
    profile: &ProfileMetadata,
) -> Result<()> {
    let StoredPlanRecord::Current(plan_v2) = store.load_stored_plan_record(&plan.operation_id)?
    else {
        ensure_plan_execution_contract(store, plan)?;
        return Err(CliError::guided(
            "CFCTL_PLAN_V2_MISSING",
            "the execution contract is not a current PlanV2",
            "Create and approve a new fully pinned PlanV2.",
        ));
    };
    let plan_v2 = *plan_v2;
    let current_build_hash = hash_value(&serde_json::to_value(current_build_info())?)?;
    if plan_v2.pins.build_identity_hash != current_build_hash {
        return Err(CliError::guided(
            "CFCTL_PLAN_BUILD_DRIFT",
            "the running build identity no longer matches the PlanV2 pin",
            format!(
                "Re-run `cfctl call {}` under the current checkout build.",
                plan.capability.id
            ),
        ));
    }
    if profile.credential_generation_id.as_deref()
        != Some(plan_v2.pins.credential_generation_id.as_str())
    {
        return Err(CliError::guided(
            "CFCTL_PLAN_CREDENTIAL_DRIFT",
            "the selected credential generation no longer matches the PlanV2 pin",
            format!(
                "Re-authenticate profile `{}` and create a new plan.",
                profile.id
            ),
        ));
    }
    let current_policy = active_admission_policy(store)?;
    let compiled_policy_hash = if current_policy.is_none() {
        let input: CallInput = serde_json::from_value(plan.input.clone())?;
        let impact = plan_impact(store, &plan.capability, &input, &plan.account_id)?;
        let compiled_policy = PolicyEngine.evaluate(&plan.capability, &impact.policy);
        Some(format!(
            "compiled:{}",
            hash_value(&json!({"compiled_safety_floor": compiled_policy}))?
        ))
    } else {
        None
    };
    match current_policy {
        Some(bundle)
            if plan_v2.pins.admission_policy_hash != format!("bundle:{}", bundle.content_hash) =>
        {
            return Err(CliError::guided(
                "CFCTL_PLAN_POLICY_DRIFT",
                "the active admission policy no longer matches the PlanV2 pin",
                format!(
                    "Re-run `cfctl call {}` under the active bundle.",
                    plan.capability.id
                ),
            ));
        }
        None if compiled_policy_hash.as_deref()
            != Some(plan_v2.pins.admission_policy_hash.as_str()) =>
        {
            return Err(CliError::guided(
                "CFCTL_PLAN_POLICY_DRIFT",
                "the current compiled safety floor no longer matches the PlanV2 policy pin",
                format!(
                    "Re-run `cfctl call {}` under the compiled safety floor.",
                    plan.capability.id
                ),
            ));
        }
        _ => {}
    }
    if let Some(authority_hash) = &plan_v2.pins.authority_hash {
        let authority = store
            .list_authorities()?
            .into_iter()
            .find(|authority| &authority.content_hash == authority_hash)
            .ok_or_else(|| {
                CliError::guided(
                    "CFCTL_PLAN_AUTHORITY_DRIFT",
                    "the PlanV2 authority pin no longer resolves",
                    "Create and approve a new token lifecycle policy, then re-plan.",
                )
            })?;
        authority.ensure_operational()?;
    }
    Ok(())
}

pub(super) fn persist_transaction_stage(
    store: &StateStore,
    plan: &mut PlanV1,
    stage: TransactionStageV1,
) -> Result<()> {
    plan.record_transaction_stage(stage)?;
    store.save_plan(plan)?;
    Ok(())
}

pub(super) fn persist_transaction_stage_with_artifact(
    store: &StateStore,
    plan: &mut PlanV1,
    stage: TransactionStageV1,
    artifact: Value,
) -> Result<()> {
    plan.record_transaction_stage_with_artifact(stage, artifact)?;
    store.save_plan(plan)?;
    Ok(())
}

pub(super) fn show_plan(store: &StateStore, selector: &PlanSelector) -> Result<ResultEnvelopeV2> {
    let record = store.load_stored_plan_record(&selector.operation_id)?;
    let plan = record.readable_plan().cloned().ok_or_else(|| {
        let reason = match &record {
            StoredPlanRecord::Corrupt { reason, .. } => reason.as_str(),
            _ => "the plan has no readable body",
        };
        CliError::guided(
            "CFCTL_PLAN_CORRUPT",
            reason,
            "Preserve the durable files and inspect the exact plan record before recovery.",
        )
    })?;
    plan.validate_transaction_journal()?;
    let mut result = serde_json::to_value(&plan)?;
    let plan_v2 = match &record {
        StoredPlanRecord::Current(plan)
        | StoredPlanRecord::ProjectionDrift { current: plan, .. } => Some(plan),
        _ => None,
    };
    if let Some(object) = result.as_object_mut() {
        object.insert("plan_v2".to_owned(), serde_json::to_value(plan_v2)?);
        object.insert(
            "execution_compatible".to_owned(),
            json!(record.execution_compatible()),
        );
        object.insert(
            "execution_incompatibility_reason".to_owned(),
            serde_json::to_value(record.execution_incompatibility_reason())?,
        );
    }
    let mut envelope = ResultEnvelopeV2::success("plans show", result);
    envelope.operation_id = Some(plan.operation_id);
    envelope.capability_id = Some(plan.capability.id);
    envelope.policy_decision = Some(plan.policy);
    envelope.verification.state = verification_for_status(plan.status);
    Ok(envelope)
}

pub(super) fn approve_plan(
    store: &StateStore,
    arguments: &PlanApproveArgs,
) -> Result<ResultEnvelopeV2> {
    let _lock = store.lock_plan(&arguments.operation_id)?;
    let mut plan = load_validated_plan(store, &arguments.operation_id)?;
    ensure_plan_execution_contract(store, &plan)?;
    let max_cost = arguments.max_cost.as_deref().map(parse_money).transpose()?;
    plan.approve(arguments.yes, max_cost)?;
    store.save_plan(&plan)?;
    let evidence = store.write_evidence(EvidenceClass::Preview, &serde_json::to_value(&plan)?)?;
    let mut envelope = ResultEnvelopeV2::success(
        "plans approve",
        json!({
            "operation_id": plan.operation_id,
            "content_hash": plan.content_hash,
            "expires_at": plan.expires_at,
            "run_command": format!("cfctl plans run {}", plan.operation_id),
            "message": "The exact hash-bound plan is approved."
        }),
    )
    .with_evidence(evidence);
    envelope.operation_id = Some(plan.operation_id);
    envelope.capability_id = Some(plan.capability.id);
    envelope.policy_decision = Some(plan.policy);
    Ok(envelope)
}

pub(super) fn cancel_plan(store: &StateStore, selector: &PlanSelector) -> Result<ResultEnvelopeV2> {
    let _lock = store.lock_plan(&selector.operation_id)?;
    // Deliberately load the storage classification, not the execution
    // contract: cancellation must
    // de-authorize even a plan whose journal or content no longer validates —
    // refusing would preserve exactly the authority being retired.
    let record = store.load_stored_plan_record(&selector.operation_id)?;
    let mut plan = record.readable_plan().cloned().ok_or_else(|| {
        CliError::guided(
            "CFCTL_PLAN_CORRUPT",
            "the plan has no readable canonical body to cancel",
            "Preserve the durable record and inspect it before attempting recovery.",
        )
    })?;
    plan.cancel()?;
    store.save_plan(&plan)?;
    let evidence =
        store.write_audit_evidence(EvidenceClass::Preview, &serde_json::to_value(&plan)?)?;
    let mut envelope = ResultEnvelopeV2::success(
        "plans cancel",
        json!({
            "operation_id": plan.operation_id,
            "status": plan_status_label(plan.status),
            "cancelled_at": plan.cancelled_at,
            "message": "The plan's latent authority is retired; it can no longer be approved or run."
        }),
    )
    .with_evidence(evidence);
    envelope.operation_id = Some(plan.operation_id);
    envelope.capability_id = Some(plan.capability.id);
    envelope.policy_decision = Some(plan.policy);
    Ok(envelope)
}

/// Admits plan execution against the evidence gate, keyed to the plan's
/// effect class.
///
/// The qualifying path is checked first and unconditionally, so a healthy
/// installation reaches the provider boundary through exactly the same
/// ordering as before: the authority is proven before the plan record, the
/// credential, or the provider is touched.
///
/// Only a non-qualifying authority consults the plan, and only to read its
/// classification. An operation that cannot be replayed keeps the original
/// refusal, because performing it without a receipt leaves nothing to
/// reconstruct afterward. Both `effect` and `risk` are consulted and either is
/// sufficient, since the catalog carries capabilities that are replayable by
/// effect and irreversible by risk. A plan that cannot be read keeps the
/// refusal too: an unreadable plan cannot demonstrate that it is reversible.
pub(super) fn admit_execution_attestation(
    store: &StateStore,
    operation_id: &str,
) -> Result<AttestationStatusV1> {
    let Err(refusal) = store.require_qualifying_evidence_authority() else {
        return Ok(AttestationStatusV1::attested());
    };
    let Ok(plan) = load_validated_plan(store, operation_id) else {
        return Err(CliError::Storage(refusal));
    };
    if plan.capability.requires_attestation_to_execute() {
        return Err(CliError::Storage(refusal));
    }
    Ok(AttestationStatusV1::unattested_reversible_effect(
        refusal.to_string(),
    ))
}

#[expect(
    clippy::too_many_lines,
    reason = "execution revalidates capability-specific immutable authority before dispatch"
)]
pub(super) async fn run_plan(
    store: &StateStore,
    selector: &PlanSelector,
) -> Result<ResultEnvelopeV2> {
    let _lock = store.lock_plan(&selector.operation_id)?;
    let attestation = admit_execution_attestation(store, &selector.operation_id)?;
    let catalog = ensure_catalog(store).await?;
    let mut plan = load_validated_plan(store, &selector.operation_id)?;
    ensure_plan_execution_contract(store, &plan)?;
    if plan.catalog_hash != catalog.schema_hash {
        return Err(CliError::Input(format!(
            "catalog drift invalidated the plan: planned {}, current {}",
            plan.catalog_hash, catalog.schema_hash
        )));
    }
    validate_plan_preconditions(store, &plan)?;
    if plan.capability.adapter_status == AdapterStatus::Blocked {
        let mut envelope = blocked_capability_envelope(
            "plans run",
            &plan.capability,
            plan.capability
                .blocked_reason
                .as_deref()
                .unwrap_or("the approved capability no longer has an executable adapter"),
        );
        envelope.operation_id = Some(plan.operation_id.clone());
        envelope.profile_id = Some(plan.profile_id.clone());
        envelope.account_id = Some(plan.account_id.clone());
        return Ok(envelope);
    }
    preflight_secret_sink(&plan)?;
    let profiles = ProfilesConfig::load(store)?;
    let profile = profiles.selected(Some(&plan.profile_id))?;
    if plan.capability.d1_approved_mln_import.is_some() {
        let execution_input: CallInput = serde_json::from_value(plan.input.clone())?;
        validate_approved_mln_import_prerequisites(
            store,
            &plan.capability,
            &execution_input,
            ImportPrerequisiteContext {
                profile_id: &plan.profile_id,
                credential_generation_id: profile.credential_generation_id.as_deref(),
                catalog_hash: &plan.catalog_hash,
                import_operation_id: Some(&plan.operation_id),
                before: plan.created_at,
            },
        )?;
    }
    if plan.capability.d1_approved_mln_import_poll_resume.is_some() {
        let execution_input: CallInput = serde_json::from_value(plan.input.clone())?;
        let derived = validate_and_derive_resume_poll_authority(
            store,
            &plan.capability,
            &execution_input,
            &plan.profile_id,
            profile.credential_generation_id.as_deref(),
            &plan.catalog_hash,
            plan.created_at,
            Some(&plan.operation_id),
        )?;
        if plan
            .targets
            .pointer("/adapter/approved_mln_import_poll_resume")
            != Some(&derived)
        {
            return Err(CliError::Input(
                "poll continuation authority drifted after planning; do not cross the provider boundary"
                    .to_owned(),
            ));
        }
    }
    validate_plan_v2_runtime_pins(store, &plan, profile)?;
    if is_r2_temporary_credentials_operation_identity(&plan.capability)
        && profile.kind != ProfileKind::ApiToken
    {
        return Err(CliError::Input(
            "R2 temporary credential plan no longer selects its required scoped API-token profile; the mutation boundary was not crossed"
                .to_owned(),
        ));
    }
    let secrets = platform_secrets(store);
    let credential = fresh_credential(profile, &secrets).await?;
    let execution_input = resolved_plan_input(&plan, &secrets)?;
    let adapter_targets = plan.targets.get("adapter").unwrap_or(&Value::Null);
    if plan.capability.id == worker_deployment::ROLLBACK_CAPABILITY_ID {
        validate_request_contract(&plan.capability, &execution_input)?;
    }
    let _worker_deployment_lock = if worker_deployment::mutates_traffic(&plan.capability) {
        let script_name = worker_deployment::service_name(adapter_targets)?;
        Some(
            store
                .lock_worker_deployment(&plan.account_id, script_name)
                .map_err(CliError::Storage)?,
        )
    } else {
        None
    };
    let _email_routing_catch_all_lock =
        workspace_reply_subdomain_ingress::acquire_activation_target_lock(
            store,
            &plan,
            &execution_input,
        )?;
    validate_worker_deployment_local_authority(store, &plan, &execution_input)?;
    validate_api_token_creation_contract(
        &plan.capability,
        &execution_input,
        adapter_targets,
        &plan.account_id,
    )?;
    let live_precondition_evidence = validate_live_plan_precondition_evidence(
        store,
        &catalog,
        &plan,
        &execution_input,
        &credential,
        None,
    )
    .await?;
    let graph = discover_registered(store)?;
    pages_deployment::validate_bound_plan(&graph, &plan, &execution_input)?;
    validate_worker_deployment_local_authority(store, &plan, &execution_input)?;
    plan.mark_consumed()?;
    store.save_plan(&plan)?;
    persist_transaction_stage(
        store,
        &mut plan,
        TransactionStageV1::BoundaryAttemptPersisted,
    )?;
    Box::pin(execute_consumed_plan(
        store,
        &catalog,
        &mut plan,
        &execution_input,
        &credential,
        &secrets,
        ExecutionAdmission::new(live_precondition_evidence, attestation),
    ))
    .await
}

/// The standing-authority execution lane. Identical to `run_plan` in every
/// pre-consumption re-verification (catalog hash, workspace and live
/// precondition hashes, token contract, secret sink); it differs only at the
/// consumption gate, where the authority's blast-radius bounds are validated
/// against the exact resolved execution input and consumption is recorded
/// against the authority instead of a per-operation approval.
pub(super) async fn run_plan_under_standing_authority(
    store: &StateStore,
    operation_id: &str,
    authority_id: &str,
) -> Result<ResultEnvelopeV2> {
    // Lock order is always plan -> authority. The plan lock may span async
    // preflight; the authority lock is acquired only for the synchronous
    // admission critical section below and is released before network I/O.
    let _plan_lock = store.lock_plan(operation_id)?;
    let attestation = admit_execution_attestation(store, operation_id)?;
    let authority_snapshot = store.load_authority(authority_id)?;
    store.bind_plan_authority_hash(operation_id, &authority_snapshot.content_hash)?;
    let catalog = ensure_catalog(store).await?;
    let mut plan = load_validated_plan(store, operation_id)?;
    ensure_plan_execution_contract(store, &plan)?;
    if plan.catalog_hash != catalog.schema_hash {
        return Err(CliError::Input(format!(
            "catalog drift invalidated the plan: planned {}, current {}",
            plan.catalog_hash, catalog.schema_hash
        )));
    }
    validate_plan_preconditions(store, &plan)?;
    if plan.capability.adapter_status == AdapterStatus::Blocked {
        let mut envelope = blocked_capability_envelope(
            "plans run",
            &plan.capability,
            plan.capability
                .blocked_reason
                .as_deref()
                .unwrap_or("the approved capability no longer has an executable adapter"),
        );
        envelope.operation_id = Some(plan.operation_id.clone());
        envelope.profile_id = Some(plan.profile_id.clone());
        envelope.account_id = Some(plan.account_id.clone());
        return Ok(envelope);
    }
    preflight_secret_sink(&plan)?;
    let profiles = ProfilesConfig::load(store)?;
    let profile = profiles.selected(Some(&plan.profile_id))?;
    validate_plan_v2_runtime_pins(store, &plan, profile)?;
    let secrets = platform_secrets(store);
    let credential = fresh_credential(profile, &secrets).await?;
    let execution_input = resolved_plan_input(&plan, &secrets)?;
    let adapter_targets = plan.targets.get("adapter").unwrap_or(&Value::Null);
    if plan.capability.id == worker_deployment::ROLLBACK_CAPABILITY_ID {
        validate_request_contract(&plan.capability, &execution_input)?;
    }
    let _worker_deployment_lock = if worker_deployment::mutates_traffic(&plan.capability) {
        let script_name = worker_deployment::service_name(adapter_targets)?;
        Some(
            store
                .lock_worker_deployment(&plan.account_id, script_name)
                .map_err(CliError::Storage)?,
        )
    } else {
        None
    };
    let _email_routing_catch_all_lock =
        workspace_reply_subdomain_ingress::acquire_activation_target_lock(
            store,
            &plan,
            &execution_input,
        )?;
    validate_worker_deployment_local_authority(store, &plan, &execution_input)?;
    validate_api_token_creation_contract(
        &plan.capability,
        &execution_input,
        adapter_targets,
        &plan.account_id,
    )?;
    let live_precondition_evidence = validate_live_plan_precondition_evidence(
        store,
        &catalog,
        &plan,
        &execution_input,
        &credential,
        Some(&authority_snapshot),
    )
    .await?;
    let graph = discover_registered(store)?;
    pages_deployment::validate_bound_plan(&graph, &plan, &execution_input)?;
    validate_worker_deployment_local_authority(store, &plan, &execution_input)?;
    authorize_standing_execution(&authority_snapshot, &plan, &execution_input)?;
    let standing_evidence =
        admit_standing_plan(store, &mut plan, &authority_snapshot, &execution_input)?;
    let admitted_authority_id = authority_snapshot.authority_id.clone();
    let mut envelope = Box::pin(execute_consumed_plan(
        store,
        &catalog,
        &mut plan,
        &execution_input,
        &credential,
        &secrets,
        ExecutionAdmission::new(live_precondition_evidence, attestation),
    ))
    .await?;
    envelope.evidence.push(standing_evidence);
    if let Some(result) = envelope.result.as_object_mut() {
        result.insert(
            "standing_authority_id".to_owned(),
            json!(admitted_authority_id),
        );
    }
    Ok(envelope)
}

/// Performs the synchronous standing-authority admission transaction while
/// the caller holds the plan lock. No network or async work is permitted in
/// this critical section.
pub(super) fn admit_standing_plan(
    store: &StateStore,
    plan: &mut PlanV1,
    authority_snapshot: &StandingAuthorityV1,
    execution_input: &CallInput,
) -> Result<EvidenceV1> {
    let authority_guard = store.lock_authority(&authority_snapshot.authority_id)?;
    let mut authority = store.load_authority(&authority_snapshot.authority_id)?;
    if authority.content_hash != authority_snapshot.content_hash {
        return Err(CliError::Input(
            "standing authority changed during live preflight; the mutation boundary was not crossed"
                .to_owned(),
        ));
    }
    // The live inventory was validated against the snapshot. Exact
    // content-hash equality plus the operational/hash check below proves
    // that the locked authority carries the same immutable allowlist.
    let admission_time = Utc::now();
    authorize_standing_execution_at(&authority, plan, execution_input, admission_time)?;
    plan.mark_consumed_via_standing_authority(&authority)?;
    // Durable reservation is the admission linearization point. It is saved
    // before plan consumption so a persistence failure may spend a budget
    // slot but can never permit an unaccounted boundary attempt.
    authority.reserve_run(admission_time, &plan.operation_id, &plan.capability.id)?;
    store.save_authority_guarded(&authority, &authority_guard)?;
    store.save_plan(plan)?;
    let evidence = store.write_evidence(
        EvidenceClass::StandingApply,
        &json!({
            "standing_authority_id": authority.authority_id,
            "standing_authority_content_hash": authority.content_hash,
            "operation_id": plan.operation_id,
            "capability_id": plan.capability.id,
            "account_id": plan.account_id,
            "admission": "durable_run_reservation",
        }),
    )?;
    persist_transaction_stage(store, plan, TransactionStageV1::BoundaryAttemptPersisted)?;
    Ok(evidence)
}

/// Validates the authority's bounds against the exact execution input the
/// boundary call will use — never a re-derivation.
pub(super) fn authorize_standing_execution(
    authority: &StandingAuthorityV1,
    plan: &PlanV1,
    input: &CallInput,
) -> Result<()> {
    authorize_standing_execution_at(authority, plan, input, Utc::now())
}

pub(super) fn authorize_standing_execution_at(
    authority: &StandingAuthorityV1,
    plan: &PlanV1,
    input: &CallInput,
    now: chrono::DateTime<Utc>,
) -> Result<()> {
    if plan.capability.id.ends_with("create-token") {
        let body = input.body.as_ref().ok_or_else(|| {
            CliError::Input("a standing mint requires the plan's request body".to_owned())
        })?;
        let child_name = body.get("name").and_then(Value::as_str).ok_or_else(|| {
            CliError::Input("a standing mint requires a child token name".to_owned())
        })?;
        let requested_group_ids: Vec<String> = body
            .get("policies")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|policy| policy.get("permission_groups").and_then(Value::as_array))
            .flatten()
            .filter_map(|group| group.get("id").and_then(Value::as_str))
            .map(str::to_owned)
            .collect();
        // Each policy's `resources` object is keyed by the resource string the
        // child token would bind. The authority bounds which of those are
        // permitted, so collect every key rather than assuming one policy.
        let requested_resources: Vec<String> = body
            .get("policies")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|policy| policy.get("resources").and_then(Value::as_object))
            .flat_map(serde_json::Map::keys)
            .map(String::to_owned)
            .collect();
        let child_expires_at = body
            .get("expires_on")
            .and_then(Value::as_str)
            .map(|raw| {
                chrono::DateTime::parse_from_rfc3339(raw)
                    .map(|parsed| parsed.with_timezone(&Utc))
                    .map_err(|error| {
                        CliError::Input(format!(
                            "the standing mint carries an unparseable expires_on: {error}"
                        ))
                    })
            })
            .transpose()?;
        authority.authorize_token_create(
            now,
            child_name,
            &requested_group_ids,
            &requested_resources,
            child_expires_at,
        )?;
    } else if plan.capability.id.ends_with("delete-token") {
        let token_id = input
            .selectors
            .get("token_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CliError::Input("a standing revoke requires a token_id selector".to_owned())
            })?;
        authority.authorize_token_delete(now, token_id)?;
    } else {
        return Err(CliError::Input(format!(
            "standing authorities do not cover capability `{}`",
            plan.capability.id
        )));
    }
    Ok(())
}

/// Returns the created token ID only when the validated transaction journal
/// proves that this exact authority admitted the plan and Cloudflare returned
/// a successful creation receipt. Revocation is intentionally not consulted:
/// lineage reconciliation records an already-crossed boundary; it grants no
/// new authority.
pub(super) fn validated_standing_lineage_token_id<'a>(
    plan: &'a PlanV1,
    authority: &StandingAuthorityV1,
) -> Result<Option<&'a str>> {
    plan.validate_transaction_journal()?;
    let Some(binding) = plan.transaction_artifact(TransactionStageV1::ConsumptionPersisted) else {
        return Ok(None);
    };
    let bound_authority_id = binding
        .get("standing_authority_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "standing consumption receipt has no authority ID; do not replay the mutation"
                    .to_owned(),
            )
        })?;
    let bound_authority_hash = binding
        .get("standing_authority_content_hash")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "standing consumption receipt has no authority content hash; do not replay the mutation"
                    .to_owned(),
            )
        })?;
    if bound_authority_id != authority.authority_id
        || bound_authority_hash != authority.content_hash
    {
        return Err(CliError::Input(
            "standing consumption receipt does not bind the exact authority; do not replay the mutation"
                .to_owned(),
        ));
    }
    let approval_matches = authority
        .approval
        .as_ref()
        .is_some_and(|approval| approval.approved_content_hash == authority.content_hash);
    if !approval_matches {
        return Err(CliError::Input(
            "standing authority no longer carries the approval bound by the consumption receipt; do not replay the mutation"
                .to_owned(),
        ));
    }
    let matching_reservations = authority
        .run_log
        .iter()
        .filter(|run| run.operation_id == plan.operation_id)
        .collect::<Vec<_>>();
    if matching_reservations.len() != 1
        || matching_reservations[0].capability_id != plan.capability.id
    {
        return Err(CliError::Input(
            "standing boundary receipt was not durably reserved exactly once under the same authority capability; do not replay the mutation"
                .to_owned(),
        ));
    }
    if plan.account_id != authority.account_id
        || plan.capability.id != "account-api-tokens-create-token"
        || !authority
            .capability_ids
            .iter()
            .any(|capability_id| capability_id == &plan.capability.id)
    {
        return Err(CliError::Input(
            "standing token receipt account or capability does not match its authority; do not replay the mutation"
                .to_owned(),
        ));
    }
    let Some(response) = plan.transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
    else {
        return Ok(None);
    };
    let success = response
        .get("success")
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            CliError::Input(
                "standing boundary receipt has no success result; do not replay the mutation"
                    .to_owned(),
            )
        })?;
    if !success {
        return Ok(None);
    }
    response
        .get("resource_id")
        .and_then(Value::as_str)
        .filter(|resource_id| !resource_id.trim().is_empty())
        .map(Some)
        .ok_or_else(|| {
            CliError::Input(
                "successful standing token receipt has no resource ID; do not replay the mutation and run `cfctl plans rectify`"
                    .to_owned(),
            )
        })
}

pub(super) fn standing_consumption_authority_id(plan: &PlanV1) -> Result<Option<&str>> {
    let Some(binding) = plan.transaction_artifact(TransactionStageV1::ConsumptionPersisted) else {
        return Ok(None);
    };
    if binding.get("standing_authority_id").is_none()
        && binding.get("standing_authority_content_hash").is_none()
    {
        return Ok(None);
    }
    binding
        .get("standing_authority_id")
        .and_then(Value::as_str)
        .filter(|authority_id| !authority_id.is_empty())
        .map(Some)
        .ok_or_else(|| {
            CliError::Input(
                "standing consumption receipt has no authority ID; do not replay the mutation"
                    .to_owned(),
            )
        })
}

pub(super) fn reconcile_standing_lineage_from_plan(
    store: &StateStore,
    plan: &PlanV1,
) -> Result<Option<EvidenceV1>> {
    let Some(authority_id) = standing_consumption_authority_id(plan)? else {
        return Ok(None);
    };
    if plan.capability.id != "account-api-tokens-create-token" {
        return Ok(None);
    }
    let guard = store.lock_authority(authority_id)?;
    let mut authority = store.load_authority(authority_id)?;
    let Some(token_id) = validated_standing_lineage_token_id(plan, &authority)? else {
        return Ok(None);
    };
    let already_recorded = authority
        .minted_token_ids
        .iter()
        .any(|recorded| recorded == token_id);
    authority.record_minted_token(token_id);
    if !already_recorded {
        store.save_authority_guarded(&authority, &guard)?;
    }
    let boundary_receipt_hash = plan
        .transaction_journal
        .iter()
        .find(|checkpoint| checkpoint.stage == TransactionStageV1::BoundaryResponsePersisted)
        .and_then(|checkpoint| checkpoint.artifact_hash.as_deref())
        .ok_or_else(|| {
            CliError::Input(
                "standing boundary response has no validated artifact hash; do not replay the mutation"
                    .to_owned(),
            )
        })?;
    let evidence = store.write_evidence(
        EvidenceClass::StandingApply,
        &json!({
            "standing_authority_id": authority.authority_id,
            "standing_authority_content_hash": authority.content_hash,
            "operation_id": plan.operation_id,
            "token_id": token_id,
            "source_boundary_receipt_hash": boundary_receipt_hash,
            "reconciled": true,
        }),
    )?;
    Ok(Some(evidence))
}

pub(super) fn recover_standing_lineage(
    store: &StateStore,
    authority_id: &str,
) -> Result<Vec<EvidenceV1>> {
    let mut evidence = Vec::new();
    for snapshot in store.list_plans()? {
        if standing_consumption_authority_id(&snapshot)? != Some(authority_id) {
            continue;
        }
        let _plan_lock = store.lock_plan(&snapshot.operation_id)?;
        let plan = load_validated_plan(store, &snapshot.operation_id)?;
        if standing_consumption_authority_id(&plan)? != Some(authority_id) {
            continue;
        }
        if let Some(item) = reconcile_standing_lineage_from_plan(store, &plan)? {
            evidence.push(item);
        }
    }
    Ok(evidence)
}

/// What the pre-crossing admission established, carried into the executor as
/// one value because both fields describe the crossing rather than the request.
pub(super) struct ExecutionAdmission {
    pub(super) evidence: LivePreconditionEvidence,
    pub(super) attestation: AttestationStatusV1,
}

impl ExecutionAdmission {
    pub(super) const fn new(
        evidence: LivePreconditionEvidence,
        attestation: AttestationStatusV1,
    ) -> Self {
        Self {
            evidence,
            attestation,
        }
    }
}

#[derive(Default)]
pub(super) struct LivePreconditionEvidence {
    pub(super) zone_account: Option<EvidenceV1>,
    pub(super) entitlement: Option<EvidenceV1>,
    pub(super) pages_project_absence: Option<EvidenceV1>,
    pub(super) pages_deployment_project_state: Option<EvidenceV1>,
    pub(super) permission_inventory: Option<EvidenceV1>,
    pub(super) global_warp_override_state: Option<EvidenceV1>,
    pub(super) d1_read_replication_state: Option<EvidenceV1>,
    pub(super) d1_empty_database_state: Option<EvidenceV1>,
    pub(super) kv_empty_namespace_state: Option<EvidenceV1>,
    pub(super) cloudflare_tunnel_configuration_state: Option<EvidenceV1>,
    pub(super) warp_connector_configuration_state: Option<EvidenceV1>,
    pub(super) web_analytics_rum_state: Option<EvidenceV1>,
    pub(super) dns_record_state: Option<EvidenceV1>,
    pub(super) same_path_prior_state: Option<EvidenceV1>,
    pub(super) access_operator_group_policy_ownership: Option<EvidenceV1>,
    pub(super) security_action_state: Option<EvidenceV1>,
    pub(super) oauth_client_secret_state: Option<EvidenceV1>,
    pub(super) oauth_client_update_state: Option<EvidenceV1>,
    pub(super) worker_custom_domain_state: Option<EvidenceV1>,
    pub(super) worker_deployment_state: Option<EvidenceV1>,
    pub(super) r2_parent_token: Option<EvidenceV1>,
}

pub(super) fn validate_live_plan_precondition_evidence<'a>(
    store: &'a StateStore,
    catalog: &'a CatalogSnapshot,
    plan: &'a PlanV1,
    input: &'a CallInput,
    credential: &'a AuthCredential,
    standing_authority: Option<&'a StandingAuthorityV1>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<LivePreconditionEvidence>> + 'a>> {
    Box::pin(async move {
        Ok(LivePreconditionEvidence {
            zone_account: validate_live_zone_account_precondition(
                store, catalog, plan, input, credential,
            )
            .await?,
            entitlement: validate_live_entitlement_precondition(
                store, catalog, plan, input, credential,
            )
            .await?,
            pages_project_absence: validate_live_pages_project_absence_precondition(
                store, catalog, plan, input, credential,
            )
            .await?,
            pages_deployment_project_state:
                validate_live_pages_deployment_project_state_precondition(
                    store, catalog, plan, input, credential,
                )
                .await?,
            permission_inventory: validate_live_permission_inventory_precondition(
                store,
                catalog,
                plan,
                credential,
                standing_authority,
            )
            .await?,
            global_warp_override_state: validate_live_global_warp_override_state_precondition(
                store, catalog, plan, input, credential,
            )
            .await?,
            d1_read_replication_state: validate_live_d1_read_replication_state_precondition(
                store, catalog, plan, input, credential,
            )
            .await?,
            kv_empty_namespace_state: validate_live_kv_empty_namespace_state_precondition(
                store, catalog, plan, input, credential,
            )
            .await?,
            d1_empty_database_state: validate_live_d1_empty_database_state_precondition(
                store, catalog, plan, input, credential,
            )
            .await?,
            cloudflare_tunnel_configuration_state:
                validate_live_cloudflare_tunnel_configuration_state_precondition(
                    store, catalog, plan, input, credential,
                )
                .await?,
            warp_connector_configuration_state:
                validate_live_warp_connector_configuration_state_precondition(
                    store, catalog, plan, input, credential,
                )
                .await?,
            web_analytics_rum_state: validate_live_web_analytics_rum_state_precondition(
                store, catalog, plan, input, credential,
            )
            .await?,
            dns_record_state: validate_live_dns_record_state_precondition(
                store, catalog, plan, input, credential,
            )
            .await?,
            same_path_prior_state: validate_live_same_path_prior_state_precondition(
                store, catalog, plan, input, credential,
            )
            .await?,
            access_operator_group_policy_ownership:
                validate_live_access_operator_group_policy_ownership_precondition(
                    store, catalog, plan, input, credential,
                )
                .await?,
            security_action_state: validate_live_security_action_state_precondition(
                store, catalog, plan, input, credential,
            )
            .await?,
            oauth_client_secret_state: validate_live_oauth_client_secret_state_precondition(
                store, catalog, plan, input, credential,
            )
            .await?,
            oauth_client_update_state: validate_live_oauth_client_update_state_precondition(
                store, catalog, plan, input, credential,
            )
            .await?,
            worker_custom_domain_state: worker_custom_domain::validate_live_precondition(
                store, catalog, plan, input, credential,
            )
            .await?,
            worker_deployment_state: validate_live_worker_deployment_state_precondition(
                store, catalog, plan, credential,
            )
            .await?,
            r2_parent_token: validate_live_r2_parent_token_precondition(
                store, catalog, plan, input, credential,
            )
            .await?,
        })
    })
}

/// Executes a consumed plan and stamps the admission that let it reach the
/// provider boundary onto the resulting envelope.
///
/// `attestation` is a required parameter rather than a field the callers
/// remember to set, so an execution lane cannot cross a provider boundary
/// without saying, in its own result, whether the crossing was attested.
pub(super) async fn execute_consumed_plan(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    plan: &mut PlanV1,
    execution_input: &CallInput,
    credential: &AuthCredential,
    secrets: &dyn SecretStore,
    admission: ExecutionAdmission,
) -> Result<ResultEnvelopeV2> {
    let ExecutionAdmission {
        evidence,
        attestation,
    } = admission;
    let mut envelope = Box::pin(execute_consumed_plan_inner(
        store,
        catalog,
        plan,
        execution_input,
        credential,
        secrets,
        evidence,
    ))
    .await?;
    envelope.attestation = Some(attestation);
    Ok(envelope)
}

async fn execute_consumed_plan_inner(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    plan: &mut PlanV1,
    execution_input: &CallInput,
    credential: &AuthCredential,
    secrets: &dyn SecretStore,
    evidence: LivePreconditionEvidence,
) -> Result<ResultEnvelopeV2> {
    if plan.capability.id == cfctl_core::EVENT_BATCH_CAPABILITY_ID {
        let mut result = event_batch::execute(store, catalog, plan, credential, secrets).await;
        if let Ok(envelope) = &mut result {
            prepend_live_precondition_evidence(envelope, evidence);
        }
        return result;
    }
    if plan.capability.adapter_status == AdapterStatus::DelegatedCli {
        let result = Box::pin(execute_delegated_plan(
            store,
            catalog,
            plan,
            execution_input,
            credential,
            secrets,
        ))
        .await;
        return match result {
            Ok(mut envelope) => {
                prepend_live_precondition_evidence(&mut envelope, evidence);
                Ok(envelope)
            }
            Err(error)
                if plan.transaction_stage == TransactionStageV1::BoundaryAttemptPersisted =>
            {
                persist_delegated_pre_response_failure(store, plan, &error, secrets)?;
                let mut envelope = delegated_pre_response_failure_envelope(plan, &error);
                prepend_live_precondition_evidence(&mut envelope, evidence);
                Ok(envelope)
            }
            Err(error) => Err(error),
        };
    }
    if plan.capability.adapter_status == AdapterStatus::GovernedUi {
        let mut result = execute_governed_ui_plan(store, plan, execution_input, secrets);
        if result.is_err() && plan.transaction_stage == TransactionStageV1::BoundaryAttemptPersisted
        {
            plan.status = PlanStatus::RectificationRequired;
            persist_transaction_stage_with_artifact(
                store,
                plan,
                TransactionStageV1::BoundaryResponsePersisted,
                boundary_failure_artifact("governed_ui", "handoff_failed"),
            )?;
            persist_secret_lifecycle(store, plan, false, None, secrets)?;
        }
        if let Ok(envelope) = &mut result {
            prepend_live_precondition_evidence(envelope, evidence);
        }
        return result;
    }
    let mut envelope = Box::pin(execute_api_plan(
        store,
        &catalog.schema_hash,
        plan,
        execution_input,
        credential,
        secrets,
    ))
    .await?;
    prepend_live_precondition_evidence(&mut envelope, evidence);
    Ok(envelope)
}

pub(super) fn persist_delegated_pre_response_failure(
    store: &StateStore,
    plan: &mut PlanV1,
    error: &CliError,
    secrets: &dyn SecretStore,
) -> Result<()> {
    plan.status = PlanStatus::RectificationRequired;
    let outcome = if delegated_mutation_was_attempted(error) {
        "no_receipt"
    } else {
        "not_attempted"
    };
    persist_transaction_stage_with_artifact(
        store,
        plan,
        TransactionStageV1::BoundaryResponsePersisted,
        boundary_failure_artifact("delegated_cli", outcome),
    )?;
    persist_secret_lifecycle(store, plan, false, None, secrets)?;
    Ok(())
}

pub(super) fn delegated_pre_response_failure_envelope(
    plan: &PlanV1,
    error: &CliError,
) -> ResultEnvelopeV2 {
    let next_step = format!(
        "Do not replay the mutation; run `cfctl plans status {} --json`, then `cfctl plans rectify {} --json`.",
        plan.operation_id, plan.operation_id
    );
    let mut envelope = ResultEnvelopeV2::failure(
        "plans run",
        error.code(),
        &error.to_string(),
        Some(&next_step),
    );
    let performed = delegated_mutation_was_attempted(error);
    envelope.result = json!({
        "success": false,
        "outcome": if performed { "unknown" } else { "not_attempted" },
        "receipt_available": false,
        "boundary_replayed": false,
    });
    envelope.performed = performed;
    envelope.operation_id = Some(plan.operation_id.clone());
    envelope.capability_id = Some(plan.capability.id.clone());
    envelope.profile_id = Some(plan.profile_id.clone());
    envelope.account_id = Some(plan.account_id.clone());
    envelope.policy_decision = Some(plan.policy.clone());
    envelope.verification.state = if performed {
        VerificationState::Pending
    } else {
        VerificationState::Failed
    };
    envelope.verification.basis = Some(if performed {
        "the mutation-capable delegated subprocess started, but no complete boundary receipt exists; provider acceptance is unknown and the consumed plan requires rectification without replay"
            .to_owned()
    } else {
        "no mutation-capable delegated subprocess was started; plan consumption is preserved for rectification, but no provider write is claimed"
            .to_owned()
    });
    envelope
}

pub(super) fn delegated_mutation_was_attempted(error: &CliError) -> bool {
    matches!(
        error,
        CliError::SubprocessTimeout { .. } | CliError::SubprocessReceiptUnavailable { .. }
    )
}

pub(super) fn prepend_live_precondition_evidence(
    envelope: &mut ResultEnvelopeV2,
    evidence: LivePreconditionEvidence,
) {
    for item in [
        evidence.pages_project_absence,
        evidence.pages_deployment_project_state,
        evidence.r2_parent_token,
        evidence.oauth_client_secret_state,
        evidence.oauth_client_update_state,
        evidence.worker_custom_domain_state,
        evidence.worker_deployment_state,
        evidence.dns_record_state,
        evidence.same_path_prior_state,
        evidence.access_operator_group_policy_ownership,
        evidence.security_action_state,
        evidence.web_analytics_rum_state,
        evidence.warp_connector_configuration_state,
        evidence.cloudflare_tunnel_configuration_state,
        evidence.d1_empty_database_state,
        evidence.kv_empty_namespace_state,
        evidence.d1_read_replication_state,
        evidence.global_warp_override_state,
        evidence.permission_inventory,
        evidence.entitlement,
        evidence.zone_account,
    ]
    .into_iter()
    .flatten()
    {
        envelope.evidence.insert(0, item);
    }
}
