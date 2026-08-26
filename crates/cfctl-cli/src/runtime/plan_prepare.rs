use super::api_boundary::blocked_capability_envelope;
use super::entitlement_state::should_bind_pages_project_absence;
use super::guide_generation::approval_command_argv;
use super::import_planning::SECURITY_ACTION_STATE_PRECONDITION;
use super::keys_commands::validate_selected_permission_groups;
use super::oauth_state::is_oauth_client_create_operation_identity;
use super::pages_deployment::PROJECT_ABSENCE_PRECONDITION;
use super::pages_source::SOURCE_REMOTE_PRECONDITION;
use super::pages_source::pages_source_remote_snapshot;
use super::pages_source::plan_impact;
use super::pages_source::registered_pages_source_repository;
use super::plan_create::prepare_cloudflare_tunnel_configuration_state_precondition;
use super::plan_create::prepare_d1_empty_database_state_precondition;
use super::plan_create::prepare_d1_read_replication_state_precondition;
use super::plan_create::prepare_dns_record_state_precondition;
use super::plan_create::prepare_global_warp_override_state_precondition;
use super::plan_create::prepare_kv_empty_namespace_state_precondition;
use super::plan_create::prepare_oauth_client_secret_state_precondition;
use super::plan_create::prepare_oauth_client_update_state_precondition;
use super::plan_create::prepare_pages_deployment_project_state_precondition;
use super::plan_create::prepare_pages_project_absence_precondition;
use super::plan_create::prepare_same_path_prior_state_precondition;
use super::plan_create::prepare_security_action_state_precondition;
use super::plan_create::prepare_warp_connector_configuration_state_precondition;
use super::plan_create::prepare_web_analytics_rum_state_precondition;
use super::plan_create::prepare_worker_deployment_state_precondition;
use super::plan_secret::ACCESS_OPERATOR_GROUP_POLICY_OWNERSHIP_PRECONDITION;
use super::plan_secret::CLOUDFLARE_TUNNEL_CONFIGURATION_STATE_PRECONDITION;
use super::plan_secret::D1_EMPTY_DATABASE_PRECONDITION;
use super::plan_secret::D1_READ_REPLICATION_PRECONDITION;
use super::plan_secret::DNS_RECORD_STATE_PRECONDITION;
use super::plan_secret::KV_EMPTY_NAMESPACE_PRECONDITION;
use super::plan_secret::OAUTH_CLIENT_KEY_OVERLAP_PRECONDITION;
use super::plan_secret::OAUTH_CLIENT_UPDATE_STATE_PRECONDITION;
use super::plan_secret::SAME_PATH_PRIOR_STATE_PRECONDITION;
use super::plan_secret::WARP_CONNECTOR_CONFIGURATION_STATE_PRECONDITION;
use super::plan_secret::WEB_ANALYTICS_RUM_STATE_PRECONDITION;
use super::policy_commands::active_admission_policy;
use super::prelude::{
    AuthCredential, BTreeMap, BTreeSet, CallInput, CapabilityV1, CatalogSnapshot, ChronoDuration,
    CliError, EvidenceClass, EvidenceV1, KeyMutationArgs, PlanPinsV2, PlanV1, PlanV2,
    PolicyDisposition, PolicyEngine, ProfileKind, ProfileMetadata, Result, ResultEnvelopeV2,
    StateStore, Utc, Value, VerificationState, json,
};
use super::r2_credentials::R2_PARENT_TOKEN_PRECONDITION;
use super::r2_credentials::is_r2_temporary_credentials_operation_identity;
use super::r2_credentials::should_bind_r2_parent_token;
use super::secret_io::preflight_secret_sink;
use super::workspace_state::discover_registered;
use super::workspace_state::workspace_precondition_hashes_for_scope;
use super::{pages_deployment, worker_custom_domain, worker_deployment};
use crate::build_identity::current_build_info;
use cfctl_core::hash_value;

pub(super) async fn prepare_live_plan_preconditions(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    adapter_targets: &Value,
    account_id: &str,
    credential: Option<&AuthCredential>,
) -> Result<LivePlanPreconditions> {
    Ok(LivePlanPreconditions {
        entitlement: None,
        zone_account: None,
        pages_project_absence: prepare_pages_project_absence_precondition(
            store, catalog, capability, input, account_id, credential,
        )
        .await?,
        pages_deployment_project_state: prepare_pages_deployment_project_state_precondition(
            store, catalog, capability, input, account_id, credential,
        )
        .await?,
        r2_parent_token: None,
        global_warp_override_state: prepare_global_warp_override_state_precondition(
            store, catalog, capability, input, account_id, credential,
        )
        .await?,
        d1_read_replication_state: prepare_d1_read_replication_state_precondition(
            store, catalog, capability, input, account_id, credential,
        )
        .await?,
        kv_empty_namespace_state: prepare_kv_empty_namespace_state_precondition(
            store,
            catalog,
            capability,
            input,
            adapter_targets,
            account_id,
            credential,
        )
        .await?,
        d1_empty_database_state: prepare_d1_empty_database_state_precondition(
            store,
            catalog,
            capability,
            input,
            adapter_targets,
            account_id,
            credential,
        )
        .await?,
        cloudflare_tunnel_configuration_state:
            prepare_cloudflare_tunnel_configuration_state_precondition(
                store, catalog, capability, input, account_id, credential,
            )
            .await?,
        warp_connector_configuration_state:
            prepare_warp_connector_configuration_state_precondition(
                store, catalog, capability, input, account_id, credential,
            )
            .await?,
        web_analytics_rum_state: prepare_web_analytics_rum_state_precondition(
            store, catalog, capability, input, account_id, credential,
        )
        .await?,
        dns_record_state: prepare_dns_record_state_precondition(
            store, catalog, capability, input, account_id, credential,
        )
        .await?,
        same_path_prior_state: prepare_same_path_prior_state_precondition(
            store, catalog, capability, input, account_id, credential,
        )
        .await?,
        access_operator_group_policy_ownership: None,
        security_action_state: prepare_security_action_state_precondition(
            store,
            catalog,
            capability,
            input,
            adapter_targets,
            account_id,
            credential,
        )
        .await?,
        oauth_client_secret_state: prepare_oauth_client_secret_state_precondition(
            store, catalog, capability, input, account_id, credential,
        )
        .await?,
        oauth_client_update_state: prepare_oauth_client_update_state_precondition(
            store, catalog, capability, input, account_id, credential,
        )
        .await?,
        worker_custom_domain_state: worker_custom_domain::prepare_state_precondition(
            store, catalog, capability, input, account_id, credential,
        )
        .await?,
        worker_deployment_state: prepare_worker_deployment_state_precondition(
            store,
            catalog,
            capability,
            adapter_targets,
            account_id,
            credential,
        )
        .await?,
    })
}

pub(super) struct PlanAuthority<'a> {
    pub(super) profile: &'a ProfileMetadata,
    pub(super) account_id: &'a str,
}

pub(super) struct LivePlanPreconditions {
    pub(super) entitlement: Option<(Value, EvidenceV1)>,
    pub(super) zone_account: Option<(Value, EvidenceV1)>,
    pub(super) pages_project_absence: Option<(Value, EvidenceV1)>,
    pub(super) pages_deployment_project_state: Option<(Value, EvidenceV1)>,
    pub(super) r2_parent_token: Option<(Value, EvidenceV1)>,
    pub(super) global_warp_override_state: Option<(Value, EvidenceV1)>,
    pub(super) d1_read_replication_state: Option<(Value, EvidenceV1)>,
    pub(super) d1_empty_database_state: Option<(Value, EvidenceV1)>,
    pub(super) kv_empty_namespace_state: Option<(Value, EvidenceV1)>,
    pub(super) cloudflare_tunnel_configuration_state: Option<(Value, EvidenceV1)>,
    pub(super) warp_connector_configuration_state: Option<(Value, EvidenceV1)>,
    pub(super) web_analytics_rum_state: Option<(Value, EvidenceV1)>,
    pub(super) dns_record_state: Option<(Value, EvidenceV1)>,
    pub(super) same_path_prior_state: Option<(Value, EvidenceV1)>,
    pub(super) access_operator_group_policy_ownership: Option<(Value, EvidenceV1)>,
    pub(super) security_action_state: Option<(Value, EvidenceV1)>,
    pub(super) oauth_client_secret_state: Option<(Value, EvidenceV1)>,
    pub(super) oauth_client_update_state: Option<(Value, EvidenceV1)>,
    pub(super) worker_custom_domain_state: Option<(Value, EvidenceV1)>,
    pub(super) worker_deployment_state: Option<(Value, EvidenceV1)>,
}

pub(super) fn plan_targets(
    input: &CallInput,
    account_id: &str,
    adapter_targets: &Value,
    live_preconditions: &LivePlanPreconditions,
) -> Value {
    let mut targets = json!({
        "selectors": input.selectors,
        "account_id": account_id,
        "adapter": adapter_targets,
    });
    if let Some((receipt, _)) = &live_preconditions.pages_project_absence {
        targets["live_preconditions"][PROJECT_ABSENCE_PRECONDITION] = receipt.clone();
    }
    if let Some((receipt, _)) = &live_preconditions.pages_deployment_project_state {
        targets["live_preconditions"][pages_deployment::PROJECT_STATE_PRECONDITION] =
            receipt.clone();
    }
    if let Some((receipt, _)) = &live_preconditions.global_warp_override_state {
        targets["live_preconditions"]["global_warp_override_state"] = receipt.clone();
    }
    if let Some((receipt, _)) = &live_preconditions.d1_read_replication_state {
        targets["live_preconditions"][D1_READ_REPLICATION_PRECONDITION] = receipt.clone();
    }
    if let Some((receipt, _)) = &live_preconditions.d1_empty_database_state {
        targets["live_preconditions"][D1_EMPTY_DATABASE_PRECONDITION] = receipt.clone();
    }
    if let Some((receipt, _)) = &live_preconditions.kv_empty_namespace_state {
        targets["live_preconditions"][KV_EMPTY_NAMESPACE_PRECONDITION] = receipt.clone();
    }
    if let Some((receipt, _)) = &live_preconditions.cloudflare_tunnel_configuration_state {
        targets["live_preconditions"][CLOUDFLARE_TUNNEL_CONFIGURATION_STATE_PRECONDITION] =
            receipt.clone();
    }
    if let Some((receipt, _)) = &live_preconditions.warp_connector_configuration_state {
        targets["live_preconditions"][WARP_CONNECTOR_CONFIGURATION_STATE_PRECONDITION] =
            receipt.clone();
    }
    if let Some((receipt, _)) = &live_preconditions.web_analytics_rum_state {
        targets["live_preconditions"][WEB_ANALYTICS_RUM_STATE_PRECONDITION] = receipt.clone();
    }
    if let Some((receipt, _)) = &live_preconditions.dns_record_state {
        targets["live_preconditions"][DNS_RECORD_STATE_PRECONDITION] = receipt.clone();
    }
    if let Some((receipt, _)) = &live_preconditions.same_path_prior_state {
        targets["live_preconditions"][SAME_PATH_PRIOR_STATE_PRECONDITION] = receipt.clone();
    }
    if let Some((receipt, _)) = &live_preconditions.access_operator_group_policy_ownership {
        targets["live_preconditions"][ACCESS_OPERATOR_GROUP_POLICY_OWNERSHIP_PRECONDITION] =
            receipt.clone();
    }
    if let Some((receipt, _)) = &live_preconditions.security_action_state {
        targets["live_preconditions"][SECURITY_ACTION_STATE_PRECONDITION] = receipt.clone();
    }
    if let Some((receipt, _)) = &live_preconditions.oauth_client_secret_state {
        targets["live_preconditions"][OAUTH_CLIENT_KEY_OVERLAP_PRECONDITION] = receipt.clone();
    }
    if let Some((receipt, _)) = &live_preconditions.oauth_client_update_state {
        targets["live_preconditions"][OAUTH_CLIENT_UPDATE_STATE_PRECONDITION] = receipt.clone();
    }
    if let Some((receipt, _)) = &live_preconditions.worker_custom_domain_state {
        targets["live_preconditions"]
            [worker_custom_domain::WORKER_CUSTOM_DOMAIN_STATE_PRECONDITION] = receipt.clone();
    }
    if let Some((receipt, _)) = &live_preconditions.worker_deployment_state {
        targets["live_preconditions"][worker_deployment::STATE_PRECONDITION] = receipt.clone();
    }
    if let Some((receipt, _)) = &live_preconditions.r2_parent_token {
        targets["live_preconditions"][R2_PARENT_TOKEN_PRECONDITION] = receipt.clone();
    }
    targets
}

pub(super) fn bind_live_plan_preconditions(
    plan: &mut PlanV1,
    live_preconditions: &LivePlanPreconditions,
) -> Result<()> {
    for (name, precondition) in [
        ("entitlement", &live_preconditions.entitlement),
        ("zone_account", &live_preconditions.zone_account),
        (
            PROJECT_ABSENCE_PRECONDITION,
            &live_preconditions.pages_project_absence,
        ),
        (
            pages_deployment::PROJECT_STATE_PRECONDITION,
            &live_preconditions.pages_deployment_project_state,
        ),
        (
            "global_warp_override_state",
            &live_preconditions.global_warp_override_state,
        ),
        (
            D1_READ_REPLICATION_PRECONDITION,
            &live_preconditions.d1_read_replication_state,
        ),
        (
            D1_EMPTY_DATABASE_PRECONDITION,
            &live_preconditions.d1_empty_database_state,
        ),
        (
            KV_EMPTY_NAMESPACE_PRECONDITION,
            &live_preconditions.kv_empty_namespace_state,
        ),
        (
            CLOUDFLARE_TUNNEL_CONFIGURATION_STATE_PRECONDITION,
            &live_preconditions.cloudflare_tunnel_configuration_state,
        ),
        (
            WARP_CONNECTOR_CONFIGURATION_STATE_PRECONDITION,
            &live_preconditions.warp_connector_configuration_state,
        ),
        (
            WEB_ANALYTICS_RUM_STATE_PRECONDITION,
            &live_preconditions.web_analytics_rum_state,
        ),
        (
            DNS_RECORD_STATE_PRECONDITION,
            &live_preconditions.dns_record_state,
        ),
        (
            SAME_PATH_PRIOR_STATE_PRECONDITION,
            &live_preconditions.same_path_prior_state,
        ),
        (
            ACCESS_OPERATOR_GROUP_POLICY_OWNERSHIP_PRECONDITION,
            &live_preconditions.access_operator_group_policy_ownership,
        ),
        (
            SECURITY_ACTION_STATE_PRECONDITION,
            &live_preconditions.security_action_state,
        ),
        (
            OAUTH_CLIENT_KEY_OVERLAP_PRECONDITION,
            &live_preconditions.oauth_client_secret_state,
        ),
        (
            OAUTH_CLIENT_UPDATE_STATE_PRECONDITION,
            &live_preconditions.oauth_client_update_state,
        ),
        (
            worker_custom_domain::WORKER_CUSTOM_DOMAIN_STATE_PRECONDITION,
            &live_preconditions.worker_custom_domain_state,
        ),
        (
            worker_deployment::STATE_PRECONDITION,
            &live_preconditions.worker_deployment_state,
        ),
        (
            R2_PARENT_TOKEN_PRECONDITION,
            &live_preconditions.r2_parent_token,
        ),
    ] {
        if let Some((receipt, _)) = precondition {
            plan.precondition_hashes
                .insert(name.to_owned(), hash_value(receipt)?);
        }
    }
    Ok(())
}

pub(super) fn planned_cloudflare_diff(
    plan: &PlanV1,
    input: &CallInput,
    live_preconditions: &LivePlanPreconditions,
) -> Value {
    let mut diff = json!({
        "request_method": plan.capability.method,
        "request_path": plan.capability.path,
        "request_body": input.body,
    });
    if let Some((receipt, _)) = &live_preconditions.global_warp_override_state {
        diff["observed_before"] = json!({
            "disconnect": receipt.get("disconnect").cloned().unwrap_or(Value::Null),
        });
        diff["planned_after"] = json!({
            "disconnect": input
                .body
                .as_ref()
                .and_then(|body| body.get("disconnect"))
                .cloned()
                .unwrap_or(Value::Null),
        });
    }
    if let Some((receipt, _)) = &live_preconditions.d1_read_replication_state {
        diff["observed_before"] = json!({
            "read_replication": receipt
                .get("read_replication")
                .cloned()
                .unwrap_or(Value::Null),
        });
        diff["planned_after"] = json!({
            "read_replication": input
                .body
                .as_ref()
                .and_then(|body| body.get("read_replication"))
                .cloned()
                .unwrap_or(Value::Null),
        });
    }
    if let Some((receipt, _)) = &live_preconditions.cloudflare_tunnel_configuration_state {
        diff["observed_before"] = json!({
            "config": receipt.get("prior_config").cloned().unwrap_or(Value::Null),
        });
        diff["planned_after"] = json!({
            "config": input
                .body
                .as_ref()
                .and_then(|body| body.get("config"))
                .cloned()
                .unwrap_or(Value::Null),
        });
    }
    if let Some((receipt, _)) = &live_preconditions.warp_connector_configuration_state {
        diff["observed_before"] = json!({
            "ha_mode": receipt
                .get("prior_ha_mode")
                .cloned()
                .unwrap_or(Value::Null),
            "config": receipt.get("prior_config").cloned().unwrap_or(Value::Null),
        });
        diff["planned_after"] = input.body.clone().unwrap_or(Value::Null);
    }
    if let Some((receipt, _)) = &live_preconditions.web_analytics_rum_state {
        diff["observed_before"] = json!({
            "value": receipt.get("prior_value").cloned().unwrap_or(Value::Null),
        });
        diff["planned_after"] = json!({
            "value": input
                .body
                .as_ref()
                .and_then(|body| body.get("value"))
                .cloned()
                .unwrap_or(Value::Null),
        });
    }
    if let Some((receipt, _)) = &live_preconditions.dns_record_state {
        diff["observed_before"] = receipt.get("prior_record").cloned().unwrap_or(Value::Null);
        diff["planned_after"] = input.body.clone().unwrap_or(Value::Null);
    }
    if let Some((receipt, _)) = &live_preconditions.same_path_prior_state {
        diff["observed_before"] = receipt.get("prior_state").cloned().unwrap_or(Value::Null);
        diff["planned_after"] = input.body.clone().unwrap_or(Value::Null);
    }
    if let Some((receipt, _)) = &live_preconditions.security_action_state {
        diff["security_current_state"] = receipt.get("state").cloned().unwrap_or(Value::Null);
        diff["security_governance"] = plan
            .targets
            .pointer("/adapter/security_action")
            .cloned()
            .unwrap_or(Value::Null);
    }
    if let Some((receipt, _)) = &live_preconditions.oauth_client_secret_state {
        let observed_before = receipt
            .get("key_overlap_active")
            .cloned()
            .unwrap_or(Value::Null);
        diff["observed_before"] = json!({"key_overlap_active": observed_before});
        diff["planned_after"] = json!({
            "key_overlap_active": !observed_before.as_bool().unwrap_or(false)
        });
    }
    apply_oauth_client_update_plan_diff(&mut diff, input, live_preconditions);
    apply_worker_deployment_plan_diff(&mut diff, plan, live_preconditions);
    diff
}

pub(super) fn apply_worker_deployment_plan_diff(
    diff: &mut Value,
    plan: &PlanV1,
    live_preconditions: &LivePlanPreconditions,
) {
    if let Some((state, _)) = &live_preconditions.worker_deployment_state {
        worker_deployment::apply_plan_diff(diff, plan, state);
    }
}

pub(super) fn apply_oauth_client_update_plan_diff(
    diff: &mut Value,
    input: &CallInput,
    live_preconditions: &LivePlanPreconditions,
) {
    if let Some((receipt, _)) = &live_preconditions.oauth_client_update_state {
        diff["observed_before"] = receipt.get("prior_state").cloned().unwrap_or(Value::Null);
        diff["planned_after"] = input.body.clone().unwrap_or(Value::Null);
        diff["irreversible_visibility_promotion"] = Value::Bool(
            input.body.as_ref().and_then(|body| body.get("visibility")) == Some(&json!("public")),
        );
    }
}

pub(super) fn prepare_pages_source_remote_precondition(
    store: &StateStore,
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<Option<Value>> {
    if !should_bind_pages_project_absence(capability) {
        return Ok(None);
    }
    let graph = discover_registered(store)?;
    let repository = registered_pages_source_repository(&graph, input)?;
    pages_source_remote_snapshot(repository, input).map(Some)
}

#[expect(
    clippy::too_many_lines,
    reason = "PlanV1 compatibility, PlanV2 pins, durable persistence, and the returned preview must be constructed from one immutable preparation context"
)]
pub(super) fn persist_prepared_plan(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: cfctl_core::CapabilityV1,
    input: CallInput,
    authority: PlanAuthority<'_>,
    adapter_targets: Value,
    live_preconditions: LivePlanPreconditions,
) -> Result<ResultEnvelopeV2> {
    let PlanAuthority {
        profile,
        account_id,
    } = authority;
    validate_api_token_creation_contract(&capability, &input, &adapter_targets, account_id)?;
    validate_prepared_r2_parent_token_contract(
        &capability,
        &input,
        profile,
        account_id,
        &live_preconditions,
    )?;
    let impact = plan_impact(store, &capability, &input, account_id)?;
    let compiled_policy = PolicyEngine.evaluate(&capability, &impact.policy);
    let active_policy = active_admission_policy(store)?;
    let policy = active_policy.as_ref().map_or_else(
        || Ok(compiled_policy.clone()),
        |bundle| bundle.tighten(&compiled_policy, &capability),
    )?;
    if policy.disposition == PolicyDisposition::Blocked {
        return Ok(blocked_capability_envelope(
            "call",
            &capability,
            &policy.reasons.join("; "),
        ));
    }
    let pages_source_remote = prepare_pages_source_remote_precondition(store, &capability, &input)?;
    let mut targets = plan_targets(&input, account_id, &adapter_targets, &live_preconditions);
    if let Some(snapshot) = &pages_source_remote {
        targets["source_preconditions"][SOURCE_REMOTE_PRECONDITION] = snapshot.clone();
    }
    let mut plan = PlanV1::draft(
        &profile.id,
        account_id,
        &catalog.schema_hash,
        capability,
        targets,
    )?;
    match profile.kind {
        ProfileKind::OAuth => "oauth",
        ProfileKind::ApiToken => "api_token",
        ProfileKind::LegacyWranglerSession => "unsupported_legacy_wrangler_session",
        ProfileKind::GlobalKey => "emergency_global_key",
    }
    .clone_into(&mut plan.permission_lane);
    plan.input = serde_json::to_value(&input)?;
    if is_oauth_client_create_operation_identity(&plan.capability) {
        preflight_secret_sink(&plan)?;
    }
    plan.precondition_hashes
        .insert("catalog".to_owned(), catalog.schema_hash.clone());
    plan.precondition_hashes
        .insert("request_input".to_owned(), hash_value(&plan.input)?);
    bind_live_plan_preconditions(&mut plan, &live_preconditions)?;
    if let Some(snapshot) = &pages_source_remote {
        plan.precondition_hashes
            .insert(SOURCE_REMOTE_PRECONDITION.to_owned(), hash_value(snapshot)?);
    }
    plan.precondition_hashes
        .extend(workspace_precondition_hashes_for_scope(
            store,
            &impact.affected_repositories,
            &impact.local_artifact_paths,
        )?);
    plan.affected_repositories = impact.affected_repositories;
    plan.affected_resources = impact.affected_resources;
    plan.local_diffs = impact.local_diffs;
    let cloudflare_diff = planned_cloudflare_diff(&plan, &input, &live_preconditions);
    plan.cloudflare_diffs.push(cloudflare_diff);
    plan.verification_steps
        .push(plan.capability.verification.strategy.clone());
    if let Some(strategy) = &plan.capability.rollback.strategy {
        plan.compensation_steps.push(strategy.clone());
    }
    if let Some(warning) = &plan.capability.rollback.warning {
        plan.non_reversible_warnings.push(warning.clone());
    }
    plan.policy = policy.clone();
    plan.refresh_hash()?;
    let build_identity_hash = hash_value(&serde_json::to_value(current_build_info())?)?;
    let credential_generation_id = profile.credential_generation_id.clone().ok_or_else(|| {
        CliError::guided(
            "CFCTL_CREDENTIAL_UNBOUND",
            format!(
                "profile `{}` has no credential generation and cannot create a PlanV2",
                profile.id
            ),
            format!(
                "Re-import or log in to profile `{}` before creating the mutation plan.",
                profile.id
            ),
        )
    })?;
    let admission_policy_hash = active_policy.as_ref().map_or_else(
        || {
            hash_value(&json!({"compiled_safety_floor": compiled_policy}))
                .map(|hash| format!("compiled:{hash}"))
        },
        |bundle| Ok(format!("bundle:{}", bundle.content_hash)),
    )?;
    let workspace_graph_hash = plan
        .precondition_hashes
        .get("workspace_graph")
        .cloned()
        .ok_or_else(|| {
            CliError::Input("PlanV2 requires a pinned workspace graph hash".to_owned())
        })?;
    let resource_observation_hashes = plan
        .precondition_hashes
        .iter()
        .filter(|(key, _)| {
            !matches!(
                key.as_str(),
                "catalog" | "request_input" | "workspace_graph"
            )
        })
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let plan_v2 = PlanV2::new(
        plan.clone(),
        PlanPinsV2 {
            build_identity_hash,
            catalog_hash: catalog.schema_hash.clone(),
            credential_generation_id,
            admission_policy_hash,
            authority_hash: None,
            workspace_graph_hash,
            resource_observation_hashes,
            cost_budget: None,
        },
    )?;
    store.save_plan_v2(&plan_v2)?;
    let evidence =
        store.write_evidence(EvidenceClass::Preview, &serde_json::to_value(&plan_v2)?)?;
    let mut envelope = ResultEnvelopeV2::success(
        "call",
        json!({
            "plan": plan,
            "plan_v2": plan_v2,
            "approval_command": approval_command_argv(&plan.capability, &plan.operation_id).join(" "),
            "run_command": format!("cfctl plans run {}", plan.operation_id),
            "message": if policy.disposition == PolicyDisposition::AutoExecute {
                "Plan created and policy-authorized for automatic execution; run the exact operation ID."
            } else {
                "Plan created. Review it, then approve the exact operation ID with y/n."
            }
        }),
    )
    .with_evidence(evidence);
    envelope.capability_id = Some(plan.capability.id.clone());
    envelope.operation_id = Some(plan.operation_id.clone());
    envelope.profile_id = Some(profile.id.clone());
    envelope.account_id = Some(account_id.to_owned());
    envelope.policy_decision = Some(policy);
    envelope.verification.state = VerificationState::Pending;
    prepend_prepared_plan_evidence(&mut envelope, live_preconditions);
    Ok(envelope)
}

pub(super) fn prepend_prepared_plan_evidence(
    envelope: &mut ResultEnvelopeV2,
    live_preconditions: LivePlanPreconditions,
) {
    for (_, evidence) in [
        live_preconditions.entitlement,
        live_preconditions.zone_account,
        live_preconditions.global_warp_override_state,
        live_preconditions.d1_read_replication_state,
        live_preconditions.cloudflare_tunnel_configuration_state,
        live_preconditions.warp_connector_configuration_state,
        live_preconditions.web_analytics_rum_state,
        live_preconditions.dns_record_state,
        live_preconditions.same_path_prior_state,
        live_preconditions.access_operator_group_policy_ownership,
        live_preconditions.security_action_state,
        live_preconditions.oauth_client_secret_state,
        live_preconditions.oauth_client_update_state,
        live_preconditions.r2_parent_token,
    ]
    .into_iter()
    .flatten()
    {
        envelope.evidence.insert(0, evidence);
    }
}

pub(super) fn validate_prepared_r2_parent_token_contract(
    capability: &CapabilityV1,
    input: &CallInput,
    profile: &ProfileMetadata,
    account_id: &str,
    live_preconditions: &LivePlanPreconditions,
) -> Result<()> {
    if !is_r2_temporary_credentials_operation_identity(capability) {
        return Ok(());
    }
    if !should_bind_r2_parent_token(capability) || profile.kind != ProfileKind::ApiToken {
        return Err(CliError::Input(
            "R2 temporary credential plan is inconsistent with its governed active API-token parent contract"
                .to_owned(),
        ));
    }
    let (receipt, _) = live_preconditions.r2_parent_token.as_ref().ok_or_else(|| {
        CliError::Input(
            "R2 temporary credential plan is missing its live parent-token receipt".to_owned(),
        )
    })?;
    let parent = input
        .body
        .as_ref()
        .and_then(|body| body.get("parentAccessKeyId"))
        .and_then(Value::as_str);
    if receipt.get("account_id").and_then(Value::as_str) != Some(account_id)
        || receipt.get("parent_access_key_id").and_then(Value::as_str) != parent
    {
        return Err(CliError::Input(
            "R2 temporary credential parent-token receipt does not match the planned account and request"
                .to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn validate_api_token_creation_contract(
    capability: &CapabilityV1,
    input: &CallInput,
    adapter_targets: &Value,
    account_id: &str,
) -> Result<()> {
    let Some(inventory_contract) = token_permission_inventory_contract(&capability.id) else {
        return Ok(());
    };
    let inventory = adapter_targets
        .get("permission_inventory")
        .ok_or_else(|| {
            CliError::Input(
                "direct token-create calls are blocked because they do not bind a fresh permission inventory; use `cfctl keys mint`"
                    .to_owned(),
            )
        })?;
    if inventory
        .get("source_capability_id")
        .and_then(Value::as_str)
        != Some(inventory_contract.capability_id)
    {
        return Err(CliError::Input(format!(
            "token mint permission metadata is not bound to the required `{}` inventory capability",
            inventory_contract.capability_id
        )));
    }
    let selected_groups = inventory
        .get("selected_groups")
        .and_then(Value::as_array)
        .filter(|groups| !groups.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "token mint permission inventory contains no selected groups".to_owned(),
            )
        })?;
    let selected_ids = selected_groups
        .iter()
        .map(|group| {
            group
                .get("id")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| {
                    CliError::Input(
                        "token mint permission inventory contains a group without an ID".to_owned(),
                    )
                })
        })
        .collect::<Result<Vec<_>>>()?;
    let normalized_groups =
        validate_selected_permission_groups(&selected_ids, &Value::Array(selected_groups.clone()))?;
    let policy_bindings = token_policy_bindings_from_inventory(
        inventory,
        &normalized_groups,
        &selected_ids,
        account_id,
    )?;
    let expected_hash = inventory
        .get("selected_groups_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input("token mint permission inventory hash is missing".to_owned())
        })?;
    if hash_value(&serde_json::to_value(&normalized_groups)?)? != expected_hash {
        return Err(CliError::Input(
            "token mint permission inventory metadata does not match its bound hash".to_owned(),
        ));
    }
    let evidence_hashes = inventory
        .get("evidence_hashes")
        .and_then(Value::as_array)
        .filter(|hashes| {
            !hashes.is_empty()
                && hashes.iter().all(|hash| {
                    hash.as_str()
                        .is_some_and(|hash| hash.starts_with("sha256:") && hash.len() == 71)
                })
        })
        .ok_or_else(|| {
            CliError::Input(
                "token mint permission inventory is missing a live-read evidence hash".to_owned(),
            )
        })?;
    if evidence_hashes.len() != 1 {
        return Err(CliError::Input(
            "token mint permission inventory must bind exactly one live-read evidence receipt"
                .to_owned(),
        ));
    }
    validate_token_policy_body_bindings(input.body.as_ref(), &policy_bindings)
}

#[derive(Clone, Copy)]
pub(super) struct TokenPermissionInventoryContract {
    pub(super) capability_id: &'static str,
    pub(super) path: &'static str,
    pub(super) account_selector: bool,
}

pub(super) fn token_permission_inventory_contract(
    token_create_capability_id: &str,
) -> Option<TokenPermissionInventoryContract> {
    match token_create_capability_id {
        "account-api-tokens-create-token" => Some(TokenPermissionInventoryContract {
            capability_id: "account-api-tokens-list-permission-groups",
            path: "/accounts/{account_id}/tokens/permission_groups",
            account_selector: true,
        }),
        "user-api-tokens-create-token" => Some(TokenPermissionInventoryContract {
            capability_id: "permission-groups-list-permission-groups",
            path: "/user/tokens/permission_groups",
            account_selector: false,
        }),
        _ => None,
    }
}

/// A standing authority's groups must all be bindable to something the
/// authority actually pins. Account scope is always acceptable; zone scope only
/// when the authority pins a zone. A group supporting neither would be
/// unmintable under the authority, so reject it at draft time rather than
/// leaving a dead group in an approved allowlist.
pub(super) fn validate_standing_authority_group_scopes(
    groups: &[Value],
    zone_id: Option<&str>,
) -> Result<()> {
    let account_scope = "com.cloudflare.api.account";
    if zone_id.is_none() {
        return validate_permission_group_resource_scope(groups, account_scope);
    }
    let zone_scope = "com.cloudflare.api.account.zone";
    for group in groups {
        let id = group
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("<missing>");
        if !permission_group_supports_scope(group, account_scope)
            && !permission_group_supports_scope(group, zone_scope)
        {
            return Err(CliError::Input(format!(
                "permission group `{id}` supports neither `{account_scope}` nor `{zone_scope}`, so no child of this authority could bind it"
            )));
        }
    }
    Ok(())
}

pub(super) fn validate_permission_group_resource_scope(
    groups: &[Value],
    required_scope: &str,
) -> Result<()> {
    for group in groups {
        let id = group
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("<missing>");
        let supports_scope = group
            .get("scopes")
            .and_then(Value::as_array)
            .is_some_and(|scopes| {
                scopes
                    .iter()
                    .any(|scope| scope.as_str() == Some(required_scope))
            });
        if !supports_scope {
            return Err(CliError::Input(format!(
                "permission group `{id}` does not support the required resource scope `{required_scope}`"
            )));
        }
    }
    Ok(())
}

/// Resolves the least-privilege resource scope for a mint: the whole `--account`
/// (default) or a single `--zone`. Returns the permission scope selected groups
/// must support and the exact policy resource `{scope}.{id}`. Zone-scoped
/// permission groups (Cache Purge, DNS Write, …) carry scope
/// `com.cloudflare.api.account.zone`, which the whole-account scope does not
/// admit — resolving to the zone scope is what lets those groups mint through
/// the governed lane instead of an out-of-band raw token.
pub(super) fn resolve_mint_token_scope(
    arguments: &KeyMutationArgs,
    account: &str,
) -> Result<(&'static str, String)> {
    match arguments.zone.as_deref() {
        Some(zone_id) => {
            if arguments.user {
                return Err(CliError::Input(
                    "zone-scoped minting is account-owned; omit --user (the token still belongs to --account)"
                        .to_owned(),
                ));
            }
            validate_zone_id(zone_id)?;
            Ok((
                "com.cloudflare.api.account.zone",
                format!("com.cloudflare.api.account.zone.{zone_id}"),
            ))
        }
        None => Ok((
            "com.cloudflare.api.account",
            format!("com.cloudflare.api.account.{account}"),
        )),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct TokenPolicyBinding {
    pub(super) permission_scope: String,
    pub(super) token_resource: String,
    pub(super) permission_group_ids: Vec<String>,
}

impl TokenPolicyBinding {
    pub(super) fn as_json(&self) -> Value {
        json!({
            "permission_scope": self.permission_scope,
            "token_resource": self.token_resource,
            "permission_group_ids": self.permission_group_ids,
        })
    }
}

pub(super) fn permission_group_supports_scope(group: &Value, scope: &str) -> bool {
    group
        .get("scopes")
        .and_then(Value::as_array)
        .is_some_and(|scopes| {
            scopes
                .iter()
                .any(|candidate| candidate.as_str() == Some(scope))
        })
}

/// Partitions a token's selected permissions into the exact resource scopes
/// Cloudflare accepts. With `--zone`, zone-capable permissions are bound to the
/// named zone while account-only permissions remain bound to the account. A
/// group supporting neither resource class fails closed.
pub(super) fn resolve_mint_token_bindings(
    arguments: &KeyMutationArgs,
    account: &str,
    selected_groups: &[Value],
) -> Result<Vec<TokenPolicyBinding>> {
    let (preferred_scope, preferred_resource) = resolve_mint_token_scope(arguments, account)?;
    let account_scope = "com.cloudflare.api.account";
    let account_resource = format!("{account_scope}.{account}");
    let mut account_ids = Vec::new();
    let mut preferred_ids = Vec::new();

    for group in selected_groups {
        let id = group.get("id").and_then(Value::as_str).ok_or_else(|| {
            CliError::Input("selected permission group is missing its ID".to_owned())
        })?;
        if preferred_scope != account_scope
            && permission_group_supports_scope(group, preferred_scope)
        {
            preferred_ids.push(id.to_owned());
        } else if permission_group_supports_scope(group, account_scope) {
            account_ids.push(id.to_owned());
        } else {
            return Err(CliError::Input(format!(
                "permission group `{id}` supports neither the account resource scope nor the requested `{preferred_scope}` scope"
            )));
        }
    }

    let mut bindings = Vec::new();
    if !account_ids.is_empty() {
        bindings.push(TokenPolicyBinding {
            permission_scope: account_scope.to_owned(),
            token_resource: account_resource,
            permission_group_ids: account_ids,
        });
    }
    if !preferred_ids.is_empty() {
        bindings.push(TokenPolicyBinding {
            permission_scope: preferred_scope.to_owned(),
            token_resource: preferred_resource,
            permission_group_ids: preferred_ids,
        });
    }
    Ok(bindings)
}

pub(super) fn token_policy_bindings_from_inventory(
    inventory: &Value,
    selected_groups: &[Value],
    selected_ids: &[String],
    account_id: &str,
) -> Result<Vec<TokenPolicyBinding>> {
    let Some(raw_bindings) = inventory.get("permission_bindings") else {
        // Backward compatibility for plans minted before mixed-scope support.
        let permission_scope = inventory
            .get("permission_scope")
            .and_then(Value::as_str)
            .unwrap_or("com.cloudflare.api.account");
        let default_resource = format!("com.cloudflare.api.account.{account_id}");
        let token_resource = inventory
            .get("token_resource")
            .and_then(Value::as_str)
            .unwrap_or(&default_resource);
        validate_token_binding_resource(permission_scope, token_resource, account_id)?;
        validate_permission_group_resource_scope(selected_groups, permission_scope)?;
        return Ok(vec![TokenPolicyBinding {
            permission_scope: permission_scope.to_owned(),
            token_resource: token_resource.to_owned(),
            permission_group_ids: selected_ids.to_vec(),
        }]);
    };

    let raw_bindings = raw_bindings
        .as_array()
        .filter(|bindings| !bindings.is_empty())
        .ok_or_else(|| CliError::Input("token mint permission bindings are empty".to_owned()))?;
    let groups_by_id = selected_groups
        .iter()
        .filter_map(|group| {
            group
                .get("id")
                .and_then(Value::as_str)
                .map(|id| (id, group))
        })
        .collect::<BTreeMap<_, _>>();
    let mut bound_ids = Vec::new();
    let mut resources = BTreeSet::new();
    let mut bindings = Vec::new();
    for raw in raw_bindings {
        let permission_scope = raw
            .get("permission_scope")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CliError::Input("token mint permission binding has no scope".to_owned())
            })?;
        let token_resource = raw
            .get("token_resource")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CliError::Input("token mint permission binding has no resource".to_owned())
            })?;
        validate_token_binding_resource(permission_scope, token_resource, account_id)?;
        if !resources.insert(token_resource.to_owned()) {
            return Err(CliError::Input(
                "token mint permission bindings repeat a resource".to_owned(),
            ));
        }
        let permission_group_ids = raw
            .get("permission_group_ids")
            .and_then(Value::as_array)
            .filter(|ids| !ids.is_empty())
            .ok_or_else(|| {
                CliError::Input("token mint permission binding has no permission groups".to_owned())
            })?
            .iter()
            .map(|id| {
                id.as_str().map(str::to_owned).ok_or_else(|| {
                    CliError::Input(
                        "token mint permission binding contains a non-string group ID".to_owned(),
                    )
                })
            })
            .collect::<Result<Vec<_>>>()?;
        for id in &permission_group_ids {
            let group = groups_by_id.get(id.as_str()).ok_or_else(|| {
                CliError::Input(format!(
                    "token mint permission binding references unselected group `{id}`"
                ))
            })?;
            validate_permission_group_resource_scope(
                std::slice::from_ref(group),
                permission_scope,
            )?;
            bound_ids.push(id.clone());
        }
        bindings.push(TokenPolicyBinding {
            permission_scope: permission_scope.to_owned(),
            token_resource: token_resource.to_owned(),
            permission_group_ids,
        });
    }
    let original_len = bound_ids.len();
    bound_ids.sort();
    bound_ids.dedup();
    if original_len != bound_ids.len() || bound_ids != selected_ids {
        return Err(CliError::Input(
            "token mint permission bindings do not partition the selected live inventory exactly once".to_owned(),
        ));
    }
    Ok(bindings)
}

/// Builds one least-privilege token-create policy per exact resource binding,
/// plus an optional expiry. The contract validator rechecks every policy
/// against the hash-bound live permission inventory before the mint runs.
pub(super) fn build_mint_policy_body(
    name: &str,
    bindings: &[TokenPolicyBinding],
    ttl_hours: Option<u32>,
) -> Value {
    let mut body = json!({
        "name": name,
        "policies": bindings.iter().map(|binding| json!({
            "effect": "allow",
            "permission_groups": binding.permission_group_ids.iter().map(|id| json!({"id": id})).collect::<Vec<_>>(),
            "resources": {binding.token_resource.clone(): "*"}
        })).collect::<Vec<_>>()
    });
    if let Some(hours) = ttl_hours {
        // Cloudflare's token API requires seconds-precision UTC with a `Z`
        // suffix (e.g. 2005-12-30T01:02:03Z) and rejects the fractional-second
        // `+00:00` form that `to_rfc3339()` emits with a 400.
        body["expires_on"] = json!(
            (Utc::now() + ChronoDuration::hours(i64::from(hours)))
                .format("%Y-%m-%dT%H:%M:%SZ")
                .to_string()
        );
    }
    body
}

/// Fail-closed local check on a `--zone` argument: Cloudflare zone ids are
/// 32-character lowercase hex. Cross-account zone ownership is still enforced at
/// the Cloudflare boundary when the governed plan runs; this only rejects
/// obviously-malformed input before it becomes a plan.
pub(super) fn validate_zone_id(zone_id: &str) -> Result<()> {
    let well_formed = zone_id.len() == 32
        && zone_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if well_formed {
        Ok(())
    } else {
        Err(CliError::Input(format!(
            "`--zone` expects a 32-character lowercase-hex Cloudflare zone id, got `{zone_id}`"
        )))
    }
}

/// Fail-closed: the token resource must be exactly `{scope}.{id}` where `id` is
/// a single concrete account/zone identifier — ASCII alphanumeric and `-` only.
/// This rejects a nested scope (`.zone.<id>` under the account scope, or the
/// reverse) AND a wildcard id (`*`), so no claimed permission scope can be
/// widened to a broader resource even if the hash-bound metadata were tampered.
pub(super) fn validate_resource_is_single_concrete_id_under_scope(
    expected_resource: &str,
    permission_scope: &str,
) -> Result<()> {
    let ok = expected_resource
        .strip_prefix(permission_scope)
        .and_then(|rest| rest.strip_prefix('.'))
        .is_some_and(|id| {
            !id.is_empty()
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    if ok {
        Ok(())
    } else {
        Err(CliError::Input(format!(
            "token mint resource `{expected_resource}` is not a single concrete resource under its declared permission scope `{permission_scope}`"
        )))
    }
}

pub(super) fn validate_token_binding_resource(
    permission_scope: &str,
    token_resource: &str,
    account_id: &str,
) -> Result<()> {
    validate_resource_is_single_concrete_id_under_scope(token_resource, permission_scope)?;
    match permission_scope {
        "com.cloudflare.api.account" => {
            let expected = format!("com.cloudflare.api.account.{account_id}");
            if token_resource != expected {
                return Err(CliError::Input(format!(
                    "token mint account resource must be the selected account `{expected}`"
                )));
            }
        }
        "com.cloudflare.api.account.zone" => {
            let zone_id = token_resource
                .strip_prefix("com.cloudflare.api.account.zone.")
                .ok_or_else(|| {
                    CliError::Input(format!(
                        "token mint zone resource `{token_resource}` is not under the declared zone scope"
                    ))
                })?;
            validate_zone_id(zone_id)?;
        }
        other => {
            return Err(CliError::Input(format!(
                "token mint permission binding uses unsupported resource scope `{other}`"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn validate_token_policy_body(
    body: Option<&Value>,
    selected_ids: &[String],
    expected_resource: &str,
) -> Result<()> {
    validate_token_policy_body_bindings(
        body,
        &[TokenPolicyBinding {
            permission_scope: String::new(),
            token_resource: expected_resource.to_owned(),
            permission_group_ids: selected_ids.to_vec(),
        }],
    )
}

pub(super) fn validate_token_policy_body_bindings(
    body: Option<&Value>,
    bindings: &[TokenPolicyBinding],
) -> Result<()> {
    let policies = body
        .and_then(|body| body.get("policies"))
        .and_then(Value::as_array)
        .filter(|policies| policies.len() == bindings.len())
        .ok_or_else(|| {
            CliError::Input(
                "token minting requires exactly one hash-bound least-privilege policy per resource binding".to_owned(),
            )
        })?;
    let expected = bindings
        .iter()
        .map(|binding| {
            let mut ids = binding.permission_group_ids.clone();
            ids.sort();
            (binding.token_resource.clone(), ids)
        })
        .collect::<BTreeMap<_, _>>();
    let mut actual = BTreeMap::new();
    for policy in policies {
        if policy.get("effect").and_then(Value::as_str) != Some("allow") {
            return Err(CliError::Input(
                "token minting requires explicit allow policies".to_owned(),
            ));
        }
        let mut body_ids = policy
            .get("permission_groups")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                CliError::Input("token mint policy has no permission-group list".to_owned())
            })?
            .iter()
            .map(|group| {
                group
                    .get("id")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .ok_or_else(|| {
                        CliError::Input(
                            "token mint policy contains a permission group without an ID"
                                .to_owned(),
                        )
                    })
            })
            .collect::<Result<Vec<_>>>()?;
        let original_len = body_ids.len();
        body_ids.sort();
        body_ids.dedup();
        if original_len != body_ids.len() {
            return Err(CliError::Input(
                "token mint policy repeats a permission group".to_owned(),
            ));
        }
        let resources = policy
            .get("resources")
            .and_then(Value::as_object)
            .filter(|resources| resources.len() == 1)
            .ok_or_else(|| {
                CliError::Input("token mint policy must bind exactly one resource".to_owned())
            })?;
        let (resource, value) = resources.iter().next().ok_or_else(|| {
            CliError::Input("token mint policy must bind exactly one resource".to_owned())
        })?;
        if value.as_str() != Some("*") || actual.insert(resource.clone(), body_ids).is_some() {
            return Err(CliError::Input(
                "token mint policy resource binding is invalid or repeated".to_owned(),
            ));
        }
    }
    if actual != expected {
        let expected_resources = expected.keys().cloned().collect::<Vec<_>>().join(", ");
        return Err(CliError::Input(format!(
            "token mint policies do not exactly match the hash-bound permission/resource partition for `{expected_resources}`"
        )));
    }
    Ok(())
}
