use super::access_application::is_access_application_login_methods_mutation;
use super::access_application::prepare_access_application_login_methods_plan_input;
use super::access_ownership::read_live_access_operator_group_policy_ownership;
use super::access_ownership::read_live_same_path_prior_state;
use super::access_policy::is_access_application_owned_whole_host_mutation;
use super::access_policy::is_access_human_policy_mutation;
use super::access_policy::is_access_operator_group_policy_create;
use super::access_policy::is_access_operator_group_policy_update;
use super::access_policy::prepare_access_human_policy_plan_input;
use super::call_input::resolve_account_id;
use super::cloudflare_api::BASE_URL as API_BASE_URL;
use super::credential_resolution::fresh_credential;
use super::credential_resolution::platform_secrets;
use super::entitlement_state::plan_requires_live_credential;
use super::entitlement_state::read_live_entitlement_probe;
use super::entitlement_state::read_live_pages_project_absence;
use super::entitlement_state::read_live_zone_account;
use super::entitlement_state::read_live_zone_entitlement;
use super::entitlement_state::should_bind_pages_project_absence;
use super::entitlement_state::should_bind_zone_account;
use super::entitlement_state::should_resolve_entitlement_probe;
use super::entitlement_state::should_resolve_zone_entitlement;
use super::live_state_contracts::should_bind_cloudflare_tunnel_configuration_state;
use super::live_state_contracts::should_bind_d1_empty_database_state;
use super::live_state_contracts::should_bind_d1_read_replication_state;
use super::live_state_contracts::should_bind_dns_record_state;
use super::live_state_contracts::should_bind_global_warp_override_state;
use super::live_state_contracts::should_bind_same_path_prior_state;
use super::live_state_contracts::should_bind_warp_connector_configuration_state;
use super::live_state_contracts::should_bind_web_analytics_rum_state;
use super::oauth_state::read_live_oauth_client_secret_state;
use super::oauth_state::read_live_oauth_client_update_state;
use super::oauth_state::should_bind_oauth_client_secret_state;
use super::oauth_state::should_bind_oauth_client_update_state;
use super::plan_prepare::LivePlanPreconditions;
use super::plan_prepare::PlanAuthority;
use super::plan_prepare::persist_prepared_plan;
use super::plan_prepare::prepare_live_plan_preconditions;
use super::plan_secret::KV_EMPTY_NAMESPACE_COMPENSATION_STRATEGY;
use super::plan_secret::KV_EMPTY_NAMESPACE_PRECONDITION;
use super::plan_secret::KV_NAMESPACE_CREATE_CAPABILITY_ID;
use super::plan_secret::KV_NAMESPACE_DELETE_CAPABILITY_ID;
use super::plan_secret::KV_NAMESPACE_KEYS_READ_CAPABILITY_ID;
use super::prelude::{
    AdapterStatus, AuthCredential, BTreeSet, CallInput, CapabilityV1, CatalogSnapshot, CliError,
    CloudflareResponseV1, EvidenceClass, EvidenceV1, Executor, PlanV1, ProfileKind, ProfilesConfig,
    Result, ResultEnvelopeV2, StateStore, Value, json,
};
use super::provider_state::read_live_cloudflare_tunnel_configuration_state;
use super::provider_state::read_live_d1_empty_database_state;
use super::provider_state::read_live_d1_read_replication_state;
use super::provider_state::read_live_dns_record_state;
use super::provider_state::read_live_global_warp_override_state;
use super::provider_state::read_live_warp_connector_configuration_state;
use super::provider_state::read_live_web_analytics_rum_state;
use super::r2_credentials::read_live_r2_parent_token;
use super::r2_credentials::should_bind_r2_parent_token;
use super::security_action_state::read_live_security_action_state;
use super::security_action_state::should_bind_security_action_state;
use super::support::capability_missing;
use super::support::http_client;
use super::{pages_deployment, worker_deployment};
use cfctl_core::hash_value;

#[expect(
    clippy::too_many_lines,
    reason = "plan creation keeps current-state evidence, normalization, risk, cost, permission, entitlement, verification, rollback, and immutable hashing together"
)]
pub(super) async fn create_plan(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    mut capability: cfctl_core::CapabilityV1,
    mut input: CallInput,
    requested_profile: Option<&str>,
    requested_account: Option<&str>,
    adapter_targets: Value,
) -> Result<ResultEnvelopeV2> {
    let profiles = ProfilesConfig::load(store)?;
    let profile = profiles.selected(requested_profile)?;
    let resolved_account = resolve_account_id(store, profile, requested_account, &input)?;
    let account_id = resolved_account
        .as_deref()
        .or_else(|| matches!(capability.account_scope.as_str(), "user" | "global").then_some("user"))
        .ok_or_else(|| {
            CliError::Input(
                "this capability needs an explicit account; pin one on the profile or pass `--account`"
                    .to_owned(),
            )
    })?;
    let resolve_entitlement_probe = should_resolve_entitlement_probe(&capability);
    let resolve_entitlement = should_resolve_zone_entitlement(&capability);
    let credential = if plan_requires_live_credential(&capability, &adapter_targets) {
        Some(fresh_credential(profile, &platform_secrets(store)).await?)
    } else {
        None
    };
    let access_state_precondition = if is_access_operator_group_policy_update(&capability) {
        let credential = credential.as_ref().ok_or_else(|| {
            CliError::Input(
                "operator-group Access policy prior-state credential was not resolved".to_owned(),
            )
        })?;
        Some(
            read_live_same_path_prior_state(
                store,
                catalog,
                &capability,
                &input,
                account_id,
                credential,
            )
            .await?,
        )
    } else if is_access_application_owned_whole_host_mutation(&capability) {
        let credential = credential.as_ref().ok_or_else(|| {
            CliError::Input(
                "owned whole-host Access application state precondition credential was not resolved"
                    .to_owned(),
            )
        })?;
        Some(
            read_live_same_path_prior_state(
                store,
                catalog,
                &capability,
                &input,
                account_id,
                credential,
            )
            .await?,
        )
    } else if is_access_application_login_methods_mutation(&capability) {
        let credential = credential.as_ref().ok_or_else(|| {
            CliError::Input(
                "Access application state precondition credential was not resolved".to_owned(),
            )
        })?;
        prepare_access_application_login_methods_plan_input(
            store,
            catalog,
            &mut capability,
            &mut input,
            account_id,
            credential,
        )
        .await?
    } else if is_access_human_policy_mutation(&capability) {
        let credential = credential.as_ref().ok_or_else(|| {
            CliError::Input(
                "human Access policy state precondition credential was not resolved".to_owned(),
            )
        })?;
        prepare_access_human_policy_plan_input(
            store,
            catalog,
            &capability,
            &mut input,
            account_id,
            credential,
        )
        .await?
    } else {
        None
    };
    let access_operator_group_policy_ownership =
        if is_access_operator_group_policy_create(&capability)
            || is_access_operator_group_policy_update(&capability)
        {
            let credential = credential.as_ref().ok_or_else(|| {
                CliError::Input(
                    "operator-group Access policy ownership credential was not resolved".to_owned(),
                )
            })?;
            Some(
                read_live_access_operator_group_policy_ownership(
                    store,
                    catalog,
                    &capability,
                    &input,
                    account_id,
                    credential,
                )
                .await?,
            )
        } else {
            None
        };
    let r2_parent_token_precondition = if should_bind_r2_parent_token(&capability) {
        if profile.kind != ProfileKind::ApiToken {
            return Err(CliError::Input(
                "R2 temporary credentials require an active scoped API-token profile; OAuth and emergency global-key profiles cannot serve as the parent access key"
                    .to_owned(),
            ));
        }
        let credential = credential.as_ref().ok_or_else(|| {
            CliError::Input("R2 parent-token precondition credential was not resolved".to_owned())
        })?;
        Some(
            read_live_r2_parent_token(
                store,
                catalog,
                &capability,
                &mut input,
                account_id,
                credential,
            )
            .await?,
        )
    } else {
        None
    };
    let entitlement_precondition = if resolve_entitlement_probe {
        let credential = credential.as_ref().ok_or_else(|| {
            CliError::Input("live entitlement-probe credential was not resolved".to_owned())
        })?;
        Some(
            read_live_entitlement_probe(store, catalog, &mut capability, &input, credential)
                .await?,
        )
    } else if resolve_entitlement {
        let credential = credential.as_ref().ok_or_else(|| {
            CliError::Input("live zone precondition credential was not resolved".to_owned())
        })?;
        Some(read_live_zone_entitlement(store, catalog, &mut capability, &input, credential).await?)
    } else {
        None
    };
    if capability.entitlement.available == Some(false) {
        return Err(CliError::Input(
            capability.entitlement.blocker.clone().unwrap_or_else(|| {
                "the selected zone subscription does not permit this capability".to_owned()
            }),
        ));
    }
    let zone_account_precondition = if should_bind_zone_account(&capability) {
        let credential = credential.as_ref().ok_or_else(|| {
            CliError::Input("live zone precondition credential was not resolved".to_owned())
        })?;
        Some(
            read_live_zone_account(store, catalog, &capability, &input, account_id, credential)
                .await?,
        )
    } else {
        None
    };
    let mut live_preconditions = prepare_live_plan_preconditions(
        store,
        catalog,
        &capability,
        &input,
        &adapter_targets,
        account_id,
        credential.as_ref(),
    )
    .await?;
    live_preconditions.entitlement = entitlement_precondition;
    live_preconditions.zone_account = zone_account_precondition;
    live_preconditions.r2_parent_token = r2_parent_token_precondition;
    live_preconditions.same_path_prior_state =
        access_state_precondition.or(live_preconditions.same_path_prior_state);
    live_preconditions.access_operator_group_policy_ownership =
        access_operator_group_policy_ownership;
    resolve_kv_empty_namespace_delete_cost(&mut capability, &live_preconditions);
    persist_prepared_plan(
        store,
        catalog,
        capability,
        input,
        PlanAuthority {
            profile,
            account_id,
        },
        adapter_targets,
        live_preconditions,
    )
}

pub(super) async fn prepare_pages_project_absence_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: Option<&AuthCredential>,
) -> Result<Option<(Value, EvidenceV1)>> {
    if !should_bind_pages_project_absence(capability) {
        return Ok(None);
    }
    let credential = credential.ok_or_else(|| {
        CliError::Input("Pages project absence precondition credential was not resolved".to_owned())
    })?;
    read_live_pages_project_absence(store, catalog, capability, input, account_id, credential)
        .await
        .map(Some)
}

#[expect(
    clippy::too_many_lines,
    reason = "Pages admission binds exact project mode and the complete pre-write deployment identity set in one live receipt"
)]
pub(super) async fn read_live_pages_deployment_project_state(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: &AuthCredential,
) -> Result<(Value, EvidenceV1)> {
    if !pages_deployment::binds_project_state(capability) {
        return Err(CliError::Input(
            "Pages deployment project-state read was requested for an unrelated capability"
                .to_owned(),
        ));
    }
    let project_name = pages_deployment::project_name(capability, input)?;
    let project_read = catalog
        .get(pages_deployment::PROJECT_READ_CAPABILITY_ID)
        .ok_or_else(|| capability_missing(pages_deployment::PROJECT_READ_CAPABILITY_ID))?;
    if project_read.method != "GET"
        || project_read.path != pages_deployment::PROJECT_DETAIL_PATH
        || project_read.mutating
        || !matches!(
            project_read.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
    {
        return Err(CliError::Input(
            "Pages deployment project-state source drifted from the exact project read".to_owned(),
        ));
    }
    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let project = executor
        .execute_read(
            project_read,
            &CallInput {
                selectors: json!({
                    "account_id": account_id,
                    "project_name": project_name,
                }),
                query: json!({}),
                body: None,
                ..CallInput::default()
            },
            credential,
        )
        .await?;
    let expected_branch = pages_deployment::binds_artifact(capability)
        .then(|| input.query.get("branch").and_then(Value::as_str))
        .flatten();
    let mut receipt = pages_deployment::apply_project_response(
        capability,
        account_id,
        project_name,
        expected_branch,
        &project,
    )?;
    if pages_deployment::binds_artifact(capability) {
        let list = catalog
            .get(pages_deployment::DEPLOYMENT_LIST_CAPABILITY_ID)
            .ok_or_else(|| capability_missing(pages_deployment::DEPLOYMENT_LIST_CAPABILITY_ID))?;
        if list.method != "GET"
            || list.path != pages_deployment::DEPLOYMENT_LIST_PATH
            || list.mutating
            || !matches!(
                list.adapter_status,
                AdapterStatus::Native | AdapterStatus::DynamicApi
            )
        {
            return Err(CliError::Input(
                "Pages deployment list source drifted from the exact project collection read"
                    .to_owned(),
            ));
        }
        let deployments = executor
            .execute_read(
                list,
                &CallInput {
                    selectors: json!({
                        "account_id": account_id,
                        "project_name": project_name,
                    }),
                    query: json!({}),
                    body: None,
                    ..CallInput::default()
                },
                credential,
            )
            .await?;
        if !deployments.success || deployments.status != 200 {
            return Err(CliError::Input(format!(
                "Pages deployment identity admission read returned HTTP {}; the deployment boundary was not crossed",
                deployments.status
            )));
        }
        let branch = expected_branch.ok_or_else(|| {
            CliError::Input("Pages direct-upload plan omitted its branch identity".to_owned())
        })?;
        let commit_hash = input
            .query
            .get("commit_hash")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CliError::Input("Pages direct-upload plan omitted its commit identity".to_owned())
            })?;
        let prior_ids = pages_deployment::deployment_ids(&deployments.result);
        let prior_matches = pages_deployment::matching_deployment_ids(
            &deployments.result,
            &BTreeSet::new(),
            project_name,
            branch,
            commit_hash,
        );
        if !prior_matches.is_empty() {
            return Err(CliError::Input(
                "Pages already contains a deployment with the reviewed project, branch, and commit identity; replay is blocked before planning"
                    .to_owned(),
            ));
        }
        receipt["prior_deployment_ids"] = serde_json::to_value(prior_ids)?;
        receipt["prior_exact_identity_count"] = json!(0);
        receipt["deployment_list_source_capability_id"] =
            json!(pages_deployment::DEPLOYMENT_LIST_CAPABILITY_ID);
    }
    let evidence = store.write_evidence(EvidenceClass::LiveRead, &receipt)?;
    Ok((receipt, evidence))
}

pub(super) async fn prepare_pages_deployment_project_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: Option<&AuthCredential>,
) -> Result<Option<(Value, EvidenceV1)>> {
    if !pages_deployment::binds_project_state(capability) {
        return Ok(None);
    }
    let credential = credential.ok_or_else(|| {
        CliError::Input("Pages deployment project-state credential was not resolved".to_owned())
    })?;
    read_live_pages_deployment_project_state(
        store, catalog, capability, input, account_id, credential,
    )
    .await
    .map(Some)
}

pub(super) async fn prepare_global_warp_override_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: Option<&AuthCredential>,
) -> Result<Option<(Value, EvidenceV1)>> {
    if !should_bind_global_warp_override_state(capability) {
        return Ok(None);
    }
    let credential = credential.ok_or_else(|| {
        CliError::Input(
            "Global WARP override state precondition credential was not resolved".to_owned(),
        )
    })?;
    read_live_global_warp_override_state(store, catalog, capability, input, account_id, credential)
        .await
        .map(Some)
}

pub(super) async fn prepare_d1_read_replication_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: Option<&AuthCredential>,
) -> Result<Option<(Value, EvidenceV1)>> {
    if !should_bind_d1_read_replication_state(capability) {
        return Ok(None);
    }
    let credential = credential.ok_or_else(|| {
        CliError::Input(
            "D1 read-replication state precondition credential was not resolved".to_owned(),
        )
    })?;
    read_live_d1_read_replication_state(store, catalog, capability, input, account_id, credential)
        .await
        .map(Some)
}

/// The KV namespace delete, identified permissively of adapter status: unlike
/// every other delete, it starts `Blocked` (cost unknown for a populated
/// namespace), and the emptiness precondition is what resolves that block. So
/// identity is by id/method/path/product, not by an already-unblocked status.
pub(super) fn is_kv_namespace_delete(capability: &CapabilityV1) -> bool {
    capability.id == KV_NAMESPACE_DELETE_CAPABILITY_ID
        && capability.method == "DELETE"
        && capability.path == "/accounts/{account_id}/storage/kv/namespaces/{namespace_id}"
        && capability.product == "Workers KV Namespace"
        && capability.account_scope == "account"
        && capability.mutating
        && capability.request_schema.is_none()
}

/// Bind the empty-namespace precondition only when the delete is a compensation
/// for a cfctl-created namespace, carrying a source receipt hash. This is the
/// safety floor: the four production namespaces were not created by cfctl, so
/// they can never enter this path, and arbitrary KV namespace deletion stays
/// blocked.
pub(super) fn should_bind_kv_empty_namespace_state(
    capability: &CapabilityV1,
    adapter_targets: &Value,
) -> bool {
    is_kv_namespace_delete(capability)
        && adapter_targets
            .get("compensates_capability_id")
            .and_then(Value::as_str)
            == Some(KV_NAMESPACE_CREATE_CAPABILITY_ID)
        && adapter_targets
            .get("compensation_strategy")
            .and_then(Value::as_str)
            == Some(KV_EMPTY_NAMESPACE_COMPENSATION_STRATEGY)
        && adapter_targets
            .get("compensates_operation_id")
            .and_then(Value::as_str)
            .is_some_and(|operation_id| !operation_id.is_empty())
        && adapter_targets
            .get("source_receipt_hash")
            .and_then(Value::as_str)
            .is_some_and(|hash| hash.starts_with("sha256:"))
}

/// Prove the namespace is empty from the paginated key-list read: the `result`
/// array must be empty, `result_info.count` must be 0, and the list must be
/// complete (no continuation cursor). Any populated or truncated result fails
/// closed — cfctl will not derive a delete whose cost it cannot bound to zero.
pub(super) fn apply_kv_empty_namespace_state_response(
    account_id: &str,
    namespace_id: &str,
    response: &CloudflareResponseV1,
) -> Result<Value> {
    if !response.success || !(200..300).contains(&response.status) {
        return Err(CliError::Input(format!(
            "Cloudflare rejected the KV empty-namespace read with HTTP {}; the compensation plan was not created",
            response.status
        )));
    }
    let keys = response.result.as_array().ok_or_else(|| {
        CliError::Input(
            "KV empty-namespace read did not return a key-list array; the compensation plan was not created"
                .to_owned(),
        )
    })?;
    if !keys.is_empty() {
        return Err(CliError::Input(format!(
            "KV namespace `{namespace_id}` still contains keys; cfctl will not derive a destructive compensation plan whose per-key deletion cost is unbounded"
        )));
    }
    let count = response
        .result_info
        .as_ref()
        .and_then(|info| info.get("count"))
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            CliError::Input(
                "KV empty-namespace read omitted an integer result_info.count; the compensation plan was not created"
                    .to_owned(),
            )
        })?;
    if count != 0 {
        return Err(CliError::Input(format!(
            "KV namespace `{namespace_id}` reports {count} key(s); cfctl will not derive a destructive compensation plan"
        )));
    }
    // A non-empty cursor means the listing is truncated: emptiness is not
    // proven. Cloudflare omits the cursor or returns an empty string when the
    // list is complete.
    let cursor_complete = response
        .result_info
        .as_ref()
        .and_then(|info| info.get("cursor"))
        .is_none_or(|cursor| cursor.as_str().is_some_and(str::is_empty));
    if !cursor_complete {
        return Err(CliError::Input(format!(
            "KV empty-namespace read for `{namespace_id}` was truncated (a continuation cursor remains); emptiness is not proven"
        )));
    }
    Ok(json!({
        "account_id": account_id,
        "namespace_id": namespace_id,
        "key_count": count,
        "list_complete": true,
    }))
}

pub(super) async fn read_live_kv_empty_namespace_state(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    adapter_targets: &Value,
    account_id: &str,
    credential: &AuthCredential,
) -> Result<(Value, EvidenceV1)> {
    if !should_bind_kv_empty_namespace_state(capability, adapter_targets) {
        return Err(CliError::Input(
            "KV compensation drifted from its governed empty-namespace contract".to_owned(),
        ));
    }
    let selected_account = input
        .selectors
        .get("account_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "KV empty-namespace precondition requires string selector `account_id`".to_owned(),
            )
        })?;
    if selected_account != account_id {
        return Err(CliError::Input(format!(
            "KV compensation account `{selected_account}` differs from selected account `{account_id}`; the compensation plan was not created"
        )));
    }
    let namespace_id = input
        .selectors
        .get("namespace_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "KV empty-namespace precondition requires string selector `namespace_id`"
                    .to_owned(),
            )
        })?;
    let source_capability = catalog
        .get(KV_NAMESPACE_KEYS_READ_CAPABILITY_ID)
        .ok_or_else(|| capability_missing(KV_NAMESPACE_KEYS_READ_CAPABILITY_ID))?;
    if source_capability.method != "GET"
        || source_capability.path
            != "/accounts/{account_id}/storage/kv/namespaces/{namespace_id}/keys"
    {
        return Err(CliError::Input(
            "KV empty-namespace source capability drifted from the governed key-list read"
                .to_owned(),
        ));
    }
    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let response = executor
        .execute_read(
            source_capability,
            &CallInput {
                selectors: json!({"account_id": account_id, "namespace_id": namespace_id}),
                query: json!({"limit": 1}),
                body: None,
                ..CallInput::default()
            },
            credential,
        )
        .await?;
    let receipt = apply_kv_empty_namespace_state_response(account_id, namespace_id, &response)?;
    let evidence = store.write_evidence(EvidenceClass::LiveRead, &receipt)?;
    Ok((receipt, evidence))
}

pub(super) async fn prepare_kv_empty_namespace_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    adapter_targets: &Value,
    account_id: &str,
    credential: Option<&AuthCredential>,
) -> Result<Option<(Value, EvidenceV1)>> {
    if !should_bind_kv_empty_namespace_state(capability, adapter_targets) {
        return Ok(None);
    }
    let credential = credential.ok_or_else(|| {
        CliError::Input("KV empty-namespace precondition credential was not resolved".to_owned())
    })?;
    read_live_kv_empty_namespace_state(
        store,
        catalog,
        capability,
        input,
        adapter_targets,
        account_id,
        credential,
    )
    .await
    .map(Some)
}

pub(super) fn required_kv_empty_namespace_state_precondition(
    plan: &PlanV1,
) -> Result<Option<&str>> {
    let adapter_targets = plan.targets.get("adapter").unwrap_or(&Value::Null);
    if !is_kv_namespace_delete(&plan.capability)
        || adapter_targets
            .get("compensates_capability_id")
            .and_then(Value::as_str)
            != Some(KV_NAMESPACE_CREATE_CAPABILITY_ID)
    {
        return Ok(None);
    }
    if !should_bind_kv_empty_namespace_state(&plan.capability, adapter_targets) {
        return Err(CliError::Input(
            "KV compensation plan is inconsistent with its hash-bound empty-namespace contract; create a new plan"
                .to_owned(),
        ));
    }
    let expected_hash = plan
        .precondition_hashes
        .get(KV_EMPTY_NAMESPACE_PRECONDITION)
        .map(String::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "KV compensation plan predates the live empty-namespace contract; create a new plan"
                    .to_owned(),
            )
        })?;
    let receipt = plan
        .targets
        .pointer("/live_preconditions/kv_empty_namespace_state")
        .ok_or_else(|| {
            CliError::Input(
                "KV compensation plan omitted its hash-bound empty-namespace receipt; create a new plan"
                    .to_owned(),
            )
        })?;
    if receipt.get("key_count").and_then(Value::as_u64) != Some(0)
        || receipt.get("list_complete").and_then(Value::as_bool) != Some(true)
    {
        return Err(CliError::Input(
            "KV compensation plan empty-namespace receipt does not prove an empty, fully-listed namespace; create a new plan"
                .to_owned(),
        ));
    }
    if hash_value(receipt)? != expected_hash {
        return Err(CliError::Input(
            "plan KV empty-namespace receipt does not match its precondition hash; create a new plan"
                .to_owned(),
        ));
    }
    Ok(Some(expected_hash))
}

pub(super) async fn validate_live_kv_empty_namespace_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    plan: &PlanV1,
    input: &CallInput,
    credential: &AuthCredential,
) -> Result<Option<EvidenceV1>> {
    let Some(expected_hash) = required_kv_empty_namespace_state_precondition(plan)? else {
        return Ok(None);
    };
    let adapter_targets = plan.targets.get("adapter").unwrap_or(&Value::Null);
    let (receipt, evidence) = read_live_kv_empty_namespace_state(
        store,
        catalog,
        &plan.capability,
        input,
        adapter_targets,
        &plan.account_id,
        credential,
    )
    .await?;
    if hash_value(&receipt)? != expected_hash {
        return Err(CliError::Input(
            "live KV empty-namespace state drifted after planning; the delete boundary was not crossed and a new compensation review is required"
                .to_owned(),
        ));
    }
    Ok(Some(evidence))
}

/// The cost-block resolution. A KV namespace delete is blocked because a
/// populated namespace's per-key deletion billing is undocumented. When the
/// governed empty-namespace precondition is bound — proving zero keys — the
/// cost is provably zero, so this resolves the plan capability's cost and,
/// only if that was the sole remaining gap, un-blocks it for this exact
/// compensation plan. It fires nowhere else: the precondition binds only for a
/// compensation of a cfctl-created namespace, and the plan re-reads emptiness
/// live before the boundary is crossed.
pub(super) fn resolve_kv_empty_namespace_delete_cost(
    capability: &mut CapabilityV1,
    live_preconditions: &LivePlanPreconditions,
) {
    if live_preconditions.kv_empty_namespace_state.is_none() || !is_kv_namespace_delete(capability)
    {
        return;
    }
    capability.cost.known = true;
    capability.cost.incremental = false;
    capability.cost.maximum = Some(0.0);
    capability.cost.currency = None;
    capability.cost.basis = Some(
        "the namespace was proven empty by a hash-bound live key-list read re-checked before the boundary, so there are no keys to bill for deletion; the cost is zero for this compensation only"
            .to_owned(),
    );
    if capability.mutation_contract_gaps().is_empty() {
        capability.adapter_status = AdapterStatus::DynamicApi;
        capability.blocked_reason = None;
    }
}

pub(super) async fn prepare_d1_empty_database_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    adapter_targets: &Value,
    account_id: &str,
    credential: Option<&AuthCredential>,
) -> Result<Option<(Value, EvidenceV1)>> {
    if !should_bind_d1_empty_database_state(capability, adapter_targets) {
        return Ok(None);
    }
    let credential = credential.ok_or_else(|| {
        CliError::Input("D1 empty-state precondition credential was not resolved".to_owned())
    })?;
    read_live_d1_empty_database_state(
        store,
        catalog,
        capability,
        input,
        adapter_targets,
        account_id,
        credential,
    )
    .await
    .map(Some)
}

pub(super) async fn prepare_cloudflare_tunnel_configuration_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: Option<&AuthCredential>,
) -> Result<Option<(Value, EvidenceV1)>> {
    if !should_bind_cloudflare_tunnel_configuration_state(capability) {
        return Ok(None);
    }
    let credential = credential.ok_or_else(|| {
        CliError::Input(
            "Tunnel configuration state precondition credential was not resolved".to_owned(),
        )
    })?;
    read_live_cloudflare_tunnel_configuration_state(
        store, catalog, capability, input, account_id, credential,
    )
    .await
    .map(Some)
}

pub(super) async fn prepare_warp_connector_configuration_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: Option<&AuthCredential>,
) -> Result<Option<(Value, EvidenceV1)>> {
    if !should_bind_warp_connector_configuration_state(capability) {
        return Ok(None);
    }
    let credential = credential.ok_or_else(|| {
        CliError::Input(
            "WARP Connector configuration state precondition credential was not resolved"
                .to_owned(),
        )
    })?;
    read_live_warp_connector_configuration_state(
        store, catalog, capability, input, account_id, credential,
    )
    .await
    .map(Some)
}

pub(super) async fn prepare_web_analytics_rum_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: Option<&AuthCredential>,
) -> Result<Option<(Value, EvidenceV1)>> {
    if !should_bind_web_analytics_rum_state(capability) {
        return Ok(None);
    }
    let credential = credential.ok_or_else(|| {
        CliError::Input(
            "Web Analytics RUM state precondition credential was not resolved".to_owned(),
        )
    })?;
    read_live_web_analytics_rum_state(store, catalog, capability, input, account_id, credential)
        .await
        .map(Some)
}

pub(super) async fn prepare_dns_record_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: Option<&AuthCredential>,
) -> Result<Option<(Value, EvidenceV1)>> {
    if !should_bind_dns_record_state(capability) {
        return Ok(None);
    }
    let credential = credential.ok_or_else(|| {
        CliError::Input("DNS record state precondition credential was not resolved".to_owned())
    })?;
    read_live_dns_record_state(store, catalog, capability, input, account_id, credential)
        .await
        .map(Some)
}

pub(super) async fn prepare_oauth_client_secret_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: Option<&AuthCredential>,
) -> Result<Option<(Value, EvidenceV1)>> {
    if !should_bind_oauth_client_secret_state(capability) {
        return Ok(None);
    }
    let credential = credential.ok_or_else(|| {
        CliError::Input("OAuth client state precondition credential was not resolved".to_owned())
    })?;
    read_live_oauth_client_secret_state(store, catalog, capability, input, account_id, credential)
        .await
        .map(Some)
}

pub(super) async fn prepare_oauth_client_update_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: Option<&AuthCredential>,
) -> Result<Option<(Value, EvidenceV1)>> {
    if !should_bind_oauth_client_update_state(capability) {
        return Ok(None);
    }
    let credential = credential.ok_or_else(|| {
        CliError::Input("OAuth client snapshot credential was not resolved".to_owned())
    })?;
    read_live_oauth_client_update_state(store, catalog, capability, input, account_id, credential)
        .await
        .map(Some)
}

pub(super) async fn read_live_worker_deployment_state(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    adapter_targets: &Value,
    account_id: &str,
    credential: &AuthCredential,
) -> Result<(Value, EvidenceV1)> {
    if !worker_deployment::binds_live_state(capability) {
        return Err(CliError::Input(
            "Worker deployment state read was requested for another capability".to_owned(),
        ));
    }
    let service_name = worker_deployment::service_name(adapter_targets)?;
    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let settings_source = exact_worker_deployment_read_capability(
        catalog,
        worker_deployment::SETTINGS_CAPABILITY_ID,
        worker_deployment::SETTINGS_PATH,
    )?;
    let input = CallInput {
        selectors: json!({
            "account_id": account_id,
            "script_name": service_name,
        }),
        query: json!({}),
        body: None,
        ..CallInput::default()
    };
    let settings = executor
        .execute_read(settings_source, &input, credential)
        .await?;
    let deployments = if settings.success && (200..300).contains(&settings.status) {
        let source = exact_worker_deployment_read_capability(
            catalog,
            worker_deployment::DEPLOYMENTS_CAPABILITY_ID,
            worker_deployment::DEPLOYMENTS_PATH,
        )?;
        Some(executor.execute_read(source, &input, credential).await?)
    } else {
        None
    };
    let receipt = if capability.id == worker_deployment::ROLLBACK_CAPABILITY_ID {
        let target = worker_deployment::target(adapter_targets)
            .ok_or_else(|| CliError::Input("Worker rollback target is missing".to_owned()))?;
        let target_version_id = target
            .pointer("/rollback/target_version_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CliError::Input("Worker rollback target version is missing".to_owned())
            })?;
        let version_source = exact_worker_deployment_read_capability(
            catalog,
            worker_deployment::VERSION_CAPABILITY_ID,
            worker_deployment::VERSION_PATH,
        )?;
        let version_input = CallInput {
            selectors: json!({
                "account_id": account_id,
                "script_name": service_name,
                "version_id": target_version_id,
            }),
            query: json!({}),
            body: None,
            ..CallInput::default()
        };
        let version = executor
            .execute_read(version_source, &version_input, credential)
            .await?;
        worker_deployment::apply_rollback_state_responses(
            account_id,
            service_name,
            target,
            &settings,
            deployments.as_ref().ok_or_else(|| {
                CliError::Input("Worker rollback deployments read is missing".to_owned())
            })?,
            &version,
        )?
    } else {
        worker_deployment::apply_state_responses(
            account_id,
            service_name,
            &settings,
            deployments.as_ref(),
        )?
    };
    let evidence = store.write_evidence(EvidenceClass::LiveRead, &receipt)?;
    Ok((receipt, evidence))
}

pub(super) fn exact_worker_deployment_read_capability<'a>(
    catalog: &'a CatalogSnapshot,
    id: &str,
    path: &str,
) -> Result<&'a CapabilityV1> {
    let source = catalog.get(id).ok_or_else(|| capability_missing(id))?;
    if source.method != "GET"
        || source.path != path
        || source.mutating
        || !matches!(
            source.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
    {
        return Err(CliError::Input(format!(
            "Worker deployment state source `{id}` drifted from its governed exact read"
        )));
    }
    Ok(source)
}

pub(super) async fn prepare_worker_deployment_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    adapter_targets: &Value,
    account_id: &str,
    credential: Option<&AuthCredential>,
) -> Result<Option<(Value, EvidenceV1)>> {
    if worker_deployment::target(adapter_targets).is_none() {
        return Ok(None);
    }
    let credential = credential.ok_or_else(|| {
        CliError::Input("Worker deployment state credential was not resolved".to_owned())
    })?;
    read_live_worker_deployment_state(
        store,
        catalog,
        capability,
        adapter_targets,
        account_id,
        credential,
    )
    .await
    .map(Some)
}

pub(super) async fn prepare_same_path_prior_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: Option<&AuthCredential>,
) -> Result<Option<(Value, EvidenceV1)>> {
    if !should_bind_same_path_prior_state(capability)
        || is_access_application_login_methods_mutation(capability)
        || is_access_human_policy_mutation(capability)
    {
        return Ok(None);
    }
    let credential = credential.ok_or_else(|| {
        CliError::Input("same-path prior-state precondition credential was not resolved".to_owned())
    })?;
    read_live_same_path_prior_state(store, catalog, capability, input, account_id, credential)
        .await
        .map(Some)
}

pub(super) async fn prepare_security_action_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    adapter_targets: &Value,
    account_id: &str,
    credential: Option<&AuthCredential>,
) -> Result<Option<(Value, EvidenceV1)>> {
    if !should_bind_security_action_state(capability, adapter_targets) {
        return Ok(None);
    }
    let credential = credential.ok_or_else(|| {
        CliError::Input(
            "security-action current-state precondition credential was not resolved".to_owned(),
        )
    })?;
    read_live_security_action_state(
        store,
        catalog,
        capability,
        input,
        adapter_targets,
        account_id,
        credential,
    )
    .await
    .map(Some)
}
