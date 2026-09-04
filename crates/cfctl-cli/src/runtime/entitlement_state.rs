use super::access_application::is_access_application_login_methods_mutation;
use super::access_policy::is_access_human_policy_mutation;
use super::access_policy::is_access_operator_group_policy_create;
use super::access_policy::is_access_operator_group_policy_update;
use super::cloudflare_api::BASE_URL as API_BASE_URL;
use super::live_state_contracts::should_bind_cloudflare_tunnel_configuration_state;
use super::live_state_contracts::should_bind_d1_empty_database_state;
use super::live_state_contracts::should_bind_d1_read_replication_state;
use super::live_state_contracts::should_bind_dns_record_state;
use super::live_state_contracts::should_bind_global_warp_override_state;
use super::live_state_contracts::should_bind_same_path_prior_state;
use super::live_state_contracts::should_bind_warp_connector_configuration_state;
use super::live_state_contracts::should_bind_web_analytics_rum_state;
use super::oauth_state::should_bind_oauth_client_secret_state;
use super::oauth_state::should_bind_oauth_client_update_state;
use super::pages_deployment::{
    PROJECT_CREATE_CAPABILITY_ID, PROJECT_DETAIL_PATH, PROJECT_NOT_FOUND_ERROR_CODE,
    PROJECT_READ_CAPABILITY_ID,
};
use super::plan_create::should_bind_kv_empty_namespace_state;
use super::plan_secret::ENTITLEMENT_UNRESOLVED_GAP;
use super::plan_secret::ZONE_DETAILS_CAPABILITY_ID;
use super::plan_secret::ZONE_SUBSCRIPTION_CAPABILITY_ID;
use super::prelude::{
    AdapterStatus, AuthCredential, CallInput, CapabilityV1, CatalogSnapshot, CliError,
    CloudflareResponseV1, EvidenceClass, EvidenceV1, Executor, Map, Result, StateStore, Value,
    json,
};
use super::r2_credentials::should_bind_r2_parent_token;
use super::security_action_state::should_bind_security_action_state;
use super::support::capability_missing;
use super::support::http_client;
use super::{pages_deployment, worker_custom_domain, worker_deployment};
use cfctl_catalog::refresh_dynamic_mutation_contract;
use cfctl_core::hash_value;

pub(super) fn should_resolve_zone_entitlement(capability: &CapabilityV1) -> bool {
    let dynamic_contract = capability.adapter_status == AdapterStatus::DynamicApi
        || (capability.adapter_status == AdapterStatus::Blocked
            && capability
                .blocked_reason
                .as_deref()
                .is_some_and(|reason| reason.starts_with("operation contract incomplete:")));
    dynamic_contract
        && capability.account_scope == "zone"
        && capability.entitlement.requires_live_resolution
        && capability.mutation_contract_gaps() == [ENTITLEMENT_UNRESOLVED_GAP]
}

pub(super) fn should_resolve_entitlement_probe(capability: &CapabilityV1) -> bool {
    let dynamic_contract = capability.adapter_status == AdapterStatus::DynamicApi
        || (capability.adapter_status == AdapterStatus::Blocked
            && capability
                .blocked_reason
                .as_deref()
                .is_some_and(|reason| reason.starts_with("operation contract incomplete:")));
    dynamic_contract
        && capability.entitlement.requires_live_resolution
        && capability.entitlement.probe.is_some()
        && capability.entitlement.available != Some(true)
        && capability.mutation_contract_gaps().is_empty()
}

pub(super) fn should_bind_zone_account(capability: &CapabilityV1) -> bool {
    capability.mutating
        && capability.account_scope == "zone"
        && (matches!(
            capability.adapter_status,
            AdapterStatus::Native
                | AdapterStatus::DynamicApi
                | AdapterStatus::DelegatedCli
                | AdapterStatus::GovernedUi
        ) || should_resolve_zone_entitlement(capability)
            || should_resolve_entitlement_probe(capability))
}

pub(super) fn zone_target(capability: &CapabilityV1, input: &CallInput) -> Result<String> {
    let zone_selectors = capability
        .path
        .split('/')
        .filter_map(|segment| {
            segment
                .strip_prefix('{')
                .and_then(|value| value.strip_suffix('}'))
        })
        .filter(|selector| selector.to_ascii_lowercase().contains("zone"))
        .collect::<Vec<_>>();
    let [selector] = zone_selectors.as_slice() else {
        return Err(CliError::Input(format!(
            "live zone preconditions require exactly one zone selector in capability `{}`",
            capability.id
        )));
    };
    input
        .selectors
        .get(*selector)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            CliError::Input(format!(
                "live zone preconditions require string selector `{selector}`"
            ))
        })
}

pub(super) fn canonical_zone_plan(plan: &str) -> Option<&'static str> {
    match plan {
        "free" | "partners_free" => Some("free"),
        "pro" | "partners_pro" => Some("pro"),
        "business" | "partners_business" => Some("business"),
        "enterprise" | "partners_enterprise" => Some("enterprise"),
        _ => None,
    }
}

pub(super) fn apply_zone_entitlement_response(
    capability: &mut CapabilityV1,
    zone_id: &str,
    response: &CloudflareResponseV1,
) -> Result<Value> {
    if !response.success || !(200..300).contains(&response.status) {
        return Err(CliError::Input(format!(
            "Cloudflare rejected the zone subscription entitlement read with HTTP {}; the mutation boundary was not crossed",
            response.status
        )));
    }
    let state = response
        .result
        .get("state")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "zone subscription entitlement read omitted the subscription state".to_owned(),
            )
        })?;
    if !matches!(state, "Trial" | "Provisioned" | "Paid") {
        return Err(CliError::Input(format!(
            "zone subscription state `{state}` is not active; the mutation boundary was not crossed"
        )));
    }
    let observed_plan = response
        .result
        .pointer("/rate_plan/id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "zone subscription entitlement read omitted the rate-plan ID".to_owned(),
            )
        })?;
    let canonical_plan = canonical_zone_plan(observed_plan).ok_or_else(|| {
        CliError::Input(format!(
            "zone rate plan `{observed_plan}` cannot be mapped to the official free/pro/business/enterprise availability matrix"
        ))
    })?;
    let available = capability
        .entitlement
        .plans
        .get(canonical_plan)
        .copied()
        .ok_or_else(|| {
            CliError::Input(format!(
                "capability `{}` has no `{canonical_plan}` entry in its official plan-availability matrix",
                capability.id
            ))
        })?;
    let plan_matrix_hash = hash_value(&serde_json::to_value(&capability.entitlement.plans)?)?;
    capability.entitlement.available = Some(available);
    capability.entitlement.observed_plan = Some(observed_plan.to_owned());
    capability.entitlement.source = Some(
        "live Cloudflare GET /zones/{zone_id}/subscription evaluated against official OpenAPI x-cfPlanAvailability"
            .to_owned(),
    );
    capability.entitlement.blocker = (!available).then(|| {
        format!(
            "live zone plan `{observed_plan}` does not permit capability `{}`",
            capability.id
        )
    });
    refresh_dynamic_mutation_contract(capability);
    Ok(json!({
        "schema_version": 1,
        "source_capability_id": ZONE_SUBSCRIPTION_CAPABILITY_ID,
        "source_path": "/zones/{zone_id}/subscription",
        "target_scope": "zone",
        "target_id": zone_id,
        "observed_plan": observed_plan,
        "canonical_plan": canonical_plan,
        "subscription_state": state,
        "available": available,
        "plan_matrix_hash": plan_matrix_hash,
    }))
}

pub(super) async fn read_live_zone_entitlement(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &mut CapabilityV1,
    input: &CallInput,
    credential: &AuthCredential,
) -> Result<(Value, EvidenceV1)> {
    let source_capability = catalog
        .get(ZONE_SUBSCRIPTION_CAPABILITY_ID)
        .ok_or_else(|| capability_missing(ZONE_SUBSCRIPTION_CAPABILITY_ID))?;
    if source_capability.method != "GET"
        || source_capability.path != "/zones/{zone_id}/subscription"
        || source_capability.mutating
        || !matches!(
            source_capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
    {
        return Err(CliError::Input(
            "zone entitlement source capability drifted from the governed subscription read"
                .to_owned(),
        ));
    }
    let zone_id = zone_target(capability, input)?;
    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let response = executor
        .execute_read(
            source_capability,
            &CallInput {
                selectors: json!({"zone_id": zone_id}),
                query: json!({}),
                body: None,
                ..CallInput::default()
            },
            credential,
        )
        .await?;
    let receipt = apply_zone_entitlement_response(capability, &zone_id, &response)?;
    let evidence = store.write_observation_evidence(EvidenceClass::LiveRead, &receipt)?;
    Ok((receipt, evidence))
}

pub(super) fn entitlement_probe_selectors(
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<Value> {
    let probe =
        capability.entitlement.probe.as_ref().ok_or_else(|| {
            CliError::Input("live entitlement probe contract is absent".to_owned())
        })?;
    let input_selectors = input.selectors.as_object().ok_or_else(|| {
        CliError::Input("live entitlement probe selectors are not an object".to_owned())
    })?;
    let mut selectors = Map::new();
    for name in &probe.selector_names {
        let value = input_selectors
            .get(name)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                CliError::Input(format!(
                    "live entitlement probe requires string selector `{name}`"
                ))
            })?;
        selectors.insert(name.clone(), Value::String(value.to_owned()));
    }
    Ok(Value::Object(selectors))
}

pub(super) fn apply_entitlement_probe_response(
    capability: &mut CapabilityV1,
    selectors: &Value,
    response: &CloudflareResponseV1,
) -> Result<Value> {
    let probe =
        capability.entitlement.probe.as_ref().ok_or_else(|| {
            CliError::Input("live entitlement probe contract is absent".to_owned())
        })?;
    if !response.success || !(200..300).contains(&response.status) {
        return Err(CliError::Input(format!(
            "Cloudflare rejected the declared product entitlement probe with HTTP {}; token authorization, product entitlement, and account configuration remain unresolved, and the mutation boundary was not crossed",
            response.status
        )));
    }
    let probe_capability_id = probe.capability_id.clone();
    let probe_path = probe.path.clone();
    let selector_hash = hash_value(selectors)?;
    capability.entitlement.available = Some(true);
    capability.entitlement.blocker = None;
    capability.entitlement.observed_plan = None;
    capability.entitlement.source = Some(format!(
        "live Cloudflare read capability `{probe_capability_id}` returned a successful response"
    ));
    refresh_dynamic_mutation_contract(capability);
    Ok(json!({
        "schema_version":1,
        "source_capability_id":probe_capability_id,
        "source_path":probe_path,
        "target_scope":capability.account_scope,
        "target_selectors_hash":selector_hash,
        "http_status":response.status,
        "available":true,
        "negative_inference":false,
        "basis":"a successful read proves current API access; a rejected read would not distinguish authorization, entitlement, or product configuration"
    }))
}

pub(super) async fn read_live_entitlement_probe(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &mut CapabilityV1,
    input: &CallInput,
    credential: &AuthCredential,
) -> Result<(Value, EvidenceV1)> {
    let probe =
        capability.entitlement.probe.as_ref().ok_or_else(|| {
            CliError::Input("live entitlement probe contract is absent".to_owned())
        })?;
    let source_capability = catalog
        .get(&probe.capability_id)
        .ok_or_else(|| capability_missing(&probe.capability_id))?;
    if source_capability.method != "GET"
        || source_capability.path != probe.path
        || source_capability.mutating
        || !matches!(
            source_capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
    {
        return Err(CliError::Input(
            "declared product entitlement probe drifted from its governed read capability"
                .to_owned(),
        ));
    }
    let selectors = entitlement_probe_selectors(capability, input)?;
    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let response = executor
        .execute_read(
            source_capability,
            &CallInput {
                selectors: selectors.clone(),
                query: json!({}),
                body: None,
                ..CallInput::default()
            },
            credential,
        )
        .await?;
    let receipt = apply_entitlement_probe_response(capability, &selectors, &response)?;
    let evidence = store.write_observation_evidence(EvidenceClass::LiveRead, &receipt)?;
    Ok((receipt, evidence))
}

pub(super) fn apply_zone_account_response(
    zone_id: &str,
    expected_account_id: &str,
    response: &CloudflareResponseV1,
) -> Result<Value> {
    if !response.success || !(200..300).contains(&response.status) {
        return Err(CliError::Input(format!(
            "Cloudflare rejected the zone-account ownership read with HTTP {}; the mutation boundary was not crossed",
            response.status
        )));
    }
    let observed_zone_id = response
        .result
        .get("id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input("zone-account ownership read omitted the zone ID".to_owned())
        })?;
    if observed_zone_id != zone_id {
        return Err(CliError::Input(format!(
            "zone-account ownership read for `{zone_id}` returned zone `{observed_zone_id}`; the mutation boundary was not crossed"
        )));
    }
    let observed_account_id = response
        .result
        .pointer("/account/id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input("zone-account ownership read omitted the account ID".to_owned())
        })?;
    if observed_account_id != expected_account_id {
        return Err(CliError::Input(format!(
            "zone `{zone_id}` belongs to account `{observed_account_id}`, not selected account `{expected_account_id}`; the mutation boundary was not crossed"
        )));
    }
    Ok(json!({
        "schema_version": 1,
        "source_capability_id": ZONE_DETAILS_CAPABILITY_ID,
        "source_path": "/zones/{zone_id}",
        "target_scope": "zone",
        "target_id": zone_id,
        "expected_account_id": expected_account_id,
        "observed_account_id": observed_account_id,
        "account_matches": true,
    }))
}

pub(super) fn should_bind_pages_project_absence(capability: &CapabilityV1) -> bool {
    capability.id == PROJECT_CREATE_CAPABILITY_ID
        && capability.method == "POST"
        && capability.path == "/accounts/{account_id}/pages/projects"
}

pub(super) fn pages_project_name(input: &CallInput) -> Result<&str> {
    input
        .body
        .as_ref()
        .and_then(|body| body.get("name"))
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "Pages project creation requires a non-empty project `name` in the request body"
                    .to_owned(),
            )
        })
}

pub(super) fn apply_pages_project_absence_response(
    account_id: &str,
    project_name: &str,
    response: &CloudflareResponseV1,
) -> Result<Value> {
    let exact_not_found = response.status == 404
        && !response.success
        && response.result.is_null()
        && response.errors.len() == 1
        && response.errors[0].code == Some(PROJECT_NOT_FOUND_ERROR_CODE);
    if exact_not_found {
        return Ok(json!({
            "schema_version": 1,
            "source_capability_id": PROJECT_READ_CAPABILITY_ID,
            "source_path": PROJECT_DETAIL_PATH,
            "target_capability_id": PROJECT_CREATE_CAPABILITY_ID,
            "target_path": "/accounts/{account_id}/pages/projects",
            "target_scope": "account",
            "account_id": account_id,
            "project_name": project_name,
            "http_status": response.status,
            "absent": true,
        }));
    }
    if response.success && (200..300).contains(&response.status) {
        return Err(CliError::Input(format!(
            "Cloudflare Pages project `{project_name}` already exists in the selected account; the creation boundary was not crossed"
        )));
    }
    Err(CliError::Input(format!(
        "Cloudflare Pages project read returned HTTP {} and cannot prove exact target absence; the creation boundary was not crossed",
        response.status
    )))
}

pub(super) async fn read_live_pages_project_absence(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: &AuthCredential,
) -> Result<(Value, EvidenceV1)> {
    if !should_bind_pages_project_absence(capability) {
        return Err(CliError::Input(
            "Pages project absence read was requested for a different capability".to_owned(),
        ));
    }
    let source_capability = catalog
        .get(PROJECT_READ_CAPABILITY_ID)
        .ok_or_else(|| capability_missing(PROJECT_READ_CAPABILITY_ID))?;
    if source_capability.method != "GET"
        || source_capability.path != PROJECT_DETAIL_PATH
        || source_capability.mutating
        || !matches!(
            source_capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
    {
        return Err(CliError::Input(
            "Pages project absence source capability drifted from the governed exact-project read"
                .to_owned(),
        ));
    }
    let project_name = pages_project_name(input)?;
    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let response = executor
        .execute_read(
            source_capability,
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
    let receipt = apply_pages_project_absence_response(account_id, project_name, &response)?;
    let evidence = store.write_observation_evidence(EvidenceClass::LiveRead, &receipt)?;
    Ok((receipt, evidence))
}

pub(super) async fn read_live_zone_account(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: &AuthCredential,
) -> Result<(Value, EvidenceV1)> {
    let source_capability = catalog
        .get(ZONE_DETAILS_CAPABILITY_ID)
        .ok_or_else(|| capability_missing(ZONE_DETAILS_CAPABILITY_ID))?;
    if source_capability.method != "GET"
        || source_capability.path != "/zones/{zone_id}"
        || source_capability.mutating
        || !matches!(
            source_capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
    {
        return Err(CliError::Input(
            "zone-account source capability drifted from the governed zone-details read".to_owned(),
        ));
    }
    let zone_id = zone_target(capability, input)?;
    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let response = executor
        .execute_read(
            source_capability,
            &CallInput {
                selectors: json!({"zone_id": zone_id}),
                query: json!({}),
                body: None,
                ..CallInput::default()
            },
            credential,
        )
        .await?;
    let receipt = apply_zone_account_response(&zone_id, account_id, &response)?;
    let evidence = store.write_observation_evidence(EvidenceClass::LiveRead, &receipt)?;
    Ok((receipt, evidence))
}

pub(super) fn plan_requires_live_credential(
    capability: &CapabilityV1,
    adapter_targets: &Value,
) -> bool {
    should_bind_pages_project_absence(capability)
        || pages_deployment::binds_project_state(capability)
        || worker_deployment::target(adapter_targets).is_some()
        || should_resolve_entitlement_probe(capability)
        || should_resolve_zone_entitlement(capability)
        || should_bind_zone_account(capability)
        || should_bind_global_warp_override_state(capability)
        || should_bind_d1_read_replication_state(capability)
        || should_bind_d1_empty_database_state(capability, adapter_targets)
        || should_bind_kv_empty_namespace_state(capability, adapter_targets)
        || should_bind_cloudflare_tunnel_configuration_state(capability)
        || should_bind_warp_connector_configuration_state(capability)
        || should_bind_web_analytics_rum_state(capability)
        || should_bind_dns_record_state(capability)
        || should_bind_same_path_prior_state(capability)
        || should_bind_security_action_state(capability, adapter_targets)
        || should_bind_oauth_client_secret_state(capability)
        || should_bind_oauth_client_update_state(capability)
        || worker_custom_domain::should_bind_state(capability)
        || should_bind_r2_parent_token(capability)
        || is_access_application_login_methods_mutation(capability)
        || is_access_human_policy_mutation(capability)
        || is_access_operator_group_policy_update(capability)
        || is_access_operator_group_policy_create(capability)
        || is_access_operator_group_policy_update(capability)
}
