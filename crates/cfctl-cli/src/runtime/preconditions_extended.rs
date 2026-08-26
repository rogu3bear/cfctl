use super::access_application::access_application_login_methods_contract_supported;
use super::access_application::access_application_login_methods_variant;
use super::access_application::access_application_mutable_body;
use super::access_application::access_application_rollback_idps;
use super::access_application::is_access_application_implicit_open_concurrency_plan;
use super::access_application::normalized_access_application_idps;
use super::access_ownership::read_live_same_path_prior_state;
use super::access_policy::access_human_policy_restorable_body;
use super::access_policy::access_operator_group_policy_restorable_body;
use super::access_policy::is_access_application_owned_whole_host_mutation;
use super::access_policy::is_access_human_policy_mutation;
use super::access_policy::is_access_operator_group_policy_update;
use super::live_state_contracts::is_dns_record_update_mutation;
use super::live_state_contracts::is_warp_connector_configuration_mutation;
use super::live_state_contracts::is_web_analytics_rum_mutation;
use super::live_state_contracts::requires_same_path_state_precondition;
use super::live_state_contracts::same_path_prior_state_fields;
use super::live_state_contracts::should_bind_dns_record_state;
use super::live_state_contracts::should_bind_same_path_prior_state;
use super::live_state_contracts::should_bind_warp_connector_configuration_state;
use super::live_state_contracts::should_bind_web_analytics_rum_state;
use super::oauth_state::is_oauth_client_update_capability;
use super::oauth_state::oauth_client_secret_expected_prior_state;
use super::oauth_state::read_live_oauth_client_secret_state;
use super::oauth_state::read_live_oauth_client_update_state;
use super::oauth_state::should_bind_oauth_client_secret_state;
use super::oauth_state::should_bind_oauth_client_update_state;
use super::plan_secret::ACCESS_APP_COLLECTION_PATH;
use super::plan_secret::ACCESS_APP_LIST_CAPABILITY_ID;
use super::plan_secret::DNS_RECORD_DETAIL_PATH;
use super::plan_secret::DNS_RECORD_DETAIL_READ_CAPABILITY_ID;
use super::plan_secret::DNS_RECORD_STATE_PRECONDITION;
use super::plan_secret::OAUTH_CLIENT_DETAIL_PATH;
use super::plan_secret::OAUTH_CLIENT_DETAIL_READ_CAPABILITY_ID;
use super::plan_secret::OAUTH_CLIENT_KEY_OVERLAP_PRECONDITION;
use super::plan_secret::OAUTH_CLIENT_MUTABLE_FIELDS;
use super::plan_secret::OAUTH_CLIENT_UPDATE_STATE_PRECONDITION;
use super::plan_secret::SAME_PATH_PRIOR_STATE_PRECONDITION;
use super::plan_secret::SAME_PATH_PRIOR_STATE_ROLLBACK_STRATEGY;
use super::plan_secret::WARP_CONNECTOR_CONFIGURATION_PATH;
use super::plan_secret::WARP_CONNECTOR_CONFIGURATION_READ_CAPABILITY_ID;
use super::plan_secret::WARP_CONNECTOR_CONFIGURATION_STATE_PRECONDITION;
use super::plan_secret::WEB_ANALYTICS_RUM_PATH;
use super::plan_secret::WEB_ANALYTICS_RUM_READ_CAPABILITY_ID;
use super::plan_secret::WEB_ANALYTICS_RUM_STATE_PRECONDITION;
use super::prelude::{
    AuthCredential, CallInput, CatalogSnapshot, CliError, EvidenceV1, PlanV1, Result, StateStore,
    Value, json,
};
use super::provider_state::project_dns_record_snapshot;
use super::provider_state::read_live_dns_record_state;
use super::provider_state::read_live_warp_connector_configuration_state;
use super::provider_state::read_live_web_analytics_rum_state;
use super::provider_state::warp_connector_configuration_restore_body;
use super::r2_credentials::preflight_call_input;
use cfctl_cloudflare::validate_request_contract;
use cfctl_core::{hash_value, redact_json};

pub(super) async fn validate_live_warp_connector_configuration_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    plan: &PlanV1,
    input: &CallInput,
    credential: &AuthCredential,
) -> Result<Option<EvidenceV1>> {
    let Some(expected_hash) = required_warp_connector_configuration_state_precondition(plan)?
    else {
        return Ok(None);
    };
    let (receipt, evidence) = read_live_warp_connector_configuration_state(
        store,
        catalog,
        &plan.capability,
        input,
        &plan.account_id,
        credential,
    )
    .await?;
    if hash_value(&receipt)? != expected_hash {
        return Err(CliError::Input(
            "live WARP Connector configuration drifted after planning; the mutation boundary was not crossed and a new plan is required"
                .to_owned(),
        ));
    }
    Ok(Some(evidence))
}

pub(super) fn validate_warp_connector_configuration_prior_state_receipt(
    plan: &PlanV1,
    receipt: &Value,
) -> Result<Value> {
    let tunnel_id = plan
        .targets
        .pointer("/selectors/tunnel_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "WARP Connector plan omitted its hash-bound Tunnel selector; create a new plan"
                    .to_owned(),
            )
        })?;
    let exact_identity = receipt.as_object().is_some_and(|object| object.len() == 11)
        && receipt.get("schema_version").and_then(Value::as_u64) == Some(1)
        && receipt.get("source_capability_id").and_then(Value::as_str)
            == Some(WARP_CONNECTOR_CONFIGURATION_READ_CAPABILITY_ID)
        && receipt.get("source_path").and_then(Value::as_str)
            == Some(WARP_CONNECTOR_CONFIGURATION_PATH)
        && receipt.get("target_capability_id").and_then(Value::as_str)
            == Some(plan.capability.id.as_str())
        && receipt.get("target_method").and_then(Value::as_str)
            == Some(plan.capability.method.as_str())
        && receipt.get("target_path").and_then(Value::as_str)
            == Some(plan.capability.path.as_str())
        && receipt.get("target_scope").and_then(Value::as_str) == Some("account")
        && receipt.get("account_id").and_then(Value::as_str) == Some(plan.account_id.as_str())
        && receipt.get("tunnel_id").and_then(Value::as_str) == Some(tunnel_id);
    let prior_ha_mode = receipt.get("prior_ha_mode").and_then(Value::as_str);
    let prior_config = receipt
        .get("prior_config")
        .filter(|value| value.is_null() || value.is_object());
    if !exact_identity || prior_ha_mode.is_none() || prior_config.is_none() {
        return Err(CliError::Input(
            "plan WARP Connector prior-state receipt has an invalid account, Tunnel, source, method, path, or HA state shape; create a new plan"
                .to_owned(),
        ));
    }
    let prior_ha_mode = prior_ha_mode.unwrap_or_default();
    let prior_config = prior_config.unwrap_or(&Value::Null);
    let observed_state_input = CallInput {
        selectors: json!({"account_id": plan.account_id, "tunnel_id": tunnel_id}),
        body: Some(json!({
            "ha_mode": prior_ha_mode,
            "config": prior_config,
        })),
        ..CallInput::default()
    };
    preflight_call_input(&plan.capability, &observed_state_input, None).map_err(|error| {
        CliError::Input(format!(
            "plan WARP Connector prior-state receipt is outside the exact restorable HA contract; create a new plan: {error}"
        ))
    })?;
    Ok(warp_connector_configuration_restore_body(
        prior_ha_mode,
        Some(prior_config),
    ))
}

pub(super) fn required_warp_connector_configuration_state_precondition(
    plan: &PlanV1,
) -> Result<Option<&str>> {
    if !is_warp_connector_configuration_mutation(&plan.capability) {
        return Ok(None);
    }
    if !should_bind_warp_connector_configuration_state(&plan.capability) {
        return Err(CliError::Input(
            "WARP Connector plan is inconsistent with its hash-bound prior-state contract; create a new plan"
                .to_owned(),
        ));
    }
    let expected_hash = plan
        .precondition_hashes
        .get(WARP_CONNECTOR_CONFIGURATION_STATE_PRECONDITION)
        .map(String::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "plan predates the live WARP Connector prior-state contract; create a new plan"
                    .to_owned(),
            )
        })?;
    let receipt = plan
        .targets
        .pointer("/live_preconditions/warp_connector_configuration_state")
        .ok_or_else(|| {
            CliError::Input(
                "plan predates the hash-bound WARP Connector prior-state receipt; create a new plan"
                    .to_owned(),
            )
        })?;
    validate_warp_connector_configuration_prior_state_receipt(plan, receipt)?;
    if hash_value(receipt)? != expected_hash {
        return Err(CliError::Input(
            "plan WARP Connector prior-state receipt does not match its precondition hash; create a new plan"
                .to_owned(),
        ));
    }
    Ok(Some(expected_hash))
}

pub(super) fn warp_connector_configuration_prior_snapshot(plan: &PlanV1) -> Result<Value> {
    required_warp_connector_configuration_state_precondition(plan)?.ok_or_else(|| {
        CliError::Input(
            "WARP Connector compensation requires a hash-bound prior-state precondition".to_owned(),
        )
    })?;
    let receipt = plan
        .targets
        .pointer("/live_preconditions/warp_connector_configuration_state")
        .ok_or_else(|| {
            CliError::Input(
                "WARP Connector compensation requires a hash-bound prior-state receipt".to_owned(),
            )
        })?;
    validate_warp_connector_configuration_prior_state_receipt(plan, receipt)
}

pub(super) async fn validate_live_web_analytics_rum_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    plan: &PlanV1,
    input: &CallInput,
    credential: &AuthCredential,
) -> Result<Option<EvidenceV1>> {
    let Some(expected_hash) = required_web_analytics_rum_state_precondition(plan)? else {
        return Ok(None);
    };
    let (receipt, evidence) = read_live_web_analytics_rum_state(
        store,
        catalog,
        &plan.capability,
        input,
        &plan.account_id,
        credential,
    )
    .await?;
    if hash_value(&receipt)? != expected_hash {
        return Err(CliError::Input(
            "live Web Analytics RUM state drifted after planning; the mutation boundary was not crossed and a new plan is required"
                .to_owned(),
        ));
    }
    Ok(Some(evidence))
}

pub(super) fn validate_web_analytics_rum_prior_state_receipt<'a>(
    plan: &PlanV1,
    receipt: &'a Value,
) -> Result<&'a str> {
    let zone_id = plan
        .targets
        .pointer("/selectors/zone_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "Web Analytics RUM plan omitted its hash-bound zone selector; create a new plan"
                    .to_owned(),
            )
        })?;
    let prior_value = receipt
        .get("prior_value")
        .and_then(Value::as_str)
        .filter(|value| matches!(*value, "on" | "off"));
    let exact_identity = receipt.as_object().is_some_and(|object| object.len() == 12)
        && receipt.get("schema_version").and_then(Value::as_u64) == Some(1)
        && receipt.get("source_capability_id").and_then(Value::as_str)
            == Some(WEB_ANALYTICS_RUM_READ_CAPABILITY_ID)
        && receipt.get("source_path").and_then(Value::as_str) == Some(WEB_ANALYTICS_RUM_PATH)
        && receipt.get("target_capability_id").and_then(Value::as_str)
            == Some(plan.capability.id.as_str())
        && receipt.get("target_method").and_then(Value::as_str)
            == Some(plan.capability.method.as_str())
        && receipt.get("target_path").and_then(Value::as_str)
            == Some(plan.capability.path.as_str())
        && receipt.get("target_scope").and_then(Value::as_str) == Some("zone")
        && receipt.get("account_id").and_then(Value::as_str) == Some(plan.account_id.as_str())
        && receipt.get("zone_id").and_then(Value::as_str) == Some(zone_id)
        && receipt.get("setting_id").and_then(Value::as_str) == Some("rum")
        && receipt.get("editable").and_then(Value::as_bool) == Some(true);
    if !exact_identity || prior_value.is_none() {
        return Err(CliError::Input(
            "plan Web Analytics RUM prior-state receipt has an invalid account, zone, source, method, path, editability, or on/off value; create a new plan"
                .to_owned(),
        ));
    }
    Ok(prior_value.unwrap_or_default())
}

pub(super) fn required_web_analytics_rum_state_precondition(plan: &PlanV1) -> Result<Option<&str>> {
    if !is_web_analytics_rum_mutation(&plan.capability) {
        return Ok(None);
    }
    if !should_bind_web_analytics_rum_state(&plan.capability) {
        return Err(CliError::Input(
            "Web Analytics RUM plan is inconsistent with its hash-bound prior-state contract; create a new plan"
                .to_owned(),
        ));
    }
    let expected_hash = plan
        .precondition_hashes
        .get(WEB_ANALYTICS_RUM_STATE_PRECONDITION)
        .map(String::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "plan predates the live Web Analytics RUM prior-state contract; create a new plan"
                    .to_owned(),
            )
        })?;
    let receipt = plan
        .targets
        .pointer("/live_preconditions/web_analytics_rum_state")
        .ok_or_else(|| {
            CliError::Input(
                "plan predates the hash-bound Web Analytics RUM prior-state receipt; create a new plan"
                    .to_owned(),
            )
        })?;
    validate_web_analytics_rum_prior_state_receipt(plan, receipt)?;
    if hash_value(receipt)? != expected_hash {
        return Err(CliError::Input(
            "plan Web Analytics RUM prior-state receipt does not match its precondition hash; create a new plan"
                .to_owned(),
        ));
    }
    Ok(Some(expected_hash))
}

pub(super) fn web_analytics_rum_prior_value(plan: &PlanV1) -> Result<&str> {
    required_web_analytics_rum_state_precondition(plan)?.ok_or_else(|| {
        CliError::Input(
            "Web Analytics RUM compensation requires a hash-bound prior-state precondition"
                .to_owned(),
        )
    })?;
    let receipt = plan
        .targets
        .pointer("/live_preconditions/web_analytics_rum_state")
        .ok_or_else(|| {
            CliError::Input(
                "Web Analytics RUM compensation requires a hash-bound prior-state receipt"
                    .to_owned(),
            )
        })?;
    validate_web_analytics_rum_prior_state_receipt(plan, receipt)
}

pub(super) async fn validate_live_dns_record_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    plan: &PlanV1,
    input: &CallInput,
    credential: &AuthCredential,
) -> Result<Option<EvidenceV1>> {
    let Some(expected_hash) = required_dns_record_state_precondition(plan)? else {
        return Ok(None);
    };
    let (receipt, evidence) = read_live_dns_record_state(
        store,
        catalog,
        &plan.capability,
        input,
        &plan.account_id,
        credential,
    )
    .await?;
    if hash_value(&receipt)? != expected_hash {
        return Err(CliError::Input(
            "live DNS record state drifted after planning; the mutation boundary was not crossed and a new plan is required"
                .to_owned(),
        ));
    }
    Ok(Some(evidence))
}

pub(super) async fn validate_live_oauth_client_secret_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    plan: &PlanV1,
    input: &CallInput,
    credential: &AuthCredential,
) -> Result<Option<EvidenceV1>> {
    let Some(expected_hash) = required_oauth_client_secret_state_precondition(plan)? else {
        return Ok(None);
    };
    let (receipt, evidence) = read_live_oauth_client_secret_state(
        store,
        catalog,
        &plan.capability,
        input,
        &plan.account_id,
        credential,
    )
    .await?;
    if hash_value(&receipt)? != expected_hash {
        return Err(CliError::Input(
            "live OAuth client two-secret state drifted after planning; the mutation boundary was not crossed and a new plan is required"
                .to_owned(),
        ));
    }
    Ok(Some(evidence))
}

pub(super) fn validate_oauth_client_update_state_receipt(
    plan: &PlanV1,
    receipt: &Value,
) -> Result<()> {
    let account_id = plan
        .targets
        .pointer("/selectors/account_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "OAuth client update omitted its hash-bound account selector; create a new plan"
                    .to_owned(),
            )
        })?;
    let oauth_client_id = plan
        .targets
        .pointer("/selectors/oauth_client_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "OAuth client update omitted its hash-bound client selector; create a new plan"
                    .to_owned(),
            )
        })?;
    let prior_state = receipt
        .get("prior_state")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CliError::Input(
                "OAuth client update receipt omitted its projected prior state; create a new plan"
                    .to_owned(),
            )
        })?;
    let absent_fields = receipt
        .get("absent_fields")
        .and_then(Value::as_array)
        .and_then(|fields| {
            fields
                .iter()
                .map(|field| field.as_str().map(str::to_owned))
                .collect::<Option<Vec<_>>>()
        })
        .ok_or_else(|| {
            CliError::Input(
                "OAuth client update receipt omitted its exact absent-field set; create a new plan"
                    .to_owned(),
            )
        })?;
    let mut projected_fields = prior_state.keys().cloned().collect::<Vec<_>>();
    projected_fields.extend(absent_fields.iter().cloned());
    projected_fields.sort();
    let expected_fields = OAUTH_CLIENT_MUTABLE_FIELDS
        .iter()
        .map(|field| (*field).to_owned())
        .collect::<Vec<_>>();
    let exact = receipt.as_object().is_some_and(|object| object.len() == 12)
        && receipt.get("schema_version").and_then(Value::as_u64) == Some(1)
        && receipt.get("source_capability_id").and_then(Value::as_str)
            == Some(OAUTH_CLIENT_DETAIL_READ_CAPABILITY_ID)
        && receipt.get("source_path").and_then(Value::as_str) == Some(OAUTH_CLIENT_DETAIL_PATH)
        && receipt.get("target_capability_id").and_then(Value::as_str)
            == Some(plan.capability.id.as_str())
        && receipt.get("target_method").and_then(Value::as_str)
            == Some(plan.capability.method.as_str())
        && receipt.get("target_path").and_then(Value::as_str)
            == Some(plan.capability.path.as_str())
        && receipt.get("target_scope").and_then(Value::as_str) == Some("account")
        && receipt.get("account_id").and_then(Value::as_str) == Some(account_id)
        && account_id == plan.account_id
        && receipt.get("oauth_client_id").and_then(Value::as_str) == Some(oauth_client_id)
        && receipt
            .get("observed_result_hash")
            .and_then(Value::as_str)
            .is_some_and(|hash| hash.starts_with("sha256:"))
        && projected_fields == expected_fields
        && !projected_fields.windows(2).any(|pair| pair[0] == pair[1])
        && prior_state
            .get("visibility")
            .and_then(Value::as_str)
            .is_some_and(|visibility| matches!(visibility, "private" | "public"))
        && redact_json(&Value::Object(prior_state.clone())) == Value::Object(prior_state.clone());
    if !exact {
        return Err(CliError::Input(
            "OAuth client update receipt has an invalid account, client, source, hash, visibility, or field projection; create a new plan"
                .to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn required_oauth_client_update_state_precondition(
    plan: &PlanV1,
) -> Result<Option<&str>> {
    if !is_oauth_client_update_capability(&plan.capability) {
        return Ok(None);
    }
    if !should_bind_oauth_client_update_state(&plan.capability) {
        return Err(CliError::Input(
            "OAuth client update is inconsistent with its hash-bound snapshot contract; create a new plan"
                .to_owned(),
        ));
    }
    let expected_hash = plan
        .precondition_hashes
        .get(OAUTH_CLIENT_UPDATE_STATE_PRECONDITION)
        .map(String::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "plan predates the live OAuth client update snapshot contract; create a new plan"
                    .to_owned(),
            )
        })?;
    let receipt = plan
        .targets
        .pointer("/live_preconditions/oauth_client_update_state")
        .ok_or_else(|| {
            CliError::Input(
                "plan predates the hash-bound OAuth client update state receipt; create a new plan"
                    .to_owned(),
            )
        })?;
    validate_oauth_client_update_state_receipt(plan, receipt)?;
    if hash_value(receipt)? != expected_hash {
        return Err(CliError::Input(
            "plan OAuth client update receipt does not match its precondition hash; create a new plan"
                .to_owned(),
        ));
    }
    Ok(Some(expected_hash))
}

pub(super) async fn validate_live_oauth_client_update_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    plan: &PlanV1,
    input: &CallInput,
    credential: &AuthCredential,
) -> Result<Option<EvidenceV1>> {
    let Some(expected_hash) = required_oauth_client_update_state_precondition(plan)? else {
        return Ok(None);
    };
    let (receipt, evidence) = read_live_oauth_client_update_state(
        store,
        catalog,
        &plan.capability,
        input,
        &plan.account_id,
        credential,
    )
    .await?;
    if hash_value(&receipt)? != expected_hash {
        return Err(CliError::Input(
            "live OAuth client state drifted after planning; the mutation boundary was not crossed and a new plan is required"
                .to_owned(),
        ));
    }
    Ok(Some(evidence))
}

pub(super) fn validate_oauth_client_secret_state_receipt(
    plan: &PlanV1,
    receipt: &Value,
) -> Result<()> {
    let account_id = plan
        .targets
        .pointer("/selectors/account_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "OAuth client plan omitted its hash-bound account selector; create a new plan"
                    .to_owned(),
            )
        })?;
    let oauth_client_id = plan
        .targets
        .pointer("/selectors/oauth_client_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "OAuth client plan omitted its hash-bound client selector; create a new plan"
                    .to_owned(),
            )
        })?;
    let expected_state =
        oauth_client_secret_expected_prior_state(&plan.capability).ok_or_else(|| {
            CliError::Input(
                "OAuth client plan has an unsupported hash-bound cutover phase; create a new plan"
                    .to_owned(),
            )
        })?;
    let exact = receipt.as_object().is_some_and(|object| object.len() == 9)
        && receipt.get("schema_version").and_then(Value::as_u64) == Some(1)
        && receipt.get("source_capability_id").and_then(Value::as_str)
            == Some(OAUTH_CLIENT_DETAIL_READ_CAPABILITY_ID)
        && receipt.get("source_path").and_then(Value::as_str) == Some(OAUTH_CLIENT_DETAIL_PATH)
        && receipt.get("target_capability_id").and_then(Value::as_str)
            == Some(plan.capability.id.as_str())
        && receipt.get("target_method").and_then(Value::as_str)
            == Some(plan.capability.method.as_str())
        && receipt.get("target_scope").and_then(Value::as_str) == Some("account")
        && receipt.get("account_id").and_then(Value::as_str) == Some(account_id)
        && account_id == plan.account_id
        && receipt.get("oauth_client_id").and_then(Value::as_str) == Some(oauth_client_id)
        && receipt.get("key_overlap_active").and_then(Value::as_bool) == Some(expected_state);
    if !exact {
        return Err(CliError::Input(
            "plan OAuth client prior-state receipt has an invalid account, client, source, phase, or two-secret state; create a new plan"
                .to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn required_oauth_client_secret_state_precondition(
    plan: &PlanV1,
) -> Result<Option<&str>> {
    if oauth_client_secret_expected_prior_state(&plan.capability).is_none() {
        return Ok(None);
    }
    if !should_bind_oauth_client_secret_state(&plan.capability) {
        return Err(CliError::Input(
            "OAuth client secret plan is inconsistent with its hash-bound two-secret cutover contract; create a new plan"
                .to_owned(),
        ));
    }
    let expected_hash = plan
        .precondition_hashes
        .get(OAUTH_CLIENT_KEY_OVERLAP_PRECONDITION)
        .map(String::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "plan predates the live OAuth client two-secret state contract; create a new plan"
                    .to_owned(),
            )
        })?;
    let receipt = plan
        .targets
        .pointer("/live_preconditions/oauth_client_key_overlap")
        .ok_or_else(|| {
            CliError::Input(
                "plan predates the hash-bound OAuth client two-secret state receipt; create a new plan"
                    .to_owned(),
            )
        })?;
    validate_oauth_client_secret_state_receipt(plan, receipt)?;
    if hash_value(receipt)? != expected_hash {
        return Err(CliError::Input(
            "plan OAuth client prior-state receipt does not match its precondition hash; create a new plan"
                .to_owned(),
        ));
    }
    Ok(Some(expected_hash))
}

pub(super) fn validate_dns_record_prior_state_receipt(
    plan: &PlanV1,
    receipt: &Value,
) -> Result<Value> {
    let zone_id = plan
        .targets
        .pointer("/selectors/zone_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "DNS plan omitted its hash-bound zone selector; create a new plan".to_owned(),
            )
        })?;
    let dns_record_id = plan
        .targets
        .pointer("/selectors/dns_record_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "DNS plan omitted its hash-bound record selector; create a new plan".to_owned(),
            )
        })?;
    let exact_identity = receipt.as_object().is_some_and(|object| object.len() == 10)
        && receipt.get("schema_version").and_then(Value::as_u64) == Some(1)
        && receipt.get("source_capability_id").and_then(Value::as_str)
            == Some(DNS_RECORD_DETAIL_READ_CAPABILITY_ID)
        && receipt.get("source_path").and_then(Value::as_str) == Some(DNS_RECORD_DETAIL_PATH)
        && receipt.get("target_capability_id").and_then(Value::as_str)
            == Some(plan.capability.id.as_str())
        && receipt.get("target_method").and_then(Value::as_str)
            == Some(plan.capability.method.as_str())
        && receipt.get("target_scope").and_then(Value::as_str) == Some("zone")
        && receipt.get("account_id").and_then(Value::as_str) == Some(plan.account_id.as_str())
        && receipt.get("zone_id").and_then(Value::as_str) == Some(zone_id)
        && receipt.get("dns_record_id").and_then(Value::as_str) == Some(dns_record_id);
    let prior_record = receipt.get("prior_record").ok_or_else(|| {
        CliError::Input(
            "plan DNS prior-state receipt omitted its writable record snapshot; create a new plan"
                .to_owned(),
        )
    })?;
    let projected = project_dns_record_snapshot(&plan.capability, prior_record)?;
    if !exact_identity || &projected != prior_record {
        return Err(CliError::Input(
            "plan DNS prior-state receipt has an invalid account, zone, record, source, method, or writable snapshot shape; create a new plan"
                .to_owned(),
        ));
    }
    validate_request_contract(
        &plan.capability,
        &CallInput {
            selectors: json!({"zone_id":zone_id,"dns_record_id":dns_record_id}),
            query: json!({}),
            body: Some(projected.clone()),
            ..CallInput::default()
        },
    )?;
    Ok(projected)
}

pub(super) fn required_dns_record_state_precondition(plan: &PlanV1) -> Result<Option<&str>> {
    if !is_dns_record_update_mutation(&plan.capability) {
        return Ok(None);
    }
    if !should_bind_dns_record_state(&plan.capability) {
        return Err(CliError::Input(
            "DNS record plan is inconsistent with its hash-bound prior-state contract; create a new plan"
                .to_owned(),
        ));
    }
    let expected_hash = plan
        .precondition_hashes
        .get(DNS_RECORD_STATE_PRECONDITION)
        .map(String::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "plan predates the live DNS record prior-state contract; create a new plan"
                    .to_owned(),
            )
        })?;
    let receipt = plan
        .targets
        .pointer("/live_preconditions/dns_record_state")
        .ok_or_else(|| {
            CliError::Input(
                "plan predates the hash-bound DNS record prior-state receipt; create a new plan"
                    .to_owned(),
            )
        })?;
    validate_dns_record_prior_state_receipt(plan, receipt)?;
    if hash_value(receipt)? != expected_hash {
        return Err(CliError::Input(
            "plan DNS record prior-state receipt does not match its precondition hash; create a new plan"
                .to_owned(),
        ));
    }
    Ok(Some(expected_hash))
}

pub(super) fn dns_record_prior_snapshot(plan: &PlanV1) -> Result<Value> {
    required_dns_record_state_precondition(plan)?.ok_or_else(|| {
        CliError::Input(
            "DNS record compensation requires a hash-bound prior-state precondition".to_owned(),
        )
    })?;
    let receipt = plan
        .targets
        .pointer("/live_preconditions/dns_record_state")
        .ok_or_else(|| {
            CliError::Input(
                "DNS record compensation requires a hash-bound prior-state receipt".to_owned(),
            )
        })?;
    validate_dns_record_prior_state_receipt(plan, receipt)
}

#[expect(
    clippy::too_many_lines,
    reason = "the compensation validator keeps every receipt identity and complete prior-state invariant visible at one rollback boundary"
)]
pub(super) fn validate_same_path_prior_state_receipt(
    plan: &PlanV1,
    receipt: &Value,
) -> Result<Value> {
    let target = plan.capability.same_path_read.as_ref().ok_or_else(|| {
        CliError::Input(
            "same-path rollback plan omitted its hash-bound readback contract".to_owned(),
        )
    })?;
    let input: CallInput = serde_json::from_value(plan.input.clone())?;
    let expected_receipt_fields =
        if is_access_application_owned_whole_host_mutation(&plan.capability) {
            11
        } else {
            10
        };
    let exact_identity = receipt
        .as_object()
        .is_some_and(|object| object.len() == expected_receipt_fields)
        && receipt.get("schema_version").and_then(Value::as_u64) == Some(1)
        && receipt.get("source_capability_id").and_then(Value::as_str)
            == Some(target.read_capability_id.as_str())
        && receipt.get("source_path").and_then(Value::as_str) == Some(target.path.as_str())
        && receipt.get("target_capability_id").and_then(Value::as_str)
            == Some(plan.capability.id.as_str())
        && receipt.get("target_method").and_then(Value::as_str)
            == Some(plan.capability.method.as_str())
        && receipt.get("target_path").and_then(Value::as_str)
            == Some(plan.capability.path.as_str())
        && receipt.get("target_scope").and_then(Value::as_str)
            == Some(plan.capability.account_scope.as_str())
        && receipt.get("account_id").and_then(Value::as_str) == Some(plan.account_id.as_str())
        && receipt.get("selectors") == Some(&input.selectors);
    let ownership_identity = if is_access_application_owned_whole_host_mutation(&plan.capability) {
        let app_id = input.selectors.get("app_id").and_then(Value::as_str);
        let name = input
            .body
            .as_ref()
            .and_then(|body| body.get("name"))
            .and_then(Value::as_str);
        let hostname = input
            .body
            .as_ref()
            .and_then(|body| body.get("domain"))
            .and_then(Value::as_str);
        receipt.get("ownership").is_some_and(|ownership| {
            ownership
                .as_object()
                .is_some_and(|object| object.len() == 12)
                && ownership.get("schema_version").and_then(Value::as_u64) == Some(1)
                && ownership
                    .get("source_capability_id")
                    .and_then(Value::as_str)
                    == Some(ACCESS_APP_LIST_CAPABILITY_ID)
                && ownership.get("source_path").and_then(Value::as_str)
                    == Some(ACCESS_APP_COLLECTION_PATH)
                && ownership
                    .get("selected_application_id")
                    .and_then(Value::as_str)
                    == app_id
                && ownership
                    .get("selected_application_type")
                    .and_then(Value::as_str)
                    == Some("self_hosted")
                && ownership.get("selected_name").and_then(Value::as_str) == name
                && ownership.get("selected_hostname").and_then(Value::as_str) == hostname
                && ownership.get("selected_id_count").and_then(Value::as_u64) == Some(1)
                && ownership.get("candidate_count").and_then(Value::as_u64) == Some(1)
                && ownership
                    .get("collection_count")
                    .and_then(Value::as_u64)
                    .is_some_and(|count| count >= 1)
                && ownership
                    .get("collection_digest")
                    .and_then(Value::as_str)
                    .is_some_and(|digest| {
                        digest.len() == 71
                            && digest.starts_with("sha256:")
                            && digest[7..]
                                .chars()
                                .all(|character| character.is_ascii_hexdigit())
                    })
                && ownership
                    .get("terminal_pagination")
                    .and_then(Value::as_bool)
                    == Some(true)
        })
    } else {
        receipt.get("ownership").is_none()
    };
    let prior_state = receipt
        .get("prior_state")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| {
            CliError::Input(
                "same-path prior-state receipt omitted its restorable object snapshot; create a new plan"
                    .to_owned(),
            )
    })?;
    let prior_state = Value::Object(prior_state);
    let access_application_concurrency_only =
        is_access_application_implicit_open_concurrency_plan(&plan.capability);
    let valid_state_shape = if is_access_operator_group_policy_update(&plan.capability) {
        access_operator_group_policy_restorable_body(&prior_state)
            .is_ok_and(|normalized| normalized == prior_state)
    } else if is_access_human_policy_mutation(&plan.capability) {
        access_human_policy_restorable_body(&prior_state)
            .is_ok_and(|normalized| normalized == prior_state)
    } else if access_application_login_methods_contract_supported(&plan.capability) {
        let expected_fields = same_path_prior_state_fields(&plan.capability, &input)?;
        let observed_fields = prior_state
            .as_object()
            .map(|state| state.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        let variant = access_application_login_methods_variant(&plan.capability.id);
        let current_idps = prior_state
            .get("allowed_idps")
            .ok_or_else(|| {
                CliError::Input(
                    "same-path Access application receipt omitted `allowed_idps`; create a new plan"
                        .to_owned(),
                )
            })
            .and_then(|allowed_idps| {
                if access_application_concurrency_only {
                    let idps = normalized_access_application_idps(allowed_idps)?;
                    if idps.is_empty() {
                        Ok(idps)
                    } else {
                        Err(CliError::Input(
                            "implicit-open Access application receipt contains a non-empty identity-provider allowlist; create a new plan"
                                .to_owned(),
                        ))
                    }
                } else {
                    access_application_rollback_idps(allowed_idps)
                }
            });
        observed_fields == expected_fields
            && variant
                .zip(current_idps.ok())
                .is_some_and(|(variant, current_idps)| {
                    access_application_mutable_body(&prior_state, &current_idps, variant)
                        .is_ok_and(|normalized| normalized == prior_state)
                })
    } else {
        let expected_fields = same_path_prior_state_fields(&plan.capability, &input)?;
        let observed_fields = prior_state
            .as_object()
            .map(|state| state.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        observed_fields == expected_fields
    };
    if !exact_identity || !ownership_identity || !valid_state_shape {
        return Err(CliError::Input(
            "same-path prior-state receipt has an invalid source, target, selector, or field set; create a new plan"
                .to_owned(),
        ));
    }
    let mut restore_input = input;
    restore_input.query = json!({});
    restore_input.body = Some(prior_state.clone());
    if access_application_concurrency_only {
        return Ok(prior_state);
    }
    preflight_call_input(&plan.capability, &restore_input, None).map_err(|error| {
        CliError::Input(format!(
            "same-path prior-state receipt is outside the exact restorable request contract; create a new plan: {error}"
        ))
    })?;
    Ok(prior_state)
}

pub(super) fn required_same_path_prior_state_precondition(plan: &PlanV1) -> Result<Option<&str>> {
    let declares_same_path_state = plan.capability.rollback.strategy.as_deref()
        == Some(SAME_PATH_PRIOR_STATE_ROLLBACK_STRATEGY)
        || (access_application_login_methods_contract_supported(&plan.capability)
            && !plan.capability.rollback.supported
            && plan.capability.rollback.strategy.is_none());
    if !declares_same_path_state {
        return Ok(None);
    }
    if !requires_same_path_state_precondition(&plan.capability) {
        return Err(CliError::Input(
            "plan is inconsistent with its hash-bound same-path prior-state contract; create a new plan"
                .to_owned(),
        ));
    }
    let expected_hash = plan
        .precondition_hashes
        .get(SAME_PATH_PRIOR_STATE_PRECONDITION)
        .map(String::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "plan predates the same-path prior-state contract; create a new plan".to_owned(),
            )
        })?;
    let receipt = plan
        .targets
        .pointer("/live_preconditions/same_path_prior_state")
        .ok_or_else(|| {
            CliError::Input(
                "plan predates the hash-bound same-path prior-state receipt; create a new plan"
                    .to_owned(),
            )
        })?;
    validate_same_path_prior_state_receipt(plan, receipt)?;
    if hash_value(receipt)? != expected_hash {
        return Err(CliError::Input(
            "plan same-path prior-state receipt does not match its precondition hash; create a new plan"
                .to_owned(),
        ));
    }
    Ok(Some(expected_hash))
}

pub(super) fn same_path_prior_snapshot(plan: &PlanV1) -> Result<Value> {
    if !should_bind_same_path_prior_state(&plan.capability) {
        return Err(CliError::Input(
            "same-path compensation requires a supported automatic rollback contract".to_owned(),
        ));
    }
    required_same_path_prior_state_precondition(plan)?.ok_or_else(|| {
        CliError::Input(
            "same-path compensation requires a hash-bound prior-state precondition".to_owned(),
        )
    })?;
    let receipt = plan
        .targets
        .pointer("/live_preconditions/same_path_prior_state")
        .ok_or_else(|| {
            CliError::Input(
                "same-path compensation requires a hash-bound prior-state receipt".to_owned(),
            )
        })?;
    validate_same_path_prior_state_receipt(plan, receipt)
}

pub(super) fn validate_same_path_prior_state_receipt_precondition(
    expected_hash: &str,
    current_receipt: &Value,
) -> Result<()> {
    if hash_value(current_receipt)? != expected_hash {
        return Err(CliError::Input(
            "live same-path state drifted after planning; the mutation boundary was not crossed and a new plan is required"
                .to_owned(),
        ));
    }
    Ok(())
}

pub(super) async fn validate_live_same_path_prior_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    plan: &PlanV1,
    input: &CallInput,
    credential: &AuthCredential,
) -> Result<Option<EvidenceV1>> {
    let Some(expected_hash) = required_same_path_prior_state_precondition(plan)? else {
        return Ok(None);
    };
    let (receipt, evidence) = read_live_same_path_prior_state(
        store,
        catalog,
        &plan.capability,
        input,
        &plan.account_id,
        credential,
    )
    .await?;
    validate_same_path_prior_state_receipt_precondition(expected_hash, &receipt)?;
    Ok(Some(evidence))
}
