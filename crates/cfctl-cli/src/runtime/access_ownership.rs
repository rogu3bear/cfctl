use super::access_policy::access_operator_group_policy_identity;
use super::access_policy::is_access_application_owned_whole_host_mutation;
use super::access_policy::is_access_operator_group_policy_create;
use super::access_policy::is_access_operator_group_policy_update;
use super::cloudflare_api::BASE_URL as API_BASE_URL;
use super::live_state_contracts::apply_same_path_prior_state_response;
use super::live_state_contracts::requires_same_path_state_precondition;
use super::live_state_contracts::same_path_read_source_contract_supported;
use super::plan_secret::ACCESS_APP_COLLECTION_PATH;
use super::plan_secret::ACCESS_APP_LIST_CAPABILITY_ID;
use super::plan_secret::ACCESS_POLICY_COLLECTION_PATH;
use super::plan_secret::ACCESS_POLICY_LIST_CAPABILITY_ID;
use super::prelude::{
    AdapterStatus, AuthCredential, CallInput, CapabilityV1, CatalogSnapshot, CliError,
    CloudflareResponseV1, EvidenceClass, EvidenceV1, Executor, Result, StateStore, Uuid, Value,
    json,
};
use super::security_action_state::collection_read_complete;
use super::support::capability_missing;
use super::support::http_client;
use cfctl_core::hash_value;

pub(super) fn access_application_collection_source_contract_supported(
    source: &CapabilityV1,
) -> bool {
    source.id == ACCESS_APP_LIST_CAPABILITY_ID
        && source.method == "GET"
        && source.path == ACCESS_APP_COLLECTION_PATH
        && source.account_scope == "account"
        && !source.mutating
        && matches!(
            source.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        && source.request_schema.is_none()
        && source.selectors.iter().any(|selector| {
            selector.name == "account_id" && selector.location == "path" && selector.required
        })
        && source.response_contract.as_ref().is_some_and(|contract| {
            contract.body_mode == cfctl_core::ResponseBodyModeV1::CloudflareJsonEnvelope
                && contract.success_statuses == ["200"]
                && contract.success_media_types == ["application/json"]
        })
}

pub(super) fn normalized_access_application_hostname(value: &str) -> Option<String> {
    let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
    let value = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
        .unwrap_or(&value);
    let hostname = value.split('/').next().unwrap_or_default();
    if hostname.is_empty() || hostname.contains(':') {
        return None;
    }
    Some(hostname.to_owned())
}

pub(super) fn access_application_hostname_overlaps(candidate: &str, target: &str) -> bool {
    let Some(candidate) = normalized_access_application_hostname(candidate) else {
        return false;
    };
    candidate == target
        || candidate
            .strip_prefix("*.")
            .is_some_and(|suffix| target.ends_with(&format!(".{suffix}")))
}

pub(super) fn access_application_mentions_hostname(application: &Value, hostname: &str) -> bool {
    application
        .get("domain")
        .and_then(Value::as_str)
        .is_some_and(|value| access_application_hostname_overlaps(value, hostname))
        || application
            .get("self_hosted_domains")
            .and_then(Value::as_array)
            .is_some_and(|values| {
                values.iter().any(|value| {
                    value
                        .as_str()
                        .is_some_and(|value| access_application_hostname_overlaps(value, hostname))
                })
            })
        || application
            .get("destinations")
            .and_then(Value::as_array)
            .is_some_and(|values| {
                values.iter().any(|value| {
                    value
                        .get("uri")
                        .and_then(Value::as_str)
                        .is_some_and(|value| access_application_hostname_overlaps(value, hostname))
                })
            })
}

#[expect(
    clippy::too_many_lines,
    reason = "the complete ownership collection, overlap rejection, and prior-snapshot receipt remain visible at one admission boundary"
)]
pub(super) fn owned_whole_host_access_application_receipt(
    input: &CallInput,
    response: &CloudflareResponseV1,
) -> Result<Value> {
    if !response.success || !(200..300).contains(&response.status) {
        return Err(CliError::Input(format!(
            "Cloudflare rejected the Access application ownership collection read with HTTP {}; the mutation boundary was not crossed",
            response.status
        )));
    }
    if !collection_read_complete(response) {
        return Err(CliError::Input(
            "Access application ownership collection read was not terminally paginated; the mutation boundary was not crossed"
                .to_owned(),
        ));
    }
    let applications = response.result.as_array().ok_or_else(|| {
        CliError::Input(
            "Access application ownership collection read did not return an array; the mutation boundary was not crossed"
                .to_owned(),
        )
    })?;
    let app_id = input
        .selectors
        .get("app_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CliError::Input("owned Access application omitted app_id".to_owned()))?;
    let body = input
        .body
        .as_ref()
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CliError::Input("owned Access application omitted its complete body".to_owned())
        })?;
    let name = body.get("name").and_then(Value::as_str).ok_or_else(|| {
        CliError::Input("owned Access application omitted its exact name".to_owned())
    })?;
    let hostname = body.get("domain").and_then(Value::as_str).ok_or_else(|| {
        CliError::Input("owned Access application omitted its exact hostname".to_owned())
    })?;

    let mut selected = Vec::new();
    let mut candidates = Vec::new();
    for application in applications {
        let object = application.as_object().ok_or_else(|| {
            CliError::Input(
                "Access application ownership collection contained a non-object entry; the mutation boundary was not crossed"
                    .to_owned(),
            )
        })?;
        let id = object.get("id").and_then(Value::as_str).filter(|value| !value.is_empty()).ok_or_else(|| {
            CliError::Input(
                "Access application ownership collection contained an application without an id; the mutation boundary was not crossed"
                    .to_owned(),
            )
        })?;
        let app_type = object
            .get("type")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                CliError::Input(
                    "Access application ownership collection contained an application without a type; the mutation boundary was not crossed"
                        .to_owned(),
                )
            })?;
        if id == app_id {
            selected.push(application);
        }
        if object.get("name").and_then(Value::as_str) == Some(name)
            || access_application_mentions_hostname(application, hostname)
        {
            candidates.push((id, app_type));
        }
    }

    if selected.len() != 1 {
        return Err(CliError::Input(format!(
            "Access application ownership collection contained {} entries for the exact application id; the mutation boundary was not crossed",
            selected.len()
        )));
    }
    let selected = selected[0];
    if selected.get("type").and_then(Value::as_str) != Some("self_hosted")
        || selected.get("name").and_then(Value::as_str) != Some(name)
        || selected
            .get("domain")
            .and_then(Value::as_str)
            .and_then(normalized_access_application_hostname)
            .as_deref()
            != Some(hostname)
    {
        return Err(CliError::Input(
            "the exact Access application id does not already own the requested self-hosted name and whole hostname; the mutation boundary was not crossed"
                .to_owned(),
        ));
    }
    if candidates.len() != 1 || candidates[0].0 != app_id || candidates[0].1 != "self_hosted" {
        return Err(CliError::Input(format!(
            "Access application ownership is ambiguous across {} exact or overlapping name/hostname candidates; the mutation boundary was not crossed",
            candidates.len()
        )));
    }

    Ok(json!({
        "schema_version": 1,
        "source_capability_id": ACCESS_APP_LIST_CAPABILITY_ID,
        "source_path": ACCESS_APP_COLLECTION_PATH,
        "selected_application_id": app_id,
        "selected_application_type": "self_hosted",
        "selected_name": name,
        "selected_hostname": hostname,
        "selected_id_count": 1,
        "candidate_count": candidates.len(),
        "collection_count": applications.len(),
        "collection_digest": hash_value(&response.result)?,
        "terminal_pagination": true,
    }))
}

pub(super) fn access_policy_collection_source_contract_supported(source: &CapabilityV1) -> bool {
    source.id == ACCESS_POLICY_LIST_CAPABILITY_ID
        && source.method == "GET"
        && source.path == ACCESS_POLICY_COLLECTION_PATH
        && source.product == "Access application-scoped policies"
        && source.account_scope == "account"
        && !source.mutating
        && source.request_schema.is_none()
        && matches!(
            source.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        && source.selectors.len() == 2
        && ["account_id", "app_id"].iter().all(|name| {
            source.selectors.iter().any(|selector| {
                selector.name == *name
                    && selector.location == "path"
                    && selector.required
                    && selector.value_type == "string"
            })
        })
        && source.response_contract.as_ref().is_some_and(|contract| {
            contract.body_mode == cfctl_core::ResponseBodyModeV1::CloudflareJsonEnvelope
                && contract.success_statuses == ["200"]
                && contract.success_media_types == ["application/json"]
        })
}

pub(super) fn exact_policy_operator_group_id(policy: &Value) -> Option<&str> {
    policy
        .get("include")
        .and_then(Value::as_array)
        .filter(|include| include.len() == 1)
        .and_then(|include| include[0].as_object())
        .filter(|rule| rule.len() == 1)
        .and_then(|rule| rule.get("group"))
        .and_then(Value::as_object)
        .filter(|group| group.len() == 1)
        .and_then(|group| group.get("id"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

pub(super) fn policy_contains_operator_group(
    policy: &Value,
    expected_group_id: &str,
) -> Result<bool> {
    let Some(include) = policy.get("include") else {
        return Ok(false);
    };
    let include = include.as_array().ok_or_else(|| {
        CliError::Input(
            "Access policy ownership collection contained a non-array include rule set; the mutation boundary was not crossed"
                .to_owned(),
        )
    })?;
    let expected_group_id = Uuid::parse_str(expected_group_id).map_err(|_| {
        CliError::Input("operator-group policy input contained an invalid group id".to_owned())
    })?;
    for rule in include {
        let rule = rule.as_object().ok_or_else(|| {
            CliError::Input(
                "Access policy ownership collection contained a non-object include rule; the mutation boundary was not crossed"
                    .to_owned(),
            )
        })?;
        let Some(group) = rule.get("group") else {
            continue;
        };
        let group_id = group
            .as_object()
            .and_then(|group| group.get("id"))
            .and_then(Value::as_str)
            .and_then(|group_id| Uuid::parse_str(group_id).ok())
            .ok_or_else(|| {
                CliError::Input(
                    "Access policy ownership collection contained an unclassified operator-group include rule; the mutation boundary was not crossed"
                        .to_owned(),
                )
            })?;
        if group_id == expected_group_id {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(super) fn access_operator_group_policy_ownership_receipt(
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    response: &CloudflareResponseV1,
) -> Result<Value> {
    if !response.success || !(200..300).contains(&response.status) {
        return Err(CliError::Input(format!(
            "Cloudflare rejected the Access policy ownership collection read with HTTP {}; the mutation boundary was not crossed",
            response.status
        )));
    }
    if !collection_read_complete(response) {
        return Err(CliError::Input(
            "Access policy ownership collection read was not terminally paginated; the mutation boundary was not crossed"
                .to_owned(),
        ));
    }
    let policies = response.result.as_array().ok_or_else(|| {
        CliError::Input(
            "Access policy ownership collection read did not return an array; the mutation boundary was not crossed"
                .to_owned(),
        )
    })?;
    let (name, group_id) = access_operator_group_policy_identity(input)?;
    let selected_id = input.selectors.get("policy_id").and_then(Value::as_str);
    let mut candidates = Vec::new();
    let mut selected = Vec::new();
    for policy in policies {
        let object = policy.as_object().ok_or_else(|| {
            CliError::Input(
                "Access policy ownership collection contained a non-object entry; the mutation boundary was not crossed"
                    .to_owned(),
            )
        })?;
        let id = object
            .get("id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                CliError::Input(
                    "Access policy ownership collection contained a policy without an id; the mutation boundary was not crossed"
                        .to_owned(),
                )
            })?;
        if selected_id == Some(id) {
            selected.push(policy);
        }
        if object.get("name").and_then(Value::as_str) == Some(name)
            || policy_contains_operator_group(policy, group_id)?
        {
            candidates.push(id);
        }
    }

    let (expected_candidates, selected_policy_id) = if is_access_operator_group_policy_create(
        capability,
    ) {
        if selected_id.is_some() || !selected.is_empty() || !candidates.is_empty() {
            return Err(CliError::Input(format!(
                "Access policy create requires zero exact-name and operator-group overlap candidates, but found {}; the mutation boundary was not crossed",
                candidates.len()
            )));
        }
        (0_u64, Value::Null)
    } else if is_access_operator_group_policy_update(capability) {
        let selected_id = selected_id.ok_or_else(|| {
            CliError::Input("operator-group policy update omitted policy_id".to_owned())
        })?;
        if selected.len() != 1
            || candidates.len() != 1
            || candidates[0] != selected_id
            || selected[0].get("name").and_then(Value::as_str) != Some(name)
            || exact_policy_operator_group_id(selected[0]) != Some(group_id)
            || selected[0].get("decision").and_then(Value::as_str) != Some("allow")
            || selected[0].get("reusable").and_then(Value::as_bool) != Some(false)
        {
            return Err(CliError::Input(format!(
                "Access policy update ownership is ambiguous across {} exact-name or operator-group candidates; the mutation boundary was not crossed",
                candidates.len()
            )));
        }
        (1_u64, Value::String(selected_id.to_owned()))
    } else {
        return Err(CliError::Input(
            "Access policy ownership read was requested for an unrelated capability".to_owned(),
        ));
    };

    Ok(json!({
        "schema_version":1,
        "source_capability_id":ACCESS_POLICY_LIST_CAPABILITY_ID,
        "source_path":ACCESS_POLICY_COLLECTION_PATH,
        "target_capability_id":capability.id,
        "target_method":capability.method,
        "target_path":capability.path,
        "account_id":account_id,
        "app_id":input.selectors.get("app_id"),
        "selected_policy_id":selected_policy_id,
        "policy_name":name,
        "operator_group_id":group_id,
        "candidate_count":expected_candidates,
        "collection_count":policies.len(),
        "collection_digest":hash_value(&response.result)?,
        "terminal_pagination":true,
    }))
}

pub(super) async fn read_live_access_operator_group_policy_ownership(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: &AuthCredential,
) -> Result<(Value, EvidenceV1)> {
    let source = catalog
        .get(ACCESS_POLICY_LIST_CAPABILITY_ID)
        .ok_or_else(|| capability_missing(ACCESS_POLICY_LIST_CAPABILITY_ID))?;
    if !access_policy_collection_source_contract_supported(source) {
        return Err(CliError::Input(
            "Access policy ownership source capability drifted from the governed complete collection read"
                .to_owned(),
        ));
    }
    let app_id = input
        .selectors
        .get("app_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CliError::Input("operator-group policy omitted app_id".to_owned()))?;
    let response = Executor::new(http_client()?, API_BASE_URL)?
        .execute_read(
            source,
            &CallInput {
                selectors: json!({"account_id":account_id,"app_id":app_id}),
                query: json!({}),
                body: None,
                ..CallInput::default()
            },
            credential,
        )
        .await?;
    let receipt =
        access_operator_group_policy_ownership_receipt(capability, input, account_id, &response)?;
    let evidence = store.write_evidence(EvidenceClass::LiveRead, &receipt)?;
    Ok((receipt, evidence))
}

pub(super) async fn read_live_same_path_prior_state(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: &AuthCredential,
) -> Result<(Value, EvidenceV1)> {
    if !requires_same_path_state_precondition(capability) {
        return Err(CliError::Input(
            "mutation drifted from its governed same-path prior-state contract".to_owned(),
        ));
    }
    let target = capability.same_path_read.as_ref().ok_or_else(|| {
        CliError::Input(
            "same-path prior-state mutation omitted its hash-bound readback contract".to_owned(),
        )
    })?;
    let source = catalog
        .get(&target.read_capability_id)
        .ok_or_else(|| capability_missing(&target.read_capability_id))?;
    if !same_path_read_source_contract_supported(capability, source) {
        return Err(CliError::Input(
            "same-path state source capability drifted from the governed exact-resource read"
                .to_owned(),
        ));
    }
    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let response = executor
        .execute_read(
            source,
            &CallInput {
                selectors: input.selectors.clone(),
                query: json!({}),
                body: None,
                ..CallInput::default()
            },
            credential,
        )
        .await?;
    let mut receipt =
        apply_same_path_prior_state_response(capability, input, account_id, &response)?;
    if is_access_application_owned_whole_host_mutation(capability) {
        let collection_source = catalog
            .get(ACCESS_APP_LIST_CAPABILITY_ID)
            .ok_or_else(|| capability_missing(ACCESS_APP_LIST_CAPABILITY_ID))?;
        if !access_application_collection_source_contract_supported(collection_source) {
            return Err(CliError::Input(
                "Access application ownership source capability drifted from the governed complete collection read"
                    .to_owned(),
            ));
        }
        let collection_response = executor
            .execute_read(
                collection_source,
                &CallInput {
                    selectors: json!({"account_id": account_id}),
                    query: json!({}),
                    body: None,
                    ..CallInput::default()
                },
                credential,
            )
            .await?;
        receipt["ownership"] =
            owned_whole_host_access_application_receipt(input, &collection_response)?;
    }
    let evidence = store.write_evidence(EvidenceClass::LiveRead, &receipt)?;
    Ok((receipt, evidence))
}
