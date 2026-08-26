use super::access_application::access_application_login_methods_contract_supported;
use super::access_application::access_application_login_methods_variant;
use super::access_application::access_application_mutable_body;
use super::access_application::access_application_rollback_idps;
use super::access_application::is_access_application_implicit_open_concurrency_plan;
use super::access_application::normalized_access_application_idps;
use super::access_policy::access_human_policy_prior_state;
use super::access_policy::access_operator_group_policy_restorable_body;
use super::access_policy::is_access_human_policy_mutation;
use super::access_policy::is_access_operator_group_policy_update;
use super::plan_secret::CLOUDFLARE_TUNNEL_CONFIGURATION_MUTATION_CAPABILITY_ID;
use super::plan_secret::CLOUDFLARE_TUNNEL_CONFIGURATION_PATH;
use super::plan_secret::CLOUDFLARE_TUNNEL_CONFIGURATION_READ_CAPABILITY_ID;
use super::plan_secret::D1_DATABASE_CREATE_CAPABILITY_ID;
use super::plan_secret::D1_DATABASE_DELETE_CAPABILITY_ID;
use super::plan_secret::D1_EMPTY_DATABASE_COMPENSATION_STRATEGY;
use super::plan_secret::D1_READ_REPLICATION_PATH;
use super::plan_secret::D1_READ_REPLICATION_READ_CAPABILITY_ID;
use super::plan_secret::DNS_RECORD_DETAIL_PATH;
use super::plan_secret::GLOBAL_WARP_OVERRIDE_MUTATION_CAPABILITY_ID;
use super::plan_secret::GLOBAL_WARP_OVERRIDE_PATH;
use super::plan_secret::GLOBAL_WARP_OVERRIDE_READ_CAPABILITY_ID;
use super::plan_secret::SAME_PATH_PRIOR_STATE_ROLLBACK_STRATEGY;
use super::plan_secret::WARP_CONNECTOR_CONFIGURATION_MUTATION_CAPABILITY_ID;
use super::plan_secret::WARP_CONNECTOR_CONFIGURATION_PATH;
use super::plan_secret::WARP_CONNECTOR_CONFIGURATION_READ_CAPABILITY_ID;
use super::plan_secret::WEB_ANALYTICS_RUM_MUTATION_CAPABILITY_ID;
use super::plan_secret::WEB_ANALYTICS_RUM_PATH;
use super::plan_secret::WEB_ANALYTICS_RUM_READ_CAPABILITY_ID;
use super::prelude::{
    AdapterStatus, BTreeSet, CallInput, CapabilityV1, CliError, CloudflareResponseV1, Result,
    Value, json,
};
use super::r2_credentials::preflight_call_input;

pub(super) fn is_global_warp_override_mutation(capability: &CapabilityV1) -> bool {
    capability.id == GLOBAL_WARP_OVERRIDE_MUTATION_CAPABILITY_ID
}

pub(super) fn should_bind_global_warp_override_state(capability: &CapabilityV1) -> bool {
    is_global_warp_override_mutation(capability)
        && capability.mutating
        && capability.method == "POST"
        && capability.path == GLOBAL_WARP_OVERRIDE_PATH
        && capability.account_scope == "account"
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        && capability.verification.strategy
            == "same_path_result_contains_planned_fields_after_mutation"
        && capability.same_path_read.as_ref().is_some_and(|read| {
            read.path == GLOBAL_WARP_OVERRIDE_PATH
                && read.read_capability_id == GLOBAL_WARP_OVERRIDE_READ_CAPABILITY_ID
                && read.verified_response_fields == ["disconnect"]
        })
}

pub(super) fn global_warp_override_read_contract_supported(capability: &CapabilityV1) -> bool {
    capability.id == GLOBAL_WARP_OVERRIDE_READ_CAPABILITY_ID
        && capability.method == "GET"
        && capability.path == GLOBAL_WARP_OVERRIDE_PATH
        && capability.product == "Devices Resilience"
        && capability.account_scope == "account"
        && !capability.mutating
        && capability.request_schema.is_none()
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        && capability.selectors.len() == 1
        && capability.selectors.iter().any(|selector| {
            selector.name == "account_id" && selector.location == "path" && selector.required
        })
        && capability
            .response_contract
            .as_ref()
            .is_some_and(|contract| {
                matches!(
                    contract.body_mode,
                    cfctl_core::ResponseBodyModeV1::CloudflareJsonEnvelope
                ) && contract.success_statuses == ["200"]
                    && contract.success_media_types == ["application/json"]
            })
}

pub(super) fn is_d1_read_replication_mutation(capability: &CapabilityV1) -> bool {
    matches!(
        capability.id.as_str(),
        "d1-update-database" | "d1-update-partial-database"
    )
}

pub(super) fn should_bind_d1_read_replication_state(capability: &CapabilityV1) -> bool {
    is_d1_read_replication_mutation(capability)
        && capability.mutating
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        && capability.rollback.strategy.as_deref() == Some("restore_d1_read_replication_prior_mode")
        && capability.rollback_contract_supported()
}

pub(super) fn is_d1_database_delete(capability: &CapabilityV1) -> bool {
    capability.id == D1_DATABASE_DELETE_CAPABILITY_ID
        && capability.title == "Delete D1 Database"
        && capability.method == "DELETE"
        && capability.path == D1_READ_REPLICATION_PATH
        && capability.product == "D1"
        && capability.account_scope == "account"
        && capability.mutating
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
}

pub(super) fn should_bind_d1_empty_database_state(
    capability: &CapabilityV1,
    adapter_targets: &Value,
) -> bool {
    is_d1_database_delete(capability)
        && adapter_targets
            .get("compensates_capability_id")
            .and_then(Value::as_str)
            == Some(D1_DATABASE_CREATE_CAPABILITY_ID)
        && adapter_targets
            .get("compensation_strategy")
            .and_then(Value::as_str)
            == Some(D1_EMPTY_DATABASE_COMPENSATION_STRATEGY)
        && adapter_targets
            .get("compensates_operation_id")
            .and_then(Value::as_str)
            .is_some_and(|operation_id| !operation_id.is_empty())
        && adapter_targets
            .get("source_receipt_hash")
            .and_then(Value::as_str)
            .is_some_and(|hash| hash.starts_with("sha256:"))
}

pub(super) fn d1_read_replication_read_contract_supported(capability: &CapabilityV1) -> bool {
    capability.id == D1_READ_REPLICATION_READ_CAPABILITY_ID
        && capability.method == "GET"
        && capability.path == D1_READ_REPLICATION_PATH
        && capability.product == "D1"
        && capability.account_scope == "account"
        && !capability.mutating
        && capability.request_schema.is_none()
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        && capability.selectors.len() == 3
        && ["account_id", "database_id"].iter().all(|name| {
            capability.selectors.iter().any(|selector| {
                selector.name == *name && selector.location == "path" && selector.required
            })
        })
        && capability.selectors.iter().any(|selector| {
            selector.name == "fields"
                && selector.location == "query"
                && !selector.required
                && selector.value_type == "array"
                && selector.contract.as_ref().is_some_and(|contract| {
                    contract.schema.get("type").and_then(Value::as_str) == Some("array")
                        && contract.query.as_ref().is_some_and(|query| {
                            query.style == "form"
                                && !query.explode
                                && !query.allow_reserved
                                && !query.allow_empty_value
                        })
                })
        })
        && capability
            .response_contract
            .as_ref()
            .is_some_and(|contract| {
                matches!(
                    contract.body_mode,
                    cfctl_core::ResponseBodyModeV1::CloudflareJsonEnvelope
                ) && contract.success_statuses == ["200"]
                    && contract.success_media_types == ["application/json"]
            })
}

pub(super) fn is_cloudflare_tunnel_configuration_mutation(capability: &CapabilityV1) -> bool {
    capability.id == CLOUDFLARE_TUNNEL_CONFIGURATION_MUTATION_CAPABILITY_ID
}

pub(super) fn should_bind_cloudflare_tunnel_configuration_state(capability: &CapabilityV1) -> bool {
    is_cloudflare_tunnel_configuration_mutation(capability)
        && capability.mutating
        && capability.method == "PUT"
        && capability.path == CLOUDFLARE_TUNNEL_CONFIGURATION_PATH
        && capability.product == "Cloudflare Tunnel Configuration"
        && capability.account_scope == "account"
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        && capability.rollback.strategy.as_deref()
            == Some("restore_cloudflare_tunnel_configuration_prior_snapshot")
        && capability.rollback_contract_supported()
}

pub(super) fn cloudflare_tunnel_configuration_read_contract_supported(
    capability: &CapabilityV1,
) -> bool {
    capability.id == CLOUDFLARE_TUNNEL_CONFIGURATION_READ_CAPABILITY_ID
        && capability.method == "GET"
        && capability.path == CLOUDFLARE_TUNNEL_CONFIGURATION_PATH
        && capability.product == "Cloudflare Tunnel Configuration"
        && capability.account_scope == "account"
        && !capability.mutating
        && capability.request_schema.is_none()
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        && capability.permissions
            == [
                "Cloudflare One Connectors Write",
                "Cloudflare One Connectors Read",
                "Cloudflare One Connector: cloudflared Write",
                "Cloudflare One Connector: cloudflared Read",
                "Cloudflare Tunnel Write",
                "Cloudflare Tunnel Read",
            ]
        && capability.selectors.len() == 2
        && ["account_id", "tunnel_id"].iter().all(|name| {
            capability.selectors.iter().any(|selector| {
                selector.name == *name && selector.location == "path" && selector.required
            })
        })
        && capability
            .response_contract
            .as_ref()
            .is_some_and(|contract| {
                matches!(
                    contract.body_mode,
                    cfctl_core::ResponseBodyModeV1::CloudflareJsonEnvelope
                ) && contract.success_statuses == ["200"]
                    && contract.success_media_types == ["application/json"]
            })
}

pub(super) fn is_warp_connector_configuration_mutation(capability: &CapabilityV1) -> bool {
    capability.id == WARP_CONNECTOR_CONFIGURATION_MUTATION_CAPABILITY_ID
}

pub(super) fn should_bind_warp_connector_configuration_state(capability: &CapabilityV1) -> bool {
    is_warp_connector_configuration_mutation(capability)
        && capability.mutating
        && capability.method == "PUT"
        && capability.path == WARP_CONNECTOR_CONFIGURATION_PATH
        && capability.product == "Cloudflare Tunnel Configuration"
        && capability.account_scope == "account"
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        && capability.rollback.strategy.as_deref()
            == Some("restore_warp_connector_configuration_prior_snapshot")
        && capability.rollback_contract_supported()
}

pub(super) fn warp_connector_configuration_read_contract_supported(
    capability: &CapabilityV1,
) -> bool {
    capability.id == WARP_CONNECTOR_CONFIGURATION_READ_CAPABILITY_ID
        && capability.method == "GET"
        && capability.path == WARP_CONNECTOR_CONFIGURATION_PATH
        && capability.product == "Cloudflare Tunnel Configuration"
        && capability.account_scope == "account"
        && !capability.mutating
        && capability.request_schema.is_none()
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        && capability.permissions
            == [
                "Cloudflare One Connectors Write",
                "Cloudflare One Connectors Read",
                "Cloudflare One Connector: WARP Write",
                "Cloudflare One Connector: WARP Read",
            ]
        && capability.selectors.len() == 2
        && ["account_id", "tunnel_id"].iter().all(|name| {
            capability.selectors.iter().any(|selector| {
                selector.name == *name && selector.location == "path" && selector.required
            })
        })
        && capability
            .response_contract
            .as_ref()
            .is_some_and(|contract| {
                matches!(
                    contract.body_mode,
                    cfctl_core::ResponseBodyModeV1::CloudflareJsonEnvelope
                ) && contract.success_statuses == ["200"]
                    && contract.success_media_types == ["application/json"]
            })
}

pub(super) fn is_web_analytics_rum_mutation(capability: &CapabilityV1) -> bool {
    capability.id == WEB_ANALYTICS_RUM_MUTATION_CAPABILITY_ID
}

pub(super) fn should_bind_web_analytics_rum_state(capability: &CapabilityV1) -> bool {
    is_web_analytics_rum_mutation(capability)
        && capability.mutating
        && capability.method == "PATCH"
        && capability.path == WEB_ANALYTICS_RUM_PATH
        && capability.product == "Web Analytics"
        && capability.account_scope == "zone"
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        && capability.rollback.strategy.as_deref() == Some("restore_web_analytics_rum_prior_value")
        && capability.rollback_contract_supported()
}

pub(super) fn web_analytics_rum_read_contract_supported(capability: &CapabilityV1) -> bool {
    capability.id == WEB_ANALYTICS_RUM_READ_CAPABILITY_ID
        && capability.method == "GET"
        && capability.path == WEB_ANALYTICS_RUM_PATH
        && capability.product == "Web Analytics"
        && capability.account_scope == "zone"
        && !capability.mutating
        && capability.request_schema.is_none()
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        && capability.permissions == ["Zone Settings Write", "Zone Settings Read"]
        && capability.selectors.len() == 1
        && capability.selectors.iter().any(|selector| {
            selector.name == "zone_id"
                && selector.location == "path"
                && selector.required
                && selector.value_type == "string"
        })
        && capability
            .response_contract
            .as_ref()
            .is_some_and(|contract| {
                matches!(
                    contract.body_mode,
                    cfctl_core::ResponseBodyModeV1::CloudflareJsonEnvelope
                ) && contract.success_statuses == ["200"]
                    && contract.success_media_types == ["application/json"]
            })
}

pub(super) fn is_dns_record_update_mutation(capability: &CapabilityV1) -> bool {
    matches!(
        (capability.id.as_str(), capability.method.as_str()),
        ("dns-records-for-a-zone-update-dns-record", "PUT")
            | ("dns-records-for-a-zone-patch-dns-record", "PATCH")
    )
}

pub(super) fn should_bind_dns_record_state(capability: &CapabilityV1) -> bool {
    is_dns_record_update_mutation(capability)
        && capability.mutating
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        && capability.rollback.strategy.as_deref()
            == Some("restore_dns_record_prior_snapshot_with_put")
        && capability.rollback_contract_supported()
        && dns_record_routing_contract_supported(capability)
}

pub(super) fn dns_record_routing_contract_supported(capability: &CapabilityV1) -> bool {
    capability.path == DNS_RECORD_DETAIL_PATH
        && capability.account_scope == "zone"
        && capability.selectors.len() == 3
        && ["zone_id", "dns_record_id"].iter().all(|name| {
            capability.selectors.iter().any(|selector| {
                selector.name == *name && selector.location == "path" && selector.required
            })
        })
        && capability.selectors.iter().any(|selector| {
            selector.name == "include_shadow_metadata"
                && selector.location == "query"
                && !selector.required
                && selector.value_type == "boolean"
                && selector.contract.as_ref().is_some_and(|contract| {
                    contract.schema.get("type").and_then(Value::as_str) == Some("boolean")
                        && contract.query.as_ref().is_some_and(|query| {
                            query.style == "form"
                                && query.explode
                                && !query.allow_reserved
                                && !query.allow_empty_value
                        })
                })
        })
}

pub(super) fn should_bind_same_path_prior_state(capability: &CapabilityV1) -> bool {
    capability.mutating
        && matches!(capability.method.as_str(), "PATCH" | "PUT")
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        && capability.rollback.strategy.as_deref() == Some(SAME_PATH_PRIOR_STATE_ROLLBACK_STRATEGY)
        && capability.rollback_contract_supported()
}

pub(super) fn requires_same_path_state_precondition(capability: &CapabilityV1) -> bool {
    should_bind_same_path_prior_state(capability)
        || is_access_application_implicit_open_concurrency_plan(capability)
}

pub(super) fn same_path_read_source_contract_supported(
    capability: &CapabilityV1,
    source: &CapabilityV1,
) -> bool {
    let Some(target) = capability.same_path_read.as_ref() else {
        return false;
    };
    if source.id != target.read_capability_id
        || source.method != "GET"
        || source.path != target.path
        || source.mutating
        || !matches!(
            source.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        || source.request_schema.is_some()
        || source.response_contract.as_ref().is_none_or(|contract| {
            contract.body_mode != cfctl_core::ResponseBodyModeV1::CloudflareJsonEnvelope
                || contract.success_statuses != ["200"]
                || contract.success_media_types != ["application/json"]
        })
    {
        return false;
    }
    let mutation_paths = capability
        .selectors
        .iter()
        .filter(|selector| selector.location == "path" && selector.required)
        .map(|selector| selector.name.as_str())
        .collect::<BTreeSet<_>>();
    let source_paths = source
        .selectors
        .iter()
        .filter(|selector| selector.location == "path" && selector.required)
        .map(|selector| selector.name.as_str())
        .collect::<BTreeSet<_>>();
    mutation_paths == source_paths
        && source
            .selectors
            .iter()
            .all(|selector| selector.location == "path" || !selector.required)
}

pub(super) fn same_path_prior_state_fields(
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<Vec<String>> {
    let target = capability.same_path_read.as_ref().ok_or_else(|| {
        CliError::Input(
            "same-path prior-state mutation omitted its hash-bound readback contract".to_owned(),
        )
    })?;
    let planned = input
        .body
        .as_ref()
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CliError::Input(
                "same-path prior-state mutation requires a validated object body".to_owned(),
            )
        })?;
    let mut fields = planned
        .keys()
        .filter(|field| !capability.request_object_field_is_verification_omitted(field))
        .cloned()
        .collect::<Vec<_>>();
    fields.sort();
    if fields.is_empty()
        || fields.iter().any(|field| {
            target
                .verified_response_fields
                .binary_search(field)
                .is_err()
        })
    {
        return Err(CliError::Input(
            "same-path prior-state mutation has no fully observable planned fields".to_owned(),
        ));
    }
    Ok(fields)
}

#[expect(
    clippy::too_many_lines,
    reason = "the Access application and policy snapshot variants remain visible in one prior-state projection boundary"
)]
pub(super) fn project_same_path_prior_state(
    capability: &CapabilityV1,
    input: &CallInput,
    result: &Value,
) -> Result<Value> {
    if is_access_operator_group_policy_update(capability) {
        let policy_id = input
            .selectors
            .get("policy_id")
            .and_then(Value::as_str)
            .filter(|policy_id| !policy_id.is_empty())
            .ok_or_else(|| {
                CliError::Input(
                    "operator-group Access policy prior-state read omitted its exact policy selector"
                        .to_owned(),
                )
            })?;
        if result.get("id").and_then(Value::as_str) != Some(policy_id) {
            return Err(CliError::Input(
                "operator-group Access policy prior-state read returned a different policy id; the mutation boundary was not crossed"
                    .to_owned(),
            ));
        }
        let prior = access_operator_group_policy_restorable_body(result)?;
        let mut restore_input = input.clone();
        restore_input.query = json!({});
        restore_input.body = Some(prior.clone());
        preflight_call_input(capability, &restore_input, None).map_err(|error| {
            CliError::Input(format!(
                "live operator-group Access policy is outside the exact restorable request contract; the mutation boundary was not crossed: {error}"
            ))
        })?;
        return Ok(prior);
    }
    if is_access_human_policy_mutation(capability) {
        let policy_id = input
            .selectors
            .get("policy_id")
            .and_then(Value::as_str)
            .filter(|policy_id| !policy_id.is_empty())
            .ok_or_else(|| {
                CliError::Input(
                    "human Access policy prior-state read omitted its exact policy selector"
                        .to_owned(),
                )
            })?;
        if result.get("id").and_then(Value::as_str) != Some(policy_id) {
            return Err(CliError::Input(
                "human Access policy prior-state read returned a different or missing policy id; the mutation boundary was not crossed"
                    .to_owned(),
            ));
        }
        let prior = access_human_policy_prior_state(result)?;
        let mut restore_input = input.clone();
        restore_input.query = json!({});
        restore_input.body = Some(prior.clone());
        preflight_call_input(capability, &restore_input, None).map_err(|error| {
            CliError::Input(format!(
                "live human Access policy is outside the exact restorable request contract; the mutation boundary was not crossed: {error}"
            ))
        })?;
        return Ok(prior);
    }
    if access_application_login_methods_contract_supported(capability) {
        let app_id = input
            .selectors
            .get("app_id")
            .and_then(Value::as_str)
            .filter(|app_id| !app_id.is_empty())
            .ok_or_else(|| {
                CliError::Input(
                    "Access application prior-state read omitted its exact app selector".to_owned(),
                )
            })?;
        let variant =
            access_application_login_methods_variant(&capability.id).ok_or_else(|| {
                CliError::Input(
                    "Access application prior-state contract omitted its exact application variant"
                        .to_owned(),
                )
            })?;
        if result.get("id").and_then(Value::as_str) != Some(app_id)
            || result.get("type").and_then(Value::as_str) != Some(variant.app_type)
        {
            return Err(CliError::Input(format!(
                "Access application prior-state read returned a different app or a non-{} app; the mutation boundary was not crossed",
                variant.app_type
            )));
        }
        let concurrency_only = is_access_application_implicit_open_concurrency_plan(capability);
        let current_idps = if concurrency_only {
            normalized_access_application_idps(result.get("allowed_idps").unwrap_or(&Value::Null))?
        } else {
            access_application_rollback_idps(result.get("allowed_idps").unwrap_or(&Value::Null))?
        };
        let prior = access_application_mutable_body(result, &current_idps, variant)?;
        if concurrency_only && current_idps.is_empty() {
            return Ok(prior);
        }
        let mut restore_input = input.clone();
        restore_input.query = json!({});
        restore_input.body = Some(prior.clone());
        preflight_call_input(capability, &restore_input, None).map_err(|error| {
            CliError::Input(format!(
                "live Access application is outside the exact restorable request contract; the mutation boundary was not crossed: {error}"
            ))
        })?;
        return Ok(prior);
    }
    let normalized_result = normalize_same_path_prior_state(&capability.id, result.clone());
    let mut prior = serde_json::Map::new();
    for field in same_path_prior_state_fields(capability, input)? {
        let response_field = capability
            .request_object_field_verification_response_field(&field)
            .unwrap_or_else(|| field.clone());
        let value = normalized_result.get(&response_field).cloned().ok_or_else(|| {
            CliError::Input(format!(
                "same-path state read omitted restorable field `{response_field}`; the mutation boundary was not crossed"
            ))
        })?;
        prior.insert(field, value);
    }
    let prior = Value::Object(prior);
    let mut restore_input = input.clone();
    restore_input.query = json!({});
    restore_input.body = Some(prior.clone());
    preflight_call_input(capability, &restore_input, None).map_err(|error| {
        CliError::Input(format!(
            "live same-path state is outside the exact restorable request contract; the mutation boundary was not crossed: {error}"
        ))
    })?;
    Ok(prior)
}

pub(super) fn normalize_same_path_prior_state(capability_id: &str, mut result: Value) -> Value {
    if capability_id != "r2-put-bucket-lifecycle-configuration" {
        return result;
    }
    let Some(rules) = result.get_mut("rules").and_then(Value::as_array_mut) else {
        return result;
    };
    for rule in rules {
        let is_provider_default = rule.as_object().is_some_and(|rule| {
            rule.len() == 4
                && rule.get("id").and_then(Value::as_str) == Some("Default Multipart Abort Rule")
                && rule.get("enabled").and_then(Value::as_bool) == Some(true)
                && rule
                    .get("conditions")
                    .and_then(Value::as_object)
                    .is_some_and(serde_json::Map::is_empty)
                && rule
                    .get("abortMultipartUploadsTransition")
                    .and_then(|transition| transition.pointer("/condition/maxAge"))
                    == Some(&json!(604_800))
        });
        if !is_provider_default {
            continue;
        }
        let Some(conditions) = rule.get_mut("conditions").and_then(Value::as_object_mut) else {
            continue;
        };
        conditions
            .entry("prefix".to_owned())
            .or_insert_with(|| Value::String(String::new()));
    }
    result
}

pub(super) fn apply_same_path_prior_state_response(
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    response: &CloudflareResponseV1,
) -> Result<Value> {
    if !response.success || !(200..300).contains(&response.status) {
        return Err(CliError::Input(format!(
            "Cloudflare rejected the same-path state read with HTTP {}; the mutation boundary was not crossed",
            response.status
        )));
    }
    let target = capability.same_path_read.as_ref().ok_or_else(|| {
        CliError::Input(
            "same-path prior-state mutation omitted its hash-bound readback contract".to_owned(),
        )
    })?;
    let prior_state = project_same_path_prior_state(capability, input, &response.result)?;
    Ok(json!({
        "schema_version": 1,
        "source_capability_id": target.read_capability_id,
        "source_path": target.path,
        "target_capability_id": capability.id,
        "target_method": capability.method,
        "target_path": capability.path,
        "target_scope": capability.account_scope,
        "account_id": account_id,
        "selectors": input.selectors,
        "prior_state": prior_state,
    }))
}
