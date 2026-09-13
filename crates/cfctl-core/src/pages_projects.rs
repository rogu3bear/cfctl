//! Closed Pages setup contracts shared by discovery, admission and verification.
mod configuration;
use crate::{AdapterStatus, CapabilityV1, EffectClass, ResponseBodyModeV1, RiskClass, hash_value};
pub use configuration::configuration_metadata;
use serde_json::{Map, Value, json};

pub const CREATE_ID: &str = "pages-project-create-direct-upload";
pub const VARIABLES_ID: &str = "pages-project-add-production-variables";
pub const READ_ID: &str = "pages-project-get-project";
pub const DELETE_ID: &str = "pages-project-delete-project";
pub const COLLECTION: &str = "/accounts/{account_id}/pages/projects";
pub const DETAIL: &str = "/accounts/{account_id}/pages/projects/{project_name}";
pub const CREATE_STRATEGY: &str = "pages_direct_project_matches_returned_identity_without_git";
pub const VARIABLES_STRATEGY: &str =
    "pages_production_variables_added_with_preserved_configuration";

#[must_use]
pub fn create_schema() -> Value {
    json!({
        "type":"object", "additionalProperties":false, "x-cfctl-body-required":true,
        "required":["name","production_branch"],
        "properties":{
            "name":{"type":"string","minLength":1,"maxLength":58},
            "production_branch":{"type":"string","enum":["main"]}
        }
    })
}

#[must_use]
pub fn variables_schema() -> Value {
    json!({
        "type":"object", "additionalProperties":false, "x-cfctl-body-required":true,
        "required":["deployment_configs"], "properties":{"deployment_configs":{
            "type":"object", "writeOnly":true, "additionalProperties":false,
            "required":["production"], "properties":{"production":{
                "type":"object", "additionalProperties":false,
                "required":["env_vars"], "properties":{"env_vars":{
                    "type":"object", "minProperties":1, "maxProperties":100,
                    "additionalProperties":{
                        "type":"object", "additionalProperties":false,
                        "required":["type","value"], "properties":{
                            "type":{"type":"string","enum":["plain_text","secret_text"]},
                            "value":{"type":"string","minLength":1,"maxLength":5120,"writeOnly":true}
                        }
                    }
                }}
            }}
        }}
    })
}

#[must_use]
pub fn contract_supported(capability: &CapabilityV1) -> bool {
    let common = capability.mutating
        && capability.product == "Pages Project"
        && capability.account_scope == "account"
        && capability.permissions == ["Pages Write"]
        && capability.effect == EffectClass::ReversibleWrite
        && matches!(
            capability.adapter_status,
            AdapterStatus::DynamicApi | AdapterStatus::Native
        )
        && capability
            .response_contract
            .as_ref()
            .is_some_and(|response| {
                response.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
                    && response.success_media_types == ["application/json"]
                    && !response.success_statuses.is_empty()
            })
        && capability.selectors.iter().all(|selector| {
            selector.location == "path"
                && selector.required
                && matches!(selector.name.as_str(), "account_id" | "project_name")
        })
        && capability
            .selectors
            .iter()
            .any(|selector| selector.name == "account_id");
    if !common {
        return false;
    }
    match capability.id.as_str() {
        CREATE_ID => {
            capability.method == "POST"
                && capability.path == COLLECTION
                && capability.selectors.len() == 1
                && capability.risk == RiskClass::CrossConfig
                && capability.request_schema == Some(create_schema())
                && capability.verification.strategy == CREATE_STRATEGY
                && capability.created_resource.as_ref().is_some_and(|target| {
                    target.detail_path == DETAIL
                        && target.identity_selector == "project_name"
                        && target.response_result_identity_pointer == "/name"
                        && target.read_capability_id == READ_ID
                        && target.delete_capability_id == DELETE_ID
                        && target.verified_response_fields == ["name", "production_branch"]
                })
        }
        VARIABLES_ID => {
            capability.method == "PATCH"
                && capability.path == DETAIL
                && capability.selectors.len() == 2
                && capability
                    .selectors
                    .iter()
                    .any(|selector| selector.name == "project_name")
                && capability.risk == RiskClass::SecretSensitive
                && capability.request_schema == Some(variables_schema())
                && capability.verification.strategy == VARIABLES_STRATEGY
                && capability.same_path_read.as_ref().is_some_and(|target| {
                    target.path == DETAIL
                        && target.read_capability_id == READ_ID
                        && target.verified_response_fields == ["deployment_configs"]
                })
        }
        _ => false,
    }
}

#[must_use]
pub fn valid_project_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 58
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-')
}

#[must_use]
pub fn valid_variable_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && name.bytes().enumerate().all(|(index, byte)| {
            byte == b'_' || byte.is_ascii_alphabetic() || (index > 0 && byte.is_ascii_digit())
        })
}

#[must_use]
pub fn requested_variables(body: &Value) -> Option<&Map<String, Value>> {
    body.pointer("/deployment_configs/production/env_vars")?
        .as_object()
}

/// A source-less initial project must also have no executable Git build setup.
#[must_use]
pub fn project_is_direct(project: &Value, name: &str) -> bool {
    project.get("name").and_then(Value::as_str) == Some(name)
        && project
            .get("id")
            .and_then(Value::as_str)
            .is_some_and(|id| !id.is_empty())
        && project.get("production_branch").and_then(Value::as_str) == Some("main")
        && project.get("source").is_none_or(Value::is_null)
        && project.get("build_config").is_none_or(|build| {
            build.is_null()
                || build.as_object().is_some_and(|fields| {
                    fields.iter().all(|(key, value)| {
                        matches!(
                            key.as_str(),
                            "build_command"
                                | "destination_dir"
                                | "root_dir"
                                | "build_caching"
                                | "web_analytics_tag"
                                | "web_analytics_token"
                        ) && (value.is_null()
                            || value.as_str() == Some("")
                            || value.as_bool() == Some(false))
                    })
                })
        })
}

/// Commit to configuration without persisting any variable values. The verifier
/// removes only the newly admitted names before checking sibling preservation.
pub fn configuration_hash(project: &Value, added_names: &[String]) -> crate::Result<String> {
    let mut fields = Map::new();
    for key in [
        "id",
        "name",
        "production_branch",
        "source",
        "build_config",
        "deployment_configs",
    ] {
        fields.insert(
            key.to_owned(),
            project.get(key).cloned().unwrap_or(Value::Null),
        );
    }
    let mut snapshot = Value::Object(fields);
    if let Some(production) = snapshot
        .pointer_mut("/deployment_configs/production")
        .and_then(Value::as_object_mut)
    {
        production.entry("env_vars").or_insert_with(|| json!({}));
    }
    if let Some(vars) = snapshot
        .pointer_mut("/deployment_configs/production/env_vars")
        .and_then(Value::as_object_mut)
    {
        for name in added_names {
            vars.remove(name);
        }
    }
    hash_value(&snapshot)
}

/// Pages may include environment values in successful or malformed responses.
/// Error prose is never trustworthy as a secret-safe projection.
#[must_use]
pub fn redact_response(value: &Value) -> Value {
    if let Some(object) = value.as_object()
        && object.contains_key("success")
        && object.get("success") != Some(&Value::Bool(true))
    {
        let mut response = Map::new();
        for key in ["status", "success", "etag", "cf_ray"] {
            if let Some(value) = object.get(key) {
                response.insert(key.to_owned(), value.clone());
            }
        }
        response.insert("result".to_owned(), Value::Null);
        response.insert("result_info".to_owned(), Value::Null);
        response.insert(
            "errors".to_owned(),
            redacted_errors(object.get("errors").unwrap_or(&Value::Null)),
        );
        return Value::Object(response);
    }
    match value {
        Value::Object(object) => {
            let mut output = Map::new();
            for (key, value) in object {
                if key == "web_analytics_token" {
                    continue;
                }
                let projected = match key.as_str() {
                    "env_vars" => environment_metadata(value),
                    "value" => Value::String("[REDACTED]".to_owned()),
                    "errors" | "messages" => redacted_errors(value),
                    _ => redact_response(value),
                };
                output.insert(key.clone(), projected);
            }
            Value::Object(output)
        }
        Value::Array(values) => Value::Array(values.iter().map(redact_response).collect()),
        _ => value.clone(),
    }
}

fn environment_metadata(value: &Value) -> Value {
    if let Some(entries) = value.as_array()
        && entries.iter().all(|entry| {
            entry.as_object().is_some_and(|fields| fields.len() == 2)
                && entry["name"]
                    .as_str()
                    .is_some_and(|name| valid_variable_name(name) || name == "[UNRECOGNIZED]")
                && (entry["type"].is_null()
                    || matches!(entry["type"].as_str(), Some("plain_text" | "secret_text")))
        })
    {
        return value.clone();
    }
    let Some(variables) = value.as_object() else {
        return Value::String("[REDACTED]".to_owned());
    };
    Value::Array(variables.iter().map(|(name, entry)| {
        let kind = entry.get("type").and_then(Value::as_str)
            .filter(|kind| matches!(*kind,"plain_text" | "secret_text"));
        json!({"name":if valid_variable_name(name) { name.as_str() } else { "[UNRECOGNIZED]" },"type":kind})
    }).collect())
}

fn redacted_errors(value: &Value) -> Value {
    Value::Array(value.as_array().into_iter().flatten().map(|entry| {
        json!({"code":entry.get("code").filter(|code| code.is_number()),"message":"[REDACTED]"})
    }).collect())
}
