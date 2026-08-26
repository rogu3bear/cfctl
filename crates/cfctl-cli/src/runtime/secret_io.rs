use super::oauth_state::is_oauth_client_create_operation_identity;
use super::prelude::fs;
use super::prelude::{
    CallInput, CapabilityV1, CliError, PathBuf, PermissionsExt, PlanV1, Result, RiskClass,
    SecretStore, Value, Write, json,
};
use super::r2_credentials::is_r2_temporary_credentials_operation_identity;
use super::support::cli_io;
use super::worker_deployment;
use cfctl_core::hash_value;

pub(super) fn preflight_secret_sink(plan: &PlanV1) -> Result<()> {
    if !is_secret_output_plan(plan) {
        return Ok(());
    }
    let path = secret_sink_path(plan)?;
    if path.exists() {
        return Err(CliError::Input(format!(
            "secret sink already exists and will not be overwritten: {}",
            path.display()
        )));
    }
    let parent = path
        .parent()
        .ok_or_else(|| CliError::Input("secret sink has no parent directory".to_owned()))?;
    if !is_oauth_client_create_operation_identity(&plan.capability) {
        return fs::create_dir_all(parent).map_err(|source| cli_io(parent, source));
    }
    if !path.is_absolute() {
        return Err(CliError::Input(
            "OAuth client --value-out must be an absolute path under a pre-existing mode-0700 operator-secret directory outside every Git repository"
                .to_owned(),
        ));
    }
    let canonical_parent = fs::canonicalize(parent).map_err(|source| cli_io(parent, source))?;
    if canonical_parent
        .ancestors()
        .any(|ancestor| ancestor.join(".git").exists())
    {
        return Err(CliError::Input(
            "OAuth client secret output is forbidden inside a Git repository".to_owned(),
        ));
    }
    let metadata =
        fs::metadata(&canonical_parent).map_err(|source| cli_io(&canonical_parent, source))?;
    if !metadata.is_dir() {
        return Err(CliError::Input(
            "OAuth client secret output parent is not a directory".to_owned(),
        ));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(CliError::Input(format!(
            "OAuth client secret output parent {} must have mode 0700",
            canonical_parent.display()
        )));
    }
    #[cfg(not(unix))]
    return Err(CliError::Input(
        "OAuth client creation requires a platform where cfctl can prove a mode-0700 operator-secret directory"
            .to_owned(),
    ));
    #[cfg(unix)]
    Ok(())
}

pub(super) fn resolved_plan_input(plan: &PlanV1, secrets: &dyn SecretStore) -> Result<CallInput> {
    let mut input: CallInput = serde_json::from_value(plan.input.clone())?;
    let Some(reference) = plan_secret_body_ref(plan) else {
        return Ok(input);
    };
    let encoded = secrets.get(reference)?.ok_or_else(|| {
        CliError::Input(
            "the plan's secret request body is missing from the platform credential store"
                .to_owned(),
        )
    })?;
    let body: Value = serde_json::from_str(&encoded)?;
    let expected_hash = plan
        .targets
        .pointer("/adapter/secret_body_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input("secret request body hash is missing from the plan".to_owned())
        })?;
    if hash_value(&body)? != expected_hash {
        return Err(CliError::Input(
            "the secret request body drifted after planning; approval is invalid".to_owned(),
        ));
    }
    input.body = Some(body);
    Ok(input)
}

pub(super) fn plan_secret_body_ref(plan: &PlanV1) -> Option<&str> {
    plan.targets
        .pointer("/adapter/secret_body_ref")
        .and_then(Value::as_str)
}

pub(super) fn sink_secret_result(plan: &PlanV1, result: &Value) -> Result<PathBuf> {
    let payload = secret_sink_payload(&plan.capability, result)?;
    let path = secret_sink_path(plan)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&path)
        .map_err(|source| cli_io(&path, source))?;
    file.write_all(&payload)
        .map_err(|source| cli_io(&path, source))?;
    file.sync_all().map_err(|source| cli_io(&path, source))?;
    Ok(path)
}

pub(super) fn secret_sink_payload(capability: &CapabilityV1, result: &Value) -> Result<Vec<u8>> {
    if is_worker_tail_create_capability(capability) {
        let required = |field: &'static str| {
            result
                .get(field)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    CliError::Input(format!(
                        "Cloudflare reported Worker tail creation success without non-empty `{field}`; no lease sink was created and the operation requires rectification"
                    ))
                })
        };
        return Ok(serde_json::to_vec(&json!({
            "expires_at": required("expires_at")?,
            "id": required("id")?,
            "url": required("url")?,
        }))?);
    }
    if is_r2_temporary_credentials_operation_identity(capability) {
        let required = |field: &'static str| {
            result
                .get(field)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    CliError::Input(format!(
                        "Cloudflare reported R2 temporary-credential success without non-empty `{field}`; no credential sink was created and the operation requires rectification"
                    ))
                })
        };
        let access_key_id = required("accessKeyId")?;
        let secret_access_key = required("secretAccessKey")?;
        let session_token = required("sessionToken")?;
        return Ok(serde_json::to_vec(&json!({
            "accessKeyId": access_key_id,
            "secretAccessKey": secret_access_key,
            "sessionToken": session_token,
        }))?);
    }
    if is_access_service_token_create_capability(capability) {
        let client_id = result
            .get("client_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                CliError::Input(
                    "Cloudflare reported Access service-token creation success without a non-empty client_id; no credential sink was created and the operation requires rectification"
                        .to_owned(),
                )
            })?;
        let client_secret = result
            .get("client_secret")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                CliError::Input(
                    "Cloudflare reported Access service-token creation success without a non-empty client_secret; no credential sink was created and the operation requires rectification"
                        .to_owned(),
                )
            })?;
        return Ok(serde_json::to_vec(&json!({
            "client_id": client_id,
            "client_secret": client_secret,
        }))?);
    }
    if is_oauth_client_create_operation_identity(capability) {
        let client_id = result
            .get("client_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                CliError::Input(
                    "Cloudflare reported OAuth client creation success without a non-empty client_id; no credential sink was created and the operation requires rectification"
                        .to_owned(),
                )
            })?;
        let client_secret = result
            .get("client_secret")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                CliError::Input(
                    "Cloudflare omitted the required OAuth client secret; no credential sink was created and the operation requires rectification"
                        .to_owned(),
                )
            })?;
        return Ok(serde_json::to_vec(&json!({
            "client_id":client_id,
            "client_secret":client_secret,
        }))?);
    }

    let Some(secret) = find_secret_value(result) else {
        return Err(CliError::Input(
            "Cloudflare reported success but no one-time credential value was present; the operation requires rectification"
                .to_owned(),
        ));
    };
    Ok(secret.as_bytes().to_vec())
}

pub(super) fn is_access_service_token_create_capability(capability: &CapabilityV1) -> bool {
    let exact_operation = matches!(
        (
            capability.id.as_str(),
            capability.path.as_str(),
            capability.product.as_str(),
            capability.account_scope.as_str(),
        ),
        (
            "access-service-tokens-create-a-service-token",
            "/accounts/{account_id}/access/service_tokens",
            "Access service tokens",
            "account",
        ) | (
            "zone-level-access-service-tokens-create-a-service-token",
            "/zones/{zone_id}/access/service_tokens",
            "Zone-Level Access service tokens",
            "zone",
        )
    );
    exact_operation
        && capability.method == "POST"
        && capability.permissions == ["Access: Service Tokens Write"]
}

pub(super) fn secret_sink_format(capability: &CapabilityV1) -> Option<&'static str> {
    if !is_secret_output_capability(capability) {
        None
    } else if is_worker_tail_create_capability(capability) {
        Some("worker_tail_lease_json")
    } else if is_r2_temporary_credentials_operation_identity(capability) {
        Some("r2_temporary_credentials_json")
    } else if is_access_service_token_create_capability(capability) {
        Some("access_service_token_json")
    } else if is_oauth_client_create_operation_identity(capability) {
        Some("oauth_client_json")
    } else {
        Some("opaque_text")
    }
}

pub(super) fn secret_sink_path(plan: &PlanV1) -> Result<PathBuf> {
    plan.targets
        .pointer("/adapter/value_out")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| CliError::Input("secret-producing plan has no value_out sink".to_owned()))
}

pub(super) fn is_secret_output_plan(plan: &PlanV1) -> bool {
    is_secret_output_capability(&plan.capability)
}

pub(super) fn is_secret_output_capability(capability: &CapabilityV1) -> bool {
    (capability.risk == RiskClass::SecretSensitive
        && !is_worker_script_secret_input_only_capability(capability))
        || is_access_service_token_create_capability(capability)
        || is_r2_temporary_credentials_operation_identity(capability)
        || is_oauth_client_create_operation_identity(capability)
}

pub(super) fn should_redact_secret_response(capability: &CapabilityV1) -> bool {
    capability.risk == RiskClass::SecretSensitive
        || is_access_service_token_create_capability(capability)
        || is_r2_temporary_credentials_operation_identity(capability)
        || is_oauth_client_create_operation_identity(capability)
}

pub(super) fn is_worker_tail_create_capability(capability: &CapabilityV1) -> bool {
    capability.id == "worker-tail-logs-start-tail"
        && capability.method == "POST"
        && capability.path == "/accounts/{account_id}/workers/scripts/{script_name}/tails"
        && capability.product == "Worker Tail Logs"
        && capability.account_scope == "account"
        && capability.permissions == ["Workers Tail Read", "Workers Scripts Write"]
        && capability.verification.strategy == "worker_tail_collection_contains_created_lease_id"
}

pub(super) fn is_worker_tail_response_capability(capability: &CapabilityV1) -> bool {
    is_worker_tail_create_capability(capability)
        || (capability.id == "worker-tail-logs-list-tails"
            && capability.method == "GET"
            && capability.path == "/accounts/{account_id}/workers/scripts/{script_name}/tails"
            && capability.product == "Worker Tail Logs"
            && capability.account_scope == "account"
            && capability.permissions == ["Workers Tail Read"])
}

pub(super) fn is_worker_script_secret_input_only_capability(capability: &CapabilityV1) -> bool {
    capability.id == "worker-put-script-secret"
        && capability.method == "PUT"
        && capability.path == "/accounts/{account_id}/workers/scripts/{script_name}/secrets"
        && capability.product == "Worker Script"
        && capability.permissions == ["Workers Scripts Write"]
        && capability.verification.strategy
            == "worker_script_secret_reports_planned_name_and_type_after_put"
        && capability.request_object_field_is_write_only("text")
        && capability.request_object_field_is_write_only("key_base64")
        && capability.request_object_field_is_write_only("key_jwk")
}

pub(super) fn find_secret_value(value: &Value) -> Option<&str> {
    if let Some(value) = value.as_str() {
        return Some(value);
    }
    if let Some(object) = value.as_object() {
        for key in cfctl_core::SECRET_SINK_VALUE_KEYS.iter().copied() {
            if let Some(candidate) = object.get(key) {
                if let Some(value) = candidate.as_str() {
                    return Some(value);
                }
                if (candidate.is_object() || candidate.is_array())
                    && let Some(value) = find_secret_value(candidate)
                {
                    return Some(value);
                }
            }
        }
        return object
            .values()
            .filter(|candidate| candidate.is_object() || candidate.is_array())
            .find_map(find_secret_value);
    }
    value.as_array()?.iter().find_map(find_secret_value)
}

pub(super) fn redact_secret_result(value: &Value) -> Value {
    if let Value::Object(object) = value {
        let mut redacted = object.clone();
        if let Some(result) = object.get("result") {
            redacted.insert("result".to_owned(), redact_secret_payload(result, true));
        }
        return Value::Object(redacted);
    }
    redact_secret_payload(value, true)
}

pub(super) fn redact_response_for_capability(capability: &CapabilityV1, value: &Value) -> Value {
    if capability.id == worker_deployment::ROLLBACK_CAPABILITY_ID {
        let error_codes = value
            .get("errors")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|error| error.get("code").cloned())
            .collect::<Vec<_>>();
        return json!({
            "status":value.get("status").cloned().unwrap_or(Value::Null),
            "success":value.get("success").cloned().unwrap_or(Value::Bool(false)),
            "result":{
                "id":value.pointer("/result/id").cloned().unwrap_or(Value::Null),
                "provider_output_retained":false,
            },
            "error_codes":error_codes,
            "etag":value.get("etag").cloned().unwrap_or(Value::Null),
            "cf_ray":value.get("cf_ray").cloned().unwrap_or(Value::Null),
        });
    }
    let redacted = if should_redact_secret_response(capability) {
        redact_secret_result(value)
    } else {
        value.clone()
    };
    if is_worker_tail_response_capability(capability) {
        redact_field_recursively(&redacted, "url")
    } else {
        redacted
    }
}

pub(super) fn redact_field_recursively(value: &Value, field: &str) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, item)| {
                    if key == field {
                        (key.clone(), Value::String("[SUNK]".to_owned()))
                    } else {
                        (key.clone(), redact_field_recursively(item, field))
                    }
                })
                .collect(),
        ),
        Value::Array(values) => Value::Array(
            values
                .iter()
                .map(|item| redact_field_recursively(item, field))
                .collect(),
        ),
        _ => value.clone(),
    }
}

pub(super) fn redact_secret_payload(value: &Value, root: bool) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, item)| {
                    // Single-sourced against `cfctl_core::SECRET_FIELD_NAMES`;
                    // the `secret_payload_redaction_mirrors_the_core_set` test
                    // binds the two so this arm set cannot drift.
                    if cfctl_core::SECRET_FIELD_NAMES.contains(&key.as_str()) {
                        (key.clone(), Value::String("[SUNK]".to_owned()))
                    } else {
                        (key.clone(), redact_secret_payload(item, false))
                    }
                })
                .collect(),
        ),
        Value::Array(values) => Value::Array(
            values
                .iter()
                .map(|item| redact_secret_payload(item, true))
                .collect(),
        ),
        Value::String(_) if root => Value::String("[SUNK]".to_owned()),
        _ => value.clone(),
    }
}
