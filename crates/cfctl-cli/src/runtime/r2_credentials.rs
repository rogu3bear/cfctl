use super::cloudflare_api::BASE_URL as API_BASE_URL;
use super::mutation_input::validate_cloudflare_tunnel_configuration_ingress;
use super::mutation_input::validate_d1_database_create_semantics;
use super::mutation_input::validate_warp_connector_configuration_semantics;
use super::mutation_input::validate_worker_script_secret_semantics;
use super::prelude::{
    AdapterStatus, AuthCredential, BTreeSet, CallInput, CapabilityV1, CatalogSnapshot, CliError,
    CloudflareResponseV1, EffectClass, EvidenceClass, EvidenceV1, Executor, Map, Result, RiskClass,
    StateStore, Value, json,
};
use super::support::capability_missing;
use super::support::http_client;
use cfctl_cloudflare::validate_request_contract;

pub(super) fn preflight_call_input(
    capability: &CapabilityV1,
    input: &CallInput,
    secret_body: Option<&Value>,
) -> Result<()> {
    let mut resolved = input.clone();
    if let Some(secret_body) = secret_body {
        resolved.body = Some(secret_body.clone());
    }
    validate_request_contract(capability, &resolved)?;
    validate_cloudflare_tunnel_configuration_ingress(capability, &resolved)?;
    validate_warp_connector_configuration_semantics(capability, &resolved)?;
    validate_d1_database_create_semantics(capability, &resolved)?;
    validate_worker_script_secret_semantics(capability, &resolved)?;
    validate_r2_temporary_credentials_semantics(capability, &resolved)?;
    Ok(())
}

pub(super) const R2_TEMPORARY_CREDENTIALS_CAPABILITY_ID: &str = "r2-create-temp-access-credentials";
pub(super) const R2_TEMPORARY_CREDENTIALS_PATH: &str =
    "/accounts/{account_id}/r2/temp-access-credentials";
pub(super) const R2_PARENT_TOKEN_VERIFY_CAPABILITY_ID: &str = "user-api-tokens-verify-token";
pub(super) const R2_PARENT_TOKEN_VERIFY_PATH: &str = "/user/tokens/verify";
pub(super) const R2_PARENT_TOKEN_PRECONDITION: &str = "r2_parent_token";
pub(super) const R2_ACTIVE_PROFILE_TOKEN_ID: &str = "$cfctl_active_profile_token_id";
pub(super) const R2_TEMPORARY_CREDENTIAL_PERMISSIONS: [&str; 6] = [
    "Workers R2 Storage Write",
    "Workers R2 Storage Read",
    "Workers R2 Storage Bucket Item Write",
    "Workers R2 Storage Bucket Item Read",
    "Workers R2 Data Catalog Write",
    "Workers R2 Data Catalog Read",
];

pub(super) fn is_r2_temporary_credentials_operation_identity(capability: &CapabilityV1) -> bool {
    capability.id == R2_TEMPORARY_CREDENTIALS_CAPABILITY_ID
        && capability.title == "Create Temporary Access Credentials"
        && capability.method == "POST"
        && capability.path == R2_TEMPORARY_CREDENTIALS_PATH
        && capability.product == "R2 Bucket"
        && capability.account_scope == "account"
}

pub(super) fn is_r2_temporary_credentials_capability(capability: &CapabilityV1) -> bool {
    is_r2_temporary_credentials_operation_identity(capability)
        && capability.permissions
            == R2_TEMPORARY_CREDENTIAL_PERMISSIONS
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        && capability.risk == RiskClass::SecretSensitive
        && capability.effect == EffectClass::IdentityOrOwnership
        && !capability.verification.required
        && capability.verification.strategy == "sink_write_and_source_response_status"
        && capability.request_schema.as_ref().is_some_and(|schema| {
            schema
                .pointer("/properties/parentAccessKeyId/x-cfctl-derived-from-active-profile")
                .and_then(Value::as_bool)
                == Some(true)
        })
}

pub(super) fn prepare_r2_temporary_credentials_input(
    capability: &CapabilityV1,
    input: &mut CallInput,
) -> Result<()> {
    if !is_r2_temporary_credentials_capability(capability) {
        return Ok(());
    }
    let body = input
        .body
        .as_mut()
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            CliError::Input("R2 temporary credentials require a JSON object body".to_owned())
        })?;
    if body.contains_key("parentAccessKeyId") {
        return Err(CliError::Input(
            "omit `parentAccessKeyId`; cfctl derives and hash-binds it from the active API-token profile so callers cannot redirect signing to another parent"
                .to_owned(),
        ));
    }
    body.insert(
        "parentAccessKeyId".to_owned(),
        Value::String(R2_ACTIVE_PROFILE_TOKEN_ID.to_owned()),
    );
    Ok(())
}

pub(super) fn should_bind_r2_parent_token(capability: &CapabilityV1) -> bool {
    is_r2_temporary_credentials_capability(capability)
        && capability.mutating
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
}

pub(super) fn r2_parent_token_verify_contract_supported(capability: &CapabilityV1) -> bool {
    capability.id == R2_PARENT_TOKEN_VERIFY_CAPABILITY_ID
        && capability.title == "Verify Token"
        && capability.method == "GET"
        && capability.path == R2_PARENT_TOKEN_VERIFY_PATH
        && capability.product == "User API Tokens"
        && capability.account_scope == "user"
        && !capability.mutating
        && capability.request_schema.is_none()
        && capability.permissions.is_empty()
        && capability.selectors.is_empty()
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
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

pub(super) fn r2_parent_permission_contract(permission: &str) -> Result<Value> {
    let allowed_capabilities: &[&str] = match permission {
        "admin-read-write" => &[
            "object_read",
            "object_write",
            "object_list",
            "bucket_configuration_read",
            "bucket_configuration_write",
            "data_catalog_read",
            "data_catalog_write",
        ],
        "admin-read-only" => &[
            "object_read",
            "object_list",
            "bucket_configuration_read",
            "data_catalog_read",
        ],
        "object-read-write" => &["object_read", "object_write", "object_list"],
        "object-read-only" => &["object_read", "object_list"],
        _ => {
            return Err(CliError::Input(format!(
                "unsupported R2 temporary credential permission `{permission}`"
            )));
        }
    };
    Ok(json!({
        "rule": "temporary_scope_must_not_exceed_parent",
        "enforced_by": "cloudflare",
        "requested_scope": permission,
        "allowed_capabilities": allowed_capabilities,
    }))
}

pub(super) fn r2_delegated_scope(input: &CallInput) -> Result<Value> {
    let body = input
        .body
        .as_ref()
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CliError::Input("R2 temporary credentials require a JSON object body".to_owned())
        })?;
    let mut scope = Map::new();
    for field in ["bucket", "permission", "ttlSeconds", "prefixes", "objects"] {
        if let Some(value) = body.get(field) {
            scope.insert(field.to_owned(), value.clone());
        }
    }
    Ok(Value::Object(scope))
}

pub(super) fn apply_r2_parent_token_response(
    capability: &CapabilityV1,
    account_id: &str,
    input: &mut CallInput,
    response: &CloudflareResponseV1,
) -> Result<Value> {
    if !should_bind_r2_parent_token(capability) {
        return Err(CliError::Input(
            "R2 temporary credential operation drifted from its governed parent-token contract"
                .to_owned(),
        ));
    }
    if !response.success || response.status != 200 {
        return Err(CliError::Input(format!(
            "active API-token verification did not return the exact successful HTTP 200 contract (received {}); the mutation boundary was not crossed",
            response.status
        )));
    }
    let parent_access_key_id = response
        .result
        .get("id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .ok_or_else(|| {
            CliError::Input(
                "active API-token verification omitted a bounded token id; the mutation boundary was not crossed"
                    .to_owned(),
            )
        })?;
    let token_status = response
        .result
        .get("status")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "active API-token verification omitted token status; the mutation boundary was not crossed"
                    .to_owned(),
            )
        })?;
    if token_status != "active" {
        return Err(CliError::Input(format!(
            "selected API-token profile is not active (status `{token_status}`); the mutation boundary was not crossed"
        )));
    }
    let body = input
        .body
        .as_mut()
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            CliError::Input("R2 temporary credentials require a JSON object body".to_owned())
        })?;
    let planned_parent = body
        .get("parentAccessKeyId")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "R2 temporary credential request omitted its cfctl-derived parent token marker"
                    .to_owned(),
            )
        })?;
    if planned_parent != R2_ACTIVE_PROFILE_TOKEN_ID && planned_parent != parent_access_key_id {
        return Err(CliError::Input(
            "R2 temporary credential parent token differs from the selected API-token profile; the mutation boundary was not crossed"
                .to_owned(),
        ));
    }
    body.insert(
        "parentAccessKeyId".to_owned(),
        Value::String(parent_access_key_id.to_owned()),
    );
    let delegated_scope = r2_delegated_scope(input)?;
    let permission = delegated_scope
        .get("permission")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input("R2 temporary credential permission is missing".to_owned())
        })?;
    Ok(json!({
        "schema_version": 1,
        "source_capability_id": R2_PARENT_TOKEN_VERIFY_CAPABILITY_ID,
        "source_path": R2_PARENT_TOKEN_VERIFY_PATH,
        "target_capability_id": capability.id,
        "target_method": capability.method,
        "target_path": capability.path,
        "target_scope": "account",
        "account_id": account_id,
        "parent_access_key_id": parent_access_key_id,
        "token_status": token_status,
        "delegated_scope": delegated_scope,
        "parent_permission_contract": r2_parent_permission_contract(permission)?,
    }))
}

pub(super) async fn read_live_r2_parent_token(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &mut CallInput,
    account_id: &str,
    credential: &AuthCredential,
) -> Result<(Value, EvidenceV1)> {
    let source_capability = catalog
        .get(R2_PARENT_TOKEN_VERIFY_CAPABILITY_ID)
        .ok_or_else(|| capability_missing(R2_PARENT_TOKEN_VERIFY_CAPABILITY_ID))?;
    if !r2_parent_token_verify_contract_supported(source_capability) {
        return Err(CliError::Input(
            "R2 parent-token source capability drifted from the governed user-token verification read"
                .to_owned(),
        ));
    }
    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let response = executor
        .execute_read(source_capability, &CallInput::default(), credential)
        .await?;
    let receipt = apply_r2_parent_token_response(capability, account_id, input, &response)?;
    let evidence = store.write_observation_evidence(EvidenceClass::LiveRead, &receipt)?;
    Ok((receipt, evidence))
}

pub(super) fn validate_r2_temporary_credentials_semantics(
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<()> {
    if !is_r2_temporary_credentials_capability(capability) {
        return Ok(());
    }
    let body = input
        .body
        .as_ref()
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CliError::Input("R2 temporary credentials require a JSON object body".to_owned())
        })?;
    let allowed = [
        "bucket",
        "objects",
        "parentAccessKeyId",
        "permission",
        "prefixes",
        "ttlSeconds",
    ];
    if let Some(field) = body.keys().find(|field| !allowed.contains(&field.as_str())) {
        return Err(CliError::Input(format!(
            "R2 temporary credentials reject undeclared body field `{field}`"
        )));
    }
    let bucket = body
        .get("bucket")
        .and_then(Value::as_str)
        .filter(|bucket| !bucket.trim().is_empty())
        .ok_or_else(|| {
            CliError::Input("R2 temporary credentials require a non-empty `bucket`".to_owned())
        })?;
    let _ = bucket;
    let ttl = body
        .get("ttlSeconds")
        .and_then(Value::as_u64)
        .filter(|ttl| (1..=604_800).contains(ttl))
        .ok_or_else(|| {
            CliError::Input(
                "R2 temporary credential `ttlSeconds` must be a whole number from 1 through 604800; use the shortest practical TTL"
                    .to_owned(),
            )
        })?;
    let _ = ttl;
    for field in ["prefixes", "objects"] {
        let Some(values) = body.get(field) else {
            continue;
        };
        let values = values.as_array().ok_or_else(|| {
            CliError::Input(format!(
                "R2 temporary credential `{field}` must be an array of non-empty strings"
            ))
        })?;
        let mut unique = BTreeSet::new();
        for value in values {
            let value = value
                .as_str()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    CliError::Input(format!(
                        "R2 temporary credential `{field}` must contain only non-empty strings"
                    ))
                })?;
            if !unique.insert(value) {
                return Err(CliError::Input(format!(
                    "R2 temporary credential `{field}` contains duplicate path `{value}`"
                )));
            }
        }
    }
    Ok(())
}
