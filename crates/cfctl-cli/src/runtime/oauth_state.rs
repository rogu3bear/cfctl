use super::cloudflare_api::BASE_URL as API_BASE_URL;
use super::plan_secret::OAUTH_CLIENT_COLLECTION_PATH;
use super::plan_secret::OAUTH_CLIENT_CREATE_CAPABILITY_ID;
use super::plan_secret::OAUTH_CLIENT_DETAIL_PATH;
use super::plan_secret::OAUTH_CLIENT_DETAIL_READ_CAPABILITY_ID;
use super::plan_secret::OAUTH_CLIENT_MUTABLE_FIELDS;
use super::plan_secret::OAUTH_CLIENT_UPDATE_CAPABILITY_ID;
use super::prelude::{
    AdapterStatus, AuthCredential, BTreeMap, CallInput, CapabilityV1, CatalogSnapshot, CliError,
    CloudflareResponseV1, EffectClass, EvidenceClass, EvidenceV1, Executor, Result, RiskClass,
    StateStore, Value, json,
};
use super::support::capability_missing;
use super::support::http_client;
use cfctl_core::{hash_value, redact_json};

pub(super) fn oauth_client_secret_expected_prior_state(capability: &CapabilityV1) -> Option<bool> {
    match (
        capability.id.as_str(),
        capability.method.as_str(),
        capability.verification.strategy.as_str(),
    ) {
        (
            "oauth-clients-rotate-secret",
            "POST",
            "oauth_client_reports_rotated_secret_after_value_roll",
        ) => Some(false),
        (
            "oauth-clients-delete-rotated-secret",
            "DELETE",
            "oauth_client_reports_no_rotated_secret_after_old_secret_delete",
        ) => Some(true),
        _ => None,
    }
}

pub(super) fn should_bind_oauth_client_secret_state(capability: &CapabilityV1) -> bool {
    oauth_client_secret_expected_prior_state(capability).is_some()
        && capability.mutating
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        && capability.verification_contract_supported()
}

pub(super) fn oauth_client_detail_read_contract_supported(capability: &CapabilityV1) -> bool {
    capability.id == OAUTH_CLIENT_DETAIL_READ_CAPABILITY_ID
        && capability.method == "GET"
        && capability.path == OAUTH_CLIENT_DETAIL_PATH
        && capability.product == "OAuth Clients"
        && capability.account_scope == "account"
        && !capability.mutating
        && capability.request_schema.is_none()
        && capability.permissions == ["OAuth Client Read"]
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        && capability.selectors.len() == 2
        && ["account_id", "oauth_client_id"].iter().all(|name| {
            capability.selectors.iter().any(|selector| {
                selector.name == *name
                    && selector.location == "path"
                    && selector.required
                    && selector.value_type == "string"
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

pub(super) fn oauth_client_all_plan_entitlement_supported(capability: &CapabilityV1) -> bool {
    capability.entitlement.available == Some(true)
        && capability.entitlement.plans
            == BTreeMap::from([
                ("business".to_owned(), true),
                ("enterprise".to_owned(), true),
                ("free".to_owned(), true),
                ("pro".to_owned(), true),
            ])
}

pub(super) fn oauth_client_success_response_contract_supported(capability: &CapabilityV1) -> bool {
    capability
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

pub(super) fn is_oauth_client_create_operation_identity(capability: &CapabilityV1) -> bool {
    capability.id == OAUTH_CLIENT_CREATE_CAPABILITY_ID
        && capability.method == "POST"
        && capability.path == OAUTH_CLIENT_COLLECTION_PATH
        && capability.product == "OAuth Clients"
        && capability.account_scope == "account"
        && capability.permissions == ["OAuth Client Write", "OAuth Client Read"]
}

pub(super) fn is_oauth_client_create_capability(capability: &CapabilityV1) -> bool {
    is_oauth_client_create_operation_identity(capability)
        && capability.risk == RiskClass::IdentityOrOwnership
        && capability.effect == EffectClass::IdentityOrOwnership
        && capability.cost.known
        && !capability.cost.incremental
        && oauth_client_all_plan_entitlement_supported(capability)
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        && oauth_client_success_response_contract_supported(capability)
        && capability.selectors.len() == 1
        && capability.selectors.iter().any(|selector| {
            selector.name == "account_id"
                && selector.location == "path"
                && selector.required
                && selector.value_type == "string"
        })
        && capability.request_object_fields()
            == Some(
                OAUTH_CLIENT_MUTABLE_FIELDS[..12]
                    .iter()
                    .map(|field| (*field).to_owned())
                    .collect(),
            )
        && capability.request_schema.as_ref().is_some_and(|schema| {
            schema.get("type").and_then(Value::as_str) == Some("object")
                && schema.get("additionalProperties").and_then(Value::as_bool) == Some(false)
                && schema.get("x-cfctl-body-required").and_then(Value::as_bool) == Some(true)
        })
        && capability.verification.strategy
            == "created_resource_contains_planned_fields_by_returned_id"
        && capability.verification_contract_supported()
        && capability.created_resource.as_ref().is_some_and(|created| {
            created.detail_path == OAUTH_CLIENT_DETAIL_PATH
                && created.identity_selector == "oauth_client_id"
                && created.response_result_identity_pointer == "/client_id"
                && created.read_capability_id == OAUTH_CLIENT_DETAIL_READ_CAPABILITY_ID
                && created.delete_capability_id == "oauth-clients-delete"
                && created.verified_response_fields
                    == OAUTH_CLIENT_MUTABLE_FIELDS[..12]
                        .iter()
                        .map(|field| (*field).to_owned())
                        .collect::<Vec<_>>()
        })
        && !capability.rollback.supported
        && capability.rollback.strategy.is_none()
}

pub(super) fn is_oauth_client_update_capability(capability: &CapabilityV1) -> bool {
    capability.id == OAUTH_CLIENT_UPDATE_CAPABILITY_ID
        && capability.method == "PATCH"
        && capability.path == OAUTH_CLIENT_DETAIL_PATH
        && capability.product == "OAuth Clients"
        && capability.account_scope == "account"
        && capability.permissions == ["OAuth Client Write", "OAuth Client Read"]
        && capability.risk == RiskClass::IdentityOrOwnership
        && capability.effect == EffectClass::IdentityOrOwnership
        && capability.cost.known
        && !capability.cost.incremental
        && oauth_client_all_plan_entitlement_supported(capability)
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        && oauth_client_success_response_contract_supported(capability)
        && capability.selectors.len() == 2
        && ["account_id", "oauth_client_id"].iter().all(|name| {
            capability.selectors.iter().any(|selector| {
                selector.name == *name
                    && selector.location == "path"
                    && selector.required
                    && selector.value_type == "string"
            })
        })
        && capability.request_object_fields()
            == Some(
                OAUTH_CLIENT_MUTABLE_FIELDS
                    .iter()
                    .map(|field| (*field).to_owned())
                    .collect(),
            )
        && capability.request_schema.as_ref().is_some_and(|schema| {
            schema.get("type").and_then(Value::as_str) == Some("object")
                && schema.get("additionalProperties").and_then(Value::as_bool) == Some(false)
                && schema.get("minProperties").and_then(Value::as_u64) == Some(1)
                && schema.get("x-cfctl-body-required").and_then(Value::as_bool) == Some(true)
                && schema.pointer("/properties/visibility/enum") == Some(&json!(["public"]))
        })
        && capability.verification.strategy == "same_resource_contains_planned_fields_after_update"
        && capability.verification_contract_supported()
        && capability.same_path_read.as_ref().is_some_and(|read| {
            read.path == OAUTH_CLIENT_DETAIL_PATH
                && read.read_capability_id == OAUTH_CLIENT_DETAIL_READ_CAPABILITY_ID
                && read.verified_response_fields
                    == OAUTH_CLIENT_MUTABLE_FIELDS
                        .iter()
                        .map(|field| (*field).to_owned())
                        .collect::<Vec<_>>()
        })
        && !capability.rollback.supported
        && capability.rollback.strategy.is_none()
        && capability
            .rollback
            .warning
            .as_deref()
            .is_some_and(|warning| warning.contains("permanent"))
}

pub(super) fn should_bind_oauth_client_update_state(capability: &CapabilityV1) -> bool {
    is_oauth_client_update_capability(capability) && capability.mutating
}

pub(super) fn apply_oauth_client_update_state_response(
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    response: &CloudflareResponseV1,
) -> Result<Value> {
    if !should_bind_oauth_client_update_state(capability) {
        return Err(CliError::Input(
            "OAuth client update drifted from its governed snapshot contract".to_owned(),
        ));
    }
    if !response.success || response.status != 200 {
        return Err(CliError::Input(format!(
            "OAuth client snapshot read did not return the exact successful HTTP 200 contract (received {}); the mutation boundary was not crossed",
            response.status
        )));
    }
    let oauth_client_id = input
        .selectors
        .get("oauth_client_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "OAuth client update requires an exact oauth_client_id selector".to_owned(),
            )
        })?;
    if response.result.get("client_id").and_then(Value::as_str) != Some(oauth_client_id) {
        return Err(CliError::Input(
            "OAuth client snapshot read returned a different or missing client id; the mutation boundary was not crossed"
                .to_owned(),
        ));
    }
    if redact_json(&response.result) != response.result {
        return Err(CliError::Input(
            "OAuth client snapshot unexpectedly contained secret-bearing fields; no plan or evidence was created"
                .to_owned(),
        ));
    }
    let visibility = response
        .result
        .get("visibility")
        .and_then(Value::as_str)
        .filter(|visibility| matches!(*visibility, "private" | "public"))
        .ok_or_else(|| {
            CliError::Input(
                "OAuth client snapshot omitted its exact private/public visibility state"
                    .to_owned(),
            )
        })?;
    let planned = input
        .body
        .as_ref()
        .and_then(Value::as_object)
        .filter(|body| !body.is_empty())
        .ok_or_else(|| CliError::Input("OAuth client update body is empty".to_owned()))?;
    if planned.contains_key("visibility")
        && (planned.len() != 1
            || planned.get("visibility").and_then(Value::as_str) != Some("public")
            || visibility != "private")
    {
        return Err(CliError::Input(
            "public OAuth visibility is an irreversible one-field promotion from a private client and cannot be combined with metadata changes"
                .to_owned(),
        ));
    }
    if planned
        .iter()
        .all(|(field, value)| response.result.get(field) == Some(value))
    {
        return Err(CliError::Input(
            "OAuth client already has every requested field; no mutation plan was created"
                .to_owned(),
        ));
    }

    let mut prior_state = serde_json::Map::new();
    let mut absent_fields = Vec::new();
    for field in OAUTH_CLIENT_MUTABLE_FIELDS {
        if let Some(value) = response.result.get(field) {
            prior_state.insert(field.to_owned(), value.clone());
        } else {
            absent_fields.push(field);
        }
    }
    Ok(json!({
        "schema_version":1,
        "source_capability_id":OAUTH_CLIENT_DETAIL_READ_CAPABILITY_ID,
        "source_path":OAUTH_CLIENT_DETAIL_PATH,
        "target_capability_id":capability.id,
        "target_method":capability.method,
        "target_path":capability.path,
        "target_scope":"account",
        "account_id":account_id,
        "oauth_client_id":oauth_client_id,
        "observed_result_hash":hash_value(&response.result)?,
        "prior_state":prior_state,
        "absent_fields":absent_fields,
    }))
}

pub(super) async fn read_live_oauth_client_update_state(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: &AuthCredential,
) -> Result<(Value, EvidenceV1)> {
    if !should_bind_oauth_client_update_state(capability) {
        return Err(CliError::Input(
            "OAuth client update drifted from its governed prior-state contract".to_owned(),
        ));
    }
    let selected_account = input
        .selectors
        .get("account_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "OAuth client snapshot requires string selector `account_id`".to_owned(),
            )
        })?;
    if selected_account != account_id {
        return Err(CliError::Input(
            "OAuth client target account differs from the selected account; the mutation boundary was not crossed"
                .to_owned(),
        ));
    }
    let source = catalog
        .get(OAUTH_CLIENT_DETAIL_READ_CAPABILITY_ID)
        .ok_or_else(|| capability_missing(OAUTH_CLIENT_DETAIL_READ_CAPABILITY_ID))?;
    if !oauth_client_detail_read_contract_supported(source) {
        return Err(CliError::Input(
            "OAuth client detail source drifted from the governed exact-client read".to_owned(),
        ));
    }
    let response = Executor::new(http_client()?, API_BASE_URL)?
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
    let receipt =
        apply_oauth_client_update_state_response(capability, input, account_id, &response)?;
    let evidence = store.write_observation_evidence(EvidenceClass::LiveRead, &receipt)?;
    Ok((receipt, evidence))
}

pub(super) fn apply_oauth_client_secret_state_response(
    capability: &CapabilityV1,
    account_id: &str,
    oauth_client_id: &str,
    response: &CloudflareResponseV1,
) -> Result<Value> {
    if !should_bind_oauth_client_secret_state(capability) {
        return Err(CliError::Input(
            "OAuth client secret operation drifted from its governed two-secret cutover contract"
                .to_owned(),
        ));
    }
    if !response.success || response.status != 200 {
        return Err(CliError::Input(format!(
            "OAuth client state read did not return the exact successful HTTP 200 contract (received {}); the mutation boundary was not crossed",
            response.status
        )));
    }
    if response.result.get("client_id").and_then(Value::as_str) != Some(oauth_client_id) {
        return Err(CliError::Input(
            "OAuth client state read returned a different or missing client id; the mutation boundary was not crossed"
                .to_owned(),
        ));
    }
    let has_rotated_secret = response
        .result
        .get("has_rotated_secret")
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            CliError::Input(
                "OAuth client state read omitted the two-secret state; the mutation boundary was not crossed"
                    .to_owned(),
            )
        })?;
    let expected = oauth_client_secret_expected_prior_state(capability)
        .ok_or_else(|| CliError::Input("OAuth client cutover phase is unsupported".to_owned()))?;
    if has_rotated_secret != expected {
        let required_state = if expected {
            "two active secrets before deleting the old one"
        } else {
            "one active secret before creating the overlap secret"
        };
        return Err(CliError::Input(format!(
            "OAuth client secret operation requires {required_state}; the mutation boundary was not crossed"
        )));
    }
    Ok(json!({
        "schema_version": 1,
        "source_capability_id": OAUTH_CLIENT_DETAIL_READ_CAPABILITY_ID,
        "source_path": OAUTH_CLIENT_DETAIL_PATH,
        "target_capability_id": capability.id,
        "target_method": capability.method,
        "target_scope": "account",
        "account_id": account_id,
        "oauth_client_id": oauth_client_id,
        "key_overlap_active": has_rotated_secret,
    }))
}

pub(super) async fn read_live_oauth_client_secret_state(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: &AuthCredential,
) -> Result<(Value, EvidenceV1)> {
    if !should_bind_oauth_client_secret_state(capability) {
        return Err(CliError::Input(
            "OAuth client secret operation drifted from its governed prior-state contract"
                .to_owned(),
        ));
    }
    let selected_account = input
        .selectors
        .get("account_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "OAuth client state precondition requires string selector `account_id`".to_owned(),
            )
        })?;
    if selected_account != account_id {
        return Err(CliError::Input(
            "OAuth client target account differs from the selected account; the mutation boundary was not crossed"
                .to_owned(),
        ));
    }
    let oauth_client_id = input
        .selectors
        .get("oauth_client_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "OAuth client state precondition requires string selector `oauth_client_id`"
                    .to_owned(),
            )
        })?;
    let source_capability = catalog
        .get(OAUTH_CLIENT_DETAIL_READ_CAPABILITY_ID)
        .ok_or_else(|| capability_missing(OAUTH_CLIENT_DETAIL_READ_CAPABILITY_ID))?;
    if !oauth_client_detail_read_contract_supported(source_capability) {
        return Err(CliError::Input(
            "OAuth client state source capability drifted from the governed client detail read"
                .to_owned(),
        ));
    }
    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let response = executor
        .execute_read(
            source_capability,
            &CallInput {
                selectors: json!({
                    "account_id":account_id,
                    "oauth_client_id":oauth_client_id
                }),
                query: json!({}),
                body: None,
                ..CallInput::default()
            },
            credential,
        )
        .await?;
    let receipt = apply_oauth_client_secret_state_response(
        capability,
        account_id,
        oauth_client_id,
        &response,
    )?;
    let evidence = store.write_observation_evidence(EvidenceClass::LiveRead, &receipt)?;
    Ok((receipt, evidence))
}
