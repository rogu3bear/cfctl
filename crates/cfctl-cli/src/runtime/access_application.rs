use super::access_ownership::read_live_same_path_prior_state;
use super::cloudflare_api::BASE_URL as API_BASE_URL;
use super::live_state_contracts::apply_same_path_prior_state_response;
use super::plan_secret::ACCESS_APP_DETAIL_PATH;
use super::plan_secret::ACCESS_APP_IMPLICIT_OPEN_ROLLBACK_WARNING;
use super::plan_secret::ACCESS_APP_LAUNCHER_LOGIN_METHODS_CAPABILITY_ID;
use super::plan_secret::ACCESS_APP_LAUNCHER_MUTABLE_FIELDS;
use super::plan_secret::ACCESS_APP_LAUNCHER_READ_ONLY_FIELDS;
use super::plan_secret::ACCESS_APP_LAUNCHER_REQUIRED_FIELDS;
use super::plan_secret::ACCESS_APP_LOGIN_METHODS_CAPABILITY_ID;
use super::plan_secret::ACCESS_APP_MUTABLE_FIELDS;
use super::plan_secret::ACCESS_APP_OWNED_WHOLE_HOST_CAPABILITY_ID;
use super::plan_secret::ACCESS_APP_READ_CAPABILITY_ID;
use super::plan_secret::ACCESS_APP_READ_ONLY_FIELDS;
use super::plan_secret::ACCESS_APP_REQUIRED_FIELDS;
use super::plan_secret::SAME_PATH_PRIOR_STATE_ROLLBACK_STRATEGY;
use super::prelude::{
    AdapterStatus, AuthCredential, BTreeSet, CallInput, CapabilityV1, CatalogSnapshot, CliError,
    CloudflareResponseV1, EvidenceClass, EvidenceV1, Executor, Map, Result, StateStore, Uuid,
    Value, json,
};
use super::r2_credentials::preflight_call_input;
use super::support::capability_missing;
use super::support::http_client;
use cfctl_cloudflare::validate_request_contract;

#[derive(Clone, Copy)]
pub(super) struct AccessApplicationLoginMethodsVariant {
    pub(super) app_type: &'static str,
    pub(super) mutable_fields: &'static [&'static str],
    pub(super) required_fields: &'static [&'static str],
    pub(super) read_only_fields: &'static [&'static str],
}

pub(super) fn access_application_login_methods_variant(
    capability_id: &str,
) -> Option<AccessApplicationLoginMethodsVariant> {
    match capability_id {
        ACCESS_APP_LOGIN_METHODS_CAPABILITY_ID | ACCESS_APP_OWNED_WHOLE_HOST_CAPABILITY_ID => {
            Some(AccessApplicationLoginMethodsVariant {
                app_type: "self_hosted",
                mutable_fields: &ACCESS_APP_MUTABLE_FIELDS,
                required_fields: &ACCESS_APP_REQUIRED_FIELDS,
                read_only_fields: &ACCESS_APP_READ_ONLY_FIELDS,
            })
        }
        ACCESS_APP_LAUNCHER_LOGIN_METHODS_CAPABILITY_ID => {
            Some(AccessApplicationLoginMethodsVariant {
                app_type: "app_launcher",
                mutable_fields: &ACCESS_APP_LAUNCHER_MUTABLE_FIELDS,
                required_fields: &ACCESS_APP_LAUNCHER_REQUIRED_FIELDS,
                read_only_fields: &ACCESS_APP_LAUNCHER_READ_ONLY_FIELDS,
            })
        }
        _ => None,
    }
}

pub(super) fn access_application_login_methods_contract_supported(
    capability: &CapabilityV1,
) -> bool {
    let Some(variant) = access_application_login_methods_variant(&capability.id) else {
        return false;
    };
    capability.method == "PUT"
        && capability.path == ACCESS_APP_DETAIL_PATH
        && capability.product == "Access applications"
        && capability.account_scope == "account"
        && capability.mutating
        && capability.permissions == ["Access: Apps and Policies Write"]
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        && capability.verification.strategy
            == "same_path_result_contains_planned_fields_after_update"
        && capability.same_path_read.as_ref().is_some_and(|read| {
            read.path == ACCESS_APP_DETAIL_PATH
                && read.read_capability_id == ACCESS_APP_READ_CAPABILITY_ID
                && read.verified_response_fields
                    == variant
                        .mutable_fields
                        .iter()
                        .map(|field| (*field).to_owned())
                        .collect::<Vec<_>>()
        })
        && capability.verification_contract_supported()
}

pub(super) fn is_access_application_login_methods_mutation(capability: &CapabilityV1) -> bool {
    access_application_login_methods_contract_supported(capability)
        && capability.rollback.supported
        && capability.rollback.strategy.as_deref() == Some(SAME_PATH_PRIOR_STATE_ROLLBACK_STRATEGY)
        && capability.rollback_contract_supported()
}

pub(super) fn is_access_application_implicit_open_concurrency_plan(
    capability: &CapabilityV1,
) -> bool {
    access_application_login_methods_contract_supported(capability)
        && !capability.rollback.supported
        && capability.rollback.strategy.is_none()
        && capability.rollback.warning.as_deref() == Some(ACCESS_APP_IMPLICIT_OPEN_ROLLBACK_WARNING)
        && capability.mutation_contract_gaps().is_empty()
}

pub(super) fn access_application_login_methods_desired_schema() -> Value {
    json!({
        "type":"object",
        "additionalProperties":false,
        "required":["allowed_idps"],
        "properties":{
            "allowed_idps":{
                "type":"array",
                "minItems":1,
                "maxItems":25,
                "uniqueItems":true,
                "items":cfctl_catalog::access_identity_provider_id_schema()
            }
        },
        "x-cfctl-body-required":true
    })
}

pub(super) fn validate_access_application_login_methods_desired_input(
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<()> {
    if !is_access_application_login_methods_mutation(capability) {
        return Err(CliError::Input(
            "Access application login-method capability drifted from its governed exact-update contract"
                .to_owned(),
        ));
    }
    let mut desired_capability = capability.clone();
    desired_capability.request_schema = Some(access_application_login_methods_desired_schema());
    validate_request_contract(&desired_capability, input)?;
    access_application_desired_idps(input)?;
    Ok(())
}

pub(super) fn parse_access_identity_provider_id(value: &str) -> Option<Uuid> {
    let bytes = value.as_bytes();
    let valid_rendering = match bytes.len() {
        32 => bytes.iter().all(u8::is_ascii_hexdigit),
        36 => bytes.iter().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        }),
        _ => false,
    };
    valid_rendering
        .then(|| Uuid::parse_str(value).ok())
        .flatten()
}

pub(super) fn access_application_desired_idps(input: &CallInput) -> Result<Vec<String>> {
    let body = input
        .body
        .as_ref()
        .and_then(Value::as_object)
        .filter(|body| body.len() == 1)
        .ok_or_else(|| {
            CliError::Input(
                "Access login-method input must contain only a non-empty `allowed_idps` array"
                    .to_owned(),
            )
        })?;
    let values = body
        .get("allowed_idps")
        .and_then(Value::as_array)
        .filter(|values| !values.is_empty() && values.len() <= 25)
        .ok_or_else(|| {
            CliError::Input(
                "Access login-method input requires between 1 and 25 identity-provider IDs; an empty list would allow every login method"
                    .to_owned(),
            )
        })?;
    let mut desired = values
        .iter()
        .map(|value| {
            let value = value.as_str().ok_or_else(|| {
                CliError::Input("every Access identity-provider ID must be a valid UUID".to_owned())
            })?;
            parse_access_identity_provider_id(value)
                .map(|id| id.hyphenated().to_string())
                .ok_or_else(|| {
                    CliError::Input(
                        "every Access identity-provider ID must be a valid UUID".to_owned(),
                    )
                })
        })
        .collect::<Result<Vec<_>>>()?;
    desired.sort();
    if desired.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(CliError::Input(
            "Access identity-provider IDs must be unique".to_owned(),
        ));
    }
    Ok(desired)
}

pub(super) fn normalize_access_application_policies(value: &Value) -> Result<Value> {
    let policies = value
        .as_array()
        .filter(|policies| !policies.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "live Access application has no restorable policy references; the mutation boundary was not crossed"
                    .to_owned(),
            )
        })?;
    let mut normalized = policies
        .iter()
        .map(|policy| {
            let id = policy
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .ok_or_else(|| {
                    CliError::Input(
                        "live Access application policy omitted its identity; the mutation boundary was not crossed"
                            .to_owned(),
                    )
                })?;
            let precedence = policy
                .get("precedence")
                .and_then(Value::as_u64)
                .filter(|precedence| *precedence > 0)
                .ok_or_else(|| {
                    CliError::Input(
                        "live Access application policy omitted a positive precedence; the mutation boundary was not crossed"
                            .to_owned(),
                    )
                })?;
            Ok(json!({"id":id,"precedence":precedence}))
        })
        .collect::<Result<Vec<_>>>()?;
    let policy_identities = normalized
        .iter()
        .filter_map(|policy| policy.get("id").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    if policy_identities.len() != normalized.len() {
        return Err(CliError::Input(
            "live Access application returned duplicate policy identities; the mutation boundary was not crossed"
                .to_owned(),
        ));
    }
    normalized.sort_by(|left, right| {
        let left_precedence = left
            .get("precedence")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let right_precedence = right
            .get("precedence")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        left_precedence.cmp(&right_precedence).then_with(|| {
            left.get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .cmp(right.get("id").and_then(Value::as_str).unwrap_or_default())
        })
    });
    Ok(Value::Array(normalized))
}

pub(super) fn normalized_access_application_idps(value: &Value) -> Result<Vec<String>> {
    let mut idps = value
        .as_array()
        .ok_or_else(|| {
            CliError::Input(
                "live Access application returned an invalid identity-provider allowlist; the mutation boundary was not crossed"
                    .to_owned(),
            )
        })?
        .iter()
        .map(|idp| {
            let idp = idp.as_str().ok_or_else(|| {
                CliError::Input(
                    "live Access application returned an invalid identity-provider ID; the mutation boundary was not crossed"
                        .to_owned(),
                )
            })?;
            parse_access_identity_provider_id(idp)
                .map(|id| id.hyphenated().to_string())
                .ok_or_else(|| {
                    CliError::Input(
                        "live Access application returned an invalid identity-provider ID; the mutation boundary was not crossed"
                            .to_owned(),
                    )
                })
        })
        .collect::<Result<Vec<_>>>()?;
    idps.sort();
    if idps.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(CliError::Input(
            "live Access application returned duplicate identity-provider IDs; the mutation boundary was not crossed"
                .to_owned(),
        ));
    }
    Ok(idps)
}

/// Rollback-only validation keeps an implicit-open prior state from being
/// represented as a restorable empty allowlist.
pub(super) fn access_application_rollback_idps(value: &Value) -> Result<Vec<String>> {
    let idps = normalized_access_application_idps(value)?;
    if idps.is_empty() {
        return Err(CliError::Input(
            "live Access application has an empty identity-provider allowlist; the mutation boundary was not crossed"
                .to_owned(),
        ));
    }
    Ok(idps)
}

pub(super) fn access_application_mutable_body(
    result: &Value,
    desired_idps: &[String],
    variant: AccessApplicationLoginMethodsVariant,
) -> Result<Value> {
    let result = result.as_object().ok_or_else(|| {
        CliError::Input(
            "live Access application read did not return an object; the mutation boundary was not crossed"
                .to_owned(),
        )
    })?;
    let known_fields = variant
        .mutable_fields
        .iter()
        .chain(variant.read_only_fields.iter())
        .copied()
        .collect::<BTreeSet<_>>();
    let unknown_fields = result
        .keys()
        .filter(|field| !known_fields.contains(field.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if !unknown_fields.is_empty() {
        return Err(CliError::Input(format!(
            "live Access application contains unclassified field(s) {}; the preservation-safe mutation boundary was not crossed",
            unknown_fields.join(",")
        )));
    }
    if variant.app_type == "self_hosted" {
        let (Some(destinations), Some(self_hosted_domains)) = (
            result.get("destinations").and_then(Value::as_array),
            result.get("self_hosted_domains").and_then(Value::as_array),
        ) else {
            return Err(CliError::Input(
                "live self-hosted Access application has no populated destination representation; the mutation boundary was not crossed"
                    .to_owned(),
            ));
        };
        if destinations.is_empty() && self_hosted_domains.is_empty() {
            return Err(CliError::Input(
                "live self-hosted Access application has no populated destination representation; the mutation boundary was not crossed"
                    .to_owned(),
            ));
        }
    }
    let mut body = Map::new();
    for &field in variant.mutable_fields {
        let Some(value) = result.get(field).cloned() else {
            if variant.required_fields.contains(&field) {
                return Err(CliError::Input(format!(
                    "live Access application omitted required mutable field `{field}`; the mutation boundary was not crossed"
                )));
            }
            continue;
        };
        let value = match field {
            "allowed_idps" => json!(desired_idps),
            "policies" => normalize_access_application_policies(&value)?,
            _ => value,
        };
        body.insert(field.to_owned(), value);
    }
    Ok(Value::Object(body))
}

pub(super) fn access_application_read_contract_supported(capability: &CapabilityV1) -> bool {
    capability.id == ACCESS_APP_READ_CAPABILITY_ID
        && capability.method == "GET"
        && capability.path == ACCESS_APP_DETAIL_PATH
        && capability.product == "Access applications"
        && capability.account_scope == "account"
        && !capability.mutating
        && capability.request_schema.is_none()
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        && capability.selectors.len() == 2
        && ["account_id", "app_id"].iter().all(|name| {
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
            .is_some_and(|response| {
                response.body_mode == cfctl_core::ResponseBodyModeV1::CloudflareJsonEnvelope
                    && response.success_statuses == ["200"]
                    && response.success_media_types == ["application/json"]
            })
}

pub(super) async fn prepare_access_application_login_methods_plan_input(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &mut CapabilityV1,
    input: &mut CallInput,
    account_id: &str,
    credential: &AuthCredential,
) -> Result<Option<(Value, EvidenceV1)>> {
    if !is_access_application_login_methods_mutation(capability) {
        return Ok(None);
    }
    let variant = access_application_login_methods_variant(&capability.id).ok_or_else(|| {
        CliError::Input(
            "Access application login-method capability omitted its exact application variant"
                .to_owned(),
        )
    })?;
    let body_field_count = input
        .body
        .as_ref()
        .and_then(Value::as_object)
        .map_or(0, serde_json::Map::len);
    if body_field_count != 1 {
        preflight_call_input(capability, input, None)?;
        return read_live_same_path_prior_state(
            store, catalog, capability, input, account_id, credential,
        )
        .await
        .map(Some);
    }
    let desired_idps = access_application_desired_idps(input)?;
    input
        .selectors
        .get("app_id")
        .and_then(Value::as_str)
        .filter(|app_id| !app_id.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "Access login-method plan requires an exact `app_id` selector".to_owned(),
            )
        })?;
    let source = catalog
        .get(ACCESS_APP_READ_CAPABILITY_ID)
        .ok_or_else(|| capability_missing(ACCESS_APP_READ_CAPABILITY_ID))?;
    if !access_application_read_contract_supported(source) {
        return Err(CliError::Input(
            "Access application state source drifted from the governed exact-app read".to_owned(),
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
    let Some(receipt) = finalize_access_application_login_methods_plan_input(
        capability,
        input,
        &desired_idps,
        variant,
        account_id,
        &response,
    )?
    else {
        return Ok(None);
    };
    let evidence = store.write_evidence(EvidenceClass::LiveRead, &receipt)?;
    Ok(Some((receipt, evidence)))
}

pub(super) fn finalize_access_application_login_methods_plan_input(
    capability: &mut CapabilityV1,
    input: &mut CallInput,
    desired_idps: &[String],
    variant: AccessApplicationLoginMethodsVariant,
    account_id: &str,
    response: &CloudflareResponseV1,
) -> Result<Option<Value>> {
    if !response.success || response.status != 200 {
        return Err(CliError::Input(format!(
            "Cloudflare rejected the Access application state read with HTTP {}; the mutation boundary was not crossed",
            response.status
        )));
    }
    let app_id = input
        .selectors
        .get("app_id")
        .and_then(Value::as_str)
        .filter(|app_id| !app_id.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "Access login-method plan requires an exact `app_id` selector".to_owned(),
            )
        })?
        .to_owned();
    if response.result.get("id").and_then(Value::as_str) != Some(app_id.as_str())
        || response.result.get("type").and_then(Value::as_str) != Some(variant.app_type)
    {
        return Err(CliError::Input(format!(
            "Access application state read returned a different app or a non-{} app; the mutation boundary was not crossed",
            variant.app_type
        )));
    }
    let current_idps = normalized_access_application_idps(
        response.result.get("allowed_idps").unwrap_or(&Value::Null),
    )?;
    if current_idps == desired_idps {
        return Err(CliError::Input(
            "Access application already has the exact requested identity-provider allowlist; no mutation plan was created"
                .to_owned(),
        ));
    }
    input.body = Some(access_application_mutable_body(
        &response.result,
        desired_idps,
        variant,
    )?);
    if variant.app_type == "self_hosted" {
        capability.request_schema =
            Some(cfctl_catalog::access_application_login_methods_materialized_schema());
    }
    preflight_call_input(capability, input, None)?;
    if current_idps.is_empty() {
        capability.rollback.supported = false;
        capability.rollback.strategy = None;
        capability.rollback.warning = Some(ACCESS_APP_IMPLICIT_OPEN_ROLLBACK_WARNING.to_owned());
        return apply_same_path_prior_state_response(capability, input, account_id, response)
            .map(Some);
    }
    apply_same_path_prior_state_response(capability, input, account_id, response).map(Some)
}
