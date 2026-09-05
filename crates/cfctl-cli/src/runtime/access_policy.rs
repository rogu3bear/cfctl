use super::access_application::access_application_login_methods_desired_schema;
use super::access_application::is_access_application_login_methods_mutation;
use super::cloudflare_api::BASE_URL as API_BASE_URL;
use super::live_state_contracts::apply_same_path_prior_state_response;
use super::plan_secret::ACCESS_APP_OWNED_WHOLE_HOST_CAPABILITY_ID;
use super::plan_secret::ACCESS_HUMAN_POLICY_DESIRED_FIELDS;
use super::plan_secret::ACCESS_HUMAN_POLICY_MUTABLE_FIELDS;
use super::plan_secret::ACCESS_HUMAN_POLICY_READ_ONLY_FIELDS;
use super::plan_secret::ACCESS_HUMAN_POLICY_REQUIRED_FIELDS;
use super::plan_secret::ACCESS_HUMAN_POLICY_UPDATE_CAPABILITY_ID;
use super::plan_secret::ACCESS_OPERATOR_GROUP_POLICY_CREATE_CAPABILITY_ID;
use super::plan_secret::ACCESS_OPERATOR_GROUP_POLICY_UPDATE_CAPABILITY_ID;
use super::plan_secret::ACCESS_POLICY_COLLECTION_PATH;
use super::plan_secret::ACCESS_POLICY_DETAIL_PATH;
use super::plan_secret::ACCESS_POLICY_READ_CAPABILITY_ID;
use super::plan_secret::SAME_PATH_PRIOR_STATE_ROLLBACK_STRATEGY;
use super::prelude::{
    AdapterStatus, AuthCredential, BTreeSet, CallInput, CapabilityV1, CatalogSnapshot, CliError,
    EffectClass, EvidenceClass, EvidenceV1, Executor, Map, Result, RiskClass, StateStore, Value,
    json,
};
use super::r2_credentials::preflight_call_input;
use super::support::capability_missing;
use super::support::http_client;
use cfctl_cloudflare::validate_request_contract;

pub(super) fn is_access_human_policy_mutation(capability: &CapabilityV1) -> bool {
    capability.id == ACCESS_HUMAN_POLICY_UPDATE_CAPABILITY_ID
        && capability.method == "PUT"
        && capability.path == ACCESS_POLICY_DETAIL_PATH
        && capability.product == "Access application-scoped policies"
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
            read.path == ACCESS_POLICY_DETAIL_PATH
                && read.read_capability_id == ACCESS_POLICY_READ_CAPABILITY_ID
                && read.verified_response_fields
                    == ACCESS_HUMAN_POLICY_MUTABLE_FIELDS
                        .iter()
                        .map(|field| (*field).to_owned())
                        .collect::<Vec<_>>()
        })
        && capability.rollback.strategy.as_deref() == Some(SAME_PATH_PRIOR_STATE_ROLLBACK_STRATEGY)
        && capability.verification_contract_supported()
        && capability.rollback_contract_supported()
}

pub(super) fn is_access_operator_group_policy_create(capability: &CapabilityV1) -> bool {
    capability.id == ACCESS_OPERATOR_GROUP_POLICY_CREATE_CAPABILITY_ID
        && capability.method == "POST"
        && capability.path == ACCESS_POLICY_COLLECTION_PATH
        && capability.product == "Access application-scoped policies"
        && capability.account_scope == "account"
        && capability.mutating
        && capability.permissions == ["Access: Apps and Policies Write"]
        && capability.risk == RiskClass::IdentityOrOwnership
        && capability.effect == EffectClass::IdentityOrOwnership
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        && capability.verification.strategy
            == "created_resource_contains_planned_fields_by_returned_id"
        && capability.created_resource.as_ref().is_some_and(|created| {
            created.detail_path == ACCESS_POLICY_DETAIL_PATH
                && created.identity_selector == "policy_id"
                && created.response_result_identity_pointer == "/id"
                && created.read_capability_id == ACCESS_POLICY_READ_CAPABILITY_ID
                && created.delete_capability_id == "access-policies-delete-an-access-policy"
        })
        && capability.rollback.supported
        && capability.rollback.strategy.as_deref() == Some("delete_created_resource_by_returned_id")
        && capability.mutation_contract_gaps().is_empty()
}

pub(super) fn is_access_operator_group_policy_update(capability: &CapabilityV1) -> bool {
    capability.id == ACCESS_OPERATOR_GROUP_POLICY_UPDATE_CAPABILITY_ID
        && capability.method == "PUT"
        && capability.path == ACCESS_POLICY_DETAIL_PATH
        && capability.product == "Access application-scoped policies"
        && capability.account_scope == "account"
        && capability.mutating
        && capability.permissions == ["Access: Apps and Policies Write"]
        && capability.risk == RiskClass::IdentityOrOwnership
        && capability.effect == EffectClass::IdentityOrOwnership
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        && capability.verification.strategy
            == "same_path_result_contains_planned_fields_after_update"
        && capability.same_path_read.as_ref().is_some_and(|read| {
            read.path == ACCESS_POLICY_DETAIL_PATH
                && read.read_capability_id == ACCESS_POLICY_READ_CAPABILITY_ID
        })
        && capability.rollback.supported
        && capability.rollback.strategy.as_deref() == Some(SAME_PATH_PRIOR_STATE_ROLLBACK_STRATEGY)
        && capability.mutation_contract_gaps().is_empty()
}

pub(super) fn access_operator_group_policy_identity(input: &CallInput) -> Result<(&str, &str)> {
    let body = input
        .body
        .as_ref()
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CliError::Input(
                "operator-group Access policy requires a complete object body".to_owned(),
            )
        })?;
    let name = body
        .get("name")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input("operator-group Access policy requires an exact policy name".to_owned())
        })?;
    let group_id = body
        .get("include")
        .and_then(Value::as_array)
        .filter(|include| include.len() == 1)
        .and_then(|include| include[0].pointer("/group/id"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "operator-group Access policy requires exactly one operator-group eligibility rule"
                    .to_owned(),
            )
        })?;
    Ok((name, group_id))
}

pub(super) fn validate_access_operator_group_policy_input(
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<()> {
    if !is_access_operator_group_policy_create(capability)
        && !is_access_operator_group_policy_update(capability)
    {
        return Err(CliError::Input(
            "operator-group Access policy capability drifted from its governed closed contract"
                .to_owned(),
        ));
    }
    preflight_call_input(capability, input, None)?;
    access_operator_group_policy_identity(input)?;
    Ok(())
}

pub(super) fn access_operator_group_policy_restorable_body(result: &Value) -> Result<Value> {
    let result = result.as_object().ok_or_else(|| {
        CliError::Input(
            "operator-group Access policy read did not return an object; the mutation boundary was not crossed"
                .to_owned(),
        )
    })?;
    let known = [
        "created_at",
        "decision",
        "exclude",
        "id",
        "include",
        "name",
        "precedence",
        "require",
        "reusable",
        "session_duration",
        "uid",
        "updated_at",
    ];
    let unknown = result
        .keys()
        .filter(|field| !known.contains(&field.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if !unknown.is_empty() {
        return Err(CliError::Input(format!(
            "live operator-group Access policy contains unclassified field(s) {}; the mutation boundary was not crossed",
            unknown.join(",")
        )));
    }
    if result.get("reusable").and_then(Value::as_bool) != Some(false)
        || result.get("decision").and_then(Value::as_str) != Some("allow")
        || result
            .get("exclude")
            .and_then(Value::as_array)
            .is_none_or(|rules| !rules.is_empty())
        || result
            .get("require")
            .and_then(Value::as_array)
            .is_none_or(|rules| !rules.is_empty())
    {
        return Err(CliError::Input(
            "live policy is not one application-scoped operator-group allow policy; the mutation boundary was not crossed"
                .to_owned(),
        ));
    }
    let mut body = serde_json::Map::new();
    for field in [
        "name",
        "decision",
        "include",
        "exclude",
        "require",
        "precedence",
        "session_duration",
    ] {
        if let Some(value) = result.get(field) {
            if field == "session_duration" && value.as_str() == Some("") {
                continue;
            }
            body.insert(field.to_owned(), value.clone());
        }
    }
    let body = Value::Object(body);
    let probe = CallInput {
        body: Some(body.clone()),
        ..CallInput::default()
    };
    access_operator_group_policy_identity(&probe)?;
    Ok(body)
}

pub(super) fn access_human_policy_identity_rule_schema() -> Value {
    json!({
        "oneOf":[
            {
                "type":"object",
                "additionalProperties":false,
                "required":["email"],
                "properties":{
                    "email":{
                        "type":"object",
                        "additionalProperties":false,
                        "required":["email"],
                        "properties":{
                            "email":{
                                "type":"string",
                                "format":"email",
                                "minLength":3,
                                "maxLength":254
                            }
                        }
                    }
                }
            },
            {
                "type":"object",
                "additionalProperties":false,
                "required":["email_domain"],
                "properties":{
                    "email_domain":{
                        "type":"object",
                        "additionalProperties":false,
                        "required":["domain"],
                        "properties":{
                            "domain":{
                                "type":"string",
                                "format":"hostname",
                                "minLength":3,
                                "maxLength":253
                            }
                        }
                    }
                }
            }
        ]
    })
}

pub(super) fn access_human_policy_mfa_schema() -> Value {
    json!({
        "type":"object",
        "additionalProperties":false,
        "required":["allowed_authenticators","mfa_disabled"],
        "properties":{
            "allowed_authenticators":{
                "type":"array",
                "minItems":1,
                "maxItems":3,
                "uniqueItems":true,
                "items":{
                    "type":"string",
                    "enum":["totp","biometrics","security_key"]
                }
            },
            "mfa_disabled":{"type":"boolean"},
            "session_duration":{"type":"string","minLength":2,"maxLength":16}
        }
    })
}

pub(super) fn access_human_policy_desired_schema() -> Value {
    let identity_rule = access_human_policy_identity_rule_schema();
    json!({
        "type":"object",
        "additionalProperties":false,
        "minProperties":1,
        "properties":{
            "include":{
                "type":"array",
                "minItems":1,
                "maxItems":100,
                "uniqueItems":true,
                "items":identity_rule.clone()
            },
            "exclude":{
                "type":"array",
                "maxItems":100,
                "uniqueItems":true,
                "items":identity_rule
            },
            "mfa_config":access_human_policy_mfa_schema()
        },
        "x-cfctl-body-required":true
    })
}

pub(super) fn caller_facing_capability(capability: &CapabilityV1) -> CapabilityV1 {
    let mut public = capability.clone();
    if is_access_application_owned_whole_host_mutation(capability) {
        public.request_schema = Some(cfctl_catalog::access_application_owned_whole_host_schema());
    } else if is_access_application_login_methods_mutation(capability) {
        public.request_schema = Some(access_application_login_methods_desired_schema());
    } else if is_access_human_policy_mutation(capability) {
        public.request_schema = Some(access_human_policy_desired_schema());
    }
    public
}

pub(super) fn is_access_application_owned_whole_host_mutation(capability: &CapabilityV1) -> bool {
    capability.id == ACCESS_APP_OWNED_WHOLE_HOST_CAPABILITY_ID
        && is_access_application_login_methods_mutation(capability)
}

pub(super) fn validate_access_application_owned_whole_host_input(
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<()> {
    if !is_access_application_owned_whole_host_mutation(capability) {
        return Err(CliError::Input(
            "owned whole-host Access application capability drifted from its governed exact-update contract"
                .to_owned(),
        ));
    }
    preflight_call_input(capability, input, None)?;
    let body = input
        .body
        .as_ref()
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CliError::Input(
                "owned whole-host Access application requires a complete object body".to_owned(),
            )
        })?;
    if body.get("type").and_then(Value::as_str) != Some("self_hosted") {
        return Err(CliError::Input(
            "owned whole-host Access application type must be exactly `self_hosted`".to_owned(),
        ));
    }
    let domain = body
        .get("domain")
        .and_then(Value::as_str)
        .filter(|value| *value == value.to_ascii_lowercase() && !value.contains('*'))
        .ok_or_else(|| {
            CliError::Input(
                "owned whole-host Access application domain must be a normalized lowercase hostname without wildcards"
                    .to_owned(),
            )
        })?;
    let self_hosted_domains = body
        .get("self_hosted_domains")
        .and_then(Value::as_array)
        .filter(|values| values.len() == 1)
        .and_then(|values| values[0].as_str())
        .filter(|value| *value == domain)
        .ok_or_else(|| {
            CliError::Input(
                "owned whole-host Access application must declare exactly its selected domain in self_hosted_domains"
                    .to_owned(),
            )
        })?;
    let destination = body
        .get("destinations")
        .and_then(Value::as_array)
        .filter(|values| values.len() == 1)
        .and_then(|values| values[0].as_object())
        .filter(|value| {
            value.len() == 2 && value.get("type").and_then(Value::as_str) == Some("public")
        })
        .and_then(|value| value.get("uri"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "owned whole-host Access application requires exactly one public destination"
                    .to_owned(),
            )
        })?;
    if destination != self_hosted_domains {
        return Err(CliError::Input(
            "owned whole-host Access application destination must be the exact bare whole hostname"
                .to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn validate_access_human_policy_desired_input(
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<()> {
    if !is_access_human_policy_mutation(capability) {
        return Err(CliError::Input(
            "human Access policy capability drifted from its governed preservation-safe contract"
                .to_owned(),
        ));
    }
    let mut desired_capability = capability.clone();
    desired_capability.request_schema = Some(access_human_policy_desired_schema());
    validate_request_contract(&desired_capability, input)?;
    access_human_policy_desired_changes(input)?;
    Ok(())
}

pub(super) fn normalized_access_human_identity_rules(
    value: &Value,
    require_nonempty: bool,
) -> Result<Value> {
    let values = value.as_array().ok_or_else(|| {
        CliError::Input("human Access identity rules must be an array".to_owned())
    })?;
    if require_nonempty && values.is_empty() {
        return Err(CliError::Input(
            "human Access policy include rules must not be empty".to_owned(),
        ));
    }
    if values.len() > 100 {
        return Err(CliError::Input(
            "human Access policy identity rules exceed the bounded 100-rule contract".to_owned(),
        ));
    }
    let mut normalized = values
        .iter()
        .map(|value| {
            let rule = value.as_object().filter(|rule| rule.len() == 1).ok_or_else(|| {
                CliError::Input(
                    "human Access policy rules must contain exactly one email or email_domain selector"
                        .to_owned(),
                )
            })?;
            if let Some(email) = rule.get("email") {
                let email = email
                    .as_object()
                    .filter(|email| email.len() == 1)
                    .and_then(|email| email.get("email"))
                    .and_then(Value::as_str)
                    .filter(|email| !email.is_empty())
                    .ok_or_else(|| {
                        CliError::Input(
                            "human Access email rules require one non-empty email value".to_owned(),
                        )
                    })?;
                return Ok(("email".to_owned(), email.to_owned()));
            }
            let domain = rule
                .get("email_domain")
                .and_then(Value::as_object)
                .filter(|domain| domain.len() == 1)
                .and_then(|domain| domain.get("domain"))
                .and_then(Value::as_str)
                .filter(|domain| !domain.is_empty())
                .ok_or_else(|| {
                    CliError::Input(
                        "human Access policy rules admit only one non-empty email or email_domain selector"
                            .to_owned(),
                    )
                })?;
            Ok(("email_domain".to_owned(), domain.to_owned()))
        })
        .collect::<Result<Vec<_>>>()?;
    normalized.sort();
    if normalized.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(CliError::Input(
            "human Access policy identity rules must be unique".to_owned(),
        ));
    }
    Ok(Value::Array(
        normalized
            .into_iter()
            .map(|(kind, value)| match kind.as_str() {
                "email" => json!({"email":{"email":value}}),
                _ => json!({"email_domain":{"domain":value}}),
            })
            .collect(),
    ))
}

pub(super) fn normalized_access_human_mfa_config(
    value: &Value,
    tolerate_empty_provider_duration: bool,
) -> Result<Value> {
    let config = value.as_object().ok_or_else(|| {
        CliError::Input("human Access MFA configuration must be an object".to_owned())
    })?;
    let known_fields = ["allowed_authenticators", "mfa_disabled", "session_duration"];
    let unknown_fields = config
        .keys()
        .filter(|field| !known_fields.contains(&field.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if !unknown_fields.is_empty() {
        return Err(CliError::Input(format!(
            "human Access MFA configuration contains unclassified field(s) {}",
            unknown_fields.join(",")
        )));
    }
    let mut authenticators = config
        .get("allowed_authenticators")
        .and_then(Value::as_array)
        .filter(|values| !values.is_empty() && values.len() <= 3)
        .ok_or_else(|| {
            CliError::Input(
                "human Access MFA requires between one and three authenticators".to_owned(),
            )
        })?
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|value| matches!(*value, "totp" | "biometrics" | "security_key"))
                .map(str::to_owned)
                .ok_or_else(|| {
                    CliError::Input(
                        "human Access MFA admits only totp, biometrics, and security_key"
                            .to_owned(),
                    )
                })
        })
        .collect::<Result<Vec<_>>>()?;
    authenticators.sort();
    if authenticators.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(CliError::Input(
            "human Access MFA authenticators must be unique".to_owned(),
        ));
    }
    let mfa_disabled = config
        .get("mfa_disabled")
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            CliError::Input(
                "human Access MFA configuration requires a boolean mfa_disabled value".to_owned(),
            )
        })?;
    let mut normalized = Map::new();
    normalized.insert("allowed_authenticators".to_owned(), json!(authenticators));
    normalized.insert("mfa_disabled".to_owned(), json!(mfa_disabled));
    if let Some(duration) = config.get("session_duration") {
        let duration = duration.as_str().ok_or_else(|| {
            CliError::Input("human Access MFA session duration must be a string".to_owned())
        })?;
        if duration.is_empty() && tolerate_empty_provider_duration {
            return Ok(Value::Object(normalized));
        }
        if duration.is_empty() {
            return Err(CliError::Input(
                "human Access MFA session duration must not be empty".to_owned(),
            ));
        }
        normalized.insert("session_duration".to_owned(), json!(duration));
    }
    Ok(Value::Object(normalized))
}

pub(super) fn access_human_policy_desired_changes(input: &CallInput) -> Result<Map<String, Value>> {
    let desired = input
        .body
        .as_ref()
        .and_then(Value::as_object)
        .filter(|desired| !desired.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "human Access policy input requires at least one eligibility or MFA change"
                    .to_owned(),
            )
        })?;
    let unknown_fields = desired
        .keys()
        .filter(|field| !ACCESS_HUMAN_POLICY_DESIRED_FIELDS.contains(&field.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if !unknown_fields.is_empty() {
        return Err(CliError::Input(format!(
            "human Access policy desired input contains unclassified field(s) {}",
            unknown_fields.join(",")
        )));
    }
    let mut normalized = Map::new();
    for (field, value) in desired {
        let value = match field.as_str() {
            "include" => normalized_access_human_identity_rules(value, true)?,
            "exclude" => normalized_access_human_identity_rules(value, false)?,
            "mfa_config" => normalized_access_human_mfa_config(value, false)?,
            _ => unreachable!("unknown desired fields were rejected"),
        };
        normalized.insert(field.clone(), value);
    }
    Ok(normalized)
}

pub(super) fn access_human_policy_mutable_body(
    result: &Value,
    desired: &Map<String, Value>,
) -> Result<Value> {
    access_human_policy_projected_body(
        result,
        desired,
        AccessHumanPolicySnapshotMode::LiveApplicationScoped,
    )
}

pub(super) fn access_human_policy_restorable_body(result: &Value) -> Result<Value> {
    access_human_policy_projected_body(
        result,
        &Map::new(),
        AccessHumanPolicySnapshotMode::CuratedRollback,
    )
}

#[derive(Clone, Copy)]
pub(super) enum AccessHumanPolicySnapshotMode {
    LiveApplicationScoped,
    CuratedRollback,
}

pub(super) fn validate_access_human_policy_snapshot(
    result: &Map<String, Value>,
    mode: AccessHumanPolicySnapshotMode,
) -> Result<()> {
    let mut known_fields = ACCESS_HUMAN_POLICY_MUTABLE_FIELDS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if matches!(mode, AccessHumanPolicySnapshotMode::LiveApplicationScoped) {
        known_fields.extend(ACCESS_HUMAN_POLICY_READ_ONLY_FIELDS);
    }
    let unknown_fields = result
        .keys()
        .filter(|field| !known_fields.contains(field.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if !unknown_fields.is_empty() {
        return Err(CliError::Input(format!(
            "live human Access policy contains unclassified field(s) {}; the preservation-safe mutation boundary was not crossed",
            unknown_fields.join(",")
        )));
    }
    if matches!(mode, AccessHumanPolicySnapshotMode::LiveApplicationScoped)
        && result.get("reusable").and_then(Value::as_bool) != Some(false)
    {
        return Err(CliError::Input(
            "live Access policy is reusable or omitted its reusable classification; application-scoped policy updates cannot preserve that routing contract, so the mutation boundary was not crossed"
                .to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn access_human_policy_projected_body(
    result: &Value,
    desired: &Map<String, Value>,
    mode: AccessHumanPolicySnapshotMode,
) -> Result<Value> {
    let result = result.as_object().ok_or_else(|| {
        CliError::Input(
            "live human Access policy read did not return an object; the mutation boundary was not crossed"
                .to_owned(),
        )
    })?;
    validate_access_human_policy_snapshot(result, mode)?;
    if result.get("decision").and_then(Value::as_str) != Some("allow") {
        return Err(CliError::Input(
            "live Access policy is not a human allow policy; the mutation boundary was not crossed"
                .to_owned(),
        ));
    }
    if result
        .get("require")
        .and_then(Value::as_array)
        .is_none_or(|rules| !rules.is_empty())
    {
        return Err(CliError::Input(
            "live Access policy has non-empty require rules; the human-only mutation boundary was not crossed"
                .to_owned(),
        ));
    }

    let mut body = Map::new();
    for field in ACCESS_HUMAN_POLICY_MUTABLE_FIELDS {
        let value = desired.get(field).or_else(|| result.get(field));
        let Some(value) = value else {
            if ACCESS_HUMAN_POLICY_REQUIRED_FIELDS.contains(&field) {
                return Err(CliError::Input(format!(
                    "live human Access policy omitted required mutable field `{field}`; the mutation boundary was not crossed"
                )));
            }
            continue;
        };
        let value = match field {
            "include" => normalized_access_human_identity_rules(value, true)?,
            "exclude" => normalized_access_human_identity_rules(value, false)?,
            "mfa_config" => {
                normalized_access_human_mfa_config(value, !desired.contains_key(field))?
            }
            "session_duration" => {
                let duration = value.as_str().ok_or_else(|| {
                    CliError::Input(
                        "live human Access policy session duration is not a string; the mutation boundary was not crossed"
                            .to_owned(),
                    )
                })?;
                if duration.is_empty() {
                    continue;
                }
                json!(duration)
            }
            "name" => {
                let name = value
                    .as_str()
                    .filter(|name| !name.is_empty())
                    .ok_or_else(|| {
                        CliError::Input(
                            "live human Access policy omitted its name; the mutation boundary was not crossed"
                                .to_owned(),
                        )
                    })?;
                json!(name)
            }
            "precedence" => {
                let precedence = value
                    .as_u64()
                    .filter(|precedence| *precedence > 0)
                    .ok_or_else(|| {
                        CliError::Input(
                            "live human Access policy omitted a positive precedence; the mutation boundary was not crossed"
                                .to_owned(),
                        )
                    })?;
                json!(precedence)
            }
            "decision" => json!("allow"),
            "require" => json!([]),
            _ => unreachable!("human Access policy field set is closed"),
        };
        body.insert(field.to_owned(), value);
    }
    Ok(Value::Object(body))
}

pub(super) fn access_human_policy_prior_state(result: &Value) -> Result<Value> {
    access_human_policy_mutable_body(result, &Map::new())
}

pub(super) fn access_human_policy_desired_matches_live(
    result: &Value,
    desired: &Map<String, Value>,
) -> Result<bool> {
    let current = access_human_policy_prior_state(result)?;
    let updated = access_human_policy_mutable_body(result, desired)?;
    Ok(desired
        .keys()
        .all(|field| current.get(field) == updated.get(field)))
}

pub(super) fn access_policy_read_contract_supported(capability: &CapabilityV1) -> bool {
    capability.id == ACCESS_POLICY_READ_CAPABILITY_ID
        && capability.method == "GET"
        && capability.path == ACCESS_POLICY_DETAIL_PATH
        && capability.product == "Access application-scoped policies"
        && capability.account_scope == "account"
        && !capability.mutating
        && capability.request_schema.is_none()
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        && capability.selectors.len() == 3
        && ["account_id", "app_id", "policy_id"].iter().all(|name| {
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

pub(super) async fn prepare_access_human_policy_plan_input(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &mut CallInput,
    account_id: &str,
    credential: &AuthCredential,
) -> Result<Option<(Value, EvidenceV1)>> {
    if !is_access_human_policy_mutation(capability) {
        return Ok(None);
    }
    let body = input
        .body
        .as_ref()
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CliError::Input("human Access policy plan requires an object body".to_owned())
        })?;
    let materialized_body = body
        .keys()
        .any(|field| !ACCESS_HUMAN_POLICY_DESIRED_FIELDS.contains(&field.as_str()));
    let desired = if materialized_body {
        preflight_call_input(capability, input, None)?;
        None
    } else {
        Some(access_human_policy_desired_changes(input)?)
    };
    let policy_id = input
        .selectors
        .get("policy_id")
        .and_then(Value::as_str)
        .filter(|policy_id| !policy_id.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "human Access policy plan requires an exact `policy_id` selector".to_owned(),
            )
        })?;
    let source = catalog
        .get(ACCESS_POLICY_READ_CAPABILITY_ID)
        .ok_or_else(|| capability_missing(ACCESS_POLICY_READ_CAPABILITY_ID))?;
    if !access_policy_read_contract_supported(source) {
        return Err(CliError::Input(
            "Access policy state source drifted from the governed exact-policy read".to_owned(),
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
    if !response.success || response.status != 200 {
        return Err(CliError::Input(format!(
            "Cloudflare rejected the human Access policy state read with HTTP {}; the mutation boundary was not crossed",
            response.status
        )));
    }
    if response.result.get("id").and_then(Value::as_str) != Some(policy_id) {
        return Err(CliError::Input(
            "Access policy state read returned a different or missing policy id; the mutation boundary was not crossed"
                .to_owned(),
        ));
    }
    access_human_policy_prior_state(&response.result)?;
    if let Some(desired) = desired {
        if access_human_policy_desired_matches_live(&response.result, &desired)? {
            return Err(CliError::Input(
                "human Access policy already has the exact requested eligibility and MFA state; no mutation plan was created"
                    .to_owned(),
            ));
        }
        input.body = Some(access_human_policy_mutable_body(
            &response.result,
            &desired,
        )?);
        preflight_call_input(capability, input, None)?;
    }
    let receipt = apply_same_path_prior_state_response(capability, input, account_id, &response)?;
    let evidence = store.write_observation_evidence(EvidenceClass::LiveRead, &receipt)?;
    Ok(Some((receipt, evidence)))
}
