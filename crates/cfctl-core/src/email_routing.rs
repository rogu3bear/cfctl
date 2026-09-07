//! Bounded, body-free projections of zone and account Email Routing rules.

use crate::{CapabilityV1, ResponseBodyModeV1};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const EMAIL_ROUTING_RULES_LIST_CAPABILITY_ID: &str =
    "email-routing-routing-rules-list-routing-rules";
pub const EMAIL_ROUTING_RULES_LIST_PATH: &str = "/zones/{zone_id}/email/routing/rules";
pub const EMAIL_ROUTING_ACCOUNT_RULES_LIST_CAPABILITY_ID: &str =
    "email-routing-account-rules-list-routing-rules";
pub const EMAIL_ROUTING_ACCOUNT_RULES_LIST_PATH: &str =
    "/accounts/{account_id}/email/routing/rules";
pub const EMAIL_ROUTING_RULES_PAGE_SIZE: u64 = 50;
pub const EMAIL_ROUTING_RULES_MAX_PAGES: u64 = 100;
const EMAIL_ROUTING_RULES_MAX_MATCHERS: usize = 32;
const EMAIL_ROUTING_RULES_MAX_ACTIONS: usize = 32;
const EMAIL_ROUTING_RULES_MAX_ACTION_VALUES: usize = 100;
const EMAIL_ROUTING_RULES_MAX_STRING_BYTES: usize = 4_096;
const EMAIL_ROUTING_RULE_IDENTIFIER_MAX_BYTES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailRoutingRuleSetV1 {
    pub schema_version: u8,
    pub complete: bool,
    pub page_size: u64,
    pub pages: u64,
    pub rule_count: usize,
    pub rules: Vec<EmailRoutingRuleV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailRoutingRuleV1 {
    pub rule_identifier: String,
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone_name_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone_tag_sha256: Option<String>,
    pub matchers: Vec<EmailRoutingMatcherV1>,
    pub actions: Vec<EmailRoutingActionV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailRoutingMatcherV1 {
    pub matcher_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailRoutingActionV1 {
    pub action_type: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub worker_targets: Vec<String>,
    pub value_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailRoutingRuleDiagnosticV1 {
    pub schema_version: u8,
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_index: Option<usize>,
    pub component: String,
}

impl EmailRoutingRuleDiagnosticV1 {
    #[must_use]
    pub fn new(code: &str, rule_index: Option<usize>, component: &str) -> Self {
        Self {
            schema_version: 1,
            code: code.to_owned(),
            rule_index,
            component: component.to_owned(),
        }
    }
}

#[must_use]
pub fn is_email_routing_rules_list_capability(capability: &CapabilityV1) -> bool {
    ((capability.id == EMAIL_ROUTING_RULES_LIST_CAPABILITY_ID
        && capability.path == EMAIL_ROUTING_RULES_LIST_PATH)
        || (capability.id == EMAIL_ROUTING_ACCOUNT_RULES_LIST_CAPABILITY_ID
            && capability.path == EMAIL_ROUTING_ACCOUNT_RULES_LIST_PATH))
        && capability.method == "GET"
        && !capability.mutating
        && capability
            .response_contract
            .as_ref()
            .is_some_and(|contract| {
                contract.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
            })
}

pub fn normalize_email_routing_rule_set(
    value: &Value,
    pages: u64,
) -> std::result::Result<EmailRoutingRuleSetV1, EmailRoutingRuleDiagnosticV1> {
    normalize_email_routing_rule_set_with_page_size(value, pages, EMAIL_ROUTING_RULES_PAGE_SIZE)
}

pub fn normalize_email_routing_rule_set_with_page_size(
    value: &Value,
    pages: u64,
    page_size: u64,
) -> std::result::Result<EmailRoutingRuleSetV1, EmailRoutingRuleDiagnosticV1> {
    normalize_email_routing_rule_set_with_scope(value, pages, page_size, false)
}

pub fn normalize_email_routing_account_rule_set(
    value: &Value,
    pages: u64,
) -> std::result::Result<EmailRoutingRuleSetV1, EmailRoutingRuleDiagnosticV1> {
    normalize_email_routing_account_rule_set_with_page_size(
        value,
        pages,
        EMAIL_ROUTING_RULES_PAGE_SIZE,
    )
}

pub fn normalize_email_routing_account_rule_set_with_page_size(
    value: &Value,
    pages: u64,
    page_size: u64,
) -> std::result::Result<EmailRoutingRuleSetV1, EmailRoutingRuleDiagnosticV1> {
    normalize_email_routing_rule_set_with_scope(value, pages, page_size, true)
}

fn normalize_email_routing_rule_set_with_scope(
    value: &Value,
    pages: u64,
    page_size: u64,
    account_scoped: bool,
) -> std::result::Result<EmailRoutingRuleSetV1, EmailRoutingRuleDiagnosticV1> {
    if !(1..=EMAIL_ROUTING_RULES_MAX_PAGES).contains(&pages) {
        return Err(EmailRoutingRuleDiagnosticV1::new(
            "page_bound_invalid",
            None,
            "pagination",
        ));
    }
    if !(1..=EMAIL_ROUTING_RULES_PAGE_SIZE).contains(&page_size) {
        return Err(EmailRoutingRuleDiagnosticV1::new(
            "page_size_invalid",
            None,
            "pagination",
        ));
    }
    let rules = value
        .as_array()
        .ok_or_else(|| EmailRoutingRuleDiagnosticV1::new("rules_not_array", None, "rules"))?;
    let maximum_rules = usize::try_from(
        EMAIL_ROUTING_RULES_PAGE_SIZE.saturating_mul(EMAIL_ROUTING_RULES_MAX_PAGES),
    )
    .unwrap_or(usize::MAX);
    if rules.len() > maximum_rules {
        return Err(EmailRoutingRuleDiagnosticV1::new(
            "rule_bound_exceeded",
            None,
            "rules",
        ));
    }
    let normalized = rules
        .iter()
        .enumerate()
        .map(|(rule_index, rule)| normalize_email_routing_rule(rule, rule_index, account_scoped))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(EmailRoutingRuleSetV1 {
        schema_version: 1,
        complete: true,
        page_size,
        pages,
        rule_count: normalized.len(),
        rules: normalized,
    })
}

fn normalize_email_routing_rule(
    value: &Value,
    rule_index: usize,
    account_scoped: bool,
) -> std::result::Result<EmailRoutingRuleV1, EmailRoutingRuleDiagnosticV1> {
    let rule = value.as_object().ok_or_else(|| {
        EmailRoutingRuleDiagnosticV1::new("rule_not_object", Some(rule_index), "rule")
    })?;
    let bounded_identifier = |value| {
        bounded_email_routing_string(value).filter(|identifier| {
            identifier.len() <= EMAIL_ROUTING_RULE_IDENTIFIER_MAX_BYTES
                && identifier
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
    };
    let rule_identifier = if account_scoped {
        bounded_identifier(rule.get("id")).or_else(|| bounded_identifier(rule.get("tag")))
    } else {
        bounded_identifier(rule.get("tag"))
    }
    .ok_or_else(|| {
        EmailRoutingRuleDiagnosticV1::new(
            "rule_identifier_invalid",
            Some(rule_index),
            if account_scoped {
                "rule.id_or_tag"
            } else {
                "rule.tag"
            },
        )
    })?;
    let enabled = rule
        .get("enabled")
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            EmailRoutingRuleDiagnosticV1::new("enabled_not_boolean", Some(rule_index), "enabled")
        })?;
    let (zone_name_sha256, zone_tag_sha256) = if account_scoped {
        let zone = rule.get("zone").and_then(Value::as_object).ok_or_else(|| {
            EmailRoutingRuleDiagnosticV1::new("zone_not_object", Some(rule_index), "zone")
        })?;
        let zone_name = bounded_email_routing_string(zone.get("name"))
            .and_then(|name| normalize_email_routing_domain(&name))
            .ok_or_else(|| {
                EmailRoutingRuleDiagnosticV1::new(
                    "zone_name_invalid",
                    Some(rule_index),
                    "zone.name",
                )
            })?;
        let zone_tag = bounded_email_routing_string(zone.get("tag")).ok_or_else(|| {
            EmailRoutingRuleDiagnosticV1::new("zone_tag_invalid", Some(rule_index), "zone.tag")
        })?;
        (
            Some(format!(
                "sha256:{}",
                hex::encode(Sha256::digest(zone_name.as_bytes()))
            )),
            Some(format!(
                "sha256:{}",
                hex::encode(Sha256::digest(zone_tag.as_bytes()))
            )),
        )
    } else {
        (None, None)
    };
    let matcher_values = bounded_email_routing_array(
        rule.get("matchers"),
        EMAIL_ROUTING_RULES_MAX_MATCHERS,
        "matchers_not_bounded_array",
        rule_index,
        "matchers",
    )?;
    let action_values = bounded_email_routing_array(
        rule.get("actions"),
        EMAIL_ROUTING_RULES_MAX_ACTIONS,
        "actions_not_bounded_array",
        rule_index,
        "actions",
    )?;
    let matchers = matcher_values
        .iter()
        .map(|matcher| normalize_email_routing_matcher(matcher, rule_index))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let actions = action_values
        .iter()
        .map(|action| normalize_email_routing_action(action, rule_index))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(EmailRoutingRuleV1 {
        rule_identifier,
        enabled,
        zone_name_sha256,
        zone_tag_sha256,
        matchers,
        actions,
    })
}

fn normalize_email_routing_domain(value: &str) -> Option<String> {
    let normalized = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.len() > 253
        || !normalized.contains('.')
        || normalized.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        None
    } else {
        Some(normalized)
    }
}

fn bounded_email_routing_array<'a>(
    value: Option<&'a Value>,
    maximum: usize,
    code: &str,
    rule_index: usize,
    component: &str,
) -> std::result::Result<&'a [Value], EmailRoutingRuleDiagnosticV1> {
    value
        .and_then(Value::as_array)
        .filter(|values| !values.is_empty() && values.len() <= maximum)
        .map(Vec::as_slice)
        .ok_or_else(|| EmailRoutingRuleDiagnosticV1::new(code, Some(rule_index), component))
}

fn normalize_email_routing_matcher(
    value: &Value,
    rule_index: usize,
) -> std::result::Result<EmailRoutingMatcherV1, EmailRoutingRuleDiagnosticV1> {
    let matcher = value.as_object().ok_or_else(|| {
        EmailRoutingRuleDiagnosticV1::new("matcher_not_object", Some(rule_index), "matcher")
    })?;
    let matcher_type = bounded_email_routing_string(matcher.get("type")).ok_or_else(|| {
        EmailRoutingRuleDiagnosticV1::new("matcher_type_invalid", Some(rule_index), "matcher.type")
    })?;
    let field = matcher.get("field");
    let value = matcher.get("value");
    let (field, value_sha256) = match (field, value) {
        (None, None) => (None, None),
        (Some(field), Some(value)) => {
            let field = bounded_email_routing_string(Some(field)).ok_or_else(|| {
                EmailRoutingRuleDiagnosticV1::new(
                    "matcher_field_invalid",
                    Some(rule_index),
                    "matcher.field",
                )
            })?;
            let value = bounded_email_routing_string(Some(value)).ok_or_else(|| {
                EmailRoutingRuleDiagnosticV1::new(
                    "matcher_value_invalid",
                    Some(rule_index),
                    "matcher.value",
                )
            })?;
            (
                Some(field),
                Some(format!(
                    "sha256:{}",
                    hex::encode(Sha256::digest(value.as_bytes()))
                )),
            )
        }
        _ => {
            return Err(EmailRoutingRuleDiagnosticV1::new(
                "matcher_pair_incomplete",
                Some(rule_index),
                "matcher",
            ));
        }
    };
    Ok(EmailRoutingMatcherV1 {
        matcher_type,
        field,
        value_sha256,
    })
}

fn normalize_email_routing_action(
    value: &Value,
    rule_index: usize,
) -> std::result::Result<EmailRoutingActionV1, EmailRoutingRuleDiagnosticV1> {
    let action = value.as_object().ok_or_else(|| {
        EmailRoutingRuleDiagnosticV1::new("action_not_object", Some(rule_index), "action")
    })?;
    let action_type = bounded_email_routing_string(action.get("type")).ok_or_else(|| {
        EmailRoutingRuleDiagnosticV1::new("action_type_invalid", Some(rule_index), "action.type")
    })?;
    let values = match (action_type.as_str(), action.get("value")) {
        ("drop", None) => Vec::new(),
        ("drop", Some(Value::Array(values))) if values.is_empty() => Vec::new(),
        (action_type, Some(Value::Array(values)))
            if action_type != "drop" && values.len() <= EMAIL_ROUTING_RULES_MAX_ACTION_VALUES =>
        {
            values
                .iter()
                .map(|value| bounded_email_routing_string(Some(value)))
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| {
                    EmailRoutingRuleDiagnosticV1::new(
                        "action_values_invalid",
                        Some(rule_index),
                        "action.value",
                    )
                })?
        }
        _ => {
            return Err(EmailRoutingRuleDiagnosticV1::new(
                "action_values_invalid",
                Some(rule_index),
                "action.value",
            ));
        }
    };
    let worker_targets = if action_type == "worker" {
        if values
            .iter()
            .any(|value| value.contains('@') || value.chars().any(char::is_control))
        {
            return Err(EmailRoutingRuleDiagnosticV1::new(
                "worker_target_invalid",
                Some(rule_index),
                "action.value",
            ));
        }
        values.clone()
    } else {
        Vec::new()
    };
    Ok(EmailRoutingActionV1 {
        action_type,
        worker_targets,
        value_count: values.len(),
    })
}

fn bounded_email_routing_string(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty()
                && value.len() <= EMAIL_ROUTING_RULES_MAX_STRING_BYTES
                && !value.chars().any(char::is_control)
        })
        .map(str::to_owned)
}
