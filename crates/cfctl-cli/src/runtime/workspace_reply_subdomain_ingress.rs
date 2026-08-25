use std::collections::BTreeSet;

use cfctl_auth::{AuthCredential, ProfileMetadata};
use cfctl_catalog::CatalogSnapshot;
use cfctl_cloudflare::{CallInput, CloudflareResponseV1, Executor};
use cfctl_core::{AdapterStatus, CapabilityV1, ResponseBodyModeV1};
use cfctl_storage::StateStore;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{API_BASE_URL, CliError, Result, http_client};

const ZONE_LIST_PATH: &str = "/zones";
const ZONE_LIST_ID: &str = "zones-get";
const SUBDOMAIN_DNS_ID: &str = "email-routing-settings-email-routing-dns-settings";
const SUBDOMAIN_DNS_PATH: &str = "/zones/{zone_id}/email/routing/dns";
const ACCOUNT_RULES_ID: &str = cfctl_core::EMAIL_ROUTING_ACCOUNT_RULES_LIST_CAPABILITY_ID;
const ACCOUNT_RULES_PATH: &str = cfctl_core::EMAIL_ROUTING_ACCOUNT_RULES_LIST_PATH;
const CANONICAL_MX: [&str; 3] = [
    "route1.mx.cloudflare.net",
    "route2.mx.cloudflare.net",
    "route3.mx.cloudflare.net",
];
const RESULT_KEYS: [&str; 12] = [
    "adapter",
    "success",
    "boundary_crossed",
    "schema_version",
    "reply_domain_sha256",
    "worker_target_sha256",
    "dns_scope",
    "routing_scope",
    "dns",
    "routing_rule",
    "provider_output_retained",
    "body_returned",
];
const DNS_RESULT_INFO_KEYS: [&str; 7] = [
    "page",
    "per_page",
    "total_pages",
    "count",
    "total_count",
    "cfctl_pages",
    "cfctl_page_complete",
];

pub(super) fn load(store: &StateStore, id: &str) -> Result<Option<CapabilityV1>> {
    Ok(
        cfctl_workspace::load_workspace_reply_subdomain_ingress_capability(
            &store.workspace_roots()?,
            id,
        )?,
    )
}

pub(super) fn receipt_is_complete(receipt: &Value) -> bool {
    let Some(object) = receipt.as_object() else {
        return false;
    };
    object.len() == RESULT_KEYS.len()
        && RESULT_KEYS.iter().all(|key| object.contains_key(*key))
        && receipt.get("adapter").and_then(Value::as_str)
            == Some(cfctl_workspace::MAILDESK_REPLY_SUBDOMAIN_INGRESS_PROJECTION)
        && receipt.get("success").and_then(Value::as_bool) == Some(true)
        && receipt.get("boundary_crossed").and_then(Value::as_bool) == Some(true)
        && receipt.get("schema_version").and_then(Value::as_u64) == Some(1)
        && ["reply_domain_sha256", "worker_target_sha256"]
            .iter()
            .all(|key| {
                receipt
                    .get(*key)
                    .and_then(Value::as_str)
                    .is_some_and(is_sha256)
            })
        && receipt.get("dns_scope").and_then(Value::as_str) == Some("exact_reply_subdomain")
        && receipt.get("routing_scope").and_then(Value::as_str)
            == Some("exact_reply_subdomain_catch_all_to_worker")
        && ["dns", "routing_rule"].iter().all(|key| {
            matches!(
                receipt.get(*key).and_then(Value::as_str),
                Some("ok" | "drift" | "missing")
            )
        })
        && receipt
            .get("provider_output_retained")
            .and_then(Value::as_bool)
            == Some(false)
        && receipt.get("body_returned").and_then(Value::as_bool) == Some(false)
}

#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "profile, account, credential generation, catalog, credential, and workspace contract stay explicit at the composed provider-read boundary"
)]
pub(super) async fn read(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    credential: &AuthCredential,
    profile: &ProfileMetadata,
    account_id: &str,
    credential_generation_id: &str,
) -> Result<Value> {
    let contract = capability
        .workspace_reply_subdomain_ingress
        .as_ref()
        .ok_or_else(|| CliError::Input("reply-subdomain ingress contract missing".to_owned()))?;
    let current = load(store, &capability.id)?.ok_or_else(|| {
        CliError::Input(
            "reply-subdomain ingress authority is no longer uniquely available".to_owned(),
        )
    })?;
    if current.workspace_reply_subdomain_ingress.as_ref() != Some(contract) {
        return Err(CliError::Input(
            "reply-subdomain ingress repository authority drifted".to_owned(),
        ));
    }
    if profile.account_id.as_deref() != Some(account_id)
        || profile.credential_generation_id.as_deref() != Some(credential_generation_id)
    {
        return Err(CliError::Input(
            "reply-subdomain ingress profile, account, or credential generation binding drifted"
                .to_owned(),
        ));
    }
    let target = target(input, account_id)?;
    let zone_capability = exact_zone_list_capability(catalog)?;
    let dns_capability = exact_capability(catalog, SUBDOMAIN_DNS_ID, SUBDOMAIN_DNS_PATH)?;
    let account_rules_capability = exact_capability(catalog, ACCOUNT_RULES_ID, ACCOUNT_RULES_PATH)?;
    validate_provider_contracts(zone_capability, dns_capability, account_rules_capability)?;

    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let mut zone_id = None;
    for parent_zone in parent_zone_candidates(&target.reply_domain) {
        let Ok(zone) = executor
            .execute_read(
                zone_capability,
                &CallInput {
                    query: json!({
                        "account.id":account_id,
                        "name":parent_zone,
                        "page":1,
                        "per_page":50,
                    }),
                    ..CallInput::default()
                },
                credential,
            )
            .await
        else {
            return Ok(failure(
                "parent_zone_read_failed",
                "parent_zone",
                true,
                None,
            ));
        };
        match project_zone(&zone, &target.account_id, &parent_zone) {
            Ok(ZoneState::Missing) => {}
            Ok(ZoneState::Drift) => {
                return Ok(failure(
                    "parent_zone_inactive",
                    "parent_zone",
                    true,
                    Some(1),
                ));
            }
            Ok(ZoneState::Active(id)) => {
                zone_id = Some(id);
                break;
            }
            Err(receipt) => return Ok(receipt),
        }
    }
    let Some(zone_id) = zone_id else {
        return Ok(failure("parent_zone_missing", "parent_zone", true, Some(0)));
    };

    let Ok(dns) = executor
        .execute_read(
            dns_capability,
            &CallInput {
                selectors: json!({"zone_id":zone_id}),
                query: json!({"subdomain":target.reply_domain}),
                ..CallInput::default()
            },
            credential,
        )
        .await
    else {
        return Ok(failure("dns_read_failed", "dns", true, None));
    };
    let dns_state = match project_subdomain_dns(&dns, &target.reply_domain) {
        Ok(state) => state,
        Err(receipt) => return Ok(receipt),
    };
    let Ok(account_rules) = executor
        .execute_read(
            account_rules_capability,
            &CallInput {
                selectors: json!({"account_id":target.account_id}),
                ..CallInput::default()
            },
            credential,
        )
        .await
    else {
        return Ok(failure(
            "account_rules_read_failed",
            "routing_rule",
            true,
            None,
        ));
    };
    let routing_state = match project_account_rules(&account_rules, &target, &zone_id) {
        Ok(state) => state,
        Err(receipt) => return Ok(receipt),
    };
    Ok(success(&target, dns_state, routing_state))
}

#[derive(Debug)]
struct Target {
    account_id: String,
    reply_domain: String,
    worker_script_name: String,
}

fn target(input: &CallInput, account_id: &str) -> Result<Target> {
    let selectors = input.selectors.as_object().ok_or_else(|| {
        CliError::Input("reply-subdomain ingress requires exact selectors".to_owned())
    })?;
    if input.body.is_some()
        || input
            .query
            .as_object()
            .is_none_or(|query| !query.is_empty())
        || selectors.len() != 3
        || selectors.get("account_id").and_then(Value::as_str) != Some(account_id)
    {
        return Err(CliError::Input(
            "reply-subdomain ingress accepts only exact account_id, reply_domain, and worker_script_name selectors"
                .to_owned(),
        ));
    }
    let reply_domain = selectors
        .get("reply_domain")
        .and_then(Value::as_str)
        .and_then(normalize_domain)
        .ok_or_else(|| CliError::Input("reply_domain is not a valid exact DNS name".to_owned()))?;
    let worker_script_name = selectors
        .get("worker_script_name")
        .and_then(Value::as_str)
        .filter(|value| valid_worker_name(value))
        .ok_or_else(|| CliError::Input("worker_script_name is invalid".to_owned()))?
        .to_owned();
    Ok(Target {
        account_id: account_id.to_owned(),
        reply_domain,
        worker_script_name,
    })
}

#[derive(Debug, PartialEq, Eq)]
enum ZoneState {
    Missing,
    Drift,
    Active(String),
}

fn project_zone(
    response: &CloudflareResponseV1,
    account_id: &str,
    expected_zone: &str,
) -> std::result::Result<ZoneState, Value> {
    if !successful_complete_page(response) {
        return Err(failure("zone_read_incomplete", "zone", true, None));
    }
    let Some(zones) = response.result.as_array() else {
        return Err(failure("zone_projection_malformed", "zone", true, None));
    };
    if zones.is_empty() {
        return Ok(ZoneState::Missing);
    }
    if zones.len() != 1 {
        return Err(failure(
            "zone_cardinality_ambiguous",
            "zone",
            true,
            Some(zones.len()),
        ));
    }
    let zone = &zones[0];
    let exact = zone
        .get("name")
        .and_then(Value::as_str)
        .and_then(normalize_domain)
        .as_deref()
        == Some(expected_zone)
        && zone.pointer("/account/id").and_then(Value::as_str) == Some(account_id)
        && zone
            .get("id")
            .and_then(Value::as_str)
            .is_some_and(|id| !id.is_empty())
        && zone.get("status").and_then(Value::as_str).is_some();
    if !exact {
        return Err(failure("zone_projection_malformed", "zone", true, Some(1)));
    }
    if zone.get("status").and_then(Value::as_str) != Some("active") {
        return Ok(ZoneState::Drift);
    }
    Ok(ZoneState::Active(
        zone.get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
    ))
}

fn project_subdomain_dns(
    response: &CloudflareResponseV1,
    reply_domain: &str,
) -> std::result::Result<&'static str, Value> {
    if !response.success || response.status != 200 || !response.errors.is_empty() {
        return Err(failure("dns_read_incomplete", "dns", true, None));
    }
    let records = if let Some(records) = response.result.as_array() {
        records
    } else if let Some(result) = response.result.as_object() {
        if result
            .get("errors")
            .is_some_and(|errors| !errors.is_array())
        {
            return Err(failure("dns_projection_malformed", "dns", true, None));
        }
        if result
            .get("errors")
            .and_then(Value::as_array)
            .is_some_and(|errors| !errors.is_empty())
        {
            return Ok("drift");
        }
        let Some(records) = result.get("record").and_then(Value::as_array) else {
            return Err(failure("dns_projection_malformed", "dns", true, None));
        };
        records
    } else {
        return Err(failure("dns_projection_malformed", "dns", true, None));
    };
    if !coherent_optional_result_info(response.result_info.as_ref(), records.len()) {
        return Err(failure("dns_read_incomplete", "dns", true, None));
    }
    if records.is_empty() {
        return Ok("missing");
    }
    let mut observed = BTreeSet::new();
    let mut mx_count = 0_usize;
    let mut duplicate_mx = false;
    for record in records {
        let Some(record_type) = record.get("type").and_then(Value::as_str) else {
            return Err(failure(
                "dns_projection_malformed",
                "dns",
                true,
                Some(records.len()),
            ));
        };
        if record_type != "MX" {
            continue;
        }
        mx_count += 1;
        let exact = record
            .get("name")
            .and_then(Value::as_str)
            .and_then(normalize_domain)
            .as_deref()
            == Some(reply_domain);
        let Some(content) = record
            .get("content")
            .and_then(Value::as_str)
            .and_then(normalize_domain)
        else {
            return Err(failure(
                "dns_projection_malformed",
                "dns",
                true,
                Some(records.len()),
            ));
        };
        if !exact {
            return Err(failure(
                "dns_projection_malformed",
                "dns",
                true,
                Some(records.len()),
            ));
        }
        duplicate_mx |= !observed.insert(content);
    }
    let expected = CANONICAL_MX.into_iter().map(str::to_owned).collect();
    Ok(
        if mx_count == CANONICAL_MX.len() && !duplicate_mx && observed == expected {
            "ok"
        } else {
            "drift"
        },
    )
}

fn coherent_optional_result_info(result_info: Option<&Value>, record_count: usize) -> bool {
    let Some(info) = result_info else {
        return true;
    };
    let Some(info) = info.as_object() else {
        return false;
    };
    if info
        .keys()
        .any(|key| !DNS_RESULT_INFO_KEYS.contains(&key.as_str()))
    {
        return false;
    }
    let count = record_count as u64;
    let provider_complete = info.get("page").and_then(Value::as_u64) == Some(1)
        && info.get("total_pages").and_then(Value::as_u64) == Some(1)
        && info.get("count").and_then(Value::as_u64) == Some(count)
        && info.get("total_count").and_then(Value::as_u64) == Some(count);
    let cfctl_complete = match (info.get("cfctl_pages"), info.get("cfctl_page_complete")) {
        (None, None) => true,
        (Some(pages), Some(complete)) => {
            pages.as_u64() == Some(1) && complete.as_bool() == Some(true)
        }
        _ => false,
    };
    provider_complete
        && cfctl_complete
        && info.get("per_page").is_none_or(|value| {
            value
                .as_u64()
                .is_some_and(|per_page| per_page > 0 && count <= per_page)
        })
}

fn parent_zone_candidates(reply_domain: &str) -> Vec<String> {
    let labels = reply_domain.split('.').collect::<Vec<_>>();
    (1..labels.len().saturating_sub(1))
        .map(|index| labels[index..].join("."))
        .collect()
}

fn success(target: &Target, dns: &str, routing_rule: &str) -> Value {
    json!({
        "adapter":cfctl_workspace::MAILDESK_REPLY_SUBDOMAIN_INGRESS_PROJECTION,
        "success":true,
        "boundary_crossed":true,
        "schema_version":1,
        "reply_domain_sha256":sha256(target.reply_domain.as_bytes()),
        "worker_target_sha256":sha256(target.worker_script_name.as_bytes()),
        "dns_scope":"exact_reply_subdomain",
        "routing_scope":"exact_reply_subdomain_catch_all_to_worker",
        "dns":dns,
        "routing_rule":routing_rule,
        "provider_output_retained":false,
        "body_returned":false,
    })
}

fn project_account_rules(
    response: &CloudflareResponseV1,
    target: &Target,
    parent_zone_id: &str,
) -> std::result::Result<&'static str, Value> {
    if !response.success || response.status != 200 || !response.errors.is_empty() {
        return Err(failure(
            "account_rules_read_incomplete",
            "routing_rule",
            true,
            None,
        ));
    }
    let projection: cfctl_core::EmailRoutingRuleSetV1 =
        serde_json::from_value(response.result.clone()).map_err(|_| {
            failure(
                "account_rules_projection_malformed",
                "routing_rule",
                true,
                None,
            )
        })?;
    let info_complete = response.result_info.as_ref().is_some_and(|info| {
        info.get("page").and_then(Value::as_u64) == Some(1)
            && info.get("per_page").and_then(Value::as_u64) == Some(projection.page_size)
            && info.get("total_pages").and_then(Value::as_u64) == Some(projection.pages)
            && info.get("total_count").and_then(Value::as_u64) == Some(projection.rule_count as u64)
            && info
                .get("cfctl_page_probe_complete")
                .and_then(Value::as_bool)
                == Some(true)
            && info.get("cfctl_projection").and_then(Value::as_str)
                == Some("email_routing_account_rule_set_v1")
    });
    if projection.schema_version != 1
        || !projection.complete
        || !(1..=cfctl_core::EMAIL_ROUTING_RULES_PAGE_SIZE).contains(&projection.page_size)
        || projection.pages == 0
        || projection.rule_count != projection.rules.len()
        || !info_complete
        || projection.rules.iter().any(|rule| {
            rule.zone_name_sha256
                .as_deref()
                .is_none_or(|hash| !is_sha256(hash))
                || rule
                    .zone_tag_sha256
                    .as_deref()
                    .is_none_or(|hash| !is_sha256(hash))
        })
    {
        return Err(failure(
            "account_rules_projection_malformed",
            "routing_rule",
            true,
            None,
        ));
    }
    let domain_hash = sha256(target.reply_domain.as_bytes());
    let parent_zone_hash = sha256(parent_zone_id.as_bytes());
    let domain_rules = projection
        .rules
        .iter()
        .filter(|rule| rule.zone_name_sha256.as_deref() == Some(domain_hash.as_str()))
        .collect::<Vec<_>>();
    if domain_rules.is_empty() {
        return Ok("missing");
    }
    let all_matcher_candidates = domain_rules
        .iter()
        .filter(|rule| {
            rule.enabled
                && rule.matchers.len() == 1
                && rule.matchers[0].matcher_type == "all"
                && rule.matchers[0].field.is_none()
                && rule.matchers[0].value_sha256.is_none()
        })
        .collect::<Vec<_>>();
    match all_matcher_candidates.len() {
        0 => Ok("drift"),
        1 => {
            let candidate = all_matcher_candidates[0];
            if candidate.zone_tag_sha256.as_deref() == Some(parent_zone_hash.as_str())
                && candidate.actions.len() == 1
                && candidate.actions[0].action_type == "worker"
                && candidate.actions[0].value_count == 1
                && candidate.actions[0].worker_targets == [target.worker_script_name.as_str()]
            {
                Ok("ok")
            } else {
                Ok("drift")
            }
        }
        count => Err(failure(
            "account_rules_cardinality_ambiguous",
            "routing_rule",
            true,
            Some(count),
        )),
    }
}

fn failure(status: &str, stage: &str, boundary_crossed: bool, match_count: Option<usize>) -> Value {
    json!({
        "adapter":cfctl_workspace::MAILDESK_REPLY_SUBDOMAIN_INGRESS_PROJECTION,
        "success":false,
        "boundary_crossed":boundary_crossed,
        "schema_version":1,
        "status":status,
        "stage":stage,
        "match_count":match_count,
        "provider_output_retained":false,
        "body_returned":false,
    })
}

fn successful_complete_page(response: &CloudflareResponseV1) -> bool {
    let result_count = response.result.as_array().map(Vec::len);
    response.success
        && response.status == 200
        && response.errors.is_empty()
        && response.result_info.as_ref().is_some_and(|info| {
            info.get("cfctl_page_complete").and_then(Value::as_bool) == Some(true)
                && info
                    .get("page")
                    .and_then(Value::as_u64)
                    .is_some_and(|page| {
                        page > 0
                            && info.get("total_pages").and_then(Value::as_u64) == Some(page)
                            && info.get("cfctl_pages").and_then(Value::as_u64) == Some(page)
                    })
                && result_count.is_some_and(|count| {
                    info.get("count").and_then(Value::as_u64) == Some(count as u64)
                        && info.get("total_count").and_then(Value::as_u64) == Some(count as u64)
                })
        })
}

fn exact_zone_list_capability(catalog: &CatalogSnapshot) -> Result<&CapabilityV1> {
    exact_capability(catalog, ZONE_LIST_ID, ZONE_LIST_PATH)
}

fn exact_capability<'a>(
    catalog: &'a CatalogSnapshot,
    id: &str,
    path: &str,
) -> Result<&'a CapabilityV1> {
    catalog
        .get(id)
        .filter(|capability| capability.method == "GET" && capability.path == path)
        .ok_or_else(|| {
            CliError::Input(format!(
                "reply-subdomain ingress provider source `{id}` is unavailable or drifted"
            ))
        })
}

fn validate_provider_contracts(
    zone: &CapabilityV1,
    dns: &CapabilityV1,
    account_rules: &CapabilityV1,
) -> Result<()> {
    let common = |capability: &CapabilityV1| {
        !capability.mutating
            && capability.request_schema.is_none()
            && matches!(
                capability.adapter_status,
                AdapterStatus::Native | AdapterStatus::DynamicApi
            )
            && capability
                .response_contract
                .as_ref()
                .is_some_and(|contract| {
                    contract.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
                        && contract.success_statuses == ["200"]
                        && contract.success_media_types == ["application/json"]
                })
    };
    let selector = |capability: &CapabilityV1, name: &str, location: &str| {
        capability
            .selectors
            .iter()
            .any(|selector| selector.name == name && selector.location == location)
    };
    let zone_ok = common(zone)
        && zone
            .permissions
            .iter()
            .any(|permission| permission == "Zone Zone Read")
        && ["name", "account.id", "page", "per_page"]
            .iter()
            .all(|name| selector(zone, name, "query"));
    let dns_ok = common(dns)
        && dns
            .permissions
            .iter()
            .any(|permission| permission == "Zone Settings Read")
        && selector(dns, "zone_id", "path")
        && selector(dns, "subdomain", "query");
    let account_rules_ok = common(account_rules)
        && account_rules.id == ACCOUNT_RULES_ID
        && account_rules.path == ACCOUNT_RULES_PATH
        && account_rules
            .permissions
            .iter()
            .any(|permission| permission == "Email Routing Rules Read")
        && selector(account_rules, "account_id", "path")
        && ["page", "per_page"]
            .iter()
            .all(|name| selector(account_rules, name, "query"));
    if !zone_ok || !dns_ok || !account_rules_ok {
        return Err(CliError::Input(
            "reply-subdomain ingress parent-zone, subdomain DNS, or account-rule inventory source contract drifted"
                .to_owned(),
        ));
    }
    Ok(())
}

fn normalize_domain(value: &str) -> Option<String> {
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

fn valid_worker_name(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn is_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use cfctl_cloudflare::CloudflareApiErrorV1;
    use serde_json::json;

    use super::*;

    fn response(result: Value, count: usize) -> CloudflareResponseV1 {
        CloudflareResponseV1 {
            status: 200,
            success: true,
            result,
            errors: Vec::new(),
            result_info: Some(json!({
                "page":1,
                "total_pages":1,
                "total_count":count,
                "count":count,
                "cfctl_pages":1,
                "cfctl_page_complete":true,
            })),
            etag: None,
            cf_ray: None,
        }
    }

    fn target() -> Target {
        Target {
            account_id: "private-account".to_owned(),
            reply_domain: "reply.example.com".to_owned(),
            worker_script_name: "maildesk-relay-router".to_owned(),
        }
    }

    #[test]
    fn parent_zone_and_exact_subdomain_dns_project_without_apex_rule_inference() {
        let target = target();
        let zone = response(
            json!([{"id":"private-zone","name":"example.com","status":"active","account":{"id":"private-account"}}]),
            1,
        );
        assert_eq!(
            project_zone(&zone, &target.account_id, "example.com").expect("zone"),
            ZoneState::Active("private-zone".to_owned())
        );
        let dns = CloudflareResponseV1 {
            result: json!({
                "errors":[],
                "record":CANONICAL_MX.map(|content| json!({
                    "type":"MX","name":"reply.example.com","content":content,
                })),
            }),
            result_info: None,
            ..response(Value::Null, 0)
        };
        assert_eq!(
            project_subdomain_dns(&dns, &target.reply_domain).expect("dns"),
            "ok"
        );
        let receipt = success(&target, "ok", "ok");
        assert!(receipt_is_complete(&receipt));
        let serialized = serde_json::to_string(&receipt).expect("receipt");
        assert!(!serialized.contains("reply.example.com"));
        assert!(!serialized.contains("maildesk-relay-router"));
        assert!(!serialized.contains("private-zone"));
        assert!(!serialized.contains("private-account"));
    }

    #[test]
    fn documented_dns_response_variants_project_with_coherent_optional_metadata() {
        let target = target();
        let records = CANONICAL_MX.map(|content| {
            json!({
                "type":"MX",
                "name":"reply.example.com",
                "content":content,
            })
        });
        let collection = CloudflareResponseV1 {
            result: json!(records),
            result_info: Some(json!({
                "page":1,
                "per_page":20,
                "total_pages":1,
                "total_count":3,
                "count":3,
            })),
            ..response(Value::Null, 0)
        };
        assert_eq!(
            project_subdomain_dns(&collection, &target.reply_domain).expect("collection"),
            "ok"
        );

        let object_without_optional_errors = CloudflareResponseV1 {
            result: json!({"record":records}),
            result_info: None,
            ..response(Value::Null, 0)
        };
        assert_eq!(
            project_subdomain_dns(&object_without_optional_errors, &target.reply_domain)
                .expect("object response"),
            "ok"
        );
    }

    #[test]
    fn collection_dns_metadata_conflicts_and_unknown_cursors_fail_closed() {
        let target = target();
        let records = CANONICAL_MX.map(|content| {
            json!({
                "type":"MX",
                "name":"reply.example.com",
                "content":content,
            })
        });
        for result_info in [
            json!({}),
            json!({
                "page":1,
                "count":3,
            }),
            json!({
                "page":1,
                "per_page":20,
                "total_pages":2,
                "total_count":3,
                "count":3,
            }),
            json!({
                "page":1,
                "per_page":20,
                "total_pages":1,
                "total_count":4,
                "count":3,
            }),
            json!({
                "page":1,
                "per_page":20,
                "total_pages":1,
                "total_count":3,
                "count":3,
                "cursor":"private-provider-cursor",
            }),
            json!({
                "page":1,
                "per_page":20,
                "total_pages":1,
                "total_count":3,
                "count":3,
                "cfctl_pages":1,
            }),
        ] {
            let response = CloudflareResponseV1 {
                result: json!(records),
                result_info: Some(result_info),
                ..response(Value::Null, 0)
            };
            let failure =
                project_subdomain_dns(&response, &target.reply_domain).expect_err("incomplete");
            assert_eq!(failure["status"], "dns_read_incomplete");
            let serialized = serde_json::to_string(&failure).expect("body-free failure");
            assert!(!serialized.contains("provider-cursor"));
            assert_eq!(failure["provider_output_retained"], false);
        }
    }

    #[test]
    fn typed_missing_and_drift_remain_distinct_from_ambiguous_or_incomplete_reads() {
        let target = target();
        assert_eq!(
            project_zone(&response(json!([]), 0), &target.account_id, "example.com")
                .expect("missing"),
            ZoneState::Missing
        );
        let ambiguous = project_zone(
            &response(
                json!([
                    {"id":"one","name":"example.com","status":"active","account":{"id":"private-account"}},
                    {"id":"two","name":"example.com","status":"active","account":{"id":"private-account"}},
                ]),
                2,
            ),
            &target.account_id,
            "example.com",
        )
        .expect_err("ambiguous");
        assert_eq!(ambiguous["status"], "zone_cardinality_ambiguous");
        assert_eq!(ambiguous["match_count"], 2);
        assert!(!receipt_is_complete(&ambiguous));

        let mut incomplete = response(json!({"errors":[],"record":[]}), 0);
        incomplete.success = false;
        let failure =
            project_subdomain_dns(&incomplete, &target.reply_domain).expect_err("incomplete");
        assert_eq!(failure["status"], "dns_read_incomplete");
        assert_eq!(failure["provider_output_retained"], false);
    }

    #[test]
    fn noncanonical_subdomain_mx_is_drift_without_provider_retention() {
        let target = target();
        let dns = CloudflareResponseV1 {
            result: json!({"errors":[],"record":[
                {"type":"MX","name":"reply.example.com","content":"route1.mx.cloudflare.net"},
                {"type":"MX","name":"reply.example.com","content":"wrong.mx.example.net"}
            ]}),
            result_info: None,
            ..response(Value::Null, 0)
        };
        assert_eq!(
            project_subdomain_dns(&dns, &target.reply_domain).expect("dns"),
            "drift"
        );
        let receipt = success(&target, "drift", "ok");
        assert!(receipt_is_complete(&receipt));
        assert!(
            !serde_json::to_string(&receipt)
                .expect("receipt")
                .contains("wrong")
        );
    }

    #[test]
    fn provider_errors_and_malformed_rows_fail_closed_body_free() {
        let target = target();
        let mut denied = response(json!([{"private":"provider-payload"}]), 1);
        denied.success = false;
        denied.errors = vec![CloudflareApiErrorV1 {
            code: Some(9109),
            message: "private provider marker".to_owned(),
        }];
        let failure = project_zone(&denied, &target.account_id, "example.com").expect_err("denied");
        let serialized = serde_json::to_string(&failure).expect("failure");
        assert!(!serialized.contains("provider-payload"));
        assert!(!serialized.contains("provider marker"));
        assert_eq!(failure["provider_output_retained"], false);
        assert_eq!(failure["body_returned"], false);

        let mut expanded = json!({
            "adapter":cfctl_workspace::MAILDESK_REPLY_SUBDOMAIN_INGRESS_PROJECTION,
            "success":true,
            "boundary_crossed":true,
            "schema_version":1,
            "reply_domain_sha256":sha256(target.reply_domain.as_bytes()),
            "worker_target_sha256":sha256(target.worker_script_name.as_bytes()),
            "dns_scope":"exact_reply_subdomain",
            "routing_scope":"exact_reply_subdomain_catch_all_to_worker",
            "dns":"ok",
            "routing_rule":"ok",
            "provider_output_retained":false,
            "body_returned":false,
        });
        assert!(receipt_is_complete(&expanded));
        expanded["provider_payload"] = json!({"raw":true});
        assert!(!receipt_is_complete(&expanded));
    }

    #[test]
    fn incomplete_dns_metadata_and_duplicate_mx_fail_closed() {
        let target = target();
        let records = CANONICAL_MX
            .map(|content| json!({"type":"MX","name":"reply.example.com","content":content}));
        let mut incomplete = CloudflareResponseV1 {
            result: json!({"errors":[],"record":records}),
            result_info: Some(json!({
                "page":1,
                "total_pages":2,
                "total_count":3,
                "count":3,
                "cfctl_pages":1,
                "cfctl_page_complete":false,
            })),
            ..response(Value::Null, 0)
        };
        let failure =
            project_subdomain_dns(&incomplete, &target.reply_domain).expect_err("incomplete");
        assert_eq!(failure["status"], "dns_read_incomplete");
        assert_eq!(failure["provider_output_retained"], false);

        incomplete.result_info = Some(json!({
            "page":2,
            "total_pages":2,
            "total_count":3,
            "count":3,
            "cfctl_pages":2,
            "cfctl_page_complete":true,
        }));
        let later_page =
            project_subdomain_dns(&incomplete, &target.reply_domain).expect_err("later page");
        assert_eq!(later_page["status"], "dns_read_incomplete");
        assert_eq!(later_page["provider_output_retained"], false);

        incomplete.result_info = None;
        incomplete.result = json!({"errors":[],"record":[
            {"type":"MX","name":"reply.example.com","content":"route1.mx.cloudflare.net"},
            {"type":"MX","name":"reply.example.com","content":"route1.mx.cloudflare.net"},
            {"type":"MX","name":"reply.example.com","content":"route2.mx.cloudflare.net"},
            {"type":"MX","name":"reply.example.com","content":"route3.mx.cloudflare.net"}
        ]});
        assert_eq!(
            project_subdomain_dns(&incomplete, &target.reply_domain).expect("duplicate drift"),
            "drift"
        );
    }

    #[test]
    fn subdomain_dns_permission_drift_is_rejected_by_preflight_contract() {
        let mut zone = provider_capability(
            ZONE_LIST_ID,
            ZONE_LIST_PATH,
            &["Zone Zone Read"],
            &[
                ("name", "query"),
                ("account.id", "query"),
                ("page", "query"),
                ("per_page", "query"),
            ],
        );
        let mut dns = provider_capability(
            SUBDOMAIN_DNS_ID,
            SUBDOMAIN_DNS_PATH,
            &["Zone Settings Read"],
            &[("zone_id", "path"), ("subdomain", "query")],
        );
        let account_rules = provider_capability(
            ACCOUNT_RULES_ID,
            ACCOUNT_RULES_PATH,
            &["Email Routing Rules Read"],
            &[
                ("account_id", "path"),
                ("page", "query"),
                ("per_page", "query"),
            ],
        );
        assert!(validate_provider_contracts(&zone, &dns, &account_rules).is_ok());
        dns.permissions.clear();
        assert!(validate_provider_contracts(&zone, &dns, &account_rules).is_err());
        zone.permissions.clear();
        dns.permissions.push("Zone Settings Read".to_owned());
        assert!(validate_provider_contracts(&zone, &dns, &account_rules).is_err());
    }

    #[test]
    fn parent_candidates_exclude_reply_domain() {
        assert_eq!(
            parent_zone_candidates("reply.mail.example.com"),
            ["mail.example.com", "example.com"]
        );
    }

    #[test]
    fn account_rule_projection_exactly_binds_subdomain_parent_zone_and_worker() {
        let target = target();
        let account_rules = CloudflareResponseV1 {
            result: json!({
                "schema_version":1,
                "complete":true,
                "page_size":50,
                "pages":2,
                "rule_count":1,
                "rules":[{
                    "rule_identifier":"rule-001",
                    "enabled":true,
                    "zone_name_sha256":sha256(target.reply_domain.as_bytes()),
                    "zone_tag_sha256":sha256(b"private-zone"),
                    "matchers":[{"matcher_type":"all"}],
                    "actions":[{
                        "action_type":"worker",
                        "worker_targets":["maildesk-relay-router"],
                        "value_count":1
                    }]
                }]
            }),
            result_info: Some(json!({
                "page":1,
                "per_page":50,
                "total_pages":2,
                "total_count":1,
                "cfctl_page_probe_complete":true,
                "cfctl_projection":"email_routing_account_rule_set_v1"
            })),
            ..response(Value::Null, 0)
        };
        assert_eq!(
            project_account_rules(&account_rules, &target, "private-zone").expect("rules"),
            "ok"
        );
        let serialized =
            serde_json::to_string(&success(&target, "ok", "ok")).expect("body-free receipt");
        assert!(!serialized.contains("reply.example.com"));
        assert!(!serialized.contains("private-zone"));
    }

    #[test]
    fn account_rule_projection_distinguishes_missing_drift_and_ambiguous_cardinality() {
        let target = target();
        let rule = json!({
            "rule_identifier":"rule-001",
            "enabled":true,
            "zone_name_sha256":sha256(target.reply_domain.as_bytes()),
            "zone_tag_sha256":sha256(b"private-zone"),
            "matchers":[{"matcher_type":"all"}],
            "actions":[{
                "action_type":"worker",
                "worker_targets":["maildesk-relay-router"],
                "value_count":1
            }]
        });
        let projected = |rules: Vec<Value>| {
            let count = rules.len();
            CloudflareResponseV1 {
                result: json!({
                    "schema_version":1,
                    "complete":true,
                    "page_size":50,
                    "pages":2,
                    "rule_count":count,
                    "rules":rules
                }),
                result_info: Some(json!({
                    "page":1,
                    "per_page":50,
                    "total_pages":2,
                    "total_count":count,
                    "cfctl_page_probe_complete":true,
                    "cfctl_projection":"email_routing_account_rule_set_v1"
                })),
                ..response(Value::Null, 0)
            }
        };
        assert_eq!(
            project_account_rules(&projected(Vec::new()), &target, "private-zone")
                .expect("complete absence"),
            "missing"
        );
        let mut wrong_worker = rule.clone();
        wrong_worker["actions"][0]["worker_targets"] = json!(["another-worker"]);
        assert_eq!(
            project_account_rules(&projected(vec![wrong_worker]), &target, "private-zone")
                .expect("typed drift"),
            "drift"
        );
        let ambiguous = project_account_rules(
            &projected(vec![rule.clone(), rule.clone()]),
            &target,
            "private-zone",
        )
        .expect_err("duplicate exact rule is ambiguous");
        assert_eq!(ambiguous["status"], "account_rules_cardinality_ambiguous");
        assert_eq!(ambiguous["match_count"], 2);
        let mut wrong_worker = rule.clone();
        wrong_worker["actions"][0]["worker_targets"] = json!(["another-worker"]);
        let mixed_target = project_account_rules(
            &projected(vec![rule.clone(), wrong_worker]),
            &target,
            "private-zone",
        )
        .expect_err("two enabled all-matcher rules are ambiguous before target selection");
        assert_eq!(
            mixed_target["status"],
            "account_rules_cardinality_ambiguous"
        );
        assert_eq!(mixed_target["match_count"], 2);
        let mut wrong_parent = rule.clone();
        wrong_parent["zone_tag_sha256"] = json!(sha256(b"different-parent-zone"));
        let parent_conflict = project_account_rules(
            &projected(vec![rule, wrong_parent]),
            &target,
            "private-zone",
        )
        .expect_err("same-domain all-matcher rules cannot hide a parent-zone conflict");
        assert_eq!(
            parent_conflict["status"],
            "account_rules_cardinality_ambiguous"
        );
        assert_eq!(parent_conflict["match_count"], 2);
        let serialized = serde_json::to_string(&ambiguous).expect("body-free ambiguity");
        assert!(!serialized.contains("reply.example.com"));
        assert!(!serialized.contains("maildesk-relay-router"));
    }

    fn provider_capability(
        id: &str,
        path: &str,
        permissions: &[&str],
        selectors: &[(&str, &str)],
    ) -> CapabilityV1 {
        let mut capability = CapabilityV1::new(id, id, "GET", path);
        capability.adapter_status = AdapterStatus::DynamicApi;
        capability.permissions = permissions
            .iter()
            .map(|permission| (*permission).to_owned())
            .collect();
        capability.selectors = selectors
            .iter()
            .map(|(name, location)| cfctl_core::SelectorV1 {
                name: (*name).to_owned(),
                location: (*location).to_owned(),
                required: true,
                value_type: "string".to_owned(),
                description: None,
                contract: None,
            })
            .collect();
        capability.response_contract = Some(cfctl_core::ResponseContractV1 {
            success_statuses: vec!["200".to_owned()],
            success_media_types: vec!["application/json".to_owned()],
            body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
        });
        capability
    }
}
