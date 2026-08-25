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
const DNS_LIST_ID: &str = "dns-records-for-a-zone-list-dns-records";
const DNS_LIST_PATH: &str = "/zones/{zone_id}/dns_records";
const CATCH_ALL_ID: &str = "email-routing-routing-rules-get-catch-all-rule";
const CATCH_ALL_PATH: &str = "/zones/{zone_id}/email/routing/rules/catch_all";
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
    let dns_capability = exact_capability(catalog, DNS_LIST_ID, DNS_LIST_PATH)?;
    let catch_all_capability = exact_capability(catalog, CATCH_ALL_ID, CATCH_ALL_PATH)?;
    validate_provider_contracts(zone_capability, dns_capability, catch_all_capability)?;

    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let Ok(zone) = executor
        .execute_read(
            zone_capability,
            &CallInput {
                query: json!({
                    "account.id":account_id,
                    "name":target.reply_domain,
                    "page":1,
                    "per_page":50,
                }),
                ..CallInput::default()
            },
            credential,
        )
        .await
    else {
        return Ok(failure("zone_read_failed", "zone", true, None));
    };
    let zone_state = match project_zone(&zone, &target) {
        Ok(state) => state,
        Err(receipt) => return Ok(receipt),
    };
    let ZoneState::Active(zone_id) = zone_state else {
        let state = if zone_state == ZoneState::Missing {
            "missing"
        } else {
            "drift"
        };
        return Ok(success(&target, state, state));
    };

    let Ok(dns) = executor
        .execute_read(
            dns_capability,
            &CallInput {
                selectors: json!({"zone_id":zone_id}),
                query: json!({
                    "name.exact":target.reply_domain,
                    "type":"MX",
                    "match":"all",
                    "page":1,
                    "per_page":50,
                }),
                ..CallInput::default()
            },
            credential,
        )
        .await
    else {
        return Ok(failure("dns_read_failed", "dns", true, None));
    };
    let dns_state = match project_dns(&dns, &target.reply_domain) {
        Ok(state) => state,
        Err(receipt) => return Ok(receipt),
    };

    let Ok(catch_all) = executor
        .execute_read(
            catch_all_capability,
            &CallInput {
                selectors: json!({"zone_id":zone_id}),
                ..CallInput::default()
            },
            credential,
        )
        .await
    else {
        return Ok(failure("catch_all_read_failed", "routing_rule", true, None));
    };
    let routing_state = match project_catch_all(&catch_all, &target.worker_script_name) {
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
    target: &Target,
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
        == Some(target.reply_domain.as_str())
        && zone.pointer("/account/id").and_then(Value::as_str) == Some(target.account_id.as_str())
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

fn project_dns(
    response: &CloudflareResponseV1,
    reply_domain: &str,
) -> std::result::Result<&'static str, Value> {
    if !successful_complete_page(response) {
        return Err(failure("dns_read_incomplete", "dns", true, None));
    }
    let Some(records) = response.result.as_array() else {
        return Err(failure("dns_projection_malformed", "dns", true, None));
    };
    if records.is_empty() {
        return Ok("missing");
    }
    let mut observed = BTreeSet::new();
    for record in records {
        let exact = record.get("type").and_then(Value::as_str) == Some("MX")
            && record
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
        observed.insert(content);
    }
    let expected = CANONICAL_MX.into_iter().map(str::to_owned).collect();
    Ok(
        if records.len() == CANONICAL_MX.len() && observed == expected {
            "ok"
        } else {
            "drift"
        },
    )
}

fn project_catch_all(
    response: &CloudflareResponseV1,
    worker_script_name: &str,
) -> std::result::Result<&'static str, Value> {
    if !response.success || response.status != 200 || !response.errors.is_empty() {
        return Err(failure(
            "catch_all_read_incomplete",
            "routing_rule",
            true,
            None,
        ));
    }
    if response.result.is_null() {
        return Ok("missing");
    }
    let Some(rule) = response.result.as_object() else {
        return Err(failure(
            "catch_all_projection_malformed",
            "routing_rule",
            true,
            None,
        ));
    };
    let Some(enabled) = rule.get("enabled").and_then(Value::as_bool) else {
        return Err(failure(
            "catch_all_projection_malformed",
            "routing_rule",
            true,
            Some(1),
        ));
    };
    let Some(matchers) = rule.get("matchers").and_then(Value::as_array) else {
        return Err(failure(
            "catch_all_projection_malformed",
            "routing_rule",
            true,
            Some(1),
        ));
    };
    let Some(actions) = rule.get("actions").and_then(Value::as_array) else {
        return Err(failure(
            "catch_all_projection_malformed",
            "routing_rule",
            true,
            Some(1),
        ));
    };
    let matcher_exact =
        matchers.len() == 1 && matchers[0].get("type").and_then(Value::as_str) == Some("all");
    let worker_exact = actions.len() == 1
        && actions[0].get("type").and_then(Value::as_str) == Some("worker")
        && actions[0]
            .get("value")
            .and_then(Value::as_array)
            .is_some_and(|values| {
                values.len() == 1 && values[0].as_str() == Some(worker_script_name)
            });
    Ok(if enabled && matcher_exact && worker_exact {
        "ok"
    } else {
        "drift"
    })
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
    catch_all: &CapabilityV1,
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
            .any(|permission| permission == "DNS Read")
        && selector(dns, "zone_id", "path")
        && ["name.exact", "type", "match", "page", "per_page"]
            .iter()
            .all(|name| selector(dns, name, "query"));
    let catch_all_ok = common(catch_all)
        && catch_all.id == CATCH_ALL_ID
        && catch_all
            .permissions
            .iter()
            .any(|permission| permission == "Email Routing Rules Read")
        && selector(catch_all, "zone_id", "path");
    if !zone_ok || !dns_ok || !catch_all_ok {
        return Err(CliError::Input(
            "reply-subdomain ingress zone, exact MX, or dedicated catch-all source contract drifted"
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
    fn exact_zone_dns_and_dedicated_catch_all_project_to_closed_result() {
        let target = target();
        let zone = response(
            json!([{"id":"private-zone","name":"reply.example.com","status":"active","account":{"id":"private-account"}}]),
            1,
        );
        assert_eq!(
            project_zone(&zone, &target).expect("zone"),
            ZoneState::Active("private-zone".to_owned())
        );
        let dns = response(
            json!(CANONICAL_MX.map(|content| json!({
                "type":"MX","name":"reply.example.com","content":content,
            }))),
            3,
        );
        assert_eq!(project_dns(&dns, &target.reply_domain).expect("dns"), "ok");
        let catch_all = CloudflareResponseV1 {
            result: json!({
                "enabled":true,
                "matchers":[{"type":"all"}],
                "actions":[{"type":"worker","value":["maildesk-relay-router"]}],
            }),
            result_info: None,
            ..response(Value::Null, 0)
        };
        assert_eq!(
            project_catch_all(&catch_all, &target.worker_script_name).expect("rule"),
            "ok"
        );
        let receipt = success(&target, "ok", "ok");
        assert!(receipt_is_complete(&receipt));
        assert_eq!(receipt.as_object().map(serde_json::Map::len), Some(12));
        let serialized = serde_json::to_string(&receipt).expect("receipt");
        assert!(!serialized.contains("reply.example.com"));
        assert!(!serialized.contains("maildesk-relay-router"));
        assert!(!serialized.contains("private-zone"));
        assert!(!serialized.contains("private-account"));
    }

    #[test]
    fn typed_missing_and_drift_remain_distinct_from_ambiguous_or_incomplete_reads() {
        let target = target();
        assert_eq!(
            project_zone(&response(json!([]), 0), &target).expect("missing"),
            ZoneState::Missing
        );
        let ambiguous = project_zone(
            &response(
                json!([
                    {"id":"one","name":"reply.example.com","status":"active","account":{"id":"private-account"}},
                    {"id":"two","name":"reply.example.com","status":"active","account":{"id":"private-account"}},
                ]),
                2,
            ),
            &target,
        )
        .expect_err("ambiguous");
        assert_eq!(ambiguous["status"], "zone_cardinality_ambiguous");
        assert_eq!(ambiguous["match_count"], 2);
        assert!(!receipt_is_complete(&ambiguous));

        let mut incomplete = response(json!([]), 0);
        incomplete.result_info = None;
        let failure = project_dns(&incomplete, &target.reply_domain).expect_err("incomplete");
        assert_eq!(failure["status"], "dns_read_incomplete");
        assert_eq!(failure["provider_output_retained"], false);
    }

    #[test]
    fn wrong_worker_and_noncanonical_mx_are_drift_without_provider_retention() {
        let target = target();
        let dns = response(
            json!([
                {"type":"MX","name":"reply.example.com","content":"route1.mx.cloudflare.net"},
                {"type":"MX","name":"reply.example.com","content":"wrong.mx.example.net"},
            ]),
            2,
        );
        assert_eq!(
            project_dns(&dns, &target.reply_domain).expect("dns"),
            "drift"
        );
        let rule = CloudflareResponseV1 {
            result: json!({
                "enabled":true,
                "matchers":[{"type":"all"}],
                "actions":[{"type":"worker","value":["wrong-worker"]}],
            }),
            result_info: None,
            ..response(Value::Null, 0)
        };
        assert_eq!(
            project_catch_all(&rule, &target.worker_script_name).expect("rule"),
            "drift"
        );
        let receipt = success(&target, "drift", "drift");
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
        let failure = project_zone(&denied, &target).expect_err("denied");
        let serialized = serde_json::to_string(&failure).expect("failure");
        assert!(!serialized.contains("provider-payload"));
        assert!(!serialized.contains("provider marker"));
        assert_eq!(failure["provider_output_retained"], false);
        assert_eq!(failure["body_returned"], false);

        let mut expanded = success(&target, "ok", "ok");
        expanded["provider_payload"] = json!({"raw":true});
        assert!(!receipt_is_complete(&expanded));
    }
}
