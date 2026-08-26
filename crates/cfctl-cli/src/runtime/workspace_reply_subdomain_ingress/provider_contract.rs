use super::super::prelude::{
    AdapterStatus, CapabilityV1, CatalogSnapshot, CliError, CloudflareResponseV1, Digest,
    EffectClass, ResponseBodyModeV1, Result, Sha256, Value, json,
};
use super::{
    ACCOUNT_PLAN_ID, ACCOUNT_PLAN_PATH, CATCH_ALL_GET_ID, CATCH_ALL_GET_PATH, CATCH_ALL_UPDATE_ID,
    CATCH_ALL_UPDATE_PATH, WORKERS_LIST_ID, WORKERS_LIST_PATH, ZONE_LIST_ID, ZONE_LIST_PATH,
};

pub(super) fn failure(
    status: &str,
    stage: &str,
    boundary_crossed: bool,
    match_count: Option<usize>,
) -> Value {
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

pub(super) fn successful_complete_page(response: &CloudflareResponseV1) -> bool {
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

pub(super) fn exact_zone_list_capability(catalog: &CatalogSnapshot) -> Result<&CapabilityV1> {
    exact_capability(catalog, ZONE_LIST_ID, ZONE_LIST_PATH)
}

pub(super) fn exact_capability<'a>(
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

pub(super) fn validate_provider_contracts(
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
            .any(|permission| permission == "Zone Settings Read")
        && selector(dns, "zone_id", "path")
        && selector(dns, "subdomain", "query");
    let catch_all_ok = common(catch_all)
        && catch_all.id == CATCH_ALL_GET_ID
        && catch_all.path == CATCH_ALL_GET_PATH
        && catch_all
            .permissions
            .iter()
            .any(|permission| permission == "Email Routing Rules Read")
        && selector(catch_all, "zone_id", "path");
    if !zone_ok || !dns_ok || !catch_all_ok {
        return Err(CliError::Input(
            "reply-subdomain ingress parent-zone, subdomain DNS, or parent-zone catch-all source contract drifted"
                .to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn validate_activation_provider_contracts(
    zone: &CapabilityV1,
    workers: &CapabilityV1,
    account_plan: &CapabilityV1,
    catch_all_get: &CapabilityV1,
    catch_all: &CapabilityV1,
) -> Result<()> {
    let selector = |capability: &CapabilityV1, name: &str, location: &str| {
        capability
            .selectors
            .iter()
            .any(|selector| selector.name == name && selector.location == location)
    };
    let envelope = |capability: &CapabilityV1| {
        capability
            .response_contract
            .as_ref()
            .is_some_and(|contract| {
                contract.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
                    && contract.success_statuses == ["200"]
                    && contract.success_media_types == ["application/json"]
            })
    };
    let zone_ok = zone.id == ZONE_LIST_ID
        && zone.method == "GET"
        && zone.path == ZONE_LIST_PATH
        && !zone.mutating
        && zone
            .permissions
            .iter()
            .any(|permission| permission == "Zone Zone Read")
        && ["name", "account.id", "page", "per_page"]
            .iter()
            .all(|name| selector(zone, name, "query"))
        && envelope(zone);
    let workers_ok = workers.id == WORKERS_LIST_ID
        && workers.method == "GET"
        && workers.path == WORKERS_LIST_PATH
        && !workers.mutating
        && workers
            .permissions
            .iter()
            .any(|permission| permission == "Workers Scripts Read")
        && selector(workers, "account_id", "path")
        && ["page", "per_page"]
            .iter()
            .all(|name| selector(workers, name, "query"))
        && envelope(workers);
    let account_plan_ok = account_plan.id == ACCOUNT_PLAN_ID
        && account_plan.method == "POST"
        && account_plan.path == ACCOUNT_PLAN_PATH
        && account_plan
            .request_schema
            .as_ref()
            .is_some_and(|schema| {
                schema.get("x-cfctl-body-required") == Some(&Value::Bool(true))
                    && schema.pointer("/properties/owner_worker_tag/writeOnly")
                        == Some(&Value::Bool(true))
                    && schema.pointer("/properties/catch_all_rules/items/properties/target/type")
                        .and_then(Value::as_str)
                        == Some("string")
                    && schema
                        .pointer("/properties/catch_all_rules/items/properties/rule/properties/matchers/items/properties/type/enum/0")
                        .and_then(Value::as_str)
                        == Some("all")
            })
        && selector(account_plan, "account_id", "path")
        && envelope(account_plan);
    let catch_all_get_ok = catch_all_get.id == CATCH_ALL_GET_ID
        && catch_all_get.method == "GET"
        && catch_all_get.path == CATCH_ALL_GET_PATH
        && !catch_all_get.mutating
        && catch_all_get
            .permissions
            .iter()
            .any(|permission| permission == "Email Routing Rules Read")
        && selector(catch_all_get, "zone_id", "path")
        && envelope(catch_all_get);
    let catch_all_ok = catch_all.id == CATCH_ALL_UPDATE_ID
        && catch_all.method == "PUT"
        && catch_all.path == CATCH_ALL_UPDATE_PATH
        && catch_all.mutating
        && catch_all.effect == EffectClass::ReversibleWrite
        && catch_all
            .permissions
            .iter()
            .any(|permission| permission == "Email Routing Rules Write")
        && selector(catch_all, "zone_id", "path")
        && catch_all
            .request_schema
            .as_ref()
            .is_some_and(activation_apply_schema_supported)
        && envelope(catch_all);
    if !zone_ok || !workers_ok || !account_plan_ok || !catch_all_get_ok || !catch_all_ok {
        return Err(CliError::Input(
            "reply-subdomain activation Worker inventory, account-plan, or catch-all update source contract drifted"
                .to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn activation_apply_schema_supported(schema: &Value) -> bool {
    let enum_contains = |pointer: &str, expected: &str| {
        schema
            .pointer(pointer)
            .and_then(Value::as_array)
            .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(expected)))
    };
    let required = schema.get("required").and_then(Value::as_array);
    schema.get("x-cfctl-body-required") == Some(&Value::Bool(true))
        && schema
            .pointer("/properties/owner_worker_tag/type")
            .and_then(Value::as_str)
            == Some("string")
        && schema.pointer("/properties/owner_worker_tag/writeOnly") == Some(&Value::Bool(true))
        && schema
            .pointer("/properties/owner_worker_tag/maxLength")
            .and_then(Value::as_u64)
            == Some(32)
        && enum_contains("/properties/source/enum", "wrangler")
        && schema
            .pointer("/properties/enabled/enum")
            .and_then(Value::as_array)
            .is_some_and(|values| values.contains(&Value::Bool(true)))
        && enum_contains("/properties/matchers/items/properties/type/enum", "all")
        && enum_contains("/properties/actions/items/properties/type/enum", "worker")
        && schema
            .pointer("/properties/actions/minItems")
            .and_then(Value::as_u64)
            == Some(1)
        && schema
            .pointer("/properties/actions/maxItems")
            .and_then(Value::as_u64)
            == Some(1)
        && schema
            .pointer("/properties/actions/items/properties/value/maxItems")
            .and_then(Value::as_u64)
            == Some(1)
        && ["actions", "matchers"].iter().all(|field| {
            required.is_some_and(|values| values.iter().any(|value| value.as_str() == Some(field)))
        })
}

pub(super) fn activation_apply_body(worker_script_name: &str, worker_tag: &str) -> Value {
    json!({
        "matchers":[{"type":"all"}],
        "actions":[{"type":"worker","value":[worker_script_name]}],
        "enabled":true,
        "source":"wrangler",
        "owner_worker_tag":worker_tag,
    })
}

pub(super) fn normalize_domain(value: &str) -> Option<String> {
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

pub(super) fn valid_worker_name(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

pub(super) fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

pub(super) fn is_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

pub(super) fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
