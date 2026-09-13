//! Fixed media selection for operations with a reviewed JSON alternative.

use super::{
    AdapterStatus, CapabilityV1, ResponseBodyModeV1, Value, schema_declares_boolean_path,
    success_response_schemas,
};
use std::collections::BTreeMap;

pub(super) fn finalize_entitlement_reads(
    document: &Value,
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    for (id, path, selector, permission) in [
        (
            "entitlements-get-account-entitlements",
            "/accounts/{account_id}/entitlements",
            "account_id",
            "Account Read",
        ),
        (
            "entitlements-get-zone-entitlements",
            "/zones/{zone_id}/entitlements",
            "zone_id",
            "Zone Read",
        ),
    ] {
        let Some(capability) = capabilities.get_mut(id) else {
            continue;
        };
        let operation = document
            .get("paths")
            .and_then(|paths| paths.get(path))
            .and_then(|item| item.get("get"));
        if capability.method != "GET" || capability.path != path || capability.mutating
            || capability.adapter_status != AdapterStatus::DynamicApi || capability.blocked_reason.is_some()
            || capability.permissions != [permission] || capability.request_schema.is_some()
            || capability.selectors.len() != 1
            || !capability.selectors.iter().any(|value| value.name == selector && value.location == "path" && value.required && value.value_type == "string")
            || !operation.is_some_and(|operation| {
                operation.pointer("/responses/204/description").and_then(Value::as_str) == Some("Request canceled by the client before the upstream could respond. No response body.\n")
                    && operation.pointer("/responses/204/content").is_none()
                    && success_response_schemas(document, operation).any(|schema| schema_declares_boolean_path(document, schema, &["success"], 0))
            })
        { continue; }
        let Some(response) = capability.response_contract.as_mut() else {
            continue;
        };
        if response.success_statuses == ["200", "204"]
            && response.success_media_types == ["application/json"]
            && response.body_mode == ResponseBodyModeV1::Unsupported
        {
            // The provider documents 204 as cancellation, not an empty result.
            // Only a complete 200 JSON envelope can establish entitlement data.
            response.success_statuses = vec!["200".to_owned()];
            response.body_mode = ResponseBodyModeV1::CloudflareJsonEnvelope;
        }
    }
}

pub(super) fn finalize_queue_metrics(
    document: &Value,
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    const ID: &str = "queues-get-metrics";
    const PATH: &str = "/accounts/{account_id}/queues/{queue_id}/metrics";
    let Some(capability) = capabilities.get_mut(ID) else {
        return;
    };
    let operation = document
        .get("paths")
        .and_then(|paths| paths.get(PATH))
        .and_then(|item| item.get("get"));
    if capability.method != "GET"
        || capability.path != PATH
        || capability.product != "Queue"
        || capability.mutating
        || capability.adapter_status != AdapterStatus::DynamicApi
        || capability.blocked_reason.is_some()
        || capability.request_schema.is_some()
        || capability.permissions
            != [
                "Queues Write",
                "Queues Read",
                "Workers Scripts Write",
                "Workers Scripts Read",
            ]
        || capability.selectors.len() != 2
        || !["account_id", "queue_id"].iter().all(|name| {
            capability.selectors.iter().any(|selector| {
                selector.name == *name
                    && selector.location == "path"
                    && selector.required
                    && selector.value_type == "string"
            })
        })
        || !operation.is_some_and(|operation| {
            success_response_schemas(document, operation)
                .any(|schema| schema_declares_boolean_path(document, schema, &["success"], 0))
        })
    {
        return;
    }
    let Some(response) = capability.response_contract.as_mut() else {
        return;
    };
    if response.success_statuses != ["200"]
        || response.success_media_types != ["application/json", "text/event-stream"]
        || response.body_mode != ResponseBodyModeV1::Unsupported
    {
        return;
    }
    // RequestBuilder already pins Accept to application/json. Keep the response
    // contract equally narrow: receiving SSE or any other status is an error.
    response.success_media_types = vec!["application/json".to_owned()];
    response.body_mode = ResponseBodyModeV1::CloudflareJsonEnvelope;
    capability.adapter_status = AdapterStatus::DynamicApi;
    capability.blocked_reason = None;
}
