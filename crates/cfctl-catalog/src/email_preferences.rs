//! Preserve the governed preview preference when upstream adds delivery settings.

use super::{CapabilityV1, ResponseBodyModeV1, Value};
use std::collections::BTreeMap;

pub(super) fn restrict_preview_update(capabilities: &mut BTreeMap<String, CapabilityV1>) {
    const READ: &str = "email-sending-subdomains-get-sending-subdomain";
    const UPDATE: &str = "email-sending-subdomains-update-sending-subdomain";
    const PATH: &str = "/zones/{zone_id}/email/sending/subdomains/{subdomain_id}";
    let read_supported = capabilities.get(READ).is_some_and(|read| {
        read.method == "GET"
            && read.path == PATH
            && !read.mutating
            && read.response_contract.as_ref().is_some_and(|response| {
                response.success_statuses == ["200"]
                    && response.success_media_types == ["application/json"]
                    && response.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
            })
    });
    let Some(update) = capabilities.get_mut(UPDATE) else {
        return;
    };
    let legacy = serde_json::json!({
        "type":"object","required":["preview_enabled"],
        "properties":{"preview_enabled":{"type":"boolean"}},
        "x-cfctl-body-required":true
    });
    let current = serde_json::json!({
        "type":"object",
        "properties":{"preview_enabled":{"type":"boolean"},"drop_suppressed_recipients":{"type":"boolean"}},
        "anyOf":[{"required":["preview_enabled"]},{"required":["drop_suppressed_recipients"]}],
        "x-cfctl-body-required":true
    });
    let mut closed = legacy.clone();
    closed["additionalProperties"] = Value::Bool(false);
    if !read_supported
        || update.method != "PATCH"
        || update.path != PATH
        || ![&legacy, &current, &closed]
            .into_iter()
            .any(|schema| update.request_schema.as_ref() == Some(schema))
        || !update.same_path_read.as_ref().is_some_and(|read| {
            read.read_capability_id == READ
                && read.path == PATH
                && (read.verified_response_fields == ["preview_enabled"]
                    || read.verified_response_fields
                        == ["drop_suppressed_recipients", "preview_enabled"])
        })
    {
        return;
    }
    update.request_schema = Some(closed);
    if let Some(read) = update.same_path_read.as_mut() {
        read.verified_response_fields = vec!["preview_enabled".to_owned()];
    }
    update.description = Some("Updates the activity-log preview preference for a sending subdomain. This governed workflow accepts preview_enabled only; recipient-suppression delivery changes require a separately reviewed contract.".to_owned());
}
