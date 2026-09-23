//! Exact secret-bearing widget read. The secret is never ordinary read evidence.
use crate::{CapabilityV1, ResponseBodyModeV1};

pub const ID: &str = "accounts-turnstile-widget-get";
pub const PATH: &str = "/accounts/{account_id}/challenges/widgets/{sitekey}";
pub const VERIFY: &str = "turnstile_widget_identity_and_private_sink";

#[must_use]
pub fn supported(cap: &CapabilityV1) -> bool {
    cap.id == ID
        && cap.method == "GET"
        && cap.path == PATH
        && cap.product == "Turnstile"
        && cap.account_scope == "account"
        && !cap.mutating
        && cap.request_schema.is_none()
        && cap.permissions.len() == 4
        && [
            "Turnstile Sites Write",
            "Turnstile Sites Read",
            "Account Settings Write",
            "Account Settings Read",
        ]
        .iter()
        .all(|p| cap.permissions.iter().any(|actual| actual == p))
        && cap.selectors.len() == 2
        && ["account_id", "sitekey"].iter().all(|name| {
            cap.selectors.iter().any(|s| {
                s.name == *name
                    && s.location == "path"
                    && s.required
                    && s.value_type == "string"
                    && s.contract.as_ref().is_some_and(|c| {
                        c.query.is_none()
                            && c.schema == serde_json::json!({"maxLength":32,"type":"string"})
                    })
            })
        })
        && cap.response_contract.as_ref().is_some_and(|r| {
            r.success_statuses == ["200"]
                && r.success_media_types == ["application/json"]
                && r.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
        })
}
