//! Targeted response-header rule repair; no ruleset replacement or reordering.
use crate::{AdapterStatus, CapabilityV1, EffectClass, RiskClass};
use serde_json::{Value, json};
use std::collections::BTreeSet;
pub const ID: &str = "updateZoneRulesetRule";
pub const PATH: &str = "/zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}";
pub const READ_ID: &str = "getZoneRuleset";
pub const READ_PATH: &str = "/zones/{zone_id}/rulesets/{ruleset_id}";
pub const VERIFY: &str = "response_header_rule_and_unchanged_parent_readback";
pub const ROLLBACK: &str = "restore_response_header_rule_prior_definition";
pub const PRECONDITION: &str = "same_path_prior_state";
pub const FIELDS: [&str; 6] = [
    "action",
    "action_parameters",
    "description",
    "enabled",
    "expression",
    "ref",
];
type Checked<T> = Result<T, &'static str>;
fn rejected() -> &'static str {
    "targeted response-header rule contract rejected"
}

#[must_use]
pub fn request_schema() -> Value {
    json!({"type":"object","additionalProperties":false,"required":FIELDS,"properties":{
        "action":{"const":"rewrite"},
        "action_parameters":{"type":"object","additionalProperties":false,"required":["headers"],"properties":{
            "headers":{"type":"object","minProperties":1,"maxProperties":10,"additionalProperties":{
                "type":"object","additionalProperties":false,"required":["operation","value"],"properties":{
                    "operation":{"const":"set"},"value":{"type":"string","maxLength":16384}
                }
            }}
        }},
        "description":{"type":"string","maxLength":1024},"enabled":{"type":"boolean"},
        "expression":{"type":"string","minLength":1,"maxLength":4096},
        "ref":{"type":"string","minLength":1,"maxLength":256}
    }})
}
#[must_use]
pub fn supported(cap: &CapabilityV1) -> bool {
    cap.id == ID
        && cap.method == "PATCH"
        && cap.path == PATH
        && cap.mutating
        && cap.account_scope == "zone"
        && cap.risk == RiskClass::CrossConfig
        && cap.effect == EffectClass::ReversibleWrite
        && cap.permissions == ["Zone Transform Rules Read", "Zone Transform Rules Write"]
        && cap.response_contract.as_ref().is_some_and(|r| {
            r.success_statuses == ["200"]
                && r.success_media_types == ["application/json"]
                && r.body_mode == crate::ResponseBodyModeV1::CloudflareJsonEnvelope
        })
        && matches!(
            cap.adapter_status,
            AdapterStatus::DynamicApi | AdapterStatus::Blocked
        )
        && cap.verification.required
        && cap.verification.strategy == VERIFY
        && cap.rollback.supported
        && cap.rollback.strategy.as_deref() == Some(ROLLBACK)
        && cap.request_schema.as_ref() == Some(&request_schema())
        && cap.same_path_read.as_ref().is_some_and(|r| {
            r.path == READ_PATH
                && r.read_capability_id == READ_ID
                && r.verified_response_fields == FIELDS
        })
        && cap.selectors.len() == 3
        && ["zone_id", "ruleset_id", "rule_id"].iter().all(|name| {
            cap.selectors
                .iter()
                .any(|s| s.name == *name && s.location == "path" && s.required)
        })
}
fn id(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|s| s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit()))
}
fn version(value: &Value) -> Checked<u64> {
    let s = value.as_str().ok_or_else(rejected)?;
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(rejected());
    }
    s.parse().map_err(|_| rejected())
}
pub fn target<'a>(parent: &'a Value, selectors: &Value) -> Checked<&'a Value> {
    if selectors.as_object().is_none_or(|s| s.len() != 3)
        || ["zone_id", "ruleset_id", "rule_id"]
            .iter()
            .any(|key| !id(&selectors[*key]))
        || parent["id"] != selectors["ruleset_id"]
        || parent["phase"] != "http_response_headers_transform"
        || parent["kind"] != "zone"
        || version(&parent["version"]).is_err()
        || serde_json::to_vec(parent).map_err(|_| rejected())?.len() > 2 * 1024 * 1024
    {
        return Err(rejected());
    }
    let rules = parent["rules"]
        .as_array()
        .filter(|rules| !rules.is_empty() && rules.len() <= 1000)
        .ok_or_else(rejected)?;
    let mut ids = BTreeSet::new();
    for rule in rules {
        if !id(&rule["id"]) || !ids.insert(rule["id"].as_str().ok_or_else(rejected)?) {
            return Err(rejected());
        }
    }
    let target = rules
        .iter()
        .find(|rule| rule["id"] == selectors["rule_id"])
        .ok_or_else(rejected)?;
    version(&target["version"])?;
    if target.as_object().is_none_or(|r| {
        r.keys().any(|key| {
            !FIELDS.contains(&key.as_str())
                && !matches!(key.as_str(), "id" | "version" | "last_updated")
        })
    }) {
        return Err(rejected());
    }
    definition(target)?;
    Ok(target)
}
pub fn definition(rule: &Value) -> Checked<Value> {
    let mut body = serde_json::Map::new();
    for field in FIELDS {
        body.insert(field.into(), rule.get(field).ok_or_else(rejected)?.clone());
    }
    let body = Value::Object(body);
    if !valid_body(&body) {
        return Err(rejected());
    }
    Ok(body)
}
#[must_use]
pub fn valid_body(body: &Value) -> bool {
    let Some(fields) = body.as_object() else {
        return false;
    };
    if fields.len() != FIELDS.len()
        || FIELDS.iter().any(|key| !fields.contains_key(*key))
        || body["action"] != "rewrite"
        || !body["enabled"].is_boolean()
    {
        return false;
    }
    for (name, min, max) in [
        ("description", 0, 1024),
        ("expression", 1, 4096),
        ("ref", 1, 256),
    ] {
        if body[name]
            .as_str()
            .is_none_or(|s| s.len() < min || s.len() > max)
        {
            return false;
        }
    }
    let parameters = &body["action_parameters"];
    let Some(headers) = parameters["headers"].as_object() else {
        return false;
    };
    parameters.as_object().is_some_and(|p| p.len() == 1)
        && !headers.is_empty()
        && headers.len() <= 10
        && headers.iter().all(|(name, value)| {
            !name.is_empty()
                && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && value.as_object().is_some_and(|v| v.len() == 2)
                && value["operation"] == "set"
                && value["value"]
                    .as_str()
                    .is_some_and(|s| s.len() <= 16384 && !s.contains(['\r', '\n']))
        })
}
/// Only enablement and expression may change; all authored header fields stay exact.
pub fn validate_patch(parent: &Value, selectors: &Value, body: &Value) -> Checked<()> {
    if !valid_body(body) {
        return Err(rejected());
    }
    let previous = target(parent, selectors)?;
    if ["action", "action_parameters", "description", "ref"]
        .iter()
        .any(|key| previous[*key] != body[*key])
    {
        return Err(rejected());
    }
    Ok(())
}
pub fn verify_after(before: &Value, after: &Value, selectors: &Value, body: &Value) -> Checked<()> {
    validate_patch(before, selectors, body)?;
    let previous = target(before, selectors)?;
    let observed = target(after, selectors)?;
    if definition(observed)? != *body
        || version(&after["version"])? <= version(&before["version"])?
        || version(&observed["version"])? <= version(&previous["version"])?
    {
        return Err(rejected());
    }
    let mut expected = before.clone();
    let mut actual = after.clone();
    // Only provider-owned version/time on the parent and edited child can move.
    for value in [&mut expected, &mut actual] {
        let object = value.as_object_mut().ok_or_else(rejected)?;
        object.remove("version");
        object.remove("last_updated");
        let rules = object
            .get_mut("rules")
            .and_then(Value::as_array_mut)
            .ok_or_else(rejected)?;
        let rule = rules
            .iter_mut()
            .find(|r| r["id"] == selectors["rule_id"])
            .and_then(Value::as_object_mut)
            .ok_or_else(rejected)?;
        rule.remove("version");
        rule.remove("last_updated");
        for field in FIELDS {
            rule.insert(field.into(), body[field].clone());
        }
    }
    if expected != actual {
        return Err("unrelated ruleset fields, rules or order changed");
    }
    Ok(())
}

pub fn receipt(
    cap: &CapabilityV1,
    selectors: &Value,
    account: &str,
    parent: &Value,
    body: &Value,
) -> Checked<Value> {
    if !supported(cap) {
        return Err(rejected());
    }
    validate_patch(parent, selectors, body)?;
    Ok(
        json!({"schema_version":1,"source_capability_id":READ_ID,"source_path":READ_PATH,
        "target_capability_id":ID,"target_method":"PATCH","target_path":PATH,"target_scope":"zone",
        "account_id":account,"selectors":selectors,"prior_state":parent}),
    )
}
pub fn prior<'a>(plan: &'a crate::PlanV1, selectors: &Value, body: &Value) -> Checked<&'a Value> {
    let stored = plan
        .targets
        .pointer("/live_preconditions/same_path_prior_state")
        .ok_or_else(rejected)?;
    let parent = stored.get("prior_state").ok_or_else(rejected)?;
    if *stored != receipt(&plan.capability, selectors, &plan.account_id, parent, body)?
        || plan.precondition_hashes.get(PRECONDITION)
            != Some(&crate::hash_value(stored).map_err(|_| rejected())?)
    {
        return Err(rejected());
    }
    Ok(parent)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;
    fn body() -> Value {
        json!({"action":"rewrite","action_parameters":{"headers":{"Cache-Control":{"operation":"set","value":"no-store"}}},"description":"HTML cache policy","enabled":true,"expression":"http.host eq \"example.test\"","ref":"reference"})
    }
    fn fixture() -> (Value, Value, Value) {
        let selectors =
            json!({"zone_id":"a".repeat(32),"ruleset_id":"b".repeat(32),"rule_id":"c".repeat(32)});
        let mut target = body();
        target["id"] = selectors["rule_id"].clone();
        target["version"] = json!("5");
        let parent = json!({"id":selectors["ruleset_id"],"phase":"http_response_headers_transform","kind":"zone","version":"11","rules":[target,{"id":"d".repeat(32),"version":"3","action":"rewrite","opaque":{"keep":true}}]});
        (parent, selectors, body())
    }
    #[test]
    fn exact_patch_preserves_unrelated_rules_and_supports_prior_field_recovery() {
        let (before, selectors, mut body) = fixture();
        body["enabled"] = json!(false);
        assert!(validate_patch(&before, &selectors, &body).is_ok());
        let mut after = before.clone();
        after["version"] = json!("12");
        after["rules"][0]["version"] = json!("6");
        after["rules"][0]["enabled"] = json!(false);
        assert!(verify_after(&before, &after, &selectors, &body).is_ok());
        assert_eq!(
            definition(target(&before, &selectors).expect("target")).expect("definition")["enabled"],
            true
        );
        for mode in ["reorder", "other", "target", "phase", "version"] {
            let mut changed = after.clone();
            match mode {
                "reorder" => changed["rules"].as_array_mut().expect("rules").reverse(),
                "other" => changed["rules"][1]["opaque"]["keep"] = json!(false),
                "target" => changed["rules"][0]["expression"] = json!("true"),
                "phase" => changed["phase"] = json!("http_request_firewall_custom"),
                _ => changed["version"] = json!("11"),
            }
            assert!(
                verify_after(&before, &changed, &selectors, &body).is_err(),
                "{mode}"
            );
        }
    }
    #[test]
    fn rejects_partial_body_header_edits_unknown_rule_fields_and_ambiguous_identity() {
        let (before, selectors, mut body) = fixture();
        body["action_parameters"]["headers"]["Cache-Control"]["value"] = json!("public");
        assert!(validate_patch(&before, &selectors, &body).is_err());
        assert!(validate_patch(&before, &selectors, &json!({"enabled":false})).is_err());
        let mut duplicate = before.clone();
        duplicate["rules"][1]["id"] = selectors["rule_id"].clone();
        assert!(target(&duplicate, &selectors).is_err());
        let mut unknown = before.clone();
        unknown["rules"][0]["future_definition"] = json!(true);
        assert!(target(&unknown, &selectors).is_err());
    }
}
