//! Expression-only correction of an existing custom challenge rule.
use crate::{AdapterStatus, CapabilityV1, EffectClass, PlanV1, RiskClass, hash_value};
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub const ID: &str = "zone-custom-challenge-expression-update";
pub const PATH: &str = "/zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}";
pub const READ_ID: &str = "getZoneRuleset";
pub const READ_PATH: &str = "/zones/{zone_id}/rulesets/{ruleset_id}";
pub const VERIFY: &str = "custom_challenge_expression_and_unchanged_parent";
pub const ROLLBACK: &str = "restore_custom_challenge_expression_from_verified_state";
pub const PRECONDITION: &str = "same_path_prior_state";
pub const FIELDS: [&str; 5] = [
    "expression",
    "expected_expression",
    "expected_rule_version",
    "expected_ruleset_version",
    "expected_definition",
];
const DEFINITION_FIELDS: [&str; 5] = ["action", "enabled", "expression", "description", "ref"];
type Checked<T> = Result<T, &'static str>;
fn rejected() -> &'static str {
    "custom challenge expression contract rejected"
}

#[must_use]
pub fn request_schema() -> Value {
    json!({"type":"object","additionalProperties":false,"required":FIELDS,"properties":{
        "expression":{"type":"string","minLength":1,"maxLength":4096},
        "expected_expression":{"type":"string","minLength":1,"maxLength":4096},
        "expected_rule_version":{"type":"string","pattern":"^[0-9]+$","maxLength":20},
        "expected_ruleset_version":{"type":"string","pattern":"^[0-9]+$","maxLength":20},
        "expected_definition":{"type":"object","additionalProperties":false,"required":DEFINITION_FIELDS,"properties":{
            "action":{"enum":["managed_challenge","js_challenge"]},"enabled":{"type":"boolean"},
            "expression":{"type":"string","minLength":1,"maxLength":4096},
            "description":{"type":"string","maxLength":1024},"ref":{"type":"string","minLength":1,"maxLength":256}
        }}
    }})
}
#[must_use]
pub fn supported(cap: &CapabilityV1) -> bool {
    cap.id == ID
        && cap.method == "PATCH"
        && cap.path == PATH
        && cap.mutating
        && cap.account_scope == "zone"
        && matches!(
            cap.adapter_status,
            AdapterStatus::DynamicApi | AdapterStatus::Blocked
        )
        && cap.risk == RiskClass::IdentityOrOwnership
        && cap.effect == EffectClass::ReversibleWrite
        && cap.permissions == ["Zone WAF Read", "Zone WAF Write"]
        && cap.request_schema == Some(request_schema())
        && cap.verification.required
        && cap.verification.strategy == VERIFY
        && cap.rollback.supported
        && cap.rollback.strategy.as_deref() == Some(ROLLBACK)
        && cap.same_path_read.as_ref().is_some_and(|r| {
            r.path == READ_PATH
                && r.read_capability_id == READ_ID
                && r.verified_response_fields == ["expression"]
        })
        && cap.response_contract.as_ref().is_some_and(|r| {
            r.success_statuses == ["200"]
                && r.success_media_types == ["application/json"]
                && r.body_mode == crate::ResponseBodyModeV1::CloudflareJsonEnvelope
        })
        && cap.selectors.len() == 3
        && ["zone_id", "ruleset_id", "rule_id"].iter().all(|name| {
            cap.selectors
                .iter()
                .any(|s| s.name == *name && s.location == "path" && s.required)
        })
}
fn version(v: &Value) -> Checked<u64> {
    v.as_str()
        .filter(|s| !s.is_empty() && s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|s| s.parse().ok())
        .ok_or_else(rejected)
}
fn id(v: &Value) -> bool {
    v.as_str()
        .is_some_and(|s| s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit()))
}
fn expression(v: &Value) -> bool {
    v.as_str().is_some_and(|s| {
        !s.trim().is_empty() && s.len() <= 4096 && !s.chars().any(char::is_control)
    })
}
#[must_use]
pub fn valid_body(body: &Value) -> bool {
    body.as_object()
        .is_some_and(|b| b.len() == FIELDS.len() && FIELDS.iter().all(|k| b.contains_key(*k)))
        && expression(&body["expression"])
        && expression(&body["expected_expression"])
        && body["expression"] != body["expected_expression"]
        && version(&body["expected_rule_version"]).is_ok()
        && version(&body["expected_ruleset_version"]).is_ok()
        && valid_definition(&body["expected_definition"])
        && body["expected_definition"]["expression"] == body["expected_expression"]
}
fn valid_definition(value: &Value) -> bool {
    value.as_object().is_some_and(|o| {
        o.len() == DEFINITION_FIELDS.len() && DEFINITION_FIELDS.iter().all(|k| o.contains_key(*k))
    }) && matches!(
        value["action"].as_str(),
        Some("managed_challenge" | "js_challenge")
    ) && value["enabled"].is_boolean()
        && expression(&value["expression"])
        && value["description"]
            .as_str()
            .is_some_and(|s| s.len() <= 1024)
        && value["ref"]
            .as_str()
            .is_some_and(|s| !s.is_empty() && s.len() <= 256)
}
pub fn definition(rule: &Value) -> Checked<Value> {
    let mut value = rule.as_object().ok_or_else(rejected)?.clone();
    for k in ["id", "version", "last_updated"] {
        value.remove(k);
    }
    let value = Value::Object(value);
    if !valid_definition(&value) {
        return Err(rejected());
    }
    Ok(value)
}
pub fn wire_body(body: &Value) -> Checked<Value> {
    if !valid_body(body) {
        return Err(rejected());
    }
    let mut wire = body["expected_definition"].clone();
    wire["expression"] = body["expression"].clone();
    Ok(wire)
}
pub fn target<'a>(parent: &'a Value, selectors: &Value) -> Checked<&'a Value> {
    if selectors.as_object().is_none_or(|s| s.len() != 3)
        || ["zone_id", "ruleset_id", "rule_id"]
            .iter()
            .any(|k| !id(&selectors[*k]))
        || parent["id"] != selectors["ruleset_id"]
        || parent["kind"] != "zone"
        || parent["phase"] != "http_request_firewall_custom"
        || version(&parent["version"]).is_err()
        || serde_json::to_vec(parent).map_err(|_| rejected())?.len() > 2 * 1024 * 1024
    {
        return Err(rejected());
    }
    let rules = parent["rules"]
        .as_array()
        .filter(|r| !r.is_empty() && r.len() <= 1000)
        .ok_or_else(rejected)?;
    let mut ids = BTreeSet::new();
    for r in rules {
        if !id(&r["id"]) || !ids.insert(r["id"].as_str().ok_or_else(rejected)?) {
            return Err(rejected());
        }
    }
    let r = rules
        .iter()
        .find(|r| r["id"] == selectors["rule_id"])
        .ok_or_else(rejected)?;
    if !matches!(
        r["action"].as_str(),
        Some("managed_challenge" | "js_challenge")
    ) || !r["enabled"].is_boolean()
        || !expression(&r["expression"])
        || version(&r["version"]).is_err()
    {
        return Err(rejected());
    }
    definition(r)?;
    Ok(r)
}
pub fn validate_patch(parent: &Value, selectors: &Value, body: &Value) -> Checked<()> {
    let r = target(parent, selectors)?;
    if !valid_body(body)
        || r["expression"] != body["expected_expression"]
        || r["version"] != body["expected_rule_version"]
        || parent["version"] != body["expected_ruleset_version"]
        || definition(r)? != body["expected_definition"]
    {
        return Err("expected challenge expression or versions drifted; create a fresh plan");
    }
    Ok(())
}
fn normalized(parent: &Value, selectors: &Value, replacement: &Value) -> Checked<Value> {
    target(parent, selectors)?;
    let mut v = parent.clone();
    let o = v.as_object_mut().ok_or_else(rejected)?;
    o.remove("version");
    o.remove("last_updated");
    let r = o
        .get_mut("rules")
        .and_then(Value::as_array_mut)
        .ok_or_else(rejected)?
        .iter_mut()
        .find(|r| r["id"] == selectors["rule_id"])
        .and_then(Value::as_object_mut)
        .ok_or_else(rejected)?;
    r.remove("version");
    r.remove("last_updated");
    r.insert("expression".into(), replacement.clone());
    Ok(v)
}
pub fn verify_after(before: &Value, after: &Value, selectors: &Value, body: &Value) -> Checked<()> {
    validate_patch(before, selectors, body)?;
    let old = target(before, selectors)?;
    let new = target(after, selectors)?;
    if new["expression"] != body["expression"]
        || version(&new["version"])? <= version(&old["version"])?
        || version(&after["version"])? <= version(&before["version"])?
        || normalized(before, selectors, &body["expression"])?
            != normalized(after, selectors, &body["expression"])?
    {
        return Err("challenge expression, unrelated fields or rule order failed verification");
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
pub fn prior<'a>(plan: &'a PlanV1, selectors: &Value, body: &Value) -> Checked<&'a Value> {
    let stored = plan
        .targets
        .pointer("/live_preconditions/same_path_prior_state")
        .ok_or_else(rejected)?;
    let parent = stored.get("prior_state").ok_or_else(rejected)?;
    if *stored != receipt(&plan.capability, selectors, &plan.account_id, parent, body)?
        || plan.precondition_hashes.get(PRECONDITION)
            != Some(&hash_value(stored).map_err(|_| rejected())?)
    {
        return Err(rejected());
    }
    Ok(parent)
}
/// Recovery uses the apply response and authenticated readback, not inferred versions.
/// Unrelated parent drift is preserved; later target edits refuse recovery.
pub fn recovery_body(
    before: &Value,
    applied: &Value,
    observed: &Value,
    selectors: &Value,
    body: &Value,
) -> Checked<Value> {
    validate_patch(before, selectors, body)?;
    let applied_rule = target(applied, selectors)?;
    let r = target(observed, selectors)?;
    if definition(applied_rule)? != wire_body(body)?
        || applied_rule != r
        || version(&applied_rule["version"])? <= version(&target(before, selectors)?["version"])?
        || version(&applied["version"])? <= version(&before["version"])?
        || version(&observed["version"])? < version(&applied["version"])?
    {
        return Err(
            "post-write target changed or apply evidence missing; reconcile without replay",
        );
    }
    Ok(
        json!({"expression":body["expected_expression"],"expected_expression":body["expression"],
        "expected_rule_version":r["version"],"expected_ruleset_version":observed["version"],
        "expected_definition":definition(r)?}),
    )
}

#[cfg(test)]
mod tests;
