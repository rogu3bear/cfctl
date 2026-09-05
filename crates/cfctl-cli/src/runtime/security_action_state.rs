use super::cloudflare_api::BASE_URL as API_BASE_URL;
use super::import_planning::SECURITY_IP_RULE_COLLECTION_PATH;
use super::import_planning::SECURITY_IP_RULE_CREATE_ID;
use super::import_planning::SECURITY_IP_RULE_REMOVE_ID;
use super::import_planning::SECURITY_IP_RULE_STATE_CAPABILITY_ID;
use super::import_planning::SECURITY_LIST_MEMBER_COLLECTION_PATH;
use super::import_planning::SECURITY_LIST_MEMBER_CREATE_ID;
use super::import_planning::SECURITY_LIST_MEMBER_REMOVE_ID;
use super::import_planning::SECURITY_LIST_MEMBER_STATE_CAPABILITY_ID;
use super::import_planning::SECURITY_LIST_METADATA_CAPABILITY_ID;
use super::import_planning::SECURITY_LIST_METADATA_PATH;
use super::import_planning::SECURITY_WAF_RULE_CREATE_ID;
use super::import_planning::SECURITY_WAF_RULE_PARENT_PATH;
use super::import_planning::SECURITY_WAF_RULE_REMOVE_ID;
use super::import_planning::SECURITY_WAF_RULE_STATE_CAPABILITY_ID;
use super::plan_commands::load_validated_plan;
use super::prelude::{
    AdapterStatus, AuthCredential, CallInput, CapabilityV1, CatalogSnapshot, CliError,
    CloudflareResponseV1, EvidenceClass, EvidenceV1, Executor, PlanStatus, PlanV1, Result,
    StateStore, TransactionStageV1, Value, json,
};
use super::support::capability_missing;
use super::support::http_client;
use cfctl_core::hash_value;

pub(super) fn security_action_adapter_target(adapter_targets: &Value) -> Option<&Value> {
    adapter_targets
        .get("security_action")
        .filter(|value| value.is_object())
}

pub(super) fn should_bind_security_action_state(
    capability: &CapabilityV1,
    adapter_targets: &Value,
) -> bool {
    capability.security_action_contract_supported()
        && matches!(
            capability.id.as_str(),
            SECURITY_IP_RULE_CREATE_ID
                | SECURITY_IP_RULE_REMOVE_ID
                | SECURITY_WAF_RULE_CREATE_ID
                | SECURITY_WAF_RULE_REMOVE_ID
                | SECURITY_LIST_MEMBER_CREATE_ID
                | SECURITY_LIST_MEMBER_REMOVE_ID
        )
        && security_action_adapter_target(adapter_targets).is_some()
}

pub(super) fn security_collection_complete(response: &CloudflareResponseV1) -> bool {
    response.result_info.as_ref().is_some_and(|result_info| {
        let page = result_info.get("page").and_then(Value::as_u64);
        let total_pages = result_info.get("total_pages").and_then(Value::as_u64);
        (page.is_some() && page == total_pages)
            || result_info
                .get("cfctl_cursor_complete")
                .and_then(Value::as_bool)
                == Some(true)
    })
}

pub(super) fn collection_read_complete(response: &CloudflareResponseV1) -> bool {
    security_collection_complete(response)
}

pub(super) fn security_rule_planned_body(plan: &PlanV1) -> Result<Value> {
    let input: CallInput = serde_json::from_value(plan.input.clone())?;
    input.body.ok_or_else(|| {
        CliError::Input(
            "source security action plan omitted its exact Cloudflare rule body".to_owned(),
        )
    })
}

pub(super) fn validate_security_action_removal_source(
    store: &StateStore,
    metadata: &Value,
    zone_id: &str,
    rule_id: &str,
) -> Result<Value> {
    let operation_id = metadata
        .get("source_operation_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input("expired-action removal omitted its source operation ID".to_owned())
        })?;
    let plan = load_validated_plan(store, operation_id)?;
    if plan.status != PlanStatus::Verified
        || plan.capability.id != SECURITY_IP_RULE_CREATE_ID
        || plan
            .targets
            .pointer("/selectors/zone_id")
            .and_then(Value::as_str)
            != Some(zone_id)
        || plan
            .targets
            .pointer("/adapter/security_action/evidence_ref")
            .and_then(Value::as_str)
            != metadata.get("evidence_ref").and_then(Value::as_str)
        || plan
            .targets
            .pointer("/adapter/security_action/expires_at")
            .and_then(Value::as_str)
            != metadata.get("expires_at").and_then(Value::as_str)
    {
        return Err(CliError::Input(
            "expired-action removal is not bound to a verified source security-action plan with the same zone, evidence, and deadline"
                .to_owned(),
        ));
    }
    let boundary_rule_id = plan
        .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
        .and_then(|artifact| artifact.get("resource_id"))
        .and_then(Value::as_str);
    if boundary_rule_id != Some(rule_id) {
        return Err(CliError::Input(
            "expired-action rule ID does not match the hash-bound identity returned by its source plan"
                .to_owned(),
        ));
    }
    security_rule_planned_body(&plan)
}

#[expect(
    clippy::too_many_lines,
    reason = "IP access-rule verification deliberately captures current state, audit lineage, expiry, conflicts, and removal guidance in one receipt"
)]
pub(super) fn security_action_state_receipt(
    store: &StateStore,
    capability: &CapabilityV1,
    input: &CallInput,
    adapter_targets: &Value,
    account_id: &str,
    response: &CloudflareResponseV1,
) -> Result<Value> {
    if !response.success || !(200..300).contains(&response.status) {
        return Err(CliError::Input(format!(
            "Cloudflare rejected the security-action current-state read with HTTP {}; the mutation boundary was not crossed",
            response.status
        )));
    }
    if !security_collection_complete(response) {
        return Err(CliError::Input(
            "security-action current-state read did not prove complete pagination; the mutation boundary was not crossed"
                .to_owned(),
        ));
    }
    let rules = response.result.as_array().ok_or_else(|| {
        CliError::Input(
            "security-action current-state read did not return a rule collection".to_owned(),
        )
    })?;
    let metadata = security_action_adapter_target(adapter_targets).ok_or_else(|| {
        CliError::Input("security-action governance receipt is missing".to_owned())
    })?;
    let zone_id = input
        .selectors
        .get("zone_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CliError::Input("security action requires `zone_id`".to_owned()))?;
    let kind = metadata
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input("security-action governance receipt omitted its kind".to_owned())
        })?;
    let state = match kind {
        "create_expiring" => {
            let target = metadata.get("target").ok_or_else(|| {
                CliError::Input("security-action governance receipt omitted its target".to_owned())
            })?;
            let conflicts = rules
                .iter()
                .filter(|rule| rule.get("configuration") == Some(target))
                .map(|rule| {
                    json!({
                        "id":rule.get("id").cloned().unwrap_or(Value::Null),
                        "mode":rule.get("mode").cloned().unwrap_or(Value::Null),
                        "notes_hash":rule.get("notes").map(hash_value).transpose().unwrap_or(None),
                    })
                })
                .collect::<Vec<_>>();
            if !conflicts.is_empty() {
                return Err(CliError::Input(format!(
                    "security action target already has {} matching rule(s); inspect and resolve the duplicate or conflict before creating another action",
                    conflicts.len()
                )));
            }
            json!({
                "matching_rule_count":0,
                "target":target,
                "action":metadata.get("action").cloned().unwrap_or(Value::Null),
            })
        }
        "remove_expired" => {
            let rule_id = input
                .selectors
                .get("rule_id")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    CliError::Input("expired-action removal requires `rule_id`".to_owned())
                })?;
            let planned_rule =
                validate_security_action_removal_source(store, metadata, zone_id, rule_id)?;
            let matching = rules
                .iter()
                .filter(|rule| rule.get("id").and_then(Value::as_str) == Some(rule_id))
                .collect::<Vec<_>>();
            if matching.len() != 1 {
                return Err(CliError::Input(format!(
                    "expired-action removal requires exactly one live rule with the source identity; found {}",
                    matching.len()
                )));
            }
            let live_projection = json!({
                "configuration":matching[0].get("configuration").cloned().unwrap_or(Value::Null),
                "mode":matching[0].get("mode").cloned().unwrap_or(Value::Null),
                "notes":matching[0].get("notes").cloned().unwrap_or(Value::Null),
            });
            if live_projection != planned_rule {
                return Err(CliError::Input(
                    "expired security rule drifted from the exact body verified by its source operation; inspect it before removal"
                        .to_owned(),
                ));
            }
            json!({
                "matching_rule_count":1,
                "rule_id":rule_id,
                "live_rule_hash":hash_value(&live_projection)?,
                "source_operation_id":metadata.get("source_operation_id").cloned().unwrap_or(Value::Null),
            })
        }
        _ => {
            return Err(CliError::Input(
                "security-action governance receipt has an unsupported kind".to_owned(),
            ));
        }
    };
    Ok(json!({
        "schema_version":1,
        "source_capability_id":SECURITY_IP_RULE_STATE_CAPABILITY_ID,
        "source_path":SECURITY_IP_RULE_COLLECTION_PATH,
        "target_capability_id":capability.id,
        "target_method":capability.method,
        "target_path":capability.path,
        "account_id":account_id,
        "zone_id":zone_id,
        "kind":kind,
        "evidence_ref":metadata.get("evidence_ref").cloned().unwrap_or(Value::Null),
        "expires_at":metadata.get("expires_at").cloned().unwrap_or(Value::Null),
        "state":state,
    }))
}

pub(super) fn validate_waf_security_action_removal_source(
    store: &StateStore,
    metadata: &Value,
    zone_id: &str,
    ruleset_id: &str,
    rule_id: &str,
) -> Result<Value> {
    let operation_id = metadata
        .get("source_operation_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input("expired WAF action omitted its source operation ID".to_owned())
        })?;
    let plan = load_validated_plan(store, operation_id)?;
    if plan.status != PlanStatus::Verified
        || plan.capability.id != SECURITY_WAF_RULE_CREATE_ID
        || plan
            .targets
            .pointer("/selectors/zone_id")
            .and_then(Value::as_str)
            != Some(zone_id)
        || plan
            .targets
            .pointer("/selectors/ruleset_id")
            .and_then(Value::as_str)
            != Some(ruleset_id)
        || plan
            .targets
            .pointer("/adapter/security_action/evidence_ref")
            .and_then(Value::as_str)
            != metadata.get("evidence_ref").and_then(Value::as_str)
        || plan
            .targets
            .pointer("/adapter/security_action/expires_at")
            .and_then(Value::as_str)
            != metadata.get("expires_at").and_then(Value::as_str)
    {
        return Err(CliError::Input(
            "expired WAF removal is not bound to a verified source security-action plan with the same zone, ruleset, evidence, and deadline"
                .to_owned(),
        ));
    }
    let boundary_rule_id = plan
        .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
        .and_then(|artifact| artifact.get("resource_id"))
        .and_then(Value::as_str);
    if boundary_rule_id != Some(rule_id) {
        return Err(CliError::Input(
            "expired WAF rule ID does not match the correlated identity in its source plan receipt"
                .to_owned(),
        ));
    }
    security_rule_planned_body(&plan)
}

#[expect(
    clippy::too_many_lines,
    reason = "WAF verification deliberately binds ruleset state, normalized target, audit lineage, expiry, conflicts, and rollback guidance in one receipt"
)]
pub(super) fn waf_security_action_state_receipt(
    store: &StateStore,
    capability: &CapabilityV1,
    input: &CallInput,
    adapter_targets: &Value,
    account_id: &str,
    response: &CloudflareResponseV1,
) -> Result<Value> {
    if !response.success || response.status != 200 {
        return Err(CliError::Input(format!(
            "Cloudflare rejected the WAF current-state read with HTTP {}; the mutation boundary was not crossed",
            response.status
        )));
    }
    let rules = response
        .result
        .get("rules")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CliError::Input(
                "WAF current-state read did not return the complete ruleset rule array".to_owned(),
            )
        })?;
    let metadata = security_action_adapter_target(adapter_targets).ok_or_else(|| {
        CliError::Input("WAF security-action governance receipt is missing".to_owned())
    })?;
    let zone_id = input
        .selectors
        .get("zone_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CliError::Input("WAF security action requires `zone_id`".to_owned()))?;
    let ruleset_id = input
        .selectors
        .get("ruleset_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CliError::Input("WAF security action requires `ruleset_id`".to_owned()))?;
    let kind = metadata
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input("WAF security-action governance receipt omitted its kind".to_owned())
        })?;
    let state = match kind {
        "create_expiring_waf" => {
            let correlation = metadata
                .get("correlation_ref")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    CliError::Input(
                        "WAF security-action receipt omitted its correlation reference".to_owned(),
                    )
                })?;
            let expression = metadata
                .get("expression")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    CliError::Input(
                        "WAF security-action receipt omitted its compiled expression".to_owned(),
                    )
                })?;
            let conflicts = rules
                .iter()
                .filter(|rule| {
                    rule.get("ref").and_then(Value::as_str) == Some(correlation)
                        || rule.get("expression").and_then(Value::as_str) == Some(expression)
                })
                .map(|rule| {
                    json!({
                        "id":rule.get("id").cloned().unwrap_or(Value::Null),
                        "action":rule.get("action").cloned().unwrap_or(Value::Null),
                        "ref":rule.get("ref").cloned().unwrap_or(Value::Null),
                        "expression_hash":rule.get("expression").map(hash_value).transpose().unwrap_or(None),
                    })
                })
                .collect::<Vec<_>>();
            if !conflicts.is_empty() {
                return Err(CliError::Input(format!(
                    "WAF target already has {} correlated or expression-equivalent rule(s); inspect and resolve the duplicate or conflict before creating another action",
                    conflicts.len()
                )));
            }
            json!({
                "matching_rule_count":0,
                "correlation_ref":correlation,
                "expression_hash":hash_value(&Value::String(expression.to_owned()))?,
                "action":metadata.get("action").cloned().unwrap_or(Value::Null),
                "ruleset_rule_count":rules.len(),
            })
        }
        "remove_expired_waf" => {
            let rule_id = input
                .selectors
                .get("rule_id")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    CliError::Input("expired WAF removal requires `rule_id`".to_owned())
                })?;
            let planned_rule = validate_waf_security_action_removal_source(
                store, metadata, zone_id, ruleset_id, rule_id,
            )?;
            let matching = rules
                .iter()
                .filter(|rule| rule.get("id").and_then(Value::as_str) == Some(rule_id))
                .collect::<Vec<_>>();
            if matching.len() != 1 {
                return Err(CliError::Input(format!(
                    "expired WAF removal requires exactly one live rule with the source identity; found {}",
                    matching.len()
                )));
            }
            let planned = planned_rule.as_object().ok_or_else(|| {
                CliError::Input("verified source WAF body is not an object".to_owned())
            })?;
            let live_projection = Value::Object(
                planned
                    .keys()
                    .map(|key| {
                        (
                            key.clone(),
                            matching[0].get(key).cloned().unwrap_or(Value::Null),
                        )
                    })
                    .collect(),
            );
            if live_projection != planned_rule {
                return Err(CliError::Input(
                    "expired WAF rule drifted from the exact body verified by its source operation; inspect it before removal"
                        .to_owned(),
                ));
            }
            json!({
                "matching_rule_count":1,
                "rule_id":rule_id,
                "live_rule_hash":hash_value(&live_projection)?,
                "source_operation_id":metadata.get("source_operation_id").cloned().unwrap_or(Value::Null),
            })
        }
        _ => {
            return Err(CliError::Input(
                "WAF security-action governance receipt has an unsupported kind".to_owned(),
            ));
        }
    };
    Ok(json!({
        "schema_version":1,
        "source_capability_id":SECURITY_WAF_RULE_STATE_CAPABILITY_ID,
        "source_path":SECURITY_WAF_RULE_PARENT_PATH,
        "target_capability_id":capability.id,
        "target_method":capability.method,
        "target_path":capability.path,
        "account_id":account_id,
        "zone_id":zone_id,
        "ruleset_id":ruleset_id,
        "kind":kind,
        "evidence_ref":metadata.get("evidence_ref").cloned().unwrap_or(Value::Null),
        "expires_at":metadata.get("expires_at").cloned().unwrap_or(Value::Null),
        "state":state,
    }))
}

pub(super) fn list_item_target_projection(item: &Value) -> Option<Value> {
    let mut targets = Vec::new();
    if let Some(ip) = item.get("ip").and_then(Value::as_str) {
        targets.push(json!({"ip":ip}));
    }
    if let Some(asn) = item.get("asn").and_then(Value::as_u64) {
        targets.push(json!({"asn":asn}));
    }
    if let Some(hostname) = item
        .pointer("/hostname/url_hostname")
        .and_then(Value::as_str)
    {
        targets.push(json!({"hostname":{"url_hostname":hostname}}));
    }
    (targets.len() == 1).then(|| targets.remove(0))
}

pub(super) fn list_item_verification_projection(item: &Value) -> Option<Value> {
    let comment = item
        .get("comment")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())?;
    let mut projection = list_item_target_projection(item)?.as_object()?.clone();
    projection.insert("comment".to_owned(), Value::String(comment.to_owned()));
    Some(Value::Object(projection))
}

pub(super) fn validated_list_member_removal_source(
    store: &StateStore,
    metadata: &Value,
    account_id: &str,
    list_id: &str,
    member_id: &str,
) -> Result<Value> {
    let operation_id = metadata
        .get("source_operation_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "expired List member removal omitted its source operation ID".to_owned(),
            )
        })?;
    let plan = load_validated_plan(store, operation_id)?;
    let verification_passed = plan
        .transaction_artifact(TransactionStageV1::VerificationResponsePersisted)
        .and_then(|artifact| artifact.get("state"))
        .and_then(Value::as_str)
        == Some("passed");
    if !(plan.status == PlanStatus::Verified
        || (plan.status == PlanStatus::RectificationRequired && verification_passed))
        || plan.capability.id != SECURITY_LIST_MEMBER_CREATE_ID
        || plan
            .targets
            .pointer("/selectors/account_id")
            .and_then(Value::as_str)
            != Some(account_id)
        || plan
            .targets
            .pointer("/selectors/list_id")
            .and_then(Value::as_str)
            != Some(list_id)
        || plan
            .targets
            .pointer("/adapter/security_action/evidence_ref")
            .and_then(Value::as_str)
            != metadata.get("evidence_ref").and_then(Value::as_str)
        || plan
            .targets
            .pointer("/adapter/security_action/expires_at")
            .and_then(Value::as_str)
            != metadata.get("expires_at").and_then(Value::as_str)
    {
        return Err(CliError::Input(
            "expired List member removal is not bound to a verified source add with the same account, list, evidence, and deadline"
                .to_owned(),
        ));
    }
    let verified_member_id = plan
        .transaction_artifact(TransactionStageV1::VerificationResponsePersisted)
        .and_then(|artifact| artifact.get("resource_id"))
        .and_then(Value::as_str);
    if verified_member_id != Some(member_id) {
        return Err(CliError::Input(
            "List member ID does not match the correlated identity in the source verification receipt"
                .to_owned(),
        ));
    }
    let source_input: CallInput = serde_json::from_value(plan.input.clone())?;
    source_input
        .body
        .as_ref()
        .and_then(Value::as_array)
        .filter(|items| items.len() == 1)
        .and_then(|items| items.first())
        .and_then(list_item_verification_projection)
        .ok_or_else(|| {
            CliError::Input(
                "verified source List plan omitted its exact one-member wire projection".to_owned(),
            )
        })
}

#[expect(
    clippy::too_many_lines,
    reason = "list-member verification deliberately binds list and member state, consumer scope, expiry, duplicate detection, and removal guidance"
)]
pub(super) fn list_security_action_state_receipt(
    store: &StateStore,
    capability: &CapabilityV1,
    input: &CallInput,
    adapter_targets: &Value,
    account_id: &str,
    metadata_response: &CloudflareResponseV1,
    items_response: &CloudflareResponseV1,
) -> Result<Value> {
    if !metadata_response.success || metadata_response.status != 200 {
        return Err(CliError::Input(format!(
            "Cloudflare rejected the List metadata read with HTTP {}; the mutation boundary was not crossed",
            metadata_response.status
        )));
    }
    if !items_response.success || items_response.status != 200 {
        return Err(CliError::Input(format!(
            "Cloudflare rejected the List member read with HTTP {}; the mutation boundary was not crossed",
            items_response.status
        )));
    }
    if !security_collection_complete(items_response) {
        return Err(CliError::Input(
            "List member current-state read did not prove complete cursor pagination; the mutation boundary was not crossed"
                .to_owned(),
        ));
    }
    let list_kind = metadata_response
        .result
        .get("kind")
        .and_then(Value::as_str)
        .filter(|kind| matches!(*kind, "ip" | "asn" | "hostname"))
        .ok_or_else(|| {
            CliError::Input(
                "List metadata did not report one governed IP, ASN, or hostname kind".to_owned(),
            )
        })?;
    let items = items_response.result.as_array().ok_or_else(|| {
        CliError::Input("List member current-state read did not return an item array".to_owned())
    })?;
    let metadata = security_action_adapter_target(adapter_targets).ok_or_else(|| {
        CliError::Input("List security-action governance receipt is missing".to_owned())
    })?;
    let list_id = input
        .selectors
        .get("list_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CliError::Input("List security action requires `list_id`".to_owned()))?;
    let kind = metadata
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input("List security-action receipt omitted its kind".to_owned())
        })?;
    let state = match kind {
        "add_expiring_list_member" => {
            let planned = input
                .body
                .as_ref()
                .and_then(Value::as_array)
                .filter(|items| items.len() == 1)
                .and_then(|items| items.first())
                .ok_or_else(|| {
                    CliError::Input("List add plan does not contain one wire item".to_owned())
                })?;
            let target = metadata.get("target").ok_or_else(|| {
                CliError::Input("List security-action receipt omitted its target".to_owned())
            })?;
            let expected_kind = match target.get("type").and_then(Value::as_str) {
                Some("ip" | "ip_range") => "ip",
                Some("asn") => "asn",
                Some("hostname") => "hostname",
                _ => {
                    return Err(CliError::Input(
                        "List security target type is outside the governed kind mapping".to_owned(),
                    ));
                }
            };
            if list_kind != expected_kind {
                return Err(CliError::Input(format!(
                    "target type requires a `{expected_kind}` List, but the selected List reports kind `{list_kind}`"
                )));
            }
            let planned_target = list_item_target_projection(planned).ok_or_else(|| {
                CliError::Input("List add plan has no exact target projection".to_owned())
            })?;
            let planned_comment = planned.get("comment").and_then(Value::as_str);
            let conflicts = items
                .iter()
                .filter(|item| {
                    list_item_target_projection(item).as_ref() == Some(&planned_target)
                        || (planned_comment.is_some()
                            && item.get("comment").and_then(Value::as_str) == planned_comment)
                })
                .count();
            if conflicts != 0 {
                return Err(CliError::Input(format!(
                    "selected List already has {conflicts} target-equivalent or correlation-equivalent member(s); resolve the duplicate before adding another"
                )));
            }
            json!({
                "matching_member_count":0,
                "target_hash":hash_value(&planned_target)?,
                "expected_consumer_action":metadata.get("expected_consumer_action").cloned().unwrap_or(Value::Null),
                "consumer_scope_confirmed":metadata.get("consumer_scope_confirmed").cloned().unwrap_or(Value::Null),
            })
        }
        "remove_expired_list_member" => {
            let member_id = metadata
                .get("member_id")
                .and_then(Value::as_str)
                .filter(|identity| !identity.is_empty())
                .ok_or_else(|| {
                    CliError::Input("expired List removal omitted its member identity".to_owned())
                })?;
            let planned = validated_list_member_removal_source(
                store, metadata, account_id, list_id, member_id,
            )?;
            let matching = items
                .iter()
                .filter(|item| item.get("id").and_then(Value::as_str) == Some(member_id))
                .collect::<Vec<_>>();
            if matching.len() != 1 {
                return Err(CliError::Input(format!(
                    "expired List removal requires exactly one live member with the source identity; found {}",
                    matching.len()
                )));
            }
            let live = list_item_verification_projection(matching[0]).ok_or_else(|| {
                CliError::Input("live List member has an invalid target/comment shape".to_owned())
            })?;
            if live != planned {
                return Err(CliError::Input(
                    "expired List member drifted from the exact target and audit comment verified by its source operation"
                        .to_owned(),
                ));
            }
            json!({
                "matching_member_count":1,
                "member_id":member_id,
                "live_member_hash":hash_value(&live)?,
                "source_operation_id":metadata.get("source_operation_id").cloned().unwrap_or(Value::Null),
            })
        }
        _ => {
            return Err(CliError::Input(
                "List security-action receipt has an unsupported kind".to_owned(),
            ));
        }
    };
    Ok(json!({
        "schema_version":1,
        "source_capability_ids":[SECURITY_LIST_METADATA_CAPABILITY_ID,SECURITY_LIST_MEMBER_STATE_CAPABILITY_ID],
        "source_paths":[SECURITY_LIST_METADATA_PATH,SECURITY_LIST_MEMBER_COLLECTION_PATH],
        "target_capability_id":capability.id,
        "target_method":capability.method,
        "target_path":capability.path,
        "account_id":account_id,
        "list_id":list_id,
        "list_kind":list_kind,
        "list_item_count":items.len(),
        "kind":kind,
        "evidence_ref":metadata.get("evidence_ref").cloned().unwrap_or(Value::Null),
        "expires_at":metadata.get("expires_at").cloned().unwrap_or(Value::Null),
        "state":state,
        "redaction":"raw List target values and audit comments are represented only by hashes",
    }))
}

#[expect(
    clippy::too_many_lines,
    reason = "security-action current-state reads form one fail-closed dispatcher whose branches produce the evidence bound into immutable plans"
)]
pub(super) async fn read_live_security_action_state(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    adapter_targets: &Value,
    account_id: &str,
    credential: &AuthCredential,
) -> Result<(Value, EvidenceV1)> {
    if !should_bind_security_action_state(capability, adapter_targets) {
        return Err(CliError::Input(
            "security action drifted from its governed current-state contract".to_owned(),
        ));
    }
    if matches!(
        capability.id.as_str(),
        SECURITY_LIST_MEMBER_CREATE_ID | SECURITY_LIST_MEMBER_REMOVE_ID
    ) {
        let metadata_source = catalog
            .get(SECURITY_LIST_METADATA_CAPABILITY_ID)
            .ok_or_else(|| capability_missing(SECURITY_LIST_METADATA_CAPABILITY_ID))?;
        let items_source = catalog
            .get(SECURITY_LIST_MEMBER_STATE_CAPABILITY_ID)
            .ok_or_else(|| capability_missing(SECURITY_LIST_MEMBER_STATE_CAPABILITY_ID))?;
        if metadata_source.method != "GET"
            || metadata_source.path != SECURITY_LIST_METADATA_PATH
            || metadata_source.mutating
            || items_source.method != "GET"
            || items_source.path != SECURITY_LIST_MEMBER_COLLECTION_PATH
            || items_source.mutating
            || !matches!(
                metadata_source.adapter_status,
                AdapterStatus::Native | AdapterStatus::DynamicApi
            )
            || !matches!(
                items_source.adapter_status,
                AdapterStatus::Native | AdapterStatus::DynamicApi
            )
        {
            return Err(CliError::Input(
                "List security-action state sources drifted from the governed metadata plus complete-member reads"
                    .to_owned(),
            ));
        }
        let selectors = json!({
            "account_id":input.selectors.get("account_id").cloned().unwrap_or(Value::Null),
            "list_id":input.selectors.get("list_id").cloned().unwrap_or(Value::Null),
        });
        let executor = Executor::new(http_client()?, API_BASE_URL)?;
        let metadata_response = executor
            .execute_read(
                metadata_source,
                &CallInput {
                    selectors: selectors.clone(),
                    query: json!({}),
                    body: None,
                    ..CallInput::default()
                },
                credential,
            )
            .await?;
        let items_response = executor
            .execute_read(
                items_source,
                &CallInput {
                    selectors,
                    query: json!({"per_page":500}),
                    body: None,
                    ..CallInput::default()
                },
                credential,
            )
            .await?;
        let receipt = list_security_action_state_receipt(
            store,
            capability,
            input,
            adapter_targets,
            account_id,
            &metadata_response,
            &items_response,
        )?;
        let evidence = store.write_observation_evidence(EvidenceClass::LiveRead, &receipt)?;
        return Ok((receipt, evidence));
    }
    if matches!(
        capability.id.as_str(),
        SECURITY_WAF_RULE_CREATE_ID | SECURITY_WAF_RULE_REMOVE_ID
    ) {
        let source = catalog
            .get(SECURITY_WAF_RULE_STATE_CAPABILITY_ID)
            .ok_or_else(|| capability_missing(SECURITY_WAF_RULE_STATE_CAPABILITY_ID))?;
        if source.method != "GET"
            || source.path != SECURITY_WAF_RULE_PARENT_PATH
            || source.mutating
            || !matches!(
                source.adapter_status,
                AdapterStatus::Native | AdapterStatus::DynamicApi
            )
        {
            return Err(CliError::Input(
                "WAF state source capability drifted from the governed exact-ruleset read"
                    .to_owned(),
            ));
        }
        let response = Executor::new(http_client()?, API_BASE_URL)?
            .execute_read(
                source,
                &CallInput {
                    selectors: json!({
                        "zone_id":input.selectors.get("zone_id").cloned().unwrap_or(Value::Null),
                        "ruleset_id":input.selectors.get("ruleset_id").cloned().unwrap_or(Value::Null),
                    }),
                    query: json!({}),
                    body: None,
                    ..CallInput::default()
                },
                credential,
            )
            .await?;
        let receipt = waf_security_action_state_receipt(
            store,
            capability,
            input,
            adapter_targets,
            account_id,
            &response,
        )?;
        let evidence = store.write_observation_evidence(EvidenceClass::LiveRead, &receipt)?;
        return Ok((receipt, evidence));
    }
    let source = catalog
        .get(SECURITY_IP_RULE_STATE_CAPABILITY_ID)
        .ok_or_else(|| capability_missing(SECURITY_IP_RULE_STATE_CAPABILITY_ID))?;
    if source.method != "GET"
        || source.path != SECURITY_IP_RULE_COLLECTION_PATH
        || source.mutating
        || !matches!(
            source.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
    {
        return Err(CliError::Input(
            "security-action state source capability drifted from the governed complete rule-list read"
                .to_owned(),
        ));
    }
    let metadata = security_action_adapter_target(adapter_targets).ok_or_else(|| {
        CliError::Input("security-action governance receipt is missing".to_owned())
    })?;
    let query = match metadata.get("kind").and_then(Value::as_str) {
        Some("create_expiring") => json!({
            "configuration.value":metadata.pointer("/target/value").cloned().unwrap_or(Value::Null),
            "match":"all",
            "per_page":50,
        }),
        Some("remove_expired") => json!({
            "notes":metadata.get("evidence_ref").cloned().unwrap_or(Value::Null),
            "match":"all",
            "per_page":50,
        }),
        _ => {
            return Err(CliError::Input(
                "security-action governance receipt has an unsupported kind".to_owned(),
            ));
        }
    };
    let response = Executor::new(http_client()?, API_BASE_URL)?
        .execute_read(
            source,
            &CallInput {
                selectors: json!({
                    "zone_id":input.selectors.get("zone_id").cloned().unwrap_or(Value::Null),
                }),
                query,
                body: None,
                ..CallInput::default()
            },
            credential,
        )
        .await?;
    let receipt = security_action_state_receipt(
        store,
        capability,
        input,
        adapter_targets,
        account_id,
        &response,
    )?;
    let evidence = store.write_observation_evidence(EvidenceClass::LiveRead, &receipt)?;
    Ok((receipt, evidence))
}
