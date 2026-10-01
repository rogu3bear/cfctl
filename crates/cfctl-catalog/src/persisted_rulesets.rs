//! Select the persisted subset used by the existing ruleset lifecycles.

use super::{AdapterStatus, CatalogSnapshot};

const PERSISTED_OPERATIONS: [(&str, &str, &str); 4] = [
    ("createZoneRuleset", "POST", "/zones/{zone_id}/rulesets"),
    (
        "deleteZoneRuleset",
        "DELETE",
        "/zones/{zone_id}/rulesets/{ruleset_id}",
    ),
    (
        "createZoneRulesetRule",
        "POST",
        "/zones/{zone_id}/rulesets/{ruleset_id}/rules",
    ),
    (
        "deleteZoneRulesetRule",
        "DELETE",
        "/zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}",
    ),
];

pub(super) fn restrict_dry_run(snapshot: &mut CatalogSnapshot) {
    for (id, method, path) in PERSISTED_OPERATIONS {
        let Some(capability) = snapshot.capabilities.get_mut(id) else {
            continue;
        };
        if capability.method != method || capability.path != path {
            continue;
        }
        let dry_run = capability
            .selectors
            .iter()
            .filter(|selector| selector.name == "dry_run")
            .collect::<Vec<_>>();
        if dry_run.len() != 1 {
            continue;
        }
        let selector = dry_run[0];
        let reviewed = selector.location == "query"
            && !selector.required
            && selector.value_type == "boolean"
            && selector.description.as_deref()
                == Some(
                    "Validates the request without persisting changes when set to `true`. Responses that normally return 200 return `result: null`; endpoints that normally return 204 continue to return 204.",
                )
            && selector.contract.as_ref().is_some_and(|contract| {
                contract.schema == serde_json::json!({"type":"boolean"})
                    && contract.query.as_ref().is_some_and(|query| {
                        query.style == "form"
                            && query.explode
                            && !query.allow_reserved
                            && !query.allow_empty_value
                    })
            });
        if reviewed {
            // Omission selects a persisted operation. Removing the selector
            // makes caller-supplied dry_run fail query validation before I/O;
            // accepting a preview would invalidate readback and compensation.
            capability
                .selectors
                .retain(|selector| selector.name != "dry_run");
        }
    }
}

/// Runs after every ruleset lifecycle overlay. A reviewed `dry_run` selector
/// was removed above, so one that remains on a persisted operation, or on a
/// capability derived from it, means its contract drifted: omission might no
/// longer select a persisted change, so the capability stays blocked.
pub(super) fn block_unreviewed_dry_run(snapshot: &mut CatalogSnapshot) {
    for capability in snapshot.capabilities.values_mut() {
        let persisted = PERSISTED_OPERATIONS
            .iter()
            .any(|(_, method, path)| capability.method == *method && capability.path == *path);
        if persisted
            && capability
                .selectors
                .iter()
                .any(|selector| selector.name == "dry_run")
        {
            capability.adapter_status = AdapterStatus::Blocked;
            capability.blocked_reason = Some(
                "schema drift: the ruleset `dry_run` selector no longer matches the reviewed persisted-operation contract; this lifecycle stays blocked until the new contract is reviewed"
                    .to_owned(),
            );
        }
    }
}
