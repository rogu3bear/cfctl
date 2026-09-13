//! Select the persisted subset used by the existing ruleset lifecycles.

use super::CatalogSnapshot;

pub(super) fn restrict_dry_run(snapshot: &mut CatalogSnapshot) {
    for (id, method, path) in [
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
    ] {
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
