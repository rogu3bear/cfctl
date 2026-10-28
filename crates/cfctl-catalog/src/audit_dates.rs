//! Correct the provider's date annotation for its documented audit-v2 union.

use cfctl_core::CapabilityV1;
use serde_json::json;
use std::collections::BTreeMap;

const OPERATIONS: [(&str, &str); 4] = [
    (
        "audit-logs-v2-get-account-audit-logs",
        "/accounts/{account_id}/logs/audit",
    ),
    (
        "audit-logs-v2-get-account-audit-log-history",
        "/accounts/{account_id}/logs/audit/{id}/history",
    ),
    (
        "audit-logs-v2-get-organization-audit-logs",
        "/organizations/{organization_id}/logs/audit",
    ),
    (
        "audit-logs-v2-get-organization-audit-log-history",
        "/organizations/{organization_id}/logs/audit/{id}/history",
    ),
];

const SINCE: &str = "Limits the returned results to logs newer than the specified date. This can be a date string 2019-04-30 (interpreted in UTC) or an absolute timestamp that conforms to RFC3339.";
const BEFORE: &str = "Limits the returned results to logs older than the specified date. This can be a date string 2019-04-30 (interpreted in UTC) or an absolute timestamp that conforms to RFC3339.";

pub(super) fn finalize(capabilities: &mut BTreeMap<String, CapabilityV1>) {
    for (id, path) in OPERATIONS {
        let Some(capability) = capabilities.get_mut(id) else {
            continue;
        };
        if capability.id != id
            || capability.method != "GET"
            || capability.path != path
            || capability.mutating
        {
            continue;
        }
        for selector in &mut capability.selectors {
            let description = match selector.name.as_str() {
                "since" => SINCE,
                "before" => BEFORE,
                _ => continue,
            };
            if selector.location != "query"
                || selector.value_type != "string"
                || !selector.description.as_deref().is_some_and(|actual| {
                    actual.split_whitespace().eq(description.split_whitespace())
                })
            {
                continue;
            }
            let Some(contract) = selector.contract.as_mut() else {
                continue;
            };
            if contract.schema != json!({"type":"string","format":"date"}) {
                continue;
            }
            contract.schema = json!({"oneOf":[
                {"type":"string","format":"date"},
                {"type":"string","format":"date-time"}
            ]});
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use cfctl_core::{QuerySerializationV1, SelectorContractV1, SelectorV1};

    fn capability(id: &str, path: &str) -> CapabilityV1 {
        let mut capability = CapabilityV1::new(id, "Audit logs", "GET", path);
        capability.permissions = vec![
            "Account Settings Read".into(),
            "Account Settings Write".into(),
        ];
        capability.selectors = [("since", SINCE), ("before", BEFORE)]
            .into_iter()
            .map(|(name, description)| SelectorV1 {
                name: name.into(),
                location: "query".into(),
                required: true,
                value_type: "string".into(),
                description: Some(description.into()),
                contract: Some(SelectorContractV1 {
                    schema: json!({"type":"string","format":"date"}),
                    query: Some(QuerySerializationV1 {
                        style: "form".into(),
                        explode: true,
                        allow_reserved: false,
                        allow_empty_value: false,
                    }),
                }),
            })
            .collect();
        capability
    }

    #[test]
    fn audit_dates_changes_only_eight_schemas_and_is_idempotent() {
        let mut capabilities = BTreeMap::new();
        for (id, path) in OPERATIONS {
            capabilities.insert(id.into(), capability(id, path));
        }
        let mut expected = capabilities.clone();
        for capability in expected.values_mut() {
            for selector in &mut capability.selectors {
                selector.contract.as_mut().expect("contract").schema = json!({"oneOf":[
                    {"type":"string","format":"date"}, {"type":"string","format":"date-time"}
                ]});
            }
        }
        finalize(&mut capabilities);
        assert_eq!(
            serde_json::to_value(&capabilities).expect("actual"),
            serde_json::to_value(&expected).expect("expected")
        );
        let once = serde_json::to_value(&capabilities).expect("once");
        finalize(&mut capabilities);
        assert_eq!(serde_json::to_value(&capabilities).expect("twice"), once);
    }

    #[test]
    fn audit_dates_preserves_unreviewed_operation_or_selector_drift() {
        let mutations: [fn(&mut CapabilityV1); 11] = [
            |cap| cap.id = "different-id".into(),
            |cap| cap.path = OPERATIONS[1].1.into(),
            |cap| cap.method = "POST".into(),
            |cap| cap.mutating = true,
            |cap| cap.selectors.clear(),
            |cap| {
                cap.selectors
                    .iter_mut()
                    .for_each(|s| s.location = "header".into());
            },
            |cap| {
                cap.selectors
                    .iter_mut()
                    .for_each(|s| s.value_type = "integer".into());
            },
            |cap| {
                cap.selectors.iter_mut().for_each(|s| {
                    s.description = Some("Only a date, never RFC3339 timestamps".into());
                });
            },
            |cap| cap.selectors.iter_mut().for_each(|s| s.contract = None),
            |cap| {
                cap.selectors.iter_mut().for_each(|s| {
                    s.contract.as_mut().expect("contract").schema["maxLength"] = json!(10);
                });
            },
            |cap| {
                cap.selectors.iter_mut().for_each(|s| {
                    s.contract.as_mut().expect("contract").schema =
                        json!({"type":"string","format":"date-time"});
                });
            },
        ];
        for mutate in mutations {
            let (id, path) = OPERATIONS[0];
            let mut capability = capability(id, path);
            mutate(&mut capability);
            let mut capabilities = BTreeMap::from([(id.into(), capability)]);
            let before = serde_json::to_value(&capabilities).expect("before");
            finalize(&mut capabilities);
            assert_eq!(serde_json::to_value(&capabilities).expect("after"), before);
        }
        let (id, path) = OPERATIONS[0];
        let mut unrelated = BTreeMap::from([(
            "unrelated-audit-read".into(),
            capability("unrelated-audit-read", path),
        )]);
        let before = serde_json::to_value(&unrelated).expect("before");
        finalize(&mut unrelated);
        assert_eq!(serde_json::to_value(&unrelated).expect("after"), before);
        assert!(!unrelated.contains_key(id));
    }

    #[test]
    fn audit_dates_accepts_only_harmless_description_whitespace_changes() {
        let (id, path) = OPERATIONS[0];
        let mut cap = capability(id, path);
        for selector in &mut cap.selectors {
            selector.description = selector
                .description
                .as_ref()
                .map(|value| value.replace(' ', "\n "));
        }
        let descriptions: Vec<_> = cap
            .selectors
            .iter()
            .map(|s| s.description.clone())
            .collect();
        let mut capabilities = BTreeMap::from([(id.into(), cap)]);
        finalize(&mut capabilities);
        let cap = &capabilities[id];
        for (selector, description) in cap.selectors.iter().zip(descriptions) {
            assert!(
                selector
                    .contract
                    .as_ref()
                    .expect("contract")
                    .schema
                    .get("oneOf")
                    .is_some()
            );
            assert_eq!(selector.description, description);
        }
    }
}
