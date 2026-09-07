#![allow(clippy::expect_used, clippy::unwrap_used)]

use serde_json::json;

#[test]
fn email_routing_projection_preserves_only_a_bounded_rule_identifier() {
    let valid = json!([{
        "tag": "rule_001",
        "enabled": true,
        "matchers": [{"type": "literal", "field": "to", "value": "security@example.com"}],
        "actions": [{"type": "worker", "value": ["maildesk-router"]}]
    }]);
    let projection = cfctl_core::normalize_email_routing_rule_set(&valid, 1)
        .expect("bounded provider identity should remain actionable");
    assert_eq!(projection.rules[0].rule_identifier, "rule_001");
    let serialized = serde_json::to_string(&projection).expect("serialize projection");
    assert!(!serialized.contains("security@example.com"));

    let both_fields = json!([{
        "id": "new-account-style-id",
        "tag": "legacy-zone-tag",
        "enabled": true,
        "matchers": [{"type": "all"}],
        "actions": [{"type": "worker", "value": ["maildesk-router"]}]
    }]);
    let projection = cfctl_core::normalize_email_routing_rule_set(&both_fields, 1)
        .expect("zone projection must retain its legacy tag identity");
    assert_eq!(projection.rules[0].rule_identifier, "legacy-zone-tag");

    let mut malformed_id = both_fields;
    malformed_id[0]["id"] = json!("malformed account id");
    let projection = cfctl_core::normalize_email_routing_rule_set(&malformed_id, 1)
        .expect("zone projection must ignore malformed account-only id when tag is valid");
    assert_eq!(projection.rules[0].rule_identifier, "legacy-zone-tag");

    for tag in [
        json!(null),
        json!(""),
        json!("bad identifier"),
        json!("x".repeat(33)),
    ] {
        let mut rejected = valid.clone();
        rejected[0]["tag"] = tag;
        let diagnostic = cfctl_core::normalize_email_routing_rule_set(&rejected, 1)
            .expect_err("missing or unbounded provider identity must fail closed");
        assert_eq!(diagnostic.code, "rule_identifier_invalid");
        assert_eq!(diagnostic.component, "rule.tag");
    }
}

#[test]
fn email_routing_projection_accepts_only_value_free_drop_actions() {
    let canonical_default = json!([{
        "tag": "rule_001",
        "enabled": true,
        "matchers": [{"type": "all"}],
        "actions": [{"type": "drop"}]
    }]);
    let projection = cfctl_core::normalize_email_routing_rule_set(&canonical_default, 1)
        .expect("provider default drop action may omit value");
    assert_eq!(projection.rules[0].actions[0].action_type, "drop");
    assert_eq!(projection.rules[0].actions[0].value_count, 0);

    let mut explicit_empty = canonical_default.clone();
    explicit_empty[0]["actions"][0]["value"] = json!([]);
    let projection = cfctl_core::normalize_email_routing_rule_set(&explicit_empty, 1)
        .expect("drop action may explicitly carry an empty value array");
    assert_eq!(projection.rules[0].actions[0].value_count, 0);

    for invalid_value in [
        json!(null),
        json!(true),
        json!({}),
        json!("operator@example.com"),
        json!(["operator@example.com"]),
    ] {
        let mut rejected = canonical_default.clone();
        rejected[0]["actions"][0]["value"] = invalid_value;
        let diagnostic = cfctl_core::normalize_email_routing_rule_set(&rejected, 1)
            .expect_err("drop action must not carry a target");
        assert_eq!(diagnostic.code, "action_values_invalid");
        assert_eq!(diagnostic.component, "action.value");
    }
}

#[test]
fn account_email_routing_projection_hashes_exact_rule_domain_without_retaining_plaintext() {
    let rules = json!([{
        "id": "rule_001",
        "enabled": true,
        "zone": {"name": "reply.example.com", "tag": "parent-zone-tag"},
        "matchers": [{"type": "all"}],
        "actions": [{"type": "worker", "value": ["maildesk-router"]}],
        "priority": 0
    }]);
    let projection = cfctl_core::normalize_email_routing_account_rule_set(&rules, 2)
        .expect("complete account inventory should retain only body-free domain identity");
    assert_eq!(projection.pages, 2);
    assert_eq!(
        projection.rules[0].zone_name_sha256.as_deref(),
        Some("sha256:ee551193ff63e4819a1f4333a425488c2980fe91b67f1d6b3d66faaa24f4e708")
    );
    assert!(projection.rules[0].zone_tag_sha256.is_some());
    assert_eq!(projection.rules[0].matchers[0].matcher_type, "all");
    assert_eq!(
        projection.rules[0].actions[0].worker_targets,
        ["maildesk-router"]
    );
    let serialized = serde_json::to_string(&projection).expect("serialize projection");
    assert!(!serialized.contains("reply.example.com"));
    assert!(!serialized.contains("parent-zone-tag"));

    let mut fallback = rules;
    fallback[0]["id"] = json!("malformed account id");
    fallback[0]["tag"] = json!("bounded-tag-fallback");
    let projection = cfctl_core::normalize_email_routing_account_rule_set(&fallback, 1)
        .expect("account projection may fall back from malformed id to bounded tag");
    assert_eq!(projection.rules[0].rule_identifier, "bounded-tag-fallback");
}
