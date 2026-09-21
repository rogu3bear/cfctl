#![allow(clippy::unwrap_used)]
use super::*;

fn fixture() -> (Value, Value, Value, Value) {
    let selectors =
        json!({"zone_id":"a".repeat(32),"ruleset_id":"b".repeat(32),"rule_id":"c".repeat(32)});
    let definition = json!({"action":"managed_challenge","expression":"true","enabled":true,"description":"entry wall","ref":"wall"});
    let mut target = definition.clone();
    target["id"] = selectors["rule_id"].clone();
    target["version"] = json!("11");
    target["last_updated"] = json!("before");
    let before = json!({"id":selectors["ruleset_id"],"kind":"zone","phase":"http_request_firewall_custom","version":"14","last_updated":"before","rules":[target,{"id":"d".repeat(32),"action":"block","expression":"false","version":"3"}]});
    let body = json!({"expression":"http.host ne \"meet.example.com\"","expected_expression":"true","expected_rule_version":"11","expected_ruleset_version":"14","expected_definition":definition});
    let mut after = before.clone();
    after["version"] = json!("15");
    after["last_updated"] = json!("after");
    after["rules"][0]["version"] = json!("12");
    after["rules"][0]["last_updated"] = json!("after");
    after["rules"][0]["expression"] = body["expression"].clone();
    (selectors, body, before, after)
}

#[test]
fn wire_retains_definition_and_never_sends_local_expectations_or_order() {
    let (selectors, body, before, after) = fixture();
    validate_patch(&before, &selectors, &body).unwrap();
    verify_after(&before, &after, &selectors, &body).unwrap();
    let wire = wire_body(&body).unwrap();
    assert_eq!(wire.as_object().unwrap().len(), 5);
    assert_eq!(wire, definition(&after["rules"][0]).unwrap());
    assert!(wire.get("expected_expression").is_none());
    for key in ["position", "action", "rules", "dry_run"] {
        let mut invalid = body.clone();
        invalid[key] = json!(true);
        assert!(!valid_body(&invalid));
    }
    for key in ["action", "enabled", "description", "ref"] {
        let mut invalid = body.clone();
        invalid["expected_definition"][key] = if key == "enabled" {
            json!(false)
        } else {
            json!("js_challenge")
        };
        assert!(validate_patch(&before, &selectors, &invalid).is_err());
    }
}

#[test]
fn closed_shape_rejects_unsupported_phases_actions_selectors_and_definitions() {
    let (selectors, body, before, _) = fixture();
    for (pointer, value) in [
        ("/phase", json!("http_response_headers_transform")),
        ("/kind", json!("account")),
        ("/rules/0/action", json!("skip")),
        ("/rules/0/action_parameters", json!({})),
        ("/rules/0/position", json!({"index":1})),
        ("/rules/0/version", json!("unknown")),
    ] {
        let mut invalid = before.clone();
        let (parent, key) = pointer.rsplit_once('/').unwrap();
        invalid.pointer_mut(parent).unwrap()[key] = value;
        assert!(
            validate_patch(&invalid, &selectors, &body).is_err(),
            "{pointer}"
        );
    }
    let mut duplicate = before.clone();
    duplicate["rules"][1]["id"] = selectors["rule_id"].clone();
    assert!(target(&duplicate, &selectors).is_err());
    let mut wrong = selectors.clone();
    wrong["rule_id"] = json!("e".repeat(32));
    assert!(target(&before, &wrong).is_err());
    wrong["zone_id"] = json!("not-a-zone");
    assert!(target(&before, &wrong).is_err());
}

#[test]
fn expression_and_version_expectations_fail_closed() {
    let (selectors, body, before, _) = fixture();
    for key in [
        "expected_expression",
        "expected_rule_version",
        "expected_ruleset_version",
    ] {
        let mut invalid = body.clone();
        invalid[key] = json!("12");
        assert!(validate_patch(&before, &selectors, &invalid).is_err());
    }
    for value in [
        json!(""),
        json!("true\n"),
        json!("x".repeat(4097)),
        json!(false),
    ] {
        let mut invalid = body.clone();
        invalid["expression"] = value;
        assert!(wire_body(&invalid).is_err());
    }
    let mut noop = body;
    noop["expression"] = noop["expected_expression"].clone();
    assert!(!valid_body(&noop));
}

#[test]
fn verification_rejects_every_unrelated_change_and_nonadvancing_versions() {
    let (selectors, body, before, after) = fixture();
    for (pointer, value) in [
        ("/rules/0/action", json!("js_challenge")),
        ("/rules/0/enabled", json!(false)),
        ("/rules/0/description", json!("lost")),
        ("/rules/0/ref", json!("changed")),
        ("/rules/0/version", json!("11")),
        ("/rules/1/action", json!("skip")),
        ("/rules/1/version", json!("4")),
        ("/version", json!("14")),
    ] {
        let mut invalid = after.clone();
        *invalid.pointer_mut(pointer).unwrap() = value;
        assert!(
            verify_after(&before, &invalid, &selectors, &body).is_err(),
            "{pointer}"
        );
    }
    let mut reordered = after;
    reordered["rules"].as_array_mut().unwrap().reverse();
    assert!(verify_after(&before, &reordered, &selectors, &body).is_err());
}

#[test]
fn recovery_preserves_other_rules_and_rejects_later_target_edits() {
    let (selectors, body, before, applied) = fixture();
    let mut observed = applied.clone();
    observed["rules"][1]["expression"] = json!("true");
    observed["version"] = json!("16");
    assert!(verify_after(&before, &observed, &selectors, &body).is_err());
    let restore = recovery_body(&before, &applied, &observed, &selectors, &body).unwrap();
    validate_patch(&observed, &selectors, &restore).unwrap();
    assert_eq!(wire_body(&restore).unwrap(), body["expected_definition"]);
    for pointer in ["/rules/0/version", "/version"] {
        let mut later = observed.clone();
        *later.pointer_mut(pointer).unwrap() = json!("17");
        assert!(validate_patch(&later, &selectors, &restore).is_err());
    }
    observed["rules"][0]["version"] = json!("13");
    assert!(recovery_body(&before, &applied, &observed, &selectors, &body).is_err());
    assert!(recovery_body(&before, &before, &applied, &selectors, &body).is_err());
}
