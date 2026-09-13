#![allow(clippy::expect_used)]

use cfctl_catalog::normalize_openapi;
use cfctl_core::AdapterStatus;
use serde_json::{Value, json};

fn official_schema() -> Value {
    serde_json::from_str(include_str!("fixtures/access-human-policy-openapi.json"))
        .expect("official Access schema fixture")
}

fn assert_status(document: &Value, expected: AdapterStatus) {
    let catalog = normalize_openapi(document).expect("normalize official Access pair");
    let capability = catalog
        .get("access-policies-update-human-access-controls")
        .expect("human policy capability");
    assert_eq!(
        capability.adapter_status, expected,
        "{:?}",
        capability.blocked_reason
    );
}

#[test]
fn official_access_human_policy_schema_retains_governed_update() {
    // Exact GET/PUT operations and their transitive references from Cloudflare's
    // official api-schemas/main/openapi.json, retrieved 2026-09-13.
    let document = official_schema();
    let catalog = normalize_openapi(&document).expect("normalize official Access pair");
    let capability = catalog
        .get("access-policies-update-human-access-controls")
        .expect("human policy capability");
    assert_eq!(
        capability.adapter_status,
        AdapterStatus::DynamicApi,
        "{:?}",
        capability.blocked_reason
    );
    assert!(capability.mutation_contract_gaps().is_empty());
    assert_eq!(
        capability
            .same_path_read
            .as_ref()
            .expect("exact readback")
            .read_capability_id,
        "access-policies-get-an-access-policy"
    );
    assert_eq!(
        capability.rollback.strategy.as_deref(),
        Some("restore_same_path_prior_snapshot")
    );
}

#[test]
fn official_access_source_depth_remains_bounded() {
    for (wrappers, expected) in [
        (15, AdapterStatus::DynamicApi),
        (16, AdapterStatus::Blocked),
    ] {
        let mut document = official_schema();
        let mut scalar = document["components"]["schemas"]["access_email_rule"]
            ["properties"]["email"]["properties"]["email"].clone();
        for index in 0..wrappers {
            let name = format!("email_depth_{index}");
            document["components"]["schemas"][&name] = scalar;
            scalar = json!({"$ref": format!("#/components/schemas/{name}")});
        }
        document["components"]["schemas"]["access_email_rule"]["properties"]["email"]["properties"]
            ["email"] = scalar;
        assert_status(&document, expected);
    }
}

#[test]
fn official_access_source_cycles_constraints_and_ambiguous_unions_fail_closed() {
    let mut cycle = official_schema();
    cycle["components"]["schemas"]["access_email_rule"]["properties"]["email"]["properties"]["email"] =
        json!({"$ref":"#/components/schemas/access_email_rule"});
    assert_status(&cycle, AdapterStatus::Blocked);

    let mut incompatible = official_schema();
    incompatible["components"]["schemas"]["access_email_rule"]["properties"]["email"]["properties"]
        ["email"]["type"] = json!("integer");
    assert_status(&incompatible, AdapterStatus::Blocked);

    let mut ambiguous = official_schema();
    ambiguous["components"]["schemas"]["access_access_group_rule"]
        .as_object_mut()
        .expect("group rule")
        .remove("required");
    assert_status(&ambiguous, AdapterStatus::Blocked);
}
