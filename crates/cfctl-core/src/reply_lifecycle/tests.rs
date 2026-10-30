use super::{WorkspaceD1ReplyContainmentContractV3, WorkspaceD1ReplyLifecycleContract};
use crate::WorkspaceD1ReplyAdmissionContractV1;
use serde_json::{Value, json};

fn admission_value() -> Value {
    json!({
        "operation_kind": "activate",
        "repository_root": "/fixture/app",
        "repository_head": "a".repeat(40),
        "repository_origin": "fixture",
        "operation_pack_path": ".cfctl/operations/d1-reply-admission.toml",
        "operation_pack_sha256": format!("sha256:{}", "b".repeat(64)),
        "compiler_path": "scripts/compiler.ts",
        "compiler_sha256": format!("sha256:{}", "c".repeat(64)),
        "compiler_runtime": "bun",
        "compiler_runtime_version": "1.3.14",
        "compiler_runtime_sha256": format!("sha256:{}", "d".repeat(64)),
        "config_template_path": "wrangler.toml",
        "config_template_sha256": format!("sha256:{}", "e".repeat(64)),
        "production_config_path": "wrangler.production.toml",
        "database_binding": "DB",
        "wrangler_version": "4.110.0",
        "admission_table": "reply_admissions",
        "input_contract": "maildesk_reply_admission_compiler_input_v1",
        "mutation_projection": "maildesk_reply_admission_insert_v1",
        "recovery_capability_id": "d1-time-travel-get-bookmark",
        "recovery_max_age_seconds": 600,
        "rollback_capability_id": "d1-restore-exact-bookmark"
    })
}

fn containment_value() -> Value {
    let mut value = admission_value();
    if let Some(object) = value.as_object_mut() {
        object.remove("admission_table");
        object.remove("mutation_projection");
    }
    value["contract"] = json!("maildesk_reply_containment_v3");
    value["schema_version"] = json!(3);
    value["operation_kind"] = json!("pre_read");
    value["repository_tree"] = json!("f".repeat(40));
    value["operation_pack_path"] = json!(".cfctl/operations/d1-reply-containment.toml");
    value["input_contract"] = json!("maildesk_reply_containment_v3");
    value
}

#[test]
fn admission_wire_shape_and_round_trip_remain_unchanged() -> Result<(), serde_json::Error> {
    let value = admission_value();
    let legacy: WorkspaceD1ReplyAdmissionContractV1 = serde_json::from_value(value.clone())?;
    let family: WorkspaceD1ReplyLifecycleContract = legacy.clone().into();
    assert_eq!(serde_json::to_value(&family)?, value);
    let round_trip: WorkspaceD1ReplyLifecycleContract = serde_json::from_value(value)?;
    assert_eq!(round_trip.admission(), Some(&legacy));
    assert!(round_trip.containment().is_none());
    Ok(())
}

#[test]
fn containment_is_a_disjoint_versioned_payload() -> Result<(), serde_json::Error> {
    let value = containment_value();
    let contract: WorkspaceD1ReplyContainmentContractV3 = serde_json::from_value(value.clone())?;
    let family: WorkspaceD1ReplyLifecycleContract = serde_json::from_value(value.clone())?;
    assert_eq!(family.containment(), Some(&contract));
    assert!(family.admission().is_none());
    assert_eq!(serde_json::to_value(&family)?, value);
    assert_eq!(
        contract.operation_kind.capability_id(),
        "star-maildesk-cf.reply-containment-pre-read"
    );
    Ok(())
}

#[test]
fn unknown_versions_roles_and_mixed_payloads_fail_closed() {
    for (key, invalid) in [
        ("schema_version", json!(1)),
        ("schema_version", json!(2)),
        ("contract", json!("maildesk_reply_containment_v1")),
        ("operation_kind", json!("activate")),
        ("admission_table", json!("reply_admissions")),
        (
            "mutation_projection",
            json!("maildesk_reply_admission_insert_v1"),
        ),
        (
            "caller_sql",
            json!("UPDATE reply_admissions SET status='revoked'"),
        ),
    ] {
        let mut value = containment_value();
        value[key] = invalid;
        assert!(serde_json::from_value::<WorkspaceD1ReplyLifecycleContract>(value).is_err());
    }
    let mut legacy = admission_value();
    legacy["contract"] = json!("maildesk_reply_containment_v3");
    assert!(serde_json::from_value::<WorkspaceD1ReplyLifecycleContract>(legacy).is_err());
}
