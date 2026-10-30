use cfctl_core::{
    ReplyContainmentOperationV3, ReplyContainmentSchemaV3,
    WorkspaceD1ReplyContainmentContractV3 as Contract,
};
use serde_json::Value;

pub(super) fn contract() -> Contract {
    Contract {
        contract: ReplyContainmentSchemaV3::V3,
        schema_version: 3,
        operation_kind: ReplyContainmentOperationV3::Apply,
        repository_root: "/fixture".into(),
        repository_head: "a".repeat(40),
        repository_tree: "b".repeat(40),
        repository_origin: "fixture".into(),
        operation_pack_path: ".cfctl/operations/d1-reply-containment.toml".into(),
        operation_pack_sha256: format!("sha256:{}", "a".repeat(64)),
        compiler_path: "scripts/compile-reply-containment.ts".into(),
        compiler_sha256: format!("sha256:{}", "b".repeat(64)),
        compiler_runtime: "bun".into(),
        compiler_runtime_version: "1.3.14".into(),
        compiler_runtime_sha256: format!("sha256:{}", "c".repeat(64)),
        config_template_path: "wrangler.toml".into(),
        config_template_sha256: format!("sha256:{}", "d".repeat(64)),
        production_config_path: "wrangler.production.toml".into(),
        database_binding: "DB".into(),
        wrangler_version: "4.110.0".into(),
        input_contract: "maildesk_reply_containment_v3".into(),
        recovery_capability_id: "d1-time-travel-get-bookmark".into(),
        recovery_max_age_seconds: 600,
        rollback_capability_id: "d1-restore-exact-bookmark".into(),
    }
}
pub(super) fn fixture() -> Result<Value, serde_json::Error> {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../cfctl-core/src/reply_lifecycle/containment/tests/fixtures/pre_send_rollback.json"
    )))
}
