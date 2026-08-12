#![allow(clippy::expect_used)]

use std::collections::BTreeMap;

use cfctl_catalog::{CatalogSnapshot, ingest_native_control_capabilities};
use cfctl_core::{
    AdapterStatus, CapabilityAuthorityScopeV1, EffectClass, ResponseBodyModeV1, RiskClass,
};
use chrono::Utc;

#[test]
fn native_catalog_exposes_one_closed_reviewed_schema_migration_lane() {
    let mut snapshot = CatalogSnapshot {
        schema_version: 1,
        generated_at: Utc::now(),
        source_url: "fixture".to_owned(),
        source_hash: "fixture".to_owned(),
        schema_hash: String::new(),
        capabilities: BTreeMap::new(),
    };
    ingest_native_control_capabilities(&mut snapshot).expect("native control overlay");
    let capability = snapshot
        .get("d1-apply-reviewed-schema-migration")
        .expect("reviewed schema migration capability");
    assert_eq!(
        capability.authority_scope,
        Some(CapabilityAuthorityScopeV1::ProviderGeneric)
    );
    assert_eq!(capability.adapter_status, AdapterStatus::Native);
    assert_eq!(capability.method, "POST");
    assert_eq!(
        capability.path,
        "/accounts/{account_id}/d1/database/{database_id}/query"
    );
    assert!(capability.mutating);
    assert_eq!(capability.risk, RiskClass::Irreversible);
    assert_eq!(capability.effect, EffectClass::DataWrite);
    assert_eq!(capability.permissions, ["D1 Write"]);
    assert_eq!(
        capability.verification.strategy,
        "d1_reviewed_schema_batch_reports_every_statement_success"
    );
    assert!(capability.verification.required);
    assert_eq!(
        capability
            .response_contract
            .as_ref()
            .expect("response contract")
            .body_mode,
        ResponseBodyModeV1::CloudflareJsonEnvelope
    );
    let contract = capability
        .d1_approved_mln_import
        .as_ref()
        .expect("reviewed source contract");
    assert!(contract.repository_id.is_empty());
    assert!(contract.migrations.is_empty());
    assert_eq!(contract.max_source_bytes, 1024 * 1024);
    assert_eq!(contract.max_poll_attempts, 0);
    assert!(contract.upload_url_suffix.is_empty());
    assert!(contract.requires_create_new_mode_0600_stage);

    let request = capability
        .request_schema
        .as_ref()
        .expect("closed recovery request");
    let encoded = serde_json::to_string(request).expect("request JSON");
    assert!(!encoded.contains("\"sql\""));
    assert!(!encoded.contains("\"params\""));
    assert_eq!(request["additionalProperties"], false);
}
