#![allow(clippy::expect_used)]
use cfctl_catalog::{CatalogSnapshot, ingest_wrangler_pages_deploy_help};
use std::collections::BTreeMap;

#[test]
fn qualified_pages_help_declares_closed_production_default_preview_intent() {
    let mut catalog = CatalogSnapshot {
        schema_version: 1,
        generated_at: chrono::Utc::now(),
        source_url: "fixture://pages".to_owned(),
        source_hash: "source".to_owned(),
        schema_hash: "schema".to_owned(),
        capabilities: BTreeMap::new(),
    };
    ingest_wrangler_pages_deploy_help(
        &mut catalog,
        "4.107.0",
        "wrangler pages deploy [directory] --project-name --branch --commit-hash --commit-message",
    );
    let capability = catalog.get("wrangler.pages-deploy").expect("exact command");
    let selector = capability
        .selectors
        .iter()
        .find(|s| s.name == "environment")
        .expect("intent selector");
    assert!(!selector.required);
    assert_eq!(selector.location, "query");
    assert_eq!(
        selector.contract.as_ref().expect("closed contract").schema,
        serde_json::json!({"type":"string","enum":["production","preview"],"default":"production"})
    );
    assert_eq!(
        capability.verification.strategy,
        "wrangler_pages_new_deployment_succeeds_by_returned_id"
    );
    assert!(capability.created_resource.is_some());
}
