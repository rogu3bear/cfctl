#![allow(clippy::expect_used)]

use super::{oauth_scope_inventory_status, persist_catalog_sync};
use crate::{Cli, profiles::ProfilesConfig};
use cfctl_auth::{
    EvidenceKeyManager, MemorySecretStore, ProfileKind, ProfileMetadata, SecretBackend,
};
use cfctl_catalog::{CatalogSnapshot, OfficialTextFeedsV1, ingest_wrangler_pages_deploy_help};
use cfctl_storage::{RuntimePaths, StateStore};
use clap::Parser;
use serde_json::json;
use std::{collections::BTreeMap, fs, sync::Arc};

const PAGES_HELP: &str =
    "wrangler pages deploy [directory] --project-name --branch --commit-hash --commit-message";

fn discovery() -> (CatalogSnapshot, OfficialTextFeedsV1) {
    let mut catalog = CatalogSnapshot {
        schema_version: 1,
        generated_at: chrono::Utc::now(),
        source_url: "fixture://public-catalog".to_owned(),
        source_hash: "fixture".to_owned(),
        schema_hash: String::new(),
        capabilities: BTreeMap::new(),
    };
    ingest_wrangler_pages_deploy_help(&mut catalog, "4.107.0", PAGES_HELP);
    catalog.refresh_hash().expect("catalog hash");
    let feeds = OfficialTextFeedsV1 {
        fetched_at: chrono::Utc::now(),
        docs_index_url: "fixture://docs".to_owned(),
        docs_index: String::new(),
        product_indexes: BTreeMap::new(),
        unread_product_indexes: BTreeMap::new(),
        changelog_url: "fixture://changelog".to_owned(),
        changelog: String::new(),
    };
    (catalog, feeds)
}

#[test]
fn only_explicit_no_auth_sync_avoids_the_runtime_evidence_key() {
    for (argv, unqualified) in [
        (
            vec!["cfctl", "catalog", "sync", "--no-auth", "--json"],
            true,
        ),
        (vec!["cfctl", "catalog", "sync", "--json"], false),
        (vec!["cfctl", "catalog", "coverage"], false),
    ] {
        let cli = Cli::try_parse_from(argv).expect("supported command");
        assert_eq!(
            super::super::command_uses_nonqualifying_audit_evidence(
                cli.command.as_ref().expect("command")
            ),
            unqualified
        );
    }
}

#[tokio::test]
async fn no_auth_persists_discovery_without_reading_profiles_or_signing_evidence() {
    let root = tempfile::tempdir().expect("runtime");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("unqualified store");
    let profiles = store.paths().profiles_file();
    // Even metadata loading would fail. A successful discovery therefore
    // cannot have selected a profile, loaded its credential, or fetched scopes.
    fs::write(&profiles, b"not valid profile json").expect("poison metadata");
    let scopes = super::super::credential_resolution::oauth_scope_inventory_file(&store);
    store
        .write_json(&scopes, &json!({"preserve": true}))
        .expect("existing scopes");
    let scopes_before = fs::read(&scopes).expect("scope preimage");
    let (catalog, feeds) = discovery();
    store
        .write_json(&store.paths().catalog_file(), &catalog)
        .expect("previous catalog");

    let result = persist_catalog_sync(&store, &catalog, &feeds, true)
        .await
        .expect("public discovery");
    assert_eq!(result.result["oauth_scope_inventory"]["status"], "skipped");
    assert_eq!(result.result["previous_catalog"]["status"], "preserved");
    assert_eq!(
        fs::read(&profiles).expect("metadata remains"),
        b"not valid profile json"
    );
    assert_eq!(fs::read(&scopes).expect("scopes remain"), scopes_before);
    assert!(
        store
            .evidence_root_identity()
            .expect("root state")
            .is_none()
    );
    let evidence = result.evidence.first().expect("audit receipt");
    assert!(store.load_evidence(&evidence.content_hash).is_err());
    let body = store
        .read_audit_evidence_value(&evidence.content_hash)
        .expect("audit body");
    assert_eq!(body["oauth_scope_inventory"]["status"], "skipped");
    let saved = CatalogSnapshot::load(&store.paths().catalog_file()).expect("persisted catalog");
    assert_eq!(saved.schema_hash, catalog.schema_hash);
    assert_eq!(
        saved
            .get("wrangler.pages-deploy")
            .expect("discovered Pages")
            .source,
        "wrangler 4.107.0 pages deploy help"
    );
    assert!(super::catalog_index_file(&store).is_file());
}

#[test]
fn pages_discovery_still_requires_every_help_marker() {
    for marker in [
        "wrangler pages deploy [directory]",
        "--project-name",
        "--branch",
        "--commit-hash",
        "--commit-message",
    ] {
        let (mut catalog, _) = discovery();
        catalog.capabilities.clear();
        ingest_wrangler_pages_deploy_help(&mut catalog, "4.107.0", &PAGES_HELP.replace(marker, ""));
        assert!(
            catalog.get("wrangler.pages-deploy").is_none(),
            "missing {marker}"
        );
    }
}

#[tokio::test]
async fn default_sync_still_loads_profiles_and_attempts_the_selected_credential() {
    let root = tempfile::tempdir().expect("runtime");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("store");
    fs::write(store.paths().profiles_file(), b"not valid profile json").expect("poison metadata");
    let malformed = oauth_scope_inventory_status(&store, false).await;
    assert_eq!(malformed["status"], "not_refreshed");
    assert_ne!(malformed["reason"], "no active authenticated profile");

    let mut profiles = ProfilesConfig::default();
    profiles.current_profile = Some("ambient".to_owned());
    profiles.profiles.insert(
        "ambient".to_owned(),
        ProfileMetadata::new("ambient", ProfileKind::ApiToken, Some("account")),
    );
    profiles.save(&store).expect("valid selected profile");
    // A missing in-memory credential fails before any provider request.
    let missing = super::super::credential_resolution::TEST_SECRETS
        .scope(
            Arc::new(MemorySecretStore::default()),
            oauth_scope_inventory_status(&store, false),
        )
        .await;
    assert_eq!(missing["status"], "not_refreshed");
    assert!(
        missing["reason"]
            .as_str()
            .expect("credential error")
            .contains("credential")
    );
}

#[tokio::test]
async fn default_sync_retains_authenticated_evidence_and_no_profile_status() {
    let root = tempfile::tempdir().expect("runtime");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("store");
    let (catalog, feeds) = discovery();
    assert!(
        persist_catalog_sync(&store, &catalog, &feeds, false)
            .await
            .is_err()
    );
    let manager = Arc::new(
        EvidenceKeyManager::new(
            Arc::new(MemorySecretStore::default()),
            store.evidence_location_identity(),
            SecretBackend::Memory,
        )
        .expect("memory evidence manager"),
    );
    let identity = format!("sha256:{}", "a".repeat(64));
    manager.initialize(&identity).expect("test key");
    store
        .initialize_evidence_root_identity(&identity)
        .expect("test root");
    let store = store
        .with_evidence_authenticator(manager)
        .expect("authenticated store");
    let result = persist_catalog_sync(&store, &catalog, &feeds, false)
        .await
        .expect("ordinary sync");
    assert_eq!(
        result.result["oauth_scope_inventory"]["status"],
        "not_refreshed"
    );
    assert_eq!(
        result.result["oauth_scope_inventory"]["reason"],
        "no active authenticated profile"
    );
    store
        .load_evidence(
            &result
                .evidence
                .first()
                .expect("signed receipt")
                .content_hash,
        )
        .expect("default evidence authenticates");
}
