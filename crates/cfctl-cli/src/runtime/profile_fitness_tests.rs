#![allow(clippy::expect_used)]

use super::check_profile_fitness;
use cfctl_auth::{ManagedApiTokenV1, ProfileKind, ProfileMetadata};
use cfctl_core::{
    AdapterStatus, CapabilityV1, ResponseBodyModeV1, ResponseContractV1, SelectorContractV1,
    SelectorV1, StandingAuthorityV1,
};
use cfctl_storage::{RuntimePaths, StateStore};
use chrono::{Duration, Utc};
use serde_json::json;

fn widget() -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        cfctl_core::turnstile_secret::ID,
        "Turnstile Widget Details",
        "GET",
        cfctl_core::turnstile_secret::PATH,
    );
    capability.permissions = [
        "Turnstile Sites Write",
        "Turnstile Sites Read",
        "Account Settings Write",
        "Account Settings Read",
    ]
    .map(str::to_owned)
    .to_vec();
    capability.product = "Turnstile".into();
    capability.account_scope = "account".into();
    capability.selectors = ["account_id", "sitekey"]
        .map(|name| SelectorV1 {
            name: name.into(),
            location: "path".into(),
            required: true,
            value_type: "string".into(),
            description: None,
            contract: Some(SelectorContractV1 {
                schema: json!({"maxLength":32,"type":"string"}),
                query: None,
            }),
        })
        .to_vec();
    capability.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".into()],
        success_media_types: vec!["application/json".into()],
        body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
    });
    assert!(cfctl_core::turnstile_secret::supported(&capability));
    capability
}

fn managed_profile(store: &StateStore, group_name: Option<&str>, active: bool) -> ProfileMetadata {
    let names = group_name.into_iter().collect::<Vec<_>>();
    managed_profile_with_permissions(store, &names, active)
}

fn managed_profile_with_permissions(
    store: &StateStore,
    names: &[&str],
    active: bool,
) -> ProfileMetadata {
    let ids = (0..names.len().max(1))
        .map(|i| format!("granted-{i}"))
        .collect();
    let mut authority = StandingAuthorityV1::draft(
        "account-a",
        None,
        vec![cfctl_core::turnstile_secret::ID.to_owned()],
        ids,
        "sha256:fixture-inventory",
        1,
        "fitness-test",
        1,
        Utc::now() + Duration::hours(1),
    )
    .expect("fixture authority");
    if active {
        authority.approve(true).expect("activate local fixture");
    }
    store.save_authority(&authority).expect("save fixture");
    let groups = json!(
        names
            .iter()
            .enumerate()
            .map(|(i, name)| { json!({"id":format!("granted-{i}"),"name":name}) })
            .collect::<Vec<_>>()
    );
    store
        .save_authority_permissions(&authority.authority_id, &groups)
        .expect("cache fixture inventory");
    let mut profile = ProfileMetadata::new("managed", ProfileKind::ApiToken, Some("account-a"));
    profile.managed_api_token = Some(ManagedApiTokenV1 {
        schema_version: 1,
        token_id: "fixture-child".to_owned(),
        expires_at: Utc::now() + Duration::minutes(30),
        standing_authority_id: authority.authority_id,
        pending_revoke_token_id: None,
        pending_revoke_operation_id: None,
        pending_revoke_slot_id: None,
    });
    profile
}

fn store(root: &tempfile::TempDir) -> StateStore {
    super::super::tests::authenticated_test_store(RuntimePaths::from_root(root.path()))
}

#[test]
fn handoff_managed_widget_read_accepts_each_provider_permission_alternative() {
    let capability = widget();
    for permission in &capability.permissions {
        let root = tempfile::tempdir().expect("root");
        let store = store(&root);
        let profile = managed_profile(&store, Some(permission), true);
        check_profile_fitness(&store, &profile, &capability, Some("account-a"))
            .expect("one documented alternative admits preflight");
    }
}

#[test]
fn handoff_managed_widget_read_rejects_a_known_unrelated_permission() {
    let root = tempfile::tempdir().expect("root");
    let store = store(&root);
    let profile = managed_profile(&store, Some("DNS Read"), true);
    let error = check_profile_fitness(&store, &profile, &widget(), Some("account-a"))
        .expect_err("no accepted alternative");
    assert_eq!(error.code(), "CFCTL_PROFILE_INSUFFICIENT_PERMISSIONS");
}

#[test]
fn handoff_managed_fitness_preserves_account_and_authority_checks() {
    for active in [true, false] {
        let root = tempfile::tempdir().expect("root");
        let store = store(&root);
        let profile = managed_profile(&store, Some("Turnstile Sites Read"), active);
        let error = check_profile_fitness(&store, &profile, &widget(), Some("account-b"))
            .expect_err("account or authority mismatch");
        assert_eq!(
            error.code(),
            if active {
                "CFCTL_PROFILE_ACCOUNT_MISMATCH"
            } else {
                "CFCTL_PROFILE_AUTHORITY_INACTIVE"
            }
        );
    }
}

#[test]
fn handoff_managed_fitness_cannot_infer_denial_from_incomplete_inventory() {
    let root = tempfile::tempdir().expect("root");
    let store = store(&root);
    let profile = managed_profile(&store, None, true);
    check_profile_fitness(&store, &profile, &widget(), Some("account-a"))
        .expect("unknown permission is not proof of missing permission");
}

#[test]
fn handoff_native_and_workspace_permissions_remain_conjunctive() {
    for native in [true, false] {
        let root = tempfile::tempdir().expect("root");
        let store = store(&root);
        let profile = managed_profile(&store, Some("Turnstile Sites Read"), true);
        let mut capability = widget();
        if native {
            capability.adapter_status = AdapterStatus::Native;
        } else {
            capability.source = "workspace-operation".to_owned();
        }
        let error = check_profile_fitness(&store, &profile, &capability, Some("account-a"))
            .expect_err("composite permissions still all required");
        assert_eq!(error.code(), "CFCTL_PROFILE_INSUFFICIENT_PERMISSIONS");
    }
}

#[test]
fn handoff_permission_cache_preserves_authority_listing() {
    let root = tempfile::tempdir().expect("root");
    let store = store(&root);
    let profile = managed_profile(&store, Some("Turnstile Sites Read"), true);
    let authority_id = &profile
        .managed_api_token
        .as_ref()
        .expect("managed")
        .standing_authority_id;
    let authorities = store
        .list_authorities()
        .expect("cache is not an authority document");
    assert_eq!(authorities.len(), 1);
    assert_eq!(&authorities[0].authority_id, authority_id);
    assert!(
        store
            .load_authority_permissions(authority_id)
            .expect("cache")
            .is_some()
    );
}

#[cfg(unix)]
#[test]
fn handoff_permission_cache_symlink_remains_rejected_by_listing() {
    let root = tempfile::tempdir().expect("root");
    let store = store(&root);
    let profile = managed_profile(&store, Some("Turnstile Sites Read"), true);
    let authority_id = &profile
        .managed_api_token
        .as_ref()
        .expect("managed")
        .standing_authority_id;
    let cache = store
        .paths()
        .data_dir
        .join("authorities")
        .join(format!("{authority_id}-permissions.json"));
    std::fs::remove_file(&cache).expect("remove fixture cache");
    let outside = root.path().join("outside.json");
    std::fs::write(&outside, "[]").expect("fixture outside");
    std::os::unix::fs::symlink(&outside, &cache).expect("fixture symlink");
    assert!(store.list_authorities().is_err());
}

fn finalized_rule_catalog() -> cfctl_catalog::CatalogSnapshot {
    use cfctl_core::response_header_rule as rule;
    let mut cap = CapabilityV1::new(rule::ID, "Update rule", "PATCH", rule::PATH);
    cap.account_scope = "zone".into();
    cap.selectors = ["zone_id", "ruleset_id", "rule_id"]
        .map(|name| SelectorV1 {
            name: name.into(),
            location: "path".into(),
            required: true,
            value_type: "string".into(),
            description: None,
            contract: None,
        })
        .to_vec();
    cap.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".into()],
        success_media_types: vec!["application/json".into()],
        body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
    });
    let read = CapabilityV1::new(rule::READ_ID, "Read ruleset", "GET", rule::READ_PATH);
    let mut catalog = cfctl_catalog::CatalogSnapshot {
        schema_version: 2,
        generated_at: Utc::now(),
        source_url: "fixture".into(),
        source_hash: String::new(),
        schema_hash: String::new(),
        capabilities: std::collections::BTreeMap::from([
            (cap.id.clone(), cap),
            (read.id.clone(), read),
        ]),
    };
    cfctl_catalog::ingest_telemetry_capabilities(&mut catalog).expect("actual finalizers");
    catalog
}

#[test]
fn handoff_finalized_dynamic_rule_composites_require_all_authored_permissions() {
    let catalog = finalized_rule_catalog();
    for id in [
        cfctl_core::response_header_rule::ID,
        cfctl_core::custom_challenge_rule::ID,
    ] {
        let cap = catalog.get(id).expect("finalized capability");
        assert_eq!(cap.adapter_status, AdapterStatus::DynamicApi);
        assert_eq!(cap.source, "cloudflare-api-schemas");
        assert_eq!(cap.permissions.len(), 2);
        for complete in [false, true] {
            let names = cap
                .permissions
                .iter()
                .take(if complete { 2 } else { 1 })
                .map(String::as_str)
                .collect::<Vec<_>>();
            let root = tempfile::tempdir().expect("root");
            let store = store(&root);
            let profile = managed_profile_with_permissions(&store, &names, true);
            let result = check_profile_fitness(&store, &profile, cap, Some("account-a"));
            if complete {
                result.expect("all authored requirements covered");
            } else {
                assert_eq!(
                    result
                        .expect_err("read-only grant must not admit write")
                        .code(),
                    "CFCTL_PROFILE_INSUFFICIENT_PERMISSIONS"
                );
            }
        }
    }
}
