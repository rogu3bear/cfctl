#![allow(clippy::wildcard_imports, reason = "white-box domain tests")]

use super::super::RuntimePaths;

use super::*;

fn projection_contract() -> cfctl_core::WorkspaceD1PolicyProjectionContractV1 {
    cfctl_core::WorkspaceD1PolicyProjectionContractV1 {
        repository_root: "/repo".to_owned(),
        repository_head: "a".repeat(40),
        repository_origin: "https://example.com/repo.git".to_owned(),
        operation_pack_path: ".cfctl/operations/d1-projection.toml".to_owned(),
        operation_pack_sha256: format!("sha256:{}", "a".repeat(64)),
        config_template_path: "wrangler.toml".to_owned(),
        config_template_sha256: format!("sha256:{}", "b".repeat(64)),
        production_config_path: "wrangler.production.toml".to_owned(),
        database_binding: "DB".to_owned(),
        wrangler_version: "4.120.1".to_owned(),
        route_table: "alias_routes".to_owned(),
        route_policy_sha_column: "policy_sha256".to_owned(),
        runtime_state_table: "runtime_state".to_owned(),
        runtime_state_key_column: "state_key".to_owned(),
        runtime_state_value_column: "state_value".to_owned(),
        active_policy_key: "active_policy_sha256".to_owned(),
        desired_state_digest_key: "desired_state_sha256".to_owned(),
        projection_digest_key: "projection_sha256".to_owned(),
        recovery_capability_id: "d1-time-travel-get-bookmark".to_owned(),
        recovery_max_age_seconds: 600,
        rollback_capability_id: "d1-restore-exact-bookmark".to_owned(),
    }
}

#[test]
fn expected_projection_accepts_only_bounded_hashes_and_counts() {
    let input: CallInput = serde_json::from_value(json!({
        "selectors": {},
        "query": {
            "policy_sha256": format!("sha256:{}", "a".repeat(64)),
            "desired_state_sha256": format!("sha256:{}", "b".repeat(64)),
            "projection_sha256": format!("sha256:{}", "c".repeat(64)),
            "expected_route_count": "141"
        }
    }))
    .expect("input");
    let expected = expected_projection(&input).expect("projection");
    assert_eq!(expected.route_count, 141);
}

#[test]
fn d1_verification_uses_raw_digest_values_and_rejects_state_drift() {
    let contract = projection_contract();
    let policy = format!("sha256:{}", "a".repeat(64));
    let desired = format!("sha256:{}", "b".repeat(64));
    let projection = format!("sha256:{}", "c".repeat(64));

    let sql = route_count_sql(&contract, &policy).expect("count SQL");
    assert!(sql.contains(&format!("= '{}'", "a".repeat(64))));
    assert!(!sql.contains("sha256:"));

    let observed = BTreeMap::from([
        (contract.active_policy_key.clone(), "a".repeat(64)),
        (contract.desired_state_digest_key.clone(), "b".repeat(64)),
        (contract.projection_digest_key.clone(), "c".repeat(64)),
    ]);
    assert!(
        digest_readbacks_match(&contract, &observed, &policy, &desired, &projection)
            .expect("matching raw digests")
    );

    let mut drifted = observed;
    drifted.insert(contract.projection_digest_key.clone(), "d".repeat(64));
    assert!(
        !digest_readbacks_match(&contract, &drifted, &policy, &desired, &projection)
            .expect("drift decision")
    );
}

#[cfg(unix)]
#[test]
fn private_projection_stage_is_mode_0600_and_body_free() {
    let root = tempfile::tempdir_in("/private/tmp").expect("root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("store");
    let source = root.path().join("projection.sql");
    fs::write(&source, "BEGIN; INSERT INTO routes VALUES (1); COMMIT;\n").expect("source");
    fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).expect("mode");
    let staged = stage_private_projection(&store, &source).expect("stage");
    assert_eq!(staged["content_in_plan"], false);
    assert_eq!(staged["path_in_plan"], false);
    assert!(staged.get("path").is_none());
    assert!(!staged.to_string().contains("INSERT INTO"));
    assert!(
        !staged
            .to_string()
            .contains(root.path().to_str().expect("root"))
    );
    let metadata = fs::metadata(
        private_stage_path(&store, staged.as_object().expect("stage object")).expect("path"),
    )
    .expect("metadata");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
}

#[cfg(unix)]
#[test]
fn private_projection_rejects_a_symlinked_source_component() {
    let root = tempfile::tempdir_in("/private/tmp").expect("root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("store");
    let private_dir = root.path().join("private");
    fs::create_dir(&private_dir).expect("private directory");
    let source = private_dir.join("projection.sql");
    fs::write(&source, "BEGIN; COMMIT;\n").expect("source");
    fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).expect("mode");
    let linked_dir = root.path().join("linked-private");
    std::os::unix::fs::symlink(&private_dir, &linked_dir).expect("symlink");

    let error = stage_private_projection(&store, &linked_dir.join("projection.sql"))
        .expect_err("symlinked parent must fail closed");
    assert!(error.to_string().contains("symlink component"));
}

#[test]
fn state_keys_and_identifiers_fail_closed() {
    assert!(identifier("alias_routes").is_ok());
    assert!(identifier("routes; DROP TABLE routes").is_err());
    assert!(state_key("active_policy_sha256").is_ok());
    assert!(state_key("active' OR 1=1").is_err());
}
