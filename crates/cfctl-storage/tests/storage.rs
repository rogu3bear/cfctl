#![allow(clippy::expect_used, clippy::unwrap_used)]

use cfctl_core::{
    CapabilityV1, EvidenceClass, OperationalProofOutcomeV1, OperationalProofScopeV1,
    OperationalProofV1, PlanStatus, PlanV1, StandingAuthorityStatus, StandingAuthorityV1,
    TransactionStageV1,
};
use cfctl_storage::{RuntimePaths, StateStore, StorageError};
use chrono::{Duration, Utc};
use serde_json::json;

fn sha256(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

fn only_proof_index_path(paths: &RuntimePaths) -> std::path::PathBuf {
    let mut entries = std::fs::read_dir(paths.data_dir.join("evidence-index"))
        .expect("proof index lists")
        .map(|entry| entry.expect("proof index entry").path())
        .collect::<Vec<_>>();
    assert_eq!(entries.len(), 1, "fixture has one proof-index row");
    entries.pop().expect("one proof-index row")
}

fn draft_plan() -> PlanV1 {
    PlanV1::draft(
        "profile-a",
        "account-a",
        "sha256:catalog",
        CapabilityV1::new(
            "account-api-tokens-create-token",
            "Create account token",
            "POST",
            "/accounts/{account_id}/tokens",
        ),
        json!({"account_id":"account-a"}),
    )
    .expect("draft plan")
}

fn draft_authority() -> StandingAuthorityV1 {
    StandingAuthorityV1::draft(
        "account-a",
        None,
        vec!["account-api-tokens-create-token".to_owned()],
        vec!["permission-a".to_owned()],
        "sha256:permission-inventory",
        24,
        "agent-",
        1,
        Utc::now() + Duration::hours(24),
    )
    .expect("draft authority")
}

#[test]
fn evidence_is_redacted_content_addressed_and_deduplicated() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let paths = RuntimePaths::from_root(root.path());
    let store = StateStore::open(paths).expect("storage opens");

    let first = store
        .write_evidence(
            EvidenceClass::LiveRead,
            &json!({"result": {"id": "zone-1"}, "access_token": "must-not-survive"}),
        )
        .expect("evidence writes");
    let second = store
        .write_evidence(
            EvidenceClass::LiveRead,
            &json!({"result": {"id": "zone-1"}, "access_token": "another-value"}),
        )
        .expect("same redacted evidence deduplicates");

    assert_eq!(first.content_hash, second.content_hash);
    assert_eq!(first.path, second.path);
    let stored = std::fs::read_to_string(&first.path).expect("stored evidence");
    assert!(!stored.contains("must-not-survive"));
    assert!(!stored.contains("another-value"));
    assert!(stored.contains("[REDACTED]"));
}

#[test]
fn operational_proof_index_is_append_only_scoped_and_live_read_only() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("storage opens");
    let evidence = store
        .write_evidence(
            EvidenceClass::LiveRead,
            &json!({"result": {"id": "zone-1"}}),
        )
        .expect("live evidence writes");
    let proof = OperationalProofV1::new(
        Utc::now(),
        "zones-list",
        &sha256('a'),
        &sha256('b'),
        OperationalProofScopeV1::new(Some("default"), Some("account-a")),
        OperationalProofOutcomeV1::Succeeded,
        evidence,
    );

    store
        .record_operational_proof(&proof)
        .expect("proof indexes");
    store
        .record_operational_proof(&proof)
        .expect("same proof is idempotent");
    let indexed = store.list_operational_proofs().expect("proofs list");
    assert_eq!(indexed, vec![proof.clone()]);

    let mut forged = proof;
    forged.evidence.path = "/tmp/not-this-store.json".to_owned();
    assert!(matches!(
        store.record_operational_proof(&forged),
        Err(StorageError::InvalidOperationalProof(_))
    ));

    let local_evidence = store
        .write_evidence(EvidenceClass::LocalProof, &json!({"ok": true}))
        .expect("local evidence writes");
    let invalid = OperationalProofV1::new(
        Utc::now(),
        "zones-list",
        &sha256('a'),
        &sha256('b'),
        OperationalProofScopeV1::new(None, None),
        OperationalProofOutcomeV1::Succeeded,
        local_evidence,
    );
    assert!(matches!(
        store.record_operational_proof(&invalid),
        Err(StorageError::InvalidOperationalProof(_))
    ));
}

#[test]
fn operational_proof_index_rejects_tampered_stored_bytes() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let paths = RuntimePaths::from_root(root.path());
    let store = StateStore::open(paths.clone()).expect("storage opens");
    let evidence = store
        .write_evidence(EvidenceClass::LiveRead, &json!({"bounded": true}))
        .expect("evidence writes");
    let proof = OperationalProofV1::new(
        Utc::now(),
        "zones-list",
        &sha256('a'),
        &sha256('b'),
        OperationalProofScopeV1::new(Some("profile-a"), Some("account-a")),
        OperationalProofOutcomeV1::Succeeded,
        evidence,
    );
    store
        .record_operational_proof(&proof)
        .expect("proof indexes");
    let index_path = only_proof_index_path(&paths);
    let mut tampered = serde_json::to_value(&proof).expect("proof encodes");
    tampered["account_id"] = json!("account-b");
    std::fs::write(
        &index_path,
        serde_json::to_vec_pretty(&tampered).expect("tampered proof encodes"),
    )
    .expect("tampered proof writes");

    assert!(matches!(
        store.list_operational_proofs(),
        Err(StorageError::InvalidOperationalProof(message))
            if message.contains("filename does not match")
    ));
    assert!(matches!(
        store.record_operational_proof(&proof),
        Err(StorageError::InvalidOperationalProof(message))
            if message.contains("filename does not match")
    ));
}

#[test]
fn operational_proof_requires_exact_hashes_and_nonempty_scope() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("storage opens");
    let evidence = store
        .write_evidence(EvidenceClass::LiveRead, &json!({"bounded": true}))
        .expect("evidence writes");
    let invalid_hash = OperationalProofV1::new(
        Utc::now(),
        "zones-list",
        "sha256:catalog",
        &sha256('b'),
        OperationalProofScopeV1::new(Some("profile-a"), Some("account-a")),
        OperationalProofOutcomeV1::Succeeded,
        evidence.clone(),
    );
    assert!(matches!(
        store.record_operational_proof(&invalid_hash),
        Err(StorageError::InvalidOperationalProof(_))
    ));
    let empty_scope = OperationalProofV1::new(
        Utc::now(),
        "zones-list",
        &sha256('a'),
        &sha256('b'),
        OperationalProofScopeV1::new(Some("  "), Some("account-a")),
        OperationalProofOutcomeV1::Succeeded,
        evidence,
    );
    assert!(matches!(
        store.record_operational_proof(&empty_scope),
        Err(StorageError::InvalidOperationalProof(_))
    ));
}

#[test]
fn operational_proof_join_rejects_missing_or_modified_evidence() {
    for replacement in [None, Some(br#"{"different":true}"#.as_slice())] {
        let root = tempfile::tempdir().expect("temporary storage root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("storage opens");
        let evidence = store
            .write_evidence(EvidenceClass::LiveRead, &json!({"bounded": true}))
            .expect("evidence writes");
        let evidence_path = std::path::PathBuf::from(&evidence.path);
        let proof = OperationalProofV1::new(
            Utc::now(),
            "zones-list",
            &sha256('a'),
            &sha256('b'),
            OperationalProofScopeV1::new(Some("profile-a"), Some("account-a")),
            OperationalProofOutcomeV1::Succeeded,
            evidence,
        );
        store
            .record_operational_proof(&proof)
            .expect("proof indexes");
        if let Some(bytes) = replacement {
            std::fs::write(&evidence_path, bytes).expect("evidence replacement writes");
        } else {
            std::fs::remove_file(&evidence_path).expect("evidence removes");
        }
        assert!(store.list_operational_proofs().is_err());
    }
}

#[cfg(unix)]
#[test]
fn operational_proof_join_rejects_symlinked_evidence() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().expect("temporary storage root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("storage opens");
    let evidence = store
        .write_evidence(EvidenceClass::LiveRead, &json!({"bounded": true}))
        .expect("evidence writes");
    let evidence_path = std::path::PathBuf::from(&evidence.path);
    let proof = OperationalProofV1::new(
        Utc::now(),
        "zones-list",
        &sha256('a'),
        &sha256('b'),
        OperationalProofScopeV1::new(Some("profile-a"), Some("account-a")),
        OperationalProofOutcomeV1::Succeeded,
        evidence,
    );
    store
        .record_operational_proof(&proof)
        .expect("proof indexes");
    let target = root.path().join("alternate-evidence.json");
    std::fs::write(&target, b"{}").expect("symlink target writes");
    std::fs::remove_file(&evidence_path).expect("evidence removes");
    symlink(&target, &evidence_path).expect("evidence symlink creates");

    assert!(matches!(
        store.list_operational_proofs(),
        Err(StorageError::UnsafeManagedDocument { .. })
    ));
}

#[test]
fn recent_operational_proof_projection_is_bounded_and_reports_truncation() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("storage opens");
    let evidence = store
        .write_evidence(EvidenceClass::LiveRead, &json!({"bounded": true}))
        .expect("evidence writes");
    for (offset, input_byte) in [(3, 'b'), (2, 'c'), (1, 'd')] {
        store
            .record_operational_proof(&OperationalProofV1::new(
                Utc::now() - Duration::seconds(offset),
                "zones-list",
                &sha256('a'),
                &sha256(input_byte),
                OperationalProofScopeV1::new(Some("profile-a"), Some("account-a")),
                OperationalProofOutcomeV1::Succeeded,
                evidence.clone(),
            ))
            .expect("proof indexes");
    }

    let page = store
        .list_recent_operational_proofs(2)
        .expect("recent proof projection loads");
    assert_eq!(page.proofs.len(), 2);
    assert_eq!(page.total_count, 3);
    assert!(page.truncated);
    let empty = store
        .list_recent_operational_proofs(0)
        .expect("zero-sized projection reports history");
    assert!(empty.proofs.is_empty());
    assert_eq!(empty.total_count, 3);
    assert!(empty.truncated);
}

#[test]
fn plans_are_atomic_and_raw_secret_material_is_rejected() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("storage opens");
    let capability = CapabilityV1::new(
        "workers.secret.rotate",
        "Rotate secret",
        "PUT",
        "/accounts/{account_id}/workers/secrets/{name}",
    );
    let mut plan = PlanV1::draft(
        "default",
        "account-1",
        "sha256:catalog",
        capability,
        json!({"account_id": "account-1", "name": "API_KEY"}),
    )
    .expect("draft plan");
    plan.input = json!({"secret": "plaintext-secret"});
    plan.refresh_hash().expect("refresh plan hash");

    let error = store.save_plan(&plan).expect_err("secret plan must fail");
    assert!(matches!(error, StorageError::SensitiveData));

    plan.input = json!({"secret_ref": "keychain:plan/account-1/API_KEY"});
    plan.refresh_hash().expect("refresh safe plan hash");
    store.save_plan(&plan).expect("safe plan stores");
    let loaded = store.load_plan(&plan.operation_id).expect("plan loads");
    assert_eq!(loaded.content_hash, plan.content_hash);
}

#[test]
fn storage_rejects_an_unjournaled_plan_status() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("storage opens");
    let capability = CapabilityV1::new(
        "account-api-tokens-create-token",
        "Create account token",
        "POST",
        "/accounts/{account_id}/tokens",
    );
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "sha256:catalog",
        capability,
        json!({"account_id":"account-a"}),
    )
    .expect("plan");
    plan.status = PlanStatus::Verified;

    let error = store
        .save_plan(&plan)
        .expect_err("unjournaled status must not persist");
    assert!(matches!(error, StorageError::InvalidPlan(_)));
}

#[test]
fn storage_rejects_a_status_tampered_plan_on_load() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let paths = RuntimePaths::from_root(root.path());
    let store = StateStore::open(paths.clone()).expect("storage opens");
    let capability = CapabilityV1::new(
        "account-api-tokens-create-token",
        "Create account token",
        "POST",
        "/accounts/{account_id}/tokens",
    );
    let plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "sha256:catalog",
        capability,
        json!({"account_id":"account-a"}),
    )
    .expect("plan");
    store.save_plan(&plan).expect("valid plan stores");
    let path = paths
        .data_dir
        .join("plans")
        .join(format!("{}.json", plan.operation_id));
    let mut document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("stored plan reads"))
            .expect("stored plan parses");
    document["status"] = json!("verified");
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&document).expect("tampered plan encodes"),
    )
    .expect("tampered plan writes");

    let error = store
        .load_plan(&plan.operation_id)
        .expect_err("status tampering must fail on load");
    assert!(matches!(error, StorageError::InvalidPlan(_)));
}

#[test]
fn registered_roots_are_explicit_and_canonicalized() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let workspace = tempfile::tempdir().expect("workspace root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("storage opens");
    store
        .register_workspace_root(workspace.path())
        .expect("register root");
    let roots = store.workspace_roots().expect("read roots");
    assert_eq!(
        roots,
        vec![workspace.path().canonicalize().expect("canonical root")]
    );
}

#[test]
fn imports_are_bounded_to_the_managed_data_directory() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("storage opens");
    let destination = store
        .write_import(
            std::path::Path::new("v1/sha256-safe/state/dns.yaml"),
            b"records: []\n",
        )
        .expect("bounded import");
    assert!(destination.starts_with(root.path().join("data/imports")));
    assert_eq!(
        std::fs::read_to_string(destination).expect("imported contents"),
        "records: []\n"
    );
    assert!(
        store
            .write_import(std::path::Path::new("../escape"), b"no")
            .is_err()
    );
}

#[test]
fn plan_locks_are_exclusive_and_expired_crash_locks_are_reclaimed() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("storage opens");
    let operation_a = "00000000-0000-4000-8000-000000000001";
    let operation_b = "00000000-0000-4000-8000-000000000002";
    let first = store.lock_plan(operation_a).expect("first lock");
    assert!(matches!(
        store.lock_plan(operation_a),
        Err(StorageError::PlanLocked(_))
    ));
    drop(first);
    drop(store.lock_plan(operation_a).expect("released lock"));

    let crashed = store.lock_plan(operation_b).expect("crash fixture lock");
    std::mem::forget(crashed);
    let lock_path = root
        .path()
        .join("data/locks")
        .join(format!("{operation_b}.lock"));
    std::fs::write(
        &lock_path,
        br#"{"pid":999999,"created_at_unix":0,"nonce":"crashed"}"#,
    )
    .expect("age crash lock");
    drop(store.lock_plan(operation_b).expect("stale lock reclaimed"));
    assert!(!lock_path.exists());
}

#[test]
fn managed_ids_cannot_escape_or_alias_their_storage_directories() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("storage opens");

    let escaped_lock = root.path().join("data/escaped-plan.lock");
    assert!(matches!(
        store.lock_plan("../escaped-plan"),
        Err(StorageError::InvalidPlanId(_))
    ));
    assert!(!escaped_lock.exists());

    let mut traversal = draft_authority();
    traversal.authority_id = "../../escaped-authority".to_owned();
    assert!(matches!(
        store.save_authority(&traversal),
        Err(StorageError::InvalidAuthorityId(_))
    ));
    assert!(!root.path().join("escaped-authority.json").exists());

    let mut absolute = draft_authority();
    let escaped_absolute = root.path().join("absolute-authority.json");
    absolute.authority_id = root.path().join("absolute-authority").display().to_string();
    assert!(matches!(
        store.save_authority(&absolute),
        Err(StorageError::InvalidAuthorityId(_))
    ));
    assert!(!escaped_absolute.exists());

    let plan = draft_plan();
    assert!(matches!(
        store.load_plan(&plan.operation_id.to_uppercase()),
        Err(StorageError::InvalidPlanId(_))
    ));
    assert!(matches!(
        store.load_plan(&plan.operation_id.replace('-', "")),
        Err(StorageError::InvalidPlanId(_))
    ));

    let authority = draft_authority();
    assert!(matches!(
        store.load_authority(&authority.authority_id.to_uppercase()),
        Err(StorageError::InvalidAuthorityId(_))
    ));
    assert!(matches!(
        store.load_authority(&authority.authority_id.replace('-', "")),
        Err(StorageError::InvalidAuthorityId(_))
    ));
}

#[test]
fn authority_creation_is_create_only_and_cannot_clobber_existing_state() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("storage opens");
    let authority = draft_authority();
    store
        .save_authority(&authority)
        .expect("first authority creation succeeds");

    let mut replacement = authority.clone();
    replacement.revoke();
    assert!(matches!(
        store.save_authority(&replacement),
        Err(StorageError::AuthorityAlreadyExists(_))
    ));

    let reloaded = store
        .load_authority(&authority.authority_id)
        .expect("original authority remains readable");
    assert_eq!(reloaded.status, StandingAuthorityStatus::PendingApproval);
}

#[test]
fn managed_document_identity_must_match_its_filename() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let paths = RuntimePaths::from_root(root.path());
    let store = StateStore::open(paths.clone()).expect("storage opens");

    let plan = draft_plan();
    store.save_plan(&plan).expect("plan stores");
    let forged_plan_id = "00000000-0000-4000-8000-000000000047";
    std::fs::copy(
        paths
            .data_dir
            .join("plans")
            .join(format!("{}.json", plan.operation_id)),
        paths
            .data_dir
            .join("plans")
            .join(format!("{forged_plan_id}.json")),
    )
    .expect("forged plan document writes");
    assert!(matches!(
        store.load_plan(forged_plan_id),
        Err(StorageError::ManagedDocumentIdentityMismatch { .. })
    ));
    assert!(matches!(
        store.list_plans(),
        Err(StorageError::ManagedDocumentIdentityMismatch { .. })
    ));

    let authority = draft_authority();
    store.save_authority(&authority).expect("authority stores");
    let forged_authority_id = "00000000-0000-4000-8000-000000000048";
    std::fs::copy(
        paths
            .data_dir
            .join("authorities")
            .join(format!("{}.json", authority.authority_id)),
        paths
            .data_dir
            .join("authorities")
            .join(format!("{forged_authority_id}.json")),
    )
    .expect("forged authority document writes");
    assert!(matches!(
        store.load_authority(forged_authority_id),
        Err(StorageError::ManagedDocumentIdentityMismatch { .. })
    ));
    assert!(matches!(
        store.list_authorities(),
        Err(StorageError::ManagedDocumentIdentityMismatch { .. })
    ));
}

#[cfg(unix)]
#[test]
fn managed_documents_reject_symlinks_instead_of_following_them() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().expect("temporary storage root");
    let paths = RuntimePaths::from_root(root.path());
    let store = StateStore::open(paths.clone()).expect("storage opens");

    let plan = draft_plan();
    store.save_plan(&plan).expect("plan stores");
    let plan_path = paths
        .data_dir
        .join("plans")
        .join(format!("{}.json", plan.operation_id));
    let external_plan = root.path().join("external-plan.json");
    std::fs::rename(&plan_path, &external_plan).expect("move plan outside managed directory");
    symlink(&external_plan, &plan_path).expect("forge plan symlink");
    assert!(matches!(
        store.load_plan(&plan.operation_id),
        Err(StorageError::UnsafeManagedDocument { .. })
    ));
    assert!(matches!(
        store.save_plan(&plan),
        Err(StorageError::UnsafeManagedDocument { .. })
    ));
    assert!(matches!(
        store.list_plans(),
        Err(StorageError::UnsafeManagedDocument { .. })
    ));

    let authority = draft_authority();
    store.save_authority(&authority).expect("authority stores");
    let authority_path = paths
        .data_dir
        .join("authorities")
        .join(format!("{}.json", authority.authority_id));
    let external_authority = root.path().join("external-authority.json");
    std::fs::rename(&authority_path, &external_authority)
        .expect("move authority outside managed directory");
    symlink(&external_authority, &authority_path).expect("forge authority symlink");
    assert!(matches!(
        store.load_authority(&authority.authority_id),
        Err(StorageError::UnsafeManagedDocument { .. })
    ));
    assert!(matches!(
        store.save_authority(&authority),
        Err(StorageError::UnsafeManagedDocument { .. })
    ));
    assert!(matches!(
        store.list_authorities(),
        Err(StorageError::UnsafeManagedDocument { .. })
    ));
}

#[test]
fn managed_document_listing_rejects_malformed_names_and_non_regular_files() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let paths = RuntimePaths::from_root(root.path());
    let store = StateStore::open(paths.clone()).expect("storage opens");
    let plan = draft_plan();
    store.save_plan(&plan).expect("plan stores");
    std::fs::copy(
        paths
            .data_dir
            .join("plans")
            .join(format!("{}.json", plan.operation_id)),
        paths.data_dir.join("plans/not-a-uuid.json"),
    )
    .expect("malformed plan filename fixture writes");
    assert!(matches!(
        store.list_plans(),
        Err(StorageError::InvalidPlanId(_))
    ));

    std::fs::remove_file(paths.data_dir.join("plans/not-a-uuid.json"))
        .expect("remove malformed fixture");
    let non_regular_id = "00000000-0000-4000-8000-000000000049";
    std::fs::create_dir(paths.data_dir.join(format!("plans/{non_regular_id}.json")))
        .expect("non-regular plan fixture writes");
    assert!(matches!(
        store.load_plan(non_regular_id),
        Err(StorageError::UnsafeManagedDocument { .. })
    ));
    assert!(matches!(
        store.list_plans(),
        Err(StorageError::UnsafeManagedDocument { .. })
    ));

    let authority = draft_authority();
    store
        .create_authority(&authority)
        .expect("authority stores");
    std::fs::copy(
        paths
            .data_dir
            .join("authorities")
            .join(format!("{}.json", authority.authority_id)),
        paths.data_dir.join("authorities/NOT-A-UUID.json"),
    )
    .expect("malformed authority filename fixture writes");
    assert!(matches!(
        store.list_authorities(),
        Err(StorageError::InvalidAuthorityId(_))
    ));
}

#[test]
fn authority_lock_guards_are_bound_to_the_store_root_and_authority_id() {
    let first_root = tempfile::tempdir().expect("first temporary storage root");
    let first_store =
        StateStore::open(RuntimePaths::from_root(first_root.path())).expect("first storage opens");
    let first = draft_authority();
    let second = draft_authority();
    first_store
        .create_authority(&first)
        .expect("first authority stores");
    first_store
        .create_authority(&second)
        .expect("second authority stores");

    let first_guard = first_store
        .lock_authority(&first.authority_id)
        .expect("first authority locks");
    let mut second_update = second.clone();
    second_update.revoke();
    assert!(matches!(
        first_store.save_authority_guarded(&second_update, &first_guard),
        Err(StorageError::AuthorityLockMismatch(_))
    ));
    drop(first_guard);

    let other_root = tempfile::tempdir().expect("other temporary storage root");
    let other_store =
        StateStore::open(RuntimePaths::from_root(other_root.path())).expect("other storage opens");
    other_store
        .create_authority(&first)
        .expect("same identifier stores under other root");
    let other_guard = other_store
        .lock_authority(&first.authority_id)
        .expect("other-root authority locks");
    assert!(matches!(
        first_store.save_authority_guarded(&first, &other_guard),
        Err(StorageError::AuthorityLockMismatch(_))
    ));
}

#[test]
fn authority_locks_are_os_backed_and_exclusive_across_stores() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let paths = RuntimePaths::from_root(root.path());
    let first_store = StateStore::open(paths.clone()).expect("first storage opens");
    let second_store = StateStore::open(paths).expect("second storage opens");
    let authority = draft_authority();
    first_store
        .create_authority(&authority)
        .expect("authority stores");
    let first_guard = first_store
        .lock_authority(&authority.authority_id)
        .expect("first store acquires lock");

    let authority_id = authority.authority_id.clone();
    let (acquired_tx, acquired_rx) = std::sync::mpsc::channel();
    let contender = std::thread::spawn(move || {
        let guard = second_store
            .lock_authority(&authority_id)
            .expect("second store eventually acquires lock");
        acquired_tx.send(()).expect("report lock acquisition");
        guard
    });
    assert!(matches!(
        acquired_rx.recv_timeout(std::time::Duration::from_millis(150)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
    ));

    drop(first_guard);
    acquired_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("second store acquires released lock");
    drop(contender.join().expect("lock contender joins"));
}

#[test]
fn guarded_authority_saves_preserve_durable_revocation_and_lineage() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("storage opens");
    let authority = draft_authority();
    store
        .create_authority(&authority)
        .expect("authority stores");

    let approval_guard = store
        .lock_authority(&authority.authority_id)
        .expect("authority locks for approval");
    let mut active = store
        .load_authority(&authority.authority_id)
        .expect("authority reloads under lock");
    active.approve(true).expect("authority approves");
    store
        .save_authority_guarded(&active, &approval_guard)
        .expect("approval saves under guard");
    drop(approval_guard);

    let revocation_guard = store
        .lock_authority(&authority.authority_id)
        .expect("authority locks for revocation");
    let mut revoked = store
        .load_authority(&authority.authority_id)
        .expect("active authority reloads under lock");
    revoked.revoke();
    store
        .save_authority_guarded(&revoked, &revocation_guard)
        .expect("revocation saves under guard");
    drop(revocation_guard);

    let lineage_guard = store
        .lock_authority(&authority.authority_id)
        .expect("authority locks for lineage");
    let mut stale_active = active;
    stale_active.record_minted_token("token-stale");
    assert!(matches!(
        store.save_authority_guarded(&stale_active, &lineage_guard),
        Err(StorageError::AuthorityRevocationRollback(_))
    ));
    let mut lineage = store
        .load_authority(&authority.authority_id)
        .expect("revoked authority reloads under lock");
    lineage.record_minted_token("token-reconciled");
    store
        .save_authority_guarded(&lineage, &lineage_guard)
        .expect("lineage saves without reversing revocation");
    drop(lineage_guard);

    let reloaded = store
        .load_authority(&authority.authority_id)
        .expect("authority reloads");
    assert_eq!(reloaded.status, StandingAuthorityStatus::Revoked);
    assert_eq!(reloaded.minted_token_ids, vec!["token-reconciled"]);
}

#[cfg(unix)]
#[test]
fn managed_documents_and_lock_files_use_private_modes() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().expect("temporary storage root");
    let paths = RuntimePaths::from_root(root.path());
    let store = StateStore::open(paths.clone()).expect("storage opens");
    let plan = draft_plan();
    let authority = draft_authority();
    store.save_plan(&plan).expect("plan stores");
    store
        .create_authority(&authority)
        .expect("authority stores");
    let plan_guard = store.lock_plan(&plan.operation_id).expect("plan locks");
    let authority_guard = store
        .lock_authority(&authority.authority_id)
        .expect("authority locks");

    for path in [
        paths
            .data_dir
            .join("plans")
            .join(format!("{}.json", plan.operation_id)),
        paths
            .data_dir
            .join("authorities")
            .join(format!("{}.json", authority.authority_id)),
        paths
            .data_dir
            .join("locks")
            .join(format!("{}.lock", plan.operation_id)),
        paths
            .data_dir
            .join("locks/authorities")
            .join(format!("{}.lock", authority.authority_id)),
    ] {
        let mode = std::fs::metadata(&path)
            .expect("managed file metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "{} must be private", path.display());
    }

    drop(authority_guard);
    drop(plan_guard);
}

#[test]
fn crash_injection_matrix_recovers_the_last_durable_transaction_stage() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let paths = RuntimePaths::from_root(root.path());
    let mut store = StateStore::open(paths.clone()).expect("storage opens");
    let capability = CapabilityV1::new(
        "account-api-tokens-create-token",
        "Create account token",
        "POST",
        "/accounts/{account_id}/tokens",
    );
    let mut durable = PlanV1::draft(
        "profile-a",
        "account-a",
        "sha256:catalog",
        capability,
        json!({"account_id":"account-a"}),
    )
    .expect("plan");
    store.save_plan(&durable).expect("initial checkpoint");

    for next_stage in [
        TransactionStageV1::ApprovalPersisted,
        TransactionStageV1::ConsumptionPersisted,
        TransactionStageV1::BoundaryAttemptPersisted,
        TransactionStageV1::BoundaryResponsePersisted,
        TransactionStageV1::SecretSinkPersisted,
        TransactionStageV1::VerificationAttemptPersisted,
        TransactionStageV1::VerificationResponsePersisted,
        TransactionStageV1::CompensationAttemptPersisted,
        TransactionStageV1::CompensationResponsePersisted,
        TransactionStageV1::Closed,
    ] {
        let persisted_stage = durable.transaction_stage;
        let mut volatile = durable.clone();
        advance_transaction(&mut volatile, next_stage);
        drop(volatile);
        drop(store);

        store = StateStore::open(paths.clone()).expect("storage reopens after injected crash");
        let recovered = store
            .load_plan(&durable.operation_id)
            .expect("last durable plan reloads");
        recovered
            .validate_transaction_journal()
            .expect("recovered journal validates");
        assert_eq!(recovered.transaction_stage, persisted_stage);

        advance_transaction(&mut durable, next_stage);
        store
            .save_plan(&durable)
            .expect("next stage becomes durable");
        drop(store);
        store = StateStore::open(paths.clone()).expect("storage reopens after durable stage");
        durable = store
            .load_plan(&durable.operation_id)
            .expect("durable stage reloads");
        durable
            .validate_transaction_journal()
            .expect("durable journal validates");
        assert_eq!(durable.transaction_stage, next_stage);
    }
}

fn advance_transaction(plan: &mut PlanV1, stage: TransactionStageV1) {
    match stage {
        TransactionStageV1::ApprovalPersisted => plan.approve(true, None).expect("approve"),
        TransactionStageV1::ConsumptionPersisted => plan.mark_consumed().expect("consume"),
        TransactionStageV1::BoundaryResponsePersisted
        | TransactionStageV1::SecretSinkPersisted
        | TransactionStageV1::VerificationResponsePersisted
        | TransactionStageV1::CompensationResponsePersisted => plan
            .record_transaction_stage_with_artifact(
                stage,
                json!({"stage":stage.as_str(),"receipt_hash":"sha256:fixture"}),
            )
            .expect("artifact checkpoint"),
        _ => plan
            .record_transaction_stage(stage)
            .expect("transaction checkpoint"),
    }
}
