#![allow(clippy::expect_used, clippy::unwrap_used)]
use super::*;
use crate::{ArchivedRuntimeV1, PRIVATE_MODE_FILE, PrivateDirectory, RuntimePaths};
use cfctl_core::{
    EvidenceClass, OperationalProofOutcomeV1, OperationalProofScopeV1, OperationalProofV1,
};
use chrono::Utc;
use serde_json::json;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

struct Fixture {
    root: tempfile::TempDir,
    store: StateStore,
    original: EvidenceKeyManager,
    previous_device: u64,
    root_identity: String,
    evidence_hash: String,
    proof_hash: String,
}

fn fixture() -> Fixture {
    let root = tempfile::tempdir().expect("fixture root");
    let paths = RuntimePaths::from_root(root.path());
    for path in [&paths.data_dir, &paths.config_dir, &paths.cache_dir] {
        PrivateDirectory::create(path).expect("owned private directory");
    }
    PrivateDirectory::create(&paths.data_dir.join("private-authority")).expect("authority custody");
    let origin = ArchivedRuntimeV1 {
        schema_version: 1,
        epoch_id: uuid::Uuid::new_v4().to_string(),
        config_dir: PathBuf::from("/archived/config"),
        data_dir: PathBuf::from("/archived/data"),
        cache_dir: PathBuf::from("/archived/cache"),
        continuity: "unavailable_fresh_authority".to_owned(),
    };
    PrivateDirectory::open(&paths.data_dir)
        .expect("data")
        .write(
            PRIVATE_MODE_FILE,
            &serde_json::to_vec(&origin).expect("origin JSON"),
        )
        .expect("private origin");
    let store = StateStore::open(paths).expect("private store");
    let location = store.private_location().expect("current native location");
    let previous_device = location.device_id + 1;
    let original_location = location
        .at_device(previous_device)
        .expect("previous namespace");
    let original = store
        .raw_private_manager(&original_location)
        .expect("original manager");
    let root_identity = format!("sha256:{}", "a".repeat(64));
    original
        .initialize(&root_identity)
        .expect("original authority");
    store
        .initialize_evidence_root_identity(&root_identity)
        .expect("existing marker");
    // Seed the exact pre-drift namespace without changing the host mount. This
    // fixture-only store models writes made before the device number changed.
    let mut historical = store.clone();
    historical.evidence_authenticator = Some(Arc::new(original.clone()));
    let evidence = historical
        .write_evidence(EvidenceClass::LiveRead, &json!({"original": true}))
        .expect("original evidence");
    let evidence_hash = evidence.content_hash.clone();
    let proof = OperationalProofV1::new(
        Utc::now(),
        "zones-list",
        &format!("sha256:{}", "b".repeat(64)),
        &format!("sha256:{}", "c".repeat(64)),
        OperationalProofScopeV1::new(
            Some("fixture-profile"),
            Some("fixture-account"),
            Some("7ff2b63e-f412-4a73-978a-e88b86ef5327"),
        ),
        OperationalProofOutcomeV1::Succeeded,
        evidence,
    );
    historical
        .record_operational_proof(&proof)
        .expect("original proof");
    let proof_hash = historical
        .operational_proof_hash(&proof)
        .expect("proof identity");
    Fixture {
        root,
        store,
        original,
        previous_device,
        root_identity,
        evidence_hash,
        proof_hash,
    }
}

fn files(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut result = BTreeMap::new();
    for entry in fs::read_dir(root).expect("fixture directory") {
        let entry = entry.expect("entry");
        if entry.file_type().expect("entry type").is_dir() {
            result.extend(files(&entry.path()));
        } else {
            result.insert(entry.path(), fs::read(entry.path()).expect("fixture bytes"));
        }
    }
    result
}

fn bind(fixture: &Fixture) -> PrivateAuthorityRebindPreviewV1 {
    let preview = fixture
        .store
        .private_authority_rebind_preview(fixture.previous_device)
        .expect("preview");
    fixture
        .store
        .rebind_private_authority(fixture.previous_device, &preview.review_digest)
        .expect("bind reviewed authority")
}

#[test]
fn private_rebind_preview_verifies_original_history_without_writes_or_implicit_attachment() {
    let fixture = fixture();
    let before = files(&fixture.store.paths.data_dir);
    let marker = Some(fixture.root_identity.as_str());
    let verifier = HistoryVerifier(fixture.original.clone());
    assert!(verifier.status(marker).is_err());
    assert!(
        verifier
            .authenticate(&fixture.root_identity, "probe", b"read only")
            .is_err()
    );
    assert!(
        !fixture
            .store
            .platform_evidence_key_manager()
            .expect("current manager")
            .status(marker)
            .expect("current status")
            .initialized
    );
    let preview = fixture
        .store
        .private_authority_rebind_preview(fixture.previous_device)
        .expect("native history preview");
    assert_eq!(preview.review.history.descriptor_count, 1);
    assert_eq!(preview.review.history.proof_count, 1);
    assert_eq!(
        preview.review.original_authority,
        fixture.original.status(marker).expect("original status")
    );
    assert!(!preview.already_bound);
    assert!(!preview.secret_key_bytes_exposed);
    let rendered = serde_json::to_string(&preview).expect("public preview");
    let secret_path = fs::read_dir(fixture.store.paths.data_dir.join("private-authority"))
        .expect("custody")
        .next()
        .expect("one registry")
        .expect("registry entry")
        .path();
    let registry: serde_json::Value =
        serde_json::from_slice(&fs::read(secret_path).expect("fixture registry"))
            .expect("fixture registry JSON");
    for value in registry["generations"]
        .as_object()
        .expect("fixture keys")
        .values()
    {
        assert!(!rendered.contains(value.as_str().expect("fixture key")));
    }
    assert_eq!(files(&fixture.store.paths.data_dir), before);
    assert!(
        !fixture
            .store
            .platform_evidence_key_manager()
            .expect("current manager")
            .status(marker)
            .expect("current status")
            .initialized
    );
}

#[test]
fn private_rebind_preserves_original_key_marker_and_history_and_reopens_natively() {
    let fixture = fixture();
    let before = files(&fixture.store.paths.data_dir);
    let result = bind(&fixture);
    assert!(!result.already_bound);
    let after = files(&fixture.store.paths.data_dir);
    assert_eq!(after.len(), before.len() + 1);
    for (path, bytes) in before {
        assert_eq!(after.get(&path), Some(&bytes));
    }
    let reopened = StateStore::open(fixture.store.paths.clone()).expect("reopen");
    let manager = reopened
        .platform_evidence_key_manager()
        .expect("bound manager");
    assert_eq!(
        manager.location_identity(),
        reopened.evidence_location_identity()
    );
    assert_eq!(
        manager
            .status(Some(&fixture.root_identity))
            .expect("bound status"),
        result.review.original_authority
    );
    let qualified = reopened
        .with_evidence_authenticator(Arc::new(manager))
        .expect("exact current attachment");
    qualified
        .require_qualifying_evidence_authority()
        .expect("qualifying original key");
    qualified
        .load_evidence(&fixture.evidence_hash)
        .expect("original body and descriptor");
    qualified
        .load_operational_proof(&fixture.proof_hash)
        .expect("original proof");
    let retry = fixture
        .store
        .rebind_private_authority(fixture.previous_device, &result.review_digest)
        .expect("exact retry");
    assert!(retry.already_bound);
    assert_eq!(files(&fixture.store.paths.data_dir), after);
}

#[test]
fn private_rebind_rejects_wrong_device_and_ambiguous_registry_without_writes() {
    let fixture = fixture();
    let before = files(&fixture.store.paths.data_dir);
    assert!(
        fixture
            .store
            .private_authority_rebind_preview(fixture.previous_device + 1)
            .is_err()
    );
    assert_eq!(files(&fixture.store.paths.data_dir), before);
    fixture
        .store
        .private_secret_store()
        .put("unselected-registry", "fixture residue")
        .expect("ambiguous custody fixture");
    let ambiguous = files(&fixture.store.paths.data_dir);
    assert!(
        fixture
            .store
            .private_authority_rebind_preview(fixture.previous_device)
            .is_err()
    );
    assert_eq!(files(&fixture.store.paths.data_dir), ambiguous);
}

#[test]
fn private_rebind_rejects_marker_mismatch_and_malformed_original_registry() {
    let fixture = fixture();
    let marker_path = fixture.store.paths.data_dir.join("evidence-root-v1.json");
    let marker = fs::read(&marker_path).expect("original marker");
    fs::write(&marker_path, serde_json::to_vec(&json!({"schema_version": 1, "state_root_identity": format!("sha256:{}", "d".repeat(64))})).expect("mismatch JSON")).expect("fixture marker mismatch");
    assert!(
        fixture
            .store
            .private_authority_rebind_preview(fixture.previous_device)
            .is_err()
    );
    fs::write(&marker_path, marker).expect("restore fixture marker");
    fixture
        .store
        .private_secret_store()
        .put(
            &format!(
                "evidence-integrity/location/{}/registry-v1",
                fixture.original.location_identity()
            ),
            "{",
        )
        .expect("fixture malformed registry");
    assert!(
        fixture
            .store
            .private_authority_rebind_preview(fixture.previous_device)
            .is_err()
    );
    assert!(
        fixture
            .store
            .read_private_binding()
            .expect("binding remains absent")
            .is_none()
    );
}

#[test]
fn private_rebind_rejects_corrupt_or_partial_history() {
    for kind in ["evidence", "evidence-descriptors", "evidence-index"] {
        let fixture = fixture();
        let digest = if kind == "evidence-index" {
            &fixture.proof_hash
        } else {
            &fixture.evidence_hash
        };
        let path = fixture
            .store
            .paths
            .data_dir
            .join(kind)
            .join(format!("{}.json", &digest[7..]));
        fs::write(&path, b"{}").expect("corrupt fixture artifact");
        let before = files(&fixture.store.paths.data_dir);
        assert!(
            fixture
                .store
                .private_authority_rebind_preview(fixture.previous_device)
                .is_err(),
            "corrupt {kind}"
        );
        assert_eq!(files(&fixture.store.paths.data_dir), before);
    }
    let fixture = fixture();
    fs::remove_file(
        fixture
            .store
            .paths
            .data_dir
            .join("evidence-index")
            .join(format!("{}.json", &fixture.proof_hash[7..])),
    )
    .expect("remove fixture proof");
    assert!(
        fixture
            .store
            .private_authority_rebind_preview(fixture.previous_device)
            .is_err()
    );
}

#[test]
fn private_rebind_requires_the_exact_fresh_history_review() {
    let fixture = fixture();
    let preview = fixture
        .store
        .private_authority_rebind_preview(fixture.previous_device)
        .expect("preview");
    assert!(
        fixture
            .store
            .rebind_private_authority(fixture.previous_device, "sha256:wrong")
            .is_err()
    );
    let mut historical = fixture.store.clone();
    historical.evidence_authenticator = Some(Arc::new(fixture.original.clone()));
    historical
        .write_evidence(EvidenceClass::LiveRead, &json!({"later": true}))
        .expect("history advances");
    assert!(
        fixture
            .store
            .rebind_private_authority(fixture.previous_device, &preview.review_digest)
            .is_err()
    );
    assert!(
        fixture
            .store
            .read_private_binding()
            .expect("no binding")
            .is_none()
    );
}

#[test]
fn private_rebind_rejects_tampered_binding_without_fallback_or_overwrite() {
    let fixture = fixture();
    let result = bind(&fixture);
    let path = fixture
        .store
        .paths
        .data_dir
        .join(fixture.store.binding_name().expect("binding name"));
    let mut binding = fixture
        .store
        .read_private_binding()
        .expect("binding")
        .expect("present");
    binding.review.history.descriptor_count += 1;
    fs::write(
        &path,
        serde_json::to_vec(&binding).expect("fixture mutation"),
    )
    .expect("tamper binding");
    let before = files(&fixture.store.paths.data_dir);
    assert!(fixture.store.platform_evidence_key_manager().is_err());
    assert!(
        fixture
            .store
            .rebind_private_authority(fixture.previous_device, &result.review_digest)
            .is_err()
    );
    assert_eq!(files(&fixture.store.paths.data_dir), before);
}

#[test]
fn private_rebind_preserves_each_custody_incarnation_and_canonical_path() {
    let fixture = fixture();
    let location = fixture.store.private_location().expect("current location");
    let original = location
        .at_device(fixture.previous_device)
        .expect("original address");
    for index in 0..5 {
        let mut replaced = location.clone();
        replaced.object_identities[index].push('1');
        assert_ne!(
            replaced
                .at_device(fixture.previous_device)
                .expect("replacement address"),
            original
        );
    }
    let mut moved = location;
    moved.canonical_data_path.push_str("-copy");
    assert_ne!(
        moved
            .at_device(fixture.previous_device)
            .expect("moved address"),
        original
    );
    bind(&fixture);
    let displaced = fixture.root.path().join("displaced-evidence");
    fs::rename(fixture.store.paths.data_dir.join("evidence"), &displaced)
        .expect("displace fixture bodies directory");
    fs::create_dir(fixture.store.paths.data_dir.join("evidence"))
        .expect("replacement fixture directory");
    let replaced = StateStore::open(fixture.store.paths.clone()).expect("reopen replacement");
    assert!(
        !replaced
            .platform_evidence_key_manager()
            .expect("no binding at replacement identity")
            .status(Some(&fixture.root_identity))
            .expect("status")
            .initialized
    );
    assert!(
        replaced
            .private_authority_rebind_preview(fixture.previous_device)
            .is_err()
    );
}

#[test]
fn private_rebind_interrupted_creation_preserves_authority_and_retries_exactly() {
    for crossed in [false, true] {
        let fixture = fixture();
        let preview = fixture
            .store
            .private_authority_rebind_preview(fixture.previous_device)
            .expect("preview");
        let before = files(&fixture.store.paths.data_dir);
        let result = fixture.store.rebind_private_authority_with_publish(
            fixture.previous_device,
            &preview.review_digest,
            |store, name, bytes| {
                if crossed {
                    crate::atomic_create_capability_file(
                        &store.evidence_directories.data,
                        name,
                        bytes,
                        &store.paths.data_dir.join(name),
                    )?;
                }
                Err(failure("injected publication interruption"))
            },
        );
        assert!(result.is_err());
        let after = files(&fixture.store.paths.data_dir);
        for (path, bytes) in before {
            assert_eq!(after.get(&path), Some(&bytes));
        }
        let retry = fixture
            .store
            .rebind_private_authority(fixture.previous_device, &preview.review_digest)
            .expect("retry reviewed recovery");
        assert_eq!(retry.already_bound, crossed);
    }
}

#[test]
fn private_rebind_survives_rotation_and_protects_its_signing_generation_from_retirement() {
    let fixture = fixture();
    let result = bind(&fixture);
    let original_generation = result
        .review
        .original_authority
        .active_generation_id
        .expect("original generation");
    let manager = fixture
        .store
        .platform_evidence_key_manager()
        .expect("bound manager");
    manager
        .rotate(&fixture.root_identity)
        .expect("normal rotation retains original verification key");
    let reopened = StateStore::open(fixture.store.paths.clone()).expect("reopen after rotation");
    let manager = reopened
        .platform_evidence_key_manager()
        .expect("binding verifies with retained generation");
    assert_ne!(
        manager
            .status(Some(&fixture.root_identity))
            .expect("rotated status")
            .active_generation_id
            .as_deref(),
        Some(original_generation.as_str())
    );
    let qualified = reopened
        .with_evidence_authenticator(Arc::new(manager))
        .expect("attach");
    let lifecycle = qualified.lock_evidence_lifecycle().expect("lifecycle");
    assert_eq!(
        qualified
            .evidence_key_generation_usage(&lifecycle, &original_generation)
            .expect("all generation dependents"),
        3
    );
    let mut binding = qualified
        .read_private_binding()
        .expect("binding reads")
        .expect("binding exists");
    binding.authentication.tag = "0".repeat(64);
    fs::write(
        qualified
            .paths
            .data_dir
            .join(qualified.binding_name().expect("binding name")),
        serde_json::to_vec(&binding).expect("tampered fixture JSON"),
    )
    .expect("tamper fixture binding after manager construction");
    assert!(
        qualified
            .evidence_key_generation_usage(&lifecycle, &original_generation)
            .is_err()
    );
}
