#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::{
    fs,
    path::Path,
    sync::{Arc, Mutex, mpsc},
    thread,
    time::Duration as StdDuration,
};

use cfctl_auth::{
    AuthError, EvidenceAuthenticationV1, EvidenceKeyManager, EvidenceKeyStatusV1,
    EvidenceMacProvider, MemorySecretStore, SecretBackend,
};
use cfctl_core::{
    EvidenceClass, EvidenceV1, OperationalProofOutcomeV1, OperationalProofScopeV1,
    OperationalProofV1,
};
use cfctl_storage::{RuntimePaths, StateStore, StorageError};
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const GENERATION: &str = "7ff2b63e-f412-4a73-978a-e88b86ef5327";

fn sha256(byte: u8) -> String {
    format!("sha256:{}", char::from(byte).to_string().repeat(64))
}

fn descriptor_path(paths: &RuntimePaths, content_hash: &str) -> std::path::PathBuf {
    paths
        .data_dir
        .join("evidence-descriptors")
        .join(format!("{}.json", &content_hash[7..]))
}

fn proof(evidence: EvidenceV1) -> OperationalProofV1 {
    OperationalProofV1::new(
        Utc::now(),
        "zones-list",
        &sha256(b'a'),
        &sha256(b'b'),
        OperationalProofScopeV1::new(Some("profile-a"), Some("account-a"), Some(GENERATION)),
        OperationalProofOutcomeV1::Succeeded,
        evidence,
    )
}

fn proof_hash(proof: &OperationalProofV1) -> String {
    let bytes = serde_json::to_vec_pretty(proof).expect("proof encodes");
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn proof_path(paths: &RuntimePaths, proof: &OperationalProofV1) -> std::path::PathBuf {
    paths
        .data_dir
        .join("evidence-index")
        .join(format!("{}.json", &proof_hash(proof)[7..]))
}

fn authenticated_store(paths: RuntimePaths) -> StateStore {
    authenticated_store_with_manager(paths).0
}

fn authenticated_store_with_manager(paths: RuntimePaths) -> (StateStore, Arc<EvidenceKeyManager>) {
    let store = StateStore::open(paths).expect("storage opens");
    let manager = Arc::new(
        EvidenceKeyManager::new(
            Arc::new(MemorySecretStore::default()),
            store.evidence_location_identity(),
            SecretBackend::Memory,
        )
        .expect("test evidence key manager"),
    );
    let state_root_identity = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(b"cfctl-storage-evidence-test-root"))
    );
    manager
        .initialize(&state_root_identity)
        .expect("test evidence key initializes");
    store
        .initialize_evidence_root_identity(&state_root_identity)
        .expect("test root marker initializes");
    let store = store
        .with_evidence_authenticator(manager.clone())
        .expect("authenticated storage opens");
    (store, manager)
}

struct PausingEvidenceMacProvider {
    inner: Arc<EvidenceKeyManager>,
    authenticated: Mutex<Option<mpsc::SyncSender<()>>>,
    resume: Mutex<mpsc::Receiver<()>>,
}

impl EvidenceMacProvider for PausingEvidenceMacProvider {
    fn location_identity(&self) -> &str {
        self.inner.location_identity()
    }

    fn status(&self, state_root_identity: Option<&str>) -> Result<EvidenceKeyStatusV1, AuthError> {
        self.inner.status(state_root_identity)
    }

    fn authenticate(
        &self,
        state_root_identity: &str,
        domain: &str,
        payload: &[u8],
    ) -> Result<EvidenceAuthenticationV1, AuthError> {
        let authentication = self
            .inner
            .authenticate(state_root_identity, domain, payload)?;
        if let Some(authenticated) = self.authenticated.lock().expect("pause lock").take() {
            authenticated
                .send(())
                .expect("writer announces authentication");
            self.resume
                .lock()
                .expect("resume lock")
                .recv()
                .expect("writer resumes");
        }
        Ok(authentication)
    }

    fn verify(
        &self,
        state_root_identity: &str,
        domain: &str,
        payload: &[u8],
        authentication: &EvidenceAuthenticationV1,
    ) -> Result<(), AuthError> {
        self.inner
            .verify(state_root_identity, domain, payload, authentication)
    }
}

fn generation_usage(store: &StateStore, generation_id: &str) -> cfctl_storage::Result<usize> {
    let lifecycle = store.lock_evidence_lifecycle()?;
    store.evidence_key_generation_usage(&lifecycle, generation_id)
}

#[test]
fn paused_old_generation_publication_precedes_rotation_and_retirement() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let paths = RuntimePaths::from_root(root.path());
    let (store, manager) = authenticated_store_with_manager(paths);
    let root_identity = store
        .evidence_root_identity()
        .expect("root reads")
        .expect("root exists");
    let old_generation = manager
        .status(Some(&root_identity))
        .expect("status")
        .active_generation_id
        .expect("active generation");

    let (authenticated_tx, authenticated_rx) = mpsc::sync_channel(1);
    let (resume_tx, resume_rx) = mpsc::sync_channel(1);
    let provider = Arc::new(PausingEvidenceMacProvider {
        inner: manager.clone(),
        authenticated: Mutex::new(Some(authenticated_tx)),
        resume: Mutex::new(resume_rx),
    });
    let writer_store = store
        .clone()
        .with_evidence_authenticator(provider)
        .expect("paused authenticated store");
    let writer = thread::spawn(move || {
        writer_store.write_evidence(EvidenceClass::LiveRead, &json!({"paused_generation":"g0"}))
    });
    authenticated_rx
        .recv()
        .expect("writer pauses after authenticating with g0");

    let retirement_store = store.clone();
    let retirement_manager = manager.clone();
    let retirement_root = root_identity.clone();
    let retirement_generation = old_generation.clone();
    let (attempting_tx, attempting_rx) = mpsc::sync_channel(1);
    let (acquired_tx, acquired_rx) = mpsc::sync_channel(1);
    let retirement = thread::spawn(move || {
        attempting_tx.send(()).expect("retirement attempts lock");
        let lifecycle = retirement_store
            .lock_evidence_lifecycle()
            .expect("retirement lifecycle lock");
        acquired_tx.send(()).expect("retirement acquired lock");
        retirement_manager
            .rotate(&retirement_root)
            .expect("rotation after publication");
        let usage = retirement_store
            .evidence_key_generation_usage(&lifecycle, &retirement_generation)
            .expect("authenticated usage scans");
        let result = retirement_manager.retire(&retirement_root, &retirement_generation, usage);
        (usage, result)
    });
    attempting_rx.recv().expect("retirement thread started");
    assert!(
        acquired_rx
            .recv_timeout(StdDuration::from_millis(150))
            .is_err(),
        "retirement must not cross the writer's lifecycle lock"
    );

    resume_tx.send(()).expect("writer resumes");
    writer
        .join()
        .expect("writer thread joins")
        .expect("g0 descriptor publishes");
    acquired_rx
        .recv()
        .expect("retirement proceeds after publication");
    let (usage, retirement_result) = retirement.join().expect("retirement thread joins");
    assert_eq!(usage, 1);
    assert!(
        retirement_result.is_err(),
        "the newly published g0 descriptor must block key deletion"
    );
}

#[cfg(unix)]
#[test]
fn replaced_lifecycle_lock_fails_closed_before_retirement_can_scan() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let paths = RuntimePaths::from_root(root.path());
    let (store, manager) = authenticated_store_with_manager(paths.clone());
    let root_identity = store
        .evidence_root_identity()
        .expect("root reads")
        .expect("root exists");
    let old_generation = manager
        .status(Some(&root_identity))
        .expect("status")
        .active_generation_id
        .expect("active generation");

    let (authenticated_tx, authenticated_rx) = mpsc::sync_channel(1);
    let (resume_tx, resume_rx) = mpsc::sync_channel(1);
    let writer_store = store
        .clone()
        .with_evidence_authenticator(Arc::new(PausingEvidenceMacProvider {
            inner: manager.clone(),
            authenticated: Mutex::new(Some(authenticated_tx)),
            resume: Mutex::new(resume_rx),
        }))
        .expect("paused authenticated store");
    let writer = thread::spawn(move || {
        writer_store.write_evidence(EvidenceClass::LiveRead, &json!({"paused_generation":"g0"}))
    });
    authenticated_rx
        .recv()
        .expect("writer pauses after authenticating with g0");

    let lock_path = paths.data_dir.join("locks").join("evidence-lifecycle.lock");
    let displaced_path = paths
        .data_dir
        .join("locks")
        .join("evidence-lifecycle.displaced");
    fs::rename(&lock_path, &displaced_path).expect("attacker displaces locked inode");
    fs::write(&lock_path, b"replacement").expect("attacker creates replacement inode");

    let error = store
        .lock_evidence_lifecycle()
        .expect_err("replacement lock cannot serialize retirement");
    assert!(
        error.to_string().contains("lock identity changed"),
        "replacement must fail closed before usage scan or key mutation: {error}"
    );
    let status = manager
        .status(Some(&root_identity))
        .expect("registry remains readable");
    assert_eq!(
        status.active_generation_id.as_deref(),
        Some(old_generation.as_str())
    );
    assert!(status.verification_generation_ids.is_empty());

    resume_tx.send(()).expect("writer resumes");
    writer
        .join()
        .expect("writer joins")
        .expect("already-held writer publishes before any retirement");
}

#[cfg(unix)]
#[test]
fn replaced_state_root_cannot_reuse_lock_inode_or_platform_authority() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let paths = RuntimePaths::from_root(root.path());
    let secret_store = Arc::new(MemorySecretStore::default());
    let initial = StateStore::open(paths.clone()).expect("initial storage opens");
    let initial_location = initial.evidence_location_identity().to_owned();
    let manager = Arc::new(
        EvidenceKeyManager::new(
            secret_store.clone(),
            initial_location.clone(),
            SecretBackend::Memory,
        )
        .expect("initial evidence manager"),
    );
    let state_root_identity = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(b"root-replacement-test-authority"))
    );
    manager
        .initialize(&state_root_identity)
        .expect("initial authority initializes");
    initial
        .initialize_evidence_root_identity(&state_root_identity)
        .expect("initial marker initializes");
    let initial = initial
        .with_evidence_authenticator(manager.clone())
        .expect("initial authority attaches");
    initial
        .write_evidence(EvidenceClass::LiveRead, &json!({"generation":"g0"}))
        .expect("g0 evidence publishes");
    let old_generation = manager
        .status(Some(&state_root_identity))
        .expect("g0 status")
        .active_generation_id
        .expect("g0 exists");
    manager
        .rotate(&state_root_identity)
        .expect("g1 becomes active");

    let displaced = root.path().join("displaced-data-root");
    fs::rename(&paths.data_dir, &displaced).expect("attacker displaces the entire data root");
    fs::create_dir_all(paths.data_dir.join("locks")).expect("replacement lock directory exists");
    fs::hard_link(
        displaced.join("locks").join("evidence-lifecycle.lock"),
        paths.data_dir.join("locks").join("evidence-lifecycle.lock"),
    )
    .expect("replacement reuses the original lock inode");
    fs::copy(
        displaced.join("evidence-root-v1.json"),
        paths.data_dir.join("evidence-root-v1.json"),
    )
    .expect("replacement copies the public root marker");

    let replacement = StateStore::open(paths.clone()).expect("replacement storage opens");
    assert_ne!(
        replacement.evidence_location_identity(),
        initial_location,
        "data-directory identity must distinguish a replacement tree even when the lock inode is reused"
    );
    let replacement_manager = Arc::new(
        EvidenceKeyManager::new(
            secret_store,
            replacement.evidence_location_identity(),
            SecretBackend::Memory,
        )
        .expect("replacement evidence manager"),
    );
    assert!(
        !replacement_manager
            .status(Some(&state_root_identity))
            .expect("replacement status is readable")
            .initialized,
        "replacement location cannot reach the original key registry"
    );
    let error = replacement
        .with_evidence_authenticator(replacement_manager)
        .expect("replacement authenticator attaches to its distinct location")
        .require_qualifying_evidence_authority()
        .expect_err("copied marker without the location-bound registry is nonqualifying");
    assert!(
        error
            .to_string()
            .contains("evidence authority are inconsistent")
    );

    let original_status = manager
        .status(Some(&state_root_identity))
        .expect("original registry remains unchanged");
    assert!(
        original_status
            .verification_generation_ids
            .contains(&old_generation),
        "the replacement tree cannot retire the original g0 generation"
    );
}

#[test]
fn body_only_audit_evidence_is_readable_nonqualifying_and_does_not_block_retirement() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let paths = RuntimePaths::from_root(root.path());
    let (store, manager) = authenticated_store_with_manager(paths.clone());
    let root_identity = store
        .evidence_root_identity()
        .expect("root reads")
        .expect("root exists");
    let old_generation = {
        let lifecycle = store
            .lock_evidence_lifecycle()
            .expect("rotation lifecycle lock");
        let old_generation = manager
            .status(Some(&root_identity))
            .expect("status")
            .active_generation_id
            .expect("active generation");
        manager.rotate(&root_identity).expect("rotation");
        drop(lifecycle);
        old_generation
    };

    let audit_store = StateStore::open(paths.clone()).expect("unqualified audit store");
    let evidence = audit_store
        .write_audit_evidence(EvidenceClass::Preview, &json!({"cancelled":true}))
        .expect("body-only audit evidence writes");
    assert!(!descriptor_path(&paths, &evidence.content_hash).exists());
    assert_eq!(
        audit_store
            .read_audit_evidence_value(&evidence.content_hash)
            .expect("audit body reads"),
        json!({"cancelled":true})
    );
    assert!(store.record_operational_proof(&proof(evidence)).is_err());

    let lifecycle = store
        .lock_evidence_lifecycle()
        .expect("retirement lifecycle lock");
    let usage = store
        .evidence_key_generation_usage(&lifecycle, &old_generation)
        .expect("body-only audit record is outside authentication usage");
    assert_eq!(usage, 0);
    manager
        .retire(&root_identity, &old_generation, usage)
        .expect("unused old generation retires");
}

#[test]
fn descriptor_authority_fields_require_authentication() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let paths = RuntimePaths::from_root(root.path());
    let store = authenticated_store(paths.clone());
    let evidence = store
        .write_evidence(EvidenceClass::LocalProof, &json!({"qualified":true}))
        .expect("evidence writes");
    assert_eq!(
        store
            .load_evidence(&evidence.content_hash)
            .expect("exact descriptor"),
        evidence
    );
    let descriptor = descriptor_path(&paths, &evidence.content_hash);
    let original = fs::read(&descriptor).expect("descriptor bytes");

    for (field, replacement) in [
        ("class", json!("apply")),
        ("generated_at", json!("2030-01-01T00:00:00Z")),
    ] {
        let mut value: Value = serde_json::from_slice(&original).expect("descriptor JSON");
        value["payload"][field] = replacement;
        fs::write(
            &descriptor,
            serde_json::to_vec_pretty(&value).expect("JSON"),
        )
        .expect("tamper descriptor");
        assert!(
            store.load_evidence(&evidence.content_hash).is_err(),
            "tampered descriptor field `{field}` must not qualify"
        );
        fs::write(&descriptor, &original).expect("restore descriptor");
    }
}

#[test]
fn authenticated_envelope_layers_reject_unknown_fields() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let paths = RuntimePaths::from_root(root.path());
    let store = authenticated_store(paths.clone());
    let evidence = store
        .write_evidence(EvidenceClass::LiveRead, &json!({"bounded":true}))
        .expect("evidence writes");
    let descriptor = descriptor_path(&paths, &evidence.content_hash);
    let original = fs::read(&descriptor).expect("descriptor bytes");

    for pointer in [
        "/unexpected",
        "/payload/unexpected",
        "/authentication/unexpected",
    ] {
        let mut value: Value = serde_json::from_slice(&original).expect("descriptor JSON");
        let (parent, field) = pointer.rsplit_once('/').expect("closed pointer");
        let object = if parent.is_empty() {
            value.as_object_mut().expect("outer object")
        } else {
            value
                .pointer_mut(parent)
                .and_then(Value::as_object_mut)
                .expect("nested object")
        };
        object.insert(field.to_owned(), json!(true));
        fs::write(
            &descriptor,
            serde_json::to_vec_pretty(&value).expect("JSON"),
        )
        .expect("inject unknown field");
        assert!(store.load_evidence(&evidence.content_hash).is_err());
        fs::write(&descriptor, &original).expect("restore descriptor");
    }
}
#[test]
fn evidence_descriptor_is_independently_addressed_and_exactly_reloadable() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let paths = RuntimePaths::from_root(root.path());
    let store = authenticated_store(paths.clone());
    let evidence = store
        .write_evidence(EvidenceClass::LiveRead, &json!({"result":{"id":"zone-1"}}))
        .expect("evidence writes");
    assert!(descriptor_path(&paths, &evidence.content_hash).is_file());
    store
        .record_operational_proof(&proof(evidence.clone()))
        .expect("qualification reloads the exact descriptor");
    assert_eq!(
        store
            .read_evidence_value(&evidence.content_hash)
            .expect("body reloads"),
        json!({"result":{"id":"zone-1"}})
    );
}

#[test]
fn descriptor_deletion_and_body_only_legacy_fail_qualification() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let paths = RuntimePaths::from_root(root.path());
    let store = authenticated_store(paths.clone());
    let evidence = store
        .write_evidence(EvidenceClass::LiveRead, &json!({"bounded":true}))
        .expect("evidence writes");
    fs::remove_file(descriptor_path(&paths, &evidence.content_hash)).expect("descriptor removed");
    assert!(
        store
            .record_operational_proof(&proof(evidence.clone()))
            .is_err()
    );
    assert!(store.read_evidence_value(&evidence.content_hash).is_err());
    assert_eq!(
        store
            .read_audit_evidence_value(&evidence.content_hash)
            .expect("body remains audit-readable"),
        json!({"bounded":true})
    );

    let legacy = EvidenceV1::new(
        EvidenceClass::LiveRead,
        &evidence.content_hash,
        &evidence.path,
    );
    assert!(matches!(
        store.record_operational_proof(&proof(legacy)),
        Err(StorageError::InvalidOperationalProof(_)
            | StorageError::UnsafeManagedDocument { .. }
            | StorageError::Io { .. })
    ));
}

#[test]
fn descriptor_tamper_and_recomputed_substitution_fail_exact_expected_identity() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let paths = RuntimePaths::from_root(root.path());
    let store = authenticated_store(paths.clone());
    let evidence = store
        .write_evidence(EvidenceClass::LiveRead, &json!({"bounded":true}))
        .expect("evidence writes");
    let path = descriptor_path(&paths, &evidence.content_hash);
    let original_bytes = fs::read(&path).expect("descriptor reads");
    let original: Value = serde_json::from_slice(&original_bytes).expect("descriptor JSON");

    for (field, replacement) in [
        ("class", json!("post_change_verification")),
        (
            "generated_at",
            json!((Utc::now() + Duration::days(30)).to_rfc3339()),
        ),
        ("path", json!("/tmp/substituted.json")),
        ("metadata", json!({"substituted":true})),
    ] {
        let mut tampered = original.clone();
        tampered["payload"][field] = replacement;
        fs::write(
            &path,
            serde_json::to_vec_pretty(&tampered).expect("tampered descriptor encodes"),
        )
        .expect("tampered descriptor writes");
        assert!(
            store
                .record_operational_proof(&proof(evidence.clone()))
                .is_err()
        );
        fs::write(&path, &original_bytes).expect("descriptor restored for next falsifier");
    }

    let mut substituted = original;
    substituted["payload"]["class"] = json!("post_change_verification");
    let substituted_bytes = serde_json::to_vec_pretty(&substituted).expect("substitution encodes");
    fs::write(&path, &substituted_bytes).expect("substituted descriptor writes");
    assert!(store.record_operational_proof(&proof(evidence)).is_err());
}

#[test]
fn coordinated_descriptor_and_proof_rewrite_cannot_manufacture_live_read_authority() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let paths = RuntimePaths::from_root(root.path());
    let store = authenticated_store(paths.clone());
    let mut evidence = store
        .write_evidence(
            EvidenceClass::PostChangeVerification,
            &json!({"same_body":"attacker_relabels_both_sides"}),
        )
        .expect("evidence writes");

    let descriptor = descriptor_path(&paths, &evidence.content_hash);
    let mut substituted: Value = serde_json::from_slice(
        &fs::read(&descriptor).expect("descriptor reads before coordinated rewrite"),
    )
    .expect("descriptor JSON");
    substituted["payload"]["class"] = json!("live_read");
    fs::write(
        &descriptor,
        serde_json::to_vec_pretty(&substituted).expect("substituted descriptor encodes"),
    )
    .expect("descriptor is replaced by the local-state attacker");
    evidence.class = EvidenceClass::LiveRead;
    let forged = proof(evidence);

    assert!(
        store.record_operational_proof(&forged).is_err(),
        "a coordinated descriptor and nested-proof rewrite must not manufacture authority"
    );

    fs::write(
        proof_path(&paths, &forged),
        serde_json::to_vec_pretty(&forged).expect("forged proof encodes"),
    )
    .expect("attacker writes a recomputed content-addressed proof row");
    assert!(store.load_operational_proof(&proof_hash(&forged)).is_err());
    assert!(store.list_operational_proofs().is_err());
    let page = store
        .list_recent_operational_proofs(10)
        .expect("recent projection preserves raw V1 classification");
    assert!(page.proofs.is_empty());
    assert_eq!(page.legacy_nonqualifying_count, 1);
    assert!(page.failures.is_empty());
}

#[test]
fn proof_envelope_rejects_rehashed_authority_substitution() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let paths = RuntimePaths::from_root(root.path());
    let store = authenticated_store(paths.clone());
    let evidence = store
        .write_evidence(EvidenceClass::LiveRead, &json!({"bounded":true}))
        .expect("evidence writes");
    let original = proof(evidence);
    store
        .record_operational_proof(&original)
        .expect("proof indexes");
    let original_path = proof_path(&paths, &original);
    let mut envelope: Value = serde_json::from_slice(
        &fs::read(&original_path).expect("authenticated proof envelope reads"),
    )
    .expect("proof envelope JSON");
    envelope["payload"]["capability_id"] = json!("zones-get");
    let forged: OperationalProofV1 =
        serde_json::from_value(envelope["payload"].clone()).expect("forged proof decodes");
    let forged_path = proof_path(&paths, &forged);
    fs::write(
        &forged_path,
        serde_json::to_vec_pretty(&envelope).expect("forged envelope encodes"),
    )
    .expect("attacker writes rehashed proof envelope");

    assert!(store.load_operational_proof(&proof_hash(&forged)).is_err());
    assert!(store.list_operational_proofs().is_err());
    let page = store
        .list_recent_operational_proofs(10)
        .expect("recent projection classifies candidate failure");
    assert_eq!(page.proofs.len(), 1);
    assert_eq!(page.proofs[0], original);
    assert_eq!(page.legacy_nonqualifying_count, 0);
    assert_eq!(page.failures.len(), 1);
    assert_eq!(page.failures[0].account_id.as_deref(), Some("account-a"));
}

#[test]
fn retirement_usage_rejects_descriptor_and_proof_generation_substitution() {
    use cfctl_auth::EvidenceMacProvider as _;

    let root = tempfile::tempdir().expect("temporary storage root");
    let paths = RuntimePaths::from_root(root.path());
    let (store, manager) = authenticated_store_with_manager(paths.clone());
    let evidence = store
        .write_evidence(EvidenceClass::LiveRead, &json!({"bounded":true}))
        .expect("evidence writes");
    let authenticated_proof = proof(evidence.clone());
    store
        .record_operational_proof(&authenticated_proof)
        .expect("proof indexes");
    let old_generation = manager
        .status(
            store
                .evidence_root_identity()
                .expect("root reads")
                .as_deref(),
        )
        .expect("status")
        .active_generation_id
        .expect("active generation");
    assert_eq!(
        generation_usage(&store, &old_generation).expect("authenticated usage scans"),
        2,
        "the descriptor and proof independently reference the signing generation"
    );
    let root_identity = store
        .evidence_root_identity()
        .expect("root reads")
        .expect("root exists");
    let rotated = manager.rotate(&root_identity).expect("rotation");
    let new_generation = rotated.active_generation_id.expect("new active generation");
    let descriptor = descriptor_path(&paths, &evidence.content_hash);
    let descriptor_bytes = fs::read(&descriptor).expect("authenticated descriptor reads");
    let mut envelope: Value = serde_json::from_slice(&descriptor_bytes).expect("descriptor JSON");
    envelope["authentication"]["key_generation_id"] = json!(new_generation);
    fs::write(
        &descriptor,
        serde_json::to_vec_pretty(&envelope).expect("substituted envelope encodes"),
    )
    .expect("attacker substitutes key generation");
    assert!(
        generation_usage(&store, &old_generation).is_err(),
        "retirement must authenticate descriptor generation metadata before counting"
    );

    fs::write(&descriptor, descriptor_bytes).expect("descriptor restores");
    let proof_path = proof_path(&paths, &authenticated_proof);
    let proof_bytes = fs::read(&proof_path).expect("authenticated proof reads");
    let mut envelope: Value = serde_json::from_slice(&proof_bytes).expect("proof JSON");
    envelope["authentication"]["key_generation_id"] = json!(new_generation);
    fs::write(
        &proof_path,
        serde_json::to_vec_pretty(&envelope).expect("substituted proof envelope encodes"),
    )
    .expect("attacker substitutes proof key generation");
    assert!(
        generation_usage(&store, &old_generation).is_err(),
        "retirement must authenticate proof generation metadata before counting"
    );

    fs::write(&proof_path, proof_bytes).expect("proof restores");
    let usage =
        generation_usage(&store, &old_generation).expect("restored authenticated usage scans");
    assert_eq!(usage, 2);
    assert!(
        manager
            .retire(&root_identity, &old_generation, usage)
            .is_err()
    );
}

#[test]
fn legacy_body_and_plain_proof_remain_readable_only_at_the_body_audit_boundary() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let paths = RuntimePaths::from_root(root.path());
    let store = StateStore::open(paths.clone()).expect("legacy-compatible storage opens");
    let evidence = store
        .write_audit_evidence(EvidenceClass::LiveRead, &json!({"legacy":true}))
        .expect("legacy body writes");
    let legacy_proof = proof(evidence.clone());
    fs::write(
        proof_path(&paths, &legacy_proof),
        serde_json::to_vec_pretty(&legacy_proof).expect("legacy proof encodes"),
    )
    .expect("legacy proof row writes");

    assert_eq!(
        store
            .read_audit_evidence_value(&evidence.content_hash)
            .expect("legacy body remains audit-readable"),
        json!({"legacy":true})
    );
    assert!(
        store
            .load_operational_proof(&proof_hash(&legacy_proof))
            .is_err()
    );
    assert!(store.list_operational_proofs().is_err());
    let page = store
        .list_recent_operational_proofs(10)
        .expect("recent projection preserves raw V1 classification");
    assert!(page.proofs.is_empty());
    assert_eq!(page.legacy_nonqualifying_count, 1);
    assert!(page.failures.is_empty());
}

#[test]
fn authenticated_state_fails_closed_after_a_canonical_root_move() {
    let parent = tempfile::tempdir().expect("temporary parent");
    let first_root = parent.path().join("first-root");
    let moved_root = parent.path().join("moved-root");
    let (store, manager) = authenticated_store_with_manager(RuntimePaths::from_root(&first_root));
    let evidence = store
        .write_evidence(EvidenceClass::LiveRead, &json!({"bounded":true}))
        .expect("evidence writes before move");
    drop(store);
    fs::rename(&first_root, &moved_root).expect("attacker moves the complete state tree");
    let moved = StateStore::open(RuntimePaths::from_root(&moved_root))
        .expect("moved tree is structurally readable");

    assert!(moved.with_evidence_authenticator(manager).is_err());
    let audit = StateStore::open(RuntimePaths::from_root(&moved_root))
        .expect("moved body audit store opens");
    assert_eq!(
        audit
            .read_audit_evidence_value(&evidence.content_hash)
            .expect("body hash remains audit-readable after move"),
        json!({"bounded":true})
    );
}

#[cfg(unix)]
#[test]
fn live_store_loses_lifecycle_and_qualification_after_data_root_replacement() {
    let root = tempfile::tempdir().expect("temporary parent");
    let paths = RuntimePaths::from_root(root.path());
    let (store, manager) = authenticated_store_with_manager(paths.clone());
    let root_identity = store
        .evidence_root_identity()
        .expect("root identity reads")
        .expect("root identity exists");
    let evidence = store
        .write_evidence(EvidenceClass::LiveRead, &json!({"generation":"g0"}))
        .expect("g0 evidence writes");
    store
        .record_operational_proof(&proof(evidence))
        .expect("g0 proof writes");
    let old_generation = manager
        .status(Some(&root_identity))
        .expect("g0 status")
        .active_generation_id
        .expect("g0 exists");
    {
        let _lifecycle = store
            .lock_evidence_lifecycle()
            .expect("rotation lifecycle lock");
        manager.rotate(&root_identity).expect("g1 becomes active");
    }
    let status_after_rotation = manager
        .status(Some(&root_identity))
        .expect("post-rotation status");

    let displaced = root.path().join("displaced-data-root");
    fs::rename(&paths.data_dir, &displaced).expect("attacker displaces the live data root");
    fs::create_dir(&paths.data_dir).expect("attacker creates replacement data root");
    let replacement = StateStore::open(paths.clone()).expect("replacement store opens");
    assert_ne!(
        replacement.evidence_location_identity(),
        store.evidence_location_identity(),
        "the replacement root must select a distinct authority"
    );

    assert!(store.lock_evidence_lifecycle().is_err());
    assert!(store.require_qualifying_evidence_authority().is_err());
    assert!(
        store
            .write_evidence(EvidenceClass::LiveRead, &json!({"after":"replacement"}))
            .is_err()
    );
    assert!(generation_usage(&store, &old_generation).is_err());
    let rotate_attempt = store
        .lock_evidence_lifecycle()
        .map(|_lifecycle| manager.rotate(&root_identity));
    assert!(
        rotate_attempt.is_err(),
        "rotation must not cross the root check"
    );
    let retire_attempt = store.lock_evidence_lifecycle().map(|lifecycle| {
        let usage = store.evidence_key_generation_usage(&lifecycle, &old_generation)?;
        manager
            .retire(&root_identity, &old_generation, usage)
            .map_err(|error| StorageError::EvidenceAuthentication(error.to_string()))
    });
    assert!(
        retire_attempt.is_err(),
        "retirement must not cross the root check"
    );
    assert_eq!(
        manager
            .status(Some(&root_identity))
            .expect("original status remains readable"),
        status_after_rotation,
        "failed displaced-root operations cannot mutate key generations"
    );
}

#[cfg(unix)]
#[test]
fn capability_created_evidence_files_are_private_under_permissive_umask() {
    const CHILD_MARKER: &str = "CFCTL_EVIDENCE_PERMISSION_TEST_CHILD";
    const TEST_NAME: &str = "capability_created_evidence_files_are_private_under_permissive_umask";

    if std::env::var_os(CHILD_MARKER).is_some() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().expect("temporary storage root");
        let paths = RuntimePaths::from_root(root.path());
        let (store, _manager) = authenticated_store_with_manager(paths.clone());
        let evidence = store
            .write_evidence(EvidenceClass::LiveRead, &json!({"private":true}))
            .expect("evidence writes");
        let operational_proof = proof(evidence.clone());
        store
            .record_operational_proof(&operational_proof)
            .expect("proof writes");

        for path in [
            paths.data_dir.join("evidence-root-v1.json"),
            std::path::PathBuf::from(&evidence.path),
            descriptor_path(&paths, &evidence.content_hash),
            proof_path(&paths, &operational_proof),
        ] {
            let mode = fs::metadata(&path)
                .expect("capability-created file metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "{} must be private", path.display());
        }
        return;
    }

    let executable = std::env::current_exe().expect("current test executable");
    let output = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg("umask 000; exec \"$1\" --exact \"$2\" --nocapture")
        .arg("cfctl-evidence-permission-test")
        .arg(executable)
        .arg(TEST_NAME)
        .env(CHILD_MARKER, "1")
        .output()
        .expect("permission child executes");
    assert!(
        output.status.success(),
        "permission child failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn operational_proof_requires_the_exact_stored_descriptor_and_proof_identity() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let paths = RuntimePaths::from_root(root.path());
    let store = authenticated_store(paths.clone());
    let evidence = store
        .write_evidence(EvidenceClass::LiveRead, &json!({"bounded":true}))
        .expect("evidence writes");
    let valid = proof(evidence.clone());
    store
        .record_operational_proof(&valid)
        .expect("proof indexes");
    let expected_hash = proof_hash(&valid);
    assert_eq!(
        store
            .load_operational_proof(&expected_hash)
            .expect("exact proof reloads"),
        valid
    );

    let mut class_substitution = valid.clone();
    class_substitution.evidence.class = EvidenceClass::PostChangeVerification;
    assert!(matches!(
        store.record_operational_proof(&class_substitution),
        Err(StorageError::InvalidOperationalProof(_))
    ));

    let mut time_substitution = valid.clone();
    time_substitution.evidence.generated_at += Duration::seconds(1);
    assert!(store.record_operational_proof(&time_substitution).is_err());

    let mut path_substitution = valid;
    path_substitution.evidence.path = "/tmp/substituted.json".to_owned();
    assert!(store.record_operational_proof(&path_substitution).is_err());
}

#[cfg(unix)]
#[test]
fn descriptor_reload_rejects_a_symlink_without_following_it() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().expect("temporary storage root");
    let paths = RuntimePaths::from_root(root.path());
    let store = authenticated_store(paths.clone());
    let evidence = store
        .write_evidence(EvidenceClass::LiveRead, &json!({"bounded":true}))
        .expect("evidence writes");
    let path = descriptor_path(&paths, &evidence.content_hash);
    let outside = root.path().join("outside.json");
    fs::write(&outside, fs::read(&path).expect("descriptor reads")).expect("outside writes");
    fs::remove_file(&path).expect("descriptor removed");
    symlink(&outside, &path).expect("descriptor symlink created");

    assert!(store.record_operational_proof(&proof(evidence)).is_err());
}

#[cfg(unix)]
#[test]
fn state_store_rejects_a_symlinked_managed_evidence_directory() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().expect("temporary storage root");
    let outside = tempfile::tempdir().expect("outside directory");
    let paths = RuntimePaths::from_root(root.path());
    fs::create_dir_all(&paths.data_dir).expect("data directory exists");
    symlink(outside.path(), paths.data_dir.join("evidence-descriptors"))
        .expect("attacker installs ancestor symlink");

    assert!(
        StateStore::open(paths).is_err(),
        "managed evidence directories must be opened as non-symlink capabilities"
    );
}

#[cfg(unix)]
#[test]
fn opened_directory_capability_fails_closed_without_following_a_later_parent_swap() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().expect("temporary storage root");
    let outside = tempfile::tempdir().expect("outside directory");
    let paths = RuntimePaths::from_root(root.path());
    let store = authenticated_store(paths.clone());
    let held = paths.data_dir.join("evidence-descriptors-held");
    fs::rename(paths.data_dir.join("evidence-descriptors"), &held)
        .expect("attacker renames managed directory after open");
    symlink(outside.path(), paths.data_dir.join("evidence-descriptors"))
        .expect("attacker replaces pathname with symlink");

    let error = store
        .write_evidence(EvidenceClass::LiveRead, &json!({"bounded":true}))
        .expect_err("qualifying publication requires the canonical held directory identity");
    assert!(
        error
            .to_string()
            .contains("managed evidence directory identity changed"),
        "publication must fail at the lifecycle boundary: {error}"
    );
    assert_eq!(
        fs::read_dir(outside.path()).expect("outside reads").count(),
        0,
        "no write follows the replacement pathname"
    );
    assert_eq!(
        fs::read_dir(held).expect("held directory reads").count(),
        0,
        "the held directory remains confined but cannot publish after canonical displacement"
    );
}

#[cfg(unix)]
fn initialized_store_for_managed_replacement(
    paths: &RuntimePaths,
    secret_store: Arc<MemorySecretStore>,
) -> (StateStore, Arc<EvidenceKeyManager>, String, String) {
    let initial = StateStore::open(paths.clone()).expect("initial storage opens");
    let manager = Arc::new(
        EvidenceKeyManager::new(
            secret_store,
            initial.evidence_location_identity(),
            SecretBackend::Memory,
        )
        .expect("initial evidence manager"),
    );
    let root_identity = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(b"managed-directory-replacement-root"))
    );
    manager
        .initialize(&root_identity)
        .expect("initial authority initializes");
    initial
        .initialize_evidence_root_identity(&root_identity)
        .expect("root marker initializes");
    let initial = initial
        .with_evidence_authenticator(manager.clone())
        .expect("initial authority attaches");
    let evidence = initial
        .write_evidence(EvidenceClass::LiveRead, &json!({"generation":"g0"}))
        .expect("g0 evidence publishes");
    initial
        .record_operational_proof(&proof(evidence))
        .expect("g0 proof publishes");
    let old_generation = manager
        .status(Some(&root_identity))
        .expect("g0 status")
        .active_generation_id
        .expect("g0 exists");
    {
        let _lifecycle = initial
            .lock_evidence_lifecycle()
            .expect("rotation lifecycle lock");
        manager.rotate(&root_identity).expect("g1 becomes active");
    }
    (initial, manager, root_identity, old_generation)
}

#[cfg(unix)]
fn assert_replaced_managed_evidence_directory_fails_closed(managed_name: &str) {
    let root = tempfile::tempdir().expect("temporary storage root");
    let paths = RuntimePaths::from_root(root.path());
    let secret_store = Arc::new(MemorySecretStore::default());
    let (initial, manager, root_identity, old_generation) =
        initialized_store_for_managed_replacement(&paths, secret_store.clone());
    let initial_location = manager.location_identity().to_owned();

    let managed_path = paths.data_dir.join(managed_name);
    let displaced = paths.data_dir.join(format!("{managed_name}-displaced"));
    fs::rename(&managed_path, &displaced).expect("attacker displaces managed evidence inventory");
    fs::create_dir(&managed_path).expect("attacker creates replacement evidence inventory");

    let replacement = StateStore::open(paths.clone()).expect("replacement storage opens");
    assert_ne!(
        replacement.evidence_location_identity(),
        initial_location,
        "a replacement managed directory must select a distinct platform authority"
    );
    assert!(
        replacement
            .clone()
            .with_evidence_authenticator(manager.clone())
            .is_err(),
        "the replacement inventory cannot attach the displaced inventory's authority"
    );
    let lifecycle_error = initial
        .lock_evidence_lifecycle()
        .expect_err("the displaced store cannot regain lifecycle authority");
    assert!(
        lifecycle_error
            .to_string()
            .contains("managed evidence directory identity changed"),
        "lifecycle denial must identify the replaced managed directory: {lifecycle_error}"
    );

    let replacement_manager = Arc::new(
        EvidenceKeyManager::new(
            secret_store,
            replacement.evidence_location_identity(),
            SecretBackend::Memory,
        )
        .expect("replacement evidence manager"),
    );
    let replacement_status = replacement_manager
        .status(Some(&root_identity))
        .expect("replacement status remains readable");
    assert!(
        !replacement_status.initialized,
        "the replacement store cannot discover the displaced authority"
    );
    assert!(replacement_manager.rotate(&root_identity).is_err());
    assert!(
        replacement_manager
            .retire(&root_identity, &old_generation, 0)
            .is_err(),
        "the replacement manager cannot delete a displaced verification generation"
    );
    assert_eq!(
        fs::read_dir(&displaced)
            .expect("displaced inventory reads")
            .count(),
        1,
        "the original authenticated descriptor remains present"
    );
    let original_status = manager
        .status(Some(&root_identity))
        .expect("original authority remains readable");
    assert!(
        original_status
            .verification_generation_ids
            .contains(&old_generation),
        "the displaced descriptor's verification key remains preserved"
    );
}

#[cfg(unix)]
#[test]
fn replaced_managed_evidence_directory_cannot_share_authority_or_retire_displaced_usage() {
    for managed_name in ["evidence", "evidence-descriptors", "evidence-index"] {
        assert_replaced_managed_evidence_directory_fails_closed(managed_name);
    }
}

#[test]
fn ordinary_body_deduplication_and_redaction_remain_compatible() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let store = authenticated_store(RuntimePaths::from_root(root.path()));
    let first = store
        .write_evidence(
            EvidenceClass::LiveRead,
            &json!({"result":{"id":"zone-1"},"access_token":"first-secret"}),
        )
        .expect("first evidence writes");
    let second = store
        .write_evidence(
            EvidenceClass::LiveRead,
            &json!({"result":{"id":"zone-1"},"access_token":"second-secret"}),
        )
        .expect("second evidence writes");

    assert_eq!(first.content_hash, second.content_hash);
    assert_eq!(first.path, second.path);
    assert_eq!(first, second);
    let stored = fs::read_to_string(Path::new(&first.path)).expect("body reads");
    assert!(!stored.contains("first-secret"));
    assert!(!stored.contains("second-secret"));
    assert!(stored.contains("[REDACTED]"));
}

#[test]
fn exact_resource_locks_serialize_only_their_owned_targets() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let account = "a".repeat(32);
    let zone = "b".repeat(32);

    let worker = store
        .lock_worker_deployment(&account, "jkca-web-drop")
        .expect("first Worker target lock");
    assert!(matches!(
        store.lock_worker_deployment(&account, "jkca-web-drop"),
        Err(StorageError::WorkerDeploymentLocked { .. })
    ));
    assert!(
        store
            .lock_worker_deployment(&account, "jkca-web-sign")
            .is_ok()
    );
    drop(worker);
    assert!(
        store
            .lock_worker_deployment(&account, "jkca-web-drop")
            .is_ok()
    );

    let routing = store
        .lock_email_routing_catch_all(&account, &zone)
        .expect("first Email Routing target lock");
    assert!(matches!(
        store.lock_email_routing_catch_all(&account, &zone),
        Err(StorageError::EmailRoutingCatchAllLocked { .. })
    ));
    assert!(
        store
            .lock_email_routing_catch_all(&account, &"c".repeat(32))
            .is_ok()
    );
    drop(routing);
    assert!(store.lock_email_routing_catch_all(&account, &zone).is_ok());
    assert!(
        store
            .lock_email_routing_catch_all(&account, "not-a-zone-id")
            .is_err()
    );
}
