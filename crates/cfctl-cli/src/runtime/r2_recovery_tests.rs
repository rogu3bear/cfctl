#![allow(clippy::expect_used, clippy::unwrap_used)]
use super::{CallInput, StateStore, json, verify, verify_private_files};
use cfctl_core::r2_recovery::{CaptureManifestV1, CaptureWindowV1, CapturedObjectV1};
use cfctl_storage::{PrivateDirectory, RuntimePaths};
use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};

#[test]
fn replaced_capture_parent_is_rejected_before_creating_a_child() {
    let root = tempfile::tempdir_in("/private/tmp").expect("root");
    let parent_path = root.path().join("custody");
    let parent = PrivateDirectory::create(&parent_path).expect("parent");
    fs::rename(&parent_path, root.path().join("displaced-custody")).expect("replace parent");
    PrivateDirectory::create(&parent_path).expect("replacement");
    assert!(parent.create_new_directory("snapshot").is_err());
    assert!(!parent_path.join("snapshot").exists());
    assert!(!root.path().join("displaced-custody/snapshot").exists());
}

#[test]
fn replaced_parent_after_creation_blocks_private_capture_writes() {
    use cfctl_cloudflare::r2_recovery::CaptureFiles;
    let root = tempfile::tempdir_in("/private/tmp").expect("root");
    let parent_path = root.path().join("custody");
    let parent = PrivateDirectory::create(&parent_path).expect("parent");
    let child = parent.create_new_directory("snapshot").expect("child");
    let files = super::CaptureDirectory(child, parent);
    fs::rename(&parent_path, root.path().join("old-custody")).expect("replace parent");
    PrivateDirectory::create(&parent_path).expect("replacement");
    assert!(files.create_new("object-0000.bin").is_err());
    assert!(files.sync().is_err());
}

#[test]
fn equivalent_window_encodings_produce_the_same_proof_input() {
    let root = tempfile::tempdir_in("/private/tmp").expect("root");
    let mut snapshot = cfctl_catalog::CatalogSnapshot {
        schema_version: 1,
        generated_at: Utc::now(),
        source_url: "fixture".into(),
        source_hash: String::new(),
        schema_hash: String::new(),
        capabilities: std::collections::BTreeMap::new(),
    };
    cfctl_catalog::ingest_native_control_capabilities(&mut snapshot).expect("catalog");
    let cap = snapshot
        .get(cfctl_core::r2_recovery::CAPTURE_ID)
        .expect("capture");
    let window = CaptureWindowV1 {
        window_id: uuid::Uuid::new_v4().to_string(),
        opened_at: Utc::now() - Duration::seconds(2),
        expires_at: Utc::now() + Duration::seconds(60),
        recovery_binding_sha256: "a".repeat(64),
    };
    let offset = chrono::FixedOffset::west_opt(5 * 3600).expect("offset");
    let mut body = serde_json::to_value(&window).expect("window");
    body["opened_at"] = json!(window.opened_at.with_timezone(&offset).to_rfc3339());
    body["expires_at"] = json!(window.expires_at.with_timezone(&offset).to_rfc3339());
    let input = CallInput {
        selectors: json!({"account_id":"a".repeat(32),"bucket_name":"private-pdfs"}),
        query: json!({}),
        body: Some(body),
        ..CallInput::default()
    };
    let canonical = super::preflight_capture(cap, &input, &root.path().join("new-snapshot"))
        .expect("normalized window");
    assert_eq!(
        serde_json::to_value(canonical).expect("canonical body"),
        serde_json::to_value(window).expect("receipt body")
    );
}
use std::{
    fs,
    io::Write,
    os::unix::fs::{PermissionsExt, symlink},
};

fn fixture(directory: &PrivateDirectory) -> cfctl_core::r2_recovery::CaptureReceiptV1 {
    let now = Utc::now();
    let manifest = CaptureManifestV1 {
        schema_version: 1,
        run_id: uuid::Uuid::new_v4().to_string(),
        account_id: "a".repeat(32),
        bucket_name: "private-pdfs".into(),
        window: CaptureWindowV1 {
            window_id: uuid::Uuid::new_v4().to_string(),
            opened_at: now - Duration::seconds(2),
            expires_at: now + Duration::seconds(60),
            recovery_binding_sha256: "b".repeat(64),
        },
        started_at: now - Duration::seconds(1),
        completed_at: now,
        list_pages: 2,
        total_bytes: 4,
        objects: vec![CapturedObjectV1 {
            provider_metadata: json!({"key":"docs/private","size":4,"etag":"one","last_modified":"2026-09-07T00:00:00Z","storage_class":"Standard"}),
            blob: "object-0000.bin".into(),
            sha256: hex::encode(Sha256::digest(b"%PDF")),
            byte_count: 4,
        }],
    };
    directory
        .create_new_file("object-0000.bin")
        .expect("blob")
        .write_all(b"%PDF")
        .expect("bytes");
    let encoded = serde_json::to_vec(&manifest).expect("manifest");
    directory
        .create_new_file("manifest.json")
        .expect("file")
        .write_all(&encoded)
        .expect("manifest bytes");
    manifest.receipt(hex::encode(Sha256::digest(encoded)))
}

#[test]
fn same_private_files_detect_tampering_links_and_permissions() {
    for mode in ["tamper", "metadata", "symlink", "hardlink", "permissions"] {
        let root = tempfile::tempdir_in("/private/tmp").expect("root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private root");
        let directory = PrivateDirectory::open(root.path()).expect("directory");
        let receipt = fixture(&directory);
        verify_private_files(&directory, &receipt).expect("intact");
        let path = root.path().join("object-0000.bin");
        match mode {
            "tamper" => fs::write(&path, b"evil").expect("tamper"),
            "metadata" => {
                let manifest_path = root.path().join("manifest.json");
                let mut manifest: serde_json::Value =
                    serde_json::from_slice(&fs::read(&manifest_path).expect("manifest"))
                        .expect("decode");
                manifest["objects"][0]["provider_metadata"]["http_metadata"] =
                    json!({"contentType":"application/pdf"});
                fs::write(
                    manifest_path,
                    serde_json::to_vec(&manifest).expect("tampered manifest"),
                )
                .expect("replace manifest");
            }
            "symlink" => {
                fs::rename(&path, root.path().join("private-value")).expect("move");
                symlink("private-value", &path).expect("symlink");
            }
            "hardlink" => fs::hard_link(&path, root.path().join("alias")).expect("hardlink"),
            _ => {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("permissions");
            }
        }
        assert!(verify_private_files(&directory, &receipt).is_err());
    }
}

#[test]
fn self_authored_manifest_is_not_provider_capture_authority() {
    let root = tempfile::tempdir_in("/private/tmp").expect("root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("store");
    let mut snapshot = cfctl_catalog::CatalogSnapshot {
        schema_version: 1,
        generated_at: Utc::now(),
        source_url: "fixture".into(),
        source_hash: String::new(),
        schema_hash: String::new(),
        capabilities: std::collections::BTreeMap::new(),
    };
    cfctl_catalog::ingest_native_control_capabilities(&mut snapshot).expect("catalog");
    let capability = snapshot
        .get(cfctl_core::r2_recovery::VERIFY_ID)
        .expect("verify capability");
    let input = CallInput {
        selectors: json!({"account_id":"a".repeat(32),"bucket_name":"private-pdfs"}),
        query: json!({}),
        body: Some(
            json!({"capture_evidence_hash":format!("sha256:{}","c".repeat(64)),"capture_run_id":uuid::Uuid::new_v4().to_string()}),
        ),
        ..CallInput::default()
    };
    assert!(verify(&store, capability, &input, root.path()).is_err());
}

#[test]
fn native_capture_provenance_joins_exact_target_window_and_private_files() {
    use cfctl_auth::{EvidenceKeyManager, MemorySecretStore, SecretBackend};
    use cfctl_core::{
        EvidenceClass, OperationalProofOutcomeV1, OperationalProofScopeV1, OperationalProofV1,
        hash_value,
    };
    use std::sync::Arc;
    let root = tempfile::tempdir_in("/private/tmp").expect("root");
    let initial = StateStore::open(RuntimePaths::from_root(root.path())).expect("store");
    let manager = Arc::new(
        EvidenceKeyManager::new(
            Arc::new(MemorySecretStore::default()),
            initial.evidence_location_identity(),
            SecretBackend::Memory,
        )
        .expect("evidence manager"),
    );
    let identity = format!("sha256:{}", "a".repeat(64));
    manager.initialize(&identity).expect("key");
    initial
        .initialize_evidence_root_identity(&identity)
        .expect("root identity");
    let store = initial
        .with_evidence_authenticator(manager)
        .expect("authenticated store");
    let private_path = root.path().join("snapshot");
    let directory = PrivateDirectory::create(&private_path).expect("snapshot");
    let receipt = fixture(&directory);
    let mut snapshot = cfctl_catalog::CatalogSnapshot {
        schema_version: 1,
        generated_at: Utc::now(),
        source_url: "fixture".into(),
        source_hash: String::new(),
        schema_hash: String::new(),
        capabilities: std::collections::BTreeMap::new(),
    };
    cfctl_catalog::ingest_native_control_capabilities(&mut snapshot).expect("catalog");
    let capability = snapshot
        .get(cfctl_core::r2_recovery::VERIFY_ID)
        .expect("verify capability");
    let original = CallInput {
        selectors: json!({"account_id":receipt.account_id,"bucket_name":receipt.bucket_name}),
        query: json!({}),
        body: Some(serde_json::to_value(&receipt.window).expect("window")),
        ..CallInput::default()
    };
    let evidence = store
        .write_evidence(
            EvidenceClass::LiveRead,
            &json!({"status":200,"success":true,"result":receipt}),
        )
        .expect("authenticated evidence");
    let mut input = CallInput {
        selectors: original.selectors.clone(),
        query: json!({}),
        body: Some(
            json!({"capture_evidence_hash":evidence.content_hash,"capture_run_id":receipt.run_id}),
        ),
        ..CallInput::default()
    };
    // A descriptor alone is insufficient: require native execution provenance.
    assert!(verify(&store, capability, &input, &private_path).is_err());
    let mut proof = OperationalProofV1::new(
        Utc::now(),
        cfctl_core::r2_recovery::CAPTURE_ID,
        &snapshot.schema_hash,
        &hash_value(&serde_json::to_value(&original).expect("original input")).expect("input hash"),
        OperationalProofScopeV1::new(
            Some("fixture-profile"),
            Some(&receipt.account_id),
            Some("11111111-1111-4111-8111-111111111111"),
        ),
        OperationalProofOutcomeV1::Succeeded,
        evidence,
    );
    proof
        .bind_build_identity_hash(&format!("sha256:{}", "d".repeat(64)))
        .expect("build");
    store
        .record_operational_proof(&proof)
        .expect("native execution proof");
    let verified =
        verify(&store, capability, &input, &private_path).expect("authenticated private capture");
    assert_eq!(verified.result["recovery_ready"], false);
    assert_eq!(verified.result["conditional_restore_qualified"], false);
    input.selectors["bucket_name"] = json!("another-bucket");
    assert!(verify(&store, capability, &input, &private_path).is_err());
    input.selectors = original.selectors;
    fs::write(private_path.join("object-0000.bin"), b"evil").expect("change captured bytes");
    assert!(verify(&store, capability, &input, &private_path).is_err());
}
