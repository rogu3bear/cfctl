#![allow(clippy::expect_used, clippy::unwrap_used)]

use cfctl_core::{
    AdmissionPolicyBundleStatusV1, AdmissionPolicyBundleV1, AdmissionPolicyRuleV1, CapabilityV1,
    EvidenceClass, Mln0142GovernedExecutionBindingV1, Mln0143GovernedExecutionBindingV1,
    OperationalProofOutcomeV1, OperationalProofScopeV1, OperationalProofV1, PlanStatus, PlanV1,
    PolicyDisposition, StandingAuthorityStatus, StandingAuthorityV1, TransactionStageV1,
    hash_value,
};
use cfctl_storage::{RuntimePaths, StateStore, StorageError, StoredPlanRecord};
use chrono::{Duration, Utc};
use serde_json::json;
use sha2::{Digest as _, Sha256};

fn sha256(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

const GENERATION_A: &str = "11111111-1111-4111-8111-111111111111";

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

fn admission_bundle(name: &str) -> AdmissionPolicyBundleV1 {
    AdmissionPolicyBundleV1::pending(
        name,
        vec![AdmissionPolicyRuleV1 {
            rule_id: format!("block-{name}"),
            capability_id: Some(format!("capability-{name}")),
            product: None,
            effect: None,
            risk: None,
            disposition: PolicyDisposition::Blocked,
            reason: format!("{name} is locally blocked"),
        }],
    )
    .expect("admission bundle")
}

#[test]
fn admission_bundles_are_create_only_and_activation_uses_a_hash_bound_pointer() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let paths = RuntimePaths::from_root(root.path());
    let store = StateStore::open(paths.clone()).expect("storage opens");
    let bundle = admission_bundle("one");

    store
        .create_admission_bundle(&bundle)
        .expect("pending bundle stages once");
    assert!(matches!(
        store.create_admission_bundle(&bundle),
        Err(StorageError::AdmissionBundleAlreadyExists(id)) if id == bundle.bundle_id
    ));
    assert!(
        store
            .approve_admission_bundle(&bundle.bundle_id, false)
            .is_err()
    );
    assert_eq!(
        store
            .load_admission_bundle(&bundle.bundle_id)
            .expect("pending bundle remains")
            .status,
        AdmissionPolicyBundleStatusV1::Pending
    );
    store
        .approve_admission_bundle(&bundle.bundle_id, true)
        .expect("explicit approval persists");
    let activation = store
        .activate_admission_bundle(&bundle.bundle_id)
        .expect("approved bundle activates");
    assert_eq!(activation.previous_bundle_id, None);
    assert_eq!(
        store
            .active_admission_policy()
            .expect("active pointer validates")
            .expect("active bundle")
            .content_hash,
        bundle.content_hash
    );

    store
        .write_json(
            &paths.config_dir.join("policy/admission/active.json"),
            &json!({
                "schema_version":1,
                "bundle_id":bundle.bundle_id,
                "content_hash":"sha256:drift"
            }),
        )
        .expect("tamper pointer fixture");
    assert!(matches!(
        store.active_admission_policy(),
        Err(StorageError::InvalidAdmissionPointer(_))
    ));
}

#[test]
fn concurrent_admission_activation_serializes_to_one_active_bundle() {
    use std::sync::{Arc, Barrier};

    let root = tempfile::tempdir().expect("temporary storage root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("storage opens");
    let first = admission_bundle("first");
    let second = admission_bundle("second");
    for bundle in [&first, &second] {
        store
            .create_admission_bundle(bundle)
            .expect("bundle stages");
        store
            .approve_admission_bundle(&bundle.bundle_id, true)
            .expect("bundle approves");
    }
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for bundle_id in [first.bundle_id.clone(), second.bundle_id.clone()] {
        let store = store.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            store.activate_admission_bundle(&bundle_id)
        }));
    }
    barrier.wait();
    for handle in handles {
        handle
            .join()
            .expect("activation thread joins")
            .expect("serialized activation succeeds");
    }

    let active = store
        .active_admission_policy()
        .expect("active pointer validates")
        .expect("one active bundle");
    let bundles = store.list_admission_bundles().expect("bundles list");
    assert_eq!(
        bundles
            .iter()
            .filter(|bundle| bundle.status == AdmissionPolicyBundleStatusV1::Active)
            .count(),
        1
    );
    assert!(
        matches!(active.bundle_id.as_str(), id if id == first.bundle_id || id == second.bundle_id)
    );
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
fn evidence_reload_revalidates_the_content_hash() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("storage opens");
    let value = json!({"capability_id":"mln-0143-data-invariants","complete":true});
    let evidence = store
        .write_evidence(EvidenceClass::LiveRead, &value)
        .expect("evidence writes");
    assert_eq!(
        store
            .read_evidence_value(&evidence.content_hash)
            .expect("verified evidence reload"),
        value
    );
    assert!(store.read_evidence_value("sha256:not-a-digest").is_err());
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
        OperationalProofScopeV1::new(Some("default"), Some("account-a"), Some(GENERATION_A)),
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
        OperationalProofScopeV1::new(None, None, None),
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
        OperationalProofScopeV1::new(Some("profile-a"), Some("account-a"), Some(GENERATION_A)),
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
        OperationalProofScopeV1::new(Some("profile-a"), Some("account-a"), Some(GENERATION_A)),
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
        OperationalProofScopeV1::new(Some("  "), Some("account-a"), Some(GENERATION_A)),
        OperationalProofOutcomeV1::Succeeded,
        evidence.clone(),
    );
    assert!(matches!(
        store.record_operational_proof(&empty_scope),
        Err(StorageError::InvalidOperationalProof(_))
    ));

    let unbound = OperationalProofV1::new(
        Utc::now(),
        "zones-list",
        &sha256('a'),
        &sha256('b'),
        OperationalProofScopeV1::new(Some("profile-a"), Some("account-a"), None),
        OperationalProofOutcomeV1::Succeeded,
        evidence,
    );
    assert!(matches!(
        store.record_operational_proof(&unbound),
        Err(StorageError::InvalidOperationalProof(message))
            if message.contains("credential-generation")
    ));
}

#[test]
fn mln_0143_operational_proof_requires_exact_completed_runtime_binding() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("storage opens");
    let observed_at = Utc::now();
    let evidence = store
        .write_evidence(
            EvidenceClass::LiveRead,
            &json!({"result":{"complete":true}}),
        )
        .expect("evidence writes");
    let valid_binding = Mln0143GovernedExecutionBindingV1 {
        schema_version: 1,
        operation_id: "22222222-2222-4222-8222-222222222222".to_owned(),
        capability_id: "mln-0143-data-invariants".to_owned(),
        capability_version: 3,
        validator_contract_hash: sha256('c'),
        fixed_query_sha256: sha256('d'),
        catalog_hash: sha256('a'),
        target_scope_hash: sha256('e'),
        phase: "pre_import".to_owned(),
        manifest_evidence_hash: evidence.content_hash.clone(),
        request_hash: sha256('b'),
        profile_identity_hash: hash_value(&json!({
            "profile_id":"profile-a",
            "credential_generation_id":GENERATION_A,
        }))
        .expect("profile identity hash"),
        credential_generation_id: GENERATION_A.to_owned(),
        completion_status: "completed".to_owned(),
        completed_at: observed_at,
        cross_operation_lineage_hash: None,
    };
    let build = |binding: Mln0143GovernedExecutionBindingV1| {
        let mut proof = OperationalProofV1::new(
            observed_at,
            "mln-0143-data-invariants",
            &sha256('a'),
            &sha256('b'),
            OperationalProofScopeV1::new(Some("profile-a"), Some("account-a"), Some(GENERATION_A)),
            OperationalProofOutcomeV1::Succeeded,
            evidence.clone(),
        );
        proof
            .bind_mln_0143_governed_execution(binding)
            .map(|()| proof)
    };
    store
        .record_operational_proof(&build(valid_binding.clone()).expect("valid binding"))
        .expect("valid governed proof indexes");

    let mut invalid_bindings = Vec::new();
    for mutate in [
        |binding: &mut Mln0143GovernedExecutionBindingV1| {
            binding.operation_id = "not-an-operation".to_owned();
        },
        |binding: &mut Mln0143GovernedExecutionBindingV1| {
            binding.capability_id = "zones-list".to_owned();
        },
        |binding: &mut Mln0143GovernedExecutionBindingV1| {
            binding.request_hash = sha256('9');
        },
        |binding: &mut Mln0143GovernedExecutionBindingV1| {
            binding.credential_generation_id = "33333333-3333-4333-8333-333333333333".to_owned();
        },
        |binding: &mut Mln0143GovernedExecutionBindingV1| {
            binding.target_scope_hash = "not-a-hash".to_owned();
        },
        |binding: &mut Mln0143GovernedExecutionBindingV1| {
            binding.phase = "during_import".to_owned();
        },
        |binding: &mut Mln0143GovernedExecutionBindingV1| {
            binding.validator_contract_hash = "not-a-hash".to_owned();
        },
        |binding: &mut Mln0143GovernedExecutionBindingV1| {
            binding.fixed_query_sha256 = "not-a-hash".to_owned();
        },
        |binding: &mut Mln0143GovernedExecutionBindingV1| {
            binding.manifest_evidence_hash = sha256('8');
        },
        |binding: &mut Mln0143GovernedExecutionBindingV1| {
            binding.profile_identity_hash = sha256('7');
        },
        |binding: &mut Mln0143GovernedExecutionBindingV1| {
            binding.completion_status = "started".to_owned();
        },
        |binding: &mut Mln0143GovernedExecutionBindingV1| {
            binding.completed_at += Duration::seconds(1);
        },
    ] {
        let mut binding = valid_binding.clone();
        mutate(&mut binding);
        invalid_bindings.push(binding);
    }
    for binding in invalid_bindings {
        if let Ok(proof) = build(binding) {
            assert!(matches!(
                store.record_operational_proof(&proof),
                Err(StorageError::InvalidOperationalProof(_))
            ));
        }
    }
}

#[test]
fn mln_0142_operational_proof_rejects_synthetic_or_drifted_authority() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("storage opens");
    let observed_at = Utc::now();
    let evidence = store
        .write_evidence(EvidenceClass::LiveRead, &json!({"present":true}))
        .expect("evidence writes");
    let valid = Mln0142GovernedExecutionBindingV1 {
        schema_version: 1,
        operation_id: "22222222-2222-4222-8222-222222222222".to_owned(),
        capability_id: "mln-0142-post-import-schema".to_owned(),
        capability_version: 1,
        catalog_hash: sha256('a'),
        target_scope_hash: sha256('b'),
        import_operation_id: "33333333-3333-4333-8333-333333333333".to_owned(),
        import_boundary_evidence_hash: sha256('c'),
        import_source_sha256: sha256('d'),
        import_plan_hash: sha256('e'),
        final_bookmark_hash: sha256('f'),
        trigger_name: "document_render_jobs_terminal_generation_guard".to_owned(),
        trigger_definition_sha256:
            "sha256:cb32c4ed1b14799465b90693ac73cf03d4650c3db573f080acc3d3b4cc436c2b".to_owned(),
        manifest_evidence_hash: evidence.content_hash.clone(),
        request_hash: sha256('1'),
        credential_generation_id: GENERATION_A.to_owned(),
        completion_status: "completed".to_owned(),
        completed_at: observed_at,
    };
    let build = |binding: Mln0142GovernedExecutionBindingV1| {
        let mut proof = OperationalProofV1::new(
            observed_at,
            "mln-0142-post-import-schema",
            &sha256('a'),
            &sha256('1'),
            OperationalProofScopeV1::new(Some("profile-a"), Some("account-a"), Some(GENERATION_A)),
            OperationalProofOutcomeV1::Succeeded,
            evidence.clone(),
        );
        proof
            .bind_mln_0142_governed_execution(binding)
            .map(|()| proof)
    };
    store
        .record_operational_proof(&build(valid.clone()).expect("valid binding"))
        .expect("valid proof indexes");
    for mutate in [
        |binding: &mut Mln0142GovernedExecutionBindingV1| {
            binding.import_source_sha256 = "not-a-hash".to_owned();
        },
        |binding: &mut Mln0142GovernedExecutionBindingV1| {
            binding.import_plan_hash = "not-a-hash".to_owned();
        },
        |binding: &mut Mln0142GovernedExecutionBindingV1| {
            binding.target_scope_hash = "not-a-hash".to_owned();
        },
        |binding: &mut Mln0142GovernedExecutionBindingV1| {
            binding.trigger_definition_sha256 = sha256('9');
        },
    ] {
        let mut binding = valid.clone();
        mutate(&mut binding);
        if let Ok(proof) = build(binding) {
            assert!(matches!(
                store.record_operational_proof(&proof),
                Err(StorageError::InvalidOperationalProof(_))
            ));
        }
    }
    let synthetic = OperationalProofV1::new(
        observed_at,
        "mln-0142-post-import-schema",
        &sha256('a'),
        &sha256('1'),
        OperationalProofScopeV1::new(Some("profile-a"), Some("account-a"), Some(GENERATION_A)),
        OperationalProofOutcomeV1::Succeeded,
        evidence,
    );
    assert!(matches!(
        store.record_operational_proof(&synthetic),
        Err(StorageError::InvalidOperationalProof(_))
    ));
}

#[test]
fn d1_import_checkpoints_are_append_only_hash_bound_and_operation_scoped() {
    let root = tempfile::tempdir().expect("runtime root");
    let paths = RuntimePaths::from_root(root.path());
    let store = StateStore::open(paths.clone()).expect("store");
    let operation_id = "11111111-1111-4111-8111-111111111111";
    let first = json!({
        "schema_version":1,
        "operation_id":operation_id,
        "step":"init_response",
        "performed":true,
        "rectification_required":false,
        "receipt":{"upload_url_sha256":format!("sha256:{}", "a".repeat(64))}
    });
    let second = json!({
        "schema_version":1,
        "operation_id":operation_id,
        "step":"provider_complete",
        "performed":true,
        "rectification_required":false,
        "receipt":{"state":"provider_complete"}
    });
    let first_hash = store
        .record_d1_import_checkpoint(operation_id, &first)
        .expect("first checkpoint");
    let second_hash = store
        .record_d1_import_checkpoint(operation_id, &second)
        .expect("second checkpoint");
    let checkpoints = store
        .read_d1_import_checkpoints(operation_id)
        .expect("checkpoint journal");
    assert_eq!(checkpoints, [(first_hash, first), (second_hash, second)]);

    let checkpoint_path = paths
        .data_dir
        .join("d1-import-checkpoints")
        .join(operation_id)
        .read_dir()
        .expect("checkpoint directory")
        .next()
        .expect("checkpoint entry")
        .expect("checkpoint path")
        .path();
    std::fs::write(&checkpoint_path, b"{}").expect("tamper checkpoint");
    assert!(
        store.read_d1_import_checkpoints(operation_id).is_err(),
        "tampered checkpoint bytes fail closed"
    );
    assert!(
        store
            .record_d1_import_checkpoint(
                operation_id,
                &json!({"schema_version":1,"operation_id":"22222222-2222-4222-8222-222222222222","step":"poll"})
            )
            .is_err(),
        "a checkpoint cannot be grafted across operations"
    );
}

#[test]
fn legacy_unbound_operational_proof_remains_readable_but_cannot_be_rewritten() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let paths = RuntimePaths::from_root(root.path());
    let store = StateStore::open(paths.clone()).expect("storage opens");
    let evidence = store
        .write_evidence(EvidenceClass::LiveRead, &json!({"bounded": true}))
        .expect("evidence writes");
    let legacy = OperationalProofV1::new(
        Utc::now(),
        "zones-list",
        &sha256('a'),
        &sha256('b'),
        OperationalProofScopeV1::new(Some("profile-a"), Some("account-a"), None),
        OperationalProofOutcomeV1::Succeeded,
        evidence,
    );
    let encoded = serde_json::to_vec_pretty(&legacy).expect("legacy row encodes");
    let digest = hex::encode(Sha256::digest(&encoded));
    std::fs::write(
        paths
            .data_dir
            .join("evidence-index")
            .join(format!("{digest}.json")),
        encoded,
    )
    .expect("legacy index row writes");

    assert_eq!(
        store.list_operational_proofs().expect("legacy row reads"),
        vec![legacy.clone()]
    );
    assert!(matches!(
        store.record_operational_proof(&legacy),
        Err(StorageError::InvalidOperationalProof(message))
            if message.contains("credential-generation")
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
            OperationalProofScopeV1::new(Some("profile-a"), Some("account-a"), Some(GENERATION_A)),
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
        OperationalProofScopeV1::new(Some("profile-a"), Some("account-a"), Some(GENERATION_A)),
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
                OperationalProofScopeV1::new(
                    Some("profile-a"),
                    Some("account-a"),
                    Some(GENERATION_A),
                ),
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
        .register_workspace(workspace.path(), None)
        .expect("register root");
    let roots = store.workspace_roots().expect("read roots");
    assert_eq!(
        roots,
        vec![workspace.path().canonicalize().expect("canonical root")]
    );
}

#[test]
fn workspace_manifest_migrates_legacy_roots_and_account_pins_once() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let workspace = tempfile::tempdir().expect("workspace root");
    let paths = RuntimePaths::from_root(root.path());
    let store = StateStore::open(paths.clone()).expect("storage opens");
    let canonical = workspace.path().canonicalize().expect("canonical root");
    store
        .write_json(
            &paths.config_dir.join("workspace-roots.json"),
            &vec![canonical.clone()],
        )
        .expect("legacy roots write");
    store
        .write_json(
            &paths.config_dir.join("workspace-accounts.json"),
            &std::collections::BTreeMap::from([(canonical.clone(), "account-a")]),
        )
        .expect("legacy pins write");

    let manifest = store.workspace_manifest().expect("legacy state migrates");
    assert_eq!(manifest.roots(), vec![canonical.clone()]);
    assert_eq!(
        manifest.account_pins(),
        std::collections::BTreeMap::from([(canonical, "account-a".to_owned())])
    );
    assert!(
        paths
            .config_dir
            .join("workspace-manifest-v1.json")
            .is_file()
    );
}

#[test]
fn workspace_registration_updates_root_and_account_pin_atomically() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let workspace_a = tempfile::tempdir().expect("workspace a");
    let workspace_b = tempfile::tempdir().expect("workspace b");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("storage opens");
    let store_a = store.clone();
    let path_a = workspace_a.path().to_path_buf();
    let write_a = std::thread::spawn(move || {
        store_a
            .register_workspace(&path_a, Some("account-a".to_owned()))
            .expect("register workspace a");
    });
    let store_b = store.clone();
    let path_b = workspace_b.path().to_path_buf();
    let write_b = std::thread::spawn(move || {
        store_b
            .register_workspace(&path_b, Some("account-b".to_owned()))
            .expect("register workspace b");
    });
    write_a.join().expect("workspace a writer joins");
    write_b.join().expect("workspace b writer joins");

    let manifest = store.workspace_manifest().expect("manifest reads");
    let pins = manifest.account_pins();
    let canonical_a = workspace_a.path().canonicalize().expect("canonical a");
    let canonical_b = workspace_b.path().canonicalize().expect("canonical b");
    assert_eq!(
        pins.get(&canonical_a).map(String::as_str),
        Some("account-a")
    );
    assert_eq!(
        pins.get(&canonical_b).map(String::as_str),
        Some("account-b")
    );

    let (_, removed, account_pin_removed) = store
        .unregister_workspace(&canonical_a)
        .expect("workspace removal");
    assert!(removed);
    assert!(account_pin_removed);
    let manifest = store.workspace_manifest().expect("manifest rereads");
    assert!(!manifest.roots().contains(&canonical_a));
    assert!(!manifest.account_pins().contains_key(&canonical_a));
}

#[test]
fn plan_v2_sidecar_tracks_forward_plan_state_while_plan_v1_history_remains_readable() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("storage opens");
    let capability = CapabilityV1::new("workers-list", "List", "GET", "/accounts/a/workers");
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "sha256:catalog",
        capability,
        json!({"account_id":"account-a"}),
    )
    .expect("plan");
    store.save_plan(&plan).expect("plan v1 stores");
    assert!(!store.has_plan_v2(&plan.operation_id).expect("v2 check"));
    assert_eq!(store.load_plan(&plan.operation_id).expect("v1 reads"), plan);

    let plan_v2 = cfctl_core::PlanV2::new(
        plan.clone(),
        cfctl_core::PlanPinsV2 {
            build_identity_hash: "sha256:build".to_owned(),
            catalog_hash: plan.catalog_hash.clone(),
            credential_generation_id: "generation-a".to_owned(),
            admission_policy_hash: "sha256:policy".to_owned(),
            authority_hash: None,
            workspace_graph_hash: "sha256:workspace".to_owned(),
            resource_observation_hashes: std::collections::BTreeMap::default(),
            cost_budget: None,
        },
    )
    .expect("plan v2");
    store.save_plan_v2(&plan_v2).expect("v2 stores");
    plan.approve(true, None).expect("approve plan");
    store.save_plan(&plan).expect("approved plan stores");

    let reloaded = store.load_plan_v2(&plan.operation_id).expect("v2 reads");
    assert_eq!(reloaded.plan.status, PlanStatus::Approved);
    assert_eq!(reloaded.plan.content_hash, plan.content_hash);
    reloaded.validate().expect("v2 remains valid");
}

#[test]
fn stored_plan_record_fails_closed_when_a_current_mutation_loses_plan_v2() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("storage opens");
    let plan = draft_plan();
    store.save_plan(&plan).expect("compatibility plan stores");

    assert!(matches!(
        store
            .load_stored_plan_record(&plan.operation_id)
            .expect("record classifies"),
        StoredPlanRecord::RequiredSidecarMissing(candidate) if *candidate == plan
    ));
}

#[test]
fn stored_plan_record_keeps_historical_plan_v1_readable_but_not_execution_compatible() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("storage opens");
    let mut plan = draft_plan();
    plan.created_at = chrono::DateTime::parse_from_rfc3339("2026-07-20T00:00:00Z")
        .expect("historical timestamp")
        .with_timezone(&Utc);
    plan.transaction_journal.clear();
    plan.refresh_hash().expect("refresh historical plan");
    plan.record_transaction_stage(TransactionStageV1::PlanPrepared)
        .expect("historical journal");
    store.save_plan(&plan).expect("historical plan stores");

    let record = store
        .load_stored_plan_record(&plan.operation_id)
        .expect("record classifies");
    assert!(matches!(record, StoredPlanRecord::LegacyReadable(_)));
    assert!(!record.execution_compatible());
    assert_eq!(
        record.execution_incompatibility_reason(),
        Some("legacy_plan_v1")
    );
}

#[test]
fn stored_plan_record_detects_plan_v1_projection_drift() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let paths = RuntimePaths::from_root(root.path());
    let store = StateStore::open(paths.clone()).expect("storage opens");
    let plan = draft_plan();
    let plan_v2 = cfctl_core::PlanV2::new(
        plan.clone(),
        cfctl_core::PlanPinsV2 {
            build_identity_hash: "sha256:build".to_owned(),
            catalog_hash: plan.catalog_hash.clone(),
            credential_generation_id: "generation-a".to_owned(),
            admission_policy_hash: "sha256:policy".to_owned(),
            authority_hash: None,
            workspace_graph_hash: "sha256:workspace".to_owned(),
            resource_observation_hashes: std::collections::BTreeMap::default(),
            cost_budget: None,
        },
    )
    .expect("plan v2");
    store.save_plan_v2(&plan_v2).expect("current plan stores");

    let mut drifted = plan;
    drifted.affected_resources.push("worker:other".to_owned());
    drifted.transaction_journal.clear();
    drifted.refresh_hash().expect("refresh drifted projection");
    drifted
        .record_transaction_stage(TransactionStageV1::PlanPrepared)
        .expect("drifted journal");
    store
        .write_json(
            &paths
                .data_dir
                .join("plans")
                .join(format!("{}.json", drifted.operation_id)),
            &drifted,
        )
        .expect("inject projection drift");

    assert!(matches!(
        store
            .load_stored_plan_record(&drifted.operation_id)
            .expect("record classifies"),
        StoredPlanRecord::ProjectionDrift { .. }
    ));
    assert!(matches!(
        store.load_plan(&drifted.operation_id),
        Err(StorageError::PlanProjectionDrift(_))
    ));
}

#[test]
fn registered_roots_can_be_retired_after_the_workspace_disappears() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let workspace_parent = tempfile::tempdir().expect("workspace parent");
    let workspace = workspace_parent.path().join("retired-workspace");
    std::fs::create_dir(&workspace).expect("workspace root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("storage opens");
    store
        .register_workspace(&workspace, None)
        .expect("register root");
    let canonical = workspace.canonicalize().expect("canonical workspace");
    std::fs::remove_dir(&workspace).expect("retire temporary workspace fixture");

    let (removed_path, removed, account_pin_removed) = store
        .unregister_workspace(&canonical)
        .expect("unregister stale root");

    assert_eq!(removed_path, canonical);
    assert!(removed);
    assert!(!account_pin_removed);
    assert!(store.workspace_roots().expect("read roots").is_empty());
    let (_, removed_again, _) = store
        .unregister_workspace(&removed_path)
        .expect("repeat removal is idempotent");
    assert!(!removed_again);
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
