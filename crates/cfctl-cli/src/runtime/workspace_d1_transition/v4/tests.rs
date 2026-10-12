#![allow(clippy::unwrap_used, clippy::expect_used, clippy::wildcard_imports)]
use super::*;

#[test]
fn runtime4_rejects_legacy_effect_success_flags_and_missing_assurance() {
    let legacy = serde_json::to_value(super::super::tests::binding()).unwrap();
    assert!(serde_json::from_value::<RuntimeBindingV4>(legacy.clone()).is_err());
    let mut missing = legacy;
    missing["schema_version"] = json!(4);
    assert!(serde_json::from_value::<RuntimeBindingV4>(missing).is_err());
    assert!(
        serde_json::from_value::<RuntimeBindingV4>(json!({"schema_version":4,"passed":true}))
            .is_err()
    );
}

#[test]
fn generic_post_change_receipt_cannot_be_a_typed_execution_or_qualification() {
    let generic = json!({"passed":true,"operation_id":"verified","evidence_hash":"sha256:abc"});
    assert!(serde_json::from_value::<ExecutionRecord>(generic.clone()).is_err());
    assert!(serde_json::from_value::<Qualification>(generic).is_err());
}

#[test]
fn native_rollback_error_requires_exact_scope_class_time_and_bookmark() {
    let root = tempfile::tempdir().unwrap();
    let store = crate::runtime::tests::authenticated_test_store(
        cfctl_storage::RuntimePaths::from_root(root.path()),
    );
    let body = json!({"kind":"workspace_d1_transition_import_progress_v1",
        "phase":"provider_error","operation_id":"attempt","database_id":"synthetic",
        "bookmark_sha256":format!("sha256:{}","a".repeat(64))});
    let evidence = store.write_evidence(EvidenceClass::Apply, &body).unwrap();
    let now = Utc::now();
    let (at, bookmark) =
        producers::provider_error(&store, &evidence.content_hash, "attempt", "synthetic", now)
            .unwrap();
    assert_eq!(at, evidence.generated_at);
    assert_eq!(bookmark, body["bookmark_sha256"].as_str().unwrap());
    assert!(
        producers::provider_error(&store, &evidence.content_hash, "other", "synthetic", now)
            .is_err()
    );
    assert!(
        producers::provider_error(&store, &evidence.content_hash, "attempt", "production", now)
            .is_err()
    );
    assert!(
        producers::provider_error(
            &store,
            &evidence.content_hash,
            "attempt",
            "synthetic",
            at - chrono::Duration::seconds(1)
        )
        .is_err()
    );
    for (class, mut value) in [
        (EvidenceClass::LocalProof, body.clone()),
        (EvidenceClass::Apply, body),
    ] {
        if class == EvidenceClass::Apply {
            value["bookmark_sha256"] = json!("caller claim");
        }
        value["test_case"] = json!(format!("{class:?}"));
        let wrong = store.write_evidence(class, &value).unwrap();
        assert!(
            producers::provider_error(&store, &wrong.content_hash, "attempt", "synthetic", now)
                .is_err()
        );
    }
}

#[test]
fn native_progress_persists_private_resume_without_exposing_raw_bookmark() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let private = tempfile::tempdir().unwrap();
    std::fs::set_permissions(private.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let directory =
        cfctl_storage::PrivateDirectory::open(&private.path().canonicalize().unwrap()).unwrap();
    let store = crate::runtime::tests::authenticated_test_store(
        cfctl_storage::RuntimePaths::from_root(root.path()),
    );
    let progress = cfctl_cloudflare::d1_transition::import::Progress {
        operation_id: "11111111-1111-4111-8111-111111111111".into(),
        database_id: "22222222-2222-4222-8222-222222222222".into(),
        phase: "provider_error",
        at_bookmark: Some("synthetic-private-bookmark".into()),
        terminal_bookmark: None,
        provider_error: None,
        terminal: None,
    };
    let hash = producers::persist_import_progress(&store, &directory, &progress).unwrap();
    let body = store.read_evidence_value(&hash).unwrap();
    assert!(!body.to_string().contains("synthetic-private-bookmark"));
    let name = body["private_progress"]["name"].as_str().unwrap();
    let path = private.path().join(name);
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let resume: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(resume["at_bookmark"], "synthetic-private-bookmark");
    assert!(
        producers::provider_error(
            &store,
            &hash,
            &progress.operation_id,
            &progress.database_id,
            Utc::now()
        )
        .is_ok()
    );
}
