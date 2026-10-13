#![allow(clippy::unwrap_used, clippy::expect_used, clippy::wildcard_imports)]
use super::*;

#[test]
fn public_local_producer_refuses_substituted_catalog_selectors_and_claimed_verdicts() {
    let root = tempfile::tempdir().unwrap();
    let store = crate::runtime::tests::authenticated_test_store(
        cfctl_storage::RuntimePaths::from_root(root.path()),
    );
    let capability = cfctl_catalog::d1_transition_proof_capability();
    let mut catalog = cfctl_catalog::CatalogSnapshot {
        schema_version: 2,
        generated_at: Utc::now(),
        source_url: String::new(),
        source_hash: String::new(),
        schema_hash: String::new(),
        capabilities: std::collections::BTreeMap::from([(capability.id.clone(), capability)]),
    };
    catalog.refresh_hash().unwrap();
    let proof = json!({"proof_hash":format!("sha256:{}","a".repeat(64)),
        "evidence_hash":format!("sha256:{}","b".repeat(64))});
    let request = json!({"action":"application", "operation_id":"351df28d-1459-4135-b7d6-af9e666eddfc",
        "terminal_assertions":proof,"diagnostic":proof});
    for body in [
        request.clone(),
        json!({"action":"application","passed":true}),
        json!({"action":"aggregate","qualification":{"passed":true}}),
    ] {
        let input = CallInput {
            body: Some(body),
            ..CallInput::default()
        };
        assert!(proof_command(&store, &catalog, &input).is_err());
    }
    let input = CallInput {
        selectors: json!({"database_id":"substitute"}),
        body: Some(request.clone()),
        ..CallInput::default()
    };
    assert!(proof_command(&store, &catalog, &input).is_err());
    catalog
        .capabilities
        .get_mut(cfctl_core::workspace_d1::transition::application::PRODUCER_ID)
        .unwrap()
        .path = "substitute".into();
    let input = CallInput {
        body: Some(request),
        ..CallInput::default()
    };
    let error = proof_command(&store, &catalog, &input).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("differs from its native contract")
    );
    assert!(store.list_plans().unwrap().is_empty());
    assert!(store.list_operational_proofs().unwrap().is_empty());
}

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
