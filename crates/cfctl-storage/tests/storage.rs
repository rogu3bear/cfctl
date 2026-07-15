#![allow(clippy::expect_used, clippy::unwrap_used)]

use cfctl_core::{CapabilityV1, EvidenceClass, PlanV1, TransactionStageV1};
use cfctl_storage::{RuntimePaths, StateStore, StorageError};
use serde_json::json;

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
    let first = store.lock_plan("operation-a").expect("first lock");
    assert!(matches!(
        store.lock_plan("operation-a"),
        Err(StorageError::PlanLocked(_))
    ));
    drop(first);
    drop(store.lock_plan("operation-a").expect("released lock"));

    let crashed = store.lock_plan("operation-b").expect("crash fixture lock");
    std::mem::forget(crashed);
    let lock_path = root.path().join("data/locks/operation-b.lock");
    std::fs::write(
        &lock_path,
        br#"{"pid":999999,"created_at_unix":0,"nonce":"crashed"}"#,
    )
    .expect("age crash lock");
    drop(
        store
            .lock_plan("operation-b")
            .expect("stale lock reclaimed"),
    );
    assert!(!lock_path.exists());
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
