use super::*;
mod content;

async fn failed_fixture() -> Fixture {
    let root = tempfile::tempdir().expect("failed restore root");
    let store = authenticated_test_store(RuntimePaths::from_root(root.path()));
    let mut input = input();
    input.body.as_mut().expect("body")["target_bookmark"] = json!("current-bookmark");
    Box::pin(execute_failed_fixture(root, store, input)).await
}

async fn execute_failed_fixture(
    root: tempfile::TempDir,
    store: StorageStateStore,
    input: CallInput,
) -> Fixture {
    Box::pin(execute_failed_fixture_readback(
        root,
        store,
        input,
        json!({"bookmark":"advanced-bookmark"}),
    ))
    .await
}

async fn execute_failed_fixture_readback(
    root: tempfile::TempDir,
    store: StorageStateStore,
    input: CallInput,
    readback: Value,
) -> Fixture {
    let mut plan = pending_plan_with_input(&store, &input);
    let (url, mut server) = mock_server_with_results(vec![
        json!({"bookmark":"current-bookmark"}),
        json!({"bookmark":"current-bookmark","previous_bookmark":"previous-bookmark","message":"restored"}),
        readback,
    ]).await;
    let executor = Executor::new(reqwest::Client::new(), &url).expect("mock executor");
    let credential = AuthCredential::Bearer {
        token: "synthetic-token".into(),
    };
    let apply = executor
        .execute_consumed_plan_with_input(&mut plan, &catalog().schema_hash, &credential, &input)
        .await
        .expect("single restore");
    process_api_boundary_response(&store, &mut plan, &apply, &MemorySecretStore::default())
        .expect("persist apply");
    let outcome = verify_api_plan(&store, &executor, &mut plan, &apply, &input, &credential)
        .await
        .expect("persist authenticated failed verification");
    assert_eq!(outcome.state, VerificationState::Failed);
    assert_eq!((&mut server.0).await.expect("server").len(), 3);
    Fixture { root, store, plan }
}

#[tokio::test]
async fn failed_restore_verifier_error_keeps_authenticated_execution_but_cannot_reconcile() {
    let root = tempfile::tempdir().expect("root");
    let store = authenticated_test_store(RuntimePaths::from_root(root.path()));
    let mut input = input();
    input.body.as_mut().expect("body")["target_bookmark"] = json!("current-bookmark");
    let fixture = Box::pin(execute_failed_fixture_readback(
        root,
        store,
        input,
        json!({}),
    ))
    .await;
    let (_, verification) = fixture.verification();
    assert_eq!(verification["passed"], false);
    assert_eq!(
        verification[CONTEXT]["operation_id"],
        fixture.plan.operation_id
    );
    assert!(history(&fixture).is_err());
    fixture.assert_unqualified("restore_lifecycle_not_verified_closed");
}

#[test]
fn unbindable_failure_is_recorded_as_rejected_while_a_malformed_body_is_refused() {
    use crate::runtime::d1_restore_proof::{
        attach_verification_context, recordable, unqualified_reason,
    };
    let root = tempfile::tempdir().expect("root");
    let store = authenticated_test_store(RuntimePaths::from_root(root.path()));
    // This plan never reached verification, so its execution cannot be bound.
    let plan = pending_plan(&store);
    let before = snapshot(root.path());
    let strategy = plan.capability.verification.strategy.clone();
    let mut failure = json!({"strategy":strategy,"passed":false,"error":"verifier unavailable"});
    attach_verification_context(&store, &plan, &mut failure)
        .expect("failed verification stays recordable");
    assert_eq!(failure[CONTEXT]["bound"], false);
    assert_eq!(
        unqualified_reason(&failure),
        Some("restore_verification_producer_mismatch")
    );
    let mut success = json!({"strategy":strategy,"passed":true,"basis":"matched","readback":{}});
    assert!(attach_verification_context(&store, &plan, &mut success).is_err());
    assert!(success.get(CONTEXT).is_none());
    assert_eq!(unqualified_reason(&success), None);
    // A malformed verification body is refused rather than recorded, and a
    // passing verification is never kept without its binding.
    for reason in [
        "unsupported_restore_verification_strategy",
        "invalid_verification_failure",
        "invalid_verification_body",
    ] {
        assert!(!recordable(reason, false), "{reason}");
    }
    for reason in [
        "restore_plan_unavailable",
        "restore_verification_producer_mismatch",
        "apply_evidence_unavailable_or_unauthenticated",
    ] {
        assert!(recordable(reason, false), "{reason}");
        assert!(!recordable(reason, true), "{reason}");
    }
    assert_eq!(snapshot(root.path()), before);
}

fn history(fixture: &Fixture) -> Result<Value> {
    let document = fixture
        .store
        .load_plan_v2(&fixture.plan.operation_id)
        .expect("plan");
    crate::runtime::d1_restore_proof::failed_reconciliation_history(&fixture.store, &document)
}

#[tokio::test]
async fn failed_restore_producer_authenticates_lineage_without_reclassifying_failure() {
    let fixture = Box::pin(failed_fixture()).await;
    let before = snapshot(fixture.root.path());
    let (_, verification) = fixture.verification();
    assert_eq!(verification["passed"], false);
    assert_eq!(
        verification[CONTEXT]["operation_id"],
        fixture.plan.operation_id
    );
    assert_eq!(verification[CONTEXT]["account_id"], ACCOUNT);
    assert_eq!(verification[CONTEXT]["database_id"], DATABASE);
    let result = history(&fixture).expect("authenticated failed execution");
    assert_eq!(result["original_verification_state"], "failed");
    assert_eq!(
        result["bookmarks"]["post_restore_bookmark"],
        "advanced-bookmark"
    );
    fixture.assert_unqualified("restore_lifecycle_not_verified_closed");
    assert_eq!(snapshot(fixture.root.path()), before);
}

#[tokio::test]
async fn failed_restore_rejects_recomputed_build_pins_and_operation_identity() {
    let mut fixture = Box::pin(failed_fixture()).await;
    let mut document = fixture
        .store
        .load_plan_v2(&fixture.plan.operation_id)
        .expect("plan");
    document.pins.build_identity_hash = hash_value(&json!("forged-build")).expect("hash");
    let document = PlanV2::new(document.plan, document.pins).expect("self-hashed forged pins");
    overwrite_unkeyed_plan_files(&fixture.store, &document);
    assert!(
        history(&fixture)
            .expect_err("forged build rejected")
            .to_string()
            .contains("historical_failed_restore_missing_authenticated_execution_binding")
    );
    fixture.plan.operation_id = Uuid::new_v4().to_string();
    rehash_plan(&mut fixture.plan);
    let document =
        PlanV2::new(fixture.plan.clone(), document.pins).expect("self-hashed forged identity");
    overwrite_unkeyed_plan_files(&fixture.store, &document);
    assert!(history(&fixture).is_err());
}

#[tokio::test]
async fn failed_restore_rejects_legacy_signed_failure_without_execution_binding() {
    let mut fixture = Box::pin(failed_fixture()).await;
    let (_, mut verification) = fixture.verification();
    verification
        .as_object_mut()
        .expect("object")
        .remove(CONTEXT);
    let descriptor = fixture
        .store
        .write_observation_evidence(EvidenceClass::PostChangeVerification, &verification)
        .expect("synthetic old producer signed unbound failure");
    fixture
        .plan
        .transaction_artifacts
        .get_mut(TransactionStageV1::VerificationResponsePersisted.as_str())
        .expect("artifact")["evidence_hash"] = json!(descriptor.content_hash);
    rehash_plan(&mut fixture.plan);
    fixture.save();
    assert!(
        history(&fixture)
            .expect_err("legacy receipt rejected")
            .to_string()
            .contains("historical_failed_restore_missing_authenticated_execution_binding")
    );
}

#[tokio::test]
async fn a_rejected_binding_is_reported_apart_from_one_an_older_build_never_wrote() {
    let mut fixture = Box::pin(failed_fixture()).await;
    let (_, mut verification) = fixture.verification();
    verification[CONTEXT] = json!({"bound":false,"reason":"restore_plan_unavailable"});
    let descriptor = fixture
        .store
        .write_observation_evidence(EvidenceClass::PostChangeVerification, &verification)
        .expect("signed rejected binding");
    fixture
        .plan
        .transaction_artifacts
        .get_mut(TransactionStageV1::VerificationResponsePersisted.as_str())
        .expect("artifact")["evidence_hash"] = json!(descriptor.content_hash);
    rehash_plan(&mut fixture.plan);
    fixture.save();
    assert_eq!(
        crate::runtime::d1_restore_proof::recorded_binding_rejection(&fixture.store, &fixture.plan)
            .as_deref(),
        Some("restore_plan_unavailable")
    );
    // Reconciliation separates a rejected binding from a missing one.
    assert!(
        history(&fixture)
            .expect_err("a rejected binding cannot reconcile")
            .to_string()
            .contains("execution_binding_rejected_at_execution")
    );
}
