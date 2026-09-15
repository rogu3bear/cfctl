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
