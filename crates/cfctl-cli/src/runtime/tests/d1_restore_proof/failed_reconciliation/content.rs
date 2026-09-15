use super::*;
use cfctl_core::d1_reconciliation::{ReleaseBinding, Window};
use std::os::unix::fs::PermissionsExt;

fn export(
    store: &StorageStateStore,
    directory: &Path,
    name: &str,
    bookmark: &str,
    sql: &[u8],
) -> (String, String) {
    let path = directory.join(name);
    fs::write(&path, sql).expect("private SQL");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private mode");
    let catalog = catalog();
    let input = CallInput {
        selectors: json!({"account_id":ACCOUNT,"database_id":DATABASE}),
        query: json!({}),
        ..CallInput::default()
    };
    let result = json!({"success":true,"status":200,"errors":[],
        "result":{"database":input.selectors,"output_file":{"path":path,"bytes":sql.len(),
            "sha256":format!("sha256:{}",hex::encode(Sha256::digest(sql))),"complete":true,"hash_matches":true},
            "provider":{"at_bookmark":bookmark,"exported_at":Utc::now()}},
        "result_info":{"verification":{"passed":true},"output":{"partial":false}}});
    let evidence = store
        .write_observation_evidence(EvidenceClass::LiveRead, &result)
        .expect("authenticated export");
    let hash = evidence.content_hash.clone();
    let mut envelope = ResultEnvelopeV2::success("call", result).with_evidence(evidence);
    envelope.performed = true;
    envelope.profile_id = Some("restore-fixture".into());
    envelope.account_id = Some(ACCOUNT.into());
    record_operational_proof(
        store,
        &catalog,
        catalog.get("d1-full-export").expect("capability"),
        &input,
        Some("22222222-2222-4222-8222-222222222222"),
        &envelope,
    )
    .expect("native export provenance");
    let proofs = store.list_operational_proofs().expect("proofs");
    let proof = proofs
        .iter()
        .find(|p| p.evidence.content_hash == hash)
        .expect("proof");
    (
        proof
            .d1_full_export_governed_execution()
            .expect("binding")
            .operation_id
            .clone(),
        hash,
    )
}

/// Object keys only, so the published examples track the producer's structure.
fn field_shape(value: &Value) -> Value {
    match value {
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(key, child)| (key.clone(), field_shape(child)))
                .collect(),
        ),
        _ => Value::Null,
    }
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the consumer fixture exercises source export, original producer, historical and current exports, then positive and adversarial admission"
)]
async fn d1_content_reconciliation_joins_native_failed_producer_and_private_exports_without_changing_plan()
 {
    let root = tempfile::tempdir().expect("root");
    let store = authenticated_test_store(RuntimePaths::from_root(root.path()));
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private directory");
    store
        .write_json(&store.paths().catalog_file(), &catalog())
        .expect("catalog");
    let mut profile = ProfileMetadata::new("restore-fixture", ProfileKind::ApiToken, Some(ACCOUNT));
    profile.credential_generation_id = Some("22222222-2222-4222-8222-222222222222".into());
    let mut profiles = ProfilesConfig::default();
    profiles.profiles.insert(profile.id.clone(), profile);
    profiles.save(&store).expect("profiles");
    let sql = b"CREATE TABLE initial_closed(value TEXT);\n";
    let (source_operation, source_hash) =
        export(&store, root.path(), "source.sql", "current-bookmark", sql);
    let mut input = input();
    let body = input.body.as_mut().expect("body");
    body["target_bookmark"] = json!("current-bookmark");
    body["source_operation_id"] = json!(source_operation);
    body["source_evidence_hash"] = json!(source_hash);
    let fixture = Box::pin(execute_failed_fixture(root, store, input)).await;
    let (_, historical_hash) = export(
        &fixture.store,
        fixture.root.path(),
        "post.sql",
        "advanced-bookmark",
        sql,
    );
    let opened_at = Utc::now();
    let binding = ReleaseBinding {
        commit: "a".repeat(40),
        tree: "b".repeat(40),
        deploy_artifact_digest: "c".repeat(64),
        declaration_sha256: "d".repeat(64),
        window: Window {
            window_id: Uuid::new_v4().to_string(),
            opened_at,
            expires_at: opened_at + ChronoDuration::seconds(900),
        },
    };
    let (_, current_hash) = export(
        &fixture.store,
        fixture.root.path(),
        "current.sql",
        "later-bookmark",
        sql,
    );
    let request = CallInput {
        body: Some(json!({"restore_operation_id":fixture.plan.operation_id,
        "historical_post_export_evidence_hash":historical_hash,"current_export_evidence_hash":current_hash,
        "release_binding":binding})),
        selectors: json!({}),
        query: json!({}),
        ..CallInput::default()
    };
    let before = fixture
        .store
        .load_plan_v2(&fixture.plan.operation_id)
        .expect("original plan");
    let result = crate::runtime::d1_reconciliation::reconcile(&fixture.store, &catalog(), &request)
        .expect("native reconciliation");
    assert!(result.ok);
    assert_eq!(result.verification.state, VerificationState::Passed);
    assert_eq!(result.result["qualified"], true);
    assert_eq!(result.result["limits"]["provider_requests"], 0);
    assert_eq!(
        result.result["limits"]["original_operation_reclassified"],
        false
    );
    assert_eq!(result.result["limits"]["write_authority_granted"], false);
    let example: cfctl_core::d1_reconciliation::ReconcileRequest = serde_json::from_str(
        include_str!("../../fixtures/d1-reconciliation-request.json"),
    )
    .expect("request example matches the closed contract");
    crate::runtime::d1_reconciliation::validate_window(
        &example.release_binding,
        example.release_binding.window.opened_at,
    )
    .expect("request example window is admissible");
    let documented: Value =
        serde_json::from_str(include_str!("../../fixtures/d1-reconciliation-result.json"))
            .expect("result example");
    assert_eq!(field_shape(&documented), field_shape(&result.result));
    assert_eq!(
        fixture
            .store
            .load_plan_v2(&fixture.plan.operation_id)
            .expect("unchanged plan"),
        before
    );
    let evidence = result.evidence.first().expect("signed result");
    assert_eq!(
        fixture
            .store
            .load_evidence_value(&evidence.content_hash)
            .expect("MAC verified")
            .1,
        result.result
    );

    let mut expired = request.clone();
    expired.body.as_mut().expect("body")["release_binding"]["window"]["expires_at"] =
        json!(opened_at);
    assert!(
        crate::runtime::d1_reconciliation::reconcile(&fixture.store, &catalog(), &expired).is_err()
    );
    let mut wrong_target = request.clone();
    wrong_target.body.as_mut().expect("body")["historical_post_export_evidence_hash"] =
        json!(source_hash);
    assert!(
        crate::runtime::d1_reconciliation::reconcile(&fixture.store, &catalog(), &wrong_target)
            .is_err()
    );
    fs::write(fixture.root.path().join("current.sql"), b"changed content").expect("drift SQL");
    assert!(
        crate::runtime::d1_reconciliation::reconcile(&fixture.store, &catalog(), &request).is_err()
    );
}
