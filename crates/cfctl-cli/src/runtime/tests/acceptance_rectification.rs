use super::*;

fn consumed_plan(store: &StorageStateStore) -> (PlanV1, CatalogSnapshot) {
    let mut capability = CapabilityV1::new("fixture.delegated", "Fixture", "CLI", "fixture");
    capability.mutating = true;
    capability.effect = EffectClass::ReversibleWrite;
    capability.risk = RiskClass::ScopedWrite;
    capability.adapter_status = AdapterStatus::DelegatedCli;
    let catalog = CatalogSnapshot {
        schema_version: 1,
        generated_at: Utc::now(),
        source_url: String::new(),
        source_hash: String::new(),
        schema_hash: "fixture".to_owned(),
        capabilities: BTreeMap::new(),
    };
    let mut plan = PlanV1::draft("profile", "account", "fixture", capability, json!({}))
        .expect("acceptance fixture and expected result");
    plan.approve(true, None)
        .expect("acceptance fixture and expected result");
    plan.mark_consumed()
        .expect("acceptance fixture and expected result");
    plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("acceptance fixture and expected result");
    store
        .save_plan(&plan)
        .expect("acceptance fixture and expected result");
    (plan, catalog)
}

#[tokio::test]
async fn returned_delegated_receipt_survives_evidence_and_recovery_storage_failure() {
    for recovery_fails in [false, true] {
        let root = tempfile::tempdir().expect("acceptance fixture and expected result");
        // No authenticator: apply evidence fails after the supplied boundary receipt.
        let store = StorageStateStore::open(RuntimePaths::from_root(root.path()))
            .expect("acceptance fixture and expected result");
        let (mut plan, catalog) = consumed_plan(&store);
        if recovery_fails {
            // Keep the consumed record, but make replacing it impossible.
            let path = store
                .paths()
                .data_dir
                .join("plans")
                .join(format!("{}.json", plan.operation_id));
            fs::rename(&path, path.with_extension("consumed"))
                .expect("acceptance fixture and expected result");
            fs::create_dir(&path).expect("acceptance fixture and expected result");
        }
        let receipt = json!({"success":true,"boundary_crossed":true,"deployment_id":"observed","token":"private"});
        let envelope = complete_delegated_plan(
            &store,
            &catalog,
            &mut plan,
            &CallInput::default(),
            &AuthCredential::Bearer {
                token: "fixture".to_owned(),
            },
            &MemorySecretStore::default(),
            receipt,
        )
        .await;
        assert!(!envelope.ok);
        assert!(envelope.performed);
        assert_eq!(envelope.result["deployment_id"], "observed");
        assert_ne!(envelope.result["token"], "private");
        assert_eq!(
            envelope
                .error
                .as_ref()
                .expect("acceptance fixture and expected result")
                .code,
            "CFCTL_POST_BOUNDARY_RECOVERY_REQUIRED"
        );
        assert!(
            envelope
                .error
                .as_ref()
                .expect("acceptance fixture and expected result")
                .next_step
                .as_ref()
                .expect("acceptance fixture and expected result")
                .contains("Do not replay")
        );
        if recovery_fails {
            assert!(
                envelope
                    .error
                    .expect("acceptance fixture and expected result")
                    .message
                    .contains("recovery persistence also failed")
            );
        } else {
            let durable = store
                .load_plan(&plan.operation_id)
                .expect("acceptance fixture and expected result");
            assert_eq!(durable.status, PlanStatus::RectificationRequired);
            durable
                .validate_transaction_journal()
                .expect("acceptance fixture and expected result");
            assert_eq!(
                durable
                    .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
                    .expect("acceptance fixture and expected result")["boundary_crossed"],
                true
            );
        }
    }
}

#[test]
fn unattested_observations_complete_apply_verify_and_recovery_without_qualifying() {
    let root = tempfile::tempdir().expect("acceptance fixture and expected result");
    let store = StorageStateStore::open(RuntimePaths::from_root(root.path()))
        .expect("acceptance fixture and expected result");
    let (mut plan, _) = consumed_plan(&store);
    let attestation = admit_execution_attestation(&store, &plan.operation_id)
        .expect("acceptance fixture and expected result");
    assert_eq!(
        attestation.state,
        AttestationStateV1::UnattestedReversibleEffect
    );
    let scoped = store.with_observation_attestation(&attestation);
    for class in [
        EvidenceClass::Preview,
        EvidenceClass::LiveRead,
        EvidenceClass::Apply,
        EvidenceClass::PostChangeVerification,
    ] {
        let evidence = scoped
            .write_observation_evidence(class, &json!({"class":class,"token":"private"}))
            .expect("acceptance fixture and expected result");
        assert_eq!(evidence.metadata["qualifying"], false);
        assert!(store.load_evidence(&evidence.content_hash).is_err());
        assert_ne!(
            store
                .read_audit_evidence_value(&evidence.content_hash)
                .expect("acceptance fixture and expected result")["token"],
            "private"
        );
    }
    let response = CloudflareResponseV1 {
        success: true,
        status: 200,
        result: json!({"id":"created"}),
        errors: vec![],
        etag: None,
        cf_ray: None,
        result_info: None,
    };
    assert!(matches!(
        process_api_boundary_response(&scoped, &mut plan, &response, &MemorySecretStore::default())
            .expect("acceptance fixture and expected result"),
        ApiBoundaryResponseOutcome::Ready { .. }
    ));
    let verification = verification_outcome(
        &scoped,
        &mut plan,
        OperationVerificationV1 {
            passed: true,
            strategy: "fixture".to_owned(),
            basis: "exact readback".to_owned(),
            readback: response.clone(),
            correlated_resource_id: None,
        },
    )
    .expect("acceptance fixture and expected result");
    assert_eq!(verification.state, VerificationState::Passed);
    persist_transaction_stage_with_artifact(
        &scoped,
        &mut plan,
        TransactionStageV1::VerificationResponsePersisted,
        json!({"state":"passed","evidence_hash":verification.evidence.expect("acceptance fixture and expected result").content_hash}),
    )
    .expect("acceptance fixture and expected result");
    persist_transaction_stage(&scoped, &mut plan, TransactionStageV1::Closed)
        .expect("acceptance fixture and expected result");
    let durable = store
        .load_plan(&plan.operation_id)
        .expect("acceptance fixture and expected result");
    assert_eq!(durable.status, PlanStatus::Verified);
    durable
        .validate_transaction_journal()
        .expect("acceptance fixture and expected result");
    assert!(
        scoped
            .write_evidence(EvidenceClass::Apply, &json!({"strict":true}))
            .is_err()
    );
    assert!(
        scoped
            .write_observation_evidence(EvidenceClass::StandingApply, &json!({"grant":true}))
            .is_err()
    );
    assert!(scoped.require_qualifying_evidence_authority().is_err());
}

#[test]
fn unattested_get_only_recovery_closes_without_authority_promotion() {
    let root = tempfile::tempdir().expect("acceptance fixture and expected result");
    let store = StorageStateStore::open(RuntimePaths::from_root(root.path()))
        .expect("acceptance fixture and expected result");
    let target = "11111111-2222-4333-8444-555555555555";
    let mut plan = super::boundary_rectification::rollback_rectification_plan(target);
    plan.status = PlanStatus::RectificationRequired;
    plan.record_transaction_stage_with_artifact(
        TransactionStageV1::BoundaryResponsePersisted,
        json!({"outcome":"transport_error","receipt_available":false}),
    )
    .expect("acceptance fixture and expected result");
    store
        .save_plan(&plan)
        .expect("acceptance fixture and expected result");
    let scoped = store.with_observation_attestation(
        &AttestationStatusV1::unattested_reversible_effect("missing authority".to_owned()),
    );
    let annotation = cfctl_cloudflare::worker_version_rollback_annotation(
        "restore known good",
        &plan.operation_id,
    )
    .expect("acceptance fixture and expected result");
    let readback = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"deployments":[{"id":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "versions":[{"version_id":target,"percentage":100}],
            "annotations":{"workers/message":annotation}}]}),
        errors: vec![],
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let envelope = persist_worker_version_rollback_rectification(
        &scoped,
        &mut plan,
        target,
        &annotation,
        &readback,
    )
    .expect("acceptance fixture and expected result");
    assert!(envelope.ok);
    assert!(!envelope.performed);
    assert_eq!(plan.status, PlanStatus::Verified);
    store
        .load_plan(&plan.operation_id)
        .expect("acceptance fixture and expected result")
        .validate_transaction_journal()
        .expect("acceptance fixture and expected result");
    assert_eq!(envelope.evidence[0].metadata["qualifying"], false);
    assert!(
        store
            .load_evidence(&envelope.evidence[0].content_hash)
            .is_err()
    );
}

#[test]
fn observation_scope_does_not_change_authenticated_writes_or_original_store() {
    let root = tempfile::tempdir().expect("acceptance fixture and expected result");
    let store = authenticated_test_store(RuntimePaths::from_root(root.path()));
    let scoped = store.with_observation_attestation(&AttestationStatusV1::attested());
    let evidence = scoped
        .write_observation_evidence(EvidenceClass::LiveRead, &json!({"state":"observed"}))
        .expect("acceptance fixture and expected result");
    assert_eq!(
        store
            .load_evidence(&evidence.content_hash)
            .expect("acceptance fixture and expected result"),
        evidence
    );
    let degraded = store.with_observation_attestation(
        &AttestationStatusV1::unattested_reversible_effect("fixture".to_owned()),
    );
    let audit = degraded
        .write_observation_evidence(EvidenceClass::LiveRead, &json!({"state":"degraded"}))
        .expect("acceptance fixture and expected result");
    assert!(store.load_evidence(&audit.content_hash).is_err());
    let original = store
        .write_observation_evidence(EvidenceClass::LiveRead, &json!({"state":"original"}))
        .expect("acceptance fixture and expected result");
    assert_eq!(
        store
            .load_evidence(&original.content_hash)
            .expect("acceptance fixture and expected result"),
        original
    );
}

#[test]
fn identical_unattested_body_cannot_refresh_existing_qualified_evidence() {
    let root = tempfile::tempdir().expect("acceptance fixture and expected result");
    let store = authenticated_test_store(RuntimePaths::from_root(root.path()));
    let body = json!({"same":"observed bytes"});
    let genuine = store
        .write_evidence(EvidenceClass::LiveRead, &body)
        .expect("acceptance fixture and expected result");
    let proof = OperationalProofV1::new(
        Utc::now(),
        "fixture-read",
        &format!("sha256:{}", "a".repeat(64)),
        &format!("sha256:{}", "b".repeat(64)),
        OperationalProofScopeV1::new(
            Some("profile"),
            Some("account"),
            Some("11111111-1111-4111-8111-111111111111"),
        ),
        OperationalProofOutcomeV1::Succeeded,
        genuine.clone(),
    );
    store
        .record_operational_proof(&proof)
        .expect("acceptance fixture and expected result");
    let scoped = store.with_observation_attestation(
        &AttestationStatusV1::unattested_reversible_effect("fixture".to_owned()),
    );
    let audit = scoped
        .write_observation_evidence(EvidenceClass::LiveRead, &body)
        .expect("acceptance fixture and expected result");
    assert_eq!(audit.content_hash, genuine.content_hash);
    assert_eq!(audit.metadata["qualifying"], false);
    let mut forged_refresh = proof.clone();
    forged_refresh.observed_at = Utc::now();
    forged_refresh.evidence = audit;
    assert!(store.record_operational_proof(&forged_refresh).is_err());
    assert_eq!(
        store
            .load_evidence(&genuine.content_hash)
            .expect("acceptance fixture and expected result"),
        genuine
    );
    assert_eq!(
        store
            .list_operational_proofs()
            .expect("acceptance fixture and expected result"),
        vec![proof]
    );
}
