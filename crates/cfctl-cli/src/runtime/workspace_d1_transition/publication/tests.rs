#![allow(clippy::expect_used, clippy::unwrap_used, clippy::wildcard_imports)]
use super::*;
use cfctl_core::{
    CapabilityV1, EvidenceClass, OperationalProofOutcomeV1, OperationalProofScopeV1,
    OperationalProofV1, PlanPinsV2, PlanStatus, PlanV1, TransactionStageV1,
};

const ACCOUNT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CATALOG: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const GENERATION: &str = "22222222-2222-4222-8222-222222222222";
const VERSION: &str = "66666666-6666-4666-8666-666666666666";
use std::collections::BTreeMap;

fn fixture() -> (PlanV2, WorkspaceD1MigrationContractV1) {
    let contract = super::super::tests::contract();
    let target = json!({
        "repository":contract.repository_root,"source_sha":contract.repository_head,
        "service_name":"founder",
        "config":{"authority":"exact_head_blob","path":"absent/wrangler.toml","sha256":"c".repeat(64)},
        "artifact":{"sha256":"d".repeat(64)},
        "version_message":format!("source={} artifact-sha256={}", contract.repository_head, "d".repeat(64))
    });
    let plan = PlanV1::draft(
        "worker-profile",
        ACCOUNT,
        CATALOG,
        CapabilityV1::new("wrangler.deploy", "Deploy", "CLI", "wrangler deploy"),
        json!({"adapter":{"worker_deployment":target}}),
    )
    .unwrap();
    let pins = PlanPinsV2 {
        build_identity_hash: "build".into(),
        catalog_hash: CATALOG.into(),
        credential_generation_id: GENERATION.into(),
        admission_policy_hash: "policy".into(),
        authority_hash: None,
        workspace_graph_hash: "graph".into(),
        resource_observation_hashes: BTreeMap::new(),
        cost_budget: None,
    };
    (PlanV2::new(plan, pins).unwrap(), contract)
}

#[test]
fn publication_rejects_other_source_config_repository_and_artifact_substitution() {
    let (plan, contract) = fixture();
    artifact_message(target(&plan, &contract).unwrap(), &contract).unwrap();
    for pointer in [
        "/repository",
        "/source_sha",
        "/config/path",
        "/config/sha256",
        "/config/authority",
    ] {
        let mut wrong = plan.clone();
        *wrong.plan.targets["adapter"]["worker_deployment"]
            .pointer_mut(pointer)
            .unwrap() = json!("other");
        assert!(target(&wrong, &contract).is_err(), "{pointer}");
    }
    let mut wrong = target(&plan, &contract).unwrap().clone();
    wrong["artifact"]["sha256"] = json!("e".repeat(64));
    assert!(artifact_message(&wrong, &contract).is_err());
    wrong["artifact"]["sha256"] = json!("not-a-digest");
    wrong["version_message"] = json!(format!(
        "source={} artifact-sha256=not-a-digest",
        contract.repository_head
    ));
    assert!(artifact_message(&wrong, &contract).is_err());
}

#[test]
fn upload_must_share_exact_config_and_worker_with_promotion() {
    let (mut plan, contract) = fixture();
    let promoted = target(&plan, &contract).unwrap().clone();
    assert!(target_for_upload(&plan, &contract, &promoted).is_err());
    plan.plan.capability.id = "wrangler.versions-upload".into();
    target_for_upload(&plan, &contract, &promoted).unwrap();
    for pointer in ["/service_name", "/config/sha256"] {
        let mut wrong = promoted.clone();
        *wrong.pointer_mut(pointer).unwrap() = json!("other");
        assert!(target_for_upload(&plan, &contract, &wrong).is_err());
    }
}

#[test]
fn publication_requires_one_exact_d1_binding_in_each_provider_shape() {
    let binding = json!({"type":"d1","name":"DB","id":"database"});
    database_binding(
        &json!({"bindings":[binding]}),
        "/bindings",
        "DB",
        "database",
    )
    .unwrap();
    database_binding(
        &json!({"resources":{"bindings":[binding]}}),
        "/resources/bindings",
        "DB",
        "database",
    )
    .unwrap();
    for bindings in [
        json!([]),
        json!([binding, binding]),
        json!([{"type":"d1","name":"DB","id":"other"}]),
        json!([{"type":"r2_bucket","name":"DB","id":"database"}]),
    ] {
        assert!(
            database_binding(&json!({"bindings":bindings}), "/bindings", "DB", "database").is_err()
        );
    }
    assert!(database_binding(&json!({}), "/bindings", "DB", "database").is_err());
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one authenticated read fixture exercises the closed target, scope and time rejection matrix"
)]
fn publication_reads_bind_native_input_profile_build_and_time() {
    let root = tempfile::tempdir().unwrap();
    let store = crate::runtime::tests::authenticated_test_store(
        cfctl_storage::RuntimePaths::from_root(root.path()),
    );
    let selectors = json!({"account_id":ACCOUNT,"script_name":"founder"});
    let input = CallInput {
        selectors: selectors.clone(),
        query: json!({}),
        ..CallInput::default()
    };
    let evidence = store.write_evidence(EvidenceClass::LiveRead, &json!({
        "status":200,"success":true,"result":{},"errors":[],"result_info":null,"etag":null,"cf_ray":null
    })).unwrap();
    let mut proof = OperationalProofV1::new(
        Utc::now(),
        worker_deployment::SETTINGS_CAPABILITY_ID,
        CATALOG,
        &hash_value(&serde_json::to_value(input).unwrap()).unwrap(),
        OperationalProofScopeV1::new(Some("worker-profile"), Some(ACCOUNT), Some(GENERATION)),
        OperationalProofOutcomeV1::Succeeded,
        evidence,
    );
    let build = hash_value(&json!("build")).unwrap();
    proof.bind_build_identity_hash(&build).unwrap();
    store.record_operational_proof(&proof).unwrap();
    let reference = ProofRef {
        proof_hash: store.operational_proof_hash(&proof).unwrap(),
        evidence_hash: proof.evidence.content_hash.clone(),
    };
    let scope = Scope {
        account: ACCOUNT,
        profile: "worker-profile",
        generation: GENERATION,
        catalog: CATALOG,
        build: &build,
    };
    let now = Utc::now();
    let after = proof.evidence.generated_at - Duration::seconds(1);
    response(
        &store,
        &reference,
        &scope,
        worker_deployment::SETTINGS_CAPABILITY_ID,
        selectors.clone(),
        after,
        now,
    )
    .unwrap();
    assert!(
        response(
            &store,
            &reference,
            &scope,
            worker_deployment::VERSION_CAPABILITY_ID,
            selectors.clone(),
            after,
            now
        )
        .is_err()
    );
    assert!(
        response(
            &store,
            &reference,
            &scope,
            worker_deployment::SETTINGS_CAPABILITY_ID,
            json!({"account_id":ACCOUNT,"script_name":"other"}),
            after,
            now
        )
        .is_err()
    );
    assert!(
        response(
            &store,
            &reference,
            &scope,
            worker_deployment::SETTINGS_CAPABILITY_ID,
            selectors.clone(),
            now,
            now
        )
        .is_err()
    );
    assert!(
        response(
            &store,
            &reference,
            &scope,
            worker_deployment::SETTINGS_CAPABILITY_ID,
            selectors.clone(),
            after,
            now + Duration::seconds(601)
        )
        .is_err()
    );
    let other = Scope {
        profile: "d1-profile",
        ..scope
    };
    assert!(
        response(
            &store,
            &reference,
            &other,
            worker_deployment::SETTINGS_CAPABILITY_ID,
            selectors,
            after,
            now
        )
        .is_err()
    );
}

fn native_read(store: &StateStore, capability: &str, selectors: Value, result: Value) -> ProofRef {
    let evidence = store.write_evidence(EvidenceClass::LiveRead, &json!({
        "status":200,"success":true,"result":result,"errors":[],"result_info":null,"etag":null,"cf_ray":null
    })).unwrap();
    let input = CallInput {
        selectors,
        query: json!({}),
        ..CallInput::default()
    };
    let mut proof = OperationalProofV1::new(
        Utc::now(),
        capability,
        CATALOG,
        &hash_value(&serde_json::to_value(input).unwrap()).unwrap(),
        OperationalProofScopeV1::new(Some("worker-profile"), Some(ACCOUNT), Some(GENERATION)),
        OperationalProofOutcomeV1::Succeeded,
        evidence,
    );
    proof
        .bind_build_identity_hash(&hash_value(&json!("build")).unwrap())
        .unwrap();
    store.record_operational_proof(&proof).unwrap();
    ProofRef {
        proof_hash: store.operational_proof_hash(&proof).unwrap(),
        evidence_hash: proof.evidence.content_hash,
    }
}

fn native_deploy(store: &StateStore, mut plan: PlanV2) -> EffectRef {
    let evidence = store
        .write_evidence(
            EvidenceClass::PostChangeVerification,
            &json!({"passed":true,"version_id":VERSION}),
        )
        .unwrap();
    plan.plan.refresh_hash().unwrap();
    plan.plan.approve(true, None).unwrap();
    plan.plan.mark_consumed().unwrap();
    for stage in [
        TransactionStageV1::BoundaryAttemptPersisted,
        TransactionStageV1::BoundaryResponsePersisted,
        TransactionStageV1::VerificationAttemptPersisted,
    ] {
        plan.plan.record_transaction_stage(stage).unwrap();
    }
    plan.plan.status = PlanStatus::Verified;
    plan.plan
        .record_transaction_stage_with_artifact(
            TransactionStageV1::VerificationResponsePersisted,
            json!({"state":"passed","evidence_hash":evidence.content_hash}),
        )
        .unwrap();
    plan.plan
        .record_transaction_stage(TransactionStageV1::Closed)
        .unwrap();
    let plan = PlanV2::new(plan.plan, plan.pins).unwrap();
    store.save_plan_v2(&plan).unwrap();
    EffectRef {
        operation_id: plan.plan.operation_id,
        evidence_hash: evidence.content_hash,
    }
}

#[test]
fn publication_joins_authenticated_deploy_and_reads_using_worker_credential_lane() {
    use sha2::{Digest, Sha256};
    let root = tempfile::tempdir().unwrap();
    let store = crate::runtime::tests::authenticated_test_store(
        cfctl_storage::RuntimePaths::from_root(root.path()),
    );
    let (mut plan, mut contract) = fixture();
    let config = b"name = 'founder'\n";
    std::fs::write(root.path().join("wrangler.toml"), config).unwrap();
    contract.repository_root = root.path().display().to_string();
    contract.config_template_sha256 = format!("sha256:{}", hex::encode(Sha256::digest(config)));
    let target = &mut plan.plan.targets["adapter"]["worker_deployment"];
    target["repository"] = json!(contract.repository_root);
    target["config"]["path"] = json!(root.path().join("wrangler.toml"));
    target["config"]["sha256"] = json!(hex::encode(Sha256::digest(config)));
    let message = target["version_message"].clone();
    let build = hash_value(&json!("build")).unwrap();
    plan.pins.build_identity_hash.clone_from(&build);
    let effect = native_deploy(&store, plan);
    let selectors = json!({"account_id":ACCOUNT,"script_name":"founder"});
    let binding = json!({"type":"d1","name":"DB","id":"database"});
    let mut reference = PublicationRef {
        effect,
        upload: None,
        verification: native_read(
            &store,
            worker_deployment::DEPLOYMENTS_CAPABILITY_ID,
            selectors.clone(),
            json!({"deployments":[{"id":"deployment","versions":[{"version_id":VERSION,"percentage":100}]}]}),
        ),
        version: native_read(
            &store,
            worker_deployment::VERSION_CAPABILITY_ID,
            json!({"account_id":ACCOUNT,"script_name":"founder","version_id":VERSION}),
            json!({"id":VERSION,"annotations":{"workers/message":message},"resources":{"bindings":[binding]}}),
        ),
        settings: native_read(
            &store,
            worker_deployment::SETTINGS_CAPABILITY_ID,
            selectors.clone(),
            json!({"bindings":[binding]}),
        ),
    };
    let scope = Scope {
        account: ACCOUNT,
        profile: "d1-profile",
        generation: "d1-generation",
        catalog: CATALOG,
        build: &build,
    };
    validate(&store, &contract, &reference, &scope, Utc::now()).unwrap();
    reference.settings = native_read(
        &store,
        worker_deployment::SETTINGS_CAPABILITY_ID,
        selectors,
        json!({"bindings":[{"type":"d1","name":"DB","id":"different-database"}]}),
    );
    assert!(validate(&store, &contract, &reference, &scope, Utc::now()).is_err());
}
