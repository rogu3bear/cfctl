#![allow(clippy::expect_used, clippy::unwrap_used)]
#[path = "r2_restore_projection_tests.rs"]
mod projection_tests;
use super::super::prelude::{
    CallInput, CatalogSnapshot, PlanV1, ProfilesConfig, StateStore, Value, json,
};
use super::{PrivateSources, ROOT_NAME, TARGET, load_with_secrets, prepare};
use cfctl_auth::{
    EvidenceKeyManager, MemorySecretStore, ProfileKind, ProfileMetadata, SecretBackend,
};
use cfctl_core::{
    AdapterStatus, CapabilityV1, EffectClass, EvidenceClass, OperationalProofOutcomeV1,
    OperationalProofScopeV1, OperationalProofV1, PlanPinsV2, PlanV2, ResponseBodyModeV1,
    ResponseContractV1, RiskClass, hash_value,
    r2_recovery::{CaptureManifestV1, CaptureWindowV1, CapturedObjectV1},
    r2_restore::{self as contract, CaptureRefV1, CurrentExpectationV1, RestoreRequestV1},
};
use cfctl_storage::{PrivateDirectory, RuntimePaths};
use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
};
use uuid::Uuid;

struct Fixture {
    root: tempfile::TempDir,
    store: StateStore,
    catalog: CatalogSnapshot,
    profile: ProfileMetadata,
    secrets: MemorySecretStore,
    input: CallInput,
    sources: PathBuf,
}

fn proof(
    store: &StateStore,
    cap: &str,
    catalog: &str,
    input: &CallInput,
    profile: &ProfileMetadata,
    value: &Value,
    observed: DateTime<Utc>,
) -> String {
    let evidence = store
        .write_evidence(EvidenceClass::LiveRead, value)
        .expect("authenticated observation");
    let hash = evidence.content_hash.clone();
    let mut proof = OperationalProofV1::new(
        observed,
        cap,
        catalog,
        &hash_value(&serde_json::to_value(input).expect("input")).expect("input hash"),
        OperationalProofScopeV1::new(
            Some(&profile.id),
            profile.account_id.as_deref(),
            profile.credential_generation_id.as_deref(),
        ),
        OperationalProofOutcomeV1::Succeeded,
        evidence,
    );
    let build_hash = if cap == cfctl_core::r2_recovery::CAPTURE_ID {
        format!("sha256:{}", "d".repeat(64))
    } else {
        hash_value(
            &serde_json::to_value(crate::build_identity::current_build_info()).expect("build"),
        )
        .expect("current build hash")
    };
    proof
        .bind_build_identity_hash(&build_hash)
        .expect("build identity");
    store
        .record_operational_proof(&proof)
        .expect("native provenance");
    hash
}

fn snapshot(
    root: &Path,
    store: &StateStore,
    profile: &ProfileMetadata,
    name: &str,
    bytes: &[u8],
    when: DateTime<Utc>,
) -> (PathBuf, CaptureRefV1) {
    let path = root.join(name);
    let dir = PrivateDirectory::create(&path).expect("snapshot");
    let manifest = CaptureManifestV1 {
        schema_version: 1,
        run_id: Uuid::new_v4().to_string(),
        account_id: "a".repeat(32),
        bucket_name: "private-pdfs".into(),
        window: CaptureWindowV1 {
            window_id: Uuid::new_v4().to_string(),
            opened_at: when - Duration::seconds(1),
            expires_at: when + Duration::minutes(10),
            recovery_binding_sha256: "a".repeat(64),
        },
        started_at: when,
        completed_at: when,
        list_pages: 2,
        total_bytes: bytes.len() as u64,
        objects: vec![CapturedObjectV1 {
            provider_metadata: json!({"key":"docs/private","size":bytes.len(),"etag":name,
            "last_modified":"2026-08-07T00:00:00Z","storage_class":"Standard"}),
            blob: "object-0000.bin".into(),
            sha256: hex::encode(Sha256::digest(bytes)),
            byte_count: bytes.len() as u64,
        }],
    };
    dir.create_new_file("object-0000.bin")
        .expect("blob")
        .write_all(bytes)
        .expect("bytes");
    let encoded = serde_json::to_vec(&manifest).expect("manifest");
    dir.create_new_file("manifest.json")
        .expect("file")
        .write_all(&encoded)
        .expect("manifest");
    let receipt = manifest.receipt(hex::encode(Sha256::digest(&encoded)));
    let input = CallInput {
        selectors: json!({"account_id":manifest.account_id,"bucket_name":manifest.bucket_name}),
        query: json!({}),
        body: Some(serde_json::to_value(&manifest.window).expect("window")),
        ..CallInput::default()
    };
    let evidence_hash = proof(
        store,
        cfctl_core::r2_recovery::CAPTURE_ID,
        &hash_value(&json!("historical-native-catalog")).expect("historical catalog identity"),
        &input,
        profile,
        &json!({"status":200,"success":true,"result":receipt}),
        when + Duration::milliseconds(1),
    );
    (
        path,
        CaptureRefV1 {
            evidence_hash,
            run_id: manifest.run_id,
        },
    )
}

fn token_cap(id: &str, path: &str) -> CapabilityV1 {
    let mut cap = CapabilityV1::new(id, "fixture token metadata", "GET", path);
    cap.account_scope = "account".into();
    cap.adapter_status = AdapterStatus::DynamicApi;
    cap.risk = RiskClass::Read;
    cap.effect = EffectClass::ReadOnly;
    cap.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".into()],
        success_media_types: vec!["application/json".into()],
        body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
    });
    cap
}

#[expect(
    clippy::too_many_lines,
    reason = "one isolated fixture records native historical capture provenance and independent current token provenance before exercising ordinary staging"
)]
fn fixture(stale_token: bool) -> Fixture {
    let root = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in("/private/tmp")
        .expect("isolated fixture");
    let initial = StateStore::open(RuntimePaths::from_root(root.path())).expect("state");
    fs::set_permissions(&initial.paths().data_dir, fs::Permissions::from_mode(0o700))
        .expect("private state");
    let manager = Arc::new(
        EvidenceKeyManager::new(
            Arc::new(MemorySecretStore::default()),
            initial.evidence_location_identity(),
            SecretBackend::Memory,
        )
        .expect("memory evidence"),
    );
    let identity = format!("sha256:{}", "a".repeat(64));
    manager.initialize(&identity).expect("key");
    initial
        .initialize_evidence_root_identity(&identity)
        .expect("root");
    let store = initial
        .with_evidence_authenticator(manager)
        .expect("authenticated state");
    let profile = ProfileMetadata::new(
        "current-effect",
        ProfileKind::ApiToken,
        Some(&"a".repeat(32)),
    );
    let mut profiles = ProfilesConfig::default();
    profiles
        .profiles
        .insert(profile.id.clone(), profile.clone());
    profiles.save(&store).expect("profiles");
    let mut catalog = CatalogSnapshot {
        schema_version: 1,
        generated_at: Utc::now(),
        source_url: "fixture".into(),
        source_hash: String::new(),
        schema_hash: String::new(),
        capabilities: BTreeMap::new(),
    };
    cfctl_catalog::ingest_native_control_capabilities(&mut catalog).expect("native catalog");
    for cap in [
        token_cap(
            "fixture-account-verify",
            "/accounts/{account_id}/tokens/verify",
        ),
        token_cap(
            "fixture-account-policy",
            "/accounts/{account_id}/tokens/{token_id}",
        ),
    ] {
        catalog.capabilities.insert(cap.id.clone(), cap);
    }
    catalog.refresh_hash().expect("catalog identity");
    catalog
        .save(&store.paths().catalog_file())
        .expect("catalog");
    let historical = ProfileMetadata::new(
        "retired-capture-profile",
        ProfileKind::ApiToken,
        Some(&"a".repeat(32)),
    );
    let (source_path, source_capture) = snapshot(
        root.path(),
        &store,
        &historical,
        "original",
        b"%PDF",
        Utc::now() - Duration::days(30),
    );
    let (current_path, current_capture) = snapshot(
        root.path(),
        &store,
        &profile,
        "current",
        b"CURR",
        Utc::now() - Duration::seconds(1),
    );
    let verified_input = CallInput {
        selectors: json!({"account_id":"a".repeat(32)}),
        query: json!({}),
        ..CallInput::default()
    };
    let now = Utc::now();
    let observed = if stale_token {
        now - Duration::minutes(10)
    } else {
        now
    };
    let token = json!({"id":"1".repeat(32),"status":"active","expires_on":now+Duration::days(1)});
    let verification_hash = proof(
        &store,
        "fixture-account-verify",
        &catalog.schema_hash,
        &verified_input,
        &profile,
        &json!({"status":200,"success":true,"result":token}),
        observed,
    );
    let mut policy = token;
    policy["policies"] = json!([{"effect":"allow","resources":{(format!("com.cloudflare.api.account.{}","a".repeat(32))):"*"},"permission_groups":[{"name":"Workers R2 Storage Write"}]}]);
    let policy_input = CallInput {
        selectors: json!({"account_id":"a".repeat(32),"token_id":"1".repeat(32)}),
        query: json!({}),
        ..CallInput::default()
    };
    let policy_hash = proof(
        &store,
        "fixture-account-policy",
        &catalog.schema_hash,
        &policy_input,
        &profile,
        &json!({"status":200,"success":true,"result":policy}),
        observed,
    );
    let request = RestoreRequestV1 {
        source_capture,
        source_object_index: 0,
        current_capture,
        expected_current: CurrentExpectationV1::Present { object_index: 0 },
        token_verification_evidence_hash: verification_hash,
        token_policy_evidence_hash: policy_hash,
    };
    let input = CallInput {
        selectors: json!({"account_id":"a".repeat(32),"bucket_name":"private-pdfs"}),
        query: json!({}),
        body: Some(serde_json::to_value(request).expect("request")),
        ..CallInput::default()
    };
    let sources = root.path().join("sources.json");
    PrivateDirectory::open(root.path())
        .expect("root")
        .create_new_file("sources.json")
        .expect("sources")
        .write_all(
            &serde_json::to_vec(&PrivateSources {
                source_capture_directory: source_path,
                current_capture_directory: current_path,
            })
            .expect("private paths"),
        )
        .expect("sources bytes");
    Fixture {
        root,
        store,
        catalog,
        profile,
        secrets: MemorySecretStore::default(),
        input,
        sources,
    }
}

fn prepared(f: &Fixture) -> PlanV1 {
    let target = prepare(
        &f.store, &f.catalog, &f.input, &f.profile, &f.sources, &f.secrets,
    )
    .expect("qualified private stage");
    let cap = f
        .catalog
        .get(contract::RESTORE_ID)
        .expect("restore")
        .clone();
    assert!(cap.verification_contract_supported());
    let mut plan = PlanV1::draft(
        &f.profile.id,
        &"a".repeat(32),
        &f.catalog.schema_hash,
        cap,
        json!({"adapter":{"r2_private_restore":target}}),
    )
    .expect("plan");
    plan.input = serde_json::to_value(&f.input).expect("input");
    plan.permission_lane = "api_token".into();
    plan.refresh_hash().expect("bound draft input");
    plan
}

fn consumed(f: &Fixture) -> PlanV1 {
    consume_prepared(f, prepared(f))
}

fn consume_prepared(f: &Fixture, mut plan: PlanV1) -> PlanV1 {
    let document = PlanV2::new(
        plan.clone(),
        PlanPinsV2 {
            build_identity_hash: hash_value(&json!(crate::build_identity::current_build_info()))
                .expect("build identity"),
            catalog_hash: plan.catalog_hash.clone(),
            credential_generation_id: f
                .profile
                .credential_generation_id
                .clone()
                .expect("fixture generation"),
            admission_policy_hash: hash_value(&json!("fixture-policy")).expect("policy pin"),
            authority_hash: None,
            workspace_graph_hash: hash_value(&json!("fixture-workspace")).expect("workspace pin"),
            resource_observation_hashes: BTreeMap::new(),
            cost_budget: None,
        },
    )
    .expect("current draft PlanV2");
    f.store
        .save_plan_v2(&document)
        .expect("canonical draft before approval");
    plan.approve(true, None).expect("exact fixture approval");
    plan.mark_consumed().expect("one-use consumption");
    plan.record_transaction_stage(cfctl_core::TransactionStageV1::BoundaryAttemptPersisted)
        .expect("boundary checkpoint");
    f.store.save_plan(&plan).expect("durable consumed plan");
    assert!(matches!(
        f.store
            .load_stored_plan_record(&plan.operation_id)
            .expect("stored fixture"),
        cfctl_storage::StoredPlanRecord::Current(_)
    ));
    plan
}

#[test]
fn historical_capture_uses_current_window_and_preserves_displaced_bytes() {
    let f = fixture(false);
    let plan = prepared(&f);
    fs::write(f.root.path().join("original/object-0000.bin"), b"EVIL")
        .expect("original changes after staging");
    let loaded =
        load_with_secrets(&f.store, &plan, true, &f.secrets).expect("managed immutable copy");
    assert_eq!(loaded.source_bytes, b"%PDF");
    assert_eq!(
        loaded.token_id.as_deref(),
        Some("11111111111111111111111111111111")
    );
    assert_eq!(
        loaded
            .selection
            .displaced
            .as_ref()
            .expect("preserved")
            .sha256,
        hex::encode(Sha256::digest(b"CURR"))
    );
    assert!(loaded.selection.window.expires_at > Utc::now());
    let public = serde_json::to_string(&plan.targets).expect("public target");
    assert!(!public.contains("docs/private"));
    assert!(!public.contains(f.root.path().to_str().expect("path")));
}

#[test]
fn immutable_target_key_and_metadata_are_revalidated_before_restore() {
    for field in ["object_key_sha256", "source_semantic_metadata_sha256"] {
        let f = fixture(false);
        let mut plan = prepared(&f);
        plan.targets.pointer_mut(TARGET).expect("target")[field] = if field == "object_key_sha256" {
            json!("0".repeat(64))
        } else {
            json!(format!("sha256:{}", "0".repeat(64)))
        };
        plan.refresh_hash().expect("self-consistent changed plan");
        assert!(
            load_with_secrets(&f.store, &plan, true, &f.secrets).is_err(),
            "{field}"
        );
    }
}

#[test]
fn private_stage_tampering_and_profile_rotation_block_write_authority() {
    for kind in ["source", "displaced", "generation"] {
        let f = fixture(false);
        let plan = prepared(&f);
        let reference = plan.targets.pointer(TARGET).expect("target")["stage_ref"]
            .as_str()
            .expect("reference");
        let id = reference.strip_prefix("r2-private-restore/").expect("id");
        if kind == "generation" {
            let mut profiles = ProfilesConfig::load(&f.store).expect("profiles");
            profiles
                .profiles
                .get_mut(&f.profile.id)
                .expect("profile")
                .credential_generation_id = Some(Uuid::new_v4().to_string());
            profiles.save(&f.store).expect("rotation");
            assert!(
                load_with_secrets(&f.store, &plan, false, &f.secrets).is_ok(),
                "historical read custody survives effect-credential rotation"
            );
        } else {
            let dir = if kind == "source" {
                "source"
            } else {
                "current"
            };
            fs::write(
                f.store
                    .paths()
                    .data_dir
                    .join(ROOT_NAME)
                    .join(id)
                    .join(dir)
                    .join("object-0000.bin"),
                b"EVIL",
            )
            .expect("tamper");
        }
        assert!(load_with_secrets(&f.store, &plan, true, &f.secrets).is_err());
    }
}

#[test]
fn stale_credentials_wrong_member_and_false_absence_are_rejected_locally() {
    for kind in ["stale", "member", "absence", "provenance"] {
        let mut f = fixture(kind == "stale");
        let body = f.input.body.as_mut().expect("body");
        match kind {
            "member" => body["source_object_index"] = json!(9),
            "absence" => body["expected_current"] = json!({"state":"absent"}),
            "provenance" => {
                body["source_capture"]["evidence_hash"] =
                    json!(format!("sha256:{}", "e".repeat(64)));
            }
            _ => {}
        }
        assert!(
            prepare(
                &f.store, &f.catalog, &f.input, &f.profile, &f.sources, &f.secrets
            )
            .is_err()
        );
        assert!(
            !f.store.paths().data_dir.join(ROOT_NAME).exists(),
            "rejected admission creates no private recovery stage"
        );
    }
}

#[tokio::test]
async fn consumed_stage_failure_persists_no_write_attempt_without_provider_access() {
    let f = fixture(false);
    let mut plan = consumed(&f);
    let reference = plan.targets.pointer(TARGET).expect("target")["stage_ref"]
        .as_str()
        .expect("stage reference");
    let id = reference
        .strip_prefix("r2-private-restore/")
        .expect("stage id");
    let blob = f
        .store
        .paths()
        .data_dir
        .join(ROOT_NAME)
        .join(id)
        .join("source/object-0000.bin");
    fs::write(blob, b"EVIL").expect("post-consumption tamper");
    let result = super::super::r2_restore_execution::execute(
        &f.store,
        &f.catalog.schema_hash,
        &mut plan,
        &f.input,
        &cfctl_auth::AuthCredential::Bearer {
            token: "synthetic-no-network".into(),
        },
        &f.secrets,
    )
    .await
    .expect("durable local failure");
    assert!(!result.ok);
    assert!(!result.performed);
    assert_eq!(plan.status, cfctl_core::PlanStatus::RectificationRequired);
    let serialized = serde_json::to_value(&result).expect("receipt");
    assert!(serialized.to_string().contains("not_attempted"));
    assert!(!serialized.to_string().contains("docs/private"));
    let stored = f
        .store
        .load_plan(&plan.operation_id)
        .expect("durable consumed result");
    assert_eq!(stored.status, cfctl_core::PlanStatus::RectificationRequired);
    assert_eq!(
        stored
            .transaction_artifact(cfctl_core::TransactionStageV1::BoundaryResponsePersisted)
            .expect("no-write receipt")["put_attempted"],
        false
    );
    assert!(
        plan.mark_consumed().is_err(),
        "failed consumed operation cannot replay"
    );
}

#[test]
fn repeated_read_only_rectification_preserves_the_original_journal_and_can_close() {
    use super::super::{api_boundary, r2_restore_execution};
    use cfctl_core::{PlanStatus, TransactionStageV1};
    let f = fixture(false);
    let mut plan = consumed(&f);
    let mut first_verification = None;
    for passed in [false, false, true] {
        let old_journal = plan.transaction_journal.clone();
        r2_restore_execution::begin_rectification_observation(&f.store, &mut plan)
            .expect("read-only attempt without journal rewind");
        let observation = cfctl_cloudflare::OperationVerificationV1 {
            strategy: contract::STRATEGY.into(),
            passed,
            basis: "synthetic current byte and metadata comparison".into(),
            correlated_resource_id: None,
            readback: cfctl_cloudflare::CloudflareResponseV1 {
                status: 200,
                success: true,
                result: json!({"bytes_and_metadata_match":passed,"put_replayed":false}),
                errors: vec![],
                result_info: None,
                etag: None,
                cf_ray: None,
            },
        };
        let outcome = api_boundary::verification_outcome(&f.store, &mut plan, observation)
            .expect("authenticated current observation");
        r2_restore_execution::persist_rectification(&f.store, &mut plan, &outcome)
            .expect("durable forward-only reconciliation");
        assert_eq!(&plan.transaction_journal[..old_journal.len()], &old_journal);
        let receipt = plan
            .transaction_artifact(TransactionStageV1::VerificationResponsePersisted)
            .expect("first verification checkpoint")
            .clone();
        if let Some(first) = &first_verification {
            assert_eq!(first, &receipt, "first failed response remains immutable");
        } else {
            first_verification = Some(receipt);
        }
        let mut stored = f
            .store
            .load_plan(&plan.operation_id)
            .expect("durable state");
        stored
            .validate_transaction_journal()
            .expect("valid journal");
        assert_eq!(
            stored.status,
            if passed {
                PlanStatus::Verified
            } else {
                PlanStatus::RectificationRequired
            }
        );
        assert!(
            stored.mark_consumed().is_err(),
            "read-only observations never renew write authority"
        );
    }
    assert_eq!(plan.transaction_stage, TransactionStageV1::Closed);
    assert_eq!(
        plan.transaction_artifact(TransactionStageV1::Closed)
            .expect("closure")["historical_put_outcome_proven"],
        false
    );
}
