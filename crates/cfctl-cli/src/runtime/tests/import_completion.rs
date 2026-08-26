use super::*;

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the matrix rebuilds valid PlanV2 children across every pinned authority drift"
)]
pub(super) fn poll_child_resolver_rejects_canonical_terminal_and_intermediate_authority_drift() {
    let drift_cases = [
        "credential_pin",
        "profile",
        "catalog",
        "capability_contract_hash",
        "capability",
        "root_input",
        "root_stage",
        "target_account",
    ];
    for generations in [1, 2] {
        for drift_case in drift_cases {
            let fixture = build_poll_child_lineage(generations);
            let child_index = generations - 1;
            let mut child = fixture.children[child_index].clone();
            let response_artifact = child
                .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
                .expect("terminal response artifact")
                .clone();
            let terminal_status = child.status;
            let mut pins = fixture
                .store
                .load_plan_v2(&child.operation_id)
                .expect("canonical child")
                .pins;
            match drift_case {
                "credential_pin" => {
                    pins.credential_generation_id = "drifted-credential".to_owned();
                }
                "profile" => {
                    child.profile_id = "profile-b".to_owned();
                }
                "catalog" => {
                    child.catalog_hash = "drifted-catalog".to_owned();
                    pins.catalog_hash = child.catalog_hash.clone();
                }
                "capability_contract_hash" => {
                    child.targets["adapter"]["approved_mln_import_poll_resume"]["capability_contract_hash"] = json!(
                        hash_value(&json!({
                            "different":"capability"
                        }))
                        .expect("drifted contract hash")
                    );
                }
                "capability" => {
                    child.capability.title.push_str(" drifted");
                }
                "root_input" => {
                    child.targets["adapter"]["approved_mln_import_poll_resume"]["root_input"]["body"]
                        ["migration_id"] = json!("0142");
                }
                "root_stage" => {
                    child.targets["adapter"]["approved_mln_import_poll_resume"]["root_stage"]["sha256"] =
                        json!("sha256:drifted");
                }
                "target_account" => {
                    child.account_id = "drifted-account".to_owned();
                }
                _ => unreachable!("closed drift matrix"),
            }
            rebuild_poll_child_terminal_lifecycle(&mut child, terminal_status, response_artifact);
            persist_poll_test_plan_v2(&fixture.store, &child, pins);
            assert!(
                super::exact_linear_poll_child_provider_complete(
                    &fixture.store,
                    &fixture.root_plan
                )
                .is_err(),
                "{drift_case} must be rejected for a {generations}-generation terminal child"
            );
        }
    }

    for drift_case in drift_cases {
        let fixture = build_poll_child_lineage(2);
        let mut child = fixture.children[0].clone();
        let response_artifact = child
            .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
            .expect("intermediate exhaustion response artifact")
            .clone();
        let mut pins = fixture
            .store
            .load_plan_v2(&child.operation_id)
            .expect("canonical intermediate child")
            .pins;
        match drift_case {
            "credential_pin" => {
                pins.credential_generation_id = "drifted-credential".to_owned();
            }
            "profile" => {
                child.profile_id = "profile-b".to_owned();
            }
            "catalog" => {
                child.catalog_hash = "drifted-catalog".to_owned();
                pins.catalog_hash = child.catalog_hash.clone();
            }
            "capability_contract_hash" => {
                child.targets["adapter"]["approved_mln_import_poll_resume"]["capability_contract_hash"] = json!(
                    hash_value(&json!({
                        "different":"capability"
                    }))
                    .expect("drifted contract hash")
                );
            }
            "capability" => {
                child.capability.title.push_str(" drifted");
            }
            "root_input" => {
                child.targets["adapter"]["approved_mln_import_poll_resume"]["root_input"]["body"]
                    ["migration_id"] = json!("0142");
            }
            "root_stage" => {
                child.targets["adapter"]["approved_mln_import_poll_resume"]["root_stage"]["sha256"] =
                    json!("sha256:drifted");
            }
            "target_account" => {
                child.account_id = "drifted-account".to_owned();
            }
            _ => unreachable!("closed drift matrix"),
        }
        rebuild_poll_child_terminal_lifecycle(
            &mut child,
            PlanStatus::RectificationRequired,
            response_artifact,
        );
        persist_poll_test_plan_v2(&fixture.store, &child, pins);
        assert!(
            super::exact_linear_poll_child_provider_complete(&fixture.store, &fixture.root_plan)
                .is_err(),
            "{drift_case} must be rejected for an intermediate exhausted child"
        );
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one matrix proves missing, undurable, exact, duplicate, and mismatched completion"
)]
pub(super) fn approved_mln_completion_requires_one_exact_durable_provider_boundary() {
    let mut catalog = CatalogSnapshot {
        schema_version: 1,
        generated_at: Utc::now(),
        source_url: "test://native".to_owned(),
        source_hash: "sha256:test".to_owned(),
        schema_hash: String::new(),
        capabilities: BTreeMap::new(),
    };
    ingest_native_control_capabilities(&mut catalog).expect("native overlay");
    let capability = catalog
        .capabilities
        .remove("d1-import-approved-mln-migration")
        .expect("native import capability");
    let contract = capability
        .d1_approved_mln_import
        .as_ref()
        .expect("import contract");
    let migration = contract
        .migrations
        .iter()
        .find(|migration| migration.migration_id == "0143")
        .expect("0143 migration");
    let build = |root: &std::path::Path| {
        let store = StateStore::open(RuntimePaths::from_root(root)).expect("runtime state store");
        let mut plan = PlanV1::draft(
            "profile-a",
            &contract.account_id,
            POLL_FIXTURE_CATALOG_HASH,
            capability.clone(),
            json!({}),
        )
        .expect("import plan");
        plan.created_at = Utc::now() + ChronoDuration::hours(1);
        plan.expires_at = plan.created_at + ChronoDuration::hours(1);
        let prerequisites = authentic_0143_prerequisites(&store, &capability, plan.created_at);
        plan.input = serde_json::to_value(CallInput {
            selectors: json!({
                "account_id":contract.account_id,
                "database_id":contract.database_id,
            }),
            query: json!({}),
            body: Some(prerequisites),
            ..CallInput::default()
        })
        .expect("input");
        plan.precondition_hashes
            .insert("catalog".to_owned(), plan.catalog_hash.clone());
        let source_authority = json!({
            "schema_version":1,
            "repository_id":contract.repository_id,
            "observed_worktree_root":"/reviewed/mln-web",
            "observed_git_common_dir":"/reviewed/mln-web/.git",
            "head":contract.repository_head,
            "repository_relative_path":migration.repository_relative_path,
            "git_blob_oid":migration.git_blob_oid,
        });
        let staged = json!({
            "schema_version":1,
            "migration_id":"0143",
            "catalog_basename":migration.basename,
            "source_authority":source_authority,
            "source_authority_hash":hash_value(&source_authority).expect("authority hash"),
            "bytes":migration.bytes,
            "sha256":format!("sha256:{}",migration.sha256),
            "md5":migration.md5,
            "stage_path":"/managed/0143.sql",
            "stage_lifecycle":"preserve_until_verified_or_explicitly_retired",
            "target":{
                "account_id":contract.account_id,
                "database_id":contract.database_id,
            },
            "prerequisites":plan.input.get("body"),
        });
        plan.targets = json!({"adapter":{"approved_mln_import":staged}});
        plan.refresh_hash().expect("refresh import plan");
        save_current_test_plan(&store, &plan);
        (store, plan)
    };
    let accepted_ingest = |plan: &PlanV1, target_value: Value| {
        json!({
            "schema_version":1,
            "operation_id":plan.operation_id,
            "step":"ingest_response",
            "performed":true,
            "rectification_required":false,
            "receipt":{
                "http_status":200,
                "success":true,
                "response_action":"ingest",
                "provider":"cloudflare",
                "effect":"d1_import_ingest_accepted",
                "migration_id":"0143",
                "target":target_value,
                "plan_input_hash":hash_value(&plan.input).expect("input hash"),
                "no_replay":false,
                "result":{
                    "type":"import",
                    "status":"active",
                    "success":true,
                    "at_bookmark":"before",
                },
                "errors":[],
            }
        })
    };
    let checkpoint = |plan: &PlanV1, target_value: Value| {
        let staged = plan
            .targets
            .pointer("/adapter/approved_mln_import")
            .expect("stage");
        json!({
            "schema_version":1,
            "operation_id":plan.operation_id,
            "step":"provider_complete",
            "performed":true,
            "rectification_required":false,
            "receipt":{
                "provider":"cloudflare",
                "effect":"d1_import_provider_complete",
                "response_action":"poll",
                "no_replay":true,
                "migration_id":"0143",
                "source_sha256":staged.get("sha256"),
                "source_md5":staged.get("md5"),
                "source_bytes":staged.get("bytes"),
                "source_authority_hash":staged.get("source_authority_hash"),
                "stage_identity_hash":hash_value(staged).expect("stage hash"),
                "target":target_value,
                "plan_input_hash":hash_value(&plan.input).expect("input hash"),
                "prerequisites":plan.input.get("body"),
                "at_bookmark":"before",
                "final_bookmark":"after",
                "provider_status":"complete",
                "provider_success":true,
                "state":"provider_complete",
            }
        })
    };
    let persist = |store: &StateStore, plan: &PlanV1, value: &Value| {
        let hash = store
            .record_d1_import_checkpoint(&plan.operation_id, value)
            .expect("checkpoint");
        assert_eq!(
            store
                .write_evidence(EvidenceClass::Apply, value)
                .expect("checkpoint evidence")
                .content_hash,
            hash
        );
        hash
    };
    let d1_target = || {
        json!({
            "account_id":contract.account_id,
            "database_id":contract.database_id,
        })
    };

    let missing_root = tempfile::tempdir().expect("missing root");
    let (missing_store, missing_plan) = build(missing_root.path());
    assert!(
        exact_durable_provider_complete_boundary(
            &missing_store,
            missing_plan.operation_id.as_str()
        )
        .is_err()
    );

    let evidence_failure_root = tempfile::tempdir().expect("evidence failure root");
    let (evidence_failure_store, evidence_failure_plan) = build(evidence_failure_root.path());
    persist(
        &evidence_failure_store,
        &evidence_failure_plan,
        &accepted_ingest(&evidence_failure_plan, d1_target()),
    );
    let evidence_failure = checkpoint(&evidence_failure_plan, d1_target());
    evidence_failure_store
        .record_d1_import_checkpoint(&evidence_failure_plan.operation_id, &evidence_failure)
        .expect("checkpoint without evidence");
    assert!(
        exact_durable_provider_complete_boundary(
            &evidence_failure_store,
            evidence_failure_plan.operation_id.as_str()
        )
        .is_err(),
        "a checkpoint whose matching apply evidence did not persist cannot authorize Running"
    );

    let exact_root = tempfile::tempdir().expect("exact root");
    let (exact_store, exact_plan) = build(exact_root.path());
    persist(
        &exact_store,
        &exact_plan,
        &accepted_ingest(&exact_plan, d1_target()),
    );
    let exact = checkpoint(&exact_plan, d1_target());
    let hash = persist(&exact_store, &exact_plan, &exact);
    assert_eq!(
        exact_durable_provider_complete_boundary(&exact_store, &exact_plan.operation_id)
            .expect("exact durable completion")
            .evidence_hash,
        hash
    );
    exact_store
        .record_d1_import_checkpoint(&exact_plan.operation_id, &exact)
        .expect("duplicate checkpoint");
    assert!(
        exact_durable_provider_complete_boundary(&exact_store, &exact_plan.operation_id).is_err()
    );

    let mismatch_root = tempfile::tempdir().expect("mismatch root");
    let (mismatch_store, mismatch_plan) = build(mismatch_root.path());
    persist(
        &mismatch_store,
        &mismatch_plan,
        &accepted_ingest(&mismatch_plan, d1_target()),
    );
    let mismatch = checkpoint(
        &mismatch_plan,
        json!({
            "account_id":contract.account_id,
            "database_id":"different-database",
        }),
    );
    persist(&mismatch_store, &mismatch_plan, &mismatch);
    assert!(
        exact_durable_provider_complete_boundary(&mismatch_store, &mismatch_plan.operation_id)
            .is_err()
    );

    for (pointer, replacement) in [
        ("/performed", json!(false)),
        ("/rectification_required", json!(true)),
        ("/receipt/provider", json!("different-provider")),
        ("/receipt/effect", json!("different-effect")),
        ("/receipt/response_action", json!("ingest")),
        ("/receipt/no_replay", json!(false)),
        ("/receipt/migration_id", json!("0142")),
        ("/receipt/source_sha256", json!("sha256:different")),
        ("/receipt/source_md5", json!("different")),
        ("/receipt/source_bytes", json!(1)),
        ("/receipt/source_authority_hash", json!("sha256:different")),
        ("/receipt/stage_identity_hash", json!("sha256:different")),
        ("/receipt/plan_input_hash", json!("sha256:different")),
        ("/receipt/prerequisites/migration_id", json!("0142")),
        ("/receipt/at_bookmark", json!("different")),
        ("/receipt/final_bookmark", json!("")),
        ("/receipt/provider_status", json!("active")),
        ("/receipt/provider_success", json!(false)),
        ("/receipt/state", json!("different")),
    ] {
        let mutation_root = tempfile::tempdir().expect("mutation root");
        let (mutation_store, mutation_plan) = build(mutation_root.path());
        persist(
            &mutation_store,
            &mutation_plan,
            &accepted_ingest(&mutation_plan, d1_target()),
        );
        let mut mutation = checkpoint(&mutation_plan, d1_target());
        *mutation
            .pointer_mut(pointer)
            .expect("completion mutation pointer") = replacement;
        persist(&mutation_store, &mutation_plan, &mutation);
        assert!(
            exact_durable_provider_complete_boundary(&mutation_store, &mutation_plan.operation_id)
                .is_err(),
            "every durable-completion consumer must reject drift at {pointer}"
        );
    }

    let deleted_root = tempfile::tempdir().expect("deleted evidence root");
    let (deleted_store, deleted_plan) = build(deleted_root.path());
    persist(
        &deleted_store,
        &deleted_plan,
        &accepted_ingest(&deleted_plan, d1_target()),
    );
    let deleted = checkpoint(&deleted_plan, d1_target());
    let deleted_hash = persist(&deleted_store, &deleted_plan, &deleted);
    std::fs::remove_file(
        deleted_store
            .paths()
            .data_dir
            .join("evidence")
            .join(format!(
                "{}.json",
                deleted_hash.trim_start_matches("sha256:")
            )),
    )
    .expect("delete provider-complete evidence");
    assert!(
        exact_durable_provider_complete_boundary(&deleted_store, &deleted_plan.operation_id)
            .is_err()
    );

    let corrupt_root = tempfile::tempdir().expect("corrupt evidence root");
    let (corrupt_store, corrupt_plan) = build(corrupt_root.path());
    persist(
        &corrupt_store,
        &corrupt_plan,
        &accepted_ingest(&corrupt_plan, d1_target()),
    );
    let corrupt = checkpoint(&corrupt_plan, d1_target());
    let corrupt_hash = persist(&corrupt_store, &corrupt_plan, &corrupt);
    std::fs::write(
        corrupt_store
            .paths()
            .data_dir
            .join("evidence")
            .join(format!(
                "{}.json",
                corrupt_hash.trim_start_matches("sha256:")
            )),
        b"{\"mismatched\":true}\n",
    )
    .expect("corrupt provider-complete evidence");
    assert!(
        exact_durable_provider_complete_boundary(&corrupt_store, &corrupt_plan.operation_id)
            .is_err()
    );

    let duplicate_ingest_root = tempfile::tempdir().expect("duplicate ingest root");
    let (duplicate_ingest_store, duplicate_ingest_plan) = build(duplicate_ingest_root.path());
    let duplicate_ingest = accepted_ingest(&duplicate_ingest_plan, d1_target());
    persist(
        &duplicate_ingest_store,
        &duplicate_ingest_plan,
        &duplicate_ingest,
    );
    duplicate_ingest_store
        .record_d1_import_checkpoint(&duplicate_ingest_plan.operation_id, &duplicate_ingest)
        .expect("duplicate accepted-ingest checkpoint");
    let complete = checkpoint(&duplicate_ingest_plan, d1_target());
    persist(&duplicate_ingest_store, &duplicate_ingest_plan, &complete);
    assert!(
        exact_durable_provider_complete_boundary(
            &duplicate_ingest_store,
            &duplicate_ingest_plan.operation_id
        )
        .is_err()
    );

    for (pointer, replacement) in [
        ("/plan/profile_id", json!("")),
        ("/plan/catalog_hash", json!("sha256:different")),
        ("/pins/catalog_hash", json!("sha256:different")),
        ("/pins/credential_generation_id", json!("")),
    ] {
        let plan_drift_root = tempfile::tempdir().expect("PlanV2 drift root");
        let (plan_drift_store, plan_drift) = build(plan_drift_root.path());
        persist(
            &plan_drift_store,
            &plan_drift,
            &accepted_ingest(&plan_drift, d1_target()),
        );
        persist(
            &plan_drift_store,
            &plan_drift,
            &checkpoint(&plan_drift, d1_target()),
        );
        let path = plan_drift_store
            .paths()
            .data_dir
            .join("plans-v2")
            .join(format!("{}.json", plan_drift.operation_id));
        let mut document: Value =
            serde_json::from_slice(&std::fs::read(&path).expect("read PlanV2"))
                .expect("decode PlanV2");
        *document
            .pointer_mut(pointer)
            .expect("PlanV2 mutation pointer") = replacement;
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&document).expect("encode drifted PlanV2"),
        )
        .expect("write drifted PlanV2");
        assert!(
            exact_durable_provider_complete_boundary(&plan_drift_store, &plan_drift.operation_id)
                .is_err(),
            "every durable-completion consumer must reject PlanV2 drift at {pointer}"
        );
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one state-machine regression proves known provider failure versus transport ambiguity"
)]
pub(super) fn approved_mln_provider_failure_uses_its_durable_receipt_not_transport_unknown() {
    let mut catalog = CatalogSnapshot {
        schema_version: 1,
        generated_at: Utc::now(),
        source_url: "test://native".to_owned(),
        source_hash: "sha256:test".to_owned(),
        schema_hash: String::new(),
        capabilities: BTreeMap::new(),
    };
    ingest_native_control_capabilities(&mut catalog).expect("native overlay");
    let capability = catalog
        .capabilities
        .remove("d1-import-approved-mln-migration")
        .expect("native import capability");
    let contract = capability
        .d1_approved_mln_import
        .as_ref()
        .expect("import contract");
    let build_plan = || {
        let mut plan = PlanV1::draft(
            "profile-a",
            &contract.account_id,
            "catalog-sha",
            capability.clone(),
            json!({}),
        )
        .expect("import plan");
        plan.input = serde_json::to_value(CallInput {
            selectors: json!({
                "account_id":contract.account_id,
                "database_id":contract.database_id,
            }),
            body: Some(json!({"migration_id":"0143"})),
            ..CallInput::default()
        })
        .expect("input");
        plan.refresh_hash().expect("refresh import plan");
        plan.status = PlanStatus::RectificationRequired;
        plan
    };
    let checkpoint = |plan: &PlanV1| {
        json!({
            "schema_version":1,
            "operation_id":plan.operation_id,
            "step":"ingest_response",
            "performed":true,
            "rectification_required":true,
            "receipt":{
                "http_status":200,
                "success":true,
                "response_action":"ingest",
                "target":{
                    "account_id":contract.account_id,
                    "database_id":contract.database_id,
                },
                "plan_input_hash":hash_value(&plan.input).expect("input hash"),
                "no_replay":true,
                "result":{
                    "type":"import",
                    "status":"error",
                    "success":false,
                    "at_bookmark":null,
                    "provider_error_present":true,
                },
                "errors":[],
                "etag":null,
                "cf_ray":null,
            }
        })
    };

    let uncertainty_root = tempfile::tempdir().expect("uncertainty root");
    let uncertainty_store = StateStore::open(RuntimePaths::from_root(uncertainty_root.path()))
        .expect("uncertainty store");
    let uncertainty_plan = build_plan();
    let uncertainty = D1ImportCheckpointV1 {
        schema_version: 1,
        operation_id: uncertainty_plan.operation_id.clone(),
        step: "upload_send_uncertain".to_owned(),
        performed: true,
        rectification_required: true,
        receipt: json!({
            "provider":"cloudflare",
            "effect":"d1_import_transport_uncertain",
            "transport_stage":"upload",
            "migration_id":"0143",
            "target":{
                "account_id":contract.account_id,
                "database_id":contract.database_id,
            },
            "plan_input_hash":hash_value(&uncertainty_plan.input).expect("input hash"),
            "outcome":"unknown",
            "receipt_available":false,
            "no_replay":true,
        }),
    };
    persist_d1_import_checkpoint(
        &uncertainty_store,
        &uncertainty_plan.operation_id,
        &uncertainty,
    )
    .expect("durable uncertainty checkpoint");
    let uncertainty_value = serde_json::to_value(&uncertainty).expect("uncertainty value");
    let uncertainty_hash = uncertainty_store
        .read_d1_import_checkpoints(&uncertainty_plan.operation_id)
        .expect("uncertainty checkpoints")
        .into_iter()
        .find(|(_, checkpoint)| checkpoint == &uncertainty_value)
        .map(|(hash, _)| hash)
        .expect("uncertainty checkpoint hash");
    assert_eq!(
        uncertainty_store
            .read_evidence_value(&uncertainty_hash)
            .expect("durable uncertainty evidence"),
        uncertainty_value
    );
    let timeout_envelope = approved_mln_import_execution_error_envelope(
        &uncertainty_store,
        &mut uncertainty_plan.clone(),
        CloudflareError::InvalidRequestBody(
            "D1 import upload transport failed; presigned URL redacted; do not replay".to_owned(),
        ),
        &MemorySecretStore::default(),
    );
    assert_eq!(timeout_envelope.result["receipt_available"], false);
    assert!(
        timeout_envelope
            .verification
            .basis
            .as_deref()
            .is_none_or(|basis| !basis.contains("upload response is durable"))
    );

    for (name, status, success, etag_present, expected_outcome) in [
        (
            "missing etag",
            200,
            true,
            false,
            "upload_integrity_rejected",
        ),
        (
            "mismatched etag",
            200,
            true,
            true,
            "upload_integrity_rejected",
        ),
        ("provider rejection", 403, false, false, "upload_rejected"),
    ] {
        let upload_root = tempfile::tempdir().expect("upload response root");
        let upload_store =
            StateStore::open(RuntimePaths::from_root(upload_root.path())).expect(name);
        let mut upload_plan = build_plan();
        let upload_checkpoint = D1ImportCheckpointV1 {
            schema_version: 1,
            operation_id: upload_plan.operation_id.clone(),
            step: "upload_response".to_owned(),
            performed: true,
            rectification_required: true,
            receipt: json!({
                "provider":"cloudflare",
                "effect":"d1_import_upload_response",
                "migration_id":"0143",
                "target":{
                    "account_id":contract.account_id,
                    "database_id":contract.database_id,
                },
                "plan_input_hash":hash_value(&upload_plan.input).expect("input hash"),
                "http_status":status,
                "success":success,
                "etag_present":etag_present,
                "etag_matches":false,
                "no_replay":true,
            }),
        };
        persist_d1_import_checkpoint(&upload_store, &upload_plan.operation_id, &upload_checkpoint)
            .expect("durable upload response");
        let envelope = approved_mln_import_execution_error_envelope(
            &upload_store,
            &mut upload_plan,
            CloudflareError::D1ImportUploadResponseIntegrityFailure,
            &MemorySecretStore::default(),
        );
        assert!(envelope.performed, "{name}");
        assert_eq!(envelope.result["outcome"], expected_outcome, "{name}");
        assert_eq!(envelope.result["receipt_available"], true, "{name}");
        assert_eq!(envelope.result["http_status"], status, "{name}");
        assert_eq!(envelope.result["etag_present"], etag_present, "{name}");
        assert_eq!(envelope.result["etag_matches"], false, "{name}");
        assert_ne!(upload_plan.status, PlanStatus::Running, "{name}");
        assert!(
            !envelope.result.to_string().contains("etag_sha256"),
            "{name}"
        );
    }

    let missing_evidence_root = tempfile::tempdir().expect("missing evidence root");
    let missing_evidence_store =
        StateStore::open(RuntimePaths::from_root(missing_evidence_root.path()))
            .expect("missing evidence store");
    let mut missing_evidence_plan = build_plan();
    let missing_evidence_checkpoint = json!({
        "schema_version":1,
        "operation_id":missing_evidence_plan.operation_id,
        "step":"upload_response",
        "performed":true,
        "rectification_required":true,
        "receipt":{
            "provider":"cloudflare",
            "effect":"d1_import_upload_response",
            "migration_id":"0143",
            "target":{
                "account_id":contract.account_id,
                "database_id":contract.database_id,
            },
            "plan_input_hash":hash_value(&missing_evidence_plan.input).expect("input hash"),
            "http_status":200,
            "success":true,
            "etag_present":false,
            "etag_matches":false,
            "no_replay":true,
        }
    });
    missing_evidence_store
        .record_d1_import_checkpoint(
            &missing_evidence_plan.operation_id,
            &missing_evidence_checkpoint,
        )
        .expect("checkpoint without evidence");
    let invalid_receipt = approved_mln_import_execution_error_envelope(
        &missing_evidence_store,
        &mut missing_evidence_plan,
        CloudflareError::D1ImportUploadResponseIntegrityFailure,
        &MemorySecretStore::default(),
    );
    assert_eq!(
        invalid_receipt.result["outcome"],
        "upload_rejected_receipt_invalid"
    );
    assert_eq!(invalid_receipt.result["receipt_available"], false);

    let duplicate_root = tempfile::tempdir().expect("duplicate response root");
    let duplicate_store = StateStore::open(RuntimePaths::from_root(duplicate_root.path()))
        .expect("duplicate response store");
    let mut duplicate_plan = build_plan();
    let duplicate_checkpoint = |status: u16, success: bool| D1ImportCheckpointV1 {
        schema_version: 1,
        operation_id: duplicate_plan.operation_id.clone(),
        step: "upload_response".to_owned(),
        performed: true,
        rectification_required: true,
        receipt: json!({
            "provider":"cloudflare",
            "effect":"d1_import_upload_response",
            "migration_id":"0143",
            "target":{
                "account_id":contract.account_id,
                "database_id":contract.database_id,
            },
            "plan_input_hash":hash_value(&duplicate_plan.input).expect("input hash"),
            "http_status":status,
            "success":success,
            "etag_present":false,
            "etag_matches":false,
            "no_replay":true,
        }),
    };
    for checkpoint in [
        duplicate_checkpoint(200, true),
        duplicate_checkpoint(403, false),
    ] {
        persist_d1_import_checkpoint(&duplicate_store, &duplicate_plan.operation_id, &checkpoint)
            .expect("duplicate durable response");
    }
    let duplicate_receipt = approved_mln_import_execution_error_envelope(
        &duplicate_store,
        &mut duplicate_plan,
        CloudflareError::D1ImportUploadResponseIntegrityFailure,
        &MemorySecretStore::default(),
    );
    assert_eq!(
        duplicate_receipt.result["outcome"],
        "upload_rejected_receipt_invalid"
    );
    assert_eq!(duplicate_receipt.result["receipt_available"], false);

    let init_root = tempfile::tempdir().expect("known init response root");
    let init_store =
        StateStore::open(RuntimePaths::from_root(init_root.path())).expect("init store");
    let mut init_plan = build_plan();
    let init_checkpoint = D1ImportCheckpointV1 {
        schema_version: 1,
        operation_id: init_plan.operation_id.clone(),
        step: "init_response".to_owned(),
        performed: true,
        rectification_required: true,
        receipt: json!({
            "http_status":200,
            "success":true,
            "response_action":"init",
            "provider":"cloudflare",
            "effect":"d1_import_response",
            "migration_id":"0143",
            "target":{
                "account_id":contract.account_id,
                "database_id":contract.database_id,
            },
            "plan_input_hash":hash_value(&init_plan.input).expect("input hash"),
            "result":{
                "type":"import",
                "status":null,
                "success":true,
                "at_bookmark_present":false,
                "at_bookmark_is_string":false,
                "upload_url_present":true,
                "upload_url_sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "upload_url_host_is_exact_account_endpoint":true,
                "upload_url_host_is_cloudflare_r2":true,
                "filename_present":true,
                "filename_sha256":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "filename_shape_valid":true,
                "provider_error_present":true,
                "cfctl_classification_failure":"nested_state_rejected",
            },
            "errors":[],
            "provider_errors_present":true,
            "no_replay":true,
            "etag_present":true,
            "etag_sha256":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "cf_ray":"safe-ray",
        }),
    };
    persist_d1_import_checkpoint(&init_store, &init_plan.operation_id, &init_checkpoint)
        .expect("durable init response");
    let init_envelope = approved_mln_import_execution_error_envelope(
        &init_store,
        &mut init_plan,
        CloudflareError::D1ImportInitResponseFailure,
        &MemorySecretStore::default(),
    );
    assert!(init_envelope.performed);
    assert_eq!(init_envelope.result["outcome"], "invalid_provider_response");
    assert_eq!(init_envelope.result["receipt_available"], true);
    assert_ne!(init_plan.status, PlanStatus::Running);
    assert!(
        rectify_approved_mln_import(&init_store, &mut init_plan).is_err(),
        "provider-error init receipts must remain unrectified"
    );
    for forbidden in ["X-Amz-Signature", "SECRET", "upload_url\":"] {
        assert!(!init_envelope.result.to_string().contains(forbidden));
        assert!(
            !init_envelope
                .verification
                .basis
                .as_deref()
                .unwrap_or_default()
                .contains(forbidden)
        );
    }

    let abandoned_root = tempfile::tempdir().expect("abandoned init root");
    let abandoned_store = StateStore::open(RuntimePaths::from_root(abandoned_root.path()))
        .expect("abandoned init store");
    let mut abandoned_plan = build_plan();
    abandoned_plan.status = PlanStatus::Draft;
    abandoned_plan
        .approve(true, None)
        .expect("approve abandoned plan");
    abandoned_plan
        .mark_consumed()
        .expect("consume abandoned plan");
    abandoned_plan
        .record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("persist abandoned boundary attempt");
    let abandoned_checkpoint = D1ImportCheckpointV1 {
        schema_version: 1,
        operation_id: abandoned_plan.operation_id.clone(),
        step: "init_response".to_owned(),
        performed: true,
        rectification_required: true,
        receipt: json!({
            "http_status":200,
            "success":true,
            "response_action":"init",
            "provider":"cloudflare",
            "effect":"d1_import_response",
            "migration_id":"0143",
            "target":{
                "account_id":contract.account_id,
                "database_id":contract.database_id,
            },
            "plan_input_hash":hash_value(&abandoned_plan.input).expect("input hash"),
            "result":{
                "type":null,
                "status":null,
                "success":true,
                "at_bookmark_present":false,
                "at_bookmark_is_string":false,
                "upload_url_present":true,
                "upload_url_sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "upload_url_host_is_exact_account_endpoint":false,
                "upload_url_host_is_cloudflare_r2":true,
                "filename_present":true,
                "filename_sha256":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "filename_shape_valid":true,
                "provider_error_present":false,
                "cfctl_classification_failure":"upload_url_authority_or_shape_rejected",
            },
            "errors":[],
            "provider_errors_present":false,
            "no_replay":true,
            "etag_present":false,
            "etag_sha256":null,
            "cf_ray":"safe-ray",
        }),
    };
    persist_d1_import_checkpoint(
        &abandoned_store,
        &abandoned_plan.operation_id,
        &abandoned_checkpoint,
    )
    .expect("durable abandoned init response");
    let rectified = rectify_approved_mln_import(&abandoned_store, &mut abandoned_plan)
        .expect("rectify interrupted abandoned unuploaded session");
    assert!(rectified.ok);
    assert!(!rectified.performed);
    assert_eq!(rectified.result["upload_performed"], false);
    assert_eq!(rectified.result["database_write_performed"], false);
    assert_eq!(abandoned_plan.status, PlanStatus::Rectified);
    assert_eq!(abandoned_plan.transaction_stage, TransactionStageV1::Closed);
    assert_eq!(
        abandoned_store
            .read_d1_import_checkpoints(&abandoned_plan.operation_id)
            .expect("unchanged abandoned checkpoint set")
            .len(),
        1
    );

    let resumed_root = tempfile::tempdir().expect("resumed init root");
    let resumed_store =
        StateStore::open(RuntimePaths::from_root(resumed_root.path())).expect("resumed init store");
    let mut resumed_plan = build_plan();
    resumed_plan.status = PlanStatus::Draft;
    resumed_plan
        .approve(true, None)
        .expect("approve resumed plan");
    resumed_plan.mark_consumed().expect("consume resumed plan");
    resumed_plan
        .record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("persist resumed boundary attempt");
    let mut resumed_checkpoint = abandoned_checkpoint.clone();
    resumed_checkpoint
        .operation_id
        .clone_from(&resumed_plan.operation_id);
    resumed_checkpoint.receipt["plan_input_hash"] =
        json!(hash_value(&resumed_plan.input).expect("resumed input hash"));
    persist_d1_import_checkpoint(
        &resumed_store,
        &resumed_plan.operation_id,
        &resumed_checkpoint,
    )
    .expect("durable resumed init response");
    let (resumed_evidence, _) =
        super::exact_durable_init_response_failure(&resumed_store, &resumed_plan)
            .expect("exact resumed init response");
    resumed_plan.status = PlanStatus::RectificationRequired;
    resumed_plan
        .record_transaction_stage_with_artifact(
            TransactionStageV1::BoundaryResponsePersisted,
            json!({
                "adapter":"dynamic_api",
                "performed":true,
                "success":false,
                "outcome":"invalid_provider_response",
                "receipt_available":true,
                "init_response_evidence_hash":resumed_evidence.content_hash,
            }),
        )
        .expect("persist interrupted boundary response");
    resumed_store
        .save_plan(&resumed_plan)
        .expect("persist interrupted recovery state");
    let mut reloaded = resumed_store
        .load_plan(&resumed_plan.operation_id)
        .expect("reload interrupted recovery state");
    let resumed = rectify_approved_mln_import(&resumed_store, &mut reloaded)
        .expect("resume interrupted init-only rectification");
    assert!(resumed.ok);
    assert!(!resumed.performed);
    assert_eq!(resumed.result["upload_performed"], false);
    assert_eq!(resumed.result["database_write_performed"], false);
    assert_eq!(reloaded.status, PlanStatus::Rectified);
    assert_eq!(reloaded.transaction_stage, TransactionStageV1::Closed);

    for (action, step, error) in [
        (
            "ingest",
            "ingest_response",
            CloudflareError::D1ImportIngestResponseFailure,
        ),
        (
            "poll",
            "poll_response_1",
            CloudflareError::D1ImportPollResponseFailure,
        ),
    ] {
        let action_root = tempfile::tempdir().expect("known action response root");
        let action_store = StateStore::open(RuntimePaths::from_root(action_root.path()))
            .expect("action response store");
        let mut action_plan = build_plan();
        let action_checkpoint = D1ImportCheckpointV1 {
            schema_version: 1,
            operation_id: action_plan.operation_id.clone(),
            step: step.to_owned(),
            performed: true,
            rectification_required: true,
            receipt: json!({
                "http_status":200,
                "success":true,
                "response_action":action,
                "provider":"cloudflare",
                "effect":"d1_import_response",
                "migration_id":"0143",
                "target":{
                    "account_id":contract.account_id,
                    "database_id":contract.database_id,
                },
                "plan_input_hash":hash_value(&action_plan.input).expect("input hash"),
                "result":{
                    "type":"import",
                    "status":"unsupported",
                    "success":true,
                    "at_bookmark":"owned",
                    "result":{"final_bookmark":null},
                    "provider_error_present":false,
                },
                "errors":[],
                "provider_errors_present":false,
                "no_replay":true,
                "etag_present":false,
                "etag_sha256":null,
                "cf_ray":null,
            }),
        };
        persist_d1_import_checkpoint(&action_store, &action_plan.operation_id, &action_checkpoint)
            .expect("durable action response");
        let action_envelope = approved_mln_import_execution_error_envelope(
            &action_store,
            &mut action_plan,
            error,
            &MemorySecretStore::default(),
        );
        assert!(action_envelope.performed, "{action}");
        assert_eq!(
            action_envelope.result["outcome"], "invalid_provider_response",
            "{action}"
        );
        assert_eq!(
            action_envelope.result["receipt_available"], true,
            "{action}"
        );
        assert_eq!(action_envelope.result["response_action"], action);
        assert_ne!(action_plan.status, PlanStatus::Running);
        assert!(!action_envelope.result.to_string().contains("SECRET"));
    }

    let exhaustion_root = tempfile::tempdir().expect("poll exhaustion root");
    let exhaustion_store = StateStore::open(RuntimePaths::from_root(exhaustion_root.path()))
        .expect("poll exhaustion store");
    let mut exhaustion_plan = build_plan();
    exhaustion_plan
        .capability
        .d1_approved_mln_import
        .as_mut()
        .expect("import contract")
        .max_poll_attempts = 2;
    exhaustion_plan.targets = json!({
        "adapter":{
            "approved_mln_import":{
                "sha256":"sha256:source",
            }
        }
    });
    exhaustion_plan
        .refresh_hash()
        .expect("exhaustion plan hash");
    let exhaustion_target = json!({
        "account_id":contract.account_id,
        "database_id":contract.database_id,
    });
    let input_hash = hash_value(&exhaustion_plan.input).expect("input hash");
    let accepted = D1ImportCheckpointV1 {
        schema_version: 1,
        operation_id: exhaustion_plan.operation_id.clone(),
        step: "ingest_response".to_owned(),
        performed: true,
        rectification_required: false,
        receipt: json!({
            "http_status":200,
            "success":true,
            "response_action":"ingest",
            "provider":"cloudflare",
            "effect":"d1_import_ingest_accepted",
            "migration_id":"0143",
            "target":exhaustion_target,
            "plan_input_hash":input_hash,
            "result":{
                "type":"import",
                "status":"active",
                "success":true,
                "at_bookmark":"owned",
                "result":{"final_bookmark":null},
                "provider_error_present":false,
            },
            "errors":[],
            "provider_errors_present":false,
            "no_replay":false,
            "etag_present":false,
            "etag_sha256":null,
            "cf_ray":null,
        }),
    };
    persist_d1_import_checkpoint(&exhaustion_store, &exhaustion_plan.operation_id, &accepted)
        .expect("accepted ingest authority");
    let exhaustion_operation_id = exhaustion_plan.operation_id.clone();
    let poll_checkpoint = |attempt| D1ImportCheckpointV1 {
        schema_version: 1,
        operation_id: exhaustion_operation_id.clone(),
        step: format!("poll_response_{attempt}"),
        performed: true,
        rectification_required: false,
        receipt: json!({
            "http_status":200,
            "success":true,
            "response_action":"poll",
            "provider":"cloudflare",
            "effect":"d1_import_response",
            "migration_id":"0143",
            "target":exhaustion_target,
            "plan_input_hash":input_hash,
            "result":{
                "type":"import",
                "status":"active",
                "success":true,
                "at_bookmark":"owned",
                "result":{"final_bookmark":null},
                "provider_error_present":false,
            },
            "errors":[],
            "provider_errors_present":false,
            "no_replay":false,
            "etag_present":false,
            "etag_sha256":null,
            "cf_ray":null,
        }),
    };
    for attempt in 1..=2 {
        let poll = poll_checkpoint(attempt);
        persist_d1_import_checkpoint(&exhaustion_store, &exhaustion_plan.operation_id, &poll)
            .expect("durable in-progress poll");
    }
    let exact_poll = serde_json::to_value(poll_checkpoint(1)).expect("exact poll");
    let exact_poll_hash = exhaustion_store
        .read_d1_import_checkpoints(&exhaustion_plan.operation_id)
        .expect("poll checkpoints")
        .into_iter()
        .find(|(_, checkpoint)| checkpoint == &exact_poll)
        .map(|(hash, _)| hash)
        .expect("exact poll hash");
    assert!(exact_in_progress_poll_receipt(
        &exhaustion_store,
        &exhaustion_plan,
        &exact_poll_hash,
        &exact_poll,
        1,
        &exhaustion_target,
        &input_hash,
        "0143",
        "owned",
    ));
    for (pointer, replacement) in [
        ("/schema_version", json!(2)),
        ("/operation_id", json!("different")),
        ("/step", json!("poll_response_2")),
        ("/performed", json!(false)),
        ("/rectification_required", json!(true)),
        ("/receipt/http_status", json!(201)),
        ("/receipt/success", json!(false)),
        ("/receipt/response_action", json!("ingest")),
        ("/receipt/provider", json!("different")),
        ("/receipt/effect", json!("different")),
        ("/receipt/migration_id", json!("0142")),
        ("/receipt/target/database_id", json!("different")),
        ("/receipt/plan_input_hash", json!("sha256:different")),
        ("/receipt/result/type", json!("export")),
        ("/receipt/result/status", json!("complete")),
        ("/receipt/result/success", json!(false)),
        ("/receipt/result/at_bookmark", json!("grafted")),
        ("/receipt/result/provider_error_present", json!(true)),
        ("/receipt/result/result/final_bookmark", json!("unexpected")),
        ("/receipt/errors", json!(["SECRET"])),
        ("/receipt/provider_errors_present", json!(true)),
        ("/receipt/no_replay", json!(true)),
        ("/receipt/etag_present", json!(true)),
        ("/receipt/etag_sha256", json!("raw-etag")),
        ("/receipt/unknown", json!("SECRET")),
    ] {
        let mut drifted = exact_poll.clone();
        if pointer == "/receipt/unknown" {
            drifted["receipt"]["unknown"] = replacement;
        } else {
            *drifted.pointer_mut(pointer).expect("mutation pointer") = replacement;
        }
        assert!(
            !exact_in_progress_poll_receipt(
                &exhaustion_store,
                &exhaustion_plan,
                &exact_poll_hash,
                &drifted,
                1,
                &exhaustion_target,
                &input_hash,
                "0143",
                "owned",
            ),
            "{pointer}"
        );
    }
    assert!(
        !exact_in_progress_poll_receipt(
            &exhaustion_store,
            &exhaustion_plan,
            "sha256:missing",
            &exact_poll,
            1,
            &exhaustion_target,
            &input_hash,
            "0143",
            "owned",
        ),
        "missing or mismatched evidence must fail"
    );
    let exhausted = D1ImportCheckpointV1 {
        schema_version: 1,
        operation_id: exhaustion_plan.operation_id.clone(),
        step: "poll_in_progress_exhausted".to_owned(),
        performed: true,
        rectification_required: true,
        receipt: json!({
            "provider":"cloudflare",
            "effect":"d1_import_poll_in_progress_exhausted",
            "migration_id":"0143",
            "target":exhaustion_target,
            "plan_input_hash":input_hash,
            "source_sha256":"sha256:source",
            "at_bookmark":"owned",
            "attempt_count":2,
            "attempt_bound":2,
            "outcome":"poll_in_progress_exhausted",
            "receipt_available":true,
            "no_replay":true,
        }),
    };
    persist_d1_import_checkpoint(&exhaustion_store, &exhaustion_plan.operation_id, &exhausted)
        .expect("durable exhaustion");
    let exhaustion_envelope = approved_mln_import_execution_error_envelope(
        &exhaustion_store,
        &mut exhaustion_plan,
        CloudflareError::D1ImportPollInProgressExhausted,
        &MemorySecretStore::default(),
    );
    assert!(exhaustion_envelope.performed);
    assert_eq!(
        exhaustion_envelope.result["outcome"],
        "poll_in_progress_exhausted"
    );
    assert_eq!(exhaustion_envelope.result["receipt_available"], true);
    assert_eq!(exhaustion_envelope.result["attempt_count"], 2);
    assert_eq!(exhaustion_envelope.result["attempt_bound"], 2);
    assert!(
        exhaustion_envelope.result["accepted_ingest_evidence_hash"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("sha256:"))
    );
    assert_ne!(exhaustion_plan.status, PlanStatus::Running);
    persist_d1_import_checkpoint(
        &exhaustion_store,
        &exhaustion_plan.operation_id,
        &poll_checkpoint(2),
    )
    .expect("later duplicate poll");
    assert!(
        exact_durable_poll_exhaustion(&exhaustion_store, &exhaustion_plan).is_err(),
        "a duplicate poll after exhaustion must invalidate chronology and tail authority"
    );

    let root = tempfile::tempdir().expect("known failure root");
    let store =
        StateStore::open(RuntimePaths::from_root(root.path())).expect("known failure store");
    let mut plan = build_plan();
    let receipt = checkpoint(&plan);
    let hash = store
        .record_d1_import_checkpoint(&plan.operation_id, &receipt)
        .expect("provider-failure checkpoint");
    assert_eq!(
        store
            .write_evidence(EvidenceClass::Apply, &receipt)
            .expect("provider-failure evidence")
            .content_hash,
        hash
    );
    let envelope = approved_mln_import_execution_error_envelope(
        &store,
        &mut plan,
        CloudflareError::D1ImportProviderFailure,
        &MemorySecretStore::default(),
    );
    assert!(!envelope.ok);
    assert!(envelope.performed);
    assert_eq!(envelope.result["outcome"], "provider_rejected");
    assert_eq!(envelope.result["receipt_available"], true);
    assert!(
        envelope
            .verification
            .basis
            .as_deref()
            .is_some_and(|basis| basis.contains("provider-failure response is durable"))
    );
    assert!(
        !envelope
            .result
            .to_string()
            .contains("provider rejected import")
    );
    assert_eq!(plan.status, PlanStatus::RectificationRequired);
    assert_ne!(plan.status, PlanStatus::Running);

    let init_root = tempfile::tempdir().expect("init failure root");
    let init_store =
        StateStore::open(RuntimePaths::from_root(init_root.path())).expect("init store");
    let mut init_plan = build_plan();
    let mut init_receipt = checkpoint(&init_plan);
    init_receipt["step"] = json!("init_response");
    init_receipt["receipt"]["response_action"] = json!("init");
    let init_hash = init_store
        .record_d1_import_checkpoint(&init_plan.operation_id, &init_receipt)
        .expect("init failure checkpoint");
    assert_eq!(
        init_store
            .write_evidence(EvidenceClass::Apply, &init_receipt)
            .expect("init failure evidence")
            .content_hash,
        init_hash
    );
    let init_envelope = approved_mln_import_execution_error_envelope(
        &init_store,
        &mut init_plan,
        CloudflareError::D1ImportProviderFailure,
        &MemorySecretStore::default(),
    );
    assert_eq!(init_envelope.result["outcome"], "provider_rejected");
    assert_eq!(init_envelope.result["receipt_available"], true);
    assert_ne!(init_plan.status, PlanStatus::Running);

    let poll_root = tempfile::tempdir().expect("poll failure root");
    let poll_store =
        StateStore::open(RuntimePaths::from_root(poll_root.path())).expect("poll store");
    let poll_plan = build_plan();
    let mut accepted_ingest = checkpoint(&poll_plan);
    accepted_ingest["rectification_required"] = json!(false);
    accepted_ingest["receipt"]["provider"] = json!("cloudflare");
    accepted_ingest["receipt"]["effect"] = json!("d1_import_ingest_accepted");
    accepted_ingest["receipt"]["migration_id"] = json!("0143");
    accepted_ingest["receipt"]["no_replay"] = json!(false);
    accepted_ingest["receipt"]["result"] = json!({
        "type":"import",
        "status":"active",
        "success":true,
        "at_bookmark":"before",
    });
    let accepted_hash = poll_store
        .record_d1_import_checkpoint(&poll_plan.operation_id, &accepted_ingest)
        .expect("accepted ingest checkpoint");
    assert_eq!(
        poll_store
            .write_evidence(EvidenceClass::Apply, &accepted_ingest)
            .expect("accepted ingest evidence")
            .content_hash,
        accepted_hash
    );
    let expected_target = json!({
        "account_id":contract.account_id,
        "database_id":contract.database_id,
    });
    let input_hash = hash_value(&poll_plan.input).expect("poll plan input hash");
    assert_eq!(
        exact_accepted_ingest_bookmarks(
            &poll_store,
            &poll_plan,
            &[(accepted_hash.clone(), accepted_ingest.clone())],
            &expected_target,
            &input_hash,
        ),
        vec!["before"]
    );

    for (pointer, replacement) in [
        ("/schema_version", json!(2)),
        ("/operation_id", json!("different-operation")),
        ("/step", json!("poll_response_1")),
        ("/performed", json!(false)),
        ("/rectification_required", json!(true)),
        ("/receipt/success", json!(false)),
        ("/receipt/response_action", json!("poll")),
        ("/receipt/provider", json!("different-provider")),
        ("/receipt/effect", json!("d1_import_response")),
        ("/receipt/migration_id", json!("0142")),
        (
            "/receipt/target",
            json!({
                "account_id":contract.account_id,
                "database_id":"different-database",
            }),
        ),
        ("/receipt/plan_input_hash", json!("sha256:different")),
        ("/receipt/no_replay", json!(true)),
        ("/receipt/result/type", json!("other")),
        ("/receipt/result/status", json!("complete")),
        ("/receipt/result/success", json!(false)),
        ("/receipt/result/at_bookmark", json!("")),
    ] {
        let mut drifted = accepted_ingest.clone();
        *drifted.pointer_mut(pointer).expect("mutation pointer") = replacement;
        let drifted_hash = poll_store
            .write_evidence(EvidenceClass::Apply, &drifted)
            .expect("drifted accepted-ingest evidence")
            .content_hash;
        assert!(
            exact_accepted_ingest_bookmarks(
                &poll_store,
                &poll_plan,
                &[(drifted_hash, drifted)],
                &expected_target,
                &input_hash,
            )
            .is_empty(),
            "accepted-ingest authority must reject drift at {pointer}"
        );
    }
    for (pointer, replacement) in [
        ("/receipt/result/provider_error_present", json!(true)),
        ("/receipt/result/error", json!({"code":7500})),
    ] {
        let mut errored = accepted_ingest.clone();
        errored
            .pointer_mut("/receipt/result")
            .and_then(Value::as_object_mut)
            .expect("result object")
            .insert(
                pointer.rsplit('/').next().expect("field").to_owned(),
                replacement,
            );
        let errored_hash = poll_store
            .write_evidence(EvidenceClass::Apply, &errored)
            .expect("errored accepted-ingest evidence")
            .content_hash;
        assert!(
            exact_accepted_ingest_bookmarks(
                &poll_store,
                &poll_plan,
                &[(errored_hash, errored)],
                &expected_target,
                &input_hash,
            )
            .is_empty(),
            "accepted-ingest authority must reject {pointer}"
        );
    }
    assert!(
        exact_accepted_ingest_bookmarks(
            &poll_store,
            &poll_plan,
            &[("sha256:missing".to_owned(), accepted_ingest.clone())],
            &expected_target,
            &input_hash,
        )
        .is_empty(),
        "accepted-ingest authority requires durable evidence"
    );
    let mismatched_hash = poll_store
        .write_evidence(EvidenceClass::Apply, &json!({"different":"evidence"}))
        .expect("mismatched evidence")
        .content_hash;
    assert!(
        exact_accepted_ingest_bookmarks(
            &poll_store,
            &poll_plan,
            &[(mismatched_hash, accepted_ingest.clone())],
            &expected_target,
            &input_hash,
        )
        .is_empty(),
        "accepted-ingest authority requires exact immutable evidence"
    );
    assert_eq!(
        exact_accepted_ingest_bookmarks(
            &poll_store,
            &poll_plan,
            &[
                (accepted_hash.clone(), accepted_ingest.clone()),
                (accepted_hash, accepted_ingest.clone()),
            ],
            &expected_target,
            &input_hash,
        )
        .len(),
        2,
        "duplicate accepted-ingest authorities remain visible to the exact-one gate"
    );
    let mut poll_receipt = checkpoint(&poll_plan);
    poll_receipt["step"] = json!("poll_response_1");
    poll_receipt["receipt"]["response_action"] = json!("poll");
    poll_receipt["receipt"]["result"]["at_bookmark"] = json!("before");
    let poll_hash = poll_store
        .record_d1_import_checkpoint(&poll_plan.operation_id, &poll_receipt)
        .expect("poll failure checkpoint");
    assert_eq!(
        poll_store
            .write_evidence(EvidenceClass::Apply, &poll_receipt)
            .expect("poll failure evidence")
            .content_hash,
        poll_hash
    );
    assert!(
        exact_durable_provider_failure_boundary(&poll_store, &poll_plan).is_ok(),
        "poll failure binds the exact accepted-ingest bookmark"
    );

    store
        .record_d1_import_checkpoint(&plan.operation_id, &receipt)
        .expect("duplicate known failure");
    assert!(exact_durable_provider_failure_boundary(&store, &plan).is_err());

    for receipt_fixture in [
        None,
        Some({
            let mut mismatched = checkpoint(&build_plan());
            mismatched["receipt"]["result"]["provider_error_present"] = json!(false);
            mismatched
        }),
        Some({
            let mut grafted = checkpoint(&build_plan());
            grafted["receipt"]["response_action"] = json!("poll");
            grafted
        }),
    ] {
        let invalid_root = tempfile::tempdir().expect("invalid receipt root");
        let invalid_store =
            StateStore::open(RuntimePaths::from_root(invalid_root.path())).expect("store");
        let mut invalid_plan = build_plan();
        if let Some(mut invalid_receipt) = receipt_fixture {
            invalid_receipt["operation_id"] = json!(invalid_plan.operation_id);
            invalid_store
                .record_d1_import_checkpoint(&invalid_plan.operation_id, &invalid_receipt)
                .expect("invalid provider checkpoint");
            invalid_store
                .write_evidence(EvidenceClass::Apply, &invalid_receipt)
                .expect("invalid provider evidence");
        }
        let invalid = approved_mln_import_execution_error_envelope(
            &invalid_store,
            &mut invalid_plan,
            CloudflareError::D1ImportProviderFailure,
            &MemorySecretStore::default(),
        );
        assert_eq!(
            invalid.result["outcome"],
            "provider_rejected_receipt_invalid"
        );
        assert_eq!(invalid.result["receipt_available"], false);
        assert_ne!(invalid_plan.status, PlanStatus::Running);
    }

    let transport_root = tempfile::tempdir().expect("transport root");
    let transport_store =
        StateStore::open(RuntimePaths::from_root(transport_root.path())).expect("store");
    let mut transport_plan = build_plan();
    let transport = approved_mln_import_execution_error_envelope(
        &transport_store,
        &mut transport_plan,
        CloudflareError::InvalidRequestBody("injected transport timeout".to_owned()),
        &MemorySecretStore::default(),
    );
    assert_eq!(transport.result["outcome"], "unknown");
    assert_eq!(transport.result["receipt_available"], false);
    assert!(
        transport
            .verification
            .basis
            .as_deref()
            .is_some_and(|basis| basis.contains("no Cloudflare response was received"))
    );
    assert_eq!(transport_plan.status, PlanStatus::RectificationRequired);
}
