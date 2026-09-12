use super::*;
use crate::runtime::import_rectification::rectify_completed_reviewed_import;

fn prepared_import() -> (ExportCoverageFixture, PlanV1) {
    let fixture = export_coverage_fixture();
    let store = &fixture.store;
    let catalog: CatalogSnapshot = store
        .read_json(&store.paths().catalog_file())
        .expect("catalog");
    let capability = catalog.get("d1-import-database").expect("import").clone();
    assert!(
        capability.cost.references.len() > 1,
        "exercise production enrichment"
    );
    let proof = store.list_operational_proofs().expect("proofs").remove(0);
    let binding = proof
        .d1_full_export_governed_execution()
        .expect("export binding");
    let mut input = fixture.input.clone();
    input.body = Some(json!({
        "pre_recovery_anchor_operation_id":binding.operation_id,
        "pre_recovery_anchor_evidence_hash":binding.manifest_evidence_hash,
        "pre_recovery_anchor_output_sha256":binding.output_file_sha256,
        "pre_recovery_anchor_bookmark_hash":binding.at_bookmark_hash,
    }));
    let repo = fixture.root.path().join("reviewed");
    fs::create_dir(&repo).expect("repo");
    let repo = fs::canonicalize(repo).expect("canonical repo");
    for args in [
        vec!["init"],
        vec!["config", "user.name", "Fixture"],
        vec!["config", "user.email", "fixture@example.invalid"],
        vec![
            "remote",
            "add",
            "origin",
            "https://github.com/example/import.git",
        ],
    ] {
        assert!(
            StdCommand::new("git")
                .arg("-C")
                .arg(&repo)
                .args(args)
                .output()
                .expect("git")
                .status
                .success()
        );
    }
    let source = repo.join("migration.sql");
    fs::write(&source, "CREATE TABLE example (id TEXT PRIMARY KEY);\n").expect("source");
    for args in [
        vec!["add", "migration.sql"],
        vec!["commit", "-m", "fixture"],
    ] {
        assert!(
            StdCommand::new("git")
                .arg("-C")
                .arg(&repo)
                .args(args)
                .output()
                .expect("git")
                .status
                .success()
        );
    }
    let stage = stage_approved_mln_migration(store, &capability, &input, &source).expect("stage");
    let mut plan = PlanV1::draft(
        "profile-a",
        input.selectors["account_id"].as_str().expect("account"),
        binding.catalog_hash.as_str(),
        capability,
        json!({"adapter":{"approved_mln_import":stage}}),
    )
    .expect("plan");
    plan.input = serde_json::to_value(input).expect("input");
    plan.precondition_hashes
        .insert("catalog".to_owned(), plan.catalog_hash.clone());
    plan.refresh_hash().expect("hash");
    save_current_test_plan(store, &plan);
    validate_trusted_root_import_plan(
        store,
        &store.load_plan_v2(&plan.operation_id).expect("canonical"),
    )
    .expect("enriched production capability admits before boundary");
    plan.approve(true, None).expect("approve");
    plan.mark_consumed().expect("consume");
    plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("attempt");
    save_current_test_plan(store, &plan);
    (fixture, plan)
}

fn complete_import(store: &StorageStateStore, plan: &mut PlanV1, drift: &str) {
    let stage = &plan.targets["adapter"]["approved_mln_import"];
    let ingest = json!({"schema_version":1,"operation_id":plan.operation_id,
        "step":"ingest_response","performed":true,"rectification_required":false,
        "receipt":{"http_status":200,"success":true,"response_action":"ingest",
            "provider":"cloudflare","effect":"d1_import_ingest_accepted",
            "migration_id":stage["migration_id"],"target":stage["target"],
            "plan_input_hash":hash_value(&plan.input).expect("input hash"),"no_replay":false,
            "result":{"type":"import","status":"active","success":true,"at_bookmark":"before"},"errors":[]}});
    if drift != "missing_ingest" {
        persist_poll_lineage_checkpoint(store, &plan.operation_id, &ingest);
    }
    let mut receipt = json!({"provider":"cloudflare","effect":"d1_import_provider_complete",
        "response_action":"poll","no_replay":true,"migration_id":stage["migration_id"],
        "source_sha256":stage["sha256"],"source_md5":stage["md5"],"source_bytes":stage["bytes"],
        "source_authority_hash":stage["source_authority_hash"],
        "stage_identity_hash":hash_value(stage).expect("stage hash"),"target":stage["target"],
        "plan_input_hash":hash_value(&plan.input).expect("input hash"),"prerequisites":plan.input["body"],
        "at_bookmark":"before","final_bookmark":"after","provider_status":"complete",
        "provider_success":true,"state":"provider_complete"});
    if drift == "source" {
        receipt["source_sha256"] = json!("sha256:substituted");
    }
    if drift == "target" {
        receipt["target"]["database_id"] = json!(Uuid::new_v4().to_string());
    }
    let completion = json!({"schema_version":1,"operation_id":plan.operation_id,
        "step":"provider_complete","performed":true,"rectification_required":false,"receipt":receipt});
    if drift != "missing_completion" {
        persist_poll_lineage_checkpoint(store, &plan.operation_id, &completion);
    }
    if drift == "duplicate_completion" {
        persist_poll_lineage_checkpoint(store, &plan.operation_id, &completion);
    }
    if drift == "apply_substitution" {
        receipt["final_bookmark"] = json!("other");
    }
    let response = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"status":"complete","_cfctl":receipt}),
        errors: vec![],
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    plan.status = PlanStatus::Running;
    let evidence = store
        .write_evidence(
            EvidenceClass::Apply,
            &serde_json::to_value(&response).expect("response"),
        )
        .expect("evidence");
    let mut boundary = boundary_response_artifact(plan, &response, Some(&evidence));
    if drift == "missing_apply" {
        boundary["apply_evidence_hash"] = json!(format!("sha256:{}", "e".repeat(64)));
    }
    plan.record_transaction_stage_with_artifact(
        TransactionStageV1::BoundaryResponsePersisted,
        boundary,
    )
    .expect("boundary");
    plan.record_transaction_stage_with_artifact(
        TransactionStageV1::SecretSinkPersisted,
        secret_sink_artifact(plan, None, false, drift != "sink", false, None, None),
    )
    .expect("sink");
    store.save_plan(plan).expect("persist completion");
}

#[tokio::test]
async fn reviewed_import_recovers_enriched_catalog_without_replay() {
    for failed_verification in [false, true] {
        let (fixture, mut plan) = prepared_import();
        complete_import(&fixture.store, &mut plan, "none");
        let journal = plan.transaction_journal.clone();
        let pins = fixture
            .store
            .load_plan_v2(&plan.operation_id)
            .expect("plan")
            .pins;
        if failed_verification {
            let error = persist_import_verification_failure(
                &fixture.store,
                &mut plan,
                CliError::Input("original completion failure".to_owned()),
            );
            assert!(error.to_string().contains("original completion failure"));
            plan.validate_transaction_journal()
                .expect("recovery journal");
            assert_eq!(plan.status, PlanStatus::RectificationRequired);
        }
        let checkpoints = fixture
            .store
            .read_d1_import_checkpoints(&plan.operation_id)
            .expect("checkpoints");
        let result = rectify_loaded_plan(&fixture.store, &mut plan)
            .await
            .expect("local recovery through dispatcher");
        assert!(result.ok);
        assert!(!result.performed);
        assert_eq!(plan.status, PlanStatus::Verified);
        assert_eq!(plan.transaction_stage, TransactionStageV1::Closed);
        assert_eq!(
            &plan.transaction_journal[..journal.len()],
            journal.as_slice()
        );
        assert_eq!(
            fixture
                .store
                .load_plan_v2(&plan.operation_id)
                .expect("plan")
                .pins,
            pins
        );
        assert_eq!(
            fixture
                .store
                .read_d1_import_checkpoints(&plan.operation_id)
                .expect("checkpoints"),
            checkpoints
        );
        plan.validate_transaction_journal().expect("closed journal");
        // Isolated fixture models a crash after verification persisted, before Closed.
        plan.transaction_journal.pop();
        plan.transaction_stage = TransactionStageV1::VerificationResponsePersisted;
        save_current_test_plan(&fixture.store, &plan);
        let resumed = rectify_loaded_plan(&fixture.store, &mut plan)
            .await
            .expect("resume final close");
        assert!(resumed.ok);
        assert!(!resumed.performed);
        assert_eq!(plan.transaction_stage, TransactionStageV1::Closed);
        let closed = plan.clone();
        let repeated = rectify_loaded_plan(&fixture.store, &mut plan)
            .await
            .expect("repeat local reconciliation");
        assert!(repeated.ok);
        assert!(!repeated.performed);
        assert_eq!(plan, closed);
    }
}

#[test]
fn reviewed_import_rejects_incomplete_or_substituted_completion_without_mutation() {
    for drift in [
        "missing_ingest",
        "missing_completion",
        "duplicate_completion",
        "source",
        "target",
        "apply_substitution",
        "missing_apply",
        "sink",
    ] {
        let (fixture, mut plan) = prepared_import();
        complete_import(&fixture.store, &mut plan, drift);
        let before = plan.clone();
        assert!(
            rectify_completed_reviewed_import(&fixture.store, &mut plan).is_err(),
            "{drift}"
        );
        assert_eq!(plan, before, "{drift}");
        assert_eq!(
            fixture
                .store
                .load_plan(&plan.operation_id)
                .expect("unchanged"),
            before
        );
    }
}

#[test]
fn reviewed_import_enrichment_never_changes_execution_authority() {
    let fixture = export_coverage_fixture();
    let catalog: CatalogSnapshot = fixture
        .store
        .read_json(&fixture.store.paths().catalog_file())
        .expect("catalog");
    let actual = catalog.get("d1-import-database").expect("import");
    let trusted = trusted_native_capability(&actual.id).expect("trusted");
    assert!(native_import_contract_matches(actual, &trusted));
    for field in [
        "method",
        "cost",
        "entitlement",
        "verification",
        "d1_approved_mln_import",
    ] {
        let mut changed = serde_json::to_value(actual).expect("capability");
        match field {
            "method" => changed[field] = json!("DELETE"),
            "cost" => changed[field]["known"] = json!(!actual.cost.known),
            "entitlement" => {
                changed[field]["requires_live_resolution"] =
                    json!(!actual.entitlement.requires_live_resolution);
            }
            "verification" => changed[field]["strategy"] = json!("different"),
            _ => changed[field]["max_source_bytes"] = json!(0),
        }
        let changed = serde_json::from_value(changed).expect("changed capability");
        assert!(
            !native_import_contract_matches(&changed, &trusted),
            "{field}"
        );
    }
}

#[tokio::test]
async fn reviewed_import_preserves_effect_when_recovery_persistence_fails() {
    let (fixture, mut plan) = prepared_import();
    complete_import(&fixture.store, &mut plan, "none");
    let before = plan.clone();
    let plans_dir = fixture.store.paths().data_dir.join("plans-v2");
    let preserved = fixture.store.paths().data_dir.join("plans-v2-preserved");
    fs::rename(&plans_dir, &preserved).expect("preserve isolated test plans");
    fs::write(&plans_dir, "injected local persistence failure").expect("block test plan directory");
    let error = persist_import_verification_failure(
        &fixture.store,
        &mut plan,
        CliError::Input("original completion error".to_owned()),
    );
    assert!(error.to_string().contains("original completion error"));
    assert!(error.to_string().contains("could not be persisted"));
    let envelope = post_boundary_failure_envelope(
        &plan,
        json!({}),
        None,
        None,
        &error,
        true,
        "completion persistence failed",
    );
    assert!(!envelope.ok);
    assert!(envelope.performed);
    assert_ne!(envelope.verification.state, VerificationState::Passed);
    assert_eq!(plan, before);
    fs::remove_file(&plans_dir).expect("remove injected test obstacle");
    fs::rename(preserved, plans_dir).expect("restore isolated test plans");
    assert_eq!(
        fixture
            .store
            .load_plan(&plan.operation_id)
            .expect("original saved plan"),
        before
    );
    let checkpoints = fixture
        .store
        .read_d1_import_checkpoints(&plan.operation_id)
        .expect("checkpoints");
    let result = rectify_loaded_plan(&fixture.store, &mut plan)
        .await
        .expect("forward recovery");
    assert!(result.ok);
    assert!(!result.performed);
    assert_eq!(
        fixture
            .store
            .read_d1_import_checkpoints(&plan.operation_id)
            .expect("unchanged provider history"),
        checkpoints
    );
}
