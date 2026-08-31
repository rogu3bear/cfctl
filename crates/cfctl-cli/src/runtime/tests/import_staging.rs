use super::*;

#[test]
pub(super) fn d1_full_export_runtime_records_the_exact_bookmark_anchor_receipt() {
    let root = tempfile::tempdir().expect("runtime root");
    let store = authenticated_test_store(RuntimePaths::from_root(root.path()));
    let mut catalog = CatalogSnapshot {
        schema_version: 1,
        generated_at: Utc::now(),
        source_url: "fixture".to_owned(),
        source_hash: "fixture".to_owned(),
        schema_hash: String::new(),
        capabilities: BTreeMap::new(),
    };
    ingest_native_control_capabilities(&mut catalog).expect("native capabilities");
    let capability = catalog.get("d1-full-export").expect("D1 export");
    let input = CallInput {
        selectors: json!({
            "account_id":"ca30e922fda7f5578e49873542e4aaca",
            "database_id":"15dc8c91-cba5-4ba8-9e5b-a06cf7e6bf15",
        }),
        query: json!({}),
        ..CallInput::default()
    };
    let result = json!({
        "result": {
            "output_file":{
                "sha256":format!("sha256:{}", "a".repeat(64)),
                "complete":true,
                "hash_matches":true,
            },
            "provider":{"at_bookmark":"bookmark-after-0142"},
        }
    });
    let evidence = store
        .write_evidence(EvidenceClass::LiveRead, &result)
        .expect("evidence");
    let mut envelope = ResultEnvelopeV2::success("call", result).with_evidence(evidence.clone());
    envelope.performed = true;
    envelope.profile_id = Some("profile-a".to_owned());
    envelope.account_id = Some("ca30e922fda7f5578e49873542e4aaca".to_owned());
    record_operational_proof(
        &store,
        &catalog,
        capability,
        &input,
        Some("22222222-2222-4222-8222-222222222222"),
        &envelope,
    )
    .expect("governed export proof");
    let proofs = store.list_operational_proofs().expect("proofs");
    assert_eq!(proofs.len(), 1);
    let binding = proofs[0]
        .d1_full_export_governed_execution()
        .expect("bound export");
    assert_eq!(binding.manifest_evidence_hash, evidence.content_hash);
    assert_eq!(
        binding.at_bookmark_hash,
        hash_value(&json!("bookmark-after-0142")).expect("bookmark hash")
    );
    assert_eq!(binding.completion_status, "completed");
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one portable Git fixture proves the complete reviewed-source authority boundary"
)]
pub(super) fn approved_mln_source_rejects_suffix_grafts_and_git_authority_drift() {
    let root = tempfile::tempdir().expect("fixture root");
    let repository = root.path().join("mln-web");
    fs::create_dir_all(&repository).expect("repo directory");
    let repository = fs::canonicalize(repository).expect("canonical repo directory");
    let git = |arguments: &[&str]| {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(&repository)
            .args(arguments)
            .output()
            .expect("git runs");
        assert!(
            output.status.success(),
            "git {}: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("git output")
            .trim()
            .to_owned()
    };
    git(&["init"]);
    git(&["config", "user.email", "fixture@example.invalid"]);
    git(&["config", "user.name", "Fixture"]);
    git(&[
        "remote",
        "add",
        "origin",
        "https://github.com/rogu3bear/mln-web.git",
    ]);
    let relative = "crates/founder/migrations/d1/0142_document_render_claim_generation.sql";
    let source = repository.join(relative);
    fs::create_dir_all(source.parent().expect("source parent")).expect("migration directory");
    let bytes = b"approved migration\n";
    fs::write(&source, bytes).expect("migration source");
    git(&["add", relative]);
    git(&["commit", "-m", "fixture"]);
    let head = git(&["rev-parse", "HEAD"]);
    let blob_spec = format!("HEAD:{relative}");
    let blob = git(&["rev-parse", &blob_spec]);

    let mut catalog = CatalogSnapshot {
        schema_version: 1,
        generated_at: Utc::now(),
        source_url: "fixture".to_owned(),
        source_hash: "fixture".to_owned(),
        schema_hash: String::new(),
        capabilities: BTreeMap::new(),
    };
    ingest_native_control_capabilities(&mut catalog).expect("native capabilities");
    let mut capability = catalog
        .get("d1-import-approved-mln-migration")
        .expect("import")
        .clone();
    let contract = capability
        .d1_approved_mln_import
        .as_mut()
        .expect("contract");
    contract.repository_head = head.clone();
    let migration = &mut contract.migrations[0];
    migration.bytes = bytes.len() as u64;
    migration.sha256 = hex::encode(Sha256::digest(bytes));
    migration.md5 = hex::encode(Md5::digest(bytes));
    migration.git_blob_oid = blob.clone();
    let contract = capability
        .d1_approved_mln_import
        .as_ref()
        .expect("contract")
        .clone();
    validate_approved_mln_repository_authority(
        &contract,
        &contract.migrations[0],
        &repository,
        Some(bytes),
    )
    .expect("exact portable repository authority");

    for remote in [
        "https://github.com/rogu3bear/mln-web.git",
        "https://github.com/rogu3bear/mln-web",
        "git@github.com:rogu3bear/mln-web.git",
        "git@github.com:rogu3bear/mln-web",
    ] {
        assert_eq!(
            normalize_reviewed_mln_repository_id(remote).as_deref(),
            Some("github.com/rogu3bear/mln-web")
        );
    }
    for remote in [
        "https://user@github.com/rogu3bear/mln-web.git",
        "https://github.com:443/rogu3bear/mln-web.git",
        "https://github.com/rogu3bear/mln-web.git?x=1",
        "https://example.com/rogu3bear/mln-web.git",
    ] {
        assert!(normalize_reviewed_mln_repository_id(remote).is_none());
    }

    let state = tempfile::tempdir().expect("state root");
    let store = StateStore::open(RuntimePaths::from_root(state.path())).expect("state store opens");
    let input = CallInput {
        body: Some(json!({"migration_id":"0142"})),
        ..CallInput::default()
    };
    let staged = stage_approved_mln_migration(&store, &capability, &input, &source)
        .expect("exact reviewed source stages");
    let mut plan = PlanV1::draft(
        "profile-a",
        contract.account_id.as_str(),
        "catalog-sha",
        capability.clone(),
        json!({"adapter":{"approved_mln_import":staged}}),
    )
    .expect("managed import plan");
    plan.input = serde_json::to_value(&input).expect("plan input");
    plan.refresh_hash().expect("refresh staged plan");
    validate_managed_mln_stage_authority(&plan).expect("managed stage authority");
    let graft = root.path().join("graft").join(relative);
    fs::create_dir_all(graft.parent().expect("graft parent")).expect("graft directory");
    fs::write(&graft, bytes).expect("graft bytes");
    assert!(
        stage_approved_mln_migration(&store, &capability, &input, &graft).is_err(),
        "an exact-byte suffix graft outside the reviewed Git authority must fail"
    );

    let mut wrong = contract.clone();
    wrong.repository_head = "1111111111111111111111111111111111111111".to_owned();
    assert!(
        validate_approved_mln_repository_authority(
            &wrong,
            &wrong.migrations[0],
            &repository,
            Some(bytes)
        )
        .is_err()
    );
    let mut wrong = contract.clone();
    wrong.repository_id = "github.com/attacker/mln-web".to_owned();
    assert!(
        validate_approved_mln_repository_authority(
            &wrong,
            &wrong.migrations[0],
            &repository,
            Some(bytes)
        )
        .is_err()
    );
    let mut wrong_migration = contract.migrations[0].clone();
    wrong_migration.git_blob_oid = "1111111111111111111111111111111111111111".to_owned();
    assert!(
        validate_approved_mln_repository_authority(
            &contract,
            &wrong_migration,
            &repository,
            Some(bytes)
        )
        .is_err()
    );
    fs::write(&source, b"dirty source\n").expect("dirty source");
    assert!(
        validate_approved_mln_repository_authority(
            &contract,
            &contract.migrations[0],
            &repository,
            Some(bytes)
        )
        .is_err(),
        "dirty worktree source must fail"
    );
    validate_managed_mln_stage_authority(&plan)
        .expect("execution consumes the immutable managed stage, not the changed checkout");
    git(&["checkout", "--", relative]);
    let symlink_root = root.path().join("mln-link");
    std::os::unix::fs::symlink(&repository, &symlink_root).expect("root symlink");
    assert!(
        validate_approved_mln_repository_authority(
            &contract,
            &contract.migrations[0],
            &symlink_root,
            Some(bytes)
        )
        .is_err(),
        "symlink root substitution must fail"
    );
    let stage_path = plan
        .targets
        .pointer("/adapter/approved_mln_import/stage_path")
        .and_then(Value::as_str)
        .expect("managed stage path");
    fs::write(stage_path, b"tampered stage\n").expect("tamper managed stage");
    assert!(
        validate_managed_mln_stage_authority(&plan).is_err(),
        "execution must reject a managed stage that drifted after planning"
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one executable Git fixture proves generic source capture and execution-time drift gates"
)]
pub(super) fn reviewed_git_d1_import_stages_one_exact_clean_head_and_fails_on_drift() {
    let root = tempfile::tempdir().expect("fixture root");
    let repository = root.path().join("portable-import");
    fs::create_dir_all(&repository).expect("repo directory");
    let repository = fs::canonicalize(repository).expect("canonical repository");
    let git = |arguments: &[&str]| {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(&repository)
            .args(arguments)
            .output()
            .expect("git runs");
        assert!(
            output.status.success(),
            "git {}: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("git output")
            .trim()
            .to_owned()
    };
    git(&["init"]);
    git(&["config", "user.email", "fixture@example.invalid"]);
    git(&["config", "user.name", "Fixture"]);
    git(&[
        "remote",
        "add",
        "origin",
        "https://github.com/example/portable-import.git",
    ]);
    let relative = "migrations/0001_authority.sql";
    let source = repository.join(relative);
    fs::create_dir_all(source.parent().expect("source parent")).expect("migration directory");
    let bytes = b"CREATE TABLE authority (id TEXT PRIMARY KEY);\n";
    fs::write(&source, bytes).expect("migration source");
    git(&["add", relative]);
    git(&["commit", "-m", "fixture"]);

    let mut catalog = CatalogSnapshot {
        schema_version: 1,
        generated_at: Utc::now(),
        source_url: "fixture".to_owned(),
        source_hash: "fixture".to_owned(),
        schema_hash: String::new(),
        capabilities: BTreeMap::new(),
    };
    ingest_native_control_capabilities(&mut catalog).expect("native capabilities");
    let capability = catalog
        .get("d1-import-database")
        .expect("generic import")
        .clone();
    let input = CallInput {
        selectors: json!({
            "account_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "database_id":"11111111-1111-4111-8111-111111111111",
        }),
        body: Some(json!({
            "pre_recovery_anchor_operation_id":"22222222-2222-4222-8222-222222222222",
            "pre_recovery_anchor_evidence_hash":format!("sha256:{}", "a".repeat(64)),
            "pre_recovery_anchor_output_sha256":format!("sha256:{}", "b".repeat(64)),
            "pre_recovery_anchor_bookmark_hash":format!("sha256:{}", "c".repeat(64)),
        })),
        ..CallInput::default()
    };
    let state = tempfile::tempdir().expect("state root");
    let store = StateStore::open(RuntimePaths::from_root(state.path())).expect("state store");
    let staged = stage_approved_mln_migration(&store, &capability, &input, &source)
        .expect("clean reviewed source stages");
    assert_eq!(staged["bytes"], bytes.len());
    assert_eq!(
        staged["sha256"],
        format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
    );
    assert_eq!(staged["md5"], hex::encode(Md5::digest(bytes)));
    assert_eq!(staged["target"], input.selectors);
    assert_eq!(
        staged.pointer("/source_authority/repository_id"),
        Some(&json!("github.com/example/portable-import"))
    );
    let stage_path = PathBuf::from(staged["stage_path"].as_str().expect("stage path"));
    #[cfg(unix)]
    assert_eq!(
        fs::metadata(&stage_path)
            .expect("stage metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    let mut plan = PlanV1::draft(
        "profile-a",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "catalog-sha",
        capability.clone(),
        json!({"adapter":{"approved_mln_import":staged}}),
    )
    .expect("generic plan");
    plan.input = serde_json::to_value(&input).expect("plan input");
    plan.refresh_hash().expect("plan hash");
    validate_managed_reviewed_git_stage_authority(&plan)
        .expect("exact source and stage remain executable");

    let mut zero_bound_capability = capability.clone();
    zero_bound_capability
        .d1_approved_mln_import
        .as_mut()
        .expect("reviewed Git import contract")
        .max_source_bytes = 0;
    let planning_error =
        stage_approved_mln_migration(&store, &zero_bound_capability, &input, &source)
            .expect_err("a historical zero source bound cannot authorize planning");
    assert!(matches!(
        planning_error,
        CliError::Input(message) if message.contains("no larger than 0 bytes")
    ));

    let mut zero_bound_plan = plan.clone();
    zero_bound_plan
        .capability
        .d1_approved_mln_import
        .as_mut()
        .expect("reviewed Git import contract")
        .max_source_bytes = 0;
    zero_bound_plan
        .refresh_hash()
        .expect("zero-bound plan hash");
    let execution_error = validate_managed_reviewed_git_stage_authority(&zero_bound_plan)
        .expect_err("a historical zero source bound cannot authorize execution");
    assert!(matches!(
        execution_error,
        CliError::Input(message) if message == "managed source size is outside its bound"
    ));

    let schema_capability = catalog
        .get("d1-apply-reviewed-schema-migration")
        .expect("reviewed schema migration")
        .clone();
    let schema_staged = stage_approved_mln_migration(&store, &schema_capability, &input, &source)
        .expect("the production schema lane stages the same clean Git source");
    assert_eq!(schema_staged["statement_count"], 1);
    let mut schema_plan = PlanV1::draft(
        "profile-a",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "catalog-sha",
        schema_capability,
        json!({"adapter":{"approved_mln_import":schema_staged}}),
    )
    .expect("schema plan");
    schema_plan.input = serde_json::to_value(&input).expect("schema plan input");
    schema_plan.refresh_hash().expect("schema plan hash");
    validate_managed_reviewed_git_stage_authority(&schema_plan)
        .expect("schema lane revalidates Git, private stage, and statement count");

    fs::write(&source, b"CREATE TABLE drifted (id TEXT);\n").expect("dirty source");
    assert!(
        validate_managed_reviewed_git_stage_authority(&plan).is_err(),
        "execution must fail after checkout drift"
    );
    assert!(
        stage_approved_mln_migration(&store, &capability, &input, &source).is_err(),
        "planning must reject a dirty repository"
    );
    git(&["checkout", "--", relative]);
    fs::write(&stage_path, b"tampered stage\n").expect("tamper stage");
    assert!(
        validate_managed_reviewed_git_stage_authority(&plan).is_err(),
        "execution must reject a changed private stage"
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one lineage fixture proves all stale-parent and full-packet phase transitions"
)]
pub(super) fn mln_0143_lineage_binds_post_restore_to_the_same_pre_baseline() {
    let root = tempfile::tempdir().expect("runtime root");
    let store = authenticated_test_store(RuntimePaths::from_root(root.path()));
    let mut catalog = CatalogSnapshot {
        schema_version: 1,
        generated_at: Utc::now(),
        source_url: "fixture".to_owned(),
        source_hash: "fixture".to_owned(),
        schema_hash: String::new(),
        capabilities: BTreeMap::new(),
    };
    ingest_native_control_capabilities(&mut catalog).expect("native capabilities");
    let capability = catalog
        .get("mln-0143-data-invariants")
        .expect("MLN invariant");
    let contract = capability
        .mln_0143_data_invariants
        .as_ref()
        .expect("typed contract");
    let scope = hash_value(&json!({
        "account_id":contract.account_id,
        "database_id":contract.database_id,
    }))
    .expect("scope hash");
    let base = |phase: &str| {
        json!({
            "schema_version":1,
            "capability_id":"mln-0143-data-invariants",
            "capability_version":contract.capability_version,
            "validator_contract_hash":contract.validator_contract_hash,
            "migration_id":"0143",
            "migration_sha256":contract.migration_sha256,
            "phase":phase,
            "target_scope_hash":scope,
            "complete":true,
            "projection":{"digest":format!("sha256:{}", "a".repeat(64)),"count":2,"counts_by_kind":[]},
            "semantic_schema_hash":if phase == "post_import" {
                contract.post_table_definition_hash.clone()
            } else {
                contract.pre_table_definition_hash.clone()
            },
            "packet_hash":format!("sha256:{}", "c".repeat(64)),
            "packet_count":3,
            "packet_non_target_hash":format!("sha256:{}", "e".repeat(64)),
            "packet_non_target_count":2,
            "prior_0142_trigger_definition_hash":contract.prior_0142_trigger_definition_hash,
            "trigger_definition_hashes":if phase == "pre_import" {
                json!([])
            } else {
                json!(contract.trigger_definition_hashes)
            },
            "assertions":{
                "old_table_absent":true,
                "unique_hash_index_present":true,
                "event_index_exact_non_unique_shape":true,
                "document_index_exact_non_unique_shape":true,
                "foreign_key_check_empty":true,
                "duplicate_hash_groups_zero":true,
                "invalid_evidence_kinds_zero":true,
                "invalid_advanced_events_zero":true,
                "prior_0142_terminal_trigger_present":true
            },
            "query":{
                "sha256":contract.fixed_query_sha256,
                "row_limit":256,
                "probe_rows":257,
                "byte_limit":1024 * 1024,
                "timeout_seconds":30,
                "received_rows":2,
                "provider_rows_read":20,
                "provider_duration":0.1,
                "bounds_saturated":false
            },
            "lineage":{}
        })
    };
    let synthetic_pre = store
        .write_evidence(EvidenceClass::LiveRead, &base("pre_import"))
        .expect("synthetic pre evidence");
    let synthetic_input = CallInput {
        body: Some(json!({
            "migration_id":"0143",
            "phase":"post_import",
            "pre_import_evidence_hash":synthetic_pre.content_hash
        })),
        ..CallInput::default()
    };
    assert!(
        mln_0143_parent_manifests(&store, &catalog, capability, &synthetic_input).is_err(),
        "direct evidence persistence must not mint governed-execution provenance"
    );
    let credential_generation_id = "11111111-1111-4111-8111-111111111111";
    let register = |manifest: Value, phase: &str| {
        let response = json!({"result": manifest});
        let evidence = store
            .write_evidence(EvidenceClass::LiveRead, &response)
            .expect("runtime evidence");
        let mut envelope =
            cfctl_core::ResultEnvelopeV2::success("call", response).with_evidence(evidence.clone());
        envelope.performed = true;
        envelope.capability_id = Some(capability.id.clone());
        envelope.profile_id = Some("default".to_owned());
        envelope.account_id = Some(contract.account_id.clone());
        let proof_input = CallInput {
            body: Some(json!({"migration_id":"0143","phase":phase})),
            ..CallInput::default()
        };
        record_operational_proof(
            &store,
            &catalog,
            capability,
            &proof_input,
            Some(credential_generation_id),
            &envelope,
        )
        .expect("governed runtime proof");
        evidence
    };
    let pre = register(base("pre_import"), "pre_import");
    for (label, mut stale) in [
        ("v1", base("pre_import")),
        ("missing query hash", base("pre_import")),
        ("wrong validator hash", base("pre_import")),
        ("missing authority identities", base("pre_import")),
    ] {
        match label {
            "v1" => stale["capability_version"] = json!(1),
            "missing query hash" => {
                stale["query"]
                    .as_object_mut()
                    .expect("query")
                    .remove("sha256");
            }
            "wrong validator hash" => {
                stale["validator_contract_hash"] =
                    Value::String(format!("sha256:{}", "f".repeat(64)));
            }
            "missing authority identities" => {
                stale
                    .as_object_mut()
                    .expect("manifest")
                    .remove("assertions");
                stale
                    .as_object_mut()
                    .expect("manifest")
                    .remove("semantic_schema_hash");
                stale
                    .as_object_mut()
                    .expect("manifest")
                    .remove("packet_hash");
            }
            _ => unreachable!(),
        }
        let evidence = store
            .write_evidence(EvidenceClass::LiveRead, &stale)
            .expect("stale evidence");
        let stale_input = CallInput {
            body: Some(json!({
                "migration_id":"0143",
                "phase":"post_import",
                "pre_import_evidence_hash":evidence.content_hash
            })),
            ..CallInput::default()
        };
        assert!(
            mln_0143_parent_manifests(&store, &catalog, capability, &stale_input).is_err(),
            "{label}"
        );
    }
    let mut post_manifest = base("post_import");
    post_manifest["lineage"]["pre_import_evidence_hash"] = Value::String(pre.content_hash.clone());
    let post = register(post_manifest, "post_import");
    let input = CallInput {
        body: Some(json!({
            "migration_id":"0143",
            "phase":"post_restore",
            "pre_import_evidence_hash":pre.content_hash,
            "post_import_evidence_hash":post.content_hash
        })),
        ..CallInput::default()
    };
    assert!(
        mln_0143_parent_manifests(&store, &catalog, capability, &input).is_err(),
        "post-restore evidence without the exact import and restore operation joins fails closed"
    );
    let parents = vec![
        (pre.content_hash.clone(), base("pre_import")),
        (post.content_hash.clone(), {
            let mut manifest = base("post_import");
            manifest["lineage"]["pre_import_evidence_hash"] =
                Value::String(pre.content_hash.clone());
            manifest
        }),
    ];
    validate_mln_0143_lineage_result(&input, &base("post_restore"), &parents)
        .expect("restored result equals pre baseline");

    let mut drifted = base("post_restore");
    drifted["packet_hash"] = Value::String(format!("sha256:{}", "d".repeat(64)));
    assert!(validate_mln_0143_lineage_result(&input, &drifted, &parents).is_err());

    let mut non_target_post_drift = base("post_import");
    non_target_post_drift["packet_non_target_hash"] =
        Value::String(format!("sha256:{}", "9".repeat(64)));
    assert!(
        validate_mln_0143_lineage_result(
            &CallInput {
                body: Some(json!({"phase":"post_import"})),
                ..CallInput::default()
            },
            &non_target_post_drift,
            &[(pre.content_hash.clone(), base("pre_import"))],
        )
        .is_err()
    );
    let mut non_target_restore_drift = base("post_restore");
    non_target_restore_drift["packet_count"] = json!(2);
    assert!(validate_mln_0143_lineage_result(&input, &non_target_restore_drift, &parents).is_err());
    let duplicate_pre = register(base("pre_import"), "pre_import");
    assert_eq!(duplicate_pre.content_hash, pre.content_hash);
    assert!(
        mln_0143_parent_manifests(&store, &catalog, capability, &input).is_err(),
        "duplicate governed executions for one parent manifest fail closed"
    );
}

#[test]
pub(super) fn d1_full_export_guide_binds_exact_selectors_and_file_output() {
    let mut catalog = CatalogSnapshot {
        schema_version: 1,
        generated_at: Utc::now(),
        source_url: "fixture".to_owned(),
        source_hash: "fixture".to_owned(),
        schema_hash: String::new(),
        capabilities: BTreeMap::new(),
    };
    ingest_native_control_capabilities(&mut catalog).expect("native capabilities");
    let guide = guide_json(catalog.get("d1-full-export").expect("D1 export"));
    assert_eq!(guide["contract_state"], "available");
    assert_eq!(
        guide["call_argv"],
        json!([
            "cfctl",
            "call",
            "d1-full-export",
            "--selector",
            "account_id=<account_id>",
            "--selector",
            "database_id=<database_id>",
            "--out",
            "<new-mode-0600-sql-path>",
            "--json"
        ])
    );
    let encoded = serde_json::to_string(&guide).expect("guide JSON");
    assert!(!encoded.contains("\"sql\""));
    assert!(!encoded.contains("\"restore\""));
}

#[test]
pub(super) fn d1_restore_exact_bookmark_guide_is_closed_and_approval_bound() {
    let mut catalog = CatalogSnapshot {
        schema_version: 1,
        generated_at: Utc::now(),
        source_url: "fixture".to_owned(),
        source_hash: "fixture".to_owned(),
        schema_hash: String::new(),
        capabilities: BTreeMap::new(),
    };
    ingest_native_control_capabilities(&mut catalog).expect("native capabilities");
    let capability = catalog
        .get("d1-restore-exact-bookmark")
        .expect("D1 restore");
    let guide = guide_json(capability);
    assert_eq!(guide["contract_state"], "available");
    assert_eq!(
        guide["call_argv"],
        json!([
            "cfctl",
            "call",
            "d1-restore-exact-bookmark",
            "--selector",
            "account_id=<account_id>",
            "--selector",
            "database_id=<database_id>",
            "--body-stdin",
            "--json"
        ])
    );
    let schema = &guide["capability"]["request_schema"];
    assert_eq!(schema["additionalProperties"], false);
    let encoded = serde_json::to_string(schema).expect("schema JSON");
    assert!(!encoded.contains("\"timestamp\""));
    assert!(!encoded.contains("\"url\""));
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one CLI boundary regression covers the exact export allowlist and ordinary mutation denial"
)]
pub(super) async fn d1_full_export_requires_out_and_rejects_caller_body_before_credentials() {
    let root = tempfile::tempdir().expect("runtime root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let mut catalog = CatalogSnapshot {
        schema_version: 1,
        generated_at: Utc::now(),
        source_url: "fixture".to_owned(),
        source_hash: "fixture".to_owned(),
        schema_hash: String::new(),
        capabilities: BTreeMap::new(),
    };
    ingest_native_control_capabilities(&mut catalog).expect("native capabilities");
    store
        .write_json(&store.paths().catalog_file(), &catalog)
        .expect("seed catalog");
    let arguments = CallArgs {
        capability_id: "d1-full-export".to_owned(),
        selectors: vec![
            ("account_id".to_owned(), "a".repeat(32)),
            (
                "database_id".to_owned(),
                "11111111-2222-3333-4444-555555555555".to_owned(),
            ),
        ],
        query: Vec::new(),
        body_json: None,
        body_stdin: false,
        profile: None,
        account: None,
        if_match: None,
        if_none_match: None,
        value_out: None,
        credential_in: None,
        out: None,
        source_file: None,
    };
    let error = Box::pin(call_command(&store, arguments))
        .await
        .expect_err("missing --out");
    assert!(error.to_string().contains("requires `--out"));

    let error = Box::pin(call_command(
        &store,
        CallArgs {
            capability_id: "d1-full-export".to_owned(),
            selectors: vec![
                ("account_id".to_owned(), "a".repeat(32)),
                (
                    "database_id".to_owned(),
                    "11111111-2222-3333-4444-555555555555".to_owned(),
                ),
            ],
            query: Vec::new(),
            body_json: Some(r#"{"sql":"SELECT 1"}"#.to_owned()),
            body_stdin: false,
            profile: None,
            account: None,
            if_match: None,
            if_none_match: None,
            value_out: None,
            credential_in: None,
            out: Some(root.path().join("snapshot.sql")),
            source_file: None,
        },
    ))
    .await
    .expect_err("caller SQL must be rejected");
    assert!(error.to_string().contains("caller SQL"));

    let mut mutation = CapabilityV1::new(
        "fixture-mutation",
        "Fixture mutation",
        "POST",
        "/accounts/{account_id}/fixture",
    );
    mutation.mutating = true;
    mutation.selectors = vec![SelectorV1 {
        name: "account_id".to_owned(),
        location: "path".to_owned(),
        required: true,
        value_type: "string".to_owned(),
        description: None,
        contract: None,
    }];
    catalog.capabilities.insert(mutation.id.clone(), mutation);
    catalog.refresh_hash().expect("refresh catalog");
    store
        .write_json(&store.paths().catalog_file(), &catalog)
        .expect("replace catalog");
    let error = Box::pin(call_command(
        &store,
        CallArgs {
            capability_id: "fixture-mutation".to_owned(),
            selectors: vec![("account_id".to_owned(), "a".repeat(32))],
            query: Vec::new(),
            body_json: None,
            body_stdin: false,
            profile: None,
            account: None,
            if_match: None,
            if_none_match: None,
            value_out: None,
            credential_in: None,
            out: Some(root.path().join("mutation.out")),
            source_file: None,
        },
    ))
    .await
    .expect_err("ordinary mutation must reject --out");
    assert!(
        error
            .to_string()
            .contains("restricted to bounded analytics")
    );
}
