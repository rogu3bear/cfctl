use super::*;

#[test]
pub(super) fn d1_schema_introspection_guide_emits_only_closed_body_and_exact_selectors() {
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
        .get("d1-schema-introspection")
        .expect("D1 introspection");
    let guide = guide_json(capability);

    assert_eq!(guide["contract_state"], "available");
    assert_eq!(
        guide["call_argv"],
        json!([
            "cfctl",
            "call",
            "d1-schema-introspection",
            "--selector",
            "account_id=<account_id>",
            "--selector",
            "database_id=<database_id>",
            "--body-stdin",
            "--json"
        ])
    );
    let schema = &guide["capability"]["request_schema"];
    let encoded = serde_json::to_string(schema).expect("guide schema");
    assert!(!encoded.contains("\"sql\""));
    assert!(!encoded.contains("\"params\""));
}

#[test]
pub(super) fn mln_0143_invariant_guide_exposes_only_pinned_phase_lineage_input() {
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
        .expect("MLN invariant capability");
    let guide = guide_json(capability);
    assert_eq!(guide["contract_state"], "available");
    assert_eq!(
        guide["call_argv"],
        json!([
            "cfctl",
            "call",
            "mln-0143-data-invariants",
            "--selector",
            "account_id=<account_id>",
            "--selector",
            "database_id=<database_id>",
            "--body-stdin",
            "--json"
        ])
    );
    let encoded = serde_json::to_string(&guide).expect("guide JSON");
    for forbidden in ["\"sql\"", "\"table\"", "\"document_hash\"", "\"output\""] {
        assert!(!encoded.contains(forbidden), "{forbidden}");
    }
}

#[test]
pub(super) fn mln_0143_admission_requires_0142_verified_and_terminal_not_provider_complete_running()
{
    let capability = CapabilityV1::new(
        "d1-import-approved-mln-migration",
        "fixture",
        "POST",
        "/accounts/{account_id}/d1/database/{database_id}/import",
    );
    let mut plan = PlanV1::draft(
        "profile-a",
        "ca30e922fda7f5578e49873542e4aaca",
        "catalog-a",
        capability,
        json!({}),
    )
    .expect("draft plan");
    plan.status = PlanStatus::Running;
    plan.transaction_stage = TransactionStageV1::SecretSinkPersisted;
    assert!(
        !mln_0142_terminal_import_state(&plan),
        "provider_complete Running cannot authorize 0143"
    );
    plan.status = PlanStatus::Verified;
    assert!(
        !mln_0142_terminal_import_state(&plan),
        "Verified without terminal journal closure cannot authorize 0143"
    );
    plan.transaction_stage = TransactionStageV1::Closed;
    assert!(
        mln_0142_terminal_import_state(&plan),
        "only Verified plus Closed is admissible"
    );
}

#[test]
pub(super) fn mln_0143_restore_anchor_join_rejects_every_authority_substitution() {
    let anchor_completed_at = Utc::now() - chrono::Duration::minutes(2);
    let restore_created_at = Utc::now() - chrono::Duration::minutes(1);
    let exact = Mln0143RestoreAnchorJoin {
        input_source_operation_id: "post-0142-anchor".to_owned(),
        receipt_source_operation_id: "post-0142-anchor".to_owned(),
        input_source_evidence_hash: "sha256:anchor-evidence".to_owned(),
        receipt_source_evidence_hash: "sha256:anchor-evidence".to_owned(),
        input_target_bookmark_hash: "sha256:post-0142-bookmark".to_owned(),
        requested_bookmark_hash: "sha256:post-0142-bookmark".to_owned(),
        observed_bookmark_hash: "sha256:post-0142-bookmark".to_owned(),
        account_id: "account".to_owned(),
        profile_id: "profile".to_owned(),
        catalog_hash: "sha256:catalog".to_owned(),
        credential_generation_id: "credential-generation".to_owned(),
        anchor_completed_at,
        restore_created_at,
    };
    assert!(mln_0143_restore_anchor_matches(&exact, &exact));
    for (label, drifted) in [
        ("input operation", {
            let mut value = exact.clone();
            value.input_source_operation_id = "pre-0142-anchor".to_owned();
            value
        }),
        ("receipt operation", {
            let mut value = exact.clone();
            value.receipt_source_operation_id = "grafted-operation".to_owned();
            value
        }),
        ("input evidence", {
            let mut value = exact.clone();
            value.input_source_evidence_hash = "sha256:substitute".to_owned();
            value
        }),
        ("receipt evidence", {
            let mut value = exact.clone();
            value.receipt_source_evidence_hash = "sha256:substitute".to_owned();
            value
        }),
        ("target bookmark", {
            let mut value = exact.clone();
            value.input_target_bookmark_hash = "sha256:pre-0142".to_owned();
            value
        }),
        ("requested bookmark", {
            let mut value = exact.clone();
            value.requested_bookmark_hash = "sha256:pre-0142".to_owned();
            value
        }),
        ("observed bookmark", {
            let mut value = exact.clone();
            value.observed_bookmark_hash = "sha256:pre-0142".to_owned();
            value
        }),
        ("account", {
            let mut value = exact.clone();
            value.account_id = "other-account".to_owned();
            value
        }),
        ("profile", {
            let mut value = exact.clone();
            value.profile_id = "other-profile".to_owned();
            value
        }),
        ("catalog", {
            let mut value = exact.clone();
            value.catalog_hash = "sha256:other-catalog".to_owned();
            value
        }),
        ("credential", {
            let mut value = exact.clone();
            value.credential_generation_id = "other-generation".to_owned();
            value
        }),
        ("chronology", {
            let mut value = exact.clone();
            value.anchor_completed_at = restore_created_at;
            value
        }),
    ] {
        assert!(
            !mln_0143_restore_anchor_matches(&drifted, &exact),
            "{label}"
        );
    }
}

#[test]
pub(super) fn poll_child_resolver_rejects_conditionals_canonical_hash_and_parent_target_grafts() {
    for generations in [1, 2] {
        for conditional in ["if_match", "if_none_match"] {
            let fixture = build_poll_child_lineage(generations);
            let index = generations - 1;
            let mut child = fixture.children[index].clone();
            let response_artifact = child
                .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
                .expect("terminal response artifact")
                .clone();
            let mut input: CallInput =
                serde_json::from_value(child.input.clone()).expect("child input");
            if conditional == "if_match" {
                input.if_match = Some("grafted-etag".to_owned());
            } else {
                input.if_none_match = Some("grafted-etag".to_owned());
            }
            child.input = serde_json::to_value(input).expect("conditional child input");
            let terminal_status = child.status;
            rebuild_poll_child_terminal_lifecycle(&mut child, terminal_status, response_artifact);
            let pins = fixture
                .store
                .load_plan_v2(&child.operation_id)
                .expect("canonical child")
                .pins;
            persist_poll_test_plan_v2(&fixture.store, &child, pins);
            assert!(
                super::exact_linear_poll_child_provider_complete(
                    &fixture.store,
                    &fixture.root_plan
                )
                .is_err(),
                "{conditional} must fail closed for generation {generations}"
            );
        }
    }

    for intermediate in [false, true] {
        let fixture = build_poll_child_lineage(if intermediate { 2 } else { 1 });
        let index = 0;
        let mut child = fixture.children[index].clone();
        let response_artifact = child
            .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
            .expect("response artifact")
            .clone();
        let substituted_hash =
            hash_value(&serde_json::to_value(&fixture.root_plan.capability).expect("root cap"))
                .expect("substituted canonical hash");
        child.targets["adapter"]["approved_mln_import_poll_resume"]["capability_contract_hash"] =
            json!(substituted_hash);
        let status = child.status;
        rebuild_poll_child_terminal_lifecycle(&mut child, status, response_artifact);
        let pins = fixture
            .store
            .load_plan_v2(&child.operation_id)
            .expect("canonical child")
            .pins;
        persist_poll_test_plan_v2(&fixture.store, &child, pins);
        assert!(
            super::exact_linear_poll_child_provider_complete(&fixture.store, &fixture.root_plan)
                .is_err(),
            "another canonical capability hash must not substitute"
        );
    }

    let fixture = build_poll_child_lineage(2);
    let mut terminal = fixture.children[1].clone();
    let response_artifact = terminal
        .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
        .expect("terminal response artifact")
        .clone();
    terminal.targets["adapter"]["approved_mln_import_poll_resume"]["target"] = json!({
        "account_id":"target-b",
        "database_id":"22222222-2222-4222-8222-222222222222",
    });
    let mut input: CallInput =
        serde_json::from_value(terminal.input.clone()).expect("terminal input");
    input.selectors =
        terminal.targets["adapter"]["approved_mln_import_poll_resume"]["target"].clone();
    terminal.input = serde_json::to_value(input).expect("target-grafted input");
    rebuild_poll_child_terminal_lifecycle(&mut terminal, PlanStatus::Running, response_artifact);
    let pins = fixture
        .store
        .load_plan_v2(&terminal.operation_id)
        .expect("canonical terminal")
        .pins;
    persist_poll_test_plan_v2(&fixture.store, &terminal, pins);
    assert!(
        super::exact_linear_poll_child_provider_complete(&fixture.store, &fixture.root_plan)
            .is_err(),
        "terminal target must match its exact intermediate parent"
    );
}

#[test]
pub(super) fn poll_child_resolver_rejects_fully_coordinated_target_b_substitution() {
    for intermediate in [false, true] {
        let fixture = build_poll_child_lineage(if intermediate { 2 } else { 1 });
        let mut child = fixture.children[0].clone();
        let original_apply = (!intermediate).then(|| completed_poll_child_apply_response(&fixture));
        let target_b = json!({
            "account_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "database_id":"22222222-2222-4222-8222-222222222222",
        });
        let contract = child
            .capability
            .d1_approved_mln_import_poll_resume
            .as_mut()
            .expect("poll child contract");
        contract.account_id = target_b["account_id"]
            .as_str()
            .expect("target B account")
            .to_owned();
        contract.database_id = target_b["database_id"]
            .as_str()
            .expect("target B database")
            .to_owned();
        child.account_id = contract.account_id.clone();
        let mut input: CallInput =
            serde_json::from_value(child.input.clone()).expect("child input");
        input.selectors = target_b.clone();
        child.input = serde_json::to_value(input).expect("target B input");
        child.targets["adapter"]["approved_mln_import_poll_resume"]["target"] = target_b.clone();
        child.targets["adapter"]["approved_mln_import_poll_resume"]["root_stage"]["target"] =
            target_b.clone();
        child.targets["adapter"]["approved_mln_import_poll_resume"]["root_input"]["selectors"] =
            target_b.clone();
        child.targets["adapter"]["approved_mln_import_poll_resume"]["capability_contract_hash"] = json!(
            hash_value(&serde_json::to_value(&child.capability).expect("target B capability"))
                .expect("target B capability hash")
        );
        let rewritten = rewrite_poll_test_checkpoints_for_target(&fixture.store, &child, &target_b);
        let response_artifact = if intermediate {
            let (exhaustion_hash, _) = rewritten
                .get("poll_in_progress_exhausted")
                .expect("rewritten exhaustion");
            let accepted_hash = child
                .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
                .and_then(|artifact| artifact.get("accepted_ingest_evidence_hash"))
                .and_then(Value::as_str)
                .expect("accepted evidence hash");
            json!({
                "adapter":"dynamic_api",
                "performed":true,
                "success":false,
                "outcome":"poll_in_progress_exhausted",
                "receipt_available":true,
                "poll_exhaustion_evidence_hash":exhaustion_hash,
                "accepted_ingest_evidence_hash":accepted_hash,
            })
        } else {
            let (_, completion) = rewritten
                .get("provider_complete")
                .expect("rewritten completion");
            let mut response = original_apply.expect("original apply response");
            response["result"]["_cfctl"] = completion["receipt"].clone();
            response["result"]["at_bookmark"] = completion["receipt"]["at_bookmark"].clone();
            response["result"]["result"]["final_bookmark"] =
                completion["receipt"]["final_bookmark"].clone();
            let apply = fixture
                .store
                .write_evidence(EvidenceClass::Apply, &response)
                .expect("target B apply evidence");
            let mut artifact = child
                .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
                .expect("completion response artifact")
                .clone();
            artifact["apply_evidence_hash"] = json!(apply.content_hash);
            artifact
        };
        let status = child.status;
        rebuild_poll_child_terminal_lifecycle(&mut child, status, response_artifact);
        let pins = fixture
            .store
            .load_plan_v2(&child.operation_id)
            .expect("canonical child")
            .pins;
        persist_poll_test_plan_v2(&fixture.store, &child, pins);
        assert!(
            super::exact_linear_poll_child_provider_complete(&fixture.store, &fixture.root_plan)
                .is_err(),
            "fully coordinated target B substitution must fail closed"
        );
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the matrix coordinates root source authority, stage, checkpoints, child lineage, and evidence"
)]
pub(super) fn poll_child_resolver_rejects_recomputed_valid_root_source_authority_grafts() {
    let positive = build_poll_child_lineage(1);
    let positive_root = positive
        .store
        .load_plan_v2(&positive.root_plan.operation_id)
        .expect("canonical positive root");
    super::validate_trusted_root_import_plan(&positive.store, &positive_root)
        .expect("trusted positive root");
    super::exact_linear_poll_child_provider_complete(&positive.store, &positive.root_plan)
        .expect("positive root-to-child completion");

    for graft in [
        "repository_head",
        "repository_id",
        "migration_path_blob",
        "migration_digest",
        "migration_bytes",
    ] {
        let fixture = build_poll_child_lineage(1);
        let mut root = fixture.root_plan.clone();
        let contract = root
            .capability
            .d1_approved_mln_import
            .as_mut()
            .expect("root import contract");
        let migration = contract
            .migrations
            .iter_mut()
            .find(|migration| migration.migration_id == "0143")
            .expect("0143 migration");
        let stage = root
            .targets
            .pointer_mut("/adapter/approved_mln_import")
            .expect("root stage");
        match graft {
            "repository_head" => {
                contract.repository_head = "1111111111111111111111111111111111111111".to_owned();
                stage["source_authority"]["head"] = json!(contract.repository_head);
            }
            "repository_id" => {
                contract.repository_id = "grafted/mln-web".to_owned();
                stage["source_authority"]["repository_id"] = json!(contract.repository_id);
            }
            "migration_path_blob" => {
                migration.repository_relative_path =
                    "grafted/0143_advisor_final_equity_instrument.sql".to_owned();
                migration.git_blob_oid = "2222222222222222222222222222222222222222".to_owned();
                stage["source_authority"]["repository_relative_path"] =
                    json!(migration.repository_relative_path);
                stage["source_authority"]["git_blob_oid"] = json!(migration.git_blob_oid);
            }
            "migration_digest" => {
                migration.sha256 = "33".repeat(32);
                migration.md5 = "44".repeat(16);
                stage["sha256"] = json!(format!("sha256:{}", migration.sha256));
                stage["md5"] = json!(migration.md5);
            }
            "migration_bytes" => {
                migration.bytes = migration.bytes.saturating_add(1);
                stage["bytes"] = json!(migration.bytes);
            }
            _ => unreachable!("closed root graft matrix"),
        }
        stage["source_authority_hash"] =
            json!(hash_value(&stage["source_authority"]).expect("grafted authority hash"));
        let stage = stage.clone();
        root.refresh_hash().expect("grafted root hash");
        let root_pins = fixture
            .store
            .load_plan_v2(&root.operation_id)
            .expect("canonical root")
            .pins;
        persist_poll_test_plan_v2(&fixture.store, &root, root_pins);

        let root_checkpoint_dir = fixture
            .store
            .paths()
            .data_dir
            .join("d1-import-checkpoints")
            .join(&root.operation_id);
        let root_checkpoints = fixture
            .store
            .read_d1_import_checkpoints(&root.operation_id)
            .expect("root checkpoints");
        for entry in fs::read_dir(&root_checkpoint_dir).expect("root checkpoint directory") {
            fs::remove_file(entry.expect("root checkpoint entry").path())
                .expect("remove root checkpoint");
        }
        let mut accepted_hash = None;
        let mut exhaustion_hash = None;
        for (_, mut checkpoint) in root_checkpoints {
            if checkpoint.get("step").and_then(Value::as_str) == Some("poll_in_progress_exhausted")
            {
                checkpoint["receipt"]["source_sha256"] = stage["sha256"].clone();
            }
            let step = checkpoint
                .get("step")
                .and_then(Value::as_str)
                .expect("root checkpoint step")
                .to_owned();
            let hash =
                persist_poll_lineage_checkpoint(&fixture.store, &root.operation_id, &checkpoint);
            if step == "ingest_response" {
                accepted_hash = Some(hash.clone());
            }
            if step == "poll_in_progress_exhausted" {
                exhaustion_hash = Some(hash);
            }
        }
        let accepted_hash = accepted_hash.expect("accepted evidence hash");
        let exhaustion_hash = exhaustion_hash.expect("exhaustion evidence hash");

        let mut child = fixture.children[0].clone();
        let authority = child
            .targets
            .pointer_mut("/adapter/approved_mln_import_poll_resume")
            .expect("child authority");
        authority["root_plan_hash"] = json!(root.content_hash);
        authority["parent_plan_hash"] = json!(root.content_hash);
        authority["parent_exhaustion_evidence_hash"] = json!(exhaustion_hash);
        authority["accepted_ingest_evidence_hash"] = json!(accepted_hash);
        authority["root_input"] = root.input.clone();
        authority["root_stage"] = stage.clone();
        let mut input: CallInput =
            serde_json::from_value(child.input.clone()).expect("child input");
        let body = input
            .body
            .as_mut()
            .and_then(Value::as_object_mut)
            .expect("child input body");
        body.insert("parent_plan_hash".to_owned(), json!(root.content_hash));
        body.insert(
            "exhaustion_evidence_hash".to_owned(),
            json!(exhaustion_hash),
        );
        body.insert(
            "accepted_ingest_evidence_hash".to_owned(),
            json!(accepted_hash),
        );
        child.input = serde_json::to_value(input).expect("rebound child input");

        let checkpoint_dir = fixture
            .store
            .paths()
            .data_dir
            .join("d1-import-checkpoints")
            .join(&child.operation_id);
        let child_checkpoints = fixture
            .store
            .read_d1_import_checkpoints(&child.operation_id)
            .expect("child checkpoints");
        for entry in fs::read_dir(&checkpoint_dir).expect("child checkpoint directory") {
            fs::remove_file(entry.expect("child checkpoint entry").path())
                .expect("remove child checkpoint");
        }
        let child_input_hash = hash_value(&child.input).expect("child input hash");
        let mut completion = None;
        for (_, mut checkpoint) in child_checkpoints {
            checkpoint["receipt"]["plan_input_hash"] = json!(child_input_hash);
            if checkpoint.get("step").and_then(Value::as_str) == Some("provider_complete") {
                checkpoint["receipt"]["source_sha256"] = stage["sha256"].clone();
                checkpoint["receipt"]["source_md5"] = stage["md5"].clone();
                checkpoint["receipt"]["source_bytes"] = stage["bytes"].clone();
                checkpoint["receipt"]["source_authority_hash"] =
                    stage["source_authority_hash"].clone();
                checkpoint["receipt"]["stage_identity_hash"] =
                    json!(hash_value(&stage).expect("grafted stage hash"));
                checkpoint["receipt"]["root_plan_hash"] = json!(root.content_hash);
                checkpoint["receipt"]["parent_exhaustion_evidence_hash"] = json!(exhaustion_hash);
                completion = Some(checkpoint.clone());
            }
            persist_poll_lineage_checkpoint(&fixture.store, &child.operation_id, &checkpoint);
        }
        let completion = completion.expect("rebound completion");
        let mut apply_response = completed_poll_child_apply_response(&fixture);
        apply_response["result"]["_cfctl"] = completion["receipt"].clone();
        apply_response["result"]["at_bookmark"] = completion["receipt"]["at_bookmark"].clone();
        apply_response["result"]["result"]["final_bookmark"] =
            completion["receipt"]["final_bookmark"].clone();
        let apply = fixture
            .store
            .write_evidence(EvidenceClass::Apply, &apply_response)
            .expect("rebound completion evidence");
        let mut response_artifact = child
            .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
            .expect("child response artifact")
            .clone();
        response_artifact["apply_evidence_hash"] = json!(apply.content_hash);
        rebuild_poll_child_terminal_lifecycle(&mut child, PlanStatus::Running, response_artifact);
        let child_pins = fixture
            .store
            .load_plan_v2(&child.operation_id)
            .expect("canonical child")
            .pins;
        persist_poll_test_plan_v2(&fixture.store, &child, child_pins);

        let grafted_root = fixture
            .store
            .load_plan_v2(&root.operation_id)
            .expect("grafted root PlanV2");
        assert!(
            super::validate_trusted_root_import_plan(&fixture.store, &grafted_root).is_err(),
            "{graft} must fail direct trusted-root admission"
        );
        assert!(
            super::exact_durable_provider_complete_boundary(&fixture.store, &root.operation_id)
                .is_err(),
            "{graft} must fail direct completion resolution"
        );
        assert!(
            super::exact_linear_poll_child_provider_complete(&fixture.store, &root).is_err(),
            "{graft} must fail root-to-child completion resolution"
        );
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the matrix rebinds every root-input dependent child receipt and PlanV2 lifecycle"
)]
pub(super) fn poll_child_resolver_rejects_recomputed_valid_root_input_grafts() {
    for graft in [
        "if_match",
        "if_none_match",
        "missing_selector",
        "extra_selector",
        "wrong_selector",
        "nonempty_query",
        "extra_body_key",
        "unknown_migration",
        "missing_pre_anchor_field",
        "wrong_type_pre_anchor_field",
        "missing_0143_prior_field",
        "wrong_type_0143_prior_field",
        "missing_0143_invariant_field",
        "wrong_type_0143_invariant_field",
        "drifted_prior_boundary",
        "drifted_post_anchor",
    ] {
        let fixture = build_poll_child_lineage(1);
        let mut root = fixture.root_plan.clone();
        let mut input: CallInput = serde_json::from_value(root.input.clone()).expect("root input");
        match graft {
            "if_match" => input.if_match = Some("grafted-etag".to_owned()),
            "if_none_match" => input.if_none_match = Some("grafted-etag".to_owned()),
            "missing_selector" => {
                input
                    .selectors
                    .as_object_mut()
                    .expect("root selectors")
                    .remove("database_id");
            }
            "extra_selector" => {
                input
                    .selectors
                    .as_object_mut()
                    .expect("root selectors")
                    .insert("extra".to_owned(), json!("grafted"));
            }
            "wrong_selector" => {
                input.selectors["database_id"] = json!("22222222-2222-4222-8222-222222222222");
            }
            "nonempty_query" => input.query = json!({"extra":"grafted"}),
            "extra_body_key" => {
                input
                    .body
                    .as_mut()
                    .and_then(Value::as_object_mut)
                    .expect("root body")
                    .insert("extra".to_owned(), json!("grafted"));
            }
            "unknown_migration" => {
                input
                    .body
                    .as_mut()
                    .and_then(Value::as_object_mut)
                    .expect("root body")
                    .insert("migration_id".to_owned(), json!("9999"));
            }
            "missing_pre_anchor_field" => {
                input
                    .body
                    .as_mut()
                    .and_then(Value::as_object_mut)
                    .expect("root body")
                    .remove("pre_recovery_anchor_evidence_hash");
            }
            "wrong_type_pre_anchor_field" => {
                input.body.as_mut().expect("root body")["pre_recovery_anchor_operation_id"] =
                    json!(42);
            }
            "missing_0143_prior_field" => {
                input
                    .body
                    .as_mut()
                    .and_then(Value::as_object_mut)
                    .expect("root body")
                    .remove("prior_0142_schema_proof_operation_id");
            }
            "wrong_type_0143_prior_field" => {
                input.body.as_mut().expect("root body")["prior_0142_operation_id"] = json!(false);
            }
            "missing_0143_invariant_field" => {
                input
                    .body
                    .as_mut()
                    .and_then(Value::as_object_mut)
                    .expect("root body")
                    .remove("pre_import_invariant_evidence_hash");
            }
            "wrong_type_0143_invariant_field" => {
                input.body.as_mut().expect("root body")["pre_import_invariant_operation_id"] =
                    json!([]);
            }
            "drifted_prior_boundary" => {
                input.body.as_mut().expect("root body")["prior_0142_boundary_evidence_hash"] =
                    json!(format!("sha256:{}", "9".repeat(64)));
            }
            "drifted_post_anchor" => {
                input.body.as_mut().expect("root body")["post_0142_anchor_operation_id"] =
                    json!(Uuid::new_v4());
            }
            _ => unreachable!("closed root input graft matrix"),
        }
        root.input = serde_json::to_value(input).expect("grafted root input");
        if graft == "unknown_migration" {
            root.targets["adapter"]["approved_mln_import"]["migration_id"] = json!("9999");
        }
        root.targets["adapter"]["approved_mln_import"]["prerequisites"] =
            root.input.get("body").cloned().unwrap_or(Value::Null);
        root.refresh_hash().expect("grafted root hash");
        let root_pins = fixture
            .store
            .load_plan_v2(&root.operation_id)
            .expect("canonical root")
            .pins;
        persist_poll_test_plan_v2(&fixture.store, &root, root_pins);

        let mut child = fixture.children[0].clone();
        child.targets["adapter"]["approved_mln_import_poll_resume"]["root_plan_hash"] =
            json!(root.content_hash);
        child.targets["adapter"]["approved_mln_import_poll_resume"]["parent_plan_hash"] =
            json!(root.content_hash);
        child.targets["adapter"]["approved_mln_import_poll_resume"]["root_input"] =
            root.input.clone();
        child.targets["adapter"]["approved_mln_import_poll_resume"]["root_stage"] =
            root.targets["adapter"]["approved_mln_import"].clone();
        let mut child_input: CallInput =
            serde_json::from_value(child.input.clone()).expect("child input");
        child_input
            .body
            .as_mut()
            .and_then(Value::as_object_mut)
            .expect("child body")
            .insert("parent_plan_hash".to_owned(), json!(root.content_hash));
        child.input = serde_json::to_value(child_input).expect("rebound child input");

        let checkpoint_dir = fixture
            .store
            .paths()
            .data_dir
            .join("d1-import-checkpoints")
            .join(&child.operation_id);
        let checkpoints = fixture
            .store
            .read_d1_import_checkpoints(&child.operation_id)
            .expect("child checkpoints");
        for entry in fs::read_dir(&checkpoint_dir).expect("child checkpoint directory") {
            fs::remove_file(entry.expect("child checkpoint entry").path())
                .expect("remove child checkpoint");
        }
        let child_input_hash = hash_value(&child.input).expect("child input hash");
        let mut completion = None;
        for (_, mut checkpoint) in checkpoints {
            checkpoint["receipt"]["plan_input_hash"] = json!(child_input_hash);
            if checkpoint.get("step").and_then(Value::as_str) == Some("provider_complete") {
                checkpoint["receipt"]["root_plan_hash"] = json!(root.content_hash);
                completion = Some(checkpoint.clone());
            }
            persist_poll_lineage_checkpoint(&fixture.store, &child.operation_id, &checkpoint);
        }
        let completion = completion.expect("rebound completion");
        let mut apply_response = completed_poll_child_apply_response(&fixture);
        apply_response["result"]["_cfctl"] = completion["receipt"].clone();
        let apply = fixture
            .store
            .write_evidence(EvidenceClass::Apply, &apply_response)
            .expect("rebound apply evidence");
        let mut response_artifact = child
            .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
            .expect("child response artifact")
            .clone();
        response_artifact["apply_evidence_hash"] = json!(apply.content_hash);
        rebuild_poll_child_terminal_lifecycle(&mut child, PlanStatus::Running, response_artifact);
        let child_pins = fixture
            .store
            .load_plan_v2(&child.operation_id)
            .expect("canonical child")
            .pins;
        persist_poll_test_plan_v2(&fixture.store, &child, child_pins);

        let root_v2 = fixture
            .store
            .load_plan_v2(&root.operation_id)
            .expect("grafted root PlanV2");
        assert!(
            super::validate_trusted_root_import_plan(&fixture.store, &root_v2).is_err(),
            "{graft} must fail trusted-root input admission"
        );
        assert!(
            super::exact_durable_provider_complete_boundary(&fixture.store, &root.operation_id)
                .is_err(),
            "{graft} must fail direct completion resolution"
        );
        assert!(
            super::exact_linear_poll_child_provider_complete(&fixture.store, &root).is_err(),
            "{graft} must fail root-to-child completion resolution"
        );
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the adversarial anchor fixture keeps every joined authority dimension visible"
)]
pub(super) fn mln_import_anchor_requires_the_exact_governed_export_join() {
    let after = Utc::now();
    let completed_at = after + ChronoDuration::seconds(10);
    let before = completed_at + ChronoDuration::seconds(10);
    let evidence = EvidenceV1::new(
        EvidenceClass::LiveRead,
        "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        "/tmp/export-evidence.json",
    );
    let binding = D1FullExportGovernedExecutionBindingV1 {
        schema_version: 1,
        operation_id: "11111111-1111-4111-8111-111111111111".to_owned(),
        capability_id: "d1-full-export".to_owned(),
        catalog_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .to_owned(),
        target_scope_hash:
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
        output_file_sha256:
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_owned(),
        at_bookmark_hash: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
            .to_owned(),
        manifest_evidence_hash: evidence.content_hash.clone(),
        request_hash: "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            .to_owned(),
        profile_id: "profile-a".to_owned(),
        credential_generation_id: "22222222-2222-4222-8222-222222222222".to_owned(),
        completion_status: "completed".to_owned(),
        completed_at,
    };
    let build = |binding: D1FullExportGovernedExecutionBindingV1| {
        let mut proof = OperationalProofV1::new(
            binding.completed_at,
            "d1-full-export",
            &binding.catalog_hash,
            &binding.request_hash,
            OperationalProofScopeV1::new(
                Some("profile-a"),
                Some("account-a"),
                Some("22222222-2222-4222-8222-222222222222"),
            ),
            OperationalProofOutcomeV1::Succeeded,
            evidence.clone(),
        );
        proof
            .bind_d1_full_export_governed_execution(binding)
            .expect("valid export binding");
        proof
    };
    let proof = build(binding.clone());
    let exact = D1RecoveryAnchorExpectation {
        operation_id: &binding.operation_id,
        evidence_hash: &binding.manifest_evidence_hash,
        output_sha256: Some(&binding.output_file_sha256),
        bookmark_hash: &binding.at_bookmark_hash,
        catalog_hash: &binding.catalog_hash,
        request_hash: &binding.request_hash,
        target_scope_hash: &binding.target_scope_hash,
        account_id: "account-a",
        profile_id: "profile-a",
        credential_generation_id: Some(&binding.credential_generation_id),
        after: Some(after),
        before,
    };
    assert!(d1_recovery_anchor_matches(&proof, &exact));
    assert!(
        d1_recovery_anchor_matches(
            &proof,
            &D1RecoveryAnchorExpectation {
                after: None,
                ..exact
            }
        ),
        "the same typed export is a valid pre-migration anchor when it predates the plan"
    );
    assert_eq!(
        [proof.clone(), proof.clone()]
            .iter()
            .filter(|candidate| d1_recovery_anchor_matches(candidate, &exact))
            .count(),
        2,
        "the admission cardinality gate must reject duplicate matching proof rows"
    );
    for drifted in [
        D1RecoveryAnchorExpectation {
            operation_id: "33333333-3333-4333-8333-333333333333",
            ..exact
        },
        D1RecoveryAnchorExpectation {
            evidence_hash: "sha256:9999999999999999999999999999999999999999999999999999999999999999",
            ..exact
        },
        D1RecoveryAnchorExpectation {
            output_sha256: Some(
                "sha256:9999999999999999999999999999999999999999999999999999999999999999",
            ),
            ..exact
        },
        D1RecoveryAnchorExpectation {
            bookmark_hash: "sha256:9999999999999999999999999999999999999999999999999999999999999999",
            ..exact
        },
        D1RecoveryAnchorExpectation {
            catalog_hash: "sha256:9999999999999999999999999999999999999999999999999999999999999999",
            ..exact
        },
        D1RecoveryAnchorExpectation {
            request_hash: "sha256:9999999999999999999999999999999999999999999999999999999999999999",
            ..exact
        },
        D1RecoveryAnchorExpectation {
            target_scope_hash: "sha256:9999999999999999999999999999999999999999999999999999999999999999",
            ..exact
        },
        D1RecoveryAnchorExpectation {
            profile_id: "other-profile",
            ..exact
        },
        D1RecoveryAnchorExpectation {
            credential_generation_id: Some("33333333-3333-4333-8333-333333333333"),
            ..exact
        },
        D1RecoveryAnchorExpectation {
            after: Some(completed_at),
            ..exact
        },
        D1RecoveryAnchorExpectation {
            before: completed_at,
            ..exact
        },
    ] {
        assert!(!d1_recovery_anchor_matches(&proof, &drifted));
    }
    let mut stale = binding.clone();
    stale.completed_at = after - ChronoDuration::seconds(1);
    assert!(
        !d1_recovery_anchor_matches(&build(stale), &exact),
        "a pre-0142 export cannot serve as the post-0142 anchor"
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the adversarial fixture keeps every pre-import authority and chronology dimension visible"
)]
pub(super) fn mln_0143_pre_import_requires_one_current_authority_proof_after_recovery_anchor() {
    let after = Utc::now();
    let completed_at = after + ChronoDuration::seconds(10);
    let before = completed_at + ChronoDuration::seconds(10);
    let evidence = EvidenceV1::new(
        EvidenceClass::LiveRead,
        "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        "/tmp/pre-import-evidence.json",
    );
    let binding = Mln0143GovernedExecutionBindingV1 {
        schema_version: 1,
        operation_id: "11111111-1111-4111-8111-111111111111".to_owned(),
        capability_id: "mln-0143-data-invariants".to_owned(),
        capability_version: 5,
        validator_contract_hash:
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        fixed_query_sha256:
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
        catalog_hash: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            .to_owned(),
        target_scope_hash:
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_owned(),
        phase: "pre_import".to_owned(),
        manifest_evidence_hash: evidence.content_hash.clone(),
        request_hash: "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            .to_owned(),
        profile_identity_hash: hash_value(&json!({
            "profile_id":"profile-a",
            "credential_generation_id":"22222222-2222-4222-8222-222222222222",
        }))
        .expect("profile identity"),
        credential_generation_id: "22222222-2222-4222-8222-222222222222".to_owned(),
        completion_status: "completed".to_owned(),
        completed_at,
        cross_operation_lineage_hash: None,
    };
    let build = |binding: Mln0143GovernedExecutionBindingV1| {
        let mut proof = OperationalProofV1::new(
            binding.completed_at,
            "mln-0143-data-invariants",
            &binding.catalog_hash,
            &binding.request_hash,
            OperationalProofScopeV1::new(
                Some("profile-a"),
                Some("account-a"),
                Some("22222222-2222-4222-8222-222222222222"),
            ),
            OperationalProofOutcomeV1::Succeeded,
            evidence.clone(),
        );
        proof
            .bind_mln_0143_governed_execution(binding)
            .expect("valid pre-import binding");
        proof
    };
    let proof = build(binding.clone());
    let exact = Mln0143PreImportExpectation {
        operation_id: &binding.operation_id,
        evidence_hash: &binding.manifest_evidence_hash,
        catalog_hash: &binding.catalog_hash,
        request_hash: &binding.request_hash,
        target_scope_hash: &binding.target_scope_hash,
        account_id: "account-a",
        profile_id: "profile-a",
        credential_generation_id: Some(&binding.credential_generation_id),
        capability_version: binding.capability_version,
        validator_contract_hash: &binding.validator_contract_hash,
        fixed_query_sha256: &binding.fixed_query_sha256,
        after,
        before,
    };
    assert!(mln_0143_pre_import_matches(&proof, &exact));
    assert_eq!(
        [proof.clone(), proof.clone()]
            .iter()
            .filter(|candidate| mln_0143_pre_import_authority_matches(candidate, &exact))
            .count(),
        2,
        "duplicate or intervening current-authority proofs must invalidate admission"
    );
    for drifted in [
        Mln0143PreImportExpectation {
            operation_id: "33333333-3333-4333-8333-333333333333",
            ..exact
        },
        Mln0143PreImportExpectation {
            evidence_hash: "sha256:9999999999999999999999999999999999999999999999999999999999999999",
            ..exact
        },
        Mln0143PreImportExpectation {
            catalog_hash: "sha256:9999999999999999999999999999999999999999999999999999999999999999",
            ..exact
        },
        Mln0143PreImportExpectation {
            request_hash: "sha256:9999999999999999999999999999999999999999999999999999999999999999",
            ..exact
        },
        Mln0143PreImportExpectation {
            target_scope_hash: "sha256:9999999999999999999999999999999999999999999999999999999999999999",
            ..exact
        },
        Mln0143PreImportExpectation {
            profile_id: "other-profile",
            ..exact
        },
        Mln0143PreImportExpectation {
            credential_generation_id: Some("33333333-3333-4333-8333-333333333333"),
            ..exact
        },
        Mln0143PreImportExpectation {
            capability_version: 3,
            ..exact
        },
        Mln0143PreImportExpectation {
            validator_contract_hash: "sha256:9999999999999999999999999999999999999999999999999999999999999999",
            ..exact
        },
        Mln0143PreImportExpectation {
            fixed_query_sha256: "sha256:9999999999999999999999999999999999999999999999999999999999999999",
            ..exact
        },
        Mln0143PreImportExpectation {
            after: completed_at,
            ..exact
        },
        Mln0143PreImportExpectation {
            before: completed_at,
            ..exact
        },
    ] {
        assert!(!mln_0143_pre_import_matches(&proof, &drifted));
    }
    let mut stale = binding.clone();
    stale.completed_at = after - ChronoDuration::seconds(1);
    assert!(
        !mln_0143_pre_import_matches(&build(stale), &exact),
        "a proof before 0142 closure or the recovery anchor must fail"
    );
    let mut after_plan = binding.clone();
    after_plan.completed_at = before + ChronoDuration::seconds(1);
    assert!(
        !mln_0143_pre_import_matches(&build(after_plan), &exact),
        "a proof after the immutable plan cutoff must fail"
    );
}

#[test]
pub(super) fn closed_import_recovery_bookmark_must_be_fresh_at_plan_time() {
    let evaluate = |age: ChronoDuration| {
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
            .get("d1-import-approved-osint-research-migration")
            .expect("OSINT Research migration capability");
        let contract = capability
            .d1_approved_mln_import
            .as_ref()
            .expect("OSINT Research migration contract");
        let before = Utc::now();
        let bookmark = "osint-pre-migration-bookmark";
        let evidence = store
            .write_evidence(
                EvidenceClass::LiveRead,
                &json!({
                    "status":200,
                    "success":true,
                    "result":{"bookmark":bookmark},
                }),
            )
            .expect("bookmark evidence");
        let input = CallInput {
            selectors: json!({
                "account_id":contract.account_id,
                "database_id":contract.database_id,
            }),
            query: json!({}),
            body: Some(json!({
                "migration_id":"0028",
                "pre_recovery_anchor_evidence_hash":evidence.content_hash,
                "pre_recovery_anchor_bookmark_hash":hash_value(&json!(bookmark))
                    .expect("bookmark hash"),
            })),
            ..CallInput::default()
        };
        let proof_input_hash = hash_value(
            &serde_json::to_value(CallInput {
                selectors: input.selectors.clone(),
                query: json!({}),
                ..CallInput::default()
            })
            .expect("proof input"),
        )
        .expect("proof input hash");
        let proof = OperationalProofV1::new(
            before - age,
            "d1-time-travel-get-bookmark",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &proof_input_hash,
            OperationalProofScopeV1::new(
                Some("osint-profile"),
                Some(contract.account_id.as_str()),
                Some("22222222-2222-4222-8222-222222222222"),
            ),
            OperationalProofOutcomeV1::Succeeded,
            evidence,
        );
        store
            .record_operational_proof(&proof)
            .expect("bookmark proof");
        validate_closed_import_recovery_bookmark(
            &store,
            &input,
            input
                .body
                .as_ref()
                .and_then(Value::as_object)
                .expect("closed body"),
            contract,
            ImportPrerequisiteContext {
                profile_id: "osint-profile",
                credential_generation_id: Some("22222222-2222-4222-8222-222222222222"),
                catalog_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                import_operation_id: None,
                before,
            },
            "OSINT Research",
        )
    };

    assert!(evaluate(ChronoDuration::minutes(9)).is_ok());
    assert!(matches!(
        evaluate(ChronoDuration::minutes(11)),
        Err(CliError::Input(reason)) if reason.contains("10 minutes before planning")
    ));
}
