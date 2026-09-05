use super::*;

pub(super) fn save_current_test_plan(store: &StorageStateStore, plan: &PlanV1) {
    let document = PlanV2::new(
        plan.clone(),
        PlanPinsV2 {
            build_identity_hash: "sha256:test-build".to_owned(),
            catalog_hash: plan.catalog_hash.clone(),
            credential_generation_id: "22222222-2222-4222-8222-222222222222".to_owned(),
            admission_policy_hash: "compiled:test-policy".to_owned(),
            authority_hash: None,
            workspace_graph_hash: "sha256:test-workspace".to_owned(),
            resource_observation_hashes: BTreeMap::new(),
            cost_budget: None,
        },
    )
    .expect("current PlanV2 fixture");
    store
        .save_plan_v2(&document)
        .expect("persist current PlanV2 fixture");
}

pub(super) struct PollChildLineageFixture {
    pub(super) _root: tempfile::TempDir,
    pub(super) store: StorageStateStore,
    pub(super) root_plan: PlanV1,
    pub(super) children: Vec<PlanV1>,
}

pub(super) const POLL_FIXTURE_CATALOG_HASH: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
pub(super) const POLL_FIXTURE_CREDENTIAL_GENERATION: &str = "22222222-2222-4222-8222-222222222222";

pub(super) fn persist_poll_lineage_checkpoint(
    store: &StorageStateStore,
    operation_id: &str,
    checkpoint: &Value,
) -> String {
    let hash = store
        .record_d1_import_checkpoint(operation_id, checkpoint)
        .expect("persist lineage checkpoint");
    assert_eq!(
        store
            .write_evidence(EvidenceClass::Apply, checkpoint)
            .expect("persist lineage evidence")
            .content_hash,
        hash
    );
    hash
}

pub(super) fn record_test_export_anchor(
    store: &StorageStateStore,
    contract: &cfctl_core::D1ApprovedMlnImportContractV1,
    catalog_hash: &str,
    completed_at: chrono::DateTime<Utc>,
    bookmark: &str,
) -> (String, String, String, String) {
    let operation_id = Uuid::new_v4().to_string();
    let output_sha256 = format!("sha256:{}", "a".repeat(64));
    let bookmark_hash = hash_value(&json!(bookmark)).expect("bookmark hash");
    let target_scope_hash = hash_value(&json!({
        "account_id":contract.account_id,
        "database_id":contract.database_id,
    }))
    .expect("target hash");
    let request_hash = hash_value(
        &serde_json::to_value(CallInput {
            selectors: json!({
                "account_id":contract.account_id,
                "database_id":contract.database_id,
            }),
            query: json!({}),
            ..CallInput::default()
        })
        .expect("export input"),
    )
    .expect("export request hash");
    let evidence = store
        .write_evidence(
            EvidenceClass::LiveRead,
            &json!({"operation_id":operation_id,"bookmark":bookmark}),
        )
        .expect("anchor evidence");
    let binding = D1FullExportGovernedExecutionBindingV1 {
        schema_version: 1,
        operation_id: operation_id.clone(),
        capability_id: "d1-full-export".to_owned(),
        catalog_hash: catalog_hash.to_owned(),
        target_scope_hash,
        output_file_sha256: output_sha256.clone(),
        at_bookmark_hash: bookmark_hash.clone(),
        manifest_evidence_hash: evidence.content_hash.clone(),
        request_hash: request_hash.clone(),
        profile_id: "profile-a".to_owned(),
        credential_generation_id: POLL_FIXTURE_CREDENTIAL_GENERATION.to_owned(),
        completion_status: "completed".to_owned(),
        completed_at,
    };
    let mut proof = OperationalProofV1::new(
        completed_at,
        "d1-full-export",
        catalog_hash,
        &request_hash,
        OperationalProofScopeV1::new(
            Some("profile-a"),
            Some(&contract.account_id),
            Some(POLL_FIXTURE_CREDENTIAL_GENERATION),
        ),
        OperationalProofOutcomeV1::Succeeded,
        evidence.clone(),
    );
    proof
        .bind_d1_full_export_governed_execution(binding)
        .expect("bind export anchor");
    store
        .record_operational_proof(&proof)
        .expect("record export anchor");
    (
        operation_id,
        evidence.content_hash,
        output_sha256,
        bookmark_hash,
    )
}

#[expect(
    clippy::too_many_lines,
    reason = "the production-shaped fixture materializes the entire governed 0142 to 0143 authority chain"
)]
pub(super) fn authentic_0143_prerequisites(
    store: &StorageStateStore,
    root_capability: &CapabilityV1,
    root_created_at: chrono::DateTime<Utc>,
) -> Value {
    let contract = root_capability
        .d1_approved_mln_import
        .as_ref()
        .expect("root import contract");
    let selectors = json!({
        "account_id":contract.account_id,
        "database_id":contract.database_id,
    });
    let (pre_operation, pre_evidence, pre_output, pre_bookmark) = record_test_export_anchor(
        store,
        contract,
        POLL_FIXTURE_CATALOG_HASH,
        root_created_at - ChronoDuration::minutes(50),
        "pre-0142",
    );
    let body_0142 = json!({
        "migration_id":"0142",
        "pre_recovery_anchor_operation_id":pre_operation,
        "pre_recovery_anchor_evidence_hash":pre_evidence,
        "pre_recovery_anchor_output_sha256":pre_output,
        "pre_recovery_anchor_bookmark_hash":pre_bookmark,
    });
    let migration = contract
        .migrations
        .iter()
        .find(|migration| migration.migration_id == "0142")
        .expect("0142 migration");
    let mut prior = PlanV1::draft(
        "profile-a",
        &contract.account_id,
        POLL_FIXTURE_CATALOG_HASH,
        root_capability.clone(),
        json!({}),
    )
    .expect("0142 plan");
    prior.created_at = root_created_at - ChronoDuration::minutes(40);
    prior.expires_at = root_created_at + ChronoDuration::minutes(20);
    prior.input = serde_json::to_value(CallInput {
        selectors: selectors.clone(),
        query: json!({}),
        body: Some(body_0142.clone()),
        ..CallInput::default()
    })
    .expect("0142 input");
    prior
        .precondition_hashes
        .insert("catalog".to_owned(), prior.catalog_hash.clone());
    let authority = json!({
        "schema_version":1,
        "repository_id":contract.repository_id,
        "observed_worktree_root":"/reviewed/mln-web",
        "observed_git_common_dir":"/reviewed/mln-web/.git",
        "head":contract.repository_head,
        "repository_relative_path":migration.repository_relative_path,
        "git_blob_oid":migration.git_blob_oid,
    });
    let stage = json!({
        "schema_version":1,
        "migration_id":"0142",
        "catalog_basename":migration.basename,
        "source_authority":authority,
        "source_authority_hash":hash_value(&authority).expect("0142 authority hash"),
        "bytes":migration.bytes,
        "sha256":format!("sha256:{}",migration.sha256),
        "md5":migration.md5,
        "stage_path":"/managed/0142.sql",
        "stage_lifecycle":"preserve_until_verified_or_explicitly_retired",
        "target":selectors,
        "prerequisites":body_0142,
    });
    prior.targets = json!({"adapter":{"approved_mln_import":stage}});
    prior.refresh_hash().expect("0142 plan hash");
    prior.approve(true, None).expect("approve 0142");
    prior.mark_consumed().expect("consume 0142");
    prior
        .record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("0142 boundary attempt");
    let input_hash = hash_value(&prior.input).expect("0142 input hash");
    let accepted = json!({
        "schema_version":1,"operation_id":prior.operation_id,"step":"ingest_response",
        "performed":true,"rectification_required":false,
        "receipt":{"http_status":200,"success":true,"response_action":"ingest",
            "provider":"cloudflare","effect":"d1_import_ingest_accepted",
            "migration_id":"0142","target":selectors,"plan_input_hash":input_hash,
            "no_replay":false,"result":{"type":"import","status":"active","success":true,
                "at_bookmark":"accepted-0142"},"errors":[]}
    });
    persist_poll_lineage_checkpoint(store, &prior.operation_id, &accepted);
    let completion = json!({
        "schema_version":1,"operation_id":prior.operation_id,"step":"provider_complete",
        "performed":true,"rectification_required":false,
        "receipt":{"provider":"cloudflare","effect":"d1_import_provider_complete",
            "response_action":"poll","no_replay":true,"state":"provider_complete",
            "provider_status":"complete","provider_success":true,"migration_id":"0142",
            "target":selectors,"plan_input_hash":input_hash,
            "source_sha256":stage["sha256"],"source_md5":stage["md5"],
            "source_bytes":stage["bytes"],"source_authority_hash":stage["source_authority_hash"],
            "stage_identity_hash":hash_value(&stage).expect("0142 stage hash"),
            "prerequisites":body_0142,"at_bookmark":"accepted-0142",
            "final_bookmark":"completed-0142"}
    });
    let boundary_hash = persist_poll_lineage_checkpoint(store, &prior.operation_id, &completion);
    prior.status = PlanStatus::Running;
    prior
        .record_transaction_stage(TransactionStageV1::BoundaryResponsePersisted)
        .expect("0142 boundary response");
    prior
        .record_transaction_stage(TransactionStageV1::SecretSinkPersisted)
        .expect("0142 secret sink");
    let proof_operation = Uuid::new_v4().to_string();
    let verification = store
        .write_evidence(
            EvidenceClass::Apply,
            &json!({"state":"verified","operation_id":prior.operation_id,
                    "provider_complete_evidence_hash":boundary_hash,
                    "post_import_operation_id":proof_operation}),
        )
        .expect("0142 verification evidence");
    prior.status = PlanStatus::Verified;
    prior
        .record_transaction_stage(TransactionStageV1::VerificationAttemptPersisted)
        .expect("0142 verification attempt");
    prior
        .record_transaction_stage_with_artifact(
            TransactionStageV1::VerificationResponsePersisted,
            json!({"evidence_hash":verification.content_hash}),
        )
        .expect("0142 verification response");
    prior
        .record_transaction_stage(TransactionStageV1::Closed)
        .expect("close 0142");
    prior.refresh_hash().expect("terminal 0142 hash");
    save_current_test_plan(store, &prior);
    let schema_evidence = store
        .write_evidence(
            EvidenceClass::LiveRead,
            &json!({"operation_id":proof_operation,"migration_id":"0142"}),
        )
        .expect("0142 schema evidence");
    let schema_capability = super::trusted_native_capability("mln-0142-post-import-schema")
        .expect("0142 schema capability");
    let schema_contract = schema_capability
        .mln_0142_post_import_schema
        .expect("0142 schema contract");
    let schema_request_hash =
        hash_value(&json!({"fixture":"0142-schema"})).expect("0142 schema request hash");
    let mut schema_proof = OperationalProofV1::new(
        root_created_at - ChronoDuration::minutes(20),
        "mln-0142-post-import-schema",
        POLL_FIXTURE_CATALOG_HASH,
        &schema_request_hash,
        OperationalProofScopeV1::new(
            Some("profile-a"),
            Some(&contract.account_id),
            Some(POLL_FIXTURE_CREDENTIAL_GENERATION),
        ),
        OperationalProofOutcomeV1::Succeeded,
        schema_evidence.clone(),
    );
    schema_proof
            .bind_mln_0142_governed_execution(Mln0142GovernedExecutionBindingV1 {
                schema_version: 1,
                operation_id: proof_operation.clone(),
                capability_id: "mln-0142-post-import-schema".to_owned(),
                capability_version: 1,
                catalog_hash: POLL_FIXTURE_CATALOG_HASH.to_owned(),
                target_scope_hash: hash_value(&selectors).expect("target hash"),
                import_operation_id: prior.operation_id.clone(),
                import_boundary_evidence_hash: boundary_hash.clone(),
                import_source_sha256:
                    "sha256:07e1c5bd77dd529bfe58f0eee80ad29c40fdd0f3e9c9a37163cfaa0683124af0"
                        .to_owned(),
                import_plan_hash: prior.content_hash.clone(),
                final_bookmark_hash: hash_value(&json!("completed-0142"))
                    .expect("final bookmark hash"),
                trigger_name: schema_contract.trigger_name,
                trigger_definition_sha256: schema_contract.trigger_definition_sha256,
                manifest_evidence_hash: schema_evidence.content_hash.clone(),
                request_hash: schema_request_hash,
                credential_generation_id: POLL_FIXTURE_CREDENTIAL_GENERATION.to_owned(),
                completion_status: "completed".to_owned(),
                completed_at: root_created_at - ChronoDuration::minutes(20),
            })
            .expect("bind 0142 schema proof");
    store
        .record_operational_proof(&schema_proof)
        .expect("record 0142 schema proof");
    let (post_operation, post_evidence, _, post_bookmark) = record_test_export_anchor(
        store,
        contract,
        POLL_FIXTURE_CATALOG_HASH,
        root_created_at - ChronoDuration::minutes(10),
        "post-0142",
    );
    let invariant_operation = Uuid::new_v4().to_string();
    let invariant_evidence = store
        .write_evidence(
            EvidenceClass::LiveRead,
            &json!({"operation_id":invariant_operation,"migration_id":"0143","phase":"pre_import"}),
        )
        .expect("0143 invariant evidence");
    let invariant_request_hash = hash_value(
        &serde_json::to_value(CallInput {
            selectors: selectors.clone(),
            query: json!({}),
            body: Some(json!({"migration_id":"0143","phase":"pre_import"})),
            ..CallInput::default()
        })
        .expect("0143 invariant input"),
    )
    .expect("0143 invariant request hash");
    let completed_at = root_created_at - ChronoDuration::minutes(5);
    let mut invariant_proof = OperationalProofV1::new(
        completed_at,
        "mln-0143-data-invariants",
        POLL_FIXTURE_CATALOG_HASH,
        &invariant_request_hash,
        OperationalProofScopeV1::new(
            Some("profile-a"),
            Some(&contract.account_id),
            Some(POLL_FIXTURE_CREDENTIAL_GENERATION),
        ),
        OperationalProofOutcomeV1::Succeeded,
        invariant_evidence.clone(),
    );
    invariant_proof
        .bind_mln_0143_governed_execution(Mln0143GovernedExecutionBindingV1 {
            schema_version: 1,
            operation_id: invariant_operation.clone(),
            capability_id: "mln-0143-data-invariants".to_owned(),
            capability_version: contract.pre_import_capability_version,
            validator_contract_hash: contract.pre_import_validator_contract_hash.clone(),
            fixed_query_sha256: contract.pre_import_fixed_query_sha256.clone(),
            catalog_hash: POLL_FIXTURE_CATALOG_HASH.to_owned(),
            target_scope_hash: hash_value(&selectors).expect("target hash"),
            phase: "pre_import".to_owned(),
            manifest_evidence_hash: invariant_evidence.content_hash.clone(),
            request_hash: invariant_request_hash,
            profile_identity_hash: hash_value(&json!({
                "profile_id":"profile-a",
                "credential_generation_id":POLL_FIXTURE_CREDENTIAL_GENERATION,
            }))
            .expect("profile identity hash"),
            credential_generation_id: POLL_FIXTURE_CREDENTIAL_GENERATION.to_owned(),
            completion_status: "completed".to_owned(),
            completed_at,
            cross_operation_lineage_hash: None,
        })
        .expect("bind 0143 invariant");
    store
        .record_operational_proof(&invariant_proof)
        .expect("record 0143 invariant");
    json!({
        "migration_id":"0143",
        "pre_recovery_anchor_operation_id":pre_operation,
        "pre_recovery_anchor_evidence_hash":pre_evidence,
        "pre_recovery_anchor_output_sha256":pre_output,
        "pre_recovery_anchor_bookmark_hash":pre_bookmark,
        "prior_0142_operation_id":prior.operation_id,
        "prior_0142_boundary_evidence_hash":boundary_hash,
        "prior_0142_schema_proof_operation_id":proof_operation,
        "prior_0142_verification_evidence_hash":verification.content_hash,
        "post_0142_anchor_operation_id":post_operation,
        "post_0142_anchor_evidence_hash":post_evidence,
        "post_0142_anchor_bookmark_hash":post_bookmark,
        "pre_import_invariant_operation_id":invariant_operation,
        "pre_import_invariant_evidence_hash":invariant_evidence.content_hash,
    })
}

#[expect(
    clippy::too_many_lines,
    reason = "the fixture builds the exact root exhaustion and immutable child lifecycle"
)]
pub(super) fn build_poll_child_lineage(generations: usize) -> PollChildLineageFixture {
    assert!((1..=2).contains(&generations));
    let root = tempfile::tempdir().expect("poll lineage root");
    let store = authenticated_test_store(RuntimePaths::from_root(root.path()));
    let mut catalog = CatalogSnapshot {
        schema_version: 1,
        generated_at: Utc::now(),
        source_url: "test://native".to_owned(),
        source_hash: "sha256:test".to_owned(),
        schema_hash: String::new(),
        capabilities: BTreeMap::new(),
    };
    ingest_native_control_capabilities(&mut catalog).expect("native overlay");
    let root_capability = catalog
        .capabilities
        .remove("d1-import-approved-mln-migration")
        .expect("root import capability");
    let root_poll_bound = root_capability
        .d1_approved_mln_import
        .as_ref()
        .expect("root contract")
        .max_poll_attempts;
    let child_capability = catalog
        .capabilities
        .remove("d1-resume-approved-mln-import-poll")
        .expect("child poll capability");
    let child_poll_bound = child_capability
        .d1_approved_mln_import_poll_resume
        .as_ref()
        .expect("child contract")
        .max_poll_attempts;
    let root_contract = root_capability
        .d1_approved_mln_import
        .clone()
        .expect("root contract");
    let migration = root_contract
        .migrations
        .iter()
        .find(|migration| migration.migration_id == "0143")
        .expect("0143 migration");
    let mut root_plan = PlanV1::draft(
        "profile-a",
        &root_contract.account_id,
        POLL_FIXTURE_CATALOG_HASH,
        root_capability.clone(),
        json!({}),
    )
    .expect("root plan");
    root_plan.created_at = Utc::now() + ChronoDuration::hours(1);
    root_plan.expires_at = root_plan.created_at + ChronoDuration::hours(1);
    let prerequisites =
        authentic_0143_prerequisites(&store, &root_capability, root_plan.created_at);
    root_plan.input = serde_json::to_value(CallInput {
        selectors: json!({
            "account_id":root_contract.account_id,
            "database_id":root_contract.database_id,
        }),
        query: json!({}),
        body: Some(prerequisites),
        ..CallInput::default()
    })
    .expect("root input");
    root_plan
        .precondition_hashes
        .insert("catalog".to_owned(), root_plan.catalog_hash.clone());
    let source_authority = json!({
        "schema_version":1,
        "repository_id":root_contract.repository_id,
        "observed_worktree_root":"/reviewed/mln-web",
        "observed_git_common_dir":"/reviewed/mln-web/.git",
        "head":root_contract.repository_head,
        "repository_relative_path":migration.repository_relative_path,
        "git_blob_oid":migration.git_blob_oid,
    });
    let root_stage = json!({
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
            "account_id":root_contract.account_id,
            "database_id":root_contract.database_id,
        },
        "prerequisites":root_plan.input.get("body"),
    });
    root_plan.targets = json!({"adapter":{"approved_mln_import":root_stage}});
    root_plan.refresh_hash().expect("root plan hash");
    save_current_test_plan(&store, &root_plan);

    let root_target = json!({
        "account_id":root_contract.account_id,
        "database_id":root_contract.database_id,
    });
    let root_input_hash = hash_value(&root_plan.input).expect("root input hash");
    let accepted = json!({
        "schema_version":1,
        "operation_id":root_plan.operation_id,
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
            "target":root_target,
            "plan_input_hash":root_input_hash,
            "no_replay":false,
            "result":{
                "type":"import",
                "status":"active",
                "success":true,
                "at_bookmark":"accepted",
            },
            "errors":[],
        }
    });
    let accepted_hash = persist_poll_lineage_checkpoint(&store, &root_plan.operation_id, &accepted);
    for attempt in 1..=root_poll_bound {
        let root_poll = json!({
            "schema_version":1,
            "operation_id":root_plan.operation_id,
            "step":format!("poll_response_{attempt}"),
            "performed":true,
            "rectification_required":false,
            "receipt":{
                "http_status":200,"success":true,"response_action":"poll",
                "provider":"cloudflare","effect":"d1_import_response",
                "migration_id":"0143","target":root_target,"plan_input_hash":root_input_hash,
                "result":{"type":"import","status":"active","success":true,
                    "at_bookmark":"accepted","result":{"final_bookmark":null},
                    "provider_error_present":false},
                "errors":[],"provider_errors_present":false,"no_replay":false,
                "etag_present":false,"etag_sha256":null,"cf_ray":null
            }
        });
        persist_poll_lineage_checkpoint(&store, &root_plan.operation_id, &root_poll);
    }
    let root_exhaustion = json!({
        "schema_version":1,
        "operation_id":root_plan.operation_id,
        "step":"poll_in_progress_exhausted",
        "performed":true,
        "rectification_required":true,
        "receipt":{
            "provider":"cloudflare","effect":"d1_import_poll_in_progress_exhausted",
            "migration_id":"0143","target":root_target,"plan_input_hash":root_input_hash,
            "source_sha256":root_stage["sha256"],"at_bookmark":"accepted",
            "attempt_count":root_poll_bound,"attempt_bound":root_poll_bound,
            "outcome":"poll_in_progress_exhausted","receipt_available":true,"no_replay":true
        }
    });
    let mut parent_exhaustion_hash =
        persist_poll_lineage_checkpoint(&store, &root_plan.operation_id, &root_exhaustion);
    let mut parent = root_plan.clone();
    let mut children = Vec::new();
    for generation in 1..=generations {
        let mut child = PlanV1::draft(
            "profile-a",
            &root_contract.account_id,
            POLL_FIXTURE_CATALOG_HASH,
            child_capability.clone(),
            json!({}),
        )
        .expect("child plan");
        child.created_at = parent.created_at + ChronoDuration::seconds(1);
        child.expires_at = child.created_at + ChronoDuration::hours(1);
        child.input = serde_json::to_value(CallInput {
            selectors: json!({
                "account_id":root_contract.account_id,
                "database_id":root_contract.database_id,
            }),
            body: Some(json!({
                "parent_operation_id":parent.operation_id,
                "parent_plan_hash":parent.content_hash,
                "exhaustion_evidence_hash":parent_exhaustion_hash,
                "accepted_ingest_evidence_hash":accepted_hash,
                "accepted_bookmark_hash":hash_value(&json!("accepted"))
                    .expect("bookmark hash"),
            })),
            ..CallInput::default()
        })
        .expect("child input");
        child.targets = json!({"adapter":{"approved_mln_import_poll_resume":{
            "root_operation_id":root_plan.operation_id,
            "root_plan_hash":root_plan.content_hash,
            "parent_operation_id":parent.operation_id,
            "parent_plan_hash":parent.content_hash,
            "parent_exhaustion_evidence_hash":parent_exhaustion_hash,
            "accepted_ingest_evidence_hash":accepted_hash,
            "accepted_bookmark":"accepted",
            "accepted_bookmark_hash":hash_value(&json!("accepted")).expect("bookmark hash"),
            "root_input":root_plan.input,
            "root_stage":root_stage,
            "profile_id":"profile-a",
            "credential_generation_id":POLL_FIXTURE_CREDENTIAL_GENERATION,
            "catalog_hash":POLL_FIXTURE_CATALOG_HASH,
            "capability_contract_hash":hash_value(
                &serde_json::to_value(&child_capability).expect("child capability value")
            ).expect("child capability hash"),
            "target":root_target,
        }}});
        child.refresh_hash().expect("child hash");
        child.approve(true, None).expect("approve child");
        child.mark_consumed().expect("consume child");
        child
            .record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
            .expect("child boundary attempt");
        let child_input_hash = hash_value(&child.input).expect("child input hash");
        if generation == generations {
            let completion = json!({
                "schema_version":1,
                "operation_id":child.operation_id,
                "step":"provider_complete",
                "performed":true,
                "rectification_required":false,
                "receipt":{
                    "provider":"cloudflare","effect":"d1_import_provider_complete",
                    "response_action":"poll","migration_id":"0143","target":root_target,
                    "plan_input_hash":child_input_hash,
                    "source_sha256":root_stage["sha256"],
                    "source_md5":root_stage["md5"],
                    "source_bytes":root_stage["bytes"],
                    "source_authority_hash":root_stage["source_authority_hash"],
                    "stage_identity_hash":hash_value(&root_stage).expect("stage hash"),
                    "at_bookmark":"accepted","final_bookmark":"completed",
                    "root_operation_id":root_plan.operation_id,
                    "root_plan_hash":root_plan.content_hash,
                    "parent_operation_id":parent.operation_id,
                    "parent_exhaustion_evidence_hash":parent_exhaustion_hash,
                }
            });
            persist_poll_lineage_checkpoint(&store, &child.operation_id, &completion);
            child.status = PlanStatus::Running;
            let response = CloudflareResponseV1 {
                status: 200,
                success: true,
                result: json!({
                    "type":"import",
                    "status":"complete",
                    "success":true,
                    "at_bookmark":"accepted",
                    "result":{"final_bookmark":"completed"},
                    "_cfctl":completion["receipt"],
                }),
                errors: Vec::new(),
                result_info: None,
                etag: None,
                cf_ray: None,
            };
            assert!(matches!(
                super::process_api_boundary_response(
                    &store,
                    &mut child,
                    &response,
                    &MemorySecretStore::default(),
                )
                .expect("production completion lifecycle"),
                super::ApiBoundaryResponseOutcome::Ready { .. }
            ));
        } else {
            for attempt in 1..=child_poll_bound {
                let child_poll = json!({
                    "schema_version":1,
                    "operation_id":child.operation_id,
                    "step":format!("poll_response_{attempt}"),
                    "performed":true,
                    "rectification_required":false,
                    "receipt":{
                        "http_status":200,"success":true,"response_action":"poll",
                        "provider":"cloudflare","effect":"d1_import_response",
                        "migration_id":"0143","target":root_target,"plan_input_hash":child_input_hash,
                        "result":{"type":"import","status":"active","success":true,
                            "at_bookmark":"accepted","result":{"final_bookmark":null},
                            "provider_error_present":false},
                        "errors":[],"provider_errors_present":false,"no_replay":false,
                        "etag_present":false,"etag_sha256":null,"cf_ray":null
                    }
                });
                persist_poll_lineage_checkpoint(&store, &child.operation_id, &child_poll);
            }
            let exhaustion = json!({
                "schema_version":1,
                "operation_id":child.operation_id,
                "step":"poll_in_progress_exhausted",
                "performed":true,
                "rectification_required":true,
                "receipt":{
                    "provider":"cloudflare","effect":"d1_import_poll_in_progress_exhausted",
                    "migration_id":"0143","target":root_target,"plan_input_hash":child_input_hash,
                    "source_sha256":root_stage["sha256"],"at_bookmark":"accepted",
                    "attempt_count":child_poll_bound,"attempt_bound":child_poll_bound,
                    "outcome":"poll_in_progress_exhausted","receipt_available":true,
                    "no_replay":true
                }
            });
            parent_exhaustion_hash =
                persist_poll_lineage_checkpoint(&store, &child.operation_id, &exhaustion);
            let envelope = super::known_import_poll_exhausted_envelope(
                &store,
                &mut child,
                &MemorySecretStore::default(),
            );
            assert!(!envelope.ok);
            assert_eq!(child.status, PlanStatus::RectificationRequired);
        }
        save_current_test_plan(&store, &child);
        parent = child.clone();
        children.push(child);
    }
    PollChildLineageFixture {
        _root: root,
        store,
        root_plan,
        children,
    }
}

#[test]
pub(super) fn poll_child_resolver_accepts_exact_one_and_two_generation_plan_v2_lineages() {
    for generations in [1, 2] {
        let fixture = build_poll_child_lineage(generations);
        let boundary =
            super::exact_linear_poll_child_provider_complete(&fixture.store, &fixture.root_plan)
                .expect("exact child lineage");
        assert_eq!(
            boundary
                .checkpoint
                .pointer("/receipt/final_bookmark")
                .and_then(Value::as_str),
            Some("completed")
        );
        assert_eq!(fixture.children.len(), generations);
    }
}

#[test]
pub(super) fn trusted_root_validator_accepts_direct_0142_and_0143_completion_authorities() {
    let fixture = build_poll_child_lineage(1);
    let root_v2 = fixture
        .store
        .load_plan_v2(&fixture.root_plan.operation_id)
        .expect("canonical 0143 root");
    super::validate_trusted_root_import_plan(&fixture.store, &root_v2)
        .expect("authentic 0143 root");
    let root_input: CallInput =
        serde_json::from_value(fixture.root_plan.input.clone()).expect("0143 input");
    let prior_0142 = root_input
        .body
        .as_ref()
        .and_then(|body| body.get("prior_0142_operation_id"))
        .and_then(Value::as_str)
        .expect("prior 0142 operation");
    let prior_v2 = fixture
        .store
        .load_plan_v2(prior_0142)
        .expect("canonical 0142 root");
    super::validate_trusted_root_import_plan(&fixture.store, &prior_v2)
        .expect("authentic 0142 root");
    super::exact_durable_provider_complete_boundary(&fixture.store, prior_0142)
        .expect("direct exact 0142 completion");

    let stage = &fixture.root_plan.targets["adapter"]["approved_mln_import"];
    let provider_target = stage["target"].clone();
    let completion = json!({
        "schema_version":1,"operation_id":fixture.root_plan.operation_id,
        "step":"provider_complete","performed":true,"rectification_required":false,
        "receipt":{"provider":"cloudflare","effect":"d1_import_provider_complete",
            "response_action":"poll","no_replay":true,"state":"provider_complete",
            "provider_status":"complete","provider_success":true,"migration_id":"0143",
            "target":provider_target,"plan_input_hash":hash_value(&fixture.root_plan.input)
                .expect("0143 input hash"),
            "source_sha256":stage["sha256"],"source_md5":stage["md5"],
            "source_bytes":stage["bytes"],"source_authority_hash":stage["source_authority_hash"],
            "stage_identity_hash":hash_value(stage).expect("0143 stage hash"),
            "prerequisites":root_input.body,"at_bookmark":"accepted",
            "final_bookmark":"completed-direct-0143"}
    });
    persist_poll_lineage_checkpoint(&fixture.store, &fixture.root_plan.operation_id, &completion);
    super::exact_durable_provider_complete_boundary(
        &fixture.store,
        &fixture.root_plan.operation_id,
    )
    .expect("direct exact 0143 completion");
}

#[test]
pub(super) fn poll_child_resolver_rejects_required_plan_v2_sidecar_missing() {
    let fixture = build_poll_child_lineage(1);
    let child = fixture.children.first().expect("poll child");
    fs::remove_file(
        fixture
            .store
            .paths()
            .data_dir
            .join("plans-v2")
            .join(format!("{}.json", child.operation_id)),
    )
    .expect("remove required PlanV2 sidecar");
    let error =
        super::exact_linear_poll_child_provider_complete(&fixture.store, &fixture.root_plan)
            .expect_err("missing PlanV2 sidecar must fail closed");
    assert!(
        error.to_string().contains("authentic PlanV2 sidecar"),
        "{error}"
    );
}

pub(super) fn reset_poll_child_to_draft(child: &mut PlanV1) {
    child.status = PlanStatus::Draft;
    child.approval = None;
    child.transaction_stage = TransactionStageV1::PlanPrepared;
    child.transaction_journal.clear();
    child.transaction_artifacts.clear();
    child
        .record_transaction_stage(TransactionStageV1::PlanPrepared)
        .expect("restore prepared draft lifecycle");
}

pub(super) fn persist_rebound_poll_child(store: &StorageStateStore, child: &PlanV1) {
    store
        .save_plan(child)
        .expect("persist rebound canonical child and projection");
}

#[test]
pub(super) fn poll_child_resolver_rejects_projection_drift() {
    let fixture = build_poll_child_lineage(1);
    let mut projection = fixture.children[0].clone();
    projection
        .verification_steps
        .push("projection drift".to_owned());
    projection
        .refresh_hash()
        .expect("refresh drifted projection");
    let path = fixture
        .store
        .paths()
        .data_dir
        .join("plans")
        .join(format!("{}.json", projection.operation_id));
    fs::write(
        path,
        serde_json::to_vec_pretty(&projection).expect("encode drifted projection"),
    )
    .expect("write drifted compatibility projection");
    assert!(
        super::exact_linear_poll_child_provider_complete(&fixture.store, &fixture.root_plan)
            .is_err()
    );
}

#[test]
pub(super) fn poll_child_resolver_rejects_unapproved_unconsumed_and_missing_attempt_lifecycles() {
    let unapproved = build_poll_child_lineage(1);
    let mut unapproved_child = unapproved.children[0].clone();
    reset_poll_child_to_draft(&mut unapproved_child);
    persist_rebound_poll_child(&unapproved.store, &unapproved_child);
    assert!(
        super::exact_linear_poll_child_provider_complete(&unapproved.store, &unapproved.root_plan)
            .is_err()
    );

    let unconsumed = build_poll_child_lineage(1);
    let mut unconsumed_child = unconsumed.children[0].clone();
    reset_poll_child_to_draft(&mut unconsumed_child);
    unconsumed_child
        .approve(true, None)
        .expect("approve unconsumed child");
    persist_rebound_poll_child(&unconsumed.store, &unconsumed_child);
    assert!(
        super::exact_linear_poll_child_provider_complete(&unconsumed.store, &unconsumed.root_plan)
            .is_err()
    );

    let missing_attempt = build_poll_child_lineage(1);
    let mut missing_attempt_child = missing_attempt.children[0].clone();
    reset_poll_child_to_draft(&mut missing_attempt_child);
    missing_attempt_child
        .approve(true, None)
        .expect("approve missing-attempt child");
    missing_attempt_child
        .mark_consumed()
        .expect("consume missing-attempt child");
    persist_rebound_poll_child(&missing_attempt.store, &missing_attempt_child);
    assert!(
        super::exact_linear_poll_child_provider_complete(
            &missing_attempt.store,
            &missing_attempt.root_plan
        )
        .is_err()
    );
}

#[test]
pub(super) fn poll_child_resolver_rejects_missing_or_mismatched_boundary_response_artifacts() {
    for replacement in [None, Some(json!({"outcome":"grafted"}))] {
        let fixture = build_poll_child_lineage(1);
        let child = fixture.children.first().expect("poll child");
        let v2_path = fixture
            .store
            .paths()
            .data_dir
            .join("plans-v2")
            .join(format!("{}.json", child.operation_id));
        let projection_path = fixture
            .store
            .paths()
            .data_dir
            .join("plans")
            .join(format!("{}.json", child.operation_id));
        let mut current = fixture
            .store
            .load_plan_v2(&child.operation_id)
            .expect("canonical child");
        match replacement.clone() {
            Some(value) => {
                current.plan.transaction_artifacts.insert(
                    TransactionStageV1::BoundaryResponsePersisted
                        .as_str()
                        .to_owned(),
                    value,
                );
            }
            None => {
                current
                    .plan
                    .transaction_artifacts
                    .remove(TransactionStageV1::BoundaryResponsePersisted.as_str());
            }
        }
        fs::write(
            &v2_path,
            serde_json::to_vec_pretty(&current).expect("encode corrupt canonical child"),
        )
        .expect("write corrupt canonical child");
        fs::write(
            &projection_path,
            serde_json::to_vec_pretty(&current.plan).expect("encode corrupt child projection"),
        )
        .expect("write corrupt child projection");
        assert!(
            super::exact_linear_poll_child_provider_complete(&fixture.store, &fixture.root_plan)
                .is_err()
        );
    }
}

#[test]
pub(super) fn poll_child_resolver_rejects_duplicate_completion_and_lineage_grafts() {
    let duplicate = build_poll_child_lineage(1);
    let child = duplicate.children.first().expect("poll child");
    let (_, completion) = duplicate
        .store
        .read_d1_import_checkpoints(&child.operation_id)
        .expect("child checkpoints")
        .into_iter()
        .find(|(_, checkpoint)| {
            checkpoint.get("step").and_then(Value::as_str) == Some("provider_complete")
        })
        .expect("provider completion");
    persist_poll_lineage_checkpoint(&duplicate.store, &child.operation_id, &completion);
    assert!(
        super::exact_linear_poll_child_provider_complete(&duplicate.store, &duplicate.root_plan)
            .is_err()
    );

    for pointer in [
        "/adapter/approved_mln_import_poll_resume/parent_operation_id",
        "/adapter/approved_mln_import_poll_resume/root_operation_id",
    ] {
        let fixture = build_poll_child_lineage(1);
        let mut grafted = fixture.children[0].clone();
        reset_poll_child_to_draft(&mut grafted);
        *grafted
            .targets
            .pointer_mut(pointer)
            .expect("lineage graft pointer") = json!(grafted.operation_id);
        grafted.refresh_hash().expect("refresh grafted child");
        grafted.approve(true, None).expect("approve grafted child");
        grafted.mark_consumed().expect("consume grafted child");
        grafted
            .record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
            .expect("grafted child attempt");
        grafted
            .record_transaction_stage_with_artifact(
                TransactionStageV1::BoundaryResponsePersisted,
                json!({"outcome":"grafted"}),
            )
            .expect("grafted child response");
        persist_rebound_poll_child(&fixture.store, &grafted);
        assert!(
            super::exact_linear_poll_child_provider_complete(&fixture.store, &fixture.root_plan)
                .is_err()
        );
    }
}

pub(super) fn poll_test_evidence_path(store: &StorageStateStore, hash: &str) -> PathBuf {
    store
        .paths()
        .data_dir
        .join("evidence")
        .join(format!("{}.json", hash.trim_start_matches("sha256:")))
}

pub(super) fn exact_poll_test_secret_artifact() -> Value {
    json!({
        "completed":true,
        "failure":Value::Null,
        "input_cleanup":{"required":false,"completed":true},
        "output_sink":{"required":false,"completed":true,"create_new":false,
            "format":Value::Null,
            "unix_mode":if cfg!(unix) {
                Value::String("0600".to_owned())
            } else {
                Value::Null
            }},
        "path":Value::Null,
    })
}

pub(super) fn rebuild_poll_child_terminal_lifecycle(
    child: &mut PlanV1,
    terminal_status: PlanStatus,
    response_artifact: Value,
) {
    reset_poll_child_to_draft(child);
    child.refresh_hash().expect("refresh rebound child");
    child.approve(true, None).expect("approve rebound child");
    child.mark_consumed().expect("consume rebound child");
    child
        .record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("rebound boundary attempt");
    child.status = terminal_status;
    child
        .record_transaction_stage_with_artifact(
            TransactionStageV1::BoundaryResponsePersisted,
            response_artifact,
        )
        .expect("rebound boundary response");
    child
        .record_transaction_stage_with_artifact(
            TransactionStageV1::SecretSinkPersisted,
            exact_poll_test_secret_artifact(),
        )
        .expect("rebound secret lifecycle");
}

pub(super) fn rebind_poll_child_terminal_lifecycle(
    store: &StorageStateStore,
    child: &mut PlanV1,
    terminal_status: PlanStatus,
    response_artifact: Value,
) {
    rebuild_poll_child_terminal_lifecycle(child, terminal_status, response_artifact);
    persist_rebound_poll_child(store, child);
}

pub(super) fn persist_poll_test_plan_v2(
    store: &StorageStateStore,
    plan: &PlanV1,
    pins: PlanPinsV2,
) {
    let document = PlanV2::new(plan.clone(), pins).expect("valid drifted PlanV2");
    let projection_path = store
        .paths()
        .data_dir
        .join("plans")
        .join(format!("{}.json", plan.operation_id));
    let current_path = store
        .paths()
        .data_dir
        .join("plans-v2")
        .join(format!("{}.json", plan.operation_id));
    fs::write(
        projection_path,
        serde_json::to_vec_pretty(plan).expect("encode drifted projection"),
    )
    .expect("persist drifted projection");
    fs::write(
        current_path,
        serde_json::to_vec_pretty(&document).expect("encode drifted PlanV2"),
    )
    .expect("persist drifted PlanV2");
}

pub(super) fn rewrite_poll_test_checkpoints_for_target(
    store: &StorageStateStore,
    plan: &PlanV1,
    expected_target: &Value,
) -> BTreeMap<String, (String, Value)> {
    let checkpoints = store
        .read_d1_import_checkpoints(&plan.operation_id)
        .expect("read target-drift checkpoints");
    let directory = store
        .paths()
        .data_dir
        .join("d1-import-checkpoints")
        .join(&plan.operation_id);
    for entry in fs::read_dir(&directory).expect("checkpoint directory") {
        fs::remove_file(entry.expect("checkpoint entry").path()).expect("remove old checkpoint");
    }
    let input_hash = hash_value(&plan.input).expect("target-drift input hash");
    checkpoints
        .into_iter()
        .map(|(_, mut checkpoint)| {
            checkpoint["receipt"]["target"] = expected_target.clone();
            checkpoint["receipt"]["plan_input_hash"] = json!(input_hash);
            let step = checkpoint
                .get("step")
                .and_then(Value::as_str)
                .expect("checkpoint step")
                .to_owned();
            let hash = persist_poll_lineage_checkpoint(store, &plan.operation_id, &checkpoint);
            (step, (hash, checkpoint))
        })
        .collect()
}

pub(super) fn rebind_completed_poll_child_apply_evidence(
    fixture: &PollChildLineageFixture,
    apply_response: &Value,
) {
    let mut child = fixture.children[0].clone();
    let evidence = fixture
        .store
        .write_evidence(EvidenceClass::Apply, apply_response)
        .expect("replacement apply evidence");
    let mut response_artifact = child
        .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
        .expect("completion response artifact")
        .clone();
    response_artifact["apply_evidence_hash"] = json!(evidence.content_hash);
    rebind_poll_child_terminal_lifecycle(
        &fixture.store,
        &mut child,
        PlanStatus::Running,
        response_artifact,
    );
}

pub(super) fn completed_poll_child_apply_response(fixture: &PollChildLineageFixture) -> Value {
    let child = &fixture.children[0];
    let hash = child
        .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
        .and_then(|artifact| artifact.get("apply_evidence_hash"))
        .and_then(Value::as_str)
        .expect("completion apply evidence hash");
    fixture
        .store
        .read_evidence_value(hash)
        .expect("completion apply evidence")
}

#[test]
pub(super) fn poll_child_resolver_rejects_missing_or_corrupt_completion_apply_evidence() {
    for corrupt in [false, true] {
        let fixture = build_poll_child_lineage(1);
        let child = &fixture.children[0];
        let hash = child
            .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
            .and_then(|artifact| artifact.get("apply_evidence_hash"))
            .and_then(Value::as_str)
            .expect("completion apply evidence hash");
        let path = poll_test_evidence_path(&fixture.store, hash);
        if corrupt {
            fs::write(path, b"{\"corrupt\":true}").expect("corrupt completion evidence");
        } else {
            fs::remove_file(path).expect("remove completion evidence");
        }
        assert!(
            super::exact_linear_poll_child_provider_complete(&fixture.store, &fixture.root_plan)
                .is_err()
        );
    }
}

#[test]
pub(super) fn poll_child_resolver_rejects_grafted_or_semantically_drifted_completion_evidence() {
    let mutations = [
        ("/status", json!(202)),
        ("/success", json!(false)),
        ("/result/type", json!("export")),
        ("/result/status", json!("active")),
        ("/result/success", json!(false)),
        ("/result/at_bookmark", json!("other")),
        ("/result/result/final_bookmark", json!("other")),
        ("/result/_cfctl/response_action", json!("init")),
        ("/result/_cfctl/root_operation_id", json!(Uuid::new_v4())),
        ("/result/_cfctl/final_bookmark", json!("other")),
    ];
    for (pointer, replacement) in mutations {
        let fixture = build_poll_child_lineage(1);
        let mut apply_response = completed_poll_child_apply_response(&fixture);
        *apply_response
            .pointer_mut(pointer)
            .unwrap_or_else(|| panic!("missing completion semantic pointer {pointer}")) =
            replacement;
        rebind_completed_poll_child_apply_evidence(&fixture, &apply_response);
        assert!(
            super::exact_linear_poll_child_provider_complete(&fixture.store, &fixture.root_plan)
                .is_err(),
            "completion evidence drift at {pointer} must fail closed"
        );
    }

    let fixture = build_poll_child_lineage(1);
    let mut valid_other = completed_poll_child_apply_response(&fixture);
    valid_other["result"]["_cfctl"]["root_operation_id"] = json!(Uuid::new_v4());
    valid_other["result"]["_cfctl"]["parent_operation_id"] = json!(Uuid::new_v4());
    rebind_completed_poll_child_apply_evidence(&fixture, &valid_other);
    assert!(
        super::exact_linear_poll_child_provider_complete(&fixture.store, &fixture.root_plan)
            .is_err(),
        "an otherwise valid response from another operation must not graft"
    );
}

#[test]
pub(super) fn poll_child_resolver_rejects_missing_or_corrupt_exhaustion_lineage_evidence() {
    for evidence_kind in ["exhaustion", "accepted"] {
        for corrupt in [false, true] {
            let fixture = build_poll_child_lineage(2);
            let exhausted = &fixture.children[0];
            let artifact = exhausted
                .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
                .expect("exhaustion response artifact");
            let hash = artifact
                .get(match evidence_kind {
                    "exhaustion" => "poll_exhaustion_evidence_hash",
                    _ => "accepted_ingest_evidence_hash",
                })
                .and_then(Value::as_str)
                .expect("lineage evidence hash");
            let path = poll_test_evidence_path(&fixture.store, hash);
            if corrupt {
                fs::write(path, b"{\"corrupt\":true}")
                    .expect("corrupt exhaustion lineage evidence");
            } else {
                fs::remove_file(path).expect("remove exhaustion lineage evidence");
            }
            assert!(
                super::exact_linear_poll_child_provider_complete(
                    &fixture.store,
                    &fixture.root_plan
                )
                .is_err(),
                "{evidence_kind} evidence must be authentic"
            );
        }
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the matrix grafts every exhaustion and accepted-ingest semantic dimension"
)]
pub(super) fn poll_child_resolver_rejects_grafted_or_semantically_drifted_exhaustion_evidence() {
    let fixture = build_poll_child_lineage(2);
    let mut exhausted = fixture.children[0].clone();
    let unrelated = fixture
        .store
        .write_evidence(
            EvidenceClass::Apply,
            &json!({
                "schema_version":1,
                "operation_id":Uuid::new_v4(),
                "step":"ingest_response",
                "performed":true,
                "rectification_required":false,
                "receipt":{"result":{"at_bookmark":"accepted"}}
            }),
        )
        .expect("grafted accepted evidence");
    exhausted.targets["adapter"]["approved_mln_import_poll_resume"]["accepted_ingest_evidence_hash"] =
        json!(unrelated.content_hash);
    let exhaustion_hash = exhausted
        .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
        .and_then(|artifact| artifact.get("poll_exhaustion_evidence_hash"))
        .and_then(Value::as_str)
        .expect("exhaustion evidence hash")
        .to_owned();
    rebind_poll_child_terminal_lifecycle(
        &fixture.store,
        &mut exhausted,
        PlanStatus::RectificationRequired,
        json!({
            "adapter":"dynamic_api",
            "performed":true,
            "success":false,
            "outcome":"poll_in_progress_exhausted",
            "receipt_available":true,
            "poll_exhaustion_evidence_hash":exhaustion_hash,
            "accepted_ingest_evidence_hash":unrelated.content_hash,
        }),
    );
    let current = fixture
        .store
        .load_plan_v2(&exhausted.operation_id)
        .expect("rebound exhausted child");
    assert!(
        super::validate_canonical_poll_child_lifecycle(&fixture.store, &current).is_err(),
        "semantically unrelated accepted evidence must not graft"
    );

    let fixture = build_poll_child_lineage(2);
    let mut exhausted = fixture.children[0].clone();
    let graft = fixture
        .store
        .write_evidence(EvidenceClass::Apply, &json!({"other":"exhaustion"}))
        .expect("grafted exhaustion evidence");
    let accepted_hash = exhausted
        .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
        .and_then(|artifact| artifact.get("accepted_ingest_evidence_hash"))
        .and_then(Value::as_str)
        .expect("accepted evidence hash")
        .to_owned();
    rebind_poll_child_terminal_lifecycle(
        &fixture.store,
        &mut exhausted,
        PlanStatus::RectificationRequired,
        json!({
            "adapter":"dynamic_api",
            "performed":true,
            "success":false,
            "outcome":"poll_in_progress_exhausted",
            "receipt_available":true,
            "poll_exhaustion_evidence_hash":graft.content_hash,
            "accepted_ingest_evidence_hash":accepted_hash,
        }),
    );
    let current = fixture
        .store
        .load_plan_v2(&exhausted.operation_id)
        .expect("rebound exhausted child");
    assert!(
        super::validate_canonical_poll_child_lifecycle(&fixture.store, &current).is_err(),
        "a valid but unrelated exhaustion evidence object must not graft"
    );

    let fixture = build_poll_child_lineage(2);
    let mut exhausted = fixture.children[0].clone();
    let checkpoint_dir = fixture
        .store
        .paths()
        .data_dir
        .join("d1-import-checkpoints")
        .join(&exhausted.operation_id);
    let exhaustion_path = fs::read_dir(&checkpoint_dir)
        .expect("exhaustion checkpoint directory")
        .map(|entry| entry.expect("checkpoint entry").path())
        .find(|path| {
            fs::read(path)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                .and_then(|checkpoint| {
                    checkpoint
                        .get("step")
                        .and_then(Value::as_str)
                        .map(|step| step == "poll_in_progress_exhausted")
                })
                .unwrap_or(false)
        })
        .expect("exhaustion checkpoint path");
    let mut semantic_mismatch: Value =
        serde_json::from_slice(&fs::read(&exhaustion_path).expect("read exhaustion checkpoint"))
            .expect("decode exhaustion checkpoint");
    fs::remove_file(exhaustion_path).expect("remove original exhaustion checkpoint");
    semantic_mismatch["receipt"]["outcome"] = json!("different");
    let exhaustion_hash = persist_poll_lineage_checkpoint(
        &fixture.store,
        &exhausted.operation_id,
        &semantic_mismatch,
    );
    let accepted_hash = exhausted
        .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
        .and_then(|artifact| artifact.get("accepted_ingest_evidence_hash"))
        .and_then(Value::as_str)
        .expect("accepted evidence hash")
        .to_owned();
    rebind_poll_child_terminal_lifecycle(
        &fixture.store,
        &mut exhausted,
        PlanStatus::RectificationRequired,
        json!({
            "adapter":"dynamic_api",
            "performed":true,
            "success":false,
            "outcome":"poll_in_progress_exhausted",
            "receipt_available":true,
            "poll_exhaustion_evidence_hash":exhaustion_hash,
            "accepted_ingest_evidence_hash":accepted_hash,
        }),
    );
    let current = fixture
        .store
        .load_plan_v2(&exhausted.operation_id)
        .expect("semantically drifted exhausted child");
    assert!(
        super::validate_canonical_poll_child_lifecycle(&fixture.store, &current).is_err(),
        "semantically mismatched exhaustion evidence must fail closed"
    );
}

#[test]
fn direct_ingest_completion_requires_exact_durable_terminal_ingest() {
    let fixture = build_poll_child_lineage(1);
    for defect in ["none", "final_bookmark", "action", "target", "not_durable"] {
        let original = &fixture.root_plan;
        let mut plan = PlanV1::draft(
            &original.profile_id,
            &original.account_id,
            &original.catalog_hash,
            original.capability.clone(),
            json!({}),
        )
        .expect("fresh import");
        plan.created_at = original.created_at;
        plan.expires_at = original.expires_at;
        plan.input = original.input.clone();
        plan.targets = original.targets.clone();
        plan.precondition_hashes = original.precondition_hashes.clone();
        plan.refresh_hash().expect("hash");
        plan.approve(true, None).expect("approve");
        plan.mark_consumed().expect("consume");
        plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
            .expect("attempt");
        save_current_test_plan(&fixture.store, &plan);
        let stage = &plan.targets["adapter"]["approved_mln_import"];
        let mut ingest = json!({
            "schema_version":1,"operation_id":plan.operation_id,"step":"ingest_response",
            "performed":true,"rectification_required":false,
            "receipt":{"http_status":200,"success":true,"response_action":"ingest",
                "provider":"cloudflare","effect":"d1_import_ingest_accepted",
                "migration_id":"0143","target":stage["target"],
                "plan_input_hash":hash_value(&plan.input).expect("input hash"),
                "no_replay":true,"result":{"type":"import","status":"complete","success":true,
                    "at_bookmark":"accepted","result":{"final_bookmark":"finished"}}}
        });
        match defect {
            "final_bookmark" => {
                ingest["receipt"]["result"]["result"]["final_bookmark"] = json!("other")
            }
            "action" => ingest["receipt"]["response_action"] = json!("poll"),
            "target" => ingest["receipt"]["target"]["database_id"] = json!("other"),
            _ => {}
        }
        if defect == "not_durable" {
            fixture
                .store
                .record_d1_import_checkpoint(&plan.operation_id, &ingest)
                .expect("checkpoint only");
        } else {
            persist_poll_lineage_checkpoint(&fixture.store, &plan.operation_id, &ingest);
        }
        let completion = json!({
            "schema_version":1,"operation_id":plan.operation_id,"step":"provider_complete",
            "performed":true,"rectification_required":false,
            "receipt":{"provider":"cloudflare","effect":"d1_import_provider_complete",
                "response_action":"ingest","no_replay":true,"state":"provider_complete",
                "provider_status":"complete","provider_success":true,"migration_id":"0143",
                "target":stage["target"],"plan_input_hash":hash_value(&plan.input).expect("hash"),
                "source_sha256":stage["sha256"],"source_md5":stage["md5"],"source_bytes":stage["bytes"],
                "source_authority_hash":stage["source_authority_hash"],"stage_identity_hash":hash_value(stage).expect("stage hash"),
                "prerequisites":plan.input["body"],"at_bookmark":"accepted","final_bookmark":"finished"}
        });
        persist_poll_lineage_checkpoint(&fixture.store, &plan.operation_id, &completion);
        let result =
            super::exact_durable_provider_complete_boundary(&fixture.store, &plan.operation_id);
        if defect == "none" {
            result.expect("exact immediate completion");
        } else {
            assert!(result.is_err(), "{defect}");
        }
        let checkpoints = fixture
            .store
            .read_d1_import_checkpoints(&plan.operation_id)
            .expect("checkpoints");
        assert_eq!(checkpoints.len(), 2);
        assert!(!checkpoints.iter().any(|(_, value)| {
            value["step"]
                .as_str()
                .is_some_and(|step| step.starts_with("poll_"))
        }));
    }
}
