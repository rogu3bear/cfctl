use super::*;

pub(super) fn rollback_rectification_plan(target_version: &str) -> PlanV1 {
    let mut capability = CapabilityV1::new(
        "worker-version-rollback",
        "Rollback Worker version",
        "POST",
        "/accounts/{account_id}/workers/scripts/{script_name}/deployments",
    );
    capability.adapter_status = AdapterStatus::Native;
    let input = CallInput {
        selectors: json!({
            "account_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "script_name":"drop",
        }),
        query: json!({}),
        body: Some(json!({
            "target_version_id":target_version,
            "expected_current_deployment_id":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "message":"restore known good",
        })),
        ..CallInput::default()
    };
    let mut plan = PlanV1::draft(
        "profile-a",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "sha256:rollback-catalog",
        capability,
        json!({"adapter":{"worker_deployment":{
            "schema_version":1,
            "service_name":"drop",
            "rollback":{
                "target_version_id":target_version,
                "expected_current_deployment_id":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                "message":"restore known good",
                "traffic_percentage":100,
                "force":false,
            }
        }}}),
    )
    .expect("rollback plan");
    plan.input = serde_json::to_value(input).expect("rollback input");
    plan.refresh_hash().expect("bind rollback input");
    plan.approve(true, None).expect("rollback approval");
    plan.mark_consumed().expect("rollback consumption");
    plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("rollback boundary attempt");
    plan
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one persistence test proves unique-marker closure, projected evidence, duplicate rejection, and durable open state"
)]
pub(super) fn worker_rollback_get_only_rectification_closes_only_unique_current_marker() {
    let target_version = "66666666-7777-4888-8999-aaaaaaaaaaaa";
    let deployment_id = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff";
    let root = tempfile::tempdir().expect("rollback rectification root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let mut plan = rollback_rectification_plan(target_version);
    plan.status = PlanStatus::RectificationRequired;
    plan.record_transaction_stage_with_artifact(
        TransactionStageV1::BoundaryResponsePersisted,
        json!({"outcome":"transport_error","receipt_available":false}),
    )
    .expect("unknown rollback boundary");
    store.save_plan(&plan).expect("persist ambiguous rollback");
    let annotation = cfctl_cloudflare::worker_version_rollback_annotation(
        "restore known good",
        &plan.operation_id,
    )
    .expect("operation marker");
    let readback = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"deployments":[{
            "id":deployment_id,
            "versions":[{"version_id":target_version,"percentage":100}],
            "annotations":{"workers/message":annotation},
        }]}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let envelope = persist_worker_version_rollback_rectification(
        &store,
        &mut plan,
        target_version,
        &annotation,
        &readback,
    )
    .expect("GET-only rectification");
    assert!(envelope.ok);
    assert!(
        !envelope.performed,
        "rectification must not replay the POST"
    );
    assert_eq!(plan.status, PlanStatus::Verified);
    assert_eq!(plan.transaction_stage, TransactionStageV1::Closed);
    let evidence = store
        .read_evidence_value(&envelope.evidence[0].content_hash)
        .expect("projected rectification evidence");
    assert_eq!(evidence["verification_only"], true);
    assert_eq!(evidence["boundary_replayed"], false);
    assert_eq!(
        evidence["readback"]["result"]["provider_output_retained"],
        false
    );
    assert!(evidence["readback"]["result"].get("deployments").is_none());
    assert!(!evidence.to_string().contains("restore known good"));

    let mut duplicate = rollback_rectification_plan(target_version);
    duplicate.status = PlanStatus::RectificationRequired;
    duplicate
        .record_transaction_stage_with_artifact(
            TransactionStageV1::BoundaryResponsePersisted,
            json!({"outcome":"transport_error","receipt_available":false}),
        )
        .expect("unknown duplicate-marker boundary");
    store
        .save_plan(&duplicate)
        .expect("persist duplicate-marker rollback");
    let duplicate_annotation = cfctl_cloudflare::worker_version_rollback_annotation(
        "restore known good",
        &duplicate.operation_id,
    )
    .expect("duplicate operation marker");
    let duplicate_readback = CloudflareResponseV1 {
        result: json!({"deployments":[
            {
                "id":deployment_id,
                "versions":[{"version_id":target_version,"percentage":100}],
                "annotations":{"workers/message":duplicate_annotation},
            },
            {
                "id":"cccccccc-dddd-4eee-8fff-000000000000",
                "versions":[{"version_id":target_version,"percentage":100}],
                "annotations":{"workers/message":duplicate_annotation},
            }
        ]}),
        ..readback
    };
    let envelope = persist_worker_version_rollback_rectification(
        &store,
        &mut duplicate,
        target_version,
        &duplicate_annotation,
        &duplicate_readback,
    )
    .expect("failed GET-only rectification remains inspectable");
    assert!(!envelope.ok);
    assert!(!envelope.performed);
    assert_eq!(duplicate.status, PlanStatus::RectificationRequired);
    assert_eq!(
        store
            .load_plan(&duplicate.operation_id)
            .expect("reload open rollback")
            .status,
        PlanStatus::RectificationRequired
    );
}

#[test]
pub(super) fn worker_rollback_apply_receipt_discards_provider_annotations_and_author_metadata() {
    let capability = CapabilityV1::new(
        "worker-version-rollback",
        "Rollback Worker version",
        "POST",
        "/accounts/{account_id}/workers/scripts/{script_name}/deployments",
    );
    let projected = redact_response_for_capability(
        &capability,
        &json!({
            "status":200,
            "success":true,
            "result":{
                "id":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                "annotations":{"workers/message":"private reviewed reason"},
                "author_email":"operator@example.com",
            },
            "errors":[],
            "result_info":{"page":1},
            "etag":"etag-a",
            "cf_ray":"ray-a",
        }),
    );
    assert_eq!(
        projected["result"]["id"],
        "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    );
    assert_eq!(projected["result"]["provider_output_retained"], false);
    assert!(!projected.to_string().contains("private reviewed reason"));
    assert!(!projected.to_string().contains("operator@example.com"));
    assert!(projected.get("result_info").is_none());
}

#[test]
pub(super) fn oversized_worker_rollback_reason_fails_before_consumption_or_boundary_attempt() {
    let mut capability = CapabilityV1::new(
        "worker-version-rollback",
        "Rollback Worker version",
        "POST",
        "/accounts/{account_id}/workers/scripts/{script_name}/deployments",
    );
    capability.request_schema = Some(json!({
        "type":"object",
        "additionalProperties":false,
        "x-cfctl-body-required":true,
        "required":["target_version_id","expected_current_deployment_id","message"],
        "properties":{
            "target_version_id":{"type":"string"},
            "expected_current_deployment_id":{"type":"string"},
            "message":{"type":"string","minLength":1,"maxLength":900}
        }
    }));
    let input = CallInput {
        selectors: json!({
            "account_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "script_name":"drop",
        }),
        query: json!({}),
        body: Some(json!({
            "target_version_id":"66666666-7777-4888-8999-aaaaaaaaaaaa",
            "expected_current_deployment_id":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "message":"x".repeat(901),
        })),
        ..CallInput::default()
    };
    let mut plan = PlanV1::draft(
        "profile-a",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "sha256:rollback-catalog",
        capability,
        json!({}),
    )
    .expect("rollback plan");
    plan.input = serde_json::to_value(&input).expect("rollback input");
    plan.refresh_hash().expect("bind rollback input");
    plan.approve(true, None).expect("approval");

    assert!(validate_request_contract(&plan.capability, &input).is_err());
    assert_eq!(plan.status, PlanStatus::Approved);
    assert!(plan.transaction_journal.iter().all(|checkpoint| {
        checkpoint.stage != TransactionStageV1::ConsumptionPersisted
            && checkpoint.stage != TransactionStageV1::BoundaryAttemptPersisted
    }));
}

#[tokio::test]
pub(super) async fn worker_rollback_retryable_http_response_enters_no_replay_rectification() {
    let target_version = "66666666-7777-4888-8999-aaaaaaaaaaaa";
    for status in [429, 500] {
        let root = tempfile::tempdir().expect("ambiguous rollback root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
        let mut plan = rollback_rectification_plan(target_version);
        plan.status = PlanStatus::Failed;
        plan.record_transaction_stage_with_artifact(
            TransactionStageV1::BoundaryResponsePersisted,
            json!({"http_status":status,"success":false}),
        )
        .expect("ambiguous boundary response");
        plan.record_transaction_stage_with_artifact(
            TransactionStageV1::SecretSinkPersisted,
            json!({"completed":true,"output_sink":{"required":false}}),
        )
        .expect("no secret lifecycle");
        store.save_plan(&plan).expect("persist provider response");
        let input = CallInput {
            selectors: json!({
                "account_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "script_name":"drop",
            }),
            query: json!({}),
            body: Some(json!({
                "target_version_id":target_version,
                "expected_current_deployment_id":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                "message":"restore known good",
            })),
            ..CallInput::default()
        };
        let response = CloudflareResponseV1 {
            status,
            success: false,
            result: Value::Null,
            errors: Vec::new(),
            result_info: None,
            etag: None,
            cf_ray: None,
        };
        let executor =
            cfctl_cloudflare::Executor::new(reqwest::Client::new(), "http://127.0.0.1:9")
                .expect("unused rollback executor");
        let outcome = super::verify_api_plan(
            &store,
            &executor,
            &mut plan,
            &response,
            &input,
            &cfctl_auth::AuthCredential::Bearer {
                token: "unused".to_owned(),
            },
        )
        .await
        .expect("classify ambiguous response without readback");
        assert_eq!(outcome.state, VerificationState::Pending);
        assert_eq!(plan.status, PlanStatus::RectificationRequired);
        assert_eq!(
            plan.transaction_stage,
            TransactionStageV1::VerificationResponsePersisted
        );
        assert_eq!(
            store
                .load_plan(&plan.operation_id)
                .expect("reload ambiguous rollback")
                .status,
            PlanStatus::RectificationRequired
        );
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one lifecycle test covers boundary eligibility, crash retry, failed readback, and hash-chained closure"
)]
pub(super) fn workspace_d1_rectification_requires_a_boundary_receipt_and_journals_a_passing_retry()
{
    let mut capability = CapabilityV1::new(
        "example.d1-migrations-apply",
        "Apply workspace D1 migrations",
        "POST",
        "/workspace/d1/migrations",
    );
    capability.workspace_d1_migration = Some(WorkspaceD1MigrationContractV1 {
        repository_root: "/repo".to_owned(),
        repository_head: "a".repeat(40),
        repository_origin: "https://example.com/repo.git".to_owned(),
        operation_pack_path: ".cfctl/operations/d1.toml".to_owned(),
        operation_pack_sha256: format!("sha256:{}", "a".repeat(64)),
        config_template_path: "wrangler.toml".to_owned(),
        config_template_sha256: format!("sha256:{}", "b".repeat(64)),
        production_config_path: "wrangler.production.toml".to_owned(),
        migrations_dir: "migrations".to_owned(),
        database_binding: "DB".to_owned(),
        wrangler_version: "4.120.1".to_owned(),
        migrations: Vec::new(),
        assertions: Vec::new(),
        recovery_capability_id: "d1-time-travel-get-bookmark".to_owned(),
        recovery_max_age_seconds: 600,
        rollback_capability_id: "d1-restore-exact-bookmark".to_owned(),
        transition: None,
        manifest_migration: None,
    });
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
        json!({}),
    )
    .expect("workspace D1 plan");
    assert!(!workspace_d1_migration_rectification_eligible(&plan));

    plan.approve(true, None).expect("approval");
    plan.mark_consumed().expect("consumption");
    plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("boundary attempt");
    plan.record_transaction_stage_with_artifact(
        TransactionStageV1::BoundaryResponsePersisted,
        json!({"boundary_crossed":true,"success":true}),
    )
    .expect("durable boundary response");
    plan.status = PlanStatus::RectificationRequired;
    assert!(workspace_d1_migration_rectification_eligible(&plan));

    plan.record_transaction_stage_with_artifact(
        TransactionStageV1::SecretSinkPersisted,
        json!({"sink":"private","success":true}),
    )
    .expect("durable secret sink receipt");
    assert!(
        workspace_d1_migration_rectification_eligible(&plan),
        "a crossed migration whose private receipt persisted before verification must remain retryable"
    );

    plan.status = PlanStatus::Draft;
    assert!(!workspace_d1_migration_rectification_eligible(&plan));

    plan.status = PlanStatus::RectificationRequired;
    plan.record_transaction_stage(TransactionStageV1::VerificationAttemptPersisted)
        .expect("verification attempt");
    assert!(
        workspace_d1_migration_rectification_eligible(&plan),
        "a crash after the read-only verification-attempt checkpoint must remain retryable"
    );
    plan.record_transaction_stage_with_artifact(
        TransactionStageV1::VerificationResponsePersisted,
        json!({"state":"failed","evidence_hash":format!("sha256:{}", "b".repeat(64))}),
    )
    .expect("failed verification response");
    let root = tempfile::tempdir().expect("rectification store");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    store.save_plan(&plan).expect("save failed verification");
    let journal_len_before_retry = plan.transaction_journal.len();
    persist_workspace_d1_rectification_result(
        &store,
        &mut plan,
        json!({"state":"failed","evidence_hash":format!("sha256:{}", "c".repeat(64))}),
        false,
        true,
    )
    .expect("failed retry remains open");
    assert_eq!(plan.transaction_journal.len(), journal_len_before_retry);
    assert_eq!(plan.status, PlanStatus::RectificationRequired);

    let passing_receipt = json!({
        "state":"passed",
        "evidence_hash":format!("sha256:{}", "d".repeat(64)),
        "reconciliation":true,
        "boundary_replayed":false,
    });
    persist_workspace_d1_rectification_result(
        &store,
        &mut plan,
        passing_receipt.clone(),
        true,
        true,
    )
    .expect("passing retry closes with receipt");
    assert_eq!(plan.status, PlanStatus::Verified);
    assert_eq!(plan.transaction_stage, TransactionStageV1::Closed);
    assert_eq!(
        plan.transaction_artifact(TransactionStageV1::Closed)
            .expect("closed checkpoint artifact")["rectification_verification"],
        passing_receipt
    );
    plan.validate_transaction_journal()
        .expect("passing retry remains hash chained");
    let durable = store
        .load_plan(&plan.operation_id)
        .expect("reload closed rectification plan");
    assert_eq!(
        durable.transaction_artifact(TransactionStageV1::Closed),
        plan.transaction_artifact(TransactionStageV1::Closed)
    );
}

#[test]
pub(super) fn workspace_d1_projection_rectification_requires_crossed_boundary_and_never_replays() {
    let mut capability = CapabilityV1::new(
        "example.d1-policy-project",
        "Project workspace policy into D1",
        "POST",
        "/workspace/d1/policy-projection",
    );
    capability.workspace_d1_policy_projection = Some(WorkspaceD1PolicyProjectionContractV1 {
        repository_root: "/repo".to_owned(),
        repository_head: "a".repeat(40),
        repository_origin: "https://example.com/repo.git".to_owned(),
        operation_pack_path: ".cfctl/operations/d1-projection.toml".to_owned(),
        operation_pack_sha256: format!("sha256:{}", "a".repeat(64)),
        config_template_path: "wrangler.toml".to_owned(),
        config_template_sha256: format!("sha256:{}", "b".repeat(64)),
        production_config_path: "wrangler.production.toml".to_owned(),
        database_binding: "DB".to_owned(),
        wrangler_version: "4.120.1".to_owned(),
        route_table: "alias_routes".to_owned(),
        route_policy_sha_column: "policy_sha256".to_owned(),
        runtime_state_table: "runtime_state".to_owned(),
        runtime_state_key_column: "state_key".to_owned(),
        runtime_state_value_column: "state_value".to_owned(),
        active_policy_key: "active_policy_sha256".to_owned(),
        desired_state_digest_key: "desired_state_sha256".to_owned(),
        projection_digest_key: "projection_sha256".to_owned(),
        recovery_capability_id: "d1-time-travel-get-bookmark".to_owned(),
        recovery_max_age_seconds: 600,
        rollback_capability_id: "d1-restore-exact-bookmark".to_owned(),
    });
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
        json!({}),
    )
    .expect("projection plan");
    assert!(!workspace_d1_projection_rectification_eligible(&plan));

    plan.approve(true, None).expect("approval");
    plan.mark_consumed().expect("consumption");
    plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("boundary attempt");
    plan.record_transaction_stage_with_artifact(
        TransactionStageV1::BoundaryResponsePersisted,
        json!({"boundary_crossed":true,"success":true}),
    )
    .expect("boundary response");
    plan.status = PlanStatus::RectificationRequired;
    plan.record_transaction_stage(TransactionStageV1::VerificationAttemptPersisted)
        .expect("verification attempt");
    plan.record_transaction_stage_with_artifact(
        TransactionStageV1::VerificationResponsePersisted,
        json!({"state":"failed","boundary_replayed":false}),
    )
    .expect("failed verification response");
    assert!(workspace_d1_projection_rectification_eligible(&plan));

    let root = tempfile::tempdir().expect("rectification store");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let journal_len_before_retry = plan.transaction_journal.len();
    persist_workspace_d1_projection_rectification_result(
        &store,
        &mut plan,
        json!({
            "state":"failed",
            "evidence_hash":format!("sha256:{}", "c".repeat(64)),
            "reconciliation":true,
            "boundary_replayed":false,
        }),
        false,
        true,
    )
    .expect("failed verification-only retry remains open");
    assert_eq!(plan.status, PlanStatus::RectificationRequired);
    assert_eq!(
        plan.transaction_stage,
        TransactionStageV1::VerificationResponsePersisted
    );
    assert_eq!(plan.transaction_journal.len(), journal_len_before_retry);

    let retry = json!({
        "state":"passed",
        "evidence_hash":format!("sha256:{}", "d".repeat(64)),
        "reconciliation":true,
        "boundary_replayed":false,
    });
    persist_workspace_d1_projection_rectification_result(
        &store,
        &mut plan,
        retry.clone(),
        true,
        true,
    )
    .expect("passing verification-only retry");
    assert_eq!(plan.status, PlanStatus::Verified);
    assert_eq!(plan.transaction_stage, TransactionStageV1::Closed);
    assert_eq!(
        plan.transaction_artifact(TransactionStageV1::Closed)
            .expect("closed checkpoint")["rectification_verification"],
        retry
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the regression proves eligibility, exact digest and target matching, fail-closed drift, no replay, and durable closure in one fixture"
)]
pub(super) fn private_r2_upload_rectification_requires_exact_digest_and_never_replays_put() {
    let mut capability = CapabilityV1::new(
        "r2-put-object",
        "Upload private object",
        "PUT",
        "/accounts/{account_id}/r2/buckets/{bucket_name}/objects/{object_key}",
    );
    capability.r2_private_file_upload = Some(R2PrivateFileUploadContractV1 {
        max_source_bytes: 300_000_000,
        allowed_content_types: vec!["application/json".to_owned()],
        require_if_none_match_star: true,
        read_capability_id: "r2-get-object".to_owned(),
        delete_capability_id: "r2-delete-object".to_owned(),
        etag_algorithm: "md5".to_owned(),
    });
    let input = CallInput {
        selectors: json!({
            "account_id":"account-a",
            "bucket_name":"bucket-a",
            "object_key":"config/policy.json",
            "Content-Type":"application/json"
        }),
        if_none_match: Some("*".to_owned()),
        ..CallInput::default()
    };
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
        json!({}),
    )
    .expect("private R2 plan");
    plan.input = serde_json::to_value(&input).expect("input");
    plan.targets = json!({"adapter":{"r2_private_file_upload":{
        "source_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "source_bytes":36234,
        "create_only":true
    }}});
    plan.refresh_hash().expect("refresh private R2 plan hash");
    plan.approve(true, None).expect("approval");
    plan.mark_consumed().expect("consumption");
    plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("boundary attempt");
    plan.record_transaction_stage_with_artifact(
        TransactionStageV1::BoundaryResponsePersisted,
        json!({"http_status":200,"success":true,"etag":null}),
    )
    .expect("headerless successful boundary");
    plan.status = PlanStatus::RectificationRequired;
    plan.record_transaction_stage(TransactionStageV1::SecretSinkPersisted)
        .expect("sink checkpoint");
    plan.record_transaction_stage(TransactionStageV1::VerificationAttemptPersisted)
        .expect("verification attempt");
    plan.record_transaction_stage_with_artifact(
        TransactionStageV1::VerificationResponsePersisted,
        json!({"state":"failed"}),
    )
    .expect("verification response");
    assert!(r2_private_upload_rectification_eligible(&plan));

    let digest = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({
            "schema_version":1,
            "account_id":"account-a",
            "bucket_name":"bucket-a",
            "object_key":"config/policy.json",
            "byte_count":36234,
            "etag":"\"provider-etag\"",
            "sha256":format!("sha256:{}", "a".repeat(64)),
            "body_returned":false
        }),
        errors: Vec::new(),
        result_info: None,
        etag: Some("\"provider-etag\"".to_owned()),
        cf_ray: None,
    };
    assert!(r2_private_upload_digest_matches(&plan, &digest).expect("exact digest"));
    let mut drifted = digest.clone();
    drifted.result["byte_count"] = json!(36233);
    assert!(!r2_private_upload_digest_matches(&plan, &drifted).expect("drift decision"));
    let mut digest_drifted = digest.clone();
    digest_drifted.result["sha256"] = json!(format!("sha256:{}", "c".repeat(64)));
    assert!(
        !r2_private_upload_digest_matches(&plan, &digest_drifted).expect("digest drift decision")
    );
    let mut target_drifted = digest.clone();
    target_drifted.result["object_key"] = json!("config/other.json");
    assert!(
        !r2_private_upload_digest_matches(&plan, &target_drifted).expect("target drift decision")
    );

    let root = tempfile::tempdir().expect("rectification store");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let journal_len = plan.transaction_journal.len();
    persist_r2_private_upload_rectification_result(
        &store,
        &mut plan,
        json!({
            "state":"failed",
            "reconciliation":true,
            "verification_only":true,
            "boundary_replayed":false,
            "evidence_hash":format!("sha256:{}", "c".repeat(64))
        }),
        false,
    )
    .expect("failed verification remains rectifiable");
    assert_eq!(plan.status, PlanStatus::RectificationRequired);
    assert_eq!(
        plan.transaction_stage,
        TransactionStageV1::VerificationResponsePersisted
    );
    assert_eq!(plan.transaction_journal.len(), journal_len);

    let receipt = json!({
        "state":"passed",
        "reconciliation":true,
        "verification_only":true,
        "boundary_replayed":false,
        "evidence_hash":format!("sha256:{}", "b".repeat(64))
    });
    persist_r2_private_upload_rectification_result(&store, &mut plan, receipt.clone(), true)
        .expect("close verified rectification");
    assert_eq!(plan.status, PlanStatus::Verified);
    assert_eq!(plan.transaction_stage, TransactionStageV1::Closed);
    assert_eq!(
        plan.transaction_artifact(TransactionStageV1::Closed)
            .expect("closed checkpoint")["rectification_verification"],
        receipt
    );
}

#[test]
pub(super) fn delegated_failure_status_precedes_durable_boundary_receipts() {
    let root = tempfile::tempdir().expect("runtime root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let mut capability = CapabilityV1::new(
        "example.delegated-write",
        "Run delegated write",
        "CLI",
        "example delegated write",
    );
    capability.mutating = true;
    capability.adapter_status = AdapterStatus::DelegatedCli;
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
        json!({}),
    )
    .expect("delegated plan");
    plan.approve(true, None).expect("approval");
    plan.mark_consumed().expect("consumption");
    plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("boundary attempt");
    store.save_plan(&plan).expect("persist boundary attempt");
    let receipt = json!({"success":false,"boundary_crossed":true});
    let evidence_hash = format!("sha256:{}", "a".repeat(64));
    let evidence = EvidenceV1::new(
        EvidenceClass::Apply,
        &evidence_hash,
        "/managed/evidence/apply.json",
    );

    super::persist_delegated_boundary_result(
        &store,
        &mut plan,
        false,
        &receipt,
        &evidence,
        &MemorySecretStore::default(),
    )
    .expect("a failed delegated boundary remains durably rectifiable");

    let durable = store
        .load_plan(&plan.operation_id)
        .expect("failed delegated plan reloads");
    assert_eq!(durable.status, PlanStatus::RectificationRequired);
    assert_eq!(
        durable.transaction_stage,
        TransactionStageV1::SecretSinkPersisted
    );
    assert!(
        durable
            .transaction_journal
            .iter()
            .filter(|checkpoint| {
                matches!(
                    checkpoint.stage,
                    TransactionStageV1::BoundaryResponsePersisted
                        | TransactionStageV1::SecretSinkPersisted
                )
            })
            .all(|checkpoint| checkpoint.plan_status == PlanStatus::RectificationRequired),
        "every post-boundary failure checkpoint must bind the terminal recovery status"
    );
    durable
        .validate_transaction_journal()
        .expect("the durable failure journal is coherent");
}

#[test]
pub(super) fn delegated_timeout_persists_unknown_outcome_and_returns_no_replay_guidance() {
    let root = tempfile::tempdir().expect("runtime root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let mut capability =
        CapabilityV1::new("wrangler.deploy", "Deploy Worker", "CLI", "wrangler deploy");
    capability.mutating = true;
    capability.adapter_status = AdapterStatus::DelegatedCli;
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
        json!({}),
    )
    .expect("delegated plan");
    plan.approve(true, None).expect("approval");
    plan.mark_consumed().expect("consumption");
    plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("boundary attempt");
    store.save_plan(&plan).expect("persist boundary attempt");
    let timeout = CliError::SubprocessTimeout {
        label: "wrangler deploy".to_owned(),
        timeout_seconds: 600,
    };

    super::persist_delegated_pre_response_failure(
        &store,
        &mut plan,
        &timeout,
        &MemorySecretStore::default(),
    )
    .expect("persist timeout recovery state");
    let envelope = super::delegated_pre_response_failure_envelope(&plan, &timeout);

    let durable = store
        .load_plan(&plan.operation_id)
        .expect("timed-out delegated plan reloads");
    assert_eq!(durable.status, PlanStatus::RectificationRequired);
    assert_eq!(
        durable.transaction_stage,
        TransactionStageV1::SecretSinkPersisted
    );
    assert_eq!(
        durable
            .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
            .expect("body-free missing-receipt checkpoint")["outcome"],
        "no_receipt"
    );
    durable
        .validate_transaction_journal()
        .expect("timeout recovery journal is coherent");

    assert!(!envelope.ok);
    assert!(envelope.performed);
    assert_eq!(envelope.command, "plans run");
    assert_eq!(envelope.operation_id, Some(plan.operation_id.clone()));
    assert_eq!(envelope.result["outcome"], "unknown");
    assert_eq!(envelope.result["receipt_available"], false);
    assert_eq!(envelope.result["boundary_replayed"], false);
    assert_eq!(envelope.verification.state, VerificationState::Pending);
    let error = envelope.error.expect("typed timeout recovery error");
    assert_eq!(error.code, "CFCTL_SUBPROCESS_TIMEOUT");
    let next_step = error.next_step.expect("operation-bound recovery");
    assert!(next_step.contains(&format!("cfctl plans status {} --json", plan.operation_id)));
    assert!(next_step.contains(&format!("cfctl plans rectify {} --json", plan.operation_id)));
    assert!(next_step.contains("Do not replay"));
}

#[tokio::test]
pub(super) async fn delegated_local_failure_after_consumption_does_not_claim_a_provider_attempt() {
    let root = tempfile::tempdir().expect("runtime root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let mut capability = CapabilityV1::new(
        "invalid.delegate",
        "Invalid delegate",
        "CLI",
        "unreviewed-tool",
    );
    capability.mutating = true;
    capability.adapter_status = AdapterStatus::DelegatedCli;
    let mut catalog = CatalogSnapshot {
        schema_version: 1,
        generated_at: Utc::now(),
        source_url: "https://example.invalid/openapi.json".to_owned(),
        source_hash: "source-sha".to_owned(),
        schema_hash: String::new(),
        capabilities: BTreeMap::from([(capability.id.clone(), capability.clone())]),
    };
    catalog.refresh_hash().expect("catalog hash");
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        &catalog.schema_hash,
        capability,
        json!({}),
    )
    .expect("delegated plan");
    plan.approve(true, None).expect("approval");
    plan.mark_consumed().expect("consumption");
    plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("boundary checkpoint");
    store.save_plan(&plan).expect("persist consumed plan");

    let envelope = super::execute_consumed_plan(
        &store,
        &catalog,
        &mut plan,
        &CallInput::default(),
        &AuthCredential::Bearer {
            token: "fixture-token".to_owned(),
        },
        &MemorySecretStore::default(),
        ExecutionAdmission {
            evidence: LivePreconditionEvidence::default(),
            attestation: AttestationStatusV1::unattested_reversible_effect(
                "fixture executes without a qualifying evidence authority".to_owned(),
            ),
        },
    )
    .await
    .expect("local delegated failure becomes a typed recovery envelope");

    // A boundary crossing must report its own attestation even when the
    // crossing failed locally: an unattested attempt is exactly the case a
    // reader needs to be able to see.
    let attestation = envelope
        .attestation
        .clone()
        .expect("every executed plan reports whether its crossing was attested");
    assert_eq!(
        attestation.state,
        AttestationStateV1::UnattestedReversibleEffect
    );
    assert_eq!(
        attestation.reason.as_deref(),
        Some("fixture executes without a qualifying evidence authority")
    );
    assert!(!envelope.ok);
    assert!(!envelope.performed);
    assert_eq!(envelope.result["outcome"], "not_attempted");
    assert_eq!(envelope.result["receipt_available"], false);
    assert_eq!(envelope.result["boundary_replayed"], false);
    assert_eq!(envelope.verification.state, VerificationState::Failed);
    assert!(envelope.verification.basis.as_deref().is_some_and(|basis| {
        basis.contains("no mutation-capable delegated subprocess was started")
    }));
    let durable = store
        .load_plan(&plan.operation_id)
        .expect("not-attempted plan reloads");
    assert_eq!(durable.status, PlanStatus::RectificationRequired);
    assert_eq!(
        durable
            .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
            .expect("body-free not-attempted checkpoint")["outcome"],
        "not_attempted"
    );
    durable
        .validate_transaction_journal()
        .expect("not-attempted recovery journal is coherent");
}

#[tokio::test]
pub(super) async fn plans_rectify_recovers_missing_lineage_idempotently() {
    let root = tempfile::tempdir().expect("runtime root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let mut authority = active_standing_authority(2);
    let plan = standing_token_plan_with_receipt(
        &authority,
        json!({"success":true,"resource_id":"token-rectify-recovery"}),
    );
    reserve_standing_plan(&mut authority, &plan);
    store
        .create_authority(&authority)
        .expect("persist active authority and run reservation");
    let operation_id = plan.operation_id.clone();
    store
        .save_plan(&plan)
        .expect("persist successful boundary receipt");

    let first = Box::pin(rectify_plan(
        &store,
        &PlanSelector {
            operation_id: operation_id.clone(),
        },
    ))
    .await
    .expect("rectify reconciles without replaying the source mutation");
    assert!(
        first
            .evidence
            .iter()
            .any(|evidence| evidence.class == EvidenceClass::StandingApply),
        "rectify must return the receipt for its authority-lineage mutation"
    );
    Box::pin(rectify_plan(
        &store,
        &PlanSelector {
            operation_id: operation_id.clone(),
        },
    ))
    .await
    .expect("repeated rectification is idempotent");

    let durable = store
        .load_authority(&authority.authority_id)
        .expect("authority lineage reloads");
    assert_eq!(durable.minted_token_ids, vec!["token-rectify-recovery"]);
}

#[tokio::test]
pub(super) async fn plans_rectify_cannot_race_an_in_flight_plan() {
    let root = tempfile::tempdir().expect("runtime root");
    let paths = RuntimePaths::from_root(root.path());
    let running_store = StateStore::open(paths.clone()).expect("running store");
    let rectify_store = StateStore::open(paths).expect("rectify store");
    let mut authority = active_standing_authority(2);
    let authority_id = authority.authority_id.clone();
    let plan = standing_token_plan_with_receipt(
        &authority,
        json!({"success":true,"resource_id":"token-rectify-in-flight"}),
    );
    reserve_standing_plan(&mut authority, &plan);
    running_store
        .create_authority(&authority)
        .expect("persist active authority and run reservation");
    let operation_id = plan.operation_id.clone();
    running_store
        .save_plan(&plan)
        .expect("persist boundary response before the sink attempt");
    let plan_guard = running_store
        .lock_plan(&operation_id)
        .expect("running invocation owns the plan");

    let error = Box::pin(rectify_plan(
        &rectify_store,
        &PlanSelector {
            operation_id: operation_id.clone(),
        },
    ))
    .await
    .expect_err("rectification cannot race an in-flight run");

    assert!(error.to_string().contains("locked"), "{error}");
    assert!(
        rectify_store
            .load_authority(&authority_id)
            .expect("authority reloads")
            .minted_token_ids
            .is_empty(),
        "rectification must not publish lineage while the source run owns the plan"
    );
    drop(plan_guard);
    Box::pin(rectify_plan(&rectify_store, &PlanSelector { operation_id }))
        .await
        .expect("rectification proceeds after the source plan lock is released");
    assert_eq!(
        rectify_store
            .load_authority(&authority_id)
            .expect("reconciled authority reloads")
            .minted_token_ids,
        vec!["token-rectify-in-flight"]
    );
}

#[test]
pub(super) fn concurrent_lineage_reconciliation_is_idempotent_and_preserves_revocation() {
    let root = tempfile::tempdir().expect("runtime root");
    let paths = RuntimePaths::from_root(root.path());
    let store = StateStore::open(paths.clone()).expect("state store");
    let mut authority = active_standing_authority(2);
    let authority_id = authority.authority_id.clone();
    let plan = standing_token_plan_with_receipt(
        &authority,
        json!({"success":true,"resource_id":"token-concurrent-recovery"}),
    );
    reserve_standing_plan(&mut authority, &plan);
    store
        .create_authority(&authority)
        .expect("persist active authority and run reservation");
    store
        .save_plan(&plan)
        .expect("persist successful boundary receipt");
    key_policy_revoke(
        &store,
        &KeyPolicySelector {
            authority_id: authority_id.clone(),
        },
    )
    .expect("revocation commits before late reconciliation");
    let barrier = Arc::new(Barrier::new(2));
    let handles = (0..2)
        .map(|_| {
            let paths = paths.clone();
            let barrier = Arc::clone(&barrier);
            let plan = plan.clone();
            thread::spawn(move || {
                let store = StateStore::open(paths).expect("reconciliation store");
                barrier.wait();
                reconcile_standing_lineage_from_plan(&store, &plan)
            })
        })
        .collect::<Vec<_>>();

    for handle in handles {
        handle
            .join()
            .expect("reconciliation thread joins")
            .expect("receipt reconciliation succeeds");
    }
    let durable = store
        .load_authority(&authority_id)
        .expect("authority reloads");
    assert_eq!(durable.status, StandingAuthorityStatus::Revoked);
    assert_eq!(durable.minted_token_ids, vec!["token-concurrent-recovery"]);
}

pub(super) fn email_routing_subdomain_dns_rectification_plan() -> PlanV1 {
    let mut capability = CapabilityV1::new(
        "email-routing-settings-enable-email-routing-dns",
        "Enable explicit Email Routing subdomain",
        "POST",
        "/zones/{zone_id}/email/routing/dns",
    );
    capability.mutating = true;
    capability.risk = RiskClass::ScopedWrite;
    capability.effect = EffectClass::ReversibleWrite;
    capability.verification.required = true;
    capability.verification.strategy = "email_routing_subdomain_dns_records_match".to_owned();
    capability.email_routing_subdomain_dns = Some(cfctl_core::EmailRoutingSubdomainDnsContractV1 {
        read_capability_id: "email-routing-settings-email-routing-dns-settings".to_owned(),
        read_path: "/zones/{zone_id}/email/routing/dns".to_owned(),
        request_name_field: "name".to_owned(),
        read_query_field: "subdomain".to_owned(),
    });
    let input = CallInput {
        selectors: json!({"zone_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}),
        body: Some(json!({"name":"reply.maildesk.example.com"})),
        ..CallInput::default()
    };
    let mut plan = PlanV1::draft(
        "maildesk-deploy",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "sha256:catalog",
        capability,
        json!({}),
    )
    .expect("Email Routing DNS plan");
    plan.input = serde_json::to_value(input).expect("Email Routing DNS input");
    plan.refresh_hash().expect("bind Email Routing DNS input");
    plan.approve(true, None)
        .expect("approve Email Routing DNS plan");
    plan.mark_consumed()
        .expect("consume Email Routing DNS plan");
    plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("Email Routing DNS boundary attempt");
    plan.record_transaction_stage_with_artifact(
        TransactionStageV1::BoundaryResponsePersisted,
        json!({"http_status":200,"success":true}),
    )
    .expect("Email Routing DNS boundary response");
    plan.record_transaction_stage(TransactionStageV1::SecretSinkPersisted)
        .expect("Email Routing DNS sink");
    plan.record_transaction_stage(TransactionStageV1::VerificationAttemptPersisted)
        .expect("Email Routing DNS verification attempt");
    plan.status = PlanStatus::RectificationRequired;
    plan.record_transaction_stage_with_artifact(
        TransactionStageV1::VerificationResponsePersisted,
        json!({"state":"failed"}),
    )
    .expect("Email Routing DNS verification response");
    plan
}

#[test]
pub(super) fn email_routing_subdomain_dns_rectification_closes_only_from_fresh_get_proof() {
    let root = tempfile::tempdir().expect("Email Routing rectification root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let mut plan = email_routing_subdomain_dns_rectification_plan();
    assert!(email_routing_subdomain_dns_rectification_eligible(&plan));
    store
        .save_plan(&plan)
        .expect("persist open Email Routing plan");
    let verification = OperationVerificationV1 {
        strategy: "email_routing_subdomain_dns_records_match".to_owned(),
        passed: true,
        basis: "the exact subdomain returned a complete DNS record set".to_owned(),
        readback: CloudflareResponseV1 {
            status: 200,
            success: true,
            result: json!({
                "subdomain":"reply.maildesk.example.com",
                "errors_empty":true,
                "records_match":true,
                "record_count":4,
            }),
            errors: Vec::new(),
            result_info: None,
            etag: None,
            cf_ray: None,
        },
        correlated_resource_id: None,
    };
    let envelope =
        persist_email_routing_subdomain_dns_rectification(&store, &mut plan, verification)
            .expect("GET-only Email Routing rectification");
    assert!(envelope.ok);
    assert!(!envelope.performed);
    assert_eq!(plan.status, PlanStatus::Verified);
    assert_eq!(plan.transaction_stage, TransactionStageV1::Closed);
    let evidence = store
        .read_evidence_value(&envelope.evidence[0].content_hash)
        .expect("Email Routing rectification evidence");
    assert_eq!(evidence["verification_only"], true);
    assert_eq!(evidence["boundary_replayed"], false);
    assert_eq!(evidence["readback"]["result"]["record_count"], 4);
    assert!(evidence.to_string().contains("reply.maildesk.example.com"));
    assert!(!evidence.to_string().contains("record-content"));

    let mut failed = email_routing_subdomain_dns_rectification_plan();
    store.save_plan(&failed).expect("persist failed proof plan");
    let failed_verification = OperationVerificationV1 {
        strategy: "email_routing_subdomain_dns_records_match".to_owned(),
        passed: false,
        basis: "the exact subdomain DNS records remain incomplete".to_owned(),
        readback: CloudflareResponseV1 {
            status: 200,
            success: true,
            result: json!({
                "subdomain":"reply.maildesk.example.com",
                "errors_empty":false,
                "records_match":false,
                "record_count":0,
            }),
            errors: Vec::new(),
            result_info: None,
            etag: None,
            cf_ray: None,
        },
        correlated_resource_id: None,
    };
    let envelope =
        persist_email_routing_subdomain_dns_rectification(&store, &mut failed, failed_verification)
            .expect("failed GET proof remains inspectable");
    assert!(!envelope.ok);
    assert!(!envelope.performed);
    assert_eq!(failed.status, PlanStatus::RectificationRequired);
    assert_eq!(
        failed.transaction_stage,
        TransactionStageV1::VerificationResponsePersisted
    );
}
