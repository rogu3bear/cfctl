use super::*;

#[tokio::test]
pub(super) async fn plan_run_rejects_missing_evidence_authority_before_loading_execution_state() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let store =
        StorageStateStore::open(RuntimePaths::from_root(root.path())).expect("storage opens");

    let error = Box::pin(run_plan(
        &store,
        &PlanSelector {
            operation_id: "00000000-0000-4000-8000-000000000001".to_owned(),
        },
    ))
    .await
    .expect_err("missing evidence authority blocks execution");

    assert!(
        error
            .to_string()
            .contains("evidence state-root identity is missing"),
        "the evidence authority precondition must precede catalog, plan, credential, and provider access: {error}"
    );
}

#[test]
pub(super) fn cancellation_remains_available_without_an_evidence_key() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let store = StorageStateStore::open(RuntimePaths::from_root(root.path()))
        .expect("storage opens without evidence authority");
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        CapabilityV1::new(
            "dns.records.update",
            "Update DNS record",
            "PUT",
            "/zones/{zone_id}/dns_records/{record_id}",
        ),
        json!({"zone_id":"zone-a","record_id":"record-a"}),
    )
    .expect("draft plan");
    plan.approve(true, None).expect("approve in-memory plan");
    let operation_id = plan.operation_id.clone();
    save_current_test_plan(&store, &plan);

    let envelope = cancel_plan(&store, &PlanSelector { operation_id })
        .expect("cancellation uses audit evidence without a key");
    assert_eq!(envelope.result["status"], "cancelled");
    assert_eq!(store.evidence_root_identity().expect("marker read"), None);
    assert_eq!(envelope.evidence.len(), 1);
}

#[test]
pub(super) fn token_creation_rectification_builds_a_separate_revoke_request() {
    let mut capability = CapabilityV1::new(
        "account-api-tokens-create-token",
        "Create account token",
        "POST",
        "/accounts/{account_id}/tokens",
    );
    capability.rollback.supported = true;
    capability.rollback.strategy =
        Some("revoke_created_api_token_by_returned_id_if_downstream_installation_fails".to_owned());
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
        json!({"account_id":"account-a"}),
    )
    .expect("plan");
    plan.approve(true, None).expect("approve");
    plan.mark_consumed().expect("consume");
    plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("attempt");
    plan.record_transaction_stage_with_artifact(
        TransactionStageV1::BoundaryResponsePersisted,
        json!({"resource_id":"token-id","success":true}),
    )
    .expect("response receipt");
    plan.status = PlanStatus::RectificationRequired;

    let request = compensation_request(&plan)
        .expect("request resolves")
        .expect("compensation is supported");

    assert_eq!(request.capability_id, "account-api-tokens-delete-token");
    assert_eq!(request.expected_method, "DELETE");
    assert_eq!(request.input.selectors["account_id"], "account-a");
    assert_eq!(request.input.selectors["token_id"], "token-id");
    assert_eq!(request.requested_account.as_deref(), Some("account-a"));
}

#[test]
pub(super) fn dns_record_creation_rectification_builds_a_separate_delete_request() {
    let mut capability = CapabilityV1::new(
        "dns-records-for-a-zone-create-dns-record",
        "Create DNS record",
        "POST",
        "/zones/{zone_id}/dns_records",
    );
    capability.rollback.supported = true;
    capability.rollback.strategy = Some("delete_created_dns_record_by_returned_id".to_owned());
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
        json!({"zone_id":"zone-a"}),
    )
    .expect("plan");
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"zone_id":"zone-a"}),
        query: json!({}),
        body: Some(json!({"type":"A","name":"www.example.com","content":"192.0.2.1"})),
        ..CallInput::default()
    })
    .expect("call input");
    plan.refresh_hash().expect("bind call input");
    plan.approve(true, None).expect("approve");
    plan.mark_consumed().expect("consume");
    plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("attempt");
    plan.record_transaction_stage_with_artifact(
        TransactionStageV1::BoundaryResponsePersisted,
        json!({"resource_id":"record-id","success":true}),
    )
    .expect("response receipt");
    plan.status = PlanStatus::RectificationRequired;

    let request = compensation_request(&plan)
        .expect("request resolves")
        .expect("compensation is supported");

    assert_eq!(
        request.capability_id,
        "dns-records-for-a-zone-delete-dns-record"
    );
    assert_eq!(request.input.selectors["zone_id"], "zone-a");
    assert_eq!(request.input.selectors["dns_record_id"], "record-id");
    assert_eq!(request.requested_account.as_deref(), Some("account-a"));
}

#[test]
pub(super) fn generic_creation_rectification_uses_only_the_hash_bound_resource_target_and_receipt()
{
    let mut capability = CapabilityV1::new(
        "widgets-create",
        "Create Widget",
        "POST",
        "/accounts/{account_id}/widgets",
    );
    capability.rollback.supported = true;
    capability.rollback.strategy = Some("delete_created_resource_by_returned_id".to_owned());
    capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: "/accounts/{account_id}/widgets/{slug}".to_owned(),
        identity_selector: "slug".to_owned(),
        response_result_identity_pointer: "/slug".to_owned(),
        read_capability_id: "widgets-get".to_owned(),
        delete_capability_id: "widgets-delete".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
    });
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
        json!({}),
    )
    .expect("plan");
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-a"}),
        query: json!({"mutation_mode":"secret-like-query"}),
        body: Some(json!({"name":"secret-like-widget"})),
        if_match: Some("mutation-etag".to_owned()),
        ..CallInput::default()
    })
    .expect("call input");
    plan.refresh_hash().expect("bind call input");
    plan.approve(true, None).expect("approve");
    plan.mark_consumed().expect("consume");
    plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("attempt");
    let response = CloudflareResponseV1 {
        status: 201,
        success: true,
        result: json!({"slug":"widget-one","name":"secret-like-widget"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let apply_evidence = EvidenceV1::new(
        EvidenceClass::Apply,
        "sha256:apply-receipt",
        "/tmp/apply-receipt.json",
    );
    plan.record_transaction_stage_with_artifact(
        TransactionStageV1::BoundaryResponsePersisted,
        boundary_response_artifact(&plan, &response, Some(&apply_evidence)),
    )
    .expect("response receipt");
    plan.status = PlanStatus::RectificationRequired;

    let mut request = compensation_request(&plan)
        .expect("request resolves")
        .expect("compensation is supported");

    assert_eq!(request.capability_id, "widgets-delete");
    assert_eq!(request.expected_method, "DELETE");
    assert_eq!(
        request.expected_path,
        "/accounts/{account_id}/widgets/{slug}"
    );
    assert_eq!(request.input.selectors["account_id"], "account-a");
    assert_eq!(request.input.selectors["slug"], "widget-one");
    assert_eq!(request.input.query, json!({}));
    assert!(request.input.body.is_none());
    assert!(request.input.if_match.is_none());
    assert!(request.input.if_none_match.is_none());
    assert_eq!(request.requested_account.as_deref(), Some("account-a"));

    let mut delete_capability = CapabilityV1::new(
        "widgets-delete",
        "Delete Widget",
        "DELETE",
        "/accounts/{account_id}/widgets/{slug}",
    );
    delete_capability.request_schema = Some(json!({
        "type":"object",
        "properties":{},
        "additionalProperties":false,
        "x-cfctl-body-required":true
    }));
    bind_required_empty_compensation_body(&mut request, &delete_capability);
    assert_eq!(request.input.body, Some(json!({})));
}

#[test]
pub(super) fn r2_bucket_creation_rectification_preserves_jurisdiction_for_exact_empty_bucket_delete()
 {
    let mut capability = CapabilityV1::new(
        "r2-create-bucket",
        "Create Bucket",
        "POST",
        "/accounts/{account_id}/r2/buckets",
    );
    capability.product = "R2 Bucket".to_owned();
    capability.rollback.supported = true;
    capability.rollback.strategy = Some("delete_created_resource_by_returned_id".to_owned());
    capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: "/accounts/{account_id}/r2/buckets/{bucket_name}".to_owned(),
        identity_selector: "bucket_name".to_owned(),
        response_result_identity_pointer: "/name".to_owned(),
        read_capability_id: "r2-get-bucket".to_owned(),
        delete_capability_id: "r2-delete-bucket".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
    });
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
        json!({}),
    )
    .expect("plan");
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({
            "account_id":"account-a",
            "cf-r2-jurisdiction":"eu"
        }),
        query: json!({}),
        body: Some(json!({
            "name":"smoke-bucket",
            "locationHint":"weur",
            "storageClass":"InfrequentAccess"
        })),
        ..CallInput::default()
    })
    .expect("call input");
    plan.refresh_hash().expect("bind call input");
    plan.approve(true, None).expect("approve");
    plan.mark_consumed().expect("consume");
    plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("attempt");
    let response = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"name":"smoke-bucket"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let apply_evidence = EvidenceV1::new(
        EvidenceClass::Apply,
        "sha256:r2-create-apply-receipt",
        "/tmp/r2-create-apply-receipt.json",
    );
    plan.record_transaction_stage_with_artifact(
        TransactionStageV1::BoundaryResponsePersisted,
        boundary_response_artifact(&plan, &response, Some(&apply_evidence)),
    )
    .expect("response receipt");
    plan.status = PlanStatus::RectificationRequired;

    let request = compensation_request(&plan)
        .expect("request resolves")
        .expect("compensation is supported");

    assert_eq!(request.capability_id, "r2-delete-bucket");
    assert_eq!(request.expected_method, "DELETE");
    assert_eq!(
        request.expected_path,
        "/accounts/{account_id}/r2/buckets/{bucket_name}"
    );
    assert_eq!(request.input.selectors["account_id"], "account-a");
    assert_eq!(request.input.selectors["bucket_name"], "smoke-bucket");
    assert_eq!(request.input.selectors["cf-r2-jurisdiction"], "eu");
    assert_eq!(request.input.query, json!({}));
    assert!(request.input.body.is_none());
    assert_eq!(request.requested_account.as_deref(), Some("account-a"));
}

#[test]
pub(super) fn d1_creation_rectification_derives_only_the_guarded_uuid_delete_target() {
    let capability = d1_database_create_capability();
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
        json!({}),
    )
    .expect("plan");
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-a"}),
        body: Some(json!({"name":"smoke-database","jurisdiction":"eu"})),
        ..CallInput::default()
    })
    .expect("call input");
    plan.refresh_hash().expect("bind call input");
    plan.approve(true, None).expect("approve");
    plan.mark_consumed().expect("consume");
    plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("attempt");
    plan.record_transaction_stage_with_artifact(
        TransactionStageV1::BoundaryResponsePersisted,
        json!({"resource_id":"database-a","success":true}),
    )
    .expect("response receipt");
    plan.status = PlanStatus::RectificationRequired;

    let request = compensation_request(&plan)
        .expect("request resolves")
        .expect("guarded D1 compensation is supported");
    assert_eq!(request.capability_id, "d1-delete-database");
    assert_eq!(request.expected_method, "DELETE");
    assert_eq!(
        request.expected_path,
        "/accounts/{account_id}/d1/database/{database_id}"
    );
    assert_eq!(request.input.selectors["account_id"], "account-a");
    assert_eq!(request.input.selectors["database_id"], "database-a");
    assert!(request.input.body.is_none());
    assert_eq!(request.requested_account.as_deref(), Some("account-a"));
}

#[test]
pub(super) fn collection_backed_creation_rectification_builds_an_exact_hash_bound_delete() {
    let mut capability = CapabilityV1::new(
        "widgets-create",
        "Create Widget",
        "POST",
        "/accounts/{account_id}/widgets",
    );
    capability.rollback.supported = true;
    capability.rollback.strategy = Some("delete_created_resource_by_returned_id".to_owned());
    capability.created_collection_resource = Some(CreatedCollectionResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        delete_capability_id: "widgets-delete".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
        requires_page_number_completion: true,
    });
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
        json!({}),
    )
    .expect("plan");
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-a"}),
        query: json!({"mutation_mode":"secret-like-query"}),
        body: Some(json!({"name":"secret-like-widget"})),
        if_match: Some("mutation-etag".to_owned()),
        ..CallInput::default()
    })
    .expect("call input");
    plan.refresh_hash().expect("bind call input");
    plan.approve(true, None).expect("approve");
    plan.mark_consumed().expect("consume");
    plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("attempt");
    plan.record_transaction_stage_with_artifact(
        TransactionStageV1::BoundaryResponsePersisted,
        json!({"resource_id":"widget-id","success":true}),
    )
    .expect("response receipt");
    plan.status = PlanStatus::RectificationRequired;

    let request = compensation_request(&plan)
        .expect("request resolves")
        .expect("compensation is supported");

    assert_eq!(request.capability_id, "widgets-delete");
    assert_eq!(
        request.expected_path,
        "/accounts/{account_id}/widgets/{widget_id}"
    );
    assert_eq!(request.input.selectors["account_id"], "account-a");
    assert_eq!(request.input.selectors["widget_id"], "widget-id");
    assert_eq!(request.input.query, json!({}));
    assert!(request.input.body.is_none());
    assert!(request.input.if_match.is_none());
    assert!(request.input.if_none_match.is_none());
    assert_eq!(request.requested_account.as_deref(), Some("account-a"));
}

#[test]
pub(super) fn input_cleanup_failure_is_a_hash_bound_rectification_checkpoint() {
    let root = tempfile::tempdir().expect("runtime root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let capability = CapabilityV1::new(
        "dns-records-create",
        "Create DNS record",
        "POST",
        "/zones/{zone_id}/dns_records",
    );
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
        json!({"adapter":{"secret_body_ref":"test-ref"}}),
    )
    .expect("plan");
    plan.approve(true, None).expect("approve");
    plan.mark_consumed().expect("consume");
    plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("attempt");
    plan.status = PlanStatus::Running;
    plan.record_transaction_stage_with_artifact(
        TransactionStageV1::BoundaryResponsePersisted,
        json!({"success":true}),
    )
    .expect("response");

    let error = persist_secret_lifecycle(
        &store,
        &mut plan,
        true,
        Some(&json!({})),
        &DeleteFailingSecretStore,
    )
    .expect_err("cleanup fails");

    assert!(error.to_string().contains("injected delete failure"));
    assert_eq!(plan.status, PlanStatus::RectificationRequired);
    assert_eq!(
        plan.transaction_stage,
        TransactionStageV1::SecretSinkPersisted
    );
    assert_eq!(
        plan.transaction_artifact(TransactionStageV1::SecretSinkPersisted)
            .and_then(|artifact| artifact.get("failure"))
            .and_then(serde_json::Value::as_str),
        Some("input_cleanup_failed")
    );
    plan.validate_transaction_journal()
        .expect("failure receipt validates");
    store
        .load_plan(&plan.operation_id)
        .expect("failure receipt is durable")
        .validate_transaction_journal()
        .expect("durable failure receipt validates");
}

#[test]
pub(super) fn missing_sink_only_output_is_a_hash_bound_rectification_checkpoint() {
    let root = tempfile::tempdir().expect("runtime root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let mut capability = CapabilityV1::new(
        "account-api-tokens-create-token",
        "Create account token",
        "POST",
        "/accounts/{account_id}/tokens",
    );
    capability.risk = RiskClass::SecretSensitive;
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
        json!({"adapter":{"value_out":root.path().join("token.txt")}}),
    )
    .expect("plan");
    plan.approve(true, None).expect("approve");
    plan.mark_consumed().expect("consume");
    plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("attempt");
    plan.status = PlanStatus::Running;
    plan.record_transaction_stage_with_artifact(
        TransactionStageV1::BoundaryResponsePersisted,
        json!({"success":true}),
    )
    .expect("response");

    persist_secret_lifecycle(&store, &mut plan, true, None, &DeleteFailingSecretStore)
        .expect_err("missing output fails closed");

    assert_eq!(plan.status, PlanStatus::RectificationRequired);
    assert_eq!(
        plan.transaction_artifact(TransactionStageV1::SecretSinkPersisted)
            .and_then(|artifact| artifact.get("failure"))
            .and_then(serde_json::Value::as_str),
        Some("output_missing")
    );
    plan.validate_transaction_journal()
        .expect("missing output receipt validates");
}

#[test]
pub(super) fn guided_error_carries_its_own_code_and_next_step() {
    let error = super::CliError::guided("CFCTL_DEMO", "something is off", "Run `cfctl doctor`.");
    assert_eq!(error.code(), "CFCTL_DEMO");
    assert_eq!(error.next_step().as_deref(), Some("Run `cfctl doctor`."));
}

#[test]
pub(super) fn plain_input_error_falls_back_to_generic() {
    let error = super::CliError::Input("freeform".to_owned());
    assert_eq!(error.code(), "CFCTL_ERROR");
    assert_eq!(error.next_step(), None);
}

#[test]
pub(super) fn missing_selector_points_at_guide() {
    let error = super::CliError::Cloudflare(cfctl_cloudflare::CloudflareError::MissingSelector(
        "zone_id".to_owned(),
    ));
    assert_eq!(error.code(), "CFCTL_REQUEST_CONTRACT");
    let step = error
        .next_step()
        .expect("selector errors carry a next step");
    assert!(step.contains("cfctl guide"), "{step}");
    assert!(step.contains("--selector"), "{step}");
}

#[test]
pub(super) fn approved_plan_required_points_at_the_governed_loop() {
    let error = super::CliError::Cloudflare(
        cfctl_cloudflare::CloudflareError::ApprovedPlanRequired("some-cap".to_owned()),
    );
    assert_eq!(error.code(), "CFCTL_PLAN_REQUIRED");
    let step = error.next_step().expect("mutation needs the governed loop");
    assert!(step.contains("cfctl plans approve"), "{step}");
    assert!(step.contains("cfctl plans run"), "{step}");
}

#[test]
pub(super) fn explicit_approval_required_points_at_yes_flag() {
    let error = super::CliError::Core(cfctl_core::CoreError::ExplicitApprovalRequired);
    assert_eq!(error.code(), "CFCTL_PLAN_LIFECYCLE");
    assert!(
        error
            .next_step()
            .expect("approval carries a step")
            .contains("--yes")
    );
}

#[test]
pub(super) fn run_before_approve_points_at_approve_first() {
    // Run-path rejection: the plan is not yet in an approved state.
    let error = super::CliError::Core(cfctl_core::CoreError::InvalidPlanState {
        operation_id: "op-123".to_owned(),
        actual: cfctl_core::PlanStatus::Draft,
        expected: "approved or policy-authorized auto-execute draft",
    });
    let step = error.next_step().expect("state errors carry a step");
    assert!(step.contains("cfctl plans approve op-123 --yes"), "{step}");
}

#[test]
pub(super) fn rerunning_a_completed_plan_is_not_told_to_approve_again() {
    // Regression: a Consumed/Executed plan re-run raises the same `expected`
    // string as run-before-approve. Keying on `actual` must NOT advise
    // re-approving/re-running a completed mutation.
    for actual in [
        cfctl_core::PlanStatus::Consumed,
        cfctl_core::PlanStatus::Verified,
        cfctl_core::PlanStatus::Running,
    ] {
        let error = super::CliError::Core(cfctl_core::CoreError::InvalidPlanState {
            operation_id: "op-9".to_owned(),
            actual,
            expected: "approved or policy-authorized auto-execute draft",
        });
        let step = error.next_step().expect("state errors carry a step");
        assert!(step.contains("already ran"), "{actual:?}: {step}");
        assert!(!step.contains("plans approve op-9"), "{actual:?}: {step}");
    }
}

#[test]
pub(super) fn unapproved_standing_draft_is_not_a_false_approved_match() {
    // Regression: `expected` contains the substring "approved" inside
    // "unapproved"; the old branch mis-routed this to "Approve the plan
    // first". Keying on `actual` (Draft) + the "unapproved" marker fixes it.
    let error = super::CliError::Core(cfctl_core::CoreError::InvalidPlanState {
        operation_id: "op-7".to_owned(),
        actual: cfctl_core::PlanStatus::Draft,
        expected: "unapproved approval-required draft for standing-authority consumption",
    });
    let step = error.next_step().expect("state errors carry a step");
    assert!(step.contains("standing policy"), "{step}");
    assert!(!step.contains("Approve the plan first"), "{step}");
}

#[test]
pub(super) fn plan_not_found_names_the_operation_id() {
    let error = super::CliError::Storage(cfctl_storage::StorageError::PlanNotFound(
        "op-xyz".to_owned(),
    ));
    assert_eq!(error.code(), "CFCTL_PLAN_LIFECYCLE");
    assert!(
        error
            .next_step()
            .expect("plan lookup carries a step")
            .contains("cfctl plans show op-xyz")
    );
}

#[test]
pub(super) fn missing_credential_points_at_import() {
    let error = super::CliError::Auth(cfctl_auth::AuthError::MissingCredential("prod".to_owned()));
    assert_eq!(error.code(), "CFCTL_AUTH");
    assert!(
        error
            .next_step()
            .expect("auth carries a step")
            .contains("import-api-token")
    );
}
#[test]
pub(super) fn evidence_key_transition_guidance_distinguishes_unchanged_and_indeterminate() {
    let unchanged = super::CliError::Auth(cfctl_auth::AuthError::EvidenceKeyLifecycle(
        cfctl_auth::EvidenceKeyLifecycleError::Unchanged {
            action: "rotation".to_owned(),
            cause: "injected prepublication failure".to_owned(),
        },
    ));
    assert_eq!(unchanged.code(), "CFCTL_EVIDENCE_KEY_UNCHANGED");
    let unchanged_step = unchanged.next_step().expect("unchanged guidance");
    assert!(unchanged_step.contains("evidence-key status"));
    assert!(unchanged_step.contains("did not cross"));

    let indeterminate = super::CliError::Auth(cfctl_auth::AuthError::EvidenceKeyLifecycle(
        cfctl_auth::EvidenceKeyLifecycleError::Indeterminate {
            action: "retirement".to_owned(),
            cause: "injected crossed write".to_owned(),
            readback: "injected readback failure".to_owned(),
        },
    ));
    assert_eq!(indeterminate.code(), "CFCTL_EVIDENCE_KEY_INDETERMINATE");
    let indeterminate_step = indeterminate.next_step().expect("indeterminate guidance");
    assert!(indeterminate_step.contains("Do not replay"));
    assert!(indeterminate_step.contains("evidence-key status"));

    let recovery = super::CliError::Auth(cfctl_auth::AuthError::EvidenceKeyLifecycle(
        cfctl_auth::EvidenceKeyLifecycleError::Indeterminate {
            action: "malformed-registry recovery".to_owned(),
            cause: "replacement crossed".to_owned(),
            readback: "restoration unknown".to_owned(),
        },
    ));
    let recovery_step = recovery.next_step().expect("recovery guidance");
    assert!(recovery_step.contains("same opaque plan"));
    assert!(recovery_step.contains("recover-plan status"));
    assert!(recovery_step.contains("resume only that same plan forward"));
}

#[test]
pub(super) fn crossed_evidence_publication_cleanup_guidance_forbids_replay() {
    let error = super::CliError::Storage(
        cfctl_storage::StorageError::CapabilityPublicationCleanupFailed {
            path: "/managed/evidence.json".to_owned(),
            temporary_name: ".evidence.json.tmp-test".to_owned(),
            directory_durability: "confirmed after the final hard link".to_owned(),
            source: std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "injected cleanup failure",
            ),
        },
    );
    assert_eq!(error.code(), "CFCTL_EVIDENCE_PUBLICATION_CLEANUP");
    let step = error.next_step().expect("cleanup guidance");
    assert!(step.contains("Do not replay"));
    assert!(step.contains("temporary hard-link alias"));
}

#[test]
pub(super) fn evidence_durability_guidance_requires_exact_reconciliation_before_retry() {
    let error = super::CliError::Storage(cfctl_storage::StorageError::WriteDurabilityUnknown {
        path: "/managed/evidence-descriptors/digest.json".to_owned(),
        source: std::io::Error::other("injected directory sync failure"),
    });
    assert_eq!(error.code(), "CFCTL_EVIDENCE_DURABILITY");
    let step = error.next_step().expect("evidence durability guidance");
    assert!(step.contains("Do not blindly replay"));
    assert!(step.contains("exact authentication and byte equality"));
    assert!(step.contains("held-directory sync"));
    assert!(step.contains("Temporary-alias cleanup is a separate"));

    let plan_error =
        super::CliError::Storage(cfctl_storage::StorageError::WriteDurabilityUnknown {
            path: "/managed/evidence/cfctl/data/plans/operation.json".to_owned(),
            source: std::io::Error::other("injected directory sync failure"),
        });
    assert_eq!(plan_error.code(), "CFCTL_PLAN_LIFECYCLE");
    assert!(
        plan_error
            .next_step()
            .expect("plan durability guidance")
            .contains("cfctl plans status")
    );
}

#[test]
pub(super) fn live_read_failure_guidance_is_status_specific() {
    assert_eq!(
        super::live_read_failure_guidance(403).0,
        "CFCTL_LIVE_UNAUTHORIZED"
    );
    assert!(
        super::live_read_failure_guidance(401)
            .1
            .contains("keys permissions")
    );
    assert_eq!(
        super::live_read_failure_guidance(404).0,
        "CFCTL_LIVE_BAD_REQUEST"
    );
    assert!(super::live_read_failure_guidance(400).1.contains("zone id"));
    assert_eq!(
        super::live_read_failure_guidance(503).0,
        "CFCTL_LIVE_UPSTREAM"
    );
    assert_eq!(super::live_read_failure_guidance(418).0, "CFCTL_LIVE_ERROR");
}

#[test]
pub(super) fn email_routing_contract_rejection_is_performed_but_never_raw_provider_data() {
    let mut capability = CapabilityV1::new(
        "email-routing-routing-rules-list-routing-rules",
        "List routing rules",
        "GET",
        "/zones/{zone_id}/email/routing/rules",
    );
    capability.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".to_owned()],
        success_media_types: vec!["application/json".to_owned()],
        body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
    });
    let response = CloudflareResponseV1 {
        status: 200,
        success: false,
        result: json!({
            "schema_version": 1,
            "complete": false,
            "diagnostic": {
                "schema_version": 1,
                "code": "matcher_pair_incomplete",
                "rule_index": 0,
                "component": "matcher"
            }
        }),
        errors: vec![CloudflareApiErrorV1 {
            code: None,
            message: "bounded normalized response rejection".to_owned(),
        }],
        result_info: Some(json!({
            "cfctl_projection": "email_routing_rule_set_v1",
            "cfctl_page_probe_complete": false
        })),
        etag: None,
        cf_ray: None,
    };

    assert!(super::email_routing_contract_diagnostic(&capability, &response).is_some());
    assert_eq!(
        super::live_read_failure_guidance_for_response(&capability, &response).0,
        "CFCTL_RESPONSE_CONTRACT_MISMATCH"
    );
    let availability = super::live_read_availability(&capability, &response);
    assert_eq!(availability["state"], "response_contract_rejected");
    assert_eq!(availability["data_state"], "not_observed");
    assert!(
        !serde_json::to_string(&response)
            .expect("serialize bounded rejection")
            .contains("operator@example.com")
    );
}

#[test]
pub(super) fn email_routing_provider_denial_uses_status_guidance_after_redaction() {
    let mut capability = CapabilityV1::new(
        "email-routing-routing-rules-list-routing-rules",
        "List routing rules",
        "GET",
        "/zones/{zone_id}/email/routing/rules",
    );
    capability.permissions = vec![
        "Email Routing Rules Write".to_owned(),
        "Email Routing Rules Read".to_owned(),
    ];
    capability.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".to_owned()],
        success_media_types: vec!["application/json".to_owned()],
        body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
    });
    let response = CloudflareResponseV1 {
        status: 403,
        success: false,
        result: json!({
            "schema_version": 1,
            "complete": false,
            "diagnostic": {
                "schema_version": 1,
                "code": "provider_page_unsuccessful",
                "component": "provider_response"
            }
        }),
        errors: vec![CloudflareApiErrorV1 {
            code: None,
            message: "Email Routing rules failed the bounded normalized response contract"
                .to_owned(),
        }],
        result_info: Some(json!({
            "cfctl_projection": "email_routing_rule_set_v1",
            "cfctl_page_probe_complete": false
        })),
        etag: None,
        cf_ray: None,
    };

    assert!(super::email_routing_contract_diagnostic(&capability, &response).is_none());
    assert_eq!(
        super::live_read_failure_guidance_for_response(&capability, &response).0,
        "CFCTL_LIVE_UNAUTHORIZED"
    );
    let availability = super::live_read_availability(&capability, &response);
    assert_eq!(
        availability["state"],
        "authorization_or_entitlement_unresolved"
    );
    assert_eq!(
        availability["authorization_entitlement_distinction_proven"],
        false
    );
}

#[test]
pub(super) fn live_read_availability_distinguishes_empty_data_from_denied_access() {
    let mut capability =
        resolver_read_capability("telemetry-read", "Read bounded telemetry", "Telemetry");
    capability.permissions = vec!["Account Analytics Read".to_owned()];
    capability.analytics_query = Some(AnalyticsQueryContractV1 {
        kind: AnalyticsQueryKindV1::WorkersObservability,
        dataset: Some("workers_invocations".to_owned()),
        dataset_pointer: None,
        time_range: None,
        row_limit_pointer: None,
        max_rows: 1_000,
        max_bytes: 1_048_576,
        max_timeout_seconds: 30,
        allowed_output_formats: vec![OutputFormatV1::Json],
        default_output_format: OutputFormatV1::Json,
        pagination: PaginationModeV1::BoundedResult,
        read_only: true,
        freshness: Some("upstream_dataset_dependent".to_owned()),
        sampling: Some("upstream_dataset_dependent".to_owned()),
    });
    let no_data = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!([]),
        errors: Vec::new(),
        result_info: Some(json!({"output": {"rows": 0}})),
        etag: None,
        cf_ray: None,
    };
    let receipt = super::live_read_availability(&capability, &no_data);
    assert_eq!(receipt["state"], "available");
    assert_eq!(receipt["data_state"], "no_data_in_bounded_query_window");
    assert_eq!(
        receipt["authorization_entitlement_distinction_proven"],
        true
    );
    assert_eq!(receipt["permission_owner"], "account_owned");

    let denied = CloudflareResponseV1 {
        status: 403,
        success: false,
        result: Value::Null,
        errors: vec![CloudflareApiErrorV1 {
            code: Some(10000),
            message: "redacted authorization failure".to_owned(),
        }],
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let receipt = super::live_read_availability(&capability, &denied);
    assert_eq!(receipt["state"], "authorization_or_entitlement_unresolved");
    assert_eq!(
        receipt["authorization_entitlement_distinction_proven"],
        false
    );
    assert_eq!(
        receipt["required_permissions"],
        json!(["Account Analytics Read"])
    );
}

/// Builds a stored plan carrying both classifications, in a store that has no
/// evidence authority at all.
///
/// Both must be set explicitly. `CapabilityV1::new` defaults a mutating
/// capability to `RiskClass::Unknown`, so a fixture that sets only `effect`
/// silently tests an unclassified capability rather than the one it names.
fn plan_awaiting_attestation(
    root: &Path,
    effect: EffectClass,
    risk: RiskClass,
) -> (StorageStateStore, String) {
    let store = StorageStateStore::open(RuntimePaths::from_root(root)).expect("storage opens");
    let mut capability = CapabilityV1::new(
        "dns.records.update",
        "Update DNS record",
        "PUT",
        "/zones/{zone_id}/dns_records/{record_id}",
    );
    capability.mutating = true;
    capability.effect = effect;
    capability.risk = risk;
    let plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
        json!({}),
    )
    .expect("plan drafts");
    let operation_id = plan.operation_id.clone();
    store.save_plan(&plan).expect("plan persists");
    (store, operation_id)
}

#[test]
pub(super) fn effects_that_cannot_be_replayed_refuse_without_an_evidence_authority() {
    for effect in [
        EffectClass::Destructive,
        EffectClass::ExternalCommunication,
        EffectClass::IdentityOrOwnership,
        EffectClass::Spend,
        EffectClass::Irreversible,
        EffectClass::Unknown,
    ] {
        let root = tempfile::tempdir().expect("temporary storage root");
        let (store, operation_id) =
            plan_awaiting_attestation(root.path(), effect, RiskClass::ScopedWrite);
        let error = admit_execution_attestation(&store, &operation_id)
            .expect_err("an unattestable effect must not execute unattested");
        assert!(
            error
                .to_string()
                .contains("evidence state-root identity is missing"),
            "{effect:?} must keep the original evidence refusal: {error}"
        );
    }
}

#[test]
pub(super) fn replayable_effects_proceed_unattested_and_record_why() {
    for effect in [
        EffectClass::ReadOnly,
        EffectClass::DataWrite,
        EffectClass::ReversibleWrite,
    ] {
        let root = tempfile::tempdir().expect("temporary storage root");
        let (store, operation_id) =
            plan_awaiting_attestation(root.path(), effect, RiskClass::ScopedWrite);
        let attestation = admit_execution_attestation(&store, &operation_id)
            .expect("a replayable effect degrades instead of refusing");
        assert_eq!(
            attestation.state,
            AttestationStateV1::UnattestedReversibleEffect,
            "{effect:?} must be admitted as explicitly unattested"
        );
        assert!(
            attestation
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("evidence state-root identity is missing")),
            "the degraded admission must carry the reason the authority did not qualify: {attestation:?}"
        );
    }
}

#[test]
pub(super) fn a_plan_that_cannot_be_read_keeps_the_evidence_refusal() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let store =
        StorageStateStore::open(RuntimePaths::from_root(root.path())).expect("storage opens");

    let error = admit_execution_attestation(&store, "00000000-0000-4000-8000-000000000001")
        .expect_err("an unreadable plan cannot demonstrate that its effect is reversible");

    assert!(
        error
            .to_string()
            .contains("evidence state-root identity is missing"),
        "the evidence refusal must survive an unreadable plan rather than becoming a plan error: {error}"
    );
}

#[test]
pub(super) fn a_qualifying_authority_admits_every_effect_as_attested() {
    let root = tempfile::tempdir().expect("temporary storage root");
    let store =
        StateStore::open(RuntimePaths::from_root(root.path())).expect("authenticated store");
    let mut capability = CapabilityV1::new(
        "dns.records.delete",
        "Delete DNS record",
        "DELETE",
        "/zones/{zone_id}/dns_records/{record_id}",
    );
    capability.mutating = true;
    capability.effect = EffectClass::Destructive;
    let plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
        json!({}),
    )
    .expect("plan drafts");
    store.save_plan(&plan).expect("plan persists");

    let attestation =
        admit_execution_attestation(&store, &plan.operation_id).expect("qualifying authority");

    assert_eq!(attestation.state, AttestationStateV1::Attested);
    assert!(
        attestation.reason.is_none(),
        "an attested admission has no degradation to explain"
    );
}

#[test]
pub(super) fn a_replayable_effect_carrying_a_severe_risk_still_refuses() {
    // The shape that matters in the live catalog: d1-import-database is
    // DataWrite by effect and Irreversible by risk. Keying the gate on effect
    // alone would let a production database import proceed unattested.
    for risk in [
        RiskClass::Irreversible,
        RiskClass::Destructive,
        RiskClass::SecretSensitive,
        RiskClass::IdentityOrOwnership,
        RiskClass::ExternalCommunication,
        RiskClass::Spend,
    ] {
        let root = tempfile::tempdir().expect("temporary storage root");
        let (store, operation_id) =
            plan_awaiting_attestation(root.path(), EffectClass::DataWrite, risk);
        let error = admit_execution_attestation(&store, &operation_id)
            .expect_err("a severe risk must refuse even when the effect class would degrade");
        assert!(
            error
                .to_string()
                .contains("evidence state-root identity is missing"),
            "risk {risk:?} must keep the evidence refusal despite a DataWrite effect: {error}"
        );
    }
}

#[test]
pub(super) fn an_unclassified_capability_refuses_rather_than_degrading() {
    // CapabilityV1::new defaults a mutating capability to Unknown on both
    // axes. An operation that cannot state what it does must not be assumed
    // replayable.
    let root = tempfile::tempdir().expect("temporary storage root");
    let (store, operation_id) =
        plan_awaiting_attestation(root.path(), EffectClass::Unknown, RiskClass::Unknown);
    assert!(
        admit_execution_attestation(&store, &operation_id).is_err(),
        "an unclassified capability must fail closed"
    );
}
