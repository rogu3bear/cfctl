use super::*;

pub(super) fn resolver_read_capability(id: &str, title: &str, product: &str) -> CapabilityV1 {
    let mut capability = CapabilityV1::new(id, title, "GET", "/accounts/{account_id}/things");
    capability.adapter_status = AdapterStatus::DynamicApi;
    capability.product = product.to_owned();
    capability
}

pub(super) fn resolver_mutation_capability() -> CapabilityV1 {
    // A contract-complete mutating capability so mutation_contract_gaps() is
    // empty and the resolver treats it as contract-ready. Uses the two
    // synthetic-friendly gap-free paths: the secret-sink verification
    // strategy (valid when required=false and risk=SecretSensitive) and a
    // declared-irreversible rollback (supported=false plus a warning).
    let mut capability = CapabilityV1::new(
        "widget-secret-set",
        "Set Widget Secret",
        "PUT",
        "/accounts/x/widget/secret",
    );
    capability.mutating = true;
    capability.adapter_status = AdapterStatus::Native; // avoids the permission-lane gap
    capability.product = "Widgets".to_owned();
    capability.risk = RiskClass::SecretSensitive;
    capability.effect = EffectClass::ReversibleWrite;
    capability.cost.known = true;
    capability.cost.incremental = false;
    capability.verification.required = false;
    capability.verification.strategy = "sink_write_and_source_response_status".to_owned();
    capability.rollback.supported = false;
    capability.rollback.warning =
        Some("this operation cannot be automatically rolled back".to_owned());
    capability
}

pub(super) fn resolver_workflow_capability(id: &str, title: &str) -> CapabilityV1 {
    let mut capability = CapabilityV1::new(id, title, "GET", "/cfctl/workflows/test");
    capability.adapter_status = AdapterStatus::Native;
    capability.product = "Telemetry workflows".to_owned();
    capability.workflow = Some(WorkflowContractV1 {
        purpose: title.to_owned(),
        steps: vec![WorkflowStepV1 {
            id: "inspect".to_owned(),
            capability_id: "graphql-analytics-zone-http-requests".to_owned(),
            purpose: "Inspect bounded analytics".to_owned(),
            mutating: false,
            depends_on: Vec::new(),
        }],
        preserves_component_approval: true,
        exports_evidence_packet: false,
        proof_freshness_seconds: 300,
    });
    capability
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn registered_schema_v2_pack_does_not_block_cli_resolve_for_an_unrelated_intent() {
    let runtime = tempfile::tempdir().expect("runtime root");
    let repository = tempfile::tempdir().expect("registered repository");
    let git = |arguments: &[&str]| {
        let output = StdCommand::new("git")
            .current_dir(repository.path())
            .args(arguments)
            .output()
            .expect("git fixture command");
        assert!(
            output.status.success(),
            "git {:?}: {}",
            arguments,
            String::from_utf8_lossy(&output.stderr)
        );
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "test@example.com"]);
    git(&["config", "user.name", "Test"]);
    git(&["remote", "add", "origin", "https://example.com/founder.git"]);
    fs::create_dir_all(repository.path().join(".cfctl/operations")).expect("operation pack dir");
    fs::write(
        repository
            .path()
            .join(".cfctl/operations/d1-migrations.toml"),
        r#"schema_version = 2

[[operation]]
id = "mln-web.founder-d1-migration-apply"
title = "Future manifest operation"
description = "Apply one exact target after an exact remote baseline."
authority = "cfctl_native_workspace_operation"
manifest_path = ".control-plane/d1_migration_manifest.json"
config_template = "workers/founder/wrangler.toml"
account_id = "ca30e922fda7f5578e49873542e4aaca"
profile_id = "mln-founder-d1"
database_name = "founder"
database_id = "7c282983-2e48-4ea4-9f0d-09b0d718fe65"
database_binding = "FOUNDER_DB"
baseline_start_sequence = 116
baseline_end_sequence = 171
target_sequence = 172
migrations_dir = "crates/founder/migrations/d1"
migrations_pattern = "{target_path}"
ledger_table = "d1_migrations"
ledger_name = "{target_name}"
wrangler_version = "4.100.0"
wrangler_cli_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

[operation.recovery]
full_export_capability_id = "d1-full-export"
bookmark_capability_id = "d1-time-travel-get-bookmark"
rollback_capability_id = "d1-restore-exact-bookmark"
requires_fresh_full_export = true
requires_fresh_bookmark = true
existing_anchor_reusable = false

[operation.atomicity]
local_ddl_failure_zero_schema_delta = true
local_ddl_failure_zero_ledger_delta = true
local_ledger_failure_zero_schema_delta = true
local_ledger_failure_zero_ledger_delta = true
remote_ddl_failure_zero_schema_delta = true
remote_ddl_failure_zero_ledger_delta = true
remote_ledger_failure_zero_schema_delta = true
remote_ledger_failure_zero_ledger_delta = true

[operation.verification]
require_exact_post_ledger = true
forbidden_future_sequences = [173, 174]
require_exact_schema_sql = true
require_foreign_key_check_empty = true
require_integrity_check_ok = true
require_unchanged_worker_identity = true
require_old_worker_compatibility = true
"#,
    )
    .expect("schema-v2 pack");
    git(&["add", "."]);
    git(&["commit", "-qm", "schema-v2 fixture"]);

    let store = StateStore::open(RuntimePaths::from_root(runtime.path())).expect("store opens");
    store
        .register_workspace(repository.path(), Some("account-a".to_owned()))
        .expect("register exact repository");
    let mut catalog = CatalogSnapshot {
        schema_version: 1,
        generated_at: Utc::now(),
        source_url: "test://resolver".to_owned(),
        source_hash: "sha256:source".to_owned(),
        schema_hash: String::new(),
        capabilities: [(
            "workers-scripts-list".to_owned(),
            resolver_read_capability("workers-scripts-list", "List Workers", "Workers"),
        )]
        .into_iter()
        .collect(),
    };
    catalog.refresh_hash().expect("catalog hash");
    store
        .write_json(&store.paths().catalog_file(), &catalog)
        .expect("store catalog");

    let envelope = resolve_command(
        &store,
        ResolveArgs {
            intent: "deploy JKCA workers".to_owned(),
            account: None,
            limit: 5,
        },
    )
    .await
    .expect("unrelated schema-v2 pack must not become a workspace resolver error");
    assert_eq!(envelope.command, "resolve");
    assert!(!envelope.performed);
}

#[test]
pub(super) fn workflow_guide_replaces_generic_mutation_ceremony_with_preview_semantics() {
    let workflow = resolver_workflow_capability(
        "workflow.telemetry.audit-account",
        "Audit telemetry coverage across an account",
    );
    let guide = guide_json(&workflow);
    let stages = guide["stages"].as_array().expect("guide stages");
    let build_plan = stages
        .iter()
        .find(|stage| stage["name"] == "build_plan")
        .expect("build-plan stage remains visible");
    assert_eq!(build_plan["required"], false);
    assert_eq!(build_plan["contract_state"], "not_applicable");
    assert!(build_plan["commands"].as_array().is_some_and(Vec::is_empty));
    let execute_stage = stages
        .iter()
        .find(|stage| stage["name"] == "execute")
        .expect("execute stage");
    assert_eq!(execute_stage["evidence_class"], "agent_action");
    assert!(
        execute_stage["summary"]
            .as_str()
            .unwrap_or_default()
            .contains("Generate the workflow preview")
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one end-to-end fixture binds preview freshness, profile isolation, coverage, and lifecycle packet export"
)]
pub(super) fn workflow_preview_joins_scoped_proof_without_crossing_the_cloudflare_boundary() {
    let root = tempfile::tempdir().expect("runtime root");
    let store = authenticated_test_store(RuntimePaths::from_root(root.path()));
    let read_capability = resolver_read_capability(
        "graphql-analytics-zone-http-requests",
        "Query zone HTTP analytics",
        "GraphQL Analytics",
    );
    let workflow = resolver_workflow_capability(
        "workflow.telemetry.audit-account",
        "Audit telemetry coverage across an account",
    );
    let mut export = resolver_workflow_capability(
        "workflow.telemetry.export-evidence-packet",
        "Export an operator telemetry evidence packet",
    );
    let export_contract = export.workflow.as_mut().expect("export workflow");
    export_contract.steps[0].capability_id = workflow.id.clone();
    export_contract.exports_evidence_packet = true;
    export_contract.proof_freshness_seconds = 3_600;
    let mut catalog = CatalogSnapshot {
        schema_version: 1,
        generated_at: Utc::now(),
        source_url: "test://workflow".to_owned(),
        source_hash: "sha256:source".to_owned(),
        schema_hash: String::new(),
        capabilities: vec![
            (read_capability.id.clone(), read_capability),
            (workflow.id.clone(), workflow.clone()),
            (export.id.clone(), export.clone()),
        ]
        .into_iter()
        .collect(),
    };
    catalog.refresh_hash().expect("catalog hashes");
    let evidence = store
        .write_evidence(EvidenceClass::LiveRead, &json!({"bounded": true}))
        .expect("live evidence");
    let input_hash = format!("sha256:{}", "a".repeat(64));
    let mut profiles = ProfilesConfig::default();
    for (profile_id, generation_id) in [
        ("default", "11111111-1111-4111-8111-111111111111"),
        ("secondary", "22222222-2222-4222-8222-222222222222"),
    ] {
        let mut profile =
            ProfileMetadata::new(profile_id, ProfileKind::ApiToken, Some("account-a"));
        profile.credential_generation_id = Some(generation_id.to_owned());
        profiles.profiles.insert(profile_id.to_owned(), profile);
        store
            .record_operational_proof(&OperationalProofV1::new(
                Utc::now(),
                "graphql-analytics-zone-http-requests",
                &catalog.schema_hash,
                &input_hash,
                OperationalProofScopeV1::new(
                    Some(profile_id),
                    Some("account-a"),
                    Some(generation_id),
                ),
                OperationalProofOutcomeV1::Succeeded,
                evidence.clone(),
            ))
            .expect("proof indexes");
    }
    store
        .record_operational_proof(&OperationalProofV1::new(
            Utc::now(),
            "graphql-analytics-zone-http-requests",
            &catalog.schema_hash,
            &input_hash,
            OperationalProofScopeV1::new(
                Some("default"),
                Some("account-a"),
                Some("33333333-3333-4333-8333-333333333333"),
            ),
            OperationalProofOutcomeV1::Failed,
            evidence.clone(),
        ))
        .expect("prior credential generation remains separately indexed");
    profiles.current_profile = Some("default".to_owned());
    profiles.save(&store).expect("profiles persist");
    let mut mutation = resolver_mutation_capability();
    mutation.id = "security-response-create-expiring-ip-access-rule".to_owned();
    let plan = PlanV1::draft(
        "default",
        "account-a",
        &catalog.schema_hash,
        mutation,
        json!({"zone_id": "zone-a"}),
    )
    .expect("mutation plan drafts");
    store.save_plan(&plan).expect("mutation plan persists");

    let envelope =
        execute_native_workflow(&store, &catalog, &workflow).expect("workflow preview succeeds");
    assert!(!envelope.performed);
    assert_eq!(envelope.result["kind"], "workflow_preview_v1");
    assert_eq!(envelope.result["cloudflare_boundary_crossed"], false);
    assert_eq!(
        envelope.result["steps"][0]["proof"]["observations"][0]["state"],
        "fresh"
    );
    assert_eq!(
        envelope.result["steps"][0]["proof"]["observations"]
            .as_array()
            .map(Vec::len),
        Some(3),
        "profile and credential generations remain distinct"
    );
    let workflow_states = envelope.result["steps"][0]["proof"]["observations"]
        .as_array()
        .expect("workflow observations")
        .iter()
        .filter_map(|observation| observation["state"].as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        workflow_states,
        std::collections::BTreeSet::from(["credential_drifted", "fresh"])
    );
    assert_eq!(envelope.evidence[0].class, EvidenceClass::AgentAction);

    let coverage = operational_proof_coverage(&store, &catalog).expect("proof coverage");
    assert_eq!(coverage["current_catalog_successes"], 2);
    assert_eq!(coverage["current_catalog_failures"], 0);
    assert_eq!(coverage["credential_drifted_observations"], 1);
    assert_eq!(coverage["credential_unbound_observations"], 0);
    assert_eq!(
        coverage["latest_scoped_observations"]
            .as_array()
            .map(Vec::len),
        Some(3)
    );
    assert_eq!(
        coverage["mutation_lifecycle"]["observations"][0]["capability_id"],
        "security-response-create-expiring-ip-access-rule"
    );
    assert_eq!(
        coverage["mutation_lifecycle"]["observations"][0]["status"],
        "draft"
    );
    assert_eq!(
        coverage["mutation_lifecycle"]["observations"][0]["verification"],
        "pending"
    );

    let packet = execute_native_workflow(&store, &catalog, &export)
        .expect("evidence packet preview succeeds");
    assert_eq!(
        packet.result["evidence_packet"]["contains_raw_telemetry"],
        false
    );
    assert_eq!(
        packet.result["evidence_packet"]["read_receipts"]
            .as_array()
            .map(Vec::len),
        Some(3)
    );
    assert_eq!(
        packet.result["evidence_packet"]["mutation_lifecycle_receipts"][0]["operation_id"],
        plan.operation_id
    );
    assert_eq!(
        packet.result["evidence_packet"]["mutation_lifecycle_receipts"][0]["receipt_classes"][0],
        "plan"
    );
    assert_eq!(
        packet.result["evidence_packet"]["contains_plan_inputs"],
        false
    );
    assert_eq!(
        packet.result["evidence_packet"]["contains_transaction_artifacts"],
        false
    );
    let packet_text = serde_json::to_string(&packet.result["evidence_packet"])
        .expect("evidence packet serializes");
    assert!(!packet_text.contains("\"targets\""));
    assert!(!packet_text.contains("\"input\""));
    assert!(!packet_text.contains("\"transaction_artifacts\":"));
    assert!(packet.result["steps"][0]["nested_steps"].is_array());
}

#[test]
pub(super) fn delegated_cli_receipt_is_truthfully_marked_performed() {
    let envelope = delegated_read_envelope(
        "sha256:catalog",
        "delegated.read",
        "profile-a",
        Some("account-a".to_owned()),
        json!({"success": true, "bounded": true}),
        Some(EvidenceV1::new(
            EvidenceClass::LiveRead,
            "sha256:evidence",
            "/tmp/evidence.json",
        )),
    );

    assert!(envelope.ok);
    assert!(envelope.performed);
    assert_eq!(envelope.capability_id.as_deref(), Some("delegated.read"));
    assert_eq!(envelope.evidence[0].class, EvidenceClass::LiveRead);
}

#[test]
pub(super) fn delegated_d1_verification_requires_coherent_v1_and_complete_bounded_v2() {
    let coherent = json!({
        "adapter":"workspace_d1_evidence_v1",
        "success":true,
        "provider_output_retained":false,
        "body_returned":false,
        "evidence":{
            "schema_version":1,
            "body_returned":false
        },
        "route_health":{
            "schema_version":2,
            "record_count":1,
            "complete":true,
            "records":[{"route_ref_sha256":format!("sha256:{}", "a".repeat(64))}],
            "provider_output_retained":false,
            "body_returned":false
        }
    });
    let mut coherent_envelope = delegated_read_envelope(
        "sha256:catalog",
        "star-maildesk-cf.d1-evidence-read",
        "profile-a",
        Some("account-a".to_owned()),
        coherent.clone(),
        Some(EvidenceV1::new(
            EvidenceClass::LiveRead,
            "sha256:evidence",
            "/tmp/evidence.json",
        )),
    );
    set_workspace_d1_evidence_verification(
        &mut coherent_envelope,
        workspace_d1_evidence::receipt_is_complete(&coherent),
    );
    assert_eq!(
        coherent_envelope.verification.state,
        VerificationState::Passed
    );
    assert!(
        coherent_envelope
            .verification
            .basis
            .as_deref()
            .is_some_and(|basis| basis.contains("complete bounded body-free"))
    );

    let mut incomplete = coherent.clone();
    incomplete["route_health"]["complete"] = json!(false);
    let mut count_mismatch = coherent.clone();
    count_mismatch["route_health"]["record_count"] = json!(2);
    let mut retained = coherent.clone();
    retained["route_health"]["provider_output_retained"] = json!(true);
    let mut malformed = coherent.clone();
    malformed["route_health"]["records"] = json!({"not":"an array"});
    let mut oversized = coherent.clone();
    oversized["route_health"]["records"] = Value::Array(vec![Value::Null; 1_001]);
    oversized["route_health"]["record_count"] = json!(1_001);
    let missing_v2 = json!({
        "success":true,
        "provider_output_retained":false,
        "body_returned":false,
        "evidence":{"schema_version":1,"body_returned":false}
    });

    for receipt in [
        incomplete,
        count_mismatch,
        retained,
        malformed,
        oversized,
        missing_v2,
    ] {
        let mut envelope = delegated_read_envelope(
            "sha256:catalog",
            "star-maildesk-cf.d1-evidence-read",
            "profile-a",
            Some("account-a".to_owned()),
            receipt.clone(),
            Some(EvidenceV1::new(
                EvidenceClass::LiveRead,
                "sha256:evidence",
                "/tmp/evidence.json",
            )),
        );
        set_workspace_d1_evidence_verification(
            &mut envelope,
            workspace_d1_evidence::receipt_is_complete(&receipt),
        );
        assert_eq!(envelope.verification.state, VerificationState::Failed);
        assert!(
            envelope
                .verification
                .basis
                .as_deref()
                .is_some_and(|basis| basis.contains("did not prove"))
        );
    }
}

#[test]
pub(super) fn delegated_d1_preflight_failure_retains_identity_without_claiming_a_boundary() {
    let envelope = delegated_read_envelope(
        "sha256:catalog",
        "star-maildesk-cf.d1-evidence-read",
        "profile-a",
        Some("account-a".to_owned()),
        json!({
            "adapter":"workspace_d1_evidence_v1",
            "success":false,
            "boundary_crossed":false,
            "failure_code":"CFCTL_WORKSPACE_D1_EVIDENCE_PREFLIGHT_FAILED",
            "failure_stage":"preflight",
            "provider_output_retained":false,
            "body_returned":false
        }),
        None,
    );

    assert!(!envelope.ok);
    assert!(!envelope.performed);
    assert_eq!(
        envelope.capability_id.as_deref(),
        Some("star-maildesk-cf.d1-evidence-read")
    );
    assert_eq!(envelope.profile_id.as_deref(), Some("profile-a"));
    assert_eq!(envelope.account_id.as_deref(), Some("account-a"));
    assert_eq!(envelope.verification.state, VerificationState::Failed);
    assert!(envelope.evidence.is_empty());
    assert_eq!(
        envelope.error.as_ref().map(|error| error.code.as_str()),
        Some("CFCTL_WORKSPACE_D1_EVIDENCE_PREFLIGHT_FAILED")
    );
}

#[test]
pub(super) fn delegated_d1_post_boundary_failure_is_bound_body_free_and_not_retryable_by_inference()
{
    let envelope = delegated_read_envelope(
        "sha256:catalog",
        "star-maildesk-cf.d1-evidence-read",
        "profile-a",
        Some("account-a".to_owned()),
        json!({
            "adapter":"workspace_d1_evidence_v1",
            "success":false,
            "boundary_crossed":true,
            "failure_code":"CFCTL_WORKSPACE_D1_EVIDENCE_PROVIDER_READ_FAILED",
            "failure_stage":"provider_query",
            "provider_output_retained":false,
            "body_returned":false
        }),
        Some(EvidenceV1::new(
            EvidenceClass::LiveRead,
            "sha256:evidence",
            "/tmp/evidence.json",
        )),
    );

    assert!(!envelope.ok);
    assert!(envelope.performed);
    assert_eq!(envelope.verification.state, VerificationState::Failed);
    let error = envelope.error.as_ref().expect("typed failure");
    assert_eq!(
        error.code,
        "CFCTL_WORKSPACE_D1_EVIDENCE_PROVIDER_READ_FAILED"
    );
    assert!(
        error
            .next_step
            .as_deref()
            .is_some_and(|step| step.contains("Do not replay"))
    );
    let encoded = serde_json::to_string(&envelope).expect("failure envelope JSON");
    for prohibited in [
        "subject",
        "recipient",
        "message_content",
        "provider_payload",
    ] {
        assert!(
            !encoded.contains(prohibited),
            "prohibited field `{prohibited}`"
        );
    }
}

#[test]
pub(super) fn worker_deployment_identity_drift_stops_before_delegated_boundary() {
    let planned = json!({
        "schema_version": 1,
        "source_capability_id": "worker-script-get-settings",
        "source_path": "/accounts/{account_id}/workers/scripts/{script_name}/settings",
        "deployment_source_capability_id": "worker-deployments-list-deployments",
        "deployment_source_path": "/accounts/{account_id}/workers/scripts/{script_name}/deployments",
        "account_id": "account-a",
        "service_name": "cfctl-site",
        "http_status": 200,
        "deployment_http_status": 200,
        "exists": true,
        "redacted_settings_hash": "sha256:same-settings",
        "redacted_deployments_hash": "sha256:deployment-a",
    });
    let mut current = planned.clone();
    current["redacted_deployments_hash"] = json!("sha256:deployment-b");
    let planned_hash = hash_value(&planned).expect("planned state hash");
    let mut capability = CapabilityV1::new(
        "wrangler.versions-deploy",
        "Promote Worker version",
        "CLI",
        "wrangler versions deploy --yes",
    );
    capability.mutating = true;
    capability.adapter_status = AdapterStatus::DelegatedCli;
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
        json!({
            "adapter": {
                "worker_deployment": {
                    "schema_version": 1,
                    "service_name": "cfctl-site",
                    "source_sha": "1111111111111111111111111111111111111111",
                    "promotion": {
                        "version_id": "11111111-2222-4333-8444-555555555555",
                        "traffic_percentage": 100,
                    },
                },
            },
            "live_preconditions": {
                "worker_deployment_state": planned,
            },
        }),
    )
    .expect("promotion plan");
    plan.precondition_hashes.insert(
        super::worker_deployment::STATE_PRECONDITION.to_owned(),
        planned_hash.clone(),
    );
    assert_eq!(
        super::required_worker_deployment_state_precondition(&plan)
            .expect("promotion state authority"),
        Some(planned_hash.as_str())
    );
    let mut grafted_legacy = plan.clone();
    let grafted_receipt = grafted_legacy
        .targets
        .pointer_mut("/live_preconditions/worker_deployment_state")
        .expect("legacy state receipt");
    grafted_receipt["current_active"] = json!({
        "deployment_id": "deployment-a",
        "version_id": "version-a",
        "traffic_percentage": 100,
    });
    grafted_legacy.precondition_hashes.insert(
        super::worker_deployment::STATE_PRECONDITION.to_owned(),
        hash_value(grafted_receipt).expect("grafted state hash"),
    );
    assert!(
        super::required_worker_deployment_state_precondition(&grafted_legacy).is_err(),
        "legacy receipt schema must reject a grafted strict rollback identity"
    );
    let mut delegated_boundary_crossed = false;

    let result = (|| -> std::result::Result<(), super::CliError> {
        validate_current_worker_deployment_state(&planned_hash, &current)?;
        delegated_boundary_crossed = true;
        Ok(())
    })();

    assert!(result.is_err());
    assert!(!delegated_boundary_crossed);
    assert_eq!(plan.status, PlanStatus::Draft);
}

#[test]
pub(super) fn worker_planning_receipt_requires_exact_prior_active_identity() {
    let planned = json!({
        "schema_version": 1,
        "source_capability_id": "worker-script-get-settings",
        "source_path": "/accounts/{account_id}/workers/scripts/{script_name}/settings",
        "deployment_source_capability_id": "worker-deployments-list-deployments",
        "deployment_source_path": "/accounts/{account_id}/workers/scripts/{script_name}/deployments",
        "account_id": "account-a",
        "service_name": "relay-router",
        "http_status": 200,
        "deployment_http_status": 200,
        "exists": true,
        "redacted_settings_hash": "sha256:settings",
        "redacted_deployments_hash": "sha256:deployments",
        "current_active": {
            "deployment_id": "deployment-a",
            "version_id": "version-a",
            "traffic_percentage": 100,
        },
    });
    let planned_hash = hash_value(&planned).expect("strict state hash");
    let mut capability = CapabilityV1::new(
        WORKER_DEPLOYMENT_PLAN_CAPABILITY_ID,
        "Compile Worker deployment",
        "POST",
        "/cfctl/plans/accounts/{account_id}/workers/deployment",
    );
    capability.mutating = true;
    capability.adapter_status = AdapterStatus::Native;
    capability.execution_supported = false;
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
        json!({
            "adapter": {
                "worker_deployment": {
                    "schema_version": 1,
                    "service_name": "relay-router",
                },
            },
            "live_preconditions": {
                "worker_deployment_state": planned,
            },
        }),
    )
    .expect("planning-only plan");
    plan.precondition_hashes.insert(
        super::worker_deployment::STATE_PRECONDITION.to_owned(),
        planned_hash.clone(),
    );
    assert_eq!(
        super::required_worker_deployment_state_precondition(&plan)
            .expect("strict planning state authority"),
        Some(planned_hash.as_str())
    );

    let malformed_receipt = plan
        .targets
        .pointer_mut("/live_preconditions/worker_deployment_state/current_active")
        .expect("current active identity");
    malformed_receipt["traffic_percentage"] = json!(50);
    let malformed_hash = hash_value(
        plan.targets
            .pointer("/live_preconditions/worker_deployment_state")
            .expect("malformed state receipt"),
    )
    .expect("malformed state hash");
    plan.precondition_hashes.insert(
        super::worker_deployment::STATE_PRECONDITION.to_owned(),
        malformed_hash,
    );
    assert!(
        super::required_worker_deployment_state_precondition(&plan).is_err(),
        "strict planning receipt must reject a non-100-percent active identity"
    );
}

#[test]
pub(super) fn worker_promotion_readback_is_exact_service_and_configless() {
    let cache = tempfile::tempdir().expect("cache root");
    let prepared = prepare_wrangler_deployment_status_command(
        WranglerDeploymentStatusTarget::Service("cfctl-site"),
        "account-a",
        cache.path(),
    )
    .expect("exact-service readback command");
    let args = prepared
        .command
        .as_std()
        .get_args()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        args,
        ["deployments", "status", "--name", "cfctl-site", "--json"]
    );
    assert!(!args.iter().any(|argument| argument == "--config"));
    assert_eq!(prepared.exact_service_name, Some("cfctl-site"));
    let isolated = prepared
        .isolated_directory
        .as_ref()
        .expect("private configless readback directory");
    assert_eq!(
        prepared.command.as_std().get_current_dir(),
        Some(isolated.path())
    );
}

#[test]
pub(super) fn quick_tunnel_origin_is_loopback_and_port_bound() {
    assert_eq!(
        super::validated_quick_tunnel_origin("http://127.0.0.1:3300").expect("loopback origin"),
        "http://127.0.0.1:3300/"
    );
    assert_eq!(
        super::validated_quick_tunnel_origin("http://localhost:3300").expect("localhost origin"),
        "http://localhost:3300/"
    );
    assert!(super::validated_quick_tunnel_origin("https://example.com").is_err());
    assert!(super::validated_quick_tunnel_origin("http://127.0.0.1").is_err());
    assert!(super::validated_quick_tunnel_origin("file:///tmp/socket").is_err());
}

#[test]
pub(super) fn quick_tunnel_public_url_is_extracted_only_from_trycloudflare_https() {
    let log = concat!(
        "INF Requesting new quick Tunnel on trycloudflare.com...\n",
        "INF +------------------------------------------------------------+\n",
        "INF |  https://quiet-river-123.trycloudflare.com                 |\n",
    );
    assert_eq!(
        super::trycloudflare_public_url(log).as_deref(),
        Some("https://quiet-river-123.trycloudflare.com")
    );
    assert!(super::trycloudflare_public_url("https://example.com").is_none());
    assert!(super::trycloudflare_public_url("http://quiet-river.trycloudflare.com").is_none());
}

#[test]
pub(super) fn quick_tunnel_health_url_accepts_only_a_relative_path() {
    assert_eq!(
        super::quick_tunnel_verification_url(
            "https://quiet-river.trycloudflare.com",
            Some("/healthz")
        )
        .expect("health URL"),
        "https://quiet-river.trycloudflare.com/healthz"
    );
    assert_eq!(
        super::quick_tunnel_verification_url("https://quiet-river.trycloudflare.com", None)
            .expect("default URL"),
        "https://quiet-river.trycloudflare.com/"
    );
    assert!(
        super::quick_tunnel_verification_url(
            "https://quiet-river.trycloudflare.com",
            Some("https://example.com")
        )
        .is_err()
    );
    assert!(
        super::quick_tunnel_verification_url(
            "https://quiet-river.trycloudflare.com",
            Some("//example.com")
        )
        .is_err()
    );
}

#[test]
pub(super) fn operational_proof_persistence_failure_preserves_boundary_truth_and_fails_envelope() {
    let mut envelope =
        ResultEnvelopeV2::success("call", json!({"bounded": true})).with_evidence(EvidenceV1::new(
            EvidenceClass::LiveRead,
            "sha256:evidence",
            "/tmp/evidence.json",
        ));
    envelope.performed = true;

    apply_operational_proof_index_result(
        &mut envelope,
        Err(CliError::Input("fixture persistence failure".to_owned())),
    );

    assert!(!envelope.ok);
    assert!(envelope.performed, "the completed read remains truthful");
    assert_eq!(
        envelope.error.as_ref().map(|error| error.code.as_str()),
        Some("CFCTL_OPERATIONAL_PROOF_INDEX_FAILED")
    );
    assert_eq!(envelope.evidence[0].class, EvidenceClass::LiveRead);
}

#[test]
pub(super) fn operational_proof_persistence_failure_does_not_replace_the_first_read_blocker() {
    let mut envelope = ResultEnvelopeV2::failure(
        "call",
        "CFCTL_WORKSPACE_D1_EVIDENCE_PROVIDER_READ_FAILED",
        "workspace D1 evidence failed",
        Some("Do not replay the read."),
    )
    .with_evidence(EvidenceV1::new(
        EvidenceClass::LiveRead,
        "sha256:evidence",
        "/tmp/evidence.json",
    ));
    envelope.performed = true;

    apply_operational_proof_index_result(
        &mut envelope,
        Err(CliError::Input("fixture persistence failure".to_owned())),
    );

    assert!(!envelope.ok);
    assert!(envelope.performed);
    assert_eq!(
        envelope.error.as_ref().map(|error| error.code.as_str()),
        Some("CFCTL_WORKSPACE_D1_EVIDENCE_PROVIDER_READ_FAILED")
    );
    assert_eq!(envelope.result["operational_proof_indexed"], false);
}

#[test]
pub(super) fn workflow_preview_withholds_calls_for_blocked_gapped_and_cyclic_components() {
    let root = tempfile::tempdir().expect("runtime root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("store opens");
    let mut blocked = resolver_read_capability("blocked.read", "Blocked read", "Telemetry");
    blocked.adapter_status = AdapterStatus::Blocked;
    blocked.blocked_reason = Some("fixture blocker".to_owned());
    let mut gapped = CapabilityV1::new(
        "gapped.mutation",
        "Gapped mutation",
        "POST",
        "/accounts/{account_id}/gapped",
    );
    gapped.mutating = true;
    gapped.adapter_status = AdapterStatus::DynamicApi;
    let mut workflow = resolver_workflow_capability("workflow.fail-closed", "Fail closed");
    workflow.workflow.as_mut().expect("workflow contract").steps = vec![
        WorkflowStepV1 {
            id: "blocked".to_owned(),
            capability_id: blocked.id.clone(),
            purpose: "Blocked component".to_owned(),
            mutating: false,
            depends_on: Vec::new(),
        },
        WorkflowStepV1 {
            id: "gapped".to_owned(),
            capability_id: gapped.id.clone(),
            purpose: "Gapped component".to_owned(),
            mutating: true,
            depends_on: Vec::new(),
        },
    ];
    let mut catalog = CatalogSnapshot {
        schema_version: 1,
        generated_at: Utc::now(),
        source_url: "test://workflow".to_owned(),
        source_hash: "sha256:source".to_owned(),
        schema_hash: String::new(),
        capabilities: vec![
            (blocked.id.clone(), blocked),
            (gapped.id.clone(), gapped),
            (workflow.id.clone(), workflow.clone()),
        ]
        .into_iter()
        .collect(),
    };
    catalog.refresh_hash().expect("catalog hashes");

    let preview =
        execute_native_workflow(&store, &catalog, &workflow).expect("fail-closed preview renders");
    for step in preview.result["steps"].as_array().expect("preview steps") {
        assert_eq!(step["available"], false);
        assert!(step["call_argv"].is_null());
        assert!(step["guide_argv"].is_array());
        assert!(
            step["blocking_gaps"]
                .as_array()
                .is_some_and(|gaps| !gaps.is_empty())
        );
    }

    let mut cycle_a = resolver_workflow_capability("workflow.cycle-a", "Cycle A");
    let mut cycle_b = resolver_workflow_capability("workflow.cycle-b", "Cycle B");
    cycle_a.workflow.as_mut().expect("cycle A contract").steps[0].capability_id =
        cycle_b.id.clone();
    cycle_b.workflow.as_mut().expect("cycle B contract").steps[0].capability_id =
        cycle_a.id.clone();
    let mut cycle_catalog = CatalogSnapshot {
        schema_version: 1,
        generated_at: Utc::now(),
        source_url: "test://cycle".to_owned(),
        source_hash: "sha256:source".to_owned(),
        schema_hash: String::new(),
        capabilities: BTreeMap::from([
            (cycle_a.id.clone(), cycle_a.clone()),
            (cycle_b.id.clone(), cycle_b),
        ]),
    };
    cycle_catalog.refresh_hash().expect("cycle catalog hashes");
    let cycle = execute_native_workflow(&store, &cycle_catalog, &cycle_a)
        .expect("cyclic preview terminates");
    let blocked_cycle = &cycle.result["steps"][0]["nested_steps"][0]["nested_steps"][0];
    assert_eq!(blocked_cycle["available"], false);
    assert!(blocked_cycle["call_argv"].is_null());
    assert_eq!(
        blocked_cycle["blocking_gaps"][0],
        "workflow composition cycle detected"
    );
}

#[test]
pub(super) fn workspace_proof_posture_requires_an_account_pin_and_keeps_catalog_truth_separate() {
    let evidence = EvidenceV1::new(
        EvidenceClass::LiveRead,
        "sha256:evidence",
        "/tmp/evidence.json",
    );
    let proofs = vec![
        OperationalProofV1::new(
            Utc::now(),
            "telemetry.query",
            "sha256:current",
            "sha256:input-a",
            OperationalProofScopeV1::new(
                Some("default"),
                Some("account-a"),
                Some("11111111-1111-4111-8111-111111111111"),
            ),
            OperationalProofOutcomeV1::Succeeded,
            evidence.clone(),
        ),
        OperationalProofV1::new(
            Utc::now(),
            "telemetry.query",
            "sha256:old",
            "sha256:input-b",
            OperationalProofScopeV1::new(
                Some("other"),
                Some("account-b"),
                Some("22222222-2222-4222-8222-222222222222"),
            ),
            OperationalProofOutcomeV1::Succeeded,
            evidence,
        ),
    ];

    let mut profiles = ProfilesConfig::default();
    let mut profile = ProfileMetadata::new("default", ProfileKind::ApiToken, Some("account-a"));
    profile.credential_generation_id = Some("11111111-1111-4111-8111-111111111111".to_owned());
    profiles.profiles.insert("default".to_owned(), profile);

    let unscoped = workspace_operational_proof_posture(&proofs, &[], &profiles, None, None);
    assert_eq!(unscoped["state"], "unscoped");
    let account = workspace_operational_proof_posture(
        &proofs,
        &[],
        &profiles,
        Some("account-a"),
        Some("sha256:current"),
    );
    assert_eq!(account["proof_count"], 1);
    assert_eq!(account["current_catalog_successes"], 1);
    assert_eq!(account["catalog_drifted_or_unclassified"], 0);
    let failures = vec![cfctl_storage::OperationalProofFailureV1 {
        account_id: None,
        proof_identity: format!("sha256:{}", "f".repeat(64)),
        reason: "authentication failed".to_owned(),
    }];
    let original_account = workspace_operational_proof_posture(
        &proofs,
        &failures,
        &profiles,
        Some("account-a"),
        Some("sha256:current"),
    );
    assert_eq!(original_account["state"], "invalid");
    assert_eq!(
        original_account["proof_failures"].as_array().map(Vec::len),
        Some(1)
    );
    let other_account = workspace_operational_proof_posture(
        &proofs,
        &failures,
        &profiles,
        Some("account-b"),
        Some("sha256:current"),
    );
    assert_eq!(other_account["state"], "invalid");
}

#[test]
pub(super) fn resolve_result_empty_fails_closed_with_discovery_guidance() {
    let ranked: Vec<(&CapabilityV1, usize)> = Vec::new();
    let (result, error) = super::resolve_result("do a thing", &ranked, None, 5);
    let error = error.expect("empty match fails closed");
    assert_eq!(error.code, "CFCTL_RESOLVE_NO_MATCH");
    assert!(
        error.next_step.is_some(),
        "fail-closed carries envelope next_step"
    );
    assert_eq!(result["ambiguous"], serde_json::Value::Bool(true));
    assert_eq!(result["resolved"], serde_json::Value::Null);
    assert!(result["disambiguation"]["search_argv"].is_array());
}

#[test]
pub(super) fn broad_telemetry_intent_returns_an_overview_and_withholds_mutation_commands() {
    let read_capability = resolver_read_capability(
        "graphql-analytics-zone-http-requests",
        "Query zone HTTP analytics",
        "GraphQL Analytics",
    );
    let mutation = resolver_mutation_capability();
    let workflow = resolver_workflow_capability(
        "workflow.telemetry.audit-account",
        "Audit telemetry coverage across an account",
    );
    let mut blocked = resolver_mutation_capability();
    blocked.id = "telemetry.live-tail.heartbeat.get".to_owned();
    blocked.adapter_status = AdapterStatus::Blocked;
    blocked.blocked_reason = Some("operation contract incomplete: risk_unknown".to_owned());
    let ranked = vec![
        (&mutation, 20usize),
        (&read_capability, 18usize),
        (&workflow, 4usize),
        (&blocked, 19usize),
    ];
    let (result, error) = super::resolve_result("telemetry overview", &ranked, None, 5);
    assert!(error.is_none());
    assert_eq!(result["resolved"]["kind"], "telemetry_domain_overview");
    assert_eq!(result["ambiguous"], false);
    assert_eq!(
        result["resolved"]["mutation_selection"],
        "withheld_until_a_specific_capability_is_resolved_and_guided"
    );
    assert_eq!(
        result["resolved"]["mutation_candidates"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    assert_eq!(
        result["resolved"]["governed_workflows"][0]["capability_id"],
        "workflow.telemetry.audit-account"
    );
    assert_eq!(
        result["resolved"]["blocked_or_unclassified_gaps"][0]["capability_id"],
        "telemetry.live-tail.heartbeat.get"
    );
    assert!(!result.to_string().contains("draft_argv"));
    assert!(super::is_broad_telemetry_intent("show analytics"));
    assert!(!super::is_broad_telemetry_intent(
        "configure Worker observability sampling"
    ));
}

#[test]
pub(super) fn resolve_result_weak_top_score_fails_closed() {
    let cap = resolver_read_capability("a-thing", "A Thing", "Things");
    let ranked = vec![(&cap, 3usize)];
    let (result, error) = super::resolve_result("thing", &ranked, None, 5);
    let error = error.expect("a sub-threshold score must not commit");
    assert_eq!(error.code, "CFCTL_RESOLVE_AMBIGUOUS");
    assert!(error.next_step.is_some());
    assert!(
        result["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("too weak")
    );
}

#[test]
pub(super) fn resolve_result_close_scores_fail_closed_as_ambiguous() {
    let a = resolver_read_capability("cap-a", "Cap A", "P");
    let b = resolver_read_capability("cap-b", "Cap B", "P");
    // 8 vs 7 (1.14x): top*5=40 < runner*6=42 -> below the 1.2x margin.
    let ranked = vec![(&a, 8usize), (&b, 7usize)];
    let (result, error) = super::resolve_result("ambiguous intent", &ranked, None, 5);
    assert!(error.is_some(), "close scores fail closed");
    assert_eq!(result["ambiguous"], serde_json::Value::Bool(true));
    assert_eq!(result["matched"].as_array().map(Vec::len), Some(2));
}

// The 1.2x commit-margin boundary (evidence-backed by the live-catalog
// effectiveness study). Deterministic, and every ambiguity safeguard below
// 1.2x remains fail-closed.
#[test]
pub(super) fn resolve_exact_tie_stays_fail_closed() {
    let a = resolver_read_capability("cap-a", "Cap A", "P");
    let b = resolver_read_capability("cap-b", "Cap B", "P");
    // 24 vs 24 (1.0x): the score cannot distinguish the pair; e.g. a "set"
    // intent tying a get/update pair must never auto-commit the wrong one.
    let ranked = vec![(&a, 24usize), (&b, 24usize)];
    let (result, error) = super::resolve_result("tied intent", &ranked, None, 5);
    assert!(error.is_some(), "an exact tie must fail closed");
    assert_eq!(result["resolved"], serde_json::Value::Null);
}

#[test]
pub(super) fn resolve_near_tie_below_margin_stays_fail_closed() {
    let a = resolver_read_capability("cap-a", "Cap A", "P");
    let b = resolver_read_capability("cap-b", "Cap B", "P");
    // 11 vs 10 (1.1x): top*5=55 < runner*6=60 -> just below 1.2x.
    let ranked = vec![(&a, 11usize), (&b, 10usize)];
    let (result, error) = super::resolve_result("near tie intent", &ranked, None, 5);
    assert!(error.is_some(), "a sub-1.2x near tie must fail closed");
    assert_eq!(result["resolved"], serde_json::Value::Null);
}

#[test]
pub(super) fn resolve_clear_winner_at_margin_commits() {
    let a = resolver_read_capability("cap-win", "Winner", "P");
    let b = resolver_read_capability("cap-b", "Cap B", "P");
    // 12 vs 10 (exactly 1.2x): top*5=60 >= runner*6=60 -> commits.
    let ranked = vec![(&a, 12usize), (&b, 10usize)];
    let (result, error) = super::resolve_result("clear winner intent", &ranked, None, 5);
    assert!(error.is_none(), "a >=1.2x clear winner must commit");
    assert_eq!(result["resolved"]["capability_id"], "cap-win");
    assert!(result["resolved"]["commands"]["draft_argv"].is_array());
}

#[test]
pub(super) fn resolve_result_confident_read_emits_only_a_draft() {
    let cap = resolver_read_capability("email-routing-list", "List Email Routing", "Email Routing");
    let ranked = vec![(&cap, 12usize)];
    let (result, error) = super::resolve_result("list email routing", &ranked, None, 5);
    assert!(error.is_none(), "a confident read resolves");
    assert_eq!(result["ambiguous"], serde_json::Value::Bool(false));
    assert_eq!(result["resolved"]["capability_id"], "email-routing-list");
    assert!(result["resolved"]["commands"]["draft_argv"].is_array());
    // A read draws no approve/run/status governed loop.
    assert!(result["resolved"]["commands"]["approve_argv"].is_null());
}

#[test]
pub(super) fn resolve_result_confident_mutation_emits_the_governed_loop() {
    let cap = resolver_mutation_capability();
    let ranked = vec![(&cap, 20usize)];
    let (result, error) = super::resolve_result("enable email routing", &ranked, None, 5);
    assert!(error.is_none(), "a confident mutation resolves");
    assert_eq!(
        result["resolved"]["contract_ready"],
        serde_json::Value::Bool(true),
        "fixture must be gap-free; resolved={}",
        result["resolved"]
    );
    let commands = &result["resolved"]["commands"];
    assert!(commands["draft_argv"].is_array());
    let approve = commands["approve_argv"].as_array().expect("approve argv");
    assert!(approve.iter().any(|part| part == "approve"));
    assert!(approve.iter().any(|part| part == "--yes"));
    assert!(commands["run_argv"].is_array());
    assert!(commands["status_argv"].is_array());
}

#[test]
pub(super) fn resolve_result_blocked_capability_withholds_the_call() {
    let mut cap = resolver_read_capability("blocked-thing", "Blocked Thing", "Things");
    cap.adapter_status = AdapterStatus::Blocked;
    cap.blocked_reason = Some("operation contract incomplete: cost".to_owned());
    let ranked = vec![(&cap, 12usize)];
    let (result, error) = super::resolve_result("blocked thing", &ranked, None, 5);
    assert!(
        error.is_none(),
        "a blocked-but-unambiguous top match still resolves (with withheld commands)"
    );
    assert_eq!(
        result["resolved"]["contract_ready"],
        serde_json::Value::Bool(false)
    );
    let commands = &result["resolved"]["commands"];
    assert_eq!(commands["blocked"], serde_json::Value::Bool(true));
    // No draft call is offered for a blocked capability.
    assert!(commands["draft_argv"].is_null());
    assert!(commands["next_action"].is_object());
}

#[test]
pub(super) fn resolve_result_emits_zone_hint_and_threads_account() {
    let mut cap = CapabilityV1::new(
        "zone-settings-get",
        "Get Zone Setting",
        "GET",
        "/zones/{zone_id}/settings",
    );
    cap.adapter_status = AdapterStatus::DynamicApi;
    cap.product = "Zones".to_owned();
    cap.selectors = vec![cfctl_core::SelectorV1 {
        name: "zone_id".to_owned(),
        location: "path".to_owned(),
        required: true,
        value_type: "string".to_owned(),
        description: None,
        contract: None,
    }];
    let ranked = vec![(&cap, 12usize)];
    let (result, error) =
        super::resolve_result("get setting on example.com", &ranked, Some("acct-9"), 5);
    assert!(error.is_none());
    let hint = &result["resolved"]["zone_resolution_hint"];
    assert!(hint.is_object());
    let example = hint["example_read_argv"].as_array().expect("example argv");
    assert!(example.iter().any(|part| part == "name=example.com"));
    assert_eq!(result["resolved"]["account"], "acct-9");
}

#[test]
pub(super) fn resolve_candidate_limit_is_respected() {
    let caps: Vec<CapabilityV1> = (0..8)
        .map(|index| resolver_read_capability(&format!("cap-{index}"), "Cap", "P"))
        .collect();
    // Distinct descending scores so ordering is deterministic and the top is
    // ambiguous-safe is irrelevant here; we only assert the candidate cap.
    let ranked: Vec<(&CapabilityV1, usize)> = caps
        .iter()
        .enumerate()
        .map(|(index, cap)| (cap, 100 - index))
        .collect();
    let (result, _error) = super::resolve_result("cap", &ranked, None, 3);
    assert_eq!(result["matched"].as_array().map(Vec::len), Some(3));
}
