#![allow(clippy::expect_used)]

use std::{collections::BTreeMap, fs};

use cfctl_catalog::CatalogSnapshot;
use cfctl_core::{
    CapabilityV1, D1FullExportGovernedExecutionBindingV1, EvidenceClass, EvidenceV1,
    OperationalProofOutcomeV1, OperationalProofScopeV1, OperationalProofV1, PlanPinsV2, PlanStatus,
    PlanV1, PlanV2, TransactionStageV1, WorkspaceD1AtomicityQualificationV1,
    WorkspaceD1ManifestMigrationContractV1, WorkspaceD1MigrationContractV1,
    WorkspaceD1MigrationFileV1, WorkspaceD1MigrationLedgerEntryV1, WorkspaceD1OldWorkerCanaryV1,
    hash_value,
};
use cfctl_storage::{RuntimePaths, StorageError};
use serde_json::{Value, json};

use super::*;

const ACCOUNT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PROFILE: &str = "profile-a";
const GENERATION: &str = "22222222-2222-4222-8222-222222222222";
const DATABASE: &str = "33333333-3333-4333-8333-333333333333";

fn digest(label: &str) -> String {
    hash_value(&Value::String(label.to_owned())).expect("hash")
}

fn store() -> (tempfile::TempDir, StateStore) {
    let root = tempfile::tempdir().expect("runtime root");
    let store = super::super::tests::authenticated_test_store(RuntimePaths::from_root(root.path()));
    (root, store)
}

fn migration_contract(
    migration_sha256: &str,
    manifest_backed: bool,
) -> WorkspaceD1MigrationContractV1 {
    WorkspaceD1MigrationContractV1 {
        repository_root: "/repo".to_owned(),
        repository_head: "a".repeat(40),
        repository_origin: "https://example.com/mln-web.git".to_owned(),
        operation_pack_path: ".cfctl/operations/d1-migrations.toml".to_owned(),
        operation_pack_sha256: digest("operation-pack"),
        config_template_path: "workers/founder/wrangler.toml".to_owned(),
        config_template_sha256: digest("config-template"),
        production_config_path: "workers/founder/wrangler.production.toml".to_owned(),
        migrations_dir: "crates/founder/migrations/d1".to_owned(),
        database_binding: "FOUNDER_DB".to_owned(),
        wrangler_version: "4.100.0".to_owned(),
        migrations: vec![WorkspaceD1MigrationFileV1 {
            path: "crates/founder/migrations/d1/0172_target.sql".to_owned(),
            sha256: migration_sha256.to_owned(),
        }],
        assertions: Vec::new(),
        recovery_capability_id: "d1-time-travel-get-bookmark".to_owned(),
        recovery_max_age_seconds: 600,
        rollback_capability_id: "d1-restore-exact-bookmark".to_owned(),
        manifest_migration: manifest_backed.then(|| WorkspaceD1ManifestMigrationContractV1 {
            manifest_path: ".control-plane/d1_migration_manifest.json".to_owned(),
            manifest_sha256: digest("manifest"),
            account_id: ACCOUNT.to_owned(),
            profile_id: PROFILE.to_owned(),
            database_name: "founder".to_owned(),
            database_id: DATABASE.to_owned(),
            baseline_start_sequence: 1,
            baseline_end_sequence: 1,
            baseline: vec![WorkspaceD1MigrationLedgerEntryV1 {
                sequence: 1,
                name: "0001_baseline.sql".to_owned(),
                sha256: digest("baseline-migration"),
            }],
            baseline_digest: digest("baseline"),
            target_sequence: 2,
            target_git_blob_oid: "b".repeat(40),
            migrations_pattern: "crates/founder/migrations/d1/0172_target.sql".to_owned(),
            ledger_table: "d1_migrations".to_owned(),
            ledger_name: "0172_target.sql".to_owned(),
            wrangler_cli_sha256: digest("wrangler"),
            full_export_capability_id: "d1-full-export".to_owned(),
            require_exact_post_ledger: true,
            forbidden_future_sequences: vec![3],
            require_exact_schema_sql: true,
            require_foreign_key_check_empty: true,
            require_integrity_check_ok: true,
            require_unchanged_worker_identity: true,
            require_old_worker_compatibility: true,
        }),
    }
}

struct StoredPlan {
    role: String,
    operation_id: String,
    plan_hash: String,
    pins_hash: String,
    capability_id: String,
    catalog_hash: String,
    target_hash: String,
    status: PlanStatus,
    stage: TransactionStageV1,
    evidence_hash: String,
}

#[expect(
    clippy::too_many_arguments,
    reason = "the authenticated plan fixture keeps each authority and migration identity explicit"
)]
fn stored_plan(
    store: &StateStore,
    role: &str,
    capability_id: &str,
    candidate_hash: &str,
    catalog_hash: &str,
    target: Value,
    status: PlanStatus,
    success_migration_sha256: &str,
) -> StoredPlan {
    let verification = store
        .write_evidence(
            EvidenceClass::PostChangeVerification,
            &json!({"role":role,"passed":status == PlanStatus::Verified}),
        )
        .expect("verification evidence");
    let apply = store
        .write_evidence(EvidenceClass::Apply, &json!({"role":role,"applied":true}))
        .expect("apply evidence");
    let mut capability = CapabilityV1::new(capability_id, role, "POST", "/fixture");
    if role == "success_apply" {
        capability.workspace_d1_migration =
            Some(migration_contract(success_migration_sha256, false));
    }
    let plan_target = if role == "success_apply" {
        let mut plan_target = target.clone();
        plan_target["adapter"] =
            json!({"workspace_d1_migration":{"wrangler_cli_sha256":digest("wrangler")}});
        plan_target
    } else {
        target.clone()
    };
    let mut plan = PlanV1::draft(
        PROFILE,
        ACCOUNT,
        catalog_hash,
        capability,
        plan_target.clone(),
    )
    .expect("draft plan");
    plan.input = serde_json::to_value(CallInput {
        selectors: target.clone(),
        ..CallInput::default()
    })
    .expect("plan input");
    plan.refresh_hash().expect("refresh plan input");
    plan.approve(true, None).expect("approve");
    plan.mark_consumed().expect("consume");
    plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("boundary attempt");
    plan.record_transaction_stage_with_artifact(
        TransactionStageV1::BoundaryResponsePersisted,
        json!({"success":true,"apply_evidence_hash":apply.content_hash}),
    )
    .expect("boundary response");
    plan.record_transaction_stage(TransactionStageV1::VerificationAttemptPersisted)
        .expect("verification attempt");
    plan.status = status;
    plan.record_transaction_stage_with_artifact(
        TransactionStageV1::VerificationResponsePersisted,
        json!({
            "state": if status == PlanStatus::Verified { "passed" } else { "failed" },
            "evidence_hash":verification.content_hash,
        }),
    )
    .expect("verification response");
    let stage = if status == PlanStatus::Verified {
        plan.record_transaction_stage(TransactionStageV1::Closed)
            .expect("closed");
        TransactionStageV1::Closed
    } else {
        TransactionStageV1::VerificationResponsePersisted
    };
    let plan_hash = plan.content_hash.clone();
    let operation_id = plan.operation_id.clone();
    let pins = PlanPinsV2 {
        build_identity_hash: candidate_hash.to_owned(),
        catalog_hash: catalog_hash.to_owned(),
        credential_generation_id: GENERATION.to_owned(),
        admission_policy_hash: digest("policy"),
        authority_hash: None,
        workspace_graph_hash: digest("workspace"),
        resource_observation_hashes: BTreeMap::new(),
        cost_budget: None,
    };
    let pins_hash =
        hash_value(&serde_json::to_value(&pins).expect("pins JSON")).expect("pins hash");
    let plan_v2 = PlanV2::new(plan, pins).expect("PlanV2");
    store.save_plan_v2(&plan_v2).expect("store PlanV2");
    StoredPlan {
        role: role.to_owned(),
        operation_id,
        plan_hash,
        pins_hash,
        capability_id: capability_id.to_owned(),
        catalog_hash: catalog_hash.to_owned(),
        target_hash: hash_value(&plan_target).expect("target hash"),
        status,
        stage,
        evidence_hash: verification.content_hash,
    }
}

fn plan_expectation(plan: &StoredPlan) -> PlanExpectation<'_> {
    PlanExpectation {
        role: &plan.role,
        operation_id: &plan.operation_id,
        plan_content_hash: &plan.plan_hash,
        pins_hash: &plan.pins_hash,
        capability_id: &plan.capability_id,
        catalog_hash: &plan.catalog_hash,
        profile_id: PROFILE,
        account_id: ACCOUNT,
        credential_generation_id: GENERATION,
        target_hash: &plan.target_hash,
        expected_status: plan.status,
        expected_stage: plan.stage,
        expected_evidence_class: EvidenceClass::PostChangeVerification,
        evidence_hash: &plan.evidence_hash,
    }
}

struct StoredProof {
    role: String,
    proof_hash: String,
    evidence_hash: String,
    capability_id: String,
    catalog_hash: String,
    input_hash: String,
    build_identity_hash: String,
}

fn stored_proof(
    store: &StateStore,
    role: &str,
    capability_id: &str,
    candidate_hash: &str,
    catalog_hash: &str,
    input: Value,
    body: Value,
) -> StoredProof {
    let evidence = store
        .write_evidence(EvidenceClass::LiveRead, &body)
        .expect("live-read evidence");
    let input_hash = hash_value(&input).expect("input hash");
    let observed_at = Utc::now();
    let mut proof = OperationalProofV1::new(
        observed_at,
        capability_id,
        catalog_hash,
        &input_hash,
        OperationalProofScopeV1::new(Some(PROFILE), Some(ACCOUNT), Some(GENERATION)),
        OperationalProofOutcomeV1::Succeeded,
        evidence,
    );
    proof
        .bind_build_identity_hash(candidate_hash)
        .expect("build identity");
    if capability_id == "d1-full-export" {
        proof
            .bind_d1_full_export_governed_execution(D1FullExportGovernedExecutionBindingV1 {
                schema_version: 1,
                operation_id: "44444444-4444-4444-8444-444444444444".to_owned(),
                capability_id: capability_id.to_owned(),
                catalog_hash: catalog_hash.to_owned(),
                target_scope_hash: hash_value(
                    &json!({"account_id":ACCOUNT,"database_id":DATABASE}),
                )
                .expect("target scope hash"),
                output_file_sha256: digest("full-export-output"),
                at_bookmark_hash: digest("full-export-bookmark"),
                manifest_evidence_hash: proof.evidence.content_hash.clone(),
                request_hash: input_hash.clone(),
                profile_id: PROFILE.to_owned(),
                credential_generation_id: GENERATION.to_owned(),
                completion_status: "completed".to_owned(),
                completed_at: observed_at,
            })
            .expect("full-export governed-execution provenance");
    }
    store
        .record_operational_proof(&proof)
        .expect("record proof");
    StoredProof {
        role: role.to_owned(),
        proof_hash: store.operational_proof_hash(&proof).expect("proof hash"),
        evidence_hash: proof.evidence.content_hash,
        capability_id: capability_id.to_owned(),
        catalog_hash: catalog_hash.to_owned(),
        input_hash,
        build_identity_hash: candidate_hash.to_owned(),
    }
}

fn proof_expectation(proof: &StoredProof) -> ProofExpectation<'_> {
    ProofExpectation {
        role: &proof.role,
        proof_hash: &proof.proof_hash,
        evidence_hash: &proof.evidence_hash,
        capability_id: &proof.capability_id,
        catalog_hash: &proof.catalog_hash,
        input_hash: &proof.input_hash,
        build_identity_hash: &proof.build_identity_hash,
        profile_id: PROFILE,
        account_id: ACCOUNT,
        credential_generation_id: GENERATION,
        expected_outcome: OperationalProofOutcomeV1::Succeeded,
    }
}

struct Fixture {
    production_contract: WorkspaceD1MigrationContractV1,
    atomicity: WorkspaceD1AtomicityQualificationV1,
    canary: WorkspaceD1OldWorkerCanaryV1,
    plans: Vec<StoredPlan>,
    proofs: Vec<StoredProof>,
    worker_plan: StoredPlan,
    worker_proofs: Vec<StoredProof>,
}

#[allow(clippy::too_many_lines)]
fn fixture(store: &StateStore) -> Fixture {
    let migration_sha256 = digest("migration");
    fixture_with_migrations(store, &migration_sha256, &migration_sha256)
}

#[allow(clippy::too_many_lines)]
fn fixture_with_migrations(
    store: &StateStore,
    production_migration_sha256: &str,
    success_migration_sha256: &str,
) -> Fixture {
    let candidate = digest("cfctl-candidate");
    let catalog = digest("catalog");
    let production_contract = migration_contract(production_migration_sha256, true);
    let target = json!({"account_id":ACCOUNT,"database_id":DATABASE});
    let plans = [
        (
            "create_database",
            "d1-create-database",
            PlanStatus::Verified,
        ),
        (
            "success_apply",
            "mln-web.founder-d1-migration-apply",
            PlanStatus::Verified,
        ),
        (
            "ddl_failure_apply",
            "mln-web.founder-d1-migration-apply",
            PlanStatus::RectificationRequired,
        ),
        (
            "ledger_failure_apply",
            "mln-web.founder-d1-migration-apply",
            PlanStatus::RectificationRequired,
        ),
        ("restore", "d1-restore-exact-bookmark", PlanStatus::Verified),
        (
            "delete_database",
            "d1-delete-database",
            PlanStatus::Verified,
        ),
    ]
    .into_iter()
    .map(|(role, capability, status)| {
        stored_plan(
            store,
            role,
            capability,
            &candidate,
            &catalog,
            target.clone(),
            status,
            success_migration_sha256,
        )
    })
    .collect::<Vec<_>>();
    let zero_delta_body = |role: &str, observation: &str| {
        let snapshot = store
            .write_evidence(
                EvidenceClass::LiveRead,
                &json!({"role":role,"observation":observation,"rows":[]}),
            )
            .expect("snapshot evidence");
        json!({
            "schema_version":1,
            "kind":"workspace_d1_zero_delta_observation_v1",
            "observation":observation,
            "before_evidence_hash":snapshot.content_hash,
            "after_evidence_hash":snapshot.content_hash,
        })
    };
    let proofs = [
        ("get_database", "d1-get-database"),
        ("full_export", "d1-full-export"),
        ("bookmark", "d1-time-travel-get-bookmark"),
        ("ddl_zero_schema", "d1-schema-introspection"),
        ("ddl_zero_ledger", "mln-web.founder-d1-migration-apply"),
        ("ledger_zero_schema", "d1-schema-introspection"),
        ("ledger_zero_ledger", "mln-web.founder-d1-migration-apply"),
        ("cleanup_absence", "d1-get-database"),
    ]
    .into_iter()
    .map(|(role, capability)| {
        let input = serde_json::to_value(CallInput {
            selectors: target.clone(),
            query: json!({}),
            ..CallInput::default()
        })
        .expect("D1 proof input");
        let body = match role {
            "ddl_zero_schema" | "ledger_zero_schema" => zero_delta_body(role, "schema"),
            "ddl_zero_ledger" | "ledger_zero_ledger" => zero_delta_body(role, "ledger"),
            _ => json!({"status":200,"success":true,"result":{"id":DATABASE},"errors":[],"result_info":null,"etag":null,"cf_ray":null}),
        };
        stored_proof(
            store,
            role,
            capability,
            &candidate,
            &catalog,
            input,
            body,
        )
    })
    .collect::<Vec<_>>();
    let plan = |role: &str| {
        plans
            .iter()
            .find(|plan| plan.role == role)
            .expect("plan role")
    };
    let proof = |role: &str| {
        proofs
            .iter()
            .find(|proof| proof.role == role)
            .expect("proof role")
    };
    let atomicity = WorkspaceD1AtomicityQualificationV1 {
        schema_version: 1,
        kind: "workspace_d1_provider_atomicity_v1".to_owned(),
        evidence_class: EvidenceClass::PostChangeVerification,
        qualification_id: "11111111-1111-4111-8111-111111111111".to_owned(),
        cfctl_candidate_hash: candidate.clone(),
        repository_head: "a".repeat(40),
        operation_pack_sha256: digest("operation-pack"),
        catalog_hash: catalog.clone(),
        account_id: ACCOUNT.to_owned(),
        profile_id: PROFILE.to_owned(),
        credential_generation_id: GENERATION.to_owned(),
        isolated_database_id: DATABASE.to_owned(),
        isolated_database_identity_hash: hash_value(
            &json!({"account_id":ACCOUNT,"database_id":DATABASE}),
        )
        .expect("database identity"),
        wrangler_version: "4.100.0".to_owned(),
        wrangler_cli_sha256: digest("wrangler"),
        synthetic_migration_sha256: success_migration_sha256.to_owned(),
        create_database_operation_id: plan("create_database").operation_id.clone(),
        create_database_plan_hash: plan("create_database").plan_hash.clone(),
        get_database_proof_hash: proof("get_database").proof_hash.clone(),
        get_database_evidence_hash: proof("get_database").evidence_hash.clone(),
        success_apply_operation_id: plan("success_apply").operation_id.clone(),
        success_apply_plan_hash: plan("success_apply").plan_hash.clone(),
        ddl_failure_apply_operation_id: plan("ddl_failure_apply").operation_id.clone(),
        ddl_failure_apply_plan_hash: plan("ddl_failure_apply").plan_hash.clone(),
        ledger_failure_apply_operation_id: plan("ledger_failure_apply").operation_id.clone(),
        ledger_failure_apply_plan_hash: plan("ledger_failure_apply").plan_hash.clone(),
        full_export_proof_hash: proof("full_export").proof_hash.clone(),
        full_export_evidence_hash: proof("full_export").evidence_hash.clone(),
        bookmark_proof_hash: proof("bookmark").proof_hash.clone(),
        bookmark_evidence_hash: proof("bookmark").evidence_hash.clone(),
        restore_operation_id: plan("restore").operation_id.clone(),
        restore_plan_hash: plan("restore").plan_hash.clone(),
        delete_database_operation_id: plan("delete_database").operation_id.clone(),
        delete_database_plan_hash: plan("delete_database").plan_hash.clone(),
        create_database_evidence_hash: plan("create_database").evidence_hash.clone(),
        restore_evidence_hash: plan("restore").evidence_hash.clone(),
        delete_database_evidence_hash: plan("delete_database").evidence_hash.clone(),
        success_outcome_evidence_hash: plan("success_apply").evidence_hash.clone(),
        ddl_failure_outcome_evidence_hash: plan("ddl_failure_apply").evidence_hash.clone(),
        ddl_failure_zero_schema_proof_hash: proof("ddl_zero_schema").proof_hash.clone(),
        ddl_failure_zero_schema_delta_hash: proof("ddl_zero_schema").evidence_hash.clone(),
        ddl_failure_zero_ledger_proof_hash: proof("ddl_zero_ledger").proof_hash.clone(),
        ddl_failure_zero_ledger_delta_hash: proof("ddl_zero_ledger").evidence_hash.clone(),
        ledger_failure_outcome_evidence_hash: plan("ledger_failure_apply").evidence_hash.clone(),
        ledger_failure_zero_schema_proof_hash: proof("ledger_zero_schema").proof_hash.clone(),
        ledger_failure_zero_schema_delta_hash: proof("ledger_zero_schema").evidence_hash.clone(),
        ledger_failure_zero_ledger_proof_hash: proof("ledger_zero_ledger").proof_hash.clone(),
        ledger_failure_zero_ledger_delta_hash: proof("ledger_zero_ledger").evidence_hash.clone(),
        cleanup_proof_hash: proof("cleanup_absence").proof_hash.clone(),
        cleanup_evidence_hash: proof("cleanup_absence").evidence_hash.clone(),
        success_passed: true,
        ddl_failure_observed: true,
        ddl_failure_zero_schema_delta: true,
        ddl_failure_zero_ledger_delta: true,
        ledger_failure_observed: true,
        ledger_failure_zero_schema_delta: true,
        ledger_failure_zero_ledger_delta: true,
        cleanup_database_absent: true,
        completed_at: Utc::now(),
    };

    let worker_target = json!({"account_id":ACCOUNT,"script_name":"founder-worker"});
    let worker_plan = stored_plan(
        store,
        "worker_deployment",
        "worker-deployment-plan",
        &candidate,
        &catalog,
        worker_target.clone(),
        PlanStatus::Verified,
        success_migration_sha256,
    );
    let worker_proofs = [
        ("deployments", "worker-deployments-list-deployments"),
        ("version", "worker-versions-get-version-detail"),
        ("settings", "worker-script-get-settings"),
    ]
    .into_iter()
    .map(|(role, capability)| {
        let selectors = if role == "version" {
            json!({
                "account_id":ACCOUNT,
                "script_name":"founder-worker",
                "version_id":"66666666-6666-4666-8666-666666666666",
            })
        } else {
            worker_target.clone()
        };
        stored_proof(
            store,
            role,
            capability,
            &candidate,
            &catalog,
            serde_json::to_value(CallInput {
                selectors,
                query: json!({}),
                body: None,
                if_match: None,
                if_none_match: None,
            })
            .expect("Worker input"),
            match role {
                "deployments" => json!({
                    "status":200,"success":true,
                    "result":{"deployments":[{"id":"55555555-5555-4555-8555-555555555555","versions":[{"version_id":"66666666-6666-4666-8666-666666666666","percentage":100.0}]}]},
                    "errors":[],"result_info":null,"etag":null,"cf_ray":null,
                }),
                "version" => json!({
                    "status":200,"success":true,"result":{"id":"66666666-6666-4666-8666-666666666666"},
                    "errors":[],"result_info":null,"etag":null,"cf_ray":null,
                }),
                "settings" => json!({
                    "status":200,"success":true,"result":{"compatibility_date":"2026-08-29"},
                    "errors":[],"result_info":null,"etag":null,"cf_ray":null,
                }),
                _ => unreachable!(),
            },
        )
    })
    .collect::<Vec<_>>();
    let worker_proof = |role: &str| {
        worker_proofs
            .iter()
            .find(|proof| proof.role == role)
            .expect("Worker proof role")
    };
    let mut canary = WorkspaceD1OldWorkerCanaryV1 {
        schema_version: 1,
        kind: "workspace_d1_old_worker_canary_v1".to_owned(),
        evidence_class: EvidenceClass::PostChangeVerification,
        capability_id: "mln-web.founder-d1-migration-apply".to_owned(),
        workspace_contract_sha256: hash_value(
            &serde_json::to_value(&production_contract).expect("workspace contract JSON"),
        )
        .expect("workspace contract"),
        cfctl_candidate_hash: candidate,
        repository_head: "a".repeat(40),
        operation_pack_sha256: digest("operation-pack"),
        catalog_hash: catalog,
        account_id: ACCOUNT.to_owned(),
        profile_id: PROFILE.to_owned(),
        credential_generation_id: GENERATION.to_owned(),
        database_id: DATABASE.to_owned(),
        migration_sha256: production_migration_sha256.to_owned(),
        migration_operation_id: atomicity.success_apply_operation_id.clone(),
        migration_plan_hash: atomicity.success_apply_plan_hash.clone(),
        migration_apply_evidence_hash: atomicity.success_outcome_evidence_hash.clone(),
        worker_script_name: "founder-worker".to_owned(),
        worker_deployment_operation_id: worker_plan.operation_id.clone(),
        worker_deployment_plan_hash: worker_plan.plan_hash.clone(),
        deployments_read_proof_hash: worker_proof("deployments").proof_hash.clone(),
        deployments_read_evidence_hash: worker_proof("deployments").evidence_hash.clone(),
        version_detail_proof_hash: worker_proof("version").proof_hash.clone(),
        version_detail_evidence_hash: worker_proof("version").evidence_hash.clone(),
        settings_proof_hash: worker_proof("settings").proof_hash.clone(),
        settings_evidence_hash: worker_proof("settings").evidence_hash.clone(),
        deployment_id: "55555555-5555-4555-8555-555555555555".to_owned(),
        version_id: "66666666-6666-4666-8666-666666666666".to_owned(),
        request_sha256: digest("request"),
        result_sha256: digest("result"),
        semantic_assertions_sha256: digest("opaque-founder-semantics"),
        declared_evidence_hashes: BTreeMap::from([
            ("diagz_build_after".to_owned(), digest("build-after")),
            ("diagz_build_before".to_owned(), digest("build-before")),
            ("post_state".to_owned(), digest("post-state")),
            ("pre_state".to_owned(), digest("pre-state")),
            ("recovery_bookmark".to_owned(), digest("bookmark")),
            ("schema_ledger".to_owned(), digest("schema-ledger")),
        ]),
        disposition: "pass".to_owned(),
        passed: true,
        observed_at: Utc::now(),
        canary_receipt_sha256: String::new(),
        worker_identity_evidence_sha256: String::new(),
    };
    canary.worker_identity_evidence_sha256 =
        worker_identity_join_hash(&canary).expect("worker join");
    canary.canary_receipt_sha256 =
        hash_value(&serde_json::to_value(&canary).expect("canary JSON")).expect("receipt hash");
    Fixture {
        production_contract,
        atomicity,
        canary,
        plans,
        proofs,
        worker_plan,
        worker_proofs,
    }
}

pub(super) fn producer_fixture() -> (tempfile::TempDir, StateStore, CatalogSnapshot, CallInput) {
    let (root, store) = store();
    let fixture = fixture(&store);
    let plan = |role: &str| {
        fixture
            .plans
            .iter()
            .find(|plan| plan.role == role)
            .expect("plan role")
    };
    let proof = |role: &str| {
        fixture
            .proofs
            .iter()
            .find(|proof| proof.role == role)
            .expect("proof role")
    };
    let worker_proof = |role: &str| {
        fixture
            .worker_proofs
            .iter()
            .find(|proof| proof.role == role)
            .expect("Worker proof role")
    };
    let catalog = CatalogSnapshot {
        schema_version: 2,
        generated_at: Utc::now(),
        source_url: "fixture".to_owned(),
        source_hash: digest("source"),
        schema_hash: fixture.atomicity.catalog_hash.clone(),
        capabilities: BTreeMap::new(),
    };
    let input = CallInput {
        body: Some(json!({
            "schema_version":1,
            "atomicity":{
                "create_database_operation_id":plan("create_database").operation_id,
                "success_apply_operation_id":plan("success_apply").operation_id,
                "ddl_failure_apply_operation_id":plan("ddl_failure_apply").operation_id,
                "ledger_failure_apply_operation_id":plan("ledger_failure_apply").operation_id,
                "restore_operation_id":plan("restore").operation_id,
                "delete_database_operation_id":plan("delete_database").operation_id,
                "get_database_proof_hash":proof("get_database").proof_hash,
                "full_export_proof_hash":proof("full_export").proof_hash,
                "bookmark_proof_hash":proof("bookmark").proof_hash,
                "ddl_failure_zero_schema_proof_hash":proof("ddl_zero_schema").proof_hash,
                "ddl_failure_zero_ledger_proof_hash":proof("ddl_zero_ledger").proof_hash,
                "ledger_failure_zero_schema_proof_hash":proof("ledger_zero_schema").proof_hash,
                "ledger_failure_zero_ledger_proof_hash":proof("ledger_zero_ledger").proof_hash,
                "cleanup_proof_hash":proof("cleanup_absence").proof_hash,
            },
            "old_worker_canary":{
                "worker_deployment_operation_id":fixture.worker_plan.operation_id,
                "deployments_read_proof_hash":worker_proof("deployments").proof_hash,
                "version_detail_proof_hash":worker_proof("version").proof_hash,
                "settings_proof_hash":worker_proof("settings").proof_hash,
                "request_sha256":fixture.canary.request_sha256,
                "result_sha256":fixture.canary.result_sha256,
                "semantic_assertions_sha256":fixture.canary.semantic_assertions_sha256,
                "declared_evidence_hashes":fixture.canary.declared_evidence_hashes,
                "disposition":"pass"
            }
        })),
        ..CallInput::default()
    };
    (root, store, catalog, input)
}

fn atomicity_expected<'a>(
    fixture: &'a Fixture,
    plans: &'a [PlanExpectation<'a>],
    proofs: &'a [ProofExpectation<'a>],
) -> AtomicityExpectations<'a> {
    let r = &fixture.atomicity;
    AtomicityExpectations {
        cfctl_candidate_hash: &r.cfctl_candidate_hash,
        repository_head: &r.repository_head,
        operation_pack_sha256: &r.operation_pack_sha256,
        catalog_hash: &r.catalog_hash,
        account_id: &r.account_id,
        profile_id: &r.profile_id,
        credential_generation_id: &r.credential_generation_id,
        wrangler_version: &r.wrangler_version,
        wrangler_cli_sha256: &r.wrangler_cli_sha256,
        synthetic_migration_sha256: &r.synthetic_migration_sha256,
        plans,
        proofs,
    }
}

fn canary_expected<'a>(
    fixture: &'a Fixture,
    proofs: &'a [ProofExpectation<'a>],
) -> CanaryExpectations<'a> {
    let r = &fixture.canary;
    CanaryExpectations {
        capability_id: &r.capability_id,
        workspace_contract_sha256: &r.workspace_contract_sha256,
        cfctl_candidate_hash: &r.cfctl_candidate_hash,
        repository_head: &r.repository_head,
        operation_pack_sha256: &r.operation_pack_sha256,
        catalog_hash: &r.catalog_hash,
        account_id: &r.account_id,
        profile_id: &r.profile_id,
        credential_generation_id: &r.credential_generation_id,
        database_id: &r.database_id,
        migration_sha256: &r.migration_sha256,
        migration_operation_id: &r.migration_operation_id,
        migration_plan_hash: &r.migration_plan_hash,
        migration_apply_evidence_hash: &r.migration_apply_evidence_hash,
        worker_script_name: &r.worker_script_name,
        deployment_id: &r.deployment_id,
        version_id: &r.version_id,
        worker_plan: plan_expectation(&fixture.worker_plan),
        worker_proofs: proofs,
    }
}

fn outer<T: serde::Serialize>(store: &StateStore, value: &T) -> EvidenceV1 {
    store
        .write_evidence(
            EvidenceClass::PostChangeVerification,
            &serde_json::to_value(value).expect("JSON"),
        )
        .expect("outer evidence")
}

fn qualification_hashes(plan: &PlanV1) -> BTreeMap<String, String> {
    [
        ATOMICITY_QUALIFICATION_PRECONDITION,
        OLD_WORKER_CANARY_PRECONDITION,
        WORKER_DEPLOYMENTS_PRECONDITION,
        WORKER_VERSION_PRECONDITION,
        WORKER_SETTINGS_PRECONDITION,
        WORKER_DEPLOYMENT_PLAN_PRECONDITION,
    ]
    .into_iter()
    .filter_map(|name| {
        plan.precondition_hashes
            .get(name)
            .map(|hash| (name.to_owned(), hash.clone()))
    })
    .collect()
}

fn store_execution_plan_with_observations(
    store: &StateStore,
    fixture: &Fixture,
    mut plan: PlanV1,
    resource_observation_hashes: BTreeMap<String, String>,
) -> PlanV1 {
    plan.refresh_hash().expect("refresh execution plan");
    let plan_v2 = PlanV2::new(
        plan.clone(),
        PlanPinsV2 {
            build_identity_hash: fixture.atomicity.cfctl_candidate_hash.clone(),
            catalog_hash: fixture.atomicity.catalog_hash.clone(),
            credential_generation_id: GENERATION.to_owned(),
            admission_policy_hash: digest("execution-policy"),
            authority_hash: None,
            workspace_graph_hash: digest("execution-workspace"),
            resource_observation_hashes,
            cost_budget: None,
        },
    )
    .expect("execution PlanV2");
    store
        .save_plan_v2(&plan_v2)
        .expect("store execution PlanV2");
    plan
}

fn store_execution_plan(store: &StateStore, fixture: &Fixture, plan: PlanV1) -> PlanV1 {
    let resource_observation_hashes = qualification_hashes(&plan);
    store_execution_plan_with_observations(store, fixture, plan, resource_observation_hashes)
}

fn bound_execution_plan_draft(store: &StateStore, fixture: &Fixture) -> PlanV1 {
    let plans = fixture
        .plans
        .iter()
        .map(plan_expectation)
        .collect::<Vec<_>>();
    let proofs = fixture
        .proofs
        .iter()
        .map(proof_expectation)
        .collect::<Vec<_>>();
    let worker_proofs = fixture
        .worker_proofs
        .iter()
        .map(proof_expectation)
        .collect::<Vec<_>>();
    let joins = validate_qualification_pair(
        store,
        &outer(store, &fixture.atomicity),
        &outer(store, &fixture.canary),
        &atomicity_expected(fixture, &plans, &proofs),
        &canary_expected(fixture, &worker_proofs),
        Utc::now(),
    )
    .expect("qualification pair");
    let mut capability = CapabilityV1::new(
        "mln-web.founder-d1-migration-apply",
        "fixture",
        "POST",
        "/fixture",
    );
    capability.workspace_d1_migration = Some(fixture.production_contract.clone());
    let mut plan = PlanV1::draft(
        PROFILE,
        ACCOUNT,
        &fixture.atomicity.catalog_hash,
        capability,
        json!({
            "adapter": {
                "workspace_d1_migration": {
                    "repository_head": fixture.atomicity.repository_head,
                    "operation_pack_sha256": fixture.atomicity.operation_pack_sha256,
                    "wrangler_version": fixture.atomicity.wrangler_version,
                    "wrangler_cli_sha256": fixture.atomicity.wrangler_cli_sha256,
                    "evidence_joins": joins.clone(),
                }
            }
        }),
    )
    .expect("plan");
    bind_plan_evidence_hashes(
        &mut plan,
        &json!({"workspace_d1_migration":{"evidence_joins":joins}}),
    )
    .expect("joins");
    plan.input = serde_json::to_value(CallInput::default()).expect("execution input");
    plan
}

fn bound_execution_plan(store: &StateStore, fixture: &Fixture) -> PlanV1 {
    store_execution_plan(store, fixture, bound_execution_plan_draft(store, fixture))
}

fn plan_with_canary_mutation(
    store: &StateStore,
    fixture: &Fixture,
    mutate: impl FnOnce(&mut WorkspaceD1OldWorkerCanaryV1),
) -> PlanV1 {
    let mut plan = bound_execution_plan_draft(store, fixture);
    let mut canary = fixture.canary.clone();
    mutate(&mut canary);
    canary.worker_identity_evidence_sha256 =
        worker_identity_join_hash(&canary).expect("worker identity hash");
    canary.canary_receipt_sha256.clear();
    canary.canary_receipt_sha256 =
        hash_value(&serde_json::to_value(&canary).expect("canary JSON")).expect("canary hash");
    let canary_hash = outer(store, &canary).content_hash;
    plan.precondition_hashes.insert(
        OLD_WORKER_CANARY_PRECONDITION.to_owned(),
        canary_hash.clone(),
    );
    plan.targets
        .pointer_mut(
            "/adapter/workspace_d1_migration/evidence_joins/old_worker_canary_evidence_hash",
        )
        .expect("canary target join")
        .clone_from(&json!(canary_hash));
    store_execution_plan(store, fixture, plan)
}

fn plan_with_atomicity_mutation(
    store: &StateStore,
    fixture: &Fixture,
    mutate: impl FnOnce(&mut WorkspaceD1AtomicityQualificationV1),
) -> PlanV1 {
    let mut plan = bound_execution_plan_draft(store, fixture);
    let mut atomicity = fixture.atomicity.clone();
    mutate(&mut atomicity);
    atomicity.isolated_database_identity_hash = hash_value(&json!({
        "account_id": atomicity.account_id,
        "database_id": atomicity.isolated_database_id,
    }))
    .expect("isolated identity hash");
    let atomicity_hash = outer(store, &atomicity).content_hash;
    plan.precondition_hashes.insert(
        ATOMICITY_QUALIFICATION_PRECONDITION.to_owned(),
        atomicity_hash.clone(),
    );
    plan.targets
        .pointer_mut(
            "/adapter/workspace_d1_migration/evidence_joins/atomicity_qualification_evidence_hash",
        )
        .expect("atomicity target join")
        .clone_from(&json!(atomicity_hash));
    store_execution_plan(store, fixture, plan)
}

fn rejects_execution(store: &StateStore, plan: &PlanV1) {
    assert!(current_plan_evidence_hashes(store, plan, Utc::now()).is_err());
}

#[test]
fn full_export_proof_without_governed_execution_provenance_is_rejected() {
    let (_root, store) = store();
    let evidence = store
        .write_evidence(
            EvidenceClass::LiveRead,
            &json!({"status":200,"success":true}),
        )
        .expect("live-read evidence");
    let mut proof = OperationalProofV1::new(
        Utc::now(),
        "d1-full-export",
        &digest("catalog"),
        &digest("request"),
        OperationalProofScopeV1::new(Some(PROFILE), Some(ACCOUNT), Some(GENERATION)),
        OperationalProofOutcomeV1::Succeeded,
        evidence,
    );
    proof
        .bind_build_identity_hash(&digest("cfctl-candidate"))
        .expect("build identity");

    assert!(matches!(
        store.record_operational_proof(&proof),
        Err(StorageError::InvalidOperationalProof(message))
            if message == "D1 full-export operational proof requires governed-execution provenance"
    ));
}

#[test]
fn qualification_resolves_children_before_binding_six_joins() {
    let (_root, store) = store();
    let fixture = fixture(&store);
    let plans = fixture
        .plans
        .iter()
        .map(plan_expectation)
        .collect::<Vec<_>>();
    let proofs = fixture
        .proofs
        .iter()
        .map(proof_expectation)
        .collect::<Vec<_>>();
    let before_completion = Utc::now();
    let mut future_completion = fixture.atomicity.clone();
    future_completion.completed_at = before_completion + Duration::seconds(1);
    assert!(matches!(
        validate_atomicity_qualification(
            &store,
            &outer(&store, &future_completion),
            &atomicity_expected(&fixture, &plans, &proofs),
            before_completion,
        ),
        Err(CliError::Input(message))
            if message
                == "workspace D1 atomicity qualification is incomplete, stale, or identity-drifted"
    ));
    let plan = bound_execution_plan(&store, &fixture);
    assert_eq!(plan.precondition_hashes.len(), 6);
    current_plan_evidence_hashes(&store, &plan, Utc::now())
        .expect("unchanged qualified plan preconditions");
}

#[test]
fn execution_rejects_authenticated_success_child_with_different_migration() {
    let (_root, store) = store();
    let production = digest("production-migration");
    let synthetic = digest("synthetic-migration");
    let fixture = fixture_with_migrations(&store, &production, &synthetic);
    let plan = bound_execution_plan(&store, &fixture);

    rejects_execution(&store, &plan);
}

#[test]
fn qualification_join_names_are_the_literal_closed_six() {
    assert_eq!(
        EVIDENCE_JOIN_PRECONDITIONS,
        [
            "workspace_d1_atomicity_qualification",
            "workspace_d1_old_worker_canary",
            "workspace_d1_worker_deployments",
            "workspace_d1_worker_version",
            "workspace_d1_worker_settings",
            "workspace_d1_worker_deployment_plan",
        ]
    );
}

#[test]
fn qualification_and_planning_reject_duplicate_evidence_identities_early() {
    let (_root, store) = store();
    let fixture = fixture(&store);
    let mut canary = fixture.canary.clone();
    canary.settings_evidence_hash = canary.version_detail_evidence_hash.clone();
    assert!(
        evidence_joins(
            &outer(&store, &fixture.atomicity),
            &outer(&store, &canary),
            &canary,
        )
        .is_err()
    );

    let mut plan = bound_execution_plan_draft(&store, &fixture);
    let mut target = plan
        .targets
        .pointer("/adapter")
        .expect("adapter target")
        .clone();
    target["workspace_d1_migration"]["evidence_joins"]["worker_settings_evidence_hash"] =
        target["workspace_d1_migration"]["evidence_joins"]["worker_version_evidence_hash"].clone();
    assert!(bind_plan_evidence_hashes(&mut plan, &target).is_err());
}

#[test]
fn qualification_namespace_is_closed_while_unrelated_shared_keys_are_allowed() {
    {
        let (_root, store) = store();
        let fixture = fixture(&store);
        let mut plan = bound_execution_plan_draft(&store, &fixture);
        plan.precondition_hashes.insert(
            "workspace_d1_unexpected_qualification_join".to_owned(),
            digest("unknown-plan-key"),
        );
        let plan = store_execution_plan(&store, &fixture, plan);
        rejects_execution(&store, &plan);
    }
    {
        let (_root, store) = store();
        let fixture = fixture(&store);
        let plan = bound_execution_plan_draft(&store, &fixture);
        let mut observations = qualification_hashes(&plan);
        observations.insert(
            "workspace_d1_unexpected_qualification_join".to_owned(),
            digest("unknown-pin-key"),
        );
        let plan = store_execution_plan_with_observations(&store, &fixture, plan, observations);
        rejects_execution(&store, &plan);
    }
    {
        let (_root, store) = store();
        let fixture = fixture(&store);
        let mut plan = bound_execution_plan_draft(&store, &fixture);
        plan.targets
            .pointer_mut("/adapter/workspace_d1_migration/evidence_joins")
            .and_then(Value::as_object_mut)
            .expect("evidence join target")
            .insert(
                "unexpected_join".to_owned(),
                json!(digest("unknown-target-key")),
            );
        let plan = store_execution_plan(&store, &fixture, plan);
        rejects_execution(&store, &plan);
    }
    {
        let (_root, store) = store();
        let mut plan = PlanV1::draft(
            PROFILE,
            ACCOUNT,
            &digest("non-manifest-catalog"),
            CapabilityV1::new("fixture-read", "fixture", "GET", "/fixture"),
            json!({}),
        )
        .expect("non-manifest plan");
        plan.precondition_hashes.insert(
            "workspace_d1_unexpected_qualification_join".to_owned(),
            digest("unknown-only-non-manifest"),
        );
        assert!(current_plan_evidence_hashes(&store, &plan, Utc::now()).is_err());
    }
    {
        let (_root, store) = store();
        let fixture = fixture(&store);
        let mut plan = bound_execution_plan_draft(&store, &fixture);
        plan.precondition_hashes.insert(
            "source_artifact:/repo/reviewed.sql".to_owned(),
            digest("unrelated-source-artifact"),
        );
        let mut observations = qualification_hashes(&plan);
        observations.insert(
            "source_artifact:/repo/reviewed.sql".to_owned(),
            digest("unrelated-source-artifact"),
        );
        let plan = store_execution_plan_with_observations(&store, &fixture, plan, observations);
        current_plan_evidence_hashes(&store, &plan, Utc::now())
            .expect("unrelated shared-map keys remain permitted");
    }
}

#[test]
fn coherent_all_three_invalid_join_sets_fail_closed() {
    for invalid in [
        format!("sha256:{}", "A".repeat(64)),
        digest("coherent-duplicate-placeholder"),
    ] {
        let (_root, store) = store();
        let fixture = fixture(&store);
        let mut plan = bound_execution_plan_draft(&store, &fixture);
        let value = if invalid == digest("coherent-duplicate-placeholder") {
            plan.precondition_hashes[WORKER_VERSION_PRECONDITION].clone()
        } else {
            invalid
        };
        plan.precondition_hashes
            .insert(WORKER_SETTINGS_PRECONDITION.to_owned(), value.clone());
        plan.targets
            .pointer_mut(
                "/adapter/workspace_d1_migration/evidence_joins/worker_settings_evidence_hash",
            )
            .expect("settings target join")
            .clone_from(&json!(value));
        let observations = qualification_hashes(&plan);
        let plan = store_execution_plan_with_observations(&store, &fixture, plan, observations);
        rejects_execution(&store, &plan);
    }
}

#[test]
fn every_plan_join_name_is_required_and_individually_bound() {
    for name in EVIDENCE_JOIN_PRECONDITIONS {
        {
            let (_root, store) = store();
            let fixture = fixture(&store);
            let mut plan = bound_execution_plan_draft(&store, &fixture);
            let observations = qualification_hashes(&plan);
            plan.precondition_hashes.remove(name);
            let plan = store_execution_plan_with_observations(&store, &fixture, plan, observations);
            rejects_execution(&store, &plan);
        }
        {
            let (_root, store) = store();
            let fixture = fixture(&store);
            let mut plan = bound_execution_plan_draft(&store, &fixture);
            let observations = qualification_hashes(&plan);
            plan.precondition_hashes
                .insert(name.to_owned(), digest(&format!("mismatch:{name}")));
            let plan = store_execution_plan_with_observations(&store, &fixture, plan, observations);
            rejects_execution(&store, &plan);
        }
    }
}

#[test]
fn execution_rejects_target_precondition_and_pin_join_disagreement() {
    {
        let (_root, store) = store();
        let fixture = fixture(&store);
        let mut plan = bound_execution_plan_draft(&store, &fixture);
        plan.targets
            .pointer_mut(
                "/adapter/workspace_d1_migration/evidence_joins/worker_settings_evidence_hash",
            )
            .expect("settings target join")
            .clone_from(&json!(digest("target-only-settings")));
        let plan = store_execution_plan(&store, &fixture, plan);
        rejects_execution(&store, &plan);
    }
    {
        let (_root, store) = store();
        let fixture = fixture(&store);
        let mut plan = bound_execution_plan_draft(&store, &fixture);
        let original_observations = qualification_hashes(&plan);
        let mut canary = fixture.canary.clone();
        canary.observed_at += Duration::milliseconds(1);
        canary.canary_receipt_sha256.clear();
        canary.canary_receipt_sha256 =
            hash_value(&serde_json::to_value(&canary).expect("canary JSON")).expect("canary hash");
        plan.precondition_hashes.insert(
            OLD_WORKER_CANARY_PRECONDITION.to_owned(),
            outer(&store, &canary).content_hash,
        );
        let plan =
            store_execution_plan_with_observations(&store, &fixture, plan, original_observations);
        rejects_execution(&store, &plan);
    }
    {
        let (_root, store) = store();
        let fixture = fixture(&store);
        let plan = bound_execution_plan_draft(&store, &fixture);
        let mut observations = qualification_hashes(&plan);
        observations.insert(
            WORKER_SETTINGS_PRECONDITION.to_owned(),
            digest("pin-only-settings"),
        );
        let plan = store_execution_plan_with_observations(&store, &fixture, plan, observations);
        rejects_execution(&store, &plan);
    }
}

#[test]
fn coherently_rehashed_receipt_cannot_supply_its_own_contract_expectations() {
    {
        let (_root, store) = store();
        let fixture = fixture(&store);
        let plan = plan_with_canary_mutation(&store, &fixture, |canary| {
            canary.workspace_contract_sha256 = digest("substituted-workspace-contract");
        });
        rejects_execution(&store, &plan);
    }
    {
        let (_root, store) = store();
        let fixture = fixture(&store);
        let plan = plan_with_canary_mutation(&store, &fixture, |canary| {
            canary.migration_sha256 = digest("substituted-production-migration");
        });
        rejects_execution(&store, &plan);
    }
    {
        let (_root, store) = store();
        let fixture = fixture(&store);
        let plan = plan_with_atomicity_mutation(&store, &fixture, |atomicity| {
            atomicity.synthetic_migration_sha256 = digest("substituted-synthetic-migration");
        });
        rejects_execution(&store, &plan);
    }
}

#[test]
fn execution_rejects_body_only_qualification_without_durable_descriptor() {
    let (_root, store) = store();
    let fixture = fixture(&store);
    let plan = bound_execution_plan(&store, &fixture);
    let hash = &plan.precondition_hashes[ATOMICITY_QUALIFICATION_PRECONDITION];
    let evidence = store.load_evidence(hash).expect("durable descriptor");
    let body = std::path::Path::new(&evidence.path);
    let digest = body
        .file_stem()
        .and_then(std::ffi::OsStr::to_str)
        .expect("digest filename");
    let descriptor = store
        .paths()
        .data_dir
        .join("evidence-descriptors")
        .join(format!("{digest}.json"));
    fs::remove_file(descriptor).expect("remove descriptor fixture");

    rejects_execution(&store, &plan);
    assert!(store.read_audit_evidence_value(hash).is_ok());
    assert!(store.read_evidence_value(hash).is_err());
    assert!(store.load_evidence(hash).is_err());
}

#[test]
fn execution_rejects_incomplete_stale_and_cross_identity_qualification_joins() {
    {
        let (_root, store) = store();
        let fixture = fixture(&store);
        let mut plan = bound_execution_plan_draft(&store, &fixture);
        plan.precondition_hashes
            .remove(WORKER_SETTINGS_PRECONDITION);
        let plan = store_execution_plan(&store, &fixture, plan);
        rejects_execution(&store, &plan);
    }
    {
        let (_root, store) = store();
        let fixture = fixture(&store);
        let mut plan = bound_execution_plan_draft(&store, &fixture);
        let substituted = plan.precondition_hashes[WORKER_VERSION_PRECONDITION].clone();
        plan.precondition_hashes
            .insert(WORKER_DEPLOYMENTS_PRECONDITION.to_owned(), substituted);
        let plan = store_execution_plan(&store, &fixture, plan);
        rejects_execution(&store, &plan);
    }
    for mutate in [
        ("stale", ""),
        ("cross_account", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        ("cross_database", "44444444-4444-4444-8444-444444444444"),
        ("cross_operation", "55555555-5555-4555-8555-555555555555"),
        ("cross_worker", "other-worker"),
    ] {
        let (_root, store) = store();
        let fixture = fixture(&store);
        let plan = plan_with_canary_mutation(&store, &fixture, |canary| match mutate.0 {
            "stale" => canary.observed_at = Utc::now() - Duration::minutes(16),
            "cross_account" => canary.account_id = mutate.1.to_owned(),
            "cross_database" => canary.database_id = mutate.1.to_owned(),
            "cross_operation" => canary.migration_operation_id = mutate.1.to_owned(),
            "cross_worker" => canary.worker_script_name = mutate.1.to_owned(),
            _ => unreachable!(),
        });
        rejects_execution(&store, &plan);
    }
    {
        let (_root, store) = store();
        let fixture = fixture(&store);
        let plan = plan_with_atomicity_mutation(&store, &fixture, |atomicity| {
            atomicity.isolated_database_id = "44444444-4444-4444-8444-444444444444".to_owned();
        });
        rejects_execution(&store, &plan);
    }
}

#[test]
fn recomputed_cross_worker_and_cross_child_substitutions_fail() {
    let (_root, store) = store();
    let now = Utc::now();
    let fixture = fixture(&store);
    let plans = fixture
        .plans
        .iter()
        .map(plan_expectation)
        .collect::<Vec<_>>();
    let proofs = fixture
        .proofs
        .iter()
        .map(proof_expectation)
        .collect::<Vec<_>>();
    let worker_proofs = fixture
        .worker_proofs
        .iter()
        .map(proof_expectation)
        .collect::<Vec<_>>();
    let mut cross_worker = fixture.canary.clone();
    cross_worker.deployments_read_proof_hash = digest("other-worker-proof");
    cross_worker.deployments_read_evidence_hash = digest("other-worker-evidence");
    cross_worker.worker_identity_evidence_sha256 =
        worker_identity_join_hash(&cross_worker).expect("join");
    cross_worker.canary_receipt_sha256.clear();
    cross_worker.canary_receipt_sha256 =
        hash_value(&serde_json::to_value(&cross_worker).expect("JSON")).expect("hash");
    assert!(
        validate_old_worker_canary(
            &store,
            &outer(&store, &cross_worker),
            &canary_expected(&fixture, &worker_proofs),
            now + Duration::seconds(1)
        )
        .is_err()
    );

    let mut cross_child = fixture.atomicity.clone();
    std::mem::swap(
        &mut cross_child.ddl_failure_apply_operation_id,
        &mut cross_child.ledger_failure_apply_operation_id,
    );
    assert!(
        validate_atomicity_qualification(
            &store,
            &outer(&store, &cross_child),
            &atomicity_expected(&fixture, &plans, &proofs),
            now + Duration::seconds(1)
        )
        .is_err()
    );
}

#[test]
fn recomputed_worker_body_and_zero_delta_semantic_substitutions_fail() {
    let (_root, store) = store();
    let now = Utc::now();
    let fixture = fixture(&store);
    let bad_worker = stored_proof(
        &store,
        "deployments",
        "worker-deployments-list-deployments",
        &fixture.canary.cfctl_candidate_hash,
        &fixture.canary.catalog_hash,
        serde_json::to_value(CallInput {
            selectors: json!({"account_id":ACCOUNT,"script_name":"founder-worker"}),
            query: json!({}),
            body: None,
            if_match: None,
            if_none_match: None,
        })
        .expect("input"),
        json!({
            "status":200,"success":true,
            "result":{"deployments":[{"id":"77777777-7777-4777-8777-777777777777","versions":[{"version_id":"66666666-6666-4666-8666-666666666666","percentage":100.0}]}]},
            "errors":[],"result_info":null,"etag":null,"cf_ray":null,
        }),
    );
    let worker_expectations = fixture
        .worker_proofs
        .iter()
        .map(|proof| {
            if proof.role == "deployments" {
                proof_expectation(&bad_worker)
            } else {
                proof_expectation(proof)
            }
        })
        .collect::<Vec<_>>();
    let mut canary = fixture.canary.clone();
    canary.deployments_read_proof_hash = bad_worker.proof_hash.clone();
    canary.deployments_read_evidence_hash = bad_worker.evidence_hash.clone();
    canary.worker_identity_evidence_sha256 = worker_identity_join_hash(&canary).expect("join");
    canary.canary_receipt_sha256.clear();
    canary.canary_receipt_sha256 =
        hash_value(&serde_json::to_value(&canary).expect("JSON")).expect("hash");
    assert!(
        validate_old_worker_canary(
            &store,
            &outer(&store, &canary),
            &canary_expected(&fixture, &worker_expectations),
            now + Duration::seconds(1),
        )
        .is_err()
    );

    let before = store
        .write_evidence(EvidenceClass::LiveRead, &json!({"rows":[]}))
        .expect("before");
    let after = store
        .write_evidence(
            EvidenceClass::LiveRead,
            &json!({"rows":[{"name":"smuggled"}]}),
        )
        .expect("after");
    let bad_delta = stored_proof(
        &store,
        "ddl_zero_schema",
        "d1-schema-introspection",
        &fixture.atomicity.cfctl_candidate_hash,
        &fixture.atomicity.catalog_hash,
        json!({"account_id":ACCOUNT,"database_id":DATABASE}),
        json!({
            "schema_version":1,"kind":"workspace_d1_zero_delta_observation_v1",
            "observation":"schema","before_evidence_hash":before.content_hash,
            "after_evidence_hash":after.content_hash,
        }),
    );
    let proof_expectations = fixture
        .proofs
        .iter()
        .map(|proof| {
            if proof.role == "ddl_zero_schema" {
                proof_expectation(&bad_delta)
            } else {
                proof_expectation(proof)
            }
        })
        .collect::<Vec<_>>();
    let plans = fixture
        .plans
        .iter()
        .map(plan_expectation)
        .collect::<Vec<_>>();
    let mut atomicity = fixture.atomicity.clone();
    atomicity.ddl_failure_zero_schema_proof_hash = bad_delta.proof_hash.clone();
    atomicity.ddl_failure_zero_schema_delta_hash = bad_delta.evidence_hash.clone();
    assert!(
        validate_atomicity_qualification(
            &store,
            &outer(&store, &atomicity),
            &atomicity_expected(&fixture, &plans, &proof_expectations),
            now + Duration::seconds(1),
        )
        .is_err()
    );
}

#[test]
fn canary_retains_only_semantic_hash_and_exact_six_names() {
    let (_root, store) = store();
    let now = Utc::now();
    let fixture = fixture(&store);
    let worker_proofs = fixture
        .worker_proofs
        .iter()
        .map(proof_expectation)
        .collect::<Vec<_>>();
    assert!(
        serde_json::to_value(&fixture.canary)
            .expect("JSON")
            .get("semantic_assertions")
            .is_none()
    );
    for extra in [false, true] {
        let mut changed = fixture.canary.clone();
        if extra {
            changed
                .declared_evidence_hashes
                .insert("alias".to_owned(), digest("alias"));
        } else {
            changed.declared_evidence_hashes.remove("schema_ledger");
        }
        changed.canary_receipt_sha256.clear();
        changed.canary_receipt_sha256 =
            hash_value(&serde_json::to_value(&changed).expect("JSON")).expect("hash");
        assert!(
            validate_old_worker_canary(
                &store,
                &outer(&store, &changed),
                &canary_expected(&fixture, &worker_proofs),
                now + Duration::seconds(1)
            )
            .is_err()
        );
    }
}

#[test]
fn wrong_class_candidate_scope_disposition_and_raw_semantics_fail_closed() {
    let (_root, store) = store();
    let now = Utc::now();
    let fixture = fixture(&store);
    let mut plans = fixture
        .plans
        .iter()
        .map(plan_expectation)
        .collect::<Vec<_>>();
    let mut proofs = fixture
        .proofs
        .iter()
        .map(proof_expectation)
        .collect::<Vec<_>>();
    let worker_proofs = fixture
        .worker_proofs
        .iter()
        .map(proof_expectation)
        .collect::<Vec<_>>();

    let mut wrong_class = outer(&store, &fixture.atomicity);
    wrong_class.class = EvidenceClass::LiveRead;
    assert!(
        validate_atomicity_qualification(
            &store,
            &wrong_class,
            &atomicity_expected(&fixture, &plans, &proofs),
            now + Duration::seconds(1),
        )
        .is_err()
    );

    plans[0].expected_status = PlanStatus::RectificationRequired;
    assert!(
        validate_atomicity_qualification(
            &store,
            &outer(&store, &fixture.atomicity),
            &atomicity_expected(&fixture, &plans, &proofs),
            now + Duration::seconds(1),
        )
        .is_err()
    );
    plans[0].expected_status = PlanStatus::Verified;
    proofs[0].expected_outcome = OperationalProofOutcomeV1::Failed;
    assert!(
        validate_atomicity_qualification(
            &store,
            &outer(&store, &fixture.atomicity),
            &atomicity_expected(&fixture, &plans, &proofs),
            now + Duration::seconds(1),
        )
        .is_err()
    );

    let mut cross_scope = fixture.canary.clone();
    cross_scope.account_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned();
    cross_scope.canary_receipt_sha256.clear();
    cross_scope.canary_receipt_sha256 =
        hash_value(&serde_json::to_value(&cross_scope).expect("JSON")).expect("hash");
    assert!(
        validate_old_worker_canary(
            &store,
            &outer(&store, &cross_scope),
            &canary_expected(&fixture, &worker_proofs),
            now + Duration::seconds(1),
        )
        .is_err()
    );

    let mut raw = serde_json::to_value(&fixture.canary).expect("canary JSON");
    raw["semantic_assertions"] = json!({"must_not":"be retained"});
    let raw_evidence = store
        .write_evidence(EvidenceClass::PostChangeVerification, &raw)
        .expect("raw evidence");
    assert!(
        validate_old_worker_canary(
            &store,
            &raw_evidence,
            &canary_expected(&fixture, &worker_proofs),
            now + Duration::seconds(1),
        )
        .is_err()
    );
}
