#![allow(
    clippy::assigning_clones,
    reason = "test fixture mutations remain explicit"
)]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::wildcard_imports)]
use super::*;
use cfctl_core::{EvidenceV1, OperationalProofScopeV1};

fn reference() -> ProofRef {
    ProofRef {
        proof_hash: format!("sha256:{}", "a".repeat(64)),
        evidence_hash: format!("sha256:{}", "b".repeat(64)),
    }
}
fn scope() -> Scope<'static> {
    Scope {
        account: "account",
        profile: "profile",
        generation: "generation",
        catalog: "catalog",
        build: "build",
    }
}

#[test]
fn v3_native_read_rejects_wrong_scope_failed_local_future_and_substituted_evidence() {
    let now = Utc::now();
    let reference = reference();
    let mut proof = OperationalProofV1::new(
        now,
        "d1-full-export",
        "catalog",
        "input",
        OperationalProofScopeV1::new(Some("profile"), Some("account"), Some("generation")),
        OperationalProofOutcomeV1::Succeeded,
        EvidenceV1::new(EvidenceClass::LiveRead, &reference.evidence_hash, "ignored"),
    );
    proof.build_identity_hash = Some("build".to_owned());
    proof.observed_at = now - Duration::seconds(1);
    proof.evidence.generated_at = proof.observed_at;
    assert!(validate_read(&proof, &reference, &scope(), now).is_ok());
    let mut wrong = proof.clone();
    wrong.outcome = OperationalProofOutcomeV1::Failed;
    assert!(validate_read(&wrong, &reference, &scope(), now).is_err());
    let mut wrong = proof.clone();
    wrong.account_id = Some("other".to_owned());
    assert!(validate_read(&wrong, &reference, &scope(), now).is_err());
    let mut wrong = proof.clone();
    wrong.evidence.class = EvidenceClass::LocalProof;
    assert!(validate_read(&wrong, &reference, &scope(), now).is_err());
    let mut wrong = proof.clone();
    wrong.observed_at = now + Duration::seconds(1);
    assert!(validate_read(&wrong, &reference, &scope(), now).is_err());
    let mut wrong = proof;
    wrong.evidence.content_hash = reference.proof_hash.clone();
    assert!(validate_read(&wrong, &reference, &scope(), now).is_err());
}

#[test]
fn v3_runtime_cannot_deserialize_caller_success_in_place_of_required_receipts() {
    assert!(
        serde_json::from_value::<RuntimeBinding>(
            serde_json::json!({"schema_version":3,"success":true})
        )
        .is_err()
    );
}

fn compiled() -> Compiled {
    use cfctl_core::workspace_d1::transition::{Assertions, Declaration, Source, Step, Target};
    let source = Source {
        path: "source.sql".to_owned(),
        sha256: format!("sha256:{}", "a".repeat(64)),
        git_blob_oid: "a".repeat(40),
    };
    let target = Target {
        sequence: 174,
        file: "0174.sql".to_owned(),
        source: source.clone(),
    };
    Compiled {
        declaration: Declaration {
            id: "fixture".to_owned(),
            title: "fixture".to_owned(),
            description: "fixture".to_owned(),
            manifest: source.clone(),
            historical_ledger: source.clone(),
            config_template: "wrangler.toml".to_owned(),
            account_id: "account".to_owned(),
            profile_id: "profile".to_owned(),
            database_id: "database".to_owned(),
            database_binding: "DB".to_owned(),
            migrations_dir: "sql".to_owned(),
            target: target.clone(),
            transition_schedule: vec![
                Step {
                    sequence: 172,
                    phase: Phase::PreDeploy,
                    required_completed_transition_sequences: vec![],
                    deferred_sequences: vec![],
                },
                Step {
                    sequence: 174,
                    phase: Phase::PostDeploy,
                    required_completed_transition_sequences: vec![172],
                    deferred_sequences: vec![],
                },
            ],
            assertions: Assertions {
                preconditions: source.clone(),
                capture: source.clone(),
                preservation: source.clone(),
                cleanup: source,
            },
        },
        compiler_id: "workspace-d1-envelope-v3.1".to_owned(),
        envelope_sha256: format!("sha256:{}", "d".repeat(64)),
        envelope_length: 1,
        segments: vec![],
        historical_sequences: vec![],
        scheduled_targets: vec![target],
    }
}
fn contract() -> WorkspaceD1MigrationContractV1 {
    WorkspaceD1MigrationContractV1 {
        repository_root: "absent".to_owned(),
        repository_head: "a".repeat(40),
        repository_origin: "https://example.com/source.git".to_owned(),
        operation_pack_path: ".cfctl/operations/d1-migrations.toml".to_owned(),
        operation_pack_sha256: format!("sha256:{}", "c".repeat(64)),
        config_template_path: "wrangler.toml".to_owned(),
        config_template_sha256: format!("sha256:{}", "c".repeat(64)),
        production_config_path: "wrangler.toml".to_owned(),
        migrations_dir: "sql".to_owned(),
        database_binding: "DB".to_owned(),
        wrangler_version: "4.100.0".to_owned(),
        migrations: vec![],
        assertions: vec![],
        recovery_capability_id: "d1-full-export".to_owned(),
        recovery_max_age_seconds: 600,
        rollback_capability_id: "d1-restore-exact-bookmark".to_owned(),
        manifest_migration: None,
        transition: Some(Box::new(compiled())),
    }
}
fn binding() -> RuntimeBinding {
    use cfctl_core::workspace_d1::transition::{CompletedRef, PublicationRef};
    let baseline = reference();
    let mut preservation = reference();
    preservation.evidence_hash = format!("sha256:{}", "c".repeat(64));
    let effect = EffectRef {
        operation_id: "operation".to_owned(),
        evidence_hash: format!("sha256:{}", "d".repeat(64)),
    };
    RuntimeBinding {
        schema_version: 3,
        observed_baseline: baseline.clone(),
        baseline_assertions: baseline.clone(),
        completed: vec![CompletedRef {
            sequence: 172,
            baseline_evidence_hash: baseline.evidence_hash.clone(),
            predecessor_evidence_hash: baseline.evidence_hash.clone(),
            envelope_sha256: format!("sha256:{}", "f".repeat(64)),
            effect: effect.clone(),
            preservation: preservation.clone(),
        }],
        recovery: preservation.clone(),
        provider_qualification: effect.clone(),
        publication: Some(PublicationRef {
            effect,
            verification: preservation,
        }),
    }
}

#[test]
fn v3_lineage_requires_exact_prefix_same_baseline_and_post_publication() {
    let compiled = compiled();
    let binding = binding();
    assert!(validate_lineage(&compiled, &binding).is_ok());
    let mut wrong = binding.clone();
    wrong.completed.clear();
    assert!(validate_lineage(&compiled, &wrong).is_err());
    let mut wrong = binding.clone();
    wrong.completed[0].baseline_evidence_hash = wrong.completed[0].envelope_sha256.clone();
    assert!(validate_lineage(&compiled, &wrong).is_err());
    let mut wrong = binding.clone();
    wrong.completed[0].predecessor_evidence_hash = wrong.completed[0].envelope_sha256.clone();
    assert!(validate_lineage(&compiled, &wrong).is_err());
    let mut wrong = binding;
    wrong.publication = None;
    assert!(validate_lineage(&compiled, &wrong).is_err());
}

#[test]
fn v3_prepare_rejects_absent_native_receipts_and_legacy_boundary_stays_closed() {
    use cfctl_core::{
        AdapterStatus, CapabilityAuthorityScopeV1, CapabilityV1, EffectClass, PlanV1, RiskClass,
    };
    let root = tempfile::tempdir().unwrap();
    let store = StateStore::open(cfctl_storage::RuntimePaths::from_root(root.path())).unwrap();
    let contract = contract();
    let input = CallInput {
        selectors: serde_json::json!({"database_id":"database"}),
        body: Some(serde_json::to_value(binding()).unwrap()),
        ..CallInput::default()
    };
    assert!(
        prepare(
            &store,
            &contract,
            &input,
            "account",
            "profile",
            "generation",
            "catalog"
        )
        .is_err()
    );
    let mut capability =
        CapabilityV1::new("fixture", "fixture", "POST", "wrangler d1 migrations apply");
    capability.authority_scope = Some(CapabilityAuthorityScopeV1::WorkspaceOwned);
    capability.adapter_status = AdapterStatus::DelegatedCli;
    capability.mutating = true;
    capability.risk = RiskClass::ScopedWrite;
    capability.effect = EffectClass::DataWrite;
    capability.verification.required = true;
    capability.verification.strategy =
        "workspace_d1_migration_ledger_and_schema_assertions".to_owned();
    capability.workspace_d1_migration = Some(contract);
    assert!(!capability.verification_contract_supported());
    let plan = PlanV1::draft(
        "profile",
        "account",
        "catalog",
        capability,
        serde_json::json!({}),
    )
    .unwrap();
    let error =
        super::super::workspace_d1_migration::validate_bound_plan(&store, &plan).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("V3 production transport is disabled")
    );
    assert!(store.list_operational_proofs().unwrap().is_empty());
}
