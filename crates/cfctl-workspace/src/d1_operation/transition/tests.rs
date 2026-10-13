#![allow(
    clippy::assigning_clones,
    reason = "test fixture mutations remain explicit"
)]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::wildcard_imports)]
use super::*;
use crate::WorkspaceOperationLoad;
use crate::load_workspace_d1_migration_capability;
use cfctl_core::workspace_d1::transition::{Assertions, Phase, Step};
use serde_json::json;
use std::{fs, process::Command};

fn git(root: &Path, args: &[&str]) {
    assert!(
        Command::new("git")
            .current_dir(root)
            .args(args)
            .output()
            .unwrap()
            .status
            .success()
    );
}
fn source(root: &Path, path: &str) -> Source {
    Source {
        path: path.to_owned(),
        sha256: sha256(&fs::read(root.join(path)).unwrap()),
        git_blob_oid: git_optional(root, &["rev-parse", &format!("HEAD:{path}")])
            .unwrap()
            .unwrap(),
    }
}

#[test]
fn v3_managed_policy_is_committed_exact_target_source_without_activation() {
    use cfctl_core::workspace_d1::transition::{Observation, assurance};
    let (root, mut op) = fixture(176);
    let policy = json!({"schema_version":1,"mode":"managed_d1_application_v1",
        "release_id":"fixture/intake","account_id":op.account_id,"database_id":op.database_id,
        "target_sequence":op.target.sequence,"migration_sha256":op.target.source.sha256,
        "accepted_unobserved_properties":["global_index_consistency","global_uniqueness_storage_consistency"],
        "required_controls":["primary_quick_check","exact_schema","full_scan_typed_population_preservation",
            "foreign_key_check","atomic_failure_rollback","target_once_ledger","final_scratch_cleanup"]});
    fs::write(
        root.path().join("policy.json"),
        serde_json::to_vec(&policy).unwrap(),
    )
    .unwrap();
    fs::write(
        root.path().join("diagnostic.json"),
        include_bytes!("../../../tests/fixtures/d1-reads/inventory.json"),
    )
    .unwrap();
    git(root.path(), &["add", "policy.json", "diagnostic.json"]);
    git(root.path(), &["commit", "-qm", "bind proposed assurance"]);
    op.assurance = Some(assurance::Declaration::ManagedD1ApplicationV1 {
        policy: source(root.path(), "policy.json"),
        diagnostic: Observation {
            capability_id: "fixture.diagnostic".into(),
            inventory: source(root.path(), "diagnostic.json"),
        },
    });
    let compiled = compile(root.path(), &op, WorkspaceOperationLoad::Execute).unwrap();
    assert_eq!(
        compiled.assurance_policy.unwrap().release_id,
        "fixture/intake"
    );
    let mut bad = policy;
    bad["target_sequence"] = json!(177);
    fs::write(
        root.path().join("policy.json"),
        serde_json::to_vec(&bad).unwrap(),
    )
    .unwrap();
    git(root.path(), &["add", "policy.json"]);
    git(root.path(), &["commit", "-qm", "wrong target"]);
    if let Some(assurance::Declaration::ManagedD1ApplicationV1 { policy, .. }) = &mut op.assurance {
        *policy = source(root.path(), "policy.json");
    }
    assert!(compile(root.path(), &op, WorkspaceOperationLoad::Execute).is_err());
}
#[expect(
    clippy::too_many_lines,
    reason = "one committed synthetic repository binds the full historical ledger, schedule and reviewed SQL sources"
)]
fn fixture(count: u64) -> (tempfile::TempDir, Declaration) {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir_all(root.path().join("sql")).unwrap();
    fs::create_dir_all(root.path().join(".cfctl/operations")).unwrap();
    git(root.path(), &["init", "-q"]);
    git(
        root.path(),
        &["config", "user.email", "operator@example.com"],
    );
    git(root.path(), &["config", "user.name", "Fixture"]);
    git(
        root.path(),
        &["remote", "add", "origin", "https://example.com/fixture.git"],
    );
    let name = |i| {
        if i == 183 {
            "0176_contract.sql".to_owned()
        } else {
            format!("migration_{i:04}.sql")
        }
    };
    let mut manifest = Vec::new();
    let mut history = Vec::new();
    for i in 1..=count {
        let sql = format!("-- original {i}\nCREATE TABLE t{i}(id INTEGER);\n");
        fs::write(root.path().join("sql").join(name(i)), &sql).unwrap();
        let digest = sha256(sql.as_bytes())
            .trim_start_matches("sha256:")
            .to_owned();
        manifest.push(json!({"sequence":i,"file":name(i),"sha256":digest,"predecessor":if i==1 {None} else {Some(name(i-1))},"production_applied":i<=171}));
        if i <= 171 {
            history.push(json!({"file":name(i),"sha256":digest,"applied_at":"historical"}));
        }
    }
    fs::write(
        root.path().join("manifest.json"),
        serde_json::to_vec(&json!({"manifest_version":1,"migrations":manifest})).unwrap(),
    )
    .unwrap();
    fs::write(
        root.path().join("history.json"),
        serde_json::to_vec(&json!({"migrations":history})).unwrap(),
    )
    .unwrap();
    for file in ["pre.sql", "capture.sql", "preserve.sql", "cleanup.sql"] {
        fs::write(
            root.path().join(file),
            format!("-- reviewed {file}\nSELECT 1;\n"),
        )
        .unwrap();
    }
    fs::write(root.path().join("wrangler.toml"), "name = 'fixture'\n").unwrap();
    git(root.path(), &["add", "."]);
    git(root.path(), &["commit", "-qm", "sources"]);
    let order: Vec<_> = (172..=count)
        .filter(|i| ![175, 183].contains(i))
        .chain([175, 183].into_iter().filter(|i| *i <= count))
        .collect();
    let schedule = order
        .iter()
        .enumerate()
        .map(|(index, sequence)| Step {
            sequence: *sequence,
            phase: if [175, 183].contains(sequence) {
                Phase::PostDeploy
            } else {
                Phase::PreDeploy
            },
            required_completed_transition_sequences: if index == 0 {
                vec![]
            } else {
                vec![order[index - 1]]
            },
            deferred_sequences: (172..*sequence)
                .filter(|i| !order[..index].contains(i))
                .collect(),
        })
        .collect();
    let target = Target {
        sequence: 172,
        file: name(172),
        source: source(root.path(), &format!("sql/{}", name(172))),
    };
    let declaration = Declaration {
        id: "fixture.d1-transition".to_owned(),
        title: "Fixture".to_owned(),
        description: "Synthetic source qualification".to_owned(),
        manifest: source(root.path(), "manifest.json"),
        historical_ledger: source(root.path(), "history.json"),
        config_template: "wrangler.toml".to_owned(),
        account_id: "a".repeat(32),
        profile_id: "fixture".to_owned(),
        database_id: "00000000-0000-0000-0000-000000000000".to_owned(),
        database_binding: "DB".to_owned(),
        migrations_dir: "sql".to_owned(),
        target,
        transition_schedule: schedule,
        assertions: Assertions {
            preconditions: source(root.path(), "pre.sql"),
            capture: source(root.path(), "capture.sql"),
            preservation: source(root.path(), "preserve.sql"),
            cleanup: source(root.path(), "cleanup.sql"),
        },
        observations: None,
        assurance: None,
    };
    (root, declaration)
}

#[test]
fn v3_preserves_184_history_and_compiles_each_phase_without_source_rewrites() {
    let (root, mut op) = fixture(184);
    let initial = compile(root.path(), &op, WorkspaceOperationLoad::Execute).unwrap();
    assert_eq!(initial.historical_sequences.len(), 171);
    assert_eq!(
        initial.execution.ledger_name,
        initial.declaration.target.file
    );
    assert_eq!(initial.execution.ledger_offset, initial.segments[4].offset);
    assert_eq!(
        initial.execution.source_envelope_sha256,
        initial.envelope_sha256
    );
    assert!(initial.execution.execution_length > initial.envelope_length);
    for (position, target) in initial.scheduled_targets.iter().enumerate() {
        op.target = target.clone();
        let compiled = compile(root.path(), &op, WorkspaceOperationLoad::Execute).unwrap();
        compiled
            .validate_completed(
                &op.transition_schedule[..position]
                    .iter()
                    .map(|s| s.sequence)
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        let joined: Vec<u8> = compiled
            .segments
            .iter()
            .flat_map(|s| fs::read(root.path().join(&s.source.path)).unwrap())
            .collect();
        assert_eq!(compiled.envelope_sha256, sha256(&joined));
        let segment = &compiled.segments[2];
        assert_eq!(
            &joined[segment.offset..segment.offset + segment.length],
            fs::read(root.path().join(&target.source.path)).unwrap()
        );
    }
    assert_eq!(initial.scheduled_targets.last().unwrap().sequence, 183);
    assert_eq!(
        initial.scheduled_targets.last().unwrap().file,
        "0176_contract.sql"
    );
}

#[test]
fn v3_rejects_wrong_identity_missing_gap_prerequisite_overflow_and_drift() {
    let (root, op) = fixture(184);
    let mut bad = op.clone();
    bad.target.sequence = 176;
    assert!(compile(root.path(), &bad, WorkspaceOperationLoad::Execute).is_err());
    let mut bad = op.clone();
    bad.target.source.sha256 = format!("sha256:{}", "0".repeat(64));
    assert!(compile(root.path(), &bad, WorkspaceOperationLoad::Execute).is_err());
    let mut bad = op.clone();
    bad.transition_schedule[3].deferred_sequences.clear();
    assert!(compile(root.path(), &bad, WorkspaceOperationLoad::Execute).is_err());
    let mut bad = op.clone();
    bad.transition_schedule[0].required_completed_transition_sequences = vec![174];
    assert!(compile(root.path(), &bad, WorkspaceOperationLoad::Execute).is_err());
    let mut bad = op.clone();
    bad.transition_schedule.remove(2);
    assert!(compile(root.path(), &bad, WorkspaceOperationLoad::Execute).is_err());
    fs::write(root.path().join("pre.sql"), "SELECT 0;\n").unwrap();
    assert!(compile(root.path(), &op, WorkspaceOperationLoad::Execute).is_err());
    let (root, op) = fixture(257);
    assert!(compile(root.path(), &op, WorkspaceOperationLoad::Execute).is_err());
}

fn operations(root: &Path, op: &Declaration) -> Vec<Declaration> {
    compile(root, op, WorkspaceOperationLoad::Execute)
        .unwrap()
        .scheduled_targets
        .into_iter()
        .map(|target| {
            let mut declaration = op.clone();
            declaration.id = format!("fixture.transition-{}", target.sequence);
            declaration.target = target;
            declaration
        })
        .collect()
}

#[test]
fn v3_observation_sources_are_committed_and_hash_bound() {
    use cfctl_core::workspace_d1::transition::{Observation, Observations};
    let (root, mut op) = fixture(172);
    fs::write(
        root.path().join("boundary.json"),
        include_bytes!("../../../tests/fixtures/d1-reads/inventory.json"),
    )
    .unwrap();
    git(root.path(), &["add", "boundary.json"]);
    git(root.path(), &["commit", "-qm", "reviewed boundary"]);
    let observation = Observation {
        capability_id: "fixture.boundary".into(),
        inventory: source(root.path(), "boundary.json"),
    };
    op.observations = Some(Observations {
        baseline: observation.clone(),
        terminal: observation,
    });
    compile(root.path(), &op, WorkspaceOperationLoad::Execute).unwrap();
    fs::write(root.path().join("boundary.json"), "{}").unwrap();
    assert!(compile(root.path(), &op, WorkspaceOperationLoad::Execute).is_err());
}

#[test]
fn v3_materialization_preserves_bytes_and_rejects_contract_and_source_drift() {
    let (root, op) = fixture(172);
    let declarations = operations(root.path(), &op);
    let text = toml::to_string(&json!({"schema_version":3,"operation":declarations})).unwrap();
    fs::write(root.path().join(PACK_RELATIVE_PATH), text).unwrap();
    git(root.path(), &["add", "."]);
    git(root.path(), &["commit", "-qm", "frozen pack"]);
    let capability =
        load_workspace_d1_migration_capability(&[root.path().to_path_buf()], &declarations[0].id)
            .unwrap()
            .unwrap();
    let contract = capability.workspace_d1_migration.unwrap();
    let compiled = contract.transition.as_ref().unwrap();
    let expected: Vec<u8> = compiled
        .segments
        .iter()
        .flat_map(|s| fs::read(root.path().join(&s.source.path)).unwrap())
        .collect();
    assert_eq!(
        materialize_workspace_d1_transition(&contract).unwrap(),
        expected
    );
    let execution = materialize_workspace_d1_transition_execution(&contract).unwrap();
    let manifest = &compiled.execution;
    assert_eq!(execution.len(), manifest.execution_length);
    assert_eq!(sha256(&execution), manifest.execution_sha256);
    assert_eq!(
        &execution[..manifest.ledger_offset],
        &expected[..manifest.ledger_offset]
    );
    assert_eq!(
        &execution[manifest.ledger_offset + manifest.ledger_length..],
        &expected[manifest.ledger_offset..]
    );
    let mut substituted = contract.clone();
    substituted
        .transition
        .as_mut()
        .unwrap()
        .execution
        .ledger_offset += 1;
    assert!(materialize_workspace_d1_transition_execution(&substituted).is_err());
    for kind in 0..5 {
        let mut bad = contract.clone();
        let compiled = bad.transition.as_mut().unwrap();
        match kind {
            0 => compiled.segments.swap(0, 1),
            1 => compiled.segments[1].offset += 1,
            2 => compiled.segments[2].length += 1,
            3 => compiled.envelope_sha256 = format!("sha256:{}", "0".repeat(64)),
            _ => compiled.compiler_id = "unreviewed-compiler".to_owned(),
        }
        assert!(materialize_workspace_d1_transition(&bad).is_err());
    }
    fs::write(root.path().join("capture.sql"), "SELECT 'changed';\n").unwrap();
    assert!(materialize_workspace_d1_transition(&contract).is_err());
    git(root.path(), &["add", "capture.sql"]);
    git(root.path(), &["commit", "-qm", "changed assertion"]);
    assert!(materialize_workspace_d1_transition(&contract).is_err());
}

#[test]
fn v3_native_verification_contract_is_distinct_and_does_not_activate_blocked_source() {
    use cfctl_core::workspace_d1::transition::{Observation, Observations, assurance};
    let (root, op) = fixture(172);
    let operations = operations(root.path(), &op);
    fs::write(
        root.path().join(PACK_RELATIVE_PATH),
        toml::to_string(&json!({"schema_version":3,"operation":operations})).unwrap(),
    )
    .unwrap();
    git(root.path(), &["add", "."]);
    git(root.path(), &["commit", "-qm", "native contract fixture"]);
    let blocked =
        load_workspace_d1_migration_capability(&[root.path().to_path_buf()], &operations[0].id)
            .unwrap()
            .unwrap();
    assert!(!blocked.verification_contract_supported());
    let mut native = blocked.clone();
    native.adapter_status = AdapterStatus::Native;
    assert!(!native.verification_contract_supported());
    let compiled = native
        .workspace_d1_migration
        .as_mut()
        .unwrap()
        .transition
        .as_mut()
        .unwrap();
    let observation = Observation {
        capability_id: "fixture.read".into(),
        inventory: compiled.declaration.assertions.preconditions.clone(),
    };
    compiled.declaration.assurance = Some(assurance::Declaration::FullIntegrityV1 {
        diagnostic: observation.clone(),
    });
    compiled.declaration.observations = Some(Observations {
        baseline: observation.clone(),
        terminal: observation,
    });
    assert!(native.verification_contract_supported());
    native.verification.strategy = "workspace_d1_migration_ledger_and_schema_assertions".into();
    assert!(!native.verification_contract_supported());
    assert_eq!(blocked.adapter_status, AdapterStatus::Blocked);
    assert!(!blocked.verification_contract_supported());
}

#[test]
fn v3_real_loader_binds_every_target_in_one_frozen_pack_and_keeps_transport_blocked() {
    let (root, op) = fixture(184);
    let operations = operations(root.path(), &op);
    let text = toml::to_string(&json!({"schema_version":3,"operation":operations})).unwrap();
    fs::write(root.path().join(PACK_RELATIVE_PATH), text).unwrap();
    git(root.path(), &["add", "."]);
    git(root.path(), &["commit", "-qm", "complete frozen pack"]);
    let head = git_optional(root.path(), &["rev-parse", "HEAD"]).unwrap();
    for operation in &operations {
        let capability =
            load_workspace_d1_migration_capability(&[root.path().to_path_buf()], &operation.id)
                .unwrap()
                .unwrap();
        assert_eq!(capability.adapter_status, AdapterStatus::Blocked);
        assert!(!capability.verification_contract_supported());
        let contract = capability.workspace_d1_migration.unwrap();
        assert_eq!(Some(contract.repository_head), head);
        assert_eq!(
            contract.transition.unwrap().declaration.target,
            operation.target
        );
    }
    assert_eq!(
        git_optional(root.path(), &["rev-parse", "HEAD"]).unwrap(),
        head
    );
    assert!(
        git_optional(root.path(), &["status", "--porcelain"])
            .unwrap()
            .unwrap_or_default()
            .is_empty()
    );
}

#[test]
fn v3_frozen_pack_rejects_missing_duplicate_divergent_or_unbound_future_declarations() {
    let (root, op) = fixture(184);
    let declarations = operations(root.path(), &op);
    assert!(
        compile_pack(
            root.path(),
            std::slice::from_ref(&op),
            WorkspaceOperationLoad::Execute
        )
        .is_err()
    );
    let mut bad = declarations.clone();
    bad[1].target = bad[0].target.clone();
    assert!(compile_pack(root.path(), &bad, WorkspaceOperationLoad::Execute).is_err());
    let mut bad = declarations.clone();
    bad[1].transition_schedule[0].phase = Phase::PostDeploy;
    assert!(compile_pack(root.path(), &bad, WorkspaceOperationLoad::Execute).is_err());
    let mut bad = declarations;
    bad.last_mut().unwrap().assertions.preservation.sha256 = format!("sha256:{}", "0".repeat(64));
    assert!(compile_pack(root.path(), &bad, WorkspaceOperationLoad::Execute).is_err());
    let mut value = serde_json::to_value(op).unwrap();
    value["approved"] = json!(true);
    assert!(serde_json::from_value::<Declaration>(value).is_err());
}

#[test]
fn v3_history_preserves_known_metadata_and_rejects_unknown_or_contradictory_fields() {
    let (root, mut op) = fixture(176);
    let path = root.path().join("history.json");
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    value["migrations"][0]["sequence"] = json!(1);
    value["migrations"][0]["migration_class"] = json!("schema");
    value["migrations"][0]["notes"] = json!("retained canonical source note");
    let manifest_path = root.path().join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    manifest["migrations"][0]["migration_class"] = json!("schema");
    fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    git(root.path(), &["add", "manifest.json", "history.json"]);
    git(
        root.path(),
        &[
            "commit",
            "-qm",
            "retain canonical optional history metadata",
        ],
    );
    op.manifest = source(root.path(), "manifest.json");
    op.historical_ledger = source(root.path(), "history.json");
    let compiled = compile(root.path(), &op, WorkspaceOperationLoad::Execute).unwrap();
    assert_eq!(compiled.historical_sequences.len(), 171);
    for mutation in 0..6 {
        let mut wrong = value.clone();
        match mutation {
            0 => wrong["migrations"][0]["sequence"] = json!(2),
            1 => wrong["migrations"][0]["migration_class"] = json!("compatibility"),
            2 => wrong["migrations"][0]["migration_class"] = json!("invented"),
            3 => wrong["migrations"][0]["notes"] = json!("  "),
            4 => wrong["migrations"][0]["caller_passed"] = json!(true),
            _ => wrong["migrations"][0]["notes"] = serde_json::Value::Null,
        }
        fs::write(&path, serde_json::to_vec(&wrong).unwrap()).unwrap();
        git(root.path(), &["add", "history.json"]);
        git(
            root.path(),
            &["commit", "-qm", "reject contradictory history metadata"],
        );
        op.historical_ledger = source(root.path(), "history.json");
        assert!(compile(root.path(), &op, WorkspaceOperationLoad::Execute).is_err());
    }
}

#[test]
fn bound_transition_source_requires_exact_revision_blob_and_local_bytes() {
    let (root, op) = fixture(176);
    let head = git_optional(root.path(), &["rev-parse", "HEAD"])
        .unwrap()
        .unwrap();
    let source = op.assertions.capture.clone();
    let bytes =
        materialize_workspace_d1_transition_source(root.path(), head.trim(), &source).unwrap();
    assert_eq!(bytes, fs::read(root.path().join(&source.path)).unwrap());
    assert!(
        materialize_workspace_d1_transition_source(root.path(), &"f".repeat(40), &source).is_err()
    );
    let mut wrong = source.clone();
    wrong.git_blob_oid = "f".repeat(40);
    assert!(materialize_workspace_d1_transition_source(root.path(), head.trim(), &wrong).is_err());
    wrong = source.clone();
    wrong.path = "../escape.sql".into();
    assert!(materialize_workspace_d1_transition_source(root.path(), head.trim(), &wrong).is_err());
    fs::write(root.path().join(&source.path), b"SELECT 'changed';").unwrap();
    assert!(materialize_workspace_d1_transition_source(root.path(), head.trim(), &source).is_err());
}
