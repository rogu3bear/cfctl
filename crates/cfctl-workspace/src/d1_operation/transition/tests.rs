#![allow(
    clippy::assigning_clones,
    reason = "test fixture mutations remain explicit"
)]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::wildcard_imports)]
use super::*;
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
    };
    (root, declaration)
}

#[test]
fn v3_preserves_184_history_and_compiles_each_phase_without_source_rewrites() {
    let (root, mut op) = fixture(184);
    let initial = compile(root.path(), &op).unwrap();
    assert_eq!(initial.historical_sequences.len(), 171);
    for (position, target) in initial.scheduled_targets.iter().enumerate() {
        op.target = target.clone();
        let compiled = compile(root.path(), &op).unwrap();
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
    assert!(compile(root.path(), &bad).is_err());
    let mut bad = op.clone();
    bad.target.source.sha256 = format!("sha256:{}", "0".repeat(64));
    assert!(compile(root.path(), &bad).is_err());
    let mut bad = op.clone();
    bad.transition_schedule[3].deferred_sequences.clear();
    assert!(compile(root.path(), &bad).is_err());
    let mut bad = op.clone();
    bad.transition_schedule[0].required_completed_transition_sequences = vec![174];
    assert!(compile(root.path(), &bad).is_err());
    let mut bad = op.clone();
    bad.transition_schedule.remove(2);
    assert!(compile(root.path(), &bad).is_err());
    fs::write(root.path().join("pre.sql"), "SELECT 0;\n").unwrap();
    assert!(compile(root.path(), &op).is_err());
    let (root, op) = fixture(257);
    assert!(compile(root.path(), &op).is_err());
}

fn operations(root: &Path, op: &Declaration) -> Vec<Declaration> {
    compile(root, op)
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
    assert!(compile_pack(root.path(), std::slice::from_ref(&op)).is_err());
    let mut bad = declarations.clone();
    bad[1].target = bad[0].target.clone();
    assert!(compile_pack(root.path(), &bad).is_err());
    let mut bad = declarations.clone();
    bad[1].transition_schedule[0].phase = Phase::PostDeploy;
    assert!(compile_pack(root.path(), &bad).is_err());
    let mut bad = declarations;
    bad.last_mut().unwrap().assertions.preservation.sha256 = format!("sha256:{}", "0".repeat(64));
    assert!(compile_pack(root.path(), &bad).is_err());
    let mut value = serde_json::to_value(op).unwrap();
    value["approved"] = json!(true);
    assert!(serde_json::from_value::<Declaration>(value).is_err());
}
