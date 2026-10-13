#![allow(clippy::expect_used, clippy::unwrap_used, clippy::wildcard_imports)]
use super::*;
use cfctl_cloudflare::d1_transition::{Terminal, execute_once};
use cfctl_core::workspace_d1::transition::{
    ProofRef,
    application::{APPLICATION_KIND, ApplicationVerification},
    proofs::{VERIFIED_EXECUTION_KIND, VerifiedExecutionRecord},
};
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::cell::Cell;

fn digest(c: char) -> String {
    format!("sha256:{}", c.to_string().repeat(64))
}
fn prepared(bytes: &[u8]) -> Checkpoint {
    Checkpoint {
        schema_version: 1,
        operation_id: uuid::Uuid::new_v4().to_string(),
        identity: Identity {
            repository_head: "a".repeat(40),
            operation_pack_sha256: digest('a'),
            declaration_sha256: digest('b'),
            source_envelope_sha256: digest('c'),
            execution_sha256: format!("sha256:{}", hex::encode(Sha256::digest(bytes))),
            account_id: "a".repeat(32),
            database_id: "11111111-1111-4111-8111-111111111111".into(),
            target_sequence: 195,
            migration_sha256: digest('d'),
        },
        plan_hash: digest('e'),
        qualification_evidence_hash: digest('f'),
        assurance_sha256: digest('a'),
        baseline_evidence_hash: digest('b'),
        predecessor_evidence_hash: digest('c'),
        stage: Stage::Prepared,
        previous_checkpoint_sha256: None,
        provider_receipt_sha256: None,
        bookmark_sha256: None,
    }
}

type Rows = Vec<(String, String)>;
fn state(db: &Connection) -> (Rows, Rows) {
    let schema = db
        .prepare("SELECT name,coalesce(sql,'') FROM sqlite_schema ORDER BY type,name")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    let rows = db
        .prepare(
            "SELECT typeof(value),quote(value) FROM original ORDER BY typeof(value),quote(value)",
        )
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    (schema, rows)
}

/// Local `SQLite` is the fault oracle, not a claim about D1 import transactionality.
#[expect(
    clippy::too_many_lines,
    reason = "one end-to-end fault matrix binds byte transport, SQLite rollback and native evidence"
)]
#[tokio::test]
async fn one_file_preserves_multiline_bytes_and_rolls_back_each_local_fault_site() {
    for failed_stage in [
        None,
        Some("migration"),
        Some("preservation"),
        Some("ledger"),
        Some("cleanup"),
    ] {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE original(value); INSERT INTO original VALUES(NULL),(x'00FF'),(-7),(1.25),('semi;colon'),('repeat'),('repeat'); CREATE TABLE d1_migrations(name TEXT UNIQUE);").unwrap();
        let before = state(&db);
        let fault = "INSERT INTO check_result VALUES(0);\n";
        let migration = "CREATE INDEX \"new_index\"\n    ON \"original\" (\n        \"value\"  /* preserve:  two spaces; comment */\n    );\n";
        let mut sql="-- preconditions;\nCREATE TABLE check_result(passed CHECK(passed=1));\nCREATE TABLE captured AS SELECT value FROM original;\n".to_owned();
        for (stage, statement) in [
            ("migration", migration),
            (
                "preservation",
                "INSERT INTO check_result SELECT CASE WHEN (SELECT COUNT(*) FROM original)=7 THEN 1 ELSE 0 END;\n",
            ),
            (
                "ledger",
                "INSERT INTO d1_migrations(name) VALUES('0195_exact.sql');\n",
            ),
            (
                "cleanup",
                "DROP TABLE captured;\nDROP TABLE check_result;\n",
            ),
        ] {
            if failed_stage == Some(stage) {
                sql.push_str(fault);
            }
            sql.push_str(statement);
        }
        let bytes = sql.as_bytes();
        let checkpoint = prepared(bytes);
        let root = tempfile::tempdir().unwrap();
        let store = crate::runtime::tests::authenticated_test_store(
            cfctl_storage::RuntimePaths::from_root(root.path()),
        );
        let directory = claim(&store, &checkpoint).unwrap();
        let record = RefCell::new(ExecutionRecord {
            schema_version: 1,
            kind: EXECUTION_KIND.into(),
            checkpoints: vec![],
            checkpoint_evidence_hashes: vec![],
        });
        let sends = Cell::new(0);
        let terminal = execute_once(
            &checkpoint,
            bytes,
            |c| persist_checkpoint(&store, &directory, &record, c),
            |received| {
                sends.set(sends.get() + 1);
                assert_eq!(received, bytes);
                let transaction = db.unchecked_transaction().unwrap();
                let applied = transaction.execute_batch(std::str::from_utf8(&received).unwrap());
                let disposition = if applied.is_ok() {
                    transaction.commit().unwrap();
                    Terminal::Committed {
                        receipt_sha256: digest('d'),
                        bookmark_sha256: digest('e'),
                    }
                } else {
                    transaction.rollback().unwrap();
                    Terminal::RolledBack {
                        receipt_sha256: digest('d'),
                        bookmark_sha256: digest('e'),
                    }
                };
                async move { disposition }
            },
        )
        .await
        .unwrap();
        assert_eq!(sends.get(), 1);
        assert!(claim(&store, &checkpoint).is_err());
        assert_eq!(record.borrow().terminal().unwrap(), &terminal);
        if failed_stage.is_some() {
            assert_eq!(terminal.stage, Stage::RolledBack);
            assert_eq!(state(&db), before);
        } else {
            assert_eq!(terminal.stage, Stage::Committed);
            assert_eq!(state(&db).1, before.1);
            let ddl: String = db
                .query_row(
                    "SELECT sql FROM sqlite_schema WHERE name='new_index'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(ddl, migration.trim_end_matches('\n').trim_end_matches(';'));
            assert_eq!(
                db.query_row(
                    "SELECT COUNT(*) FROM d1_migrations WHERE name='0195_exact.sql'",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
                1
            );
            assert_eq!(
                db.query_row(
                    "SELECT COUNT(*) FROM sqlite_schema WHERE name IN ('captured','check_result')",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
                0
            );
            let reference = ProofRef {
                proof_hash: digest('a'),
                evidence_hash: digest('b'),
            };
            let application = ApplicationVerification {
                schema_version: 1,
                kind: APPLICATION_KIND.into(),
                identity: checkpoint.identity.clone(),
                verified_execution: VerifiedExecutionRecord {
                    schema_version: 1,
                    kind: VERIFIED_EXECUTION_KIND.into(),
                    apply_evidence_hash: digest('c'),
                    execution: record.into_inner(),
                },
                terminal_assertions: reference.clone(),
                diagnostic: reference,
            };
            application.validate().unwrap();
            let mut wrong = application.clone();
            wrong.identity.execution_sha256 = digest('0');
            assert!(wrong.validate().is_err());
            let mut wrong = serde_json::to_value(application).unwrap();
            wrong["passed"] = json!(true);
            assert!(serde_json::from_value::<ApplicationVerification>(wrong).is_err());
        }
    }
}

#[tokio::test]
async fn durable_native_claim_and_checkpoint_refuse_redispatch_after_lost_response() {
    let root = tempfile::tempdir().unwrap();
    let store = crate::runtime::tests::authenticated_test_store(
        cfctl_storage::RuntimePaths::from_root(root.path()),
    );
    let bytes = b"SELECT 'not; split';\n";
    let prepared = prepared(bytes);
    let directory = claim(&store, &prepared).unwrap();
    let record = RefCell::new(ExecutionRecord {
        schema_version: 1,
        kind: EXECUTION_KIND.into(),
        checkpoints: vec![],
        checkpoint_evidence_hashes: vec![],
    });
    let last = execute_once(
        &prepared,
        bytes,
        |c| persist_checkpoint(&store, &directory, &record, c),
        |received| async move {
            assert_eq!(received, bytes);
            Terminal::Uncertain
        },
    )
    .await
    .unwrap();
    assert_eq!(last.stage, Stage::Uncertain);
    assert!(record.borrow().terminal().is_err());
    assert!(claim(&store, &prepared).is_err());
    let disk = directory.read("checkpoint-1.json", 65536).unwrap().unwrap();
    let value: serde_json::Value = serde_json::from_slice(&disk).unwrap();
    assert_eq!(value["checkpoint"]["stage"], "dispatch_intent");
    assert!(
        execute_once(&last, bytes, |_| Ok(()), |_| async { panic!("no replay") })
            .await
            .is_err()
    );
}

#[tokio::test]
async fn failed_durable_sink_never_dispatches_and_keeps_the_claim() {
    let root = tempfile::tempdir().unwrap();
    let store = crate::runtime::tests::authenticated_test_store(
        cfctl_storage::RuntimePaths::from_root(root.path()),
    );
    let bytes = b"SELECT 1;\n";
    let prepared = prepared(bytes);
    let directory = claim(&store, &prepared).unwrap();
    directory
        .publish_new_file(
            "checkpoint-0.json",
            b"blocked",
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
    let record = RefCell::new(ExecutionRecord {
        schema_version: 1,
        kind: EXECUTION_KIND.into(),
        checkpoints: vec![],
        checkpoint_evidence_hashes: vec![],
    });
    let failure = execute_once(
        &prepared,
        bytes,
        |c| persist_checkpoint(&store, &directory, &record, c),
        |_| async { panic!("no send before persistence") },
    )
    .await
    .unwrap_err();
    assert_eq!(failure.classification, "prepared_checkpoint_not_durable");
    assert!(record.borrow().checkpoints.is_empty());
    assert!(claim(&store, &prepared).is_err());
}

#[tokio::test]
async fn consumed_native_admission_failure_remains_held_without_credential_or_provider_access() {
    let root = tempfile::tempdir().unwrap();
    let store = crate::runtime::tests::authenticated_test_store(
        cfctl_storage::RuntimePaths::from_root(root.path()),
    );
    let mut capability = cfctl_core::CapabilityV1::new(
        "native.fixture",
        "Fixture",
        "POST",
        "workspace:d1-transition-envelope-v3",
    );
    capability.mutating = true;
    capability.risk = cfctl_core::RiskClass::ScopedWrite;
    capability.effect = cfctl_core::EffectClass::DataWrite;
    let mut plan = PlanV1::draft("profile", "account", "catalog", capability, json!({})).unwrap();
    plan.approve(true, None).unwrap();
    plan.mark_consumed().unwrap();
    plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .unwrap();
    store.save_plan(&plan).unwrap();
    let credential = AuthCredential::Bearer {
        token: "synthetic-unused".into(),
    };
    let result = Box::pin(execute(&store, &mut plan, &credential))
        .await
        .unwrap();
    assert!(!result.ok);
    assert!(!result.performed);
    assert_eq!(result.result["no_replay"], true);
    assert_eq!(result.result["rectification_persisted"], true);
    let held = store.load_plan(&plan.operation_id).unwrap();
    assert_eq!(held.status, PlanStatus::RectificationRequired);
    assert_eq!(
        held.transaction_stage,
        TransactionStageV1::BoundaryResponsePersisted
    );
    assert!(held.validate_transaction_journal().is_ok());
    assert!(!store.paths().data_dir.join("d1-transition-runs").exists());
}
