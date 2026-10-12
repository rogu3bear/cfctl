#![allow(clippy::unwrap_used, clippy::expect_used, clippy::wildcard_imports)]
use super::*;
use cfctl_core::workspace_d1::transition::proofs::Identity;
use std::cell::{Cell, RefCell};

fn digest(c: char) -> String {
    format!("sha256:{}", c.to_string().repeat(64))
}
pub(super) fn prepared() -> Checkpoint {
    Checkpoint {
        schema_version: 1,
        operation_id: "22222222-2222-4222-8222-222222222222".into(),
        identity: Identity {
            repository_head: "a".repeat(40),
            operation_pack_sha256: digest('a'),
            declaration_sha256: digest('a'),
            source_envelope_sha256: digest('a'),
            execution_sha256: format!("sha256:{}", hex::encode(Sha256::digest(b"SELECT 1;\n"))),
            account_id: "a".repeat(32),
            database_id: "11111111-1111-4111-8111-111111111111".into(),
            target_sequence: 176,
            migration_sha256: digest('a'),
        },
        plan_hash: digest('a'),
        qualification_evidence_hash: digest('b'),
        assurance_sha256: digest('c'),
        baseline_evidence_hash: digest('d'),
        predecessor_evidence_hash: digest('d'),
        stage: Stage::Prepared,
        previous_checkpoint_sha256: None,
        provider_receipt_sha256: None,
        bookmark_sha256: None,
    }
}

#[tokio::test]
async fn lost_response_persists_uncertainty_and_cannot_redispatch() {
    let records = RefCell::new(Vec::new());
    let sends = Cell::new(0);
    let uncertain = execute_once(
        &prepared(),
        b"SELECT 1;\n",
        |checkpoint| {
            records.borrow_mut().push(checkpoint.clone());
            Ok(())
        },
        |_| {
            sends.set(sends.get() + 1);
            async { Terminal::Uncertain }
        },
    )
    .await
    .unwrap();
    assert_eq!(sends.get(), 1);
    assert_eq!(uncertain.stage, Stage::Uncertain);
    assert_eq!(records.borrow()[1].stage, Stage::DispatchIntent);
    assert!(
        execute_once(
            &uncertain,
            b"SELECT 1;\n",
            |_| Ok(()),
            |_| {
                sends.set(sends.get() + 1);
                async { Terminal::Uncertain }
            }
        )
        .await
        .is_err()
    );
    assert_eq!(sends.get(), 1);
}

#[tokio::test]
async fn failed_intent_persistence_prevents_dispatch_and_sink_failure_prevents_replay() {
    for fail_at in [0, 1, 2] {
        let writes = Cell::new(0);
        let sends = Cell::new(0);
        let result = execute_once(
            &prepared(),
            b"SELECT 1;\n",
            |_| {
                let n = writes.get();
                writes.set(n + 1);
                if n == fail_at { Err(()) } else { Ok(()) }
            },
            |_| {
                sends.set(sends.get() + 1);
                async {
                    Terminal::Committed {
                        receipt_sha256: digest('e'),
                        bookmark_sha256: digest('f'),
                    }
                }
            },
        )
        .await
        .unwrap_err();
        assert_eq!(sends.get(), usize::from(fail_at == 2));
        assert_eq!(
            result.durable.stage,
            if fail_at == 2 {
                Stage::DispatchIntent
            } else {
                Stage::Prepared
            }
        );
    }
}

#[tokio::test]
async fn changed_sql_is_rejected_before_any_checkpoint_or_transport() {
    let sends = Cell::new(0);
    let writes = Cell::new(0);
    assert!(
        execute_once(
            &prepared(),
            b"SELECT 2;\n",
            |_| {
                writes.set(writes.get() + 1);
                Ok(())
            },
            |_| {
                sends.set(sends.get() + 1);
                async { Terminal::Uncertain }
            }
        )
        .await
        .is_err()
    );
    assert_eq!(sends.get(), 0);
    assert_eq!(writes.get(), 0);
}

#[test]
fn interrupted_intent_reconciles_without_execution_and_rejects_repeat() {
    let intent = prepared().advance(Event::Dispatch, None, None).unwrap();
    let records = RefCell::new(Vec::new());
    let terminal = reconcile(
        &intent,
        Terminal::RolledBack {
            receipt_sha256: digest('e'),
            bookmark_sha256: digest('f'),
        },
        |checkpoint| {
            records.borrow_mut().push(checkpoint.clone());
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(records.borrow()[0].stage, Stage::Uncertain);
    assert_eq!(terminal.stage, Stage::RolledBack);
    assert!(reconcile(&terminal, Terminal::Uncertain, |_| Ok(())).is_err());
}
