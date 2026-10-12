#![allow(clippy::unwrap_used, clippy::wildcard_imports)]
use super::*;
use cfctl_core::workspace_d1::transition::{
    execution::{Checkpoint, Event},
    proofs::EXECUTION_KIND,
};
fn digest(c: char) -> String {
    format!("sha256:{}", c.to_string().repeat(64))
}
fn record() -> ExecutionRecord {
    let prepared = Checkpoint {
        schema_version: 1,
        operation_id: "22222222-2222-4222-8222-222222222222".into(),
        identity: Identity {
            repository_head: "a".repeat(40),
            operation_pack_sha256: digest('a'),
            declaration_sha256: digest('b'),
            source_envelope_sha256: digest('c'),
            execution_sha256: digest('d'),
            account_id: "f".repeat(32),
            database_id: "11111111-1111-4111-8111-111111111111".into(),
            target_sequence: 176,
            migration_sha256: digest('e'),
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
    };
    let intent = prepared.advance(Event::Dispatch, None, None).unwrap();
    let terminal = intent
        .advance(Event::Commit, Some(&digest('e')), Some(&digest('f')))
        .unwrap();
    ExecutionRecord {
        schema_version: 1,
        kind: EXECUTION_KIND.into(),
        checkpoints: vec![prepared, intent, terminal],
        checkpoint_evidence_hashes: vec![digest('a'), digest('b'), digest('c')],
    }
}
#[test]
fn dispatch_and_terminal_times_require_every_exact_authenticated_apply_checkpoint() {
    for mutation in 0..5 {
        let root = tempfile::tempdir().unwrap();
        let store = crate::runtime::tests::authenticated_test_store(
            cfctl_storage::RuntimePaths::from_root(root.path()),
        );
        let mut record = record();
        for (index, checkpoint) in record.checkpoints.iter().enumerate() {
            if mutation == 1 && index == 1 {
                continue;
            }
            let class = if mutation == 2 && index == 1 {
                EvidenceClass::LocalProof
            } else {
                EvidenceClass::Apply
            };
            let evidence = store
                .write_evidence(class, &serde_json::to_value(checkpoint).unwrap())
                .unwrap();
            record.checkpoint_evidence_hashes[index] = evidence.content_hash;
            if mutation == 4 && index == 1 {
                record.checkpoint_evidence_hashes[index] =
                    cfctl_core::hash_value(&serde_json::to_value(checkpoint).unwrap()).unwrap();
            }
        }
        let not_after = if mutation == 3 {
            DateTime::<Utc>::MIN_UTC
        } else {
            Utc::now()
        };
        let result = checkpoint_times(&store, &record, not_after);
        if mutation == 0 {
            let times = result.unwrap();
            assert!(times.dispatch <= times.terminal);
        } else {
            assert!(result.is_err());
        }
    }
}

#[test]
fn verification_wrappers_preserve_distinct_immutable_apply_and_verification_classes() {
    use cfctl_core::workspace_d1::transition::proofs::{
        VERIFIED_EXECUTION_KIND, VerifiedExecutionRecord,
    };
    let root = tempfile::tempdir().unwrap();
    let store = crate::runtime::tests::authenticated_test_store(
        cfctl_storage::RuntimePaths::from_root(root.path()),
    );
    let execution = record();
    let apply = store
        .write_evidence(
            EvidenceClass::Apply,
            &serde_json::to_value(&execution).unwrap(),
        )
        .unwrap();
    let wrapper = VerifiedExecutionRecord {
        schema_version: 1,
        kind: VERIFIED_EXECUTION_KIND.into(),
        apply_evidence_hash: apply.content_hash.clone(),
        execution,
    };
    wrapper.validate().unwrap();
    let verified = store
        .write_evidence(
            EvidenceClass::PostChangeVerification,
            &serde_json::to_value(wrapper).unwrap(),
        )
        .unwrap();
    assert_ne!(verified.content_hash, apply.content_hash);
    assert_eq!(
        store.load_evidence(&apply.content_hash).unwrap().class,
        EvidenceClass::Apply
    );
    assert_eq!(
        store.load_evidence(&verified.content_hash).unwrap().class,
        EvidenceClass::PostChangeVerification
    );
}
