#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::wildcard_imports,
    clippy::assigning_clones
)]
use super::{assurance::*, execution::*, proofs::*, *};

fn digest(c: char) -> String {
    format!("sha256:{}", c.to_string().repeat(64))
}
fn identity() -> Identity {
    Identity {
        repository_head: "a".repeat(40),
        operation_pack_sha256: digest('b'),
        declaration_sha256: digest('c'),
        source_envelope_sha256: digest('d'),
        execution_sha256: digest('e'),
        account_id: "f".repeat(32),
        database_id: "11111111-1111-4111-8111-111111111111".into(),
        target_sequence: 176,
        migration_sha256: digest('a'),
    }
}
fn reference(c: char) -> ProofRef {
    ProofRef {
        proof_hash: digest(c),
        evidence_hash: digest(c),
    }
}
fn checkpoint() -> Checkpoint {
    Checkpoint {
        schema_version: 1,
        operation_id: "22222222-2222-4222-8222-222222222222".into(),
        identity: identity(),
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

#[test]
fn managed_policy_requires_every_cumulative_control_and_exact_target() {
    let target = Target {
        sequence: 176,
        file: "0177.sql".into(),
        source: Source {
            path: "sql/0177.sql".into(),
            sha256: digest('a'),
            git_blob_oid: "b".repeat(40),
        },
    };
    let policy = ManagedPolicyV1 {
        schema_version: 1,
        mode: "managed_d1_application_v1".into(),
        release_id: "founder/intake-0177".into(),
        account_id: "account".into(),
        database_id: "database".into(),
        target_sequence: 176,
        migration_sha256: digest('a'),
        accepted_unobserved_properties: vec![
            UnobservedProperty::GlobalIndexConsistency,
            UnobservedProperty::GlobalUniquenessStorageConsistency,
        ],
        required_controls: vec![
            Control::PrimaryQuickCheck,
            Control::ExactSchema,
            Control::FullScanTypedPopulationPreservation,
            Control::ForeignKeyCheck,
            Control::AtomicFailureRollback,
            Control::TargetOnceLedger,
            Control::FinalScratchCleanup,
        ],
    };
    policy.validate("account", "database", &target).unwrap();
    for i in 0..policy.required_controls.len() {
        let mut bad = policy.clone();
        bad.required_controls.remove(i);
        assert!(bad.validate("account", "database", &target).is_err());
    }
    for mutation in 0..5 {
        let mut bad = policy.clone();
        match mutation {
            0 => bad.schema_version = 2,
            1 => bad.target_sequence = 177,
            2 => bad.database_id = "other".into(),
            3 => bad.accepted_unobserved_properties.clear(),
            _ => bad.required_controls.push(Control::ExactSchema),
        }
        assert!(bad.validate("account", "database", &target).is_err());
    }
}

#[test]
fn full_mode_rejects_managed_runtime_and_unknown_assurance_fields() {
    let observation = Observation {
        capability_id: "fixture.diagnostic".into(),
        inventory: Source {
            path: "diagnostic.json".into(),
            sha256: digest('a'),
            git_blob_oid: "a".repeat(40),
        },
    };
    let full = assurance::Declaration::FullIntegrityV1 {
        diagnostic: observation.clone(),
    };
    let managed = assurance::Declaration::ManagedD1ApplicationV1 {
        policy: observation.inventory.clone(),
        diagnostic: observation.clone(),
    };
    let full_binding = Binding::FullIntegrityV1 {
        diagnostic: reference('a'),
    };
    full_binding.validate_mode(&full).unwrap();
    assert!(full_binding.validate_mode(&managed).is_err());
    let mut value = serde_json::to_value(full_binding).unwrap();
    value["success"] = serde_json::json!(true);
    assert!(serde_json::from_value::<Binding>(value).is_err());
    assert!(
        serde_json::from_value::<Binding>(serde_json::json!({"mode":"quick_is_full"})).is_err()
    );
}

fn qualification() -> Qualification {
    Qualification {
        schema_version: QUALIFICATION_SCHEMA_VERSION,
        kind: QUALIFICATION_KIND.into(),
        identity: identity(),
        transport: TRANSPORT.into(),
        max_execution_bytes: 1024,
        cases: REQUIRED_CASES
            .into_iter()
            .map(|case| CaseRef {
                case,
                effect: EffectRef {
                    operation_id: format!("{case:?}"),
                    evidence_hash: digest('b'),
                },
                before: reference('c'),
                after: reference('d'),
                synthetic_database_id: "33333333-3333-4333-8333-333333333333".into(),
                fixture_sha256: digest('e'),
                fixture_bytes: 1024,
                failure_sentinel: case
                    .is_failure()
                    .then(|| format!("QUALIFIED_NATIVE_{case:?}").to_uppercase()),
                performance_max_seconds: (case == Case::PerformanceBound).then_some(600),
                concurrency: (case == Case::ConcurrentPopulation).then(|| ConcurrentCase {
                    source: ConcurrentSource {
                        writer: Source {
                            path: "writer.sql".into(),
                            sha256: digest('f'),
                            git_blob_oid: "a".repeat(40),
                        },
                        writer_bytes: 100,
                        post_writer_inventory: Observation {
                            capability_id: "fixture.writer.read".into(),
                            inventory: Source {
                                path: "writer-read.json".into(),
                                sha256: digest('f'),
                                git_blob_oid: "b".repeat(40),
                            },
                        },
                        expected_post_writer_state_sha256: digest('a'),
                    },
                    writer: EffectRef {
                        operation_id: "33333333-3333-4333-8333-333333333333".into(),
                        evidence_hash: digest('e'),
                    },
                    post_writer_observation: reference('d'),
                }),
                before_population_inventory: Observation {
                    capability_id: "fixture.population".into(),
                    inventory: Source {
                        path: "population.json".into(),
                        sha256: digest('f'),
                        git_blob_oid: "a".repeat(40),
                    },
                },
                after_population_inventory: Observation {
                    capability_id: "fixture.population".into(),
                    inventory: Source {
                        path: "population.json".into(),
                        sha256: digest('f'),
                        git_blob_oid: "a".repeat(40),
                    },
                },
                expected_after_state_sha256: digest('a'),
            })
            .collect(),
    }
}

#[test]
fn qualification_rejects_missing_duplicate_and_production_case_substitution() {
    let good = qualification();
    good.validate(&identity(), 1024).unwrap();
    for mutation in 0..18 {
        let mut bad = good.clone();
        match mutation {
            0 => {
                bad.cases.pop();
            }
            1 => bad.cases[0].case = bad.cases[1].case,
            2 => bad.cases[0].synthetic_database_id = identity().database_id,
            3 => bad.transport = "wrangler".into(),
            4 => bad.max_execution_bytes = 1023,
            5 => bad.cases[1].after_population_inventory.inventory.sha256 = digest('b'),
            6 => {
                bad.cases
                    .iter_mut()
                    .find(|case| case.case == Case::PerformanceBound)
                    .unwrap()
                    .fixture_bytes = 1023;
            }
            7 => bad.cases[1].failure_sentinel = None,
            8 => bad.cases[1].failure_sentinel = Some("SQL echo 'failure'".into()),
            9 => bad.cases[8].performance_max_seconds = None,
            10 => bad.cases[8].performance_max_seconds = Some(601),
            11 => bad.cases[4].concurrency = None,
            12 => {
                bad.cases[4]
                    .concurrency
                    .as_mut()
                    .unwrap()
                    .source
                    .writer_bytes = 0;
            }
            13 => bad.cases[0].performance_max_seconds = Some(1),
            14 => bad.schema_version = 1,
            15 => bad.kind = "workspace_d1_transition_qualification_v1".into(),
            16 => bad.cases.last_mut().unwrap().failure_sentinel = None,
            _ => {
                bad.cases
                    .last_mut()
                    .unwrap()
                    .after_population_inventory
                    .inventory
                    .sha256 = digest('b');
            }
        }
        assert!(
            bad.validate(&identity(), 1024).is_err(),
            "qualification mutation {mutation} must be rejected"
        );
    }
}

#[test]
fn atomic_chain_rejects_replay_identity_swap_and_missing_terminal_receipt() {
    let prepared = checkpoint();
    let intent = prepared.advance(Event::Dispatch, None, None).unwrap();
    let committed = intent
        .advance(Event::Commit, Some(&digest('e')), Some(&digest('f')))
        .unwrap();
    let good = ExecutionRecord {
        schema_version: 1,
        kind: EXECUTION_KIND.into(),
        checkpoints: vec![prepared, intent.clone(), committed.clone()],
        checkpoint_evidence_hashes: vec![digest('a'), digest('b'), digest('c')],
    };
    assert_eq!(good.terminal().unwrap().stage, Stage::Committed);
    assert!(intent.advance(Event::Dispatch, None, None).is_err());
    assert!(committed.advance(Event::Dispatch, None, None).is_err());
    assert!(intent.advance(Event::Commit, None, None).is_err());
    for mutation in 0..7 {
        let mut bad = good.clone();
        match mutation {
            0 => bad.checkpoints[2].identity.database_id = "other".into(),
            1 => bad.checkpoints[2].baseline_evidence_hash = digest('f'),
            2 => {
                bad.checkpoints.remove(1);
            }
            3 => bad.checkpoints[2].previous_checkpoint_sha256 = Some(digest('a')),
            4 => {
                bad.checkpoint_evidence_hashes.pop();
            }
            5 => bad.checkpoint_evidence_hashes[1] = "caller claim".into(),
            _ => bad.checkpoint_evidence_hashes[1] = bad.checkpoint_evidence_hashes[0].clone(),
        }
        assert!(bad.terminal().is_err());
    }
}

#[test]
fn ambiguous_execution_only_accepts_reconciliation_and_stays_terminal() {
    let prepared = checkpoint();
    let intent = prepared.advance(Event::Dispatch, None, None).unwrap();
    let uncertain = intent.advance(Event::Ambiguous, None, None).unwrap();
    assert!(
        uncertain
            .advance(Event::Commit, Some(&digest('a')), Some(&digest('b')))
            .is_err()
    );
    let terminal = uncertain
        .advance(
            Event::ReconciledRollback,
            Some(&digest('a')),
            Some(&digest('b')),
        )
        .unwrap();
    ExecutionRecord {
        schema_version: 1,
        kind: EXECUTION_KIND.into(),
        checkpoints: vec![prepared, intent, uncertain, terminal],
        checkpoint_evidence_hashes: vec![digest('a'), digest('b'), digest('c'), digest('d')],
    }
    .terminal()
    .unwrap();
}

#[test]
fn typed_import_terminal_rejects_other_operation_database_digest_and_outcome() {
    let prepared = checkpoint();
    let intent = prepared.advance(Event::Dispatch, None, None).unwrap();
    let terminal = intent
        .advance(Event::Commit, Some(&digest('e')), Some(&digest('f')))
        .unwrap();
    let receipt = TransportReceipt {
        schema_version: 1,
        kind: TRANSPORT_RECEIPT_KIND.into(),
        operation_id: terminal.operation_id.clone(),
        database_id: terminal.identity.database_id.clone(),
        transport: TRANSPORT.into(),
        execution_sha256: terminal.identity.execution_sha256.clone(),
        stage: Stage::Committed,
        bookmark_sha256: digest('f'),
        provider_error_evidence_hash: None,
        continuation: None,
    };
    receipt
        .validate(&terminal, &terminal.identity.database_id)
        .unwrap();
    for mutation in 0..6 {
        let mut bad = receipt.clone();
        match mutation {
            0 => bad.operation_id = "other".into(),
            1 => bad.database_id = "other".into(),
            2 => bad.execution_sha256 = digest('b'),
            3 => bad.stage = Stage::RolledBack,
            4 => bad.bookmark_sha256 = digest('a'),
            _ => bad.provider_error_evidence_hash = Some(digest('b')),
        }
        assert!(
            bad.validate(&terminal, &terminal.identity.database_id)
                .is_err()
        );
    }
}
