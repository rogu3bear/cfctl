#![allow(clippy::expect_used)]

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use crate::MemorySecretStore;

use super::*;

#[derive(Default)]
struct PlatformMemoryStore {
    inner: MemorySecretStore,
    fail_active_pointer_before_write: AtomicBool,
    fail_next_put_after_write: AtomicBool,
    puts: AtomicUsize,
}

impl SecretStore for PlatformMemoryStore {
    fn put(&self, key: &str, value: &str) -> Result<()> {
        self.puts.fetch_add(1, Ordering::AcqRel);
        if value.contains("\"phase\":\"active\"")
            && self
                .fail_active_pointer_before_write
                .swap(false, Ordering::AcqRel)
        {
            return Err(AuthError::SecretStore(
                "injected crash before active pointer publication".to_owned(),
            ));
        }
        self.inner.put(key, value)?;
        if self.fail_next_put_after_write.swap(false, Ordering::AcqRel) {
            return Err(AuthError::SecretStore(
                "injected response loss after publication".to_owned(),
            ));
        }
        Ok(())
    }

    fn get(&self, key: &str) -> Result<Option<String>> {
        self.inner.get(key)
    }

    fn delete(&self, key: &str) -> Result<()> {
        self.inner.delete(key)
    }

    fn locate(&self, key: &str) -> Result<Option<SecretBackend>> {
        Ok(self.inner.get(key)?.map(|_| SecretBackend::PlatformKeyring))
    }
}

fn acceptance(cdhash: char) -> EvidenceKeyAdoptionAcceptanceV1 {
    EvidenceKeyAdoptionAcceptanceV1::operator_supplied(
        format!("git:{}", "1".repeat(40)),
        format!("sha256:{}", "2".repeat(64)),
        "arm64".to_owned(),
        cdhash.to_string().repeat(40),
        "sha256-truncated-20".to_owned(),
        format!("sha256:{}", "3".repeat(64)),
    )
    .expect("operator acceptance")
}

fn runtime(
    acceptance: &EvidenceKeyAdoptionAcceptanceV1,
    state: &str,
) -> EvidenceKeyAdoptionRuntimeIdentityV1 {
    EvidenceKeyAdoptionRuntimeIdentityV1 {
        validation_provider: "injected_native_provider".to_owned(),
        requirement_text: acceptance.requirement_text.clone(),
        requirement_sha256: acceptance.requirement_sha256.clone(),
        dynamic_self_validation: state.to_owned(),
        protocol_identity: EVIDENCE_KEY_ADOPTION_PROTOCOL_ID.to_owned(),
    }
}

fn clock(boot: &str, monotonic_ns: u64, wall_seconds: i64) -> EvidenceKeyAdoptionClockV1 {
    EvidenceKeyAdoptionClockV1 {
        boot_identity: boot.to_owned(),
        monotonic_ns,
        wall_at: DateTime::from_timestamp(wall_seconds, 0).expect("test timestamp"),
    }
}

fn observation(
    acceptance: &EvidenceKeyAdoptionAcceptanceV1,
    state: &str,
    marker: Option<&str>,
    clock: EvidenceKeyAdoptionClockV1,
) -> EvidenceKeyAdoptionObservationV1 {
    EvidenceKeyAdoptionObservationV1 {
        marker_identity: marker.map(str::to_owned),
        authenticated_descriptor_count: 0,
        authenticated_proof_count: 0,
        runtime: runtime(acceptance, state),
        clock,
    }
}

fn manager() -> (Arc<PlatformMemoryStore>, EvidenceKeyManager, String) {
    let store = Arc::new(PlatformMemoryStore::default());
    let manager = EvidenceKeyManager::new(
        store.clone(),
        format!("sha256:{}", "4".repeat(64)),
        SecretBackend::PlatformKeyring,
    )
    .expect("manager");
    let root = format!("sha256:{}", "5".repeat(64));
    manager.initialize(&root).expect("valid authority");
    (store, manager, root)
}

#[test]
fn six_state_projection_is_marker_time_runtime_and_terminal_aware() {
    let (_store, manager, root) = manager();
    let accepted = acceptance('a');
    let created = observation(&accepted, "satisfied", None, clock("boot-a", 100, 1_000));
    let plan = manager
        .create_adoption_plan(&created, accepted.clone())
        .expect("plan creates");
    assert_eq!(plan.state, "prepared");
    assert_eq!(plan.accepted_runtime.admission_source, "operator_supplied");

    let expired = observation(
        &accepted,
        "satisfied",
        None,
        clock("boot-a", 900_000_000_100, 1_899),
    );
    assert_eq!(
        manager
            .adoption_plan_status(&plan.plan_id, &expired)
            .expect("expiry status")
            .state,
        "expired"
    );
    let rollback = observation(&accepted, "satisfied", None, clock("boot-a", 99, 999));
    assert_eq!(
        manager
            .adoption_plan_status(&plan.plan_id, &rollback)
            .expect("rollback status")
            .state,
        "indeterminate"
    );
    let runtime_conflict = observation(
        &accepted,
        "not_satisfied",
        None,
        clock("boot-a", 101, 1_001),
    );
    assert_eq!(
        manager
            .adoption_plan_status(&plan.plan_id, &runtime_conflict)
            .expect("runtime status")
            .state,
        "conflict"
    );
    assert!(
        manager
            .prepare_adoption(&plan.plan_id, &runtime_conflict)
            .is_err()
    );

    let committed_marker = observation(
        &accepted,
        "satisfied",
        Some(&root),
        clock("boot-a", 101, 1_001),
    );
    manager
        .commit_adoption_marker_crossing(&plan.plan_id, &committed_marker)
        .expect("crossing commitment");

    let crossed_after_boot = observation(
        &accepted,
        "indeterminate",
        Some(&root),
        clock("boot-b", 1, 20_000),
    );
    assert_eq!(
        manager
            .adoption_plan_status(&plan.plan_id, &crossed_after_boot)
            .expect("crossed status is forward-only")
            .state,
        "marker_crossed"
    );
    let conflict = observation(
        &accepted,
        "satisfied",
        Some("sha256:conflicting-marker"),
        clock("boot-a", 101, 1_001),
    );
    assert_eq!(
        manager
            .adoption_plan_status(&plan.plan_id, &conflict)
            .expect("marker conflict")
            .state,
        "conflict"
    );

    let crossed = observation(
        &accepted,
        "satisfied",
        Some(&root),
        clock("boot-a", 102, 1_002),
    );
    manager
        .complete_adoption_plan(&plan.plan_id, &crossed)
        .expect("completion");
    assert_eq!(
        manager
            .adoption_plan_status(&plan.plan_id, &crossed)
            .expect("completed status")
            .state,
        "completed"
    );
}

#[test]
fn revoked_and_expired_history_remains_id_addressable_across_successors() {
    let (_store, manager, _root) = manager();
    let first_acceptance = acceptance('a');
    let first_observation = observation(
        &first_acceptance,
        "satisfied",
        None,
        clock("boot-a", 100, 1_000),
    );
    let first = manager
        .create_adoption_plan(&first_observation, first_acceptance.clone())
        .expect("first plan");
    let revoked = manager
        .revoke_adoption_plan(&first.plan_id, &first_observation)
        .expect("revoke");
    assert_eq!(revoked.state, "revoked");

    let second_acceptance = acceptance('b');
    let second_observation = observation(
        &second_acceptance,
        "satisfied",
        None,
        clock("boot-a", 200, 1_100),
    );
    let second = manager
        .create_adoption_plan(&second_observation, second_acceptance.clone())
        .expect("successor plan");
    assert_ne!(first.plan_id, second.plan_id);
    assert_eq!(
        manager
            .adoption_plan_status(&first.plan_id, &first_observation)
            .expect("historical revoked plan")
            .state,
        "revoked"
    );

    let second_expired = observation(
        &second_acceptance,
        "satisfied",
        None,
        clock("boot-a", 900_000_000_200, 2_000),
    );
    assert_eq!(
        manager
            .adoption_plan_status(&second.plan_id, &second_expired)
            .expect("historical expiry")
            .state,
        "expired"
    );
    let third_acceptance = acceptance('c');
    manager
        .create_adoption_plan(
            &observation(
                &third_acceptance,
                "satisfied",
                None,
                clock("boot-a", 900_000_000_201, 2_001),
            ),
            third_acceptance,
        )
        .expect("successor after expiry");
    assert_eq!(
        manager
            .adoption_plan_status(&second.plan_id, &second_expired)
            .expect("expired record remains addressable")
            .state,
        "expired"
    );
}

#[test]
fn expired_history_cannot_complete_after_successor_crosses_shared_marker() {
    let (store, manager, root) = manager();
    let first_acceptance = acceptance('a');
    let first_created = observation(
        &first_acceptance,
        "satisfied",
        None,
        clock("boot-a", 100, 1_000),
    );
    let first = manager
        .create_adoption_plan(&first_created, first_acceptance.clone())
        .expect("first plan");
    let first_expired = observation(
        &first_acceptance,
        "satisfied",
        None,
        clock("boot-a", 900_000_000_100, 1_900),
    );
    assert_eq!(
        manager
            .adoption_plan_status(&first.plan_id, &first_expired)
            .expect("first plan expires")
            .state,
        "expired"
    );

    let successor_acceptance = acceptance('b');
    let successor_created = observation(
        &successor_acceptance,
        "satisfied",
        None,
        clock("boot-a", 900_000_000_101, 1_901),
    );
    let successor = manager
        .create_adoption_plan(&successor_created, successor_acceptance.clone())
        .expect("successor plan");
    manager
        .prepare_adoption(&successor.plan_id, &successor_created)
        .expect("current successor prepares");
    let successor_crossed = observation(
        &successor_acceptance,
        "satisfied",
        Some(&root),
        clock("boot-a", 900_000_000_102, 1_902),
    );
    manager
        .commit_adoption_marker_crossing(&successor.plan_id, &successor_crossed)
        .expect("successor crossing commitment");
    assert_eq!(
        manager
            .adoption_plan_status(&successor.plan_id, &successor_crossed)
            .expect("current successor owns crossed marker")
            .state,
        "marker_crossed"
    );

    let historical_crossed = observation(
        &first_acceptance,
        "satisfied",
        Some(&root),
        clock("boot-a", 900_000_000_103, 1_903),
    );
    assert_eq!(
        manager
            .adoption_plan_status(&first.plan_id, &historical_crossed)
            .expect("historical status remains readable")
            .state,
        "conflict",
        "the authority-wide marker cannot make a historical record executable"
    );
    manager
        .prepare_adoption(&first.plan_id, &historical_crossed)
        .expect_err("historical plan cannot resume through successor marker");
    manager
        .complete_adoption_plan(&first.plan_id, &historical_crossed)
        .expect_err("historical plan cannot create a false completion receipt");
    assert_eq!(
        store
            .inner
            .get(
                &manager
                    .terminal_key(&first.plan_id, "completed")
                    .expect("historical terminal key"),
            )
            .expect("historical terminal readback"),
        None
    );
}

#[test]
fn marker_requires_a_durable_pre_expiry_crossing_commitment() {
    let (_store, manager, root) = manager();
    let accepted = acceptance('a');
    let created = observation(&accepted, "satisfied", None, clock("boot-a", 100, 1_000));
    let plan = manager
        .create_adoption_plan(&created, accepted.clone())
        .expect("plan");
    let expired_marker = observation(
        &accepted,
        "satisfied",
        Some(&root),
        clock("boot-a", 900_000_000_100, 1_900),
    );
    EvidenceMacProvider::status(&manager, Some(&root))
        .expect_err("an unsealed adoption blocks ordinary authority status");
    manager
        .authenticate(&root, "test-domain", b"payload")
        .expect_err("an unsealed adoption blocks new authenticated evidence");
    assert_eq!(
        manager
            .adoption_plan_status(&plan.plan_id, &expired_marker)
            .expect("matching marker without commitment is classified")
            .state,
        "conflict"
    );
    manager
        .complete_adoption_plan(&plan.plan_id, &expired_marker)
        .expect_err("an uncommitted marker cannot authorize completion");
}

#[test]
fn crossing_commitment_is_admitted_before_expiry_and_recovers_forward_after_expiry() {
    let (_store, manager, root) = manager();
    let accepted = acceptance('a');
    let created = observation(&accepted, "satisfied", None, clock("boot-a", 100, 1_000));
    let plan = manager
        .create_adoption_plan(&created, accepted.clone())
        .expect("plan");
    let before_deadline = observation(
        &accepted,
        "satisfied",
        Some(&root),
        clock("boot-a", 900_000_000_099, 1_899),
    );
    let committed = manager
        .commit_adoption_marker_crossing(&plan.plan_id, &before_deadline)
        .expect("crossing commitment");
    assert_eq!(committed.state, "marker_crossed");
    EvidenceMacProvider::status(&manager, Some(&root))
        .expect("sealed marker re-enables ordinary authority status");

    let after_reboot = observation(
        &accepted,
        "satisfied",
        Some(&root),
        clock("boot-b", 1, 2_000),
    );
    assert_eq!(
        manager
            .adoption_plan_status(&plan.plan_id, &after_reboot)
            .expect("committed crossing survives expiry and reboot")
            .state,
        "marker_crossed"
    );
    assert_eq!(
        manager
            .complete_adoption_plan(&plan.plan_id, &after_reboot)
            .expect("same plan completes forward")
            .state,
        "completed"
    );
}

#[test]
fn deadline_equality_cannot_seal_a_crossed_marker() {
    let (_store, manager, root) = manager();
    let accepted = acceptance('a');
    let created = observation(&accepted, "satisfied", None, clock("boot-a", 100, 1_000));
    let plan = manager
        .create_adoption_plan(&created, accepted.clone())
        .expect("plan");
    let at_deadline = observation(
        &accepted,
        "satisfied",
        Some(&root),
        clock("boot-a", 900_000_000_100, 1_900),
    );
    manager
        .commit_adoption_marker_crossing(&plan.plan_id, &at_deadline)
        .expect_err("deadline equality expires authorization");

    let successor_acceptance = acceptance('b');
    let successor = manager
        .create_adoption_plan(
            &observation(
                &successor_acceptance,
                "satisfied",
                None,
                clock("boot-a", 900_000_000_101, 1_901),
            ),
            successor_acceptance,
        )
        .expect("expired uncommitted plan permits successor");
    assert_ne!(successor.plan_id, plan.plan_id);
}

#[test]
fn crossing_commitment_blocks_successor_while_marker_is_absent() {
    let (_store, manager, root) = manager();
    let accepted = acceptance('a');
    let created = observation(&accepted, "satisfied", None, clock("boot-a", 100, 1_000));
    let plan = manager
        .create_adoption_plan(&created, accepted.clone())
        .expect("plan");
    let crossed = observation(
        &accepted,
        "satisfied",
        Some(&root),
        clock("boot-a", 101, 1_001),
    );
    manager
        .commit_adoption_marker_crossing(&plan.plan_id, &crossed)
        .expect("crossing commitment");

    let successor_acceptance = acceptance('b');
    manager
        .create_adoption_plan(
            &observation(
                &successor_acceptance,
                "satisfied",
                None,
                clock("boot-b", 1, 2_000),
            ),
            successor_acceptance,
        )
        .expect_err("forward-only crossing commitment blocks a successor");
}

#[test]
fn crossing_commitment_reconciles_only_exact_response_lost_publication() {
    let (store, manager, root) = manager();
    let accepted = acceptance('a');
    let created = observation(&accepted, "satisfied", None, clock("boot-a", 100, 1_000));
    let plan = manager
        .create_adoption_plan(&created, accepted)
        .expect("plan");
    let crossed = observation(
        &acceptance('a'),
        "satisfied",
        Some(&root),
        clock("boot-a", 101, 1_001),
    );
    store
        .fail_next_put_after_write
        .store(true, Ordering::Release);
    let committed = manager
        .commit_adoption_marker_crossing(&plan.plan_id, &crossed)
        .expect("exact readback reconciles response loss");
    assert_eq!(committed.state, "marker_crossed");

    let public = serde_json::to_string(&committed).expect("public plan json");
    for private_field in [
        "\"record_sha256\":",
        "\"generation\":",
        "\"predecessor_pointer_sha256\":",
        "\"monotonic_observed_ns\":",
        "\"wall_observed_at\":",
    ] {
        assert!(!public.contains(private_field));
    }
}

#[test]
fn response_loss_is_reconciled_and_one_allocating_orphan_recovers_exactly() {
    let (store, manager, _root) = manager();
    let accepted = acceptance('d');
    let observed = observation(&accepted, "satisfied", None, clock("boot-a", 100, 1_000));
    store
        .fail_next_put_after_write
        .store(true, Ordering::Release);
    let first = manager
        .create_adoption_plan(&observed, accepted.clone())
        .expect("response-lost write reconciles by exact readback");
    manager
        .revoke_adoption_plan(&first.plan_id, &observed)
        .expect("first plan revokes");

    let successor = acceptance('e');
    let successor_observation =
        observation(&successor, "satisfied", None, clock("boot-a", 200, 1_100));
    store
        .fail_active_pointer_before_write
        .store(true, Ordering::Release);
    manager
        .create_adoption_plan(&successor_observation, successor.clone())
        .expect_err("crash leaves one allocating pointer and exact record");
    let recovered = manager
        .create_adoption_plan(&successor_observation, successor.clone())
        .expect("same admission recovers the exact allocating orphan");
    assert_eq!(recovered.state, "prepared");
    assert!(
        manager
            .create_adoption_plan(&successor_observation, acceptance('f'))
            .is_err(),
        "a different admission cannot capture the orphan"
    );
}

#[test]
fn immutable_record_precedes_pointer_and_record_only_crash_allows_fresh_create() {
    for (crash_stage, inject_response_loss) in [
        (AdoptionPlanPersistenceStage::RecordReadback, false),
        (
            AdoptionPlanPersistenceStage::RecordResponseLossReconciled,
            true,
        ),
    ] {
        let (store, manager, _root) = manager();
        let accepted = acceptance('d');
        let observed = observation(&accepted, "satisfied", None, clock("boot-a", 100, 1_000));
        if inject_response_loss {
            store
                .fail_next_put_after_write
                .store(true, Ordering::Release);
        }
        let puts_before = store.puts.load(Ordering::Acquire);
        manager
            .create_adoption_plan_with_hook(&observed, accepted, |stage| {
                if stage == crash_stage {
                    Err(AuthError::SecretStore(format!(
                        "injected crash at {stage:?}"
                    )))
                } else {
                    Ok(())
                }
            })
            .expect_err("record-only crash must interrupt before pointer publication");
        assert_eq!(
            store.puts.load(Ordering::Acquire) - puts_before,
            1,
            "only the create-only record may cross before the pointer"
        );
        assert_eq!(
            manager
                .current_adoption_plan_id()
                .expect("current allocation classification"),
            None,
            "a record without a pointer is not a discoverable allocation"
        );

        let successor = acceptance('e');
        let successor_observation =
            observation(&successor, "satisfied", None, clock("boot-a", 200, 1_100));
        manager
            .create_adoption_plan(&successor_observation, successor)
            .expect("an undiscoverable record-only orphan cannot wedge fresh creation");
    }
}

#[test]
fn allocating_pointer_without_record_is_no_allocation_and_can_be_replaced_exactly() {
    let (store, manager, _root) = manager();
    let accepted = acceptance('d');
    let observed = observation(&accepted, "satisfied", None, clock("boot-a", 100, 1_000));
    manager
        .create_adoption_plan_with_hook(&observed, accepted, |stage| {
            if stage == AdoptionPlanPersistenceStage::AllocatingPointerReadback {
                Err(AuthError::SecretStore(
                    "injected crash after allocating pointer readback".to_owned(),
                ))
            } else {
                Ok(())
            }
        })
        .expect_err("allocating pointer crash must interrupt");
    let stale_pointer = manager
        .load_pointer()
        .expect("stale pointer read")
        .expect("stale allocating pointer");
    store
        .inner
        .delete(
            &manager
                .record_key(&stale_pointer.plan_id)
                .expect("stale record key"),
        )
        .expect("simulate the legacy pointer-before-record crash boundary");
    assert_eq!(
        manager
            .current_adoption_plan_id()
            .expect("current allocation classification"),
        None,
        "a pointer without its immutable record is not an allocation"
    );

    let successor = acceptance('e');
    let successor_observation =
        observation(&successor, "satisfied", None, clock("boot-a", 200, 1_100));
    let created = manager
        .create_adoption_plan(&successor_observation, successor)
        .expect("fresh creation must replace the exact stale pointer slot");
    assert_ne!(created.plan_id, stale_pointer.plan_id);
    let replacement = manager
        .load_pointer()
        .expect("replacement pointer read")
        .expect("replacement pointer");
    assert_eq!(replacement.generation, stale_pointer.generation + 1);
    assert_eq!(
        replacement.predecessor_pointer_sha256,
        Some(pointer_digest(&stale_pointer).expect("stale pointer digest")),
        "fresh recovery remains authenticated to the exact interrupted pointer"
    );
}

#[test]
fn allocating_pointer_cannot_seal_project_crossed_or_enable_authority() {
    let (store, manager, root) = manager();
    let accepted = acceptance('d');
    let prepared = observation(&accepted, "satisfied", None, clock("boot-a", 100, 1_000));
    manager
        .create_adoption_plan_with_hook(&prepared, accepted.clone(), |stage| {
            if stage == AdoptionPlanPersistenceStage::AllocatingPointerReadback {
                Err(AuthError::SecretStore(
                    "injected crash with a record-backed allocating pointer".to_owned(),
                ))
            } else {
                Ok(())
            }
        })
        .expect_err("allocation crash remains recoverable but inactive");
    let pointer = manager
        .load_pointer()
        .expect("pointer read")
        .expect("allocating pointer");
    assert_eq!(pointer.phase, "allocating");
    let crossed = observation(
        &accepted,
        "satisfied",
        Some(root.as_str()),
        clock("boot-a", 101, 1_001),
    );
    let puts_before = store.puts.load(Ordering::Acquire);

    let error = manager
        .commit_adoption_marker_crossing(&pointer.plan_id, &crossed)
        .expect_err("allocating pointer cannot publish a crossing seal");

    assert!(error.to_string().contains("exact active plan pointer"));
    assert_eq!(store.puts.load(Ordering::Acquire), puts_before);
    let record = manager
        .load_record(&pointer.plan_id)
        .expect("immutable record");
    let commitment = CrossingCommitmentV1 {
        version: CROSSING_COMMITMENT_VERSION,
        plan_id: record.plan_id.clone(),
        record_sha256: sha256(
            serde_json::to_string(&record)
                .expect("record encoding")
                .as_bytes(),
        ),
        generation: record.generation,
        predecessor_pointer_sha256: record.predecessor_pointer_sha256.clone(),
        boot_identity: "boot-a".to_owned(),
        monotonic_observed_ns: 101,
        wall_observed_at: clock("boot-a", 101, 1_001).wall_at,
    };
    store
        .inner
        .put(
            &manager
                .crossing_commitment_key(&pointer.plan_id)
                .expect("commitment key"),
            &serde_json::to_string(&commitment).expect("commitment encoding"),
        )
        .expect("inject otherwise valid seal against allocating pointer");
    assert_eq!(
        manager
            .adoption_plan_status(&pointer.plan_id, &crossed)
            .expect("historical state remains inspectable")
            .state,
        "conflict"
    );
    assert!(
        !manager
            .adoption_crossing_is_sealed_or_absent()
            .expect("ordinary authority gate remains closed")
    );
}

#[test]
fn allocating_pointer_recovers_after_every_persistence_boundary() {
    let cases = [
        AdoptionPlanPersistenceStage::AllocatingPointerReadback,
        AdoptionPlanPersistenceStage::AllocatingPointerResponseLossReconciled,
        AdoptionPlanPersistenceStage::BeforeActivePointerPublication,
        AdoptionPlanPersistenceStage::ActivePointerResponseLossReconciled,
        AdoptionPlanPersistenceStage::ActivePointerReadback,
    ];
    for crash_stage in cases {
        let (store, manager, _root) = manager();
        let accepted = acceptance('d');
        let observed = observation(&accepted, "satisfied", None, clock("boot-a", 100, 1_000));
        let crashed =
            manager.create_adoption_plan_with_hook(&observed, accepted.clone(), |stage| {
                if crash_stage
                    == AdoptionPlanPersistenceStage::AllocatingPointerResponseLossReconciled
                    && stage == AdoptionPlanPersistenceStage::RecordReadback
                {
                    store
                        .fail_next_put_after_write
                        .store(true, Ordering::Release);
                }
                if crash_stage == AdoptionPlanPersistenceStage::ActivePointerResponseLossReconciled
                    && stage == AdoptionPlanPersistenceStage::BeforeActivePointerPublication
                {
                    store
                        .fail_next_put_after_write
                        .store(true, Ordering::Release);
                }
                if stage == crash_stage {
                    return Err(AuthError::SecretStore(format!(
                        "injected crash at {stage:?}"
                    )));
                }
                Ok(())
            });
        assert!(crashed.is_err(), "stage {crash_stage:?} must interrupt");
        let plan_id = manager
            .current_adoption_plan_id()
            .expect("pointer remains readable")
            .expect("pointer identity remains");
        let current = manager
            .adoption_plan_status(&plan_id, &observed)
            .expect("interrupted plan remains addressable");
        assert!(
            matches!(
                current.state.as_str(),
                "allocating_recoverable" | "prepared"
            ),
            "stage {crash_stage:?} projected {}",
            current.state
        );
        assert!(
            manager
                .create_adoption_plan(&observed, acceptance('e'))
                .is_err(),
            "different admission must not capture stage {crash_stage:?}"
        );
        let recovered = manager
            .create_adoption_plan(&observed, accepted.clone())
            .expect("identical admission resumes");
        assert_eq!(recovered.plan_id, plan_id);
        assert_eq!(recovered.state, "prepared");
        let replay = manager
            .create_adoption_plan(&observed, accepted.clone())
            .expect("identical active replay is idempotent");
        assert_eq!(replay.plan_id, plan_id);
    }
}

#[test]
fn conflicting_record_never_overwrites_allocating_pointer_evidence() {
    let (store, manager, _root) = manager();
    let accepted = acceptance('d');
    let observed = observation(&accepted, "satisfied", None, clock("boot-a", 100, 1_000));
    manager
        .create_adoption_plan_with_hook(&observed, accepted.clone(), |stage| {
            if stage == AdoptionPlanPersistenceStage::AllocatingPointerReadback {
                Err(AuthError::SecretStore("injected crash".to_owned()))
            } else {
                Ok(())
            }
        })
        .expect_err("pointer-only state injected");
    let pointer = manager
        .load_pointer()
        .expect("pointer read")
        .expect("allocating pointer");
    let key = manager.record_key(&pointer.plan_id).expect("record key");
    store
        .inner
        .put(&key, "{\"conflicting\":true}")
        .expect("inject collision");
    let puts_before = store.puts.load(Ordering::Acquire);
    assert!(manager.create_adoption_plan(&observed, accepted).is_err());
    assert_eq!(store.puts.load(Ordering::Acquire), puts_before);
    assert_eq!(
        store.inner.get(&key).expect("record readback").as_deref(),
        Some("{\"conflicting\":true}")
    );
}

#[test]
fn malformed_public_acceptance_is_rejected_before_any_persistence_write() {
    let (store, manager, _root) = manager();
    let valid = acceptance('a');
    let observed = observation(&valid, "satisfied", None, clock("boot-a", 100, 1_000));
    let mut malformed = Vec::new();
    let mut value = valid.clone();
    value.admission_source = "derived".to_owned();
    malformed.push(value);
    let mutations: [fn(&mut EvidenceKeyAdoptionAcceptanceV1); 10] = [
        |value: &mut EvidenceKeyAdoptionAcceptanceV1| {
            value.source_candidate_identity.clear();
        },
        |value: &mut EvidenceKeyAdoptionAcceptanceV1| {
            value.source_candidate_identity = "git:bad identity".to_owned();
        },
        |value: &mut EvidenceKeyAdoptionAcceptanceV1| {
            value.installed_artifact_identity = "sha256:bad".to_owned();
        },
        |value: &mut EvidenceKeyAdoptionAcceptanceV1| {
            value.expected_architecture = " ".to_owned();
        },
        |value: &mut EvidenceKeyAdoptionAcceptanceV1| {
            value.expected_running_cdhash = "f".repeat(39);
        },
        |value: &mut EvidenceKeyAdoptionAcceptanceV1| {
            value.expected_cdhash_algorithm.clear();
        },
        |value: &mut EvidenceKeyAdoptionAcceptanceV1| {
            value.expected_cdhash_full_digest_provenance = "bad provenance".to_owned();
        },
        |value: &mut EvidenceKeyAdoptionAcceptanceV1| {
            value.requirement_text.push(' ');
        },
        |value: &mut EvidenceKeyAdoptionAcceptanceV1| {
            value.requirement_utf8_hex = "00".to_owned();
        },
        |value: &mut EvidenceKeyAdoptionAcceptanceV1| {
            value.requirement_sha256 = format!("sha256:{}", "0".repeat(64));
        },
    ];
    for mutate in mutations {
        let mut value = valid.clone();
        mutate(&mut value);
        malformed.push(value);
    }
    let puts_before = store.puts.load(Ordering::Acquire);
    for candidate in malformed {
        let serialized = serde_json::to_string(&candidate).expect("public value serializes");
        let deserialized: EvidenceKeyAdoptionAcceptanceV1 =
            serde_json::from_str(&serialized).expect("public value deserializes");
        assert!(
            manager
                .create_adoption_plan(&observed, deserialized)
                .is_err(),
            "malformed acceptance must fail at persistence boundary: {serialized}"
        );
        assert_eq!(store.puts.load(Ordering::Acquire), puts_before);
    }
}

#[test]
fn dual_terminal_or_record_drift_is_never_projected_as_completed() {
    let (store, manager, root) = manager();
    let accepted = acceptance('a');
    let created = observation(&accepted, "satisfied", None, clock("boot-a", 100, 1_000));
    let plan = manager
        .create_adoption_plan(&created, accepted.clone())
        .expect("plan");
    let crossed = observation(
        &accepted,
        "satisfied",
        Some(&root),
        clock("boot-a", 101, 1_001),
    );
    manager
        .commit_adoption_marker_crossing(&plan.plan_id, &crossed)
        .expect("crossing commitment");
    manager
        .complete_adoption_plan(&plan.plan_id, &crossed)
        .expect("completed terminal");
    let record = manager.load_record(&plan.plan_id).expect("record");
    let revoked = TerminalV1 {
        version: EVIDENCE_KEY_ADOPTION_TERMINAL_VERSION,
        plan_id: plan.plan_id.clone(),
        record_sha256: sha256(
            serde_json::to_string(&record)
                .expect("record json")
                .as_bytes(),
        ),
        outcome: "revoked".to_owned(),
        at: crossed.clock.wall_at,
    };
    store
        .inner
        .put(
            &manager
                .terminal_key(&plan.plan_id, "revoked")
                .expect("terminal key"),
            &serde_json::to_string(&revoked).expect("terminal json"),
        )
        .expect("inject conflicting immutable event");
    assert!(
        manager
            .adoption_plan_status(&plan.plan_id, &crossed)
            .is_err()
    );
}
