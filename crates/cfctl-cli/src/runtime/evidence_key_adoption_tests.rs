//! Work192 focused provider and command-contract tests.

#![allow(clippy::expect_used)]

use cfctl_auth::EvidenceKeyAdoptionAcceptanceV1;
use cfctl_auth::{EvidenceKeyManager, MemorySecretStore, SecretBackend, SecretStore};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::{cell::RefCell, rc::Rc};

use super::{
    AdoptionExecutionStage, AdoptionRuntimeEvaluationStage, EvidenceKeyAdoptArgs, StateStore,
    adopt_with_marker_write, adopt_with_runtime_provider_and_marker_write, adoption_observation,
    classify_native_self_validation, parse_macos_boot_time, runtime_result,
};

#[derive(Default)]
struct PlatformMemoryStore {
    inner: MemorySecretStore,
    puts: AtomicUsize,
    deletes: AtomicUsize,
}

impl SecretStore for PlatformMemoryStore {
    fn put(&self, key: &str, value: &str) -> cfctl_auth::Result<()> {
        self.puts.fetch_add(1, Ordering::AcqRel);
        self.inner.put(key, value)
    }

    fn get(&self, key: &str) -> cfctl_auth::Result<Option<String>> {
        self.inner.get(key)
    }

    fn delete(&self, key: &str) -> cfctl_auth::Result<()> {
        self.deletes.fetch_add(1, Ordering::AcqRel);
        self.inner.delete(key)
    }

    fn locate(&self, key: &str) -> cfctl_auth::Result<Option<SecretBackend>> {
        Ok(self.inner.get(key)?.map(|_| SecretBackend::PlatformKeyring))
    }
}

fn acceptance(cdhash: &str) -> cfctl_auth::Result<EvidenceKeyAdoptionAcceptanceV1> {
    EvidenceKeyAdoptionAcceptanceV1::operator_supplied(
        "git:0123456789abcdef0123456789abcdef01234567".to_owned(),
        format!("sha256:{}", "a".repeat(64)),
        "arm64".to_owned(),
        cdhash.to_owned(),
        "sha256-truncated-20".to_owned(),
        format!("sha256:{}", "b".repeat(64)),
    )
}

#[test]
fn operator_cdhash_builds_one_exact_canonical_requirement_and_digest() {
    let accepted = acceptance("ABCDEF0123456789ABCDEF0123456789ABCDEF01")
        .expect("canonical operator admission");
    assert_eq!(
        accepted.expected_running_cdhash,
        "abcdef0123456789abcdef0123456789abcdef01"
    );
    assert_eq!(
        accepted.requirement_text,
        "cdhash H\"abcdef0123456789abcdef0123456789abcdef01\""
    );
    assert_eq!(
        accepted.requirement_utf8_hex,
        hex::encode(accepted.requirement_text.as_bytes())
    );
    assert_eq!(
        accepted.requirement_sha256,
        "sha256:8ce5ddaac0d4ba8832d53aaf532e1876c363c4b55b582c4ebdf96396af201d08"
    );
    assert_eq!(accepted.admission_source, "operator_supplied");
}

#[test]
fn marker_crossing_is_forward_only_and_same_plan_reconciles_without_registry_change() {
    let root = tempfile::tempdir().expect("temporary state root");
    let state =
        StateStore::open(cfctl_storage::RuntimePaths::from_root(root.path())).expect("state store");
    let secrets = Arc::new(PlatformMemoryStore::default());
    let manager = EvidenceKeyManager::new(
        secrets.clone(),
        state.evidence_location_identity(),
        SecretBackend::PlatformKeyring,
    )
    .expect("manager");
    let state_root_identity = format!("sha256:{}", "5".repeat(64));
    manager
        .initialize(&state_root_identity)
        .expect("valid split authority");
    let registry_key = format!(
        "evidence-integrity/location/{}/registry-v1",
        state.evidence_location_identity()
    );
    let registry_before = secrets
        .inner
        .get(&registry_key)
        .expect("registry read")
        .expect("registry exists");
    let accepted = acceptance(&"a".repeat(40)).expect("accepted runtime");
    let runtime = runtime_result(&accepted, "injected_native_provider", "satisfied");
    let observation = adoption_observation(None, 0, 0, &runtime).expect("observation");
    let plan = manager
        .create_adoption_plan(&observation, accepted)
        .expect("plan");
    let puts_before_status = secrets.puts.load(Ordering::Acquire);
    manager
        .adoption_plan_status(&plan.plan_id, &observation)
        .expect("read-only status");
    assert_eq!(secrets.puts.load(Ordering::Acquire), puts_before_status);

    let crossed = adopt_with_marker_write(
        &state,
        &manager,
        &EvidenceKeyAdoptArgs {
            plan_id: plan.plan_id.clone(),
            yes: true,
        },
        &runtime,
        |identity| {
            state.initialize_evidence_root_identity(identity)?;
            Err(cfctl_storage::StorageError::WriteDurabilityUnknown {
                path: "evidence-root-v1.json".to_owned(),
                source: std::io::Error::other("injected response loss after marker creation"),
            })
        },
    )
    .expect_err("crossed marker reports interrupted completion");
    assert!(crossed.to_string().contains("same adoption plan"));

    let completed = adopt_with_marker_write(
        &state,
        &manager,
        &EvidenceKeyAdoptArgs {
            plan_id: plan.plan_id,
            yes: true,
        },
        &runtime,
        |identity| state.initialize_evidence_root_identity(identity),
    )
    .expect("same plan reconciles forward");
    assert_eq!(completed.result["receipt"]["state"], "completed");
    let replay = adopt_with_marker_write(
        &state,
        &manager,
        &EvidenceKeyAdoptArgs {
            plan_id: completed.result["receipt"]["plan_id"]
                .as_str()
                .expect("receipt plan id")
                .to_owned(),
            yes: true,
        },
        &runtime,
        |identity| state.initialize_evidence_root_identity(identity),
    )
    .expect("completed same-plan replay is idempotent");
    assert!(!replay.performed);
    assert_eq!(
        secrets.inner.get(&registry_key).expect("registry readback"),
        Some(registry_before)
    );
    assert_eq!(secrets.deletes.load(Ordering::Acquire), 0);
    assert_eq!(
        state.evidence_root_identity().expect("marker readback"),
        Some(state_root_identity)
    );
}

#[test]
fn runtime_evaluation_is_fresh_for_prepare_marker_and_completion() {
    let root = tempfile::tempdir().expect("temporary state root");
    let state =
        StateStore::open(cfctl_storage::RuntimePaths::from_root(root.path())).expect("state store");
    let secrets = Arc::new(PlatformMemoryStore::default());
    let manager = EvidenceKeyManager::new(
        secrets.clone(),
        state.evidence_location_identity(),
        SecretBackend::PlatformKeyring,
    )
    .expect("manager");
    let state_root_identity = format!("sha256:{}", "5".repeat(64));
    manager
        .initialize(&state_root_identity)
        .expect("valid split authority");
    let registry_key = format!(
        "evidence-integrity/location/{}/registry-v1",
        state.evidence_location_identity()
    );
    let registry_before = secrets
        .inner
        .get(&registry_key)
        .expect("registry read")
        .expect("registry exists");
    let accepted = acceptance(&"a".repeat(40)).expect("accepted runtime");
    let satisfied = runtime_result(&accepted, "injected_native_provider", "satisfied");
    let plan = manager
        .create_adoption_plan(
            &adoption_observation(None, 0, 0, &satisfied).expect("observation"),
            accepted.clone(),
        )
        .expect("plan");
    let puts_before_execute = secrets.puts.load(Ordering::Acquire);
    let events = Rc::new(RefCell::new(Vec::new()));
    let runtime_events = Rc::new(RefCell::new(Vec::new()));
    let call_order = Rc::new(RefCell::new(Vec::new()));
    let runtime_calls = Arc::new(AtomicUsize::new(0));
    let event_sink = events.clone();
    let runtime_event_sink = runtime_events.clone();
    let runtime_order_sink = call_order.clone();
    let stage_order_sink = call_order.clone();
    let call_count = runtime_calls.clone();
    let failed = adopt_with_runtime_provider_and_marker_write(
        &state,
        &manager,
        &EvidenceKeyAdoptArgs {
            plan_id: plan.plan_id.clone(),
            yes: true,
        },
        |acceptance, stage| {
            runtime_event_sink.borrow_mut().push(stage);
            runtime_order_sink.borrow_mut().push(match stage {
                AdoptionRuntimeEvaluationStage::Prepare => "runtime_prepare",
                AdoptionRuntimeEvaluationStage::MarkerCrossing => "runtime_marker",
                AdoptionRuntimeEvaluationStage::Completion => "runtime_completion",
            });
            let call = call_count.fetch_add(1, Ordering::AcqRel);
            runtime_result(
                acceptance,
                "injected_native_provider",
                if call < 2 { "satisfied" } else { "not_satisfied" },
            )
        },
        |identity| state.initialize_evidence_root_identity(identity),
        |stage| {
            event_sink.borrow_mut().push(stage);
            stage_order_sink.borrow_mut().push(match stage {
                AdoptionExecutionStage::LifecycleLockAcquired => "lock",
                AdoptionExecutionStage::PrepareRuntimeEvaluated => "prepare_evaluated",
                AdoptionExecutionStage::PrepareAccepted => "prepare_accepted",
                AdoptionExecutionStage::MarkerRuntimeEvaluated => "marker_evaluated",
                AdoptionExecutionStage::MarkerCrossed => "marker_crossed",
                AdoptionExecutionStage::CompletionRuntimeEvaluated => "completion_evaluated",
                AdoptionExecutionStage::TerminalCompleted => "terminal_completed",
            });
            Ok(())
        },
    )
    .expect_err("fresh completion validation mismatch denies completion");
    assert!(failed.to_string().contains("dynamic self-validation"));
    assert_eq!(
        runtime_calls.load(Ordering::Acquire),
        3,
        "prepare, marker crossing, and completion each require a fresh identity"
    );
    assert_eq!(
        runtime_events.borrow().as_slice(),
        [
            AdoptionRuntimeEvaluationStage::Prepare,
            AdoptionRuntimeEvaluationStage::MarkerCrossing,
            AdoptionRuntimeEvaluationStage::Completion,
        ]
    );
    assert_eq!(
        events.borrow().as_slice(),
        [
            AdoptionExecutionStage::LifecycleLockAcquired,
            AdoptionExecutionStage::PrepareRuntimeEvaluated,
            AdoptionExecutionStage::PrepareAccepted,
            AdoptionExecutionStage::MarkerRuntimeEvaluated,
            AdoptionExecutionStage::MarkerCrossed,
            AdoptionExecutionStage::CompletionRuntimeEvaluated,
        ]
    );
    assert_eq!(
        call_order.borrow().as_slice(),
        [
            "lock",
            "runtime_prepare",
            "prepare_evaluated",
            "prepare_accepted",
            "runtime_marker",
            "marker_evaluated",
            "marker_crossed",
            "runtime_completion",
            "completion_evaluated",
        ],
        "the lock precedes every runtime read and each protected transition receives a fresh read"
    );
    assert_eq!(
        state.evidence_root_identity().expect("marker readback"),
        Some(state_root_identity.clone())
    );
    assert_eq!(secrets.puts.load(Ordering::Acquire), puts_before_execute);
    assert_eq!(
        secrets.inner.get(&registry_key).expect("registry readback"),
        Some(registry_before.clone())
    );
    let marker_observation =
        adoption_observation(Some(state_root_identity.clone()), 0, 0, &satisfied)
            .expect("marker observation");
    assert_eq!(
        manager
            .adoption_plan_status(&plan.plan_id, &marker_observation)
            .expect("forward-only status")
            .state,
        "marker_crossed"
    );

    let resumed = adopt_with_marker_write(
        &state,
        &manager,
        &EvidenceKeyAdoptArgs {
            plan_id: plan.plan_id,
            yes: true,
        },
        &satisfied,
        |identity| state.initialize_evidence_root_identity(identity),
    )
    .expect("same plan resumes without re-authorizing or replacing authority");
    assert_eq!(resumed.result["receipt"]["state"], "completed");
    assert_eq!(
        secrets.inner.get(&registry_key).expect("registry readback"),
        Some(registry_before)
    );
}

#[test]
fn unsatisfied_prepare_never_crosses_marker_or_requests_completion_validation() {
    let root = tempfile::tempdir().expect("temporary state root");
    let state =
        StateStore::open(cfctl_storage::RuntimePaths::from_root(root.path())).expect("state store");
    let secrets = Arc::new(PlatformMemoryStore::default());
    let manager = EvidenceKeyManager::new(
        secrets,
        state.evidence_location_identity(),
        SecretBackend::PlatformKeyring,
    )
    .expect("manager");
    let state_root_identity = format!("sha256:{}", "5".repeat(64));
    manager
        .initialize(&state_root_identity)
        .expect("valid split authority");
    let accepted = acceptance(&"a".repeat(40)).expect("accepted runtime");
    let satisfied = runtime_result(&accepted, "injected_native_provider", "satisfied");
    let plan = manager
        .create_adoption_plan(
            &adoption_observation(None, 0, 0, &satisfied).expect("observation"),
            accepted,
        )
        .expect("plan");
    let runtime_calls = AtomicUsize::new(0);
    adopt_with_runtime_provider_and_marker_write(
        &state,
        &manager,
        &EvidenceKeyAdoptArgs {
            plan_id: plan.plan_id,
            yes: true,
        },
        |acceptance, _stage| {
            runtime_calls.fetch_add(1, Ordering::AcqRel);
            runtime_result(acceptance, "injected_native_provider", "not_satisfied")
        },
        |identity| state.initialize_evidence_root_identity(identity),
        |_| Ok(()),
    )
    .expect_err("unsatisfied prepare fails closed");
    assert_eq!(runtime_calls.load(Ordering::Acquire), 1);
    assert_eq!(
        state.evidence_root_identity().expect("marker readback"),
        None
    );
}

#[test]
fn unsatisfied_marker_validation_never_crosses_marker_or_requests_completion_validation() {
    let root = tempfile::tempdir().expect("temporary state root");
    let state =
        StateStore::open(cfctl_storage::RuntimePaths::from_root(root.path())).expect("state store");
    let secrets = Arc::new(PlatformMemoryStore::default());
    let manager = EvidenceKeyManager::new(
        secrets,
        state.evidence_location_identity(),
        SecretBackend::PlatformKeyring,
    )
    .expect("manager");
    let state_root_identity = format!("sha256:{}", "5".repeat(64));
    manager
        .initialize(&state_root_identity)
        .expect("valid split authority");
    let accepted = acceptance(&"a".repeat(40)).expect("accepted runtime");
    let satisfied = runtime_result(&accepted, "injected_native_provider", "satisfied");
    let plan = manager
        .create_adoption_plan(
            &adoption_observation(None, 0, 0, &satisfied).expect("observation"),
            accepted,
        )
        .expect("plan");
    let runtime_calls = AtomicUsize::new(0);
    adopt_with_runtime_provider_and_marker_write(
        &state,
        &manager,
        &EvidenceKeyAdoptArgs {
            plan_id: plan.plan_id,
            yes: true,
        },
        |acceptance, stage| {
            runtime_calls.fetch_add(1, Ordering::AcqRel);
            runtime_result(
                acceptance,
                "injected_native_provider",
                if stage == AdoptionRuntimeEvaluationStage::Prepare {
                    "satisfied"
                } else {
                    "not_satisfied"
                },
            )
        },
        |identity| state.initialize_evidence_root_identity(identity),
        |_| Ok(()),
    )
    .expect_err("unsatisfied marker-crossing validation fails closed");
    assert_eq!(runtime_calls.load(Ordering::Acquire), 2);
    assert_eq!(
        state.evidence_root_identity().expect("marker readback"),
        None
    );
}

#[test]
fn operator_cdhash_rejects_bad_length_non_hex_and_whitespace() {
    assert!(acceptance(&"a".repeat(39)).is_err());
    assert!(acceptance(&"a".repeat(41)).is_err());
    assert!(acceptance(&format!("{}g", "a".repeat(39))).is_err());
    assert!(acceptance(&format!(" {}", "a".repeat(40))).is_err());
}

#[test]
fn runtime_result_separates_accepted_metadata_from_dynamic_validation() {
    let accepted = acceptance(&"1".repeat(40)).expect("operator admission");
    let runtime = runtime_result(&accepted, "injected_native_provider", "satisfied");
    assert_eq!(runtime.requirement_text, accepted.requirement_text);
    assert_eq!(runtime.requirement_sha256, accepted.requirement_sha256);
    assert_eq!(runtime.dynamic_self_validation, "satisfied");
    assert_eq!(runtime.validation_provider, "injected_native_provider");
    let json = serde_json::to_string(&runtime).expect("runtime serializes");
    assert!(!json.contains("qualified"));
    assert!(!json.contains("observed_cdhash"));
    assert!(!json.contains("private-key-material"));
}

#[test]
fn native_requirement_parse_self_lookup_and_validity_fail_closed_by_stage() {
    assert_eq!(
        classify_native_self_validation(false, false, false),
        "indeterminate"
    );
    assert_eq!(
        classify_native_self_validation(true, false, false),
        "indeterminate"
    );
    assert_eq!(
        classify_native_self_validation(true, true, false),
        "not_satisfied"
    );
    assert_eq!(
        classify_native_self_validation(true, true, true),
        "satisfied"
    );
}

#[test]
fn macos_boottime_parser_accepts_exact_native_layout_and_ignores_padding() {
    let mut raw = [0_u8; 16];
    raw[0..8].copy_from_slice(&1_725_000_001_i64.to_ne_bytes());
    raw[8..12].copy_from_slice(&42_i32.to_ne_bytes());
    raw[12..16].copy_from_slice(&[7, 8, 9, 10]);
    assert_eq!(
        parse_macos_boot_time(&raw).expect("valid timeval tripwire"),
        "macos-kern-boottime:1725000001.000042"
    );
}

#[test]
fn macos_boottime_parser_fails_closed_on_layout_and_value_boundaries() {
    assert!(parse_macos_boot_time(&[0_u8; 15]).is_err());
    for (seconds, microseconds) in [(0_i64, 0_i32), (-1, 0), (1, -1), (1, 1_000_000)] {
        let mut raw = [0_u8; 16];
        raw[0..8].copy_from_slice(&seconds.to_ne_bytes());
        raw[8..12].copy_from_slice(&microseconds.to_ne_bytes());
        assert!(parse_macos_boot_time(&raw).is_err());
    }
}

#[test]
fn production_source_has_no_path_reopen_subprocess_or_unsafe_shortcut() {
    let source = include_str!("evidence_key_commands.rs");
    for banned in [
        "current_exe(",
        "Command::new(\"codesign\")",
        "security_framework_sys",
        "value_as::<",
        "unsafe {",
    ] {
        assert!(
            !source.contains(banned),
            "banned provider shortcut: {banned}"
        );
    }
    assert!(source.contains("SecCode::for_self(Flags::NONE)"));
    assert!(source.contains("check_validity(Flags::NONE, &requirement)"));
    assert!(source.contains("Ctl::new(\"kern.boottime\")"));
    assert!(source.contains("/proc/self/exe"));
    assert!(source.contains("/proc/sys/kernel/random/boot_id"));
}
