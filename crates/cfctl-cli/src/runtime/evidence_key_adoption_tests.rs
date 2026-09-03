//! Work214 fail-closed adoption command and provider-contract tests.

#![allow(clippy::expect_used)]

use crate::{EvidenceKeyAdoptArgs, EvidenceKeyAdoptPlanArgs};
use cfctl_auth::{
    AuthError, EvidenceKeyAdoptionAcceptanceV1, EvidenceKeyAdoptionError,
    EvidenceKeyAdoptionPlanV1, EvidenceKeyStatusV1,
};
use chrono::{TimeZone as _, Utc};

use super::{
    EvidenceKeyAdoptPlanCommand, EvidenceKeyCommand, StateStore, adoption_plan_status_envelope,
    classify_native_self_validation, evidence_key_command, parse_macos_boot_time,
};

fn assert_receipt_hold(error: super::CliError) {
    assert!(matches!(
        error,
        super::CliError::Auth(AuthError::EvidenceKeyAdoption(
            EvidenceKeyAdoptionError::InstalledIdentityReceiptRequired
        ))
    ));
    assert_eq!(
        error.code(),
        "CFCTL_AUTH_INSTALLED_IDENTITY_RECEIPT_REQUIRED"
    );
    let next_step = error.next_step().expect("receipt HOLD guidance");
    assert!(next_step.contains("Signed publication and installation may proceed"));
    assert!(next_step.contains("remain unavailable"));
    assert!(!next_step.contains("doctor"));
}

#[test]
fn plan_creation_and_adopt_fail_closed_before_platform_manager_access() {
    let root = tempfile::tempdir().expect("temporary state root");
    let state =
        StateStore::open(cfctl_storage::RuntimePaths::from_root(root.path())).expect("state store");

    let create_error = evidence_key_command(
        &state,
        EvidenceKeyCommand::AdoptPlan(EvidenceKeyAdoptPlanArgs {
            command: EvidenceKeyAdoptPlanCommand::Create,
        }),
    )
    .expect_err("receipt-free plan creation is unavailable");
    assert_receipt_hold(create_error);

    let adopt_error = evidence_key_command(
        &state,
        EvidenceKeyCommand::Adopt(EvidenceKeyAdoptArgs {
            plan_id: "00000000-0000-4000-8000-000000000001".to_owned(),
            yes: true,
        }),
    )
    .expect_err("receipt-free marker crossing is unavailable");
    assert_receipt_hold(adopt_error);
}

#[test]
fn current_status_execution_renderer_preserves_the_originating_command() {
    let accepted = EvidenceKeyAdoptionAcceptanceV1::operator_supplied(
        "git:0123456789abcdef0123456789abcdef01234567".to_owned(),
        format!("sha256:{}", "a".repeat(64)),
        "arm64".to_owned(),
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
        "sha256-truncated-20".to_owned(),
        format!("sha256:{}", "c".repeat(64)),
    )
    .expect("well-shaped historical acceptance");
    let plan = EvidenceKeyAdoptionPlanV1 {
        plan_id: "00000000-0000-4000-8000-000000000001".to_owned(),
        status: EvidenceKeyStatusV1 {
            initialized: true,
            state_root_identity: Some(format!("sha256:{}", "d".repeat(64))),
            active_generation_id: Some("00000000-0000-4000-8000-000000000002".to_owned()),
            verification_generation_ids: vec![],
            backend: Some(cfctl_auth::SecretBackend::PlatformKeyring),
        },
        created_at: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
        expires_at: Utc.timestamp_opt(1_700_000_900, 0).unwrap(),
        completed_at: None,
        state: "prepared".to_owned(),
        next_action: "none".to_owned(),
        accepted_runtime: accepted,
        runtime_validation: "indeterminate".to_owned(),
    };

    let current = adoption_plan_status_envelope(
        "auth evidence-key adopt-plan current",
        "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        plan.clone(),
    );
    let status = adoption_plan_status_envelope(
        "auth evidence-key adopt-plan status",
        "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        plan,
    );

    assert_eq!(current.command, "auth evidence-key adopt-plan current");
    assert_eq!(status.command, "auth evidence-key adopt-plan status");
    assert!(!current.performed);
    assert!(!status.performed);
}

#[test]
fn native_validation_classification_still_fails_closed() {
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
