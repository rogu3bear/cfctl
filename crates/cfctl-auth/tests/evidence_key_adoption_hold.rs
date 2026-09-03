#![allow(clippy::expect_used)]

use std::sync::Arc;

use cfctl_auth::{
    AuthError, EvidenceKeyAdoptionAcceptanceV1, EvidenceKeyAdoptionClockV1,
    EvidenceKeyAdoptionError, EvidenceKeyAdoptionObservationV1,
    EvidenceKeyAdoptionRuntimeIdentityV1, EvidenceKeyManager, MemorySecretStore, SecretBackend,
};
use chrono::{TimeZone as _, Utc};

fn observation() -> EvidenceKeyAdoptionObservationV1 {
    EvidenceKeyAdoptionObservationV1 {
        marker_identity: None,
        authenticated_descriptor_count: 0,
        authenticated_proof_count: 0,
        runtime: EvidenceKeyAdoptionRuntimeIdentityV1 {
            validation_provider: "untrusted-test-caller".to_owned(),
            requirement_text: "raw caller claim".to_owned(),
            requirement_sha256: format!("sha256:{}", "a".repeat(64)),
            dynamic_self_validation: "satisfied".to_owned(),
            protocol_identity: "cfctl-evidence-key-adoption-v2".to_owned(),
        },
        clock: EvidenceKeyAdoptionClockV1 {
            boot_identity: "test-boot".to_owned(),
            monotonic_ns: 1,
            wall_at: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
        },
    }
}

fn assert_receipt_hold<T>(result: cfctl_auth::Result<T>) {
    assert!(matches!(
        result,
        Err(AuthError::EvidenceKeyAdoption(
            EvidenceKeyAdoptionError::InstalledIdentityReceiptRequired
        ))
    ));
}

#[test]
fn public_manager_rejects_every_receipt_free_consequential_transition() {
    let manager = EvidenceKeyManager::new(
        Arc::new(MemorySecretStore::default()),
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        SecretBackend::PlatformKeyring,
    )
    .expect("manager");
    let observed = observation();
    let acceptance = EvidenceKeyAdoptionAcceptanceV1::operator_supplied(
        "git:0123456789abcdef0123456789abcdef01234567".to_owned(),
        format!("sha256:{}", "b".repeat(64)),
        "arm64".to_owned(),
        "cccccccccccccccccccccccccccccccccccccccc".to_owned(),
        "sha256-truncated-20".to_owned(),
        format!("sha256:{}", "d".repeat(64)),
    )
    .expect("well-shaped raw claims");
    let plan_id = "00000000-0000-4000-8000-000000000001";

    assert_receipt_hold(manager.create_adoption_plan(&observed, acceptance));
    assert_receipt_hold(manager.prepare_adoption(plan_id, &observed));
    assert_receipt_hold(manager.commit_adoption_marker_crossing(plan_id, &observed));
    assert_receipt_hold(manager.complete_adoption_plan(plan_id, &observed));
}
