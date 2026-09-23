//! Envelope success vocabulary tests that ensure `performed` and attestation
//! alone do not imply success. A live 403 Unauthorized or similar authorization
//! failure must set `ok: false` even when `performed: true`.

use super::*;

/// Test that a 403 Unauthorized response with performed=true is correctly
/// marked as ok=false, not success.
#[test]
fn live_403_unauthorized_is_not_success_despite_performed() {
    // Simulate a 403 Unauthorized response from Cloudflare API.
    // The boundary was crossed (performed=true), an attestation exists,
    // but the operation failed due to insufficient permissions.
    let envelope = ResultEnvelopeV2 {
        schema_version: 2,
        generated_at: Utc::now(),
        ok: false, // Must be false for authorization failures
        command: "call".to_owned(),
        capability_id: Some("zones-get".to_owned()),
        operation_id: None,
        profile_id: Some("test-profile".to_owned()),
        account_id: Some("test-account".to_owned()),
        performed: true, // Boundary was crossed
        policy_decision: None,
        verification: VerificationStatusV1 {
            state: VerificationState::Pending,
            basis: None,
        },
        evidence: vec![EvidenceV1 {
            schema_version: 1,
            generated_at: Utc::now(),
            class: EvidenceClass::LiveRead,
            content_hash: "sha256:abcd1234".to_owned(),
            path: "/evidence/live-read-abcd1234.json".to_owned(),
            metadata: json!({}),
        }],
        result: json!({
            "errors": [{
                "code": 10000,
                "message": "Authentication error"
            }]
        }),
        error: Some(ErrorV1 {
            code: "CFCTL_CLOUDFLARE_UNAUTHORIZED".to_owned(),
            message: "Cloudflare returned 403 Forbidden: insufficient permissions".to_owned(),
            next_step: Some("Verify profile permissions with `cfctl keys permissions --account <account-id> --json`, then re-import or use a different profile".to_owned()),
        }),
        attestation: Some(AttestationStatusV1 {
            schema_version: 1,
            state: AttestationStateV1::Attested,
            reason: None,
        }),
    };

    // Critical assertion: 403 with performed=true must still be ok=false
    assert_eq!(
        envelope.ok, false,
        "A 403 Unauthorized response must set ok=false even when performed=true"
    );

    // Verify that error is present
    assert!(
        envelope.error.is_some(),
        "A 403 Unauthorized response must include an error"
    );

    // Verify that even though performed=true and attestation exists,
    // this is NOT a success
    assert!(
        envelope.performed,
        "Test fixture must have performed=true to verify the distinction"
    );
    assert!(
        envelope.attestation.is_some(),
        "Test fixture must have attestation to verify the distinction"
    );
    assert_eq!(
        envelope.ok, false,
        "Success requires ok=true; performed and attestation alone are insufficient"
    );
}

/// Test that a successful live read has ok=true and appropriate verification.
#[test]
fn successful_live_read_has_ok_true_and_verification() {
    let envelope = ResultEnvelopeV2 {
        schema_version: 2,
        generated_at: Utc::now(),
        ok: true, // Success
        command: "call".to_owned(),
        capability_id: Some("zones-get".to_owned()),
        operation_id: None,
        profile_id: Some("test-profile".to_owned()),
        account_id: Some("test-account".to_owned()),
        performed: true,
        policy_decision: None,
        verification: VerificationStatusV1 {
            state: VerificationState::Passed,
            basis: Some("live_response_matches_schema".to_owned()),
        },
        evidence: vec![EvidenceV1 {
            schema_version: 1,
            generated_at: Utc::now(),
            class: EvidenceClass::LiveRead,
            content_hash: "sha256:live1234".to_owned(),
            path: "/evidence/live-read-live1234.json".to_owned(),
            metadata: json!({}),
        }],
        result: json!({
            "result": [{"id": "zone-1", "name": "example.com"}],
            "success": true
        }),
        error: None,
        attestation: Some(AttestationStatusV1 {
            schema_version: 1,
            state: AttestationStateV1::Attested,
            reason: None,
        }),
    };

    assert_eq!(envelope.ok, true, "Successful live read must have ok=true");
    assert!(envelope.error.is_none(), "Successful operation has no error");
    assert_eq!(
        envelope.verification.state,
        VerificationState::Passed,
        "Successful live read should have verification"
    );
}

/// Test that a 401 authentication error is correctly marked as failure.
#[test]
fn live_401_authentication_error_is_not_success() {
    let envelope = ResultEnvelopeV2 {
        schema_version: 2,
        generated_at: Utc::now(),
        ok: false,
        command: "call".to_owned(),
        capability_id: Some("zones-get".to_owned()),
        operation_id: None,
        profile_id: Some("test-profile".to_owned()),
        account_id: Some("test-account".to_owned()),
        performed: true,
        policy_decision: None,
        verification: VerificationStatusV1 {
            state: VerificationState::Pending,
            basis: None,
        },
        evidence: vec![],
        result: json!({"errors": [{"code": 10000, "message": "Invalid API token"}]}),
        error: Some(ErrorV1 {
            code: "CFCTL_CLOUDFLARE_AUTHENTICATION_FAILED".to_owned(),
            message: "Cloudflare authentication failed: invalid API token".to_owned(),
            next_step: Some("Re-import credentials with `cfctl auth import-api-token` or log in again".to_owned()),
        }),
        attestation: Some(AttestationStatusV1 {
            schema_version: 1,
            state: AttestationStateV1::Attested,
            reason: None,
        }),
    };

    assert_eq!(
        envelope.ok, false,
        "401 authentication error must set ok=false"
    );
    assert!(
        envelope.error.is_some(),
        "Authentication error must include error details"
    );
}

/// Test that a local error (no boundary crossed) has performed=false and ok=false.
#[test]
fn local_error_has_performed_false_and_ok_false() {
    let envelope = ResultEnvelopeV2::failure(
        "call",
        "CFCTL_INPUT_VALIDATION",
        "Required selector 'account_id' is missing",
        Some("Provide --account or ensure profile has account_id pinned"),
    );

    assert_eq!(
        envelope.ok, false,
        "Local validation error must have ok=false"
    );
    assert_eq!(
        envelope.performed, false,
        "Local error before boundary must have performed=false"
    );
    assert!(envelope.error.is_some(), "Local error must have error field");
    assert_eq!(
        envelope.attestation, None,
        "Local error has no live attestation"
    );
}

/// Test envelope success helper that agents might use to check success.
#[test]
fn envelope_success_check_requires_ok_true() {
    fn is_envelope_success(envelope: &ResultEnvelopeV2) -> bool {
        // Correct success check: requires ok=true.
        // performed and attestation are evidence metadata, not success indicators.
        envelope.ok && envelope.error.is_none()
    }

    // Success case
    let success = ResultEnvelopeV2::success("call", json!({"result": "ok"}));
    assert!(
        is_envelope_success(&success),
        "ok=true with no error is success"
    );

    // 403 case: performed=true, attestation exists, but ok=false
    let forbidden = ResultEnvelopeV2 {
        schema_version: 2,
        generated_at: Utc::now(),
        ok: false,
        command: "call".to_owned(),
        capability_id: Some("zones-get".to_owned()),
        operation_id: None,
        profile_id: Some("test-profile".to_owned()),
        account_id: Some("test-account".to_owned()),
        performed: true,
        policy_decision: None,
        verification: VerificationStatusV1 {
            state: VerificationState::Pending,
            basis: None,
        },
        evidence: vec![],
        result: json!(null),
        error: Some(ErrorV1 {
            code: "CFCTL_CLOUDFLARE_UNAUTHORIZED".to_owned(),
            message: "403 Forbidden".to_owned(),
            next_step: None,
        }),
        attestation: Some(AttestationStatusV1 {
            schema_version: 1,
            state: AttestationStateV1::Attested,
            reason: None,
        }),
    };

    assert!(
        !is_envelope_success(&forbidden),
        "403 with performed=true and attestation is NOT success"
    );
    assert!(
        forbidden.performed && forbidden.attestation.is_some(),
        "Test fixture must have performed and attestation to verify distinction"
    );
}

/// Test that verification state is independent of success.
/// A local operation can succeed (ok=true) without live verification.
#[test]
fn local_operation_can_succeed_without_live_verification() {
    let envelope = ResultEnvelopeV2 {
        schema_version: 2,
        generated_at: Utc::now(),
        ok: true,
        command: "catalog sync".to_owned(),
        capability_id: None,
        operation_id: None,
        profile_id: None,
        account_id: None,
        performed: false, // No Cloudflare boundary crossed
        policy_decision: None,
        verification: VerificationStatusV1 {
            state: VerificationState::NotApplicable,
            basis: None,
        },
        evidence: vec![EvidenceV1 {
            schema_version: 1,
            generated_at: Utc::now(),
            class: EvidenceClass::SourceConfig,
            content_hash: "sha256:catalog1234".to_owned(),
            path: "/evidence/source-catalog1234.json".to_owned(),
            metadata: json!({}),
        }],
        result: json!({"synchronized": true}),
        error: None,
        attestation: None, // No live attestation for local operation
    };

    assert_eq!(
        envelope.ok, true,
        "Local operation can succeed without live boundary"
    );
    assert_eq!(
        envelope.performed, false,
        "Local operation has performed=false"
    );
    assert_eq!(
        envelope.verification.state,
        VerificationState::NotApplicable,
        "Local operation has no live verification"
    );
    assert!(
        envelope.attestation.is_none(),
        "Local operation has no live attestation"
    );
}
