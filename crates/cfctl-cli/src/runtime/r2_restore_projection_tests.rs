use super::super::super::{
    api_boundary, plan_commands, r2_restore_execution, r2_restore_projection,
};
use super::super::{ROOT_NAME, TARGET, load_with_secrets};
use super::{Fixture, consume_prepared, consumed, fixture, prepared};
use cfctl_cloudflare::{CloudflareResponseV1, OperationVerificationV1};
use cfctl_core::{
    CapabilityV1, EvidenceClass, PlanStatus, PlanV1, TransactionStageV1, VerificationState,
    hash_value,
    r2_recovery::CaptureWindowV1,
    r2_restore::{
        self as contract, RestoreObservationKindV1 as ObservationKind, RestoreSelectionV1,
    },
};
use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use uuid::Uuid;

fn observation(selection: &RestoreSelectionV1, passed: bool) -> OperationVerificationV1 {
    let metadata =
        contract::semantic_headers(&selection.source.provider_metadata).expect("metadata");
    OperationVerificationV1 {
        strategy: contract::STRATEGY.into(),
        passed,
        basis: "synthetic current bytes and stored metadata comparison".into(),
        correlated_resource_id: None,
        readback: CloudflareResponseV1 {
            status: 200,
            success: true,
            errors: vec![],
            result_info: None,
            etag: None,
            cf_ray: None,
            result: json!({"schema_version":1,"account_id":selection.account_id,"bucket_name":selection.bucket_name,
                "object_key_sha256":hex::encode(Sha256::digest(b"docs/private")),
                "sha256":if passed {selection.source.sha256.clone()} else {"f".repeat(64)},
                "byte_count":selection.source.byte_count,
                "metadata_sha256":hash_value(&serde_json::to_value(metadata).expect("headers")).expect("digest"),
                "observed_at":Utc::now(),"bytes_and_metadata_match":passed,"provider_requests":2,
                "body_returned":false,"put_replayed":false,"metadata_atomic_precondition":false,
                "writer_exclusion_qualified":false,"retention_qualified":false,"combined_recovery_ready":false}),
        },
    }
}

fn produce(
    f: &Fixture,
    plan: &mut PlanV1,
    passed: bool,
    kind: ObservationKind,
) -> api_boundary::ApiVerificationOutcome {
    let loaded = load_with_secrets(&f.store, plan, false, &f.secrets).expect("historical source");
    r2_restore_execution::begin_rectification_observation(&f.store, plan).expect("checkpoint");
    r2_restore_projection::persist_observation(
        &f.store,
        plan,
        &loaded.selection,
        &loaded.source_window,
        observation(&loaded.selection, passed),
        kind,
    )
    .expect("actual bound verification producer")
}

fn seal(f: &Fixture, plan: &mut PlanV1, outcome: &api_boundary::ApiVerificationOutcome) {
    plan_commands::persist_transaction_stage_with_artifact(
        &f.store,
        plan,
        TransactionStageV1::VerificationResponsePersisted,
        api_boundary::verification_response_artifact(outcome).expect("reference"),
    )
    .expect("immutable verification reference");
    if plan.status == PlanStatus::Verified {
        plan_commands::persist_transaction_stage(&f.store, plan, TransactionStageV1::Closed)
            .expect("closure");
    }
}

fn inspect(f: &Fixture, plan: &PlanV1) -> super::super::super::prelude::ResultEnvelopeV2 {
    plan_commands::show_plan(
        &f.store,
        &super::super::super::prelude::PlanSelector {
            operation_id: plan.operation_id.clone(),
        },
    )
    .expect("ordinary plan inspection")
}

fn projection(f: &Fixture, plan: &PlanV1) -> Value {
    inspect(f, plan).result["private_restore_verification"].clone()
}

fn binding_rejection_reason(case: &str) -> &'static str {
    match case {
        "source_window" => "capture_window_binding_mismatch",
        "observed_bytes" | "observed_metadata" | "strategy" | "false_combined" => {
            "restore_readback_mismatch"
        }
        "historical_unbound" => "historical_unbound_verification",
        "evidence_class" => "wrong_verification_evidence_class",
        "observation_kind" => "verification_reference_mismatch",
        _ => "restore_binding_mismatch",
    }
}

fn assert_unqualified(
    envelope: &super::super::super::prelude::ResultEnvelopeV2,
    reason: &str,
    case: &str,
) {
    let value = &envelope.result["private_restore_verification"];
    assert_eq!(value["reason"], reason, "{case}");
    assert_eq!(value["qualified"], false, "{case}");
    assert_eq!(
        envelope.verification.state,
        VerificationState::Failed,
        "{case}"
    );
}

#[test]
fn actual_producer_storage_and_inspection_join_without_current_credentials_or_files() {
    let f = fixture(false);
    let mut plan = consumed(&f);
    let outcome = produce(&f, &mut plan, true, ObservationKind::ImmediatePostWrite);
    seal(&f, &mut plan, &outcome);
    let before = f.store.load_plan(&plan.operation_id).expect("before");
    // Inspection must not re-qualify present retained files or effect credentials.
    fs::remove_file(f.store.paths().profiles_file()).expect("remove fixture credentials metadata");
    fs::remove_dir_all(f.store.paths().data_dir.join(ROOT_NAME))
        .expect("remove fixture private snapshots");
    let envelope = inspect(&f, &plan);
    let value = &envelope.result["private_restore_verification"];
    assert_eq!(envelope.verification.state, VerificationState::Passed);
    assert_eq!(value["qualified"], true);
    assert_eq!(value["binding"]["operation_id"], plan.operation_id);
    assert_eq!(value["binding"]["plan_content_hash"], plan.content_hash);
    assert_eq!(
        value["binding"]["request_hash"],
        hash_value(&plan.input).expect("input")
    );
    assert_eq!(
        value["binding"]["source_capture"],
        f.input.body.as_ref().expect("request")["source_capture"]
    );
    assert_eq!(
        value["binding"]["current_capture"],
        f.input.body.as_ref().expect("request")["current_capture"]
    );
    assert_eq!(value["binding"]["observation_kind"], "immediate_post_write");
    let original: CaptureWindowV1 =
        serde_json::from_value(value["binding"]["source_window"].clone()).expect("original window");
    assert!(original.expires_at < Utc::now());
    assert_eq!(value["expected"], value["observed"]);
    assert_eq!(value["evidence"]["class"], "post_change_verification");
    assert_eq!(
        value["evidence"]["content_hash"],
        outcome.evidence.expect("evidence").content_hash
    );
    assert_eq!(value["provider_requests"], 0);
    for key in [
        "body_returned",
        "historical_put_outcome_proven",
        "metadata_atomic_precondition",
        "writer_exclusion_qualified",
        "d1_recovery_qualified",
        "retention_qualified",
        "combined_recovery_ready",
        "current_provider_state_qualified",
        "freshness_qualified",
        "present_retained_file_custody_qualified",
        "write_authority_granted",
    ] {
        assert_eq!(value[key], false, "{key}");
    }
    let public = value.to_string();
    assert!(!public.contains("docs/private"));
    assert!(!public.contains(f.root.path().to_str().expect("path")));
    assert!(!public.contains("current-effect"));
    assert_eq!(
        f.store.load_plan(&plan.operation_id).expect("after"),
        before
    );
}

#[test]
fn repeated_rectification_selects_the_later_closure_evidence_without_rewriting_first_failure() {
    let f = fixture(false);
    let mut plan = consumed(&f);
    let mut first = None;
    let mut last_hash = String::new();
    for passed in [false, false, true] {
        let outcome = produce(
            &f,
            &mut plan,
            passed,
            ObservationKind::ReadOnlyRectification,
        );
        last_hash = outcome
            .evidence
            .as_ref()
            .expect("evidence")
            .content_hash
            .clone();
        r2_restore_execution::persist_rectification(&f.store, &mut plan, &outcome)
            .expect("forward-only persistence");
        let current_first = plan
            .transaction_artifact(TransactionStageV1::VerificationResponsePersisted)
            .expect("first reference")
            .clone();
        if let Some(original) = &first {
            assert_eq!(original, &current_first);
        } else {
            first = Some(current_first);
        }
        let observed = projection(&f, &plan);
        assert_eq!(observed["qualified"], passed);
        assert_eq!(observed["readback_passed"], passed);
        assert_eq!(observed["bytes_match"], passed);
        assert_eq!(observed["stored_semantic_metadata_match"], true);
        if !passed {
            assert_eq!(observed["reason"], "verification_did_not_pass");
            assert_eq!(observed["observed"]["sha256"], "f".repeat(64));
        }
    }
    let value = projection(&f, &plan);
    assert_eq!(
        value["binding"]["observation_kind"],
        "read_only_rectification"
    );
    assert_eq!(value["verification_reference_stage"], "closed");
    assert_eq!(value["evidence"]["content_hash"], last_hash);
    assert_ne!(
        value["evidence"]["content_hash"],
        first.expect("first")["evidence_hash"]
    );
    assert_eq!(value["historical_put_outcome_proven"], false);
    assert!(plan.mark_consumed().is_err());
}

#[test]
fn authenticated_but_wrong_binding_or_readback_remains_unqualified_despite_verified_status() {
    for case in [
        "operation",
        "plan",
        "request",
        "source_ref",
        "current_ref",
        "member",
        "current_member",
        "account",
        "bucket",
        "key",
        "current_window",
        "source_window",
        "expected_bytes",
        "expected_metadata",
        "observed_bytes",
        "observed_metadata",
        "strategy",
        "historical_unbound",
        "false_combined",
        "evidence_class",
        "observation_kind",
    ] {
        let f = fixture(false);
        let mut plan = consumed(&f);
        let mut outcome = produce(&f, &mut plan, true, ObservationKind::ImmediatePostWrite);
        let mut body = f
            .store
            .read_evidence_value(
                &outcome
                    .evidence
                    .as_ref()
                    .expect("native evidence")
                    .content_hash,
            )
            .expect("authenticated body");
        let binding = &mut body["readback"]["result"]["restore_binding"];
        match case {
            "operation" => binding["operation_id"] = json!(Uuid::new_v4()),
            "plan" => binding["plan_content_hash"] = json!(format!("sha256:{}", "0".repeat(64))),
            "request" => binding["request_hash"] = json!(format!("sha256:{}", "0".repeat(64))),
            "source_ref" => binding["source_capture"]["run_id"] = json!(Uuid::new_v4()),
            "current_ref" => binding["current_capture"]["run_id"] = json!(Uuid::new_v4()),
            "member" => binding["source_object_index"] = json!(1),
            "current_member" => binding["expected_current"]["object_index"] = json!(1),
            "observation_kind" => binding["observation_kind"] = json!("read_only_rectification"),
            "account" => binding["account_id"] = json!("b".repeat(32)),
            "bucket" => binding["bucket_name"] = json!("another-bucket"),
            "key" => binding["object_key_sha256"] = json!("0".repeat(64)),
            "current_window" => binding["current_window"]["window_id"] = json!(Uuid::new_v4()),
            "source_window" => binding["source_window"]["window_id"] = json!(Uuid::new_v4()),
            "expected_bytes" => binding["expected"]["byte_count"] = json!(99),
            "expected_metadata" => {
                binding["expected"]["semantic_metadata_sha256"] =
                    json!(format!("sha256:{}", "0".repeat(64)));
            }
            "observed_bytes" => body["readback"]["result"]["byte_count"] = json!(99),
            "observed_metadata" => {
                body["readback"]["result"]["metadata_sha256"] =
                    json!(format!("sha256:{}", "0".repeat(64)));
            }
            "strategy" => body["strategy"] = json!("different_strategy"),
            "historical_unbound" => {
                body["readback"]["result"]
                    .as_object_mut()
                    .expect("result")
                    .remove("restore_binding");
            }
            "false_combined" => body["readback"]["result"]["combined_recovery_ready"] = json!(true),
            "evidence_class" => {
                body["basis"] = json!("fixture observation of the wrong evidence class");
            }
            _ => unreachable!(),
        }
        let class = if case == "evidence_class" {
            EvidenceClass::Apply
        } else {
            EvidenceClass::PostChangeVerification
        };
        // An authenticated descriptor still cannot qualify a mismatched native body.
        outcome.evidence = Some(
            f.store
                .write_evidence(class, &body)
                .expect("synthetic counterexample"),
        );
        seal(&f, &mut plan, &outcome);
        assert_eq!(plan.status, PlanStatus::Verified);
        let inspected = inspect(&f, &plan);
        assert_unqualified(&inspected, binding_rejection_reason(case), case);
    }
}

#[test]
fn equivalent_window_offsets_preserve_exact_instants_and_raw_declaration_identity() {
    let f = fixture(false);
    let mut plan = consumed(&f);
    let mut outcome = produce(&f, &mut plan, true, ObservationKind::ImmediatePostWrite);
    let mut body = f
        .store
        .read_evidence_value(&outcome.evidence.as_ref().expect("evidence").content_hash)
        .expect("body");
    let binding = &mut body["readback"]["result"]["restore_binding"];
    for name in ["source_window", "current_window"] {
        for field in ["opened_at", "expires_at"] {
            let instant: DateTime<Utc> =
                serde_json::from_value(binding[name][field].clone()).expect("instant");
            binding[name][field] = json!(
                instant
                    .with_timezone(&chrono::FixedOffset::east_opt(19_800).expect("offset"))
                    .to_rfc3339_opts(chrono::SecondsFormat::Nanos, false)
            );
        }
    }
    outcome.evidence = Some(
        f.store
            .write_evidence(EvidenceClass::PostChangeVerification, &body)
            .expect("equivalent authenticated representation"),
    );
    seal(&f, &mut plan, &outcome);
    let value = projection(&f, &plan);
    assert_eq!(value["qualified"], true);
    assert_eq!(
        value["binding"]["current_window"]["recovery_binding_sha256"],
        "a".repeat(64)
    );
}

#[test]
fn the_producer_rejects_a_readback_from_before_its_verification_attempt() {
    let f = fixture(false);
    let mut plan = consumed(&f);
    let loaded = load_with_secrets(&f.store, &plan, false, &f.secrets).expect("source");
    r2_restore_execution::begin_rectification_observation(&f.store, &mut plan).expect("attempt");
    let mut verification = observation(&loaded.selection, true);
    verification.readback.result["observed_at"] = json!(
        plan.transaction_journal
            .last()
            .expect("attempt")
            .recorded_at
            - Duration::nanoseconds(1)
    );
    let before = f.store.load_plan(&plan.operation_id).expect("before");
    assert!(
        r2_restore_projection::persist_observation(
            &f.store,
            &mut plan,
            &loaded.selection,
            &loaded.source_window,
            verification,
            ObservationKind::ImmediatePostWrite
        )
        .is_err()
    );
    assert_eq!(plan, before);
    assert_eq!(
        f.store.load_plan(&plan.operation_id).expect("after"),
        before
    );
}

#[test]
fn expiry_equality_is_rejected_at_production_and_authenticated_inspection() {
    let f = fixture(false);
    let mut plan = prepared(&f);
    let mut loaded = load_with_secrets(&f.store, &plan, false, &f.secrets).expect("source");
    let observed_at = Utc::now();
    // Finalize the synthetic expiry while still a draft. The exact rejection
    // reason below distinguishes the expiry guard from observation ordering.
    loaded.selection.window.expires_at = observed_at;
    let target = plan.targets.pointer_mut(TARGET).expect("target");
    target["window"] = json!(loaded.selection.window);
    target["selection_sha256"] = json!(hash_value(&json!(loaded.selection)).expect("selection"));
    plan.refresh_hash().expect("fixture window identity");
    let mut plan = consume_prepared(&f, plan);
    r2_restore_execution::begin_rectification_observation(&f.store, &mut plan).expect("attempt");
    let before = f.store.load_plan(&plan.operation_id).expect("before");
    let mut verification = observation(&loaded.selection, true);
    verification.readback.result["observed_at"] = json!(observed_at);
    let result = r2_restore_projection::persist_observation(
        &f.store,
        &mut plan,
        &loaded.selection,
        &loaded.source_window,
        verification.clone(),
        ObservationKind::ImmediatePostWrite,
    );
    assert_eq!(
        result.err().map(|error| error.to_string()).as_deref(),
        Some("private restore observation is unqualified: restore_readback_mismatch")
    );
    assert_eq!(plan, before);
    assert_eq!(
        f.store.load_plan(&plan.operation_id).expect("after"),
        before
    );

    verification.readback.result["observed_at"] = json!(Utc::now());
    let mut outcome = r2_restore_projection::persist_observation(
        &f.store,
        &mut plan,
        &loaded.selection,
        &loaded.source_window,
        verification,
        ObservationKind::ReadOnlyRectification,
    )
    .expect("read-only production may observe after the write window ends");
    let (_, mut body) = f
        .store
        .load_evidence_value(&outcome.evidence.as_ref().expect("evidence").content_hash)
        .expect("authenticated body");
    body["readback"]["result"]["restore_binding"]["observation_kind"] =
        json!("immediate_post_write");
    body["readback"]["result"]["observed_at"] = json!(observed_at);
    outcome.evidence = Some(
        f.store
            .write_evidence(EvidenceClass::PostChangeVerification, &body)
            .expect("authenticated expiry counterexample"),
    );
    seal(&f, &mut plan, &outcome);
    let value = projection(&f, &plan);
    assert_eq!(value["qualified"], false);
    assert_eq!(value["reason"], "restore_readback_mismatch");
}

#[test]
fn coherently_altered_key_and_metadata_must_still_match_the_immutable_plan() {
    for case in ["key", "metadata"] {
        let f = fixture(false);
        let mut plan = consumed(&f);
        let mut outcome = produce(&f, &mut plan, true, ObservationKind::ImmediatePostWrite);
        let (_, mut body) = f
            .store
            .load_evidence_value(&outcome.evidence.as_ref().expect("evidence").content_hash)
            .expect("authenticated body");
        let readback = &mut body["readback"]["result"];
        if case == "key" {
            readback["restore_binding"]["object_key_sha256"] = json!("0".repeat(64));
            readback["object_key_sha256"] = json!("0".repeat(64));
        } else {
            let digest = format!("sha256:{}", "0".repeat(64));
            readback["restore_binding"]["expected"]["semantic_metadata_sha256"] = json!(digest);
            readback["metadata_sha256"] = json!(digest);
        }
        outcome.evidence = Some(
            f.store
                .write_evidence(EvidenceClass::PostChangeVerification, &body)
                .expect("authenticated counterexample"),
        );
        seal(&f, &mut plan, &outcome);
        assert_eq!(plan.status, PlanStatus::Verified);
        assert_eq!(
            projection(&f, &plan)["reason"],
            "restore_binding_mismatch",
            "{case}"
        );
    }
}

#[test]
fn authenticated_descriptor_and_matching_identity_require_actual_successful_readback() {
    for case in [
        "http_failure",
        "readback_failure",
        "future_readback",
        "before_verification",
        "basis",
    ] {
        let f = fixture(false);
        let mut plan = consumed(&f);
        let mut outcome = produce(&f, &mut plan, true, ObservationKind::ImmediatePostWrite);
        let (_, mut body) = f
            .store
            .load_evidence_value(&outcome.evidence.as_ref().expect("evidence").content_hash)
            .expect("authenticated native evidence");
        match case {
            "http_failure" => body["readback"]["status"] = json!(500),
            "readback_failure" => body["readback"]["success"] = json!(false),
            "future_readback" => {
                body["readback"]["result"]["observed_at"] = json!(Utc::now() + Duration::hours(1));
            }
            "before_verification" => {
                let attempt = plan
                    .transaction_journal
                    .iter()
                    .find(|c| c.stage == TransactionStageV1::VerificationAttemptPersisted)
                    .expect("attempt");
                body["readback"]["result"]["observed_at"] =
                    json!(attempt.recorded_at - Duration::nanoseconds(1));
            }
            "basis" => body["basis"] = json!("a different verification basis"),
            _ => unreachable!(),
        }
        outcome.evidence = Some(
            f.store
                .write_evidence(EvidenceClass::PostChangeVerification, &body)
                .expect("authenticated counterexample"),
        );
        seal(&f, &mut plan, &outcome);
        assert_eq!(plan.status, PlanStatus::Verified);
        assert_eq!(projection(&f, &plan)["qualified"], false, "{case}");
        let reason = if matches!(case, "before_verification" | "basis") {
            "verification_reference_mismatch"
        } else {
            "restore_readback_mismatch"
        };
        assert_eq!(projection(&f, &plan)["reason"], reason, "{case}");
    }
}

#[test]
fn missing_tampered_and_body_only_evidence_cannot_qualify() {
    for case in [
        "missing_body",
        "tampered_body",
        "body_only",
        "tampered_descriptor",
        "missing_plan_v2",
    ] {
        let f = fixture(false);
        let mut plan = consumed(&f);
        let outcome = produce(&f, &mut plan, true, ObservationKind::ImmediatePostWrite);
        seal(&f, &mut plan, &outcome);
        assert_eq!(projection(&f, &plan)["qualified"], true, "{case} baseline");
        let evidence = outcome.evidence.expect("evidence");
        let descriptor = f
            .store
            .paths()
            .data_dir
            .join("evidence-descriptors")
            .join(format!(
                "{}.json",
                evidence
                    .content_hash
                    .strip_prefix("sha256:")
                    .expect("digest")
            ));
        match case {
            "missing_body" => fs::remove_file(&evidence.path).expect("remove fixture body"),
            "tampered_body" => fs::write(&evidence.path, b"{}").expect("tamper fixture body"),
            "body_only" => {
                fs::remove_file(descriptor).expect("remove fixture descriptor");
                assert!(
                    f.store
                        .read_audit_evidence_value(&evidence.content_hash)
                        .is_ok()
                );
            }
            "tampered_descriptor" => {
                fs::write(descriptor, b"{}").expect("tamper fixture descriptor");
            }
            "missing_plan_v2" => {
                fs::remove_file(
                    f.store
                        .paths()
                        .data_dir
                        .join("plans-v2")
                        .join(format!("{}.json", plan.operation_id)),
                )
                .expect("remove fixture canonical plan");
            }
            _ => unreachable!(),
        }
        assert_eq!(projection(&f, &plan)["qualified"], false, "{case}");
        let reason = if case == "missing_plan_v2" {
            "plan_projection_drift"
        } else {
            "verification_evidence_unavailable_or_unauthenticated"
        };
        assert_eq!(projection(&f, &plan)["reason"], reason, "{case}");
    }
}

#[test]
fn valid_evidence_from_another_operation_is_rejected() {
    let f = fixture(false);
    let mut original = consumed(&f);
    let outcome = produce(&f, &mut original, true, ObservationKind::ImmediatePostWrite);
    seal(&f, &mut original, &outcome);
    let mut other = consumed(&f);
    r2_restore_execution::begin_rectification_observation(&f.store, &mut other)
        .expect("checkpoint");
    other.status = PlanStatus::Verified;
    seal(&f, &mut other, &outcome);
    assert_eq!(projection(&f, &original)["qualified"], true);
    assert_eq!(projection(&f, &other)["qualified"], false);
    assert_eq!(projection(&f, &other)["reason"], "restore_binding_mismatch");
}

#[test]
fn missing_verification_and_unrelated_capability_keep_distinct_inspection_behavior() {
    let f = fixture(false);
    let plan = consumed(&f);
    assert_eq!(
        projection(&f, &plan)["reason"],
        "missing_verification_reference"
    );
    assert_eq!(projection(&f, &plan)["operation_id"], plan.operation_id);
    let mut unrelated = PlanV1::draft(
        "fixture",
        &"a".repeat(32),
        "fixture",
        CapabilityV1::new("fixture-unrelated", "unrelated", "GET", "/fixture"),
        json!({}),
    )
    .expect("unrelated plan");
    unrelated.approve(true, None).expect("approval");
    unrelated.mark_consumed().expect("consume");
    unrelated
        .record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("boundary");
    r2_restore_execution::begin_rectification_observation(&f.store, &mut unrelated)
        .expect("checkpoint");
    let loaded =
        load_with_secrets(&f.store, &plan, false, &f.secrets).expect("fixture observation");
    let outcome = api_boundary::verification_outcome(
        &f.store,
        &mut unrelated,
        observation(&loaded.selection, true),
    )
    .expect("ordinary verification producer");
    seal(&f, &mut unrelated, &outcome);
    let envelope = inspect(&f, &unrelated);
    assert!(
        envelope
            .result
            .get("private_restore_verification")
            .is_none()
    );
    assert_eq!(envelope.verification.state, VerificationState::Passed);
}
