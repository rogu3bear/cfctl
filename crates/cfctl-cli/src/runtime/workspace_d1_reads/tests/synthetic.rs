#![allow(clippy::expect_used, clippy::wildcard_imports)]
use super::*;
use cfctl_core::workspace_d1::transition::{
    EffectRef,
    admission::resource::{PopulationBinding, ReadPhase, Resource},
    proofs::{Case, Identity},
};

#[test]
fn qualification_synthetic_evidence_rejects_target_drift_and_unapproved_rows_before_write() {
    let (_owner, mut capability, input) = fixture(false);
    capability.source = "workspace-d1-synthetic-read-v1".into();
    let validated = d1_read_inventory::validate(&capability, &input).expect("native population");
    let contract = validated.contract();
    let digest = format!("sha256:{}", "a".repeat(64));
    let binding = PopulationBinding {
        phase: ReadPhase::Before,
        resource: Resource {
            schema_version: 1,
            identity: Identity {
                repository_head: contract.repository_head.clone(),
                operation_pack_sha256: digest.clone(),
                declaration_sha256: digest.clone(),
                source_envelope_sha256: digest.clone(),
                execution_sha256: digest.clone(),
                account_id: contract.operation.account_id.clone(),
                database_id: "22222222-2222-4222-8222-222222222222".into(),
                target_sequence: 176,
                migration_sha256: digest.clone(),
            },
            qualification_pack_sha256: contract.operation_pack_sha256.clone(),
            case: Case::Success,
            resource_name: "fixture-case".into(),
            create: EffectRef {
                operation_id: "33333333-3333-4333-8333-333333333333".into(),
                evidence_hash: digest.clone(),
            },
            create_plan_sha256: digest,
            database_id: contract.operation.database_id.clone(),
        },
    };
    let runtime = tempfile::tempdir().expect("runtime");
    let store = super::super::super::tests::authenticated_test_store(RuntimePaths::from_root(
        runtime.path(),
    ));
    let attestation =
        super::super::super::plan_commands::observation_attestation(&store, &capability)
            .expect("attestation");
    let scoped = store.with_observation_attestation(&attestation);
    let good = result(&validated);
    let accepted = persist_synthetic(
        &scoped,
        &catalog(),
        &capability,
        &validated,
        &profile(),
        (Utc::now(), &good),
        &binding,
    )
    .expect("native synthetic evidence");
    assert_eq!(
        accepted.envelope.result["synthetic_binding"],
        serde_json::to_value(&binding).expect("binding")
    );
    let before = files(runtime.path());
    let mut wrong = binding.clone();
    wrong
        .resource
        .database_id
        .clone_from(&binding.resource.identity.database_id);
    assert!(
        persist_synthetic(
            &scoped,
            &catalog(),
            &capability,
            &validated,
            &profile(),
            (Utc::now(), &good),
            &wrong
        )
        .is_err()
    );
    assert_eq!(before, files(runtime.path()));
    let mut bad = good;
    bad.results[0].receipt.as_mut().expect("receipt")["result"][0]["results"][0]["unexpected_private"] =
        json!("NEVER_PERSIST_THIS_ROW");
    let error = persist_synthetic(
        &scoped,
        &catalog(),
        &capability,
        &validated,
        &profile(),
        (Utc::now(), &bad),
        &binding,
    )
    .expect_err("unapproved native rows rejected");
    assert!(!error.to_string().contains("NEVER_PERSIST_THIS_ROW"));
    assert_eq!(
        before,
        files(runtime.path()),
        "rejected rows must not cross durable observation boundary"
    );
}
