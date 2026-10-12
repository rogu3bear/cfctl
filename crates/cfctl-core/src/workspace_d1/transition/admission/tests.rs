#![allow(
    clippy::unwrap_used,
    clippy::wildcard_imports,
    clippy::assigning_clones
)]
use super::*;

fn input_source() -> Source {
    Source {
        path: "fixtures/source.sql".into(),
        sha256: format!("sha256:{}", "a".repeat(64)),
        git_blob_oid: "b".repeat(40),
    }
}

pub(super) fn pack() -> Pack {
    let observation = Observation {
        capability_id: "team.qualification-population".into(),
        inventory: input_source(),
    };
    let cases = [
        Case::Success,
        Case::MigrationFailure,
        Case::LedgerFailure,
        Case::CleanupFailure,
        Case::ConcurrentPopulation,
        Case::InterruptedResponse,
        Case::FullScanAccessPath,
        Case::ExactSchemaFormat,
        Case::PerformanceBound,
        Case::PreservationFailure,
    ]
    .into_iter()
    .enumerate()
    .map(|(i, case)| CaseSource {
        case,
        resource_name: format!("team-qualification-{i}"),
        seed: input_source(),
        execution: input_source(),
        before: observation.clone(),
        after: observation.clone(),
        before_oracle: input_source(),
        after_oracle: input_source(),
        expected_before_state_sha256: format!("sha256:{}", "c".repeat(64)),
        expected_after_state_sha256: format!("sha256:{}", "c".repeat(64)),
        failure_sentinel: case.is_failure().then(|| "EXACT_SYNTHETIC_FAILURE".into()),
        performance_max_seconds: (case == Case::PerformanceBound).then_some(120),
        concurrent_source: (case == Case::ConcurrentPopulation).then(|| ConcurrentSource {
            writer: input_source(),
            writer_bytes: 64,
            post_writer_inventory: observation.clone(),
            expected_post_writer_state_sha256: format!("sha256:{}", "d".repeat(64)),
        }),
        post_writer_oracle: (case == Case::ConcurrentPopulation).then(input_source),
    })
    .collect();
    Pack {
        schema_version: 1,
        contract: CONTRACT.into(),
        transition_operation_id: "team.transition".into(),
        maximum_live_databases: 1,
        maximum_database_lifetimes: 10,
        resets_allowed: false,
        operation: [
            Role::Create,
            Role::Seed,
            Role::Execute,
            Role::Writer,
            Role::Poll,
            Role::Cleanup,
            Role::Population,
            Role::Aggregate,
            Role::Policy,
        ]
        .into_iter()
        .enumerate()
        .map(|(i, role)| Operation {
            id: if role == Role::Population {
                "team.qualification-population".into()
            } else {
                format!("team.qualification-{i}")
            },
            title: "Synthetic qualification".into(),
            description: "One source-bound synthetic role".into(),
            role,
        })
        .collect(),
        cases,
    }
}

#[test]
fn qualification_source_has_no_preallocated_database_or_approval_fields() {
    let pack = pack();
    assert_eq!(pack.validate(), Ok(()));
    let mut value = serde_json::to_value(&pack).unwrap();
    for key in ["database_id", "approved", "operation_id", "cost_qualified"] {
        value[key] = serde_json::json!(true);
        assert!(serde_json::from_value::<Pack>(value.clone()).is_err());
        value.as_object_mut().unwrap().remove(key);
    }
}

#[test]
fn qualification_source_rejects_shared_resources_resets_and_missing_cases() {
    let pack = pack();
    let mut changed = pack.clone();
    changed.cases[1].resource_name = changed.cases[0].resource_name.clone();
    assert!(changed.validate().is_err());
    let mut changed = pack.clone();
    changed.maximum_live_databases = 2;
    assert!(changed.validate().is_err());
    let mut changed = pack.clone();
    changed.maximum_database_lifetimes = 9;
    assert!(changed.validate().is_err());
    let mut changed = pack.clone();
    changed.resets_allowed = true;
    assert!(changed.validate().is_err());
    let mut changed = pack;
    changed.cases.pop();
    assert!(changed.validate().is_err());
}

#[test]
fn qualification_source_binds_fault_rollback_oracle_and_writer_inventory() {
    let pack = pack();
    let mut changed = pack.clone();
    changed.cases[1].expected_after_state_sha256 = format!("sha256:{}", "f".repeat(64));
    assert!(changed.validate().is_err());
    let mut changed = pack.clone();
    changed.cases[1].failure_sentinel = None;
    assert!(changed.validate().is_err());
    let mut changed = pack.clone();
    changed.cases[4]
        .concurrent_source
        .as_mut()
        .unwrap()
        .post_writer_inventory
        .capability_id = "unrelated.read".into();
    assert!(changed.validate().is_err());
    let mut changed = pack.clone();
    changed.cases[0].seed.path = "../source.sql".into();
    assert!(changed.validate().is_err());
    let mut changed = pack;
    changed.operation[0].role = Role::Cleanup;
    assert!(changed.validate().is_err());
}
