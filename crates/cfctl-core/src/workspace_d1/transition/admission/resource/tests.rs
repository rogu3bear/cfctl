#![allow(
    clippy::expect_used,
    clippy::wildcard_imports,
    clippy::assigning_clones
)]
use super::*;
use crate::workspace_d1::transition::ProofRef;

fn digest(value: char) -> String {
    format!("sha256:{}", value.to_string().repeat(64))
}
fn effect(id: u8) -> EffectRef {
    EffectRef {
        operation_id: format!("{id:08}-1111-4111-8111-111111111111"),
        evidence_hash: digest('a'),
    }
}
fn resource() -> Resource {
    Resource {
        schema_version: 1,
        identity: Identity {
            repository_head: "a".repeat(40),
            operation_pack_sha256: digest('b'),
            declaration_sha256: digest('c'),
            source_envelope_sha256: digest('d'),
            execution_sha256: digest('e'),
            account_id: "f".repeat(32),
            database_id: "11111111-1111-4111-8111-111111111111".into(),
            target_sequence: 176,
            migration_sha256: digest('a'),
        },
        qualification_pack_sha256: digest('b'),
        case: Case::Success,
        resource_name: "team-qualification-0".into(),
        create: effect(1),
        create_plan_sha256: digest('c'),
        database_id: "22222222-2222-4222-8222-222222222222".into(),
    }
}
fn terminal(resource: &Resource, pack: &Pack) -> CaseRef {
    let source = &pack.cases[0];
    let proof = ProofRef {
        proof_hash: digest('d'),
        evidence_hash: digest('e'),
    };
    CaseRef {
        case: source.case,
        effect: effect(3),
        before: proof.clone(),
        after: proof,
        synthetic_database_id: resource.database_id.clone(),
        fixture_sha256: source.execution.sha256.clone(),
        fixture_bytes: 42,
        failure_sentinel: None,
        performance_max_seconds: None,
        concurrency: None,
        before_population_inventory: source.before.clone(),
        after_population_inventory: source.after.clone(),
        expected_after_state_sha256: source.expected_after_state_sha256.clone(),
    }
}

#[test]
fn qualification_resource_rejects_production_uuid_and_frozen_source_drift() {
    let pack = super::super::tests::pack();
    let original = resource();
    original
        .validate(
            &pack,
            &original.identity,
            &original.qualification_pack_sha256,
        )
        .expect("source binding");
    for mutation in 0..6 {
        let mut changed = original.clone();
        match mutation {
            0 => changed.database_id = original.identity.database_id.clone(),
            1 => changed.identity.repository_head = "b".repeat(40),
            2 => changed.qualification_pack_sha256 = digest('c'),
            3 => changed.resource_name = "unreviewed-name".into(),
            4 => changed.create.operation_id = "standalone-json".into(),
            _ => changed.create_plan_sha256 = "unbound".into(),
        }
        assert!(
            changed
                .validate(
                    &pack,
                    &original.identity,
                    &original.qualification_pack_sha256
                )
                .is_err()
        );
    }
}

#[test]
fn qualification_seeded_cleanup_requires_distinct_seed_and_exact_terminal_case() {
    let pack = super::super::tests::pack();
    let resource = resource();
    let target = SeededCleanupTarget {
        schema_version: 1,
        terminal: terminal(&resource, &pack),
        seed: effect(2),
        resource,
    };
    let validate = |value: &SeededCleanupTarget| {
        value.validate(
            &pack,
            &target.resource.identity,
            &target.resource.qualification_pack_sha256,
            42,
        )
    };
    validate(&target).expect("separate source-bound cleanup proposal");
    for mutation in 0..6 {
        let mut changed = target.clone();
        match mutation {
            0 => changed.seed = target.resource.create.clone(),
            1 => changed.terminal.effect = changed.seed.clone(),
            2 => {
                changed.terminal.synthetic_database_id =
                    target.resource.identity.database_id.clone();
            }
            3 => changed.terminal.fixture_bytes += 1,
            4 => changed.terminal.expected_after_state_sha256 = digest('f'),
            _ => {
                changed
                    .terminal
                    .after_population_inventory
                    .inventory
                    .git_blob_oid = "f".repeat(40);
            }
        }
        assert!(validate(&changed).is_err());
    }
}

#[test]
fn qualification_population_phase_and_seed_cannot_override_committed_inputs() {
    let pack = super::super::tests::pack();
    assert!(ReadPhase::PostWriter.observation(&pack.cases[0]).is_err());
    assert!(ReadPhase::PostWriter.expected_state(&pack.cases[4]).is_ok());
    let original = resource();
    let mut seed = SeedTarget {
        resource: original.clone(),
        source: pack.cases[0].seed.clone(),
        bytes: 42,
    };
    seed.validate(
        &pack,
        &original.identity,
        &original.qualification_pack_sha256,
        42,
    )
    .expect("exact seed");
    seed.source.path = "caller.sql".into();
    assert!(
        seed.validate(
            &pack,
            &original.identity,
            &original.qualification_pack_sha256,
            42
        )
        .is_err()
    );
    let mut value = serde_json::to_value(&original).expect("resource JSON");
    value["approved"] = serde_json::json!(true);
    assert!(serde_json::from_value::<Resource>(value).is_err());
}

#[test]
fn qualification_population_request_cannot_supply_sql_database_or_approval() {
    let request = PopulationRequest {
        schema_version: 1,
        case: Case::Success,
        phase: ReadPhase::Before,
        create: effect(1),
        expected_credential_generation_id: "33333333-3333-4333-8333-333333333333".into(),
    };
    request.validate().expect("closed native request");
    let value = serde_json::to_value(&request).expect("request JSON");
    for key in [
        "sql",
        "database_id",
        "approved",
        "inventory_path",
        "output_override",
    ] {
        let mut changed = value.clone();
        changed[key] = serde_json::json!("caller override");
        assert!(serde_json::from_value::<PopulationRequest>(changed).is_err());
    }
    let mut changed = request;
    changed.expected_credential_generation_id = "caller-generation".into();
    assert!(changed.validate().is_err());
}
