//! Scope: the registered native transition proof producer, not provider coverage.
use super::*;
use cfctl_core::workspace_d1::transition::{
    EffectRef, Observation, ProofRef, Source,
    application::{PRODUCER_ID, ProofRequest},
    proofs::{
        Case, CaseRef, Identity, PopulationPhase, QUALIFICATION_KIND, QUALIFICATION_SCHEMA_VERSION,
        Qualification, REQUIRED_CASES, TRANSPORT,
    },
};

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "Derive the six proof actions from their typed owner and test catalog, parser, dispatcher and guide agreement."
)]
async fn local_proof_catalog_parser_dispatch_and_guide_agree_without_provider_authority() {
    use clap::Parser as _;
    let root = tempfile::tempdir().expect("isolated runtime");
    let store = authenticated_test_store(RuntimePaths::from_root(root.path()));
    let capability = cfctl_catalog::d1_transition_proof_capability();
    let mut catalog = CatalogSnapshot {
        schema_version: 2,
        generated_at: Utc::now(),
        source_url: "fixture".into(),
        source_hash: "fixture".into(),
        schema_hash: String::new(),
        capabilities: BTreeMap::from([(capability.id.clone(), capability.clone())]),
    };
    catalog.refresh_hash().expect("catalog");
    catalog
        .save(&store.paths().catalog_file())
        .expect("cached catalog");
    let guide = guide_document(&capability);
    assert!(guide.call_argv.is_some());
    assert_eq!(capability.adapter_status, AdapterStatus::Native);
    assert!(!capability.mutating);
    assert!(capability.permissions.is_empty());
    let hash = format!("sha256:{}", "a".repeat(64));
    let reference = ProofRef {
        proof_hash: hash.clone(),
        evidence_hash: hash.clone(),
    };
    let operation_id = "11111111-1111-4111-8111-111111111111".to_owned();
    let observation = Observation {
        capability_id: "fixture.population".into(),
        inventory: Source {
            path: "fixture.json".into(),
            sha256: hash.clone(),
            git_blob_oid: "a".repeat(40),
        },
    };
    let case = Box::new(CaseRef {
        case: Case::Success,
        effect: EffectRef {
            operation_id: operation_id.clone(),
            evidence_hash: hash.clone(),
        },
        before: reference.clone(),
        after: reference.clone(),
        synthetic_database_id: operation_id.clone(),
        fixture_sha256: hash.clone(),
        fixture_bytes: 1,
        failure_sentinel: None,
        performance_max_seconds: None,
        concurrency: None,
        before_population_inventory: observation.clone(),
        after_population_inventory: observation,
        expected_after_state_sha256: hash.clone(),
    });
    let identity = Identity {
        repository_head: "a".repeat(40),
        operation_pack_sha256: hash.clone(),
        declaration_sha256: hash.clone(),
        source_envelope_sha256: hash.clone(),
        execution_sha256: hash.clone(),
        account_id: "a".repeat(32),
        database_id: operation_id.clone(),
        target_sequence: 1,
        migration_sha256: hash,
    };
    let source_id = "fixture.qualification".to_owned();
    let requests = [
        ProofRequest::Application {
            operation_id,
            terminal_assertions: reference.clone(),
            diagnostic: reference.clone(),
        },
        ProofRequest::Population {
            capability_id: source_id.clone(),
            case: case.clone(),
            phase: PopulationPhase::Before,
            source: reference,
        },
        ProofRequest::Case {
            capability_id: source_id.clone(),
            case: case.clone(),
        },
        ProofRequest::Writer {
            capability_id: source_id.clone(),
            case: case.clone(),
        },
        ProofRequest::Poll {
            capability_id: source_id.clone(),
            case,
        },
        ProofRequest::Aggregate {
            capability_id: source_id,
            qualification: Box::new(Qualification {
                schema_version: QUALIFICATION_SCHEMA_VERSION,
                kind: QUALIFICATION_KIND.into(),
                identity,
                transport: TRANSPORT.into(),
                max_execution_bytes: 1,
                cases: Vec::new(),
            }),
        },
    ];
    let mut actual_actions = BTreeSet::new();
    for request in requests {
        let body = serde_json::to_value(&request).expect("typed request");
        actual_actions.insert(body["action"].as_str().expect("action").to_owned());
        assert_eq!(
            serde_json::from_value::<ProofRequest>(body.clone()).expect("closed parser"),
            request
        );
        let serialized = body.to_string();
        let parsed = crate::Cli::try_parse_from([
            "cfctl",
            "call",
            PRODUCER_ID,
            "--body-json",
            &serialized,
            "--json",
        ])
        .expect("public command grammar");
        let Some(crate::Command::Call(arguments)) = parsed.command else {
            panic!("call parser");
        };
        let error = Box::pin(call_command(&store, arguments))
            .await
            .expect_err("no referenced source or plan");
        assert!(
            !matches!(error, CliError::Json(_)),
            "each registered action reaches typed reference validation: {error}"
        );
        assert!(store.list_plans().expect("plans").is_empty());
        assert!(store.list_operational_proofs().expect("proofs").is_empty());
    }
    let declared = capability
        .request_schema
        .as_ref()
        .expect("schema")
        .pointer("/properties/action/enum")
        .and_then(Value::as_array)
        .expect("declared actions")
        .iter()
        .map(|value| value.as_str().expect("action").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(declared, actual_actions);
    assert_eq!(QUALIFICATION_SCHEMA_VERSION, 2);
    assert_eq!(REQUIRED_CASES.len(), 10);
    assert!(REQUIRED_CASES.contains(&Case::PreservationFailure));
}
