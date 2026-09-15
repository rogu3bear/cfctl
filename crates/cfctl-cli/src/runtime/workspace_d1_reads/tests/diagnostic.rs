use super::*;

#[test]
fn diagnostic_guide_declares_the_explicit_target_and_private_sink() {
    let mut catalog = catalog();
    cfctl_catalog::ingest_native_control_capabilities(&mut catalog).expect("catalog");
    let capability = catalog
        .get(cfctl_core::d1_reconciliation::DIAGNOSTIC_ID)
        .expect("diagnostic");
    let guide = super::super::super::guide_generation::guide_document(capability);
    let argv = guide.call_argv.expect("native command");
    for required in ["--profile", "--account", "--body-stdin", "--out", "--json"] {
        assert!(argv.iter().any(|arg| arg == required));
    }
    assert_eq!(guide.next_action.argv, argv);
}

#[tokio::test]
async fn diagnostic_rejects_rebound_or_unrejected_history_before_credentials_or_output() {
    let (owner, capability, input) = fixture(false);
    let runtime = tempfile::tempdir().expect("runtime");
    let store = super::super::super::tests::authenticated_test_store(RuntimePaths::from_root(
        runtime.path(),
    ));
    store
        .register_workspace(owner.path(), Some("a".repeat(32)))
        .expect("register");
    let validated = d1_read_inventory::validate(&capability, &input).expect("inventory");
    let mut observation = result(&validated);
    observation.read_complete = false;
    observation.rows_read = 1;
    let rejected = &mut observation.results[1];
    rejected.status = D1ReadStatusV1::Rejected;
    rejected.classification = "provider_http_error".into();
    rejected.http_status = Some(400);
    rejected.rows_read = None;
    rejected.receipt = None;
    let persisted = persist(
        &store,
        &catalog(),
        &capability,
        &validated,
        &profile(),
        Utc::now(),
        &observation,
    )
    .expect("native incomplete observation");
    let original = persisted.envelope.result;
    let output = runtime.path().join("must-not-exist.json");
    for (field, replacement) in [
        ("account_id", json!("b".repeat(32))),
        ("database_id", json!("22222222-2222-4222-8222-222222222222")),
        (
            "inventory_sha256",
            json!(format!("sha256:{}", "c".repeat(64))),
        ),
        ("profile_id", json!("different-profile")),
        ("kind", json!("unrelated_read")),
        ("capability_id", json!("other-capability")),
        ("execution", json!({"read_complete":true,"results":[]})),
    ] {
        let mut changed = original.clone();
        changed[field] = replacement;
        let evidence = store
            .write_observation_evidence(EvidenceClass::LiveRead, &changed)
            .expect("signed fixture");
        let request = CallInput {
            selectors: json!({}),
            query: json!({}),
            body: Some(json!({
            "failed_evidence_hash":evidence.content_hash,"capability_id":capability.id,
            "query_id":validated.contract().inventory.queries[1].id,
            "expected_credential_generation_id":"22222222-2222-4222-8222-222222222222"})),
            ..CallInput::default()
        };
        let error = super::super::super::d1_failed_query::execute(
            &store,
            &catalog(),
            &request,
            Some("example-read"),
            Some(&"a".repeat(32)),
            Some(&output),
        )
        .await
        .expect_err("rebound history");
        assert!(
            error.to_string().contains("D1 diagnostic requires"),
            "{field}: {error}"
        );
        assert!(!output.exists());
        assert!(!store.paths().profiles_file().exists());
    }
}
