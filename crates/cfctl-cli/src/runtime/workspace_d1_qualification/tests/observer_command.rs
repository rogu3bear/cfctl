use cfctl_catalog::ingest_native_control_capabilities;
use cfctl_core::VerificationState;

use super::*;

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the command-surface test constructs the exact plan, public source proof, CLI request, and durable observer proof in one visible scenario"
)]
async fn public_call_command_records_one_operation_bound_observation_proof() {
    let (_root, store) = store();
    let mut catalog = CatalogSnapshot {
        schema_version: 2,
        generated_at: Utc::now(),
        source_url: "fixture".to_owned(),
        source_hash: digest("source"),
        schema_hash: String::new(),
        capabilities: BTreeMap::new(),
    };
    ingest_native_control_capabilities(&mut catalog).expect("native observer capability");
    let expected_catalog_hash = catalog.schema_hash.clone();
    store
        .write_json(&store.paths().catalog_file(), &catalog)
        .expect("seed public catalog");
    let attempted = stored_plan(
        &store,
        "ddl_failure_apply",
        "mln-web.founder-d1-migration-apply",
        &digest("cfctl-candidate"),
        &expected_catalog_hash,
        json!({"account_id":ACCOUNT,"database_id":DATABASE}),
        PlanStatus::RectificationRequired,
        &digest("migration"),
    );
    let operation_id = attempted.operation_id;
    let cfctl_storage::StoredPlanRecord::Current(plan) = store
        .load_stored_plan_record(&operation_id)
        .expect("attempted plan")
    else {
        panic!("current attempted plan")
    };
    let attempted_plan_hash = plan.plan.content_hash.clone();
    let observed_at = plan
        .plan
        .transaction_journal
        .iter()
        .find(|checkpoint| checkpoint.stage == TransactionStageV1::BoundaryAttemptPersisted)
        .map(|checkpoint| checkpoint.recorded_at - chrono::Duration::milliseconds(1))
        .expect("attempt boundary");
    let assertion = json!({"kind":"migration_ledger_equals","entries":[]});
    let assertion_hash = hash_value(&assertion).expect("assertion hash");
    let source_input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":ACCOUNT,"database_id":DATABASE}),
        query: json!({}),
        body: Some(assertion.clone()),
        if_match: None,
        if_none_match: None,
    })
    .expect("source input");
    let source = stored_proof_at(
        &store,
        "public_schema_source",
        "d1-schema-introspection",
        &plan.pins.build_identity_hash,
        &expected_catalog_hash,
        source_input,
        json!({
            "status":200,"success":true,"result":[{"results":[{"present":true}],"success":true,"meta":{"rows_written":0}}],
            "errors":[],
            "result_info":{"query":{"kind":"d1_schema_introspection","assertion_input_sha256":assertion_hash,"caller_sql":false,"read_only":true}},
            "etag":null,"cf_ray":null,"availability":{},
        }),
        observed_at,
        OperationalProofOutcomeV1::Succeeded,
    );
    let body = json!({
        "schema_version":1,
        "attempted_operation_id":operation_id,
        "attempted_plan_hash":attempted_plan_hash,
        "phase":"before",
        "observation":"ledger",
        "source_proof_hash":source.proof_hash,
        "source_assertion":assertion,
    });
    let envelope = Box::pin(crate::runtime::call_command::call_command(
        &store,
        crate::CallArgs {
            capability_id: "workspace-d1-qualification-observe".to_owned(),
            selectors: vec![
                ("account_id".to_owned(), ACCOUNT.to_owned()),
                ("database_id".to_owned(), DATABASE.to_owned()),
            ],
            query: Vec::new(),
            body_json: Some(body.to_string()),
            body_stdin: false,
            profile: None,
            account: None,
            if_match: None,
            if_none_match: None,
            value_out: None,
            credential_in: None,
            out: None,
            source_file: None,
        },
    ))
    .await
    .expect("public observer call");
    assert_eq!(
        envelope.capability_id.as_deref(),
        Some(OBSERVER_CAPABILITY_ID)
    );
    assert_eq!(envelope.verification.state, VerificationState::Passed);
    let proof_hash = envelope
        .result
        .get("proof_hash")
        .and_then(Value::as_str)
        .expect("observer proof hash");
    let proof = store
        .load_operational_proof(proof_hash)
        .expect("stored observer proof");
    assert_eq!(proof.capability_id, OBSERVER_CAPABILITY_ID);
}
