use cfctl_catalog::ingest_native_control_capabilities;
use cfctl_core::VerificationState;

use super::*;

#[tokio::test]
async fn public_call_command_records_schema_and_ledger_operation_bound_observation_proofs() {
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
    let build_identity_hash = hash_value(
        &serde_json::to_value(crate::build_identity::current_build_info()).expect("build info"),
    )
    .expect("build identity");
    for (index, observation, source_assertion) in [
        (
            0_u8,
            "schema",
            json!({"assertion":"table_exists","table":"users"}),
        ),
        (
            1_u8,
            "ledger",
            json!({"assertion":"migration_ledger_equals","migrations":["0001_init.sql"]}),
        ),
    ] {
        let role = if index == 0 {
            "ddl_failure_apply"
        } else {
            "ledger_failure_apply"
        };
        let attempted = stored_plan(
            &store,
            role,
            "mln-web.founder-d1-migration-apply",
            &build_identity_hash,
            &expected_catalog_hash,
            json!({"account_id":ACCOUNT,"database_id":DATABASE}),
            PlanStatus::RectificationRequired,
            &digest(&format!("migration-{index}")),
        );
        let source_envelope = super::super::super::read_execution::with_test_d1_schema_read(
            super::super::super::read_execution::TestD1SchemaReadV1 {
                response: cfctl_cloudflare::CloudflareResponseV1 {
                    status: 200,
                    success: true,
                    result: json!([{"results":[{"present":true}],"success":true,"meta":{"rows_written":0}}]),
                    errors: Vec::new(),
                    result_info: None,
                    etag: None,
                    cf_ray: None,
                },
                profile_id: PROFILE.to_owned(),
                account_id: ACCOUNT.to_owned(),
                credential_generation_id: GENERATION.to_owned(),
            },
            Box::pin(crate::runtime::call_command::call_command(
                &store,
                call_args("d1-schema-introspection", Some(source_assertion.to_string())),
            )),
        )
        .await
        .expect("canonical public source call");
        assert!(source_envelope.performed);
        let source_proof = store
            .list_operational_proofs()
            .expect("source proofs")
            .into_iter()
            .filter(|proof| proof.capability_id == "d1-schema-introspection")
            .max_by_key(|proof| proof.observed_at)
            .expect("canonical source proof");
        let observer_body = json!({
            "schema_version":1,
            "attempted_operation_id":attempted.operation_id,
            "attempted_plan_hash":attempted.plan_hash,
            "phase":"after",
            "observation":observation,
            "source_proof_hash":store.operational_proof_hash(&source_proof).expect("source proof hash"),
            "source_assertion":source_assertion,
        });
        let envelope = Box::pin(crate::runtime::call_command::call_command(
            &store,
            call_args(
                "workspace-d1-qualification-observe",
                Some(observer_body.to_string()),
            ),
        ))
        .await
        .expect("public observer call");
        assert_eq!(
            envelope.capability_id.as_deref(),
            Some(OBSERVER_CAPABILITY_ID)
        );
        assert_eq!(envelope.verification.state, VerificationState::Passed);
    }
}

fn call_args(capability_id: &str, body_json: Option<String>) -> crate::CallArgs {
    crate::CallArgs {
        capability_id: capability_id.to_owned(),
        selectors: vec![
            ("account_id".to_owned(), ACCOUNT.to_owned()),
            ("database_id".to_owned(), DATABASE.to_owned()),
        ],
        query: Vec::new(),
        body_json,
        body_stdin: false,
        profile: Some(PROFILE.to_owned()),
        account: Some(ACCOUNT.to_owned()),
        if_match: None,
        if_none_match: None,
        value_out: None,
        credential_in: None,
        out: None,
        source_file: None,
    }
}
