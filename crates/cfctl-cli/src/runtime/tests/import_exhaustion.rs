use super::*;

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the fixture proves every bounded child receipt and inherited authority pin"
)]
pub(super) fn poll_child_exhaustion_is_exact_bounded_and_carries_root_ingest_authority() {
    let root = tempfile::tempdir().expect("poll child root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("poll child store");
    let mut catalog = CatalogSnapshot {
        schema_version: 1,
        generated_at: Utc::now(),
        source_url: "test://native".to_owned(),
        source_hash: "sha256:test".to_owned(),
        schema_hash: String::new(),
        capabilities: BTreeMap::new(),
    };
    ingest_native_control_capabilities(&mut catalog).expect("native overlay");
    let mut capability = catalog
        .capabilities
        .remove("d1-resume-approved-mln-import-poll")
        .expect("poll child capability");
    capability
        .d1_approved_mln_import_poll_resume
        .as_mut()
        .expect("poll child contract")
        .max_poll_attempts = 2;
    let contract = capability
        .d1_approved_mln_import_poll_resume
        .clone()
        .expect("poll child contract");
    let import_target = json!({
        "account_id":contract.account_id,
        "database_id":contract.database_id,
    });
    let root_input = json!({"body":{"migration_id":"0143"}});
    let accepted = json!({
        "schema_version":1,
        "operation_id":"00000000-0000-4000-8000-000000000001",
        "step":"ingest_response",
        "performed":true,
        "rectification_required":false,
        "receipt":{
            "http_status":200,"success":true,"response_action":"ingest",
            "provider":"cloudflare","effect":"d1_import_ingest_accepted",
            "migration_id":"0143","target":import_target,
            "plan_input_hash":hash_value(&root_input).expect("root input hash"),
            "no_replay":false,
            "result":{"type":"import","status":"active","success":true,
                "at_bookmark":"accepted"},
            "errors":[]
        }
    });
    let accepted_evidence = store
        .write_evidence(EvidenceClass::Apply, &accepted)
        .expect("accepted evidence");
    let mut plan = PlanV1::draft(
        "profile-a",
        &contract.account_id,
        "catalog-sha",
        capability,
        json!({}),
    )
    .expect("poll child plan");
    plan.input = serde_json::to_value(CallInput {
            selectors: json!({
                "account_id":contract.account_id,
                "database_id":contract.database_id,
            }),
            body: Some(json!({
                "parent_operation_id":"00000000-0000-4000-8000-000000000001",
                "parent_plan_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "exhaustion_evidence_hash":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "accepted_ingest_evidence_hash":accepted_evidence.content_hash,
                "accepted_bookmark_hash":hash_value(&json!("accepted")).expect("bookmark hash"),
            })),
            ..CallInput::default()
        })
        .expect("poll child input");
    plan.targets = json!({"adapter":{"approved_mln_import_poll_resume":{
        "root_operation_id":"00000000-0000-4000-8000-000000000001",
        "root_plan_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "root_input":root_input,
        "root_stage":{"sha256":"sha256:source"},
        "accepted_ingest_evidence_hash":accepted_evidence.content_hash,
        "accepted_bookmark":"accepted"
    }}});
    plan.refresh_hash().expect("poll child hash");
    let input_hash = hash_value(&plan.input).expect("input hash");
    for attempt in 1..=2 {
        let checkpoint = D1ImportCheckpointV1 {
            schema_version: 1,
            operation_id: plan.operation_id.clone(),
            step: format!("poll_response_{attempt}"),
            performed: true,
            rectification_required: false,
            receipt: json!({
                "http_status":200,"success":true,"response_action":"poll",
                "provider":"cloudflare","effect":"d1_import_response",
                "migration_id":"0143","target":import_target,"plan_input_hash":input_hash,
                "result":{"type":"import","status":"active","success":true,
                    "at_bookmark":"accepted","result":{"final_bookmark":null},
                    "provider_error_present":false},
                "errors":[],"provider_errors_present":false,"no_replay":false,
                "etag_present":false,"etag_sha256":null,"cf_ray":null
            }),
        };
        persist_d1_import_checkpoint(&store, &plan.operation_id, &checkpoint)
            .expect("poll checkpoint");
    }
    let exhausted = D1ImportCheckpointV1 {
        schema_version: 1,
        operation_id: plan.operation_id.clone(),
        step: "poll_in_progress_exhausted".to_owned(),
        performed: true,
        rectification_required: true,
        receipt: json!({
            "provider":"cloudflare","effect":"d1_import_poll_in_progress_exhausted",
            "migration_id":"0143","target":import_target,"plan_input_hash":input_hash,
            "source_sha256":"sha256:source","at_bookmark":"accepted",
            "attempt_count":2,"attempt_bound":2,
            "outcome":"poll_in_progress_exhausted","receipt_available":true,"no_replay":true
        }),
    };
    persist_d1_import_checkpoint(&store, &plan.operation_id, &exhausted)
        .expect("exhaustion checkpoint");
    let exact = super::exact_resume_poll_exhaustion(&store, &plan).expect("exact child exhaustion");
    assert_eq!(exact.accepted_bookmark, "accepted");
    assert_eq!(
        exact.accepted_ingest_evidence.content_hash,
        accepted_evidence.content_hash
    );
    let mut grafted = plan.clone();
    grafted.targets["adapter"]["approved_mln_import_poll_resume"]["accepted_bookmark"] =
        json!("grafted");
    assert!(super::exact_resume_poll_exhaustion(&store, &grafted).is_err());
}
