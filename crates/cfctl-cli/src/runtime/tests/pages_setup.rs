use super::*;
use cfctl_cloudflare::pages_projects::{
    STATE_PRECONDITION, variable_state_receipt, variable_target,
};
use cfctl_core::pages_projects as contract;

fn capability(creating: bool) -> CapabilityV1 {
    let mut cap = CapabilityV1::new(
        if creating {
            contract::CREATE_ID
        } else {
            contract::VARIABLES_ID
        },
        "Pages setup",
        if creating { "POST" } else { "PATCH" },
        if creating {
            contract::COLLECTION
        } else {
            contract::DETAIL
        },
    );
    "Pages Project".clone_into(&mut cap.product);
    "account".clone_into(&mut cap.account_scope);
    cap.mutating = true;
    cap.adapter_status = AdapterStatus::DynamicApi;
    cap.effect = EffectClass::ReversibleWrite;
    cap.risk = if creating {
        RiskClass::CrossConfig
    } else {
        RiskClass::SecretSensitive
    };
    cap.permissions = vec!["Pages Write".to_owned()];
    cap.selectors = ["account_id"]
        .into_iter()
        .chain((!creating).then_some("project_name"))
        .map(|name| SelectorV1 {
            name: name.to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        })
        .collect();
    cap.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".to_owned()],
        success_media_types: vec!["application/json".to_owned()],
        body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
    });
    cap.verification.required = true;
    if creating {
        cap.request_schema = Some(contract::create_schema());
        contract::CREATE_STRATEGY.clone_into(&mut cap.verification.strategy);
        cap.created_resource = Some(CreatedResourceContractV1 {
            detail_path: contract::DETAIL.to_owned(),
            identity_selector: "project_name".to_owned(),
            response_result_identity_pointer: "/name".to_owned(),
            read_capability_id: contract::READ_ID.to_owned(),
            delete_capability_id: contract::DELETE_ID.to_owned(),
            verified_response_fields: vec!["name".to_owned(), "production_branch".to_owned()],
        });
    } else {
        cap.request_schema = Some(contract::variables_schema());
        contract::VARIABLES_STRATEGY.clone_into(&mut cap.verification.strategy);
        cap.same_path_read = Some(cfctl_core::SamePathReadContractV1 {
            path: contract::DETAIL.to_owned(),
            read_capability_id: contract::READ_ID.to_owned(),
            verified_response_fields: vec!["deployment_configs".to_owned()],
        });
    }
    assert!(cap.verification_contract_supported());
    cap
}

fn project() -> Value {
    json!({"id":"11111111-1111-4111-8111-111111111111","name":"codex-token-bar","production_branch":"main",
        "build_config":{"web_analytics_token":null},"deployment_configs":{"production":{},"preview":{}}})
}

fn response(project: Value) -> CloudflareResponseV1 {
    CloudflareResponseV1 {
        status: 200,
        success: true,
        result: project,
        errors: vec![],
        result_info: None,
        etag: None,
        cf_ray: None,
    }
}

fn profile() -> ProfileMetadata {
    let mut profile = ProfileMetadata::new("pages", ProfileKind::ApiToken, Some("account-a"));
    profile.credential_generation_id = Some("22222222-2222-4222-8222-222222222222".to_owned());
    profile
}

fn catalog() -> CatalogSnapshot {
    CatalogSnapshot {
        schema_version: 1,
        generated_at: Utc::now(),
        source_url: "fixture://pages".to_owned(),
        source_hash: hash_value(&json!("source")).expect("Pages setup fixture succeeds"),
        schema_hash: hash_value(&json!("catalog")).expect("Pages setup fixture succeeds"),
        capabilities: BTreeMap::from([
            (contract::CREATE_ID.to_owned(), capability(true)),
            (contract::VARIABLES_ID.to_owned(), capability(false)),
        ]),
    }
}

fn save_plan(store: &StorageStateStore, plan: &PlanV1) {
    let pins = PlanPinsV2 {
        build_identity_hash: hash_value(
            &serde_json::to_value(crate::build_identity::current_build_info())
                .expect("Pages setup fixture succeeds"),
        )
        .expect("Pages setup fixture succeeds"),
        catalog_hash: plan.catalog_hash.clone(),
        credential_generation_id: profile()
            .credential_generation_id
            .expect("Pages setup fixture succeeds"),
        admission_policy_hash: "compiled:test".to_owned(),
        authority_hash: None,
        workspace_graph_hash: hash_value(&json!("workspace"))
            .expect("Pages setup fixture succeeds"),
        resource_observation_hashes: BTreeMap::new(),
        cost_budget: None,
    };
    store
        .save_plan_v2(&PlanV2::new(plan.clone(), pins).expect("Pages setup fixture succeeds"))
        .expect("Pages setup fixture succeeds");
}

fn consumed_plan(
    store: &StorageStateStore,
    creating: bool,
    input: &CallInput,
    targets: Value,
) -> PlanV1 {
    let mut plan = PlanV1::draft(
        "pages",
        "account-a",
        &catalog().schema_hash,
        capability(creating),
        targets,
    )
    .expect("Pages setup fixture succeeds");
    plan.input = serde_json::to_value(input).expect("Pages setup fixture succeeds");
    "api_token".clone_into(&mut plan.permission_lane);
    plan.refresh_hash().expect("Pages setup fixture succeeds");
    plan.approve(true, None)
        .expect("Pages setup fixture succeeds");
    plan.mark_consumed().expect("Pages setup fixture succeeds");
    plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("Pages setup fixture succeeds");
    save_plan(store, &plan);
    plan
}

async fn response_server(bodies: Vec<Value>) -> (String, tokio::task::JoinHandle<Vec<String>>) {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Pages setup fixture succeeds");
    let address = listener.local_addr().expect("Pages setup fixture succeeds");
    let task = tokio::spawn(async move {
        let mut requests = Vec::new();
        for body in bodies {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("Pages setup fixture succeeds");
            let mut data = vec![0_u8; 16384];
            let size = stream
                .read(&mut data)
                .await
                .expect("Pages setup fixture succeeds");
            requests.push(
                String::from_utf8(data[..size].to_vec()).expect("Pages setup fixture succeeds"),
            );
            let body = body.to_string();
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.expect("Pages setup fixture succeeds");
        }
        requests
    });
    (format!("http://{address}/client/v4"), task)
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one authenticated create transaction supplies the positive admission and all identity, custody and expiry refusal cases"
)]
async fn pages_setup_native_create_receipt_admits_only_exact_current_initial_project() {
    let root = tempfile::tempdir().expect("Pages setup fixture succeeds");
    let store = authenticated_test_store(RuntimePaths::from_root(root.path()));
    let input = CallInput {
        selectors: json!({"account_id":"account-a"}),
        query: json!({}),
        body: Some(json!({"name":"codex-token-bar","production_branch":"main"})),
        ..CallInput::default()
    };
    let mut plan = consumed_plan(&store, true, &input, json!({}));
    let project = project();
    let provider = json!({"success":true,"result":project,"errors":[]});
    let (url, server) = response_server(vec![provider.clone(), provider]).await;
    let executor =
        Executor::new(reqwest::Client::new(), &url).expect("Pages setup fixture succeeds");
    let credential = AuthCredential::Bearer {
        token: "test-token".to_owned(),
    };
    let secrets = MemorySecretStore::default();
    let apply = executor
        .execute_consumed_plan_with_input(&mut plan, &catalog().schema_hash, &credential, &input)
        .await
        .expect("Pages setup fixture succeeds");
    assert!(matches!(
        process_api_boundary_response(&store, &mut plan, &apply, &secrets)
            .expect("Pages setup fixture succeeds"),
        ApiBoundaryResponseOutcome::Ready { .. }
    ));
    let verified = verify_api_plan(&store, &executor, &mut plan, &apply, &input, &credential)
        .await
        .expect("Pages setup fixture succeeds");
    assert_eq!(verified.state, VerificationState::Passed);
    persist_transaction_stage(&store, &mut plan, TransactionStageV1::Closed)
        .expect("Pages setup fixture succeeds");
    let requests = server.await.expect("Pages setup fixture succeeds");
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with("POST /client/v4/accounts/account-a/pages/projects "));
    assert!(
        requests[1]
            .starts_with("GET /client/v4/accounts/account-a/pages/projects/codex-token-bar ")
    );
    let proof = pages_direct_proof::find(
        &store,
        &catalog(),
        &profile(),
        "account-a",
        "codex-token-bar",
        &project,
    )
    .expect("Pages setup fixture succeeds");
    assert!(
        pages_direct_proof::find_at(
            &store,
            &catalog(),
            &profile(),
            "account-a",
            "codex-token-bar",
            &project,
            plan.expires_at + ChronoDuration::seconds(1)
        )
        .is_err()
    );
    let unauthenticated = StorageStateStore::open(RuntimePaths::from_root(root.path()))
        .expect("Pages setup fixture succeeds");
    assert!(
        pages_direct_proof::find(
            &unauthenticated,
            &catalog(),
            &profile(),
            "account-a",
            "codex-token-bar",
            &project
        )
        .is_err()
    );
    let deploy = CapabilityV1::new(
        "wrangler.pages-deploy",
        "Pages upload",
        "CLI",
        "wrangler pages deploy",
    );
    assert!(
        apply_project_response(
            &deploy,
            "account-a",
            "codex-token-bar",
            Some("main"),
            &response(project.clone())
        )
        .is_err()
    );
    let receipt = apply_project_response_with_create_proof(
        &deploy,
        "account-a",
        "codex-token-bar",
        Some("main"),
        &response(project.clone()),
        Some(&proof),
    )
    .expect("Pages setup fixture succeeds");
    assert!(receipt_source_mode_is_bound(&receipt, "direct_upload"));
    assert_eq!(
        receipt["source_mode_basis"],
        "omitted_source_authenticated_direct_create"
    );
    for (field, value) in [
        ("id", json!("recreated-project")),
        ("source", json!({"type":"github","config":{}})),
        ("production_branch", json!("preview")),
        ("build_config", json!({"build_command":"npm build"})),
    ] {
        let mut other = project.clone();
        other[field] = value;
        assert!(
            pages_direct_proof::find(
                &store,
                &catalog(),
                &profile(),
                "account-a",
                "codex-token-bar",
                &other
            )
            .is_err()
        );
    }
    let mut rotated = profile();
    rotated.credential_generation_id = Some(Uuid::new_v4().to_string());
    assert!(
        pages_direct_proof::find(
            &store,
            &catalog(),
            &rotated,
            "account-a",
            "codex-token-bar",
            &project
        )
        .is_err()
    );
    let mut other_catalog = catalog();
    other_catalog.schema_hash = hash_value(&json!("other")).expect("Pages setup fixture succeeds");
    assert!(
        pages_direct_proof::find(
            &store,
            &other_catalog,
            &profile(),
            "account-a",
            "codex-token-bar",
            &project
        )
        .is_err()
    );
    assert!(
        pages_direct_proof::find(
            &store,
            &catalog(),
            &profile(),
            "other-account",
            "codex-token-bar",
            &project
        )
        .is_err()
    );
    let mut tampered = receipt.clone();
    tampered["project_id"] = json!("different");
    assert!(!receipt_source_mode_is_bound(&tampered, "direct_upload"));
    let verification_path = verified
        .evidence
        .expect("Pages setup fixture succeeds")
        .path;
    let bytes = fs::read(&verification_path).expect("Pages setup fixture succeeds");
    fs::write(&verification_path, b"{\"passed\":true}").expect("Pages setup fixture succeeds");
    assert!(
        pages_direct_proof::find(
            &store,
            &catalog(),
            &profile(),
            "account-a",
            "codex-token-bar",
            &project
        )
        .is_err()
    );
    fs::write(verification_path, bytes).expect("Pages setup fixture succeeds");
    let descriptor_hash = proof["verification_evidence_hash"]
        .as_str()
        .expect("Pages setup fixture succeeds");
    let (descriptor, _) = store
        .load_evidence_value(descriptor_hash)
        .expect("Pages setup fixture succeeds");
    assert_eq!(descriptor.class, EvidenceClass::PostChangeVerification);
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the secret lifecycle test follows the protected input through execution, cleanup, verification and every durable receipt"
)]
async fn pages_setup_secret_input_is_resolved_once_cleaned_and_never_written_to_receipts() {
    let root = tempfile::tempdir().expect("Pages setup fixture succeeds");
    let store = authenticated_test_store(RuntimePaths::from_root(root.path()));
    let secrets = MemorySecretStore::default();
    let body = json!({"deployment_configs":{"production":{"env_vars":{
        "PLAIN":{"type":"plain_text","value":"plain-canary-private"},
        "RESEND_API_KEY":{"type":"secret_text","value":"secret-canary-private"}
    }}}});
    assert!(request_body_contains_secret(&capability(false), &body));
    assert!(!is_secret_output_capability(&capability(false)));
    let target = variable_target(&body).expect("Pages setup fixture succeeds");
    let reference = "plan-input/pages-test";
    secrets
        .put(reference, &body.to_string())
        .expect("Pages setup fixture succeeds");
    let stored_input = CallInput {
        selectors: json!({"account_id":"account-a","project_name":"codex-token-bar"}),
        query: json!({}),
        body: Some(
            json!({"$cfctl_secret_body_ref":reference,"content_hash":hash_value(&body).expect("Pages setup fixture succeeds")}),
        ),
        ..CallInput::default()
    };
    let prior = project();
    let state = variable_state_receipt(
        "account-a",
        "codex-token-bar",
        &target,
        &response(prior.clone()),
    )
    .expect("Pages setup fixture succeeds");
    let targets = json!({"adapter":{"secret_body_ref":reference,"secret_body_hash":hash_value(&body).expect("Pages setup fixture succeeds"),"pages_production_variables":target},
        "live_preconditions":{STATE_PRECONDITION:state}});
    let mut draft = PlanV1::draft(
        "pages",
        "account-a",
        &catalog().schema_hash,
        capability(false),
        targets,
    )
    .expect("Pages setup fixture succeeds");
    draft.input = serde_json::to_value(&stored_input).expect("Pages setup fixture succeeds");
    draft.precondition_hashes.insert(
        STATE_PRECONDITION.to_owned(),
        hash_value(&state).expect("Pages setup fixture succeeds"),
    );
    "api_token".clone_into(&mut draft.permission_lane);
    draft.refresh_hash().expect("Pages setup fixture succeeds");
    draft
        .approve(true, None)
        .expect("Pages setup fixture succeeds");
    draft.mark_consumed().expect("Pages setup fixture succeeds");
    draft
        .record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("Pages setup fixture succeeds");
    save_plan(&store, &draft);
    let input = resolved_plan_input(&draft, &secrets).expect("Pages setup fixture succeeds");
    assert_eq!(input.body, Some(body.clone()));
    let mut after = prior;
    after["deployment_configs"]["production"]["env_vars"] =
        body["deployment_configs"]["production"]["env_vars"].clone();
    let provider = json!({"success":true,"result":after,"errors":[]});
    let (url, server) = response_server(vec![provider.clone(), provider]).await;
    let executor =
        Executor::new(reqwest::Client::new(), &url).expect("Pages setup fixture succeeds");
    let credential = AuthCredential::Bearer {
        token: "test-token".to_owned(),
    };
    let apply = executor
        .execute_consumed_plan_with_input(&mut draft, &catalog().schema_hash, &credential, &input)
        .await
        .expect("Pages setup fixture succeeds");
    assert!(matches!(
        process_api_boundary_response(&store, &mut draft, &apply, &secrets)
            .expect("Pages setup fixture succeeds"),
        ApiBoundaryResponseOutcome::Ready { .. }
    ));
    assert!(
        secrets
            .get(reference)
            .expect("Pages setup fixture succeeds")
            .is_none()
    );
    let verified = verify_api_plan(&store, &executor, &mut draft, &apply, &input, &credential)
        .await
        .expect("Pages setup fixture succeeds");
    assert_eq!(verified.state, VerificationState::Passed);
    let (_, stored_verification) = store
        .load_evidence_value(
            &verified
                .evidence
                .as_ref()
                .expect("Pages setup fixture succeeds")
                .content_hash,
        )
        .expect("Pages setup fixture succeeds");
    assert!(
        stored_verification["readback"]["result"]["deployment_configs"]["production"]["env_vars"]
            .as_array()
            .expect("Pages setup fixture succeeds")
            .iter()
            .any(|entry| entry["name"] == "RESEND_API_KEY" && entry["type"] == "secret_text")
    );
    persist_transaction_stage(&store, &mut draft, TransactionStageV1::Closed)
        .expect("Pages setup fixture succeeds");
    assert_eq!(server.await.expect("Pages setup fixture succeeds").len(), 2);
    for entry in walkdir::WalkDir::new(root.path())
        .into_iter()
        .map(|entry| entry.expect("durable test state entry"))
        .filter(|entry| entry.file_type().is_file())
    {
        let bytes = fs::read(entry.path()).expect("Pages setup fixture succeeds");
        let text = String::from_utf8_lossy(&bytes);
        for marker in ["plain-canary-private", "secret-canary-private"] {
            assert!(
                !text.contains(marker),
                "value leaked into durable test state"
            );
        }
    }
}

#[test]
fn pages_setup_redacts_values_and_provider_errors_on_project_read_and_setup_paths() {
    let raw = json!({"status":400,"success":false,"errors":[{"code":1000,"message":"error-value-canary"}],
        "result":{"deployment_configs":{"preview":{"env_vars":{"P":{"type":"plain_text","value":"preview-value-canary"}}},
        "production":{"env_vars":{"SECRET":{"type":"secret_text","value":"secret-value-canary"}}}}}});
    let mut read = capability(true);
    contract::READ_ID.clone_into(&mut read.id);
    "GET".clone_into(&mut read.method);
    contract::DETAIL.clone_into(&mut read.path);
    read.risk = RiskClass::Read;
    read.mutating = false;
    for cap in [&capability(true), &capability(false), &read] {
        assert!(should_redact_secret_response(cap));
        let rendered = redact_response_for_capability(cap, &raw).to_string();
        for marker in [
            "error-value-canary",
            "preview-value-canary",
            "secret-value-canary",
        ] {
            assert!(!rendered.contains(marker));
        }
        let reflected = json!({"status":400,"success":false,"result":{"echo":"reflected-value-canary"},"unexpected":"reflected-value-canary","errors":[]});
        assert!(
            !redact_response_for_capability(cap, &reflected)
                .to_string()
                .contains("reflected-value-canary")
        );
        let malformed = json!({"result":{"deployment_configs":{"production":{"env_vars":"malformed-value-canary"}}}});
        assert!(
            !redact_response_for_capability(cap, &malformed)
                .to_string()
                .contains("malformed-value-canary")
        );
    }
}

#[test]
fn pages_project_redaction_preserves_domains_and_hides_nested_credentials() {
    let mut read = capability(true);
    contract::READ_ID.clone_into(&mut read.id);
    "GET".clone_into(&mut read.method);
    contract::DETAIL.clone_into(&mut read.path);
    read.risk = RiskClass::Read;
    read.mutating = false;
    let raw = json!({"status":200,"success":true,"result":{
        "name":"aos-web", "production_branch":"main",
        "domains":["adapteros.com","www.adapteros.com"],
        "deployment_configs":{"production":{"env_vars":{
            "SECRET":{"type":"secret_text","value":"environment-secret-canary"}
        }}},
        "deployments":[{"aliases":["main.aos-web.pages.dev"],
            "credentials":[{"token":"deployment-token-canary"}]}]
    }});
    let redacted = redact_response_for_capability(&read, &raw);
    assert_eq!(redacted["result"]["domains"], raw["result"]["domains"]);
    assert_eq!(
        redacted["result"]["deployments"][0]["aliases"],
        raw["result"]["deployments"][0]["aliases"]
    );
    assert!(!redacted.to_string().contains("environment-secret-canary"));
    assert!(!redacted.to_string().contains("deployment-token-canary"));
}

#[test]
fn pages_setup_direct_create_reuses_absence_without_git_repository_preconditions() {
    let cap = capability(true);
    assert!(should_bind_pages_project_absence(&cap));
    assert!(!is_git_pages_project_create(&cap));
    let root = tempfile::tempdir().expect("Pages setup fixture succeeds");
    let store = authenticated_test_store(RuntimePaths::from_root(root.path()));
    let input = CallInput {
        selectors: json!({"account_id":"account-a"}),
        query: json!({}),
        body: Some(json!({"name":"codex-token-bar","production_branch":"main"})),
        ..CallInput::default()
    };
    assert!(
        prepare_pages_source_remote_precondition(&store, &cap, &input)
            .expect("Pages setup fixture succeeds")
            .is_none()
    );
    let response = CloudflareResponseV1 {
        status: 404,
        success: false,
        result: Value::Null,
        errors: vec![CloudflareApiErrorV1 {
            code: Some(PROJECT_NOT_FOUND_ERROR_CODE),
            message: "not found".to_owned(),
        }],
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let mut receipt =
        apply_pages_project_absence_response("account-a", "codex-token-bar", &response)
            .expect("Pages setup fixture succeeds");
    receipt["target_capability_id"] = json!(contract::CREATE_ID);
    let mut plan = PlanV1::draft(
        "pages",
        "account-a",
        &catalog().schema_hash,
        cap,
        json!({"live_preconditions":{PROJECT_ABSENCE_PRECONDITION:receipt}}),
    )
    .expect("Pages setup fixture succeeds");
    plan.input = serde_json::to_value(input).expect("Pages setup fixture succeeds");
    plan.precondition_hashes.insert(
        PROJECT_ABSENCE_PRECONDITION.to_owned(),
        hash_value(&receipt).expect("Pages setup fixture succeeds"),
    );
    assert!(
        required_pages_project_absence_precondition(&plan)
            .expect("Pages setup fixture succeeds")
            .is_some()
    );
    plan.targets["live_preconditions"][PROJECT_ABSENCE_PRECONDITION]["target_capability_id"] =
        json!("pages-project-create-project");
    assert!(required_pages_project_absence_precondition(&plan).is_err());
}

#[tokio::test]
async fn pages_setup_uncertain_http_status_requires_rectification_without_verification_claim() {
    for status in [429, 500] {
        let root = tempfile::tempdir().expect("Pages setup fixture succeeds");
        let store = authenticated_test_store(RuntimePaths::from_root(root.path()));
        let input = CallInput {
            selectors: json!({"account_id":"account-a"}),
            query: json!({}),
            body: Some(json!({"name":"codex-token-bar","production_branch":"main"})),
            ..CallInput::default()
        };
        let mut plan = consumed_plan(&store, true, &input, json!({}));
        plan.status = PlanStatus::Failed;
        let mut uncertain = response(Value::Null);
        uncertain.status = status;
        uncertain.success = false;
        uncertain.errors = vec![CloudflareApiErrorV1 {
            code: Some(1000),
            message: "provider-echo-private".to_owned(),
        }];
        let secrets = MemorySecretStore::default();
        assert!(matches!(
            process_api_boundary_response(&store, &mut plan, &uncertain, &secrets)
                .expect("Pages setup fixture succeeds"),
            ApiBoundaryResponseOutcome::Ready { .. }
        ));
        let executor = Executor::new(reqwest::Client::new(), "http://127.0.0.1:1")
            .expect("Pages setup fixture succeeds");
        let result = verify_api_plan(
            &store,
            &executor,
            &mut plan,
            &uncertain,
            &input,
            &AuthCredential::Bearer {
                token: "test-token".to_owned(),
            },
        )
        .await
        .expect("Pages setup fixture succeeds");
        assert_eq!(result.state, VerificationState::Pending);
        assert_eq!(plan.status, PlanStatus::RectificationRequired);
        assert_eq!(
            result.error.expect("Pages setup fixture succeeds").code,
            "CFCTL_PAGES_SETUP_OUTCOME_AMBIGUOUS"
        );
        assert!(result.evidence.is_none());
        assert!(
            !serde_json::to_string(&plan)
                .expect("Pages setup fixture succeeds")
                .contains("provider-echo-private")
        );
    }
}

#[test]
fn pages_configuration_metadata_survives_receipt_redaction_without_variable_values() {
    let mut cap = capability(false);
    cap.id = contract::READ_ID.into();
    cap.method = "GET".into();
    cap.mutating = false;
    let raw = json!({"success":true,"status":200,"result":{"name":"fixture",
        "source":{"config":{"preview_branch_includes":["preview/*"]}},
        "deployment_configs":{"preview":{"env_vars":{"ACCESS_AUD":{"type":"secret_text","value":"CANARY_PRIVATE"}}}}}});
    let projected = redact_response_for_capability(&cap, &raw);
    let store_root = tempfile::tempdir().expect("receipt root");
    let store = StateStore::open(RuntimePaths::from_root(store_root.path())).expect("store");
    let evidence = store
        .write_observation_evidence(EvidenceClass::LiveRead, &projected)
        .expect("receipt");
    let stored = store
        .read_evidence_value(&evidence.content_hash)
        .expect("stored receipt");
    assert_eq!(
        stored["configuration_metadata"]["triggers"]["preview_branch_includes"]["observed"][0]["pattern"],
        "preview/*"
    );
    let envelope = ResultEnvelopeV2::success("call", projected).with_evidence(evidence);
    let rendered = serde_json::to_string(&envelope).expect("public envelope");
    assert!(!rendered.contains("CANARY_PRIVATE"));
    assert!(!stored.to_string().contains("CANARY_PRIVATE"));
    let failed =
        redact_response_for_capability(&cap, &json!({"success":false,"result":raw["result"]}));
    assert!(failed.get("configuration_metadata").is_none());
}
