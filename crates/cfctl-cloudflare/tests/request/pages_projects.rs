use super::{
    AdapterStatus, AuthCredential, CallInput, CapabilityV1, CloudflareResponseV1,
    CreatedResourceContractV1, EffectClass, Executor, PlanStatus, PlanV1, RequestBuilder,
    ResponseBodyModeV1, ResponseContractV1, RiskClass, SamePathReadContractV1, Value, json,
    json_response_sequence_server, path_selector, single_raw_response_server,
    validate_request_contract,
};
use cfctl_cloudflare::pages_projects::{
    STATE_PRECONDITION, validate_variable_plan_state, variable_state_receipt, variable_target,
};
use cfctl_core::{hash_value, pages_projects as contract};

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
    cap.adapter_status = AdapterStatus::DynamicApi;
    cap.mutating = true;
    cap.effect = EffectClass::ReversibleWrite;
    cap.risk = if creating {
        RiskClass::CrossConfig
    } else {
        RiskClass::SecretSensitive
    };
    cap.permissions = vec!["Pages Write".to_owned()];
    cap.selectors = vec![path_selector("account_id")];
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
        cap.selectors.push(path_selector("project_name"));
        cap.request_schema = Some(contract::variables_schema());
        contract::VARIABLES_STRATEGY.clone_into(&mut cap.verification.strategy);
        cap.same_path_read = Some(SamePathReadContractV1 {
            path: contract::DETAIL.to_owned(),
            read_capability_id: contract::READ_ID.to_owned(),
            verified_response_fields: vec!["deployment_configs".to_owned()],
        });
    }
    assert!(cap.verification_contract_supported());
    cap
}

fn project() -> Value {
    json!({"id":"11111111-1111-4111-8111-111111111111", "name":"codex-token-bar", "production_branch":"main",
    "build_config":{"build_command":"","destination_dir":"","root_dir":""},
    "deployment_configs":{
        "production":{"compatibility_date":"2026-09-01"},
        "preview":{"env_vars":{"PREVIEW":{"type":"plain_text","value":"existing-preview-private"}}}
    }})
}

fn body() -> Value {
    json!({"deployment_configs":{"production":{"env_vars":{
        "SITE_ORIGIN":{"type":"plain_text","value":"https://private-input.example"},
        "SECRET_KEY":{"type":"secret_text","value":"private-secret-input-canary"}
    }}}})
}

fn input(creating: bool) -> CallInput {
    CallInput {
        selectors: if creating {
            json!({"account_id":"account-a"})
        } else {
            json!({"account_id":"account-a","project_name":"codex-token-bar"})
        },
        query: json!({}),
        body: Some(if creating {
            json!({"name":"codex-token-bar","production_branch":"main"})
        } else {
            body()
        }),
        ..CallInput::default()
    }
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

fn variables_plan(prior: &Value) -> (PlanV1, CallInput) {
    let input = input(false);
    let target = variable_target(input.body.as_ref().unwrap()).unwrap();
    let receipt = variable_state_receipt(
        "account-a",
        "codex-token-bar",
        &target,
        &response(prior.clone()),
    )
    .unwrap();
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-a",
        capability(false),
        json!({
            "adapter":{"pages_production_variables":target},
            "live_preconditions":{STATE_PRECONDITION:receipt}
        }),
    )
    .unwrap();
    plan.input = serde_json::to_value(&input).unwrap();
    plan.precondition_hashes
        .insert(STATE_PRECONDITION.to_owned(), hash_value(&receipt).unwrap());
    (plan, input)
}

fn configured(prior: &Value) -> Value {
    let mut after = prior.clone();
    if after
        .pointer("/deployment_configs/production/env_vars")
        .is_none()
    {
        after["deployment_configs"]["production"]["env_vars"] = json!({});
    }
    for (name, value) in contract::requested_variables(&body()).unwrap() {
        after["deployment_configs"]["production"]["env_vars"][name] = value.clone();
    }
    // Cloudflare secrets are write-only; a value match is deliberately impossible.
    after["deployment_configs"]["production"]["env_vars"]["SECRET_KEY"] =
        json!({"type":"secret_text"});
    after
}

#[test]
fn pages_setup_requests_reject_every_widening_and_never_echo_values() {
    let builder = RequestBuilder::new("https://api.cloudflare.com/client/v4").unwrap();
    for creating in [true, false] {
        let cap = capability(creating);
        let valid = input(creating);
        let request = builder.build_unchecked(&cap, &valid).unwrap();
        assert_eq!(request.body, valid.body);
        assert!(request.url.as_str().ends_with(if creating {
            "/pages/projects"
        } else {
            "/pages/projects/codex-token-bar"
        }));
        for key in [
            "source",
            "build_config",
            "usage_model",
            "preview",
            "unknown",
        ] {
            let mut wrong = valid.clone();
            wrong.body.as_mut().unwrap()[key] = json!("private-secret-input-canary");
            let error = validate_request_contract(&cap, &wrong)
                .unwrap_err()
                .to_string();
            assert!(!error.contains("private-secret-input-canary"));
        }
        let mut query = valid.clone();
        query.query = json!({"force":true});
        assert!(validate_request_contract(&cap, &query).is_err());
    }
    for patch in [
        json!({"deployment_configs":{"preview":{"env_vars":{"X":{"type":"plain_text","value":"secret"}}}}}),
        json!({"deployment_configs":{"production":{"usage_model":"unbound","env_vars":{"X":{"type":"plain_text","value":"secret"}}}}}),
        json!({"deployment_configs":{"production":{"env_vars":{"X":null}}}}),
        json!({"deployment_configs":{"production":{"env_vars":{"X":{"type":"secret_text","value":null}}}}}),
        json!({"deployment_configs":{"production":{"env_vars":{"X":{"type":"plain_text","value":""}}}}}),
        json!({"deployment_configs":{"production":{"env_vars":{"bad name private-secret-input-canary":{"type":"plain_text","value":"x"}}}}}),
        json!({"deployment_configs":{"production":{"env_vars":{"X":{"type":"json","value":"secret"}}}}}),
    ] {
        let mut invalid = input(false);
        invalid.body = Some(patch);
        let error = validate_request_contract(&capability(false), &invalid)
            .unwrap_err()
            .to_string();
        assert!(!error.contains("private-secret-input-canary"));
    }
    let mut bad = input(true);
    bad.body.as_mut().unwrap()["production_branch"] = json!("preview");
    assert!(validate_request_contract(&capability(true), &bad).is_err());
}

#[test]
fn pages_setup_variable_target_producer_joins_prefixed_hashes_and_refuses_overwrite() {
    let prior = project();
    let (plan, input) = variables_plan(&prior);
    let receipt = validate_variable_plan_state(&plan, &input).unwrap();
    assert!(
        receipt["configuration_hash"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    assert!(
        receipt["input_target"]["body_hash"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    assert!(!receipt.to_string().contains("private-secret-input-canary"));
    assert!(!receipt.to_string().contains("private-input.example"));
    let mut existing = prior.clone();
    existing["deployment_configs"]["production"]["env_vars"] =
        json!({"SITE_ORIGIN":{"type":"plain_text","value":"old"}});
    assert!(
        variable_state_receipt(
            "account-a",
            "codex-token-bar",
            &receipt["input_target"],
            &response(existing)
        )
        .is_err()
    );
    for field in ["body_hash", "requested_variables"] {
        let mut changed = plan.clone();
        changed.targets["adapter"]["pages_production_variables"][field] = Value::Null;
        assert!(validate_variable_plan_state(&changed, &input).is_err());
    }
    let mut changed_input = input;
    changed_input.body.as_mut().unwrap()["deployment_configs"]["production"]["env_vars"]["SECRET_KEY"]
        ["value"] = json!("different");
    assert!(validate_variable_plan_state(&plan, &changed_input).is_err());
}

#[tokio::test]
async fn pages_setup_adds_values_and_preserves_absent_empty_and_existing_inventory() {
    for inventory in [
        None,
        Some(json!({})),
        Some(json!({"KEEP":{"type":"plain_text","value":"prior-production-private"}})),
    ] {
        let mut prior = project();
        if let Some(inventory) = inventory {
            prior["deployment_configs"]["production"]["env_vars"] = inventory;
        }
        let after = configured(&prior);
        let (plan, input) = variables_plan(&prior);
        let (address, server) = json_response_sequence_server(vec![
            json!({"success":true,"result":after,"errors":[]}).to_string(),
        ])
        .await;
        let executor = Executor::new(
            reqwest::Client::new(),
            &format!("http://{address}/client/v4"),
        )
        .unwrap();
        let outcome = executor
            .verify_plan_with_input(
                &plan,
                &response(after),
                &input,
                &AuthCredential::Bearer {
                    token: "test-token".to_owned(),
                },
            )
            .await
            .unwrap();
        assert!(outcome.passed, "{}", outcome.basis);
        let rendered = serde_json::to_string(&outcome).unwrap();
        for marker in [
            "private-secret-input-canary",
            "private-input.example",
            "prior-production-private",
            "existing-preview-private",
        ] {
            assert!(!rendered.contains(marker), "leaked variable value");
        }
        let requests = server.await.unwrap();
        assert_eq!(requests.len(), 1);
        assert!(
            requests[0]
                .starts_with("GET /client/v4/accounts/account-a/pages/projects/codex-token-bar ")
        );
    }
}

#[tokio::test]
async fn pages_setup_verification_rejects_partial_writes_identity_drift_and_sibling_changes() {
    let prior = project();
    let valid = configured(&prior);
    for (pointer, replacement) in [
        ("/id", json!("other-id")),
        ("/name", json!("other-project")),
        ("/source", json!({"type":"github","config":{}})),
        (
            "/deployment_configs/production/env_vars/SECRET_KEY/type",
            json!("plain_text"),
        ),
        (
            "/deployment_configs/production/env_vars/SITE_ORIGIN/value",
            json!("incorrect"),
        ),
        (
            "/deployment_configs/production/compatibility_date",
            json!("2020-01-01"),
        ),
        (
            "/deployment_configs/preview/env_vars/PREVIEW/value",
            json!("changed"),
        ),
    ] {
        let mut drifted = valid.clone();
        if pointer == "/source" {
            drifted["source"] = replacement;
        } else {
            *drifted.pointer_mut(pointer).unwrap() = replacement;
        }
        let (plan, input) = variables_plan(&prior);
        let (address, server) = json_response_sequence_server(vec![
            json!({"success":true,"result":drifted,"errors":[]}).to_string(),
        ])
        .await;
        let executor = Executor::new(
            reqwest::Client::new(),
            &format!("http://{address}/client/v4"),
        )
        .unwrap();
        let outcome = executor
            .verify_plan_with_input(
                &plan,
                &response(valid.clone()),
                &input,
                &AuthCredential::Bearer {
                    token: "test-token".to_owned(),
                },
            )
            .await
            .unwrap();
        assert!(!outcome.passed, "unexpected match for {pointer}");
        server.await.unwrap();
    }
}

#[tokio::test]
async fn pages_setup_direct_create_verifies_returned_project_id_and_no_git() {
    let created = project();
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-a",
        capability(true),
        json!({}),
    )
    .unwrap();
    let input = input(true);
    plan.input = serde_json::to_value(&input).unwrap();
    for matches in [true, false] {
        let mut observed = created.clone();
        if !matches {
            observed["id"] = json!("recreated-id");
        }
        let (address, server) = json_response_sequence_server(vec![
            json!({"success":true,"result":observed,"errors":[]}).to_string(),
        ])
        .await;
        let executor = Executor::new(
            reqwest::Client::new(),
            &format!("http://{address}/client/v4"),
        )
        .unwrap();
        let outcome = executor
            .verify_plan(
                &plan,
                &response(created.clone()),
                &AuthCredential::Bearer {
                    token: "test-token".to_owned(),
                },
            )
            .await
            .unwrap();
        assert_eq!(outcome.passed, matches);
        assert!(server.await.unwrap()[0].contains("/pages/projects/codex-token-bar"));
    }
    for source in [
        json!({}),
        json!({"type":"github","config":{}}),
        json!(false),
    ] {
        let mut wrong = created.clone();
        wrong["source"] = source;
        let executor = Executor::new(reqwest::Client::new(), "http://127.0.0.1:1").unwrap();
        let outcome = executor
            .verify_plan(
                &plan,
                &response(wrong),
                &AuthCredential::Bearer {
                    token: "test-token".to_owned(),
                },
            )
            .await
            .unwrap();
        assert!(!outcome.passed);
    }
}

#[tokio::test]
async fn pages_setup_mutations_never_retry_an_uncertain_boundary() {
    for creating in [true, false] {
        let (mut plan, input) = if creating {
            (
                PlanV1::draft("p", "account-a", "catalog-a", capability(true), json!({})).unwrap(),
                input(true),
            )
        } else {
            variables_plan(&project())
        };
        plan.status = PlanStatus::Consumed;
        let (address,server) = single_raw_response_server("500 Internal Server Error", "application/json",
            json!({"success":false,"result":null,"errors":[{"code":1000,"message":"private-secret-input-canary"}]}).to_string()).await;
        let executor = Executor::new(
            reqwest::Client::new(),
            &format!("http://{address}/client/v4"),
        )
        .unwrap()
        .with_max_retries(2);
        let result = executor
            .execute_consumed_plan_with_input(
                &mut plan,
                "catalog-a",
                &AuthCredential::Bearer {
                    token: "test-token".to_owned(),
                },
                &input,
            )
            .await
            .unwrap();
        assert_eq!(result.status, 500);
        server.await.unwrap();
    }
}
