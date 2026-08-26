use super::*;

pub(super) fn access_human_policy_live_result() -> Value {
    json!({
        "created_at":"2026-07-14T09:51:08Z",
        "decision":"allow",
        "exclude":[{"email":{"email":"founders@mlnavigator.com"}}],
        "id":"45e44306-0e2a-460a-94aa-34c21eefdb4a",
        "include":[{"email_domain":{"domain":"mlnavigator.com"}}],
        "mfa_config":{
            "allowed_authenticators":["biometrics","totp"],
            "mfa_disabled":false,
            "session_duration":""
        },
        "name":"Allow MLNavigator Investor Staff",
        "precedence":1,
        "require":[],
        "reusable":false,
        "session_duration":"24h",
        "uid":"45e44306-0e2a-460a-94aa-34c21eefdb4a",
        "updated_at":"2026-07-29T02:40:54Z"
    })
}

pub(super) fn access_human_policy_capability() -> CapabilityV1 {
    let identity_rule = super::access_human_policy_identity_rule_schema();
    let mut capability = CapabilityV1::new(
        super::ACCESS_HUMAN_POLICY_UPDATE_CAPABILITY_ID,
        "Update human Access eligibility and independent MFA",
        "PUT",
        super::ACCESS_POLICY_DETAIL_PATH,
    );
    capability.product = "Access application-scoped policies".to_owned();
    capability.account_scope = "account".to_owned();
    capability.mutating = true;
    capability.adapter_status = AdapterStatus::DynamicApi;
    capability.permissions = vec!["Access: Apps and Policies Write".to_owned()];
    capability.risk = RiskClass::IdentityOrOwnership;
    capability.effect = EffectClass::IdentityOrOwnership;
    capability.cost.known = true;
    capability.cost.maximum = Some(0.0);
    capability.entitlement.available = Some(true);
    capability.selectors = ["account_id", "app_id", "policy_id"]
        .into_iter()
        .map(|name| SelectorV1 {
            name: name.to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        })
        .collect();
    capability.request_schema = Some(json!({
        "type":"object",
        "additionalProperties":false,
        "required":["name","decision","include","exclude","require","precedence"],
        "properties":{
            "name":{"type":"string","minLength":1,"maxLength":350},
            "decision":{"type":"string","enum":["allow"]},
            "include":{
                "type":"array",
                "minItems":1,
                "maxItems":100,
                "uniqueItems":true,
                "items":identity_rule.clone()
            },
            "exclude":{
                "type":"array",
                "maxItems":100,
                "uniqueItems":true,
                "items":identity_rule
            },
            "require":{"type":"array","maxItems":0},
            "precedence":{"type":"integer","minimum":1},
            "session_duration":{"type":"string","minLength":2,"maxLength":16},
            "mfa_config":super::access_human_policy_mfa_schema()
        },
        "x-cfctl-body-required":true
    }));
    capability.verification.required = true;
    capability.verification.strategy =
        "same_path_result_contains_planned_fields_after_update".to_owned();
    capability.same_path_read = Some(SamePathReadContractV1 {
        path: super::ACCESS_POLICY_DETAIL_PATH.to_owned(),
        read_capability_id: super::ACCESS_POLICY_READ_CAPABILITY_ID.to_owned(),
        verified_response_fields: super::ACCESS_HUMAN_POLICY_MUTABLE_FIELDS
            .iter()
            .map(|field| (*field).to_owned())
            .collect(),
    });
    capability.rollback.supported = true;
    capability.rollback.strategy = Some(super::SAME_PATH_PRIOR_STATE_ROLLBACK_STRATEGY.to_owned());
    capability.rollback.warning = Some("restoration requires a separate approved plan".to_owned());
    capability
}

#[test]
pub(super) fn access_human_policy_guide_readiness_uses_canonical_executable_contract() {
    let capability = access_human_policy_capability();
    assert!(
        capability.mutation_contract_gaps().is_empty(),
        "positive control requires an executable canonical human-policy contract"
    );

    let guide = guide_json(&capability);
    assert_eq!(
        guide["capability"]["request_schema"],
        super::access_human_policy_desired_schema(),
        "guide presentation must expose the caller-facing desired-state schema"
    );
    assert_eq!(
        guide["contract_state"], "available",
        "an executable human-policy operation must remain guide-ready: {:?}",
        guide["blocking_gaps"]
    );
    assert_eq!(guide["blocking_gaps"], json!([]));
    assert!(
        guide["call_argv"].as_array().is_some(),
        "an available human-policy guide must expose its governed call"
    );
    let stages = guide["stages"].as_array().expect("guide stages");
    for stage_name in ["verify", "rectify"] {
        let stage = stages
            .iter()
            .find(|stage| stage["name"] == stage_name)
            .expect("governed lifecycle stage");
        assert_eq!(
            stage["contract_state"], "available",
            "{stage_name} must be evaluated against the canonical executable contract"
        );
        assert!(
            stage["commands"]
                .as_array()
                .is_some_and(|commands| !commands.is_empty()),
            "{stage_name} must retain its governed command"
        );
    }
}

#[tokio::test]
pub(super) async fn catalog_search_exposes_same_access_caller_schema_as_show_and_call() {
    let root = tempfile::tempdir().expect("runtime root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let capability = access_human_policy_capability();
    let capability_id = capability.id.clone();
    let expected_schema = super::access_human_policy_desired_schema();
    let mut catalog = CatalogSnapshot {
        schema_version: 1,
        generated_at: Utc::now(),
        source_url: "https://example.invalid/openapi.json".to_owned(),
        source_hash: "source-sha".to_owned(),
        schema_hash: String::new(),
        capabilities: BTreeMap::from([(capability_id.clone(), capability.clone())]),
    };
    catalog.refresh_hash().expect("catalog hash");
    store
        .write_json(&store.paths().catalog_file(), &catalog)
        .expect("current catalog");

    let input = CallInput {
        selectors: json!({
            "account_id":"account-a",
            "app_id":"82131ea1-c7a6-4fc7-ab99-b11ddd2ff426",
            "policy_id":"45e44306-0e2a-460a-94aa-34c21eefdb4a"
        }),
        body: Some(json!({
            "mfa_config":{
                "allowed_authenticators":["biometrics","totp"],
                "mfa_disabled":false
            }
        })),
        ..CallInput::default()
    };
    super::validate_access_human_policy_desired_input(&capability, &input)
        .expect("the real call branch accepts the caller-facing body");

    let shown = super::catalog_command(
        &store,
        CatalogCommand::Show(CapabilitySelector {
            capability_id: capability_id.clone(),
        }),
    )
    .await
    .expect("catalog show");
    assert_eq!(
        shown.result["request_schema"], expected_schema,
        "catalog show positive control must expose the caller-facing schema"
    );

    let searched = super::catalog_command(
        &store,
        CatalogCommand::Search(SearchArgs {
            query: capability_id.clone(),
            limit: 1,
        }),
    )
    .await
    .expect("catalog search");
    let result = searched
        .result
        .as_array()
        .and_then(|results| results.first())
        .filter(|result| result.get("id").and_then(Value::as_str) == Some(&capability_id))
        .expect("catalog search returns the human-policy capability");
    assert_eq!(
        result["request_schema"], shown.result["request_schema"],
        "catalog search must expose the same caller-facing schema as show and call"
    );
}

#[test]
pub(super) fn access_discovery_matches_call_schema_and_keeps_materialization_internal() {
    let application = access_application_login_methods_capability();
    let application_input = CallInput {
        selectors: json!({
            "account_id":"account-a",
            "app_id":"82131ea1-c7a6-4fc7-ab99-b11ddd2ff426"
        }),
        body: Some(json!({
            "allowed_idps":["7b0bc477-5d42-4dab-b0ea-c97d0aef7810"]
        })),
        ..CallInput::default()
    };
    super::validate_access_application_login_methods_desired_input(
        &application,
        &application_input,
    )
    .expect("the real call branch accepts the narrow application input");

    let human_policy = access_human_policy_capability();
    let human_input = CallInput {
        selectors: json!({
            "account_id":"account-a",
            "app_id":"82131ea1-c7a6-4fc7-ab99-b11ddd2ff426",
            "policy_id":"45e44306-0e2a-460a-94aa-34c21eefdb4a"
        }),
        body: Some(json!({
            "mfa_config":{
                "allowed_authenticators":["biometrics","totp"],
                "mfa_disabled":false
            }
        })),
        ..CallInput::default()
    };
    super::validate_access_human_policy_desired_input(&human_policy, &human_input)
        .expect("the real call branch accepts the narrow human-policy input");

    let application_body = super::access_application_mutable_body(
        &access_application_live_result(),
        &super::access_application_desired_idps(&application_input)
            .expect("validated desired identity providers"),
        super::access_application_login_methods_variant(&application.id)
            .expect("self-hosted application variant"),
    )
    .expect("application materialization");
    assert!(
        application_body.get("name").is_some() && application_body.get("policies").is_some(),
        "the provider PUT body remains an internal full-state materialization"
    );
    let human_body = super::access_human_policy_mutable_body(
        &access_human_policy_live_result(),
        &super::access_human_policy_desired_changes(&human_input)
            .expect("validated desired human-policy changes"),
    )
    .expect("human-policy materialization");
    assert!(
        human_body.get("name").is_some() && human_body.get("decision").is_some(),
        "the provider policy PUT body remains an internal full-state materialization"
    );

    let mut mismatches = Vec::new();
    for (label, capability, input, desired_schema) in [
        (
            "application",
            application,
            application_input,
            super::access_application_login_methods_desired_schema(),
        ),
        (
            "human policy",
            human_policy,
            human_input,
            super::access_human_policy_desired_schema(),
        ),
    ] {
        let discovered_schema = guide_json(&capability)
            .pointer("/capability/request_schema")
            .cloned()
            .expect("guide advertises a request schema");
        let mut discovered_capability = capability;
        discovered_capability.request_schema = Some(discovered_schema.clone());
        if let Err(error) = super::validate_request_contract(&discovered_capability, &input) {
            mismatches.push(format!(
                "{label} discovery rejects the body accepted by call: {error}"
            ));
        }
        if discovered_schema != desired_schema {
            mismatches.push(format!(
                "{label} discovery exposes the internal materialized PUT schema"
            ));
        }
    }

    assert!(
        mismatches.is_empty(),
        "Access discovery and call disagree on caller-facing bodies: {mismatches:?}"
    );
}

pub(super) fn access_human_policy_materialized_input(policy_id: &str) -> CallInput {
    CallInput {
        selectors: json!({
            "account_id":"account-a",
            "app_id":"82131ea1-c7a6-4fc7-ab99-b11ddd2ff426",
            "policy_id":policy_id
        }),
        body: Some(json!({
            "decision":"allow",
            "exclude":[{"email":{"email":"founders@mlnavigator.com"}}],
            "include":[
                {"email_domain":{"domain":"mlnavigator.com"}},
                {"email":{"email":"advisor@mlnavigator.com"}}
            ],
            "mfa_config":{
                "allowed_authenticators":["biometrics","totp"],
                "mfa_disabled":false
            },
            "name":"Allow MLNavigator Investor Staff",
            "precedence":1,
            "require":[]
        })),
        ..CallInput::default()
    }
}

pub(super) fn access_human_policy_response_without_optional_fields() -> CloudflareResponseV1 {
    let mut live = access_human_policy_live_result();
    live.as_object_mut()
        .expect("policy object")
        .remove("mfa_config");
    live.as_object_mut()
        .expect("policy object")
        .remove("session_duration");
    CloudflareResponseV1 {
        status: 200,
        success: true,
        result: live,
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    }
}

#[test]
pub(super) fn access_human_policy_body_preserves_live_state_and_applies_narrow_eligibility_change()
{
    let input = CallInput {
        body: Some(json!({
            "include":[
                {"email_domain":{"domain":"mlnavigator.com"}},
                {"email":{"email":"advisor@mlnavigator.com"}}
            ]
        })),
        ..CallInput::default()
    };
    let desired = super::access_human_policy_desired_changes(&input).expect("narrow desired state");
    let body =
        super::access_human_policy_mutable_body(&access_human_policy_live_result(), &desired)
            .expect("preservation-safe human policy body");

    assert_eq!(
        body["include"],
        json!([
            {"email":{"email":"advisor@mlnavigator.com"}},
            {"email_domain":{"domain":"mlnavigator.com"}}
        ])
    );
    assert_eq!(
        body["exclude"],
        json!([{"email":{"email":"founders@mlnavigator.com"}}])
    );
    assert_eq!(
        body["mfa_config"],
        json!({
            "allowed_authenticators":["biometrics","totp"],
            "mfa_disabled":false
        })
    );
    assert_eq!(body["name"], json!("Allow MLNavigator Investor Staff"));
    assert_eq!(body["decision"], json!("allow"));
    assert_eq!(body["require"], json!([]));
    assert_eq!(body["precedence"], json!(1));
    assert_eq!(body["session_duration"], json!("24h"));
    assert!(body.get("id").is_none());
    assert!(body.get("uid").is_none());
    assert!(body.get("created_at").is_none());
    assert!(body.get("updated_at").is_none());
    assert!(body.get("reusable").is_none());
}

#[test]
pub(super) fn access_human_policy_body_replaces_only_requested_mfa_state() {
    let input = CallInput {
        body: Some(json!({
            "mfa_config":{
                "allowed_authenticators":["totp","biometrics"],
                "mfa_disabled":false,
                "session_duration":"12h"
            }
        })),
        ..CallInput::default()
    };
    let desired = super::access_human_policy_desired_changes(&input).expect("narrow desired state");
    let body =
        super::access_human_policy_mutable_body(&access_human_policy_live_result(), &desired)
            .expect("preservation-safe human policy body");

    assert_eq!(
        body["include"],
        json!([{"email_domain":{"domain":"mlnavigator.com"}}])
    );
    assert_eq!(
        body["exclude"],
        json!([{"email":{"email":"founders@mlnavigator.com"}}])
    );
    assert_eq!(
        body["mfa_config"],
        json!({
            "allowed_authenticators":["biometrics","totp"],
            "mfa_disabled":false,
            "session_duration":"12h"
        })
    );
}

#[test]
pub(super) fn access_human_policy_body_fails_closed_on_nonhuman_or_unclassified_live_state() {
    let input = CallInput {
        body: Some(json!({"exclude":[]})),
        ..CallInput::default()
    };
    let desired = super::access_human_policy_desired_changes(&input).expect("narrow desired state");

    let mut nonhuman = access_human_policy_live_result();
    nonhuman["decision"] = json!("bypass");
    assert!(
        super::access_human_policy_mutable_body(&nonhuman, &desired)
            .expect_err("bypass policy must not enter the human mutation lane")
            .to_string()
            .contains("allow")
    );

    let mut unknown = access_human_policy_live_result();
    unknown["approval_groups"] = json!([{"email_list_uuid":"list-id"}]);
    assert!(
        super::access_human_policy_mutable_body(&unknown, &desired)
            .expect_err("unknown policy fields must block")
            .to_string()
            .contains("approval_groups")
    );
}

#[test]
pub(super) fn access_human_policy_body_rejects_reusable_policy_before_app_scoped_projection() {
    let input = CallInput {
        body: Some(json!({"exclude":[]})),
        ..CallInput::default()
    };
    let desired = super::access_human_policy_desired_changes(&input).expect("narrow desired state");
    let mut reusable = access_human_policy_live_result();
    reusable["reusable"] = json!(true);

    let error = super::access_human_policy_mutable_body(&reusable, &desired)
        .expect_err("reusable policy must not enter the application-scoped PUT lane");
    assert!(error.to_string().contains("reusable"), "{error}");
}

#[test]
pub(super) fn access_human_policy_live_projection_rejects_omitted_reusable_classification() {
    let input = CallInput {
        body: Some(json!({"exclude":[]})),
        ..CallInput::default()
    };
    let desired = super::access_human_policy_desired_changes(&input).expect("narrow desired state");
    let mut unclassified = access_human_policy_live_result();
    unclassified
        .as_object_mut()
        .expect("policy object")
        .remove("reusable");

    let error = super::access_human_policy_mutable_body(&unclassified, &desired)
        .expect_err("live policy must explicitly classify reusable false");
    assert!(error.to_string().contains("reusable"), "{error}");
}

#[test]
pub(super) fn access_human_policy_curated_rollback_accepts_only_mutable_field_allowlist() {
    let prior = super::access_human_policy_prior_state(&access_human_policy_live_result())
        .expect("classified live snapshot projects a rollback body");
    assert!(prior.get("reusable").is_none());
    assert_eq!(
        super::access_human_policy_restorable_body(&prior).expect("curated rollback body"),
        prior
    );

    let mut injected = prior;
    injected["reusable"] = json!(false);
    let error = super::access_human_policy_restorable_body(&injected)
        .expect_err("rollback body must reject read-only routing metadata");
    assert!(error.to_string().contains("reusable"), "{error}");
}

#[test]
pub(super) fn access_human_policy_prior_state_preserves_optional_field_absence_for_rollback() {
    let mut live = access_human_policy_live_result();
    live.as_object_mut()
        .expect("policy object")
        .remove("mfa_config");
    live.as_object_mut()
        .expect("policy object")
        .remove("session_duration");

    let prior = super::access_human_policy_prior_state(&live).expect("restorable policy snapshot");
    assert!(prior.get("mfa_config").is_none());
    assert!(prior.get("session_duration").is_none());
    assert_eq!(prior["name"], json!("Allow MLNavigator Investor Staff"));
    assert_eq!(prior["decision"], json!("allow"));
    assert_eq!(prior["require"], json!([]));
}

#[test]
pub(super) fn access_human_policy_desired_input_rejects_empty_or_unclassified_changes() {
    let input = |body: Value| CallInput {
        body: Some(body),
        ..CallInput::default()
    };
    assert!(super::access_human_policy_desired_changes(&input(json!({}))).is_err());
    assert!(super::access_human_policy_desired_changes(&input(json!({"name":"rename"}))).is_err());
}

#[test]
pub(super) fn access_human_policy_desired_input_rejects_malformed_email_before_plan_creation() {
    let capability = access_human_policy_capability();
    let input = CallInput {
        selectors: json!({
            "account_id":"account-a",
            "app_id":"82131ea1-c7a6-4fc7-ab99-b11ddd2ff426",
            "policy_id":"45e44306-0e2a-460a-94aa-34c21eefdb4a"
        }),
        body: Some(json!({
            "include":[{"email":{"email":"abc"}}]
        })),
        ..CallInput::default()
    };

    assert!(
        super::validate_access_human_policy_desired_input(&capability, &input).is_err(),
        "malformed email selector reached approval-ready plan input"
    );
}

#[test]
pub(super) fn access_human_policy_desired_input_rejects_malformed_email_domain_before_plan_creation()
 {
    let capability = access_human_policy_capability();
    assert_eq!(
            capability.request_schema.as_ref().and_then(|schema| {
                schema.pointer(
                    "/properties/include/items/oneOf/1/properties/email_domain/properties/domain/format",
                )
            }),
            Some(&json!("hostname")),
            "runtime schema must mirror the catalog hostname contract"
        );
    let input = |domain: &str| CallInput {
        selectors: json!({
            "account_id":"account-a",
            "app_id":"82131ea1-c7a6-4fc7-ab99-b11ddd2ff426",
            "policy_id":"45e44306-0e2a-460a-94aa-34c21eefdb4a"
        }),
        body: Some(json!({
            "include":[{"email_domain":{"domain":domain}}]
        })),
        ..CallInput::default()
    };

    assert!(
        super::validate_access_human_policy_desired_input(
            &capability,
            &input("advisors.mlnavigator.com"),
        )
        .is_ok(),
        "ordinary hostname selector must remain valid"
    );
    assert!(
        super::validate_access_human_policy_desired_input(&capability, &input("not a domain"),)
            .is_err(),
        "malformed email-domain selector reached approval-ready plan input"
    );
}

#[test]
pub(super) fn access_human_policy_snapshot_is_hash_bound_exact_and_reconstructs_rollback() {
    let capability = access_human_policy_capability();
    assert!(
        super::is_access_human_policy_mutation(&capability),
        "gaps: {:?}",
        capability.mutation_contract_gaps()
    );
    let policy_id = "45e44306-0e2a-460a-94aa-34c21eefdb4a";
    let input = access_human_policy_materialized_input(policy_id);
    let response = access_human_policy_response_without_optional_fields();
    let receipt =
        super::apply_same_path_prior_state_response(&capability, &input, "account-a", &response)
            .expect("exact prior-state receipt");
    assert!(receipt["prior_state"].get("mfa_config").is_none());
    assert!(receipt["prior_state"].get("session_duration").is_none());

    let receipt_hash = hash_value(&receipt).expect("receipt hash");
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability.clone(),
        json!({
            "selectors":input.selectors,
            "account_id":"account-a",
            "adapter":{},
            "live_preconditions":{
                "same_path_prior_state":receipt
            }
        }),
    )
    .expect("plan");
    plan.input = serde_json::to_value(&input).expect("plan input");
    plan.precondition_hashes.insert(
        super::SAME_PATH_PRIOR_STATE_PRECONDITION.to_owned(),
        receipt_hash.clone(),
    );
    assert_eq!(
        super::required_same_path_prior_state_precondition(&plan).expect("bound prior state"),
        Some(receipt_hash.as_str())
    );
    let compensation =
        super::same_path_prior_state_compensation_request(&plan).expect("restoration request");
    assert_eq!(
        compensation.input.body,
        Some(json!({
            "decision":"allow",
            "exclude":[{"email":{"email":"founders@mlnavigator.com"}}],
            "include":[{"email_domain":{"domain":"mlnavigator.com"}}],
            "name":"Allow MLNavigator Investor Staff",
            "precedence":1,
            "require":[]
        }))
    );

    let mut drifted = plan.targets["live_preconditions"]["same_path_prior_state"].clone();
    drifted["prior_state"]["exclude"] = json!([]);
    plan.targets["live_preconditions"]["same_path_prior_state"] = drifted;
    assert!(
        super::required_same_path_prior_state_precondition(&plan)
            .expect_err("drifted state must not reuse the original hash")
            .to_string()
            .contains("does not match")
    );
}

#[test]
pub(super) fn access_human_policy_snapshot_requires_exact_policy_identity() {
    let capability = access_human_policy_capability();
    let policy_id = "45e44306-0e2a-460a-94aa-34c21eefdb4a";
    let input = access_human_policy_materialized_input(policy_id);
    let mut wrong_resource = access_human_policy_response_without_optional_fields();
    wrong_resource.result["id"] = json!("different-policy");
    assert!(
        super::apply_same_path_prior_state_response(
            &capability,
            &input,
            "account-a",
            &wrong_resource
        )
        .expect_err("wrong policy identity must fail")
        .to_string()
        .contains("different or missing policy id")
    );
}

#[test]
pub(super) fn is_domain_like_accepts_domains_and_rejects_noise() {
    assert!(super::is_domain_like("example.com"));
    assert!(super::is_domain_like("mail.example.co.uk"));
    assert!(!super::is_domain_like("example"));
    assert!(!super::is_domain_like("enable"));
    assert!(!super::is_domain_like("v2.0")); // numeric TLD is not a domain
    assert!(!super::is_domain_like("a.b")); // TLD too short
}

#[test]
pub(super) fn extract_domain_finds_the_first_domain_token() {
    assert_eq!(
        super::extract_domain("enable email routing on Example.COM please").as_deref(),
        Some("example.com")
    );
    assert_eq!(super::extract_domain("enable email routing"), None);
}
