use super::*;

fn managed_oauth_capability() -> CapabilityV1 {
    let mut capability = access_application_login_methods_capability();
    capability.id = super::ACCESS_APP_MANAGED_OAUTH_CAPABILITY_ID.to_owned();
    capability.request_schema = Some(cfctl_catalog::access_application_managed_oauth_schema());
    capability
        .same_path_read
        .as_mut()
        .expect("readback")
        .verified_response_fields = super::ACCESS_APP_MANAGED_OAUTH_MUTABLE_FIELDS
        .iter()
        .map(|field| (*field).to_owned())
        .collect();
    capability
}

#[test]
pub(super) fn access_application_oauth_only_body_merges_snapshot_when_oauth_config_absent() {
    let mut live_result = access_application_live_result();
    live_result
        .as_object_mut()
        .expect("fixture value")
        .remove("oauth_configuration");

    let desired_oauth_config = json!({
        "enabled": true,
        "dynamic_client_registration": {
            "enabled": true,
            "allowed_uris": ["mlnavigator-remote://oauth/callback"]
        }
    });

    let variant = super::access_application_login_methods_variant(
        super::ACCESS_APP_MANAGED_OAUTH_CAPABILITY_ID,
    )
    .expect("managed oauth variant");

    let response = CloudflareResponseV1 {
        success: true,
        status: 200,
        result: live_result.clone(),
        errors: vec![],
        result_info: None,
        etag: None,
        cf_ray: None,
    };

    let mut capability = managed_oauth_capability();

    let mut input = CallInput {
        selectors: json!({
            "account_id": "account-a",
            "app_id": "82131ea1-c7a6-4fc7-ab99-b11ddd2ff426"
        }),
        body: Some(json!({"oauth_configuration": desired_oauth_config})),
        ..CallInput::default()
    };

    let _receipt = super::finalize_access_application_oauth_plan_input(
        &mut capability,
        &mut input,
        &desired_oauth_config,
        variant,
        "account-a",
        &response,
    )
    .expect("oauth plan")
    .expect("receipt");

    let body = input.body.as_ref().expect("prepared body");
    assert_eq!(
        body.get("oauth_configuration"),
        Some(&desired_oauth_config),
        "oauth_configuration should be set to desired value"
    );
    assert_eq!(
        body.get("allowed_idps"),
        live_result.get("allowed_idps"),
        "allowed_idps should be preserved from live state"
    );
    assert_eq!(
        body.get("policies"),
        Some(&json!([{
            "id": "45e44306-0e2a-460a-94aa-34c21eefdb4a",
            "precedence": 1
        }])),
        "policies should be normalized"
    );
    assert_eq!(
        body.get("domain"),
        live_result.get("domain"),
        "domain should be preserved"
    );
    assert!(body.get("id").is_none(), "id should be omitted");
    assert!(body.get("aud").is_none(), "aud should be omitted");
}

#[test]
pub(super) fn access_application_oauth_only_body_merges_snapshot_when_oauth_config_present() {
    let mut live_result = access_application_live_result();
    live_result.as_object_mut().expect("fixture object").insert(
        "oauth_configuration".to_owned(),
        json!({
            "enabled": false
        }),
    );

    let desired_oauth_config = json!({
        "enabled": true,
        "dynamic_client_registration": {
            "enabled": true,
            "allowed_uris": ["mlnavigator-remote://oauth/callback"]
        }
    });

    let variant = super::access_application_login_methods_variant(
        super::ACCESS_APP_MANAGED_OAUTH_CAPABILITY_ID,
    )
    .expect("managed oauth variant");

    let response = CloudflareResponseV1 {
        success: true,
        status: 200,
        result: live_result.clone(),
        errors: vec![],
        result_info: None,
        etag: None,
        cf_ray: None,
    };

    let mut capability = managed_oauth_capability();

    let mut input = CallInput {
        selectors: json!({
            "account_id": "account-a",
            "app_id": "82131ea1-c7a6-4fc7-ab99-b11ddd2ff426"
        }),
        body: Some(json!({"oauth_configuration": desired_oauth_config})),
        ..CallInput::default()
    };

    let _receipt = super::finalize_access_application_oauth_plan_input(
        &mut capability,
        &mut input,
        &desired_oauth_config,
        variant,
        "account-a",
        &response,
    )
    .expect("oauth plan")
    .expect("receipt");

    let body = input.body.as_ref().expect("prepared body");
    assert_eq!(
        body.get("oauth_configuration"),
        Some(&desired_oauth_config),
        "oauth_configuration should be updated"
    );
    assert_eq!(
        body.get("allowed_idps"),
        live_result.get("allowed_idps"),
        "allowed_idps should be preserved from live state"
    );
}

#[test]
pub(super) fn access_application_oauth_only_body_rejects_no_mutation() {
    let desired_oauth_config = json!({
        "enabled": true
    });

    let mut live_result = access_application_live_result();
    live_result.as_object_mut().expect("fixture object").insert(
        "oauth_configuration".to_owned(),
        desired_oauth_config.clone(),
    );

    let variant = super::access_application_login_methods_variant(
        super::ACCESS_APP_MANAGED_OAUTH_CAPABILITY_ID,
    )
    .expect("managed oauth variant");

    let response = CloudflareResponseV1 {
        success: true,
        status: 200,
        result: live_result,
        errors: vec![],
        result_info: None,
        etag: None,
        cf_ray: None,
    };

    let mut capability = managed_oauth_capability();

    let mut input = CallInput {
        selectors: json!({
            "account_id": "account-a",
            "app_id": "82131ea1-c7a6-4fc7-ab99-b11ddd2ff426"
        }),
        body: Some(json!({"oauth_configuration": desired_oauth_config})),
        ..CallInput::default()
    };

    let result = super::finalize_access_application_oauth_plan_input(
        &mut capability,
        &mut input,
        &desired_oauth_config,
        variant,
        "account-a",
        &response,
    );

    assert!(
        result.is_err(),
        "should reject when oauth_configuration is already set to desired value"
    );
    assert!(
        result
            .expect_err("expected validation failure")
            .to_string()
            .contains("already has the exact requested OAuth configuration"),
        "error message should mention no mutation needed"
    );
}

#[test]
pub(super) fn access_application_oauth_only_body_rejects_missing_allowed_idps() {
    let mut live_result = access_application_live_result();
    live_result
        .as_object_mut()
        .expect("fixture object")
        .remove("allowed_idps");

    let desired_oauth_config = json!({
        "enabled": true
    });

    let variant = super::access_application_login_methods_variant(
        super::ACCESS_APP_MANAGED_OAUTH_CAPABILITY_ID,
    )
    .expect("managed oauth variant");

    let response = CloudflareResponseV1 {
        success: true,
        status: 200,
        result: live_result,
        errors: vec![],
        result_info: None,
        etag: None,
        cf_ray: None,
    };

    let mut capability = managed_oauth_capability();

    let mut input = CallInput {
        selectors: json!({
            "account_id": "account-a",
            "app_id": "82131ea1-c7a6-4fc7-ab99-b11ddd2ff426"
        }),
        body: Some(json!({"oauth_configuration": desired_oauth_config})),
        ..CallInput::default()
    };

    let result = super::finalize_access_application_oauth_plan_input(
        &mut capability,
        &mut input,
        &desired_oauth_config,
        variant,
        "account-a",
        &response,
    );

    assert!(
        result.is_err(),
        "should reject when allowed_idps is missing from live state"
    );
    assert!(
        result
            .expect_err("expected validation failure")
            .to_string()
            .contains("omitted restorable field allowed_idps"),
        "error message should mention missing allowed_idps"
    );
}

#[test]
pub(super) fn access_application_oauth_only_body_rejects_empty_allowed_idps() {
    let mut live_result = access_application_live_result();
    live_result
        .as_object_mut()
        .expect("fixture value")
        .insert("allowed_idps".to_owned(), json!([]));

    let desired_oauth_config = json!({
        "enabled": true
    });

    let variant = super::access_application_login_methods_variant(
        super::ACCESS_APP_MANAGED_OAUTH_CAPABILITY_ID,
    )
    .expect("managed oauth variant");

    let response = CloudflareResponseV1 {
        success: true,
        status: 200,
        result: live_result,
        errors: vec![],
        result_info: None,
        etag: None,
        cf_ray: None,
    };

    let mut capability = managed_oauth_capability();

    let mut input = CallInput {
        selectors: json!({
            "account_id": "account-a",
            "app_id": "82131ea1-c7a6-4fc7-ab99-b11ddd2ff426"
        }),
        body: Some(json!({"oauth_configuration": desired_oauth_config})),
        ..CallInput::default()
    };

    let result = super::finalize_access_application_oauth_plan_input(
        &mut capability,
        &mut input,
        &desired_oauth_config,
        variant,
        "account-a",
        &response,
    );

    assert!(result.is_err(), "should reject when allowed_idps is empty");
    assert!(
        result
            .expect_err("expected validation failure")
            .to_string()
            .contains("empty identity-provider allowlist"),
        "error message should mention empty allowed_idps"
    );
}

#[test]
pub(super) fn call_validation_accepts_oauth_only_for_managed_oauth() {
    let capability = managed_oauth_capability();

    let input = CallInput {
        selectors: json!({
            "account_id": "account-a",
            "app_id": "82131ea1-c7a6-4fc7-ab99-b11ddd2ff426"
        }),
        body: Some(json!({
            "oauth_configuration": {
                "enabled": true,
                "dynamic_client_registration": {
                    "enabled": true,
                    "allowed_uris": ["mlnavigator-remote://oauth/callback"]
                }
            }
        })),
        ..CallInput::default()
    };

    let result =
        super::validate_access_application_login_methods_desired_input(&capability, &input);

    assert!(
        result.is_ok(),
        "oauth-only body should be accepted for managed-oauth capability: {:?}",
        result.expect_err("expected validation failure")
    );
}

#[test]
pub(super) fn call_validation_rejects_oauth_only_for_non_managed_oauth() {
    let capability = access_application_login_methods_capability();

    let input = CallInput {
        selectors: json!({
            "account_id": "account-a",
            "app_id": "82131ea1-c7a6-4fc7-ab99-b11ddd2ff426"
        }),
        body: Some(json!({
            "oauth_configuration": {
                "enabled": true
            }
        })),
        ..CallInput::default()
    };

    let result =
        super::validate_access_application_login_methods_desired_input(&capability, &input);

    assert!(
        result.is_err(),
        "oauth-only body should be rejected for non-managed-oauth capability"
    );

    let error_msg = result.expect_err("expected validation failure").to_string();
    assert!(
        error_msg.contains("allowed_idps") || error_msg.contains("required"),
        "error should indicate missing required field allowed_idps, got: {error_msg}"
    );
}

#[test]
pub(super) fn call_validation_accepts_idps_only_for_managed_oauth() {
    let capability = managed_oauth_capability();

    let input = CallInput {
        selectors: json!({
            "account_id": "account-a",
            "app_id": "82131ea1-c7a6-4fc7-ab99-b11ddd2ff426"
        }),
        body: Some(json!({
            "allowed_idps": [
                "7b0bc477-5d42-4dab-b0ea-c97d0aef7810",
                "6f88b4fc-0ed2-48fa-95ea-3f7336c90053"
            ]
        })),
        ..CallInput::default()
    };

    let result =
        super::validate_access_application_login_methods_desired_input(&capability, &input);

    assert!(
        result.is_ok(),
        "idps-only body should be accepted for managed-oauth capability: {:?}",
        result.expect_err("expected validation failure")
    );
}

#[test]
pub(super) fn call_validation_rejects_invalid_oauth_only_shapes() {
    let capability = managed_oauth_capability();

    let input_non_object = CallInput {
        selectors: json!({
            "account_id": "account-a",
            "app_id": "82131ea1-c7a6-4fc7-ab99-b11ddd2ff426"
        }),
        body: Some(json!({
            "oauth_configuration": "not an object"
        })),
        ..CallInput::default()
    };

    let result = super::validate_access_application_login_methods_desired_input(
        &capability,
        &input_non_object,
    );

    assert!(
        result.is_err(),
        "non-object oauth_configuration should be rejected"
    );
    assert!(
        result
            .expect_err("expected validation failure")
            .to_string()
            .contains("must be an object"),
        "error should mention oauth_configuration must be an object"
    );
}

#[test]
pub(super) fn managed_oauth_prior_state_validation_allows_introducing_oauth_configuration() {
    let mut capability = managed_oauth_capability();

    let desired_oauth_config = json!({
        "enabled": true,
        "dynamic_client_registration": {
            "enabled": true,
            "allowed_uris": ["mlnavigator-remote://oauth/callback"]
        }
    });

    let variant = super::access_application_login_methods_variant(
        super::ACCESS_APP_MANAGED_OAUTH_CAPABILITY_ID,
    )
    .expect("managed oauth variant");

    let mut live_result = access_application_live_result();
    live_result
        .as_object_mut()
        .expect("fixture value")
        .remove("oauth_configuration");

    let response = CloudflareResponseV1 {
        success: true,
        status: 200,
        result: live_result,
        errors: vec![],
        result_info: None,
        etag: None,
        cf_ray: None,
    };

    let mut input = CallInput {
        selectors: json!({
            "account_id": "account-a",
            "app_id": "82131ea1-c7a6-4fc7-ab99-b11ddd2ff426"
        }),
        body: Some(json!({"oauth_configuration": desired_oauth_config.clone()})),
        ..CallInput::default()
    };

    let receipt = super::finalize_access_application_oauth_plan_input(
        &mut capability,
        &mut input,
        &desired_oauth_config,
        variant,
        "account-a",
        &response,
    )
    .expect("oauth plan")
    .expect("receipt");

    let prior_state = receipt.get("prior_state").expect("prior_state");
    assert!(
        prior_state.get("oauth_configuration").is_none(),
        "prior_state should not have oauth_configuration since it was absent from live"
    );

    assert!(
        input
            .body
            .as_ref()
            .expect("fixture value")
            .get("oauth_configuration")
            .is_some(),
        "input body should have oauth_configuration"
    );

    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-a",
        capability,
        json!({
            "selectors": input.selectors,
            "live_preconditions": {"same_path_prior_state": receipt}
        }),
    )
    .expect("plan draft");
    plan.input = serde_json::to_value(&input).expect("plan input");

    let restored = super::validate_same_path_prior_state_receipt(
        &plan,
        plan.targets
            .pointer("/live_preconditions/same_path_prior_state")
            .expect("receipt"),
    )
    .expect("validation should pass when oauth_configuration is being introduced");

    assert!(
        restored.get("oauth_configuration").is_none(),
        "restored prior state should not have oauth_configuration"
    );
    assert!(
        restored.get("allowed_idps").is_some(),
        "restored prior state should have allowed_idps"
    );
}

#[test]
pub(super) fn managed_oauth_prior_state_validation_rejects_when_oauth_config_in_both() {
    let mut capability = managed_oauth_capability();

    let desired_oauth_config = json!({
        "enabled": true,
        "dynamic_client_registration": {
            "enabled": true,
            "allowed_uris": ["mlnavigator-remote://oauth/callback"]
        }
    });

    let variant = super::access_application_login_methods_variant(
        super::ACCESS_APP_MANAGED_OAUTH_CAPABILITY_ID,
    )
    .expect("managed oauth variant");

    let mut live_result = access_application_live_result();
    live_result.as_object_mut().expect("fixture object").insert(
        "oauth_configuration".to_owned(),
        json!({
            "enabled": false
        }),
    );

    let response = CloudflareResponseV1 {
        success: true,
        status: 200,
        result: live_result,
        errors: vec![],
        result_info: None,
        etag: None,
        cf_ray: None,
    };

    let mut input = CallInput {
        selectors: json!({
            "account_id": "account-a",
            "app_id": "82131ea1-c7a6-4fc7-ab99-b11ddd2ff426"
        }),
        body: Some(json!({"oauth_configuration": desired_oauth_config.clone()})),
        ..CallInput::default()
    };

    let receipt = super::finalize_access_application_oauth_plan_input(
        &mut capability,
        &mut input,
        &desired_oauth_config,
        variant,
        "account-a",
        &response,
    )
    .expect("oauth plan")
    .expect("receipt");

    let prior_state = receipt.get("prior_state").expect("prior_state");
    assert!(
        prior_state.get("oauth_configuration").is_some(),
        "prior_state should have oauth_configuration when it was present in live"
    );

    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-a",
        capability,
        json!({
            "selectors": input.selectors.clone(),
            "live_preconditions": {"same_path_prior_state": receipt.clone()}
        }),
    )
    .expect("plan draft");
    plan.input = serde_json::to_value(&input).expect("plan input");

    let restored = super::validate_same_path_prior_state_receipt(
        &plan,
        plan.targets
            .pointer("/live_preconditions/same_path_prior_state")
            .expect("receipt"),
    )
    .expect("validation should pass when oauth_configuration is present in both");

    assert!(
        restored.get("oauth_configuration").is_some(),
        "restored prior state should have oauth_configuration"
    );

    let mut tampered_receipt = receipt.clone();
    if let Some(prior) = tampered_receipt
        .get_mut("prior_state")
        .and_then(Value::as_object_mut)
    {
        prior.remove("allowed_idps");
    }

    let error = super::validate_same_path_prior_state_receipt(&plan, &tampered_receipt)
        .expect_err("validation should fail when required field is missing");

    assert!(
        error
            .to_string()
            .contains("invalid source, target, selector, or field set"),
        "error should indicate field set mismatch: {error}"
    );
}

#[test]
fn managed_oauth_idp_plan_preserves_existing_oauth_configuration() {
    let mut capability = managed_oauth_capability();
    let variant = super::access_application_login_methods_variant(&capability.id)
        .expect("managed OAuth variant");
    let desired_idps = vec!["7b0bc477-5d42-4dab-b0ea-c97d0aef7810".to_owned()];
    let oauth = json!({"enabled":true});
    let mut live = access_application_live_result();
    live["oauth_configuration"] = oauth.clone();
    let mut input = CallInput {
        selectors: json!({"account_id":"account-a","app_id":"82131ea1-c7a6-4fc7-ab99-b11ddd2ff426"}),
        body: Some(json!({"allowed_idps":desired_idps})),
        ..CallInput::default()
    };
    let prior = super::finalize_access_application_login_methods_plan_input(
        &mut capability,
        &mut input,
        &desired_idps,
        variant,
        "account-a",
        &CloudflareResponseV1 {
            status: 200,
            success: true,
            result: live,
            errors: vec![],
            result_info: None,
            etag: None,
            cf_ray: None,
        },
    )
    .expect("managed OAuth IdP plan")
    .expect("prior-state receipt");
    assert_eq!(
        input.body.as_ref().expect("prepared body")["oauth_configuration"],
        oauth
    );
    assert_eq!(prior["prior_state"]["oauth_configuration"], oauth);
    assert!(super::access_application_login_methods_contract_supported(
        &capability
    ));
}
