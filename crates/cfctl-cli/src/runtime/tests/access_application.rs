use super::*;

pub(super) fn access_application_live_result() -> Value {
    json!({
        "allowed_idps":[
            "7b0bc477-5d42-4dab-b0ea-c97d0aef7810",
            "6f88b4fc-0ed2-48fa-95ea-3f7336c90053"
        ],
        "app_launcher_visible":true,
        "aud":"aud-value",
        "auto_redirect_to_identity":false,
        "created_at":"2026-03-24T02:31:11Z",
        "destinations":[{"type":"public","uri":"investors.mlnavigator.com"}],
        "domain":"investors.mlnavigator.com",
        "enable_binding_cookie":true,
        "http_only_cookie_attribute":true,
        "id":"82131ea1-c7a6-4fc7-ab99-b11ddd2ff426",
        "name":"MLNavigator Investor Portal",
        "options_preflight_bypass":false,
        "policies":[{
            "created_at":"2026-07-14T09:51:08Z",
            "decision":"allow",
            "id":"45e44306-0e2a-460a-94aa-34c21eefdb4a",
            "include":[{"email_domain":{"domain":"mlnavigator.com"}}],
            "name":"Allow MLNavigator Investor Staff",
            "precedence":1,
            "updated_at":"2026-07-14T09:51:08Z"
        }],
        "same_site_cookie_attribute":"lax",
        "self_hosted_domains":["investors.mlnavigator.com"],
        "session_duration":"24h",
        "tags":["customer:investors","env:production"],
        "type":"self_hosted",
        "uid":"82131ea1-c7a6-4fc7-ab99-b11ddd2ff426",
        "updated_at":"2026-07-14T09:51:47Z"
    })
}

pub(super) fn access_app_launcher_live_result() -> Value {
    json!({
        "allowed_idps":["6f88b4fc-0ed2-48fa-95ea-3f7336c90053"],
        "aud":"aud-value",
        "auto_redirect_to_identity":false,
        "created_at":"2026-04-17T15:14:52Z",
        "domain":"auch-id.cloudflareaccess.com",
        "id":"564ba110-aca0-401a-850d-b706c2c1a642",
        "landing_page_design":{},
        "name":"App Launcher",
        "policies":[{
            "created_at":"2026-04-28T20:10:14Z",
            "decision":"allow",
            "id":"89cae51e-3bb6-480f-a9a1-9abdf0964b82",
            "include":[{"email_domain":{"domain":"mlnavigator.com"}}],
            "name":"Allow MLNavigator Staff",
            "precedence":1,
            "updated_at":"2026-04-28T20:10:14Z"
        }],
        "session_duration":"24h",
        "skip_app_launcher_login_page":false,
        "type":"app_launcher",
        "uid":"564ba110-aca0-401a-850d-b706c2c1a642",
        "updated_at":"2026-07-03T03:57:20Z"
    })
}

#[test]
pub(super) fn access_application_login_method_body_preserves_mutable_state_and_normalizes_policies()
{
    let otp = "7b0bc477-5d42-4dab-b0ea-c97d0aef7810".to_owned();
    let variant = super::access_application_login_methods_variant(
        super::ACCESS_APP_LOGIN_METHODS_CAPABILITY_ID,
    )
    .expect("self-hosted variant");
    let body =
        super::access_application_mutable_body(&access_application_live_result(), &[otp], variant)
            .expect("preservation-safe body");
    assert_eq!(
        body["allowed_idps"],
        json!(["7b0bc477-5d42-4dab-b0ea-c97d0aef7810"])
    );
    assert_eq!(
        body["policies"],
        json!([{
            "id":"45e44306-0e2a-460a-94aa-34c21eefdb4a",
            "precedence":1
        }])
    );
    assert_eq!(body["auto_redirect_to_identity"], json!(false));
    assert_eq!(body["enable_binding_cookie"], json!(true));
    assert_eq!(body["domain"], json!("investors.mlnavigator.com"));
    assert_eq!(body["same_site_cookie_attribute"], json!("lax"));
    assert!(body.get("id").is_none());
    assert!(body.get("aud").is_none());
    assert!(body.get("created_at").is_none());
    assert!(body.get("updated_at").is_none());
    assert_eq!(
        body["tags"],
        json!(["customer:investors", "env:production"])
    );
}

#[test]
pub(super) fn access_application_empty_tags_remain_distinct_from_absence() {
    let otp = "7b0bc477-5d42-4dab-b0ea-c97d0aef7810".to_owned();
    let variant = super::access_application_login_methods_variant(
        super::ACCESS_APP_LOGIN_METHODS_CAPABILITY_ID,
    )
    .expect("self-hosted variant");
    let mut with_empty_tags = access_application_live_result();
    with_empty_tags["tags"] = json!([]);
    let body = super::access_application_mutable_body(
        &with_empty_tags,
        std::slice::from_ref(&otp),
        variant,
    )
    .expect("explicit empty tags remain in the full PUT");
    assert_eq!(body.get("tags"), Some(&json!([])));

    let mut without_tags = access_application_live_result();
    without_tags
        .as_object_mut()
        .expect("application object")
        .remove("tags");
    let body = super::access_application_mutable_body(&without_tags, &[otp], variant)
        .expect("absent optional tags remain absent");
    assert!(body.get("tags").is_none());
}

#[test]
pub(super) fn access_app_launcher_login_method_body_preserves_launcher_state() {
    let otp = "7b0bc477-5d42-4dab-b0ea-c97d0aef7810".to_owned();
    let variant = super::access_application_login_methods_variant(
        super::ACCESS_APP_LAUNCHER_LOGIN_METHODS_CAPABILITY_ID,
    )
    .expect("App Launcher variant");
    let body =
        super::access_application_mutable_body(&access_app_launcher_live_result(), &[otp], variant)
            .expect("preservation-safe App Launcher body");
    assert_eq!(
        body["allowed_idps"],
        json!(["7b0bc477-5d42-4dab-b0ea-c97d0aef7810"])
    );
    assert_eq!(
        body["policies"],
        json!([{
            "id":"89cae51e-3bb6-480f-a9a1-9abdf0964b82",
            "precedence":1
        }])
    );
    assert_eq!(body["auto_redirect_to_identity"], json!(false));
    assert_eq!(body["landing_page_design"], json!({}));
    assert_eq!(body["skip_app_launcher_login_page"], json!(false));
    assert_eq!(body["type"], json!("app_launcher"));
    assert!(body.get("domain").is_none());
    assert!(body.get("name").is_none());
    assert!(body.get("aud").is_none());
    assert!(body.get("id").is_none());
}

#[test]
pub(super) fn access_application_login_method_body_fails_closed_on_unclassified_live_state() {
    let mut result = access_application_live_result();
    result["future_writable_field"] = json!({"must_be_preserved":true});
    let variant = super::access_application_login_methods_variant(
        super::ACCESS_APP_LOGIN_METHODS_CAPABILITY_ID,
    )
    .expect("self-hosted variant");
    let error = super::access_application_mutable_body(
        &result,
        &["7b0bc477-5d42-4dab-b0ea-c97d0aef7810".to_owned()],
        variant,
    )
    .expect_err("unclassified app override must block");
    assert!(error.to_string().contains("future_writable_field"));
}

pub(super) fn access_application_login_methods_capability() -> CapabilityV1 {
    let mut properties = json!({
        "allowed_idps":{"type":"array","items":{"type":"string"}},
        "app_launcher_visible":{"type":"boolean"},
        "auto_redirect_to_identity":{"type":"boolean"},
        "destinations":{"type":"array","items":{"type":"object"}},
        "domain":{"type":"string"},
        "eager_redirect_cookie_setting":{"type":"boolean"},
        "enable_binding_cookie":{"type":"boolean"},
        "http_only_cookie_attribute":{"type":"boolean"},
        "name":{"type":"string"},
        "options_preflight_bypass":{"type":"boolean"},
        "path_cookie_attribute":{"type":"boolean"},
        "policies":{"type":"array","items":{"type":"object"}},
        "same_site_cookie_attribute":{"type":"string"},
        "self_hosted_domains":{"type":"array","items":{"type":"string"}},
        "session_duration":{"type":"string"},
        "tags":{"type":"array","items":{"type":"string"}},
        "type":{"type":"string","enum":["self_hosted"]}
    })
    .as_object()
    .cloned()
    .expect("object properties");
    properties.retain(|field, _| super::ACCESS_APP_MUTABLE_FIELDS.contains(&field.as_str()));
    let required = super::ACCESS_APP_MUTABLE_FIELDS
        .iter()
        .filter(|field| {
            !matches!(
                **field,
                "eager_redirect_cookie_setting"
                    | "path_cookie_attribute"
                    | "same_site_cookie_attribute"
                    | "tags"
            )
        })
        .copied()
        .collect::<Vec<_>>();
    let mut capability = CapabilityV1::new(
        super::ACCESS_APP_LOGIN_METHODS_CAPABILITY_ID,
        "Update self-hosted Access application login methods",
        "PUT",
        super::ACCESS_APP_DETAIL_PATH,
    );
    capability.product = "Access applications".to_owned();
    capability.account_scope = "account".to_owned();
    capability.mutating = true;
    capability.adapter_status = AdapterStatus::DynamicApi;
    capability.permissions = vec!["Access: Apps and Policies Write".to_owned()];
    capability.risk = RiskClass::IdentityOrOwnership;
    capability.effect = EffectClass::IdentityOrOwnership;
    capability.cost.known = true;
    capability.cost.maximum = Some(0.0);
    capability.entitlement.available = Some(true);
    capability.selectors = ["account_id", "app_id"]
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
        "required":required,
        "properties":properties,
        "x-cfctl-body-required":true
    }));
    capability.verification.required = true;
    capability.verification.strategy =
        "same_path_result_contains_planned_fields_after_update".to_owned();
    capability.same_path_read = Some(SamePathReadContractV1 {
        path: super::ACCESS_APP_DETAIL_PATH.to_owned(),
        read_capability_id: super::ACCESS_APP_READ_CAPABILITY_ID.to_owned(),
        verified_response_fields: super::ACCESS_APP_MUTABLE_FIELDS
            .iter()
            .map(|field| (*field).to_owned())
            .collect(),
    });
    capability.rollback.supported = true;
    capability.rollback.strategy = Some(super::SAME_PATH_PRIOR_STATE_ROLLBACK_STRATEGY.to_owned());
    capability.rollback.warning = Some("restoration requires a separate approved plan".to_owned());
    capability
}

pub(super) fn owned_whole_host_access_application_capability() -> CapabilityV1 {
    let mut capability = access_application_login_methods_capability();
    capability.id = super::ACCESS_APP_OWNED_WHOLE_HOST_CAPABILITY_ID.to_owned();
    capability.title = "Update owned whole-host Access application".to_owned();
    capability.request_schema = Some(cfctl_catalog::access_application_owned_whole_host_schema());
    capability
}

pub(super) fn owned_whole_host_access_application_input() -> CallInput {
    let capability = owned_whole_host_access_application_capability();
    let variant = super::access_application_login_methods_variant(&capability.id)
        .expect("owned self-hosted variant");
    let mut live = access_application_live_result();
    live["domain"] = json!("health.example.com");
    live["name"] = json!("Routing health");
    live["self_hosted_domains"] = json!(["health.example.com"]);
    live["destinations"] = json!([{"type":"public","uri":"health.example.com"}]);
    let body = super::access_application_mutable_body(
        &live,
        &["7b0bc477-5d42-4dab-b0ea-c97d0aef7810".to_owned()],
        variant,
    )
    .expect("complete whole-host body");
    CallInput {
        selectors: json!({
            "account_id":"account-a",
            "app_id":"82131ea1-c7a6-4fc7-ab99-b11ddd2ff426"
        }),
        body: Some(body),
        ..CallInput::default()
    }
}

pub(super) fn access_application_collection(result: Value, complete: bool) -> CloudflareResponseV1 {
    CloudflareResponseV1 {
        status: 200,
        success: true,
        result,
        errors: Vec::new(),
        result_info: Some(if complete {
            json!({"cfctl_page_complete":true,"page":1,"total_pages":1,"cfctl_pages":1})
        } else {
            json!({"cursor":"next-page"})
        }),
        etag: None,
        cf_ray: None,
    }
}

pub(super) fn operator_group_policy_capability(create: bool) -> CapabilityV1 {
    let (id, method, path) = if create {
        (
            super::ACCESS_OPERATOR_GROUP_POLICY_CREATE_CAPABILITY_ID,
            "POST",
            super::ACCESS_POLICY_COLLECTION_PATH,
        )
    } else {
        (
            super::ACCESS_OPERATOR_GROUP_POLICY_UPDATE_CAPABILITY_ID,
            "PUT",
            super::ACCESS_POLICY_DETAIL_PATH,
        )
    };
    let mut capability = CapabilityV1::new(id, "Operator group allow policy", method, path);
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
    capability.selectors = if create {
        ["account_id", "app_id"].as_slice()
    } else {
        ["account_id", "app_id", "policy_id"].as_slice()
    }
    .iter()
    .map(|name| SelectorV1 {
        name: (*name).to_owned(),
        location: "path".to_owned(),
        required: true,
        value_type: "string".to_owned(),
        description: None,
        contract: None,
    })
    .collect();
    capability.request_schema = Some(cfctl_catalog::access_operator_group_allow_policy_schema());
    capability.verification.required = true;
    if create {
        capability.verification.strategy =
            "created_resource_contains_planned_fields_by_returned_id".to_owned();
        capability.created_resource = Some(CreatedResourceContractV1 {
            detail_path: super::ACCESS_POLICY_DETAIL_PATH.to_owned(),
            identity_selector: "policy_id".to_owned(),
            response_result_identity_pointer: "/id".to_owned(),
            read_capability_id: super::ACCESS_POLICY_READ_CAPABILITY_ID.to_owned(),
            delete_capability_id: "access-policies-delete-an-access-policy".to_owned(),
            verified_response_fields: [
                "decision",
                "exclude",
                "include",
                "name",
                "precedence",
                "require",
                "session_duration",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        });
        capability.rollback.supported = true;
        capability.rollback.strategy = Some("delete_created_resource_by_returned_id".to_owned());
    } else {
        capability.verification.strategy =
            "same_path_result_contains_planned_fields_after_update".to_owned();
        capability.same_path_read = Some(SamePathReadContractV1 {
            path: super::ACCESS_POLICY_DETAIL_PATH.to_owned(),
            read_capability_id: super::ACCESS_POLICY_READ_CAPABILITY_ID.to_owned(),
            verified_response_fields: [
                "decision",
                "exclude",
                "include",
                "name",
                "precedence",
                "require",
                "session_duration",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        });
        capability.rollback.supported = true;
        capability.rollback.strategy =
            Some(super::SAME_PATH_PRIOR_STATE_ROLLBACK_STRATEGY.to_owned());
    }
    capability
}

pub(super) fn operator_group_policy_input(update: bool) -> CallInput {
    let mut selectors = json!({"account_id":"account-a","app_id":"application-a"});
    if update {
        selectors["policy_id"] = json!("policy-a");
    }
    CallInput {
        selectors,
        body: Some(json!({
            "name":"Allow operators",
            "decision":"allow",
            "include":[{"group":{"id":"7b0bc477-5d42-4dab-b0ea-c97d0aef7810"}}],
            "exclude":[],
            "require":[],
            "precedence":1,
            "session_duration":"24h"
        })),
        ..CallInput::default()
    }
}

pub(super) fn operator_group_policy_collection(
    result: Value,
    complete: bool,
) -> CloudflareResponseV1 {
    access_application_collection(result, complete)
}

#[test]
pub(super) fn operator_group_policy_schema_rejects_every_alternate_rule_shape() {
    for create in [true, false] {
        let capability = operator_group_policy_capability(create);
        let input = operator_group_policy_input(!create);
        super::validate_access_operator_group_policy_input(&capability, &input)
            .expect("exact operator group policy");
        for drift in [
            json!({"email":{"email":"operator@example.com"}}),
            json!({"service_token":{"token_id":"token-a"}}),
            json!({"device_posture":{"integration_uid":"device-a"}}),
            json!({"external_evaluation":{"evaluate_url":"https://example.com"}}),
        ] {
            let mut drifted = input.clone();
            drifted.body.as_mut().expect("body")["include"] = json!([drift]);
            assert!(
                super::validate_access_operator_group_policy_input(&capability, &drifted).is_err()
            );
        }
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one matrix proves create, update, broader overlap, malformed-rule, and pagination ownership failures"
)]
pub(super) fn operator_group_policy_ownership_distinguishes_create_update_and_ambiguity() {
    let create = operator_group_policy_capability(true);
    let create_input = operator_group_policy_input(false);
    let empty = super::access_operator_group_policy_ownership_receipt(
        &create,
        &create_input,
        "account-a",
        &operator_group_policy_collection(json!([]), true),
    )
    .expect("zero-candidate create");
    assert_eq!(empty["candidate_count"], json!(0));
    assert_eq!(empty["selected_policy_id"], Value::Null);

    let existing = json!({
        "id":"policy-a",
        "name":"Allow operators",
        "decision":"allow",
        "include":[{"group":{"id":"7b0bc477-5d42-4dab-b0ea-c97d0aef7810"}}],
        "exclude":[],
        "require":[],
        "precedence":1,
        "reusable":false
    });
    assert!(
        super::access_operator_group_policy_ownership_receipt(
            &create,
            &create_input,
            "account-a",
            &operator_group_policy_collection(json!([existing.clone()]), true),
        )
        .expect_err("create overlap must fail")
        .to_string()
        .contains("zero")
    );

    let update = operator_group_policy_capability(false);
    let update_input = operator_group_policy_input(true);
    let exact = super::access_operator_group_policy_ownership_receipt(
        &update,
        &update_input,
        "account-a",
        &operator_group_policy_collection(json!([existing.clone()]), true),
    )
    .expect("one exact update candidate");
    assert_eq!(exact["candidate_count"], json!(1));
    assert_eq!(exact["selected_policy_id"], json!("policy-a"));

    let overlapping = json!({
        "id":"policy-b",
        "name":"Another policy",
        "decision":"bypass",
        "include":[{"group":{"id":"7b0bc477-5d42-4dab-b0ea-c97d0aef7810"}}],
        "reusable":false
    });
    assert!(
        super::access_operator_group_policy_ownership_receipt(
            &update,
            &update_input,
            "account-a",
            &operator_group_policy_collection(json!([existing.clone(), overlapping]), true),
        )
        .expect_err("overlapping group must fail")
        .to_string()
        .contains("ambiguous")
    );
    let broader_overlap = json!({
        "id":"policy-b",
        "name":"Broader policy",
        "decision":"allow",
        "include":[
            {"group":{"id":"7b0bc477-5d42-4dab-b0ea-c97d0aef7810"}},
            {"email_domain":{"domain":"example.com"}}
        ],
        "reusable":false
    });
    assert!(
        super::access_operator_group_policy_ownership_receipt(
            &create,
            &create_input,
            "account-a",
            &operator_group_policy_collection(json!([broader_overlap.clone()]), true),
        )
        .expect_err("group inside broader policy must count as overlap")
        .to_string()
        .contains("zero")
    );
    assert!(
        super::access_operator_group_policy_ownership_receipt(
            &update,
            &update_input,
            "account-a",
            &operator_group_policy_collection(json!([existing.clone(), broader_overlap]), true),
        )
        .expect_err("broader second group policy must make update ownership ambiguous")
        .to_string()
        .contains("ambiguous")
    );
    for malformed in [
        json!({
            "id":"policy-malformed",
            "name":"Other policy",
            "include":"concealed"
        }),
        json!({
            "id":"policy-malformed",
            "name":"Other policy",
            "include":["concealed"]
        }),
        json!({
            "id":"policy-malformed",
            "name":"Other policy",
            "include":[{"group":{"future_id":"concealed"}}]
        }),
    ] {
        assert!(
            super::access_operator_group_policy_ownership_receipt(
                &create,
                &create_input,
                "account-a",
                &operator_group_policy_collection(json!([malformed]), true),
            )
            .expect_err("unclassified include shapes must fail closed")
            .to_string()
            .contains("mutation boundary was not crossed")
        );
    }
    assert!(
        super::access_operator_group_policy_ownership_receipt(
            &create,
            &create_input,
            "account-a",
            &operator_group_policy_collection(json!([]), false),
        )
        .expect_err("partial collection must fail")
        .to_string()
        .contains("terminally paginated")
    );
}

#[test]
pub(super) fn operator_group_policy_prior_snapshot_is_complete_closed_and_absence_preserving() {
    let base = json!({
        "id":"policy-a",
        "uid":"policy-a",
        "name":"Allow operators",
        "decision":"allow",
        "include":[{"group":{"id":"7b0bc477-5d42-4dab-b0ea-c97d0aef7810"}}],
        "exclude":[],
        "require":[],
        "precedence":1,
        "reusable":false,
        "created_at":"2026-08-20T12:00:00Z",
        "updated_at":"2026-08-20T12:00:00Z"
    });
    let prior = super::access_operator_group_policy_restorable_body(&base)
        .expect("closed restorable policy");
    assert!(prior.get("session_duration").is_none());
    assert!(prior.get("id").is_none());
    assert_eq!(prior["include"], base["include"]);

    for (field, value) in [
        ("reusable", json!(true)),
        ("decision", json!("bypass")),
        ("require", json!([{"device_posture":{"id":"device-a"}}])),
        ("future_rule_mode", json!("provider-added")),
        (
            "mfa_config",
            json!({"allowed_authenticators":["totp"],"mfa_disabled":false}),
        ),
    ] {
        let mut drifted = base.clone();
        drifted[field] = value;
        assert!(
            super::access_operator_group_policy_restorable_body(&drifted).is_err(),
            "{field} drift must fail closed"
        );
    }
}

#[test]
pub(super) fn owned_whole_host_access_application_requires_exact_closed_shape() {
    let capability = owned_whole_host_access_application_capability();
    let input = owned_whole_host_access_application_input();
    super::validate_access_application_owned_whole_host_input(&capability, &input)
        .expect("exact whole-host body");

    for (pointer, drifted, expected) in [
        ("/domain", json!("*.example.com"), "hostname format"),
        (
            "/self_hosted_domains",
            json!(["other.example.com"]),
            "selected domain",
        ),
        (
            "/destinations/0/uri",
            json!("other.example.com"),
            "exact bare whole hostname",
        ),
        ("/type", json!("saas"), "pinned enum values"),
    ] {
        let mut drifted_input = input.clone();
        let body = drifted_input.body.as_mut().expect("body");
        *body.pointer_mut(pointer).expect("test pointer") = drifted;
        let error =
            super::validate_access_application_owned_whole_host_input(&capability, &drifted_input)
                .expect_err("drifted whole-host body must fail closed");
        assert!(error.to_string().contains(expected), "{error}");
    }
}

#[test]
pub(super) fn owned_whole_host_access_application_binds_unique_terminal_collection() {
    let input = owned_whole_host_access_application_input();
    let selected = json!({
        "id":"82131ea1-c7a6-4fc7-ab99-b11ddd2ff426",
        "name":"Routing health",
        "type":"self_hosted",
        "domain":"health.example.com",
        "self_hosted_domains":["health.example.com"],
        "destinations":[{"type":"public","uri":"health.example.com"}]
    });
    let receipt = super::owned_whole_host_access_application_receipt(
        &input,
        &access_application_collection(json!([selected.clone()]), true),
    )
    .expect("unique exact ownership");
    assert_eq!(receipt["candidate_count"], json!(1));
    assert_eq!(receipt["selected_id_count"], json!(1));
    assert_eq!(receipt["terminal_pagination"], json!(true));
    assert!(
        receipt["collection_digest"]
            .as_str()
            .is_some_and(|digest| digest.starts_with("sha256:"))
    );

    let incomplete = super::owned_whole_host_access_application_receipt(
        &input,
        &access_application_collection(json!([selected.clone()]), false),
    )
    .expect_err("incomplete collection must fail closed");
    assert!(incomplete.to_string().contains("terminally paginated"));

    let ambiguous_name = json!({
        "id":"alternate-app",
        "name":"Routing health",
        "type":"saas",
        "domain":"unrelated.example.net"
    });
    let ambiguous = super::owned_whole_host_access_application_receipt(
        &input,
        &access_application_collection(json!([selected.clone(), ambiguous_name]), true),
    )
    .expect_err("alternate-type name collision must fail closed");
    assert!(ambiguous.to_string().contains("ambiguous"));

    for other in [
        json!({"id":"other","type":"self_hosted","destinations":[{"type":"public"}]}),
        json!({"id":"other","type":"self_hosted"}),
        json!({"id":"other","type":"unknown"}),
    ] {
        assert!(
            super::owned_whole_host_access_application_receipt(
                &input,
                &access_application_collection(json!([selected.clone(), other]), true),
            )
            .is_err(),
            "unclassifiable rows must not establish unique ownership"
        );
    }
    let mut terminal_only = access_application_collection(json!([selected.clone()]), true);
    terminal_only.result_info = Some(json!({"page":2,"total_pages":2}));
    assert!(super::owned_whole_host_access_application_receipt(&input, &terminal_only).is_err());

    let wildcard_overlap = json!({
        "id":"overlapping-app",
        "name":"Other application",
        "type":"self_hosted",
        "domain":"*.example.com"
    });
    let overlapping = super::owned_whole_host_access_application_receipt(
        &input,
        &access_application_collection(json!([selected, wildcard_overlap]), true),
    )
    .expect_err("wildcard hostname collision must fail closed");
    assert!(overlapping.to_string().contains("ambiguous"));
}

#[test]
pub(super) fn owned_whole_host_access_application_receipt_binds_ownership_and_prior_snapshot() {
    let capability = owned_whole_host_access_application_capability();
    let input = owned_whole_host_access_application_input();
    let mut live = access_application_live_result();
    live["domain"] = json!("health.example.com");
    live["name"] = json!("Routing health");
    live["self_hosted_domains"] = json!(["health.example.com"]);
    live["destinations"] = json!([{"type":"public","uri":"health.example.com"}]);
    let mut receipt = super::apply_same_path_prior_state_response(
        &capability,
        &input,
        "account-a",
        &CloudflareResponseV1 {
            status: 200,
            success: true,
            result: live,
            errors: Vec::new(),
            result_info: None,
            etag: None,
            cf_ray: None,
        },
    )
    .expect("complete prior snapshot");
    let selected = json!({
        "id":"82131ea1-c7a6-4fc7-ab99-b11ddd2ff426",
        "name":"Routing health",
        "type":"self_hosted",
        "domain":"health.example.com",
        "self_hosted_domains":["health.example.com"],
        "destinations":[{"type":"public","uri":"health.example.com"}]
    });
    receipt["ownership"] = super::owned_whole_host_access_application_receipt(
        &input,
        &access_application_collection(json!([selected]), true),
    )
    .expect("ownership receipt");
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-a",
        capability,
        json!({
            "selectors":input.selectors,
            "live_preconditions":{"same_path_prior_state":receipt}
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
    .expect("receipt contract");
    assert_eq!(restored["name"], json!("Routing health"));
    assert_eq!(restored["domain"], json!("health.example.com"));

    let mut tampered = plan.targets["live_preconditions"]["same_path_prior_state"].clone();
    tampered["ownership"]["candidate_count"] = json!(2);
    assert!(
        super::validate_same_path_prior_state_receipt(&plan, &tampered)
            .expect_err("ambiguous ownership receipt must not authorize rollback")
            .to_string()
            .contains("invalid source, target, selector, or field set")
    );
}

pub(super) fn assert_access_application_optional_fields(body: &Value) {
    assert_eq!(body["same_site_cookie_attribute"], json!("lax"));
    assert_eq!(body["eager_redirect_cookie_setting"], json!(true));
    assert_eq!(
        body["tags"],
        json!(["customer:investors", "env:production"])
    );
}

pub(super) fn assert_eager_redirect_cookie_contract(capability: &CapabilityV1) {
    let materialized_schema = cfctl_catalog::access_application_login_methods_materialized_schema();
    assert_eq!(
        materialized_schema["properties"]["eager_redirect_cookie_setting"]["type"],
        "boolean"
    );
    assert!(
        !materialized_schema["required"]
            .as_array()
            .expect("required fields")
            .iter()
            .any(|field| field == "eager_redirect_cookie_setting"),
        "eager redirect is an optional provider field"
    );
    assert!(
        capability
            .same_path_read
            .as_ref()
            .expect("same-path read")
            .verified_response_fields
            .iter()
            .any(|field| field == "eager_redirect_cookie_setting")
    );
}

#[test]
pub(super) fn access_application_path_cookie_round_trips_through_snapshot_contract() {
    let capability = access_application_login_methods_capability();
    let variant = super::access_application_login_methods_variant(
        super::ACCESS_APP_LOGIN_METHODS_CAPABILITY_ID,
    )
    .expect("self-hosted variant");
    let mut live = access_application_live_result();
    live["path_cookie_attribute"] = json!(true);
    let body = super::access_application_mutable_body(
        &live,
        &["7b0bc477-5d42-4dab-b0ea-c97d0aef7810".to_owned()],
        variant,
    )
    .expect("path-scoped cookie configuration must be preserved");
    assert_eq!(body["path_cookie_attribute"], json!(true));

    let materialized_schema = cfctl_catalog::access_application_login_methods_materialized_schema();
    assert_eq!(
        materialized_schema["properties"]["path_cookie_attribute"]["type"],
        "boolean"
    );
    assert!(
        !materialized_schema["required"]
            .as_array()
            .expect("required fields")
            .iter()
            .any(|field| field == "path_cookie_attribute"),
        "path-scoped cookies are an optional provider field"
    );
    assert!(
        capability
            .same_path_read
            .as_ref()
            .expect("same-path read")
            .verified_response_fields
            .iter()
            .any(|field| field == "path_cookie_attribute")
    );

    let input = CallInput {
        selectors: json!({
            "account_id":"account-a",
            "app_id":"82131ea1-c7a6-4fc7-ab99-b11ddd2ff426"
        }),
        body: Some(body),
        ..CallInput::default()
    };
    let receipt = super::apply_same_path_prior_state_response(
        &capability,
        &input,
        "account-a",
        &CloudflareResponseV1 {
            status: 200,
            success: true,
            result: live,
            errors: Vec::new(),
            result_info: None,
            etag: None,
            cf_ray: None,
        },
    )
    .expect("path-scoped cookie configuration must enter the concurrency receipt");
    assert_eq!(receipt["prior_state"]["path_cookie_attribute"], json!(true));
}

#[test]
pub(super) fn access_application_same_site_cookie_round_trips_through_rollback() {
    let capability = access_application_login_methods_capability();
    assert!(
        super::is_access_application_login_methods_mutation(&capability),
        "gaps: {:?}",
        capability.mutation_contract_gaps()
    );
    let variant = super::access_application_login_methods_variant(
        super::ACCESS_APP_LOGIN_METHODS_CAPABILITY_ID,
    )
    .expect("self-hosted variant");
    let mut planned_source = access_application_live_result();
    planned_source["eager_redirect_cookie_setting"] = json!(true);
    if !variant
        .mutable_fields
        .contains(&"same_site_cookie_attribute")
    {
        planned_source
            .as_object_mut()
            .expect("application object")
            .remove("same_site_cookie_attribute");
    }
    let input = CallInput {
        selectors: json!({
            "account_id":"account-a",
            "app_id":"82131ea1-c7a6-4fc7-ab99-b11ddd2ff426"
        }),
        body: Some(
            super::access_application_mutable_body(
                &planned_source,
                &["7b0bc477-5d42-4dab-b0ea-c97d0aef7810".to_owned()],
                variant,
            )
            .expect("preservation-safe full PUT body"),
        ),
        ..CallInput::default()
    };
    assert_access_application_optional_fields(input.body.as_ref().expect("materialized body"));
    assert_eager_redirect_cookie_contract(&capability);
    let response = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: planned_source,
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let receipt =
        super::apply_same_path_prior_state_response(&capability, &input, "account-a", &response)
            .expect("exact prior-state receipt");
    assert_access_application_optional_fields(&receipt["prior_state"]);

    let receipt_hash = hash_value(&receipt).expect("receipt hash");
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
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
        receipt_hash,
    );
    let compensation =
        super::same_path_prior_state_compensation_request(&plan).expect("restoration request");
    assert_access_application_optional_fields(
        compensation.input.body.as_ref().expect("restoration body"),
    );
}

#[test]
pub(super) fn access_application_precondition_distinguishes_absence_from_empty_optional_state() {
    let capability = access_application_login_methods_capability();
    let variant = super::access_application_login_methods_variant(
        super::ACCESS_APP_LOGIN_METHODS_CAPABILITY_ID,
    )
    .expect("self-hosted variant");
    let mut planned_source = access_application_live_result();
    planned_source
        .as_object_mut()
        .expect("application object")
        .remove("tags");
    planned_source
        .as_object_mut()
        .expect("application object")
        .remove("same_site_cookie_attribute");
    let input = CallInput {
        selectors: json!({
            "account_id":"account-a",
            "app_id":"82131ea1-c7a6-4fc7-ab99-b11ddd2ff426"
        }),
        body: Some(
            super::access_application_mutable_body(
                &planned_source,
                &["7b0bc477-5d42-4dab-b0ea-c97d0aef7810".to_owned()],
                variant,
            )
            .expect("preservation-safe full PUT body"),
        ),
        ..CallInput::default()
    };
    let planned = super::apply_same_path_prior_state_response(
        &capability,
        &input,
        "account-a",
        &CloudflareResponseV1 {
            status: 200,
            success: true,
            result: planned_source.clone(),
            errors: Vec::new(),
            result_info: None,
            etag: None,
            cf_ray: None,
        },
    )
    .expect("planned absence receipt");
    assert!(planned["prior_state"].get("tags").is_none());

    let mut drifted_source = planned_source;
    drifted_source["tags"] = json!([]);
    let drifted = super::apply_same_path_prior_state_response(
        &capability,
        &input,
        "account-a",
        &CloudflareResponseV1 {
            status: 200,
            success: true,
            result: drifted_source,
            errors: Vec::new(),
            result_info: None,
            etag: None,
            cf_ray: None,
        },
    )
    .expect("drifted empty-state receipt");
    assert_eq!(drifted["prior_state"]["tags"], json!([]));
    let planned_hash = hash_value(&planned).expect("planned hash");
    let error = super::validate_same_path_prior_state_receipt_precondition(&planned_hash, &drifted);
    assert!(
        error
            .expect_err("an optional field appearing after planning must block execution")
            .to_string()
            .contains("drifted after planning")
    );
}

#[test]
pub(super) fn access_application_precondition_rejects_new_null_optional_state() {
    let capability = access_application_login_methods_capability();
    let variant = super::access_application_login_methods_variant(
        super::ACCESS_APP_LOGIN_METHODS_CAPABILITY_ID,
    )
    .expect("self-hosted variant");
    let mut planned_source = access_application_live_result();
    planned_source
        .as_object_mut()
        .expect("application object")
        .remove("same_site_cookie_attribute");
    let input = CallInput {
        selectors: json!({
            "account_id":"account-a",
            "app_id":"82131ea1-c7a6-4fc7-ab99-b11ddd2ff426"
        }),
        body: Some(
            super::access_application_mutable_body(
                &planned_source,
                &["7b0bc477-5d42-4dab-b0ea-c97d0aef7810".to_owned()],
                variant,
            )
            .expect("preservation-safe full PUT body"),
        ),
        ..CallInput::default()
    };
    planned_source["same_site_cookie_attribute"] = Value::Null;
    let error = super::apply_same_path_prior_state_response(
        &capability,
        &input,
        "account-a",
        &CloudflareResponseV1 {
            status: 200,
            success: true,
            result: planned_source,
            errors: Vec::new(),
            result_info: None,
            etag: None,
            cf_ray: None,
        },
    )
    .expect_err("null is present state, not absence");
    assert!(
        error.to_string().contains("same_site_cookie_attribute"),
        "{error}"
    );
}

#[test]
pub(super) fn access_application_execution_precondition_rejects_new_unclassified_state() {
    let capability = access_application_login_methods_capability();
    let variant = super::access_application_login_methods_variant(
        super::ACCESS_APP_LOGIN_METHODS_CAPABILITY_ID,
    )
    .expect("self-hosted variant");
    let planned_source = access_application_live_result();
    let input = CallInput {
        selectors: json!({
            "account_id":"account-a",
            "app_id":"82131ea1-c7a6-4fc7-ab99-b11ddd2ff426"
        }),
        body: Some(
            super::access_application_mutable_body(
                &planned_source,
                &["7b0bc477-5d42-4dab-b0ea-c97d0aef7810".to_owned()],
                variant,
            )
            .expect("preservation-safe full PUT body"),
        ),
        ..CallInput::default()
    };
    let mut drifted_source = planned_source;
    drifted_source["future_writable_field"] = json!({"must_be_preserved":true});
    let error = super::apply_same_path_prior_state_response(
        &capability,
        &input,
        "account-a",
        &CloudflareResponseV1 {
            status: 200,
            success: true,
            result: drifted_source,
            errors: Vec::new(),
            result_info: None,
            etag: None,
            cf_ray: None,
        },
    )
    .expect_err("new unclassified state must block execution");
    assert!(error.to_string().contains("future_writable_field"));
}

#[test]
pub(super) fn access_application_policy_projection_rejects_duplicate_stable_identity() {
    let policies = json!([
        {"id":"policy-a","precedence":1},
        {"id":"policy-a","precedence":2}
    ]);
    assert!(
        super::normalize_access_application_policies(&policies)
            .expect_err("one policy identity cannot occupy two precedences")
            .to_string()
            .contains("duplicate")
    );
}

#[test]
pub(super) fn access_application_forward_pinning_accepts_implicit_open_current_state_without_weakening_guards()
 {
    let desired_idp = "7b0bc477-5d42-4dab-b0ea-c97d0aef7810".to_owned();
    let desired_input = CallInput {
        selectors: json!({
            "account_id":"account-a",
            "app_id":"82131ea1-c7a6-4fc7-ab99-b11ddd2ff426"
        }),
        body: Some(json!({"allowed_idps":[desired_idp.clone()]})),
        ..CallInput::default()
    };
    let empty_desired_input = CallInput {
        body: Some(json!({"allowed_idps":[]})),
        ..desired_input.clone()
    };
    assert!(
        super::access_application_desired_idps(&empty_desired_input).is_err(),
        "an empty desired IdP set must continue to fail closed"
    );

    let capability = access_application_login_methods_capability();
    let variant = super::access_application_login_methods_variant(
        super::ACCESS_APP_LOGIN_METHODS_CAPABILITY_ID,
    )
    .expect("self-hosted variant");
    let mut implicit_open = access_application_live_result();
    implicit_open["allowed_idps"] = json!([]);
    let planned_body = super::access_application_mutable_body(
        &implicit_open,
        std::slice::from_ref(&desired_idp),
        variant,
    )
    .expect("non-empty desired IdP set produces a preservation-safe forward body");
    assert_eq!(planned_body["allowed_idps"], json!([desired_idp]));

    let rollback_error = super::apply_same_path_prior_state_response(
        &capability,
        &CallInput {
            body: Some(planned_body),
            ..desired_input
        },
        "account-a",
        &CloudflareResponseV1 {
            status: 200,
            success: true,
            result: implicit_open.clone(),
            errors: Vec::new(),
            result_info: None,
            etag: None,
            cf_ray: None,
        },
    )
    .expect_err("an implicit-open prior state must retain an explicit rollback limitation");
    assert!(
        rollback_error
            .to_string()
            .contains("empty identity-provider allowlist"),
        "{rollback_error}"
    );

    assert_eq!(
        super::normalized_access_application_idps(&implicit_open["allowed_idps"])
            .expect("forward pinning must accept an implicit-open current IdP set"),
        Vec::<String>::new()
    );
}

#[test]
pub(super) fn access_application_plan_accepts_one_populated_destination_representation() {
    let desired_idp = "7b0bc477-5d42-4dab-b0ea-c97d0aef7810".to_owned();
    let variant = super::access_application_login_methods_variant(
        super::ACCESS_APP_LOGIN_METHODS_CAPABILITY_ID,
    )
    .expect("self-hosted variant");
    let mut failures = Vec::new();

    for (label, empty_field) in [
        ("self-hosted domains only", "destinations"),
        ("destinations only", "self_hosted_domains"),
    ] {
        let mut capability = access_application_login_methods_capability();
        let schema = capability
            .request_schema
            .as_mut()
            .expect("materialized application request schema");
        schema["properties"]["destinations"]["minItems"] = json!(1);
        schema["properties"]["self_hosted_domains"]["minItems"] = json!(1);

        let mut input = CallInput {
            selectors: json!({
                "account_id":"account-a",
                "app_id":"82131ea1-c7a6-4fc7-ab99-b11ddd2ff426"
            }),
            body: Some(json!({"allowed_idps":[desired_idp.clone()]})),
            ..CallInput::default()
        };
        super::validate_access_application_login_methods_desired_input(&capability, &input)
            .expect("narrow desired input remains valid");

        let mut live = access_application_live_result();
        live[empty_field] = json!([]);
        let populated_field = if empty_field == "destinations" {
            "self_hosted_domains"
        } else {
            "destinations"
        };
        assert!(
            live[empty_field].as_array().is_some_and(Vec::is_empty)
                && live[populated_field]
                    .as_array()
                    .is_some_and(|values| !values.is_empty()),
            "{label} fixture must contain exactly one populated representation"
        );

        let response = CloudflareResponseV1 {
            status: 200,
            success: true,
            result: live,
            errors: Vec::new(),
            result_info: None,
            etag: None,
            cf_ray: None,
        };
        match super::finalize_access_application_login_methods_plan_input(
            &mut capability,
            &mut input,
            std::slice::from_ref(&desired_idp),
            variant,
            "account-a",
            &response,
        ) {
            Ok(Some(_)) => {}
            Ok(None) => failures.push(format!("{label}: plan omitted its prior-state receipt")),
            Err(error) => failures.push(format!("{label}: {error}")),
        }
    }

    assert!(
        failures.is_empty(),
        "one valid destination representation must be sufficient for planning: {failures:?}"
    );
}

pub(super) fn assert_implicit_open_concurrency_receipt_blocks_drift_without_rollback(
    capability: CapabilityV1,
    input: &CallInput,
    prior_state: Option<Value>,
    expected_current_state: &Value,
) {
    let receipt = prior_state.expect(
            "implicit-open plans still need a hash-bound closed current-state receipt for apply-time concurrency checks",
        );
    assert_eq!(
        receipt.get("prior_state"),
        Some(expected_current_state),
        "the concurrency receipt must retain the exact closed mutable snapshot"
    );
    let receipt_hash = hash_value(&receipt).expect("concurrency receipt hash");
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
        json!({
            "selectors":input.selectors,
            "account_id":"account-a",
            "adapter":{},
            "live_preconditions":{
                "same_path_prior_state":receipt.clone()
            }
        }),
    )
    .expect("implicit-open plan");
    plan.input = serde_json::to_value(input).expect("plan input");
    plan.precondition_hashes.insert(
        super::SAME_PATH_PRIOR_STATE_PRECONDITION.to_owned(),
        receipt_hash.clone(),
    );
    assert_eq!(
        super::required_same_path_prior_state_precondition(&plan)
            .expect("apply must require the concurrency precondition"),
        Some(receipt_hash.as_str()),
        "unsupported rollback must not disable apply-time live re-read"
    );

    let mut drifted_receipt = receipt.clone();
    drifted_receipt["prior_state"]["name"] = json!("Concurrent application rename");
    let drift_error =
        super::validate_same_path_prior_state_receipt_precondition(&receipt_hash, &drifted_receipt)
            .expect_err("a mutable-field change between plan and apply must block execution");
    assert!(
        drift_error.to_string().contains("drifted after planning"),
        "{drift_error}"
    );

    plan.refresh_hash().expect("bind concurrency precondition");
    plan.approve(true, None).expect("approve test plan");
    plan.mark_consumed().expect("consume test plan");
    plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("record boundary attempt");
    plan.record_transaction_stage_with_artifact(
        TransactionStageV1::BoundaryResponsePersisted,
        json!({"success":true,"http_status":200}),
    )
    .expect("record successful boundary response");
    assert!(
        super::compensation_request(&plan)
            .expect("compensation selection")
            .is_none(),
        "the concurrency receipt must not become automatic rollback authority"
    );
}

#[test]
pub(super) fn access_application_implicit_open_plan_is_concurrency_guarded_without_automatic_rollback()
 {
    let desired_idp = "7b0bc477-5d42-4dab-b0ea-c97d0aef7810".to_owned();
    let mut input = CallInput {
        selectors: json!({
            "account_id":"account-a",
            "app_id":"82131ea1-c7a6-4fc7-ab99-b11ddd2ff426"
        }),
        body: Some(json!({"allowed_idps":[desired_idp.clone()]})),
        ..CallInput::default()
    };
    let desired_idps = super::access_application_desired_idps(&input)
        .expect("a non-empty UUID-validated desired IdP set");
    let mut capability = access_application_login_methods_capability();
    let variant = super::access_application_login_methods_variant(
        super::ACCESS_APP_LOGIN_METHODS_CAPABILITY_ID,
    )
    .expect("self-hosted variant");
    let mut implicit_open = access_application_live_result();
    implicit_open["allowed_idps"] = json!([]);
    let expected_current_state =
        super::access_application_mutable_body(&implicit_open, &[], variant)
            .expect("the implicit-open application state has a closed mutable projection");
    let expected_body =
        super::access_application_mutable_body(&implicit_open, &desired_idps, variant)
            .expect("the desired IdP set materializes a preservation-safe full PUT body");
    let response = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: implicit_open,
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };

    let prior_state = super::finalize_access_application_login_methods_plan_input(
            &mut capability,
            &mut input,
            &desired_idps,
            variant,
            "account-a",
            &response,
        )
        .unwrap_or_else(|error| {
            panic!(
                "an implicit-open current IdP state must produce a plan with explicit non-restorable rollback metadata: {error}"
            )
        });

    assert_eq!(
        input.body.as_ref(),
        Some(&expected_body),
        "plan preparation must retain the fully materialized desired application body"
    );
    assert!(!capability.rollback.supported);
    assert!(capability.rollback.strategy.is_none());
    assert_eq!(
        capability.rollback.warning.as_deref(),
        Some(
            "the prior implicit-open identity-provider state cannot be restored automatically; manual rollback requires a separately reviewed Cloudflare Access application change"
        )
    );
    assert!(
        capability.mutation_contract_gaps().is_empty(),
        "explicitly unsupported rollback must remain a complete mutation contract: {:?}",
        capability.mutation_contract_gaps()
    );

    assert_implicit_open_concurrency_receipt_blocks_drift_without_rollback(
        capability,
        &input,
        prior_state,
        &expected_current_state,
    );
}

#[test]
pub(super) fn access_application_desired_idps_rejects_empty_duplicate_and_non_uuid_sets() {
    let input = |allowed_idps: Value| CallInput {
        selectors: json!({
            "account_id":"account-a",
            "app_id":"82131ea1-c7a6-4fc7-ab99-b11ddd2ff426"
        }),
        body: Some(json!({"allowed_idps":allowed_idps})),
        ..CallInput::default()
    };
    let capability = access_application_login_methods_capability();
    let mut desired_schema_capability = capability.clone();
    desired_schema_capability.request_schema =
        Some(super::access_application_login_methods_desired_schema());
    assert_eq!(
        desired_schema_capability
            .request_schema
            .as_ref()
            .and_then(|schema| schema.pointer("/properties/allowed_idps/items")),
        Some(&cfctl_catalog::access_identity_provider_id_schema()),
        "runtime and catalog must share the exact identity-provider schema"
    );
    for documented_id in [
        "699d98642c564d2e855e9661899b7252",
        "7b0bc477-5d42-4dab-b0ea-c97d0aef7810",
    ] {
        super::validate_request_contract(
            &desired_schema_capability,
            &input(json!([documented_id])),
        )
        .unwrap_or_else(|error| {
            panic!("schema should accept documented ID {documented_id}: {error}")
        });
        super::validate_access_application_login_methods_desired_input(
            &capability,
            &input(json!([documented_id])),
        )
        .unwrap_or_else(|error| panic!("{documented_id} should be accepted: {error}"));
    }
    assert!(super::access_application_desired_idps(&input(json!([]))).is_err());
    assert!(
        super::access_application_desired_idps(&input(json!([
            "7b0bc477-5d42-4dab-b0ea-c97d0aef7810",
            "7b0bc477-5d42-4dab-b0ea-c97d0aef7810"
        ])))
        .is_err()
    );
    assert!(
        super::access_application_desired_idps(&input(json!([
            "7b0bc4775d424dabb0eac97d0aef7810",
            "7b0bc477-5d42-4dab-b0ea-c97d0aef7810"
        ])))
        .is_err(),
        "one stable IdP identity rendered two ways must remain a duplicate"
    );
    assert!(super::access_application_desired_idps(&input(json!(["github"]))).is_err());
    for malformed in [
        "699d98642c564d2e855e9661899b725",
        "699d98642c564d2e855e9661899b72520",
        "7b0bc477-5d42-4dab-b0ea-c97d0aef781",
        "g99d98642c564d2e855e9661899b7252",
        "7b0bc477-5d42-4dab-b0ea-c97d0aef781z",
        "7b0bc4775-d42-4dab-b0ea-c97d0aef7810",
    ] {
        assert!(
            super::validate_request_contract(
                &desired_schema_capability,
                &input(json!([malformed])),
            )
            .is_err(),
            "pinned schema accepted malformed identity-provider ID: {malformed}"
        );
        assert!(
            super::validate_access_application_login_methods_desired_input(
                &capability,
                &input(json!([malformed])),
            )
            .is_err(),
            "malformed identity-provider ID was accepted: {malformed}"
        );
    }
}
