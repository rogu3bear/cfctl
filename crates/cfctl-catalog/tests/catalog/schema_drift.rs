use super::*;

fn with_enabled(mut document: Value) -> Value {
    document["components"]["schemas"]["ServiceToken"]["properties"]["enabled"] =
        json!({"type":"boolean"});
    for (path, item) in document["paths"].as_object_mut().unwrap() {
        if path.ends_with("/service_tokens") || path.ends_with("/service_tokens/{service_token_id}")
        {
            for method in ["post", "put"] {
                if let Some(operation) = item.get_mut(method) {
                    operation["requestBody"]["content"]["application/json"]["schema"]["properties"]
                        ["enabled"] = json!({"type":"boolean"});
                }
            }
        }
    }
    document
}

#[test]
fn access_enabled_is_typed_verified_and_keeps_secret_rotation_out_of_the_body() {
    for fixture in [
        access_service_token_fixture(),
        zone_access_service_token_fixture(),
    ] {
        let snapshot = normalize_openapi(&with_enabled(fixture)).unwrap();
        for capability in snapshot.capabilities.values().filter(|capability| {
            capability.id.ends_with("create-a-service-token")
                || capability.id.ends_with("update-a-service-token")
        }) {
            assert_eq!(
                capability.adapter_status,
                AdapterStatus::DynamicApi,
                "{} {:?}",
                capability.id,
                capability.blocked_reason
            );
            let schema = capability.request_schema.as_ref().unwrap();
            assert_eq!(schema["properties"]["enabled"], json!({"type":"boolean"}));
            assert_eq!(schema["additionalProperties"], false);
            assert!(schema["properties"].get("client_secret_version").is_none());
            assert!(capability.mutation_contract_gaps().is_empty());
            let fields = capability
                .created_resource
                .as_ref()
                .map(|c| &c.verified_response_fields)
                .or_else(|| {
                    capability
                        .same_path_read
                        .as_ref()
                        .map(|c| &c.verified_response_fields)
                })
                .unwrap();
            assert!(fields.iter().any(|field| field == "enabled"));
            assert_eq!(capability.effect, EffectClass::IdentityOrOwnership);
        }
    }
}

#[test]
fn access_enabled_schema_or_readback_drift_remains_blocked() {
    for bad_type in ["string", "number"] {
        let mut document = with_enabled(access_service_token_fixture());
        document["paths"]["/accounts/{account_id}/access/service_tokens"]["post"]["requestBody"]
            ["content"]["application/json"]["schema"]["properties"]["enabled"] =
            json!({"type":bad_type});
        let snapshot = normalize_openapi(&document).unwrap();
        assert_eq!(
            snapshot
                .get("access-service-tokens-create-a-service-token")
                .unwrap()
                .adapter_status,
            AdapterStatus::Blocked
        );
    }
    let mut document = with_enabled(access_service_token_fixture());
    document["components"]["schemas"]["ServiceToken"]["properties"]
        .as_object_mut()
        .unwrap()
        .remove("enabled");
    let snapshot = normalize_openapi(&document).unwrap();
    assert_eq!(
        snapshot
            .get("access-service-tokens-create-a-service-token")
            .unwrap()
            .adapter_status,
        AdapterStatus::Blocked
    );
}

#[test]
fn kv_jurisdiction_schema_keeps_default_creation_separate_from_private_beta_access() {
    let mut document = workers_kv_namespace_fixture();
    let mut body =
        document["components"]["schemas"]["workers-kv_create_rename_namespace_body"].clone();
    body["properties"]["jurisdiction"] = json!({"type":"string","enum":["eu","fedramp","us"]});
    document["paths"]["/accounts/{account_id}/storage/kv/namespaces"]["post"]["requestBody"]["content"]
        ["application/json"]["schema"] = body;
    let snapshot = normalize_openapi(&document).unwrap();
    let create = snapshot
        .get("workers-kv-namespace-create-a-namespace")
        .unwrap();
    assert_workers_kv_namespace_create(create);
    let schema = create.request_schema.as_ref().unwrap();
    assert_eq!(schema["additionalProperties"], false);
    assert!(schema["properties"].get("jurisdiction").is_none());
    assert_eq!(
        create
            .created_resource
            .as_ref()
            .unwrap()
            .verified_response_fields,
        ["title"]
    );
}

fn dry_run_selector() -> SelectorV1 {
    SelectorV1 {
        name: "dry_run".to_owned(),
        location: "query".to_owned(),
        required: false,
        value_type: "boolean".to_owned(),
        description: Some("Validates the request without persisting changes when set to `true`. Responses that normally return 200 return `result: null`; endpoints that normally return 204 continue to return 204.".to_owned()),
        contract: Some(cfctl_core::SelectorContractV1 {
            schema: json!({"type":"boolean"}),
            query: Some(cfctl_core::QuerySerializationV1 {
                style: "form".to_owned(), explode: true,
                allow_reserved: false, allow_empty_value: false,
            }),
        }),
    }
}

#[test]
fn waf_persisted_lifecycles_exclude_dry_run_and_keep_raw_rules_restricted() {
    let mut snapshot = telemetry_tail_and_ruleset_overlay_snapshot();
    snapshot
        .capabilities
        .extend(waf_security_response_overlay_snapshot().capabilities);
    for capability in snapshot.capabilities.values_mut().filter(|c| c.mutating) {
        capability.selectors.push(dry_run_selector());
    }
    ingest_telemetry_capabilities(&mut snapshot).unwrap();
    for id in [
        "security-response-create-empty-custom-ruleset",
        "deleteZoneRuleset",
        "deleteZoneRulesetRule",
        "security-response-remove-expired-waf-rule",
    ] {
        let capability = snapshot.get(id).unwrap();
        assert_eq!(
            capability.adapter_status,
            AdapterStatus::DynamicApi,
            "{id} {:?}",
            capability.blocked_reason
        );
        assert!(
            !capability
                .selectors
                .iter()
                .any(|selector| selector.name == "dry_run")
        );
        assert!(capability.mutation_contract_gaps().is_empty());
    }
    for id in ["createZoneRuleset", "createZoneRulesetRule"] {
        assert_eq!(
            snapshot.get(id).unwrap().adapter_status,
            AdapterStatus::Blocked
        );
    }
}

#[test]
fn waf_dry_run_contract_drift_cannot_promote_a_persisted_operation() {
    let mut snapshot = telemetry_tail_and_ruleset_overlay_snapshot();
    let mut selector = dry_run_selector();
    selector.required = true;
    snapshot
        .capabilities
        .get_mut("createZoneRuleset")
        .unwrap()
        .selectors
        .push(selector);
    ingest_telemetry_capabilities(&mut snapshot).unwrap();
    let create = snapshot
        .get("security-response-create-empty-custom-ruleset")
        .unwrap();
    assert_eq!(create.adapter_status, AdapterStatus::Blocked);
}

fn with_optional_scopes(mut document: Value) -> Value {
    for (path, method) in [
        ("/accounts/{account_id}/oauth_clients", "post"),
        (
            "/accounts/{account_id}/oauth_clients/{oauth_client_id}",
            "patch",
        ),
    ] {
        document["paths"][path][method]["requestBody"]["content"]["application/json"]["schema"]["allOf"]
            [0]["properties"]["optional_scopes"] =
            json!({"type":"array","items":{"type":"string"}});
    }
    document["paths"]["/accounts/{account_id}/oauth_clients/{oauth_client_id}"]["get"]["responses"]
        ["200"]["content"]["application/json"]["schema"]["allOf"][1]["properties"]["result"]["properties"]
        ["optional_scopes"] = json!({"type":"array","items":{"type":"string"}});
    document
}

#[test]
fn oauth_optional_scopes_are_closed_and_bound_to_detail_readback() {
    let snapshot =
        normalize_openapi(&with_optional_scopes(oauth_client_create_update_fixture())).unwrap();
    for id in ["oauth-clients-create", "oauth-clients-update"] {
        let capability = snapshot.get(id).unwrap();
        assert_eq!(
            capability.adapter_status,
            AdapterStatus::DynamicApi,
            "{id} {:?}",
            capability.blocked_reason
        );
        assert!(capability.mutation_contract_gaps().is_empty());
        assert_eq!(
            capability.request_schema.as_ref().unwrap()["properties"]["optional_scopes"],
            json!({"type":"array","items":{"type":"string"}})
        );
        let fields = capability
            .created_resource
            .as_ref()
            .map(|target| &target.verified_response_fields)
            .or_else(|| {
                capability
                    .same_path_read
                    .as_ref()
                    .map(|target| &target.verified_response_fields)
            })
            .unwrap();
        assert!(fields.iter().any(|field| field == "optional_scopes"));
    }
}

#[test]
fn oauth_optional_scopes_without_readback_or_with_schema_drift_stay_blocked() {
    for missing_readback in [true, false] {
        let mut document = with_optional_scopes(oauth_client_create_update_fixture());
        if missing_readback {
            document["paths"]["/accounts/{account_id}/oauth_clients/{oauth_client_id}"]["get"]["responses"]
                ["200"]["content"]["application/json"]["schema"]["allOf"][1]["properties"]["result"]
                ["properties"].as_object_mut().unwrap().remove("optional_scopes");
        } else {
            document["paths"]["/accounts/{account_id}/oauth_clients"]["post"]["requestBody"]["content"]
                ["application/json"]["schema"]["allOf"][0]["properties"]["optional_scopes"] =
                json!({"type":"string"});
        }
        assert_eq!(
            normalize_openapi(&document)
                .unwrap()
                .get("oauth-clients-create")
                .unwrap()
                .adapter_status,
            AdapterStatus::Blocked
        );
    }
}

#[test]
fn r2_us_jurisdiction_preserves_companions_and_bounds_a_rounded_billing_unit() {
    let mut document = r2_bucket_fixture();
    document["components"]["schemas"]["jurisdiction"]["enum"] =
        json!(["default", "eu", "us", "fedramp"]);
    let snapshot = normalize_openapi(&document).unwrap();
    let create = snapshot.get("r2-create-bucket").unwrap();
    assert_eq!(
        create.adapter_status,
        AdapterStatus::DynamicApi,
        "{:?}",
        create.blocked_reason
    );
    assert_eq!(create.cost.maximum, Some(9.0));
    assert!(create.cost.basis.as_ref().unwrap().contains("round"));
    let header = create
        .selectors
        .iter()
        .find(|selector| selector.name == "cf-r2-jurisdiction")
        .unwrap();
    assert_eq!(
        header.contract.as_ref().unwrap().schema["enum"],
        json!(["default", "eu", "us"])
    );
    assert_eq!(
        create.created_resource.as_ref().unwrap().read_capability_id,
        "r2-get-bucket"
    );
    assert_eq!(
        create
            .created_resource
            .as_ref()
            .unwrap()
            .delete_capability_id,
        "r2-delete-bucket"
    );
}

#[test]
fn email_preview_retains_snapshot_recovery_and_explicit_zone_entitlement() {
    let document: Value =
        serde_json::from_str(include_str!("../fixtures/email-preview-operations.json")).unwrap();
    let snapshot = normalize_openapi(&document).unwrap();
    let update = snapshot
        .get("email-sending-subdomains-update-sending-subdomain")
        .unwrap();
    let schema = update.request_schema.as_ref().unwrap();
    assert_eq!(schema["required"], json!(["preview_enabled"]));
    assert_eq!(schema["additionalProperties"], false);
    assert!(
        schema["properties"]
            .get("drop_suppressed_recipients")
            .is_none()
    );
    assert_eq!(
        update
            .same_path_read
            .as_ref()
            .unwrap()
            .verified_response_fields,
        ["preview_enabled"]
    );
    assert_eq!(
        update.rollback.strategy.as_deref(),
        Some("restore_same_path_prior_snapshot")
    );
    assert_eq!(update.permissions, ["Email Sending Write"]);
    assert!(update.cost.known);
    assert_eq!(update.entitlement.available, None);
    let probe = update.entitlement.probe.as_ref().unwrap();
    assert_eq!(probe.selector_names, ["zone_id"]);
    assert_eq!(
        probe.capability_id,
        "email-sending-subdomains-list-sending-subdomains"
    );
    assert_eq!(update.adapter_status, AdapterStatus::DynamicApi);
    assert!(update.entitlement.requires_live_resolution);
    let gaps = update.mutation_contract_gaps();
    assert!(gaps.is_empty(), "{gaps:?}");
    let mut drifted = document;
    drifted["components"]["schemas"]["email_update_sending_subdomain_properties"]["properties"]["preview_enabled"] =
        json!({"type":"string"});
    assert_eq!(
        normalize_openapi(&drifted)
            .unwrap()
            .get("email-sending-subdomains-update-sending-subdomain")
            .unwrap()
            .adapter_status,
        AdapterStatus::Blocked
    );
}
