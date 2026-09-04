use super::*;

#[test]
pub(super) fn d1_state_hash_is_validated_by_the_live_precondition_lane() {
    assert!(is_live_plan_precondition_hash("d1_read_replication_state"));
    assert!(is_live_plan_precondition_hash(
        "cloudflare_tunnel_configuration_state"
    ));
    assert!(is_live_plan_precondition_hash(
        "warp_connector_configuration_state"
    ));
    assert!(is_live_plan_precondition_hash("web_analytics_rum_state"));
    assert!(is_live_plan_precondition_hash("r2_parent_token"));
    assert!(!is_live_plan_precondition_hash("workspace_graph"));
}

pub(super) fn test_catalog() -> CatalogSnapshot {
    let capability = CapabilityV1::new("accounts-list", "List accounts", "GET", "/accounts");
    let mut catalog = CatalogSnapshot {
        schema_version: 1,
        generated_at: Utc::now(),
        source_url: "https://example.invalid/openapi.json".to_owned(),
        source_hash: "source-sha".to_owned(),
        schema_hash: String::new(),
        capabilities: BTreeMap::from([(capability.id.clone(), capability)]),
    };
    catalog.refresh_hash().expect("catalog hash");
    catalog
}

pub(super) fn workers_secret_input_capability() -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        "worker-put-script-secret",
        "Add script secret",
        "PUT",
        "/accounts/{account_id}/workers/scripts/{script_name}/secrets",
    );
    "Worker Script".clone_into(&mut capability.product);
    capability.permissions = vec!["Workers Scripts Write".to_owned()];
    capability.risk = RiskClass::SecretSensitive;
    "worker_script_secret_reports_planned_name_and_type_after_put"
        .clone_into(&mut capability.verification.strategy);
    capability.request_schema = Some(json!({
        "type":"object",
        "oneOf":[
            {
                "type":"object",
                "required":["name","type","text"],
                "properties":{
                    "name":{"type":"string"},
                    "type":{"type":"string","enum":["secret_text"]},
                    "text":{"type":"string","writeOnly":true}
                }
            },
            {
                "type":"object",
                "required":["name","type","format","algorithm","usages"],
                "properties":{
                    "name":{"type":"string"},
                    "type":{"type":"string","enum":["secret_key"]},
                    "format":{"type":"string","enum":["raw","pkcs8","spki","jwk"]},
                    "algorithm":{"type":"object"},
                    "usages":{"type":"array","items":{"type":"string"}},
                    "key_base64":{"type":"string","writeOnly":true},
                    "key_jwk":{"type":"object","writeOnly":true}
                }
            }
        ],
        "x-cfctl-body-required":true
    }));
    capability
}

#[test]
pub(super) fn workers_secret_inputs_are_schema_detected_without_becoming_secret_outputs() {
    let capability = workers_secret_input_capability();
    let body = json!({
        "name":"DATABASE_TOKEN",
        "type":"secret_text",
        "text":"not-detected-by-generic-key-redaction"
    });

    assert!(request_body_contains_secret(&capability, &body));
    assert!(!is_secret_output_capability(&capability));
    assert!(should_redact_secret_response(&capability));
    assert_eq!(secret_sink_format(&capability), None);
    let argv = capability_call_argv(&capability);
    assert!(argv.iter().any(|argument| argument == "--body-stdin"));
    assert!(!argv.iter().any(|argument| argument == "--value-out"));

    let mut ordinary = CapabilityV1::new(
        "workers-update-description",
        "Update description",
        "PUT",
        "/accounts/{account_id}/workers/scripts/{script_name}",
    );
    ordinary.request_schema = Some(json!({
        "type":"object",
        "properties":{"text":{"type":"string"}}
    }));
    assert!(!request_body_contains_secret(
        &ordinary,
        &json!({"text":"ordinary public text"})
    ));
}

#[test]
pub(super) fn workers_secret_key_material_matches_the_declared_format() {
    let capability = workers_secret_input_capability();
    for body in [
        json!({"name":"TOKEN","type":"secret_text","text":"value"}),
        json!({"name":"KEY","type":"secret_key","format":"raw","algorithm":{},"usages":["sign"],"key_base64":"dmFsdWU="}),
        json!({"name":"KEY","type":"secret_key","format":"jwk","algorithm":{},"usages":["sign"],"key_jwk":{"kty":"oct","k":"dmFsdWU"}}),
    ] {
        validate_worker_script_secret_semantics(
            &capability,
            &CallInput {
                body: Some(body),
                ..CallInput::default()
            },
        )
        .expect("valid secret input");
    }

    for (body, expected) in [
        (
            json!({"name":"TOKEN","type":"secret_text","text":"value","key_base64":"dmFsdWU="}),
            "secret_text accepts only `text`",
        ),
        (
            json!({"name":"KEY","type":"secret_key","format":"jwk","algorithm":{},"usages":["sign"],"key_base64":"dmFsdWU="}),
            "format `jwk` requires `key_jwk`",
        ),
        (
            json!({"name":"KEY","type":"secret_key","format":"raw","algorithm":{},"usages":["sign"],"key_jwk":{"kty":"oct"}}),
            "format `raw` requires `key_base64`",
        ),
        (
            json!({"name":"KEY","type":"secret_key","format":"raw","algorithm":{},"usages":["sign"],"key_base64":"dmFsdWU=","key_jwk":{"kty":"oct"}}),
            "exactly one key material field",
        ),
    ] {
        let error = validate_worker_script_secret_semantics(
            &capability,
            &CallInput {
                body: Some(body),
                ..CallInput::default()
            },
        )
        .expect_err("invalid key material must fail before planning")
        .to_string();
        assert!(error.contains(expected), "{error}");
        assert!(!error.contains("dmFsdWU"));
    }
}

#[test]
pub(super) fn workers_secret_response_redaction_defensively_covers_input_field_names() {
    let response = json!({
        "success":true,
        "result":{
            "name":"DATABASE_TOKEN",
            "type":"secret_text",
            "text":"unexpected-text-echo",
            "key_base64":"unexpected-key-echo",
            "key_jwk":{"k":"unexpected-jwk-echo"}
        }
    });

    let redacted = redact_secret_result(&response);
    assert_eq!(redacted["result"]["name"], "DATABASE_TOKEN");
    assert_eq!(redacted["result"]["type"], "secret_text");
    assert_eq!(redacted["result"]["text"], "[SUNK]");
    assert_eq!(redacted["result"]["key_base64"], "[SUNK]");
    assert_eq!(redacted["result"]["key_jwk"], "[SUNK]");
    assert!(!redacted.to_string().contains("unexpected"));
}

pub(super) fn global_warp_override_capability() -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        "devices-resilience-set-global-warp-override",
        "Set Global WARP override state",
        "POST",
        "/accounts/{account_id}/devices/resilience/disconnect",
    );
    capability.mutating = true;
    capability.account_scope = "account".to_owned();
    capability.adapter_status = AdapterStatus::DynamicApi;
    capability.product = "Devices Resilience".to_owned();
    capability.risk = RiskClass::CrossConfig;
    capability.effect = EffectClass::ReversibleWrite;
    capability.permissions = vec!["Zero Trust Resilience Write".to_owned()];
    capability.cost.known = true;
    capability.cost.maximum = Some(0.0);
    capability.cost.basis = Some("no direct incremental operation charge".to_owned());
    capability.entitlement.available = Some(true);
    capability.request_schema = Some(json!({
        "type": "object",
        "required": ["disconnect"],
        "x-cfctl-body-required": true,
        "additionalProperties": false,
        "properties": {
            "disconnect": {"type": "boolean"},
            "justification": {
                "type": "string",
                "x-cfctl-verification-observable": false,
            },
        },
    }));
    capability.selectors = vec![SelectorV1 {
        name: "account_id".to_owned(),
        location: "path".to_owned(),
        required: true,
        value_type: "string".to_owned(),
        description: None,
        contract: None,
    }];
    capability.verification.strategy =
        "same_path_result_contains_planned_fields_after_mutation".to_owned();
    capability.same_path_read = Some(SamePathReadContractV1 {
        path: "/accounts/{account_id}/devices/resilience/disconnect".to_owned(),
        read_capability_id: "devices-resilience-retrieve-global-warp-override".to_owned(),
        verified_response_fields: vec!["disconnect".to_owned()],
    });
    capability.rollback.supported = true;
    capability.rollback.strategy =
        Some("restore_global_warp_override_prior_disconnect_state".to_owned());
    capability.rollback.warning = Some("restoration requires explicit approval".to_owned());
    capability
}

pub(super) fn d1_read_replication_update_capability() -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        "d1-update-partial-database",
        "Update D1 Database partially",
        "PATCH",
        "/accounts/{account_id}/d1/database/{database_id}",
    );
    capability.mutating = true;
    capability.account_scope = "account".to_owned();
    capability.adapter_status = AdapterStatus::DynamicApi;
    capability.product = "D1".to_owned();
    capability.risk = RiskClass::ScopedWrite;
    capability.effect = EffectClass::ReversibleWrite;
    capability.permissions = vec!["D1 Write".to_owned()];
    capability.cost.known = true;
    capability.cost.maximum = Some(0.0);
    capability.cost.basis = Some("no incremental operation charge".to_owned());
    capability.request_schema = Some(json!({
        "type": "object",
        "x-cfctl-body-required": true,
        "properties": {
            "read_replication": {
                "type": "object",
                "required": ["mode"],
                "properties": {
                    "mode": {"type": "string", "enum": ["auto", "disabled"]},
                },
            },
        },
    }));
    capability.selectors = vec![
        SelectorV1 {
            name: "account_id".to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        },
        SelectorV1 {
            name: "database_id".to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        },
    ];
    capability.verification.strategy =
        "same_resource_contains_planned_fields_after_update".to_owned();
    capability.same_path_read = Some(SamePathReadContractV1 {
        path: "/accounts/{account_id}/d1/database/{database_id}".to_owned(),
        read_capability_id: "d1-get-database".to_owned(),
        verified_response_fields: vec!["read_replication".to_owned()],
    });
    capability.rollback.supported = true;
    capability.rollback.strategy = Some("restore_d1_read_replication_prior_mode".to_owned());
    capability.rollback.warning = Some("restoration requires explicit approval".to_owned());
    capability
}

pub(super) fn d1_database_create_capability() -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        "d1-create-database",
        "Create D1 Database",
        "POST",
        "/accounts/{account_id}/d1/database",
    );
    capability.mutating = true;
    capability.account_scope = "account".to_owned();
    capability.adapter_status = AdapterStatus::DynamicApi;
    capability.product = "D1".to_owned();
    capability.risk = RiskClass::ScopedWrite;
    capability.effect = EffectClass::ReversibleWrite;
    capability.permissions = vec!["D1 Write".to_owned()];
    capability.request_schema = Some(json!({
        "type":"object",
        "required":["name"],
        "x-cfctl-body-required":true,
        "properties":{
            "jurisdiction":{"type":"string","enum":["eu","fedramp","us"]},
            "name":{"type":"string"},
            "primary_location_hint":{
                "type":"string",
                "enum":["wnam","enam","weur","eeur","apac","oc"],
                "x-cfctl-verification-observable":false
            },
            "read_replication":{
                "type":"object",
                "required":["mode"],
                "properties":{"mode":{"type":"string","enum":["auto","disabled"]}}
            }
        }
    }));
    capability.verification.strategy =
        "created_resource_contains_planned_fields_by_returned_id".to_owned();
    capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: "/accounts/{account_id}/d1/database/{database_id}".to_owned(),
        identity_selector: "database_id".to_owned(),
        response_result_identity_pointer: "/uuid".to_owned(),
        read_capability_id: "d1-get-database".to_owned(),
        delete_capability_id: "d1-delete-database".to_owned(),
        verified_response_fields: vec![
            "jurisdiction".to_owned(),
            "name".to_owned(),
            "read_replication".to_owned(),
        ],
    });
    capability.rollback.supported = true;
    capability.rollback.strategy =
        Some("delete_created_empty_d1_database_by_returned_uuid_if_unchanged".to_owned());
    capability
}

pub(super) fn d1_database_delete_capability() -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        "d1-delete-database",
        "Delete D1 Database",
        "DELETE",
        "/accounts/{account_id}/d1/database/{database_id}",
    );
    capability.mutating = true;
    capability.account_scope = "account".to_owned();
    capability.adapter_status = AdapterStatus::DynamicApi;
    capability.product = "D1".to_owned();
    capability.risk = RiskClass::Destructive;
    capability.effect = EffectClass::Irreversible;
    capability
}

pub(super) fn cloudflare_tunnel_configuration_capability() -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        "cloudflare-tunnel-configuration-put-configuration",
        "Put configuration",
        "PUT",
        "/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations",
    );
    capability.mutating = true;
    capability.account_scope = "account".to_owned();
    capability.adapter_status = AdapterStatus::DynamicApi;
    capability.product = "Cloudflare Tunnel Configuration".to_owned();
    capability.risk = RiskClass::CrossConfig;
    capability.effect = EffectClass::ReversibleWrite;
    capability.permissions = vec![
        "Cloudflare One Connectors Write".to_owned(),
        "Cloudflare One Connector: cloudflared Write".to_owned(),
        "Cloudflare Tunnel Write".to_owned(),
    ];
    capability.cost.known = true;
    capability.cost.maximum = Some(0.0);
    capability.cost.basis = Some("no direct incremental operation charge".to_owned());
    capability.entitlement.available = Some(true);
    capability.request_schema = Some(
            serde_json::from_str(include_str!(
                "../../../../cfctl-core/tests/fixtures/cloudflare-tunnel-configuration-put-request-schema.json"
            ))
            .expect("pinned Cloudflare Tunnel configuration schema"),
        );
    capability.selectors = ["account_id", "tunnel_id"]
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
    capability.verification.required = true;
    capability.verification.strategy =
        "same_path_result_contains_planned_fields_after_update".to_owned();
    capability.same_path_read = Some(SamePathReadContractV1 {
        path: "/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations".to_owned(),
        read_capability_id: "cloudflare-tunnel-configuration-get-configuration".to_owned(),
        verified_response_fields: vec!["config".to_owned()],
    });
    capability.rollback.supported = true;
    capability.rollback.strategy =
        Some("restore_cloudflare_tunnel_configuration_prior_snapshot".to_owned());
    capability.rollback.warning = Some("restoration requires explicit approval".to_owned());
    capability
}

pub(super) fn warp_connector_configuration_capability() -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        "cloudflare-tunnel-configuration-update-warp-connector-configuration",
        "Update WARP Connector configuration",
        "PUT",
        "/accounts/{account_id}/warp_connector/{tunnel_id}/configurations",
    );
    capability.mutating = true;
    capability.account_scope = "account".to_owned();
    capability.adapter_status = AdapterStatus::DynamicApi;
    capability.product = "Cloudflare Tunnel Configuration".to_owned();
    capability.risk = RiskClass::CrossConfig;
    capability.effect = EffectClass::ReversibleWrite;
    capability.permissions = vec![
        "Cloudflare One Connectors Write".to_owned(),
        "Cloudflare One Connector: WARP Write".to_owned(),
    ];
    capability.cost.known = true;
    capability.cost.maximum = Some(0.0);
    capability.cost.basis = Some("no direct incremental operation charge".to_owned());
    capability.entitlement.available = Some(true);
    capability.request_schema = Some(
            serde_json::from_str(include_str!(
                "../../../../cfctl-core/tests/fixtures/warp-connector-configuration-update-request-schema.json"
            ))
            .expect("pinned WARP Connector configuration schema"),
        );
    capability.selectors = ["account_id", "tunnel_id"]
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
    capability.verification.required = true;
    capability.verification.strategy =
        "same_path_result_contains_planned_fields_after_update".to_owned();
    capability.same_path_read = Some(SamePathReadContractV1 {
        path: "/accounts/{account_id}/warp_connector/{tunnel_id}/configurations".to_owned(),
        read_capability_id: "cloudflare-tunnel-configuration-get-warp-connector-configuration"
            .to_owned(),
        verified_response_fields: vec!["config".to_owned(), "ha_mode".to_owned()],
    });
    capability.rollback.supported = true;
    capability.rollback.strategy =
        Some("restore_warp_connector_configuration_prior_snapshot".to_owned());
    capability.rollback.warning = Some("restoration requires explicit approval".to_owned());
    capability
}

pub(super) fn web_analytics_rum_capability() -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        "web-analytics-toggle-rum",
        "Toggle RUM on/off for a zone",
        "PATCH",
        "/zones/{zone_id}/settings/rum",
    );
    capability.mutating = true;
    capability.account_scope = "zone".to_owned();
    capability.adapter_status = AdapterStatus::DynamicApi;
    capability.product = "Web Analytics".to_owned();
    capability.risk = RiskClass::CrossConfig;
    capability.effect = EffectClass::ReversibleWrite;
    capability.permissions = vec!["Zone Settings Write".to_owned()];
    capability.cost.known = true;
    capability.cost.maximum = Some(0.0);
    capability.cost.basis = Some("no direct incremental operation charge".to_owned());
    capability.entitlement.available = Some(true);
    capability.request_schema = Some(
        serde_json::from_str(include_str!(
            "../../../../cfctl-core/tests/fixtures/web-analytics-rum-toggle-request-schema.json"
        ))
        .expect("pinned Web Analytics RUM toggle schema"),
    );
    capability.selectors = vec![SelectorV1 {
        name: "zone_id".to_owned(),
        location: "path".to_owned(),
        required: true,
        value_type: "string".to_owned(),
        description: None,
        contract: None,
    }];
    capability.verification.required = true;
    capability.verification.strategy =
        "same_path_result_contains_planned_fields_after_update".to_owned();
    capability.same_path_read = Some(SamePathReadContractV1 {
        path: "/zones/{zone_id}/settings/rum".to_owned(),
        read_capability_id: "web-analytics-get-rum-status".to_owned(),
        verified_response_fields: vec!["value".to_owned()],
    });
    capability.rollback.supported = true;
    capability.rollback.strategy = Some("restore_web_analytics_rum_prior_value".to_owned());
    capability.rollback.warning = Some("restoration requires explicit approval".to_owned());
    capability
}

pub(super) fn dns_record_update_capability(method: &str) -> CapabilityV1 {
    let id = if method == "PUT" {
        "dns-records-for-a-zone-update-dns-record"
    } else {
        "dns-records-for-a-zone-patch-dns-record"
    };
    let mut capability = CapabilityV1::new(id, "Update DNS Record", method, DNS_RECORD_DETAIL_PATH);
    capability.mutating = true;
    capability.account_scope = "zone".to_owned();
    capability.adapter_status = AdapterStatus::DynamicApi;
    capability.product = "DNS Records for a Zone".to_owned();
    capability.risk = RiskClass::ScopedWrite;
    capability.effect = EffectClass::ReversibleWrite;
    capability.permissions = vec!["DNS Write".to_owned()];
    capability.cost.known = true;
    capability.cost.maximum = Some(0.0);
    capability.request_schema = Some(
        serde_json::from_str(include_str!(
            "../../../../cfctl-core/tests/fixtures/dns-record-update-request-schema.json"
        ))
        .expect("pinned DNS record schema"),
    );
    capability.selectors = vec![
        SelectorV1 {
            name: "dns_record_id".to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: Some(SelectorContractV1 {
                schema: json!({"type":"string","maxLength":32}),
                query: None,
            }),
        },
        SelectorV1 {
            name: "zone_id".to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: Some(SelectorContractV1 {
                schema: json!({"type":"string","maxLength":32}),
                query: None,
            }),
        },
        SelectorV1 {
            name: "include_shadow_metadata".to_owned(),
            location: "query".to_owned(),
            required: false,
            value_type: "boolean".to_owned(),
            description: None,
            contract: Some(SelectorContractV1 {
                schema: json!({"type":"boolean"}),
                query: Some(QuerySerializationV1 {
                    style: "form".to_owned(),
                    explode: true,
                    allow_reserved: false,
                    allow_empty_value: false,
                }),
            }),
        },
    ];
    capability.verification.strategy = "dns_record_details_match_planned_id_and_fields".to_owned();
    capability.same_path_read = Some(SamePathReadContractV1 {
        path: DNS_RECORD_DETAIL_PATH.to_owned(),
        read_capability_id: DNS_RECORD_DETAIL_READ_CAPABILITY_ID.to_owned(),
        verified_response_fields: [
            "comment",
            "content",
            "data",
            "name",
            "priority",
            "private_routing",
            "proxied",
            "settings",
            "tags",
            "ttl",
            "type",
        ]
        .map(str::to_owned)
        .to_vec(),
    });
    capability.rollback.supported = true;
    capability.rollback.strategy = Some("restore_dns_record_prior_snapshot_with_put".to_owned());
    capability
}

#[test]
pub(super) fn dns_record_state_receipt_projects_only_the_exact_writable_type_branch() {
    let capability = dns_record_update_capability("PATCH");
    assert!(should_bind_dns_record_state(&capability));
    let response = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({
            "id":"record-a",
            "type":"TXT",
            "name":"txt.example.com",
            "content":"prior-value",
            "ttl":300,
            "proxied":false,
            "comment":null,
            "tags":[],
            "settings":{"ipv4_only":false,"future_read_only":true},
            "meta":{"auto_added":false},
            "modified_on":"future",
        }),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };

    let receipt =
        apply_dns_record_state_response(&capability, "account-a", "zone-a", "record-a", &response)
            .expect("DNS state receipt");
    assert_eq!(
        receipt["prior_record"],
        json!({
            "type":"TXT",
            "name":"txt.example.com",
            "content":"prior-value",
            "ttl":300,
            "proxied":false,
            "tags":[],
            "settings":{"ipv4_only":false},
        })
    );
    assert!(receipt["prior_record"].get("meta").is_none());

    let mut unknown = response;
    unknown.result["type"] = json!("FUTURE");
    assert!(
        apply_dns_record_state_response(&capability, "account-a", "zone-a", "record-a", &unknown,)
            .is_err()
    );
}

#[test]
pub(super) fn dns_record_state_receipt_rejects_rehashed_broadening_and_retargeting() {
    let capability = dns_record_update_capability("PATCH");
    let receipt = json!({
        "schema_version":1,
        "source_capability_id": DNS_RECORD_DETAIL_READ_CAPABILITY_ID,
        "source_path": DNS_RECORD_DETAIL_PATH,
        "target_capability_id":"dns-records-for-a-zone-patch-dns-record",
        "target_method":"PATCH",
        "target_scope":"zone",
        "account_id":"account-a",
        "zone_id":"zone-a",
        "dns_record_id":"record-a",
        "prior_record":{
            "type":"TXT",
            "name":"txt.example.com",
            "content":"prior-value",
            "ttl":300,
        },
    });
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
        json!({
            "selectors":{"zone_id":"zone-a","dns_record_id":"record-a"},
            "account_id":"account-a",
            "adapter":{},
            "live_preconditions":{"dns_record_state":receipt},
        }),
    )
    .expect("plan");
    plan.precondition_hashes.insert(
        "dns_record_state".to_owned(),
        hash_value(&receipt).expect("receipt hash"),
    );
    assert_eq!(
        required_dns_record_state_precondition(&plan).expect("bound DNS precondition"),
        plan.precondition_hashes
            .get("dns_record_state")
            .map(String::as_str)
    );

    let mut broadened = receipt.clone();
    broadened["prior_record"]["future"] = json!(true);
    plan.precondition_hashes.insert(
        "dns_record_state".to_owned(),
        hash_value(&broadened).expect("broadened hash"),
    );
    plan.targets["live_preconditions"]["dns_record_state"] = broadened;
    required_dns_record_state_precondition(&plan)
        .expect_err("a rehashed broadened snapshot must fail");

    let mut retargeted = receipt;
    retargeted["dns_record_id"] = json!("record-b");
    plan.precondition_hashes.insert(
        "dns_record_state".to_owned(),
        hash_value(&retargeted).expect("retargeted hash"),
    );
    plan.targets["live_preconditions"]["dns_record_state"] = retargeted;
    let error = required_dns_record_state_precondition(&plan)
        .expect_err("a rehashed cross-record receipt must fail");
    assert!(error.to_string().contains("account, zone, record"));
}

pub(super) fn oauth_client_secret_capability(
    id: &str,
    method: &str,
    strategy: &str,
) -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        id,
        id,
        method,
        "/accounts/{account_id}/oauth_clients/{oauth_client_id}/rotate_secret",
    );
    capability.product = "OAuth Clients".to_owned();
    capability.permissions = vec![
        "OAuth Client Write".to_owned(),
        "OAuth Client Read".to_owned(),
    ];
    capability.adapter_status = AdapterStatus::DynamicApi;
    capability.cost = CostV1::default();
    capability.entitlement.available = Some(true);
    capability.verification.strategy = strategy.to_owned();
    capability.rollback.supported = false;
    capability.rollback.warning = Some(
            "OAuth client secret cutover has no automatic rollback; preserve the old secret until dependents are verified"
                .to_owned(),
        );
    if method == "POST" {
        capability.risk = RiskClass::SecretSensitive;
        capability.effect = EffectClass::IdentityOrOwnership;
    } else {
        capability.risk = RiskClass::Destructive;
        capability.effect = EffectClass::Irreversible;
    }
    capability.selectors = ["account_id", "oauth_client_id"]
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
    capability.same_path_read = Some(SamePathReadContractV1 {
        path: "/accounts/{account_id}/oauth_clients/{oauth_client_id}".to_owned(),
        read_capability_id: "oauth-clients-get".to_owned(),
        verified_response_fields: vec!["client_id".to_owned(), "has_rotated_secret".to_owned()],
    });
    capability
}

pub(super) fn oauth_client_request_properties(
    include_visibility: bool,
) -> serde_json::Map<String, Value> {
    let mut properties = json!({
            "allowed_cors_origins":{"items":{"type":"string"},"type":"array"},
            "client_name":{"type":"string"},
            "client_uri":{"type":"string"},
            "grant_types":{"items":{"enum":["authorization_code","refresh_token"],"type":"string"},"type":"array"},
            "logo_uri":{"type":"string"},
            "policy_uri":{"type":"string"},
            "post_logout_redirect_uris":{"items":{"type":"string"},"type":"array"},
            "redirect_uris":{"items":{"type":"string"},"type":"array"},
            "response_types":{"items":{"enum":["token","id_token","code"],"type":"string"},"type":"array"},
            "scopes":{"items":{"type":"string"},"type":"array"},
            "token_endpoint_auth_method":{"enum":["none","client_secret_basic","client_secret_post"],"type":"string"},
            "tos_uri":{"type":"string"}
        })
        .as_object()
        .expect("OAuth request properties")
        .clone();
    if include_visibility {
        properties.insert(
            "visibility".to_owned(),
            json!({"enum":["public"],"type":"string"}),
        );
    }
    properties
}

pub(super) fn oauth_client_test_selectors(update: bool) -> Vec<SelectorV1> {
    let names: &[&str] = if update {
        &["account_id", "oauth_client_id"]
    } else {
        &["account_id"]
    };
    names
        .iter()
        .map(|name| SelectorV1 {
            name: (*name).to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        })
        .collect()
}

pub(super) fn oauth_client_test_request_schema(update: bool) -> Value {
    let mut schema = json!({
        "type":"object",
        "additionalProperties":false,
        "properties":oauth_client_request_properties(update),
        "x-cfctl-body-required":true,
    });
    if update {
        schema["minProperties"] = json!(1);
    } else {
        schema["required"] = json!([
            "client_name",
            "grant_types",
            "redirect_uris",
            "response_types",
            "scopes",
            "token_endpoint_auth_method"
        ]);
    }
    schema
}

pub(super) fn oauth_client_capability(update: bool) -> CapabilityV1 {
    let (id, method, path) = if update {
        (
            "oauth-clients-update",
            "PATCH",
            "/accounts/{account_id}/oauth_clients/{oauth_client_id}",
        )
    } else {
        (
            "oauth-clients-create",
            "POST",
            "/accounts/{account_id}/oauth_clients",
        )
    };
    let mut capability = CapabilityV1::new(id, id, method, path);
    capability.product = "OAuth Clients".to_owned();
    capability.permissions = vec![
        "OAuth Client Write".to_owned(),
        "OAuth Client Read".to_owned(),
    ];
    capability.adapter_status = AdapterStatus::DynamicApi;
    capability.risk = RiskClass::IdentityOrOwnership;
    capability.effect = EffectClass::IdentityOrOwnership;
    capability.cost = CostV1::default();
    capability.entitlement.available = Some(true);
    capability.entitlement.plans = BTreeMap::from([
        ("business".to_owned(), true),
        ("enterprise".to_owned(), true),
        ("free".to_owned(), true),
        ("pro".to_owned(), true),
    ]);
    capability.selectors = oauth_client_test_selectors(update);
    capability.request_schema = Some(oauth_client_test_request_schema(update));
    capability.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".to_owned()],
        success_media_types: vec!["application/json".to_owned()],
        body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
    });
    capability.verification.strategy = if update {
        "same_resource_contains_planned_fields_after_update"
    } else {
        "created_resource_contains_planned_fields_by_returned_id"
    }
    .to_owned();
    capability.rollback.supported = false;
    capability.rollback.strategy = None;
    capability.rollback.warning = Some(if update {
        "restore metadata only through a separately reviewed snapshot-bound update; public visibility promotion is permanent"
                .to_owned()
    } else {
        "OAuth client deletion requires a separately reviewed destructive plan".to_owned()
    });
    let verified_response_fields = oauth_client_request_properties(update)
        .into_iter()
        .map(|(field, _)| field)
        .collect::<Vec<_>>();
    if update {
        capability.same_path_read = Some(SamePathReadContractV1 {
            path: path.to_owned(),
            read_capability_id: "oauth-clients-get".to_owned(),
            verified_response_fields,
        });
    } else {
        capability.created_resource = Some(CreatedResourceContractV1 {
            detail_path: "/accounts/{account_id}/oauth_clients/{oauth_client_id}".to_owned(),
            identity_selector: "oauth_client_id".to_owned(),
            response_result_identity_pointer: "/client_id".to_owned(),
            read_capability_id: "oauth-clients-get".to_owned(),
            delete_capability_id: "oauth-clients-delete".to_owned(),
            verified_response_fields,
        });
    }
    capability
}

pub(super) fn oauth_client_update_response(visibility: &str) -> CloudflareResponseV1 {
    CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({
            "client_id":"oauth-client-a",
            "client_name":"old name",
            "grant_types":["authorization_code","refresh_token"],
            "redirect_uris":["https://example.com/oauth/callback"],
            "response_types":["code"],
            "scopes":["account:read"],
            "token_endpoint_auth_method":"none",
            "visibility":visibility,
            "modified_on":"future provider metadata"
        }),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    }
}

pub(super) fn oauth_client_update_input(body: Value) -> CallInput {
    CallInput {
        selectors: json!({
            "account_id":"account-a",
            "oauth_client_id":"oauth-client-a"
        }),
        body: Some(body),
        ..CallInput::default()
    }
}

#[test]
pub(super) fn oauth_client_update_snapshot_is_exact_target_bound_and_visibility_safe() {
    let capability = oauth_client_capability(true);
    assert!(should_bind_oauth_client_update_state(&capability));
    assert!(
        capability.mutation_contract_gaps().is_empty(),
        "{:?}",
        capability.mutation_contract_gaps()
    );
    let input = oauth_client_update_input(json!({"client_name":"new name"}));
    let response = oauth_client_update_response("private");
    let receipt =
        apply_oauth_client_update_state_response(&capability, &input, "account-a", &response)
            .expect("snapshot-bound OAuth update receipt");
    assert_eq!(receipt["prior_state"]["client_name"], "old name");
    assert_eq!(
        receipt["observed_result_hash"],
        hash_value(&response.result).expect("full provider result hash")
    );
    assert!(
        receipt["absent_fields"]
            .as_array()
            .is_some_and(|fields| fields.contains(&json!("client_uri")))
    );
    assert!(receipt["prior_state"].get("modified_on").is_none());

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
                OAUTH_CLIENT_UPDATE_STATE_PRECONDITION:receipt
            }
        }),
    )
    .expect("OAuth update plan");
    plan.input = serde_json::to_value(&input).expect("serialized OAuth update input");
    plan.precondition_hashes.insert(
        OAUTH_CLIENT_UPDATE_STATE_PRECONDITION.to_owned(),
        hash_value(&receipt).expect("receipt hash"),
    );
    assert_eq!(
        required_oauth_client_update_state_precondition(&plan)
            .expect("bound OAuth update precondition"),
        plan.precondition_hashes
            .get(OAUTH_CLIENT_UPDATE_STATE_PRECONDITION)
            .map(String::as_str)
    );

    let mut retargeted = receipt.clone();
    retargeted["oauth_client_id"] = json!("oauth-client-b");
    plan.precondition_hashes.insert(
        OAUTH_CLIENT_UPDATE_STATE_PRECONDITION.to_owned(),
        hash_value(&retargeted).expect("retargeted receipt hash"),
    );
    plan.targets["live_preconditions"][OAUTH_CLIENT_UPDATE_STATE_PRECONDITION] = retargeted;
    required_oauth_client_update_state_precondition(&plan)
        .expect_err("a rehashed cross-client snapshot must fail");

    let mut secret_response = response.clone();
    secret_response.result["client_secret"] = json!("must-never-persist");
    apply_oauth_client_update_state_response(&capability, &input, "account-a", &secret_response)
        .expect_err("a secret-bearing detail response must fail closed");

    let promotion = oauth_client_update_input(json!({"visibility":"public"}));
    apply_oauth_client_update_state_response(&capability, &promotion, "account-a", &response)
        .expect("private to public one-field promotion");
    let combined = oauth_client_update_input(json!({
        "visibility":"public",
        "client_name":"new name"
    }));
    apply_oauth_client_update_state_response(&capability, &combined, "account-a", &response)
        .expect_err("irreversible promotion cannot be combined with metadata changes");
    apply_oauth_client_update_state_response(
        &capability,
        &promotion,
        "account-a",
        &oauth_client_update_response("public"),
    )
    .expect_err("public OAuth clients cannot be promoted again or demoted");

    let mut response_drift = capability;
    response_drift.response_contract = None;
    assert!(!should_bind_oauth_client_update_state(&response_drift));
}

#[test]
pub(super) fn prepared_oauth_client_update_plan_carries_snapshot_and_irreversibility() {
    let root = tempfile::tempdir().expect("runtime root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let capability = oauth_client_capability(true);
    let mut catalog = CatalogSnapshot {
        schema_version: 2,
        generated_at: Utc::now(),
        source_url: "https://example.invalid/openapi.json".to_owned(),
        source_hash: "source-sha".to_owned(),
        schema_hash: String::new(),
        capabilities: BTreeMap::from([(capability.id.clone(), capability.clone())]),
    };
    catalog.refresh_hash().expect("catalog hash");
    let profile = ProfileMetadata::new("profile-a", ProfileKind::ApiToken, Some("account-a"));
    let input = oauth_client_update_input(json!({"visibility":"public"}));
    let receipt = apply_oauth_client_update_state_response(
        &capability,
        &input,
        "account-a",
        &oauth_client_update_response("private"),
    )
    .expect("OAuth update snapshot");
    let receipt_hash = hash_value(&receipt).expect("receipt hash");
    let evidence = store
        .write_evidence(EvidenceClass::LiveRead, &receipt)
        .expect("live-read evidence");
    let envelope = persist_prepared_plan(
        &store,
        &catalog,
        capability,
        input,
        PlanAuthority {
            profile: &profile,
            account_id: "account-a",
        },
        json!({}),
        LivePlanPreconditions {
            entitlement: None,
            zone_account: None,
            pages_project_absence: None,
            pages_deployment_project_state: None,
            r2_parent_token: None,
            global_warp_override_state: None,
            d1_read_replication_state: None,
            d1_empty_database_state: None,
            kv_empty_namespace_state: None,
            cloudflare_tunnel_configuration_state: None,
            warp_connector_configuration_state: None,
            web_analytics_rum_state: None,
            dns_record_state: None,
            same_path_prior_state: None,
            access_application_absence: None,
            access_operator_group_policy_ownership: None,
            security_action_state: None,
            oauth_client_secret_state: None,
            oauth_client_update_state: Some((receipt.clone(), evidence)),
            worker_custom_domain_state: None,
            worker_deployment_state: None,
        },
    )
    .expect("prepared OAuth update plan");
    let plan = &envelope.result["plan"];
    assert_eq!(
        plan["capability"]["permissions"],
        json!(["OAuth Client Write", "OAuth Client Read"])
    );
    assert_eq!(
        plan["precondition_hashes"][OAUTH_CLIENT_UPDATE_STATE_PRECONDITION],
        receipt_hash
    );
    assert_eq!(
        plan["targets"]["live_preconditions"][OAUTH_CLIENT_UPDATE_STATE_PRECONDITION],
        receipt
    );
    assert_eq!(
        plan["cloudflare_diffs"][0]["observed_before"]["visibility"],
        "private"
    );
    assert_eq!(
        plan["cloudflare_diffs"][0]["planned_after"],
        json!({"visibility":"public"})
    );
    assert_eq!(
        plan["cloudflare_diffs"][0]["irreversible_visibility_promotion"],
        true
    );
    let persisted_plan: PlanV1 =
        serde_json::from_value(plan.clone()).expect("persisted OAuth update plan");
    validate_plan_preconditions(&store, &persisted_plan)
        .expect("live OAuth snapshot is re-read by its dedicated execution precondition");
}

#[test]
pub(super) fn oauth_client_update_snapshot_routes_through_live_credential_resolution() {
    let capability = oauth_client_capability(true);

    let (resolved, _) = resolve_actionable(
        &capability,
        "promote the exact OAuth client",
        Some("account-a"),
    );
    assert_eq!(
        resolved["permission_lane"],
        json!(["OAuth Client Write", "OAuth Client Read"])
    );

    assert!(
        should_bind_oauth_client_update_state(&capability),
        "the governed update requires a hash-bound live snapshot"
    );
    assert!(
        plan_requires_live_credential(&capability, &json!({})),
        "planning must resolve a credential before preparing the OAuth snapshot"
    );

    let mut missing_read = capability;
    missing_read.permissions = vec!["OAuth Client Write".to_owned()];
    assert!(!should_bind_oauth_client_update_state(&missing_read));
}

#[cfg(unix)]
pub(super) fn oauth_client_create_test_plan(sink: &Path) -> (CapabilityV1, PlanV1) {
    let capability = oauth_client_capability(false);
    let input = CallInput {
        selectors: json!({"account_id":"account-a"}),
        body: Some(json!({
            "client_name":"cfctl",
            "grant_types":["authorization_code","refresh_token"],
            "redirect_uris":["https://cfctl.com/oauth/callback"],
            "response_types":["code"],
            "scopes":["account:read"],
            "token_endpoint_auth_method":"none"
        })),
        ..CallInput::default()
    };
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability.clone(),
        json!({
            "selectors":input.selectors,
            "account_id":"account-a",
            "adapter":{"value_out":sink}
        }),
    )
    .expect("OAuth create plan");
    plan.input = serde_json::to_value(&input).expect("serialized OAuth create input");
    (capability, plan)
}

#[cfg(unix)]
#[test]
pub(super) fn oauth_client_creation_secret_sink_is_conditional_private_and_redacted() {
    let root = tempfile::tempdir().expect("operator-secret root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
        .expect("mode-0700 operator-secret root");
    let sink = root.path().join("oauth-client.json");
    let (capability, mut plan) = oauth_client_create_test_plan(&sink);
    assert_eq!(
        capability.permissions,
        ["OAuth Client Write", "OAuth Client Read"]
    );
    assert!(is_secret_output_capability(&capability));
    assert!(should_redact_secret_response(&capability));
    assert_eq!(secret_sink_format(&capability), Some("oauth_client_json"));
    preflight_secret_sink(&plan).expect("fresh external OAuth secret sink");

    let public_result = json!({"client_id":"oauth-client-a"});
    assert_eq!(
        super::oauth_client_secret_output_state(&plan, true, Some(&public_result))
            .expect("public-client secret state"),
        (false, Some(false))
    );
    assert!(
        !sink.exists(),
        "an omitted optional secret must not create an empty sink"
    );
    let no_secret_artifact =
        secret_sink_artifact(&plan, None, false, true, false, Some(false), None);
    assert_eq!(no_secret_artifact["secret_returned"], false);
    assert_eq!(no_secret_artifact["output_sink"]["requested"], true);
    assert_eq!(no_secret_artifact["output_sink"]["required"], false);
    assert!(no_secret_artifact["path"].is_null());

    let secret_result = json!({
        "client_id":"oauth-client-a",
        "client_secret":"one-time-secret"
    });
    assert_eq!(
        super::oauth_client_secret_output_state(&plan, true, Some(&secret_result))
            .expect("returned-secret state"),
        (true, Some(true))
    );
    let written = sink_secret_result(&plan, &secret_result).expect("OAuth secret sink");
    assert_eq!(written, sink);
    assert_eq!(
        fs::metadata(&written)
            .expect("sink metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(&written).expect("sink bytes"))
            .expect("OAuth sink JSON"),
        secret_result
    );
    let redacted = redact_response_for_capability(
        &capability,
        &json!({"success":true,"result":secret_result}),
    );
    assert_eq!(redacted["result"]["client_id"], "oauth-client-a");
    assert_eq!(redacted["result"]["client_secret"], "[SUNK]");
    assert!(!redacted.to_string().contains("one-time-secret"));

    let repo = root.path().join("repo");
    fs::create_dir_all(repo.join(".git")).expect("test Git marker");
    let repo_secret_dir = repo.join("operator-secrets");
    fs::create_dir(&repo_secret_dir).expect("repo secret directory");
    fs::set_permissions(&repo_secret_dir, fs::Permissions::from_mode(0o700))
        .expect("repo secret mode");
    plan.targets["adapter"]["value_out"] = json!(repo_secret_dir.join("client.json"));
    preflight_secret_sink(&plan).expect_err("OAuth secret output inside Git must fail");

    let basic_sink = root.path().join("oauth-client-basic.json");
    plan.targets["adapter"]["value_out"] = json!(basic_sink);
    plan.input["body"]["token_endpoint_auth_method"] = json!("client_secret_basic");
    assert_eq!(
        super::oauth_client_secret_output_state(&plan, true, Some(&public_result))
            .expect("secret-authenticated client state"),
        (true, Some(false))
    );
    sink_secret_result(&plan, &public_result)
        .expect_err("missing required OAuth secret must require rectification");
    assert!(!basic_sink.exists());

    let mut risk_drift = capability;
    risk_drift.risk = RiskClass::ScopedWrite;
    assert!(is_secret_output_capability(&risk_drift));
    assert!(should_redact_secret_response(&risk_drift));
}

pub(super) fn oauth_client_secret_state_response(has_rotated_secret: bool) -> CloudflareResponseV1 {
    CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({
            "client_id":"oauth-client-a",
            "has_rotated_secret":has_rotated_secret,
        }),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    }
}

#[test]
pub(super) fn oauth_client_secret_state_precondition_is_phase_specific_and_target_bound() {
    let rotate = oauth_client_secret_capability(
        "oauth-clients-rotate-secret",
        "POST",
        "oauth_client_reports_rotated_secret_after_value_roll",
    );
    let delete_old = oauth_client_secret_capability(
        "oauth-clients-delete-rotated-secret",
        "DELETE",
        "oauth_client_reports_no_rotated_secret_after_old_secret_delete",
    );
    assert!(should_bind_oauth_client_secret_state(&rotate));
    assert!(should_bind_oauth_client_secret_state(&delete_old));
    let guide = guide_json(&rotate);
    assert_eq!(guide["stages"][4]["contract_state"], "live_read_required");
    assert_eq!(
        guide["stages"][4]["commands"][0],
        json!([
            "cfctl",
            "call",
            "oauth-clients-get",
            "--selector",
            "account_id=<account_id>",
            "--selector",
            "oauth_client_id=<oauth_client_id>",
            "--json"
        ])
    );
    let rotate_receipt = apply_oauth_client_secret_state_response(
        &rotate,
        "account-a",
        "oauth-client-a",
        &oauth_client_secret_state_response(false),
    )
    .expect("one-secret state permits rotation planning");
    assert_eq!(rotate_receipt["key_overlap_active"], false);
    apply_oauth_client_secret_state_response(
        &rotate,
        "account-a",
        "oauth-client-a",
        &oauth_client_secret_state_response(true),
    )
    .expect_err("a second rotation must be refused while two secrets exist");

    let delete_receipt = apply_oauth_client_secret_state_response(
        &delete_old,
        "account-a",
        "oauth-client-a",
        &oauth_client_secret_state_response(true),
    )
    .expect("two-secret state permits old-secret deletion planning");
    assert_eq!(delete_receipt["key_overlap_active"], true);
    apply_oauth_client_secret_state_response(
        &delete_old,
        "account-a",
        "oauth-client-a",
        &oauth_client_secret_state_response(false),
    )
    .expect_err("old-secret deletion must be refused without two secrets");

    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        delete_old,
        json!({
            "selectors":{
                "account_id":"account-a",
                "oauth_client_id":"oauth-client-a"
            },
            "account_id":"account-a",
            "adapter":{},
            "live_preconditions":{"oauth_client_key_overlap":delete_receipt},
        }),
    )
    .expect("plan");
    plan.precondition_hashes.insert(
        "oauth_client_key_overlap".to_owned(),
        hash_value(&delete_receipt).expect("receipt hash"),
    );
    assert!(
        required_oauth_client_secret_state_precondition(&plan)
            .expect("bound OAuth precondition")
            .is_some()
    );

    let mut retargeted = delete_receipt;
    retargeted["oauth_client_id"] = json!("oauth-client-b");
    plan.precondition_hashes.insert(
        "oauth_client_key_overlap".to_owned(),
        hash_value(&retargeted).expect("retargeted receipt hash"),
    );
    plan.targets["live_preconditions"]["oauth_client_key_overlap"] = retargeted;
    required_oauth_client_secret_state_precondition(&plan)
        .expect_err("a rehashed cross-client receipt must fail");
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the regression keeps the full sink-only two-secret plan and its execution-time live-precondition routing in one lifecycle proof"
)]
pub(super) fn prepared_oauth_client_rotation_plan_carries_exact_two_secret_transition() {
    let root = tempfile::tempdir().expect("runtime root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let capability = oauth_client_secret_capability(
        "oauth-clients-rotate-secret",
        "POST",
        "oauth_client_reports_rotated_secret_after_value_roll",
    );
    assert!(
        capability.mutation_contract_gaps().is_empty(),
        "{:?}",
        capability.mutation_contract_gaps()
    );
    let mut catalog = CatalogSnapshot {
        schema_version: 1,
        generated_at: Utc::now(),
        source_url: "https://example.invalid/openapi.json".to_owned(),
        source_hash: "source-sha".to_owned(),
        schema_hash: String::new(),
        capabilities: BTreeMap::from([(capability.id.clone(), capability.clone())]),
    };
    catalog.refresh_hash().expect("catalog hash");
    let profile = ProfileMetadata::new("profile-a", ProfileKind::ApiToken, Some("account-a"));
    let input = CallInput {
        selectors: json!({
            "account_id":"account-a",
            "oauth_client_id":"oauth-client-a"
        }),
        ..CallInput::default()
    };
    let response = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({
            "client_id":"oauth-client-a",
            "has_rotated_secret":false,
        }),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let receipt = apply_oauth_client_secret_state_response(
        &capability,
        "account-a",
        "oauth-client-a",
        &response,
    )
    .expect("OAuth state receipt");
    let receipt_hash = hash_value(&receipt).expect("receipt hash");
    let evidence = store
        .write_evidence(EvidenceClass::LiveRead, &receipt)
        .expect("live read evidence");
    let sink = root.path().join("oauth-client-secret");

    let envelope = persist_prepared_plan(
        &store,
        &catalog,
        capability,
        input,
        PlanAuthority {
            profile: &profile,
            account_id: "account-a",
        },
        json!({"value_out":sink}),
        LivePlanPreconditions {
            entitlement: None,
            zone_account: None,
            pages_project_absence: None,
            pages_deployment_project_state: None,
            r2_parent_token: None,
            global_warp_override_state: None,
            d1_read_replication_state: None,
            d1_empty_database_state: None,
            kv_empty_namespace_state: None,
            cloudflare_tunnel_configuration_state: None,
            warp_connector_configuration_state: None,
            web_analytics_rum_state: None,
            dns_record_state: None,
            same_path_prior_state: None,
            access_application_absence: None,
            access_operator_group_policy_ownership: None,
            security_action_state: None,
            oauth_client_secret_state: Some((receipt.clone(), evidence)),
            oauth_client_update_state: None,
            worker_custom_domain_state: None,
            worker_deployment_state: None,
        },
    )
    .expect("prepared OAuth rotation plan");
    let plan = &envelope.result["plan"];

    assert_eq!(
        plan["precondition_hashes"][OAUTH_CLIENT_KEY_OVERLAP_PRECONDITION],
        receipt_hash
    );
    assert_eq!(
        plan["targets"]["live_preconditions"][OAUTH_CLIENT_KEY_OVERLAP_PRECONDITION],
        receipt
    );
    assert_eq!(
        plan["cloudflare_diffs"][0]["observed_before"],
        json!({"key_overlap_active":false})
    );
    assert_eq!(
        plan["cloudflare_diffs"][0]["planned_after"],
        json!({"key_overlap_active":true})
    );
    let persisted_plan: PlanV1 =
        serde_json::from_value(plan.clone()).expect("persisted OAuth rotation plan");
    validate_plan_preconditions(&store, &persisted_plan)
        .expect("live OAuth key-overlap state is re-read by its dedicated execution precondition");
}
