use super::*;

#[test]
pub(super) fn d1_state_receipt_binds_only_the_exact_database_mode() {
    let capability = d1_read_replication_update_capability();
    assert!(should_bind_d1_read_replication_state(&capability));
    let response = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({
            "uuid": "database-a",
            "read_replication": {
                "mode": "disabled",
                "ignored_future_field": true,
            },
        }),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };

    let receipt =
        apply_d1_read_replication_state_response(&capability, "account-a", "database-a", &response)
            .expect("D1 state receipt");
    assert_eq!(
        receipt,
        json!({
            "schema_version": 1,
            "source_capability_id": "d1-get-database",
            "source_path": "/accounts/{account_id}/d1/database/{database_id}",
            "target_capability_id": "d1-update-partial-database",
            "target_method": "PATCH",
            "target_scope": "account",
            "account_id": "account-a",
            "database_id": "database-a",
            "read_replication": {"mode":"disabled"},
        })
    );

    let mut drifted = response;
    drifted.result["read_replication"]["mode"] = json!("experimental");
    let error =
        apply_d1_read_replication_state_response(&capability, "account-a", "database-a", &drifted)
            .expect_err("unknown modes fail closed");
    assert!(error.to_string().contains("bounded read_replication.mode"));
}

#[test]
pub(super) fn d1_state_receipt_rejects_rehashed_cross_database_targets() {
    let capability = d1_read_replication_update_capability();
    let receipt = json!({
        "schema_version": 1,
        "source_capability_id": "d1-get-database",
        "source_path": "/accounts/{account_id}/d1/database/{database_id}",
        "target_capability_id": "d1-update-partial-database",
        "target_method": "PATCH",
        "target_scope": "account",
        "account_id": "account-a",
        "database_id": "database-a",
        "read_replication": {"mode":"disabled"},
    });
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
        json!({
            "selectors":{"account_id":"account-a","database_id":"database-a"},
            "account_id":"account-a",
            "adapter":{},
            "live_preconditions":{"d1_read_replication_state":receipt},
        }),
    )
    .expect("plan");
    plan.precondition_hashes.insert(
        "d1_read_replication_state".to_owned(),
        hash_value(&receipt).expect("receipt hash"),
    );
    assert_eq!(
        required_d1_read_replication_state_precondition(&plan).expect("bound precondition"),
        plan.precondition_hashes
            .get("d1_read_replication_state")
            .map(String::as_str)
    );

    let mut broadened = receipt.clone();
    broadened["read_replication"]["future"] = json!(true);
    plan.precondition_hashes.insert(
        "d1_read_replication_state".to_owned(),
        hash_value(&broadened).expect("broadened receipt hash"),
    );
    plan.targets["live_preconditions"]["d1_read_replication_state"] = broadened;
    required_d1_read_replication_state_precondition(&plan)
        .expect_err("a rehashed broadened state object must still fail");

    let mut retargeted = receipt;
    retargeted["database_id"] = json!("database-b");
    plan.precondition_hashes.insert(
        "d1_read_replication_state".to_owned(),
        hash_value(&retargeted).expect("retargeted receipt hash"),
    );
    plan.targets["live_preconditions"]["d1_read_replication_state"] = retargeted;
    let error = required_d1_read_replication_state_precondition(&plan)
        .expect_err("a rehashed cross-database receipt must still fail");
    assert!(error.to_string().contains("invalid account, database"));
}

#[test]
pub(super) fn cloudflare_tunnel_configuration_receipt_binds_only_restorable_routing_state() {
    let capability = cloudflare_tunnel_configuration_capability();
    assert!(should_bind_cloudflare_tunnel_configuration_state(
        &capability
    ));
    let response = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({
            "config": {
                "ingress": [
                    {"hostname":"app.example.com","service":"http://localhost:8080"},
                    {"hostname":"","service":"http_status:404"}
                ]
            },
            "version": 17,
        }),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };

    let receipt = apply_cloudflare_tunnel_configuration_state_response(
        &capability,
        "account-a",
        "tunnel-a",
        &response,
    )
    .expect("Tunnel configuration receipt");
    assert_eq!(
        receipt,
        json!({
            "schema_version": 1,
            "source_capability_id": "cloudflare-tunnel-configuration-get-configuration",
            "source_path": "/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations",
            "target_capability_id": "cloudflare-tunnel-configuration-put-configuration",
            "target_method": "PUT",
            "target_path": "/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations",
            "target_scope": "account",
            "account_id": "account-a",
            "tunnel_id": "tunnel-a",
            "prior_config": {
                "ingress": [
                    {"hostname":"app.example.com","service":"http://localhost:8080"},
                    {"hostname":"","service":"http_status:404"}
                ]
            },
        })
    );

    let mut unsupported = response;
    unsupported.result["config"]["future_routing_control"] = json!(true);
    let error = apply_cloudflare_tunnel_configuration_state_response(
        &capability,
        "account-a",
        "tunnel-a",
        &unsupported,
    )
    .expect_err("unrestorable future fields fail closed");
    assert!(error.to_string().contains("restorable request contract"));
}

#[test]
pub(super) fn cloudflare_tunnel_configuration_preflight_requires_one_final_catch_all_rule() {
    let capability = cloudflare_tunnel_configuration_capability();
    let valid = CallInput {
        selectors: json!({"account_id":"account-a","tunnel_id":"tunnel-a"}),
        body: Some(json!({"config":{"ingress":[
            {"hostname":"app.example.com","service":"http://localhost:8080"},
            {"hostname":"","service":"http_status:404"}
        ]}})),
        ..CallInput::default()
    };
    preflight_call_input(&capability, &valid, None).expect("final catch-all is valid");

    let mut missing = valid.clone();
    missing.body.as_mut().expect("body")["config"]["ingress"][1]["hostname"] =
        json!("other.example.com");
    let error = preflight_call_input(&capability, &missing, None)
        .expect_err("a named final rule does not match all traffic");
    assert!(error.to_string().contains("final catch-all"));

    let mut unreachable = valid;
    unreachable.body.as_mut().expect("body")["config"]["ingress"] = json!([
        {"hostname":"","service":"http_status:404"},
        {"hostname":"app.example.com","service":"http://localhost:8080"},
        {"hostname":"","service":"http_status:404"}
    ]);
    let error = preflight_call_input(&capability, &unreachable, None)
        .expect_err("an earlier catch-all makes later rules unreachable");
    assert!(error.to_string().contains("rule 1"));
    assert!(error.to_string().contains("unreachable"));
}

#[test]
pub(super) fn d1_database_create_preflight_rejects_ignored_location_hint_combinations() {
    let mut capability = CapabilityV1::new(
        "d1-create-database",
        "Create D1 Database",
        "POST",
        "/accounts/{account_id}/d1/database",
    );
    capability.request_schema = Some(json!({
        "type":"object",
        "required":["name"],
        "properties":{
            "name":{"type":"string"},
            "jurisdiction":{"type":"string","enum":["eu","fedramp"]},
            "primary_location_hint":{"type":"string","enum":["wnam","enam"]}
        }
    }));
    let input = CallInput {
        selectors: json!({"account_id":"account-a"}),
        body: Some(json!({
            "name":"smoke-database",
            "jurisdiction":"eu",
            "primary_location_hint":"enam"
        })),
        ..CallInput::default()
    };
    let error = preflight_call_input(&capability, &input, None)
        .expect_err("Cloudflare ignores the location hint when jurisdiction is set");
    assert!(
        error.to_string().contains("gives jurisdiction precedence"),
        "{error}"
    );

    let mut location_only = input;
    location_only
        .body
        .as_mut()
        .and_then(Value::as_object_mut)
        .expect("D1 body")
        .remove("jurisdiction");
    preflight_call_input(&capability, &location_only, None)
        .expect("a location hint without jurisdiction is unambiguous");
}

#[test]
pub(super) fn d1_empty_database_compensation_binds_exact_live_state_and_rejects_tables() {
    let capability = d1_database_delete_capability();
    let adapter = json!({
        "compensates_operation_id":"source-create-op",
        "compensates_capability_id":"d1-create-database",
        "compensation_strategy":"delete_created_empty_d1_database_by_returned_uuid_if_unchanged",
        "source_receipt_hash":"sha256:source-create-receipt"
    });
    let response = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({
            "uuid":"database-a",
            "name":"smoke-database",
            "num_tables":0,
            "file_size":12288,
            "jurisdiction":"eu",
            "read_replication":{"mode":"disabled"}
        }),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let receipt = apply_d1_empty_database_state_response(
        &capability,
        &adapter,
        "account-a",
        "database-a",
        &response,
    )
    .expect("empty database receipt");
    assert_eq!(receipt["num_tables"], 0);
    assert_eq!(receipt["database_id"], "database-a");
    assert_eq!(
        receipt["source_create_receipt_hash"],
        "sha256:source-create-receipt"
    );

    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability.clone(),
        json!({
            "selectors":{"account_id":"account-a","database_id":"database-a"},
            "account_id":"account-a",
            "adapter":adapter,
            "live_preconditions":{"d1_empty_database_state":receipt.clone()}
        }),
    )
    .expect("D1 compensation plan");
    plan.precondition_hashes.insert(
        "d1_empty_database_state".to_owned(),
        hash_value(&receipt).expect("receipt hash"),
    );
    assert_eq!(
        required_d1_empty_database_state_precondition(&plan)
            .expect("bound empty-state precondition"),
        plan.precondition_hashes
            .get("d1_empty_database_state")
            .map(String::as_str)
    );

    let mut retargeted = receipt;
    retargeted["database_id"] = json!("database-b");
    plan.precondition_hashes.insert(
        "d1_empty_database_state".to_owned(),
        hash_value(&retargeted).expect("retargeted receipt hash"),
    );
    plan.targets["live_preconditions"]["d1_empty_database_state"] = retargeted;
    let error = required_d1_empty_database_state_precondition(&plan)
        .expect_err("a rehashed cross-database receipt must fail");
    assert!(error.to_string().contains("account, database, table count"));

    let mut populated = response;
    populated.result["num_tables"] = json!(1);
    let error = apply_d1_empty_database_state_response(
        &capability,
        &plan.targets["adapter"],
        "account-a",
        "database-a",
        &populated,
    )
    .expect_err("a populated database must never become a compensation delete plan");
    assert!(error.to_string().contains("contains 1 table"));
}

#[test]
pub(super) fn cloudflare_tunnel_configuration_state_rejects_rehashed_cross_tunnel_targets() {
    let capability = cloudflare_tunnel_configuration_capability();
    let receipt = json!({
        "schema_version": 1,
        "source_capability_id": "cloudflare-tunnel-configuration-get-configuration",
        "source_path": "/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations",
        "target_capability_id": "cloudflare-tunnel-configuration-put-configuration",
        "target_method": "PUT",
        "target_path": "/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations",
        "target_scope": "account",
        "account_id": "account-a",
        "tunnel_id": "tunnel-a",
        "prior_config": {"ingress":[{"hostname":"","service":"http_status:404"}]},
    });
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
        json!({
            "selectors":{"account_id":"account-a","tunnel_id":"tunnel-a"},
            "account_id":"account-a",
            "adapter":{},
            "live_preconditions":{"cloudflare_tunnel_configuration_state":receipt},
        }),
    )
    .expect("plan");
    plan.precondition_hashes.insert(
        "cloudflare_tunnel_configuration_state".to_owned(),
        hash_value(&receipt).expect("receipt hash"),
    );
    assert_eq!(
        required_cloudflare_tunnel_configuration_state_precondition(&plan)
            .expect("bound precondition"),
        plan.precondition_hashes
            .get("cloudflare_tunnel_configuration_state")
            .map(String::as_str)
    );

    let mut retargeted = receipt;
    retargeted["tunnel_id"] = json!("tunnel-b");
    plan.precondition_hashes.insert(
        "cloudflare_tunnel_configuration_state".to_owned(),
        hash_value(&retargeted).expect("retargeted receipt hash"),
    );
    plan.targets["live_preconditions"]["cloudflare_tunnel_configuration_state"] = retargeted;
    let error = required_cloudflare_tunnel_configuration_state_precondition(&plan)
        .expect_err("a rehashed cross-Tunnel receipt must still fail");
    assert!(error.to_string().contains("account, Tunnel"));
}

#[test]
pub(super) fn warp_connector_configuration_preflight_binds_mode_to_exact_provider_state() {
    let capability = warp_connector_configuration_capability();
    assert!(should_bind_warp_connector_configuration_state(&capability));
    for body in [
        json!({"ha_mode":"none"}),
        json!({"ha_mode":"disabled","config":{}}),
        json!({"ha_mode":"aws","config":{"fnr_id":"eni-secondary-a"}}),
        json!({
            "ha_mode":"local",
            "config":{
                "vips":[{"address":"192.0.2.10"},{"address":"2001:db8::10"}],
                "vips_previous":[{"address":"192.0.2.9"}]
            }
        }),
    ] {
        preflight_call_input(
            &capability,
            &CallInput {
                selectors: json!({"account_id":"account-a","tunnel_id":"tunnel-a"}),
                body: Some(body),
                ..CallInput::default()
            },
            None,
        )
        .expect("valid HA provider contract");
    }

    for (body, expected) in [
        (
            json!({"ha_mode":"none","config":{"fnr_id":"eni-a"}}),
            "requires `config` to be omitted",
        ),
        (
            json!({"ha_mode":"aws","config":{"fnr_id":""}}),
            "non-empty `config.fnr_id`",
        ),
        (
            json!({"ha_mode":"local","config":{"vips":[{"address":"not-an-ip"}]}}),
            "not a valid IPv4 or IPv6 address",
        ),
        (
            json!({
                "ha_mode":"local",
                "config":{
                    "vips":[{"address":"192.0.2.10"}],
                    "vips_previous":[{"address":"192.0.2.10"}]
                }
            }),
            "duplicated across",
        ),
        (
            json!({
                "ha_mode":"local",
                "config":{
                    "vips":[{"address":"2001:db8::1"}],
                    "vips_previous":[{"address":"2001:0db8:0:0:0:0:0:1"}]
                }
            }),
            "duplicated across",
        ),
    ] {
        let error = preflight_call_input(
            &capability,
            &CallInput {
                selectors: json!({"account_id":"account-a","tunnel_id":"tunnel-a"}),
                body: Some(body),
                ..CallInput::default()
            },
            None,
        )
        .expect_err("invalid HA provider contract must fail closed");
        assert!(error.to_string().contains(expected), "{error}");
    }
}

#[test]
pub(super) fn warp_connector_state_receipt_binds_only_restorable_mesh_ha_state() {
    let capability = warp_connector_configuration_capability();
    let response = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({
            "ha_mode":"local",
            "config":{"vips":[{"address":"192.0.2.10"}]},
            "version":7,
            "tunnel_id":"tunnel-a",
            "future_read_only":"ignored"
        }),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let receipt = apply_warp_connector_configuration_state_response(
        &capability,
        "account-a",
        "tunnel-a",
        &response,
    )
    .expect("WARP Connector state receipt");
    assert_eq!(
        receipt,
        json!({
            "schema_version":1,
            "source_capability_id":"cloudflare-tunnel-configuration-get-warp-connector-configuration",
            "source_path":"/accounts/{account_id}/warp_connector/{tunnel_id}/configurations",
            "target_capability_id":"cloudflare-tunnel-configuration-update-warp-connector-configuration",
            "target_method":"PUT",
            "target_path":"/accounts/{account_id}/warp_connector/{tunnel_id}/configurations",
            "target_scope":"account",
            "account_id":"account-a",
            "tunnel_id":"tunnel-a",
            "prior_ha_mode":"local",
            "prior_config":{"vips":[{"address":"192.0.2.10"}]},
        })
    );

    let mut unsupported = response;
    unsupported.result["config"]["vips"][0]["address"] = json!("invalid");
    let error = apply_warp_connector_configuration_state_response(
        &capability,
        "account-a",
        "tunnel-a",
        &unsupported,
    )
    .expect_err("unrestorable live state fails closed");
    assert!(error.to_string().contains("restorable HA contract"));

    unsupported.result = json!({
        "ha_mode":"disabled",
        "config":{"fnr_id":"stale-provider-state"}
    });
    let error = apply_warp_connector_configuration_state_response(
        &capability,
        "account-a",
        "tunnel-a",
        &unsupported,
    )
    .expect_err("disabled state with provider config cannot be restored exactly");
    assert!(error.to_string().contains("restorable HA contract"));
}

#[test]
pub(super) fn warp_connector_state_rejects_rehashed_cross_tunnel_targets() {
    let capability = warp_connector_configuration_capability();
    let receipt = json!({
        "schema_version":1,
        "source_capability_id":"cloudflare-tunnel-configuration-get-warp-connector-configuration",
        "source_path":"/accounts/{account_id}/warp_connector/{tunnel_id}/configurations",
        "target_capability_id":"cloudflare-tunnel-configuration-update-warp-connector-configuration",
        "target_method":"PUT",
        "target_path":"/accounts/{account_id}/warp_connector/{tunnel_id}/configurations",
        "target_scope":"account",
        "account_id":"account-a",
        "tunnel_id":"tunnel-a",
        "prior_ha_mode":"disabled",
        "prior_config":null,
    });
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
        json!({
            "selectors":{"account_id":"account-a","tunnel_id":"tunnel-a"},
            "account_id":"account-a",
            "adapter":{},
            "live_preconditions":{"warp_connector_configuration_state":receipt},
        }),
    )
    .expect("plan");
    plan.precondition_hashes.insert(
        "warp_connector_configuration_state".to_owned(),
        hash_value(&receipt).expect("receipt hash"),
    );
    assert_eq!(
        required_warp_connector_configuration_state_precondition(&plan)
            .expect("bound precondition"),
        plan.precondition_hashes
            .get("warp_connector_configuration_state")
            .map(String::as_str)
    );

    let mut retargeted = receipt;
    retargeted["tunnel_id"] = json!("tunnel-b");
    plan.precondition_hashes.insert(
        "warp_connector_configuration_state".to_owned(),
        hash_value(&retargeted).expect("retargeted receipt hash"),
    );
    plan.targets["live_preconditions"]["warp_connector_configuration_state"] = retargeted;
    let error = required_warp_connector_configuration_state_precondition(&plan)
        .expect_err("a rehashed cross-Tunnel receipt must still fail");
    assert!(error.to_string().contains("account, Tunnel"));
}

#[test]
pub(super) fn web_analytics_rum_state_receipt_binds_only_editable_on_off_state() {
    let capability = web_analytics_rum_capability();
    assert!(should_bind_web_analytics_rum_state(&capability));
    let response = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({
            "id":"rum",
            "editable":true,
            "value":"off",
            "modified_on":"2026-07-15T12:00:00Z",
            "future_read_only":"ignored"
        }),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let receipt =
        apply_web_analytics_rum_state_response(&capability, "account-a", "zone-a", &response)
            .expect("Web Analytics RUM state receipt");
    assert_eq!(
        receipt,
        json!({
            "schema_version":1,
            "source_capability_id":"web-analytics-get-rum-status",
            "source_path":"/zones/{zone_id}/settings/rum",
            "target_capability_id":"web-analytics-toggle-rum",
            "target_method":"PATCH",
            "target_path":"/zones/{zone_id}/settings/rum",
            "target_scope":"zone",
            "account_id":"account-a",
            "zone_id":"zone-a",
            "setting_id":"rum",
            "editable":true,
            "prior_value":"off",
        })
    );

    for (result, expected) in [
        (
            json!({"id":"rum","editable":true,"value":"manual"}),
            "restorable",
        ),
        (
            json!({"id":"rum","editable":false,"value":"off"}),
            "editable",
        ),
        (
            json!({"id":"other","editable":true,"value":"off"}),
            "identify setting",
        ),
    ] {
        let mut invalid = response.clone();
        invalid.result = result;
        let error =
            apply_web_analytics_rum_state_response(&capability, "account-a", "zone-a", &invalid)
                .expect_err("unrestorable RUM state must fail closed");
        assert!(error.to_string().contains(expected), "{error}");
    }
}

#[test]
pub(super) fn web_analytics_rum_preflight_allows_only_exact_on_off_requests() {
    let capability = web_analytics_rum_capability();
    for value in ["on", "off"] {
        preflight_call_input(
            &capability,
            &CallInput {
                selectors: json!({"zone_id":"zone-a"}),
                body: Some(json!({"value":value})),
                ..CallInput::default()
            },
            None,
        )
        .expect("exact RUM value is accepted");
    }
    for body in [
        json!({"value":"manual"}),
        json!({"value":"on","future":true}),
        json!({}),
    ] {
        let error = preflight_call_input(
            &capability,
            &CallInput {
                selectors: json!({"zone_id":"zone-a"}),
                body: Some(body),
                ..CallInput::default()
            },
            None,
        )
        .expect_err("unsupported RUM request must fail closed");
        assert!(
            error.to_string().contains("request body") || error.to_string().contains("schema"),
            "{error}"
        );
    }
}

#[test]
pub(super) fn web_analytics_rum_state_rejects_rehashed_cross_zone_targets() {
    let capability = web_analytics_rum_capability();
    let receipt = json!({
        "schema_version":1,
        "source_capability_id":"web-analytics-get-rum-status",
        "source_path":"/zones/{zone_id}/settings/rum",
        "target_capability_id":"web-analytics-toggle-rum",
        "target_method":"PATCH",
        "target_path":"/zones/{zone_id}/settings/rum",
        "target_scope":"zone",
        "account_id":"account-a",
        "zone_id":"zone-a",
        "setting_id":"rum",
        "editable":true,
        "prior_value":"off",
    });
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
        json!({
            "selectors":{"zone_id":"zone-a"},
            "account_id":"account-a",
            "adapter":{},
            "live_preconditions":{"web_analytics_rum_state":receipt},
        }),
    )
    .expect("plan");
    plan.precondition_hashes.insert(
        "web_analytics_rum_state".to_owned(),
        hash_value(&receipt).expect("receipt hash"),
    );
    assert_eq!(
        required_web_analytics_rum_state_precondition(&plan).expect("bound precondition"),
        plan.precondition_hashes
            .get("web_analytics_rum_state")
            .map(String::as_str)
    );

    let mut retargeted = receipt;
    retargeted["zone_id"] = json!("zone-b");
    plan.precondition_hashes.insert(
        "web_analytics_rum_state".to_owned(),
        hash_value(&retargeted).expect("retargeted receipt hash"),
    );
    plan.targets["live_preconditions"]["web_analytics_rum_state"] = retargeted;
    let error = required_web_analytics_rum_state_precondition(&plan)
        .expect_err("a rehashed cross-zone receipt must still fail");
    assert!(error.to_string().contains("account, zone"));
}

#[test]
pub(super) fn global_warp_override_state_receipt_binds_only_the_exact_account_state() {
    let response = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({
            "disconnect": false,
            "timestamp": "2026-07-15T12:00:00Z",
            "ignored_future_field": "does-not-enter-the-receipt",
        }),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };

    let receipt = apply_global_warp_override_state_response("account-a", &response)
        .expect("global WARP state receipt");
    assert_eq!(
        receipt,
        json!({
            "schema_version": 1,
            "source_capability_id": "devices-resilience-retrieve-global-warp-override",
            "source_path": "/accounts/{account_id}/devices/resilience/disconnect",
            "target_capability_id": "devices-resilience-set-global-warp-override",
            "target_scope": "account",
            "target_id": "account-a",
            "disconnect": false,
        })
    );

    let expected_hash = hash_value(&receipt).expect("receipt hash");
    validate_global_warp_override_state_receipt_precondition(&expected_hash, &receipt)
        .expect("unchanged state");
    let mut drifted = receipt;
    drifted["disconnect"] = json!(true);
    let error = validate_global_warp_override_state_receipt_precondition(&expected_hash, &drifted)
        .expect_err("changed state must fail before the write boundary");
    assert!(error.to_string().contains("drifted after planning"));
    assert!(
        error
            .to_string()
            .contains("mutation boundary was not crossed")
    );
}

#[test]
pub(super) fn global_warp_override_state_receipt_rejects_failed_or_ambiguous_reads() {
    let response = |status, success, result| CloudflareResponseV1 {
        status,
        success,
        result,
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let failed = apply_global_warp_override_state_response(
        "account-a",
        &response(403, false, json!({"disconnect": false})),
    )
    .expect_err("failed read");
    assert!(failed.to_string().contains("HTTP 403"));
    let omitted = apply_global_warp_override_state_response(
        "account-a",
        &response(200, true, json!({"timestamp": "now"})),
    )
    .expect_err("missing state");
    assert!(omitted.to_string().contains("omitted boolean `disconnect`"));
}

#[test]
pub(super) fn executable_global_warp_override_plan_requires_its_bound_prior_state() {
    let capability = global_warp_override_capability();
    assert!(should_bind_global_warp_override_state(&capability));
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
        json!({
            "selectors": {"account_id": "account-a"},
            "account_id": "account-a",
            "adapter": {},
        }),
    )
    .expect("plan");

    let missing = required_global_warp_override_state_precondition(&plan)
        .expect_err("old plan without a prior-state receipt must fail");
    assert!(missing.to_string().contains("predates"));

    let receipt = json!({
        "schema_version": 1,
        "source_capability_id": "devices-resilience-retrieve-global-warp-override",
        "source_path": "/accounts/{account_id}/devices/resilience/disconnect",
        "target_capability_id": "devices-resilience-set-global-warp-override",
        "target_scope": "account",
        "target_id": "account-a",
        "disconnect": false,
    });
    let receipt_hash = hash_value(&receipt).expect("receipt hash");
    plan.targets["live_preconditions"]["global_warp_override_state"] = receipt;
    plan.precondition_hashes.insert(
        "global_warp_override_state".to_owned(),
        receipt_hash.clone(),
    );
    assert_eq!(
        required_global_warp_override_state_precondition(&plan).expect("bound precondition"),
        Some(receipt_hash.as_str())
    );

    let mut retargeted = plan.targets["live_preconditions"]["global_warp_override_state"].clone();
    retargeted["target_id"] = json!("account-b");
    plan.precondition_hashes.insert(
        "global_warp_override_state".to_owned(),
        hash_value(&retargeted).expect("retargeted receipt hash"),
    );
    plan.targets["live_preconditions"]["global_warp_override_state"] = retargeted;
    let error = required_global_warp_override_state_precondition(&plan)
        .expect_err("a rehashed cross-account receipt must still fail");
    assert!(error.to_string().contains("invalid account"));
}

#[test]
pub(super) fn prepared_global_warp_override_plan_carries_exact_before_and_after_state() {
    let root = tempfile::tempdir().expect("runtime root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let capability = global_warp_override_capability();
    assert!(capability.mutation_contract_gaps().is_empty());
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
        selectors: json!({"account_id": "account-a"}),
        body: Some(json!({
            "disconnect": true,
            "justification": "controlled test plan",
        })),
        ..CallInput::default()
    };
    let receipt = json!({
        "schema_version": 1,
        "source_capability_id": "devices-resilience-retrieve-global-warp-override",
        "source_path": "/accounts/{account_id}/devices/resilience/disconnect",
        "target_capability_id": "devices-resilience-set-global-warp-override",
        "target_scope": "account",
        "target_id": "account-a",
        "disconnect": false,
    });
    let receipt_hash = hash_value(&receipt).expect("receipt hash");
    let receipt_evidence = store
        .write_evidence(EvidenceClass::LiveRead, &receipt)
        .expect("live read evidence");

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
            global_warp_override_state: Some((receipt.clone(), receipt_evidence)),
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
            oauth_client_update_state: None,
            worker_custom_domain_state: None,
            worker_deployment_state: None,
        },
    )
    .expect("prepared plan");
    let plan = &envelope.result["plan"];

    assert_eq!(
        plan["precondition_hashes"]["global_warp_override_state"],
        receipt_hash
    );
    assert_eq!(
        plan["targets"]["live_preconditions"]["global_warp_override_state"],
        receipt
    );
    assert_eq!(
        plan["cloudflare_diffs"][0]["observed_before"],
        json!({"disconnect": false})
    );
    assert_eq!(
        plan["cloudflare_diffs"][0]["planned_after"],
        json!({"disconnect": true})
    );
    assert_eq!(
        plan["cloudflare_diffs"][0]["request_body"]["justification"],
        "controlled test plan"
    );
}

#[test]
pub(super) fn prepared_d1_plan_carries_exact_before_and_after_replication_mode() {
    let root = tempfile::tempdir().expect("runtime root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let capability = d1_read_replication_update_capability();
    assert!(capability.mutation_contract_gaps().is_empty());
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
        selectors: json!({"account_id":"account-a","database_id":"database-a"}),
        body: Some(json!({"read_replication":{"mode":"auto"}})),
        ..CallInput::default()
    };
    let receipt = json!({
        "schema_version": 1,
        "source_capability_id": "d1-get-database",
        "source_path": "/accounts/{account_id}/d1/database/{database_id}",
        "target_capability_id": "d1-update-partial-database",
        "target_method": "PATCH",
        "target_scope": "account",
        "account_id": "account-a",
        "database_id": "database-a",
        "read_replication": {"mode":"disabled"},
    });
    let receipt_hash = hash_value(&receipt).expect("receipt hash");
    let receipt_evidence = store
        .write_evidence(EvidenceClass::LiveRead, &receipt)
        .expect("live read evidence");

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
            d1_read_replication_state: Some((receipt.clone(), receipt_evidence)),
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
            oauth_client_update_state: None,
            worker_custom_domain_state: None,
            worker_deployment_state: None,
        },
    )
    .expect("prepared plan");
    let plan = &envelope.result["plan"];

    assert_eq!(
        plan["precondition_hashes"]["d1_read_replication_state"],
        receipt_hash
    );
    assert_eq!(
        plan["targets"]["live_preconditions"]["d1_read_replication_state"],
        receipt
    );
    assert_eq!(
        plan["cloudflare_diffs"][0]["observed_before"],
        json!({"read_replication":{"mode":"disabled"}})
    );
    assert_eq!(
        plan["cloudflare_diffs"][0]["planned_after"],
        json!({"read_replication":{"mode":"auto"}})
    );
}

#[test]
pub(super) fn prepared_cloudflare_tunnel_configuration_plan_carries_exact_before_and_after_routing()
{
    let root = tempfile::tempdir().expect("runtime root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let capability = cloudflare_tunnel_configuration_capability();
    assert!(capability.mutation_contract_gaps().is_empty());
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
    let prior_config = json!({
        "ingress":[{"hostname":"","service":"http_status:404"}]
    });
    let planned_config = json!({
        "ingress":[
            {"hostname":"app.example.com","service":"http://localhost:8080"},
            {"hostname":"","service":"http_status:404"}
        ]
    });
    let receipt = json!({
        "schema_version": 1,
        "source_capability_id": "cloudflare-tunnel-configuration-get-configuration",
        "source_path": "/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations",
        "target_capability_id": "cloudflare-tunnel-configuration-put-configuration",
        "target_method": "PUT",
        "target_path": "/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations",
        "target_scope": "account",
        "account_id": "account-a",
        "tunnel_id": "tunnel-a",
        "prior_config": prior_config,
    });
    let receipt_hash = hash_value(&receipt).expect("receipt hash");
    let receipt_evidence = store
        .write_evidence(EvidenceClass::LiveRead, &receipt)
        .expect("live read evidence");

    let envelope = persist_prepared_plan(
        &store,
        &catalog,
        capability,
        CallInput {
            selectors: json!({"account_id":"account-a","tunnel_id":"tunnel-a"}),
            body: Some(json!({"config":planned_config})),
            ..CallInput::default()
        },
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
            cloudflare_tunnel_configuration_state: Some((receipt.clone(), receipt_evidence)),
            warp_connector_configuration_state: None,
            web_analytics_rum_state: None,
            dns_record_state: None,
            same_path_prior_state: None,
            access_application_absence: None,
            access_operator_group_policy_ownership: None,
            security_action_state: None,
            oauth_client_secret_state: None,
            oauth_client_update_state: None,
            worker_custom_domain_state: None,
            worker_deployment_state: None,
        },
    )
    .expect("prepared plan");
    let plan = &envelope.result["plan"];

    assert_eq!(
        plan["precondition_hashes"]["cloudflare_tunnel_configuration_state"],
        receipt_hash
    );
    assert_eq!(
        plan["targets"]["live_preconditions"]["cloudflare_tunnel_configuration_state"],
        receipt
    );
    assert_eq!(
        plan["cloudflare_diffs"][0]["observed_before"],
        json!({"config":prior_config})
    );
    assert_eq!(
        plan["cloudflare_diffs"][0]["planned_after"],
        json!({"config":planned_config})
    );
}

#[test]
pub(super) fn prepared_warp_connector_plan_carries_exact_before_and_after_ha_state() {
    let root = tempfile::tempdir().expect("runtime root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let capability = warp_connector_configuration_capability();
    assert!(capability.mutation_contract_gaps().is_empty());
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
    let receipt = json!({
        "schema_version":1,
        "source_capability_id":"cloudflare-tunnel-configuration-get-warp-connector-configuration",
        "source_path":"/accounts/{account_id}/warp_connector/{tunnel_id}/configurations",
        "target_capability_id":"cloudflare-tunnel-configuration-update-warp-connector-configuration",
        "target_method":"PUT",
        "target_path":"/accounts/{account_id}/warp_connector/{tunnel_id}/configurations",
        "target_scope":"account",
        "account_id":"account-a",
        "tunnel_id":"tunnel-a",
        "prior_ha_mode":"disabled",
        "prior_config":null,
    });
    let receipt_hash = hash_value(&receipt).expect("receipt hash");
    let evidence = store
        .write_evidence(EvidenceClass::LiveRead, &receipt)
        .expect("live read evidence");
    let planned = json!({
        "ha_mode":"local",
        "config":{"vips":[{"address":"192.0.2.10"}]}
    });

    let envelope = persist_prepared_plan(
        &store,
        &catalog,
        capability,
        CallInput {
            selectors: json!({"account_id":"account-a","tunnel_id":"tunnel-a"}),
            body: Some(planned.clone()),
            ..CallInput::default()
        },
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
            cloudflare_tunnel_configuration_state: None,
            d1_empty_database_state: None,
            kv_empty_namespace_state: None,
            warp_connector_configuration_state: Some((receipt.clone(), evidence)),
            web_analytics_rum_state: None,
            dns_record_state: None,
            same_path_prior_state: None,
            access_application_absence: None,
            access_operator_group_policy_ownership: None,
            security_action_state: None,
            oauth_client_secret_state: None,
            oauth_client_update_state: None,
            worker_custom_domain_state: None,
            worker_deployment_state: None,
        },
    )
    .expect("prepared plan");
    let plan = &envelope.result["plan"];

    assert_eq!(
        plan["precondition_hashes"]["warp_connector_configuration_state"],
        receipt_hash
    );
    assert_eq!(
        plan["targets"]["live_preconditions"]["warp_connector_configuration_state"],
        receipt
    );
    assert_eq!(
        plan["cloudflare_diffs"][0]["observed_before"],
        json!({"ha_mode":"disabled","config":null})
    );
    assert_eq!(plan["cloudflare_diffs"][0]["planned_after"], planned);
}

#[test]
pub(super) fn prepared_web_analytics_rum_plan_carries_exact_before_and_after_state() {
    let root = tempfile::tempdir().expect("runtime root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let capability = web_analytics_rum_capability();
    assert!(capability.mutation_contract_gaps().is_empty());
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
    let receipt = json!({
        "schema_version":1,
        "source_capability_id":"web-analytics-get-rum-status",
        "source_path":"/zones/{zone_id}/settings/rum",
        "target_capability_id":"web-analytics-toggle-rum",
        "target_method":"PATCH",
        "target_path":"/zones/{zone_id}/settings/rum",
        "target_scope":"zone",
        "account_id":"account-a",
        "zone_id":"zone-a",
        "setting_id":"rum",
        "editable":true,
        "prior_value":"off",
    });
    let receipt_hash = hash_value(&receipt).expect("receipt hash");
    let evidence = store
        .write_evidence(EvidenceClass::LiveRead, &receipt)
        .expect("live read evidence");

    let envelope = persist_prepared_plan(
        &store,
        &catalog,
        capability,
        CallInput {
            selectors: json!({"zone_id":"zone-a"}),
            body: Some(json!({"value":"on"})),
            ..CallInput::default()
        },
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
            cloudflare_tunnel_configuration_state: None,
            warp_connector_configuration_state: None,
            d1_empty_database_state: None,
            kv_empty_namespace_state: None,
            web_analytics_rum_state: Some((receipt.clone(), evidence)),
            dns_record_state: None,
            same_path_prior_state: None,
            access_application_absence: None,
            access_operator_group_policy_ownership: None,
            security_action_state: None,
            oauth_client_secret_state: None,
            oauth_client_update_state: None,
            worker_custom_domain_state: None,
            worker_deployment_state: None,
        },
    )
    .expect("prepared plan");
    let plan = &envelope.result["plan"];

    assert_eq!(
        plan["precondition_hashes"]["web_analytics_rum_state"],
        receipt_hash
    );
    assert_eq!(
        plan["targets"]["live_preconditions"]["web_analytics_rum_state"],
        receipt
    );
    assert_eq!(
        plan["cloudflare_diffs"][0]["observed_before"],
        json!({"value":"off"})
    );
    assert_eq!(
        plan["cloudflare_diffs"][0]["planned_after"],
        json!({"value":"on"})
    );
}

#[test]
pub(super) fn prepared_dns_record_plan_carries_exact_before_and_after_record_state() {
    let root = tempfile::tempdir().expect("runtime root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let capability = dns_record_update_capability("PATCH");
    assert!(capability.mutation_contract_gaps().is_empty());
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
        selectors: json!({"zone_id":"zone-a","dns_record_id":"record-a"}),
        body: Some(json!({
            "type":"TXT",
            "name":"txt.example.com",
            "content":"new-value",
            "ttl":300,
            "proxied":false,
            "tags":[],
        })),
        ..CallInput::default()
    };
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
            "proxied":false,
            "tags":[],
        },
    });
    let receipt_hash = hash_value(&receipt).expect("receipt hash");
    let receipt_evidence = store
        .write_evidence(EvidenceClass::LiveRead, &receipt)
        .expect("live read evidence");

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
            dns_record_state: Some((receipt.clone(), receipt_evidence)),
            ..LivePlanPreconditions::default()
        },
    )
    .expect("prepared plan");
    let plan = &envelope.result["plan"];

    assert_eq!(
        plan["precondition_hashes"][DNS_RECORD_STATE_PRECONDITION],
        receipt_hash
    );
    assert_eq!(
        plan["targets"]["live_preconditions"][DNS_RECORD_STATE_PRECONDITION],
        receipt
    );
    assert_eq!(
        plan["cloudflare_diffs"][0]["observed_before"]["content"],
        "prior-value"
    );
    assert_eq!(
        plan["cloudflare_diffs"][0]["planned_after"]["content"],
        "new-value"
    );
}
