use super::*;

#[test]
pub(super) fn global_warp_rectification_derives_a_separate_exact_restore_request() {
    let capability = global_warp_override_capability();
    let receipt = json!({
        "schema_version": 1,
        "source_capability_id": "devices-resilience-retrieve-global-warp-override",
        "source_path": "/accounts/{account_id}/devices/resilience/disconnect",
        "target_capability_id": "devices-resilience-set-global-warp-override",
        "target_scope": "account",
        "target_id": "account-a",
        "disconnect": false,
    });
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability.clone(),
        json!({
            "selectors":{"account_id":"account-a"},
            "account_id":"account-a",
            "adapter":{},
            "live_preconditions":{"global_warp_override_state":receipt},
        }),
    )
    .expect("plan");
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-a"}),
        query: json!({}),
        body: Some(json!({
            "disconnect": true,
            "justification": "controlled source plan",
        })),
        ..CallInput::default()
    })
    .expect("call input");
    plan.precondition_hashes.insert(
        "global_warp_override_state".to_owned(),
        hash_value(&receipt).expect("receipt hash"),
    );
    plan.refresh_hash().expect("bind source plan");
    plan.approve(true, None).expect("approve");
    plan.mark_consumed().expect("consume");
    plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("attempt");
    plan.record_transaction_stage_with_artifact(
        TransactionStageV1::BoundaryResponsePersisted,
        json!({"success":true,"http_status":200}),
    )
    .expect("response receipt");
    plan.status = PlanStatus::RectificationRequired;

    let request = compensation_request(&plan)
        .expect("request resolves")
        .expect("compensation is supported");

    assert_eq!(request.capability_id, capability.id);
    assert_eq!(request.expected_method, "POST");
    assert_eq!(request.expected_path, capability.path);
    assert_eq!(request.input.selectors, json!({"account_id":"account-a"}));
    assert_eq!(request.input.query, json!({}));
    assert_eq!(request.input.body, Some(json!({"disconnect":false})));
    assert!(request.input.if_match.is_none());
    assert!(request.input.if_none_match.is_none());
    assert_eq!(request.requested_account.as_deref(), Some("account-a"));
}

#[test]
pub(super) fn d1_rectification_derives_a_separate_exact_mode_restore_request() {
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
        capability.clone(),
        json!({
            "selectors":{"account_id":"account-a","database_id":"database-a"},
            "account_id":"account-a",
            "adapter":{},
            "live_preconditions":{"d1_read_replication_state":receipt},
        }),
    )
    .expect("plan");
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-a","database_id":"database-a"}),
        query: json!({}),
        body: Some(json!({"read_replication":{"mode":"auto"}})),
        ..CallInput::default()
    })
    .expect("call input");
    plan.precondition_hashes.insert(
        "d1_read_replication_state".to_owned(),
        hash_value(&receipt).expect("receipt hash"),
    );
    plan.refresh_hash().expect("bind source plan");
    plan.approve(true, None).expect("approve");
    plan.mark_consumed().expect("consume");
    plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("attempt");
    plan.record_transaction_stage_with_artifact(
        TransactionStageV1::BoundaryResponsePersisted,
        json!({"success":true,"http_status":200}),
    )
    .expect("response receipt");
    plan.status = PlanStatus::RectificationRequired;

    let request = compensation_request(&plan)
        .expect("request resolves")
        .expect("compensation is supported");

    assert_eq!(request.capability_id, capability.id);
    assert_eq!(request.expected_method, "PATCH");
    assert_eq!(request.expected_path, capability.path);
    assert_eq!(
        request.input.selectors,
        json!({"account_id":"account-a","database_id":"database-a"})
    );
    assert_eq!(request.input.query, json!({}));
    assert_eq!(
        request.input.body,
        Some(json!({"read_replication":{"mode":"disabled"}}))
    );
    assert_eq!(request.requested_account.as_deref(), Some("account-a"));
}

#[test]
pub(super) fn cloudflare_tunnel_configuration_rectification_derives_an_exact_restore_put() {
    let capability = cloudflare_tunnel_configuration_capability();
    let prior_config = json!({
        "ingress": [
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
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability.clone(),
        json!({
            "selectors":{"account_id":"account-a","tunnel_id":"tunnel-a"},
            "account_id":"account-a",
            "adapter":{},
            "live_preconditions":{"cloudflare_tunnel_configuration_state":receipt},
        }),
    )
    .expect("plan");
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-a","tunnel_id":"tunnel-a"}),
        body: Some(json!({
            "config":{"ingress":[{"hostname":"","service":"http_status:503"}]}
        })),
        ..CallInput::default()
    })
    .expect("call input");
    plan.precondition_hashes.insert(
        "cloudflare_tunnel_configuration_state".to_owned(),
        hash_value(&receipt).expect("receipt hash"),
    );
    plan.refresh_hash().expect("bind source plan");
    plan.approve(true, None).expect("approve");
    plan.mark_consumed().expect("consume");
    plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("attempt");
    plan.record_transaction_stage_with_artifact(
        TransactionStageV1::BoundaryResponsePersisted,
        json!({"success":true,"http_status":200}),
    )
    .expect("response receipt");
    plan.status = PlanStatus::RectificationRequired;

    let request = compensation_request(&plan)
        .expect("request resolves")
        .expect("compensation is supported");

    assert_eq!(request.capability_id, capability.id);
    assert_eq!(request.expected_method, "PUT");
    assert_eq!(request.expected_path, capability.path);
    assert_eq!(
        request.input.selectors,
        json!({"account_id":"account-a","tunnel_id":"tunnel-a"})
    );
    assert_eq!(request.input.query, json!({}));
    assert_eq!(request.input.body, Some(json!({"config":prior_config})));
    assert_eq!(request.requested_account.as_deref(), Some("account-a"));
}

#[test]
pub(super) fn warp_connector_rectification_derives_an_exact_restore_put() {
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
        "prior_ha_mode":"aws",
        "prior_config":{"fnr_id":"eni-secondary-a"},
    });
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability.clone(),
        json!({
            "selectors":{"account_id":"account-a","tunnel_id":"tunnel-a"},
            "account_id":"account-a",
            "adapter":{},
            "live_preconditions":{"warp_connector_configuration_state":receipt},
        }),
    )
    .expect("plan");
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-a","tunnel_id":"tunnel-a"}),
        body: Some(json!({
            "ha_mode":"local",
            "config":{"vips":[{"address":"192.0.2.10"}]}
        })),
        ..CallInput::default()
    })
    .expect("call input");
    plan.precondition_hashes.insert(
        "warp_connector_configuration_state".to_owned(),
        hash_value(&receipt).expect("receipt hash"),
    );
    plan.refresh_hash().expect("bind source plan");
    plan.approve(true, None).expect("approve");
    plan.mark_consumed().expect("consume");
    plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("attempt");
    plan.record_transaction_stage_with_artifact(
        TransactionStageV1::BoundaryResponsePersisted,
        json!({"success":true,"http_status":200}),
    )
    .expect("response receipt");
    plan.status = PlanStatus::RectificationRequired;

    let request = compensation_request(&plan)
        .expect("request resolves")
        .expect("compensation is supported");
    assert_eq!(request.capability_id, capability.id);
    assert_eq!(request.expected_method, "PUT");
    assert_eq!(request.expected_path, capability.path);
    assert_eq!(
        request.input.selectors,
        json!({"account_id":"account-a","tunnel_id":"tunnel-a"})
    );
    assert_eq!(
        request.input.body,
        Some(json!({"ha_mode":"aws","config":{"fnr_id":"eni-secondary-a"}}))
    );
    assert_eq!(request.requested_account.as_deref(), Some("account-a"));
}

#[test]
pub(super) fn web_analytics_rum_rectification_derives_an_exact_restore_patch() {
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
        capability.clone(),
        json!({
            "selectors":{"zone_id":"zone-a"},
            "account_id":"account-a",
            "adapter":{},
            "live_preconditions":{"web_analytics_rum_state":receipt},
        }),
    )
    .expect("plan");
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"zone_id":"zone-a"}),
        body: Some(json!({"value":"on"})),
        ..CallInput::default()
    })
    .expect("call input");
    plan.precondition_hashes.insert(
        "web_analytics_rum_state".to_owned(),
        hash_value(&receipt).expect("receipt hash"),
    );
    plan.refresh_hash().expect("bind source plan");
    plan.approve(true, None).expect("approve");
    plan.mark_consumed().expect("consume");
    plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("attempt");
    plan.record_transaction_stage_with_artifact(
        TransactionStageV1::BoundaryResponsePersisted,
        json!({"success":true,"http_status":200}),
    )
    .expect("response receipt");
    plan.status = PlanStatus::RectificationRequired;

    let request = compensation_request(&plan)
        .expect("request resolves")
        .expect("compensation is supported");
    assert_eq!(request.capability_id, capability.id);
    assert_eq!(request.expected_method, "PATCH");
    assert_eq!(request.expected_path, capability.path);
    assert_eq!(request.input.selectors, json!({"zone_id":"zone-a"}));
    assert_eq!(request.input.query, json!({}));
    assert_eq!(request.input.body, Some(json!({"value":"off"})));
    assert_eq!(request.requested_account.as_deref(), Some("account-a"));
}

#[test]
pub(super) fn dns_rectification_derives_a_separate_exact_put_restore_request() {
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
            "proxied":false,
            "tags":[],
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
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"zone_id":"zone-a","dns_record_id":"record-a"}),
        query: json!({}),
        body: Some(json!({"content":"new-value"})),
        ..CallInput::default()
    })
    .expect("call input");
    plan.precondition_hashes.insert(
        "dns_record_state".to_owned(),
        hash_value(&receipt).expect("receipt hash"),
    );
    plan.refresh_hash().expect("bind source plan");
    plan.approve(true, None).expect("approve");
    plan.mark_consumed().expect("consume");
    plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("attempt");
    plan.record_transaction_stage_with_artifact(
        TransactionStageV1::BoundaryResponsePersisted,
        json!({"success":true,"http_status":200}),
    )
    .expect("response receipt");
    plan.status = PlanStatus::RectificationRequired;

    let request = compensation_request(&plan)
        .expect("request resolves")
        .expect("DNS compensation is supported");
    assert_eq!(
        request.capability_id,
        "dns-records-for-a-zone-update-dns-record"
    );
    assert_eq!(request.expected_method, "PUT");
    assert_eq!(request.expected_path, DNS_RECORD_DETAIL_PATH);
    assert_eq!(
        request.input.selectors,
        json!({"zone_id":"zone-a","dns_record_id":"record-a"})
    );
    assert_eq!(request.input.query, json!({}));
    assert_eq!(request.input.body, Some(receipt["prior_record"].clone()));
    assert_eq!(request.requested_account.as_deref(), Some("account-a"));
}

#[test]
pub(super) fn global_warp_override_guide_requires_the_exact_live_state_read() {
    let capability = global_warp_override_capability();
    let guide = guide_json(&capability);
    let current_state = &guide["stages"][4];
    assert_eq!(current_state["name"], "inspect_current_state");
    assert_eq!(current_state["contract_state"], "live_read_required");
    assert_eq!(current_state["evidence_class"], "live_read");
    assert_eq!(
        current_state["commands"][0],
        json!([
            "cfctl",
            "call",
            "devices-resilience-retrieve-global-warp-override",
            "--selector",
            "account_id=<account_id>",
            "--json"
        ])
    );
    let rectify = &guide["stages"][13];
    assert_eq!(rectify["name"], "rectify");
    assert_eq!(rectify["contract_state"], "available");
    assert_eq!(
        rectify["commands"][0],
        json!(["cfctl", "plans", "rectify", "<operation-id>", "--json"])
    );
}

#[test]
pub(super) fn d1_guide_requires_the_exact_live_database_state_read() {
    let capability = d1_read_replication_update_capability();
    let guide = guide_json(&capability);
    let current_state = &guide["stages"][4];
    assert_eq!(current_state["name"], "inspect_current_state");
    assert_eq!(current_state["contract_state"], "live_read_required");
    assert_eq!(current_state["evidence_class"], "live_read");
    assert_eq!(
        current_state["commands"][0],
        json!([
            "cfctl",
            "call",
            "d1-get-database",
            "--selector",
            "account_id=<account_id>",
            "--selector",
            "database_id=<database_id>",
            "--json"
        ])
    );
    assert_eq!(guide["stages"][13]["contract_state"], "available");
}

#[test]
pub(super) fn cloudflare_tunnel_configuration_guide_requires_the_exact_live_routing_read() {
    let capability = cloudflare_tunnel_configuration_capability();
    let guide = guide_json(&capability);
    let current_state = &guide["stages"][4];
    assert_eq!(current_state["name"], "inspect_current_state");
    assert_eq!(current_state["contract_state"], "live_read_required");
    assert_eq!(current_state["evidence_class"], "live_read");
    assert_eq!(
        current_state["commands"][0],
        json!([
            "cfctl",
            "call",
            "cloudflare-tunnel-configuration-get-configuration",
            "--selector",
            "account_id=<account_id>",
            "--selector",
            "tunnel_id=<tunnel_id>",
            "--json"
        ])
    );
    assert_eq!(guide["stages"][13]["contract_state"], "available");
}

#[test]
pub(super) fn warp_connector_configuration_guide_requires_the_exact_live_ha_read() {
    let capability = warp_connector_configuration_capability();
    let guide = guide_json(&capability);
    let current_state = &guide["stages"][4];
    assert_eq!(current_state["name"], "inspect_current_state");
    assert_eq!(current_state["contract_state"], "live_read_required");
    assert_eq!(current_state["evidence_class"], "live_read");
    assert_eq!(
        current_state["commands"][0],
        json!([
            "cfctl",
            "call",
            "cloudflare-tunnel-configuration-get-warp-connector-configuration",
            "--selector",
            "account_id=<account_id>",
            "--selector",
            "tunnel_id=<tunnel_id>",
            "--json"
        ])
    );
    assert_eq!(guide["stages"][13]["contract_state"], "available");
}

#[test]
pub(super) fn web_analytics_rum_guide_requires_the_exact_live_setting_read() {
    let capability = web_analytics_rum_capability();
    let guide = guide_json(&capability);
    let current_state = &guide["stages"][4];
    assert_eq!(current_state["name"], "inspect_current_state");
    assert_eq!(current_state["contract_state"], "live_read_required");
    assert_eq!(current_state["evidence_class"], "live_read");
    assert_eq!(
        current_state["commands"][0],
        json!([
            "cfctl",
            "call",
            "web-analytics-get-rum-status",
            "--selector",
            "zone_id=<zone_id>",
            "--json"
        ])
    );
    assert_eq!(guide["stages"][13]["contract_state"], "available");
}

#[test]
pub(super) fn dns_record_guide_requires_the_exact_live_record_state_read() {
    let capability = dns_record_update_capability("PATCH");
    let guide = guide_json(&capability);
    let current_state = &guide["stages"][4];
    assert_eq!(current_state["name"], "inspect_current_state");
    assert_eq!(current_state["contract_state"], "live_read_required");
    assert_eq!(current_state["evidence_class"], "live_read");
    assert_eq!(
        current_state["commands"][0],
        json!([
            "cfctl",
            "call",
            DNS_RECORD_DETAIL_READ_CAPABILITY_ID,
            "--selector",
            "zone_id=<zone_id>",
            "--selector",
            "dns_record_id=<dns_record_id>",
            "--json"
        ])
    );
    assert_eq!(guide["stages"][13]["contract_state"], "available");
}

#[test]
pub(super) fn workspace_resource_keys_require_capability_context_for_ambiguous_names() {
    let dns = CapabilityV1::new(
        "dns-record-create",
        "Create DNS record",
        "POST",
        "/zones/{zone_id}/dns_records",
    );
    let generic = CapabilityV1::new(
        "widgets-create",
        "Create widget",
        "POST",
        "/accounts/{account_id}/widgets",
    );
    let input = CallInput {
        selectors: json!({"namespace_id":"shared-name"}),
        body: Some(json!({"name":"api.example.com","pattern":"*.example.com"})),
        ..CallInput::default()
    };

    assert_eq!(
        workspace_resource_keys(&dns, &input),
        vec!["hostname:api.example.com"]
    );
    assert!(workspace_resource_keys(&generic, &input).is_empty());

    let mut kv = generic;
    kv.product = "Workers KV Namespace".to_owned();
    kv.path = "/accounts/{account_id}/storage/kv/namespaces/{namespace_id}".to_owned();
    assert_eq!(
        workspace_resource_keys(&kv, &input),
        vec!["kv_namespace:shared-name"]
    );
}

#[test]
pub(super) fn typed_query_input_preserves_array_values_and_rejects_ambiguous_scalars() {
    let mut capability = CapabilityV1::new(
        "query-read",
        "Query read",
        "GET",
        "/accounts/{account_id}/items",
    );
    capability.selectors = vec![
        SelectorV1 {
            name: "tags".to_owned(),
            location: "query".to_owned(),
            required: false,
            value_type: "array".to_owned(),
            description: None,
            contract: None,
        },
        SelectorV1 {
            name: "cursor".to_owned(),
            location: "query".to_owned(),
            required: false,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        },
    ];
    let query = query_object_from_pairs(
        &capability,
        &[
            ("tags".to_owned(), "one".to_owned()),
            ("tags".to_owned(), "two".to_owned()),
            ("cursor".to_owned(), "next".to_owned()),
        ],
    )
    .expect("typed query");
    assert_eq!(query, json!({"tags":["one","two"], "cursor":"next"}));

    let error = query_object_from_pairs(
        &capability,
        &[
            ("cursor".to_owned(), "one".to_owned()),
            ("cursor".to_owned(), "two".to_owned()),
        ],
    )
    .expect_err("duplicate scalar query controls must fail closed")
    .to_string();
    assert!(error.contains("cursor") && error.contains("repeated"));
}

#[test]
pub(super) fn catalog_sync_preserves_only_a_valid_current_snapshot() {
    let root = tempfile::tempdir().expect("runtime root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let catalog = test_catalog();
    store
        .write_json(&store.paths().catalog_file(), &catalog)
        .expect("current catalog");

    let preserved = preserve_previous_catalog(&store).expect("preserve current catalog");
    assert_eq!(preserved["status"], "preserved");
    assert_eq!(preserved["schema_hash"], catalog.schema_hash);
    assert_eq!(
        CatalogSnapshot::load(&store.paths().catalog_previous_file()).expect("previous catalog"),
        catalog
    );

    let mut tampered = serde_json::to_value(&catalog).expect("catalog JSON");
    tampered["capabilities"]["accounts-list"]["title"] = json!("Tampered account listing");
    store
        .write_json(&store.paths().catalog_file(), &tampered)
        .expect("tampered current catalog");

    let discarded = preserve_previous_catalog(&store).expect("discard invalid current");
    assert_eq!(discarded["status"], "discarded_invalid");
    assert!(
        discarded["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("catalog content hash mismatch"))
    );
    assert_eq!(
        CatalogSnapshot::load(&store.paths().catalog_previous_file())
            .expect("last valid previous catalog remains"),
        catalog
    );
}

#[test]
pub(super) fn call_preflight_rejects_nested_contract_drift_before_planning() {
    let mut capability =
        CapabilityV1::new("d1-update", "Update database", "PATCH", "/databases/id");
    capability.request_schema = Some(json!({
        "type":"object",
        "x-cfctl-body-required":true,
        "properties":{"read_replication":{
            "type":"object",
            "required":["mode"],
            "properties":{"mode":{"type":"string","enum":["auto","disabled"]}}
        }}
    }));
    let input = CallInput {
        body: Some(json!({"read_replication":{"mode":"experimental"}})),
        ..CallInput::default()
    };

    let error = preflight_call_input(&capability, &input, None)
        .expect_err("invalid nested body must fail before planning");
    assert!(error.to_string().contains("pinned enum"));

    let secret_body = json!({"read_replication":{"mode":"auto"}});
    preflight_call_input(&capability, &CallInput::default(), Some(&secret_body))
        .expect("secret body must be validated before it is replaced by an opaque reference");
}

#[test]
pub(super) fn zone_entitlement_binds_the_exact_active_subscription_plan() {
    let mut capability = CapabilityV1::new(
        "custom-pages-update",
        "Update custom page",
        "PUT",
        "/zones/{zone_identifier}/custom_pages/{identifier}",
    );
    capability.account_scope = "zone".to_owned();
    capability.entitlement.requires_live_resolution = true;
    capability.entitlement.plans = BTreeMap::from([
        ("free".to_owned(), false),
        ("pro".to_owned(), true),
        ("business".to_owned(), true),
        ("enterprise".to_owned(), true),
    ]);
    let input = CallInput {
        selectors: json!({
            "zone_identifier": "zone-a",
            "identifier": "page-a",
        }),
        ..CallInput::default()
    };
    let response = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({
            "state": "Paid",
            "rate_plan": {"id": "partners_business"},
        }),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };

    assert_eq!(
        zone_target(&capability, &input).expect("zone target"),
        "zone-a"
    );
    let receipt = apply_zone_entitlement_response(&mut capability, "zone-a", &response)
        .expect("entitlement receipt");

    assert_eq!(capability.entitlement.available, Some(true));
    assert_eq!(
        capability.entitlement.observed_plan.as_deref(),
        Some("partners_business")
    );
    assert_eq!(receipt["canonical_plan"], "business");
    assert_eq!(receipt["subscription_state"], "Paid");
    assert_eq!(receipt["available"], true);
    assert_eq!(receipt["target_id"], "zone-a");
    assert!(receipt["plan_matrix_hash"].as_str().is_some());
}

#[test]
pub(super) fn zone_entitlement_rejects_inactive_or_unmapped_subscription_plans() {
    let mut capability = CapabilityV1::new(
        "custom-pages-update",
        "Update custom page",
        "PUT",
        "/zones/{zone_id}/custom_pages/{identifier}",
    );
    capability.account_scope = "zone".to_owned();
    capability.entitlement.requires_live_resolution = true;
    capability.entitlement.plans = BTreeMap::from([
        ("free".to_owned(), false),
        ("pro".to_owned(), true),
        ("business".to_owned(), true),
        ("enterprise".to_owned(), true),
    ]);
    let response = |state: &str, plan: &str| CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"state": state, "rate_plan": {"id": plan}}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };

    let inactive = apply_zone_entitlement_response(
        &mut capability,
        "zone-a",
        &response("Cancelled", "business"),
    )
    .expect_err("inactive subscription");
    assert!(inactive.to_string().contains("is not active"));

    let unmapped =
        apply_zone_entitlement_response(&mut capability, "zone-a", &response("Paid", "pro_plus"))
            .expect_err("unmapped plan");
    assert!(unmapped.to_string().contains("cannot be mapped"));
}

#[test]
pub(super) fn declared_product_read_probe_resolves_entitlement_without_negative_inference() {
    let mut capability = security_action_create_capability();
    capability.cost = CostV1::default();
    capability.entitlement.requires_live_resolution = true;
    capability.entitlement.plans =
        BTreeMap::from([("free".to_owned(), false), ("enterprise".to_owned(), true)]);
    capability.entitlement.probe = Some(EntitlementProbeV1 {
        capability_id: SECURITY_IP_RULE_STATE_CAPABILITY_ID.to_owned(),
        path: SECURITY_IP_RULE_COLLECTION_PATH.to_owned(),
        selector_names: vec!["zone_id".to_owned()],
    });
    let input = CallInput {
        selectors: json!({"zone_id":"zone-a"}),
        ..CallInput::default()
    };
    assert!(
        capability.mutation_contract_gaps().is_empty(),
        "{:?}",
        capability.mutation_contract_gaps()
    );
    assert!(should_resolve_entitlement_probe(&capability));
    let selectors = entitlement_probe_selectors(&capability, &input).expect("selectors");
    let response = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!([]),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };

    let receipt = apply_entitlement_probe_response(&mut capability, &selectors, &response)
        .expect("probe receipt");

    assert_eq!(capability.entitlement.available, Some(true));
    assert!(!should_resolve_entitlement_probe(&capability));
    assert_eq!(receipt["available"], true);
    assert_eq!(receipt["negative_inference"], false);
    assert!(receipt["target_selectors_hash"].as_str().is_some());
    assert!(!receipt.to_string().contains("zone-a"));

    capability.entitlement.available = None;
    let rejected = CloudflareResponseV1 {
        status: 403,
        success: false,
        result: Value::Null,
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let error = apply_entitlement_probe_response(&mut capability, &selectors, &rejected)
        .expect_err("a rejected read cannot prove entitlement")
        .to_string();
    assert!(error.contains("authorization"));
    assert!(error.contains("entitlement"));
    assert_eq!(capability.entitlement.available, None);
}

#[test]
pub(super) fn blocked_capability_failure_routes_to_guide() {
    let mut capability = CapabilityV1::new(
        "cache-purge",
        "Purge cached content",
        "POST",
        "/zones/{zone_id}/purge_cache",
    );
    capability.adapter_status = AdapterStatus::Blocked;
    capability.blocked_reason = Some(
        "operation contract incomplete: operation-specific verification is not declared".to_owned(),
    );
    let envelope = blocked_capability_envelope(
        "call",
        &capability,
        capability
            .blocked_reason
            .as_deref()
            .expect("blocked reason fixture"),
    );
    assert!(!envelope.ok);
    assert_eq!(envelope.capability_id.as_deref(), Some("cache-purge"));
    assert!(
        envelope
            .result
            .get("blocking_gaps")
            .is_some_and(Value::is_array)
    );
    let error = envelope.error.expect("blocked envelope carries an error");
    assert_eq!(error.code, "CFCTL_CAPABILITY_BLOCKED");
    assert!(error.message.contains("capability is blocked"));
    let next_step = error
        .next_step
        .expect("blocked envelope carries a next step");
    assert!(next_step.contains("cfctl guide cache-purge --json"));
    assert!(next_step.contains("never bypass"));
}

#[test]
pub(super) fn zone_entitlement_unblocks_only_a_complete_contract_and_rechecks_drift() {
    let mut capability = CapabilityV1::new(
        "custom-pages-delete",
        "Delete custom page",
        "DELETE",
        "/zones/{zone_id}/custom_pages/{identifier}",
    );
    capability.account_scope = "zone".to_owned();
    capability.adapter_status = AdapterStatus::Blocked;
    capability.blocked_reason = Some(
            "operation contract incomplete: account entitlement has not been resolved for this plan-gated operation"
                .to_owned(),
        );
    capability.risk = RiskClass::Destructive;
    capability.effect = EffectClass::Destructive;
    capability.cost.known = true;
    capability.cost.maximum = Some(0.0);
    capability.cost.basis =
        Some("deleting an existing resource has no incremental operation charge".to_owned());
    capability.permissions = vec!["Zone Settings Write".to_owned()];
    capability.verification.strategy = "same_resource_returns_not_found_after_delete".to_owned();
    capability.same_path_read = Some(SamePathReadContractV1 {
        path: "/zones/{zone_id}/custom_pages/{identifier}".to_owned(),
        read_capability_id: "custom-pages-get".to_owned(),
        verified_response_fields: Vec::new(),
    });
    capability.rollback.supported = false;
    capability.rollback.warning =
        Some("deletion is irreversible without a prior resource snapshot".to_owned());
    capability.entitlement.requires_live_resolution = true;
    capability.entitlement.plans = BTreeMap::from([
        ("free".to_owned(), false),
        ("pro".to_owned(), true),
        ("business".to_owned(), true),
        ("enterprise".to_owned(), true),
    ]);
    assert!(
        should_resolve_zone_entitlement(&capability),
        "gaps: {:?}",
        capability.mutation_contract_gaps()
    );
    let guide = guide_json(&capability);
    assert_eq!(guide["contract_state"], "blocked");
    assert_eq!(guide["next_action"]["argv"][0], "cfctl");
    assert_eq!(guide["next_action"]["argv"][1], "call");
    assert!(
        guide["next_action"]["summary"]
            .as_str()
            .is_some_and(|summary| summary.contains("live zone-subscription read"))
    );
    assert_eq!(guide["stages"][2]["contract_state"], "live_read_required");
    assert_eq!(guide["stages"][2]["evidence_class"], "live_read");
    assert_eq!(guide["stages"][3]["contract_state"], "live_read_required");
    assert_eq!(guide["stages"][3]["evidence_class"], "live_read");
    let response = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({
            "state": "Paid",
            "rate_plan": {"id": "pro"},
        }),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };

    let receipt = apply_zone_entitlement_response(&mut capability, "zone-a", &response)
        .expect("entitlement receipt");
    assert_eq!(capability.adapter_status, AdapterStatus::DynamicApi);
    assert!(capability.blocked_reason.is_none());
    let expected_hash = hash_value(&receipt).expect("receipt hash");
    validate_entitlement_receipt_precondition(&expected_hash, &capability, &receipt)
        .expect("unchanged entitlement");

    let mut drifted = receipt;
    drifted["observed_plan"] = json!("business");
    let error = validate_entitlement_receipt_precondition(&expected_hash, &capability, &drifted)
        .expect_err("drift must fail");
    assert!(error.to_string().contains("drifted after planning"));
}

#[test]
pub(super) fn zone_entitlement_precondition_cannot_be_omitted_from_an_executable_plan() {
    let mut capability = CapabilityV1::new(
        "custom-pages-delete",
        "Delete custom page",
        "DELETE",
        "/zones/{zone_id}/custom_pages/{identifier}",
    );
    capability.account_scope = "zone".to_owned();
    capability.entitlement.requires_live_resolution = true;
    capability.entitlement.available = Some(true);
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
        json!({}),
    )
    .expect("plan");

    let error = required_entitlement_precondition(&plan)
        .expect_err("missing entitlement precondition must fail");
    assert!(error.to_string().contains("predates"));

    plan.precondition_hashes.insert(
        "entitlement".to_owned(),
        format!("sha256:{}", "a".repeat(64)),
    );
    assert_eq!(
        required_entitlement_precondition(&plan).expect("entitlement precondition"),
        plan.precondition_hashes
            .get("entitlement")
            .map(String::as_str)
    );
}

#[test]
pub(super) fn zone_account_receipt_binds_the_exact_target_and_selected_account() {
    let response = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({
            "id": "zone-a",
            "account": {"id": "account-a", "name": "Example"},
        }),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };

    let receipt = apply_zone_account_response("zone-a", "account-a", &response)
        .expect("zone account receipt");
    assert_eq!(receipt["target_id"], "zone-a");
    assert_eq!(receipt["expected_account_id"], "account-a");
    assert_eq!(receipt["observed_account_id"], "account-a");
    assert_eq!(receipt["account_matches"], true);
    let receipt_hash = hash_value(&receipt).expect("zone-account receipt hash");
    validate_zone_account_receipt_precondition(&receipt_hash, &receipt)
        .expect("unchanged zone-account receipt");

    let mut drifted = receipt.clone();
    drifted["observed_account_id"] = json!("account-b");
    let drift = validate_zone_account_receipt_precondition(&receipt_hash, &drifted)
        .expect_err("zone-account receipt drift must fail");
    assert!(drift.to_string().contains("ownership drifted"));

    let mismatch = apply_zone_account_response("zone-a", "account-b", &response)
        .expect_err("cross-account zone must fail");
    assert!(
        mismatch
            .to_string()
            .contains("belongs to account `account-a`")
    );

    let wrong_zone = apply_zone_account_response("zone-b", "account-a", &response)
        .expect_err("wrong zone response must fail");
    assert!(wrong_zone.to_string().contains("returned zone `zone-a`"));
}

#[test]
pub(super) fn every_executable_zone_mutation_requires_an_account_precondition() {
    let mut capability = CapabilityV1::new(
        "custom-pages-delete",
        "Delete custom page",
        "DELETE",
        "/zones/{zone_id}/custom_pages/{identifier}",
    );
    capability.account_scope = "zone".to_owned();
    capability.adapter_status = AdapterStatus::DynamicApi;
    assert!(should_bind_zone_account(&capability));
    let guide = guide_json(&capability);
    assert_eq!(guide["stages"][2]["contract_state"], "live_read_required");
    assert_eq!(guide["stages"][2]["evidence_class"], "live_read");

    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
        json!({}),
    )
    .expect("plan");
    let missing = required_zone_account_precondition(&plan)
        .expect_err("missing zone-account precondition must fail");
    assert!(missing.to_string().contains("zone-account ownership"));

    plan.precondition_hashes.insert(
        "zone_account".to_owned(),
        format!("sha256:{}", "b".repeat(64)),
    );
    assert_eq!(
        required_zone_account_precondition(&plan).expect("zone-account precondition"),
        plan.precondition_hashes
            .get("zone_account")
            .map(String::as_str)
    );
}

impl SecretStore for DeleteFailingSecretStore {
    fn put(&self, _key: &str, _value: &str) -> cfctl_auth::Result<()> {
        Ok(())
    }

    fn get(&self, _key: &str) -> cfctl_auth::Result<Option<String>> {
        Ok(None)
    }

    fn delete(&self, _key: &str) -> cfctl_auth::Result<()> {
        Err(AuthError::SecretStore("injected delete failure".to_owned()))
    }

    fn locate(&self, _key: &str) -> cfctl_auth::Result<Option<cfctl_auth::SecretBackend>> {
        Ok(None)
    }
}

impl SecretStore for PutFailingSecretStore {
    fn put(&self, _key: &str, _value: &str) -> cfctl_auth::Result<()> {
        Err(AuthError::SecretStore("injected put failure".to_owned()))
    }

    fn get(&self, _key: &str) -> cfctl_auth::Result<Option<String>> {
        Ok(None)
    }

    fn delete(&self, _key: &str) -> cfctl_auth::Result<()> {
        Ok(())
    }

    fn locate(&self, _key: &str) -> cfctl_auth::Result<Option<cfctl_auth::SecretBackend>> {
        Ok(None)
    }
}
