use super::*;

#[test]
pub(super) fn selected_permission_groups_must_match_unique_live_inventory_entries() {
    let inventory = json!([
        {
            "id": "group-b",
            "name": "Workers Scripts Write",
            "scopes": ["com.cloudflare.api.account"]
        },
        {
            "id": "group-a",
            "name": "Account Settings Read",
            "scopes": ["com.cloudflare.api.account", "com.cloudflare.api.zone"]
        }
    ]);

    let selected = validate_selected_permission_groups(
        &["group-b".to_owned(), "group-a".to_owned()],
        &inventory,
    )
    .expect("selected groups resolve");

    assert_eq!(selected[0]["id"], "group-a");
    assert_eq!(selected[0]["name"], "Account Settings Read");
    assert_eq!(selected[1]["id"], "group-b");
    assert_eq!(selected[1]["scopes"], json!(["com.cloudflare.api.account"]));

    let missing = validate_selected_permission_groups(&["group-missing".to_owned()], &inventory)
        .expect_err("missing group is rejected");
    assert!(missing.to_string().contains("group-missing"));

    let duplicate_inventory = json!([
        {"id":"group-a","name":"First","scopes":["com.cloudflare.api.account"]},
        {"id":"group-a","name":"Second","scopes":["com.cloudflare.api.account"]}
    ]);
    let duplicate =
        validate_selected_permission_groups(&["group-a".to_owned()], &duplicate_inventory)
            .expect_err("ambiguous group is rejected");
    assert!(duplicate.to_string().contains("not unique"));
}

#[test]
pub(super) fn selected_permission_groups_accept_exact_names_and_reject_ambiguous_names() {
    let inventory = json!([
        {
            "id": "group-a",
            "name": "Workers Scripts Write",
            "scopes": ["com.cloudflare.api.account"]
        },
        {
            "id": "group-b",
            "name": "Account Settings Read",
            "scopes": ["com.cloudflare.api.account"]
        }
    ]);

    let selected = validate_selected_permission_groups(
        &[
            "Workers Scripts Write".to_owned(),
            "group-a".to_owned(),
            "Account Settings Read".to_owned(),
        ],
        &inventory,
    )
    .expect("exact ID and exact name selectors resolve deterministically");

    assert_eq!(selected.len(), 2, "ID/name aliases deduplicate by group ID");
    assert_eq!(selected[0]["id"], "group-a");
    assert_eq!(selected[1]["id"], "group-b");

    let ambiguous_inventory = json!([
        {
            "id": "group-a",
            "name": "Shared Name",
            "scopes": ["com.cloudflare.api.account"]
        },
        {
            "id": "group-b",
            "name": "Shared Name",
            "scopes": ["com.cloudflare.api.account"]
        }
    ]);
    let error =
        validate_selected_permission_groups(&["Shared Name".to_owned()], &ambiguous_inventory)
            .expect_err("ambiguous exact names fail closed");
    assert!(error.to_string().contains("matched 2"), "{error}");
}

#[test]
pub(super) fn token_creation_requires_inventory_bound_permissions_and_exact_account_scope() {
    let capability = CapabilityV1::new(
        "account-api-tokens-create-token",
        "Create account token",
        "POST",
        "/accounts/{account_id}/tokens",
    );
    let groups = json!([{
        "id": "group-a",
        "name": "Workers Scripts Write",
        "scopes": ["com.cloudflare.api.account"]
    }]);
    let groups_hash = hash_value(&groups).expect("group hash");
    let adapter = json!({
        "permission_inventory": {
            "source_capability_id": "account-api-tokens-list-permission-groups",
            "selected_groups": groups,
            "selected_groups_hash": groups_hash,
            "evidence_hashes": [format!("sha256:{}", "a".repeat(64))]
        }
    });
    let input = CallInput {
        selectors: json!({"account_id":"account-a"}),
        query: json!({}),
        body: Some(json!({
            "name":"least-privilege token",
            "policies":[{
                "effect":"allow",
                "permission_groups":[{"id":"group-a"}],
                "resources":{"com.cloudflare.api.account.account-a":"*"}
            }]
        })),
        ..CallInput::default()
    };

    validate_api_token_creation_contract(&capability, &input, &adapter, "account-a")
        .expect("inventory-bound token plan is valid");

    let direct = validate_api_token_creation_contract(&capability, &input, &json!({}), "account-a")
        .expect_err("direct token call is rejected");
    assert!(direct.to_string().contains("cfctl keys mint"));

    let mut widened = input.clone();
    widened.body = Some(json!({
        "name":"widened token",
        "policies":[{
            "effect":"allow",
            "permission_groups":[{"id":"group-a"}],
            "resources":{"com.cloudflare.api.account.other-account":"*"}
        }]
    }));
    let widened =
        validate_api_token_creation_contract(&capability, &widened, &adapter, "account-a")
            .expect_err("cross-account scope is rejected");
    assert!(widened.to_string().contains("account-a"));
}

#[test]
pub(super) fn validate_zone_id_accepts_only_32_char_lowercase_hex() {
    validate_zone_id("e826a542f6b80137a949a3291c1cad9c").expect("valid zone id");
    // uppercase, wrong length, and non-hex are all rejected.
    validate_zone_id("E826A542F6B80137A949A3291C1CAD9C").expect_err("uppercase");
    validate_zone_id("e826a542").expect_err("too short");
    validate_zone_id("g826a542f6b80137a949a3291c1cad9z").expect_err("non-hex");
    validate_zone_id("").expect_err("empty");
}

#[test]
pub(super) fn resource_scope_guard_admits_zone_groups_only_under_zone_scope() {
    let zone_group = json!([{
        "id": "e17beae8b8cb423a99b1730f21238bed",
        "name": "Cache Purge",
        "scopes": ["com.cloudflare.api.account.zone"]
    }]);
    let account_group = json!([{
        "id": "group-a",
        "name": "Workers Scripts Write",
        "scopes": ["com.cloudflare.api.account"]
    }]);
    let zone = zone_group.as_array().expect("zone groups");
    let account = account_group.as_array().expect("account groups");
    // A zone-scoped group is admitted only under the zone scope.
    validate_permission_group_resource_scope(zone, "com.cloudflare.api.account.zone")
        .expect("zone group under zone scope");
    validate_permission_group_resource_scope(zone, "com.cloudflare.api.account")
        .expect_err("zone group cannot be minted under account scope");
    // …and an account-only group cannot be minted under the zone scope.
    validate_permission_group_resource_scope(account, "com.cloudflare.api.account.zone")
        .expect_err("account group cannot be minted under zone scope");
}

#[test]
pub(super) fn zone_scoped_token_creation_binds_the_zone_resource_and_rejects_drift() {
    let capability = CapabilityV1::new(
        "account-api-tokens-create-token",
        "Create account token",
        "POST",
        "/accounts/{account_id}/tokens",
    );
    let zone = "e826a542f6b80137a949a3291c1cad9c";
    let resource = format!("com.cloudflare.api.account.zone.{zone}");
    let groups = json!([{
        "id": "e17beae8b8cb423a99b1730f21238bed",
        "name": "Cache Purge",
        "scopes": ["com.cloudflare.api.account.zone"]
    }]);
    let groups_hash = hash_value(&groups).expect("group hash");
    let adapter = json!({
        "permission_inventory": {
            "source_capability_id": "account-api-tokens-list-permission-groups",
            "selected_groups": groups,
            "selected_groups_hash": groups_hash,
            "token_resource": resource,
            "permission_scope": "com.cloudflare.api.account.zone",
            "evidence_hashes": [format!("sha256:{}", "a".repeat(64))]
        }
    });
    let input = CallInput {
        selectors: json!({"account_id":"account-a"}),
        query: json!({}),
        body: Some(json!({
            "name":"cache purge token",
            "policies":[{
                "effect":"allow",
                "permission_groups":[{"id":"e17beae8b8cb423a99b1730f21238bed"}],
                "resources":{resource.clone():"*"}
            }]
        })),
        ..CallInput::default()
    };
    validate_api_token_creation_contract(&capability, &input, &adapter, "account-a")
        .expect("zone-scoped token plan is valid");

    // Body scoped to a different zone than the bound resource is rejected.
    let mut drifted = input.clone();
    drifted.body = Some(json!({
        "name":"cache purge token",
        "policies":[{
            "effect":"allow",
            "permission_groups":[{"id":"e17beae8b8cb423a99b1730f21238bed"}],
            "resources":{"com.cloudflare.api.account.zone.ffffffffffffffffffffffffffffffff":"*"}
        }]
    }));
    validate_api_token_creation_contract(&capability, &drifted, &adapter, "account-a")
        .expect_err("resource drift off the bound zone is rejected");
}

#[test]
pub(super) fn account_scope_claim_cannot_bind_a_zone_resource() {
    // The cross-scope attack: claim whole-account permission scope (so the
    // group check is lax) but bind a narrower-looking zone resource. The
    // single-segment-under-scope guard must reject it.
    let capability = CapabilityV1::new(
        "account-api-tokens-create-token",
        "Create account token",
        "POST",
        "/accounts/{account_id}/tokens",
    );
    let zone_resource = "com.cloudflare.api.account.zone.e826a542f6b80137a949a3291c1cad9c";
    let groups = json!([{
        "id": "group-a",
        "name": "Workers Scripts Write",
        "scopes": ["com.cloudflare.api.account", "com.cloudflare.api.account.zone"]
    }]);
    let groups_hash = hash_value(&groups).expect("group hash");
    let adapter = json!({
        "permission_inventory": {
            "source_capability_id": "account-api-tokens-list-permission-groups",
            "selected_groups": groups,
            "selected_groups_hash": groups_hash,
            "token_resource": zone_resource,
            "permission_scope": "com.cloudflare.api.account",
            "evidence_hashes": [format!("sha256:{}", "a".repeat(64))]
        }
    });
    let input = CallInput {
        selectors: json!({"account_id":"account-a"}),
        query: json!({}),
        body: Some(json!({
            "name":"mismatched token",
            "policies":[{
                "effect":"allow",
                "permission_groups":[{"id":"group-a"}],
                "resources":{zone_resource:"*"}
            }]
        })),
        ..CallInput::default()
    };
    let error = validate_api_token_creation_contract(&capability, &input, &adapter, "account-a")
        .expect_err("account scope claim with a zone resource is rejected");
    assert!(
        error.to_string().contains("not a single concrete resource"),
        "{error}"
    );

    // A wildcard id (`*`) is single-segment but not a concrete resource;
    // the guard must reject it so a tampered metadata resource cannot widen
    // to the whole account under an account scope claim.
    let mut wildcard = adapter.clone();
    wildcard["permission_inventory"]["token_resource"] = json!("com.cloudflare.api.account.*");
    let wildcard_input = CallInput {
        selectors: json!({"account_id":"account-a"}),
        query: json!({}),
        body: Some(json!({
            "name":"wildcard token",
            "policies":[{
                "effect":"allow",
                "permission_groups":[{"id":"group-a"}],
                "resources":{"com.cloudflare.api.account.*":"*"}
            }]
        })),
        ..CallInput::default()
    };
    validate_api_token_creation_contract(&capability, &wildcard_input, &wildcard, "account-a")
        .expect_err("a wildcard resource id is rejected");
}

#[test]
pub(super) fn token_policy_body_accepts_the_bound_resource_verbatim() {
    // Backward-compat + zone: validate_token_policy_body scopes to exactly
    // the expected resource, whatever its shape.
    let account_body = json!({
        "policies":[{
            "effect":"allow",
            "permission_groups":[{"id":"group-a"}],
            "resources":{"com.cloudflare.api.account.account-a":"*"}
        }]
    });
    validate_token_policy_body(
        Some(&account_body),
        &["group-a".to_owned()],
        "com.cloudflare.api.account.account-a",
    )
    .expect("account resource accepted");
    let zone_body = json!({
        "policies":[{
            "effect":"allow",
            "permission_groups":[{"id":"group-a"}],
            "resources":{"com.cloudflare.api.account.zone.e826a542f6b80137a949a3291c1cad9c":"*"}
        }]
    });
    validate_token_policy_body(
        Some(&zone_body),
        &["group-a".to_owned()],
        "com.cloudflare.api.account.zone.e826a542f6b80137a949a3291c1cad9c",
    )
    .expect("zone resource accepted");
    // Mismatch between the bound resource and the body is rejected.
    validate_token_policy_body(
        Some(&zone_body),
        &["group-a".to_owned()],
        "com.cloudflare.api.account.account-a",
    )
    .expect_err("resource mismatch rejected");
}

#[test]
pub(super) fn mint_policy_body_expires_on_is_cloudflare_compatible() {
    // Cloudflare rejects the fractional-second `+00:00` form that
    // `to_rfc3339()` emits with a 400; it requires seconds-precision UTC
    // with a `Z` suffix (e.g. 2005-12-30T01:02:03Z).
    let binding = TokenPolicyBinding {
        permission_scope: "com.cloudflare.api.account.zone".to_owned(),
        token_resource: "com.cloudflare.api.account.zone.e826a542f6b80137a949a3291c1cad9c"
            .to_owned(),
        permission_group_ids: vec!["group-a".to_owned()],
    };
    let body = build_mint_policy_body("t", std::slice::from_ref(&binding), Some(1));
    let expires = body["expires_on"].as_str().expect("expires_on present");
    assert!(expires.ends_with('Z'), "{expires}");
    assert!(!expires.contains('.'), "no fractional seconds: {expires}");
    assert!(!expires.contains('+'), "no numeric offset: {expires}");
    // Cloudflare's parser and cfctl's standing-mint parser both accept it.
    chrono::DateTime::parse_from_rfc3339(expires).expect("valid rfc3339");
    // No TTL → no expiry field.
    let no_ttl = build_mint_policy_body("t", &[binding], None);
    assert!(no_ttl.get("expires_on").is_none());
}

#[test]
pub(super) fn mixed_scope_token_creation_partitions_account_and_zone_permissions() {
    let capability = CapabilityV1::new(
        "account-api-tokens-create-token",
        "Create account token",
        "POST",
        "/accounts/{account_id}/tokens",
    );
    let zone = "e826a542f6b80137a949a3291c1cad9c";
    let groups = json!([
        {
            "id": "account-group",
            "name": "Workers Scripts Write",
            "scopes": ["com.cloudflare.api.account"]
        },
        {
            "id": "zone-group",
            "name": "Workers Routes Read",
            "scopes": ["com.cloudflare.api.account.zone"]
        }
    ]);
    let selected = groups.as_array().expect("groups");
    let arguments = KeyMutationArgs {
        profile: None,
        user: false,
        name: "wrangler deploy".to_owned(),
        permissions: vec![],
        account: Some("account-a".to_owned()),
        zone: Some(zone.to_owned()),
        ttl_hours: Some(1),
        value_out: None,
        under_policy: None,
    };
    let bindings = resolve_mint_token_bindings(&arguments, "account-a", selected)
        .expect("mixed scopes partition");
    assert_eq!(bindings.len(), 2);
    assert_eq!(
        bindings[0].token_resource,
        "com.cloudflare.api.account.account-a"
    );
    assert_eq!(bindings[0].permission_group_ids, ["account-group"]);
    assert_eq!(
        bindings[1].token_resource,
        format!("com.cloudflare.api.account.zone.{zone}")
    );
    assert_eq!(bindings[1].permission_group_ids, ["zone-group"]);

    let groups_hash = hash_value(&groups).expect("group hash");
    let adapter = json!({
        "permission_inventory": {
            "source_capability_id": "account-api-tokens-list-permission-groups",
            "selected_groups": groups,
            "selected_groups_hash": groups_hash,
            "permission_bindings": bindings.iter().map(TokenPolicyBinding::as_json).collect::<Vec<_>>(),
            "evidence_hashes": [format!("sha256:{}", "a".repeat(64))]
        }
    });
    let input = CallInput {
        selectors: json!({"account_id":"account-a"}),
        query: json!({}),
        body: Some(build_mint_policy_body(
            "wrangler deploy",
            &bindings,
            Some(1),
        )),
        ..CallInput::default()
    };
    validate_api_token_creation_contract(&capability, &input, &adapter, "account-a")
        .expect("mixed-scope token plan is valid");

    let mut drifted = input.clone();
    drifted.body.as_mut().expect("body")["policies"][1]["permission_groups"] =
        json!([{"id":"account-group"}]);
    validate_api_token_creation_contract(&capability, &drifted, &adapter, "account-a")
        .expect_err("permission migration across resource bindings is rejected");

    let mut duplicated = adapter.clone();
    duplicated["permission_inventory"]["permission_bindings"][1]["permission_group_ids"] =
        json!(["account-group", "zone-group"]);
    validate_api_token_creation_contract(&capability, &input, &duplicated, "account-a")
        .expect_err("a group cannot appear in multiple bindings");
}

#[test]
pub(super) fn user_token_creation_requires_its_own_inventory_and_account_compatible_groups() {
    let user_capability = CapabilityV1::new(
        "user-api-tokens-create-token",
        "Create user-owned token",
        "POST",
        "/user/tokens",
    );
    let groups = json!([{
        "id": "group-a",
        "name": "Workers Scripts Write",
        "scopes": ["com.cloudflare.api.account"]
    }]);
    let groups_hash = hash_value(&groups).expect("group hash");
    let user_adapter = json!({
        "permission_inventory": {
            "source_capability_id": "permission-groups-list-permission-groups",
            "selected_groups": groups,
            "selected_groups_hash": groups_hash,
            "evidence_hashes": [format!("sha256:{}", "b".repeat(64))]
        }
    });
    let input = CallInput {
        selectors: json!({}),
        query: json!({}),
        body: Some(json!({
            "name":"least-privilege user token",
            "policies":[{
                "effect":"allow",
                "permission_groups":[{"id":"group-a"}],
                "resources":{"com.cloudflare.api.account.account-a":"*"}
            }]
        })),
        ..CallInput::default()
    };
    validate_api_token_creation_contract(&user_capability, &input, &user_adapter, "account-a")
        .expect("user-owned account-scoped token uses the user inventory");

    let mut wrong_owner_inventory = user_adapter.clone();
    wrong_owner_inventory["permission_inventory"]["source_capability_id"] =
        json!("account-api-tokens-list-permission-groups");
    let wrong_owner = validate_api_token_creation_contract(
        &user_capability,
        &input,
        &wrong_owner_inventory,
        "account-a",
    )
    .expect_err("user-owned token cannot borrow an account-owned permission inventory");
    assert!(
        wrong_owner
            .to_string()
            .contains("permission-groups-list-permission-groups")
    );

    let zone_only_groups = json!([{
        "id": "group-a",
        "name": "DNS Write",
        "scopes": ["com.cloudflare.api.account.zone"]
    }]);
    let zone_only_adapter = json!({
        "permission_inventory": {
            "source_capability_id": "permission-groups-list-permission-groups",
            "selected_groups": zone_only_groups,
            "selected_groups_hash": hash_value(&zone_only_groups).expect("zone group hash"),
            "evidence_hashes": [format!("sha256:{}", "c".repeat(64))]
        }
    });
    let incompatible = validate_api_token_creation_contract(
        &user_capability,
        &input,
        &zone_only_adapter,
        "account-a",
    )
    .expect_err("zone-only permission cannot be attached to an account resource");
    assert!(
        incompatible
            .to_string()
            .contains("does not support the required resource scope `com.cloudflare.api.account`"),
        "{incompatible}"
    );
}

#[test]
pub(super) fn token_permission_precondition_rejects_renamed_or_rescoped_groups() {
    let selected = json!([{
        "id":"group-a",
        "name":"Workers Scripts Write",
        "scopes":["com.cloudflare.api.account"]
    }]);
    let contract = json!({
        "selected_groups": selected,
        "selected_groups_hash": hash_value(&selected).expect("selected hash")
    });
    validate_current_permission_groups(
        &contract,
        &json!([{
            "id":"group-a",
            "name":"Workers Scripts Write",
            "scopes":["com.cloudflare.api.account"]
        }]),
    )
    .expect("unchanged permission group passes");

    for drifted in [
        json!([{
            "id":"group-a",
            "name":"Workers Scripts Administrator",
            "scopes":["com.cloudflare.api.account"]
        }]),
        json!([{
            "id":"group-a",
            "name":"Workers Scripts Write",
            "scopes":["com.cloudflare.api.account", "com.cloudflare.api.user"]
        }]),
    ] {
        let error = validate_current_permission_groups(&contract, &drifted)
            .expect_err("permission metadata drift is rejected");
        assert!(error.to_string().contains("drifted after planning"));
    }
}

#[test]
pub(super) fn standing_authority_inventory_validation_binds_complete_allowlist_metadata() {
    let approved_inventory = json!([
        {
            "id":"group-b",
            "name":"Account Settings Read",
            "scopes":["com.cloudflare.api.account"]
        },
        {
            "id":"group-a",
            "name":"Workers Scripts Write",
            "scopes":["com.cloudflare.api.zone", "com.cloudflare.api.account"],
            "category":"workers"
        }
    ]);
    let approved_groups = validate_selected_permission_groups(
        &["group-a".to_owned(), "group-b".to_owned()],
        &approved_inventory,
    )
    .expect("approved groups normalize");
    let authority = StandingAuthorityV1::draft(
        "account-a",
        None,
        vec!["account-api-tokens-create-token".to_owned()],
        vec!["group-a".to_owned(), "group-b".to_owned()],
        &hash_value(&serde_json::to_value(&approved_groups).expect("approved groups JSON"))
            .expect("approved inventory hash"),
        24,
        "cf-rotation-",
        2,
        Utc::now() + ChronoDuration::days(30),
    )
    .expect("authority draft");

    validate_standing_authority_permission_inventory(
        &authority,
        &json!([
            {
                "id":"unrelated",
                "name":"Unrelated Addition",
                "scopes":["com.cloudflare.api.account"]
            },
            {
                "id":"group-a",
                "name":"Workers Scripts Write",
                "scopes":["com.cloudflare.api.account", "com.cloudflare.api.zone"],
                "category":"workers"
            },
            {
                "id":"group-b",
                "name":"Account Settings Read",
                "scopes":["com.cloudflare.api.account"]
            }
        ]),
    )
    .expect("reordering and unrelated additions preserve the approved allowlist");

    for drifted in [
        json!([
            {"id":"group-a","name":"Workers Scripts Admin","scopes":["com.cloudflare.api.account","com.cloudflare.api.zone"],"category":"workers"},
            {"id":"group-b","name":"Account Settings Read","scopes":["com.cloudflare.api.account"]}
        ]),
        json!([
            {"id":"group-a","name":"Workers Scripts Write","scopes":["com.cloudflare.api.account"],"category":"workers"},
            {"id":"group-b","name":"Account Settings Read","scopes":["com.cloudflare.api.account"]}
        ]),
        json!([
            {"id":"group-a","name":"Workers Scripts Write","scopes":["com.cloudflare.api.account","com.cloudflare.api.zone"],"category":"different"},
            {"id":"group-b","name":"Account Settings Read","scopes":["com.cloudflare.api.account"]}
        ]),
        json!([
            {"id":"group-a","name":"Workers Scripts Write","scopes":["com.cloudflare.api.account","com.cloudflare.api.zone"],"category":"workers"}
        ]),
        json!([
            {"id":"group-a","name":"Workers Scripts Write","scopes":["com.cloudflare.api.account","com.cloudflare.api.zone"],"category":"workers"},
            {"id":"group-a","name":"Duplicate","scopes":["com.cloudflare.api.account"]},
            {"id":"group-b","name":"Account Settings Read","scopes":["com.cloudflare.api.account"]}
        ]),
    ] {
        let error = validate_standing_authority_permission_inventory(&authority, &drifted)
            .expect_err("approved allowlist drift fails closed");
        assert!(
            error.to_string().contains("permission") || error.to_string().contains("inventory"),
            "{error}"
        );
    }
}

#[test]
pub(super) fn guide_names_exact_blockers_and_never_suggests_executing_a_blocked_call() {
    let mut capability = CapabilityV1::new(
        "widgets-update",
        "Update widget",
        "PATCH",
        "/accounts/{account_id}/widgets/{widget_id}",
    );
    capability.product = "Widgets".to_owned();
    capability.adapter_status = AdapterStatus::Blocked;
    capability.blocked_reason = Some(
        "operation contract incomplete: operation-specific incremental cost is unknown".to_owned(),
    );
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
            name: "widget_id".to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        },
    ];
    capability.request_schema = Some(json!({
        "type":"object",
        "x-cfctl-body-required":true,
        "properties":{"enabled":{"type":"boolean"}}
    }));

    let guide = guide_json(&capability);

    assert_eq!(guide["contract_state"], "blocked");
    assert!(guide["blocking_gaps"].as_array().is_some_and(|gaps| {
        gaps.iter().any(|gap| {
            gap.as_str()
                .is_some_and(|gap| gap.contains("incremental cost"))
        })
    }));
    assert!(guide["call_argv"].is_null());
    let stages = guide["stages"].as_array().expect("guide stages");
    assert_eq!(stages.len(), 15);
    assert_eq!(stages[3]["name"], "check_entitlement");
    assert_eq!(stages[7]["name"], "calculate_cost");
    assert_eq!(stages[7]["contract_state"], "blocked");
    assert_eq!(stages[8]["name"], "build_plan");
    assert_eq!(stages[8]["contract_state"], "blocked");
    assert_eq!(stages[8]["commands"], json!([]));
    assert_eq!(
        guide["post_resolution_call_argv"],
        json!([
            "cfctl",
            "call",
            "widgets-update",
            "--selector",
            "account_id=<account_id>",
            "--selector",
            "widget_id=<widget_id>",
            "--body-stdin",
            "--json"
        ])
    );
}

#[test]
pub(super) fn guide_binds_the_declared_ceiling_for_a_known_paid_operation() {
    let mut capability = CapabilityV1::new(
        "r2-create-bucket",
        "Create R2 bucket",
        "POST",
        "/accounts/{account_id}/r2/buckets",
    );
    capability.product = "R2".to_owned();
    capability.adapter_status = AdapterStatus::DynamicApi;
    capability.risk = RiskClass::ScopedWrite;
    capability.effect = EffectClass::ReversibleWrite;
    capability.permissions = vec!["Workers R2 Storage Write".to_owned()];
    capability.cost.incremental = true;
    capability.cost.currency = Some("USD".to_owned());
    capability.cost.maximum = Some(0.000_009);
    capability.cost.known = true;
    capability.entitlement.available = Some(true);
    capability.verification.strategy = "created_resource_detail_matches".to_owned();
    capability.rollback.supported = true;
    capability.rollback.strategy = Some("delete newly created empty bucket".to_owned());
    capability.request_schema = Some(json!({
        "type":"object",
        "x-cfctl-body-required":true,
        "properties":{"name":{"type":"string"}}
    }));

    assert_eq!(
        guide_stage_commands(
            cfctl_core::GuideStage::RequestApproval,
            &capability,
            cfctl_core::GuideContractStateV1::Available,
            None,
        ),
        vec![
            [
                "cfctl",
                "plans",
                "approve",
                "<operation-id>",
                "--yes",
                "--max-cost",
                "USD:0.000009",
                "--json"
            ]
            .map(str::to_owned)
            .to_vec()
        ]
    );
}

#[test]
pub(super) fn guide_requests_optional_meaningful_bodies_without_prompting_for_empty_objects() {
    let mut queue_update = CapabilityV1::new(
        "queues-update-partial",
        "Update Queue configuration",
        "PATCH",
        "/accounts/{account_id}/queues/{queue_id}",
    );
    queue_update.request_schema = Some(json!({
        "type":"object",
        "x-cfctl-body-required":false,
        "properties":{
            "settings":{
                "type":"object",
                "properties":{"delivery_paused":{"type":"boolean"}}
            }
        }
    }));

    let queue_argv = capability_call_argv(&queue_update);
    assert!(queue_argv.iter().any(|argument| argument == "--body-stdin"));

    let mut empty_object = CapabilityV1::new(
        "widgets-touch",
        "Touch widget",
        "POST",
        "/accounts/{account_id}/widgets/{widget_id}/touch",
    );
    empty_object.request_schema = Some(json!({
        "type":"object",
        "x-cfctl-body-required":false,
        "properties":{}
    }));
    let empty_argv = capability_call_argv(&empty_object);
    assert!(!empty_argv.iter().any(|argument| argument == "--body-stdin"));

    for request_schema in [
        json!({"type":"array", "items":{"type":"string"}}),
        json!({"type":"string"}),
    ] {
        let mut capability = CapabilityV1::new(
            "widgets-import",
            "Import widgets",
            "POST",
            "/accounts/{account_id}/widgets/import",
        );
        capability.request_schema = Some(request_schema);
        let argv = capability_call_argv(&capability);
        assert!(argv.iter().any(|argument| argument == "--body-stdin"));
    }
}

#[test]
pub(super) fn guide_does_not_pretend_an_ambiguous_account_subscription_proves_entitlement() {
    let mut capability = CapabilityV1::new(
        "account-widgets-create",
        "Create account widget",
        "POST",
        "/accounts/{account_id}/widgets",
    );
    capability.product = "Widgets".to_owned();
    capability.adapter_status = AdapterStatus::Blocked;
    capability.entitlement.plans = BTreeMap::from([
        ("free".to_owned(), false),
        ("pro".to_owned(), true),
        ("business".to_owned(), true),
        ("enterprise".to_owned(), true),
    ]);
    capability.entitlement.blocker = Some(
            "live account entitlement resolution is unsupported because the official plan matrix has no product-scoped subscription join key"
                .to_owned(),
        );
    capability.blocked_reason = Some(format!(
        "operation contract incomplete: {}",
        capability.entitlement.blocker.as_deref().expect("blocker")
    ));

    let guide = guide_json(&capability);

    assert_eq!(guide["contract_state"], "blocked");
    assert!(
        guide["next_action"]["summary"]
            .as_str()
            .is_some_and(|summary| {
                summary.contains("cannot safely map")
                    && summary.contains("product-scoped subscription")
            })
    );
    assert_eq!(guide["next_action"]["argv"][1], "docs");
    assert!(guide["call_argv"].is_null());
}

#[test]
pub(super) fn token_creation_guide_routes_through_the_inventory_bound_keys_workflow() {
    let mut account_token = CapabilityV1::new(
        "account-api-tokens-create-token",
        "Create account token",
        "POST",
        "/accounts/{account_id}/tokens",
    );
    account_token.risk = RiskClass::SecretSensitive;
    account_token.effect = cfctl_core::EffectClass::IdentityOrOwnership;
    account_token.cost.known = true;
    account_token.verification.strategy =
        "api_token_details_match_created_id_and_active_status".to_owned();
    account_token.rollback.warning = Some("revoke the new token if installation fails".to_owned());
    account_token.permissions = vec!["API Tokens Write".to_owned()];

    let account_guide = guide_json(&account_token);
    assert_eq!(account_guide["contract_state"], "available");
    assert_eq!(
        account_guide["call_argv"],
        json!([
            "cfctl",
            "keys",
            "mint",
            "--name",
            "<token-name>",
            "--permission",
            "<permission-group-id>",
            "--account",
            "<account_id>",
            "--value-out",
            "<new-mode-0600-path>",
            "--json"
        ])
    );
    assert_ne!(account_guide["call_argv"][1], "call");

    account_token.id = "user-api-tokens-create-token".to_owned();
    let user_guide = guide_json(&account_token);
    assert_eq!(user_guide["contract_state"], "available");
    assert_eq!(
        user_guide["call_argv"],
        json!([
            "cfctl",
            "keys",
            "mint",
            "--user",
            "--name",
            "<token-name>",
            "--permission",
            "<permission-group-id>",
            "--account",
            "<account_id>",
            "--value-out",
            "<new-mode-0600-path>",
            "--json"
        ])
    );
}
