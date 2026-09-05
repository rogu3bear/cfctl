use super::*;

#[test]
pub(super) fn mint_scope_contradictions_resolve_before_any_network_read() {
    // key_mint resolves the requested scope before the live inventory
    // call. When this ran after the read instead, `--user --zone` came
    // back as an inventory failure — the wrong problem, reported only
    // after spending a live call to reach it.
    let zone = "4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b";
    let arguments = |user: bool, zone: Option<&str>| KeyMutationArgs {
        profile: None,
        user,
        name: "proof".to_owned(),
        permissions: vec!["group-a".to_owned()],
        account: Some("account-a".to_owned()),
        zone: zone.map(str::to_owned),
        ttl_hours: Some(1),
        value_out: None,
        under_policy: None,
    };

    let (scope, resource) = resolve_mint_token_scope(&arguments(false, Some(zone)), "account-a")
        .expect("account-owned zone minting resolves");
    assert_eq!(scope, "com.cloudflare.api.account.zone");
    assert_eq!(resource, format!("com.cloudflare.api.account.zone.{zone}"));

    let denied = resolve_mint_token_scope(&arguments(true, Some(zone)), "account-a")
        .expect_err("zone minting is account-owned");
    assert!(
        denied.to_string().contains("omit --user"),
        "the error must name the contradiction, not an inventory failure: {denied}"
    );

    let malformed = resolve_mint_token_scope(&arguments(false, Some("NOT-A-ZONE")), "account-a")
        .expect_err("zone ids are validated before use");
    assert!(
        malformed.to_string().contains("32-character"),
        "{malformed}"
    );

    // No zone: the account resource, and --user stays legal.
    let (scope, resource) =
        resolve_mint_token_scope(&arguments(true, None), "account-a").expect("user-owned mint");
    assert_eq!(scope, "com.cloudflare.api.account");
    assert_eq!(resource, "com.cloudflare.api.account.account-a");
}

#[test]
pub(super) fn standing_authority_group_scopes_follow_the_zone_bound() {
    let account_group = json!({"id": "g-account", "scopes": ["com.cloudflare.api.account"]});
    let zone_group = json!({"id": "g-zone", "scopes": ["com.cloudflare.api.account.zone"]});
    let unrelated = json!({"id": "g-user", "scopes": ["com.cloudflare.api.user"]});

    // Without a zone bound the authority stays account-only, so a
    // zone-only group would be unmintable and is refused at draft time.
    validate_standing_authority_group_scopes(std::slice::from_ref(&account_group), None)
        .expect("account groups are always acceptable");
    assert!(
        validate_standing_authority_group_scopes(std::slice::from_ref(&zone_group), None).is_err(),
        "a zone-only group needs the authority to pin a zone"
    );

    // With a zone bound both scopes are bindable.
    let zone = Some("4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b");
    validate_standing_authority_group_scopes(&[account_group.clone(), zone_group.clone()], zone)
        .expect("mixed account and zone groups are acceptable under a zone bound");
    assert!(
        validate_standing_authority_group_scopes(&[unrelated], zone).is_err(),
        "a group supporting neither scope is refused"
    );
}

#[test]
pub(super) fn wrangler_subprocesses_pin_to_the_reviewed_config_directory() {
    assert_eq!(
        wrangler_config_directory("/srv/jkca-web-home/wrangler.toml").expect("nested config"),
        PathBuf::from("/srv/jkca-web-home")
    );
    assert_eq!(
        wrangler_config_directory("workers/api/wrangler.jsonc").expect("relative config"),
        PathBuf::from("workers/api")
    );
    // A bare filename has an empty parent; the subprocess must still get a
    // usable directory rather than inheriting cfctl's own cwd implicitly.
    assert_eq!(
        wrangler_config_directory("wrangler.toml").expect("bare config"),
        PathBuf::from(".")
    );
    assert!(wrangler_config_directory("/").is_err());
}

#[test]
pub(super) fn workspace_plan_pins_ignore_unrelated_repositories_but_bind_the_selected_artifact() {
    let root = tempfile::tempdir().expect("runtime root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let windowdrop = root.path().join("windowdrop");
    let unrelated = root.path().join("unrelated");
    for repository in [&windowdrop, &unrelated] {
        fs::create_dir_all(repository.join("serve")).expect("repository directories");
        StdCommand::new("git")
            .args(["init", "--quiet"])
            .current_dir(repository)
            .status()
            .expect("git init");
    }
    fs::write(windowdrop.join("serve/index.html"), "windowdrop-v1").expect("WindowDrop artifact");
    fs::write(
        unrelated.join("wrangler.toml"),
        "name = \"unrelated\"\nmain = \"src/index.js\"\n",
    )
    .expect("unrelated config");
    for repository in [&windowdrop, &unrelated] {
        StdCommand::new("git")
            .args(["add", "."])
            .current_dir(repository)
            .status()
            .expect("git add");
        StdCommand::new("git")
            .args([
                "-c",
                "user.name=cfctl test",
                "-c",
                "user.email=cfctl-test@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "fixture",
            ])
            .current_dir(repository)
            .status()
            .expect("git commit");
    }
    store
        .register_workspace(&windowdrop, None)
        .expect("register WindowDrop");
    store
        .register_workspace(&unrelated, None)
        .expect("register unrelated repository");

    let repositories = vec![
        fs::canonicalize(&windowdrop)
            .expect("canonical WindowDrop")
            .display()
            .to_string(),
    ];
    let artifacts = vec![windowdrop.join("serve")];
    let before = workspace_precondition_hashes_for_scope(&store, &repositories, &artifacts)
        .expect("initial scoped pins");

    fs::write(
        unrelated.join("wrangler.toml"),
        "name = \"unrelated-changed\"\nmain = \"src/index.js\"\n",
    )
    .expect("mutate unrelated config");
    fs::write(unrelated.join("untracked.txt"), "unrelated dirt")
        .expect("mutate unrelated Git state");
    let after_unrelated_change =
        workspace_precondition_hashes_for_scope(&store, &repositories, &artifacts)
            .expect("pins after unrelated change");
    assert_eq!(before, after_unrelated_change);

    fs::write(windowdrop.join("serve/index.html"), "windowdrop-v2")
        .expect("mutate selected artifact");
    let after_artifact_change =
        workspace_precondition_hashes_for_scope(&store, &repositories, &artifacts)
            .expect("pins after artifact change");
    assert_ne!(before, after_artifact_change);
}

#[test]
pub(super) fn governed_wrangler_subprocesses_pin_account_and_external_cache() {
    let environment = governed_cli_workspace_env(
        "wrangler",
        Some("account-a"),
        PathBuf::from("/platform/cache").as_path(),
    );
    assert_eq!(
        environment,
        vec![
            (
                "WRANGLER_CACHE_DIR",
                PathBuf::from("/platform/cache/wrangler").into_os_string()
            ),
            (
                "CLOUDFLARE_ACCOUNT_ID",
                std::ffi::OsString::from("account-a")
            ),
        ]
    );
    assert!(
        governed_cli_workspace_env(
            "cloudflared",
            Some("account-a"),
            PathBuf::from("/platform/cache").as_path(),
        )
        .is_empty(),
        "non-Wrangler subprocesses must not inherit Wrangler-specific state"
    );
    assert_eq!(
        governed_cli_environment_contract(PathBuf::from("/platform/cache").as_path()),
        json!({
            "schema_version": 1,
            "wrangler": {
                "account_binding": "selected_cfctl_account",
                "account_env": "CLOUDFLARE_ACCOUNT_ID",
                "cache_binding": "cfctl_platform_cache",
                "cache_env": "WRANGLER_CACHE_DIR",
                "cache_dir": "/platform/cache/wrangler",
                "survives_env_clear": true,
            },
        })
    );
}

#[test]
pub(super) fn secret_payload_redaction_mirrors_the_core_set() {
    // Every field `cfctl-core` marks secret must be sunk by the payload
    // redactor, and a non-secret sibling must survive untouched. Binding
    // the redactor to `SECRET_FIELD_NAMES` keeps the two provably mirrored.
    let mut object = serde_json::Map::new();
    for name in SECRET_FIELD_NAMES {
        object.insert((*name).to_owned(), json!("live-secret"));
    }
    object.insert("account_id".to_owned(), json!("acct-123"));
    let redacted = redact_secret_payload(&Value::Object(object), false);
    for name in SECRET_FIELD_NAMES {
        assert_eq!(redacted[*name], json!("[SUNK]"), "{name} was not sunk");
    }
    assert_eq!(redacted["account_id"], json!("acct-123"));
}

#[test]
pub(super) fn permission_inventory_routes_owner_without_dropping_account_context() {
    let account = permission_inventory_call(&KeyPermissionArgs {
        profile: Some("minter".to_owned()),
        user: false,
        account: "account-a".to_owned(),
    });
    assert_eq!(
        account.capability_id,
        "account-api-tokens-list-permission-groups"
    );
    assert_eq!(
        account.selectors,
        [("account_id".to_owned(), "account-a".to_owned())]
    );
    assert_eq!(account.account.as_deref(), Some("account-a"));
    assert_eq!(account.profile.as_deref(), Some("minter"));

    let user = permission_inventory_call(&KeyPermissionArgs {
        profile: None,
        user: true,
        account: "account-a".to_owned(),
    });
    assert_eq!(
        user.capability_id,
        "permission-groups-list-permission-groups"
    );
    assert!(user.selectors.is_empty());
    assert_eq!(user.account.as_deref(), Some("account-a"));
}

pub(super) fn kv_key_list_response(
    status: u16,
    success: bool,
    keys: Value,
    result_info: Option<Value>,
) -> CloudflareResponseV1 {
    CloudflareResponseV1 {
        status,
        success,
        result: keys,
        errors: Vec::new(),
        result_info,
        etag: None,
        cf_ray: None,
    }
}

#[test]
pub(super) fn kv_empty_namespace_receipt_proves_zero_keys_and_a_complete_list() {
    // The one honest empty case: empty result, count 0, no continuation.
    let receipt = apply_kv_empty_namespace_state_response(
        "account-1",
        "namespace-1",
        &kv_key_list_response(
            200,
            true,
            json!([]),
            Some(json!({"count": 0, "cursor": ""})),
        ),
    )
    .expect("an empty, fully-listed namespace is provable");
    assert_eq!(receipt["key_count"], json!(0));
    assert_eq!(receipt["list_complete"], json!(true));
    assert_eq!(receipt["namespace_id"], json!("namespace-1"));

    // Absent cursor also means complete.
    apply_kv_empty_namespace_state_response(
        "account-1",
        "namespace-1",
        &kv_key_list_response(200, true, json!([]), Some(json!({"count": 0}))),
    )
    .expect("an omitted cursor means the list is complete");
}

#[test]
pub(super) fn kv_empty_namespace_receipt_fails_closed_on_any_non_empty_signal() {
    // A key present in the result array.
    assert!(
        apply_kv_empty_namespace_state_response(
            "account-1",
            "namespace-1",
            &kv_key_list_response(
                200,
                true,
                json!([{"name": "still-here"}]),
                Some(json!({"count": 1, "cursor": ""})),
            ),
        )
        .is_err(),
        "a populated result array must fail closed"
    );
    // Empty array but a non-zero count — trust neither over the other.
    assert!(
        apply_kv_empty_namespace_state_response(
            "account-1",
            "namespace-1",
            &kv_key_list_response(
                200,
                true,
                json!([]),
                Some(json!({"count": 5, "cursor": ""}))
            ),
        )
        .is_err(),
        "a non-zero count must fail closed even with an empty page"
    );
    // Empty page, count 0, but a continuation cursor: the list is truncated.
    assert!(
        apply_kv_empty_namespace_state_response(
            "account-1",
            "namespace-1",
            &kv_key_list_response(
                200,
                true,
                json!([]),
                Some(json!({"count": 0, "cursor": "next-page"})),
            ),
        )
        .is_err(),
        "a remaining cursor means emptiness is not proven"
    );
    // Missing result_info entirely.
    assert!(
        apply_kv_empty_namespace_state_response(
            "account-1",
            "namespace-1",
            &kv_key_list_response(200, true, json!([]), None),
        )
        .is_err(),
        "an absent result_info cannot prove count 0"
    );
    // Cloudflare-side failure.
    assert!(
        apply_kv_empty_namespace_state_response(
            "account-1",
            "namespace-1",
            &kv_key_list_response(200, false, Value::Null, None),
        )
        .is_err(),
        "an unsuccessful read cannot prove emptiness"
    );
}

#[test]
pub(super) fn kv_empty_namespace_gate_is_compensation_and_cfctl_created_only() {
    let mut delete = CapabilityV1::new(
        "workers-kv-namespace-remove-a-namespace",
        "Remove a Namespace",
        "DELETE",
        "/accounts/{account_id}/storage/kv/namespaces/{namespace_id}",
    );
    "Workers KV Namespace".clone_into(&mut delete.product);
    "account".clone_into(&mut delete.account_scope);
    // Blocked status is expected — the gate must still recognize it.
    delete.adapter_status = AdapterStatus::Blocked;

    let full_targets = json!({
        "compensates_capability_id": "workers-kv-namespace-create-a-namespace",
        "compensation_strategy": "delete_created_empty_kv_namespace_by_returned_id_if_unchanged",
        "compensates_operation_id": "11111111-2222-3333-4444-555555555555",
        "source_receipt_hash": "sha256:abc",
    });
    assert!(should_bind_kv_empty_namespace_state(&delete, &full_targets));

    // A direct (non-compensation) delete: no targets, never binds.
    assert!(!should_bind_kv_empty_namespace_state(&delete, &json!({})));

    // Compensating the wrong capability (not KV create) never binds — this
    // is the barrier that keeps arbitrary and production namespaces out.
    let mut wrong = full_targets.clone();
    wrong["compensates_capability_id"] = json!("d1-create-database");
    assert!(!should_bind_kv_empty_namespace_state(&delete, &wrong));

    // Missing source receipt hash never binds.
    let mut no_receipt = full_targets.clone();
    no_receipt["source_receipt_hash"] = json!("not-a-sha");
    assert!(!should_bind_kv_empty_namespace_state(&delete, &no_receipt));
}

#[test]
pub(super) fn kv_cost_resolves_only_with_a_bound_empty_precondition() {
    let mut delete = CapabilityV1::new(
        "workers-kv-namespace-remove-a-namespace",
        "Remove a Namespace",
        "DELETE",
        "/accounts/{account_id}/storage/kv/namespaces/{namespace_id}",
    );
    "Workers KV Namespace".clone_into(&mut delete.product);
    "account".clone_into(&mut delete.account_scope);
    delete.risk = RiskClass::Destructive;
    delete.effect = EffectClass::Irreversible;
    delete.permissions = vec!["Workers KV Storage Write".to_owned()];
    delete.entitlement.available = Some(true);
    delete.rollback.warning = Some("irreversible".to_owned());
    delete.verification.strategy = "same_resource_returns_not_found_after_delete".to_owned();
    delete.same_path_read = Some(SamePathReadContractV1 {
        path: "/accounts/{account_id}/storage/kv/namespaces/{namespace_id}".to_owned(),
        read_capability_id: "workers-kv-namespace-get-a-namespace".to_owned(),
        verified_response_fields: Vec::new(),
    });
    delete.adapter_status = AdapterStatus::Blocked;

    let no_preconditions = || LivePlanPreconditions {
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
        oauth_client_update_state: None,
        worker_custom_domain_state: None,
        worker_deployment_state: None,
    };

    // Without a bound empty precondition, nothing changes.
    let none = no_preconditions();
    let mut untouched = delete.clone();
    resolve_kv_empty_namespace_delete_cost(&mut untouched, &none);
    assert_eq!(untouched.adapter_status, AdapterStatus::Blocked);
    assert!(!untouched.cost.known);

    // With the empty precondition bound, cost resolves to zero and the
    // capability un-blocks for this plan.
    let mut bound = no_preconditions();
    bound.kv_empty_namespace_state = Some((
        json!({"key_count": 0}),
        EvidenceV1::new(
            EvidenceClass::LiveRead,
            "sha256:kv-empty",
            "/managed/evidence/kv-empty.json",
        ),
    ));
    resolve_kv_empty_namespace_delete_cost(&mut delete, &bound);
    assert!(delete.cost.known);
    assert_eq!(delete.cost.maximum, Some(0.0));
    assert_eq!(delete.adapter_status, AdapterStatus::DynamicApi);

    // A different capability with the precondition bound is not touched.
    let mut other = CapabilityV1::new("some-other-delete", "x", "DELETE", "/x/{id}");
    other.adapter_status = AdapterStatus::Blocked;
    resolve_kv_empty_namespace_delete_cost(&mut other, &bound);
    assert_eq!(other.adapter_status, AdapterStatus::Blocked);
}

#[test]
pub(super) fn permission_inventory_rewraps_command_and_maps_403_or_9109() {
    let success_response = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!([]),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let success = permission_inventory_envelope(ResultEnvelopeV2::success(
        "call",
        serde_json::to_value(success_response).expect("response JSON"),
    ));
    assert_eq!(success.command, "keys permissions");
    assert!(success.ok);

    for (status, code) in [(403, None), (400, Some(9109))] {
        let response = CloudflareResponseV1 {
            status,
            success: false,
            result: Value::Null,
            errors: vec![CloudflareApiErrorV1 {
                code,
                message: "forbidden".to_owned(),
            }],
            result_info: None,
            etag: None,
            cf_ray: None,
        };
        let mut envelope = ResultEnvelopeV2::success(
            "call",
            serde_json::to_value(response).expect("response JSON"),
        );
        envelope.ok = false;
        let mapped = permission_inventory_envelope(envelope);
        assert_eq!(mapped.command, "keys permissions");
        assert_eq!(mapped.verification.state, VerificationState::Failed);
        let error = mapped.error.expect("actionable permission error");
        assert_eq!(error.code, "CFCTL_PERMISSION_INVENTORY_FORBIDDEN");
        assert!(error.message.contains("Account API Tokens Read"));
        assert!(error.message.contains("Account API Tokens Write"));
    }
}

pub(super) struct DeleteFailingSecretStore;
pub(super) struct PutFailingSecretStore;

pub(super) struct ProductionOAuthRouteStore {
    pub(super) encoded: Option<String>,
    pub(super) legacy_loads: AtomicUsize,
}

impl ProductionOAuthRouteStore {
    pub(super) fn new(encoded: Option<&str>) -> Self {
        Self {
            encoded: encoded.map(str::to_owned),
            legacy_loads: AtomicUsize::new(0),
        }
    }
}

impl SecretStore for ProductionOAuthRouteStore {
    fn put(&self, _key: &str, _value: &str) -> cfctl_auth::Result<()> {
        Ok(())
    }

    fn get(&self, _key: &str) -> cfctl_auth::Result<Option<String>> {
        Ok(self.encoded.clone())
    }

    fn delete(&self, _key: &str) -> cfctl_auth::Result<()> {
        Ok(())
    }

    fn locate(&self, _key: &str) -> cfctl_auth::Result<Option<cfctl_auth::SecretBackend>> {
        Ok(None)
    }

    fn load_oauth_tokens(
        &self,
        _profile_id: &str,
    ) -> cfctl_auth::Result<cfctl_auth::OAuthTokenSet> {
        self.legacy_loads.fetch_add(1, Ordering::SeqCst);
        Err(AuthError::SecretStore(
            "legacy OAuth loader must not be used".to_owned(),
        ))
    }
}
