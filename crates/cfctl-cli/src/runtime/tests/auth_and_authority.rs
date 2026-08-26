use super::*;

pub(super) fn emergency_global_key_as_current() -> ProfilesConfig {
    let mut profiles = BTreeMap::new();
    profiles.insert(
        "emergency".to_owned(),
        ProfileMetadata::new("emergency", ProfileKind::GlobalKey, None),
    );
    profiles.insert(
        "work".to_owned(),
        ProfileMetadata::new("work", ProfileKind::OAuth, Some("account-a")),
    );
    ProfilesConfig {
        current_profile: Some("emergency".to_owned()),
        profiles,
        ..ProfilesConfig::default()
    }
}

#[test]
pub(super) fn emergency_global_key_is_never_selected_without_an_explicit_profile_flag() {
    let mut profiles = emergency_global_key_as_current();

    let blocked = profiles
        .selected(None)
        .expect_err("implicit global-key current profile must fail closed");
    assert!(
        blocked.to_string().contains("never selected implicitly"),
        "{blocked}"
    );
    profiles
        .selected(Some("emergency"))
        .expect("explicit --profile may use the emergency lane");

    profiles.current_profile = Some("work".to_owned());
    profiles
        .selected(None)
        .expect("non-emergency profiles remain selectable as current");
}

#[tokio::test]
pub(super) async fn execute_read_rejects_implicit_global_key_before_live_credential_use() {
    let root = tempfile::tempdir().expect("runtime root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    emergency_global_key_as_current()
        .save(&store)
        .expect("save emergency as current");

    let capability = CapabilityV1::new("accounts-list", "List accounts", "GET", "/accounts");
    let catalog = test_catalog();
    let input = CallInput::default();

    let error = execute_read(
        &store,
        &catalog,
        &capability,
        &input,
        None,
        None,
        None,
        None,
        None,
    )
    .await
    .expect_err("live read must not use ambient global-key current profile");
    assert!(
        error.to_string().contains("never selected implicitly"),
        "{error}"
    );

    // Explicit --profile is allowed past selection; without a real secret store
    // credential it still fails later — never with an implicit selection path.
    let explicit = execute_read(
        &store,
        &catalog,
        &capability,
        &input,
        Some("emergency"),
        None,
        None,
        None,
        None,
    )
    .await;
    let explicit_error = explicit.expect_err("no real emergency credential in this fixture");
    assert!(
        !explicit_error
            .to_string()
            .contains("never selected implicitly"),
        "explicit --profile must not be blocked by the ambient-selection guard: {explicit_error}"
    );
}

#[tokio::test]
pub(super) async fn call_command_live_read_rejects_implicit_global_key_current_profile() {
    let root = tempfile::tempdir().expect("runtime root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let catalog = test_catalog();
    store
        .write_json(&store.paths().catalog_file(), &catalog)
        .expect("seed non-stale catalog so call does not network-sync");
    emergency_global_key_as_current()
        .save(&store)
        .expect("save emergency as current");

    let error = Box::pin(call_command(
        &store,
        CallArgs {
            capability_id: "accounts-list".to_owned(),
            selectors: Vec::new(),
            query: Vec::new(),
            body_json: None,
            body_stdin: false,
            profile: None,
            account: None,
            if_match: None,
            if_none_match: None,
            value_out: None,
            credential_in: None,
            out: None,
            source_file: None,
        },
    ))
    .await
    .expect_err("call without --profile must fail closed on ambient global-key");
    assert!(
        error.to_string().contains("never selected implicitly"),
        "{error}"
    );
}

#[test]
pub(super) fn store_imported_api_token_selects_scoped_profile_and_keeps_secret_out_of_envelope() {
    let root = tempfile::tempdir().expect("runtime root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let secrets = MemorySecretStore::default();
    let mut profiles = ProfilesConfig::default();
    let token = "cfat_test_token_must_not_echo";

    let envelope = store_imported_api_token(
        &store,
        &mut profiles,
        &secrets,
        "default",
        "account-a",
        token,
    )
    .expect("import api token");
    assert_eq!(envelope.command, "auth import-api-token");
    assert!(envelope.ok);
    assert_eq!(envelope.result["selected"], true);
    assert_eq!(envelope.result["kind"], "api_token");
    assert_eq!(envelope.result["account_id"], "account-a");
    assert_eq!(envelope.result["secret_backend"], "memory");
    let encoded = serde_json::to_string(&envelope).expect("envelope serializes");
    assert!(
        !encoded.contains(token),
        "token must not appear in the result envelope: {encoded}"
    );
    assert_eq!(profiles.current_profile.as_deref(), Some("default"));
    let profile = profiles.profiles.get("default").expect("profile saved");
    assert_eq!(profile.kind, ProfileKind::ApiToken);
    assert_eq!(profile.account_id.as_deref(), Some("account-a"));
    assert!(!profile.emergency_only);
    let initial_generation = profile
        .credential_generation_id
        .clone()
        .expect("import assigns a credential generation");
    assert_eq!(
        secrets
            .load_credential("default", ProfileKind::ApiToken)
            .expect("credential")
            .bearer_token(),
        Some(token)
    );

    store_imported_api_token(
        &store,
        &mut profiles,
        &secrets,
        "default",
        "account-a",
        "cfat_replacement_token",
    )
    .expect("replacement import");
    assert_ne!(
        profiles.profiles["default"]
            .credential_generation_id
            .as_deref(),
        Some(initial_generation.as_str()),
        "credential replacement must not inherit prior proof scope"
    );

    let empty = store_imported_api_token(
        &store,
        &mut ProfilesConfig::default(),
        &secrets,
        "default",
        "account-a",
        "",
    )
    .expect_err("empty token rejected");
    assert!(empty.to_string().contains("API token was empty"));

    let unpinned = store_imported_api_token(
        &store,
        &mut ProfilesConfig::default(),
        &secrets,
        "default",
        "  ",
        token,
    )
    .expect_err("empty account rejected");
    assert!(unpinned.to_string().contains("--account"));
}

#[test]
pub(super) fn credential_unavailable_has_stable_noninteractive_guidance() {
    let error = CliError::Auth(AuthError::CredentialUnavailable {
        profile_id: "audit".to_owned(),
        reason: CredentialUnavailableReason::MissingSelectedFallback,
    });

    assert_eq!(error.code(), "CFCTL_CREDENTIAL_UNAVAILABLE");
    let next_step = error.next_step().expect("credential recovery guidance");
    assert!(
        next_step.contains("selected profile `audit`"),
        "{next_step}"
    );
    assert!(
        next_step.contains("cfctl auth repair-keychain-access audit"),
        "{next_step}"
    );
}

#[tokio::test]
pub(super) async fn production_oauth_reads_use_selected_profile_validation_without_legacy_lookup() {
    let cases = [
        (
            "missing",
            None,
            CredentialUnavailableReason::MissingSelectedFallback,
        ),
        (
            "malformed",
            Some("not-json"),
            CredentialUnavailableReason::Malformed,
        ),
        (
            "empty",
            Some(
                r#"{"access_token":" ","refresh_token":null,"token_type":"bearer","expires_in":null,"expires_at":null,"scope":null}"#,
            ),
            CredentialUnavailableReason::Invalid,
        ),
        (
            "expired-without-refresh",
            Some(
                r#"{"access_token":"expired-token","refresh_token":null,"token_type":"bearer","expires_in":null,"expires_at":"2000-01-01T00:00:00Z","scope":null}"#,
            ),
            CredentialUnavailableReason::Expired,
        ),
    ];

    for (name, encoded, expected_reason) in cases {
        let store = ProductionOAuthRouteStore::new(encoded);
        let profile = ProfileMetadata::new("audit", ProfileKind::OAuth, Some("account-a"));

        let error = fresh_credential(&profile, &store).await.expect_err(name);

        assert!(
            matches!(
                error,
                CliError::Auth(AuthError::CredentialUnavailable {
                    reason,
                    ..
                }) if reason == expected_reason
            ),
            "{name}: {error}"
        );
        assert_eq!(error.code(), "CFCTL_CREDENTIAL_UNAVAILABLE", "{name}");
        assert!(
            error
                .next_step()
                .is_some_and(|step| step.contains("selected profile `audit`")),
            "{name}: expected noninteractive selected-profile guidance"
        );
        assert_eq!(
            store.legacy_loads.load(Ordering::SeqCst),
            0,
            "{name}: production OAuth read must not use the legacy loader"
        );
    }
}

#[test]
pub(super) fn explicit_keychain_repair_warns_before_access() {
    let secrets = MemorySecretStore::default();
    secrets
        .store_api_token("audit", "opaque-token")
        .expect("seed credential");
    let mut profiles = ProfilesConfig::default();
    profiles.profiles.insert(
        "audit".to_owned(),
        ProfileMetadata::new("audit", ProfileKind::ApiToken, Some("account-a")),
    );
    let selector = ProfileSelector {
        profile: "audit".to_owned(),
    };
    let mut warnings = Vec::new();

    let envelope =
        repair_keychain_access_with_warning(&profiles, &secrets, &selector, &mut warnings)
            .expect("explicit repair");

    assert!(envelope.ok);
    assert_eq!(warnings, KEYCHAIN_REPAIR_WARNING.as_bytes());
    assert!(!String::from_utf8_lossy(&warnings).contains("opaque-token"));
}

#[test]
pub(super) fn failed_credential_install_leaves_profile_unbound_instead_of_reusing_old_proof_scope()
{
    let root = tempfile::tempdir().expect("runtime root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let mut profiles = ProfilesConfig::default();
    let old_profile = ProfileMetadata::new("default", ProfileKind::ApiToken, Some("account-a"));
    let old_generation = old_profile
        .credential_generation_id
        .clone()
        .expect("old profile generation");
    profiles.profiles.insert("default".to_owned(), old_profile);
    profiles.current_profile = Some("default".to_owned());
    profiles.save(&store).expect("old profile persists");

    let error = store_imported_api_token(
        &store,
        &mut profiles,
        &PutFailingSecretStore,
        "default",
        "account-a",
        "cfat_replacement_token",
    )
    .expect_err("injected credential-store failure");
    assert!(error.to_string().contains("injected put failure"));

    let persisted = ProfilesConfig::load(&store).expect("pending profile reloads");
    assert_eq!(persisted.current_profile.as_deref(), Some("default"));
    assert!(
        persisted.profiles["default"]
            .credential_generation_id
            .is_none(),
        "a partial replacement must fail closed instead of preserving {old_generation}"
    );
}

#[test]
pub(super) fn proof_bearing_reads_reject_missing_or_malformed_credential_generations() {
    let mut profile = ProfileMetadata::new("default", ProfileKind::ApiToken, Some("account-a"));
    profile.credential_generation_id = None;
    assert!(
        credential_generation_for_read(&profile)
            .expect_err("missing generation")
            .to_string()
            .contains("has no credential generation")
    );

    profile.credential_generation_id = Some("not-a-uuid".to_owned());
    assert!(
        credential_generation_for_read(&profile)
            .expect_err("malformed generation")
            .to_string()
            .contains("invalid credential generation")
    );
}

#[test]
pub(super) fn authority_listings_show_the_scope_being_approved() {
    // The enforcement was right and well covered; what shipped broken was
    // that `keys policy list` told the operator to "review the bounds"
    // without printing the zone bound. Assert the scope is visible
    // wherever an authority is inspected.
    let root = tempfile::tempdir().expect("runtime root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let zone = "4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b";
    let authority = StandingAuthorityV1::draft(
        "account-a",
        Some(zone),
        vec!["account-api-tokens-create-token".to_owned()],
        vec!["group-a".to_owned()],
        "sha256:inventory-binding",
        24,
        "cf-rotation-",
        2,
        Utc::now() + ChronoDuration::days(30),
    )
    .expect("zone-bounded draft");
    store.save_authority(&authority).expect("persist draft");

    let listed = key_policy_list(&store).expect("list authorities");
    let entry = &listed.result["authorities"][0];
    assert_eq!(entry["zone_id"], json!(zone));
    assert_eq!(
        entry["bound_resources"],
        json!([
            "com.cloudflare.api.account.account-a",
            format!("com.cloudflare.api.account.zone.{zone}"),
        ]),
        "an approver must see every resource a child could bind"
    );

    // An account-scoped authority reports a null zone and the account
    // resource alone, so the absence of a zone bound is explicit.
    let account_only = StandingAuthorityV1::draft(
        "account-b",
        None,
        vec!["account-api-tokens-create-token".to_owned()],
        vec!["group-a".to_owned()],
        "sha256:inventory-binding",
        24,
        "cf-rotation-",
        2,
        Utc::now() + ChronoDuration::days(30),
    )
    .expect("account-only draft");
    store.save_authority(&account_only).expect("persist draft");
    let listed = key_policy_list(&store).expect("list authorities");
    let entry = listed.result["authorities"]
        .as_array()
        .expect("authorities")
        .iter()
        .find(|entry| entry["account_id"] == json!("account-b"))
        .expect("account-only authority listed");
    assert_eq!(entry["zone_id"], Value::Null);
    assert_eq!(
        entry["bound_resources"],
        json!(["com.cloudflare.api.account.account-b"])
    );
}

#[test]
pub(super) fn standing_authority_lifecycle_approves_lists_and_revokes_offline() {
    let root = tempfile::tempdir().expect("runtime root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let authority = StandingAuthorityV1::draft(
        "account-a",
        None,
        vec!["account-api-tokens-create-token".to_owned()],
        vec!["group-a".to_owned()],
        "sha256:inventory-binding",
        24,
        "cf-rotation-",
        2,
        Utc::now() + ChronoDuration::days(30),
    )
    .expect("authority draft");
    let authority_id = authority.authority_id.clone();
    store.save_authority(&authority).expect("persist draft");

    let denied = key_policy_approve(
        &store,
        &KeyPolicyApproveArgs {
            authority_id: authority_id.clone(),
            yes: false,
        },
    )
    .expect_err("approval requires an explicit yes");
    assert!(denied.to_string().contains("explicit yes"), "{denied}");

    let approved = key_policy_approve(
        &store,
        &KeyPolicyApproveArgs {
            authority_id: authority_id.clone(),
            yes: true,
        },
    )
    .expect("explicit approval activates");
    assert_eq!(approved.result["status"], "active");

    let listed = key_policy_list(&store).expect("list authorities");
    assert_eq!(
        listed.result["authorities"][0]["authority_id"],
        serde_json::json!(authority_id)
    );
    assert_eq!(listed.result["authorities"][0]["status"], "active");
    assert_eq!(listed.result["authorities"][0]["runs_last_24h"], 0);
    assert_eq!(listed.result["authorities"][0]["runs_remaining_24h"], 2);
    assert_eq!(
        listed.result["authorities"][0]["minted_token_ids"],
        json!([])
    );
    assert!(
        listed.result["authorities"][0]["next_action"]
            .as_str()
            .is_some_and(|action| action.contains("--under-policy"))
    );

    preflight_standing_authority(&store, Some(&authority_id))
        .expect("active authority passes preflight");
    assert!(
        preflight_standing_authority(&store, Some("ghost")).is_err(),
        "unknown authorities fail closed before any network"
    );

    let revoked = key_policy_revoke(
        &store,
        &KeyPolicySelector {
            authority_id: authority_id.clone(),
        },
    )
    .expect("revocation is unconditional");
    assert_eq!(revoked.result["status"], "revoked");
    assert!(
        preflight_standing_authority(&store, Some(&authority_id)).is_err(),
        "revoked authorities fail preflight immediately"
    );
}

#[test]
pub(super) fn standing_authority_list_reports_effective_expiry() {
    let root = tempfile::tempdir().expect("runtime root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let expired = StandingAuthorityV1::draft(
        "account-a",
        None,
        vec!["account-api-tokens-create-token".to_owned()],
        vec!["group-a".to_owned()],
        "sha256:inventory-binding",
        24,
        "cf-rotation-",
        2,
        Utc::now() - ChronoDuration::seconds(1),
    )
    .expect("expired authority draft remains inspectable");
    store
        .create_authority(&expired)
        .expect("persist expired authority");

    let listed = key_policy_list(&store).expect("list authorities");

    assert_eq!(listed.result["authorities"][0]["status"], "expired");
}

#[test]
pub(super) fn approval_and_revocation_race_cannot_resurrect_an_authority() {
    let root = tempfile::tempdir().expect("runtime root");
    let paths = RuntimePaths::from_root(root.path());
    let store = StateStore::open(paths.clone()).expect("state store");
    let authority = StandingAuthorityV1::draft(
        "account-a",
        None,
        vec!["account-api-tokens-create-token".to_owned()],
        vec!["group-a".to_owned()],
        "sha256:inventory-binding",
        24,
        "cf-rotation-",
        2,
        Utc::now() + ChronoDuration::days(30),
    )
    .expect("authority draft");
    let authority_id = authority.authority_id.clone();
    store
        .create_authority(&authority)
        .expect("persist pending authority");
    let barrier = Arc::new(Barrier::new(2));

    let approve = {
        let paths = paths.clone();
        let barrier = Arc::clone(&barrier);
        let authority_id = authority_id.clone();
        thread::spawn(move || {
            let store = StateStore::open(paths).expect("approval store");
            barrier.wait();
            key_policy_approve(
                &store,
                &KeyPolicyApproveArgs {
                    authority_id,
                    yes: true,
                },
            )
        })
    };
    let revoke = {
        let paths = paths.clone();
        let barrier = Arc::clone(&barrier);
        let authority_id = authority_id.clone();
        thread::spawn(move || {
            let store = StateStore::open(paths).expect("revocation store");
            barrier.wait();
            key_policy_revoke(&store, &KeyPolicySelector { authority_id })
        })
    };

    let _approval_result = approve.join().expect("approval thread joins");
    revoke
        .join()
        .expect("revocation thread joins")
        .expect("revocation always commits");
    let durable = store
        .load_authority(&authority_id)
        .expect("durable authority reloads");
    assert_eq!(durable.status, StandingAuthorityStatus::Revoked);
}

pub(super) fn active_standing_authority(max_runs_per_day: u32) -> StandingAuthorityV1 {
    let mut authority = StandingAuthorityV1::draft(
        "account-a",
        None,
        vec![
            "account-api-tokens-create-token".to_owned(),
            "account-api-tokens-delete-token".to_owned(),
        ],
        vec!["group-a".to_owned()],
        "sha256:inventory-binding",
        24,
        "cf-rotation-",
        max_runs_per_day,
        Utc::now() + ChronoDuration::days(30),
    )
    .expect("authority draft");
    authority.approve(true).expect("authority approval");
    authority
}

pub(super) fn standing_mint_plan() -> (PlanV1, CallInput) {
    let mut capability = CapabilityV1::new(
        "account-api-tokens-create-token",
        "Create account token",
        "POST",
        "/accounts/{account_id}/tokens",
    );
    capability.risk = RiskClass::SecretSensitive;
    let plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
        json!({}),
    )
    .expect("standing mint plan");
    let input = CallInput {
        selectors: json!({"account_id":"account-a"}),
        query: json!({}),
        body: Some(json!({
            "name":"cf-rotation-child",
            "expires_on":(Utc::now() + ChronoDuration::hours(1)).to_rfc3339(),
            "policies":[{
                "effect":"allow",
                "permission_groups":[{"id":"group-a"}],
                "resources":{"com.cloudflare.api.account.account-a":"*"}
            }]
        })),
        ..CallInput::default()
    };
    (plan, input)
}

#[test]
pub(super) fn standing_admission_serializes_one_run_budget_across_two_stores() {
    let root = tempfile::tempdir().expect("runtime root");
    let paths = RuntimePaths::from_root(root.path());
    let store = StateStore::open(paths.clone()).expect("state store");
    let mut authority = StandingAuthorityV1::draft(
        "account-a",
        None,
        vec!["account-api-tokens-create-token".to_owned()],
        vec!["group-a".to_owned()],
        "sha256:inventory-binding",
        24,
        "cf-rotation-",
        1,
        Utc::now() + ChronoDuration::days(30),
    )
    .expect("authority draft");
    authority.approve(true).expect("authority approval");
    store
        .create_authority(&authority)
        .expect("persist authority");
    let (plan_a, input_a) = standing_mint_plan();
    let (plan_b, input_b) = standing_mint_plan();
    let operation_ids = [plan_a.operation_id.clone(), plan_b.operation_id.clone()];
    store.save_plan(&plan_a).expect("persist plan A");
    store.save_plan(&plan_b).expect("persist plan B");

    let barrier = Arc::new(Barrier::new(2));
    let handles = [(plan_a, input_a), (plan_b, input_b)]
        .into_iter()
        .map(|(mut plan, input)| {
            let paths = paths.clone();
            let barrier = Arc::clone(&barrier);
            let snapshot = authority.clone();
            thread::spawn(move || {
                let store = StateStore::open(paths).expect("second store");
                barrier.wait();
                admit_standing_plan(&store, &mut plan, &snapshot, &input)
            })
        })
        .collect::<Vec<_>>();
    let results = handles
        .into_iter()
        .map(|handle| handle.join().expect("admission thread"))
        .collect::<Vec<_>>();

    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    let stored = store
        .load_authority(&authority.authority_id)
        .expect("stored authority");
    assert_eq!(stored.run_log.len(), 1);
    assert_eq!(stored.runs_in_last_day(Utc::now()), 1);
    let consumed = operation_ids
        .iter()
        .map(|operation_id| store.load_plan(operation_id).expect("stored plan"))
        .filter(|plan| plan.status == PlanStatus::Consumed)
        .count();
    assert_eq!(consumed, 1, "only the durably reserved plan is consumed");
}

#[test]
pub(super) fn revocation_before_admission_blocks_the_run_without_spending_budget() {
    let root = tempfile::tempdir().expect("runtime root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let authority = active_standing_authority(2);
    let authority_id = authority.authority_id.clone();
    store
        .create_authority(&authority)
        .expect("persist active authority");
    let (mut plan, input) = standing_mint_plan();
    store.save_plan(&plan).expect("persist draft plan");
    key_policy_revoke(
        &store,
        &KeyPolicySelector {
            authority_id: authority_id.clone(),
        },
    )
    .expect("revocation commits before admission");

    let error = admit_standing_plan(&store, &mut plan, &authority, &input)
        .expect_err("revoked authority cannot admit a run");

    assert!(error.to_string().contains("revoked"), "{error}");
    let durable = store
        .load_authority(&authority_id)
        .expect("authority reloads");
    assert_eq!(durable.status, StandingAuthorityStatus::Revoked);
    assert!(durable.run_log.is_empty());
    assert_eq!(
        store
            .load_plan(&plan.operation_id)
            .expect("draft plan reloads")
            .status,
        PlanStatus::Draft
    );
}

#[test]
pub(super) fn standing_admission_reserves_budget_before_plan_persistence() {
    let root = tempfile::tempdir().expect("runtime root");
    let paths = RuntimePaths::from_root(root.path());
    let store = StateStore::open(paths.clone()).expect("state store");
    let authority = active_standing_authority(1);
    store
        .create_authority(&authority)
        .expect("persist active authority");
    let (mut plan, input) = standing_mint_plan();
    store.save_plan(&plan).expect("persist draft plan");
    let plan_path = paths
        .data_dir
        .join("plans")
        .join(format!("{}.json", plan.operation_id));
    fs::remove_file(&plan_path).expect("remove plan for injected persistence failure");
    fs::create_dir(&plan_path).expect("replace plan with non-regular fixture");

    admit_standing_plan(&store, &mut plan, &authority, &input)
        .expect_err("plan persistence fails after authority reservation");

    let durable = store
        .load_authority(&authority.authority_id)
        .expect("authority reservation reloads");
    assert_eq!(durable.run_log.len(), 1);
    assert_eq!(durable.run_log[0].operation_id, plan.operation_id);
    assert_eq!(
        plan.transaction_stage,
        TransactionStageV1::ConsumptionPersisted,
        "the boundary attempt is not recorded until after the plan save"
    );
}

pub(super) fn standing_token_plan_with_receipt(
    authority: &StandingAuthorityV1,
    response: Value,
) -> PlanV1 {
    standing_token_plan_with_receipt_and_targets(authority, response, json!({}))
}

pub(super) fn standing_token_plan_with_receipt_and_targets(
    authority: &StandingAuthorityV1,
    response: Value,
    targets: Value,
) -> PlanV1 {
    let mut plan = standing_token_plan_at_boundary_attempt(authority, targets);
    plan.record_transaction_stage_with_artifact(
        TransactionStageV1::BoundaryResponsePersisted,
        response,
    )
    .expect("boundary response");
    plan
}

pub(super) fn standing_token_plan_at_boundary_attempt(
    authority: &StandingAuthorityV1,
    targets: Value,
) -> PlanV1 {
    let mut capability = CapabilityV1::new(
        "account-api-tokens-create-token",
        "Create account token",
        "POST",
        "/accounts/{account_id}/tokens",
    );
    capability.risk = RiskClass::SecretSensitive;
    let mut plan = PlanV1::draft("profile-a", "account-a", "catalog-sha", capability, targets)
        .expect("standing plan");
    plan.mark_consumed_via_standing_authority(authority)
        .expect("standing consumption");
    plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("boundary attempt");
    plan
}

pub(super) fn reserve_standing_plan(authority: &mut StandingAuthorityV1, plan: &PlanV1) {
    authority
        .reserve_run(Utc::now(), &plan.operation_id, &plan.capability.id)
        .expect("standing run reservation");
}

#[test]
pub(super) fn standing_lineage_uses_only_validated_success_receipts_and_survives_revocation() {
    let mut authority = StandingAuthorityV1::draft(
        "account-a",
        None,
        vec!["account-api-tokens-create-token".to_owned()],
        vec!["group-a".to_owned()],
        "sha256:inventory-binding",
        24,
        "cf-rotation-",
        8,
        Utc::now() + ChronoDuration::days(30),
    )
    .expect("authority draft");
    authority.approve(true).expect("authority approval");
    let plan = standing_token_plan_with_receipt(
        &authority,
        json!({"success":true,"resource_id":"token-child"}),
    );
    let malformed = [
        json!({"success":true}),
        json!({"success":true,"resource_id":""}),
    ]
    .map(|receipt| standing_token_plan_with_receipt(&authority, receipt));
    let unsuccessful = standing_token_plan_with_receipt(
        &authority,
        json!({"success":false,"resource_id":"token-never-created"}),
    );
    reserve_standing_plan(&mut authority, &plan);
    for candidate in &malformed {
        reserve_standing_plan(&mut authority, candidate);
    }
    reserve_standing_plan(&mut authority, &unsuccessful);

    assert_eq!(
        validated_standing_lineage_token_id(&plan, &authority).expect("valid standing receipt"),
        Some("token-child")
    );
    authority.revoke();
    assert_eq!(
        validated_standing_lineage_token_id(&plan, &authority)
            .expect("revocation cannot erase a completed boundary fact"),
        Some("token-child")
    );

    let mut wrong_authority = authority.clone();
    wrong_authority.authority_id = "00000000-0000-4000-8000-000000000001".to_owned();
    assert!(
        validated_standing_lineage_token_id(&plan, &wrong_authority).is_err(),
        "the consumption receipt binds the exact authority"
    );

    for malformed in &malformed {
        assert!(
            validated_standing_lineage_token_id(malformed, &authority).is_err(),
            "successful receipts require a nonempty resource id"
        );
    }

    assert_eq!(
        validated_standing_lineage_token_id(&unsuccessful, &authority)
            .expect("an unsuccessful receipt is validated but creates no lineage"),
        None
    );
}

#[test]
pub(super) fn standing_lineage_requires_the_authoritys_durable_run_reservation() {
    let authority = active_standing_authority(2);
    let plan = standing_token_plan_with_receipt(
        &authority,
        json!({"success":true,"resource_id":"token-unreserved"}),
    );

    let error = validated_standing_lineage_token_id(&plan, &authority)
        .expect_err("a plan-side receipt cannot manufacture authority lineage");

    assert!(error.to_string().contains("reserved"), "{error}");
}

#[test]
pub(super) fn standing_lineage_reservation_must_bind_the_same_capability() {
    let mut authority = active_standing_authority(2);
    let plan = standing_token_plan_with_receipt(
        &authority,
        json!({"success":true,"resource_id":"token-wrong-capability"}),
    );
    authority
        .reserve_run(
            Utc::now(),
            &plan.operation_id,
            "account-api-tokens-delete-token",
        )
        .expect("persist mismatched reservation fixture");

    let error = validated_standing_lineage_token_id(&plan, &authority)
        .expect_err("the reservation must bind the exact creation capability");

    assert!(error.to_string().contains("reserved"), "{error}");
    assert!(error.to_string().contains("capability"), "{error}");
}

#[test]
pub(super) fn standing_lineage_is_reconciled_even_when_the_secret_sink_fails() {
    let root = tempfile::tempdir().expect("runtime root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let mut authority = active_standing_authority(2);
    let mut plan = standing_token_plan_with_receipt(
        &authority,
        json!({"success":true,"resource_id":"token-sink-failed"}),
    );
    reserve_standing_plan(&mut authority, &plan);
    store
        .create_authority(&authority)
        .expect("persist active authority and run reservation");
    store
        .save_plan(&plan)
        .expect("persist successful boundary receipt");

    let outcome = persist_secret_lifecycle_and_reconcile_lineage(
        &store,
        &mut plan,
        true,
        None,
        &MemorySecretStore::default(),
        true,
    );
    let error = outcome
        .error
        .expect("missing one-time secret fails the sink");

    assert!(
        error.to_string().contains("required sink-only value"),
        "{error}"
    );
    assert!(
        outcome.lineage_evidence.is_some(),
        "lineage evidence survives a sink failure"
    );
    let durable_authority = store
        .load_authority(&authority.authority_id)
        .expect("authority lineage reloads");
    assert_eq!(
        durable_authority.minted_token_ids,
        vec!["token-sink-failed"]
    );
    let durable_plan = store
        .load_plan(&plan.operation_id)
        .expect("sink failure checkpoint reloads");
    assert_eq!(durable_plan.status, PlanStatus::RectificationRequired);
    assert_eq!(
        durable_plan.transaction_stage,
        TransactionStageV1::SecretSinkPersisted
    );
}

#[test]
pub(super) fn post_boundary_failure_envelope_retains_performed_truth_and_receipts() {
    let (plan, _) = standing_mint_plan();
    let apply = EvidenceV1::new(
        EvidenceClass::Apply,
        "sha256:apply",
        "/managed/evidence/apply.json",
    );
    let lineage = EvidenceV1::new(
        EvidenceClass::StandingApply,
        "sha256:lineage",
        "/managed/evidence/lineage.json",
    );
    let error = super::CliError::Input("injected sink failure".to_owned());

    let envelope = super::post_boundary_failure_envelope(
        &plan,
        json!({"success":true,"resource_id":"token-created"}),
        Some(apply),
        Some(lineage),
        &error,
        true,
        "the Cloudflare boundary response is durable, but recovery is required",
    );

    assert!(!envelope.ok);
    assert!(envelope.performed);
    assert_eq!(envelope.command, "plans run");
    assert_eq!(
        envelope.operation_id.as_deref(),
        Some(plan.operation_id.as_str())
    );
    assert_eq!(
        envelope.capability_id.as_deref(),
        Some(plan.capability.id.as_str())
    );
    assert_eq!(envelope.evidence.len(), 2);
    assert!(envelope.error.as_ref().is_some_and(|error| {
        error.message.contains("injected sink failure")
            && error.next_step.as_deref().is_some_and(|next| {
                next.contains("Do not replay") && next.contains(&plan.operation_id)
            })
    }));
}

#[test]
pub(super) fn final_checkpoint_failure_preserves_boundary_and_verification_truth() {
    let (mut plan, _) = standing_mint_plan();
    plan.status = PlanStatus::Verified;
    let apply = EvidenceV1::new(
        EvidenceClass::Apply,
        "sha256:apply",
        "/managed/evidence/apply.json",
    );
    let lineage = EvidenceV1::new(
        EvidenceClass::StandingApply,
        "sha256:lineage",
        "/managed/evidence/lineage.json",
    );
    let verification_evidence = EvidenceV1::new(
        EvidenceClass::PostChangeVerification,
        "sha256:verification",
        "/managed/evidence/verification.json",
    );
    let finalization_error =
        super::CliError::Input("injected closed-checkpoint failure".to_owned());

    let envelope = super::api_plan_result_envelope(
        &plan,
        json!({"success":true,"resource_id":"token-created"}),
        apply,
        Some(lineage),
        super::ApiVerificationOutcome {
            state: VerificationState::Passed,
            basis: "live readback matched".to_owned(),
            evidence: Some(verification_evidence),
            error: None,
            correlated_resource_id: None,
        },
        true,
        Some(&finalization_error),
    );

    assert!(!envelope.ok);
    assert!(envelope.performed);
    assert_eq!(envelope.verification.state, VerificationState::Passed);
    assert!(
        envelope
            .verification
            .basis
            .as_deref()
            .is_some_and(|basis| basis.contains("live readback matched")
                && basis.contains("final plan checkpoint"))
    );
    assert_eq!(envelope.evidence.len(), 3);
    assert!(
        envelope
            .error
            .as_ref()
            .is_some_and(|error| error.message.contains("injected closed-checkpoint failure"))
    );
}

#[test]
pub(super) fn successful_response_still_sinks_the_secret_when_apply_evidence_persistence_fails() {
    let root = tempfile::tempdir().expect("runtime root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let mut authority = active_standing_authority(2);
    let sink_path = root.path().join("created-token.txt");
    let mut plan = standing_token_plan_at_boundary_attempt(
        &authority,
        json!({"adapter":{"value_out":sink_path}}),
    );
    reserve_standing_plan(&mut authority, &plan);
    store
        .create_authority(&authority)
        .expect("persist active authority and run reservation");
    store
        .save_plan(&plan)
        .expect("persist boundary attempt before the remote call");
    let evidence_dir = store.paths().data_dir.join("evidence");
    fs::remove_dir(&evidence_dir).expect("remove empty evidence directory");
    fs::write(&evidence_dir, "not-a-directory").expect("block evidence persistence");
    let response = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"token-apply-evidence-failed","value":"one-time-secret"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };

    let envelope = match super::process_api_boundary_response(
        &store,
        &mut plan,
        &response,
        &MemorySecretStore::default(),
    )
    .expect("a local evidence failure returns a recovery envelope")
    {
        super::ApiBoundaryResponseOutcome::Recovery(envelope) => envelope,
        super::ApiBoundaryResponseOutcome::Ready { .. } => {
            panic!("missing apply evidence cannot proceed to verification")
        }
    };

    assert!(!envelope.ok);
    assert!(envelope.performed);
    assert_eq!(
        envelope.operation_id.as_deref(),
        Some(plan.operation_id.as_str())
    );
    assert_eq!(envelope.verification.state, VerificationState::Pending);
    assert!(envelope.error.as_ref().is_some_and(|error| {
        error.message.contains("apply evidence")
            && error
                .next_step
                .as_deref()
                .is_some_and(|next| next.contains("Do not replay") && next.contains("rectify"))
    }));
    assert_eq!(
        fs::read_to_string(&sink_path).expect("one-time secret was sunk"),
        "one-time-secret"
    );
    assert_eq!(
        store
            .load_authority(&authority.authority_id)
            .expect("authority lineage reloads")
            .minted_token_ids,
        vec!["token-apply-evidence-failed"]
    );
    let durable_plan = store
        .load_plan(&plan.operation_id)
        .expect("boundary receipt and sink checkpoint reload");
    assert_eq!(durable_plan.status, PlanStatus::RectificationRequired);
    assert!(
        durable_plan
            .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
            .is_some(),
        "the receipt remains durable even when the separate apply evidence write fails"
    );
}

#[test]
pub(super) fn successful_response_still_sinks_the_secret_when_boundary_receipt_persistence_fails() {
    let root = tempfile::tempdir().expect("runtime root");
    let paths = RuntimePaths::from_root(root.path());
    let store = StateStore::open(paths.clone()).expect("state store");
    let mut authority = active_standing_authority(2);
    let sink_path = root.path().join("created-token.txt");
    let mut plan = standing_token_plan_at_boundary_attempt(
        &authority,
        json!({"adapter":{"value_out":sink_path}}),
    );
    reserve_standing_plan(&mut authority, &plan);
    store
        .create_authority(&authority)
        .expect("persist active authority and run reservation");
    store
        .save_plan(&plan)
        .expect("persist boundary attempt before the remote call");
    let plan_path = paths
        .data_dir
        .join("plans")
        .join(format!("{}.json", plan.operation_id));
    fs::remove_file(&plan_path).expect("remove plan before injected persistence failure");
    fs::create_dir(&plan_path).expect("replace plan with a non-regular fixture");
    let response = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"token-receipt-persistence-failed","value":"one-time-secret"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };

    let envelope = match super::process_api_boundary_response(
        &store,
        &mut plan,
        &response,
        &MemorySecretStore::default(),
    )
    .expect("a receipt persistence failure returns a recovery envelope")
    {
        super::ApiBoundaryResponseOutcome::Recovery(envelope) => envelope,
        super::ApiBoundaryResponseOutcome::Ready { .. } => {
            panic!("an undurable boundary receipt cannot proceed to verification")
        }
    };

    assert!(!envelope.ok);
    assert!(envelope.performed);
    assert_eq!(
        envelope.operation_id.as_deref(),
        Some(plan.operation_id.as_str())
    );
    assert_eq!(envelope.verification.state, VerificationState::Pending);
    assert!(envelope.error.as_ref().is_some_and(|error| {
        error.message.contains("boundary response")
            && error
                .next_step
                .as_deref()
                .is_some_and(|next| next.contains("Do not replay") && next.contains("rectify"))
    }));
    assert_eq!(
        fs::read_to_string(&sink_path).expect("one-time secret was sunk"),
        "one-time-secret"
    );
    assert!(
        store
            .load_authority(&authority.authority_id)
            .expect("authority reloads")
            .minted_token_ids
            .is_empty(),
        "an undurable boundary receipt cannot authorize lineage reconciliation"
    );
}

#[test]
pub(super) fn transport_error_after_boundary_attempt_returns_unknown_no_replay_envelope() {
    let root = tempfile::tempdir().expect("runtime root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let authority = active_standing_authority(2);
    let mut plan = standing_token_plan_at_boundary_attempt(&authority, json!({}));
    store
        .save_plan(&plan)
        .expect("persist boundary attempt before the remote call");
    let transport_error = super::CliError::Input("injected response timeout".to_owned());

    let envelope = super::process_api_transport_failure(
        &store,
        &mut plan,
        &transport_error,
        &MemorySecretStore::default(),
    );

    assert!(!envelope.ok);
    assert!(!envelope.performed);
    assert_eq!(
        envelope.operation_id.as_deref(),
        Some(plan.operation_id.as_str())
    );
    assert_eq!(envelope.verification.state, VerificationState::Pending);
    assert!(envelope.error.as_ref().is_some_and(|error| {
        error.message.contains("outcome is unknown")
            && error.message.contains("injected response timeout")
            && error
                .next_step
                .as_deref()
                .is_some_and(|next| next.contains("Do not replay") && next.contains("rectify"))
    }));
    let durable_plan = store
        .load_plan(&plan.operation_id)
        .expect("unknown outcome checkpoints reload");
    assert_eq!(durable_plan.status, PlanStatus::RectificationRequired);
    assert_eq!(
        durable_plan.transaction_stage,
        TransactionStageV1::SecretSinkPersisted
    );
    assert_eq!(
        durable_plan
            .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
            .and_then(|artifact| artifact.get("receipt_available"))
            .and_then(Value::as_bool),
        Some(false)
    );
}

#[test]
pub(super) fn standing_lineage_is_durable_before_a_failing_verification_checkpoint() {
    let root = tempfile::tempdir().expect("runtime root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let mut authority = active_standing_authority(2);
    let sink_path = root.path().join("created-token.txt");
    let mut plan = standing_token_plan_with_receipt_and_targets(
        &authority,
        json!({"success":true,"resource_id":"token-verification-failed"}),
        json!({"adapter":{"value_out":sink_path}}),
    );
    reserve_standing_plan(&mut authority, &plan);
    store
        .create_authority(&authority)
        .expect("persist active authority and run reservation");
    store
        .save_plan(&plan)
        .expect("persist successful boundary receipt");

    let outcome = persist_secret_lifecycle_and_reconcile_lineage(
        &store,
        &mut plan,
        true,
        Some(&json!({"id":"token-verification-failed","value":"one-time-secret"})),
        &MemorySecretStore::default(),
        true,
    );
    assert!(
        outcome.error.is_none(),
        "sink and lineage reconciliation complete: {:?}",
        outcome.error
    );
    assert!(outcome.lineage_evidence.is_some());
    assert_eq!(
        store
            .load_authority(&authority.authority_id)
            .expect("authority lineage reloads")
            .minted_token_ids,
        vec!["token-verification-failed"]
    );

    super::persist_transaction_stage(
        &store,
        &mut plan,
        TransactionStageV1::VerificationAttemptPersisted,
    )
    .expect("verification attempt checkpoint persists");
    let outcome = super::verification_outcome(
        &store,
        &mut plan,
        OperationVerificationV1 {
            strategy: "test_readback".to_owned(),
            passed: false,
            basis: "injected post-change mismatch".to_owned(),
            readback: CloudflareResponseV1 {
                status: 200,
                success: true,
                result: json!({"id":"token-verification-failed","status":"unexpected"}),
                errors: Vec::new(),
                result_info: None,
                etag: None,
                cf_ray: None,
            },
            correlated_resource_id: None,
        },
    )
    .expect("verification outcome records evidence");
    let artifact =
        super::verification_response_artifact(&outcome).expect("verification receipt builds");
    super::persist_transaction_stage_with_artifact(
        &store,
        &mut plan,
        TransactionStageV1::VerificationResponsePersisted,
        artifact,
    )
    .expect("failing verification checkpoint persists");

    let durable_authority = store
        .load_authority(&authority.authority_id)
        .expect("authority reloads after verification failure");
    assert_eq!(durable_authority.status, StandingAuthorityStatus::Active);
    assert_eq!(
        durable_authority.minted_token_ids,
        vec!["token-verification-failed"]
    );
    assert_eq!(plan.status, PlanStatus::RectificationRequired);
}

#[test]
pub(super) fn later_standing_preflight_recovers_missing_lineage_after_reopen() {
    let root = tempfile::tempdir().expect("runtime root");
    let paths = RuntimePaths::from_root(root.path());
    let store = StateStore::open(paths.clone()).expect("state store");
    let mut authority = active_standing_authority(2);
    let authority_id = authority.authority_id.clone();
    let plan = standing_token_plan_with_receipt(
        &authority,
        json!({"success":true,"resource_id":"token-crash-recovery"}),
    );
    reserve_standing_plan(&mut authority, &plan);
    store
        .create_authority(&authority)
        .expect("persist active authority and run reservation");
    store
        .save_plan(&plan)
        .expect("persist only the boundary receipt before simulated crash");
    drop(store);

    let reopened = StateStore::open(paths).expect("state store reopens");
    preflight_standing_authority(&reopened, Some(&authority_id))
        .expect("later standing preflight recovers lineage");
    preflight_standing_authority(&reopened, Some(&authority_id))
        .expect("repeated recovery is idempotent");

    let durable = reopened
        .load_authority(&authority_id)
        .expect("reconciled authority reloads");
    assert_eq!(durable.minted_token_ids, vec!["token-crash-recovery"]);
}

#[test]
pub(super) fn standing_lineage_recovery_cannot_observe_an_in_flight_plan() {
    let root = tempfile::tempdir().expect("runtime root");
    let paths = RuntimePaths::from_root(root.path());
    let running_store = StateStore::open(paths.clone()).expect("running store");
    let recovery_store = StateStore::open(paths).expect("recovery store");
    let mut authority = active_standing_authority(2);
    let authority_id = authority.authority_id.clone();
    let plan = standing_token_plan_with_receipt(
        &authority,
        json!({"success":true,"resource_id":"token-in-flight"}),
    );
    reserve_standing_plan(&mut authority, &plan);
    running_store
        .create_authority(&authority)
        .expect("persist active authority and run reservation");
    let operation_id = plan.operation_id.clone();
    running_store
        .save_plan(&plan)
        .expect("persist boundary response before the sink attempt");
    let plan_guard = running_store
        .lock_plan(&operation_id)
        .expect("running invocation owns the plan");

    let error = super::recover_standing_lineage(&recovery_store, &authority_id)
        .expect_err("recovery cannot inspect an in-flight plan");

    assert!(error.to_string().contains("locked"), "{error}");
    assert!(
        recovery_store
            .load_authority(&authority_id)
            .expect("authority reloads")
            .minted_token_ids
            .is_empty(),
        "recovery must not publish lineage before the running invocation attempts its sink"
    );
    drop(plan_guard);
    super::recover_standing_lineage(&recovery_store, &authority_id)
        .expect("recovery proceeds after the running invocation releases its plan");
    assert_eq!(
        recovery_store
            .load_authority(&authority_id)
            .expect("reconciled authority reloads")
            .minted_token_ids,
        vec!["token-in-flight"]
    );
}
