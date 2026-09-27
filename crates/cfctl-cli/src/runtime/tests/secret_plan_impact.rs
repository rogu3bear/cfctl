use super::*;

const CONFIG: &str = "name = \"jkca-web-drop\"\nmain = \"src/index.js\"\n";

fn capability() -> CapabilityV1 {
    let mut cap = workers_secret_input_capability();
    cap.effect = EffectClass::IdentityOrOwnership;
    cap.cost.known = true;
    cap.rollback.warning = Some("The prior secret value cannot be restored automatically; use a separately reviewed plan from a trusted source.".to_owned());
    cap.request_schema.as_mut().expect("schema")["oneOf"][1]["properties"]["usages"]["items"] = json!({"type":"string","enum":["encrypt","decrypt","sign","verify","deriveKey","deriveBits","wrapKey","unwrapKey"]});
    cap.selectors = [
        ("account_id", json!({"maxLength":32,"type":"string"})),
        ("script_name", json!({"type":"string"})),
    ]
    .into_iter()
    .map(|(name, schema)| SelectorV1 {
        name: name.to_owned(),
        location: "path".to_owned(),
        required: true,
        value_type: "string".to_owned(),
        description: None,
        contract: Some(SelectorContractV1 {
            schema,
            query: None,
        }),
    })
    .collect();
    cap.same_path_read = Some(SamePathReadContractV1 {
        path: "/accounts/{account_id}/workers/scripts/{script_name}/secrets/{secret_name}"
            .to_owned(),
        read_capability_id: "worker-get-script-secret".to_owned(),
        verified_response_fields: vec!["name".to_owned(), "type".to_owned()],
    });
    assert!(
        cap.mutation_contract_gaps().is_empty(),
        "{:?}",
        cap.mutation_contract_gaps()
    );
    cap
}

fn input() -> CallInput {
    CallInput {
        selectors: json!({"account_id":"account-a","script_name":"jkca-web-drop"}),
        ..CallInput::default()
    }
}

fn register(store: &StorageStateStore, root: &Path, name: &str) -> PathBuf {
    let path = root.join(name);
    init_pages_scope_repository(&path, CONFIG);
    store
        .register_workspace(&path, Some("account-a".to_owned()))
        .expect("registered repository");
    path.canonicalize().expect("canonical repository")
}

fn unrelated_dirt(path: &Path) {
    fs::write(path.join("README.md"), "owned Agents and ledger notes\n").expect("owned edit");
    fs::write(path.join("sign.css"), ".sign { color: orange; }\n").expect("owned styling");
}

fn secret_body() -> Value {
    json!({"name":"TURNSTILE_SECRET_KEY_DROP","type":"secret_text","text":"synthetic-regression-value"})
}

fn prepare(store: &StorageStateStore, cap: CapabilityV1, mut input: CallInput) -> ResultEnvelopeV2 {
    let mut catalog = test_catalog();
    catalog.capabilities.insert(cap.id.clone(), cap.clone());
    catalog.refresh_hash().expect("catalog hash");
    let profile = ProfileMetadata::new("profile-a", ProfileKind::ApiToken, Some("account-a"));
    let content_hash = hash_value(&secret_body()).expect("synthetic body hash");
    input.body =
        Some(json!({"$cfctl_secret_body_ref":"plan-input/test","content_hash":content_hash}));
    persist_prepared_plan(
        store,
        &catalog,
        cap,
        input,
        PlanAuthority {
            profile: &profile,
            account_id: "account-a",
        },
        json!({"secret_body_ref":"plan-input/test","secret_body_hash":content_hash}),
        LivePlanPreconditions::default(),
    )
    .expect("local plan preparation")
}

#[test]
fn secret_plan_allows_unrelated_owned_dirt_and_keeps_approval_and_workspace_pins() {
    let state = tempfile::tempdir().expect("state");
    let repos = tempfile::tempdir().expect("repositories");
    let store = StateStore::open(RuntimePaths::from_root(state.path())).expect("store");
    let source = register(&store, repos.path(), "jkca-web");
    register(&store, repos.path(), "historical-a");
    register(&store, repos.path(), "historical-b");
    unrelated_dirt(&source);

    let envelope = prepare(&store, capability(), input());
    assert!(envelope.ok, "{:?}", envelope.error);
    assert!(!envelope.performed);
    assert!(
        !serde_json::to_string(&envelope)
            .expect("envelope")
            .contains("synthetic-regression-value")
    );
    let plan = store
        .load_plan(envelope.operation_id.as_deref().expect("operation id"))
        .expect("persisted plan");
    assert_eq!(plan.policy.disposition, PolicyDisposition::ApprovalRequired);
    assert_eq!(plan.affected_repositories.len(), 3);
    assert_eq!(plan.local_diffs.len(), 3);
    assert!(plan.local_diffs.iter().all(|diff| diff["dirty"] == false));
    assert!(plan.precondition_hashes.contains_key("workspace_graph"));
    assert_eq!(
        plan.precondition_hashes
            .keys()
            .filter(|key| key.starts_with("source_config:"))
            .count(),
        3
    );
    validate_plan_preconditions(&store, &plan).expect("unchanged dirty workspace remains bound");
    let secrets = MemorySecretStore::default();
    secrets
        .put("plan-input/test", &secret_body().to_string())
        .expect("synthetic private body");
    assert_eq!(
        resolved_plan_input(&plan, &secrets)
            .expect("bound secret")
            .body,
        Some(secret_body())
    );
    secrets
        .put("plan-input/test", "{}")
        .expect("synthetic body drift");
    assert!(
        resolved_plan_input(&plan, &secrets)
            .expect_err("secret drift denied")
            .to_string()
            .contains("secret request body drifted")
    );
    fs::write(
        source.join("wrangler.toml"),
        format!("{CONFIG}[vars]\nSTAGE = \"changed\"\n"),
    )
    .expect("binding drift");
    let error = validate_plan_preconditions(&store, &plan).expect_err("changed binding blocked");
    assert!(error.to_string().contains("drifted after planning"));
}

#[test]
fn secret_plan_blocks_dirty_configuration_and_missing_selectors() {
    let state = tempfile::tempdir().expect("state");
    let repos = tempfile::tempdir().expect("repositories");
    let store = StateStore::open(RuntimePaths::from_root(state.path())).expect("store");
    let source = register(&store, repos.path(), "jkca-web");
    fs::write(
        source.join("wrangler.toml"),
        format!("{CONFIG}[vars]\nOWNED = \"edit\"\n"),
    )
    .expect("owned configuration edit");
    let blocked = prepare(&store, capability(), input());
    assert!(!blocked.ok);
    assert!(!blocked.performed);
    assert!(blocked.operation_id.is_none());
    assert!(blocked.error.expect("error").message.contains("overlaps"));

    fs::write(source.join("wrangler.toml"), CONFIG).expect("restore fixture config");
    unrelated_dirt(&source);
    let mut ambiguous = input();
    ambiguous.selectors = json!({"account_id":"account-a"});
    let blocked = prepare(&store, capability(), ambiguous);
    assert!(
        blocked
            .error
            .expect("error")
            .message
            .contains("ambiguously")
    );
    assert!(blocked.operation_id.is_none());
}

#[test]
fn secret_plan_does_not_relax_other_operations_or_drifted_secret_contracts() {
    let state = tempfile::tempdir().expect("state");
    let repos = tempfile::tempdir().expect("repositories");
    let store = StateStore::open(RuntimePaths::from_root(state.path())).expect("store");
    let source = register(&store, repos.path(), "jkca-web");
    unrelated_dirt(&source);
    let mut other = capability();
    other.id = "worker-delete-script-secret".to_owned();
    let mut drifted = capability();
    drifted.same_path_read = None;
    for cap in [other, drifted] {
        let impact = plan_impact(&store, &cap, &input(), "account-a").expect("impact");
        assert!(impact.policy.has_dirty_overlap);
        assert_eq!(
            PolicyEngine.evaluate(&cap, &impact.policy).disposition,
            PolicyDisposition::Blocked
        );
    }
}

#[test]
fn secret_plan_repair_keeps_deployment_source_dirt_blocked() {
    let state = tempfile::tempdir().expect("state");
    let repos = tempfile::tempdir().expect("repositories");
    let store = StateStore::open(RuntimePaths::from_root(state.path())).expect("store");
    let source = register(&store, repos.path(), "jkca-web");
    let artifact = source.join("dist");
    fs::create_dir(&artifact).expect("artifact directory");
    fs::write(artifact.join("index.html"), "fixture").expect("artifact");
    unrelated_dirt(&source);
    let mut catalog = test_catalog();
    cfctl_catalog::ingest_wrangler_pages_deploy_help(
        &mut catalog,
        "test",
        "wrangler pages deploy [directory] --project-name --branch --commit-hash --commit-message",
    );
    let cap = catalog.get("wrangler.pages-deploy").expect("Pages deploy");
    let input = CallInput {
        selectors: json!({"account_id":"account-a"}),
        query: json!({"argument":artifact}),
        ..CallInput::default()
    };
    let impact = plan_impact(&store, cap, &input, "account-a").expect("artifact impact");
    assert_eq!(impact.local_artifact_paths, vec![artifact]);
    assert!(impact.policy.has_dirty_overlap);
    assert_eq!(
        PolicyEngine.evaluate(cap, &impact.policy).disposition,
        PolicyDisposition::Blocked
    );
}
