#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::{fs, process::Command as ProcessCommand};

use cfctl_cli::{Cli, Command, InvocationMode, classify_invocation};
use clap::{CommandFactory as _, Parser};

#[test]
fn every_public_command_group_is_parseable() {
    for command in [
        "auth",
        "keys",
        "catalog",
        "call",
        "guide",
        "plans",
        "workspace",
        "agents",
        "docs",
        "doctor",
        "update",
        "migrate",
    ] {
        let arguments: Vec<&str> = match command {
            "auth" => vec!["cfctl", "auth", "status"],
            "keys" => vec!["cfctl", "keys", "permissions"],
            "catalog" => vec!["cfctl", "catalog", "coverage"],
            "call" => vec!["cfctl", "call", "dns-records-list"],
            "guide" => vec!["cfctl", "guide", "dns-records-delete"],
            "plans" => vec!["cfctl", "plans", "status", "operation-id"],
            "workspace" => vec!["cfctl", "workspace", "graph"],
            "agents" => vec!["cfctl", "agents", "doctor"],
            "docs" => vec!["cfctl", "docs", "coverage"],
            "doctor" => vec!["cfctl", "doctor"],
            "update" => vec!["cfctl", "update", "--check"],
            "migrate" => vec!["cfctl", "migrate", "v1"],
            _ => unreachable!("fixed command set"),
        };
        let parsed = Cli::try_parse_from(arguments).expect("public command parses");
        assert!(
            matches!(parsed.command, Some(Command::Auth(_))) == (command == "auth")
                || command != "auth"
        );
    }
}

#[test]
fn guide_topics_are_additive_and_capability_guides_remain_compatible() {
    let capability = Cli::try_parse_from(["cfctl", "guide", "dns-records-list"])
        .expect("existing capability guide parses");
    let Some(Command::Guide(capability)) = capability.command else {
        panic!("guide command");
    };
    assert_eq!(
        capability.capability_id.as_deref(),
        Some("dns-records-list")
    );
    assert!(capability.topic.is_none());

    for (value, expected) in [
        ("system", cfctl_cli::GuideTopicArg::System),
        (
            "standing-authority",
            cfctl_cli::GuideTopicArg::StandingAuthority,
        ),
    ] {
        let parsed =
            Cli::try_parse_from(["cfctl", "guide", "--topic", value]).expect("guide topic parses");
        let Some(Command::Guide(arguments)) = parsed.command else {
            panic!("guide command");
        };
        assert!(arguments.capability_id.is_none());
        assert_eq!(arguments.topic, Some(expected));
    }

    assert!(Cli::try_parse_from(["cfctl", "guide"]).is_err());
    assert!(
        Cli::try_parse_from(["cfctl", "guide", "dns-records-list", "--topic", "system"]).is_err()
    );
}

#[test]
fn guide_help_explains_capability_and_system_targets() {
    let mut guide = Cli::command()
        .find_subcommand("guide")
        .expect("guide subcommand")
        .clone();
    let help = guide.render_long_help().to_string();
    assert!(help.contains("CAPABILITY_ID"));
    assert!(help.contains("--topic <TOPIC>"));
    assert!(help.contains("system"));
    assert!(help.contains("standing-authority"));
}

#[test]
fn system_topics_run_offline_without_a_catalog() {
    let runtime = tempfile::tempdir().expect("runtime root");
    for topic in ["system", "standing-authority"] {
        let output = ProcessCommand::new(env!("CARGO_BIN_EXE_cfctl"))
            .env("CFCTL_HOME", runtime.path())
            .args(["guide", "--topic", topic, "--json"])
            .output()
            .expect("run system topic");
        assert!(
            output.status.success(),
            "{topic}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let envelope: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("guide topic envelope");
        assert_eq!(envelope["schema_version"], 2);
        assert_eq!(envelope["performed"], false);
        assert_eq!(envelope["result"]["schema_version"], 1);
        assert_eq!(envelope["result"]["topic"], topic);
        assert_eq!(
            envelope["result"]["answers"].as_array().map(Vec::len),
            Some(5)
        );
        assert!(
            !runtime.path().join("data/catalog/current.json").exists(),
            "a static topic must not create or refresh the catalog"
        );
    }
}

#[test]
fn bare_text_is_agent_intent_but_deterministic_commands_are_not() {
    assert_eq!(
        classify_invocation(["cfctl", "rotate the production Worker secret"]),
        InvocationMode::NaturalLanguage("rotate the production Worker secret".to_owned())
    );
    assert_eq!(
        classify_invocation(["cfctl", "catalog", "coverage"]),
        InvocationMode::Deterministic
    );
    assert_eq!(
        classify_invocation(["cfctl", "--json", "inspect the active account"]),
        InvocationMode::NaturalLanguage("inspect the active account".to_owned())
    );
}

#[test]
fn bare_single_unknown_tokens_fail_closed_to_the_deterministic_parser() {
    for typo in ["not-a-real-verb", "verify", "catallog", "env"] {
        assert_eq!(
            classify_invocation(["cfctl", typo]),
            InvocationMode::Deterministic,
            "single token `{typo}` must fail closed, not launch an agent"
        );
        assert!(
            Cli::try_parse_from(["cfctl", typo]).is_err(),
            "clap must reject the unknown verb `{typo}`"
        );
    }
    assert_eq!(
        classify_invocation(["cfctl", "--json", "verify"]),
        InvocationMode::Deterministic
    );
    // The documented quoted natural-language form keeps the agent lane, as
    // does unquoted multi-argument intent.
    assert_eq!(
        classify_invocation(["cfctl", "list dns records for the active zone"]),
        InvocationMode::NaturalLanguage("list dns records for the active zone".to_owned())
    );
    assert_eq!(
        classify_invocation(["cfctl", "list", "dns", "records"]),
        InvocationMode::NaturalLanguage("list dns records".to_owned())
    );
    // `help` is injected by clap at parse time and must stay deterministic.
    assert_eq!(
        classify_invocation(["cfctl", "help"]),
        InvocationMode::Deterministic
    );
}

#[test]
fn unknown_single_verb_exits_nonzero_without_launching_an_agent() {
    let output = ProcessCommand::new(env!("CARGO_BIN_EXE_cfctl"))
        .arg("not-a-real-verb")
        .output()
        .expect("cfctl binary runs");
    assert!(
        !output.status.success(),
        "an unknown verb must not exit 0 (the old behavior launched an agent)"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unrecognized subcommand"),
        "clap must reject the verb with a usage error, got: {stderr}"
    );
}

#[test]
fn approval_requires_the_exact_plan_id_and_explicit_yes_flag() {
    let parsed = Cli::try_parse_from([
        "cfctl",
        "plans",
        "approve",
        "op-123",
        "--yes",
        "--max-cost",
        "USD:10.00",
    ])
    .expect("approval parses");
    let Some(Command::Plans(arguments)) = parsed.command else {
        panic!("plans command");
    };
    let cfctl_cli::PlansCommand::Approve(approval) = arguments.command else {
        panic!("approve command");
    };
    assert_eq!(approval.operation_id, "op-123");
    assert!(approval.yes);
    assert_eq!(approval.max_cost.as_deref(), Some("USD:10.00"));

    let without_yes = Cli::try_parse_from(["cfctl", "plans", "approve", "op-123"])
        .expect("approve without --yes still parses as a draft gate request");
    let Some(Command::Plans(arguments)) = without_yes.command else {
        panic!("plans command");
    };
    let cfctl_cli::PlansCommand::Approve(approval) = arguments.command else {
        panic!("approve command");
    };
    assert_eq!(approval.operation_id, "op-123");
    assert!(
        !approval.yes,
        "chat/intent alone must not set the approval flag; only --yes grants authority"
    );
}

#[test]
fn user_owned_key_lifecycle_requires_an_explicit_owner_flag_and_account_context() {
    let parsed = Cli::try_parse_from([
        "cfctl",
        "keys",
        "mint",
        "--user",
        "--name",
        "deployment",
        "--permission",
        "group-id",
        "--account",
        "account-id",
        "--value-out",
        "/tmp/new-token",
    ])
    .expect("user-owned mint parses");
    let Some(Command::Keys(arguments)) = parsed.command else {
        panic!("keys command");
    };
    let cfctl_cli::KeysCommand::Mint(mint) = arguments.command else {
        panic!("mint command");
    };
    assert!(mint.user);
    assert_eq!(mint.account.as_deref(), Some("account-id"));

    for action in ["rotate", "revoke"] {
        let mut arguments = vec![
            "cfctl",
            "keys",
            action,
            "--user",
            "--id",
            "token-id",
            "--account",
            "account-id",
        ];
        if action == "rotate" {
            arguments.extend(["--value-out", "/tmp/rotated-token"]);
        }
        let parsed = Cli::try_parse_from(arguments).expect("user-owned lifecycle parses");
        let Some(Command::Keys(arguments)) = parsed.command else {
            panic!("keys command");
        };
        match arguments.command {
            cfctl_cli::KeysCommand::Rotate(rotate) => assert!(rotate.user),
            cfctl_cli::KeysCommand::Revoke(revoke) => assert!(revoke.user),
            _ => panic!("unexpected key command"),
        }
    }
}

#[test]
fn standing_policy_verbs_parse_and_under_policy_rides_mint_and_revoke() {
    let parsed = Cli::try_parse_from([
        "cfctl",
        "keys",
        "policy",
        "create",
        "--account",
        "account-id",
        "--name-prefix",
        "cf-rotation-",
        "--permission",
        "Workers Scripts Write",
        "--max-child-ttl-hours",
        "24",
        "--max-runs-per-day",
        "4",
    ])
    .expect("policy create parses");
    let Some(Command::Keys(arguments)) = parsed.command else {
        panic!("keys command");
    };
    let cfctl_cli::KeysCommand::Policy(policy) = arguments.command else {
        panic!("policy command");
    };
    let cfctl_cli::KeyPolicyCommand::Create(create) = policy.command else {
        panic!("create command");
    };
    assert_eq!(create.account, "account-id");
    assert_eq!(create.name_prefix, "cf-rotation-");
    assert_eq!(create.max_child_ttl_hours, 24);
    assert_eq!(create.max_runs_per_day, 4);
    assert_eq!(create.expires_days, 90, "authority TTL defaults to 90 days");

    let approve = Cli::try_parse_from(["cfctl", "keys", "policy", "approve", "authority-1"])
        .expect("approve without --yes still parses as a draft gate request");
    let Some(Command::Keys(arguments)) = approve.command else {
        panic!("keys command");
    };
    let cfctl_cli::KeysCommand::Policy(policy) = arguments.command else {
        panic!("policy command");
    };
    let cfctl_cli::KeyPolicyCommand::Approve(approve) = policy.command else {
        panic!("approve command");
    };
    assert!(
        !approve.yes,
        "chat/intent alone must not set the approval flag; only --yes grants authority"
    );

    let minted = Cli::try_parse_from([
        "cfctl",
        "keys",
        "mint",
        "--name",
        "cf-rotation-web",
        "--permission",
        "group-id",
        "--account",
        "account-id",
        "--value-out",
        "/tmp/child.tok",
        "--under-policy",
        "authority-1",
    ])
    .expect("under-policy mint parses");
    let Some(Command::Keys(arguments)) = minted.command else {
        panic!("keys command");
    };
    let cfctl_cli::KeysCommand::Mint(mint) = arguments.command else {
        panic!("mint command");
    };
    assert_eq!(mint.under_policy.as_deref(), Some("authority-1"));
}

#[test]
fn standing_runs_fail_closed_before_any_network_when_the_authority_is_missing() {
    let runtime = tempfile::tempdir().expect("runtime root");
    let missing_authority_id = "00000000-0000-4000-8000-000000000001";
    let output = ProcessCommand::new(env!("CARGO_BIN_EXE_cfctl"))
        .env("CFCTL_HOME", runtime.path())
        .args([
            "keys",
            "mint",
            "--name",
            "cf-rotation-x",
            "--permission",
            "group",
            "--account",
            "account-a",
            "--value-out",
            "/tmp/never-written.tok",
            "--under-policy",
            missing_authority_id,
            "--json",
        ])
        .output()
        .expect("cfctl binary runs");
    assert!(
        !output.status.success(),
        "a standing run against a missing authority must fail closed"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!(
            "standing authority `{missing_authority_id}` does not exist"
        )),
        "missing authority must be the failure, got: {stderr}"
    );
}

#[test]
fn help_and_version_are_successful_public_commands() {
    for argument in ["--help", "--version"] {
        let output = ProcessCommand::new(env!("CARGO_BIN_EXE_cfctl"))
            .arg(argument)
            .output()
            .expect("run public metadata command");
        assert!(
            output.status.success(),
            "{argument} exited {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.stdout.is_empty());
    }
}

#[test]
fn isolated_doctor_and_registered_workspace_emit_v2_envelopes() {
    let runtime = tempfile::tempdir().expect("runtime root");
    let workspace = tempfile::tempdir().expect("workspace root");

    let doctor = ProcessCommand::new(env!("CARGO_BIN_EXE_cfctl"))
        .env("CFCTL_HOME", runtime.path())
        .args(["doctor", "--json"])
        .output()
        .expect("run isolated doctor");
    assert!(
        doctor.status.success(),
        "{}",
        String::from_utf8_lossy(&doctor.stderr)
    );
    let doctor: serde_json::Value =
        serde_json::from_slice(&doctor.stdout).expect("doctor JSON envelope");
    assert_eq!(doctor["schema_version"], 2);
    assert_eq!(doctor["ok"], true);
    assert_eq!(doctor["performed"], false);
    assert_eq!(doctor["command"], "doctor");
    assert_eq!(doctor["result"]["catalog"]["present"], false);
    assert!(doctor["result"]["public_oauth"].is_string());

    let add = ProcessCommand::new(env!("CARGO_BIN_EXE_cfctl"))
        .env("CFCTL_HOME", runtime.path())
        .args([
            "workspace",
            "add",
            workspace.path().to_str().expect("UTF-8 workspace path"),
            "--json",
        ])
        .output()
        .expect("register workspace");
    assert!(
        add.status.success(),
        "{}",
        String::from_utf8_lossy(&add.stderr)
    );
    let add: serde_json::Value = serde_json::from_slice(&add.stdout).expect("workspace add JSON");
    assert_eq!(add["schema_version"], 2);
    assert_eq!(add["ok"], true);
    assert_eq!(add["performed"], false);
    assert_eq!(add["command"], "workspace add");
    let reported_path = add["result"]["path"]
        .as_str()
        .map(std::path::Path::new)
        .expect("workspace add reports a path");
    assert_eq!(
        reported_path
            .canonicalize()
            .expect("canonical reported path"),
        workspace
            .path()
            .canonicalize()
            .expect("canonical workspace")
    );

    let discover = ProcessCommand::new(env!("CARGO_BIN_EXE_cfctl"))
        .env("CFCTL_HOME", runtime.path())
        .args(["workspace", "discover", "--json"])
        .output()
        .expect("discover registered workspace");
    assert!(
        discover.status.success(),
        "{}",
        String::from_utf8_lossy(&discover.stderr)
    );
    let discover: serde_json::Value =
        serde_json::from_slice(&discover.stdout).expect("workspace discover JSON");
    assert_eq!(discover["schema_version"], 2);
    assert_eq!(discover["ok"], true);
    assert_eq!(discover["performed"], false);
    assert_eq!(discover["command"], "workspace discover");
    assert_eq!(
        discover["result"]["repositories"].as_array().map(Vec::len),
        Some(0),
        "a registered configless, non-Git directory is bounded but is not fabricated as a repository"
    );
}

#[test]
fn v1_migration_imports_safe_state_without_copying_secret_content() {
    let source = tempfile::tempdir().expect("source root");
    let runtime = tempfile::tempdir().expect("runtime root");
    fs::create_dir_all(source.path().join("state")).expect("state directory");
    fs::write(
        source.path().join("state/dns.yaml"),
        "zone: example.com\nrecords: []\n",
    )
    .expect("safe state");
    fs::write(
        source.path().join("state/private.json"),
        r#"{"access_token":"must-not-be-imported"}"#,
    )
    .expect("secret state");

    let output = ProcessCommand::new(env!("CARGO_BIN_EXE_cfctl"))
        .current_dir(source.path())
        .env("CFCTL_HOME", runtime.path())
        .args(["--json", "migrate", "v1"])
        .output()
        .expect("run migration");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("JSON result envelope");
    assert_eq!(
        envelope["result"]["imported"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(
        envelope["result"]["skipped"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(envelope["result"]["credentials_imported"], false);

    for entry in walkdir::WalkDir::new(runtime.path())
        .into_iter()
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.file_type().is_file())
    {
        let bytes = fs::read(entry.path()).expect("runtime artifact");
        assert!(
            !bytes
                .windows(20)
                .any(|window| window == b"must-not-be-imported")
        );
    }
}

#[test]
fn legacy_wrangler_profile_can_be_inspected_and_removed_without_revival() {
    let runtime = tempfile::tempdir().expect("runtime root");
    write_legacy_wrangler_profile(runtime.path());

    let profiles = ProcessCommand::new(env!("CARGO_BIN_EXE_cfctl"))
        .env("CFCTL_HOME", runtime.path())
        .args(["auth", "profiles", "--json"])
        .output()
        .expect("inspect legacy profiles");
    assert!(
        profiles.status.success(),
        "{}",
        String::from_utf8_lossy(&profiles.stderr)
    );
    let profiles: serde_json::Value =
        serde_json::from_slice(&profiles.stdout).expect("profiles envelope");
    assert_eq!(
        profiles["result"]["profiles"][0]["kind"], "wrangler_session",
        "{profiles}"
    );

    let doctor = ProcessCommand::new(env!("CARGO_BIN_EXE_cfctl"))
        .env("CFCTL_HOME", runtime.path())
        .args(["doctor", "--json"])
        .output()
        .expect("diagnose legacy profile");
    assert!(
        doctor.status.success(),
        "{}",
        String::from_utf8_lossy(&doctor.stderr)
    );
    let doctor: serde_json::Value =
        serde_json::from_slice(&doctor.stdout).expect("doctor envelope");
    assert_eq!(
        doctor["result"]["unsupported_legacy_profiles"][0]["profile"],
        "legacy"
    );
    assert_eq!(
        doctor["result"]["unsupported_legacy_profiles"][0]["credential_store_accessed"],
        false
    );
    assert_eq!(
        doctor["result"]["unsupported_legacy_profiles"][0]["remove_argv"],
        serde_json::json!(["cfctl", "auth", "logout", "legacy", "--json"])
    );

    for command in [
        ["auth", "status", "legacy", "--json"],
        ["auth", "use", "legacy", "--json"],
    ] {
        let rejected = ProcessCommand::new(env!("CARGO_BIN_EXE_cfctl"))
            .env("CFCTL_HOME", runtime.path())
            .args(command)
            .output()
            .expect("reject legacy profile");
        assert!(!rejected.status.success());
        let envelope: serde_json::Value =
            serde_json::from_slice(&rejected.stderr).expect("failure envelope");
        let message = envelope["error"]["message"]
            .as_str()
            .expect("failure message");
        assert!(message.contains("no longer supported"), "{message}");
        assert!(message.contains("auth logout legacy"), "{message}");
        assert!(message.contains("auth login"), "{message}");
        assert!(!message.contains("stored JSON is invalid"), "{message}");
    }

    let logout = ProcessCommand::new(env!("CARGO_BIN_EXE_cfctl"))
        .env("CFCTL_HOME", runtime.path())
        .args(["auth", "logout", "legacy", "--json"])
        .output()
        .expect("remove legacy profile metadata");
    assert!(
        logout.status.success(),
        "{}",
        String::from_utf8_lossy(&logout.stderr)
    );
    let logout: serde_json::Value =
        serde_json::from_slice(&logout.stdout).expect("logout envelope");
    assert_eq!(logout["result"]["credentials_removed"], false);
    assert_eq!(logout["result"]["legacy_profile_removed"], true);

    let saved: serde_json::Value = serde_json::from_slice(
        &fs::read(runtime.path().join("config/profiles.json")).expect("saved profiles"),
    )
    .expect("saved profile JSON");
    assert_eq!(saved["current_profile"], serde_json::Value::Null);
    assert_eq!(
        saved["profiles"].as_object().map(serde_json::Map::len),
        Some(0)
    );
}

fn write_legacy_wrangler_profile(runtime: &std::path::Path) {
    fs::create_dir_all(runtime.join("config")).expect("runtime config directory");
    fs::write(
        runtime.join("config/profiles.json"),
        r#"{
            "schema_version": 1,
            "current_profile": "legacy",
            "profiles": {
                "legacy": {
                    "schema_version": 1,
                    "id": "legacy",
                    "kind": "wrangler_session",
                    "account_id": "account-a",
                    "oauth_client_id": null,
                    "oauth_scopes": [],
                    "oauth_scope_inventory_hash": null,
                    "emergency_only": false
                }
            },
            "pending_logins": {}
        }"#,
    )
    .expect("legacy profile fixture");
}

fn write_emergency_global_key_current(runtime: &std::path::Path) {
    fs::create_dir_all(runtime.join("config")).expect("runtime config directory");
    fs::write(
        runtime.join("config/profiles.json"),
        r#"{
            "schema_version": 1,
            "current_profile": "emergency",
            "profiles": {
                "emergency": {
                    "schema_version": 1,
                    "id": "emergency",
                    "kind": "global_key",
                    "account_id": null,
                    "oauth_client_id": null,
                    "oauth_scopes": [],
                    "oauth_scope_inventory_hash": null,
                    "emergency_only": true
                }
            },
            "pending_logins": {}
        }"#,
    )
    .expect("emergency global-key current profile fixture");
}

fn write_fresh_accounts_list_catalog(runtime: &std::path::Path) {
    use cfctl_catalog::CatalogSnapshot;
    use cfctl_core::CapabilityV1;
    use chrono::Utc;
    use std::collections::BTreeMap;

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
    let path = runtime.join("data/catalog/catalog-v1.json");
    fs::create_dir_all(path.parent().expect("catalog parent")).expect("catalog directory");
    fs::write(
        &path,
        serde_json::to_vec_pretty(&catalog).expect("catalog JSON"),
    )
    .expect("write catalog fixture");
}

#[test]
fn binary_import_api_token_requires_stdin_flag() {
    let runtime = tempfile::tempdir().expect("runtime root");
    let output = ProcessCommand::new(env!("CARGO_BIN_EXE_cfctl"))
        .env("CFCTL_HOME", runtime.path())
        .args([
            "auth",
            "import-api-token",
            "--account",
            "account-a",
            "--json",
        ])
        .output()
        .expect("import-api-token without --stdin");
    assert!(!output.status.success());
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("--stdin"),
        "must require stdin sink: {combined}"
    );
}

#[test]
fn binary_import_global_key_requires_a_secret_source() {
    let runtime = tempfile::tempdir().expect("runtime root");
    let output = ProcessCommand::new(env!("CARGO_BIN_EXE_cfctl"))
        .env("CFCTL_HOME", runtime.path())
        .args([
            "auth",
            "import-global-key",
            "--email",
            "ops@example.com",
            "--json",
        ])
        .output()
        .expect("import-global-key without a source");
    assert!(!output.status.success());
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("--stdin") && combined.contains("--value-in"),
        "must offer both out-of-band sources: {combined}"
    );
}

#[test]
fn binary_auth_login_without_client_id_points_at_import_api_token() {
    let runtime = tempfile::tempdir().expect("runtime root");
    let output = ProcessCommand::new(env!("CARGO_BIN_EXE_cfctl"))
        .env("CFCTL_HOME", runtime.path())
        .env_remove("CFCTL_OAUTH_CLIENT_ID")
        .args(["auth", "login", "--json"])
        .output()
        .expect("auth login without client id");
    assert!(!output.status.success());
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("import-api-token"),
        "login without client-id must point operators at the simple token lane: {combined}"
    );
}

#[test]
fn binary_call_rejects_ambient_emergency_global_key_without_profile_flag() {
    let runtime = tempfile::tempdir().expect("runtime root");
    write_emergency_global_key_current(runtime.path());
    write_fresh_accounts_list_catalog(runtime.path());

    let output = ProcessCommand::new(env!("CARGO_BIN_EXE_cfctl"))
        .env("CFCTL_HOME", runtime.path())
        .args(["call", "accounts-list", "--json"])
        .output()
        .expect("run cfctl call with ambient global-key current profile");
    assert!(
        !output.status.success(),
        "ambient global-key must fail closed; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("never selected implicitly"),
        "expected ambient global-key denial, got: {combined}"
    );
}
