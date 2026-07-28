#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::{fs, process::Command as ProcessCommand};

use cfctl_cli::{
    Cli, Command, InvocationMode, KeysCommand,
    build_identity::{build_identity_is_healthy, current_build_info},
    classify_invocation,
};
use cfctl_core::{GuideTopicV1, PUBLIC_V2_SUBCOMMANDS, render_guide_topic_markdown};
use clap::{CommandFactory as _, Parser};

fn health_envelope(output: &std::process::Output, context: &str) -> serde_json::Value {
    let bytes = if output.status.success() {
        &output.stdout
    } else {
        &output.stderr
    };
    serde_json::from_slice(bytes).unwrap_or_else(|error| {
        panic!(
            "{context} did not emit a JSON health envelope: {error}: {}",
            String::from_utf8_lossy(bytes)
        )
    })
}

#[test]
fn every_public_command_group_is_parseable() {
    // Iterate the single source of truth so a newly added top-level verb cannot
    // slip in without a parse example here (this is what once let `resolve`
    // escape coverage).
    for command in PUBLIC_V2_SUBCOMMANDS {
        let arguments: Vec<&str> = match *command {
            "auth" => vec!["cfctl", "auth", "status"],
            "keys" => vec!["cfctl", "keys", "permissions", "--account", "account-a"],
            "catalog" => vec!["cfctl", "catalog", "coverage"],
            "call" => vec!["cfctl", "call", "dns-records-list"],
            "resolve" => vec!["cfctl", "resolve", "list dns records"],
            "guide" => vec!["cfctl", "guide", "dns-records-delete"],
            "plans" => vec!["cfctl", "plans", "status", "operation-id"],
            "policy" => vec!["cfctl", "policy", "admission", "list"],
            "registry" => vec!["cfctl", "registry", "status"],
            "workspace" => vec!["cfctl", "workspace", "graph"],
            "agents" => vec!["cfctl", "agents", "doctor"],
            "docs" => vec!["cfctl", "docs", "coverage"],
            "events" => vec!["cfctl", "events", "status"],
            "doctor" => vec!["cfctl", "doctor"],
            "update" => vec!["cfctl", "update", "--check"],
            "version" => vec!["cfctl", "version"],
            "migrate" => vec!["cfctl", "migrate", "v1"],
            other => panic!("PUBLIC_V2_SUBCOMMANDS verb `{other}` has no parse example"),
        };
        let parsed = Cli::try_parse_from(arguments).expect("public command parses");
        assert!(
            matches!(parsed.command, Some(Command::Auth(_))) == (*command == "auth")
                || *command != "auth"
        );
    }
}

#[test]
fn version_reports_structured_build_identity_without_touching_runtime_state() {
    let runtime = tempfile::tempdir().expect("runtime root");
    let output = ProcessCommand::new(env!("CARGO_BIN_EXE_cfctl"))
        .env("CFCTL_HOME", runtime.path())
        .args(["version", "--json"])
        .output()
        .expect("run version");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("version envelope");
    assert_eq!(envelope["command"], "version");
    assert_eq!(envelope["result"]["schema_version"], 1);
    assert_eq!(envelope["result"]["version"], env!("CARGO_PKG_VERSION"));
    assert!(
        matches!(
            envelope["result"]["identity_source"].as_str(),
            Some("release_env" | "git_checkout" | "unknown")
        ),
        "{envelope}"
    );
    let commit = envelope["result"]["git_commit"].as_str();
    assert!(
        commit.is_none_or(|value| {
            value.len() == 40
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }),
        "{envelope}"
    );
    assert!(
        fs::read_dir(runtime.path())
            .expect("inspect untouched runtime root")
            .next()
            .is_none(),
        "version must not initialize mutable runtime state"
    );
}

#[test]
fn clap_human_version_behavior_remains_compatible() {
    let output = ProcessCommand::new(env!("CARGO_BIN_EXE_cfctl"))
        .arg("--version")
        .output()
        .expect("run clap version");
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).expect("version is UTF-8"),
        format!("cfctl {}\n", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn json_parser_failures_are_v2_usage_envelopes_with_exit_two() {
    let output = ProcessCommand::new(env!("CARGO_BIN_EXE_cfctl"))
        .args(["--json", "keys", "permissions"])
        .output()
        .expect("run invalid JSON invocation");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stderr).expect("usage failure envelope");
    assert_eq!(envelope["schema_version"], 2);
    assert_eq!(envelope["ok"], false);
    assert_eq!(envelope["command"], "cfctl");
    assert_eq!(envelope["error"]["code"], "CFCTL_USAGE");
    assert!(
        envelope["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("--account")),
        "{envelope}"
    );
}

#[test]
fn human_parser_failures_and_metadata_keep_clap_behavior() {
    let failure = ProcessCommand::new(env!("CARGO_BIN_EXE_cfctl"))
        .args(["keys", "permissions"])
        .output()
        .expect("run invalid human invocation");
    assert_eq!(failure.status.code(), Some(2));
    assert!(failure.stdout.is_empty());
    let stderr = String::from_utf8(failure.stderr).expect("human usage is UTF-8");
    assert!(stderr.starts_with("error:"), "{stderr}");
    assert!(serde_json::from_str::<serde_json::Value>(&stderr).is_err());

    for argument in ["--help", "--version"] {
        let metadata = ProcessCommand::new(env!("CARGO_BIN_EXE_cfctl"))
            .args(["--json", argument])
            .output()
            .expect("run Clap metadata with JSON flag present");
        assert!(metadata.status.success(), "{argument}");
        assert!(!metadata.stdout.is_empty(), "{argument}");
        assert!(metadata.stderr.is_empty(), "{argument}");
    }
}

#[test]
fn permission_inventory_requires_account_for_both_owners() {
    assert!(Cli::try_parse_from(["cfctl", "keys", "permissions"]).is_err());

    let account = Cli::try_parse_from(["cfctl", "keys", "permissions", "--account", "account-a"])
        .expect("account-owned inventory parses");
    let Some(Command::Keys(account)) = account.command else {
        panic!("keys command");
    };
    let KeysCommand::Permissions(account) = account.command else {
        panic!("permissions command");
    };
    assert!(!account.user);
    assert_eq!(account.account, "account-a");

    let user = Cli::try_parse_from([
        "cfctl",
        "keys",
        "permissions",
        "--user",
        "--account",
        "account-a",
    ])
    .expect("user-owned inventory parses");
    let Some(Command::Keys(user)) = user.command else {
        panic!("keys command");
    };
    let KeysCommand::Permissions(user) = user.command else {
        panic!("permissions command");
    };
    assert!(user.user);
    assert_eq!(user.account, "account-a");
}

#[test]
fn public_command_contract_exactly_matches_the_clap_tree() {
    let command = Cli::command();
    let mut actual = command
        .get_subcommands()
        .map(clap::Command::get_name)
        .collect::<Vec<_>>();
    actual.sort_unstable();
    assert_eq!(actual, PUBLIC_V2_SUBCOMMANDS);
}

#[test]
fn public_subcommand_tree_exactly_matches_the_clap_tree() {
    use cfctl_core::{CommandNodeV1, PUBLIC_V2_COMMAND_TREE};

    fn child_names(command: &clap::Command) -> Vec<String> {
        let mut names = command
            .get_subcommands()
            .map(|sub| sub.get_name().to_owned())
            .filter(|name| name != "help")
            .collect::<Vec<_>>();
        names.sort_unstable();
        names
    }

    fn declared_names(node: &CommandNodeV1) -> Vec<String> {
        let mut names = node
            .subcommands
            .iter()
            .map(|child| child.name.to_owned())
            .collect::<Vec<_>>();
        names.sort_unstable();
        names
    }

    fn assert_node_matches(parent: &clap::Command, node: &CommandNodeV1) {
        let clap_child = parent
            .find_subcommand(node.name)
            .unwrap_or_else(|| panic!("clap tree is missing subcommand `{}`", node.name));
        assert_eq!(
            child_names(clap_child),
            declared_names(node),
            "subcommands of `{}` drifted from PUBLIC_V2_COMMAND_TREE",
            node.name
        );
        // Recurse into every declared child, leaves included. A declared leaf
        // asserts its clap node has no children of its own, so a command group
        // cannot sprout beneath a node the tree calls final.
        for child in node.subcommands {
            assert_node_matches(clap_child, child);
        }
    }

    let root = Cli::command();
    for node in PUBLIC_V2_COMMAND_TREE {
        assert_node_matches(&root, node);
    }

    // Every clap verb that itself takes subcommands must be declared in the
    // tree, so a newly added command group cannot silently escape the contract.
    // This stays top-level only on purpose: leaf verbs (`call`, `guide`,
    // `resolve`, `doctor`, `version`, `update`) take arguments rather than
    // subcommands and are absent from the tree by design. Nested completeness
    // is already enforced by the per-node name equality above, in both
    // directions, at every depth.
    let mut clap_groups = root
        .get_subcommands()
        .filter(|sub| {
            sub.get_subcommands()
                .any(|nested| nested.get_name() != "help")
        })
        .map(|sub| sub.get_name().to_owned())
        .collect::<Vec<_>>();
    clap_groups.sort_unstable();
    let mut tree_groups = PUBLIC_V2_COMMAND_TREE
        .iter()
        .map(|node| node.name.to_owned())
        .collect::<Vec<_>>();
    tree_groups.sort_unstable();
    assert_eq!(
        clap_groups, tree_groups,
        "top-level command groups drifted from PUBLIC_V2_COMMAND_TREE"
    );
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
fn system_topics_run_without_opening_mutable_runtime_state() {
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
            fs::read_dir(runtime.path())
                .expect("inspect untouched runtime root")
                .next()
                .is_none(),
            "a static topic must not create the runtime tree, load a catalog, or touch account state"
        );
    }
}

#[test]
fn human_system_topics_render_the_same_markdown_as_checked_in_guidance() {
    let runtime = tempfile::tempdir().expect("runtime root");
    for (topic, contract) in [
        ("system", GuideTopicV1::System),
        ("standing-authority", GuideTopicV1::StandingAuthority),
    ] {
        let output = ProcessCommand::new(env!("CARGO_BIN_EXE_cfctl"))
            .env("CFCTL_HOME", runtime.path())
            .args(["guide", "--topic", topic])
            .output()
            .expect("run human system topic");
        assert!(
            output.status.success(),
            "{topic}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8(output.stdout).expect("topic markdown is UTF-8"),
            render_guide_topic_markdown(contract)
        );
        assert!(
            fs::read_dir(runtime.path())
                .expect("inspect untouched runtime root")
                .next()
                .is_none(),
            "human topic rendering must remain stateless"
        );
    }
}

#[test]
fn migrate_v1_accepts_quarantined_repo_state_and_external_legacy_state() {
    for source_root in ["compat/v1/state", "state"] {
        let workspace = tempfile::tempdir().expect("legacy workspace");
        let runtime = tempfile::tempdir().expect("runtime root");
        let source = workspace.path().join(source_root).join("dns.record");
        fs::create_dir_all(&source).expect("create retained state root");
        fs::write(
            source.join("example.json"),
            r#"{"match":{"name":"example"},"body":{"name":"example"}}"#,
        )
        .expect("write retained state");

        let output = ProcessCommand::new(env!("CARGO_BIN_EXE_cfctl"))
            .current_dir(workspace.path())
            .env("CFCTL_HOME", runtime.path())
            .args(["migrate", "v1", "--json"])
            .output()
            .expect("run v1 migration");
        assert!(
            output.status.success(),
            "{source_root}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let envelope: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("migration envelope");
        let imported = envelope["result"]["imported"]
            .as_array()
            .expect("import list");
        assert_eq!(imported.len(), 1, "{source_root}");
        assert!(
            imported[0]["source_path"].as_str().is_some_and(
                |path| path.ends_with(&format!("{source_root}/dns.record/example.json"))
            )
        );
        assert!(
            imported[0]["destination"]
                .as_str()
                .is_some_and(|path| path.ends_with("/state/dns.record/example.json")),
            "both source layouts must preserve the v1 `state` import label"
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
fn retired_v1_command_shapes_fail_closed_instead_of_launching_an_agent() {
    for verb in [
        "admin",
        "bootstrap",
        "cloudflared",
        "env",
        "form-intake",
        "hostname",
        "lanes",
        "locks",
        "maildesk-cf",
        "ownership",
        "previews",
        "skills",
        "standards",
        "surfaces",
        "wrangler",
    ] {
        assert_eq!(
            classify_invocation(["cfctl", verb, "legacy-target"]),
            InvocationMode::Deterministic,
            "retired v1 command `{verb}` must reach clap and fail closed"
        );
    }
    for verb in [
        "apply", "can", "classify", "diff", "explain", "get", "list", "snapshot", "verify",
    ] {
        assert_eq!(
            classify_invocation(["cfctl", verb, "dns.record"]),
            InvocationMode::Deterministic,
            "retired v1 surface command `{verb}` must fail closed"
        );
    }
    for arguments in [["cfctl", "token", "mint"], ["cfctl", "token", "revoke"]] {
        assert_eq!(
            classify_invocation(arguments),
            InvocationMode::Deterministic,
            "retired token lifecycle command must fail closed"
        );
    }
    for arguments in [
        ["cfctl", "token", "permission-groups"],
        ["cfctl", "token", "rotate"],
        ["cfctl", "audit", "trust"],
        ["cfctl", "audit", "access"],
        ["cfctl", "audit", "state"],
    ] {
        assert_eq!(
            classify_invocation(arguments),
            InvocationMode::Deterministic,
            "concrete retired v1 command must fail closed: {arguments:?}"
        );
    }
}

#[test]
fn retired_words_do_not_disable_clear_natural_language_requests() {
    for arguments in [
        ["cfctl", "audit", "my Cloudflare account"],
        ["cfctl", "diff", "current DNS configuration"],
        ["cfctl", "explain", "how standing authority works"],
        ["cfctl", "list", "dns records"],
        ["cfctl", "verify", "the production zone"],
    ] {
        assert!(
            matches!(
                classify_invocation(arguments),
                InvocationMode::NaturalLanguage(_)
            ),
            "clear natural language must keep the agent lane: {arguments:?}"
        );
    }

    let audit_request = [
        "cfctl",
        "audit",
        "access",
        "posture",
        "for",
        "the",
        "production",
        "account",
    ];
    assert!(
        matches!(
            classify_invocation(audit_request),
            InvocationMode::NaturalLanguage(_)
        ),
        "only the exact retired two-token audit command may fail closed"
    );
}

#[test]
fn retired_multi_token_command_exits_nonzero_without_launching_an_agent() {
    for arguments in [
        ["diff", "dns.record"],
        ["token", "permission-groups"],
        ["token", "rotate"],
        ["audit", "trust"],
        ["audit", "access"],
        ["audit", "state"],
    ] {
        let output = ProcessCommand::new(env!("CARGO_BIN_EXE_cfctl"))
            .args(arguments)
            .output()
            .expect("cfctl binary runs");
        assert!(!output.status.success(), "{arguments:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("unrecognized subcommand"),
            "retired command {arguments:?} must reach clap instead of the agent launcher, got: {stderr}"
        );
    }
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
#[expect(
    clippy::too_many_lines,
    reason = "the isolated CLI contract covers doctor, registered workspace add/remove, registry sync, and rebuild in one process-boundary fixture"
)]
fn isolated_doctor_and_registered_workspace_emit_v2_envelopes() {
    let runtime = tempfile::tempdir().expect("runtime root");
    let workspace = tempfile::tempdir().expect("workspace root");
    let binary = std::path::Path::new(env!("CARGO_BIN_EXE_cfctl"));
    let binary_dir = binary.parent().expect("binary directory");

    let doctor = ProcessCommand::new(binary)
        .env("CFCTL_HOME", runtime.path())
        .env("HOME", runtime.path())
        .env("PATH", binary_dir)
        .args(["doctor", "--json"])
        .output()
        .expect("run isolated doctor");
    let identity_healthy = build_identity_is_healthy(&current_build_info());
    assert_eq!(doctor.status.success(), identity_healthy);
    let doctor = health_envelope(&doctor, "doctor");
    assert_eq!(doctor["schema_version"], 2);
    assert_eq!(doctor["ok"], identity_healthy);
    assert_eq!(doctor["performed"], false);
    assert_eq!(doctor["command"], "doctor");
    assert_eq!(doctor["result"]["build_identity_healthy"], identity_healthy);
    assert_eq!(doctor["result"]["catalog"]["present"], false);
    assert_eq!(doctor["result"]["path_build"]["state"], "current");
    assert_eq!(
        doctor["result"]["running_build"],
        doctor["result"]["path_build"]["build"]
    );
    assert!(doctor["result"]["public_oauth"].is_string());

    let add = ProcessCommand::new(env!("CARGO_BIN_EXE_cfctl"))
        .env("CFCTL_HOME", runtime.path())
        .args([
            "workspace",
            "add",
            workspace.path().to_str().expect("UTF-8 workspace path"),
            "--account",
            "account-a",
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

    let remove = ProcessCommand::new(env!("CARGO_BIN_EXE_cfctl"))
        .env("CFCTL_HOME", runtime.path())
        .args([
            "workspace",
            "remove",
            workspace.path().to_str().expect("UTF-8 workspace path"),
            "--json",
        ])
        .output()
        .expect("remove registered workspace");
    assert!(
        remove.status.success(),
        "{}",
        String::from_utf8_lossy(&remove.stderr)
    );
    let remove: serde_json::Value =
        serde_json::from_slice(&remove.stdout).expect("workspace remove JSON");
    assert_eq!(remove["schema_version"], 2);
    assert_eq!(remove["ok"], true);
    assert_eq!(remove["performed"], false);
    assert_eq!(remove["command"], "workspace remove");
    assert_eq!(remove["result"]["removed"], true);
    assert_eq!(remove["result"]["account_pin_removed"], true);

    let graph = ProcessCommand::new(env!("CARGO_BIN_EXE_cfctl"))
        .env("CFCTL_HOME", runtime.path())
        .args(["workspace", "graph", "--json"])
        .output()
        .expect("read workspace graph after removal");
    assert!(graph.status.success());
    let graph: serde_json::Value =
        serde_json::from_slice(&graph.stdout).expect("workspace graph JSON");
    assert_eq!(
        graph["result"]["repositories"].as_array().map(Vec::len),
        Some(0)
    );
    assert_eq!(
        graph["result"]["resources"].as_array().map(Vec::len),
        Some(0)
    );
}

#[test]
fn isolated_registry_is_versioned_rebuildable_and_honest_about_partial_coverage() {
    let runtime = tempfile::tempdir().expect("runtime root");
    let binary = std::path::Path::new(env!("CARGO_BIN_EXE_cfctl"));

    let adopt = ProcessCommand::new(binary)
        .env("CFCTL_HOME", runtime.path())
        .args([
            "registry",
            "scopes",
            "adopt",
            "--kind",
            "account",
            "--id",
            "account-a",
            "--json",
        ])
        .output()
        .expect("adopt registry scope");
    assert!(
        adopt.status.success(),
        "{}",
        String::from_utf8_lossy(&adopt.stderr)
    );

    let sync = ProcessCommand::new(binary)
        .env("CFCTL_HOME", runtime.path())
        .args(["registry", "sync", "--json"])
        .output()
        .expect("sync registry");
    assert!(
        sync.status.success(),
        "{}",
        String::from_utf8_lossy(&sync.stderr)
    );
    let sync: serde_json::Value = serde_json::from_slice(&sync.stdout).expect("registry sync JSON");
    assert_eq!(sync["schema_version"], 2);
    assert_eq!(sync["command"], "registry sync");
    assert_eq!(sync["performed"], false);
    assert_eq!(sync["result"]["coverage"]["partial"], true);
    assert_eq!(
        sync["result"]["coverage"]["blockers"][0],
        "no live inventory providers are registered"
    );

    let status = ProcessCommand::new(binary)
        .env("CFCTL_HOME", runtime.path())
        .args(["registry", "status", "--json"])
        .output()
        .expect("registry status");
    assert!(status.status.success());
    let status: serde_json::Value =
        serde_json::from_slice(&status.stdout).expect("registry status JSON");
    assert_eq!(status["result"]["database_schema_version"], 3);
    assert_eq!(status["result"]["journal_mode"], "wal");
    assert_eq!(status["result"]["integrity"], "ok");
    assert!(status["result"]["last_sync_at"].is_string());

    let rebuild = ProcessCommand::new(binary)
        .env("CFCTL_HOME", runtime.path())
        .args(["registry", "rebuild", "--json"])
        .output()
        .expect("rebuild registry");
    assert!(
        rebuild.status.success(),
        "{}",
        String::from_utf8_lossy(&rebuild.stderr)
    );
    let rebuild: serde_json::Value =
        serde_json::from_slice(&rebuild.stdout).expect("registry rebuild JSON");
    assert!(
        std::path::Path::new(rebuild["result"]["backup"].as_str().expect("backup path")).is_file()
    );
}

#[test]
fn admission_policy_lifecycle_requires_separate_explicit_approval() {
    let runtime = tempfile::tempdir().expect("runtime root");
    let inputs = tempfile::tempdir().expect("input root");
    let binary = std::path::Path::new(env!("CARGO_BIN_EXE_cfctl"));
    let bundle_file = inputs.path().join("bundle.json");
    fs::write(
        &bundle_file,
        serde_json::to_vec_pretty(&serde_json::json!({
            "name":"block worker deletion",
            "rules":[{
                "rule_id":"deny-worker-delete",
                "capability_id":"workers-delete",
                "disposition":"blocked",
                "reason":"local policy forbids deletion"
            }]
        }))
        .expect("bundle JSON"),
    )
    .expect("write bundle input");
    let stage = ProcessCommand::new(binary)
        .env("CFCTL_HOME", runtime.path())
        .args([
            "policy",
            "admission",
            "stage",
            "--file",
            bundle_file.to_str().expect("bundle path"),
            "--json",
        ])
        .output()
        .expect("stage admission bundle");
    assert!(
        stage.status.success(),
        "{}",
        String::from_utf8_lossy(&stage.stderr)
    );
    let stage: serde_json::Value = serde_json::from_slice(&stage.stdout).expect("stage JSON");
    let bundle_id = stage["result"]["bundle"]["bundle_id"]
        .as_str()
        .expect("bundle id");
    assert_eq!(stage["result"]["bundle"]["status"], "pending");

    let approve = ProcessCommand::new(binary)
        .env("CFCTL_HOME", runtime.path())
        .args([
            "policy",
            "admission",
            "approve",
            bundle_id,
            "--yes",
            "--json",
        ])
        .output()
        .expect("approve admission bundle");
    assert!(approve.status.success());
    let activate = ProcessCommand::new(binary)
        .env("CFCTL_HOME", runtime.path())
        .args(["policy", "admission", "activate", bundle_id, "--json"])
        .output()
        .expect("activate admission bundle");
    assert!(activate.status.success());
    let activate: serde_json::Value =
        serde_json::from_slice(&activate.stdout).expect("activate JSON");
    assert_eq!(activate["result"]["bundle"]["status"], "active");
}

#[test]
fn generalized_authority_and_event_watch_are_not_public_commands() {
    assert!(Cli::try_parse_from(["cfctl", "authority", "list"]).is_err());
    assert!(
        Cli::try_parse_from([
            "cfctl",
            "events",
            "watch",
            "--queue",
            "queue-a",
            "--subscription",
            "subscription-a",
        ])
        .is_err()
    );
}

#[test]
fn historical_plan_v1_is_readable_but_unconsumed_mutation_requires_replanning() {
    use cfctl_core::{CapabilityV1, PlanV1, TransactionStageV1};
    use cfctl_storage::{RuntimePaths, StateStore};

    let runtime = tempfile::tempdir().expect("runtime root");
    let store = StateStore::open(RuntimePaths::from_root(runtime.path())).expect("store");
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "sha256:catalog",
        CapabilityV1::new(
            "workers-delete",
            "Delete worker",
            "DELETE",
            "/accounts/{account_id}/workers/{script_name}",
        ),
        serde_json::json!({"script_name":"worker-a"}),
    )
    .expect("historical plan");
    plan.created_at = chrono::DateTime::parse_from_rfc3339("2026-07-20T00:00:00Z")
        .expect("historical timestamp")
        .with_timezone(&chrono::Utc);
    plan.expires_at = chrono::Utc::now() + chrono::Duration::hours(1);
    plan.transaction_journal.clear();
    plan.refresh_hash().expect("refresh historical plan");
    plan.record_transaction_stage(TransactionStageV1::PlanPrepared)
        .expect("historical journal");
    store.save_plan(&plan).expect("save historical plan");

    let binary = std::path::Path::new(env!("CARGO_BIN_EXE_cfctl"));
    let show = ProcessCommand::new(binary)
        .env("CFCTL_HOME", runtime.path())
        .args(["plans", "show", &plan.operation_id, "--json"])
        .output()
        .expect("show historical plan");
    assert!(show.status.success());
    let show: serde_json::Value = serde_json::from_slice(&show.stdout).expect("show JSON");
    assert_eq!(show["result"]["schema_version"], 1);
    assert_eq!(show["result"]["execution_compatible"], false);
    assert_eq!(
        show["result"]["execution_incompatibility_reason"],
        "legacy_plan_v1"
    );

    let approve = ProcessCommand::new(binary)
        .env("CFCTL_HOME", runtime.path())
        .args(["plans", "approve", &plan.operation_id, "--yes", "--json"])
        .output()
        .expect("refuse historical approval");
    assert!(!approve.status.success());
    let approve = health_envelope(&approve, "historical PlanV1 approval");
    assert_eq!(approve["error"]["code"], "CFCTL_PLAN_REPLAN_REQUIRED");
}

#[test]
fn current_mutation_missing_plan_v2_is_readable_but_fails_closed() {
    use cfctl_core::{CapabilityV1, PlanV1};
    use cfctl_storage::{RuntimePaths, StateStore};

    let runtime = tempfile::tempdir().expect("runtime root");
    let store = StateStore::open(RuntimePaths::from_root(runtime.path())).expect("store");
    let plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "sha256:catalog",
        CapabilityV1::new(
            "workers-delete",
            "Delete worker",
            "DELETE",
            "/accounts/{account_id}/workers/{script_name}",
        ),
        serde_json::json!({"script_name":"worker-a"}),
    )
    .expect("current plan");
    store
        .save_plan(&plan)
        .expect("inject missing PlanV2 fixture");

    let binary = std::path::Path::new(env!("CARGO_BIN_EXE_cfctl"));
    let show = ProcessCommand::new(binary)
        .env("CFCTL_HOME", runtime.path())
        .args(["plans", "show", &plan.operation_id, "--json"])
        .output()
        .expect("show incomplete current plan");
    assert!(show.status.success());
    let show: serde_json::Value = serde_json::from_slice(&show.stdout).expect("show JSON");
    assert_eq!(show["result"]["execution_compatible"], false);
    assert_eq!(
        show["result"]["execution_incompatibility_reason"],
        "required_plan_v2_missing"
    );

    let approve = ProcessCommand::new(binary)
        .env("CFCTL_HOME", runtime.path())
        .args(["plans", "approve", &plan.operation_id, "--yes", "--json"])
        .output()
        .expect("refuse incomplete current plan");
    assert!(!approve.status.success());
    let approve = health_envelope(&approve, "current plan missing PlanV2");
    assert_eq!(approve["error"]["code"], "CFCTL_PLAN_V2_MISSING");

    let cancel = ProcessCommand::new(binary)
        .env("CFCTL_HOME", runtime.path())
        .args(["plans", "cancel", &plan.operation_id, "--json"])
        .output()
        .expect("cancel incomplete current plan");
    assert!(cancel.status.success());
    let cancelled: serde_json::Value = serde_json::from_slice(&cancel.stdout).expect("cancel JSON");
    assert_eq!(cancelled["result"]["status"], "cancelled");
}

#[test]
fn isolated_agents_doctor_accepts_the_exact_running_path_build() {
    let runtime = tempfile::tempdir().expect("runtime root");
    let binary = std::path::Path::new(env!("CARGO_BIN_EXE_cfctl"));
    let binary_dir = binary.parent().expect("binary directory");
    let output = ProcessCommand::new(binary)
        .env("CFCTL_HOME", runtime.path())
        .env("HOME", runtime.path())
        .env("PATH", binary_dir)
        .env("CFCTL_AGENT", "codex")
        .args(["agents", "doctor", "--json"])
        .output()
        .expect("run isolated agents doctor");
    let identity_healthy = build_identity_is_healthy(&current_build_info());
    assert_eq!(output.status.success(), identity_healthy);
    let envelope = health_envelope(&output, "agents doctor");
    assert_eq!(envelope["command"], "agents doctor");
    assert_eq!(
        envelope["result"]["build_identity_healthy"],
        identity_healthy
    );
    assert_eq!(envelope["result"]["path_build"]["state"], "current");
    assert_eq!(envelope["result"]["instruction_drift"], 0);
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
    let binary = std::path::Path::new(env!("CARGO_BIN_EXE_cfctl"));
    let binary_dir = binary.parent().expect("binary directory");

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

    let doctor = ProcessCommand::new(binary)
        .env("CFCTL_HOME", runtime.path())
        .env("HOME", runtime.path())
        .env("PATH", binary_dir)
        .args(["doctor", "--json"])
        .output()
        .expect("diagnose legacy profile");
    let identity_healthy = build_identity_is_healthy(&current_build_info());
    assert_eq!(doctor.status.success(), identity_healthy);
    let doctor = health_envelope(&doctor, "legacy profile doctor");
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
