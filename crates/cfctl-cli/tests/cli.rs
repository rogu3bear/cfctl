#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::{fs, process::Command as ProcessCommand};

use cfctl_cli::{Cli, Command, InvocationMode, classify_invocation};
use clap::Parser;

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
