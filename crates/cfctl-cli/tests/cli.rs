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
