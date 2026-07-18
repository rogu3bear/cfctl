#![allow(clippy::expect_used, clippy::unwrap_used)]

use cfctl_agent::{
    AgentKind, AgentLauncher, InstallMode, InvocationContext, build_intent_action,
    install_agent_skill,
};

#[test]
fn bare_intent_launches_the_configured_agent_once() {
    let launcher = AgentLauncher::new(AgentKind::Codex);
    let invocation = launcher
        .prepare(
            "rotate the production Worker secret",
            &InvocationContext::default(),
        )
        .expect("initial invocation can launch");
    assert_eq!(invocation.program, "codex");
    assert!(
        invocation
            .env
            .iter()
            .any(|(k, v)| k == "CFCTL_AGENT_SESSION" && v == "1")
    );

    let nested = InvocationContext {
        agent_session: true,
    };
    assert!(launcher.prepare("same intent", &nested).is_err());
}

#[test]
fn agent_skill_installation_is_managed_versioned_and_does_not_overwrite_drift() {
    let root = tempfile::tempdir().expect("agent home");
    let receipt = install_agent_skill(root.path(), AgentKind::Codex, InstallMode::Install)
        .expect("install skill");
    let content = std::fs::read_to_string(&receipt.path).expect("installed skill");
    assert!(content.contains("cfctl version --json"));
    assert!(content.contains("cfctl resolve \"<intent>\" --json"));
    assert!(content.contains("cfctl catalog search"));
    assert!(content.contains("cfctl guide --topic system --json"));
    assert!(content.contains("cfctl keys permissions --account <account-id> --json"));
    assert!(content.contains("cfctl keys permissions --user --account <account-id> --json"));
    assert!(content.contains("cfctl guide --topic standing-authority --json"));
    assert!(content.contains("cfctl plans approve <operation-id> --yes"));
    assert!(content.contains("cfctl keys policy approve <authority-id> --yes"));
    assert!(content.contains("cfctl keys policy revoke <authority-id>"));
    assert!(content.contains("fixture directories are opt-in roots"));
    assert!(content.contains("Every cfctl failure envelope carries a specific `next_step`"));
    assert!(content.contains("contract: 4"));
    assert!(content.contains("CFCTL_CAPABILITY_BLOCKED"));
    assert!(content.contains("cfctl guide <capability-id> --json"));
    assert!(content.contains("report the capability id, `blocking_gaps`, and the guide output"));
    assert!(!content.to_ascii_lowercase().contains("mcp"));

    std::fs::write(&receipt.path, "user-owned drift").expect("drift fixture");
    let error = install_agent_skill(root.path(), AgentKind::Codex, InstallMode::Install)
        .expect_err("install cannot overwrite drift");
    assert!(error.to_string().contains("sync"));
}

#[test]
fn cursor_guidance_preserves_plan_approval_and_explains_standing_policy_ceremony() {
    let root = tempfile::tempdir().expect("agent home");
    let receipt = install_agent_skill(root.path(), AgentKind::Cursor, InstallMode::Install)
        .expect("install Cursor rule");
    let content = std::fs::read_to_string(&receipt.path).expect("installed Cursor rule");

    assert!(content.contains("cfctl version --json"));
    assert!(content.contains("cfctl plans approve <operation-id> --yes"));
    assert!(content.contains("cfctl guide --topic system --json"));
    assert!(content.contains("cfctl keys permissions --account <account-id> --json"));
    assert!(content.contains("cfctl keys permissions --user --account <account-id> --json"));
    assert!(content.contains("cfctl guide --topic standing-authority --json"));
    assert!(content.contains("cfctl keys policy approve <authority-id> --yes"));
    assert!(content.contains("cfctl keys policy revoke <authority-id>"));
    assert!(content.contains("fixture directories are opt-in roots"));
    assert!(content.contains("CFCTL_CAPABILITY_BLOCKED"));
    assert!(content.contains("cfctl guide <capability-id> --json"));
}

#[test]
fn agent_actions_are_hash_bound_and_do_not_grant_authority() {
    let action =
        build_intent_action(AgentKind::Claude, "inspect DNS", None).expect("action should build");
    assert!(action.content_hash.starts_with("sha256:"));
    assert!(
        action
            .instructions
            .contains("does not grant mutation authority")
    );
}
