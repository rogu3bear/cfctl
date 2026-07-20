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
    assert_eq!(
        receipt.path,
        root.path().join(".agents/skills/cfctl/SKILL.md")
    );
    let content = std::fs::read_to_string(&receipt.path).expect("installed skill");
    assert!(content.starts_with("---\nname: cfctl\n"));
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
fn sync_migrates_only_the_exact_legacy_codex_skill() {
    let root = tempfile::tempdir().expect("agent home");
    let legacy = root.path().join(".agents/skills/cloudflare/SKILL.md");
    std::fs::create_dir_all(legacy.parent().expect("legacy parent"))
        .expect("create legacy directory");
    std::fs::write(&legacy, legacy_managed_skill()).expect("legacy skill");

    let receipt = install_agent_skill(root.path(), AgentKind::Codex, InstallMode::Sync)
        .expect("sync migrates exact legacy skill");
    assert!(receipt.changed);
    assert!(!legacy.exists());
    assert!(!legacy.parent().expect("legacy directory").exists());
    assert!(receipt.path.is_file());

    std::fs::create_dir_all(legacy.parent().expect("legacy parent"))
        .expect("recreate legacy directory");
    std::fs::write(&legacy, "operator-owned drift").expect("legacy drift");
    let error = install_agent_skill(root.path(), AgentKind::Codex, InstallMode::Sync)
        .expect_err("sync must preserve unknown legacy content");
    assert!(error.to_string().contains("local drift"));
    assert_eq!(
        std::fs::read_to_string(&legacy).expect("preserved legacy drift"),
        "operator-owned drift"
    );
}

fn legacy_managed_skill() -> &'static str {
    include_str!("fixtures/cfctl-managed-skill-v2.md")
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
    // Drift rectification: the Cursor rule must carry the paid-plan cost gate
    // and present `resolve` as the primary intent translator, matching the
    // operator skill rather than flattening it into an undifferentiated list.
    assert!(content.contains("`--max-cost CURRENCY:AMOUNT`"));
    assert!(content.contains("cfctl resolve \"<intent>\" --json"));
}

/// The shared doctrine fragments are single-sourced, so every load-bearing
/// line must appear verbatim in both the operator skill and the Cursor rule.
///
/// This iterates the exported fragment list rather than a hand-copied set of
/// substrings: a fragment added to the builders is covered the moment it
/// exists, instead of the moment somebody remembers to assert it here.
#[test]
fn shared_doctrine_is_identical_across_the_skill_and_cursor_rule() {
    let root = tempfile::tempdir().expect("agent home");
    let skill = install_and_read(root.path(), AgentKind::Codex);
    let cursor = install_and_read(root.path(), AgentKind::Cursor);
    assert!(
        !cfctl_agent::MANAGED_FRAGMENTS.is_empty(),
        "the fragment list must not be empty or this test proves nothing"
    );
    for fragment in cfctl_agent::MANAGED_FRAGMENTS {
        assert!(
            skill.contains(fragment),
            "operator skill missing: {fragment}"
        );
        assert!(cursor.contains(fragment), "cursor rule missing: {fragment}");
    }
}

/// The installed front matter's contract number derives from the exported
/// constant. Both assertions are load-bearing: the formatted one catches a
/// builder that stopped using the constant, the literal one catches a constant
/// bumped without intending every install to go stale.
#[test]
fn managed_skill_contract_header_is_single_sourced() {
    let root = tempfile::tempdir().expect("agent home");
    let skill = install_and_read(root.path(), AgentKind::Codex);
    assert!(skill.contains(&format!(
        "contract: {}",
        cfctl_agent::MANAGED_SKILL_CONTRACT
    )));
    assert!(skill.contains("contract: 4"));
}

fn install_and_read(home: &std::path::Path, agent: AgentKind) -> String {
    let receipt =
        install_agent_skill(home, agent, InstallMode::Install).expect("install managed guidance");
    std::fs::read_to_string(&receipt.path).expect("installed managed guidance")
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
