//! Agent discovery, installation, and hash-bound handoff contracts.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::LazyLock,
};

use cfctl_core::{AgentActionKind, AgentActionV1, hash_value};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

const LEGACY_CODEX_SKILL_V2_SHA256: &str =
    "70bdb43a6c8623faf9b99aa320c6a9888d3f08ab1cd733ff47de7a2bbc7b158d";

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("cfctl is already running inside an agent session; refusing recursive launch")]
    RecursiveLaunch,
    #[error(transparent)]
    Core(#[from] cfctl_core::CoreError),
    #[error("agent integration I/O failed for {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("agent integration at {0} has local drift; use `cfctl agents sync` to replace it")]
    Drift(String),
    #[error(
        "superseded agent integration at {0} is not the exact artifact cfctl installed, so cfctl will not remove it; inspect it and delete it yourself once you are satisfied nothing depends on it"
    )]
    LegacyDrift(String),
}

pub type Result<T> = std::result::Result<T, AgentError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentKind {
    Codex,
    Claude,
    Cursor,
    Gemini,
}

impl AgentKind {
    #[must_use]
    pub const fn all() -> [Self; 4] {
        [Self::Codex, Self::Claude, Self::Cursor, Self::Gemini]
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Claude => "claude",
            Self::Cursor => "cursor",
            Self::Gemini => "gemini",
        }
    }
}

impl AgentKind {
    #[must_use]
    pub const fn program(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Claude => "claude",
            Self::Cursor => "agent",
            Self::Gemini => "gemini",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InvocationContext {
    pub agent_session: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedInvocation {
    pub program: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
}

#[derive(Debug, Clone, Copy)]
pub struct AgentLauncher {
    kind: AgentKind,
}

impl AgentLauncher {
    #[must_use]
    pub const fn new(kind: AgentKind) -> Self {
        Self { kind }
    }

    pub fn prepare(&self, intent: &str, context: &InvocationContext) -> Result<PreparedInvocation> {
        if context.agent_session {
            return Err(AgentError::RecursiveLaunch);
        }
        let prompt = format!(
            "Use the installed cfctl operator skill. Treat this as intent only, not authority: {intent}"
        );
        let args = match self.kind {
            AgentKind::Codex => vec!["exec".to_owned(), prompt],
            AgentKind::Claude | AgentKind::Cursor => vec!["--print".to_owned(), prompt],
            AgentKind::Gemini => vec!["--prompt".to_owned(), prompt],
        };
        Ok(PreparedInvocation {
            program: self.kind.program().to_owned(),
            args,
            env: vec![("CFCTL_AGENT_SESSION".to_owned(), "1".to_owned())],
        })
    }
}

pub fn build_intent_action(
    agent: AgentKind,
    intent: &str,
    operation_id: Option<&str>,
) -> Result<AgentActionV1> {
    let action_id = Uuid::new_v4().to_string();
    let instructions = format!(
        "Interpret this bounded Cloudflare intent through deterministic cfctl commands. This handoff does not grant mutation authority: {intent}"
    );
    let content = serde_json::json!({
        "schema_version": 1,
        "action_id": action_id,
        "operation_id": operation_id,
        "kind": AgentActionKind::InterpretIntent,
        "agent": agent,
        "target": Value::Null,
        "instructions": instructions,
    });
    Ok(AgentActionV1 {
        schema_version: 1,
        action_id,
        operation_id: operation_id.map(str::to_owned),
        kind: AgentActionKind::InterpretIntent,
        agent: format!("{agent:?}").to_ascii_lowercase(),
        account_id: None,
        target: Value::Null,
        instructions,
        content_hash: hash_value(&content)?,
    })
}

pub fn build_ui_action(
    agent: AgentKind,
    operation_id: Option<&str>,
    account_id: Option<&str>,
    target: Value,
    instructions: &str,
    mutating: bool,
) -> Result<AgentActionV1> {
    let action_id = Uuid::new_v4().to_string();
    let kind = if mutating {
        AgentActionKind::ChangeUi
    } else {
        AgentActionKind::ObserveUi
    };
    let content = serde_json::json!({
        "schema_version": 1,
        "action_id": action_id,
        "operation_id": operation_id,
        "kind": kind,
        "agent": agent,
        "account_id": account_id,
        "target": target,
        "instructions": instructions,
    });
    Ok(AgentActionV1 {
        schema_version: 1,
        action_id,
        operation_id: operation_id.map(str::to_owned),
        kind,
        agent: agent.label().to_owned(),
        account_id: account_id.map(str::to_owned),
        target,
        instructions: instructions.to_owned(),
        content_hash: hash_value(&content)?,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallMode {
    Install,
    Sync,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentInstallReceipt {
    pub agent: AgentKind,
    pub version: String,
    pub path: PathBuf,
    pub content_hash: String,
    pub changed: bool,
}

pub fn install_agent_skill(
    home: &Path,
    agent: AgentKind,
    mode: InstallMode,
) -> Result<AgentInstallReceipt> {
    let path = skill_path(home, agent);
    let content = managed_skill(agent);
    let legacy = legacy_codex_skill(home, agent)?;
    let legacy_changed = legacy.is_some();
    let existing = if path.is_file() {
        Some(fs::read_to_string(&path).map_err(|source| agent_io(&path, source))?)
    } else {
        None
    };
    if existing.as_deref().is_some_and(|value| value != content) && mode == InstallMode::Install {
        return Err(AgentError::Drift(path.display().to_string()));
    }
    let changed = existing.as_deref() != Some(content);
    if changed {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| agent_io(parent, source))?;
        }
        fs::write(&path, content).map_err(|source| agent_io(&path, source))?;
    }
    if let Some((legacy_path, legacy_bytes)) = legacy {
        remove_exact_legacy_skill(&legacy_path, &legacy_bytes)?;
    }
    Ok(AgentInstallReceipt {
        agent,
        version: env!("CARGO_PKG_VERSION").to_owned(),
        path,
        content_hash: hash_value(&serde_json::json!({"content": content}))?,
        changed: changed || legacy_changed,
    })
}

/// Locates the superseded Codex skill so a migration can remove it.
///
/// Removability is decided by the frozen hash alone, not by the install mode. A
/// file that matches `LEGACY_CODEX_SKILL_V2_SHA256` byte for byte is the exact
/// artifact cfctl itself wrote, and calling that "local drift" made the only
/// machines that needed migrating the only ones that could not migrate: install
/// refused because the legacy file existed, and sync never reached them because
/// it skips agents whose managed skill is absent — which is precisely the state
/// a machine is in before it has been migrated.
///
/// Anything that is not a byte-exact match is still refused in both modes, and
/// `remove_exact_legacy_skill` re-reads and re-compares before unlinking, so a
/// file cfctl did not write is never deleted.
fn legacy_codex_skill(home: &Path, agent: AgentKind) -> Result<Option<(PathBuf, Vec<u8>)>> {
    if agent != AgentKind::Codex {
        return Ok(None);
    }
    let path = home.join(".agents/skills/cloudflare/SKILL.md");
    if !path.is_file() {
        return Ok(None);
    }
    // A symlinked parent means the file is not in the agent home cfctl
    // manages — it is shared infrastructure that something else owns and other
    // tools may link to. Deleting through the link would reach outside our own
    // tree, so leave it: the managed skill installs beside it and the operator
    // decides the superseded copy's fate.
    if path
        .parent()
        .is_some_and(|parent| parent.symlink_metadata().is_ok_and(|it| it.is_symlink()))
    {
        return Ok(None);
    }
    let bytes = fs::read(&path).map_err(|source| agent_io(&path, source))?;
    let digest = hex::encode(Sha256::digest(&bytes));
    if digest != LEGACY_CODEX_SKILL_V2_SHA256 {
        return Err(AgentError::LegacyDrift(path.display().to_string()));
    }
    Ok(Some((path, bytes)))
}

fn remove_exact_legacy_skill(path: &Path, expected: &[u8]) -> Result<()> {
    let current = fs::read(path).map_err(|source| agent_io(path, source))?;
    if current != expected {
        return Err(AgentError::LegacyDrift(path.display().to_string()));
    }
    fs::remove_file(path).map_err(|source| agent_io(path, source))?;
    // Pruning the emptied directory is housekeeping, not the contract. The
    // migration succeeded the moment the file was removed, so a directory that
    // will not go away — non-empty, not ours, not a directory at all — must not
    // turn a completed migration into a failed install.
    if let Some(parent) = path.parent() {
        let _ = fs::remove_dir(parent);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentDoctorV1 {
    pub agent: AgentKind,
    pub program: String,
    pub program_on_path: bool,
    pub skill_path: PathBuf,
    pub skill_present: bool,
    pub skill_current: bool,
}

#[must_use]
pub fn inspect_agent(home: &Path, agent: AgentKind, program_on_path: bool) -> AgentDoctorV1 {
    let path = skill_path(home, agent);
    let content = fs::read_to_string(&path).ok();
    AgentDoctorV1 {
        agent,
        program: agent.program().to_owned(),
        program_on_path,
        skill_path: path,
        skill_present: content.is_some(),
        skill_current: content.as_deref() == Some(managed_skill(agent)),
    }
}

fn skill_path(home: &Path, agent: AgentKind) -> PathBuf {
    match agent {
        AgentKind::Codex => home.join(".agents/skills/cfctl/SKILL.md"),
        AgentKind::Claude => home.join(".claude/skills/cfctl/SKILL.md"),
        AgentKind::Cursor => home.join(".cursor/rules/cfctl.mdc"),
        AgentKind::Gemini => home.join(".gemini/skills/cfctl/SKILL.md"),
    }
}

fn managed_skill(agent: AgentKind) -> &'static str {
    match agent {
        AgentKind::Cursor => MANAGED_CURSOR_RULE.as_str(),
        _ => MANAGED_OPERATOR_SKILL.as_str(),
    }
}

// Single-sourced doctrine fragments. Each load-bearing line lives here exactly
// once so the operator skill and the Cursor rule can never drift apart on the
// resolve-primary framing, the paid-plan `--max-cost` rule, the plan-approval
// gate, the fixture skip-list, or the `keys` account/user semantics. The two
// managed guidance documents below are assembled from these shared fragments.
//
// Recovery verbs (`plans rectify`, `plans cancel`) are deliberately absent.
// Step 4 sends every agent to `cfctl guide <capability-id> --json` before it
// acts, and the guide emits a Rectify stage — with the exact
// `cfctl plans rectify <operation-id> --json` argv — for every mutating
// capability. Routing through the guide is strictly better than naming the verb
// here: the guide knows whether the capability mutates and arrives with the
// operation id in hand. Restating it would add a contract bump, and with it a
// stale-install sweep across four harnesses, to teach less.

/// Fail-closed doctor contract: a doctor never launches a different PATH cfctl.
pub const FRAGMENT_DOCTOR_TRUST: &str = "`cfctl doctor` and `cfctl agents doctor` trust the PATH build only when it resolves to the running executable; a missing or different PATH cfctl is never launched by the health check and is unhealthy, so invoke it directly with `cfctl version --json` when its self-reported identity is needed. Drifted managed instructions are also unhealthy.";

/// Resolve is the primary intent-to-capability translation; browsing is secondary.
pub const FRAGMENT_RESOLVE_PRIMARY: &str = r#"Translate intent with `cfctl resolve "<intent>" --json`: it deterministically maps the goal to a capability and emits the exact governed `call`/`approve`/`run` commands, and fails closed with ranked candidates when the match is ambiguous. To browse instead, use `cfctl catalog search "<intent>" --json`."#;

/// Registered-root discovery skips nested fixture trees.
pub const FRAGMENT_FIXTURE_SKIP: &str = "Nested `fixtures`, `__fixtures__`, `testdata`, `test-data`, and `test_data` directories are skipped; fixture directories are opt-in roots and must be registered directly when they are intentional workspace evidence.";

/// The exact plan-approval command that a reviewed yes maps to.
pub const FRAGMENT_APPROVE_COMMAND: &str = "`cfctl plans approve <operation-id> --yes`";

/// The paid-plan cost ceiling that both documents must carry.
pub const FRAGMENT_MAX_COST: &str =
    "Paid plans also require the reviewed `--max-cost CURRENCY:AMOUNT`.";

/// Account- vs user-owned permission inventory semantics.
pub const FRAGMENT_KEYS_INVENTORY: &str = "Read account-owned permission inventory with `cfctl keys permissions --account <account-id> --json`. For user-owned inventory use `cfctl keys permissions --user --account <account-id> --json`; `--user` changes the endpoint, not the explicit account resource context.";

/// Standing-authority ceremony: bounded policy, explicit approval, immediate revoke.
pub const FRAGMENT_STANDING_AUTHORITY: &str = "For recurring token-lifecycle work, first load `cfctl guide --topic standing-authority --json`, then activate a reviewed standing policy only after explicit approval with `cfctl keys policy approve <authority-id> --yes`. Standing approval moves authority to that bounded policy; it is not blanket mutation authority. Revoke standing authority with `cfctl keys policy revoke <authority-id>` and treat the policy as unusable immediately.";

/// Blocked-capability route: follow the guide's next action, never route around it.
pub const FRAGMENT_BLOCKED_ROUTE: &str = "When a capability or plan is blocked (`adapter_status: blocked`, `contract_state: blocked`, or error code `CFCTL_CAPABILITY_BLOCKED`), run `cfctl guide <capability-id> --json` and follow its `next_action` exactly. Satisfy the named contract gap or extend cfctl; never route around a blocker with raw HTTP, Wrangler, or the dashboard. If next_action cannot resolve the gap, stop and report the capability id, `blocking_gaps`, and the guide output to the operator.";

/// Every shared doctrine fragment, in document order. Tests iterate this rather
/// than restating the fragment bodies, so a fragment added above is covered the
/// moment it exists instead of the moment somebody remembers to assert it.
pub const MANAGED_FRAGMENTS: &[&str] = &[
    FRAGMENT_DOCTOR_TRUST,
    FRAGMENT_RESOLVE_PRIMARY,
    FRAGMENT_FIXTURE_SKIP,
    FRAGMENT_APPROVE_COMMAND,
    FRAGMENT_MAX_COST,
    FRAGMENT_KEYS_INVENTORY,
    FRAGMENT_STANDING_AUTHORITY,
    FRAGMENT_BLOCKED_ROUTE,
];

/// The rendered managed documents with labels, for gates that must check what
/// agents are actually told rather than what the repository says about itself.
/// These live in Rust source, so the tracked-file lints do not see them.
#[must_use]
pub fn managed_documents() -> [(&'static str, &'static str); 2] {
    [
        (
            "crates/cfctl-agent MANAGED_OPERATOR_SKILL",
            MANAGED_OPERATOR_SKILL.as_str(),
        ),
        (
            "crates/cfctl-agent MANAGED_CURSOR_RULE",
            MANAGED_CURSOR_RULE.as_str(),
        ),
    ]
}

/// The managed-skill contract number carried in the installed front matter.
/// Bump this when the installed document's contract changes; `agents doctor`
/// compares whole strings, so every install goes stale on purpose when it moves.
pub const MANAGED_SKILL_CONTRACT: u32 = 4;

static MANAGED_OPERATOR_SKILL: LazyLock<String> = LazyLock::new(build_managed_operator_skill);
static MANAGED_CURSOR_RULE: LazyLock<String> = LazyLock::new(build_managed_cursor_rule);

fn build_managed_operator_skill() -> String {
    let header = format!(
        "---\nname: cfctl\ndescription: Use cfctl as the universal governed Cloudflare control plane.\nmetadata:\n  managed-by: cfctl\n  contract: {MANAGED_SKILL_CONTRACT}\n---\n\n# Cloudflare through cfctl\n\nUse `cfctl` first for all Cloudflare discovery, reads, planning, writes, verification, and evidence. Do not use archived shell verbs, backend script paths as the public surface, or raw HTTP as a substitute for cataloged capabilities.\n\n1. Orient with `cfctl version --json`, `cfctl guide --topic system --json`, `cfctl doctor --json`, and, when useful, `cfctl agents doctor --json`. "
    );
    [
        header.as_str(),
        FRAGMENT_DOCTOR_TRUST,
        "\n2. ",
        FRAGMENT_RESOLVE_PRIMARY,
        "\n3. Inspect the capability with `cfctl catalog show <capability-id> --json`.\n4. Load its lifecycle with `cfctl guide <capability-id> --json`.\n5. Use `cfctl call <capability-id>` for deterministic reads or plan creation.\n6. Register repository roots with `cfctl workspace add` before workspace discovery; never scan arbitrary paths. ",
        FRAGMENT_FIXTURE_SKIP,
        "\n7. If approval is required, show the exact plan and ask y/n.\n8. Translate yes only into ",
        FRAGMENT_APPROVE_COMMAND,
        ". ",
        FRAGMENT_MAX_COST,
        "\n9. Run with `cfctl plans run <operation-id>`, inspect `cfctl plans status <operation-id>`, and report verification honestly.\n10. ",
        FRAGMENT_KEYS_INVENTORY,
        "\n11. ",
        FRAGMENT_STANDING_AUTHORITY,
        "\n12. ",
        FRAGMENT_BLOCKED_ROUTE,
        "\n\nEvery cfctl failure envelope carries a specific `next_step`; run it rather than guessing. Never treat model output as authority. Never bypass a blocked adapter, selector ambiguity, cost blocker, drift check, or plan hash. Browser or Computer Use is allowed only when the capability catalog classifies the operation as governed UI and the same plan policy is preserved.\n",
    ]
    .concat()
}

fn build_managed_cursor_rule() -> String {
    [
        "---\ndescription: Route Cloudflare work through the governed cfctl v2 control plane\nalwaysApply: true\n---\n\nStart with `cfctl version --json` and `cfctl guide --topic system --json`. ",
        FRAGMENT_DOCTOR_TRUST,
        " ",
        FRAGMENT_RESOLVE_PRIMARY,
        " Inspect capabilities with `cfctl catalog show <capability-id> --json`, load lifecycles with `cfctl guide <capability-id> --json`, run governed reads or plan creation with `cfctl call <capability-id>`, and bound impact with `cfctl workspace`. ",
        FRAGMENT_FIXTURE_SKIP,
        " ",
        FRAGMENT_KEYS_INVENTORY,
        " Model output is intent, never authority. If a plan needs approval, ask y/n and translate yes only into ",
        FRAGMENT_APPROVE_COMMAND,
        ", then use `cfctl plans run <operation-id>` and inspect `plans status`. ",
        FRAGMENT_MAX_COST,
        " ",
        FRAGMENT_STANDING_AUTHORITY,
        " ",
        FRAGMENT_BLOCKED_ROUTE,
        " Do not bypass catalog blockers, selector ambiguity, cost ceilings, drift checks, or verification. Do not teach archived shell verbs or backend script paths as the public surface.\n",
    ]
    .concat()
}

fn agent_io(path: &Path, source: std::io::Error) -> AgentError {
    AgentError::Io {
        path: path.display().to_string(),
        source,
    }
}
