//! Agent discovery, installation, and hash-bound handoff contracts.

use std::{
    fs,
    path::{Path, PathBuf},
};

use cfctl_core::{AgentActionKind, AgentActionV1, hash_value};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

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
    Ok(AgentInstallReceipt {
        agent,
        version: env!("CARGO_PKG_VERSION").to_owned(),
        path,
        content_hash: hash_value(&serde_json::json!({"content": content}))?,
        changed,
    })
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
        AgentKind::Codex => home.join(".agents/skills/cloudflare/SKILL.md"),
        AgentKind::Claude => home.join(".claude/skills/cfctl/SKILL.md"),
        AgentKind::Cursor => home.join(".cursor/rules/cfctl.mdc"),
        AgentKind::Gemini => home.join(".gemini/skills/cfctl/SKILL.md"),
    }
}

fn managed_skill(agent: AgentKind) -> &'static str {
    match agent {
        AgentKind::Cursor => MANAGED_CURSOR_RULE,
        _ => MANAGED_SKILL,
    }
}

const MANAGED_SKILL: &str = r#"---
name: cloudflare
description: Use cfctl as the universal governed Cloudflare control plane.
metadata:
  managed-by: cfctl
  contract: 2
---

# Cloudflare through cfctl

Use `cfctl` first for all Cloudflare discovery, reads, planning, writes, verification, and evidence. Do not use archived shell verbs, backend script paths as the public surface, or raw HTTP as a substitute for cataloged capabilities.

1. Orient with `cfctl doctor --json` and, when useful, `cfctl agents doctor --json`.
2. Translate intent with `cfctl catalog search "<intent>" --json`.
3. Inspect the capability with `cfctl catalog show <capability-id> --json`.
4. Load its lifecycle with `cfctl guide <capability-id> --json`.
5. Use `cfctl call <capability-id>` for deterministic reads or plan creation.
6. Register repository roots with `cfctl workspace add` before workspace discovery; never scan arbitrary paths.
7. If approval is required, show the exact plan and ask y/n.
8. Translate yes only into `cfctl plans approve <operation-id> --yes`. Paid plans also require the reviewed `--max-cost CURRENCY:AMOUNT`.
9. Run with `cfctl plans run <operation-id>`, inspect `cfctl plans status <operation-id>`, and report verification honestly.
10. For recurring token-lifecycle work, activate a reviewed standing policy only after explicit approval with `cfctl keys policy approve <authority-id> --yes`. Standing approval moves authority to that bounded policy; it is not blanket mutation authority.
11. Revoke standing authority with `cfctl keys policy revoke <authority-id>` and treat the policy as unusable immediately.

Never treat model output as authority. Never bypass a blocked adapter, selector ambiguity, cost blocker, drift check, or plan hash. Browser or Computer Use is allowed only when the capability catalog classifies the operation as governed UI and the same plan policy is preserved.
"#;

const MANAGED_CURSOR_RULE: &str = r"---
description: Route Cloudflare work through the governed cfctl v2 control plane
alwaysApply: true
---

Use `cfctl doctor`, `cfctl catalog search`, `cfctl catalog show`, `cfctl guide`, `cfctl call`, and `cfctl workspace` for Cloudflare work. Model output is intent, never authority. If a plan needs approval, ask y/n and translate yes only into `cfctl plans approve <operation-id> --yes`, then use `cfctl plans run <operation-id>` and inspect `plans status`. For recurring token-lifecycle work, activate a reviewed standing policy only after explicit approval with `cfctl keys policy approve <authority-id> --yes`; this moves authority to that bounded policy, not to arbitrary mutations. Revoke it with `cfctl keys policy revoke <authority-id>` and treat it as unusable immediately. Do not bypass catalog blockers, selector ambiguity, cost ceilings, drift checks, or verification. Do not teach archived shell verbs or backend script paths as the public surface.
";

fn agent_io(path: &Path, source: std::io::Error) -> AgentError {
    AgentError::Io {
        path: path.display().to_string(),
        source,
    }
}
