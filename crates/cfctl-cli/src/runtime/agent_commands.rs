use super::health_commands::health_envelope;
use super::health_commands::platform_secret_store_health;
use super::prelude::{
    AgentKind, AgentsCommand, EvidenceClass, InstallMode, Result, ResultEnvelopeV2, StateStore,
    env, json,
};
use super::support::configured_agent;
use super::support::home_directory;
use crate::build_identity::{build_identity_is_healthy, current_build_info, inspect_path_build};
use cfctl_agent::{inspect_agent, install_agent_skill};

pub(super) fn agents_command(
    store: &StateStore,
    command: AgentsCommand,
) -> Result<ResultEnvelopeV2> {
    let home = home_directory()?;
    match command {
        AgentsCommand::Install(arguments) => {
            let selected: Vec<AgentKind> = if arguments.all_detected {
                AgentKind::all()
                    .into_iter()
                    .filter(|agent| which::which(agent.program()).is_ok())
                    .collect()
            } else {
                vec![configured_agent()?]
            };
            let receipts = selected
                .into_iter()
                .map(|agent| install_agent_skill(&home, agent, InstallMode::Install))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let evidence = store
                .write_evidence(EvidenceClass::LocalProof, &serde_json::to_value(&receipts)?)?;
            Ok(ResultEnvelopeV2::success(
                "agents install",
                json!({"receipts": receipts, "message": "Managed cfctl discovery instructions installed for detected agents."}),
            )
            .with_evidence(evidence))
        }
        AgentsCommand::Sync => {
            // Sync replaces what is already installed; creating a missing
            // integration is `agents install`. Naming the agents it passed over
            // matters because the silent case is the confusing one: an operator
            // who runs sync to fix a missing skill would otherwise read
            // "synchronized" and believe it was done.
            let (present, skipped): (Vec<_>, Vec<_>) =
                AgentKind::all().into_iter().partition(|agent| {
                    inspect_agent(&home, *agent, which::which(agent.program()).is_ok())
                        .skill_present
                });
            let receipts = present
                .into_iter()
                .map(|agent| install_agent_skill(&home, agent, InstallMode::Sync))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let skipped: Vec<_> = skipped.into_iter().map(AgentKind::label).collect();
            let message = if skipped.is_empty() {
                "Existing managed integrations synchronized.".to_owned()
            } else {
                format!(
                    "Existing managed integrations synchronized. No managed instructions are installed for {}; run `cfctl agents install` to add them.",
                    skipped.join(", ")
                )
            };
            Ok(ResultEnvelopeV2::success(
                "agents sync",
                json!({"receipts": receipts, "skipped_agents": skipped, "message": message}),
            ))
        }
        AgentsCommand::Doctor => {
            let status: Vec<_> = AgentKind::all()
                .into_iter()
                .map(|agent| inspect_agent(&home, agent, which::which(agent.program()).is_ok()))
                .collect();
            let configured = configured_agent()?;
            let running_build = current_build_info();
            let build_identity_healthy = build_identity_is_healthy(&running_build);
            let path_build = inspect_path_build(&running_build);
            let instruction_drift = status
                .iter()
                .filter(|agent| agent.skill_present && !agent.skill_current)
                .count();
            let healthy = build_identity_healthy && path_build.healthy && instruction_drift == 0;
            Ok(health_envelope(
                "agents doctor",
                json!({
                    "running_build": running_build,
                    "build_identity_healthy": build_identity_healthy,
                    "path_build": path_build,
                    "configured_default_agent": configured,
                    "platform": env::consts::OS,
                    "platform_secret_store": platform_secret_store_health(store)?,
                    "instruction_drift": instruction_drift,
                    "agents": status,
                }),
                healthy,
                "CFCTL_AGENT_OR_BUILD_DRIFT",
                "The source identity, PATH build, or managed agent instructions are not current.",
            ))
        }
    }
}
