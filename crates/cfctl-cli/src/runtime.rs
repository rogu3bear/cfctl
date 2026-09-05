//! Deterministic command handlers for the cfctl v2 binary.

#![deny(clippy::wildcard_imports)]

mod access_application;
mod access_create;
mod access_ownership;
mod access_policy;
mod agent_commands;
mod api_boundary;
mod api_execution;
mod auth_commands;
mod call_command;
mod call_input;
mod catalog_commands;
mod cloudflare_api;
mod compensation;
mod credential_resolution;
mod delegated_execution;
mod delegated_read;
mod docs_commands;
mod entitlement_state;
mod error;
mod event_batch;
mod events_commands;
mod evidence_key_commands;
mod governed_cli;
mod guide_generation;
mod health_commands;
mod import_failures;
mod import_lineage;
mod import_planning;
mod import_resume;
mod keys_commands;
mod live_state_contracts;
mod mutation_input;
mod oauth_state;
mod pages_deployment;
mod pages_source;
mod plan_commands;
mod plan_create;
mod plan_prepare;
mod plan_secret;
mod plan_set;
mod policy_commands;
mod preconditions_authority;
mod preconditions_core;
mod preconditions_extended;
mod prelude;
mod private_runtime;
mod provider_state;
mod r2_credentials;
mod r2_private_upload;
mod read_execution;
mod rectification;
mod registry_commands;
mod secret_io;
mod security_action_input;
mod security_action_state;
mod support;
mod v1_migration;
mod worker_custom_domain;
mod worker_deployment;
mod worker_deployment_artifact;
mod workspace_commands;
mod workspace_d1_evidence;
mod workspace_d1_migration;
mod workspace_d1_projection;
mod workspace_d1_qualification;
mod workspace_d1_reply_admission;
mod workspace_d1_transition;
mod workspace_reply_subdomain_ingress;
mod workspace_state;

use agent_commands::agents_command;
use auth_commands::auth_command;
use call_command::call_command;
use catalog_commands::{catalog_command, guide_command, guide_topic_envelope};
use cfctl_agent::build_intent_action;
use cfctl_core::render_guide_topic_document_markdown;
use docs_commands::docs_command;
use events_commands::events_command;
use guide_generation::resolve_command;
use health_commands::{doctor_command, update_command, version_command};
use keys_commands::keys_command;
use plan_commands::plans_command;
use policy_commands::policy_command;
use prelude::{
    AgentLauncher, Cli, Command, EvidenceClass, GuideTopicDocumentV1, InvocationContext, Path,
    ProcessCommand, ResultEnvelopeV2, RuntimePaths, StateStore, Stdio, Value, env, json,
};
use registry_commands::registry_command;
use support::{cli_io, configured_agent};
use v1_migration::migrate_command;
use workspace_commands::workspace_command;

pub(crate) use call_input::verification_for_status;
pub(crate) use guide_generation::{
    capability_call_argv, capability_has_meaningful_request_body, required_selectors_json,
};

pub use error::CliError;

pub type Result<T> = std::result::Result<T, CliError>;

pub async fn execute(cli: Cli) -> Result<ResultEnvelopeV2> {
    let command = cli.command.ok_or_else(|| {
        CliError::Input("run `cfctl --help` or pass a natural-language intent".to_owned())
    })?;
    if let Command::Guide(arguments) = &command
        && let Some(topic) = arguments.topic
    {
        return guide_topic_envelope(topic);
    }
    if matches!(command, Command::Version) {
        return version_command();
    }
    if matches!(command, Command::Commands) {
        return Ok(crate::command_help::envelope());
    }
    let activating = matches!(
        &command,
        Command::Auth(crate::AuthArgs {
            command: crate::AuthCommand::EvidenceKey(crate::EvidenceKeyArgs {
                command: crate::EvidenceKeyCommand::PrivateActivate(_)
            })
        })
    );
    let _runtime_lock =
        cfctl_storage::lock_runtime_selection(&RuntimePaths::unselected()?, activating)?;
    let store = if command_uses_nonqualifying_audit_evidence(&command) {
        runtime_unqualified_state_store()?
    } else {
        runtime_qualifying_state_store()?
    };
    match command {
        Command::Commands => Ok(crate::command_help::envelope()),
        Command::Auth(arguments) => auth_command(&store, arguments.command).await,
        Command::Keys(arguments) => Box::pin(keys_command(&store, arguments.command)).await,
        Command::Catalog(arguments) => catalog_command(&store, arguments.command).await,
        Command::Call(arguments) => Box::pin(call_command(&store, arguments)).await,
        Command::Resolve(arguments) => resolve_command(&store, arguments).await,
        Command::Guide(arguments) => guide_command(&store, &arguments).await,
        Command::Plans(arguments) => Box::pin(plans_command(&store, arguments.command)).await,
        Command::Policy(arguments) => policy_command(&store, arguments.command),
        Command::Registry(arguments) => registry_command(&store, arguments.command),
        Command::Events(arguments) => events_command(&store, arguments.command),
        Command::Workspace(arguments) => workspace_command(&store, arguments.command),
        Command::Agents(arguments) => agents_command(&store, arguments.command),
        Command::Docs(arguments) => docs_command(&store, arguments.command).await,
        Command::Doctor => doctor_command(&store),
        Command::Version => version_command(),
        Command::Update(arguments) => update_command(arguments.check).await,
        Command::Migrate(arguments) => migrate_command(&store, arguments.command),
    }
}

pub async fn execute_natural_language(intent: &str) -> Result<ResultEnvelopeV2> {
    let runtime_lock = cfctl_storage::lock_runtime_selection(&RuntimePaths::unselected()?, false)?;
    let store = runtime_qualifying_state_store()?;
    let agent = configured_agent()?;
    let context = InvocationContext {
        agent_session: env::var_os("CFCTL_AGENT_SESSION").is_some(),
    };
    let invocation = AgentLauncher::new(agent).prepare(intent, &context)?;
    let action = build_intent_action(agent, intent, None)?;
    let evidence =
        store.write_evidence(EvidenceClass::AgentAction, &serde_json::to_value(&action)?)?;
    drop(runtime_lock);
    let mut process = ProcessCommand::new(&invocation.program);
    process.args(&invocation.args);
    for (key, value) in invocation.env {
        process.env(key, value);
    }
    process
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let status = process
        .status()
        .await
        .map_err(|source| cli_io(Path::new(&invocation.program), source))?;
    let mut envelope = ResultEnvelopeV2::success(
        "intent",
        json!({
            "agent": agent.label(),
            "agent_exit_status": status.code(),
            "message": "The agent interpreted intent; deterministic cfctl receipts remain authoritative."
        }),
    )
    .with_evidence(evidence);
    envelope.ok = status.success();
    Ok(envelope)
}

fn runtime_unqualified_state_store() -> Result<StateStore> {
    Ok(StateStore::open(RuntimePaths::discover()?)?)
}

fn runtime_qualifying_state_store() -> Result<StateStore> {
    let store = StateStore::open(RuntimePaths::discover()?)?;
    let authenticator = std::sync::Arc::new(store.platform_evidence_key_manager()?);
    Ok(store.with_evidence_authenticator(authenticator)?)
}

fn command_uses_nonqualifying_audit_evidence(command: &Command) -> bool {
    match command {
        // Cancellation de-authorizes a plan and migration imports only
        // non-secret historical state. Neither command may be blocked by a
        // missing evidence key, and neither output qualifies future authority.
        Command::Plans(arguments) => {
            matches!(&arguments.command, crate::PlansCommand::Cancel(_))
        }
        Command::Migrate(_) => true,
        _ => false,
    }
}

pub fn render(envelope: &ResultEnvelopeV2, json_output: bool) -> Result<String> {
    if json_output {
        return Ok(format!("{}\n", serde_json::to_string(envelope)?));
    }
    if let Some(error) = &envelope.error {
        let next = error
            .next_step
            .as_deref()
            .map(|step| format!("\nNext: {step}"))
            .unwrap_or_default();
        return Ok(format!("Error: {}{next}\n", error.message));
    }
    if envelope.command == "guide"
        && envelope.result.get("topic").is_some()
        && let Ok(document) =
            serde_json::from_value::<GuideTopicDocumentV1>(envelope.result.clone())
    {
        return Ok(render_guide_topic_document_markdown(&document));
    }
    if envelope.command == "version"
        && let Ok(build) =
            serde_json::from_value::<cfctl_core::BuildInfoV1>(envelope.result.clone())
    {
        let commit = build.git_commit.as_deref().unwrap_or("unknown");
        let source = match build.identity_source {
            cfctl_core::BuildIdentitySourceV1::ReleaseEnv => "release_env",
            cfctl_core::BuildIdentitySourceV1::GitCheckout => "git_checkout",
            cfctl_core::BuildIdentitySourceV1::Unknown => "unknown",
        };
        return Ok(format!("cfctl {} ({commit}, {source})\n", build.version));
    }
    if let Some(message) = envelope.result.get("message").and_then(Value::as_str) {
        return Ok(format!("{message}\n"));
    }
    Ok(format!(
        "{}\n",
        serde_json::to_string_pretty(&envelope.result)?
    ))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests;
