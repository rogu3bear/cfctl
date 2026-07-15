//! Deterministic command handlers for the cfctl v2 binary.

use std::{
    collections::BTreeMap,
    env, fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use cfctl_agent::{
    AgentKind, AgentLauncher, InstallMode, InvocationContext, build_intent_action, build_ui_action,
    inspect_agent, install_agent_skill,
};
use cfctl_auth::{
    AuthCredential, OAuthClientConfig, PkceSession, PlatformSecretStore, ProfileKind,
    ProfileMetadata, SecretStore, exchange_authorization_code, refresh_oauth_tokens,
    revoke_oauth_token,
};
use cfctl_catalog::{
    CatalogIndex, CatalogSnapshot, OfficialTextFeedsV1, attach_official_product_knowledge,
    fetch_official, fetch_official_text_feeds, ingest_cli_help, ingest_governed_ui_capabilities,
};
use cfctl_cloudflare::{
    CallInput, CloudflareError, CloudflareResponseV1, Executor, OperationVerificationV1,
};
use cfctl_core::{
    AdapterStatus, CapabilityV1, ErrorV1, EvidenceClass, EvidenceV1, MoneyV1, PlanStatus, PlanV1,
    PolicyDisposition, ResultEnvelopeV2, RiskClass, TransactionStageV1, VerificationState,
    guide_stages, hash_value, redact_json,
};
use cfctl_planner::{ImpactContext, PolicyEngine};
use cfctl_storage::{RuntimePaths, StateStore};
use cfctl_workspace::{RegisteredRoot, WorkspaceGraph};
use chrono::{Duration as ChronoDuration, Utc};
use futures_util::{StreamExt, stream};
use serde_json::{Map, Value, json};
use thiserror::Error;
use tokio::process::Command as ProcessCommand;

use crate::{
    AgentsCommand, AuthCommand, AuthLoginArgs, CallArgs, CatalogCommand, Cli, Command, DocsCommand,
    GuideArgs, ImportGlobalKeyArgs, KeyMutationArgs, KeyPermissionArgs, KeyRevokeArgs,
    KeyRotateArgs, KeysCommand, MigrateCommand, PlanApproveArgs, PlanSelector, PlansCommand,
    ProfileSelector, SearchArgs, WorkspaceCommand,
    profiles::{PendingLogin, ProfilesConfig},
};

const API_BASE_URL: &str = "https://api.cloudflare.com/client/v4";

#[derive(Debug, Error)]
pub enum CliError {
    #[error("{0}")]
    Input(String),
    #[error("I/O failed for {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error(transparent)]
    Storage(#[from] cfctl_storage::StorageError),
    #[error(transparent)]
    Catalog(#[from] cfctl_catalog::CatalogError),
    #[error(transparent)]
    Auth(#[from] cfctl_auth::AuthError),
    #[error(transparent)]
    Core(#[from] cfctl_core::CoreError),
    #[error(transparent)]
    Cloudflare(#[from] cfctl_cloudflare::CloudflareError),
    #[error(transparent)]
    Workspace(#[from] cfctl_workspace::WorkspaceError),
    #[error(transparent)]
    Agent(#[from] cfctl_agent::AgentError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("HTTP client construction failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("subprocess `{0}` exceeded the 120-second governed timeout")]
    SubprocessTimeout(String),
}

pub type Result<T> = std::result::Result<T, CliError>;

pub async fn execute(cli: Cli) -> Result<ResultEnvelopeV2> {
    let store = StateStore::open(RuntimePaths::discover()?)?;
    let command = cli.command.ok_or_else(|| {
        CliError::Input("run `cfctl --help` or pass a natural-language intent".to_owned())
    })?;
    match command {
        Command::Auth(arguments) => auth_command(&store, arguments.command).await,
        Command::Keys(arguments) => keys_command(&store, arguments.command).await,
        Command::Catalog(arguments) => catalog_command(&store, arguments.command).await,
        Command::Call(arguments) => call_command(&store, arguments).await,
        Command::Guide(arguments) => guide_command(&store, &arguments).await,
        Command::Plans(arguments) => plans_command(&store, arguments.command).await,
        Command::Workspace(arguments) => workspace_command(&store, arguments.command),
        Command::Agents(arguments) => agents_command(&store, arguments.command),
        Command::Docs(arguments) => docs_command(&store, arguments.command).await,
        Command::Doctor => doctor_command(&store),
        Command::Update(arguments) => update_command(arguments.check).await,
        Command::Migrate(arguments) => migrate_command(&store, arguments.command),
    }
}

pub async fn execute_natural_language(intent: &str) -> Result<ResultEnvelopeV2> {
    let store = StateStore::open(RuntimePaths::discover()?)?;
    let agent = configured_agent()?;
    let context = InvocationContext {
        agent_session: env::var_os("CFCTL_AGENT_SESSION").is_some(),
    };
    let invocation = AgentLauncher::new(agent).prepare(intent, &context)?;
    let action = build_intent_action(agent, intent, None)?;
    let evidence =
        store.write_evidence(EvidenceClass::AgentAction, &serde_json::to_value(&action)?)?;
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
    if let Some(message) = envelope.result.get("message").and_then(Value::as_str) {
        return Ok(format!("{message}\n"));
    }
    Ok(format!(
        "{}\n",
        serde_json::to_string_pretty(&envelope.result)?
    ))
}

async fn auth_command(store: &StateStore, command: AuthCommand) -> Result<ResultEnvelopeV2> {
    let secrets = PlatformSecretStore;
    let mut profiles = ProfilesConfig::load(store)?;
    match command {
        AuthCommand::Login(arguments) if !arguments.complete => {
            begin_oauth_login(store, &mut profiles, &secrets, arguments).await
        }
        AuthCommand::Login(arguments) => {
            complete_oauth_login(store, &mut profiles, &secrets, arguments).await
        }
        AuthCommand::Status(selector) => auth_status(&profiles, &secrets, &selector),
        AuthCommand::Profiles => Ok(ResultEnvelopeV2::success(
            "auth profiles",
            json!({"current": profiles.current_profile, "profiles": profiles.profiles.values().collect::<Vec<_>>() }),
        )),
        AuthCommand::Use(selector) => use_profile(store, &mut profiles, &selector),
        AuthCommand::Logout(selector) => {
            logout_profile(store, &mut profiles, &secrets, &selector).await
        }
        AuthCommand::ImportGlobalKey(arguments) => {
            import_global_key(store, &mut profiles, &secrets, &arguments)
        }
    }
}

async fn begin_oauth_login(
    store: &StateStore,
    profiles: &mut ProfilesConfig,
    secrets: &dyn SecretStore,
    arguments: AuthLoginArgs,
) -> Result<ResultEnvelopeV2> {
    let requested_scopes =
        resolve_login_scopes(store, profiles, secrets, &arguments.scopes).await?;
    let client = OAuthClientConfig::cfctl_public(&arguments.client_id);
    let scopes: Vec<&str> = requested_scopes.iter().map(String::as_str).collect();
    let session = PkceSession::begin(&client, &scopes)?;
    secrets.put(
        &format!("pending/{}/pkce-verifier", arguments.profile),
        &session.code_verifier,
    )?;
    profiles.pending_logins.insert(
        arguments.profile.clone(),
        PendingLogin {
            profile_id: arguments.profile.clone(),
            state: session.state.clone(),
            client,
            scopes: requested_scopes,
            account_id: arguments.account,
        },
    );
    profiles.save(store)?;
    Ok(ResultEnvelopeV2::success(
        "auth login",
        json!({
            "authorization_url": session.authorization_url,
            "profile": arguments.profile,
            "message": "Open the authorization URL, then pipe the callback payload `STATE CODE` into `cfctl auth login --complete` with the same profile and client ID."
        }),
    ))
}

async fn complete_oauth_login(
    store: &StateStore,
    profiles: &mut ProfilesConfig,
    secrets: &dyn SecretStore,
    arguments: AuthLoginArgs,
) -> Result<ResultEnvelopeV2> {
    let pending = profiles
        .pending_logins
        .get(&arguments.profile)
        .cloned()
        .ok_or_else(|| CliError::Input(format!("no pending login for `{}`", arguments.profile)))?;
    if pending.client.client_id != arguments.client_id {
        return Err(CliError::Input(
            "OAuth client ID differs from the pending login".to_owned(),
        ));
    }
    let (state, code) = parse_callback(&read_stdin()?)?;
    if state != pending.state {
        return Err(CliError::Input(
            "OAuth state does not match the pending login".to_owned(),
        ));
    }
    let verifier_key = format!("pending/{}/pkce-verifier", arguments.profile);
    let verifier = secrets
        .get(&verifier_key)?
        .ok_or_else(|| CliError::Input("pending PKCE verifier is missing".to_owned()))?;
    let tokens =
        exchange_authorization_code(&http_client()?, &pending.client, &code, &verifier).await?;
    secrets.store_oauth_tokens(&arguments.profile, &tokens)?;
    secrets.delete(&verifier_key)?;
    let mut profile = ProfileMetadata::new(
        &arguments.profile,
        ProfileKind::OAuth,
        pending.account_id.as_deref(),
    );
    profile.oauth_client_id = Some(pending.client.client_id);
    profile.oauth_scopes = tokens.scopes().into_iter().map(str::to_owned).collect();
    profile.oauth_scope_inventory_hash = oauth_scope_inventory_hash(store)?;
    profiles.profiles.insert(arguments.profile.clone(), profile);
    profiles.current_profile = Some(arguments.profile.clone());
    profiles.pending_logins.remove(&arguments.profile);
    profiles.save(store)?;
    Ok(ResultEnvelopeV2::success(
        "auth login",
        json!({
            "profile": arguments.profile,
            "scopes": tokens.scopes(),
            "expires_at": tokens.expires_at(),
            "message": "OAuth login completed; tokens were stored in the platform credential store."
        }),
    ))
}

fn auth_status(
    profiles: &ProfilesConfig,
    secrets: &dyn SecretStore,
    selector: &ProfileSelector,
) -> Result<ResultEnvelopeV2> {
    let profile = profiles
        .profiles
        .get(&selector.profile)
        .ok_or_else(|| CliError::Input(format!("profile `{}` does not exist", selector.profile)))?;
    let credential_available = secrets.load_credential(&profile.id, profile.kind).is_ok();
    Ok(ResultEnvelopeV2::success(
        "auth status",
        json!({"profile": profile, "credential_available": credential_available, "selected": profiles.current_profile.as_deref() == Some(&profile.id)}),
    ))
}

fn use_profile(
    store: &StateStore,
    profiles: &mut ProfilesConfig,
    selector: &ProfileSelector,
) -> Result<ResultEnvelopeV2> {
    if !profiles.profiles.contains_key(&selector.profile) {
        return Err(CliError::Input(format!(
            "profile `{}` does not exist",
            selector.profile
        )));
    }
    profiles.current_profile = Some(selector.profile.clone());
    profiles.save(store)?;
    Ok(ResultEnvelopeV2::success(
        "auth use",
        json!({"profile": selector.profile, "message": "Active profile changed."}),
    ))
}

async fn logout_profile(
    store: &StateStore,
    profiles: &mut ProfilesConfig,
    secrets: &dyn SecretStore,
    selector: &ProfileSelector,
) -> Result<ResultEnvelopeV2> {
    if let Some(profile) = profiles.profiles.get(&selector.profile)
        && profile.kind == ProfileKind::OAuth
    {
        let tokens = secrets.load_oauth_tokens(&profile.id)?;
        let client_id = profile
            .oauth_client_id
            .as_deref()
            .ok_or_else(|| CliError::Input("OAuth profile is missing its client ID".to_owned()))?;
        let token = tokens
            .refresh_token()
            .unwrap_or_else(|| tokens.access_token());
        revoke_oauth_token(
            &http_client()?,
            &OAuthClientConfig::cfctl_public(client_id),
            token,
        )
        .await?;
    }
    secrets.delete_profile(&selector.profile)?;
    profiles.profiles.remove(&selector.profile);
    profiles.pending_logins.remove(&selector.profile);
    if profiles.current_profile.as_deref() == Some(&selector.profile) {
        profiles.current_profile = None;
    }
    profiles.save(store)?;
    Ok(ResultEnvelopeV2::success(
        "auth logout",
        json!({"profile": selector.profile, "message": "Profile credentials and metadata were removed."}),
    ))
}

fn import_global_key(
    store: &StateStore,
    profiles: &mut ProfilesConfig,
    secrets: &dyn SecretStore,
    arguments: &ImportGlobalKeyArgs,
) -> Result<ResultEnvelopeV2> {
    if !arguments.stdin {
        return Err(CliError::Input(
            "global keys are accepted only through stdin; add `--stdin`".to_owned(),
        ));
    }
    let key = read_stdin()?.trim().to_owned();
    if key.is_empty() {
        return Err(CliError::Input(
            "stdin did not contain a global key".to_owned(),
        ));
    }
    secrets.store_global_key(&arguments.profile, &arguments.email, &key)?;
    let profile = ProfileMetadata::new(&arguments.profile, ProfileKind::GlobalKey, None);
    profiles.profiles.insert(arguments.profile.clone(), profile);
    profiles.save(store)?;
    Ok(ResultEnvelopeV2::success(
        "auth import-global-key",
        json!({
            "profile": arguments.profile,
            "emergency_only": true,
            "selected": false,
            "message": "Emergency global key stored. It was not selected."
        }),
    ))
}

async fn catalog_command(store: &StateStore, command: CatalogCommand) -> Result<ResultEnvelopeV2> {
    match command {
        CatalogCommand::Sync => sync_catalog(store).await,
        CatalogCommand::Search(arguments) => {
            let catalog = ensure_catalog(store).await?;
            let results: Vec<_> = catalog
                .search(&arguments.query)
                .into_iter()
                .take(arguments.limit)
                .collect();
            Ok(ResultEnvelopeV2::success(
                "catalog search",
                serde_json::to_value(results)?,
            ))
        }
        CatalogCommand::Show(selector) => {
            let catalog = ensure_catalog(store).await?;
            let capability = catalog
                .get(&selector.capability_id)
                .ok_or_else(|| capability_missing(&selector.capability_id))?;
            Ok(ResultEnvelopeV2::success(
                "catalog show",
                serde_json::to_value(capability)?,
            ))
        }
        CatalogCommand::Changes => {
            let current = ensure_catalog(store).await?;
            let previous_path = store.paths().catalog_previous_file();
            let changes = if previous_path.is_file() {
                CatalogSnapshot::diff(&CatalogSnapshot::load(&previous_path)?, &current)
            } else {
                Vec::new()
            };
            Ok(ResultEnvelopeV2::success(
                "catalog changes",
                json!({"current_schema_hash": current.schema_hash, "changes": changes, "has_previous_snapshot": previous_path.is_file()}),
            ))
        }
        CatalogCommand::Coverage => {
            let catalog = ensure_catalog(store).await?;
            Ok(ResultEnvelopeV2::success(
                "catalog coverage",
                serde_json::to_value(catalog.coverage())?,
            ))
        }
    }
}

async fn sync_catalog(store: &StateStore) -> Result<ResultEnvelopeV2> {
    let client = http_client()?;
    let (mut catalog, feeds) =
        tokio::try_join!(fetch_official(&client), fetch_official_text_feeds(&client))?;
    attach_official_product_knowledge(&mut catalog, &feeds)?;
    for (program, version_argument) in [("wrangler", "--version"), ("cloudflared", "version")] {
        if which::which(program).is_ok() {
            let help = std::process::Command::new(program)
                .arg("--help")
                .output()
                .map_err(|source| cli_io(Path::new(program), source))?;
            let version = std::process::Command::new(program)
                .arg(version_argument)
                .output()
                .map_err(|source| cli_io(Path::new(program), source))?;
            ingest_cli_help(
                &mut catalog,
                program,
                String::from_utf8_lossy(&version.stdout).trim(),
                &String::from_utf8_lossy(&help.stdout),
            );
        }
    }
    ingest_governed_ui_capabilities(&mut catalog);
    catalog.refresh_hash()?;
    let oauth_scope_status = match refresh_oauth_scopes_if_authenticated(store).await {
        Ok(Some(snapshot)) => json!({
            "status": "refreshed",
            "schema_hash": snapshot.get("schema_hash"),
            "count": snapshot.pointer("/scopes").and_then(Value::as_array).map(Vec::len),
        }),
        Ok(None) => json!({"status": "not_refreshed", "reason": "no active authenticated profile"}),
        Err(error) => json!({"status": "not_refreshed", "reason": error.to_string()}),
    };
    let current_path = store.paths().catalog_file();
    if current_path.is_file() {
        let current = CatalogSnapshot::load(&current_path)?;
        store.write_json(&store.paths().catalog_previous_file(), &current)?;
    }
    store.write_json(&current_path, &catalog)?;
    store.write_json(&docs_file(store), &feeds)?;
    let index_path = catalog_index_file(store);
    CatalogIndex::rebuild(&index_path, &catalog)?;
    let evidence = store.write_evidence(
        EvidenceClass::LiveRead,
        &json!({
            "source": catalog.source_url,
            "schema_hash": catalog.schema_hash,
            "capability_count": catalog.capabilities.len(),
            "docs_index_url": feeds.docs_index_url,
            "changelog_url": feeds.changelog_url,
            "oauth_scope_inventory": oauth_scope_status.clone(),
        }),
    )?;
    Ok(ResultEnvelopeV2::success(
        "catalog sync",
        json!({
            "coverage": catalog.coverage(),
            "docs_fetched_at": feeds.fetched_at,
            "oauth_scope_inventory": oauth_scope_status,
            "message": format!("Catalog synced: {} API, CLI, and governed UI capabilities indexed.", catalog.capabilities.len())
        }),
    )
    .with_evidence(evidence))
}

async fn guide_command(store: &StateStore, arguments: &GuideArgs) -> Result<ResultEnvelopeV2> {
    let catalog = ensure_catalog(store).await?;
    let capability = catalog
        .get(&arguments.capability_id)
        .ok_or_else(|| capability_missing(&arguments.capability_id))?;
    let stages: Vec<Value> = guide_stages()
        .iter()
        .enumerate()
        .map(|(index, stage)| {
            json!({
                "stage": index + 1,
                "name": format!("{stage:?}").to_ascii_lowercase(),
                "capability_id": capability.id,
                "required": stage_required(*stage, capability),
            })
        })
        .collect();
    Ok(ResultEnvelopeV2::success(
        "guide",
        json!({"capability": capability, "stages": stages}),
    ))
}

async fn call_command(store: &StateStore, arguments: CallArgs) -> Result<ResultEnvelopeV2> {
    let catalog = ensure_catalog(store).await?;
    let capability = catalog
        .get(&arguments.capability_id)
        .cloned()
        .ok_or_else(|| capability_missing(&arguments.capability_id))?;
    if capability.risk == RiskClass::SecretSensitive && arguments.value_out.is_none() {
        return Err(CliError::Input(
            "secret-producing capabilities require `--value-out <new-path>`; the value is never written to stdout or evidence"
                .to_owned(),
        ));
    }
    let mut prepared = call_input(&arguments)?;
    if !capability.mutating {
        if prepared.secret_body.is_some() {
            return Err(CliError::Input(
                "read operations cannot accept secret request bodies".to_owned(),
            ));
        }
        return execute_read(
            store,
            &catalog,
            &capability,
            &prepared.input,
            arguments.profile.as_deref(),
            arguments.account.as_deref(),
        )
        .await;
    }
    let secrets = PlatformSecretStore;
    let mut secret_ref = None;
    let mut adapter_targets = Map::new();
    if let Some(secret_body) = &prepared.secret_body {
        let reference = format!("plan-input/{}", uuid::Uuid::new_v4());
        let content_hash = hash_value(secret_body)?;
        secrets.put(&reference, &serde_json::to_string(secret_body)?)?;
        prepared.input.body = Some(json!({
            "$cfctl_secret_body_ref": reference,
            "content_hash": content_hash,
        }));
        secret_ref = Some(reference.clone());
        adapter_targets.insert("secret_body_ref".to_owned(), Value::String(reference));
        adapter_targets.insert("secret_body_hash".to_owned(), Value::String(content_hash));
    }
    if let Some(value_out) = &arguments.value_out {
        adapter_targets.insert(
            "value_out".to_owned(),
            Value::String(value_out.display().to_string()),
        );
    }
    let result = create_plan(
        store,
        &catalog,
        capability,
        prepared.input,
        arguments.profile.as_deref(),
        arguments.account.as_deref(),
        Value::Object(adapter_targets),
    );
    if result.is_err()
        && let Some(reference) = secret_ref
    {
        secrets.delete(&reference)?;
    }
    result
}

async fn execute_read(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &cfctl_core::CapabilityV1,
    input: &CallInput,
    requested_profile: Option<&str>,
    requested_account: Option<&str>,
) -> Result<ResultEnvelopeV2> {
    match capability.adapter_status {
        AdapterStatus::DelegatedCli => {
            return execute_delegated_read(
                store,
                catalog,
                capability,
                input,
                requested_profile,
                requested_account,
            )
            .await;
        }
        AdapterStatus::GovernedUi => {
            return execute_governed_ui_read(
                store,
                catalog,
                capability,
                input,
                requested_profile,
                requested_account,
            );
        }
        AdapterStatus::Blocked => {
            return Err(CliError::Input(format!(
                "capability is blocked: {}",
                capability
                    .blocked_reason
                    .as_deref()
                    .unwrap_or("no executable adapter is available")
            )));
        }
        AdapterStatus::Native | AdapterStatus::DynamicApi => {}
    }
    let profiles = ProfilesConfig::load(store)?;
    let profile = profiles.selected(requested_profile)?;
    let account_id = resolve_account_id(store, profile, requested_account, input)?;
    let credential = fresh_credential(profile, &PlatformSecretStore).await?;
    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let response = executor
        .execute_read(capability, input, &credential)
        .await?;
    let sanitized = serde_json::to_value(&response)?;
    let evidence = store.write_evidence(EvidenceClass::LiveRead, &sanitized)?;
    let mut envelope = ResultEnvelopeV2::success("call", sanitized).with_evidence(evidence);
    envelope.capability_id = Some(capability.id.clone());
    envelope.profile_id = Some(profile.id.clone());
    envelope.account_id = account_id;
    envelope.ok = response.success;
    envelope.verification.state = VerificationState::NotApplicable;
    envelope.verification.basis = Some(format!(
        "live Cloudflare read pinned to catalog {}",
        catalog.schema_hash
    ));
    Ok(envelope)
}

async fn execute_delegated_read(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    requested_profile: Option<&str>,
    requested_account: Option<&str>,
) -> Result<ResultEnvelopeV2> {
    let profiles = ProfilesConfig::load(store)?;
    let profile = profiles.selected(requested_profile)?;
    let account_id = resolve_account_id(store, profile, requested_account, input)?;
    let credential = fresh_credential(profile, &PlatformSecretStore).await?;
    let receipt = run_delegated_cli(capability, input, &credential).await?;
    let evidence = store.write_evidence(EvidenceClass::LiveRead, &receipt)?;
    let success = receipt
        .get("success")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut envelope = ResultEnvelopeV2::success("call", receipt).with_evidence(evidence);
    envelope.ok = success;
    envelope.capability_id = Some(capability.id.clone());
    envelope.profile_id = Some(profile.id.clone());
    envelope.account_id = account_id;
    envelope.verification.state = VerificationState::NotApplicable;
    envelope.verification.basis = Some(format!(
        "governed CLI read pinned to catalog {}",
        catalog.schema_hash
    ));
    Ok(envelope)
}

fn execute_governed_ui_read(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    requested_profile: Option<&str>,
    requested_account: Option<&str>,
) -> Result<ResultEnvelopeV2> {
    let profiles = ProfilesConfig::load(store)?;
    let profile = profiles.selected(requested_profile)?;
    let account_id = resolve_account_id(store, profile, requested_account, input)?;
    let agent = configured_agent()?;
    let target = json!({
        "capability_id": capability.id,
        "url": capability.path,
        "selectors": input.selectors,
        "query": input.query,
        "catalog_hash": catalog.schema_hash,
    });
    let action = build_ui_action(
        agent,
        None,
        account_id.as_deref(),
        target,
        &format!(
            "Observe only: {}. Use the authenticated Cloudflare dashboard only after confirming API and CLI coverage cannot answer it. Capture redacted before evidence and do not mutate state.",
            capability.title
        ),
        false,
    )?;
    let evidence =
        store.write_evidence(EvidenceClass::AgentAction, &serde_json::to_value(&action)?)?;
    let mut envelope = ResultEnvelopeV2::success(
        "call",
        json!({
            "agent_action": action,
            "performed": false,
            "message": "Governed UI observation handoff created. The action is target-bound evidence, not authority or proof that the UI was inspected."
        }),
    )
    .with_evidence(evidence);
    envelope.capability_id = Some(capability.id.clone());
    envelope.profile_id = Some(profile.id.clone());
    envelope.account_id = account_id;
    envelope.verification.state = VerificationState::Pending;
    envelope.verification.basis =
        Some("awaiting hash-bound before/after UI evidence from the configured agent".to_owned());
    Ok(envelope)
}

async fn execute_delegated_plan(
    store: &StateStore,
    plan: &mut PlanV1,
    input: &CallInput,
    credential: &AuthCredential,
    secrets: &dyn SecretStore,
) -> Result<ResultEnvelopeV2> {
    let receipt = run_delegated_cli(&plan.capability, input, credential).await?;
    let success = receipt
        .get("success")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    plan.status = if success {
        PlanStatus::RectificationRequired
    } else {
        PlanStatus::Failed
    };
    let evidence = store.write_evidence(EvidenceClass::Apply, &receipt)?;
    persist_transaction_stage_with_artifact(
        store,
        plan,
        TransactionStageV1::BoundaryResponsePersisted,
        json!({
            "adapter": "delegated_cli",
            "apply_evidence_hash": evidence.content_hash,
            "success": success,
        }),
    )?;
    persist_secret_lifecycle(store, plan, success, Some(&receipt), secrets)?;
    if plan.status == PlanStatus::Failed {
        persist_transaction_stage(store, plan, TransactionStageV1::Closed)?;
    }
    let mut envelope = ResultEnvelopeV2::success("plans run", receipt).with_evidence(evidence);
    envelope.ok = success;
    envelope.performed = success;
    envelope.operation_id = Some(plan.operation_id.clone());
    envelope.capability_id = Some(plan.capability.id.clone());
    envelope.profile_id = Some(plan.profile_id.clone());
    envelope.account_id = Some(plan.account_id.clone());
    envelope.policy_decision = Some(plan.policy.clone());
    envelope.verification.state = if success {
        VerificationState::Unsupported
    } else {
        VerificationState::Failed
    };
    envelope.verification.basis = Some(if success {
        "the governed subprocess completed successfully; operation-specific live verification is still required"
            .to_owned()
    } else {
        "the governed subprocess returned a failing exit status".to_owned()
    });
    Ok(envelope)
}

fn execute_governed_ui_plan(
    store: &StateStore,
    plan: &mut PlanV1,
    input: &CallInput,
    secrets: &dyn SecretStore,
) -> Result<ResultEnvelopeV2> {
    let agent = configured_agent()?;
    let target = json!({
        "capability_id": plan.capability.id,
        "url": plan.capability.path,
        "selectors": input.selectors,
        "query": input.query,
        "body": input.body.as_ref().map(redact_json),
        "plan_hash": plan.content_hash,
    });
    let action = build_ui_action(
        agent,
        Some(&plan.operation_id),
        Some(&plan.account_id),
        target,
        &format!(
            "Execute only the exact approved Cloudflare dashboard action: {}. Bind the session to account {}, capture redacted before/after evidence, and stop on any target or content drift.",
            plan.capability.title, plan.account_id
        ),
        true,
    )?;
    let evidence =
        store.write_evidence(EvidenceClass::AgentAction, &serde_json::to_value(&action)?)?;
    plan.status = PlanStatus::RectificationRequired;
    persist_transaction_stage_with_artifact(
        store,
        plan,
        TransactionStageV1::BoundaryResponsePersisted,
        json!({
            "adapter": "governed_ui",
            "agent_action_evidence_hash": evidence.content_hash,
            "performed": false,
            "success": false,
        }),
    )?;
    persist_secret_lifecycle(store, plan, false, None, secrets)?;
    let mut envelope = ResultEnvelopeV2::success(
        "plans run",
        json!({
            "agent_action": action,
            "performed": false,
            "message": "Approved UI action handed off. cfctl does not claim the dashboard change was performed until hash-bound before/after evidence is returned."
        }),
    )
    .with_evidence(evidence);
    envelope.performed = false;
    envelope.operation_id = Some(plan.operation_id.clone());
    envelope.capability_id = Some(plan.capability.id.clone());
    envelope.profile_id = Some(plan.profile_id.clone());
    envelope.account_id = Some(plan.account_id.clone());
    envelope.policy_decision = Some(plan.policy.clone());
    envelope.verification.state = VerificationState::Pending;
    envelope.verification.basis =
        Some("awaiting hash-bound governed UI completion evidence".to_owned());
    Ok(envelope)
}

async fn run_delegated_cli(
    capability: &CapabilityV1,
    input: &CallInput,
    credential: &AuthCredential,
) -> Result<Value> {
    let mut path_parts = capability.path.split_whitespace();
    let program = path_parts
        .next()
        .ok_or_else(|| CliError::Input("delegated capability has no program".to_owned()))?;
    if !matches!(program, "wrangler" | "cloudflared") {
        return Err(CliError::Input(format!(
            "delegated program `{program}` is not governed by cfctl"
        )));
    }
    let mut command = ProcessCommand::new(program);
    command.args(path_parts);
    append_cli_input(&mut command, &input.selectors)?;
    append_cli_input(&mut command, &input.query)?;
    if input.body.is_some() {
        return Err(CliError::Input(
            "delegated CLI request bodies need a capability-specific native adapter".to_owned(),
        ));
    }
    command
        .env_clear()
        .env("PATH", env::var_os("PATH").unwrap_or_default())
        .env("HOME", env::var_os("HOME").unwrap_or_default())
        .env("NO_COLOR", "1")
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    match credential {
        AuthCredential::Bearer { token } => {
            command.env("CLOUDFLARE_API_TOKEN", token);
        }
        AuthCredential::GlobalKey { email, key } => {
            command
                .env("CLOUDFLARE_EMAIL", email)
                .env("CLOUDFLARE_API_KEY", key);
        }
    }
    let label = capability.path.clone();
    let output = tokio::time::timeout(Duration::from_secs(120), command.output())
        .await
        .map_err(|_| CliError::SubprocessTimeout(label.clone()))?
        .map_err(|source| cli_io(Path::new(program), source))?;
    let stdout = redact_subprocess_text(&String::from_utf8_lossy(&output.stdout), credential);
    let stderr = redact_subprocess_text(&String::from_utf8_lossy(&output.stderr), credential);
    Ok(json!({
        "adapter": "delegated_cli",
        "command": capability.path,
        "exit_status": output.status.code(),
        "success": output.status.success(),
        "stdout": stdout,
        "stderr": stderr,
        "credential_environment": match credential {
            AuthCredential::Bearer { .. } => ["CLOUDFLARE_API_TOKEN"].as_slice(),
            AuthCredential::GlobalKey { .. } => ["CLOUDFLARE_EMAIL", "CLOUDFLARE_API_KEY"].as_slice(),
        },
    }))
}

fn append_cli_input(command: &mut ProcessCommand, input: &Value) -> Result<()> {
    let fields = input
        .as_object()
        .ok_or_else(|| CliError::Input("CLI selectors and query must be objects".to_owned()))?;
    for (key, value) in fields {
        let rendered = value
            .as_str()
            .map_or_else(|| value.to_string(), str::to_owned);
        if matches!(key.as_str(), "argument" | "arg" | "path") {
            command.arg(rendered);
        } else {
            command
                .arg(format!("--{}", key.replace('_', "-")))
                .arg(rendered);
        }
    }
    Ok(())
}

fn redact_subprocess_text(text: &str, credential: &AuthCredential) -> String {
    let mut sanitized = text.to_owned();
    for secret in [credential.bearer_token(), credential.global_key()]
        .into_iter()
        .flatten()
    {
        sanitized = sanitized.replace(secret, "[REDACTED]");
    }
    sanitized
        .lines()
        .map(|line| {
            let lower = line.to_ascii_lowercase();
            if [
                "access_token",
                "api_token",
                "api key",
                "authorization:",
                "password=",
            ]
            .iter()
            .any(|marker| lower.contains(marker))
            {
                "[REDACTED SECRET-BEARING LINE]".to_owned()
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn delete_plan_secret(plan: &PlanV1, secrets: &dyn SecretStore) -> Result<bool> {
    let Some(reference) = plan_secret_body_ref(plan).map(str::to_owned) else {
        return Ok(false);
    };
    secrets.delete(&reference)?;
    Ok(true)
}

fn create_plan(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: cfctl_core::CapabilityV1,
    input: CallInput,
    requested_profile: Option<&str>,
    requested_account: Option<&str>,
    adapter_targets: Value,
) -> Result<ResultEnvelopeV2> {
    let profiles = ProfilesConfig::load(store)?;
    let profile = profiles.selected(requested_profile)?;
    if profile.kind == ProfileKind::GlobalKey && requested_profile.is_none() {
        return Err(CliError::Input(
            "the emergency global-key profile is never selected implicitly; pass `--profile` explicitly"
                .to_owned(),
        ));
    }
    let resolved_account = resolve_account_id(store, profile, requested_account, &input)?;
    let account_id = resolved_account
        .as_deref()
        .or_else(|| matches!(capability.account_scope.as_str(), "user" | "global").then_some("user"))
        .ok_or_else(|| {
            CliError::Input(
                "this capability needs an explicit account; pin one on the profile or pass `--account`"
                    .to_owned(),
            )
        })?;
    let impact = plan_impact(store, &capability, &input, account_id)?;
    let policy = PolicyEngine.evaluate(&capability, &impact.policy);
    if policy.disposition == PolicyDisposition::Blocked {
        return Err(CliError::Input(format!(
            "capability is blocked: {}",
            policy.reasons.join("; ")
        )));
    }
    let targets = json!({
        "selectors": input.selectors,
        "account_id": account_id,
        "adapter": adapter_targets,
    });
    let mut plan = PlanV1::draft(
        &profile.id,
        account_id,
        &catalog.schema_hash,
        capability,
        targets,
    )?;
    match profile.kind {
        ProfileKind::OAuth => "oauth",
        ProfileKind::ApiToken => "api_token",
        ProfileKind::GlobalKey => "emergency_global_key",
    }
    .clone_into(&mut plan.permission_lane);
    plan.input = serde_json::to_value(&input)?;
    plan.precondition_hashes
        .insert("catalog".to_owned(), catalog.schema_hash.clone());
    plan.precondition_hashes
        .insert("request_input".to_owned(), hash_value(&plan.input)?);
    plan.precondition_hashes
        .extend(workspace_precondition_hashes(store)?);
    plan.affected_repositories = impact.affected_repositories;
    plan.affected_resources = impact.affected_resources;
    plan.local_diffs = impact.local_diffs;
    plan.cloudflare_diffs.push(json!({
        "request_method": plan.capability.method,
        "request_path": plan.capability.path,
        "request_body": input.body,
    }));
    plan.verification_steps
        .push(plan.capability.verification.strategy.clone());
    if let Some(strategy) = &plan.capability.rollback.strategy {
        plan.compensation_steps.push(strategy.clone());
    }
    if let Some(warning) = &plan.capability.rollback.warning {
        plan.non_reversible_warnings.push(warning.clone());
    }
    plan.policy = policy.clone();
    plan.refresh_hash()?;
    store.save_plan(&plan)?;
    let evidence = store.write_evidence(EvidenceClass::Preview, &serde_json::to_value(&plan)?)?;
    let mut envelope = ResultEnvelopeV2::success(
        "call",
        json!({
            "plan": plan,
            "approval_command": format!("cfctl plans approve {} --yes", plan.operation_id),
            "run_command": format!("cfctl plans run {}", plan.operation_id),
            "message": if policy.disposition == PolicyDisposition::AutoExecute {
                "Plan created and policy-authorized for automatic execution; run the exact operation ID."
            } else {
                "Plan created. Review it, then approve the exact operation ID with y/n."
            }
        }),
    )
    .with_evidence(evidence);
    envelope.capability_id = Some(plan.capability.id.clone());
    envelope.operation_id = Some(plan.operation_id.clone());
    envelope.profile_id = Some(profile.id.clone());
    envelope.account_id = Some(account_id.to_owned());
    envelope.policy_decision = Some(policy);
    envelope.verification.state = VerificationState::Pending;
    Ok(envelope)
}

struct PlannedImpact {
    policy: ImpactContext,
    affected_repositories: Vec<String>,
    affected_resources: Vec<String>,
    local_diffs: Vec<Value>,
}

fn plan_impact(
    store: &StateStore,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
) -> Result<PlannedImpact> {
    let selector_map = input.selectors.as_object();
    let query_map = input.query.as_object();
    let missing_required = capability.selectors.iter().any(|selector| {
        if !selector.required || (selector.name == "account_id" && !account_id.is_empty()) {
            return false;
        }
        let values = if selector.location == "query" {
            query_map
        } else {
            selector_map
        };
        values.and_then(|map| map.get(&selector.name)).is_none()
    });
    let graph = discover_registered(store)?;
    let mut affected_resources = Vec::new();
    if let Some(selectors) = selector_map {
        for (key, value) in selectors {
            if let Some(value) = value.as_str() {
                affected_resources.push(format!("{key}:{value}"));
            }
        }
    }
    let workspace_resource_keys = workspace_resource_keys(input);
    affected_resources.extend(workspace_resource_keys.iter().cloned());
    affected_resources.sort();
    affected_resources.dedup();
    let workspace_impact = graph.impact_for(&workspace_resource_keys);
    let local_diffs = workspace_impact
        .local_diffs
        .iter()
        .map(serde_json::to_value)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let policy = ImpactContext {
        affected_repositories: workspace_impact.affected_repositories.len(),
        affected_resources: affected_resources.len(),
        dependent_configurations: workspace_impact.local_diffs.len(),
        has_unmanaged_dependencies: workspace_impact.has_unmanaged_dependencies,
        has_dirty_overlap: workspace_impact.has_dirty_overlap,
        selector_ambiguous: missing_required,
    };
    Ok(PlannedImpact {
        policy,
        affected_repositories: workspace_impact.affected_repositories,
        affected_resources,
        local_diffs,
    })
}

fn workspace_resource_keys(input: &CallInput) -> Vec<String> {
    let mut resources = Vec::new();
    collect_workspace_resource_keys(&input.selectors, None, &mut resources);
    collect_workspace_resource_keys(&input.query, None, &mut resources);
    if let Some(body) = &input.body {
        collect_workspace_resource_keys(body, None, &mut resources);
    }
    resources.sort();
    resources.dedup();
    resources
}

fn collect_workspace_resource_keys(
    value: &Value,
    field: Option<&str>,
    resources: &mut Vec<String>,
) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                collect_workspace_resource_keys(value, Some(key), resources);
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_workspace_resource_keys(value, field, resources);
            }
        }
        Value::String(value) => {
            let field = field.unwrap_or_default().to_ascii_lowercase();
            let resource = if field.contains("hostname")
                || field == "pattern"
                || (field == "name" && value.contains('.'))
            {
                hostname_from_resource_value(value).map(|hostname| format!("hostname:{hostname}"))
            } else if field == "zone_name" {
                Some(format!("zone:{value}"))
            } else if matches!(field.as_str(), "script_name" | "worker" | "worker_name") {
                Some(format!("worker:{value}"))
            } else if matches!(field.as_str(), "bucket_name" | "r2_bucket") {
                Some(format!("r2_bucket:{value}"))
            } else if matches!(field.as_str(), "database_id" | "database_name") {
                Some(format!("d1_database:{value}"))
            } else if matches!(field.as_str(), "namespace_id" | "kv_namespace_id") {
                Some(format!("kv_namespace:{value}"))
            } else if matches!(field.as_str(), "queue" | "queue_name") {
                Some(format!("queue:{value}"))
            } else if matches!(field.as_str(), "service" | "service_name") {
                Some(format!("service:{value}"))
            } else {
                None
            };
            if let Some(resource) = resource {
                resources.push(resource);
            }
        }
        _ => {}
    }
}

fn hostname_from_resource_value(value: &str) -> Option<String> {
    let without_scheme = value
        .split_once("://")
        .map_or(value, |(_, remainder)| remainder);
    let hostname = without_scheme
        .split('/')
        .next()
        .unwrap_or_default()
        .trim_start_matches("*.")
        .trim_end_matches('*')
        .trim_end_matches('.');
    (!hostname.is_empty()).then(|| hostname.to_owned())
}

async fn plans_command(store: &StateStore, command: PlansCommand) -> Result<ResultEnvelopeV2> {
    match command {
        PlansCommand::Show(selector) | PlansCommand::Status(selector) => {
            show_plan(store, &selector)
        }
        PlansCommand::Approve(arguments) => approve_plan(store, &arguments),
        PlansCommand::Run(selector) => run_plan(store, &selector).await,
        PlansCommand::Resume(selector) => resume_plan(store, &selector).await,
        PlansCommand::Rectify(selector) => rectify_plan(store, &selector).await,
    }
}

fn load_validated_plan(store: &StateStore, operation_id: &str) -> Result<PlanV1> {
    let plan = store.load_plan(operation_id)?;
    plan.validate_transaction_journal()?;
    Ok(plan)
}

fn persist_transaction_stage(
    store: &StateStore,
    plan: &mut PlanV1,
    stage: TransactionStageV1,
) -> Result<()> {
    plan.record_transaction_stage(stage)?;
    store.save_plan(plan)?;
    Ok(())
}

fn persist_transaction_stage_with_artifact(
    store: &StateStore,
    plan: &mut PlanV1,
    stage: TransactionStageV1,
    artifact: Value,
) -> Result<()> {
    plan.record_transaction_stage_with_artifact(stage, artifact)?;
    store.save_plan(plan)?;
    Ok(())
}

fn show_plan(store: &StateStore, selector: &PlanSelector) -> Result<ResultEnvelopeV2> {
    let plan = load_validated_plan(store, &selector.operation_id)?;
    let mut envelope = ResultEnvelopeV2::success("plans show", serde_json::to_value(&plan)?);
    envelope.operation_id = Some(plan.operation_id);
    envelope.capability_id = Some(plan.capability.id);
    envelope.policy_decision = Some(plan.policy);
    envelope.verification.state = verification_for_status(plan.status);
    Ok(envelope)
}

fn approve_plan(store: &StateStore, arguments: &PlanApproveArgs) -> Result<ResultEnvelopeV2> {
    let _lock = store.lock_plan(&arguments.operation_id)?;
    let mut plan = load_validated_plan(store, &arguments.operation_id)?;
    let max_cost = arguments.max_cost.as_deref().map(parse_money).transpose()?;
    plan.approve(arguments.yes, max_cost)?;
    store.save_plan(&plan)?;
    let evidence = store.write_evidence(EvidenceClass::Preview, &serde_json::to_value(&plan)?)?;
    let mut envelope = ResultEnvelopeV2::success(
        "plans approve",
        json!({
            "operation_id": plan.operation_id,
            "content_hash": plan.content_hash,
            "expires_at": plan.expires_at,
            "run_command": format!("cfctl plans run {}", plan.operation_id),
            "message": "The exact hash-bound plan is approved."
        }),
    )
    .with_evidence(evidence);
    envelope.operation_id = Some(plan.operation_id);
    envelope.capability_id = Some(plan.capability.id);
    envelope.policy_decision = Some(plan.policy);
    Ok(envelope)
}

async fn run_plan(store: &StateStore, selector: &PlanSelector) -> Result<ResultEnvelopeV2> {
    let _lock = store.lock_plan(&selector.operation_id)?;
    let catalog = ensure_catalog(store).await?;
    let mut plan = load_validated_plan(store, &selector.operation_id)?;
    if plan.catalog_hash != catalog.schema_hash {
        return Err(CliError::Input(format!(
            "catalog drift invalidated the plan: planned {}, current {}",
            plan.catalog_hash, catalog.schema_hash
        )));
    }
    validate_plan_preconditions(store, &plan)?;
    if plan.capability.adapter_status == AdapterStatus::Blocked {
        return Err(CliError::Input(
            plan.capability.blocked_reason.clone().unwrap_or_else(|| {
                "the approved capability no longer has an executable adapter".to_owned()
            }),
        ));
    }
    preflight_secret_sink(&plan)?;
    let profiles = ProfilesConfig::load(store)?;
    let profile = profiles.selected(Some(&plan.profile_id))?;
    let credential = fresh_credential(profile, &PlatformSecretStore).await?;
    let secrets = PlatformSecretStore;
    let execution_input = resolved_plan_input(&plan, &secrets)?;
    plan.mark_consumed()?;
    store.save_plan(&plan)?;
    persist_transaction_stage(
        store,
        &mut plan,
        TransactionStageV1::BoundaryAttemptPersisted,
    )?;
    if plan.capability.adapter_status == AdapterStatus::DelegatedCli {
        let result =
            execute_delegated_plan(store, &mut plan, &execution_input, &credential, &secrets).await;
        if result.is_err() && plan.transaction_stage == TransactionStageV1::BoundaryAttemptPersisted
        {
            plan.status = PlanStatus::RectificationRequired;
            persist_transaction_stage_with_artifact(
                store,
                &mut plan,
                TransactionStageV1::BoundaryResponsePersisted,
                boundary_failure_artifact("delegated_cli", "no_receipt"),
            )?;
            persist_secret_lifecycle(store, &mut plan, false, None, &secrets)?;
        }
        return result;
    }
    if plan.capability.adapter_status == AdapterStatus::GovernedUi {
        let result = execute_governed_ui_plan(store, &mut plan, &execution_input, &secrets);
        if result.is_err() && plan.transaction_stage == TransactionStageV1::BoundaryAttemptPersisted
        {
            plan.status = PlanStatus::RectificationRequired;
            persist_transaction_stage_with_artifact(
                store,
                &mut plan,
                TransactionStageV1::BoundaryResponsePersisted,
                boundary_failure_artifact("governed_ui", "handoff_failed"),
            )?;
            persist_secret_lifecycle(store, &mut plan, false, None, &secrets)?;
        }
        return result;
    }
    execute_api_plan(
        store,
        &catalog.schema_hash,
        &mut plan,
        &execution_input,
        &credential,
        &secrets,
    )
    .await
}

async fn execute_api_plan(
    store: &StateStore,
    catalog_hash: &str,
    plan: &mut PlanV1,
    execution_input: &CallInput,
    credential: &AuthCredential,
    secrets: &dyn SecretStore,
) -> Result<ResultEnvelopeV2> {
    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let response_result = executor
        .execute_consumed_plan_with_input(plan, catalog_hash, credential, execution_input)
        .await;
    let response = match response_result {
        Ok(response) => response,
        Err(error) => {
            plan.status = PlanStatus::RectificationRequired;
            persist_transaction_stage_with_artifact(
                store,
                plan,
                TransactionStageV1::BoundaryResponsePersisted,
                boundary_failure_artifact("dynamic_api", "transport_error"),
            )?;
            persist_secret_lifecycle(store, plan, false, None, secrets)?;
            return Err(error.into());
        }
    };
    let mut response_value = serde_json::to_value(&response)?;
    if is_secret_output_plan(plan) {
        response_value = redact_secret_result(&response_value);
    }
    let apply_evidence = store.write_evidence(EvidenceClass::Apply, &response_value)?;
    persist_transaction_stage_with_artifact(
        store,
        plan,
        TransactionStageV1::BoundaryResponsePersisted,
        boundary_response_artifact(&response, &apply_evidence),
    )?;
    persist_secret_lifecycle(
        store,
        plan,
        response.success,
        Some(&response.result),
        secrets,
    )?;
    let performed = response.success;
    let verification = verify_api_plan(store, &executor, plan, &response, credential).await?;
    if matches!(plan.status, PlanStatus::Verified | PlanStatus::Failed) {
        persist_transaction_stage(store, plan, TransactionStageV1::Closed)?;
    } else {
        store.save_plan(plan)?;
    }
    let mut envelope =
        ResultEnvelopeV2::success("plans run", response_value).with_evidence(apply_evidence);
    if let Some(evidence) = verification.evidence {
        envelope.evidence.push(evidence);
    }
    envelope.ok = response.success && plan.status == PlanStatus::Verified;
    envelope.performed = performed;
    envelope.operation_id = Some(plan.operation_id.clone());
    envelope.capability_id = Some(plan.capability.id.clone());
    envelope.profile_id = Some(plan.profile_id.clone());
    envelope.account_id = Some(plan.account_id.clone());
    envelope.policy_decision = Some(plan.policy.clone());
    envelope.verification.state = verification.state;
    envelope.verification.basis = Some(verification.basis);
    envelope.error = verification.error;
    Ok(envelope)
}

struct ApiVerificationOutcome {
    state: VerificationState,
    basis: String,
    evidence: Option<EvidenceV1>,
    error: Option<ErrorV1>,
}

fn boundary_response_artifact(
    response: &CloudflareResponseV1,
    apply_evidence: &EvidenceV1,
) -> Value {
    json!({
        "apply_evidence_hash": apply_evidence.content_hash,
        "http_status": response.status,
        "success": response.success,
        "resource_id": response.result.get("id").and_then(Value::as_str),
        "resource_status": response.result.get("status").and_then(Value::as_str),
        "etag": response.etag,
        "cf_ray": response.cf_ray,
    })
}

fn boundary_failure_artifact(adapter: &str, outcome: &str) -> Value {
    json!({
        "adapter": adapter,
        "outcome": outcome,
        "receipt_available": false,
        "success": false,
    })
}

fn secret_sink_artifact(
    plan: &PlanV1,
    response_success: bool,
    path: Option<&Path>,
    input_cleanup_required: bool,
    input_cleanup_completed: bool,
    failure: Option<&str>,
) -> Value {
    let output_required = response_success && is_secret_output_plan(plan);
    let output_completed = !output_required || path.is_some();
    json!({
        "completed": input_cleanup_completed && output_completed && failure.is_none(),
        "failure": failure,
        "input_cleanup": {
            "required": input_cleanup_required,
            "completed": input_cleanup_completed,
        },
        "output_sink": {
            "required": output_required,
            "completed": output_completed,
            "create_new": output_required,
            "unix_mode": cfg!(unix).then_some("0600"),
        },
        "path": path.map(|path| path.display().to_string()),
    })
}

fn persist_secret_lifecycle(
    store: &StateStore,
    plan: &mut PlanV1,
    response_success: bool,
    response_result: Option<&Value>,
    secrets: &dyn SecretStore,
) -> Result<Option<PathBuf>> {
    let input_cleanup_required = plan_secret_body_ref(plan).is_some();
    let input_cleanup_completed = match delete_plan_secret(plan, secrets) {
        Ok(deleted) => !input_cleanup_required || deleted,
        Err(error) => {
            plan.status = PlanStatus::RectificationRequired;
            persist_transaction_stage_with_artifact(
                store,
                plan,
                TransactionStageV1::SecretSinkPersisted,
                secret_sink_artifact(
                    plan,
                    response_success,
                    None,
                    input_cleanup_required,
                    false,
                    Some("input_cleanup_failed"),
                ),
            )?;
            return Err(error);
        }
    };
    let output_required = response_success && is_secret_output_plan(plan);
    let sink_path = if output_required {
        let Some(result) = response_result else {
            plan.status = PlanStatus::RectificationRequired;
            persist_transaction_stage_with_artifact(
                store,
                plan,
                TransactionStageV1::SecretSinkPersisted,
                secret_sink_artifact(
                    plan,
                    response_success,
                    None,
                    input_cleanup_required,
                    input_cleanup_completed,
                    Some("output_missing"),
                ),
            )?;
            return Err(CliError::Input(
                "the adapter reported success without returning the required sink-only value; do not replay the mutation"
                    .to_owned(),
            ));
        };
        match sink_secret_result(plan, result) {
            Ok(path) => Some(path),
            Err(error) => {
                plan.status = PlanStatus::RectificationRequired;
                persist_transaction_stage_with_artifact(
                    store,
                    plan,
                    TransactionStageV1::SecretSinkPersisted,
                    secret_sink_artifact(
                        plan,
                        response_success,
                        None,
                        input_cleanup_required,
                        input_cleanup_completed,
                        Some("output_sink_failed"),
                    ),
                )?;
                return Err(error);
            }
        }
    } else {
        None
    };
    persist_transaction_stage_with_artifact(
        store,
        plan,
        TransactionStageV1::SecretSinkPersisted,
        secret_sink_artifact(
            plan,
            response_success,
            sink_path.as_deref(),
            input_cleanup_required,
            input_cleanup_completed,
            None,
        ),
    )?;
    Ok(sink_path)
}

fn verification_response_artifact(outcome: &ApiVerificationOutcome) -> Result<Value> {
    Ok(json!({
        "state": outcome.state.as_str(),
        "basis_hash": hash_value(&json!(outcome.basis))?,
        "evidence_hash": outcome.evidence.as_ref().map(|evidence| evidence.content_hash.as_str()),
    }))
}

async fn verify_api_plan(
    store: &StateStore,
    executor: &Executor,
    plan: &mut PlanV1,
    response: &CloudflareResponseV1,
    credential: &AuthCredential,
) -> Result<ApiVerificationOutcome> {
    if !response.success {
        plan.status = PlanStatus::Failed;
        return Ok(ApiVerificationOutcome {
            state: VerificationState::NotApplicable,
            basis: "Cloudflare rejected the mutation before verification".to_owned(),
            evidence: None,
            error: None,
        });
    }
    persist_transaction_stage(
        store,
        plan,
        TransactionStageV1::VerificationAttemptPersisted,
    )?;
    if !plan.capability.verification.required {
        plan.status = PlanStatus::Verified;
        let outcome = ApiVerificationOutcome {
            state: VerificationState::Passed,
            basis: "operation declares no post-change verifier".to_owned(),
            evidence: None,
            error: None,
        };
        persist_transaction_stage_with_artifact(
            store,
            plan,
            TransactionStageV1::VerificationResponsePersisted,
            verification_response_artifact(&outcome)?,
        )?;
        return Ok(outcome);
    }
    let outcome = match executor.verify_plan(plan, response, credential).await {
        Ok(verification) => verification_outcome(store, plan, verification)?,
        Err(error) => verification_error_outcome(store, plan, &error)?,
    };
    persist_transaction_stage_with_artifact(
        store,
        plan,
        TransactionStageV1::VerificationResponsePersisted,
        verification_response_artifact(&outcome)?,
    )?;
    Ok(outcome)
}

fn verification_outcome(
    store: &StateStore,
    plan: &mut PlanV1,
    verification: OperationVerificationV1,
) -> Result<ApiVerificationOutcome> {
    let state = if verification.passed {
        VerificationState::Passed
    } else {
        VerificationState::Failed
    };
    plan.status = if verification.passed {
        PlanStatus::Verified
    } else {
        PlanStatus::RectificationRequired
    };
    let evidence = Some(store.write_evidence(
        EvidenceClass::PostChangeVerification,
        &serde_json::to_value(&verification)?,
    )?);
    let error = (!verification.passed).then(|| ErrorV1 {
        code: "CFCTL_VERIFICATION_FAILED".to_owned(),
        message: verification.basis.clone(),
        next_step: Some(format!(
            "Inspect live state with `cfctl plans rectify {}` before any compensation.",
            plan.operation_id
        )),
    });
    Ok(ApiVerificationOutcome {
        state,
        basis: verification.basis,
        evidence,
        error,
    })
}

fn verification_error_outcome(
    store: &StateStore,
    plan: &mut PlanV1,
    verification_error: &CloudflareError,
) -> Result<ApiVerificationOutcome> {
    let basis = format!("operation-specific verifier failed: {verification_error}");
    plan.status = PlanStatus::RectificationRequired;
    let evidence = Some(store.write_evidence(
        EvidenceClass::PostChangeVerification,
        &json!({
            "strategy": plan.capability.verification.strategy,
            "passed": false,
            "error": verification_error.to_string(),
        }),
    )?);
    Ok(ApiVerificationOutcome {
        state: VerificationState::Failed,
        basis: basis.clone(),
        evidence,
        error: Some(ErrorV1 {
            code: "CFCTL_VERIFICATION_ERROR".to_owned(),
            message: basis,
            next_step: Some(format!(
                "Do not replay the mutation; run `cfctl plans rectify {}`.",
                plan.operation_id
            )),
        }),
    })
}

async fn resume_plan(store: &StateStore, selector: &PlanSelector) -> Result<ResultEnvelopeV2> {
    let plan = load_validated_plan(store, &selector.operation_id)?;
    match plan.status {
        PlanStatus::Draft | PlanStatus::Approved => run_plan(store, selector).await,
        PlanStatus::Consumed | PlanStatus::Running => Err(CliError::Input(
            "the operation may have crossed the Cloudflare boundary; replay is blocked until rectification proves current state"
                .to_owned(),
        )),
        PlanStatus::Verified | PlanStatus::Rectified => show_plan(store, selector),
        _ => Err(CliError::Input(format!(
            "operation is {:?}; use `cfctl plans rectify {}`",
            plan.status, plan.operation_id
        ))),
    }
}

struct CompensationRequest {
    capability_id: String,
    input: CallInput,
    requested_account: Option<String>,
}

fn token_compensation_request(plan: &PlanV1) -> Result<Option<CompensationRequest>> {
    if !matches!(
        plan.status,
        PlanStatus::Consumed | PlanStatus::Running | PlanStatus::RectificationRequired
    ) || !plan.capability.rollback.supported
    {
        return Ok(None);
    }
    let capability_id = match plan.capability.id.as_str() {
        "account-api-tokens-create-token" => "account-api-tokens-delete-token",
        "user-api-tokens-create-token" => "user-api-tokens-delete-token",
        _ => return Ok(None),
    };
    let Some(artifact) = plan.transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
    else {
        return Ok(None);
    };
    if artifact.get("success").and_then(Value::as_bool) != Some(true) {
        return Ok(None);
    }
    let resource_id = artifact
        .get("resource_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "the token creation response is recorded, but its hash-bound receipt has no resource id; inspect live token state before compensating"
                    .to_owned(),
            )
        })?;
    let selectors = if plan.capability.id == "account-api-tokens-create-token" {
        json!({"account_id": plan.account_id, "token_id": resource_id})
    } else {
        json!({"token_id": resource_id})
    };
    Ok(Some(CompensationRequest {
        capability_id: capability_id.to_owned(),
        input: CallInput {
            selectors,
            query: json!({}),
            body: None,
            ..CallInput::default()
        },
        requested_account: Some(plan.account_id.clone()),
    }))
}

async fn rectify_plan(store: &StateStore, selector: &PlanSelector) -> Result<ResultEnvelopeV2> {
    let plan = load_validated_plan(store, &selector.operation_id)?;
    if let Some(request) = token_compensation_request(&plan)? {
        let catalog = ensure_catalog(store).await?;
        let capability = catalog
            .get(&request.capability_id)
            .cloned()
            .ok_or_else(|| capability_missing(&request.capability_id))?;
        let source_receipt_hash = plan
            .transaction_journal
            .iter()
            .find(|checkpoint| checkpoint.stage == TransactionStageV1::BoundaryResponsePersisted)
            .and_then(|checkpoint| checkpoint.artifact_hash.as_deref());
        let mut envelope = create_plan(
            store,
            &catalog,
            capability,
            request.input,
            Some(&plan.profile_id),
            request.requested_account.as_deref(),
            json!({
                "compensates_operation_id": plan.operation_id,
                "compensates_capability_id": plan.capability.id,
                "source_receipt_hash": source_receipt_hash,
            }),
        )?;
        "plans rectify".clone_into(&mut envelope.command);
        if let Some(result) = envelope.result.as_object_mut() {
            result.insert(
                "compensates_operation_id".to_owned(),
                Value::String(plan.operation_id.clone()),
            );
            result.insert(
                "message".to_owned(),
                Value::String(
                    "A separate hash-bound compensation plan was created from the verified response receipt. It has not run; review and explicitly approve its operation ID."
                        .to_owned(),
                ),
            );
        }
        return Ok(envelope);
    }
    Ok(ResultEnvelopeV2::success(
        "plans rectify",
        json!({
            "operation_id": plan.operation_id,
            "status": plan.status,
            "compensation_steps": plan.compensation_steps,
            "verification_steps": plan.verification_steps,
            "non_reversible_warnings": plan.non_reversible_warnings,
            "message": "No safe automatic compensation plan can be derived from the hash-bound receipts for this capability. Inspect live state with the catalog, then create a new hash-bound plan."
        }),
    ))
}

async fn keys_command(store: &StateStore, command: KeysCommand) -> Result<ResultEnvelopeV2> {
    match command {
        KeysCommand::Permissions(arguments) => key_permissions(store, &arguments).await,
        KeysCommand::Mint(arguments) => key_mint(store, &arguments).await,
        KeysCommand::Rotate(arguments) => key_rotate(store, &arguments).await,
        KeysCommand::Revoke(arguments) => key_revoke(store, &arguments).await,
    }
}

async fn key_permissions(
    store: &StateStore,
    arguments: &KeyPermissionArgs,
) -> Result<ResultEnvelopeV2> {
    let capability_id = if arguments.account.is_some() {
        "account-api-tokens-list-permission-groups"
    } else {
        "permission-groups-list-permission-groups"
    };
    let mut selectors = Vec::new();
    if let Some(account) = &arguments.account {
        selectors.push(("account_id".to_owned(), account.clone()));
    }
    call_command(
        store,
        CallArgs {
            capability_id: capability_id.to_owned(),
            selectors,
            query: Vec::new(),
            body_json: None,
            body_stdin: false,
            profile: None,
            account: arguments.account.clone(),
            if_match: None,
            if_none_match: None,
            value_out: None,
        },
    )
    .await
}

async fn key_mint(store: &StateStore, arguments: &KeyMutationArgs) -> Result<ResultEnvelopeV2> {
    let account = arguments.account.as_deref().ok_or_else(|| {
        CliError::Input("token minting requires `--account` for explicit resource scope".to_owned())
    })?;
    let value_out = arguments.value_out.as_ref().ok_or_else(|| {
        CliError::Input("token minting requires the sink-only `--value-out <path>`".to_owned())
    })?;
    if arguments.permissions.is_empty() {
        return Err(CliError::Input(
            "at least one permission group ID is required; use `cfctl keys permissions --account <id>`"
                .to_owned(),
        ));
    }
    let mut body = json!({
        "name": arguments.name,
        "policies": [{
            "effect": "allow",
            "permission_groups": arguments.permissions.iter().map(|id| json!({"id": id})).collect::<Vec<_>>(),
            "resources": {format!("com.cloudflare.api.account.{account}"): "*"}
        }]
    });
    if let Some(hours) = arguments.ttl_hours {
        body["expires_on"] =
            json!((Utc::now() + ChronoDuration::hours(i64::from(hours))).to_rfc3339());
    }
    let catalog = ensure_catalog(store).await?;
    let capability = catalog
        .get("account-api-tokens-create-token")
        .cloned()
        .ok_or_else(|| capability_missing("account-api-tokens-create-token"))?;
    create_plan(
        store,
        &catalog,
        capability,
        CallInput {
            selectors: json!({"account_id": account}),
            query: json!({}),
            body: Some(body),
            ..CallInput::default()
        },
        None,
        Some(account),
        json!({"value_out": value_out}),
    )
}

async fn key_rotate(store: &StateStore, arguments: &KeyRotateArgs) -> Result<ResultEnvelopeV2> {
    let catalog = ensure_catalog(store).await?;
    let capability = catalog
        .get("account-api-tokens-roll-token")
        .cloned()
        .ok_or_else(|| capability_missing("account-api-tokens-roll-token"))?;
    create_plan(
        store,
        &catalog,
        capability,
        CallInput {
            selectors: json!({"account_id": arguments.account, "token_id": arguments.id}),
            query: json!({}),
            body: Some(json!({})),
            ..CallInput::default()
        },
        None,
        Some(&arguments.account),
        json!({"value_out": arguments.value_out}),
    )
}

async fn key_revoke(store: &StateStore, arguments: &KeyRevokeArgs) -> Result<ResultEnvelopeV2> {
    let account = arguments.account.as_deref().ok_or_else(|| {
        CliError::Input("token revocation requires `--account` for explicit ownership".to_owned())
    })?;
    let catalog = ensure_catalog(store).await?;
    let capability = catalog
        .get("account-api-tokens-delete-token")
        .cloned()
        .ok_or_else(|| capability_missing("account-api-tokens-delete-token"))?;
    create_plan(
        store,
        &catalog,
        capability,
        CallInput {
            selectors: json!({"account_id": account, "token_id": arguments.id}),
            query: json!({}),
            body: None,
            ..CallInput::default()
        },
        None,
        Some(account),
        Value::Null,
    )
}

fn workspace_command(store: &StateStore, command: WorkspaceCommand) -> Result<ResultEnvelopeV2> {
    match command {
        WorkspaceCommand::Add(arguments) => {
            store.register_workspace_root(&arguments.path)?;
            if let Some(account) = arguments.account {
                let path = store.paths().config_dir.join("workspace-accounts.json");
                let mut pins: BTreeMap<PathBuf, String> = if path.is_file() {
                    store.read_json(&path)?
                } else {
                    BTreeMap::new()
                };
                pins.insert(
                    arguments
                        .path
                        .canonicalize()
                        .map_err(|source| cli_io(&arguments.path, source))?,
                    account,
                );
                store.write_json(&path, &pins)?;
            }
            Ok(ResultEnvelopeV2::success(
                "workspace add",
                json!({"path": arguments.path, "message": "Workspace root registered; discovery remains bounded to registered roots."}),
            ))
        }
        WorkspaceCommand::Discover => {
            let graph = discover_registered(store)?;
            store.write_json(&workspace_graph_file(store), &graph)?;
            Ok(ResultEnvelopeV2::success(
                "workspace discover",
                serde_json::to_value(graph)?,
            ))
        }
        WorkspaceCommand::Graph => {
            let graph = discover_registered(store)?;
            Ok(ResultEnvelopeV2::success(
                "workspace graph",
                serde_json::to_value(graph)?,
            ))
        }
        WorkspaceCommand::Audit => {
            let graph = discover_registered(store)?;
            let mut repositories = Vec::new();
            for repository in &graph.repositories {
                let output = std::process::Command::new("git")
                    .args([
                        "-C",
                        &repository.path.display().to_string(),
                        "status",
                        "--porcelain",
                    ])
                    .output()
                    .map_err(|source| cli_io(&repository.path, source))?;
                repositories.push(json!({
                    "name": repository.name,
                    "path": repository.path,
                    "dirty": !output.stdout.is_empty(),
                    "cloudflare_configs": repository.cloudflare_configs,
                }));
            }
            Ok(ResultEnvelopeV2::success(
                "workspace audit",
                json!({"repositories": repositories, "resource_count": graph.resources.len()}),
            ))
        }
    }
}

fn agents_command(store: &StateStore, command: AgentsCommand) -> Result<ResultEnvelopeV2> {
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
            let receipts = AgentKind::all()
                .into_iter()
                .filter(|agent| {
                    inspect_agent(&home, *agent, which::which(agent.program()).is_ok())
                        .skill_present
                })
                .map(|agent| install_agent_skill(&home, agent, InstallMode::Sync))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(ResultEnvelopeV2::success(
                "agents sync",
                json!({"receipts": receipts, "message": "Existing managed integrations synchronized."}),
            ))
        }
        AgentsCommand::Doctor => {
            let status: Vec<_> = AgentKind::all()
                .into_iter()
                .map(|agent| inspect_agent(&home, agent, which::which(agent.program()).is_ok()))
                .collect();
            let configured = configured_agent()?;
            Ok(ResultEnvelopeV2::success(
                "agents doctor",
                json!({
                    "binary_version": env!("CARGO_PKG_VERSION"),
                    "binary_on_path": which::which("cfctl").ok(),
                    "configured_default_agent": configured,
                    "platform": env::consts::OS,
                    "platform_secret_store": if cfg!(target_os = "macos") { "keychain" } else if cfg!(target_os = "linux") { "secret_service" } else { "unsupported" },
                    "instruction_drift": status.iter().filter(|agent| agent.skill_present && !agent.skill_current).count(),
                    "agents": status,
                }),
            ))
        }
    }
}

async fn docs_command(store: &StateStore, command: DocsCommand) -> Result<ResultEnvelopeV2> {
    let _catalog = ensure_catalog(store).await?;
    let mut feeds: OfficialTextFeedsV1 = store.read_json(&docs_file(store))?;
    if feeds.product_indexes.is_empty() {
        feeds = fetch_official_text_feeds(&http_client()?).await?;
        store.write_json(&docs_file(store), &feeds)?;
    }
    match command {
        DocsCommand::Search(SearchArgs { query, limit }) => {
            let matches = search_docs(&http_client()?, &feeds, &query, limit.min(100)).await;
            Ok(ResultEnvelopeV2::success(
                "docs search",
                json!({
                    "query": query,
                    "matches": matches,
                    "fetched_at": feeds.fetched_at,
                    "result_limit": limit.min(100),
                    "limit_capped": limit > 100,
                }),
            ))
        }
        DocsCommand::Changes => Ok(ResultEnvelopeV2::success(
            "docs changes",
            json!({"source": feeds.changelog_url, "fetched_at": feeds.fetched_at, "text": feeds.changelog}),
        )),
        DocsCommand::Coverage => {
            let linked_pages = feeds
                .product_indexes
                .values()
                .flat_map(|index| index.lines())
                .filter_map(cfctl_catalog::markdown_link)
                .filter(|url| url.ends_with("/index.md"))
                .count();
            Ok(ResultEnvelopeV2::success(
                "docs coverage",
                json!({
                    "official_index": feeds.docs_index_url,
                    "official_changelog": feeds.changelog_url,
                    "linked_pages": linked_pages,
                    "product_indexes": feeds.product_indexes.len(),
                    "unread_product_indexes": feeds.unread_product_indexes,
                    "fetched_at": feeds.fetched_at,
                    "note": "Coverage indexes official product feeds; matching page bodies are fetched from Cloudflare on demand and returned with per-page fetch status."
                }),
            ))
        }
    }
}

async fn search_docs(
    client: &reqwest::Client,
    feeds: &OfficialTextFeedsV1,
    query: &str,
    limit: usize,
) -> Vec<Value> {
    let terms: Vec<String> = query
        .split_whitespace()
        .map(str::to_ascii_lowercase)
        .collect();
    let candidates: Vec<String> = feeds
        .docs_index
        .lines()
        .chain(
            feeds
                .product_indexes
                .values()
                .flat_map(|index| index.lines()),
        )
        .chain(feeds.changelog.lines())
        .filter(|line| {
            let line = line.to_ascii_lowercase();
            terms.iter().all(|term| line.contains(term))
        })
        .take(limit)
        .map(str::to_owned)
        .collect();
    let mut matches = stream::iter(candidates.into_iter().enumerate())
        .map(|(position, index_entry)| {
            let client = client.clone();
            let terms = terms.clone();
            async move {
                let Some(url) = cfctl_catalog::markdown_link(&index_entry).map(str::to_owned) else {
                    return (
                        position,
                        json!({"index_entry": index_entry, "body_status": "not_a_page_link"}),
                    );
                };
                let response = client
                    .get(&url)
                    .header(reqwest::header::ACCEPT, "text/markdown")
                    .send()
                    .await
                    .and_then(reqwest::Response::error_for_status);
                match response {
                    Ok(response) => match response.text().await {
                        Ok(body) => (
                            position,
                            json!({
                                "index_entry": index_entry,
                                "url": url,
                                "body_status": "fetched",
                                "excerpt": docs_excerpt(&body, &terms),
                            }),
                        ),
                        Err(error) => (
                            position,
                            json!({"index_entry": index_entry, "url": url, "body_status": "unread", "reason": error.to_string()}),
                        ),
                    },
                    Err(error) => (
                        position,
                        json!({"index_entry": index_entry, "url": url, "body_status": "unread", "reason": error.to_string()}),
                    ),
                }
            }
        })
        .buffer_unordered(8)
        .collect::<Vec<_>>()
        .await;
    matches.sort_by_key(|(position, _)| *position);
    matches.into_iter().map(|(_, value)| value).collect()
}

fn docs_excerpt(body: &str, terms: &[String]) -> String {
    let matching: Vec<&str> = body
        .lines()
        .filter(|line| {
            let line = line.to_ascii_lowercase();
            terms.iter().all(|term| line.contains(term))
        })
        .filter(|line| !line.trim().is_empty())
        .take(6)
        .collect();
    let lines = if matching.is_empty() {
        body.lines()
            .filter(|line| !line.trim().is_empty())
            .take(6)
            .collect()
    } else {
        matching
    };
    lines.join("\n").chars().take(2_000).collect()
}

fn doctor_command(store: &StateStore) -> Result<ResultEnvelopeV2> {
    let profiles = ProfilesConfig::load(store)?;
    let inventory_hash = oauth_scope_inventory_hash(store)?;
    let oauth_reconsent: Vec<Value> = profiles
        .profiles
        .values()
        .filter(|profile| profile.kind == ProfileKind::OAuth)
        .map(|profile| {
            let reconsent_required = inventory_hash.is_some()
                && profile.oauth_scope_inventory_hash.as_ref() != inventory_hash.as_ref();
            json!({
                "profile": profile.id,
                "granted_scope_count": profile.oauth_scopes.len(),
                "scope_inventory_hash": profile.oauth_scope_inventory_hash,
                "reconsent_required": reconsent_required,
            })
        })
        .collect();
    let catalog = if store.paths().catalog_file().is_file() {
        let catalog = CatalogSnapshot::load(&store.paths().catalog_file())?;
        json!({
            "present": true,
            "schema_hash": catalog.schema_hash,
            "capabilities": catalog.capabilities.len(),
            "stale": catalog_is_stale(store),
        })
    } else {
        json!({"present": false})
    };
    let home = home_directory()?;
    let agents: Vec<_> = AgentKind::all()
        .into_iter()
        .map(|agent| inspect_agent(&home, agent, which::which(agent.program()).is_ok()))
        .collect();
    Ok(ResultEnvelopeV2::success(
        "doctor",
        json!({
            "version": env!("CARGO_PKG_VERSION"),
            "platform": env::consts::OS,
            "config_dir": store.paths().config_dir,
            "data_dir": store.paths().data_dir,
            "cache_dir": store.paths().cache_dir,
            "catalog": catalog,
            "profile_count": profiles.profiles.len(),
            "current_profile": profiles.current_profile,
            "oauth_scope_inventory_hash": inventory_hash,
            "oauth_profiles": oauth_reconsent,
            "platform_secret_store": if cfg!(target_os = "macos") { "keychain" } else if cfg!(target_os = "linux") { "secret_service" } else { "unsupported" },
            "agents": agents,
            "public_oauth": "unconfigured until cfctl.io ownership, site publication, domain verification, and permanent promotion are explicitly completed",
        }),
    ))
}

async fn update_command(check: bool) -> Result<ResultEnvelopeV2> {
    if !check {
        return Err(CliError::Input(
            "self-update is disabled until a release has signed checksums and attestations; use `cfctl update --check`"
                .to_owned(),
        ));
    }
    let response = http_client()?
        .get("https://api.github.com/repos/rogu3bear/cfctl/releases/latest")
        .header(reqwest::header::USER_AGENT, "cfctl")
        .send()
        .await?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(ResultEnvelopeV2::success(
            "update",
            json!({"current": env!("CARGO_PKG_VERSION"), "published_release": null, "message": "No public GitHub release exists yet."}),
        ));
    }
    let release = response.error_for_status()?.json::<Value>().await?;
    Ok(ResultEnvelopeV2::success(
        "update",
        json!({"current": env!("CARGO_PKG_VERSION"), "latest": release.get("tag_name"), "release_url": release.get("html_url")}),
    ))
}

fn migrate_command(store: &StateStore, command: MigrateCommand) -> Result<ResultEnvelopeV2> {
    match command {
        MigrateCommand::V1 => {
            let cwd = env::current_dir().map_err(|source| cli_io(Path::new("."), source))?;
            let mut imported = Vec::new();
            let mut skipped = Vec::new();
            for source_root in ["state", "var/inventory"] {
                let root = cwd.join(source_root);
                if !root.is_dir() {
                    continue;
                }
                for entry in walkdir::WalkDir::new(&root)
                    .follow_links(false)
                    .into_iter()
                    .filter_map(std::result::Result::ok)
                    .filter(|entry| entry.file_type().is_file())
                {
                    let path = entry.path();
                    if is_secret_path(path) {
                        skipped.push(json!({"source_path": path, "reason": "secret-shaped path"}));
                        continue;
                    }
                    let content =
                        fs::read_to_string(path).map_err(|source| cli_io(path, source))?;
                    if contains_sensitive_content(&content) {
                        skipped
                            .push(json!({"source_path": path, "reason": "secret-shaped content"}));
                        continue;
                    }
                    let content_hash = hash_value(&Value::String(content.clone()))?;
                    let digest = content_hash
                        .strip_prefix("sha256:")
                        .unwrap_or(&content_hash);
                    let Ok(source_relative) = path.strip_prefix(&root) else {
                        skipped.push(
                            json!({"source_path": path, "reason": "path escaped source root"}),
                        );
                        continue;
                    };
                    let destination = store.write_import(
                        &Path::new("v1")
                            .join(digest)
                            .join(source_root)
                            .join(source_relative),
                        content.as_bytes(),
                    )?;
                    let evidence = store.write_evidence(
                        EvidenceClass::SourceConfig,
                        &json!({
                            "source_path": path,
                            "destination": destination,
                            "source_content_hash": content_hash,
                        }),
                    )?;
                    imported.push(json!({
                        "source_path": path,
                        "destination": destination,
                        "source_content_hash": content_hash,
                        "evidence": evidence,
                    }));
                }
            }
            Ok(ResultEnvelopeV2::success(
                "migrate v1",
                json!({
                    "imported": imported,
                    "skipped": skipped,
                    "credentials_imported": false,
                    "message": "V1 desired state and evidence were copied into content-addressed imports; secret-shaped files and credentials were not imported."
                }),
            ))
        }
    }
}

async fn ensure_catalog(store: &StateStore) -> Result<CatalogSnapshot> {
    if !store.paths().catalog_file().is_file() || catalog_is_stale(store) {
        let _receipt = sync_catalog(store).await?;
    }
    Ok(CatalogSnapshot::load(&store.paths().catalog_file())?)
}

async fn resolve_login_scopes(
    store: &StateStore,
    profiles: &ProfilesConfig,
    secrets: &dyn SecretStore,
    requested: &[String],
) -> Result<Vec<String>> {
    if !requested.is_empty() {
        let mut scopes = requested.to_vec();
        scopes.sort();
        scopes.dedup();
        return Ok(scopes);
    }
    let snapshot = if oauth_scope_inventory_file(store).is_file() {
        store.read_json::<Value>(&oauth_scope_inventory_file(store))?
    } else {
        let profile = profiles.selected(None).map_err(|_| {
            CliError::Input(
                "default all-scope login needs a cached authenticated `/oauth/scopes` inventory; first pass explicit --scope IDs or refresh with an active profile"
                    .to_owned(),
            )
        })?;
        let credential = fresh_credential(profile, secrets).await?;
        fetch_oauth_scope_snapshot(&credential).await?
    };
    let scopes = oauth_scope_ids(&snapshot)?;
    store.write_json(&oauth_scope_inventory_file(store), &snapshot)?;
    if scopes.is_empty() {
        return Err(CliError::Input(
            "Cloudflare returned an empty OAuth scope inventory; pass explicit --scope IDs"
                .to_owned(),
        ));
    }
    Ok(scopes)
}

async fn fresh_credential(
    profile: &ProfileMetadata,
    secrets: &dyn SecretStore,
) -> Result<AuthCredential> {
    if profile.kind != ProfileKind::OAuth {
        return Ok(secrets.load_credential(&profile.id, profile.kind)?);
    }
    let tokens = secrets.load_oauth_tokens(&profile.id)?;
    if !tokens.needs_refresh() {
        return Ok(AuthCredential::Bearer {
            token: tokens.access_token().to_owned(),
        });
    }
    let refresh_token = tokens.refresh_token().ok_or_else(|| {
        CliError::Input(format!(
            "OAuth profile `{}` expired and has no refresh token; log in again",
            profile.id
        ))
    })?;
    let client_id = profile.oauth_client_id.as_deref().ok_or_else(|| {
        CliError::Input(format!(
            "OAuth profile `{}` is missing its client ID; log in again",
            profile.id
        ))
    })?;
    let refreshed = refresh_oauth_tokens(
        &http_client()?,
        &OAuthClientConfig::cfctl_public(client_id),
        refresh_token,
    )
    .await?;
    let credential = AuthCredential::Bearer {
        token: refreshed.access_token().to_owned(),
    };
    secrets.store_oauth_tokens(&profile.id, &refreshed)?;
    Ok(credential)
}

async fn refresh_oauth_scopes_if_authenticated(store: &StateStore) -> Result<Option<Value>> {
    let profiles = ProfilesConfig::load(store)?;
    let Ok(profile) = profiles.selected(None) else {
        return Ok(None);
    };
    let credential = fresh_credential(profile, &PlatformSecretStore).await?;
    let snapshot = fetch_oauth_scope_snapshot(&credential).await?;
    store.write_json(&oauth_scope_inventory_file(store), &snapshot)?;
    Ok(Some(snapshot))
}

async fn fetch_oauth_scope_snapshot(credential: &AuthCredential) -> Result<Value> {
    let client = http_client()?;
    let request = client.get(format!("{API_BASE_URL}/oauth/scopes"));
    let request = match credential {
        AuthCredential::Bearer { token } => request.bearer_auth(token),
        AuthCredential::GlobalKey { email, key } => request
            .header("X-Auth-Email", email)
            .header("X-Auth-Key", key),
    };
    let envelope = request
        .send()
        .await?
        .error_for_status()?
        .json::<Value>()
        .await?;
    if !envelope
        .get("success")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Err(CliError::Input(format!(
            "Cloudflare rejected OAuth scope inventory: {}",
            envelope
                .get("errors")
                .cloned()
                .unwrap_or(Value::String("unknown error".to_owned()))
        )));
    }
    let scopes = envelope
        .get("result")
        .and_then(Value::as_array)
        .ok_or_else(|| CliError::Input("OAuth scope inventory result is not an array".to_owned()))?
        .clone();
    let ids = oauth_scope_ids(&json!({"scopes": scopes.clone()}))?;
    let schema_hash = hash_value(&serde_json::to_value(&ids)?)?;
    Ok(json!({
        "schema_version": 1,
        "fetched_at": Utc::now(),
        "source": "/oauth/scopes",
        "schema_hash": schema_hash,
        "scopes": scopes,
    }))
}

fn oauth_scope_ids(snapshot: &Value) -> Result<Vec<String>> {
    let mut ids: Vec<String> = snapshot
        .get("scopes")
        .and_then(Value::as_array)
        .ok_or_else(|| CliError::Input("cached OAuth scope inventory is malformed".to_owned()))?
        .iter()
        .filter_map(|scope| scope.get("id").and_then(Value::as_str))
        .map(str::to_owned)
        .collect();
    ids.sort();
    ids.dedup();
    Ok(ids)
}

fn oauth_scope_inventory_hash(store: &StateStore) -> Result<Option<String>> {
    let path = oauth_scope_inventory_file(store);
    if !path.is_file() {
        return Ok(None);
    }
    let snapshot: Value = store.read_json(&path)?;
    Ok(snapshot
        .get("schema_hash")
        .and_then(Value::as_str)
        .map(str::to_owned))
}

fn oauth_scope_inventory_file(store: &StateStore) -> PathBuf {
    store.paths().data_dir.join("auth/oauth-scopes-v1.json")
}

fn discover_registered(store: &StateStore) -> Result<WorkspaceGraph> {
    let roots: Vec<RegisteredRoot> = store
        .workspace_roots()?
        .iter()
        .map(|path| RegisteredRoot::new(path))
        .collect();
    Ok(WorkspaceGraph::discover(&roots)?)
}

fn workspace_precondition_hashes(store: &StateStore) -> Result<BTreeMap<String, String>> {
    let graph = discover_registered(store)?;
    let mut hashes = BTreeMap::new();
    hashes.insert(
        "workspace_graph".to_owned(),
        hash_value(&serde_json::to_value(&graph)?)?,
    );
    for path in graph
        .repositories
        .iter()
        .flat_map(|repository| &repository.cloudflare_configs)
    {
        let content = fs::read_to_string(path).map_err(|source| cli_io(path, source))?;
        hashes.insert(
            format!("source_config:{}", path.display()),
            hash_value(&Value::String(content))?,
        );
    }
    Ok(hashes)
}

fn validate_plan_preconditions(store: &StateStore, plan: &PlanV1) -> Result<()> {
    let current = workspace_precondition_hashes(store)?;
    for (name, expected) in &plan.precondition_hashes {
        if name == "catalog" || name == "request_input" {
            continue;
        }
        if current.get(name) != Some(expected) {
            return Err(CliError::Input(format!(
                "precondition `{name}` drifted after planning; create a new plan"
            )));
        }
    }
    Ok(())
}

fn resolve_account_id(
    store: &StateStore,
    profile: &ProfileMetadata,
    requested: Option<&str>,
    input: &CallInput,
) -> Result<Option<String>> {
    let selector = input.selectors.get("account_id").and_then(Value::as_str);
    if let (Some(argument), Some(selector)) = (requested, selector)
        && argument != selector
    {
        return Err(CliError::Input(format!(
            "account selection is ambiguous: --account `{argument}` differs from selector `{selector}`"
        )));
    }
    if let Some(explicit) = requested.or(selector) {
        return Ok(Some(explicit.to_owned()));
    }

    let pin_path = store.paths().config_dir.join("workspace-accounts.json");
    let workspace_pin = if pin_path.is_file() {
        let pins: BTreeMap<PathBuf, String> = store.read_json(&pin_path)?;
        let cwd = env::current_dir().map_err(|source| cli_io(Path::new("."), source))?;
        pins.into_iter()
            .filter(|(root, _)| cwd.starts_with(root))
            .max_by_key(|(root, _)| root.components().count())
            .map(|(_, account)| account)
    } else {
        None
    };
    if let (Some(workspace), Some(profile_account)) =
        (workspace_pin.as_deref(), profile.account_id.as_deref())
        && workspace != profile_account
    {
        return Err(CliError::Input(format!(
            "account selection is ambiguous: workspace pins `{workspace}` but profile `{}` pins `{profile_account}`; pass --account explicitly",
            profile.id
        )));
    }
    Ok(workspace_pin.or_else(|| profile.account_id.clone()))
}

struct PreparedCallInput {
    input: CallInput,
    secret_body: Option<Value>,
}

fn call_input(arguments: &CallArgs) -> Result<PreparedCallInput> {
    let selectors = object_from_pairs(&arguments.selectors);
    let query = object_from_pairs(&arguments.query);
    let body = if arguments.body_stdin {
        Some(serde_json::from_str(&read_stdin()?)?)
    } else {
        arguments
            .body_json
            .as_deref()
            .map(serde_json::from_str)
            .transpose()?
    };
    let contains_secret = body
        .as_ref()
        .is_some_and(|value| redact_json(value) != *value);
    if contains_secret && !arguments.body_stdin {
        return Err(CliError::Input(
            "secret-shaped request fields are accepted only through `--body-stdin`, never command arguments"
                .to_owned(),
        ));
    }
    Ok(PreparedCallInput {
        input: CallInput {
            selectors,
            query,
            body: if contains_secret { None } else { body.clone() },
            if_match: arguments.if_match.clone(),
            if_none_match: arguments.if_none_match.clone(),
        },
        secret_body: contains_secret.then_some(body).flatten(),
    })
}

fn object_from_pairs(pairs: &[(String, String)]) -> Value {
    Value::Object(
        pairs
            .iter()
            .map(|(key, value)| (key.clone(), Value::String(value.clone())))
            .collect::<Map<String, Value>>(),
    )
}

fn parse_callback(value: &str) -> Result<(String, String)> {
    if let Ok(document) = serde_json::from_str::<Value>(value) {
        let state = document.get("state").and_then(Value::as_str);
        let code = document.get("code").and_then(Value::as_str);
        if let (Some(state), Some(code)) = (state, code) {
            return Ok((state.to_owned(), code.to_owned()));
        }
    }
    let mut parts = value.split_whitespace();
    let state = parts.next();
    let code = parts.next();
    if let (Some(state), Some(code), None) = (state, code, parts.next()) {
        return Ok((state.to_owned(), code.to_owned()));
    }
    Err(CliError::Input(
        "callback stdin must be JSON with `state` and `code`, or exactly `STATE CODE`".to_owned(),
    ))
}

fn parse_money(value: &str) -> Result<MoneyV1> {
    let (currency, amount) = value
        .split_once(':')
        .ok_or_else(|| CliError::Input("cost ceiling must be CURRENCY:AMOUNT".to_owned()))?;
    if currency.len() != 3
        || !currency
            .chars()
            .all(|character| character.is_ascii_alphabetic())
    {
        return Err(CliError::Input(
            "currency must be a three-letter code".to_owned(),
        ));
    }
    let amount = amount
        .parse::<f64>()
        .map_err(|_| CliError::Input("cost amount is not a number".to_owned()))?;
    if !amount.is_finite() || amount < 0.0 {
        return Err(CliError::Input(
            "cost amount must be finite and non-negative".to_owned(),
        ));
    }
    Ok(MoneyV1 {
        currency: currency.to_ascii_uppercase(),
        amount,
    })
}

fn verification_for_status(status: PlanStatus) -> VerificationState {
    match status {
        PlanStatus::Verified | PlanStatus::Rectified => VerificationState::Passed,
        PlanStatus::Failed => VerificationState::Failed,
        PlanStatus::RectificationRequired => VerificationState::Unsupported,
        _ => VerificationState::Pending,
    }
}

fn stage_required(stage: cfctl_core::GuideStage, capability: &cfctl_core::CapabilityV1) -> bool {
    use cfctl_core::GuideStage;
    match stage {
        GuideStage::RequestApproval | GuideStage::Rectify => capability.mutating,
        GuideStage::CalculateCost => capability.cost.incremental || !capability.cost.known,
        GuideStage::Verify => capability.verification.required,
        _ => true,
    }
}

fn preflight_secret_sink(plan: &PlanV1) -> Result<()> {
    if !is_secret_output_plan(plan) {
        return Ok(());
    }
    let path = secret_sink_path(plan)?;
    if path.exists() {
        return Err(CliError::Input(format!(
            "secret sink already exists and will not be overwritten: {}",
            path.display()
        )));
    }
    let parent = path
        .parent()
        .ok_or_else(|| CliError::Input("secret sink has no parent directory".to_owned()))?;
    fs::create_dir_all(parent).map_err(|source| cli_io(parent, source))
}

fn resolved_plan_input(plan: &PlanV1, secrets: &dyn SecretStore) -> Result<CallInput> {
    let mut input: CallInput = serde_json::from_value(plan.input.clone())?;
    let Some(reference) = plan_secret_body_ref(plan) else {
        return Ok(input);
    };
    let encoded = secrets.get(reference)?.ok_or_else(|| {
        CliError::Input(
            "the plan's secret request body is missing from the platform credential store"
                .to_owned(),
        )
    })?;
    let body: Value = serde_json::from_str(&encoded)?;
    let expected_hash = plan
        .targets
        .pointer("/adapter/secret_body_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input("secret request body hash is missing from the plan".to_owned())
        })?;
    if hash_value(&body)? != expected_hash {
        return Err(CliError::Input(
            "the secret request body drifted after planning; approval is invalid".to_owned(),
        ));
    }
    input.body = Some(body);
    Ok(input)
}

fn plan_secret_body_ref(plan: &PlanV1) -> Option<&str> {
    plan.targets
        .pointer("/adapter/secret_body_ref")
        .and_then(Value::as_str)
}

fn sink_secret_result(plan: &PlanV1, result: &Value) -> Result<PathBuf> {
    let Some(secret) = find_secret_value(result) else {
        return Err(CliError::Input(
            "Cloudflare reported success but no one-time credential value was present; the operation requires rectification"
                .to_owned(),
        ));
    };
    let path = secret_sink_path(plan)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&path)
        .map_err(|source| cli_io(&path, source))?;
    file.write_all(secret.as_bytes())
        .map_err(|source| cli_io(&path, source))?;
    file.sync_all().map_err(|source| cli_io(&path, source))?;
    Ok(path)
}

fn secret_sink_path(plan: &PlanV1) -> Result<PathBuf> {
    plan.targets
        .pointer("/adapter/value_out")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| CliError::Input("secret-producing plan has no value_out sink".to_owned()))
}

fn is_secret_output_plan(plan: &PlanV1) -> bool {
    plan.capability.risk == RiskClass::SecretSensitive
}

fn find_secret_value(value: &Value) -> Option<&str> {
    if let Some(value) = value.as_str() {
        return Some(value);
    }
    if let Some(object) = value.as_object() {
        for key in ["value", "token", "secret", "access_token"] {
            if let Some(candidate) = object.get(key) {
                if let Some(value) = candidate.as_str() {
                    return Some(value);
                }
                if (candidate.is_object() || candidate.is_array())
                    && let Some(value) = find_secret_value(candidate)
                {
                    return Some(value);
                }
            }
        }
        return object
            .values()
            .filter(|candidate| candidate.is_object() || candidate.is_array())
            .find_map(find_secret_value);
    }
    value.as_array()?.iter().find_map(find_secret_value)
}

fn redact_secret_result(value: &Value) -> Value {
    if let Value::Object(object) = value {
        let mut redacted = object.clone();
        if let Some(result) = object.get("result") {
            redacted.insert("result".to_owned(), redact_secret_payload(result, true));
        }
        return Value::Object(redacted);
    }
    redact_secret_payload(value, true)
}

fn redact_secret_payload(value: &Value, root: bool) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, item)| {
                    if matches!(key.as_str(), "value" | "token" | "secret" | "access_token") {
                        (key.clone(), Value::String("[SUNK]".to_owned()))
                    } else {
                        (key.clone(), redact_secret_payload(item, false))
                    }
                })
                .collect(),
        ),
        Value::Array(values) => Value::Array(
            values
                .iter()
                .map(|item| redact_secret_payload(item, true))
                .collect(),
        ),
        Value::String(_) if root => Value::String("[SUNK]".to_owned()),
        _ => value.clone(),
    }
}

fn catalog_is_stale(store: &StateStore) -> bool {
    fs::metadata(store.paths().catalog_file())
        .ok()
        .and_then(|metadata| metadata.modified().ok())
        .and_then(|modified| modified.elapsed().ok())
        .is_none_or(|age| age > Duration::from_secs(24 * 60 * 60))
}

fn http_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(120))
        .user_agent(concat!("cfctl/", env!("CARGO_PKG_VERSION")))
        .build()?)
}

fn configured_agent() -> Result<AgentKind> {
    match env::var("CFCTL_AGENT")
        .unwrap_or_else(|_| "codex".to_owned())
        .to_ascii_lowercase()
        .as_str()
    {
        "codex" => Ok(AgentKind::Codex),
        "claude" | "claude-code" => Ok(AgentKind::Claude),
        "cursor" => Ok(AgentKind::Cursor),
        "gemini" => Ok(AgentKind::Gemini),
        value => Err(CliError::Input(format!(
            "unsupported configured agent `{value}`"
        ))),
    }
}

fn home_directory() -> Result<PathBuf> {
    env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| CliError::Input("HOME is unavailable".to_owned()))
}

fn read_stdin() -> Result<String> {
    let mut value = String::new();
    std::io::stdin()
        .read_to_string(&mut value)
        .map_err(|source| cli_io(Path::new("stdin"), source))?;
    Ok(value)
}

fn docs_file(store: &StateStore) -> PathBuf {
    store
        .paths()
        .data_dir
        .join("catalog/official-text-feeds-v1.json")
}

fn catalog_index_file(store: &StateStore) -> PathBuf {
    store.paths().data_dir.join("catalog/catalog-v1.sqlite3")
}

fn workspace_graph_file(store: &StateStore) -> PathBuf {
    store.paths().data_dir.join("workspace-graph-v1.json")
}

fn capability_missing(id: &str) -> CliError {
    CliError::Input(format!(
        "capability `{id}` is not in the current catalog; run `cfctl catalog search`"
    ))
}

fn is_secret_path(path: &Path) -> bool {
    let normalized = path.display().to_string().to_ascii_lowercase();
    [".env", "secret", "credential", "token", "private_key"]
        .iter()
        .any(|needle| normalized.contains(needle))
}

fn contains_sensitive_content(content: &str) -> bool {
    if let Ok(value) = serde_json::from_str::<Value>(content)
        && redact_json(&value) != value
    {
        return true;
    }
    content.lines().any(|line| {
        let normalized = line.trim().to_ascii_lowercase();
        !normalized.contains("[redacted]")
            && [
                "access_token",
                "refresh_token",
                "api_token",
                "api_key",
                "global_key",
                "client_secret",
                "private_key",
                "password",
            ]
            .iter()
            .any(|marker| {
                normalized.starts_with(marker)
                    && (normalized.contains('=') || normalized.contains(':'))
            })
    })
}

fn cli_io(path: &Path, source: std::io::Error) -> CliError {
    CliError::Io {
        path: path.display().to_string(),
        source,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{
        find_secret_value, persist_secret_lifecycle, redact_secret_result, sink_secret_result,
        token_compensation_request,
    };
    use cfctl_auth::{AuthError, SecretStore};
    use cfctl_core::{CapabilityV1, PlanStatus, PlanV1, RiskClass, TransactionStageV1};
    use cfctl_storage::{RuntimePaths, StateStore};
    use serde_json::json;

    struct DeleteFailingSecretStore;

    impl SecretStore for DeleteFailingSecretStore {
        fn put(&self, _key: &str, _value: &str) -> cfctl_auth::Result<()> {
            Ok(())
        }

        fn get(&self, _key: &str) -> cfctl_auth::Result<Option<String>> {
            Ok(None)
        }

        fn delete(&self, _key: &str) -> cfctl_auth::Result<()> {
            Err(AuthError::SecretStore("injected delete failure".to_owned()))
        }
    }

    #[test]
    fn secret_response_preserves_safe_receipt_metadata() {
        let response = json!({
            "status": 200,
            "success": true,
            "result": {
                "id": "token-id",
                "name": "automation token",
                "status": "active",
                "value": "must-not-survive"
            }
        });

        let redacted = redact_secret_result(&response);

        assert_eq!(redacted["result"]["id"], "token-id");
        assert_eq!(redacted["result"]["status"], "active");
        assert_eq!(redacted["result"]["value"], "[SUNK]");
        assert!(!redacted.to_string().contains("must-not-survive"));
    }

    #[test]
    fn resource_metadata_is_not_mistaken_for_a_secret_value() {
        assert_eq!(
            find_secret_value(&json!({"id":"token-id","status":"active"})),
            None
        );
        assert_eq!(
            find_secret_value(&json!({
                "id": "token-id",
                "nested": {"value": "one-time-secret"}
            })),
            Some("one-time-secret")
        );
    }

    #[test]
    fn metadata_only_secret_response_is_rejected_without_creating_a_sink() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("credential.txt");
        let capability = CapabilityV1::new(
            "account-api-tokens-create-token",
            "Create account token",
            "POST",
            "/accounts/{account_id}/tokens",
        );
        let plan = PlanV1::draft(
            "profile-a",
            "account-a",
            "catalog-sha",
            capability,
            json!({"adapter":{"value_out":path}}),
        )
        .expect("plan");

        assert!(sink_secret_result(&plan, &json!({"id":"token-id","status":"active"})).is_err());
        assert!(!path.exists());
    }

    #[test]
    fn token_creation_rectification_builds_a_separate_revoke_request() {
        let mut capability = CapabilityV1::new(
            "account-api-tokens-create-token",
            "Create account token",
            "POST",
            "/accounts/{account_id}/tokens",
        );
        capability.rollback.supported = true;
        capability.rollback.strategy = Some(
            "revoke_created_api_token_by_returned_id_if_downstream_installation_fails".to_owned(),
        );
        let mut plan = PlanV1::draft(
            "profile-a",
            "account-a",
            "catalog-sha",
            capability,
            json!({"account_id":"account-a"}),
        )
        .expect("plan");
        plan.approve(true, None).expect("approve");
        plan.mark_consumed().expect("consume");
        plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
            .expect("attempt");
        plan.record_transaction_stage_with_artifact(
            TransactionStageV1::BoundaryResponsePersisted,
            json!({"resource_id":"token-id","success":true}),
        )
        .expect("response receipt");
        plan.status = PlanStatus::RectificationRequired;

        let request = token_compensation_request(&plan)
            .expect("request resolves")
            .expect("compensation is supported");

        assert_eq!(request.capability_id, "account-api-tokens-delete-token");
        assert_eq!(request.input.selectors["account_id"], "account-a");
        assert_eq!(request.input.selectors["token_id"], "token-id");
        assert_eq!(request.requested_account.as_deref(), Some("account-a"));
    }

    #[test]
    fn input_cleanup_failure_is_a_hash_bound_rectification_checkpoint() {
        let root = tempfile::tempdir().expect("runtime root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
        let capability = CapabilityV1::new(
            "dns-records-create",
            "Create DNS record",
            "POST",
            "/zones/{zone_id}/dns_records",
        );
        let mut plan = PlanV1::draft(
            "profile-a",
            "account-a",
            "catalog-sha",
            capability,
            json!({"adapter":{"secret_body_ref":"keychain:plan/operation/body"}}),
        )
        .expect("plan");
        plan.approve(true, None).expect("approve");
        plan.mark_consumed().expect("consume");
        plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
            .expect("attempt");
        plan.status = PlanStatus::Running;
        plan.record_transaction_stage_with_artifact(
            TransactionStageV1::BoundaryResponsePersisted,
            json!({"success":true}),
        )
        .expect("response");

        let error = persist_secret_lifecycle(
            &store,
            &mut plan,
            true,
            Some(&json!({})),
            &DeleteFailingSecretStore,
        )
        .expect_err("cleanup fails");

        assert!(error.to_string().contains("injected delete failure"));
        assert_eq!(plan.status, PlanStatus::RectificationRequired);
        assert_eq!(
            plan.transaction_stage,
            TransactionStageV1::SecretSinkPersisted
        );
        assert_eq!(
            plan.transaction_artifact(TransactionStageV1::SecretSinkPersisted)
                .and_then(|artifact| artifact.get("failure"))
                .and_then(serde_json::Value::as_str),
            Some("input_cleanup_failed")
        );
        plan.validate_transaction_journal()
            .expect("failure receipt validates");
        store
            .load_plan(&plan.operation_id)
            .expect("failure receipt is durable")
            .validate_transaction_journal()
            .expect("durable failure receipt validates");
    }

    #[test]
    fn missing_sink_only_output_is_a_hash_bound_rectification_checkpoint() {
        let root = tempfile::tempdir().expect("runtime root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
        let mut capability = CapabilityV1::new(
            "account-api-tokens-create-token",
            "Create account token",
            "POST",
            "/accounts/{account_id}/tokens",
        );
        capability.risk = RiskClass::SecretSensitive;
        let mut plan = PlanV1::draft(
            "profile-a",
            "account-a",
            "catalog-sha",
            capability,
            json!({"adapter":{"value_out":root.path().join("token.txt")}}),
        )
        .expect("plan");
        plan.approve(true, None).expect("approve");
        plan.mark_consumed().expect("consume");
        plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
            .expect("attempt");
        plan.status = PlanStatus::Running;
        plan.record_transaction_stage_with_artifact(
            TransactionStageV1::BoundaryResponsePersisted,
            json!({"success":true}),
        )
        .expect("response");

        persist_secret_lifecycle(&store, &mut plan, true, None, &DeleteFailingSecretStore)
            .expect_err("missing output fails closed");

        assert_eq!(plan.status, PlanStatus::RectificationRequired);
        assert_eq!(
            plan.transaction_artifact(TransactionStageV1::SecretSinkPersisted)
                .and_then(|artifact| artifact.get("failure"))
                .and_then(serde_json::Value::as_str),
            Some("output_missing")
        );
        plan.validate_transaction_journal()
            .expect("missing output receipt validates");
    }
}
