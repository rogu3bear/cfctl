//! Deterministic command handlers for the cfctl v2 binary.

use std::{
    collections::{BTreeMap, BTreeSet},
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
    ProfileMetadata, SecretBackend, SecretStore, exchange_authorization_code, refresh_oauth_tokens,
    revoke_oauth_token,
};
use cfctl_catalog::{
    CatalogIndex, CatalogSnapshot, OfficialTextFeedsV1, attach_official_product_knowledge,
    fetch_official, fetch_official_text_feeds, ingest_cli_help, ingest_governed_ui_capabilities,
    refresh_dynamic_mutation_contract,
};
use cfctl_cloudflare::{
    CallInput, CloudflareError, CloudflareResponseV1, Executor, OperationVerificationV1,
    validate_request_contract,
};
use cfctl_core::{
    AdapterStatus, CapabilityGuideStageV1, CapabilityGuideV1, CapabilityV1, ErrorV1, EvidenceClass,
    EvidenceV1, GuideActionV1, GuideContractStateV1, GuideTopicDocumentV1, GuideTopicV1, MoneyV1,
    PlanStatus, PlanV1, PolicyDisposition, ResultEnvelopeV2, RiskClass, StandingAuthorityV1,
    TransactionStageV1, VerificationState, guide_stages, guide_topic_document, hash_value,
    redact_json, render_guide_topic_document_markdown,
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
    GuideArgs, GuideTopicArg, ImportApiTokenArgs, ImportGlobalKeyArgs, KeyMutationArgs,
    KeyPermissionArgs, KeyPolicyApproveArgs, KeyPolicyCommand, KeyPolicyCreateArgs,
    KeyPolicySelector, KeyRevokeArgs, KeyRotateArgs, KeysCommand, MigrateCommand, PlanApproveArgs,
    PlanSelector, PlansCommand, ProfileSelector, SearchArgs, WorkspaceCommand,
    build_identity::{current_build_info, inspect_path_build},
    profiles::{PendingLogin, ProfilesConfig, ensure_supported_profile},
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
    let store = StateStore::open(RuntimePaths::discover()?)?;
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
        Command::Version => version_command(),
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

fn platform_secrets(store: &StateStore) -> PlatformSecretStore {
    PlatformSecretStore::new(store.paths().data_dir.join("auth").join("secrets"))
}

fn describe_secret_backend(backend: Option<SecretBackend>) -> (&'static str, &'static str) {
    match backend {
        Some(SecretBackend::PlatformKeyring) => {
            ("platform_keyring", "in the platform credential store")
        }
        Some(SecretBackend::FallbackFile) => (
            "fallback_file",
            "in cfctl's mode-0600 file secret store because the platform keyring is unavailable (see `cfctl doctor`)",
        ),
        Some(SecretBackend::Memory) => ("memory", "in the in-process secret store"),
        None => ("unknown", "in an undetermined backend"),
    }
}

fn platform_secret_store_health(store: &StateStore) -> Result<Value> {
    let secrets = platform_secrets(store);
    let preferred = if cfg!(target_os = "macos") {
        "keychain"
    } else if cfg!(target_os = "linux") {
        "secret_service"
    } else {
        "unsupported"
    };
    let (keyring, active_backend) = match secrets.keyring_probe() {
        Ok(()) => ("ok".to_owned(), "platform_keyring"),
        Err(error) => (format!("unavailable: {error}"), "fallback_file"),
    };
    Ok(json!({
        "preferred": preferred,
        "keyring": keyring,
        "active_backend": active_backend,
        "fallback_dir": secrets.fallback_root(),
        "fallback_secret_count": secrets.fallback_secret_count()?,
    }))
}

fn standing_authorities_health(store: &StateStore) -> Result<Value> {
    let now = Utc::now();
    let authorities: Vec<Value> = store
        .list_authorities()?
        .iter()
        .map(|authority| {
            json!({
                "authority_id": authority.authority_id,
                "status": authority.status.as_str(),
                "account_id": authority.account_id,
                "name_prefix": authority.name_prefix,
                "capability_ids": authority.capability_ids,
                "expires_at": authority.expires_at,
                "max_runs_per_day": authority.max_runs_per_day,
                "runs_last_24h": authority.runs_in_last_day(now),
                "minted_tokens": authority.minted_token_ids.len(),
            })
        })
        .collect();
    Ok(Value::Array(authorities))
}

async fn auth_command(store: &StateStore, command: AuthCommand) -> Result<ResultEnvelopeV2> {
    let secrets = platform_secrets(store);
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
        AuthCommand::ImportApiToken(arguments) => {
            import_api_token(store, &mut profiles, &secrets, &arguments)
        }
        AuthCommand::ImportGlobalKey(arguments) => {
            import_global_key(store, &mut profiles, &secrets, &arguments)
        }
    }
}

fn require_oauth_client_id(client_id: Option<&str>) -> Result<&str> {
    client_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "OAuth login needs --client-id (or CFCTL_OAUTH_CLIENT_ID). Until public cfctl OAuth is promoted, use the simple scoped lane: printf '%s' \"$CLOUDFLARE_API_TOKEN\" | cfctl auth import-api-token --account <account-id> --stdin"
                    .to_owned(),
            )
        })
}

async fn begin_oauth_login(
    store: &StateStore,
    profiles: &mut ProfilesConfig,
    secrets: &dyn SecretStore,
    arguments: AuthLoginArgs,
) -> Result<ResultEnvelopeV2> {
    let client_id = require_oauth_client_id(arguments.client_id.as_deref())?;
    let requested_scopes =
        resolve_login_scopes(store, profiles, secrets, &arguments.scopes).await?;
    let client = OAuthClientConfig::cfctl_public(client_id);
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
    let client_id = require_oauth_client_id(arguments.client_id.as_deref())?;
    let pending = profiles
        .pending_logins
        .get(&arguments.profile)
        .cloned()
        .ok_or_else(|| CliError::Input(format!("no pending login for `{}`", arguments.profile)))?;
    if pending.client.client_id != client_id {
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
    ensure_supported_profile(profile)?;
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
    let profile = profiles
        .profiles
        .get(&selector.profile)
        .ok_or_else(|| CliError::Input(format!("profile `{}` does not exist", selector.profile)))?;
    ensure_supported_profile(profile)?;
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
    let legacy_profile = profiles
        .profiles
        .get(&selector.profile)
        .is_some_and(|profile| profile.kind == ProfileKind::LegacyWranglerSession);
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
    if !legacy_profile {
        secrets.delete_profile(&selector.profile)?;
    }
    profiles.profiles.remove(&selector.profile);
    profiles.pending_logins.remove(&selector.profile);
    if profiles.current_profile.as_deref() == Some(&selector.profile) {
        profiles.current_profile = None;
    }
    profiles.save(store)?;
    Ok(ResultEnvelopeV2::success(
        "auth logout",
        json!({
            "profile": selector.profile,
            "credentials_removed": !legacy_profile,
            "legacy_profile_removed": legacy_profile,
            "message": if legacy_profile {
                "Unsupported legacy Wrangler session metadata was removed; no credential store entry was read or changed."
            } else {
                "Profile credentials and metadata were removed."
            }
        }),
    ))
}

fn import_api_token(
    store: &StateStore,
    profiles: &mut ProfilesConfig,
    secrets: &dyn SecretStore,
    arguments: &ImportApiTokenArgs,
) -> Result<ResultEnvelopeV2> {
    let token = read_import_secret(arguments.stdin, arguments.value_in.as_deref(), "API token")?;
    store_imported_api_token(
        store,
        profiles,
        secrets,
        &arguments.profile,
        &arguments.account,
        &token,
    )
}

fn store_imported_api_token(
    store: &StateStore,
    profiles: &mut ProfilesConfig,
    secrets: &dyn SecretStore,
    profile_id: &str,
    account: &str,
    token: &str,
) -> Result<ResultEnvelopeV2> {
    let account = account.trim();
    let token = token.trim();
    if account.is_empty() {
        return Err(CliError::Input(
            "API-token import requires a non-empty `--account` pin".to_owned(),
        ));
    }
    if token.is_empty() {
        return Err(CliError::Input(
            "the supplied API token was empty".to_owned(),
        ));
    }
    if token.chars().any(char::is_whitespace) {
        return Err(CliError::Input(
            "the supplied API token must be a single value without whitespace".to_owned(),
        ));
    }
    secrets.store_api_token(profile_id, token)?;
    let (secret_backend, storage_note) =
        describe_secret_backend(secrets.locate_api_token(profile_id)?);
    let profile = ProfileMetadata::new(profile_id, ProfileKind::ApiToken, Some(account));
    profiles.profiles.insert(profile_id.to_owned(), profile);
    profiles.current_profile = Some(profile_id.to_owned());
    profiles.save(store)?;
    Ok(ResultEnvelopeV2::success(
        "auth import-api-token",
        json!({
            "profile": profile_id,
            "kind": "api_token",
            "account_id": account,
            "selected": true,
            "emergency_only": false,
            "secret_backend": secret_backend,
            "message": format!("API token stored {storage_note} and selected as the active profile. The token value was not written to stdout, plans, or repository files.")
        }),
    ))
}

fn import_global_key(
    store: &StateStore,
    profiles: &mut ProfilesConfig,
    secrets: &dyn SecretStore,
    arguments: &ImportGlobalKeyArgs,
) -> Result<ResultEnvelopeV2> {
    let key = read_import_secret(arguments.stdin, arguments.value_in.as_deref(), "global key")?
        .trim()
        .to_owned();
    if key.is_empty() {
        return Err(CliError::Input(
            "the supplied global key was empty".to_owned(),
        ));
    }
    secrets.store_global_key(&arguments.profile, &arguments.email, &key)?;
    let (secret_backend, storage_note) =
        describe_secret_backend(secrets.locate_global_key(&arguments.profile)?);
    let profile = ProfileMetadata::new(&arguments.profile, ProfileKind::GlobalKey, None);
    profiles.profiles.insert(arguments.profile.clone(), profile);
    profiles.save(store)?;
    Ok(ResultEnvelopeV2::success(
        "auth import-global-key",
        json!({
            "profile": arguments.profile,
            "emergency_only": true,
            "selected": false,
            "secret_backend": secret_backend,
            "message": format!("Emergency global key stored {storage_note}. It was not selected.")
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
    let previous_catalog = preserve_previous_catalog(store)?;
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
            "previous_catalog": previous_catalog.clone(),
        }),
    )?;
    Ok(ResultEnvelopeV2::success(
        "catalog sync",
        json!({
            "coverage": catalog.coverage(),
            "docs_fetched_at": feeds.fetched_at,
            "oauth_scope_inventory": oauth_scope_status,
            "previous_catalog": previous_catalog,
            "message": format!("Catalog synced: {} API, CLI, and governed UI capabilities indexed.", catalog.capabilities.len())
        }),
    )
    .with_evidence(evidence))
}

fn preserve_previous_catalog(store: &StateStore) -> Result<Value> {
    let current_path = store.paths().catalog_file();
    if !current_path.is_file() {
        return Ok(json!({"status": "absent"}));
    }

    match CatalogSnapshot::load(&current_path) {
        Ok(current) => {
            let schema_hash = current.schema_hash.clone();
            store.write_json(&store.paths().catalog_previous_file(), &current)?;
            Ok(json!({
                "status": "preserved",
                "schema_hash": schema_hash,
            }))
        }
        Err(error) => Ok(json!({
            "status": "discarded_invalid",
            "reason": error.to_string(),
        })),
    }
}

async fn guide_command(store: &StateStore, arguments: &GuideArgs) -> Result<ResultEnvelopeV2> {
    if let Some(topic) = arguments.topic {
        return guide_topic_envelope(topic);
    }
    let capability_id = arguments.capability_id.as_deref().ok_or_else(|| {
        CliError::Input("guide requires one capability ID or `--topic`".to_owned())
    })?;
    let catalog = ensure_catalog(store).await?;
    let capability = catalog
        .get(capability_id)
        .ok_or_else(|| capability_missing(capability_id))?;
    Ok(ResultEnvelopeV2::success(
        "guide",
        serde_json::to_value(guide_document(capability))?,
    ))
}

fn guide_topic_envelope(topic: GuideTopicArg) -> Result<ResultEnvelopeV2> {
    let topic = match topic {
        GuideTopicArg::System => GuideTopicV1::System,
        GuideTopicArg::StandingAuthority => GuideTopicV1::StandingAuthority,
    };
    Ok(ResultEnvelopeV2::success(
        "guide",
        serde_json::to_value(guide_topic_document(topic))?,
    ))
}

async fn call_command(store: &StateStore, arguments: CallArgs) -> Result<ResultEnvelopeV2> {
    let catalog = ensure_catalog(store).await?;
    let capability = catalog
        .get(&arguments.capability_id)
        .cloned()
        .ok_or_else(|| capability_missing(&arguments.capability_id))?;
    if is_secret_output_capability(&capability) && arguments.value_out.is_none() {
        return Err(CliError::Input(
            "secret-producing capabilities require `--value-out <new-path>`; the value is never written to stdout or evidence"
                .to_owned(),
        ));
    }
    let mut prepared = call_input(&capability, &arguments)?;
    preflight_call_input(&capability, &prepared.input, prepared.secret_body.as_ref())?;
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
    let secrets = platform_secrets(store);
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
    )
    .await;
    if result.is_err()
        && let Some(reference) = secret_ref
    {
        secrets.delete(&reference)?;
    }
    result
}

fn preflight_call_input(
    capability: &CapabilityV1,
    input: &CallInput,
    secret_body: Option<&Value>,
) -> Result<()> {
    let mut resolved = input.clone();
    if let Some(secret_body) = secret_body {
        resolved.body = Some(secret_body.clone());
    }
    validate_request_contract(capability, &resolved)?;
    validate_cloudflare_tunnel_configuration_ingress(capability, &resolved)?;
    validate_warp_connector_configuration_semantics(capability, &resolved)?;
    validate_d1_database_create_semantics(capability, &resolved)?;
    Ok(())
}

fn validate_d1_database_create_semantics(
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<()> {
    if capability.id != "d1-create-database" {
        return Ok(());
    }
    let Some(body) = input.body.as_ref().and_then(Value::as_object) else {
        return Ok(());
    };
    if body.contains_key("jurisdiction") && body.contains_key("primary_location_hint") {
        return Err(CliError::Input(
            "D1 database creation cannot combine `jurisdiction` with `primary_location_hint`: Cloudflare gives jurisdiction precedence and ignores the location hint; choose the hard jurisdiction boundary or the best-effort location hint"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_cloudflare_tunnel_configuration_ingress(
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<()> {
    if !is_cloudflare_tunnel_configuration_mutation(capability) {
        return Ok(());
    }
    let ingress = input
        .body
        .as_ref()
        .and_then(|body| body.pointer("/config/ingress"))
        .and_then(Value::as_array)
        .filter(|rules| !rules.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "Tunnel configuration requires at least one ingress rule and a final catch-all rule"
                    .to_owned(),
            )
        })?;
    for (index, rule) in ingress.iter().enumerate() {
        let service = rule
            .get("service")
            .and_then(Value::as_str)
            .filter(|service| !service.trim().is_empty())
            .ok_or_else(|| {
                CliError::Input(format!(
                    "Tunnel ingress rule {} requires a non-empty service",
                    index + 1
                ))
            })?;
        let _ = service;
        let matches_all_traffic =
            rule.get("hostname").and_then(Value::as_str) == Some("") && rule.get("path").is_none();
        if matches_all_traffic && index + 1 != ingress.len() {
            return Err(CliError::Input(format!(
                "Tunnel ingress rule {} is a catch-all, so every later rule is unreachable; move the catch-all to the end",
                index + 1
            )));
        }
        if index + 1 == ingress.len() && !matches_all_traffic {
            return Err(CliError::Input(
                "Tunnel configuration requires a final catch-all ingress rule with an empty hostname and no path"
                    .to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_warp_connector_configuration_semantics(
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<()> {
    if !is_warp_connector_configuration_mutation(capability) {
        return Ok(());
    }
    let body = input
        .body
        .as_ref()
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CliError::Input("WARP Connector configuration requires a JSON object body".to_owned())
        })?;
    let mode = body.get("ha_mode").and_then(Value::as_str).ok_or_else(|| {
        CliError::Input("WARP Connector configuration requires string field `ha_mode`".to_owned())
    })?;
    let config = body.get("config").filter(|value| !value.is_null());
    match mode {
        "none" | "disabled" => {
            if config.is_some_and(|value| {
                value
                    .as_object()
                    .is_none_or(|configuration| !configuration.is_empty())
            }) {
                return Err(CliError::Input(format!(
                    "WARP Connector HA mode `{mode}` requires `config` to be omitted, null, or an empty object"
                )));
            }
        }
        "aws" => {
            let fnr_id = config
                .and_then(|value| value.get("fnr_id"))
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| {
                    CliError::Input(
                        "WARP Connector HA mode `aws` requires a non-empty `config.fnr_id`"
                            .to_owned(),
                    )
                })?;
            let _ = fnr_id;
        }
        "local" => {
            let configuration = config.and_then(Value::as_object).ok_or_else(|| {
                CliError::Input("WARP Connector HA mode `local` requires `config.vips`".to_owned())
            })?;
            let mut addresses = BTreeSet::new();
            validate_warp_connector_vip_addresses(configuration, "vips", true, &mut addresses)?;
            validate_warp_connector_vip_addresses(
                configuration,
                "vips_previous",
                false,
                &mut addresses,
            )?;
        }
        _ => {
            return Err(CliError::Input(format!(
                "unsupported WARP Connector HA mode `{mode}`"
            )));
        }
    }
    Ok(())
}

fn validate_warp_connector_vip_addresses(
    configuration: &Map<String, Value>,
    field: &str,
    required: bool,
    addresses: &mut BTreeSet<std::net::IpAddr>,
) -> Result<()> {
    let Some(values) = configuration.get(field) else {
        return if required {
            Err(CliError::Input(format!(
                "WARP Connector HA mode `local` requires `config.{field}`"
            )))
        } else {
            Ok(())
        };
    };
    let values = values.as_array().ok_or_else(|| {
        CliError::Input(format!(
            "WARP Connector `config.{field}` must be an array of IP addresses"
        ))
    })?;
    for (index, value) in values.iter().enumerate() {
        let address = value
            .get("address")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                CliError::Input(format!(
                    "WARP Connector `config.{field}[{index}].address` must be a non-empty IP address"
                ))
            })?;
        let address_identity = address.parse::<std::net::IpAddr>().map_err(|_| {
            CliError::Input(format!(
                "WARP Connector `config.{field}[{index}].address` is not a valid IPv4 or IPv6 address"
            ))
        })?;
        if !addresses.insert(address_identity) {
            return Err(CliError::Input(format!(
                "WARP Connector IP address `{address}` is duplicated across the current and previous VIP sets"
            )));
        }
    }
    Ok(())
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
    let credential = fresh_credential(profile, &platform_secrets(store)).await?;
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
    envelope.performed = true;
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
    let credential = fresh_credential(profile, &platform_secrets(store)).await?;
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

const ENTITLEMENT_UNRESOLVED_GAP: &str =
    "account entitlement has not been resolved for this plan-gated operation";
const GLOBAL_WARP_OVERRIDE_MUTATION_CAPABILITY_ID: &str =
    "devices-resilience-set-global-warp-override";
const GLOBAL_WARP_OVERRIDE_READ_CAPABILITY_ID: &str =
    "devices-resilience-retrieve-global-warp-override";
const GLOBAL_WARP_OVERRIDE_PATH: &str = "/accounts/{account_id}/devices/resilience/disconnect";
const D1_READ_REPLICATION_READ_CAPABILITY_ID: &str = "d1-get-database";
const D1_READ_REPLICATION_PATH: &str = "/accounts/{account_id}/d1/database/{database_id}";
const D1_READ_REPLICATION_PRECONDITION: &str = "d1_read_replication_state";
const D1_DATABASE_CREATE_CAPABILITY_ID: &str = "d1-create-database";
const D1_DATABASE_DELETE_CAPABILITY_ID: &str = "d1-delete-database";
const D1_EMPTY_DATABASE_PRECONDITION: &str = "d1_empty_database_state";
const D1_EMPTY_DATABASE_COMPENSATION_STRATEGY: &str =
    "delete_created_empty_d1_database_by_returned_uuid_if_unchanged";
const CLOUDFLARE_TUNNEL_CONFIGURATION_MUTATION_CAPABILITY_ID: &str =
    "cloudflare-tunnel-configuration-put-configuration";
const CLOUDFLARE_TUNNEL_CONFIGURATION_READ_CAPABILITY_ID: &str =
    "cloudflare-tunnel-configuration-get-configuration";
const CLOUDFLARE_TUNNEL_CONFIGURATION_PATH: &str =
    "/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations";
const CLOUDFLARE_TUNNEL_CONFIGURATION_STATE_PRECONDITION: &str =
    "cloudflare_tunnel_configuration_state";
const WARP_CONNECTOR_CONFIGURATION_MUTATION_CAPABILITY_ID: &str =
    "cloudflare-tunnel-configuration-update-warp-connector-configuration";
const WARP_CONNECTOR_CONFIGURATION_READ_CAPABILITY_ID: &str =
    "cloudflare-tunnel-configuration-get-warp-connector-configuration";
const WARP_CONNECTOR_CONFIGURATION_PATH: &str =
    "/accounts/{account_id}/warp_connector/{tunnel_id}/configurations";
const WARP_CONNECTOR_CONFIGURATION_STATE_PRECONDITION: &str = "warp_connector_configuration_state";
const WEB_ANALYTICS_RUM_MUTATION_CAPABILITY_ID: &str = "web-analytics-toggle-rum";
const WEB_ANALYTICS_RUM_READ_CAPABILITY_ID: &str = "web-analytics-get-rum-status";
const WEB_ANALYTICS_RUM_PATH: &str = "/zones/{zone_id}/settings/rum";
const WEB_ANALYTICS_RUM_STATE_PRECONDITION: &str = "web_analytics_rum_state";
const DNS_RECORD_DETAIL_READ_CAPABILITY_ID: &str = "dns-records-for-a-zone-dns-record-details";
const DNS_RECORD_DETAIL_PATH: &str = "/zones/{zone_id}/dns_records/{dns_record_id}";
const DNS_RECORD_STATE_PRECONDITION: &str = "dns_record_state";
const DNS_RECORD_RESTORE_CAPABILITY_ID: &str = "dns-records-for-a-zone-update-dns-record";
const OAUTH_CLIENT_DETAIL_READ_CAPABILITY_ID: &str = "oauth-clients-get";
const OAUTH_CLIENT_DETAIL_PATH: &str = "/accounts/{account_id}/oauth_clients/{oauth_client_id}";
const OAUTH_CLIENT_KEY_OVERLAP_PRECONDITION: &str = "oauth_client_key_overlap";
const ZONE_DETAILS_CAPABILITY_ID: &str = "zones-0-get";
const ZONE_SUBSCRIPTION_CAPABILITY_ID: &str = "zone-subscription-zone-subscription-details";

fn oauth_client_secret_expected_prior_state(capability: &CapabilityV1) -> Option<bool> {
    match (
        capability.id.as_str(),
        capability.method.as_str(),
        capability.verification.strategy.as_str(),
    ) {
        (
            "oauth-clients-rotate-secret",
            "POST",
            "oauth_client_reports_rotated_secret_after_value_roll",
        ) => Some(false),
        (
            "oauth-clients-delete-rotated-secret",
            "DELETE",
            "oauth_client_reports_no_rotated_secret_after_old_secret_delete",
        ) => Some(true),
        _ => None,
    }
}

fn should_bind_oauth_client_secret_state(capability: &CapabilityV1) -> bool {
    oauth_client_secret_expected_prior_state(capability).is_some()
        && capability.mutating
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        && capability.verification_contract_supported()
}

fn oauth_client_detail_read_contract_supported(capability: &CapabilityV1) -> bool {
    capability.id == OAUTH_CLIENT_DETAIL_READ_CAPABILITY_ID
        && capability.method == "GET"
        && capability.path == OAUTH_CLIENT_DETAIL_PATH
        && capability.product == "OAuth Clients"
        && capability.account_scope == "account"
        && !capability.mutating
        && capability.request_schema.is_none()
        && capability.permissions == ["OAuth Client Read"]
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        && capability.selectors.len() == 2
        && ["account_id", "oauth_client_id"].iter().all(|name| {
            capability.selectors.iter().any(|selector| {
                selector.name == *name
                    && selector.location == "path"
                    && selector.required
                    && selector.value_type == "string"
            })
        })
        && capability
            .response_contract
            .as_ref()
            .is_some_and(|contract| {
                matches!(
                    contract.body_mode,
                    cfctl_core::ResponseBodyModeV1::CloudflareJsonEnvelope
                ) && contract.success_statuses == ["200"]
                    && contract.success_media_types == ["application/json"]
            })
}

fn apply_oauth_client_secret_state_response(
    capability: &CapabilityV1,
    account_id: &str,
    oauth_client_id: &str,
    response: &CloudflareResponseV1,
) -> Result<Value> {
    if !should_bind_oauth_client_secret_state(capability) {
        return Err(CliError::Input(
            "OAuth client secret operation drifted from its governed two-secret cutover contract"
                .to_owned(),
        ));
    }
    if !response.success || response.status != 200 {
        return Err(CliError::Input(format!(
            "OAuth client state read did not return the exact successful HTTP 200 contract (received {}); the mutation boundary was not crossed",
            response.status
        )));
    }
    if response.result.get("client_id").and_then(Value::as_str) != Some(oauth_client_id) {
        return Err(CliError::Input(
            "OAuth client state read returned a different or missing client id; the mutation boundary was not crossed"
                .to_owned(),
        ));
    }
    let has_rotated_secret = response
        .result
        .get("has_rotated_secret")
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            CliError::Input(
                "OAuth client state read omitted the two-secret state; the mutation boundary was not crossed"
                    .to_owned(),
            )
        })?;
    let expected = oauth_client_secret_expected_prior_state(capability)
        .ok_or_else(|| CliError::Input("OAuth client cutover phase is unsupported".to_owned()))?;
    if has_rotated_secret != expected {
        let required_state = if expected {
            "two active secrets before deleting the old one"
        } else {
            "one active secret before creating the overlap secret"
        };
        return Err(CliError::Input(format!(
            "OAuth client secret operation requires {required_state}; the mutation boundary was not crossed"
        )));
    }
    Ok(json!({
        "schema_version": 1,
        "source_capability_id": OAUTH_CLIENT_DETAIL_READ_CAPABILITY_ID,
        "source_path": OAUTH_CLIENT_DETAIL_PATH,
        "target_capability_id": capability.id,
        "target_method": capability.method,
        "target_scope": "account",
        "account_id": account_id,
        "oauth_client_id": oauth_client_id,
        "key_overlap_active": has_rotated_secret,
    }))
}

async fn read_live_oauth_client_secret_state(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: &AuthCredential,
) -> Result<(Value, EvidenceV1)> {
    if !should_bind_oauth_client_secret_state(capability) {
        return Err(CliError::Input(
            "OAuth client secret operation drifted from its governed prior-state contract"
                .to_owned(),
        ));
    }
    let selected_account = input
        .selectors
        .get("account_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "OAuth client state precondition requires string selector `account_id`".to_owned(),
            )
        })?;
    if selected_account != account_id {
        return Err(CliError::Input(
            "OAuth client target account differs from the selected account; the mutation boundary was not crossed"
                .to_owned(),
        ));
    }
    let oauth_client_id = input
        .selectors
        .get("oauth_client_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "OAuth client state precondition requires string selector `oauth_client_id`"
                    .to_owned(),
            )
        })?;
    let source_capability = catalog
        .get(OAUTH_CLIENT_DETAIL_READ_CAPABILITY_ID)
        .ok_or_else(|| capability_missing(OAUTH_CLIENT_DETAIL_READ_CAPABILITY_ID))?;
    if !oauth_client_detail_read_contract_supported(source_capability) {
        return Err(CliError::Input(
            "OAuth client state source capability drifted from the governed client detail read"
                .to_owned(),
        ));
    }
    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let response = executor
        .execute_read(
            source_capability,
            &CallInput {
                selectors: json!({
                    "account_id":account_id,
                    "oauth_client_id":oauth_client_id
                }),
                query: json!({}),
                body: None,
                ..CallInput::default()
            },
            credential,
        )
        .await?;
    let receipt = apply_oauth_client_secret_state_response(
        capability,
        account_id,
        oauth_client_id,
        &response,
    )?;
    let evidence = store.write_evidence(EvidenceClass::LiveRead, &receipt)?;
    Ok((receipt, evidence))
}

fn is_global_warp_override_mutation(capability: &CapabilityV1) -> bool {
    capability.id == GLOBAL_WARP_OVERRIDE_MUTATION_CAPABILITY_ID
}

fn should_bind_global_warp_override_state(capability: &CapabilityV1) -> bool {
    is_global_warp_override_mutation(capability)
        && capability.mutating
        && capability.method == "POST"
        && capability.path == GLOBAL_WARP_OVERRIDE_PATH
        && capability.account_scope == "account"
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        && capability.verification.strategy
            == "same_path_result_contains_planned_fields_after_mutation"
        && capability.same_path_read.as_ref().is_some_and(|read| {
            read.path == GLOBAL_WARP_OVERRIDE_PATH
                && read.read_capability_id == GLOBAL_WARP_OVERRIDE_READ_CAPABILITY_ID
                && read.verified_response_fields == ["disconnect"]
        })
}

fn global_warp_override_read_contract_supported(capability: &CapabilityV1) -> bool {
    capability.id == GLOBAL_WARP_OVERRIDE_READ_CAPABILITY_ID
        && capability.method == "GET"
        && capability.path == GLOBAL_WARP_OVERRIDE_PATH
        && capability.product == "Devices Resilience"
        && capability.account_scope == "account"
        && !capability.mutating
        && capability.request_schema.is_none()
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        && capability.selectors.len() == 1
        && capability.selectors.iter().any(|selector| {
            selector.name == "account_id" && selector.location == "path" && selector.required
        })
        && capability
            .response_contract
            .as_ref()
            .is_some_and(|contract| {
                matches!(
                    contract.body_mode,
                    cfctl_core::ResponseBodyModeV1::CloudflareJsonEnvelope
                ) && contract.success_statuses == ["200"]
                    && contract.success_media_types == ["application/json"]
            })
}

fn is_d1_read_replication_mutation(capability: &CapabilityV1) -> bool {
    matches!(
        capability.id.as_str(),
        "d1-update-database" | "d1-update-partial-database"
    )
}

fn should_bind_d1_read_replication_state(capability: &CapabilityV1) -> bool {
    is_d1_read_replication_mutation(capability)
        && capability.mutating
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        && capability.rollback.strategy.as_deref() == Some("restore_d1_read_replication_prior_mode")
        && capability.rollback_contract_supported()
}

fn is_d1_database_delete(capability: &CapabilityV1) -> bool {
    capability.id == D1_DATABASE_DELETE_CAPABILITY_ID
        && capability.title == "Delete D1 Database"
        && capability.method == "DELETE"
        && capability.path == D1_READ_REPLICATION_PATH
        && capability.product == "D1"
        && capability.account_scope == "account"
        && capability.mutating
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
}

fn should_bind_d1_empty_database_state(capability: &CapabilityV1, adapter_targets: &Value) -> bool {
    is_d1_database_delete(capability)
        && adapter_targets
            .get("compensates_capability_id")
            .and_then(Value::as_str)
            == Some(D1_DATABASE_CREATE_CAPABILITY_ID)
        && adapter_targets
            .get("compensation_strategy")
            .and_then(Value::as_str)
            == Some(D1_EMPTY_DATABASE_COMPENSATION_STRATEGY)
        && adapter_targets
            .get("compensates_operation_id")
            .and_then(Value::as_str)
            .is_some_and(|operation_id| !operation_id.is_empty())
        && adapter_targets
            .get("source_receipt_hash")
            .and_then(Value::as_str)
            .is_some_and(|hash| hash.starts_with("sha256:"))
}

fn d1_read_replication_read_contract_supported(capability: &CapabilityV1) -> bool {
    capability.id == D1_READ_REPLICATION_READ_CAPABILITY_ID
        && capability.method == "GET"
        && capability.path == D1_READ_REPLICATION_PATH
        && capability.product == "D1"
        && capability.account_scope == "account"
        && !capability.mutating
        && capability.request_schema.is_none()
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        && capability.selectors.len() == 3
        && ["account_id", "database_id"].iter().all(|name| {
            capability.selectors.iter().any(|selector| {
                selector.name == *name && selector.location == "path" && selector.required
            })
        })
        && capability.selectors.iter().any(|selector| {
            selector.name == "fields"
                && selector.location == "query"
                && !selector.required
                && selector.value_type == "array"
                && selector.contract.as_ref().is_some_and(|contract| {
                    contract.schema.get("type").and_then(Value::as_str) == Some("array")
                        && contract.query.as_ref().is_some_and(|query| {
                            query.style == "form"
                                && !query.explode
                                && !query.allow_reserved
                                && !query.allow_empty_value
                        })
                })
        })
        && capability
            .response_contract
            .as_ref()
            .is_some_and(|contract| {
                matches!(
                    contract.body_mode,
                    cfctl_core::ResponseBodyModeV1::CloudflareJsonEnvelope
                ) && contract.success_statuses == ["200"]
                    && contract.success_media_types == ["application/json"]
            })
}

fn is_cloudflare_tunnel_configuration_mutation(capability: &CapabilityV1) -> bool {
    capability.id == CLOUDFLARE_TUNNEL_CONFIGURATION_MUTATION_CAPABILITY_ID
}

fn should_bind_cloudflare_tunnel_configuration_state(capability: &CapabilityV1) -> bool {
    is_cloudflare_tunnel_configuration_mutation(capability)
        && capability.mutating
        && capability.method == "PUT"
        && capability.path == CLOUDFLARE_TUNNEL_CONFIGURATION_PATH
        && capability.product == "Cloudflare Tunnel Configuration"
        && capability.account_scope == "account"
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        && capability.rollback.strategy.as_deref()
            == Some("restore_cloudflare_tunnel_configuration_prior_snapshot")
        && capability.rollback_contract_supported()
}

fn cloudflare_tunnel_configuration_read_contract_supported(capability: &CapabilityV1) -> bool {
    capability.id == CLOUDFLARE_TUNNEL_CONFIGURATION_READ_CAPABILITY_ID
        && capability.method == "GET"
        && capability.path == CLOUDFLARE_TUNNEL_CONFIGURATION_PATH
        && capability.product == "Cloudflare Tunnel Configuration"
        && capability.account_scope == "account"
        && !capability.mutating
        && capability.request_schema.is_none()
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        && capability.permissions
            == [
                "Cloudflare One Connectors Write",
                "Cloudflare One Connectors Read",
                "Cloudflare One Connector: cloudflared Write",
                "Cloudflare One Connector: cloudflared Read",
                "Cloudflare Tunnel Write",
                "Cloudflare Tunnel Read",
            ]
        && capability.selectors.len() == 2
        && ["account_id", "tunnel_id"].iter().all(|name| {
            capability.selectors.iter().any(|selector| {
                selector.name == *name && selector.location == "path" && selector.required
            })
        })
        && capability
            .response_contract
            .as_ref()
            .is_some_and(|contract| {
                matches!(
                    contract.body_mode,
                    cfctl_core::ResponseBodyModeV1::CloudflareJsonEnvelope
                ) && contract.success_statuses == ["200"]
                    && contract.success_media_types == ["application/json"]
            })
}

fn is_warp_connector_configuration_mutation(capability: &CapabilityV1) -> bool {
    capability.id == WARP_CONNECTOR_CONFIGURATION_MUTATION_CAPABILITY_ID
}

fn should_bind_warp_connector_configuration_state(capability: &CapabilityV1) -> bool {
    is_warp_connector_configuration_mutation(capability)
        && capability.mutating
        && capability.method == "PUT"
        && capability.path == WARP_CONNECTOR_CONFIGURATION_PATH
        && capability.product == "Cloudflare Tunnel Configuration"
        && capability.account_scope == "account"
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        && capability.rollback.strategy.as_deref()
            == Some("restore_warp_connector_configuration_prior_snapshot")
        && capability.rollback_contract_supported()
}

fn warp_connector_configuration_read_contract_supported(capability: &CapabilityV1) -> bool {
    capability.id == WARP_CONNECTOR_CONFIGURATION_READ_CAPABILITY_ID
        && capability.method == "GET"
        && capability.path == WARP_CONNECTOR_CONFIGURATION_PATH
        && capability.product == "Cloudflare Tunnel Configuration"
        && capability.account_scope == "account"
        && !capability.mutating
        && capability.request_schema.is_none()
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        && capability.permissions
            == [
                "Cloudflare One Connectors Write",
                "Cloudflare One Connectors Read",
                "Cloudflare One Connector: WARP Write",
                "Cloudflare One Connector: WARP Read",
            ]
        && capability.selectors.len() == 2
        && ["account_id", "tunnel_id"].iter().all(|name| {
            capability.selectors.iter().any(|selector| {
                selector.name == *name && selector.location == "path" && selector.required
            })
        })
        && capability
            .response_contract
            .as_ref()
            .is_some_and(|contract| {
                matches!(
                    contract.body_mode,
                    cfctl_core::ResponseBodyModeV1::CloudflareJsonEnvelope
                ) && contract.success_statuses == ["200"]
                    && contract.success_media_types == ["application/json"]
            })
}

fn is_web_analytics_rum_mutation(capability: &CapabilityV1) -> bool {
    capability.id == WEB_ANALYTICS_RUM_MUTATION_CAPABILITY_ID
}

fn should_bind_web_analytics_rum_state(capability: &CapabilityV1) -> bool {
    is_web_analytics_rum_mutation(capability)
        && capability.mutating
        && capability.method == "PATCH"
        && capability.path == WEB_ANALYTICS_RUM_PATH
        && capability.product == "Web Analytics"
        && capability.account_scope == "zone"
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        && capability.rollback.strategy.as_deref() == Some("restore_web_analytics_rum_prior_value")
        && capability.rollback_contract_supported()
}

fn web_analytics_rum_read_contract_supported(capability: &CapabilityV1) -> bool {
    capability.id == WEB_ANALYTICS_RUM_READ_CAPABILITY_ID
        && capability.method == "GET"
        && capability.path == WEB_ANALYTICS_RUM_PATH
        && capability.product == "Web Analytics"
        && capability.account_scope == "zone"
        && !capability.mutating
        && capability.request_schema.is_none()
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        && capability.permissions == ["Zone Settings Write", "Zone Settings Read"]
        && capability.selectors.len() == 1
        && capability.selectors.iter().any(|selector| {
            selector.name == "zone_id"
                && selector.location == "path"
                && selector.required
                && selector.value_type == "string"
        })
        && capability
            .response_contract
            .as_ref()
            .is_some_and(|contract| {
                matches!(
                    contract.body_mode,
                    cfctl_core::ResponseBodyModeV1::CloudflareJsonEnvelope
                ) && contract.success_statuses == ["200"]
                    && contract.success_media_types == ["application/json"]
            })
}

fn is_dns_record_update_mutation(capability: &CapabilityV1) -> bool {
    matches!(
        (capability.id.as_str(), capability.method.as_str()),
        ("dns-records-for-a-zone-update-dns-record", "PUT")
            | ("dns-records-for-a-zone-patch-dns-record", "PATCH")
    )
}

fn should_bind_dns_record_state(capability: &CapabilityV1) -> bool {
    is_dns_record_update_mutation(capability)
        && capability.mutating
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        && capability.rollback.strategy.as_deref()
            == Some("restore_dns_record_prior_snapshot_with_put")
        && capability.rollback_contract_supported()
        && dns_record_routing_contract_supported(capability)
}

fn dns_record_routing_contract_supported(capability: &CapabilityV1) -> bool {
    capability.path == DNS_RECORD_DETAIL_PATH
        && capability.account_scope == "zone"
        && capability.selectors.len() == 3
        && ["zone_id", "dns_record_id"].iter().all(|name| {
            capability.selectors.iter().any(|selector| {
                selector.name == *name && selector.location == "path" && selector.required
            })
        })
        && capability.selectors.iter().any(|selector| {
            selector.name == "include_shadow_metadata"
                && selector.location == "query"
                && !selector.required
                && selector.value_type == "boolean"
                && selector.contract.as_ref().is_some_and(|contract| {
                    contract.schema.get("type").and_then(Value::as_str) == Some("boolean")
                        && contract.query.as_ref().is_some_and(|query| {
                            query.style == "form"
                                && query.explode
                                && !query.allow_reserved
                                && !query.allow_empty_value
                        })
                })
        })
}

fn apply_dns_record_state_response(
    capability: &CapabilityV1,
    account_id: &str,
    zone_id: &str,
    dns_record_id: &str,
    response: &CloudflareResponseV1,
) -> Result<Value> {
    if !response.success || !(200..300).contains(&response.status) {
        return Err(CliError::Input(format!(
            "Cloudflare rejected the DNS record state read with HTTP {}; the mutation boundary was not crossed",
            response.status
        )));
    }
    if response.result.get("id").and_then(Value::as_str) != Some(dns_record_id) {
        return Err(CliError::Input(
            "DNS record state read returned a different or missing record id; the mutation boundary was not crossed"
                .to_owned(),
        ));
    }
    let prior_record = project_dns_record_snapshot(capability, &response.result)?;
    validate_request_contract(
        capability,
        &CallInput {
            selectors: json!({"zone_id":zone_id,"dns_record_id":dns_record_id}),
            query: json!({}),
            body: Some(prior_record.clone()),
            ..CallInput::default()
        },
    )?;
    Ok(json!({
        "schema_version": 1,
        "source_capability_id": DNS_RECORD_DETAIL_READ_CAPABILITY_ID,
        "source_path": DNS_RECORD_DETAIL_PATH,
        "target_capability_id": capability.id,
        "target_method": capability.method,
        "target_scope": "zone",
        "account_id": account_id,
        "zone_id": zone_id,
        "dns_record_id": dns_record_id,
        "prior_record": prior_record,
    }))
}

fn project_dns_record_snapshot(capability: &CapabilityV1, source: &Value) -> Result<Value> {
    let record_type = source
        .get("type")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "DNS record state read omitted its bounded record type; the mutation boundary was not crossed"
                    .to_owned(),
            )
        })?;
    let paths = capability
        .request_object_paths_by_discriminator("type")
        .and_then(|branches| branches.get(record_type).cloned())
        .ok_or_else(|| {
            CliError::Input(format!(
                "DNS record type `{record_type}` is outside the reviewed restoration schema; the mutation boundary was not crossed"
            ))
        })?;
    let mut snapshot = serde_json::Map::new();
    for path in &paths {
        let Some(value) = value_at_dotted_path(source, path) else {
            continue;
        };
        if value.is_null() {
            continue;
        }
        insert_dotted_object_path(&mut snapshot, path, value.clone())?;
    }
    let snapshot = Value::Object(snapshot);
    if snapshot.get("type").and_then(Value::as_str) != Some(record_type)
        || snapshot
            .get("name")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || (paths.contains(&"content".to_owned()) && snapshot.get("content").is_none())
        || (paths.iter().any(|path| path.starts_with("data."))
            && snapshot
                .get("data")
                .and_then(Value::as_object)
                .is_none_or(serde_json::Map::is_empty))
    {
        return Err(CliError::Input(
            "DNS record state read omitted fields required to reconstruct the reviewed record type; the mutation boundary was not crossed"
                .to_owned(),
        ));
    }
    Ok(snapshot)
}

fn value_at_dotted_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.')
        .try_fold(value, |current, segment| current.as_object()?.get(segment))
}

fn insert_dotted_object_path(
    object: &mut serde_json::Map<String, Value>,
    path: &str,
    value: Value,
) -> Result<()> {
    let segments = path.split('.').collect::<Vec<_>>();
    insert_object_path_segments(object, &segments, value)
}

fn insert_object_path_segments(
    object: &mut serde_json::Map<String, Value>,
    segments: &[&str],
    value: Value,
) -> Result<()> {
    let Some((segment, remaining)) = segments.split_first() else {
        return Err(CliError::Input(
            "DNS record restoration schema produced an empty writable path".to_owned(),
        ));
    };
    if remaining.is_empty() {
        object.insert((*segment).to_owned(), value);
        return Ok(());
    }
    let nested = object
        .entry((*segment).to_owned())
        .or_insert_with(|| Value::Object(serde_json::Map::new()))
        .as_object_mut()
        .ok_or_else(|| {
            CliError::Input(
                "DNS record restoration schema produced conflicting writable paths".to_owned(),
            )
        })?;
    insert_object_path_segments(nested, remaining, value)
}

fn dns_record_detail_read_contract_supported(capability: &CapabilityV1) -> bool {
    capability.id == DNS_RECORD_DETAIL_READ_CAPABILITY_ID
        && capability.method == "GET"
        && capability.path == DNS_RECORD_DETAIL_PATH
        && capability.product == "DNS Records for a Zone"
        && capability.account_scope == "zone"
        && !capability.mutating
        && capability.request_schema.is_none()
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        && dns_record_routing_contract_supported(capability)
        && capability
            .response_contract
            .as_ref()
            .is_some_and(|contract| {
                matches!(
                    contract.body_mode,
                    cfctl_core::ResponseBodyModeV1::CloudflareJsonEnvelope
                ) && contract.success_statuses == ["200"]
                    && contract.success_media_types == ["application/json"]
            })
}

async fn read_live_dns_record_state(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: &AuthCredential,
) -> Result<(Value, EvidenceV1)> {
    if !should_bind_dns_record_state(capability) {
        return Err(CliError::Input(
            "DNS record mutation drifted from its governed prior-state contract".to_owned(),
        ));
    }
    let zone_id = input
        .selectors
        .get("zone_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input("DNS state precondition requires string selector `zone_id`".to_owned())
        })?;
    let dns_record_id = input
        .selectors
        .get("dns_record_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "DNS state precondition requires string selector `dns_record_id`".to_owned(),
            )
        })?;
    let source_capability = catalog
        .get(DNS_RECORD_DETAIL_READ_CAPABILITY_ID)
        .ok_or_else(|| capability_missing(DNS_RECORD_DETAIL_READ_CAPABILITY_ID))?;
    if !dns_record_detail_read_contract_supported(source_capability) {
        return Err(CliError::Input(
            "DNS state source capability drifted from the governed record detail read".to_owned(),
        ));
    }
    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let response = executor
        .execute_read(
            source_capability,
            &CallInput {
                selectors: json!({"zone_id":zone_id,"dns_record_id":dns_record_id}),
                query: json!({}),
                body: None,
                ..CallInput::default()
            },
            credential,
        )
        .await?;
    let receipt =
        apply_dns_record_state_response(capability, account_id, zone_id, dns_record_id, &response)?;
    let evidence = store.write_evidence(EvidenceClass::LiveRead, &receipt)?;
    Ok((receipt, evidence))
}

fn apply_d1_read_replication_state_response(
    capability: &CapabilityV1,
    account_id: &str,
    database_id: &str,
    response: &CloudflareResponseV1,
) -> Result<Value> {
    if !response.success || !(200..300).contains(&response.status) {
        return Err(CliError::Input(format!(
            "Cloudflare rejected the D1 read-replication state read with HTTP {}; the mutation boundary was not crossed",
            response.status
        )));
    }
    let mode = response
        .result
        .pointer("/read_replication/mode")
        .and_then(Value::as_str)
        .filter(|mode| matches!(*mode, "auto" | "disabled"))
        .ok_or_else(|| {
            CliError::Input(
                "D1 state read omitted the bounded read_replication.mode value; the mutation boundary was not crossed"
                    .to_owned(),
            )
        })?;
    Ok(json!({
        "schema_version": 1,
        "source_capability_id": D1_READ_REPLICATION_READ_CAPABILITY_ID,
        "source_path": D1_READ_REPLICATION_PATH,
        "target_capability_id": capability.id,
        "target_method": capability.method,
        "target_scope": "account",
        "account_id": account_id,
        "database_id": database_id,
        "read_replication": {"mode": mode},
    }))
}

async fn read_live_d1_read_replication_state(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: &AuthCredential,
) -> Result<(Value, EvidenceV1)> {
    if !should_bind_d1_read_replication_state(capability) {
        return Err(CliError::Input(
            "D1 read-replication mutation drifted from its governed prior-state contract"
                .to_owned(),
        ));
    }
    let selected_account = input
        .selectors
        .get("account_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "D1 state precondition requires string selector `account_id`".to_owned(),
            )
        })?;
    if selected_account != account_id {
        return Err(CliError::Input(format!(
            "D1 target account `{selected_account}` differs from selected account `{account_id}`; the mutation boundary was not crossed"
        )));
    }
    let database_id = input
        .selectors
        .get("database_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "D1 state precondition requires string selector `database_id`".to_owned(),
            )
        })?;
    let source_capability = catalog
        .get(D1_READ_REPLICATION_READ_CAPABILITY_ID)
        .ok_or_else(|| capability_missing(D1_READ_REPLICATION_READ_CAPABILITY_ID))?;
    if !d1_read_replication_read_contract_supported(source_capability) {
        return Err(CliError::Input(
            "D1 state source capability drifted from the governed database read".to_owned(),
        ));
    }
    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let response = executor
        .execute_read(
            source_capability,
            &CallInput {
                selectors: json!({"account_id": account_id, "database_id": database_id}),
                query: json!({}),
                body: None,
                ..CallInput::default()
            },
            credential,
        )
        .await?;
    let receipt =
        apply_d1_read_replication_state_response(capability, account_id, database_id, &response)?;
    let evidence = store.write_evidence(EvidenceClass::LiveRead, &receipt)?;
    Ok((receipt, evidence))
}

fn apply_d1_empty_database_state_response(
    capability: &CapabilityV1,
    adapter_targets: &Value,
    account_id: &str,
    database_id: &str,
    response: &CloudflareResponseV1,
) -> Result<Value> {
    if !response.success || !(200..300).contains(&response.status) {
        return Err(CliError::Input(format!(
            "Cloudflare rejected the D1 empty-state read with HTTP {}; the compensation plan was not created",
            response.status
        )));
    }
    let uuid = response
        .result
        .get("uuid")
        .and_then(Value::as_str)
        .filter(|uuid| *uuid == database_id)
        .ok_or_else(|| {
            CliError::Input(
                "D1 empty-state read did not return the exact created database UUID; the compensation plan was not created"
                    .to_owned(),
            )
        })?;
    let name = response
        .result
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "D1 empty-state read omitted the database name; the compensation plan was not created"
                    .to_owned(),
            )
        })?;
    let num_tables = response
        .result
        .get("num_tables")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            CliError::Input(
                "D1 empty-state read omitted an integer num_tables value; the compensation plan was not created"
                    .to_owned(),
            )
        })?;
    if num_tables != 0 {
        return Err(CliError::Input(format!(
            "D1 database `{database_id}` now contains {num_tables} table(s); cfctl will not derive a destructive compensation plan"
        )));
    }
    let file_size = response
        .result
        .get("file_size")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            CliError::Input(
                "D1 empty-state read omitted an integer file_size value; the compensation plan was not created"
                    .to_owned(),
            )
        })?;
    let jurisdiction = response
        .result
        .get("jurisdiction")
        .filter(|value| value.is_null() || value.is_string())
        .cloned()
        .ok_or_else(|| {
            CliError::Input(
                "D1 empty-state read omitted its nullable jurisdiction; the compensation plan was not created"
                    .to_owned(),
            )
        })?;
    let replication_mode = response
        .result
        .pointer("/read_replication/mode")
        .and_then(Value::as_str)
        .filter(|mode| matches!(*mode, "auto" | "disabled"))
        .ok_or_else(|| {
            CliError::Input(
                "D1 empty-state read omitted the bounded read-replication mode; the compensation plan was not created"
                    .to_owned(),
            )
        })?;
    let (source_operation_id, source_receipt_hash) =
        d1_compensation_source_binding(adapter_targets)?;
    Ok(json!({
        "schema_version": 1,
        "source_capability_id": D1_READ_REPLICATION_READ_CAPABILITY_ID,
        "source_path": D1_READ_REPLICATION_PATH,
        "target_capability_id": capability.id,
        "target_method": capability.method,
        "target_path": capability.path,
        "target_scope": "account",
        "account_id": account_id,
        "database_id": uuid,
        "database_name": name,
        "num_tables": num_tables,
        "file_size": file_size,
        "jurisdiction": jurisdiction,
        "read_replication": {"mode": replication_mode},
        "compensates_operation_id": source_operation_id,
        "source_create_receipt_hash": source_receipt_hash,
    }))
}

fn d1_compensation_source_binding(adapter_targets: &Value) -> Result<(&str, &str)> {
    let source_operation_id = adapter_targets
        .get("compensates_operation_id")
        .and_then(Value::as_str)
        .filter(|operation_id| !operation_id.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "D1 compensation target omitted its source operation ID; the compensation plan was not created"
                    .to_owned(),
            )
        })?;
    let source_receipt_hash = adapter_targets
        .get("source_receipt_hash")
        .and_then(Value::as_str)
        .filter(|hash| hash.starts_with("sha256:"))
        .ok_or_else(|| {
            CliError::Input(
                "D1 compensation target omitted its source create receipt hash; the compensation plan was not created"
                    .to_owned(),
            )
        })?;
    Ok((source_operation_id, source_receipt_hash))
}

async fn read_live_d1_empty_database_state(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    adapter_targets: &Value,
    account_id: &str,
    credential: &AuthCredential,
) -> Result<(Value, EvidenceV1)> {
    if !should_bind_d1_empty_database_state(capability, adapter_targets) {
        return Err(CliError::Input(
            "D1 compensation drifted from its governed empty-database contract".to_owned(),
        ));
    }
    let selected_account = input
        .selectors
        .get("account_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "D1 empty-state precondition requires string selector `account_id`".to_owned(),
            )
        })?;
    if selected_account != account_id {
        return Err(CliError::Input(format!(
            "D1 compensation account `{selected_account}` differs from selected account `{account_id}`; the compensation plan was not created"
        )));
    }
    let database_id = input
        .selectors
        .get("database_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "D1 empty-state precondition requires string selector `database_id`".to_owned(),
            )
        })?;
    let source_capability = catalog
        .get(D1_READ_REPLICATION_READ_CAPABILITY_ID)
        .ok_or_else(|| capability_missing(D1_READ_REPLICATION_READ_CAPABILITY_ID))?;
    if !d1_read_replication_read_contract_supported(source_capability) {
        return Err(CliError::Input(
            "D1 empty-state source capability drifted from the governed database read".to_owned(),
        ));
    }
    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let response = executor
        .execute_read(
            source_capability,
            &CallInput {
                selectors: json!({"account_id": account_id, "database_id": database_id}),
                query: json!({"fields":[
                    "uuid", "name", "jurisdiction", "num_tables", "file_size", "read_replication"
                ]}),
                body: None,
                ..CallInput::default()
            },
            credential,
        )
        .await?;
    let receipt = apply_d1_empty_database_state_response(
        capability,
        adapter_targets,
        account_id,
        database_id,
        &response,
    )?;
    let evidence = store.write_evidence(EvidenceClass::LiveRead, &receipt)?;
    Ok((receipt, evidence))
}

fn apply_cloudflare_tunnel_configuration_state_response(
    capability: &CapabilityV1,
    account_id: &str,
    tunnel_id: &str,
    response: &CloudflareResponseV1,
) -> Result<Value> {
    if !response.success || !(200..300).contains(&response.status) {
        return Err(CliError::Input(format!(
            "Cloudflare rejected the Tunnel configuration state read with HTTP {}; the mutation boundary was not crossed",
            response.status
        )));
    }
    let prior_config = response
        .result
        .get("config")
        .filter(|config| config.is_object())
        .cloned()
        .ok_or_else(|| {
            CliError::Input(
                "Tunnel configuration state read omitted an object `config`; initial configuration creation has no restorable prior snapshot and the mutation boundary was not crossed"
                    .to_owned(),
            )
        })?;
    let restore_input = CallInput {
        selectors: json!({"account_id": account_id, "tunnel_id": tunnel_id}),
        body: Some(json!({"config": prior_config})),
        ..CallInput::default()
    };
    preflight_call_input(capability, &restore_input, None).map_err(|error| {
        CliError::Input(format!(
            "live Tunnel configuration is outside cfctl's exact restorable request contract; the mutation boundary was not crossed: {error}"
        ))
    })?;
    let prior_config = restore_input
        .body
        .as_ref()
        .and_then(|body| body.get("config"))
        .cloned()
        .ok_or_else(|| {
            CliError::Input(
                "validated Tunnel configuration restore body omitted `config`; the mutation boundary was not crossed"
                    .to_owned(),
            )
        })?;
    Ok(json!({
        "schema_version": 1,
        "source_capability_id": CLOUDFLARE_TUNNEL_CONFIGURATION_READ_CAPABILITY_ID,
        "source_path": CLOUDFLARE_TUNNEL_CONFIGURATION_PATH,
        "target_capability_id": capability.id,
        "target_method": capability.method,
        "target_path": capability.path,
        "target_scope": "account",
        "account_id": account_id,
        "tunnel_id": tunnel_id,
        "prior_config": prior_config,
    }))
}

async fn read_live_cloudflare_tunnel_configuration_state(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: &AuthCredential,
) -> Result<(Value, EvidenceV1)> {
    if !should_bind_cloudflare_tunnel_configuration_state(capability) {
        return Err(CliError::Input(
            "Tunnel configuration mutation drifted from its governed prior-state contract"
                .to_owned(),
        ));
    }
    let selected_account = input
        .selectors
        .get("account_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "Tunnel configuration state precondition requires string selector `account_id`"
                    .to_owned(),
            )
        })?;
    if selected_account != account_id {
        return Err(CliError::Input(format!(
            "Tunnel configuration target account `{selected_account}` differs from selected account `{account_id}`; the mutation boundary was not crossed"
        )));
    }
    let tunnel_id = input
        .selectors
        .get("tunnel_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "Tunnel configuration state precondition requires string selector `tunnel_id`"
                    .to_owned(),
            )
        })?;
    let source_capability = catalog
        .get(CLOUDFLARE_TUNNEL_CONFIGURATION_READ_CAPABILITY_ID)
        .ok_or_else(|| capability_missing(CLOUDFLARE_TUNNEL_CONFIGURATION_READ_CAPABILITY_ID))?;
    if !cloudflare_tunnel_configuration_read_contract_supported(source_capability) {
        return Err(CliError::Input(
            "Tunnel configuration state source capability drifted from the governed same-path read"
                .to_owned(),
        ));
    }
    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let response = executor
        .execute_read(
            source_capability,
            &CallInput {
                selectors: json!({"account_id": account_id, "tunnel_id": tunnel_id}),
                ..CallInput::default()
            },
            credential,
        )
        .await?;
    let receipt = apply_cloudflare_tunnel_configuration_state_response(
        capability, account_id, tunnel_id, &response,
    )?;
    let evidence = store.write_evidence(EvidenceClass::LiveRead, &receipt)?;
    Ok((receipt, evidence))
}

fn warp_connector_configuration_restore_body(ha_mode: &str, config: Option<&Value>) -> Value {
    let mut body = Map::from_iter([("ha_mode".to_owned(), Value::String(ha_mode.to_owned()))]);
    if matches!(ha_mode, "aws" | "local")
        && let Some(config) = config.filter(|value| !value.is_null())
    {
        body.insert("config".to_owned(), config.clone());
    }
    Value::Object(body)
}

fn apply_warp_connector_configuration_state_response(
    capability: &CapabilityV1,
    account_id: &str,
    tunnel_id: &str,
    response: &CloudflareResponseV1,
) -> Result<Value> {
    if !response.success || !(200..300).contains(&response.status) {
        return Err(CliError::Input(format!(
            "Cloudflare rejected the WARP Connector configuration state read with HTTP {}; the mutation boundary was not crossed",
            response.status
        )));
    }
    let prior_ha_mode = response
        .result
        .get("ha_mode")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "WARP Connector configuration state read omitted string `ha_mode`; the mutation boundary was not crossed"
                    .to_owned(),
            )
        })?;
    let prior_config = response
        .result
        .get("config")
        .cloned()
        .unwrap_or(Value::Null);
    let observed_state_input = CallInput {
        selectors: json!({"account_id": account_id, "tunnel_id": tunnel_id}),
        body: Some(json!({
            "ha_mode": prior_ha_mode,
            "config": prior_config,
        })),
        ..CallInput::default()
    };
    preflight_call_input(capability, &observed_state_input, None).map_err(|error| {
        CliError::Input(format!(
            "live WARP Connector configuration is outside cfctl's exact restorable HA contract; the mutation boundary was not crossed: {error}"
        ))
    })?;
    Ok(json!({
        "schema_version": 1,
        "source_capability_id": WARP_CONNECTOR_CONFIGURATION_READ_CAPABILITY_ID,
        "source_path": WARP_CONNECTOR_CONFIGURATION_PATH,
        "target_capability_id": capability.id,
        "target_method": capability.method,
        "target_path": capability.path,
        "target_scope": "account",
        "account_id": account_id,
        "tunnel_id": tunnel_id,
        "prior_ha_mode": prior_ha_mode,
        "prior_config": prior_config,
    }))
}

async fn read_live_warp_connector_configuration_state(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: &AuthCredential,
) -> Result<(Value, EvidenceV1)> {
    if !should_bind_warp_connector_configuration_state(capability) {
        return Err(CliError::Input(
            "WARP Connector configuration mutation drifted from its governed prior-state contract"
                .to_owned(),
        ));
    }
    let selected_account = input
        .selectors
        .get("account_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "WARP Connector state precondition requires string selector `account_id`"
                    .to_owned(),
            )
        })?;
    if selected_account != account_id {
        return Err(CliError::Input(format!(
            "WARP Connector target account `{selected_account}` differs from selected account `{account_id}`; the mutation boundary was not crossed"
        )));
    }
    let tunnel_id = input
        .selectors
        .get("tunnel_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "WARP Connector state precondition requires string selector `tunnel_id`".to_owned(),
            )
        })?;
    let source_capability = catalog
        .get(WARP_CONNECTOR_CONFIGURATION_READ_CAPABILITY_ID)
        .ok_or_else(|| capability_missing(WARP_CONNECTOR_CONFIGURATION_READ_CAPABILITY_ID))?;
    if !warp_connector_configuration_read_contract_supported(source_capability) {
        return Err(CliError::Input(
            "WARP Connector state source capability drifted from the governed same-path read"
                .to_owned(),
        ));
    }
    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let response = executor
        .execute_read(
            source_capability,
            &CallInput {
                selectors: json!({"account_id": account_id, "tunnel_id": tunnel_id}),
                ..CallInput::default()
            },
            credential,
        )
        .await?;
    let receipt = apply_warp_connector_configuration_state_response(
        capability, account_id, tunnel_id, &response,
    )?;
    let evidence = store.write_evidence(EvidenceClass::LiveRead, &receipt)?;
    Ok((receipt, evidence))
}

fn apply_web_analytics_rum_state_response(
    capability: &CapabilityV1,
    account_id: &str,
    zone_id: &str,
    response: &CloudflareResponseV1,
) -> Result<Value> {
    if !response.success || !(200..300).contains(&response.status) {
        return Err(CliError::Input(format!(
            "Cloudflare rejected the Web Analytics RUM state read with HTTP {}; the mutation boundary was not crossed",
            response.status
        )));
    }
    if response.result.get("id").and_then(Value::as_str) != Some("rum") {
        return Err(CliError::Input(
            "Web Analytics RUM state read did not identify setting `rum`; the mutation boundary was not crossed"
                .to_owned(),
        ));
    }
    if response.result.get("editable").and_then(Value::as_bool) != Some(true) {
        return Err(CliError::Input(
            "Web Analytics RUM state is not explicitly editable; the mutation boundary was not crossed"
                .to_owned(),
        ));
    }
    let prior_value = response
        .result
        .get("value")
        .and_then(Value::as_str)
        .filter(|value| matches!(*value, "on" | "off"))
        .ok_or_else(|| {
            CliError::Input(
                "Web Analytics RUM state is not an exactly restorable `on` or `off` value; `manual` and unknown states require operator inspection"
                    .to_owned(),
            )
        })?;
    Ok(json!({
        "schema_version": 1,
        "source_capability_id": WEB_ANALYTICS_RUM_READ_CAPABILITY_ID,
        "source_path": WEB_ANALYTICS_RUM_PATH,
        "target_capability_id": capability.id,
        "target_method": capability.method,
        "target_path": capability.path,
        "target_scope": "zone",
        "account_id": account_id,
        "zone_id": zone_id,
        "setting_id": "rum",
        "editable": true,
        "prior_value": prior_value,
    }))
}

async fn read_live_web_analytics_rum_state(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: &AuthCredential,
) -> Result<(Value, EvidenceV1)> {
    if !should_bind_web_analytics_rum_state(capability) {
        return Err(CliError::Input(
            "Web Analytics RUM mutation drifted from its governed prior-state contract".to_owned(),
        ));
    }
    let zone_id = input
        .selectors
        .get("zone_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "Web Analytics RUM state precondition requires string selector `zone_id`"
                    .to_owned(),
            )
        })?;
    let source_capability = catalog
        .get(WEB_ANALYTICS_RUM_READ_CAPABILITY_ID)
        .ok_or_else(|| capability_missing(WEB_ANALYTICS_RUM_READ_CAPABILITY_ID))?;
    if !web_analytics_rum_read_contract_supported(source_capability) {
        return Err(CliError::Input(
            "Web Analytics RUM state source capability drifted from the governed same-path read"
                .to_owned(),
        ));
    }
    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let response = executor
        .execute_read(
            source_capability,
            &CallInput {
                selectors: json!({"zone_id": zone_id}),
                ..CallInput::default()
            },
            credential,
        )
        .await?;
    let receipt =
        apply_web_analytics_rum_state_response(capability, account_id, zone_id, &response)?;
    let evidence = store.write_evidence(EvidenceClass::LiveRead, &receipt)?;
    Ok((receipt, evidence))
}

fn apply_global_warp_override_state_response(
    account_id: &str,
    response: &CloudflareResponseV1,
) -> Result<Value> {
    if !response.success || !(200..300).contains(&response.status) {
        return Err(CliError::Input(format!(
            "Cloudflare rejected the Global WARP override state read with HTTP {}; the mutation boundary was not crossed",
            response.status
        )));
    }
    let disconnect = response
        .result
        .get("disconnect")
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            CliError::Input(
                "Global WARP override state read omitted boolean `disconnect`; the mutation boundary was not crossed"
                    .to_owned(),
            )
        })?;
    Ok(json!({
        "schema_version": 1,
        "source_capability_id": GLOBAL_WARP_OVERRIDE_READ_CAPABILITY_ID,
        "source_path": GLOBAL_WARP_OVERRIDE_PATH,
        "target_capability_id": GLOBAL_WARP_OVERRIDE_MUTATION_CAPABILITY_ID,
        "target_scope": "account",
        "target_id": account_id,
        "disconnect": disconnect,
    }))
}

async fn read_live_global_warp_override_state(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: &AuthCredential,
) -> Result<(Value, EvidenceV1)> {
    if !should_bind_global_warp_override_state(capability) {
        return Err(CliError::Input(
            "Global WARP override mutation drifted from its governed prior-state contract"
                .to_owned(),
        ));
    }
    let selected_account = input
        .selectors
        .get("account_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "Global WARP override state precondition requires string selector `account_id`"
                    .to_owned(),
            )
        })?;
    if selected_account != account_id {
        return Err(CliError::Input(format!(
            "Global WARP override target account `{selected_account}` differs from selected account `{account_id}`; the mutation boundary was not crossed"
        )));
    }
    let source_capability = catalog
        .get(GLOBAL_WARP_OVERRIDE_READ_CAPABILITY_ID)
        .ok_or_else(|| capability_missing(GLOBAL_WARP_OVERRIDE_READ_CAPABILITY_ID))?;
    if !global_warp_override_read_contract_supported(source_capability) {
        return Err(CliError::Input(
            "Global WARP override state source capability drifted from the governed account read"
                .to_owned(),
        ));
    }
    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let response = executor
        .execute_read(
            source_capability,
            &CallInput {
                selectors: json!({"account_id": account_id}),
                query: json!({}),
                body: None,
                ..CallInput::default()
            },
            credential,
        )
        .await?;
    let receipt = apply_global_warp_override_state_response(account_id, &response)?;
    let evidence = store.write_evidence(EvidenceClass::LiveRead, &receipt)?;
    Ok((receipt, evidence))
}

fn should_resolve_zone_entitlement(capability: &CapabilityV1) -> bool {
    let dynamic_contract = capability.adapter_status == AdapterStatus::DynamicApi
        || (capability.adapter_status == AdapterStatus::Blocked
            && capability
                .blocked_reason
                .as_deref()
                .is_some_and(|reason| reason.starts_with("operation contract incomplete:")));
    dynamic_contract
        && capability.account_scope == "zone"
        && capability.entitlement.requires_live_resolution
        && capability.mutation_contract_gaps() == [ENTITLEMENT_UNRESOLVED_GAP]
}

fn should_bind_zone_account(capability: &CapabilityV1) -> bool {
    capability.mutating
        && capability.account_scope == "zone"
        && (matches!(
            capability.adapter_status,
            AdapterStatus::Native
                | AdapterStatus::DynamicApi
                | AdapterStatus::DelegatedCli
                | AdapterStatus::GovernedUi
        ) || should_resolve_zone_entitlement(capability))
}

fn zone_target(capability: &CapabilityV1, input: &CallInput) -> Result<String> {
    let zone_selectors = capability
        .path
        .split('/')
        .filter_map(|segment| {
            segment
                .strip_prefix('{')
                .and_then(|value| value.strip_suffix('}'))
        })
        .filter(|selector| selector.to_ascii_lowercase().contains("zone"))
        .collect::<Vec<_>>();
    let [selector] = zone_selectors.as_slice() else {
        return Err(CliError::Input(format!(
            "live zone preconditions require exactly one zone selector in capability `{}`",
            capability.id
        )));
    };
    input
        .selectors
        .get(*selector)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            CliError::Input(format!(
                "live zone preconditions require string selector `{selector}`"
            ))
        })
}

fn canonical_zone_plan(plan: &str) -> Option<&'static str> {
    match plan {
        "free" | "partners_free" => Some("free"),
        "pro" | "partners_pro" => Some("pro"),
        "business" | "partners_business" => Some("business"),
        "enterprise" | "partners_enterprise" => Some("enterprise"),
        _ => None,
    }
}

fn apply_zone_entitlement_response(
    capability: &mut CapabilityV1,
    zone_id: &str,
    response: &CloudflareResponseV1,
) -> Result<Value> {
    if !response.success || !(200..300).contains(&response.status) {
        return Err(CliError::Input(format!(
            "Cloudflare rejected the zone subscription entitlement read with HTTP {}; the mutation boundary was not crossed",
            response.status
        )));
    }
    let state = response
        .result
        .get("state")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "zone subscription entitlement read omitted the subscription state".to_owned(),
            )
        })?;
    if !matches!(state, "Trial" | "Provisioned" | "Paid") {
        return Err(CliError::Input(format!(
            "zone subscription state `{state}` is not active; the mutation boundary was not crossed"
        )));
    }
    let observed_plan = response
        .result
        .pointer("/rate_plan/id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "zone subscription entitlement read omitted the rate-plan ID".to_owned(),
            )
        })?;
    let canonical_plan = canonical_zone_plan(observed_plan).ok_or_else(|| {
        CliError::Input(format!(
            "zone rate plan `{observed_plan}` cannot be mapped to the official free/pro/business/enterprise availability matrix"
        ))
    })?;
    let available = capability
        .entitlement
        .plans
        .get(canonical_plan)
        .copied()
        .ok_or_else(|| {
            CliError::Input(format!(
                "capability `{}` has no `{canonical_plan}` entry in its official plan-availability matrix",
                capability.id
            ))
        })?;
    let plan_matrix_hash = hash_value(&serde_json::to_value(&capability.entitlement.plans)?)?;
    capability.entitlement.available = Some(available);
    capability.entitlement.observed_plan = Some(observed_plan.to_owned());
    capability.entitlement.source = Some(
        "live Cloudflare GET /zones/{zone_id}/subscription evaluated against official OpenAPI x-cfPlanAvailability"
            .to_owned(),
    );
    capability.entitlement.blocker = (!available).then(|| {
        format!(
            "live zone plan `{observed_plan}` does not permit capability `{}`",
            capability.id
        )
    });
    refresh_dynamic_mutation_contract(capability);
    Ok(json!({
        "schema_version": 1,
        "source_capability_id": ZONE_SUBSCRIPTION_CAPABILITY_ID,
        "source_path": "/zones/{zone_id}/subscription",
        "target_scope": "zone",
        "target_id": zone_id,
        "observed_plan": observed_plan,
        "canonical_plan": canonical_plan,
        "subscription_state": state,
        "available": available,
        "plan_matrix_hash": plan_matrix_hash,
    }))
}

async fn read_live_zone_entitlement(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &mut CapabilityV1,
    input: &CallInput,
    credential: &AuthCredential,
) -> Result<(Value, EvidenceV1)> {
    let source_capability = catalog
        .get(ZONE_SUBSCRIPTION_CAPABILITY_ID)
        .ok_or_else(|| capability_missing(ZONE_SUBSCRIPTION_CAPABILITY_ID))?;
    if source_capability.method != "GET"
        || source_capability.path != "/zones/{zone_id}/subscription"
        || source_capability.mutating
        || !matches!(
            source_capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
    {
        return Err(CliError::Input(
            "zone entitlement source capability drifted from the governed subscription read"
                .to_owned(),
        ));
    }
    let zone_id = zone_target(capability, input)?;
    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let response = executor
        .execute_read(
            source_capability,
            &CallInput {
                selectors: json!({"zone_id": zone_id}),
                query: json!({}),
                body: None,
                ..CallInput::default()
            },
            credential,
        )
        .await?;
    let receipt = apply_zone_entitlement_response(capability, &zone_id, &response)?;
    let evidence = store.write_evidence(EvidenceClass::LiveRead, &receipt)?;
    Ok((receipt, evidence))
}

fn apply_zone_account_response(
    zone_id: &str,
    expected_account_id: &str,
    response: &CloudflareResponseV1,
) -> Result<Value> {
    if !response.success || !(200..300).contains(&response.status) {
        return Err(CliError::Input(format!(
            "Cloudflare rejected the zone-account ownership read with HTTP {}; the mutation boundary was not crossed",
            response.status
        )));
    }
    let observed_zone_id = response
        .result
        .get("id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input("zone-account ownership read omitted the zone ID".to_owned())
        })?;
    if observed_zone_id != zone_id {
        return Err(CliError::Input(format!(
            "zone-account ownership read for `{zone_id}` returned zone `{observed_zone_id}`; the mutation boundary was not crossed"
        )));
    }
    let observed_account_id = response
        .result
        .pointer("/account/id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input("zone-account ownership read omitted the account ID".to_owned())
        })?;
    if observed_account_id != expected_account_id {
        return Err(CliError::Input(format!(
            "zone `{zone_id}` belongs to account `{observed_account_id}`, not selected account `{expected_account_id}`; the mutation boundary was not crossed"
        )));
    }
    Ok(json!({
        "schema_version": 1,
        "source_capability_id": ZONE_DETAILS_CAPABILITY_ID,
        "source_path": "/zones/{zone_id}",
        "target_scope": "zone",
        "target_id": zone_id,
        "expected_account_id": expected_account_id,
        "observed_account_id": observed_account_id,
        "account_matches": true,
    }))
}

async fn read_live_zone_account(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: &AuthCredential,
) -> Result<(Value, EvidenceV1)> {
    let source_capability = catalog
        .get(ZONE_DETAILS_CAPABILITY_ID)
        .ok_or_else(|| capability_missing(ZONE_DETAILS_CAPABILITY_ID))?;
    if source_capability.method != "GET"
        || source_capability.path != "/zones/{zone_id}"
        || source_capability.mutating
        || !matches!(
            source_capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
    {
        return Err(CliError::Input(
            "zone-account source capability drifted from the governed zone-details read".to_owned(),
        ));
    }
    let zone_id = zone_target(capability, input)?;
    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let response = executor
        .execute_read(
            source_capability,
            &CallInput {
                selectors: json!({"zone_id": zone_id}),
                query: json!({}),
                body: None,
                ..CallInput::default()
            },
            credential,
        )
        .await?;
    let receipt = apply_zone_account_response(&zone_id, account_id, &response)?;
    let evidence = store.write_evidence(EvidenceClass::LiveRead, &receipt)?;
    Ok((receipt, evidence))
}

fn plan_requires_live_credential(capability: &CapabilityV1, adapter_targets: &Value) -> bool {
    should_resolve_zone_entitlement(capability)
        || should_bind_zone_account(capability)
        || should_bind_global_warp_override_state(capability)
        || should_bind_d1_read_replication_state(capability)
        || should_bind_d1_empty_database_state(capability, adapter_targets)
        || should_bind_cloudflare_tunnel_configuration_state(capability)
        || should_bind_warp_connector_configuration_state(capability)
        || should_bind_web_analytics_rum_state(capability)
        || should_bind_dns_record_state(capability)
        || should_bind_oauth_client_secret_state(capability)
}

async fn create_plan(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    mut capability: cfctl_core::CapabilityV1,
    input: CallInput,
    requested_profile: Option<&str>,
    requested_account: Option<&str>,
    adapter_targets: Value,
) -> Result<ResultEnvelopeV2> {
    let profiles = ProfilesConfig::load(store)?;
    let profile = profiles.selected(requested_profile)?;
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
    let resolve_entitlement = should_resolve_zone_entitlement(&capability);
    let credential = if plan_requires_live_credential(&capability, &adapter_targets) {
        Some(fresh_credential(profile, &platform_secrets(store)).await?)
    } else {
        None
    };
    let entitlement_precondition = if resolve_entitlement {
        let credential = credential.as_ref().ok_or_else(|| {
            CliError::Input("live zone precondition credential was not resolved".to_owned())
        })?;
        Some(read_live_zone_entitlement(store, catalog, &mut capability, &input, credential).await?)
    } else {
        None
    };
    if capability.entitlement.available == Some(false) {
        return Err(CliError::Input(
            capability.entitlement.blocker.clone().unwrap_or_else(|| {
                "the selected zone subscription does not permit this capability".to_owned()
            }),
        ));
    }
    let zone_account_precondition = if should_bind_zone_account(&capability) {
        let credential = credential.as_ref().ok_or_else(|| {
            CliError::Input("live zone precondition credential was not resolved".to_owned())
        })?;
        Some(
            read_live_zone_account(store, catalog, &capability, &input, account_id, credential)
                .await?,
        )
    } else {
        None
    };
    let mut live_preconditions = prepare_live_plan_preconditions(
        store,
        catalog,
        &capability,
        &input,
        &adapter_targets,
        account_id,
        credential.as_ref(),
    )
    .await?;
    live_preconditions.entitlement = entitlement_precondition;
    live_preconditions.zone_account = zone_account_precondition;
    persist_prepared_plan(
        store,
        catalog,
        capability,
        input,
        PlanAuthority {
            profile,
            account_id,
        },
        adapter_targets,
        live_preconditions,
    )
}

async fn prepare_global_warp_override_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: Option<&AuthCredential>,
) -> Result<Option<(Value, EvidenceV1)>> {
    if !should_bind_global_warp_override_state(capability) {
        return Ok(None);
    }
    let credential = credential.ok_or_else(|| {
        CliError::Input(
            "Global WARP override state precondition credential was not resolved".to_owned(),
        )
    })?;
    read_live_global_warp_override_state(store, catalog, capability, input, account_id, credential)
        .await
        .map(Some)
}

async fn prepare_d1_read_replication_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: Option<&AuthCredential>,
) -> Result<Option<(Value, EvidenceV1)>> {
    if !should_bind_d1_read_replication_state(capability) {
        return Ok(None);
    }
    let credential = credential.ok_or_else(|| {
        CliError::Input(
            "D1 read-replication state precondition credential was not resolved".to_owned(),
        )
    })?;
    read_live_d1_read_replication_state(store, catalog, capability, input, account_id, credential)
        .await
        .map(Some)
}

async fn prepare_d1_empty_database_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    adapter_targets: &Value,
    account_id: &str,
    credential: Option<&AuthCredential>,
) -> Result<Option<(Value, EvidenceV1)>> {
    if !should_bind_d1_empty_database_state(capability, adapter_targets) {
        return Ok(None);
    }
    let credential = credential.ok_or_else(|| {
        CliError::Input("D1 empty-state precondition credential was not resolved".to_owned())
    })?;
    read_live_d1_empty_database_state(
        store,
        catalog,
        capability,
        input,
        adapter_targets,
        account_id,
        credential,
    )
    .await
    .map(Some)
}

async fn prepare_cloudflare_tunnel_configuration_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: Option<&AuthCredential>,
) -> Result<Option<(Value, EvidenceV1)>> {
    if !should_bind_cloudflare_tunnel_configuration_state(capability) {
        return Ok(None);
    }
    let credential = credential.ok_or_else(|| {
        CliError::Input(
            "Tunnel configuration state precondition credential was not resolved".to_owned(),
        )
    })?;
    read_live_cloudflare_tunnel_configuration_state(
        store, catalog, capability, input, account_id, credential,
    )
    .await
    .map(Some)
}

async fn prepare_warp_connector_configuration_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: Option<&AuthCredential>,
) -> Result<Option<(Value, EvidenceV1)>> {
    if !should_bind_warp_connector_configuration_state(capability) {
        return Ok(None);
    }
    let credential = credential.ok_or_else(|| {
        CliError::Input(
            "WARP Connector configuration state precondition credential was not resolved"
                .to_owned(),
        )
    })?;
    read_live_warp_connector_configuration_state(
        store, catalog, capability, input, account_id, credential,
    )
    .await
    .map(Some)
}

async fn prepare_web_analytics_rum_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: Option<&AuthCredential>,
) -> Result<Option<(Value, EvidenceV1)>> {
    if !should_bind_web_analytics_rum_state(capability) {
        return Ok(None);
    }
    let credential = credential.ok_or_else(|| {
        CliError::Input(
            "Web Analytics RUM state precondition credential was not resolved".to_owned(),
        )
    })?;
    read_live_web_analytics_rum_state(store, catalog, capability, input, account_id, credential)
        .await
        .map(Some)
}

async fn prepare_dns_record_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: Option<&AuthCredential>,
) -> Result<Option<(Value, EvidenceV1)>> {
    if !should_bind_dns_record_state(capability) {
        return Ok(None);
    }
    let credential = credential.ok_or_else(|| {
        CliError::Input("DNS record state precondition credential was not resolved".to_owned())
    })?;
    read_live_dns_record_state(store, catalog, capability, input, account_id, credential)
        .await
        .map(Some)
}

async fn prepare_oauth_client_secret_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: Option<&AuthCredential>,
) -> Result<Option<(Value, EvidenceV1)>> {
    if !should_bind_oauth_client_secret_state(capability) {
        return Ok(None);
    }
    let credential = credential.ok_or_else(|| {
        CliError::Input("OAuth client state precondition credential was not resolved".to_owned())
    })?;
    read_live_oauth_client_secret_state(store, catalog, capability, input, account_id, credential)
        .await
        .map(Some)
}

async fn prepare_live_plan_preconditions(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    adapter_targets: &Value,
    account_id: &str,
    credential: Option<&AuthCredential>,
) -> Result<LivePlanPreconditions> {
    Ok(LivePlanPreconditions {
        entitlement: None,
        zone_account: None,
        global_warp_override_state: prepare_global_warp_override_state_precondition(
            store, catalog, capability, input, account_id, credential,
        )
        .await?,
        d1_read_replication_state: prepare_d1_read_replication_state_precondition(
            store, catalog, capability, input, account_id, credential,
        )
        .await?,
        d1_empty_database_state: prepare_d1_empty_database_state_precondition(
            store,
            catalog,
            capability,
            input,
            adapter_targets,
            account_id,
            credential,
        )
        .await?,
        cloudflare_tunnel_configuration_state:
            prepare_cloudflare_tunnel_configuration_state_precondition(
                store, catalog, capability, input, account_id, credential,
            )
            .await?,
        warp_connector_configuration_state:
            prepare_warp_connector_configuration_state_precondition(
                store, catalog, capability, input, account_id, credential,
            )
            .await?,
        web_analytics_rum_state: prepare_web_analytics_rum_state_precondition(
            store, catalog, capability, input, account_id, credential,
        )
        .await?,
        dns_record_state: prepare_dns_record_state_precondition(
            store, catalog, capability, input, account_id, credential,
        )
        .await?,
        oauth_client_secret_state: prepare_oauth_client_secret_state_precondition(
            store, catalog, capability, input, account_id, credential,
        )
        .await?,
    })
}

struct PlanAuthority<'a> {
    profile: &'a ProfileMetadata,
    account_id: &'a str,
}

struct LivePlanPreconditions {
    entitlement: Option<(Value, EvidenceV1)>,
    zone_account: Option<(Value, EvidenceV1)>,
    global_warp_override_state: Option<(Value, EvidenceV1)>,
    d1_read_replication_state: Option<(Value, EvidenceV1)>,
    d1_empty_database_state: Option<(Value, EvidenceV1)>,
    cloudflare_tunnel_configuration_state: Option<(Value, EvidenceV1)>,
    warp_connector_configuration_state: Option<(Value, EvidenceV1)>,
    web_analytics_rum_state: Option<(Value, EvidenceV1)>,
    dns_record_state: Option<(Value, EvidenceV1)>,
    oauth_client_secret_state: Option<(Value, EvidenceV1)>,
}

fn plan_targets(
    input: &CallInput,
    account_id: &str,
    adapter_targets: &Value,
    live_preconditions: &LivePlanPreconditions,
) -> Value {
    let mut targets = json!({
        "selectors": input.selectors,
        "account_id": account_id,
        "adapter": adapter_targets,
    });
    if let Some((receipt, _)) = &live_preconditions.global_warp_override_state {
        targets["live_preconditions"]["global_warp_override_state"] = receipt.clone();
    }
    if let Some((receipt, _)) = &live_preconditions.d1_read_replication_state {
        targets["live_preconditions"][D1_READ_REPLICATION_PRECONDITION] = receipt.clone();
    }
    if let Some((receipt, _)) = &live_preconditions.d1_empty_database_state {
        targets["live_preconditions"][D1_EMPTY_DATABASE_PRECONDITION] = receipt.clone();
    }
    if let Some((receipt, _)) = &live_preconditions.cloudflare_tunnel_configuration_state {
        targets["live_preconditions"][CLOUDFLARE_TUNNEL_CONFIGURATION_STATE_PRECONDITION] =
            receipt.clone();
    }
    if let Some((receipt, _)) = &live_preconditions.warp_connector_configuration_state {
        targets["live_preconditions"][WARP_CONNECTOR_CONFIGURATION_STATE_PRECONDITION] =
            receipt.clone();
    }
    if let Some((receipt, _)) = &live_preconditions.web_analytics_rum_state {
        targets["live_preconditions"][WEB_ANALYTICS_RUM_STATE_PRECONDITION] = receipt.clone();
    }
    if let Some((receipt, _)) = &live_preconditions.dns_record_state {
        targets["live_preconditions"][DNS_RECORD_STATE_PRECONDITION] = receipt.clone();
    }
    if let Some((receipt, _)) = &live_preconditions.oauth_client_secret_state {
        targets["live_preconditions"][OAUTH_CLIENT_KEY_OVERLAP_PRECONDITION] = receipt.clone();
    }
    targets
}

fn bind_live_plan_preconditions(
    plan: &mut PlanV1,
    live_preconditions: &LivePlanPreconditions,
) -> Result<()> {
    for (name, precondition) in [
        ("entitlement", &live_preconditions.entitlement),
        ("zone_account", &live_preconditions.zone_account),
        (
            "global_warp_override_state",
            &live_preconditions.global_warp_override_state,
        ),
        (
            D1_READ_REPLICATION_PRECONDITION,
            &live_preconditions.d1_read_replication_state,
        ),
        (
            D1_EMPTY_DATABASE_PRECONDITION,
            &live_preconditions.d1_empty_database_state,
        ),
        (
            CLOUDFLARE_TUNNEL_CONFIGURATION_STATE_PRECONDITION,
            &live_preconditions.cloudflare_tunnel_configuration_state,
        ),
        (
            WARP_CONNECTOR_CONFIGURATION_STATE_PRECONDITION,
            &live_preconditions.warp_connector_configuration_state,
        ),
        (
            WEB_ANALYTICS_RUM_STATE_PRECONDITION,
            &live_preconditions.web_analytics_rum_state,
        ),
        (
            DNS_RECORD_STATE_PRECONDITION,
            &live_preconditions.dns_record_state,
        ),
        (
            OAUTH_CLIENT_KEY_OVERLAP_PRECONDITION,
            &live_preconditions.oauth_client_secret_state,
        ),
    ] {
        if let Some((receipt, _)) = precondition {
            plan.precondition_hashes
                .insert(name.to_owned(), hash_value(receipt)?);
        }
    }
    Ok(())
}

fn planned_cloudflare_diff(
    plan: &PlanV1,
    input: &CallInput,
    live_preconditions: &LivePlanPreconditions,
) -> Value {
    let mut diff = json!({
        "request_method": plan.capability.method,
        "request_path": plan.capability.path,
        "request_body": input.body,
    });
    if let Some((receipt, _)) = &live_preconditions.global_warp_override_state {
        diff["observed_before"] = json!({
            "disconnect": receipt.get("disconnect").cloned().unwrap_or(Value::Null),
        });
        diff["planned_after"] = json!({
            "disconnect": input
                .body
                .as_ref()
                .and_then(|body| body.get("disconnect"))
                .cloned()
                .unwrap_or(Value::Null),
        });
    }
    if let Some((receipt, _)) = &live_preconditions.d1_read_replication_state {
        diff["observed_before"] = json!({
            "read_replication": receipt
                .get("read_replication")
                .cloned()
                .unwrap_or(Value::Null),
        });
        diff["planned_after"] = json!({
            "read_replication": input
                .body
                .as_ref()
                .and_then(|body| body.get("read_replication"))
                .cloned()
                .unwrap_or(Value::Null),
        });
    }
    if let Some((receipt, _)) = &live_preconditions.cloudflare_tunnel_configuration_state {
        diff["observed_before"] = json!({
            "config": receipt.get("prior_config").cloned().unwrap_or(Value::Null),
        });
        diff["planned_after"] = json!({
            "config": input
                .body
                .as_ref()
                .and_then(|body| body.get("config"))
                .cloned()
                .unwrap_or(Value::Null),
        });
    }
    if let Some((receipt, _)) = &live_preconditions.warp_connector_configuration_state {
        diff["observed_before"] = json!({
            "ha_mode": receipt
                .get("prior_ha_mode")
                .cloned()
                .unwrap_or(Value::Null),
            "config": receipt.get("prior_config").cloned().unwrap_or(Value::Null),
        });
        diff["planned_after"] = input.body.clone().unwrap_or(Value::Null);
    }
    if let Some((receipt, _)) = &live_preconditions.web_analytics_rum_state {
        diff["observed_before"] = json!({
            "value": receipt.get("prior_value").cloned().unwrap_or(Value::Null),
        });
        diff["planned_after"] = json!({
            "value": input
                .body
                .as_ref()
                .and_then(|body| body.get("value"))
                .cloned()
                .unwrap_or(Value::Null),
        });
    }
    if let Some((receipt, _)) = &live_preconditions.dns_record_state {
        diff["observed_before"] = receipt.get("prior_record").cloned().unwrap_or(Value::Null);
        diff["planned_after"] = input.body.clone().unwrap_or(Value::Null);
    }
    if let Some((receipt, _)) = &live_preconditions.oauth_client_secret_state {
        let observed_before = receipt
            .get("key_overlap_active")
            .cloned()
            .unwrap_or(Value::Null);
        diff["observed_before"] = json!({"key_overlap_active": observed_before});
        diff["planned_after"] = json!({
            "key_overlap_active": !observed_before.as_bool().unwrap_or(false)
        });
    }
    diff
}

fn persist_prepared_plan(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: cfctl_core::CapabilityV1,
    input: CallInput,
    authority: PlanAuthority<'_>,
    adapter_targets: Value,
    live_preconditions: LivePlanPreconditions,
) -> Result<ResultEnvelopeV2> {
    let PlanAuthority {
        profile,
        account_id,
    } = authority;
    validate_api_token_creation_contract(&capability, &input, &adapter_targets, account_id)?;
    let impact = plan_impact(store, &capability, &input, account_id)?;
    let policy = PolicyEngine.evaluate(&capability, &impact.policy);
    if policy.disposition == PolicyDisposition::Blocked {
        return Err(CliError::Input(format!(
            "capability is blocked: {}",
            policy.reasons.join("; ")
        )));
    }
    let targets = plan_targets(&input, account_id, &adapter_targets, &live_preconditions);
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
        ProfileKind::LegacyWranglerSession => "unsupported_legacy_wrangler_session",
        ProfileKind::GlobalKey => "emergency_global_key",
    }
    .clone_into(&mut plan.permission_lane);
    plan.input = serde_json::to_value(&input)?;
    plan.precondition_hashes
        .insert("catalog".to_owned(), catalog.schema_hash.clone());
    plan.precondition_hashes
        .insert("request_input".to_owned(), hash_value(&plan.input)?);
    bind_live_plan_preconditions(&mut plan, &live_preconditions)?;
    plan.precondition_hashes
        .extend(workspace_precondition_hashes(store)?);
    plan.affected_repositories = impact.affected_repositories;
    plan.affected_resources = impact.affected_resources;
    plan.local_diffs = impact.local_diffs;
    let cloudflare_diff = planned_cloudflare_diff(&plan, &input, &live_preconditions);
    plan.cloudflare_diffs.push(cloudflare_diff);
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
            "approval_command": approval_command_argv(&plan.capability, &plan.operation_id).join(" "),
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
    if let Some((_, evidence)) = live_preconditions.entitlement {
        envelope.evidence.insert(0, evidence);
    }
    if let Some((_, evidence)) = live_preconditions.zone_account {
        envelope.evidence.insert(0, evidence);
    }
    if let Some((_, evidence)) = live_preconditions.global_warp_override_state {
        envelope.evidence.insert(0, evidence);
    }
    if let Some((_, evidence)) = live_preconditions.d1_read_replication_state {
        envelope.evidence.insert(0, evidence);
    }
    if let Some((_, evidence)) = live_preconditions.cloudflare_tunnel_configuration_state {
        envelope.evidence.insert(0, evidence);
    }
    if let Some((_, evidence)) = live_preconditions.warp_connector_configuration_state {
        envelope.evidence.insert(0, evidence);
    }
    if let Some((_, evidence)) = live_preconditions.web_analytics_rum_state {
        envelope.evidence.insert(0, evidence);
    }
    if let Some((_, evidence)) = live_preconditions.dns_record_state {
        envelope.evidence.insert(0, evidence);
    }
    Ok(envelope)
}

fn validate_api_token_creation_contract(
    capability: &CapabilityV1,
    input: &CallInput,
    adapter_targets: &Value,
    account_id: &str,
) -> Result<()> {
    let Some(inventory_contract) = token_permission_inventory_contract(&capability.id) else {
        return Ok(());
    };
    let inventory = adapter_targets
        .get("permission_inventory")
        .ok_or_else(|| {
            CliError::Input(
                "direct token-create calls are blocked because they do not bind a fresh permission inventory; use `cfctl keys mint`"
                    .to_owned(),
            )
        })?;
    if inventory
        .get("source_capability_id")
        .and_then(Value::as_str)
        != Some(inventory_contract.capability_id)
    {
        return Err(CliError::Input(format!(
            "token mint permission metadata is not bound to the required `{}` inventory capability",
            inventory_contract.capability_id
        )));
    }
    let selected_groups = inventory
        .get("selected_groups")
        .and_then(Value::as_array)
        .filter(|groups| !groups.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "token mint permission inventory contains no selected groups".to_owned(),
            )
        })?;
    let selected_ids = selected_groups
        .iter()
        .map(|group| {
            group
                .get("id")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| {
                    CliError::Input(
                        "token mint permission inventory contains a group without an ID".to_owned(),
                    )
                })
        })
        .collect::<Result<Vec<_>>>()?;
    let normalized_groups =
        validate_selected_permission_groups(&selected_ids, &Value::Array(selected_groups.clone()))?;
    validate_permission_group_resource_scope(&normalized_groups, "com.cloudflare.api.account")?;
    let expected_hash = inventory
        .get("selected_groups_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input("token mint permission inventory hash is missing".to_owned())
        })?;
    if hash_value(&serde_json::to_value(&normalized_groups)?)? != expected_hash {
        return Err(CliError::Input(
            "token mint permission inventory metadata does not match its bound hash".to_owned(),
        ));
    }
    let evidence_hashes = inventory
        .get("evidence_hashes")
        .and_then(Value::as_array)
        .filter(|hashes| {
            !hashes.is_empty()
                && hashes.iter().all(|hash| {
                    hash.as_str()
                        .is_some_and(|hash| hash.starts_with("sha256:") && hash.len() == 71)
                })
        })
        .ok_or_else(|| {
            CliError::Input(
                "token mint permission inventory is missing a live-read evidence hash".to_owned(),
            )
        })?;
    if evidence_hashes.len() != 1 {
        return Err(CliError::Input(
            "token mint permission inventory must bind exactly one live-read evidence receipt"
                .to_owned(),
        ));
    }
    validate_token_policy_body(input.body.as_ref(), &selected_ids, account_id)
}

#[derive(Clone, Copy)]
struct TokenPermissionInventoryContract {
    capability_id: &'static str,
    path: &'static str,
    account_selector: bool,
}

fn token_permission_inventory_contract(
    token_create_capability_id: &str,
) -> Option<TokenPermissionInventoryContract> {
    match token_create_capability_id {
        "account-api-tokens-create-token" => Some(TokenPermissionInventoryContract {
            capability_id: "account-api-tokens-list-permission-groups",
            path: "/accounts/{account_id}/tokens/permission_groups",
            account_selector: true,
        }),
        "user-api-tokens-create-token" => Some(TokenPermissionInventoryContract {
            capability_id: "permission-groups-list-permission-groups",
            path: "/user/tokens/permission_groups",
            account_selector: false,
        }),
        _ => None,
    }
}

fn validate_permission_group_resource_scope(groups: &[Value], required_scope: &str) -> Result<()> {
    for group in groups {
        let id = group
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("<missing>");
        let supports_scope = group
            .get("scopes")
            .and_then(Value::as_array)
            .is_some_and(|scopes| {
                scopes
                    .iter()
                    .any(|scope| scope.as_str() == Some(required_scope))
            });
        if !supports_scope {
            return Err(CliError::Input(format!(
                "permission group `{id}` does not support the required account resource scope `{required_scope}`"
            )));
        }
    }
    Ok(())
}

fn validate_token_policy_body(
    body: Option<&Value>,
    selected_ids: &[String],
    account_id: &str,
) -> Result<()> {
    let policies = body
        .and_then(|body| body.get("policies"))
        .and_then(Value::as_array)
        .filter(|policies| policies.len() == 1)
        .ok_or_else(|| {
            CliError::Input(
                "token minting requires exactly one hash-bound least-privilege policy".to_owned(),
            )
        })?;
    let policy = &policies[0];
    if policy.get("effect").and_then(Value::as_str) != Some("allow") {
        return Err(CliError::Input(
            "token minting requires one explicit allow policy".to_owned(),
        ));
    }
    let mut body_ids = policy
        .get("permission_groups")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CliError::Input("token mint policy has no permission-group list".to_owned())
        })?
        .iter()
        .map(|group| {
            group
                .get("id")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| {
                    CliError::Input(
                        "token mint policy contains a permission group without an ID".to_owned(),
                    )
                })
        })
        .collect::<Result<Vec<_>>>()?;
    let original_len = body_ids.len();
    body_ids.sort();
    body_ids.dedup();
    if original_len != body_ids.len() || body_ids != selected_ids {
        return Err(CliError::Input(
            "token mint policy permissions do not exactly match the bound live inventory selection"
                .to_owned(),
        ));
    }
    let resources = policy
        .get("resources")
        .and_then(Value::as_object)
        .ok_or_else(|| CliError::Input("token mint policy has no resource scope".to_owned()))?;
    let expected_resource = format!("com.cloudflare.api.account.{account_id}");
    if resources.len() != 1
        || resources.get(&expected_resource).and_then(Value::as_str) != Some("*")
    {
        return Err(CliError::Input(format!(
            "token mint policy must be scoped only to account `{account_id}`"
        )));
    }
    Ok(())
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
    let workspace_resource_keys = workspace_resource_keys(capability, input);
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

fn workspace_resource_keys(capability: &CapabilityV1, input: &CallInput) -> Vec<String> {
    let mut resources = Vec::new();
    collect_workspace_resource_keys(capability, &input.selectors, None, &mut resources);
    collect_workspace_resource_keys(capability, &input.query, None, &mut resources);
    if let Some(body) = &input.body {
        collect_workspace_resource_keys(capability, body, None, &mut resources);
    }
    resources.sort();
    resources.dedup();
    resources
}

fn collect_workspace_resource_keys(
    capability: &CapabilityV1,
    value: &Value,
    field: Option<&str>,
    resources: &mut Vec<String>,
) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                collect_workspace_resource_keys(capability, value, Some(key), resources);
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_workspace_resource_keys(capability, value, field, resources);
            }
        }
        Value::String(value) => {
            let field = field.unwrap_or_default().to_ascii_lowercase();
            let product = capability.product.to_ascii_lowercase();
            let is_hostname_name = field == "name"
                && value.contains('.')
                && (capability.path.contains("/dns_records") || product.contains("dns record"));
            let is_hostname_pattern = field == "pattern"
                && (capability.path.contains("/workers/routes")
                    || product.contains("worker route"));
            let resource = if field.contains("hostname") || is_hostname_name || is_hostname_pattern
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
            } else if matches!(field.as_str(), "namespace_id" | "kv_namespace_id")
                && (capability.path.contains("/storage/kv/namespaces")
                    || product == "workers kv namespace")
            {
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
    let secrets = platform_secrets(store);
    let credential = fresh_credential(profile, &secrets).await?;
    let execution_input = resolved_plan_input(&plan, &secrets)?;
    let adapter_targets = plan.targets.get("adapter").unwrap_or(&Value::Null);
    validate_api_token_creation_contract(
        &plan.capability,
        &execution_input,
        adapter_targets,
        &plan.account_id,
    )?;
    let live_precondition_evidence = validate_live_plan_precondition_evidence(
        store,
        &catalog,
        &plan,
        &execution_input,
        &credential,
        None,
    )
    .await?;
    plan.mark_consumed()?;
    store.save_plan(&plan)?;
    persist_transaction_stage(
        store,
        &mut plan,
        TransactionStageV1::BoundaryAttemptPersisted,
    )?;
    execute_consumed_plan(
        store,
        &catalog.schema_hash,
        &mut plan,
        &execution_input,
        &credential,
        &secrets,
        live_precondition_evidence,
    )
    .await
}

/// The standing-authority execution lane. Identical to `run_plan` in every
/// pre-consumption re-verification (catalog hash, workspace and live
/// precondition hashes, token contract, secret sink); it differs only at the
/// consumption gate, where the authority's blast-radius bounds are validated
/// against the exact resolved execution input and consumption is recorded
/// against the authority instead of a per-operation approval.
async fn run_plan_under_standing_authority(
    store: &StateStore,
    operation_id: &str,
    authority_id: &str,
) -> Result<ResultEnvelopeV2> {
    // Lock order is always plan -> authority. The plan lock may span async
    // preflight; the authority lock is acquired only for the synchronous
    // admission critical section below and is released before network I/O.
    let _plan_lock = store.lock_plan(operation_id)?;
    let authority_snapshot = store.load_authority(authority_id)?;
    let catalog = ensure_catalog(store).await?;
    let mut plan = load_validated_plan(store, operation_id)?;
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
    let secrets = platform_secrets(store);
    let credential = fresh_credential(profile, &secrets).await?;
    let execution_input = resolved_plan_input(&plan, &secrets)?;
    let adapter_targets = plan.targets.get("adapter").unwrap_or(&Value::Null);
    validate_api_token_creation_contract(
        &plan.capability,
        &execution_input,
        adapter_targets,
        &plan.account_id,
    )?;
    let live_precondition_evidence = validate_live_plan_precondition_evidence(
        store,
        &catalog,
        &plan,
        &execution_input,
        &credential,
        Some(&authority_snapshot),
    )
    .await?;
    authorize_standing_execution(&authority_snapshot, &plan, &execution_input)?;
    let standing_evidence =
        admit_standing_plan(store, &mut plan, &authority_snapshot, &execution_input)?;
    let admitted_authority_id = authority_snapshot.authority_id.clone();
    let mut envelope = execute_consumed_plan(
        store,
        &catalog.schema_hash,
        &mut plan,
        &execution_input,
        &credential,
        &secrets,
        live_precondition_evidence,
    )
    .await?;
    envelope.evidence.push(standing_evidence);
    if let Some(result) = envelope.result.as_object_mut() {
        result.insert(
            "standing_authority_id".to_owned(),
            json!(admitted_authority_id),
        );
    }
    Ok(envelope)
}

/// Performs the synchronous standing-authority admission transaction while
/// the caller holds the plan lock. No network or async work is permitted in
/// this critical section.
fn admit_standing_plan(
    store: &StateStore,
    plan: &mut PlanV1,
    authority_snapshot: &StandingAuthorityV1,
    execution_input: &CallInput,
) -> Result<EvidenceV1> {
    let authority_guard = store.lock_authority(&authority_snapshot.authority_id)?;
    let mut authority = store.load_authority(&authority_snapshot.authority_id)?;
    if authority.content_hash != authority_snapshot.content_hash {
        return Err(CliError::Input(
            "standing authority changed during live preflight; the mutation boundary was not crossed"
                .to_owned(),
        ));
    }
    // The live inventory was validated against the snapshot. Exact
    // content-hash equality plus the operational/hash check below proves
    // that the locked authority carries the same immutable allowlist.
    let admission_time = Utc::now();
    authorize_standing_execution_at(&authority, plan, execution_input, admission_time)?;
    plan.mark_consumed_via_standing_authority(&authority)?;
    // Durable reservation is the admission linearization point. It is saved
    // before plan consumption so a persistence failure may spend a budget
    // slot but can never permit an unaccounted boundary attempt.
    authority.reserve_run(admission_time, &plan.operation_id, &plan.capability.id)?;
    store.save_authority_guarded(&authority, &authority_guard)?;
    store.save_plan(plan)?;
    let evidence = store.write_evidence(
        EvidenceClass::StandingApply,
        &json!({
            "standing_authority_id": authority.authority_id,
            "standing_authority_content_hash": authority.content_hash,
            "operation_id": plan.operation_id,
            "capability_id": plan.capability.id,
            "account_id": plan.account_id,
            "admission": "durable_run_reservation",
        }),
    )?;
    persist_transaction_stage(store, plan, TransactionStageV1::BoundaryAttemptPersisted)?;
    Ok(evidence)
}

/// Validates the authority's bounds against the exact execution input the
/// boundary call will use — never a re-derivation.
fn authorize_standing_execution(
    authority: &StandingAuthorityV1,
    plan: &PlanV1,
    input: &CallInput,
) -> Result<()> {
    authorize_standing_execution_at(authority, plan, input, Utc::now())
}

fn authorize_standing_execution_at(
    authority: &StandingAuthorityV1,
    plan: &PlanV1,
    input: &CallInput,
    now: chrono::DateTime<Utc>,
) -> Result<()> {
    if plan.capability.id.ends_with("create-token") {
        let body = input.body.as_ref().ok_or_else(|| {
            CliError::Input("a standing mint requires the plan's request body".to_owned())
        })?;
        let child_name = body.get("name").and_then(Value::as_str).ok_or_else(|| {
            CliError::Input("a standing mint requires a child token name".to_owned())
        })?;
        let requested_group_ids: Vec<String> = body
            .get("policies")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|policy| policy.get("permission_groups").and_then(Value::as_array))
            .flatten()
            .filter_map(|group| group.get("id").and_then(Value::as_str))
            .map(str::to_owned)
            .collect();
        let child_expires_at = body
            .get("expires_on")
            .and_then(Value::as_str)
            .map(|raw| {
                chrono::DateTime::parse_from_rfc3339(raw)
                    .map(|parsed| parsed.with_timezone(&Utc))
                    .map_err(|error| {
                        CliError::Input(format!(
                            "the standing mint carries an unparseable expires_on: {error}"
                        ))
                    })
            })
            .transpose()?;
        authority.authorize_token_create(
            now,
            child_name,
            &requested_group_ids,
            child_expires_at,
        )?;
    } else if plan.capability.id.ends_with("delete-token") {
        let token_id = input
            .selectors
            .get("token_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CliError::Input("a standing revoke requires a token_id selector".to_owned())
            })?;
        authority.authorize_token_delete(now, token_id)?;
    } else {
        return Err(CliError::Input(format!(
            "standing authorities do not cover capability `{}`",
            plan.capability.id
        )));
    }
    Ok(())
}

/// Returns the created token ID only when the validated transaction journal
/// proves that this exact authority admitted the plan and Cloudflare returned
/// a successful creation receipt. Revocation is intentionally not consulted:
/// lineage reconciliation records an already-crossed boundary; it grants no
/// new authority.
fn validated_standing_lineage_token_id<'a>(
    plan: &'a PlanV1,
    authority: &StandingAuthorityV1,
) -> Result<Option<&'a str>> {
    plan.validate_transaction_journal()?;
    let Some(binding) = plan.transaction_artifact(TransactionStageV1::ConsumptionPersisted) else {
        return Ok(None);
    };
    let bound_authority_id = binding
        .get("standing_authority_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "standing consumption receipt has no authority ID; do not replay the mutation"
                    .to_owned(),
            )
        })?;
    let bound_authority_hash = binding
        .get("standing_authority_content_hash")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "standing consumption receipt has no authority content hash; do not replay the mutation"
                    .to_owned(),
            )
        })?;
    if bound_authority_id != authority.authority_id
        || bound_authority_hash != authority.content_hash
    {
        return Err(CliError::Input(
            "standing consumption receipt does not bind the exact authority; do not replay the mutation"
                .to_owned(),
        ));
    }
    let approval_matches = authority
        .approval
        .as_ref()
        .is_some_and(|approval| approval.approved_content_hash == authority.content_hash);
    if !approval_matches {
        return Err(CliError::Input(
            "standing authority no longer carries the approval bound by the consumption receipt; do not replay the mutation"
                .to_owned(),
        ));
    }
    let matching_reservations = authority
        .run_log
        .iter()
        .filter(|run| run.operation_id == plan.operation_id)
        .collect::<Vec<_>>();
    if matching_reservations.len() != 1
        || matching_reservations[0].capability_id != plan.capability.id
    {
        return Err(CliError::Input(
            "standing boundary receipt was not durably reserved exactly once under the same authority capability; do not replay the mutation"
                .to_owned(),
        ));
    }
    if plan.account_id != authority.account_id
        || plan.capability.id != "account-api-tokens-create-token"
        || !authority
            .capability_ids
            .iter()
            .any(|capability_id| capability_id == &plan.capability.id)
    {
        return Err(CliError::Input(
            "standing token receipt account or capability does not match its authority; do not replay the mutation"
                .to_owned(),
        ));
    }
    let Some(response) = plan.transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
    else {
        return Ok(None);
    };
    let success = response
        .get("success")
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            CliError::Input(
                "standing boundary receipt has no success result; do not replay the mutation"
                    .to_owned(),
            )
        })?;
    if !success {
        return Ok(None);
    }
    response
        .get("resource_id")
        .and_then(Value::as_str)
        .filter(|resource_id| !resource_id.trim().is_empty())
        .map(Some)
        .ok_or_else(|| {
            CliError::Input(
                "successful standing token receipt has no resource ID; do not replay the mutation and run `cfctl plans rectify`"
                    .to_owned(),
            )
        })
}

fn standing_consumption_authority_id(plan: &PlanV1) -> Result<Option<&str>> {
    let Some(binding) = plan.transaction_artifact(TransactionStageV1::ConsumptionPersisted) else {
        return Ok(None);
    };
    if binding.get("standing_authority_id").is_none()
        && binding.get("standing_authority_content_hash").is_none()
    {
        return Ok(None);
    }
    binding
        .get("standing_authority_id")
        .and_then(Value::as_str)
        .filter(|authority_id| !authority_id.is_empty())
        .map(Some)
        .ok_or_else(|| {
            CliError::Input(
                "standing consumption receipt has no authority ID; do not replay the mutation"
                    .to_owned(),
            )
        })
}

fn reconcile_standing_lineage_from_plan(
    store: &StateStore,
    plan: &PlanV1,
) -> Result<Option<EvidenceV1>> {
    let Some(authority_id) = standing_consumption_authority_id(plan)? else {
        return Ok(None);
    };
    if plan.capability.id != "account-api-tokens-create-token" {
        return Ok(None);
    }
    let guard = store.lock_authority(authority_id)?;
    let mut authority = store.load_authority(authority_id)?;
    let Some(token_id) = validated_standing_lineage_token_id(plan, &authority)? else {
        return Ok(None);
    };
    let already_recorded = authority
        .minted_token_ids
        .iter()
        .any(|recorded| recorded == token_id);
    authority.record_minted_token(token_id);
    if !already_recorded {
        store.save_authority_guarded(&authority, &guard)?;
    }
    let boundary_receipt_hash = plan
        .transaction_journal
        .iter()
        .find(|checkpoint| checkpoint.stage == TransactionStageV1::BoundaryResponsePersisted)
        .and_then(|checkpoint| checkpoint.artifact_hash.as_deref())
        .ok_or_else(|| {
            CliError::Input(
                "standing boundary response has no validated artifact hash; do not replay the mutation"
                    .to_owned(),
            )
        })?;
    let evidence = store.write_evidence(
        EvidenceClass::StandingApply,
        &json!({
            "standing_authority_id": authority.authority_id,
            "standing_authority_content_hash": authority.content_hash,
            "operation_id": plan.operation_id,
            "token_id": token_id,
            "source_boundary_receipt_hash": boundary_receipt_hash,
            "reconciled": true,
        }),
    )?;
    Ok(Some(evidence))
}

fn recover_standing_lineage(store: &StateStore, authority_id: &str) -> Result<Vec<EvidenceV1>> {
    let mut evidence = Vec::new();
    for snapshot in store.list_plans()? {
        if standing_consumption_authority_id(&snapshot)? != Some(authority_id) {
            continue;
        }
        let _plan_lock = store.lock_plan(&snapshot.operation_id)?;
        let plan = load_validated_plan(store, &snapshot.operation_id)?;
        if standing_consumption_authority_id(&plan)? != Some(authority_id) {
            continue;
        }
        if let Some(item) = reconcile_standing_lineage_from_plan(store, &plan)? {
            evidence.push(item);
        }
    }
    Ok(evidence)
}

struct LivePreconditionEvidence {
    zone_account: Option<EvidenceV1>,
    entitlement: Option<EvidenceV1>,
    permission_inventory: Option<EvidenceV1>,
    global_warp_override_state: Option<EvidenceV1>,
    d1_read_replication_state: Option<EvidenceV1>,
    d1_empty_database_state: Option<EvidenceV1>,
    cloudflare_tunnel_configuration_state: Option<EvidenceV1>,
    warp_connector_configuration_state: Option<EvidenceV1>,
    web_analytics_rum_state: Option<EvidenceV1>,
    dns_record_state: Option<EvidenceV1>,
    oauth_client_secret_state: Option<EvidenceV1>,
}

async fn validate_live_plan_precondition_evidence(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    plan: &PlanV1,
    input: &CallInput,
    credential: &AuthCredential,
    standing_authority: Option<&StandingAuthorityV1>,
) -> Result<LivePreconditionEvidence> {
    Ok(LivePreconditionEvidence {
        zone_account: validate_live_zone_account_precondition(
            store, catalog, plan, input, credential,
        )
        .await?,
        entitlement: validate_live_entitlement_precondition(
            store, catalog, plan, input, credential,
        )
        .await?,
        permission_inventory: validate_live_permission_inventory_precondition(
            store,
            catalog,
            plan,
            credential,
            standing_authority,
        )
        .await?,
        global_warp_override_state: validate_live_global_warp_override_state_precondition(
            store, catalog, plan, input, credential,
        )
        .await?,
        d1_read_replication_state: validate_live_d1_read_replication_state_precondition(
            store, catalog, plan, input, credential,
        )
        .await?,
        d1_empty_database_state: validate_live_d1_empty_database_state_precondition(
            store, catalog, plan, input, credential,
        )
        .await?,
        cloudflare_tunnel_configuration_state:
            validate_live_cloudflare_tunnel_configuration_state_precondition(
                store, catalog, plan, input, credential,
            )
            .await?,
        warp_connector_configuration_state:
            validate_live_warp_connector_configuration_state_precondition(
                store, catalog, plan, input, credential,
            )
            .await?,
        web_analytics_rum_state: validate_live_web_analytics_rum_state_precondition(
            store, catalog, plan, input, credential,
        )
        .await?,
        dns_record_state: validate_live_dns_record_state_precondition(
            store, catalog, plan, input, credential,
        )
        .await?,
        oauth_client_secret_state: validate_live_oauth_client_secret_state_precondition(
            store, catalog, plan, input, credential,
        )
        .await?,
    })
}

async fn execute_consumed_plan(
    store: &StateStore,
    catalog_hash: &str,
    plan: &mut PlanV1,
    execution_input: &CallInput,
    credential: &AuthCredential,
    secrets: &dyn SecretStore,
    evidence: LivePreconditionEvidence,
) -> Result<ResultEnvelopeV2> {
    if plan.capability.adapter_status == AdapterStatus::DelegatedCli {
        let mut result =
            execute_delegated_plan(store, plan, execution_input, credential, secrets).await;
        if result.is_err() && plan.transaction_stage == TransactionStageV1::BoundaryAttemptPersisted
        {
            plan.status = PlanStatus::RectificationRequired;
            persist_transaction_stage_with_artifact(
                store,
                plan,
                TransactionStageV1::BoundaryResponsePersisted,
                boundary_failure_artifact("delegated_cli", "no_receipt"),
            )?;
            persist_secret_lifecycle(store, plan, false, None, secrets)?;
        }
        if let Ok(envelope) = &mut result {
            prepend_live_precondition_evidence(envelope, evidence);
        }
        return result;
    }
    if plan.capability.adapter_status == AdapterStatus::GovernedUi {
        let mut result = execute_governed_ui_plan(store, plan, execution_input, secrets);
        if result.is_err() && plan.transaction_stage == TransactionStageV1::BoundaryAttemptPersisted
        {
            plan.status = PlanStatus::RectificationRequired;
            persist_transaction_stage_with_artifact(
                store,
                plan,
                TransactionStageV1::BoundaryResponsePersisted,
                boundary_failure_artifact("governed_ui", "handoff_failed"),
            )?;
            persist_secret_lifecycle(store, plan, false, None, secrets)?;
        }
        if let Ok(envelope) = &mut result {
            prepend_live_precondition_evidence(envelope, evidence);
        }
        return result;
    }
    let mut envelope = execute_api_plan(
        store,
        catalog_hash,
        plan,
        execution_input,
        credential,
        secrets,
    )
    .await?;
    prepend_live_precondition_evidence(&mut envelope, evidence);
    Ok(envelope)
}

fn prepend_live_precondition_evidence(
    envelope: &mut ResultEnvelopeV2,
    evidence: LivePreconditionEvidence,
) {
    for item in [
        evidence.oauth_client_secret_state,
        evidence.dns_record_state,
        evidence.web_analytics_rum_state,
        evidence.warp_connector_configuration_state,
        evidence.cloudflare_tunnel_configuration_state,
        evidence.d1_empty_database_state,
        evidence.d1_read_replication_state,
        evidence.global_warp_override_state,
        evidence.permission_inventory,
        evidence.entitlement,
        evidence.zone_account,
    ]
    .into_iter()
    .flatten()
    {
        envelope.evidence.insert(0, item);
    }
}

async fn validate_live_global_warp_override_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    plan: &PlanV1,
    input: &CallInput,
    credential: &AuthCredential,
) -> Result<Option<EvidenceV1>> {
    let Some(expected_hash) = required_global_warp_override_state_precondition(plan)? else {
        return Ok(None);
    };
    let (receipt, evidence) = read_live_global_warp_override_state(
        store,
        catalog,
        &plan.capability,
        input,
        &plan.account_id,
        credential,
    )
    .await?;
    validate_global_warp_override_state_receipt_precondition(expected_hash, &receipt)?;
    Ok(Some(evidence))
}

fn validate_global_warp_override_state_receipt_precondition(
    expected_hash: &str,
    receipt: &Value,
) -> Result<()> {
    if hash_value(receipt)? != expected_hash {
        return Err(CliError::Input(
            "live Global WARP override state drifted after planning; the mutation boundary was not crossed and a new plan is required"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_global_warp_override_prior_state_receipt(
    plan: &PlanV1,
    receipt: &Value,
) -> Result<bool> {
    let exact_identity = receipt.as_object().is_some_and(|object| object.len() == 7)
        && receipt.get("schema_version").and_then(Value::as_u64) == Some(1)
        && receipt.get("source_capability_id").and_then(Value::as_str)
            == Some(GLOBAL_WARP_OVERRIDE_READ_CAPABILITY_ID)
        && receipt.get("source_path").and_then(Value::as_str) == Some(GLOBAL_WARP_OVERRIDE_PATH)
        && receipt.get("target_capability_id").and_then(Value::as_str)
            == Some(GLOBAL_WARP_OVERRIDE_MUTATION_CAPABILITY_ID)
        && receipt.get("target_scope").and_then(Value::as_str) == Some("account")
        && receipt.get("target_id").and_then(Value::as_str) == Some(plan.account_id.as_str());
    let disconnect = receipt.get("disconnect").and_then(Value::as_bool);
    if !exact_identity || disconnect.is_none() {
        return Err(CliError::Input(
            "plan Global WARP override prior-state receipt has an invalid account, source, or state shape; create a new plan"
                .to_owned(),
        ));
    }
    disconnect.ok_or_else(|| {
        CliError::Input(
            "plan Global WARP override prior-state receipt omitted boolean `disconnect`; create a new plan"
                .to_owned(),
        )
    })
}

fn required_global_warp_override_state_precondition(plan: &PlanV1) -> Result<Option<&str>> {
    if !is_global_warp_override_mutation(&plan.capability) {
        return Ok(None);
    }
    if !should_bind_global_warp_override_state(&plan.capability) {
        return Err(CliError::Input(
            "Global WARP override plan is inconsistent with its hash-bound prior-state contract; create a new plan"
                .to_owned(),
        ));
    }
    let expected_hash = plan
        .precondition_hashes
        .get("global_warp_override_state")
        .map(String::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "plan predates the live Global WARP override prior-state contract; create a new plan"
                    .to_owned(),
            )
        })?;
    let receipt = plan
        .targets
        .pointer("/live_preconditions/global_warp_override_state")
        .ok_or_else(|| {
            CliError::Input(
                "plan predates the hash-bound Global WARP override prior-state receipt; create a new plan"
                    .to_owned(),
            )
        })?;
    validate_global_warp_override_prior_state_receipt(plan, receipt)?;
    if hash_value(receipt)? != expected_hash {
        return Err(CliError::Input(
            "plan Global WARP override prior-state receipt does not match its precondition hash; create a new plan"
                .to_owned(),
        ));
    }
    Ok(Some(expected_hash))
}

fn global_warp_override_prior_disconnect_state(plan: &PlanV1) -> Result<bool> {
    required_global_warp_override_state_precondition(plan)?.ok_or_else(|| {
        CliError::Input(
            "Global WARP override compensation requires a hash-bound prior-state precondition"
                .to_owned(),
        )
    })?;
    let receipt = plan
        .targets
        .pointer("/live_preconditions/global_warp_override_state")
        .ok_or_else(|| {
            CliError::Input(
                "Global WARP override compensation requires a hash-bound prior-state receipt"
                    .to_owned(),
            )
        })?;
    validate_global_warp_override_prior_state_receipt(plan, receipt)
}

async fn validate_live_d1_read_replication_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    plan: &PlanV1,
    input: &CallInput,
    credential: &AuthCredential,
) -> Result<Option<EvidenceV1>> {
    let Some(expected_hash) = required_d1_read_replication_state_precondition(plan)? else {
        return Ok(None);
    };
    let (receipt, evidence) = read_live_d1_read_replication_state(
        store,
        catalog,
        &plan.capability,
        input,
        &plan.account_id,
        credential,
    )
    .await?;
    if hash_value(&receipt)? != expected_hash {
        return Err(CliError::Input(
            "live D1 read-replication state drifted after planning; the mutation boundary was not crossed and a new plan is required"
                .to_owned(),
        ));
    }
    Ok(Some(evidence))
}

fn validate_d1_empty_database_state_receipt(plan: &PlanV1, receipt: &Value) -> Result<()> {
    let adapter_targets = plan.targets.get("adapter").unwrap_or(&Value::Null);
    let database_id = plan
        .targets
        .pointer("/selectors/database_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "D1 compensation plan omitted its hash-bound database selector; create a new plan"
                    .to_owned(),
            )
        })?;
    let source_operation_id = adapter_targets
        .get("compensates_operation_id")
        .and_then(Value::as_str);
    let source_receipt_hash = adapter_targets
        .get("source_receipt_hash")
        .and_then(Value::as_str);
    let exact = receipt.as_object().is_some_and(|object| object.len() == 16)
        && receipt.get("schema_version").and_then(Value::as_u64) == Some(1)
        && receipt.get("source_capability_id").and_then(Value::as_str)
            == Some(D1_READ_REPLICATION_READ_CAPABILITY_ID)
        && receipt.get("source_path").and_then(Value::as_str) == Some(D1_READ_REPLICATION_PATH)
        && receipt.get("target_capability_id").and_then(Value::as_str)
            == Some(D1_DATABASE_DELETE_CAPABILITY_ID)
        && receipt.get("target_method").and_then(Value::as_str) == Some("DELETE")
        && receipt.get("target_path").and_then(Value::as_str) == Some(D1_READ_REPLICATION_PATH)
        && receipt.get("target_scope").and_then(Value::as_str) == Some("account")
        && receipt.get("account_id").and_then(Value::as_str) == Some(plan.account_id.as_str())
        && receipt.get("database_id").and_then(Value::as_str) == Some(database_id)
        && receipt
            .get("database_name")
            .and_then(Value::as_str)
            .is_some_and(|name| !name.is_empty())
        && receipt.get("num_tables").and_then(Value::as_u64) == Some(0)
        && receipt.get("file_size").and_then(Value::as_u64).is_some()
        && receipt
            .get("jurisdiction")
            .is_some_and(|value| value.is_null() || value.is_string())
        && receipt
            .pointer("/read_replication/mode")
            .and_then(Value::as_str)
            .is_some_and(|mode| matches!(mode, "auto" | "disabled"))
        && receipt
            .get("read_replication")
            .and_then(Value::as_object)
            .is_some_and(|state| state.len() == 1)
        && receipt
            .get("compensates_operation_id")
            .and_then(Value::as_str)
            == source_operation_id
        && receipt
            .get("source_create_receipt_hash")
            .and_then(Value::as_str)
            == source_receipt_hash;
    if !exact {
        return Err(CliError::Input(
            "plan D1 empty-state receipt has an invalid source create receipt, account, database, table count, or state shape; create a new plan"
                .to_owned(),
        ));
    }
    Ok(())
}

fn required_d1_empty_database_state_precondition(plan: &PlanV1) -> Result<Option<&str>> {
    let adapter_targets = plan.targets.get("adapter").unwrap_or(&Value::Null);
    if !is_d1_database_delete(&plan.capability)
        || adapter_targets
            .get("compensates_capability_id")
            .and_then(Value::as_str)
            != Some(D1_DATABASE_CREATE_CAPABILITY_ID)
    {
        return Ok(None);
    }
    if !should_bind_d1_empty_database_state(&plan.capability, adapter_targets) {
        return Err(CliError::Input(
            "D1 compensation plan is inconsistent with its hash-bound empty-database contract; create a new plan"
                .to_owned(),
        ));
    }
    let expected_hash = plan
        .precondition_hashes
        .get(D1_EMPTY_DATABASE_PRECONDITION)
        .map(String::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "D1 compensation plan predates the live empty-state contract; create a new plan"
                    .to_owned(),
            )
        })?;
    let receipt = plan
        .targets
        .pointer("/live_preconditions/d1_empty_database_state")
        .ok_or_else(|| {
            CliError::Input(
                "D1 compensation plan omitted its hash-bound empty-state receipt; create a new plan"
                    .to_owned(),
            )
        })?;
    validate_d1_empty_database_state_receipt(plan, receipt)?;
    if hash_value(receipt)? != expected_hash {
        return Err(CliError::Input(
            "plan D1 empty-state receipt does not match its precondition hash; create a new plan"
                .to_owned(),
        ));
    }
    Ok(Some(expected_hash))
}

async fn validate_live_d1_empty_database_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    plan: &PlanV1,
    input: &CallInput,
    credential: &AuthCredential,
) -> Result<Option<EvidenceV1>> {
    let Some(expected_hash) = required_d1_empty_database_state_precondition(plan)? else {
        return Ok(None);
    };
    let adapter_targets = plan.targets.get("adapter").unwrap_or(&Value::Null);
    let (receipt, evidence) = read_live_d1_empty_database_state(
        store,
        catalog,
        &plan.capability,
        input,
        adapter_targets,
        &plan.account_id,
        credential,
    )
    .await?;
    if hash_value(&receipt)? != expected_hash {
        return Err(CliError::Input(
            "live D1 empty-database state drifted after planning; the delete boundary was not crossed and a new compensation review is required"
                .to_owned(),
        ));
    }
    Ok(Some(evidence))
}

fn validate_d1_read_replication_prior_state_receipt(
    plan: &PlanV1,
    receipt: &Value,
) -> Result<String> {
    let database_id = plan
        .targets
        .pointer("/selectors/database_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "D1 plan omitted its hash-bound database selector; create a new plan".to_owned(),
            )
        })?;
    let exact_identity = receipt.as_object().is_some_and(|object| object.len() == 9)
        && receipt.get("schema_version").and_then(Value::as_u64) == Some(1)
        && receipt.get("source_capability_id").and_then(Value::as_str)
            == Some(D1_READ_REPLICATION_READ_CAPABILITY_ID)
        && receipt.get("source_path").and_then(Value::as_str) == Some(D1_READ_REPLICATION_PATH)
        && receipt.get("target_capability_id").and_then(Value::as_str)
            == Some(plan.capability.id.as_str())
        && receipt.get("target_method").and_then(Value::as_str)
            == Some(plan.capability.method.as_str())
        && receipt.get("target_scope").and_then(Value::as_str) == Some("account")
        && receipt.get("account_id").and_then(Value::as_str) == Some(plan.account_id.as_str())
        && receipt.get("database_id").and_then(Value::as_str) == Some(database_id);
    let replication = receipt.get("read_replication").and_then(Value::as_object);
    let mode = replication
        .and_then(|state| state.get("mode"))
        .and_then(Value::as_str)
        .filter(|mode| matches!(*mode, "auto" | "disabled"));
    if !exact_identity || replication.is_none_or(|state| state.len() != 1) || mode.is_none() {
        return Err(CliError::Input(
            "plan D1 prior-state receipt has an invalid account, database, source, method, or mode shape; create a new plan"
                .to_owned(),
        ));
    }
    mode.map(str::to_owned).ok_or_else(|| {
        CliError::Input(
            "plan D1 prior-state receipt omitted its bounded mode; create a new plan".to_owned(),
        )
    })
}

fn required_d1_read_replication_state_precondition(plan: &PlanV1) -> Result<Option<&str>> {
    if !is_d1_read_replication_mutation(&plan.capability) {
        return Ok(None);
    }
    if !should_bind_d1_read_replication_state(&plan.capability) {
        return Err(CliError::Input(
            "D1 plan is inconsistent with its hash-bound prior-state contract; create a new plan"
                .to_owned(),
        ));
    }
    let expected_hash = plan
        .precondition_hashes
        .get(D1_READ_REPLICATION_PRECONDITION)
        .map(String::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "plan predates the live D1 prior-state contract; create a new plan".to_owned(),
            )
        })?;
    let receipt = plan
        .targets
        .pointer("/live_preconditions/d1_read_replication_state")
        .ok_or_else(|| {
            CliError::Input(
                "plan predates the hash-bound D1 prior-state receipt; create a new plan".to_owned(),
            )
        })?;
    validate_d1_read_replication_prior_state_receipt(plan, receipt)?;
    if hash_value(receipt)? != expected_hash {
        return Err(CliError::Input(
            "plan D1 prior-state receipt does not match its precondition hash; create a new plan"
                .to_owned(),
        ));
    }
    Ok(Some(expected_hash))
}

fn d1_read_replication_prior_mode(plan: &PlanV1) -> Result<String> {
    required_d1_read_replication_state_precondition(plan)?.ok_or_else(|| {
        CliError::Input("D1 compensation requires a hash-bound prior-state precondition".to_owned())
    })?;
    let receipt = plan
        .targets
        .pointer("/live_preconditions/d1_read_replication_state")
        .ok_or_else(|| {
            CliError::Input("D1 compensation requires a hash-bound prior-state receipt".to_owned())
        })?;
    validate_d1_read_replication_prior_state_receipt(plan, receipt)
}

async fn validate_live_cloudflare_tunnel_configuration_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    plan: &PlanV1,
    input: &CallInput,
    credential: &AuthCredential,
) -> Result<Option<EvidenceV1>> {
    let Some(expected_hash) = required_cloudflare_tunnel_configuration_state_precondition(plan)?
    else {
        return Ok(None);
    };
    let (receipt, evidence) = read_live_cloudflare_tunnel_configuration_state(
        store,
        catalog,
        &plan.capability,
        input,
        &plan.account_id,
        credential,
    )
    .await?;
    if hash_value(&receipt)? != expected_hash {
        return Err(CliError::Input(
            "live Tunnel configuration drifted after planning; the mutation boundary was not crossed and a new plan is required"
                .to_owned(),
        ));
    }
    Ok(Some(evidence))
}

fn validate_cloudflare_tunnel_configuration_prior_state_receipt(
    plan: &PlanV1,
    receipt: &Value,
) -> Result<Value> {
    let tunnel_id = plan
        .targets
        .pointer("/selectors/tunnel_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "Tunnel configuration plan omitted its hash-bound Tunnel selector; create a new plan"
                    .to_owned(),
            )
        })?;
    let exact_identity = receipt.as_object().is_some_and(|object| object.len() == 10)
        && receipt.get("schema_version").and_then(Value::as_u64) == Some(1)
        && receipt.get("source_capability_id").and_then(Value::as_str)
            == Some(CLOUDFLARE_TUNNEL_CONFIGURATION_READ_CAPABILITY_ID)
        && receipt.get("source_path").and_then(Value::as_str)
            == Some(CLOUDFLARE_TUNNEL_CONFIGURATION_PATH)
        && receipt.get("target_capability_id").and_then(Value::as_str)
            == Some(plan.capability.id.as_str())
        && receipt.get("target_method").and_then(Value::as_str)
            == Some(plan.capability.method.as_str())
        && receipt.get("target_path").and_then(Value::as_str)
            == Some(plan.capability.path.as_str())
        && receipt.get("target_scope").and_then(Value::as_str) == Some("account")
        && receipt.get("account_id").and_then(Value::as_str) == Some(plan.account_id.as_str())
        && receipt.get("tunnel_id").and_then(Value::as_str) == Some(tunnel_id);
    let prior_config = receipt
        .get("prior_config")
        .filter(|config| config.is_object())
        .cloned();
    if !exact_identity || prior_config.is_none() {
        return Err(CliError::Input(
            "plan Tunnel configuration prior-state receipt has an invalid account, Tunnel, source, method, path, or state shape; create a new plan"
                .to_owned(),
        ));
    }
    let prior_config = prior_config.ok_or_else(|| {
        CliError::Input(
            "plan Tunnel configuration prior-state receipt omitted an object configuration; create a new plan"
                .to_owned(),
        )
    })?;
    let restore_input = CallInput {
        selectors: json!({"account_id": plan.account_id, "tunnel_id": tunnel_id}),
        body: Some(json!({"config": prior_config})),
        ..CallInput::default()
    };
    preflight_call_input(&plan.capability, &restore_input, None).map_err(|error| {
        CliError::Input(format!(
            "plan Tunnel configuration prior-state receipt is outside the exact restorable request contract; create a new plan: {error}"
        ))
    })?;
    restore_input
        .body
        .and_then(|body| body.get("config").cloned())
        .ok_or_else(|| {
            CliError::Input(
                "plan Tunnel configuration prior-state receipt omitted its validated configuration; create a new plan"
                    .to_owned(),
            )
        })
}

fn required_cloudflare_tunnel_configuration_state_precondition(
    plan: &PlanV1,
) -> Result<Option<&str>> {
    if !is_cloudflare_tunnel_configuration_mutation(&plan.capability) {
        return Ok(None);
    }
    if !should_bind_cloudflare_tunnel_configuration_state(&plan.capability) {
        return Err(CliError::Input(
            "Tunnel configuration plan is inconsistent with its hash-bound prior-state contract; create a new plan"
                .to_owned(),
        ));
    }
    let expected_hash = plan
        .precondition_hashes
        .get(CLOUDFLARE_TUNNEL_CONFIGURATION_STATE_PRECONDITION)
        .map(String::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "plan predates the live Tunnel configuration prior-state contract; create a new plan"
                    .to_owned(),
            )
        })?;
    let receipt = plan
        .targets
        .pointer("/live_preconditions/cloudflare_tunnel_configuration_state")
        .ok_or_else(|| {
            CliError::Input(
                "plan predates the hash-bound Tunnel configuration prior-state receipt; create a new plan"
                    .to_owned(),
            )
        })?;
    validate_cloudflare_tunnel_configuration_prior_state_receipt(plan, receipt)?;
    if hash_value(receipt)? != expected_hash {
        return Err(CliError::Input(
            "plan Tunnel configuration prior-state receipt does not match its precondition hash; create a new plan"
                .to_owned(),
        ));
    }
    Ok(Some(expected_hash))
}

fn cloudflare_tunnel_configuration_prior_snapshot(plan: &PlanV1) -> Result<Value> {
    required_cloudflare_tunnel_configuration_state_precondition(plan)?.ok_or_else(|| {
        CliError::Input(
            "Tunnel configuration compensation requires a hash-bound prior-state precondition"
                .to_owned(),
        )
    })?;
    let receipt = plan
        .targets
        .pointer("/live_preconditions/cloudflare_tunnel_configuration_state")
        .ok_or_else(|| {
            CliError::Input(
                "Tunnel configuration compensation requires a hash-bound prior-state receipt"
                    .to_owned(),
            )
        })?;
    validate_cloudflare_tunnel_configuration_prior_state_receipt(plan, receipt)
}

async fn validate_live_warp_connector_configuration_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    plan: &PlanV1,
    input: &CallInput,
    credential: &AuthCredential,
) -> Result<Option<EvidenceV1>> {
    let Some(expected_hash) = required_warp_connector_configuration_state_precondition(plan)?
    else {
        return Ok(None);
    };
    let (receipt, evidence) = read_live_warp_connector_configuration_state(
        store,
        catalog,
        &plan.capability,
        input,
        &plan.account_id,
        credential,
    )
    .await?;
    if hash_value(&receipt)? != expected_hash {
        return Err(CliError::Input(
            "live WARP Connector configuration drifted after planning; the mutation boundary was not crossed and a new plan is required"
                .to_owned(),
        ));
    }
    Ok(Some(evidence))
}

fn validate_warp_connector_configuration_prior_state_receipt(
    plan: &PlanV1,
    receipt: &Value,
) -> Result<Value> {
    let tunnel_id = plan
        .targets
        .pointer("/selectors/tunnel_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "WARP Connector plan omitted its hash-bound Tunnel selector; create a new plan"
                    .to_owned(),
            )
        })?;
    let exact_identity = receipt.as_object().is_some_and(|object| object.len() == 11)
        && receipt.get("schema_version").and_then(Value::as_u64) == Some(1)
        && receipt.get("source_capability_id").and_then(Value::as_str)
            == Some(WARP_CONNECTOR_CONFIGURATION_READ_CAPABILITY_ID)
        && receipt.get("source_path").and_then(Value::as_str)
            == Some(WARP_CONNECTOR_CONFIGURATION_PATH)
        && receipt.get("target_capability_id").and_then(Value::as_str)
            == Some(plan.capability.id.as_str())
        && receipt.get("target_method").and_then(Value::as_str)
            == Some(plan.capability.method.as_str())
        && receipt.get("target_path").and_then(Value::as_str)
            == Some(plan.capability.path.as_str())
        && receipt.get("target_scope").and_then(Value::as_str) == Some("account")
        && receipt.get("account_id").and_then(Value::as_str) == Some(plan.account_id.as_str())
        && receipt.get("tunnel_id").and_then(Value::as_str) == Some(tunnel_id);
    let prior_ha_mode = receipt.get("prior_ha_mode").and_then(Value::as_str);
    let prior_config = receipt
        .get("prior_config")
        .filter(|value| value.is_null() || value.is_object());
    if !exact_identity || prior_ha_mode.is_none() || prior_config.is_none() {
        return Err(CliError::Input(
            "plan WARP Connector prior-state receipt has an invalid account, Tunnel, source, method, path, or HA state shape; create a new plan"
                .to_owned(),
        ));
    }
    let prior_ha_mode = prior_ha_mode.unwrap_or_default();
    let prior_config = prior_config.unwrap_or(&Value::Null);
    let observed_state_input = CallInput {
        selectors: json!({"account_id": plan.account_id, "tunnel_id": tunnel_id}),
        body: Some(json!({
            "ha_mode": prior_ha_mode,
            "config": prior_config,
        })),
        ..CallInput::default()
    };
    preflight_call_input(&plan.capability, &observed_state_input, None).map_err(|error| {
        CliError::Input(format!(
            "plan WARP Connector prior-state receipt is outside the exact restorable HA contract; create a new plan: {error}"
        ))
    })?;
    Ok(warp_connector_configuration_restore_body(
        prior_ha_mode,
        Some(prior_config),
    ))
}

fn required_warp_connector_configuration_state_precondition(plan: &PlanV1) -> Result<Option<&str>> {
    if !is_warp_connector_configuration_mutation(&plan.capability) {
        return Ok(None);
    }
    if !should_bind_warp_connector_configuration_state(&plan.capability) {
        return Err(CliError::Input(
            "WARP Connector plan is inconsistent with its hash-bound prior-state contract; create a new plan"
                .to_owned(),
        ));
    }
    let expected_hash = plan
        .precondition_hashes
        .get(WARP_CONNECTOR_CONFIGURATION_STATE_PRECONDITION)
        .map(String::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "plan predates the live WARP Connector prior-state contract; create a new plan"
                    .to_owned(),
            )
        })?;
    let receipt = plan
        .targets
        .pointer("/live_preconditions/warp_connector_configuration_state")
        .ok_or_else(|| {
            CliError::Input(
                "plan predates the hash-bound WARP Connector prior-state receipt; create a new plan"
                    .to_owned(),
            )
        })?;
    validate_warp_connector_configuration_prior_state_receipt(plan, receipt)?;
    if hash_value(receipt)? != expected_hash {
        return Err(CliError::Input(
            "plan WARP Connector prior-state receipt does not match its precondition hash; create a new plan"
                .to_owned(),
        ));
    }
    Ok(Some(expected_hash))
}

fn warp_connector_configuration_prior_snapshot(plan: &PlanV1) -> Result<Value> {
    required_warp_connector_configuration_state_precondition(plan)?.ok_or_else(|| {
        CliError::Input(
            "WARP Connector compensation requires a hash-bound prior-state precondition".to_owned(),
        )
    })?;
    let receipt = plan
        .targets
        .pointer("/live_preconditions/warp_connector_configuration_state")
        .ok_or_else(|| {
            CliError::Input(
                "WARP Connector compensation requires a hash-bound prior-state receipt".to_owned(),
            )
        })?;
    validate_warp_connector_configuration_prior_state_receipt(plan, receipt)
}

async fn validate_live_web_analytics_rum_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    plan: &PlanV1,
    input: &CallInput,
    credential: &AuthCredential,
) -> Result<Option<EvidenceV1>> {
    let Some(expected_hash) = required_web_analytics_rum_state_precondition(plan)? else {
        return Ok(None);
    };
    let (receipt, evidence) = read_live_web_analytics_rum_state(
        store,
        catalog,
        &plan.capability,
        input,
        &plan.account_id,
        credential,
    )
    .await?;
    if hash_value(&receipt)? != expected_hash {
        return Err(CliError::Input(
            "live Web Analytics RUM state drifted after planning; the mutation boundary was not crossed and a new plan is required"
                .to_owned(),
        ));
    }
    Ok(Some(evidence))
}

fn validate_web_analytics_rum_prior_state_receipt<'a>(
    plan: &PlanV1,
    receipt: &'a Value,
) -> Result<&'a str> {
    let zone_id = plan
        .targets
        .pointer("/selectors/zone_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "Web Analytics RUM plan omitted its hash-bound zone selector; create a new plan"
                    .to_owned(),
            )
        })?;
    let prior_value = receipt
        .get("prior_value")
        .and_then(Value::as_str)
        .filter(|value| matches!(*value, "on" | "off"));
    let exact_identity = receipt.as_object().is_some_and(|object| object.len() == 12)
        && receipt.get("schema_version").and_then(Value::as_u64) == Some(1)
        && receipt.get("source_capability_id").and_then(Value::as_str)
            == Some(WEB_ANALYTICS_RUM_READ_CAPABILITY_ID)
        && receipt.get("source_path").and_then(Value::as_str) == Some(WEB_ANALYTICS_RUM_PATH)
        && receipt.get("target_capability_id").and_then(Value::as_str)
            == Some(plan.capability.id.as_str())
        && receipt.get("target_method").and_then(Value::as_str)
            == Some(plan.capability.method.as_str())
        && receipt.get("target_path").and_then(Value::as_str)
            == Some(plan.capability.path.as_str())
        && receipt.get("target_scope").and_then(Value::as_str) == Some("zone")
        && receipt.get("account_id").and_then(Value::as_str) == Some(plan.account_id.as_str())
        && receipt.get("zone_id").and_then(Value::as_str) == Some(zone_id)
        && receipt.get("setting_id").and_then(Value::as_str) == Some("rum")
        && receipt.get("editable").and_then(Value::as_bool) == Some(true);
    if !exact_identity || prior_value.is_none() {
        return Err(CliError::Input(
            "plan Web Analytics RUM prior-state receipt has an invalid account, zone, source, method, path, editability, or on/off value; create a new plan"
                .to_owned(),
        ));
    }
    Ok(prior_value.unwrap_or_default())
}

fn required_web_analytics_rum_state_precondition(plan: &PlanV1) -> Result<Option<&str>> {
    if !is_web_analytics_rum_mutation(&plan.capability) {
        return Ok(None);
    }
    if !should_bind_web_analytics_rum_state(&plan.capability) {
        return Err(CliError::Input(
            "Web Analytics RUM plan is inconsistent with its hash-bound prior-state contract; create a new plan"
                .to_owned(),
        ));
    }
    let expected_hash = plan
        .precondition_hashes
        .get(WEB_ANALYTICS_RUM_STATE_PRECONDITION)
        .map(String::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "plan predates the live Web Analytics RUM prior-state contract; create a new plan"
                    .to_owned(),
            )
        })?;
    let receipt = plan
        .targets
        .pointer("/live_preconditions/web_analytics_rum_state")
        .ok_or_else(|| {
            CliError::Input(
                "plan predates the hash-bound Web Analytics RUM prior-state receipt; create a new plan"
                    .to_owned(),
            )
        })?;
    validate_web_analytics_rum_prior_state_receipt(plan, receipt)?;
    if hash_value(receipt)? != expected_hash {
        return Err(CliError::Input(
            "plan Web Analytics RUM prior-state receipt does not match its precondition hash; create a new plan"
                .to_owned(),
        ));
    }
    Ok(Some(expected_hash))
}

fn web_analytics_rum_prior_value(plan: &PlanV1) -> Result<&str> {
    required_web_analytics_rum_state_precondition(plan)?.ok_or_else(|| {
        CliError::Input(
            "Web Analytics RUM compensation requires a hash-bound prior-state precondition"
                .to_owned(),
        )
    })?;
    let receipt = plan
        .targets
        .pointer("/live_preconditions/web_analytics_rum_state")
        .ok_or_else(|| {
            CliError::Input(
                "Web Analytics RUM compensation requires a hash-bound prior-state receipt"
                    .to_owned(),
            )
        })?;
    validate_web_analytics_rum_prior_state_receipt(plan, receipt)
}

async fn validate_live_dns_record_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    plan: &PlanV1,
    input: &CallInput,
    credential: &AuthCredential,
) -> Result<Option<EvidenceV1>> {
    let Some(expected_hash) = required_dns_record_state_precondition(plan)? else {
        return Ok(None);
    };
    let (receipt, evidence) = read_live_dns_record_state(
        store,
        catalog,
        &plan.capability,
        input,
        &plan.account_id,
        credential,
    )
    .await?;
    if hash_value(&receipt)? != expected_hash {
        return Err(CliError::Input(
            "live DNS record state drifted after planning; the mutation boundary was not crossed and a new plan is required"
                .to_owned(),
        ));
    }
    Ok(Some(evidence))
}

async fn validate_live_oauth_client_secret_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    plan: &PlanV1,
    input: &CallInput,
    credential: &AuthCredential,
) -> Result<Option<EvidenceV1>> {
    let Some(expected_hash) = required_oauth_client_secret_state_precondition(plan)? else {
        return Ok(None);
    };
    let (receipt, evidence) = read_live_oauth_client_secret_state(
        store,
        catalog,
        &plan.capability,
        input,
        &plan.account_id,
        credential,
    )
    .await?;
    if hash_value(&receipt)? != expected_hash {
        return Err(CliError::Input(
            "live OAuth client two-secret state drifted after planning; the mutation boundary was not crossed and a new plan is required"
                .to_owned(),
        ));
    }
    Ok(Some(evidence))
}

fn validate_oauth_client_secret_state_receipt(plan: &PlanV1, receipt: &Value) -> Result<()> {
    let account_id = plan
        .targets
        .pointer("/selectors/account_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "OAuth client plan omitted its hash-bound account selector; create a new plan"
                    .to_owned(),
            )
        })?;
    let oauth_client_id = plan
        .targets
        .pointer("/selectors/oauth_client_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "OAuth client plan omitted its hash-bound client selector; create a new plan"
                    .to_owned(),
            )
        })?;
    let expected_state =
        oauth_client_secret_expected_prior_state(&plan.capability).ok_or_else(|| {
            CliError::Input(
                "OAuth client plan has an unsupported hash-bound cutover phase; create a new plan"
                    .to_owned(),
            )
        })?;
    let exact = receipt.as_object().is_some_and(|object| object.len() == 9)
        && receipt.get("schema_version").and_then(Value::as_u64) == Some(1)
        && receipt.get("source_capability_id").and_then(Value::as_str)
            == Some(OAUTH_CLIENT_DETAIL_READ_CAPABILITY_ID)
        && receipt.get("source_path").and_then(Value::as_str) == Some(OAUTH_CLIENT_DETAIL_PATH)
        && receipt.get("target_capability_id").and_then(Value::as_str)
            == Some(plan.capability.id.as_str())
        && receipt.get("target_method").and_then(Value::as_str)
            == Some(plan.capability.method.as_str())
        && receipt.get("target_scope").and_then(Value::as_str) == Some("account")
        && receipt.get("account_id").and_then(Value::as_str) == Some(account_id)
        && account_id == plan.account_id
        && receipt.get("oauth_client_id").and_then(Value::as_str) == Some(oauth_client_id)
        && receipt.get("key_overlap_active").and_then(Value::as_bool) == Some(expected_state);
    if !exact {
        return Err(CliError::Input(
            "plan OAuth client prior-state receipt has an invalid account, client, source, phase, or two-secret state; create a new plan"
                .to_owned(),
        ));
    }
    Ok(())
}

fn required_oauth_client_secret_state_precondition(plan: &PlanV1) -> Result<Option<&str>> {
    if oauth_client_secret_expected_prior_state(&plan.capability).is_none() {
        return Ok(None);
    }
    if !should_bind_oauth_client_secret_state(&plan.capability) {
        return Err(CliError::Input(
            "OAuth client secret plan is inconsistent with its hash-bound two-secret cutover contract; create a new plan"
                .to_owned(),
        ));
    }
    let expected_hash = plan
        .precondition_hashes
        .get(OAUTH_CLIENT_KEY_OVERLAP_PRECONDITION)
        .map(String::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "plan predates the live OAuth client two-secret state contract; create a new plan"
                    .to_owned(),
            )
        })?;
    let receipt = plan
        .targets
        .pointer("/live_preconditions/oauth_client_key_overlap")
        .ok_or_else(|| {
            CliError::Input(
                "plan predates the hash-bound OAuth client two-secret state receipt; create a new plan"
                    .to_owned(),
            )
        })?;
    validate_oauth_client_secret_state_receipt(plan, receipt)?;
    if hash_value(receipt)? != expected_hash {
        return Err(CliError::Input(
            "plan OAuth client prior-state receipt does not match its precondition hash; create a new plan"
                .to_owned(),
        ));
    }
    Ok(Some(expected_hash))
}

fn validate_dns_record_prior_state_receipt(plan: &PlanV1, receipt: &Value) -> Result<Value> {
    let zone_id = plan
        .targets
        .pointer("/selectors/zone_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "DNS plan omitted its hash-bound zone selector; create a new plan".to_owned(),
            )
        })?;
    let dns_record_id = plan
        .targets
        .pointer("/selectors/dns_record_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "DNS plan omitted its hash-bound record selector; create a new plan".to_owned(),
            )
        })?;
    let exact_identity = receipt.as_object().is_some_and(|object| object.len() == 10)
        && receipt.get("schema_version").and_then(Value::as_u64) == Some(1)
        && receipt.get("source_capability_id").and_then(Value::as_str)
            == Some(DNS_RECORD_DETAIL_READ_CAPABILITY_ID)
        && receipt.get("source_path").and_then(Value::as_str) == Some(DNS_RECORD_DETAIL_PATH)
        && receipt.get("target_capability_id").and_then(Value::as_str)
            == Some(plan.capability.id.as_str())
        && receipt.get("target_method").and_then(Value::as_str)
            == Some(plan.capability.method.as_str())
        && receipt.get("target_scope").and_then(Value::as_str) == Some("zone")
        && receipt.get("account_id").and_then(Value::as_str) == Some(plan.account_id.as_str())
        && receipt.get("zone_id").and_then(Value::as_str) == Some(zone_id)
        && receipt.get("dns_record_id").and_then(Value::as_str) == Some(dns_record_id);
    let prior_record = receipt.get("prior_record").ok_or_else(|| {
        CliError::Input(
            "plan DNS prior-state receipt omitted its writable record snapshot; create a new plan"
                .to_owned(),
        )
    })?;
    let projected = project_dns_record_snapshot(&plan.capability, prior_record)?;
    if !exact_identity || &projected != prior_record {
        return Err(CliError::Input(
            "plan DNS prior-state receipt has an invalid account, zone, record, source, method, or writable snapshot shape; create a new plan"
                .to_owned(),
        ));
    }
    validate_request_contract(
        &plan.capability,
        &CallInput {
            selectors: json!({"zone_id":zone_id,"dns_record_id":dns_record_id}),
            query: json!({}),
            body: Some(projected.clone()),
            ..CallInput::default()
        },
    )?;
    Ok(projected)
}

fn required_dns_record_state_precondition(plan: &PlanV1) -> Result<Option<&str>> {
    if !is_dns_record_update_mutation(&plan.capability) {
        return Ok(None);
    }
    if !should_bind_dns_record_state(&plan.capability) {
        return Err(CliError::Input(
            "DNS record plan is inconsistent with its hash-bound prior-state contract; create a new plan"
                .to_owned(),
        ));
    }
    let expected_hash = plan
        .precondition_hashes
        .get(DNS_RECORD_STATE_PRECONDITION)
        .map(String::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "plan predates the live DNS record prior-state contract; create a new plan"
                    .to_owned(),
            )
        })?;
    let receipt = plan
        .targets
        .pointer("/live_preconditions/dns_record_state")
        .ok_or_else(|| {
            CliError::Input(
                "plan predates the hash-bound DNS record prior-state receipt; create a new plan"
                    .to_owned(),
            )
        })?;
    validate_dns_record_prior_state_receipt(plan, receipt)?;
    if hash_value(receipt)? != expected_hash {
        return Err(CliError::Input(
            "plan DNS record prior-state receipt does not match its precondition hash; create a new plan"
                .to_owned(),
        ));
    }
    Ok(Some(expected_hash))
}

fn dns_record_prior_snapshot(plan: &PlanV1) -> Result<Value> {
    required_dns_record_state_precondition(plan)?.ok_or_else(|| {
        CliError::Input(
            "DNS record compensation requires a hash-bound prior-state precondition".to_owned(),
        )
    })?;
    let receipt = plan
        .targets
        .pointer("/live_preconditions/dns_record_state")
        .ok_or_else(|| {
            CliError::Input(
                "DNS record compensation requires a hash-bound prior-state receipt".to_owned(),
            )
        })?;
    validate_dns_record_prior_state_receipt(plan, receipt)
}

async fn validate_live_zone_account_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    plan: &PlanV1,
    input: &CallInput,
    credential: &AuthCredential,
) -> Result<Option<EvidenceV1>> {
    let Some(expected_hash) = required_zone_account_precondition(plan)? else {
        return Ok(None);
    };
    let (receipt, evidence) = read_live_zone_account(
        store,
        catalog,
        &plan.capability,
        input,
        &plan.account_id,
        credential,
    )
    .await?;
    validate_zone_account_receipt_precondition(expected_hash, &receipt)?;
    Ok(Some(evidence))
}

fn validate_zone_account_receipt_precondition(expected_hash: &str, receipt: &Value) -> Result<()> {
    if hash_value(receipt)? != expected_hash {
        return Err(CliError::Input(
            "live zone-account ownership drifted after planning; the mutation boundary was not crossed and a new plan is required"
                .to_owned(),
        ));
    }
    Ok(())
}

fn required_zone_account_precondition(plan: &PlanV1) -> Result<Option<&str>> {
    if !plan.capability.mutating || plan.capability.account_scope != "zone" {
        return Ok(None);
    }
    plan.precondition_hashes
        .get("zone_account")
        .map(String::as_str)
        .map(Some)
        .ok_or_else(|| {
            CliError::Input(
                "plan predates the live zone-account ownership contract; create a new plan"
                    .to_owned(),
            )
        })
}

async fn validate_live_entitlement_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    plan: &PlanV1,
    input: &CallInput,
    credential: &AuthCredential,
) -> Result<Option<EvidenceV1>> {
    let Some(expected_hash) = required_entitlement_precondition(plan)? else {
        return Ok(None);
    };
    let mut capability = plan.capability.clone();
    let (receipt, evidence) =
        read_live_zone_entitlement(store, catalog, &mut capability, input, credential).await?;
    validate_entitlement_receipt_precondition(expected_hash, &capability, &receipt)?;
    Ok(Some(evidence))
}

fn required_entitlement_precondition(plan: &PlanV1) -> Result<Option<&str>> {
    if !plan.capability.entitlement.requires_live_resolution {
        return Ok(None);
    }
    if plan.capability.account_scope != "zone"
        || plan.capability.entitlement.available != Some(true)
    {
        return Err(CliError::Input(
            "plan entitlement precondition is inconsistent with its hash-bound zone capability; create a new plan"
                .to_owned(),
        ));
    }
    plan.precondition_hashes
        .get("entitlement")
        .map(String::as_str)
        .map(Some)
        .ok_or_else(|| {
            CliError::Input(
                "plan predates the live zone-entitlement contract; create a new plan".to_owned(),
            )
        })
}

fn validate_entitlement_receipt_precondition(
    expected_hash: &str,
    capability: &CapabilityV1,
    receipt: &Value,
) -> Result<()> {
    let actual_hash = hash_value(receipt)?;
    if actual_hash != expected_hash || capability.entitlement.available != Some(true) {
        return Err(CliError::Input(
            "live zone entitlement drifted after planning; the mutation boundary was not crossed and a new plan is required"
                .to_owned(),
        ));
    }
    Ok(())
}

async fn validate_live_permission_inventory_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    plan: &PlanV1,
    credential: &AuthCredential,
    standing_authority: Option<&StandingAuthorityV1>,
) -> Result<Option<EvidenceV1>> {
    let Some(expected_inventory) = token_permission_inventory_contract(&plan.capability.id) else {
        return Ok(None);
    };
    let inventory_contract = plan
        .targets
        .pointer("/adapter/permission_inventory")
        .ok_or_else(|| {
            CliError::Input(
                "token mint plan predates the live permission-inventory contract; create a new plan"
                    .to_owned(),
            )
        })?;
    let source_capability_id = inventory_contract
        .get("source_capability_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input("token mint permission-inventory capability is missing".to_owned())
        })?;
    let source_capability = catalog.get(source_capability_id).ok_or_else(|| {
        CliError::Input(format!(
            "token mint permission-inventory capability `{source_capability_id}` no longer exists"
        ))
    })?;
    if source_capability.id != expected_inventory.capability_id
        || source_capability.method != "GET"
        || source_capability.path != expected_inventory.path
    {
        return Err(CliError::Input(
            "token mint permission-inventory capability drifted from its governed owner-specific read"
                .to_owned(),
        ));
    }
    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let response = executor
        .execute_read(
            source_capability,
            &CallInput {
                selectors: if expected_inventory.account_selector {
                    json!({"account_id": plan.account_id})
                } else {
                    json!({})
                },
                query: json!({}),
                body: None,
                ..CallInput::default()
            },
            credential,
        )
        .await?;
    if !response.success {
        return Err(CliError::Input(
            "Cloudflare rejected the permission-inventory precondition read; the token mint boundary was not crossed"
                .to_owned(),
        ));
    }
    validate_current_permission_groups(inventory_contract, &response.result)?;
    if let Some(authority) = standing_authority {
        validate_standing_authority_permission_inventory(authority, &response.result)?;
    }
    let evidence =
        store.write_evidence(EvidenceClass::LiveRead, &serde_json::to_value(&response)?)?;
    Ok(Some(evidence))
}

fn validate_current_permission_groups(inventory_contract: &Value, current: &Value) -> Result<()> {
    let selected_groups = inventory_contract
        .get("selected_groups")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CliError::Input("token mint selected permission groups are missing".to_owned())
        })?;
    let selected_ids = selected_groups
        .iter()
        .map(|group| {
            group
                .get("id")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| {
                    CliError::Input(
                        "token mint selected permission group is missing an ID".to_owned(),
                    )
                })
        })
        .collect::<Result<Vec<_>>>()?;
    let expected_hash = inventory_contract
        .get("selected_groups_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input("token mint selected permission-group hash is missing".to_owned())
        })?;
    let current_groups = validate_selected_permission_groups(&selected_ids, current)?;
    let current_hash = hash_value(&serde_json::to_value(&current_groups)?)?;
    if current_hash != expected_hash {
        return Err(CliError::Input(
            "selected permission-group metadata drifted after planning; create and review a new token mint plan"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_standing_authority_permission_inventory(
    authority: &StandingAuthorityV1,
    current: &Value,
) -> Result<()> {
    let current_allowlist =
        validate_selected_permission_groups(&authority.permission_group_ids, current)?;
    authority.validate_permission_inventory(&Value::Array(current_allowlist))?;
    Ok(())
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
            let error = CliError::from(error);
            return Ok(process_api_transport_failure(store, plan, &error, secrets));
        }
    };
    let (response_value, apply_evidence, lineage_evidence) =
        match process_api_boundary_response(store, plan, &response, secrets)? {
            ApiBoundaryResponseOutcome::Ready {
                response_value,
                apply_evidence,
                lineage_evidence,
            } => (response_value, apply_evidence, lineage_evidence),
            ApiBoundaryResponseOutcome::Recovery(envelope) => return Ok(envelope),
        };
    let performed = response.success;
    let verification = match verify_api_plan(store, &executor, plan, &response, credential).await {
        Ok(verification) => verification,
        Err(error) => {
            return Ok(post_boundary_failure_envelope(
                plan,
                response_value,
                Some(apply_evidence),
                lineage_evidence,
                &error,
                performed,
                "the Cloudflare boundary response and secret lifecycle are durable, but verification could not complete",
            ));
        }
    };
    let finalization: Result<()> =
        if matches!(plan.status, PlanStatus::Verified | PlanStatus::Failed) {
            persist_transaction_stage(store, plan, TransactionStageV1::Closed)
        } else {
            store.save_plan(plan).map_err(CliError::from)
        };
    let finalization_error = finalization.err();
    Ok(api_plan_result_envelope(
        plan,
        response_value,
        apply_evidence,
        lineage_evidence,
        verification,
        performed,
        finalization_error.as_ref(),
    ))
}

enum ApiBoundaryResponseOutcome {
    Ready {
        response_value: Value,
        apply_evidence: EvidenceV1,
        lineage_evidence: Option<EvidenceV1>,
    },
    Recovery(ResultEnvelopeV2),
}

/// Persists the non-secret response receipt, always attempts the one-time
/// secret sink, and reconciles lineage only when the boundary receipt was
/// durably saved. Any local failure after a successful response returns a
/// no-replay recovery envelope instead of losing boundary truth through the
/// generic top-level error path.
fn process_api_boundary_response(
    store: &StateStore,
    plan: &mut PlanV1,
    response: &CloudflareResponseV1,
    secrets: &dyn SecretStore,
) -> Result<ApiBoundaryResponseOutcome> {
    let mut response_value = serde_json::to_value(response)?;
    if is_secret_output_plan(plan) {
        response_value = redact_secret_result(&response_value);
    }
    let mut failures = Vec::new();
    let apply_evidence = match store.write_evidence(EvidenceClass::Apply, &response_value) {
        Ok(evidence) => Some(evidence),
        Err(error) => {
            plan.status = PlanStatus::RectificationRequired;
            failures.push(format!("apply evidence persistence failed: {error}"));
            None
        }
    };
    let boundary_response_persisted = match persist_transaction_stage_with_artifact(
        store,
        plan,
        TransactionStageV1::BoundaryResponsePersisted,
        boundary_response_artifact(plan, response, apply_evidence.as_ref()),
    ) {
        Ok(()) => true,
        Err(error) => {
            plan.status = PlanStatus::RectificationRequired;
            failures.push(format!("boundary response persistence failed: {error}"));
            false
        }
    };
    let lifecycle = persist_secret_lifecycle_and_reconcile_lineage(
        store,
        plan,
        response.success,
        Some(&response.result),
        secrets,
        boundary_response_persisted,
    );
    if let Some(error) = lifecycle.error {
        failures.push(error.to_string());
    }
    if !failures.is_empty() {
        let error = CliError::Input(failures.join("; "));
        let verification_basis = if boundary_response_persisted {
            "the Cloudflare boundary response is durable, but local post-boundary recovery is required before verification can be trusted"
        } else {
            "Cloudflare returned a mutation response, but the boundary receipt is not durably validated; the one-time secret sink was still attempted and the mutation must not be replayed"
        };
        return Ok(ApiBoundaryResponseOutcome::Recovery(
            post_boundary_failure_envelope(
                plan,
                response_value,
                apply_evidence,
                lifecycle.lineage_evidence,
                &error,
                response.success,
                verification_basis,
            ),
        ));
    }
    let Some(apply_evidence) = apply_evidence else {
        return Err(CliError::Input(
            "post-boundary response handling lost its apply evidence without recording a recovery failure"
                .to_owned(),
        ));
    };
    Ok(ApiBoundaryResponseOutcome::Ready {
        response_value,
        apply_evidence,
        lineage_evidence: lifecycle.lineage_evidence,
    })
}

/// A transport error after `BoundaryAttemptPersisted` cannot prove that the
/// remote mutation did not happen. Persist as much local recovery state as
/// possible and return an operation-bound unknown-outcome envelope.
fn process_api_transport_failure(
    store: &StateStore,
    plan: &mut PlanV1,
    transport_error: &CliError,
    secrets: &dyn SecretStore,
) -> ResultEnvelopeV2 {
    plan.status = PlanStatus::RectificationRequired;
    let mut failures = vec![format!(
        "Cloudflare mutation outcome is unknown after the request crossed the boundary: {transport_error}"
    )];
    if let Err(error) = persist_transaction_stage_with_artifact(
        store,
        plan,
        TransactionStageV1::BoundaryResponsePersisted,
        boundary_failure_artifact("dynamic_api", "transport_error"),
    ) {
        failures.push(format!(
            "unknown-outcome boundary receipt persistence failed: {error}"
        ));
    }
    if let Err(error) = persist_secret_lifecycle(store, plan, false, None, secrets) {
        failures.push(format!(
            "unknown-outcome secret lifecycle persistence failed: {error}"
        ));
    }
    let error = CliError::Input(failures.join("; "));
    post_boundary_failure_envelope(
        plan,
        json!({
            "success": false,
            "outcome": "unknown",
            "receipt_available": false,
        }),
        None,
        None,
        &error,
        false,
        "the mutation request was sent, but no Cloudflare response was received; the remote outcome is unknown and must be rectified without replay",
    )
}

fn api_plan_result_envelope(
    plan: &PlanV1,
    result: Value,
    apply_evidence: EvidenceV1,
    lineage_evidence: Option<EvidenceV1>,
    verification: ApiVerificationOutcome,
    performed: bool,
    finalization_error: Option<&CliError>,
) -> ResultEnvelopeV2 {
    if let Some(error) = finalization_error {
        let mut envelope = post_boundary_failure_envelope(
            plan,
            result,
            Some(apply_evidence),
            lineage_evidence,
            error,
            performed,
            "the Cloudflare boundary response is durable, but the final local checkpoint requires recovery",
        );
        envelope.verification.state = verification.state;
        envelope.verification.basis = Some(format!(
            "{}; the final plan checkpoint could not be persisted",
            verification.basis
        ));
        if let Some(evidence) = verification.evidence {
            envelope.evidence.push(evidence);
        }
        return envelope;
    }
    let mut envelope = ResultEnvelopeV2::success("plans run", result).with_evidence(apply_evidence);
    if let Some(evidence) = lineage_evidence {
        envelope.evidence.push(evidence);
    }
    if let Some(evidence) = verification.evidence {
        envelope.evidence.push(evidence);
    }
    envelope.ok = performed && plan.status == PlanStatus::Verified;
    envelope.performed = performed;
    envelope.operation_id = Some(plan.operation_id.clone());
    envelope.capability_id = Some(plan.capability.id.clone());
    envelope.profile_id = Some(plan.profile_id.clone());
    envelope.account_id = Some(plan.account_id.clone());
    envelope.policy_decision = Some(plan.policy.clone());
    envelope.verification.state = verification.state;
    envelope.verification.basis = Some(verification.basis);
    envelope.error = verification.error;
    envelope
}

struct ApiVerificationOutcome {
    state: VerificationState,
    basis: String,
    evidence: Option<EvidenceV1>,
    error: Option<ErrorV1>,
}

fn post_boundary_failure_envelope(
    plan: &PlanV1,
    result: Value,
    apply_evidence: Option<EvidenceV1>,
    lineage_evidence: Option<EvidenceV1>,
    error: &CliError,
    performed: bool,
    verification_basis: &str,
) -> ResultEnvelopeV2 {
    let next_step = format!(
        "Do not replay the mutation; run `cfctl plans rectify {}`.",
        plan.operation_id
    );
    let mut envelope = ResultEnvelopeV2::failure(
        "plans run",
        "CFCTL_POST_BOUNDARY_RECOVERY_REQUIRED",
        &error.to_string(),
        Some(&next_step),
    );
    envelope.result = redact_json(&result);
    envelope.performed = performed;
    envelope.operation_id = Some(plan.operation_id.clone());
    envelope.capability_id = Some(plan.capability.id.clone());
    envelope.profile_id = Some(plan.profile_id.clone());
    envelope.account_id = Some(plan.account_id.clone());
    envelope.policy_decision = Some(plan.policy.clone());
    envelope.verification.state = VerificationState::Pending;
    envelope.verification.basis = Some(verification_basis.to_owned());
    if let Some(evidence) = apply_evidence {
        envelope.evidence.push(evidence);
    }
    if let Some(evidence) = lineage_evidence {
        envelope.evidence.push(evidence);
    }
    envelope
}

fn boundary_response_artifact(
    plan: &PlanV1,
    response: &CloudflareResponseV1,
    apply_evidence: Option<&EvidenceV1>,
) -> Value {
    let identity_pointer = plan
        .capability
        .created_resource
        .as_ref()
        .map(|target| target.response_result_identity_pointer.as_str())
        .or_else(|| {
            plan.capability
                .created_collection_resource
                .as_ref()
                .map(|target| target.response_result_identity_pointer.as_str())
        })
        .unwrap_or("/id");
    json!({
        "apply_evidence_hash": apply_evidence.map(|evidence| evidence.content_hash.as_str()),
        "http_status": response.status,
        "success": response.success,
        "resource_id": response.result.pointer(identity_pointer).and_then(Value::as_str),
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
            "format": secret_sink_format(&plan.capability),
            "unix_mode": cfg!(unix).then_some("0600"),
        },
        "path": path.map(|path| path.display().to_string()),
    })
}

/// Persists the secret-sink outcome and then reconciles token lineage from the
/// already-durable boundary receipt regardless of whether the sink succeeded.
/// A post-boundary error always directs the operator to rectification; replay
/// is never an acceptable recovery path.
struct PostBoundaryLifecycleOutcome {
    lineage_evidence: Option<EvidenceV1>,
    error: Option<CliError>,
}

fn persist_secret_lifecycle_and_reconcile_lineage(
    store: &StateStore,
    plan: &mut PlanV1,
    response_success: bool,
    response_result: Option<&Value>,
    secrets: &dyn SecretStore,
    boundary_response_durable: bool,
) -> PostBoundaryLifecycleOutcome {
    let secret_sink_result =
        persist_secret_lifecycle(store, plan, response_success, response_result, secrets);
    let lineage_result = if boundary_response_durable {
        reconcile_standing_lineage_from_plan(store, plan)
    } else {
        Ok(None)
    };
    match (secret_sink_result, lineage_result) {
        (Ok(_sink_path), Ok(lineage_evidence)) => PostBoundaryLifecycleOutcome {
            lineage_evidence,
            error: None,
        },
        (Err(sink_error), Ok(lineage_evidence)) => PostBoundaryLifecycleOutcome {
            lineage_evidence,
            error: Some(CliError::Input(format!(
                "the Cloudflare boundary response was persisted, but the secret sink failed: {sink_error}. Do not replay the mutation; run `cfctl plans rectify {}`",
                plan.operation_id
            ))),
        },
        (Ok(_), Err(lineage_error)) => PostBoundaryLifecycleOutcome {
            lineage_evidence: None,
            error: Some(CliError::Input(format!(
                "the Cloudflare boundary response was persisted, but standing token lineage reconciliation failed: {lineage_error}. Do not replay the mutation; run `cfctl plans rectify {}`",
                plan.operation_id
            ))),
        },
        (Err(sink_error), Err(lineage_error)) => PostBoundaryLifecycleOutcome {
            lineage_evidence: None,
            error: Some(CliError::Input(format!(
                "the Cloudflare boundary response was persisted, but both the secret sink and standing token lineage reconciliation failed (sink: {sink_error}; lineage: {lineage_error}). Do not replay the mutation; run `cfctl plans rectify {}`",
                plan.operation_id
            ))),
        },
    }
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
            basis: non_readback_verification_basis(&plan.capability),
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

fn non_readback_verification_basis(capability: &CapabilityV1) -> String {
    if capability.verification.strategy == "sink_write_and_source_response_status" {
        "Cloudflare returned success and the required sink-only secret output was durably persisted"
            .to_owned()
    } else {
        "operation declares no post-change verifier".to_owned()
    }
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
    expected_method: String,
    expected_path: String,
    input: CallInput,
    requested_account: Option<String>,
}

struct CompensationTarget {
    capability_id: String,
    expected_method: String,
    expected_path: String,
    selectors: Value,
    body: Option<Value>,
}

fn validate_compensation_contract(capability: &CapabilityV1) -> Result<()> {
    if capability.rollback_contract_supported() {
        return Ok(());
    }
    Err(CliError::Input(format!(
        "rollback strategy `{}` is not implemented for capability `{}`; inspect live state before compensating",
        capability
            .rollback
            .strategy
            .as_deref()
            .unwrap_or("<missing>"),
        capability.id
    )))
}

fn global_warp_override_compensation_request(plan: &PlanV1) -> Result<CompensationRequest> {
    Ok(CompensationRequest {
        capability_id: GLOBAL_WARP_OVERRIDE_MUTATION_CAPABILITY_ID.to_owned(),
        expected_method: "POST".to_owned(),
        expected_path: GLOBAL_WARP_OVERRIDE_PATH.to_owned(),
        input: CallInput {
            selectors: json!({"account_id": plan.account_id}),
            query: json!({}),
            body: Some(json!({
                "disconnect": global_warp_override_prior_disconnect_state(plan)?,
            })),
            ..CallInput::default()
        },
        requested_account: Some(plan.account_id.clone()),
    })
}

fn d1_read_replication_compensation_request(plan: &PlanV1) -> Result<CompensationRequest> {
    let database_id = plan
        .targets
        .pointer("/selectors/database_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input("D1 compensation requires a hash-bound database selector".to_owned())
        })?;
    Ok(CompensationRequest {
        capability_id: plan.capability.id.clone(),
        expected_method: plan.capability.method.clone(),
        expected_path: D1_READ_REPLICATION_PATH.to_owned(),
        input: CallInput {
            selectors: json!({
                "account_id": plan.account_id,
                "database_id": database_id,
            }),
            query: json!({}),
            body: Some(json!({
                "read_replication": {
                    "mode": d1_read_replication_prior_mode(plan)?,
                },
            })),
            ..CallInput::default()
        },
        requested_account: Some(plan.account_id.clone()),
    })
}

fn cloudflare_tunnel_configuration_compensation_request(
    plan: &PlanV1,
) -> Result<CompensationRequest> {
    let tunnel_id = plan
        .targets
        .pointer("/selectors/tunnel_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "Tunnel configuration compensation requires a hash-bound Tunnel selector"
                    .to_owned(),
            )
        })?;
    Ok(CompensationRequest {
        capability_id: CLOUDFLARE_TUNNEL_CONFIGURATION_MUTATION_CAPABILITY_ID.to_owned(),
        expected_method: "PUT".to_owned(),
        expected_path: CLOUDFLARE_TUNNEL_CONFIGURATION_PATH.to_owned(),
        input: CallInput {
            selectors: json!({
                "account_id": plan.account_id,
                "tunnel_id": tunnel_id,
            }),
            query: json!({}),
            body: Some(json!({
                "config": cloudflare_tunnel_configuration_prior_snapshot(plan)?,
            })),
            ..CallInput::default()
        },
        requested_account: Some(plan.account_id.clone()),
    })
}

fn warp_connector_configuration_compensation_request(plan: &PlanV1) -> Result<CompensationRequest> {
    let tunnel_id = plan
        .targets
        .pointer("/selectors/tunnel_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "WARP Connector compensation requires a hash-bound Tunnel selector".to_owned(),
            )
        })?;
    Ok(CompensationRequest {
        capability_id: WARP_CONNECTOR_CONFIGURATION_MUTATION_CAPABILITY_ID.to_owned(),
        expected_method: "PUT".to_owned(),
        expected_path: WARP_CONNECTOR_CONFIGURATION_PATH.to_owned(),
        input: CallInput {
            selectors: json!({
                "account_id": plan.account_id,
                "tunnel_id": tunnel_id,
            }),
            query: json!({}),
            body: Some(warp_connector_configuration_prior_snapshot(plan)?),
            ..CallInput::default()
        },
        requested_account: Some(plan.account_id.clone()),
    })
}

fn web_analytics_rum_compensation_request(plan: &PlanV1) -> Result<CompensationRequest> {
    let zone_id = plan
        .targets
        .pointer("/selectors/zone_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "Web Analytics RUM compensation requires a hash-bound zone selector".to_owned(),
            )
        })?;
    Ok(CompensationRequest {
        capability_id: WEB_ANALYTICS_RUM_MUTATION_CAPABILITY_ID.to_owned(),
        expected_method: "PATCH".to_owned(),
        expected_path: WEB_ANALYTICS_RUM_PATH.to_owned(),
        input: CallInput {
            selectors: json!({"zone_id": zone_id}),
            query: json!({}),
            body: Some(json!({"value": web_analytics_rum_prior_value(plan)?})),
            ..CallInput::default()
        },
        requested_account: Some(plan.account_id.clone()),
    })
}

fn dns_record_compensation_request(plan: &PlanV1) -> Result<CompensationRequest> {
    let zone_id = plan
        .targets
        .pointer("/selectors/zone_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "DNS record compensation requires a hash-bound zone selector".to_owned(),
            )
        })?;
    let dns_record_id = plan
        .targets
        .pointer("/selectors/dns_record_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "DNS record compensation requires a hash-bound record selector".to_owned(),
            )
        })?;
    Ok(CompensationRequest {
        capability_id: DNS_RECORD_RESTORE_CAPABILITY_ID.to_owned(),
        expected_method: "PUT".to_owned(),
        expected_path: DNS_RECORD_DETAIL_PATH.to_owned(),
        input: CallInput {
            selectors: json!({
                "zone_id": zone_id,
                "dns_record_id": dns_record_id,
            }),
            query: json!({}),
            body: Some(dns_record_prior_snapshot(plan)?),
            ..CallInput::default()
        },
        requested_account: Some(plan.account_id.clone()),
    })
}

fn compensation_resource_id(artifact: &Value) -> Result<&str> {
    artifact
        .get("resource_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "the creation response is recorded, but its hash-bound receipt has no resource id; inspect live resource state before compensating"
                    .to_owned(),
            )
        })
}

fn operation_specific_compensation_request(plan: &PlanV1) -> Result<Option<CompensationRequest>> {
    let request = if plan.capability.id == GLOBAL_WARP_OVERRIDE_MUTATION_CAPABILITY_ID {
        global_warp_override_compensation_request(plan)?
    } else if is_d1_read_replication_mutation(&plan.capability) {
        d1_read_replication_compensation_request(plan)?
    } else if is_cloudflare_tunnel_configuration_mutation(&plan.capability) {
        cloudflare_tunnel_configuration_compensation_request(plan)?
    } else if is_warp_connector_configuration_mutation(&plan.capability) {
        warp_connector_configuration_compensation_request(plan)?
    } else if is_web_analytics_rum_mutation(&plan.capability) {
        web_analytics_rum_compensation_request(plan)?
    } else if is_dns_record_update_mutation(&plan.capability) {
        dns_record_compensation_request(plan)?
    } else {
        return Ok(None);
    };
    Ok(Some(request))
}

fn compensation_request(plan: &PlanV1) -> Result<Option<CompensationRequest>> {
    if !matches!(
        plan.status,
        PlanStatus::Consumed | PlanStatus::Running | PlanStatus::RectificationRequired
    ) || !plan.capability.rollback.supported
    {
        return Ok(None);
    }
    validate_compensation_contract(&plan.capability)?;
    let Some(artifact) = plan.transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
    else {
        return Ok(None);
    };
    if artifact.get("success").and_then(Value::as_bool) != Some(true) {
        return Ok(None);
    }
    if let Some(request) = operation_specific_compensation_request(plan)? {
        return Ok(Some(request));
    }
    let resource_id = compensation_resource_id(artifact)?;
    let Some(target) = created_resource_compensation_target(plan, resource_id)? else {
        return Ok(None);
    };
    Ok(Some(CompensationRequest {
        capability_id: target.capability_id,
        expected_method: target.expected_method,
        expected_path: target.expected_path,
        input: CallInput {
            selectors: target.selectors,
            query: json!({}),
            body: target.body,
            ..CallInput::default()
        },
        requested_account: Some(plan.account_id.clone()),
    }))
}

fn created_resource_compensation_target(
    plan: &PlanV1,
    resource_id: &str,
) -> Result<Option<CompensationTarget>> {
    let (capability_id, expected_method, expected_path, selectors, body) = match plan
        .capability
        .id
        .as_str()
    {
        "account-api-tokens-create-token" => (
            "account-api-tokens-delete-token".to_owned(),
            "DELETE".to_owned(),
            "/accounts/{account_id}/tokens/{token_id}".to_owned(),
            json!({"account_id": plan.account_id, "token_id": resource_id}),
            None,
        ),
        "user-api-tokens-create-token" => (
            "user-api-tokens-delete-token".to_owned(),
            "DELETE".to_owned(),
            "/user/tokens/{token_id}".to_owned(),
            json!({"token_id": resource_id}),
            None,
        ),
        "dns-records-for-a-zone-create-dns-record" => {
            let input: CallInput = serde_json::from_value(plan.input.clone())?;
            let zone_id = input
                .selectors
                .get("zone_id")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    CliError::Input(
                        "the DNS record creation receipt is valid, but its source plan has no zone_id selector; inspect live DNS state before compensating"
                            .to_owned(),
                    )
                })?;
            (
                "dns-records-for-a-zone-delete-dns-record".to_owned(),
                "DELETE".to_owned(),
                "/zones/{zone_id}/dns_records/{dns_record_id}".to_owned(),
                json!({"zone_id": zone_id, "dns_record_id": resource_id}),
                None,
            )
        }
        D1_DATABASE_CREATE_CAPABILITY_ID => {
            if plan.capability.rollback.strategy.as_deref()
                != Some(D1_EMPTY_DATABASE_COMPENSATION_STRATEGY)
            {
                return Ok(None);
            }
            let (capability_id, expected_path, selectors) =
                generic_created_resource_compensation(plan, resource_id)?;
            (
                capability_id,
                "DELETE".to_owned(),
                expected_path,
                selectors,
                None,
            )
        }
        _ => {
            if plan.capability.rollback.strategy.as_deref()
                != Some("delete_created_resource_by_returned_id")
            {
                return Ok(None);
            }
            let (capability_id, expected_path, selectors) =
                generic_created_resource_compensation(plan, resource_id)?;
            (
                capability_id,
                "DELETE".to_owned(),
                expected_path,
                selectors,
                None,
            )
        }
    };
    Ok(Some(CompensationTarget {
        capability_id,
        expected_method,
        expected_path,
        selectors,
        body,
    }))
}

fn generic_created_resource_compensation(
    plan: &PlanV1,
    resource_id: &str,
) -> Result<(String, String, Value)> {
    let input: CallInput = serde_json::from_value(plan.input.clone())?;
    let mut selectors = input.selectors.as_object().cloned().ok_or_else(|| {
        CliError::Input(
            "the creation receipt is valid, but its source selectors are not an object; inspect live resource state before compensating"
                .to_owned(),
        )
    })?;
    let (identity_selector, delete_capability_id, expected_path) = if let Some(target) =
        plan.capability.created_resource.as_ref()
    {
        (
            target.identity_selector.as_str(),
            target.delete_capability_id.clone(),
            target.detail_path.clone(),
        )
    } else if let Some(target) = plan.capability.created_collection_resource.as_ref() {
        (
            target.identity_selector.as_str(),
            target.delete_capability_id.clone(),
            format!(
                "{}/{{{}}}",
                target.collection_path.trim_end_matches('/'),
                target.identity_selector
            ),
        )
    } else {
        return Err(CliError::Input(
                "the rollback strategy names created-resource deletion, but the hash-bound resource target is absent"
                    .to_owned(),
            ));
    };
    selectors.insert(
        identity_selector.to_owned(),
        Value::String(resource_id.to_owned()),
    );
    Ok((
        delete_capability_id,
        expected_path,
        Value::Object(selectors),
    ))
}

fn bind_required_empty_compensation_body(
    request: &mut CompensationRequest,
    capability: &cfctl_core::CapabilityV1,
) {
    if request.expected_method == "DELETE"
        && capability.method == request.expected_method
        && capability.path == request.expected_path
        && request.input.body.is_none()
        && capability.required_empty_request_body_contract()
    {
        request.input.body = Some(json!({}));
    }
}

async fn rectify_plan(store: &StateStore, selector: &PlanSelector) -> Result<ResultEnvelopeV2> {
    let _plan_lock = store.lock_plan(&selector.operation_id)?;
    let plan = load_validated_plan(store, &selector.operation_id)?;
    let lineage_evidence = reconcile_standing_lineage_from_plan(store, &plan)?;
    if let Some(mut request) = compensation_request(&plan)? {
        let catalog = ensure_catalog(store).await?;
        let capability = catalog
            .get(&request.capability_id)
            .cloned()
            .ok_or_else(|| capability_missing(&request.capability_id))?;
        if capability.method != request.expected_method || capability.path != request.expected_path
        {
            return Err(CliError::Input(format!(
                "compensation target `{}` no longer resolves to the hash-bound {} path; inspect live resource state before creating a replacement plan",
                request.capability_id, request.expected_method
            )));
        }
        bind_required_empty_compensation_body(&mut request, &capability);
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
                "compensation_strategy": plan.capability.rollback.strategy,
                "source_receipt_hash": source_receipt_hash,
                "source_precondition_hash": plan
                    .precondition_hashes
                    .get("global_warp_override_state")
                    .or_else(|| plan.precondition_hashes.get(D1_READ_REPLICATION_PRECONDITION))
                    .or_else(|| plan.precondition_hashes.get(DNS_RECORD_STATE_PRECONDITION)),
            }),
        )
        .await?;
        "plans rectify".clone_into(&mut envelope.command);
        if let Some(result) = envelope.result.as_object_mut() {
            result.insert(
                "compensates_operation_id".to_owned(),
                Value::String(plan.operation_id.clone()),
            );
            result.insert(
                "message".to_owned(),
                Value::String(
                    "A separate hash-bound compensation plan was created from the source plan receipts. It has not run; review and explicitly approve its operation ID."
                        .to_owned(),
                ),
            );
        }
        if let Some(evidence) = lineage_evidence {
            envelope.evidence.push(evidence);
        }
        return Ok(envelope);
    }
    let mut envelope = ResultEnvelopeV2::success(
        "plans rectify",
        json!({
            "operation_id": plan.operation_id,
            "status": plan.status,
            "compensation_steps": plan.compensation_steps,
            "verification_steps": plan.verification_steps,
            "non_reversible_warnings": plan.non_reversible_warnings,
            "message": "No safe automatic compensation plan can be derived from the hash-bound receipts for this capability. Inspect live state with the catalog, then create a new hash-bound plan."
        }),
    );
    if let Some(evidence) = lineage_evidence {
        envelope.evidence.push(evidence);
    }
    Ok(envelope)
}

async fn keys_command(store: &StateStore, command: KeysCommand) -> Result<ResultEnvelopeV2> {
    match command {
        KeysCommand::Permissions(arguments) => key_permissions(store, &arguments).await,
        KeysCommand::Mint(arguments) => {
            preflight_standing_authority(store, arguments.under_policy.as_deref())?;
            let plan = key_mint(store, &arguments).await?;
            finish_standing_run(store, plan, arguments.under_policy.as_deref()).await
        }
        KeysCommand::Rotate(arguments) => key_rotate(store, &arguments).await,
        KeysCommand::Revoke(arguments) => {
            preflight_standing_authority(store, arguments.under_policy.as_deref())?;
            let plan = key_revoke(store, &arguments).await?;
            finish_standing_run(store, plan, arguments.under_policy.as_deref()).await
        }
        KeysCommand::Policy(arguments) => key_policy(store, arguments.command).await,
    }
}

/// Fails a standing run closed before any live read or plan creation when
/// the named authority is missing, unapproved, revoked, or expired.
fn preflight_standing_authority(store: &StateStore, under_policy: Option<&str>) -> Result<()> {
    if let Some(authority_id) = under_policy {
        recover_standing_lineage(store, authority_id)?;
        store.load_authority(authority_id)?.ensure_operational()?;
    }
    Ok(())
}

/// When `--under-policy` names a standing authority, the freshly created plan
/// is immediately validated against the authority's bounds and executed in
/// the same invocation; otherwise the plan envelope is returned for the
/// ordinary per-operation approval ceremony.
async fn finish_standing_run(
    store: &StateStore,
    plan_envelope: ResultEnvelopeV2,
    under_policy: Option<&str>,
) -> Result<ResultEnvelopeV2> {
    let Some(authority_id) = under_policy else {
        return Ok(plan_envelope);
    };
    let Some(operation_id) = plan_envelope.operation_id.clone() else {
        return Err(CliError::Input(
            "a standing run requires the plan envelope to carry an operation id".to_owned(),
        ));
    };
    run_plan_under_standing_authority(store, &operation_id, authority_id).await
}

async fn key_policy(store: &StateStore, command: KeyPolicyCommand) -> Result<ResultEnvelopeV2> {
    match command {
        KeyPolicyCommand::Create(arguments) => key_policy_create(store, &arguments).await,
        KeyPolicyCommand::List => key_policy_list(store),
        KeyPolicyCommand::Approve(arguments) => key_policy_approve(store, &arguments),
        KeyPolicyCommand::Revoke(selector) => key_policy_revoke(store, &selector),
    }
}

async fn key_policy_create(
    store: &StateStore,
    arguments: &KeyPolicyCreateArgs,
) -> Result<ResultEnvelopeV2> {
    if arguments.permissions.is_empty() {
        return Err(CliError::Input(
            "a standing authority requires at least one allowlisted permission group; use `cfctl keys permissions --account <id>`"
                .to_owned(),
        ));
    }
    if arguments.name_prefix.trim().is_empty() {
        return Err(CliError::Input(
            "a standing authority requires a non-empty `--name-prefix` lineage bound".to_owned(),
        ));
    }
    if arguments.max_child_ttl_hours == 0 || arguments.max_runs_per_day == 0 {
        return Err(CliError::Input(
            "`--max-child-ttl-hours` and `--max-runs-per-day` must both be at least 1".to_owned(),
        ));
    }
    let inventory = key_permissions(
        store,
        &KeyPermissionArgs {
            account: arguments.account.clone(),
            user: false,
        },
    )
    .await?;
    if !inventory.ok
        || !inventory.performed
        || inventory.account_id.as_deref() != Some(arguments.account.as_str())
    {
        return Err(CliError::Input(
            "fresh account-bound permission inventory did not produce a live-read receipt"
                .to_owned(),
        ));
    }
    let selected_groups = validate_selected_permission_groups(
        &arguments.permissions,
        inventory.result.get("result").unwrap_or(&Value::Null),
    )?;
    validate_permission_group_resource_scope(&selected_groups, "com.cloudflare.api.account")?;
    let selected_group_ids = selected_groups
        .iter()
        .filter_map(|group| group.get("id").and_then(Value::as_str))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let selected_groups_hash = hash_value(&serde_json::to_value(&selected_groups)?)?;
    let expires_at = Utc::now() + ChronoDuration::days(i64::from(arguments.expires_days));
    let authority = StandingAuthorityV1::draft(
        &arguments.account,
        vec![
            "account-api-tokens-create-token".to_owned(),
            "account-api-tokens-delete-token".to_owned(),
        ],
        selected_group_ids,
        &selected_groups_hash,
        arguments.max_child_ttl_hours,
        &arguments.name_prefix,
        arguments.max_runs_per_day,
        expires_at,
    )?;
    store.create_authority(&authority)?;
    let mut envelope = ResultEnvelopeV2::success(
        "keys policy create",
        json!({
            "authority_id": authority.authority_id,
            "status": authority.status.as_str(),
            "account_id": authority.account_id,
            "capability_ids": authority.capability_ids,
            "name_prefix": authority.name_prefix,
            "max_child_ttl_hours": authority.max_child_ttl_hours,
            "max_runs_per_day": authority.max_runs_per_day,
            "expires_at": authority.expires_at,
            "resolved_permission_groups": selected_groups,
            "permission_inventory_hash": authority.permission_inventory_hash,
            "approval_command": format!(
                "cfctl keys policy approve {} --yes",
                authority.authority_id
            ),
            "message": "Standing authority drafted from a fresh live permission inventory. Review the resolved groups and bounds, then approve the exact authority ID."
        }),
    );
    envelope.account_id = Some(arguments.account.clone());
    envelope.evidence = inventory.evidence;
    Ok(envelope)
}

fn key_policy_list(store: &StateStore) -> Result<ResultEnvelopeV2> {
    let now = Utc::now();
    let authorities: Vec<Value> = store
        .list_authorities()?
        .iter()
        .map(|authority| {
            let effective_status = authority.effective_status(now);
            let runs_last_24h = authority.runs_in_last_day(now);
            let runs_remaining_24h = usize::try_from(authority.max_runs_per_day)
                .unwrap_or(usize::MAX)
                .saturating_sub(runs_last_24h);
            let next_action = match effective_status {
                "pending_approval" => format!(
                    "Review the bounds, then run `cfctl keys policy approve {} --yes`.",
                    authority.authority_id
                ),
                "active" if runs_remaining_24h == 0 => format!(
                    "The rolling run budget is exhausted; wait for budget to age out or revoke with `cfctl keys policy revoke {}`.",
                    authority.authority_id
                ),
                "active" => format!(
                    "Use `--under-policy {}` only for a matching mint or lineage-bound revoke; list again to inspect the resulting budget and lineage.",
                    authority.authority_id
                ),
                "expired" => {
                    "This authority is effectively expired; create and explicitly approve a new policy if recurring work must continue."
                        .to_owned()
                }
                "revoked" => {
                    "This authority is revoked and cannot admit new runs; individually revoke any surviving child tokens when needed."
                        .to_owned()
                }
                _ => "Inspect the authority document before taking another action.".to_owned(),
            };
            json!({
                "authority_id": authority.authority_id,
                "status": effective_status,
                "account_id": authority.account_id,
                "capability_ids": authority.capability_ids,
                "name_prefix": authority.name_prefix,
                "permission_group_count": authority.permission_group_ids.len(),
                "max_child_ttl_hours": authority.max_child_ttl_hours,
                "max_runs_per_day": authority.max_runs_per_day,
                "runs_last_24h": runs_last_24h,
                "runs_remaining_24h": runs_remaining_24h,
                "minted_tokens": authority.minted_token_ids.len(),
                "minted_token_ids": authority.minted_token_ids,
                "created_at": authority.created_at,
                "expires_at": authority.expires_at,
                "next_action": next_action,
            })
        })
        .collect();
    Ok(ResultEnvelopeV2::success(
        "keys policy list",
        json!({"authorities": authorities}),
    ))
}

fn key_policy_approve(
    store: &StateStore,
    arguments: &KeyPolicyApproveArgs,
) -> Result<ResultEnvelopeV2> {
    let guard = store.lock_authority(&arguments.authority_id)?;
    let mut authority = store.load_authority(&arguments.authority_id)?;
    authority.approve(arguments.yes)?;
    store.save_authority_guarded(&authority, &guard)?;
    Ok(ResultEnvelopeV2::success(
        "keys policy approve",
        json!({
            "authority_id": authority.authority_id,
            "status": authority.status.as_str(),
            "approved_content_hash": authority.approval.as_ref().map(|approval| approval.approved_content_hash.clone()),
            "expires_at": authority.expires_at,
            "message": "Standing authority is active. Unattended runs under it are bounded, rate-limited, attributable, and revocable with `cfctl keys policy revoke`."
        }),
    ))
}

fn key_policy_revoke(store: &StateStore, selector: &KeyPolicySelector) -> Result<ResultEnvelopeV2> {
    let guard = store.lock_authority(&selector.authority_id)?;
    let mut authority = store.load_authority(&selector.authority_id)?;
    authority.revoke();
    store.save_authority_guarded(&authority, &guard)?;
    Ok(ResultEnvelopeV2::success(
        "keys policy revoke",
        json!({
            "authority_id": authority.authority_id,
            "status": authority.status.as_str(),
            "message": "Standing authority revoked. Runs not yet durably admitted fail closed; an already-admitted boundary attempt may finish, and later lineage reconciliation cannot reactivate the grant. Already-minted child tokens are unaffected and can be revoked individually."
        }),
    ))
}

async fn key_permissions(
    store: &StateStore,
    arguments: &KeyPermissionArgs,
) -> Result<ResultEnvelopeV2> {
    let envelope = call_command(store, permission_inventory_call(arguments)).await?;
    Ok(permission_inventory_envelope(envelope))
}

fn permission_inventory_call(arguments: &KeyPermissionArgs) -> CallArgs {
    let capability_id = if arguments.user {
        "permission-groups-list-permission-groups"
    } else {
        "account-api-tokens-list-permission-groups"
    };
    let mut selectors = Vec::new();
    if !arguments.user {
        selectors.push(("account_id".to_owned(), arguments.account.clone()));
    }
    CallArgs {
        capability_id: capability_id.to_owned(),
        selectors,
        query: Vec::new(),
        body_json: None,
        body_stdin: false,
        profile: None,
        account: Some(arguments.account.clone()),
        if_match: None,
        if_none_match: None,
        value_out: None,
    }
}

fn permission_inventory_envelope(mut envelope: ResultEnvelopeV2) -> ResultEnvelopeV2 {
    "keys permissions".clone_into(&mut envelope.command);
    let forbidden = serde_json::from_value::<CloudflareResponseV1>(envelope.result.clone())
        .is_ok_and(|response| {
            !response.success
                && (response.status == 403
                    || response.errors.iter().any(|error| error.code == Some(9109)))
        });
    if forbidden {
        envelope.ok = false;
        envelope.verification.state = VerificationState::Failed;
        envelope.error = Some(ErrorV1 {
            code: "CFCTL_PERMISSION_INVENTORY_FORBIDDEN".to_owned(),
            message: "Cloudflare denied the permission-group inventory. The selected API token requires the `Account API Tokens Read` or `Account API Tokens Write` grant for the explicit account."
                .to_owned(),
            next_step: Some(
                "Grant the selected token Account API Tokens Read or Write, then retry the same account-bound inventory command."
                    .to_owned(),
            ),
        });
    }
    envelope
}

async fn key_mint(store: &StateStore, arguments: &KeyMutationArgs) -> Result<ResultEnvelopeV2> {
    let account = arguments.account.as_deref().ok_or_else(|| {
        CliError::Input("token minting requires `--account` for explicit resource scope".to_owned())
    })?;
    let value_out = arguments.value_out.as_ref().ok_or_else(|| {
        CliError::Input("token minting requires the sink-only `--value-out <path>`".to_owned())
    })?;
    if arguments.permissions.is_empty() {
        return Err(CliError::Input(if arguments.user {
            "at least one permission group ID or exact name is required; use `cfctl keys permissions --user --account <id>`"
                    .to_owned()
        } else {
            "at least one permission group ID or exact name is required; use `cfctl keys permissions --account <id>`"
                    .to_owned()
        }));
    }
    let inventory = key_permissions(
        store,
        &KeyPermissionArgs {
            account: account.to_owned(),
            user: arguments.user,
        },
    )
    .await?;
    if !inventory.ok || !inventory.performed || inventory.account_id.as_deref() != Some(account) {
        return Err(CliError::Input(
            "fresh owner-specific permission inventory did not produce an account-bound live-read receipt"
                .to_owned(),
        ));
    }
    let selected_groups = validate_selected_permission_groups(
        &arguments.permissions,
        inventory.result.get("result").unwrap_or(&Value::Null),
    )?;
    validate_permission_group_resource_scope(&selected_groups, "com.cloudflare.api.account")?;
    let selected_group_ids = selected_groups
        .iter()
        .filter_map(|group| group.get("id").and_then(Value::as_str))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let selected_groups_hash = hash_value(&serde_json::to_value(&selected_groups)?)?;
    let inventory_evidence_hashes = inventory
        .evidence
        .iter()
        .map(|evidence| evidence.content_hash.clone())
        .collect::<Vec<_>>();
    let mut body = json!({
        "name": arguments.name,
        "policies": [{
            "effect": "allow",
            "permission_groups": selected_group_ids.iter().map(|id| json!({"id": id})).collect::<Vec<_>>(),
            "resources": {format!("com.cloudflare.api.account.{account}"): "*"}
        }]
    });
    if let Some(hours) = arguments.ttl_hours {
        body["expires_on"] =
            json!((Utc::now() + ChronoDuration::hours(i64::from(hours))).to_rfc3339());
    }
    let catalog = ensure_catalog(store).await?;
    let capability_id = if arguments.user {
        "user-api-tokens-create-token"
    } else {
        "account-api-tokens-create-token"
    };
    let inventory_contract = token_permission_inventory_contract(capability_id)
        .ok_or_else(|| capability_missing(capability_id))?;
    let capability = catalog
        .get(capability_id)
        .cloned()
        .ok_or_else(|| capability_missing(capability_id))?;
    let mut plan = create_plan(
        store,
        &catalog,
        capability,
        CallInput {
            selectors: if arguments.user {
                json!({})
            } else {
                json!({"account_id": account})
            },
            query: json!({}),
            body: Some(body),
            ..CallInput::default()
        },
        None,
        Some(account),
        json!({
            "value_out": value_out,
            "permission_inventory": {
                "source_capability_id": inventory_contract.capability_id,
                "selected_groups": selected_groups,
                "selected_groups_hash": selected_groups_hash,
                "evidence_hashes": inventory_evidence_hashes,
            }
        }),
    )
    .await?;
    plan.evidence.splice(0..0, inventory.evidence);
    Ok(plan)
}

fn validate_selected_permission_groups(
    requested_selectors: &[String],
    inventory: &Value,
) -> Result<Vec<Value>> {
    if requested_selectors.is_empty() {
        return Err(CliError::Input(
            "at least one permission group ID or exact name must be selected".to_owned(),
        ));
    }
    let groups = inventory.as_array().ok_or_else(|| {
        CliError::Input("live permission inventory result is not an array".to_owned())
    })?;
    let mut requested_selectors = requested_selectors.to_vec();
    requested_selectors.sort();
    requested_selectors.dedup();
    let mut resolved = BTreeMap::<String, &Value>::new();
    for requested_selector in requested_selectors {
        let matches = groups
            .iter()
            .filter(|group| {
                group.get("id").and_then(Value::as_str) == Some(&requested_selector)
                    || group.get("name").and_then(Value::as_str) == Some(&requested_selector)
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(CliError::Input(format!(
                "permission group selector `{requested_selector}` is not unique in the fresh account inventory (matched {})",
                matches.len()
            )));
        }
        let group = matches[0];
        let resolved_id = group
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.trim().is_empty())
            .ok_or_else(|| {
                CliError::Input(format!(
                    "permission group `{requested_selector}` has no auditable ID in the fresh account inventory"
                ))
            })?;
        let id_matches = groups
            .iter()
            .filter(|candidate| candidate.get("id").and_then(Value::as_str) == Some(resolved_id))
            .count();
        if id_matches != 1 {
            return Err(CliError::Input(format!(
                "permission group `{resolved_id}` is not unique in the fresh account inventory (matched {id_matches})"
            )));
        }
        resolved.insert(resolved_id.to_owned(), group);
    }
    let mut selected = Vec::with_capacity(resolved.len());
    for (resolved_id, group) in resolved {
        let name = group
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.trim().is_empty())
            .ok_or_else(|| {
                CliError::Input(format!(
                    "permission group `{resolved_id}` has no auditable name in the fresh account inventory"
                ))
            })?;
        let mut scopes = group
            .get("scopes")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                CliError::Input(format!(
                    "permission group `{resolved_id}` has no auditable scope list in the fresh account inventory"
                ))
            })?
            .iter()
            .map(|scope| {
                scope.as_str().map(str::to_owned).ok_or_else(|| {
                    CliError::Input(format!(
                        "permission group `{resolved_id}` contains a non-string scope"
                    ))
                })
            })
            .collect::<Result<Vec<_>>>()?;
        scopes.sort();
        scopes.dedup();
        if scopes.is_empty() {
            return Err(CliError::Input(format!(
                "permission group `{resolved_id}` has an empty scope list"
            )));
        }
        let mut normalized = Map::from_iter([
            ("id".to_owned(), Value::String(resolved_id)),
            ("name".to_owned(), Value::String(name.to_owned())),
            ("scopes".to_owned(), serde_json::to_value(scopes)?),
        ]);
        if let Some(category) = group.get("category").and_then(Value::as_str) {
            normalized.insert("category".to_owned(), Value::String(category.to_owned()));
        }
        selected.push(Value::Object(normalized));
    }
    Ok(selected)
}

async fn key_rotate(store: &StateStore, arguments: &KeyRotateArgs) -> Result<ResultEnvelopeV2> {
    let catalog = ensure_catalog(store).await?;
    let capability_id = if arguments.user {
        "user-api-tokens-roll-token"
    } else {
        "account-api-tokens-roll-token"
    };
    let capability = catalog
        .get(capability_id)
        .cloned()
        .ok_or_else(|| capability_missing(capability_id))?;
    create_plan(
        store,
        &catalog,
        capability,
        CallInput {
            selectors: if arguments.user {
                json!({"token_id": arguments.id})
            } else {
                json!({"account_id": arguments.account, "token_id": arguments.id})
            },
            query: json!({}),
            body: Some(json!({})),
            ..CallInput::default()
        },
        None,
        Some(&arguments.account),
        json!({"value_out": arguments.value_out}),
    )
    .await
}

async fn key_revoke(store: &StateStore, arguments: &KeyRevokeArgs) -> Result<ResultEnvelopeV2> {
    let account = arguments.account.as_deref().ok_or_else(|| {
        CliError::Input("token revocation requires `--account` for explicit ownership".to_owned())
    })?;
    let catalog = ensure_catalog(store).await?;
    let capability_id = if arguments.user {
        "user-api-tokens-delete-token"
    } else {
        "account-api-tokens-delete-token"
    };
    let capability = catalog
        .get(capability_id)
        .cloned()
        .ok_or_else(|| capability_missing(capability_id))?;
    create_plan(
        store,
        &catalog,
        capability,
        CallInput {
            selectors: if arguments.user {
                json!({"token_id": arguments.id})
            } else {
                json!({"account_id": account, "token_id": arguments.id})
            },
            query: json!({}),
            body: None,
            ..CallInput::default()
        },
        None,
        Some(account),
        Value::Null,
    )
    .await
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
            let running_build = current_build_info();
            let path_build = inspect_path_build(&running_build);
            let instruction_drift = status
                .iter()
                .filter(|agent| agent.skill_present && !agent.skill_current)
                .count();
            let healthy = path_build.healthy && instruction_drift == 0;
            Ok(health_envelope(
                "agents doctor",
                json!({
                    "running_build": running_build,
                    "path_build": path_build,
                    "configured_default_agent": configured,
                    "platform": env::consts::OS,
                    "platform_secret_store": platform_secret_store_health(store)?,
                    "instruction_drift": instruction_drift,
                    "agents": status,
                }),
                healthy,
                "CFCTL_AGENT_OR_BUILD_DRIFT",
                "The PATH build or managed agent instructions are not current.",
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
    let unsupported_legacy_profiles: Vec<Value> = profiles
        .profiles
        .values()
        .filter(|profile| profile.kind == ProfileKind::LegacyWranglerSession)
        .map(|profile| {
            json!({
                "profile": profile.id,
                "kind": "wrangler_session",
                "supported": false,
                "credential_store_accessed": false,
                "remove_argv": ["cfctl", "auth", "logout", profile.id, "--json"],
                "next_step": format!(
                    "Remove this metadata-only legacy profile with `cfctl auth logout {}` and create a supported OAuth or API-token profile; Wrangler authentication is not a cfctl credential lane.",
                    profile.id
                ),
            })
        })
        .collect();
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
    let running_build = current_build_info();
    let path_build = inspect_path_build(&running_build);
    let instruction_drift = agents
        .iter()
        .filter(|agent| agent.skill_present && !agent.skill_current)
        .count();
    let healthy = path_build.healthy && instruction_drift == 0;
    Ok(health_envelope(
        "doctor",
        json!({
            "running_build": running_build,
            "path_build": path_build,
            "platform": env::consts::OS,
            "config_dir": store.paths().config_dir,
            "data_dir": store.paths().data_dir,
            "cache_dir": store.paths().cache_dir,
            "catalog": catalog,
            "profile_count": profiles.profiles.len(),
            "current_profile": profiles.current_profile,
            "unsupported_legacy_profiles": unsupported_legacy_profiles,
            "oauth_scope_inventory_hash": inventory_hash,
            "oauth_profiles": oauth_reconsent,
            "platform_secret_store": platform_secret_store_health(store)?,
            "standing_authorities": standing_authorities_health(store)?,
            "instruction_drift": instruction_drift,
            "agents": agents,
            "public_oauth": "unconfigured until cfctl.io ownership, site publication, domain verification, and permanent promotion are explicitly completed; use `cfctl auth import-api-token --account <id> --stdin` for the scoped day-to-day lane",
        }),
        healthy,
        "CFCTL_RUNTIME_DRIFT",
        "The PATH build or managed agent instructions are not current.",
    ))
}

fn version_command() -> Result<ResultEnvelopeV2> {
    Ok(ResultEnvelopeV2::success(
        "version",
        serde_json::to_value(current_build_info())?,
    ))
}

fn health_envelope(
    command: &str,
    result: Value,
    healthy: bool,
    code: &str,
    message: &str,
) -> ResultEnvelopeV2 {
    let mut envelope = ResultEnvelopeV2::success(command, result);
    if !healthy {
        envelope.ok = false;
        envelope.verification.state = VerificationState::Failed;
        envelope.error = Some(ErrorV1 {
            code: code.to_owned(),
            message: message.to_owned(),
            next_step: Some(
                "Run ./bootstrap.sh from a tracked-clean checkout, then synchronize managed agents."
                    .to_owned(),
            ),
        });
    }
    envelope
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
            let retained_repo_state = "compat/v1/state";
            let state_source = if cwd.join(retained_repo_state).is_dir() {
                retained_repo_state
            } else {
                "state"
            };
            for (source_root, import_label) in
                [(state_source, "state"), ("var/inventory", "var/inventory")]
            {
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
                            .join(import_label)
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
    let credential = fresh_credential(profile, &platform_secrets(store)).await?;
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
        if is_live_plan_precondition_hash(name) {
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

fn is_live_plan_precondition_hash(name: &str) -> bool {
    matches!(
        name,
        "catalog"
            | "request_input"
            | "entitlement"
            | "zone_account"
            | "global_warp_override_state"
            | D1_READ_REPLICATION_PRECONDITION
            | D1_EMPTY_DATABASE_PRECONDITION
            | CLOUDFLARE_TUNNEL_CONFIGURATION_STATE_PRECONDITION
            | WARP_CONNECTOR_CONFIGURATION_STATE_PRECONDITION
            | WEB_ANALYTICS_RUM_STATE_PRECONDITION
            | DNS_RECORD_STATE_PRECONDITION
    )
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

fn call_input(capability: &CapabilityV1, arguments: &CallArgs) -> Result<PreparedCallInput> {
    let selectors = object_from_pairs(&arguments.selectors);
    let query = query_object_from_pairs(capability, &arguments.query)?;
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

fn query_object_from_pairs(capability: &CapabilityV1, pairs: &[(String, String)]) -> Result<Value> {
    let mut grouped = BTreeMap::<String, Vec<String>>::new();
    for (name, value) in pairs {
        grouped.entry(name.clone()).or_default().push(value.clone());
    }
    let mut query = Map::new();
    for (name, values) in grouped {
        let array_typed = capability.selectors.iter().any(|selector| {
            selector.location == "query" && selector.name == name && selector.value_type == "array"
        });
        if array_typed {
            query.insert(
                name,
                Value::Array(values.into_iter().map(Value::String).collect()),
            );
        } else if values.len() == 1 {
            query.insert(name, Value::String(values[0].clone()));
        } else {
            return Err(CliError::Input(format!(
                "query control `{name}` is repeated but its catalog type is not an array"
            )));
        }
    }
    Ok(Value::Object(query))
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

fn guide_document(capability: &CapabilityV1) -> CapabilityGuideV1 {
    let blocking_gaps = capability.mutation_contract_gaps();
    let post_resolution_call_argv = capability_call_argv(capability);
    let contract_ready =
        capability.adapter_status != AdapterStatus::Blocked && blocking_gaps.is_empty();
    let call_argv = contract_ready.then(|| post_resolution_call_argv.clone());
    let stages = guide_stages()
        .iter()
        .enumerate()
        .map(|(index, stage)| {
            guide_stage_document(
                index + 1,
                *stage,
                capability,
                contract_ready,
                &blocking_gaps,
                Some(&post_resolution_call_argv),
            )
        })
        .collect::<Vec<_>>();

    CapabilityGuideV1 {
        capability: capability.clone(),
        contract_state: if contract_ready {
            GuideContractStateV1::Available
        } else {
            GuideContractStateV1::Blocked
        },
        blocking_gaps,
        blocked_reason: capability.blocked_reason.clone(),
        call_argv,
        post_resolution_call_argv: post_resolution_call_argv.clone(),
        next_action: guide_next_action(
            capability,
            contract_ready,
            Some(&post_resolution_call_argv),
        ),
        stages,
    }
}

fn capability_call_argv(capability: &CapabilityV1) -> Vec<String> {
    if matches!(
        capability.id.as_str(),
        "account-api-tokens-create-token" | "user-api-tokens-create-token"
    ) {
        let mut argv = vec!["cfctl", "keys", "mint"];
        if capability.id == "user-api-tokens-create-token" {
            argv.push("--user");
        }
        argv.extend([
            "--name",
            "<token-name>",
            "--permission",
            "<permission-group-id>",
            "--account",
            "<account_id>",
            "--value-out",
            "<new-mode-0600-path>",
            "--json",
        ]);
        return argv.into_iter().map(str::to_owned).collect();
    }

    let mut argv = vec!["cfctl".to_owned(), "call".to_owned(), capability.id.clone()];
    for selector in capability
        .selectors
        .iter()
        .filter(|selector| selector.required)
    {
        argv.push(
            if selector.location == "query" {
                "--query"
            } else {
                "--selector"
            }
            .to_owned(),
        );
        argv.push(format!("{}=<{}>", selector.name, selector.name));
    }
    if capability_has_meaningful_request_body(capability) {
        argv.push("--body-stdin".to_owned());
    }
    if is_secret_output_capability(capability) {
        let sink = if is_access_service_token_create_capability(capability) {
            "<new-mode-0600-json-path>"
        } else {
            "<new-mode-0600-path>"
        };
        argv.extend(["--value-out".to_owned(), sink.to_owned()]);
    }
    argv.push("--json".to_owned());
    argv
}

fn capability_has_meaningful_request_body(capability: &CapabilityV1) -> bool {
    let Some(schema) = capability.request_schema.as_ref() else {
        return false;
    };
    if schema.get("x-cfctl-body-required").and_then(Value::as_bool) == Some(true) {
        return true;
    }
    if capability
        .request_object_fields()
        .is_some_and(|fields| !fields.is_empty())
    {
        return true;
    }
    schema
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|value_type| value_type != "object")
}

fn guide_next_action(
    capability: &CapabilityV1,
    contract_ready: bool,
    call_argv: Option<&[String]>,
) -> GuideActionV1 {
    if contract_ready {
        let summary = if capability.mutating {
            "Create the preview plan with the exact generated argv; no Cloudflare mutation occurs until the resulting operation is run."
        } else {
            "Run the exact generated argv to produce a redacted live-read receipt."
        };
        return GuideActionV1 {
            summary: summary.to_owned(),
            argv: call_argv.unwrap_or_default().to_vec(),
        };
    }

    let gaps = capability.mutation_contract_gaps();
    let blocked_text = format!(
        "{} {}",
        capability.blocked_reason.as_deref().unwrap_or_default(),
        gaps.join(" ")
    )
    .to_ascii_lowercase();
    let (summary, argv) = if should_resolve_zone_entitlement(capability) {
        (
            "Run the exact call to perform the governed live zone-subscription read. cfctl creates a plan only when the active plan is allowed by the official matrix, then binds and rechecks that entitlement before execution.",
            call_argv.unwrap_or_default().to_vec(),
        )
    } else if blocked_text.contains("product-scoped subscription join key") {
        (
            "cfctl cannot safely map the account's product-scoped subscriptions to this operation's generic plan matrix because the official schema supplies no product-scoped subscription join key. Keep the operation blocked; do not treat any active account subscription as proof of entitlement.",
            vec![
                "cfctl".to_owned(),
                "docs".to_owned(),
                "search".to_owned(),
                format!("{} plans subscriptions", capability.product),
                "--json".to_owned(),
            ],
        )
    } else if blocked_text.contains("cost") {
        (
            "Resolve and bind the operation's official pricing contract before planning it.",
            vec![
                "cfctl".to_owned(),
                "docs".to_owned(),
                "search".to_owned(),
                format!("{} pricing", capability.product),
                "--json".to_owned(),
            ],
        )
    } else if blocked_text.contains("entitlement") {
        (
            "Review the official plan gate, then obtain an account-backed entitlement result before planning. Documentation identifies requirements but does not prove the selected account is entitled.",
            vec![
                "cfctl".to_owned(),
                "docs".to_owned(),
                "search".to_owned(),
                format!("{} plans", capability.product),
                "--json".to_owned(),
            ],
        )
    } else if blocked_text.contains("permission inventory")
        || blocked_text.contains("permission lane")
    {
        (
            "Inspect the fresh account permission inventory. Inventory alone does not prove that a permission group authorizes this operation; token creation must use the governed keys workflow.",
            [
                "cfctl",
                "keys",
                "permissions",
                "--account",
                "<account_id>",
                "--json",
            ]
            .map(str::to_owned)
            .to_vec(),
        )
    } else {
        (
            "Inspect the exact blocked adapter and contract metadata; do not attempt execution until every named gap is resolved.",
            vec![
                "cfctl".to_owned(),
                "catalog".to_owned(),
                "show".to_owned(),
                capability.id.clone(),
                "--json".to_owned(),
            ],
        )
    };
    GuideActionV1 {
        summary: summary.to_owned(),
        argv,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum GuideLiveRead {
    ZoneAccount,
    ZoneEntitlement,
    GlobalWarpOverrideState,
    D1ReadReplicationState,
    CloudflareTunnelConfigurationState,
    WarpConnectorConfigurationState,
    WebAnalyticsRumState,
    DnsRecordState,
    OAuthClientSecretState,
}

fn guide_live_reads(capability: &CapabilityV1) -> Vec<GuideLiveRead> {
    [
        (
            should_bind_zone_account(capability),
            GuideLiveRead::ZoneAccount,
        ),
        (
            should_resolve_zone_entitlement(capability),
            GuideLiveRead::ZoneEntitlement,
        ),
        (
            should_bind_global_warp_override_state(capability),
            GuideLiveRead::GlobalWarpOverrideState,
        ),
        (
            should_bind_d1_read_replication_state(capability),
            GuideLiveRead::D1ReadReplicationState,
        ),
        (
            should_bind_cloudflare_tunnel_configuration_state(capability),
            GuideLiveRead::CloudflareTunnelConfigurationState,
        ),
        (
            should_bind_warp_connector_configuration_state(capability),
            GuideLiveRead::WarpConnectorConfigurationState,
        ),
        (
            should_bind_web_analytics_rum_state(capability),
            GuideLiveRead::WebAnalyticsRumState,
        ),
        (
            should_bind_dns_record_state(capability),
            GuideLiveRead::DnsRecordState,
        ),
        (
            should_bind_oauth_client_secret_state(capability),
            GuideLiveRead::OAuthClientSecretState,
        ),
    ]
    .into_iter()
    .filter_map(|(required, read)| required.then_some(read))
    .collect()
}

fn guide_stage_contract_state(
    stage: cfctl_core::GuideStage,
    capability: &CapabilityV1,
    contract_ready: bool,
    blocking_gaps: &[String],
    live_reads: &[GuideLiveRead],
) -> GuideContractStateV1 {
    use cfctl_core::GuideStage;

    let entitlement_blocked = capability.entitlement.available == Some(false)
        || blocking_gaps.iter().any(|gap| gap.contains("entitlement"));
    let entitlement_unresolved = capability.mutating
        && capability.entitlement.available != Some(true)
        && capability.entitlement.plans.is_empty();
    match stage {
        GuideStage::SelectAccount if live_reads.contains(&GuideLiveRead::ZoneAccount) => {
            GuideContractStateV1::LiveReadRequired
        }
        GuideStage::CheckEntitlement if live_reads.contains(&GuideLiveRead::ZoneEntitlement) => {
            GuideContractStateV1::LiveReadRequired
        }
        GuideStage::InspectCurrentState
            if live_reads.iter().any(|read| {
                matches!(
                    read,
                    GuideLiveRead::GlobalWarpOverrideState
                        | GuideLiveRead::D1ReadReplicationState
                        | GuideLiveRead::CloudflareTunnelConfigurationState
                        | GuideLiveRead::WarpConnectorConfigurationState
                        | GuideLiveRead::WebAnalyticsRumState
                        | GuideLiveRead::DnsRecordState
                        | GuideLiveRead::OAuthClientSecretState
                )
            }) =>
        {
            GuideContractStateV1::LiveReadRequired
        }
        GuideStage::CheckEntitlement if entitlement_blocked => GuideContractStateV1::Blocked,
        GuideStage::CheckEntitlement if entitlement_unresolved => {
            GuideContractStateV1::ManualReview
        }
        GuideStage::CalculateCost if capability.mutating && !capability.cost.known => {
            GuideContractStateV1::Blocked
        }
        GuideStage::CalculateCost
        | GuideStage::BuildPlan
        | GuideStage::RequestApproval
        | GuideStage::AcquireLocks
        | GuideStage::Rectify
            if !capability.mutating =>
        {
            GuideContractStateV1::NotApplicable
        }
        GuideStage::BuildPlan
        | GuideStage::RequestApproval
        | GuideStage::AcquireLocks
        | GuideStage::Execute
            if !contract_ready =>
        {
            GuideContractStateV1::Blocked
        }
        GuideStage::Verify
            if !capability.verification_contract_declared()
                || !capability.verification_contract_supported() =>
        {
            GuideContractStateV1::Blocked
        }
        GuideStage::Verify if !capability.verification.required => {
            GuideContractStateV1::NotApplicable
        }
        GuideStage::Rectify
            if !capability.rollback_contract_declared()
                || !capability.rollback_contract_supported() =>
        {
            GuideContractStateV1::Blocked
        }
        GuideStage::CloseWithEvidence if capability.mutating && !contract_ready => {
            GuideContractStateV1::Blocked
        }
        _ => GuideContractStateV1::Available,
    }
}

fn guide_live_read_summary(
    stage: cfctl_core::GuideStage,
    live_reads: &[GuideLiveRead],
) -> Option<&'static str> {
    use cfctl_core::GuideStage;

    match stage {
        GuideStage::SelectAccount if live_reads.contains(&GuideLiveRead::ZoneAccount) => Some(
            "Read the exact live zone details and require its account ID to match the selected account.",
        ),
        GuideStage::CheckEntitlement if live_reads.contains(&GuideLiveRead::ZoneEntitlement) => {
            Some(
                "Read the exact live zone subscription and evaluate its active plan against the official availability matrix.",
            )
        }
        GuideStage::InspectCurrentState
            if live_reads.contains(&GuideLiveRead::GlobalWarpOverrideState) =>
        {
            Some(
                "Read and bind the exact live account-wide disconnect state; execution repeats this read and rejects drift before crossing the mutation boundary.",
            )
        }
        GuideStage::InspectCurrentState
            if live_reads.contains(&GuideLiveRead::D1ReadReplicationState) =>
        {
            Some(
                "Read and bind the exact live database read-replication mode; execution repeats this read and rejects drift before crossing the mutation boundary.",
            )
        }
        GuideStage::InspectCurrentState
            if live_reads.contains(&GuideLiveRead::CloudflareTunnelConfigurationState) =>
        {
            Some(
                "Read and bind the exact live remotely managed Tunnel routing configuration; execution repeats this read and rejects drift before replacing any ingress rule.",
            )
        }
        GuideStage::InspectCurrentState
            if live_reads.contains(&GuideLiveRead::WarpConnectorConfigurationState) =>
        {
            Some(
                "Read and bind the exact live WARP Connector high-availability mode and provider configuration; execution repeats this read and rejects drift before changing Cloudflare Mesh failover behavior.",
            )
        }
        GuideStage::InspectCurrentState
            if live_reads.contains(&GuideLiveRead::WebAnalyticsRumState) =>
        {
            Some(
                "Read and bind the exact live editable Web Analytics RUM on/off value; execution repeats this read and rejects manual state or drift before changing zone-wide data collection.",
            )
        }
        GuideStage::InspectCurrentState if live_reads.contains(&GuideLiveRead::DnsRecordState) => {
            Some(
                "Read and bind the exact live writable DNS record state; execution repeats this read and rejects drift before crossing the mutation boundary.",
            )
        }
        _ => None,
    }
}

fn guide_stage_uses_live_read(stage: cfctl_core::GuideStage, live_reads: &[GuideLiveRead]) -> bool {
    use cfctl_core::GuideStage;

    match stage {
        GuideStage::SelectAccount => live_reads.contains(&GuideLiveRead::ZoneAccount),
        GuideStage::CheckEntitlement => live_reads.contains(&GuideLiveRead::ZoneEntitlement),
        GuideStage::InspectCurrentState => live_reads.iter().any(|read| {
            matches!(
                read,
                GuideLiveRead::GlobalWarpOverrideState
                    | GuideLiveRead::D1ReadReplicationState
                    | GuideLiveRead::CloudflareTunnelConfigurationState
                    | GuideLiveRead::WarpConnectorConfigurationState
                    | GuideLiveRead::WebAnalyticsRumState
                    | GuideLiveRead::DnsRecordState
            )
        }),
        _ => false,
    }
}

fn guide_stage_document(
    number: usize,
    stage: cfctl_core::GuideStage,
    capability: &CapabilityV1,
    contract_ready: bool,
    blocking_gaps: &[String],
    call_argv: Option<&[String]>,
) -> CapabilityGuideStageV1 {
    let live_reads = guide_live_reads(capability);
    let contract_state = guide_stage_contract_state(
        stage,
        capability,
        contract_ready,
        blocking_gaps,
        &live_reads,
    );
    let summary = guide_live_read_summary(stage, &live_reads)
        .unwrap_or_else(|| guide_stage_summary(stage, capability));
    let evidence_class = if guide_stage_uses_live_read(stage, &live_reads) {
        EvidenceClass::LiveRead
    } else {
        guide_stage_evidence_class(stage, capability.mutating)
    };
    CapabilityGuideStageV1 {
        stage: number,
        name: stage,
        capability_id: capability.id.clone(),
        required: stage_required(stage, capability),
        contract_state,
        summary: summary.to_owned(),
        evidence_class,
        commands: guide_stage_commands(stage, capability, contract_state, call_argv),
    }
}

fn guide_stage_summary(stage: cfctl_core::GuideStage, capability: &CapabilityV1) -> &'static str {
    use cfctl_core::GuideStage;

    let mutating = capability.mutating;

    match stage {
        GuideStage::Discover => {
            "Inspect the catalog contract and adapter classification selected for this capability."
        }
        GuideStage::Authenticate => {
            "Confirm that the selected profile has a usable credential without exposing its value."
        }
        GuideStage::SelectAccount => {
            "Reconcile the explicit account, profile pin, and registered workspace pin; ambiguity fails closed."
        }
        GuideStage::CheckEntitlement => {
            "Inspect the official plan matrix. When live resolution is required, catalog metadata alone does not prove the selected account's entitlement."
        }
        GuideStage::InspectCurrentState if mutating => {
            "Audit registered-workspace state before deriving impact; use an operation-specific Cloudflare read or verifier rather than infer live state from local configuration."
        }
        GuideStage::InspectCurrentState => {
            "Run the capability as a redacted live read to inspect current Cloudflare state."
        }
        GuideStage::LoadStandards => {
            "Load current official product documentation and changelog context."
        }
        GuideStage::MapDependencies => {
            "Map exact local IaC references and affected registered repositories."
        }
        GuideStage::CalculateCost => {
            "Use the bound cost model and official pricing references; unknown or unbounded cost remains blocked."
        }
        GuideStage::BuildPlan => {
            "Create a hash-bound preview plan from the exact selectors, request body, workspace impact, and safety contracts."
        }
        GuideStage::RequestApproval => {
            "Review the plan, then bind approval and any cost ceiling to its exact operation ID."
        }
        GuideStage::AcquireLocks => {
            "Revalidate catalog, account, request, and workspace hashes before acquiring execution locks."
        }
        GuideStage::Execute if mutating => {
            "Cross the Cloudflare write boundary only through the exact durable operation ID."
        }
        GuideStage::Execute => {
            "Perform the redacted live read through the catalog-selected adapter."
        }
        GuideStage::Verify
            if capability.verification.strategy == "sink_write_and_source_response_status" =>
        {
            "Treat Cloudflare success plus the durable sink-only secret receipt as the terminal verification; no readback can prove the new credential value."
        }
        GuideStage::Verify => {
            "Require operation-specific post-change verification before declaring success."
        }
        GuideStage::Rectify => {
            "Use only the declared compensation contract and hash-bound boundary receipts."
        }
        GuideStage::CloseWithEvidence => {
            "Close only with final durable status and content-addressed evidence."
        }
    }
}

fn guide_stage_evidence_class(stage: cfctl_core::GuideStage, mutating: bool) -> EvidenceClass {
    use cfctl_core::GuideStage;

    match stage {
        GuideStage::Discover
        | GuideStage::CheckEntitlement
        | GuideStage::LoadStandards
        | GuideStage::MapDependencies
        | GuideStage::CalculateCost => EvidenceClass::SourceConfig,
        GuideStage::InspectCurrentState | GuideStage::Execute if !mutating => {
            EvidenceClass::LiveRead
        }
        GuideStage::Authenticate
        | GuideStage::SelectAccount
        | GuideStage::InspectCurrentState
        | GuideStage::AcquireLocks
        | GuideStage::CloseWithEvidence => EvidenceClass::LocalProof,
        GuideStage::BuildPlan | GuideStage::RequestApproval => EvidenceClass::Preview,
        GuideStage::Execute | GuideStage::Rectify => EvidenceClass::Apply,
        GuideStage::Verify => EvidenceClass::PostChangeVerification,
    }
}

fn operation_specific_current_state_command(capability: &CapabilityV1) -> Option<Vec<String>> {
    if should_bind_global_warp_override_state(capability) {
        return Some(vec![
            "cfctl".to_owned(),
            "call".to_owned(),
            GLOBAL_WARP_OVERRIDE_READ_CAPABILITY_ID.to_owned(),
            "--selector".to_owned(),
            "account_id=<account_id>".to_owned(),
            "--json".to_owned(),
        ]);
    }
    if should_bind_d1_read_replication_state(capability) {
        return Some(vec![
            "cfctl".to_owned(),
            "call".to_owned(),
            D1_READ_REPLICATION_READ_CAPABILITY_ID.to_owned(),
            "--selector".to_owned(),
            "account_id=<account_id>".to_owned(),
            "--selector".to_owned(),
            "database_id=<database_id>".to_owned(),
            "--json".to_owned(),
        ]);
    }
    if should_bind_cloudflare_tunnel_configuration_state(capability) {
        return Some(vec![
            "cfctl".to_owned(),
            "call".to_owned(),
            CLOUDFLARE_TUNNEL_CONFIGURATION_READ_CAPABILITY_ID.to_owned(),
            "--selector".to_owned(),
            "account_id=<account_id>".to_owned(),
            "--selector".to_owned(),
            "tunnel_id=<tunnel_id>".to_owned(),
            "--json".to_owned(),
        ]);
    }
    if should_bind_warp_connector_configuration_state(capability) {
        return Some(vec![
            "cfctl".to_owned(),
            "call".to_owned(),
            WARP_CONNECTOR_CONFIGURATION_READ_CAPABILITY_ID.to_owned(),
            "--selector".to_owned(),
            "account_id=<account_id>".to_owned(),
            "--selector".to_owned(),
            "tunnel_id=<tunnel_id>".to_owned(),
            "--json".to_owned(),
        ]);
    }
    if should_bind_web_analytics_rum_state(capability) {
        return Some(vec![
            "cfctl".to_owned(),
            "call".to_owned(),
            WEB_ANALYTICS_RUM_READ_CAPABILITY_ID.to_owned(),
            "--selector".to_owned(),
            "zone_id=<zone_id>".to_owned(),
            "--json".to_owned(),
        ]);
    }
    if should_bind_dns_record_state(capability) {
        return Some(vec![
            "cfctl".to_owned(),
            "call".to_owned(),
            DNS_RECORD_DETAIL_READ_CAPABILITY_ID.to_owned(),
            "--selector".to_owned(),
            "zone_id=<zone_id>".to_owned(),
            "--selector".to_owned(),
            "dns_record_id=<dns_record_id>".to_owned(),
            "--json".to_owned(),
        ]);
    }
    should_bind_oauth_client_secret_state(capability).then(|| {
        vec![
            "cfctl".to_owned(),
            "call".to_owned(),
            OAUTH_CLIENT_DETAIL_READ_CAPABILITY_ID.to_owned(),
            "--selector".to_owned(),
            "account_id=<account_id>".to_owned(),
            "--selector".to_owned(),
            "oauth_client_id=<oauth_client_id>".to_owned(),
            "--json".to_owned(),
        ]
    })
}

fn guide_stage_commands(
    stage: cfctl_core::GuideStage,
    capability: &CapabilityV1,
    contract_state: GuideContractStateV1,
    call_argv: Option<&[String]>,
) -> Vec<Vec<String>> {
    use cfctl_core::GuideStage;

    let available = contract_state == GuideContractStateV1::Available;
    let conditional =
        |command: Option<Vec<String>>| available.then_some(command).flatten().into_iter().collect();
    match stage {
        GuideStage::SelectAccount | GuideStage::CheckEntitlement
            if contract_state == GuideContractStateV1::LiveReadRequired =>
        {
            call_argv.map(<[String]>::to_vec).into_iter().collect()
        }
        GuideStage::Discover | GuideStage::CheckEntitlement | GuideStage::CalculateCost => {
            vec![catalog_show_argv(&capability.id)]
        }
        GuideStage::Authenticate => vec![argv(&["cfctl", "auth", "status", "default", "--json"])],
        GuideStage::SelectAccount => vec![
            argv(&["cfctl", "auth", "profiles", "--json"]),
            argv(&["cfctl", "workspace", "graph", "--json"]),
        ],
        GuideStage::InspectCurrentState if !capability.mutating => {
            conditional(call_argv.map(<[String]>::to_vec))
        }
        GuideStage::InspectCurrentState => operation_specific_current_state_command(capability)
            .map_or_else(
                || vec![argv(&["cfctl", "workspace", "audit", "--json"])],
                |command| vec![command],
            ),
        GuideStage::LoadStandards => vec![vec![
            "cfctl".to_owned(),
            "docs".to_owned(),
            "search".to_owned(),
            capability.product.clone(),
            "--json".to_owned(),
        ]],
        GuideStage::MapDependencies => {
            vec![argv(&["cfctl", "workspace", "graph", "--json"])]
        }
        GuideStage::RequestApproval => {
            conditional(Some(approval_command_argv(capability, "<operation-id>")))
        }
        GuideStage::AcquireLocks => conditional(Some(argv(&[
            "cfctl",
            "plans",
            "show",
            "<operation-id>",
            "--json",
        ]))),
        GuideStage::Execute if capability.mutating => conditional(Some(argv(&[
            "cfctl",
            "plans",
            "run",
            "<operation-id>",
            "--json",
        ]))),
        GuideStage::BuildPlan | GuideStage::Execute => {
            conditional(call_argv.map(<[String]>::to_vec))
        }
        GuideStage::Verify => conditional(Some(argv(&[
            "cfctl",
            "plans",
            "status",
            "<operation-id>",
            "--json",
        ]))),
        GuideStage::Rectify => conditional(Some(argv(&[
            "cfctl",
            "plans",
            "rectify",
            "<operation-id>",
            "--json",
        ]))),
        GuideStage::CloseWithEvidence if capability.mutating => conditional(Some(argv(&[
            "cfctl",
            "plans",
            "status",
            "<operation-id>",
            "--json",
        ]))),
        GuideStage::CloseWithEvidence => Vec::new(),
    }
}

fn approval_command_argv(capability: &CapabilityV1, operation_id: &str) -> Vec<String> {
    let mut command = ["cfctl", "plans", "approve"].map(str::to_owned).to_vec();
    command.extend([operation_id.to_owned(), "--yes".to_owned()]);
    if capability.cost.incremental
        && capability.cost.known
        && let (Some(currency), Some(maximum)) =
            (&capability.cost.currency, capability.cost.maximum)
    {
        command.extend([
            "--max-cost".to_owned(),
            format!("{}:{maximum}", currency.to_ascii_uppercase()),
        ]);
    }
    command.push("--json".to_owned());
    command
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

fn catalog_show_argv(capability_id: &str) -> Vec<String> {
    vec![
        "cfctl".to_owned(),
        "catalog".to_owned(),
        "show".to_owned(),
        capability_id.to_owned(),
        "--json".to_owned(),
    ]
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
    let payload = secret_sink_payload(&plan.capability, result)?;
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
    file.write_all(&payload)
        .map_err(|source| cli_io(&path, source))?;
    file.sync_all().map_err(|source| cli_io(&path, source))?;
    Ok(path)
}

fn secret_sink_payload(capability: &CapabilityV1, result: &Value) -> Result<Vec<u8>> {
    if is_access_service_token_create_capability(capability) {
        let client_id = result
            .get("client_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                CliError::Input(
                    "Cloudflare reported Access service-token creation success without a non-empty client_id; no credential sink was created and the operation requires rectification"
                        .to_owned(),
                )
            })?;
        let client_secret = result
            .get("client_secret")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                CliError::Input(
                    "Cloudflare reported Access service-token creation success without a non-empty client_secret; no credential sink was created and the operation requires rectification"
                        .to_owned(),
                )
            })?;
        return Ok(serde_json::to_vec(&json!({
            "client_id": client_id,
            "client_secret": client_secret,
        }))?);
    }

    let Some(secret) = find_secret_value(result) else {
        return Err(CliError::Input(
            "Cloudflare reported success but no one-time credential value was present; the operation requires rectification"
                .to_owned(),
        ));
    };
    Ok(secret.as_bytes().to_vec())
}

fn is_access_service_token_create_capability(capability: &CapabilityV1) -> bool {
    let exact_operation = matches!(
        (
            capability.id.as_str(),
            capability.path.as_str(),
            capability.product.as_str(),
            capability.account_scope.as_str(),
        ),
        (
            "access-service-tokens-create-a-service-token",
            "/accounts/{account_id}/access/service_tokens",
            "Access service tokens",
            "account",
        ) | (
            "zone-level-access-service-tokens-create-a-service-token",
            "/zones/{zone_id}/access/service_tokens",
            "Zone-Level Access service tokens",
            "zone",
        )
    );
    exact_operation
        && capability.method == "POST"
        && capability.permissions == ["Access: Service Tokens Write"]
}

fn secret_sink_format(capability: &CapabilityV1) -> Option<&'static str> {
    if !is_secret_output_capability(capability) {
        None
    } else if is_access_service_token_create_capability(capability) {
        Some("access_service_token_json")
    } else {
        Some("opaque_text")
    }
}

fn secret_sink_path(plan: &PlanV1) -> Result<PathBuf> {
    plan.targets
        .pointer("/adapter/value_out")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| CliError::Input("secret-producing plan has no value_out sink".to_owned()))
}

fn is_secret_output_plan(plan: &PlanV1) -> bool {
    is_secret_output_capability(&plan.capability)
}

fn is_secret_output_capability(capability: &CapabilityV1) -> bool {
    capability.risk == RiskClass::SecretSensitive
        || is_access_service_token_create_capability(capability)
}

fn find_secret_value(value: &Value) -> Option<&str> {
    if let Some(value) = value.as_str() {
        return Some(value);
    }
    if let Some(object) = value.as_object() {
        for key in ["value", "token", "secret", "access_token", "client_secret"] {
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
                    if matches!(
                        key.as_str(),
                        "value" | "token" | "secret" | "access_token" | "client_secret"
                    ) {
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
    let mut builder = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(120))
        .user_agent(concat!("cfctl/", env!("CARGO_PKG_VERSION")));
    // IP-allowlisted API tokens (e.g. a laptop-pinned minter) are usually
    // scoped to the machine's IPv4. When the host default-routes over IPv6,
    // Cloudflare rejects the call with error 9109 ("Cannot use the access
    // token from location: <IPv6>"). `CFCTL_FORCE_IPV4=1` binds egress to an
    // IPv4 source so those tokens work — including unattended (launchd) runs
    // that can't fall back to an interactive `curl -4`.
    if force_ipv4_egress() {
        builder = builder.local_address(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    }
    Ok(builder.build()?)
}

/// True when `CFCTL_FORCE_IPV4` is set to an affirmative value. Off by default
/// so IPv6-only hosts and non-allowlisted tokens are unaffected.
fn force_ipv4_egress() -> bool {
    force_ipv4_from(std::env::var("CFCTL_FORCE_IPV4").ok().as_deref())
}

fn force_ipv4_from(value: Option<&str>) -> bool {
    matches!(value, Some("1" | "true" | "yes" | "on"))
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

/// Read an out-of-band secret from exactly one source. `--value-in <path>`
/// exists so callers can hand cfctl a secret without piping it through a build
/// wrapper such as `./cfctl`, which routes stdin through `cargo` and can consume
/// it before the binary reads it. Exactly one of stdin or a file is required.
fn read_import_secret(from_stdin: bool, value_in: Option<&Path>, label: &str) -> Result<String> {
    match (from_stdin, value_in) {
        (true, Some(_)) => Err(CliError::Input(format!(
            "choose one {label} source: either `--stdin` or `--value-in <path>`, not both"
        ))),
        (false, None) => Err(CliError::Input(format!(
            "the {label} must be supplied out-of-band: add `--stdin` or `--value-in <mode-0600 path>`; values in command arguments are forbidden"
        ))),
        (true, None) => read_stdin(),
        (false, Some(path)) => read_secret_file(path),
    }
}

/// Read a secret from a file that no other user can read. On Unix any group or
/// other permission bit fails closed, mirroring the mode-0600 sink that
/// `--value-out` writes.
fn read_secret_file(path: &Path) -> Result<String> {
    let metadata = fs::metadata(path).map_err(|source| cli_io(path, source))?;
    if !metadata.is_file() {
        return Err(CliError::Input(format!(
            "`--value-in` path is not a regular file: {}",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(CliError::Input(format!(
                "`--value-in` file {} must not be readable by group or others; run `chmod 600 {}` (current mode {:04o})",
                path.display(),
                path.display(),
                mode & 0o7777
            )));
        }
    }
    fs::read_to_string(path).map_err(|source| cli_io(path, source))
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
        CallInput, DNS_RECORD_STATE_PRECONDITION, LivePlanPreconditions,
        OAUTH_CLIENT_KEY_OVERLAP_PRECONDITION, PlanAuthority, admit_standing_plan,
        apply_cloudflare_tunnel_configuration_state_response,
        apply_d1_empty_database_state_response, apply_d1_read_replication_state_response,
        apply_dns_record_state_response, apply_global_warp_override_state_response,
        apply_oauth_client_secret_state_response,
        apply_warp_connector_configuration_state_response, apply_web_analytics_rum_state_response,
        apply_zone_account_response, apply_zone_entitlement_response, approve_plan,
        bind_required_empty_compensation_body, boundary_response_artifact, call_command,
        capability_call_argv, compensation_request, execute_read, find_secret_value,
        force_ipv4_from, guide_document, guide_stage_commands, http_client,
        is_live_plan_precondition_hash, is_secret_output_capability, key_policy_approve,
        key_policy_list, key_policy_revoke, non_readback_verification_basis,
        permission_inventory_call, permission_inventory_envelope, persist_prepared_plan,
        persist_secret_lifecycle, persist_secret_lifecycle_and_reconcile_lineage,
        preflight_call_input, preflight_standing_authority, preserve_previous_catalog,
        query_object_from_pairs, read_import_secret, read_secret_file,
        reconcile_standing_lineage_from_plan, rectify_plan, redact_secret_result,
        required_cloudflare_tunnel_configuration_state_precondition,
        required_d1_empty_database_state_precondition,
        required_d1_read_replication_state_precondition, required_dns_record_state_precondition,
        required_entitlement_precondition, required_global_warp_override_state_precondition,
        required_oauth_client_secret_state_precondition,
        required_warp_connector_configuration_state_precondition,
        required_web_analytics_rum_state_precondition, required_zone_account_precondition,
        secret_sink_format, should_bind_cloudflare_tunnel_configuration_state,
        should_bind_d1_read_replication_state, should_bind_dns_record_state,
        should_bind_global_warp_override_state, should_bind_oauth_client_secret_state,
        should_bind_warp_connector_configuration_state, should_bind_web_analytics_rum_state,
        should_bind_zone_account, should_resolve_zone_entitlement, sink_secret_result,
        store_imported_api_token, validate_api_token_creation_contract,
        validate_current_permission_groups, validate_entitlement_receipt_precondition,
        validate_global_warp_override_state_receipt_precondition,
        validate_selected_permission_groups, validate_standing_authority_permission_inventory,
        validate_zone_account_receipt_precondition, validated_standing_lineage_token_id,
        workspace_resource_keys, zone_target,
    };
    use crate::profiles::ProfilesConfig;
    use crate::{
        CallArgs, KeyPermissionArgs, KeyPolicyApproveArgs, KeyPolicySelector, PlanApproveArgs,
        PlanSelector,
    };
    use cfctl_auth::{AuthError, MemorySecretStore, ProfileKind, ProfileMetadata, SecretStore};
    use cfctl_catalog::CatalogSnapshot;
    use cfctl_cloudflare::{CloudflareApiErrorV1, CloudflareResponseV1, OperationVerificationV1};
    use cfctl_core::{
        AdapterStatus, CapabilityV1, CostV1, CreatedCollectionResourceContractV1,
        CreatedResourceContractV1, EffectClass, EvidenceClass, EvidenceV1, PlanStatus, PlanV1,
        QuerySerializationV1, ResultEnvelopeV2, RiskClass, SamePathReadContractV1,
        SelectorContractV1, SelectorV1, StandingAuthorityStatus, StandingAuthorityV1,
        TransactionStageV1, VerificationState, hash_value,
    };
    use cfctl_storage::{RuntimePaths, StateStore};
    use chrono::{Duration as ChronoDuration, Utc};
    use serde_json::{Value, json};
    use std::{
        collections::BTreeMap,
        fs,
        sync::{Arc, Barrier},
        thread,
    };

    fn guide_json(capability: &CapabilityV1) -> Value {
        serde_json::to_value(guide_document(capability)).expect("typed capability guide JSON")
    }

    #[test]
    fn permission_inventory_routes_owner_without_dropping_account_context() {
        let account = permission_inventory_call(&KeyPermissionArgs {
            user: false,
            account: "account-a".to_owned(),
        });
        assert_eq!(
            account.capability_id,
            "account-api-tokens-list-permission-groups"
        );
        assert_eq!(
            account.selectors,
            [("account_id".to_owned(), "account-a".to_owned())]
        );
        assert_eq!(account.account.as_deref(), Some("account-a"));

        let user = permission_inventory_call(&KeyPermissionArgs {
            user: true,
            account: "account-a".to_owned(),
        });
        assert_eq!(
            user.capability_id,
            "permission-groups-list-permission-groups"
        );
        assert!(user.selectors.is_empty());
        assert_eq!(user.account.as_deref(), Some("account-a"));
    }

    #[test]
    fn permission_inventory_rewraps_command_and_maps_403_or_9109() {
        let success_response = CloudflareResponseV1 {
            status: 200,
            success: true,
            result: json!([]),
            errors: Vec::new(),
            result_info: None,
            etag: None,
            cf_ray: None,
        };
        let success = permission_inventory_envelope(ResultEnvelopeV2::success(
            "call",
            serde_json::to_value(success_response).expect("response JSON"),
        ));
        assert_eq!(success.command, "keys permissions");
        assert!(success.ok);

        for (status, code) in [(403, None), (400, Some(9109))] {
            let response = CloudflareResponseV1 {
                status,
                success: false,
                result: Value::Null,
                errors: vec![CloudflareApiErrorV1 {
                    code,
                    message: "forbidden".to_owned(),
                }],
                result_info: None,
                etag: None,
                cf_ray: None,
            };
            let mut envelope = ResultEnvelopeV2::success(
                "call",
                serde_json::to_value(response).expect("response JSON"),
            );
            envelope.ok = false;
            let mapped = permission_inventory_envelope(envelope);
            assert_eq!(mapped.command, "keys permissions");
            assert_eq!(mapped.verification.state, VerificationState::Failed);
            let error = mapped.error.expect("actionable permission error");
            assert_eq!(error.code, "CFCTL_PERMISSION_INVENTORY_FORBIDDEN");
            assert!(error.message.contains("Account API Tokens Read"));
            assert!(error.message.contains("Account API Tokens Write"));
        }
    }

    struct DeleteFailingSecretStore;

    #[test]
    fn d1_state_hash_is_validated_by_the_live_precondition_lane() {
        assert!(is_live_plan_precondition_hash("d1_read_replication_state"));
        assert!(is_live_plan_precondition_hash(
            "cloudflare_tunnel_configuration_state"
        ));
        assert!(is_live_plan_precondition_hash(
            "warp_connector_configuration_state"
        ));
        assert!(is_live_plan_precondition_hash("web_analytics_rum_state"));
        assert!(!is_live_plan_precondition_hash("workspace_graph"));
    }

    fn test_catalog() -> CatalogSnapshot {
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
        catalog
    }

    fn global_warp_override_capability() -> CapabilityV1 {
        let mut capability = CapabilityV1::new(
            "devices-resilience-set-global-warp-override",
            "Set Global WARP override state",
            "POST",
            "/accounts/{account_id}/devices/resilience/disconnect",
        );
        capability.mutating = true;
        capability.account_scope = "account".to_owned();
        capability.adapter_status = AdapterStatus::DynamicApi;
        capability.product = "Devices Resilience".to_owned();
        capability.risk = RiskClass::CrossConfig;
        capability.effect = EffectClass::ReversibleWrite;
        capability.permissions = vec!["Zero Trust Resilience Write".to_owned()];
        capability.cost.known = true;
        capability.cost.maximum = Some(0.0);
        capability.cost.basis = Some("no direct incremental operation charge".to_owned());
        capability.entitlement.available = Some(true);
        capability.request_schema = Some(json!({
            "type": "object",
            "required": ["disconnect"],
            "x-cfctl-body-required": true,
            "additionalProperties": false,
            "properties": {
                "disconnect": {"type": "boolean"},
                "justification": {
                    "type": "string",
                    "x-cfctl-verification-observable": false,
                },
            },
        }));
        capability.selectors = vec![SelectorV1 {
            name: "account_id".to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        }];
        capability.verification.strategy =
            "same_path_result_contains_planned_fields_after_mutation".to_owned();
        capability.same_path_read = Some(SamePathReadContractV1 {
            path: "/accounts/{account_id}/devices/resilience/disconnect".to_owned(),
            read_capability_id: "devices-resilience-retrieve-global-warp-override".to_owned(),
            verified_response_fields: vec!["disconnect".to_owned()],
        });
        capability.rollback.supported = true;
        capability.rollback.strategy =
            Some("restore_global_warp_override_prior_disconnect_state".to_owned());
        capability.rollback.warning = Some("restoration requires explicit approval".to_owned());
        capability
    }

    fn d1_read_replication_update_capability() -> CapabilityV1 {
        let mut capability = CapabilityV1::new(
            "d1-update-partial-database",
            "Update D1 Database partially",
            "PATCH",
            "/accounts/{account_id}/d1/database/{database_id}",
        );
        capability.mutating = true;
        capability.account_scope = "account".to_owned();
        capability.adapter_status = AdapterStatus::DynamicApi;
        capability.product = "D1".to_owned();
        capability.risk = RiskClass::ScopedWrite;
        capability.effect = EffectClass::ReversibleWrite;
        capability.permissions = vec!["D1 Write".to_owned()];
        capability.cost.known = true;
        capability.cost.maximum = Some(0.0);
        capability.cost.basis = Some("no incremental operation charge".to_owned());
        capability.request_schema = Some(json!({
            "type": "object",
            "x-cfctl-body-required": true,
            "properties": {
                "read_replication": {
                    "type": "object",
                    "required": ["mode"],
                    "properties": {
                        "mode": {"type": "string", "enum": ["auto", "disabled"]},
                    },
                },
            },
        }));
        capability.selectors = vec![
            SelectorV1 {
                name: "account_id".to_owned(),
                location: "path".to_owned(),
                required: true,
                value_type: "string".to_owned(),
                description: None,
                contract: None,
            },
            SelectorV1 {
                name: "database_id".to_owned(),
                location: "path".to_owned(),
                required: true,
                value_type: "string".to_owned(),
                description: None,
                contract: None,
            },
        ];
        capability.verification.strategy =
            "same_resource_contains_planned_fields_after_update".to_owned();
        capability.same_path_read = Some(SamePathReadContractV1 {
            path: "/accounts/{account_id}/d1/database/{database_id}".to_owned(),
            read_capability_id: "d1-get-database".to_owned(),
            verified_response_fields: vec!["read_replication".to_owned()],
        });
        capability.rollback.supported = true;
        capability.rollback.strategy = Some("restore_d1_read_replication_prior_mode".to_owned());
        capability.rollback.warning = Some("restoration requires explicit approval".to_owned());
        capability
    }

    fn d1_database_create_capability() -> CapabilityV1 {
        let mut capability = CapabilityV1::new(
            "d1-create-database",
            "Create D1 Database",
            "POST",
            "/accounts/{account_id}/d1/database",
        );
        capability.mutating = true;
        capability.account_scope = "account".to_owned();
        capability.adapter_status = AdapterStatus::DynamicApi;
        capability.product = "D1".to_owned();
        capability.risk = RiskClass::ScopedWrite;
        capability.effect = EffectClass::ReversibleWrite;
        capability.permissions = vec!["D1 Write".to_owned()];
        capability.request_schema = Some(json!({
            "type":"object",
            "required":["name"],
            "x-cfctl-body-required":true,
            "properties":{
                "jurisdiction":{"type":"string","enum":["eu","fedramp"]},
                "name":{"type":"string"},
                "primary_location_hint":{
                    "type":"string",
                    "enum":["wnam","enam","weur","eeur","apac","oc"],
                    "x-cfctl-verification-observable":false
                },
                "read_replication":{
                    "type":"object",
                    "required":["mode"],
                    "properties":{"mode":{"type":"string","enum":["auto","disabled"]}}
                }
            }
        }));
        capability.verification.strategy =
            "created_resource_contains_planned_fields_by_returned_id".to_owned();
        capability.created_resource = Some(CreatedResourceContractV1 {
            detail_path: "/accounts/{account_id}/d1/database/{database_id}".to_owned(),
            identity_selector: "database_id".to_owned(),
            response_result_identity_pointer: "/uuid".to_owned(),
            read_capability_id: "d1-get-database".to_owned(),
            delete_capability_id: "d1-delete-database".to_owned(),
            verified_response_fields: vec![
                "jurisdiction".to_owned(),
                "name".to_owned(),
                "read_replication".to_owned(),
            ],
        });
        capability.rollback.supported = true;
        capability.rollback.strategy =
            Some("delete_created_empty_d1_database_by_returned_uuid_if_unchanged".to_owned());
        capability
    }

    fn d1_database_delete_capability() -> CapabilityV1 {
        let mut capability = CapabilityV1::new(
            "d1-delete-database",
            "Delete D1 Database",
            "DELETE",
            "/accounts/{account_id}/d1/database/{database_id}",
        );
        capability.mutating = true;
        capability.account_scope = "account".to_owned();
        capability.adapter_status = AdapterStatus::DynamicApi;
        capability.product = "D1".to_owned();
        capability.risk = RiskClass::Destructive;
        capability.effect = EffectClass::Irreversible;
        capability
    }

    fn cloudflare_tunnel_configuration_capability() -> CapabilityV1 {
        let mut capability = CapabilityV1::new(
            "cloudflare-tunnel-configuration-put-configuration",
            "Put configuration",
            "PUT",
            "/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations",
        );
        capability.mutating = true;
        capability.account_scope = "account".to_owned();
        capability.adapter_status = AdapterStatus::DynamicApi;
        capability.product = "Cloudflare Tunnel Configuration".to_owned();
        capability.risk = RiskClass::CrossConfig;
        capability.effect = EffectClass::ReversibleWrite;
        capability.permissions = vec![
            "Cloudflare One Connectors Write".to_owned(),
            "Cloudflare One Connector: cloudflared Write".to_owned(),
            "Cloudflare Tunnel Write".to_owned(),
        ];
        capability.cost.known = true;
        capability.cost.maximum = Some(0.0);
        capability.cost.basis = Some("no direct incremental operation charge".to_owned());
        capability.entitlement.available = Some(true);
        capability.request_schema = Some(
            serde_json::from_str(include_str!(
                "../../cfctl-core/tests/fixtures/cloudflare-tunnel-configuration-put-request-schema.json"
            ))
            .expect("pinned Cloudflare Tunnel configuration schema"),
        );
        capability.selectors = ["account_id", "tunnel_id"]
            .into_iter()
            .map(|name| SelectorV1 {
                name: name.to_owned(),
                location: "path".to_owned(),
                required: true,
                value_type: "string".to_owned(),
                description: None,
                contract: None,
            })
            .collect();
        capability.verification.required = true;
        capability.verification.strategy =
            "same_path_result_contains_planned_fields_after_update".to_owned();
        capability.same_path_read = Some(SamePathReadContractV1 {
            path: "/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations".to_owned(),
            read_capability_id: "cloudflare-tunnel-configuration-get-configuration".to_owned(),
            verified_response_fields: vec!["config".to_owned()],
        });
        capability.rollback.supported = true;
        capability.rollback.strategy =
            Some("restore_cloudflare_tunnel_configuration_prior_snapshot".to_owned());
        capability.rollback.warning = Some("restoration requires explicit approval".to_owned());
        capability
    }

    fn warp_connector_configuration_capability() -> CapabilityV1 {
        let mut capability = CapabilityV1::new(
            "cloudflare-tunnel-configuration-update-warp-connector-configuration",
            "Update WARP Connector configuration",
            "PUT",
            "/accounts/{account_id}/warp_connector/{tunnel_id}/configurations",
        );
        capability.mutating = true;
        capability.account_scope = "account".to_owned();
        capability.adapter_status = AdapterStatus::DynamicApi;
        capability.product = "Cloudflare Tunnel Configuration".to_owned();
        capability.risk = RiskClass::CrossConfig;
        capability.effect = EffectClass::ReversibleWrite;
        capability.permissions = vec![
            "Cloudflare One Connectors Write".to_owned(),
            "Cloudflare One Connector: WARP Write".to_owned(),
        ];
        capability.cost.known = true;
        capability.cost.maximum = Some(0.0);
        capability.cost.basis = Some("no direct incremental operation charge".to_owned());
        capability.entitlement.available = Some(true);
        capability.request_schema = Some(
            serde_json::from_str(include_str!(
                "../../cfctl-core/tests/fixtures/warp-connector-configuration-update-request-schema.json"
            ))
            .expect("pinned WARP Connector configuration schema"),
        );
        capability.selectors = ["account_id", "tunnel_id"]
            .into_iter()
            .map(|name| SelectorV1 {
                name: name.to_owned(),
                location: "path".to_owned(),
                required: true,
                value_type: "string".to_owned(),
                description: None,
                contract: None,
            })
            .collect();
        capability.verification.required = true;
        capability.verification.strategy =
            "same_path_result_contains_planned_fields_after_update".to_owned();
        capability.same_path_read = Some(SamePathReadContractV1 {
            path: "/accounts/{account_id}/warp_connector/{tunnel_id}/configurations".to_owned(),
            read_capability_id: "cloudflare-tunnel-configuration-get-warp-connector-configuration"
                .to_owned(),
            verified_response_fields: vec!["config".to_owned(), "ha_mode".to_owned()],
        });
        capability.rollback.supported = true;
        capability.rollback.strategy =
            Some("restore_warp_connector_configuration_prior_snapshot".to_owned());
        capability.rollback.warning = Some("restoration requires explicit approval".to_owned());
        capability
    }

    fn web_analytics_rum_capability() -> CapabilityV1 {
        let mut capability = CapabilityV1::new(
            "web-analytics-toggle-rum",
            "Toggle RUM on/off for a zone",
            "PATCH",
            "/zones/{zone_id}/settings/rum",
        );
        capability.mutating = true;
        capability.account_scope = "zone".to_owned();
        capability.adapter_status = AdapterStatus::DynamicApi;
        capability.product = "Web Analytics".to_owned();
        capability.risk = RiskClass::CrossConfig;
        capability.effect = EffectClass::ReversibleWrite;
        capability.permissions = vec!["Zone Settings Write".to_owned()];
        capability.cost.known = true;
        capability.cost.maximum = Some(0.0);
        capability.cost.basis = Some("no direct incremental operation charge".to_owned());
        capability.entitlement.available = Some(true);
        capability.request_schema = Some(
            serde_json::from_str(include_str!(
                "../../cfctl-core/tests/fixtures/web-analytics-rum-toggle-request-schema.json"
            ))
            .expect("pinned Web Analytics RUM toggle schema"),
        );
        capability.selectors = vec![SelectorV1 {
            name: "zone_id".to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        }];
        capability.verification.required = true;
        capability.verification.strategy =
            "same_path_result_contains_planned_fields_after_update".to_owned();
        capability.same_path_read = Some(SamePathReadContractV1 {
            path: "/zones/{zone_id}/settings/rum".to_owned(),
            read_capability_id: "web-analytics-get-rum-status".to_owned(),
            verified_response_fields: vec!["value".to_owned()],
        });
        capability.rollback.supported = true;
        capability.rollback.strategy = Some("restore_web_analytics_rum_prior_value".to_owned());
        capability.rollback.warning = Some("restoration requires explicit approval".to_owned());
        capability
    }

    fn dns_record_update_capability(method: &str) -> CapabilityV1 {
        let id = if method == "PUT" {
            "dns-records-for-a-zone-update-dns-record"
        } else {
            "dns-records-for-a-zone-patch-dns-record"
        };
        let mut capability = CapabilityV1::new(
            id,
            "Update DNS Record",
            method,
            "/zones/{zone_id}/dns_records/{dns_record_id}",
        );
        capability.mutating = true;
        capability.account_scope = "zone".to_owned();
        capability.adapter_status = AdapterStatus::DynamicApi;
        capability.product = "DNS Records for a Zone".to_owned();
        capability.risk = RiskClass::ScopedWrite;
        capability.effect = EffectClass::ReversibleWrite;
        capability.permissions = vec!["DNS Write".to_owned()];
        capability.cost.known = true;
        capability.cost.maximum = Some(0.0);
        capability.request_schema = Some(
            serde_json::from_str(include_str!(
                "../../cfctl-core/tests/fixtures/dns-record-update-request-schema.json"
            ))
            .expect("pinned DNS record schema"),
        );
        capability.selectors = vec![
            SelectorV1 {
                name: "dns_record_id".to_owned(),
                location: "path".to_owned(),
                required: true,
                value_type: "string".to_owned(),
                description: None,
                contract: Some(SelectorContractV1 {
                    schema: json!({"type":"string","maxLength":32}),
                    query: None,
                }),
            },
            SelectorV1 {
                name: "zone_id".to_owned(),
                location: "path".to_owned(),
                required: true,
                value_type: "string".to_owned(),
                description: None,
                contract: Some(SelectorContractV1 {
                    schema: json!({"type":"string","maxLength":32}),
                    query: None,
                }),
            },
            SelectorV1 {
                name: "include_shadow_metadata".to_owned(),
                location: "query".to_owned(),
                required: false,
                value_type: "boolean".to_owned(),
                description: None,
                contract: Some(SelectorContractV1 {
                    schema: json!({"type":"boolean"}),
                    query: Some(QuerySerializationV1 {
                        style: "form".to_owned(),
                        explode: true,
                        allow_reserved: false,
                        allow_empty_value: false,
                    }),
                }),
            },
        ];
        capability.verification.strategy =
            "dns_record_details_match_planned_id_and_fields".to_owned();
        capability.same_path_read = Some(SamePathReadContractV1 {
            path: "/zones/{zone_id}/dns_records/{dns_record_id}".to_owned(),
            read_capability_id: "dns-records-for-a-zone-dns-record-details".to_owned(),
            verified_response_fields: [
                "comment",
                "content",
                "data",
                "name",
                "priority",
                "private_routing",
                "proxied",
                "settings",
                "tags",
                "ttl",
                "type",
            ]
            .map(str::to_owned)
            .to_vec(),
        });
        capability.rollback.supported = true;
        capability.rollback.strategy =
            Some("restore_dns_record_prior_snapshot_with_put".to_owned());
        capability
    }

    #[test]
    fn dns_record_state_receipt_projects_only_the_exact_writable_type_branch() {
        let capability = dns_record_update_capability("PATCH");
        assert!(should_bind_dns_record_state(&capability));
        let response = CloudflareResponseV1 {
            status: 200,
            success: true,
            result: json!({
                "id":"record-a",
                "type":"TXT",
                "name":"txt.example.com",
                "content":"prior-value",
                "ttl":300,
                "proxied":false,
                "comment":null,
                "tags":[],
                "settings":{"ipv4_only":false,"future_read_only":true},
                "meta":{"auto_added":false},
                "modified_on":"future",
            }),
            errors: Vec::new(),
            result_info: None,
            etag: None,
            cf_ray: None,
        };

        let receipt = apply_dns_record_state_response(
            &capability,
            "account-a",
            "zone-a",
            "record-a",
            &response,
        )
        .expect("DNS state receipt");
        assert_eq!(
            receipt["prior_record"],
            json!({
                "type":"TXT",
                "name":"txt.example.com",
                "content":"prior-value",
                "ttl":300,
                "proxied":false,
                "tags":[],
                "settings":{"ipv4_only":false},
            })
        );
        assert!(receipt["prior_record"].get("meta").is_none());

        let mut unknown = response;
        unknown.result["type"] = json!("FUTURE");
        assert!(
            apply_dns_record_state_response(
                &capability,
                "account-a",
                "zone-a",
                "record-a",
                &unknown,
            )
            .is_err()
        );
    }

    #[test]
    fn dns_record_state_receipt_rejects_rehashed_broadening_and_retargeting() {
        let capability = dns_record_update_capability("PATCH");
        let receipt = json!({
            "schema_version":1,
            "source_capability_id":"dns-records-for-a-zone-dns-record-details",
            "source_path":"/zones/{zone_id}/dns_records/{dns_record_id}",
            "target_capability_id":"dns-records-for-a-zone-patch-dns-record",
            "target_method":"PATCH",
            "target_scope":"zone",
            "account_id":"account-a",
            "zone_id":"zone-a",
            "dns_record_id":"record-a",
            "prior_record":{
                "type":"TXT",
                "name":"txt.example.com",
                "content":"prior-value",
                "ttl":300,
            },
        });
        let mut plan = PlanV1::draft(
            "profile-a",
            "account-a",
            "catalog-sha",
            capability,
            json!({
                "selectors":{"zone_id":"zone-a","dns_record_id":"record-a"},
                "account_id":"account-a",
                "adapter":{},
                "live_preconditions":{"dns_record_state":receipt},
            }),
        )
        .expect("plan");
        plan.precondition_hashes.insert(
            "dns_record_state".to_owned(),
            hash_value(&receipt).expect("receipt hash"),
        );
        assert_eq!(
            required_dns_record_state_precondition(&plan).expect("bound DNS precondition"),
            plan.precondition_hashes
                .get("dns_record_state")
                .map(String::as_str)
        );

        let mut broadened = receipt.clone();
        broadened["prior_record"]["future"] = json!(true);
        plan.precondition_hashes.insert(
            "dns_record_state".to_owned(),
            hash_value(&broadened).expect("broadened hash"),
        );
        plan.targets["live_preconditions"]["dns_record_state"] = broadened;
        required_dns_record_state_precondition(&plan)
            .expect_err("a rehashed broadened snapshot must fail");

        let mut retargeted = receipt;
        retargeted["dns_record_id"] = json!("record-b");
        plan.precondition_hashes.insert(
            "dns_record_state".to_owned(),
            hash_value(&retargeted).expect("retargeted hash"),
        );
        plan.targets["live_preconditions"]["dns_record_state"] = retargeted;
        let error = required_dns_record_state_precondition(&plan)
            .expect_err("a rehashed cross-record receipt must fail");
        assert!(error.to_string().contains("account, zone, record"));
    }

    fn oauth_client_secret_capability(id: &str, method: &str, strategy: &str) -> CapabilityV1 {
        let mut capability = CapabilityV1::new(
            id,
            id,
            method,
            "/accounts/{account_id}/oauth_clients/{oauth_client_id}/rotate_secret",
        );
        capability.product = "OAuth Clients".to_owned();
        capability.permissions = vec!["OAuth Client Write".to_owned()];
        capability.adapter_status = AdapterStatus::DynamicApi;
        capability.cost = CostV1::default();
        capability.entitlement.available = Some(true);
        capability.verification.strategy = strategy.to_owned();
        capability.rollback.supported = false;
        capability.rollback.warning = Some(
            "OAuth client secret cutover has no automatic rollback; preserve the old secret until dependents are verified"
                .to_owned(),
        );
        if method == "POST" {
            capability.risk = RiskClass::SecretSensitive;
            capability.effect = EffectClass::IdentityOrOwnership;
        } else {
            capability.risk = RiskClass::Destructive;
            capability.effect = EffectClass::Irreversible;
        }
        capability.selectors = ["account_id", "oauth_client_id"]
            .into_iter()
            .map(|name| SelectorV1 {
                name: name.to_owned(),
                location: "path".to_owned(),
                required: true,
                value_type: "string".to_owned(),
                description: None,
                contract: None,
            })
            .collect();
        capability.same_path_read = Some(SamePathReadContractV1 {
            path: "/accounts/{account_id}/oauth_clients/{oauth_client_id}".to_owned(),
            read_capability_id: "oauth-clients-get".to_owned(),
            verified_response_fields: vec!["client_id".to_owned(), "has_rotated_secret".to_owned()],
        });
        capability
    }

    fn oauth_client_secret_state_response(has_rotated_secret: bool) -> CloudflareResponseV1 {
        CloudflareResponseV1 {
            status: 200,
            success: true,
            result: json!({
                "client_id":"oauth-client-a",
                "has_rotated_secret":has_rotated_secret,
            }),
            errors: Vec::new(),
            result_info: None,
            etag: None,
            cf_ray: None,
        }
    }

    #[test]
    fn oauth_client_secret_state_precondition_is_phase_specific_and_target_bound() {
        let rotate = oauth_client_secret_capability(
            "oauth-clients-rotate-secret",
            "POST",
            "oauth_client_reports_rotated_secret_after_value_roll",
        );
        let delete_old = oauth_client_secret_capability(
            "oauth-clients-delete-rotated-secret",
            "DELETE",
            "oauth_client_reports_no_rotated_secret_after_old_secret_delete",
        );
        assert!(should_bind_oauth_client_secret_state(&rotate));
        assert!(should_bind_oauth_client_secret_state(&delete_old));
        let guide = guide_json(&rotate);
        assert_eq!(guide["stages"][4]["contract_state"], "live_read_required");
        assert_eq!(
            guide["stages"][4]["commands"][0],
            json!([
                "cfctl",
                "call",
                "oauth-clients-get",
                "--selector",
                "account_id=<account_id>",
                "--selector",
                "oauth_client_id=<oauth_client_id>",
                "--json"
            ])
        );
        let rotate_receipt = apply_oauth_client_secret_state_response(
            &rotate,
            "account-a",
            "oauth-client-a",
            &oauth_client_secret_state_response(false),
        )
        .expect("one-secret state permits rotation planning");
        assert_eq!(rotate_receipt["key_overlap_active"], false);
        apply_oauth_client_secret_state_response(
            &rotate,
            "account-a",
            "oauth-client-a",
            &oauth_client_secret_state_response(true),
        )
        .expect_err("a second rotation must be refused while two secrets exist");

        let delete_receipt = apply_oauth_client_secret_state_response(
            &delete_old,
            "account-a",
            "oauth-client-a",
            &oauth_client_secret_state_response(true),
        )
        .expect("two-secret state permits old-secret deletion planning");
        assert_eq!(delete_receipt["key_overlap_active"], true);
        apply_oauth_client_secret_state_response(
            &delete_old,
            "account-a",
            "oauth-client-a",
            &oauth_client_secret_state_response(false),
        )
        .expect_err("old-secret deletion must be refused without two secrets");

        let mut plan = PlanV1::draft(
            "profile-a",
            "account-a",
            "catalog-sha",
            delete_old,
            json!({
                "selectors":{
                    "account_id":"account-a",
                    "oauth_client_id":"oauth-client-a"
                },
                "account_id":"account-a",
                "adapter":{},
                "live_preconditions":{"oauth_client_key_overlap":delete_receipt},
            }),
        )
        .expect("plan");
        plan.precondition_hashes.insert(
            "oauth_client_key_overlap".to_owned(),
            hash_value(&delete_receipt).expect("receipt hash"),
        );
        assert!(
            required_oauth_client_secret_state_precondition(&plan)
                .expect("bound OAuth precondition")
                .is_some()
        );

        let mut retargeted = delete_receipt;
        retargeted["oauth_client_id"] = json!("oauth-client-b");
        plan.precondition_hashes.insert(
            "oauth_client_key_overlap".to_owned(),
            hash_value(&retargeted).expect("retargeted receipt hash"),
        );
        plan.targets["live_preconditions"]["oauth_client_key_overlap"] = retargeted;
        required_oauth_client_secret_state_precondition(&plan)
            .expect_err("a rehashed cross-client receipt must fail");
    }

    #[test]
    fn prepared_oauth_client_rotation_plan_carries_exact_two_secret_transition() {
        let root = tempfile::tempdir().expect("runtime root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
        let capability = oauth_client_secret_capability(
            "oauth-clients-rotate-secret",
            "POST",
            "oauth_client_reports_rotated_secret_after_value_roll",
        );
        assert!(capability.mutation_contract_gaps().is_empty());
        let mut catalog = CatalogSnapshot {
            schema_version: 1,
            generated_at: Utc::now(),
            source_url: "https://example.invalid/openapi.json".to_owned(),
            source_hash: "source-sha".to_owned(),
            schema_hash: String::new(),
            capabilities: BTreeMap::from([(capability.id.clone(), capability.clone())]),
        };
        catalog.refresh_hash().expect("catalog hash");
        let profile = ProfileMetadata::new("profile-a", ProfileKind::ApiToken, Some("account-a"));
        let input = CallInput {
            selectors: json!({
                "account_id":"account-a",
                "oauth_client_id":"oauth-client-a"
            }),
            query: json!({}),
            body: None,
            ..CallInput::default()
        };
        let response = CloudflareResponseV1 {
            status: 200,
            success: true,
            result: json!({
                "client_id":"oauth-client-a",
                "has_rotated_secret":false,
            }),
            errors: Vec::new(),
            result_info: None,
            etag: None,
            cf_ray: None,
        };
        let receipt = apply_oauth_client_secret_state_response(
            &capability,
            "account-a",
            "oauth-client-a",
            &response,
        )
        .expect("OAuth state receipt");
        let receipt_hash = hash_value(&receipt).expect("receipt hash");
        let evidence = store
            .write_evidence(EvidenceClass::LiveRead, &receipt)
            .expect("live read evidence");
        let sink = root.path().join("oauth-client-secret");

        let envelope = persist_prepared_plan(
            &store,
            &catalog,
            capability,
            input,
            PlanAuthority {
                profile: &profile,
                account_id: "account-a",
            },
            json!({"value_out":sink}),
            LivePlanPreconditions {
                entitlement: None,
                zone_account: None,
                global_warp_override_state: None,
                d1_read_replication_state: None,
                d1_empty_database_state: None,
                cloudflare_tunnel_configuration_state: None,
                warp_connector_configuration_state: None,
                web_analytics_rum_state: None,
                dns_record_state: None,
                oauth_client_secret_state: Some((receipt.clone(), evidence)),
            },
        )
        .expect("prepared OAuth rotation plan");
        let plan = &envelope.result["plan"];

        assert_eq!(
            plan["precondition_hashes"][OAUTH_CLIENT_KEY_OVERLAP_PRECONDITION],
            receipt_hash
        );
        assert_eq!(
            plan["targets"]["live_preconditions"][OAUTH_CLIENT_KEY_OVERLAP_PRECONDITION],
            receipt
        );
        assert_eq!(
            plan["cloudflare_diffs"][0]["observed_before"],
            json!({"key_overlap_active":false})
        );
        assert_eq!(
            plan["cloudflare_diffs"][0]["planned_after"],
            json!({"key_overlap_active":true})
        );
    }

    #[test]
    fn d1_state_receipt_binds_only_the_exact_database_mode() {
        let capability = d1_read_replication_update_capability();
        assert!(should_bind_d1_read_replication_state(&capability));
        let response = CloudflareResponseV1 {
            status: 200,
            success: true,
            result: json!({
                "uuid": "database-a",
                "read_replication": {
                    "mode": "disabled",
                    "ignored_future_field": true,
                },
            }),
            errors: Vec::new(),
            result_info: None,
            etag: None,
            cf_ray: None,
        };

        let receipt = apply_d1_read_replication_state_response(
            &capability,
            "account-a",
            "database-a",
            &response,
        )
        .expect("D1 state receipt");
        assert_eq!(
            receipt,
            json!({
                "schema_version": 1,
                "source_capability_id": "d1-get-database",
                "source_path": "/accounts/{account_id}/d1/database/{database_id}",
                "target_capability_id": "d1-update-partial-database",
                "target_method": "PATCH",
                "target_scope": "account",
                "account_id": "account-a",
                "database_id": "database-a",
                "read_replication": {"mode":"disabled"},
            })
        );

        let mut drifted = response;
        drifted.result["read_replication"]["mode"] = json!("experimental");
        let error = apply_d1_read_replication_state_response(
            &capability,
            "account-a",
            "database-a",
            &drifted,
        )
        .expect_err("unknown modes fail closed");
        assert!(error.to_string().contains("bounded read_replication.mode"));
    }

    #[test]
    fn d1_state_receipt_rejects_rehashed_cross_database_targets() {
        let capability = d1_read_replication_update_capability();
        let receipt = json!({
            "schema_version": 1,
            "source_capability_id": "d1-get-database",
            "source_path": "/accounts/{account_id}/d1/database/{database_id}",
            "target_capability_id": "d1-update-partial-database",
            "target_method": "PATCH",
            "target_scope": "account",
            "account_id": "account-a",
            "database_id": "database-a",
            "read_replication": {"mode":"disabled"},
        });
        let mut plan = PlanV1::draft(
            "profile-a",
            "account-a",
            "catalog-sha",
            capability,
            json!({
                "selectors":{"account_id":"account-a","database_id":"database-a"},
                "account_id":"account-a",
                "adapter":{},
                "live_preconditions":{"d1_read_replication_state":receipt},
            }),
        )
        .expect("plan");
        plan.precondition_hashes.insert(
            "d1_read_replication_state".to_owned(),
            hash_value(&receipt).expect("receipt hash"),
        );
        assert_eq!(
            required_d1_read_replication_state_precondition(&plan).expect("bound precondition"),
            plan.precondition_hashes
                .get("d1_read_replication_state")
                .map(String::as_str)
        );

        let mut broadened = receipt.clone();
        broadened["read_replication"]["future"] = json!(true);
        plan.precondition_hashes.insert(
            "d1_read_replication_state".to_owned(),
            hash_value(&broadened).expect("broadened receipt hash"),
        );
        plan.targets["live_preconditions"]["d1_read_replication_state"] = broadened;
        required_d1_read_replication_state_precondition(&plan)
            .expect_err("a rehashed broadened state object must still fail");

        let mut retargeted = receipt;
        retargeted["database_id"] = json!("database-b");
        plan.precondition_hashes.insert(
            "d1_read_replication_state".to_owned(),
            hash_value(&retargeted).expect("retargeted receipt hash"),
        );
        plan.targets["live_preconditions"]["d1_read_replication_state"] = retargeted;
        let error = required_d1_read_replication_state_precondition(&plan)
            .expect_err("a rehashed cross-database receipt must still fail");
        assert!(error.to_string().contains("invalid account, database"));
    }

    #[test]
    fn cloudflare_tunnel_configuration_receipt_binds_only_restorable_routing_state() {
        let capability = cloudflare_tunnel_configuration_capability();
        assert!(should_bind_cloudflare_tunnel_configuration_state(
            &capability
        ));
        let response = CloudflareResponseV1 {
            status: 200,
            success: true,
            result: json!({
                "config": {
                    "ingress": [
                        {"hostname":"app.example.com","service":"http://localhost:8080"},
                        {"hostname":"","service":"http_status:404"}
                    ]
                },
                "version": 17,
            }),
            errors: Vec::new(),
            result_info: None,
            etag: None,
            cf_ray: None,
        };

        let receipt = apply_cloudflare_tunnel_configuration_state_response(
            &capability,
            "account-a",
            "tunnel-a",
            &response,
        )
        .expect("Tunnel configuration receipt");
        assert_eq!(
            receipt,
            json!({
                "schema_version": 1,
                "source_capability_id": "cloudflare-tunnel-configuration-get-configuration",
                "source_path": "/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations",
                "target_capability_id": "cloudflare-tunnel-configuration-put-configuration",
                "target_method": "PUT",
                "target_path": "/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations",
                "target_scope": "account",
                "account_id": "account-a",
                "tunnel_id": "tunnel-a",
                "prior_config": {
                    "ingress": [
                        {"hostname":"app.example.com","service":"http://localhost:8080"},
                        {"hostname":"","service":"http_status:404"}
                    ]
                },
            })
        );

        let mut unsupported = response;
        unsupported.result["config"]["future_routing_control"] = json!(true);
        let error = apply_cloudflare_tunnel_configuration_state_response(
            &capability,
            "account-a",
            "tunnel-a",
            &unsupported,
        )
        .expect_err("unrestorable future fields fail closed");
        assert!(error.to_string().contains("restorable request contract"));
    }

    #[test]
    fn cloudflare_tunnel_configuration_preflight_requires_one_final_catch_all_rule() {
        let capability = cloudflare_tunnel_configuration_capability();
        let valid = CallInput {
            selectors: json!({"account_id":"account-a","tunnel_id":"tunnel-a"}),
            body: Some(json!({"config":{"ingress":[
                {"hostname":"app.example.com","service":"http://localhost:8080"},
                {"hostname":"","service":"http_status:404"}
            ]}})),
            ..CallInput::default()
        };
        preflight_call_input(&capability, &valid, None).expect("final catch-all is valid");

        let mut missing = valid.clone();
        missing.body.as_mut().expect("body")["config"]["ingress"][1]["hostname"] =
            json!("other.example.com");
        let error = preflight_call_input(&capability, &missing, None)
            .expect_err("a named final rule does not match all traffic");
        assert!(error.to_string().contains("final catch-all"));

        let mut unreachable = valid;
        unreachable.body.as_mut().expect("body")["config"]["ingress"] = json!([
            {"hostname":"","service":"http_status:404"},
            {"hostname":"app.example.com","service":"http://localhost:8080"},
            {"hostname":"","service":"http_status:404"}
        ]);
        let error = preflight_call_input(&capability, &unreachable, None)
            .expect_err("an earlier catch-all makes later rules unreachable");
        assert!(error.to_string().contains("rule 1"));
        assert!(error.to_string().contains("unreachable"));
    }

    #[test]
    fn d1_database_create_preflight_rejects_ignored_location_hint_combinations() {
        let mut capability = CapabilityV1::new(
            "d1-create-database",
            "Create D1 Database",
            "POST",
            "/accounts/{account_id}/d1/database",
        );
        capability.request_schema = Some(json!({
            "type":"object",
            "required":["name"],
            "properties":{
                "name":{"type":"string"},
                "jurisdiction":{"type":"string","enum":["eu","fedramp"]},
                "primary_location_hint":{"type":"string","enum":["wnam","enam"]}
            }
        }));
        let input = CallInput {
            selectors: json!({"account_id":"account-a"}),
            body: Some(json!({
                "name":"smoke-database",
                "jurisdiction":"eu",
                "primary_location_hint":"enam"
            })),
            ..CallInput::default()
        };
        let error = preflight_call_input(&capability, &input, None)
            .expect_err("Cloudflare ignores the location hint when jurisdiction is set");
        assert!(
            error.to_string().contains("gives jurisdiction precedence"),
            "{error}"
        );

        let mut location_only = input;
        location_only
            .body
            .as_mut()
            .and_then(Value::as_object_mut)
            .expect("D1 body")
            .remove("jurisdiction");
        preflight_call_input(&capability, &location_only, None)
            .expect("a location hint without jurisdiction is unambiguous");
    }

    #[test]
    fn d1_empty_database_compensation_binds_exact_live_state_and_rejects_tables() {
        let capability = d1_database_delete_capability();
        let adapter = json!({
            "compensates_operation_id":"source-create-op",
            "compensates_capability_id":"d1-create-database",
            "compensation_strategy":"delete_created_empty_d1_database_by_returned_uuid_if_unchanged",
            "source_receipt_hash":"sha256:source-create-receipt"
        });
        let response = CloudflareResponseV1 {
            status: 200,
            success: true,
            result: json!({
                "uuid":"database-a",
                "name":"smoke-database",
                "num_tables":0,
                "file_size":12288,
                "jurisdiction":"eu",
                "read_replication":{"mode":"disabled"}
            }),
            errors: Vec::new(),
            result_info: None,
            etag: None,
            cf_ray: None,
        };
        let receipt = apply_d1_empty_database_state_response(
            &capability,
            &adapter,
            "account-a",
            "database-a",
            &response,
        )
        .expect("empty database receipt");
        assert_eq!(receipt["num_tables"], 0);
        assert_eq!(receipt["database_id"], "database-a");
        assert_eq!(
            receipt["source_create_receipt_hash"],
            "sha256:source-create-receipt"
        );

        let mut plan = PlanV1::draft(
            "profile-a",
            "account-a",
            "catalog-sha",
            capability.clone(),
            json!({
                "selectors":{"account_id":"account-a","database_id":"database-a"},
                "account_id":"account-a",
                "adapter":adapter,
                "live_preconditions":{"d1_empty_database_state":receipt.clone()}
            }),
        )
        .expect("D1 compensation plan");
        plan.precondition_hashes.insert(
            "d1_empty_database_state".to_owned(),
            hash_value(&receipt).expect("receipt hash"),
        );
        assert_eq!(
            required_d1_empty_database_state_precondition(&plan)
                .expect("bound empty-state precondition"),
            plan.precondition_hashes
                .get("d1_empty_database_state")
                .map(String::as_str)
        );

        let mut retargeted = receipt;
        retargeted["database_id"] = json!("database-b");
        plan.precondition_hashes.insert(
            "d1_empty_database_state".to_owned(),
            hash_value(&retargeted).expect("retargeted receipt hash"),
        );
        plan.targets["live_preconditions"]["d1_empty_database_state"] = retargeted;
        let error = required_d1_empty_database_state_precondition(&plan)
            .expect_err("a rehashed cross-database receipt must fail");
        assert!(error.to_string().contains("account, database, table count"));

        let mut populated = response;
        populated.result["num_tables"] = json!(1);
        let error = apply_d1_empty_database_state_response(
            &capability,
            &plan.targets["adapter"],
            "account-a",
            "database-a",
            &populated,
        )
        .expect_err("a populated database must never become a compensation delete plan");
        assert!(error.to_string().contains("contains 1 table"));
    }

    #[test]
    fn cloudflare_tunnel_configuration_state_rejects_rehashed_cross_tunnel_targets() {
        let capability = cloudflare_tunnel_configuration_capability();
        let receipt = json!({
            "schema_version": 1,
            "source_capability_id": "cloudflare-tunnel-configuration-get-configuration",
            "source_path": "/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations",
            "target_capability_id": "cloudflare-tunnel-configuration-put-configuration",
            "target_method": "PUT",
            "target_path": "/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations",
            "target_scope": "account",
            "account_id": "account-a",
            "tunnel_id": "tunnel-a",
            "prior_config": {"ingress":[{"hostname":"","service":"http_status:404"}]},
        });
        let mut plan = PlanV1::draft(
            "profile-a",
            "account-a",
            "catalog-sha",
            capability,
            json!({
                "selectors":{"account_id":"account-a","tunnel_id":"tunnel-a"},
                "account_id":"account-a",
                "adapter":{},
                "live_preconditions":{"cloudflare_tunnel_configuration_state":receipt},
            }),
        )
        .expect("plan");
        plan.precondition_hashes.insert(
            "cloudflare_tunnel_configuration_state".to_owned(),
            hash_value(&receipt).expect("receipt hash"),
        );
        assert_eq!(
            required_cloudflare_tunnel_configuration_state_precondition(&plan)
                .expect("bound precondition"),
            plan.precondition_hashes
                .get("cloudflare_tunnel_configuration_state")
                .map(String::as_str)
        );

        let mut retargeted = receipt;
        retargeted["tunnel_id"] = json!("tunnel-b");
        plan.precondition_hashes.insert(
            "cloudflare_tunnel_configuration_state".to_owned(),
            hash_value(&retargeted).expect("retargeted receipt hash"),
        );
        plan.targets["live_preconditions"]["cloudflare_tunnel_configuration_state"] = retargeted;
        let error = required_cloudflare_tunnel_configuration_state_precondition(&plan)
            .expect_err("a rehashed cross-Tunnel receipt must still fail");
        assert!(error.to_string().contains("account, Tunnel"));
    }

    #[test]
    fn warp_connector_configuration_preflight_binds_mode_to_exact_provider_state() {
        let capability = warp_connector_configuration_capability();
        assert!(should_bind_warp_connector_configuration_state(&capability));
        for body in [
            json!({"ha_mode":"none"}),
            json!({"ha_mode":"disabled","config":{}}),
            json!({"ha_mode":"aws","config":{"fnr_id":"eni-secondary-a"}}),
            json!({
                "ha_mode":"local",
                "config":{
                    "vips":[{"address":"192.0.2.10"},{"address":"2001:db8::10"}],
                    "vips_previous":[{"address":"192.0.2.9"}]
                }
            }),
        ] {
            preflight_call_input(
                &capability,
                &CallInput {
                    selectors: json!({"account_id":"account-a","tunnel_id":"tunnel-a"}),
                    body: Some(body),
                    ..CallInput::default()
                },
                None,
            )
            .expect("valid HA provider contract");
        }

        for (body, expected) in [
            (
                json!({"ha_mode":"none","config":{"fnr_id":"eni-a"}}),
                "requires `config` to be omitted",
            ),
            (
                json!({"ha_mode":"aws","config":{"fnr_id":""}}),
                "non-empty `config.fnr_id`",
            ),
            (
                json!({"ha_mode":"local","config":{"vips":[{"address":"not-an-ip"}]}}),
                "not a valid IPv4 or IPv6 address",
            ),
            (
                json!({
                    "ha_mode":"local",
                    "config":{
                        "vips":[{"address":"192.0.2.10"}],
                        "vips_previous":[{"address":"192.0.2.10"}]
                    }
                }),
                "duplicated across",
            ),
            (
                json!({
                    "ha_mode":"local",
                    "config":{
                        "vips":[{"address":"2001:db8::1"}],
                        "vips_previous":[{"address":"2001:0db8:0:0:0:0:0:1"}]
                    }
                }),
                "duplicated across",
            ),
        ] {
            let error = preflight_call_input(
                &capability,
                &CallInput {
                    selectors: json!({"account_id":"account-a","tunnel_id":"tunnel-a"}),
                    body: Some(body),
                    ..CallInput::default()
                },
                None,
            )
            .expect_err("invalid HA provider contract must fail closed");
            assert!(error.to_string().contains(expected), "{error}");
        }
    }

    #[test]
    fn warp_connector_state_receipt_binds_only_restorable_mesh_ha_state() {
        let capability = warp_connector_configuration_capability();
        let response = CloudflareResponseV1 {
            status: 200,
            success: true,
            result: json!({
                "ha_mode":"local",
                "config":{"vips":[{"address":"192.0.2.10"}]},
                "version":7,
                "tunnel_id":"tunnel-a",
                "future_read_only":"ignored"
            }),
            errors: Vec::new(),
            result_info: None,
            etag: None,
            cf_ray: None,
        };
        let receipt = apply_warp_connector_configuration_state_response(
            &capability,
            "account-a",
            "tunnel-a",
            &response,
        )
        .expect("WARP Connector state receipt");
        assert_eq!(
            receipt,
            json!({
                "schema_version":1,
                "source_capability_id":"cloudflare-tunnel-configuration-get-warp-connector-configuration",
                "source_path":"/accounts/{account_id}/warp_connector/{tunnel_id}/configurations",
                "target_capability_id":"cloudflare-tunnel-configuration-update-warp-connector-configuration",
                "target_method":"PUT",
                "target_path":"/accounts/{account_id}/warp_connector/{tunnel_id}/configurations",
                "target_scope":"account",
                "account_id":"account-a",
                "tunnel_id":"tunnel-a",
                "prior_ha_mode":"local",
                "prior_config":{"vips":[{"address":"192.0.2.10"}]},
            })
        );

        let mut unsupported = response;
        unsupported.result["config"]["vips"][0]["address"] = json!("invalid");
        let error = apply_warp_connector_configuration_state_response(
            &capability,
            "account-a",
            "tunnel-a",
            &unsupported,
        )
        .expect_err("unrestorable live state fails closed");
        assert!(error.to_string().contains("restorable HA contract"));

        unsupported.result = json!({
            "ha_mode":"disabled",
            "config":{"fnr_id":"stale-provider-state"}
        });
        let error = apply_warp_connector_configuration_state_response(
            &capability,
            "account-a",
            "tunnel-a",
            &unsupported,
        )
        .expect_err("disabled state with provider config cannot be restored exactly");
        assert!(error.to_string().contains("restorable HA contract"));
    }

    #[test]
    fn warp_connector_state_rejects_rehashed_cross_tunnel_targets() {
        let capability = warp_connector_configuration_capability();
        let receipt = json!({
            "schema_version":1,
            "source_capability_id":"cloudflare-tunnel-configuration-get-warp-connector-configuration",
            "source_path":"/accounts/{account_id}/warp_connector/{tunnel_id}/configurations",
            "target_capability_id":"cloudflare-tunnel-configuration-update-warp-connector-configuration",
            "target_method":"PUT",
            "target_path":"/accounts/{account_id}/warp_connector/{tunnel_id}/configurations",
            "target_scope":"account",
            "account_id":"account-a",
            "tunnel_id":"tunnel-a",
            "prior_ha_mode":"disabled",
            "prior_config":null,
        });
        let mut plan = PlanV1::draft(
            "profile-a",
            "account-a",
            "catalog-sha",
            capability,
            json!({
                "selectors":{"account_id":"account-a","tunnel_id":"tunnel-a"},
                "account_id":"account-a",
                "adapter":{},
                "live_preconditions":{"warp_connector_configuration_state":receipt},
            }),
        )
        .expect("plan");
        plan.precondition_hashes.insert(
            "warp_connector_configuration_state".to_owned(),
            hash_value(&receipt).expect("receipt hash"),
        );
        assert_eq!(
            required_warp_connector_configuration_state_precondition(&plan)
                .expect("bound precondition"),
            plan.precondition_hashes
                .get("warp_connector_configuration_state")
                .map(String::as_str)
        );

        let mut retargeted = receipt;
        retargeted["tunnel_id"] = json!("tunnel-b");
        plan.precondition_hashes.insert(
            "warp_connector_configuration_state".to_owned(),
            hash_value(&retargeted).expect("retargeted receipt hash"),
        );
        plan.targets["live_preconditions"]["warp_connector_configuration_state"] = retargeted;
        let error = required_warp_connector_configuration_state_precondition(&plan)
            .expect_err("a rehashed cross-Tunnel receipt must still fail");
        assert!(error.to_string().contains("account, Tunnel"));
    }

    #[test]
    fn web_analytics_rum_state_receipt_binds_only_editable_on_off_state() {
        let capability = web_analytics_rum_capability();
        assert!(should_bind_web_analytics_rum_state(&capability));
        let response = CloudflareResponseV1 {
            status: 200,
            success: true,
            result: json!({
                "id":"rum",
                "editable":true,
                "value":"off",
                "modified_on":"2026-07-15T12:00:00Z",
                "future_read_only":"ignored"
            }),
            errors: Vec::new(),
            result_info: None,
            etag: None,
            cf_ray: None,
        };
        let receipt =
            apply_web_analytics_rum_state_response(&capability, "account-a", "zone-a", &response)
                .expect("Web Analytics RUM state receipt");
        assert_eq!(
            receipt,
            json!({
                "schema_version":1,
                "source_capability_id":"web-analytics-get-rum-status",
                "source_path":"/zones/{zone_id}/settings/rum",
                "target_capability_id":"web-analytics-toggle-rum",
                "target_method":"PATCH",
                "target_path":"/zones/{zone_id}/settings/rum",
                "target_scope":"zone",
                "account_id":"account-a",
                "zone_id":"zone-a",
                "setting_id":"rum",
                "editable":true,
                "prior_value":"off",
            })
        );

        for (result, expected) in [
            (
                json!({"id":"rum","editable":true,"value":"manual"}),
                "restorable",
            ),
            (
                json!({"id":"rum","editable":false,"value":"off"}),
                "editable",
            ),
            (
                json!({"id":"other","editable":true,"value":"off"}),
                "identify setting",
            ),
        ] {
            let mut invalid = response.clone();
            invalid.result = result;
            let error = apply_web_analytics_rum_state_response(
                &capability,
                "account-a",
                "zone-a",
                &invalid,
            )
            .expect_err("unrestorable RUM state must fail closed");
            assert!(error.to_string().contains(expected), "{error}");
        }
    }

    #[test]
    fn web_analytics_rum_preflight_allows_only_exact_on_off_requests() {
        let capability = web_analytics_rum_capability();
        for value in ["on", "off"] {
            preflight_call_input(
                &capability,
                &CallInput {
                    selectors: json!({"zone_id":"zone-a"}),
                    body: Some(json!({"value":value})),
                    ..CallInput::default()
                },
                None,
            )
            .expect("exact RUM value is accepted");
        }
        for body in [
            json!({"value":"manual"}),
            json!({"value":"on","future":true}),
            json!({}),
        ] {
            let error = preflight_call_input(
                &capability,
                &CallInput {
                    selectors: json!({"zone_id":"zone-a"}),
                    body: Some(body),
                    ..CallInput::default()
                },
                None,
            )
            .expect_err("unsupported RUM request must fail closed");
            assert!(
                error.to_string().contains("request body") || error.to_string().contains("schema"),
                "{error}"
            );
        }
    }

    #[test]
    fn web_analytics_rum_state_rejects_rehashed_cross_zone_targets() {
        let capability = web_analytics_rum_capability();
        let receipt = json!({
            "schema_version":1,
            "source_capability_id":"web-analytics-get-rum-status",
            "source_path":"/zones/{zone_id}/settings/rum",
            "target_capability_id":"web-analytics-toggle-rum",
            "target_method":"PATCH",
            "target_path":"/zones/{zone_id}/settings/rum",
            "target_scope":"zone",
            "account_id":"account-a",
            "zone_id":"zone-a",
            "setting_id":"rum",
            "editable":true,
            "prior_value":"off",
        });
        let mut plan = PlanV1::draft(
            "profile-a",
            "account-a",
            "catalog-sha",
            capability,
            json!({
                "selectors":{"zone_id":"zone-a"},
                "account_id":"account-a",
                "adapter":{},
                "live_preconditions":{"web_analytics_rum_state":receipt},
            }),
        )
        .expect("plan");
        plan.precondition_hashes.insert(
            "web_analytics_rum_state".to_owned(),
            hash_value(&receipt).expect("receipt hash"),
        );
        assert_eq!(
            required_web_analytics_rum_state_precondition(&plan).expect("bound precondition"),
            plan.precondition_hashes
                .get("web_analytics_rum_state")
                .map(String::as_str)
        );

        let mut retargeted = receipt;
        retargeted["zone_id"] = json!("zone-b");
        plan.precondition_hashes.insert(
            "web_analytics_rum_state".to_owned(),
            hash_value(&retargeted).expect("retargeted receipt hash"),
        );
        plan.targets["live_preconditions"]["web_analytics_rum_state"] = retargeted;
        let error = required_web_analytics_rum_state_precondition(&plan)
            .expect_err("a rehashed cross-zone receipt must still fail");
        assert!(error.to_string().contains("account, zone"));
    }

    #[test]
    fn global_warp_override_state_receipt_binds_only_the_exact_account_state() {
        let response = CloudflareResponseV1 {
            status: 200,
            success: true,
            result: json!({
                "disconnect": false,
                "timestamp": "2026-07-15T12:00:00Z",
                "ignored_future_field": "does-not-enter-the-receipt",
            }),
            errors: Vec::new(),
            result_info: None,
            etag: None,
            cf_ray: None,
        };

        let receipt = apply_global_warp_override_state_response("account-a", &response)
            .expect("global WARP state receipt");
        assert_eq!(
            receipt,
            json!({
                "schema_version": 1,
                "source_capability_id": "devices-resilience-retrieve-global-warp-override",
                "source_path": "/accounts/{account_id}/devices/resilience/disconnect",
                "target_capability_id": "devices-resilience-set-global-warp-override",
                "target_scope": "account",
                "target_id": "account-a",
                "disconnect": false,
            })
        );

        let expected_hash = hash_value(&receipt).expect("receipt hash");
        validate_global_warp_override_state_receipt_precondition(&expected_hash, &receipt)
            .expect("unchanged state");
        let mut drifted = receipt;
        drifted["disconnect"] = json!(true);
        let error =
            validate_global_warp_override_state_receipt_precondition(&expected_hash, &drifted)
                .expect_err("changed state must fail before the write boundary");
        assert!(error.to_string().contains("drifted after planning"));
        assert!(
            error
                .to_string()
                .contains("mutation boundary was not crossed")
        );
    }

    #[test]
    fn global_warp_override_state_receipt_rejects_failed_or_ambiguous_reads() {
        let response = |status, success, result| CloudflareResponseV1 {
            status,
            success,
            result,
            errors: Vec::new(),
            result_info: None,
            etag: None,
            cf_ray: None,
        };
        let failed = apply_global_warp_override_state_response(
            "account-a",
            &response(403, false, json!({"disconnect": false})),
        )
        .expect_err("failed read");
        assert!(failed.to_string().contains("HTTP 403"));
        let omitted = apply_global_warp_override_state_response(
            "account-a",
            &response(200, true, json!({"timestamp": "now"})),
        )
        .expect_err("missing state");
        assert!(omitted.to_string().contains("omitted boolean `disconnect`"));
    }

    #[test]
    fn executable_global_warp_override_plan_requires_its_bound_prior_state() {
        let capability = global_warp_override_capability();
        assert!(should_bind_global_warp_override_state(&capability));
        let mut plan = PlanV1::draft(
            "profile-a",
            "account-a",
            "catalog-sha",
            capability,
            json!({
                "selectors": {"account_id": "account-a"},
                "account_id": "account-a",
                "adapter": {},
            }),
        )
        .expect("plan");

        let missing = required_global_warp_override_state_precondition(&plan)
            .expect_err("old plan without a prior-state receipt must fail");
        assert!(missing.to_string().contains("predates"));

        let receipt = json!({
            "schema_version": 1,
            "source_capability_id": "devices-resilience-retrieve-global-warp-override",
            "source_path": "/accounts/{account_id}/devices/resilience/disconnect",
            "target_capability_id": "devices-resilience-set-global-warp-override",
            "target_scope": "account",
            "target_id": "account-a",
            "disconnect": false,
        });
        let receipt_hash = hash_value(&receipt).expect("receipt hash");
        plan.targets["live_preconditions"]["global_warp_override_state"] = receipt;
        plan.precondition_hashes.insert(
            "global_warp_override_state".to_owned(),
            receipt_hash.clone(),
        );
        assert_eq!(
            required_global_warp_override_state_precondition(&plan).expect("bound precondition"),
            Some(receipt_hash.as_str())
        );

        let mut retargeted =
            plan.targets["live_preconditions"]["global_warp_override_state"].clone();
        retargeted["target_id"] = json!("account-b");
        plan.precondition_hashes.insert(
            "global_warp_override_state".to_owned(),
            hash_value(&retargeted).expect("retargeted receipt hash"),
        );
        plan.targets["live_preconditions"]["global_warp_override_state"] = retargeted;
        let error = required_global_warp_override_state_precondition(&plan)
            .expect_err("a rehashed cross-account receipt must still fail");
        assert!(error.to_string().contains("invalid account"));
    }

    #[test]
    fn prepared_global_warp_override_plan_carries_exact_before_and_after_state() {
        let root = tempfile::tempdir().expect("runtime root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
        let capability = global_warp_override_capability();
        assert!(capability.mutation_contract_gaps().is_empty());
        let mut catalog = CatalogSnapshot {
            schema_version: 1,
            generated_at: Utc::now(),
            source_url: "https://example.invalid/openapi.json".to_owned(),
            source_hash: "source-sha".to_owned(),
            schema_hash: String::new(),
            capabilities: BTreeMap::from([(capability.id.clone(), capability.clone())]),
        };
        catalog.refresh_hash().expect("catalog hash");
        let profile = ProfileMetadata::new("profile-a", ProfileKind::ApiToken, Some("account-a"));
        let input = CallInput {
            selectors: json!({"account_id": "account-a"}),
            body: Some(json!({
                "disconnect": true,
                "justification": "controlled test plan",
            })),
            ..CallInput::default()
        };
        let receipt = json!({
            "schema_version": 1,
            "source_capability_id": "devices-resilience-retrieve-global-warp-override",
            "source_path": "/accounts/{account_id}/devices/resilience/disconnect",
            "target_capability_id": "devices-resilience-set-global-warp-override",
            "target_scope": "account",
            "target_id": "account-a",
            "disconnect": false,
        });
        let receipt_hash = hash_value(&receipt).expect("receipt hash");
        let receipt_evidence = store
            .write_evidence(EvidenceClass::LiveRead, &receipt)
            .expect("live read evidence");

        let envelope = persist_prepared_plan(
            &store,
            &catalog,
            capability,
            input,
            PlanAuthority {
                profile: &profile,
                account_id: "account-a",
            },
            json!({}),
            LivePlanPreconditions {
                entitlement: None,
                zone_account: None,
                global_warp_override_state: Some((receipt.clone(), receipt_evidence)),
                d1_read_replication_state: None,
                d1_empty_database_state: None,
                cloudflare_tunnel_configuration_state: None,
                warp_connector_configuration_state: None,
                web_analytics_rum_state: None,
                dns_record_state: None,
                oauth_client_secret_state: None,
            },
        )
        .expect("prepared plan");
        let plan = &envelope.result["plan"];

        assert_eq!(
            plan["precondition_hashes"]["global_warp_override_state"],
            receipt_hash
        );
        assert_eq!(
            plan["targets"]["live_preconditions"]["global_warp_override_state"],
            receipt
        );
        assert_eq!(
            plan["cloudflare_diffs"][0]["observed_before"],
            json!({"disconnect": false})
        );
        assert_eq!(
            plan["cloudflare_diffs"][0]["planned_after"],
            json!({"disconnect": true})
        );
        assert_eq!(
            plan["cloudflare_diffs"][0]["request_body"]["justification"],
            "controlled test plan"
        );
    }

    #[test]
    fn prepared_d1_plan_carries_exact_before_and_after_replication_mode() {
        let root = tempfile::tempdir().expect("runtime root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
        let capability = d1_read_replication_update_capability();
        assert!(capability.mutation_contract_gaps().is_empty());
        let mut catalog = CatalogSnapshot {
            schema_version: 1,
            generated_at: Utc::now(),
            source_url: "https://example.invalid/openapi.json".to_owned(),
            source_hash: "source-sha".to_owned(),
            schema_hash: String::new(),
            capabilities: BTreeMap::from([(capability.id.clone(), capability.clone())]),
        };
        catalog.refresh_hash().expect("catalog hash");
        let profile = ProfileMetadata::new("profile-a", ProfileKind::ApiToken, Some("account-a"));
        let input = CallInput {
            selectors: json!({"account_id":"account-a","database_id":"database-a"}),
            body: Some(json!({"read_replication":{"mode":"auto"}})),
            ..CallInput::default()
        };
        let receipt = json!({
            "schema_version": 1,
            "source_capability_id": "d1-get-database",
            "source_path": "/accounts/{account_id}/d1/database/{database_id}",
            "target_capability_id": "d1-update-partial-database",
            "target_method": "PATCH",
            "target_scope": "account",
            "account_id": "account-a",
            "database_id": "database-a",
            "read_replication": {"mode":"disabled"},
        });
        let receipt_hash = hash_value(&receipt).expect("receipt hash");
        let receipt_evidence = store
            .write_evidence(EvidenceClass::LiveRead, &receipt)
            .expect("live read evidence");

        let envelope = persist_prepared_plan(
            &store,
            &catalog,
            capability,
            input,
            PlanAuthority {
                profile: &profile,
                account_id: "account-a",
            },
            json!({}),
            LivePlanPreconditions {
                entitlement: None,
                zone_account: None,
                global_warp_override_state: None,
                d1_read_replication_state: Some((receipt.clone(), receipt_evidence)),
                d1_empty_database_state: None,
                cloudflare_tunnel_configuration_state: None,
                warp_connector_configuration_state: None,
                web_analytics_rum_state: None,
                dns_record_state: None,
                oauth_client_secret_state: None,
            },
        )
        .expect("prepared plan");
        let plan = &envelope.result["plan"];

        assert_eq!(
            plan["precondition_hashes"]["d1_read_replication_state"],
            receipt_hash
        );
        assert_eq!(
            plan["targets"]["live_preconditions"]["d1_read_replication_state"],
            receipt
        );
        assert_eq!(
            plan["cloudflare_diffs"][0]["observed_before"],
            json!({"read_replication":{"mode":"disabled"}})
        );
        assert_eq!(
            plan["cloudflare_diffs"][0]["planned_after"],
            json!({"read_replication":{"mode":"auto"}})
        );
    }

    #[test]
    fn prepared_cloudflare_tunnel_configuration_plan_carries_exact_before_and_after_routing() {
        let root = tempfile::tempdir().expect("runtime root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
        let capability = cloudflare_tunnel_configuration_capability();
        assert!(capability.mutation_contract_gaps().is_empty());
        let mut catalog = CatalogSnapshot {
            schema_version: 1,
            generated_at: Utc::now(),
            source_url: "https://example.invalid/openapi.json".to_owned(),
            source_hash: "source-sha".to_owned(),
            schema_hash: String::new(),
            capabilities: BTreeMap::from([(capability.id.clone(), capability.clone())]),
        };
        catalog.refresh_hash().expect("catalog hash");
        let profile = ProfileMetadata::new("profile-a", ProfileKind::ApiToken, Some("account-a"));
        let prior_config = json!({
            "ingress":[{"hostname":"","service":"http_status:404"}]
        });
        let planned_config = json!({
            "ingress":[
                {"hostname":"app.example.com","service":"http://localhost:8080"},
                {"hostname":"","service":"http_status:404"}
            ]
        });
        let receipt = json!({
            "schema_version": 1,
            "source_capability_id": "cloudflare-tunnel-configuration-get-configuration",
            "source_path": "/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations",
            "target_capability_id": "cloudflare-tunnel-configuration-put-configuration",
            "target_method": "PUT",
            "target_path": "/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations",
            "target_scope": "account",
            "account_id": "account-a",
            "tunnel_id": "tunnel-a",
            "prior_config": prior_config,
        });
        let receipt_hash = hash_value(&receipt).expect("receipt hash");
        let receipt_evidence = store
            .write_evidence(EvidenceClass::LiveRead, &receipt)
            .expect("live read evidence");

        let envelope = persist_prepared_plan(
            &store,
            &catalog,
            capability,
            CallInput {
                selectors: json!({"account_id":"account-a","tunnel_id":"tunnel-a"}),
                body: Some(json!({"config":planned_config})),
                ..CallInput::default()
            },
            PlanAuthority {
                profile: &profile,
                account_id: "account-a",
            },
            json!({}),
            LivePlanPreconditions {
                entitlement: None,
                zone_account: None,
                global_warp_override_state: None,
                d1_read_replication_state: None,
                d1_empty_database_state: None,
                cloudflare_tunnel_configuration_state: Some((receipt.clone(), receipt_evidence)),
                warp_connector_configuration_state: None,
                web_analytics_rum_state: None,
                dns_record_state: None,
                oauth_client_secret_state: None,
            },
        )
        .expect("prepared plan");
        let plan = &envelope.result["plan"];

        assert_eq!(
            plan["precondition_hashes"]["cloudflare_tunnel_configuration_state"],
            receipt_hash
        );
        assert_eq!(
            plan["targets"]["live_preconditions"]["cloudflare_tunnel_configuration_state"],
            receipt
        );
        assert_eq!(
            plan["cloudflare_diffs"][0]["observed_before"],
            json!({"config":prior_config})
        );
        assert_eq!(
            plan["cloudflare_diffs"][0]["planned_after"],
            json!({"config":planned_config})
        );
    }

    #[test]
    fn prepared_warp_connector_plan_carries_exact_before_and_after_ha_state() {
        let root = tempfile::tempdir().expect("runtime root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
        let capability = warp_connector_configuration_capability();
        assert!(capability.mutation_contract_gaps().is_empty());
        let mut catalog = CatalogSnapshot {
            schema_version: 1,
            generated_at: Utc::now(),
            source_url: "https://example.invalid/openapi.json".to_owned(),
            source_hash: "source-sha".to_owned(),
            schema_hash: String::new(),
            capabilities: BTreeMap::from([(capability.id.clone(), capability.clone())]),
        };
        catalog.refresh_hash().expect("catalog hash");
        let profile = ProfileMetadata::new("profile-a", ProfileKind::ApiToken, Some("account-a"));
        let receipt = json!({
            "schema_version":1,
            "source_capability_id":"cloudflare-tunnel-configuration-get-warp-connector-configuration",
            "source_path":"/accounts/{account_id}/warp_connector/{tunnel_id}/configurations",
            "target_capability_id":"cloudflare-tunnel-configuration-update-warp-connector-configuration",
            "target_method":"PUT",
            "target_path":"/accounts/{account_id}/warp_connector/{tunnel_id}/configurations",
            "target_scope":"account",
            "account_id":"account-a",
            "tunnel_id":"tunnel-a",
            "prior_ha_mode":"disabled",
            "prior_config":null,
        });
        let receipt_hash = hash_value(&receipt).expect("receipt hash");
        let evidence = store
            .write_evidence(EvidenceClass::LiveRead, &receipt)
            .expect("live read evidence");
        let planned = json!({
            "ha_mode":"local",
            "config":{"vips":[{"address":"192.0.2.10"}]}
        });

        let envelope = persist_prepared_plan(
            &store,
            &catalog,
            capability,
            CallInput {
                selectors: json!({"account_id":"account-a","tunnel_id":"tunnel-a"}),
                body: Some(planned.clone()),
                ..CallInput::default()
            },
            PlanAuthority {
                profile: &profile,
                account_id: "account-a",
            },
            json!({}),
            LivePlanPreconditions {
                entitlement: None,
                zone_account: None,
                global_warp_override_state: None,
                d1_read_replication_state: None,
                cloudflare_tunnel_configuration_state: None,
                d1_empty_database_state: None,
                warp_connector_configuration_state: Some((receipt.clone(), evidence)),
                web_analytics_rum_state: None,
                dns_record_state: None,
                oauth_client_secret_state: None,
            },
        )
        .expect("prepared plan");
        let plan = &envelope.result["plan"];

        assert_eq!(
            plan["precondition_hashes"]["warp_connector_configuration_state"],
            receipt_hash
        );
        assert_eq!(
            plan["targets"]["live_preconditions"]["warp_connector_configuration_state"],
            receipt
        );
        assert_eq!(
            plan["cloudflare_diffs"][0]["observed_before"],
            json!({"ha_mode":"disabled","config":null})
        );
        assert_eq!(plan["cloudflare_diffs"][0]["planned_after"], planned);
    }

    #[test]
    fn prepared_web_analytics_rum_plan_carries_exact_before_and_after_state() {
        let root = tempfile::tempdir().expect("runtime root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
        let capability = web_analytics_rum_capability();
        assert!(capability.mutation_contract_gaps().is_empty());
        let mut catalog = CatalogSnapshot {
            schema_version: 1,
            generated_at: Utc::now(),
            source_url: "https://example.invalid/openapi.json".to_owned(),
            source_hash: "source-sha".to_owned(),
            schema_hash: String::new(),
            capabilities: BTreeMap::from([(capability.id.clone(), capability.clone())]),
        };
        catalog.refresh_hash().expect("catalog hash");
        let profile = ProfileMetadata::new("profile-a", ProfileKind::ApiToken, Some("account-a"));
        let receipt = json!({
            "schema_version":1,
            "source_capability_id":"web-analytics-get-rum-status",
            "source_path":"/zones/{zone_id}/settings/rum",
            "target_capability_id":"web-analytics-toggle-rum",
            "target_method":"PATCH",
            "target_path":"/zones/{zone_id}/settings/rum",
            "target_scope":"zone",
            "account_id":"account-a",
            "zone_id":"zone-a",
            "setting_id":"rum",
            "editable":true,
            "prior_value":"off",
        });
        let receipt_hash = hash_value(&receipt).expect("receipt hash");
        let evidence = store
            .write_evidence(EvidenceClass::LiveRead, &receipt)
            .expect("live read evidence");

        let envelope = persist_prepared_plan(
            &store,
            &catalog,
            capability,
            CallInput {
                selectors: json!({"zone_id":"zone-a"}),
                body: Some(json!({"value":"on"})),
                ..CallInput::default()
            },
            PlanAuthority {
                profile: &profile,
                account_id: "account-a",
            },
            json!({}),
            LivePlanPreconditions {
                entitlement: None,
                zone_account: None,
                global_warp_override_state: None,
                d1_read_replication_state: None,
                cloudflare_tunnel_configuration_state: None,
                warp_connector_configuration_state: None,
                d1_empty_database_state: None,
                web_analytics_rum_state: Some((receipt.clone(), evidence)),
                dns_record_state: None,
                oauth_client_secret_state: None,
            },
        )
        .expect("prepared plan");
        let plan = &envelope.result["plan"];

        assert_eq!(
            plan["precondition_hashes"]["web_analytics_rum_state"],
            receipt_hash
        );
        assert_eq!(
            plan["targets"]["live_preconditions"]["web_analytics_rum_state"],
            receipt
        );
        assert_eq!(
            plan["cloudflare_diffs"][0]["observed_before"],
            json!({"value":"off"})
        );
        assert_eq!(
            plan["cloudflare_diffs"][0]["planned_after"],
            json!({"value":"on"})
        );
    }

    #[test]
    fn prepared_dns_record_plan_carries_exact_before_and_after_record_state() {
        let root = tempfile::tempdir().expect("runtime root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
        let capability = dns_record_update_capability("PATCH");
        assert!(capability.mutation_contract_gaps().is_empty());
        let mut catalog = CatalogSnapshot {
            schema_version: 1,
            generated_at: Utc::now(),
            source_url: "https://example.invalid/openapi.json".to_owned(),
            source_hash: "source-sha".to_owned(),
            schema_hash: String::new(),
            capabilities: BTreeMap::from([(capability.id.clone(), capability.clone())]),
        };
        catalog.refresh_hash().expect("catalog hash");
        let profile = ProfileMetadata::new("profile-a", ProfileKind::ApiToken, Some("account-a"));
        let input = CallInput {
            selectors: json!({"zone_id":"zone-a","dns_record_id":"record-a"}),
            body: Some(json!({
                "type":"TXT",
                "name":"txt.example.com",
                "content":"new-value",
                "ttl":300,
                "proxied":false,
                "tags":[],
            })),
            ..CallInput::default()
        };
        let receipt = json!({
            "schema_version":1,
            "source_capability_id":"dns-records-for-a-zone-dns-record-details",
            "source_path":"/zones/{zone_id}/dns_records/{dns_record_id}",
            "target_capability_id":"dns-records-for-a-zone-patch-dns-record",
            "target_method":"PATCH",
            "target_scope":"zone",
            "account_id":"account-a",
            "zone_id":"zone-a",
            "dns_record_id":"record-a",
            "prior_record":{
                "type":"TXT",
                "name":"txt.example.com",
                "content":"prior-value",
                "ttl":300,
                "proxied":false,
                "tags":[],
            },
        });
        let receipt_hash = hash_value(&receipt).expect("receipt hash");
        let receipt_evidence = store
            .write_evidence(EvidenceClass::LiveRead, &receipt)
            .expect("live read evidence");

        let envelope = persist_prepared_plan(
            &store,
            &catalog,
            capability,
            input,
            PlanAuthority {
                profile: &profile,
                account_id: "account-a",
            },
            json!({}),
            LivePlanPreconditions {
                entitlement: None,
                zone_account: None,
                global_warp_override_state: None,
                d1_read_replication_state: None,
                cloudflare_tunnel_configuration_state: None,
                warp_connector_configuration_state: None,
                web_analytics_rum_state: None,
                d1_empty_database_state: None,
                dns_record_state: Some((receipt.clone(), receipt_evidence)),
                oauth_client_secret_state: None,
            },
        )
        .expect("prepared plan");
        let plan = &envelope.result["plan"];

        assert_eq!(
            plan["precondition_hashes"][DNS_RECORD_STATE_PRECONDITION],
            receipt_hash
        );
        assert_eq!(
            plan["targets"]["live_preconditions"][DNS_RECORD_STATE_PRECONDITION],
            receipt
        );
        assert_eq!(
            plan["cloudflare_diffs"][0]["observed_before"]["content"],
            "prior-value"
        );
        assert_eq!(
            plan["cloudflare_diffs"][0]["planned_after"]["content"],
            "new-value"
        );
    }

    #[test]
    fn global_warp_rectification_derives_a_separate_exact_restore_request() {
        let capability = global_warp_override_capability();
        let receipt = json!({
            "schema_version": 1,
            "source_capability_id": "devices-resilience-retrieve-global-warp-override",
            "source_path": "/accounts/{account_id}/devices/resilience/disconnect",
            "target_capability_id": "devices-resilience-set-global-warp-override",
            "target_scope": "account",
            "target_id": "account-a",
            "disconnect": false,
        });
        let mut plan = PlanV1::draft(
            "profile-a",
            "account-a",
            "catalog-sha",
            capability.clone(),
            json!({
                "selectors":{"account_id":"account-a"},
                "account_id":"account-a",
                "adapter":{},
                "live_preconditions":{"global_warp_override_state":receipt},
            }),
        )
        .expect("plan");
        plan.input = serde_json::to_value(CallInput {
            selectors: json!({"account_id":"account-a"}),
            query: json!({}),
            body: Some(json!({
                "disconnect": true,
                "justification": "controlled source plan",
            })),
            ..CallInput::default()
        })
        .expect("call input");
        plan.precondition_hashes.insert(
            "global_warp_override_state".to_owned(),
            hash_value(&receipt).expect("receipt hash"),
        );
        plan.refresh_hash().expect("bind source plan");
        plan.approve(true, None).expect("approve");
        plan.mark_consumed().expect("consume");
        plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
            .expect("attempt");
        plan.record_transaction_stage_with_artifact(
            TransactionStageV1::BoundaryResponsePersisted,
            json!({"success":true,"http_status":200}),
        )
        .expect("response receipt");
        plan.status = PlanStatus::RectificationRequired;

        let request = compensation_request(&plan)
            .expect("request resolves")
            .expect("compensation is supported");

        assert_eq!(request.capability_id, capability.id);
        assert_eq!(request.expected_method, "POST");
        assert_eq!(request.expected_path, capability.path);
        assert_eq!(request.input.selectors, json!({"account_id":"account-a"}));
        assert_eq!(request.input.query, json!({}));
        assert_eq!(request.input.body, Some(json!({"disconnect":false})));
        assert!(request.input.if_match.is_none());
        assert!(request.input.if_none_match.is_none());
        assert_eq!(request.requested_account.as_deref(), Some("account-a"));
    }

    #[test]
    fn d1_rectification_derives_a_separate_exact_mode_restore_request() {
        let capability = d1_read_replication_update_capability();
        let receipt = json!({
            "schema_version": 1,
            "source_capability_id": "d1-get-database",
            "source_path": "/accounts/{account_id}/d1/database/{database_id}",
            "target_capability_id": "d1-update-partial-database",
            "target_method": "PATCH",
            "target_scope": "account",
            "account_id": "account-a",
            "database_id": "database-a",
            "read_replication": {"mode":"disabled"},
        });
        let mut plan = PlanV1::draft(
            "profile-a",
            "account-a",
            "catalog-sha",
            capability.clone(),
            json!({
                "selectors":{"account_id":"account-a","database_id":"database-a"},
                "account_id":"account-a",
                "adapter":{},
                "live_preconditions":{"d1_read_replication_state":receipt},
            }),
        )
        .expect("plan");
        plan.input = serde_json::to_value(CallInput {
            selectors: json!({"account_id":"account-a","database_id":"database-a"}),
            query: json!({}),
            body: Some(json!({"read_replication":{"mode":"auto"}})),
            ..CallInput::default()
        })
        .expect("call input");
        plan.precondition_hashes.insert(
            "d1_read_replication_state".to_owned(),
            hash_value(&receipt).expect("receipt hash"),
        );
        plan.refresh_hash().expect("bind source plan");
        plan.approve(true, None).expect("approve");
        plan.mark_consumed().expect("consume");
        plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
            .expect("attempt");
        plan.record_transaction_stage_with_artifact(
            TransactionStageV1::BoundaryResponsePersisted,
            json!({"success":true,"http_status":200}),
        )
        .expect("response receipt");
        plan.status = PlanStatus::RectificationRequired;

        let request = compensation_request(&plan)
            .expect("request resolves")
            .expect("compensation is supported");

        assert_eq!(request.capability_id, capability.id);
        assert_eq!(request.expected_method, "PATCH");
        assert_eq!(request.expected_path, capability.path);
        assert_eq!(
            request.input.selectors,
            json!({"account_id":"account-a","database_id":"database-a"})
        );
        assert_eq!(request.input.query, json!({}));
        assert_eq!(
            request.input.body,
            Some(json!({"read_replication":{"mode":"disabled"}}))
        );
        assert_eq!(request.requested_account.as_deref(), Some("account-a"));
    }

    #[test]
    fn cloudflare_tunnel_configuration_rectification_derives_an_exact_restore_put() {
        let capability = cloudflare_tunnel_configuration_capability();
        let prior_config = json!({
            "ingress": [
                {"hostname":"app.example.com","service":"http://localhost:8080"},
                {"hostname":"","service":"http_status:404"}
            ]
        });
        let receipt = json!({
            "schema_version": 1,
            "source_capability_id": "cloudflare-tunnel-configuration-get-configuration",
            "source_path": "/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations",
            "target_capability_id": "cloudflare-tunnel-configuration-put-configuration",
            "target_method": "PUT",
            "target_path": "/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations",
            "target_scope": "account",
            "account_id": "account-a",
            "tunnel_id": "tunnel-a",
            "prior_config": prior_config,
        });
        let mut plan = PlanV1::draft(
            "profile-a",
            "account-a",
            "catalog-sha",
            capability.clone(),
            json!({
                "selectors":{"account_id":"account-a","tunnel_id":"tunnel-a"},
                "account_id":"account-a",
                "adapter":{},
                "live_preconditions":{"cloudflare_tunnel_configuration_state":receipt},
            }),
        )
        .expect("plan");
        plan.input = serde_json::to_value(CallInput {
            selectors: json!({"account_id":"account-a","tunnel_id":"tunnel-a"}),
            body: Some(json!({
                "config":{"ingress":[{"hostname":"","service":"http_status:503"}]}
            })),
            ..CallInput::default()
        })
        .expect("call input");
        plan.precondition_hashes.insert(
            "cloudflare_tunnel_configuration_state".to_owned(),
            hash_value(&receipt).expect("receipt hash"),
        );
        plan.refresh_hash().expect("bind source plan");
        plan.approve(true, None).expect("approve");
        plan.mark_consumed().expect("consume");
        plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
            .expect("attempt");
        plan.record_transaction_stage_with_artifact(
            TransactionStageV1::BoundaryResponsePersisted,
            json!({"success":true,"http_status":200}),
        )
        .expect("response receipt");
        plan.status = PlanStatus::RectificationRequired;

        let request = compensation_request(&plan)
            .expect("request resolves")
            .expect("compensation is supported");

        assert_eq!(request.capability_id, capability.id);
        assert_eq!(request.expected_method, "PUT");
        assert_eq!(request.expected_path, capability.path);
        assert_eq!(
            request.input.selectors,
            json!({"account_id":"account-a","tunnel_id":"tunnel-a"})
        );
        assert_eq!(request.input.query, json!({}));
        assert_eq!(request.input.body, Some(json!({"config":prior_config})));
        assert_eq!(request.requested_account.as_deref(), Some("account-a"));
    }

    #[test]
    fn warp_connector_rectification_derives_an_exact_restore_put() {
        let capability = warp_connector_configuration_capability();
        let receipt = json!({
            "schema_version":1,
            "source_capability_id":"cloudflare-tunnel-configuration-get-warp-connector-configuration",
            "source_path":"/accounts/{account_id}/warp_connector/{tunnel_id}/configurations",
            "target_capability_id":"cloudflare-tunnel-configuration-update-warp-connector-configuration",
            "target_method":"PUT",
            "target_path":"/accounts/{account_id}/warp_connector/{tunnel_id}/configurations",
            "target_scope":"account",
            "account_id":"account-a",
            "tunnel_id":"tunnel-a",
            "prior_ha_mode":"aws",
            "prior_config":{"fnr_id":"eni-secondary-a"},
        });
        let mut plan = PlanV1::draft(
            "profile-a",
            "account-a",
            "catalog-sha",
            capability.clone(),
            json!({
                "selectors":{"account_id":"account-a","tunnel_id":"tunnel-a"},
                "account_id":"account-a",
                "adapter":{},
                "live_preconditions":{"warp_connector_configuration_state":receipt},
            }),
        )
        .expect("plan");
        plan.input = serde_json::to_value(CallInput {
            selectors: json!({"account_id":"account-a","tunnel_id":"tunnel-a"}),
            body: Some(json!({
                "ha_mode":"local",
                "config":{"vips":[{"address":"192.0.2.10"}]}
            })),
            ..CallInput::default()
        })
        .expect("call input");
        plan.precondition_hashes.insert(
            "warp_connector_configuration_state".to_owned(),
            hash_value(&receipt).expect("receipt hash"),
        );
        plan.refresh_hash().expect("bind source plan");
        plan.approve(true, None).expect("approve");
        plan.mark_consumed().expect("consume");
        plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
            .expect("attempt");
        plan.record_transaction_stage_with_artifact(
            TransactionStageV1::BoundaryResponsePersisted,
            json!({"success":true,"http_status":200}),
        )
        .expect("response receipt");
        plan.status = PlanStatus::RectificationRequired;

        let request = compensation_request(&plan)
            .expect("request resolves")
            .expect("compensation is supported");
        assert_eq!(request.capability_id, capability.id);
        assert_eq!(request.expected_method, "PUT");
        assert_eq!(request.expected_path, capability.path);
        assert_eq!(
            request.input.selectors,
            json!({"account_id":"account-a","tunnel_id":"tunnel-a"})
        );
        assert_eq!(
            request.input.body,
            Some(json!({"ha_mode":"aws","config":{"fnr_id":"eni-secondary-a"}}))
        );
        assert_eq!(request.requested_account.as_deref(), Some("account-a"));
    }

    #[test]
    fn web_analytics_rum_rectification_derives_an_exact_restore_patch() {
        let capability = web_analytics_rum_capability();
        let receipt = json!({
            "schema_version":1,
            "source_capability_id":"web-analytics-get-rum-status",
            "source_path":"/zones/{zone_id}/settings/rum",
            "target_capability_id":"web-analytics-toggle-rum",
            "target_method":"PATCH",
            "target_path":"/zones/{zone_id}/settings/rum",
            "target_scope":"zone",
            "account_id":"account-a",
            "zone_id":"zone-a",
            "setting_id":"rum",
            "editable":true,
            "prior_value":"off",
        });
        let mut plan = PlanV1::draft(
            "profile-a",
            "account-a",
            "catalog-sha",
            capability.clone(),
            json!({
                "selectors":{"zone_id":"zone-a"},
                "account_id":"account-a",
                "adapter":{},
                "live_preconditions":{"web_analytics_rum_state":receipt},
            }),
        )
        .expect("plan");
        plan.input = serde_json::to_value(CallInput {
            selectors: json!({"zone_id":"zone-a"}),
            body: Some(json!({"value":"on"})),
            ..CallInput::default()
        })
        .expect("call input");
        plan.precondition_hashes.insert(
            "web_analytics_rum_state".to_owned(),
            hash_value(&receipt).expect("receipt hash"),
        );
        plan.refresh_hash().expect("bind source plan");
        plan.approve(true, None).expect("approve");
        plan.mark_consumed().expect("consume");
        plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
            .expect("attempt");
        plan.record_transaction_stage_with_artifact(
            TransactionStageV1::BoundaryResponsePersisted,
            json!({"success":true,"http_status":200}),
        )
        .expect("response receipt");
        plan.status = PlanStatus::RectificationRequired;

        let request = compensation_request(&plan)
            .expect("request resolves")
            .expect("compensation is supported");
        assert_eq!(request.capability_id, capability.id);
        assert_eq!(request.expected_method, "PATCH");
        assert_eq!(request.expected_path, capability.path);
        assert_eq!(request.input.selectors, json!({"zone_id":"zone-a"}));
        assert_eq!(request.input.query, json!({}));
        assert_eq!(request.input.body, Some(json!({"value":"off"})));
        assert_eq!(request.requested_account.as_deref(), Some("account-a"));
    }

    #[test]
    fn dns_rectification_derives_a_separate_exact_put_restore_request() {
        let capability = dns_record_update_capability("PATCH");
        let receipt = json!({
            "schema_version":1,
            "source_capability_id":"dns-records-for-a-zone-dns-record-details",
            "source_path":"/zones/{zone_id}/dns_records/{dns_record_id}",
            "target_capability_id":"dns-records-for-a-zone-patch-dns-record",
            "target_method":"PATCH",
            "target_scope":"zone",
            "account_id":"account-a",
            "zone_id":"zone-a",
            "dns_record_id":"record-a",
            "prior_record":{
                "type":"TXT",
                "name":"txt.example.com",
                "content":"prior-value",
                "ttl":300,
                "proxied":false,
                "tags":[],
            },
        });
        let mut plan = PlanV1::draft(
            "profile-a",
            "account-a",
            "catalog-sha",
            capability,
            json!({
                "selectors":{"zone_id":"zone-a","dns_record_id":"record-a"},
                "account_id":"account-a",
                "adapter":{},
                "live_preconditions":{"dns_record_state":receipt},
            }),
        )
        .expect("plan");
        plan.input = serde_json::to_value(CallInput {
            selectors: json!({"zone_id":"zone-a","dns_record_id":"record-a"}),
            query: json!({}),
            body: Some(json!({"content":"new-value"})),
            ..CallInput::default()
        })
        .expect("call input");
        plan.precondition_hashes.insert(
            "dns_record_state".to_owned(),
            hash_value(&receipt).expect("receipt hash"),
        );
        plan.refresh_hash().expect("bind source plan");
        plan.approve(true, None).expect("approve");
        plan.mark_consumed().expect("consume");
        plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
            .expect("attempt");
        plan.record_transaction_stage_with_artifact(
            TransactionStageV1::BoundaryResponsePersisted,
            json!({"success":true,"http_status":200}),
        )
        .expect("response receipt");
        plan.status = PlanStatus::RectificationRequired;

        let request = compensation_request(&plan)
            .expect("request resolves")
            .expect("DNS compensation is supported");
        assert_eq!(
            request.capability_id,
            "dns-records-for-a-zone-update-dns-record"
        );
        assert_eq!(request.expected_method, "PUT");
        assert_eq!(
            request.expected_path,
            "/zones/{zone_id}/dns_records/{dns_record_id}"
        );
        assert_eq!(
            request.input.selectors,
            json!({"zone_id":"zone-a","dns_record_id":"record-a"})
        );
        assert_eq!(request.input.query, json!({}));
        assert_eq!(request.input.body, Some(receipt["prior_record"].clone()));
        assert_eq!(request.requested_account.as_deref(), Some("account-a"));
    }

    #[test]
    fn global_warp_override_guide_requires_the_exact_live_state_read() {
        let capability = global_warp_override_capability();
        let guide = guide_json(&capability);
        let current_state = &guide["stages"][4];
        assert_eq!(current_state["name"], "inspect_current_state");
        assert_eq!(current_state["contract_state"], "live_read_required");
        assert_eq!(current_state["evidence_class"], "live_read");
        assert_eq!(
            current_state["commands"][0],
            json!([
                "cfctl",
                "call",
                "devices-resilience-retrieve-global-warp-override",
                "--selector",
                "account_id=<account_id>",
                "--json"
            ])
        );
        let rectify = &guide["stages"][13];
        assert_eq!(rectify["name"], "rectify");
        assert_eq!(rectify["contract_state"], "available");
        assert_eq!(
            rectify["commands"][0],
            json!(["cfctl", "plans", "rectify", "<operation-id>", "--json"])
        );
    }

    #[test]
    fn d1_guide_requires_the_exact_live_database_state_read() {
        let capability = d1_read_replication_update_capability();
        let guide = guide_json(&capability);
        let current_state = &guide["stages"][4];
        assert_eq!(current_state["name"], "inspect_current_state");
        assert_eq!(current_state["contract_state"], "live_read_required");
        assert_eq!(current_state["evidence_class"], "live_read");
        assert_eq!(
            current_state["commands"][0],
            json!([
                "cfctl",
                "call",
                "d1-get-database",
                "--selector",
                "account_id=<account_id>",
                "--selector",
                "database_id=<database_id>",
                "--json"
            ])
        );
        assert_eq!(guide["stages"][13]["contract_state"], "available");
    }

    #[test]
    fn cloudflare_tunnel_configuration_guide_requires_the_exact_live_routing_read() {
        let capability = cloudflare_tunnel_configuration_capability();
        let guide = guide_json(&capability);
        let current_state = &guide["stages"][4];
        assert_eq!(current_state["name"], "inspect_current_state");
        assert_eq!(current_state["contract_state"], "live_read_required");
        assert_eq!(current_state["evidence_class"], "live_read");
        assert_eq!(
            current_state["commands"][0],
            json!([
                "cfctl",
                "call",
                "cloudflare-tunnel-configuration-get-configuration",
                "--selector",
                "account_id=<account_id>",
                "--selector",
                "tunnel_id=<tunnel_id>",
                "--json"
            ])
        );
        assert_eq!(guide["stages"][13]["contract_state"], "available");
    }

    #[test]
    fn warp_connector_configuration_guide_requires_the_exact_live_ha_read() {
        let capability = warp_connector_configuration_capability();
        let guide = guide_json(&capability);
        let current_state = &guide["stages"][4];
        assert_eq!(current_state["name"], "inspect_current_state");
        assert_eq!(current_state["contract_state"], "live_read_required");
        assert_eq!(current_state["evidence_class"], "live_read");
        assert_eq!(
            current_state["commands"][0],
            json!([
                "cfctl",
                "call",
                "cloudflare-tunnel-configuration-get-warp-connector-configuration",
                "--selector",
                "account_id=<account_id>",
                "--selector",
                "tunnel_id=<tunnel_id>",
                "--json"
            ])
        );
        assert_eq!(guide["stages"][13]["contract_state"], "available");
    }

    #[test]
    fn web_analytics_rum_guide_requires_the_exact_live_setting_read() {
        let capability = web_analytics_rum_capability();
        let guide = guide_json(&capability);
        let current_state = &guide["stages"][4];
        assert_eq!(current_state["name"], "inspect_current_state");
        assert_eq!(current_state["contract_state"], "live_read_required");
        assert_eq!(current_state["evidence_class"], "live_read");
        assert_eq!(
            current_state["commands"][0],
            json!([
                "cfctl",
                "call",
                "web-analytics-get-rum-status",
                "--selector",
                "zone_id=<zone_id>",
                "--json"
            ])
        );
        assert_eq!(guide["stages"][13]["contract_state"], "available");
    }

    #[test]
    fn dns_record_guide_requires_the_exact_live_record_state_read() {
        let capability = dns_record_update_capability("PATCH");
        let guide = guide_json(&capability);
        let current_state = &guide["stages"][4];
        assert_eq!(current_state["name"], "inspect_current_state");
        assert_eq!(current_state["contract_state"], "live_read_required");
        assert_eq!(current_state["evidence_class"], "live_read");
        assert_eq!(
            current_state["commands"][0],
            json!([
                "cfctl",
                "call",
                "dns-records-for-a-zone-dns-record-details",
                "--selector",
                "zone_id=<zone_id>",
                "--selector",
                "dns_record_id=<dns_record_id>",
                "--json"
            ])
        );
        assert_eq!(guide["stages"][13]["contract_state"], "available");
    }

    #[test]
    fn workspace_resource_keys_require_capability_context_for_ambiguous_names() {
        let dns = CapabilityV1::new(
            "dns-record-create",
            "Create DNS record",
            "POST",
            "/zones/{zone_id}/dns_records",
        );
        let generic = CapabilityV1::new(
            "widgets-create",
            "Create widget",
            "POST",
            "/accounts/{account_id}/widgets",
        );
        let input = CallInput {
            selectors: json!({"namespace_id":"shared-name"}),
            body: Some(json!({"name":"api.example.com","pattern":"*.example.com"})),
            ..CallInput::default()
        };

        assert_eq!(
            workspace_resource_keys(&dns, &input),
            vec!["hostname:api.example.com"]
        );
        assert!(workspace_resource_keys(&generic, &input).is_empty());

        let mut kv = generic;
        kv.product = "Workers KV Namespace".to_owned();
        kv.path = "/accounts/{account_id}/storage/kv/namespaces/{namespace_id}".to_owned();
        assert_eq!(
            workspace_resource_keys(&kv, &input),
            vec!["kv_namespace:shared-name"]
        );
    }

    #[test]
    fn typed_query_input_preserves_array_values_and_rejects_ambiguous_scalars() {
        let mut capability = CapabilityV1::new(
            "query-read",
            "Query read",
            "GET",
            "/accounts/{account_id}/items",
        );
        capability.selectors = vec![
            SelectorV1 {
                name: "tags".to_owned(),
                location: "query".to_owned(),
                required: false,
                value_type: "array".to_owned(),
                description: None,
                contract: None,
            },
            SelectorV1 {
                name: "cursor".to_owned(),
                location: "query".to_owned(),
                required: false,
                value_type: "string".to_owned(),
                description: None,
                contract: None,
            },
        ];
        let query = query_object_from_pairs(
            &capability,
            &[
                ("tags".to_owned(), "one".to_owned()),
                ("tags".to_owned(), "two".to_owned()),
                ("cursor".to_owned(), "next".to_owned()),
            ],
        )
        .expect("typed query");
        assert_eq!(query, json!({"tags":["one","two"], "cursor":"next"}));

        let error = query_object_from_pairs(
            &capability,
            &[
                ("cursor".to_owned(), "one".to_owned()),
                ("cursor".to_owned(), "two".to_owned()),
            ],
        )
        .expect_err("duplicate scalar query controls must fail closed")
        .to_string();
        assert!(error.contains("cursor") && error.contains("repeated"));
    }

    #[test]
    fn catalog_sync_preserves_only_a_valid_current_snapshot() {
        let root = tempfile::tempdir().expect("runtime root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
        let catalog = test_catalog();
        store
            .write_json(&store.paths().catalog_file(), &catalog)
            .expect("current catalog");

        let preserved = preserve_previous_catalog(&store).expect("preserve current catalog");
        assert_eq!(preserved["status"], "preserved");
        assert_eq!(preserved["schema_hash"], catalog.schema_hash);
        assert_eq!(
            CatalogSnapshot::load(&store.paths().catalog_previous_file())
                .expect("previous catalog"),
            catalog
        );

        let mut tampered = serde_json::to_value(&catalog).expect("catalog JSON");
        tampered["capabilities"]["accounts-list"]["title"] = json!("Tampered account listing");
        store
            .write_json(&store.paths().catalog_file(), &tampered)
            .expect("tampered current catalog");

        let discarded = preserve_previous_catalog(&store).expect("discard invalid current");
        assert_eq!(discarded["status"], "discarded_invalid");
        assert!(
            discarded["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("catalog content hash mismatch"))
        );
        assert_eq!(
            CatalogSnapshot::load(&store.paths().catalog_previous_file())
                .expect("last valid previous catalog remains"),
            catalog
        );
    }

    #[test]
    fn call_preflight_rejects_nested_contract_drift_before_planning() {
        let mut capability =
            CapabilityV1::new("d1-update", "Update database", "PATCH", "/databases/id");
        capability.request_schema = Some(json!({
            "type":"object",
            "x-cfctl-body-required":true,
            "properties":{"read_replication":{
                "type":"object",
                "required":["mode"],
                "properties":{"mode":{"type":"string","enum":["auto","disabled"]}}
            }}
        }));
        let input = CallInput {
            body: Some(json!({"read_replication":{"mode":"experimental"}})),
            ..CallInput::default()
        };

        let error = preflight_call_input(&capability, &input, None)
            .expect_err("invalid nested body must fail before planning");
        assert!(error.to_string().contains("pinned enum"));

        let secret_body = json!({"read_replication":{"mode":"auto"}});
        preflight_call_input(&capability, &CallInput::default(), Some(&secret_body))
            .expect("secret body must be validated before it is replaced by an opaque reference");
    }

    #[test]
    fn zone_entitlement_binds_the_exact_active_subscription_plan() {
        let mut capability = CapabilityV1::new(
            "custom-pages-update",
            "Update custom page",
            "PUT",
            "/zones/{zone_identifier}/custom_pages/{identifier}",
        );
        capability.account_scope = "zone".to_owned();
        capability.entitlement.requires_live_resolution = true;
        capability.entitlement.plans = BTreeMap::from([
            ("free".to_owned(), false),
            ("pro".to_owned(), true),
            ("business".to_owned(), true),
            ("enterprise".to_owned(), true),
        ]);
        let input = CallInput {
            selectors: json!({
                "zone_identifier": "zone-a",
                "identifier": "page-a",
            }),
            ..CallInput::default()
        };
        let response = CloudflareResponseV1 {
            status: 200,
            success: true,
            result: json!({
                "state": "Paid",
                "rate_plan": {"id": "partners_business"},
            }),
            errors: Vec::new(),
            result_info: None,
            etag: None,
            cf_ray: None,
        };

        assert_eq!(
            zone_target(&capability, &input).expect("zone target"),
            "zone-a"
        );
        let receipt = apply_zone_entitlement_response(&mut capability, "zone-a", &response)
            .expect("entitlement receipt");

        assert_eq!(capability.entitlement.available, Some(true));
        assert_eq!(
            capability.entitlement.observed_plan.as_deref(),
            Some("partners_business")
        );
        assert_eq!(receipt["canonical_plan"], "business");
        assert_eq!(receipt["subscription_state"], "Paid");
        assert_eq!(receipt["available"], true);
        assert_eq!(receipt["target_id"], "zone-a");
        assert!(receipt["plan_matrix_hash"].as_str().is_some());
    }

    #[test]
    fn zone_entitlement_rejects_inactive_or_unmapped_subscription_plans() {
        let mut capability = CapabilityV1::new(
            "custom-pages-update",
            "Update custom page",
            "PUT",
            "/zones/{zone_id}/custom_pages/{identifier}",
        );
        capability.account_scope = "zone".to_owned();
        capability.entitlement.requires_live_resolution = true;
        capability.entitlement.plans = BTreeMap::from([
            ("free".to_owned(), false),
            ("pro".to_owned(), true),
            ("business".to_owned(), true),
            ("enterprise".to_owned(), true),
        ]);
        let response = |state: &str, plan: &str| CloudflareResponseV1 {
            status: 200,
            success: true,
            result: json!({"state": state, "rate_plan": {"id": plan}}),
            errors: Vec::new(),
            result_info: None,
            etag: None,
            cf_ray: None,
        };

        let inactive = apply_zone_entitlement_response(
            &mut capability,
            "zone-a",
            &response("Cancelled", "business"),
        )
        .expect_err("inactive subscription");
        assert!(inactive.to_string().contains("is not active"));

        let unmapped = apply_zone_entitlement_response(
            &mut capability,
            "zone-a",
            &response("Paid", "pro_plus"),
        )
        .expect_err("unmapped plan");
        assert!(unmapped.to_string().contains("cannot be mapped"));
    }

    #[test]
    fn zone_entitlement_unblocks_only_a_complete_contract_and_rechecks_drift() {
        let mut capability = CapabilityV1::new(
            "custom-pages-delete",
            "Delete custom page",
            "DELETE",
            "/zones/{zone_id}/custom_pages/{identifier}",
        );
        capability.account_scope = "zone".to_owned();
        capability.adapter_status = AdapterStatus::Blocked;
        capability.blocked_reason = Some(
            "operation contract incomplete: account entitlement has not been resolved for this plan-gated operation"
                .to_owned(),
        );
        capability.risk = RiskClass::Destructive;
        capability.effect = EffectClass::Destructive;
        capability.cost.known = true;
        capability.cost.maximum = Some(0.0);
        capability.cost.basis =
            Some("deleting an existing resource has no incremental operation charge".to_owned());
        capability.permissions = vec!["Zone Settings Write".to_owned()];
        capability.verification.strategy =
            "same_resource_returns_not_found_after_delete".to_owned();
        capability.same_path_read = Some(SamePathReadContractV1 {
            path: "/zones/{zone_id}/custom_pages/{identifier}".to_owned(),
            read_capability_id: "custom-pages-get".to_owned(),
            verified_response_fields: Vec::new(),
        });
        capability.rollback.supported = false;
        capability.rollback.warning =
            Some("deletion is irreversible without a prior resource snapshot".to_owned());
        capability.entitlement.requires_live_resolution = true;
        capability.entitlement.plans = BTreeMap::from([
            ("free".to_owned(), false),
            ("pro".to_owned(), true),
            ("business".to_owned(), true),
            ("enterprise".to_owned(), true),
        ]);
        assert!(
            should_resolve_zone_entitlement(&capability),
            "gaps: {:?}",
            capability.mutation_contract_gaps()
        );
        let guide = guide_json(&capability);
        assert_eq!(guide["contract_state"], "blocked");
        assert_eq!(guide["next_action"]["argv"][0], "cfctl");
        assert_eq!(guide["next_action"]["argv"][1], "call");
        assert!(
            guide["next_action"]["summary"]
                .as_str()
                .is_some_and(|summary| summary.contains("live zone-subscription read"))
        );
        assert_eq!(guide["stages"][2]["contract_state"], "live_read_required");
        assert_eq!(guide["stages"][2]["evidence_class"], "live_read");
        assert_eq!(guide["stages"][3]["contract_state"], "live_read_required");
        assert_eq!(guide["stages"][3]["evidence_class"], "live_read");
        let response = CloudflareResponseV1 {
            status: 200,
            success: true,
            result: json!({
                "state": "Paid",
                "rate_plan": {"id": "pro"},
            }),
            errors: Vec::new(),
            result_info: None,
            etag: None,
            cf_ray: None,
        };

        let receipt = apply_zone_entitlement_response(&mut capability, "zone-a", &response)
            .expect("entitlement receipt");
        assert_eq!(capability.adapter_status, AdapterStatus::DynamicApi);
        assert!(capability.blocked_reason.is_none());
        let expected_hash = hash_value(&receipt).expect("receipt hash");
        validate_entitlement_receipt_precondition(&expected_hash, &capability, &receipt)
            .expect("unchanged entitlement");

        let mut drifted = receipt;
        drifted["observed_plan"] = json!("business");
        let error =
            validate_entitlement_receipt_precondition(&expected_hash, &capability, &drifted)
                .expect_err("drift must fail");
        assert!(error.to_string().contains("drifted after planning"));
    }

    #[test]
    fn zone_entitlement_precondition_cannot_be_omitted_from_an_executable_plan() {
        let mut capability = CapabilityV1::new(
            "custom-pages-delete",
            "Delete custom page",
            "DELETE",
            "/zones/{zone_id}/custom_pages/{identifier}",
        );
        capability.account_scope = "zone".to_owned();
        capability.entitlement.requires_live_resolution = true;
        capability.entitlement.available = Some(true);
        let mut plan = PlanV1::draft(
            "profile-a",
            "account-a",
            "catalog-sha",
            capability,
            json!({}),
        )
        .expect("plan");

        let error = required_entitlement_precondition(&plan)
            .expect_err("missing entitlement precondition must fail");
        assert!(error.to_string().contains("predates"));

        plan.precondition_hashes.insert(
            "entitlement".to_owned(),
            format!("sha256:{}", "a".repeat(64)),
        );
        assert_eq!(
            required_entitlement_precondition(&plan).expect("entitlement precondition"),
            plan.precondition_hashes
                .get("entitlement")
                .map(String::as_str)
        );
    }

    #[test]
    fn zone_account_receipt_binds_the_exact_target_and_selected_account() {
        let response = CloudflareResponseV1 {
            status: 200,
            success: true,
            result: json!({
                "id": "zone-a",
                "account": {"id": "account-a", "name": "Example"},
            }),
            errors: Vec::new(),
            result_info: None,
            etag: None,
            cf_ray: None,
        };

        let receipt = apply_zone_account_response("zone-a", "account-a", &response)
            .expect("zone account receipt");
        assert_eq!(receipt["target_id"], "zone-a");
        assert_eq!(receipt["expected_account_id"], "account-a");
        assert_eq!(receipt["observed_account_id"], "account-a");
        assert_eq!(receipt["account_matches"], true);
        let receipt_hash = hash_value(&receipt).expect("zone-account receipt hash");
        validate_zone_account_receipt_precondition(&receipt_hash, &receipt)
            .expect("unchanged zone-account receipt");

        let mut drifted = receipt.clone();
        drifted["observed_account_id"] = json!("account-b");
        let drift = validate_zone_account_receipt_precondition(&receipt_hash, &drifted)
            .expect_err("zone-account receipt drift must fail");
        assert!(drift.to_string().contains("ownership drifted"));

        let mismatch = apply_zone_account_response("zone-a", "account-b", &response)
            .expect_err("cross-account zone must fail");
        assert!(
            mismatch
                .to_string()
                .contains("belongs to account `account-a`")
        );

        let wrong_zone = apply_zone_account_response("zone-b", "account-a", &response)
            .expect_err("wrong zone response must fail");
        assert!(wrong_zone.to_string().contains("returned zone `zone-a`"));
    }

    #[test]
    fn every_executable_zone_mutation_requires_an_account_precondition() {
        let mut capability = CapabilityV1::new(
            "custom-pages-delete",
            "Delete custom page",
            "DELETE",
            "/zones/{zone_id}/custom_pages/{identifier}",
        );
        capability.account_scope = "zone".to_owned();
        capability.adapter_status = AdapterStatus::DynamicApi;
        assert!(should_bind_zone_account(&capability));
        let guide = guide_json(&capability);
        assert_eq!(guide["stages"][2]["contract_state"], "live_read_required");
        assert_eq!(guide["stages"][2]["evidence_class"], "live_read");

        let mut plan = PlanV1::draft(
            "profile-a",
            "account-a",
            "catalog-sha",
            capability,
            json!({}),
        )
        .expect("plan");
        let missing = required_zone_account_precondition(&plan)
            .expect_err("missing zone-account precondition must fail");
        assert!(missing.to_string().contains("zone-account ownership"));

        plan.precondition_hashes.insert(
            "zone_account".to_owned(),
            format!("sha256:{}", "b".repeat(64)),
        );
        assert_eq!(
            required_zone_account_precondition(&plan).expect("zone-account precondition"),
            plan.precondition_hashes
                .get("zone_account")
                .map(String::as_str)
        );
    }

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

        fn locate(&self, _key: &str) -> cfctl_auth::Result<Option<cfctl_auth::SecretBackend>> {
            Ok(None)
        }
    }

    #[test]
    fn selected_permission_groups_must_match_unique_live_inventory_entries() {
        let inventory = json!([
            {
                "id": "group-b",
                "name": "Workers Scripts Write",
                "scopes": ["com.cloudflare.api.account"]
            },
            {
                "id": "group-a",
                "name": "Account Settings Read",
                "scopes": ["com.cloudflare.api.account", "com.cloudflare.api.zone"]
            }
        ]);

        let selected = validate_selected_permission_groups(
            &["group-b".to_owned(), "group-a".to_owned()],
            &inventory,
        )
        .expect("selected groups resolve");

        assert_eq!(selected[0]["id"], "group-a");
        assert_eq!(selected[0]["name"], "Account Settings Read");
        assert_eq!(selected[1]["id"], "group-b");
        assert_eq!(selected[1]["scopes"], json!(["com.cloudflare.api.account"]));

        let missing =
            validate_selected_permission_groups(&["group-missing".to_owned()], &inventory)
                .expect_err("missing group is rejected");
        assert!(missing.to_string().contains("group-missing"));

        let duplicate_inventory = json!([
            {"id":"group-a","name":"First","scopes":["com.cloudflare.api.account"]},
            {"id":"group-a","name":"Second","scopes":["com.cloudflare.api.account"]}
        ]);
        let duplicate =
            validate_selected_permission_groups(&["group-a".to_owned()], &duplicate_inventory)
                .expect_err("ambiguous group is rejected");
        assert!(duplicate.to_string().contains("not unique"));
    }

    #[test]
    fn selected_permission_groups_accept_exact_names_and_reject_ambiguous_names() {
        let inventory = json!([
            {
                "id": "group-a",
                "name": "Workers Scripts Write",
                "scopes": ["com.cloudflare.api.account"]
            },
            {
                "id": "group-b",
                "name": "Account Settings Read",
                "scopes": ["com.cloudflare.api.account"]
            }
        ]);

        let selected = validate_selected_permission_groups(
            &[
                "Workers Scripts Write".to_owned(),
                "group-a".to_owned(),
                "Account Settings Read".to_owned(),
            ],
            &inventory,
        )
        .expect("exact ID and exact name selectors resolve deterministically");

        assert_eq!(selected.len(), 2, "ID/name aliases deduplicate by group ID");
        assert_eq!(selected[0]["id"], "group-a");
        assert_eq!(selected[1]["id"], "group-b");

        let ambiguous_inventory = json!([
            {
                "id": "group-a",
                "name": "Shared Name",
                "scopes": ["com.cloudflare.api.account"]
            },
            {
                "id": "group-b",
                "name": "Shared Name",
                "scopes": ["com.cloudflare.api.account"]
            }
        ]);
        let error =
            validate_selected_permission_groups(&["Shared Name".to_owned()], &ambiguous_inventory)
                .expect_err("ambiguous exact names fail closed");
        assert!(error.to_string().contains("matched 2"), "{error}");
    }

    #[test]
    fn token_creation_requires_inventory_bound_permissions_and_exact_account_scope() {
        let capability = CapabilityV1::new(
            "account-api-tokens-create-token",
            "Create account token",
            "POST",
            "/accounts/{account_id}/tokens",
        );
        let groups = json!([{
            "id": "group-a",
            "name": "Workers Scripts Write",
            "scopes": ["com.cloudflare.api.account"]
        }]);
        let groups_hash = hash_value(&groups).expect("group hash");
        let adapter = json!({
            "permission_inventory": {
                "source_capability_id": "account-api-tokens-list-permission-groups",
                "selected_groups": groups,
                "selected_groups_hash": groups_hash,
                "evidence_hashes": [format!("sha256:{}", "a".repeat(64))]
            }
        });
        let input = CallInput {
            selectors: json!({"account_id":"account-a"}),
            query: json!({}),
            body: Some(json!({
                "name":"least-privilege token",
                "policies":[{
                    "effect":"allow",
                    "permission_groups":[{"id":"group-a"}],
                    "resources":{"com.cloudflare.api.account.account-a":"*"}
                }]
            })),
            ..CallInput::default()
        };

        validate_api_token_creation_contract(&capability, &input, &adapter, "account-a")
            .expect("inventory-bound token plan is valid");

        let direct =
            validate_api_token_creation_contract(&capability, &input, &json!({}), "account-a")
                .expect_err("direct token call is rejected");
        assert!(direct.to_string().contains("cfctl keys mint"));

        let mut widened = input.clone();
        widened.body = Some(json!({
            "name":"widened token",
            "policies":[{
                "effect":"allow",
                "permission_groups":[{"id":"group-a"}],
                "resources":{"com.cloudflare.api.account.other-account":"*"}
            }]
        }));
        let widened =
            validate_api_token_creation_contract(&capability, &widened, &adapter, "account-a")
                .expect_err("cross-account scope is rejected");
        assert!(widened.to_string().contains("account-a"));
    }

    #[test]
    fn user_token_creation_requires_its_own_inventory_and_account_compatible_groups() {
        let user_capability = CapabilityV1::new(
            "user-api-tokens-create-token",
            "Create user-owned token",
            "POST",
            "/user/tokens",
        );
        let groups = json!([{
            "id": "group-a",
            "name": "Workers Scripts Write",
            "scopes": ["com.cloudflare.api.account"]
        }]);
        let groups_hash = hash_value(&groups).expect("group hash");
        let user_adapter = json!({
            "permission_inventory": {
                "source_capability_id": "permission-groups-list-permission-groups",
                "selected_groups": groups,
                "selected_groups_hash": groups_hash,
                "evidence_hashes": [format!("sha256:{}", "b".repeat(64))]
            }
        });
        let input = CallInput {
            selectors: json!({}),
            query: json!({}),
            body: Some(json!({
                "name":"least-privilege user token",
                "policies":[{
                    "effect":"allow",
                    "permission_groups":[{"id":"group-a"}],
                    "resources":{"com.cloudflare.api.account.account-a":"*"}
                }]
            })),
            ..CallInput::default()
        };
        validate_api_token_creation_contract(&user_capability, &input, &user_adapter, "account-a")
            .expect("user-owned account-scoped token uses the user inventory");

        let mut wrong_owner_inventory = user_adapter.clone();
        wrong_owner_inventory["permission_inventory"]["source_capability_id"] =
            json!("account-api-tokens-list-permission-groups");
        let wrong_owner = validate_api_token_creation_contract(
            &user_capability,
            &input,
            &wrong_owner_inventory,
            "account-a",
        )
        .expect_err("user-owned token cannot borrow an account-owned permission inventory");
        assert!(
            wrong_owner
                .to_string()
                .contains("permission-groups-list-permission-groups")
        );

        let zone_only_groups = json!([{
            "id": "group-a",
            "name": "DNS Write",
            "scopes": ["com.cloudflare.api.account.zone"]
        }]);
        let zone_only_adapter = json!({
            "permission_inventory": {
                "source_capability_id": "permission-groups-list-permission-groups",
                "selected_groups": zone_only_groups,
                "selected_groups_hash": hash_value(&zone_only_groups).expect("zone group hash"),
                "evidence_hashes": [format!("sha256:{}", "c".repeat(64))]
            }
        });
        let incompatible = validate_api_token_creation_contract(
            &user_capability,
            &input,
            &zone_only_adapter,
            "account-a",
        )
        .expect_err("zone-only permission cannot be attached to an account resource");
        assert!(incompatible.to_string().contains("account resource scope"));
    }

    #[test]
    fn token_permission_precondition_rejects_renamed_or_rescoped_groups() {
        let selected = json!([{
            "id":"group-a",
            "name":"Workers Scripts Write",
            "scopes":["com.cloudflare.api.account"]
        }]);
        let contract = json!({
            "selected_groups": selected,
            "selected_groups_hash": hash_value(&selected).expect("selected hash")
        });
        validate_current_permission_groups(
            &contract,
            &json!([{
                "id":"group-a",
                "name":"Workers Scripts Write",
                "scopes":["com.cloudflare.api.account"]
            }]),
        )
        .expect("unchanged permission group passes");

        for drifted in [
            json!([{
                "id":"group-a",
                "name":"Workers Scripts Administrator",
                "scopes":["com.cloudflare.api.account"]
            }]),
            json!([{
                "id":"group-a",
                "name":"Workers Scripts Write",
                "scopes":["com.cloudflare.api.account", "com.cloudflare.api.user"]
            }]),
        ] {
            let error = validate_current_permission_groups(&contract, &drifted)
                .expect_err("permission metadata drift is rejected");
            assert!(error.to_string().contains("drifted after planning"));
        }
    }

    #[test]
    fn standing_authority_inventory_validation_binds_complete_allowlist_metadata() {
        let approved_inventory = json!([
            {
                "id":"group-b",
                "name":"Account Settings Read",
                "scopes":["com.cloudflare.api.account"]
            },
            {
                "id":"group-a",
                "name":"Workers Scripts Write",
                "scopes":["com.cloudflare.api.zone", "com.cloudflare.api.account"],
                "category":"workers"
            }
        ]);
        let approved_groups = validate_selected_permission_groups(
            &["group-a".to_owned(), "group-b".to_owned()],
            &approved_inventory,
        )
        .expect("approved groups normalize");
        let authority = StandingAuthorityV1::draft(
            "account-a",
            vec!["account-api-tokens-create-token".to_owned()],
            vec!["group-a".to_owned(), "group-b".to_owned()],
            &hash_value(&serde_json::to_value(&approved_groups).expect("approved groups JSON"))
                .expect("approved inventory hash"),
            24,
            "cf-rotation-",
            2,
            Utc::now() + ChronoDuration::days(30),
        )
        .expect("authority draft");

        validate_standing_authority_permission_inventory(
            &authority,
            &json!([
                {
                    "id":"unrelated",
                    "name":"Unrelated Addition",
                    "scopes":["com.cloudflare.api.account"]
                },
                {
                    "id":"group-a",
                    "name":"Workers Scripts Write",
                    "scopes":["com.cloudflare.api.account", "com.cloudflare.api.zone"],
                    "category":"workers"
                },
                {
                    "id":"group-b",
                    "name":"Account Settings Read",
                    "scopes":["com.cloudflare.api.account"]
                }
            ]),
        )
        .expect("reordering and unrelated additions preserve the approved allowlist");

        for drifted in [
            json!([
                {"id":"group-a","name":"Workers Scripts Admin","scopes":["com.cloudflare.api.account","com.cloudflare.api.zone"],"category":"workers"},
                {"id":"group-b","name":"Account Settings Read","scopes":["com.cloudflare.api.account"]}
            ]),
            json!([
                {"id":"group-a","name":"Workers Scripts Write","scopes":["com.cloudflare.api.account"],"category":"workers"},
                {"id":"group-b","name":"Account Settings Read","scopes":["com.cloudflare.api.account"]}
            ]),
            json!([
                {"id":"group-a","name":"Workers Scripts Write","scopes":["com.cloudflare.api.account","com.cloudflare.api.zone"],"category":"different"},
                {"id":"group-b","name":"Account Settings Read","scopes":["com.cloudflare.api.account"]}
            ]),
            json!([
                {"id":"group-a","name":"Workers Scripts Write","scopes":["com.cloudflare.api.account","com.cloudflare.api.zone"],"category":"workers"}
            ]),
            json!([
                {"id":"group-a","name":"Workers Scripts Write","scopes":["com.cloudflare.api.account","com.cloudflare.api.zone"],"category":"workers"},
                {"id":"group-a","name":"Duplicate","scopes":["com.cloudflare.api.account"]},
                {"id":"group-b","name":"Account Settings Read","scopes":["com.cloudflare.api.account"]}
            ]),
        ] {
            let error = validate_standing_authority_permission_inventory(&authority, &drifted)
                .expect_err("approved allowlist drift fails closed");
            assert!(
                error.to_string().contains("permission") || error.to_string().contains("inventory"),
                "{error}"
            );
        }
    }

    #[test]
    fn guide_names_exact_blockers_and_never_suggests_executing_a_blocked_call() {
        let mut capability = CapabilityV1::new(
            "widgets-update",
            "Update widget",
            "PATCH",
            "/accounts/{account_id}/widgets/{widget_id}",
        );
        capability.product = "Widgets".to_owned();
        capability.adapter_status = AdapterStatus::Blocked;
        capability.blocked_reason = Some(
            "operation contract incomplete: operation-specific incremental cost is unknown"
                .to_owned(),
        );
        capability.selectors = vec![
            SelectorV1 {
                name: "account_id".to_owned(),
                location: "path".to_owned(),
                required: true,
                value_type: "string".to_owned(),
                description: None,
                contract: None,
            },
            SelectorV1 {
                name: "widget_id".to_owned(),
                location: "path".to_owned(),
                required: true,
                value_type: "string".to_owned(),
                description: None,
                contract: None,
            },
        ];
        capability.request_schema = Some(json!({
            "type":"object",
            "x-cfctl-body-required":true,
            "properties":{"enabled":{"type":"boolean"}}
        }));

        let guide = guide_json(&capability);

        assert_eq!(guide["contract_state"], "blocked");
        assert!(guide["blocking_gaps"].as_array().is_some_and(|gaps| {
            gaps.iter().any(|gap| {
                gap.as_str()
                    .is_some_and(|gap| gap.contains("incremental cost"))
            })
        }));
        assert!(guide["call_argv"].is_null());
        let stages = guide["stages"].as_array().expect("guide stages");
        assert_eq!(stages.len(), 15);
        assert_eq!(stages[3]["name"], "check_entitlement");
        assert_eq!(stages[7]["name"], "calculate_cost");
        assert_eq!(stages[7]["contract_state"], "blocked");
        assert_eq!(stages[8]["name"], "build_plan");
        assert_eq!(stages[8]["contract_state"], "blocked");
        assert_eq!(stages[8]["commands"], json!([]));
        assert_eq!(
            guide["post_resolution_call_argv"],
            json!([
                "cfctl",
                "call",
                "widgets-update",
                "--selector",
                "account_id=<account_id>",
                "--selector",
                "widget_id=<widget_id>",
                "--body-stdin",
                "--json"
            ])
        );
    }

    #[test]
    fn guide_binds_the_declared_ceiling_for_a_known_paid_operation() {
        let mut capability = CapabilityV1::new(
            "r2-create-bucket",
            "Create R2 bucket",
            "POST",
            "/accounts/{account_id}/r2/buckets",
        );
        capability.product = "R2".to_owned();
        capability.adapter_status = AdapterStatus::DynamicApi;
        capability.risk = RiskClass::ScopedWrite;
        capability.effect = EffectClass::ReversibleWrite;
        capability.permissions = vec!["Workers R2 Storage Write".to_owned()];
        capability.cost.incremental = true;
        capability.cost.currency = Some("USD".to_owned());
        capability.cost.maximum = Some(0.000_009);
        capability.cost.known = true;
        capability.entitlement.available = Some(true);
        capability.verification.strategy = "created_resource_detail_matches".to_owned();
        capability.rollback.supported = true;
        capability.rollback.strategy = Some("delete newly created empty bucket".to_owned());
        capability.request_schema = Some(json!({
            "type":"object",
            "x-cfctl-body-required":true,
            "properties":{"name":{"type":"string"}}
        }));

        assert_eq!(
            guide_stage_commands(
                cfctl_core::GuideStage::RequestApproval,
                &capability,
                cfctl_core::GuideContractStateV1::Available,
                None,
            ),
            vec![
                [
                    "cfctl",
                    "plans",
                    "approve",
                    "<operation-id>",
                    "--yes",
                    "--max-cost",
                    "USD:0.000009",
                    "--json"
                ]
                .map(str::to_owned)
                .to_vec()
            ]
        );
    }

    #[test]
    fn guide_requests_optional_meaningful_bodies_without_prompting_for_empty_objects() {
        let mut queue_update = CapabilityV1::new(
            "queues-update-partial",
            "Update Queue configuration",
            "PATCH",
            "/accounts/{account_id}/queues/{queue_id}",
        );
        queue_update.request_schema = Some(json!({
            "type":"object",
            "x-cfctl-body-required":false,
            "properties":{
                "settings":{
                    "type":"object",
                    "properties":{"delivery_paused":{"type":"boolean"}}
                }
            }
        }));

        let queue_argv = capability_call_argv(&queue_update);
        assert!(queue_argv.iter().any(|argument| argument == "--body-stdin"));

        let mut empty_object = CapabilityV1::new(
            "widgets-touch",
            "Touch widget",
            "POST",
            "/accounts/{account_id}/widgets/{widget_id}/touch",
        );
        empty_object.request_schema = Some(json!({
            "type":"object",
            "x-cfctl-body-required":false,
            "properties":{}
        }));
        let empty_argv = capability_call_argv(&empty_object);
        assert!(!empty_argv.iter().any(|argument| argument == "--body-stdin"));

        for request_schema in [
            json!({"type":"array", "items":{"type":"string"}}),
            json!({"type":"string"}),
        ] {
            let mut capability = CapabilityV1::new(
                "widgets-import",
                "Import widgets",
                "POST",
                "/accounts/{account_id}/widgets/import",
            );
            capability.request_schema = Some(request_schema);
            let argv = capability_call_argv(&capability);
            assert!(argv.iter().any(|argument| argument == "--body-stdin"));
        }
    }

    #[test]
    fn guide_does_not_pretend_an_ambiguous_account_subscription_proves_entitlement() {
        let mut capability = CapabilityV1::new(
            "account-widgets-create",
            "Create account widget",
            "POST",
            "/accounts/{account_id}/widgets",
        );
        capability.product = "Widgets".to_owned();
        capability.adapter_status = AdapterStatus::Blocked;
        capability.entitlement.plans = BTreeMap::from([
            ("free".to_owned(), false),
            ("pro".to_owned(), true),
            ("business".to_owned(), true),
            ("enterprise".to_owned(), true),
        ]);
        capability.entitlement.blocker = Some(
            "live account entitlement resolution is unsupported because the official plan matrix has no product-scoped subscription join key"
                .to_owned(),
        );
        capability.blocked_reason = Some(format!(
            "operation contract incomplete: {}",
            capability.entitlement.blocker.as_deref().expect("blocker")
        ));

        let guide = guide_json(&capability);

        assert_eq!(guide["contract_state"], "blocked");
        assert!(
            guide["next_action"]["summary"]
                .as_str()
                .is_some_and(|summary| {
                    summary.contains("cannot safely map")
                        && summary.contains("product-scoped subscription")
                })
        );
        assert_eq!(guide["next_action"]["argv"][1], "docs");
        assert!(guide["call_argv"].is_null());
    }

    #[test]
    fn token_creation_guide_routes_through_the_inventory_bound_keys_workflow() {
        let mut account_token = CapabilityV1::new(
            "account-api-tokens-create-token",
            "Create account token",
            "POST",
            "/accounts/{account_id}/tokens",
        );
        account_token.risk = RiskClass::SecretSensitive;
        account_token.effect = cfctl_core::EffectClass::IdentityOrOwnership;
        account_token.cost.known = true;
        account_token.verification.strategy =
            "api_token_details_match_created_id_and_active_status".to_owned();
        account_token.rollback.warning =
            Some("revoke the new token if installation fails".to_owned());
        account_token.permissions = vec!["API Tokens Write".to_owned()];

        let account_guide = guide_json(&account_token);
        assert_eq!(account_guide["contract_state"], "available");
        assert_eq!(
            account_guide["call_argv"],
            json!([
                "cfctl",
                "keys",
                "mint",
                "--name",
                "<token-name>",
                "--permission",
                "<permission-group-id>",
                "--account",
                "<account_id>",
                "--value-out",
                "<new-mode-0600-path>",
                "--json"
            ])
        );
        assert_ne!(account_guide["call_argv"][1], "call");

        account_token.id = "user-api-tokens-create-token".to_owned();
        let user_guide = guide_json(&account_token);
        assert_eq!(user_guide["contract_state"], "available");
        assert_eq!(
            user_guide["call_argv"],
            json!([
                "cfctl",
                "keys",
                "mint",
                "--user",
                "--name",
                "<token-name>",
                "--permission",
                "<permission-group-id>",
                "--account",
                "<account_id>",
                "--value-out",
                "<new-mode-0600-path>",
                "--json"
            ])
        );
    }

    fn emergency_global_key_as_current() -> ProfilesConfig {
        let mut profiles = BTreeMap::new();
        profiles.insert(
            "emergency".to_owned(),
            ProfileMetadata::new("emergency", ProfileKind::GlobalKey, None),
        );
        profiles.insert(
            "work".to_owned(),
            ProfileMetadata::new("work", ProfileKind::OAuth, Some("account-a")),
        );
        ProfilesConfig {
            current_profile: Some("emergency".to_owned()),
            profiles,
            ..ProfilesConfig::default()
        }
    }

    #[test]
    fn emergency_global_key_is_never_selected_without_an_explicit_profile_flag() {
        let mut profiles = emergency_global_key_as_current();

        let blocked = profiles
            .selected(None)
            .expect_err("implicit global-key current profile must fail closed");
        assert!(
            blocked.to_string().contains("never selected implicitly"),
            "{blocked}"
        );
        profiles
            .selected(Some("emergency"))
            .expect("explicit --profile may use the emergency lane");

        profiles.current_profile = Some("work".to_owned());
        profiles
            .selected(None)
            .expect("non-emergency profiles remain selectable as current");
    }

    #[tokio::test]
    async fn execute_read_rejects_implicit_global_key_before_live_credential_use() {
        let root = tempfile::tempdir().expect("runtime root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
        emergency_global_key_as_current()
            .save(&store)
            .expect("save emergency as current");

        let capability = CapabilityV1::new("accounts-list", "List accounts", "GET", "/accounts");
        let catalog = test_catalog();
        let input = CallInput::default();

        let error = execute_read(&store, &catalog, &capability, &input, None, None)
            .await
            .expect_err("live read must not use ambient global-key current profile");
        assert!(
            error.to_string().contains("never selected implicitly"),
            "{error}"
        );

        // Explicit --profile is allowed past selection; without a real secret store
        // credential it still fails later — never with an implicit selection path.
        let explicit = execute_read(
            &store,
            &catalog,
            &capability,
            &input,
            Some("emergency"),
            None,
        )
        .await;
        let explicit_error = explicit.expect_err("no real emergency credential in this fixture");
        assert!(
            !explicit_error
                .to_string()
                .contains("never selected implicitly"),
            "explicit --profile must not be blocked by the ambient-selection guard: {explicit_error}"
        );
    }

    #[tokio::test]
    async fn call_command_live_read_rejects_implicit_global_key_current_profile() {
        let root = tempfile::tempdir().expect("runtime root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
        let catalog = test_catalog();
        store
            .write_json(&store.paths().catalog_file(), &catalog)
            .expect("seed non-stale catalog so call does not network-sync");
        emergency_global_key_as_current()
            .save(&store)
            .expect("save emergency as current");

        let error = call_command(
            &store,
            CallArgs {
                capability_id: "accounts-list".to_owned(),
                selectors: Vec::new(),
                query: Vec::new(),
                body_json: None,
                body_stdin: false,
                profile: None,
                account: None,
                if_match: None,
                if_none_match: None,
                value_out: None,
            },
        )
        .await
        .expect_err("call without --profile must fail closed on ambient global-key");
        assert!(
            error.to_string().contains("never selected implicitly"),
            "{error}"
        );
    }

    #[test]
    fn store_imported_api_token_selects_scoped_profile_and_keeps_secret_out_of_envelope() {
        let root = tempfile::tempdir().expect("runtime root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
        let secrets = MemorySecretStore::default();
        let mut profiles = ProfilesConfig::default();
        let token = "cfat_test_token_must_not_echo";

        let envelope = store_imported_api_token(
            &store,
            &mut profiles,
            &secrets,
            "default",
            "account-a",
            token,
        )
        .expect("import api token");
        assert_eq!(envelope.command, "auth import-api-token");
        assert!(envelope.ok);
        assert_eq!(envelope.result["selected"], true);
        assert_eq!(envelope.result["kind"], "api_token");
        assert_eq!(envelope.result["account_id"], "account-a");
        assert_eq!(envelope.result["secret_backend"], "memory");
        let encoded = serde_json::to_string(&envelope).expect("envelope serializes");
        assert!(
            !encoded.contains(token),
            "token must not appear in the result envelope: {encoded}"
        );
        assert_eq!(profiles.current_profile.as_deref(), Some("default"));
        let profile = profiles.profiles.get("default").expect("profile saved");
        assert_eq!(profile.kind, ProfileKind::ApiToken);
        assert_eq!(profile.account_id.as_deref(), Some("account-a"));
        assert!(!profile.emergency_only);
        assert_eq!(
            secrets
                .load_credential("default", ProfileKind::ApiToken)
                .expect("credential")
                .bearer_token(),
            Some(token)
        );

        let empty = store_imported_api_token(
            &store,
            &mut ProfilesConfig::default(),
            &secrets,
            "default",
            "account-a",
            "",
        )
        .expect_err("empty token rejected");
        assert!(empty.to_string().contains("API token was empty"));

        let unpinned = store_imported_api_token(
            &store,
            &mut ProfilesConfig::default(),
            &secrets,
            "default",
            "  ",
            token,
        )
        .expect_err("empty account rejected");
        assert!(unpinned.to_string().contains("--account"));
    }

    #[test]
    fn standing_authority_lifecycle_approves_lists_and_revokes_offline() {
        let root = tempfile::tempdir().expect("runtime root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
        let authority = StandingAuthorityV1::draft(
            "account-a",
            vec!["account-api-tokens-create-token".to_owned()],
            vec!["group-a".to_owned()],
            "sha256:inventory-binding",
            24,
            "cf-rotation-",
            2,
            Utc::now() + ChronoDuration::days(30),
        )
        .expect("authority draft");
        let authority_id = authority.authority_id.clone();
        store.save_authority(&authority).expect("persist draft");

        let denied = key_policy_approve(
            &store,
            &KeyPolicyApproveArgs {
                authority_id: authority_id.clone(),
                yes: false,
            },
        )
        .expect_err("approval requires an explicit yes");
        assert!(denied.to_string().contains("explicit yes"), "{denied}");

        let approved = key_policy_approve(
            &store,
            &KeyPolicyApproveArgs {
                authority_id: authority_id.clone(),
                yes: true,
            },
        )
        .expect("explicit approval activates");
        assert_eq!(approved.result["status"], "active");

        let listed = key_policy_list(&store).expect("list authorities");
        assert_eq!(
            listed.result["authorities"][0]["authority_id"],
            serde_json::json!(authority_id)
        );
        assert_eq!(listed.result["authorities"][0]["status"], "active");
        assert_eq!(listed.result["authorities"][0]["runs_last_24h"], 0);
        assert_eq!(listed.result["authorities"][0]["runs_remaining_24h"], 2);
        assert_eq!(
            listed.result["authorities"][0]["minted_token_ids"],
            json!([])
        );
        assert!(
            listed.result["authorities"][0]["next_action"]
                .as_str()
                .is_some_and(|action| action.contains("--under-policy"))
        );

        preflight_standing_authority(&store, Some(&authority_id))
            .expect("active authority passes preflight");
        assert!(
            preflight_standing_authority(&store, Some("ghost")).is_err(),
            "unknown authorities fail closed before any network"
        );

        let revoked = key_policy_revoke(
            &store,
            &KeyPolicySelector {
                authority_id: authority_id.clone(),
            },
        )
        .expect("revocation is unconditional");
        assert_eq!(revoked.result["status"], "revoked");
        assert!(
            preflight_standing_authority(&store, Some(&authority_id)).is_err(),
            "revoked authorities fail preflight immediately"
        );
    }

    #[test]
    fn standing_authority_list_reports_effective_expiry() {
        let root = tempfile::tempdir().expect("runtime root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
        let expired = StandingAuthorityV1::draft(
            "account-a",
            vec!["account-api-tokens-create-token".to_owned()],
            vec!["group-a".to_owned()],
            "sha256:inventory-binding",
            24,
            "cf-rotation-",
            2,
            Utc::now() - ChronoDuration::seconds(1),
        )
        .expect("expired authority draft remains inspectable");
        store
            .create_authority(&expired)
            .expect("persist expired authority");

        let listed = key_policy_list(&store).expect("list authorities");

        assert_eq!(listed.result["authorities"][0]["status"], "expired");
    }

    #[test]
    fn approval_and_revocation_race_cannot_resurrect_an_authority() {
        let root = tempfile::tempdir().expect("runtime root");
        let paths = RuntimePaths::from_root(root.path());
        let store = StateStore::open(paths.clone()).expect("state store");
        let authority = StandingAuthorityV1::draft(
            "account-a",
            vec!["account-api-tokens-create-token".to_owned()],
            vec!["group-a".to_owned()],
            "sha256:inventory-binding",
            24,
            "cf-rotation-",
            2,
            Utc::now() + ChronoDuration::days(30),
        )
        .expect("authority draft");
        let authority_id = authority.authority_id.clone();
        store
            .create_authority(&authority)
            .expect("persist pending authority");
        let barrier = Arc::new(Barrier::new(2));

        let approve = {
            let paths = paths.clone();
            let barrier = Arc::clone(&barrier);
            let authority_id = authority_id.clone();
            thread::spawn(move || {
                let store = StateStore::open(paths).expect("approval store");
                barrier.wait();
                key_policy_approve(
                    &store,
                    &KeyPolicyApproveArgs {
                        authority_id,
                        yes: true,
                    },
                )
            })
        };
        let revoke = {
            let paths = paths.clone();
            let barrier = Arc::clone(&barrier);
            let authority_id = authority_id.clone();
            thread::spawn(move || {
                let store = StateStore::open(paths).expect("revocation store");
                barrier.wait();
                key_policy_revoke(&store, &KeyPolicySelector { authority_id })
            })
        };

        let _approval_result = approve.join().expect("approval thread joins");
        revoke
            .join()
            .expect("revocation thread joins")
            .expect("revocation always commits");
        let durable = store
            .load_authority(&authority_id)
            .expect("durable authority reloads");
        assert_eq!(durable.status, StandingAuthorityStatus::Revoked);
    }

    fn active_standing_authority(max_runs_per_day: u32) -> StandingAuthorityV1 {
        let mut authority = StandingAuthorityV1::draft(
            "account-a",
            vec![
                "account-api-tokens-create-token".to_owned(),
                "account-api-tokens-delete-token".to_owned(),
            ],
            vec!["group-a".to_owned()],
            "sha256:inventory-binding",
            24,
            "cf-rotation-",
            max_runs_per_day,
            Utc::now() + ChronoDuration::days(30),
        )
        .expect("authority draft");
        authority.approve(true).expect("authority approval");
        authority
    }

    fn standing_mint_plan() -> (PlanV1, CallInput) {
        let mut capability = CapabilityV1::new(
            "account-api-tokens-create-token",
            "Create account token",
            "POST",
            "/accounts/{account_id}/tokens",
        );
        capability.risk = RiskClass::SecretSensitive;
        let plan = PlanV1::draft(
            "profile-a",
            "account-a",
            "catalog-sha",
            capability,
            json!({}),
        )
        .expect("standing mint plan");
        let input = CallInput {
            selectors: json!({"account_id":"account-a"}),
            query: json!({}),
            body: Some(json!({
                "name":"cf-rotation-child",
                "expires_on":(Utc::now() + ChronoDuration::hours(1)).to_rfc3339(),
                "policies":[{
                    "effect":"allow",
                    "permission_groups":[{"id":"group-a"}],
                    "resources":{"com.cloudflare.api.account.account-a":"*"}
                }]
            })),
            ..CallInput::default()
        };
        (plan, input)
    }

    #[test]
    fn standing_admission_serializes_one_run_budget_across_two_stores() {
        let root = tempfile::tempdir().expect("runtime root");
        let paths = RuntimePaths::from_root(root.path());
        let store = StateStore::open(paths.clone()).expect("state store");
        let mut authority = StandingAuthorityV1::draft(
            "account-a",
            vec!["account-api-tokens-create-token".to_owned()],
            vec!["group-a".to_owned()],
            "sha256:inventory-binding",
            24,
            "cf-rotation-",
            1,
            Utc::now() + ChronoDuration::days(30),
        )
        .expect("authority draft");
        authority.approve(true).expect("authority approval");
        store
            .create_authority(&authority)
            .expect("persist authority");
        let (plan_a, input_a) = standing_mint_plan();
        let (plan_b, input_b) = standing_mint_plan();
        let operation_ids = [plan_a.operation_id.clone(), plan_b.operation_id.clone()];
        store.save_plan(&plan_a).expect("persist plan A");
        store.save_plan(&plan_b).expect("persist plan B");

        let barrier = Arc::new(Barrier::new(2));
        let handles = [(plan_a, input_a), (plan_b, input_b)]
            .into_iter()
            .map(|(mut plan, input)| {
                let paths = paths.clone();
                let barrier = Arc::clone(&barrier);
                let snapshot = authority.clone();
                thread::spawn(move || {
                    let store = StateStore::open(paths).expect("second store");
                    barrier.wait();
                    admit_standing_plan(&store, &mut plan, &snapshot, &input)
                })
            })
            .collect::<Vec<_>>();
        let results = handles
            .into_iter()
            .map(|handle| handle.join().expect("admission thread"))
            .collect::<Vec<_>>();

        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        let stored = store
            .load_authority(&authority.authority_id)
            .expect("stored authority");
        assert_eq!(stored.run_log.len(), 1);
        assert_eq!(stored.runs_in_last_day(Utc::now()), 1);
        let consumed = operation_ids
            .iter()
            .map(|operation_id| store.load_plan(operation_id).expect("stored plan"))
            .filter(|plan| plan.status == PlanStatus::Consumed)
            .count();
        assert_eq!(consumed, 1, "only the durably reserved plan is consumed");
    }

    #[test]
    fn revocation_before_admission_blocks_the_run_without_spending_budget() {
        let root = tempfile::tempdir().expect("runtime root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
        let authority = active_standing_authority(2);
        let authority_id = authority.authority_id.clone();
        store
            .create_authority(&authority)
            .expect("persist active authority");
        let (mut plan, input) = standing_mint_plan();
        store.save_plan(&plan).expect("persist draft plan");
        key_policy_revoke(
            &store,
            &KeyPolicySelector {
                authority_id: authority_id.clone(),
            },
        )
        .expect("revocation commits before admission");

        let error = admit_standing_plan(&store, &mut plan, &authority, &input)
            .expect_err("revoked authority cannot admit a run");

        assert!(error.to_string().contains("revoked"), "{error}");
        let durable = store
            .load_authority(&authority_id)
            .expect("authority reloads");
        assert_eq!(durable.status, StandingAuthorityStatus::Revoked);
        assert!(durable.run_log.is_empty());
        assert_eq!(
            store
                .load_plan(&plan.operation_id)
                .expect("draft plan reloads")
                .status,
            PlanStatus::Draft
        );
    }

    #[test]
    fn standing_admission_reserves_budget_before_plan_persistence() {
        let root = tempfile::tempdir().expect("runtime root");
        let paths = RuntimePaths::from_root(root.path());
        let store = StateStore::open(paths.clone()).expect("state store");
        let authority = active_standing_authority(1);
        store
            .create_authority(&authority)
            .expect("persist active authority");
        let (mut plan, input) = standing_mint_plan();
        store.save_plan(&plan).expect("persist draft plan");
        let plan_path = paths
            .data_dir
            .join("plans")
            .join(format!("{}.json", plan.operation_id));
        fs::remove_file(&plan_path).expect("remove plan for injected persistence failure");
        fs::create_dir(&plan_path).expect("replace plan with non-regular fixture");

        admit_standing_plan(&store, &mut plan, &authority, &input)
            .expect_err("plan persistence fails after authority reservation");

        let durable = store
            .load_authority(&authority.authority_id)
            .expect("authority reservation reloads");
        assert_eq!(durable.run_log.len(), 1);
        assert_eq!(durable.run_log[0].operation_id, plan.operation_id);
        assert_eq!(
            plan.transaction_stage,
            TransactionStageV1::ConsumptionPersisted,
            "the boundary attempt is not recorded until after the plan save"
        );
    }

    fn standing_token_plan_with_receipt(
        authority: &StandingAuthorityV1,
        response: Value,
    ) -> PlanV1 {
        standing_token_plan_with_receipt_and_targets(authority, response, json!({}))
    }

    fn standing_token_plan_with_receipt_and_targets(
        authority: &StandingAuthorityV1,
        response: Value,
        targets: Value,
    ) -> PlanV1 {
        let mut plan = standing_token_plan_at_boundary_attempt(authority, targets);
        plan.record_transaction_stage_with_artifact(
            TransactionStageV1::BoundaryResponsePersisted,
            response,
        )
        .expect("boundary response");
        plan
    }

    fn standing_token_plan_at_boundary_attempt(
        authority: &StandingAuthorityV1,
        targets: Value,
    ) -> PlanV1 {
        let mut capability = CapabilityV1::new(
            "account-api-tokens-create-token",
            "Create account token",
            "POST",
            "/accounts/{account_id}/tokens",
        );
        capability.risk = RiskClass::SecretSensitive;
        let mut plan = PlanV1::draft("profile-a", "account-a", "catalog-sha", capability, targets)
            .expect("standing plan");
        plan.mark_consumed_via_standing_authority(authority)
            .expect("standing consumption");
        plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
            .expect("boundary attempt");
        plan
    }

    fn reserve_standing_plan(authority: &mut StandingAuthorityV1, plan: &PlanV1) {
        authority
            .reserve_run(Utc::now(), &plan.operation_id, &plan.capability.id)
            .expect("standing run reservation");
    }

    #[test]
    fn standing_lineage_uses_only_validated_success_receipts_and_survives_revocation() {
        let mut authority = StandingAuthorityV1::draft(
            "account-a",
            vec!["account-api-tokens-create-token".to_owned()],
            vec!["group-a".to_owned()],
            "sha256:inventory-binding",
            24,
            "cf-rotation-",
            8,
            Utc::now() + ChronoDuration::days(30),
        )
        .expect("authority draft");
        authority.approve(true).expect("authority approval");
        let plan = standing_token_plan_with_receipt(
            &authority,
            json!({"success":true,"resource_id":"token-child"}),
        );
        let malformed = [
            json!({"success":true}),
            json!({"success":true,"resource_id":""}),
        ]
        .map(|receipt| standing_token_plan_with_receipt(&authority, receipt));
        let unsuccessful = standing_token_plan_with_receipt(
            &authority,
            json!({"success":false,"resource_id":"token-never-created"}),
        );
        reserve_standing_plan(&mut authority, &plan);
        for candidate in &malformed {
            reserve_standing_plan(&mut authority, candidate);
        }
        reserve_standing_plan(&mut authority, &unsuccessful);

        assert_eq!(
            validated_standing_lineage_token_id(&plan, &authority).expect("valid standing receipt"),
            Some("token-child")
        );
        authority.revoke();
        assert_eq!(
            validated_standing_lineage_token_id(&plan, &authority)
                .expect("revocation cannot erase a completed boundary fact"),
            Some("token-child")
        );

        let mut wrong_authority = authority.clone();
        wrong_authority.authority_id = "00000000-0000-4000-8000-000000000001".to_owned();
        assert!(
            validated_standing_lineage_token_id(&plan, &wrong_authority).is_err(),
            "the consumption receipt binds the exact authority"
        );

        for malformed in &malformed {
            assert!(
                validated_standing_lineage_token_id(malformed, &authority).is_err(),
                "successful receipts require a nonempty resource id"
            );
        }

        assert_eq!(
            validated_standing_lineage_token_id(&unsuccessful, &authority)
                .expect("an unsuccessful receipt is validated but creates no lineage"),
            None
        );
    }

    #[test]
    fn standing_lineage_requires_the_authoritys_durable_run_reservation() {
        let authority = active_standing_authority(2);
        let plan = standing_token_plan_with_receipt(
            &authority,
            json!({"success":true,"resource_id":"token-unreserved"}),
        );

        let error = validated_standing_lineage_token_id(&plan, &authority)
            .expect_err("a plan-side receipt cannot manufacture authority lineage");

        assert!(error.to_string().contains("reserved"), "{error}");
    }

    #[test]
    fn standing_lineage_reservation_must_bind_the_same_capability() {
        let mut authority = active_standing_authority(2);
        let plan = standing_token_plan_with_receipt(
            &authority,
            json!({"success":true,"resource_id":"token-wrong-capability"}),
        );
        authority
            .reserve_run(
                Utc::now(),
                &plan.operation_id,
                "account-api-tokens-delete-token",
            )
            .expect("persist mismatched reservation fixture");

        let error = validated_standing_lineage_token_id(&plan, &authority)
            .expect_err("the reservation must bind the exact creation capability");

        assert!(error.to_string().contains("reserved"), "{error}");
        assert!(error.to_string().contains("capability"), "{error}");
    }

    #[test]
    fn standing_lineage_is_reconciled_even_when_the_secret_sink_fails() {
        let root = tempfile::tempdir().expect("runtime root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
        let mut authority = active_standing_authority(2);
        let mut plan = standing_token_plan_with_receipt(
            &authority,
            json!({"success":true,"resource_id":"token-sink-failed"}),
        );
        reserve_standing_plan(&mut authority, &plan);
        store
            .create_authority(&authority)
            .expect("persist active authority and run reservation");
        store
            .save_plan(&plan)
            .expect("persist successful boundary receipt");

        let outcome = persist_secret_lifecycle_and_reconcile_lineage(
            &store,
            &mut plan,
            true,
            None,
            &MemorySecretStore::default(),
            true,
        );
        let error = outcome
            .error
            .expect("missing one-time secret fails the sink");

        assert!(
            error.to_string().contains("required sink-only value"),
            "{error}"
        );
        assert!(
            outcome.lineage_evidence.is_some(),
            "lineage evidence survives a sink failure"
        );
        let durable_authority = store
            .load_authority(&authority.authority_id)
            .expect("authority lineage reloads");
        assert_eq!(
            durable_authority.minted_token_ids,
            vec!["token-sink-failed"]
        );
        let durable_plan = store
            .load_plan(&plan.operation_id)
            .expect("sink failure checkpoint reloads");
        assert_eq!(durable_plan.status, PlanStatus::RectificationRequired);
        assert_eq!(
            durable_plan.transaction_stage,
            TransactionStageV1::SecretSinkPersisted
        );
    }

    #[test]
    fn post_boundary_failure_envelope_retains_performed_truth_and_receipts() {
        let (plan, _) = standing_mint_plan();
        let apply = EvidenceV1::new(
            EvidenceClass::Apply,
            "sha256:apply",
            "/managed/evidence/apply.json",
        );
        let lineage = EvidenceV1::new(
            EvidenceClass::StandingApply,
            "sha256:lineage",
            "/managed/evidence/lineage.json",
        );
        let error = super::CliError::Input("injected sink failure".to_owned());

        let envelope = super::post_boundary_failure_envelope(
            &plan,
            json!({"success":true,"resource_id":"token-created"}),
            Some(apply),
            Some(lineage),
            &error,
            true,
            "the Cloudflare boundary response is durable, but recovery is required",
        );

        assert!(!envelope.ok);
        assert!(envelope.performed);
        assert_eq!(envelope.command, "plans run");
        assert_eq!(
            envelope.operation_id.as_deref(),
            Some(plan.operation_id.as_str())
        );
        assert_eq!(
            envelope.capability_id.as_deref(),
            Some(plan.capability.id.as_str())
        );
        assert_eq!(envelope.evidence.len(), 2);
        assert!(envelope.error.as_ref().is_some_and(|error| {
            error.message.contains("injected sink failure")
                && error.next_step.as_deref().is_some_and(|next| {
                    next.contains("Do not replay") && next.contains(&plan.operation_id)
                })
        }));
    }

    #[test]
    fn final_checkpoint_failure_preserves_boundary_and_verification_truth() {
        let (mut plan, _) = standing_mint_plan();
        plan.status = PlanStatus::Verified;
        let apply = EvidenceV1::new(
            EvidenceClass::Apply,
            "sha256:apply",
            "/managed/evidence/apply.json",
        );
        let lineage = EvidenceV1::new(
            EvidenceClass::StandingApply,
            "sha256:lineage",
            "/managed/evidence/lineage.json",
        );
        let verification_evidence = EvidenceV1::new(
            EvidenceClass::PostChangeVerification,
            "sha256:verification",
            "/managed/evidence/verification.json",
        );
        let finalization_error =
            super::CliError::Input("injected closed-checkpoint failure".to_owned());

        let envelope = super::api_plan_result_envelope(
            &plan,
            json!({"success":true,"resource_id":"token-created"}),
            apply,
            Some(lineage),
            super::ApiVerificationOutcome {
                state: VerificationState::Passed,
                basis: "live readback matched".to_owned(),
                evidence: Some(verification_evidence),
                error: None,
            },
            true,
            Some(&finalization_error),
        );

        assert!(!envelope.ok);
        assert!(envelope.performed);
        assert_eq!(envelope.verification.state, VerificationState::Passed);
        assert!(
            envelope
                .verification
                .basis
                .as_deref()
                .is_some_and(|basis| basis.contains("live readback matched")
                    && basis.contains("final plan checkpoint"))
        );
        assert_eq!(envelope.evidence.len(), 3);
        assert!(
            envelope
                .error
                .as_ref()
                .is_some_and(|error| error.message.contains("injected closed-checkpoint failure"))
        );
    }

    #[test]
    fn successful_response_still_sinks_the_secret_when_apply_evidence_persistence_fails() {
        let root = tempfile::tempdir().expect("runtime root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
        let mut authority = active_standing_authority(2);
        let sink_path = root.path().join("created-token.txt");
        let mut plan = standing_token_plan_at_boundary_attempt(
            &authority,
            json!({"adapter":{"value_out":sink_path}}),
        );
        reserve_standing_plan(&mut authority, &plan);
        store
            .create_authority(&authority)
            .expect("persist active authority and run reservation");
        store
            .save_plan(&plan)
            .expect("persist boundary attempt before the remote call");
        let evidence_dir = store.paths().data_dir.join("evidence");
        fs::remove_dir(&evidence_dir).expect("remove empty evidence directory");
        fs::write(&evidence_dir, "not-a-directory").expect("block evidence persistence");
        let response = CloudflareResponseV1 {
            status: 200,
            success: true,
            result: json!({"id":"token-apply-evidence-failed","value":"one-time-secret"}),
            errors: Vec::new(),
            result_info: None,
            etag: None,
            cf_ray: None,
        };

        let envelope = match super::process_api_boundary_response(
            &store,
            &mut plan,
            &response,
            &MemorySecretStore::default(),
        )
        .expect("a local evidence failure returns a recovery envelope")
        {
            super::ApiBoundaryResponseOutcome::Recovery(envelope) => envelope,
            super::ApiBoundaryResponseOutcome::Ready { .. } => {
                panic!("missing apply evidence cannot proceed to verification")
            }
        };

        assert!(!envelope.ok);
        assert!(envelope.performed);
        assert_eq!(
            envelope.operation_id.as_deref(),
            Some(plan.operation_id.as_str())
        );
        assert_eq!(envelope.verification.state, VerificationState::Pending);
        assert!(envelope.error.as_ref().is_some_and(|error| {
            error.message.contains("apply evidence")
                && error
                    .next_step
                    .as_deref()
                    .is_some_and(|next| next.contains("Do not replay") && next.contains("rectify"))
        }));
        assert_eq!(
            fs::read_to_string(&sink_path).expect("one-time secret was sunk"),
            "one-time-secret"
        );
        assert_eq!(
            store
                .load_authority(&authority.authority_id)
                .expect("authority lineage reloads")
                .minted_token_ids,
            vec!["token-apply-evidence-failed"]
        );
        let durable_plan = store
            .load_plan(&plan.operation_id)
            .expect("boundary receipt and sink checkpoint reload");
        assert_eq!(durable_plan.status, PlanStatus::RectificationRequired);
        assert!(
            durable_plan
                .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
                .is_some(),
            "the receipt remains durable even when the separate apply evidence write fails"
        );
    }

    #[test]
    fn successful_response_still_sinks_the_secret_when_boundary_receipt_persistence_fails() {
        let root = tempfile::tempdir().expect("runtime root");
        let paths = RuntimePaths::from_root(root.path());
        let store = StateStore::open(paths.clone()).expect("state store");
        let mut authority = active_standing_authority(2);
        let sink_path = root.path().join("created-token.txt");
        let mut plan = standing_token_plan_at_boundary_attempt(
            &authority,
            json!({"adapter":{"value_out":sink_path}}),
        );
        reserve_standing_plan(&mut authority, &plan);
        store
            .create_authority(&authority)
            .expect("persist active authority and run reservation");
        store
            .save_plan(&plan)
            .expect("persist boundary attempt before the remote call");
        let plan_path = paths
            .data_dir
            .join("plans")
            .join(format!("{}.json", plan.operation_id));
        fs::remove_file(&plan_path).expect("remove plan before injected persistence failure");
        fs::create_dir(&plan_path).expect("replace plan with a non-regular fixture");
        let response = CloudflareResponseV1 {
            status: 200,
            success: true,
            result: json!({"id":"token-receipt-persistence-failed","value":"one-time-secret"}),
            errors: Vec::new(),
            result_info: None,
            etag: None,
            cf_ray: None,
        };

        let envelope = match super::process_api_boundary_response(
            &store,
            &mut plan,
            &response,
            &MemorySecretStore::default(),
        )
        .expect("a receipt persistence failure returns a recovery envelope")
        {
            super::ApiBoundaryResponseOutcome::Recovery(envelope) => envelope,
            super::ApiBoundaryResponseOutcome::Ready { .. } => {
                panic!("an undurable boundary receipt cannot proceed to verification")
            }
        };

        assert!(!envelope.ok);
        assert!(envelope.performed);
        assert_eq!(
            envelope.operation_id.as_deref(),
            Some(plan.operation_id.as_str())
        );
        assert_eq!(envelope.verification.state, VerificationState::Pending);
        assert!(envelope.error.as_ref().is_some_and(|error| {
            error.message.contains("boundary response")
                && error
                    .next_step
                    .as_deref()
                    .is_some_and(|next| next.contains("Do not replay") && next.contains("rectify"))
        }));
        assert_eq!(
            fs::read_to_string(&sink_path).expect("one-time secret was sunk"),
            "one-time-secret"
        );
        assert!(
            store
                .load_authority(&authority.authority_id)
                .expect("authority reloads")
                .minted_token_ids
                .is_empty(),
            "an undurable boundary receipt cannot authorize lineage reconciliation"
        );
    }

    #[test]
    fn transport_error_after_boundary_attempt_returns_unknown_no_replay_envelope() {
        let root = tempfile::tempdir().expect("runtime root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
        let authority = active_standing_authority(2);
        let mut plan = standing_token_plan_at_boundary_attempt(&authority, json!({}));
        store
            .save_plan(&plan)
            .expect("persist boundary attempt before the remote call");
        let transport_error = super::CliError::Input("injected response timeout".to_owned());

        let envelope = super::process_api_transport_failure(
            &store,
            &mut plan,
            &transport_error,
            &MemorySecretStore::default(),
        );

        assert!(!envelope.ok);
        assert!(!envelope.performed);
        assert_eq!(
            envelope.operation_id.as_deref(),
            Some(plan.operation_id.as_str())
        );
        assert_eq!(envelope.verification.state, VerificationState::Pending);
        assert!(envelope.error.as_ref().is_some_and(|error| {
            error.message.contains("outcome is unknown")
                && error.message.contains("injected response timeout")
                && error
                    .next_step
                    .as_deref()
                    .is_some_and(|next| next.contains("Do not replay") && next.contains("rectify"))
        }));
        let durable_plan = store
            .load_plan(&plan.operation_id)
            .expect("unknown outcome checkpoints reload");
        assert_eq!(durable_plan.status, PlanStatus::RectificationRequired);
        assert_eq!(
            durable_plan.transaction_stage,
            TransactionStageV1::SecretSinkPersisted
        );
        assert_eq!(
            durable_plan
                .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
                .and_then(|artifact| artifact.get("receipt_available"))
                .and_then(Value::as_bool),
            Some(false)
        );
    }

    #[test]
    fn standing_lineage_is_durable_before_a_failing_verification_checkpoint() {
        let root = tempfile::tempdir().expect("runtime root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
        let mut authority = active_standing_authority(2);
        let sink_path = root.path().join("created-token.txt");
        let mut plan = standing_token_plan_with_receipt_and_targets(
            &authority,
            json!({"success":true,"resource_id":"token-verification-failed"}),
            json!({"adapter":{"value_out":sink_path}}),
        );
        reserve_standing_plan(&mut authority, &plan);
        store
            .create_authority(&authority)
            .expect("persist active authority and run reservation");
        store
            .save_plan(&plan)
            .expect("persist successful boundary receipt");

        let outcome = persist_secret_lifecycle_and_reconcile_lineage(
            &store,
            &mut plan,
            true,
            Some(&json!({"id":"token-verification-failed","value":"one-time-secret"})),
            &MemorySecretStore::default(),
            true,
        );
        assert!(
            outcome.error.is_none(),
            "sink and lineage reconciliation complete: {:?}",
            outcome.error
        );
        assert!(outcome.lineage_evidence.is_some());
        assert_eq!(
            store
                .load_authority(&authority.authority_id)
                .expect("authority lineage reloads")
                .minted_token_ids,
            vec!["token-verification-failed"]
        );

        super::persist_transaction_stage(
            &store,
            &mut plan,
            TransactionStageV1::VerificationAttemptPersisted,
        )
        .expect("verification attempt checkpoint persists");
        let outcome = super::verification_outcome(
            &store,
            &mut plan,
            OperationVerificationV1 {
                strategy: "test_readback".to_owned(),
                passed: false,
                basis: "injected post-change mismatch".to_owned(),
                readback: CloudflareResponseV1 {
                    status: 200,
                    success: true,
                    result: json!({"id":"token-verification-failed","status":"unexpected"}),
                    errors: Vec::new(),
                    result_info: None,
                    etag: None,
                    cf_ray: None,
                },
            },
        )
        .expect("verification outcome records evidence");
        let artifact =
            super::verification_response_artifact(&outcome).expect("verification receipt builds");
        super::persist_transaction_stage_with_artifact(
            &store,
            &mut plan,
            TransactionStageV1::VerificationResponsePersisted,
            artifact,
        )
        .expect("failing verification checkpoint persists");

        let durable_authority = store
            .load_authority(&authority.authority_id)
            .expect("authority reloads after verification failure");
        assert_eq!(durable_authority.status, StandingAuthorityStatus::Active);
        assert_eq!(
            durable_authority.minted_token_ids,
            vec!["token-verification-failed"]
        );
        assert_eq!(plan.status, PlanStatus::RectificationRequired);
    }

    #[test]
    fn later_standing_preflight_recovers_missing_lineage_after_reopen() {
        let root = tempfile::tempdir().expect("runtime root");
        let paths = RuntimePaths::from_root(root.path());
        let store = StateStore::open(paths.clone()).expect("state store");
        let mut authority = active_standing_authority(2);
        let authority_id = authority.authority_id.clone();
        let plan = standing_token_plan_with_receipt(
            &authority,
            json!({"success":true,"resource_id":"token-crash-recovery"}),
        );
        reserve_standing_plan(&mut authority, &plan);
        store
            .create_authority(&authority)
            .expect("persist active authority and run reservation");
        store
            .save_plan(&plan)
            .expect("persist only the boundary receipt before simulated crash");
        drop(store);

        let reopened = StateStore::open(paths).expect("state store reopens");
        preflight_standing_authority(&reopened, Some(&authority_id))
            .expect("later standing preflight recovers lineage");
        preflight_standing_authority(&reopened, Some(&authority_id))
            .expect("repeated recovery is idempotent");

        let durable = reopened
            .load_authority(&authority_id)
            .expect("reconciled authority reloads");
        assert_eq!(durable.minted_token_ids, vec!["token-crash-recovery"]);
    }

    #[test]
    fn standing_lineage_recovery_cannot_observe_an_in_flight_plan() {
        let root = tempfile::tempdir().expect("runtime root");
        let paths = RuntimePaths::from_root(root.path());
        let running_store = StateStore::open(paths.clone()).expect("running store");
        let recovery_store = StateStore::open(paths).expect("recovery store");
        let mut authority = active_standing_authority(2);
        let authority_id = authority.authority_id.clone();
        let plan = standing_token_plan_with_receipt(
            &authority,
            json!({"success":true,"resource_id":"token-in-flight"}),
        );
        reserve_standing_plan(&mut authority, &plan);
        running_store
            .create_authority(&authority)
            .expect("persist active authority and run reservation");
        let operation_id = plan.operation_id.clone();
        running_store
            .save_plan(&plan)
            .expect("persist boundary response before the sink attempt");
        let plan_guard = running_store
            .lock_plan(&operation_id)
            .expect("running invocation owns the plan");

        let error = super::recover_standing_lineage(&recovery_store, &authority_id)
            .expect_err("recovery cannot inspect an in-flight plan");

        assert!(error.to_string().contains("locked"), "{error}");
        assert!(
            recovery_store
                .load_authority(&authority_id)
                .expect("authority reloads")
                .minted_token_ids
                .is_empty(),
            "recovery must not publish lineage before the running invocation attempts its sink"
        );
        drop(plan_guard);
        super::recover_standing_lineage(&recovery_store, &authority_id)
            .expect("recovery proceeds after the running invocation releases its plan");
        assert_eq!(
            recovery_store
                .load_authority(&authority_id)
                .expect("reconciled authority reloads")
                .minted_token_ids,
            vec!["token-in-flight"]
        );
    }

    #[tokio::test]
    async fn plans_rectify_recovers_missing_lineage_idempotently() {
        let root = tempfile::tempdir().expect("runtime root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
        let mut authority = active_standing_authority(2);
        let plan = standing_token_plan_with_receipt(
            &authority,
            json!({"success":true,"resource_id":"token-rectify-recovery"}),
        );
        reserve_standing_plan(&mut authority, &plan);
        store
            .create_authority(&authority)
            .expect("persist active authority and run reservation");
        let operation_id = plan.operation_id.clone();
        store
            .save_plan(&plan)
            .expect("persist successful boundary receipt");

        let first = rectify_plan(
            &store,
            &PlanSelector {
                operation_id: operation_id.clone(),
            },
        )
        .await
        .expect("rectify reconciles without replaying the source mutation");
        assert!(
            first
                .evidence
                .iter()
                .any(|evidence| evidence.class == EvidenceClass::StandingApply),
            "rectify must return the receipt for its authority-lineage mutation"
        );
        rectify_plan(
            &store,
            &PlanSelector {
                operation_id: operation_id.clone(),
            },
        )
        .await
        .expect("repeated rectification is idempotent");

        let durable = store
            .load_authority(&authority.authority_id)
            .expect("authority lineage reloads");
        assert_eq!(durable.minted_token_ids, vec!["token-rectify-recovery"]);
    }

    #[tokio::test]
    async fn plans_rectify_cannot_race_an_in_flight_plan() {
        let root = tempfile::tempdir().expect("runtime root");
        let paths = RuntimePaths::from_root(root.path());
        let running_store = StateStore::open(paths.clone()).expect("running store");
        let rectify_store = StateStore::open(paths).expect("rectify store");
        let mut authority = active_standing_authority(2);
        let authority_id = authority.authority_id.clone();
        let plan = standing_token_plan_with_receipt(
            &authority,
            json!({"success":true,"resource_id":"token-rectify-in-flight"}),
        );
        reserve_standing_plan(&mut authority, &plan);
        running_store
            .create_authority(&authority)
            .expect("persist active authority and run reservation");
        let operation_id = plan.operation_id.clone();
        running_store
            .save_plan(&plan)
            .expect("persist boundary response before the sink attempt");
        let plan_guard = running_store
            .lock_plan(&operation_id)
            .expect("running invocation owns the plan");

        let error = rectify_plan(
            &rectify_store,
            &PlanSelector {
                operation_id: operation_id.clone(),
            },
        )
        .await
        .expect_err("rectification cannot race an in-flight run");

        assert!(error.to_string().contains("locked"), "{error}");
        assert!(
            rectify_store
                .load_authority(&authority_id)
                .expect("authority reloads")
                .minted_token_ids
                .is_empty(),
            "rectification must not publish lineage while the source run owns the plan"
        );
        drop(plan_guard);
        rectify_plan(&rectify_store, &PlanSelector { operation_id })
            .await
            .expect("rectification proceeds after the source plan lock is released");
        assert_eq!(
            rectify_store
                .load_authority(&authority_id)
                .expect("reconciled authority reloads")
                .minted_token_ids,
            vec!["token-rectify-in-flight"]
        );
    }

    #[test]
    fn concurrent_lineage_reconciliation_is_idempotent_and_preserves_revocation() {
        let root = tempfile::tempdir().expect("runtime root");
        let paths = RuntimePaths::from_root(root.path());
        let store = StateStore::open(paths.clone()).expect("state store");
        let mut authority = active_standing_authority(2);
        let authority_id = authority.authority_id.clone();
        let plan = standing_token_plan_with_receipt(
            &authority,
            json!({"success":true,"resource_id":"token-concurrent-recovery"}),
        );
        reserve_standing_plan(&mut authority, &plan);
        store
            .create_authority(&authority)
            .expect("persist active authority and run reservation");
        store
            .save_plan(&plan)
            .expect("persist successful boundary receipt");
        key_policy_revoke(
            &store,
            &KeyPolicySelector {
                authority_id: authority_id.clone(),
            },
        )
        .expect("revocation commits before late reconciliation");
        let barrier = Arc::new(Barrier::new(2));
        let handles = (0..2)
            .map(|_| {
                let paths = paths.clone();
                let barrier = Arc::clone(&barrier);
                let plan = plan.clone();
                thread::spawn(move || {
                    let store = StateStore::open(paths).expect("reconciliation store");
                    barrier.wait();
                    reconcile_standing_lineage_from_plan(&store, &plan)
                })
            })
            .collect::<Vec<_>>();

        for handle in handles {
            handle
                .join()
                .expect("reconciliation thread joins")
                .expect("receipt reconciliation succeeds");
        }
        let durable = store
            .load_authority(&authority_id)
            .expect("authority reloads");
        assert_eq!(durable.status, StandingAuthorityStatus::Revoked);
        assert_eq!(durable.minted_token_ids, vec!["token-concurrent-recovery"]);
    }

    #[test]
    fn read_import_secret_requires_exactly_one_out_of_band_source() {
        let neither = read_import_secret(false, None, "API token").expect_err("no source rejected");
        let neither = neither.to_string();
        assert!(neither.contains("--stdin"), "{neither}");
        assert!(neither.contains("--value-in"), "{neither}");

        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("token");
        std::fs::write(&path, "cfat_from_file").expect("write token file");
        let both =
            read_import_secret(true, Some(&path), "API token").expect_err("two sources rejected");
        assert!(both.to_string().contains("not both"), "{both}");
    }

    #[test]
    fn force_ipv4_flag_parses_affirmative_values_only() {
        for on in ["1", "true", "yes", "on"] {
            assert!(force_ipv4_from(Some(on)), "{on} should enable IPv4");
        }
        for off in [Some("0"), Some("false"), Some(""), None] {
            assert!(!force_ipv4_from(off), "{off:?} should not enable IPv4");
        }
    }

    #[test]
    fn http_client_builds_in_both_egress_modes() {
        // Default builder is valid.
        http_client().expect("default client builds");
        // The IPv4-bound builder is also valid (binds a v4 source address).
        reqwest::Client::builder()
            .local_address(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
            .build()
            .expect("ipv4-bound client builds");
    }

    #[cfg(unix)]
    #[test]
    fn read_secret_file_reads_mode_0600_and_rejects_group_readable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("token");
        std::fs::write(&path, "cfat_from_file\n").expect("write token file");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod 600");
        let value = read_secret_file(&path).expect("read 0600 file");
        assert_eq!(value.trim(), "cfat_from_file");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).expect("chmod 640");
        let leaky = read_secret_file(&path).expect_err("group-readable rejected");
        let leaky = leaky.to_string();
        assert!(leaky.contains("group or others"), "{leaky}");
        assert!(leaky.contains("chmod 600"), "{leaky}");
    }

    #[test]
    fn approve_plan_requires_explicit_yes_on_the_store_path() {
        let root = tempfile::tempdir().expect("runtime root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
        let capability = CapabilityV1::new(
            "dns.records.update",
            "Update DNS record",
            "PUT",
            "/zones/{zone_id}/dns_records/{record_id}",
        );
        let plan = PlanV1::draft(
            "profile-a",
            "account-a",
            "catalog-sha",
            capability,
            json!({"zone_id":"zone-a","record_id":"record-a"}),
        )
        .expect("draft plan");
        let operation_id = plan.operation_id.clone();
        store.save_plan(&plan).expect("persist draft");

        let error = approve_plan(
            &store,
            &PlanApproveArgs {
                operation_id: operation_id.clone(),
                yes: false,
                max_cost: None,
            },
        )
        .expect_err("store path must refuse chat/intent without --yes");
        assert!(
            error
                .to_string()
                .contains("approval must be an explicit yes bound to the operation id"),
            "{error}"
        );
        let reloaded = store.load_plan(&operation_id).expect("plan remains draft");
        assert_eq!(reloaded.status, PlanStatus::Draft);
        assert!(reloaded.approval.is_none());
    }

    #[test]
    fn approve_plan_rejects_hash_drifted_store_draft_before_authority() {
        let root = tempfile::tempdir().expect("runtime root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
        let capability = CapabilityV1::new(
            "dns.records.update",
            "Update DNS record",
            "PUT",
            "/zones/{zone_id}/dns_records/{record_id}",
        );
        let mut plan = PlanV1::draft(
            "profile-a",
            "account-a",
            "catalog-sha",
            capability,
            json!({"zone_id":"zone-a","record_id":"record-a"}),
        )
        .expect("draft plan");
        let operation_id = plan.operation_id.clone();
        let bound_hash = plan.content_hash.clone();
        store.save_plan(&plan).expect("persist hash-bound draft");

        plan.targets = json!({"zone_id":"zone-b","record_id":"record-a"});
        assert_eq!(plan.content_hash, bound_hash);
        store
            .save_plan(&plan)
            .expect("persist drifted targets without rehash");

        let error = approve_plan(
            &store,
            &PlanApproveArgs {
                operation_id: operation_id.clone(),
                yes: true,
                max_cost: None,
            },
        )
        .expect_err("store path must refuse hash-drifted draft");
        assert!(
            error.to_string().contains("unchanged hash-bound draft"),
            "{error}"
        );
        let reloaded = store.load_plan(&operation_id).expect("still draft");
        assert_eq!(reloaded.status, PlanStatus::Draft);
        assert!(reloaded.approval.is_none());

        plan.refresh_hash()
            .expect("operator rebinds reviewed content");
        store.save_plan(&plan).expect("persist rehashed draft");
        let approved = approve_plan(
            &store,
            &PlanApproveArgs {
                operation_id: operation_id.clone(),
                yes: true,
                max_cost: None,
            },
        )
        .expect("rehashed draft may approve with explicit yes");
        assert_eq!(approved.command, "plans approve");
        assert!(approved.ok);
        let reloaded = store.load_plan(&operation_id).expect("approved plan");
        assert_eq!(reloaded.status, PlanStatus::Approved);
        assert_eq!(
            reloaded
                .approval
                .as_ref()
                .map(|approval| approval.approved_content_hash.as_str()),
            Some(reloaded.content_hash.as_str())
        );
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
    fn sink_only_verification_basis_names_the_durable_secret_receipt() {
        let mut capability = CapabilityV1::new(
            "accounts-turnstile-widget-rotate-secret",
            "Rotate Turnstile secret",
            "POST",
            "/accounts/{account_id}/challenges/widgets/{sitekey}/rotate_secret",
        );
        capability.risk = RiskClass::SecretSensitive;
        capability.verification.required = false;
        capability.verification.strategy = "sink_write_and_source_response_status".to_owned();

        assert_eq!(
            non_readback_verification_basis(&capability),
            "Cloudflare returned success and the required sink-only secret output was durably persisted"
        );
        let guide = guide_json(&capability);
        let verify = guide["stages"]
            .as_array()
            .expect("guide stages")
            .iter()
            .find(|stage| stage["name"] == "verify")
            .expect("verify stage");
        assert_eq!(verify["required"], false);
        assert_eq!(verify["contract_state"], "not_applicable");
        assert!(
            verify["summary"]
                .as_str()
                .is_some_and(|summary| summary.contains("durable sink-only secret receipt"))
        );
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
    fn oauth_client_secret_is_extracted_and_redacted_as_sink_only_material() {
        let response = json!({
            "success": true,
            "result": {
                "client_secret": "oauth-client-secret-must-not-survive",
                "client_id": "public-client-id"
            }
        });

        assert_eq!(
            find_secret_value(&response["result"]),
            Some("oauth-client-secret-must-not-survive")
        );
        let redacted = redact_secret_result(&response);
        assert_eq!(redacted["result"]["client_secret"], "[SUNK]");
        assert_eq!(redacted["result"]["client_id"], "public-client-id");
        assert!(!redacted.to_string().contains("must-not-survive"));
    }

    #[test]
    fn access_service_token_credentials_are_sunk_as_a_complete_json_bundle() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("access-service-token.json");
        let mut capability = CapabilityV1::new(
            "access-service-tokens-create-a-service-token",
            "Create a service token",
            "POST",
            "/accounts/{account_id}/access/service_tokens",
        );
        capability.product = "Access service tokens".to_owned();
        capability.permissions = vec!["Access: Service Tokens Write".to_owned()];
        capability.risk = RiskClass::SecretSensitive;
        capability.verification.strategy =
            "created_resource_contains_planned_fields_by_returned_id".to_owned();
        let plan = PlanV1::draft(
            "profile-a",
            "account-a",
            "catalog-sha",
            capability,
            json!({"adapter":{"value_out":path}}),
        )
        .expect("plan");

        let written = sink_secret_result(
            &plan,
            &json!({
                "id":"service-token-id",
                "client_id":"service-token-client-id.access",
                "client_secret":"service-token-secret-must-not-leak",
                "name":"deployment automation"
            }),
        )
        .expect("credential bundle");
        assert_eq!(written, path);
        let payload: Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("credential bundle contents"))
                .expect("credential bundle JSON");
        assert_eq!(
            payload,
            json!({
                "client_id":"service-token-client-id.access",
                "client_secret":"service-token-secret-must-not-leak"
            })
        );
        assert!(!payload.to_string().contains("service-token-id"));
        assert!(!payload.to_string().contains("deployment automation"));
        assert_eq!(
            capability_call_argv(&plan.capability)
                .iter()
                .find(|argument| argument.contains("0600"))
                .map(String::as_str),
            Some("<new-mode-0600-json-path>")
        );
        let mut risk_metadata_drift = plan.capability.clone();
        risk_metadata_drift.risk = RiskClass::Unknown;
        assert!(is_secret_output_capability(&risk_metadata_drift));
        assert_eq!(
            secret_sink_format(&risk_metadata_drift),
            Some("access_service_token_json")
        );
        assert_eq!(
            capability_call_argv(&risk_metadata_drift)
                .iter()
                .find(|argument| argument.contains("0600"))
                .map(String::as_str),
            Some("<new-mode-0600-json-path>")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path)
                    .expect("credential bundle metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn zone_access_service_token_credentials_use_the_complete_json_sink_despite_risk_drift() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("zone-access-service-token.json");
        let mut capability = CapabilityV1::new(
            "zone-level-access-service-tokens-create-a-service-token",
            "Create a service token",
            "POST",
            "/zones/{zone_id}/access/service_tokens",
        );
        capability.product = "Zone-Level Access service tokens".to_owned();
        capability.permissions = vec!["Access: Service Tokens Write".to_owned()];
        capability.risk = RiskClass::Unknown;
        capability.verification.strategy =
            "created_resource_contains_planned_fields_by_returned_id".to_owned();
        let plan = PlanV1::draft(
            "profile-a",
            "account-a",
            "catalog-sha",
            capability,
            json!({"adapter":{"value_out":path}}),
        )
        .expect("plan");

        let written = sink_secret_result(
            &plan,
            &json!({
                "id":"zone-service-token-id",
                "client_id":"zone-service-token-client-id.access",
                "client_secret":"zone-service-token-secret-must-not-leak",
                "name":"zone deployment automation"
            }),
        )
        .expect("zone credential bundle");
        assert_eq!(written, path);
        let payload: Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("credential bundle contents"))
                .expect("credential bundle JSON");
        assert_eq!(
            payload,
            json!({
                "client_id":"zone-service-token-client-id.access",
                "client_secret":"zone-service-token-secret-must-not-leak"
            })
        );
        assert_eq!(
            secret_sink_format(&plan.capability),
            Some("access_service_token_json")
        );
        assert_eq!(
            capability_call_argv(&plan.capability)
                .iter()
                .find(|argument| argument.contains("0600"))
                .map(String::as_str),
            Some("<new-mode-0600-json-path>")
        );
    }

    #[test]
    fn access_service_token_sink_rejects_incomplete_credentials_before_file_creation() {
        for result in [
            json!({"client_id":"service-token-client-id.access"}),
            json!({"client_secret":"service-token-secret"}),
            json!({"client_id":"","client_secret":"service-token-secret"}),
        ] {
            let directory = tempfile::tempdir().expect("temporary directory");
            let path = directory.path().join("access-service-token.json");
            let mut capability = CapabilityV1::new(
                "access-service-tokens-create-a-service-token",
                "Create a service token",
                "POST",
                "/accounts/{account_id}/access/service_tokens",
            );
            capability.product = "Access service tokens".to_owned();
            capability.permissions = vec!["Access: Service Tokens Write".to_owned()];
            capability.risk = RiskClass::SecretSensitive;
            capability.verification.strategy =
                "created_resource_contains_planned_fields_by_returned_id".to_owned();
            let plan = PlanV1::draft(
                "profile-a",
                "account-a",
                "catalog-sha",
                capability,
                json!({"adapter":{"value_out":path}}),
            )
            .expect("plan");

            assert!(sink_secret_result(&plan, &result).is_err());
            assert!(!path.exists());
        }
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

        let request = compensation_request(&plan)
            .expect("request resolves")
            .expect("compensation is supported");

        assert_eq!(request.capability_id, "account-api-tokens-delete-token");
        assert_eq!(request.expected_method, "DELETE");
        assert_eq!(request.input.selectors["account_id"], "account-a");
        assert_eq!(request.input.selectors["token_id"], "token-id");
        assert_eq!(request.requested_account.as_deref(), Some("account-a"));
    }

    #[test]
    fn dns_record_creation_rectification_builds_a_separate_delete_request() {
        let mut capability = CapabilityV1::new(
            "dns-records-for-a-zone-create-dns-record",
            "Create DNS record",
            "POST",
            "/zones/{zone_id}/dns_records",
        );
        capability.rollback.supported = true;
        capability.rollback.strategy = Some("delete_created_dns_record_by_returned_id".to_owned());
        let mut plan = PlanV1::draft(
            "profile-a",
            "account-a",
            "catalog-sha",
            capability,
            json!({"zone_id":"zone-a"}),
        )
        .expect("plan");
        plan.input = serde_json::to_value(CallInput {
            selectors: json!({"zone_id":"zone-a"}),
            query: json!({}),
            body: Some(json!({"type":"A","name":"www.example.com","content":"192.0.2.1"})),
            ..CallInput::default()
        })
        .expect("call input");
        plan.refresh_hash().expect("bind call input");
        plan.approve(true, None).expect("approve");
        plan.mark_consumed().expect("consume");
        plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
            .expect("attempt");
        plan.record_transaction_stage_with_artifact(
            TransactionStageV1::BoundaryResponsePersisted,
            json!({"resource_id":"record-id","success":true}),
        )
        .expect("response receipt");
        plan.status = PlanStatus::RectificationRequired;

        let request = compensation_request(&plan)
            .expect("request resolves")
            .expect("compensation is supported");

        assert_eq!(
            request.capability_id,
            "dns-records-for-a-zone-delete-dns-record"
        );
        assert_eq!(request.input.selectors["zone_id"], "zone-a");
        assert_eq!(request.input.selectors["dns_record_id"], "record-id");
        assert_eq!(request.requested_account.as_deref(), Some("account-a"));
    }

    #[test]
    fn generic_creation_rectification_uses_only_the_hash_bound_resource_target_and_receipt() {
        let mut capability = CapabilityV1::new(
            "widgets-create",
            "Create Widget",
            "POST",
            "/accounts/{account_id}/widgets",
        );
        capability.rollback.supported = true;
        capability.rollback.strategy = Some("delete_created_resource_by_returned_id".to_owned());
        capability.created_resource = Some(CreatedResourceContractV1 {
            detail_path: "/accounts/{account_id}/widgets/{slug}".to_owned(),
            identity_selector: "slug".to_owned(),
            response_result_identity_pointer: "/slug".to_owned(),
            read_capability_id: "widgets-get".to_owned(),
            delete_capability_id: "widgets-delete".to_owned(),
            verified_response_fields: vec!["name".to_owned()],
        });
        let mut plan = PlanV1::draft(
            "profile-a",
            "account-a",
            "catalog-sha",
            capability,
            json!({}),
        )
        .expect("plan");
        plan.input = serde_json::to_value(CallInput {
            selectors: json!({"account_id":"account-a"}),
            query: json!({"mutation_mode":"secret-like-query"}),
            body: Some(json!({"name":"secret-like-widget"})),
            if_match: Some("mutation-etag".to_owned()),
            ..CallInput::default()
        })
        .expect("call input");
        plan.refresh_hash().expect("bind call input");
        plan.approve(true, None).expect("approve");
        plan.mark_consumed().expect("consume");
        plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
            .expect("attempt");
        let response = CloudflareResponseV1 {
            status: 201,
            success: true,
            result: json!({"slug":"widget-one","name":"secret-like-widget"}),
            errors: Vec::new(),
            result_info: None,
            etag: None,
            cf_ray: None,
        };
        let apply_evidence = EvidenceV1::new(
            EvidenceClass::Apply,
            "sha256:apply-receipt",
            "/tmp/apply-receipt.json",
        );
        plan.record_transaction_stage_with_artifact(
            TransactionStageV1::BoundaryResponsePersisted,
            boundary_response_artifact(&plan, &response, Some(&apply_evidence)),
        )
        .expect("response receipt");
        plan.status = PlanStatus::RectificationRequired;

        let mut request = compensation_request(&plan)
            .expect("request resolves")
            .expect("compensation is supported");

        assert_eq!(request.capability_id, "widgets-delete");
        assert_eq!(request.expected_method, "DELETE");
        assert_eq!(
            request.expected_path,
            "/accounts/{account_id}/widgets/{slug}"
        );
        assert_eq!(request.input.selectors["account_id"], "account-a");
        assert_eq!(request.input.selectors["slug"], "widget-one");
        assert_eq!(request.input.query, json!({}));
        assert!(request.input.body.is_none());
        assert!(request.input.if_match.is_none());
        assert!(request.input.if_none_match.is_none());
        assert_eq!(request.requested_account.as_deref(), Some("account-a"));

        let mut delete_capability = CapabilityV1::new(
            "widgets-delete",
            "Delete Widget",
            "DELETE",
            "/accounts/{account_id}/widgets/{slug}",
        );
        delete_capability.request_schema = Some(json!({
            "type":"object",
            "properties":{},
            "additionalProperties":false,
            "x-cfctl-body-required":true
        }));
        bind_required_empty_compensation_body(&mut request, &delete_capability);
        assert_eq!(request.input.body, Some(json!({})));
    }

    #[test]
    fn r2_bucket_creation_rectification_preserves_jurisdiction_for_exact_empty_bucket_delete() {
        let mut capability = CapabilityV1::new(
            "r2-create-bucket",
            "Create Bucket",
            "POST",
            "/accounts/{account_id}/r2/buckets",
        );
        capability.product = "R2 Bucket".to_owned();
        capability.rollback.supported = true;
        capability.rollback.strategy = Some("delete_created_resource_by_returned_id".to_owned());
        capability.created_resource = Some(CreatedResourceContractV1 {
            detail_path: "/accounts/{account_id}/r2/buckets/{bucket_name}".to_owned(),
            identity_selector: "bucket_name".to_owned(),
            response_result_identity_pointer: "/name".to_owned(),
            read_capability_id: "r2-get-bucket".to_owned(),
            delete_capability_id: "r2-delete-bucket".to_owned(),
            verified_response_fields: vec!["name".to_owned()],
        });
        let mut plan = PlanV1::draft(
            "profile-a",
            "account-a",
            "catalog-sha",
            capability,
            json!({}),
        )
        .expect("plan");
        plan.input = serde_json::to_value(CallInput {
            selectors: json!({
                "account_id":"account-a",
                "cf-r2-jurisdiction":"eu"
            }),
            query: json!({}),
            body: Some(json!({
                "name":"smoke-bucket",
                "locationHint":"weur",
                "storageClass":"InfrequentAccess"
            })),
            ..CallInput::default()
        })
        .expect("call input");
        plan.refresh_hash().expect("bind call input");
        plan.approve(true, None).expect("approve");
        plan.mark_consumed().expect("consume");
        plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
            .expect("attempt");
        let response = CloudflareResponseV1 {
            status: 200,
            success: true,
            result: json!({"name":"smoke-bucket"}),
            errors: Vec::new(),
            result_info: None,
            etag: None,
            cf_ray: None,
        };
        let apply_evidence = EvidenceV1::new(
            EvidenceClass::Apply,
            "sha256:r2-create-apply-receipt",
            "/tmp/r2-create-apply-receipt.json",
        );
        plan.record_transaction_stage_with_artifact(
            TransactionStageV1::BoundaryResponsePersisted,
            boundary_response_artifact(&plan, &response, Some(&apply_evidence)),
        )
        .expect("response receipt");
        plan.status = PlanStatus::RectificationRequired;

        let request = compensation_request(&plan)
            .expect("request resolves")
            .expect("compensation is supported");

        assert_eq!(request.capability_id, "r2-delete-bucket");
        assert_eq!(request.expected_method, "DELETE");
        assert_eq!(
            request.expected_path,
            "/accounts/{account_id}/r2/buckets/{bucket_name}"
        );
        assert_eq!(request.input.selectors["account_id"], "account-a");
        assert_eq!(request.input.selectors["bucket_name"], "smoke-bucket");
        assert_eq!(request.input.selectors["cf-r2-jurisdiction"], "eu");
        assert_eq!(request.input.query, json!({}));
        assert!(request.input.body.is_none());
        assert_eq!(request.requested_account.as_deref(), Some("account-a"));
    }

    #[test]
    fn d1_creation_rectification_derives_only_the_guarded_uuid_delete_target() {
        let capability = d1_database_create_capability();
        let mut plan = PlanV1::draft(
            "profile-a",
            "account-a",
            "catalog-sha",
            capability,
            json!({}),
        )
        .expect("plan");
        plan.input = serde_json::to_value(CallInput {
            selectors: json!({"account_id":"account-a"}),
            body: Some(json!({"name":"smoke-database","jurisdiction":"eu"})),
            ..CallInput::default()
        })
        .expect("call input");
        plan.refresh_hash().expect("bind call input");
        plan.approve(true, None).expect("approve");
        plan.mark_consumed().expect("consume");
        plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
            .expect("attempt");
        plan.record_transaction_stage_with_artifact(
            TransactionStageV1::BoundaryResponsePersisted,
            json!({"resource_id":"database-a","success":true}),
        )
        .expect("response receipt");
        plan.status = PlanStatus::RectificationRequired;

        let request = compensation_request(&plan)
            .expect("request resolves")
            .expect("guarded D1 compensation is supported");
        assert_eq!(request.capability_id, "d1-delete-database");
        assert_eq!(request.expected_method, "DELETE");
        assert_eq!(
            request.expected_path,
            "/accounts/{account_id}/d1/database/{database_id}"
        );
        assert_eq!(request.input.selectors["account_id"], "account-a");
        assert_eq!(request.input.selectors["database_id"], "database-a");
        assert!(request.input.body.is_none());
        assert_eq!(request.requested_account.as_deref(), Some("account-a"));
    }

    #[test]
    fn collection_backed_creation_rectification_builds_an_exact_hash_bound_delete() {
        let mut capability = CapabilityV1::new(
            "widgets-create",
            "Create Widget",
            "POST",
            "/accounts/{account_id}/widgets",
        );
        capability.rollback.supported = true;
        capability.rollback.strategy = Some("delete_created_resource_by_returned_id".to_owned());
        capability.created_collection_resource = Some(CreatedCollectionResourceContractV1 {
            collection_path: "/accounts/{account_id}/widgets".to_owned(),
            identity_selector: "widget_id".to_owned(),
            response_result_identity_pointer: "/id".to_owned(),
            response_item_identity_pointer: "/id".to_owned(),
            read_capability_id: "widgets-list".to_owned(),
            delete_capability_id: "widgets-delete".to_owned(),
            verified_response_fields: vec!["name".to_owned()],
            requires_page_number_completion: true,
        });
        let mut plan = PlanV1::draft(
            "profile-a",
            "account-a",
            "catalog-sha",
            capability,
            json!({}),
        )
        .expect("plan");
        plan.input = serde_json::to_value(CallInput {
            selectors: json!({"account_id":"account-a"}),
            query: json!({"mutation_mode":"secret-like-query"}),
            body: Some(json!({"name":"secret-like-widget"})),
            if_match: Some("mutation-etag".to_owned()),
            ..CallInput::default()
        })
        .expect("call input");
        plan.refresh_hash().expect("bind call input");
        plan.approve(true, None).expect("approve");
        plan.mark_consumed().expect("consume");
        plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
            .expect("attempt");
        plan.record_transaction_stage_with_artifact(
            TransactionStageV1::BoundaryResponsePersisted,
            json!({"resource_id":"widget-id","success":true}),
        )
        .expect("response receipt");
        plan.status = PlanStatus::RectificationRequired;

        let request = compensation_request(&plan)
            .expect("request resolves")
            .expect("compensation is supported");

        assert_eq!(request.capability_id, "widgets-delete");
        assert_eq!(
            request.expected_path,
            "/accounts/{account_id}/widgets/{widget_id}"
        );
        assert_eq!(request.input.selectors["account_id"], "account-a");
        assert_eq!(request.input.selectors["widget_id"], "widget-id");
        assert_eq!(request.input.query, json!({}));
        assert!(request.input.body.is_none());
        assert!(request.input.if_match.is_none());
        assert!(request.input.if_none_match.is_none());
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
