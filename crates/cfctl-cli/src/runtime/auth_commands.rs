use super::call_input::parse_callback;
use super::credential_resolution::describe_secret_backend;
use super::credential_resolution::oauth_scope_inventory_hash;
use super::credential_resolution::platform_secrets;
use super::credential_resolution::resolve_login_scopes;
use super::evidence_key_commands::evidence_key_command;
use super::prelude::{
    AuthCommand, AuthLoginArgs, CliError, ImportApiTokenArgs, ImportGlobalKeyArgs,
    OAuthClientConfig, PendingLogin, PkceSession, ProfileKind, ProfileMetadata, ProfileSelector,
    ProfilesConfig, Result, ResultEnvelopeV2, SecretStore, StateStore, Write, json,
};
use super::support::http_client;
use super::support::read_import_secret;
use super::support::read_stdin;
use crate::profiles::ensure_supported_profile;
use cfctl_auth::{exchange_authorization_code, revoke_oauth_token};

pub(super) async fn auth_command(
    store: &StateStore,
    command: AuthCommand,
) -> Result<ResultEnvelopeV2> {
    let command = match command {
        AuthCommand::EvidenceKey(arguments) => {
            return evidence_key_command(store, arguments.command);
        }
        command => command,
    };
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
        AuthCommand::RepairKeychainAccess(selector) => {
            repair_keychain_access(&profiles, &secrets, &selector)
        }
        AuthCommand::Logout(selector) => {
            logout_profile(store, &mut profiles, &secrets, &selector).await
        }
        AuthCommand::ImportApiToken(arguments) => {
            import_api_token(store, &mut profiles, &secrets, &arguments)
        }
        AuthCommand::ImportGlobalKey(arguments) => {
            import_global_key(store, &mut profiles, &secrets, &arguments)
        }
        AuthCommand::EvidenceKey(_) => unreachable!("matched before profile loading"),
    }
}

pub(super) fn require_oauth_client_id(client_id: Option<&str>) -> Result<&str> {
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

pub(super) async fn begin_oauth_login(
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

pub(super) async fn complete_oauth_login(
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
    let mut profile = ProfileMetadata::new(
        &arguments.profile,
        ProfileKind::OAuth,
        pending.account_id.as_deref(),
    );
    profile.oauth_client_id = Some(pending.client.client_id);
    profile.oauth_scopes = tokens.scopes().into_iter().map(str::to_owned).collect();
    profile.oauth_scope_inventory_hash = oauth_scope_inventory_hash(store)?;
    mark_credential_install_pending(store, profiles, &profile, true)?;
    secrets.store_oauth_tokens(&arguments.profile, &tokens)?;
    profiles.profiles.insert(arguments.profile.clone(), profile);
    profiles.current_profile = Some(arguments.profile.clone());
    profiles.pending_logins.remove(&arguments.profile);
    profiles.save(store)?;
    secrets.delete(&verifier_key)?;
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

pub(super) fn auth_status(
    profiles: &ProfilesConfig,
    secrets: &dyn SecretStore,
    selector: &ProfileSelector,
) -> Result<ResultEnvelopeV2> {
    let profile = profiles
        .profiles
        .get(&selector.profile)
        .ok_or_else(|| CliError::Input(format!("profile `{}` does not exist", selector.profile)))?;
    ensure_supported_profile(profile)?;
    let credential_available = secrets.load_profile_credential(profile).is_ok();
    Ok(ResultEnvelopeV2::success(
        "auth status",
        json!({"profile": profile, "credential_available": credential_available, "selected": profiles.current_profile.as_deref() == Some(&profile.id)}),
    ))
}

pub(super) fn repair_keychain_access(
    profiles: &ProfilesConfig,
    secrets: &dyn SecretStore,
    selector: &ProfileSelector,
) -> Result<ResultEnvelopeV2> {
    let mut warnings = std::io::stderr().lock();
    repair_keychain_access_with_warning(profiles, secrets, selector, &mut warnings)
}

pub(super) const KEYCHAIN_REPAIR_WARNING: &str = "warning: this explicit repair may open macOS Keychain for the selected profile; cancel the system prompt to stop without changing the credential\n";

pub(super) fn repair_keychain_access_with_warning(
    profiles: &ProfilesConfig,
    secrets: &dyn SecretStore,
    selector: &ProfileSelector,
    warnings: &mut dyn Write,
) -> Result<ResultEnvelopeV2> {
    let profile = profiles
        .profiles
        .get(&selector.profile)
        .ok_or_else(|| CliError::Input(format!("profile `{}` does not exist", selector.profile)))?;
    ensure_supported_profile(profile)?;
    warnings
        .write_all(KEYCHAIN_REPAIR_WARNING.as_bytes())
        .map_err(|source| CliError::Io {
            path: "stderr".to_owned(),
            source,
        })?;
    secrets.repair_profile_credential_access(profile)?;
    let backend = secrets.locate_profile_credential(profile)?;
    Ok(ResultEnvelopeV2::success(
        "auth repair-keychain-access",
        json!({
            "profile": profile.id,
            "credential_available": true,
            "backend": backend,
            "message": "The opaque credential was rewritten without disclosure using the unattended platform-reader access contract."
        }),
    ))
}

pub(super) fn use_profile(
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

pub(super) async fn logout_profile(
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
        let tokens = secrets.load_profile_oauth_tokens(profile)?;
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

pub(super) fn import_api_token(
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

pub(super) fn store_imported_api_token(
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
    let profile = ProfileMetadata::new(profile_id, ProfileKind::ApiToken, Some(account));
    mark_credential_install_pending(store, profiles, &profile, true)?;
    secrets.store_api_token(profile_id, token)?;
    let (secret_backend, storage_note) =
        describe_secret_backend(secrets.locate_api_token(profile_id)?);
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

pub(super) fn import_global_key(
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
    let profile = ProfileMetadata::new(&arguments.profile, ProfileKind::GlobalKey, None);
    mark_credential_install_pending(store, profiles, &profile, false)?;
    secrets.store_global_key(&arguments.profile, &arguments.email, &key)?;
    let (secret_backend, storage_note) =
        describe_secret_backend(secrets.locate_global_key(&arguments.profile)?);
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

pub(super) fn mark_credential_install_pending(
    store: &StateStore,
    profiles: &mut ProfilesConfig,
    complete_profile: &ProfileMetadata,
    select: bool,
) -> Result<()> {
    let mut pending_profile = complete_profile.clone();
    pending_profile.credential_generation_id = None;
    profiles
        .profiles
        .insert(pending_profile.id.clone(), pending_profile);
    if select {
        profiles.current_profile = Some(complete_profile.id.clone());
    }
    profiles.save(store)
}
