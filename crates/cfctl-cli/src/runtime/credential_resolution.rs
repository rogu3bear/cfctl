use super::catalog_commands::sync_catalog;
use super::cloudflare_api::BASE_URL as API_BASE_URL;
use super::prelude::{
    AuthCredential, CatalogSnapshot, CliError, OAuthClientConfig, PathBuf, PlatformSecretStore,
    ProfileKind, ProfileMetadata, ProfilesConfig, Result, SecretBackend, SecretStore, StateStore,
    Utc, Value, json,
};
use super::support::catalog_is_stale;
use super::support::http_client;
use cfctl_auth::refresh_oauth_tokens;
use cfctl_core::hash_value;

pub(super) fn platform_secrets(store: &StateStore) -> PlatformSecretStore {
    let root = store.paths().data_dir.join("auth").join("secrets");
    if store.private_origin().is_some() {
        return PlatformSecretStore::private_only(
            root.clone(),
            std::sync::Arc::new(cfctl_storage::PrivateFileSecretStore::new(root)),
        );
    }
    PlatformSecretStore::new(root)
}

pub(super) fn describe_secret_backend(
    backend: Option<SecretBackend>,
) -> (&'static str, &'static str) {
    match backend {
        Some(SecretBackend::PlatformKeyring) => {
            ("platform_keyring", "in the platform credential store")
        }
        Some(SecretBackend::FallbackFile) => (
            "fallback_file",
            "in cfctl's mode-0600 file secret store because the platform keyring is unavailable (see `cfctl doctor`)",
        ),
        Some(SecretBackend::PrivateFile) => (
            "private_file",
            "in the explicitly selected private local credential store",
        ),
        Some(SecretBackend::Memory) => ("memory", "in the in-process secret store"),
        None => ("unknown", "in an undetermined backend"),
    }
}

pub(super) async fn ensure_catalog(store: &StateStore) -> Result<CatalogSnapshot> {
    if !store.paths().catalog_file().is_file() || catalog_is_stale(store) {
        let _receipt = sync_catalog(store).await?;
    }
    Ok(CatalogSnapshot::load(&store.paths().catalog_file())?)
}

pub(super) async fn resolve_login_scopes(
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

pub(super) async fn fresh_credential(
    profile: &ProfileMetadata,
    secrets: &dyn SecretStore,
) -> Result<AuthCredential> {
    if profile.kind != ProfileKind::OAuth {
        return Ok(secrets.load_profile_credential(profile)?);
    }
    let tokens = secrets.load_profile_oauth_tokens(profile)?;
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

pub(super) async fn refresh_oauth_scopes_if_authenticated(
    store: &StateStore,
) -> Result<Option<Value>> {
    let profiles = ProfilesConfig::load(store)?;
    let Ok(profile) = profiles.selected(None) else {
        return Ok(None);
    };
    let credential = fresh_credential(profile, &platform_secrets(store)).await?;
    let snapshot = fetch_oauth_scope_snapshot(&credential).await?;
    store.write_json(&oauth_scope_inventory_file(store), &snapshot)?;
    Ok(Some(snapshot))
}

pub(super) async fn fetch_oauth_scope_snapshot(credential: &AuthCredential) -> Result<Value> {
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

pub(super) fn oauth_scope_ids(snapshot: &Value) -> Result<Vec<String>> {
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

pub(super) fn oauth_scope_inventory_hash(store: &StateStore) -> Result<Option<String>> {
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

pub(super) fn oauth_scope_inventory_file(store: &StateStore) -> PathBuf {
    store.paths().data_dir.join("auth/oauth-scopes-v1.json")
}
