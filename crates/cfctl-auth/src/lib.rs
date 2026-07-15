//! OAuth, profile, account selection, and secret-store contracts.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{Rng as _, distr::Alphanumeric};
use std::{collections::BTreeMap, fmt, sync::Mutex};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

pub const CLOUDFLARE_AUTHORIZATION_ENDPOINT: &str = "https://dash.cloudflare.com/oauth2/auth";
pub const CLOUDFLARE_TOKEN_ENDPOINT: &str = "https://dash.cloudflare.com/oauth2/token";
pub const CLOUDFLARE_REVOKE_ENDPOINT: &str = "https://dash.cloudflare.com/oauth2/revoke";
pub const CFCTL_CALLBACK_URL: &str = "https://cfctl.io/oauth/callback";

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("failed to construct OAuth URL: {0}")]
    Url(#[from] url::ParseError),
    #[error("no Cloudflare accounts are available to this profile")]
    NoAccounts,
    #[error("account selection is ambiguous across {count} accounts")]
    AmbiguousAccount { count: usize },
    #[error("Cloudflare account `{0}` was not found")]
    AccountNotFound(String),
    #[error("OAuth HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("OAuth token response is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("secret store failed: {0}")]
    SecretStore(String),
    #[error("profile `{0}` has no stored credential")]
    MissingCredential(String),
    #[error(
        "legacy Wrangler session profile `{0}` is no longer supported; run `cfctl auth logout {0}` to remove its metadata, then `cfctl auth login --profile {0}`"
    )]
    UnsupportedLegacyWranglerSession(String),
}

pub type Result<T> = std::result::Result<T, AuthError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthClientConfig {
    pub client_id: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub revoke_endpoint: String,
    pub redirect_uri: String,
}

impl OAuthClientConfig {
    #[must_use]
    pub fn cfctl_public(client_id: &str) -> Self {
        Self {
            client_id: client_id.to_owned(),
            authorization_endpoint: CLOUDFLARE_AUTHORIZATION_ENDPOINT.to_owned(),
            token_endpoint: CLOUDFLARE_TOKEN_ENDPOINT.to_owned(),
            revoke_endpoint: CLOUDFLARE_REVOKE_ENDPOINT.to_owned(),
            redirect_uri: CFCTL_CALLBACK_URL.to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkceSession {
    pub authorization_url: Url,
    pub code_verifier: String,
    pub state: String,
}

impl PkceSession {
    pub fn begin(config: &OAuthClientConfig, scopes: &[&str]) -> Result<Self> {
        let verifier: String = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let state = Uuid::new_v4().to_string();
        let mut authorization_url = Url::parse(&config.authorization_endpoint)?;
        authorization_url
            .query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &config.client_id)
            .append_pair("redirect_uri", &config.redirect_uri)
            .append_pair("scope", &scopes.join(" "))
            .append_pair("state", &state)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        Ok(Self {
            authorization_url,
            code_verifier: verifier,
            state,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountRef {
    pub id: String,
    pub name: String,
}

impl AccountRef {
    #[must_use]
    pub fn new(id: &str, name: &str) -> Self {
        Self {
            id: id.to_owned(),
            name: name.to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AccountSelectionError {
    #[error("no Cloudflare accounts are available")]
    NoneAvailable,
    #[error("account selection is ambiguous across {count} accounts")]
    Ambiguous { count: usize },
    #[error("requested account `{id}` was not found")]
    NotFound { id: String },
}

pub fn resolve_account<'a>(
    accounts: &'a [AccountRef],
    explicit_id: Option<&str>,
    pinned_id: Option<&str>,
) -> std::result::Result<&'a AccountRef, AccountSelectionError> {
    if accounts.is_empty() {
        return Err(AccountSelectionError::NoneAvailable);
    }
    if let Some(id) = explicit_id.or(pinned_id) {
        return accounts
            .iter()
            .find(|account| account.id == id)
            .ok_or_else(|| AccountSelectionError::NotFound { id: id.to_owned() });
    }
    if accounts.len() == 1 {
        return accounts.first().ok_or(AccountSelectionError::NoneAvailable);
    }
    Err(AccountSelectionError::Ambiguous {
        count: accounts.len(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileKind {
    OAuth,
    ApiToken,
    #[serde(rename = "wrangler_session")]
    LegacyWranglerSession,
    GlobalKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileMetadata {
    pub schema_version: u8,
    pub id: String,
    pub kind: ProfileKind,
    pub account_id: Option<String>,
    pub oauth_client_id: Option<String>,
    #[serde(default)]
    pub oauth_scopes: Vec<String>,
    #[serde(default)]
    pub oauth_scope_inventory_hash: Option<String>,
    pub emergency_only: bool,
}

impl ProfileMetadata {
    #[must_use]
    pub fn new(id: &str, kind: ProfileKind, account_id: Option<&str>) -> Self {
        Self {
            schema_version: 1,
            id: id.to_owned(),
            kind,
            account_id: account_id.map(str::to_owned),
            oauth_client_id: None,
            oauth_scopes: Vec::new(),
            oauth_scope_inventory_hash: None,
            emergency_only: kind == ProfileKind::GlobalKey,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OAuthTokenSet {
    access_token: String,
    refresh_token: Option<String>,
    token_type: String,
    expires_in: Option<i64>,
    expires_at: Option<DateTime<Utc>>,
    scope: Option<String>,
}

impl OAuthTokenSet {
    pub fn from_json(encoded: &str) -> Result<Self> {
        let mut tokens: Self = serde_json::from_str(encoded)?;
        tokens.set_expiry();
        Ok(tokens)
    }

    #[must_use]
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    #[must_use]
    pub fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_deref()
    }

    #[must_use]
    pub fn scopes(&self) -> Vec<&str> {
        self.scope
            .as_deref()
            .map(|scope| scope.split_whitespace().collect())
            .unwrap_or_default()
    }

    #[must_use]
    pub fn expires_at(&self) -> Option<DateTime<Utc>> {
        self.expires_at
    }

    #[must_use]
    pub fn needs_refresh(&self) -> bool {
        self.expires_at
            .is_some_and(|expires_at| expires_at <= Utc::now() + Duration::seconds(60))
    }

    fn set_expiry(&mut self) {
        if self.expires_at.is_none() {
            self.expires_at = self
                .expires_in
                .map(|seconds| Utc::now() + Duration::seconds(seconds));
        }
    }
}

impl fmt::Debug for OAuthTokenSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthTokenSet")
            .field("access_token", &"[REDACTED]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("expires_at", &self.expires_at)
            .field("scope", &self.scope)
            .finish()
    }
}

#[derive(Clone)]
pub enum AuthCredential {
    Bearer { token: String },
    GlobalKey { email: String, key: String },
}

impl AuthCredential {
    #[must_use]
    pub fn bearer_token(&self) -> Option<&str> {
        match self {
            Self::Bearer { token } => Some(token),
            Self::GlobalKey { .. } => None,
        }
    }

    #[must_use]
    pub fn global_email(&self) -> Option<&str> {
        match self {
            Self::GlobalKey { email, .. } => Some(email),
            Self::Bearer { .. } => None,
        }
    }

    #[must_use]
    pub fn global_key(&self) -> Option<&str> {
        match self {
            Self::GlobalKey { key, .. } => Some(key),
            Self::Bearer { .. } => None,
        }
    }
}

impl fmt::Debug for AuthCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bearer { .. } => formatter
                .debug_struct("Bearer")
                .field("token", &"[REDACTED]")
                .finish(),
            Self::GlobalKey { email, .. } => formatter
                .debug_struct("GlobalKey")
                .field("email", email)
                .field("key", &"[REDACTED]")
                .finish(),
        }
    }
}

pub trait SecretStore: Send + Sync {
    fn put(&self, key: &str, value: &str) -> Result<()>;
    fn get(&self, key: &str) -> Result<Option<String>>;
    fn delete(&self, key: &str) -> Result<()>;

    fn store_oauth_tokens(&self, profile_id: &str, tokens: &OAuthTokenSet) -> Result<()> {
        let encoded = serde_json::to_string(tokens)?;
        self.put(&oauth_key(profile_id), &encoded)
    }

    fn load_oauth_tokens(&self, profile_id: &str) -> Result<OAuthTokenSet> {
        let encoded = self
            .get(&oauth_key(profile_id))?
            .ok_or_else(|| AuthError::MissingCredential(profile_id.to_owned()))?;
        OAuthTokenSet::from_json(&encoded)
    }

    fn store_api_token(&self, profile_id: &str, token: &str) -> Result<()> {
        self.put(&api_token_key(profile_id), token)
    }

    fn store_global_key(&self, profile_id: &str, email: &str, key: &str) -> Result<()> {
        let encoded = serde_json::to_string(&GlobalKeyRecord {
            email: email.to_owned(),
            key: key.to_owned(),
        })?;
        self.put(&global_key(profile_id), &encoded)
    }

    fn load_credential(&self, profile_id: &str, kind: ProfileKind) -> Result<AuthCredential> {
        match kind {
            ProfileKind::OAuth => {
                let encoded = self
                    .get(&oauth_key(profile_id))?
                    .ok_or_else(|| AuthError::MissingCredential(profile_id.to_owned()))?;
                let tokens = OAuthTokenSet::from_json(&encoded)?;
                Ok(AuthCredential::Bearer {
                    token: tokens.access_token,
                })
            }
            ProfileKind::ApiToken => self
                .get(&api_token_key(profile_id))?
                .map(|token| AuthCredential::Bearer { token })
                .ok_or_else(|| AuthError::MissingCredential(profile_id.to_owned())),
            ProfileKind::LegacyWranglerSession => Err(AuthError::UnsupportedLegacyWranglerSession(
                profile_id.to_owned(),
            )),
            ProfileKind::GlobalKey => {
                let encoded = self
                    .get(&global_key(profile_id))?
                    .ok_or_else(|| AuthError::MissingCredential(profile_id.to_owned()))?;
                let record: GlobalKeyRecord = serde_json::from_str(&encoded)?;
                Ok(AuthCredential::GlobalKey {
                    email: record.email,
                    key: record.key,
                })
            }
        }
    }

    fn delete_profile(&self, profile_id: &str) -> Result<()> {
        self.delete(&oauth_key(profile_id))?;
        self.delete(&api_token_key(profile_id))?;
        self.delete(&global_key(profile_id))
    }
}

#[derive(Default)]
pub struct MemorySecretStore {
    values: Mutex<BTreeMap<String, String>>,
}

impl SecretStore for MemorySecretStore {
    fn put(&self, key: &str, value: &str) -> Result<()> {
        self.values
            .lock()
            .map_err(|_| AuthError::SecretStore("memory secret store lock is poisoned".to_owned()))?
            .insert(key.to_owned(), value.to_owned());
        Ok(())
    }

    fn get(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .values
            .lock()
            .map_err(|_| AuthError::SecretStore("memory secret store lock is poisoned".to_owned()))?
            .get(key)
            .cloned())
    }

    fn delete(&self, key: &str) -> Result<()> {
        self.values
            .lock()
            .map_err(|_| AuthError::SecretStore("memory secret store lock is poisoned".to_owned()))?
            .remove(key);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PlatformSecretStore;

impl SecretStore for PlatformSecretStore {
    fn put(&self, key: &str, value: &str) -> Result<()> {
        let entry = keyring::Entry::new("io.cfctl.cfctl", key)
            .map_err(|error| AuthError::SecretStore(error.to_string()))?;
        entry
            .set_password(value)
            .map_err(|error| AuthError::SecretStore(error.to_string()))
    }

    fn get(&self, key: &str) -> Result<Option<String>> {
        let entry = keyring::Entry::new("io.cfctl.cfctl", key)
            .map_err(|error| AuthError::SecretStore(error.to_string()))?;
        match entry.get_password() {
            Ok(value) => Ok(Some(value)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(AuthError::SecretStore(error.to_string())),
        }
    }

    fn delete(&self, key: &str) -> Result<()> {
        let entry = keyring::Entry::new("io.cfctl.cfctl", key)
            .map_err(|error| AuthError::SecretStore(error.to_string()))?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(AuthError::SecretStore(error.to_string())),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct GlobalKeyRecord {
    email: String,
    key: String,
}

fn oauth_key(profile_id: &str) -> String {
    format!("profile/{profile_id}/oauth")
}

fn api_token_key(profile_id: &str) -> String {
    format!("profile/{profile_id}/api-token")
}

fn global_key(profile_id: &str) -> String {
    format!("profile/{profile_id}/global-key")
}

pub async fn exchange_authorization_code(
    client: &reqwest::Client,
    config: &OAuthClientConfig,
    code: &str,
    verifier: &str,
) -> Result<OAuthTokenSet> {
    let response = client
        .post(&config.token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", config.client_id.as_str()),
            ("redirect_uri", config.redirect_uri.as_str()),
            ("code", code),
            ("code_verifier", verifier),
        ])
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    OAuthTokenSet::from_json(&response)
}

pub async fn refresh_oauth_tokens(
    client: &reqwest::Client,
    config: &OAuthClientConfig,
    refresh_token: &str,
) -> Result<OAuthTokenSet> {
    let response = client
        .post(&config.token_endpoint)
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", config.client_id.as_str()),
            ("refresh_token", refresh_token),
        ])
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    let mut tokens = OAuthTokenSet::from_json(&response)?;
    if tokens.refresh_token.is_none() {
        tokens.refresh_token = Some(refresh_token.to_owned());
    }
    Ok(tokens)
}

pub async fn revoke_oauth_token(
    client: &reqwest::Client,
    config: &OAuthClientConfig,
    token: &str,
) -> Result<()> {
    client
        .post(&config.revoke_endpoint)
        .form(&[("token", token), ("client_id", config.client_id.as_str())])
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}
