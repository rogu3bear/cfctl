//! OAuth, profile, account selection, and secret-store contracts.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngExt as _, distr::Alphanumeric};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::{
    collections::BTreeMap,
    fmt, fs,
    io::Write as _,
    path::{Path, PathBuf},
    sync::Mutex,
};

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

/// Backend that physically holds a stored secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretBackend {
    PlatformKeyring,
    FallbackFile,
    Memory,
}

pub trait SecretStore: Send + Sync {
    fn put(&self, key: &str, value: &str) -> Result<()>;
    fn get(&self, key: &str) -> Result<Option<String>>;
    fn delete(&self, key: &str) -> Result<()>;

    /// Report which backend currently holds `key`, if any.
    fn locate(&self, key: &str) -> Result<Option<SecretBackend>>;

    fn locate_api_token(&self, profile_id: &str) -> Result<Option<SecretBackend>> {
        self.locate(&api_token_key(profile_id))
    }

    fn locate_global_key(&self, profile_id: &str) -> Result<Option<SecretBackend>> {
        self.locate(&global_key(profile_id))
    }

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

    fn locate(&self, key: &str) -> Result<Option<SecretBackend>> {
        Ok(self.get(key)?.map(|_| SecretBackend::Memory))
    }
}

const KEYRING_SERVICE: &str = "io.cfctl.cfctl";

/// Direct platform keyring access (macOS Keychain, Linux Secret Service).
#[derive(Debug, Clone, Copy, Default)]
pub struct KeyringSecretStore;

impl SecretStore for KeyringSecretStore {
    fn put(&self, key: &str, value: &str) -> Result<()> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, key)
            .map_err(|error| AuthError::SecretStore(error.to_string()))?;
        entry
            .set_password(value)
            .map_err(|error| AuthError::SecretStore(error.to_string()))
    }

    fn get(&self, key: &str) -> Result<Option<String>> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, key)
            .map_err(|error| AuthError::SecretStore(error.to_string()))?;
        match entry.get_password() {
            Ok(value) => Ok(Some(value)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(AuthError::SecretStore(error.to_string())),
        }
    }

    fn delete(&self, key: &str) -> Result<()> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, key)
            .map_err(|error| AuthError::SecretStore(error.to_string()))?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(AuthError::SecretStore(error.to_string())),
        }
    }

    fn locate(&self, key: &str) -> Result<Option<SecretBackend>> {
        Ok(self.get(key)?.map(|_| SecretBackend::PlatformKeyring))
    }
}

/// Durable mode-0600 per-secret files for hosts whose platform keyring
/// rejects writes (for example a login keychain whose passphrase is out of
/// sync with the login password). Secret values never relax past 0600 and
/// group- or world-accessible files are refused on read.
#[derive(Debug, Clone)]
pub struct FileSecretStore {
    root: PathBuf,
}

impl FileSecretStore {
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Number of secrets currently held on disk.
    pub fn stored_secret_count(&self) -> Result<usize> {
        let entries = match fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(file_store_error("list", &self.root, &error)),
        };
        let mut count = 0;
        for entry in entries {
            let entry = entry.map_err(|error| file_store_error("list", &self.root, &error))?;
            if entry.file_name().to_string_lossy().contains(".tmp-") {
                continue;
            }
            let file_type = entry
                .file_type()
                .map_err(|error| file_store_error("list", &self.root, &error))?;
            if file_type.is_file() {
                count += 1;
            }
        }
        Ok(count)
    }

    fn secret_path(&self, key: &str) -> Result<PathBuf> {
        if key.is_empty() {
            return Err(AuthError::SecretStore(
                "secret keys must not be empty".to_owned(),
            ));
        }
        Ok(self.root.join(secret_file_name(key)))
    }

    fn ensure_root(&self) -> Result<()> {
        fs::create_dir_all(&self.root)
            .map_err(|error| file_store_error("create", &self.root, &error))?;
        #[cfg(unix)]
        fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700))
            .map_err(|error| file_store_error("restrict", &self.root, &error))?;
        Ok(())
    }
}

impl SecretStore for FileSecretStore {
    fn put(&self, key: &str, value: &str) -> Result<()> {
        let path = self.secret_path(key)?;
        self.ensure_root()?;
        let staging = self
            .root
            .join(format!("{}.tmp-{}", secret_file_name(key), Uuid::new_v4()));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let written = options
            .open(&staging)
            .map_err(|error| file_store_error("stage", &staging, &error))
            .and_then(|mut file| {
                file.write_all(value.as_bytes())
                    .and_then(|()| file.sync_all())
                    .map_err(|error| file_store_error("write", &staging, &error))
            })
            .and_then(|()| {
                fs::rename(&staging, &path)
                    .map_err(|error| file_store_error("commit", &path, &error))
            });
        if written.is_err() {
            let _ = fs::remove_file(&staging);
        }
        written
    }

    fn get(&self, key: &str) -> Result<Option<String>> {
        let path = self.secret_path(key)?;
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(file_store_error("inspect", &path, &error)),
        };
        #[cfg(unix)]
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(AuthError::SecretStore(format!(
                "refusing to read group- or world-accessible secret file {}; run `chmod 600` on it first",
                path.display()
            )));
        }
        #[cfg(not(unix))]
        let _ = metadata;
        match fs::read_to_string(&path) {
            Ok(value) => Ok(Some(value)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(file_store_error("read", &path, &error)),
        }
    }

    fn delete(&self, key: &str) -> Result<()> {
        let path = self.secret_path(key)?;
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(file_store_error("delete", &path, &error)),
        }
    }

    fn locate(&self, key: &str) -> Result<Option<SecretBackend>> {
        Ok(self.get(key)?.map(|_| SecretBackend::FallbackFile))
    }
}

/// Platform keyring first, with a durable file fallback so a broken keyring
/// (for example `errSecAuthFailed` from a desynchronized login keychain)
/// degrades to governed mode-0600 files instead of blocking credential
/// import. `cfctl doctor` reports which backend is active.
#[derive(Debug, Clone)]
pub struct PlatformSecretStore {
    keyring: KeyringSecretStore,
    fallback: FileSecretStore,
}

impl PlatformSecretStore {
    #[must_use]
    pub fn new(fallback_root: PathBuf) -> Self {
        Self {
            keyring: KeyringSecretStore,
            fallback: FileSecretStore::new(fallback_root),
        }
    }

    #[must_use]
    pub fn fallback_root(&self) -> &Path {
        self.fallback.root()
    }

    pub fn fallback_secret_count(&self) -> Result<usize> {
        self.fallback.stored_secret_count()
    }

    /// Prove the platform keyring accepts writes by round-tripping a
    /// non-secret probe value. Returns the platform failure text when the
    /// keyring is unusable.
    pub fn keyring_probe(&self) -> std::result::Result<(), String> {
        const PROBE_KEY: &str = "doctor/keyring-probe";
        const PROBE_VALUE: &str = "cfctl-keyring-probe";
        let _ = self.keyring.delete(PROBE_KEY);
        self.keyring
            .put(PROBE_KEY, PROBE_VALUE)
            .map_err(|error| error.to_string())?;
        let read = self
            .keyring
            .get(PROBE_KEY)
            .map_err(|error| error.to_string());
        let _ = self.keyring.delete(PROBE_KEY);
        match read? {
            Some(value) if value == PROBE_VALUE => Ok(()),
            _ => Err("keyring probe read back an unexpected value".to_owned()),
        }
    }
}

impl SecretStore for PlatformSecretStore {
    fn put(&self, key: &str, value: &str) -> Result<()> {
        chained_put(&self.keyring, &self.fallback, key, value)
    }

    fn get(&self, key: &str) -> Result<Option<String>> {
        chained_get(&self.keyring, &self.fallback, key)
    }

    fn delete(&self, key: &str) -> Result<()> {
        chained_delete(&self.keyring, &self.fallback, key)
    }

    fn locate(&self, key: &str) -> Result<Option<SecretBackend>> {
        if matches!(self.keyring.get(key), Ok(Some(_))) {
            return Ok(Some(SecretBackend::PlatformKeyring));
        }
        self.fallback.locate(key)
    }
}

fn chained_put(
    primary: &dyn SecretStore,
    fallback: &dyn SecretStore,
    key: &str,
    value: &str,
) -> Result<()> {
    match primary.put(key, value) {
        // Drop any stale fallback copy so a later fallback read can never
        // resurrect an old secret.
        Ok(()) => fallback.delete(key),
        Err(primary_error) => fallback.put(key, value).map_err(|fallback_error| {
            AuthError::SecretStore(format!(
                "primary secret store write failed ({primary_error}); fallback write also failed ({fallback_error})"
            ))
        }),
    }
}

fn chained_get(
    primary: &dyn SecretStore,
    fallback: &dyn SecretStore,
    key: &str,
) -> Result<Option<String>> {
    match primary.get(key) {
        Ok(Some(value)) => Ok(Some(value)),
        Ok(None) => fallback.get(key),
        Err(primary_error) => match fallback.get(key) {
            Ok(Some(value)) => Ok(Some(value)),
            Ok(None) => Err(primary_error),
            Err(fallback_error) => Err(AuthError::SecretStore(format!(
                "primary secret store read failed ({primary_error}); fallback read also failed ({fallback_error})"
            ))),
        },
    }
}

fn chained_delete(primary: &dyn SecretStore, fallback: &dyn SecretStore, key: &str) -> Result<()> {
    let primary_result = primary.delete(key);
    let fallback_result = fallback.delete(key);
    primary_result?;
    fallback_result
}

fn secret_file_name(key: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut name = String::with_capacity(key.len());
    for byte in key.bytes() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'-' => name.push(char::from(byte)),
            other => {
                name.push('%');
                name.push(char::from(HEX[usize::from(other >> 4)]));
                name.push(char::from(HEX[usize::from(other & 0x0F)]));
            }
        }
    }
    name
}

fn file_store_error(action: &str, path: &Path, error: &std::io::Error) -> AuthError {
    AuthError::SecretStore(format!(
        "file secret store failed to {action} {}: {error}",
        path.display()
    ))
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

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    struct RejectingSecretStore;

    impl SecretStore for RejectingSecretStore {
        fn put(&self, _key: &str, _value: &str) -> Result<()> {
            Err(AuthError::SecretStore(
                "primary store rejected the write".to_owned(),
            ))
        }

        fn get(&self, _key: &str) -> Result<Option<String>> {
            Err(AuthError::SecretStore(
                "primary store rejected the read".to_owned(),
            ))
        }

        fn delete(&self, _key: &str) -> Result<()> {
            Err(AuthError::SecretStore(
                "primary store rejected the delete".to_owned(),
            ))
        }

        fn locate(&self, _key: &str) -> Result<Option<SecretBackend>> {
            Ok(None)
        }
    }

    #[test]
    fn chained_put_prefers_primary_and_clears_stale_fallback_copies() {
        let primary = MemorySecretStore::default();
        let fallback = MemorySecretStore::default();
        fallback.put("k", "stale").expect("seed fallback");

        chained_put(&primary, &fallback, "k", "fresh").expect("chained put");

        assert_eq!(primary.get("k").expect("primary"), Some("fresh".to_owned()));
        assert_eq!(fallback.get("k").expect("fallback"), None);
    }

    #[test]
    fn chained_put_falls_back_when_primary_rejects_the_write() {
        let fallback = MemorySecretStore::default();

        chained_put(&RejectingSecretStore, &fallback, "k", "v").expect("fallback put");

        assert_eq!(fallback.get("k").expect("fallback"), Some("v".to_owned()));
        assert_eq!(
            chained_get(&RejectingSecretStore, &fallback, "k").expect("fallback read"),
            Some("v".to_owned())
        );
    }

    #[test]
    fn chained_put_reports_both_failures_when_no_store_accepts_the_secret() {
        let error = chained_put(&RejectingSecretStore, &RejectingSecretStore, "k", "v")
            .expect_err("double failure");
        let message = error.to_string();
        assert!(message.contains("rejected the write"), "{message}");
        assert!(message.contains("fallback write also failed"), "{message}");
    }

    #[test]
    fn chained_get_prefers_primary_and_surfaces_primary_error_on_double_miss() {
        let primary = MemorySecretStore::default();
        let fallback = MemorySecretStore::default();
        primary.put("k", "primary-value").expect("seed primary");
        fallback.put("k", "fallback-value").expect("seed fallback");

        assert_eq!(
            chained_get(&primary, &fallback, "k").expect("primary wins"),
            Some("primary-value".to_owned())
        );
        let miss = chained_get(&RejectingSecretStore, &MemorySecretStore::default(), "k")
            .expect_err("primary error surfaces when fallback misses");
        assert!(miss.to_string().contains("rejected the read"));
    }

    #[test]
    fn chained_delete_still_clears_the_fallback_when_primary_fails() {
        let fallback = MemorySecretStore::default();
        fallback.put("k", "v").expect("seed fallback");

        let error = chained_delete(&RejectingSecretStore, &fallback, "k")
            .expect_err("primary delete failure surfaces");
        assert!(error.to_string().contains("rejected the delete"));
        assert_eq!(fallback.get("k").expect("fallback"), None);
    }

    #[test]
    fn secret_file_names_stay_flat_and_injective() {
        assert_eq!(
            secret_file_name("profile/default/api-token"),
            "profile%2Fdefault%2Fapi-token"
        );
        assert_eq!(secret_file_name("a%b"), "a%25b");
        assert_eq!(secret_file_name(".."), "%2E%2E");
        assert_ne!(
            secret_file_name("profile/x"),
            secret_file_name("profile%2Fx")
        );
    }

    #[test]
    fn file_secret_store_round_trips_and_counts_secrets() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = FileSecretStore::new(root.path().join("secrets"));

        assert_eq!(store.stored_secret_count().expect("empty count"), 0);
        store.put("profile/default/api-token", "one").expect("put");
        store
            .put("profile/default/api-token", "two")
            .expect("overwrite");
        assert_eq!(
            store.get("profile/default/api-token").expect("get"),
            Some("two".to_owned())
        );
        assert_eq!(store.stored_secret_count().expect("count"), 1);
        assert_eq!(
            store.locate("profile/default/api-token").expect("locate"),
            Some(SecretBackend::FallbackFile)
        );

        store.delete("profile/default/api-token").expect("delete");
        assert_eq!(store.get("profile/default/api-token").expect("miss"), None);
        store
            .delete("profile/default/api-token")
            .expect("deleting a missing secret is not an error");
    }

    #[cfg(unix)]
    #[test]
    fn file_secret_store_enforces_0600_files_and_0700_root() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = FileSecretStore::new(root.path().join("secrets"));
        store
            .put("profile/default/api-token", "value")
            .expect("put");

        let dir_mode = fs::metadata(store.root())
            .expect("root metadata")
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o777, 0o700, "root must be 0700");

        let path = store
            .root()
            .join(secret_file_name("profile/default/api-token"));
        let file_mode = fs::metadata(&path)
            .expect("secret metadata")
            .permissions()
            .mode();
        assert_eq!(file_mode & 0o777, 0o600, "secret files must be 0600");

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("loosen");
        let error = store
            .get("profile/default/api-token")
            .expect_err("group- or world-accessible secrets are refused");
        assert!(error.to_string().contains("chmod 600"), "{error}");
    }

    #[test]
    fn empty_secret_keys_are_rejected() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = FileSecretStore::new(root.path().join("secrets"));
        assert!(store.put("", "value").is_err());
        assert!(store.get("").is_err());
        assert!(store.delete("").is_err());
    }
}
