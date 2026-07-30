//! OAuth, profile, account selection, and secret-store contracts.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngExt as _, distr::Alphanumeric};
#[cfg(target_os = "macos")]
use std::io::Read as _;
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
    /// Opaque local lineage for the credential material installed through this
    /// profile. Re-login or re-import creates a new generation without
    /// persisting any secret-derived verifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_generation_id: Option<String>,
    /// Immutable secret slot selected by this profile. Legacy profiles omit
    /// this field and continue to use their profile-keyed credential. A
    /// rotation stages a complete slot before one atomic metadata switch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_token_slot_id: Option<String>,
    /// Non-secret Cloudflare identity and expiry for a cfctl-managed child.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_api_token: Option<ManagedApiTokenV1>,
    pub emergency_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedApiTokenV1 {
    pub schema_version: u8,
    pub token_id: String,
    pub expires_at: DateTime<Utc>,
    pub standing_authority_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_revoke_token_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_revoke_operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_revoke_slot_id: Option<String>,
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
            credential_generation_id: (kind != ProfileKind::LegacyWranglerSession)
                .then(|| Uuid::new_v4().to_string()),
            api_token_slot_id: None,
            managed_api_token: None,
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

    fn locate_profile_credential(
        &self,
        profile: &ProfileMetadata,
    ) -> Result<Option<SecretBackend>> {
        self.locate(&profile_credential_key(profile)?)
    }

    /// Rewrite one profile's opaque credential through the active secret
    /// backend without exposing its value. On macOS this repairs legacy
    /// Keychain items whose creator ACL does not trust the native reader used
    /// by unattended cfctl processes.
    fn repair_profile_credential_access(&self, profile: &ProfileMetadata) -> Result<()> {
        let key = profile_credential_key(profile)?;
        let value = self
            .get(&key)?
            .ok_or_else(|| AuthError::MissingCredential(profile.id.clone()))?;
        self.put(&key, &value)
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

    fn delete_api_token(&self, profile_id: &str) -> Result<()> {
        self.delete(&api_token_key(profile_id))
    }

    fn store_api_token_slot(&self, slot_id: &str, token: &str) -> Result<()> {
        self.put(&api_token_slot_key(slot_id)?, token)
    }

    fn delete_api_token_slot(&self, slot_id: &str) -> Result<()> {
        self.delete(&api_token_slot_key(slot_id)?)
    }

    fn load_profile_credential(&self, profile: &ProfileMetadata) -> Result<AuthCredential> {
        if profile.kind == ProfileKind::ApiToken
            && let Some(slot_id) = profile.api_token_slot_id.as_deref()
        {
            return self
                .get(&api_token_slot_key(slot_id)?)?
                .map(|token| AuthCredential::Bearer { token })
                .ok_or_else(|| AuthError::MissingCredential(profile.id.clone()));
        }
        self.load_credential(&profile.id, profile.kind)
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
        #[cfg(target_os = "macos")]
        {
            if value.contains(['\n', '\r']) {
                return Err(AuthError::SecretStore(
                    "macOS Keychain credentials cannot contain line breaks".to_owned(),
                ));
            }
            let mut child = std::process::Command::new("/usr/bin/security")
                .args([
                    "add-generic-password",
                    "-U",
                    "-a",
                    key,
                    "-s",
                    KEYRING_SERVICE,
                    "-T",
                    "/usr/bin/security",
                    "-w",
                ])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .map_err(|error| AuthError::SecretStore(error.to_string()))?;
            {
                let stdin = child.stdin.as_mut().ok_or_else(|| {
                    AuthError::SecretStore(
                        "platform keyring credential write produced no input sink".to_owned(),
                    )
                })?;
                stdin
                    .write_all(value.as_bytes())
                    .and_then(|()| stdin.write_all(b"\n"))
                    .and_then(|()| stdin.write_all(value.as_bytes()))
                    .and_then(|()| stdin.write_all(b"\n"))
                    .map_err(|error| AuthError::SecretStore(error.to_string()))?;
            }
            drop(child.stdin.take());
            let status = wait_for_macos_keychain_child(&mut child)?;
            if status.success() {
                Ok(())
            } else {
                Err(AuthError::SecretStore(format!(
                    "platform keyring credential write failed with exit status {status}"
                )))
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            let entry = keyring::Entry::new(KEYRING_SERVICE, key)
                .map_err(|error| AuthError::SecretStore(error.to_string()))?;
            entry
                .set_password(value)
                .map_err(|error| AuthError::SecretStore(error.to_string()))
        }
    }

    fn get(&self, key: &str) -> Result<Option<String>> {
        #[cfg(target_os = "macos")]
        {
            let mut child = std::process::Command::new("/usr/bin/security")
                .args([
                    "find-generic-password",
                    "-s",
                    KEYRING_SERVICE,
                    "-a",
                    key,
                    "-w",
                ])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .spawn()
                .map_err(|error| AuthError::SecretStore(error.to_string()))?;
            let status = wait_for_macos_keychain_child(&mut child)?;
            if status.code() == Some(44) {
                return Ok(None);
            }
            if !status.success() {
                return Err(AuthError::SecretStore(format!(
                    "platform keyring credential read failed with exit status {status}"
                )));
            }
            let mut value = String::new();
            child
                .stdout
                .take()
                .ok_or_else(|| {
                    AuthError::SecretStore(
                        "platform keyring credential read produced no sink".to_owned(),
                    )
                })?
                .read_to_string(&mut value)
                .map_err(|error| AuthError::SecretStore(error.to_string()))?;
            while value.ends_with(['\n', '\r']) {
                value.pop();
            }
            Ok(Some(value))
        }
        #[cfg(not(target_os = "macos"))]
        {
            let entry = keyring::Entry::new(KEYRING_SERVICE, key)
                .map_err(|error| AuthError::SecretStore(error.to_string()))?;
            match entry.get_password() {
                Ok(value) => Ok(Some(value)),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(error) => Err(AuthError::SecretStore(error.to_string())),
            }
        }
    }

    fn delete(&self, key: &str) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            let mut child = std::process::Command::new("/usr/bin/security")
                .args(["delete-generic-password", "-s", KEYRING_SERVICE, "-a", key])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .map_err(|error| AuthError::SecretStore(error.to_string()))?;
            let status = wait_for_macos_keychain_child(&mut child)?;
            if status.success() || status.code() == Some(44) {
                Ok(())
            } else {
                Err(AuthError::SecretStore(format!(
                    "platform keyring credential deletion failed with exit status {status}"
                )))
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            let entry = keyring::Entry::new(KEYRING_SERVICE, key)
                .map_err(|error| AuthError::SecretStore(error.to_string()))?;
            match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(error) => Err(AuthError::SecretStore(error.to_string())),
            }
        }
    }

    fn locate(&self, key: &str) -> Result<Option<SecretBackend>> {
        Ok(self.get(key)?.map(|_| SecretBackend::PlatformKeyring))
    }
}

#[cfg(target_os = "macos")]
fn wait_for_macos_keychain_child(
    child: &mut std::process::Child,
) -> Result<std::process::ExitStatus> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match child
            .try_wait()
            .map_err(|error| AuthError::SecretStore(error.to_string()))?
        {
            Some(status) => return Ok(status),
            None if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(AuthError::SecretStore(
                    "platform keyring operation timed out after 5 seconds; unlock the login keychain and retry"
                        .to_owned(),
                ));
            }
            None => std::thread::sleep(std::time::Duration::from_millis(25)),
        }
    }
}

/// Durable mode-0600 per-secret files for hosts whose platform keyring
/// rejects writes (for example a login keychain whose passphrase is out of
/// sync with the login password). Secret values never relax past 0600 and
/// group- or world-accessible files are refused on read. A synced staging file
/// plus atomic rename gives complete old-or-new visibility across process
/// crashes. This does not claim sudden-power-loss durability across every
/// filesystem because the parent directory is not fsynced.
#[derive(Debug, Clone)]
pub struct FileSecretStore {
    root: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileSecretWriteCheckpoint {
    StagedFileSynced,
    AtomicRenameCommitted,
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

    fn put_with_checkpoint<F>(&self, key: &str, value: &str, mut checkpoint: F) -> Result<()>
    where
        F: FnMut(FileSecretWriteCheckpoint) -> Result<()>,
    {
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
            .and_then(|()| checkpoint(FileSecretWriteCheckpoint::StagedFileSynced))
            .and_then(|()| {
                fs::rename(&staging, &path)
                    .map_err(|error| file_store_error("commit", &path, &error))
            })
            .and_then(|()| checkpoint(FileSecretWriteCheckpoint::AtomicRenameCommitted));
        if written.is_err() {
            let _ = fs::remove_file(&staging);
        }
        written
    }
}

impl SecretStore for FileSecretStore {
    fn put(&self, key: &str, value: &str) -> Result<()> {
        self.put_with_checkpoint(key, value, |_| Ok(()))
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

/// Platform keyring preferred for writes, with a durable file fallback so a
/// broken keyring (for example `errSecAuthFailed` from a desynchronized login
/// keychain) degrades to governed mode-0600 files instead of blocking
/// credential import. A reserved fallback sidecar is the only state treated
/// as an in-flight write-ahead journal. Unequal raw primary/fallback values
/// from the legacy protocol are ambiguous and fail closed. When fallback state
/// already exists, replacement first atomically stages the fresh value in the
/// sidecar, then replaces the keyring value, then clears the legacy fallback
/// and sidecar. A process crash at any completed boundary therefore exposes
/// one complete old or new value without guessing which legacy copy is newer.
/// `cfctl doctor` reports which backend is active.
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
        const PROBE_VALUE: &str = "cfctl-keyring-probe";
        if self
            .fallback_secret_count()
            .map_err(|error| error.to_string())?
            > 0
        {
            return Err(
                "not probed while governed fallback credentials are active; this avoids interactive platform prompts"
                    .to_owned(),
            );
        }
        let probe_key = format!("doctor/keyring-probe/{}", Uuid::new_v4());
        self.keyring
            .put(&probe_key, PROBE_VALUE)
            .map_err(|error| error.to_string())?;
        let read = self
            .keyring
            .get(&probe_key)
            .map_err(|error| error.to_string());
        let _ = self.keyring.delete(&probe_key);
        match read? {
            Some(value) if value == PROBE_VALUE => Ok(()),
            _ => Err("keyring probe read back an unexpected value".to_owned()),
        }
    }
}

impl SecretStore for PlatformSecretStore {
    fn put(&self, key: &str, value: &str) -> Result<()> {
        if self.fallback_secret_count()? > 0 {
            return self.fallback.put(fallback_journal_key(key).as_str(), value);
        }
        chained_put(&self.keyring, &self.fallback, key, value)
    }

    fn get(&self, key: &str) -> Result<Option<String>> {
        chained_get(&self.keyring, &self.fallback, key)
    }

    fn delete(&self, key: &str) -> Result<()> {
        chained_delete(&self.keyring, &self.fallback, key)
    }

    fn locate(&self, key: &str) -> Result<Option<SecretBackend>> {
        chained_locate(&self.keyring, &self.fallback, key)
    }
}

fn chained_put(
    primary: &dyn SecretStore,
    fallback: &dyn SecretStore,
    key: &str,
    value: &str,
) -> Result<()> {
    chained_put_with_checkpoint(primary, fallback, key, value, |_| Ok(()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CredentialWriteCheckpoint {
    FallbackInspected,
    FallbackJournalCommitted,
    PrimaryWriteCommitted,
    PrimaryWriteRejected,
    LegacyFallbackCleared,
    LegacyFallbackCleanupFailed,
    FallbackJournalCleared,
    FallbackJournalCleanupFailed,
}

fn chained_put_with_checkpoint<F>(
    primary: &dyn SecretStore,
    fallback: &dyn SecretStore,
    key: &str,
    value: &str,
    mut checkpoint: F,
) -> Result<()>
where
    F: FnMut(CredentialWriteCheckpoint) -> Result<()>,
{
    let journal_key = fallback_journal_key(key);
    let fallback_exists =
        fallback.get(key)?.is_some() || fallback.get(journal_key.as_str())?.is_some();
    checkpoint(CredentialWriteCheckpoint::FallbackInspected)?;

    if fallback_exists {
        // The reserved sidecar distinguishes a current write-ahead journal
        // from an untyped legacy fallback whose freshness is unknowable.
        fallback.put(journal_key.as_str(), value)?;
        checkpoint(CredentialWriteCheckpoint::FallbackJournalCommitted)?;
        match primary.put(key, value) {
            Ok(()) => {
                checkpoint(CredentialWriteCheckpoint::PrimaryWriteCommitted)?;
                if let Err(cleanup_error) = fallback.delete(key) {
                    checkpoint(CredentialWriteCheckpoint::LegacyFallbackCleanupFailed)?;
                    return recover_with_required_fresh_journal(
                        fallback,
                        journal_key.as_str(),
                        value,
                        "legacy fallback",
                        &cleanup_error,
                    );
                }
                checkpoint(CredentialWriteCheckpoint::LegacyFallbackCleared)?;
                match fallback.delete(journal_key.as_str()) {
                    Ok(()) => {
                        checkpoint(CredentialWriteCheckpoint::FallbackJournalCleared)?;
                        Ok(())
                    }
                    Err(cleanup_error) => {
                        checkpoint(CredentialWriteCheckpoint::FallbackJournalCleanupFailed)?;
                        recover_after_journal_cleanup_failure(
                            fallback,
                            journal_key.as_str(),
                            value,
                            &cleanup_error,
                        )
                    }
                }
            }
            Err(primary_error) => {
                checkpoint(CredentialWriteCheckpoint::PrimaryWriteRejected)?;
                if fallback.get(journal_key.as_str())?.as_deref() != Some(value) {
                    fallback
                        .put(journal_key.as_str(), value)
                        .map_err(|fallback_error| {
                            AuthError::SecretStore(format!(
                                "primary secret store write failed ({primary_error}); fallback journal reconfirmation also failed ({fallback_error})"
                            ))
                        })?;
                    checkpoint(CredentialWriteCheckpoint::FallbackJournalCommitted)?;
                }
                Ok(())
            }
        }
    } else {
        match primary.put(key, value) {
            Ok(()) => {
                checkpoint(CredentialWriteCheckpoint::PrimaryWriteCommitted)?;
                if fallback.get(journal_key.as_str())?.is_some() {
                    fallback.put(journal_key.as_str(), value)?;
                    checkpoint(CredentialWriteCheckpoint::FallbackJournalCommitted)?;
                    match fallback.delete(journal_key.as_str()) {
                        Ok(()) => {
                            checkpoint(CredentialWriteCheckpoint::FallbackJournalCleared)?;
                        }
                        Err(cleanup_error) => {
                            checkpoint(CredentialWriteCheckpoint::FallbackJournalCleanupFailed)?;
                            recover_after_journal_cleanup_failure(
                                fallback,
                                journal_key.as_str(),
                                value,
                                &cleanup_error,
                            )?;
                        }
                    }
                }
                Ok(())
            }
            Err(primary_error) => {
                checkpoint(CredentialWriteCheckpoint::PrimaryWriteRejected)?;
                fallback
                    .put(journal_key.as_str(), value)
                    .map_err(|fallback_error| {
                    AuthError::SecretStore(format!(
                        "primary secret store write failed ({primary_error}); fallback write also failed ({fallback_error})"
                    ))
                })?;
                checkpoint(CredentialWriteCheckpoint::FallbackJournalCommitted)
            }
        }
    }
}

fn chained_get(
    primary: &dyn SecretStore,
    fallback: &dyn SecretStore,
    key: &str,
) -> Result<Option<String>> {
    match resolve_chained_credential(primary, fallback, key)? {
        ResolvedChainedCredential::Fallback(value) | ResolvedChainedCredential::Primary(value) => {
            Ok(Some(value))
        }
        ResolvedChainedCredential::Missing => Ok(None),
    }
}

fn chained_delete(primary: &dyn SecretStore, fallback: &dyn SecretStore, key: &str) -> Result<()> {
    let primary_result = primary.delete(key);
    let fallback_result = fallback.delete(key);
    let journal_result = if fallback_result.is_ok() {
        fallback.delete(fallback_journal_key(key).as_str())
    } else {
        Ok(())
    };
    primary_result?;
    fallback_result?;
    journal_result
}

fn chained_locate(
    primary: &dyn SecretStore,
    fallback: &dyn SecretStore,
    key: &str,
) -> Result<Option<SecretBackend>> {
    match resolve_chained_credential(primary, fallback, key)? {
        ResolvedChainedCredential::Fallback(_) => Ok(Some(SecretBackend::FallbackFile)),
        ResolvedChainedCredential::Primary(_) => primary.locate(key),
        ResolvedChainedCredential::Missing => Ok(None),
    }
}

enum ResolvedChainedCredential {
    Fallback(String),
    Primary(String),
    Missing,
}

fn resolve_chained_credential(
    primary: &dyn SecretStore,
    fallback: &dyn SecretStore,
    key: &str,
) -> Result<ResolvedChainedCredential> {
    if let Some(journal) = fallback.get(fallback_journal_key(key).as_str())? {
        return Ok(ResolvedChainedCredential::Fallback(journal));
    }
    let fallback_value = fallback.get(key)?;
    match (fallback_value, primary.get(key)) {
        (Some(fallback_value), Ok(Some(primary_value))) if primary_value == fallback_value => {
            Ok(ResolvedChainedCredential::Fallback(fallback_value))
        }
        (Some(_), Ok(Some(_))) => Err(AuthError::SecretStore(
            "primary and fallback credential values differ without a current cfctl journal; credential state is ambiguous and must be repaired by re-importing the credential"
                .to_owned(),
        )),
        (Some(fallback_value), Ok(None) | Err(_)) => {
            Ok(ResolvedChainedCredential::Fallback(fallback_value))
        }
        (None, Ok(Some(primary_value))) => Ok(ResolvedChainedCredential::Primary(primary_value)),
        (None, Ok(None)) => Ok(ResolvedChainedCredential::Missing),
        (None, Err(error)) => Err(error),
    }
}

const FALLBACK_JOURNAL_KEY_PREFIX: &str = "__cfctl_internal__/credential-journal/v1/";

fn fallback_journal_key(key: &str) -> String {
    format!(
        "{FALLBACK_JOURNAL_KEY_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(Sha256::digest(key.as_bytes()))
    )
}

fn recover_with_required_fresh_journal(
    fallback: &dyn SecretStore,
    journal_key: &str,
    value: &str,
    cleanup_target: &str,
    cleanup_error: &AuthError,
) -> Result<()> {
    match fallback.get(journal_key) {
        Ok(Some(journal)) if journal == value => Ok(()),
        Ok(Some(_) | None) => Err(AuthError::SecretStore(format!(
            "primary secret store write succeeded, but {cleanup_target} cleanup failed ({cleanup_error}) and no matching fallback journal remains; credential state is ambiguous and must be repaired before use"
        ))),
        Err(recovery_error) => Err(AuthError::SecretStore(format!(
            "primary secret store write succeeded, but {cleanup_target} cleanup failed ({cleanup_error}) and recovery inspection failed ({recovery_error}); credential state is ambiguous and must be repaired before use"
        ))),
    }
}

fn recover_after_journal_cleanup_failure(
    fallback: &dyn SecretStore,
    journal_key: &str,
    value: &str,
    cleanup_error: &AuthError,
) -> Result<()> {
    match fallback.get(journal_key) {
        Ok(Some(journal)) if journal == value => Ok(()),
        Ok(None) => Ok(()),
        Ok(Some(_)) => Err(AuthError::SecretStore(format!(
            "primary secret store write succeeded, but fallback journal cleanup failed ({cleanup_error}) and recovery found a different journal value; credential state is ambiguous and must be repaired before use"
        ))),
        Err(recovery_error) => Err(AuthError::SecretStore(format!(
            "primary secret store write succeeded, but fallback journal cleanup failed ({cleanup_error}) and recovery inspection failed ({recovery_error}); credential state is ambiguous and must be repaired before use"
        ))),
    }
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

fn api_token_slot_key(slot_id: &str) -> Result<String> {
    Uuid::parse_str(slot_id)
        .map_err(|_| AuthError::SecretStore("API-token slot identity must be a UUID".to_owned()))?;
    Ok(format!("api-token-slot/{slot_id}"))
}

fn global_key(profile_id: &str) -> String {
    format!("profile/{profile_id}/global-key")
}

fn profile_credential_key(profile: &ProfileMetadata) -> Result<String> {
    match profile.kind {
        ProfileKind::OAuth => Ok(oauth_key(&profile.id)),
        ProfileKind::ApiToken => profile
            .api_token_slot_id
            .as_deref()
            .map_or_else(|| Ok(api_token_key(&profile.id)), api_token_slot_key),
        ProfileKind::LegacyWranglerSession => Err(AuthError::UnsupportedLegacyWranglerSession(
            profile.id.clone(),
        )),
        ProfileKind::GlobalKey => Ok(global_key(&profile.id)),
    }
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

    #[derive(Default)]
    struct DeleteRejectingSecretStore {
        inner: MemorySecretStore,
    }

    impl SecretStore for DeleteRejectingSecretStore {
        fn put(&self, key: &str, value: &str) -> Result<()> {
            self.inner.put(key, value)
        }

        fn get(&self, key: &str) -> Result<Option<String>> {
            self.inner.get(key)
        }

        fn delete(&self, _key: &str) -> Result<()> {
            Err(AuthError::SecretStore(
                "fallback store rejected the delete".to_owned(),
            ))
        }

        fn locate(&self, key: &str) -> Result<Option<SecretBackend>> {
            self.inner.locate(key)
        }
    }

    #[derive(Default)]
    struct LegacyDeleteRejectingSecretStore {
        inner: MemorySecretStore,
        delete_attempts: Mutex<Vec<String>>,
    }

    impl LegacyDeleteRejectingSecretStore {
        fn delete_attempts(&self) -> Vec<String> {
            self.delete_attempts
                .lock()
                .expect("delete-attempt lock")
                .clone()
        }
    }

    impl SecretStore for LegacyDeleteRejectingSecretStore {
        fn put(&self, key: &str, value: &str) -> Result<()> {
            self.inner.put(key, value)
        }

        fn get(&self, key: &str) -> Result<Option<String>> {
            self.inner.get(key)
        }

        fn delete(&self, key: &str) -> Result<()> {
            self.delete_attempts
                .lock()
                .expect("delete-attempt lock")
                .push(key.to_owned());
            if key == "k" {
                return Err(AuthError::SecretStore(
                    "legacy fallback delete rejected".to_owned(),
                ));
            }
            self.inner.delete(key)
        }

        fn locate(&self, key: &str) -> Result<Option<SecretBackend>> {
            self.inner.locate(key)
        }
    }

    #[derive(Default)]
    struct DeleteAfterCommitRejectingSecretStore {
        inner: MemorySecretStore,
    }

    impl SecretStore for DeleteAfterCommitRejectingSecretStore {
        fn put(&self, key: &str, value: &str) -> Result<()> {
            self.inner.put(key, value)
        }

        fn get(&self, key: &str) -> Result<Option<String>> {
            self.inner.get(key)
        }

        fn delete(&self, key: &str) -> Result<()> {
            self.inner.delete(key)?;
            Err(AuthError::SecretStore(
                "fallback delete crossed before reporting failure".to_owned(),
            ))
        }

        fn locate(&self, key: &str) -> Result<Option<SecretBackend>> {
            self.inner.locate(key)
        }
    }

    #[derive(Default)]
    struct JournalDeleteRejectingSecretStore {
        inner: MemorySecretStore,
    }

    impl SecretStore for JournalDeleteRejectingSecretStore {
        fn put(&self, key: &str, value: &str) -> Result<()> {
            self.inner.put(key, value)
        }

        fn get(&self, key: &str) -> Result<Option<String>> {
            self.inner.get(key)
        }

        fn delete(&self, key: &str) -> Result<()> {
            if key.starts_with(FALLBACK_JOURNAL_KEY_PREFIX) {
                return Err(AuthError::SecretStore(
                    "fallback journal delete rejected".to_owned(),
                ));
            }
            self.inner.delete(key)
        }

        fn locate(&self, key: &str) -> Result<Option<SecretBackend>> {
            self.inner.locate(key)
        }
    }

    #[derive(Default)]
    struct JournalDeleteAfterCommitRejectingSecretStore {
        inner: MemorySecretStore,
    }

    impl SecretStore for JournalDeleteAfterCommitRejectingSecretStore {
        fn put(&self, key: &str, value: &str) -> Result<()> {
            self.inner.put(key, value)
        }

        fn get(&self, key: &str) -> Result<Option<String>> {
            self.inner.get(key)
        }

        fn delete(&self, key: &str) -> Result<()> {
            self.inner.delete(key)?;
            if key.starts_with(FALLBACK_JOURNAL_KEY_PREFIX) {
                return Err(AuthError::SecretStore(
                    "fallback journal delete crossed before reporting failure".to_owned(),
                ));
            }
            Ok(())
        }

        fn locate(&self, key: &str) -> Result<Option<SecretBackend>> {
            self.inner.locate(key)
        }
    }

    #[derive(Default)]
    struct PutRejectingMemorySecretStore {
        inner: MemorySecretStore,
    }

    impl SecretStore for PutRejectingMemorySecretStore {
        fn put(&self, _key: &str, _value: &str) -> Result<()> {
            Err(AuthError::SecretStore(
                "primary store rejected the write".to_owned(),
            ))
        }

        fn get(&self, key: &str) -> Result<Option<String>> {
            self.inner.get(key)
        }

        fn delete(&self, key: &str) -> Result<()> {
            self.inner.delete(key)
        }

        fn locate(&self, key: &str) -> Result<Option<SecretBackend>> {
            self.inner.locate(key)
        }
    }

    struct JournalCheckingPrimary<'a> {
        inner: MemorySecretStore,
        fallback: &'a dyn SecretStore,
    }

    impl SecretStore for JournalCheckingPrimary<'_> {
        fn put(&self, key: &str, value: &str) -> Result<()> {
            if self
                .fallback
                .get(fallback_journal_key(key).as_str())?
                .as_deref()
                != Some(value)
            {
                return Err(AuthError::SecretStore(
                    "primary write crossed before the fresh fallback journal".to_owned(),
                ));
            }
            self.inner.put(key, value)
        }

        fn get(&self, key: &str) -> Result<Option<String>> {
            self.inner.get(key)
        }

        fn delete(&self, key: &str) -> Result<()> {
            self.inner.delete(key)
        }

        fn locate(&self, key: &str) -> Result<Option<SecretBackend>> {
            self.inner.locate(key)
        }
    }

    struct ConcurrentJournalRemovingRejectingPrimary<'a> {
        inner: MemorySecretStore,
        fallback: &'a dyn SecretStore,
    }

    impl SecretStore for ConcurrentJournalRemovingRejectingPrimary<'_> {
        fn put(&self, key: &str, _value: &str) -> Result<()> {
            self.inner.put(key, "concurrent-value")?;
            self.fallback.delete(fallback_journal_key(key).as_str())?;
            Err(AuthError::SecretStore(
                "primary store rejected this writer after a concurrent write crossed".to_owned(),
            ))
        }

        fn get(&self, key: &str) -> Result<Option<String>> {
            self.inner.get(key)
        }

        fn delete(&self, key: &str) -> Result<()> {
            self.inner.delete(key)
        }

        fn locate(&self, key: &str) -> Result<Option<SecretBackend>> {
            self.inner.locate(key)
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
        assert_eq!(
            fallback
                .get(fallback_journal_key("k").as_str())
                .expect("journal"),
            None
        );
    }

    #[test]
    fn chained_put_clean_primary_path_does_not_create_a_fallback_journal() {
        let primary = MemorySecretStore::default();
        let fallback = MemorySecretStore::default();

        chained_put(&primary, &fallback, "k", "fresh").expect("primary put");

        assert_eq!(primary.get("k").expect("primary"), Some("fresh".to_owned()));
        assert_eq!(fallback.get("k").expect("fallback"), None);
        assert_eq!(
            fallback
                .get(fallback_journal_key("k").as_str())
                .expect("journal"),
            None
        );
    }

    #[test]
    fn active_platform_fallback_stays_sticky_for_fresh_credentials_and_health_probes() {
        let runtime = tempfile::tempdir().expect("fallback root");
        let store = PlatformSecretStore::new(runtime.path().to_path_buf());
        store
            .fallback
            .put("existing", "existing-value")
            .expect("seed active fallback");

        store
            .put("fresh", "fresh-value")
            .expect("fresh credential uses active fallback");

        assert_eq!(
            store
                .fallback
                .get(fallback_journal_key("fresh").as_str())
                .expect("read fresh fallback journal"),
            Some("fresh-value".to_owned())
        );
        let probe = store
            .keyring_probe()
            .expect_err("active fallback skips keyring");
        assert!(probe.contains("avoids interactive platform prompts"));
    }

    #[test]
    fn concurrent_successful_primary_write_does_not_leave_older_journal_authoritative() {
        let primary = MemorySecretStore::default();
        let fallback = MemorySecretStore::default();
        let mut concurrent_write_injected = false;

        chained_put_with_checkpoint(&primary, &fallback, "k", "newer", |checkpoint| {
            if checkpoint == CredentialWriteCheckpoint::FallbackInspected
                && !concurrent_write_injected
            {
                concurrent_write_injected = true;
                chained_put(&RejectingSecretStore, &fallback, "k", "older")
                    .expect("concurrent keyring rejection commits its fallback journal");
                assert_eq!(
                    fallback
                        .get(fallback_journal_key("k").as_str())
                        .expect("concurrent journal"),
                    Some("older".to_owned()),
                    "the simulated concurrent write must cross after clean-path inspection"
                );
            }
            Ok(())
        })
        .expect("newer primary write");

        assert!(concurrent_write_injected);
        assert_eq!(
            primary.get("k").expect("primary"),
            Some("newer".to_owned()),
            "the newer primary write must cross successfully"
        );
        assert_eq!(
            chained_get(&primary, &fallback, "k").expect("recovered credential"),
            Some("newer".to_owned()),
            "an older journal created after clean-path inspection must not remain authoritative"
        );
    }

    #[test]
    fn rejected_primary_write_reconfirms_its_fallback_journal_after_concurrent_cleanup() {
        let fallback = MemorySecretStore::default();
        fallback.put("k", "old").expect("seed fallback");
        let primary = ConcurrentJournalRemovingRejectingPrimary {
            inner: MemorySecretStore::default(),
            fallback: &fallback,
        };

        chained_put(&primary, &fallback, "k", "requested")
            .expect("the rejected primary write must retain its requested fallback value");

        assert_eq!(
            fallback
                .get(fallback_journal_key("k").as_str())
                .expect("journal"),
            Some("requested".to_owned()),
            "a concurrent cleanup must not erase an acknowledged fallback write"
        );
        assert_eq!(
            chained_get(&primary, &fallback, "k").expect("authoritative credential"),
            Some("requested".to_owned())
        );
    }

    #[test]
    fn chained_put_falls_back_when_primary_rejects_the_write() {
        let fallback = MemorySecretStore::default();

        chained_put(&RejectingSecretStore, &fallback, "k", "v").expect("fallback put");

        assert_eq!(fallback.get("k").expect("legacy fallback"), None);
        assert_eq!(
            fallback
                .get(fallback_journal_key("k").as_str())
                .expect("journal"),
            Some("v".to_owned())
        );
        assert_eq!(
            chained_get(&RejectingSecretStore, &fallback, "k").expect("fallback read"),
            Some("v".to_owned())
        );
    }

    #[test]
    fn chained_get_accepts_legacy_fallback_only_when_primary_is_unavailable() {
        let fallback = MemorySecretStore::default();
        fallback
            .put("k", "legacy-fallback")
            .expect("seed legacy fallback");

        assert_eq!(
            chained_get(&RejectingSecretStore, &fallback, "k").expect("fallback-only legacy state"),
            Some("legacy-fallback".to_owned())
        );
    }

    #[test]
    fn chained_put_stages_existing_fallback_before_primary_replacement() {
        let fallback = MemorySecretStore::default();
        fallback.put("k", "stale").expect("seed fallback");
        let primary = JournalCheckingPrimary {
            inner: MemorySecretStore::default(),
            fallback: &fallback,
        };

        chained_put(&primary, &fallback, "k", "fresh").expect("journaled put");

        assert_eq!(primary.get("k").expect("primary"), Some("fresh".to_owned()));
        assert_eq!(fallback.get("k").expect("fallback"), None);
    }

    #[test]
    fn chained_put_keeps_fresh_journal_authoritative_when_cleanup_fails() {
        let primary = MemorySecretStore::default();
        let fallback = DeleteRejectingSecretStore::default();
        fallback.put("k", "stale").expect("seed fallback");

        chained_put(&primary, &fallback, "k", "fresh")
            .expect("fresh fallback remains a complete authoritative journal");

        assert_eq!(primary.get("k").expect("primary"), Some("fresh".to_owned()));
        assert_eq!(
            fallback.get("k").expect("fallback"),
            Some("stale".to_owned())
        );
        assert_eq!(
            fallback
                .get(fallback_journal_key("k").as_str())
                .expect("journal"),
            Some("fresh".to_owned())
        );
        assert_eq!(
            chained_get(&primary, &fallback, "k").expect("journal read"),
            Some("fresh".to_owned())
        );
    }

    #[test]
    fn chained_put_recovers_when_fallback_delete_crosses_before_reporting_failure() {
        let primary = MemorySecretStore::default();
        let fallback = DeleteAfterCommitRejectingSecretStore::default();
        fallback
            .put("k", "stale")
            .expect("seed authoritative fallback");

        chained_put(&primary, &fallback, "k", "fresh")
            .expect("fresh primary is authoritative after crossed cleanup");

        assert_eq!(
            primary.get("k").expect("primary read"),
            Some("fresh".to_owned())
        );
        assert_eq!(fallback.get("k").expect("fallback read"), None);
        assert_eq!(
            fallback
                .get(fallback_journal_key("k").as_str())
                .expect("journal read"),
            Some("fresh".to_owned())
        );
        assert_eq!(
            chained_get(&primary, &fallback, "k").expect("journal recovery"),
            Some("fresh".to_owned())
        );
    }

    #[test]
    fn chained_put_recovers_across_journal_delete_failure_before_or_after_commit() {
        let primary = MemorySecretStore::default();
        let retained = JournalDeleteRejectingSecretStore::default();
        retained.put("k", "old").expect("seed fallback");
        chained_put(&primary, &retained, "k", "fresh")
            .expect("retained fresh journal remains authoritative");
        assert_eq!(
            chained_get(&primary, &retained, "k").expect("retained journal"),
            Some("fresh".to_owned())
        );

        let primary = MemorySecretStore::default();
        let crossed = JournalDeleteAfterCommitRejectingSecretStore::default();
        crossed.put("k", "old").expect("seed fallback");
        chained_put(&primary, &crossed, "k", "fresh")
            .expect("fresh primary survives crossed journal cleanup");
        assert_eq!(
            crossed
                .get(fallback_journal_key("k").as_str())
                .expect("journal"),
            None
        );
        assert_eq!(
            chained_get(&primary, &crossed, "k").expect("primary recovery"),
            Some("fresh".to_owned())
        );
    }

    #[test]
    fn chained_put_reports_both_failures_when_no_store_accepts_the_secret() {
        let secret = "must-not-appear-in-errors";
        let primary = PutRejectingMemorySecretStore::default();
        let fallback = PutRejectingMemorySecretStore::default();
        let error = chained_put(&primary, &fallback, "k", secret).expect_err("double failure");
        let message = error.to_string();
        assert!(message.contains("rejected the write"), "{message}");
        assert!(message.contains("fallback write also failed"), "{message}");
        assert!(!message.contains(secret), "{message}");
    }

    fn crash_at(
        target: CredentialWriteCheckpoint,
    ) -> impl FnMut(CredentialWriteCheckpoint) -> Result<()> {
        move |checkpoint| {
            if checkpoint == target {
                Err(AuthError::SecretStore(format!(
                    "simulated crash at {checkpoint:?}"
                )))
            } else {
                Ok(())
            }
        }
    }

    fn assert_crash_recovers(
        primary: &dyn SecretStore,
        fallback: &dyn SecretStore,
        checkpoint: CredentialWriteCheckpoint,
        expected: &str,
        expected_journal: Option<&str>,
    ) {
        let error =
            chained_put_with_checkpoint(primary, fallback, "k", "fresh", crash_at(checkpoint))
                .expect_err("checkpoint must stop the write");
        assert!(error.to_string().contains("simulated crash"), "{error}");
        assert_eq!(
            chained_get(primary, fallback, "k").expect("recoverable state"),
            Some(expected.to_owned()),
            "unexpected recovery at {checkpoint:?}"
        );
        assert_eq!(
            fallback
                .get(fallback_journal_key("k").as_str())
                .expect("journal state"),
            expected_journal.map(str::to_owned),
            "unexpected sidecar journal state at {checkpoint:?}"
        );
    }

    #[test]
    fn chained_put_recovers_one_complete_old_or_new_value_at_every_crash_boundary() {
        for (checkpoint, expected, expected_journal) in [
            (CredentialWriteCheckpoint::FallbackInspected, "old", None),
            (
                CredentialWriteCheckpoint::FallbackJournalCommitted,
                "fresh",
                Some("fresh"),
            ),
            (
                CredentialWriteCheckpoint::PrimaryWriteCommitted,
                "fresh",
                Some("fresh"),
            ),
            (
                CredentialWriteCheckpoint::LegacyFallbackCleared,
                "fresh",
                Some("fresh"),
            ),
            (
                CredentialWriteCheckpoint::FallbackJournalCleared,
                "fresh",
                None,
            ),
        ] {
            let primary = MemorySecretStore::default();
            let fallback = MemorySecretStore::default();
            primary.put("k", "old").expect("seed primary");
            fallback.put("k", "old").expect("seed fallback");
            assert_crash_recovers(&primary, &fallback, checkpoint, expected, expected_journal);
        }

        let primary = MemorySecretStore::default();
        let fallback = DeleteRejectingSecretStore::default();
        primary.put("k", "old").expect("seed primary");
        fallback.put("k", "old").expect("seed fallback");
        assert_crash_recovers(
            &primary,
            &fallback,
            CredentialWriteCheckpoint::LegacyFallbackCleanupFailed,
            "fresh",
            Some("fresh"),
        );

        let primary = MemorySecretStore::default();
        let fallback = JournalDeleteRejectingSecretStore::default();
        primary.put("k", "old").expect("seed primary");
        fallback.put("k", "old").expect("seed fallback");
        assert_crash_recovers(
            &primary,
            &fallback,
            CredentialWriteCheckpoint::FallbackJournalCleanupFailed,
            "fresh",
            Some("fresh"),
        );

        for (checkpoint, expected, expected_journal) in [
            (CredentialWriteCheckpoint::FallbackInspected, "old", None),
            (CredentialWriteCheckpoint::PrimaryWriteRejected, "old", None),
            (
                CredentialWriteCheckpoint::FallbackJournalCommitted,
                "fresh",
                Some("fresh"),
            ),
        ] {
            let primary = PutRejectingMemorySecretStore::default();
            let fallback = MemorySecretStore::default();
            primary.inner.put("k", "old").expect("seed primary");
            assert_crash_recovers(&primary, &fallback, checkpoint, expected, expected_journal);
        }

        let primary = MemorySecretStore::default();
        let fallback = MemorySecretStore::default();
        primary.put("k", "old").expect("seed primary");
        assert_crash_recovers(
            &primary,
            &fallback,
            CredentialWriteCheckpoint::PrimaryWriteCommitted,
            "fresh",
            None,
        );

        let primary = PutRejectingMemorySecretStore::default();
        let fallback = MemorySecretStore::default();
        primary.inner.put("k", "old").expect("seed primary");
        fallback.put("k", "old").expect("seed fallback");
        assert_crash_recovers(
            &primary,
            &fallback,
            CredentialWriteCheckpoint::PrimaryWriteRejected,
            "fresh",
            Some("fresh"),
        );
    }

    #[test]
    fn chained_get_trusts_explicit_journal_and_surfaces_primary_error_on_double_miss() {
        let primary = MemorySecretStore::default();
        let fallback = MemorySecretStore::default();
        primary.put("k", "primary-value").expect("seed primary");
        fallback
            .put(fallback_journal_key("k").as_str(), "fallback-value")
            .expect("seed explicit journal");

        assert_eq!(
            chained_get(&primary, &fallback, "k").expect("fallback wins"),
            Some("fallback-value".to_owned())
        );
        let miss = chained_get(&RejectingSecretStore, &MemorySecretStore::default(), "k")
            .expect_err("primary error surfaces when fallback misses");
        assert!(miss.to_string().contains("rejected the read"));
    }

    #[test]
    fn chained_get_fails_closed_on_ambiguous_legacy_dual_store_credentials() {
        let primary = MemorySecretStore::default();
        let fallback = MemorySecretStore::default();
        primary.put("k", "primary-value").expect("seed primary");
        fallback.put("k", "fallback-value").expect("seed fallback");

        let error = chained_get(&primary, &fallback, "k")
            .expect_err("unequal legacy credentials must not select a generation");
        let message = error.to_string();
        assert!(message.contains("ambiguous"), "{message}");
        assert!(!message.contains("primary-value"), "{message}");
        assert!(!message.contains("fallback-value"), "{message}");

        fallback
            .put("k", "primary-value")
            .expect("equalize legacy fallback");
        assert_eq!(
            chained_get(&primary, &fallback, "k").expect("equal dual values are safe"),
            Some("primary-value".to_owned())
        );
    }

    #[test]
    fn chained_locate_fails_closed_on_ambiguous_legacy_dual_store_credentials() {
        let primary = MemorySecretStore::default();
        let fallback = MemorySecretStore::default();
        primary.put("k", "primary-value").expect("seed primary");
        fallback.put("k", "fallback-value").expect("seed fallback");

        let error = chained_locate(&primary, &fallback, "k")
            .expect_err("ambiguous credentials must not report a healthy backend");
        let message = error.to_string();
        assert!(message.contains("ambiguous"), "{message}");
        assert!(!message.contains("primary-value"), "{message}");
        assert!(!message.contains("fallback-value"), "{message}");
    }

    #[test]
    fn chained_delete_still_clears_the_fallback_when_primary_fails() {
        let fallback = MemorySecretStore::default();
        fallback.put("k", "v").expect("seed fallback");
        fallback
            .put(fallback_journal_key("k").as_str(), "journal")
            .expect("seed journal");

        let error = chained_delete(&RejectingSecretStore, &fallback, "k")
            .expect_err("primary delete failure surfaces");
        assert!(error.to_string().contains("rejected the delete"));
        assert_eq!(fallback.get("k").expect("fallback"), None);
        assert_eq!(
            fallback
                .get(fallback_journal_key("k").as_str())
                .expect("journal"),
            None
        );
    }

    #[test]
    fn chained_delete_clears_primary_legacy_and_journal_on_success() {
        let primary = MemorySecretStore::default();
        let fallback = MemorySecretStore::default();
        let journal_key = fallback_journal_key("k");
        primary.put("k", "fresh").expect("seed primary");
        fallback.put("k", "fresh").expect("seed legacy fallback");
        fallback
            .put(journal_key.as_str(), "fresh")
            .expect("seed journal");

        chained_delete(&primary, &fallback, "k").expect("ordinary chained delete");

        assert_eq!(primary.get("k").expect("primary state"), None);
        assert_eq!(fallback.get("k").expect("legacy fallback state"), None);
        assert_eq!(
            fallback.get(journal_key.as_str()).expect("journal state"),
            None
        );
    }

    #[test]
    fn chained_delete_preserves_fresh_journal_when_legacy_cleanup_fails() {
        let primary = MemorySecretStore::default();
        let fallback = LegacyDeleteRejectingSecretStore::default();
        let journal_key = fallback_journal_key("k");
        primary.put("k", "fresh").expect("seed fresh primary");
        fallback.put("k", "stale").expect("seed stale fallback");
        fallback
            .put(journal_key.as_str(), "fresh")
            .expect("seed fresh journal");

        let error = chained_delete(&primary, &fallback, "k")
            .expect_err("legacy fallback cleanup failure must surface");

        assert!(
            error
                .to_string()
                .contains("legacy fallback delete rejected")
        );
        assert_eq!(primary.get("k").expect("primary state"), None);
        assert_eq!(
            fallback.get(journal_key.as_str()).expect("journal state"),
            Some("fresh".to_owned()),
            "fresh journal must survive until stale legacy fallback cleanup succeeds"
        );
        assert_eq!(
            chained_get(&primary, &fallback, "k").expect("recoverable credential"),
            Some("fresh".to_owned()),
            "failed logout must not make stale legacy state authoritative"
        );
        assert_eq!(
            fallback.delete_attempts(),
            vec!["k".to_owned()],
            "primary and legacy cleanup must be attempted without deleting the authoritative journal"
        );
    }

    #[test]
    fn chained_locate_reports_an_explicit_journal_as_fallback_state() {
        let primary = MemorySecretStore::default();
        let fallback = MemorySecretStore::default();
        fallback
            .put(fallback_journal_key("k").as_str(), "fresh")
            .expect("seed journal");

        assert_eq!(
            chained_locate(&primary, &fallback, "k").expect("locate"),
            Some(SecretBackend::FallbackFile)
        );
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

    #[cfg(unix)]
    #[test]
    fn file_secret_store_process_crash_boundaries_expose_one_complete_old_or_new_value() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = FileSecretStore::new(root.path().join("secrets"));
        store.put("k", "old").expect("seed committed value");

        let mut observed_synced_stage = false;
        let error = store
            .put_with_checkpoint("k", "fresh", |checkpoint| {
                if checkpoint != FileSecretWriteCheckpoint::StagedFileSynced {
                    return Ok(());
                }
                observed_synced_stage = true;
                let staging = fs::read_dir(store.root())
                    .expect("journal directory")
                    .map(|entry| entry.expect("journal entry").path())
                    .find(|path| {
                        path.file_name()
                            .is_some_and(|name| name.to_string_lossy().contains(".tmp-"))
                    })
                    .expect("synced staging file");
                assert_eq!(
                    fs::read_to_string(&staging).expect("complete staging value"),
                    "fresh"
                );
                let mode = fs::metadata(staging)
                    .expect("staging metadata")
                    .permissions()
                    .mode();
                assert_eq!(mode & 0o777, 0o600, "staging file must be 0600");
                assert_eq!(
                    store.get("k").expect("committed value"),
                    Some("old".to_owned()),
                    "the committed path must remain old before atomic rename"
                );
                Err(AuthError::SecretStore(
                    "simulated process crash before atomic rename".to_owned(),
                ))
            })
            .expect_err("stage checkpoint must stop the write");
        assert!(error.to_string().contains("simulated process crash"));
        assert!(observed_synced_stage);
        assert_eq!(
            store.get("k").expect("old recovery"),
            Some("old".to_owned())
        );
        assert!(
            fs::read_dir(store.root())
                .expect("journal directory")
                .all(|entry| !entry
                    .expect("journal entry")
                    .file_name()
                    .to_string_lossy()
                    .contains(".tmp-")),
            "failed process simulation must clean its staging artifact"
        );

        let error = store
            .put_with_checkpoint("k", "fresh", |checkpoint| {
                if checkpoint == FileSecretWriteCheckpoint::AtomicRenameCommitted {
                    assert_eq!(
                        store.get("k").expect("committed value"),
                        Some("fresh".to_owned())
                    );
                    return Err(AuthError::SecretStore(
                        "simulated process crash after atomic rename".to_owned(),
                    ));
                }
                Ok(())
            })
            .expect_err("rename checkpoint must stop the write");
        assert!(error.to_string().contains("simulated process crash"));
        assert_eq!(
            store.get("k").expect("new recovery"),
            Some("fresh".to_owned())
        );
    }

    #[cfg(unix)]
    #[test]
    fn chained_fallback_journal_preserves_private_file_permissions() {
        let root = tempfile::tempdir().expect("tempdir");
        let fallback = FileSecretStore::new(root.path().join("secrets"));
        fallback
            .put("profile/default/api-token", "old")
            .expect("seed legacy fallback");

        chained_put(
            &RejectingSecretStore,
            &fallback,
            "profile/default/api-token",
            "fresh",
        )
        .expect("fallback journal");

        let dir_mode = fs::metadata(fallback.root())
            .expect("root metadata")
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o777, 0o700, "journal root must be 0700");
        let path = fallback.root().join(secret_file_name(
            fallback_journal_key("profile/default/api-token").as_str(),
        ));
        let file_mode = fs::metadata(path)
            .expect("journal metadata")
            .permissions()
            .mode();
        assert_eq!(file_mode & 0o777, 0o600, "journal file must be 0600");
        assert_eq!(
            chained_get(
                &RejectingSecretStore,
                &fallback,
                "profile/default/api-token"
            )
            .expect("journal read"),
            Some("fresh".to_owned())
        );
    }

    #[cfg(unix)]
    #[test]
    fn chained_fallback_journal_staging_fits_name_max_for_long_profile_id() {
        const NAME_MAX: usize = 255;
        let root = tempfile::tempdir().expect("tempdir");
        let fallback = FileSecretStore::new(root.path().join("secrets"));
        let profile_id = "p".repeat(108);
        let key = api_token_key(&profile_id);
        fallback
            .put(&key, "old")
            .expect("the legacy fallback key fits before journal expansion");

        let journal_key = fallback_journal_key(&key);
        let staged_component_len =
            format!("{}.tmp-{}", secret_file_name(&journal_key), Uuid::nil()).len();
        let result = chained_put(&RejectingSecretStore, &fallback, &key, "fresh");
        assert!(
            result.is_ok() && staged_component_len <= NAME_MAX,
            "keyring-failure journal staging exceeded NAME_MAX: component_len={staged_component_len}, result={result:?}"
        );
        assert_eq!(
            chained_get(&RejectingSecretStore, &fallback, &key)
                .expect("bounded journal remains authoritative"),
            Some("fresh".to_owned())
        );
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
