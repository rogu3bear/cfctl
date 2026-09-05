//! Explicit platform/fallback or private credential selection.
use super::{
    AuthCredential, AuthError, CredentialUnavailableReason, FileSecretStore, KeyringSecretStore,
    MemorySecretStore, ProfileKind, ProfileMetadata, Result, SecretBackend, SecretStore, Uuid,
    api_token_key, authoritative_fallback_get, chained_delete, chained_put,
    decode_selected_credential, delete_authoritative_fallback_key, fallback_journal_key,
    global_key, oauth_key, profile_credential_key, secret_file_name,
};
use std::{
    fmt,
    path::{Path, PathBuf},
    sync::Arc,
};

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
#[derive(Clone)]
pub struct PlatformSecretStore {
    keyring: Arc<dyn SecretStore>,
    pub(super) fallback: FileSecretStore,
    private: Option<Arc<dyn SecretStore>>,
}

impl fmt::Debug for PlatformSecretStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlatformSecretStore")
            .field("keyring", &"[platform secret store]")
            .field("fallback", &self.fallback)
            .field("private", &self.private.is_some())
            .finish()
    }
}

impl PlatformSecretStore {
    #[must_use]
    pub fn new(fallback_root: PathBuf) -> Self {
        Self {
            keyring: Arc::new(KeyringSecretStore),
            fallback: FileSecretStore::new(fallback_root),
            private: None,
        }
    }

    /// Select explicit private storage even before its first credential exists.
    #[must_use]
    pub fn private_only(root: PathBuf, store: Arc<dyn SecretStore>) -> Self {
        Self {
            keyring: Arc::new(MemorySecretStore::default()),
            fallback: FileSecretStore::new(root),
            private: Some(store),
        }
    }

    #[must_use]
    pub fn is_private(&self) -> bool {
        self.private.is_some()
    }

    #[cfg(test)]
    pub(super) fn with_keyring(fallback_root: PathBuf, keyring: Arc<dyn SecretStore>) -> Self {
        Self {
            keyring,
            fallback: FileSecretStore::new(fallback_root),
            private: None,
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
        if self.private.is_some() {
            return Err("not selected: explicit private storage".to_owned());
        }
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
        if let Some(store) = &self.private {
            return store.put(key, value);
        }
        if self.fallback_secret_count()? > 0 {
            return self.fallback.put(fallback_journal_key(key).as_str(), value);
        }
        chained_put(self.keyring.as_ref(), &self.fallback, key, value)
    }

    fn get(&self, key: &str) -> Result<Option<String>> {
        if let Some(store) = &self.private {
            return store.get(key);
        }
        if self.fallback_secret_count()? > 0 {
            return authoritative_fallback_get(&self.fallback, key);
        }
        self.keyring.get(key)
    }

    fn delete(&self, key: &str) -> Result<()> {
        if let Some(store) = &self.private {
            return store.delete(key);
        }
        if self.fallback_secret_count()? > 0 {
            return delete_authoritative_fallback_key(&self.fallback, key);
        }
        chained_delete(self.keyring.as_ref(), &self.fallback, key)
    }

    fn locate(&self, key: &str) -> Result<Option<SecretBackend>> {
        if let Some(store) = &self.private {
            return store.locate(key);
        }
        if self.fallback_secret_count()? > 0 {
            return authoritative_fallback_get(&self.fallback, key)
                .map(|value| value.map(|_| SecretBackend::FallbackFile));
        }
        self.keyring.locate(key)
    }

    fn load_profile_credential(&self, profile: &ProfileMetadata) -> Result<AuthCredential> {
        if profile.kind == ProfileKind::OAuth {
            let tokens = self.load_profile_oauth_tokens(profile)?;
            return Ok(AuthCredential::Bearer {
                token: tokens.access_token,
            });
        }
        let key = profile_credential_key(profile)?;
        let encoded = self
            .get(&key)?
            .ok_or_else(|| AuthError::CredentialUnavailable {
                profile_id: profile.id.clone(),
                reason: CredentialUnavailableReason::MissingSelectedFallback,
            })?;
        decode_selected_credential(profile, encoded)
    }

    fn delete_profile(&self, profile_id: &str) -> Result<()> {
        if let Some(store) = &self.private {
            return store.delete_profile(profile_id);
        }
        if self.fallback_secret_count()? > 0 {
            for key in [
                oauth_key(profile_id),
                api_token_key(profile_id),
                global_key(profile_id),
            ] {
                delete_authoritative_fallback_key(&self.fallback, &key)?;
            }
            return Ok(());
        }
        self.keyring.delete_profile(profile_id)
    }

    fn repair_profile_credential_access(&self, profile: &ProfileMetadata) -> Result<()> {
        if self.private.is_some() {
            return Err(AuthError::SecretStore(
                "platform repair is unavailable in explicit private mode".to_owned(),
            ));
        }
        let key = profile_credential_key(profile)?;
        let value = self
            .keyring
            .get(&key)?
            .ok_or_else(|| AuthError::CredentialUnavailable {
                profile_id: profile.id.clone(),
                reason: CredentialUnavailableReason::MissingSelectedFallback,
            })?;
        decode_selected_credential(profile, value.clone())?;
        self.keyring.put(&key, &value)
    }
}

/// Read only an explicitly supplied fallback reader; never consult the platform.
/// The reader receives encoded filenames, with the journal checked first.
pub fn export_fallback_profile(
    profile: &ProfileMetadata,
    mut read: impl FnMut(&str) -> Result<Option<String>>,
) -> Result<Option<(String, String)>> {
    let key = profile_credential_key(profile)?;
    let value = match read(&secret_file_name(&fallback_journal_key(&key)))? {
        Some(value) => Some(value),
        None => read(&secret_file_name(&key))?,
    };
    value
        .map(|value| {
            decode_selected_credential(profile, value.clone())?;
            Ok((key, value))
        })
        .transpose()
}
