use std::collections::BTreeMap;

use cfctl_auth::{OAuthClientConfig, ProfileKind, ProfileMetadata};
use cfctl_storage::StateStore;
use serde::{Deserialize, Serialize};

use crate::runtime::{CliError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingLogin {
    pub profile_id: String,
    pub state: String,
    pub client: OAuthClientConfig,
    pub scopes: Vec<String>,
    pub account_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfilesConfig {
    pub schema_version: u8,
    pub current_profile: Option<String>,
    pub profiles: BTreeMap<String, ProfileMetadata>,
    pub pending_logins: BTreeMap<String, PendingLogin>,
}

impl Default for ProfilesConfig {
    fn default() -> Self {
        Self {
            schema_version: 1,
            current_profile: None,
            profiles: BTreeMap::new(),
            pending_logins: BTreeMap::new(),
        }
    }
}

impl ProfilesConfig {
    pub fn load(store: &StateStore) -> Result<Self> {
        let path = store.paths().profiles_file();
        if !path.is_file() {
            return Ok(Self::default());
        }
        Ok(store.read_json(&path)?)
    }

    pub fn save(&self, store: &StateStore) -> Result<()> {
        Ok(store.write_json(&store.paths().profiles_file(), self)?)
    }

    pub fn selected(&self, requested: Option<&str>) -> Result<&ProfileMetadata> {
        let id = requested
            .or(self.current_profile.as_deref())
            .ok_or_else(|| {
                CliError::guided(
                    "CFCTL_NO_PROFILE",
                    "no active profile is selected",
                    "Import a scoped token: `printf '%s' \"$TOKEN\" | cfctl auth import-api-token --account <account-id> --stdin`, or run `cfctl auth login --client-id <id>`. Check state with `cfctl auth status --json`.",
                )
            })?;
        let profile = self
            .profiles
            .get(id)
            .ok_or_else(|| CliError::Input(format!("profile `{id}` does not exist")))?;
        ensure_supported_profile(profile)?;
        // Every credential-using path goes through selected(); the emergency
        // global-key lane must never become ambient current-profile authority.
        if profile.kind == ProfileKind::GlobalKey && requested.is_none() {
            return Err(CliError::Input(
                "the emergency global-key profile is never selected implicitly; pass `--profile` explicitly"
                    .to_owned(),
            ));
        }
        Ok(profile)
    }
}

pub fn ensure_supported_profile(profile: &ProfileMetadata) -> Result<()> {
    if profile.kind == ProfileKind::LegacyWranglerSession {
        return Err(CliError::Input(format!(
            "legacy Wrangler session profile `{}` is no longer supported; run `cfctl auth logout {}` to remove its metadata, then `cfctl auth login --profile {}`",
            profile.id, profile.id, profile.id
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use cfctl_storage::RuntimePaths;
    use serde_json::json;

    use super::*;

    #[test]
    fn loading_pre_generation_metadata_remains_unbound_until_reauthentication() {
        let root = tempfile::tempdir().expect("runtime root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("store opens");
        store
            .write_json(
                &store.paths().profiles_file(),
                &json!({
                    "schema_version": 1,
                    "current_profile": "default",
                    "profiles": {
                        "default": {
                            "schema_version": 1,
                            "id": "default",
                            "kind": "api_token",
                            "account_id": "account-a",
                            "oauth_client_id": null,
                            "oauth_scopes": [],
                            "oauth_scope_inventory_hash": null,
                            "emergency_only": false
                        }
                    },
                    "pending_logins": {}
                }),
            )
            .expect("old metadata writes");

        let loaded = ProfilesConfig::load(&store).expect("old metadata loads");
        assert!(
            loaded.profiles["default"]
                .credential_generation_id
                .is_none()
        );
        let persisted: serde_json::Value = store
            .read_json(&store.paths().profiles_file())
            .expect("metadata reloads");
        assert!(
            persisted["profiles"]["default"]
                .get("credential_generation_id")
                .is_none()
        );
    }
}
