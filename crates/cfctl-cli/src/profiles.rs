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
                CliError::Input(
                    "no active profile; run `cfctl auth import-api-token --account <id> --stdin` or `cfctl auth login --client-id <id>`"
                        .to_owned(),
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
