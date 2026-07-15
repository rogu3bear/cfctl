use std::collections::BTreeMap;

use cfctl_auth::{OAuthClientConfig, ProfileMetadata};
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
                CliError::Input("no active profile; run `cfctl auth login`".to_owned())
            })?;
        self.profiles
            .get(id)
            .ok_or_else(|| CliError::Input(format!("profile `{id}` does not exist")))
    }
}
