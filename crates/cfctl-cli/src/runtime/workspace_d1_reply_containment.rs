//! Versioned containment boundary. Source, authority, evidence and transport are
//! independently bound before the fixed atomic mutation can be dispatched.

use super::prelude::{CliError, ProfileMetadata, Result, StateStore};
use cfctl_core::reply_lifecycle::containment::ReplyContainmentAuthorityV3;
use cfctl_core::{CapabilityV1, WorkspaceD1ReplyContainmentContractV3};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};

mod compiler;
mod execution;
mod guide;
mod planning;
mod reading;
mod stage;
#[cfg(test)]
mod test_support;
mod transport;
pub(super) use execution::{run, verify};
pub(super) use guide::{guide_commands, guide_next_action, guide_summary};
pub(super) use planning::{prepare_plan_target, validate_bound_plan};
pub(super) use reading::{project_private_query_rows, read, seal_read};

fn rejected() -> CliError {
    CliError::Input(
        "containment source, authority, receipt or fixed execution binding did not qualify".into(),
    )
}
fn hash(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
fn contract(capability: &CapabilityV1) -> Result<&WorkspaceD1ReplyContainmentContractV3> {
    capability.reply_containment_contract().ok_or_else(rejected)
}
fn rebind_source(store: &StateStore, capability: &CapabilityV1) -> Result<()> {
    let current = cfctl_workspace::load_workspace_d1_reply_containment_capability(
        &store.workspace_roots()?,
        &capability.id,
    )?
    .ok_or_else(rejected)?;
    if current.reply_containment_contract() != capability.reply_containment_contract() {
        return Err(rejected());
    }
    Ok(())
}
fn authority(
    profile: &ProfileMetadata,
    account: &str,
    database: &str,
) -> Result<ReplyContainmentAuthorityV3> {
    let generation = super::read_execution::credential_generation_for_read(profile)?;
    let path = std::env::current_exe().map_err(|_| rejected())?;
    let bytes = fs::read(path).map_err(|_| rejected())?;
    Ok(ReplyContainmentAuthorityV3 {
        cfctl_build_sha256: hash(&bytes),
        profile_sha256: hash(profile.id.as_bytes()),
        account_sha256: hash(account.as_bytes()),
        production_database_sha256: hash(database.as_bytes()),
        credential_generation_sha256: hash(generation.as_bytes()),
    })
}
fn config_value(config: &super::workspace_d1_config::ValidatedConfig) -> Value {
    json!({"path":config.path,"sha256":config.sha256,"database_name":config.database_name,"database_id":config.database_id})
}
pub(super) fn local_artifact_paths(capability: &CapabilityV1) -> Result<Option<Vec<PathBuf>>> {
    let Some(contract) = capability.reply_containment_contract() else {
        return Ok(None);
    };
    Ok(Some(vec![
        Path::new(&contract.repository_root)
            .join(&contract.operation_pack_path)
            .parent()
            .ok_or_else(rejected)?
            .to_path_buf(),
    ]))
}
