//! Borrowed source/config identity shared by four typed D1 consumers. This is
//! neither a serialized operation contract nor migration/recovery authority.
use super::{Result, WorkspaceError, git_blob, git_optional, inspect_git};
use cfctl_core::{
    WorkspaceD1EvidenceContractV1, WorkspaceD1MigrationContractV1,
    WorkspaceD1PolicyProjectionContractV1, WorkspaceD1ReplyAdmissionContractV1,
};
use sha2::{Digest as _, Sha256};
use std::path::{Component, Path};

#[derive(Clone, Copy)]
pub struct D1ConfigSource<'a> {
    pub repository_root: &'a str,
    pub repository_head: &'a str,
    pub repository_origin: &'a str,
    pub operation_pack_path: &'a str,
    pub operation_pack_sha256: &'a str,
    pub config_template_path: &'a str,
    pub config_template_sha256: &'a str,
    pub production_config_path: &'a str,
    pub database_binding: &'a str,
    pub wrangler_version: &'a str,
}

macro_rules! borrow_source {
    ($($contract:ty),+ $(,)?) => {$ (
        impl<'a> From<&'a $contract> for D1ConfigSource<'a> {
            fn from(contract: &'a $contract) -> Self {
                Self {
                    repository_root: &contract.repository_root,
                    repository_head: &contract.repository_head,
                    repository_origin: &contract.repository_origin,
                    operation_pack_path: &contract.operation_pack_path,
                    operation_pack_sha256: &contract.operation_pack_sha256,
                    config_template_path: &contract.config_template_path,
                    config_template_sha256: &contract.config_template_sha256,
                    production_config_path: &contract.production_config_path,
                    database_binding: &contract.database_binding,
                    wrangler_version: &contract.wrangler_version,
                }
            }
        }
    )+};
}
borrow_source!(
    WorkspaceD1MigrationContractV1,
    WorkspaceD1EvidenceContractV1,
    WorkspaceD1PolicyProjectionContractV1,
    WorkspaceD1ReplyAdmissionContractV1
);

impl D1ConfigSource<'_> {
    /// Recheck the selected execution source and return its committed template.
    /// Committed inspection does not call this execution-only operation.
    pub fn execution_template(self) -> Result<Vec<u8>> {
        let rejected = || {
            WorkspaceError::DiscoveryInvariant(
            "workspace D1 configuration source identity drifted; repeat selection from the clean committed source".to_owned()
        )
        };
        let root = Path::new(self.repository_root);
        if root.canonicalize().map_err(|_| rejected())? != root {
            return Err(rejected());
        }
        let git = inspect_git(root)?;
        if git.dirty
            || git.head.as_deref() != Some(self.repository_head)
            || git_optional(root, &["config", "--get", "remote.origin.url"])?.as_deref()
                != Some(self.repository_origin)
        {
            return Err(rejected());
        }
        let committed = |relative: &str, digest: &str| -> Result<Vec<u8>> {
            let path = Path::new(relative);
            if path.as_os_str().is_empty()
                || path
                    .components()
                    .any(|c| !matches!(c, Component::Normal(_)))
            {
                return Err(rejected());
            }
            let bytes = git_blob(root, path)?.ok_or_else(rejected)?;
            // Typed binders own public source limits. The separate private
            // production-config capture limit must not narrow these Git blobs.
            if format!("sha256:{}", hex::encode(Sha256::digest(&bytes))) != digest {
                return Err(rejected());
            }
            Ok(bytes)
        };
        committed(self.operation_pack_path, self.operation_pack_sha256)?;
        committed(self.config_template_path, self.config_template_sha256)
    }
}
