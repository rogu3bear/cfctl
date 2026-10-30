//! Exact source binding for the three containment-v3 lifecycle operations.

use std::{collections::BTreeSet, path::Path};

use cfctl_core::{CapabilityV1, ReplyContainmentSchemaV3, WorkspaceD1ReplyContainmentContractV3};

use super::{
    Result, WorkspaceError,
    d1_operation::{committed_file, safe_relative},
    git_optional,
    operation_identity::WorkspaceOperationLoad,
};

mod capability;
mod declaration;

pub(super) const PACK_RELATIVE_PATH: &str = ".cfctl/operations/d1-reply-containment.toml";

pub fn load_workspace_d1_reply_containment_capability(
    roots: &[std::path::PathBuf],
    id: &str,
) -> Result<Option<CapabilityV1>> {
    Ok(super::load_workspace_operation_capability(roots, id)?
        .filter(|capability| capability.reply_containment_contract().is_some()))
}

pub(super) fn load_selected(
    candidates: &[std::path::PathBuf],
    id: &str,
    mode: WorkspaceOperationLoad,
) -> Result<Option<CapabilityV1>> {
    let selected = super::operation_identity::select(candidates, PACK_RELATIVE_PATH, id)?;
    if selected.len() > 1 {
        return Err(invalid(
            "containment operation has more than one source owner",
        ));
    }
    let Some(repository) = selected.first() else {
        return Ok(None);
    };
    if mode.requires_clean_worktree() && repository.git.dirty {
        return Err(invalid("containment operation repository must be clean"));
    }
    let root = &repository.path;
    let bytes = bounded(root, PACK_RELATIVE_PATH, mode)?;
    let pack: declaration::Pack = toml::from_str(
        std::str::from_utf8(&bytes).map_err(|_| invalid("containment pack must be UTF-8"))?,
    )
    .map_err(|_| invalid("containment pack does not match its closed declaration"))?;
    if pack.schema_version != 1
        || pack.operation.len() != 3
        || pack
            .operation
            .iter()
            .map(|o| o.id.as_str())
            .collect::<BTreeSet<_>>()
            .len()
            != 3
    {
        return Err(invalid(
            "containment pack requires exactly three distinct operations",
        ));
    }
    for operation in &pack.operation {
        operation.validate()?;
    }
    let Some(first) = pack.operation.first() else {
        return Err(invalid("containment operation population is empty"));
    };
    if pack
        .operation
        .iter()
        .any(|operation| !operation.same_source_binding(first))
    {
        return Err(invalid(
            "containment operations have different source bindings",
        ));
    }
    let Some(operation) = pack.operation.iter().find(|operation| operation.id == id) else {
        return Ok(None);
    };
    let contract = bind(root, operation, &bytes, mode)?;
    Ok(Some(capability::from_declaration(operation, contract)))
}

fn bind(
    root: &Path,
    operation: &declaration::Operation,
    pack: &[u8],
    mode: WorkspaceOperationLoad,
) -> Result<WorkspaceD1ReplyContainmentContractV3> {
    let identity = |arguments: &[&str]| {
        git_optional(root, arguments)?
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid("containment source identity is unavailable"))
    };
    let head = identity(&["rev-parse", "HEAD"])?;
    let tree = identity(&["rev-parse", "HEAD^{tree}"])?;
    if !declaration::lower_hex(&head, 40) || !declaration::lower_hex(&tree, 40) {
        return Err(invalid(
            "containment source requires exact Git object identities",
        ));
    }
    let compiler = bounded(root, &operation.compiler_path, mode)?;
    if declaration::sha256(&compiler) != operation.compiler_sha256 {
        return Err(invalid("containment compiler differs from its source pin"));
    }
    let template = bounded(root, &operation.config_template, mode)?;
    safe_relative(&operation.production_config)?;
    Ok(WorkspaceD1ReplyContainmentContractV3 {
        contract: ReplyContainmentSchemaV3::V3,
        schema_version: 3,
        operation_kind: operation.kind()?,
        repository_root: root.display().to_string(),
        repository_head: head,
        repository_tree: tree,
        repository_origin: identity(&["config", "--get", "remote.origin.url"])?,
        operation_pack_path: PACK_RELATIVE_PATH.to_owned(),
        operation_pack_sha256: declaration::sha256(pack),
        compiler_path: operation.compiler_path.clone(),
        compiler_sha256: operation.compiler_sha256.clone(),
        compiler_runtime: operation.compiler_runtime.clone(),
        compiler_runtime_version: operation.compiler_runtime_version.clone(),
        compiler_runtime_sha256: operation.compiler_runtime_sha256.clone(),
        config_template_path: operation.config_template.clone(),
        config_template_sha256: declaration::sha256(&template),
        production_config_path: operation.production_config.clone(),
        database_binding: operation.database_binding.clone(),
        wrangler_version: operation.wrangler_version.clone(),
        input_contract: operation.input_contract.clone(),
        recovery_capability_id: operation.recovery_capability_id.clone().unwrap_or_default(),
        recovery_max_age_seconds: operation.recovery_max_age_seconds.unwrap_or_default(),
        rollback_capability_id: operation.rollback_capability_id.clone().unwrap_or_default(),
    })
}

fn bounded(root: &Path, path: &str, mode: WorkspaceOperationLoad) -> Result<Vec<u8>> {
    let bytes = committed_file(root, &safe_relative(path)?, mode)?;
    if bytes.len() > 4 * 1024 * 1024 {
        return Err(invalid("containment source input exceeds its byte bound"));
    }
    Ok(bytes)
}

fn invalid(message: &str) -> WorkspaceError {
    WorkspaceError::DiscoveryInvariant(message.to_owned())
}

#[cfg(test)]
mod tests;
