//! Committed pack ownership, independent of a selected execution binder.
use std::path::{Path, PathBuf};

use super::{Result, WorkspaceError, git_blob, operation_pack};

/// A declaration is an ownership claim even if its execution inputs are not
/// valid. Binder precedence must never hide another committed claim, including
/// another declaration in the same pack or a different carrier in one checkout.
pub(super) fn unique_pack_claim(
    candidates: &[PathBuf],
    capability_id: &str,
) -> Result<Option<(PathBuf, PathBuf)>> {
    let mut selected = None;
    for repository in candidates {
        for path in operation_pack::committed_pack_paths(repository)? {
            let Some(bytes) = git_blob(repository, &path)? else {
                continue;
            };
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| invalid("committed operation pack is not UTF-8"))?;
            let document: toml::Value = toml::from_str(text)
                .map_err(|_| invalid("committed operation pack is invalid TOML"))?;
            if !typed_pack(&path)
                && !operation_pack::declares_workspace_operation_contract(&document)
            {
                continue;
            }
            for _ in 0..matching_ids(&document, capability_id) {
                if selected.is_some() {
                    return Err(invalid(&format!(
                        "workspace operation id `{capability_id}` is ambiguous across committed pack declarations"
                    )));
                }
                selected = Some((repository.clone(), path.clone()));
            }
        }
        // The ingress contract is another committed carrier, not a binder
        // fallback that can override an existing pack declaration.
        if super::reply_subdomain_ingress::claims_identity(repository, capability_id)? {
            if selected.is_some() {
                return Err(invalid(&format!(
                    "workspace operation id `{capability_id}` is ambiguous across committed pack declarations"
                )));
            }
            selected = Some((repository.clone(), super::reply_subdomain_ingress::SURFACE_PATH.into()));
        }
    }
    Ok(selected)
}

fn typed_pack(path: &Path) -> bool {
    [
        super::d1_operation::PACK_RELATIVE_PATH,
        cfctl_core::workspace_d1::transition::admission::PACK_PATH,
        super::d1_policy_projection::PACK_RELATIVE_PATH,
        super::d1_reply_admission::PACK_RELATIVE_PATH,
        cfctl_core::d1_read_inventory::D1_READ_PACK_PATH,
        super::d1_evidence::PACK_RELATIVE_PATH,
    ]
    .into_iter()
    .any(|name| path == Path::new(name))
}

fn matching_ids(document: &toml::Value, id: &str) -> usize {
    document
        .get("operation")
        .and_then(toml::Value::as_array)
        .map_or(0, |operations| {
            operations
                .iter()
                .filter(|operation| operation.get("id").and_then(toml::Value::as_str) == Some(id))
                .count()
        })
}

fn invalid(message: &str) -> WorkspaceError {
    WorkspaceError::DiscoveryInvariant(message.to_owned())
}
