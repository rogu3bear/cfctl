//! Explicit linked-checkout selection for the committed D1 read consumer.
use std::path::{Path, PathBuf};

use cfctl_core::{
    CapabilityV1,
    d1_read_inventory::{
        D1_READ_PACK_PATH, D1ReadSourceBindingV1, D1ReadSourceSelectionV1,
        WorkspaceD1ReadInventoryContractV1,
    },
};

use super::{Result, WorkspaceError, git_blob, git_optional, operation_identity};

fn invalid(message: &str) -> WorkspaceError {
    WorkspaceError::DiscoveryInvariant(message.to_owned())
}

fn git(root: &Path, args: &[&str]) -> Result<String> {
    git_optional(root, args)?.ok_or_else(|| invalid("read source Git identity is unavailable"))
}

fn canonical_repository(path: &str) -> Result<PathBuf> {
    let path = Path::new(path);
    if !path.is_absolute() {
        return Err(invalid(
            "read source checkout must be an absolute repository root",
        ));
    }
    let canonical =
        std::fs::canonicalize(path).map_err(|_| invalid("read source checkout is unavailable"))?;
    if Path::new(&git(&canonical, &["rev-parse", "--show-toplevel"])?) != canonical {
        return Err(invalid(
            "read source checkout must name its repository root",
        ));
    }
    Ok(canonical)
}

fn common_directory(root: &Path) -> Result<PathBuf> {
    let path = git(
        root,
        &["rev-parse", "--path-format=absolute", "--git-common-dir"],
    )?;
    std::fs::canonicalize(path)
        .map_err(|_| invalid("read source Git common directory is unavailable"))
}

fn bind(owner: &Path, requested: &D1ReadSourceSelectionV1) -> Result<D1ReadSourceBindingV1> {
    let checkout = canonical_repository(&requested.checkout_root)?;
    let common = common_directory(owner)?;
    if common_directory(&checkout)? != common
        || git(owner, &["config", "--get", "remote.origin.url"])?
            != git(&checkout, &["config", "--get", "remote.origin.url"])?
    {
        return Err(invalid(
            "read source checkout is not linked to its registered repository",
        ));
    }
    for expected in [&requested.head, &requested.tree] {
        if expected.len() != 40
            || !expected
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(invalid(
                "read source head and tree must be exact lowercase Git identities",
            ));
        }
    }
    if git(&checkout, &["rev-parse", "HEAD"])? != requested.head
        || git(&checkout, &["rev-parse", "HEAD^{tree}"])? != requested.tree
    {
        return Err(invalid(
            "read source checkout head or tree differs from the explicit selection",
        ));
    }
    let pack = git_blob(owner, Path::new(D1_READ_PACK_PATH))?
        .ok_or_else(|| invalid("registered read operation pack disappeared"))?;
    if git_blob(&checkout, Path::new(D1_READ_PACK_PATH))?.as_ref() != Some(&pack) {
        return Err(invalid(
            "read source checkout committed pack differs from its registered owner",
        ));
    }
    Ok(D1ReadSourceBindingV1 {
        selection: D1ReadSourceSelectionV1 {
            checkout_root: checkout.display().to_string(),
            head: requested.head.clone(),
            tree: requested.tree.clone(),
        },
        registered_repository_root: owner.display().to_string(),
        registered_head: git(owner, &["rev-parse", "HEAD"])?,
        registered_tree: git(owner, &["rev-parse", "HEAD^{tree}"])?,
        git_common_directory: common.display().to_string(),
    })
}

/// Explicit selection requires one committed operation claim across carriers in
/// both the registered forest and selected checkout; it never admits a clone by URL.
pub fn load_workspace_d1_read_from_checkout(
    roots: &[PathBuf],
    capability_id: &str,
    selection: &D1ReadSourceSelectionV1,
    mode: operation_identity::WorkspaceOperationLoad,
) -> Result<CapabilityV1> {
    let candidates = operation_identity::discover(roots)?;
    let owner = unique_read_owner(&candidates, capability_id)?;
    let binding = bind(&owner, selection)?;
    let checkout = PathBuf::from(&binding.selection.checkout_root);
    unique_read_owner(std::slice::from_ref(&checkout), capability_id)?;
    let mut capability = super::d1_reads::load_selected(&[checkout], capability_id, mode)?
        .ok_or_else(|| invalid("selected D1 read operation disappeared"))?;
    capability
        .workspace_d1_read_inventory
        .as_mut()
        .ok_or_else(|| invalid("source selection is supported only for committed D1 reads"))?
        .source_binding = Some(binding);
    Ok(capability)
}

/// Recheck logical ownership at each query, without changing registration or
/// requiring the registered owner's unrelated working bytes to be clean.
pub fn revalidate_workspace_d1_read_registration(
    roots: &[PathBuf],
    contract: &WorkspaceD1ReadInventoryContractV1,
) -> Result<()> {
    let Some(binding) = &contract.source_binding else {
        return Ok(());
    };
    let owner = canonical_repository(&binding.registered_repository_root)?;
    let candidates = operation_identity::discover(roots)?;
    if unique_read_owner(&candidates, &contract.operation.id)? != owner {
        return Err(invalid(
            "selected read operation owner is no longer uniquely registered",
        ));
    }
    if bind(&owner, &binding.selection)? != *binding
        || git(&owner, &["config", "--get", "remote.origin.url"])? != contract.repository_origin
        || contract.repository_root != binding.selection.checkout_root
        || contract.repository_head != binding.selection.head
        || contract.repository_tree != binding.selection.tree
    {
        return Err(invalid(
            "selected read operation ownership or source identity changed",
        ));
    }
    unique_read_owner(
        &[PathBuf::from(&binding.selection.checkout_root)],
        &contract.operation.id,
    )?;
    Ok(())
}

fn unique_read_owner(candidates: &[PathBuf], id: &str) -> Result<PathBuf> {
    super::operation_claims::unique_pack_claim(candidates, id)?
        .filter(|(_, pack)| pack == Path::new(D1_READ_PACK_PATH))
        .map(|(owner, _)| owner)
        .ok_or_else(|| invalid("source selection requires one committed D1 read operation owner"))
}
