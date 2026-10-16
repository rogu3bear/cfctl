//! Explicit linked-checkout selection for the committed D1 read consumer.
use std::path::{Path, PathBuf};

use cfctl_core::{
    CapabilityV1,
    d1_read_inventory::{
        D1_READ_PACK_PATH, D1ReadOperationV1, D1ReadSourceBindingV1, D1ReadSourceSelectionV1,
        WorkspaceD1ReadInventoryContractV1,
    },
};

use super::{Result, WorkspaceError, git_optional, operation_identity};

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

/// A selected commit may retain older reviewed input bytes, but cannot change
/// the registered operation's authority, purpose or read inventory. Registered
/// input paths remain an ordered minimum; additional selected inputs only add
/// constraints and must validate against the selected commit's own source.
/// Each revision and input digest is validated against its own committed source;
/// neither checkout's pins are copied into the other checkout's contract.
fn same_operation_authority(
    registered: &D1ReadOperationV1,
    selected: &D1ReadOperationV1,
) -> Result<()> {
    let mut selected_paths = selected.source.iter().map(|source| &source.path);
    for required in &registered.source {
        if !selected_paths.any(|path| path == &required.path) {
            return Err(invalid(
                "selected read operation omits or reorders registered source paths",
            ));
        }
    }
    let mut comparable = selected.clone();
    comparable
        .source_revision
        .clone_from(&registered.source_revision);
    comparable.source.clone_from(&registered.source);
    if comparable != *registered {
        return Err(invalid(
            "selected read operation changes registered authority, purpose or inventory",
        ));
    }
    Ok(())
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
    let registered = super::d1_reads::load_selected(
        std::slice::from_ref(&owner),
        capability_id,
        operation_identity::WorkspaceOperationLoad::Inspect,
    )?
    .and_then(|c| c.workspace_d1_read_inventory)
    .ok_or_else(|| invalid("registered D1 read operation disappeared"))?;
    let mut capability = super::d1_reads::load_selected(&[checkout], capability_id, mode)?
        .ok_or_else(|| invalid("selected D1 read operation disappeared"))?;
    let contract = capability
        .workspace_d1_read_inventory
        .as_mut()
        .ok_or_else(|| invalid("source selection is supported only for committed D1 reads"))?;
    same_operation_authority(&registered.operation, &contract.operation)?;
    contract.source_binding = Some(binding);
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
    let checkout = PathBuf::from(&binding.selection.checkout_root);
    if operation_identity::unique_typed_owner(
        std::slice::from_ref(&checkout),
        D1_READ_PACK_PATH,
        &contract.operation.id,
    )?
    .as_ref()
        != Some(&checkout)
        || bind(&owner, &binding.selection)? != *binding
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
    // Registered HEAD/tree remain pinned. Read their committed pack without
    // consulting unrelated dirty files or revalidating every input per query.
    // Selected current bytes are checked independently at the query boundary.
    let (pack, _) =
        super::d1_reads::load_pack(&owner, operation_identity::WorkspaceOperationLoad::Inspect)?;
    let registered = pack
        .operation
        .iter()
        .find(|operation| operation.id == contract.operation.id)
        .ok_or_else(|| invalid("registered D1 read operation disappeared"))?;
    same_operation_authority(registered, &contract.operation)?;
    Ok(())
}

fn unique_read_owner(candidates: &[PathBuf], id: &str) -> Result<PathBuf> {
    operation_identity::unique_typed_owner(candidates, D1_READ_PACK_PATH, id)?
        .ok_or_else(|| invalid("source selection requires one registered D1 read operation owner"))
}
