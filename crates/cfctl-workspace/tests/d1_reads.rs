#![allow(clippy::expect_used)]
use cfctl_core::{AdapterStatus, CapabilityAuthorityScopeV1};
use cfctl_workspace::{
    inspect_workspace_operation_capability, load_workspace_operation_capability,
    revalidate_workspace_d1_read_inventory,
};
use std::{fs, path::Path, process::Command};

const ID: &str = "example.d1-read-inventory";
const PACK: &str = ".cfctl/operations/d1-reads.toml";

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .expect("git");
    assert!(
        output.status.success(),
        "git failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("UTF-8 Git result")
        .trim()
        .to_owned()
}

fn commit(root: &Path) {
    git(root, &["add", "."]);
    git(
        root,
        &[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ],
    );
}

fn repository(root: &Path) -> String {
    fs::create_dir_all(root.join(".cfctl/operations")).expect("directory");
    git(root, &["init", "-q"]);
    git(
        root,
        &[
            "remote",
            "add",
            "origin",
            "https://example.invalid/source.git",
        ],
    );
    fs::write(
        root.join("source.txt"),
        include_str!("fixtures/d1-reads/source.txt"),
    )
    .expect("source");
    commit(root);
    let source_revision = git(root, &["rev-parse", "HEAD"]);
    fs::write(
        root.join("inventory.json"),
        include_str!("fixtures/d1-reads/inventory.json"),
    )
    .expect("inventory");
    fs::write(
        root.join(PACK),
        include_str!("fixtures/d1-reads/pack-template.toml")
            .replace("SOURCE_COMMIT_40_HEX", &source_revision),
    )
    .expect("pack");
    commit(root);
    source_revision
}

fn linked_checkout(
    owner: &Path,
    checkout: &Path,
) -> cfctl_core::d1_read_inventory::D1ReadSourceSelectionV1 {
    git(
        owner,
        &[
            "worktree",
            "add",
            "--detach",
            checkout.to_str().expect("path"),
            "HEAD",
        ],
    );
    cfctl_core::d1_read_inventory::D1ReadSourceSelectionV1 {
        checkout_root: checkout.to_str().expect("path").to_owned(),
        head: git(checkout, &["rev-parse", "HEAD"]),
        tree: git(checkout, &["rev-parse", "HEAD^{tree}"]),
    }
}

#[test]
fn explicit_linked_source_preserves_dirty_owner_and_pins_contract_identity() {
    use cfctl_workspace::{
        WorkspaceOperationLoad, load_workspace_d1_read_from_checkout,
        revalidate_workspace_d1_read_registration,
    };
    let dir = tempfile::tempdir().expect("root");
    let owner = dir.path().join("owner");
    repository(&owner);
    let selection = linked_checkout(&owner, &dir.path().join("checkout"));
    fs::write(owner.join("source.txt"), "unrelated owner work").expect("dirty owner");
    let roots = [owner.clone()];
    assert!(load_workspace_operation_capability(&roots, ID).is_err());
    let capability = load_workspace_d1_read_from_checkout(
        &roots,
        ID,
        &selection,
        WorkspaceOperationLoad::Execute,
    )
    .expect("linked source");
    let contract = capability.workspace_d1_read_inventory.expect("contract");
    let binding = contract.source_binding.as_ref().expect("source binding");
    assert_eq!(contract.repository_head, selection.head);
    assert_eq!(contract.repository_tree, selection.tree);
    assert_eq!(contract.repository_root, binding.selection.checkout_root);
    assert_eq!(
        binding.registered_repository_root,
        owner
            .canonicalize()
            .expect("canonical")
            .display()
            .to_string()
    );
    revalidate_workspace_d1_read_registration(&roots, &contract).expect("registered owner");
    revalidate_workspace_d1_read_inventory(&contract).expect("clean selected source");
    assert_eq!(
        fs::read_to_string(owner.join("source.txt")).expect("preserved"),
        "unrelated owner work"
    );
    assert!(revalidate_workspace_d1_read_registration(&[], &contract).is_err());
    fs::write(owner.join("new.txt"), "owner advances").expect("write");
    commit(&owner);
    assert!(revalidate_workspace_d1_read_registration(&roots, &contract).is_err());
}

#[test]
fn source_selection_rejects_clone_dirty_checkout_and_wrong_head_or_tree() {
    use cfctl_workspace::{WorkspaceOperationLoad, load_workspace_d1_read_from_checkout};
    let dir = tempfile::tempdir().expect("root");
    let owner = dir.path().join("owner");
    repository(&owner);
    let checkout = dir.path().join("checkout");
    let selection = linked_checkout(&owner, &checkout);
    let roots = [owner];
    for wrong_tree in [false, true] {
        let mut wrong = selection.clone();
        if wrong_tree {
            wrong.tree = "0".repeat(40);
        } else {
            wrong.head = "0".repeat(40);
        }
        assert!(
            load_workspace_d1_read_from_checkout(
                &roots,
                ID,
                &wrong,
                WorkspaceOperationLoad::Inspect
            )
            .is_err()
        );
    }
    let clone = dir.path().join("clone");
    repository(&clone);
    let mut wrong = selection.clone();
    wrong.checkout_root = clone.to_str().expect("path").to_owned();
    wrong.head = git(&clone, &["rev-parse", "HEAD"]);
    wrong.tree = git(&clone, &["rev-parse", "HEAD^{tree}"]);
    assert!(
        load_workspace_d1_read_from_checkout(&roots, ID, &wrong, WorkspaceOperationLoad::Inspect)
            .is_err()
    );
    fs::write(checkout.join("source.txt"), "dirty selected source").expect("write");
    assert!(
        load_workspace_d1_read_from_checkout(
            &roots,
            ID,
            &selection,
            WorkspaceOperationLoad::Execute
        )
        .is_err()
    );
    // Inspection remains committed-blob inspection; it does not authorize call.
    assert!(
        load_workspace_d1_read_from_checkout(
            &roots,
            ID,
            &selection,
            WorkspaceOperationLoad::Inspect
        )
        .is_ok()
    );
}

#[test]
fn explicit_source_cannot_hide_ambiguous_owners_or_changed_committed_pack() {
    use cfctl_workspace::{WorkspaceOperationLoad, load_workspace_d1_read_from_checkout};
    let dir = tempfile::tempdir().expect("root");
    let owner = dir.path().join("owner");
    let other = dir.path().join("other");
    repository(&owner);
    repository(&other);
    let checkout = dir.path().join("checkout");
    let mut selection = linked_checkout(&owner, &checkout);
    let roots = [owner.clone(), other];
    assert!(load_workspace_operation_capability(&roots, ID).is_err());
    assert!(
        load_workspace_d1_read_from_checkout(
            &roots,
            ID,
            &selection,
            WorkspaceOperationLoad::Execute
        )
        .is_err()
    );
    let pack = fs::read_to_string(checkout.join(PACK)).expect("pack");
    fs::write(
        checkout.join(PACK),
        format!("{pack}\n# different committed pack\n"),
    )
    .expect("write");
    commit(&checkout);
    selection.head = git(&checkout, &["rev-parse", "HEAD"]);
    selection.tree = git(&checkout, &["rev-parse", "HEAD^{tree}"]);
    assert!(
        load_workspace_d1_read_from_checkout(
            &[owner],
            ID,
            &selection,
            WorkspaceOperationLoad::Execute
        )
        .is_err()
    );
}

#[test]
fn per_query_source_binding_rejects_a_new_discoverable_duplicate() {
    use cfctl_workspace::{
        WorkspaceOperationLoad, load_workspace_d1_read_from_checkout,
        revalidate_workspace_d1_read_registration,
    };
    let roots_dir = tempfile::tempdir().expect("registered forest");
    let linked_dir = tempfile::tempdir().expect("selected checkout parent");
    let owner = roots_dir.path().join("owner");
    repository(&owner);
    let selection = linked_checkout(&owner, &linked_dir.path().join("selected"));
    let roots = [roots_dir.path().to_path_buf()];
    let capability = load_workspace_d1_read_from_checkout(
        &roots,
        ID,
        &selection,
        WorkspaceOperationLoad::Execute,
    )
    .expect("unique owner");
    let contract = capability.workspace_d1_read_inventory.expect("contract");
    revalidate_workspace_d1_read_registration(&roots, &contract).expect("initial query boundary");
    repository(&roots_dir.path().join("added-owner"));
    assert!(revalidate_workspace_d1_read_registration(&roots, &contract).is_err());
}

#[test]
fn per_query_source_binding_rejects_shared_origin_drift() {
    use cfctl_workspace::{
        WorkspaceOperationLoad, load_workspace_d1_read_from_checkout,
        revalidate_workspace_d1_read_registration,
    };
    let dir = tempfile::tempdir().expect("root");
    let owner = dir.path().join("owner");
    repository(&owner);
    let checkout = dir.path().join("selected");
    let selection = linked_checkout(&owner, &checkout);
    let roots = [owner.clone()];
    let capability = load_workspace_d1_read_from_checkout(
        &roots,
        ID,
        &selection,
        WorkspaceOperationLoad::Execute,
    )
    .expect("selected source");
    let contract = capability.workspace_d1_read_inventory.expect("contract");
    revalidate_workspace_d1_read_registration(&roots, &contract).expect("initial origin");
    git(
        &owner,
        &[
            "remote",
            "set-url",
            "origin",
            "https://example.invalid/changed.git",
        ],
    );
    assert_eq!(
        git(&checkout, &["config", "--get", "remote.origin.url"]),
        "https://example.invalid/changed.git"
    );
    assert!(revalidate_workspace_d1_read_registration(&roots, &contract).is_err());
}

#[test]
fn clean_committed_population_derives_its_own_identity_and_public_contract() {
    let root = tempfile::tempdir().expect("root");
    let source_revision = repository(root.path());
    let capability = load_workspace_operation_capability(&[root.path().to_path_buf()], ID)
        .expect("loader")
        .expect("capability");
    let contract = capability
        .workspace_d1_read_inventory
        .as_ref()
        .expect("typed contract");
    assert_eq!(
        contract.repository_head,
        git(root.path(), &["rev-parse", "HEAD"])
    );
    assert_eq!(
        contract.repository_tree,
        git(root.path(), &["rev-parse", "HEAD^{tree}"])
    );
    assert_eq!(contract.operation.source_revision, source_revision);
    assert_ne!(contract.repository_head, source_revision);
    assert_eq!(capability.adapter_status, AdapterStatus::Native);
    assert_eq!(
        capability.authority_scope,
        Some(CapabilityAuthorityScopeV1::WorkspaceOwned)
    );
    assert!(!capability.mutating);
    assert!(!capability.cost.known);
    assert!(capability.cost.maximum.is_none());
    revalidate_workspace_d1_read_inventory(contract).expect("current immutable inputs");
}

#[test]
fn inspect_reads_a_committed_population_from_a_dirty_worktree() {
    let root = tempfile::tempdir().expect("root");
    repository(root.path());
    fs::write(root.path().join("unrelated"), "dirty").expect("unrelated dirt");
    let roots = [root.path().to_path_buf()];
    assert!(
        load_workspace_operation_capability(&roots, ID).is_err(),
        "execute still requires a clean worktree"
    );
    assert!(
        inspect_workspace_operation_capability(&roots, ID)
            .expect("inspect")
            .is_some()
    );
}

#[test]
fn changed_source_is_caught_even_when_git_status_hides_it() {
    let root = tempfile::tempdir().expect("root");
    repository(root.path());
    let capability = load_workspace_operation_capability(&[root.path().to_path_buf()], ID)
        .expect("loader")
        .expect("capability");
    let contract = capability.workspace_d1_read_inventory.expect("contract");
    git(
        root.path(),
        &["update-index", "--assume-unchanged", "source.txt"],
    );
    fs::write(root.path().join("source.txt"), "changed source").expect("changed source");
    assert!(git(root.path(), &["status", "--porcelain=v1"]).is_empty());
    assert!(revalidate_workspace_d1_read_inventory(&contract).is_err());
    assert!(load_workspace_operation_capability(&[root.path().to_path_buf()], ID).is_err());
}

#[test]
fn duplicate_owner_digest_drift_and_untracked_inventory_fail_closed() {
    let root = tempfile::tempdir().expect("root");
    let a = root.path().join("a");
    let b = root.path().join("b");
    repository(&a);
    repository(&b);
    assert!(load_workspace_operation_capability(&[a.clone(), b], ID).is_err());
    let text = fs::read_to_string(a.join(PACK)).expect("pack");
    fs::write(a.join(PACK), text.replace("sha256:", "sha256:0")).expect("wrong digest");
    commit(&a);
    assert!(load_workspace_operation_capability(std::slice::from_ref(&a), ID).is_err());
    fs::write(a.join(PACK), text).expect("restore pack");
    git(&a, &["rm", "--cached", "inventory.json"]);
    fs::write(a.join(".gitignore"), "inventory.json\n").expect("ignore inventory");
    commit(&a);
    assert!(load_workspace_operation_capability(&[a], ID).is_err());
}

#[cfg(unix)]
#[test]
fn a_committed_symlink_is_not_a_source_or_inventory_authority() {
    let root = tempfile::tempdir().expect("root");
    repository(root.path());
    let inventory = fs::read(root.path().join("inventory.json")).expect("inventory");
    fs::write(root.path().join("copy.json"), inventory).expect("copy");
    fs::remove_file(root.path().join("inventory.json")).expect("replace fixture input");
    std::os::unix::fs::symlink("copy.json", root.path().join("inventory.json")).expect("symlink");
    commit(root.path());
    assert!(load_workspace_operation_capability(&[root.path().to_path_buf()], ID).is_err());
}
