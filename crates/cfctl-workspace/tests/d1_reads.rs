#![allow(clippy::expect_used)]
use cfctl_core::{AdapterStatus, CapabilityAuthorityScopeV1};
use cfctl_workspace::{
    load_workspace_operation_capability, revalidate_workspace_d1_read_inventory,
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
