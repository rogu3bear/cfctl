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
fn explicit_source_cannot_hide_ambiguous_owners_or_changed_operation() {
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
        pack.replace(
            "profile_id = \"example-read\"",
            "profile_id = \"other-read\"",
        ),
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
fn older_selected_pack_retains_its_own_input_revision_after_owner_advances() {
    use cfctl_workspace::{
        WorkspaceOperationLoad, load_workspace_d1_read_from_checkout,
        revalidate_workspace_d1_read_registration,
    };
    use sha2::{Digest, Sha256};
    let dir = tempfile::tempdir().expect("root");
    let owner = dir.path().join("owner");
    let input_revision = repository(&owner);
    let checkout = dir.path().join("checkout");
    let selection = linked_checkout(&owner, &checkout);
    let original_pack = fs::read(checkout.join(PACK)).expect("selected pack");
    let replacement = "new registered publication inputs\n";
    fs::write(owner.join("source.txt"), replacement).expect("advance owner input");
    commit(&owner);
    let owner_input_revision = git(&owner, &["rev-parse", "HEAD"]);
    let mut pack: cfctl_core::d1_read_inventory::D1ReadPackV1 =
        toml::from_str(std::str::from_utf8(&original_pack).expect("UTF-8")).expect("pack");
    pack.operation[0].source_revision = owner_input_revision.clone();
    pack.operation[0].source[0].sha256 =
        format!("sha256:{}", hex::encode(Sha256::digest(replacement)));
    fs::write(owner.join(PACK), toml::to_string(&pack).expect("TOML")).expect("pack");
    commit(&owner);
    assert_ne!(
        fs::read(owner.join(PACK)).expect("owner pack"),
        original_pack
    );
    // Unrelated owner dirt must remain untouched and cannot become read inputs.
    fs::write(owner.join("source.txt"), "owner's unfinished work").expect("dirty owner");
    let roots = [owner.clone()];
    let capability = load_workspace_d1_read_from_checkout(
        &roots,
        ID,
        &selection,
        WorkspaceOperationLoad::Execute,
    )
    .expect("same read authority with separately validated input pins");
    let contract = capability.workspace_d1_read_inventory.expect("contract");
    let binding = contract.source_binding.as_ref().expect("binding");
    assert_eq!(contract.repository_head, selection.head);
    assert_eq!(contract.operation.source_revision, input_revision);
    assert_ne!(contract.repository_head, contract.operation.source_revision);
    assert_ne!(contract.operation.source_revision, owner_input_revision);
    assert_eq!(binding.registered_head, git(&owner, &["rev-parse", "HEAD"]));
    revalidate_workspace_d1_read_registration(&roots, &contract).expect("query authorization");
    revalidate_workspace_d1_read_inventory(&contract).expect("selected current bytes");
    assert_eq!(
        fs::read(checkout.join(PACK)).expect("selected pack"),
        original_pack
    );
    assert_eq!(
        fs::read_to_string(owner.join("source.txt")).expect("owner dirt"),
        "owner's unfinished work"
    );
    // A forged current-byte digest is rejected independently of authorization.
    let mut wrong = contract.clone();
    wrong.operation.source[0].sha256 = "sha256:".to_owned() + &"0".repeat(64);
    assert!(revalidate_workspace_d1_read_inventory(&wrong).is_err());
    for change in [
        "account",
        "database",
        "profile",
        "purpose",
        "inventory",
        "paths",
    ] {
        let mut changed = contract.clone();
        match change {
            "account" => changed.operation.account_id = "b".repeat(32),
            "database" => {
                changed.operation.database_id = "22222222-2222-4333-8444-555555555555".into();
            }
            "profile" => changed.operation.profile_id = "other-read".into(),
            "purpose" => changed.operation.description = "different purpose".into(),
            "inventory" => {
                changed.operation.inventory_sha256 = "sha256:".to_owned() + &"1".repeat(64);
            }
            "paths" => changed.operation.source[0].path = "other.txt".into(),
            _ => unreachable!(),
        }
        assert!(
            revalidate_workspace_d1_read_registration(&roots, &changed).is_err(),
            "per-query {change} drift must fail closed"
        );
    }
}

#[test]
fn explicit_source_validates_selected_nonancestor_missing_and_forged_own_inputs() {
    use cfctl_workspace::{WorkspaceOperationLoad, load_workspace_d1_read_from_checkout};
    for defect in ["nonancestor-revision", "missing-input", "forged-input-pin"] {
        let dir = tempfile::tempdir().expect("root");
        let owner = dir.path().join("owner");
        repository(&owner);
        let checkout = dir.path().join("checkout");
        let mut selection = linked_checkout(&owner, &checkout);
        fs::write(owner.join("owner-only.txt"), "divergent owner commit").expect("owner");
        commit(&owner);
        let nonancestor = git(&owner, &["rev-parse", "HEAD"]);
        let mut pack: cfctl_core::d1_read_inventory::D1ReadPackV1 =
            toml::from_str(&fs::read_to_string(checkout.join(PACK)).expect("pack")).expect("TOML");
        match defect {
            "nonancestor-revision" => pack.operation[0].source_revision = nonancestor,
            "missing-input" => fs::remove_file(checkout.join("source.txt")).expect("remove input"),
            "forged-input-pin" => {
                pack.operation[0].source[0].sha256 = "sha256:".to_owned() + &"0".repeat(64);
            }
            _ => unreachable!(),
        }
        fs::write(checkout.join(PACK), toml::to_string(&pack).expect("TOML")).expect("pack");
        commit(&checkout);
        selection.head = git(&checkout, &["rev-parse", "HEAD"]);
        selection.tree = git(&checkout, &["rev-parse", "HEAD^{tree}"]);
        for mode in [
            WorkspaceOperationLoad::Inspect,
            WorkspaceOperationLoad::Execute,
        ] {
            assert!(
                load_workspace_d1_read_from_checkout(
                    std::slice::from_ref(&owner),
                    ID,
                    &selection,
                    mode
                )
                .is_err(),
                "{defect} must be rejected using the selected checkout's own committed inputs"
            );
        }
    }
}

fn registered_owner_with_two_required_inputs(
    root: &Path,
) -> (
    std::path::PathBuf,
    cfctl_core::d1_read_inventory::D1ReadPackV1,
    String,
) {
    use cfctl_core::d1_read_inventory::{D1ReadPackV1, D1ReadSourceV1};
    use sha2::{Digest, Sha256};
    let owner = root.join("owner");
    repository(&owner);
    fs::write(owner.join("required.txt"), "second required input\n").expect("required");
    commit(&owner);
    let required_revision = git(&owner, &["rev-parse", "HEAD"]);
    let mut pack: D1ReadPackV1 =
        toml::from_str(&fs::read_to_string(owner.join(PACK)).expect("pack")).expect("TOML");
    pack.operation[0]
        .source_revision
        .clone_from(&required_revision);
    pack.operation[0].source.push(D1ReadSourceV1 {
        path: "required.txt".into(),
        sha256: format!(
            "sha256:{}",
            hex::encode(Sha256::digest(b"second required input\n"))
        ),
    });
    fs::write(owner.join(PACK), toml::to_string(&pack).expect("TOML")).expect("pack");
    commit(&owner);
    (owner, pack, required_revision)
}

#[test]
fn supplemental_selected_inputs_retain_ordered_minimum_and_validate_own_commits() {
    use cfctl_core::d1_read_inventory::D1ReadSourceV1;
    use cfctl_workspace::{
        WorkspaceOperationLoad, load_workspace_d1_read_from_checkout,
        revalidate_workspace_d1_read_registration,
    };
    use sha2::{Digest, Sha256};
    for defect in [
        "none",
        "missing-required",
        "reordered-required",
        "forged-helper",
        "helper-not-in-revision",
        "dirty-helper",
        "missing-helper",
        "duplicate-helper",
    ] {
        let dir = tempfile::tempdir().expect("root");
        let (owner, mut pack, required_revision) =
            registered_owner_with_two_required_inputs(dir.path());
        let checkout = dir.path().join("checkout");
        let mut selection = linked_checkout(&owner, &checkout);
        fs::create_dir_all(checkout.join("scripts/lib")).expect("helpers directory");
        let mut extra = Vec::new();
        for path in [
            "scripts/lib/owned_process.py",
            "scripts/lib/owned_watch_protocol.py",
            "additional-input.txt",
        ] {
            let bytes = format!("supplemental committed input {path}\n");
            fs::write(checkout.join(path), &bytes).expect("supplemental input");
            extra.push(D1ReadSourceV1 {
                path: path.into(),
                sha256: format!("sha256:{}", hex::encode(Sha256::digest(bytes.as_bytes()))),
            });
        }
        commit(&checkout);
        pack.operation[0].source_revision = git(&checkout, &["rev-parse", "HEAD"]);
        let required = pack.operation[0].source.clone();
        pack.operation[0].source = vec![
            extra[0].clone(),
            required[0].clone(),
            extra[1].clone(),
            required[1].clone(),
            extra[2].clone(),
        ];
        match defect {
            "missing-required" => {
                pack.operation[0].source.remove(1);
            }
            "reordered-required" => pack.operation[0].source.swap(1, 3),
            "forged-helper" => {
                pack.operation[0].source[0].sha256 = "sha256:".to_owned() + &"0".repeat(64);
            }
            "helper-not-in-revision" => pack.operation[0].source_revision = required_revision,
            "duplicate-helper" => pack.operation[0].source.push(extra[0].clone()),
            _ => {}
        }
        fs::write(checkout.join(PACK), toml::to_string(&pack).expect("TOML")).expect("pack");
        commit(&checkout);
        selection.head = git(&checkout, &["rev-parse", "HEAD"]);
        selection.tree = git(&checkout, &["rev-parse", "HEAD^{tree}"]);
        if defect == "dirty-helper" {
            fs::write(checkout.join(&extra[0].path), "unreviewed helper\n").expect("dirty helper");
        } else if defect == "missing-helper" {
            fs::remove_file(checkout.join(&extra[0].path)).expect("missing helper");
        }
        let roots = [owner];
        let result = load_workspace_d1_read_from_checkout(
            &roots,
            ID,
            &selection,
            WorkspaceOperationLoad::Execute,
        );
        if defect == "none" {
            let contract = result
                .expect("additional committed constraints are valid")
                .workspace_d1_read_inventory
                .expect("contract");
            assert_eq!(contract.operation.source.len(), 5);
            revalidate_workspace_d1_read_registration(&roots, &contract).expect("same authority");
            revalidate_workspace_d1_read_inventory(&contract).expect("all selected inputs");
            for reorder in [false, true] {
                let mut changed = contract.clone();
                if reorder {
                    changed.operation.source.swap(1, 3);
                } else {
                    changed.operation.source.remove(1);
                }
                assert!(revalidate_workspace_d1_read_registration(&roots, &changed).is_err());
            }
        } else {
            assert!(
                result.is_err(),
                "supplemental input {defect} must fail closed"
            );
        }
    }
}

#[test]
fn selected_committed_query_body_and_inventory_path_cannot_change_authority() {
    use cfctl_workspace::{WorkspaceOperationLoad, load_workspace_d1_read_from_checkout};
    use sha2::{Digest, Sha256};
    for change_query in [false, true] {
        let dir = tempfile::tempdir().expect("root");
        let owner = dir.path().join("owner");
        repository(&owner);
        let checkout = dir.path().join("checkout");
        let mut selection = linked_checkout(&owner, &checkout);
        let mut pack: cfctl_core::d1_read_inventory::D1ReadPackV1 =
            toml::from_str(&fs::read_to_string(checkout.join(PACK)).expect("pack")).expect("TOML");
        let inventory = fs::read(checkout.join("inventory.json")).expect("inventory");
        if change_query {
            let mut value: serde_json::Value = serde_json::from_slice(&inventory).expect("JSON");
            let sql = "SELECT COUNT(*) + 1 AS n FROM items;";
            value["queries"][1]["sql"] = sql.into();
            value["queries"][1]["sha256"] =
                format!("sha256:{}", hex::encode(Sha256::digest(sql))).into();
            let bytes = serde_json::to_vec_pretty(&value).expect("JSON");
            pack.operation[0].inventory_sha256 =
                format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
            fs::write(checkout.join("inventory.json"), bytes).expect("changed inventory");
        } else {
            fs::write(checkout.join("other-inventory.json"), &inventory)
                .expect("same bytes elsewhere");
            pack.operation[0].inventory_path = "other-inventory.json".into();
        }
        fs::write(checkout.join(PACK), toml::to_string(&pack).expect("TOML")).expect("pack");
        commit(&checkout);
        selection.head = git(&checkout, &["rev-parse", "HEAD"]);
        selection.tree = git(&checkout, &["rev-parse", "HEAD^{tree}"]);
        // It is a valid committed read in isolation, but cannot borrow the
        // registered operation's authority for a different population or path.
        assert!(
            load_workspace_operation_capability(&[checkout], ID)
                .expect("loader")
                .is_some()
        );
        let error = load_workspace_d1_read_from_checkout(
            &[owner],
            ID,
            &selection,
            WorkspaceOperationLoad::Execute,
        )
        .expect_err("changed inventory must not borrow authorization");
        assert!(
            error.to_string().contains("registered authority"),
            "{error}"
        );
    }
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

#[cfg(unix)]
#[test]
fn a_registered_symlink_cannot_supply_nested_operation_owners() {
    use cfctl_workspace::{RegisteredRoot, WorkspaceGraph};
    let root = tempfile::tempdir().expect("root");
    let outside = tempfile::tempdir().expect("outside");
    repository(&outside.path().join("nested-owner"));
    let link = root.path().join("legacy-root");
    std::os::unix::fs::symlink(outside.path(), &link).expect("root link");
    let graph = WorkspaceGraph::discover(&[RegisteredRoot::new(&link)]).expect("graph");
    assert!(graph.repositories.is_empty());
    assert_eq!(graph.skipped_roots.len(), 1);
    let roots = [link];
    assert!(
        load_workspace_operation_capability(&roots, ID)
            .expect("execute")
            .is_none()
    );
    assert!(
        inspect_workspace_operation_capability(&roots, ID)
            .expect("inspect")
            .is_none()
    );
    assert!(
        inspect_workspace_operation_capability(&[outside.path().to_path_buf()], ID)
            .expect("resolved directory remains supported")
            .is_some()
    );
}

fn competing_claim(root: &Path, pack: &str, schema: u8) {
    fs::create_dir_all(root.join(".cfctl/operations")).expect("pack directory");
    if !root.join(".git").exists() {
        git(root, &["init", "-q"]);
    }
    let marker = if pack.ends_with("generic.toml") {
        "contract = \"workspace_operation_v1\"\n"
    } else {
        ""
    };
    fs::write(
        root.join(pack),
        format!("schema_version = {schema}\n{marker}[[operation]]\nid = {ID:?}\n"),
    )
    .expect("claim");
    commit(root);
}

const COMPETING_PACKS: [(&str, u8); 4] = [
    (".cfctl/operations/generic.toml", 2),
    (".cfctl/operations/generic.toml", 99),
    (".cfctl/operations/d1-evidence.toml", 1),
    (".cfctl/operations/d1-evidence.toml", 99),
];

#[test]
fn explicit_and_default_lookup_reject_cross_carrier_committed_claims() {
    use cfctl_workspace::{WorkspaceOperationLoad, load_workspace_d1_read_from_checkout};
    for (pack, schema) in COMPETING_PACKS {
        for same_repository in [false, true] {
            let dir = tempfile::tempdir().expect("root");
            let owner = dir.path().join("owner");
            repository(&owner);
            let selection = linked_checkout(&owner, &dir.path().join("checkout"));
            let competitor = if same_repository {
                owner.clone()
            } else {
                dir.path().join("other")
            };
            competing_claim(&competitor, pack, schema);
            let roots = if same_repository {
                vec![owner]
            } else {
                vec![owner, competitor]
            };
            for mode in [
                WorkspaceOperationLoad::Inspect,
                WorkspaceOperationLoad::Execute,
            ] {
                let error = load_workspace_d1_read_from_checkout(&roots, ID, &selection, mode)
                    .expect_err("an explicit source cannot choose between carriers");
                assert!(error.to_string().contains("ambiguous"), "{error}");
            }
            let error = inspect_workspace_operation_capability(&roots, ID)
                .expect_err("inspection cannot choose by loader order");
            assert!(error.to_string().contains("ambiguous"), "{error}");
            let error = load_workspace_operation_capability(&roots, ID)
                .expect_err("execution cannot choose by loader order");
            assert!(error.to_string().contains("ambiguous"), "{error}");
        }
    }
}

#[test]
fn selected_checkout_cannot_add_a_competing_carrier() {
    use cfctl_workspace::{WorkspaceOperationLoad, load_workspace_d1_read_from_checkout};
    for (pack, schema) in COMPETING_PACKS {
        let dir = tempfile::tempdir().expect("root");
        let owner = dir.path().join("owner");
        repository(&owner);
        let checkout = dir.path().join("checkout");
        let mut selection = linked_checkout(&owner, &checkout);
        competing_claim(&checkout, pack, schema);
        selection.head = git(&checkout, &["rev-parse", "HEAD"]);
        selection.tree = git(&checkout, &["rev-parse", "HEAD^{tree}"]);
        // The registered owner remains unique and the D1 read pack is identical.
        assert!(
            inspect_workspace_operation_capability(std::slice::from_ref(&owner), ID)
                .expect("registered owner remains unambiguous")
                .is_some()
        );
        for mode in [
            WorkspaceOperationLoad::Inspect,
            WorkspaceOperationLoad::Execute,
        ] {
            let error = load_workspace_d1_read_from_checkout(
                std::slice::from_ref(&owner),
                ID,
                &selection,
                mode,
            )
            .expect_err("selected checkout has two committed claims");
            assert!(error.to_string().contains("ambiguous"), "{error}");
        }
    }
}

#[test]
fn per_query_reacquisition_rejects_a_late_cross_carrier_claim() {
    use cfctl_workspace::{
        WorkspaceOperationLoad, load_workspace_d1_read_from_checkout,
        revalidate_workspace_d1_read_registration,
    };
    for (pack, schema) in COMPETING_PACKS {
        let dir = tempfile::tempdir().expect("root");
        let owner = dir.path().join("owner");
        repository(&owner);
        let selection = linked_checkout(&owner, &dir.path().join("checkout"));
        let other = dir.path().join("late-owner");
        let roots = [owner, other.clone()];
        let capability = load_workspace_d1_read_from_checkout(
            &roots,
            ID,
            &selection,
            WorkspaceOperationLoad::Execute,
        )
        .expect("unique source initially");
        let contract = capability.workspace_d1_read_inventory.expect("contract");
        revalidate_workspace_d1_read_registration(&roots, &contract).expect("initial boundary");
        competing_claim(&other, pack, schema);
        let error = revalidate_workspace_d1_read_registration(&roots, &contract)
            .expect_err("next boundary must reacquire cross-carrier ownership");
        assert!(error.to_string().contains("ambiguous"), "{error}");
    }
}

#[test]
fn recognizing_an_unsupported_generic_claim_does_not_enable_its_execution() {
    let root = tempfile::tempdir().expect("root");
    competing_claim(root.path(), ".cfctl/operations/generic.toml", 99);
    let roots = [root.path().to_path_buf()];
    assert!(
        cfctl_workspace::workspace_operation_is_claimed(&roots, ID)
            .expect("unsupported semantics retain the committed identity claim")
    );
    for result in [
        inspect_workspace_operation_capability(&roots, ID),
        load_workspace_operation_capability(&roots, ID),
    ] {
        let error = result.expect_err("a claimed unsupported declaration must reject binding");
        assert!(
            matches!(
                &error,
                cfctl_workspace::WorkspaceError::DiscoveryInvariant(message)
                    if message.contains("no supported binding")
                        && message.contains("no alternative owner may replace it")
            ),
            "unexpected binding rejection: {error}"
        );
    }
    for result in [
        inspect_workspace_operation_capability(&roots, "example.unclaimed"),
        load_workspace_operation_capability(&roots, "example.unclaimed"),
    ] {
        assert!(
            result
                .expect("an unclaimed identity remains unknown")
                .is_none()
        );
    }
}
