#![allow(clippy::expect_used)]
use std::{fs, path::Path, process::Command};

use cfctl_core::workspace_d1::transition::Source;

use super::{WorkspaceOperationLoad, bind_inventory, sha256, source_bytes};

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .expect("fixture git");
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .expect("fixture Git UTF-8")
        .trim()
        .to_owned()
}

fn fixture() -> (tempfile::TempDir, Source) {
    let root = tempfile::tempdir().expect("fixture repository");
    git(root.path(), &["init", "-q"]);
    git(root.path(), &["config", "user.name", "Test"]);
    git(
        root.path(),
        &["config", "user.email", "test@example.invalid"],
    );
    fs::write(
        root.path().join("seed.sql"),
        "CREATE TABLE fixture(id TEXT);\n",
    )
    .expect("seed");
    git(root.path(), &["add", "seed.sql"]);
    git(root.path(), &["commit", "-qm", "source"]);
    let source = Source {
        path: "seed.sql".into(),
        sha256: sha256(&fs::read(root.path().join("seed.sql")).expect("seed bytes")),
        git_blob_oid: git(root.path(), &["rev-parse", "HEAD:seed.sql"]),
    };
    (root, source)
}

#[test]
fn qualification_inspect_reads_committed_bytes_but_execution_rejects_dirty_source() {
    let (root, source) = fixture();
    let original =
        source_bytes(root.path(), &source, WorkspaceOperationLoad::Execute).expect("source bound");
    fs::write(root.path().join("seed.sql"), "DELETE FROM fixture;\n").expect("dirty seed");
    assert_eq!(
        source_bytes(root.path(), &source, WorkspaceOperationLoad::Inspect)
            .expect("committed inspect"),
        original
    );
    assert!(source_bytes(root.path(), &source, WorkspaceOperationLoad::Execute).is_err());
}

#[test]
fn qualification_source_rejects_replaced_blob_digest_and_symlink() {
    let (root, source) = fixture();
    let mut wrong_blob = source.clone();
    wrong_blob.git_blob_oid = "a".repeat(40);
    assert!(source_bytes(root.path(), &wrong_blob, WorkspaceOperationLoad::Inspect).is_err());
    let mut wrong_digest = source.clone();
    wrong_digest.sha256 = format!("sha256:{}", "b".repeat(64));
    assert!(source_bytes(root.path(), &wrong_digest, WorkspaceOperationLoad::Inspect).is_err());
    #[cfg(unix)]
    {
        fs::write(
            root.path().join("other.sql"),
            fs::read(root.path().join("seed.sql")).expect("seed"),
        )
        .expect("copy");
        fs::remove_file(root.path().join("seed.sql")).expect("replace fixture");
        std::os::unix::fs::symlink("other.sql", root.path().join("seed.sql"))
            .expect("link fixture");
        assert!(source_bytes(root.path(), &source, WorkspaceOperationLoad::Execute).is_err());
    }
}

#[test]
fn qualification_population_rejects_noninventory_input() {
    let (root, source) = fixture();
    assert!(bind_inventory(root.path(), &source, WorkspaceOperationLoad::Inspect).is_err());
}

#[test]
fn every_declared_qualification_resource_role_stays_blocked() {
    use cfctl_core::workspace_d1::transition::admission::{Operation, REQUIRED_ROLES};
    use cfctl_core::{AdapterStatus, CapabilityAuthorityScopeV1};
    // Scope: the actual nine-role source vocabulary and the production factory,
    // not an alternate inventory of catalog support states.
    for role in REQUIRED_ROLES {
        let operation = Operation {
            id: format!("fixture.{role:?}"),
            title: "Source fixture".into(),
            description: "Frozen source, no provider admission".into(),
            role,
        };
        let capability = super::capability(&operation);
        assert_eq!(capability.adapter_status, AdapterStatus::Blocked);
        assert_eq!(
            capability.authority_scope,
            Some(CapabilityAuthorityScopeV1::WorkspaceOwned)
        );
        assert_eq!(capability.path, role.path());
        assert_eq!(capability.mutating, role.mutates());
        assert!(
            capability
                .blocked_reason
                .as_deref()
                .is_some_and(|reason| !reason.is_empty())
        );
    }
}
