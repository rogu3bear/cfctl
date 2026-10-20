#![allow(clippy::expect_used, clippy::unwrap_used)]
use super::{git, object, requested, source};
use crate::runtime::{pages_deployment, pages_immutable};
use cfctl_catalog::{CatalogSnapshot, ingest_wrangler_pages_deploy_help};
use cfctl_cloudflare::CallInput;
use cfctl_core::{CapabilityV1, pages_deployment::PagesDeploymentEnvironmentV1};
use cfctl_workspace::{GitStateV1, RepositoryNode, WorkspaceGraph};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

fn capability() -> CapabilityV1 {
    let mut catalog = CatalogSnapshot {
        schema_version: 1,
        generated_at: chrono::Utc::now(),
        source_url: "fixture://pages".into(),
        source_hash: "fixture".into(),
        schema_hash: "fixture".into(),
        capabilities: BTreeMap::default(),
    };
    ingest_wrangler_pages_deploy_help(
        &mut catalog,
        "4.107.0",
        "wrangler pages deploy [directory] --project-name --branch --commit-hash --commit-message",
    );
    catalog.get("wrangler.pages-deploy").unwrap().clone()
}

fn fixture_git(root: &Path, args: &[&str]) -> String {
    git(
        root,
        &[
            &[
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "commit.gpgsign=false",
            ][..],
            args,
        ]
        .concat(),
        false,
    )
    .unwrap()
    .trim_end_matches('\n')
    .to_owned()
}

fn commit(root: &Path, name: &str) -> String {
    fixture_git(root, &["add", "."]);
    fixture_git(
        root,
        &[
            "-c",
            "user.name=cfctl test",
            "-c",
            "user.email=cfctl@example.invalid",
            "commit",
            "--quiet",
            "-m",
            name,
        ],
    );
    object(root, "HEAD", "commit").unwrap()
}

struct Fixture {
    directory: tempfile::TempDir,
    root: PathBuf,
    artifact: PathBuf,
    graph: WorkspaceGraph,
    input: CallInput,
}

fn fixture() -> Fixture {
    let directory = tempfile::tempdir_in(fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
    let root = directory.path().join("repo");
    fs::create_dir(&root).unwrap();
    fixture_git(&root, &["init", "--quiet", "--initial-branch=main"]);
    fixture_git(
        &root,
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/example/site.git",
        ],
    );
    fs::write(root.join(".gitignore"), "output/\n").unwrap();
    fs::write(root.join("app"), "qualified application").unwrap();
    let artifact_commit = commit(&root, "artifact source");
    fixture_git(&root, &["switch", "--quiet", "-c", "procedure/repair"]);
    fs::write(root.join("procedure"), "reviewed wrapper").unwrap();
    let checkout_commit = commit(&root, "procedure revision");
    let artifact = root.join("output");
    fs::create_dir(&artifact).unwrap();
    fs::write(artifact.join("index.html"), "retained bytes").unwrap();
    let graph = WorkspaceGraph {
        repositories: vec![RepositoryNode {
            name: "site".into(),
            path: root.clone(),
            cloudflare_configs: vec![],
            configs: vec![],
            git: GitStateV1 {
                head: Some(checkout_commit.clone()),
                branch: Some("procedure/repair".into()),
                ..Default::default()
            },
        }],
        ..Default::default()
    };
    let input = CallInput {
        query: json!({"argument":artifact,"project_name":"site","branch":"main",
            "commit_hash":artifact_commit,"checkout_commit":checkout_commit,"checkout_branch":"procedure/repair"}),
        ..Default::default()
    };
    Fixture {
        directory,
        root,
        artifact,
        graph,
        input,
    }
}

#[test]
fn retained_source_separates_artifact_procedure_and_provider_identities() {
    let f = fixture();
    assert!(
        requested(
            &capability(),
            &f.input,
            PagesDeploymentEnvironmentV1::Production
        )
        .unwrap()
    );
    let bound = source(&f.graph, &f.input, &f.artifact).unwrap();
    assert_eq!(bound["mode"], "retained_artifact_v1");
    assert_eq!(bound["repository"], json!(f.root));
    assert_eq!(bound["origin"], "https://github.com/example/site.git");
    assert_eq!(
        bound["artifact_source"]["commit"],
        f.input.query["commit_hash"]
    );
    assert_eq!(
        bound["checkout"]["commit"],
        f.input.query["checkout_commit"]
    );
    assert_ne!(
        bound["artifact_source"]["commit"],
        bound["checkout"]["commit"]
    );
    assert_ne!(bound["artifact_source"]["tree"], bound["checkout"]["tree"]);
    assert_eq!(bound["checkout"]["branch"], "procedure/repair");
    assert_eq!(f.input.query["branch"], "main");
    assert!(bound.get("receipt").is_none());
}

#[test]
fn mode_requires_both_closed_catalog_selectors_and_preserves_legacy_absence() {
    let f = fixture();
    let mut cap = capability();
    let mut input = f.input.clone();
    input
        .query
        .as_object_mut()
        .unwrap()
        .remove("checkout_commit");
    input
        .query
        .as_object_mut()
        .unwrap()
        .remove("checkout_branch");
    assert!(!requested(&cap, &input, PagesDeploymentEnvironmentV1::Production).unwrap());
    input.query["checkout_commit"] = f.input.query["checkout_commit"].clone();
    assert!(requested(&cap, &input, PagesDeploymentEnvironmentV1::Production).is_err());
    for value in [Value::Null, json!(""), json!("main"), json!(123)] {
        let mut input = f.input.clone();
        input.query["checkout_commit"] = value;
        assert!(requested(&cap, &input, PagesDeploymentEnvironmentV1::Production).is_err());
    }
    for value in [
        Value::Null,
        json!(""),
        json!("bad branch"),
        json!("bad..branch"),
    ] {
        let mut input = f.input.clone();
        input.query["checkout_branch"] = value;
        assert!(requested(&cap, &input, PagesDeploymentEnvironmentV1::Production).is_err());
    }
    cap.selectors.retain(|s| s.name != "checkout_branch");
    assert!(requested(&cap, &f.input, PagesDeploymentEnvironmentV1::Production).is_err());
    let mut cap = capability();
    cap.selectors.push(
        cap.selectors
            .iter()
            .find(|s| s.name == "checkout_commit")
            .unwrap()
            .clone(),
    );
    assert!(requested(&cap, &f.input, PagesDeploymentEnvironmentV1::Production).is_err());
}

#[test]
fn retained_mode_cannot_mix_with_preview_or_native_reproduction_receipts() {
    let f = fixture();
    assert!(
        requested(
            &capability(),
            &f.input,
            PagesDeploymentEnvironmentV1::Preview
        )
        .is_err()
    );
    let mut input = f.input.clone();
    input.query["artifact_receipt"] = Value::Null;
    assert!(
        requested(
            &capability(),
            &input,
            PagesDeploymentEnvironmentV1::Production
        )
        .is_err()
    );
}

#[test]
fn absent_checkout_selectors_keep_ordinary_head_and_branch_checks() {
    let f = fixture();
    let paths = cfctl_storage::RuntimePaths::from_root(&f.directory.path().join("state"));
    let store = cfctl_storage::StateStore::open(paths).unwrap();
    let mut input = f.input.clone();
    input
        .query
        .as_object_mut()
        .unwrap()
        .remove("checkout_commit");
    input
        .query
        .as_object_mut()
        .unwrap()
        .remove("checkout_branch");
    let error =
        pages_deployment::prepare_target(&store, &f.graph, &capability(), &input).unwrap_err();
    assert!(error.to_string().contains("commit_hash must equal"));
    input.query["commit_hash"] = f.input.query["checkout_commit"].clone();
    let error =
        pages_deployment::prepare_target(&store, &f.graph, &capability(), &input).unwrap_err();
    assert!(error.to_string().contains("branch must equal"));
}

#[test]
fn retained_mode_does_not_receive_archive_workspace_exclusions() {
    let f = fixture();
    let mut plan =
        cfctl_core::PlanV1::draft("profile", "account", "catalog", capability(), json!({}))
            .unwrap();
    plan.targets = json!({"adapter":{"pages_deployment":{"schema_version":3,
        "source":source(&f.graph, &f.input, &f.artifact).unwrap()}}});
    assert!(pages_immutable::plan_repository(&plan).is_none());
}

#[test]
fn source_refuses_dirty_stale_detached_or_unregistered_procedure_checkouts() {
    let f = fixture();
    let mut input = f.input.clone();
    input.query["checkout_commit"] = input.query["commit_hash"].clone();
    assert!(source(&f.graph, &input, &f.artifact).is_err());
    input = f.input.clone();
    input.query["checkout_branch"] = json!("main");
    assert!(source(&f.graph, &input, &f.artifact).is_err());
    assert!(source(&WorkspaceGraph::default(), &f.input, &f.artifact).is_err());
    fs::write(f.root.join("unreviewed"), "dirty").unwrap();
    assert!(source(&f.graph, &f.input, &f.artifact).is_err());
    fs::remove_file(f.root.join("unreviewed")).unwrap();
    fixture_git(&f.root, &["switch", "--quiet", "--detach"]);
    assert!(source(&f.graph, &f.input, &f.artifact).is_err());
}

#[test]
fn advancing_only_the_procedure_invalidates_old_binding_while_retaining_artifact_identity() {
    let mut f = fixture();
    let bound = source(&f.graph, &f.input, &f.artifact).unwrap();
    let artifact = pages_deployment::manifest(&f.artifact).unwrap();
    fs::write(f.root.join("procedure"), "new reviewed procedure").unwrap();
    let successor = commit(&f.root, "new procedure revision");
    assert!(source(&f.graph, &f.input, &f.artifact).is_err());
    f.graph.repositories[0].git.head = Some(successor.clone());
    f.input.query["checkout_commit"] = json!(successor);
    let current = source(&f.graph, &f.input, &f.artifact).unwrap();
    assert_ne!(current["checkout"], bound["checkout"]);
    assert_eq!(current["artifact_source"], bound["artifact_source"]);
    assert_eq!(pages_deployment::manifest(&f.artifact).unwrap(), artifact);
}

#[test]
fn source_rejects_nonancestor_missing_and_legacy_grafted_objects() {
    let f = fixture();
    let unrelated = fixture_git(
        &f.root,
        &[
            "-c",
            "user.name=cfctl test",
            "-c",
            "user.email=cfctl@example.invalid",
            "commit-tree",
            "HEAD^{tree}",
            "-m",
            "unrelated root",
        ],
    );
    let mut input = f.input.clone();
    input.query["commit_hash"] = json!(unrelated);
    assert!(source(&f.graph, &input, &f.artifact).is_err());
    input.query["commit_hash"] = json!("f".repeat(40));
    assert!(source(&f.graph, &input, &f.artifact).is_err());
    fs::write(f.root.join(".git/info/grafts"), "").unwrap();
    assert!(source(&f.graph, &f.input, &f.artifact).is_err());
}

#[test]
fn source_ignores_replacement_objects_and_binds_origin_drift_without_network() {
    let f = fixture();
    let bound = source(&f.graph, &f.input, &f.artifact).unwrap();
    fixture_git(
        &f.root,
        &[
            "replace",
            f.input.query["commit_hash"].as_str().unwrap(),
            f.input.query["checkout_commit"].as_str().unwrap(),
        ],
    );
    assert_eq!(source(&f.graph, &f.input, &f.artifact).unwrap(), bound);
    fixture_git(
        &f.root,
        &[
            "remote",
            "set-url",
            "origin",
            "https://github.com/example/other.git",
        ],
    );
    assert_ne!(source(&f.graph, &f.input, &f.artifact).unwrap(), bound);
    fixture_git(
        &f.root,
        &[
            "config",
            "url.https://substitute.invalid/.insteadOf",
            "https://github.com/",
        ],
    );
    assert!(source(&f.graph, &f.input, &f.artifact).is_err());
    fixture_git(
        &f.root,
        &[
            "config",
            "--unset",
            "url.https://substitute.invalid/.insteadOf",
        ],
    );
    fixture_git(
        &f.root,
        &[
            "remote",
            "set-url",
            "origin",
            "https://secret@github.com/example/site.git",
        ],
    );
    assert!(source(&f.graph, &f.input, &f.artifact).is_err());
}

#[cfg(unix)]
#[test]
fn source_refuses_registered_alias_and_nested_nonroot() {
    let f = fixture();
    let alias = f.root.parent().unwrap().join("alias");
    std::os::unix::fs::symlink(&f.root, &alias).unwrap();
    let mut graph = f.graph.clone();
    graph.repositories[0].path = alias.clone();
    assert!(source(&graph, &f.input, &alias.join("output")).is_err());
    graph.repositories[0].path = f.artifact.clone();
    assert!(source(&graph, &f.input, &f.artifact).is_err());
}
