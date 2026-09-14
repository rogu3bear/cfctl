#![allow(clippy::expect_used, clippy::unwrap_used)]
use super::{pages_immutable, pages_reproduction as producer};
use cfctl_cloudflare::CallInput;
use cfctl_core::{
    EvidenceClass,
    pages_artifact::{self as contract, ReproductionReceiptV1, ReproductionRequestV1},
};
use cfctl_storage::{RuntimePaths, StateStore};
use cfctl_workspace::{GitStateV1, RepositoryNode, WorkspaceGraph};
use serde_json::json;
use std::{fs, path::Path};

fn graph(root: &Path) -> WorkspaceGraph {
    WorkspaceGraph {
        repositories: vec![RepositoryNode {
            name: "fixture".into(),
            path: root.into(),
            cloudflare_configs: vec![],
            configs: vec![],
            git: GitStateV1::default(),
        }],
        ..Default::default()
    }
}

#[test]
fn retained_manifest_uses_recursive_directory_order() {
    let upload = json!({"entries":[{"path":"feedback.js","size":1,"sha256":"a".repeat(64)},{"path":"feedback/index.html","size":1,"sha256":"b".repeat(64)}]});
    assert_eq!(
        producer::retained_digest(&upload).unwrap(),
        "1ad97e344bc77134766b796d26f90d1b17a7a54d3797c9b8afbd8b8d14f59b47"
    );
}

fn input(receipt: &ReproductionReceiptV1, hash: &str) -> CallInput {
    CallInput {
        selectors: json!({}),
        query: json!({"argument":receipt.request.artifact_directory,"project_name":receipt.request.project_name,"branch":receipt.request.branch,"commit_hash":receipt.request.commit,"artifact_receipt":hash}),
        ..Default::default()
    }
}

fn fixture() -> (
    tempfile::TempDir,
    StateStore,
    WorkspaceGraph,
    ReproductionReceiptV1,
) {
    let root = tempfile::tempdir_in("/private/tmp").unwrap();
    let repo = root.path().join("repo");
    fs::create_dir(&repo).unwrap();
    fs::write(repo.join("README"), "fixture").unwrap();
    for args in [
        vec!["init", "--quiet", "--initial-branch=main"],
        vec!["add", "."],
        vec![
            "-c",
            "user.name=cfctl test",
            "-c",
            "user.email=cfctl@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        ],
    ] {
        super::pages_reproduction_process::git(&repo, &args, 4096).unwrap();
    }
    let commit = String::from_utf8(
        super::pages_reproduction_process::git(&repo, &["rev-parse", "HEAD"], 128).unwrap(),
    )
    .unwrap()
    .trim()
    .to_owned();
    let tree = String::from_utf8(
        super::pages_reproduction_process::git(&repo, &["rev-parse", "HEAD^{tree}"], 128).unwrap(),
    )
    .unwrap()
    .trim()
    .to_owned();
    let artifact = root.path().join("artifact");
    fs::create_dir(&artifact).unwrap();
    fs::write(artifact.join("index.html"), "fixed artifact").unwrap();
    let manifest = producer::portable_manifest(&artifact).unwrap();
    let request = ReproductionRequestV1 {
        repository: repo.to_str().unwrap().into(),
        commit,
        tree,
        account_id: "a".repeat(32),
        project_name: "fixture".into(),
        branch: "main".into(),
        artifact_directory: artifact.to_str().unwrap().into(),
        artifact_manifest_sha256: producer::retained_digest(&manifest).unwrap(),
        esbuild_package: "/unused".into(),
    };
    let now = chrono::Utc::now();
    let receipt = ReproductionReceiptV1 {
        schema_version: 1,
        kind: contract::PRODUCER_ID.into(),
        recipe: contract::RECIPE.into(),
        request,
        run_id: uuid::Uuid::new_v4().to_string(),
        build_identity_hash: producer::build_hash().unwrap(),
        producer_contract_hash: producer::producer_hash().unwrap(),
        started_at: now,
        completed_at: now,
        materials_hash: format!("sha256:{}", "b".repeat(64)),
        esbuild_sha256: "c".repeat(64),
        helper_tools: super::pages_reproduction_process::helper_tools().unwrap(),
        environment: producer::environment(),
        artifact: manifest,
    };
    let store =
        super::tests::authenticated_test_store(RuntimePaths::from_root(&root.path().join("state")));
    (root, store, graph(&repo), receipt)
}

#[test]
fn caller_written_and_body_only_receipts_cannot_become_native_proof() {
    let (_root, store, graph, receipt) = fixture();
    let value = serde_json::to_value(&receipt).unwrap();
    let evidence = store
        .write_evidence(EvidenceClass::LocalProof, &value)
        .unwrap();
    assert!(
        pages_immutable::receipt(&store, &graph, &input(&receipt, &evidence.content_hash)).is_err()
    );
    assert!(
        store.write_pages_reproduction(&receipt).is_err(),
        "ordinary evidence cannot be restamped as native proof"
    );
    let descriptor = store
        .paths()
        .data_dir
        .join("evidence-descriptors")
        .join(format!(
            "{}.json",
            evidence.content_hash.strip_prefix("sha256:").unwrap()
        ));
    let mut forged: serde_json::Value =
        serde_json::from_slice(&fs::read(&descriptor).unwrap()).unwrap();
    forged["payload"]["metadata"] = json!({"native_producer":contract::PRODUCER_ID,"version":1});
    fs::write(&descriptor, serde_json::to_vec(&forged).unwrap()).unwrap();
    assert!(
        pages_immutable::receipt(&store, &graph, &input(&receipt, &evidence.content_hash)).is_err(),
        "editing the native origin invalidates its authentication"
    );
    let mut other = receipt.clone();
    other.run_id = uuid::Uuid::new_v4().to_string();
    let audit = store
        .write_audit_evidence(
            EvidenceClass::LocalProof,
            &serde_json::to_value(&other).unwrap(),
        )
        .unwrap();
    assert!(pages_immutable::receipt(&store, &graph, &input(&other, &audit.content_hash)).is_err());
}

#[test]
fn immutable_join_rejects_target_source_recipe_and_output_substitution() {
    let (_root, store, mut graph, receipt) = fixture();
    let evidence = store.write_pages_reproduction(&receipt).unwrap();
    let original = input(&receipt, &evidence.content_hash);
    graph.repositories[0].git.dirty = true;
    graph.repositories[0].git.head = Some("d".repeat(40));
    assert!(
        pages_immutable::receipt(&store, &graph, &original).is_ok(),
        "current HEAD is not archive source"
    );
    for field in [
        "argument",
        "project_name",
        "branch",
        "commit_hash",
        "artifact_receipt",
    ] {
        let mut bad = original.clone();
        bad.query[field] = json!("substituted");
        assert!(
            pages_immutable::receipt(&store, &graph, &bad).is_err(),
            "{field}"
        );
    }
    let mut bad = original.clone();
    bad.selectors = json!({"account_id":"b".repeat(32)});
    assert!(pages_immutable::receipt(&store, &graph, &bad).is_err());
    let source = pages_immutable::source(&store, &graph, &original).unwrap();
    assert!(
        pages_immutable::validate_account(
            &json!({"pages_deployment":{"source":source}}),
            &"b".repeat(32)
        )
        .is_err()
    );
    for field in [
        "kind",
        "recipe",
        "build_identity_hash",
        "producer_contract_hash",
        "materials_hash",
        "esbuild_sha256",
    ] {
        let mut bad = serde_json::to_value(&receipt).unwrap();
        bad[field] = json!("substituted");
        bad["run_id"] = json!(uuid::Uuid::new_v4().to_string());
        let bad: ReproductionReceiptV1 = serde_json::from_value(bad).unwrap();
        let e = store.write_pages_reproduction(&bad).unwrap();
        assert!(
            pages_immutable::receipt(&store, &graph, &input(&bad, &e.content_hash)).is_err(),
            "{field}"
        );
    }
    fs::write(
        Path::new(&receipt.request.artifact_directory).join("extra"),
        "extra",
    )
    .unwrap();
    assert!(pages_immutable::receipt(&store, &graph, &original).is_err());
}

#[test]
fn source_and_paths_fail_before_tool_execution() {
    let (root, store, graph, receipt) = fixture();
    assert!(
        producer::run(&store, &graph, receipt.request.clone()).is_err(),
        "unrecognized source recipe"
    );
    let mut bad = receipt.request.clone();
    bad.tree = "a".repeat(40);
    assert!(producer::validate_source(&graph, &bad).is_err());
    assert!(producer::validate_source(&WorkspaceGraph::default(), &receipt.request).is_err());
    let link = root.path().join("alias");
    std::os::unix::fs::symlink(&receipt.request.artifact_directory, &link).unwrap();
    assert!(producer::canonical_path(&link).is_err());
    assert!(producer::canonical_path(&link.join("../artifact")).is_err());
    std::os::unix::fs::symlink(
        "index.html",
        Path::new(&receipt.request.artifact_directory).join("escape"),
    )
    .unwrap();
    assert!(producer::portable_manifest(Path::new(&receipt.request.artifact_directory)).is_err());
}

#[test]
fn archive_impact_and_preconditions_preserve_registration_without_working_head() {
    let (_root, store, _graph, receipt) = fixture();
    let repo = Path::new(&receipt.request.repository);
    store
        .register_workspace(repo, Some(receipt.request.account_id.clone()))
        .unwrap();
    let evidence = store.write_pages_reproduction(&receipt).unwrap();
    let input = input(&receipt, &evidence.content_hash);
    let mut cap = cfctl_core::CapabilityV1::new(
        "wrangler.pages-deploy",
        "Pages",
        "CLI",
        "wrangler pages deploy",
    );
    cap.adapter_status = cfctl_core::AdapterStatus::DelegatedCli;
    let impact =
        super::pages_source::plan_impact(&store, &cap, &input, &receipt.request.account_id)
            .unwrap();
    assert_eq!(
        impact.affected_repositories,
        vec![receipt.request.repository.clone()]
    );
    assert!(!impact.policy.has_dirty_overlap);
    let before = super::workspace_state::workspace_precondition_hashes_for_archive_scope(
        &store,
        &impact.affected_repositories,
        &impact.local_artifact_paths,
        Some(&receipt.request.repository),
    )
    .unwrap();
    let legacy = super::workspace_state::workspace_precondition_hashes_for_scope(
        &store,
        &impact.affected_repositories,
        &impact.local_artifact_paths,
    )
    .unwrap();
    fs::write(repo.join("README"), "new development").unwrap();
    for args in [
        vec!["add", "."],
        vec![
            "-c",
            "user.name=cfctl test",
            "-c",
            "user.email=cfctl@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "next development",
        ],
    ] {
        super::pages_reproduction_process::git(repo, &args, 4096).unwrap();
    }
    fs::write(repo.join("README"), "more uncommitted work").unwrap();
    let after = super::workspace_state::workspace_precondition_hashes_for_archive_scope(
        &store,
        &impact.affected_repositories,
        &impact.local_artifact_paths,
        Some(&receipt.request.repository),
    )
    .unwrap();
    assert_eq!(before, after);
    assert_ne!(
        legacy,
        super::workspace_state::workspace_precondition_hashes_for_scope(
            &store,
            &impact.affected_repositories,
            &impact.local_artifact_paths
        )
        .unwrap()
    );
    let impact =
        super::pages_source::plan_impact(&store, &cap, &input, &receipt.request.account_id)
            .unwrap();
    assert!(!impact.policy.has_dirty_overlap);
    let graph = super::workspace_state::discover_registered(&store).unwrap();
    assert!(pages_immutable::receipt(&store, &graph, &input).is_ok());
    let mut legacy_input = input.clone();
    legacy_input
        .query
        .as_object_mut()
        .unwrap()
        .remove("artifact_receipt");
    assert!(super::pages_deployment::prepare_target(&store, &graph, &cap, &legacy_input).is_err());
}

/// Runs the real integrity-pinned compiler against a separately supplied,
/// immutable source/archive. Never contacts Cloudflare or edits that checkout.
#[tokio::test]
#[ignore = "requires a local lock-verified darwin-arm64 esbuild package and admitted immutable archive request"]
async fn real_reproduction_to_authenticated_prepare_and_run_admission() {
    use super::pages_deployment;
    let request: ReproductionRequestV1 = serde_json::from_str(
        &std::env::var("CFCTL_PAGES_REPRODUCTION_REQUEST").expect("exact request JSON"),
    )
    .unwrap();
    let root = tempfile::tempdir_in("/private/tmp").unwrap();
    let store =
        super::tests::authenticated_test_store(RuntimePaths::from_root(&root.path().join("state")));
    let mut graph = graph(Path::new(&request.repository));
    let result =
        producer::run(&store, &graph, request).expect("real source-to-output reproduction");
    let receipt: ReproductionReceiptV1 = serde_json::from_value(result.result.clone()).unwrap();
    let input = input(&receipt, &result.evidence[0].content_hash);
    let mut cap = cfctl_core::CapabilityV1::new(
        "wrangler.pages-deploy",
        "Pages",
        "CLI",
        "wrangler pages deploy",
    );
    cap.source = "wrangler 4.107.0 pages deploy help".into();
    cap.adapter_status = cfctl_core::AdapterStatus::DelegatedCli;
    let target = pages_deployment::prepare_target(&store, &graph, &cap, &input)
        .unwrap()
        .unwrap();
    let mut plan = cfctl_core::PlanV1::draft(
        "fixture",
        &receipt.request.account_id,
        "sha256:catalog",
        cap.clone(),
        json!({"adapter":{"pages_deployment":target}}),
    )
    .unwrap();
    plan.input = serde_json::to_value(&input).unwrap();
    graph.repositories[0].git.dirty = true;
    graph.repositories[0].git.head = Some("f".repeat(40));
    pages_deployment::validate_bound_plan(&store, &graph, &plan, &input)
        .expect("actual run admission ignores mutable HEAD");
    let mut staged = input.clone();
    let stage =
        pages_deployment::stage_bound_artifact(&plan.targets["adapter"], &mut staged).unwrap();
    pages_deployment::validate_staged_artifact(&plan.targets["adapter"], &staged).unwrap();
    // Exercise the real delegated argument/output boundary with a mock provider
    // process. It must never receive the local receipt selector as a CLI flag.
    let id = "22222222-2222-4222-8222-222222222222";
    let readback = json!({"id":id,"project_name":receipt.request.project_name,"environment":"production","deployment_trigger":{"metadata":{"branch":receipt.request.branch,"commit_hash":receipt.request.commit}},"latest_stage":{"name":"deploy","status":"success"}});
    let basic = json!({"type":"pages-deploy","version":1,"pages_project":receipt.request.project_name,"deployment_id":id,"url":"https://fixture.pages.dev"});
    let detailed = json!({"type":"pages-deploy-detailed","version":1,"pages_project":receipt.request.project_name,"deployment_id":id,"url":"https://fixture.pages.dev","environment":"production","production_branch":receipt.request.branch,"deployment_trigger":{"metadata":{"commit_hash":receipt.request.commit}}});
    let program = root.path().join("provider-fixture");
    // JSON values derive only from the validated alphanumeric target/branch and
    // Git hash above; the fixture never evaluates repository text as shell code.
    let shell_quote = |s: String| format!("'{}'", s.replace('\'', "'\\''"));
    fs::write(&program,format!("#!/bin/sh\nfor a in \"$@\"; do case \"$a\" in *artifact-receipt*|*artifact_receipt*) exit 23;; esac; done\nprintf '%s\\n' {} {} > \"$WRANGLER_OUTPUT_FILE_PATH\"\n",shell_quote(basic.to_string()),shell_quote(detailed.to_string()))).unwrap();
    let cache = root.path().join("cache");
    fs::create_dir(&cache).unwrap();
    let applied = super::governed_cli::run_delegated_cli(
        &cap,
        &staged,
        &cfctl_auth::AuthCredential::Bearer {
            token: "fixture-token".into(),
        },
        Some(&receipt.request.account_id),
        &cache,
        Some(&program),
        Some(Path::new("/bin/sh")),
    )
    .await
    .unwrap();
    assert_eq!(applied["success"], true);
    assert_eq!(applied["structured_output"]["deployment_id"], id);
    assert!(pages_deployment::deployment_matches_returned_id(
        &readback,
        id,
        &receipt.request.project_name,
        &receipt.request.branch,
        &receipt.request.commit
    ));
    let mut wrong = readback.clone();
    wrong["deployment_trigger"]["metadata"]["commit_hash"] = json!("a".repeat(40));
    assert!(!pages_deployment::deployment_matches_returned_id(
        &wrong,
        id,
        &receipt.request.project_name,
        &receipt.request.branch,
        &receipt.request.commit
    ));
    fs::write(
        Path::new(staged.query["argument"].as_str().unwrap()).join("index.html"),
        "tampered",
    )
    .unwrap();
    assert!(pages_deployment::validate_staged_artifact(&plan.targets["adapter"], &staged).is_err());
    drop(stage);
    plan.account_id = "b".repeat(32);
    assert!(pages_deployment::validate_bound_plan(&store, &graph, &plan, &input).is_err());
}
