#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::{fs, path::Path, process::Command};

use cfctl_workspace::{RegisteredRoot, WorkspaceGraph};

#[test]
fn discovery_stays_inside_registered_roots_and_finds_cloudflare_configs() {
    let root = tempfile::tempdir().expect("temp root");
    let outside = tempfile::tempdir().expect("outside root");
    init_repo(
        &root.path().join("app-a"),
        "wrangler.toml",
        "name = \"app-a\"\nroutes = [{ pattern = \"app.example.com/*\", zone_name = \"example.com\" }]\n",
    );
    fs::write(outside.path().join("wrangler.toml"), "name = \"outside\"\n")
        .expect("outside fixture");

    let graph = WorkspaceGraph::discover(&[RegisteredRoot::new(root.path())])
        .expect("registered discovery");
    assert_eq!(graph.repositories.len(), 1);
    assert_eq!(graph.repositories[0].name, "app-a");
    assert!(
        graph
            .resources
            .iter()
            .any(|r| r.key == "hostname:app.example.com")
    );
    assert!(
        !graph
            .repositories
            .iter()
            .any(|r| r.path.starts_with(outside.path()))
    );
}

#[test]
fn impact_query_returns_every_repository_linked_to_a_resource() {
    let graph = WorkspaceGraph::from_links([
        ("repo-a", "hostname:api.example.com"),
        ("repo-b", "hostname:api.example.com"),
        ("repo-c", "hostname:other.example.com"),
    ]);
    let impacted = graph.repositories_for("hostname:api.example.com");
    assert_eq!(impacted, vec!["repo-a", "repo-b"]);
}

#[test]
fn multi_repository_fixture_covers_iac_kinds_and_exact_git_state() {
    let root = tempfile::tempdir().expect("workspace root");
    let wrangler_toml = root.path().join("wrangler-toml");
    let wrangler_jsonc = root.path().join("wrangler-jsonc");
    let terraform = root.path().join("terraform");
    let pulumi = root.path().join("pulumi");
    let configless = root.path().join("configless");

    init_repo(
        &wrangler_toml,
        "wrangler.toml",
        "name = \"worker-a\"\nroutes = [{ pattern = \"api.example.com/*\", zone_name = \"example.com\" }]\n",
    );
    init_repo(
        &wrangler_jsonc,
        "wrangler.jsonc",
        "{\n  // production route\n  \"name\": \"worker-b\",\n  \"routes\": [{\"pattern\": \"edge.example.com/*\", \"zone_name\": \"example.com\"}]\n}\n",
    );
    init_repo(
        &terraform,
        "main.tf",
        "resource \"cloudflare_dns_record\" \"api\" {\n  zone_id = \"zone-1\"\n  name = \"api.example.com\"\n  type = \"A\"\n  content = \"192.0.2.1\"\n}\n",
    );
    init_repo(
        &pulumi,
        "Pulumi.yaml",
        "name: edge-stack\nruntime: yaml\nresources:\n  dnsRecord:\n    type: cloudflare:Record\n    properties:\n      zoneId: zone-1\n      name: pulumi.example.com\n",
    );
    init_repo(
        &configless,
        "README.md",
        "No Cloudflare configuration yet.\n",
    );
    fs::write(
        wrangler_toml.join("wrangler.toml"),
        "name = \"worker-a\"\nroutes = [{ pattern = \"changed.example.com/*\", zone_name = \"example.com\" }]\n",
    )
    .expect("dirty config");
    fs::write(wrangler_toml.join("untracked.txt"), "local work\n").expect("untracked file");

    let graph = WorkspaceGraph::discover(&[RegisteredRoot::new(root.path())])
        .expect("multi-repository discovery");

    assert_eq!(graph.repositories.len(), 5);
    assert!(graph.repositories.iter().any(|repository| {
        repository.name == "configless" && repository.cloudflare_configs.is_empty()
    }));
    assert!(graph.resources.iter().any(|resource| {
        resource.key == "hostname:changed.example.com" && resource.kind == "wrangler_route"
    }));
    assert!(graph.resources.iter().any(|resource| {
        resource.key == "hostname:edge.example.com" && resource.kind == "wrangler_route"
    }));
    assert!(graph.resources.iter().any(|resource| {
        resource.key == "terraform:cloudflare_dns_record.api" && resource.kind == "terraform"
    }));
    assert!(graph.resources.iter().any(|resource| {
        resource.key == "pulumi:cloudflare:Record.dnsRecord" && resource.kind == "pulumi"
    }));

    let dirty = graph
        .repositories
        .iter()
        .find(|repository| repository.name == "wrangler-toml")
        .expect("dirty repository");
    assert!(dirty.git.dirty);
    assert!(
        dirty
            .git
            .changes
            .iter()
            .any(|change| change.path == Path::new("wrangler.toml"))
    );
    let config = dirty
        .configs
        .iter()
        .find(|config| config.path.ends_with("wrangler.toml"))
        .expect("config inventory");
    assert!(config.dirty);
    assert_ne!(
        config.content_hash,
        config.head_content_hash.as_deref().unwrap()
    );
    assert!(config.worktree_diff_hash.is_some());

    let impact = graph.impact_for(&["hostname:changed.example.com".to_owned()]);
    assert!(impact.has_dirty_overlap);
    assert!(!impact.has_unmanaged_dependencies);
    assert_eq!(impact.affected_repositories.len(), 1);
    assert!(
        impact.local_diffs.iter().any(|diff| {
            diff.path.ends_with("wrangler.toml") && diff.worktree_diff_hash.is_some()
        })
    );

    let unmanaged = graph.impact_for(&["hostname:unmanaged.example.com".to_owned()]);
    assert!(unmanaged.has_unmanaged_dependencies);
    assert_eq!(
        unmanaged.unmanaged_resources,
        vec!["hostname:unmanaged.example.com"]
    );
}

fn init_repo(path: &Path, config_name: &str, content: &str) {
    fs::create_dir_all(path).expect("repository directory");
    run_git(path, &["init", "--quiet"]);
    run_git(path, &["config", "user.name", "cfctl fixture"]);
    run_git(path, &["config", "user.email", "cfctl@example.invalid"]);
    fs::write(path.join(config_name), content).expect("fixture config");
    run_git(path, &["add", config_name]);
    run_git(path, &["commit", "--quiet", "-m", "fixture"]);
}

fn run_git(path: &Path, arguments: &[&str]) {
    let output = Command::new("git")
        .current_dir(path)
        .args(arguments)
        .output()
        .expect("git command");
    assert!(
        output.status.success(),
        "git {:?}: {}",
        arguments,
        String::from_utf8_lossy(&output.stderr)
    );
}
