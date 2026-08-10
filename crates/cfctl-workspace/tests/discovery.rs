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
fn pages_output_config_is_discovered_as_a_pages_project_not_a_worker() {
    let root = tempfile::tempdir().expect("workspace root");
    init_repo(
        &root.path().join("site-source"),
        "wrangler.toml",
        concat!(
            "name = \"site-project\"\n",
            "compatibility_date = \"2026-04-22\"\n",
            "pages_build_output_dir = \"./target/site\"\n",
        ),
    );

    let graph =
        WorkspaceGraph::discover(&[RegisteredRoot::new(root.path())]).expect("Pages discovery");

    assert!(graph.resources.iter().any(|resource| {
        resource.key == "pages_project:site-project" && resource.kind == "wrangler_pages"
    }));
    assert!(
        graph
            .resources
            .iter()
            .all(|resource| resource.key != "worker:site-project")
    );
}

#[test]
fn nested_fixture_directories_are_excluded_but_explicit_fixture_roots_are_discoverable() {
    let root = tempfile::tempdir().expect("workspace root");
    let repository = root.path().join("production-app");
    init_repo(
        &repository,
        "wrangler.toml",
        concat!(
            "name = \"real-worker\"\n",
            "routes = [{ pattern = \"real.example.com/*\", zone_name = \"example.com\" }]\n",
            "d1_databases = [{ binding = \"DATABASE\", database_id = \"real-d1\" }]\n",
            "r2_buckets = [{ binding = \"ASSETS\", bucket_name = \"real-r2\" }]\n",
        ),
    );
    for (index, basename) in [
        "fixtures",
        "__fixtures__",
        "testdata",
        "test-data",
        "test_data",
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = repository.join("nested").join(basename);
        fs::create_dir_all(&fixture).expect("nested fixture directory");
        fs::write(
            fixture.join("wrangler.toml"),
            format!(
                "name = \"fixture-{index}\"\nroutes = [{{ pattern = \"fixture-{index}.example.com/*\", zone_name = \"fixture-{index}.example.com\" }}]\n"
            ),
        )
        .expect("nested fixture config");
    }

    let graph = WorkspaceGraph::discover(&[RegisteredRoot::new(root.path())])
        .expect("fixture-safe discovery");
    for (key, kind) in [
        ("worker:real-worker", "wrangler_worker"),
        ("hostname:real.example.com", "wrangler_route"),
        ("zone:example.com", "wrangler_zone"),
        ("d1_database:real-d1", "wrangler_d1"),
        ("r2_bucket:real-r2", "wrangler_r2"),
    ] {
        assert!(
            graph
                .resources
                .iter()
                .any(|resource| resource.key == key && resource.kind == kind),
            "missing real resource {key}"
        );
    }
    assert!(
        graph
            .resources
            .iter()
            .all(|resource| !resource.key.contains("fixture-")),
        "nested fixture resources polluted the graph: {:?}",
        graph.resources
    );

    let explicit_fixture = root.path().join("fixtures");
    init_repo(
        &explicit_fixture,
        "wrangler.toml",
        "name = \"fixture-opt-in\"\n",
    );
    let explicit_graph = WorkspaceGraph::discover(&[RegisteredRoot::new(&explicit_fixture)])
        .expect("explicit fixture-root discovery");
    assert!(
        explicit_graph
            .resources
            .iter()
            .any(|resource| resource.key == "worker:fixture-opt-in")
    );
}

#[test]
fn nested_generated_directories_are_excluded_but_remain_explicitly_discoverable() {
    let root = tempfile::tempdir().expect("workspace root");
    let repository = root.path().join("production-app");
    init_repo(&repository, "wrangler.toml", "name = \"real-worker\"\n");
    let generated_repository = repository
        .join("var")
        .join("cargo-home")
        .join("advisory-dbs")
        .join("rustsec");
    init_repo(
        &generated_repository,
        "wrangler.toml",
        "name = \"generated-worker\"\n",
    );

    let graph = WorkspaceGraph::discover(&[RegisteredRoot::new(root.path())])
        .expect("generated-path-safe discovery");
    assert!(
        graph
            .resources
            .iter()
            .any(|resource| resource.key == "worker:real-worker")
    );
    assert!(
        graph
            .resources
            .iter()
            .all(|resource| resource.key != "worker:generated-worker")
    );
    assert!(
        graph
            .repositories
            .iter()
            .all(|repository| repository.path != generated_repository)
    );

    let explicit_graph = WorkspaceGraph::discover(&[RegisteredRoot::new(&generated_repository)])
        .expect("explicit generated-root discovery");
    assert!(
        explicit_graph
            .resources
            .iter()
            .any(|resource| resource.key == "worker:generated-worker")
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
    fs::write(
        terraform.join("main.tf"),
        "resource \"cloudflare_dns_record\" \"api\" {\n  zone_id = \"zone-1\"\n  name = \"api.example.com\"\n  type = \"A\"\n  content = \"198.51.100.2\"\n}\n",
    )
    .expect("staged Terraform edit");
    run_git(&terraform, &["add", "main.tf"]);

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

    let staged = graph
        .repositories
        .iter()
        .find(|repository| repository.name == "terraform")
        .expect("staged repository");
    assert!(staged.git.dirty);
    assert!(staged.git.changes.iter().any(|change| {
        change.path == Path::new("main.tf")
            && change.index_status == "M"
            && change.worktree_status == " "
    }));
    let staged_config = staged
        .configs
        .iter()
        .find(|config| config.path.ends_with("main.tf"))
        .expect("staged config inventory");
    assert!(staged_config.dirty);
    assert_ne!(
        staged_config.content_hash,
        staged_config.head_content_hash.as_deref().unwrap()
    );
    assert!(staged_config.worktree_diff_hash.is_some());

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

#[test]
fn terraform_json_resources_and_data_sources_enter_the_dependency_graph() {
    let root = tempfile::tempdir().expect("workspace root");
    let repository = root.path().join("terraform-json");
    init_repo(
        &repository,
        "main.tf.json",
        r#"{
  "resource": {
    "cloudflare_dns_record": {
      "api": {"zone_id":"zone-1","name":"api.example.com","type":"A","content":"192.0.2.1"}
    }
  },
  "data": {
    "cloudflare_zone": {
      "primary": {"name":"example.com"}
    }
  }
}
"#,
    );

    let graph = WorkspaceGraph::discover(&[RegisteredRoot::new(root.path())])
        .expect("Terraform JSON discovery");

    assert!(graph.resources.iter().any(|resource| {
        resource.key == "terraform:cloudflare_dns_record.api" && resource.kind == "terraform"
    }));
    assert!(graph.resources.iter().any(|resource| {
        resource.key == "terraform:cloudflare_zone.primary" && resource.kind == "terraform_data"
    }));
}

#[test]
fn pulumi_yaml_discovery_preserves_quoted_types_and_interpolated_properties() {
    let root = tempfile::tempdir().expect("workspace root");
    let repository = root.path().join("pulumi-yaml");
    init_repo(
        &repository,
        "Pulumi.yaml",
        r#"name: edge-stack
runtime: yaml
resources:
  worker:
    type: "cloudflare:WorkersScript" # a colon-bearing scalar
    properties:
      scriptName: ${project}-worker
  unrelated:
    type: random:RandomString
"#,
    );

    let graph = WorkspaceGraph::discover(&[RegisteredRoot::new(root.path())])
        .expect("Pulumi YAML discovery");

    assert!(graph.resources.iter().any(|resource| {
        resource.key == "pulumi:cloudflare:WorkersScript.worker" && resource.kind == "pulumi"
    }));
    assert!(
        !graph
            .resources
            .iter()
            .any(|resource| resource.key == "worker:${project}-worker")
    );
    assert!(
        !graph
            .resources
            .iter()
            .any(|resource| resource.key.contains("random:RandomString"))
    );
}

#[test]
fn literal_iac_identities_connect_runtime_targets_to_exact_repositories() {
    let root = tempfile::tempdir().expect("workspace root");
    let terraform_hcl = root.path().join("terraform-hcl");
    let terraform_json = root.path().join("terraform-json");
    let pulumi = root.path().join("pulumi");
    init_repo(
        &terraform_hcl,
        "main.tf",
        "resource \"cloudflare_workers_script\" \"edge\" {\n  script_name = \"literal-worker\"\n}\nresource \"cloudflare_dns_record\" \"api\" {\n  name = \"api.example.com\"\n}\n",
    );
    init_repo(
        &terraform_json,
        "main.tf.json",
        r#"{"resource":{"cloudflare_r2_bucket":{"assets":{"name":"literal-assets"}}}}"#,
    );
    init_repo(
        &pulumi,
        "Pulumi.yaml",
        "name: edge\nruntime: yaml\nresources:\n  queue:\n    type: cloudflare:Queue\n    properties:\n      queueName: literal-jobs\n  record:\n    type: cloudflare:Record\n    properties:\n      name: pulumi.example.com\n",
    );

    let graph = WorkspaceGraph::discover(&[RegisteredRoot::new(root.path())])
        .expect("literal identity discovery");

    for (key, repository) in [
        ("worker:literal-worker", &terraform_hcl),
        ("hostname:api.example.com", &terraform_hcl),
        ("r2_bucket:literal-assets", &terraform_json),
        ("queue:literal-jobs", &pulumi),
        ("hostname:pulumi.example.com", &pulumi),
    ] {
        let canonical = repository
            .canonicalize()
            .expect("canonical fixture repository")
            .display()
            .to_string();
        assert_eq!(
            graph.repositories_for(key),
            vec![canonical],
            "missing {key}"
        );
    }
}

#[test]
fn local_bindings_and_dynamic_iac_expressions_are_not_cloudflare_identities() {
    let root = tempfile::tempdir().expect("workspace root");
    let wrangler = root.path().join("wrangler");
    let terraform = root.path().join("terraform");
    init_repo(
        &wrangler,
        "wrangler.toml",
        "name = \"worker\"\nkv_namespaces = [{ binding = \"CACHE\" }]\nr2_buckets = [{ binding = \"ASSETS\" }]\n",
    );
    init_repo(
        &terraform,
        "main.tf",
        "resource \"cloudflare_workers_script\" \"edge\" {\n  script_name = var.worker_name\n}\n",
    );

    let graph = WorkspaceGraph::discover(&[RegisteredRoot::new(root.path())])
        .expect("poison identity discovery");
    for key in [
        "kv_namespace:CACHE",
        "r2_bucket:ASSETS",
        "worker:var.worker_name",
    ] {
        assert!(
            graph.repositories_for(key).is_empty(),
            "invented identity {key}"
        );
    }
}

#[test]
fn supported_iac_fixture_matrix_preserves_cross_repository_identity_and_untracked_state() {
    let root = tempfile::tempdir().expect("workspace root");
    let service_a = root.path().join("team-a/service");
    let service_b = root.path().join("team-b/service");
    let wrangler_jsonc = root.path().join("wrangler-jsonc");
    let terraform_hcl = root.path().join("terraform-hcl");
    let terraform_json = root.path().join("terraform-json");
    let pulumi_project = root.path().join("pulumi-yaml");
    let pulumi_stack = root.path().join("pulumi-yml");
    let untracked = root.path().join("untracked-config");
    let configless = root.path().join("configless");

    init_repo(
        &service_a,
        "wrangler.toml",
        "name = \"service-a\"\nroutes = [{ pattern = \"shared.example.com/*\", zone_name = \"example.com\" }]\n",
    );
    init_repo(
        &service_b,
        "wrangler.json",
        "{\"name\":\"service-b\",\"routes\":[{\"pattern\":\"shared.example.com/*\",\"zone_name\":\"example.com\"}]}\n",
    );
    init_repo(
        &wrangler_jsonc,
        "wrangler.jsonc",
        "{\n  // all supported JSONC features\n  \"name\": \"jsonc-worker\",\n  \"kv_namespaces\": [{\"binding\":\"CACHE\",\"id\":\"kv-1\"}],\n}\n",
    );
    init_repo(
        &terraform_hcl,
        "main.tf",
        "data \"cloudflare_zone\" \"primary\" {\n  name = \"example.com\"\n}\n",
    );
    init_repo(
        &terraform_json,
        "main.tf.json",
        "{\"resource\":{\"cloudflare_r2_bucket\":{\"assets\":{\"name\":\"assets\"}}}}\n",
    );
    init_repo(
        &pulumi_project,
        "Pulumi.yaml",
        "name: yaml-stack\nruntime: yaml\nresources:\n  queue:\n    type: cloudflare:Queue\n",
    );
    init_repo(
        &pulumi_stack,
        "Pulumi.prod.yml",
        "name: yml-stack\nruntime: yaml\nresources:\n  worker:\n    type: cloudflare:WorkersScript\n",
    );
    init_repo(
        &untracked,
        "README.md",
        "The Cloudflare config is intentionally untracked.\n",
    );
    fs::write(
        untracked.join("wrangler.json"),
        "{\"name\":\"untracked-worker\"}\n",
    )
    .expect("untracked Cloudflare config");
    init_repo(&configless, "README.md", "No Cloudflare configuration.\n");

    let graph = WorkspaceGraph::discover(&[RegisteredRoot::new(root.path())])
        .expect("supported IaC matrix discovery");

    assert_eq!(graph.repositories.len(), 9);
    assert_eq!(
        graph
            .repositories
            .iter()
            .filter(|repository| repository.name == "service")
            .count(),
        2
    );
    for (key, kind) in [
        ("worker:service-a", "wrangler_worker"),
        ("worker:service-b", "wrangler_worker"),
        ("kv_namespace:kv-1", "wrangler_kv"),
        ("terraform:cloudflare_zone.primary", "terraform_data"),
        ("terraform:cloudflare_r2_bucket.assets", "terraform"),
        ("pulumi:cloudflare:Queue.queue", "pulumi"),
        ("pulumi:cloudflare:WorkersScript.worker", "pulumi"),
        ("worker:untracked-worker", "wrangler_worker"),
    ] {
        assert!(
            graph
                .resources
                .iter()
                .any(|resource| resource.key == key && resource.kind == kind),
            "missing {kind} resource {key}"
        );
    }

    let shared = graph.impact_for(&["hostname:shared.example.com".to_owned()]);
    assert_eq!(shared.affected_repositories.len(), 2);
    let first_service_root = service_a.canonicalize().expect("canonical service A");
    let second_service_root = service_b.canonicalize().expect("canonical service B");
    assert!(
        shared
            .affected_repositories
            .iter()
            .any(|repository| repository == &first_service_root.display().to_string())
    );
    assert!(
        shared
            .affected_repositories
            .iter()
            .any(|repository| repository == &second_service_root.display().to_string())
    );

    let untracked_canonical = untracked.canonicalize().expect("canonical untracked repo");
    let untracked_repository = graph
        .repositories
        .iter()
        .find(|repository| repository.path == untracked_canonical)
        .expect("untracked repository");
    let untracked_config = untracked_repository
        .configs
        .iter()
        .find(|config| config.path.ends_with("wrangler.json"))
        .expect("untracked config");
    assert!(untracked_config.dirty);
    assert!(untracked_config.head_content_hash.is_none());
    assert!(untracked_config.worktree_diff_hash.is_some());
    let configless_canonical = configless
        .canonicalize()
        .expect("canonical configless repo");
    assert!(graph.repositories.iter().any(|repository| {
        repository.path == configless_canonical && repository.cloudflare_configs.is_empty()
    }));
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
