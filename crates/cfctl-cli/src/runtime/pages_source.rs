use super::entitlement_state::should_bind_pages_project_absence;
use super::prelude::{
    CallInput, CapabilityV1, CliError, Duration, ImpactContext, OsString, Path, PathBuf,
    RepositoryNode, Result, StateStore, Value, WorkspaceGraph, env, json,
};
use super::workspace_state::discover_registered;
use super::workspace_state::hash_directory_artifact;
use super::{
    pages_deployment, worker_deployment, workspace_d1_migration, workspace_d1_projection,
    workspace_d1_reply_admission, workspace_reply_subdomain_ingress,
};

pub(super) const SOURCE_REMOTE_PRECONDITION: &str = "pages_source_remote";
pub(super) const GIT_CONFIG_TIMEOUT: Duration = Duration::from_secs(5);
const GIT_REMOTE_TIMEOUT: Duration = Duration::from_secs(15);

pub(super) struct PlannedImpact {
    pub(super) policy: ImpactContext,
    pub(super) affected_repositories: Vec<String>,
    pub(super) affected_resources: Vec<String>,
    pub(super) local_diffs: Vec<Value>,
    pub(super) local_artifact_paths: Vec<PathBuf>,
}

pub(super) fn pages_github_source(input: &CallInput) -> Result<(&str, &str, &str)> {
    let body = input.body.as_ref().ok_or_else(|| {
        CliError::Input("Pages Git integration requires a request body".to_owned())
    })?;
    if body.pointer("/source/type").and_then(Value::as_str) != Some("github") {
        return Err(CliError::Input(
            "Pages project creation requires an exact GitHub source input".to_owned(),
        ));
    }
    let required = |pointer: &str, label: &str| {
        body.pointer(pointer)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| CliError::Input(format!("Pages Git source requires `{label}`")))
    };
    let owner = required("/source/config/owner", "source.config.owner")?;
    let repository = required("/source/config/repo_name", "source.config.repo_name")?;
    let branch = required("/production_branch", "production_branch")?;
    if body
        .pointer("/source/config/production_branch")
        .and_then(Value::as_str)
        != Some(branch)
    {
        return Err(CliError::Input(
            "Pages source and project production branches must match exactly".to_owned(),
        ));
    }
    if !github_path_segment_is_safe(owner)
        || !github_path_segment_is_safe(repository)
        || !git_branch_name_is_safe(branch)
    {
        return Err(CliError::Input(
            "Pages Git source repository or branch identity is malformed".to_owned(),
        ));
    }
    Ok((owner, repository, branch))
}

pub(super) fn github_path_segment_is_safe(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

pub(super) fn git_branch_name_is_safe(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && !value.starts_with('.')
        && !value.ends_with('.')
        && !value.ends_with('/')
        && !value.contains("..")
        && !value.contains("@{")
        && !value.bytes().any(|byte| {
            byte <= b' '
                || byte == 0x7f
                || matches!(byte, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
        })
}

pub(super) fn github_remote_identity(remote: &str) -> Option<(String, String)> {
    let path = if let Some(path) = remote.strip_prefix("git@github.com:") {
        path.to_owned()
    } else {
        let parsed = url::Url::parse(remote).ok()?;
        let valid_https = parsed.scheme() == "https" && parsed.username().is_empty();
        let valid_ssh = parsed.scheme() == "ssh" && parsed.username() == "git";
        if (!valid_https && !valid_ssh)
            || parsed.password().is_some()
            || parsed.port().is_some()
            || parsed.host_str() != Some("github.com")
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return None;
        }
        parsed.path().trim_start_matches('/').to_owned()
    };
    let path = path.strip_suffix(".git").unwrap_or(&path);
    let mut segments = path.split('/');
    let owner = segments.next()?;
    let repository = segments.next()?;
    if segments.next().is_some()
        || !github_path_segment_is_safe(owner)
        || !github_path_segment_is_safe(repository)
    {
        return None;
    }
    Some((owner.to_ascii_lowercase(), repository.to_ascii_lowercase()))
}

#[derive(Debug)]
pub(super) struct BoundedPagesGitOutput {
    pub(super) success: bool,
    pub(super) code: Option<i32>,
    pub(super) stdout: String,
}

pub(super) fn run_bounded_pages_git_program(
    program: &Path,
    repository_root: Option<&Path>,
    arguments: &[&str],
    timeout: Duration,
) -> Result<BoundedPagesGitOutput> {
    let program = program.to_path_buf();
    let repository_root = repository_root.map(Path::to_path_buf);
    let arguments = arguments
        .iter()
        .map(OsString::from)
        .collect::<Vec<OsString>>();
    let path = env::var_os("PATH").unwrap_or_default();
    let inherited_environment = [
        "HOME",
        "XDG_CONFIG_HOME",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "SSH_AUTH_SOCK",
    ]
    .into_iter()
    .filter_map(|name| env::var_os(name).map(|value| (name, value)))
    .collect::<Vec<_>>();

    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| {
                CliError::Input("Pages source Git proof runtime was unavailable".to_owned())
            })?;
        runtime.block_on(async move {
            let mut command = processkit::Command::new(&program);
            if let Some(repository_root) = repository_root {
                command = command.arg("-C").arg(repository_root);
            } else {
                command = command.current_dir(env::temp_dir());
            }
            command = command
                .args(arguments)
                .env_clear()
                .env("PATH", path)
                .env("GIT_TERMINAL_PROMPT", "0")
                .env("GIT_ASKPASS", "")
                .env("SSH_ASKPASS", "")
                .env("SSH_ASKPASS_REQUIRE", "never")
                .env("GCM_INTERACTIVE", "Never")
                .stdin(processkit::Stdin::empty())
                .stderr(processkit::StdioMode::Null)
                .output_buffer(processkit::OutputBufferPolicy::bounded(8_192).with_max_bytes(8_192))
                .timeout(timeout);
            for (name, value) in inherited_environment {
                command = command.env(name, value);
            }
            let output = command.output_bytes().await.map_err(|_| {
                CliError::Input("Pages source Git proof could not start or complete".to_owned())
            })?;
            if output.timed_out() {
                return Err(CliError::SubprocessTimeout {
                    label: "Pages source Git proof".to_owned(),
                    timeout_seconds: timeout.as_secs(),
                });
            }
            if output.truncated() || output.stdout().len() > 8_192 {
                return Err(CliError::Input(
                    "Pages source Git proof output exceeded its fixed bound".to_owned(),
                ));
            }
            let stdout = String::from_utf8(output.stdout().clone()).map_err(|_| {
                CliError::Input("Pages source Git proof output was not UTF-8".to_owned())
            })?;
            Ok(BoundedPagesGitOutput {
                success: output.is_success(),
                code: output.code(),
                stdout,
            })
        })
    })
    .join()
    .map_err(|_| CliError::Input("Pages source Git proof runtime failed".to_owned()))?
}

pub(super) fn pages_git_output(
    repository_root: Option<&Path>,
    arguments: &[&str],
    timeout: Duration,
    allow_no_match: bool,
) -> Result<String> {
    let output =
        run_bounded_pages_git_program(Path::new("git"), repository_root, arguments, timeout)?;
    if output.success {
        return Ok(output.stdout);
    }
    if allow_no_match && output.code == Some(1) && output.stdout.is_empty() {
        return Ok(String::new());
    }
    Err(CliError::Input(
        "Pages source Git proof failed without exposing subprocess output".to_owned(),
    ))
}

pub(super) fn configured_origin(repository_root: &Path) -> Result<Option<String>> {
    let output = pages_git_output(
        Some(repository_root),
        &["config", "--get-all", "remote.origin.url"],
        GIT_CONFIG_TIMEOUT,
        true,
    )?;
    if output.is_empty() {
        return Ok(None);
    }
    let rows = output.lines().collect::<Vec<_>>();
    if rows.len() != 1 || rows[0].is_empty() || rows[0].trim() != rows[0] {
        return Err(CliError::Input(
            "Pages source repository must have exactly one raw effective origin URL".to_owned(),
        ));
    }
    Ok(Some(rows[0].to_owned()))
}

pub(super) fn matching_git_url_rewrite(config: &str, candidates: &[&str]) -> Result<bool> {
    for row in config.lines().filter(|row| !row.is_empty()) {
        let Some(separator) = row.find(char::is_whitespace) else {
            return Err(CliError::Input(
                "Pages source Git URL rewrite configuration was malformed".to_owned(),
            ));
        };
        let (key, value) = row.split_at(separator);
        let value = value.trim();
        if !key.starts_with("url.") || !key.ends_with(".insteadof") || value.is_empty() {
            return Err(CliError::Input(
                "Pages source Git URL rewrite configuration was malformed".to_owned(),
            ));
        }
        if candidates
            .iter()
            .any(|candidate| candidate.starts_with(value))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(super) fn registered_pages_source_repository<'a>(
    graph: &'a WorkspaceGraph,
    input: &CallInput,
) -> Result<&'a RepositoryNode> {
    let (owner, repository, _) = pages_github_source(input)?;
    let expected = (owner.to_ascii_lowercase(), repository.to_ascii_lowercase());
    let mut matches = Vec::new();
    for candidate in &graph.repositories {
        let Ok(Some(origin)) = configured_origin(&candidate.path) else {
            continue;
        };
        if github_remote_identity(&origin).as_ref() == Some(&expected) {
            matches.push(candidate);
        }
    }
    if matches.len() != 1 {
        return Err(CliError::Input(format!(
            "Pages Git source must match exactly one registered repository; found {}",
            matches.len()
        )));
    }
    Ok(matches[0])
}

pub(super) fn parse_pages_remote_head(output: &str, branch: &str) -> Result<String> {
    let expected_ref = format!("refs/heads/{branch}");
    let rows = output.lines().collect::<Vec<_>>();
    let Some(row) = rows.first() else {
        return Err(CliError::Input(
            "Pages source branch did not resolve to one exact remote commit".to_owned(),
        ));
    };
    let Some((commit, remote_ref)) = row.split_once('\t') else {
        return Err(CliError::Input(
            "Pages source branch returned a malformed remote identity".to_owned(),
        ));
    };
    if rows.len() != 1 || remote_ref != expected_ref || !is_canonical_git_sha1(commit) {
        return Err(CliError::Input(
            "Pages source branch did not resolve to one exact remote commit".to_owned(),
        ));
    }
    Ok(commit.to_owned())
}

pub(super) fn is_canonical_git_sha1(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn pages_source_remote_receipt(input: &CallInput, remote_commit: &str) -> Result<Value> {
    let (owner, repository, branch) = pages_github_source(input)?;
    if !is_canonical_git_sha1(remote_commit) {
        return Err(CliError::Input(
            "Pages source branch returned a malformed remote commit".to_owned(),
        ));
    }
    Ok(json!({
        "schema_version": 1,
        "provider": "github",
        "owner": owner.to_ascii_lowercase(),
        "repository": repository.to_ascii_lowercase(),
        "branch": branch,
        "remote_ref": format!("refs/heads/{branch}"),
        "remote_commit": remote_commit,
    }))
}

pub(super) fn pages_source_remote_snapshot(
    repository: &RepositoryNode,
    input: &CallInput,
) -> Result<Value> {
    let (owner, repository_name, branch) = pages_github_source(input)?;
    let expected = (
        owner.to_ascii_lowercase(),
        repository_name.to_ascii_lowercase(),
    );
    let origin = configured_origin(&repository.path)?.ok_or_else(|| {
        CliError::Input("Pages source repository has no raw local origin URL".to_owned())
    })?;
    if github_remote_identity(&origin).as_ref() != Some(&expected) {
        return Err(CliError::Input(
            "Pages source repository origin drifted from the reviewed GitHub identity".to_owned(),
        ));
    }
    let canonical_remote = format!("https://github.com/{owner}/{repository_name}.git");
    let rewrites = pages_git_output(
        Some(&repository.path),
        &["config", "--get-regexp", "^url\\..*\\.insteadof$"],
        GIT_CONFIG_TIMEOUT,
        true,
    )?;
    if matching_git_url_rewrite(&rewrites, &[&origin, &canonical_remote])? {
        return Err(CliError::Input(
            "Pages source Git identity is subject to a configured URL substitution".to_owned(),
        ));
    }
    let remote_ref = format!("refs/heads/{branch}");
    let output = pages_git_output(
        None,
        &[
            "-c",
            "credential.helper=",
            "ls-remote",
            "--exit-code",
            "--refs",
            &canonical_remote,
            &remote_ref,
        ],
        GIT_REMOTE_TIMEOUT,
        false,
    )?;
    let remote_commit = parse_pages_remote_head(&output, branch)?;
    pages_source_remote_receipt(input, &remote_commit)
}

pub(super) fn plan_impact(
    store: &StateStore,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
) -> Result<PlannedImpact> {
    let selector_map = input.selectors.as_object();
    let query_map = input.query.as_object();
    let missing_required = capability.selectors.iter().any(|selector| {
        if !selector.required || (selector.name == "account_id" && !account_id.is_empty()) {
            return false;
        }
        let values = if selector.location == "query" {
            query_map
        } else {
            selector_map
        };
        values.and_then(|map| map.get(&selector.name)).is_none()
    });
    let graph = discover_registered(store)?;
    let mut affected_resources = Vec::new();
    if let Some(selectors) = selector_map {
        for (key, value) in selectors {
            if let Some(value) = value.as_str() {
                affected_resources.push(format!("{key}:{value}"));
            }
        }
    }
    let workspace_resource_keys = workspace_resource_keys(capability, input);
    affected_resources.extend(workspace_resource_keys.iter().cloned());
    affected_resources.sort();
    affected_resources.dedup();
    let workspace_impact = graph.impact_for(&workspace_resource_keys);
    let local_artifact_paths = plan_local_artifact_paths(capability, input)?;
    let mut affected_repositories = workspace_impact.affected_repositories.clone();
    if should_bind_pages_project_absence(capability) {
        let source_repository = registered_pages_source_repository(&graph, input)?;
        affected_repositories.push(source_repository.path.display().to_string());
    }
    for artifact in &local_artifact_paths {
        let repository = repository_owning_path(&graph, artifact).ok_or_else(|| {
            CliError::Input(format!(
                "local deployment artifact `{}` is not owned by a registered repository",
                artifact.display()
            ))
        })?;
        affected_repositories.push(repository.path.display().to_string());
    }
    affected_repositories.sort();
    affected_repositories.dedup();
    affected_resources.extend(
        local_artifact_paths
            .iter()
            .map(|path| format!("source_artifact:{}", path.display())),
    );
    affected_resources.sort();
    affected_resources.dedup();
    let mut local_diffs = workspace_impact
        .local_diffs
        .iter()
        .map(serde_json::to_value)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    append_local_artifact_diffs(&graph, &local_artifact_paths, &mut local_diffs)?;
    for repository_id in &affected_repositories {
        let Some(repository) = graph.repository(repository_id) else {
            continue;
        };
        for config in &repository.configs {
            let diff = json!({
                "repository": repository.path,
                "path": config.path,
                "kind": config.kind,
                "content_hash": config.content_hash,
                "head_content_hash": config.head_content_hash,
                "worktree_diff_hash": config.worktree_diff_hash,
                "dirty": config.dirty,
            });
            if !local_diffs.contains(&diff) {
                local_diffs.push(diff);
            }
        }
    }
    local_diffs.sort_by_key(|value| value["path"].as_str().unwrap_or_default().to_owned());
    let policy = ImpactContext {
        affected_repositories: affected_repositories.len(),
        affected_resources: affected_resources.len(),
        dependent_configurations: local_diffs.len(),
        has_unmanaged_dependencies: workspace_impact.has_unmanaged_dependencies,
        has_dirty_overlap: affected_repositories.iter().any(|repository_id| {
            graph
                .repository(repository_id)
                .is_some_and(|repository| repository.git.dirty)
        }),
        selector_ambiguous: missing_required,
    };
    Ok(PlannedImpact {
        policy,
        affected_repositories,
        affected_resources,
        local_diffs,
        local_artifact_paths,
    })
}

pub(super) fn append_local_artifact_diffs(
    graph: &WorkspaceGraph,
    artifact_paths: &[PathBuf],
    local_diffs: &mut Vec<Value>,
) -> Result<()> {
    for artifact in artifact_paths {
        let repository = repository_owning_path(graph, artifact).ok_or_else(|| {
            CliError::Input(format!(
                "local deployment artifact `{}` is not owned by a registered repository",
                artifact.display()
            ))
        })?;
        local_diffs.push(json!({
            "repository": repository.path,
            "path": artifact,
            "kind": "deployment_artifact",
            "content_hash": hash_directory_artifact(artifact)?,
            "head_content_hash": Value::Null,
            "worktree_diff_hash": Value::Null,
            "dirty": false,
        }));
    }
    Ok(())
}

pub(super) fn plan_local_artifact_paths(
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<Vec<PathBuf>> {
    if let Some(paths) = workspace_reply_subdomain_ingress::local_artifact_paths(capability) {
        return Ok(paths);
    }
    if let Some(paths) = workspace_d1_migration::local_artifact_paths(capability)? {
        return Ok(paths);
    }
    if let Some(paths) = workspace_d1_projection::local_artifact_paths(capability)? {
        return Ok(paths);
    }
    if let Some(paths) = workspace_d1_reply_admission::local_artifact_paths(capability)? {
        return Ok(paths);
    }
    if worker_deployment::binds_artifact(capability) {
        return worker_deployment::artifact_paths(capability, input);
    }
    pages_deployment::artifact_paths(capability, input)
}

pub(super) fn repository_owning_path<'a>(
    graph: &'a WorkspaceGraph,
    path: &Path,
) -> Option<&'a cfctl_workspace::RepositoryNode> {
    graph
        .repositories
        .iter()
        .filter(|repository| path.starts_with(&repository.path))
        .max_by_key(|repository| repository.path.components().count())
}

pub(super) fn workspace_resource_keys(capability: &CapabilityV1, input: &CallInput) -> Vec<String> {
    let mut resources = Vec::new();
    collect_workspace_resource_keys(capability, &input.selectors, None, &mut resources);
    collect_workspace_resource_keys(capability, &input.query, None, &mut resources);
    if let Some(body) = &input.body {
        collect_workspace_resource_keys(capability, body, None, &mut resources);
        if should_bind_pages_project_absence(capability)
            && let Some(name) = body.get("name").and_then(Value::as_str)
            && !name.is_empty()
        {
            resources.push(format!("pages_project:{name}"));
        }
    }
    resources.sort();
    resources.dedup();
    resources
}

pub(super) fn collect_workspace_resource_keys(
    capability: &CapabilityV1,
    value: &Value,
    field: Option<&str>,
    resources: &mut Vec<String>,
) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                collect_workspace_resource_keys(capability, value, Some(key), resources);
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_workspace_resource_keys(capability, value, field, resources);
            }
        }
        Value::String(value) => {
            let field = field.unwrap_or_default().to_ascii_lowercase();
            let product = capability.product.to_ascii_lowercase();
            let is_hostname_name = field == "name"
                && value.contains('.')
                && (capability.path.contains("/dns_records") || product.contains("dns record"));
            let is_hostname_pattern = field == "pattern"
                && (capability.path.contains("/workers/routes")
                    || product.contains("worker route"));
            let resource = if field.contains("hostname") || is_hostname_name || is_hostname_pattern
            {
                hostname_from_resource_value(value).map(|hostname| format!("hostname:{hostname}"))
            } else if field == "zone_name" {
                Some(format!("zone:{value}"))
            } else if matches!(field.as_str(), "script_name" | "worker" | "worker_name") {
                Some(format!("worker:{value}"))
            } else if matches!(field.as_str(), "bucket_name" | "r2_bucket") {
                Some(format!("r2_bucket:{value}"))
            } else if matches!(field.as_str(), "database_id" | "database_name") {
                Some(format!("d1_database:{value}"))
            } else if matches!(field.as_str(), "namespace_id" | "kv_namespace_id")
                && (capability.path.contains("/storage/kv/namespaces")
                    || product == "workers kv namespace")
            {
                Some(format!("kv_namespace:{value}"))
            } else if matches!(field.as_str(), "queue" | "queue_name") {
                Some(format!("queue:{value}"))
            } else if matches!(field.as_str(), "service" | "service_name") {
                Some(format!("service:{value}"))
            } else {
                None
            };
            if let Some(resource) = resource {
                resources.push(resource);
            }
        }
        _ => {}
    }
}

pub(super) fn hostname_from_resource_value(value: &str) -> Option<String> {
    let without_scheme = value
        .split_once("://")
        .map_or(value, |(_, remainder)| remainder);
    let hostname = without_scheme
        .split('/')
        .next()
        .unwrap_or_default()
        .trim_start_matches("*.")
        .trim_end_matches('*')
        .trim_end_matches('.');
    (!hostname.is_empty()).then(|| hostname.to_owned())
}
