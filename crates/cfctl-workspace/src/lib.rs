//! Registered-root discovery and cross-repository Cloudflare impact graph.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use walkdir::{DirEntry, WalkDir};

#[derive(Debug, Error)]
pub enum WorkspaceError {
    #[error("registered root does not exist: {0}")]
    MissingRoot(String),
    #[error("failed to read workspace path {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("git inspection failed for {repository}: {message}")]
    Git { repository: String, message: String },
    #[error("workspace discovery invariant failed: {0}")]
    DiscoveryInvariant(String),
}

pub type Result<T> = std::result::Result<T, WorkspaceError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisteredRoot {
    pub path: PathBuf,
}

impl RegisteredRoot {
    #[must_use]
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitChangeV1 {
    pub path: PathBuf,
    pub index_status: String,
    pub worktree_status: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitStateV1 {
    pub head: Option<String>,
    pub branch: Option<String>,
    pub dirty: bool,
    pub changes: Vec<GitChangeV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceConfigV1 {
    pub path: PathBuf,
    pub kind: String,
    pub content_hash: String,
    pub head_content_hash: Option<String>,
    pub worktree_diff_hash: Option<String>,
    pub dirty: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepositoryNode {
    pub name: String,
    pub path: PathBuf,
    pub cloudflare_configs: Vec<PathBuf>,
    #[serde(default)]
    pub configs: Vec<SourceConfigV1>,
    #[serde(default)]
    pub git: GitStateV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceNode {
    pub key: String,
    #[serde(default)]
    pub kind: String,
    pub source: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalConfigDiffV1 {
    pub repository: PathBuf,
    pub path: PathBuf,
    pub kind: String,
    pub content_hash: String,
    pub head_content_hash: Option<String>,
    pub worktree_diff_hash: Option<String>,
    pub dirty: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceImpactV1 {
    pub affected_repositories: Vec<String>,
    pub affected_resources: Vec<String>,
    pub unmanaged_resources: Vec<String>,
    pub local_diffs: Vec<LocalConfigDiffV1>,
    pub has_dirty_overlap: bool,
    pub has_unmanaged_dependencies: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceGraph {
    pub repositories: Vec<RepositoryNode>,
    pub resources: Vec<ResourceNode>,
    pub links: BTreeMap<String, BTreeSet<String>>,
}

impl WorkspaceGraph {
    /// Discovers only explicitly registered roots and skips generated/vendor
    /// directories. Repository IDs in discovered links are absolute paths so
    /// two repositories with the same basename cannot collapse together.
    pub fn discover(roots: &[RegisteredRoot]) -> Result<Self> {
        let mut graph = Self::default();
        let mut repositories: BTreeMap<PathBuf, RepositoryNode> = BTreeMap::new();
        for root in roots {
            if !root.path.is_dir() {
                return Err(WorkspaceError::MissingRoot(root.path.display().to_string()));
            }
            discover_root(root, &mut repositories, &mut graph)?;
        }
        graph.repositories = repositories.into_values().collect();
        for repository in &mut graph.repositories {
            repository.cloudflare_configs.sort();
            repository
                .configs
                .sort_by(|left, right| left.path.cmp(&right.path));
        }
        graph
            .repositories
            .sort_by(|left, right| left.path.cmp(&right.path));
        graph.resources.sort_by(|left, right| {
            (&left.key, &left.source, &left.kind).cmp(&(&right.key, &right.source, &right.kind))
        });
        graph.resources.dedup();
        Ok(graph)
    }

    #[must_use]
    pub fn from_links<const N: usize>(links: [(&str, &str); N]) -> Self {
        let mut graph = Self::default();
        for (repository, resource) in links {
            graph
                .links
                .entry(resource.to_owned())
                .or_default()
                .insert(repository.to_owned());
        }
        graph
    }

    #[must_use]
    pub fn repositories_for(&self, resource_key: &str) -> Vec<String> {
        self.links
            .get(resource_key)
            .map(|repositories| repositories.iter().cloned().collect())
            .unwrap_or_default()
    }

    #[must_use]
    pub fn repository(&self, path: &str) -> Option<&RepositoryNode> {
        self.repositories
            .iter()
            .find(|repository| repository.path == Path::new(path))
    }

    #[must_use]
    pub fn impact_for(&self, resource_keys: &[String]) -> WorkspaceImpactV1 {
        let mut impact = WorkspaceImpactV1 {
            affected_resources: resource_keys.to_vec(),
            ..WorkspaceImpactV1::default()
        };
        for resource in resource_keys {
            if let Some(repositories) = self.links.get(resource) {
                impact
                    .affected_repositories
                    .extend(repositories.iter().cloned());
            } else {
                impact.unmanaged_resources.push(resource.clone());
            }
        }
        impact.affected_repositories.sort();
        impact.affected_repositories.dedup();
        impact.affected_resources.sort();
        impact.affected_resources.dedup();
        impact.unmanaged_resources.sort();
        impact.unmanaged_resources.dedup();
        impact.has_unmanaged_dependencies = !impact.unmanaged_resources.is_empty();
        for repository_id in &impact.affected_repositories {
            let Some(repository) = self.repository(repository_id) else {
                continue;
            };
            for config in &repository.configs {
                impact.local_diffs.push(LocalConfigDiffV1 {
                    repository: repository.path.clone(),
                    path: config.path.clone(),
                    kind: config.kind.clone(),
                    content_hash: config.content_hash.clone(),
                    head_content_hash: config.head_content_hash.clone(),
                    worktree_diff_hash: config.worktree_diff_hash.clone(),
                    dirty: config.dirty,
                });
                impact.has_dirty_overlap |= config.dirty;
            }
        }
        impact
            .local_diffs
            .sort_by(|left, right| left.path.cmp(&right.path));
        impact
    }
}

fn discover_root(
    root: &RegisteredRoot,
    repositories: &mut BTreeMap<PathBuf, RepositoryNode>,
    graph: &mut WorkspaceGraph,
) -> Result<()> {
    for entry in WalkDir::new(&root.path)
        .follow_links(false)
        .into_iter()
        .filter_entry(included_entry)
        .filter_map(std::result::Result::ok)
    {
        if entry.file_type().is_dir() && entry.path().join(".git").exists() {
            register_repository(entry.path(), repositories)?;
        }
        if !entry.file_type().is_file() || !is_cloudflare_config(entry.path()) {
            continue;
        }
        let Some(repo_path) = find_repository_root(entry.path(), &root.path) else {
            continue;
        };
        let repo_path = register_repository(&repo_path, repositories)?;
        let config_path = entry
            .path()
            .canonicalize()
            .map_err(|source| io_error(entry.path(), source))?;
        let repository = repositories.get_mut(&repo_path).ok_or_else(|| {
            WorkspaceError::DiscoveryInvariant(format!(
                "registered repository {} is unavailable",
                repo_path.display()
            ))
        })?;
        if repository.cloudflare_configs.contains(&config_path) {
            continue;
        }
        let content = fs::read(&config_path).map_err(|source| io_error(&config_path, source))?;
        let kind = config_kind(&config_path).to_owned();
        repository.cloudflare_configs.push(config_path.clone());
        repository.configs.push(config_snapshot(
            &repo_path,
            &config_path,
            &kind,
            &content,
            &repository.git,
        )?);
        for resource in resources_from_config(&config_path, &kind, &content) {
            graph
                .links
                .entry(resource.key.clone())
                .or_default()
                .insert(repo_path.display().to_string());
            graph.resources.push(resource);
        }
    }
    Ok(())
}

fn register_repository(
    path: &Path,
    repositories: &mut BTreeMap<PathBuf, RepositoryNode>,
) -> Result<PathBuf> {
    let repo_path = path
        .canonicalize()
        .map_err(|source| io_error(path, source))?;
    if !repositories.contains_key(&repo_path) {
        let name = repo_path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .unwrap_or("repository")
            .to_owned();
        repositories.insert(
            repo_path.clone(),
            RepositoryNode {
                name,
                path: repo_path.clone(),
                cloudflare_configs: Vec::new(),
                configs: Vec::new(),
                git: inspect_git(&repo_path)?,
            },
        );
    }
    Ok(repo_path)
}

fn included_entry(entry: &DirEntry) -> bool {
    if !entry.file_type().is_dir() || entry.depth() == 0 {
        return true;
    }
    !matches!(
        entry.file_name().to_str(),
        Some(".git" | ".terraform" | ".wrangler" | "node_modules" | "target" | "vendor")
    )
}

fn is_cloudflare_config(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or_default();
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "wrangler.toml" | "wrangler.json" | "wrangler.jsonc"
    ) || path
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("tf"))
        || lower.strip_suffix(".tf.json").is_some()
        || (path.extension().is_some_and(|extension| {
            extension.eq_ignore_ascii_case("yaml") || extension.eq_ignore_ascii_case("yml")
        }) && lower.starts_with("pulumi"))
}

fn config_kind(path: &Path) -> &'static str {
    let lower = path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    if lower == "wrangler.toml" {
        "wrangler_toml"
    } else if matches!(lower.as_str(), "wrangler.json" | "wrangler.jsonc") {
        "wrangler_json"
    } else if path
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("tf"))
        || lower.strip_suffix(".tf.json").is_some()
    {
        "terraform"
    } else {
        "pulumi"
    }
}

fn find_repository_root(path: &Path, boundary: &Path) -> Option<PathBuf> {
    path.ancestors()
        .take_while(|candidate| candidate.starts_with(boundary))
        .find(|candidate| candidate.join(".git").exists())
        .map(Path::to_path_buf)
}

fn inspect_git(repository: &Path) -> Result<GitStateV1> {
    let head = git_optional(repository, &["rev-parse", "HEAD"])?;
    let branch = git_optional(repository, &["branch", "--show-current"])?
        .filter(|branch| !branch.is_empty());
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(["status", "--porcelain=v1", "-z", "--untracked-files=all"])
        .output()
        .map_err(|source| io_error(repository, source))?;
    if !output.status.success() {
        return Err(git_error(repository, &output.stderr));
    }
    let mut changes = Vec::new();
    let entries: Vec<&[u8]> = output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
        .collect();
    let mut index = 0;
    while index < entries.len() {
        let entry = entries[index];
        if entry.len() < 3 {
            index += 1;
            continue;
        }
        let index_status = char::from(entry[0]).to_string();
        let worktree_status = char::from(entry[1]).to_string();
        let path = String::from_utf8_lossy(&entry[3..]).into_owned();
        changes.push(GitChangeV1 {
            path: PathBuf::from(path),
            index_status: index_status.clone(),
            worktree_status,
        });
        if matches!(index_status.as_str(), "R" | "C") {
            index += 1;
        }
        index += 1;
    }
    changes.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(GitStateV1 {
        head,
        branch,
        dirty: !changes.is_empty(),
        changes,
    })
}

fn git_optional(repository: &Path, arguments: &[&str]) -> Result<Option<String>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .output()
        .map_err(|source| io_error(repository, source))?;
    if output.status.success() {
        return Ok(Some(
            String::from_utf8_lossy(&output.stdout).trim().to_owned(),
        ));
    }
    Ok(None)
}

fn config_snapshot(
    repository: &Path,
    path: &Path,
    kind: &str,
    content: &[u8],
    git: &GitStateV1,
) -> Result<SourceConfigV1> {
    let relative = path.strip_prefix(repository).unwrap_or(path);
    let dirty = git.changes.iter().any(|change| change.path == relative);
    let head_content = git_blob(repository, relative)?;
    let diff = if dirty {
        Some(git_diff(repository, relative)?)
    } else {
        None
    };
    let worktree_diff_hash = diff.map(|diff| {
        if diff.is_empty() {
            hash_bytes(content)
        } else {
            hash_bytes(&diff)
        }
    });
    Ok(SourceConfigV1 {
        path: path.to_path_buf(),
        kind: kind.to_owned(),
        content_hash: hash_bytes(content),
        head_content_hash: head_content.as_deref().map(hash_bytes),
        worktree_diff_hash,
        dirty,
    })
}

fn git_blob(repository: &Path, relative: &Path) -> Result<Option<Vec<u8>>> {
    let object = format!("HEAD:{}", relative.to_string_lossy());
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(["show", &object])
        .output()
        .map_err(|source| io_error(repository, source))?;
    Ok(output.status.success().then_some(output.stdout))
}

fn git_diff(repository: &Path, relative: &Path) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(["diff", "--binary", "--no-ext-diff", "HEAD", "--"])
        .arg(relative)
        .output()
        .map_err(|source| io_error(repository, source))?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(git_error(repository, &output.stderr))
    }
}

fn resources_from_config(path: &Path, kind: &str, content: &[u8]) -> Vec<ResourceNode> {
    let text = String::from_utf8_lossy(content);
    let mut resources = match kind {
        "wrangler_toml" => toml::from_str::<toml::Value>(&text)
            .ok()
            .and_then(|value| serde_json::to_value(value).ok())
            .map_or_else(Vec::new, |value| resources_from_wrangler(path, &value)),
        "wrangler_json" => serde_json::from_str::<Value>(&strip_jsonc(&text))
            .ok()
            .map_or_else(Vec::new, |value| resources_from_wrangler(path, &value)),
        "terraform"
            if path
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .is_some_and(|name| name.to_ascii_lowercase().ends_with(".tf.json")) =>
        {
            serde_json::from_slice::<Value>(content).map_or_else(
                |_| Vec::new(),
                |document| resources_from_terraform_json(path, &document),
            )
        }
        "terraform" => resources_from_terraform(path, &text),
        "pulumi" => serde_saphyr::from_str::<Value>(&text)
            .ok()
            .map_or_else(Vec::new, |value| resources_from_pulumi(path, &value)),
        _ => Vec::new(),
    };
    resources.sort_by(|left, right| (&left.key, &left.kind).cmp(&(&right.key, &right.kind)));
    resources.dedup();
    resources
}

fn resources_from_wrangler(path: &Path, document: &Value) -> Vec<ResourceNode> {
    let mut resources = Vec::new();
    if let Some(root) = document.as_object() {
        collect_wrangler_scope(path, root, &mut resources);
        if let Some(environments) = root.get("env").and_then(Value::as_object) {
            for environment in environments.values().filter_map(Value::as_object) {
                collect_wrangler_scope(path, environment, &mut resources);
            }
        }
    }
    resources
}

fn collect_wrangler_scope(
    path: &Path,
    scope: &serde_json::Map<String, Value>,
    resources: &mut Vec<ResourceNode>,
) {
    if let Some(name) = scope.get("name").and_then(Value::as_str) {
        push_resource(resources, path, "wrangler_worker", format!("worker:{name}"));
    }
    for route in scope
        .get("routes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let pattern = route
            .as_str()
            .or_else(|| route.get("pattern").and_then(Value::as_str));
        if let Some(hostname) = pattern.and_then(hostname_from_pattern) {
            push_resource(
                resources,
                path,
                "wrangler_route",
                format!("hostname:{hostname}"),
            );
        }
        if let Some(zone) = route.get("zone_name").and_then(Value::as_str) {
            push_resource(resources, path, "wrangler_zone", format!("zone:{zone}"));
        }
    }
    for (field, kind, prefix, identity_fields) in [
        (
            "kv_namespaces",
            "wrangler_kv",
            "kv_namespace",
            &["id", "binding"][..],
        ),
        (
            "d1_databases",
            "wrangler_d1",
            "d1_database",
            &["database_id", "database_name", "binding"][..],
        ),
        (
            "r2_buckets",
            "wrangler_r2",
            "r2_bucket",
            &["bucket_name", "binding"][..],
        ),
        (
            "services",
            "wrangler_service",
            "service",
            &["service", "binding"][..],
        ),
    ] {
        for binding in scope
            .get(field)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(identity) = identity_fields
                .iter()
                .find_map(|field| binding.get(*field).and_then(Value::as_str))
            {
                push_resource(resources, path, kind, format!("{prefix}:{identity}"));
            }
        }
    }
    if let Some(queues) = scope.get("queues").and_then(Value::as_object) {
        for queue in ["producers", "consumers"]
            .into_iter()
            .filter_map(|field| queues.get(field).and_then(Value::as_array))
            .flatten()
        {
            if let Some(name) = queue.get("queue").and_then(Value::as_str) {
                push_resource(resources, path, "wrangler_queue", format!("queue:{name}"));
            }
        }
    }
}

fn resources_from_terraform(path: &Path, content: &str) -> Vec<ResourceNode> {
    let mut resources = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim_start();
        if !(trimmed.starts_with("resource ") || trimmed.starts_with("data ")) {
            continue;
        }
        let quoted = quoted_segments(trimmed);
        if quoted.len() < 2 || !quoted[0].starts_with("cloudflare_") {
            continue;
        }
        let category = if trimmed.starts_with("data ") {
            "terraform_data"
        } else {
            "terraform"
        };
        push_resource(
            &mut resources,
            path,
            category,
            format!("terraform:{}.{}", quoted[0], quoted[1]),
        );
    }
    resources
}

fn resources_from_terraform_json(path: &Path, document: &Value) -> Vec<ResourceNode> {
    let mut resources = Vec::new();
    for (block, kind) in [("resource", "terraform"), ("data", "terraform_data")] {
        let Some(resource_types) = document.get(block).and_then(Value::as_object) else {
            continue;
        };
        for (resource_type, instances) in resource_types {
            if !resource_type.starts_with("cloudflare_") {
                continue;
            }
            for name in instances
                .as_object()
                .into_iter()
                .flat_map(serde_json::Map::keys)
            {
                push_resource(
                    &mut resources,
                    path,
                    kind,
                    format!("terraform:{resource_type}.{name}"),
                );
            }
        }
    }
    resources
}

fn resources_from_pulumi(path: &Path, document: &Value) -> Vec<ResourceNode> {
    let mut resources = Vec::new();
    let Some(entries) = document.get("resources").and_then(Value::as_object) else {
        return resources;
    };
    for (name, resource) in entries {
        let Some(resource_type) = resource.get("type").and_then(Value::as_str) else {
            continue;
        };
        if !resource_type
            .to_ascii_lowercase()
            .starts_with("cloudflare:")
        {
            continue;
        }
        push_resource(
            &mut resources,
            path,
            "pulumi",
            format!("pulumi:{resource_type}.{name}"),
        );
    }
    resources
}

fn push_resource(resources: &mut Vec<ResourceNode>, path: &Path, kind: &str, key: String) {
    resources.push(ResourceNode {
        key,
        kind: kind.to_owned(),
        source: path.to_path_buf(),
    });
}

fn quoted_segments(line: &str) -> Vec<&str> {
    line.split('"')
        .enumerate()
        .filter_map(|(index, segment)| (index % 2 == 1).then_some(segment))
        .collect()
}

fn strip_jsonc(content: &str) -> String {
    let mut without_comments = String::with_capacity(content.len());
    let mut characters = content.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    while let Some(character) = characters.next() {
        if in_string {
            without_comments.push(character);
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
            continue;
        }
        if character == '"' {
            in_string = true;
            without_comments.push(character);
        } else if character == '/' && characters.peek() == Some(&'/') {
            characters.next();
            for next in characters.by_ref() {
                if next == '\n' {
                    without_comments.push('\n');
                    break;
                }
            }
        } else if character == '/' && characters.peek() == Some(&'*') {
            characters.next();
            let mut previous = '\0';
            for next in characters.by_ref() {
                if previous == '*' && next == '/' {
                    break;
                }
                previous = next;
            }
        } else {
            without_comments.push(character);
        }
    }
    remove_trailing_json_commas(&without_comments)
}

fn remove_trailing_json_commas(content: &str) -> String {
    let characters: Vec<char> = content.chars().collect();
    let mut output = String::with_capacity(content.len());
    let mut in_string = false;
    let mut escaped = false;
    for (index, character) in characters.iter().enumerate() {
        if in_string {
            output.push(*character);
            if escaped {
                escaped = false;
            } else if *character == '\\' {
                escaped = true;
            } else if *character == '"' {
                in_string = false;
            }
            continue;
        }
        if *character == '"' {
            in_string = true;
            output.push(*character);
            continue;
        }
        if *character == ',' {
            let next = characters[index + 1..]
                .iter()
                .find(|next| !next.is_whitespace());
            if matches!(next, Some('}' | ']')) {
                continue;
            }
        }
        output.push(*character);
    }
    output
}

fn hostname_from_pattern(pattern: &str) -> Option<String> {
    let without_scheme = pattern
        .split_once("://")
        .map_or(pattern, |(_, remainder)| remainder);
    let hostname = without_scheme
        .split('/')
        .next()
        .unwrap_or_default()
        .trim_start_matches("*.")
        .trim_end_matches('*')
        .trim_end_matches('.');
    (!hostname.is_empty()).then(|| hostname.to_owned())
}

fn hash_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn git_error(repository: &Path, stderr: &[u8]) -> WorkspaceError {
    WorkspaceError::Git {
        repository: repository.display().to_string(),
        message: String::from_utf8_lossy(stderr).trim().to_owned(),
    }
}

fn io_error(path: &Path, source: std::io::Error) -> WorkspaceError {
    WorkspaceError::Io {
        path: path.display().to_string(),
        source,
    }
}
