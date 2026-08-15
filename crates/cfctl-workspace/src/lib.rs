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

mod d1_operation;
mod d1_policy_projection;

pub use d1_operation::load_workspace_d1_migration_capability;
pub use d1_policy_projection::load_workspace_d1_policy_projection_capability;

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

pub const WORKSPACE_MANIFEST_SCHEMA_VERSION: u8 = 1;

/// One registered discovery boundary and its optional account selection.
///
/// The path and account pin intentionally live in the same record so callers
/// cannot update discovery scope without updating its selection metadata in
/// the same durable transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceRegistrationV1 {
    pub path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
}

/// Canonical registered-root configuration consumed by discovery and account
/// resolution. Storage persists this document atomically.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceManifestV1 {
    pub schema_version: u8,
    pub registrations: Vec<WorkspaceRegistrationV1>,
}

impl Default for WorkspaceManifestV1 {
    fn default() -> Self {
        Self {
            schema_version: WORKSPACE_MANIFEST_SCHEMA_VERSION,
            registrations: Vec::new(),
        }
    }
}

impl WorkspaceManifestV1 {
    #[must_use]
    pub fn roots(&self) -> Vec<PathBuf> {
        self.registrations
            .iter()
            .map(|registration| registration.path.clone())
            .collect()
    }

    #[must_use]
    pub fn account_pins(&self) -> BTreeMap<PathBuf, String> {
        self.registrations
            .iter()
            .filter_map(|registration| {
                registration
                    .account_id
                    .as_ref()
                    .map(|account| (registration.path.clone(), account.clone()))
            })
            .collect()
    }

    /// Registers one canonical root. Omitting `account_id` preserves an
    /// existing pin, matching the public `workspace add` contract.
    pub fn register(
        &mut self,
        path: PathBuf,
        account_id: Option<String>,
    ) -> WorkspaceRegistrationV1 {
        if let Some(registration) = self
            .registrations
            .iter_mut()
            .find(|registration| registration.path == path)
        {
            if account_id.is_some() {
                registration.account_id = account_id;
            }
            return registration.clone();
        }
        let registration = WorkspaceRegistrationV1 { path, account_id };
        self.registrations.push(registration.clone());
        self.registrations
            .sort_by(|left, right| left.path.cmp(&right.path));
        registration
    }

    pub fn unregister(&mut self, path: &Path) -> (bool, bool) {
        let account_pin_removed = self
            .registrations
            .iter()
            .find(|registration| registration.path == path)
            .is_some_and(|registration| registration.account_id.is_some());
        let original_len = self.registrations.len();
        self.registrations
            .retain(|registration| registration.path != path);
        (
            self.registrations.len() != original_len,
            account_pin_removed,
        )
    }
}

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
        let Some(repo_path) = find_repository_root(entry.path(), &root.path)? else {
            continue;
        };
        let repo_path = register_repository(&repo_path, repositories)?;
        let config_path = entry
            .path()
            .canonicalize()
            .map_err(|source| io_error(entry.path(), source))?;
        require_role_config_at_repository_root(&config_path, &repo_path)?;
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
    let repo_path = git_repository_root(path)?.ok_or_else(|| {
        WorkspaceError::DiscoveryInvariant(format!(
            "repository marker at `{}` is not backed by a readable Git worktree",
            path.display()
        ))
    })?;
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
        Some(
            ".cache"
                | ".git"
                | ".terraform"
                | ".wrangler"
                | "__fixtures__"
                | "cargo-home"
                | "coverage"
                | "dist"
                | "fixtures"
                | "node_modules"
                | "target"
                | "test-data"
                | "test_data"
                | "testdata"
                | "var"
                | "vendor"
        )
    )
}

fn is_cloudflare_config(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or_default();
    let lower = name.to_ascii_lowercase();
    matches!(lower.as_str(), "wrangler.toml" | "wrangler.production.toml")
        || is_role_specific_wrangler_toml_name(name)
        || matches!(lower.as_str(), "wrangler.json" | "wrangler.jsonc")
        || path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("tf"))
        || lower.strip_suffix(".tf.json").is_some()
        || (path.extension().is_some_and(|extension| {
            extension.eq_ignore_ascii_case("yaml") || extension.eq_ignore_ascii_case("yml")
        }) && lower.starts_with("pulumi"))
}

fn config_kind(path: &Path) -> &'static str {
    let name = path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or_default();
    let lower = name.to_ascii_lowercase();
    if matches!(lower.as_str(), "wrangler.toml" | "wrangler.production.toml")
        || is_role_specific_wrangler_toml_name(name)
    {
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

fn is_wrangler_toml_name(name: &str) -> bool {
    if matches!(name, "wrangler.toml" | "wrangler.production.toml") {
        return true;
    }
    let Some(stem) = name
        .strip_prefix("wrangler.")
        .and_then(|value| value.strip_suffix(".toml"))
    else {
        return false;
    };
    let role = stem.strip_suffix(".production").unwrap_or(stem);
    !role.is_empty()
        && role.len() <= 63
        && role.bytes().enumerate().all(|(index, byte)| match byte {
            b'a'..=b'z' | b'0'..=b'9' => true,
            b'-' => index > 0 && index + 1 < role.len(),
            _ => false,
        })
}

fn is_role_specific_wrangler_toml_name(name: &str) -> bool {
    name == name.to_ascii_lowercase()
        && is_wrangler_toml_name(name)
        && !matches!(name, "wrangler.toml" | "wrangler.production.toml")
}

fn require_role_config_at_repository_root(path: &Path, repository: &Path) -> Result<()> {
    let name = path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or_default();
    if !is_role_specific_wrangler_toml_name(name) {
        return Ok(());
    }
    let parent = path.parent().ok_or_else(|| {
        WorkspaceError::DiscoveryInvariant(format!(
            "role-specific Wrangler configuration `{}` has no repository parent",
            path.display()
        ))
    })?;
    if parent == repository {
        return Ok(());
    }
    Err(WorkspaceError::DiscoveryInvariant(format!(
        "role-specific Wrangler configuration `{}` must be located at repository root `{}`",
        path.display(),
        repository.display()
    )))
}

fn validate_deployment_config_path(path: &Path) -> Result<()> {
    // `Path::components()` normalizes interior `.` segments away, which would
    // erase part of the caller's raw selector before this authority check.
    // Deployment selectors originate as UTF-8 CLI/JSON strings, so reject
    // non-UTF-8 selectors and inspect both platform separator spellings
    // lexically before any filesystem lookup or canonicalization.
    let contains_lexical_dot_component = path.to_str().is_none_or(|raw| {
        raw.split(['/', '\\'])
            .any(|component| matches!(component, "." | ".."))
    });
    if contains_lexical_dot_component {
        return Err(WorkspaceError::DiscoveryInvariant(format!(
            "deployment configuration path `{}` must not contain `.` or `..` components",
            path.display()
        )));
    }
    let selected_metadata = fs::symlink_metadata(path).map_err(|source| WorkspaceError::Io {
        path: path.display().to_string(),
        source,
    })?;
    if !selected_metadata.file_type().is_file() {
        return Err(WorkspaceError::DiscoveryInvariant(format!(
            "deployment configuration `{}` must be an ordinary regular file",
            path.display()
        )));
    }
    let actual_repository = path
        .parent()
        .map(git_repository_root)
        .transpose()?
        .flatten();
    let lexical_repository = actual_repository.as_ref().and_then(|actual| {
        path.ancestors().skip(1).find_map(|candidate| {
            candidate
                .canonicalize()
                .ok()
                .filter(|canonical| canonical == actual)
                .map(|_| candidate.to_path_buf())
        })
    });
    for component in path
        .ancestors()
        .filter(|component| !component.as_os_str().is_empty())
    {
        let metadata = fs::symlink_metadata(component).map_err(|source| WorkspaceError::Io {
            path: component.display().to_string(),
            source,
        })?;
        if metadata.file_type().is_symlink() {
            return Err(WorkspaceError::DiscoveryInvariant(format!(
                "deployment configuration path `{}` contains symlink component `{}`",
                path.display(),
                component.display()
            )));
        }
        if lexical_repository
            .as_ref()
            .is_none_or(|repository| component == repository)
        {
            break;
        }
    }
    let canonical_path = path.canonicalize().map_err(|source| WorkspaceError::Io {
        path: path.display().to_string(),
        source,
    })?;
    if let Some(repository) = actual_repository {
        if !canonical_path.starts_with(&repository) {
            return Err(WorkspaceError::DiscoveryInvariant(format!(
                "deployment configuration `{}` escapes Git repository `{}`",
                canonical_path.display(),
                repository.display()
            )));
        }
        require_role_config_at_repository_root(&canonical_path, &repository)?;
    } else if path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(is_role_specific_wrangler_toml_name)
    {
        return Err(WorkspaceError::DiscoveryInvariant(format!(
            "role-specific Wrangler configuration `{}` is not owned by a readable Git worktree",
            path.display()
        )));
    }
    Ok(())
}

/// Load one Wrangler configuration through the same TOML/JSON/JSONC parser
/// used by workspace discovery. Deployment planning consumes this public
/// projection so config interpretation cannot drift from resource discovery.
pub fn load_wrangler_config(path: &Path) -> Result<Value> {
    Ok(load_wrangler_config_snapshot(path)?.document)
}

/// One captured Wrangler configuration used for both interpretation and
/// content-addressed deployment authority. Callers must not parse one read and
/// hash a later read of the same path.
#[derive(Debug, Clone, PartialEq)]
pub struct WranglerConfigSnapshot {
    pub document: Value,
    pub content_hash: String,
}

pub fn load_wrangler_config_snapshot(path: &Path) -> Result<WranglerConfigSnapshot> {
    validate_deployment_config_path(path)?;
    let content = fs::read(path).map_err(|source| WorkspaceError::Io {
        path: path.display().to_string(),
        source,
    })?;
    let text = std::str::from_utf8(&content).map_err(|_| {
        WorkspaceError::DiscoveryInvariant(format!(
            "Wrangler configuration `{}` is not valid UTF-8",
            path.display()
        ))
    })?;
    let document = match config_kind(path) {
        "wrangler_toml" => toml::from_str::<toml::Value>(text)
            .ok()
            .and_then(|value| serde_json::to_value(value).ok())
            .ok_or_else(|| {
                WorkspaceError::DiscoveryInvariant(format!(
                    "Wrangler TOML configuration `{}` is malformed",
                    path.display()
                ))
            }),
        "wrangler_json" => serde_json::from_str::<Value>(&strip_jsonc(text)).map_err(|error| {
            WorkspaceError::DiscoveryInvariant(format!(
                "Wrangler JSON configuration `{}` is malformed: {error}",
                path.display()
            ))
        }),
        _ => Err(WorkspaceError::DiscoveryInvariant(format!(
            "deployment configuration `{}` is not a canonical Wrangler TOML/JSON configuration name",
            path.display()
        ))),
    }?;
    Ok(WranglerConfigSnapshot {
        document,
        content_hash: hash_bytes(&content),
    })
}

fn find_repository_root(path: &Path, boundary: &Path) -> Result<Option<PathBuf>> {
    let Some(directory) = path.parent() else {
        return Ok(None);
    };
    let Some(repository) = git_repository_root(directory)? else {
        return Ok(None);
    };
    let boundary = boundary
        .canonicalize()
        .map_err(|source| io_error(boundary, source))?;
    Ok(repository.starts_with(boundary).then_some(repository))
}

fn git_repository_root(path: &Path) -> Result<Option<PathBuf>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(path)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|source| io_error(path, source))?;
    if !output.status.success() {
        return Ok(None);
    }
    let raw = String::from_utf8(output.stdout).map_err(|_| {
        WorkspaceError::DiscoveryInvariant(format!(
            "Git repository root for `{}` is not UTF-8",
            path.display()
        ))
    })?;
    let root = raw.trim();
    if root.is_empty() {
        return Err(WorkspaceError::DiscoveryInvariant(format!(
            "Git returned an empty repository root for `{}`",
            path.display()
        )));
    }
    Path::new(root)
        .canonicalize()
        .map(Some)
        .map_err(|source| io_error(Path::new(root), source))
}

fn inspect_git(repository: &Path) -> Result<GitStateV1> {
    let canonical_repository = repository
        .canonicalize()
        .map_err(|source| io_error(repository, source))?;
    let actual_repository = git_repository_root(repository)?.ok_or_else(|| {
        WorkspaceError::DiscoveryInvariant(format!(
            "repository `{}` has no readable Git top level",
            repository.display()
        ))
    })?;
    if actual_repository != canonical_repository {
        return Err(WorkspaceError::DiscoveryInvariant(format!(
            "repository `{}` resolves through Git to different top level `{}`",
            canonical_repository.display(),
            actual_repository.display()
        )));
    }
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
        if scope
            .get("pages_build_output_dir")
            .and_then(Value::as_str)
            .is_some_and(|directory| !directory.trim().is_empty())
        {
            push_resource(
                resources,
                path,
                "wrangler_pages",
                format!("pages_project:{name}"),
            );
        } else {
            push_resource(resources, path, "wrangler_worker", format!("worker:{name}"));
        }
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
            &["id", "preview_id"][..],
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
            &["bucket_name"][..],
        ),
        ("services", "wrangler_service", "service", &["service"][..]),
    ] {
        for binding in scope
            .get(field)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            for identity in identity_fields
                .iter()
                .filter_map(|field| binding.get(*field).and_then(Value::as_str))
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
    let mut lines = content.lines();
    while let Some(line) = lines.next() {
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
        let resource_type = quoted[0];
        let mut depth = hcl_brace_delta(trimmed);
        while depth > 0 {
            let Some(body_line) = lines.next() else {
                break;
            };
            if depth == 1
                && let Some((property, value)) = hcl_literal_string_assignment(body_line)
            {
                push_literal_iac_identity(
                    &mut resources,
                    path,
                    category,
                    resource_type,
                    property,
                    &value,
                );
            }
            depth += hcl_brace_delta(body_line);
        }
    }
    resources
}

fn hcl_brace_delta(line: &str) -> i32 {
    let mut delta = 0;
    let mut characters = line.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    while let Some(character) = characters.next() {
        if in_string {
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
        } else if character == '#' || (character == '/' && characters.peek() == Some(&'/')) {
            break;
        } else if character == '{' {
            delta += 1;
        } else if character == '}' {
            delta -= 1;
        }
    }
    delta
}

fn hcl_literal_string_assignment(line: &str) -> Option<(&str, String)> {
    let (property, expression) = line.trim().split_once('=')?;
    let property = property.trim();
    if property.is_empty()
        || !property
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
    {
        return None;
    }
    let expression = expression.trim();
    let mut escaped = false;
    let mut closing_quote = None;
    for (index, character) in expression.char_indices().skip(1) {
        if escaped {
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '"' {
            closing_quote = Some(index);
            break;
        }
    }
    let closing_quote = closing_quote?;
    if !expression.starts_with('"') {
        return None;
    }
    let remainder = expression.get(closing_quote + 1..)?.trim();
    if !remainder.is_empty() && !remainder.starts_with('#') && !remainder.starts_with("//") {
        return None;
    }
    let value = serde_json::from_str::<String>(expression.get(..=closing_quote)?).ok()?;
    (!value.contains("${") && !value.contains("%{")).then_some((property, value))
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
                if let Some(properties) = instances.get(name).and_then(Value::as_object) {
                    for (property, value) in properties {
                        if let Some(value) = value.as_str() {
                            push_literal_iac_identity(
                                &mut resources,
                                path,
                                kind,
                                resource_type,
                                property,
                                value,
                            );
                        }
                    }
                }
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
        if let Some(properties) = resource.get("properties").and_then(Value::as_object) {
            for (property, value) in properties {
                if let Some(value) = value.as_str() {
                    push_literal_iac_identity(
                        &mut resources,
                        path,
                        "pulumi",
                        resource_type,
                        property,
                        value,
                    );
                }
            }
        }
    }
    resources
}

fn push_literal_iac_identity(
    resources: &mut Vec<ResourceNode>,
    path: &Path,
    kind: &str,
    resource_type: &str,
    property: &str,
    value: &str,
) {
    if value.contains("${") || value.contains("%{") {
        return;
    }
    let resource_type = alphanumeric_key(resource_type);
    let property = alphanumeric_key(property);
    let key = if resource_type.ends_with("workersscript")
        && matches!(property.as_str(), "name" | "scriptname")
    {
        Some(format!("worker:{value}"))
    } else if resource_type.ends_with("r2bucket")
        && matches!(property.as_str(), "bucketname" | "name")
    {
        Some(format!("r2_bucket:{value}"))
    } else if resource_type.ends_with("d1database")
        && matches!(property.as_str(), "databasename" | "name")
    {
        Some(format!("d1_database:{value}"))
    } else if resource_type.ends_with("queue") && matches!(property.as_str(), "name" | "queuename")
    {
        Some(format!("queue:{value}"))
    } else if resource_type.ends_with("workersroute") && property == "pattern" {
        hostname_from_pattern(value).map(|hostname| format!("hostname:{hostname}"))
    } else if matches!(
        resource_type.as_str(),
        "cloudflarerecord" | "cloudflarednsrecord"
    ) && property == "name"
        && value.contains('.')
    {
        hostname_from_pattern(value).map(|hostname| format!("hostname:{hostname}"))
    } else if resource_type == "cloudflarezone" && matches!(property.as_str(), "name" | "zone") {
        Some(format!("zone:{value}"))
    } else {
        None
    };
    if let Some(key) = key {
        push_resource(resources, path, kind, key);
    }
}

fn alphanumeric_key(value: &str) -> String {
    value
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect()
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
