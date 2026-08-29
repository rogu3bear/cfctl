use std::{
    collections::BTreeSet,
    ffi::OsStr,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};

use cfctl_cloudflare::CallInput;
use cfctl_workspace::{WorkspaceGraph, load_wrangler_config};
use serde_json::Value;
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use super::CliError;

pub(super) fn artifact_paths(input: &CallInput) -> Result<Vec<PathBuf>, CliError> {
    let config = canonical_config(input)?;
    let directory = config.parent().ok_or_else(|| {
        CliError::Input("Wrangler configuration has no containing directory".to_owned())
    })?;
    let document = load_wrangler_config(&config)?;
    artifact_paths_from_document(directory, &document, input)
}

pub(super) fn artifact_paths_from_document(
    directory: &Path,
    document: &Value,
    input: &CallInput,
) -> Result<Vec<PathBuf>, CliError> {
    let main = input
        .query
        .get("argument")
        .and_then(Value::as_str)
        .or_else(|| document.get("main").and_then(Value::as_str));
    let assets = document
        .pointer("/assets/directory")
        .and_then(Value::as_str);
    let mut roots = BTreeSet::new();
    if let Some(main) = main.filter(|value| !value.trim().is_empty()) {
        let path = canonical_artifact_path(directory, main)?;
        roots.insert(if path.is_dir() {
            path
        } else {
            path.parent()
                .ok_or_else(|| {
                    CliError::Input("Worker entry point has no containing directory".to_owned())
                })?
                .to_path_buf()
        });
    }
    if let Some(assets) = assets.filter(|value| !value.trim().is_empty()) {
        roots.insert(canonical_artifact_path(directory, assets)?);
    }
    if roots.is_empty() {
        return Err(CliError::Input(
            "Worker deployment configuration must declare `main` or `assets.directory`".to_owned(),
        ));
    }
    Ok(roots.into_iter().collect())
}

pub(super) fn canonical_config(input: &CallInput) -> Result<PathBuf, CliError> {
    let raw = input
        .query
        .get("config")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input("Worker deployment requires a config selector".to_owned())
        })?;
    let path = Path::new(raw);
    if !path.is_absolute() {
        return Err(CliError::Input(
            "Worker deployment requires an absolute Wrangler config path".to_owned(),
        ));
    }
    load_wrangler_config(path)?;
    let canonical = fs::canonicalize(path).map_err(|source| CliError::Io {
        path: path.display().to_string(),
        source,
    })?;
    if !canonical.is_file() {
        return Err(CliError::Input(format!(
            "Wrangler configuration `{}` is not a file",
            canonical.display()
        )));
    }
    Ok(canonical)
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

fn canonical_artifact_path(directory: &Path, raw: &str) -> Result<PathBuf, CliError> {
    let path = Path::new(raw);
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        directory.join(path)
    };
    fs::canonicalize(&path).map_err(|source| CliError::Io {
        path: path.display().to_string(),
        source,
    })
}

fn is_git_metadata_name(name: &OsStr) -> bool {
    name.to_str()
        .is_some_and(|value| value.eq_ignore_ascii_case(".git"))
}

pub(super) fn validate_artifact_tree_ownership(
    graph: &WorkspaceGraph,
    repository: &Path,
    roots: &[PathBuf],
) -> Result<(), CliError> {
    for root in roots {
        let mut entries = WalkDir::new(root).follow_links(false).into_iter();
        while let Some(entry) = entries.next() {
            let entry = entry.map_err(|error| {
                CliError::Input(format!(
                    "failed to inspect Worker deployment artifact `{}`: {error}",
                    root.display()
                ))
            })?;
            if is_git_metadata_name(entry.file_name()) {
                if entry.path().parent() != Some(repository) {
                    return Err(CliError::Input(format!(
                        "Worker deployment artifact contains nested Git repository metadata `{}`",
                        entry.path().display()
                    )));
                }
                if entry.file_type().is_dir() {
                    entries.skip_current_dir();
                }
                continue;
            }
            if repository_owning_path(graph, entry.path())
                .is_none_or(|owner| owner.path != repository)
            {
                return Err(CliError::Input(format!(
                    "Worker deployment artifact `{}` is not owned by config repository `{}`",
                    entry.path().display(),
                    repository.display()
                )));
            }
        }
    }
    Ok(())
}

pub(super) fn artifact_set_sha256(
    repository: &Path,
    roots: &[PathBuf],
) -> Result<String, CliError> {
    let mut entries = Vec::new();
    for root in roots {
        let mut walker = WalkDir::new(root).follow_links(false).into_iter();
        while let Some(entry) = walker.next() {
            let entry = entry.map_err(|error| {
                CliError::Input(format!(
                    "failed to inspect Worker deployment artifact `{}`: {error}",
                    root.display()
                ))
            })?;
            if is_git_metadata_name(entry.file_name()) {
                if entry.path().parent() != Some(repository) {
                    return Err(CliError::Input(format!(
                        "Worker deployment artifact contains nested Git repository metadata `{}`",
                        entry.path().display()
                    )));
                }
                if entry.file_type().is_dir() {
                    walker.skip_current_dir();
                }
                continue;
            }
            if entry.path() == root || entry.file_type().is_dir() {
                continue;
            }
            if !entry.file_type().is_file() {
                return Err(CliError::Input(format!(
                    "Worker deployment artifact contains unsupported non-file entry `{}`",
                    entry.path().display()
                )));
            }
            let relative = entry.path().strip_prefix(repository).map_err(|_| {
                CliError::Input(format!(
                    "Worker deployment artifact `{}` escaped repository `{}`",
                    entry.path().display(),
                    repository.display()
                ))
            })?;
            let bytes = fs::read(entry.path()).map_err(|source| CliError::Io {
                path: entry.path().display().to_string(),
                source,
            })?;
            entries.push((
                relative.to_string_lossy().replace('\\', "/"),
                hex::encode(Sha256::digest(bytes)),
            ));
        }
    }
    entries.sort();
    entries.dedup();
    let mut manifest = String::new();
    for (path, digest) in entries {
        writeln!(&mut manifest, "{digest}  {path}").map_err(|error| {
            CliError::Input(format!(
                "failed to construct deployment artifact manifest: {error}"
            ))
        })?;
    }
    Ok(hex::encode(Sha256::digest(manifest.as_bytes())))
}

pub(super) fn is_full_source_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
