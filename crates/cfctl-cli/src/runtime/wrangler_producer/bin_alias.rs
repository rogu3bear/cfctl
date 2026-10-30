//! Capture only a declared dependency's package-bin alias, without following
//! arbitrary package symlinks or changing alias-free producer receipts.
use super::{CliError, declared_dependencies, package_metadata, resolve_dependency_root};
use crate::runtime::worker_frozen_files::open_absolute;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    io::Read as _,
    path::{Component, Path, PathBuf},
};

fn invalid() -> CliError {
    CliError::Input(
        "Wrangler producer bin alias is not one declared, confined dependency executable"
            .to_owned(),
    )
}

fn relative_target(base: &Path, target: &Path, boundary: &Path) -> Result<PathBuf, CliError> {
    if target.as_os_str().is_empty()
        || target.to_str().is_none_or(|text| {
            text.chars().any(char::is_control) || text.ends_with('/') || text.ends_with("/.")
        })
        || target.is_absolute()
    {
        return Err(invalid());
    }
    let mut resolved = base.to_path_buf();
    let parts = target.components().collect::<Vec<_>>();
    for (index, part) in parts.iter().enumerate() {
        match part {
            Component::Normal(name) => resolved.push(name),
            Component::CurDir => {}
            Component::ParentDir => {
                if !resolved.pop() || !resolved.starts_with(boundary) {
                    return Err(invalid());
                }
            }
            _ => return Err(invalid()),
        }
        // Do not normalize away a symlink or missing directory before `..`:
        // the OS would traverse that component when executing the bin alias.
        if index + 1 != parts.len() {
            open_absolute(&resolved, true).map_err(|_| invalid())?;
        }
    }
    if !resolved.starts_with(boundary) {
        return Err(invalid());
    }
    Ok(resolved)
}

fn declared_bin(metadata: &Value, name: &str) -> Result<Option<PathBuf>, CliError> {
    match metadata.get("bin") {
        None => Ok(None),
        Some(Value::String(path)) => Ok((metadata["name"]
            .as_str()
            .and_then(|name| name.rsplit('/').next())
            == Some(name))
        .then(|| PathBuf::from(path))),
        Some(Value::Object(bins)) => {
            if bins.values().any(|path| !path.is_string()) {
                return Err(invalid());
            }
            Ok(bins.get(name).and_then(Value::as_str).map(PathBuf::from))
        }
        Some(_) => Err(invalid()),
    }
}

/// The target is read through no-follow directory handles. Link text is checked
/// again after capture, and the complete binding is compared at execution.
pub(super) fn snapshot(
    path: &Path,
    roots: &[(String, PathBuf)],
    node_modules: &Path,
    remaining_bytes: u64,
) -> Result<(Value, u64), CliError> {
    let bin = path.parent().ok_or_else(invalid)?;
    let modules = bin.parent().ok_or_else(invalid)?;
    let owner = modules.parent().ok_or_else(invalid)?;
    if bin.file_name().is_none_or(|name| name != ".bin")
        || modules
            .file_name()
            .is_none_or(|name| name != "node_modules")
    {
        return Err(invalid());
    }
    // Recursive package walks overlap. Ownership comes from the alias's actual
    // location, never from whichever outer package is currently being walked.
    let owners = roots
        .iter()
        .filter(|(_, root)| root == owner)
        .collect::<Vec<_>>();
    let [owner_binding] = owners.as_slice() else {
        return Err(invalid());
    };
    let owner_name = &owner_binding.0;
    if roots.iter().filter(|(name, _)| name == owner_name).count() != 1 {
        return Err(invalid());
    }
    open_absolute(bin, true).map_err(|_| invalid())?;
    let alias_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(invalid)?;
    let link = fs::read_link(path).map_err(|_| invalid())?;
    let target = relative_target(bin, &link, node_modules)?;
    let metadata = package_metadata(owner)?;
    let dependencies = declared_dependencies(&metadata, "dependencies")
        .into_iter()
        .chain(declared_dependencies(&metadata, "optionalDependencies"))
        .collect::<BTreeSet<_>>();
    let mut matches = Vec::new();
    for dependency in dependencies {
        let Some(root) = resolve_dependency_root(owner, node_modules, &dependency) else {
            continue;
        };
        let canonical = fs::canonicalize(&root).map_err(|_| invalid())?;
        let admitted = roots
            .iter()
            .filter(|(_, root)| root == &canonical)
            .collect::<Vec<_>>();
        let [binding] = admitted.as_slice() else {
            return Err(invalid());
        };
        let package = package_metadata(&canonical)?;
        let Some(declared) = declared_bin(&package, alias_name)? else {
            continue;
        };
        let expected = relative_target(&canonical, &declared, &canonical)?;
        if expected == target {
            if roots.iter().filter(|(name, _)| name == &binding.0).count() != 1 {
                return Err(invalid());
            }
            matches.push(*binding);
        }
    }
    let [binding] = matches.as_slice() else {
        return Err(invalid());
    };
    let mut file = open_absolute(&target, false).map_err(|_| invalid())?;
    let metadata = file.metadata().map_err(|_| invalid())?;
    if !metadata.is_file() || metadata.len() > remaining_bytes {
        return Err(invalid());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(remaining_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    if bytes.len() as u64 != metadata.len()
        || fs::read_link(path).map_err(|_| invalid())?.as_os_str() != link.as_os_str()
    {
        return Err(invalid());
    }
    let target_path = target.strip_prefix(&binding.1).map_err(|_| invalid())?;
    Ok((
        json!({
            "owner": owner_name,
            "owner_root": owner,
            "bin_name": alias_name,
            "link_text": link.to_str().ok_or_else(invalid)?,
            "target_component": binding.0,
            "target_root": binding.1,
            "target_path": target_path.to_str().ok_or_else(invalid)?,
            "size": metadata.len(),
            "sha256": hex::encode(Sha256::digest(&bytes)),
        }),
        metadata.len(),
    ))
}
