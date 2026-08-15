use std::{
    collections::BTreeSet,
    env, fs,
    path::{Component, Path, PathBuf},
    process::Command,
};

use cfctl_cloudflare::{CallInput, CloudflareResponseV1};
use cfctl_core::{CapabilityV1, PlanV1, hash_value};
use cfctl_workspace::{RepositoryNode, WorkspaceGraph};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use super::CliError;

pub(super) const DIRECT_UPLOAD_CAPABILITY_ID: &str = "wrangler.pages-deploy";
pub(super) const GIT_TRIGGER_CAPABILITY_ID: &str = "pages-deployment-create-deployment";
pub(super) const PROJECT_STATE_PRECONDITION: &str = "pages_deployment_project_state";
pub(super) const PROJECT_READ_CAPABILITY_ID: &str = "pages-project-get-project";
pub(super) const PROJECT_DETAIL_PATH: &str = "/accounts/{account_id}/pages/projects/{project_name}";
pub(super) const DEPLOYMENT_LIST_CAPABILITY_ID: &str = "pages-deployment-get-deployments";
pub(super) const DEPLOYMENT_LIST_PATH: &str =
    "/accounts/{account_id}/pages/projects/{project_name}/deployments";
pub(super) const DEPLOYMENT_READ_CAPABILITY_ID: &str = "pages-deployment-get-deployment-info";
pub(super) const DEPLOYMENT_DETAIL_PATH: &str =
    "/accounts/{account_id}/pages/projects/{project_name}/deployments/{deployment_id}";

const MAX_ASSET_COUNT: usize = 20_000;
const MAX_FILE_BYTES: u64 = 25 * 1024 * 1024;
const MAX_PRODUCER_FILE_COUNT: usize = 10_000;
const MAX_PRODUCER_BYTES: u64 = 512 * 1024 * 1024;
const CONTROL_FILES: [&str; 4] = ["_headers", "_redirects", "_routes.json", "_worker.js"];

pub(super) fn binds_artifact(capability: &CapabilityV1) -> bool {
    capability.id == DIRECT_UPLOAD_CAPABILITY_ID
        && capability.method == "CLI"
        && capability.path == "wrangler pages deploy"
}

pub(super) fn binds_project_state(capability: &CapabilityV1) -> bool {
    binds_artifact(capability)
        || (capability.id == GIT_TRIGGER_CAPABILITY_ID
            && capability.method == "POST"
            && capability.path == DEPLOYMENT_LIST_PATH)
}

pub(super) fn project_name<'a>(
    capability: &CapabilityV1,
    input: &'a CallInput,
) -> Result<&'a str, CliError> {
    let value = if binds_artifact(capability) {
        input.query.get("project_name")
    } else {
        input.selectors.get("project_name")
    };
    value
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input("Pages deployment requires one non-empty project_name".to_owned())
        })
}

pub(super) fn artifact_paths(
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<Vec<PathBuf>, CliError> {
    if !binds_artifact(capability) {
        return Ok(Vec::new());
    }
    Ok(vec![artifact_root(input)?])
}

fn artifact_root(input: &CallInput) -> Result<PathBuf, CliError> {
    let raw = input
        .query
        .get("argument")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input("Pages direct upload requires an artifact directory".to_owned())
        })?;
    let raw = Path::new(raw);
    reject_symlink_components(raw)?;
    let canonical = fs::canonicalize(raw).map_err(|source| CliError::Io {
        path: raw.display().to_string(),
        source,
    })?;
    let metadata = fs::symlink_metadata(&canonical).map_err(|source| CliError::Io {
        path: canonical.display().to_string(),
        source,
    })?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(CliError::Input(format!(
            "Pages deployment artifact `{}` is not one regular directory",
            canonical.display()
        )));
    }
    // Constructing the manifest is admission, not an informational hash. It
    // rejects empty, ambiguous, ignored, or out-of-bound trees before a plan
    // can exist.
    let _ = manifest(&canonical)?;
    Ok(canonical)
}

fn reject_symlink_components(path: &Path) -> Result<(), CliError> {
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(CliError::Input(
            "Pages deployment artifact paths may not contain `..` components".to_owned(),
        ));
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|source| CliError::Io {
                path: ".".to_owned(),
                source,
            })?
            .join(path)
    };
    let mut cursor = PathBuf::new();
    for component in absolute.components() {
        cursor.push(component.as_os_str());
        if matches!(component, Component::RootDir | Component::Prefix(_)) {
            continue;
        }
        let metadata = fs::symlink_metadata(&cursor).map_err(|source| CliError::Io {
            path: cursor.display().to_string(),
            source,
        })?;
        if metadata.file_type().is_symlink() {
            return Err(CliError::Input(format!(
                "Pages deployment artifact has symlink component `{}`",
                cursor.display()
            )));
        }
    }
    Ok(())
}

fn ignored_by_wrangler(relative: &Path) -> bool {
    relative.components().any(|component| {
        let value = component.as_os_str().to_string_lossy();
        matches!(
            value.as_ref(),
            ".git" | ".wrangler" | "node_modules" | "functions"
        ) || value == ".DS_Store"
    })
}

#[expect(
    clippy::too_many_lines,
    reason = "artifact admission keeps path, type, size, content, and provider-limit checks in one deterministic walk"
)]
pub(super) fn manifest(root: &Path) -> Result<Value, CliError> {
    let mut entries = Vec::new();
    let mut asset_count = 0usize;
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry.map_err(|error| {
            CliError::Input(format!(
                "failed to inspect Pages deployment artifact `{}`: {error}",
                root.display()
            ))
        })?;
        if entry.path() == root {
            continue;
        }
        let relative = entry.path().strip_prefix(root).map_err(|_| {
            CliError::Input(format!(
                "Pages deployment artifact entry `{}` escaped its root",
                entry.path().display()
            ))
        })?;
        if ignored_by_wrangler(relative) {
            return Err(CliError::Input(format!(
                "Pages deployment artifact contains `{}`, which Wrangler would omit or source outside the reviewed artifact root",
                relative.display()
            )));
        }
        if entry.file_type().is_dir() {
            if relative.components().count() == 1
                && CONTROL_FILES
                    .iter()
                    .any(|control| relative == Path::new(control))
            {
                return Err(CliError::Input(format!(
                    "Pages control path `{}` must be one regular file",
                    relative.display()
                )));
            }
            continue;
        }
        if !entry.file_type().is_file() {
            return Err(CliError::Input(format!(
                "Pages deployment artifact contains unsupported non-file entry `{}`",
                entry.path().display()
            )));
        }
        let path = relative.to_str().ok_or_else(|| {
            CliError::Input("Pages deployment artifact paths must be valid UTF-8".to_owned())
        })?;
        let path = path.replace('\\', "/");
        let metadata = entry.metadata().map_err(|error| {
            CliError::Input(format!(
                "failed to inspect Pages deployment artifact file `{}`: {error}",
                entry.path().display()
            ))
        })?;
        if metadata.len() > MAX_FILE_BYTES {
            return Err(CliError::Input(format!(
                "Pages deployment artifact file `{path}` exceeds the 25 MiB provider limit"
            )));
        }
        let bytes = fs::read(entry.path()).map_err(|source| CliError::Io {
            path: entry.path().display().to_string(),
            source,
        })?;
        let after = fs::symlink_metadata(entry.path()).map_err(|source| CliError::Io {
            path: entry.path().display().to_string(),
            source,
        })?;
        if !after.file_type().is_file()
            || after.file_type().is_symlink()
            || after.len() != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
            || after.len() > MAX_FILE_BYTES
        {
            return Err(CliError::Input(format!(
                "Pages deployment artifact file `{path}` changed or became ambiguous during admission"
            )));
        }
        let role = if relative.components().count() == 1 && CONTROL_FILES.contains(&path.as_str()) {
            "multipart_control"
        } else {
            asset_count += 1;
            "asset"
        };
        entries.push(json!({
            "path": path,
            "size": bytes.len(),
            "sha256": hex::encode(Sha256::digest(&bytes)),
            "role": role,
        }));
    }
    if asset_count == 0 {
        return Err(CliError::Input(
            "Pages deployment artifact contains no uploadable asset and cannot construct a provider manifest"
                .to_owned(),
        ));
    }
    if asset_count > MAX_ASSET_COUNT {
        return Err(CliError::Input(format!(
            "Pages deployment artifact contains {asset_count} assets, exceeding the 20,000-file provider limit"
        )));
    }
    entries.sort_by_key(|entry| entry["path"].as_str().unwrap_or_default().to_owned());
    let content_hash = hash_value(&Value::Array(entries.clone()))?;
    Ok(json!({
        "schema_version": 1,
        "root": root,
        "asset_count": asset_count,
        "entry_count": entries.len(),
        "content_hash": content_hash,
        "entries": entries,
    }))
}

fn repository_owning_path<'a>(
    graph: &'a WorkspaceGraph,
    path: &Path,
) -> Option<&'a RepositoryNode> {
    graph
        .repositories
        .iter()
        .filter(|repository| path.starts_with(&repository.path))
        .max_by_key(|repository| repository.path.components().count())
}

fn full_git_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn wrangler_producer(capability: &CapabilityV1) -> Result<Value, CliError> {
    let discovered = which::which("wrangler").map_err(|error| {
        CliError::Input(format!(
            "Pages direct upload requires Wrangler on PATH before planning: {error}"
        ))
    })?;
    wrangler_producer_at(capability, &discovered)
}

fn wrangler_package_root(executable: &Path) -> Option<PathBuf> {
    let package = executable.parent()?.parent()?;
    let metadata: Value =
        serde_json::from_slice(&fs::read(package.join("package.json")).ok()?).ok()?;
    (metadata.get("name").and_then(Value::as_str) == Some("wrangler")
        && package.join("wrangler-dist/cli.js").is_file())
    .then(|| package.to_path_buf())
}

fn package_metadata(root: &Path) -> Result<Value, CliError> {
    let path = root.join("package.json");
    let bytes = fs::read(&path).map_err(|source| CliError::Io {
        path: path.display().to_string(),
        source,
    })?;
    serde_json::from_slice(&bytes).map_err(|error| {
        CliError::Input(format!(
            "Wrangler producer package metadata `{}` is invalid: {error}",
            path.display()
        ))
    })
}

fn esbuild_closure_roots(wrangler_root: &Path) -> Result<Vec<(String, PathBuf)>, CliError> {
    let wrangler = package_metadata(wrangler_root)?;
    let expected_version = wrangler
        .pointer("/dependencies/esbuild")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "Wrangler producer does not declare its required esbuild version".to_owned(),
            )
        })?;
    let node_modules = wrangler_root
        .parent()
        .ok_or_else(|| CliError::Input("Wrangler package has no node_modules parent".to_owned()))?;
    let esbuild_root = node_modules.join("esbuild");
    let esbuild = package_metadata(&esbuild_root)?;
    if esbuild.get("name").and_then(Value::as_str) != Some("esbuild")
        || esbuild.get("version").and_then(Value::as_str) != Some(expected_version)
    {
        return Err(CliError::Input(format!(
            "Wrangler requires esbuild {expected_version}, but the resolved package identity differs"
        )));
    }
    let platform_parent = node_modules.join("@esbuild");
    let mut platforms = fs::read_dir(&platform_parent)
        .map_err(|source| CliError::Io {
            path: platform_parent.display().to_string(),
            source,
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| CliError::Io {
            path: platform_parent.display().to_string(),
            source,
        })?;
    platforms.sort_by_key(std::fs::DirEntry::file_name);
    let mut selected = Vec::new();
    for entry in platforms {
        let path = entry.path();
        if !entry
            .file_type()
            .map_err(|source| CliError::Io {
                path: path.display().to_string(),
                source,
            })?
            .is_dir()
        {
            continue;
        }
        let metadata = package_metadata(&path)?;
        let name = metadata.get("name").and_then(Value::as_str).unwrap_or("");
        if name.starts_with("@esbuild/")
            && metadata.get("version").and_then(Value::as_str) == Some(expected_version)
        {
            selected.push((name.to_owned(), path));
        }
    }
    let [(platform_name, platform_root)] = selected.as_slice() else {
        return Err(CliError::Input(format!(
            "Wrangler producer requires exactly one installed esbuild {expected_version} platform package"
        )));
    };
    Ok(vec![
        ("wrangler".to_owned(), wrangler_root.to_path_buf()),
        ("esbuild".to_owned(), esbuild_root),
        (platform_name.clone(), platform_root.clone()),
    ])
}

fn producer_closure(executable: &Path) -> Result<Value, CliError> {
    let package_root = wrangler_package_root(executable);
    let executable_parent = executable
        .parent()
        .ok_or_else(|| CliError::Input("Wrangler executable has no package parent".to_owned()))?;
    let roots = if let Some(root) = &package_root {
        esbuild_closure_roots(root)?
    } else {
        vec![("executable".to_owned(), executable_parent.to_path_buf())]
    };
    let mut total_bytes = 0_u64;
    let mut files = Vec::new();
    for (component, root) in &roots {
        let mut paths = if package_root.is_some() {
            WalkDir::new(root)
                .follow_links(false)
                .into_iter()
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| {
                    CliError::Input(format!("Wrangler package cannot be inspected: {error}"))
                })?
                .into_iter()
                .filter(|entry| entry.path() != root)
                .map(walkdir::DirEntry::into_path)
                .collect::<Vec<_>>()
        } else {
            vec![executable.to_path_buf()]
        };
        paths.sort();
        for path in paths {
            let metadata = fs::symlink_metadata(&path).map_err(|source| CliError::Io {
                path: path.display().to_string(),
                source,
            })?;
            if metadata.file_type().is_symlink() || (!metadata.is_file() && !metadata.is_dir()) {
                return Err(CliError::Input(format!(
                    "Wrangler producer closure contains an ambiguous entry `{}`",
                    path.display()
                )));
            }
            if metadata.is_dir() {
                continue;
            }
            total_bytes = total_bytes.checked_add(metadata.len()).ok_or_else(|| {
                CliError::Input("Wrangler producer closure size overflowed".to_owned())
            })?;
            if total_bytes > MAX_PRODUCER_BYTES {
                return Err(CliError::Input(format!(
                    "Wrangler producer closure exceeds {MAX_PRODUCER_BYTES} bytes"
                )));
            }
            let bytes = fs::read(&path).map_err(|source| CliError::Io {
                path: path.display().to_string(),
                source,
            })?;
            let relative = path.strip_prefix(root).map_err(|_| {
                CliError::Input("Wrangler producer closure escaped its package root".to_owned())
            })?;
            files.push(json!({
                "component": component,
                "path": relative.to_string_lossy().replace('\\', "/"),
                "size": metadata.len(),
                "sha256": hex::encode(Sha256::digest(&bytes)),
            }));
            if files.len() > MAX_PRODUCER_FILE_COUNT {
                return Err(CliError::Input(format!(
                    "Wrangler producer closure contains more than {MAX_PRODUCER_FILE_COUNT} files"
                )));
            }
        }
    }
    let manifest = json!(&files);
    let manifest_sha256 = hash_value(&manifest).map_err(|error| {
        CliError::Input(format!(
            "Wrangler producer closure cannot be hashed: {error}"
        ))
    })?;
    Ok(json!({
        "kind": if package_root.is_some() { "wrangler_with_esbuild" } else { "single_file" },
        "roots": roots.iter().map(|(component, root)| json!({"component": component, "root": root})).collect::<Vec<_>>(),
        "file_count": files.len(),
        "total_bytes": total_bytes,
        "manifest_sha256": manifest_sha256,
        "files": files,
    }))
}

fn executable_interpreter(executable: &Path, bytes: &[u8]) -> Result<Option<Value>, CliError> {
    let Some(line) = bytes.split(|byte| *byte == b'\n').next() else {
        return Ok(None);
    };
    let Ok(line) = std::str::from_utf8(line) else {
        return Ok(None);
    };
    let Some(shebang) = line.strip_prefix("#!") else {
        return Ok(None);
    };
    let parts = shebang.split_whitespace().collect::<Vec<_>>();
    let raw = match parts.as_slice() {
        ["/usr/bin/env", program] => which::which(program).map_err(|error| {
            CliError::Input(format!(
                "Wrangler interpreter `{program}` is unavailable before planning: {error}"
            ))
        })?,
        [absolute] if Path::new(absolute).is_absolute() => PathBuf::from(absolute),
        _ => {
            return Err(CliError::Input(format!(
                "Wrangler launcher `{}` has an unsupported interpreter contract",
                executable.display()
            )));
        }
    };
    let path = fs::canonicalize(&raw).map_err(|source| CliError::Io {
        path: raw.display().to_string(),
        source,
    })?;
    let metadata = fs::metadata(&path).map_err(|source| CliError::Io {
        path: path.display().to_string(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(CliError::Input(format!(
            "Wrangler interpreter `{}` is not one regular file",
            path.display()
        )));
    }
    let interpreter_bytes = fs::read(&path).map_err(|source| CliError::Io {
        path: path.display().to_string(),
        source,
    })?;
    Ok(Some(json!({
        "path": path,
        "sha256": hex::encode(Sha256::digest(&interpreter_bytes)),
    })))
}

fn wrangler_producer_at(capability: &CapabilityV1, discovered: &Path) -> Result<Value, CliError> {
    let executable = fs::canonicalize(discovered).map_err(|source| CliError::Io {
        path: discovered.display().to_string(),
        source,
    })?;
    let metadata = fs::metadata(&executable).map_err(|source| CliError::Io {
        path: executable.display().to_string(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(CliError::Input(format!(
            "Wrangler executable `{}` is not one regular file",
            executable.display()
        )));
    }
    let bytes = fs::read(&executable).map_err(|source| CliError::Io {
        path: executable.display().to_string(),
        source,
    })?;
    let closure = producer_closure(&executable)?;
    let interpreter = executable_interpreter(&executable, &bytes)?;
    let isolated_home = tempfile::Builder::new()
        .prefix("cfctl-wrangler-version-")
        .tempdir()
        .map_err(|source| CliError::Io {
            path: "temporary Wrangler version home".to_owned(),
            source,
        })?;
    let mut version_command = if let Some(path) = interpreter
        .as_ref()
        .and_then(|value| value.get("path"))
        .and_then(Value::as_str)
    {
        let mut command = Command::new(path);
        command.arg(&executable);
        command
    } else {
        Command::new(&executable)
    };
    let output = version_command
        .arg("--version")
        .env_clear()
        .env("PATH", env::var_os("PATH").unwrap_or_default())
        .env("HOME", isolated_home.path())
        .env("NO_COLOR", "1")
        .output()
        .map_err(|source| CliError::Io {
            path: executable.display().to_string(),
            source,
        })?;
    if !output.status.success() {
        return Err(CliError::Input(format!(
            "Wrangler producer `{}` did not report a successful version",
            executable.display()
        )));
    }
    let version = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if version.is_empty() || capability.source != format!("wrangler {version} pages deploy help") {
        return Err(CliError::Input(format!(
            "Wrangler producer version `{version}` does not match the catalog source `{}`; sync the catalog before planning",
            capability.source
        )));
    }
    Ok(json!({
        "executable": executable,
        "executable_sha256": hex::encode(Sha256::digest(&bytes)),
        "execution_closure": closure,
        "interpreter": interpreter,
        "version": version,
        "catalog_source": capability.source,
    }))
}

pub(super) fn prepare_target(
    graph: &WorkspaceGraph,
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<Option<Value>, CliError> {
    if !binds_artifact(capability) {
        return Ok(None);
    }
    let root = artifact_root(input)?;
    let repository = repository_owning_path(graph, &root).ok_or_else(|| {
        CliError::Input(format!(
            "Pages deployment artifact `{}` is not owned by a registered repository",
            root.display()
        ))
    })?;
    if repository.git.dirty {
        return Err(CliError::Input(format!(
            "Pages deployment repository `{}` is dirty; commit the reviewed source before planning",
            repository.path.display()
        )));
    }
    let source_sha = repository
        .git
        .head
        .as_deref()
        .filter(|value| full_git_sha(value))
        .ok_or_else(|| {
            CliError::Input("Pages deployment repository has no canonical full Git HEAD".to_owned())
        })?;
    let branch = repository
        .git
        .branch
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "Pages deployment repository must be attached to one named branch".to_owned(),
            )
        })?;
    let planned_sha = input.query.get("commit_hash").and_then(Value::as_str);
    if planned_sha != Some(source_sha) {
        return Err(CliError::Input(format!(
            "Pages deployment commit_hash must equal the registered repository HEAD `{source_sha}`"
        )));
    }
    let planned_branch = input.query.get("branch").and_then(Value::as_str);
    if planned_branch != Some(branch) {
        return Err(CliError::Input(format!(
            "Pages deployment branch must equal the registered repository branch `{branch}`"
        )));
    }
    let artifact = manifest(&root)?;
    let producer = wrangler_producer(capability)?;
    Ok(Some(json!({
        "schema_version": 1,
        "project_name": project_name(capability, input)?,
        "source": {
            "repository": repository.path,
            "commit": source_sha,
            "branch": branch,
        },
        "artifact": artifact,
        "provider_request": {
            "producer": producer,
            "asset_transport": "content-addressed Pages asset upload",
            "deployment_transport": "multipart/form-data",
            "manifest_required": true,
            "implicit_working_directory_inputs": false,
        },
    })))
}

pub(super) fn bound_wrangler_executable(adapter_targets: &Value) -> Result<PathBuf, CliError> {
    let raw = target(adapter_targets)
        .and_then(|value| value.pointer("/provider_request/producer/executable"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "Pages direct-upload plan omitted its exact Wrangler producer; create a new plan"
                    .to_owned(),
            )
        })?;
    Ok(PathBuf::from(raw))
}

pub(super) fn bound_wrangler_interpreter(
    adapter_targets: &Value,
) -> Result<Option<PathBuf>, CliError> {
    let producer = target(adapter_targets)
        .and_then(|value| value.pointer("/provider_request/producer"))
        .ok_or_else(|| {
            CliError::Input(
                "Pages direct-upload plan omitted its exact Wrangler producer; create a new plan"
                    .to_owned(),
            )
        })?;
    let Some(interpreter) = producer.get("interpreter") else {
        return Err(CliError::Input(
            "Pages direct-upload plan predates interpreter binding; create a new plan".to_owned(),
        ));
    };
    if interpreter.is_null() {
        return Ok(None);
    }
    interpreter
        .get("path")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .map(Some)
        .ok_or_else(|| {
            CliError::Input(
                "Pages direct-upload plan has an invalid Wrangler interpreter binding; create a new plan"
                    .to_owned(),
            )
        })
}

pub(super) fn target(adapter_targets: &Value) -> Option<&Value> {
    adapter_targets.get("pages_deployment")
}

pub(super) fn validate_bound_plan(
    graph: &WorkspaceGraph,
    plan: &PlanV1,
    input: &CallInput,
) -> Result<(), CliError> {
    let adapter = plan.targets.get("adapter").unwrap_or(&Value::Null);
    let Some(expected) = target(adapter) else {
        if binds_artifact(&plan.capability) {
            return Err(CliError::Input(
                "Pages direct-upload plan predates immutable artifact binding; create a new plan"
                    .to_owned(),
            ));
        }
        return Ok(());
    };
    let current = prepare_target(graph, &plan.capability, input)?.ok_or_else(|| {
        CliError::Input("Pages direct-upload target could not be recomputed".to_owned())
    })?;
    if &current != expected {
        return Err(CliError::Input(
            "Pages source or artifact manifest drifted after planning; the provider boundary was not crossed and a new plan is required"
                .to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn apply_project_response(
    capability: &CapabilityV1,
    account_id: &str,
    project_name: &str,
    expected_branch: Option<&str>,
    response: &CloudflareResponseV1,
) -> Result<Value, CliError> {
    if !response.success || response.status != 200 {
        return Err(CliError::Input(format!(
            "Pages project admission read returned HTTP {}; the deployment boundary was not crossed",
            response.status
        )));
    }
    if response.result.get("name").and_then(Value::as_str) != Some(project_name) {
        return Err(CliError::Input(
            "Pages project admission read returned a different project identity; the deployment boundary was not crossed"
                .to_owned(),
        ));
    }
    let production_branch = response
        .result
        .get("production_branch")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "Pages project admission read omitted the production branch; the deployment boundary was not crossed"
                    .to_owned(),
            )
        })?;
    let source = response.result.get("source");
    let source_mode = if source.is_some_and(Value::is_null) {
        "direct_upload"
    } else if source
        .and_then(|value| value.get("type"))
        .and_then(Value::as_str)
        .is_some_and(|kind| matches!(kind, "github" | "gitlab"))
        && source
            .and_then(|value| value.get("config"))
            .is_some_and(Value::is_object)
    {
        "git_integrated"
    } else {
        return Err(CliError::Input(
            "Pages project admission read returned an unknown source mode; the deployment boundary was not crossed"
                .to_owned(),
        ));
    };
    let expected_mode = if binds_artifact(capability) {
        "direct_upload"
    } else {
        "git_integrated"
    };
    if source_mode != expected_mode {
        let next = if source_mode == "direct_upload" {
            "use `cfctl call wrangler.pages-deploy` with an admitted artifact root"
        } else {
            "use the Git-integrated bodyless deployment trigger only for this project"
        };
        return Err(CliError::Input(format!(
            "Pages project `{project_name}` is `{source_mode}`, but `{}` requires `{expected_mode}`; {next}; the deployment boundary was not crossed",
            capability.id
        )));
    }
    if expected_branch.is_some_and(|branch| branch != production_branch) {
        return Err(CliError::Input(format!(
            "Pages direct-upload branch does not match project production branch `{production_branch}`; the deployment boundary was not crossed"
        )));
    }
    Ok(json!({
        "schema_version": 1,
        "source_capability_id": PROJECT_READ_CAPABILITY_ID,
        "source_path": PROJECT_DETAIL_PATH,
        "target_capability_id": capability.id,
        "account_id": account_id,
        "project_name": project_name,
        "production_branch": production_branch,
        "source_mode": source_mode,
    }))
}

pub(super) fn deployment_ids(value: &Value) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    collect_deployment_ids(value, &mut ids);
    ids
}

fn collect_deployment_ids(value: &Value, ids: &mut BTreeSet<String>) {
    match value {
        Value::Array(values) => values
            .iter()
            .for_each(|value| collect_deployment_ids(value, ids)),
        Value::Object(fields) => {
            if let Some(id) = fields
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| uuid::Uuid::parse_str(id).is_ok())
            {
                ids.insert(id.to_owned());
            }
            fields
                .values()
                .for_each(|value| collect_deployment_ids(value, ids));
        }
        _ => {}
    }
}

pub(super) fn parse_wrangler_output(output: &str) -> Result<Value, CliError> {
    let entries = output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str::<Value>)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| {
            CliError::Input(format!(
                "Wrangler Pages structured output is not valid JSON Lines: {error}"
            ))
        })?;
    let detailed = entries
        .iter()
        .filter(|entry| {
            entry.get("type").and_then(Value::as_str) == Some("pages-deploy-detailed")
                && entry.get("version").and_then(Value::as_u64) == Some(1)
        })
        .collect::<Vec<_>>();
    if detailed.len() != 1 {
        return Err(CliError::Input(format!(
            "Wrangler Pages structured output contained {} detailed deployment receipts; exactly one is required",
            detailed.len()
        )));
    }
    let receipt = detailed[0];
    let deployment_id = receipt
        .get("deployment_id")
        .and_then(Value::as_str)
        .filter(|id| {
            uuid::Uuid::parse_str(id).is_ok_and(|parsed| parsed.hyphenated().to_string() == *id)
        })
        .ok_or_else(|| {
            CliError::Input(
                "Wrangler Pages structured output omitted one canonical deployment ID".to_owned(),
            )
        })?;
    let basic_matches = entries.iter().any(|entry| {
        entry.get("type").and_then(Value::as_str) == Some("pages-deploy")
            && entry.get("version").and_then(Value::as_u64) == Some(1)
            && entry.get("deployment_id").and_then(Value::as_str) == Some(deployment_id)
            && entry.get("pages_project") == receipt.get("pages_project")
            && entry.get("url") == receipt.get("url")
    });
    if !basic_matches
        || receipt
            .get("pages_project")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || receipt
            .get("url")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err(CliError::Input(
            "Wrangler Pages structured output receipts disagree on deployment identity".to_owned(),
        ));
    }
    Ok(receipt.clone())
}

pub(super) fn structured_output_matches(
    value: &Value,
    project_name: &str,
    branch: &str,
    commit_hash: &str,
) -> bool {
    value.get("pages_project").and_then(Value::as_str) == Some(project_name)
        && value.get("environment").and_then(Value::as_str) == Some("production")
        && value.get("production_branch").and_then(Value::as_str) == Some(branch)
        && value
            .pointer("/deployment_trigger/metadata/commit_hash")
            .and_then(Value::as_str)
            == Some(commit_hash)
}

pub(super) fn deployment_matches_returned_id(
    value: &Value,
    deployment_id: &str,
    project_name: &str,
    branch: &str,
    commit_hash: &str,
) -> bool {
    match value {
        Value::Array(values) => values.iter().any(|value| {
            deployment_matches_returned_id(value, deployment_id, project_name, branch, commit_hash)
        }),
        Value::Object(fields) => {
            let exact = fields.get("id").and_then(Value::as_str) == Some(deployment_id)
                && fields.get("project_name").and_then(Value::as_str) == Some(project_name)
                && fields.get("environment").and_then(Value::as_str) == Some("production")
                && value
                    .pointer("/deployment_trigger/metadata/branch")
                    .and_then(Value::as_str)
                    == Some(branch)
                && value
                    .pointer("/deployment_trigger/metadata/commit_hash")
                    .and_then(Value::as_str)
                    == Some(commit_hash);
            exact
                || fields.values().any(|value| {
                    deployment_matches_returned_id(
                        value,
                        deployment_id,
                        project_name,
                        branch,
                        commit_hash,
                    )
                })
        }
        _ => false,
    }
}

pub(super) fn matching_deployment_ids(
    value: &Value,
    prior_ids: &BTreeSet<String>,
    project_name: &str,
    branch: &str,
    commit_hash: &str,
) -> BTreeSet<String> {
    let mut matches = BTreeSet::new();
    collect_matching_deployments(
        value,
        prior_ids,
        project_name,
        branch,
        commit_hash,
        &mut matches,
    );
    matches
}

fn collect_matching_deployments(
    value: &Value,
    prior_ids: &BTreeSet<String>,
    project_name: &str,
    branch: &str,
    commit_hash: &str,
    matches: &mut BTreeSet<String>,
) {
    match value {
        Value::Array(values) => values.iter().for_each(|value| {
            collect_matching_deployments(
                value,
                prior_ids,
                project_name,
                branch,
                commit_hash,
                matches,
            );
        }),
        Value::Object(fields) => {
            let id = fields.get("id").and_then(Value::as_str);
            let exact = fields.get("project_name").and_then(Value::as_str) == Some(project_name)
                && fields.get("environment").and_then(Value::as_str) == Some("production")
                && value
                    .pointer("/deployment_trigger/metadata/branch")
                    .and_then(Value::as_str)
                    == Some(branch)
                && value
                    .pointer("/deployment_trigger/metadata/commit_hash")
                    .and_then(Value::as_str)
                    == Some(commit_hash);
            if exact
                && let Some(id) = id.filter(|id| uuid::Uuid::parse_str(id).is_ok())
                && !prior_ids.contains(id)
            {
                matches.insert(id.to_owned());
            }
            fields.values().for_each(|value| {
                collect_matching_deployments(
                    value,
                    prior_ids,
                    project_name,
                    branch,
                    commit_hash,
                    matches,
                );
            });
        }
        _ => {}
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use cfctl_core::AdapterStatus;

    fn direct_upload() -> CapabilityV1 {
        let mut capability = CapabilityV1::new(
            DIRECT_UPLOAD_CAPABILITY_ID,
            "deploy Pages artifact",
            "POST",
            "wrangler pages deploy",
        );
        capability.method = "CLI".to_owned();
        capability.adapter_status = AdapterStatus::DelegatedCli;
        capability
    }

    #[test]
    fn manifest_binds_path_size_hash_and_rejects_wrangler_omissions() {
        let root = tempfile::tempdir().expect("artifact");
        fs::write(root.path().join("index.html"), b"hello").expect("asset");
        fs::write(root.path().join("_headers"), b"/*\n  X-Test: yes\n").expect("control");
        let value = manifest(root.path()).expect("manifest");
        assert_eq!(value["asset_count"], 1);
        assert_eq!(value["entry_count"], 2);
        assert_eq!(value["entries"][0]["path"], "_headers");
        assert_eq!(value["entries"][0]["role"], "multipart_control");
        assert_eq!(value["entries"][1]["path"], "index.html");
        assert_eq!(value["entries"][1]["size"], 5);
        assert_eq!(
            value["entries"][1]["sha256"],
            hex::encode(Sha256::digest(b"hello"))
        );

        fs::create_dir(root.path().join("node_modules")).expect("ignored dir");
        fs::write(root.path().join("node_modules/hidden.js"), b"hidden").expect("ignored file");
        assert!(manifest(root.path()).is_err());
    }

    #[test]
    fn manifest_changes_with_content_and_rejects_nested_symlinks() {
        let root = tempfile::tempdir().expect("artifact");
        let asset = root.path().join("index.html");
        fs::write(&asset, b"first").expect("first asset");
        let first = manifest(root.path()).expect("first manifest");
        fs::write(&asset, b"second-version").expect("changed asset");
        let second = manifest(root.path()).expect("second manifest");
        assert_ne!(first["content_hash"], second["content_hash"]);
        assert_ne!(first["entries"][0]["size"], second["entries"][0]["size"]);
        assert_ne!(
            first["entries"][0]["sha256"],
            second["entries"][0]["sha256"]
        );

        #[cfg(unix)]
        {
            let alias = root.path().join("alias.html");
            std::os::unix::fs::symlink(&asset, &alias).expect("nested symlink");
            assert!(manifest(root.path()).is_err());
        }
    }

    #[test]
    fn project_mode_separates_bodyless_git_trigger_from_direct_upload() {
        let response = CloudflareResponseV1 {
            status: 200,
            success: true,
            result: json!({"name":"aos-web","production_branch":"main","source":null}),
            errors: Vec::new(),
            result_info: None,
            etag: None,
            cf_ray: None,
        };
        assert!(
            apply_project_response(&direct_upload(), "acct", "aos-web", Some("main"), &response)
                .is_ok()
        );
        let mut bodyless = CapabilityV1::new(
            GIT_TRIGGER_CAPABILITY_ID,
            "trigger Git build",
            "POST",
            DEPLOYMENT_LIST_PATH,
        );
        bodyless.adapter_status = AdapterStatus::DynamicApi;
        assert!(apply_project_response(&bodyless, "acct", "aos-web", None, &response).is_err());

        let git_project = CloudflareResponseV1 {
            result: json!({
                "name":"aos-web",
                "production_branch":"main",
                "source":{"type":"github","config":{}}
            }),
            ..response.clone()
        };
        assert!(apply_project_response(&bodyless, "acct", "aos-web", None, &git_project).is_ok());
        assert!(
            apply_project_response(
                &direct_upload(),
                "acct",
                "aos-web",
                Some("main"),
                &git_project
            )
            .is_err()
        );

        let unknown = CloudflareResponseV1 {
            result: json!({"name":"aos-web","production_branch":"main"}),
            ..response
        };
        assert!(apply_project_response(&bodyless, "acct", "aos-web", None, &unknown).is_err());
    }

    #[test]
    fn collection_identity_matches_only_new_exact_deployments() {
        let old = "11111111-1111-4111-8111-111111111111";
        let new = "22222222-2222-4222-8222-222222222222";
        let deployment = |id| {
            json!({
                "id": id,
                "project_name": "aos-web",
                "environment": "production",
                "deployment_trigger": {"metadata":{"branch":"main","commit_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
                "latest_stage":{"status":"active"}
            })
        };
        let prior = BTreeSet::from([old.to_owned()]);
        let single = json!([deployment(old), deployment(new)]);
        assert_eq!(
            matching_deployment_ids(
                &single,
                &prior,
                "aos-web",
                "main",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ),
            BTreeSet::from([new.to_owned()])
        );
        assert!(deployment_matches_returned_id(
            &single,
            new,
            "aos-web",
            "main",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
        assert!(!deployment_matches_returned_id(
            &single,
            old,
            "aos-web",
            "preview",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
        assert_eq!(
            matching_deployment_ids(
                &json!([
                    deployment(new),
                    deployment("33333333-3333-4333-8333-333333333333")
                ]),
                &prior,
                "aos-web",
                "main",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            )
            .len(),
            2,
            "replay admission must observe every exact-identity deployment"
        );
    }

    #[cfg(unix)]
    #[test]
    fn producer_identity_binds_exact_executable_hash_and_catalog_version() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("producer root");
        let executable = root.path().join("wrangler");
        fs::write(&executable, "#!/bin/sh\nprintf '4.107.0\\n'\n").expect("producer");
        let mut permissions = fs::metadata(&executable)
            .expect("producer metadata")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&executable, permissions).expect("producer mode");

        let mut capability = direct_upload();
        capability.source = "wrangler 4.107.0 pages deploy help".to_owned();
        let producer = wrangler_producer_at(&capability, &executable).expect("bound producer");
        let canonical = executable.canonicalize().expect("canonical producer");
        assert_eq!(producer["executable"].as_str(), canonical.to_str());
        assert_eq!(producer["version"], "4.107.0");
        assert_eq!(producer["execution_closure"]["kind"], "single_file");
        assert_eq!(producer["execution_closure"]["file_count"], 1);
        assert_eq!(producer["interpreter"]["path"], "/bin/sh");
        assert_eq!(
            producer["executable_sha256"],
            hex::encode(Sha256::digest(
                fs::read(&executable).expect("producer bytes")
            ))
        );
        let targets = json!({
            "pages_deployment": {
                "provider_request": {"producer": producer}
            }
        });
        assert_eq!(
            bound_wrangler_executable(&targets).expect("bound path"),
            canonical
        );
        assert_eq!(
            bound_wrangler_interpreter(&targets).expect("bound interpreter"),
            Some(PathBuf::from("/bin/sh"))
        );

        capability.source = "wrangler 4.106.0 pages deploy help".to_owned();
        assert!(wrangler_producer_at(&capability, &executable).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn producer_identity_rejects_unchanged_launcher_with_drifted_external_builder() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("producer root");
        let package = root.path().join("wrangler");
        let bin = package.join("bin");
        let distribution = package.join("wrangler-dist");
        fs::create_dir_all(&bin).expect("bin");
        fs::create_dir_all(&distribution).expect("distribution");
        fs::write(
            package.join("package.json"),
            r#"{"name":"wrangler","version":"4.107.0","dependencies":{"esbuild":"0.28.1"}}"#,
        )
        .expect("package metadata");
        let executable = bin.join("wrangler.js");
        fs::write(&executable, "#!/bin/sh\nprintf '4.107.0\\n'\n").expect("launcher");
        let mut permissions = fs::metadata(&executable)
            .expect("launcher metadata")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&executable, permissions).expect("launcher mode");
        fs::write(distribution.join("cli.js"), "require('esbuild')").expect("payload");
        let esbuild = root.path().join("esbuild");
        fs::create_dir_all(esbuild.join("lib")).expect("esbuild package");
        fs::write(
            esbuild.join("package.json"),
            r#"{"name":"esbuild","version":"0.28.1"}"#,
        )
        .expect("esbuild metadata");
        fs::write(esbuild.join("lib/main.js"), "builder-v1").expect("esbuild runtime");
        let platform = root.path().join("@esbuild/darwin-arm64");
        fs::create_dir_all(platform.join("bin")).expect("platform package");
        fs::write(
            platform.join("package.json"),
            r#"{"name":"@esbuild/darwin-arm64","version":"0.28.1"}"#,
        )
        .expect("platform metadata");
        let native = platform.join("bin/esbuild");
        fs::write(&native, "native-v1").expect("native builder");

        let mut capability = direct_upload();
        capability.source = "wrangler 4.107.0 pages deploy help".to_owned();
        let planned = wrangler_producer_at(&capability, &executable).expect("planned producer");
        fs::write(&native, "native-v2").expect("drifted external builder");
        let current = wrangler_producer_at(&capability, &executable).expect("current producer");

        assert_ne!(
            planned, current,
            "the bound producer must change when an unmodified Wrangler package delegates to drifted external builder bytes"
        );
        assert_eq!(planned["executable_sha256"], current["executable_sha256"]);
        assert_ne!(
            planned["execution_closure"]["manifest_sha256"],
            current["execution_closure"]["manifest_sha256"]
        );
    }

    #[test]
    fn wrangler_output_requires_one_consistent_provider_returned_id() {
        let id = "22222222-2222-4222-8222-222222222222";
        let commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let output = format!(
            "{{\"type\":\"pages-deploy\",\"version\":1,\"pages_project\":\"aos-web\",\"deployment_id\":\"{id}\",\"url\":\"https://example.pages.dev\"}}\n{{\"type\":\"pages-deploy-detailed\",\"version\":1,\"pages_project\":\"aos-web\",\"deployment_id\":\"{id}\",\"url\":\"https://example.pages.dev\",\"environment\":\"production\",\"production_branch\":\"main\",\"deployment_trigger\":{{\"metadata\":{{\"commit_hash\":\"{commit}\"}}}}}}\n"
        );
        let parsed = parse_wrangler_output(&output).expect("exact output");
        assert_eq!(parsed["deployment_id"], id);
        assert!(structured_output_matches(
            &parsed, "aos-web", "main", commit
        ));
        assert!(!structured_output_matches(&parsed, "other", "main", commit));
        assert!(parse_wrangler_output("{}").is_err());
        assert!(parse_wrangler_output(&format!("{output}{output}")).is_err());
    }
}
