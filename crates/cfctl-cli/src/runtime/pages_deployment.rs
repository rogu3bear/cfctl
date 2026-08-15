use std::{
    collections::{BTreeMap, BTreeSet},
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
const WORKER_BUNDLE_ARGS: &[&str] = &[
    "--bundle",
    "--format=esm",
    "--platform=browser",
    "--target=es2024",
    "--conditions=workerd,worker,browser",
    "--loader:.js=jsx",
    "--loader:.mjs=jsx",
    "--loader:.cjs=jsx",
    "--supported:import-source=true",
    "--keep-names",
    "--define:process.env.NODE_ENV=\"production\"",
    "--define:global.process.env.NODE_ENV=\"production\"",
    "--define:globalThis.process.env.NODE_ENV=\"production\"",
];

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

fn common_node_modules(package_root: &Path) -> Result<&Path, CliError> {
    package_root
        .ancestors()
        .find(|path| path.file_name().and_then(|name| name.to_str()) == Some("node_modules"))
        .ok_or_else(|| {
            CliError::Input("Wrangler package is not inside one node_modules closure".to_owned())
        })
}

fn resolve_dependency_root(
    package_root: &Path,
    node_modules: &Path,
    name: &str,
) -> Option<PathBuf> {
    let nested = package_root.join("node_modules").join(name);
    if nested.join("package.json").is_file() {
        return Some(nested);
    }
    let shared = node_modules.join(name);
    shared.join("package.json").is_file().then_some(shared)
}

fn declared_dependencies(metadata: &Value, key: &str) -> Vec<String> {
    metadata
        .get(key)
        .and_then(Value::as_object)
        .map(|dependencies| dependencies.keys().cloned().collect())
        .unwrap_or_default()
}

fn producer_package_roots(wrangler_root: &Path) -> Result<Vec<(String, PathBuf)>, CliError> {
    let node_modules = common_node_modules(wrangler_root)?;
    let mut pending = vec![wrangler_root.to_path_buf()];
    let mut roots = BTreeMap::<PathBuf, String>::new();
    while let Some(root) = pending.pop() {
        let canonical = fs::canonicalize(&root).map_err(|source| CliError::Io {
            path: root.display().to_string(),
            source,
        })?;
        if !canonical.starts_with(node_modules) {
            return Err(CliError::Input(format!(
                "Wrangler dependency `{}` escaped its node_modules closure",
                canonical.display()
            )));
        }
        if roots.contains_key(&canonical) {
            continue;
        }
        let metadata = package_metadata(&canonical)?;
        let name = metadata
            .get("name")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                CliError::Input(format!(
                    "Wrangler dependency `{}` has no package name",
                    canonical.display()
                ))
            })?
            .to_owned();
        let required = declared_dependencies(&metadata, "dependencies");
        let optional = declared_dependencies(&metadata, "optionalDependencies");
        roots.insert(canonical.clone(), name);
        for dependency in required {
            let resolved = resolve_dependency_root(&canonical, node_modules, &dependency)
                .ok_or_else(|| {
                    CliError::Input(format!(
                        "Wrangler producer dependency `{dependency}` is not installed"
                    ))
                })?;
            pending.push(resolved);
        }
        for dependency in optional {
            if let Some(resolved) = resolve_dependency_root(&canonical, node_modules, &dependency) {
                pending.push(resolved);
            }
        }
    }
    let mut roots = roots
        .into_iter()
        .map(|(root, name)| (name, root))
        .collect::<Vec<_>>();
    roots.sort();
    Ok(roots)
}

fn producer_closure(executable: &Path) -> Result<Value, CliError> {
    let package_root = wrangler_package_root(executable);
    let executable_parent = executable
        .parent()
        .ok_or_else(|| CliError::Input("Wrangler executable has no package parent".to_owned()))?;
    let roots = if let Some(root) = &package_root {
        producer_package_roots(root)?
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
        "kind": if package_root.is_some() { "node_dependency_graph" } else { "single_file" },
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

fn artifact_entry<'a>(artifact: &'a Value, path: &str) -> Option<&'a Value> {
    artifact["entries"]
        .as_array()?
        .iter()
        .find(|entry| entry["path"].as_str() == Some(path))
}

fn producer_component_root(producer: &Value, component: &str) -> Result<PathBuf, CliError> {
    producer
        .pointer("/execution_closure/roots")
        .and_then(Value::as_array)
        .and_then(|roots| {
            roots.iter().find_map(|root| {
                (root["component"].as_str() == Some(component))
                    .then(|| root["root"].as_str())
                    .flatten()
            })
        })
        .map(PathBuf::from)
        .ok_or_else(|| {
            CliError::Input(format!(
                "Pages worker bundling requires `{component}` in the bound Wrangler dependency graph"
            ))
        })
}

fn validate_worker_metafile(
    root: &Path,
    artifact: &Value,
    metafile: &Value,
) -> Result<Value, CliError> {
    let canonical_root = fs::canonicalize(root).map_err(|source| CliError::Io {
        path: root.display().to_string(),
        source,
    })?;
    let inputs = metafile["inputs"].as_object().ok_or_else(|| {
        CliError::Input("Pages worker bundler omitted its resolved input graph".to_owned())
    })?;
    let mut bound_inputs = Vec::new();
    for input in inputs.keys() {
        let joined = root.join(input);
        let canonical = fs::canonicalize(&joined).map_err(|source| CliError::Io {
            path: joined.display().to_string(),
            source,
        })?;
        let relative = canonical.strip_prefix(&canonical_root).map_err(|_| {
            CliError::Input(format!(
                "Pages worker import `{input}` resolves outside the admitted artifact root"
            ))
        })?;
        let path = relative.to_str().ok_or_else(|| {
            CliError::Input("Pages worker input paths must be valid UTF-8".to_owned())
        })?;
        let path = path.replace('\\', "/");
        let entry = artifact_entry(artifact, &path).ok_or_else(|| {
            CliError::Input(format!(
                "Pages worker input `{path}` is absent from the admitted artifact manifest"
            ))
        })?;
        bound_inputs.push(json!({
            "path": path,
            "size": entry["size"],
            "sha256": entry["sha256"],
        }));
    }
    bound_inputs.sort_by_key(|entry| entry["path"].as_str().unwrap_or_default().to_owned());
    let outputs = metafile["outputs"].as_object().ok_or_else(|| {
        CliError::Input("Pages worker bundler omitted its output graph".to_owned())
    })?;
    if outputs.len() != 1
        || outputs.values().any(|output| {
            output["imports"]
                .as_array()
                .is_none_or(|imports| !imports.is_empty())
        })
    {
        return Err(CliError::Input(
            "Pages worker bundle retained an unresolved external import".to_owned(),
        ));
    }
    Ok(Value::Array(bound_inputs))
}

fn contains_runtime_dynamic_import(bytes: &[u8]) -> bool {
    let mut cursor = 0usize;
    while cursor.saturating_add(6) <= bytes.len() {
        let Some(offset) = bytes[cursor..]
            .windows(6)
            .position(|window| window == b"import")
        else {
            return false;
        };
        let start = cursor + offset;
        let previous_is_identifier = start > 0
            && (bytes[start - 1].is_ascii_alphanumeric()
                || matches!(bytes[start - 1], b'_' | b'$'));
        let mut next = start + 6;
        let next_is_identifier = next < bytes.len()
            && (bytes[next].is_ascii_alphanumeric() || matches!(bytes[next], b'_' | b'$'));
        if !previous_is_identifier && !next_is_identifier {
            loop {
                while next < bytes.len() && bytes[next].is_ascii_whitespace() {
                    next += 1;
                }
                if bytes.get(next..next.saturating_add(2)) == Some(b"/*") {
                    let Some(end) = bytes[next + 2..]
                        .windows(2)
                        .position(|window| window == b"*/")
                    else {
                        return true;
                    };
                    next += end + 4;
                    continue;
                }
                if bytes.get(next..next.saturating_add(2)) == Some(b"//") {
                    next = bytes[next + 2..]
                        .iter()
                        .position(|byte| *byte == b'\n')
                        .map_or(bytes.len(), |end| next + end + 3);
                    continue;
                }
                break;
            }
            if bytes.get(next) == Some(&b'(') {
                return true;
            }
        }
        cursor = start + 6;
    }
    false
}

fn build_worker_bundle(
    root: &Path,
    artifact: &Value,
    producer: &Value,
) -> Result<Option<(Value, Vec<u8>)>, CliError> {
    if artifact_entry(artifact, "_worker.js").is_none() {
        return Ok(None);
    }
    let esbuild_root = producer_component_root(producer, "esbuild")?;
    let esbuild = esbuild_root.join("bin/esbuild");
    let interpreter = producer
        .pointer("/interpreter/path")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| {
            CliError::Input(
                "Pages worker bundling requires the exact bound JavaScript interpreter".to_owned(),
            )
        })?;
    let scratch = tempfile::Builder::new()
        .prefix("cfctl-pages-worker-bundle-")
        .tempdir()
        .map_err(|source| CliError::Io {
            path: "temporary Pages worker bundle directory".to_owned(),
            source,
        })?;
    let output_path = scratch.path().join("_worker.js");
    let metafile_path = scratch.path().join("metafile.json");
    let output = Command::new(&interpreter)
        .arg(&esbuild)
        .arg("_worker.js")
        .args(WORKER_BUNDLE_ARGS)
        .arg(format!("--metafile={}", metafile_path.display()))
        .arg(format!("--outfile={}", output_path.display()))
        .current_dir(root)
        .env_clear()
        .env("HOME", scratch.path())
        .env("NO_COLOR", "1")
        .output()
        .map_err(|source| CliError::Io {
            path: esbuild.display().to_string(),
            source,
        })?;
    if !output.status.success() {
        return Err(CliError::Input(format!(
            "Pages worker did not form a closed bundle from the admitted artifact: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let metafile: Value =
        serde_json::from_slice(&fs::read(&metafile_path).map_err(|source| CliError::Io {
            path: metafile_path.display().to_string(),
            source,
        })?)
        .map_err(|error| CliError::Input(format!("Pages worker metafile is invalid: {error}")))?;
    let inputs = validate_worker_metafile(root, artifact, &metafile)?;
    let bytes = fs::read(&output_path).map_err(|source| CliError::Io {
        path: output_path.display().to_string(),
        source,
    })?;
    if contains_runtime_dynamic_import(&bytes) {
        return Err(CliError::Input(
            "Pages worker bundle retained a runtime dynamic import that is absent from esbuild's closed input graph"
                .to_owned(),
        ));
    }
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_FILE_BYTES {
        return Err(CliError::Input(
            "Pages worker bundle exceeds the 25 MiB provider limit".to_owned(),
        ));
    }
    Ok(Some((
        json!({
            "schema_version": 1,
            "entrypoint": "_worker.js",
            "producer_component": "esbuild",
            "arguments": WORKER_BUNDLE_ARGS,
            "inputs": inputs,
            "output": {
                "path": "_worker.js",
                "size": bytes.len(),
                "sha256": hex::encode(Sha256::digest(&bytes)),
            },
            "runtime_dynamic_imports": false,
            "wrangler_bundle": false,
        }),
        bytes,
    )))
}

fn transport_manifest(artifact: &Value, worker_bundle: Option<&Value>) -> Result<Value, CliError> {
    let mut entries = artifact["entries"]
        .as_array()
        .cloned()
        .ok_or_else(|| CliError::Input("Pages artifact manifest omitted entries".to_owned()))?;
    if let Some(bundle) = worker_bundle {
        let worker = entries
            .iter_mut()
            .find(|entry| entry["path"].as_str() == Some("_worker.js"))
            .ok_or_else(|| {
                CliError::Input("Pages worker bundle has no admitted entrypoint".to_owned())
            })?;
        worker["size"] = bundle["output"]["size"].clone();
        worker["sha256"] = bundle["output"]["sha256"].clone();
    }
    let content_hash = hash_value(&Value::Array(entries.clone()))?;
    Ok(json!({
        "schema_version": 1,
        "asset_count": artifact["asset_count"],
        "entry_count": entries.len(),
        "content_hash": content_hash,
        "entries": entries,
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
    let worker_bundle =
        build_worker_bundle(&root, &artifact, &producer)?.map(|(contract, _bytes)| contract);
    let transport_manifest = transport_manifest(&artifact, worker_bundle.as_ref())?;
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
            "worker_bundle": worker_bundle,
            "transport_manifest": transport_manifest,
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

pub(super) fn validate_bound_producer(
    capability: &CapabilityV1,
    adapter_targets: &Value,
) -> Result<(), CliError> {
    let discovered = which::which("wrangler").map_err(|error| {
        CliError::Input(format!(
            "Pages direct upload requires Wrangler at the execution boundary: {error}"
        ))
    })?;
    validate_bound_producer_at(capability, adapter_targets, &discovered)
}

fn validate_bound_producer_at(
    capability: &CapabilityV1,
    adapter_targets: &Value,
    discovered: &Path,
) -> Result<(), CliError> {
    let expected = target(adapter_targets)
        .and_then(|value| value.pointer("/provider_request/producer"))
        .ok_or_else(|| {
            CliError::Input(
                "Pages direct-upload plan omitted its exact Wrangler producer; create a new plan"
                    .to_owned(),
            )
        })?;
    let current = wrangler_producer_at(capability, discovered)?;
    if &current != expected {
        return Err(CliError::Input(
            "Pages producer drifted at the execution boundary; no provider process was started and a new plan is required"
                .to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn target(adapter_targets: &Value) -> Option<&Value> {
    adapter_targets.get("pages_deployment")
}

pub(super) fn stage_bound_artifact(
    adapter_targets: &Value,
    input: &mut CallInput,
) -> Result<tempfile::TempDir, CliError> {
    let expected = target(adapter_targets).ok_or_else(|| {
        CliError::Input(
            "Pages direct-upload plan omitted its immutable artifact target; create a new plan"
                .to_owned(),
        )
    })?;
    let root = artifact_root(input)?;
    let artifact = manifest(&root)?;
    if artifact != expected["artifact"] {
        return Err(CliError::Input(
            "Pages artifact drifted before staging; the provider boundary was not crossed"
                .to_owned(),
        ));
    }
    let producer = &expected["provider_request"]["producer"];
    let worker_bundle = build_worker_bundle(&root, &artifact, producer)?;
    let expected_bundle = &expected["provider_request"]["worker_bundle"];
    if worker_bundle
        .as_ref()
        .map_or(&Value::Null, |(contract, _bytes)| contract)
        != expected_bundle
    {
        return Err(CliError::Input(
            "Pages worker bundle drifted before staging; the provider boundary was not crossed"
                .to_owned(),
        ));
    }
    let stage = tempfile::Builder::new()
        .prefix("cfctl-pages-staged-artifact-")
        .tempdir()
        .map_err(|source| CliError::Io {
            path: "temporary staged Pages artifact".to_owned(),
            source,
        })?;
    let staged_root = stage.path().join("artifact");
    fs::create_dir(&staged_root).map_err(|source| CliError::Io {
        path: staged_root.display().to_string(),
        source,
    })?;
    for entry in artifact["entries"].as_array().ok_or_else(|| {
        CliError::Input("Pages artifact manifest omitted its admitted entries".to_owned())
    })? {
        let relative = entry["path"].as_str().ok_or_else(|| {
            CliError::Input("Pages artifact manifest contains an invalid path".to_owned())
        })?;
        let source_path = root.join(relative);
        let destination = staged_root.join(relative);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(|source| CliError::Io {
                path: parent.display().to_string(),
                source,
            })?;
        }
        let bytes = if relative == "_worker.js" {
            worker_bundle
                .as_ref()
                .map(|(_contract, bytes)| bytes.clone())
                .ok_or_else(|| {
                    CliError::Input("Pages worker entrypoint was not bundled".to_owned())
                })?
        } else {
            fs::read(&source_path).map_err(|source| CliError::Io {
                path: source_path.display().to_string(),
                source,
            })?
        };
        fs::write(&destination, bytes).map_err(|source| CliError::Io {
            path: destination.display().to_string(),
            source,
        })?;
    }
    let staged = manifest(&staged_root)?;
    let expected_transport = &expected["provider_request"]["transport_manifest"];
    if staged["asset_count"] != expected_transport["asset_count"]
        || staged["entry_count"] != expected_transport["entry_count"]
        || staged["content_hash"] != expected_transport["content_hash"]
        || staged["entries"] != expected_transport["entries"]
    {
        return Err(CliError::Input(
            "Pages staged transport differs from the planned content-addressed payload; the provider boundary was not crossed"
                .to_owned(),
        ));
    }
    input.query["argument"] = json!(staged_root);
    Ok(stage)
}

pub(super) fn validate_staged_artifact(
    adapter_targets: &Value,
    input: &CallInput,
) -> Result<(), CliError> {
    let expected = target(adapter_targets)
        .and_then(|value| value.pointer("/provider_request/transport_manifest"))
        .ok_or_else(|| {
            CliError::Input(
                "Pages direct-upload plan omitted its staged transport manifest; create a new plan"
                    .to_owned(),
            )
        })?;
    let raw = input
        .query
        .get("argument")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input("Pages direct upload omitted its private staged directory".to_owned())
        })?;
    let root = fs::canonicalize(raw).map_err(|source| CliError::Io {
        path: raw.to_owned(),
        source,
    })?;
    let metadata = fs::symlink_metadata(&root).map_err(|source| CliError::Io {
        path: root.display().to_string(),
        source,
    })?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(CliError::Input(
            "Pages private staged artifact is not one regular directory".to_owned(),
        ));
    }
    let staged = manifest(&root)?;
    if staged["asset_count"] != expected["asset_count"]
        || staged["entry_count"] != expected["entry_count"]
        || staged["content_hash"] != expected["content_hash"]
        || staged["entries"] != expected["entries"]
    {
        return Err(CliError::Input(
            "Pages staged transport drifted at the execution boundary; no provider process was started"
                .to_owned(),
        ));
    }
    Ok(())
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
    let (source_mode, source_mode_basis, corroborating_deployment_id) = if source
        .is_some_and(Value::is_null)
    {
        ("direct_upload", "explicit_null_source", None)
    } else if source
        .and_then(|value| value.get("type"))
        .and_then(Value::as_str)
        .is_some_and(|kind| matches!(kind, "github" | "gitlab"))
        && source
            .and_then(|value| value.get("config"))
            .is_some_and(Value::is_object)
    {
        ("git_integrated", "explicit_git_source", None)
    } else if source.is_none() {
        let deployment_id = omitted_source_direct_deployment_id(
            &response.result,
            project_name,
            production_branch,
        )
        .ok_or_else(|| {
            CliError::Input(
                "Pages project admission read omitted its source without exact direct-upload deployment corroboration; the deployment boundary was not crossed"
                    .to_owned(),
            )
        })?;
        (
            "direct_upload",
            "omitted_source_exact_direct_deployment",
            Some(deployment_id),
        )
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
    let mut receipt = json!({
        "schema_version": 1,
        "source_capability_id": PROJECT_READ_CAPABILITY_ID,
        "source_path": PROJECT_DETAIL_PATH,
        "target_capability_id": capability.id,
        "account_id": account_id,
        "project_name": project_name,
        "production_branch": production_branch,
        "source_mode": source_mode,
        "source_mode_basis": source_mode_basis,
    });
    if let Some(deployment_id) = corroborating_deployment_id {
        receipt["corroborating_deployment_id"] = json!(deployment_id);
    }
    Ok(receipt)
}

fn omitted_source_direct_deployment_id<'a>(
    project: &'a Value,
    project_name: &str,
    production_branch: &str,
) -> Option<&'a str> {
    let build = project.get("build_config")?.as_object()?;
    if ["build_command", "root_dir"].iter().any(|field| {
        build.get(*field).is_some_and(|value| {
            !value.is_null() && value.as_str().is_none_or(|value| !value.is_empty())
        })
    }) {
        return None;
    }
    let canonical = project.get("canonical_deployment")?;
    let latest = project.get("latest_deployment")?;
    let canonical_id = direct_deployment_evidence(canonical, project_name, production_branch)?;
    let latest_id = direct_deployment_evidence(latest, project_name, production_branch)?;
    (canonical_id == latest_id).then_some(canonical_id)
}

fn direct_deployment_evidence<'a>(
    deployment: &'a Value,
    project_name: &str,
    production_branch: &str,
) -> Option<&'a str> {
    let id = deployment
        .get("id")?
        .as_str()
        .filter(|id| uuid::Uuid::parse_str(id).is_ok())?;
    if deployment.get("project_name").and_then(Value::as_str) != Some(project_name)
        || deployment.get("environment").and_then(Value::as_str) != Some("production")
        || deployment
            .pointer("/deployment_trigger/type")
            .and_then(Value::as_str)
            != Some("ad_hoc")
        || deployment
            .pointer("/deployment_trigger/metadata/branch")
            .and_then(Value::as_str)
            != Some(production_branch)
        || deployment
            .get("source")
            .is_some_and(|source| !source.is_null())
        || deployment
            .pointer("/latest_stage/name")
            .and_then(Value::as_str)
            != Some("deploy")
        || deployment
            .pointer("/latest_stage/status")
            .and_then(Value::as_str)
            != Some("success")
    {
        return None;
    }
    let stages = deployment.get("stages")?.as_array()?;
    let has_exact_stage = |name: &str, status: &str| {
        let mut matching = stages
            .iter()
            .filter(|stage| stage.get("name").and_then(Value::as_str) == Some(name));
        matching
            .next()
            .is_some_and(|stage| stage.get("status").and_then(Value::as_str) == Some(status))
            && matching.next().is_none()
    };
    (has_exact_stage("clone_repo", "idle")
        && has_exact_stage("build", "idle")
        && has_exact_stage("deploy", "success"))
    .then_some(id)
}

pub(super) fn receipt_source_mode_is_bound(receipt: &Value, expected_mode: &str) -> bool {
    let mode = receipt.get("source_mode").and_then(Value::as_str);
    let basis = receipt.get("source_mode_basis").and_then(Value::as_str);
    let corroborating_id = receipt
        .get("corroborating_deployment_id")
        .and_then(Value::as_str);
    match (mode, basis, corroborating_id) {
        (Some("direct_upload"), Some("explicit_null_source"), None) => {
            expected_mode == "direct_upload"
        }
        (Some("direct_upload"), Some("omitted_source_exact_direct_deployment"), Some(id)) => {
            expected_mode == "direct_upload" && uuid::Uuid::parse_str(id).is_ok()
        }
        (Some("git_integrated"), Some("explicit_git_source"), None) => {
            expected_mode == "git_integrated"
        }
        _ => false,
    }
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
    fn worker_metafile_accepts_only_hash_bound_artifact_inputs() {
        let parent = tempfile::tempdir().expect("worker project");
        let artifact = parent.path().join("dist");
        fs::create_dir(&artifact).expect("artifact root");
        fs::write(
            artifact.join("_worker.js"),
            b"import './worker-support.js'; export default {};",
        )
        .expect("worker");
        fs::write(
            artifact.join("worker-support.js"),
            b"export const ok = true;",
        )
        .expect("support");
        fs::write(artifact.join("index.html"), b"ok").expect("asset");
        let admitted = manifest(&artifact).expect("admitted manifest");
        let local = json!({
            "inputs": {
                "_worker.js": {"bytes": 51, "imports": []},
                "worker-support.js": {"bytes": 23, "imports": []}
            },
            "outputs": {
                "/tmp/bundle.js": {"imports": []}
            }
        });
        let bound = validate_worker_metafile(&artifact, &admitted, &local)
            .expect("closed local worker graph");
        assert_eq!(bound.as_array().expect("inputs").len(), 2);

        let external = parent.path().join("node_modules/some-package");
        fs::create_dir_all(&external).expect("ambient package");
        fs::write(external.join("index.js"), b"export default 'drift';").expect("ambient input");
        let escaped = json!({
            "inputs": {
                "_worker.js": {"bytes": 51, "imports": []},
                "../node_modules/some-package/index.js": {"bytes": 23, "imports": []}
            },
            "outputs": {
                "/tmp/bundle.js": {"imports": []}
            }
        });
        let error = validate_worker_metafile(&artifact, &admitted, &escaped)
            .expect_err("ancestor dependency must fail closed");
        assert!(
            error
                .to_string()
                .contains("outside the admitted artifact root")
        );

        let unresolved = json!({
            "inputs": {"_worker.js": {"bytes": 51, "imports": []}},
            "outputs": {
                "/tmp/bundle.js": {"imports": [{"path":"some-package","external":true}]}
            }
        });
        assert!(validate_worker_metafile(&artifact, &admitted, &unresolved).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn staged_worker_is_the_planned_closed_bundle() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("worker artifact");
        let artifact_root = root.path().join("site");
        fs::create_dir(&artifact_root).expect("artifact root");
        fs::write(
            artifact_root.join("_worker.js"),
            b"import './worker-support.js'; export default {};",
        )
        .expect("worker");
        fs::write(
            artifact_root.join("worker-support.js"),
            b"export const ok = true;",
        )
        .expect("support");
        fs::write(artifact_root.join("index.html"), b"ok").expect("asset");
        let artifact_root = artifact_root.canonicalize().expect("canonical artifact");
        let esbuild_root = root.path().join("producer/esbuild");
        fs::create_dir_all(esbuild_root.join("bin")).expect("esbuild bin");
        let esbuild = esbuild_root.join("bin/esbuild");
        fs::write(
            &esbuild,
            r#"#!/bin/sh
for arg in "$@"; do
  case "$arg" in
    --metafile=*) metafile="${arg#--metafile=}" ;;
    --outfile=*) outfile="${arg#--outfile=}" ;;
  esac
done
printf 'closed-worker-bundle' > "$outfile"
printf '%s' '{"inputs":{"_worker.js":{"bytes":51,"imports":[]},"worker-support.js":{"bytes":23,"imports":[]}},"outputs":{"bundle":{"imports":[]}}}' > "$metafile"
"#,
        )
        .expect("fake esbuild");
        let mut permissions = fs::metadata(&esbuild)
            .expect("fake esbuild metadata")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&esbuild, permissions).expect("fake esbuild mode");
        let artifact = manifest(&artifact_root).expect("artifact manifest");
        let producer = json!({
            "interpreter": {"path":"/bin/sh"},
            "execution_closure": {"roots":[{"component":"esbuild","root":esbuild_root}]}
        });
        let (bundle, _bytes) = build_worker_bundle(&artifact_root, &artifact, &producer)
            .expect("worker build")
            .expect("worker bundle");
        let expected_transport = transport_manifest(&artifact, Some(&bundle)).expect("transport");
        let targets = json!({
            "pages_deployment": {
                "artifact": artifact,
                "provider_request": {
                    "producer": producer,
                    "worker_bundle": bundle,
                    "transport_manifest": expected_transport
                }
            }
        });
        let mut input = CallInput {
            query: json!({"argument":artifact_root}),
            ..CallInput::default()
        };
        let stage = stage_bound_artifact(&targets, &mut input).expect("staged artifact");
        let staged = input.query["argument"].as_str().expect("staged path");
        assert!(Path::new(staged).starts_with(stage.path()));
        assert_eq!(
            fs::read(Path::new(staged).join("_worker.js")).expect("staged worker"),
            b"closed-worker-bundle"
        );
        assert_eq!(
            fs::read(Path::new(staged).join("worker-support.js")).expect("staged support"),
            b"export const ok = true;"
        );
        assert_staged_transport_drift_rejected(&targets, &input, Path::new(staged));

        fs::write(
            &esbuild,
            r#"#!/bin/sh
for arg in "$@"; do
  case "$arg" in
    --metafile=*) metafile="${arg#--metafile=}" ;;
    --outfile=*) outfile="${arg#--outfile=}" ;;
  esac
done
printf 'var p="./worker-support.js"; export default {fetch(){return import(p)}}' > "$outfile"
printf '%s' '{"inputs":{"_worker.js":{"bytes":51,"imports":[]}},"outputs":{"bundle":{"imports":[]}}}' > "$metafile"
"#,
        )
        .expect("dynamic-import esbuild");
        assert!(
            build_worker_bundle(&artifact_root, &artifact, &producer)
                .expect_err("metafile omission cannot admit a runtime import")
                .to_string()
                .contains("runtime dynamic import")
        );
    }

    fn assert_staged_transport_drift_rejected(targets: &Value, input: &CallInput, staged: &Path) {
        validate_staged_artifact(targets, input).expect("exact staged transport");
        fs::write(staged.join("index.html"), b"drifted").expect("drift staged asset");
        let error = validate_staged_artifact(targets, input)
            .expect_err("staged drift must fail before the provider process");
        assert!(
            error
                .to_string()
                .contains("no provider process was started")
        );
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
        let direct_receipt =
            apply_project_response(&direct_upload(), "acct", "aos-web", Some("main"), &response)
                .expect("explicit null remains direct upload");
        assert_eq!(direct_receipt["source_mode_basis"], "explicit_null_source");
        assert!(receipt_source_mode_is_bound(
            &direct_receipt,
            "direct_upload"
        ));
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
        let git_receipt = apply_project_response(&bodyless, "acct", "aos-web", None, &git_project)
            .expect("populated Git source remains Git integrated");
        assert_eq!(git_receipt["source_mode_basis"], "explicit_git_source");
        assert!(receipt_source_mode_is_bound(&git_receipt, "git_integrated"));
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

    fn omitted_source_project(canonical: Value, latest: Value) -> CloudflareResponseV1 {
        CloudflareResponseV1 {
            status: 200,
            success: true,
            result: json!({
                "name":"aos-web",
                "production_branch":"main",
                "build_config":{
                    "build_command":null,
                    "destination_dir":"target/site",
                    "root_dir":null
                },
                "canonical_deployment":canonical,
                "latest_deployment":latest
            }),
            errors: Vec::new(),
            result_info: None,
            etag: None,
            cf_ray: None,
        }
    }

    fn direct_deployment(id: &str) -> Value {
        json!({
            "id":id,
            "project_name":"aos-web",
            "environment":"production",
            "deployment_trigger":{
                "type":"ad_hoc",
                "metadata":{
                    "branch":"main",
                    "commit_hash":"0a2c0165ab176f744539be371314dea086b80933"
                }
            },
            "latest_stage":{"name":"deploy","status":"success"},
            "stages":[
                {"name":"queued","status":"success"},
                {"name":"initialize","status":"success"},
                {"name":"clone_repo","status":"idle"},
                {"name":"build","status":"idle"},
                {"name":"deploy","status":"success"}
            ],
            "url":"https://ff88ab4a.aos-web-183.pages.dev"
        })
    }

    #[test]
    fn omitted_project_source_requires_consistent_direct_deployment_evidence() {
        let id = "ff88ab4a-f284-4f06-86e0-c8ae3b459b60";
        let exact = omitted_source_project(direct_deployment(id), direct_deployment(id));
        let receipt =
            apply_project_response(&direct_upload(), "acct", "aos-web", Some("main"), &exact)
                .expect(
                    "omitted project source is compatible only with exact direct-upload evidence",
                );
        assert_eq!(receipt["source_mode"], "direct_upload");
        assert_eq!(
            receipt["source_mode_basis"],
            "omitted_source_exact_direct_deployment"
        );
        assert_eq!(receipt["corroborating_deployment_id"], id);
        assert!(receipt_source_mode_is_bound(&receipt, "direct_upload"));
        let mut unbound = receipt.clone();
        unbound["corroborating_deployment_id"] = json!("not-a-uuid");
        assert!(!receipt_source_mode_is_bound(&unbound, "direct_upload"));

        let only_one = omitted_source_project(direct_deployment(id), Value::Null);
        assert!(
            apply_project_response(&direct_upload(), "acct", "aos-web", Some("main"), &only_one)
                .is_err(),
            "one deployment projection cannot authorize an omitted project source"
        );

        let different = omitted_source_project(
            direct_deployment(id),
            direct_deployment("22222222-2222-4222-8222-222222222222"),
        );
        assert!(
            apply_project_response(
                &direct_upload(),
                "acct",
                "aos-web",
                Some("main"),
                &different
            )
            .is_err(),
            "different canonical/latest identities remain ambiguous"
        );

        let mut manual_git_upload = direct_deployment(id);
        manual_git_upload["source"] = json!({
            "type":"github",
            "config":{
                "owner":"MLNavigator",
                "repo_name":"aos-web",
                "repo_id":"123456789",
                "production_branch":"main",
                "production_deployments_enabled":false,
                "preview_deployment_setting":"none"
            }
        });
        let git_evidence = omitted_source_project(manual_git_upload.clone(), manual_git_upload);
        assert!(
            apply_project_response(
                &direct_upload(),
                "acct",
                "aos-web",
                Some("main"),
                &git_evidence
            )
            .is_err(),
            "a manual Wrangler deployment to a Git project remains Git-integrated"
        );

        let mut clone_stage = direct_deployment(id);
        clone_stage["stages"] = json!([
            {"name":"clone_repo","status":"success"},
            {"name":"deploy","status":"success"}
        ]);
        let git_pipeline = omitted_source_project(clone_stage.clone(), clone_stage);
        assert!(
            apply_project_response(
                &direct_upload(),
                "acct",
                "aos-web",
                Some("main"),
                &git_pipeline
            )
            .is_err(),
            "a repository pipeline cannot be normalized as direct upload"
        );

        let mut repository_build = exact.result.clone();
        repository_build["build_config"]["build_command"] = json!("npm run build");
        let repository_build = CloudflareResponseV1 {
            result: repository_build,
            ..exact
        };
        assert!(
            apply_project_response(
                &direct_upload(),
                "acct",
                "aos-web",
                Some("main"),
                &repository_build
            )
            .is_err(),
            "a configured repository build cannot be normalized as direct upload"
        );
    }

    #[test]
    fn omitted_project_source_rejects_partial_or_duplicate_stage_evidence() {
        let id = "ff88ab4a-f284-4f06-86e0-c8ae3b459b60";
        for (missing_stage, retained_repository_stage) in
            [("clone_repo", "build"), ("build", "clone_repo")]
        {
            let mut partial_stages = direct_deployment(id);
            partial_stages["stages"] = json!([
                {"name":"queued","status":"active"},
                {"name":"initialize","status":"idle"},
                {"name":retained_repository_stage,"status":"idle"},
                {"name":"deploy","status":"success"}
            ]);
            let partial_evidence = omitted_source_project(partial_stages.clone(), partial_stages);
            assert!(
                apply_project_response(
                    &direct_upload(),
                    "acct",
                    "aos-web",
                    Some("main"),
                    &partial_evidence
                )
                .is_err(),
                "missing {missing_stage} stage evidence remains ambiguous"
            );
        }

        let mut duplicate_build = direct_deployment(id);
        duplicate_build["stages"]
            .as_array_mut()
            .expect("stages array")
            .push(json!({"name":"build","status":"idle"}));
        let duplicate_evidence = omitted_source_project(duplicate_build.clone(), duplicate_build);
        assert!(
            apply_project_response(
                &direct_upload(),
                "acct",
                "aos-web",
                Some("main"),
                &duplicate_evidence
            )
            .is_err(),
            "duplicate repository-stage evidence remains ambiguous"
        );
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
    fn producer_identity_rejects_unchanged_launcher_with_drifted_asset_hasher() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("producer root");
        let node_modules = root.path().join("node_modules");
        let package = node_modules.join("wrangler");
        let bin = package.join("bin");
        let distribution = package.join("wrangler-dist");
        fs::create_dir_all(&bin).expect("bin");
        fs::create_dir_all(&distribution).expect("distribution");
        fs::write(
            package.join("package.json"),
            r#"{"name":"wrangler","version":"4.107.0","dependencies":{"blake3-wasm":"2.1.5","esbuild":"0.28.1"}}"#,
        )
        .expect("package metadata");
        let executable = bin.join("wrangler.js");
        fs::write(&executable, "#!/bin/sh\nprintf '4.107.0\\n'\n").expect("launcher");
        let mut permissions = fs::metadata(&executable)
            .expect("launcher metadata")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&executable, permissions).expect("launcher mode");
        fs::write(
            distribution.join("cli.js"),
            "require('blake3-wasm'); require('esbuild')",
        )
        .expect("payload");
        let blake3 = node_modules.join("blake3-wasm");
        fs::create_dir_all(blake3.join("dist")).expect("hasher package");
        fs::write(
            blake3.join("package.json"),
            r#"{"name":"blake3-wasm","version":"2.1.5"}"#,
        )
        .expect("hasher metadata");
        let hasher = blake3.join("dist/index.js");
        fs::write(&hasher, "hash-v1").expect("asset hasher");
        let esbuild = node_modules.join("esbuild");
        fs::create_dir_all(esbuild.join("lib")).expect("esbuild package");
        fs::write(
            esbuild.join("package.json"),
            r#"{"name":"esbuild","version":"0.28.1","optionalDependencies":{"@esbuild/darwin-arm64":"0.28.1"}}"#,
        )
        .expect("esbuild metadata");
        fs::write(esbuild.join("lib/main.js"), "builder-v1").expect("esbuild runtime");
        let platform = node_modules.join("@esbuild/darwin-arm64");
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
        let targets = json!({
            "pages_deployment": {
                "provider_request": {"producer": planned.clone()}
            }
        });
        validate_bound_producer_at(&capability, &targets, &executable)
            .expect("unchanged producer at execution boundary");
        let components = planned["execution_closure"]["files"]
            .as_array()
            .expect("closure files")
            .iter()
            .filter_map(|file| file.get("component").and_then(Value::as_str))
            .collect::<BTreeSet<_>>();
        assert!(components.contains("wrangler"));
        assert!(components.contains("blake3-wasm"));
        assert!(components.contains("esbuild"));
        assert!(components.contains("@esbuild/darwin-arm64"));
        fs::write(&hasher, "hash-v2").expect("drifted asset hasher");
        let boundary_error = validate_bound_producer_at(&capability, &targets, &executable)
            .expect_err("post-admission producer drift must stop before subprocess creation");
        assert!(
            boundary_error
                .to_string()
                .contains("no provider process was started")
        );
        let current = wrangler_producer_at(&capability, &executable).expect("current producer");

        assert_ne!(
            planned, current,
            "the bound producer must change when an unmodified Wrangler package delegates Pages asset hashing to drifted external bytes"
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
