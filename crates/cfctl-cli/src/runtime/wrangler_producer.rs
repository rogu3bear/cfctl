//! Executable, interpreter, and dependency identity shared by the two frozen
//! Wrangler transports. Each caller supplies its exact catalog operation.
use super::CliError;
use cfctl_core::{CapabilityV1, hash_value};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env, fs,
    io::Read as _,
    os::unix::{fs::OpenOptionsExt as _, process::CommandExt as _},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use walkdir::WalkDir;

const MAX_PRODUCER_FILE_COUNT: usize = 10_000;
const MAX_PRODUCER_BYTES: u64 = 512 * 1024 * 1024;
const PROBE_OUTPUT_LIMIT: u64 = 4096;

struct ProbeChild(Child);

impl Drop for ProbeChild {
    fn drop(&mut self) {
        if let Some(pid) = rustix::process::Pid::from_raw(self.0.id().cast_signed()) {
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
        }
        let _ = self.0.wait();
    }
}

fn probe_output(command: &mut Command) -> Result<String, CliError> {
    let failure = || {
        CliError::Input(
            "Wrangler producer discovery did not return one bounded successful receipt".to_owned(),
        )
    };
    let directory = tempfile::Builder::new()
        .prefix("cfctl-producer-probe-")
        .tempdir()
        .map_err(|_| failure())?;
    let path = directory.path().join("stdout");
    let output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|_| failure())?;
    let child = command
        .stdin(Stdio::null())
        .stdout(output)
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(|_| failure())?;
    let mut child = ProbeChild(child);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if fs::metadata(&path).map_err(|_| failure())?.len() > PROBE_OUTPUT_LIMIT {
            return Err(failure());
        }
        match child.0.try_wait().map_err(|_| failure())? {
            Some(status) if status.success() => break,
            None if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Some(_) | None => return Err(failure()),
        }
    }
    let mut bytes = Vec::new();
    fs::File::open(&path)
        .map_err(|_| failure())?
        .take(PROBE_OUTPUT_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| failure())?;
    if bytes.len() as u64 > PROBE_OUTPUT_LIMIT {
        return Err(failure());
    }
    String::from_utf8(bytes).map_err(|_| failure())
}

pub(super) fn resolved_interpreter(raw: &Path) -> Result<PathBuf, CliError> {
    let canonical = fs::canonicalize(raw).map_err(|source| CliError::Io {
        path: raw.display().to_string(),
        source,
    })?;
    if raw.file_name().and_then(|name| name.to_str()) != Some("node")
        || canonical.file_name().and_then(|name| name.to_str()) != Some("mise")
    {
        return Ok(canonical);
    }
    // mise dispatches a node shim by argv[0]. Canonicalizing that shim and
    // executing mise with JavaScript arguments loses the selected runtime.
    // Its documented `which` operation is read-only; do not activate a shim
    // or permit auto-install, config hooks, or network discovery here.
    // https://mise.jdx.dev/cli/which.html
    // https://mise.jdx.dev/configuration/settings.html
    let mut command = Command::new(&canonical);
    command
        .args(["which", "node"])
        .env_clear()
        .env("PATH", env::var_os("PATH").unwrap_or_default())
        .env("HOME", env::var_os("HOME").unwrap_or_default())
        .env("MISE_AUTO_INSTALL", "false")
        .env("MISE_EXEC_AUTO_INSTALL", "false")
        .env("MISE_NOT_FOUND_AUTO_INSTALL", "false")
        .env("MISE_NOT_FOUND_SYSTEM_FALLBACK", "false")
        .env("MISE_AUTO_UPDATE", "false")
        .env("MISE_OFFLINE", "true")
        .env("MISE_NO_HOOKS", "true")
        .env("MISE_NO_ENV", "true");
    let output = probe_output(&mut command)?;
    let value = output.trim();
    if value.is_empty() || value.chars().any(char::is_control) || !Path::new(value).is_absolute() {
        return Err(CliError::Input(
            "Wrangler Node discovery did not identify one installed runtime".to_owned(),
        ));
    }
    let path = fs::canonicalize(value)
        .map_err(|_| CliError::Input("Wrangler Node runtime is not installed".to_owned()))?;
    if path == canonical || !path.is_file() {
        return Err(CliError::Input(
            "Wrangler Node discovery did not resolve its interpreter".to_owned(),
        ));
    }
    Ok(path)
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
    let path = resolved_interpreter(&raw)?;
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

pub(super) fn snapshot_at(
    capability: &CapabilityV1,
    discovered: &Path,
    operation: &str,
) -> Result<Value, CliError> {
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
    version_command
        .arg("--version")
        .current_dir(isolated_home.path())
        .env_clear()
        .env("PATH", env::var_os("PATH").unwrap_or_default())
        .env("HOME", isolated_home.path())
        .env("NO_COLOR", "1")
        .env("WRANGLER_SEND_METRICS", "false");
    let version = probe_output(&mut version_command)?.trim().to_owned();
    if version.is_empty() || capability.source != format!("wrangler {version} {operation} help") {
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

pub(super) fn component_root(producer: &Value, component: &str) -> Result<PathBuf, CliError> {
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
                "Wrangler artifact transport requires `{component}` in the bound Wrangler dependency graph"
            ))
        })
}
