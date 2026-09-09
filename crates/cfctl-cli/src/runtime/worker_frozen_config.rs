//! Closed Wrangler config projection; application configuration is never edited.
use std::path::{Component, Path, PathBuf};

use cfctl_core::worker_frozen_upload::FrozenArtifactManifestV1;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::{
    CliError,
    worker_frozen_files::{failure, open_absolute, relative_path},
};

pub(super) struct Projection {
    pub bytes: Vec<u8>,
    pub sha256: String,
    pub main: String,
    pub module_root: String,
    pub custom_build_suppressed: bool,
}

// This is the admission boundary for configuration consumed in an isolated
// directory. New local-file mechanisms must be modelled here before admission.
const FIELDS: &[&str] = &[
    "$schema",
    "name",
    "account_id",
    "main",
    "compatibility_date",
    "compatibility_flags",
    "workers_dev",
    "preview_urls",
    "routes",
    "route",
    "vars",
    "assets",
    "triggers",
    "d1_databases",
    "r2_buckets",
    "kv_namespaces",
    "services",
    "durable_objects",
    "migrations",
    "queues",
    "analytics_engine_datasets",
    "dispatch_namespaces",
    "hyperdrive",
    "mtls_certificates",
    "browser",
    "ai",
    "images",
    "send_email",
    "vectorize",
    "pipelines",
    "version_metadata",
    "secrets_store_secrets",
    "observability",
    "placement",
    "tail_consumers",
    "limits",
    "logfwdr",
    "usage_model",
    "rules",
    "find_additional_modules",
    "base_dir",
    "build",
    "no_bundle",
    "minify",
    "keep_names",
    "upload_source_maps",
    "text_blobs",
    "data_blobs",
    "wasm_modules",
];

fn resolve(
    repository: &Path,
    config: &Path,
    raw: &str,
    directory: bool,
) -> Result<String, CliError> {
    let parent = config
        .parent()
        .ok_or_else(|| failure("config has no parent"))?;
    let path = if Path::new(raw).is_absolute() {
        PathBuf::from(raw)
    } else {
        parent.join(raw)
    };
    let mut normalized = PathBuf::new();
    for part in path.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(failure("config file reference escaped root"));
                }
            }
            _ => normalized.push(part.as_os_str()),
        }
    }
    // Preserve the meaning of the original spelling; lexical normalization may
    // not erase a symlink/.. traversal and silently select another input.
    let canonical = std::fs::canonicalize(&path)
        .map_err(|_| failure("config file reference is unavailable"))?;
    if canonical != normalized {
        return Err(failure("config file reference traverses a symlink"));
    }
    let _bound = open_absolute(&normalized, directory)?;
    relative_path(
        normalized
            .strip_prefix(repository)
            .map_err(|_| failure("config file reference escaped repository"))?,
    )
}

fn admitted_file(manifest: &FrozenArtifactManifestV1, path: &str) -> Result<(), CliError> {
    if !manifest.entries.iter().any(|entry| entry.path == path) {
        return Err(failure(
            "config references a file outside the admitted artifact manifest",
        ));
    }
    Ok(())
}

fn admitted_directory(manifest: &FrozenArtifactManifestV1, path: &str) -> Result<(), CliError> {
    if !manifest.directories.iter().any(|entry| entry == path) {
        return Err(failure(
            "config references a directory outside the admitted artifact manifest",
        ));
    }
    Ok(())
}

fn project_resource_paths(
    repository: &Path,
    config: &Path,
    object: &mut Map<String, Value>,
    manifest: &FrozenArtifactManifestV1,
) -> Result<(), CliError> {
    if let Some(assets) = object.get_mut("assets") {
        let assets = assets
            .as_object_mut()
            .ok_or_else(|| failure("assets must be an object"))?;
        let raw = assets
            .get("directory")
            .and_then(Value::as_str)
            .ok_or_else(|| failure("assets requires a directory"))?;
        let path = resolve(repository, config, raw, true)?;
        admitted_directory(manifest, &path)?;
        assets.insert("directory".to_owned(), Value::String(path));
    }
    for field in ["text_blobs", "data_blobs", "wasm_modules"] {
        if let Some(bindings) = object.get_mut(field) {
            for value in bindings
                .as_object_mut()
                .ok_or_else(|| failure("file bindings must be an object"))?
                .values_mut()
            {
                let raw = value
                    .as_str()
                    .ok_or_else(|| failure("file binding must name one file"))?;
                let path = resolve(repository, config, raw, false)?;
                admitted_file(manifest, &path)?;
                *value = Value::String(path);
            }
        }
    }
    Ok(())
}

pub(super) fn project(
    repository: &Path,
    config: &Path,
    document: &Value,
    manifest: &FrozenArtifactManifestV1,
) -> Result<Projection, CliError> {
    let mut projected = document.clone();
    let object = projected
        .as_object_mut()
        .ok_or_else(|| failure("config must be an object"))?;
    for key in object.keys() {
        if !FIELDS.contains(&key.as_str()) {
            return Err(CliError::Input(format!(
                "frozen Worker upload does not model config field `{key}`; no plan was admitted"
            )));
        }
    }
    let custom_build_suppressed = if let Some(build) = object.get_mut("build") {
        let build = build
            .as_object_mut()
            .ok_or_else(|| failure("build must be an object"))?;
        if build
            .keys()
            .any(|key| !matches!(key.as_str(), "command" | "cwd" | "watch_dir"))
        {
            return Err(failure(
                "legacy build upload configuration requires an explicit frozen contract",
            ));
        }
        build.remove("command").is_some()
    } else {
        false
    };
    let main = object
        .get("main")
        .map(|value| -> Result<String, CliError> {
            let raw = value
                .as_str()
                .ok_or_else(|| failure("main must be one file path"))?;
            let path = resolve(repository, config, raw, false)?;
            admitted_file(manifest, &path)?;
            if !matches!(
                Path::new(&path)
                    .extension()
                    .and_then(|value| value.to_str()),
                Some("js" | "mjs" | "cjs")
            ) {
                return Err(failure(
                    "frozen upload requires already-built JavaScript modules",
                ));
            }
            Ok(path)
        })
        .transpose()?
        .ok_or_else(|| {
            failure("frozen upload requires an explicit already-built Worker main module")
        })?;
    let module_root = {
        let root = if let Some(base) = object.get("base_dir") {
            resolve(
                repository,
                config,
                base.as_str()
                    .ok_or_else(|| failure("base_dir must be a path"))?,
                true,
            )?
        } else {
            relative_path(
                Path::new(&main)
                    .parent()
                    .ok_or_else(|| failure("main has no module directory"))?,
            )?
        };
        admitted_directory(manifest, &root)?;
        if !Path::new(&main).starts_with(&root) {
            return Err(failure("main escaped its module root"));
        }
        object.insert("main".to_owned(), Value::String(main.clone()));
        // Making the previously implicit module root explicit preserves module
        // names even though the private config has a different parent directory.
        object.insert("base_dir".to_owned(), Value::String(root.clone()));
        root
    };
    project_resource_paths(repository, config, object, manifest)?;
    object.insert("no_bundle".to_owned(), Value::Bool(true));
    let bytes = serde_json::to_vec(&projected)?;
    let sha256 = hex::encode(Sha256::digest(&bytes));
    Ok(Projection {
        bytes,
        sha256,
        main,
        module_root,
        custom_build_suppressed,
    })
}
