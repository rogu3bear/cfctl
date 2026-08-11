use std::{
    collections::BTreeSet,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};

use cfctl_cloudflare::{CallInput, CloudflareResponseV1};
use cfctl_core::{CapabilityV1, PlanV1, hash_value, redact_json};
use cfctl_workspace::{WorkspaceGraph, load_wrangler_config};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use super::CliError;

pub(super) const STATE_PRECONDITION: &str = "worker_deployment_state";
pub(super) const SETTINGS_CAPABILITY_ID: &str = "worker-script-get-settings";
pub(super) const SETTINGS_PATH: &str =
    "/accounts/{account_id}/workers/scripts/{script_name}/settings";
const NOT_FOUND_ERROR_CODE: i64 = 10_007;

pub(super) fn binds_artifact(capability: &CapabilityV1) -> bool {
    matches!(
        capability.id.as_str(),
        "wrangler.deploy" | "wrangler.versions-upload"
    )
}

pub(super) fn artifact_paths(
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<Vec<PathBuf>, CliError> {
    if !binds_artifact(capability) {
        return Ok(Vec::new());
    }
    let config = canonical_config(input)?;
    let directory = config.parent().ok_or_else(|| {
        CliError::Input("Wrangler configuration has no containing directory".to_owned())
    })?;
    let document = load_wrangler_config(&config)?;
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
    for root in &roots {
        if !root.starts_with(directory) {
            return Err(CliError::Input(format!(
                "deployment artifact `{}` escapes reviewed config directory `{}`",
                root.display(),
                directory.display()
            )));
        }
    }
    Ok(roots.into_iter().collect())
}

pub(super) fn prepare_target(
    graph: &WorkspaceGraph,
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<Option<Value>, CliError> {
    if !binds_artifact(capability) {
        return Ok(None);
    }
    let config = canonical_config(input)?;
    let document = load_wrangler_config(&config)?;
    let service_name = validated_service_name(&document, input)?;
    let repository = graph
        .repositories
        .iter()
        .filter(|repository| config.starts_with(&repository.path))
        .max_by_key(|repository| repository.path.components().count())
        .ok_or_else(|| {
            CliError::Input(format!(
                "Wrangler configuration `{}` is not owned by a registered repository",
                config.display()
            ))
        })?;
    if repository.git.dirty {
        return Err(CliError::Input(format!(
            "Worker deployment repository `{}` is dirty; commit the reviewed source before planning",
            repository.path.display()
        )));
    }
    let source_sha = repository.git.head.as_deref().ok_or_else(|| {
        CliError::Input(format!(
            "Worker deployment repository `{}` has no readable Git HEAD",
            repository.path.display()
        ))
    })?;
    if !is_full_source_sha(source_sha) {
        return Err(CliError::Input(
            "Worker deployment source identity is not a full lowercase Git SHA".to_owned(),
        ));
    }
    let artifacts = artifact_paths(capability, input)?;
    if artifacts
        .iter()
        .any(|artifact| !artifact.starts_with(&repository.path))
    {
        return Err(CliError::Input(
            "every Worker deployment artifact must be owned by the config repository".to_owned(),
        ));
    }
    let config_directory = config.parent().ok_or_else(|| {
        CliError::Input("Wrangler configuration has no containing directory".to_owned())
    })?;
    let artifact_sha256 = artifact_set_sha256(config_directory, &artifacts)?;
    let config_sha256 = hex::encode(Sha256::digest(fs::read(&config).map_err(|source| {
        CliError::Io {
            path: config.display().to_string(),
            source,
        }
    })?));
    let expected_message = format!("source={source_sha} artifact-sha256={artifact_sha256}");
    let message = input
        .query
        .get("message")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input(format!(
                "Worker deployment requires exact message `{expected_message}`"
            ))
        })?;
    if message != expected_message {
        return Err(CliError::Input(format!(
            "Worker deployment message must be exactly `{expected_message}`"
        )));
    }
    Ok(Some(json!({
        "schema_version": 1,
        "service_name": service_name,
        "source_sha": source_sha,
        "repository": repository.path,
        "config": {
            "path": config,
            "sha256": config_sha256,
        },
        "artifact": {
            "roots": artifacts,
            "sha256": artifact_sha256,
        },
        "version_message": expected_message,
    })))
}

fn validated_service_name<'a>(
    document: &'a Value,
    input: &'a CallInput,
) -> Result<&'a str, CliError> {
    let configured = document.get("name").and_then(Value::as_str);
    let requested = input.query.get("name").and_then(Value::as_str);
    let service_name = requested.or(configured).ok_or_else(|| {
        CliError::Input(
            "Worker deployment requires an exact Worker name in the config or `name` selector"
                .to_owned(),
        )
    })?;
    if service_name.trim().is_empty() {
        return Err(CliError::Input(
            "Worker deployment service name cannot be empty".to_owned(),
        ));
    }
    if let (Some(configured), Some(requested)) = (configured, requested)
        && configured != requested
    {
        return Err(CliError::Input(format!(
            "Worker name selector `{requested}` differs from reviewed config name `{configured}`"
        )));
    }
    Ok(service_name)
}

pub(super) fn target(adapter_targets: &Value) -> Option<&Value> {
    adapter_targets.get("worker_deployment")
}

pub(super) fn service_name(adapter_targets: &Value) -> Result<&str, CliError> {
    target(adapter_targets)
        .and_then(|target| target.get("service_name"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input("Worker deployment plan omitted its exact service identity".to_owned())
        })
}

pub(super) fn apply_state_response(
    account_id: &str,
    service_name: &str,
    response: &CloudflareResponseV1,
) -> Result<Value, CliError> {
    let exact_not_found = response.status == 404
        && !response.success
        && response.result.is_null()
        && response.errors.len() == 1
        && response.errors[0].code == Some(NOT_FOUND_ERROR_CODE);
    if exact_not_found {
        return Ok(json!({
            "schema_version": 1,
            "source_capability_id": SETTINGS_CAPABILITY_ID,
            "source_path": SETTINGS_PATH,
            "account_id": account_id,
            "service_name": service_name,
            "http_status": 404,
            "exists": false,
        }));
    }
    if response.success && (200..300).contains(&response.status) {
        return Ok(json!({
            "schema_version": 1,
            "source_capability_id": SETTINGS_CAPABILITY_ID,
            "source_path": SETTINGS_PATH,
            "account_id": account_id,
            "service_name": service_name,
            "http_status": response.status,
            "exists": true,
            "redacted_state_hash": hash_value(&redact_json(&response.result))?,
        }));
    }
    Err(CliError::Input(format!(
        "Worker settings read for `{service_name}` returned HTTP {} and cannot prove exact current state",
        response.status
    )))
}

pub(super) fn validate_state_receipt(plan: &PlanV1, receipt: &Value) -> Result<(), CliError> {
    let adapter = plan.targets.get("adapter").unwrap_or(&Value::Null);
    let expected_service = service_name(adapter)?;
    let exact = receipt.get("schema_version").and_then(Value::as_u64) == Some(1)
        && receipt.get("source_capability_id").and_then(Value::as_str)
            == Some(SETTINGS_CAPABILITY_ID)
        && receipt.get("source_path").and_then(Value::as_str) == Some(SETTINGS_PATH)
        && receipt.get("account_id").and_then(Value::as_str) == Some(plan.account_id.as_str())
        && receipt.get("service_name").and_then(Value::as_str) == Some(expected_service)
        && receipt.get("exists").and_then(Value::as_bool).is_some();
    if !exact {
        return Err(CliError::Input(
            "Worker deployment live-state receipt is malformed or targets another service"
                .to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn apply_plan_diff(diff: &mut Value, plan: &PlanV1, state: &Value) {
    let adapter = plan.targets.get("adapter").unwrap_or(&Value::Null);
    if let Some(target) = target(adapter) {
        diff["observed_before"] = json!({
            "service_name": state.get("service_name"),
            "exists": state.get("exists"),
            "redacted_state_hash": state.get("redacted_state_hash"),
        });
        diff["planned_after"] = target.clone();
    }
}

fn canonical_config(input: &CallInput) -> Result<PathBuf, CliError> {
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

fn artifact_set_sha256(config_directory: &Path, roots: &[PathBuf]) -> Result<String, CliError> {
    let mut entries = Vec::new();
    for root in roots {
        for entry in WalkDir::new(root).follow_links(false) {
            let entry = entry.map_err(|error| {
                CliError::Input(format!(
                    "failed to inspect Worker deployment artifact `{}`: {error}",
                    root.display()
                ))
            })?;
            if entry.path() == root || entry.file_type().is_dir() {
                continue;
            }
            if !entry.file_type().is_file() {
                return Err(CliError::Input(format!(
                    "Worker deployment artifact contains unsupported non-file entry `{}`",
                    entry.path().display()
                )));
            }
            let relative = entry.path().strip_prefix(config_directory).map_err(|_| {
                CliError::Input(format!(
                    "Worker deployment artifact `{}` escaped config directory `{}`",
                    entry.path().display(),
                    config_directory.display()
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

fn is_full_source_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use cfctl_cloudflare::CloudflareApiErrorV1;
    use cfctl_core::{AdapterStatus, EffectClass, RiskClass};
    use cfctl_workspace::RegisteredRoot;
    use std::process::Command;

    #[test]
    fn artifact_hash_matches_the_repository_shell_contract() {
        let root = tempfile::tempdir().expect("artifact root");
        let build = root.path().join("build");
        let site = root.path().join("target/site");
        fs::create_dir_all(&build).expect("build directory");
        fs::create_dir_all(&site).expect("site directory");
        fs::write(build.join("worker.js"), "worker\n").expect("worker");
        fs::write(site.join("index.html"), "site\n").expect("site");
        let digest = artifact_set_sha256(root.path(), &[build, site]).expect("artifact digest");
        let manifest = format!(
            "{}  build/worker.js\n{}  target/site/index.html\n",
            hex::encode(Sha256::digest(b"worker\n")),
            hex::encode(Sha256::digest(b"site\n"))
        );
        assert_eq!(digest, hex::encode(Sha256::digest(manifest.as_bytes())));
    }

    #[test]
    fn target_binds_clean_source_config_service_and_complete_artifact() {
        let root = tempfile::tempdir().expect("repository root");
        let build = root.path().join("build");
        let site = root.path().join("target/site");
        fs::create_dir_all(&build).expect("build directory");
        fs::create_dir_all(&site).expect("site directory");
        fs::write(build.join("_worker.js"), "worker\n").expect("worker");
        fs::write(build.join("index.wasm"), b"wasm").expect("wasm");
        fs::write(site.join("index.html"), "site\n").expect("site");
        let config = root.path().join("wrangler.toml");
        fs::write(
            &config,
            "name = \"cfctl-site\"\nmain = \"build/_worker.js\"\n[assets]\ndirectory = \"target/site\"\n",
        )
        .expect("config");
        assert!(
            Command::new("git")
                .args(["init", "--quiet", "--initial-branch=main"])
                .current_dir(root.path())
                .status()
                .expect("git init")
                .success()
        );
        assert!(
            Command::new("git")
                .args(["add", "."])
                .current_dir(root.path())
                .status()
                .expect("git add")
                .success()
        );
        assert!(
            Command::new("git")
                .args([
                    "-c",
                    "user.name=cfctl test",
                    "-c",
                    "user.email=cfctl-test@example.invalid",
                    "commit",
                    "--quiet",
                    "-m",
                    "fixture",
                ])
                .current_dir(root.path())
                .status()
                .expect("git commit")
                .success()
        );
        let source_sha = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(root.path())
            .output()
            .expect("git head");
        let source_sha = String::from_utf8(source_sha.stdout)
            .expect("UTF-8 head")
            .trim()
            .to_owned();
        let artifact_sha256 =
            artifact_set_sha256(root.path(), &[build.clone(), site.clone()]).expect("hash");
        let graph =
            WorkspaceGraph::discover(&[RegisteredRoot::new(root.path())]).expect("workspace graph");
        let mut capability =
            CapabilityV1::new("wrangler.deploy", "Deploy Worker", "CLI", "wrangler deploy");
        capability.adapter_status = AdapterStatus::DelegatedCli;
        capability.risk = RiskClass::CrossConfig;
        capability.effect = EffectClass::ReversibleWrite;
        let input = CallInput {
            query: json!({
                "config": config.canonicalize().expect("canonical config"),
                "name": "cfctl-site",
                "message": format!("source={source_sha} artifact-sha256={artifact_sha256}"),
            }),
            ..CallInput::default()
        };
        let projection = prepare_target(&graph, &capability, &input)
            .expect("projection")
            .expect("Worker projection");
        assert_eq!(projection["service_name"], "cfctl-site");
        assert_eq!(projection["source_sha"], source_sha);
        assert_eq!(projection["artifact"]["sha256"], artifact_sha256);
        assert_eq!(
            projection["artifact"]["roots"],
            json!([build.canonicalize().unwrap(), site.canonicalize().unwrap()])
        );

        fs::write(site.join("index.html"), "drift\n").expect("artifact drift");
        let error = prepare_target(&graph, &capability, &input)
            .expect_err("stale artifact identity must fail")
            .to_string();
        assert!(error.contains("message must be exactly"));
    }

    #[test]
    fn live_state_receipts_distinguish_absence_from_redacted_existing_state() {
        let absent = CloudflareResponseV1 {
            status: 404,
            success: false,
            result: Value::Null,
            errors: vec![CloudflareApiErrorV1 {
                code: Some(NOT_FOUND_ERROR_CODE),
                message: "This Worker does not exist on your account.".to_owned(),
            }],
            result_info: None,
            etag: None,
            cf_ray: None,
        };
        let absent = apply_state_response("account-a", "cfctl-site", &absent).expect("absence");
        assert_eq!(absent["exists"], false);
        assert!(absent.get("redacted_state_hash").is_none());

        let ambiguous = CloudflareResponseV1 {
            status: 404,
            success: false,
            result: Value::Null,
            errors: vec![CloudflareApiErrorV1 {
                code: Some(9_999),
                message: "ambiguous not found".to_owned(),
            }],
            result_info: None,
            etag: None,
            cf_ray: None,
        };
        assert!(apply_state_response("account-a", "cfctl-site", &ambiguous).is_err());

        let existing = CloudflareResponseV1 {
            status: 200,
            success: true,
            result: json!({"compatibility_date": "2026-08-05", "secret_text": "hidden"}),
            errors: Vec::new(),
            result_info: None,
            etag: None,
            cf_ray: None,
        };
        let existing =
            apply_state_response("account-a", "cfctl-site", &existing).expect("existing");
        assert_eq!(existing["exists"], true);
        assert!(existing["redacted_state_hash"].as_str().is_some());
        assert!(!existing.to_string().contains("hidden"));
    }
}
