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
pub(super) const DEPLOYMENTS_CAPABILITY_ID: &str = "worker-deployments-list-deployments";
pub(super) const DEPLOYMENTS_PATH: &str =
    "/accounts/{account_id}/workers/scripts/{script_name}/deployments";
const NOT_FOUND_ERROR_CODE: i64 = 10_007;

pub(super) fn binds_artifact(capability: &CapabilityV1) -> bool {
    matches!(
        capability.id.as_str(),
        "wrangler.deploy" | "wrangler.versions-upload"
    )
}

pub(super) fn binds_live_state(capability: &CapabilityV1) -> bool {
    binds_artifact(capability) || capability.id == "wrangler.versions-deploy"
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
    Ok(roots.into_iter().collect())
}

#[expect(
    clippy::too_many_lines,
    reason = "one fail-closed projection binds repository, config, artifact or promotion, and release-message identity"
)]
pub(super) fn prepare_target(
    graph: &WorkspaceGraph,
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<Option<Value>, CliError> {
    if !binds_live_state(capability) {
        return Ok(None);
    }
    let config = canonical_config(input)?;
    let document = load_wrangler_config(&config)?;
    let service_name = validated_service_name(&document, input)?;
    let repository = repository_owning_path(graph, &config).ok_or_else(|| {
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
    let config_sha256 = hex::encode(Sha256::digest(fs::read(&config).map_err(|source| {
        CliError::Io {
            path: config.display().to_string(),
            source,
        }
    })?));
    let (expected_message, operation) = if binds_artifact(capability) {
        let artifacts = artifact_paths(capability, input)?;
        if artifacts.iter().any(|artifact| {
            repository_owning_path(graph, artifact)
                .is_none_or(|owner| owner.path != repository.path)
        }) {
            return Err(CliError::Input(
                "every Worker deployment artifact must be owned by the config repository"
                    .to_owned(),
            ));
        }
        validate_artifact_tree_ownership(graph, &repository.path, &artifacts)?;
        let artifact_sha256 = artifact_set_sha256(&repository.path, &artifacts)?;
        (
            format!("source={source_sha} artifact-sha256={artifact_sha256}"),
            json!({
                "artifact": {
                    "roots": artifacts,
                    "sha256": artifact_sha256,
                },
            }),
        )
    } else {
        let version_id = versions_deploy_version_id(input)?;
        (
            format!("promote release {source_sha}"),
            json!({
                "promotion": {
                    "version_id": version_id,
                    "traffic_percentage": 100,
                },
            }),
        )
    };
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
    let mut target = json!({
        "schema_version": 1,
        "service_name": service_name,
        "source_sha": source_sha,
        "repository": repository.path,
        "config": {
            "path": config,
            "sha256": config_sha256,
        },
        "version_message": expected_message,
    });
    let target_object = target
        .as_object_mut()
        .ok_or_else(|| CliError::Input("Worker deployment target is not an object".to_owned()))?;
    let operation_object = operation.as_object().ok_or_else(|| {
        CliError::Input("Worker deployment operation is not an object".to_owned())
    })?;
    target_object.extend(operation_object.clone());
    Ok(Some(target))
}

fn versions_deploy_version_id(input: &CallInput) -> Result<&str, CliError> {
    let spec = input
        .query
        .get("argument")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "Worker Versions deployment requires exactly one UUID@100 target".to_owned(),
            )
        })?;
    let (version_id, percentage) = spec.split_once('@').ok_or_else(|| {
        CliError::Input("Worker Versions deployment target must be UUID@100".to_owned())
    })?;
    if percentage != "100"
        || uuid::Uuid::parse_str(version_id).is_err()
        || spec.matches('@').count() != 1
    {
        return Err(CliError::Input(
            "Worker Versions deployment target must be exactly one UUID@100 value".to_owned(),
        ));
    }
    Ok(version_id)
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

pub(super) fn validate_current_target(
    graph: &WorkspaceGraph,
    capability: &CapabilityV1,
    input: &CallInput,
    adapter_targets: &Value,
) -> Result<(), CliError> {
    let planned = target(adapter_targets);
    if !binds_live_state(capability) {
        if planned.is_some() {
            return Err(CliError::Input(
                "Worker deployment target is attached to an unrelated capability".to_owned(),
            ));
        }
        return Ok(());
    }
    let planned = planned.ok_or_else(|| {
        CliError::Input(
            "Worker deployment plan omitted its exact local source target; create a new plan"
                .to_owned(),
        )
    })?;
    let current = prepare_target(graph, capability, input)?.ok_or_else(|| {
        CliError::Input(
            "Worker deployment local source target could not be recomputed; create a new plan"
                .to_owned(),
        )
    })?;
    if &current != planned {
        return Err(CliError::Input(
            "Worker deployment config, source, service, or operation drifted after planning; the delegated boundary was not crossed and a new plan is required"
                .to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn delegated_execution_input(
    capability: &CapabilityV1,
    input: &CallInput,
    adapter_targets: &Value,
) -> Result<CallInput, CliError> {
    if capability.id != "wrangler.versions-deploy" {
        return Ok(input.clone());
    }
    let mut execution = input.clone();
    let query = execution.query.as_object_mut().ok_or_else(|| {
        CliError::Input("Worker promotion query is not an exact object".to_owned())
    })?;
    query.remove("config");
    query.insert(
        "name".to_owned(),
        Value::String(service_name(adapter_targets)?.to_owned()),
    );
    Ok(execution)
}

pub(super) fn requires_configless_working_directory(
    capability: &CapabilityV1,
    input: &CallInput,
) -> bool {
    capability.id == "wrangler.versions-deploy"
        && input.query.get("config").is_none()
        && input.query.get("name").and_then(Value::as_str).is_some()
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

pub(super) fn apply_state_responses(
    account_id: &str,
    service_name: &str,
    settings: &CloudflareResponseV1,
    deployments: Option<&CloudflareResponseV1>,
) -> Result<Value, CliError> {
    let exact_not_found = settings.status == 404
        && !settings.success
        && settings.result.is_null()
        && settings.errors.len() == 1
        && settings.errors[0].code == Some(NOT_FOUND_ERROR_CODE);
    if exact_not_found {
        if deployments.is_some() {
            return Err(CliError::Input(
                "absent Worker state must not carry a deployments response".to_owned(),
            ));
        }
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
    let Some(deployments) = deployments else {
        return Err(CliError::Input(
            "existing Worker state requires its exact deployments read".to_owned(),
        ));
    };
    if settings.success
        && (200..300).contains(&settings.status)
        && deployments.success
        && (200..300).contains(&deployments.status)
    {
        return Ok(json!({
            "schema_version": 1,
            "source_capability_id": SETTINGS_CAPABILITY_ID,
            "source_path": SETTINGS_PATH,
            "deployment_source_capability_id": DEPLOYMENTS_CAPABILITY_ID,
            "deployment_source_path": DEPLOYMENTS_PATH,
            "account_id": account_id,
            "service_name": service_name,
            "http_status": settings.status,
            "deployment_http_status": deployments.status,
            "exists": true,
            "redacted_settings_hash": hash_value(&redact_json(&settings.result))?,
            "redacted_deployments_hash": hash_value(&redact_json(&deployments.result))?,
        }));
    }
    Err(CliError::Input(format!(
        "Worker settings/deployments reads for `{service_name}` returned HTTP {}/{} and cannot prove exact current state",
        settings.status, deployments.status
    )))
}

pub(super) fn validate_state_receipt(plan: &PlanV1, receipt: &Value) -> Result<(), CliError> {
    let adapter = plan.targets.get("adapter").unwrap_or(&Value::Null);
    let expected_service = service_name(adapter)?;
    let exists = receipt.get("exists").and_then(Value::as_bool);
    let exact_field_count = match exists {
        Some(false) => 7,
        Some(true) => 12,
        None => 0,
    };
    let exact = receipt
        .as_object()
        .is_some_and(|object| object.len() == exact_field_count)
        && receipt.get("schema_version").and_then(Value::as_u64) == Some(1)
        && receipt.get("source_capability_id").and_then(Value::as_str)
            == Some(SETTINGS_CAPABILITY_ID)
        && receipt.get("source_path").and_then(Value::as_str) == Some(SETTINGS_PATH)
        && receipt.get("account_id").and_then(Value::as_str) == Some(plan.account_id.as_str())
        && receipt.get("service_name").and_then(Value::as_str) == Some(expected_service)
        && exists.is_some();
    let existing_state_is_exact = exists != Some(true)
        || (receipt
            .get("deployment_source_capability_id")
            .and_then(Value::as_str)
            == Some(DEPLOYMENTS_CAPABILITY_ID)
            && receipt
                .get("deployment_source_path")
                .and_then(Value::as_str)
                == Some(DEPLOYMENTS_PATH)
            && receipt
                .get("redacted_settings_hash")
                .and_then(Value::as_str)
                .is_some()
            && receipt
                .get("redacted_deployments_hash")
                .and_then(Value::as_str)
                .is_some());
    if !exact || !existing_state_is_exact {
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
            "redacted_settings_hash": state.get("redacted_settings_hash"),
            "redacted_deployments_hash": state.get("redacted_deployments_hash"),
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

fn repository_owning_path<'a>(
    graph: &'a WorkspaceGraph,
    path: &Path,
) -> Option<&'a cfctl_workspace::RepositoryNode> {
    graph
        .repositories
        .iter()
        .filter(|repository| path.starts_with(&repository.path))
        .max_by_key(|repository| repository.path.components().count())
}

fn validate_artifact_tree_ownership(
    graph: &WorkspaceGraph,
    repository: &Path,
    roots: &[PathBuf],
) -> Result<(), CliError> {
    for root in roots {
        for entry in WalkDir::new(root).follow_links(false) {
            let entry = entry.map_err(|error| {
                CliError::Input(format!(
                    "failed to inspect Worker deployment artifact `{}`: {error}",
                    root.display()
                ))
            })?;
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

fn artifact_set_sha256(repository: &Path, roots: &[PathBuf]) -> Result<String, CliError> {
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
    use cfctl_core::{AdapterStatus, EffectClass, PlanStatus, RiskClass};
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
    #[expect(
        clippy::too_many_lines,
        reason = "one executable repository fixture proves upload and promotion projections share exact source authority"
    )]
    fn target_binds_clean_source_config_service_and_complete_artifact() {
        let root = tempfile::tempdir().expect("repository root");
        let worker = root.path().join("cloudflare/site");
        let build = worker.join("build");
        let site = root.path().join("target/site");
        fs::create_dir_all(&build).expect("build directory");
        fs::create_dir_all(&site).expect("site directory");
        fs::write(build.join("_worker.js"), "worker\n").expect("worker");
        fs::write(build.join("index.wasm"), b"wasm").expect("wasm");
        fs::write(site.join("index.html"), "site\n").expect("site");
        let config = worker.join("wrangler.toml");
        fs::write(
            &config,
            "name = \"cfctl-site\"\nmain = \"build/_worker.js\"\n[assets]\ndirectory = \"../../target/site\"\n",
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
        capability.mutating = true;
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

        let version_id = "11111111-2222-4333-8444-555555555555";
        let mut promotion = capability.clone();
        promotion.id = "wrangler.versions-deploy".to_owned();
        let promotion_input = CallInput {
            query: json!({
                "argument": format!("{version_id}@100"),
                "config": config.canonicalize().expect("canonical config"),
                "message": format!("promote release {source_sha}"),
            }),
            ..CallInput::default()
        };
        let promotion_projection = prepare_target(&graph, &promotion, &promotion_input)
            .expect("promotion projection")
            .expect("Worker promotion projection");
        assert_eq!(promotion_projection["service_name"], "cfctl-site");
        assert_eq!(promotion_projection["source_sha"], source_sha);
        assert_eq!(promotion_projection["promotion"]["version_id"], version_id);
        assert_eq!(promotion_projection["promotion"]["traffic_percentage"], 100);
        assert!(promotion_projection.get("artifact").is_none());
        assert!(binds_live_state(&promotion));

        let adapter_targets = json!({"worker_deployment": promotion_projection});
        validate_current_target(&graph, &promotion, &promotion_input, &adapter_targets)
            .expect("unchanged promotion target remains executable");
        let mut promotion_plan = PlanV1::draft(
            "profile-a",
            "account-a",
            "catalog-sha",
            promotion.clone(),
            json!({"adapter": adapter_targets}),
        )
        .expect("promotion plan");
        promotion_plan.approve(true, None).expect("approve plan");
        let configless_input = delegated_execution_input(
            &promotion,
            &promotion_input,
            promotion_plan
                .targets
                .get("adapter")
                .expect("adapter targets"),
        )
        .expect("derive immutable promotion boundary");
        assert!(configless_input.query.get("config").is_none());
        assert_eq!(configless_input.query["name"], "cfctl-site");
        assert!(requires_configless_working_directory(
            &promotion,
            &configless_input
        ));
        fs::write(
            &config,
            "name = \"retargeted-service\"\nmain = \"build/_worker.js\"\n[assets]\ndirectory = \"../../target/site\"\n",
        )
        .expect("retarget config after approval");
        let mut delegated_boundary_crossed = false;
        let result = validate_current_target(
            &graph,
            &promotion,
            &promotion_input,
            promotion_plan
                .targets
                .get("adapter")
                .expect("adapter targets"),
        );
        if result.is_ok() {
            promotion_plan.mark_consumed().expect("consume plan");
            delegated_boundary_crossed = true;
        }
        assert!(result.is_err());
        assert!(!delegated_boundary_crossed);
        assert_eq!(promotion_plan.status, PlanStatus::Approved);
        assert_eq!(configless_input.query["name"], "cfctl-site");
        assert!(configless_input.query.get("config").is_none());
        fs::write(
            &config,
            "name = \"cfctl-site\"\nmain = \"build/_worker.js\"\n[assets]\ndirectory = \"../../target/site\"\n",
        )
        .expect("restore config for artifact drift proof");

        fs::write(site.join("index.html"), "drift\n").expect("artifact drift");
        let error = prepare_target(&graph, &capability, &input)
            .expect_err("stale artifact identity must fail")
            .to_string();
        assert!(error.contains("message must be exactly"));
    }

    #[test]
    fn target_rejects_artifact_that_canonicalizes_outside_registered_repository() {
        let root = tempfile::tempdir().expect("repository root");
        let outside = tempfile::tempdir().expect("outside artifact root");
        let worker = root.path().join("cloudflare/site");
        let build = worker.join("build");
        fs::create_dir_all(&build).expect("build directory");
        fs::write(build.join("_worker.js"), "worker\n").expect("worker");
        fs::write(outside.path().join("index.html"), "outside\n").expect("outside artifact");
        let config = worker.join("wrangler.toml");
        fs::write(
            &config,
            format!(
                "name = \"cfctl-site\"\nmain = \"build/_worker.js\"\n[assets]\ndirectory = {:?}\n",
                outside.path()
            ),
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
        let graph =
            WorkspaceGraph::discover(&[RegisteredRoot::new(root.path())]).expect("workspace graph");
        let mut capability =
            CapabilityV1::new("wrangler.deploy", "Deploy Worker", "CLI", "wrangler deploy");
        capability.mutating = true;
        capability.adapter_status = AdapterStatus::DelegatedCli;
        capability.risk = RiskClass::CrossConfig;
        capability.effect = EffectClass::ReversibleWrite;
        let input = CallInput {
            query: json!({
                "config": config.canonicalize().expect("canonical config"),
                "name": "cfctl-site",
                "message": "untrusted",
            }),
            ..CallInput::default()
        };
        let error = prepare_target(&graph, &capability, &input)
            .expect_err("outside artifact must fail before planning")
            .to_string();
        assert!(error.contains("must be owned by the config repository"));
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "two independently committed repository fixtures prove deepest-owner rejection"
    )]
    fn target_rejects_artifact_tree_containing_nested_registered_repository() {
        let root = tempfile::tempdir().expect("repository root");
        let worker = root.path().join("cloudflare/site");
        let build = worker.join("build");
        let shared = root.path().join("shared");
        let nested = shared.join("child-repo");
        let nested_dist = nested.join("dist");
        fs::create_dir_all(&build).expect("build directory");
        fs::create_dir_all(&nested_dist).expect("nested artifact directory");
        fs::write(build.join("_worker.js"), "worker\n").expect("worker");
        fs::write(shared.join("outer.txt"), "outer\n").expect("outer artifact");
        fs::write(nested_dist.join("index.html"), "nested\n").expect("nested artifact");
        assert!(
            Command::new("git")
                .args(["init", "--quiet", "--initial-branch=main"])
                .current_dir(&nested)
                .status()
                .expect("nested git init")
                .success()
        );
        assert!(
            Command::new("git")
                .args(["add", "."])
                .current_dir(&nested)
                .status()
                .expect("nested git add")
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
                    "nested fixture",
                ])
                .current_dir(&nested)
                .status()
                .expect("nested git commit")
                .success()
        );
        let config = worker.join("wrangler.toml");
        fs::write(
            &config,
            "name = \"cfctl-site\"\nmain = \"build/_worker.js\"\n[assets]\ndirectory = \"../../shared\"\n",
        )
        .expect("config");
        assert!(
            Command::new("git")
                .args(["init", "--quiet", "--initial-branch=main"])
                .current_dir(root.path())
                .status()
                .expect("outer git init")
                .success()
        );
        assert!(
            Command::new("git")
                .args(["add", "."])
                .current_dir(root.path())
                .status()
                .expect("outer git add")
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
                    "outer fixture",
                ])
                .current_dir(root.path())
                .status()
                .expect("outer git commit")
                .success()
        );
        let graph =
            WorkspaceGraph::discover(&[RegisteredRoot::new(root.path())]).expect("workspace graph");
        assert_eq!(
            graph.repositories.len(),
            2,
            "nested repository must be registered"
        );
        let mut capability =
            CapabilityV1::new("wrangler.deploy", "Deploy Worker", "CLI", "wrangler deploy");
        capability.mutating = true;
        capability.adapter_status = AdapterStatus::DelegatedCli;
        capability.risk = RiskClass::CrossConfig;
        capability.effect = EffectClass::ReversibleWrite;
        let input = CallInput {
            query: json!({
                "config": config.canonicalize().expect("canonical config"),
                "name": "cfctl-site",
                "message": "untrusted",
            }),
            ..CallInput::default()
        };
        let error = prepare_target(&graph, &capability, &input)
            .expect_err("artifact tree containing a nested repository must fail before planning")
            .to_string();
        assert!(error.contains("is not owned by config repository"));
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
        let absent =
            apply_state_responses("account-a", "cfctl-site", &absent, None).expect("absence");
        assert_eq!(absent["exists"], false);
        assert!(absent.get("redacted_settings_hash").is_none());
        assert!(absent.get("redacted_deployments_hash").is_none());

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
        assert!(apply_state_responses("account-a", "cfctl-site", &ambiguous, None).is_err());

        let existing = CloudflareResponseV1 {
            status: 200,
            success: true,
            result: json!({"compatibility_date": "2026-08-05", "secret_text": "hidden"}),
            errors: Vec::new(),
            result_info: None,
            etag: None,
            cf_ray: None,
        };
        let deployment_a = CloudflareResponseV1 {
            status: 200,
            success: true,
            result: json!([{"id": "deployment-a", "versions": [{"version_id": "version-a", "percentage": 100}]}]),
            errors: Vec::new(),
            result_info: None,
            etag: None,
            cf_ray: None,
        };
        let deployment_b = CloudflareResponseV1 {
            result: json!([{"id": "deployment-b", "versions": [{"version_id": "version-b", "percentage": 100}]}]),
            ..deployment_a.clone()
        };
        let existing_a =
            apply_state_responses("account-a", "cfctl-site", &existing, Some(&deployment_a))
                .expect("existing");
        let existing_b =
            apply_state_responses("account-a", "cfctl-site", &existing, Some(&deployment_b))
                .expect("drifted deployment");
        let existing = existing_a;
        assert_eq!(existing["exists"], true);
        assert!(existing["redacted_settings_hash"].as_str().is_some());
        assert!(existing["redacted_deployments_hash"].as_str().is_some());
        assert_ne!(existing, existing_b);
        assert!(!existing.to_string().contains("hidden"));
    }
}
