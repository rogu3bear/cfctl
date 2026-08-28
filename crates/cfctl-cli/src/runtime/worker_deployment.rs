use std::{
    collections::BTreeSet,
    ffi::OsStr,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};

use cfctl_cloudflare::{CallInput, CloudflareResponseV1};
use cfctl_core::{
    CapabilityV1, PlanV1, WORKER_DEPLOYMENT_PLAN_CAPABILITY_ID, hash_value, redact_json,
};
use cfctl_workspace::{WorkspaceGraph, load_wrangler_config, load_wrangler_config_snapshot};
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
pub(super) const VERSION_CAPABILITY_ID: &str = "worker-versions-get-version-detail";
pub(super) const VERSION_PATH: &str =
    "/accounts/{account_id}/workers/scripts/{script_name}/versions/{version_id}";
pub(super) const ROLLBACK_CAPABILITY_ID: &str = "worker-version-rollback";
const NOT_FOUND_ERROR_CODE: i64 = 10_007;

pub(super) fn binds_artifact(capability: &CapabilityV1) -> bool {
    matches!(
        capability.id.as_str(),
        "wrangler.deploy" | "wrangler.versions-upload" | WORKER_DEPLOYMENT_PLAN_CAPABILITY_ID
    )
}

pub(super) fn binds_live_state(capability: &CapabilityV1) -> bool {
    binds_artifact(capability)
        || matches!(
            capability.id.as_str(),
            "wrangler.versions-deploy" | ROLLBACK_CAPABILITY_ID
        )
}

/// Identifies every cfctl lane that can replace the production traffic
/// deployment for one Worker. All of these lanes must share the same
/// account/script lock; a rollback-only lock would still permit a local
/// deploy to race the rollback's final read, POST, or verification.
pub(super) fn mutates_traffic(capability: &CapabilityV1) -> bool {
    matches!(
        capability.id.as_str(),
        "wrangler.deploy" | "wrangler.versions-deploy" | ROLLBACK_CAPABILITY_ID
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
    artifact_paths_from_document(directory, &document, input)
}

fn artifact_paths_from_document(
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
    if capability.id == ROLLBACK_CAPABILITY_ID {
        return prepare_rollback_target(capability, input).map(Some);
    }
    let config = canonical_config(input)?;
    let snapshot = load_wrangler_config_snapshot(&config)?;
    let document = &snapshot.document;
    let service_name = validated_service_name(document, input)?;
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
    let config_source = repository
        .configs
        .iter()
        .find(|source| source.path == config)
        .ok_or_else(|| {
            CliError::Input(format!(
                "Wrangler configuration `{}` is absent from its repository source graph",
                config.display()
            ))
        })?;
    let private_config_authority =
        private_d1_identity_overlay(repository, &config, &snapshot, config_source)?;
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
    let config_sha256 = snapshot
        .content_hash
        .strip_prefix("sha256:")
        .ok_or_else(|| {
            CliError::Input("Wrangler configuration digest is not canonical SHA-256".to_owned())
        })?
        .to_owned();
    let (expected_message, operation) = if binds_artifact(capability) {
        let config_directory = config.parent().ok_or_else(|| {
            CliError::Input("Wrangler configuration has no containing directory".to_owned())
        })?;
        let artifacts = artifact_paths_from_document(config_directory, document, input)?;
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
    let mut config_target = json!({
        "path": config,
        "sha256": config_sha256,
        "settings_sha256": deployment_config_section_hash(document, false)?,
        "bindings_sha256": deployment_config_section_hash(document, true)?,
    });
    if let Some(authority) = private_config_authority {
        config_target["authority"] = Value::String("private_d1_identity_overlay".to_owned());
        config_target["template_path"] = json!(authority.path);
        config_target["template_sha256"] = Value::String(authority.sha256);
    }
    let mut target = json!({
        "schema_version": 1,
        "service_name": service_name,
        "source_sha": source_sha,
        "repository": repository.path,
        "config": config_target,
        "version_message": expected_message,
        "execution": {
            "supported": capability.execution_supported,
            "provider_effect_on_call": false,
        },
        "post_deploy_verification": {
            "steps": [
                {
                    "capability_id": DEPLOYMENTS_CAPABILITY_ID,
                    "path": DEPLOYMENTS_PATH,
                    "proves": "the new version is the sole latest active version at 100 percent traffic",
                },
                {
                    "capability_id": VERSION_CAPABILITY_ID,
                    "path": VERSION_PATH,
                    "proves": "the active version detail reports the exact compiled source and artifact message",
                },
                {
                    "capability_id": SETTINGS_CAPABILITY_ID,
                    "path": SETTINGS_PATH,
                    "proves": "provider-observable settings and bindings match the exact compiled configuration projection",
                }
            ],
            "artifact_and_config_identity_source": "worker_deployment target hashes",
        },
        "rollback": {
            "capability_id": ROLLBACK_CAPABILITY_ID,
            "identity_source": "worker_deployment_state.current_active",
        },
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

fn deployment_config_section_hash(document: &Value, bindings: bool) -> Result<String, CliError> {
    const BINDING_KEYS: &[&str] = &[
        "ai",
        "analytics_engine_datasets",
        "browser",
        "d1_databases",
        "dispatch_namespaces",
        "durable_objects",
        "hyperdrive",
        "images",
        "kv_namespaces",
        "mtls_certificates",
        "queues",
        "r2_buckets",
        "services",
        "unsafe",
        "vars",
        "vectorize",
        "version_metadata",
        "workflows",
    ];
    let object = document.as_object().ok_or_else(|| {
        CliError::Input("Wrangler configuration root must be an object".to_owned())
    })?;
    let section = object
        .iter()
        .filter(|(key, _)| BINDING_KEYS.contains(&key.as_str()) == bindings)
        .map(|(key, value)| (key.clone(), redact_json(value)))
        .collect::<serde_json::Map<_, _>>();
    hash_value(&Value::Object(section)).map_err(Into::into)
}

pub(super) fn prepare_rollback_target(
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<Value, CliError> {
    if capability.method != "POST"
        || capability.path != DEPLOYMENTS_PATH
        || capability.adapter_status != cfctl_core::AdapterStatus::Native
    {
        return Err(CliError::Input(
            "Worker rollback capability identity drifted".to_owned(),
        ));
    }
    let service_name = input
        .selectors
        .get("script_name")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CliError::Input("Worker rollback script_name is missing".to_owned()))?;
    let body = input
        .body
        .as_ref()
        .and_then(Value::as_object)
        .ok_or_else(|| CliError::Input("Worker rollback body is missing".to_owned()))?;
    let canonical_uuid = |key: &str| -> Result<&str, CliError> {
        let raw = body
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| CliError::Input(format!("Worker rollback {key} is missing")))?;
        let parsed = uuid::Uuid::parse_str(raw)
            .map_err(|_| CliError::Input(format!("Worker rollback {key} is not a UUID")))?;
        if parsed.to_string() != raw {
            return Err(CliError::Input(format!(
                "Worker rollback {key} must be a canonical lowercase UUID"
            )));
        }
        Ok(raw)
    };
    let target_version_id = canonical_uuid("target_version_id")?;
    let expected_current_deployment_id = canonical_uuid("expected_current_deployment_id")?;
    let message = body
        .get("message")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.chars().count() <= 900)
        .ok_or_else(|| {
            CliError::Input("Worker rollback message must contain 1 to 900 characters".to_owned())
        })?;
    Ok(json!({
        "schema_version":1,
        "service_name":service_name,
        "rollback":{
            "target_version_id":target_version_id,
            "expected_current_deployment_id":expected_current_deployment_id,
            "message":message,
            "traffic_percentage":100,
            "force":false,
        }
    }))
}

#[derive(Debug)]
struct PrivateConfigAuthority {
    path: PathBuf,
    sha256: String,
}

fn private_d1_identity_overlay(
    repository: &cfctl_workspace::RepositoryNode,
    config: &Path,
    snapshot: &cfctl_workspace::WranglerConfigSnapshot,
    source: &cfctl_workspace::SourceConfigV1,
) -> Result<Option<PrivateConfigAuthority>, CliError> {
    if source.head_content_hash.as_deref() == Some(snapshot.content_hash.as_str()) {
        return Ok(None);
    }
    if source.head_content_hash.is_some() || source.dirty || source.worktree_diff_hash.is_some() {
        return Err(exact_head_config_error(config));
    }
    if source.content_hash != snapshot.content_hash {
        return Err(CliError::Input(
            "private Worker production config drifted after workspace discovery; create a new plan"
                .to_owned(),
        ));
    }
    let template_path =
        private_config_template_path(config).ok_or_else(|| exact_head_config_error(config))?;
    if template_path.parent() != Some(repository.path.as_path()) {
        return Err(exact_head_config_error(config));
    }
    let metadata = fs::symlink_metadata(config).map_err(|source| CliError::Io {
        path: config.display().to_string(),
        source,
    })?;
    if !metadata.file_type().is_file() || metadata.len() > 1_048_576 {
        return Err(CliError::Input(
            "private Worker production config must be a regular file of at most 1 MiB".to_owned(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(CliError::Input(
                "private Worker production config must have mode 0600".to_owned(),
            ));
        }
    }
    let template_source = repository
        .configs
        .iter()
        .find(|candidate| candidate.path == template_path)
        .ok_or_else(|| {
            CliError::Input(format!(
                "private Worker production config has no tracked role template `{}`",
                template_path.display()
            ))
        })?;
    let template_snapshot = load_wrangler_config_snapshot(&template_path)?;
    if template_source.content_hash != template_snapshot.content_hash
        || template_source.head_content_hash.as_deref()
            != Some(template_snapshot.content_hash.as_str())
        || template_source.dirty
    {
        return Err(CliError::Input(format!(
            "private Worker production template `{}` does not match an exact Git HEAD blob",
            template_path.display()
        )));
    }
    let mut normalized = snapshot.document.clone();
    normalize_private_d1_identity(&mut normalized, &template_snapshot.document)?;
    if normalized != template_snapshot.document {
        return Err(CliError::Input(
            "private Worker production config differs from its tracked role template outside canonical D1 identity, sender restriction, and split relay activation fields"
                .to_owned(),
        ));
    }
    let sha256 = template_snapshot
        .content_hash
        .strip_prefix("sha256:")
        .ok_or_else(|| {
            CliError::Input("tracked Worker template digest is not canonical SHA-256".to_owned())
        })?
        .to_owned();
    Ok(Some(PrivateConfigAuthority {
        path: template_path,
        sha256,
    }))
}

fn exact_head_config_error(config: &Path) -> CliError {
    CliError::Input(format!(
        "Wrangler configuration `{}` does not match an exact Git HEAD blob",
        config.display()
    ))
}

fn private_config_template_path(config: &Path) -> Option<PathBuf> {
    let name = config.file_name()?.to_str()?;
    let stem = name.strip_suffix(".production.toml")?;
    let role = stem.strip_prefix("wrangler.")?;
    if role.is_empty() {
        return None;
    }
    Some(config.with_file_name(format!("{stem}.toml")))
}

fn normalize_private_d1_identity(production: &mut Value, template: &Value) -> Result<(), CliError> {
    let template_databases = template
        .get("d1_databases")
        .and_then(Value::as_array)
        .ok_or_else(|| CliError::Input("tracked Worker template has no D1 databases".to_owned()))?;
    let production_databases = production
        .get_mut("d1_databases")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| {
            CliError::Input("private Worker production config has no D1 databases".to_owned())
        })?;
    for database in production_databases {
        let binding = database
            .get("binding")
            .and_then(Value::as_str)
            .filter(|binding| !binding.is_empty())
            .ok_or_else(|| {
                CliError::Input("private Worker D1 binding is missing or invalid".to_owned())
            })?;
        let matches = template_databases
            .iter()
            .filter(|candidate| candidate.get("binding").and_then(Value::as_str) == Some(binding))
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(CliError::Input(
                "private Worker D1 binding does not have one exact tracked-template match"
                    .to_owned(),
            ));
        }
        let production_id = database
            .get("database_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CliError::Input("private Worker D1 database ID is missing".to_owned())
            })?;
        let parsed_id = uuid::Uuid::parse_str(production_id).map_err(|_| {
            CliError::Input(
                "private Worker D1 database ID is not a canonical lowercase UUID".to_owned(),
            )
        })?;
        if parsed_id.to_string() != production_id {
            return Err(CliError::Input(
                "private Worker D1 database ID is not a canonical lowercase UUID".to_owned(),
            ));
        }
        let template_id = matches[0].get("database_id").cloned().ok_or_else(|| {
            CliError::Input("tracked Worker D1 database ID is missing".to_owned())
        })?;
        database["database_id"] = template_id;
    }
    normalize_private_sender_identity(production, template)?;
    normalize_private_relay_activation(production, template)?;
    Ok(())
}

fn normalize_private_relay_activation(
    production: &mut Value,
    template: &Value,
) -> Result<(), CliError> {
    let Some(production_vars) = production.get_mut("vars").and_then(Value::as_object_mut) else {
        return Ok(());
    };
    let Some(template_vars) = template.get("vars").and_then(Value::as_object) else {
        return Ok(());
    };
    for key in ["MAILDESK_INBOUND_RELAY_MODE", "MAILDESK_REPLY_RELAY_MODE"] {
        let Some(production_mode) = production_vars.get(key) else {
            continue;
        };
        let valid_mode = |value: &Value| matches!(value.as_str(), Some("disabled" | "enabled"));
        if !valid_mode(production_mode) {
            return Err(CliError::Input(format!(
                "private Worker {key} must be disabled or enabled"
            )));
        }
        let template_mode = template_vars
            .get(key)
            .filter(|value| valid_mode(value))
            .ok_or_else(|| {
                CliError::Input(format!(
                    "private Worker {key} has no canonical tracked-template authority"
                ))
            })?;
        production_vars.insert(key.to_owned(), template_mode.clone());
    }
    Ok(())
}

fn normalize_private_sender_identity(
    production: &mut Value,
    template: &Value,
) -> Result<(), CliError> {
    let Some(production_senders) = production
        .get_mut("send_email")
        .and_then(Value::as_array_mut)
    else {
        return Ok(());
    };
    let Some(template_senders) = template.get("send_email").and_then(Value::as_array) else {
        return Ok(());
    };
    if production_senders.len() != template_senders.len() {
        return Ok(());
    }
    for (production_sender, template_sender) in production_senders.iter_mut().zip(template_senders)
    {
        let Some(production_table) = production_sender.as_object_mut() else {
            continue;
        };
        let Some(addresses) = production_table.get("allowed_sender_addresses") else {
            continue;
        };
        validate_private_sender_addresses(addresses)?;
        if let Some(template_addresses) = template_sender.get("allowed_sender_addresses") {
            production_table.insert(
                "allowed_sender_addresses".to_owned(),
                template_addresses.clone(),
            );
        } else {
            production_table.remove("allowed_sender_addresses");
        }
    }
    Ok(())
}

fn validate_private_sender_addresses(value: &Value) -> Result<(), CliError> {
    let Some(addresses) = value.as_array() else {
        return Err(CliError::Input(
            "private Worker allowed sender addresses must be a bounded array".to_owned(),
        ));
    };
    if !(1..=256).contains(&addresses.len()) {
        return Err(CliError::Input(
            "private Worker allowed sender addresses must be a bounded array".to_owned(),
        ));
    }
    let mut unique = BTreeSet::new();
    for address in addresses {
        let Some(address) = address.as_str() else {
            return Err(CliError::Input(
                "private Worker allowed sender addresses must be canonical email addresses"
                    .to_owned(),
            ));
        };
        let Some((local, domain)) = address.split_once('@') else {
            return Err(CliError::Input(
                "private Worker allowed sender addresses must be canonical email addresses"
                    .to_owned(),
            ));
        };
        if !(3..=320).contains(&address.len())
            || local.is_empty()
            || domain.is_empty()
            || domain.contains('@')
            || domain.starts_with('.')
            || domain.ends_with('.')
            || address
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        {
            return Err(CliError::Input(
                "private Worker allowed sender addresses must be canonical email addresses"
                    .to_owned(),
            ));
        }
        if !unique.insert(address) {
            return Err(CliError::Input(
                "private Worker allowed sender addresses must not contain duplicates".to_owned(),
            ));
        }
    }
    Ok(())
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

pub(super) fn validate_current_rollback_target(
    capability: &CapabilityV1,
    input: &CallInput,
    adapter_targets: &Value,
) -> Result<(), CliError> {
    if capability.id != ROLLBACK_CAPABILITY_ID {
        return Err(CliError::Input(
            "Worker rollback target validator received another capability".to_owned(),
        ));
    }
    let planned = target(adapter_targets).ok_or_else(|| {
        CliError::Input("Worker rollback plan omitted its exact target".to_owned())
    })?;
    let current = prepare_rollback_target(capability, input)?;
    if &current != planned {
        return Err(CliError::Input(
            "Worker rollback service, expected deployment, target version, or message drifted after planning; the provider boundary was not crossed and a new plan is required"
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
    require_singular_active: bool,
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
        let mut receipt = json!({
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
        });
        if require_singular_active {
            let (current_deployment_id, current_version_id) =
                current_active_deployment_identity(&deployments.result)?;
            receipt["current_active"] = json!({
                "deployment_id": current_deployment_id,
                "version_id": current_version_id,
                "traffic_percentage": 100,
            });
        }
        return Ok(receipt);
    }
    Err(CliError::Input(format!(
        "Worker settings/deployments reads for `{service_name}` returned HTTP {}/{} and cannot prove exact current state",
        settings.status, deployments.status
    )))
}

fn current_active_deployment_identity(deployments: &Value) -> Result<(&str, &str), CliError> {
    let history = deployments
        .get("deployments")
        .and_then(Value::as_array)
        .or_else(|| deployments.as_array())
        .ok_or_else(|| {
            CliError::Input("Worker deployments readback omitted deployment history".to_owned())
        })?;
    let current = history.first().ok_or_else(|| {
        CliError::Input("Worker deployments readback has no current deployment".to_owned())
    })?;
    let deployment_id = current
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| CliError::Input("Worker current deployment has no identity".to_owned()))?;
    let versions = current
        .get("versions")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CliError::Input("Worker current deployment has no version allocation".to_owned())
        })?;
    if versions.len() != 1 || versions[0].get("percentage").and_then(Value::as_f64) != Some(100.0) {
        return Err(CliError::Input(
            "Worker deployment planning requires one current version serving exactly 100 percent"
                .to_owned(),
        ));
    }
    let version_id = versions[0]
        .get("version_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| CliError::Input("Worker current version has no identity".to_owned()))?;
    Ok((deployment_id, version_id))
}

#[expect(
    clippy::too_many_lines,
    reason = "one fail-closed admission function binds current deployment, active version, retained prior history, and exact target-version detail into one receipt"
)]
pub(super) fn apply_rollback_state_responses(
    account_id: &str,
    service_name: &str,
    target: &Value,
    settings: &CloudflareResponseV1,
    deployments: &CloudflareResponseV1,
    version: &CloudflareResponseV1,
) -> Result<Value, CliError> {
    if !settings.success
        || !(200..300).contains(&settings.status)
        || !deployments.success
        || !(200..300).contains(&deployments.status)
        || !version.success
        || !(200..300).contains(&version.status)
    {
        return Err(CliError::Input(format!(
            "Worker rollback preflight reads for `{service_name}` returned HTTP {}/{}/{} and cannot prove exact current state",
            settings.status, deployments.status, version.status
        )));
    }
    let rollback = target
        .get("rollback")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CliError::Input(
                "Worker rollback target omitted its closed rollback contract".to_owned(),
            )
        })?;
    let target_version_id = rollback
        .get("target_version_id")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("Worker rollback target version is missing".to_owned()))?;
    let expected_current_deployment_id = rollback
        .get("expected_current_deployment_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input("Worker rollback expected current deployment is missing".to_owned())
        })?;
    let history = deployments
        .result
        .get("deployments")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CliError::Input("Worker deployments readback omitted result.deployments".to_owned())
        })?;
    if !(2..=100).contains(&history.len()) {
        return Err(CliError::Input(
            "Worker rollback requires 2 to 100 retained deployments".to_owned(),
        ));
    }
    let current = history.first().ok_or_else(|| {
        CliError::Input("Worker deployment history has no current deployment".to_owned())
    })?;
    let current_deployment_id = current
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("Worker current deployment has no identity".to_owned()))?;
    if current_deployment_id != expected_current_deployment_id {
        return Err(CliError::Input(format!(
            "Worker current deployment is `{current_deployment_id}`, not reviewed expected deployment `{expected_current_deployment_id}`"
        )));
    }
    let current_versions = current
        .get("versions")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CliError::Input("Worker current deployment has no version allocation".to_owned())
        })?;
    if current_versions.len() != 1
        || current_versions[0]
            .get("percentage")
            .and_then(Value::as_f64)
            != Some(100.0)
    {
        return Err(CliError::Input(
            "Worker rollback requires one current version serving exactly 100 percent".to_owned(),
        ));
    }
    let current_version_id = current_versions[0]
        .get("version_id")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("Worker current version has no identity".to_owned()))?;
    if current_version_id == target_version_id {
        return Err(CliError::Input(
            "Worker rollback target is already the active version".to_owned(),
        ));
    }
    let prior_deployment_id = history.iter().skip(1).find_map(|deployment| {
        deployment
            .get("versions")
            .and_then(Value::as_array)
            .filter(|versions| {
                versions.len() == 1
                    && versions[0].get("version_id").and_then(Value::as_str)
                        == Some(target_version_id)
                    && versions[0].get("percentage").and_then(Value::as_f64) == Some(100.0)
            })
            .and_then(|_| deployment.get("id"))
            .and_then(Value::as_str)
    });
    let prior_deployment_id = prior_deployment_id.ok_or_else(|| {
        CliError::Input(
            "Worker rollback target does not appear as the sole 100 percent version in retained prior deployment history"
                .to_owned(),
        )
    })?;
    if version.result.get("id").and_then(Value::as_str) != Some(target_version_id) {
        return Err(CliError::Input(
            "Worker target-version detail readback did not return the exact target identity"
                .to_owned(),
        ));
    }
    Ok(json!({
        "schema_version":2,
        "source_capability_id":SETTINGS_CAPABILITY_ID,
        "source_path":SETTINGS_PATH,
        "deployment_source_capability_id":DEPLOYMENTS_CAPABILITY_ID,
        "deployment_source_path":DEPLOYMENTS_PATH,
        "version_source_capability_id":VERSION_CAPABILITY_ID,
        "version_source_path":VERSION_PATH,
        "account_id":account_id,
        "service_name":service_name,
        "exists":true,
        "current_deployment_id":current_deployment_id,
        "current_version_id":current_version_id,
        "target_version_id":target_version_id,
        "target_prior_deployment_id":prior_deployment_id,
        "target_version_detail_id":target_version_id,
        "retained_deployment_count":history.len(),
        "redacted_settings_hash":hash_value(&redact_json(&settings.result))?,
        "redacted_deployments_hash":hash_value(&redact_json(&deployments.result))?,
        "redacted_target_version_hash":hash_value(&redact_json(&version.result))?,
        "force":false,
        "traffic_percentage":100,
    }))
}

#[expect(
    clippy::too_many_lines,
    reason = "legacy deployment receipts and the stricter rollback receipt share one dispatcher while retaining distinct exact-shape validation"
)]
pub(super) fn validate_state_receipt(plan: &PlanV1, receipt: &Value) -> Result<(), CliError> {
    let adapter = plan.targets.get("adapter").unwrap_or(&Value::Null);
    let expected_service = service_name(adapter)?;
    if plan.capability.id == ROLLBACK_CAPABILITY_ID {
        let target = target(adapter).ok_or_else(|| {
            CliError::Input("Worker rollback plan omitted its exact target".to_owned())
        })?;
        let rollback = target
            .get("rollback")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                CliError::Input("Worker rollback plan omitted its closed target".to_owned())
            })?;
        let exact = receipt.as_object().is_some_and(|object| object.len() == 21)
            && receipt.get("schema_version").and_then(Value::as_u64) == Some(2)
            && receipt.get("account_id").and_then(Value::as_str) == Some(plan.account_id.as_str())
            && receipt.get("service_name").and_then(Value::as_str) == Some(expected_service)
            && receipt.get("exists").and_then(Value::as_bool) == Some(true)
            && receipt.get("source_capability_id").and_then(Value::as_str)
                == Some(SETTINGS_CAPABILITY_ID)
            && receipt.get("source_path").and_then(Value::as_str) == Some(SETTINGS_PATH)
            && receipt
                .get("deployment_source_capability_id")
                .and_then(Value::as_str)
                == Some(DEPLOYMENTS_CAPABILITY_ID)
            && receipt
                .get("deployment_source_path")
                .and_then(Value::as_str)
                == Some(DEPLOYMENTS_PATH)
            && receipt
                .get("version_source_capability_id")
                .and_then(Value::as_str)
                == Some(VERSION_CAPABILITY_ID)
            && receipt.get("version_source_path").and_then(Value::as_str) == Some(VERSION_PATH)
            && receipt.get("current_deployment_id")
                == rollback.get("expected_current_deployment_id")
            && receipt.get("target_version_id") == rollback.get("target_version_id")
            && receipt.get("target_version_detail_id") == rollback.get("target_version_id")
            && receipt.get("force").and_then(Value::as_bool) == Some(false)
            && receipt.get("traffic_percentage").and_then(Value::as_u64) == Some(100)
            && receipt
                .get("retained_deployment_count")
                .and_then(Value::as_u64)
                .is_some_and(|count| (2..=100).contains(&count))
            && [
                "current_version_id",
                "target_prior_deployment_id",
                "redacted_settings_hash",
                "redacted_deployments_hash",
                "redacted_target_version_hash",
            ]
            .iter()
            .all(|field| {
                receipt
                    .get(*field)
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.is_empty())
            });
        if !exact {
            return Err(CliError::Input(
                "Worker rollback live-state receipt is malformed or targets another service, deployment, or version"
                    .to_owned(),
            ));
        }
        return Ok(());
    }
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

fn is_git_metadata_name(name: &OsStr) -> bool {
    name.to_str()
        .is_some_and(|value| value.eq_ignore_ascii_case(".git"))
}

fn validate_artifact_tree_ownership(
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

fn artifact_set_sha256(repository: &Path, roots: &[PathBuf]) -> Result<String, CliError> {
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

fn is_full_source_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;
