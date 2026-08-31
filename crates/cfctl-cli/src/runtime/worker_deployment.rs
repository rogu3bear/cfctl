use std::{
    collections::BTreeSet,
    fs,
    io::{Read as _, Seek as _, Write as _},
    path::{Path, PathBuf},
};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use cfctl_cloudflare::{CallInput, CloudflareResponseV1};
use cfctl_core::{
    CapabilityV1, PlanV1, WORKER_DEPLOYMENT_PLAN_CAPABILITY_ID, hash_value, redact_json,
};
use cfctl_workspace::{WorkspaceGraph, load_wrangler_config_snapshot};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{
    CliError,
    worker_deployment_artifact::{
        artifact_paths as deployment_artifact_paths, artifact_paths_from_document,
        artifact_set_sha256, canonical_config, is_full_source_sha, repository_owning_path,
        validate_artifact_tree_ownership,
    },
};

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
    deployment_artifact_paths(input)
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
    } else {
        config_target["authority"] = Value::String("exact_head_blob".to_owned());
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
        "send_email",
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

pub(super) struct BoundPrivateConfig {
    staged: tempfile::NamedTempFile,
    content_sha256: String,
    private_representations: PrivateRepresentationGuard,
}

impl BoundPrivateConfig {
    pub(super) fn path(&self) -> &Path {
        self.staged.path()
    }

    pub(super) fn content_sha256(&self) -> &str {
        &self.content_sha256
    }

    pub(super) fn retained_rows_contain_private_representation(
        &self,
        rows: &[serde_json::Map<String, Value>],
    ) -> bool {
        rows.iter().any(|row| {
            row.values()
                .any(|value| self.private_representations.contains_in_json(value))
        })
    }

    pub(super) fn retained_text_contains_private_representation(&self, value: &str) -> bool {
        self.private_representations.contains_in_text(value)
    }

    pub(super) fn replace_staged_bytes(&mut self, bytes: &[u8]) -> Result<(), CliError> {
        let path = self.staged.path().display().to_string();
        let file = self.staged.as_file_mut();
        file.set_len(0)
            .and_then(|()| file.rewind())
            .and_then(|()| file.write_all(bytes))
            .and_then(|()| file.flush())
            .and_then(|()| file.sync_data())
            .map_err(|source| CliError::Io { path, source })?;
        if fs::read(self.staged.path()).map_err(|source| CliError::Io {
            path: self.staged.path().display().to_string(),
            source,
        })? != bytes
        {
            return Err(CliError::Input(
                "private Worker execution config staging failed closed".to_owned(),
            ));
        }
        Ok(())
    }
}

struct PrivateRepresentationGuard {
    representations: BTreeSet<String>,
}

impl PrivateRepresentationGuard {
    fn from_documents(production: &Value, normalized: &Value) -> Self {
        let mut private_values = BTreeSet::new();
        collect_changed_strings(production, normalized, &mut private_values);
        let mut representations = BTreeSet::new();
        for value in private_values {
            insert_private_representations(&value, &mut representations);
            for member in value.split(',').filter(|member| !member.is_empty()) {
                insert_private_representations(member, &mut representations);
            }
            if let Some((_, domain)) = value.rsplit_once('@') {
                insert_private_representations(domain, &mut representations);
            }
        }
        Self { representations }
    }

    fn contains_in_json(&self, value: &Value) -> bool {
        match value {
            Value::String(value) => self
                .representations
                .iter()
                .any(|representation| value.contains(representation)),
            Value::Array(values) => values.iter().any(|value| self.contains_in_json(value)),
            Value::Object(values) => values.values().any(|value| self.contains_in_json(value)),
            Value::Null | Value::Bool(_) | Value::Number(_) => false,
        }
    }

    fn contains_in_text(&self, value: &str) -> bool {
        self.representations
            .iter()
            .any(|representation| value.contains(representation))
    }
}

fn collect_changed_strings(production: &Value, normalized: &Value, output: &mut BTreeSet<String>) {
    match (production, normalized) {
        (Value::String(production), Value::String(normalized)) if production != normalized => {
            if !production.is_empty() {
                output.insert(production.clone());
            }
        }
        (Value::Array(production), Value::Array(normalized))
            if production.len() == normalized.len() =>
        {
            for (production, normalized) in production.iter().zip(normalized) {
                collect_changed_strings(production, normalized, output);
            }
        }
        (Value::Object(production), Value::Object(normalized)) => {
            for (key, production) in production {
                if let Some(normalized) = normalized.get(key) {
                    collect_changed_strings(production, normalized, output);
                } else {
                    collect_all_strings(production, output);
                }
            }
        }
        (production, normalized) if production != normalized => {
            collect_all_strings(production, output);
        }
        _ => {}
    }
}

fn collect_all_strings(value: &Value, output: &mut BTreeSet<String>) {
    match value {
        Value::String(value) if !value.is_empty() => {
            output.insert(value.clone());
        }
        Value::Array(values) => {
            for value in values {
                collect_all_strings(value, output);
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                collect_all_strings(value, output);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn insert_private_representations(value: &str, output: &mut BTreeSet<String>) {
    if value.is_empty() {
        return;
    }
    let bytes = value.as_bytes();
    output.insert(value.to_owned());
    output.insert(hex_bytes(bytes, false));
    output.insert(hex_bytes(bytes, true));
    output.insert(STANDARD.encode(bytes));
    output.insert(STANDARD_NO_PAD.encode(bytes));
    output.insert(URL_SAFE.encode(bytes));
    output.insert(URL_SAFE_NO_PAD.encode(bytes));
    output.insert(percent_encode(bytes, false, false));
    output.insert(percent_encode(bytes, true, false));
    output.insert(percent_encode(bytes, false, true));
    output.insert(percent_encode(bytes, true, true));
}

fn hex_bytes(bytes: &[u8], uppercase: bool) -> String {
    bytes
        .iter()
        .map(|byte| {
            if uppercase {
                format!("{byte:02X}")
            } else {
                format!("{byte:02x}")
            }
        })
        .collect()
}

fn percent_encode(bytes: &[u8], uppercase: bool, encode_all: bool) -> String {
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(3));
    let hex = if uppercase {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    for byte in bytes {
        if !encode_all
            && (byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
        {
            encoded.push(char::from(*byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(hex[usize::from(*byte >> 4)]));
            encoded.push(char::from(hex[usize::from(*byte & 0x0f)]));
        }
    }
    encoded
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
            "private Worker production config differs from its tracked role template outside the closed private-config overlay"
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

pub(super) fn canonical_worker_version_id(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|parsed| parsed.to_string() == value)
}

pub(super) fn private_config_template_path(config: &Path) -> Option<PathBuf> {
    let name = config.file_name()?.to_str()?;
    let stem = name.strip_suffix(".production.toml")?;
    let role = stem.strip_prefix("wrangler.")?;
    if role.is_empty() {
        return None;
    }
    Some(config.with_file_name(format!("{stem}.toml")))
}

pub(super) fn bind_private_config_for_execution(
    capability: &CapabilityV1,
    input: &CallInput,
    planned: Option<&PlannedConfigExecution>,
) -> Result<Option<BoundPrivateConfig>, CliError> {
    if !binds_artifact(capability) {
        return Ok(None);
    }
    if input.query.get("config").and_then(Value::as_str).is_none() {
        return Ok(None);
    }
    let Some(planned) = planned else {
        return Ok(None);
    };
    bind_planned_config_path_for_execution(&canonical_config(input)?, planned)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum PlannedConfigExecution {
    Public {
        path: PathBuf,
        sha256: String,
    },
    Private {
        path: PathBuf,
        sha256: String,
        template_path: PathBuf,
        template_sha256: String,
    },
}

pub(super) fn planned_config_execution(
    adapter_targets: &Value,
) -> Result<Option<PlannedConfigExecution>, CliError> {
    let Some(target) = target(adapter_targets) else {
        return Ok(None);
    };
    let config = target
        .get("config")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CliError::Input("Worker deployment plan omitted its exact config target".to_owned())
        })?;
    let path = config
        .get("path")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| {
            CliError::Input("Worker deployment plan omitted its config path".to_owned())
        })?;
    let sha256 = config
        .get("sha256")
        .and_then(Value::as_str)
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| {
            CliError::Input(
                "Worker deployment plan omitted its exact config content identity".to_owned(),
            )
        })?
        .to_owned();
    match config.get("authority").and_then(Value::as_str) {
        Some("exact_head_blob") => {
            if config.contains_key("template_path") || config.contains_key("template_sha256") {
                return Err(CliError::Input(
                    "public Worker config plan contained private template authority".to_owned(),
                ));
            }
            Ok(Some(PlannedConfigExecution::Public { path, sha256 }))
        }
        Some("private_d1_identity_overlay") => {
            let template_path = config
                .get("template_path")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
                .ok_or_else(|| {
                    CliError::Input("private Worker plan omitted its template path".to_owned())
                })?;
            let template_sha256 = config
                .get("template_sha256")
                .and_then(Value::as_str)
                .filter(|value| {
                    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
                .ok_or_else(|| {
                    CliError::Input(
                        "private Worker plan omitted its template content identity".to_owned(),
                    )
                })?
                .to_owned();
            Ok(Some(PlannedConfigExecution::Private {
                path,
                sha256,
                template_path,
                template_sha256,
            }))
        }
        _ => Err(CliError::Input(
            "Worker deployment plan omitted its closed config authority".to_owned(),
        )),
    }
}

pub(super) fn bind_planned_config_path_for_execution(
    config: &Path,
    planned: &PlannedConfigExecution,
) -> Result<Option<BoundPrivateConfig>, CliError> {
    let planned_path = match planned {
        PlannedConfigExecution::Public { path, .. }
        | PlannedConfigExecution::Private { path, .. } => path,
    };
    if config != planned_path {
        return Err(CliError::Input(
            "Worker execution config does not match its planned path identity".to_owned(),
        ));
    }
    match planned {
        PlannedConfigExecution::Public { sha256, .. } => {
            let observed = load_wrangler_config_snapshot(config)?;
            if observed.content_hash.strip_prefix("sha256:") != Some(sha256.as_str()) {
                return Err(CliError::Input(
                    "public Worker config no longer matches its planned content identity"
                        .to_owned(),
                ));
            }
            Ok(None)
        }
        PlannedConfigExecution::Private {
            sha256,
            template_path,
            template_sha256,
            ..
        } => bind_private_config_path_with_template_for_execution(
            config,
            template_path,
            Some(sha256),
            Some(template_sha256),
        )
        .map(Some),
    }
}

pub(super) fn bind_private_config_path_with_template_for_execution(
    config: &Path,
    template_path: &Path,
    expected_sha256: Option<&str>,
    expected_template_sha256: Option<&str>,
) -> Result<BoundPrivateConfig, CliError> {
    bind_private_config_path_with_template_and_overlay_for_execution(
        config,
        template_path,
        expected_sha256,
        expected_template_sha256,
        PrivateConfigOverlay::WorkerDeployment,
    )
}

pub(super) fn bind_workspace_d1_private_config_for_execution(
    config: &Path,
    template_path: &Path,
    expected_sha256: Option<&str>,
    expected_template_sha256: Option<&str>,
    database_binding: &str,
) -> Result<BoundPrivateConfig, CliError> {
    bind_private_config_path_with_template_and_overlay_for_execution(
        config,
        template_path,
        expected_sha256,
        expected_template_sha256,
        PrivateConfigOverlay::WorkspaceD1 { database_binding },
    )
}

#[derive(Clone, Copy)]
enum PrivateConfigOverlay<'a> {
    WorkerDeployment,
    WorkspaceD1 { database_binding: &'a str },
}

#[expect(
    clippy::too_many_lines,
    reason = "one binding transaction keeps no-follow capture, bounded bytes, production and template hashes, closed-overlay equality, immutable staging, and staged-byte readback under one private-config lifetime"
)]
fn bind_private_config_path_with_template_and_overlay_for_execution(
    config: &Path,
    template_path: &Path,
    expected_sha256: Option<&str>,
    expected_template_sha256: Option<&str>,
    overlay: PrivateConfigOverlay<'_>,
) -> Result<BoundPrivateConfig, CliError> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut source_file = options.open(config).map_err(|source| CliError::Io {
        path: config.display().to_string(),
        source,
    })?;
    let metadata = source_file.metadata().map_err(|source| CliError::Io {
        path: config.display().to_string(),
        source,
    })?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > 1_048_576
    {
        return Err(CliError::Input(
            "private Worker production config must be a regular file of at most 1 MiB".to_owned(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(CliError::Input(
                "private Worker production config must not grant group or world permissions"
                    .to_owned(),
            ));
        }
    }
    let production_len = usize::try_from(metadata.len()).map_err(|_| {
        CliError::Input(
            "private Worker production config size exceeded this platform's addressable memory"
                .to_owned(),
        )
    })?;
    let mut production_bytes = Vec::with_capacity(production_len);
    source_file
        .read_to_end(&mut production_bytes)
        .map_err(|source| CliError::Io {
            path: config.display().to_string(),
            source,
        })?;
    if production_bytes.len() > 1_048_576 {
        return Err(CliError::Input(
            "private Worker production config must be at most 1 MiB".to_owned(),
        ));
    }
    let content_sha256 = hex::encode(Sha256::digest(&production_bytes));
    if expected_sha256.is_some_and(|expected| {
        expected.strip_prefix("sha256:").unwrap_or(expected) != content_sha256
    }) {
        return Err(CliError::Input(
            "private Worker production config no longer matches the reviewed content identity"
                .to_owned(),
        ));
    }
    let production_text = std::str::from_utf8(&production_bytes).map_err(|_| {
        CliError::Input("private Worker production config is not valid UTF-8".to_owned())
    })?;
    let production = toml::from_str::<toml::Value>(production_text)
        .ok()
        .and_then(|value| serde_json::to_value(value).ok())
        .ok_or_else(|| {
            CliError::Input("private Worker production config is malformed".to_owned())
        })?;
    let template_bytes = capture_regular_config_bytes(template_path, "tracked Worker template")?;
    let template_content_sha256 = hex::encode(Sha256::digest(&template_bytes));
    if expected_template_sha256.is_some_and(|expected| {
        expected.strip_prefix("sha256:").unwrap_or(expected) != template_content_sha256
    }) {
        return Err(CliError::Input(
            "tracked Worker template no longer matches the reviewed content identity".to_owned(),
        ));
    }
    let template_text = std::str::from_utf8(&template_bytes)
        .map_err(|_| CliError::Input("tracked Worker template is not valid UTF-8".to_owned()))?;
    let template = toml::from_str::<toml::Value>(template_text)
        .ok()
        .and_then(|value| serde_json::to_value(value).ok())
        .ok_or_else(|| CliError::Input("tracked Worker template is malformed".to_owned()))?;
    let mut normalized = production.clone();
    match overlay {
        PrivateConfigOverlay::WorkerDeployment => {
            normalize_private_d1_identity(&mut normalized, &template)?;
        }
        PrivateConfigOverlay::WorkspaceD1 { database_binding } => {
            normalize_workspace_d1_private_config(&mut normalized, &template, database_binding)?;
        }
    }
    if normalized != template {
        return Err(CliError::Input(
            "private Worker production config differs from its tracked role template outside the closed private-config overlay"
                .to_owned(),
        ));
    }
    let private_representations =
        PrivateRepresentationGuard::from_documents(&production, &normalized);

    let expected_staged_bytes = production_bytes;

    let directory = config.parent().ok_or_else(|| {
        CliError::Input("private Worker production config has no containing directory".to_owned())
    })?;
    let mut staged = tempfile::Builder::new()
        .prefix(".cfctl-private-execution-")
        .suffix(".toml")
        .tempfile_in(directory)
        .map_err(|source| CliError::Io {
            path: directory.display().to_string(),
            source,
        })?;
    staged
        .write_all(&expected_staged_bytes)
        .and_then(|()| staged.flush())
        .and_then(|()| staged.as_file().sync_data())
        .map_err(|source| CliError::Io {
            path: staged.path().display().to_string(),
            source,
        })?;
    #[cfg(unix)]
    fs::set_permissions(staged.path(), {
        use std::os::unix::fs::PermissionsExt;
        fs::Permissions::from_mode(0o400)
    })
    .map_err(|source| CliError::Io {
        path: staged.path().display().to_string(),
        source,
    })?;
    let staged_bytes = fs::read(staged.path()).map_err(|source| CliError::Io {
        path: staged.path().display().to_string(),
        source,
    })?;
    if staged_bytes != expected_staged_bytes {
        return Err(CliError::Input(
            "private Worker execution config did not preserve the reviewed bytes".to_owned(),
        ));
    }
    Ok(BoundPrivateConfig {
        staged,
        content_sha256,
        private_representations,
    })
}

fn capture_regular_config_bytes(path: &Path, label: &str) -> Result<Vec<u8>, CliError> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path).map_err(|source| CliError::Io {
        path: path.display().to_string(),
        source,
    })?;
    let before = file.metadata().map_err(|source| CliError::Io {
        path: path.display().to_string(),
        source,
    })?;
    if !before.file_type().is_file() || before.file_type().is_symlink() || before.len() > 1_048_576
    {
        return Err(CliError::Input(format!(
            "{label} must be a regular file of at most 1 MiB"
        )));
    }
    let expected_len = usize::try_from(before.len()).map_err(|_| {
        CliError::Input(format!(
            "{label} size exceeded this platform's addressable memory"
        ))
    })?;
    let mut bytes = Vec::with_capacity(expected_len);
    file.read_to_end(&mut bytes)
        .map_err(|source| CliError::Io {
            path: path.display().to_string(),
            source,
        })?;
    let after = file.metadata().map_err(|source| CliError::Io {
        path: path.display().to_string(),
        source,
    })?;
    if bytes.len() > 1_048_576 || bytes.len() != expected_len || after.len() != before.len() {
        return Err(CliError::Input(format!(
            "{label} changed during its bounded content capture"
        )));
    }
    Ok(bytes)
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
    normalize_private_verified_sender_domains(production, template)?;
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct WorkspaceD1PrivateIdentity {
    pub(super) database_name: String,
    pub(super) database_id: String,
}

pub(super) fn normalize_workspace_d1_private_config(
    production: &mut Value,
    template: &Value,
    database_binding: &str,
) -> Result<WorkspaceD1PrivateIdentity, CliError> {
    if database_binding.is_empty() {
        return Err(CliError::Input(
            "workspace D1 private-config binding is missing".to_owned(),
        ));
    }
    production
        .get("name")
        .and_then(Value::as_str)
        .filter(|value| safe_workspace_d1_name(value))
        .ok_or_else(|| CliError::Input("production Worker name is invalid".to_owned()))?;
    let template_name = template
        .get("name")
        .cloned()
        .ok_or_else(|| CliError::Input("tracked Wrangler Worker name is missing".to_owned()))?;
    production["name"] = template_name;

    let template_databases = template
        .get("d1_databases")
        .and_then(Value::as_array)
        .ok_or_else(|| CliError::Input("tracked Worker template has no D1 databases".to_owned()))?;
    let template_index = unique_workspace_d1_binding_index(
        template_databases,
        database_binding,
        "tracked Worker template",
    )?;
    let template_database = template_databases[template_index]
        .as_object()
        .ok_or_else(|| CliError::Input("tracked Worker D1 binding is not a table".to_owned()))?;

    let production_databases = production
        .get_mut("d1_databases")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| {
            CliError::Input("private Worker production config has no D1 databases".to_owned())
        })?;
    let production_index = unique_workspace_d1_binding_index(
        production_databases,
        database_binding,
        "private Worker production config",
    )?;
    let production_database = production_databases[production_index]
        .as_object_mut()
        .ok_or_else(|| CliError::Input("private Worker D1 binding is not a table".to_owned()))?;
    let database_name = production_database
        .get("database_name")
        .and_then(Value::as_str)
        .filter(|value| safe_workspace_d1_name(value))
        .ok_or_else(|| CliError::Input("production D1 database name is invalid".to_owned()))?
        .to_owned();
    let database_id = production_database
        .get("database_id")
        .and_then(Value::as_str)
        .filter(|value| canonical_workspace_d1_uuid(value))
        .ok_or_else(|| CliError::Input("production D1 database id is invalid".to_owned()))?
        .to_owned();
    if let Some(preview) = production_database.get("preview_database_id") {
        let preview = preview
            .as_str()
            .filter(|value| canonical_workspace_d1_uuid(value))
            .ok_or_else(|| {
                CliError::Input("production preview D1 database id is invalid".to_owned())
            })?;
        if preview != database_id.as_str() {
            return Err(CliError::Input(
                "a production config that declares preview_database_id must bind it to the same D1 database; use a separate governed preview config for an isolated preview database"
                    .to_owned(),
            ));
        }
    }
    for field in ["database_name", "database_id"] {
        let value = template_database
            .get(field)
            .cloned()
            .ok_or_else(|| CliError::Input(format!("tracked Worker D1 {field} is missing")))?;
        production_database.insert(field.to_owned(), value);
    }
    if let Some(preview) = template_database.get("preview_database_id") {
        production_database.insert("preview_database_id".to_owned(), preview.clone());
    } else {
        production_database.remove("preview_database_id");
    }

    normalize_private_sender_identity(production, template)?;
    normalize_private_relay_activation(production, template)?;
    normalize_private_verified_sender_domains(production, template)?;
    Ok(WorkspaceD1PrivateIdentity {
        database_name,
        database_id,
    })
}

fn unique_workspace_d1_binding_index(
    databases: &[Value],
    database_binding: &str,
    owner: &str,
) -> Result<usize, CliError> {
    let matches = databases
        .iter()
        .enumerate()
        .filter(|(_, database)| {
            database.get("binding").and_then(Value::as_str) == Some(database_binding)
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if matches.len() == 1 {
        Ok(matches[0])
    } else {
        Err(CliError::Input(format!(
            "{owner} must contain exactly one selected D1 binding"
        )))
    }
}

fn canonical_workspace_d1_uuid(value: &str) -> bool {
    value != "00000000-0000-0000-0000-000000000000"
        && uuid::Uuid::parse_str(value).is_ok_and(|parsed| parsed.hyphenated().to_string() == value)
}

fn safe_workspace_d1_name(value: &str) -> bool {
    (1..=63).contains(&value.len())
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value
            .bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn normalize_private_verified_sender_domains(
    production: &mut Value,
    template: &Value,
) -> Result<(), CliError> {
    const KEY: &str = "MAILDESK_VERIFIED_SENDER_DOMAINS";
    let template_value = template
        .get("vars")
        .and_then(Value::as_object)
        .and_then(|vars| vars.get(KEY))
        .and_then(Value::as_str)
        .filter(|value| value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "tracked Worker template must declare the empty verified-sender domain sentinel"
                    .to_owned(),
            )
        })?;
    let production_vars = production
        .get_mut("vars")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            CliError::Input(
                "private Worker production config must materialize verified-sender domains"
                    .to_owned(),
            )
        })?;
    let production_value = production_vars
        .get(KEY)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "private Worker production config must materialize verified-sender domains"
                    .to_owned(),
            )
        })?;
    validate_maildesk_verified_sender_domains(production_value)?;
    production_vars.insert(KEY.to_owned(), Value::String(template_value.to_owned()));
    Ok(())
}

pub(super) fn validate_maildesk_verified_sender_domains(value: &str) -> Result<(), CliError> {
    const MAX_ENTRIES: usize = 256;
    const MAX_BYTES: usize = 4_096;
    let invalid = || {
        CliError::Input(
            "private verified-sender domains must be a bounded comma-separated list of canonical lowercase DNS domains"
                .to_owned(),
        )
    };
    if value.is_empty() || value.len() > MAX_BYTES || !value.is_ascii() {
        return Err(invalid());
    }
    let domains = value.split(',').collect::<Vec<_>>();
    if !(1..=MAX_ENTRIES).contains(&domains.len()) {
        return Err(invalid());
    }
    let mut normalized = BTreeSet::new();
    for domain in domains {
        let lowercase = domain.to_ascii_lowercase();
        if domain != lowercase
            || !normalized.insert(lowercase)
            || domain.len() > 253
            || domain.starts_with('.')
            || domain.ends_with('.')
            || domain
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        {
            return Err(invalid());
        }
        let labels = domain.split('.').collect::<Vec<_>>();
        if labels.len() < 2
            || labels.iter().any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || !label.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
                    || !label
                        .as_bytes()
                        .first()
                        .is_some_and(u8::is_ascii_alphanumeric)
                    || !label
                        .as_bytes()
                        .last()
                        .is_some_and(u8::is_ascii_alphanumeric)
            })
        {
            return Err(invalid());
        }
    }
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
        || !canonical_worker_version_id(version_id)
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
        if require_singular_active {
            return Err(CliError::Input(
                "Worker deployment planning requires one prior active version for rollback; the exact Worker does not exist"
                    .to_owned(),
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

pub(super) fn current_active_deployment_identity(
    deployments: &Value,
) -> Result<(&str, &str), CliError> {
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
    let strict_planning = plan.capability.id == WORKER_DEPLOYMENT_PLAN_CAPABILITY_ID;
    let exact_field_count = match (strict_planning, exists) {
        (false, Some(false)) => 7,
        (false, Some(true)) => 12,
        (true, Some(true)) => 13,
        _ => 0,
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
    let strict_current_active_is_exact = !strict_planning
        || receipt
            .get("current_active")
            .and_then(Value::as_object)
            .is_some_and(|current| {
                current.len() == 3
                    && current
                        .get("deployment_id")
                        .and_then(Value::as_str)
                        .is_some_and(|value| !value.is_empty())
                    && current
                        .get("version_id")
                        .and_then(Value::as_str)
                        .is_some_and(|value| !value.is_empty())
                    && current.get("traffic_percentage").and_then(Value::as_u64) == Some(100)
            });
    if !exact || !existing_state_is_exact || !strict_current_active_is_exact {
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;
