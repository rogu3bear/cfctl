//! Admission and owned staging for an already-built Worker artifact.
use std::{
    fs,
    path::{Path, PathBuf},
};

use cfctl_core::worker_frozen_upload::{
    ARTIFACT_MODE as MODE, CAPABILITY_ID as CAPABILITY, FrozenArtifactUploadV1,
};
use cfctl_workspace::{
    RegisteredRoot, WorkspaceGraph, WranglerConfigSnapshot, load_wrangler_config_snapshot,
    parse_wrangler_config_snapshot,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::prelude::{CallInput, CapabilityV1, CliError, Result};
use super::{
    worker_deployment, worker_frozen_config, worker_frozen_files as files, worker_frozen_modules,
    wrangler_producer,
};

pub(super) fn requested(capability: &CapabilityV1, input: &CallInput) -> Result<bool> {
    let Some(mode) = input.query.get("artifact_mode") else {
        return Ok(false);
    };
    if capability.id != CAPABILITY
        || capability.method != "CLI"
        || capability.path != "wrangler versions upload"
        || mode.as_str() != Some(MODE)
    {
        return Err(CliError::Input(
            "artifact_mode=frozen-artifact is supported only for Worker version upload".to_owned(),
        ));
    }
    Ok(true)
}

fn validate_input(capability: &CapabilityV1, input: &CallInput) -> Result<()> {
    if !requested(capability, input)? {
        return Err(files::failure("explicit artifact_mode is required"));
    }
    if input.body.is_some()
        || input.if_match.is_some()
        || input.if_none_match.is_some()
        || (!input.selectors.is_null()
            && input
                .selectors
                .as_object()
                .is_none_or(|value| !value.is_empty()))
    {
        return Err(files::failure(
            "frozen upload accepts only its closed query controls",
        ));
    }
    let query = input
        .query
        .as_object()
        .ok_or_else(|| files::failure("query must be an object"))?;
    if query.keys().any(|key| {
        !matches!(
            key.as_str(),
            "config" | "name" | "message" | "artifact_mode"
        )
    }) {
        return Err(files::failure(
            "frozen upload does not admit entry overrides or extra Wrangler flags",
        ));
    }
    Ok(())
}

pub(super) fn config_snapshot(
    capability: &CapabilityV1,
    input: &CallInput,
    config: &Path,
) -> Result<WranglerConfigSnapshot> {
    if !requested(capability, input)? {
        return Ok(load_wrangler_config_snapshot(config)?);
    }
    validate_input(capability, input)?;
    if input
        .query
        .get("config")
        .and_then(Value::as_str)
        .map(Path::new)
        != Some(config)
    {
        return Err(files::failure(
            "config selector must be its canonical absolute path",
        ));
    }
    Ok(parse_wrangler_config_snapshot(
        config,
        &files::config_bytes(config)?,
    )?)
}

fn text<'a>(value: &'a Value, pointer: &str) -> Result<&'a str> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| files::failure("immutable Worker target omitted a required identity"))
}

fn roots(target: &Value) -> Result<Vec<PathBuf>> {
    target
        .pointer("/artifact/roots")
        .and_then(Value::as_array)
        .ok_or_else(|| files::failure("immutable Worker target omitted artifact roots"))?
        .iter()
        .map(|root| {
            root.as_str()
                .map(PathBuf::from)
                .ok_or_else(|| files::failure("immutable artifact root is invalid"))
        })
        .collect()
}

pub(super) fn attach(
    capability: &CapabilityV1,
    input: &CallInput,
    snapshot: &WranglerConfigSnapshot,
    target: &mut Value,
) -> Result<()> {
    if !requested(capability, input)? {
        return Ok(());
    }
    validate_input(capability, input)?;
    let repository = Path::new(text(target, "/repository")?);
    let config = Path::new(text(target, "/config/path")?);
    let artifact = files::capture(repository, &roots(target)?)?;
    if artifact.manifest.sha256 != text(target, "/artifact/sha256")? {
        return Err(files::failure("artifact changed during plan admission"));
    }
    let projection =
        worker_frozen_config::project(repository, config, &snapshot.document, &artifact.manifest)?;
    let program = which::which("wrangler")
        .map_err(|_| files::failure("Wrangler is required before plan admission"))?;
    let producer = wrangler_producer::snapshot_at(capability, &program, "versions upload")?;
    let module_graph =
        worker_frozen_modules::inspect(&artifact, &projection, &producer, &snapshot.document)?;
    if files::capture(repository, &roots(target)?)?.manifest != artifact.manifest
        || hex::encode(Sha256::digest(files::config_bytes(config)?))
            != text(target, "/config/sha256")?
    {
        return Err(files::failure(
            "source config or artifact changed during plan admission",
        ));
    }
    target["frozen_artifact"] = serde_json::to_value(FrozenArtifactUploadV1 {
        schema_version: 1,
        artifact_mode: MODE.to_owned(),
        manifest: artifact.manifest,
        projection_sha256: projection.sha256,
        custom_build_suppressed: projection.custom_build_suppressed,
        producer,
        module_graph,
    })?;
    Ok(())
}

fn contract(
    capability: &CapabilityV1,
    input: &CallInput,
    adapter_targets: &Value,
) -> Result<Option<FrozenArtifactUploadV1>> {
    let frozen =
        worker_deployment::target(adapter_targets).and_then(|target| target.get("frozen_artifact"));
    if !requested(capability, input)? {
        if frozen.is_some() {
            return Err(files::failure(
                "frozen transport cannot be downgraded to ordinary upload",
            ));
        }
        return Ok(None);
    }
    validate_input(capability, input)?;
    let frozen: FrozenArtifactUploadV1 =
        serde_json::from_value(frozen.cloned().ok_or_else(|| {
            files::failure("immutable plan omitted frozen-artifact admission; create a new plan")
        })?)
        .map_err(|_| files::failure("immutable frozen-artifact contract is malformed"))?;
    if frozen.schema_version != 1
        || frozen.artifact_mode != MODE
        || frozen.manifest.schema_version != 1
    {
        return Err(files::failure(
            "unsupported frozen-artifact contract version",
        ));
    }
    Ok(Some(frozen))
}

pub(super) struct BoundFrozenArtifact {
    _directory: tempfile::TempDir,
    canonical_directory: PathBuf,
    payload: PathBuf,
    config: PathBuf,
    original_config: PathBuf,
    original_config_sha256: String,
    original_repository: PathBuf,
    original_source_sha: String,
    original_roots: Vec<PathBuf>,
    original_input: CallInput,
    admitted: FrozenArtifactUploadV1,
}

impl BoundFrozenArtifact {
    pub(super) fn config(&self) -> &Path {
        &self.config
    }
    pub(super) fn directory(&self) -> &Path {
        &self.canonical_directory
    }
    pub(super) fn executable(&self) -> Result<PathBuf> {
        Ok(PathBuf::from(text(&self.admitted.producer, "/executable")?))
    }
    pub(super) fn interpreter(&self) -> Result<Option<PathBuf>> {
        let value = self
            .admitted
            .producer
            .get("interpreter")
            .ok_or_else(|| files::failure("producer interpreter identity missing"))?;
        if value.is_null() {
            return Ok(None);
        }
        Ok(Some(PathBuf::from(text(value, "/path")?)))
    }

    pub(super) fn validate_ready(
        &self,
        capability: &CapabilityV1,
        input: &CallInput,
    ) -> Result<()> {
        if input != &self.original_input {
            return Err(files::failure("execution input changed after staging"));
        }
        let graph = WorkspaceGraph::discover(&[RegisteredRoot::new(&self.original_repository)])?;
        let repository = graph
            .repositories
            .iter()
            .find(|repository| repository.path == self.original_repository)
            .ok_or_else(|| files::failure("source repository authority disappeared"))?;
        if repository.git.dirty
            || repository.git.head.as_deref() != Some(self.original_source_sha.as_str())
        {
            return Err(files::failure(
                "source changed before the execution boundary",
            ));
        }
        if files::capture(&self.original_repository, &self.original_roots)?.manifest
            != self.admitted.manifest
            || hex::encode(Sha256::digest(files::config_bytes(&self.original_config)?))
                != self.original_config_sha256
        {
            return Err(files::failure(
                "source config or artifact drifted before execution",
            ));
        }
        let staged_roots = self
            .admitted
            .manifest
            .roots
            .iter()
            .map(|root| self.payload.join(root))
            .collect::<Vec<_>>();
        if files::capture(&self.payload, &staged_roots)?.manifest != self.admitted.manifest
            || hex::encode(Sha256::digest(files::config_bytes(&self.config)?))
                != self.admitted.projection_sha256
        {
            return Err(files::failure(
                "private staged payload changed before execution",
            ));
        }
        let discovered = which::which("wrangler")
            .map_err(|_| files::failure("Wrangler disappeared before execution"))?;
        if wrangler_producer::snapshot_at(capability, &discovered, "versions upload")?
            != self.admitted.producer
        {
            return Err(files::failure(
                "Wrangler executable, interpreter, or dependency closure drifted",
            ));
        }
        Ok(())
    }

    pub(super) fn public_receipt(&self, version_id: Option<&str>) -> Result<Value> {
        if let Some(version_id) = version_id {
            let config = fs::read(&self.config)
                .map_err(|_| files::failure("private receipt config unavailable"))?;
            if String::from_utf8_lossy(&config).contains(version_id) {
                return Err(files::failure(
                    "version identity collided with private configuration",
                ));
            }
        }
        Ok(json!({
            "schema_version": 1, "artifact_mode": MODE,
            "source_sha": self.original_source_sha,
            "canonical_config_sha256": self.original_config_sha256,
            "artifact_sha256": self.admitted.manifest.sha256,
            "projection_sha256": self.admitted.projection_sha256,
            "custom_build_suppressed": self.admitted.custom_build_suppressed,
            "provider_output_retained": false, "produced_version_id": version_id,
        }))
    }
}

pub(super) fn stage(
    capability: &CapabilityV1,
    input: &CallInput,
    adapter_targets: &Value,
) -> Result<Option<BoundFrozenArtifact>> {
    let Some(admitted) = contract(capability, input, adapter_targets)? else {
        return Ok(None);
    };
    let target = worker_deployment::target(adapter_targets)
        .ok_or_else(|| files::failure("Worker target absent"))?;
    if input.query.get("name").and_then(Value::as_str) != Some(text(target, "/service_name")?)
        || input.query.get("message").and_then(Value::as_str)
            != Some(text(target, "/version_message")?)
    {
        return Err(files::failure(
            "Worker name or version message differs from immutable admission",
        ));
    }
    let repository = PathBuf::from(text(target, "/repository")?);
    let config = PathBuf::from(text(target, "/config/path")?);
    let original_roots = roots(target)?;
    let snapshot = config_snapshot(capability, input, &config)?;
    if snapshot.content_hash.strip_prefix("sha256:") != Some(text(target, "/config/sha256")?) {
        return Err(files::failure(
            "canonical config no longer matches immutable plan",
        ));
    }
    let artifact = files::capture(&repository, &original_roots)?;
    if artifact.manifest != admitted.manifest
        || artifact.manifest.sha256 != text(target, "/artifact/sha256")?
    {
        return Err(files::failure("artifact no longer matches immutable plan"));
    }
    let projection = worker_frozen_config::project(
        &repository,
        &config,
        &snapshot.document,
        &artifact.manifest,
    )?;
    if projection.sha256 != admitted.projection_sha256
        || projection.custom_build_suppressed != admitted.custom_build_suppressed
    {
        return Err(files::failure(
            "config projection no longer matches immutable plan",
        ));
    }
    let directory = tempfile::Builder::new()
        .prefix("cfctl-frozen-worker-")
        .tempdir()
        .map_err(|_| files::failure("cannot create private transport directory"))?;
    // macOS tempfile paths commonly begin with the /var -> /private/var
    // system alias. Bind this newly-owned root once; source admission keeps
    // its no-follow component policy unchanged.
    let canonical_directory = fs::canonicalize(directory.path())
        .map_err(|_| files::failure("cannot bind private transport directory"))?;
    let payload = canonical_directory.join("payload");
    fs::create_dir(&payload).map_err(|_| files::failure("cannot create payload directory"))?;
    for path in &artifact.manifest.directories {
        fs::create_dir_all(payload.join(path))
            .map_err(|_| files::failure("cannot create artifact directory"))?;
    }
    for (relative, bytes) in &artifact.bytes {
        files::write_private(&payload.join(relative), bytes)?;
    }
    let staged_config = payload.join("wrangler.json");
    files::write_private(&staged_config, &projection.bytes)?;
    let bound = BoundFrozenArtifact {
        _directory: directory,
        canonical_directory,
        payload,
        config: staged_config,
        original_config: config,
        original_config_sha256: text(target, "/config/sha256")?.to_owned(),
        original_source_sha: text(target, "/source_sha")?.to_owned(),
        original_repository: repository,
        original_roots,
        original_input: input.clone(),
        admitted,
    };
    Ok(Some(bound))
}
