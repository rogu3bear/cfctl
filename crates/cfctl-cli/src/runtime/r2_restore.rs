//! Authenticated capture selection and private, plan-bound recovery custody.
use super::prelude::{
    CallInput, CatalogSnapshot, CliError, PlanV1, ProfilesConfig, Result, SecretStore, StateStore,
    Value, json,
};
use cfctl_auth::ProfileMetadata;
use cfctl_core::{
    hash_value,
    r2_recovery::{CaptureManifestV1, CaptureReceiptV1, MAX_BYTES, MAX_MANIFEST_BYTES, VERIFY_ID},
    r2_restore::{
        self as contract, CaptureRefV1, CurrentExpectationV1, RestoreRequestV1, RestoreSelectionV1,
    },
};
use cfctl_storage::PrivateDirectory;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    path::{Component, Path, PathBuf},
};
use uuid::Uuid;

const NAMESPACE: &str = "r2-private-restore";
const ROOT_NAME: &str = "r2-restore-stages";
const TARGET: &str = "/adapter/r2_private_restore";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateSources {
    source_capture_directory: PathBuf,
    current_capture_directory: PathBuf,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StageBinding {
    schema_version: u8,
    id: String,
    profile_id: String,
    credential_generation_id: String,
    selection_sha256: String,
}

pub(super) struct LoadedRestore {
    pub(super) selection: RestoreSelectionV1,
    pub(super) source_window: cfctl_core::r2_recovery::CaptureWindowV1,
    pub(super) source_bytes: Vec<u8>,
    pub(super) token_id: Option<String>,
}

pub(super) fn rejected() -> CliError {
    CliError::Input("private restore requires the exact authenticated source/current capture members and immutable managed files; no private value was disclosed".into())
}

fn open_private(path: &Path) -> Result<PrivateDirectory> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
        || path.canonicalize().ok().as_deref() != Some(path)
    {
        return Err(rejected());
    }
    PrivateDirectory::open(path).map_err(|_| rejected())
}

fn verified_snapshot(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    input: &CallInput,
    reference: &CaptureRefV1,
    path: &Path,
) -> Result<(PrivateDirectory, CaptureManifestV1)> {
    let cap = catalog.get(VERIFY_ID).ok_or_else(rejected)?;
    let verify_input = CallInput {
        selectors: input.selectors.clone(),
        query: json!({}),
        body: Some(
            json!({"capture_evidence_hash":reference.evidence_hash,"capture_run_id":reference.run_id}),
        ),
        ..CallInput::default()
    };
    let verified = super::r2_recovery::verify(store, cap, &verify_input, path)?;
    let receipt: CaptureReceiptV1 = serde_json::from_value(verified.result["capture"].clone())?;
    let directory = open_private(path)?;
    let encoded = directory
        .read("manifest.json", MAX_MANIFEST_BYTES)
        .map_err(|_| rejected())?
        .ok_or_else(rejected)?;
    if hex::encode(Sha256::digest(&encoded)) != receipt.manifest_sha256 {
        return Err(rejected());
    }
    let manifest = serde_json::from_slice(&encoded).map_err(|_| rejected())?;
    Ok((directory, manifest))
}

fn select(
    input: &CallInput,
    request: &RestoreRequestV1,
    source: &CaptureManifestV1,
    current: &CaptureManifestV1,
) -> Result<RestoreSelectionV1> {
    request.validate().map_err(|_| rejected())?;
    if input.selectors != json!({"account_id":source.account_id,"bucket_name":source.bucket_name})
        || source.account_id != current.account_id
        || source.bucket_name != current.bucket_name
        || source.run_id != request.source_capture.run_id
        || current.run_id != request.current_capture.run_id
        || input.query.as_object().is_none_or(|q| !q.is_empty())
        || input.if_match.is_some()
        || input.if_none_match.is_some()
    {
        return Err(rejected());
    }
    let selected = source
        .objects
        .get(request.source_object_index)
        .ok_or_else(rejected)?;
    let key = &selected.provider_metadata["key"];
    let displaced = match request.expected_current {
        CurrentExpectationV1::Absent {} => {
            if current
                .objects
                .iter()
                .any(|o| &o.provider_metadata["key"] == key)
            {
                return Err(rejected());
            }
            None
        }
        CurrentExpectationV1::Present { object_index } => {
            let member = current.objects.get(object_index).ok_or_else(rejected)?;
            if &member.provider_metadata["key"] != key {
                return Err(rejected());
            }
            Some(member.clone())
        }
    };
    Ok(RestoreSelectionV1 {
        schema_version: 1,
        account_id: source.account_id.clone(),
        bucket_name: source.bucket_name.clone(),
        window: current.window.clone(),
        request: request.clone(),
        source: selected.clone(),
        displaced,
    })
}

fn request(input: &CallInput) -> Result<RestoreRequestV1> {
    let request: RestoreRequestV1 =
        serde_json::from_value(input.body.clone().ok_or_else(rejected)?).map_err(|_| rejected())?;
    request.validate().map_err(|_| rejected())?;
    Ok(request)
}

#[expect(
    clippy::too_many_lines,
    reason = "authenticate both snapshots, preserve and recheck managed copies, then publish one private plan binding without an intermediate usable stage"
)]
pub(super) fn prepare(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    input: &CallInput,
    profile: &ProfileMetadata,
    private_sources: &Path,
    secrets: &dyn SecretStore,
) -> Result<Value> {
    let parent = open_private(private_sources.parent().ok_or_else(rejected)?)?;
    let name = private_sources
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(rejected)?;
    let paths: PrivateSources = serde_json::from_slice(
        &parent
            .read(name, 16 * 1024)
            .map_err(|_| rejected())?
            .ok_or_else(rejected)?,
    )
    .map_err(|_| rejected())?;
    let request = request(input)?;
    let (source_dir, source) = verified_snapshot(
        store,
        catalog,
        input,
        &request.source_capture,
        &paths.source_capture_directory,
    )?;
    let (current_dir, current) = verified_snapshot(
        store,
        catalog,
        input,
        &request.current_capture,
        &paths.current_capture_directory,
    )?;
    let selection = select(input, &request, &source, &current)?;
    selection.validate(Utc::now()).map_err(|_| rejected())?;
    super::r2_restore_credentials::qualify(
        store,
        catalog,
        profile,
        &selection.account_id,
        &request,
        selection.window.expires_at,
    )?;
    let data = open_private(&store.paths().data_dir)?;
    let root_path = store.paths().data_dir.join(ROOT_NAME);
    let root = if root_path.exists() {
        open_private(&root_path)?
    } else {
        data.create_new_directory(ROOT_NAME)
            .map_err(|_| rejected())?
    };
    let id = Uuid::new_v4().to_string();
    let stage = root.create_new_directory(&id).map_err(|_| rejected())?;
    let staged_source = stage
        .create_new_directory("source")
        .map_err(|_| rejected())?;
    let staged_current = stage
        .create_new_directory("current")
        .map_err(|_| rejected())?;
    copy_snapshot(&source_dir, &source, &staged_source)?;
    copy_snapshot(&current_dir, &current, &staged_current)?;
    let staged_path = root_path.join(&id);
    verified_snapshot(
        store,
        catalog,
        input,
        &request.source_capture,
        &staged_path.join("source"),
    )?;
    verified_snapshot(
        store,
        catalog,
        input,
        &request.current_capture,
        &staged_path.join("current"),
    )?;
    selection.validate(Utc::now()).map_err(|_| rejected())?;
    super::r2_restore_credentials::qualify(
        store,
        catalog,
        profile,
        &selection.account_id,
        &request,
        selection.window.expires_at,
    )?;
    stage.sync().map_err(|_| rejected())?;
    root.sync().map_err(|_| rejected())?;
    data.sync().map_err(|_| rejected())?;
    let selection_hash = hash_value(&serde_json::to_value(&selection)?)?;
    let generation = profile
        .credential_generation_id
        .clone()
        .ok_or_else(rejected)?;
    let stage_ref = format!("{NAMESPACE}/{id}");
    secrets.put(
        &stage_ref,
        &serde_json::to_string(&StageBinding {
            schema_version: 1,
            id,
            profile_id: profile.id.clone(),
            credential_generation_id: generation.clone(),
            selection_sha256: selection_hash.clone(),
        })?,
    )?;
    let expected = selection.expected_result().map_err(|_| rejected())?;
    let object_key_sha256 = selection.object_key_sha256().map_err(|_| rejected())?;
    Ok(
        json!({"schema_version":1,"stage_ref":stage_ref,"selection_sha256":selection_hash,
        "profile_id":profile.id,"credential_generation_id":generation,"source_sha256":selection.source.sha256,
        "object_key_sha256":object_key_sha256,"source_semantic_metadata_sha256":expected.semantic_metadata_sha256,
        "source_bytes":selection.source.byte_count,"current_capture_bytes":current.total_bytes,
        "window":selection.window,"displaced_bytes_preserved":selection.displaced.is_some(),
        "metadata_atomic_precondition":false,"writer_exclusion_qualified":false,"combined_recovery_ready":false}),
    )
}

fn copy_snapshot(
    source: &PrivateDirectory,
    manifest: &CaptureManifestV1,
    target: &PrivateDirectory,
) -> Result<()> {
    for object in &manifest.objects {
        let bytes = source
            .read(&object.blob, MAX_BYTES)
            .map_err(|_| rejected())?
            .ok_or_else(rejected)?;
        if bytes.len() as u64 != object.byte_count
            || hex::encode(Sha256::digest(&bytes)) != object.sha256
        {
            return Err(rejected());
        }
        let mut file = target
            .create_new_file(&object.blob)
            .map_err(|_| rejected())?;
        file.write_all(&bytes).map_err(|_| rejected())?;
        file.sync_all().map_err(|_| rejected())?;
    }
    let encoded = source
        .read("manifest.json", MAX_MANIFEST_BYTES)
        .map_err(|_| rejected())?
        .ok_or_else(rejected)?;
    if serde_json::from_slice::<CaptureManifestV1>(&encoded).map_err(|_| rejected())? != *manifest {
        return Err(rejected());
    }
    let mut file = target
        .create_new_file("manifest.json")
        .map_err(|_| rejected())?;
    file.write_all(&encoded).map_err(|_| rejected())?;
    file.sync_all().map_err(|_| rejected())?;
    source.sync().map_err(|_| rejected())?;
    target.sync().map_err(|_| rejected())?;
    Ok(())
}

pub(super) fn validate_bound_plan(store: &StateStore, plan: &PlanV1) -> Result<()> {
    if plan.capability.id != contract::RESTORE_ID {
        return Ok(());
    }
    load(store, plan, true).map(|_| ())
}

pub(super) fn load(store: &StateStore, plan: &PlanV1, for_write: bool) -> Result<LoadedRestore> {
    load_with_secrets(
        store,
        plan,
        for_write,
        &super::credential_resolution::platform_secrets(store),
    )
}

pub(super) fn load_with_secrets(
    store: &StateStore,
    plan: &PlanV1,
    for_write: bool,
    secrets: &dyn SecretStore,
) -> Result<LoadedRestore> {
    if !contract::capability_matches(&plan.capability) || plan.permission_lane != "api_token" {
        return Err(rejected());
    }
    let target = plan.targets.pointer(TARGET).ok_or_else(rejected)?;
    let stage_ref = target["stage_ref"].as_str().ok_or_else(rejected)?;
    let id = stage_ref
        .strip_prefix(&format!("{NAMESPACE}/"))
        .ok_or_else(rejected)?;
    if !Uuid::parse_str(id).is_ok_and(|uuid| uuid.to_string() == id) {
        return Err(rejected());
    }
    let binding: StageBinding =
        serde_json::from_str(&secrets.get(stage_ref)?.ok_or_else(rejected)?)
            .map_err(|_| rejected())?;
    if binding.schema_version != 1
        || binding.id != id
        || binding.profile_id != plan.profile_id
        || target["selection_sha256"] != binding.selection_sha256
        || target["profile_id"] != binding.profile_id
        || target["credential_generation_id"] != binding.credential_generation_id
    {
        return Err(rejected());
    }
    let catalog = CatalogSnapshot::load(&store.paths().catalog_file())?;
    let input: CallInput = serde_json::from_value(plan.input.clone())?;
    let request = request(&input)?;
    let path = store.paths().data_dir.join(ROOT_NAME).join(id);
    let stage = open_private(&path)?;
    let (source_dir, source) = verified_snapshot(
        store,
        &catalog,
        &input,
        &request.source_capture,
        &path.join("source"),
    )?;
    let (_, current) = verified_snapshot(
        store,
        &catalog,
        &input,
        &request.current_capture,
        &path.join("current"),
    )?;
    let selection = select(&input, &request, &source, &current)?;
    let expected = selection.expected_result().map_err(|_| rejected())?;
    if hash_value(&serde_json::to_value(&selection)?)? != binding.selection_sha256
        || selection.account_id != plan.account_id
        || target["window"] != serde_json::to_value(&selection.window)?
        || target["source_sha256"] != selection.source.sha256
        || target["source_bytes"].as_u64() != Some(selection.source.byte_count)
        || target["object_key_sha256"] != selection.object_key_sha256().map_err(|_| rejected())?
        || target["source_semantic_metadata_sha256"] != expected.semantic_metadata_sha256
    {
        return Err(rejected());
    }
    let profiles = ProfilesConfig::load(store)?;
    let profile = profiles.selected(Some(&plan.profile_id))?;
    super::r2_restore_credentials::check_profile(profile, &plan.account_id)?;
    let token_id = if for_write {
        selection.validate(Utc::now()).map_err(|_| rejected())?;
        if profile.credential_generation_id.as_deref()
            != Some(binding.credential_generation_id.as_str())
        {
            return Err(rejected());
        }
        Some(super::r2_restore_credentials::qualify(
            store,
            &catalog,
            profile,
            &plan.account_id,
            &request,
            selection.window.expires_at,
        )?)
    } else {
        selection
            .validate(selection.window.opened_at)
            .map_err(|_| rejected())?;
        None
    };
    let source_bytes = source_dir
        .read(&selection.source.blob, MAX_BYTES)
        .map_err(|_| rejected())?
        .ok_or_else(rejected)?;
    if source_bytes.len() as u64 != selection.source.byte_count
        || hex::encode(Sha256::digest(&source_bytes)) != selection.source.sha256
    {
        return Err(rejected());
    }
    stage.sync().map_err(|_| rejected())?;
    Ok(LoadedRestore {
        selection,
        source_window: source.window,
        source_bytes,
        token_id,
    })
}

#[cfg(test)]
#[path = "r2_restore_tests.rs"]
mod tests;
