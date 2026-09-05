//! Explicit state-location selection. Publication is the last activation step.
use crate::PrivateFileSecretStore;
use crate::{PrivateDirectory, Result, RuntimePaths, StorageError};
use cfctl_auth::EvidenceKeyManager;
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::os::unix::fs::MetadataExt as _;
use std::sync::Arc;
use std::{fs, path::PathBuf};
use uuid::Uuid;

pub const PRIVATE_MODE_FILE: &str = "private-runtime-v1.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArchivedRuntimeV1 {
    pub schema_version: u8,
    pub epoch_id: String,
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub continuity: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    schema_version: u8,
    epoch_id: String,
}

fn error(error: impl std::fmt::Display) -> StorageError {
    StorageError::EvidenceAuthentication(error.to_string())
}

#[must_use]
pub fn private_control(paths: &RuntimePaths) -> PathBuf {
    paths.config_dir.join("private-runtime-control-v1")
}

pub fn open_private_control(paths: &RuntimePaths) -> Result<PrivateDirectory> {
    // This is ordinary configuration ancestry, not an authority directory.
    fs::create_dir_all(&paths.config_dir).map_err(error)?;
    let metadata = fs::symlink_metadata(&paths.config_dir).map_err(error)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        return Err(error(
            "private runtime control requires owned configuration ancestry",
        ));
    }
    PrivateDirectory::create(&private_control(paths)).map_err(error)
}

pub fn lock_runtime_selection(paths: &RuntimePaths, exclusive: bool) -> Result<fs::File> {
    open_private_control(paths)?.lock(exclusive).map_err(error)
}

pub fn private_epoch_paths(paths: &RuntimePaths, id: &str) -> Result<RuntimePaths> {
    if Uuid::parse_str(id).is_err() || id.len() != 36 {
        return Err(error("invalid private epoch identity"));
    }
    Ok(RuntimePaths::from_root(
        &private_control(paths).join(format!("epoch-{id}")),
    ))
}

pub fn selected_runtime(paths: RuntimePaths) -> Result<RuntimePaths> {
    let control_path = private_control(&paths);
    match fs::symlink_metadata(&control_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(paths),
        Err(source) => return Err(error(source)),
        Ok(_) => {}
    }
    let control = PrivateDirectory::open(&control_path).map_err(error)?;
    let Some(bytes) = control.read("active.json", 4096).map_err(error)? else {
        return Ok(paths);
    };
    let selection: Selection = serde_json::from_slice(&bytes).map_err(error)?;
    if selection.schema_version != 1 {
        return Err(error("unsupported private runtime selection"));
    }
    let selected = private_epoch_paths(&paths, &selection.epoch_id)?;
    let marker = private_runtime_origin(&selected)?
        .ok_or_else(|| error("selected private runtime is incomplete"))?;
    if marker.epoch_id != selection.epoch_id
        || marker.config_dir != paths.config_dir
        || marker.data_dir != paths.data_dir
        || marker.cache_dir != paths.cache_dir
    {
        return Err(error(
            "private runtime origin does not match the selected location",
        ));
    }
    Ok(selected)
}

pub fn private_runtime_origin(paths: &RuntimePaths) -> Result<Option<ArchivedRuntimeV1>> {
    let path = paths.data_dir.join(PRIVATE_MODE_FILE);
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(error(source)),
        Ok(_) => {}
    }
    let bytes = PrivateDirectory::open(&paths.data_dir)
        .map_err(error)?
        .read(PRIVATE_MODE_FILE, 16 * 1024)
        .map_err(error)?
        .ok_or_else(|| error("private runtime marker disappeared"))?;
    let marker: ArchivedRuntimeV1 = serde_json::from_slice(&bytes).map_err(error)?;
    if marker.schema_version != 1
        || Uuid::parse_str(&marker.epoch_id).is_err()
        || marker.continuity != "unavailable_fresh_authority"
        || !marker.config_dir.is_absolute()
        || !marker.data_dir.is_absolute()
        || !marker.cache_dir.is_absolute()
    {
        return Err(error("invalid private runtime origin"));
    }
    Ok(Some(marker))
}

pub fn publish_private_runtime(paths: &RuntimePaths, id: &str) -> Result<()> {
    let selected = private_epoch_paths(paths, id)?;
    let marker = private_runtime_origin(&selected)?
        .ok_or_else(|| error("private runtime is not initialized"))?;
    if marker.epoch_id != id {
        return Err(error("private epoch identity mismatch"));
    }
    let control = open_private_control(paths)?;
    let bytes = serde_json::to_vec(&Selection {
        schema_version: 1,
        epoch_id: id.to_owned(),
    })
    .map_err(error)?;
    if let Some(existing) = control.read("active.json", 4096).map_err(error)? {
        if existing == bytes {
            return Ok(());
        }
        return Err(error("a different runtime is already selected"));
    }
    control.write("active.json", &bytes).map_err(error)
}

impl crate::StateStore {
    /// Re-admit exact restrictive source rules in a staged private runtime.
    /// The new pending bundle is part of the explicitly confirmed transition;
    /// no approval metadata is imported from the archived runtime.
    pub fn admit_private_constraints(
        &self,
        pending: &cfctl_core::AdmissionPolicyBundleV1,
    ) -> Result<()> {
        use cfctl_core::AdmissionPolicyBundleStatusV1;
        if self.private_origin().is_none()
            || pending.status != AdmissionPolicyBundleStatusV1::Pending
        {
            return Err(error(
                "private constraint admission requires a new pending bundle",
            ));
        }
        pending.validate()?;
        let _guard = self.lock_admission_policy()?;
        let bundle = match self.load_admission_bundle(&pending.bundle_id) {
            Ok(existing) => {
                if existing.content_hash != pending.content_hash
                    || existing.status != AdmissionPolicyBundleStatusV1::Active
                {
                    return Err(error(
                        "staged private constraints differ from the confirmed transition",
                    ));
                }
                existing
            }
            Err(StorageError::AdmissionBundleNotFound(_)) => {
                let mut fresh = pending.clone();
                fresh.approve(true)?;
                fresh.activate()?;
                let value = serde_json::to_value(&fresh).map_err(error)?;
                if crate::redact_json(&value) != value {
                    return Err(StorageError::SensitiveData);
                }
                crate::atomic_create(
                    &self.admission_bundle_path(&fresh.bundle_id)?,
                    &serde_json::to_vec_pretty(&fresh).map_err(error)?,
                )?;
                fresh
            }
            Err(error) => return Err(error),
        };
        if let Some(existing) = self.active_admission_pointer()? {
            if existing.bundle_id != bundle.bundle_id
                || existing.content_hash != bundle.content_hash
            {
                return Err(error(
                    "another restrictive policy is active in the staged runtime",
                ));
            }
            return Ok(());
        }
        // Resumes a crash after writing the fresh active bundle but before its
        // pointer; the outer runtime pointer has not yet been published.
        self.write_json(
            &self.active_admission_policy_path(),
            &crate::AdmissionPolicyPointerV1 {
                schema_version: 1,
                bundle_id: bundle.bundle_id,
                content_hash: bundle.content_hash,
            },
        )
    }
}

impl crate::StateStore {
    #[must_use]
    pub fn private_origin(&self) -> Option<&ArchivedRuntimeV1> {
        self.private_origin.as_ref()
    }

    pub fn platform_evidence_key_manager(&self) -> Result<EvidenceKeyManager> {
        if self.private_origin.is_some() {
            return EvidenceKeyManager::new(
                Arc::new(PrivateFileSecretStore::new(
                    self.paths.data_dir.join("private-authority"),
                )),
                self.evidence_location_identity(),
                cfctl_auth::SecretBackend::PrivateFile,
            )
            .map_err(|error| StorageError::EvidenceAuthentication(error.to_string()));
        }
        EvidenceKeyManager::platform(self.evidence_location_identity())
            .map_err(|error| StorageError::EvidenceAuthentication(error.to_string()))
    }

    pub(super) fn reject_archived_operation(&self, operation_id: &str) -> Result<()> {
        let Some(origin) = &self.private_origin else {
            return Ok(());
        };
        let old = RuntimePaths {
            config_dir: origin.config_dir.clone(),
            data_dir: origin.data_dir.clone(),
            cache_dir: origin.cache_dir.clone(),
        };
        let directory = PrivateDirectory::open(&private_control(&old))
            .map_err(|error| StorageError::EvidenceAuthentication(error.to_string()))?;
        let bytes = directory
            .read(&format!("plan-{}.json", origin.epoch_id), 4 * 1024 * 1024)
            .map_err(|error| StorageError::EvidenceAuthentication(error.to_string()))?
            .ok_or_else(|| {
                StorageError::EvidenceAuthentication(
                    "private transition history is missing".to_owned(),
                )
            })?;
        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|error| StorageError::EvidenceAuthentication(error.to_string()))?;
        if value
            .get("history")
            .and_then(Value::as_object)
            .is_some_and(|history| history.contains_key(operation_id))
        {
            return Err(StorageError::ArchivedOperation {
                operation_id: operation_id.to_owned(),
                archive: origin.data_dir.display().to_string(),
            });
        }
        Ok(())
    }
}

impl RuntimePaths {
    pub fn discover() -> Result<Self> {
        selected_runtime(Self::unselected()?)
    }

    pub fn unselected() -> Result<Self> {
        if let Some(root) = std::env::var_os("CFCTL_HOME") {
            let root = PathBuf::from(root);
            if !root.is_absolute() {
                return Err(StorageError::InvalidRuntimeRoot(root.display().to_string()));
            }
            return Ok(Self::from_root(&root));
        }
        let project = ProjectDirs::from("io", "cfctl", "cfctl")
            .ok_or(StorageError::PlatformDirectoriesUnavailable)?;
        Ok(Self {
            config_dir: project.config_dir().to_path_buf(),
            data_dir: project.data_dir().to_path_buf(),
            cache_dir: project.cache_dir().to_path_buf(),
        })
    }
}
