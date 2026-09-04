//! Platform-local persistence for plans, evidence, catalogs, and registered roots.

mod private_runtime;
pub use private_runtime::*;
mod private_files;
pub use private_files::{PrivateDirectory, PrivateFileSecretStore};
mod evidence;
mod observations;

use evidence::{
    atomic_create_capability_file, open_evidence_directories, read_optional_capability_file,
    require_same_canonical_data_root, require_same_capability_directory,
    require_same_capability_entry,
};

use std::{
    fs,
    io::Write,
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use cap_std::fs::Dir;
use cfctl_auth::EvidenceMacProvider;
use cfctl_core::{
    AdmissionPolicyBundleStatusV1, AdmissionPolicyBundleV1, DeploymentPlanSetV1,
    OperationalProofV1, PlanV1, PlanV2, StandingAuthorityStatus, StandingAuthorityV1, redact_json,
    redact_json_schema,
};
use cfctl_workspace::{
    WORKSPACE_MANIFEST_SCHEMA_VERSION, WorkspaceManifestV1, WorkspaceRegistrationV1,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("platform configuration directories are unavailable")]
    PlatformDirectoriesUnavailable,
    #[error("CFCTL_HOME must be an absolute path, got `{0}`")]
    InvalidRuntimeRoot(String),
    #[error("storage I/O failed for {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error(
        "managed write reached replacement for {path}, but containing-directory sync failed; state may have changed but is not durably confirmed, so reload the exact document before retrying: {source}"
    )]
    WriteDurabilityUnknown {
        path: String,
        source: std::io::Error,
    },
    #[error("stored JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error(
        "managed capability publication crossed for {path}, but temporary alias `{temporary_name}` could not be removed; do not replay the write, and resolve the exact alias before lifecycle scans continue. Directory durability: {directory_durability}. Cleanup error: {source}"
    )]
    CapabilityPublicationCleanupFailed {
        path: String,
        temporary_name: String,
        directory_durability: String,
        source: std::io::Error,
    },
    #[error("the document contains secret material; store a keychain reference instead")]
    SensitiveData,
    #[error("plan transaction state is invalid: {0}")]
    InvalidPlan(#[from] cfctl_core::CoreError),
    #[error("import path escapes the managed data directory: `{0}`")]
    UnsafeImportPath(String),
    #[error("plan `{0}` does not exist")]
    PlanNotFound(String),
    #[error("plan v2 pins for `{0}` do not exist")]
    PlanV2NotFound(String),
    #[error("deployment plan set `{0}` does not exist")]
    DeploymentPlanSetNotFound(String),
    #[error("deployment plan set `{0}` already exists")]
    DeploymentPlanSetAlreadyExists(String),
    #[error("deployment plan set identifier `{0}` is not a canonical lowercase hyphenated UUID")]
    InvalidDeploymentPlanSetId(String),
    #[error(
        "plan `{0}` has a PlanV2 compatibility projection that disagrees with its canonical document"
    )]
    PlanProjectionDrift(String),
    #[error("plan `{operation_id}` is corrupt: {reason}")]
    CorruptPlan {
        operation_id: String,
        reason: String,
    },
    #[error(
        "canonical PlanV2 `{operation_id}` was stored, but its PlanV1 compatibility projection could not be updated: {reason}"
    )]
    PlanProjectionWriteFailed {
        operation_id: String,
        reason: String,
    },
    #[error("standing authority `{0}` does not exist")]
    AuthorityNotFound(String),
    #[error("plan identifier `{0}` is not a canonical lowercase hyphenated UUID")]
    InvalidPlanId(String),
    #[error("standing authority identifier `{0}` is not a canonical lowercase hyphenated UUID")]
    InvalidAuthorityId(String),
    #[error("managed document `{path}` is unsafe: {reason}")]
    UnsafeManagedDocument { path: String, reason: String },
    #[error(
        "managed {kind} filename identifier `{filename_id}` does not match document identifier `{document_id}`"
    )]
    ManagedDocumentIdentityMismatch {
        kind: &'static str,
        filename_id: String,
        document_id: String,
    },
    #[error("standing authority `{0}` already exists")]
    AuthorityAlreadyExists(String),
    #[error("admission policy bundle `{0}` does not exist")]
    AdmissionBundleNotFound(String),
    #[error("admission policy bundle `{0}` already exists")]
    AdmissionBundleAlreadyExists(String),
    #[error(
        "admission policy bundle identifier `{0}` is not a canonical lowercase hyphenated UUID"
    )]
    InvalidAdmissionBundleId(String),
    #[error("active admission policy pointer is invalid: {0}")]
    InvalidAdmissionPointer(String),
    #[error("workspace manifest is invalid: {0}")]
    InvalidWorkspaceManifest(String),
    #[error("the standing authority lock guard does not authorize saving `{0}`")]
    AuthorityLockMismatch(String),
    #[error("standing authority `{0}` is durably revoked and cannot be restored")]
    AuthorityRevocationRollback(String),
    #[error("plan `{0}` is already locked")]
    PlanLocked(String),
    #[error("Worker deployment target `{account_id}/{script_name}` is already locked")]
    WorkerDeploymentLocked {
        account_id: String,
        script_name: String,
    },
    #[error("Email Routing catch-all target `{account_id}/{zone_id}` is already locked")]
    EmailRoutingCatchAllLocked { account_id: String, zone_id: String },
    #[error(
        "operation `{operation_id}` belongs to preserved historical state at {archive}; inspect `cfctl auth evidence-key private-history`; historical approvals cannot run in the new runtime"
    )]
    ArchivedOperation {
        operation_id: String,
        archive: String,
    },
    #[error("system clock is before the Unix epoch")]
    Clock,
    #[error("operational proof is invalid: {0}")]
    InvalidOperationalProof(String),
    #[error("evidence authentication failed: {0}")]
    EvidenceAuthentication(String),
}

pub type Result<T> = std::result::Result<T, StorageError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePaths {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub cache_dir: PathBuf,
}

impl RuntimePaths {
    #[must_use]
    pub fn from_root(root: &Path) -> Self {
        Self {
            config_dir: root.join("config"),
            data_dir: root.join("data"),
            cache_dir: root.join("cache"),
        }
    }

    #[must_use]
    pub fn profiles_file(&self) -> PathBuf {
        self.config_dir.join("profiles.json")
    }

    #[must_use]
    pub fn catalog_file(&self) -> PathBuf {
        self.data_dir.join("catalog").join("catalog-v1.json")
    }

    #[must_use]
    pub fn catalog_previous_file(&self) -> PathBuf {
        self.data_dir
            .join("catalog")
            .join("catalog-v1.previous.json")
    }
}

#[derive(Clone)]
pub struct StateStore {
    paths: RuntimePaths,
    evidence_directories: Arc<EvidenceDirectoryCapabilities>,
    evidence_authenticator: Option<Arc<dyn EvidenceMacProvider>>,
    observation_attestation: Option<cfctl_core::AttestationStatusV1>,
    private_origin: Option<ArchivedRuntimeV1>,
}

impl std::fmt::Debug for StateStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StateStore")
            .field("paths", &self.paths)
            .field(
                "evidence_authenticator",
                &self.evidence_authenticator.as_ref().map(|_| "configured"),
            )
            .finish_non_exhaustive()
    }
}

struct EvidenceDirectoryCapabilities {
    data: Dir,
    data_identity: Vec<u8>,
    locks: Dir,
    lifecycle_lock: cap_std::fs::File,
    bodies: Dir,
    bodies_identity: Vec<u8>,
    descriptors: Dir,
    descriptors_identity: Vec<u8>,
    proofs: Dir,
    proofs_identity: Vec<u8>,
    location_identity: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EvidenceRootMarkerV1 {
    schema_version: u8,
    state_root_identity: String,
}

/// A bounded projection of the most recently indexed qualifying proof rows,
/// plus complete classification counts for immutable legacy history and
/// candidate-envelope failures. `total_count` describes valid index filenames
/// encountered; callers must preserve `truncated` so retained qualifying rows
/// are never presented as full qualifying history.
#[derive(Debug, Clone, PartialEq)]
pub struct OperationalProofPageV1 {
    pub proofs: Vec<OperationalProofV1>,
    pub failures: Vec<OperationalProofFailureV1>,
    pub total_count: usize,
    pub legacy_nonqualifying_count: usize,
    pub truncated: bool,
}

/// One candidate qualifying proof that could not be authenticated. Authentication
/// failures are unscoped unless separately authenticated metadata supplies scope;
/// an unscoped failure must be treated as relevant to every consumer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OperationalProofFailureV1 {
    pub account_id: Option<String>,
    pub proof_identity: String,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AuthenticatedEvidenceArtifactCountsV1 {
    pub descriptor_count: usize,
    pub proof_count: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AdmissionActivationV1 {
    pub bundle: AdmissionPolicyBundleV1,
    pub previous_bundle_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AdmissionPolicyPointerV1 {
    schema_version: u8,
    bundle_id: String,
    content_hash: String,
}

/// Storage-owned classification of the durable plan format.
///
/// `PlanV2` is canonical for current plans. `PlanV1` remains a readable
/// compatibility projection and a historical format, but it never silently
/// grants execution compatibility once the `PlanV2` boundary is active.
#[derive(Debug, Clone, PartialEq)]
pub enum StoredPlanRecord {
    Current(Box<PlanV2>),
    LegacyReadable(Box<PlanV1>),
    RequiredSidecarMissing(Box<PlanV1>),
    ProjectionDrift {
        current: Box<PlanV2>,
        projection: Box<PlanV1>,
    },
    Corrupt {
        operation_id: String,
        reason: String,
    },
}

impl StoredPlanRecord {
    #[must_use]
    pub const fn execution_compatible(&self) -> bool {
        matches!(self, Self::Current(_))
    }

    #[must_use]
    pub const fn execution_incompatibility_reason(&self) -> Option<&'static str> {
        match self {
            Self::Current(_) => None,
            Self::LegacyReadable(_) => Some("legacy_plan_v1"),
            Self::RequiredSidecarMissing(_) => Some("required_plan_v2_missing"),
            Self::ProjectionDrift { .. } => Some("plan_v2_projection_drift"),
            Self::Corrupt { .. } => Some("corrupt_plan_record"),
        }
    }

    #[must_use]
    pub const fn readable_plan(&self) -> Option<&PlanV1> {
        match self {
            Self::Current(plan) => Some(&plan.plan),
            Self::LegacyReadable(plan) | Self::RequiredSidecarMissing(plan) => Some(plan),
            Self::ProjectionDrift { current, .. } => Some(&current.plan),
            Self::Corrupt { .. } => None,
        }
    }
}

const PLAN_V2_ACTIVATED_AT: &str = "2026-07-22T00:00:00Z";

impl StateStore {
    pub fn open(paths: RuntimePaths) -> Result<Self> {
        let private_origin = private_runtime_origin(&paths)?;
        for path in [
            &paths.config_dir,
            &paths.data_dir,
            &paths.cache_dir,
            &paths.data_dir.join("plans"),
            &paths.data_dir.join("plans-v2"),
            &paths.data_dir.join("plan-sets"),
            &paths.data_dir.join("locks"),
            &paths.data_dir.join("locks").join("authorities"),
            &paths
                .config_dir
                .join("policy")
                .join("admission")
                .join("bundles"),
            &paths.data_dir.join("catalog"),
            &paths.data_dir.join("authorities"),
            &paths.data_dir.join("d1-import-checkpoints"),
        ] {
            create_dir_all(path)?;
        }
        let evidence_directories = Arc::new(open_evidence_directories(&paths)?);
        Ok(Self {
            paths,
            evidence_directories,
            evidence_authenticator: None,
            observation_attestation: None,
            private_origin,
        })
    }

    pub fn open_authenticated(
        paths: RuntimePaths,
        authenticator: Arc<dyn EvidenceMacProvider>,
    ) -> Result<Self> {
        Self::open(paths)?.with_evidence_authenticator(authenticator)
    }

    pub fn with_evidence_authenticator(
        mut self,
        authenticator: Arc<dyn EvidenceMacProvider>,
    ) -> Result<Self> {
        if authenticator.location_identity() != self.evidence_location_identity() {
            return Err(StorageError::EvidenceAuthentication(
                "evidence key authority is bound to a different canonical state location"
                    .to_owned(),
            ));
        }
        self.evidence_authenticator = Some(authenticator);
        Ok(self)
    }

    #[must_use]
    pub const fn paths(&self) -> &RuntimePaths {
        &self.paths
    }

    #[must_use]
    pub fn evidence_location_identity(&self) -> &str {
        &self.evidence_directories.location_identity
    }

    fn require_canonical_evidence_data_root(&self) -> Result<()> {
        require_same_canonical_data_root(
            &self.paths.data_dir,
            &self.evidence_directories.data,
            &self.evidence_directories.data_identity,
        )
    }

    pub fn evidence_root_identity(&self) -> Result<Option<String>> {
        let Some(bytes) = read_optional_capability_file(
            &self.evidence_directories.data,
            "evidence-root-v1.json",
            &self.paths.data_dir.join("evidence-root-v1.json"),
        )?
        else {
            return Ok(None);
        };
        let marker: EvidenceRootMarkerV1 = serde_json::from_slice(&bytes)?;
        if marker.schema_version != 1 || !is_canonical_sha256_identity(&marker.state_root_identity)
        {
            return Err(StorageError::EvidenceAuthentication(
                "evidence state-root marker is malformed".to_owned(),
            ));
        }
        Ok(Some(marker.state_root_identity))
    }

    pub fn initialize_evidence_root_identity(&self, state_root_identity: &str) -> Result<()> {
        if !is_canonical_sha256_identity(state_root_identity) {
            return Err(StorageError::EvidenceAuthentication(
                "evidence state-root identity must be canonical lowercase sha256".to_owned(),
            ));
        }
        if self.evidence_root_identity()?.is_some() {
            return Err(StorageError::EvidenceAuthentication(
                "evidence state-root marker already exists".to_owned(),
            ));
        }
        let marker = EvidenceRootMarkerV1 {
            schema_version: 1,
            state_root_identity: state_root_identity.to_owned(),
        };
        atomic_create_capability_file(
            &self.evidence_directories.data,
            "evidence-root-v1.json",
            &serde_json::to_vec_pretty(&marker)?,
            &self.paths.data_dir.join("evidence-root-v1.json"),
        )
    }

    /// Appends one immutable import-protocol checkpoint. The plan lock held by
    /// the CLI serializes writers; create-new files and content hashes make a
    /// crash or replacement visible before a later provider request.
    pub fn record_d1_import_checkpoint(
        &self,
        operation_id: &str,
        checkpoint: &Value,
    ) -> Result<String> {
        validate_plan_id(operation_id)?;
        if checkpoint.get("operation_id").and_then(Value::as_str) != Some(operation_id)
            || checkpoint.get("schema_version").and_then(Value::as_u64) != Some(1)
            || checkpoint
                .get("step")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
        {
            return Err(StorageError::UnsafeManagedDocument {
                path: "d1-import-checkpoint".to_owned(),
                reason: "checkpoint identity, version, and step must match the locked plan"
                    .to_owned(),
            });
        }
        let directory = self
            .paths
            .data_dir
            .join("d1-import-checkpoints")
            .join(operation_id);
        create_dir_all(&directory)?;
        let mut sequence = 0_u64;
        for entry in fs::read_dir(&directory).map_err(|source| io_error(&directory, source))? {
            let entry = entry.map_err(|source| io_error(&directory, source))?;
            if entry.path().extension().and_then(std::ffi::OsStr::to_str) == Some("json") {
                sequence = sequence.saturating_add(1);
            }
        }
        let redacted = redact_json(checkpoint);
        if redacted != *checkpoint {
            return Err(StorageError::SensitiveData);
        }
        let encoded = serde_json::to_vec_pretty(checkpoint)?;
        let hash = format!("sha256:{}", hex::encode(Sha256::digest(&encoded)));
        let path = directory.join(format!("{sequence:04}-{}.json", &hash[7..23]));
        atomic_create(&path, &encoded)?;
        Ok(hash)
    }

    pub fn read_d1_import_checkpoints(&self, operation_id: &str) -> Result<Vec<(String, Value)>> {
        validate_plan_id(operation_id)?;
        let directory = self
            .paths
            .data_dir
            .join("d1-import-checkpoints")
            .join(operation_id);
        let mut paths = fs::read_dir(&directory)
            .map_err(|source| io_error(&directory, source))?
            .map(|entry| {
                entry
                    .map(|entry| entry.path())
                    .map_err(|source| io_error(&directory, source))
            })
            .collect::<Result<Vec<_>>>()?;
        paths.sort();
        let mut checkpoints = Vec::new();
        for path in paths {
            if path.extension().and_then(std::ffi::OsStr::to_str) != Some("json")
                || !validate_existing_managed_file(&path)?
            {
                return Err(unsafe_managed_document(
                    &path,
                    "import checkpoint is not an immutable JSON file",
                ));
            }
            let bytes = fs::read(&path).map_err(|source| io_error(&path, source))?;
            let hash = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
            let expected_suffix = format!("-{}.json", &hash[7..23]);
            if !path
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .is_some_and(|name| name.ends_with(&expected_suffix))
            {
                return Err(unsafe_managed_document(
                    &path,
                    "import checkpoint bytes do not match the immutable filename hash",
                ));
            }
            let value: Value = serde_json::from_slice(&bytes)?;
            if value.get("operation_id").and_then(Value::as_str) != Some(operation_id) {
                return Err(unsafe_managed_document(
                    &path,
                    "import checkpoint operation identity drifted",
                ));
            }
            checkpoints.push((hash, value));
        }
        Ok(checkpoints)
    }

    pub fn save_plan(&self, plan: &PlanV1) -> Result<()> {
        validate_plan_id(&plan.operation_id)?;
        plan.validate_transaction_journal()?;
        let value = serde_json::to_value(plan)?;
        if plan_document_contains_sensitive_data(value, "/capability/request_schema") {
            return Err(StorageError::SensitiveData);
        }
        let plan_v2_path = self.plan_v2_path(&plan.operation_id)?;
        if validate_existing_managed_file(&plan_v2_path)? {
            let mut current = self.load_plan_v2(&plan.operation_id)?;
            current.refresh_from_plan(plan.clone())?;
            return self.write_current_plan(&current);
        }
        let path = self.plan_path(&plan.operation_id)?;
        if validate_existing_managed_file(&path)? {
            let stored: PlanV1 = self.read_json(&path)?;
            ensure_plan_identity(&stored, &plan.operation_id)?;
            stored.validate_transaction_journal()?;
        }
        self.write_json(&path, plan)
    }

    /// Stores a current plan with `PlanV2` as the canonical document and `PlanV1`
    /// as a compatibility projection. The canonical write is intentionally
    /// first: a projection failure can reduce compatibility, but can never
    /// acknowledge an authority state that is absent from the canonical plan.
    pub fn save_plan_v2(&self, plan: &PlanV2) -> Result<()> {
        validate_plan_id(&plan.plan.operation_id)?;
        plan.validate()?;
        let plan_v2_path = self.plan_v2_path(&plan.plan.operation_id)?;
        if validate_existing_managed_file(&plan_v2_path)? {
            let stored = self.load_plan_v2(&plan.plan.operation_id)?;
            if stored.pins != plan.pins {
                return Err(StorageError::InvalidPlan(
                    cfctl_core::CoreError::InvalidPlanV2(
                        "canonical execution pins cannot be replaced".to_owned(),
                    ),
                ));
            }
        } else {
            let projection_path = self.plan_path(&plan.plan.operation_id)?;
            if validate_existing_managed_file(&projection_path)? {
                let projection: PlanV1 = self.read_json(&projection_path)?;
                ensure_plan_identity(&projection, &plan.plan.operation_id)?;
                projection.validate_transaction_journal()?;
                if projection != plan.plan {
                    return Err(StorageError::InvalidPlan(
                        cfctl_core::CoreError::InvalidPlanV2(
                            "v2 wrapper does not match the stored PlanV1 projection".to_owned(),
                        ),
                    ));
                }
            }
        }
        self.write_current_plan(plan)
    }

    /// Binds the one existing standing-authority lane to a draft `PlanV2`.
    /// This is the only execution pin that may transition from absent to
    /// present after preparation; it is immutable once set.
    pub fn bind_plan_authority_hash(&self, operation_id: &str, authority_hash: &str) -> Result<()> {
        let mut plan = match self.load_stored_plan_record(operation_id)? {
            StoredPlanRecord::Current(plan) => *plan,
            StoredPlanRecord::LegacyReadable(_) | StoredPlanRecord::RequiredSidecarMissing(_) => {
                self.reject_archived_operation(operation_id)?;
                return Err(StorageError::PlanV2NotFound(operation_id.to_owned()));
            }
            StoredPlanRecord::ProjectionDrift { .. } => {
                return Err(StorageError::PlanProjectionDrift(operation_id.to_owned()));
            }
            StoredPlanRecord::Corrupt { reason, .. } => {
                return Err(StorageError::CorruptPlan {
                    operation_id: operation_id.to_owned(),
                    reason,
                });
            }
        };
        plan.bind_authority_hash(authority_hash)?;
        self.write_current_plan(&plan)
    }

    pub fn load_plan_v2(&self, operation_id: &str) -> Result<PlanV2> {
        let path = self.plan_v2_path(operation_id)?;
        if !validate_existing_managed_file(&path)? {
            return Err(StorageError::PlanV2NotFound(operation_id.to_owned()));
        }
        let plan: PlanV2 = self.read_json(&path)?;
        ensure_plan_identity(&plan.plan, operation_id)?;
        plan.validate()?;
        Ok(plan)
    }

    pub fn has_plan_v2(&self, operation_id: &str) -> Result<bool> {
        validate_existing_managed_file(&self.plan_v2_path(operation_id)?)
    }

    pub fn load_stored_plan_record(&self, operation_id: &str) -> Result<StoredPlanRecord> {
        validate_plan_id(operation_id)?;
        let projection_path = self.plan_path(operation_id)?;
        let current_path = self.plan_v2_path(operation_id)?;
        let projection_exists = validate_existing_managed_file(&projection_path)?;
        let current_exists = validate_existing_managed_file(&current_path)?;
        if !projection_exists && !current_exists {
            self.reject_archived_operation(operation_id)?;
            return Err(StorageError::PlanNotFound(operation_id.to_owned()));
        }

        let projection = if projection_exists {
            match self.read_json::<PlanV1>(&projection_path).and_then(|plan| {
                ensure_plan_identity(&plan, operation_id)?;
                plan.validate_transaction_journal()?;
                Ok(plan)
            }) {
                Ok(plan) => Some(plan),
                Err(error) => {
                    return Ok(StoredPlanRecord::Corrupt {
                        operation_id: operation_id.to_owned(),
                        reason: error.to_string(),
                    });
                }
            }
        } else {
            None
        };

        if current_exists {
            let current = match self.read_json::<PlanV2>(&current_path).and_then(|plan| {
                ensure_plan_identity(&plan.plan, operation_id)?;
                plan.validate()?;
                Ok(plan)
            }) {
                Ok(plan) => plan,
                Err(error) => {
                    return Ok(StoredPlanRecord::Corrupt {
                        operation_id: operation_id.to_owned(),
                        reason: error.to_string(),
                    });
                }
            };
            return Ok(match projection {
                Some(projection) if projection != current.plan => {
                    StoredPlanRecord::ProjectionDrift {
                        current: Box::new(current),
                        projection: Box::new(projection),
                    }
                }
                _ => StoredPlanRecord::Current(Box::new(current)),
            });
        }

        let projection =
            projection.ok_or_else(|| StorageError::PlanNotFound(operation_id.to_owned()))?;
        if plan_v2_is_required(&projection) {
            Ok(StoredPlanRecord::RequiredSidecarMissing(Box::new(
                projection,
            )))
        } else {
            Ok(StoredPlanRecord::LegacyReadable(Box::new(projection)))
        }
    }

    pub fn load_plan(&self, operation_id: &str) -> Result<PlanV1> {
        match self.load_stored_plan_record(operation_id)? {
            StoredPlanRecord::Current(plan) => Ok(plan.plan),
            StoredPlanRecord::LegacyReadable(plan)
            | StoredPlanRecord::RequiredSidecarMissing(plan) => Ok(*plan),
            StoredPlanRecord::ProjectionDrift { .. } => {
                Err(StorageError::PlanProjectionDrift(operation_id.to_owned()))
            }
            StoredPlanRecord::Corrupt { .. } if self.has_plan_v2(operation_id)? => {
                self.load_plan_v2(operation_id).map(|plan| plan.plan)
            }
            StoredPlanRecord::Corrupt { .. } => {
                let path = self.plan_path(operation_id)?;
                let plan: PlanV1 = self.read_json(&path)?;
                ensure_plan_identity(&plan, operation_id)?;
                plan.validate_transaction_journal()?;
                Ok(plan)
            }
        }
    }

    /// Persist one immutable multi-plan review receipt. Plan-set documents do
    /// not carry approval or execution authority and therefore have no update
    /// path; source or provider drift requires a new bundle ID.
    pub fn create_deployment_plan_set(&self, plan_set: &DeploymentPlanSetV1) -> Result<()> {
        plan_set.validate()?;
        let path = self.deployment_plan_set_path(&plan_set.bundle_id)?;
        if validate_existing_managed_file(&path)? {
            return Err(StorageError::DeploymentPlanSetAlreadyExists(
                plan_set.bundle_id.clone(),
            ));
        }
        let value = serde_json::to_value(plan_set)?;
        if redact_json(&value) != value {
            return Err(StorageError::SensitiveData);
        }
        atomic_create(&path, &serde_json::to_vec_pretty(plan_set)?)
    }

    pub fn load_deployment_plan_set(&self, bundle_id: &str) -> Result<DeploymentPlanSetV1> {
        let path = self.deployment_plan_set_path(bundle_id)?;
        if !validate_existing_managed_file(&path)? {
            return Err(StorageError::DeploymentPlanSetNotFound(
                bundle_id.to_owned(),
            ));
        }
        let plan_set: DeploymentPlanSetV1 = self.read_json(&path)?;
        if plan_set.bundle_id != bundle_id {
            return Err(StorageError::ManagedDocumentIdentityMismatch {
                kind: "deployment plan set",
                filename_id: bundle_id.to_owned(),
                document_id: plan_set.bundle_id,
            });
        }
        plan_set.validate()?;
        Ok(plan_set)
    }

    fn write_current_plan(&self, plan: &PlanV2) -> Result<()> {
        let value = serde_json::to_value(plan)?;
        if plan_document_contains_sensitive_data(value, "/plan/capability/request_schema") {
            return Err(StorageError::SensitiveData);
        }
        self.write_json(&self.plan_v2_path(&plan.plan.operation_id)?, plan)?;
        self.write_json(&self.plan_path(&plan.plan.operation_id)?, &plan.plan)
            .map_err(|error| StorageError::PlanProjectionWriteFailed {
                operation_id: plan.plan.operation_id.clone(),
                reason: error.to_string(),
            })
    }

    pub fn list_plans(&self) -> Result<Vec<PlanV1>> {
        let directory = self.paths.data_dir.join("plans");
        let mut plans = Vec::new();
        for entry in fs::read_dir(&directory).map_err(|source| io_error(&directory, source))? {
            let entry = entry.map_err(|source| io_error(&directory, source))?;
            if entry.path().extension().and_then(std::ffi::OsStr::to_str) == Some("json") {
                let operation_id = managed_document_id(&entry.path(), ManagedIdKind::Plan)?;
                if !validate_existing_managed_file(&entry.path())? {
                    return Err(unsafe_managed_document(
                        &entry.path(),
                        "directory entry disappeared while listing",
                    ));
                }
                let plan: PlanV1 = self.read_json(&entry.path())?;
                ensure_plan_identity(&plan, &operation_id)?;
                plan.validate_transaction_journal()?;
                plans.push(plan);
            }
        }
        plans.sort_by_key(|plan: &PlanV1| plan.created_at);
        Ok(plans)
    }

    fn authority_path(&self, authority_id: &str) -> Result<PathBuf> {
        validate_authority_id(authority_id)?;
        Ok(self
            .paths
            .data_dir
            .join("authorities")
            .join(format!("{authority_id}.json")))
    }

    fn plan_v2_path(&self, operation_id: &str) -> Result<PathBuf> {
        validate_plan_id(operation_id)?;
        Ok(self
            .paths
            .data_dir
            .join("plans-v2")
            .join(format!("{operation_id}.json")))
    }

    fn deployment_plan_set_path(&self, bundle_id: &str) -> Result<PathBuf> {
        validate_deployment_plan_set_id(bundle_id)?;
        Ok(self
            .paths
            .data_dir
            .join("plan-sets")
            .join(format!("{bundle_id}.json")))
    }

    /// Persists a new authority without replacing any existing document.
    /// Mutable authority state must be written through
    /// [`Self::save_authority_guarded`] while holding its OS-backed lock.
    pub fn create_authority(&self, authority: &StandingAuthorityV1) -> Result<()> {
        let path = self.authority_path(&authority.authority_id)?;
        let value = serde_json::to_value(authority)?;
        if redact_json(&value) != value {
            return Err(StorageError::SensitiveData);
        }
        if validate_existing_managed_file(&path)? {
            return Err(StorageError::AuthorityAlreadyExists(
                authority.authority_id.clone(),
            ));
        }
        let encoded = serde_json::to_vec_pretty(authority)?;
        match atomic_create(&path, &encoded) {
            Err(StorageError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::AlreadyExists =>
            {
                Err(StorageError::AuthorityAlreadyExists(
                    authority.authority_id.clone(),
                ))
            }
            result => result,
        }
    }

    /// Compatibility entry point for authority creation. This method is
    /// intentionally create-only and never overwrites durable state.
    pub fn save_authority(&self, authority: &StandingAuthorityV1) -> Result<()> {
        self.create_authority(authority)
    }

    pub fn save_authority_guarded(
        &self,
        authority: &StandingAuthorityV1,
        guard: &AuthorityLock,
    ) -> Result<()> {
        let path = self.authority_path(&authority.authority_id)?;
        if guard.authority_id != authority.authority_id || guard.authority_path != path {
            return Err(StorageError::AuthorityLockMismatch(
                authority.authority_id.clone(),
            ));
        }
        let value = serde_json::to_value(authority)?;
        if redact_json(&value) != value {
            return Err(StorageError::SensitiveData);
        }
        if !validate_existing_managed_file(&path)? {
            return Err(StorageError::AuthorityNotFound(
                authority.authority_id.clone(),
            ));
        }
        let stored: StandingAuthorityV1 = self.read_json(&path)?;
        ensure_authority_identity(&stored, &authority.authority_id)?;
        if stored.status == StandingAuthorityStatus::Revoked
            && authority.status != StandingAuthorityStatus::Revoked
        {
            return Err(StorageError::AuthorityRevocationRollback(
                authority.authority_id.clone(),
            ));
        }
        self.write_json(&path, authority)
    }

    pub fn load_authority(&self, authority_id: &str) -> Result<StandingAuthorityV1> {
        let path = self.authority_path(authority_id)?;
        if !validate_existing_managed_file(&path)? {
            return Err(StorageError::AuthorityNotFound(authority_id.to_owned()));
        }
        let authority: StandingAuthorityV1 = self.read_json(&path)?;
        ensure_authority_identity(&authority, authority_id)?;
        Ok(authority)
    }

    pub fn list_authorities(&self) -> Result<Vec<StandingAuthorityV1>> {
        let directory = self.paths.data_dir.join("authorities");
        let mut authorities = Vec::new();
        for entry in fs::read_dir(&directory).map_err(|source| io_error(&directory, source))? {
            let entry = entry.map_err(|source| io_error(&directory, source))?;
            if entry.path().extension().and_then(std::ffi::OsStr::to_str) == Some("json") {
                let authority_id = managed_document_id(&entry.path(), ManagedIdKind::Authority)?;
                if !validate_existing_managed_file(&entry.path())? {
                    return Err(unsafe_managed_document(
                        &entry.path(),
                        "directory entry disappeared while listing",
                    ));
                }
                let authority: StandingAuthorityV1 = self.read_json(&entry.path())?;
                ensure_authority_identity(&authority, &authority_id)?;
                authorities.push(authority);
            }
        }
        authorities.sort_by_key(|authority: &StandingAuthorityV1| authority.created_at);
        Ok(authorities)
    }

    /// Serializes the platform evidence-key lifecycle with authenticated
    /// descriptor and proof publication for this exact state root.
    ///
    /// Lock order is stable: callers may already hold one resource lock such
    /// as a plan lock, then acquire this lifecycle lock. Code holding this
    /// guard must never acquire another `StateStore` lock.
    pub fn lock_evidence_lifecycle(&self) -> Result<EvidenceLifecycleLock> {
        let name = "evidence-lifecycle.lock";
        let path = self.paths.data_dir.join("locks").join(name);
        let pinned_metadata = self
            .evidence_directories
            .lifecycle_lock
            .metadata()
            .map_err(|source| io_error(&path, source))?;
        require_same_capability_entry(
            &self.evidence_directories.locks,
            name,
            &pinned_metadata,
            &path,
        )?;
        let mut options = cap_std::fs::OpenOptions::new();
        options.read(true).write(true);
        let capability_file = self
            .evidence_directories
            .locks
            .open_with(name, &options)
            .map_err(|source| io_error(&path, source))?;
        let opened_metadata = capability_file
            .metadata()
            .map_err(|source| io_error(&path, source))?;
        if !same_filesystem_identity(&pinned_metadata, &opened_metadata) {
            return Err(unsafe_managed_document(
                &path,
                "evidence lifecycle lock changed while its capability was opened",
            ));
        }
        let file = capability_file.into_std();
        file.lock().map_err(|source| io_error(&path, source))?;
        require_same_capability_entry(
            &self.evidence_directories.locks,
            name,
            &pinned_metadata,
            &path,
        )?;
        self.require_canonical_evidence_data_root()?;
        for (name, directory, identity) in [
            (
                "evidence",
                &self.evidence_directories.bodies,
                self.evidence_directories.bodies_identity.as_slice(),
            ),
            (
                "evidence-descriptors",
                &self.evidence_directories.descriptors,
                self.evidence_directories.descriptors_identity.as_slice(),
            ),
            (
                "evidence-index",
                &self.evidence_directories.proofs,
                self.evidence_directories.proofs_identity.as_slice(),
            ),
        ] {
            require_same_capability_directory(
                &self.evidence_directories.data,
                name,
                directory,
                identity,
                &self.paths.data_dir.join(name),
            )?;
        }
        Ok(EvidenceLifecycleLock { _file: file })
    }

    pub fn lock_plan(&self, operation_id: &str) -> Result<PlanLock> {
        validate_plan_id(operation_id)?;
        let path = self
            .paths
            .data_dir
            .join("locks")
            .join(format!("{operation_id}.lock"));
        let _existing_regular_file = validate_existing_managed_file(&path)?;
        match create_plan_lock(&path) {
            Ok(lock) => Ok(lock),
            Err(StorageError::PlanLocked(_)) if lock_is_expired(&path)? => {
                match fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(source) => return Err(io_error(&path, source)),
                }
                create_plan_lock(&path).map_err(|error| match error {
                    StorageError::PlanLocked(_) => {
                        StorageError::PlanLocked(operation_id.to_owned())
                    }
                    other => other,
                })
            }
            Err(StorageError::PlanLocked(_)) => {
                Err(StorageError::PlanLocked(operation_id.to_owned()))
            }
            Err(error) => Err(error),
        }
    }

    /// Serializes cfctl deployment writes for one exact account and Worker.
    /// Cloudflare's deployment-create endpoint has no documented conditional
    /// request field, so this local lock narrows the reread-to-POST race across
    /// concurrent cfctl processes. External deployers still require an
    /// operator-enforced quiescent change window.
    pub fn lock_worker_deployment(
        &self,
        account_id: &str,
        script_name: &str,
    ) -> Result<WorkerDeploymentLock> {
        if account_id.len() != 32
            || !account_id.bytes().all(|byte| byte.is_ascii_hexdigit())
            || script_name.is_empty()
            || script_name.len() > 255
        {
            return Err(StorageError::UnsafeManagedDocument {
                path: "worker-deployment-lock".to_owned(),
                reason: "account_id or script_name is outside the closed Worker deployment selector contract"
                    .to_owned(),
            });
        }
        let key = hex::encode(Sha256::digest(
            format!("{account_id}\0{script_name}").as_bytes(),
        ));
        let path = self
            .paths
            .data_dir
            .join("locks")
            .join("worker-deployments")
            .join(format!("{key}.lock"));
        let _existing_regular_file = validate_existing_managed_file(&path)?;
        let file = open_lock_file(&path)?;
        match file.try_lock() {
            Ok(()) => Ok(WorkerDeploymentLock { _file: file }),
            Err(std::fs::TryLockError::WouldBlock) => Err(StorageError::WorkerDeploymentLocked {
                account_id: account_id.to_owned(),
                script_name: script_name.to_owned(),
            }),
            Err(std::fs::TryLockError::Error(source)) => Err(io_error(&path, source)),
        }
    }

    /// Serializes cfctl writes for one exact account and provider-zone
    /// catch-all resource. Cloudflare's catch-all PUT has no documented
    /// conditional request primitive, so this lock closes concurrent local
    /// cfctl writers while the caller performs its final reads, one write,
    /// receipt persistence, and immediate readback. External writers remain a
    /// provider-boundary risk and must be kept out of the change window.
    pub fn lock_email_routing_catch_all(
        &self,
        account_id: &str,
        zone_id: &str,
    ) -> Result<EmailRoutingCatchAllLock> {
        if account_id.len() != 32
            || !account_id.bytes().all(|byte| byte.is_ascii_hexdigit())
            || zone_id.len() != 32
            || !zone_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(StorageError::UnsafeManagedDocument {
                path: "email-routing-catch-all-lock".to_owned(),
                reason: "account_id or zone_id is outside the closed Email Routing catch-all selector contract"
                    .to_owned(),
            });
        }
        let key = hex::encode(Sha256::digest(
            format!("{account_id}\0{zone_id}").as_bytes(),
        ));
        let path = self
            .paths
            .data_dir
            .join("locks")
            .join("email-routing-catch-alls")
            .join(format!("{key}.lock"));
        let _existing_regular_file = validate_existing_managed_file(&path)?;
        let file = open_lock_file(&path)?;
        match file.try_lock() {
            Ok(()) => Ok(EmailRoutingCatchAllLock { _file: file }),
            Err(std::fs::TryLockError::WouldBlock) => {
                Err(StorageError::EmailRoutingCatchAllLocked {
                    account_id: account_id.to_owned(),
                    zone_id: zone_id.to_owned(),
                })
            }
            Err(std::fs::TryLockError::Error(source)) => Err(io_error(&path, source)),
        }
    }

    /// Acquires a process-crash-safe exclusive lock for one authority. The
    /// guard is bound to this store root and canonical authority identifier.
    pub fn lock_authority(&self, authority_id: &str) -> Result<AuthorityLock> {
        let authority_path = self.authority_path(authority_id)?;
        let path = self
            .paths
            .data_dir
            .join("locks")
            .join("authorities")
            .join(format!("{authority_id}.lock"));
        let _existing_regular_file = validate_existing_managed_file(&path)?;
        let file = open_lock_file(&path)?;
        file.lock().map_err(|source| io_error(&path, source))?;
        Ok(AuthorityLock {
            _file: file,
            authority_id: authority_id.to_owned(),
            authority_path,
        })
    }

    /// Creates a pending admission bundle exactly once. Existing bundle IDs
    /// are immutable identities and are never overwritten by staging.
    pub fn create_admission_bundle(&self, bundle: &AdmissionPolicyBundleV1) -> Result<()> {
        bundle.validate()?;
        if bundle.status != AdmissionPolicyBundleStatusV1::Pending {
            return Err(StorageError::InvalidAdmissionPointer(
                "only a pending admission bundle may be staged".to_owned(),
            ));
        }
        let _guard = self.lock_admission_policy()?;
        let path = self.admission_bundle_path(&bundle.bundle_id)?;
        let value = serde_json::to_value(bundle)?;
        if redact_json(&value) != value {
            return Err(StorageError::SensitiveData);
        }
        let encoded = serde_json::to_vec_pretty(bundle)?;
        match atomic_create(&path, &encoded) {
            Err(StorageError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::AlreadyExists =>
            {
                Err(StorageError::AdmissionBundleAlreadyExists(
                    bundle.bundle_id.clone(),
                ))
            }
            result => result,
        }
    }

    pub fn load_admission_bundle(&self, bundle_id: &str) -> Result<AdmissionPolicyBundleV1> {
        let path = self.admission_bundle_path(bundle_id)?;
        if !validate_existing_managed_file(&path)? {
            return Err(StorageError::AdmissionBundleNotFound(bundle_id.to_owned()));
        }
        let bundle: AdmissionPolicyBundleV1 = self.read_json(&path)?;
        validate_admission_bundle_identity(&bundle, bundle_id)?;
        bundle.validate()?;
        Ok(bundle)
    }

    pub fn list_admission_bundles(&self) -> Result<Vec<AdmissionPolicyBundleV1>> {
        let directory = self.admission_bundle_directory();
        let mut bundles = Vec::new();
        for entry in fs::read_dir(&directory).map_err(|source| io_error(&directory, source))? {
            let entry = entry.map_err(|source| io_error(&directory, source))?;
            if entry.path().extension().and_then(std::ffi::OsStr::to_str) != Some("json") {
                continue;
            }
            let bundle_id = admission_bundle_id_from_path(&entry.path())?;
            if !validate_existing_managed_file(&entry.path())? {
                return Err(unsafe_managed_document(
                    &entry.path(),
                    "directory entry disappeared while listing",
                ));
            }
            let bundle: AdmissionPolicyBundleV1 = self.read_json(&entry.path())?;
            validate_admission_bundle_identity(&bundle, &bundle_id)?;
            bundle.validate()?;
            bundles.push(bundle);
        }
        bundles.sort_by_key(|bundle| bundle.created_at);
        Ok(bundles)
    }

    pub fn approve_admission_bundle(
        &self,
        bundle_id: &str,
        explicit_yes: bool,
    ) -> Result<AdmissionPolicyBundleV1> {
        let _guard = self.lock_admission_policy()?;
        let mut bundle = self.load_admission_bundle(bundle_id)?;
        bundle.approve(explicit_yes)?;
        self.write_admission_bundle(&bundle)?;
        Ok(bundle)
    }

    #[must_use = "activation changes the active policy pointer and the returned transition must be reported"]
    pub fn activate_admission_bundle(&self, bundle_id: &str) -> Result<AdmissionActivationV1> {
        let _guard = self.lock_admission_policy()?;
        let previous_id = self
            .active_admission_pointer()?
            .map(|pointer| pointer.bundle_id);
        let mut target = self.load_admission_bundle(bundle_id)?;
        target.activate()?;
        self.write_admission_bundle(&target)?;
        let pointer = AdmissionPolicyPointerV1 {
            schema_version: 1,
            bundle_id: target.bundle_id.clone(),
            content_hash: target.content_hash.clone(),
        };
        self.write_json(&self.active_admission_policy_path(), &pointer)?;
        if let Some(previous_id) = previous_id.as_deref().filter(|id| *id != bundle_id) {
            let mut previous = self.load_admission_bundle(previous_id)?;
            previous.supersede();
            self.write_admission_bundle(&previous)?;
        }
        Ok(AdmissionActivationV1 {
            bundle: target,
            previous_bundle_id: previous_id,
        })
    }

    pub fn active_admission_bundle_id(&self) -> Result<Option<String>> {
        Ok(self
            .active_admission_pointer()?
            .map(|pointer| pointer.bundle_id))
    }

    pub fn active_admission_policy(&self) -> Result<Option<AdmissionPolicyBundleV1>> {
        let Some(pointer) = self.active_admission_pointer()? else {
            return Ok(None);
        };
        let bundle = self.load_admission_bundle(&pointer.bundle_id)?;
        if bundle.status != AdmissionPolicyBundleStatusV1::Active
            || bundle.content_hash != pointer.content_hash
        {
            return Err(StorageError::InvalidAdmissionPointer(format!(
                "pointer selects bundle `{}` without the exact active content hash",
                pointer.bundle_id
            )));
        }
        Ok(Some(bundle))
    }

    pub fn register_workspace(
        &self,
        root: &Path,
        account_id: Option<String>,
    ) -> Result<WorkspaceRegistrationV1> {
        let canonical = root
            .canonicalize()
            .map_err(|source| io_error(root, source))?;
        let _guard = self.lock_workspace_manifest()?;
        let mut manifest = self.load_workspace_manifest_unlocked()?;
        let registration = manifest.register(canonical, account_id);
        self.write_json(&self.workspace_manifest_path(), &manifest)?;
        Ok(registration)
    }

    /// Stop future discovery beneath one exact registered root.
    ///
    /// Missing absolute paths remain removable so an operator can retire a
    /// stale registration after the repository itself has already moved or
    /// been deleted. Historical workspace graphs and evidence are preserved.
    pub fn unregister_workspace(&self, root: &Path) -> Result<(PathBuf, bool, bool)> {
        let canonical = match root.canonicalize() {
            Ok(canonical) => canonical,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound && root.is_absolute() => {
                root.to_path_buf()
            }
            Err(source) => return Err(io_error(root, source)),
        };
        let _guard = self.lock_workspace_manifest()?;
        let mut manifest = self.load_workspace_manifest_unlocked()?;
        let (removed, account_pin_removed) = manifest.unregister(&canonical);
        if removed {
            self.write_json(&self.workspace_manifest_path(), &manifest)?;
        }
        Ok((canonical, removed, account_pin_removed))
    }

    pub fn workspace_roots(&self) -> Result<Vec<PathBuf>> {
        Ok(self.workspace_manifest()?.roots())
    }

    pub fn workspace_manifest(&self) -> Result<WorkspaceManifestV1> {
        let _guard = self.lock_workspace_manifest()?;
        self.load_workspace_manifest_unlocked()
    }

    pub fn write_json<T: Serialize>(&self, path: &Path, value: &T) -> Result<()> {
        let encoded = serde_json::to_vec_pretty(value)?;
        atomic_write(path, &encoded)
    }

    pub fn read_json<T: DeserializeOwned>(&self, path: &Path) -> Result<T> {
        let encoded = fs::read(path).map_err(|source| io_error(path, source))?;
        Ok(serde_json::from_slice(&encoded)?)
    }

    pub fn write_import(&self, relative: &Path, bytes: &[u8]) -> Result<PathBuf> {
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(StorageError::UnsafeImportPath(
                relative.display().to_string(),
            ));
        }
        let destination = self.paths.data_dir.join("imports").join(relative);
        atomic_write(&destination, bytes)?;
        Ok(destination)
    }

    fn plan_path(&self, operation_id: &str) -> Result<PathBuf> {
        validate_plan_id(operation_id)?;
        Ok(self
            .paths
            .data_dir
            .join("plans")
            .join(format!("{operation_id}.json")))
    }

    fn admission_bundle_directory(&self) -> PathBuf {
        self.paths
            .config_dir
            .join("policy")
            .join("admission")
            .join("bundles")
    }

    fn admission_bundle_path(&self, bundle_id: &str) -> Result<PathBuf> {
        validate_admission_bundle_id(bundle_id)?;
        Ok(self
            .admission_bundle_directory()
            .join(format!("{bundle_id}.json")))
    }

    fn active_admission_policy_path(&self) -> PathBuf {
        self.paths
            .config_dir
            .join("policy")
            .join("admission")
            .join("active.json")
    }

    fn active_admission_pointer(&self) -> Result<Option<AdmissionPolicyPointerV1>> {
        let path = self.active_admission_policy_path();
        if !path.is_file() {
            return Ok(None);
        }
        let pointer: AdmissionPolicyPointerV1 = self.read_json(&path)?;
        if pointer.schema_version != 1 || pointer.content_hash.is_empty() {
            return Err(StorageError::InvalidAdmissionPointer(
                "unsupported schema or empty content hash".to_owned(),
            ));
        }
        validate_admission_bundle_id(&pointer.bundle_id)?;
        Ok(Some(pointer))
    }

    fn write_admission_bundle(&self, bundle: &AdmissionPolicyBundleV1) -> Result<()> {
        bundle.validate()?;
        let path = self.admission_bundle_path(&bundle.bundle_id)?;
        if !validate_existing_managed_file(&path)? {
            return Err(StorageError::AdmissionBundleNotFound(
                bundle.bundle_id.clone(),
            ));
        }
        let stored: AdmissionPolicyBundleV1 = self.read_json(&path)?;
        validate_admission_bundle_identity(&stored, &bundle.bundle_id)?;
        self.write_json(&path, bundle)
    }

    fn lock_admission_policy(&self) -> Result<AdmissionPolicyLock> {
        let path = self
            .paths
            .data_dir
            .join("locks")
            .join("admission-policy.lock");
        let file = open_lock_file(&path)?;
        file.lock().map_err(|source| io_error(&path, source))?;
        Ok(AdmissionPolicyLock { _file: file })
    }

    fn workspace_manifest_path(&self) -> PathBuf {
        self.paths.config_dir.join("workspace-manifest-v1.json")
    }

    fn load_workspace_manifest_unlocked(&self) -> Result<WorkspaceManifestV1> {
        let path = self.workspace_manifest_path();
        if path.is_file() {
            let manifest: WorkspaceManifestV1 = self.read_json(&path)?;
            validate_workspace_manifest(&manifest)?;
            return Ok(manifest);
        }

        let roots_path = self.paths.config_dir.join("workspace-roots.json");
        let account_pins_path = self.paths.config_dir.join("workspace-accounts.json");
        let mut roots: Vec<PathBuf> = if roots_path.is_file() {
            self.read_json(&roots_path)?
        } else {
            Vec::new()
        };
        roots.sort();
        roots.dedup();
        let account_pins: std::collections::BTreeMap<PathBuf, String> =
            if account_pins_path.is_file() {
                self.read_json(&account_pins_path)?
            } else {
                std::collections::BTreeMap::new()
            };
        if let Some(orphan) = account_pins.keys().find(|path| !roots.contains(path)) {
            return Err(StorageError::InvalidWorkspaceManifest(format!(
                "legacy account pin `{}` is not an explicitly registered root",
                orphan.display()
            )));
        }
        let manifest = WorkspaceManifestV1 {
            schema_version: WORKSPACE_MANIFEST_SCHEMA_VERSION,
            registrations: roots
                .into_iter()
                .map(|path| WorkspaceRegistrationV1 {
                    account_id: account_pins.get(&path).cloned(),
                    path,
                })
                .collect(),
        };
        validate_workspace_manifest(&manifest)?;
        self.write_json(&path, &manifest)?;
        Ok(manifest)
    }

    fn lock_workspace_manifest(&self) -> Result<WorkspaceManifestLock> {
        let path = self
            .paths
            .data_dir
            .join("locks")
            .join("workspace-manifest.lock");
        let file = open_lock_file(&path)?;
        file.lock().map_err(|source| io_error(&path, source))?;
        Ok(WorkspaceManifestLock { _file: file })
    }
}

#[derive(Debug, Clone, Copy)]
enum ManagedIdKind {
    Plan,
    Authority,
}

impl ManagedIdKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Plan => "plan",
            Self::Authority => "standing authority",
        }
    }

    fn invalid_id(self, value: &str) -> StorageError {
        match self {
            Self::Plan => StorageError::InvalidPlanId(value.to_owned()),
            Self::Authority => StorageError::InvalidAuthorityId(value.to_owned()),
        }
    }
}

fn validate_plan_id(operation_id: &str) -> Result<()> {
    validate_managed_id(operation_id, ManagedIdKind::Plan)
}

fn validate_deployment_plan_set_id(bundle_id: &str) -> Result<()> {
    let parsed = Uuid::parse_str(bundle_id)
        .map_err(|_| StorageError::InvalidDeploymentPlanSetId(bundle_id.to_owned()))?;
    if parsed.hyphenated().to_string() != bundle_id {
        return Err(StorageError::InvalidDeploymentPlanSetId(
            bundle_id.to_owned(),
        ));
    }
    Ok(())
}

fn plan_document_contains_sensitive_data(mut value: Value, request_schema_pointer: &str) -> bool {
    if let Some(request_schema) = value.pointer_mut(request_schema_pointer) {
        if redact_json_schema(request_schema) != *request_schema {
            return true;
        }
        *request_schema = Value::Null;
    }
    redact_json(&value) != value
}

fn plan_v2_is_required(plan: &PlanV1) -> bool {
    if !plan.capability.mutating {
        return false;
    }
    DateTime::parse_from_rfc3339(PLAN_V2_ACTIVATED_AT).map_or(true, |activated_at| {
        plan.created_at >= activated_at.with_timezone(&Utc)
    })
}

fn validate_authority_id(authority_id: &str) -> Result<()> {
    validate_managed_id(authority_id, ManagedIdKind::Authority)
}

fn validate_managed_id(value: &str, kind: ManagedIdKind) -> Result<()> {
    let parsed = Uuid::parse_str(value).map_err(|_| kind.invalid_id(value))?;
    if parsed.hyphenated().to_string() != value {
        return Err(kind.invalid_id(value));
    }
    Ok(())
}

fn managed_document_id(path: &Path, kind: ManagedIdKind) -> Result<String> {
    let Some(file_name) = path.file_name().and_then(std::ffi::OsStr::to_str) else {
        return Err(unsafe_managed_document(path, "filename is not valid UTF-8"));
    };
    let Some(identifier) = file_name.strip_suffix(".json") else {
        return Err(unsafe_managed_document(
            path,
            "filename does not end in .json",
        ));
    };
    validate_managed_id(identifier, kind)?;
    Ok(identifier.to_owned())
}

fn ensure_plan_identity(plan: &PlanV1, filename_id: &str) -> Result<()> {
    validate_plan_id(&plan.operation_id)?;
    if plan.operation_id != filename_id {
        return Err(StorageError::ManagedDocumentIdentityMismatch {
            kind: ManagedIdKind::Plan.label(),
            filename_id: filename_id.to_owned(),
            document_id: plan.operation_id.clone(),
        });
    }
    Ok(())
}

fn ensure_authority_identity(authority: &StandingAuthorityV1, filename_id: &str) -> Result<()> {
    validate_authority_id(&authority.authority_id)?;
    if authority.authority_id != filename_id {
        return Err(StorageError::ManagedDocumentIdentityMismatch {
            kind: ManagedIdKind::Authority.label(),
            filename_id: filename_id.to_owned(),
            document_id: authority.authority_id.clone(),
        });
    }
    Ok(())
}

fn validate_existing_managed_file(path: &Path) -> Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(source) => return Err(io_error(path, source)),
    };
    if metadata.file_type().is_symlink() {
        return Err(unsafe_managed_document(
            path,
            "symbolic links are forbidden",
        ));
    }
    if !metadata.file_type().is_file() {
        return Err(unsafe_managed_document(
            path,
            "managed documents must be regular files",
        ));
    }
    Ok(true)
}

fn unsafe_managed_document(path: &Path, reason: &str) -> StorageError {
    StorageError::UnsafeManagedDocument {
        path: path.display().to_string(),
        reason: reason.to_owned(),
    }
}

const LOCK_TTL: Duration = Duration::from_mins(15);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PlanLockRecord {
    pid: u32,
    created_at_unix: u64,
    nonce: String,
}

fn create_plan_lock(path: &Path) -> Result<PlanLock> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StorageError::Clock)?;
    let nonce_source = format!("{}:{}", std::process::id(), now.as_nanos());
    let record = PlanLockRecord {
        pid: std::process::id(),
        created_at_unix: now.as_secs(),
        nonce: hex::encode(Sha256::digest(nonce_source.as_bytes())),
    };
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(mut file) => {
            set_private_file_permissions(&file, path)?;
            let encoded = serde_json::to_vec(&record)?;
            file.write_all(&encoded)
                .map_err(|source| io_error(path, source))?;
            file.sync_all().map_err(|source| io_error(path, source))?;
            Ok(PlanLock {
                path: path.to_path_buf(),
                nonce: record.nonce,
            })
        }
        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(StorageError::PlanLocked(path.display().to_string()))
        }
        Err(source) => Err(io_error(path, source)),
    }
}

fn open_lock_file(path: &Path) -> Result<fs::File> {
    let parent = path.parent().ok_or_else(|| StorageError::Io {
        path: path.display().to_string(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no parent"),
    })?;
    create_dir_all(parent)?;
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(path)
        .map_err(|source| io_error(path, source))?;
    let metadata = file.metadata().map_err(|source| io_error(path, source))?;
    if !metadata.file_type().is_file() {
        return Err(unsafe_managed_document(
            path,
            "authority locks must be regular files",
        ));
    }
    set_private_file_permissions(&file, path)?;
    Ok(file)
}

fn lock_is_expired(path: &Path) -> Result<bool> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StorageError::Clock)?
        .as_secs();
    match fs::read(path) {
        Ok(bytes) => {
            if let Ok(record) = serde_json::from_slice::<PlanLockRecord>(&bytes) {
                Ok(now.saturating_sub(record.created_at_unix) > LOCK_TTL.as_secs())
            } else {
                let modified = fs::metadata(path)
                    .and_then(|metadata| metadata.modified())
                    .map_err(|source| io_error(path, source))?;
                Ok(SystemTime::now()
                    .duration_since(modified)
                    .unwrap_or_default()
                    > Duration::from_secs(30))
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(source) => Err(io_error(path, source)),
    }
}

#[derive(Debug)]
pub struct PlanLock {
    path: PathBuf,
    nonce: String,
}

impl Drop for PlanLock {
    fn drop(&mut self) {
        let owns_lock = fs::read(&self.path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<PlanLockRecord>(&bytes).ok())
            .is_some_and(|record| record.nonce == self.nonce);
        if owns_lock {
            let _ignored = fs::remove_file(&self.path);
        }
    }
}

#[derive(Debug)]
pub struct EvidenceLifecycleLock {
    _file: fs::File,
}

#[derive(Debug)]
pub struct AuthorityLock {
    _file: fs::File,
    authority_id: String,
    authority_path: PathBuf,
}

#[derive(Debug)]
pub struct WorkerDeploymentLock {
    _file: fs::File,
}

#[derive(Debug)]
pub struct EmailRoutingCatchAllLock {
    _file: fs::File,
}

#[derive(Debug)]
struct AdmissionPolicyLock {
    _file: fs::File,
}

#[derive(Debug)]
struct WorkspaceManifestLock {
    _file: fs::File,
}

fn validate_workspace_manifest(manifest: &WorkspaceManifestV1) -> Result<()> {
    if manifest.schema_version != WORKSPACE_MANIFEST_SCHEMA_VERSION {
        return Err(StorageError::InvalidWorkspaceManifest(format!(
            "unsupported schema version {}",
            manifest.schema_version
        )));
    }
    let mut previous: Option<&Path> = None;
    for registration in &manifest.registrations {
        if !registration.path.is_absolute() {
            return Err(StorageError::InvalidWorkspaceManifest(format!(
                "registered root `{}` is not absolute",
                registration.path.display()
            )));
        }
        if registration
            .account_id
            .as_deref()
            .is_some_and(str::is_empty)
        {
            return Err(StorageError::InvalidWorkspaceManifest(format!(
                "registered root `{}` has an empty account pin",
                registration.path.display()
            )));
        }
        if previous.is_some_and(|path| path >= registration.path.as_path()) {
            return Err(StorageError::InvalidWorkspaceManifest(
                "registrations must be unique and sorted by path".to_owned(),
            ));
        }
        previous = Some(&registration.path);
    }
    Ok(())
}

fn validate_admission_bundle_id(bundle_id: &str) -> Result<()> {
    let parsed = Uuid::parse_str(bundle_id)
        .map_err(|_| StorageError::InvalidAdmissionBundleId(bundle_id.to_owned()))?;
    if parsed.hyphenated().to_string() != bundle_id {
        return Err(StorageError::InvalidAdmissionBundleId(bundle_id.to_owned()));
    }
    Ok(())
}

fn admission_bundle_id_from_path(path: &Path) -> Result<String> {
    let Some(file_name) = path.file_name().and_then(std::ffi::OsStr::to_str) else {
        return Err(unsafe_managed_document(path, "filename is not valid UTF-8"));
    };
    let Some(bundle_id) = file_name.strip_suffix(".json") else {
        return Err(unsafe_managed_document(
            path,
            "filename does not end in .json",
        ));
    };
    validate_admission_bundle_id(bundle_id)?;
    Ok(bundle_id.to_owned())
}

fn validate_admission_bundle_identity(
    bundle: &AdmissionPolicyBundleV1,
    filename_id: &str,
) -> Result<()> {
    validate_admission_bundle_id(&bundle.bundle_id)?;
    if bundle.bundle_id != filename_id {
        return Err(StorageError::ManagedDocumentIdentityMismatch {
            kind: "admission policy bundle",
            filename_id: filename_id.to_owned(),
            document_id: bundle.bundle_id.clone(),
        });
    }
    Ok(())
}

fn sync_capability_directory(directory: &Dir) -> std::io::Result<()> {
    directory
        .try_clone()
        .and_then(|clone| clone.into_std_file().sync_all())
}

#[cfg(unix)]
fn same_filesystem_identity(first: &cap_std::fs::Metadata, second: &cap_std::fs::Metadata) -> bool {
    use cap_std::fs::MetadataExt as _;

    first.dev() == second.dev() && first.ino() == second.ino()
}

#[cfg(windows)]
fn same_filesystem_identity(first: &cap_std::fs::Metadata, second: &cap_std::fs::Metadata) -> bool {
    use cap_std::fs::MetadataExt as _;

    stable_windows_identity_matches(
        (
            first.volume_serial_number(),
            first.file_index(),
            first.creation_time(),
        ),
        (
            second.volume_serial_number(),
            second.file_index(),
            second.creation_time(),
        ),
    )
}

#[cfg(not(any(unix, windows)))]
fn same_filesystem_identity(first: &cap_std::fs::Metadata, second: &cap_std::fs::Metadata) -> bool {
    first.file_type() == second.file_type() && first.len() == second.len()
}

fn is_canonical_sha256_identity(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn create_dir_all(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(|source| io_error(path, source))
}

fn atomic_create(path: &Path, bytes: &[u8]) -> Result<()> {
    atomic_create_with_directory_sync(path, bytes, sync_directory)
}

fn atomic_create_with_directory_sync(
    path: &Path,
    bytes: &[u8],
    directory_sync: impl FnOnce(&Path) -> std::io::Result<()>,
) -> Result<()> {
    let parent = path.parent().ok_or_else(|| StorageError::Io {
        path: path.display().to_string(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no parent"),
    })?;
    create_dir_all(parent)?;
    let mut temporary = NamedTempFile::new_in(parent).map_err(|source| io_error(parent, source))?;
    set_private_file_permissions(temporary.as_file(), path)?;
    temporary
        .write_all(bytes)
        .map_err(|source| io_error(path, source))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|source| io_error(path, source))?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| io_error(path, error.error))?;
    directory_sync(parent).map_err(|source| write_durability_unknown(path, source))?;
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    atomic_write_with_directory_sync(path, bytes, sync_directory)
}

fn atomic_write_with_directory_sync(
    path: &Path,
    bytes: &[u8],
    directory_sync: impl FnOnce(&Path) -> std::io::Result<()>,
) -> Result<()> {
    let parent = path.parent().ok_or_else(|| StorageError::Io {
        path: path.display().to_string(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no parent"),
    })?;
    create_dir_all(parent)?;
    let mut temporary = NamedTempFile::new_in(parent).map_err(|source| io_error(parent, source))?;
    set_private_file_permissions(temporary.as_file(), path)?;
    temporary
        .write_all(bytes)
        .map_err(|source| io_error(path, source))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|source| io_error(path, source))?;
    temporary
        .persist(path)
        .map_err(|error| io_error(path, error.error))?;
    directory_sync(parent).map_err(|source| write_durability_unknown(path, source))?;
    Ok(())
}

fn sync_directory(directory: &Path) -> std::io::Result<()> {
    fs::File::open(directory)?.sync_all()
}

#[cfg(unix)]
fn set_private_file_permissions(file: &fs::File, path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|source| io_error(path, source))
}

#[cfg(not(unix))]
fn set_private_file_permissions(_file: &fs::File, _path: &Path) -> Result<()> {
    Ok(())
}

fn io_error(path: &Path, source: std::io::Error) -> StorageError {
    StorageError::Io {
        path: path.display().to_string(),
        source,
    }
}

fn write_durability_unknown(path: &Path, source: std::io::Error) -> StorageError {
    StorageError::WriteDurabilityUnknown {
        path: path.display().to_string(),
        source,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod durability_tests {
    use super::*;

    #[test]
    fn atomic_state_writes_never_acknowledge_failed_directory_durability() {
        let root = tempfile::tempdir().expect("temporary storage root");
        for (name, replace, expected) in [
            ("create.json", false, b"new authority".as_slice()),
            ("replace.json", true, b"revoked authority".as_slice()),
        ] {
            let path = root.path().join(name);
            if replace {
                fs::write(&path, b"active authority").expect("seed authority");
            }
            let result = if replace {
                atomic_write_with_directory_sync(&path, expected, |_| {
                    Err(std::io::Error::other("injected directory sync failure"))
                })
            } else {
                atomic_create_with_directory_sync(&path, expected, |_| {
                    Err(std::io::Error::other("injected directory sync failure"))
                })
            };
            assert!(matches!(
                result,
                Err(StorageError::WriteDurabilityUnknown { path: failed, source })
                    if failed == path.display().to_string()
                        && source.to_string().contains("directory sync failure")
            ));
            assert_eq!(fs::read(path).expect("replacement crossed"), expected);
        }
    }
}
