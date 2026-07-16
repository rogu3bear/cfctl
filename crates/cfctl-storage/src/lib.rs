//! Platform-local persistence for plans, evidence, catalogs, and registered roots.

use std::{
    fs,
    io::Write,
    path::{Component, Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use cfctl_core::{
    EvidenceClass, EvidenceV1, PlanV1, StandingAuthorityStatus, StandingAuthorityV1, redact_json,
};
use directories::ProjectDirs;
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
    #[error("the document contains secret material; store a keychain reference instead")]
    SensitiveData,
    #[error("plan transaction state is invalid: {0}")]
    InvalidPlan(#[from] cfctl_core::CoreError),
    #[error("import path escapes the managed data directory: `{0}`")]
    UnsafeImportPath(String),
    #[error("plan `{0}` does not exist")]
    PlanNotFound(String),
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
    #[error("the standing authority lock guard does not authorize saving `{0}`")]
    AuthorityLockMismatch(String),
    #[error("standing authority `{0}` is durably revoked and cannot be restored")]
    AuthorityRevocationRollback(String),
    #[error("plan `{0}` is already locked")]
    PlanLocked(String),
    #[error("system clock is before the Unix epoch")]
    Clock,
}

pub type Result<T> = std::result::Result<T, StorageError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePaths {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub cache_dir: PathBuf,
}

impl RuntimePaths {
    pub fn discover() -> Result<Self> {
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

#[derive(Debug, Clone)]
pub struct StateStore {
    paths: RuntimePaths,
}

impl StateStore {
    pub fn open(paths: RuntimePaths) -> Result<Self> {
        for path in [
            &paths.config_dir,
            &paths.data_dir,
            &paths.cache_dir,
            &paths.data_dir.join("evidence"),
            &paths.data_dir.join("plans"),
            &paths.data_dir.join("locks"),
            &paths.data_dir.join("locks").join("authorities"),
            &paths.data_dir.join("catalog"),
            &paths.data_dir.join("authorities"),
        ] {
            create_dir_all(path)?;
        }
        Ok(Self { paths })
    }

    #[must_use]
    pub const fn paths(&self) -> &RuntimePaths {
        &self.paths
    }

    pub fn write_evidence(&self, class: EvidenceClass, value: &Value) -> Result<EvidenceV1> {
        let redacted = redact_json(value);
        let encoded = serde_json::to_vec_pretty(&redacted)?;
        let digest = hex::encode(Sha256::digest(&encoded));
        let content_hash = format!("sha256:{digest}");
        let path = self
            .paths
            .data_dir
            .join("evidence")
            .join(format!("{digest}.json"));
        if !path.exists() {
            atomic_write(&path, &encoded)?;
        }
        Ok(EvidenceV1::new(
            class,
            &content_hash,
            &path.display().to_string(),
        ))
    }

    pub fn save_plan(&self, plan: &PlanV1) -> Result<()> {
        validate_plan_id(&plan.operation_id)?;
        plan.validate_transaction_journal()?;
        let value = serde_json::to_value(plan)?;
        if redact_json(&value) != value {
            return Err(StorageError::SensitiveData);
        }
        let path = self.plan_path(&plan.operation_id)?;
        if validate_existing_managed_file(&path)? {
            let stored: PlanV1 = self.read_json(&path)?;
            ensure_plan_identity(&stored, &plan.operation_id)?;
            stored.validate_transaction_journal()?;
        }
        self.write_json(&path, plan)
    }

    pub fn load_plan(&self, operation_id: &str) -> Result<PlanV1> {
        let path = self.plan_path(operation_id)?;
        if !validate_existing_managed_file(&path)? {
            return Err(StorageError::PlanNotFound(operation_id.to_owned()));
        }
        let plan: PlanV1 = self.read_json(&path)?;
        ensure_plan_identity(&plan, operation_id)?;
        plan.validate_transaction_journal()?;
        Ok(plan)
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

    pub fn register_workspace_root(&self, root: &Path) -> Result<()> {
        let canonical = root
            .canonicalize()
            .map_err(|source| io_error(root, source))?;
        let mut roots = self.workspace_roots()?;
        if !roots.contains(&canonical) {
            roots.push(canonical);
            roots.sort();
            self.write_json(&self.paths.config_dir.join("workspace-roots.json"), &roots)?;
        }
        Ok(())
    }

    pub fn workspace_roots(&self) -> Result<Vec<PathBuf>> {
        let path = self.paths.config_dir.join("workspace-roots.json");
        if !path.is_file() {
            return Ok(Vec::new());
        }
        self.read_json(&path)
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

const LOCK_TTL: Duration = Duration::from_secs(15 * 60);

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
pub struct AuthorityLock {
    _file: fs::File,
    authority_id: String,
    authority_path: PathBuf,
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

    fn injected_directory_sync_failure(_directory: &Path) -> std::io::Result<()> {
        Err(std::io::Error::other(
            "injected parent-directory sync failure",
        ))
    }

    #[test]
    fn atomic_create_does_not_acknowledge_a_failed_directory_sync() {
        let root = tempfile::tempdir().expect("temporary storage root");
        let path = root.path().join("authority.json");
        let expected_path = path.display().to_string();

        let error = atomic_create_with_directory_sync(
            &path,
            b"new authority",
            injected_directory_sync_failure,
        )
        .expect_err("create must not report success without directory durability");
        assert!(error.to_string().contains("reload the exact document"));

        assert!(matches!(
            error,
            StorageError::WriteDurabilityUnknown { path: error_path, source }
                if error_path == expected_path
                    && source.kind() == std::io::ErrorKind::Other
                    && source.to_string().contains("parent-directory sync failure")
        ));
        assert_eq!(
            fs::read(&path).expect("rename completed before injected sync failure"),
            b"new authority"
        );
    }

    #[test]
    fn atomic_replace_reports_ambiguous_durability_after_directory_sync_failure() {
        let root = tempfile::tempdir().expect("temporary storage root");
        let path = root.path().join("authority.json");
        let expected_path = path.display().to_string();
        fs::write(&path, b"active authority").expect("write existing authority");

        let error = atomic_write_with_directory_sync(
            &path,
            b"revoked authority",
            injected_directory_sync_failure,
        )
        .expect_err("replace must not report success without directory durability");

        assert!(matches!(
            error,
            StorageError::WriteDurabilityUnknown { path: error_path, source }
                if error_path == expected_path
                    && source.kind() == std::io::ErrorKind::Other
                    && source.to_string().contains("parent-directory sync failure")
        ));
        assert_eq!(
            fs::read(&path).expect("rename completed before injected sync failure"),
            b"revoked authority"
        );
    }
}
