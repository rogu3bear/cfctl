//! Platform-local persistence for plans, evidence, catalogs, and registered roots.

use std::{
    fs,
    io::Write,
    path::{Component, Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use cfctl_core::{EvidenceClass, EvidenceV1, PlanV1, redact_json};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use thiserror::Error;

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
    #[error("stored JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("the document contains secret material; store a keychain reference instead")]
    SensitiveData,
    #[error("import path escapes the managed data directory: `{0}`")]
    UnsafeImportPath(String),
    #[error("plan `{0}` does not exist")]
    PlanNotFound(String),
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
            &paths.data_dir.join("catalog"),
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
        let value = serde_json::to_value(plan)?;
        if redact_json(&value) != value {
            return Err(StorageError::SensitiveData);
        }
        self.write_json(&self.plan_path(&plan.operation_id), plan)
    }

    pub fn load_plan(&self, operation_id: &str) -> Result<PlanV1> {
        let path = self.plan_path(operation_id);
        if !path.is_file() {
            return Err(StorageError::PlanNotFound(operation_id.to_owned()));
        }
        self.read_json(&path)
    }

    pub fn list_plans(&self) -> Result<Vec<PlanV1>> {
        let directory = self.paths.data_dir.join("plans");
        let mut plans = Vec::new();
        for entry in fs::read_dir(&directory).map_err(|source| io_error(&directory, source))? {
            let entry = entry.map_err(|source| io_error(&directory, source))?;
            if entry.path().extension().and_then(std::ffi::OsStr::to_str) == Some("json") {
                plans.push(self.read_json(&entry.path())?);
            }
        }
        plans.sort_by_key(|plan: &PlanV1| plan.created_at);
        Ok(plans)
    }

    pub fn lock_plan(&self, operation_id: &str) -> Result<PlanLock> {
        let path = self
            .paths
            .data_dir
            .join("locks")
            .join(format!("{operation_id}.lock"));
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

    fn plan_path(&self, operation_id: &str) -> PathBuf {
        self.paths
            .data_dir
            .join("plans")
            .join(format!("{operation_id}.json"))
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
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(mut file) => {
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

fn create_dir_all(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(|source| io_error(path, source))
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(|| StorageError::Io {
        path: path.display().to_string(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no parent"),
    })?;
    create_dir_all(parent)?;
    let mut temporary = NamedTempFile::new_in(parent).map_err(|source| io_error(parent, source))?;
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
    Ok(())
}

fn io_error(path: &Path, source: std::io::Error) -> StorageError {
    StorageError::Io {
        path: path.display().to_string(),
        source,
    }
}
