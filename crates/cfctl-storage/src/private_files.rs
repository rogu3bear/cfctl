//! Descriptor-relative private files for explicitly selected local authority.
//! Paths and keys never grant authority through symbolic or hard links.
use cfctl_auth::{AuthError, SecretBackend, SecretStore};
use rustix::fs::{Mode, OFlags, openat};
use sha2::{Digest as _, Sha256};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::{
    fs,
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
};
use uuid::Uuid;

const MAX_SECRET_BYTES: u64 = 4 * 1024 * 1024;

fn failure() -> AuthError {
    AuthError::SecretStore("private storage requires an owned mode-0700 directory and owned mode-0600 regular files without links; no value was disclosed".to_owned())
}

/// An opened directory pins every secret operation to one filesystem identity.
#[derive(Debug)]
pub struct PrivateDirectory {
    path: PathBuf,
    directory: fs::File,
}

impl PrivateDirectory {
    pub fn open(path: &Path) -> cfctl_auth::Result<Self> {
        let metadata = fs::symlink_metadata(path).map_err(|_| failure())?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(failure());
        }
        let directory = fs::OpenOptions::new()
            .read(true)
            .custom_flags(
                (OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC)
                    .bits()
                    .cast_signed(),
            )
            .open(path)
            .map_err(|_| failure())?;
        let opened = directory.metadata().map_err(|_| failure())?;
        if metadata.dev() != opened.dev()
            || metadata.ino() != opened.ino()
            || opened.uid() != rustix::process::geteuid().as_raw()
            || opened.mode() & 0o7777 != 0o700
        {
            return Err(failure());
        }
        Ok(Self {
            path: path.to_owned(),
            directory,
        })
    }

    pub fn create(path: &Path) -> cfctl_auth::Result<Self> {
        use std::os::unix::fs::DirBuilderExt as _;
        match fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => {
                let parent = path.parent().ok_or_else(failure)?;
                fs::File::open(parent)
                    .and_then(|file| file.sync_all())
                    .map_err(|_| failure())?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(failure()),
        }
        Self::open(path)
    }

    fn validate_address(&self) -> cfctl_auth::Result<()> {
        let current = Self::open(&self.path)?;
        let a = self.directory.metadata().map_err(|_| failure())?;
        let b = current.directory.metadata().map_err(|_| failure())?;
        if a.dev() != b.dev() || a.ino() != b.ino() {
            return Err(failure());
        }
        Ok(())
    }

    fn name(name: &str) -> cfctl_auth::Result<()> {
        if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\']) {
            return Err(failure());
        }
        Ok(())
    }

    pub fn read(&self, name: &str, maximum: u64) -> cfctl_auth::Result<Option<Vec<u8>>> {
        Self::name(name)?;
        self.validate_address()?;
        let descriptor = match openat(
            &self.directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(descriptor) => descriptor,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(_) => return Err(failure()),
        };
        let mut file = fs::File::from(descriptor);
        Self::validate_file(&file, maximum)?;
        let mut bytes = Vec::new();
        (&mut file)
            .take(maximum + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| failure())?;
        if bytes.len() as u64 > maximum {
            return Err(failure());
        }
        Self::validate_file(&file, maximum)?;
        self.validate_address()?;
        Ok(Some(bytes))
    }

    fn validate_file(file: &fs::File, maximum: u64) -> cfctl_auth::Result<()> {
        let metadata = file.metadata().map_err(|_| failure())?;
        if !metadata.is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
            || metadata.len() > maximum
        {
            return Err(failure());
        }
        Ok(())
    }

    pub fn write(&self, name: &str, bytes: &[u8]) -> cfctl_auth::Result<()> {
        Self::name(name)?;
        self.validate_address()?;
        // A preexisting unsafe target is rejected instead of silently replaced.
        self.read(name, (bytes.len() as u64).max(MAX_SECRET_BYTES))?;
        let temporary = format!(".staged-{}", Uuid::new_v4());
        let descriptor = openat(
            &self.directory,
            &temporary,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| failure())?;
        let result = (|| {
            let mut file = fs::File::from(descriptor);
            Self::validate_file(&file, bytes.len() as u64)?;
            file.write_all(bytes)
                .and_then(|()| file.sync_all())
                .map_err(|_| failure())?;
            self.validate_address()?;
            rustix::fs::renameat(&self.directory, &temporary, &self.directory, name)
                .map_err(|_| failure())?;
            self.directory.sync_all().map_err(|_| failure())?;
            self.validate_address()
        })();
        if result.is_err() {
            let _ = rustix::fs::unlinkat(&self.directory, &temporary, rustix::fs::AtFlags::empty());
        }
        result
    }

    pub fn remove(&self, name: &str) -> cfctl_auth::Result<()> {
        if self.read(name, MAX_SECRET_BYTES)?.is_none() {
            return Ok(());
        }
        rustix::fs::unlinkat(&self.directory, name, rustix::fs::AtFlags::empty())
            .map_err(|_| failure())?;
        self.directory.sync_all().map_err(|_| failure())?;
        self.validate_address()
    }

    pub fn lock(&self, exclusive: bool) -> cfctl_auth::Result<fs::File> {
        let descriptor = openat(
            &self.directory,
            "runtime.lock",
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| failure())?;
        let file = fs::File::from(descriptor);
        Self::validate_file(&file, 0)?;
        rustix::fs::flock(
            &file,
            if exclusive {
                rustix::fs::FlockOperation::NonBlockingLockExclusive
            } else {
                rustix::fs::FlockOperation::NonBlockingLockShared
            },
        )
        .map_err(|_| {
            AuthError::SecretStore(
                "another cfctl invocation is using this runtime; retry after it finishes"
                    .to_owned(),
            )
        })?;
        self.validate_address()?;
        Ok(file)
    }
}

/// Explicit local authority; unlike fallback storage, every access is durable
/// and validates private file custody. Debug never includes a secret value.
#[derive(Debug, Clone)]
pub struct PrivateFileSecretStore {
    root: PathBuf,
}
impl PrivateFileSecretStore {
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }
    fn name(key: &str) -> cfctl_auth::Result<String> {
        if key.is_empty() {
            return Err(failure());
        }
        Ok(format!(
            "{}.secret",
            hex::encode(Sha256::digest(key.as_bytes()))
        ))
    }
}
impl SecretStore for PrivateFileSecretStore {
    fn put(&self, key: &str, value: &str) -> cfctl_auth::Result<()> {
        if value.len() as u64 > MAX_SECRET_BYTES {
            return Err(failure());
        }
        PrivateDirectory::open(&self.root)?.write(&Self::name(key)?, value.as_bytes())
    }
    fn get(&self, key: &str) -> cfctl_auth::Result<Option<String>> {
        PrivateDirectory::open(&self.root)?
            .read(&Self::name(key)?, MAX_SECRET_BYTES)?
            .map(|bytes| String::from_utf8(bytes).map_err(|_| failure()))
            .transpose()
    }
    fn delete(&self, key: &str) -> cfctl_auth::Result<()> {
        PrivateDirectory::open(&self.root)?.remove(&Self::name(key)?)
    }
    fn locate(&self, key: &str) -> cfctl_auth::Result<Option<SecretBackend>> {
        Ok(self.get(key)?.map(|_| SecretBackend::PrivateFile))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    fn private_root() -> tempfile::TempDir {
        let root = tempfile::tempdir().expect("fixture directory");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
            .expect("private fixture permissions");
        root
    }

    #[test]
    fn private_files_reject_links_permissions_and_oversize_without_exposure() {
        let root = private_root();
        let directory = PrivateDirectory::open(root.path()).expect("private root");
        directory.write("value", b"private").expect("write");
        assert_eq!(
            directory.read("value", 7).expect("read"),
            Some(b"private".to_vec())
        );
        assert!(directory.read("value", 6).is_err());
        fs::hard_link(root.path().join("value"), root.path().join("hard")).expect("hard link");
        assert!(directory.read("value", 7).is_err());
        fs::remove_file(root.path().join("hard")).expect("unlink");
        symlink("value", root.path().join("symbolic")).expect("symlink");
        assert!(directory.write("symbolic", b"replacement").is_err());
        assert_eq!(
            fs::read(root.path().join("value")).expect("original"),
            b"private"
        );
        fs::set_permissions(root.path().join("value"), fs::Permissions::from_mode(0o644))
            .expect("permission change");
        assert!(directory.read("value", 7).is_err());
    }

    #[test]
    fn private_files_hold_runtime_lock_and_reject_replaced_directory() {
        let parent = private_root();
        let path = parent.path().join("private");
        let directory = PrivateDirectory::create(&path).expect("directory");
        let lock = directory.lock(true).expect("first lock");
        assert!(directory.lock(true).is_err());
        drop(lock);
        drop(directory.lock(true).expect("released lock"));
        fs::rename(&path, parent.path().join("old")).expect("rename");
        PrivateDirectory::create(&path).expect("replacement");
        assert!(directory.write("value", b"private").is_err());
        assert!(!path.join("value").exists());
    }

    #[test]
    fn private_runtime_shared_guards_coexist_and_exclude_activation() {
        let root = private_root();
        let directory = PrivateDirectory::open(root.path()).expect("directory");
        let first = directory.lock(false).expect("first ordinary command");
        let second = directory.lock(false).expect("second ordinary command");
        assert!(directory.lock(true).is_err());
        drop(first);
        assert!(directory.lock(true).is_err());
        drop(second);
        let activation = directory.lock(true).expect("exclusive activation");
        assert!(directory.lock(false).is_err());
        drop(activation);
        drop(directory.lock(false).expect("ordinary commands resume"));
    }

    #[test]
    fn private_secret_store_survives_restart_and_never_uses_platform() {
        let root = private_root();
        let first = PrivateFileSecretStore::new(root.path().to_owned());
        assert_eq!(first.get("profile/example").expect("empty"), None);
        first
            .put("profile/example", "fixture credential")
            .expect("first import");
        let reopened = PrivateFileSecretStore::new(root.path().to_owned());
        assert_eq!(
            reopened.locate("profile/example").expect("backend"),
            Some(SecretBackend::PrivateFile)
        );
        assert_eq!(
            reopened.get("profile/example").expect("read"),
            Some("fixture credential".to_owned())
        );
        reopened.delete("profile/example").expect("delete");
        assert_eq!(first.get("profile/example").expect("absent"), None);
    }
}
