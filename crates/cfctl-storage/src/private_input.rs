//! Borrowed private inputs: held descriptors and bounded bytes, without the
//! managed store's mode-0700 parent requirement. No returned error contains a
//! pathname, OS diagnostic, or input content.
use rustix::fs::{Mode, OFlags, openat};
use std::{
    fs::{self, File},
    io::Read as _,
    os::unix::fs::MetadataExt as _,
    path::{Component, Path, PathBuf},
};

#[derive(Clone, Copy, Debug)]
pub enum PrivateInputPermissions {
    /// Credential files may be read-only to their owner.
    OwnerRead,
    /// Existing D1 projection inputs require exactly mode 0600.
    OwnerReadWrite,
}

#[derive(Debug, thiserror::Error)]
#[error(
    "private input requires a bounded, stable, owned regular file without symlink components or hard links; group or others must have no access (chmod 600); no private value was disclosed"
)]
pub struct PrivateInputError;

/// Capture the bytes once. Callers parse/hash this value and never reopen the
/// input for content. Ancestors are held and revalidated, but need not be 0700.
pub fn capture_private_input(
    path: &Path,
    maximum: u64,
    permissions: PrivateInputPermissions,
) -> Result<Vec<u8>, PrivateInputError> {
    capture(path, maximum, permissions, |_| {})
}

#[derive(Clone, Copy)]
enum CaptureStage {
    Opened,
    Read,
}

fn capture(
    path: &Path,
    maximum: u64,
    permissions: PrivateInputPermissions,
    mut hook: impl FnMut(CaptureStage),
) -> Result<Vec<u8>, PrivateInputError> {
    let path = input_path(path)?;
    let (parent, ancestors) = open_parent(&path)?;
    let name = path.file_name().ok_or(PrivateInputError)?;
    let descriptor = openat(
        &parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| PrivateInputError)?;
    let mut file = File::from(descriptor);
    let before = file.metadata().map_err(|_| PrivateInputError)?;
    validate(
        &before,
        maximum,
        permissions,
        rustix::process::geteuid().as_raw(),
    )?;
    hook(CaptureStage::Opened);
    let bytes = read_bounded_private_bytes(&mut file, maximum)?;
    hook(CaptureStage::Read);
    let after = file.metadata().map_err(|_| PrivateInputError)?;
    validate(
        &after,
        maximum,
        permissions,
        rustix::process::geteuid().as_raw(),
    )?;
    if snapshot(&before) != snapshot(&after) || bytes.len() as u64 != after.len() {
        return Err(PrivateInputError);
    }
    let (_, current) = open_parent(&path)?;
    if ancestors != current {
        return Err(PrivateInputError);
    }
    let named = rustix::fs::statat(&parent, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| PrivateInputError)?;
    if crate::private_files::stat_identity(&named) != (after.dev(), after.ino()) {
        return Err(PrivateInputError);
    }
    Ok(bytes)
}

pub(crate) fn read_bounded_private_bytes(
    file: &mut impl std::io::Read,
    maximum: u64,
) -> Result<Vec<u8>, PrivateInputError> {
    let limit = maximum.checked_add(1).ok_or(PrivateInputError)?;
    let mut bytes = Vec::new();
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|_| PrivateInputError)?;
    if bytes.len() as u64 > maximum {
        return Err(PrivateInputError);
    }
    Ok(bytes)
}

fn validate(
    metadata: &fs::Metadata,
    maximum: u64,
    permissions: PrivateInputPermissions,
    owner: u32,
) -> Result<(), PrivateInputError> {
    let mode = metadata.mode() & 0o7777;
    let allowed = match permissions {
        PrivateInputPermissions::OwnerRead => matches!(mode, 0o400 | 0o600),
        PrivateInputPermissions::OwnerReadWrite => mode == 0o600,
    };
    if !metadata.is_file()
        || metadata.uid() != owner
        || !allowed
        || metadata.nlink() != 1
        || metadata.len() > maximum
    {
        return Err(PrivateInputError);
    }
    Ok(())
}

fn snapshot(metadata: &fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

type Ancestors = Vec<(u64, u64)>;
fn open_parent(path: &Path) -> Result<(File, Ancestors), PrivateInputError> {
    let root = rustix::fs::open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| PrivateInputError)?;
    let mut directory = File::from(root);
    let mut identities = Vec::new();
    for component in path.parent().ok_or(PrivateInputError)?.components() {
        if let Component::Normal(name) = component {
            directory = File::from(
                openat(
                    &directory,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| PrivateInputError)?,
            );
        }
        let metadata = directory.metadata().map_err(|_| PrivateInputError)?;
        identities.push((metadata.dev(), metadata.ino()));
    }
    Ok((directory, identities))
}

fn input_path(path: &Path) -> Result<PathBuf, PrivateInputError> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|_| PrivateInputError)?
            .join(path)
    };
    if absolute
        .components()
        .any(|part| matches!(part, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(PrivateInputError);
    }
    // macOS publishes these two root-owned system aliases. Only their exact
    // platform targets are admitted; arbitrary aliases are never canonicalized.
    #[cfg(target_os = "macos")]
    for (alias, target) in [("/var", "/private/var"), ("/tmp", "/private/tmp")] {
        if let Ok(tail) = absolute.strip_prefix(alias) {
            let link = fs::symlink_metadata(alias).map_err(|_| PrivateInputError)?;
            let destination = fs::read_link(alias).map_err(|_| PrivateInputError)?;
            if !link.file_type().is_symlink()
                || link.uid() != 0
                || (destination != Path::new(target)
                    && Path::new("/").join(destination) != Path::new(target))
            {
                return Err(PrivateInputError);
            }
            return Ok(Path::new(target).join(tail));
        }
    }
    Ok(absolute)
}

#[cfg(test)]
#[allow(clippy::expect_used)] // Fixture setup failures must fail the test.
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    const SENTINEL: &[u8] = b"secret-capture-sentinel";
    fn fixture() -> (tempfile::TempDir, PathBuf) {
        let root = tempfile::tempdir().expect("root");
        let path = root.path().join("input");
        fs::write(&path, SENTINEL).expect("bytes");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
        (root, path)
    }
    fn read(path: &Path, maximum: u64) -> Result<Vec<u8>, PrivateInputError> {
        capture_private_input(path, maximum, PrivateInputPermissions::OwnerRead)
    }
    fn refused(result: Result<Vec<u8>, PrivateInputError>) {
        let error = result.expect_err("custody refusal");
        for text in [error.to_string(), format!("{error:?}")] {
            assert!(!text.contains(std::str::from_utf8(SENTINEL).expect("sentinel")));
        }
    }

    #[test]
    fn borrowed_private_input_bounds_modes_owner_and_nonregulars() {
        let (root, path) = fixture();
        // A borrowed parent may be 0755, unlike the managed store.
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).expect("parent");
        assert_eq!(
            read(&path, SENTINEL.len() as u64).expect("exact bound"),
            SENTINEL
        );
        refused(read(&path, SENTINEL.len() as u64 - 1));
        for mode in [0o640, 0o644, 0o700, 0o4600] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("mode");
            refused(read(&path, 100));
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).expect("read only");
        assert_eq!(read(&path, 100).expect("owner read"), SENTINEL);
        refused(capture_private_input(
            &path,
            100,
            PrivateInputPermissions::OwnerReadWrite,
        ));
        let metadata = fs::metadata(&path).expect("metadata");
        assert!(
            validate(
                &metadata,
                100,
                PrivateInputPermissions::OwnerRead,
                metadata.uid().wrapping_add(1)
            )
            .is_err()
        );
        refused(read(root.path(), 100));
        let fifo = root.path().join("fifo");
        assert!(
            std::process::Command::new("mkfifo")
                .args(["-m", "600"])
                .arg(&fifo)
                .status()
                .expect("mkfifo")
                .success()
        );
        refused(read(&fifo, 100));
    }

    #[test]
    fn borrowed_private_input_refuses_links_and_ancestor_aliases() {
        let (root, path) = fixture();
        let alias = root.path().join("alias");
        symlink(&path, &alias).expect("terminal");
        refused(read(&alias, 100));
        let directory_alias = root.path().join("parent-alias");
        symlink(root.path(), &directory_alias).expect("ancestor");
        refused(read(&directory_alias.join("input"), 100));
        fs::hard_link(&path, root.path().join("hard-link")).expect("hard link");
        refused(read(&path, 100));
    }

    #[test]
    fn borrowed_private_input_detects_growth_replacement_and_same_length_change() {
        for stage in [CaptureStage::Opened, CaptureStage::Read] {
            for change in ["growth", "replacement", "same-length", "parent"] {
                let (root, path) = fixture();
                let maximum = SENTINEL.len() as u64;
                let result = capture(&path, maximum, PrivateInputPermissions::OwnerRead, |seen| {
                    if std::mem::discriminant(&stage) != std::mem::discriminant(&seen) {
                        return;
                    }
                    match change {
                        "growth" => fs::write(&path, [SENTINEL, b"!"].concat()).expect("grow"),
                        "replacement" => {
                            fs::rename(&path, root.path().join("old")).expect("rename");
                            fs::write(&path, SENTINEL).expect("replace");
                            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                                .expect("mode");
                        }
                        "same-length" => {
                            fs::write(&path, vec![b'x'; SENTINEL.len()]).expect("rewrite");
                        }
                        _ => {
                            // Replace an ancestor while retaining the original file descriptor.
                            fs::rename(root.path(), root.path().with_extension("moved"))
                                .expect("move parent");
                            fs::create_dir(root.path()).expect("replace parent");
                        }
                    }
                });
                refused(result);
                if change == "parent" {
                    fs::remove_dir_all(root.path().with_extension("moved"))
                        .expect("owned fixture cleanup");
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn borrowed_private_input_accepts_only_the_exact_system_aliases() {
        let (_root, path) = fixture();
        let physical = path.canonicalize().expect("physical fixture");
        let alias = Path::new("/").join(physical.strip_prefix("/private").expect("private tmp"));
        assert_eq!(read(&alias, 100).expect("system alias"), SENTINEL);
        assert_eq!(read(&physical, 100).expect("physical"), SENTINEL);
    }
}
