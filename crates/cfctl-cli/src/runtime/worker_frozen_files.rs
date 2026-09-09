//! Descriptor-relative capture: a rebinding ancestor never redirects a read.
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Read as _,
    path::{Component, Path, PathBuf},
};

use cfctl_core::worker_frozen_upload::{FrozenArtifactEntryV1, FrozenArtifactManifestV1};
use rustix::fs::{Dir, Mode, OFlags, open, openat};
use sha2::{Digest, Sha256};

use super::CliError;

const MAX_FILES: usize = 20_000;
const MAX_BYTES: u64 = 512 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 128 * 1024 * 1024;

pub(super) struct CapturedArtifact {
    pub manifest: FrozenArtifactManifestV1,
    pub bytes: BTreeMap<String, Vec<u8>>,
}

pub(super) fn failure(message: &str) -> CliError {
    CliError::Input(format!("frozen Worker artifact: {message}"))
}

fn io(path: &Path, source: std::io::Error) -> CliError {
    CliError::Io {
        path: path.display().to_string(),
        source,
    }
}

pub(super) fn relative_path(path: &Path) -> Result<String, CliError> {
    let value = path
        .to_str()
        .ok_or_else(|| failure("paths must be valid UTF-8"))?;
    if value.is_empty()
        || value.contains('\\')
        || value.chars().any(char::is_control)
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(failure(
            "paths must be unambiguous repository-relative names",
        ));
    }
    Ok(value.to_owned())
}

/// Every component, including the file, is opened relative to an already-open
/// directory with `O_NOFOLLOW`. Metadata and content come from that same handle.
pub(super) fn open_absolute(path: &Path, directory: bool) -> Result<File, CliError> {
    if !path.is_absolute() {
        return Err(failure("capture requires an absolute canonical path"));
    }
    let mut handle = File::from(
        open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| io(Path::new("/"), error.into()))?,
    );
    let parts = path.components().skip(1).collect::<Vec<_>>();
    for (index, part) in parts.iter().enumerate() {
        let Component::Normal(name) = part else {
            return Err(failure("capture path contains a noncanonical component"));
        };
        let mut flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        if directory || index + 1 != parts.len() {
            flags |= OFlags::DIRECTORY;
        }
        handle = File::from(
            openat(&handle, *name, flags, Mode::empty()).map_err(|error| io(path, error.into()))?,
        );
    }
    Ok(handle)
}

fn read_regular(mut file: File, path: &Path, limit: u64) -> Result<Vec<u8>, CliError> {
    let metadata = file.metadata().map_err(|source| io(path, source))?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(failure("input must be a bounded regular file"));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| io(path, source))?;
    if bytes.len() as u64 > limit || bytes.len() as u64 != metadata.len() {
        return Err(failure("file grew or changed during capture"));
    }
    Ok(bytes)
}

pub(super) fn config_bytes(path: &Path) -> Result<Vec<u8>, CliError> {
    read_regular(open_absolute(path, false)?, path, 1_048_576)
}

fn ambient_control(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | "node_modules"
            | ".wrangler"
            | "wrangler.toml"
            | "wrangler.json"
            | "wrangler.jsonc"
            | "tsconfig.json"
            | "jsconfig.json"
    ) || name == ".env"
        || name.starts_with(".env.")
        || name == ".dev.vars"
        || name.starts_with(".dev.vars.")
}

fn capture_directory(
    handle: &File,
    relative: &Path,
    files: &mut BTreeMap<String, Vec<u8>>,
    directories: &mut BTreeSet<String>,
    total: &mut u64,
) -> Result<(), CliError> {
    if relative.components().count() > 128 {
        return Err(failure(
            "artifact directory nesting exceeds the capture bound",
        ));
    }
    directories.insert(relative_path(relative)?);
    if directories.len() > MAX_FILES {
        return Err(failure("too many artifact directories"));
    }
    let mut entries = Dir::read_from(handle).map_err(|error| io(relative, error.into()))?;
    while let Some(entry) = entries.read() {
        let entry = entry.map_err(|error| io(relative, error.into()))?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| failure("file names must be UTF-8"))?;
        if matches!(name, "." | "..") {
            continue;
        }
        if ambient_control(name) {
            return Err(failure(
                "artifact contains ambient configuration or dependency discovery inputs",
            ));
        }
        let path = relative.join(name);
        let key = relative_path(&path)?;
        let child = File::from(
            openat(
                handle,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|error| io(&path, error.into()))?,
        );
        let metadata = child.metadata().map_err(|source| io(&path, source))?;
        if metadata.is_dir() {
            capture_directory(&child, &path, files, directories, total)?;
        } else {
            let bytes = read_regular(child, &path, MAX_FILE_BYTES)?;
            *total = total
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| failure("size overflow"))?;
            if *total > MAX_BYTES || files.len() >= MAX_FILES {
                return Err(failure("artifact exceeds the bounded capture budget"));
            }
            files.insert(key, bytes);
        }
    }
    Ok(())
}

pub(super) fn capture(repository: &Path, roots: &[PathBuf]) -> Result<CapturedArtifact, CliError> {
    let mut files = BTreeMap::new();
    let mut directories = BTreeSet::new();
    let mut total = 0;
    let mut relative_roots = BTreeSet::new();
    for root in roots {
        let relative = root
            .strip_prefix(repository)
            .map_err(|_| failure("artifact root escaped repository"))?;
        relative_roots.insert(relative_path(relative)?);
        let handle = open_absolute(root, true)?;
        capture_directory(&handle, relative, &mut files, &mut directories, &mut total)?;
    }
    if files.is_empty() {
        return Err(failure("artifact file set is empty"));
    }
    let entries = files
        .iter()
        .map(|(path, bytes)| FrozenArtifactEntryV1 {
            path: path.clone(),
            size: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(bytes)),
        })
        .collect::<Vec<_>>();
    let mut digest_text = String::new();
    for entry in &entries {
        digest_text.push_str(&entry.sha256);
        digest_text.push_str("  ");
        digest_text.push_str(&entry.path);
        digest_text.push('\n');
    }
    Ok(CapturedArtifact {
        manifest: FrozenArtifactManifestV1 {
            schema_version: 1,
            roots: relative_roots.into_iter().collect(),
            directories: directories.into_iter().collect(),
            entries,
            sha256: hex::encode(Sha256::digest(digest_text.as_bytes())),
        },
        bytes: files,
    })
}

pub(super) fn write_private(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|source| io(path, source))?;
    file.write_all(bytes).map_err(|source| io(path, source))
}
