use std::{
    fs,
    io::Read as _,
    path::{Path, PathBuf},
};

use cap_std::{ambient_authority, fs::Dir};
use rustix::fs::{Mode, OFlags};
use sha2::{Digest as _, Sha256};

use super::{MAX_LOGICAL_CREDENTIAL_BYTES, MacosKeychainAdapter, MutationGuard};
use crate::{AuthError, Result};

pub(super) struct SecurityCommandAdapter;

struct KeyringMutationLock {
    parent: Dir,
    _authority_lock: fs::File,
    root: Dir,
    file: fs::File,
    parent_path: PathBuf,
    parent_identity: FilesystemIdentity,
    root_name: String,
    root_path: PathBuf,
    root_identity: FilesystemIdentity,
    lock_name: String,
    lock_identity: FilesystemIdentity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FilesystemIdentity {
    device: u64,
    inode: u64,
    birth_seconds: i64,
    birth_nanoseconds: i64,
}

const MUTATION_LOCK_ROOT_COMPONENT: &str = "io.cfctl.cfctl-keyring-mutations";
const MAX_GETCONF_STDOUT_BYTES: usize = 4_096;
const GETCONF_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

impl MacosKeychainAdapter for SecurityCommandAdapter {
    fn put_raw(&self, service: &str, key: &str, value: &str) -> Result<()> {
        security_command_put(service, key, value)
    }

    fn get_raw(&self, service: &str, key: &str) -> Result<Option<String>> {
        security_command_get(service, key)
    }

    fn delete_raw(&self, service: &str, key: &str) -> Result<()> {
        security_command_delete(service, key)
    }

    fn acquire_mutation_lock<'a>(
        &'a self,
        service: &str,
        key: &str,
    ) -> Result<Box<dyn MutationGuard + 'a>> {
        acquire_mutation_lock(service, key).map(|guard| Box::new(guard) as Box<dyn MutationGuard>)
    }
}

fn mutation_lock_root() -> Result<PathBuf> {
    let mut command = std::process::Command::new("/usr/bin/getconf");
    command.arg("DARWIN_USER_TEMP_DIR").env_clear();
    mutation_lock_root_with_command(&mut command, GETCONF_TIMEOUT)
}

fn mutation_lock_root_with_command(
    command: &mut std::process::Command,
    timeout: std::time::Duration,
) -> Result<PathBuf> {
    use std::os::unix::process::CommandExt as _;

    let mut child = command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(|error| AuthError::SecretStore(error.to_string()))?;
    let Some(mut stdout) = child.stdout.take() else {
        kill_and_reap(&mut child);
        return Err(AuthError::SecretStore(
            "platform user lock authority lookup produced no output sink".to_owned(),
        ));
    };
    let flags = match rustix::fs::fcntl_getfl(&stdout) {
        Ok(flags) => flags,
        Err(error) => {
            kill_and_reap(&mut child);
            return Err(AuthError::SecretStore(error.to_string()));
        }
    };
    if let Err(error) = rustix::fs::fcntl_setfl(&stdout, flags | OFlags::NONBLOCK) {
        kill_and_reap(&mut child);
        return Err(AuthError::SecretStore(error.to_string()));
    }
    let mut bytes = vec![0_u8; MAX_GETCONF_STDOUT_BYTES + 1];
    let mut filled = 0;
    let deadline = std::time::Instant::now() + timeout;
    let mut status = None;
    let mut stdout_closed = false;
    loop {
        while !stdout_closed && filled < bytes.len() {
            match stdout.read(&mut bytes[filled..]) {
                Ok(0) => {
                    stdout_closed = true;
                    break;
                }
                Ok(read) => filled += read,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => {
                    kill_and_reap(&mut child);
                    return Err(AuthError::SecretStore(error.to_string()));
                }
            }
        }
        if filled == bytes.len() {
            kill_and_reap(&mut child);
            return Err(AuthError::SecretStore(
                "platform user lock authority lookup returned an invalid byte length".to_owned(),
            ));
        }
        if status.is_none() {
            match child.try_wait() {
                Ok(observed) => status = observed,
                Err(error) => {
                    kill_and_reap(&mut child);
                    return Err(AuthError::SecretStore(format!(
                        "platform user lock authority lookup status failed: {error}"
                    )));
                }
            }
        }
        if let Some(observed) = status {
            if !observed.success() {
                kill_and_reap(&mut child);
                bytes.truncate(filled);
                return parse_mutation_lock_root_output(observed, bytes);
            }
            if stdout_closed {
                bytes.truncate(filled);
                return parse_mutation_lock_root_output(observed, bytes);
            }
        }
        if std::time::Instant::now() >= deadline {
            kill_and_reap(&mut child);
            return Err(AuthError::SecretStore(format!(
                "platform user lock authority lookup timed out after {} milliseconds",
                timeout.as_millis()
            )));
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn kill_and_reap(child: &mut std::process::Child) {
    if let Ok(raw_pid) = i32::try_from(child.id())
        && let Some(pid) = rustix::process::Pid::from_raw(raw_pid)
    {
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn parse_mutation_lock_root_output(
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
) -> Result<PathBuf> {
    if !status.success() {
        return Err(AuthError::SecretStore(format!(
            "platform user lock authority lookup failed with exit status {status}"
        )));
    }
    if stdout.is_empty() || stdout.len() > MAX_GETCONF_STDOUT_BYTES {
        return Err(AuthError::SecretStore(
            "platform user lock authority lookup returned an invalid byte length".to_owned(),
        ));
    }
    let value = String::from_utf8(stdout).map_err(|_| {
        AuthError::SecretStore("platform user lock authority is not valid UTF-8".to_owned())
    })?;
    let Some(path) = value.strip_suffix('\n') else {
        return Err(AuthError::SecretStore(
            "platform user lock authority is missing its line terminator".to_owned(),
        ));
    };
    if path.is_empty() || path.contains(['\0', '\n', '\r']) {
        return Err(AuthError::SecretStore(
            "platform user lock authority has invalid framing".to_owned(),
        ));
    }
    let base = PathBuf::from(path);
    if !base.is_absolute() {
        return Err(AuthError::SecretStore(
            "platform user lock authority must be absolute".to_owned(),
        ));
    }
    Ok(base.join(MUTATION_LOCK_ROOT_COMPONENT))
}

fn mutation_lock_path(root: &Path, service: &str, key: &str) -> PathBuf {
    let digest = hex::encode(Sha256::digest(
        format!("keyring-mutation-v1\0{service}\0{key}").as_bytes(),
    ));
    root.join(format!("{digest}.lock"))
}

#[cfg(test)]
fn open_mutation_lock_file(root: &Path, service: &str, key: &str) -> Result<fs::File> {
    open_mutation_lock_file_with_hook(root, service, key, |_| Ok(())).map(|guard| guard.file)
}

fn open_mutation_lock_file_with_hook(
    root: &Path,
    service: &str,
    key: &str,
    after_open: impl FnOnce(&Path) -> Result<()>,
) -> Result<KeyringMutationLock> {
    let parent_path = root.parent().ok_or_else(|| {
        AuthError::SecretStore("platform keyring mutation lock root has no parent".to_owned())
    })?;
    let root_name = root
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            AuthError::SecretStore(
                "platform keyring mutation lock root has an invalid name".to_owned(),
            )
        })?
        .to_owned();
    let parent_entry = fs::symlink_metadata(parent_path)
        .map_err(|error| AuthError::SecretStore(error.to_string()))?;
    if parent_entry.file_type().is_symlink() || !parent_entry.is_dir() {
        return Err(AuthError::SecretStore(
            "platform keyring mutation lock parent must be a real directory".to_owned(),
        ));
    }
    let parent = Dir::open_ambient_dir(parent_path, ambient_authority())
        .map_err(|error| AuthError::SecretStore(error.to_string()))?;
    let parent_identity = filesystem_identity_from_dir(&parent, parent_path)?;
    if !standard_metadata_matches(&parent_entry, parent_identity) {
        return Err(lock_identity_error(
            "parent identity changed while opening authority",
        ));
    }
    let authority_lock = parent
        .try_clone()
        .map_err(|error| AuthError::SecretStore(error.to_string()))?
        .into_std_file();
    authority_lock
        .lock()
        .map_err(|error| AuthError::SecretStore(error.to_string()))?;
    require_parent_identity(parent_path, &parent, parent_identity)?;
    match parent.create_dir(&root_name) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(AuthError::SecretStore(error.to_string())),
    }
    let root_entry = parent
        .symlink_metadata(&root_name)
        .map_err(|error| AuthError::SecretStore(error.to_string()))?;
    if root_entry.file_type().is_symlink() || !root_entry.is_dir() {
        return Err(AuthError::SecretStore(
            "platform keyring mutation lock root must be a real directory".to_owned(),
        ));
    }
    let lock_root = parent
        .open_dir(&root_name)
        .map_err(|error| AuthError::SecretStore(error.to_string()))?;
    let root_identity = filesystem_identity_from_dir(&lock_root, root)?;
    if !capability_metadata_matches(&root_entry, root_identity) {
        return Err(lock_identity_error(
            "root identity changed while opening capability",
        ));
    }
    require_parent_identity(parent_path, &parent, parent_identity)?;
    require_root_identity(&parent, &root_name, &lock_root, root_identity, root)?;
    let root_file = lock_root
        .try_clone()
        .map_err(|error| AuthError::SecretStore(error.to_string()))?
        .into_std_file();
    set_handle_mode(&root_file, 0o700)?;
    require_root_identity(&parent, &root_name, &lock_root, root_identity, root)?;

    let lock_path = mutation_lock_path(root, service, key);
    let lock_name = lock_path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| {
            AuthError::SecretStore(
                "platform keyring mutation lock digest name is invalid".to_owned(),
            )
        })?
        .to_owned();
    reject_unsafe_lock_entry_if_present(&lock_root, &lock_name)?;
    let file = open_lock_nofollow(&lock_root, &lock_name, true)?;
    after_open(&lock_path)?;
    let lock_identity = filesystem_identity_from_file(&file)?;
    require_single_link_regular_file(&file)?;
    require_lock_identity(&lock_root, &lock_name, lock_identity)?;
    require_parent_identity(parent_path, &parent, parent_identity)?;
    require_root_identity(&parent, &root_name, &lock_root, root_identity, root)?;
    set_handle_mode(&file, 0o600)?;
    require_lock_identity(&lock_root, &lock_name, lock_identity)?;
    Ok(KeyringMutationLock {
        parent,
        _authority_lock: authority_lock,
        root: lock_root,
        file,
        parent_path: parent_path.to_path_buf(),
        parent_identity,
        root_name,
        root_path: root.to_path_buf(),
        root_identity,
        lock_name,
        lock_identity,
    })
}

fn acquire_mutation_lock(service: &str, key: &str) -> Result<KeyringMutationLock> {
    acquire_mutation_lock_at_with_hooks(
        &mutation_lock_root()?,
        service,
        key,
        |_| Ok(()),
        |_| Ok(()),
    )
}

fn acquire_mutation_lock_at_with_hooks(
    root: &Path,
    service: &str,
    key: &str,
    after_open: impl FnOnce(&Path) -> Result<()>,
    after_lock: impl FnOnce(&Path) -> Result<()>,
) -> Result<KeyringMutationLock> {
    let guard = open_mutation_lock_file_with_hook(root, service, key, after_open)?;
    guard
        .file
        .lock()
        .map_err(|error| AuthError::SecretStore(error.to_string()))?;
    after_lock(&mutation_lock_path(root, service, key))?;
    guard.require_identity()?;
    Ok(guard)
}

impl KeyringMutationLock {
    fn require_identity(&self) -> Result<()> {
        require_parent_identity(&self.parent_path, &self.parent, self.parent_identity)?;
        require_root_identity(
            &self.parent,
            &self.root_name,
            &self.root,
            self.root_identity,
            &self.root_path,
        )?;
        require_lock_identity(&self.root, &self.lock_name, self.lock_identity)
    }
}

fn lock_identity_error(reason: &str) -> AuthError {
    AuthError::SecretStore(format!(
        "platform keyring mutation lock authority is unsafe: {reason}"
    ))
}

fn filesystem_identity_from_file(file: &fs::File) -> Result<FilesystemIdentity> {
    use std::os::{macos::fs::MetadataExt as _, unix::fs::MetadataExt as _};

    let metadata = file
        .metadata()
        .map_err(|error| AuthError::SecretStore(error.to_string()))?;
    Ok(FilesystemIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        birth_seconds: metadata.st_birthtime(),
        birth_nanoseconds: metadata.st_birthtime_nsec(),
    })
}

fn filesystem_identity_from_dir(
    directory: &Dir,
    display_path: &Path,
) -> Result<FilesystemIdentity> {
    let file = directory
        .try_clone()
        .map_err(|error| AuthError::SecretStore(error.to_string()))?
        .into_std_file();
    filesystem_identity_from_file(&file).map_err(|_| {
        AuthError::SecretStore(format!(
            "platform keyring mutation lock identity is unavailable for {}",
            display_path.display()
        ))
    })
}

fn standard_metadata_matches(metadata: &fs::Metadata, identity: FilesystemIdentity) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    metadata.dev() == identity.device && metadata.ino() == identity.inode
}

fn capability_metadata_matches(
    metadata: &cap_std::fs::Metadata,
    identity: FilesystemIdentity,
) -> bool {
    use cap_std::fs::MetadataExt as _;

    metadata.dev() == identity.device && metadata.ino() == identity.inode
}

fn require_parent_identity(path: &Path, held: &Dir, identity: FilesystemIdentity) -> Result<()> {
    let entry =
        fs::symlink_metadata(path).map_err(|error| AuthError::SecretStore(error.to_string()))?;
    if entry.file_type().is_symlink()
        || !entry.is_dir()
        || !standard_metadata_matches(&entry, identity)
        || filesystem_identity_from_dir(held, path)? != identity
    {
        return Err(lock_identity_error("parent identity changed"));
    }
    let reopened = Dir::open_ambient_dir(path, ambient_authority())
        .map_err(|error| AuthError::SecretStore(error.to_string()))?;
    if filesystem_identity_from_dir(&reopened, path)? != identity {
        return Err(lock_identity_error("parent replacement was detected"));
    }
    Ok(())
}

fn require_root_identity(
    parent: &Dir,
    name: &str,
    held: &Dir,
    identity: FilesystemIdentity,
    display_path: &Path,
) -> Result<()> {
    let entry = parent
        .symlink_metadata(name)
        .map_err(|error| AuthError::SecretStore(error.to_string()))?;
    if entry.file_type().is_symlink()
        || !entry.is_dir()
        || !capability_metadata_matches(&entry, identity)
        || filesystem_identity_from_dir(held, display_path)? != identity
    {
        return Err(lock_identity_error("root identity changed"));
    }
    let reopened = parent
        .open_dir(name)
        .map_err(|error| AuthError::SecretStore(error.to_string()))?;
    if filesystem_identity_from_dir(&reopened, display_path)? != identity {
        return Err(lock_identity_error("root replacement was detected"));
    }
    Ok(())
}

fn reject_unsafe_lock_entry_if_present(directory: &Dir, name: &str) -> Result<()> {
    use cap_std::fs::MetadataExt as _;

    let metadata = match directory.symlink_metadata(name) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(AuthError::SecretStore(error.to_string())),
    };
    if metadata.file_type().is_symlink() {
        return Err(lock_identity_error("symbolic lock links are forbidden"));
    }
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(lock_identity_error(
            "lock entry must be one singly linked regular file",
        ));
    }
    Ok(())
}

fn open_lock_nofollow(directory: &Dir, name: &str, create: bool) -> Result<fs::File> {
    let mut flags = OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    if create {
        flags |= OFlags::CREATE;
    }
    rustix::fs::openat(directory, name, flags, Mode::RUSR | Mode::WUSR)
        .map(fs::File::from)
        .map_err(|error| AuthError::SecretStore(error.to_string()))
}

fn require_single_link_regular_file(file: &fs::File) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file
        .metadata()
        .map_err(|error| AuthError::SecretStore(error.to_string()))?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return Err(lock_identity_error(
            "opened lock must be one singly linked regular file",
        ));
    }
    Ok(())
}

fn require_lock_identity(directory: &Dir, name: &str, identity: FilesystemIdentity) -> Result<()> {
    use cap_std::fs::MetadataExt as _;

    let entry = directory
        .symlink_metadata(name)
        .map_err(|error| AuthError::SecretStore(error.to_string()))?;
    if entry.file_type().is_symlink()
        || !entry.is_file()
        || entry.nlink() != 1
        || !capability_metadata_matches(&entry, identity)
    {
        return Err(lock_identity_error("lock entry identity changed"));
    }
    let reopened = open_lock_nofollow(directory, name, false)?;
    require_single_link_regular_file(&reopened)?;
    if filesystem_identity_from_file(&reopened)? != identity {
        return Err(lock_identity_error("lock handle identity changed"));
    }
    Ok(())
}

fn set_handle_mode(file: &fs::File, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    file.set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|error| AuthError::SecretStore(error.to_string()))
}

/// Apple status codes this adapter classifies rather than passes through.
///
/// `errSecItemNotFound` is absence, not failure. `errSecUserCanceled`,
/// `errSecAuthFailed`, and `errSecInteractionNotAllowed` all mean the store is
/// present and answering but is withholding this operation until an operator
/// authorizes it, which is a different disposition from an unavailable backend.
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
const ERR_SEC_USER_CANCELED: i32 = -128;
const ERR_SEC_AUTH_FAILED: i32 = -25293;
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;
const ERR_SEC_INVALID_OWNER_EDIT: i32 = -25244;

/// Whether a status means the item exists but belongs to another application.
///
/// Items this tool wrote through the superseded subprocess adapter are owned by
/// `/usr/bin/security`, and macOS does not let an update reassign ownership.
/// Inside cfctl's own service and key namespace such an item is this tool's own
/// superseded state, so it is replaced rather than treated as a foreign secret.
const fn is_ownership_conflict(code: i32) -> bool {
    code == ERR_SEC_INVALID_OWNER_EDIT
}

/// Prefix for the journal that carries a value across an ownership migration.
///
/// The superseded subprocess adapter never wrote under this prefix, so cfctl
/// always creates these items fresh and owns them. That is what makes the
/// migration journallable at all: the journal write cannot itself hit an
/// ownership conflict.
const OWNERSHIP_MIGRATION_KEY_PREFIX: &str = "__cfctl_internal__/ownership-migration/v1";

fn ownership_migration_key(key: &str) -> String {
    format!("{OWNERSHIP_MIGRATION_KEY_PREFIX}/{key}")
}

/// Choose which stored copy answers a read.
///
/// The primary wins whenever it exists. The journal answers only when the
/// primary is absent, which is exactly the window where a migration deleted the
/// superseded item and had not yet republished it.
fn resolve_stored_value(primary: Option<Vec<u8>>, journal: Option<Vec<u8>>) -> Option<Vec<u8>> {
    primary.or(journal)
}

/// Replace an item owned by another application with one this tool owns.
///
/// The value is journalled before the superseded item is deleted, so no
/// interruption can leave it recorded nowhere:
///
/// - failing at the journal changes nothing;
/// - stopping after the delete leaves the value in the journal, where
///   [`security_command_get`] finds it and the next write republishes it;
/// - stopping after the republish leaves an inert journal that the primary
///   shadows on every read.
fn migrate_item_ownership(service: &str, key: &str, value: &str) -> Result<()> {
    let journal = ownership_migration_key(key);
    security_framework::passwords::set_generic_password(service, &journal, value.as_bytes())
        .map_err(classify_keychain_error)?;
    security_framework::passwords::delete_generic_password(service, key)
        .map_err(classify_keychain_error)?;
    security_framework::passwords::set_generic_password(service, key, value.as_bytes())
        .map_err(classify_keychain_error)?;
    // The value is durable under its own key now, so failing to retire the
    // journal leaves only state the primary already shadows.
    let _retired = security_framework::passwords::delete_generic_password(service, &journal);
    Ok(())
}

/// Read one item, tolerating an interrupted ownership migration.
fn read_item(service: &str, key: &str) -> Result<Option<Vec<u8>>> {
    match security_framework::passwords::get_generic_password(service, key) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
        Err(error) => Err(classify_keychain_error(error)),
    }
}

fn classify_keychain_error(error: security_framework::base::Error) -> AuthError {
    match error.code() {
        ERR_SEC_USER_CANCELED | ERR_SEC_AUTH_FAILED | ERR_SEC_INTERACTION_NOT_ALLOWED => {
            AuthError::SecretStoreAuthorizationRequired
        }
        code => AuthError::SecretStore(format!(
            "platform keyring operation failed with status {code}{}",
            error
                .message()
                .map_or_else(String::new, |message| format!(": {message}"))
        )),
    }
}

/// Validate one value crossing the platform boundary.
///
/// The bounds and the line-break rule are contract, not framing: they bound what
/// this store will hold and keep a value from spanning what any line-oriented
/// consumer would treat as two.
fn validate_keychain_value(bytes: Vec<u8>) -> Result<String> {
    if bytes.len() > MAX_LOGICAL_CREDENTIAL_BYTES {
        return Err(AuthError::SecretStore(
            "platform keyring item exceeds the maximum logical byte bound".to_owned(),
        ));
    }
    if bytes.contains(&b'\n') || bytes.contains(&b'\r') {
        return Err(AuthError::SecretStore(
            "platform keyring credential contains an unexpected line break".to_owned(),
        ));
    }
    String::from_utf8(bytes).map_err(|_| {
        AuthError::SecretStore("platform keyring credential is not valid UTF-8".to_owned())
    })
}

// Security.framework's interaction flag is process-global. Hold this lock until
// the SDK guard restores it so one operation cannot re-enable another's dialogs.
static KEYCHAIN_INTERACTION: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn with_keychain_interaction<T, Guard>(
    serialization: &std::sync::Mutex<()>,
    suppress: impl FnOnce() -> Result<Guard>,
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let _serialization = serialization.lock().map_err(|_| {
        AuthError::SecretStore(
            "Keychain interaction lock is poisoned; credential operation not attempted".to_owned(),
        )
    })?;
    let _dialogs = suppress()?;
    operation()
}

fn quiet_keychain_guard<Guard>(
    interaction_allowed: impl FnOnce() -> Result<bool>,
    disable: impl FnOnce() -> Result<Guard>,
) -> Result<Option<Guard>> {
    // The SDK destructor always enables interaction; preserve an already
    // disabled process flag by avoiding that destructor entirely.
    if !interaction_allowed()? {
        return Ok(None);
    }
    disable().map(Some)
}

fn with_noninteractive_keychain<T>(operation: impl FnOnce() -> Result<T>) -> Result<T> {
    use security_framework::os::macos::keychain::SecKeychain;

    let guard_error = |error: security_framework::base::Error| {
        AuthError::SecretStore(format!(
            "cannot establish noninteractive Keychain access (status {}); credential operation not attempted",
            error.code()
        ))
    };
    with_keychain_interaction(
        &KEYCHAIN_INTERACTION,
        || {
            quiet_keychain_guard(
                || SecKeychain::user_interaction_allowed().map_err(guard_error),
                || SecKeychain::disable_user_interaction().map_err(guard_error),
            )
        },
        operation,
    )
}

fn security_command_put(service: &str, key: &str, value: &str) -> Result<()> {
    if value.contains(['\n', '\r']) {
        return Err(AuthError::SecretStore(
            "macOS Keychain credentials cannot contain line breaks".to_owned(),
        ));
    }
    if value.len() > MAX_LOGICAL_CREDENTIAL_BYTES {
        return Err(AuthError::SecretStore(
            "platform keyring item exceeds the maximum logical byte bound".to_owned(),
        ));
    }
    with_noninteractive_keychain(|| {
        match security_framework::passwords::set_generic_password(service, key, value.as_bytes()) {
            Ok(()) => Ok(()),
            // Ownership migration. An item written by the superseded subprocess adapter
            // is owned by /usr/bin/security, and no update can take that ownership, so
            // every installation upgrading to the native adapter would otherwise fail its
            // first write. Replacing the item in place is the only forward path, and it
            // is confined to cfctl's own service and key namespace.
            Err(error) if is_ownership_conflict(error.code()) => {
                migrate_item_ownership(service, key, value)
            }
            Err(error) => Err(classify_keychain_error(error)),
        }
    })
}

fn security_command_get(service: &str, key: &str) -> Result<Option<String>> {
    with_noninteractive_keychain(|| {
        let primary = read_item(service, key)?;
        // Consult the migration journal only when the primary is absent. A pending
        // crossing is an answer, not a failure: an interrupted ownership migration
        // stays invisible to callers instead of reading as a missing credential.
        let journal = if primary.is_some() {
            None
        } else {
            read_item(service, &ownership_migration_key(key))?
        };
        match resolve_stored_value(primary, journal) {
            Some(bytes) => validate_keychain_value(bytes).map(Some),
            None => Ok(None),
        }
    })
}

#[cfg(test)]
const MAX_SECURITY_FRAME_BYTES: usize = 2;
#[cfg(test)]
const MAX_SECURITY_STDOUT_BYTES: usize = MAX_LOGICAL_CREDENTIAL_BYTES + MAX_SECURITY_FRAME_BYTES;

#[cfg(test)]
pub(super) fn decode_security_stdout(mut bytes: Vec<u8>) -> Result<String> {
    if bytes.len() > MAX_SECURITY_STDOUT_BYTES {
        return Err(AuthError::SecretStore(
            "platform keyring item exceeds the maximum encoded byte bound".to_owned(),
        ));
    }
    if bytes.ends_with(b"\r\n") {
        bytes.truncate(bytes.len() - 2);
    } else if bytes.last() == Some(&b'\n') {
        bytes.pop();
    } else {
        return Err(AuthError::SecretStore(
            "platform keyring output is missing its line terminator".to_owned(),
        ));
    }
    if bytes.len() > MAX_LOGICAL_CREDENTIAL_BYTES {
        return Err(AuthError::SecretStore(
            "platform keyring item exceeds the maximum logical byte bound".to_owned(),
        ));
    }
    if bytes.contains(&b'\n') || bytes.contains(&b'\r') {
        return Err(AuthError::SecretStore(
            "platform keyring credential contains an unexpected line break".to_owned(),
        ));
    }
    String::from_utf8(bytes).map_err(|_| {
        AuthError::SecretStore("platform keyring credential is not valid UTF-8".to_owned())
    })
}

fn security_command_delete(service: &str, key: &str) -> Result<()> {
    with_noninteractive_keychain(|| {
        match security_framework::passwords::delete_generic_password(service, key) {
            Ok(()) => Ok(()),
            // Absence is the intended end state, so a missing item is success. The
            // subprocess adapter expressed the same tolerance as exit status 44.
            Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(()),
            Err(error) => Err(classify_keychain_error(error)),
        }
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    #[test]
    fn quiet_keychain_guard_failure_never_calls_credential_operation() {
        for query_fails in [true, false] {
            let lock = std::sync::Mutex::new(());
            let invoked = std::cell::Cell::new(false);
            let outcome = super::with_keychain_interaction(
                &lock,
                || {
                    super::quiet_keychain_guard(
                        || {
                            if query_fails {
                                Err(AuthError::SecretStore("query failed".to_owned()))
                            } else {
                                Ok(true)
                            }
                        },
                        || Err::<(), _>(AuthError::SecretStore("disable failed".to_owned())),
                    )
                },
                || {
                    invoked.set(true);
                    Ok(())
                },
            );
            assert!(outcome.is_err());
            assert!(!invoked.get());
            assert!(lock.try_lock().is_ok());
        }
    }

    #[test]
    fn quiet_keychain_preserves_an_already_disabled_process_flag() {
        let lock = std::sync::Mutex::new(());
        let disabled_calls = std::cell::Cell::new(0);
        let flag = std::cell::Cell::new(false);
        super::with_keychain_interaction(
            &lock,
            || {
                super::quiet_keychain_guard(
                    || Ok(flag.get()),
                    || {
                        disabled_calls.set(disabled_calls.get() + 1);
                        Ok(())
                    },
                )
            },
            || {
                assert!(!flag.get());
                Ok(())
            },
        )
        .expect("quiet operation");
        assert_eq!(disabled_calls.get(), 0);
        assert!(!flag.get());
    }

    struct QuietTestGuard<'a> {
        lock: &'a std::sync::Mutex<()>,
        allowed: &'a std::sync::atomic::AtomicBool,
    }
    impl Drop for QuietTestGuard<'_> {
        fn drop(&mut self) {
            assert!(self.lock.try_lock().is_err(), "restore must precede unlock");
            assert!(!self.allowed.swap(true, std::sync::atomic::Ordering::SeqCst));
        }
    }

    #[test]
    fn quiet_keychain_serializes_operations_through_guard_restoration() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let lock = std::sync::Mutex::new(());
        let allowed = AtomicBool::new(true);
        let count = AtomicUsize::new(0);
        let start = std::sync::Barrier::new(8);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    start.wait();
                    super::with_keychain_interaction(
                        &lock,
                        || {
                            super::quiet_keychain_guard(
                                || Ok(allowed.load(Ordering::SeqCst)),
                                || {
                                    assert!(allowed.swap(false, Ordering::SeqCst));
                                    Ok(QuietTestGuard {
                                        lock: &lock,
                                        allowed: &allowed,
                                    })
                                },
                            )
                        },
                        || {
                            assert!(!allowed.load(Ordering::SeqCst));
                            std::thread::yield_now();
                            assert!(!allowed.load(Ordering::SeqCst));
                            count.fetch_add(1, Ordering::SeqCst);
                            Ok(())
                        },
                    )
                    .expect("serialized quiet operation");
                });
            }
        });
        assert_eq!(count.load(Ordering::SeqCst), 8);
        assert!(allowed.load(Ordering::SeqCst));
    }

    #[test]
    fn an_interrupted_ownership_migration_still_answers_reads() {
        let primary = b"primary".to_vec();
        let journal = b"journal".to_vec();

        // The primary always wins while it exists, so a stale journal left by an
        // interruption after republication can never shadow the live value.
        assert_eq!(
            super::resolve_stored_value(Some(primary.clone()), Some(journal.clone())),
            Some(primary.clone())
        );
        assert_eq!(
            super::resolve_stored_value(Some(primary.clone()), None),
            Some(primary)
        );
        // The window that used to lose the value: deleted, not yet republished.
        assert_eq!(
            super::resolve_stored_value(None, Some(journal.clone())),
            Some(journal)
        );
        assert_eq!(super::resolve_stored_value(None, None), None);
    }

    #[test]
    fn the_migration_journal_cannot_collide_with_the_item_it_carries() {
        let key = "evidence-integrity/location/sha256:abc/registry-v1";
        let journal = super::ownership_migration_key(key);
        assert_ne!(journal, key);
        assert!(journal.starts_with(super::OWNERSHIP_MIGRATION_KEY_PREFIX));
        assert!(journal.ends_with(key));
        // Nesting must terminate, so a journal key never derives another journal.
        assert_ne!(super::ownership_migration_key(&journal), journal);
    }

    #[test]
    fn only_an_ownership_conflict_replaces_an_existing_item() {
        // An item owned by the superseded subprocess adapter is replaced, because
        // ownership cannot be reassigned by an update.
        assert!(super::is_ownership_conflict(
            super::ERR_SEC_INVALID_OWNER_EDIT
        ));
        // Nothing else may be. Absence, cancellation, failed authentication, and
        // disallowed interaction each have their own disposition, and destroying an
        // item on any of them would discard state the caller never asked to replace.
        for code in [
            super::ERR_SEC_ITEM_NOT_FOUND,
            super::ERR_SEC_USER_CANCELED,
            super::ERR_SEC_AUTH_FAILED,
            super::ERR_SEC_INTERACTION_NOT_ALLOWED,
            0,
            -1,
        ] {
            assert!(
                !super::is_ownership_conflict(code),
                "status {code} must not destroy an existing item"
            );
        }
    }

    use std::{
        fs,
        io::Write as _,
        path::Path,
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };

    use super::*;

    const LOCK_HELPER_ENV: &str = "CFCTL_TEST_KEYRING_LOCK_HELPER";
    const LOCK_HELPER_MODE_ENV: &str = "CFCTL_TEST_KEYRING_LOCK_MODE";
    const LOCK_ROOT_ENV: &str = "CFCTL_TEST_KEYRING_LOCK_ROOT";
    const LOCK_SERVICE_ENV: &str = "CFCTL_TEST_KEYRING_LOCK_SERVICE";
    const LOCK_KEY_ENV: &str = "CFCTL_TEST_KEYRING_LOCK_KEY";
    const READY_PATH_ENV: &str = "CFCTL_TEST_KEYRING_LOCK_READY";
    const RELEASE_PATH_ENV: &str = "CFCTL_TEST_KEYRING_LOCK_RELEASE";
    const GETCONF_HELPER_ENV: &str = "CFCTL_TEST_GETCONF_HELPER";
    const GETCONF_HELPER_MODE_ENV: &str = "CFCTL_TEST_GETCONF_HELPER_MODE";
    const GETCONF_HELPER_RECEIPT_ENV: &str = "CFCTL_TEST_GETCONF_HELPER_RECEIPT";
    const GETCONF_HELPER_EXIT_RECEIPT_ENV: &str = "CFCTL_TEST_GETCONF_HELPER_EXIT_RECEIPT";
    const GETCONF_HELPER_EXE_ENV: &str = "CFCTL_TEST_GETCONF_HELPER_EXE";

    /// Publishes a helper receipt so the path never exists while incomplete.
    ///
    /// `fs::write` creates and then fills the file, so a watcher polling for
    /// existence can observe the empty window between the two. Staging beside
    /// the receipt and renaming makes the path appear only once it is whole,
    /// which is what `wait_for_path` already assumes.
    fn publish_receipt(receipt: &Path, contents: &str) {
        let staging = receipt.with_extension("partial");
        fs::write(&staging, contents.as_bytes()).expect("stage helper receipt");
        fs::rename(&staging, receipt).expect("publish helper receipt");
    }

    fn wait_for_path(path: &Path, label: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !path.exists() {
            assert!(Instant::now() < deadline, "timed out waiting for {label}");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn getconf_helper_command(mode: &str, receipt: &Path) -> Command {
        let current_exe = std::env::current_exe().expect("current test executable");
        let helper_name = "macos_keyring::platform::tests::getconf_process_helper";
        let mut command = Command::new(current_exe);
        command
            .args(["--exact", helper_name, "--nocapture"])
            .env(GETCONF_HELPER_ENV, "1")
            .env(GETCONF_HELPER_MODE_ENV, mode)
            .env(GETCONF_HELPER_RECEIPT_ENV, receipt);
        command
    }

    fn process_is_alive(pid: u32) -> bool {
        Command::new("/bin/kill")
            .args(["-0", &pid.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }

    #[test]
    fn getconf_process_helper() {
        if std::env::var_os(GETCONF_HELPER_ENV).is_none() {
            return;
        }
        let mode = std::env::var(GETCONF_HELPER_MODE_ENV).expect("getconf helper mode");
        let receipt = PathBuf::from(
            std::env::var_os(GETCONF_HELPER_RECEIPT_ENV).expect("getconf helper receipt"),
        );
        if mode == "oversize" {
            let mut stdout = std::io::stdout().lock();
            let block = [b'x'; 1_024];
            for _ in 0..1_024 {
                if stdout.write_all(&block).is_err() {
                    return;
                }
            }
            drop(stdout);
            publish_receipt(&receipt, "all-output-consumed");
            return;
        }
        if mode == "fork-holder" {
            let exit_receipt = PathBuf::from(
                std::env::var_os(GETCONF_HELPER_EXIT_RECEIPT_ENV)
                    .expect("fork-holder exit receipt"),
            );
            let current_exe = std::env::current_exe().expect("current test executable");
            let launcher = Command::new("/bin/sh")
                .args([
                    "-c",
                    "\"$CFCTL_TEST_GETCONF_HELPER_EXE\" --exact \
                     macos_keyring::platform::tests::getconf_process_helper --nocapture &",
                ])
                .env(GETCONF_HELPER_EXE_ENV, current_exe)
                .env(GETCONF_HELPER_ENV, "1")
                .env(GETCONF_HELPER_MODE_ENV, "descendant")
                .env(GETCONF_HELPER_RECEIPT_ENV, &receipt)
                .stdin(Stdio::null())
                .status()
                .expect("launch inherited-stdout descendant");
            assert!(launcher.success(), "descendant launcher failed");
            publish_receipt(&exit_receipt, "exited");
            return;
        }
        assert!(mode == "hang" || mode == "descendant");
        publish_receipt(&receipt, &std::process::id().to_string());
        loop {
            thread::sleep(Duration::from_mins(1));
        }
    }

    #[test]
    fn getconf_stdout_is_cut_off_at_the_sentinel_bound() {
        let temp = tempfile::tempdir().expect("temporary getconf receipt");
        let receipt = temp.path().join("oversize-complete");
        let mut command = getconf_helper_command("oversize", &receipt);
        let result = mutation_lock_root_with_command(&mut command, Duration::from_secs(1));
        assert!(result.is_err());
        assert!(
            !receipt.exists(),
            "resolver consumed output beyond its MAX+1 sentinel"
        );
    }

    #[test]
    fn getconf_timeout_kills_and_reaps_a_nonterminating_child() {
        let temp = tempfile::tempdir().expect("temporary getconf receipt");
        let receipt = temp.path().join("helper-pid");
        let watchdog_receipt = receipt.clone();
        let watchdog = thread::spawn(move || {
            wait_for_path(&watchdog_receipt, "getconf helper pid");
            thread::sleep(Duration::from_millis(750));
            let pid = fs::read_to_string(&watchdog_receipt)
                .expect("read helper pid")
                .parse::<u32>()
                .expect("parse helper pid");
            if process_is_alive(pid) {
                let _ = Command::new("/bin/kill")
                    .args(["-KILL", &pid.to_string()])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
        });
        let mut command = getconf_helper_command("hang", &receipt);
        let started = Instant::now();
        let error = mutation_lock_root_with_command(&mut command, Duration::from_millis(200))
            .expect_err("nonterminating resolver must time out");
        let elapsed = started.elapsed();
        watchdog.join().expect("join getconf watchdog");
        let pid = fs::read_to_string(&receipt)
            .expect("read reaped helper pid")
            .parse::<u32>()
            .expect("parse reaped helper pid");
        assert!(error.to_string().contains("timed out"));
        assert!(elapsed < Duration::from_millis(500));
        assert!(!process_is_alive(pid), "timed-out helper was not reaped");
    }

    #[test]
    fn getconf_deadline_survives_an_inherited_stdout_descendant() {
        let temp = tempfile::tempdir().expect("temporary getconf receipt");
        let receipt = temp.path().join("descendant-pid");
        let exit_receipt = temp.path().join("fork-holder-exited");
        let watchdog_receipt = receipt.clone();
        let watchdog = thread::spawn(move || {
            wait_for_path(&watchdog_receipt, "getconf descendant pid");
            thread::sleep(Duration::from_millis(750));
            let pid = fs::read_to_string(&watchdog_receipt)
                .expect("read descendant pid")
                .parse::<u32>()
                .expect("parse descendant pid");
            if process_is_alive(pid) {
                let _ = Command::new("/bin/kill")
                    .args(["-KILL", &pid.to_string()])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
        });
        let mut command = getconf_helper_command("fork-holder", &receipt);
        command.env(GETCONF_HELPER_EXIT_RECEIPT_ENV, &exit_receipt);
        let started = Instant::now();
        let error = mutation_lock_root_with_command(&mut command, Duration::from_millis(200))
            .expect_err("inherited stdout must not outlive the resolver deadline");
        let elapsed = started.elapsed();
        watchdog.join().expect("join descendant watchdog");
        let pid = fs::read_to_string(&receipt)
            .expect("read terminated descendant pid")
            .parse::<u32>()
            .expect("parse terminated descendant pid");
        assert!(
            exit_receipt.exists(),
            "direct fork-holder child did not exit before the inherited stdout deadline"
        );
        assert!(error.to_string().contains("timed out"));
        assert!(elapsed < Duration::from_millis(500));
        assert!(
            !process_is_alive(pid),
            "inherited-stdout descendant survived timeout cleanup"
        );
    }

    #[test]
    fn cross_process_lock_helper() {
        if std::env::var_os(LOCK_HELPER_ENV).is_none() {
            return;
        }
        let mode = std::env::var(LOCK_HELPER_MODE_ENV).unwrap_or_else(|_| "explicit".to_owned());
        let ready = PathBuf::from(std::env::var_os(READY_PATH_ENV).expect("ready path"));
        let release = PathBuf::from(std::env::var_os(RELEASE_PATH_ENV).expect("release path"));
        let service = std::env::var(LOCK_SERVICE_ENV).unwrap_or_else(|_| "service".to_owned());
        let key = std::env::var(LOCK_KEY_ENV).unwrap_or_else(|_| "credential".to_owned());
        if mode == "holder" || mode == "explicit-guard-holder" {
            let guard = if mode == "holder" {
                acquire_mutation_lock(&service, &key).expect("acquire production lock")
            } else {
                let root = PathBuf::from(std::env::var_os(LOCK_ROOT_ENV).expect("lock root"));
                acquire_mutation_lock_at_with_hooks(&root, &service, &key, |_| Ok(()), |_| Ok(()))
                    .expect("acquire explicit production lock")
            };
            fs::write(&ready, b"ready").expect("publish ready signal");
            wait_for_path(&release, "release signal");
            drop(guard);
            return;
        }
        let root = if mode == "explicit" {
            PathBuf::from(std::env::var_os(LOCK_ROOT_ENV).expect("lock root"))
        } else {
            mutation_lock_root().expect("production lock root")
        };
        if mode == "contender" {
            let parent = Dir::open_ambient_dir(
                root.parent().expect("production lock parent"),
                ambient_authority(),
            )
            .expect("open production authority");
            let authority = parent.into_std_file();
            assert!(matches!(
                authority.try_lock(),
                Err(fs::TryLockError::WouldBlock)
            ));
            return;
        }
        let file = open_mutation_lock_file(&root, &service, &key).expect("open lock");
        file.lock().expect("acquire child lock");
        fs::write(&ready, b"ready").expect("publish ready signal");
        wait_for_path(&release, "release signal");
    }

    #[test]
    fn mutation_lock_serializes_independent_processes() {
        let temp = tempfile::tempdir().expect("temporary lock root");
        let root = temp.path().join("locks");
        let ready = temp.path().join("ready");
        let release = temp.path().join("release");
        let current_exe = std::env::current_exe().expect("current test executable");
        let helper_name = "macos_keyring::platform::tests::cross_process_lock_helper";
        let mut child = Command::new(current_exe)
            .args(["--exact", helper_name, "--nocapture"])
            .env(LOCK_HELPER_ENV, "1")
            .env(LOCK_ROOT_ENV, &root)
            .env(READY_PATH_ENV, &ready)
            .env(RELEASE_PATH_ENV, &release)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn independent lock holder");

        wait_for_path(&ready, "child lock acquisition");
        let contender =
            open_mutation_lock_file(&root, "service", "credential").expect("open contender lock");
        assert!(matches!(
            contender.try_lock(),
            Err(fs::TryLockError::WouldBlock)
        ));

        fs::write(&release, b"release").expect("publish release signal");
        assert!(child.wait().expect("wait for lock holder").success());
        contender.lock().expect("acquire released lock");
    }

    #[test]
    fn production_lock_serializes_across_distinct_home_and_cfctl_home() {
        let temp = tempfile::tempdir().expect("temporary signals");
        let ready = temp.path().join("ready");
        let release = temp.path().join("release");
        let first_home = temp.path().join("first-home");
        let second_home = temp.path().join("second-home");
        fs::create_dir_all(&first_home).expect("first home");
        fs::create_dir_all(&second_home).expect("second home");
        let current_exe = std::env::current_exe().expect("current test executable");
        let helper_name = "macos_keyring::platform::tests::cross_process_lock_helper";
        let service = format!("io.cfctl.test.{}", std::process::id());
        let key = "environment-independent-lock";
        let mut holder = Command::new(&current_exe)
            .args(["--exact", helper_name, "--nocapture"])
            .env(LOCK_HELPER_ENV, "1")
            .env(LOCK_HELPER_MODE_ENV, "holder")
            .env(LOCK_SERVICE_ENV, &service)
            .env(LOCK_KEY_ENV, key)
            .env("HOME", &first_home)
            .env("CFCTL_HOME", first_home.join("cfctl"))
            .env(READY_PATH_ENV, &ready)
            .env(RELEASE_PATH_ENV, &release)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn production lock holder");

        wait_for_path(&ready, "production lock holder");
        let contender = Command::new(current_exe)
            .args(["--exact", helper_name, "--nocapture"])
            .env(LOCK_HELPER_ENV, "1")
            .env(LOCK_HELPER_MODE_ENV, "contender")
            .env(LOCK_SERVICE_ENV, &service)
            .env(LOCK_KEY_ENV, key)
            .env("HOME", &second_home)
            .env("CFCTL_HOME", second_home.join("cfctl"))
            .env(READY_PATH_ENV, &ready)
            .env(RELEASE_PATH_ENV, &release)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("run production lock contender");
        fs::write(&release, b"release").expect("release production lock holder");
        assert!(
            holder
                .wait()
                .expect("wait for production lock holder")
                .success()
        );
        assert!(contender.success());
    }

    #[test]
    fn root_symlink_is_rejected_before_permission_side_effect() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let temp = tempfile::tempdir().expect("temporary root");
        let target = temp.path().join("target");
        let root = temp.path().join("locks");
        fs::create_dir(&target).expect("target directory");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).expect("target mode");
        symlink(&target, &root).expect("root symlink");

        assert!(open_mutation_lock_file(&root, "service", "credential").is_err());
        assert_eq!(
            fs::metadata(&target)
                .expect("target metadata")
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        assert!(
            fs::read_dir(&target)
                .expect("target entries")
                .next()
                .is_none()
        );
    }

    #[test]
    fn lock_file_symlink_and_hard_link_are_rejected_without_target_side_effects() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let temp = tempfile::tempdir().expect("temporary root");
        let root = temp.path().join("locks");
        fs::create_dir(&root).expect("lock root");
        let target = temp.path().join("target");
        fs::write(&target, b"unchanged").expect("target contents");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).expect("target mode");
        let lock_path = mutation_lock_path(&root, "service", "credential");
        symlink(&target, &lock_path).expect("lock symlink");
        assert!(open_mutation_lock_file(&root, "service", "credential").is_err());
        assert_eq!(fs::read(&target).expect("target read"), b"unchanged");
        assert_eq!(
            fs::metadata(&target)
                .expect("target metadata")
                .permissions()
                .mode()
                & 0o777,
            0o644
        );

        fs::remove_file(&lock_path).expect("remove test symlink");
        fs::hard_link(&target, &lock_path).expect("hard-linked lock");
        assert!(open_mutation_lock_file(&root, "service", "credential").is_err());
        assert_eq!(fs::read(&target).expect("target reread"), b"unchanged");
        assert_eq!(
            fs::metadata(&target)
                .expect("target metadata")
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
    }

    #[test]
    fn lock_path_replacement_is_rejected_before_permission_or_lock_side_effect() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().expect("temporary root");
        let root = temp.path().join("locks");
        fs::create_dir(&root).expect("lock root");
        let lock_path = mutation_lock_path(&root, "service", "credential");
        fs::write(&lock_path, b"opened").expect("seed lock");
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o644)).expect("seed mode");
        let displaced = root.join("displaced.lock");
        let error =
            open_mutation_lock_file_with_hook(&root, "service", "credential", |opened_path| {
                fs::rename(opened_path, &displaced)
                    .map_err(|error| AuthError::SecretStore(error.to_string()))?;
                fs::write(opened_path, b"replacement")
                    .map_err(|error| AuthError::SecretStore(error.to_string()))?;
                Ok(())
            });
        assert!(error.is_err());
        for path in [&displaced, &lock_path] {
            assert_eq!(
                fs::metadata(path)
                    .expect("lock metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o644
            );
        }
        let displaced_file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&displaced)
            .expect("open displaced lock");
        displaced_file
            .lock()
            .expect("displaced file was not locked");
    }

    #[test]
    fn post_lock_path_replacement_is_rejected_before_mutation_authority_returns() {
        let temp = tempfile::tempdir().expect("temporary root");
        let root = temp.path().join("locks");
        let displaced = root.join("displaced.lock");
        let result = acquire_mutation_lock_at_with_hooks(
            &root,
            "service",
            "credential-post-lock",
            |_| Ok(()),
            |locked_path| {
                fs::rename(locked_path, &displaced)
                    .map_err(|error| AuthError::SecretStore(error.to_string()))?;
                fs::write(locked_path, b"replacement")
                    .map_err(|error| AuthError::SecretStore(error.to_string()))?;
                Ok(())
            },
        );
        assert!(result.is_err());
        let replacement = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(mutation_lock_path(&root, "service", "credential-post-lock"))
            .expect("open replacement");
        replacement
            .lock()
            .expect("replacement did not inherit displaced lock authority");
    }

    #[test]
    fn retained_os_authority_serializes_after_root_replacement() {
        let temp = tempfile::tempdir().expect("temporary authority");
        let root = temp.path().join("locks");
        let displaced = temp.path().join("displaced-locks");
        let ready = temp.path().join("ready");
        let release = temp.path().join("release");
        let service = "service";
        let key = "credential-root-replacement";
        let first =
            acquire_mutation_lock_at_with_hooks(&root, service, key, |_| Ok(()), |_| Ok(()))
                .expect("acquire first mutation authority");
        fs::rename(&root, &displaced).expect("displace locked root");
        fs::create_dir(&root).expect("create replacement root");

        let current_exe = std::env::current_exe().expect("current test executable");
        let helper_name = "macos_keyring::platform::tests::cross_process_lock_helper";
        let mut contender = Command::new(current_exe)
            .args(["--exact", helper_name, "--nocapture"])
            .env(LOCK_HELPER_ENV, "1")
            .env(LOCK_HELPER_MODE_ENV, "explicit-guard-holder")
            .env(LOCK_ROOT_ENV, &root)
            .env(LOCK_SERVICE_ENV, service)
            .env(LOCK_KEY_ENV, key)
            .env(READY_PATH_ENV, &ready)
            .env(RELEASE_PATH_ENV, &release)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn replacement-root contender");

        thread::sleep(Duration::from_millis(200));
        assert!(
            !ready.exists(),
            "replacement root admitted overlapping mutation authority"
        );
        drop(first);
        wait_for_path(&ready, "replacement-root contender");
        fs::write(&release, b"release").expect("release replacement-root contender");
        assert!(contender.wait().expect("wait for contender").success());
    }

    #[test]
    fn security_stdout_accepts_exact_maximum_with_crlf_frame() {
        let mut output = vec![b'x'; MAX_LOGICAL_CREDENTIAL_BYTES];
        output.extend_from_slice(b"\r\n");
        assert_eq!(
            decode_security_stdout(output).expect("CRLF frame").len(),
            MAX_LOGICAL_CREDENTIAL_BYTES
        );
    }

    #[test]
    fn security_stdout_rejects_logical_maximum_plus_one() {
        let mut output = vec![b'x'; MAX_LOGICAL_CREDENTIAL_BYTES + 1];
        output.push(b'\n');
        assert!(decode_security_stdout(output).is_err());
    }

    #[test]
    fn security_stdout_rejects_missing_or_repeated_frame() {
        assert!(decode_security_stdout(b"credential".to_vec()).is_err());
        assert!(decode_security_stdout(b"credential\r".to_vec()).is_err());
        assert!(decode_security_stdout(b"credential\n\n".to_vec()).is_err());
        assert!(decode_security_stdout(b"credential\r\n\r\n".to_vec()).is_err());
    }
}
