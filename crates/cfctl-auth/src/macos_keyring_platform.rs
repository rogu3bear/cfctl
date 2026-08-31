use std::{
    fs,
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
};

use directories::ProjectDirs;
use sha2::{Digest as _, Sha256};

use super::{MAX_LOGICAL_CREDENTIAL_BYTES, MacosKeychainAdapter, MutationGuard};
use crate::{AuthError, Result};

pub(super) struct SecurityCommandAdapter;

struct KeyringMutationLock {
    _file: fs::File,
}

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
    let project = ProjectDirs::from("io", "cfctl", "cfctl").ok_or_else(|| {
        AuthError::SecretStore("platform keyring lock directory is unavailable".to_owned())
    })?;
    Ok(project.data_dir().join("locks").join("keyring-mutations"))
}

fn mutation_lock_path(root: &Path, service: &str, key: &str) -> PathBuf {
    let digest = hex::encode(Sha256::digest(
        format!("keyring-mutation-v1\0{service}\0{key}").as_bytes(),
    ));
    root.join(format!("{digest}.lock"))
}

fn open_mutation_lock_file(root: &Path, service: &str, key: &str) -> Result<fs::File> {
    fs::create_dir_all(root).map_err(|error| AuthError::SecretStore(error.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))
            .map_err(|error| AuthError::SecretStore(error.to_string()))?;
    }
    let metadata =
        fs::symlink_metadata(root).map_err(|error| AuthError::SecretStore(error.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AuthError::SecretStore(
            "platform keyring mutation lock root must be a real directory".to_owned(),
        ));
    }
    let path = mutation_lock_path(root, service, key);
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let file = options
        .open(&path)
        .map_err(|error| AuthError::SecretStore(error.to_string()))?;
    let metadata = file
        .metadata()
        .map_err(|error| AuthError::SecretStore(error.to_string()))?;
    if !metadata.file_type().is_file() {
        return Err(AuthError::SecretStore(
            "platform keyring mutation lock must be a regular file".to_owned(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|error| AuthError::SecretStore(error.to_string()))?;
    }
    Ok(file)
}

fn acquire_mutation_lock(service: &str, key: &str) -> Result<KeyringMutationLock> {
    let file = open_mutation_lock_file(&mutation_lock_root()?, service, key)?;
    file.lock()
        .map_err(|error| AuthError::SecretStore(error.to_string()))?;
    Ok(KeyringMutationLock { _file: file })
}

pub(super) fn security_write_arguments(service: &str, key: &str) -> Vec<String> {
    [
        "add-generic-password",
        "-U",
        "-a",
        key,
        "-s",
        service,
        "-T",
        "/usr/bin/security",
        "-w",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn security_command_put(service: &str, key: &str, value: &str) -> Result<()> {
    if value.contains(['\n', '\r']) {
        return Err(AuthError::SecretStore(
            "macOS Keychain credentials cannot contain line breaks".to_owned(),
        ));
    }
    let mut child = std::process::Command::new("/usr/bin/security")
        .args(security_write_arguments(service, key))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|error| AuthError::SecretStore(error.to_string()))?;
    {
        let stdin = child.stdin.as_mut().ok_or_else(|| {
            AuthError::SecretStore(
                "platform keyring credential write produced no input sink".to_owned(),
            )
        })?;
        stdin
            .write_all(value.as_bytes())
            .and_then(|()| stdin.write_all(b"\n"))
            .and_then(|()| stdin.write_all(value.as_bytes()))
            .and_then(|()| stdin.write_all(b"\n"))
            .map_err(|error| AuthError::SecretStore(error.to_string()))?;
    }
    drop(child.stdin.take());
    let status = wait_for_child(&mut child)?;
    if status.success() {
        Ok(())
    } else {
        Err(AuthError::SecretStore(format!(
            "platform keyring credential write failed with exit status {status}"
        )))
    }
}

fn security_command_get(service: &str, key: &str) -> Result<Option<String>> {
    let mut child = std::process::Command::new("/usr/bin/security")
        .args(["find-generic-password", "-s", service, "-a", key, "-w"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|error| AuthError::SecretStore(error.to_string()))?;
    let stdout = child.stdout.take().ok_or_else(|| {
        AuthError::SecretStore("platform keyring credential read produced no sink".to_owned())
    })?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take((MAX_SECURITY_STDOUT_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let status_result = wait_for_child(&mut child);
    let bytes = reader
        .join()
        .map_err(|_| AuthError::SecretStore("platform keyring output reader failed".to_owned()))?
        .map_err(|error| AuthError::SecretStore(error.to_string()))?;
    let status = status_result?;
    if status.code() == Some(44) {
        return Ok(None);
    }
    if !status.success() {
        return Err(AuthError::SecretStore(format!(
            "platform keyring credential read failed with exit status {status}"
        )));
    }
    decode_security_stdout(bytes).map(Some)
}

const MAX_SECURITY_FRAME_BYTES: usize = 2;
const MAX_SECURITY_STDOUT_BYTES: usize = MAX_LOGICAL_CREDENTIAL_BYTES + MAX_SECURITY_FRAME_BYTES;

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
    let mut child = std::process::Command::new("/usr/bin/security")
        .args(["delete-generic-password", "-s", service, "-a", key])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|error| AuthError::SecretStore(error.to_string()))?;
    let status = wait_for_child(&mut child)?;
    if status.success() || status.code() == Some(44) {
        Ok(())
    } else {
        Err(AuthError::SecretStore(format!(
            "platform keyring credential deletion failed with exit status {status}"
        )))
    }
}

fn wait_for_child(child: &mut std::process::Child) -> Result<std::process::ExitStatus> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match child
            .try_wait()
            .map_err(|error| AuthError::SecretStore(error.to_string()))?
        {
            Some(status) => return Ok(status),
            None if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(AuthError::SecretStore(
                    "platform keyring operation timed out after 5 seconds; unlock the login keychain and retry"
                        .to_owned(),
                ));
            }
            None => std::thread::sleep(std::time::Duration::from_millis(25)),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::{
        fs,
        path::Path,
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };

    use super::*;

    const LOCK_HELPER_ENV: &str = "CFCTL_TEST_KEYRING_LOCK_HELPER";
    const LOCK_ROOT_ENV: &str = "CFCTL_TEST_KEYRING_LOCK_ROOT";
    const READY_PATH_ENV: &str = "CFCTL_TEST_KEYRING_LOCK_READY";
    const RELEASE_PATH_ENV: &str = "CFCTL_TEST_KEYRING_LOCK_RELEASE";

    fn wait_for_path(path: &Path, label: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !path.exists() {
            assert!(Instant::now() < deadline, "timed out waiting for {label}");
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn cross_process_lock_helper() {
        if std::env::var_os(LOCK_HELPER_ENV).is_none() {
            return;
        }
        let root = PathBuf::from(std::env::var_os(LOCK_ROOT_ENV).expect("lock root"));
        let ready = PathBuf::from(std::env::var_os(READY_PATH_ENV).expect("ready path"));
        let release = PathBuf::from(std::env::var_os(RELEASE_PATH_ENV).expect("release path"));
        let file = open_mutation_lock_file(&root, "service", "credential").expect("open lock");
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
