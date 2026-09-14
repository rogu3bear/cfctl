//! Bounded child lifetime and Git-object reads for the fixed local recipe.
use super::{CliError, Result};
use std::{
    fs,
    io::Read,
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

pub(super) fn rejected() -> CliError {
    CliError::Input("Pages immutable reproduction failed its closed source/tool/output contract; no receipt or provider authority was issued".into())
}

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Some(pid) = rustix::process::Pid::from_raw(self.0.id().cast_signed()) {
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
        }
        let _ = self.0.wait();
    }
}

pub(super) fn output(command: &mut Command, max: u64) -> Result<Vec<u8>> {
    let scratch = tempfile::tempdir().map_err(|_| rejected())?;
    let path = scratch.path().join("stdout");
    let file = fs::File::create(&path).map_err(|_| rejected())?;
    let child = command
        .stdin(Stdio::null())
        .stdout(file)
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(|_| rejected())?;
    let mut child = OwnedChild(child);
    let deadline = Instant::now() + Duration::from_mins(1);
    loop {
        if fs::metadata(&path).map_err(|_| rejected())?.len() > max || Instant::now() >= deadline {
            return Err(rejected());
        }
        if let Some(status) = child.0.try_wait().map_err(|_| rejected())? {
            if !status.success() {
                return Err(rejected());
            }
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|_| rejected())?
        .take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| rejected())?;
    if bytes.len() as u64 > max {
        return Err(rejected());
    }
    Ok(bytes)
}

pub(super) fn command(program: &Path, cwd: &Path) -> Command {
    let mut cmd = Command::new(program);
    cmd.current_dir(cwd)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("TZ", "UTC");
    cmd
}

pub(super) fn git(repo: &Path, args: &[&str], max: u64) -> Result<Vec<u8>> {
    output(
        command(git_program()?, repo)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env("GIT_NO_LAZY_FETCH", "1")
            .env("GIT_ALLOW_PROTOCOL", "")
            .arg("--no-replace-objects")
            .args(args),
        max,
    )
}

pub(super) fn git_program() -> Result<&'static Path> {
    static PROGRAM: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    PROGRAM
        .get_or_init(|| {
            if cfg!(target_os = "macos") {
                let bytes = output(
                    command(Path::new("/usr/bin/xcrun"), Path::new("/")).args(["--find", "git"]),
                    4096,
                )
                .ok()?;
                let text = std::str::from_utf8(&bytes).ok()?.trim();
                let path = PathBuf::from(text);
                if !path.is_absolute() {
                    return None;
                }
                fs::canonicalize(path).ok()
            } else {
                Some(PathBuf::from("/usr/bin/git"))
            }
        })
        .as_deref()
        .ok_or_else(rejected)
}

pub(super) fn helper_tools() -> Result<serde_json::Value> {
    use sha2::{Digest, Sha256};
    let paths = [git_program()?, Path::new("/usr/bin/tar")];
    let mut tools = serde_json::Map::new();
    for path in paths {
        tools.insert(
            path.display().to_string(),
            serde_json::json!(hex::encode(Sha256::digest(
                fs::read(path).map_err(|_| rejected())?
            ))),
        );
    }
    Ok(serde_json::Value::Object(tools))
}
