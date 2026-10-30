//! Executes only the declared Bun binary and three committed source files.
//! Input, output and diagnostics stay in one private, bounded staging directory.

use super::super::prelude::{CliError, Result, StateStore};
use cfctl_core::WorkspaceD1ReplyContainmentContractV3;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write as _,
    os::unix::{fs::OpenOptionsExt as _, process::CommandExt as _},
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const LIMIT: u64 = 1024 * 1024;
const FILES: [&str; 3] = [
    "scripts/compile-reply-containment.ts",
    "scripts/operation-context.ts",
    "scripts/git-candidate.ts",
];

pub(super) struct BoundCompiler {
    directory: tempfile::TempDir,
    identity: Value,
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(pid) = rustix::process::Pid::from_raw(self.0.id().cast_signed()) {
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
        }
        let _ = self.0.wait();
    }
}

fn rejected() -> CliError {
    CliError::Input("containment compiler identity, isolation, or bounded execution failed".into())
}
fn hash(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
fn file(path: &Path, bytes: &[u8], mode: u32) -> Result<fs::File> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| rejected())?;
    file.write_all(bytes).map_err(|_| rejected())?;
    file.sync_all().map_err(|_| rejected())?;
    Ok(file)
}

impl BoundCompiler {
    pub(super) fn new(
        store: &StateStore,
        contract: &WorkspaceD1ReplyContainmentContractV3,
    ) -> Result<Self> {
        if contract.compiler_runtime != "bun" || contract.compiler_path != FILES[0] {
            return Err(rejected());
        }
        let runtime =
            super::super::support::direct_runtime_executable("bun").ok_or_else(rejected)?;
        let bytes = fs::read(&runtime).map_err(|_| rejected())?;
        if hash(&bytes) != contract.compiler_runtime_sha256 {
            return Err(rejected());
        }
        let directory = tempfile::Builder::new()
            .prefix("reply-containment-compiler-")
            .tempdir_in(&store.paths().cache_dir)
            .map_err(|_| rejected())?;
        file(&directory.path().join("bun"), &bytes, 0o700)?;
        let root = Path::new(&contract.repository_root);
        let mut source_hashes = serde_json::Map::new();
        for source in FILES {
            let spec = format!("{}:{source}", contract.repository_head);
            let source_bytes =
                super::super::import_planning::git_authority_bytes(root, &["show", &spec])?;
            if source_bytes.is_empty() || source_bytes.len() as u64 > LIMIT {
                return Err(rejected());
            }
            let digest = hash(&source_bytes);
            if source == FILES[0] && digest != contract.compiler_sha256 {
                return Err(rejected());
            }
            let name = Path::new(source).file_name().ok_or_else(rejected)?;
            file(&directory.path().join(name), &source_bytes, 0o600)?;
            source_hashes.insert(source.into(), json!(digest));
        }
        let mut compiler = Self {
            directory,
            identity: Value::Null,
        };
        let output = compiler.execute(&["--version"], None)?;
        let version = std::str::from_utf8(&output).map_err(|_| rejected())?.trim();
        if output.len() > 64 || version != contract.compiler_runtime_version {
            return Err(rejected());
        }
        compiler.identity = json!({"runtime_path_sha256":hash(runtime.as_os_str().as_encoded_bytes()),
            "runtime_sha256":contract.compiler_runtime_sha256,"runtime_version":version,"committed_sources":source_hashes});
        Ok(compiler)
    }

    pub(super) fn identity(&self) -> &Value {
        &self.identity
    }

    pub(super) fn compile(&self, input: &Value, pre_read: bool) -> Result<Value> {
        let mut args = vec!["compile-reply-containment.ts"];
        if pre_read {
            args.push("--pre-read-request");
        }
        let bytes = serde_json::to_vec(input)?;
        if bytes.is_empty() || bytes.len() as u64 > LIMIT {
            return Err(rejected());
        }
        serde_json::from_slice(&self.execute(&args, Some(&bytes))?).map_err(|_| rejected())
    }

    fn execute(&self, args: &[&str], input: Option<&[u8]>) -> Result<Vec<u8>> {
        // Each invocation has its own files; no retry reuses a partial result.
        let invocation = tempfile::Builder::new()
            .prefix("call-")
            .tempdir_in(self.directory.path())
            .map_err(|_| rejected())?;
        let input_path = invocation.path().join("stdin");
        file(&input_path, input.unwrap_or_default(), 0o600)?;
        let stdout_path = invocation.path().join("stdout");
        let stderr_path = invocation.path().join("stderr");
        let stdout = file(&stdout_path, &[], 0o600)?;
        let stderr = file(&stderr_path, &[], 0o600)?;
        let child = Command::new(self.directory.path().join("bun"))
            .args(args)
            .current_dir(self.directory.path())
            .env_clear()
            .env("TZ", "UTC")
            .env("NO_COLOR", "1")
            .process_group(0)
            .stdin(Stdio::from(
                fs::File::open(input_path).map_err(|_| rejected())?,
            ))
            .stdout(stdout)
            .stderr(stderr)
            .spawn()
            .map_err(|_| rejected())?;
        let mut child = ChildGuard(child);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if [stdout_path.as_path(), stderr_path.as_path()]
                .iter()
                .any(|path| fs::metadata(path).map_or(true, |meta| meta.len() > LIMIT))
            {
                return Err(rejected());
            }
            match child.0.try_wait().map_err(|_| rejected())? {
                Some(status) if status.success() => break,
                None if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                Some(_) | None => return Err(rejected()),
            }
        }
        let bytes = fs::read(stdout_path).map_err(|_| rejected())?;
        if bytes.len() as u64 > LIMIT {
            return Err(rejected());
        }
        Ok(bytes)
    }
}
