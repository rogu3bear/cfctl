use cfctl_auth::{FileSecretStore, ProfileKind, ProfileMetadata, SecretStore};
use cfctl_storage::{RuntimePaths, StateStore};
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

// A failing contention assertion must not strand a process waiting for input.
struct Imports(Vec<Child>);

impl Drop for Imports {
    fn drop(&mut self) {
        for child in &mut self.0 {
            let _killed = child.kill();
            let _waited = child.wait();
        }
    }
}

fn import(runtime: &Path, input: Stdio) -> Child {
    Command::new(env!("CARGO_BIN_EXE_cfctl"))
        .env("CFCTL_HOME", runtime)
        .args([
            "auth",
            "import-api-token",
            "--profile",
            "new-user",
            "--account",
            "account-a",
            "--stdin",
            "--create-only",
            "--no-select",
            "--json",
        ])
        .stdin(input)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start actual CLI intake")
}

fn output(child: &mut Child, phase: &str) -> (ExitStatus, String) {
    let deadline = Instant::now() + Duration::from_secs(10);
    let timed_out = loop {
        if child.try_wait().expect("poll CLI exit").is_some() {
            break false;
        }
        if Instant::now() >= deadline {
            child.kill().expect("stop timed-out fixture child");
            break true;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let status = child.wait().expect("CLI exit");
    let mut text = String::new();
    child
        .stdout
        .take()
        .expect("stdout")
        .read_to_string(&mut text)
        .expect("read stdout");
    child
        .stderr
        .take()
        .expect("stderr")
        .read_to_string(&mut text)
        .expect("read stderr");
    assert!(!timed_out, "{phase} did not terminate: {text}");
    (status, text)
}

fn exclusive_runtime_is_held(runtime: &Path) -> bool {
    match cfctl_storage::lock_runtime_selection(&RuntimePaths::from_root(runtime), false) {
        Ok(shared) => {
            drop(shared);
            false
        }
        Err(error) => {
            assert!(
                error
                    .to_string()
                    .contains("another cfctl invocation is using this runtime"),
                "unexpected lock observation failure: {error}"
            );
            true
        }
    }
}

#[test]
fn exclusive_lock_observation_rejects_shared_and_unlocked_states() {
    let root = tempfile::tempdir().expect("isolated lock observation");
    let paths = RuntimePaths::from_root(root.path());
    let shared = cfctl_storage::lock_runtime_selection(&paths, false).expect("shared lock");
    assert!(!exclusive_runtime_is_held(root.path()));
    drop(shared);
    assert!(!exclusive_runtime_is_held(root.path()));
    let exclusive = cfctl_storage::lock_runtime_selection(&paths, true).expect("exclusive lock");
    assert!(exclusive_runtime_is_held(root.path()));
    drop(exclusive);
    assert!(!exclusive_runtime_is_held(root.path()));
}

#[test]
fn input_observation_requires_real_pipe_consumption() {
    let (mut reader, mut writer) = std::io::pipe().expect("controlled input pipe");
    writer.write_all(b"prefix").expect("queue input");
    assert_eq!(
        rustix::io::ioctl_fionread(&reader).expect("queued bytes"),
        6
    );
    reader.read_exact(&mut [0; 6]).expect("consume input");
    assert_eq!(
        rustix::io::ioctl_fionread(&reader).expect("consumed bytes"),
        0
    );
}

fn start_exclusive_import(runtime: &Path) -> (Imports, std::io::PipeWriter) {
    let (reader, mut winner_input) = std::io::pipe().expect("winner input pipe");
    let input_observer = reader
        .try_clone()
        .expect("observe the read side without consuming");
    let mut imports = Imports(vec![import(runtime, Stdio::from(reader))]);
    winner_input
        .write_all(b"synthetic-")
        .expect("queue winner prefix");
    let deadline = Instant::now() + Duration::from_secs(10);
    // A drained prefix establishes that the first process actually reached
    // input, while withholding EOF prevents credential publication. Only then
    // probe the lock, so the observer cannot itself reject an import at entry.
    while rustix::io::ioctl_fionread(&input_observer).expect("winner queued input") != 0 {
        if imports.0[0]
            .try_wait()
            .expect("poll winner startup")
            .is_some()
        {
            let (_, text) = output(&mut imports.0[0], "winner startup");
            panic!("winner exited before consuming input: {text}");
        }
        assert!(
            Instant::now() < deadline,
            "winner did not reach input within its startup deadline"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        exclusive_runtime_is_held(runtime),
        "import reached input without holding the exclusive runtime lock"
    );
    (imports, winner_input)
}

#[test]
fn concurrent_create_only_imports_serialize_before_input_and_never_replace_the_winner() {
    let root = tempfile::tempdir().expect("isolated runtime");
    super::seed_test_fallback_secret(root.path());
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("fixture store");
    drop(
        cfctl_storage::lock_runtime_selection(&RuntimePaths::from_root(root.path()), false)
            .expect("initialize the existing runtime lock"),
    );
    let existing = ProfileMetadata::new("existing", ProfileKind::ApiToken, Some("account-a"));
    let initial = json!({"schema_version":1,"current_profile":"existing","profiles":{"existing":existing},"pending_logins":{}});
    store
        .write_json(&store.paths().profiles_file(), &initial)
        .expect("initial profile metadata");
    let secrets = FileSecretStore::new(root.path().join("data/auth/secrets"));
    secrets
        .store_api_token("existing", "synthetic-existing")
        .expect("existing credential");

    let (mut imports, mut winner_input) = start_exclusive_import(root.path());
    // These processes overlap at the protected input boundary. The old shared
    // import cannot satisfy the observed-exclusive-lock assertion above.
    imports.0.push(import(root.path(), Stdio::piped()));
    let (status, rejection) = output(&mut imports.0[1], "contending import");
    assert!(!status.success());
    assert!(
        rejection.contains("another cfctl invocation is using this runtime"),
        "{rejection}"
    );
    let persisted: Value = store
        .read_json(&store.paths().profiles_file())
        .expect("unchanged profiles");
    assert_eq!(persisted, initial);

    let selection = Command::new(env!("CARGO_BIN_EXE_cfctl"))
        .env("CFCTL_HOME", root.path())
        .args(["auth", "use", "existing", "--json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("concurrent ordinary profile writer");
    imports.0.push(selection);
    let (selection_status, selection_output) = output(&mut imports.0[2], "profile selection");
    assert!(!selection_status.success());
    assert!(
        selection_output.contains("another cfctl invocation is using this runtime"),
        "{selection_output}"
    );

    winner_input
        .write_all(b"winner-token\n")
        .expect("complete winner intake");
    drop(winner_input);
    let (status, success) = output(&mut imports.0[0], "winner completion");
    assert!(status.success(), "{success}");
    let persisted: Value = store
        .read_json(&store.paths().profiles_file())
        .expect("stored winner");
    assert_eq!(persisted["current_profile"], "existing");
    assert_eq!(
        persisted["profiles"]["existing"],
        initial["profiles"]["existing"]
    );
    assert!(persisted["profiles"]["new-user"]["credential_generation_id"].is_string());

    let retry = Command::new(env!("CARGO_BIN_EXE_cfctl"))
        .env("CFCTL_HOME", root.path())
        .args([
            "auth",
            "import-api-token",
            "--profile",
            "new-user",
            "--account",
            "account-a",
            "--value-in",
        ])
        .arg(root.path().join("must-not-be-opened"))
        .args(["--create-only", "--no-select", "--json"])
        .output()
        .expect("retry rejected intake");
    assert!(!retry.status.success());
    assert!(
        String::from_utf8_lossy(&retry.stderr).contains("--create-only profile already exists")
    );
    let after_retry: Value = store
        .read_json(&store.paths().profiles_file())
        .expect("winner survives retry");
    assert_eq!(after_retry, persisted);
}
