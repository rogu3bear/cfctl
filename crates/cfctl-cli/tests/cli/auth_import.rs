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

fn import(runtime: &Path) -> Child {
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
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start actual CLI intake")
}

fn output(child: &mut Child) -> (ExitStatus, String) {
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
    (status, text)
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

    let mut imports = Imports(vec![import(root.path()), import(root.path())]);
    let deadline = Instant::now() + Duration::from_secs(10);
    // Both inputs are held open. With the old shared locks, both commands wait
    // here and the test fails. An exclusive import admits exactly one; the other
    // fails busy before reading a secret or taking a stale profile snapshot.
    let rejected = loop {
        if let Some(index) = imports
            .0
            .iter_mut()
            .position(|child| child.try_wait().expect("poll import").is_some())
        {
            break index;
        }
        assert!(
            Instant::now() < deadline,
            "concurrent imports both reached input; profile transaction is not exclusive"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    let (status, rejection) = output(&mut imports.0[rejected]);
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
        .output()
        .expect("concurrent ordinary profile writer");
    assert!(!selection.status.success());
    assert!(
        String::from_utf8_lossy(&selection.stderr)
            .contains("another cfctl invocation is using this runtime")
    );

    let winner = 1 - rejected;
    imports.0[winner]
        .stdin
        .take()
        .expect("winner input")
        .write_all(b"synthetic-winner-token\n")
        .expect("complete winner intake");
    let (status, success) = output(&mut imports.0[winner]);
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
