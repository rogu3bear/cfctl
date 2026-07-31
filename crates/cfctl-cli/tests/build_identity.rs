#![allow(clippy::expect_used)]

use std::{fs, path::Path, process::Command};

#[cfg(unix)]
use std::os::unix::fs::{PermissionsExt as _, symlink};

use cfctl_auth::{FileSecretStore, SecretStore};
use cfctl_cli::{
    build_identity::{
        PathBuildProbeV1, PathBuildStateV1, build_identity_is_healthy, classify_path_build,
        current_build_info,
    },
    build_support::{ResolvedIdentitySource, build_identity_rerun_paths, resolve_build_identity},
};
use cfctl_core::{BuildIdentitySourceV1, BuildInfoV1};
const COMMIT_A: &str = "0123456789abcdef0123456789abcdef01234567";

/// Builds a `git` invocation that cannot see the caller's git environment.
///
/// `current_dir` is not enough. Git resolves `GIT_DIR` before the working
/// directory, so a test that shells out to git while one is exported operates
/// on the caller's repository instead of its own fixture. That happens for real
/// whenever the suite runs under a pre-push hook, and in a linked worktree the
/// exported `GIT_DIR` shares the main repository's config file — so `git init`
/// against a temporary directory rewrote that config and left the developer's
/// actual repository marked `core.bare = true`.
fn git_command(repository: &Path, arguments: &[&str]) -> Command {
    let mut command = Command::new("git");
    command.current_dir(repository).args(arguments);
    for (key, _) in std::env::vars() {
        if key.starts_with("GIT_") {
            command.env_remove(key);
        }
    }
    command
}

fn git(repository: &Path, arguments: &[&str]) {
    let status = git_command(repository, arguments)
        .status()
        .expect("run git");
    assert!(status.success(), "git {arguments:?}");
}

fn seed_test_fallback_secret(runtime: &Path) {
    FileSecretStore::new(runtime.join("data").join("auth").join("secrets"))
        .put("__test__/keyring-probe-guard", "test-only")
        .expect("seed test-only fallback secret");
}

fn assert_platform_keyring_probe_skipped(envelope: &serde_json::Value) {
    let health = &envelope["result"]["platform_secret_store"];
    assert_eq!(health["active_backend"], "fallback_file");
    assert_eq!(health["fallback_secret_count"], 1);
    assert_eq!(
        health["keyring"],
        "unavailable: not probed while governed fallback credentials are active; this avoids interactive platform prompts"
    );
}

#[test]
fn release_override_requires_and_preserves_a_full_commit() {
    let resolved =
        resolve_build_identity(Some(COMMIT_A), Path::new("/not-used")).expect("valid override");
    assert_eq!(resolved.git_commit.as_deref(), Some(COMMIT_A));
    assert_eq!(resolved.identity_source, ResolvedIdentitySource::ReleaseEnv);

    for malformed in [
        "abc",
        "0123456789abcdef0123456789abcdef0123456g",
        "0123456789ABCDEF0123456789ABCDEF01234567",
    ] {
        assert!(
            resolve_build_identity(Some(malformed), Path::new("/not-used")).is_err(),
            "{malformed}"
        );
    }
}

#[test]
fn clean_checkout_fallback_binds_head_and_dirty_checkout_is_unknown() {
    let repository = tempfile::tempdir().expect("repository");
    git(repository.path(), &["init", "--quiet"]);
    git(
        repository.path(),
        &["config", "user.email", "cfctl@example.invalid"],
    );
    git(repository.path(), &["config", "user.name", "cfctl test"]);
    fs::write(repository.path().join("tracked"), "clean\n").expect("write tracked file");
    git(repository.path(), &["add", "tracked"]);
    git(repository.path(), &["commit", "--quiet", "-m", "initial"]);
    let expected = git_command(repository.path(), &["rev-parse", "HEAD"])
        .output()
        .expect("read HEAD");
    let expected = String::from_utf8(expected.stdout)
        .expect("HEAD is UTF-8")
        .trim()
        .to_owned();

    let clean = resolve_build_identity(None, repository.path()).expect("clean checkout");
    assert_eq!(clean.git_commit.as_deref(), Some(expected.as_str()));
    assert_eq!(clean.identity_source, ResolvedIdentitySource::GitCheckout);

    fs::write(repository.path().join("tracked"), "dirty\n").expect("dirty tracked file");
    let dirty = resolve_build_identity(None, repository.path()).expect("dirty checkout");
    assert!(dirty.git_commit.is_none());
    assert_eq!(dirty.identity_source, ResolvedIdentitySource::Unknown);

    fs::write(repository.path().join("tracked"), "clean\n").expect("restore tracked file");
    fs::write(repository.path().join("untracked"), "new compiler input\n")
        .expect("write untracked file");
    let untracked = resolve_build_identity(None, repository.path()).expect("untracked checkout");
    assert!(untracked.git_commit.is_none());
    assert_eq!(untracked.identity_source, ResolvedIdentitySource::Unknown);
}

#[test]
fn checkout_build_watches_tracked_untracked_and_parent_paths() {
    let repository = tempfile::tempdir().expect("repository");
    git(repository.path(), &["init", "--quiet"]);
    fs::create_dir_all(repository.path().join("crates/example/src")).expect("source directory");
    let tracked = repository.path().join("crates/example/src/lib.rs");
    fs::write(&tracked, "pub fn tracked() {}\n").expect("tracked source");
    git(repository.path(), &["add", "."]);

    let initial = build_identity_rerun_paths(repository.path());
    assert!(initial.contains(&tracked));
    assert!(initial.contains(&repository.path().join("crates/example/src")));
    assert!(initial.contains(&repository.path().join("crates/example")));
    assert!(initial.contains(&repository.path().join("crates")));
    assert!(initial.contains(&repository.path().to_path_buf()));

    let untracked = repository.path().join("crates/example/src/new.rs");
    fs::write(&untracked, "pub fn untracked() {}\n").expect("untracked source");
    let updated = build_identity_rerun_paths(repository.path());
    assert!(updated.contains(&untracked));
}

#[test]
fn build_identity_health_requires_a_trusted_source_and_full_commit() {
    let build = |identity_source, git_commit: Option<&str>| BuildInfoV1 {
        schema_version: 1,
        version: "test".to_owned(),
        git_commit: git_commit.map(str::to_owned),
        identity_source,
    };

    assert!(build_identity_is_healthy(&build(
        BuildIdentitySourceV1::GitCheckout,
        Some(COMMIT_A),
    )));
    assert!(build_identity_is_healthy(&build(
        BuildIdentitySourceV1::ReleaseEnv,
        Some(COMMIT_A),
    )));
    assert!(!build_identity_is_healthy(&build(
        BuildIdentitySourceV1::Unknown,
        Some(COMMIT_A),
    )));
    assert!(!build_identity_is_healthy(&build(
        BuildIdentitySourceV1::GitCheckout,
        None,
    )));
    assert!(!build_identity_is_healthy(&build(
        BuildIdentitySourceV1::GitCheckout,
        Some("short"),
    )));
}

#[test]
fn path_identity_classifies_missing_and_uninspectable() {
    let missing = classify_path_build(PathBuildProbeV1::Missing);
    assert!(!missing.healthy);
    assert_eq!(missing.state, PathBuildStateV1::Missing);
    assert!(missing.path.is_none());
    assert!(missing.build.is_none());

    let uninspectable = classify_path_build(PathBuildProbeV1::Uninspectable {
        path: "/bin/cfctl".into(),
        detail: "PATH cfctl is a different executable and was not run".to_owned(),
    });
    assert!(!uninspectable.healthy);
    assert_eq!(uninspectable.state, PathBuildStateV1::Uninspectable);
    assert_eq!(uninspectable.path.as_deref(), Some(Path::new("/bin/cfctl")));
    assert!(uninspectable.build.is_none());
    assert_eq!(
        uninspectable.detail,
        "PATH cfctl is a different executable and was not run"
    );
}

#[cfg(unix)]
#[test]
fn doctor_never_executes_a_different_path_cfctl() {
    let root = tempfile::tempdir().expect("runtime root");
    let fake_bin = root.path().join("fake-bin");
    fs::create_dir(&fake_bin).expect("create fake bin");
    let fake_cfctl = fake_bin.join("cfctl");
    fs::write(
        &fake_cfctl,
        "#!/bin/sh\n: > \"$CFCTL_TEST_MARKER\"\nexit 0\n",
    )
    .expect("write fake cfctl");
    fs::set_permissions(&fake_cfctl, fs::Permissions::from_mode(0o700))
        .expect("make fake cfctl executable");

    for (command, arguments) in [
        ("doctor", &["doctor", "--json"][..]),
        ("agents-doctor", &["agents", "doctor", "--json"][..]),
    ] {
        let marker = root.path().join(format!("{command}.marker"));
        let runtime = root.path().join(command);
        seed_test_fallback_secret(&runtime);
        let output = Command::new(env!("CARGO_BIN_EXE_cfctl"))
            .env("CFCTL_HOME", &runtime)
            .env("CFCTL_TEST_MARKER", &marker)
            .env("PATH", &fake_bin)
            .args(arguments)
            .output()
            .expect("run doctor with shadowed PATH");
        assert!(!output.status.success(), "{command} must fail closed");
        assert!(
            !marker.exists(),
            "{command} executed an untrusted cfctl from PATH"
        );

        let envelope: serde_json::Value =
            serde_json::from_slice(&output.stderr).expect("doctor JSON envelope");
        assert_platform_keyring_probe_skipped(&envelope);
        assert_eq!(envelope["result"]["path_build"]["state"], "uninspectable");
        assert_eq!(envelope["result"]["path_build"]["healthy"], false);
        assert!(
            envelope["result"]["path_build"]["detail"]
                .as_str()
                .is_some_and(|detail| detail.contains("was not run")),
            "doctor must explain the fail-closed trust boundary"
        );
    }
}

#[cfg(unix)]
#[test]
fn doctor_accepts_a_path_symlink_to_the_running_cfctl() {
    let root = tempfile::tempdir().expect("runtime root");
    let linked_bin = root.path().join("linked-bin");
    fs::create_dir(&linked_bin).expect("create linked bin");
    symlink(env!("CARGO_BIN_EXE_cfctl"), linked_bin.join("cfctl")).expect("link running cfctl");
    let runtime = root.path().join("current");
    seed_test_fallback_secret(&runtime);

    let output = Command::new(env!("CARGO_BIN_EXE_cfctl"))
        .env("CFCTL_HOME", &runtime)
        .env("HOME", &runtime)
        .env("PATH", &linked_bin)
        .args(["doctor", "--json"])
        .output()
        .expect("run doctor through same-file PATH");
    let identity_healthy = build_identity_is_healthy(&current_build_info());
    assert_eq!(output.status.success(), identity_healthy);
    let bytes = if output.status.success() {
        &output.stdout
    } else {
        &output.stderr
    };
    let envelope: serde_json::Value = serde_json::from_slice(bytes).expect("doctor JSON envelope");
    assert_platform_keyring_probe_skipped(&envelope);

    assert_eq!(envelope["result"]["path_build"]["state"], "current");
    assert_eq!(envelope["result"]["path_build"]["healthy"], true);
    assert_eq!(
        envelope["result"]["build_identity_healthy"],
        identity_healthy
    );
}

/// Pins the sanitization itself, because its absence is silent: the suite still
/// passes from a normal shell and only corrupts a repository when it runs under
/// a git hook, which is exactly where nobody is watching.
#[test]
fn git_fixtures_never_inherit_the_callers_git_environment() {
    let command = git_command(Path::new("/not-used"), &["status"]);
    let removed: Vec<_> = command
        .get_envs()
        .filter(|(_, value)| value.is_none())
        .map(|(key, _)| key.to_string_lossy().into_owned())
        .collect();

    for leaked in ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"] {
        if std::env::var_os(leaked).is_some() {
            assert!(
                removed.iter().any(|key| key == leaked),
                "{leaked} is set in this environment and must be cleared for git fixtures"
            );
        }
    }
    assert!(
        removed.iter().all(|key| key.starts_with("GIT_")),
        "only git variables should be cleared: {removed:?}"
    );
}
