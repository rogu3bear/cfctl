#![allow(clippy::expect_used)]

use std::{fs, path::Path, process::Command};

#[cfg(unix)]
use std::os::unix::fs::{PermissionsExt as _, symlink};

use cfctl_cli::{
    build_identity::{PathBuildProbeV1, PathBuildStateV1, classify_path_build},
    build_support::{ResolvedIdentitySource, resolve_build_identity},
};
use cfctl_core::{BuildIdentitySourceV1, BuildInfoV1};

const COMMIT_A: &str = "0123456789abcdef0123456789abcdef01234567";
const COMMIT_B: &str = "89abcdef0123456789abcdef0123456789abcdef";

fn build(commit: Option<&str>) -> BuildInfoV1 {
    BuildInfoV1 {
        schema_version: 1,
        version: env!("CARGO_PKG_VERSION").to_owned(),
        git_commit: commit.map(str::to_owned),
        identity_source: if commit.is_some() {
            BuildIdentitySourceV1::GitCheckout
        } else {
            BuildIdentitySourceV1::Unknown
        },
    }
}

fn git(repository: &Path, arguments: &[&str]) {
    let status = Command::new("git")
        .current_dir(repository)
        .args(arguments)
        .status()
        .expect("run git");
    assert!(status.success(), "git {arguments:?}");
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
    let expected = Command::new("git")
        .current_dir(repository.path())
        .args(["rev-parse", "HEAD"])
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
}

#[test]
fn path_identity_classifies_match_stale_legacy_and_missing() {
    let running = build(Some(COMMIT_A));
    let matching = classify_path_build(
        &running,
        PathBuildProbeV1::Build {
            path: "/bin/cfctl".into(),
            build: build(Some(COMMIT_A)),
        },
    );
    assert!(matching.healthy);
    assert_eq!(matching.state, PathBuildStateV1::Current);

    let stale = classify_path_build(
        &running,
        PathBuildProbeV1::Build {
            path: "/bin/cfctl".into(),
            build: build(Some(COMMIT_B)),
        },
    );
    assert!(!stale.healthy);
    assert_eq!(stale.state, PathBuildStateV1::Stale);

    let legacy = classify_path_build(
        &running,
        PathBuildProbeV1::Legacy {
            path: "/bin/cfctl".into(),
            version_output: format!("cfctl {}", env!("CARGO_PKG_VERSION")),
        },
    );
    assert!(!legacy.healthy);
    assert_eq!(legacy.state, PathBuildStateV1::Legacy);

    let missing = classify_path_build(&running, PathBuildProbeV1::Missing);
    assert!(!missing.healthy);
    assert_eq!(missing.state, PathBuildStateV1::Missing);
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
        let output = Command::new(env!("CARGO_BIN_EXE_cfctl"))
            .env("CFCTL_HOME", root.path().join(command))
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

    let output = Command::new(env!("CARGO_BIN_EXE_cfctl"))
        .env("CFCTL_HOME", root.path().join("current"))
        .env("HOME", root.path().join("current"))
        .env("PATH", &linked_bin)
        .args(["doctor", "--json"])
        .output()
        .expect("run doctor through same-file PATH");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("doctor JSON envelope");

    assert_eq!(envelope["result"]["path_build"]["state"], "current");
    assert_eq!(envelope["result"]["path_build"]["healthy"], true);
}
