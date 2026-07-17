#![allow(clippy::expect_used)]

use std::{fs, path::Path, process::Command};

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
