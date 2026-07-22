//! Dependency-free build identity resolution shared by build.rs and tests.

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    process::{Command, Output},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedIdentitySource {
    ReleaseEnv,
    GitCheckout,
    Unknown,
}

impl ResolvedIdentitySource {
    #[must_use]
    pub const fn as_env_str(self) -> &'static str {
        match self {
            Self::ReleaseEnv => "release_env",
            Self::GitCheckout => "git_checkout",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedBuildIdentity {
    pub git_commit: Option<String>,
    pub identity_source: ResolvedIdentitySource,
}

pub fn resolve_build_identity(
    release_override: Option<&str>,
    repository_root: &Path,
) -> Result<ResolvedBuildIdentity, String> {
    if let Some(commit) = release_override {
        validate_full_commit(commit)?;
        return Ok(ResolvedBuildIdentity {
            git_commit: Some(commit.to_owned()),
            identity_source: ResolvedIdentitySource::ReleaseEnv,
        });
    }
    let Some(status) = git(
        repository_root,
        &["status", "--porcelain=v1", "--untracked-files=normal"],
    ) else {
        return Ok(unknown_identity());
    };
    if !status.status.success() || !status.stdout.is_empty() {
        return Ok(unknown_identity());
    }
    let Some(head) = git(repository_root, &["rev-parse", "--verify", "HEAD"]) else {
        return Ok(unknown_identity());
    };
    if !head.status.success() {
        return Ok(unknown_identity());
    }
    let commit = String::from_utf8(head.stdout)
        .map_err(|_| "git returned a non-UTF-8 commit identity".to_owned())?;
    let commit = commit.trim();
    if validate_full_commit(commit).is_err() {
        return Ok(unknown_identity());
    }
    Ok(ResolvedBuildIdentity {
        git_commit: Some(commit.to_owned()),
        identity_source: ResolvedIdentitySource::GitCheckout,
    })
}

/// Every repository path whose change can alter checkout-derived build
/// identity. Existing files catch content edits; parent directories catch new
/// or removed untracked compiler inputs. Git metadata catches commit, staging,
/// and branch movement.
#[must_use]
pub fn build_identity_rerun_paths(repository_root: &Path) -> Vec<PathBuf> {
    let mut paths = BTreeSet::new();
    for name in ["HEAD", "index"] {
        if let Some(path) = git_path(repository_root, name) {
            paths.insert(path);
        }
    }
    let Some(files) = git(
        repository_root,
        &["ls-files", "--cached", "--others", "--exclude-standard"],
    ) else {
        return paths.into_iter().collect();
    };
    if !files.status.success() {
        return paths.into_iter().collect();
    }
    let Ok(files) = String::from_utf8(files.stdout) else {
        return paths.into_iter().collect();
    };
    for relative in files.lines().filter(|line| !line.is_empty()) {
        let file = repository_root.join(relative);
        paths.insert(file.clone());
        let mut parent = file.parent();
        while let Some(directory) = parent {
            if !directory.starts_with(repository_root) {
                break;
            }
            paths.insert(directory.to_owned());
            if directory == repository_root {
                break;
            }
            parent = directory.parent();
        }
    }
    paths.into_iter().collect()
}

pub fn validate_full_commit(commit: &str) -> Result<(), String> {
    if commit.len() == 40
        && commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(format!(
            "CFCTL_BUILD_GIT_COMMIT must be exactly 40 lowercase hexadecimal characters, got {commit}"
        ))
    }
}

fn unknown_identity() -> ResolvedBuildIdentity {
    ResolvedBuildIdentity {
        git_commit: None,
        identity_source: ResolvedIdentitySource::Unknown,
    }
}

fn git_path(repository_root: &Path, name: &str) -> Option<PathBuf> {
    let output = git(repository_root, &["rev-parse", "--git-path", name])?;
    if !output.status.success() {
        return None;
    }
    let path = PathBuf::from(String::from_utf8(output.stdout).ok()?.trim());
    Some(if path.is_absolute() {
        path
    } else {
        repository_root.join(path)
    })
}

fn git(repository_root: &Path, arguments: &[&str]) -> Option<Output> {
    let mut command = Command::new("git");
    command.arg("-C").arg(repository_root).args(arguments);
    // Hooks and linked worktrees may export GIT_DIR, GIT_WORK_TREE, or index
    // overrides. `-C` does not outrank those variables, so inherited Git
    // process state would let a checkout build claim another repository's
    // identity.
    for (key, _) in std::env::vars_os() {
        if key.as_encoded_bytes().starts_with(b"GIT_") {
            command.env_remove(key);
        }
    }
    command.output().ok()
}
