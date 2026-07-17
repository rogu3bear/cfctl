//! Dependency-free build identity resolution shared by build.rs and tests.

use std::{
    path::Path,
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
        &["status", "--porcelain=v1", "--untracked-files=no"],
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

fn git(repository_root: &Path, arguments: &[&str]) -> Option<Output> {
    Command::new("git")
        .arg("-C")
        .arg(repository_root)
        .args(arguments)
        .output()
        .ok()
}
