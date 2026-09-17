use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use cfctl_core::{BuildIdentitySourceV1, BuildInfoV1};
use serde::{Deserialize, Serialize};

#[must_use]
pub fn current_build_info() -> BuildInfoV1 {
    let git_commit = option_env!("CFCTL_BUILD_GIT_COMMIT_RESOLVED")
        .filter(|commit| !commit.is_empty())
        .map(str::to_owned);
    let identity_source = match option_env!("CFCTL_BUILD_IDENTITY_SOURCE") {
        Some("release_env") => BuildIdentitySourceV1::ReleaseEnv,
        Some("git_checkout") => BuildIdentitySourceV1::GitCheckout,
        _ => BuildIdentitySourceV1::Unknown,
    };
    BuildInfoV1 {
        schema_version: 1,
        version: env!("CARGO_PKG_VERSION").to_owned(),
        git_commit,
        identity_source,
    }
}

#[must_use]
pub fn build_identity_is_healthy(build: &BuildInfoV1) -> bool {
    build.identity_source != BuildIdentitySourceV1::Unknown
        && build.git_commit.as_deref().is_some_and(|commit| {
            commit.len() == 40
                && commit
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathBuildStateV1 {
    Current,
    Stale,
    Missing,
    Uninspectable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathBuildProbeV1 {
    Uninspectable { path: PathBuf, detail: String },
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathBuildIdentityV1 {
    pub schema_version: u8,
    pub healthy: bool,
    pub state: PathBuildStateV1,
    pub path: Option<PathBuf>,
    pub build: Option<BuildInfoV1>,
    pub detail: String,
}

#[must_use]
pub fn classify_path_build(probe: PathBuildProbeV1) -> PathBuildIdentityV1 {
    match probe {
        PathBuildProbeV1::Uninspectable { path, detail } => PathBuildIdentityV1 {
            schema_version: 1,
            healthy: false,
            state: PathBuildStateV1::Uninspectable,
            path: Some(path),
            build: None,
            detail,
        },
        PathBuildProbeV1::Missing => PathBuildIdentityV1 {
            schema_version: 1,
            healthy: false,
            state: PathBuildStateV1::Missing,
            path: None,
            build: None,
            detail: "cfctl is missing from PATH".to_owned(),
        },
    }
}

#[must_use]
pub fn inspect_path_build(running: &BuildInfoV1) -> PathBuildIdentityV1 {
    let Ok(path) = which::which("cfctl") else {
        return classify_path_build(PathBuildProbeV1::Missing);
    };
    if same_file(&path, std::env::current_exe().ok().as_deref()) {
        return same_executable_path_identity(
            running,
            path,
            cfctl_source_head(std::env::current_dir().ok().as_deref()).as_deref(),
        );
    }
    classify_path_build(PathBuildProbeV1::Uninspectable {
        path,
        detail: "PATH cfctl is a different executable and was not run; invoke it directly to inspect its build identity"
            .to_owned(),
    })
}

#[must_use]
pub fn same_executable_path_identity(
    running: &BuildInfoV1,
    path: PathBuf,
    source_head: Option<&str>,
) -> PathBuildIdentityV1 {
    let current = PathBuildIdentityV1 {
        schema_version: 1,
        healthy: true,
        state: PathBuildStateV1::Current,
        path: Some(path.clone()),
        build: Some(running.clone()),
        detail: "PATH resolves to the running cfctl executable".to_owned(),
    };
    if running.identity_source != BuildIdentitySourceV1::GitCheckout {
        return current;
    }
    let Some(installed) = running.git_commit.as_deref() else {
        return current;
    };
    let Some(head) = source_head else {
        return current;
    };
    if installed == head {
        return current;
    }
    PathBuildIdentityV1 {
        schema_version: 1,
        healthy: false,
        state: PathBuildStateV1::Stale,
        path: Some(path),
        build: Some(running.clone()),
        detail: "PATH git_commit differs from this cfctl checkout HEAD; rerun ./bootstrap.sh from a clean checkout".to_owned(),
    }
}

fn cfctl_source_head(cwd: Option<&Path>) -> Option<String> {
    let cwd = cwd?;
    let toplevel = git_stdout(cwd, &["rev-parse", "--show-toplevel"])?;
    let manifest = Path::new(&toplevel).join("crates/cfctl-cli/Cargo.toml");
    let text = fs::read_to_string(manifest).ok()?;
    if !text.contains("name = \"cfctl-cli\"") {
        return None;
    }
    git_stdout(Path::new(&toplevel), &["rev-parse", "HEAD"])
}

fn git_stdout(cwd: &Path, arguments: &[&str]) -> Option<String> {
    let mut command = Command::new("git");
    command.arg("-C").arg(cwd).args(arguments);
    for (key, _) in std::env::vars() {
        if key.starts_with("GIT_") {
            command.env_remove(key);
        }
    }
    let output = command.output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn same_file(path: &Path, current: Option<&Path>) -> bool {
    let Some(current) = current else {
        return false;
    };
    fs::canonicalize(path).ok() == fs::canonicalize(current).ok()
}
