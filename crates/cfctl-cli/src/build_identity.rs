use std::{
    fs,
    path::{Path, PathBuf},
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathBuildStateV1 {
    Current,
    Stale,
    Legacy,
    Missing,
    Uninspectable,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathBuildProbeV1 {
    Build {
        path: PathBuf,
        build: BuildInfoV1,
    },
    Legacy {
        path: PathBuf,
        version_output: String,
    },
    Uninspectable {
        path: PathBuf,
        detail: String,
    },
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathBuildIdentityV1 {
    pub schema_version: u8,
    pub healthy: bool,
    pub state: PathBuildStateV1,
    pub path: Option<PathBuf>,
    pub build: Option<BuildInfoV1>,
    pub legacy_version: Option<String>,
    pub detail: String,
}

#[must_use]
pub fn classify_path_build(running: &BuildInfoV1, probe: PathBuildProbeV1) -> PathBuildIdentityV1 {
    match probe {
        PathBuildProbeV1::Build { path, build } => {
            let (healthy, state, detail) =
                match (running.git_commit.as_deref(), build.git_commit.as_deref()) {
                    (Some(running_commit), Some(path_commit))
                        if running.version == build.version && running_commit == path_commit =>
                    {
                        (
                            true,
                            PathBuildStateV1::Current,
                            "PATH cfctl matches the running version and exact commit".to_owned(),
                        )
                    }
                    (Some(_), Some(_)) => (
                        false,
                        PathBuildStateV1::Stale,
                        "PATH cfctl differs from the running version or exact commit".to_owned(),
                    ),
                    _ => (
                        false,
                        PathBuildStateV1::Unknown,
                        "PATH or running cfctl lacks an exact commit identity".to_owned(),
                    ),
                };
            PathBuildIdentityV1 {
                schema_version: 1,
                healthy,
                state,
                path: Some(path),
                build: Some(build),
                legacy_version: None,
                detail,
            }
        }
        PathBuildProbeV1::Legacy {
            path,
            version_output,
        } => PathBuildIdentityV1 {
            schema_version: 1,
            healthy: false,
            state: PathBuildStateV1::Legacy,
            path: Some(path),
            build: None,
            legacy_version: Some(version_output),
            detail: "PATH cfctl does not expose structured build identity".to_owned(),
        },
        PathBuildProbeV1::Uninspectable { path, detail } => PathBuildIdentityV1 {
            schema_version: 1,
            healthy: false,
            state: PathBuildStateV1::Uninspectable,
            path: Some(path),
            build: None,
            legacy_version: None,
            detail,
        },
        PathBuildProbeV1::Missing => PathBuildIdentityV1 {
            schema_version: 1,
            healthy: false,
            state: PathBuildStateV1::Missing,
            path: None,
            build: None,
            legacy_version: None,
            detail: "cfctl is missing from PATH".to_owned(),
        },
    }
}

#[must_use]
pub fn inspect_path_build(running: &BuildInfoV1) -> PathBuildIdentityV1 {
    let Ok(path) = which::which("cfctl") else {
        return classify_path_build(running, PathBuildProbeV1::Missing);
    };
    if same_file(&path, std::env::current_exe().ok().as_deref()) {
        return PathBuildIdentityV1 {
            schema_version: 1,
            healthy: true,
            state: PathBuildStateV1::Current,
            path: Some(path),
            build: Some(running.clone()),
            legacy_version: None,
            detail: "PATH resolves to the running cfctl executable".to_owned(),
        };
    }
    classify_path_build(
        running,
        PathBuildProbeV1::Uninspectable {
            path,
            detail: "PATH cfctl is a different executable and was not run; invoke it directly to inspect its build identity"
                .to_owned(),
        },
    )
}

fn same_file(path: &Path, current: Option<&Path>) -> bool {
    let Some(current) = current else {
        return false;
    };
    fs::canonicalize(path).ok() == fs::canonicalize(current).ok()
}
