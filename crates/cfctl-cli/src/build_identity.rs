use std::{
    fs,
    io::{self, Read as _},
    path::{Path, PathBuf},
    process::{Command as ProcessCommand, Output, Stdio},
    time::{Duration, Instant},
};

use cfctl_core::{BuildIdentitySourceV1, BuildInfoV1, ResultEnvelopeV2};
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
    let structured = bounded_output(&path, &["version", "--json"]);
    if let Ok(output) = structured
        && output.status.success()
        && let Ok(envelope) = serde_json::from_slice::<ResultEnvelopeV2>(&output.stdout)
        && let Ok(build) = serde_json::from_value::<BuildInfoV1>(envelope.result)
    {
        return classify_path_build(running, PathBuildProbeV1::Build { path, build });
    }
    let legacy = bounded_output(&path, &["--version"]);
    if let Ok(output) = legacy
        && output.status.success()
    {
        let version_output = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        return classify_path_build(
            running,
            PathBuildProbeV1::Legacy {
                path,
                version_output,
            },
        );
    }
    classify_path_build(
        running,
        PathBuildProbeV1::Uninspectable {
            path,
            detail: "PATH cfctl could not return structured or legacy version information"
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

fn bounded_output(path: &Path, arguments: &[&str]) -> io::Result<Output> {
    let mut child = ProcessCommand::new(path)
        .args(arguments)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            if let Some(mut pipe) = child.stdout.take() {
                pipe.read_to_end(&mut stdout)?;
            }
            if let Some(mut pipe) = child.stderr.take() {
                pipe.read_to_end(&mut stderr)?;
            }
            return Ok(Output {
                status,
                stdout,
                stderr,
            });
        }
        if started.elapsed() >= Duration::from_secs(2) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "cfctl build identity probe exceeded two seconds",
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
