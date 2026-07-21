#[path = "src/build_support.rs"]
mod build_support;

use std::{env, path::PathBuf};

use build_support::{build_identity_rerun_paths, resolve_build_identity};

fn main() -> Result<(), String> {
    println!("cargo:rerun-if-env-changed=CFCTL_BUILD_GIT_COMMIT");
    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR")
        .ok_or_else(|| "CARGO_MANIFEST_DIR is unavailable to the cfctl build script".to_owned())?;
    let manifest = PathBuf::from(manifest_dir);
    let repository = manifest
        .parent()
        .and_then(|path| path.parent())
        .ok_or_else(|| "cfctl-cli must remain inside the workspace crates directory".to_owned())?;
    for path in build_identity_rerun_paths(repository) {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    let release_override = env::var("CFCTL_BUILD_GIT_COMMIT").ok();
    let identity = resolve_build_identity(release_override.as_deref(), repository)
        .map_err(|error| format!("invalid cfctl build identity: {error}"))?;
    println!(
        "cargo:rustc-env=CFCTL_BUILD_GIT_COMMIT_RESOLVED={}",
        identity.git_commit.as_deref().unwrap_or("")
    );
    println!(
        "cargo:rustc-env=CFCTL_BUILD_IDENTITY_SOURCE={}",
        identity.identity_source.as_env_str()
    );
    Ok(())
}
