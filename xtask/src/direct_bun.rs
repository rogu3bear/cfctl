//! Bind verification children to a Bun executable that survives private staging.

use std::{
    env,
    ffi::{OsStr, OsString},
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::OnceLock,
};

use crate::TaskError;

static VERIFY_PATH: OnceLock<OsString> = OnceLock::new();

pub(super) fn prefer_for_verification() -> Result<PathBuf, TaskError> {
    let search_path = env::var_os("PATH").unwrap_or_default();
    let home = env::var_os("HOME").map(PathBuf::from);
    let bun = select_direct_bun(home.as_deref(), &search_path)?;
    let directory = bun.parent().ok_or_else(|| {
        TaskError::BunVerifier(format!("{} has no parent directory", bun.display()))
    })?;
    let path = env::join_paths(
        std::iter::once(directory.to_path_buf()).chain(env::split_paths(&search_path)),
    )
    .map_err(|error| {
        TaskError::BunVerifier(format!("cannot select direct Bun on PATH: {error}"))
    })?;

    VERIFY_PATH
        .set(path)
        .map_err(|_| TaskError::BunVerifier("verification PATH was already selected".to_owned()))?;
    Ok(bun)
}

pub(super) fn apply_to_command(command: &mut Command) {
    if let Some(path) = VERIFY_PATH.get() {
        command.env("PATH", path);
    }
}

fn select_direct_bun(home: Option<&Path>, search_path: &OsStr) -> Result<PathBuf, TaskError> {
    let candidates = home
        .into_iter()
        .map(|home| home.join(".bun/bin/bun"))
        .chain(env::split_paths(search_path).map(|directory| directory.join("bun")));
    let mut rejected = Vec::new();
    let mut shim = None;
    for candidate in candidates {
        if !candidate.exists() {
            continue;
        }
        let executable = match fs::canonicalize(&candidate) {
            Ok(executable) => executable,
            Err(error) => {
                rejected.push(format!("{}: {error}", candidate.display()));
                continue;
            }
        };
        if !executable.is_file() {
            rejected.push(format!("{} is not a regular file", executable.display()));
            continue;
        }
        if executable.file_name() != Some(OsStr::new("bun")) {
            let detail = format!(
                "{} resolves to {} (a launcher or shim)",
                candidate.display(),
                executable.display()
            );
            if shim.is_none() {
                shim = Some(detail.clone());
            }
            rejected.push(detail);
            continue;
        }
        match Command::new(&executable)
            .env_clear()
            .arg("--version")
            .output()
        {
            Ok(output) if output.status.success() && !output.stdout.is_empty() => {
                return Ok(executable);
            }
            Ok(_) => rejected.push(format!(
                "{} cannot report a version with a cleared environment",
                executable.display()
            )),
            Err(error) => rejected.push(format!("{}: {error}", executable.display())),
        }
    }
    let detail = shim
        .or_else(|| rejected.into_iter().next())
        .unwrap_or_else(|| "no Bun executable was found at ~/.bun/bin/bun or on PATH".to_owned());
    Err(TaskError::BunVerifier(format!(
        "{detail}; the reply-admission proof copies Bun into an isolated stage, where version-manager shims cannot run. Put a direct Bun executable at ~/.bun/bin/bun or on PATH"
    )))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::{
        env, fs,
        os::unix::fs::{PermissionsExt, symlink},
        path::Path,
    };

    use super::select_direct_bun;

    fn executable(path: &Path) {
        fs::write(path, "#!/bin/sh\nprintf '1.3.14\\n'\n").expect("write executable");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("make executable");
    }

    #[test]
    fn prefers_direct_bun_and_explains_a_shim_without_one() {
        let root = env::temp_dir().join(format!("xtask-direct-bun-{}", uuid::Uuid::new_v4()));
        let shim_dir = root.join("shims");
        let direct_dir = root.join("home/.bun/bin");
        fs::create_dir_all(&shim_dir).expect("shim directory");
        fs::create_dir_all(&direct_dir).expect("direct directory");
        executable(&shim_dir.join("mise"));
        symlink("mise", shim_dir.join("bun")).expect("mise shim");
        executable(&direct_dir.join("bun"));
        let search_path = env::join_paths([&shim_dir]).expect("PATH");

        assert_eq!(
            select_direct_bun(Some(&root.join("home")), &search_path).expect("direct Bun selected"),
            fs::canonicalize(direct_dir.join("bun")).expect("canonical direct Bun")
        );
        let path_with_direct = env::join_paths([&shim_dir, &direct_dir]).expect("PATH with Bun");
        assert_eq!(
            select_direct_bun(None, &path_with_direct).expect("search past shim"),
            fs::canonicalize(direct_dir.join("bun")).expect("canonical direct Bun")
        );
        let error = select_direct_bun(None, &search_path).expect_err("shim cannot be staged");
        let message = error.to_string();
        assert!(message.contains("launcher or shim"), "{message}");
        assert!(message.contains("~/.bun/bin/bun"), "{message}");
        fs::remove_dir_all(root).expect("remove fixture");
    }
}
