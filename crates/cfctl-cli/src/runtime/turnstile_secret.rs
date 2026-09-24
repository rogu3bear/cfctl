//! Widget secret custody: acquire the exclusive private sink before any API read.
use super::prelude::{
    AuthCredential, CallInput, CapabilityV1, CliError, CloudflareResponseV1, Executor, Path,
    Result, json,
};
use cfctl_core::turnstile_secret as widget;
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
};

#[cfg(all(test, unix))]
mod tests;

pub(super) fn prepare(cap: &CapabilityV1, path: Option<&Path>) -> Result<File> {
    if !widget::supported(cap) || cap.verification.strategy != widget::VERIFY {
        return Err(CliError::Input("Turnstile secret read contract is stale; synchronize the qualified catalog before reading".into()));
    }
    let path =
        path.ok_or_else(|| CliError::Input("Turnstile secret read requires --value-out".into()))?;
    let parent = path
        .parent()
        .ok_or_else(|| CliError::Input("private sink parent required".into()))?;
    let parent = fs::canonicalize(parent)
        .map_err(|_| CliError::Input("private sink parent must already exist".into()))?;
    if !path.is_absolute() || parent.ancestors().any(|p| p.join(".git").exists()) {
        return Err(CliError::Input(
            "secret sink must be absolute and outside every Git repository".into(),
        ));
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        if fs::metadata(&parent)
            .map_err(|_| CliError::Input("cannot inspect private sink directory".into()))?
            .permissions()
            .mode()
            & 0o777
            != 0o700
        {
            return Err(CliError::Input(
                "secret sink parent must have mode 0700".into(),
            ));
        }
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    return Err(CliError::Input(
        "secret read requires a platform with private file permissions".into(),
    ));
    #[cfg(unix)]
    options.open(path).map_err(|_| CliError::Input("secret sink must be a new writable file; existing files and symlinks are never overwritten".into()))
}

pub(super) fn finish(
    mut response: CloudflareResponseV1,
    input: &CallInput,
    file: &mut File,
) -> Result<CloudflareResponseV1> {
    let expected = input
        .selectors
        .get("sitekey")
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| CliError::Input("exact widget sitekey required".into()))?;
    let valid = response.status == 200
        && response.success
        && response
            .result
            .get("sitekey")
            .and_then(serde_json::Value::as_str)
            == Some(expected);
    let outcome = if valid {
        if let Some(secret) = response
            .result
            .get("secret")
            .and_then(serde_json::Value::as_str)
            .filter(|s| !s.trim().is_empty())
        {
            if file
                .write_all(secret.as_bytes())
                .and_then(|()| file.sync_all())
                .is_ok()
            {
                "secret_sunk"
            } else {
                "sink_write_failed"
            }
        } else {
            "secret_missing"
        }
    } else {
        "provider_or_identity_rejected"
    };
    // Provider error text, unexpected fields and headers may echo secret values.
    // Emit only our requested identity and scalar outcome; never the raw response.
    response.success = outcome == "secret_sunk";
    response.result = json!({"sitekey":expected,"secret_sunk":response.success,"outcome":outcome});
    response.errors = Vec::new();
    response.result_info = None;
    response.etag = None;
    response.cf_ray = None;
    Ok(response)
}

pub(super) async fn fetch(
    executor: &Executor,
    capability: &CapabilityV1,
    input: &CallInput,
    credential: &AuthCredential,
    sink: &mut File,
) -> Result<CloudflareResponseV1> {
    let response = executor
        .execute_read(capability, input, credential)
        .await
        .map_err(|_| {
            CliError::Input(
                "widget secret read failed; provider details suppressed to protect secret material"
                    .into(),
            )
        })?;
    finish(response, input, sink)
}
