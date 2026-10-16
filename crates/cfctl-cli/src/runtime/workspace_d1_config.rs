//! Private D1 configuration binding shared by the four typed consumers.
use super::{
    prelude::{CallInput, CliError, Path, Result, Value},
    support::cli_io,
    worker_deployment,
};
use cfctl_workspace::D1ConfigSource;
use sha2::{Digest as _, Sha256};

#[derive(Debug)]
pub(super) struct ValidatedConfig {
    pub(super) path: String,
    pub(super) sha256: String,
    pub(super) database_name: String,
    pub(super) database_id: String,
}

pub(super) fn validated_config(
    source: D1ConfigSource<'_>,
    input: &CallInput,
) -> Result<ValidatedConfig> {
    let template_bytes = source.execution_template()?;
    let expected = Path::new(source.repository_root).join(source.production_config_path);
    let raw = input
        .query
        .get("config")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input("workspace D1 operation requires query config".to_owned())
        })?;
    let path = Path::new(raw);
    // Validate the original address, before any canonical path comparison.
    let production_bytes = cfctl_storage::capture_private_input(
        path,
        1_048_576,
        cfctl_storage::PrivateInputPermissions::OwnerRead,
    )
    .map_err(|error| CliError::Input(error.to_string()))?;
    let canonical = path.canonicalize().map_err(|error| cli_io(path, error))?;
    if canonical != expected {
        return Err(CliError::Input(
            "workspace D1 config must be the exact contract path".to_owned(),
        ));
    }
    let template: toml::Value = toml::from_str(
        std::str::from_utf8(&template_bytes)
            .map_err(|_| CliError::Input("tracked Wrangler config is not UTF-8".to_owned()))?,
    )
    .map_err(|_| CliError::Input("tracked Wrangler config is invalid".to_owned()))?;
    let template = serde_json::to_value(template)
        .map_err(|_| CliError::Input("tracked Wrangler config is invalid".to_owned()))?;
    let mut production = parse_private_production_config(&production_bytes)?;
    let identity = worker_deployment::normalize_workspace_d1_private_config(
        &mut production,
        &template,
        source.database_binding,
    )?;
    if production != template {
        return Err(CliError::Input("production Wrangler config differs from the tracked template outside the closed private-config overlay".to_owned()));
    }
    let selected = input
        .selectors
        .get("database_id")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("workspace D1 operation requires database_id".to_owned()))?;
    if selected != identity.database_id {
        return Err(CliError::Input(
            "workspace D1 database selector differs from production config".to_owned(),
        ));
    }
    Ok(ValidatedConfig {
        path: canonical.display().to_string(),
        sha256: sha256(&production_bytes),
        database_name: identity.database_name,
        database_id: identity.database_id,
    })
}

pub(super) fn parse_private_production_config(bytes: &[u8]) -> Result<Value> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| CliError::Input("production Wrangler config is not UTF-8".to_owned()))?;
    let parsed: toml::Value = toml::from_str(text)
        .map_err(|_| CliError::Input("production Wrangler config is invalid".to_owned()))?;
    serde_json::to_value(parsed)
        .map_err(|_| CliError::Input("production Wrangler config is invalid".to_owned()))
}

pub(super) fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
