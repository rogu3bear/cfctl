//! Pinned Wrangler launch and closed response mechanics for typed D1 consumers.
use super::{
    governed_cli::{governed_cli_workspace_env, redact_subprocess_text},
    prelude::{AuthCredential, CliError, Result},
    support::cli_io,
    worker_deployment,
    workspace_d1_config::sha256,
    workspace_d1_evidence, workspace_d1_projection, workspace_d1_reply_admission,
};
use serde_json::{Map, Value, json};
use std::{env, fs, path::Path};
use tokio::time::Duration;
const QUERY_TIMEOUT: Duration = Duration::from_mins(2);

pub(super) struct MigrationSelection {
    pub(super) dir: String,
    pub(super) pattern: String,
    pub(super) table: String,
}
#[expect(
    clippy::too_many_arguments,
    reason = "the two immutable config identities are boundary inputs alongside the fixed query authority"
)]
pub(super) async fn execute_json_query_with_config_identity(
    database: &str,
    database_binding: &str,
    config: &str,
    sql: &str,
    root: &Path,
    credential: &AuthCredential,
    account_id: &str,
    cache_dir: &Path,
    expected_config_sha256: &str,
    expected_template_sha256: &str,
) -> Result<Vec<Map<String, Value>>> {
    execute_json_query_with_expected_config(
        database,
        Some(database_binding),
        config,
        sql,
        root,
        credential,
        account_id,
        cache_dir,
        Some(expected_config_sha256),
        Some(expected_template_sha256),
    )
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "the exact config content identity is a security-boundary input alongside the fixed query authority"
)]
pub(super) async fn execute_json_query_with_expected_config(
    database: &str,
    database_binding: Option<&str>,
    config: &str,
    sql: &str,
    root: &Path,
    credential: &AuthCredential,
    account_id: &str,
    cache_dir: &Path,
    expected_config_sha256: Option<&str>,
    expected_template_sha256: Option<&str>,
) -> Result<Vec<Map<String, Value>>> {
    let arguments = [
        "d1".to_owned(),
        "execute".to_owned(),
        database.to_owned(),
        "--remote".to_owned(),
        "--config".to_owned(),
        config.to_owned(),
        "--command".to_owned(),
        sql.to_owned(),
        "--json".to_owned(),
    ];
    let output = run_wrangler_with_expected_config(
        &arguments,
        root,
        credential,
        account_id,
        cache_dir,
        QUERY_TIMEOUT,
        expected_config_sha256,
        expected_template_sha256,
        database_binding,
        None,
    )
    .await?;
    if output.success {
        return parse_query_rows(&output.stdout);
    }
    let failure = QueryFailureDiagnostic::from(&output);
    Err(CliError::Input(format!(
        "fixed Wrangler D1 readback failed (exit_status={}, stdout_hash={}, stderr_hash={})",
        failure.exit_status, failure.stdout_hash, failure.stderr_hash
    )))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct QueryFailureDiagnostic {
    pub(super) exit_status: String,
    pub(super) stdout_hash: String,
    pub(super) stderr_hash: String,
}

impl From<&WranglerOutput> for QueryFailureDiagnostic {
    fn from(output: &WranglerOutput) -> Self {
        Self {
            exit_status: output
                .exit_status
                .map_or_else(|| "signal".to_owned(), |status| status.to_string()),
            stdout_hash: sha256(output.stdout.as_bytes()),
            stderr_hash: sha256(output.stderr.as_bytes()),
        }
    }
}

#[derive(Debug)]
pub(super) struct WranglerOutput {
    pub(super) success: bool,
    pub(super) exit_status: Option<i32>,
    pub(super) stdout: String,
    pub(super) stderr: String,
    pub(super) provider_output_retained: bool,
    pub(super) private_config_sha256: Option<String>,
}

pub(super) async fn run_wrangler(
    arguments: &[String],
    root: &Path,
    credential: &AuthCredential,
    account_id: &str,
    cache_dir: &Path,
    timeout: Duration,
) -> Result<WranglerOutput> {
    run_wrangler_with_expected_config(
        arguments, root, credential, account_id, cache_dir, timeout, None, None, None, None,
    )
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "the two immutable config identities are boundary inputs, not ambient subprocess state"
)]
pub(super) async fn run_wrangler_with_config_identity(
    arguments: &[String],
    root: &Path,
    credential: &AuthCredential,
    account_id: &str,
    cache_dir: &Path,
    timeout: Duration,
    expected_config_sha256: &str,
    expected_template_sha256: &str,
    database_binding: &str,
    boundary: Option<&cfctl_core::BoundaryObservation>,
) -> Result<WranglerOutput> {
    run_wrangler_with_expected_config(
        arguments,
        root,
        credential,
        account_id,
        cache_dir,
        timeout,
        Some(expected_config_sha256),
        Some(expected_template_sha256),
        Some(database_binding),
        boundary,
    )
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "the immutable config identity is a boundary input, not ambient subprocess state"
)]
async fn run_wrangler_with_expected_config(
    arguments: &[String],
    root: &Path,
    credential: &AuthCredential,
    account_id: &str,
    cache_dir: &Path,
    timeout: Duration,
    expected_config_sha256: Option<&str>,
    expected_template_sha256: Option<&str>,
    database_binding: Option<&str>,
    boundary: Option<&cfctl_core::BoundaryObservation>,
) -> Result<WranglerOutput> {
    let local_wrangler = root.join("node_modules/wrangler/bin/wrangler.js");
    let program = if local_wrangler.is_file() {
        local_wrangler.as_path()
    } else {
        Path::new("wrangler")
    };
    run_wrangler_program(
        program,
        arguments,
        root,
        credential,
        account_id,
        cache_dir,
        timeout,
        expected_config_sha256,
        expected_template_sha256,
        database_binding,
        boundary,
    )
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "the closed one-file migration selection joins the immutable private-config identities at the subprocess boundary"
)]
pub(super) async fn run_wrangler_with_migration_selection(
    arguments: &[String],
    root: &Path,
    credential: &AuthCredential,
    account_id: &str,
    cache_dir: &Path,
    timeout: Duration,
    expected_config_sha256: Option<&str>,
    expected_template_sha256: Option<&str>,
    database_binding: Option<&str>,
    migration: Option<&MigrationSelection>,
    boundary: &cfctl_core::BoundaryObservation,
) -> Result<WranglerOutput> {
    let local_wrangler = root.join("node_modules/wrangler/bin/wrangler.js");
    let program = if local_wrangler.is_file() {
        local_wrangler.as_path()
    } else {
        Path::new("wrangler")
    };
    run_wrangler_program_inner(
        program,
        arguments,
        root,
        credential,
        account_id,
        cache_dir,
        timeout,
        expected_config_sha256,
        expected_template_sha256,
        database_binding,
        migration,
        Some(boundary),
    )
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "the test seam retains both immutable config identities at the subprocess boundary"
)]
pub(super) async fn run_wrangler_program(
    program: &Path,
    arguments: &[String],
    root: &Path,
    credential: &AuthCredential,
    account_id: &str,
    cache_dir: &Path,
    timeout: Duration,
    expected_config_sha256: Option<&str>,
    expected_template_sha256: Option<&str>,
    database_binding: Option<&str>,
    boundary: Option<&cfctl_core::BoundaryObservation>,
) -> Result<WranglerOutput> {
    run_wrangler_program_inner(
        program,
        arguments,
        root,
        credential,
        account_id,
        cache_dir,
        timeout,
        expected_config_sha256,
        expected_template_sha256,
        database_binding,
        None,
        boundary,
    )
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "the test seam retains immutable config identities and the optional closed migration selection at one subprocess boundary"
)]
async fn run_wrangler_program_inner(
    program: &Path,
    arguments: &[String],
    root: &Path,
    credential: &AuthCredential,
    account_id: &str,
    cache_dir: &Path,
    timeout: Duration,
    expected_config_sha256: Option<&str>,
    expected_template_sha256: Option<&str>,
    database_binding: Option<&str>,
    migration: Option<&MigrationSelection>,
    boundary: Option<&cfctl_core::BoundaryObservation>,
) -> Result<WranglerOutput> {
    let mut execution_arguments = arguments.to_vec();
    let private_config = bind_private_config_from_arguments_inner(
        &mut execution_arguments,
        expected_config_sha256,
        expected_template_sha256,
        database_binding,
        migration,
    )?;
    let token = credential.bearer_token().ok_or_else(|| {
        CliError::Input(
            "workspace D1 migrations require a scoped API-token profile; global-key execution is forbidden"
                .to_owned(),
        )
    })?;
    let mut command = processkit::Command::new(program)
        .args(&execution_arguments)
        .current_dir(root)
        .env_clear()
        .env("PATH", env::var_os("PATH").unwrap_or_default())
        .env("HOME", env::var_os("HOME").unwrap_or_default())
        .env("NO_COLOR", "1")
        .env("CLOUDFLARE_API_TOKEN", token)
        .stdin(processkit::Stdin::empty())
        .timeout(timeout);
    for (name, value) in governed_cli_workspace_env("wrangler", Some(account_id), cache_dir) {
        command = command.env(name, value);
    }
    let running = command
        .start()
        .await
        .map_err(|_| CliError::SubprocessNotStarted {
            label: "workspace D1 migration Wrangler".to_owned(),
        })?;
    if let Some(boundary) = boundary {
        boundary.record_dispatch(cfctl_core::DispatchKind::Mutation);
    }
    let output =
        running
            .output_bytes()
            .await
            .map_err(|_| CliError::SubprocessReceiptUnavailable {
                label: "workspace D1 migration Wrangler".to_owned(),
            })?;
    if output.timed_out() {
        return Err(CliError::SubprocessTimeout {
            label: "workspace D1 migration Wrangler".to_owned(),
            timeout_seconds: timeout.as_secs(),
        });
    }
    if let Some(private_config) = private_config {
        let (success, stdout) = if output.is_success()
            && execution_arguments
                .iter()
                .any(|argument| argument == "--json")
        {
            match project_private_json_query_with_guard(
                output.stdout(),
                &execution_arguments,
                &private_config,
            ) {
                Ok(projected) => (true, projected),
                Err(()) => (false, String::new()),
            }
        } else {
            (output.is_success(), String::new())
        };
        return Ok(WranglerOutput {
            success,
            exit_status: output.code(),
            stdout,
            stderr: String::new(),
            provider_output_retained: false,
            private_config_sha256: Some(private_config.content_sha256().to_owned()),
        });
    }
    Ok(WranglerOutput {
        success: output.is_success(),
        exit_status: output.code(),
        stdout: redact_subprocess_text(&String::from_utf8_lossy(output.stdout()), credential),
        stderr: redact_subprocess_text(output.stderr(), credential),
        provider_output_retained: true,
        private_config_sha256: None,
    })
}

fn bind_private_config_from_arguments_inner(
    arguments: &mut [String],
    expected_config_sha256: Option<&str>,
    expected_template_sha256: Option<&str>,
    database_binding: Option<&str>,
    migration: Option<&MigrationSelection>,
) -> Result<Option<worker_deployment::BoundPrivateConfig>> {
    if arguments
        .iter()
        .any(|argument| argument.starts_with("--config="))
    {
        return Err(CliError::Input(
            "workspace D1 Wrangler arguments must bind config as one exact --config path pair"
                .to_owned(),
        ));
    }
    let positions = arguments
        .windows(2)
        .enumerate()
        .filter_map(|(index, pair)| (pair[0] == "--config").then_some(index + 1))
        .collect::<Vec<_>>();
    if positions.is_empty() {
        return Ok(None);
    }
    if positions.len() != 1
        || arguments
            .last()
            .is_some_and(|argument| argument == "--config")
    {
        return Err(CliError::Input(
            "workspace D1 Wrangler arguments require exactly one complete --config path pair"
                .to_owned(),
        ));
    }
    let position = positions[0];
    let config = Path::new(&arguments[position]);
    let template = if config.file_name().and_then(std::ffi::OsStr::to_str)
        == Some("wrangler.production.toml")
    {
        config.with_file_name("wrangler.toml")
    } else {
        worker_deployment::private_config_template_path(config).ok_or_else(|| {
            CliError::Input(
                "workspace D1 closed operation contract requires a private production config"
                    .to_owned(),
            )
        })?
    };
    let database_binding = database_binding.ok_or_else(|| {
        CliError::Input(
            "workspace D1 private execution requires the planned database binding".to_owned(),
        )
    })?;
    let mut bound = worker_deployment::bind_workspace_d1_private_config_for_execution(
        config,
        &template,
        expected_config_sha256,
        expected_template_sha256,
        database_binding,
    )?;
    if let Some(migration) = migration {
        stage_migration_selection(&mut bound, database_binding, migration)?;
    }
    let bound = Some(bound);
    if let Some(bound) = &bound {
        arguments[position] = bound.path().display().to_string();
    }
    Ok(bound)
}

pub(super) fn stage_migration_selection(
    bound: &mut worker_deployment::BoundPrivateConfig,
    database_binding: &str,
    migration: &MigrationSelection,
) -> Result<()> {
    let text = fs::read_to_string(bound.path()).map_err(|source| cli_io(bound.path(), source))?;
    let mut document: toml::Value = toml::from_str(&text)
        .map_err(|_| CliError::Input("workspace D1 staged config is invalid".to_owned()))?;
    let databases = document
        .get_mut("d1_databases")
        .and_then(toml::Value::as_array_mut)
        .ok_or_else(|| CliError::Input("workspace D1 config omitted bindings".to_owned()))?;
    let mut selected = databases
        .iter_mut()
        .filter(|database| {
            database.get("binding").and_then(toml::Value::as_str) == Some(database_binding)
        })
        .collect::<Vec<_>>();
    if selected.len() != 1 {
        return Err(CliError::Input(
            "workspace D1 config did not contain exactly one selected binding".to_owned(),
        ));
    }
    let table = selected[0]
        .as_table_mut()
        .ok_or_else(|| CliError::Input("workspace D1 selected binding was invalid".to_owned()))?;
    table.insert(
        "migrations_dir".to_owned(),
        toml::Value::String(migration.dir.clone()),
    );
    table.insert(
        "migrations_pattern".to_owned(),
        toml::Value::String(migration.pattern.clone()),
    );
    table.insert(
        "migrations_table".to_owned(),
        toml::Value::String(migration.table.clone()),
    );
    let bytes = toml::to_string(&document).map_err(|_| {
        CliError::Input("workspace D1 staged config could not be rendered".to_owned())
    })?;
    bound.replace_staged_bytes(bytes.as_bytes())
}

#[cfg(test)]
pub(super) fn project_private_json_query(
    stdout: &[u8],
    arguments: &[String],
) -> std::result::Result<String, ()> {
    project_private_json_query_inner(stdout, arguments, None)
}

fn project_private_json_query_with_guard(
    stdout: &[u8],
    arguments: &[String],
    private_config: &worker_deployment::BoundPrivateConfig,
) -> std::result::Result<String, ()> {
    project_private_json_query_inner(stdout, arguments, Some(private_config))
}

fn project_private_json_query_inner(
    stdout: &[u8],
    arguments: &[String],
    private_config: Option<&worker_deployment::BoundPrivateConfig>,
) -> std::result::Result<String, ()> {
    let text = std::str::from_utf8(stdout).map_err(|_| ())?;
    let sql = arguments
        .windows(2)
        .filter_map(|pair| (pair[0] == "--command").then_some(pair[1].as_str()))
        .collect::<Vec<_>>();
    if sql.len() != 1 {
        return Err(());
    }
    let rows = parse_query_rows(text).map_err(|_| ())?;
    super::workspace_d1_migration::project_private_query_rows(sql[0], &rows)
        .or_else(|| workspace_d1_evidence::project_private_query_rows(sql[0], &rows))
        .or_else(|| workspace_d1_projection::project_private_query_rows(sql[0], &rows))
        .or_else(|| workspace_d1_reply_admission::project_private_query_rows(sql[0], &rows))
        .ok_or(())?
        .map_err(|_| ())?;
    if private_config.is_some_and(|private_config| {
        private_config.retained_rows_contain_private_representation(&rows)
    }) {
        return Err(());
    }
    serde_json::to_string(&json!([{"success": true, "results": rows}])).map_err(|_| ())
}

pub(super) fn parse_query_rows(stdout: &str) -> Result<Vec<Map<String, Value>>> {
    let value: Value = serde_json::from_str(stdout.trim())
        .map_err(|error| CliError::Input(format!("Wrangler D1 readback was not JSON: {error}")))?;
    let envelopes = value
        .as_array()
        .ok_or_else(|| CliError::Input("Wrangler D1 readback was not an array".to_owned()))?;
    let mut rows = Vec::new();
    for envelope in envelopes {
        if envelope.get("success").and_then(Value::as_bool) != Some(true) {
            return Err(CliError::Input(
                "Wrangler D1 readback reported an unsuccessful query".to_owned(),
            ));
        }
        let results = envelope
            .get("results")
            .and_then(Value::as_array)
            .ok_or_else(|| CliError::Input("Wrangler D1 readback omitted results".to_owned()))?;
        for row in results {
            rows.push(
                row.as_object().cloned().ok_or_else(|| {
                    CliError::Input("Wrangler D1 result row is invalid".to_owned())
                })?,
            );
        }
    }
    Ok(rows)
}

pub(super) fn parse_wrangler_version(stdout: &str) -> Result<String> {
    stdout
        .split_whitespace()
        .find(|part| {
            let components = part.split('.').collect::<Vec<_>>();
            components.len() == 3
                && components.iter().all(|component| {
                    !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
                })
        })
        .map(str::to_owned)
        .ok_or_else(|| CliError::Input("Wrangler version output was invalid".to_owned()))
}
