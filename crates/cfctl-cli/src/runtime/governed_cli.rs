use super::api_boundary::persist_secret_lifecycle;
use super::delegated_execution::wrangler_config_directory;
use super::plan_commands::persist_transaction_stage_with_artifact;
use super::prelude::{
    AuthCredential, CallInput, CapabilityV1, CliError, Duration, EvidenceClass, OpenOptions,
    OsString, Path, PlanStatus, PlanV1, ProcessCommand, Result, ResultEnvelopeV2, SecretStore,
    StateStore, StdCommand, Stdio, TransactionStageV1, Utc, Value, VerificationState, env, json,
};
use super::prelude::{OpenOptionsExt, fs};
use super::support::cli_io;
use super::support::configured_agent;
use super::support::http_client;
use super::{pages_deployment, worker_deployment};
use cfctl_agent::build_ui_action;
use cfctl_core::redact_json;

const WRANGLER_ACCOUNT_ENV: &str = "CLOUDFLARE_ACCOUNT_ID";
const WRANGLER_CACHE_ENV: &str = "WRANGLER_CACHE_DIR";
const WRANGLER_CACHE_SUBDIRECTORY: &str = "wrangler";
const DELEGATED_CLI_TIMEOUT: Duration = Duration::from_mins(2);
const WRANGLER_DEPLOY_TIMEOUT: Duration = Duration::from_mins(10);

pub(super) fn execute_governed_ui_plan(
    store: &StateStore,
    plan: &mut PlanV1,
    input: &CallInput,
    secrets: &dyn SecretStore,
) -> Result<ResultEnvelopeV2> {
    let agent = configured_agent()?;
    let target = json!({
        "capability_id": plan.capability.id,
        "url": plan.capability.path,
        "selectors": input.selectors,
        "query": input.query,
        "body": input.body.as_ref().map(redact_json),
        "plan_hash": plan.content_hash,
    });
    let action = build_ui_action(
        agent,
        Some(&plan.operation_id),
        Some(&plan.account_id),
        target,
        &format!(
            "Execute only the exact approved Cloudflare dashboard action: {}. Bind the session to account {}, capture redacted before/after evidence, and stop on any target or content drift.",
            plan.capability.title, plan.account_id
        ),
        true,
    )?;
    let evidence =
        store.write_evidence(EvidenceClass::AgentAction, &serde_json::to_value(&action)?)?;
    plan.status = PlanStatus::RectificationRequired;
    persist_transaction_stage_with_artifact(
        store,
        plan,
        TransactionStageV1::BoundaryResponsePersisted,
        json!({
            "adapter": "governed_ui",
            "agent_action_evidence_hash": evidence.content_hash,
            "performed": false,
            "success": false,
        }),
    )?;
    persist_secret_lifecycle(store, plan, false, None, secrets)?;
    let mut envelope = ResultEnvelopeV2::success(
        "plans run",
        json!({
            "agent_action": action,
            "performed": false,
            "message": "Approved UI action handed off. cfctl does not claim the dashboard change was performed until hash-bound before/after evidence is returned."
        }),
    )
    .with_evidence(evidence);
    envelope.performed = false;
    envelope.operation_id = Some(plan.operation_id.clone());
    envelope.capability_id = Some(plan.capability.id.clone());
    envelope.profile_id = Some(plan.profile_id.clone());
    envelope.account_id = Some(plan.account_id.clone());
    envelope.policy_decision = Some(plan.policy.clone());
    envelope.verification.state = VerificationState::Pending;
    envelope.verification.basis =
        Some("awaiting hash-bound governed UI completion evidence".to_owned());
    Ok(envelope)
}

pub(super) async fn run_delegated_cli(
    capability: &CapabilityV1,
    input: &CallInput,
    credential: &AuthCredential,
    account_id: Option<&str>,
    cache_dir: &Path,
    program_override: Option<&Path>,
    interpreter_override: Option<&Path>,
) -> Result<Value> {
    run_delegated_cli_with_timeout(
        capability,
        input,
        credential,
        account_id,
        cache_dir,
        program_override,
        interpreter_override,
        governed_delegated_cli_timeout(&capability.id),
    )
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "the test-only timeout seam retains every production boundary input without adding a caller-controlled capability selector"
)]
#[expect(
    clippy::too_many_lines,
    reason = "the subprocess boundary keeps governed environment, structured output, timeout, process-tree containment, and redaction in one receipt-producing transaction"
)]
pub(super) async fn run_delegated_cli_with_timeout(
    capability: &CapabilityV1,
    input: &CallInput,
    credential: &AuthCredential,
    account_id: Option<&str>,
    cache_dir: &Path,
    program_override: Option<&Path>,
    interpreter_override: Option<&Path>,
    timeout: Duration,
) -> Result<Value> {
    let mut path_parts = capability.path.split_whitespace();
    let program = path_parts
        .next()
        .ok_or_else(|| CliError::Input("delegated capability has no program".to_owned()))?;
    if !matches!(program, "wrangler" | "cloudflared") {
        return Err(CliError::Input(format!(
            "delegated program `{program}` is not governed by cfctl"
        )));
    }
    let selected_program = program_override.unwrap_or_else(|| Path::new(program));
    let mut command = if let Some(interpreter) = interpreter_override {
        processkit::Command::new(interpreter).arg(selected_program)
    } else {
        processkit::Command::new(selected_program)
    };
    command = command.args(path_parts);
    let isolated_wrangler_directory =
        if worker_deployment::requires_configless_working_directory(capability, input)
            || pages_deployment::binds_artifact(capability)
        {
            Some(
                tempfile::Builder::new()
                    .prefix("configless-governed-wrangler-")
                    .tempdir()
                    .map_err(|source| cli_io(cache_dir, source))?,
            )
        } else {
            None
        };
    if let Some(config) = input
        .query
        .get("config")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    {
        command = command.current_dir(wrangler_config_directory(config)?);
    } else if let Some(directory) = &isolated_wrangler_directory {
        command = command.current_dir(directory.path());
    }
    let wrangler_output_path = if pages_deployment::binds_artifact(capability) {
        isolated_wrangler_directory
            .as_ref()
            .map(|directory| directory.path().join("wrangler-output.jsonl"))
    } else {
        None
    };
    command = command
        .args(cli_input_arguments(&input.selectors)?)
        .args(cli_input_arguments(&input.query)?);
    if pages_deployment::binds_artifact(capability) {
        // cfctl already produced and hash-bound the closed worker bundle. A
        // second Wrangler bundle would reopen ambient project resolution.
        command = command.arg("--no-bundle");
    }
    if input.body.is_some() {
        return Err(CliError::Input(
            "delegated CLI request bodies need a capability-specific native adapter".to_owned(),
        ));
    }
    command = command
        .env_clear()
        .env("PATH", env::var_os("PATH").unwrap_or_default())
        .env("HOME", env::var_os("HOME").unwrap_or_default())
        .env("NO_COLOR", "1")
        .stdin(processkit::Stdin::empty())
        .timeout(timeout);
    for (name, value) in governed_cli_workspace_env(program, account_id, cache_dir) {
        command = command.env(name, value);
    }
    if let Some(path) = &wrangler_output_path {
        command = command.env("WRANGLER_OUTPUT_FILE_PATH", path);
    }
    command = match credential {
        AuthCredential::Bearer { token } => command.env("CLOUDFLARE_API_TOKEN", token),
        AuthCredential::GlobalKey { email, key } => command
            .env("CLOUDFLARE_EMAIL", email)
            .env("CLOUDFLARE_API_KEY", key),
    };
    let label = capability.path.clone();
    let running = command
        .start()
        .await
        .map_err(|_| CliError::SubprocessNotStarted {
            label: label.clone(),
        })?;
    let output =
        running
            .output_bytes()
            .await
            .map_err(|_| CliError::SubprocessReceiptUnavailable {
                label: label.clone(),
            })?;
    if output.timed_out() {
        return Err(CliError::SubprocessTimeout {
            label: label.clone(),
            timeout_seconds: timeout.as_secs(),
        });
    }
    let stdout = redact_subprocess_text(&String::from_utf8_lossy(output.stdout()), credential);
    let stderr = redact_subprocess_text(output.stderr(), credential);
    let structured_output = if let Some(path) = &wrangler_output_path {
        fs::read_to_string(path)
            .map_err(|source| cli_io(path, source))
            .and_then(|value| pages_deployment::parse_wrangler_output(&value))
    } else {
        Ok(Value::Null)
    };
    let success = output.is_success() && structured_output.is_ok();
    let structured_output_error = structured_output.as_ref().err().map(ToString::to_string);
    Ok(json!({
        "adapter": "delegated_cli",
        "command": capability.path,
        "exit_status": output.code(),
        "success": success,
        "stdout": stdout,
        "stderr": stderr,
        "structured_output": structured_output.unwrap_or(Value::Null),
        "structured_output_error": structured_output_error,
        "credential_environment": match credential {
            AuthCredential::Bearer { .. } => ["CLOUDFLARE_API_TOKEN"].as_slice(),
            AuthCredential::GlobalKey { .. } => ["CLOUDFLARE_EMAIL", "CLOUDFLARE_API_KEY"].as_slice(),
        },
    }))
}

pub(super) fn governed_delegated_cli_timeout(capability_id: &str) -> Duration {
    if capability_id == "wrangler.deploy" {
        WRANGLER_DEPLOY_TIMEOUT
    } else {
        DELEGATED_CLI_TIMEOUT
    }
}

pub(super) async fn run_quick_tunnel(
    store: &StateStore,
    plan: &PlanV1,
    input: &CallInput,
) -> Result<Value> {
    let (origin, health_path) = quick_tunnel_request(input)?;
    let runtime_dir = store
        .paths()
        .data_dir
        .join("quick-tunnels")
        .join(&plan.operation_id);
    fs::create_dir_all(&runtime_dir).map_err(|source| CliError::Io {
        path: runtime_dir.display().to_string(),
        source,
    })?;
    let log_path = runtime_dir.join("cloudflared.log");
    let mut child = spawn_quick_tunnel_process(&origin, &runtime_dir, &log_path)?;
    let Some(pid) = child.id() else {
        return Err(CliError::Input(
            "cloudflared started without an observable process id".to_owned(),
        ));
    };
    let started_at = Utc::now().to_rfc3339();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);

    loop {
        let log_text = fs::read_to_string(&log_path).unwrap_or_default();
        if let Some(public_url) = trycloudflare_public_url(&log_text) {
            return Ok(json!({
                "adapter": "delegated_cli",
                "command": "cloudflared tunnel --url [reviewed-loopback-origin]",
                "success": true,
                "exit_status": Value::Null,
                "origin_url": origin,
                "health_path": health_path,
                "public_url": public_url,
                "pid": pid,
                "started_at": started_at,
                "log_path": log_path,
                "credential_environment": [],
            }));
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                return Ok(json!({
                    "adapter": "delegated_cli",
                    "command": "cloudflared tunnel --url [reviewed-loopback-origin]",
                    "success": false,
                    "exit_status": status.code(),
                    "origin_url": origin,
                    "health_path": health_path,
                    "pid": pid,
                    "started_at": started_at,
                    "log_path": log_path,
                    "stderr": log_text,
                    "credential_environment": [],
                }));
            }
            Ok(None) => {}
            Err(source) => {
                terminate_quick_tunnel(&mut child).await;
                return Err(CliError::Io {
                    path: format!("cloudflared process {pid}"),
                    source,
                });
            }
        }
        if tokio::time::Instant::now() >= deadline {
            terminate_quick_tunnel(&mut child).await;
            return Ok(json!({
                "adapter": "delegated_cli",
                "command": "cloudflared tunnel --url [reviewed-loopback-origin]",
                "success": false,
                "exit_status": Value::Null,
                "origin_url": origin,
                "health_path": health_path,
                "pid": pid,
                "started_at": started_at,
                "log_path": log_path,
                "stderr": log_text,
                "failure": "cloudflared did not report a TryCloudflare URL within 30 seconds",
                "credential_environment": [],
            }));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

pub(super) fn quick_tunnel_request(input: &CallInput) -> Result<(String, Option<String>)> {
    let origin = input
        .query
        .get("url")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("quick tunnel requires query control `url`".to_owned()))
        .and_then(validated_quick_tunnel_origin)?;
    let health_path = input
        .query
        .get("health_path")
        .and_then(Value::as_str)
        .map(str::to_owned);
    quick_tunnel_verification_url(
        "https://contract-check.trycloudflare.com",
        health_path.as_deref(),
    )?;
    Ok((origin, health_path))
}

pub(super) fn spawn_quick_tunnel_process(
    origin: &str,
    runtime_dir: &Path,
    log_path: &Path,
) -> Result<tokio::process::Child> {
    let log = secure_create_new(log_path)?;
    let stderr = log.try_clone().map_err(|source| CliError::Io {
        path: log_path.display().to_string(),
        source,
    })?;
    let mut command = ProcessCommand::new("cloudflared");
    command
        .args(["tunnel", "--url", origin])
        .env_clear()
        .env("PATH", env::var_os("PATH").unwrap_or_default())
        .env("HOME", runtime_dir)
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(stderr));
    command.spawn().map_err(|source| CliError::Io {
        path: "cloudflared".to_owned(),
        source,
    })
}

pub(super) async fn terminate_quick_tunnel(child: &mut tokio::process::Child) {
    let _ = child.kill().await;
    let _ = child.wait().await;
}

pub(super) fn secure_create_new(path: &Path) -> Result<fs::File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    options.open(path).map_err(|source| CliError::Io {
        path: path.display().to_string(),
        source,
    })
}

pub(super) fn validated_quick_tunnel_origin(raw: &str) -> Result<String> {
    let parsed = url::Url::parse(raw)
        .map_err(|error| CliError::Input(format!("invalid quick tunnel origin URL: {error}")))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(CliError::Input(
            "quick tunnel origin must use http or https".to_owned(),
        ));
    }
    if !matches!(parsed.host_str(), Some("127.0.0.1" | "localhost" | "::1")) {
        return Err(CliError::Input(
            "quick tunnel origin must resolve to explicit loopback".to_owned(),
        ));
    }
    if parsed.port().is_none() {
        return Err(CliError::Input(
            "quick tunnel origin must include an explicit port".to_owned(),
        ));
    }
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(CliError::Input(
            "quick tunnel origin must not contain credentials, a path, query, or fragment"
                .to_owned(),
        ));
    }
    Ok(parsed.to_string())
}

pub(super) fn trycloudflare_public_url(log: &str) -> Option<String> {
    log.split_whitespace().find_map(|token| {
        let candidate = token.trim_matches(|character: char| {
            matches!(
                character,
                '|' | '"' | '\'' | '(' | ')' | '[' | ']' | '<' | '>' | ',' | ';'
            )
        });
        let parsed = url::Url::parse(candidate).ok()?;
        let host = parsed.host_str()?;
        (parsed.scheme() == "https"
            && host.ends_with(".trycloudflare.com")
            && parsed.port().is_none()
            && parsed.username().is_empty()
            && parsed.password().is_none())
        .then(|| candidate.trim_end_matches('/').to_owned())
    })
}

pub(super) fn quick_tunnel_verification_url(
    public_url: &str,
    health_path: Option<&str>,
) -> Result<String> {
    let mut parsed = url::Url::parse(public_url)
        .map_err(|error| CliError::Input(format!("invalid TryCloudflare URL: {error}")))?;
    if parsed.scheme() != "https"
        || !parsed
            .host_str()
            .is_some_and(|host| host.ends_with(".trycloudflare.com"))
        || parsed.port().is_some()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(CliError::Input(
            "verification URL must be an HTTPS trycloudflare.com subdomain".to_owned(),
        ));
    }
    let path = health_path.unwrap_or("/");
    if !path.starts_with('/')
        || path.starts_with("//")
        || path.contains('?')
        || path.contains('#')
        || path.contains("://")
    {
        return Err(CliError::Input(
            "quick tunnel health_path must be one relative absolute-path reference".to_owned(),
        ));
    }
    parsed.set_path(path);
    parsed.set_query(None);
    parsed.set_fragment(None);
    Ok(parsed.to_string())
}

pub(super) async fn verify_quick_tunnel_plan(input: &CallInput, receipt: &Value) -> Value {
    let context = match quick_tunnel_verification_context(input, receipt) {
        Ok(context) => context,
        Err(error) => {
            return json!({
                "passed": false,
                "basis": error.to_string(),
            });
        }
    };
    let (origin, public_url, public_health, local_health, pid) = context;
    if !quick_tunnel_process_is_alive(pid) {
        return json!({
            "passed": false,
            "basis": "cloudflared process exited before public verification",
            "public_url": public_url,
            "pid": pid,
        });
    }
    let client = match http_client() {
        Ok(client) => client,
        Err(error) => {
            return json!({
                "passed": false,
                "basis": format!("could not construct tunnel verifier: {error}"),
                "public_url": public_url,
                "pid": pid,
            });
        }
    };
    let (local_status, local_body) = match fetch_quick_tunnel_response(&client, &local_health).await
    {
        Ok(response) => response,
        Err(error) => {
            return json!({
                "passed": false,
                "basis": format!("reviewed local origin verification failed: {error}"),
                "public_url": public_url,
                "pid": pid,
            });
        }
    };
    let (public_status, public_body) =
        match fetch_quick_tunnel_response(&client, &public_health).await {
            Ok(response) => response,
            Err(error) => {
                return json!({
                    "passed": false,
                    "basis": format!("TryCloudflare HTTPS verification failed: {error}"),
                    "public_url": public_url,
                    "pid": pid,
                });
            }
        };
    let bodies_match = local_body == public_body;
    let passed = (200..300).contains(&local_status)
        && local_status == public_status
        && bodies_match
        && quick_tunnel_process_is_alive(pid);
    json!({
        "passed": passed,
        "basis": if passed {
            "the recorded cloudflared process is alive and the public HTTPS verification response matches the reviewed loopback origin"
        } else {
            "public TryCloudflare response did not match the reviewed loopback origin"
        },
        "public_url": public_url,
        "verification_url": public_health,
        "origin_url": origin,
        "origin_verification_url": local_health,
        "pid": pid,
        "local_status": local_status,
        "public_status": public_status,
        "response_body_match": bodies_match,
    })
}

pub(super) fn quick_tunnel_verification_context(
    input: &CallInput,
    receipt: &Value,
) -> Result<(String, String, String, String, u64)> {
    let public_url = receipt
        .get("public_url")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("cloudflared did not report a public URL".to_owned()))?
        .to_owned();
    let pid = receipt
        .get("pid")
        .and_then(Value::as_u64)
        .ok_or_else(|| CliError::Input("cloudflared did not report a process id".to_owned()))?;
    let (origin, health_path) = quick_tunnel_request(input)?;
    if receipt.get("origin_url").and_then(Value::as_str) != Some(origin.as_str()) {
        return Err(CliError::Input(
            "cloudflared receipt origin does not match the reviewed plan origin".to_owned(),
        ));
    }
    let public_health = quick_tunnel_verification_url(&public_url, health_path.as_deref())?;
    let local_health = url::Url::parse(&origin)
        .and_then(|base| base.join(health_path.as_deref().unwrap_or("/")))
        .map_err(|error| {
            CliError::Input(format!(
                "could not build reviewed local verification URL: {error}"
            ))
        })?
        .to_string();
    Ok((origin, public_url, public_health, local_health, pid))
}

pub(super) async fn fetch_quick_tunnel_response(
    client: &reqwest::Client,
    url: &str,
) -> Result<(u16, Vec<u8>)> {
    let response = client.get(url).send().await?;
    let status = response.status().as_u16();
    let body = response.bytes().await?.to_vec();
    Ok((status, body))
}

pub(super) fn quick_tunnel_process_is_alive(pid: u64) -> bool {
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    StdCommand::new("/bin/kill")
        .args(["-0", &pid.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Environment that must survive cfctl's fail-closed `env_clear()` boundary
/// for delegated CLI subprocesses.
///
/// Wrangler otherwise discovers its mutable account/config cache beneath the
/// closest `node_modules`, which writes operator state into the reviewed
/// workspace. Binding the cache to cfctl's platform cache directory keeps that
/// state outside source trees. The plan-selected account ID also prevents
/// Wrangler from enumerating accounts and writing a selection cache at all.
pub(super) fn governed_cli_workspace_env(
    program: &str,
    account_id: Option<&str>,
    cache_dir: &Path,
) -> Vec<(&'static str, OsString)> {
    if program != "wrangler" {
        return Vec::new();
    }
    let mut environment = vec![(
        WRANGLER_CACHE_ENV,
        cache_dir.join(WRANGLER_CACHE_SUBDIRECTORY).into_os_string(),
    )];
    if let Some(account_id) = account_id.filter(|value| !value.is_empty()) {
        environment.push((WRANGLER_ACCOUNT_ENV, OsString::from(account_id)));
    }
    environment
}

pub(super) fn governed_cli_environment_contract(cache_dir: &Path) -> Value {
    json!({
        "schema_version": 1,
        "wrangler": {
            "account_binding": "selected_cfctl_account",
            "account_env": WRANGLER_ACCOUNT_ENV,
            "cache_binding": "cfctl_platform_cache",
            "cache_env": WRANGLER_CACHE_ENV,
            "cache_dir": cache_dir.join(WRANGLER_CACHE_SUBDIRECTORY),
            "survives_env_clear": true,
        },
    })
}

pub(super) fn cli_input_arguments(input: &Value) -> Result<Vec<OsString>> {
    let fields = input
        .as_object()
        .ok_or_else(|| CliError::Input("CLI selectors and query must be objects".to_owned()))?;
    let mut arguments = Vec::with_capacity(fields.len().saturating_mul(2));
    for (key, value) in fields {
        let rendered = value
            .as_str()
            .map_or_else(|| value.to_string(), str::to_owned);
        if matches!(key.as_str(), "argument" | "arg" | "path") {
            arguments.push(OsString::from(rendered));
        } else {
            arguments.push(OsString::from(format!("--{}", key.replace('_', "-"))));
            arguments.push(OsString::from(rendered));
        }
    }
    Ok(arguments)
}

pub(super) fn redact_subprocess_text(text: &str, credential: &AuthCredential) -> String {
    let mut sanitized = text.to_owned();
    for secret in [credential.bearer_token(), credential.global_key()]
        .into_iter()
        .flatten()
    {
        sanitized = sanitized.replace(secret, "[REDACTED]");
    }
    sanitized
        .lines()
        .map(|line| {
            let lower = line.to_ascii_lowercase();
            if [
                "access_token",
                "api_token",
                "api key",
                "authorization:",
                "password=",
            ]
            .iter()
            .any(|marker| lower.contains(marker))
            {
                "[REDACTED SECRET-BEARING LINE]".to_owned()
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}
