use super::prelude::fs;
use super::prelude::{
    AgentKind, BTreeSet, CapabilityV1, CliError, Duration, Path, PathBuf,
    R2LogRetrievalCredentials, Read, Result, StateStore, Value, env,
};
use super::{
    workspace_d1_evidence, workspace_d1_migration, workspace_d1_projection,
    workspace_d1_reply_admission, workspace_reply_subdomain_ingress,
};
use cfctl_core::redact_json;

pub(super) fn catalog_is_stale(store: &StateStore) -> bool {
    fs::metadata(store.paths().catalog_file())
        .ok()
        .and_then(|metadata| metadata.modified().ok())
        .and_then(|modified| modified.elapsed().ok())
        .is_none_or(|age| age > Duration::from_hours(24))
}

pub(super) fn http_client() -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_mins(2))
        .user_agent(concat!("cfctl/", env!("CARGO_PKG_VERSION")));
    // IP-allowlisted API tokens (e.g. a laptop-pinned minter) are usually
    // scoped to the machine's IPv4. When the host default-routes over IPv6,
    // Cloudflare rejects the call with error 9109 ("Cannot use the access
    // token from location: <IPv6>"). `CFCTL_FORCE_IPV4=1` binds egress to an
    // IPv4 source so those tokens work — including unattended (launchd) runs
    // that can't fall back to an interactive `curl -4`.
    if force_ipv4_egress() {
        builder = builder.local_address(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    }
    Ok(builder.build()?)
}

/// True when `CFCTL_FORCE_IPV4` is set to an affirmative value. Off by default
/// so IPv6-only hosts and non-allowlisted tokens are unaffected.
pub(super) fn force_ipv4_egress() -> bool {
    force_ipv4_from(std::env::var("CFCTL_FORCE_IPV4").ok().as_deref())
}

pub(super) fn force_ipv4_from(value: Option<&str>) -> bool {
    matches!(value, Some("1" | "true" | "yes" | "on"))
}

pub(super) fn configured_agent() -> Result<AgentKind> {
    match env::var("CFCTL_AGENT")
        .unwrap_or_else(|_| "codex".to_owned())
        .to_ascii_lowercase()
        .as_str()
    {
        "codex" => Ok(AgentKind::Codex),
        "claude" | "claude-code" => Ok(AgentKind::Claude),
        "cursor" => Ok(AgentKind::Cursor),
        "gemini" => Ok(AgentKind::Gemini),
        value => Err(CliError::Input(format!(
            "unsupported configured agent `{value}`"
        ))),
    }
}

pub(super) fn home_directory() -> Result<PathBuf> {
    env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| CliError::Input("HOME is unavailable".to_owned()))
}

pub(super) fn read_stdin() -> Result<String> {
    let mut value = String::new();
    std::io::stdin()
        .read_to_string(&mut value)
        .map_err(|source| cli_io(Path::new("stdin"), source))?;
    Ok(value)
}

/// Read an out-of-band secret from exactly one source. `--value-in <path>`
/// exists so callers can hand cfctl a secret without piping it through a build
/// wrapper such as `./cfctl`, which routes stdin through `cargo` and can consume
/// it before the binary reads it. Exactly one of stdin or a file is required.
pub(super) fn read_import_secret(
    from_stdin: bool,
    value_in: Option<&Path>,
    label: &str,
) -> Result<String> {
    match (from_stdin, value_in) {
        (true, Some(_)) => Err(CliError::Input(format!(
            "choose one {label} source: either `--stdin` or `--value-in <path>`, not both"
        ))),
        (false, None) => Err(CliError::Input(format!(
            "the {label} must be supplied out-of-band: add `--stdin` or `--value-in <mode-0600 path>`; values in command arguments are forbidden"
        ))),
        (true, None) => read_stdin(),
        (false, Some(path)) => read_secret_file(path),
    }
}

/// Read a secret from a file that no other user can read. On Unix any group or
/// other permission bit fails closed, mirroring the mode-0600 sink that
/// `--value-out` writes.
pub(super) fn read_secret_file(path: &Path) -> Result<String> {
    read_private_secret_file(path, "--value-in")
}

pub(super) fn read_private_secret_file(path: &Path, option: &str) -> Result<String> {
    let metadata = fs::metadata(path).map_err(|source| cli_io(path, source))?;
    if !metadata.is_file() {
        return Err(CliError::Input(format!(
            "`{option}` path is not a regular file: {}",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(CliError::Input(format!(
                "`{option}` file {} must not be readable by group or others; run `chmod 600 {}` (current mode {:04o})",
                path.display(),
                path.display(),
                mode & 0o7777
            )));
        }
    }
    fs::read_to_string(path).map_err(|source| cli_io(path, source))
}

pub(super) fn read_r2_log_retrieval_credentials(path: &Path) -> Result<R2LogRetrievalCredentials> {
    let content = read_private_secret_file(path, "--credential-in")?;
    let value: Value = serde_json::from_str(&content).map_err(|_| {
        CliError::Input(
            "`--credential-in` must contain one valid JSON object; credential contents were not logged"
                .to_owned(),
        )
    })?;
    let object = value.as_object().ok_or_else(|| {
        CliError::Input("`--credential-in` must contain one JSON object".to_owned())
    })?;
    let expected = BTreeSet::from(["access_key_id", "secret_access_key"]);
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(CliError::Input(
            "`--credential-in` must contain exactly `access_key_id` and `secret_access_key`; unknown or missing fields are rejected"
                .to_owned(),
        ));
    }
    let access_key_id = object
        .get("access_key_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input("credential field `access_key_id` must be a string".to_owned())
        })?;
    let secret_access_key = object
        .get("secret_access_key")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input("credential field `secret_access_key` must be a string".to_owned())
        })?;
    R2LogRetrievalCredentials::new(access_key_id.to_owned(), secret_access_key.to_owned())
        .map_err(CliError::from)
}

pub(super) fn docs_file(store: &StateStore) -> PathBuf {
    store
        .paths()
        .data_dir
        .join("catalog/official-text-feeds-v1.json")
}

pub(super) fn catalog_index_file(store: &StateStore) -> PathBuf {
    store.paths().data_dir.join("catalog/catalog-v1.sqlite3")
}

pub(super) fn workspace_graph_file(store: &StateStore) -> PathBuf {
    store.paths().data_dir.join("workspace-graph-v1.json")
}

pub(super) fn capability_missing(id: &str) -> CliError {
    CliError::guided(
        "CFCTL_UNKNOWN_CAPABILITY",
        format!("capability `{id}` is not in the current catalog"),
        format!(
            "Find the correct id: `cfctl catalog search \"{id}\" --json` (or `cfctl resolve \"<what you want to do>\"`)."
        ),
    )
}

pub(super) fn load_workspace_capability(
    store: &StateStore,
    capability_id: &str,
) -> Result<Option<CapabilityV1>> {
    if let Some(capability) = workspace_d1_migration::load(store, capability_id)? {
        return Ok(Some(capability));
    }
    if let Some(capability) = workspace_d1_projection::load(store, capability_id)? {
        return Ok(Some(capability));
    }
    if let Some(capability) = workspace_d1_reply_admission::load(store, capability_id)? {
        return Ok(Some(capability));
    }
    if let Some(capability) = workspace_reply_subdomain_ingress::load(store, capability_id)? {
        return Ok(Some(capability));
    }
    workspace_d1_evidence::load(store, capability_id)
}

pub(super) fn is_secret_path(path: &Path) -> bool {
    let normalized = path.display().to_string().to_ascii_lowercase();
    [".env", "secret", "credential", "token", "private_key"]
        .iter()
        .any(|needle| normalized.contains(needle))
}

pub(super) fn contains_sensitive_content(content: &str) -> bool {
    if let Ok(value) = serde_json::from_str::<Value>(content)
        && redact_json(&value) != value
    {
        return true;
    }
    content.lines().any(|line| {
        let normalized = line.trim().to_ascii_lowercase();
        !normalized.contains("[redacted]")
            && [
                "access_token",
                "refresh_token",
                "api_token",
                "api_key",
                "global_key",
                "client_secret",
                "private_key",
                "password",
            ]
            .iter()
            .any(|marker| {
                normalized.starts_with(marker)
                    && (normalized.contains('=') || normalized.contains(':'))
            })
    })
}

pub(super) fn cli_io(path: &Path, source: std::io::Error) -> CliError {
    CliError::Io {
        path: path.display().to_string(),
        source,
    }
}
