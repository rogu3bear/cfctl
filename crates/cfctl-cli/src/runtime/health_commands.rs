use super::credential_resolution::oauth_scope_inventory_hash;
use super::credential_resolution::platform_secrets;
use super::governed_cli::governed_cli_environment_contract;
use super::prelude::{
    AgentKind, CatalogSnapshot, CliError, ErrorV1, ProfileKind, ProfilesConfig, Result,
    ResultEnvelopeV2, StateStore, Utc, Value, VerificationState, env, json,
};
use super::support::catalog_is_stale;
use super::support::home_directory;
use super::support::http_client;
use crate::build_identity::{build_identity_is_healthy, current_build_info, inspect_path_build};
use crate::telemetry_product::OPERATIONAL_PROOF_PROJECTION_LIMIT;
use cfctl_agent::inspect_agent;
use cfctl_core::StandingAuthorityStatus;

pub(super) fn platform_secret_store_health(store: &StateStore) -> Result<Value> {
    let secrets = platform_secrets(store);
    if secrets.is_private() {
        return Ok(
            json!({"preferred": "private_file", "keyring": "not_selected", "active_backend": "private_file", "private_dir": secrets.fallback_root(), "private_secret_count": secrets.fallback_secret_count()?}),
        );
    }
    let preferred = if cfg!(target_os = "macos") {
        "keychain"
    } else if cfg!(target_os = "linux") {
        "secret_service"
    } else {
        "unsupported"
    };
    let (keyring, active_backend) = match secrets.keyring_probe() {
        Ok(()) => ("ok".to_owned(), "platform_keyring"),
        Err(error) => (format!("unavailable: {error}"), "fallback_file"),
    };
    Ok(json!({
        "preferred": preferred,
        "keyring": keyring,
        "active_backend": active_backend,
        "fallback_dir": secrets.fallback_root(),
        "fallback_secret_count": secrets.fallback_secret_count()?,
    }))
}

/// Reports whether authenticated evidence can currently be produced.
///
/// Deliberately does not call `require_qualifying_evidence_authority`. That
/// probe reaches the platform keyring, and `doctor` is run constantly and must
/// never raise an interactive prompt or fail because one is unanswerable. The
/// bounded proof projection already degrades safely — rows it cannot
/// authenticate are counted as candidate failures rather than erroring — so the
/// same classification serves as the signal.
///
/// Zero retained rows alongside candidate failures is the state a reinstall
/// leaves behind: each build has a new code identity, the platform ACL does not
/// carry over, and nothing else surfaces it.
fn evidence_authority_health(store: &StateStore) -> Result<Value> {
    let page = store.list_recent_operational_proofs(OPERATIONAL_PROOF_PROJECTION_LIMIT)?;
    let retained = page.proofs.len();
    let failures = page.failures.len();
    let qualifying = failures == 0 && (retained > 0 || page.total_count == 0);
    Ok(json!({
        "qualifying": qualifying,
        "retained_count": retained,
        "candidate_failure_count": failures,
        "legacy_nonqualifying_count": page.legacy_nonqualifying_count,
        "total_index_rows": page.total_count,
        // Three distinct states, and the empty one is not a failure. A clean
        // install has produced nothing yet; that is healthy. Rows that exist
        // but will not verify is the state a reinstall leaves behind.
        "detail": if page.total_count == 0 {
            "no authenticated evidence has been produced yet"
        } else if failures > 0 {
            "authenticated rows exist but cannot be verified; the platform authority is unreadable by this build. Re-authorize in an interactive session."
        } else {
            "authenticated evidence can be produced and read back"
        },
    }))
}

fn standing_authorities_health(store: &StateStore) -> Result<Value> {
    let now = Utc::now();
    let authorities: Vec<Value> = store
        .list_authorities()?
        .iter()
        .map(|authority| {
            // `status` is the stored lifecycle field; it does not observe the
            // clock. An authority whose TTL has passed is refused at admission
            // by `ensure_operational_at`, but reported here it read `active`
            // with an expiry already in the past — the health surface answering
            // "which grants are live?" with the one answer it must not give.
            let expired = now > authority.expires_at;
            json!({
                "authority_id": authority.authority_id,
                "status": authority.status.as_str(),
                "expired": expired,
                "admissible": !expired
                    && authority.status == StandingAuthorityStatus::Active,
                "account_id": authority.account_id,
                "zone_id": authority.zone_id,
                "bound_resources": authority.allowed_token_resources(),
                "name_prefix": authority.name_prefix,
                "capability_ids": authority.capability_ids,
                "expires_at": authority.expires_at,
                "max_runs_per_day": authority.max_runs_per_day,
                "runs_last_24h": authority.runs_in_last_day(now),
                "minted_tokens": authority.minted_token_ids.len(),
            })
        })
        .collect();
    Ok(Value::Array(authorities))
}

pub(super) fn doctor_command(store: &StateStore) -> Result<ResultEnvelopeV2> {
    let profiles = ProfilesConfig::load(store)?;
    let inventory_hash = oauth_scope_inventory_hash(store)?;
    let unsupported_legacy_profiles: Vec<Value> = profiles
        .profiles
        .values()
        .filter(|profile| profile.kind == ProfileKind::LegacyWranglerSession)
        .map(|profile| {
            json!({
                "profile": profile.id,
                "kind": "wrangler_session",
                "supported": false,
                "credential_store_accessed": false,
                "remove_argv": ["cfctl", "auth", "logout", profile.id, "--json"],
                "next_step": format!(
                    "Remove this metadata-only legacy profile with `cfctl auth logout {}` and create a supported OAuth or API-token profile; Wrangler authentication is not a cfctl credential lane.",
                    profile.id
                ),
            })
        })
        .collect();
    let oauth_reconsent: Vec<Value> = profiles
        .profiles
        .values()
        .filter(|profile| profile.kind == ProfileKind::OAuth)
        .map(|profile| {
            let reconsent_required = inventory_hash.is_some()
                && profile.oauth_scope_inventory_hash.as_ref() != inventory_hash.as_ref();
            json!({
                "profile": profile.id,
                "granted_scope_count": profile.oauth_scopes.len(),
                "scope_inventory_hash": profile.oauth_scope_inventory_hash,
                "reconsent_required": reconsent_required,
            })
        })
        .collect();
    let catalog = if store.paths().catalog_file().is_file() {
        let catalog = CatalogSnapshot::load(&store.paths().catalog_file())?;
        json!({
            "present": true,
            "schema_hash": catalog.schema_hash,
            "capabilities": catalog.capabilities.len(),
            "stale": catalog_is_stale(store),
        })
    } else {
        json!({"present": false})
    };
    let home = home_directory()?;
    let agents: Vec<_> = AgentKind::all()
        .into_iter()
        .map(|agent| inspect_agent(&home, agent, which::which(agent.program()).is_ok()))
        .collect();
    let running_build = current_build_info();
    let build_identity_healthy = build_identity_is_healthy(&running_build);
    let path_build = inspect_path_build(&running_build);
    let instruction_drift = agents
        .iter()
        .filter(|agent| agent.skill_present && !agent.skill_current)
        .count();
    let healthy = build_identity_healthy && path_build.healthy && instruction_drift == 0;
    Ok(health_envelope(
        "doctor",
        json!({
            "running_build": running_build,
            "build_identity_healthy": build_identity_healthy,
            "path_build": path_build,
            "platform": env::consts::OS,
            "config_dir": store.paths().config_dir,
            "data_dir": store.paths().data_dir,
            "cache_dir": store.paths().cache_dir,
            "delegated_cli_environment": governed_cli_environment_contract(
                &store.paths().cache_dir
            ),
            "catalog": catalog,
            "profile_count": profiles.profiles.len(),
            "current_profile": profiles.current_profile,
            "unsupported_legacy_profiles": unsupported_legacy_profiles,
            "oauth_scope_inventory_hash": inventory_hash,
            "oauth_profiles": oauth_reconsent,
            "platform_secret_store": platform_secret_store_health(store)?,
            "standing_authorities": standing_authorities_health(store)?,
            "evidence_authority": evidence_authority_health(store)?,
            "instruction_drift": instruction_drift,
            "agents": agents,
            "public_oauth": "disabled pending a later explicit OAuth promotion transaction; cfctl.com ownership, site publication, and domain verification do not enable OAuth; use `cfctl auth import-api-token --account <id> --stdin` for the scoped day-to-day lane",
        }),
        healthy,
        "CFCTL_RUNTIME_DRIFT",
        "The source identity, PATH build, or managed agent instructions are not current.",
    ))
}

pub(super) fn version_command() -> Result<ResultEnvelopeV2> {
    Ok(ResultEnvelopeV2::success(
        "version",
        serde_json::to_value(current_build_info())?,
    ))
}

pub(super) fn health_envelope(
    command: &str,
    result: Value,
    healthy: bool,
    code: &str,
    message: &str,
) -> ResultEnvelopeV2 {
    let mut envelope = ResultEnvelopeV2::success(command, result);
    if !healthy {
        envelope.ok = false;
        envelope.verification.state = VerificationState::Failed;
        envelope.error = Some(ErrorV1 {
            code: code.to_owned(),
            message: message.to_owned(),
            next_step: Some(
                "Run ./bootstrap.sh from a checkout clean of tracked and untracked non-ignored files, then synchronize managed agents."
                    .to_owned(),
            ),
        });
    }
    envelope
}

pub(super) async fn update_command(check: bool) -> Result<ResultEnvelopeV2> {
    if !check {
        return Err(CliError::Input(
            "self-update is disabled until a release has signed checksums and attestations; use `cfctl update --check`"
                .to_owned(),
        ));
    }
    let response = http_client()?
        .get("https://api.github.com/repos/rogu3bear/cfctl/releases/latest")
        .header(reqwest::header::USER_AGENT, "cfctl")
        .send()
        .await?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(ResultEnvelopeV2::success(
            "update",
            json!({"current": env!("CARGO_PKG_VERSION"), "published_release": null, "message": "No public GitHub release exists yet."}),
        ));
    }
    let release = response.error_for_status()?.json::<Value>().await?;
    Ok(ResultEnvelopeV2::success(
        "update",
        json!({"current": env!("CARGO_PKG_VERSION"), "latest": release.get("tag_name"), "release_url": release.get("html_url")}),
    ))
}
