//! Protected API-token intake and optional user-token qualification.

use super::auth_commands::{store_api_token_profile, store_imported_api_token};
use super::auth_prompt::read_api_token_prompt;
use super::cloudflare_api::BASE_URL;
use super::plan_commands::observation_attestation;
use super::prelude::{
    AdapterStatus, AuthCredential, CallInput, CapabilityV1, CatalogSnapshot, CliError, DateTime,
    EffectClass, EvidenceClass, Executor, ImportApiTokenArgs, ProfileKind, ProfileMetadata,
    ProfilesConfig, Result, ResultEnvelopeV2, SecretStore, StateStore, Utc, Value,
    VerificationState, json,
};
use super::secret_io::redact_secret_result;
use super::support::{catalog_is_stale, http_client, read_import_secret};

const USER_VERIFY: &str = "user-api-tokens-verify-token";

pub(super) async fn import_api_token(
    store: &StateStore,
    profiles: &mut ProfilesConfig,
    secrets: &dyn SecretStore,
    arguments: &ImportApiTokenArgs,
) -> Result<ResultEnvelopeV2> {
    let executor = if arguments.verify_user {
        Some(Executor::new(http_client()?, BASE_URL)?.with_max_retries(0))
    } else {
        None
    };
    import_api_token_using(store, profiles, secrets, arguments, executor.as_ref()).await
}

async fn import_api_token_using(
    store: &StateStore,
    profiles: &mut ProfilesConfig,
    secrets: &dyn SecretStore,
    arguments: &ImportApiTokenArgs,
    executor: Option<&Executor>,
) -> Result<ResultEnvelopeV2> {
    validate_import_request(profiles, arguments, Utc::now())?;
    let catalog = if arguments.verify_user {
        Some(verification_catalog(store)?)
    } else {
        None
    };
    let token = if arguments.prompt {
        read_api_token_prompt()?
    } else {
        read_import_secret(arguments.stdin, arguments.value_in.as_deref(), "API token")?
    };
    let token = token.trim();
    if token.is_empty() || token.chars().any(char::is_whitespace) {
        return Err(CliError::Input(
            "the supplied API token must be one nonempty value without whitespace".to_owned(),
        ));
    }
    unchanged_profiles(store, profiles)?;
    validate_import_request(profiles, arguments, Utc::now())?;
    let profile = ProfileMetadata::new(
        &arguments.profile,
        ProfileKind::ApiToken,
        Some(arguments.account.trim()),
    );
    let qualification = if let Some(catalog) = &catalog {
        let executor = executor.ok_or_else(|| {
            CliError::Input("user-token verification executor is unavailable".to_owned())
        })?;
        let result = verify_user_token(
            store,
            catalog,
            executor,
            arguments,
            &profile,
            &AuthCredential::Bearer {
                token: token.to_owned(),
            },
        )
        .await?;
        if !result.ok {
            return Ok(result);
        }
        Some(result)
    } else {
        None
    };
    // A prompt or provider read can outlive another actor's profile transition.
    unchanged_profiles(store, profiles)?;
    validate_import_request(profiles, arguments, Utc::now())?;
    if let Some(catalog) = &catalog
        && verification_catalog(store)?.schema_hash != catalog.schema_hash
    {
        return Err(CliError::Input(
            "catalog changed during token verification; no credential was stored".to_owned(),
        ));
    }
    let mut envelope = if arguments.no_select || arguments.verify_user {
        store_api_token_profile(
            store,
            profiles,
            secrets,
            profile,
            token,
            !arguments.no_select,
        )?
    } else {
        store_imported_api_token(
            store,
            profiles,
            secrets,
            &arguments.profile,
            &arguments.account,
            token,
        )?
    };
    if let Some(qualification) = qualification {
        envelope.performed = true;
        envelope.profile_id = qualification.profile_id;
        envelope.account_id = qualification.account_id;
        envelope.capability_id = qualification.capability_id;
        envelope.evidence = qualification.evidence;
        envelope.attestation = qualification.attestation;
        envelope.verification = qualification.verification;
        envelope.result["credential_verification"] =
            qualification.result["credential_verification"].clone();
    }
    Ok(envelope)
}

fn unchanged_profiles(store: &StateStore, expected: &ProfilesConfig) -> Result<()> {
    if serde_json::to_value(ProfilesConfig::load(store)?)? != serde_json::to_value(expected)? {
        return Err(CliError::Input("profile state changed during token intake; no credential was stored; recheck current custody before retrying".to_owned()));
    }
    Ok(())
}

pub(super) fn validate_import_request(
    profiles: &ProfilesConfig,
    arguments: &ImportApiTokenArgs,
    now: DateTime<Utc>,
) -> Result<()> {
    if arguments.profile.trim().is_empty() || arguments.account.trim().is_empty() {
        return Err(CliError::Input(
            "API-token import requires a nonempty profile and account pin".to_owned(),
        ));
    }
    if usize::from(arguments.prompt)
        + usize::from(arguments.stdin)
        + usize::from(arguments.value_in.is_some())
        != 1
    {
        return Err(CliError::Input(
            "choose exactly one token input: --prompt, --stdin or --value-in".to_owned(),
        ));
    }
    if arguments.create_only
        && (profiles.profiles.contains_key(&arguments.profile)
            || profiles.pending_logins.contains_key(&arguments.profile))
    {
        return Err(CliError::Input("--create-only profile already exists or has a pending login; no token was read or replaced".to_owned()));
    }
    if let Some(cutoff) = arguments.expires_before
        && (!arguments.verify_user || cutoff <= now)
    {
        return Err(CliError::Input("--expires-before requires --verify-user and a future RFC3339 cutoff; no credential was stored".to_owned()));
    }
    Ok(())
}

fn verification_catalog(store: &StateStore) -> Result<CatalogSnapshot> {
    if !store.paths().catalog_file().is_file() || catalog_is_stale(store) {
        return Err(CliError::Input("user-token verification requires a current catalog; refresh it explicitly before importing; no ambient credential was used".to_owned()));
    }
    let catalog = CatalogSnapshot::load(&store.paths().catalog_file())?;
    user_verify_capability(&catalog)?;
    Ok(catalog)
}

fn user_verify_capability(catalog: &CatalogSnapshot) -> Result<&CapabilityV1> {
    catalog.get(USER_VERIFY).filter(|capability| {
        capability.method == "GET" && capability.path == "/user/tokens/verify"
            && capability.account_scope == "user" && capability.effect == EffectClass::ReadOnly
            && !capability.mutating && capability.selectors.is_empty()
            && matches!(capability.adapter_status, AdapterStatus::Native | AdapterStatus::DynamicApi)
            && capability.blocked_reason.is_none()
    }).ok_or_else(|| CliError::Input("current catalog does not provide the expected read-only user token verification contract; no credential was stored".to_owned()))
}

pub(super) async fn verify_user_token(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    executor: &Executor,
    arguments: &ImportApiTokenArgs,
    profile: &ProfileMetadata,
    credential: &AuthCredential,
) -> Result<ResultEnvelopeV2> {
    let capability = user_verify_capability(catalog)?;
    let attestation = observation_attestation(store, capability)?;
    let store = store.with_observation_attestation(&attestation);
    let response = executor
        .execute_read(capability, &CallInput::default(), credential)
        .await?;
    // Treat the token endpoint's result as secret-bearing even when the
    // verification schema currently promises identity and lifecycle fields only.
    let sanitized = redact_secret_result(&serde_json::to_value(&response)?);
    let evidence = store.write_observation_evidence(
        EvidenceClass::LiveRead,
        &json!({
            "capability_id": USER_VERIFY, "catalog_hash": catalog.schema_hash,
            "profile_id": profile.id, "credential_generation_id": profile.credential_generation_id,
            "account_id": profile.account_id, "response": sanitized,
            "credential_installed": false,
        }),
    )?;
    let problem = if !response.success || response.status != 200 {
        Some("the supplied token did not verify as an active user-owned API token".to_owned())
    } else {
        user_token_problem(&response.result, arguments.expires_before, Utc::now())
    };
    let mut envelope = if let Some(problem) = problem {
        ResultEnvelopeV2::failure(
            "auth import-api-token",
            "CFCTL_USER_TOKEN_REJECTED",
            &problem,
            Some(
                "No credential was stored or selected. Create a user token under My Profile > API Tokens with the required account permissions and expiry, then import it through protected input.",
            ),
        )
    } else {
        ResultEnvelopeV2::success(
            "auth import-api-token",
            json!({"credential_verification": {
                "owner": "user", "id": response.result["id"], "status": response.result["status"],
                "expires_on": response.result["expires_on"], "observed_at": Utc::now(),
                "catalog_hash": catalog.schema_hash, "permissions_verified": false,
                "account_membership_verified": false,
            }}),
        )
    };
    envelope.performed = true;
    envelope.attestation = Some(attestation);
    envelope.profile_id = Some(profile.id.clone());
    envelope.account_id.clone_from(&profile.account_id);
    envelope.capability_id = Some(USER_VERIFY.to_owned());
    envelope.verification.state = if envelope.ok {
        VerificationState::Passed
    } else {
        VerificationState::Failed
    };
    envelope.verification.basis = Some("user token identity/status and requested expiry bound; account membership and permission policy require their own evidence".to_owned());
    envelope.evidence.push(evidence);
    Ok(envelope)
}

pub(super) fn user_token_problem(
    result: &Value,
    cutoff: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Option<String> {
    if result.get("status").and_then(Value::as_str) != Some("active")
        || result
            .get("id")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Some("provider did not return an active user token with an identity".to_owned());
    }
    let expiration = match result.get("expires_on").filter(|value| !value.is_null()) {
        Some(value) => match value
            .as_str()
            .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        {
            Some(value) => Some(value.with_timezone(&Utc)),
            None => return Some("provider returned an invalid token expiry".to_owned()),
        },
        None => None,
    };
    if expiration.is_some_and(|expiration| expiration <= now) {
        return Some("the user token is already expired".to_owned());
    }
    if let Some(cutoff) = cutoff
        && (cutoff <= now || expiration.is_none_or(|expiration| expiration > cutoff))
    {
        return Some("provider token expiry is absent or exceeds --expires-before".to_owned());
    }
    if let Some(value) = result.get("not_before").filter(|value| !value.is_null()) {
        let start = value
            .as_str()
            .and_then(|value| DateTime::parse_from_rfc3339(value).ok());
        if start.is_none_or(|start| start > now) {
            return Some(
                "provider token activation time is invalid or still in the future".to_owned(),
            );
        }
    }
    None
}

#[cfg(test)]
mod tests;
