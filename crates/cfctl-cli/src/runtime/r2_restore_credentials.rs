//! Current effect credentials are independent of historical capture custody.
use super::prelude::{
    CallInput, CatalogSnapshot, CliError, EvidenceClass, EvidenceV1, Executor, Result, StateStore,
    Value, json,
};
use cfctl_auth::{AuthCredential, ProfileKind, ProfileMetadata};
use cfctl_core::{
    OperationalProofOutcomeV1, hash_value,
    r2_restore::{
        RestoreRequestV1, TOKEN_POLICY_PATH as POLICY_PATH, TOKEN_VERIFY_PATH as VERIFY_PATH,
        token_read_matches,
    },
};
use chrono::{DateTime, Duration, Utc};

fn rejected() -> CliError {
    CliError::Input("private restore requires matching authenticated current account-token identity, policy, account and credential generation evidence; no credential value was disclosed".into())
}

pub(super) fn qualify(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    profile: &ProfileMetadata,
    account: &str,
    request: &RestoreRequestV1,
    window_end: DateTime<Utc>,
) -> Result<String> {
    qualify_policy(
        store,
        catalog,
        profile,
        account,
        [
            &request.token_verification_evidence_hash,
            &request.token_policy_evidence_hash,
        ],
        window_end,
        ReadPolicy::RestoreWrite,
    )
}

pub(super) fn qualify_capture(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    profile: &ProfileMetadata,
    account: &str,
    request: &cfctl_core::r2_recovery::CaptureRequestV2,
) -> Result<String> {
    request.validate(Utc::now()).map_err(|_| rejected())?;
    qualify_policy(
        store,
        catalog,
        profile,
        account,
        [
            &request.token_verification_evidence_hash,
            &request.token_policy_evidence_hash,
        ],
        request.window.expires_at,
        ReadPolicy::CaptureRead,
    )
}

enum ReadPolicy {
    RestoreWrite,
    CaptureRead,
}

fn qualify_policy(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    profile: &ProfileMetadata,
    account: &str,
    evidence: [&str; 2],
    window_end: DateTime<Utc>,
    required: ReadPolicy,
) -> Result<String> {
    check_profile(profile, account)?;
    let now = Utc::now();
    let input = CallInput {
        selectors: json!({"account_id":account}),
        query: json!({}),
        ..CallInput::default()
    };
    let verified = joined_read(
        store,
        catalog,
        profile,
        evidence[0],
        VERIFY_PATH,
        &input,
        now,
    )?;
    let token_id = active_token(&verified, window_end)?;
    let policy_input = CallInput {
        selectors: json!({"account_id":account,"token_id":token_id}),
        query: json!({}),
        ..CallInput::default()
    };
    let policy = joined_read(
        store,
        catalog,
        profile,
        evidence[1],
        POLICY_PATH,
        &policy_input,
        now,
    )?;
    if policy["id"] != token_id || active_token(&policy, window_end)? != token_id {
        return Err(rejected());
    }
    let policies = policy["policies"].as_array().ok_or_else(rejected)?;
    if matches!(required, ReadPolicy::CaptureRead)
        && policies.iter().any(|p| {
            p.as_object().is_none_or(|map| {
                map.keys().any(|key| {
                    !matches!(
                        key.as_str(),
                        "id" | "effect" | "resources" | "permission_groups"
                    )
                })
            })
        })
    {
        return Err(rejected());
    }
    if policies.iter().any(|p| p["effect"] != "allow") {
        return Err(rejected());
    }
    // Only supported account-owned allow policies. Capture accepts read without
    // weakening restore's write requirement or guessing bucket/user policies.
    let account_resource = format!("com.cloudflare.api.account.{account}");
    let allowed = policies.iter().any(|p| {
        p["resources"]
            .get(&account_resource)
            .is_some_and(|scope| scope == "*")
            && p["permission_groups"].as_array().is_some_and(|groups| {
                groups.iter().any(|group| {
                    group["name"] == "Workers R2 Storage Write"
                        || (matches!(required, ReadPolicy::CaptureRead)
                            && group["name"] == "Workers R2 Storage Read")
                })
            })
    });
    if !allowed {
        return Err(rejected());
    }
    Ok(token_id)
}

pub(super) fn check_profile(profile: &ProfileMetadata, account: &str) -> Result<()> {
    if profile.kind != ProfileKind::ApiToken
        || profile.account_id.as_deref() != Some(account)
        || profile
            .credential_generation_id
            .as_deref()
            .is_none_or(str::is_empty)
    {
        return Err(rejected());
    }
    Ok(())
}

fn joined_read(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    profile: &ProfileMetadata,
    evidence_hash: &str,
    path: &str,
    input: &CallInput,
    now: DateTime<Utc>,
) -> Result<Value> {
    let encoded = store.read_evidence_value(evidence_hash)?;
    if encoded["status"] != 200 || encoded["success"] != true {
        return Err(rejected());
    }
    let input_hash = hash_value(&serde_json::to_value(input)?)?;
    let build_hash = hash_value(&serde_json::to_value(
        crate::build_identity::current_build_info(),
    )?)?;
    let matches = store
        .list_operational_proofs()?
        .into_iter()
        .filter(|proof| {
            proof.evidence.content_hash == evidence_hash
                && proof.evidence.class == EvidenceClass::LiveRead
                && proof.outcome == OperationalProofOutcomeV1::Succeeded
                && proof.input_hash == input_hash
                && proof.profile_id.as_deref() == Some(profile.id.as_str())
                && proof.account_id == profile.account_id
                && proof.credential_generation_id == profile.credential_generation_id
                && proof.catalog_hash == catalog.schema_hash
                && proof.build_identity_hash.as_deref() == Some(build_hash.as_str())
                && proof.observed_at <= now
                && proof.observed_at >= now - Duration::minutes(5)
                && proof.evidence.generated_at <= now
                && catalog
                    .get(&proof.capability_id)
                    .is_some_and(|cap| token_read_matches(cap, path))
        })
        .count();
    if matches != 1 {
        return Err(rejected());
    }
    Ok(encoded["result"].clone())
}

fn active_token(value: &Value, required_until: DateTime<Utc>) -> Result<String> {
    let id = value["id"]
        .as_str()
        .filter(|s| {
            s.len() == 32
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        .ok_or_else(rejected)?;
    if value["status"] != "active" {
        return Err(rejected());
    }
    for (field, is_expiry) in [("expires_on", true), ("not_before", false)] {
        if let Some(v) = value.get(field).filter(|v| !v.is_null()) {
            let date = DateTime::parse_from_rfc3339(v.as_str().ok_or_else(rejected)?)
                .map_err(|_| rejected())?
                .with_timezone(&Utc);
            if (is_expiry && date <= required_until) || (!is_expiry && date > Utc::now()) {
                return Err(rejected());
            }
        }
    }
    Ok(id.to_owned())
}

/// Rectification observes the old exact target under a fresh current read
/// credential. It neither renews the old write approval nor replays its PUT.
pub(super) async fn qualify_read_only(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    profile: &ProfileMetadata,
    account: &str,
    credential: &AuthCredential,
) -> Result<(String, EvidenceV1)> {
    check_profile(profile, account)?;
    let caps = catalog
        .capabilities
        .values()
        .filter(|cap| token_read_matches(cap, VERIFY_PATH))
        .collect::<Vec<_>>();
    if caps.len() != 1 {
        return Err(rejected());
    }
    let executor = Executor::new(
        super::support::private_capture_http_client()?,
        super::cloudflare_api::BASE_URL,
    )?
    .with_max_retries(0);
    let response = executor
        .execute_r2_restore_token_read(caps[0], account, credential)
        .await?;
    let safe_response = super::secret_io::redact_secret_result(&serde_json::to_value(&response)?);
    let evidence = store.write_observation_evidence(EvidenceClass::LiveRead, &safe_response)?;
    if response.status != 200 || !response.success {
        return Err(rejected());
    }
    let token_id = active_token(&response.result, Utc::now())?;
    Ok((token_id, evidence))
}
