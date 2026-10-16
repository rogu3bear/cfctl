//! Authenticated recovery joins shared only by the three mutating D1 consumers.
use super::prelude::{
    CallInput, CatalogSnapshot, CliError, OperationalProofOutcomeV1, Result, StateStore,
};
use cfctl_core::hash_value;
use chrono::{Duration as ChronoDuration, Utc};
use serde_json::{Map, Value, json};

#[expect(
    clippy::too_many_arguments,
    reason = "the recovery proof is valid only when target, catalog, profile, account, credential generation, freshness bound, and observation time are evaluated together"
)]
pub(super) fn fresh_recovery_proof(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    input: &CallInput,
    profile_id: &str,
    account_id: &str,
    generation: &str,
    max_age_seconds: u64,
    now: chrono::DateTime<Utc>,
) -> Result<Value> {
    let database_id = input
        .selectors
        .get("database_id")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("workspace D1 migration requires database_id".to_owned()))?;
    let bookmark_input = CallInput {
        selectors: json!({"account_id": account_id, "database_id": database_id}),
        query: json!({}),
        ..CallInput::default()
    };
    let input_hash = hash_value(&serde_json::to_value(bookmark_input)?)?;
    let floor = now - ChronoDuration::seconds(i64::try_from(max_age_seconds).unwrap_or(i64::MAX));
    let matches = store
        .list_operational_proofs()?
        .into_iter()
        .filter(|proof| {
            proof.capability_id == "d1-time-travel-get-bookmark"
                && proof.catalog_hash == catalog.schema_hash
                && proof.input_hash == input_hash
                && proof.profile_id.as_deref() == Some(profile_id)
                && proof.account_id.as_deref() == Some(account_id)
                && proof.credential_generation_id.as_deref() == Some(generation)
                && proof.outcome == OperationalProofOutcomeV1::Succeeded
                && proof.observed_at >= floor
                && proof.observed_at < now
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(CliError::Input(
            "workspace D1 migration requires exactly one fresh successful time-travel bookmark proof bound to the target, catalog, profile, account, and credential generation"
                .to_owned(),
        ));
    }
    let proof = &matches[0];
    let evidence = store.read_evidence_value(&proof.evidence.content_hash)?;
    let bookmark = evidence
        .pointer("/result/bookmark")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input("recovery evidence omitted the exact bookmark".to_owned())
        })?;
    if evidence.get("status").and_then(Value::as_u64) != Some(200)
        || evidence.get("success").and_then(Value::as_bool) != Some(true)
    {
        return Err(CliError::Input(
            "recovery evidence does not prove a successful bookmark read".to_owned(),
        ));
    }
    Ok(json!({
        "capability_id": proof.capability_id,
        "observed_at": proof.observed_at,
        "evidence_hash": proof.evidence.content_hash,
        "bookmark": bookmark,
        "bookmark_hash": hash_value(&Value::String(bookmark.to_owned()))?,
        "catalog_hash": proof.catalog_hash,
        "input_hash": proof.input_hash,
        "profile_id": profile_id,
        "account_id": account_id,
        "credential_generation_id": generation,
    }))
}

pub(super) fn validate_recovery_target(
    store: &StateStore,
    target: &Map<String, Value>,
    catalog_hash: &str,
    max_age_seconds: u64,
    now: chrono::DateTime<Utc>,
) -> Result<()> {
    let recovery = validate_recovery_target_identity(store, target, catalog_hash, now)?;
    let observed_at = recovery
        .get("observed_at")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("workspace D1 recovery time is missing".to_owned()))?
        .parse::<chrono::DateTime<Utc>>()
        .map_err(|_| CliError::Input("workspace D1 recovery time is invalid".to_owned()))?;
    let age = now.signed_duration_since(observed_at);
    if age > ChronoDuration::seconds(i64::try_from(max_age_seconds).unwrap_or(i64::MAX)) {
        return Err(CliError::Input(
            "workspace D1 recovery bookmark is no longer fresh; create a new plan".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn validate_recovery_target_identity<'a>(
    store: &StateStore,
    target: &'a Map<String, Value>,
    catalog_hash: &str,
    now: chrono::DateTime<Utc>,
) -> Result<&'a Map<String, Value>> {
    let recovery = target
        .get("recovery")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CliError::Input("workspace D1 plan omitted recovery authority".to_owned())
        })?;
    let observed_at = recovery
        .get("observed_at")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("workspace D1 recovery time is missing".to_owned()))?
        .parse::<chrono::DateTime<Utc>>()
        .map_err(|_| CliError::Input("workspace D1 recovery time is invalid".to_owned()))?;
    if now.signed_duration_since(observed_at) < ChronoDuration::zero() {
        return Err(CliError::Input(
            "workspace D1 recovery bookmark observation is in the future".to_owned(),
        ));
    }
    let evidence_hash = recovery_string(recovery, "evidence_hash")?;
    require_target_string(recovery, "catalog_hash", catalog_hash)?;
    require_target_string(recovery, "profile_id", target_string(target, "profile_id")?)?;
    require_target_string(recovery, "account_id", target_string(target, "account_id")?)?;
    require_target_string(
        recovery,
        "credential_generation_id",
        target_string(target, "credential_generation_id")?,
    )?;
    let evidence = store.read_evidence_value(evidence_hash)?;
    let bookmark = evidence
        .pointer("/result/bookmark")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("recovery evidence omitted bookmark readback".to_owned()))?;
    require_target_string(recovery, "bookmark", bookmark)?;
    require_target_string(
        recovery,
        "bookmark_hash",
        &hash_value(&Value::String(bookmark.to_owned()))?,
    )?;
    Ok(recovery)
}

pub(super) fn target_string<'a>(target: &'a Map<String, Value>, field: &str) -> Result<&'a str> {
    target
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CliError::Input(format!("workspace D1 target omitted {field}")))
}

pub(super) fn recovery_string<'a>(target: &'a Map<String, Value>, field: &str) -> Result<&'a str> {
    target_string(target, field)
}

pub(super) fn require_target_string(
    target: &Map<String, Value>,
    field: &str,
    expected: &str,
) -> Result<()> {
    if target_string(target, field)? == expected {
        Ok(())
    } else {
        Err(CliError::Input(format!(
            "workspace D1 target {field} drifted; create a new plan"
        )))
    }
}
