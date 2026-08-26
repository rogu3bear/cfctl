use serde_json::{Map, Value};

use super::{CliError, Result, digest, exact_keys, hash_json, timestamp};

const SOURCE_KEYS: &[&str] = &[
    "schema_version",
    "kind",
    "performed",
    "body_free",
    "route_ref_sha256",
    "domain_sha256",
    "public_role_identity_sha256",
    "policy_sha256",
    "provider_accepted_at",
    "observed_at",
    "correlation_sha256",
    "match_count",
    "opaque_relay_recipient_sha256",
    "selection_basis",
    "subject_used",
    "body_used",
    "private_identity_retained",
];

pub(super) fn validate(receipt: &Map<String, Value>) -> Result<()> {
    exact_keys(receipt, SOURCE_KEYS)?;
    if receipt.get("schema_version").and_then(Value::as_u64) != Some(2)
        || receipt.get("kind").and_then(Value::as_str) != Some("maildesk_apple_mail_inbox_receipt")
        || receipt.get("performed").and_then(Value::as_bool) != Some(true)
        || receipt.get("body_free").and_then(Value::as_bool) != Some(true)
        || receipt.get("match_count").and_then(Value::as_u64) != Some(1)
        || receipt.get("selection_basis").and_then(Value::as_str)
            != Some("provider_acceptance_interval_and_public_role_identity")
        || receipt.get("subject_used").and_then(Value::as_bool) != Some(false)
        || receipt.get("body_used").and_then(Value::as_bool) != Some(false)
        || receipt
            .get("private_identity_retained")
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err(CliError::Input(
            "reply-admission Apple Mail source receipt is not one body-free observation".to_owned(),
        ));
    }
    for key in [
        "route_ref_sha256",
        "domain_sha256",
        "public_role_identity_sha256",
        "policy_sha256",
        "correlation_sha256",
        "opaque_relay_recipient_sha256",
    ] {
        digest(receipt, key)?;
    }
    let provider_accepted_at =
        timestamp(receipt.get("provider_accepted_at"), "provider_accepted_at")?;
    let observed_at = timestamp(receipt.get("observed_at"), "observed_at")?;
    if observed_at < provider_accepted_at {
        return Err(CliError::Input(
            "reply-admission Apple Mail source receipt chronology is invalid".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn validate_projection_binding(
    source_prerequisites: &Map<String, Value>,
    projection: &Map<String, Value>,
) -> Result<()> {
    let projected = projection
        .get("prerequisites")
        .and_then(Value::as_object)
        .ok_or_else(|| CliError::Input("reply-admission prerequisites are missing".to_owned()))?;
    let source = source_prerequisites
        .get("apple_mail_inbox")
        .ok_or_else(|| {
            CliError::Input("reply-admission Apple Mail source receipt is missing".to_owned())
        })?;
    let projected_receipt = projected
        .get("apple_mail_inbox")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CliError::Input("reply-admission `apple_mail_inbox` receipt missing".to_owned())
        })?;
    if projected_receipt
        .get("receipt_sha256")
        .and_then(Value::as_str)
        != Some(hash_json(source).as_str())
    {
        return Err(CliError::Input(
            "reply-admission Apple Mail source receipt digest binding mismatch".to_owned(),
        ));
    }
    Ok(())
}
