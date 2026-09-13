//! Optional OAuth consent scopes stay within the explicitly selected grants.

use super::{CallInput, CapabilityV1, CloudflareError, Result, Value};

pub(super) fn validate_request(capability: &CapabilityV1, input: &CallInput) -> Result<()> {
    if !matches!(
        (
            capability.id.as_str(),
            capability.method.as_str(),
            capability.path.as_str()
        ),
        (
            "oauth-clients-create",
            "POST",
            "/accounts/{account_id}/oauth_clients"
        ) | (
            "oauth-clients-update",
            "PATCH",
            "/accounts/{account_id}/oauth_clients/{oauth_client_id}"
        )
    ) || capability.product != "OAuth Clients"
    {
        return Ok(());
    }
    if let Some(body) = input.body.as_ref()
        && let Some(optional) = body.get("optional_scopes")
    {
        // Nonempty optional scopes require the chosen scopes in this request.
        // The CLI also checks the merged, snapshot-bound state for PATCH.
        validate_oauth_optional_scope_selection(body.get("scopes"), optional)?;
    }
    Ok(())
}

/// Validate the declared optional scopes against a request or merged snapshot.
pub fn validate_oauth_optional_scope_selection(
    scopes: Option<&Value>,
    optional: &Value,
) -> Result<()> {
    let invalid = || {
        CloudflareError::InvalidRequestBody(
        "OAuth optional_scopes must be an array of non-protocol scopes also present in the explicit scopes array; openid, offline and offline_access cannot be optional".to_owned(),
    )
    };
    let optional = optional.as_array().ok_or_else(invalid)?;
    if optional.is_empty() {
        return Ok(());
    }
    let scopes = scopes.and_then(Value::as_array).ok_or_else(invalid)?;
    if optional.iter().any(|value| {
        value.as_str().is_none_or(|scope| {
            matches!(scope, "openid" | "offline" | "offline_access") || !scopes.contains(value)
        })
    }) {
        return Err(invalid());
    }
    Ok(())
}
