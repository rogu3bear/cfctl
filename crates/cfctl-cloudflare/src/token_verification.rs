//! Live readback for API token create, roll, and revoke.
//!
//! After `plans run` of `keys mint`, `verification.passed` means GET token
//! details reports the created id, `status=active`, the exact planned
//! permission-group ID set, and the planned account resource. The token
//! VALUE is never kept on the verification readback.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::{CallInput, CloudflareError, CloudflareResponseV1, Result};

const CREATE_STRATEGY: &str = "api_token_details_match_created_id_and_active_status";
const ROLL_STRATEGY: &str = "api_token_details_report_active_after_value_roll";
const REVOKE_STRATEGY: &str = "api_token_details_returns_not_found_after_revoke";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PlannedTokenPolicySet {
    group_ids: BTreeSet<String>,
    resources: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum TokenVerificationExpectation {
    Active,
    Created(PlannedTokenPolicySet),
    Revoked,
}

pub(super) fn token_verification_target(
    strategy: &str,
    input: &CallInput,
    apply_response: &CloudflareResponseV1,
) -> Result<(String, TokenVerificationExpectation)> {
    match strategy {
        CREATE_STRATEGY => {
            let token_id = apply_response
                .result
                .get("id")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| {
                    CloudflareError::MissingVerificationTarget(
                        "created token id is absent".to_owned(),
                    )
                })?;
            let planned = planned_token_policy_set(input)?;
            Ok((token_id, TokenVerificationExpectation::Created(planned)))
        }
        ROLL_STRATEGY => {
            planned_token_id(input).map(|token_id| (token_id, TokenVerificationExpectation::Active))
        }
        REVOKE_STRATEGY => planned_token_id(input)
            .map(|token_id| (token_id, TokenVerificationExpectation::Revoked)),
        other => Err(CloudflareError::UnsupportedVerificationStrategy(
            other.to_owned(),
        )),
    }
}

pub(super) fn evaluate_token_readback(
    expectation: TokenVerificationExpectation,
    token_id: &str,
    readback: &CloudflareResponseV1,
) -> (bool, String) {
    match expectation {
        TokenVerificationExpectation::Active => evaluate_active_id_and_status(token_id, readback),
        TokenVerificationExpectation::Created(planned) => {
            evaluate_created_token_readback(token_id, &planned, readback)
        }
        TokenVerificationExpectation::Revoked => {
            let passed = readback.status == 404 && !readback.success;
            let basis = if passed {
                format!("live token details returned not found for revoked token `{token_id}`")
            } else {
                format!(
                    "revoked token `{token_id}` still produced HTTP {} with success={}",
                    readback.status, readback.success
                )
            };
            (passed, basis)
        }
    }
}

pub(super) fn redact_token_secret_fields(response: &mut CloudflareResponseV1) {
    if let Some(object) = response.result.as_object_mut() {
        object.remove("value");
        object.remove("token");
    }
}

fn evaluate_created_token_readback(
    token_id: &str,
    planned: &PlannedTokenPolicySet,
    readback: &CloudflareResponseV1,
) -> (bool, String) {
    let (identity_passed, identity_basis) = evaluate_active_id_and_status(token_id, readback);
    if !identity_passed {
        return (false, identity_basis);
    }
    let observed = match token_policy_set_from_value(
        readback.result.get("policies").unwrap_or(&Value::Null),
        "live token details",
    ) {
        Ok(observed) => observed,
        Err(error) => {
            return (
                false,
                format!(
                    "live token details for `{token_id}` were active but policies were not comparable: {error}"
                ),
            );
        }
    };
    if observed.group_ids != planned.group_ids {
        return (
            false,
            format!(
                "live token details for `{token_id}` were active but permission group IDs did not match the planned set"
            ),
        );
    }
    if observed.resources != planned.resources {
        return (
            false,
            format!(
                "live token details for `{token_id}` were active but the account resource did not match the planned resource"
            ),
        );
    }
    (
        true,
        format!(
            "live token details matched `{token_id}` with active status, planned permission groups, and planned account resource"
        ),
    )
}

fn evaluate_active_id_and_status(
    token_id: &str,
    readback: &CloudflareResponseV1,
) -> (bool, String) {
    let readback_id = readback.result.get("id").and_then(Value::as_str);
    let readback_status = readback.result.get("status").and_then(Value::as_str);
    let passed =
        readback.success && readback_id == Some(token_id) && readback_status == Some("active");
    let basis = if passed {
        format!("live token details matched `{token_id}` with active status")
    } else {
        format!(
            "live token details did not match active token `{token_id}` (status {}, id {})",
            readback_status.unwrap_or("missing"),
            readback_id.unwrap_or("missing")
        )
    };
    (passed, basis)
}

fn planned_token_id(input: &CallInput) -> Result<String> {
    input
        .selectors
        .get("token_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "planned token_id selector is absent".to_owned(),
            )
        })
}

fn planned_token_policy_set(input: &CallInput) -> Result<PlannedTokenPolicySet> {
    let policies = input
        .body
        .as_ref()
        .and_then(|body| body.get("policies"))
        .ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "planned token policies are absent".to_owned(),
            )
        })?;
    token_policy_set_from_value(policies, "planned token policies")
}

fn token_policy_set_from_value(policies: &Value, source: &str) -> Result<PlannedTokenPolicySet> {
    let policies = policies
        .as_array()
        .filter(|items| !items.is_empty())
        .ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(format!("{source} are absent"))
        })?;
    let mut group_ids = BTreeSet::new();
    let mut resources = BTreeMap::new();
    for policy in policies {
        let groups = policy
            .get("permission_groups")
            .and_then(Value::as_array)
            .filter(|groups| !groups.is_empty())
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(format!(
                    "{source} contain a policy without permission groups"
                ))
            })?;
        for group in groups {
            let id = group
                .get("id")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|id| !id.is_empty())
                .ok_or_else(|| {
                    CloudflareError::MissingVerificationTarget(format!(
                        "{source} contain a permission group without an ID"
                    ))
                })?;
            group_ids.insert(id.to_owned());
        }
        let resource_object = policy
            .get("resources")
            .and_then(Value::as_object)
            .filter(|resources| !resources.is_empty())
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(format!(
                    "{source} contain a policy without an account resource"
                ))
            })?;
        for (key, value) in resource_object {
            let access = value
                .as_str()
                .map(str::trim)
                .filter(|access| !access.is_empty())
                .ok_or_else(|| {
                    CloudflareError::MissingVerificationTarget(format!(
                        "{source} contain a non-string resource grant"
                    ))
                })?;
            if let Some(existing) = resources.insert(key.clone(), access.to_owned())
                && existing != access
            {
                return Err(CloudflareError::MissingVerificationTarget(format!(
                    "{source} grant conflicting access on `{key}`"
                )));
            }
        }
    }
    Ok(PlannedTokenPolicySet {
        group_ids,
        resources,
    })
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "unit tests bind mint readback with explicit fixtures"
)]
mod tests {
    use super::*;
    use serde_json::json;

    const GROUP_READ: &str = "1a71c399035b4950a1bd1466bbe4f420";
    const GROUP_WRITE: &str = "e086da7e2179491d91ee5f35b3ca210a";
    const ACCOUNT_RESOURCE: &str = "com.cloudflare.api.account.account-1";

    fn planned_body() -> Value {
        json!({
            "name": "cfctl-site-release-x",
            "policies": [{
                "effect": "allow",
                "permission_groups": [{"id": GROUP_READ}, {"id": GROUP_WRITE}],
                "resources": {ACCOUNT_RESOURCE: "*"}
            }]
        })
    }

    fn create_input() -> CallInput {
        CallInput {
            selectors: json!({"account_id": "account-1"}),
            query: json!({}),
            body: Some(planned_body()),
            ..CallInput::default()
        }
    }

    fn apply_created() -> CloudflareResponseV1 {
        CloudflareResponseV1 {
            status: 200,
            success: true,
            result: json!({"id": "token-1", "status": "active", "value": "one-time-secret"}),
            errors: Vec::new(),
            result_info: None,
            etag: None,
            cf_ray: None,
        }
    }

    fn details(policies: Value, extra: Value) -> CloudflareResponseV1 {
        let mut result = json!({
            "id": "token-1",
            "status": "active",
            "policies": policies
        });
        if let (Some(object), Some(extra_object)) = (result.as_object_mut(), extra.as_object()) {
            for (key, value) in extra_object {
                object.insert(key.clone(), value.clone());
            }
        }
        CloudflareResponseV1 {
            status: 200,
            success: true,
            result,
            errors: Vec::new(),
            result_info: None,
            etag: None,
            cf_ray: None,
        }
    }

    #[test]
    fn created_token_readback_fails_when_active_but_permission_groups_differ() {
        let (token_id, expectation) =
            token_verification_target(CREATE_STRATEGY, &create_input(), &apply_created())
                .expect("create target");
        let readback = details(
            json!([{
                "effect": "allow",
                "permission_groups": [{"id": GROUP_READ, "name": "Workers Scripts Read"}],
                "resources": {ACCOUNT_RESOURCE: "*"}
            }]),
            json!({}),
        );
        let (passed, basis) = evaluate_token_readback(expectation, &token_id, &readback);
        assert!(!passed, "{basis}");
        assert!(basis.contains("permission group IDs"), "{basis}");
        assert!(!basis.contains("one-time-secret"), "{basis}");
    }

    #[test]
    fn created_token_readback_fails_when_active_but_account_resource_differs() {
        let (token_id, expectation) =
            token_verification_target(CREATE_STRATEGY, &create_input(), &apply_created())
                .expect("create target");
        let readback = details(
            json!([{
                "effect": "allow",
                "permission_groups": [
                    {"id": GROUP_WRITE, "name": "Workers Scripts Write"},
                    {"id": GROUP_READ, "name": "Workers Scripts Read"}
                ],
                "resources": {"com.cloudflare.api.account.*": "*"}
            }]),
            json!({}),
        );
        let (passed, basis) = evaluate_token_readback(expectation, &token_id, &readback);
        assert!(!passed, "{basis}");
        assert!(basis.contains("account resource"), "{basis}");
    }

    #[test]
    fn created_token_readback_passes_on_id_active_groups_and_resource() {
        let (token_id, expectation) =
            token_verification_target(CREATE_STRATEGY, &create_input(), &apply_created())
                .expect("create target");
        let mut readback = details(
            json!([{
                "id": "policy-live",
                "effect": "allow",
                "permission_groups": [
                    {"id": GROUP_WRITE, "name": "Workers Scripts Write"},
                    {"id": GROUP_READ, "name": "Workers Scripts Read"}
                ],
                "resources": {ACCOUNT_RESOURCE: "*"}
            }]),
            json!({"value": "should-not-survive"}),
        );
        redact_token_secret_fields(&mut readback);
        let (passed, basis) = evaluate_token_readback(expectation, &token_id, &readback);
        assert!(passed, "{basis}");
        assert_eq!(token_id, "token-1");
        assert!(readback.result.get("value").is_none());
        assert!(!basis.contains("should-not-survive"), "{basis}");
    }

    #[test]
    fn create_verification_requires_planned_policies() {
        let input = CallInput {
            selectors: json!({"account_id": "account-1"}),
            query: json!({}),
            body: Some(json!({"name": "empty"})),
            ..CallInput::default()
        };
        let error = token_verification_target(CREATE_STRATEGY, &input, &apply_created())
            .expect_err("create without planned policies fails closed");
        assert!(
            error.to_string().contains("planned token policies"),
            "{error}"
        );
    }
}
