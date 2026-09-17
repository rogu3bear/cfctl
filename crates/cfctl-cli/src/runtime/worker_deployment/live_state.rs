use cfctl_cloudflare::CloudflareResponseV1;
use cfctl_core::{PlanV1, WORKER_DEPLOYMENT_PLAN_CAPABILITY_ID, hash_value, redact_json};
use serde_json::{Value, json};

use super::{
    CliError, DEPLOYMENTS_CAPABILITY_ID, DEPLOYMENTS_PATH, NOT_FOUND_ERROR_CODE,
    ROLLBACK_CAPABILITY_ID, SETTINGS_CAPABILITY_ID, SETTINGS_PATH, VERSION_CAPABILITY_ID,
    VERSION_PATH, service_name, target,
};

pub(in crate::runtime) fn apply_state_responses(
    account_id: &str,
    service_name: &str,
    settings: &CloudflareResponseV1,
    deployments: Option<&CloudflareResponseV1>,
    version: Option<&CloudflareResponseV1>,
    require_singular_active: bool,
) -> Result<Value, CliError> {
    let exact_not_found = settings.status == 404
        && !settings.success
        && settings.result.is_null()
        && settings.errors.len() == 1
        && settings.errors[0].code == Some(NOT_FOUND_ERROR_CODE);
    if exact_not_found {
        if deployments.is_some() || version.is_some() {
            return Err(CliError::Input(
                "absent Worker state must not carry a deployments or version-detail response"
                    .to_owned(),
            ));
        }
        if require_singular_active {
            return Err(CliError::Input(
                "Worker deployment planning requires one prior active version for rollback; the exact Worker does not exist"
                    .to_owned(),
            ));
        }
        return Ok(json!({
            "schema_version": 1,
            "source_capability_id": SETTINGS_CAPABILITY_ID,
            "source_path": SETTINGS_PATH,
            "account_id": account_id,
            "service_name": service_name,
            "http_status": 404,
            "exists": false,
        }));
    }
    let Some(deployments) = deployments else {
        return Err(CliError::Input(
            "existing Worker state requires its exact deployments read".to_owned(),
        ));
    };
    if settings.success
        && (200..300).contains(&settings.status)
        && deployments.success
        && (200..300).contains(&deployments.status)
    {
        let mut receipt = json!({
            "schema_version": 1,
            "source_capability_id": SETTINGS_CAPABILITY_ID,
            "source_path": SETTINGS_PATH,
            "deployment_source_capability_id": DEPLOYMENTS_CAPABILITY_ID,
            "deployment_source_path": DEPLOYMENTS_PATH,
            "account_id": account_id,
            "service_name": service_name,
            "http_status": settings.status,
            "deployment_http_status": deployments.status,
            "exists": true,
            "redacted_settings_hash": hash_value(&redact_json(&settings.result))?,
            "redacted_deployments_hash": hash_value(&redact_json(&deployments.result))?,
        });
        if require_singular_active {
            bind_retrievable_rollback_anchor(&mut receipt, &deployments.result, version)?;
        }
        return Ok(receipt);
    }
    Err(CliError::Input(format!(
        "Worker settings/deployments reads for `{service_name}` returned HTTP {}/{} and cannot prove exact current state",
        settings.status, deployments.status
    )))
}

pub(in crate::runtime) fn current_active_deployment_identity(
    deployments: &Value,
) -> Result<(&str, &str), CliError> {
    let history = deployments
        .get("deployments")
        .and_then(Value::as_array)
        .or_else(|| deployments.as_array())
        .ok_or_else(|| {
            CliError::Input("Worker deployments readback omitted deployment history".to_owned())
        })?;
    let current = history.first().ok_or_else(|| {
        CliError::Input("Worker deployments readback has no current deployment".to_owned())
    })?;
    let deployment_id = current
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| CliError::Input("Worker current deployment has no identity".to_owned()))?;
    let versions = current
        .get("versions")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CliError::Input("Worker current deployment has no version allocation".to_owned())
        })?;
    if versions.len() != 1 || versions[0].get("percentage").and_then(Value::as_f64) != Some(100.0) {
        return Err(CliError::Input(
            "Worker deployment planning requires one current version serving exactly 100 percent"
                .to_owned(),
        ));
    }
    let version_id = versions[0]
        .get("version_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| CliError::Input("Worker current version has no identity".to_owned()))?;
    Ok((deployment_id, version_id))
}

/// Previous production UUID is a rollback anchor only after
/// `worker-versions-get-version-detail` returns that identity. A UUID that
/// appears in deployments-list, including as the sole 100 percent version,
/// is not retrievable by that fact alone.
pub(in crate::runtime) fn retrievable_rollback_anchor(receipt: &Value) -> Option<&str> {
    let version_id = receipt
        .pointer("/current_active/version_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())?;
    let detail_hash = receipt
        .pointer("/current_active/version_detail_hash")
        .and_then(Value::as_str)
        .or_else(|| {
            receipt
                .get("redacted_version_detail_hash")
                .and_then(Value::as_str)
        })
        .filter(|hash| !hash.is_empty())?;
    if receipt
        .get("version_source_capability_id")
        .and_then(Value::as_str)
        != Some(VERSION_CAPABILITY_ID)
    {
        return None;
    }
    if receipt
        .get("redacted_version_detail_hash")
        .and_then(Value::as_str)
        != Some(detail_hash)
    {
        return None;
    }
    if receipt
        .pointer("/current_active/traffic_percentage")
        .and_then(Value::as_u64)
        != Some(100)
    {
        return None;
    }
    Some(version_id)
}

fn bind_retrievable_rollback_anchor(
    receipt: &mut Value,
    deployments: &Value,
    version: Option<&CloudflareResponseV1>,
) -> Result<(), CliError> {
    let (current_deployment_id, current_version_id) =
        current_active_deployment_identity(deployments)?;
    let Some(version) = version else {
        return Err(CliError::Input(format!(
            "Worker rollback anchor requires `{VERSION_CAPABILITY_ID}` for `{current_version_id}`; a deployments-list UUID is not retrievable"
        )));
    };
    if !version.success
        || !(200..300).contains(&version.status)
        || version.result.get("id").and_then(Value::as_str) != Some(current_version_id)
    {
        return Err(CliError::Input(format!(
            "Worker version `{current_version_id}` appears in deployments-list but `{VERSION_CAPABILITY_ID}` did not return that identity; it is not a rollback anchor"
        )));
    }
    let version_detail_hash = hash_value(&redact_json(&version.result))?;
    receipt["version_source_capability_id"] = json!(VERSION_CAPABILITY_ID);
    receipt["version_source_path"] = json!(VERSION_PATH);
    receipt["version_http_status"] = json!(version.status);
    receipt["redacted_version_detail_hash"] = json!(version_detail_hash);
    receipt["current_active"] = json!({
        "deployment_id": current_deployment_id,
        "version_id": current_version_id,
        "traffic_percentage": 100,
        "version_detail_hash": version_detail_hash,
    });
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "one fail-closed admission function binds current deployment, active version, retained prior history, and exact target-version detail into one receipt"
)]
pub(in crate::runtime) fn apply_rollback_state_responses(
    account_id: &str,
    service_name: &str,
    target: &Value,
    settings: &CloudflareResponseV1,
    deployments: &CloudflareResponseV1,
    version: &CloudflareResponseV1,
) -> Result<Value, CliError> {
    if !settings.success
        || !(200..300).contains(&settings.status)
        || !deployments.success
        || !(200..300).contains(&deployments.status)
        || !version.success
        || !(200..300).contains(&version.status)
    {
        return Err(CliError::Input(format!(
            "Worker rollback preflight reads for `{service_name}` returned HTTP {}/{}/{} and cannot prove exact current state",
            settings.status, deployments.status, version.status
        )));
    }
    let rollback = target
        .get("rollback")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CliError::Input(
                "Worker rollback target omitted its closed rollback contract".to_owned(),
            )
        })?;
    let target_version_id = rollback
        .get("target_version_id")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("Worker rollback target version is missing".to_owned()))?;
    let expected_current_deployment_id = rollback
        .get("expected_current_deployment_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input("Worker rollback expected current deployment is missing".to_owned())
        })?;
    let history = deployments
        .result
        .get("deployments")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CliError::Input("Worker deployments readback omitted result.deployments".to_owned())
        })?;
    if !(2..=100).contains(&history.len()) {
        return Err(CliError::Input(
            "Worker rollback requires 2 to 100 retained deployments".to_owned(),
        ));
    }
    let current = history.first().ok_or_else(|| {
        CliError::Input("Worker deployment history has no current deployment".to_owned())
    })?;
    let current_deployment_id = current
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("Worker current deployment has no identity".to_owned()))?;
    if current_deployment_id != expected_current_deployment_id {
        return Err(CliError::Input(format!(
            "Worker current deployment is `{current_deployment_id}`, not reviewed expected deployment `{expected_current_deployment_id}`"
        )));
    }
    let current_versions = current
        .get("versions")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CliError::Input("Worker current deployment has no version allocation".to_owned())
        })?;
    if current_versions.len() != 1
        || current_versions[0]
            .get("percentage")
            .and_then(Value::as_f64)
            != Some(100.0)
    {
        return Err(CliError::Input(
            "Worker rollback requires one current version serving exactly 100 percent".to_owned(),
        ));
    }
    let current_version_id = current_versions[0]
        .get("version_id")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("Worker current version has no identity".to_owned()))?;
    if current_version_id == target_version_id {
        return Err(CliError::Input(
            "Worker rollback target is already the active version".to_owned(),
        ));
    }
    let prior_deployment_id = history.iter().skip(1).find_map(|deployment| {
        deployment
            .get("versions")
            .and_then(Value::as_array)
            .filter(|versions| {
                versions.len() == 1
                    && versions[0].get("version_id").and_then(Value::as_str)
                        == Some(target_version_id)
                    && versions[0].get("percentage").and_then(Value::as_f64) == Some(100.0)
            })
            .and_then(|_| deployment.get("id"))
            .and_then(Value::as_str)
    });
    let prior_deployment_id = prior_deployment_id.ok_or_else(|| {
        CliError::Input(
            "Worker rollback target does not appear as the sole 100 percent version in retained prior deployment history"
                .to_owned(),
        )
    })?;
    if version.result.get("id").and_then(Value::as_str) != Some(target_version_id) {
        return Err(CliError::Input(
            "Worker target-version detail readback did not return the exact target identity"
                .to_owned(),
        ));
    }
    Ok(json!({
        "schema_version":2,
        "source_capability_id":SETTINGS_CAPABILITY_ID,
        "source_path":SETTINGS_PATH,
        "deployment_source_capability_id":DEPLOYMENTS_CAPABILITY_ID,
        "deployment_source_path":DEPLOYMENTS_PATH,
        "version_source_capability_id":VERSION_CAPABILITY_ID,
        "version_source_path":VERSION_PATH,
        "account_id":account_id,
        "service_name":service_name,
        "exists":true,
        "current_deployment_id":current_deployment_id,
        "current_version_id":current_version_id,
        "target_version_id":target_version_id,
        "target_prior_deployment_id":prior_deployment_id,
        "target_version_detail_id":target_version_id,
        "retained_deployment_count":history.len(),
        "redacted_settings_hash":hash_value(&redact_json(&settings.result))?,
        "redacted_deployments_hash":hash_value(&redact_json(&deployments.result))?,
        "redacted_target_version_hash":hash_value(&redact_json(&version.result))?,
        "force":false,
        "traffic_percentage":100,
    }))
}

#[expect(
    clippy::too_many_lines,
    reason = "legacy deployment receipts and the stricter rollback receipt share one dispatcher while retaining distinct exact-shape validation"
)]
pub(in crate::runtime) fn validate_state_receipt(
    plan: &PlanV1,
    receipt: &Value,
) -> Result<(), CliError> {
    let adapter = plan.targets.get("adapter").unwrap_or(&Value::Null);
    let expected_service = service_name(adapter)?;
    if plan.capability.id == ROLLBACK_CAPABILITY_ID {
        let target = target(adapter).ok_or_else(|| {
            CliError::Input("Worker rollback plan omitted its exact target".to_owned())
        })?;
        let rollback = target
            .get("rollback")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                CliError::Input("Worker rollback plan omitted its closed target".to_owned())
            })?;
        let exact = receipt.as_object().is_some_and(|object| object.len() == 21)
            && receipt.get("schema_version").and_then(Value::as_u64) == Some(2)
            && receipt.get("account_id").and_then(Value::as_str) == Some(plan.account_id.as_str())
            && receipt.get("service_name").and_then(Value::as_str) == Some(expected_service)
            && receipt.get("exists").and_then(Value::as_bool) == Some(true)
            && receipt.get("source_capability_id").and_then(Value::as_str)
                == Some(SETTINGS_CAPABILITY_ID)
            && receipt.get("source_path").and_then(Value::as_str) == Some(SETTINGS_PATH)
            && receipt
                .get("deployment_source_capability_id")
                .and_then(Value::as_str)
                == Some(DEPLOYMENTS_CAPABILITY_ID)
            && receipt
                .get("deployment_source_path")
                .and_then(Value::as_str)
                == Some(DEPLOYMENTS_PATH)
            && receipt
                .get("version_source_capability_id")
                .and_then(Value::as_str)
                == Some(VERSION_CAPABILITY_ID)
            && receipt.get("version_source_path").and_then(Value::as_str) == Some(VERSION_PATH)
            && receipt.get("current_deployment_id")
                == rollback.get("expected_current_deployment_id")
            && receipt.get("target_version_id") == rollback.get("target_version_id")
            && receipt.get("target_version_detail_id") == rollback.get("target_version_id")
            && receipt.get("force").and_then(Value::as_bool) == Some(false)
            && receipt.get("traffic_percentage").and_then(Value::as_u64) == Some(100)
            && receipt
                .get("retained_deployment_count")
                .and_then(Value::as_u64)
                .is_some_and(|count| (2..=100).contains(&count))
            && [
                "current_version_id",
                "target_prior_deployment_id",
                "redacted_settings_hash",
                "redacted_deployments_hash",
                "redacted_target_version_hash",
            ]
            .iter()
            .all(|field| {
                receipt
                    .get(*field)
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.is_empty())
            });
        if !exact {
            return Err(CliError::Input(
                "Worker rollback live-state receipt is malformed or targets another service, deployment, or version"
                    .to_owned(),
            ));
        }
        return Ok(());
    }
    let exists = receipt.get("exists").and_then(Value::as_bool);
    let strict_planning = plan.capability.id == WORKER_DEPLOYMENT_PLAN_CAPABILITY_ID;
    let exact_field_count = match (strict_planning, exists) {
        (false, Some(false)) => 7,
        (false, Some(true)) => 12,
        (true, Some(true)) => 17,
        _ => 0,
    };
    let exact = receipt
        .as_object()
        .is_some_and(|object| object.len() == exact_field_count)
        && receipt.get("schema_version").and_then(Value::as_u64) == Some(1)
        && receipt.get("source_capability_id").and_then(Value::as_str)
            == Some(SETTINGS_CAPABILITY_ID)
        && receipt.get("source_path").and_then(Value::as_str) == Some(SETTINGS_PATH)
        && receipt.get("account_id").and_then(Value::as_str) == Some(plan.account_id.as_str())
        && receipt.get("service_name").and_then(Value::as_str) == Some(expected_service)
        && exists.is_some();
    let existing_state_is_exact = exists != Some(true)
        || (receipt
            .get("deployment_source_capability_id")
            .and_then(Value::as_str)
            == Some(DEPLOYMENTS_CAPABILITY_ID)
            && receipt
                .get("deployment_source_path")
                .and_then(Value::as_str)
                == Some(DEPLOYMENTS_PATH)
            && receipt
                .get("redacted_settings_hash")
                .and_then(Value::as_str)
                .is_some()
            && receipt
                .get("redacted_deployments_hash")
                .and_then(Value::as_str)
                .is_some()
            && (!strict_planning
                || (receipt
                    .get("version_source_capability_id")
                    .and_then(Value::as_str)
                    == Some(VERSION_CAPABILITY_ID)
                    && receipt.get("version_source_path").and_then(Value::as_str)
                        == Some(VERSION_PATH)
                    && receipt
                        .get("version_http_status")
                        .and_then(Value::as_u64)
                        .is_some_and(|status| (200..300).contains(&status))
                    && receipt
                        .get("redacted_version_detail_hash")
                        .and_then(Value::as_str)
                        .is_some_and(|value| !value.is_empty()))));
    let strict_current_active_is_exact = !strict_planning
        || receipt
            .get("current_active")
            .and_then(Value::as_object)
            .is_some_and(|current| {
                current.len() == 4
                    && current
                        .get("deployment_id")
                        .and_then(Value::as_str)
                        .is_some_and(|value| !value.is_empty())
                    && current
                        .get("version_id")
                        .and_then(Value::as_str)
                        .is_some_and(|value| !value.is_empty())
                    && current.get("traffic_percentage").and_then(Value::as_u64) == Some(100)
                    && current.get("version_detail_hash").and_then(Value::as_str)
                        == receipt
                            .get("redacted_version_detail_hash")
                            .and_then(Value::as_str)
            })
            && retrievable_rollback_anchor(receipt).is_some();
    if !exact || !existing_state_is_exact || !strict_current_active_is_exact {
        return Err(CliError::Input(
            "Worker deployment live-state receipt is malformed or targets another service"
                .to_owned(),
        ));
    }
    Ok(())
}

pub(in crate::runtime) fn apply_plan_diff(diff: &mut Value, plan: &PlanV1, state: &Value) {
    let adapter = plan.targets.get("adapter").unwrap_or(&Value::Null);
    if let Some(target) = target(adapter) {
        let mut observed_before = json!({
            "service_name": state.get("service_name"),
            "exists": state.get("exists"),
            "redacted_settings_hash": state.get("redacted_settings_hash"),
            "redacted_deployments_hash": state.get("redacted_deployments_hash"),
        });
        if state.get("redacted_version_detail_hash").is_some() {
            observed_before["redacted_version_detail_hash"] = state
                .get("redacted_version_detail_hash")
                .cloned()
                .unwrap_or(Value::Null);
            observed_before["current_active"] =
                state.get("current_active").cloned().unwrap_or(Value::Null);
        }
        diff["observed_before"] = observed_before;
        diff["planned_after"] = target.clone();
    }
}
