use super::api_boundary::persist_secret_lifecycle;
use super::api_boundary::post_boundary_failure_envelope;
use super::import_lineage::exact_accepted_ingest_bookmarks;
use super::import_lineage::import_plan_runtime_lineage;
use super::plan_commands::persist_transaction_stage_with_artifact;
use super::prelude::{
    CliError, CloudflareError, EvidenceClass, EvidenceV1, PlanStatus, PlanV1, Result,
    ResultEnvelopeV2, SecretStore, StateStore, TransactionStageV1, Value, json,
};
use cfctl_core::hash_value;

#[expect(
    clippy::too_many_lines,
    reason = "stage-specific init, ingest, and poll receipt authority is one fail-closed join"
)]
pub(super) fn exact_durable_provider_failure_boundary(
    store: &StateStore,
    plan: &PlanV1,
) -> Result<(EvidenceV1, Value)> {
    let (target, _migration_id, inherited_bookmark) = import_plan_runtime_lineage(plan)?;
    let input_hash = hash_value(&plan.input)?;
    let checkpoints = store.read_d1_import_checkpoints(&plan.operation_id)?;
    let accepted_ingest_bookmarks = inherited_bookmark.map_or_else(
        || exact_accepted_ingest_bookmarks(store, plan, &checkpoints, &target, &input_hash),
        |bookmark| vec![bookmark],
    );
    let failures = checkpoints
        .into_iter()
        .filter(|(_, checkpoint)| {
            let Some(step) = checkpoint.get("step").and_then(Value::as_str) else {
                return false;
            };
            let action = if step == "init_response" {
                "init"
            } else if step == "ingest_response" {
                "ingest"
            } else if step.starts_with("poll_response_") {
                "poll"
            } else {
                return false;
            };
            let bookmark = checkpoint
                .pointer("/receipt/result/at_bookmark")
                .and_then(Value::as_str);
            let bookmark_matches_stage = match action {
                "init" => bookmark.is_none(),
                "ingest" => bookmark.is_none_or(|value| !value.is_empty()),
                "poll" => {
                    accepted_ingest_bookmarks.len() == 1
                        && bookmark == accepted_ingest_bookmarks.first().map(String::as_str)
                }
                _ => false,
            };
            checkpoint.get("schema_version").and_then(Value::as_u64) == Some(1)
                && checkpoint.get("operation_id").and_then(Value::as_str)
                    == Some(plan.operation_id.as_str())
                && checkpoint
                    .pointer("/receipt/response_action")
                    .and_then(Value::as_str)
                    == Some(action)
                && checkpoint.pointer("/receipt/target") == Some(&target)
                && checkpoint
                    .pointer("/receipt/plan_input_hash")
                    .and_then(Value::as_str)
                    == Some(input_hash.as_str())
                && checkpoint.get("performed").and_then(Value::as_bool) == Some(true)
                && checkpoint
                    .get("rectification_required")
                    .and_then(Value::as_bool)
                    == Some(true)
                && checkpoint
                    .pointer("/receipt/success")
                    .and_then(Value::as_bool)
                    == Some(true)
                && checkpoint
                    .pointer("/receipt/result/type")
                    .and_then(Value::as_str)
                    == Some("import")
                && checkpoint
                    .pointer("/receipt/result/status")
                    .and_then(Value::as_str)
                    == Some("error")
                && checkpoint
                    .pointer("/receipt/result/success")
                    .and_then(Value::as_bool)
                    == Some(false)
                && checkpoint
                    .pointer("/receipt/no_replay")
                    .and_then(Value::as_bool)
                    == Some(true)
                && bookmark_matches_stage
                && checkpoint
                    .pointer("/receipt/result/provider_error_present")
                    .and_then(Value::as_bool)
                    == Some(true)
                && checkpoint.pointer("/receipt/result/error").is_none()
                && checkpoint
                    .pointer("/receipt/errors")
                    .and_then(Value::as_array)
                    .is_some_and(Vec::is_empty)
        })
        .collect::<Vec<_>>();
    if failures.len() != 1 {
        return Err(CliError::Input(
            "known import provider failure requires exactly one stage-correct durable redacted checkpoint"
                .to_owned(),
        ));
    }
    let (hash, checkpoint) = &failures[0];
    if store.read_evidence_value(hash)? != *checkpoint {
        return Err(CliError::Input(
            "known import provider-failure evidence does not match its immutable checkpoint"
                .to_owned(),
        ));
    }
    Ok((
        EvidenceV1::new(
            EvidenceClass::Apply,
            hash,
            &store
                .paths()
                .data_dir
                .join("evidence")
                .join(format!("{}.json", hash.trim_start_matches("sha256:")))
                .display()
                .to_string(),
        ),
        checkpoint.clone(),
    ))
}

pub(super) fn known_import_provider_failure_envelope(
    store: &StateStore,
    plan: &mut PlanV1,
    secrets: &dyn SecretStore,
) -> ResultEnvelopeV2 {
    plan.status = PlanStatus::RectificationRequired;
    match exact_durable_provider_failure_boundary(store, plan) {
        Ok((evidence, _checkpoint)) => {
            let artifact = json!({
                "adapter":"dynamic_api",
                "performed":true,
                "success":false,
                "outcome":"provider_rejected",
                "receipt_available":true,
                "provider_failure_evidence_hash":evidence.content_hash,
            });
            let mut local_failures = Vec::new();
            if let Err(error) = persist_transaction_stage_with_artifact(
                store,
                plan,
                TransactionStageV1::BoundaryResponsePersisted,
                artifact,
            ) {
                local_failures.push(format!("provider-failure receipt binding failed: {error}"));
            }
            if let Err(error) = persist_secret_lifecycle(store, plan, false, None, secrets) {
                local_failures.push(format!(
                    "provider-failure secret lifecycle persistence failed: {error}"
                ));
            }
            let detail = if local_failures.is_empty() {
                "Cloudflare reported a terminal D1 import failure".to_owned()
            } else {
                format!(
                    "Cloudflare reported a terminal D1 import failure; {}",
                    local_failures.join("; ")
                )
            };
            post_boundary_failure_envelope(
                plan,
                json!({
                    "success":false,
                    "outcome":"provider_rejected",
                    "receipt_available":true,
                    "provider_status":"error",
                }),
                Some(evidence),
                None,
                &CliError::Input(detail),
                true,
                "the exact redacted Cloudflare provider-failure response is durable; the import did not complete and must not be replayed",
            )
        }
        Err(error) => {
            let _ = store.save_plan(plan);
            post_boundary_failure_envelope(
                plan,
                json!({
                    "success":false,
                    "outcome":"provider_rejected_receipt_invalid",
                    "receipt_available":false,
                }),
                None,
                None,
                &error,
                true,
                "Cloudflare reported a terminal provider failure, but its exact durable redacted checkpoint could not be uniquely resolved; do not replay",
            )
        }
    }
}

pub(super) fn exact_durable_upload_response_failure(
    store: &StateStore,
    plan: &PlanV1,
) -> Result<(EvidenceV1, Value)> {
    let (target, migration_id, _) = import_plan_runtime_lineage(plan)?;
    let input_hash = hash_value(&plan.input)?;
    let failures = store
        .read_d1_import_checkpoints(&plan.operation_id)?
        .into_iter()
        .filter(|(_, checkpoint)| {
            let status = checkpoint
                .pointer("/receipt/http_status")
                .and_then(Value::as_u64);
            let success = checkpoint
                .pointer("/receipt/success")
                .and_then(Value::as_bool);
            let etag_present = checkpoint
                .pointer("/receipt/etag_present")
                .and_then(Value::as_bool);
            let etag_matches = checkpoint
                .pointer("/receipt/etag_matches")
                .and_then(Value::as_bool);
            let rejected = status.is_some_and(|value| !(200..300).contains(&value))
                && success == Some(false)
                && etag_present == Some(false)
                && etag_matches == Some(false);
            let integrity_rejected = status.is_some_and(|value| (200..300).contains(&value))
                && success == Some(true)
                && etag_present.is_some()
                && etag_matches == Some(false);
            checkpoint.get("schema_version").and_then(Value::as_u64) == Some(1)
                && checkpoint.get("operation_id").and_then(Value::as_str)
                    == Some(plan.operation_id.as_str())
                && checkpoint.get("step").and_then(Value::as_str) == Some("upload_response")
                && checkpoint.get("performed").and_then(Value::as_bool) == Some(true)
                && checkpoint
                    .get("rectification_required")
                    .and_then(Value::as_bool)
                    == Some(true)
                && checkpoint
                    .pointer("/receipt/provider")
                    .and_then(Value::as_str)
                    == Some("cloudflare")
                && checkpoint
                    .pointer("/receipt/effect")
                    .and_then(Value::as_str)
                    == Some("d1_import_upload_response")
                && checkpoint
                    .pointer("/receipt/migration_id")
                    .and_then(Value::as_str)
                    == Some(migration_id.as_str())
                && checkpoint.pointer("/receipt/target") == Some(&target)
                && checkpoint
                    .pointer("/receipt/plan_input_hash")
                    .and_then(Value::as_str)
                    == Some(input_hash.as_str())
                && checkpoint
                    .pointer("/receipt/no_replay")
                    .and_then(Value::as_bool)
                    == Some(true)
                && checkpoint.pointer("/receipt/etag").is_none()
                && (rejected || integrity_rejected)
        })
        .collect::<Vec<_>>();
    if failures.len() != 1 {
        return Err(CliError::Input(
            "known upload response requires exactly one operation-bound durable redacted checkpoint"
                .to_owned(),
        ));
    }
    let (hash, checkpoint) = &failures[0];
    if store.read_evidence_value(hash)? != *checkpoint {
        return Err(CliError::Input(
            "known upload-response evidence does not match its immutable checkpoint".to_owned(),
        ));
    }
    Ok((
        EvidenceV1::new(
            EvidenceClass::Apply,
            hash,
            &store
                .paths()
                .data_dir
                .join("evidence")
                .join(format!("{}.json", hash.trim_start_matches("sha256:")))
                .display()
                .to_string(),
        ),
        checkpoint.clone(),
    ))
}

pub(super) fn known_import_upload_response_failure_envelope(
    store: &StateStore,
    plan: &mut PlanV1,
    secrets: &dyn SecretStore,
) -> ResultEnvelopeV2 {
    plan.status = PlanStatus::RectificationRequired;
    match exact_durable_upload_response_failure(store, plan) {
        Ok((evidence, checkpoint)) => {
            let integrity_rejected = checkpoint
                .pointer("/receipt/success")
                .and_then(Value::as_bool)
                == Some(true);
            let outcome = if integrity_rejected {
                "upload_integrity_rejected"
            } else {
                "upload_rejected"
            };
            let artifact = json!({
                "adapter":"dynamic_api",
                "performed":true,
                "success":false,
                "outcome":outcome,
                "receipt_available":true,
                "upload_response_evidence_hash":evidence.content_hash,
            });
            let mut local_failures = Vec::new();
            if let Err(error) = persist_transaction_stage_with_artifact(
                store,
                plan,
                TransactionStageV1::BoundaryResponsePersisted,
                artifact,
            ) {
                local_failures.push(format!("upload-response receipt binding failed: {error}"));
            }
            if let Err(error) = persist_secret_lifecycle(store, plan, false, None, secrets) {
                local_failures.push(format!(
                    "upload-response secret lifecycle persistence failed: {error}"
                ));
            }
            let detail = if local_failures.is_empty() {
                "Cloudflare returned a known D1 import upload rejection".to_owned()
            } else {
                format!(
                    "Cloudflare returned a known D1 import upload rejection; {}",
                    local_failures.join("; ")
                )
            };
            post_boundary_failure_envelope(
                plan,
                json!({
                    "success":false,
                    "outcome":outcome,
                    "receipt_available":true,
                    "http_status":checkpoint.pointer("/receipt/http_status"),
                    "etag_present":checkpoint.pointer("/receipt/etag_present"),
                    "etag_matches":checkpoint.pointer("/receipt/etag_matches"),
                }),
                Some(evidence),
                None,
                &CliError::Input(detail),
                true,
                "the exact redacted Cloudflare upload response is durable; ingest was not attempted and the import must not be replayed",
            )
        }
        Err(error) => {
            let _ = store.save_plan(plan);
            post_boundary_failure_envelope(
                plan,
                json!({
                    "success":false,
                    "outcome":"upload_rejected_receipt_invalid",
                    "receipt_available":false,
                }),
                None,
                None,
                &error,
                true,
                "Cloudflare returned an upload response, but its exact durable redacted checkpoint could not be uniquely resolved; do not replay",
            )
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the exact init authority join intentionally validates every projected field"
)]
pub(super) fn exact_durable_init_response_failure(
    store: &StateStore,
    plan: &PlanV1,
) -> Result<(EvidenceV1, Value)> {
    let (target, migration_id, _) = import_plan_runtime_lineage(plan)?;
    let input_hash = hash_value(&plan.input)?;
    let failures = store
        .read_d1_import_checkpoints(&plan.operation_id)?
        .into_iter()
        .filter(|(_, checkpoint)| {
            let Some(result) = checkpoint
                .pointer("/receipt/result")
                .and_then(Value::as_object)
            else {
                return false;
            };
            let exact_result_fields = [
                "type",
                "status",
                "success",
                "at_bookmark_present",
                "at_bookmark_is_string",
                "upload_url_present",
                "upload_url_sha256",
                "upload_url_host_is_exact_account_endpoint",
                "upload_url_host_is_cloudflare_r2",
                "filename_present",
                "filename_sha256",
                "filename_shape_valid",
                "provider_error_present",
                "cfctl_classification_failure",
            ];
            let exact_result = result.len() == exact_result_fields.len()
                && exact_result_fields
                    .iter()
                    .all(|field| result.contains_key(*field));
            let hashes_are_redacted =
                ["upload_url_sha256", "filename_sha256"]
                    .iter()
                    .all(|field| {
                        result.get(*field).is_some_and(|value| {
                            value.is_null()
                                || value
                                    .as_str()
                                    .is_some_and(|hash| hash.starts_with("sha256:"))
                        })
                    });
            checkpoint.get("schema_version").and_then(Value::as_u64) == Some(1)
                && checkpoint.get("operation_id").and_then(Value::as_str)
                    == Some(plan.operation_id.as_str())
                && checkpoint.get("step").and_then(Value::as_str) == Some("init_response")
                && checkpoint.get("performed").and_then(Value::as_bool) == Some(true)
                && checkpoint
                    .get("rectification_required")
                    .and_then(Value::as_bool)
                    == Some(true)
                && checkpoint
                    .pointer("/receipt/response_action")
                    .and_then(Value::as_str)
                    == Some("init")
                && checkpoint
                    .pointer("/receipt/provider")
                    .and_then(Value::as_str)
                    == Some("cloudflare")
                && checkpoint
                    .pointer("/receipt/effect")
                    .and_then(Value::as_str)
                    == Some("d1_import_response")
                && checkpoint
                    .pointer("/receipt/migration_id")
                    .and_then(Value::as_str)
                    == Some(migration_id.as_str())
                && checkpoint.pointer("/receipt/target") == Some(&target)
                && checkpoint
                    .pointer("/receipt/plan_input_hash")
                    .and_then(Value::as_str)
                    == Some(input_hash.as_str())
                && checkpoint
                    .pointer("/receipt/no_replay")
                    .and_then(Value::as_bool)
                    == Some(true)
                && checkpoint.pointer("/receipt/etag").is_none()
                && exact_result
                && hashes_are_redacted
        })
        .collect::<Vec<_>>();
    if failures.len() != 1 {
        return Err(CliError::Input(
            "known init response requires exactly one operation-bound durable redacted checkpoint"
                .to_owned(),
        ));
    }
    let (hash, checkpoint) = &failures[0];
    if store.read_evidence_value(hash)? != *checkpoint {
        return Err(CliError::Input(
            "known init-response evidence does not match its immutable checkpoint".to_owned(),
        ));
    }
    Ok((
        EvidenceV1::new(
            EvidenceClass::Apply,
            hash,
            &store
                .paths()
                .data_dir
                .join("evidence")
                .join(format!("{}.json", hash.trim_start_matches("sha256:")))
                .display()
                .to_string(),
        ),
        checkpoint.clone(),
    ))
}

pub(super) fn known_import_init_response_failure_envelope(
    store: &StateStore,
    plan: &mut PlanV1,
    secrets: &dyn SecretStore,
) -> ResultEnvelopeV2 {
    plan.status = PlanStatus::RectificationRequired;
    match exact_durable_init_response_failure(store, plan) {
        Ok((evidence, checkpoint)) => {
            let provider_rejected = checkpoint
                .pointer("/receipt/success")
                .and_then(Value::as_bool)
                == Some(false)
                || checkpoint
                    .pointer("/receipt/result/status")
                    .and_then(Value::as_str)
                    == Some("error");
            let outcome = if provider_rejected {
                "provider_rejected"
            } else {
                "invalid_provider_response"
            };
            let artifact = json!({
                "adapter":"dynamic_api",
                "performed":true,
                "success":false,
                "outcome":outcome,
                "receipt_available":true,
                "init_response_evidence_hash":evidence.content_hash,
            });
            let _ = persist_transaction_stage_with_artifact(
                store,
                plan,
                TransactionStageV1::BoundaryResponsePersisted,
                artifact,
            );
            let _ = persist_secret_lifecycle(store, plan, false, None, secrets);
            post_boundary_failure_envelope(
                plan,
                json!({
                    "success":false,
                    "outcome":outcome,
                    "receipt_available":true,
                }),
                Some(evidence),
                None,
                &CliError::Input(
                    "Cloudflare returned a known rejected or invalid D1 import init response"
                        .to_owned(),
                ),
                true,
                "the exact action-projected Cloudflare init response is durable; no upload occurred and the import must not be replayed",
            )
        }
        Err(error) => {
            let _ = store.save_plan(plan);
            post_boundary_failure_envelope(
                plan,
                json!({
                    "success":false,
                    "outcome":"init_response_receipt_invalid",
                    "receipt_available":false,
                }),
                None,
                None,
                &error,
                true,
                "Cloudflare returned an init response, but its exact durable redacted checkpoint could not be uniquely resolved; do not replay",
            )
        }
    }
}

pub(super) fn exact_durable_action_response_failure(
    store: &StateStore,
    plan: &PlanV1,
    action: &str,
) -> Result<(EvidenceV1, Value)> {
    let (target, migration_id, _) = import_plan_runtime_lineage(plan)?;
    let input_hash = hash_value(&plan.input)?;
    let failures = store
        .read_d1_import_checkpoints(&plan.operation_id)?
        .into_iter()
        .filter(|(_, checkpoint)| {
            let Some(step) = checkpoint.get("step").and_then(Value::as_str) else {
                return false;
            };
            let step_matches = match action {
                "ingest" => step == "ingest_response",
                "poll" => step.starts_with("poll_response_"),
                _ => false,
            };
            let Some(result) = checkpoint
                .pointer("/receipt/result")
                .and_then(Value::as_object)
            else {
                return false;
            };
            let allowed = [
                "type",
                "status",
                "success",
                "at_bookmark",
                "result",
                "provider_error_present",
            ];
            let projected = result.keys().all(|key| allowed.contains(&key.as_str()))
                && result.get("result").is_none_or(|nested| {
                    nested.as_object().is_some_and(|object| {
                        object.len() == 1 && object.contains_key("final_bookmark")
                    })
                });
            step_matches
                && checkpoint.get("schema_version").and_then(Value::as_u64) == Some(1)
                && checkpoint.get("operation_id").and_then(Value::as_str)
                    == Some(plan.operation_id.as_str())
                && checkpoint.get("performed").and_then(Value::as_bool) == Some(true)
                && checkpoint
                    .get("rectification_required")
                    .and_then(Value::as_bool)
                    == Some(true)
                && checkpoint
                    .pointer("/receipt/response_action")
                    .and_then(Value::as_str)
                    == Some(action)
                && checkpoint
                    .pointer("/receipt/provider")
                    .and_then(Value::as_str)
                    == Some("cloudflare")
                && checkpoint
                    .pointer("/receipt/effect")
                    .and_then(Value::as_str)
                    == Some("d1_import_response")
                && checkpoint
                    .pointer("/receipt/migration_id")
                    .and_then(Value::as_str)
                    == Some(migration_id.as_str())
                && checkpoint.pointer("/receipt/target") == Some(&target)
                && checkpoint
                    .pointer("/receipt/plan_input_hash")
                    .and_then(Value::as_str)
                    == Some(input_hash.as_str())
                && checkpoint
                    .pointer("/receipt/no_replay")
                    .and_then(Value::as_bool)
                    == Some(true)
                && checkpoint.pointer("/receipt/etag").is_none()
                && projected
        })
        .collect::<Vec<_>>();
    if failures.len() != 1 {
        return Err(CliError::Input(format!(
            "known {action} response requires exactly one operation-bound durable redacted checkpoint"
        )));
    }
    let (hash, checkpoint) = &failures[0];
    if store.read_evidence_value(hash)? != *checkpoint {
        return Err(CliError::Input(format!(
            "known {action}-response evidence does not match its immutable checkpoint"
        )));
    }
    Ok((
        EvidenceV1::new(
            EvidenceClass::Apply,
            hash,
            &store
                .paths()
                .data_dir
                .join("evidence")
                .join(format!("{}.json", hash.trim_start_matches("sha256:")))
                .display()
                .to_string(),
        ),
        checkpoint.clone(),
    ))
}

pub(super) fn known_import_action_response_failure_envelope(
    store: &StateStore,
    plan: &mut PlanV1,
    error: CloudflareError,
    secrets: &dyn SecretStore,
) -> ResultEnvelopeV2 {
    plan.status = PlanStatus::RectificationRequired;
    let action = if matches!(error, CloudflareError::D1ImportIngestResponseFailure) {
        "ingest"
    } else {
        "poll"
    };
    match exact_durable_action_response_failure(store, plan, action) {
        Ok((evidence, checkpoint)) => {
            let provider_rejected = checkpoint
                .pointer("/receipt/success")
                .and_then(Value::as_bool)
                == Some(false)
                || checkpoint
                    .pointer("/receipt/result/status")
                    .and_then(Value::as_str)
                    == Some("error");
            let outcome = if provider_rejected {
                "provider_rejected"
            } else {
                "invalid_provider_response"
            };
            let artifact = json!({
                "adapter":"dynamic_api",
                "performed":true,
                "success":false,
                "outcome":outcome,
                "receipt_available":true,
                "response_action":action,
                "response_evidence_hash":evidence.content_hash,
            });
            let _ = persist_transaction_stage_with_artifact(
                store,
                plan,
                TransactionStageV1::BoundaryResponsePersisted,
                artifact,
            );
            let _ = persist_secret_lifecycle(store, plan, false, None, secrets);
            post_boundary_failure_envelope(
                plan,
                json!({
                    "success":false,
                    "outcome":outcome,
                    "receipt_available":true,
                    "response_action":action,
                }),
                Some(evidence),
                None,
                &CliError::Input(format!(
                    "Cloudflare returned a known rejected or invalid D1 import {action} response"
                )),
                true,
                &format!(
                    "the exact action-projected Cloudflare {action} response is durable; no later import action occurred and the import must not be replayed"
                ),
            )
        }
        Err(error) => {
            let _ = store.save_plan(plan);
            post_boundary_failure_envelope(
                plan,
                json!({
                    "success":false,
                    "outcome":"provider_response_receipt_invalid",
                    "receipt_available":false,
                    "response_action":action,
                }),
                None,
                None,
                &error,
                true,
                &format!(
                    "Cloudflare returned an {action} response, but its exact durable redacted checkpoint could not be uniquely resolved; do not replay"
                ),
            )
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "canonical poll authority binds every immutable lineage dimension explicitly"
)]
pub(super) fn exact_in_progress_poll_receipt(
    store: &StateStore,
    plan: &PlanV1,
    hash: &str,
    checkpoint: &Value,
    expected_attempt: u64,
    target: &Value,
    input_hash: &str,
    migration_id: &str,
    bookmark: &str,
) -> bool {
    let expected_step = format!("poll_response_{expected_attempt}");
    let Some(receipt) = checkpoint.get("receipt").and_then(Value::as_object) else {
        return false;
    };
    let Some(result) = receipt.get("result").and_then(Value::as_object) else {
        return false;
    };
    let receipt_fields = [
        "http_status",
        "success",
        "response_action",
        "provider",
        "effect",
        "migration_id",
        "target",
        "plan_input_hash",
        "result",
        "errors",
        "provider_errors_present",
        "no_replay",
        "etag_present",
        "etag_sha256",
        "cf_ray",
    ];
    let result_fields = [
        "type",
        "status",
        "success",
        "at_bookmark",
        "result",
        "provider_error_present",
    ];
    let nested_result = result.get("result").and_then(Value::as_object);
    let etag_present = receipt.get("etag_present").and_then(Value::as_bool);
    let etag_hash = receipt.get("etag_sha256");
    let etag_exact = match (etag_present, etag_hash) {
        (Some(false), Some(value)) => value.is_null(),
        (Some(true), Some(value)) => value
            .as_str()
            .and_then(|hash| hash.strip_prefix("sha256:"))
            .is_some_and(|digest| {
                digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            }),
        _ => false,
    };
    let cf_ray_exact = receipt.get("cf_ray").is_some_and(|value| {
        value.is_null()
            || value.as_str().is_some_and(|ray| {
                !ray.is_empty()
                    && ray.len() <= 128
                    && ray
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
    });
    checkpoint
        .as_object()
        .is_some_and(|object| object.len() == 6)
        && checkpoint.get("schema_version").and_then(Value::as_u64) == Some(1)
        && checkpoint.get("operation_id").and_then(Value::as_str)
            == Some(plan.operation_id.as_str())
        && checkpoint.get("step").and_then(Value::as_str) == Some(expected_step.as_str())
        && checkpoint.get("performed").and_then(Value::as_bool) == Some(true)
        && checkpoint
            .get("rectification_required")
            .and_then(Value::as_bool)
            == Some(false)
        && receipt.len() == receipt_fields.len()
        && receipt_fields
            .iter()
            .all(|field| receipt.contains_key(*field))
        && receipt.get("http_status").and_then(Value::as_u64) == Some(200)
        && receipt.get("success").and_then(Value::as_bool) == Some(true)
        && receipt.get("response_action").and_then(Value::as_str) == Some("poll")
        && receipt.get("provider").and_then(Value::as_str) == Some("cloudflare")
        && receipt.get("effect").and_then(Value::as_str) == Some("d1_import_response")
        && receipt.get("migration_id").and_then(Value::as_str) == Some(migration_id)
        && receipt.get("target") == Some(target)
        && receipt.get("plan_input_hash").and_then(Value::as_str) == Some(input_hash)
        && result.len() == result_fields.len()
        && result_fields
            .iter()
            .all(|field| result.contains_key(*field))
        && result.get("type").and_then(Value::as_str) == Some("import")
        && matches!(
            result.get("status").and_then(Value::as_str),
            Some("active" | "pending")
        )
        && result.get("success").and_then(Value::as_bool) == Some(true)
        && result.get("at_bookmark").and_then(Value::as_str) == Some(bookmark)
        && result
            .get("provider_error_present")
            .and_then(Value::as_bool)
            == Some(false)
        && nested_result.is_some_and(|nested| {
            nested.len() == 1
                && nested.contains_key("final_bookmark")
                && nested.get("final_bookmark").is_some_and(Value::is_null)
        })
        && receipt
            .get("errors")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
        && receipt
            .get("provider_errors_present")
            .and_then(Value::as_bool)
            == Some(false)
        && receipt.get("no_replay").and_then(Value::as_bool) == Some(false)
        && etag_exact
        && cf_ray_exact
        && checkpoint.get("error").is_none()
        && store
            .read_evidence_value(hash)
            .is_ok_and(|evidence| evidence == *checkpoint)
}

#[expect(
    clippy::too_many_lines,
    reason = "poll exhaustion authority joins ingest lineage every bounded poll and terminal receipt"
)]
pub(super) fn exact_durable_poll_exhaustion(
    store: &StateStore,
    plan: &PlanV1,
) -> Result<(EvidenceV1, Value, EvidenceV1)> {
    let (target, migration_id, _) = import_plan_runtime_lineage(plan)?;
    let max_poll_attempts = plan
        .capability
        .d1_approved_mln_import
        .as_ref()
        .map(|contract| contract.max_poll_attempts)
        .ok_or_else(|| CliError::Input("governed D1 import contract is missing".to_owned()))?;
    let input_hash = hash_value(&plan.input)?;
    let source_sha256 = plan
        .targets
        .pointer("/adapter/approved_mln_import/sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input("approved MLN import source identity is missing".to_owned())
        })?;
    let checkpoints = store.read_d1_import_checkpoints(&plan.operation_id)?;
    let accepted = exact_accepted_ingest_bookmarks(store, plan, &checkpoints, &target, &input_hash);
    if accepted.len() != 1 {
        return Err(CliError::Input(
            "poll exhaustion requires exactly one durable accepted-ingest bookmark".to_owned(),
        ));
    }
    let bookmark = &accepted[0];
    let accepted_entries = checkpoints
        .iter()
        .enumerate()
        .filter(|(_, (hash, checkpoint))| {
            checkpoint.get("step").and_then(Value::as_str) == Some("ingest_response")
                && checkpoint
                    .pointer("/receipt/effect")
                    .and_then(Value::as_str)
                    == Some("d1_import_ingest_accepted")
                && checkpoint
                    .pointer("/receipt/result/at_bookmark")
                    .and_then(Value::as_str)
                    == Some(bookmark.as_str())
                && store
                    .read_evidence_value(hash)
                    .is_ok_and(|evidence| evidence == *checkpoint)
        })
        .collect::<Vec<_>>();
    if accepted_entries.len() != 1 {
        return Err(CliError::Input(
            "poll exhaustion requires exactly one accepted-ingest checkpoint and evidence"
                .to_owned(),
        ));
    }
    let (accepted_index, (accepted_hash, _)) = accepted_entries[0];
    let mut attempts = checkpoints
        .iter()
        .enumerate()
        .filter_map(|(index, (hash, checkpoint))| {
            let step = checkpoint.get("step").and_then(Value::as_str)?;
            let attempt = step.strip_prefix("poll_response_")?.parse::<u64>().ok()?;
            let exact = exact_in_progress_poll_receipt(
                store,
                plan,
                hash,
                checkpoint,
                attempt,
                &target,
                &input_hash,
                migration_id.as_str(),
                bookmark,
            );
            exact.then_some((index, attempt))
        })
        .collect::<Vec<_>>();
    attempts.sort_unstable_by_key(|(_, attempt)| *attempt);
    let expected_attempts = (1..=max_poll_attempts)
        .enumerate()
        .map(|(offset, attempt)| (accepted_index + offset + 1, attempt))
        .collect::<Vec<_>>();
    if attempts != expected_attempts {
        return Err(CliError::Input(
            "poll exhaustion requires one chronological durable in-progress receipt per approved attempt"
                .to_owned(),
        ));
    }
    if checkpoints.iter().any(|(_, checkpoint)| {
        checkpoint.get("step").and_then(Value::as_str) == Some("provider_complete")
    }) {
        return Err(CliError::Input(
            "poll exhaustion conflicts with a provider_complete checkpoint".to_owned(),
        ));
    }
    let exhausted = checkpoints
        .iter()
        .enumerate()
        .filter(|(index, (_, checkpoint))| {
            let exact_receipt_shape = checkpoint
                .get("receipt")
                .and_then(Value::as_object)
                .is_some_and(|receipt| receipt.len() == 12);
            *index == accepted_index + usize::try_from(max_poll_attempts).unwrap_or(usize::MAX) + 1
                && *index + 1 == checkpoints.len()
                && checkpoint.get("step").and_then(Value::as_str)
                    == Some("poll_in_progress_exhausted")
                && checkpoint.get("performed").and_then(Value::as_bool) == Some(true)
                && checkpoint
                    .get("rectification_required")
                    .and_then(Value::as_bool)
                    == Some(true)
                && checkpoint
                    .pointer("/receipt/provider")
                    .and_then(Value::as_str)
                    == Some("cloudflare")
                && checkpoint
                    .pointer("/receipt/effect")
                    .and_then(Value::as_str)
                    == Some("d1_import_poll_in_progress_exhausted")
                && checkpoint
                    .pointer("/receipt/migration_id")
                    .and_then(Value::as_str)
                    == Some(migration_id.as_str())
                && checkpoint.pointer("/receipt/target") == Some(&target)
                && checkpoint
                    .pointer("/receipt/plan_input_hash")
                    .and_then(Value::as_str)
                    == Some(input_hash.as_str())
                && checkpoint
                    .pointer("/receipt/source_sha256")
                    .and_then(Value::as_str)
                    == Some(source_sha256)
                && checkpoint
                    .pointer("/receipt/at_bookmark")
                    .and_then(Value::as_str)
                    == Some(bookmark.as_str())
                && checkpoint
                    .pointer("/receipt/attempt_count")
                    .and_then(Value::as_u64)
                    == Some(max_poll_attempts)
                && checkpoint
                    .pointer("/receipt/attempt_bound")
                    .and_then(Value::as_u64)
                    == Some(max_poll_attempts)
                && checkpoint
                    .pointer("/receipt/outcome")
                    .and_then(Value::as_str)
                    == Some("poll_in_progress_exhausted")
                && checkpoint
                    .pointer("/receipt/receipt_available")
                    .and_then(Value::as_bool)
                    == Some(true)
                && checkpoint
                    .pointer("/receipt/no_replay")
                    .and_then(Value::as_bool)
                    == Some(true)
                && exact_receipt_shape
        })
        .collect::<Vec<_>>();
    if exhausted.len() != 1 {
        return Err(CliError::Input(
            "poll exhaustion requires exactly one lineage-bound durable receipt".to_owned(),
        ));
    }
    let (_, (hash, checkpoint)) = exhausted[0];
    if store.read_evidence_value(hash)? != *checkpoint {
        return Err(CliError::Input(
            "poll exhaustion evidence does not match its immutable checkpoint".to_owned(),
        ));
    }
    Ok((
        EvidenceV1::new(
            EvidenceClass::Apply,
            hash,
            &store
                .paths()
                .data_dir
                .join("evidence")
                .join(format!("{}.json", hash.trim_start_matches("sha256:")))
                .display()
                .to_string(),
        ),
        checkpoint.clone(),
        EvidenceV1::new(
            EvidenceClass::Apply,
            accepted_hash,
            &store
                .paths()
                .data_dir
                .join("evidence")
                .join(format!(
                    "{}.json",
                    accepted_hash.trim_start_matches("sha256:")
                ))
                .display()
                .to_string(),
        ),
    ))
}
