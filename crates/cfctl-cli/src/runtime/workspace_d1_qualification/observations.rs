use cfctl_cloudflare::CloudflareResponseV1;
use cfctl_core::{WorkspaceD1ZeroDeltaComparisonV1, hash_value};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;

use super::{PlanExpectation, ProofExpectation, validate_proof};
use crate::runtime::prelude::{CliError, Result, StateStore};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StateObservationV1 {
    schema_version: u8,
    kind: String,
    observation: String,
    observed_at: DateTime<Utc>,
    state: Value,
}

pub(super) fn derive_zero_delta_comparison(
    store: &StateStore,
    expected_observation: &str,
    before: &ProofExpectation<'_>,
    after: &ProofExpectation<'_>,
    attempted: &PlanExpectation<'_>,
) -> Result<WorkspaceD1ZeroDeltaComparisonV1> {
    let (before_proof, before_body) = validate_proof(store, before)?;
    let (after_proof, after_body) = validate_proof(store, after)?;
    let before_observation: StateObservationV1 = serde_json::from_value(before_body)
        .map_err(|_| CliError::Input("workspace D1 before observation is malformed".to_owned()))?;
    let after_observation: StateObservationV1 = serde_json::from_value(after_body)
        .map_err(|_| CliError::Input("workspace D1 after observation is malformed".to_owned()))?;
    if before.proof_hash == after.proof_hash
        || before.evidence_hash == after.evidence_hash
        || before_observation.schema_version != 1
        || after_observation.schema_version != 1
        || before_observation.kind != "workspace_d1_state_observation_v1"
        || after_observation.kind != "workspace_d1_state_observation_v1"
        || before_observation.observation != expected_observation
        || after_observation.observation != expected_observation
        || before_observation.observed_at != before_proof.observed_at
        || after_observation.observed_at != after_proof.observed_at
        || before_proof.observed_at >= after_proof.observed_at
        || before_proof.observed_at > attempted.boundary_attempted_at
        || after_proof.observed_at < attempted.boundary_responded_at
    {
        return Err(CliError::Input(
            "workspace D1 zero-delta observations are not distinct and temporally bracketing"
                .to_owned(),
        ));
    }
    let before_state_hash = hash_value(&before_observation.state)?;
    let after_state_hash = hash_value(&after_observation.state)?;
    if before_state_hash != after_state_hash {
        return Err(CliError::Input(
            "workspace D1 zero-delta observations changed semantic state".to_owned(),
        ));
    }
    Ok(WorkspaceD1ZeroDeltaComparisonV1 {
        observation: expected_observation.to_owned(),
        attempted_operation_id: attempted.operation_id.to_owned(),
        before_proof_hash: before.proof_hash.to_owned(),
        before_evidence_hash: before.evidence_hash.to_owned(),
        before_observed_at: before_proof.observed_at,
        after_proof_hash: after.proof_hash.to_owned(),
        after_evidence_hash: after.evidence_hash.to_owned(),
        after_observed_at: after_proof.observed_at,
        semantic_state_sha256: before_state_hash,
        zero_delta: true,
    })
}

pub(super) fn validate_cleanup_absence_body(body: Value) -> Result<()> {
    let exact_shape = body.as_object().is_some_and(|object| {
        object.len() == 7
            && [
                "status",
                "success",
                "result",
                "errors",
                "result_info",
                "etag",
                "cf_ray",
            ]
            .iter()
            .all(|field| object.contains_key(*field))
    });
    let response: CloudflareResponseV1 = serde_json::from_value(body)
        .map_err(|_| CliError::Input("workspace D1 cleanup proof body is malformed".to_owned()))?;
    if !exact_shape
        || response.status != 404
        || response.success
        || !response.result.is_null()
        || response.errors.len() != 1
        || response.errors[0].code.is_none()
        || response.errors[0].message.trim().is_empty()
        || response.result_info.is_some()
    {
        return Err(CliError::Input(
            "workspace D1 cleanup proof is not an exact-database not-found outcome".to_owned(),
        ));
    }
    Ok(())
}
