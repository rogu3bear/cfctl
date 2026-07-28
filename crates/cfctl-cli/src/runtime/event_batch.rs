//! One ordinary plan-gated Cloudflare Queue event-batch transaction.

use std::{collections::BTreeMap, path::Path};

use base64::Engine as _;
use cfctl_auth::{AuthCredential, SecretStore};
use cfctl_catalog::CatalogSnapshot;
use cfctl_cloudflare::{CallInput, Executor};
use cfctl_core::{
    ErrorV1, EventEnvelopeV1, EventSignatureStatusV1, EventUpstreamIdentityV1, EvidenceClass,
    EvidenceV1, PlanStatus, PlanV1, ResourceRefV1, ScopeRefV1, TransactionStageV1,
    VerificationState, redact_json,
};
use cfctl_registry::{EventIngestResultV1, Registry};
use cfctl_storage::StateStore;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{
    API_BASE_URL, ApiVerificationOutcome, CliError, Result, api_plan_result_envelope, http_client,
    persist_secret_lifecycle, persist_transaction_stage, persist_transaction_stage_with_artifact,
    post_boundary_failure_envelope, verification_response_artifact,
};

#[derive(Debug, Clone, Deserialize, Serialize)]
struct VerifiedEventInputV1 {
    schema_version: u8,
    upstream: EventUpstreamIdentityV1,
    upstream_schema_version: u64,
    occurred_at: chrono::DateTime<Utc>,
    received_at: chrono::DateTime<Utc>,
    #[serde(default)]
    scope: Option<ScopeRefV1>,
    dedupe_key: String,
    signature_status: EventSignatureStatusV1,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    resource_refs: Vec<ResourceRefV1>,
    payload: Value,
}

#[derive(Debug, Deserialize)]
struct QueuePullMessageV1 {
    id: String,
    lease_id: String,
    body: Value,
    #[serde(default)]
    metadata: BTreeMap<String, Value>,
}

/// Executes exactly one plan-bound pull, atomic local ingest, and exact lease
/// acknowledgement. No caller-controlled raw Queue capability can enter this
/// boundary.
#[expect(
    clippy::too_many_lines,
    reason = "one plan-gated Queue batch keeps pull, validation, atomic local commit, acknowledgement, and journal finalization in one ordered workflow"
)]
pub(super) async fn execute(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    plan: &mut PlanV1,
    credential: &AuthCredential,
    secrets: &dyn SecretStore,
) -> Result<cfctl_core::ResultEnvelopeV2> {
    let contract = plan.capability.event_batch.clone().ok_or_else(|| {
        CliError::Input("event batch plan omitted its hash-bound execution contract".to_owned())
    })?;
    let input: CallInput = serde_json::from_value(plan.input.clone())?;
    let queue_id = required_selector(&input, "queue_id")?;
    let subscription_id = required_selector(&input, "subscription_id")?;
    let requested_batch_size = input
        .body
        .as_ref()
        .and_then(|body| body.get("batch_size"))
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| {
            CliError::Input("event batch plan omitted its reviewed batch_size".to_owned())
        })?;
    let pull = catalog.get(&contract.pull_capability_id).ok_or_else(|| {
        CliError::Input("event batch pull capability no longer exists".to_owned())
    })?;
    let acknowledge = catalog
        .get(&contract.acknowledge_capability_id)
        .ok_or_else(|| {
            CliError::Input("event batch acknowledgement capability no longer exists".to_owned())
        })?;
    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let transport = executor.event_batch_transport(plan, pull, acknowledge)?;

    let pull_response = match transport.pull(credential).await {
        Ok(response) => response,
        Err(error) => {
            return Ok(recovery_envelope(
                store,
                plan,
                secrets,
                "pull",
                &CliError::from(error),
                false,
                json!({
                    "success": false,
                    "phase": "pull",
                    "outcome": "unknown",
                    "acknowledgement_attempted": false,
                }),
                None,
                Vec::new(),
            ));
        }
    };
    if !pull_response.success {
        return Ok(finish_known_failure(
            store,
            plan,
            secrets,
            CliError::Input("Cloudflare rejected the planned Queue pull".to_owned()),
            json!({
                "success": false,
                "phase": "pull",
                "pull_http_status": pull_response.status,
                "acknowledgement_attempted": false,
            }),
            false,
            Vec::new(),
        ));
    }

    let messages = match queue_pull_messages(&pull_response.result) {
        Ok(messages) => messages,
        Err(error) => {
            return Ok(finish_known_failure(
                store,
                plan,
                secrets,
                error,
                json!({
                    "success": false,
                    "phase": "decode_pull_response",
                    "pull_http_status": pull_response.status,
                    "acknowledgement_attempted": false,
                }),
                false,
                Vec::new(),
            ));
        }
    };
    if messages.len() > requested_batch_size
        || messages.len() > usize::try_from(contract.max_batch_size).unwrap_or(usize::MAX)
    {
        return Ok(finish_known_failure(
            store,
            plan,
            secrets,
            CliError::Input(format!(
                "Cloudflare returned {} Queue messages for a reviewed batch size of {requested_batch_size}",
                messages.len()
            )),
            json!({
                "success": false,
                "phase": "validate_batch_bounds",
                "pull_http_status": pull_response.status,
                "message_count": messages.len(),
                "acknowledgement_attempted": false,
            }),
            false,
            Vec::new(),
        ));
    }

    if messages.is_empty() {
        return Ok(finish_success(
            store,
            plan,
            secrets,
            json!({
                "success": true,
                "queue_id": queue_id,
                "subscription_id": subscription_id,
                "pull_http_status": pull_response.status,
                "acknowledgement_http_status": null,
                "message_count": 0,
                "ingest_results": [],
                "acknowledgement_attempted": false,
            }),
            Vec::new(),
            "the plan-bound Queue pull succeeded and returned no messages; no acknowledgement was required",
        ));
    }

    let inputs = match messages
        .iter()
        .map(|message| decode_queue_event(message, contract.max_message_bytes))
        .collect::<Result<Vec<_>>>()
    {
        Ok(inputs) => inputs,
        Err(error) => {
            return Ok(finish_known_failure(
                store,
                plan,
                secrets,
                error,
                json!({
                    "success": false,
                    "phase": "validate_messages",
                    "pull_http_status": pull_response.status,
                    "message_count": messages.len(),
                    "acknowledgement_attempted": false,
                }),
                false,
                Vec::new(),
            ));
        }
    };
    let mut registry = Registry::open(&store.paths().data_dir)?;
    let (ingest_results, event_evidence) = match ingest_event_inputs(
        store,
        &mut registry,
        &plan.operation_id,
        &queue_id,
        &subscription_id,
        contract.max_batch_size,
        inputs,
    ) {
        Ok(outcome) => outcome,
        Err(error) => {
            return Ok(finish_known_failure(
                store,
                plan,
                secrets,
                error,
                json!({
                    "success": false,
                    "phase": "atomic_registry_ingest",
                    "pull_http_status": pull_response.status,
                    "message_count": messages.len(),
                    "acknowledgement_attempted": false,
                }),
                false,
                Vec::new(),
            ));
        }
    };
    if ingest_results
        .iter()
        .any(|result| !result.acknowledgement_permitted)
    {
        return Ok(finish_known_failure(
            store,
            plan,
            secrets,
            CliError::Input(
                "the atomic event ledger commit did not authorize acknowledgement for every message"
                    .to_owned(),
            ),
            json!({
                "success": false,
                "phase": "acknowledgement_admission",
                "pull_http_status": pull_response.status,
                "message_count": messages.len(),
                "ingest_results": ingest_results,
                "acknowledgement_attempted": false,
            }),
            true,
            event_evidence,
        ));
    }

    let lease_ids = messages
        .iter()
        .map(|message| message.lease_id.clone())
        .collect::<Vec<_>>();
    let acknowledge_response = match transport.acknowledge(&lease_ids, credential).await {
        Ok(response) => response,
        Err(error) => {
            return Ok(recovery_envelope(
                store,
                plan,
                secrets,
                "acknowledge",
                &CliError::from(error),
                true,
                json!({
                    "success": false,
                    "phase": "acknowledge",
                    "outcome": "unknown",
                    "pull_http_status": pull_response.status,
                    "message_count": messages.len(),
                    "ingest_results": ingest_results,
                    "acknowledgement_attempted": true,
                }),
                None,
                event_evidence,
            ));
        }
    };
    if !acknowledge_response.success {
        return Ok(finish_known_failure(
            store,
            plan,
            secrets,
            CliError::Input("Cloudflare rejected the exact Queue acknowledgement batch".to_owned()),
            json!({
                "success": false,
                "phase": "acknowledge",
                "pull_http_status": pull_response.status,
                "acknowledgement_http_status": acknowledge_response.status,
                "message_count": messages.len(),
                "ingest_results": ingest_results,
                "acknowledgement_attempted": true,
            }),
            true,
            event_evidence,
        ));
    }

    Ok(finish_success(
        store,
        plan,
        secrets,
        json!({
            "success": true,
            "queue_id": queue_id,
            "subscription_id": subscription_id,
            "pull_http_status": pull_response.status,
            "acknowledgement_http_status": acknowledge_response.status,
            "message_count": messages.len(),
            "ingest_results": ingest_results,
            "acknowledgement_attempted": true,
        }),
        event_evidence,
        "every message was durably committed to the atomic event ledger before Cloudflare accepted the exact acknowledgement leases",
    ))
}

fn required_selector(input: &CallInput, name: &str) -> Result<String> {
    input
        .selectors
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            CliError::Input(format!(
                "event batch plan omitted its reviewed `{name}` selector"
            ))
        })
}

struct FinalizationFailure {
    error: Box<CliError>,
    apply_evidence: Option<EvidenceV1>,
}

fn finish_success(
    store: &StateStore,
    plan: &mut PlanV1,
    secrets: &dyn SecretStore,
    result: Value,
    event_evidence: Vec<EvidenceV1>,
    verification_basis: &str,
) -> cfctl_core::ResultEnvelopeV2 {
    let apply_evidence =
        match persist_boundary_response(store, plan, secrets, &result, true, "success") {
            Ok(evidence) => evidence,
            Err(failure) => {
                return recovery_envelope(
                    store,
                    plan,
                    secrets,
                    "finalize_success",
                    &failure.error,
                    true,
                    result,
                    failure.apply_evidence,
                    event_evidence,
                );
            }
        };
    let verification = match persist_success_verification(
        store,
        plan,
        &apply_evidence,
        &event_evidence,
        verification_basis,
    ) {
        Ok(verification) => verification,
        Err(error) => {
            return recovery_envelope(
                store,
                plan,
                secrets,
                "finalize_success",
                &error,
                true,
                result,
                Some(apply_evidence),
                event_evidence,
            );
        }
    };
    let mut envelope =
        api_plan_result_envelope(plan, result, apply_evidence, None, verification, true, None);
    envelope.evidence.splice(0..0, event_evidence);
    envelope
}

fn finish_known_failure(
    store: &StateStore,
    plan: &mut PlanV1,
    secrets: &dyn SecretStore,
    error: CliError,
    result: Value,
    performed: bool,
    event_evidence: Vec<EvidenceV1>,
) -> cfctl_core::ResultEnvelopeV2 {
    let apply_evidence =
        match persist_boundary_response(store, plan, secrets, &result, false, "known_no_replay") {
            Ok(evidence) => evidence,
            Err(failure) => {
                return recovery_envelope(
                    store,
                    plan,
                    secrets,
                    "finalize_known_failure",
                    &failure.error,
                    performed,
                    result,
                    failure.apply_evidence,
                    event_evidence,
                );
            }
        };
    plan.status = PlanStatus::Failed;
    let verification = ApiVerificationOutcome {
        state: VerificationState::Failed,
        basis: "the event batch stopped at a known failure and no uncertain acknowledgement will be replayed".to_owned(),
        evidence: None,
        error: Some(ErrorV1 {
            code: "CFCTL_EVENT_BATCH_REJECTED".to_owned(),
            message: error.to_string(),
            next_step: Some(format!(
                "Inspect `cfctl plans status {}` and create a new reviewed batch plan only after correcting the rejected input or Queue state.",
                plan.operation_id
            )),
        }),
        correlated_resource_id: None,
    };
    if let Err(error) = persist_verification_response(store, plan, &verification) {
        return recovery_envelope(
            store,
            plan,
            secrets,
            "finalize_known_failure",
            &error,
            performed,
            result,
            Some(apply_evidence),
            event_evidence,
        );
    }
    let mut envelope = api_plan_result_envelope(
        plan,
        result,
        apply_evidence,
        None,
        verification,
        performed,
        None,
    );
    envelope.evidence.splice(0..0, event_evidence);
    envelope
}

fn persist_boundary_response(
    store: &StateStore,
    plan: &mut PlanV1,
    secrets: &dyn SecretStore,
    result: &Value,
    success: bool,
    outcome: &str,
) -> std::result::Result<EvidenceV1, FinalizationFailure> {
    let apply_evidence = store
        .write_evidence(EvidenceClass::Apply, result)
        .map_err(|error| FinalizationFailure {
            error: Box::new(CliError::from(error)),
            apply_evidence: None,
        })?;
    let retain_apply = |error| FinalizationFailure {
        error: Box::new(error),
        apply_evidence: Some(apply_evidence.clone()),
    };
    persist_transaction_stage_with_artifact(
        store,
        plan,
        TransactionStageV1::BoundaryResponsePersisted,
        json!({
            "adapter": "native_event_batch",
            "apply_evidence_hash": apply_evidence.content_hash,
            "success": success,
            "outcome": outcome,
            "phase": result.get("phase"),
            "message_count": result.get("message_count"),
            "acknowledgement_attempted": result.get("acknowledgement_attempted"),
            "acknowledgement_http_status": result.get("acknowledgement_http_status"),
        }),
    )
    .map_err(&retain_apply)?;
    persist_secret_lifecycle(store, plan, success, None, secrets).map_err(&retain_apply)?;
    persist_transaction_stage(
        store,
        plan,
        TransactionStageV1::VerificationAttemptPersisted,
    )
    .map_err(retain_apply)?;
    Ok(apply_evidence)
}

fn persist_success_verification(
    store: &StateStore,
    plan: &mut PlanV1,
    apply_evidence: &EvidenceV1,
    event_evidence: &[EvidenceV1],
    verification_basis: &str,
) -> Result<ApiVerificationOutcome> {
    let verification_evidence = store.write_evidence(
        EvidenceClass::PostChangeVerification,
        &json!({
            "operation_id": plan.operation_id,
            "strategy": plan.capability.verification.strategy,
            "passed": true,
            "basis": verification_basis,
            "apply_evidence_hash": apply_evidence.content_hash,
            "event_evidence_hashes": event_evidence
                .iter()
                .map(|evidence| evidence.content_hash.as_str())
                .collect::<Vec<_>>(),
        }),
    )?;
    plan.status = PlanStatus::Verified;
    let verification = ApiVerificationOutcome {
        state: VerificationState::Passed,
        basis: verification_basis.to_owned(),
        evidence: Some(verification_evidence),
        error: None,
        correlated_resource_id: None,
    };
    persist_verification_response(store, plan, &verification)?;
    Ok(verification)
}

fn persist_verification_response(
    store: &StateStore,
    plan: &mut PlanV1,
    verification: &ApiVerificationOutcome,
) -> Result<()> {
    persist_transaction_stage_with_artifact(
        store,
        plan,
        TransactionStageV1::VerificationResponsePersisted,
        verification_response_artifact(verification)?,
    )?;
    persist_transaction_stage(store, plan, TransactionStageV1::Closed)
}

#[expect(
    clippy::too_many_arguments,
    reason = "the recovery receipt must retain exact phase, performed truth, result, and any evidence already made durable"
)]
fn recovery_envelope(
    store: &StateStore,
    plan: &mut PlanV1,
    secrets: &dyn SecretStore,
    phase: &str,
    error: &CliError,
    performed: bool,
    result: Value,
    apply_evidence: Option<EvidenceV1>,
    event_evidence: Vec<EvidenceV1>,
) -> cfctl_core::ResultEnvelopeV2 {
    plan.status = PlanStatus::RectificationRequired;
    let mut failures = vec![format!(
        "event batch {phase} outcome requires recovery: {error}"
    )];
    if plan.transaction_stage == TransactionStageV1::BoundaryAttemptPersisted
        && let Err(persist_error) = persist_transaction_stage_with_artifact(
            store,
            plan,
            TransactionStageV1::BoundaryResponsePersisted,
            json!({
                "adapter": "native_event_batch",
                "outcome": "unknown",
                "phase": phase,
                "receipt_available": false,
                "success": false,
                "apply_evidence_hash": apply_evidence
                    .as_ref()
                    .map(|evidence| evidence.content_hash.as_str()),
            }),
        )
    {
        failures.push(format!(
            "boundary recovery receipt persistence failed: {persist_error}"
        ));
    }
    if plan.transaction_stage == TransactionStageV1::BoundaryResponsePersisted
        && let Err(persist_error) = persist_secret_lifecycle(store, plan, false, None, secrets)
    {
        failures.push(format!(
            "secret lifecycle receipt persistence failed: {persist_error}"
        ));
    }
    if let Err(persist_error) = store.save_plan(plan) {
        failures.push(format!(
            "rectification status persistence failed: {persist_error}"
        ));
    }
    let recovery_error = CliError::Input(failures.join("; "));
    let mut envelope = post_boundary_failure_envelope(
        plan,
        result,
        apply_evidence,
        None,
        &recovery_error,
        performed,
        "the plan crossed the Queue batch boundary, but the exact outcome is not fully durable; do not replay pull or acknowledgement",
    );
    envelope.evidence.splice(0..0, event_evidence);
    envelope
}

fn ingest_event_inputs(
    store: &StateStore,
    registry: &mut Registry,
    operation_id: &str,
    queue_id: &str,
    subscription_id: &str,
    max_batch_size: u32,
    inputs: Vec<VerifiedEventInputV1>,
) -> Result<(Vec<EventIngestResultV1>, Vec<EvidenceV1>)> {
    if inputs.is_empty() {
        return Err(CliError::Input("event input batch is empty".to_owned()));
    }
    let batch_size = u32::try_from(inputs.len())
        .map_err(|_| CliError::Input("event input batch is too large".to_owned()))?;
    if batch_size > max_batch_size {
        return Err(CliError::Input(format!(
            "event batch size {batch_size} exceeds plan limit {max_batch_size}"
        )));
    }

    let mut events = Vec::with_capacity(inputs.len());
    let mut evidence_records = Vec::with_capacity(inputs.len());
    for mut input in inputs {
        if input.schema_version != 1 {
            return Err(CliError::Input(format!(
                "event batch input schema version {} is unsupported",
                input.schema_version
            )));
        }
        if matches!(
            input.signature_status,
            EventSignatureStatusV1::Invalid | EventSignatureStatusV1::Unknown
        ) {
            return Err(CliError::Input(format!(
                "event `{}` has no verified provider origin and is not eligible for ingestion or acknowledgement",
                input.dedupe_key
            )));
        }
        if input
            .upstream
            .queue_id
            .as_ref()
            .is_some_and(|queue| queue != queue_id)
            || input
                .upstream
                .subscription_id
                .as_ref()
                .is_some_and(|subscription| subscription != subscription_id)
        {
            return Err(CliError::Input(format!(
                "event `{}` does not match the plan-bound queue/subscription selectors",
                input.dedupe_key
            )));
        }
        input.upstream.queue_id = Some(queue_id.to_owned());
        input.upstream.subscription_id = Some(subscription_id.to_owned());
        let receipt = redact_json(&serde_json::to_value(&input)?);
        let evidence = store.write_evidence(EvidenceClass::EventReceipt, &receipt)?;
        if !Path::new(&evidence.path).is_file() {
            return Err(CliError::Input(
                "event evidence was not durably materialized".to_owned(),
            ));
        }
        evidence_records.push(evidence.clone());
        let event = EventEnvelopeV1::new(
            input.upstream,
            input.upstream_schema_version,
            input.occurred_at,
            input.received_at,
            input.scope,
            input.dedupe_key,
            input.signature_status,
            Some(operation_id.to_owned()),
            input.cursor,
            input.resource_refs,
            input.payload,
            evidence,
        )?;
        events.push(event);
    }
    let results = registry.ingest_event_batch(&events)?;
    Ok((results, evidence_records))
}

fn queue_pull_messages(result: &Value) -> Result<Vec<QueuePullMessageV1>> {
    let messages = result.get("messages").ok_or_else(|| {
        CliError::Input("Cloudflare Queue pull response omitted `result.messages`".to_owned())
    })?;
    serde_json::from_value(messages.clone()).map_err(CliError::from)
}

fn decode_queue_event(
    message: &QueuePullMessageV1,
    max_message_bytes: u64,
) -> Result<VerifiedEventInputV1> {
    if message.id.is_empty() || message.lease_id.is_empty() {
        return Err(CliError::Input(
            "Cloudflare Queue message omitted its immutable id or acknowledgement lease".to_owned(),
        ));
    }
    let content_type = message
        .metadata
        .get("CF-Content-Type")
        .or_else(|| message.metadata.get("cf-content-type"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input(format!(
                "Cloudflare Queue message `{}` omitted CF-Content-Type metadata",
                message.id
            ))
        })?;
    if content_type != "json" {
        return Err(CliError::Input(format!(
            "Cloudflare Queue message `{}` uses unsupported content type `{content_type}`; only normalized JSON event receipts are eligible",
            message.id
        )));
    }
    let encoded = message.body.as_str().ok_or_else(|| {
        CliError::Input(format!(
            "Cloudflare Queue JSON message `{}` did not contain a base64 string body",
            message.id
        ))
    })?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| {
            CliError::Input(format!(
                "Cloudflare Queue JSON message `{}` had an invalid base64 body",
                message.id
            ))
        })?;
    if u64::try_from(decoded.len()).unwrap_or(u64::MAX) > max_message_bytes {
        return Err(CliError::Input(format!(
            "Cloudflare Queue JSON message `{}` exceeded the {max_message_bytes}-byte plan limit",
            message.id,
        )));
    }
    serde_json::from_slice(&decoded).map_err(CliError::from)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::fs;

    use base64::Engine as _;
    use cfctl_auth::MemorySecretStore;
    use cfctl_core::{CapabilityV1, PlanStatus, PlanV1, TransactionStageV1};
    use cfctl_storage::{RuntimePaths, StateStore};
    use chrono::Utc;
    use serde_json::{Value, json};

    use super::{QueuePullMessageV1, decode_queue_event, finish_success};

    #[test]
    fn post_ack_local_failure_requires_rectification_without_replay() {
        let root = tempfile::tempdir().expect("temporary storage root");
        let paths = RuntimePaths::from_root(root.path());
        let store = StateStore::open(paths.clone()).expect("storage opens");
        let capability = CapabilityV1::new(
            cfctl_core::EVENT_BATCH_CAPABILITY_ID,
            "Consume event batch",
            "POST",
            "/cfctl/events/queue-batches/{account_id}/{queue_id}/{subscription_id}",
        );
        let mut plan = PlanV1::draft(
            "profile-a",
            "account-a",
            "sha256:catalog",
            capability,
            json!({}),
        )
        .expect("plan");
        plan.approve(true, None).expect("approve");
        plan.mark_consumed().expect("consume");
        plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
            .expect("boundary attempt");

        fs::remove_dir(paths.data_dir.join("evidence")).expect("remove evidence directory");
        fs::write(paths.data_dir.join("evidence"), b"blocked")
            .expect("replace evidence directory with a file");
        let envelope = finish_success(
            &store,
            &mut plan,
            &MemorySecretStore::default(),
            json!({
                "success": true,
                "acknowledgement_attempted": true,
                "acknowledgement_http_status": 200,
                "message_count": 1,
            }),
            Vec::new(),
            "acknowledgement succeeded",
        );

        assert!(!envelope.ok);
        assert!(envelope.performed);
        assert_eq!(plan.status, PlanStatus::RectificationRequired);
        assert_eq!(
            envelope.error.as_ref().map(|error| error.code.as_str()),
            Some("CFCTL_POST_BOUNDARY_RECOVERY_REQUIRED")
        );
        assert!(
            envelope
                .error
                .as_ref()
                .and_then(|error| error.next_step.as_deref())
                .is_some_and(|next_step| next_step.contains("Do not replay"))
        );
    }

    #[test]
    fn queue_pull_decoder_accepts_only_base64_normalized_json_receipts() {
        let now = Utc::now().to_rfc3339();
        let receipt = json!({
            "schema_version":1,
            "upstream":{
                "provider":"cloudflare",
                "source":"access",
                "event_type":"cf.access.application.created",
                "event_id":"delivery-a"
            },
            "upstream_schema_version":1,
            "occurred_at":now,
            "received_at":now,
            "dedupe_key":"delivery-a",
            "signature_status":"provider_originated",
            "resource_refs":[],
            "payload":{"id":"app-a"}
        });
        let message = QueuePullMessageV1 {
            id: "message-a".to_owned(),
            lease_id: "lease-a".to_owned(),
            body: Value::String(
                base64::engine::general_purpose::STANDARD
                    .encode(serde_json::to_vec(&receipt).expect("receipt JSON")),
            ),
            metadata: [(
                "CF-Content-Type".to_owned(),
                Value::String("json".to_owned()),
            )]
            .into_iter()
            .collect(),
        };
        let decoded = decode_queue_event(&message, 131_072).expect("normalized receipt decodes");
        assert_eq!(decoded.dedupe_key, "delivery-a");

        let mut unsupported = message;
        unsupported
            .metadata
            .insert("CF-Content-Type".to_owned(), Value::String("v8".to_owned()));
        assert!(decode_queue_event(&unsupported, 131_072).is_err());
    }
}
