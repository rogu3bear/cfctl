use cfctl_cloudflare::CallInput;
use cfctl_core::{
    EvidenceClass, OperationalProofOutcomeV1, OperationalProofScopeV1, OperationalProofV1,
    TransactionStageV1, hash_value,
};
use cfctl_storage::StoredPlanRecord;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::runtime::prelude::{
    CatalogSnapshot, CliError, Result, ResultEnvelopeV2, StateStore, VerificationState,
};

pub(crate) const CAPABILITY_ID: &str = "workspace-d1-qualification-observe";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObserverInputV1 {
    schema_version: u8,
    attempted_operation_id: String,
    attempted_plan_hash: String,
    phase: String,
    observation: String,
    source_proof_hash: String,
    source_assertion: Value,
}

#[expect(
    clippy::too_many_lines,
    reason = "the observer keeps the public source proof, exact attempted plan, chronology, and derived proof checks visible as one fail-closed transaction"
)]
pub(crate) fn observe(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    input: &CallInput,
) -> Result<ResultEnvelopeV2> {
    let request: ObserverInputV1 = serde_json::from_value(input.body.clone().ok_or_else(|| {
        CliError::Input("workspace D1 observer requires one closed JSON body".into())
    })?)
    .map_err(|_| CliError::Input("workspace D1 observer input is malformed".into()))?;
    if request.schema_version != 1
        || !matches!(request.phase.as_str(), "before" | "after")
        || !matches!(request.observation.as_str(), "schema" | "ledger")
    {
        return Err(CliError::Input(
            "workspace D1 observer phase, observation, or schema version is invalid".into(),
        ));
    }
    let account_id = selector(input, "account_id")?;
    let database_id = selector(input, "database_id")?;
    let plan = match store.load_stored_plan_record(&request.attempted_operation_id)? {
        StoredPlanRecord::Current(plan) => *plan,
        _ => {
            return Err(CliError::Input(
                "workspace D1 observer requires one current PlanV2".into(),
            ));
        }
    };
    if plan.plan.content_hash != request.attempted_plan_hash
        || plan.plan.capability.id != "mln-web.founder-d1-migration-apply"
        || plan.plan.account_id != account_id
        || plan.plan.catalog_hash != catalog.schema_hash
        || plan
            .plan
            .input
            .pointer("/selectors/database_id")
            .and_then(Value::as_str)
            != Some(database_id)
    {
        return Err(CliError::Input(
            "workspace D1 observer attempted plan identity or target drifted".into(),
        ));
    }
    let boundary = |stage| {
        plan.plan
            .transaction_journal
            .iter()
            .find(|checkpoint| checkpoint.stage == stage)
            .map(|checkpoint| checkpoint.recorded_at)
            .ok_or_else(|| {
                CliError::Input("workspace D1 observer plan lacks a boundary receipt".into())
            })
    };
    let attempted_at = boundary(TransactionStageV1::BoundaryAttemptPersisted)?;
    let responded_at = boundary(TransactionStageV1::BoundaryResponsePersisted)?;

    let source = store.load_operational_proof(&request.source_proof_hash)?;
    let expected_source_input = hash_value(&serde_json::to_value(CallInput {
        selectors: json!({"account_id":account_id,"database_id":database_id}),
        query: json!({}),
        body: Some(request.source_assertion.clone()),
        if_match: None,
        if_none_match: None,
    })?)?;
    if source.capability_id != "d1-schema-introspection"
        || source.catalog_hash != catalog.schema_hash
        || source.input_hash != expected_source_input
        || source.evidence.class != EvidenceClass::LiveRead
        || source.outcome != OperationalProofOutcomeV1::Succeeded
        || source.account_id.as_deref() != Some(account_id)
        || source.profile_id.as_deref() != Some(&plan.plan.profile_id)
        || source.credential_generation_id.as_deref() != Some(&plan.pins.credential_generation_id)
        || source.build_identity_hash.as_deref() != Some(&plan.pins.build_identity_hash)
        || (request.phase == "before" && source.observed_at >= attempted_at)
        || (request.phase == "after" && source.observed_at <= responded_at)
    {
        return Err(CliError::Input(
            "workspace D1 observer source proof is not current, scoped, and strictly bracketing"
                .into(),
        ));
    }
    let source_body = store.read_evidence_value(&source.evidence.content_hash)?;
    let object = source_body.as_object().ok_or_else(|| {
        CliError::Input(
            "workspace D1 observer source body is not a public response envelope".into(),
        )
    })?;
    if object.len() != 8
        || ![
            "status",
            "success",
            "result",
            "errors",
            "result_info",
            "etag",
            "cf_ray",
            "availability",
        ]
        .iter()
        .all(|field| object.contains_key(*field))
        || source_body.get("status").and_then(Value::as_u64) != Some(200)
        || source_body.get("success").and_then(Value::as_bool) != Some(true)
        || !source_body
            .get("availability")
            .is_some_and(Value::is_object)
    {
        return Err(CliError::Input(
            "workspace D1 observer source proof lacks the actual public success envelope".into(),
        ));
    }
    let assertion_hash = hash_value(&request.source_assertion)?;
    let query = source_body.pointer("/result_info/query").ok_or_else(|| {
        CliError::Input("workspace D1 observer source proof lacks its query receipt".into())
    })?;
    if query.get("kind").and_then(Value::as_str) != Some("d1_schema_introspection")
        || query.get("assertion_input_sha256").and_then(Value::as_str) != Some(&assertion_hash)
        || query.get("caller_sql").and_then(Value::as_bool) != Some(false)
        || query.get("read_only").and_then(Value::as_bool) != Some(true)
        || (request.observation == "ledger"
            && request
                .source_assertion
                .get("assertion")
                .and_then(Value::as_str)
                != Some("migration_ledger_equals"))
        || (request.observation == "schema"
            && request
                .source_assertion
                .get("assertion")
                .and_then(Value::as_str)
                == Some("migration_ledger_equals"))
    {
        return Err(CliError::Input(
            "workspace D1 observer source assertion receipt does not match its observation role"
                .into(),
        ));
    }
    let observation = json!({
        "schema_version":1,
        "kind":"workspace_d1_state_observation_v1",
        "observation":request.observation,
        "phase":request.phase,
        "attempted_operation_id":request.attempted_operation_id,
        "attempted_plan_hash":request.attempted_plan_hash,
        "observed_at":source.observed_at,
        "source_proof_hash":request.source_proof_hash,
        "source_evidence_hash":source.evidence.content_hash,
        "source_input_hash":source.input_hash,
        "semantic_state":{
            "assertion_input_sha256":assertion_hash,
            "result":source_body.get("result").cloned().unwrap_or(Value::Null),
        }
    });
    let evidence = store.write_evidence(EvidenceClass::LiveRead, &observation)?;
    let observer_input_hash = hash_value(&serde_json::to_value(input)?)?;
    let mut proof = OperationalProofV1::new(
        source.observed_at,
        CAPABILITY_ID,
        &catalog.schema_hash,
        &observer_input_hash,
        OperationalProofScopeV1::new(
            source.profile_id.as_deref(),
            source.account_id.as_deref(),
            source.credential_generation_id.as_deref(),
        ),
        OperationalProofOutcomeV1::Succeeded,
        evidence.clone(),
    );
    proof.bind_build_identity_hash(source.build_identity_hash.as_deref().ok_or_else(|| {
        CliError::Input("workspace D1 observer source proof lacks build identity".into())
    })?)?;
    store.record_operational_proof(&proof)?;
    let proof_hash = store.operational_proof_hash(&proof)?;
    let mut envelope = ResultEnvelopeV2::success(
        "call",
        json!({
            "schema_version":1,
            "kind":"workspace_d1_qualification_observation_result_v1",
            "performed_provider_boundary":false,
            "proof_hash":proof_hash,
            "evidence_hash":evidence.content_hash,
        }),
    );
    envelope.capability_id = Some(CAPABILITY_ID.into());
    envelope.profile_id = source.profile_id;
    envelope.account_id = source.account_id;
    envelope.evidence.push(evidence);
    envelope.verification.state = VerificationState::Passed;
    envelope.verification.basis = Some(
        "one public d1-schema-introspection proof was bound to one exact attempted PlanV2 and strict temporal phase"
            .into(),
    );
    Ok(envelope)
}

fn selector<'a>(input: &'a CallInput, name: &str) -> Result<&'a str> {
    input
        .selectors
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input(format!("workspace D1 observer omitted `{name}`")))
}
