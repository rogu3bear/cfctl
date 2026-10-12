//! Shared producer/consumer join for an exact native qualification child.
use super::{
    ExecutionRecord, Identity, PopulationPhase, Result, Scope, Stage, StateStore, Utc, Value,
    canonical_digest, case_verifier, invalid, producers, read, transport_receipt,
};
use cfctl_core::{
    PlanV2,
    workspace_d1::transition::proofs::{CaseRef, QualificationTarget},
};
#[expect(
    clippy::too_many_arguments,
    reason = "one exact child join authenticates source, plan, read scope and chronology"
)]
#[expect(
    clippy::too_many_lines,
    reason = "all population and transport identities are joined before producer or consumer acceptance"
)]
pub(super) fn verify(
    store: &StateStore,
    plan: &PlanV2,
    case: &CaseRef,
    expected: &Identity,
    execution: &ExecutionRecord,
    scope: &Scope<'_>,
    times: (chrono::DateTime<Utc>, chrono::DateTime<Utc>),
    aggregate_hash: Option<&str>,
) -> Result<()> {
    let (now, not_after) = times;
    let target = QualificationTarget::from_case(expected, case);
    target.validate().map_err(invalid)?;
    case_verifier::plan_scope(plan, scope)?;
    if plan.plan.operation_id != case.effect.operation_id
        || plan.plan.capability.path != "workspace:d1-transition-qualification-v1"
        || plan
            .plan
            .approval
            .as_ref()
            .map(|approval| approval.approved_content_hash.as_str())
            != Some(plan.plan.content_hash.as_str())
        || plan
            .plan
            .targets
            .pointer("/adapter/workspace_d1_transition_qualification")
            != Some(&serde_json::to_value(target)?)
        || plan
            .plan
            .input
            .pointer("/selectors/account_id")
            .and_then(Value::as_str)
            != Some(scope.account)
        || plan
            .plan
            .input
            .pointer("/selectors/database_id")
            .and_then(Value::as_str)
            != Some(case.synthetic_database_id.as_str())
    {
        return Err(invalid(
            "native child source, approval, input or exact plan differs",
        ));
    }
    let failure = case.case.is_failure();
    let terminal = execution.terminal().map_err(invalid)?;
    let mut case_identity = expected.clone();
    case_identity
        .execution_sha256
        .clone_from(&case.fixture_sha256);
    if terminal.operation_id != case.effect.operation_id
        || terminal.identity != case_identity
        || terminal.stage
            != if failure {
                Stage::RolledBack
            } else {
                Stage::Committed
            }
        || terminal.qualification_evidence_hash == aggregate_hash.unwrap_or("")
        || terminal.plan_hash != plan.plan.content_hash
    {
        return Err(invalid(
            "qualification child identity, terminal or recursive proof differs",
        ));
    }
    let times = case_verifier::verify(&case_verifier::Join {
        store,
        plan,
        case,
        identity: expected,
        record: execution,
        scope,
        not_after,
    })?;
    let boundary_at = transport_receipt(store, terminal, &case.synthetic_database_id, not_after)?;
    let before = read(store, &case.before, scope, now)?;
    let after = read(store, &case.after, scope, now)?;
    if before.capability_id != cfctl_core::workspace_d1::transition::proofs::POPULATION_CAPABILITY
        || after.capability_id
            != cfctl_core::workspace_d1::transition::proofs::POPULATION_CAPABILITY
    {
        return Err(invalid(
            "qualification population lacks the typed native producer",
        ));
    }
    if before.observed_at >= times.dispatch
        || after.observed_at <= boundary_at
        || after.observed_at > not_after
    {
        return Err(invalid(
            "qualification population observations do not bracket the child",
        ));
    }
    for (phase, observation) in [
        (PopulationPhase::Before, &case.before),
        (PopulationPhase::After, &case.after),
    ] {
        let body: cfctl_core::workspace_d1::transition::proofs::Population =
            serde_json::from_value(store.read_evidence_value(&observation.evidence_hash)?)
                .map_err(|_| {
                    invalid("qualification population is not the closed native producer record")
                })?;
        producers::validate_population(store, &body, (case, phase), expected, scope, now)?;
    }
    let after = store.read_evidence_value(&case.after.evidence_hash)?;
    if after.get("semantic_state_sha256").and_then(Value::as_str)
        != Some(case.expected_after_state_sha256.as_str())
    {
        return Err(invalid(
            "qualification final population differs from reviewed synthetic oracle",
        ));
    }
    if failure {
        let before = store.read_evidence_value(&case.before.evidence_hash)?;
        let after = store.read_evidence_value(&case.after.evidence_hash)?;
        let state = before
            .get("semantic_state_sha256")
            .and_then(Value::as_str)
            .filter(|value| canonical_digest(value))
            .ok_or_else(|| invalid("rollback state digest missing"))?;
        if after.get("semantic_state_sha256").and_then(Value::as_str) != Some(state) {
            return Err(invalid(
                "failed qualification changed synthetic schema, ledger or population",
            ));
        }
    }
    Ok(())
}
