//! Additive typed intake. No provider adapter or policy activation is exposed.
use cfctl_core::workspace_d1::transition::{
    CompletedRef, RuntimeBinding,
    assurance::{Binding, Declaration},
    execution::Stage,
    proofs::{
        ExecutionRecord, Identity, POLICY_KIND, PolicyDecision, PopulationPhase, Qualification,
        QualificationTarget, RuntimeBindingV4, TransportReceipt,
    },
};
use serde_json::json;

use super::{
    CallInput, EffectRef, EvidenceClass, Phase, PlanStatus, ProofRef, Result, Scope, StateStore,
    Utc, Value, WorkspaceD1MigrationContractV1, canonical_digest, effect, hash_value, invalid,
    observations, publication, read, validate_export,
};
mod case_validation;
mod case_verifier;
mod completed;
mod diagnostic;
mod producers;
mod resource;
mod synthetic_read;
mod verification_producers;

fn qualification(
    store: &StateStore,
    hash: &str,
    expected: &Identity,
    bytes: usize,
    scope: &Scope<'_>,
    now: chrono::DateTime<Utc>,
) -> Result<()> {
    if !canonical_digest(hash) {
        return Err(invalid("qualification hash is not canonical"));
    }
    let evidence = store.load_evidence(hash)?;
    if evidence.class != EvidenceClass::PostChangeVerification || evidence.generated_at >= now {
        return Err(invalid(
            "qualification requires native post-change evidence",
        ));
    }
    let record: Qualification = serde_json::from_value(store.read_evidence_value(hash)?)
        .map_err(|_| invalid("qualification is not the closed V3 transport proof"))?;
    validate_qualification_record(
        store,
        &record,
        expected,
        bytes,
        scope,
        now,
        evidence.generated_at,
        Some(hash),
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "one authenticated qualification join binds scope, source, observation time and optional aggregate identity"
)]
fn validate_qualification_record(
    store: &StateStore,
    record: &Qualification,
    expected: &Identity,
    bytes: usize,
    scope: &Scope<'_>,
    now: chrono::DateTime<Utc>,
    generated_at: chrono::DateTime<Utc>,
    aggregate_hash: Option<&str>,
) -> Result<()> {
    record.validate(expected, bytes).map_err(invalid)?;
    let mut effects = std::collections::BTreeSet::new();
    for case in &record.cases {
        if !effects.insert(&case.effect.operation_id) {
            return Err(invalid("qualification reuses one child effect"));
        }
        let plan = store.load_plan_v2(&case.effect.operation_id)?;
        let failure = case.case.is_failure();
        let status = if failure {
            PlanStatus::RectificationRequired
        } else {
            PlanStatus::Verified
        };
        let target = plan
            .plan
            .targets
            .pointer("/adapter/workspace_d1_transition_qualification");
        let expected_target = QualificationTarget::from_case(expected, case);
        expected_target.validate().map_err(invalid)?;
        let expected_target = serde_json::to_value(expected_target)?;
        if plan.plan.status != status
            || target != Some(&expected_target)
            || plan.plan.account_id != scope.account
            || plan.plan.profile_id != scope.profile
            || plan.plan.catalog_hash != scope.catalog
            || plan.pins.catalog_hash != scope.catalog
            || plan.pins.build_identity_hash != scope.build
            || plan.pins.credential_generation_id != scope.generation
            || plan.plan.capability.path != "workspace:d1-transition-qualification-v1"
            || plan
                .plan
                .transaction_artifact(cfctl_core::TransactionStageV1::VerificationResponsePersisted)
                .and_then(|value| value.get("evidence_hash"))
                .and_then(Value::as_str)
                != Some(case.effect.evidence_hash.as_str())
        {
            return Err(invalid(
                "qualification child is not its exact native typed plan",
            ));
        }
        let child = store.load_evidence(&case.effect.evidence_hash)?;
        if child.class != EvidenceClass::PostChangeVerification || child.generated_at > generated_at
        {
            return Err(invalid(
                "qualification child verification class or chronology differs",
            ));
        }
        let execution = case_verifier::verified_execution(
            store,
            &plan,
            &case.effect.evidence_hash,
            child.generated_at,
        )?;
        case_validation::verify(
            store,
            &plan,
            case,
            expected,
            &execution,
            scope,
            (now, child.generated_at),
            aggregate_hash,
        )?;
    }
    Ok(())
}

fn transport_receipt(
    store: &StateStore,
    terminal: &cfctl_core::workspace_d1::transition::execution::Checkpoint,
    database: &str,
    not_after: chrono::DateTime<Utc>,
) -> Result<chrono::DateTime<Utc>> {
    let hash = terminal
        .provider_receipt_sha256
        .as_deref()
        .ok_or_else(|| invalid("terminal receipt missing"))?;
    let evidence = store.load_evidence(hash)?;
    if evidence.class != EvidenceClass::Apply || evidence.generated_at > not_after {
        return Err(invalid(
            "native import terminal class or chronology differs",
        ));
    }
    let receipt: TransportReceipt = serde_json::from_value(store.read_evidence_value(hash)?)
        .map_err(|_| invalid("native import terminal artifact is malformed"))?;
    receipt.validate(terminal, database).map_err(invalid)?;
    if let Some(error_hash) = &receipt.provider_error_evidence_hash {
        let (at, bookmark) = producers::provider_error(
            store,
            error_hash,
            &terminal.operation_id,
            database,
            evidence.generated_at,
        )?;
        if bookmark != receipt.bookmark_sha256 {
            return Err(invalid("rollback terminal substituted provider bookmark"));
        }
        Ok(at)
    } else {
        Ok(evidence.generated_at)
    }
}

fn policy(
    store: &StateStore,
    contract: &WorkspaceD1MigrationContractV1,
    declaration: &Declaration,
    binding: &Binding,
    scope: &Scope<'_>,
) -> Result<()> {
    binding.validate_mode(declaration).map_err(invalid)?;
    if let (
        Declaration::ManagedD1ApplicationV1 { policy, .. },
        Binding::ManagedD1ApplicationV1 {
            policy_decision, ..
        },
    ) = (declaration, binding)
    {
        let decision_plan = effect(store, policy_decision, scope)?;
        if decision_plan.plan.capability.path != "workspace:d1-assurance-policy-v1"
            || decision_plan.plan.approval.is_none()
        {
            return Err(invalid(
                "managed assurance lacks its explicit native policy decision",
            ));
        }
        let decision: PolicyDecision =
            serde_json::from_value(store.read_evidence_value(&policy_decision.evidence_hash)?)
                .map_err(|_| invalid("managed assurance decision is malformed"))?;
        if decision.schema_version != 1
            || decision.kind != POLICY_KIND
            || decision.identity != Identity::from_contract(contract)?
            || decision.policy_sha256 != policy.sha256
            || decision.assurance_sha256 != hash_value(&serde_json::to_value(declaration)?)?
            || Some(decision.release_id.as_str())
                != contract
                    .transition
                    .as_ref()
                    .and_then(|compiled| compiled.assurance_policy.as_ref())
                    .map(|policy| policy.release_id.as_str())
        {
            return Err(invalid(
                "managed assurance decision is for different reviewed bytes or scope",
            ));
        }
    }
    Ok(())
}

pub(super) fn prepare(
    store: &StateStore,
    contract: &WorkspaceD1MigrationContractV1,
    input: &CallInput,
    scope: &Scope<'_>,
) -> Result<Option<Value>> {
    let binding: RuntimeBindingV4 = serde_json::from_value(
        input
            .body
            .clone()
            .ok_or_else(|| invalid("V4 binding missing"))?,
    )
    .map_err(|_| invalid("V4 runtime binding is malformed or contains unsupported fields"))?;
    if binding.schema_version != 4 {
        return Err(invalid("V4 runtime version differs"));
    }
    let compiled = contract
        .transition
        .as_ref()
        .ok_or_else(|| invalid("V3 source missing"))?;
    let assurance = compiled
        .declaration
        .assurance
        .as_ref()
        .ok_or_else(|| invalid("V4 requires explicit source assurance mode"))?;
    policy(store, contract, assurance, &binding.assurance, scope)?;
    let now = Utc::now();
    let baseline = read(store, &binding.observed_baseline, scope, now)?;
    validate_export(&baseline, compiled, now, false)?;
    let recovery = read(store, &binding.recovery, scope, now)?;
    validate_export(&recovery, compiled, now, true)?;
    if recovery.observed_at < baseline.observed_at {
        return Err(invalid("V4 recovery precedes baseline"));
    }
    let declared = compiled
        .declaration
        .observations
        .as_ref()
        .ok_or_else(|| invalid("V4 observations missing"))?;
    observations::read(
        store,
        contract,
        &declared.baseline,
        &binding.baseline_assertions,
        scope,
        baseline
            .observed_at
            .max(now - chrono::Duration::seconds(600)),
        now,
    )?;
    diagnostic::read(
        store,
        contract,
        assurance,
        binding.assurance.diagnostic(),
        scope,
        recovery.observed_at,
        now,
    )?;
    qualification(
        store,
        &binding.qualification_evidence_hash,
        &Identity::from_contract(contract)?,
        compiled.execution.execution_length,
        scope,
        now,
    )?;
    let completed = completed::validate(store, &binding, scope, now)?;
    let lineage = RuntimeBinding {
        schema_version: 3,
        observed_baseline: binding.observed_baseline.clone(),
        baseline_assertions: binding.baseline_assertions,
        completed,
        recovery: binding.recovery,
        provider_qualification: EffectRef {
            operation_id: String::new(),
            evidence_hash: String::new(),
        },
        publication: binding.publication.clone(),
    };
    super::validate_lineage(compiled, &lineage)?;
    super::validate_completed_observations(store, contract, compiled, &lineage, scope, now)?;
    if let Some(publication) = &binding.publication {
        let verified = publication::validate(store, contract, publication, scope, now)?;
        if recovery.observed_at <= verified {
            return Err(invalid("V4 recovery precedes publication verification"));
        }
    } else if compiled.step().map_err(invalid)?.phase == Phase::PostDeploy {
        return Err(invalid("V4 post-deploy transition lacks publication"));
    }
    Err(invalid(
        "V4 typed proofs resolved; native provider adapter and qualification producers remain disabled pending reviewed admission",
    ))
}

#[cfg(test)]
mod tests;
