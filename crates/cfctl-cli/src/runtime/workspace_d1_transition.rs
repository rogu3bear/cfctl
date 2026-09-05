//! V3 proof intake. This module performs no provider call and grants no execution token.
//! Native receipts can establish provenance; missing application proof producers remain closed.
use cfctl_core::{
    EvidenceClass, OperationalProofOutcomeV1, OperationalProofV1, PlanStatus, PlanV2,
    TransactionStageV1, WorkspaceD1MigrationContractV1, hash_value,
    workspace_d1::transition::{
        Compiled, EffectRef, Phase, ProofRef, RuntimeBinding, canonical_digest,
    },
};
use chrono::{DateTime, Duration, Utc};
use serde_json::Value;

use super::prelude::{CallInput, CliError, Result, StateStore};

struct Scope<'a> {
    account: &'a str,
    profile: &'a str,
    generation: &'a str,
    catalog: &'a str,
    build: &'a str,
}

fn invalid(message: &str) -> CliError {
    CliError::Input(format!("workspace D1 V3: {message}"))
}

fn validate_read(
    proof: &OperationalProofV1,
    reference: &ProofRef,
    scope: &Scope<'_>,
    now: DateTime<Utc>,
) -> Result<()> {
    if !canonical_digest(&reference.proof_hash)
        || !canonical_digest(&reference.evidence_hash)
        || proof.schema_version != 1
        || proof.outcome != OperationalProofOutcomeV1::Succeeded
        || proof.evidence.class != EvidenceClass::LiveRead
        || proof.evidence.content_hash != reference.evidence_hash
        || proof.account_id.as_deref() != Some(scope.account)
        || proof.profile_id.as_deref() != Some(scope.profile)
        || proof.credential_generation_id.as_deref() != Some(scope.generation)
        || proof.catalog_hash != scope.catalog
        || proof.build_identity_hash.as_deref() != Some(scope.build)
        || proof.observed_at >= now
        || proof.evidence.generated_at > now
    {
        return Err(invalid(
            "native read provenance, outcome, scope or observation time differs",
        ));
    }
    Ok(())
}

fn read(
    store: &StateStore,
    reference: &ProofRef,
    scope: &Scope<'_>,
    now: DateTime<Utc>,
) -> Result<OperationalProofV1> {
    let proof = store.load_operational_proof(&reference.proof_hash)?;
    validate_read(&proof, reference, scope, now)?;
    // Authenticated, content-bound read; caller paths and standalone JSON never qualify.
    store.read_evidence_value(&reference.evidence_hash)?;
    Ok(proof)
}

fn validate_export(
    proof: &OperationalProofV1,
    compiled: &Compiled,
    now: DateTime<Utc>,
    fresh: bool,
) -> Result<()> {
    let op = &compiled.declaration;
    let input = CallInput {
        selectors: serde_json::json!({"account_id":op.account_id,"database_id":op.database_id}),
        ..CallInput::default()
    };
    let expected = hash_value(&serde_json::to_value(input)?)?;
    let binding = proof
        .d1_full_export_governed_execution()
        .ok_or_else(|| invalid("export lacks governed native execution binding"))?;
    if proof.capability_id != "d1-full-export"
        || proof.input_hash != expected
        || binding.request_hash != expected
        || binding.capability_id != proof.capability_id
        || binding.completion_status != "completed"
        || binding.completed_at > proof.observed_at
        || binding.catalog_hash != proof.catalog_hash
        || binding.profile_id != op.profile_id
        || proof.credential_generation_id.as_deref()
            != Some(binding.credential_generation_id.as_str())
        || !canonical_digest(&binding.output_file_sha256)
        || !canonical_digest(&binding.at_bookmark_hash)
        || (fresh && proof.observed_at < now - Duration::seconds(600))
    {
        return Err(invalid(
            "export target, completion, digest or freshness differs",
        ));
    }
    Ok(())
}

fn effect(store: &StateStore, reference: &EffectRef, scope: &Scope<'_>) -> Result<PlanV2> {
    let plan = store.load_plan_v2(&reference.operation_id)?;
    validate_effect(&plan, reference, scope)?;
    let evidence = store.load_evidence(&reference.evidence_hash)?;
    if evidence.class != EvidenceClass::PostChangeVerification {
        return Err(invalid("effect requires native post-change verification"));
    }
    store.read_evidence_value(&reference.evidence_hash)?;
    Ok(plan)
}

fn validate_effect(plan: &PlanV2, reference: &EffectRef, scope: &Scope<'_>) -> Result<()> {
    let body = &plan.plan;
    if !canonical_digest(&reference.evidence_hash)
        || body.operation_id != reference.operation_id
        || body.status != PlanStatus::Verified
        || body.transaction_stage != TransactionStageV1::Closed
        || body.account_id != scope.account
        || body.profile_id != scope.profile
        || body.catalog_hash != scope.catalog
        || plan.pins.catalog_hash != scope.catalog
        || plan.pins.build_identity_hash != scope.build
        || plan.pins.credential_generation_id != scope.generation
        || body
            .transaction_artifact(TransactionStageV1::VerificationResponsePersisted)
            .and_then(|a| a.get("evidence_hash"))
            .and_then(Value::as_str)
            != Some(reference.evidence_hash.as_str())
    {
        return Err(invalid(
            "effect is not the exact verified native plan and evidence",
        ));
    }
    Ok(())
}

fn validate_lineage(compiled: &Compiled, binding: &RuntimeBinding) -> Result<()> {
    if binding.schema_version != 3 {
        return Err(invalid("runtime binding version is unsupported"));
    }
    let sequences: Vec<_> = binding.completed.iter().map(|c| c.sequence).collect();
    compiled.validate_completed(&sequences).map_err(invalid)?;
    let mut predecessor = &binding.observed_baseline.evidence_hash;
    for completed in &binding.completed {
        if completed.baseline_evidence_hash != binding.observed_baseline.evidence_hash
            || &completed.predecessor_evidence_hash != predecessor
            || !canonical_digest(&completed.envelope_sha256)
            || completed.preservation.evidence_hash == *predecessor
        {
            return Err(invalid(
                "completed transition substituted baseline or predecessor state",
            ));
        }
        predecessor = &completed.preservation.evidence_hash;
    }
    match (
        compiled.step().map_err(invalid)?.phase,
        &binding.publication,
    ) {
        (Phase::PostDeploy, None) => Err(invalid(
            "post-deploy transition requires publication and verification",
        )),
        (Phase::PreDeploy, Some(_)) => Err(invalid(
            "pre-deploy transition carries an unexpected publication binding",
        )),
        _ => Ok(()),
    }
}

/// Even entirely authentic generic receipts cannot enable the unqualified transport.
/// This is a fail-closed input consumer, not a success-bearing application assertion producer.
pub(super) fn prepare(
    store: &StateStore,
    contract: &WorkspaceD1MigrationContractV1,
    input: &CallInput,
    account: &str,
    profile: &str,
    generation: &str,
    catalog: &str,
) -> Result<Option<Value>> {
    let compiled = contract
        .transition
        .as_ref()
        .ok_or_else(|| invalid("transition contract is missing"))?;
    if contract.manifest_migration.is_some()
        || compiled.declaration.account_id != account
        || compiled.declaration.profile_id != profile
        || input.selectors.get("database_id").and_then(Value::as_str)
            != Some(compiled.declaration.database_id.as_str())
    {
        return Err(invalid("mixed legacy contract or runtime target mismatch"));
    }
    let binding: RuntimeBinding = serde_json::from_value(
        input
            .body
            .clone()
            .ok_or_else(|| invalid("typed runtime binding is required"))?,
    )
    .map_err(|_| invalid("runtime binding is malformed or contains unsupported fields"))?;
    validate_lineage(compiled, &binding)?;
    let build = hash_value(&serde_json::to_value(
        crate::build_identity::current_build_info(),
    )?)?;
    let scope = Scope {
        account,
        profile,
        generation,
        catalog,
        build: &build,
    };
    let now = Utc::now();
    let baseline = read(store, &binding.observed_baseline, &scope, now)?;
    validate_export(&baseline, compiled, now, false)?;
    let recovery = read(store, &binding.recovery, &scope, now)?;
    validate_export(&recovery, compiled, now, true)?;
    if recovery.observed_at < baseline.observed_at {
        return Err(invalid("recovery precedes observed baseline"));
    }
    read(store, &binding.baseline_assertions, &scope, now)?;
    for completed in &binding.completed {
        let plan = effect(store, &completed.effect, &scope)?;
        let prior = plan
            .plan
            .capability
            .workspace_d1_migration
            .as_ref()
            .ok_or_else(|| invalid("prior effect is not a workspace transition"))?;
        let transition = prior
            .transition
            .as_ref()
            .ok_or_else(|| invalid("legacy effect cannot establish a V3 completed transition"))?;
        if prior.repository_head != contract.repository_head
            || prior.operation_pack_sha256 != contract.operation_pack_sha256
            || transition.declaration.target.sequence != completed.sequence
            || transition.envelope_sha256 != completed.envelope_sha256
            || compiled
                .scheduled_targets
                .iter()
                .find(|t| t.sequence == completed.sequence)
                != Some(&transition.declaration.target)
        {
            return Err(invalid(
                "prior transition source, sequence or envelope identity differs",
            ));
        }
        read(store, &completed.preservation, &scope, now)?;
    }
    effect(store, &binding.provider_qualification, &scope)?;
    if let Some(publication) = &binding.publication {
        effect(store, &publication.effect, &scope)?;
        let verified = read(store, &publication.verification, &scope, now)?;
        if recovery.observed_at <= verified.observed_at {
            return Err(invalid(
                "post-deploy recovery must follow publication verification",
            ));
        }
    }
    Err(invalid(
        "native receipt identities resolved; application baseline/preservation and executor qualification semantics are unavailable; V3 production transport is disabled",
    ))
}

#[cfg(test)]
mod tests;
