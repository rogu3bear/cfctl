//! Source-prepared synthetic resource joins. No public dispatch or provider calls.
use super::{EvidenceClass, PlanStatus, Result, Scope, StateStore, Utc, Value, effect, invalid};
use cfctl_cloudflare::{CloudflareResponseV1, OperationVerificationV1};
use cfctl_core::{
    PlanV2, TransactionStageV1,
    workspace_d1::transition::{
        EffectRef,
        admission::{
            Role,
            resource::{ReadPhase, Resource, SeedTarget, SeededCleanupTarget},
        },
        proofs::{Case, Identity},
    },
};
use cfctl_workspace::{BoundQualificationSource, MaterializedPopulation};

fn approved(plan: &PlanV2) -> Result<()> {
    plan.validate()?;
    if plan
        .plan
        .approval
        .as_ref()
        .map(|approval| approval.approved_content_hash.as_str())
        != Some(plan.plan.content_hash.as_str())
    {
        return Err(invalid(
            "synthetic child requires exact native plan approval",
        ));
    }
    Ok(())
}

fn created_uuid(
    apply: &CloudflareResponseV1,
    verification: &OperationVerificationV1,
    name: &str,
) -> Result<String> {
    let readback = &verification.readback;
    let uuid = apply
        .result
        .get("uuid")
        .and_then(Value::as_str)
        .filter(|value| uuid::Uuid::parse_str(value).is_ok_and(|id| id.to_string() == *value))
        .ok_or_else(|| invalid("synthetic create did not return a canonical UUID"))?;
    if !apply.success
        || !(200..300).contains(&apply.status)
        || !apply.errors.is_empty()
        || !verification.passed
        || verification.strategy != "created_resource_contains_planned_fields_by_returned_id"
        || !readback.success
        || readback.status != 200
        || !readback.errors.is_empty()
        || apply.result.get("name").and_then(Value::as_str) != Some(name)
        || readback.result.get("name").and_then(Value::as_str) != Some(name)
        || readback.result.get("uuid").and_then(Value::as_str) != Some(uuid)
    {
        return Err(invalid(
            "synthetic create apply and exact resource readback differ",
        ));
    }
    Ok(uuid.into())
}

/// Authentication precedes any runtime UUID materialization. No caller ID is used.
pub(super) fn resolve_created(
    store: &StateStore,
    bound: &BoundQualificationSource,
    case: Case,
    reference: &EffectRef,
    scope: &Scope<'_>,
) -> Result<Resource> {
    cfctl_workspace::revalidate_qualification_source(bound)?;
    let identity = Identity::from_contract(&bound.transition)?;
    let source = bound
        .pack
        .cases
        .iter()
        .find(|source| source.case == case)
        .ok_or_else(|| invalid("synthetic create case is not committed"))?;
    let plan = effect(store, reference, scope)?;
    approved(&plan)?;
    let capability = &plan.plan.capability;
    let created = capability
        .created_resource
        .as_ref()
        .ok_or_else(|| invalid("synthetic create lacks returned-resource identity contract"))?;
    if identity.account_id != scope.account
        || capability.id != "d1-create-database"
        || capability.method != "POST"
        || capability.path != "/accounts/{account_id}/d1/database"
        || capability.verification.strategy
            != "created_resource_contains_planned_fields_by_returned_id"
        || created.response_result_identity_pointer != "/uuid"
        || created.identity_selector != "database_id"
        || created.detail_path != "/accounts/{account_id}/d1/database/{database_id}"
        || created.read_capability_id != "d1-get-database"
        || plan.plan.input.get("selectors")
            != Some(&serde_json::json!({"account_id":scope.account}))
        || plan.plan.input.get("body") != Some(&serde_json::json!({"name":source.resource_name}))
    {
        return Err(invalid(
            "synthetic create source, exact name or account differs",
        ));
    }
    let apply_hash = plan
        .plan
        .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
        .and_then(|value| value.get("evidence_hash"))
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("synthetic create apply artifact missing"))?;
    let apply_evidence = store.load_evidence(apply_hash)?;
    let verified = store.load_evidence(&reference.evidence_hash)?;
    if apply_evidence.class != EvidenceClass::Apply
        || apply_evidence.generated_at > verified.generated_at
        || verified.generated_at > Utc::now()
    {
        return Err(invalid(
            "synthetic create evidence class or chronology differs",
        ));
    }
    let apply: CloudflareResponseV1 =
        serde_json::from_value(store.read_evidence_value(apply_hash)?)?;
    let verification: OperationVerificationV1 =
        serde_json::from_value(store.read_evidence_value(&reference.evidence_hash)?)?;
    let resource = Resource {
        schema_version: 1,
        identity: identity.clone(),
        qualification_pack_sha256: bound.qualification_pack_sha256.clone(),
        case,
        resource_name: source.resource_name.clone(),
        create: reference.clone(),
        create_plan_sha256: plan.plan.content_hash.clone(),
        database_id: created_uuid(&apply, &verification, &source.resource_name)?,
    };
    resource
        .validate(&bound.pack, &identity, &bound.qualification_pack_sha256)
        .map_err(invalid)?;
    Ok(resource)
}

pub(super) fn prepare_population(
    store: &StateStore,
    bound: &BoundQualificationSource,
    target: (Case, ReadPhase),
    create: &EffectRef,
    scope: &Scope<'_>,
) -> Result<MaterializedPopulation> {
    let resource = resolve_created(store, bound, target.0, create, scope)?;
    let population =
        cfctl_workspace::materialize_qualification_population(bound, &resource, target.1)?;
    cfctl_cloudflare::d1_read_inventory::validate_inventory(&population.inventory)?;
    Ok(population)
}

/// Prepare a separate seeded-delete target; never use empty-create compensation.
#[expect(
    dead_code,
    reason = "seeded cleanup plan/executor remains unregistered"
)]
pub(super) fn prepare_cleanup(
    store: &StateStore,
    bound: &BoundQualificationSource,
    target: &SeededCleanupTarget,
    scope: &Scope<'_>,
) -> Result<()> {
    let resource = resolve_created(
        store,
        bound,
        target.resource.case,
        &target.resource.create,
        scope,
    )?;
    if resource != target.resource {
        return Err(invalid("seeded cleanup create lineage differs"));
    }
    let case = resource
        .validate(
            &bound.pack,
            &resource.identity,
            &bound.qualification_pack_sha256,
        )
        .map_err(invalid)?;
    let length = |path: &str| {
        bound
            .source_lengths
            .get(path)
            .copied()
            .ok_or_else(|| invalid("seeded cleanup source length missing"))
    };
    target
        .validate(
            &bound.pack,
            &resource.identity,
            &bound.qualification_pack_sha256,
            length(&case.execution.path)?,
        )
        .map_err(invalid)?;
    // Recheck current clean committed source, including the terminal inventory.
    cfctl_workspace::materialize_qualification_population(bound, &resource, ReadPhase::After)?;
    let seed_time = verified_seed(store, bound, &resource, &target.seed, case, scope)?;
    let plan = store.load_plan_v2(&target.terminal.effect.operation_id)?;
    let verified = store.load_evidence(&target.terminal.effect.evidence_hash)?;
    let create_time = store
        .load_evidence(&resource.create.evidence_hash)?
        .generated_at;
    let now = Utc::now();
    if plan.plan.status
        != if case.case.is_failure() {
            PlanStatus::RectificationRequired
        } else {
            PlanStatus::Verified
        }
        || plan
            .plan
            .transaction_artifact(TransactionStageV1::VerificationResponsePersisted)
            .and_then(|value| value.get("evidence_hash"))
            .and_then(Value::as_str)
            != Some(target.terminal.effect.evidence_hash.as_str())
        || !(create_time < seed_time
            && seed_time < verified.generated_at
            && verified.generated_at <= now)
    {
        return Err(invalid(
            "seeded cleanup lacks ordered terminal native child verification",
        ));
    }
    let execution = super::case_verifier::verified_execution(
        store,
        &plan,
        &target.terminal.effect.evidence_hash,
        verified.generated_at,
    )?;
    super::case_validation::verify(
        store,
        &plan,
        &target.terminal,
        &resource.identity,
        &execution,
        scope,
        (now, verified.generated_at),
        None,
    )?;
    let before = super::read(store, &target.terminal.before, scope, now)?;
    if before.observed_at <= seed_time {
        return Err(invalid("case baseline must follow verified seed"));
    }
    Ok(())
}

fn verified_seed(
    store: &StateStore,
    bound: &BoundQualificationSource,
    resource: &Resource,
    reference: &EffectRef,
    source: &cfctl_core::workspace_d1::transition::admission::CaseSource,
    scope: &Scope<'_>,
) -> Result<chrono::DateTime<Utc>> {
    let seed = effect(store, reference, scope)?;
    approved(&seed)?;
    let seed_target = SeedTarget {
        resource: resource.clone(),
        source: source.seed.clone(),
        bytes: bound
            .source_lengths
            .get(&source.seed.path)
            .copied()
            .ok_or_else(|| invalid("seed source length missing"))?,
    };
    let seed_value = serde_json::to_value(&seed_target)?;
    let seed_id = bound
        .pack
        .operation
        .iter()
        .find(|op| op.role == Role::Seed)
        .ok_or_else(|| invalid("seed operation missing"))?;
    if seed.plan.capability.id != seed_id.id
        || seed.plan.capability.path != Role::Seed.path()
        || seed
            .plan
            .targets
            .pointer("/adapter/workspace_d1_transition_seed")
            != Some(&seed_value)
        || seed.plan.input.get("body") != Some(&seed_value)
        || seed.plan.input.get("selectors")
            != Some(
                &serde_json::json!({"account_id":scope.account,"database_id":resource.database_id}),
            )
    {
        return Err(invalid(
            "seeded cleanup seed is not its exact source-bound child",
        ));
    }
    Ok(store.load_evidence(&reference.evidence_hash)?.generated_at)
}

#[cfg(test)]
mod tests;
