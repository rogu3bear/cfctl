//! A source omission on the first deployment needs authenticated native custody.
use super::prelude::{
    CallInput, CatalogSnapshot, CliError, EvidenceClass, PlanStatus, PlanV1, PlanV2,
    ProfileMetadata, Result, StateStore, TransactionStageV1, Utc, Value, json,
};
use super::read_execution::credential_generation_for_read;
use cfctl_core::{hash_value, pages_projects as contract};
use chrono::{DateTime, Utc as ChronoUtc};

fn refused() -> CliError {
    CliError::Input("the source-less initial Pages project has no current authenticated native direct-create proof bound to this project ID, account, profile generation, catalog and build; the deployment boundary was not crossed".to_owned())
}

fn provenance(plan: &PlanV2, project: &Value, apply_hash: &str) -> Result<Value> {
    Ok(json!({
        "schema_version":1,"operation_id":plan.plan.operation_id,
        "plan_content_hash":plan.plan.content_hash,"pins_hash":hash_value(&serde_json::to_value(&plan.pins)?)?,
        "profile_id":plan.plan.profile_id,"credential_generation_id":plan.pins.credential_generation_id,
        "account_id":plan.plan.account_id,"catalog_hash":plan.pins.catalog_hash,
        "build_identity_hash":plan.pins.build_identity_hash,
        "project_name":project["name"],"project_id":project["id"],"production_branch":"main",
        "apply_evidence_hash":apply_hash,"expires_at":plan.plan.expires_at,
    }))
}

/// Called only after the native verifier passes. The final authenticated payload
/// binds execution pins as well as the response, so a stored response cannot be
/// borrowed by a fabricated plan or another credential generation.
pub(super) fn attach_verification_context(
    store: &StateStore,
    plan: &PlanV1,
    verification: &mut Value,
) -> Result<()> {
    if plan.capability.id != contract::CREATE_ID || verification["passed"] != true {
        return Ok(());
    }
    let current = store.load_plan_v2(&plan.operation_id)?;
    let input: CallInput = serde_json::from_value(plan.input.clone())?;
    let project = &verification["readback"]["result"];
    let name = input
        .body
        .as_ref()
        .and_then(|body| body.get("name"))
        .and_then(Value::as_str)
        .ok_or_else(refused)?;
    if current.plan.content_hash != plan.content_hash
        || current.plan.capability != plan.capability
        || !contract::contract_supported(&plan.capability)
        || verification["strategy"] != contract::CREATE_STRATEGY
        || !contract::project_is_direct(project, name)
    {
        return Err(refused());
    }
    let apply_hash = plan
        .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
        .and_then(|artifact| artifact.get("apply_evidence_hash"))
        .and_then(Value::as_str)
        .ok_or_else(refused)?;
    verification["pages_direct_create"] = provenance(&current, project, apply_hash)?;
    Ok(())
}

pub(super) fn find(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    profile: &ProfileMetadata,
    account_id: &str,
    project_name: &str,
    project: &Value,
) -> Result<Value> {
    find_at(
        store,
        catalog,
        profile,
        account_id,
        project_name,
        project,
        Utc::now(),
    )
}

pub(super) fn find_at(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    profile: &ProfileMetadata,
    account_id: &str,
    project_name: &str,
    project: &Value,
    now: DateTime<ChronoUtc>,
) -> Result<Value> {
    let generation = credential_generation_for_read(profile)?;
    let build_hash = hash_value(&serde_json::to_value(
        crate::build_identity::current_build_info(),
    )?)?;
    if !contract::project_is_direct(project, project_name)
        || profile.account_id.as_deref() != Some(account_id)
    {
        return Err(refused());
    }
    let current_capability = catalog.get(contract::CREATE_ID).ok_or_else(refused)?;
    if !contract::contract_supported(current_capability) {
        return Err(refused());
    }
    let plans = store.list_plans()?;
    for candidate in plans.iter().rev().filter(|plan| {
        plan.capability.id == contract::CREATE_ID
            && plan.profile_id == profile.id
            && plan.account_id == account_id
            && plan.status == PlanStatus::Verified
            && plan.input.pointer("/body/name").and_then(Value::as_str) == Some(project_name)
    }) {
        let plan = store.load_plan_v2(&candidate.operation_id)?;
        if &plan.plan != candidate
            || plan.plan.capability != *current_capability
            || plan.plan.transaction_stage != TransactionStageV1::Closed
            || plan.pins.catalog_hash != catalog.schema_hash
            || plan.pins.credential_generation_id != generation
            || plan.pins.build_identity_hash != build_hash
            || now < plan.plan.created_at
            || now > plan.plan.expires_at
        {
            continue;
        }
        if let Some(proof) = load_qualified_proof(store, &plan, project, now)? {
            return Ok(proof);
        }
    }
    Err(refused())
}

fn load_qualified_proof(
    store: &StateStore,
    plan: &PlanV2,
    project: &Value,
    now: DateTime<ChronoUtc>,
) -> Result<Option<Value>> {
    let boundary = plan
        .plan
        .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
        .ok_or_else(refused)?;
    let terminal = plan
        .plan
        .transaction_artifact(TransactionStageV1::VerificationResponsePersisted)
        .ok_or_else(refused)?;
    let apply_hash = boundary
        .get("apply_evidence_hash")
        .and_then(Value::as_str)
        .ok_or_else(refused)?;
    let verification_hash = terminal
        .get("evidence_hash")
        .and_then(Value::as_str)
        .ok_or_else(refused)?;
    let (apply_descriptor, apply) = store.load_evidence_value(apply_hash)?;
    let (descriptor, verification) = store.load_evidence_value(verification_hash)?;
    let proof = provenance(plan, project, apply_hash)?;
    let name = project["name"].as_str().ok_or_else(refused)?;
    let exact = apply_descriptor.class == EvidenceClass::Apply
        && descriptor.class == EvidenceClass::PostChangeVerification
        && apply_descriptor.generated_at >= plan.plan.created_at
        && descriptor.generated_at >= apply_descriptor.generated_at
        && descriptor.generated_at <= now
        && descriptor.generated_at <= plan.plan.expires_at
        && now <= plan.plan.expires_at
        && boundary["success"] == true
        && boundary["resource_id"] == project["name"]
        && terminal["state"] == "passed"
        && verification["passed"] == true
        && verification["strategy"] == contract::CREATE_STRATEGY
        && verification["pages_direct_create"] == proof
        && terminal["basis_hash"] == hash_value(&verification["basis"])?
        && apply["success"] == true
        && apply["errors"].as_array().is_some_and(Vec::is_empty)
        && apply["status"]
            .as_u64()
            .is_some_and(|status| (200..300).contains(&status))
        && contract::project_is_direct(&apply["result"], name)
        && apply["result"]["id"] == project["id"]
        && verification["readback"]["success"] == true
        && verification["readback"]["errors"]
            .as_array()
            .is_some_and(Vec::is_empty)
        && verification["readback"]["status"]
            .as_u64()
            .is_some_and(|status| (200..300).contains(&status))
        && contract::project_is_direct(&verification["readback"]["result"], name)
        && verification["readback"]["result"]["id"] == project["id"];
    if !exact {
        return Ok(None);
    }
    let mut proof = proof;
    proof["verification_evidence_hash"] = json!(verification_hash);
    Ok(Some(proof))
}

/// This structural check is never proof admission by itself: both preparation
/// and execution call `find`, which authenticates and joins the stored records.
pub(super) fn reference_is_bound(receipt: &Value) -> bool {
    let Some(proof) = receipt.get("direct_create_proof") else {
        return false;
    };
    proof.as_object().is_some_and(|fields| fields.len() == 15)
        && proof["schema_version"] == 1
        && proof.get("account_id") == receipt.get("account_id")
        && proof.get("project_name") == receipt.get("project_name")
        && proof.get("project_id") == receipt.get("project_id")
        && proof["production_branch"] == "main"
        && receipt["production_branch"] == "main"
        && proof["operation_id"]
            .as_str()
            .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok())
        && proof["credential_generation_id"]
            .as_str()
            .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok())
        && [
            "plan_content_hash",
            "pins_hash",
            "catalog_hash",
            "build_identity_hash",
            "apply_evidence_hash",
            "verification_evidence_hash",
        ]
        .iter()
        .all(|field| {
            proof[field]
                .as_str()
                .is_some_and(cfctl_core::valid_sha256_identity)
        })
}
