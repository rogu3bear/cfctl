//! Bind existing native read receipts to a reviewed transition boundary.
use cfctl_cloudflare::d1_read_inventory::{self, ValidatedD1ReadInventory};
use cfctl_core::{
    OperationalProofV1, WorkspaceD1MigrationContractV1,
    d1_read_inventory::{D1ReadInventoryResultV1, D1ReadInventoryV1, D1ReadValueKindV1},
    hash_value,
    workspace_d1::transition::{Observation, ProofRef},
};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use super::{Scope, invalid};
use crate::runtime::{
    prelude::{CallInput, Result, StateStore},
    support::load_workspace_capability,
};

fn assertion_outputs(inventory: &D1ReadInventoryV1) -> Result<()> {
    if inventory.private_output.is_some() || inventory.queries.is_empty() {
        return Err(invalid(
            "boundary assertions require ordinary nonempty reads",
        ));
    }
    for query in &inventory.queries {
        let columns = &query.output.columns;
        if !query.parameters.is_empty()
            || query.output.min_rows != 1
            || query.output.max_rows != 1
            || columns.len() != 1
            || columns[0].name != "passed"
            || columns[0].kind != D1ReadValueKindV1::Integer
            || columns[0].nullable
            || columns[0].allowed_values.as_deref() != Some(&[json!(1)])
            || columns[0].min_integer != Some(1)
            || columns[0].max_integer != Some(1)
        {
            return Err(invalid(
                "each boundary assertion must require one integer passed=1",
            ));
        }
    }
    Ok(())
}

pub(super) fn read(
    store: &StateStore,
    transition: &WorkspaceD1MigrationContractV1,
    expected: &Observation,
    reference: &ProofRef,
    scope: &Scope<'_>,
    not_before: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<OperationalProofV1> {
    let capability = load_workspace_capability(store, &expected.capability_id)?
        .ok_or_else(|| invalid("boundary read operation is not registered"))?;
    let contract = capability
        .workspace_d1_read_inventory
        .as_ref()
        .ok_or_else(|| invalid("boundary operation is not a native read inventory"))?;
    let compiled = transition
        .transition
        .as_ref()
        .ok_or_else(|| invalid("boundary has no transition contract"))?;
    if contract.repository_root != transition.repository_root
        || contract.repository_head != transition.repository_head
        || contract.operation.inventory_path != expected.inventory.path
        || contract.operation.inventory_sha256 != expected.inventory.sha256
        || contract.operation.account_id != compiled.declaration.account_id
        || contract.operation.database_id != compiled.declaration.database_id
        || contract.operation.profile_id != compiled.declaration.profile_id
    {
        return Err(invalid(
            "boundary read source or target differs from the transition",
        ));
    }
    assertion_outputs(&contract.inventory)?;
    let input = CallInput {
        selectors: json!({"account_id":scope.account,"database_id":contract.operation.database_id}),
        query: json!({}),
        body: Some(json!({"inventory_sha256":expected.inventory.sha256,
            "expected_credential_generation_id":scope.generation})),
        ..CallInput::default()
    };
    let validated = d1_read_inventory::validate(&capability, &input)?;
    let proof = super::read(store, reference, scope, now)?;
    if proof.capability_id != expected.capability_id
        || proof.input_hash != hash_value(&serde_json::to_value(&input)?)?
    {
        return Err(invalid(
            "boundary receipt is not the exact reviewed native call",
        ));
    }
    let value = store.read_evidence_value(&reference.evidence_hash)?;
    validate_value(&value, &proof, &validated, scope, not_before, now)?;
    Ok(proof)
}

fn validate_value(
    value: &Value,
    proof: &OperationalProofV1,
    validated: &ValidatedD1ReadInventory,
    scope: &Scope<'_>,
    not_before: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<()> {
    let contract = validated.contract();
    for (key, expected) in [
        ("kind", "workspace_d1_read_inventory_v1"),
        ("capability_id", proof.capability_id.as_str()),
        ("catalog_schema_hash", scope.catalog),
        ("profile_id", scope.profile),
        ("credential_generation_id", scope.generation),
        ("account_id", scope.account),
        ("database_id", contract.operation.database_id.as_str()),
        ("repository_root", contract.repository_root.as_str()),
        ("repository_head", contract.repository_head.as_str()),
        ("repository_tree", contract.repository_tree.as_str()),
        (
            "source_revision",
            contract.operation.source_revision.as_str(),
        ),
        (
            "operation_pack_sha256",
            contract.operation_pack_sha256.as_str(),
        ),
        (
            "inventory_sha256",
            contract.operation.inventory_sha256.as_str(),
        ),
    ] {
        if value.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(invalid("boundary observation identity differs"));
        }
    }
    let contract_hash = hash_value(&serde_json::to_value(contract)?)?;
    if value.get("contract_sha256").and_then(Value::as_str) != Some(contract_hash.as_str())
        || value.get("source_inputs") != Some(&serde_json::to_value(&contract.operation.source)?)
        || value.get("non_atomic_observations") != Some(&json!(true))
        || hash_value(
            value
                .get("build")
                .ok_or_else(|| invalid("boundary build is missing"))?,
        )? != scope.build
    {
        return Err(invalid("boundary observation contract or build differs"));
    }
    let started: DateTime<Utc> = serde_json::from_value(value["started_at"].clone())
        .map_err(|_| invalid("boundary observation start is invalid"))?;
    let completed: DateTime<Utc> = serde_json::from_value(value["completed_at"].clone())
        .map_err(|_| invalid("boundary observation completion is invalid"))?;
    if started < not_before
        || completed < started
        || completed > proof.observed_at
        || completed > now
    {
        return Err(invalid("boundary observation chronology differs"));
    }
    let result: D1ReadInventoryResultV1 = serde_json::from_value(value["execution"].clone())
        .map_err(|_| invalid("boundary read results are malformed"))?;
    d1_read_inventory::validate_result(validated, &result)?;
    if !result.read_complete {
        return Err(invalid("boundary assertion population is incomplete"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
