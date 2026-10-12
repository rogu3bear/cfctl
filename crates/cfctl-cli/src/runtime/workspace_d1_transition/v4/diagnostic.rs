//! Separate primary storage diagnostic join; never an integer assertion substitute.
use cfctl_cloudflare::d1_read_inventory::{self, ValidatedD1ReadInventory};
use cfctl_core::{
    OperationalProofV1,
    d1_read_inventory::{
        D1_PRIVATE_FORMAT, D1PrivateReadArtifactV1, D1ReadInventoryV1, D1ReadValueKindV1,
    },
};
use sha2::{Digest, Sha256};

use super::{
    CallInput, Declaration, ProofRef, Result, Scope, StateStore, Utc, Value,
    WorkspaceD1MigrationContractV1, hash_value, invalid, json, observations,
};

fn output(inventory: &D1ReadInventoryV1, mode: &Declaration) -> Result<()> {
    let (sql, column) = match mode {
        Declaration::FullIntegrityV1 { .. } => (
            "SELECT integrity_check FROM pragma_integrity_check;",
            "integrity_check",
        ),
        Declaration::ManagedD1ApplicationV1 { .. } => ("PRAGMA quick_check;", "quick_check"),
    };
    let query = inventory
        .queries
        .first()
        .ok_or_else(|| invalid("diagnostic query missing"))?;
    if inventory.queries.len() != 1
        || query.sql != sql
        || !query.parameters.is_empty()
        || !query.requires.is_empty()
        || query.output.min_rows != 1
        || query.output.max_rows != 1
        || query.output.columns.len() != 1
        || query.output.columns[0].name != column
        || query.output.columns[0].kind != D1ReadValueKindV1::Text
        || query.output.columns[0].nullable
        || query.output.columns[0].max_bytes != Some(2)
        || query.output.columns[0].allowed_values.as_deref() != Some(&[json!("ok")])
        || query.output.columns[0].min_integer.is_some()
        || query.output.columns[0].max_integer.is_some()
    {
        return Err(invalid(
            "storage diagnostic mode, SQL or exact one-row text result differs",
        ));
    }
    Ok(())
}

pub(super) fn read(
    store: &StateStore,
    transition: &WorkspaceD1MigrationContractV1,
    mode: &Declaration,
    reference: &ProofRef,
    scope: &Scope<'_>,
    not_before: chrono::DateTime<Utc>,
    now: chrono::DateTime<Utc>,
) -> Result<()> {
    let expected = mode.diagnostic();
    let capability =
        crate::runtime::support::load_workspace_capability(store, &expected.capability_id)?
            .ok_or_else(|| invalid("diagnostic operation is not registered"))?;
    let contract = capability
        .workspace_d1_read_inventory
        .as_ref()
        .ok_or_else(|| invalid("diagnostic is not a native inventory"))?;
    let compiled = transition
        .transition
        .as_ref()
        .ok_or_else(|| invalid("transition missing"))?;
    if contract.repository_root != transition.repository_root
        || contract.repository_head != transition.repository_head
        || contract.operation.inventory_path != expected.inventory.path
        || contract.operation.inventory_sha256 != expected.inventory.sha256
        || contract.operation.account_id != compiled.declaration.account_id
        || contract.operation.database_id != compiled.declaration.database_id
        || contract.operation.profile_id != scope.profile
    {
        return Err(invalid("diagnostic source or database differs"));
    }
    output(&contract.inventory, mode)?;
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
        return Err(invalid("diagnostic is not its exact native call"));
    }
    let value = store.read_evidence_value(&reference.evidence_hash)?;
    if let Some(private) = &contract.inventory.private_output {
        let path = value
            .pointer("/artifact/path")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("diagnostic private artifact missing"))?;
        if value.get("output_path").and_then(Value::as_str) != Some(path) {
            return Err(invalid("diagnostic private custody path differs"));
        }
        let path = std::path::Path::new(path);
        let directory = cfctl_storage::PrivateDirectory::open(
            path.parent()
                .ok_or_else(|| invalid("diagnostic parent missing"))?,
        )
        .map_err(|_| invalid("diagnostic private directory custody failed"))?;
        let bytes = directory
            .read(
                path.file_name()
                    .and_then(|name| name.to_str())
                    .ok_or_else(|| invalid("diagnostic name missing"))?,
                private.max_artifact_bytes,
            )
            .map_err(|_| invalid("diagnostic private file custody failed"))?
            .ok_or_else(|| invalid("diagnostic private artifact unavailable"))?;
        let hash = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
        if value.pointer("/artifact/sha256").and_then(Value::as_str) != Some(hash.as_str())
            || value.pointer("/artifact/bytes").and_then(Value::as_u64) != Some(bytes.len() as u64)
        {
            return Err(invalid(
                "diagnostic artifact bytes differ from native publication",
            ));
        }
        let artifact: D1PrivateReadArtifactV1 = serde_json::from_slice(&bytes)
            .map_err(|_| invalid("diagnostic artifact schema differs"))?;
        private_value(
            &value, &artifact, &validated, &proof, scope, not_before, now,
        )?;
    } else {
        observations::validate_value(&value, &proof, &validated, scope, not_before, now)?;
    }
    Ok(())
}

fn private_value(
    value: &Value,
    artifact: &D1PrivateReadArtifactV1,
    validated: &ValidatedD1ReadInventory,
    proof: &OperationalProofV1,
    scope: &Scope<'_>,
    not_before: chrono::DateTime<Utc>,
    now: chrono::DateTime<Utc>,
) -> Result<()> {
    let contract = validated.contract();
    let binding = &artifact.binding;
    let query = &contract.inventory.queries[0];
    for (field, expected) in [
        ("kind", D1_PRIVATE_FORMAT),
        ("capability_id", proof.capability_id.as_str()),
        ("catalog_schema_hash", scope.catalog),
        ("profile_id", scope.profile),
        ("credential_generation_id", scope.generation),
        ("account_id", scope.account),
        ("database_id", contract.operation.database_id.as_str()),
        ("repository_head", contract.repository_head.as_str()),
        ("repository_tree", contract.repository_tree.as_str()),
        (
            "operation_pack_sha256",
            contract.operation_pack_sha256.as_str(),
        ),
        (
            "inventory_sha256",
            contract.operation.inventory_sha256.as_str(),
        ),
        ("query_id", query.id.as_str()),
        ("query_sha256", query.sha256.as_str()),
    ] {
        if value.get(field).and_then(Value::as_str) != Some(expected) {
            return Err(invalid(
                "private diagnostic native observation identity differs",
            ));
        }
    }
    let contract_hash = hash_value(&serde_json::to_value(contract)?)?;
    if artifact.schema_version != 1
        || artifact.kind != D1_PRIVATE_FORMAT
        || binding.contract != *contract
        || binding.capability_id != proof.capability_id
        || binding.catalog_schema_hash != scope.catalog
        || binding.profile_id != scope.profile
        || binding.credential_generation_id.to_string() != scope.generation
        || binding.contract_sha256 != contract_hash
        || value.get("contract_sha256").and_then(Value::as_str) != Some(contract_hash.as_str())
        || hash_value(&serde_json::to_value(&binding.build)?)? != scope.build
        || hash_value(&value["build"])? != scope.build
        || binding.query_id != query.id
        || binding.query_sha256 != query.sha256
        || artifact.started_at < not_before
        || artifact.completed_at < artifact.started_at
        || artifact.completed_at > proof.observed_at
        || artifact.completed_at > now
        || artifact.transport.http_status != 200
        || artifact.transport.content_encoding != "identity"
        || artifact.transport.attempted_queries != 1
        || !artifact.transport.read_complete
        || !artifact.transport.served_by_primary
        || artifact.transport.application_predicates_evaluated
        || value.get("classification").and_then(Value::as_str) != Some("complete_read")
        || value.get("read_complete") != Some(&json!(true))
        || value.get("application_predicates_evaluated") != Some(&json!(false))
        || d1_read_inventory::qualify_private_receipt(validated, 200, &artifact.provider_response)
            .ok()
            != Some(1)
    {
        return Err(invalid(
            "private diagnostic provenance, primary result or chronology differs",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
