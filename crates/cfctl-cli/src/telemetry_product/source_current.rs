//! Authenticate selected D1 source receipts in ordinary catalog coverage.
use super::{CatalogSnapshot, OperationalProofV1, StateStore, Value, hash_value};

pub(super) fn current(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    proof: &OperationalProofV1,
) -> bool {
    if catalog.get(&proof.capability_id).is_some() {
        return true;
    }
    let Ok((descriptor, body)) = store.load_evidence_value(&proof.evidence.content_hash) else {
        return false;
    };
    if descriptor.content_hash != proof.evidence.content_hash {
        return false;
    }
    let Some(source) = body.get("source_binding").filter(|v| !v.is_null()) else {
        return true;
    };
    if !matches!(
        body["kind"].as_str(),
        Some("workspace_d1_read_inventory_v1" | "workspace_d1_private_read_v1")
    ) || body["capability_id"].as_str() != Some(proof.capability_id.as_str())
    {
        return false;
    }
    let Ok(binding) = serde_json::from_value::<cfctl_core::d1_read_inventory::D1ReadSourceBindingV1>(
        source.clone(),
    ) else {
        return false;
    };
    let Ok(roots) = store.workspace_roots() else {
        return false;
    };
    let Ok(capability) = cfctl_workspace::load_workspace_d1_read_from_checkout(
        &roots,
        &proof.capability_id,
        &binding.selection,
        cfctl_workspace::WorkspaceOperationLoad::Execute,
    ) else {
        return false;
    };
    let Some(contract) = capability.workspace_d1_read_inventory.as_ref() else {
        return false;
    };
    contract.source_binding.as_ref() == Some(&binding)
        && serde_json::to_value(contract)
            .ok()
            .and_then(|v| hash_value(&v).ok())
            .is_some_and(|digest| body["contract_sha256"] == Value::String(digest))
}
