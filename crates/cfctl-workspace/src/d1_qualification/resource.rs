//! Materialize a committed case inventory for a receipt-derived synthetic UUID.
//! This is a source projection, not a Native capability or provider dispatcher.
use cfctl_core::{
    d1_read_inventory::D1ReadInventoryV1,
    workspace_d1::transition::{
        Observation,
        admission::{
            Role,
            resource::{ReadPhase, Resource},
        },
        proofs::Identity,
    },
};

use super::{BoundQualificationSource, Result, WorkspaceOperationLoad, bind_inventory, invalid};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedPopulation {
    pub resource: Resource,
    pub phase: ReadPhase,
    pub source: Observation,
    pub inventory: D1ReadInventoryV1,
    pub expected_state_sha256: String,
}

/// Internal executor projection. Catalog roles remain independently blocked.
/// The CLI must authenticate the create and credential scope before executing it.
pub fn materialize_qualification_read_capability(
    bound: &BoundQualificationSource,
    population: &MaterializedPopulation,
    profile: &str,
) -> Result<cfctl_core::CapabilityV1> {
    use cfctl_core::d1_read_inventory::{
        D1ReadOperationV1, D1ReadSourceV1, WorkspaceD1ReadInventoryContractV1,
    };
    let current =
        materialize_qualification_population(bound, &population.resource, population.phase)?;
    if &current != population || profile.is_empty() {
        return Err(invalid("synthetic read projection or profile differs"));
    }
    let root = std::path::Path::new(&bound.repository_root);
    let tree = super::git_optional(root, &["rev-parse", "HEAD^{tree}"])?
        .ok_or_else(|| invalid("synthetic read tree missing"))?;
    let origin = super::git_optional(root, &["config", "--get", "remote.origin.url"])?
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("synthetic read origin missing"))?;
    let mut capability = crate::d1_reads::capability(WorkspaceD1ReadInventoryContractV1 {
        repository_root: bound.repository_root.clone(),
        repository_head: bound.repository_head.clone(),
        repository_tree: tree,
        repository_origin: origin,
        operation_pack_sha256: bound.qualification_pack_sha256.clone(),
        operation: D1ReadOperationV1 {
            id: population.source.capability_id.clone(),
            title: "Synthetic case population".into(),
            description: "Complete committed case inventory on a create-receipt-derived database"
                .into(),
            account_id: population.resource.identity.account_id.clone(),
            database_id: population.resource.database_id.clone(),
            profile_id: profile.into(),
            source_revision: bound.repository_head.clone(),
            source: vec![
                D1ReadSourceV1 {
                    path: cfctl_core::workspace_d1::transition::admission::PACK_PATH.into(),
                    sha256: bound.qualification_pack_sha256.clone(),
                },
                D1ReadSourceV1 {
                    path: bound.transition.operation_pack_path.clone(),
                    sha256: bound.transition.operation_pack_sha256.clone(),
                },
            ],
            inventory_path: population.source.inventory.path.clone(),
            inventory_sha256: population.source.inventory.sha256.clone(),
        },
        inventory: population.inventory.clone(),
    });
    capability.source = "workspace-d1-synthetic-read-v1".into();
    Ok(capability)
}

pub fn revalidate_qualification_source(bound: &BoundQualificationSource) -> Result<()> {
    let population = bound
        .pack
        .operation
        .iter()
        .find(|op| op.role == Role::Population)
        .ok_or_else(|| invalid("qualification population role disappeared"))?;
    let current = super::load_workspace_d1_qualification_source(
        &[std::path::PathBuf::from(&bound.repository_root)],
        &population.id,
        WorkspaceOperationLoad::Execute,
    )?
    .ok_or_else(|| invalid("qualification source is no longer committed"))?;
    if &current != bound {
        return Err(invalid(
            "qualification source changed during resource materialization",
        ));
    }
    Ok(())
}

/// Rebind the exact current committed qualification pack, retaining its HEAD.
/// Runtime callers must derive `resource` from authenticated approved create
/// evidence; this function intentionally grants no credential or effect authority.
pub fn materialize_qualification_population(
    bound: &BoundQualificationSource,
    resource: &Resource,
    phase: ReadPhase,
) -> Result<MaterializedPopulation> {
    revalidate_qualification_source(bound)?;
    let identity = Identity::from_contract(&bound.transition)
        .map_err(|_| invalid("qualification transition identity is invalid"))?;
    let case = resource
        .validate(&bound.pack, &identity, &bound.qualification_pack_sha256)
        .map_err(invalid)?;
    let observation = phase.observation(case).map_err(invalid)?;
    let inventory = bind_inventory(
        std::path::Path::new(&bound.repository_root),
        &observation.inventory,
        WorkspaceOperationLoad::Execute,
    )?;
    Ok(MaterializedPopulation {
        resource: resource.clone(),
        phase,
        source: observation.clone(),
        inventory,
        expected_state_sha256: phase.expected_state(case).map_err(invalid)?.into(),
    })
}
