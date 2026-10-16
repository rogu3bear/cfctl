//! Committed synthetic qualification binder. Production remains independently closed.
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use cfctl_core::{
    AdapterStatus, CapabilityAuthorityScopeV1, CapabilityV1, EffectClass, RiskClass,
    WorkspaceD1MigrationContractV1,
    d1_read_inventory::D1ReadInventoryV1,
    workspace_d1::transition::{
        MAX_ENVELOPE_BYTES, Source,
        admission::{PACK_PATH, Pack, Role},
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::d1_operation::{committed_file, safe_relative};
use super::{Result, WorkspaceError, git_optional, operation_identity::WorkspaceOperationLoad};
mod oracle;
mod resource;
pub use resource::{
    MaterializedPopulation, materialize_qualification_population,
    materialize_qualification_read_capability, revalidate_qualification_source,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundQualificationSource {
    pub repository_root: String,
    pub repository_head: String,
    pub qualification_pack_sha256: String,
    pub pack: Pack,
    pub transition: WorkspaceD1MigrationContractV1,
    pub source_lengths: BTreeMap<String, usize>,
}

/// Read only committed source. Inspect preserves dirty app work; execution does not.
pub fn load_workspace_d1_qualification_source(
    roots: &[PathBuf],
    capability_id: &str,
    mode: WorkspaceOperationLoad,
) -> Result<Option<BoundQualificationSource>> {
    let candidates = super::operation_identity::discover(roots)?;
    if super::operation_identity::unique_typed_owner(&candidates, PACK_PATH, capability_id)?
        .is_none()
    {
        return Ok(None);
    }
    source_selected(&candidates, capability_id, mode)
}

pub(super) fn load_selected(
    candidates: &[PathBuf],
    capability_id: &str,
    mode: WorkspaceOperationLoad,
) -> Result<Option<CapabilityV1>> {
    let Some(bound) = source_selected(candidates, capability_id, mode)? else {
        return Ok(None);
    };
    let operation = bound
        .pack
        .operation
        .iter()
        .find(|op| op.id == capability_id)
        .ok_or_else(|| invalid("qualification operation changed during bind"))?;
    Ok(Some(capability(operation)))
}

fn capability(
    operation: &cfctl_core::workspace_d1::transition::admission::Operation,
) -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        &operation.id,
        &operation.title,
        "POST",
        operation.role.path(),
    );
    capability.description = Some(operation.description.clone());
    capability.authority_scope = Some(CapabilityAuthorityScopeV1::WorkspaceOwned);
    capability.source = "workspace-d1-transition-qualification-pack-v1".into();
    capability.product = "D1".into();
    capability.account_scope = "account".into();
    capability.mutating = operation.role.mutates();
    capability.risk = if capability.mutating {
        RiskClass::Irreversible
    } else {
        RiskClass::Read
    };
    capability.effect = if capability.mutating {
        EffectClass::DataWrite
    } else {
        EffectClass::ReadOnly
    };
    capability.permissions = if matches!(operation.role, Role::Population) {
        vec!["D1 Read".into()]
    } else if matches!(operation.role, Role::Aggregate | Role::Policy) {
        Vec::new()
    } else {
        vec!["D1 Write".into()]
    };
    capability.verification.required = true;
    capability.verification.strategy = "workspace_d1_transition_qualification_source_v1".into();
    capability.adapter_status = AdapterStatus::Blocked;
    capability.blocked_reason = Some("Committed synthetic source is bound; native PlanV2 resource/permission/cost/executor/verifier admission is still required. Production transition execution remains disabled.".into());
    capability
}

fn source_selected(
    candidates: &[PathBuf],
    capability_id: &str,
    mode: WorkspaceOperationLoad,
) -> Result<Option<BoundQualificationSource>> {
    let repositories = super::operation_identity::select(candidates, PACK_PATH, capability_id)?;
    if repositories.len() > 1 {
        return Err(invalid(
            "qualification source id is ambiguous across registered repositories",
        ));
    }
    let Some(repository) = repositories.first() else {
        return Ok(None);
    };
    if mode.requires_clean_worktree() && repository.git.dirty {
        return Err(invalid("qualification source repository must be clean"));
    }
    let bytes = committed_file(&repository.path, Path::new(PACK_PATH), mode)?;
    let pack: Pack = toml::from_str(
        std::str::from_utf8(&bytes).map_err(|_| invalid("qualification pack is not UTF-8"))?,
    )
    .map_err(|error| invalid(format!("qualification pack is invalid: {error}")))?;
    pack.validate().map_err(invalid)?;
    if !pack.operation.iter().any(|op| op.id == capability_id) {
        return Err(invalid("selected qualification id disappeared"));
    }
    let transition = super::operation_identity::load_selected(
        std::slice::from_ref(&repository.path),
        &pack.transition_operation_id,
        mode,
    )?
    .and_then(|capability| capability.workspace_d1_migration)
    .ok_or_else(|| invalid("qualification requires its existing typed transition source"))?;
    let compiled = transition
        .transition
        .as_ref()
        .ok_or_else(|| invalid("qualification cannot use a legacy transition"))?;
    if compiled.declaration.observations.is_none() || compiled.declaration.assurance.is_none() {
        return Err(invalid(
            "freeze explicit transition observations and assurance before qualification",
        ));
    }
    let mut bound = BoundQualificationSource {
        repository_root: transition.repository_root.clone(),
        repository_head: transition.repository_head.clone(),
        qualification_pack_sha256: sha256(&bytes),
        pack,
        transition,
        source_lengths: BTreeMap::new(),
    };
    bind_inputs(&repository.path, &mut bound, mode)?;
    Ok(Some(bound))
}

fn bind_inputs(
    root: &Path,
    bound: &mut BoundQualificationSource,
    mode: WorkspaceOperationLoad,
) -> Result<()> {
    for case in &bound.pack.cases {
        for source in [&case.seed, &case.execution] {
            let bytes = source_bytes(root, source, mode)?;
            if bytes.is_empty()
                || bytes.len() > MAX_ENVELOPE_BYTES
                || !bytes.ends_with(b"\n")
                || bytes.contains(&0)
                || std::str::from_utf8(&bytes).is_err()
            {
                return Err(invalid(
                    "qualification SQL source must be bounded nonempty NUL-free UTF-8 ending in newline",
                ));
            }
            bound
                .source_lengths
                .insert(source.path.clone(), bytes.len());
        }
        for (inventory_source, oracle_source, expected) in [
            (
                &case.before.inventory,
                &case.before_oracle,
                &case.expected_before_state_sha256,
            ),
            (
                &case.after.inventory,
                &case.after_oracle,
                &case.expected_after_state_sha256,
            ),
        ] {
            let inventory = bind_inventory(root, inventory_source, mode)?;
            oracle::bind(root, oracle_source, expected, &inventory, mode)?;
        }
        if let Some(writer) = &case.concurrent_source {
            let bytes = source_bytes(root, &writer.writer, mode)?;
            if bytes.len() != writer.writer_bytes
                || bytes.is_empty()
                || bytes.len() > MAX_ENVELOPE_BYTES
                || !bytes.ends_with(b"\n")
                || bytes.contains(&0)
                || std::str::from_utf8(&bytes).is_err()
            {
                return Err(invalid(
                    "qualification writer source byte length or SQL shape differs",
                ));
            }
            bound
                .source_lengths
                .insert(writer.writer.path.clone(), bytes.len());
            let inventory = bind_inventory(root, &writer.post_writer_inventory.inventory, mode)?;
            let source = case
                .post_writer_oracle
                .as_ref()
                .ok_or_else(|| invalid("qualification writer oracle missing"))?;
            oracle::bind(
                root,
                source,
                &writer.expected_post_writer_state_sha256,
                &inventory,
                mode,
            )?;
        }
    }
    Ok(())
}

fn bind_inventory(
    root: &Path,
    source: &Source,
    mode: WorkspaceOperationLoad,
) -> Result<D1ReadInventoryV1> {
    let bytes = source_bytes(root, source, mode)?;
    let inventory: D1ReadInventoryV1 = serde_json::from_slice(&bytes)
        .map_err(|_| invalid("qualification population inventory schema differs"))?;
    if inventory.private_output.is_some() {
        return Err(invalid(
            "synthetic population must use ordinary bounded native results",
        ));
    }
    Ok(inventory)
}

fn source_bytes(root: &Path, source: &Source, mode: WorkspaceOperationLoad) -> Result<Vec<u8>> {
    let bytes = committed_file(root, &safe_relative(&source.path)?, mode)?;
    if bytes.len() > 16 * 1024 * 1024
        || sha256(&bytes) != source.sha256
        || git_optional(
            root,
            &["rev-parse", "--verify", &format!("HEAD:{}", source.path)],
        )?
        .as_deref()
            != Some(source.git_blob_oid.as_str())
    {
        return Err(invalid(
            "qualification source digest or committed Git blob differs",
        ));
    }
    Ok(bytes)
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
fn invalid(message: impl Into<String>) -> WorkspaceError {
    WorkspaceError::DiscoveryInvariant(message.into())
}

#[cfg(test)]
mod tests;
