//! Load a reviewed read population from one clean, explicitly registered owner.
use std::{collections::BTreeSet, path::Path};

use cfctl_core::{
    AdapterStatus, BillingModelV1, CapabilityAuthorityScopeV1, CapabilityV1, CostExposureV1,
    EffectClass, ResponseBodyModeV1, ResponseContractV1, RiskClass, SelectorV1,
    d1_read_inventory::{
        D1_READ_PACK_PATH, D1ReadOperationV1, D1ReadPackV1, WorkspaceD1ReadInventoryContractV1,
    },
};
use sha2::{Digest, Sha256};

use super::{
    Result, WorkspaceError,
    d1_operation::{committed_file, reject_symlinks, safe_relative},
    git_optional,
};

/// Recheck the exact immutable owner before each provider boundary. With HEAD
/// unchanged, hash current inputs directly instead of rerunning every Git blob
/// and ancestry lookup for each query in a large population.
pub fn revalidate_workspace_d1_read_inventory(
    contract: &WorkspaceD1ReadInventoryContractV1,
) -> Result<()> {
    let root = Path::new(&contract.repository_root);
    if git_optional(root, &["rev-parse", "HEAD"])? != Some(contract.repository_head.clone())
        || git_optional(
            root,
            &["status", "--porcelain=v1", "--untracked-files=normal"],
        )?
        .is_none_or(|status| !status.is_empty())
    {
        return Err(invalid(
            "read operation source owner changed during execution",
        ));
    }
    let mut inputs = vec![
        (D1_READ_PACK_PATH, contract.operation_pack_sha256.as_str()),
        (
            contract.operation.inventory_path.as_str(),
            contract.operation.inventory_sha256.as_str(),
        ),
    ];
    inputs.extend(
        contract
            .operation
            .source
            .iter()
            .map(|s| (s.path.as_str(), s.sha256.as_str())),
    );
    for (path, expected) in inputs {
        let relative = safe_relative(path)?;
        reject_symlinks(root, &relative)?;
        let metadata = std::fs::metadata(root.join(&relative))
            .map_err(|_| invalid("read source disappeared"))?;
        if !metadata.is_file() || metadata.len() > 16 * 1024 * 1024 {
            return Err(invalid("read source size drifted"));
        }
        let bytes =
            std::fs::read(root.join(relative)).map_err(|_| invalid("read source unavailable"))?;
        if bytes.len() > 16 * 1024 * 1024 || sha256(&bytes) != expected {
            return Err(invalid("read source bytes changed during execution"));
        }
    }
    Ok(())
}

pub(super) fn load_selected(
    candidates: &[std::path::PathBuf],
    capability_id: &str,
) -> Result<Option<CapabilityV1>> {
    let selected = super::operation_identity::select(candidates, D1_READ_PACK_PATH, capability_id)?;
    if selected.len() > 1 {
        return Err(invalid(
            "read operation is ambiguous across registered repositories",
        ));
    }
    let Some(repository) = selected.first() else {
        return Ok(None);
    };
    if repository.git.dirty {
        return Err(invalid("read operation repository must be clean"));
    }
    let head = repository
        .git
        .head
        .as_deref()
        .filter(|value| lower_hex(value, 40))
        .ok_or_else(|| invalid("read operation requires a committed HEAD"))?;
    let root = &repository.path;
    let tree = git_optional(root, &["rev-parse", "HEAD^{tree}"])?
        .filter(|value| lower_hex(value, 40))
        .ok_or_else(|| invalid("read operation requires a Git tree"))?;
    let origin = git_optional(root, &["config", "--get", "remote.origin.url"])?
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("read operation requires its repository origin"))?;
    let (pack, bytes) = load_pack(root)?;
    let operation = pack
        .operation
        .into_iter()
        .find(|op| op.id == capability_id)
        .ok_or_else(|| invalid("selected read operation disappeared"))?;
    validate_operation_identity(&operation)?;
    if git_optional(
        root,
        &[
            "merge-base",
            "--is-ancestor",
            &operation.source_revision,
            head,
        ],
    )?
    .is_none()
    {
        return Err(invalid(
            "declared read source revision is not an ancestor of the pack owner",
        ));
    }
    for source in &operation.source {
        let source_bytes = bounded_committed(root, &source.path, 16 * 1024 * 1024)?;
        if sha256(&source_bytes) != source.sha256
            || !git_optional(
                root,
                &[
                    "diff",
                    "--name-only",
                    &operation.source_revision,
                    "HEAD",
                    "--",
                    &source.path,
                ],
            )?
            .is_some_and(|changed| changed.is_empty())
        {
            return Err(invalid("reviewed read source input is missing or changed"));
        }
    }
    let inventory_bytes = bounded_committed(root, &operation.inventory_path, 16 * 1024 * 1024)?;
    if sha256(&inventory_bytes) != operation.inventory_sha256 {
        return Err(invalid(
            "committed read inventory digest differs from its declaration",
        ));
    }
    let inventory = serde_json::from_slice(&inventory_bytes)
        .map_err(|_| invalid("read inventory does not match its closed JSON schema"))?;
    let contract = WorkspaceD1ReadInventoryContractV1 {
        repository_root: root.display().to_string(),
        repository_head: head.to_owned(),
        repository_tree: tree,
        repository_origin: origin,
        operation_pack_sha256: sha256(&bytes),
        operation,
        inventory,
    };
    Ok(Some(capability(contract)))
}

fn load_pack(root: &Path) -> Result<(D1ReadPackV1, Vec<u8>)> {
    let bytes = bounded_committed(root, D1_READ_PACK_PATH, 256 * 1024)?;
    let pack: D1ReadPackV1 = toml::from_str(
        std::str::from_utf8(&bytes).map_err(|_| invalid("read pack must be UTF-8"))?,
    )
    .map_err(|_| invalid("read pack does not match the typed v1 declaration"))?;
    if pack.schema_version != 1
        || pack.operation.is_empty()
        || pack.operation.len() > 32
        || pack
            .operation
            .iter()
            .map(|op| &op.id)
            .collect::<BTreeSet<_>>()
            .len()
            != pack.operation.len()
    {
        return Err(invalid(
            "unsupported read pack version, size, or duplicate operation id",
        ));
    }
    Ok((pack, bytes))
}

fn validate_operation_identity(operation: &D1ReadOperationV1) -> Result<()> {
    if !operation.id.contains('.')
        || !identifier(&operation.id)
        || !identifier(&operation.profile_id)
        || operation.title.trim().is_empty()
        || operation.title.len() > 256
        || operation.description.trim().is_empty()
        || operation.description.len() > 4096
        || !lower_hex(&operation.account_id, 32)
        || !database_id(&operation.database_id)
        || !lower_hex(&operation.source_revision, 40)
        || operation.source.is_empty()
        || operation.source.len() > 1024
        || operation
            .source
            .iter()
            .map(|s| &s.path)
            .collect::<BTreeSet<_>>()
            .len()
            != operation.source.len()
    {
        return Err(invalid(
            "read operation identity, target, purpose or source population is invalid",
        ));
    }
    Ok(())
}

fn bounded_committed(root: &Path, relative: &str, max: u64) -> Result<Vec<u8>> {
    let relative_path = safe_relative(relative)?;
    reject_symlinks(root, &relative_path)?;
    let metadata =
        std::fs::metadata(root.join(relative)).map_err(|_| invalid("read input is unavailable"))?;
    if !metadata.is_file() || metadata.len() > max {
        return Err(invalid(
            "read input must be a bounded committed regular file",
        ));
    }
    let bytes = committed_file(root, &relative_path)?;
    if bytes.len() as u64 > max {
        return Err(invalid("read input exceeded its byte bound"));
    }
    Ok(bytes)
}

fn capability(contract: WorkspaceD1ReadInventoryContractV1) -> CapabilityV1 {
    let mut cap = CapabilityV1::new(
        &contract.operation.id,
        &contract.operation.title,
        "POST",
        "/accounts/{account_id}/d1/database/{database_id}/query",
    );
    cap.description = Some(contract.operation.description.clone());
    cap.authority_scope = Some(CapabilityAuthorityScopeV1::WorkspaceOwned);
    cap.product = "D1".into();
    cap.source = "workspace-d1-read-pack-v1".into();
    cap.account_scope = "account".into();
    cap.permissions = vec!["D1 Read".into()];
    cap.mutating = false;
    cap.risk = RiskClass::Read;
    cap.effect = EffectClass::ReadOnly;
    cap.adapter_status = AdapterStatus::Native;
    cap.selectors = ["account_id", "database_id"]
        .into_iter()
        .map(|name| SelectorV1 {
            name: name.into(),
            location: "path".into(),
            required: true,
            value_type: "string".into(),
            description: None,
            contract: None,
        })
        .collect();
    cap.cost.known = false;
    cap.cost.incremental = false;
    cap.cost.maximum = None;
    cap.cost.currency = None;
    cap.cost.billing_model = BillingModelV1::UsageBased;
    cap.cost.exposure = CostExposureV1::DownstreamUsage;
    cap.cost.basis = Some("Finite read attempts/output; row scans and currency for an in-flight query have no established hard ceiling. See https://developers.cloudflare.com/d1/platform/pricing/".into());
    cap.verification.required = true;
    cap.verification.strategy = "reviewed_d1_read_inventory_v1".into();
    cap.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".into()],
        success_media_types: vec!["application/json".into()],
        body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
    });
    cap.request_schema = Some(serde_json::json!({
        "type":"object", "additionalProperties":false,
        "required":["inventory_sha256","expected_credential_generation_id"],
        "properties":{
            "inventory_sha256":{"type":"string","enum":[contract.operation.inventory_sha256]},
            "expected_credential_generation_id":{"type":"string","minLength":36,"maxLength":36}
        }
    }));
    cap.workspace_d1_read_inventory = Some(contract);
    cap
}

fn lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn database_id(value: &str) -> bool {
    value.split('-').map(str::len).eq([8, 4, 4, 4, 12])
        && value.split('-').all(|part| lower_hex(part, part.len()))
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
fn invalid(message: &str) -> WorkspaceError {
    WorkspaceError::DiscoveryInvariant(message.into())
}
