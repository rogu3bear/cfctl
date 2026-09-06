use std::{
    collections::BTreeSet,
    fs,
    path::{Component, Path, PathBuf},
};

use cfctl_core::{
    AdapterStatus, BillingModelV1, CapabilityAuthorityScopeV1, CapabilityV1, CostExposureV1,
    CostV1, EffectClass, EntitlementV1, KnowledgeReferenceV1, Maturity, RiskClass, RollbackSpecV1,
    SelectorV1, VerificationSpecV1, WorkspaceD1PolicyProjectionContractV1,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::{Result, WorkspaceError, git_blob, git_optional};

const PACK_RELATIVE_PATH: &str = ".cfctl/operations/d1-policy-projections.toml";
const PACK_SCHEMA_VERSION: u8 = 1;

#[derive(Debug, Deserialize)]
struct OperationPack {
    schema_version: u8,
    operation: Vec<OperationDeclaration>,
}

#[derive(Debug, Deserialize)]
struct OperationDeclaration {
    id: String,
    title: String,
    description: String,
    config_template: String,
    production_config: String,
    database_binding: String,
    wrangler_version: String,
    route_table: String,
    route_policy_sha_column: String,
    runtime_state_table: String,
    runtime_state_key_column: String,
    runtime_state_value_column: String,
    active_policy_key: String,
    desired_state_digest_key: String,
    projection_digest_key: String,
    recovery_capability_id: String,
    recovery_max_age_seconds: u64,
    rollback_capability_id: String,
}

/// Loads one uniquely named private D1 policy-projection capability from a
/// clean, explicitly registered repository. Projection bytes are deliberately
/// not part of this committed authority; the CLI stages them privately later.
pub fn load_workspace_d1_policy_projection_capability(
    roots: &[PathBuf],
    capability_id: &str,
) -> Result<Option<CapabilityV1>> {
    load_selected(&super::operation_identity::discover(roots)?, capability_id)
}

pub(super) fn load_selected(
    candidates: &[PathBuf],
    capability_id: &str,
) -> Result<Option<CapabilityV1>> {
    let repositories =
        super::operation_identity::select(candidates, PACK_RELATIVE_PATH, capability_id)?;
    let mut matches = Vec::new();
    for repository in &repositories {
        if let Some(capability) = load_from_repository(repository, capability_id)? {
            matches.push(capability);
        }
    }
    match matches.len() {
        0 => Ok(None),
        1 => Ok(matches.pop()),
        count => Err(invariant(format!(
            "workspace operation id `{capability_id}` is ambiguous across {count} registered repositories"
        ))),
    }
}

fn load_from_repository(
    repository: &super::RepositoryNode,
    capability_id: &str,
) -> Result<Option<CapabilityV1>> {
    if !super::operation_identity::contains(&repository.path, PACK_RELATIVE_PATH, capability_id)? {
        return Ok(None);
    }
    if repository.git.dirty {
        return Err(invariant(format!(
            "workspace operation repository `{}` must be clean",
            repository.path.display()
        )));
    }
    let head = repository
        .git
        .head
        .as_deref()
        .filter(|value| is_lower_hex(value, 40))
        .ok_or_else(|| invariant("workspace operation repository has no canonical HEAD"))?;
    let origin = git_optional(&repository.path, &["config", "--get", "remote.origin.url"])?
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invariant("workspace operation repository has no origin"))?;
    let pack_bytes = committed_file(&repository.path, Path::new(PACK_RELATIVE_PATH))?;
    let pack: OperationPack = toml::from_str(
        std::str::from_utf8(&pack_bytes)
            .map_err(|_| invariant("workspace operation pack is not UTF-8"))?,
    )
    .map_err(|error| invariant(format!("workspace operation pack is invalid: {error}")))?;
    if pack.schema_version != PACK_SCHEMA_VERSION {
        return Err(invariant(
            "workspace operation pack schema version is unsupported",
        ));
    }
    if pack
        .operation
        .iter()
        .map(|operation| operation.id.as_str())
        .collect::<BTreeSet<_>>()
        .len()
        != pack.operation.len()
    {
        return Err(invariant("workspace operation pack contains duplicate ids"));
    }
    let Some(operation) = pack
        .operation
        .iter()
        .find(|operation| operation.id == capability_id)
    else {
        return Ok(None);
    };
    validate_operation(operation)?;
    let template_relative = safe_relative(&operation.config_template)?;
    let template = committed_file(&repository.path, &template_relative)?;
    let production_config = safe_relative(&operation.production_config)?;
    let contract = WorkspaceD1PolicyProjectionContractV1 {
        repository_root: repository.path.display().to_string(),
        repository_head: head.to_owned(),
        repository_origin: origin,
        operation_pack_path: PACK_RELATIVE_PATH.to_owned(),
        operation_pack_sha256: sha256(&pack_bytes),
        config_template_path: operation.config_template.clone(),
        config_template_sha256: sha256(&template),
        production_config_path: production_config.display().to_string(),
        database_binding: operation.database_binding.clone(),
        wrangler_version: operation.wrangler_version.clone(),
        route_table: operation.route_table.clone(),
        route_policy_sha_column: operation.route_policy_sha_column.clone(),
        runtime_state_table: operation.runtime_state_table.clone(),
        runtime_state_key_column: operation.runtime_state_key_column.clone(),
        runtime_state_value_column: operation.runtime_state_value_column.clone(),
        active_policy_key: operation.active_policy_key.clone(),
        desired_state_digest_key: operation.desired_state_digest_key.clone(),
        projection_digest_key: operation.projection_digest_key.clone(),
        recovery_capability_id: operation.recovery_capability_id.clone(),
        recovery_max_age_seconds: operation.recovery_max_age_seconds,
        rollback_capability_id: operation.rollback_capability_id.clone(),
    };
    Ok(Some(capability(operation, contract)))
}

fn validate_operation(operation: &OperationDeclaration) -> Result<()> {
    let identifiers = [
        operation.database_binding.as_str(),
        operation.route_table.as_str(),
        operation.route_policy_sha_column.as_str(),
        operation.runtime_state_table.as_str(),
        operation.runtime_state_key_column.as_str(),
        operation.runtime_state_value_column.as_str(),
    ];
    if !valid_operation_id(&operation.id)
        || operation.title.trim().is_empty()
        || operation.description.trim().is_empty()
        || identifiers.into_iter().any(|value| !safe_identifier(value))
        || !safe_state_key(&operation.active_policy_key)
        || !safe_state_key(&operation.desired_state_digest_key)
        || !safe_state_key(&operation.projection_digest_key)
        || [
            operation.active_policy_key.as_str(),
            operation.desired_state_digest_key.as_str(),
            operation.projection_digest_key.as_str(),
        ]
        .into_iter()
        .collect::<BTreeSet<_>>()
        .len()
            != 3
        || !valid_wrangler_version(&operation.wrangler_version)
        || operation.recovery_capability_id != "d1-time-travel-get-bookmark"
        || operation.recovery_max_age_seconds == 0
        || operation.recovery_max_age_seconds > 600
        || operation.rollback_capability_id != "d1-restore-exact-bookmark"
    {
        return Err(invariant("workspace D1 projection declaration is invalid"));
    }
    Ok(())
}

fn capability(
    operation: &OperationDeclaration,
    contract: WorkspaceD1PolicyProjectionContractV1,
) -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        &operation.id,
        &operation.title,
        "POST",
        "wrangler d1 execute --file <private-stage>",
    );
    capability.description = Some(operation.description.clone());
    capability.authority_scope = Some(CapabilityAuthorityScopeV1::WorkspaceOwned);
    "D1".clone_into(&mut capability.product);
    "workspace-operation-pack-v1".clone_into(&mut capability.source);
    "account".clone_into(&mut capability.account_scope);
    capability.selectors = vec![
        selector("account_id", "path"),
        selector("database_id", "path"),
        selector("config", "query"),
        selector("policy_sha256", "query"),
        selector("desired_state_sha256", "query"),
        selector("projection_sha256", "query"),
        selector("expected_route_count", "query"),
    ];
    capability.permissions = vec!["D1 Read".to_owned(), "D1 Write".to_owned()];
    capability.mutating = true;
    capability.risk = RiskClass::ScopedWrite;
    capability.effect = EffectClass::DataWrite;
    capability.maturity = Maturity::GenerallyAvailable;
    capability.entitlement = EntitlementV1 {
        available: Some(true),
        source: Some(
            "workspace operation requires an existing provider-read D1 database".to_owned(),
        ),
        ..EntitlementV1::default()
    };
    capability.cost = CostV1 {
        incremental: false,
        currency: None,
        maximum: None,
        basis: Some("the operation creates no billable resource; bounded D1 row writes remain subject to ordinary usage pricing".to_owned()),
        known: true,
        billing_model: BillingModelV1::UsageBased,
        exposure: CostExposureV1::DownstreamUsage,
        references: vec![KnowledgeReferenceV1 {
            title: "Cloudflare D1 pricing".to_owned(),
            url: "https://developers.cloudflare.com/d1/platform/pricing/".to_owned(),
            source: "cloudflare-docs".to_owned(),
        }],
    };
    capability.verification = VerificationSpecV1 {
        required: true,
        strategy: "workspace_d1_policy_projection_count_and_digest".to_owned(),
    };
    capability.rollback = RollbackSpecV1 {
        supported: false,
        strategy: None,
        warning: Some("automatic rollback is forbidden; recovery requires a separately approved d1-restore-exact-bookmark plan bound to the fresh pre-projection bookmark".to_owned()),
    };
    capability.adapter_status = AdapterStatus::DelegatedCli;
    capability.blocked_reason = None;
    capability.workspace_d1_policy_projection = Some(contract);
    capability
}

fn selector(name: &str, location: &str) -> SelectorV1 {
    SelectorV1 {
        name: name.to_owned(),
        location: location.to_owned(),
        required: true,
        value_type: "string".to_owned(),
        description: None,
        contract: None,
    }
}

fn committed_file(repository: &Path, relative: &Path) -> Result<Vec<u8>> {
    let relative = safe_relative(relative.to_string_lossy().as_ref())?;
    reject_symlinks(repository, &relative)?;
    let worktree = fs::read(repository.join(&relative))
        .map_err(|source| super::io_error(&repository.join(&relative), source))?;
    let committed = git_blob(repository, &relative)?.ok_or_else(|| {
        invariant(format!(
            "workspace operation input `{}` is not tracked at HEAD",
            relative.display()
        ))
    })?;
    if worktree != committed {
        return Err(invariant(format!(
            "workspace operation input `{}` differs from HEAD",
            relative.display()
        )));
    }
    Ok(worktree)
}

fn reject_symlinks(repository: &Path, relative: &Path) -> Result<()> {
    let mut cursor = repository.to_path_buf();
    for component in relative.components() {
        cursor.push(component.as_os_str());
        let metadata =
            fs::symlink_metadata(&cursor).map_err(|source| super::io_error(&cursor, source))?;
        if metadata.file_type().is_symlink() {
            return Err(invariant(format!(
                "workspace operation input `{}` contains a symlink",
                relative.display()
            )));
        }
    }
    Ok(())
}

fn safe_relative(value: &str) -> Result<PathBuf> {
    let path = PathBuf::from(value);
    if value.is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir
                    | Component::CurDir
                    | Component::RootDir
                    | Component::Prefix(_)
            )
        })
    {
        return Err(invariant(
            "workspace operation paths must be normalized and relative",
        ));
    }
    Ok(path)
}

fn valid_operation_id(value: &str) -> bool {
    (3..=128).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')
        })
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
}

fn valid_wrangler_version(value: &str) -> bool {
    let components = value.split('.').collect::<Vec<_>>();
    components.len() == 3
        && components.iter().all(|component| {
            !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn safe_identifier(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn safe_state_key(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn invariant(message: impl Into<String>) -> WorkspaceError {
    WorkspaceError::DiscoveryInvariant(message.into())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::process::Command;
    use tempfile::TempDir;

    fn git(root: &Path, arguments: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(arguments)
            .status()
            .expect("git command");
        assert!(status.success());
    }

    fn fixture() -> TempDir {
        let root = tempfile::tempdir().expect("temp repository");
        git(root.path(), &["init", "-q"]);
        git(root.path(), &["config", "user.email", "test@example.com"]);
        git(root.path(), &["config", "user.name", "Test"]);
        git(
            root.path(),
            &[
                "remote",
                "add",
                "origin",
                "https://example.com/maildesk-cf.git",
            ],
        );
        fs::create_dir_all(root.path().join(".cfctl/operations")).expect("pack dir");
        fs::write(root.path().join("wrangler.toml"), "name = \"template\"\n[[d1_databases]]\nbinding = \"DB\"\ndatabase_name = \"template-db\"\ndatabase_id = \"00000000-0000-0000-0000-000000000000\"\n").expect("config");
        fs::write(
            root.path().join(PACK_RELATIVE_PATH),
            r#"schema_version = 1

[[operation]]
id = "maildesk.d1-policy-project"
title = "Project Maildesk policy"
description = "Project a reviewed private policy into D1."
config_template = "wrangler.toml"
production_config = "wrangler.production.toml"
database_binding = "DB"
wrangler_version = "4.120.1"
route_table = "alias_routes"
route_policy_sha_column = "policy_sha256"
runtime_state_table = "runtime_state"
runtime_state_key_column = "key"
runtime_state_value_column = "value"
active_policy_key = "active_policy_sha256"
desired_state_digest_key = "active_desired_state_sha256"
projection_digest_key = "active_projection_sha256"
recovery_capability_id = "d1-time-travel-get-bookmark"
recovery_max_age_seconds = 600
rollback_capability_id = "d1-restore-exact-bookmark"
"#,
        )
        .expect("pack");
        git(root.path(), &["add", "."]);
        git(root.path(), &["commit", "-qm", "fixture"]);
        root
    }

    #[test]
    fn loads_closed_projection_contract_without_private_bytes() {
        let root = fixture();
        let capability = load_workspace_d1_policy_projection_capability(
            &[root.path().to_path_buf()],
            "maildesk.d1-policy-project",
        )
        .expect("load")
        .expect("capability");
        assert!(capability.mutation_contract_gaps().is_empty());
        let value = serde_json::to_value(&capability).expect("serialize");
        let encoded = value.to_string();
        assert!(!encoded.contains("operator@example.com"));
        assert!(!encoded.contains("INSERT INTO"));
    }

    #[test]
    fn dirty_operation_authority_fails_closed() {
        let root = fixture();
        fs::write(root.path().join("wrangler.toml"), "drift").expect("drift");
        let error = load_workspace_d1_policy_projection_capability(
            &[root.path().to_path_buf()],
            "maildesk.d1-policy-project",
        )
        .expect_err("dirty fails closed");
        assert!(error.to_string().contains("must be clean"));
    }
}
