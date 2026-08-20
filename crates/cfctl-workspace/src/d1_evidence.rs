use std::{
    collections::BTreeSet,
    path::{Component, Path, PathBuf},
};

use cfctl_core::{
    AdapterStatus, BillingModelV1, CapabilityAuthorityScopeV1, CapabilityV1, CostExposureV1,
    CostV1, EffectClass, EntitlementV1, Maturity, RiskClass, RollbackSpecV1, SelectorV1,
    VerificationSpecV1, WorkspaceD1EvidenceContractV1,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::{RegisteredRoot, Result, WorkspaceError, WorkspaceGraph, git_blob, git_optional};

const PACK_RELATIVE_PATH: &str = ".cfctl/operations/d1-evidence.toml";
const PACK_SCHEMA_VERSION: u8 = 1;
const RESULT_COLUMNS: &[&str] = &[
    "active_policy_digest",
    "desired_state_digest",
    "semantic_projection_digest",
    "immutable_policy_object_key",
    "expected_domain_count",
    "projected_domain_count",
    "expected_route_count",
    "projected_route_count",
    "approved_schema_present",
    "approved_table_presence_json",
    "audit_event_counts_json",
    "queue_correlation_count",
    "dlq_correlation_count",
];

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
    query_path: String,
    query_sha256: String,
    result_columns: Vec<String>,
}

/// Load one clean-repository-owned, fixed-query D1 evidence capability.
/// Caller SQL, parameters, PRAGMAs, projections, and output paths do not exist
/// in the resulting request contract.
pub fn load_workspace_d1_evidence_capability(
    roots: &[PathBuf],
    capability_id: &str,
) -> Result<Option<CapabilityV1>> {
    let registered = roots
        .iter()
        .map(|path| RegisteredRoot::new(path))
        .collect::<Vec<_>>();
    let graph = WorkspaceGraph::discover(&registered)?;
    let mut matches = Vec::new();
    for repository in &graph.repositories {
        if let Some(capability) = load_from_repository(repository, capability_id)? {
            matches.push(capability);
        }
    }
    match matches.len() {
        0 => Ok(None),
        1 => Ok(matches.pop()),
        count => Err(invariant(format!(
            "workspace D1 evidence id `{capability_id}` is ambiguous across {count} registered repositories"
        ))),
    }
}

fn load_from_repository(
    repository: &super::RepositoryNode,
    capability_id: &str,
) -> Result<Option<CapabilityV1>> {
    let pack_path = repository.path.join(PACK_RELATIVE_PATH);
    if !pack_path.is_file() {
        return Ok(None);
    }
    if repository.git.dirty {
        return Err(invariant(format!(
            "workspace D1 evidence repository `{}` must be clean",
            repository.path.display()
        )));
    }
    let head = repository
        .git
        .head
        .as_deref()
        .filter(|value| lower_hex(value, 40))
        .ok_or_else(|| invariant("workspace D1 evidence repository has no canonical HEAD"))?;
    let origin = git_optional(&repository.path, &["config", "--get", "remote.origin.url"])?
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invariant("workspace D1 evidence repository has no origin"))?;
    let pack_bytes = committed_file(&repository.path, Path::new(PACK_RELATIVE_PATH))?;
    let pack: OperationPack = toml::from_str(
        std::str::from_utf8(&pack_bytes)
            .map_err(|_| invariant("workspace D1 evidence pack is not UTF-8"))?,
    )
    .map_err(|error| invariant(format!("workspace D1 evidence pack is invalid: {error}")))?;
    if pack.schema_version != PACK_SCHEMA_VERSION {
        return Err(invariant(
            "workspace D1 evidence pack schema version is unsupported",
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
        return Err(invariant(
            "workspace D1 evidence pack contains duplicate ids",
        ));
    }
    let Some(operation) = pack
        .operation
        .iter()
        .find(|operation| operation.id == capability_id)
    else {
        return Ok(None);
    };
    validate_operation(operation)?;
    let template = committed_file(
        &repository.path,
        &safe_relative(&operation.config_template)?,
    )?;
    let query = committed_file(&repository.path, &safe_relative(&operation.query_path)?)?;
    validate_fixed_query(&query)?;
    if operation.query_sha256 != sha256(&query) {
        return Err(invariant(
            "workspace D1 evidence query does not match its declared SHA-256",
        ));
    }
    let contract = WorkspaceD1EvidenceContractV1 {
        repository_root: repository.path.display().to_string(),
        repository_head: head.to_owned(),
        repository_origin: origin,
        operation_pack_path: PACK_RELATIVE_PATH.to_owned(),
        operation_pack_sha256: sha256(&pack_bytes),
        config_template_path: operation.config_template.clone(),
        config_template_sha256: sha256(&template),
        production_config_path: safe_relative(&operation.production_config)?
            .display()
            .to_string(),
        database_binding: operation.database_binding.clone(),
        wrangler_version: operation.wrangler_version.clone(),
        query_path: operation.query_path.clone(),
        query_sha256: operation.query_sha256.clone(),
        result_columns: operation.result_columns.clone(),
    };
    Ok(Some(capability(operation, contract)))
}

fn validate_fixed_query(query: &[u8]) -> Result<()> {
    if query.is_empty() || query.len() > 65_536 {
        return Err(invariant(
            "workspace D1 evidence query must be between 1 byte and 64 KiB",
        ));
    }
    let text = std::str::from_utf8(query)
        .map_err(|_| invariant("workspace D1 evidence query is not UTF-8"))?;
    let normalized = text.trim().to_ascii_lowercase();
    if (!normalized.starts_with("select ") && !normalized.starts_with("with "))
        || normalized.contains("--")
        || normalized.contains("/*")
        || normalized.contains('?')
        || normalized.matches(';').count() > 1
        || (normalized.contains(';') && !normalized.ends_with(';'))
    {
        return Err(invariant(
            "workspace D1 evidence query must be one parameter-free SELECT without comments",
        ));
    }
    for forbidden in [
        "insert",
        "update",
        "delete",
        "replace",
        "pragma",
        "attach",
        "detach",
        "alter",
        "drop",
        "create",
        "vacuum",
        "reindex",
        "load_extension",
    ] {
        if normalized
            .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
            .any(|token| token == forbidden)
        {
            return Err(invariant(format!(
                "workspace D1 evidence query contains forbidden token `{forbidden}`"
            )));
        }
    }
    Ok(())
}

fn validate_operation(operation: &OperationDeclaration) -> Result<()> {
    let expected_columns = RESULT_COLUMNS
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    if !valid_operation_id(&operation.id)
        || operation.title.trim().is_empty()
        || operation.description.trim().is_empty()
        || !safe_identifier(&operation.database_binding)
        || !valid_wrangler_version(&operation.wrangler_version)
        || !sha256_value(&operation.query_sha256)
        || operation.result_columns != expected_columns
    {
        return Err(invariant(
            "workspace D1 evidence declaration is not the fixed Maildesk projection contract",
        ));
    }
    Ok(())
}

fn capability(
    operation: &OperationDeclaration,
    contract: WorkspaceD1EvidenceContractV1,
) -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        &operation.id,
        &operation.title,
        "GET",
        "wrangler d1 execute [workspace-fixed-body-free-query]",
    );
    capability.description = Some(operation.description.clone());
    capability.authority_scope = Some(CapabilityAuthorityScopeV1::WorkspaceOwned);
    capability.product = "D1".to_owned();
    capability.source = "workspace-d1-evidence-pack-v1".to_owned();
    capability.account_scope = "account".to_owned();
    capability.selectors = vec![
        selector("account_id", "path"),
        selector("database_id", "path"),
        selector("config", "query"),
        selector("binding", "query"),
    ];
    capability.permissions = vec!["D1 Read".to_owned()];
    capability.mutating = false;
    capability.risk = RiskClass::Read;
    capability.effect = EffectClass::ReadOnly;
    capability.maturity = Maturity::GenerallyAvailable;
    capability.entitlement = EntitlementV1 {
        available: Some(true),
        source: Some("workspace operation requires an existing D1 database".to_owned()),
        ..EntitlementV1::default()
    };
    capability.cost = CostV1 {
        incremental: false,
        currency: None,
        maximum: None,
        basis: Some(
            "one fixed bounded D1 evidence projection uses ordinary read pricing".to_owned(),
        ),
        known: true,
        billing_model: BillingModelV1::UsageBased,
        exposure: CostExposureV1::DownstreamUsage,
        references: Vec::new(),
    };
    capability.verification = VerificationSpecV1 {
        required: true,
        strategy: "workspace_d1_maildesk_body_free_evidence".to_owned(),
    };
    capability.rollback = RollbackSpecV1 {
        supported: false,
        strategy: None,
        warning: None,
    };
    capability.adapter_status = AdapterStatus::DelegatedCli;
    capability.workspace_d1_evidence = Some(contract);
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
    let worktree = std::fs::read(repository.join(&relative))
        .map_err(|source| super::io_error(&repository.join(&relative), source))?;
    let committed = git_blob(repository, &relative)?.ok_or_else(|| {
        invariant(format!(
            "workspace D1 evidence input `{}` is not tracked at HEAD",
            relative.display()
        ))
    })?;
    if worktree != committed {
        return Err(invariant(format!(
            "workspace D1 evidence input `{}` differs from HEAD",
            relative.display()
        )));
    }
    Ok(worktree)
}

fn reject_symlinks(repository: &Path, relative: &Path) -> Result<()> {
    let mut current = repository.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(invariant(
                "workspace D1 evidence path is not a safe relative path",
            ));
        };
        current.push(component);
        let metadata = std::fs::symlink_metadata(&current)
            .map_err(|source| super::io_error(&current, source))?;
        if metadata.file_type().is_symlink() {
            return Err(invariant("workspace D1 evidence path traverses a symlink"));
        }
    }
    Ok(())
}

fn safe_relative(value: &str) -> Result<PathBuf> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(invariant(
            "workspace D1 evidence path is not a safe relative path",
        ));
    }
    Ok(path.to_path_buf())
}

fn valid_operation_id(value: &str) -> bool {
    let Some((namespace, operation)) = value.split_once('.') else {
        return false;
    };
    [namespace, operation].into_iter().all(|part| {
        !part.is_empty()
            && part.len() <= 63
            && part
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    })
}

fn safe_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().enumerate().all(|(index, byte)| {
            byte == b'_' || byte.is_ascii_alphabetic() || (index > 0 && byte.is_ascii_digit())
        })
}

fn valid_wrangler_version(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_value(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|digest| lower_hex(digest, 64))
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
    use std::{fs, process::Command};
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

    fn query() -> &'static str {
        "SELECT 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' AS active_policy_digest, 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' AS desired_state_digest, 'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' AS semantic_projection_digest, 'policies/sha256-aaaa.json' AS immutable_policy_object_key, 2 AS expected_domain_count, 2 AS projected_domain_count, 141 AS expected_route_count, 141 AS projected_route_count, 1 AS approved_schema_present, '{\"alias_routes\":true}' AS approved_table_presence_json, '{\"route_decision\":4}' AS audit_event_counts_json, 0 AS queue_correlation_count, 0 AS dlq_correlation_count;\n"
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
                "https://example.com/star-maildesk-cf.git",
            ],
        );
        fs::create_dir_all(root.path().join(".cfctl/operations")).expect("pack dir");
        fs::write(root.path().join("wrangler.toml"), "name = \"template\"\n[[d1_databases]]\nbinding = \"DB\"\ndatabase_name = \"template-db\"\ndatabase_id = \"00000000-0000-0000-0000-000000000000\"\n").expect("config");
        fs::write(root.path().join("evidence.sql"), query()).expect("query");
        let columns = RESULT_COLUMNS
            .iter()
            .map(|column| format!("  \"{column}\","))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(
            root.path().join(PACK_RELATIVE_PATH),
            format!(
                "schema_version = 1\n\n[[operation]]\nid = \"star-maildesk-cf.d1-evidence-read\"\ntitle = \"Read Maildesk D1 evidence\"\ndescription = \"Read one fixed body-free evidence projection.\"\nconfig_template = \"wrangler.toml\"\nproduction_config = \"wrangler.production.toml\"\ndatabase_binding = \"DB\"\nwrangler_version = \"4.120.1\"\nquery_path = \"evidence.sql\"\nquery_sha256 = \"{}\"\nresult_columns = [\n{}\n]\n",
                sha256(query().as_bytes()),
                columns
            ),
        )
        .expect("pack");
        git(root.path(), &["add", "."]);
        git(root.path(), &["commit", "-qm", "fixture"]);
        root
    }

    #[test]
    fn loads_only_the_fixed_body_free_projection() {
        let root = fixture();
        let capability = load_workspace_d1_evidence_capability(
            &[root.path().to_path_buf()],
            "star-maildesk-cf.d1-evidence-read",
        )
        .expect("load")
        .expect("capability");
        assert_eq!(capability.effect, EffectClass::ReadOnly);
        assert!(!capability.mutating);
        assert!(capability.request_schema.is_none());
        assert!(capability.verification_contract_supported());
        let rendered = serde_json::to_string(&capability).expect("capability JSON");
        for private in ["email", "subject", "recipient", "message_content"] {
            assert!(!rendered.contains(private));
        }
    }

    #[test]
    fn dirty_query_and_mutating_sql_fail_closed() {
        let root = fixture();
        fs::write(root.path().join("evidence.sql"), "DELETE FROM messages;").expect("query drift");
        let error = load_workspace_d1_evidence_capability(
            &[root.path().to_path_buf()],
            "star-maildesk-cf.d1-evidence-read",
        )
        .expect_err("dirty authority fails closed");
        assert!(error.to_string().contains("must be clean"));

        assert!(validate_fixed_query(b"DELETE FROM messages;").is_err());
        assert!(validate_fixed_query(b"PRAGMA table_info(messages);").is_err());
        assert!(validate_fixed_query(b"SELECT ? AS active_policy_digest;").is_err());
    }
}
