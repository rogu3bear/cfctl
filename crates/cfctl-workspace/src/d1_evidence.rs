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

use super::{Result, WorkspaceError, git_blob, git_optional};

const PACK_RELATIVE_PATH: &str = ".cfctl/operations/d1-evidence.toml";
const PACK_SCHEMA_VERSION: u8 = 1;
pub const MAILDESK_D1_EVIDENCE_COLUMNS_V1: &[&str] = &[
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

/// Independent active-policy sources required by current Maildesk verification.
pub const MAILDESK_D1_POLICY_IDENTITY_COLUMNS_V2: &[&str] =
    &["revision_r2_key", "projection_policy_sha256"];

/// Additive route-health columns carried by the same compiler-owned query.
/// The V1 aggregate column contract above remains unchanged.
pub const MAILDESK_D1_ROUTE_HEALTH_COLUMNS_V2: &[&str] =
    &["active_route_health_count", "route_health_rows_json"];

pub const MAILDESK_INBOUND_ACCEPTANCE_CAPABILITY_ID: &str =
    "star-maildesk-cf.inbound-acceptance-read";
pub const MAILDESK_INBOUND_ACCEPTANCE_PROJECTION_V1: &str = "maildesk_inbound_acceptance_v1";
pub const MAILDESK_INBOUND_ACCEPTANCE_COLUMNS_V1: &[&str] = &[
    "inbound_delivery_id",
    "relay_id",
    "thread_id",
    "route_id",
    "policy_sha256",
    "provider_accepted_at",
    "status",
    "recipient_count",
    "provider_accepted_count",
];
pub const MAILDESK_INBOUND_ACCEPTANCE_SQL_V1: &str = r"SELECT
  inbound.id AS inbound_delivery_id,
  inbound.relay_id,
  inbound.thread_id,
  inbound.route_id,
  inbound.policy_sha256,
  rh.last_inbound_provider_accepted_at AS provider_accepted_at,
  inbound.status,
  (SELECT COUNT(*) FROM inbound_recipient_deliveries rd WHERE rd.delivery_id = inbound.id) AS recipient_count,
  (SELECT COUNT(*) FROM inbound_recipient_deliveries rd WHERE rd.delivery_id = inbound.id AND rd.status = 'provider_accepted') AS provider_accepted_count
FROM inbound_deliveries inbound
JOIN route_health rh ON rh.route_id = inbound.route_id AND rh.policy_sha256 = inbound.policy_sha256
WHERE inbound.fingerprint_sha256 = '__MAILDESK_FINGERPRINT_SHA256__'
  AND inbound.route_id = '__MAILDESK_ROUTE_ID__'
  AND inbound.policy_sha256 = '__MAILDESK_POLICY_SHA256__'
LIMIT 2;";

/// Compiler-owned Maildesk readiness projection. Every source table, column,
/// expression, predicate, action key, and output alias is fixed here; a
/// workspace declaration cannot supply or modify SQL.
pub const MAILDESK_D1_EVIDENCE_SQL_V1: &str = r"SELECT
  'sha256:' || rs.active_policy_sha256 AS active_policy_digest,
  'sha256:' || (SELECT value FROM policy_projection_state WHERE key = 'active_desired_state_sha256') AS desired_state_digest,
  'sha256:' || (SELECT value FROM policy_projection_state WHERE key = 'active_projection_sha256') AS semantic_projection_digest,
  rs.active_policy_r2_key AS immutable_policy_object_key,
  substr(pr.r2_object_key, 1, 1025) AS revision_r2_key,
  'sha256:' || (SELECT value FROM policy_projection_state WHERE key = 'active_policy_sha256') AS projection_policy_sha256,
  pr.expected_domain_count AS expected_domain_count,
  (SELECT COUNT(DISTINCT ar.domain_id) FROM alias_routes ar WHERE ar.enabled = 1 AND ar.policy_sha256 = rs.active_policy_sha256) AS projected_domain_count,
  pr.expected_route_count AS expected_route_count,
  (SELECT COUNT(*) FROM alias_routes ar WHERE ar.enabled = 1 AND ar.policy_sha256 = rs.active_policy_sha256) AS projected_route_count,
  CASE WHEN (SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' AND name IN ('alias_routes','audit_events','domains','inbound_deliveries','inbound_recipient_deliveries','policy_projection_state','policy_revisions','relay_attempts','route_health','runtime_state')) = 10 THEN 1 ELSE 0 END AS approved_schema_present,
  json_object(
    'alias_routes', EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'alias_routes'),
    'audit_events', EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'audit_events'),
    'domains', EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'domains'),
    'inbound_deliveries', EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'inbound_deliveries'),
    'inbound_recipient_deliveries', EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'inbound_recipient_deliveries'),
    'policy_projection_state', EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'policy_projection_state'),
    'policy_revisions', EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'policy_revisions'),
    'relay_attempts', EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'relay_attempts'),
    'route_health', EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'route_health'),
    'runtime_state', EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'runtime_state')
  ) AS approved_table_presence_json,
  json_object(
    'inbound_email_accepted', (SELECT COUNT(*) FROM audit_events WHERE action = 'inbound_email_accepted'),
    'operator_delivery_provider_accepted', (SELECT COUNT(*) FROM audit_events WHERE action = 'operator_delivery_provider_accepted'),
    'inbox_reply_authorized', (SELECT COUNT(*) FROM audit_events WHERE action = 'inbox_reply_authorized'),
    'outbound_reply_delivered', (SELECT COUNT(*) FROM audit_events WHERE action = 'outbound_reply_delivered'),
    'outbound_reply_retry_scheduled', (SELECT COUNT(*) FROM audit_events WHERE action = 'outbound_reply_retry_scheduled'),
    'outbound_reply_recovery_required', (SELECT COUNT(*) FROM audit_events WHERE action = 'outbound_reply_recovery_required'),
    'outbound_reply_failed', (SELECT COUNT(*) FROM audit_events WHERE action = 'outbound_reply_failed')
  ) AS audit_event_counts_json,
  (SELECT COUNT(*) FROM relay_attempts WHERE status IN ('receiving','queued','authorized')) +
    (SELECT COUNT(*) FROM inbound_deliveries WHERE status IN ('pending','sending')) +
    (SELECT COUNT(*) FROM inbound_recipient_deliveries WHERE status IN ('pending','sending')) AS queue_correlation_count,
  (SELECT COUNT(*) FROM relay_attempts WHERE status IN ('failed','recovery_required')) +
    (SELECT COUNT(*) FROM inbound_deliveries WHERE status IN ('failed','recovery_required')) +
    (SELECT COUNT(*) FROM inbound_recipient_deliveries WHERE status IN ('failed','recovery_required')) AS dlq_correlation_count,
  (SELECT COUNT(*)
   FROM alias_routes ar
   JOIN route_health rh ON rh.route_id = ar.id AND rh.policy_sha256 = ar.policy_sha256 AND rh.decision_kind = ar.decision_kind
   WHERE ar.enabled = 1 AND ar.policy_sha256 = rs.active_policy_sha256) AS active_route_health_count,
  (SELECT json_group_array(json(route_row))
   FROM (
     SELECT json_object(
       'route_id', substr(ar.id, 1, 257),
       'domain', substr(lower(d.domain), 1, 254),
       'policy_sha256', substr(ar.policy_sha256, 1, 65),
       'route_kind', substr(rh.decision_kind, 1, 33),
       'enabled', ar.enabled,
       'desired_provider', substr(rh.desired_provider, 1, 65),
       'observed_provider', substr(rh.observed_provider, 1, 65),
       'inbound_status', substr(rh.inbound_status, 1, 65),
       'reply_status', substr(rh.reply_status, 1, 65),
       'provider_accepted_at', substr(rh.last_inbound_provider_accepted_at, 1, 65),
       'inbox_received_at', substr(rh.last_inbox_verified_at, 1, 65),
       'reply_provider_accepted_at', substr(rh.last_reply_provider_accepted_at, 1, 65),
       'reply_proven_at', substr(rh.last_reply_verified_at, 1, 65),
       'last_error_code', substr(rh.last_error_code, 1, 129),
       'updated_at', substr(rh.updated_at, 1, 65)
     ) AS route_row
     FROM alias_routes ar
     JOIN domains d ON d.id = ar.domain_id
     JOIN route_health rh ON rh.route_id = ar.id AND rh.policy_sha256 = ar.policy_sha256 AND rh.decision_kind = ar.decision_kind
     WHERE ar.enabled = 1 AND ar.policy_sha256 = rs.active_policy_sha256
     ORDER BY ar.id
     LIMIT 1001
   )) AS route_health_rows_json
FROM runtime_state rs
JOIN policy_revisions pr ON pr.policy_sha256 = rs.active_policy_sha256
WHERE rs.singleton = 1;";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationPack {
    schema_version: u8,
    operation: Vec<OperationDeclaration>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationDeclaration {
    id: String,
    title: String,
    description: String,
    config_template: String,
    production_config: String,
    database_binding: String,
    wrangler_version: String,
    projection: String,
}

/// Load one clean-repository-owned, fixed-query D1 evidence capability.
/// Caller SQL, parameters, PRAGMAs, projections, and output paths do not exist
/// in the resulting request contract.
pub fn load_workspace_d1_evidence_capability(
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
            "workspace D1 evidence id `{capability_id}` is ambiguous across {count} registered repositories"
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
        projection: operation.projection.clone(),
        query_sha256: sha256(query_for_projection(&operation.projection)?.as_bytes()),
    };
    Ok(Some(capability(operation, contract)))
}

fn validate_operation(operation: &OperationDeclaration) -> Result<()> {
    let identity_matches = (operation.projection == "maildesk_v1"
        && valid_evidence_operation_id(&operation.id))
        || (operation.id == MAILDESK_INBOUND_ACCEPTANCE_CAPABILITY_ID
            && operation.projection == MAILDESK_INBOUND_ACCEPTANCE_PROJECTION_V1);
    if !identity_matches
        || operation.title.trim().is_empty()
        || operation.description.trim().is_empty()
        || !safe_identifier(&operation.database_binding)
        || !valid_wrangler_version(&operation.wrangler_version)
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
    "D1".clone_into(&mut capability.product);
    "workspace-d1-evidence-pack-v1".clone_into(&mut capability.source);
    "account".clone_into(&mut capability.account_scope);
    capability.selectors = vec![
        selector("account_id", "path"),
        selector("database_id", "path"),
        selector("config", "query"),
        selector("binding", "query"),
    ];
    if operation.projection == MAILDESK_INBOUND_ACCEPTANCE_PROJECTION_V1 {
        capability.selectors.extend([
            selector("delivery_fingerprint_sha256", "query"),
            selector("route_id", "query"),
            selector("policy_sha256", "query"),
        ]);
    }
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
        strategy: if operation.projection == MAILDESK_INBOUND_ACCEPTANCE_PROJECTION_V1 {
            "workspace_d1_maildesk_inbound_acceptance_body_free_read".to_owned()
        } else {
            "workspace_d1_maildesk_body_free_evidence".to_owned()
        },
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

fn query_for_projection(projection: &str) -> Result<&'static str> {
    match projection {
        "maildesk_v1" => Ok(MAILDESK_D1_EVIDENCE_SQL_V1),
        MAILDESK_INBOUND_ACCEPTANCE_PROJECTION_V1 => Ok(MAILDESK_INBOUND_ACCEPTANCE_SQL_V1),
        _ => Err(invariant("workspace D1 evidence projection is unsupported")),
    }
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

fn valid_evidence_operation_id(value: &str) -> bool {
    value
        .strip_suffix(".d1-evidence-read")
        .is_some_and(|namespace| {
            !namespace.is_empty()
                && namespace.len() <= 96
                && namespace.split('.').all(|part| {
                    part.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
                        && part
                            .as_bytes()
                            .last()
                            .is_some_and(u8::is_ascii_alphanumeric)
                        && part.bytes().all(|byte| {
                            byte.is_ascii_lowercase()
                                || byte.is_ascii_digit()
                                || matches!(byte, b'-' | b'_')
                        })
                })
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
        fs::write(
            root.path().join(PACK_RELATIVE_PATH),
            "schema_version = 1\n\n[[operation]]\nid = \"star-maildesk-cf.d1-evidence-read\"\ntitle = \"Read Maildesk D1 evidence\"\ndescription = \"Read one compiler-owned body-free evidence projection.\"\nconfig_template = \"wrangler.toml\"\nproduction_config = \"wrangler.production.toml\"\ndatabase_binding = \"DB\"\nwrangler_version = \"4.120.1\"\nprojection = \"maildesk_v1\"\n\n[[operation]]\nid = \"star-maildesk-cf.inbound-acceptance-read\"\ntitle = \"Read one Maildesk inbound acceptance\"\ndescription = \"Read one compiler-owned body-free inbound binding.\"\nconfig_template = \"wrangler.toml\"\nproduction_config = \"wrangler.production.toml\"\ndatabase_binding = \"DB\"\nwrangler_version = \"4.120.1\"\nprojection = \"maildesk_inbound_acceptance_v1\"\n",
        )
        .expect("pack");
        git(root.path(), &["add", "."]);
        git(root.path(), &["commit", "-qm", "fixture"]);
        root
    }

    #[test]
    fn distinct_committed_owners_are_ambiguous_but_overlapping_roots_are_not() {
        let first = fixture();
        let second = fixture();
        let first_path = first.path().to_path_buf();
        assert!(
            load_workspace_d1_evidence_capability(
                &[first_path.clone(), first_path.clone()],
                "star-maildesk-cf.d1-evidence-read"
            )
            .expect("same canonical owner")
            .is_some()
        );
        let error = load_workspace_d1_evidence_capability(
            &[first_path, second.path().to_path_buf()],
            "star-maildesk-cf.d1-evidence-read",
        )
        .expect_err("distinct owners must remain ambiguous");
        assert!(
            error
                .to_string()
                .contains("ambiguous across 2 registered repositories")
        );
    }

    #[test]
    fn unrelated_configuration_does_not_participate_in_operation_lookup() {
        let selected = fixture();
        let unrelated = fixture();
        let pack = unrelated.path().join(PACK_RELATIVE_PATH);
        fs::write(
            &pack,
            "[[operation]]\nid = \"unrelated.d1-evidence-read\"\n",
        )
        .expect("unrelated pack");
        git(unrelated.path(), &["add", "."]);
        git(unrelated.path(), &["commit", "-qm", "unrelated identity"]);
        let nested = unrelated.path().join("nested");
        fs::create_dir(&nested).expect("nested directory");
        fs::write(
            nested.join("wrangler.router.production.toml"),
            "invalid = [",
        )
        .expect("unrelated invalid role config");
        let roots = [
            selected.path().to_path_buf(),
            unrelated.path().to_path_buf(),
        ];
        let registered = roots
            .iter()
            .map(|path| super::super::RegisteredRoot::new(path))
            .collect::<Vec<_>>();
        assert!(
            super::super::WorkspaceGraph::discover(&registered).is_err(),
            "the full config graph has an independent error"
        );
        assert!(
            load_workspace_d1_evidence_capability(&roots, "star-maildesk-cf.d1-evidence-read")
                .expect("only selected operation inputs are validated")
                .is_some()
        );
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
        let contract = capability
            .workspace_d1_evidence
            .as_ref()
            .expect("evidence contract");
        assert_eq!(contract.projection, "maildesk_v1");
        assert_eq!(MAILDESK_D1_EVIDENCE_COLUMNS_V1.len(), 13);
        assert!(!MAILDESK_D1_EVIDENCE_COLUMNS_V1.contains(&"route_health_rows_json"));
        assert_eq!(
            MAILDESK_D1_ROUTE_HEALTH_COLUMNS_V2,
            ["active_route_health_count", "route_health_rows_json"]
        );
        assert_eq!(
            MAILDESK_D1_EVIDENCE_SQL_V1
                .matches("rh.decision_kind = ar.decision_kind")
                .count(),
            2,
            "both the completeness count and emitted rows must reject route-kind drift"
        );
        assert_eq!(
            contract.query_sha256,
            sha256(MAILDESK_D1_EVIDENCE_SQL_V1.as_bytes())
        );
        let rendered = serde_json::to_string(&capability).expect("capability JSON");
        for private in ["email", "subject", "recipient", "message_content"] {
            assert!(!rendered.contains(private));
        }
    }

    #[test]
    fn loads_the_fixed_inbound_acceptance_projection_with_exact_selectors() {
        let root = fixture();
        let capability = load_workspace_d1_evidence_capability(
            &[root.path().to_path_buf()],
            MAILDESK_INBOUND_ACCEPTANCE_CAPABILITY_ID,
        )
        .expect("load")
        .expect("capability");
        assert_eq!(capability.effect, EffectClass::ReadOnly);
        assert!(!capability.mutating);
        assert!(capability.verification_contract_supported());
        assert_eq!(
            capability
                .selectors
                .iter()
                .map(|selector| selector.name.as_str())
                .collect::<Vec<_>>(),
            [
                "account_id",
                "database_id",
                "config",
                "binding",
                "delivery_fingerprint_sha256",
                "route_id",
                "policy_sha256",
            ]
        );
        let contract = capability
            .workspace_d1_evidence
            .as_ref()
            .expect("evidence contract");
        assert_eq!(
            contract.projection,
            MAILDESK_INBOUND_ACCEPTANCE_PROJECTION_V1
        );
        assert_eq!(
            contract.query_sha256,
            sha256(MAILDESK_INBOUND_ACCEPTANCE_SQL_V1.as_bytes())
        );
        assert_eq!(MAILDESK_INBOUND_ACCEPTANCE_COLUMNS_V1.len(), 9);
        assert!(
            MAILDESK_INBOUND_ACCEPTANCE_SQL_V1
                .contains("rh.last_inbound_provider_accepted_at AS provider_accepted_at")
        );
        assert!(MAILDESK_INBOUND_ACCEPTANCE_SQL_V1.contains(
            "JOIN route_health rh ON rh.route_id = inbound.route_id AND rh.policy_sha256 = inbound.policy_sha256"
        ));
        assert!(!MAILDESK_INBOUND_ACCEPTANCE_SQL_V1.contains("updated_at AS provider_accepted_at"));
    }

    #[test]
    fn dirty_authority_and_repository_supplied_sql_fail_closed() {
        let root = fixture();
        fs::write(root.path().join(PACK_RELATIVE_PATH), "schema_version = 1\n")
            .expect("pack drift");
        let error = load_workspace_d1_evidence_capability(
            &[root.path().to_path_buf()],
            "star-maildesk-cf.d1-evidence-read",
        )
        .expect_err("dirty authority fails closed");
        assert!(error.to_string().contains("must be clean"));

        let root = fixture();
        let pack = root.path().join(PACK_RELATIVE_PATH);
        let mut declaration = fs::read_to_string(&pack).expect("pack");
        declaration.push_str(
            "query_path = \"recipient.sql\"\nquery_sha256 = \"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n",
        );
        fs::write(&pack, declaration).expect("alias-smuggling declaration");
        git(root.path(), &["add", "."]);
        git(root.path(), &["commit", "-qm", "attempt query injection"]);
        let error = load_workspace_d1_evidence_capability(
            &[root.path().to_path_buf()],
            "star-maildesk-cf.d1-evidence-read",
        )
        .expect_err("repository SQL fields fail closed");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn adopted_evidence_namespace_keeps_the_fixed_query_and_clean_authority() {
        for id in [
            "maildesk-cf.d1-evidence-read",
            "team.maildesk.d1-evidence-read",
        ] {
            let root = fixture();
            let pack = root.path().join(PACK_RELATIVE_PATH);
            let declaration = fs::read_to_string(&pack)
                .expect("pack")
                .replace("star-maildesk-cf.d1-evidence-read", id);
            fs::write(&pack, declaration).expect("adopted pack");
            git(root.path(), &["add", "."]);
            git(root.path(), &["commit", "-qm", "adopt namespace"]);
            let capability =
                load_workspace_d1_evidence_capability(&[root.path().to_path_buf()], id)
                    .expect("load")
                    .expect("adopted capability");
            assert_eq!(capability.id, id);
            assert!(!capability.mutating);
            assert_eq!(
                capability
                    .workspace_d1_evidence
                    .expect("fixed query contract")
                    .query_sha256,
                sha256(MAILDESK_D1_EVIDENCE_SQL_V1.as_bytes())
            );
            fs::write(root.path().join("dirty"), "unrelated").expect("dirty fixture");
            assert!(
                load_workspace_d1_evidence_capability(&[root.path().to_path_buf()], id).is_err()
            );
        }
        for id in [
            ".d1-evidence-read",
            "../maildesk.d1-evidence-read",
            "Maildesk.d1-evidence-read",
            "maildesk.d1-query",
        ] {
            assert!(!valid_evidence_operation_id(id));
        }
    }

    #[test]
    fn operation_identity_and_projection_are_exact() {
        for (field, replacement) in [
            (
                "id = \"star-maildesk-cf.d1-evidence-read\"",
                "id = \"other/repository.d1-evidence-read\"",
            ),
            (
                "projection = \"maildesk_v1\"",
                "projection = \"caller_sql\"",
            ),
        ] {
            let root = fixture();
            let pack = root.path().join(PACK_RELATIVE_PATH);
            let declaration = fs::read_to_string(&pack)
                .expect("pack")
                .replace(field, replacement);
            fs::write(&pack, declaration).expect("drifted pack");
            git(root.path(), &["add", "."]);
            git(root.path(), &["commit", "-qm", "drift operation"]);
            let capability_id = if replacement.contains("other/repository") {
                "other/repository.d1-evidence-read"
            } else {
                "star-maildesk-cf.d1-evidence-read"
            };
            let error =
                load_workspace_d1_evidence_capability(&[root.path().to_path_buf()], capability_id)
                    .expect_err("identity or projection drift");
            assert!(error.to_string().contains("fixed Maildesk projection"));
        }
    }
}
