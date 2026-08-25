use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use cfctl_core::{
    MaildeskD1EvidenceV1, WorkspaceD1EvidenceContractV1, WorkspaceD1MigrationContractV1,
};
use serde_json::{Map, Value, json};
use tokio::time::Duration;

use cfctl_workspace::{MAILDESK_D1_EVIDENCE_COLUMNS_V1, MAILDESK_D1_EVIDENCE_SQL_V1};

use super::{
    AuthCredential, CallInput, CapabilityV1, CliError, Result, StateStore, workspace_d1_migration,
};

const QUERY_TIMEOUT: Duration = Duration::from_mins(2);
const MAX_MAP_KEYS: usize = 64;
const MAX_COUNT: u64 = 1_000_000_000;
const APPROVED_TABLE_KEYS: &[&str] = &[
    "alias_routes",
    "audit_events",
    "domains",
    "inbound_deliveries",
    "inbound_recipient_deliveries",
    "policy_projection_state",
    "policy_revisions",
    "relay_attempts",
    "route_health",
    "runtime_state",
];
const AUDIT_EVENT_KEYS: &[&str] = &[
    "inbound_email_accepted",
    "operator_delivery_provider_accepted",
    "inbox_reply_authorized",
    "outbound_reply_delivered",
    "outbound_reply_retry_scheduled",
    "outbound_reply_recovery_required",
    "outbound_reply_failed",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailureStage {
    Preflight,
    WranglerVersion,
    ProviderQuery,
    ProviderProjection,
}

impl FailureStage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Preflight => "preflight",
            Self::WranglerVersion => "wrangler_version",
            Self::ProviderQuery => "provider_query",
            Self::ProviderProjection => "provider_projection",
        }
    }

    const fn code(self) -> &'static str {
        match self {
            Self::Preflight => "CFCTL_WORKSPACE_D1_EVIDENCE_PREFLIGHT_FAILED",
            Self::WranglerVersion => "CFCTL_WORKSPACE_D1_EVIDENCE_WRANGLER_VERSION_FAILED",
            Self::ProviderQuery => "CFCTL_WORKSPACE_D1_EVIDENCE_PROVIDER_READ_FAILED",
            Self::ProviderProjection => "CFCTL_WORKSPACE_D1_EVIDENCE_PROJECTION_FAILED",
        }
    }
}

#[derive(Debug)]
pub(super) struct WorkspaceD1EvidenceFailure {
    stage: FailureStage,
    boundary_crossed: bool,
}

impl WorkspaceD1EvidenceFailure {
    fn before_boundary(stage: FailureStage, _source: CliError) -> Self {
        Self {
            stage,
            boundary_crossed: false,
        }
    }

    fn after_boundary(stage: FailureStage, _source: CliError) -> Self {
        Self {
            stage,
            boundary_crossed: true,
        }
    }

    pub(super) fn receipt(&self) -> Value {
        json!({
            "adapter":"workspace_d1_evidence_v1",
            "success":false,
            "boundary_crossed":self.boundary_crossed,
            "failure_code":self.stage.code(),
            "failure_stage":self.stage.as_str(),
            "provider_output_retained":false,
            "body_returned":false,
        })
    }

    pub(super) const fn boundary_crossed(&self) -> bool {
        self.boundary_crossed
    }
}

impl From<CliError> for WorkspaceD1EvidenceFailure {
    fn from(source: CliError) -> Self {
        Self::before_boundary(FailureStage::Preflight, source)
    }
}

pub(super) fn load(store: &StateStore, capability_id: &str) -> Result<Option<CapabilityV1>> {
    Ok(cfctl_workspace::load_workspace_d1_evidence_capability(
        &store.workspace_roots()?,
        capability_id,
    )?)
}

#[expect(
    clippy::too_many_lines,
    reason = "the preflight, version, provider-query, and body-free projection stages remain visible at one evidence boundary"
)]
pub(super) async fn execute(
    store: &StateStore,
    capability: &CapabilityV1,
    input: &CallInput,
    credential: &AuthCredential,
    account_id: &str,
) -> std::result::Result<Value, WorkspaceD1EvidenceFailure> {
    let contract = capability
        .workspace_d1_evidence
        .as_ref()
        .ok_or_else(|| CliError::Input("workspace D1 evidence contract is missing".to_owned()))?;
    let current = load(store, &capability.id)?.ok_or_else(|| {
        CliError::Input(
            "workspace D1 evidence declaration is no longer uniquely available".to_owned(),
        )
    })?;
    if current.workspace_d1_evidence.as_ref() != Some(contract) {
        return Err(CliError::Input(
            "workspace D1 evidence repository authority drifted; repeat the read from the clean committed declaration"
                .to_owned(),
        )
        .into());
    }
    if input.body.is_some() || input.query.as_object().is_none_or(|query| query.len() != 2) {
        return Err(CliError::Input(
            "workspace D1 evidence accepts only exact config and binding selectors; SQL, parameters, PRAGMAs, bodies, and arbitrary projections are impossible"
                .to_owned(),
        )
        .into());
    }
    let binding = input.query.get("binding").and_then(Value::as_str);
    if binding != Some(contract.database_binding.as_str()) {
        return Err(CliError::Input(
            "workspace D1 evidence binding selector differs from the committed declaration"
                .to_owned(),
        )
        .into());
    }
    let config = workspace_d1_migration::validated_config(&config_contract(contract), input)?;
    if contract.projection != "maildesk_v1"
        || sha256(MAILDESK_D1_EVIDENCE_SQL_V1.as_bytes()) != contract.query_sha256
    {
        return Err(CliError::Input(
            "workspace D1 evidence compiler projection drifted from its catalog contract"
                .to_owned(),
        )
        .into());
    }
    let version = workspace_d1_migration::run_wrangler(
        &["--version".to_owned()],
        Path::new(&contract.repository_root),
        credential,
        account_id,
        &store.paths().cache_dir,
        QUERY_TIMEOUT,
    )
    .await
    .map_err(|error| {
        WorkspaceD1EvidenceFailure::before_boundary(FailureStage::WranglerVersion, error)
    })?;
    let observed_version = workspace_d1_migration::parse_wrangler_version(&version.stdout)
        .map_err(|error| {
            WorkspaceD1EvidenceFailure::before_boundary(FailureStage::WranglerVersion, error)
        })?;
    if !version.success || observed_version != contract.wrangler_version {
        return Err(WorkspaceD1EvidenceFailure::before_boundary(
            FailureStage::WranglerVersion,
            CliError::Input(format!(
                "workspace D1 evidence requires Wrangler {}, observed {}",
                contract.wrangler_version, observed_version
            )),
        ));
    }
    let query = workspace_d1_migration::run_wrangler(
        &compiler_query_arguments(&config.database_name, &config.path),
        Path::new(&contract.repository_root),
        credential,
        account_id,
        &store.paths().cache_dir,
        QUERY_TIMEOUT,
    )
    .await
    .map_err(|error| {
        WorkspaceD1EvidenceFailure::after_boundary(FailureStage::ProviderQuery, error)
    })?;
    if !query.success {
        return Err(WorkspaceD1EvidenceFailure::after_boundary(
            FailureStage::ProviderQuery,
            CliError::Input(format!(
                "workspace D1 evidence query failed with exit status {}; provider output was not retained",
                query
                    .exit_status
                    .map_or_else(|| "signal".to_owned(), |status| status.to_string())
            )),
        ));
    }
    let rows = workspace_d1_migration::parse_query_rows(&query.stdout).map_err(|error| {
        WorkspaceD1EvidenceFailure::after_boundary(FailureStage::ProviderProjection, error)
    })?;
    let evidence = project_evidence(contract, rows).map_err(|error| {
        WorkspaceD1EvidenceFailure::after_boundary(FailureStage::ProviderProjection, error)
    })?;
    Ok(json!({
        "adapter":"workspace_d1_evidence_v1",
        "success":true,
        "boundary_crossed":true,
        "wrangler_version":observed_version,
        "repository_head":contract.repository_head,
        "operation_pack_sha256":contract.operation_pack_sha256,
        "query_sha256":contract.query_sha256,
        "production_config_sha256":config.sha256,
        "database_id":config.database_id,
        "evidence":evidence,
        "provider_output_retained":false,
        "body_returned":false,
    }))
}

fn compiler_query_arguments(database_name: &str, config_path: &str) -> Vec<String> {
    vec![
        "d1".to_owned(),
        "execute".to_owned(),
        database_name.to_owned(),
        "--remote".to_owned(),
        "--config".to_owned(),
        config_path.to_owned(),
        "--command".to_owned(),
        MAILDESK_D1_EVIDENCE_SQL_V1.to_owned(),
        "--json".to_owned(),
    ]
}

fn project_evidence(
    _contract: &WorkspaceD1EvidenceContractV1,
    mut rows: Vec<Map<String, Value>>,
) -> Result<MaildeskD1EvidenceV1> {
    if rows.len() != 1 {
        return Err(CliError::Input(format!(
            "workspace D1 evidence projection must return exactly one row, observed {}",
            rows.len()
        )));
    }
    let row = rows.pop().ok_or_else(|| {
        CliError::Input(
            "workspace D1 evidence projection unexpectedly lost its checked row".to_owned(),
        )
    })?;
    let observed = row.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = MAILDESK_D1_EVIDENCE_COLUMNS_V1
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if observed != expected || observed.len() != MAILDESK_D1_EVIDENCE_COLUMNS_V1.len() {
        return Err(CliError::Input(
            "workspace D1 evidence projection returned a private, missing, or arbitrary column set"
                .to_owned(),
        ));
    }
    let active_policy_digest = digest(&row, "active_policy_digest")?;
    let immutable_policy_object_key = bounded_string(&row, "immutable_policy_object_key", 1024)?;
    let expected_policy_object_key = format!(
        "config/policy/{}.json",
        active_policy_digest.trim_start_matches("sha256:")
    );
    if immutable_policy_object_key != expected_policy_object_key {
        return Err(CliError::Input(
            "workspace D1 evidence immutable policy key does not match the active digest"
                .to_owned(),
        ));
    }
    Ok(MaildeskD1EvidenceV1 {
        schema_version: 1,
        active_policy_digest,
        desired_state_digest: digest(&row, "desired_state_digest")?,
        semantic_projection_digest: digest(&row, "semantic_projection_digest")?,
        immutable_policy_object_key,
        expected_domain_count: count(&row, "expected_domain_count")?,
        projected_domain_count: count(&row, "projected_domain_count")?,
        expected_route_count: count(&row, "expected_route_count")?,
        projected_route_count: count(&row, "projected_route_count")?,
        approved_schema_present: boolean(&row, "approved_schema_present")?,
        approved_table_presence: fixed_boolean_map(
            &row,
            "approved_table_presence_json",
            APPROVED_TABLE_KEYS,
        )?,
        audit_event_counts: fixed_count_map(&row, "audit_event_counts_json", AUDIT_EVENT_KEYS)?,
        queue_correlation_count: count(&row, "queue_correlation_count")?,
        dlq_correlation_count: count(&row, "dlq_correlation_count")?,
        body_returned: false,
    })
}

fn digest(row: &Map<String, Value>, field: &str) -> Result<String> {
    let value = bounded_string(row, field, 71)?;
    if value.len() != 71
        || !value.starts_with("sha256:")
        || !value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CliError::Input(format!(
            "workspace D1 evidence field `{field}` is not a SHA-256 digest"
        )));
    }
    Ok(value)
}

fn bounded_string(row: &Map<String, Value>, field: &str, maximum: usize) -> Result<String> {
    row.get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= maximum)
        .map(str::to_owned)
        .ok_or_else(|| {
            CliError::Input(format!(
                "workspace D1 evidence field `{field}` is missing or outside its bound"
            ))
        })
}

fn count(row: &Map<String, Value>, field: &str) -> Result<u64> {
    row.get(field)
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_i64().and_then(|value| u64::try_from(value).ok()))
        })
        .filter(|value| *value <= MAX_COUNT)
        .ok_or_else(|| {
            CliError::Input(format!(
                "workspace D1 evidence count `{field}` is missing, negative, or unbounded"
            ))
        })
}

fn boolean(row: &Map<String, Value>, field: &str) -> Result<bool> {
    row.get(field)
        .and_then(|value| {
            value.as_bool().or_else(|| match value.as_i64() {
                Some(0) => Some(false),
                Some(1) => Some(true),
                _ => None,
            })
        })
        .ok_or_else(|| {
            CliError::Input(format!(
                "workspace D1 evidence boolean `{field}` is missing or invalid"
            ))
        })
}

fn parsed_map(row: &Map<String, Value>, field: &str) -> Result<Map<String, Value>> {
    let raw = bounded_string(row, field, 16_384)?;
    let value: Value = serde_json::from_str(&raw).map_err(|_| {
        CliError::Input(format!(
            "workspace D1 evidence map `{field}` is not valid JSON"
        ))
    })?;
    let map = value.as_object().cloned().ok_or_else(|| {
        CliError::Input(format!(
            "workspace D1 evidence map `{field}` is not an object"
        ))
    })?;
    if map.len() > MAX_MAP_KEYS
        || map.keys().any(|key| {
            key.is_empty()
                || key.len() > 64
                || !key
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        })
    {
        return Err(CliError::Input(format!(
            "workspace D1 evidence map `{field}` exceeds its closed key bounds"
        )));
    }
    Ok(map)
}

fn fixed_boolean_map(
    row: &Map<String, Value>,
    field: &str,
    expected_keys: &[&str],
) -> Result<BTreeMap<String, bool>> {
    let map = parsed_map(row, field)?;
    require_exact_map_keys(&map, field, expected_keys)?;
    map.into_iter()
        .map(|(key, value)| {
            value
                .as_bool()
                .or_else(|| match value.as_i64() {
                    Some(0) => Some(false),
                    Some(1) => Some(true),
                    _ => None,
                })
                .map(|value| (key, value))
                .ok_or_else(|| {
                    CliError::Input(format!(
                        "workspace D1 evidence map `{field}` contains a non-boolean value"
                    ))
                })
        })
        .collect()
}

fn fixed_count_map(
    row: &Map<String, Value>,
    field: &str,
    expected_keys: &[&str],
) -> Result<BTreeMap<String, u64>> {
    let map = parsed_map(row, field)?;
    require_exact_map_keys(&map, field, expected_keys)?;
    map.into_iter()
        .map(|(key, value)| {
            value
                .as_u64()
                .filter(|value| *value <= MAX_COUNT)
                .map(|value| (key, value))
                .ok_or_else(|| {
                    CliError::Input(format!(
                        "workspace D1 evidence map `{field}` contains a negative or unbounded count"
                    ))
                })
        })
        .collect()
}

fn require_exact_map_keys(
    map: &Map<String, Value>,
    field: &str,
    expected_keys: &[&str],
) -> Result<()> {
    let observed = map.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected_keys.iter().copied().collect::<BTreeSet<_>>();
    if observed != expected || map.len() != expected_keys.len() {
        return Err(CliError::Input(format!(
            "workspace D1 evidence map `{field}` contains a missing, private, or arbitrary key"
        )));
    }
    Ok(())
}

fn config_contract(contract: &WorkspaceD1EvidenceContractV1) -> WorkspaceD1MigrationContractV1 {
    WorkspaceD1MigrationContractV1 {
        repository_root: contract.repository_root.clone(),
        repository_head: contract.repository_head.clone(),
        repository_origin: contract.repository_origin.clone(),
        operation_pack_path: contract.operation_pack_path.clone(),
        operation_pack_sha256: contract.operation_pack_sha256.clone(),
        config_template_path: contract.config_template_path.clone(),
        config_template_sha256: contract.config_template_sha256.clone(),
        production_config_path: contract.production_config_path.clone(),
        migrations_dir: String::new(),
        database_binding: contract.database_binding.clone(),
        wrangler_version: contract.wrangler_version.clone(),
        migrations: Vec::new(),
        assertions: Vec::new(),
        recovery_capability_id: String::new(),
        recovery_max_age_seconds: 0,
        rollback_capability_id: String::new(),
    }
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn contract() -> WorkspaceD1EvidenceContractV1 {
        WorkspaceD1EvidenceContractV1 {
            repository_root: "/tmp/repository".to_owned(),
            repository_head: "a".repeat(40),
            repository_origin: "https://example.com/repository.git".to_owned(),
            operation_pack_path: ".cfctl/operations/d1-evidence.toml".to_owned(),
            operation_pack_sha256: format!("sha256:{}", "a".repeat(64)),
            config_template_path: "wrangler.toml".to_owned(),
            config_template_sha256: format!("sha256:{}", "b".repeat(64)),
            production_config_path: "wrangler.production.toml".to_owned(),
            database_binding: "DB".to_owned(),
            wrangler_version: "4.120.1".to_owned(),
            projection: "maildesk_v1".to_owned(),
            query_sha256: sha256(MAILDESK_D1_EVIDENCE_SQL_V1.as_bytes()),
        }
    }

    fn row() -> Map<String, Value> {
        serde_json::from_value::<Map<String, Value>>(json!({
            "active_policy_digest":format!("sha256:{}", "a".repeat(64)),
            "desired_state_digest":format!("sha256:{}", "b".repeat(64)),
            "semantic_projection_digest":format!("sha256:{}", "c".repeat(64)),
            "immutable_policy_object_key":format!("config/policy/{}.json", "a".repeat(64)),
            "expected_domain_count":2,
            "projected_domain_count":2,
            "expected_route_count":141,
            "projected_route_count":141,
            "approved_schema_present":1,
            "approved_table_presence_json":serde_json::to_string(&APPROVED_TABLE_KEYS.iter().map(|key| (*key, true)).collect::<BTreeMap<_, _>>()).expect("table map"),
            "audit_event_counts_json":serde_json::to_string(&AUDIT_EVENT_KEYS.iter().map(|key| (*key, 0_u64)).collect::<BTreeMap<_, _>>()).expect("audit map"),
            "queue_correlation_count":0,
            "dlq_correlation_count":0
        }))
        .expect("row")
    }

    #[test]
    fn projects_only_the_typed_body_free_evidence_contract() {
        let evidence = project_evidence(&contract(), vec![row()]).expect("evidence");
        assert_eq!(evidence.schema_version, 1);
        assert_eq!(evidence.projected_route_count, 141);
        assert!(evidence.approved_table_presence["alias_routes"]);
        assert!(!evidence.body_returned);
        let encoded = serde_json::to_value(&evidence).expect("evidence JSON");
        let top_level = encoded.as_object().expect("typed evidence object");
        for private in ["email", "subject", "recipient", "message_content"] {
            assert!(
                !top_level.contains_key(private),
                "typed evidence must not expose private field `{private}`"
            );
        }
    }

    #[test]
    fn column_order_is_irrelevant_but_extra_private_columns_fail_closed() {
        let mut private = row();
        private.insert("recipient".to_owned(), json!("operator@example.com"));
        let error = project_evidence(&contract(), vec![private]).expect_err("private column");
        assert!(error.to_string().contains("private, missing, or arbitrary"));
    }

    #[test]
    fn missing_invalid_and_unbounded_values_fail_closed() {
        let mut missing = row();
        missing.remove("active_policy_digest");
        assert!(project_evidence(&contract(), vec![missing]).is_err());

        let mut invalid_digest = row();
        invalid_digest.insert("active_policy_digest".to_owned(), json!("sha256:ABC"));
        assert!(project_evidence(&contract(), vec![invalid_digest]).is_err());

        let mut negative = row();
        negative.insert("expected_route_count".to_owned(), json!(-1));
        assert!(project_evidence(&contract(), vec![negative]).is_err());

        let mut unbounded = row();
        unbounded.insert("expected_route_count".to_owned(), json!(MAX_COUNT + 1));
        assert!(project_evidence(&contract(), vec![unbounded]).is_err());

        let mut invalid_boolean_map = row();
        invalid_boolean_map.insert(
            "approved_table_presence_json".to_owned(),
            json!("{\"alias_routes\":1}"),
        );
        assert!(project_evidence(&contract(), vec![invalid_boolean_map]).is_err());

        let mut invalid_count_map = row();
        invalid_count_map.insert(
            "audit_event_counts_json".to_owned(),
            json!("{\"route_decision\":-1}"),
        );
        assert!(project_evidence(&contract(), vec![invalid_count_map]).is_err());

        let mut key_smuggling = row();
        key_smuggling.insert(
            "audit_event_counts_json".to_owned(),
            json!("{\"recipient_private_value\":1}"),
        );
        assert!(project_evidence(&contract(), vec![key_smuggling]).is_err());

        let mut value_smuggling = row();
        value_smuggling.insert(
            "immutable_policy_object_key".to_owned(),
            json!("operator@example.com"),
        );
        assert!(project_evidence(&contract(), vec![value_smuggling]).is_err());
    }

    #[test]
    fn multiple_or_empty_rows_fail_closed() {
        assert!(project_evidence(&contract(), Vec::new()).is_err());
        assert!(project_evidence(&contract(), vec![row(), row()]).is_err());
    }

    #[test]
    fn execution_argv_is_exact_and_contains_only_the_compiler_query() {
        let arguments = compiler_query_arguments("maildesk-production", "/private/config.toml");
        assert_eq!(
            arguments,
            [
                "d1",
                "execute",
                "maildesk-production",
                "--remote",
                "--config",
                "/private/config.toml",
                "--command",
                MAILDESK_D1_EVIDENCE_SQL_V1,
                "--json",
            ]
        );
        assert!(!arguments.iter().any(|argument| argument == "--file"));
        assert_eq!(
            arguments
                .iter()
                .filter(|argument| argument.as_str() == MAILDESK_D1_EVIDENCE_SQL_V1)
                .count(),
            1
        );
    }

    #[test]
    fn failure_receipts_preserve_stage_and_boundary_without_source_material() {
        let private_source = "subject=private recipient=operator@example.com provider_payload=raw";
        let cases = [
            (
                WorkspaceD1EvidenceFailure::before_boundary(
                    FailureStage::Preflight,
                    CliError::Input(private_source.to_owned()),
                ),
                "CFCTL_WORKSPACE_D1_EVIDENCE_PREFLIGHT_FAILED",
                "preflight",
                false,
            ),
            (
                WorkspaceD1EvidenceFailure::after_boundary(
                    FailureStage::ProviderQuery,
                    CliError::Input(private_source.to_owned()),
                ),
                "CFCTL_WORKSPACE_D1_EVIDENCE_PROVIDER_READ_FAILED",
                "provider_query",
                true,
            ),
        ];

        for (failure, code, stage, boundary_crossed) in cases {
            let receipt = failure.receipt();
            assert_eq!(receipt["failure_code"], code);
            assert_eq!(receipt["failure_stage"], stage);
            assert_eq!(receipt["boundary_crossed"], boundary_crossed);
            assert_eq!(receipt["provider_output_retained"], false);
            assert_eq!(receipt["body_returned"], false);
            assert_eq!(failure.boundary_crossed(), boundary_crossed);
            let encoded = serde_json::to_string(&receipt).expect("failure receipt JSON");
            assert!(!encoded.contains(private_source));
            assert!(!encoded.contains("operator@example.com"));
            assert!(!encoded.contains("provider_payload"));
        }
    }
}
