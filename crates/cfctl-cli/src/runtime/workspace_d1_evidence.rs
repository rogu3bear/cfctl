use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use cfctl_core::{
    MaildeskD1EvidenceV1, WorkspaceD1EvidenceContractV1, WorkspaceD1MigrationContractV1,
};
use serde_json::{Map, Value, json};
use tokio::time::Duration;

use super::{
    AuthCredential, CallInput, CapabilityV1, CliError, Result, StateStore, workspace_d1_migration,
};

const QUERY_TIMEOUT: Duration = Duration::from_mins(2);
const MAX_MAP_KEYS: usize = 64;
const MAX_COUNT: u64 = 1_000_000_000;

pub(super) fn load(store: &StateStore, capability_id: &str) -> Result<Option<CapabilityV1>> {
    Ok(cfctl_workspace::load_workspace_d1_evidence_capability(
        &store.workspace_roots()?,
        capability_id,
    )?)
}

pub(super) async fn execute(
    store: &StateStore,
    capability: &CapabilityV1,
    input: &CallInput,
    credential: &AuthCredential,
    account_id: &str,
) -> Result<Value> {
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
        ));
    }
    if input.body.is_some()
        || !input
            .query
            .as_object()
            .is_some_and(|query| query.len() == 2)
    {
        return Err(CliError::Input(
            "workspace D1 evidence accepts only exact config and binding selectors; SQL, parameters, PRAGMAs, bodies, and arbitrary projections are impossible"
                .to_owned(),
        ));
    }
    let binding = input.query.get("binding").and_then(Value::as_str);
    if binding != Some(contract.database_binding.as_str()) {
        return Err(CliError::Input(
            "workspace D1 evidence binding selector differs from the committed declaration"
                .to_owned(),
        ));
    }
    let config = workspace_d1_migration::validated_config(&config_contract(contract), input)?;
    let query_path = Path::new(&contract.repository_root).join(&contract.query_path);
    let query_bytes = fs::read(&query_path).map_err(|source| super::cli_io(&query_path, source))?;
    if sha256(&query_bytes) != contract.query_sha256 {
        return Err(CliError::Input(
            "workspace D1 evidence query drifted from its committed declaration".to_owned(),
        ));
    }
    let version = workspace_d1_migration::run_wrangler(
        &["--version".to_owned()],
        Path::new(&contract.repository_root),
        credential,
        account_id,
        &store.paths().cache_dir,
        QUERY_TIMEOUT,
    )
    .await?;
    let observed_version = workspace_d1_migration::parse_wrangler_version(&version.stdout)?;
    if !version.success || observed_version != contract.wrangler_version {
        return Err(CliError::Input(format!(
            "workspace D1 evidence requires Wrangler {}, observed {}",
            contract.wrangler_version, observed_version
        )));
    }
    let query = workspace_d1_migration::run_wrangler(
        &[
            "d1".to_owned(),
            "execute".to_owned(),
            config.database_name.clone(),
            "--remote".to_owned(),
            "--config".to_owned(),
            config.path.clone(),
            "--file".to_owned(),
            query_path.display().to_string(),
            "--json".to_owned(),
        ],
        Path::new(&contract.repository_root),
        credential,
        account_id,
        &store.paths().cache_dir,
        QUERY_TIMEOUT,
    )
    .await?;
    if !query.success {
        return Err(CliError::Input(format!(
            "workspace D1 evidence query failed with exit status {}; provider output was not retained",
            query
                .exit_status
                .map_or_else(|| "signal".to_owned(), |status| status.to_string())
        )));
    }
    let rows = workspace_d1_migration::parse_query_rows(&query.stdout)?;
    let evidence = project_evidence(contract, rows)?;
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

fn project_evidence(
    contract: &WorkspaceD1EvidenceContractV1,
    mut rows: Vec<Map<String, Value>>,
) -> Result<MaildeskD1EvidenceV1> {
    if rows.len() != 1 {
        return Err(CliError::Input(format!(
            "workspace D1 evidence projection must return exactly one row, observed {}",
            rows.len()
        )));
    }
    let row = rows.pop().expect("one checked row");
    let observed = row.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = contract
        .result_columns
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if observed != expected || observed.len() != contract.result_columns.len() {
        return Err(CliError::Input(
            "workspace D1 evidence projection returned a private, missing, or arbitrary column set"
                .to_owned(),
        ));
    }
    Ok(MaildeskD1EvidenceV1 {
        schema_version: 1,
        active_policy_digest: digest(&row, "active_policy_digest")?,
        desired_state_digest: digest(&row, "desired_state_digest")?,
        semantic_projection_digest: digest(&row, "semantic_projection_digest")?,
        immutable_policy_object_key: bounded_string(&row, "immutable_policy_object_key", 1024)?,
        expected_domain_count: count(&row, "expected_domain_count")?,
        projected_domain_count: count(&row, "projected_domain_count")?,
        expected_route_count: count(&row, "expected_route_count")?,
        projected_route_count: count(&row, "projected_route_count")?,
        approved_schema_present: boolean(&row, "approved_schema_present")?,
        approved_table_presence: boolean_map(&row, "approved_table_presence_json")?,
        audit_event_counts: count_map(&row, "audit_event_counts_json")?,
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

fn boolean_map(row: &Map<String, Value>, field: &str) -> Result<BTreeMap<String, bool>> {
    parsed_map(row, field)?
        .into_iter()
        .map(|(key, value)| {
            value.as_bool().map(|value| (key, value)).ok_or_else(|| {
                CliError::Input(format!(
                    "workspace D1 evidence map `{field}` contains a non-boolean value"
                ))
            })
        })
        .collect()
}

fn count_map(row: &Map<String, Value>, field: &str) -> Result<BTreeMap<String, u64>> {
    parsed_map(row, field)?
        .into_iter()
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
mod tests {
    use super::*;

    const COLUMNS: &[&str] = &[
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
            query_path: "evidence.sql".to_owned(),
            query_sha256: format!("sha256:{}", "c".repeat(64)),
            result_columns: COLUMNS.iter().map(|value| (*value).to_owned()).collect(),
        }
    }

    fn row() -> Map<String, Value> {
        serde_json::from_value::<Map<String, Value>>(json!({
            "active_policy_digest":format!("sha256:{}", "a".repeat(64)),
            "desired_state_digest":format!("sha256:{}", "b".repeat(64)),
            "semantic_projection_digest":format!("sha256:{}", "c".repeat(64)),
            "immutable_policy_object_key":"policies/sha256-aaaa.json",
            "expected_domain_count":2,
            "projected_domain_count":2,
            "expected_route_count":141,
            "projected_route_count":141,
            "approved_schema_present":1,
            "approved_table_presence_json":"{\"alias_routes\":true}",
            "audit_event_counts_json":"{\"route_decision\":4}",
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
        assert_eq!(evidence.approved_table_presence["alias_routes"], true);
        assert!(!evidence.body_returned);
        let encoded = serde_json::to_string(&evidence).expect("evidence JSON");
        for private in ["email", "subject", "recipient", "message_content"] {
            assert!(!encoded.contains(private));
        }
    }

    #[test]
    fn column_order_is_irrelevant_but_extra_private_columns_fail_closed() {
        let mut reversed = contract();
        reversed.result_columns.reverse();
        project_evidence(&reversed, vec![row()]).expect("same closed column set");

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
    }

    #[test]
    fn multiple_or_empty_rows_fail_closed() {
        assert!(project_evidence(&contract(), Vec::new()).is_err());
        assert!(project_evidence(&contract(), vec![row(), row()]).is_err());
    }
}
