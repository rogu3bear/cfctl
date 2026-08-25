use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use cfctl_core::{
    MaildeskD1EvidenceV1, MaildeskD1RouteHealthEvidenceV2, MaildeskD1RouteHealthRecordV2,
    MaildeskRouteKindV2, MaildeskRouteProviderV2, MaildeskRouteReadinessStatusV2,
    WorkspaceD1EvidenceContractV1, WorkspaceD1MigrationContractV1,
};
use chrono::{DateTime, NaiveDateTime};
use serde_json::{Map, Value, json};
use tokio::time::Duration;

use cfctl_workspace::{
    MAILDESK_D1_EVIDENCE_COLUMNS_V1, MAILDESK_D1_EVIDENCE_SQL_V1,
    MAILDESK_D1_ROUTE_HEALTH_COLUMNS_V2,
};

use super::{
    AuthCredential, CallInput, CapabilityV1, CliError, Result, StateStore, workspace_d1_migration,
};

const QUERY_TIMEOUT: Duration = Duration::from_mins(2);
const MAX_MAP_KEYS: usize = 64;
const MAX_COUNT: u64 = 1_000_000_000;
const MAX_ROUTE_HEALTH_RECORDS: usize = 1_000;
const MAX_ROUTE_HEALTH_JSON_BYTES: usize = 2 * 1024 * 1024;
const ROUTE_HEALTH_KEYS: &[&str] = &[
    "route_id",
    "domain",
    "policy_sha256",
    "route_kind",
    "enabled",
    "desired_provider",
    "observed_provider",
    "inbound_status",
    "reply_status",
    "provider_accepted_at",
    "inbox_received_at",
    "reply_provider_accepted_at",
    "reply_proven_at",
    "last_error_code",
    "updated_at",
];
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

/// Accept a delegated receipt as verified only when the unchanged aggregate
/// V1 and the additive bounded-complete route-health V2 are both coherent.
pub(super) fn receipt_is_complete(receipt: &Value) -> bool {
    let Some(records) = receipt
        .pointer("/route_health/records")
        .and_then(Value::as_array)
    else {
        return false;
    };
    let Some(record_count) = receipt
        .pointer("/route_health/record_count")
        .and_then(Value::as_u64)
    else {
        return false;
    };
    receipt.get("success").and_then(Value::as_bool) == Some(true)
        && receipt.get("body_returned").and_then(Value::as_bool) == Some(false)
        && receipt
            .get("provider_output_retained")
            .and_then(Value::as_bool)
            == Some(false)
        && receipt
            .pointer("/evidence/schema_version")
            .and_then(Value::as_u64)
            == Some(1)
        && receipt
            .pointer("/evidence/body_returned")
            .and_then(Value::as_bool)
            == Some(false)
        && receipt
            .pointer("/route_health/schema_version")
            .and_then(Value::as_u64)
            == Some(2)
        && receipt
            .pointer("/route_health/complete")
            .and_then(Value::as_bool)
            == Some(true)
        && receipt
            .pointer("/route_health/provider_output_retained")
            .and_then(Value::as_bool)
            == Some(false)
        && receipt
            .pointer("/route_health/body_returned")
            .and_then(Value::as_bool)
            == Some(false)
        && records.len() <= MAX_ROUTE_HEALTH_RECORDS
        && usize::try_from(record_count).ok() == Some(records.len())
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
    let (evidence, route_health) = project_evidence(contract, rows).map_err(|error| {
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
        "route_health":route_health,
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
) -> Result<(MaildeskD1EvidenceV1, MaildeskD1RouteHealthEvidenceV2)> {
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
        .chain(MAILDESK_D1_ROUTE_HEALTH_COLUMNS_V2)
        .copied()
        .collect::<BTreeSet<_>>();
    if observed != expected
        || observed.len()
            != MAILDESK_D1_EVIDENCE_COLUMNS_V1.len() + MAILDESK_D1_ROUTE_HEALTH_COLUMNS_V2.len()
    {
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
    let projected_route_count = count(&row, "projected_route_count")?;
    let active_route_health_count = count(&row, "active_route_health_count")?;
    let route_health = project_route_health(
        &row,
        projected_route_count,
        active_route_health_count,
        &active_policy_digest,
    )?;
    let aggregate = MaildeskD1EvidenceV1 {
        schema_version: 1,
        active_policy_digest,
        desired_state_digest: digest(&row, "desired_state_digest")?,
        semantic_projection_digest: digest(&row, "semantic_projection_digest")?,
        immutable_policy_object_key,
        expected_domain_count: count(&row, "expected_domain_count")?,
        projected_domain_count: count(&row, "projected_domain_count")?,
        expected_route_count: count(&row, "expected_route_count")?,
        projected_route_count,
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
    };
    Ok((aggregate, route_health))
}

fn project_route_health(
    row: &Map<String, Value>,
    projected_route_count: u64,
    active_route_health_count: u64,
    active_policy_digest: &str,
) -> Result<MaildeskD1RouteHealthEvidenceV2> {
    let raw = bounded_string(row, "route_health_rows_json", MAX_ROUTE_HEALTH_JSON_BYTES)?;
    let values: Vec<Value> = serde_json::from_str(&raw).map_err(|_| {
        CliError::Input("workspace D1 route-health projection is not valid JSON".to_owned())
    })?;
    if values.len() > MAX_ROUTE_HEALTH_RECORDS
        || active_route_health_count > MAX_ROUTE_HEALTH_RECORDS as u64
    {
        return Err(CliError::Input(format!(
            "workspace D1 route-health projection exceeds its {MAX_ROUTE_HEALTH_RECORDS}-record bound"
        )));
    }
    let observed_count = u64::try_from(values.len()).map_err(|_| {
        CliError::Input("workspace D1 route-health count is unrepresentable".to_owned())
    })?;
    if observed_count != active_route_health_count || observed_count != projected_route_count {
        return Err(CliError::Input(
            "workspace D1 route-health projection is partial or disagrees with the active route inventory"
                .to_owned(),
        ));
    }

    let mut records = Vec::with_capacity(values.len());
    let mut route_refs = BTreeSet::new();
    for value in values {
        let raw_record = value.as_object().ok_or_else(|| {
            CliError::Input("workspace D1 route-health record is not an object".to_owned())
        })?;
        require_exact_map_keys(raw_record, "route_health_rows_json", ROUTE_HEALTH_KEYS)?;
        let route_id = bounded_string(raw_record, "route_id", 256)?;
        let domain = bounded_domain(raw_record, "domain")?;
        let route_ref_sha256 = sha256(route_id.as_bytes());
        if !route_refs.insert(route_ref_sha256.clone()) {
            return Err(CliError::Input(
                "workspace D1 route-health projection contains a duplicate route reference"
                    .to_owned(),
            ));
        }
        let policy_digest = raw_digest(raw_record, "policy_sha256")?;
        if policy_digest != active_policy_digest {
            return Err(CliError::Input(
                "workspace D1 route-health record is bound to a different policy revision"
                    .to_owned(),
            ));
        }
        let enabled = boolean(raw_record, "enabled")?;
        if !enabled {
            return Err(CliError::Input(
                "workspace D1 route-health projection contains a disabled active route".to_owned(),
            ));
        }
        records.push(MaildeskD1RouteHealthRecordV2 {
            route_ref_sha256,
            domain_sha256: sha256(domain.as_bytes()),
            policy_digest,
            route_kind: route_kind(raw_record)?,
            enabled,
            desired_provider: provider(raw_record, "desired_provider")?.ok_or_else(|| {
                CliError::Input("workspace D1 route-health desired provider is missing".to_owned())
            })?,
            observed_provider: provider(raw_record, "observed_provider")?,
            inbound_status: readiness_status(raw_record, "inbound_status")?,
            reply_status: readiness_status(raw_record, "reply_status")?,
            provider_accepted_at: optional_timestamp(raw_record, "provider_accepted_at")?,
            inbox_received_at: optional_timestamp(raw_record, "inbox_received_at")?,
            reply_provider_accepted_at: optional_timestamp(
                raw_record,
                "reply_provider_accepted_at",
            )?,
            reply_proven_at: optional_timestamp(raw_record, "reply_proven_at")?,
            last_error_code: optional_error_code(raw_record, "last_error_code")?,
            updated_at: required_timestamp(raw_record, "updated_at")?,
        });
    }

    Ok(MaildeskD1RouteHealthEvidenceV2 {
        schema_version: 2,
        record_count: observed_count,
        complete: true,
        records,
        provider_output_retained: false,
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

fn raw_digest(row: &Map<String, Value>, field: &str) -> Result<String> {
    let value = bounded_string(row, field, 64)?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CliError::Input(format!(
            "workspace D1 route-health field `{field}` is not a raw SHA-256 digest"
        )));
    }
    Ok(format!("sha256:{value}"))
}

fn bounded_domain(row: &Map<String, Value>, field: &str) -> Result<String> {
    let domain = bounded_string(row, field, 253)?;
    let valid = domain == domain.to_ascii_lowercase()
        && domain.len() <= 253
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        });
    if !valid {
        return Err(CliError::Input(format!(
            "workspace D1 route-health field `{field}` is not a normalized domain"
        )));
    }
    Ok(domain)
}

fn route_kind(row: &Map<String, Value>) -> Result<MaildeskRouteKindV2> {
    match bounded_string(row, "route_kind", 32)?.as_str() {
        "role_alias" => Ok(MaildeskRouteKindV2::RoleAlias),
        "personal_alias" => Ok(MaildeskRouteKindV2::PersonalAlias),
        "catch_all" => Ok(MaildeskRouteKindV2::CatchAll),
        "sink" => Ok(MaildeskRouteKindV2::Sink),
        _ => Err(CliError::Input(
            "workspace D1 route-health route kind is outside the closed contract".to_owned(),
        )),
    }
}

fn provider(row: &Map<String, Value>, field: &str) -> Result<Option<MaildeskRouteProviderV2>> {
    let Some(value) = optional_string(row, field, 64)? else {
        return Ok(None);
    };
    let provider = match value.as_str() {
        "cloudflare_email_routing" => MaildeskRouteProviderV2::CloudflareEmailRouting,
        "google_workspace" => MaildeskRouteProviderV2::GoogleWorkspace,
        "external" => MaildeskRouteProviderV2::External,
        "excluded" => MaildeskRouteProviderV2::Excluded,
        _ => {
            return Err(CliError::Input(format!(
                "workspace D1 route-health provider `{field}` is outside the closed contract"
            )));
        }
    };
    Ok(Some(provider))
}

fn readiness_status(
    row: &Map<String, Value>,
    field: &str,
) -> Result<MaildeskRouteReadinessStatusV2> {
    match bounded_string(row, field, 64)?.as_str() {
        "declared" => Ok(MaildeskRouteReadinessStatusV2::Declared),
        "local_policy_valid" => Ok(MaildeskRouteReadinessStatusV2::LocalPolicyValid),
        "edge_verified" => Ok(MaildeskRouteReadinessStatusV2::EdgeVerified),
        "provider_accepted" => Ok(MaildeskRouteReadinessStatusV2::ProviderAccepted),
        "inbox_verified" => Ok(MaildeskRouteReadinessStatusV2::InboxVerified),
        "reply_verified" => Ok(MaildeskRouteReadinessStatusV2::ReplyVerified),
        "partial_delivery" => Ok(MaildeskRouteReadinessStatusV2::PartialDelivery),
        "recovery_required" => Ok(MaildeskRouteReadinessStatusV2::RecoveryRequired),
        "failed" => Ok(MaildeskRouteReadinessStatusV2::Failed),
        "intentionally_excluded" => Ok(MaildeskRouteReadinessStatusV2::IntentionallyExcluded),
        _ => Err(CliError::Input(format!(
            "workspace D1 route-health status `{field}` is outside the closed contract"
        ))),
    }
}

fn optional_string(
    row: &Map<String, Value>,
    field: &str,
    maximum: usize,
) -> Result<Option<String>> {
    match row.get(field) {
        Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if !value.is_empty() && value.len() <= maximum => {
            Ok(Some(value.clone()))
        }
        _ => Err(CliError::Input(format!(
            "workspace D1 route-health field `{field}` is missing or outside its bound"
        ))),
    }
}

fn optional_timestamp(row: &Map<String, Value>, field: &str) -> Result<Option<String>> {
    let Some(value) = optional_string(row, field, 64)? else {
        return Ok(None);
    };
    validate_timestamp(&value, field)?;
    Ok(Some(value))
}

fn required_timestamp(row: &Map<String, Value>, field: &str) -> Result<String> {
    let value = bounded_string(row, field, 64)?;
    validate_timestamp(&value, field)?;
    Ok(value)
}

fn validate_timestamp(value: &str, field: &str) -> Result<()> {
    let valid = DateTime::parse_from_rfc3339(value).is_ok()
        || NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%.f").is_ok();
    if !valid {
        return Err(CliError::Input(format!(
            "workspace D1 route-health timestamp `{field}` is invalid"
        )));
    }
    Ok(())
}

fn optional_error_code(row: &Map<String, Value>, field: &str) -> Result<Option<String>> {
    let Some(value) = optional_string(row, field, 128)? else {
        return Ok(None);
    };
    if !value.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'.')
    }) {
        return Err(CliError::Input(
            "workspace D1 route-health error code is outside the closed contract".to_owned(),
        ));
    }
    Ok(Some(value))
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
        let route_health_rows = json!([
            {
                "route_id":"route-security-example",
                "domain":"example.com",
                "policy_sha256":"a".repeat(64),
                "route_kind":"role_alias",
                "enabled":1,
                "desired_provider":"cloudflare_email_routing",
                "observed_provider":"cloudflare_email_routing",
                "inbound_status":"inbox_verified",
                "reply_status":"provider_accepted",
                "provider_accepted_at":"2026-08-23 12:00:00",
                "inbox_received_at":"2026-08-23T12:01:00Z",
                "reply_provider_accepted_at":"2026-08-23 12:02:00",
                "reply_proven_at":null,
                "last_error_code":null,
                "updated_at":"2026-08-23 12:02:00"
            }
        ]);
        serde_json::from_value::<Map<String, Value>>(json!({
            "active_policy_digest":format!("sha256:{}", "a".repeat(64)),
            "desired_state_digest":format!("sha256:{}", "b".repeat(64)),
            "semantic_projection_digest":format!("sha256:{}", "c".repeat(64)),
            "immutable_policy_object_key":format!("config/policy/{}.json", "a".repeat(64)),
            "expected_domain_count":2,
            "projected_domain_count":2,
            "expected_route_count":1,
            "projected_route_count":1,
            "approved_schema_present":1,
            "approved_table_presence_json":serde_json::to_string(&APPROVED_TABLE_KEYS.iter().map(|key| (*key, true)).collect::<BTreeMap<_, _>>()).expect("table map"),
            "audit_event_counts_json":serde_json::to_string(&AUDIT_EVENT_KEYS.iter().map(|key| (*key, 0_u64)).collect::<BTreeMap<_, _>>()).expect("audit map"),
            "queue_correlation_count":0,
            "dlq_correlation_count":0,
            "active_route_health_count":1,
            "route_health_rows_json":serde_json::to_string(&route_health_rows).expect("route-health JSON")
        }))
        .expect("row")
    }

    #[test]
    fn projects_only_the_typed_body_free_evidence_contract() {
        let (evidence, route_health) =
            project_evidence(&contract(), vec![row()]).expect("evidence");
        assert_eq!(evidence.schema_version, 1);
        assert_eq!(evidence.projected_route_count, 1);
        assert!(evidence.approved_table_presence["alias_routes"]);
        assert!(!evidence.body_returned);
        assert_eq!(route_health.schema_version, 2);
        assert!(route_health.complete);
        assert_eq!(route_health.record_count, 1);
        assert_eq!(
            route_health.records[0].route_ref_sha256,
            sha256(b"route-security-example")
        );
        assert_eq!(
            route_health.records[0].domain_sha256,
            sha256(b"example.com")
        );
        assert!(!route_health.body_returned);
        assert!(!route_health.provider_output_retained);
        let encoded = serde_json::to_value(&evidence).expect("evidence JSON");
        let top_level = encoded.as_object().expect("typed evidence object");
        for private in ["email", "subject", "recipient", "message_content"] {
            assert!(
                !top_level.contains_key(private),
                "typed evidence must not expose private field `{private}`"
            );
        }
        let encoded_routes = serde_json::to_string(&route_health).expect("route-health JSON");
        for private in [
            "route-security-example",
            "example.com",
            "operator@example.com",
            "subject",
            "recipient",
        ] {
            assert!(
                !encoded_routes.contains(private),
                "typed route evidence must not expose private field `{private}`"
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
    fn partial_oversized_duplicate_and_malformed_route_inventory_fail_closed() {
        let mut partial = row();
        partial.insert("active_route_health_count".to_owned(), json!(0));
        assert!(project_evidence(&contract(), vec![partial]).is_err());

        let mut oversized = row();
        oversized.insert(
            "active_route_health_count".to_owned(),
            json!(MAX_ROUTE_HEALTH_RECORDS as u64 + 1),
        );
        oversized.insert(
            "projected_route_count".to_owned(),
            json!(MAX_ROUTE_HEALTH_RECORDS as u64 + 1),
        );
        assert!(project_evidence(&contract(), vec![oversized]).is_err());

        let mut duplicate = row();
        let raw = duplicate["route_health_rows_json"]
            .as_str()
            .expect("route-health JSON");
        let record = serde_json::from_str::<Vec<Value>>(raw).expect("route rows")[0].clone();
        duplicate.insert(
            "route_health_rows_json".to_owned(),
            json!(serde_json::to_string(&vec![record.clone(), record]).expect("duplicate rows")),
        );
        duplicate.insert("active_route_health_count".to_owned(), json!(2));
        duplicate.insert("projected_route_count".to_owned(), json!(2));
        assert!(project_evidence(&contract(), vec![duplicate]).is_err());

        let mut unknown_provider = row();
        let mut records = serde_json::from_str::<Vec<Value>>(
            unknown_provider["route_health_rows_json"]
                .as_str()
                .expect("route-health JSON"),
        )
        .expect("route rows");
        records[0]["observed_provider"] = json!("unknown_provider");
        unknown_provider.insert(
            "route_health_rows_json".to_owned(),
            json!(serde_json::to_string(&records).expect("route rows")),
        );
        assert!(project_evidence(&contract(), vec![unknown_provider]).is_err());

        let mut wrong_policy = row();
        let mut records = serde_json::from_str::<Vec<Value>>(
            wrong_policy["route_health_rows_json"]
                .as_str()
                .expect("route-health JSON"),
        )
        .expect("route rows");
        records[0]["policy_sha256"] = json!("d".repeat(64));
        wrong_policy.insert(
            "route_health_rows_json".to_owned(),
            json!(serde_json::to_string(&records).expect("route rows")),
        );
        assert!(project_evidence(&contract(), vec![wrong_policy]).is_err());

        let mut disabled = row();
        let mut records = serde_json::from_str::<Vec<Value>>(
            disabled["route_health_rows_json"]
                .as_str()
                .expect("route-health JSON"),
        )
        .expect("route rows");
        records[0]["enabled"] = json!(false);
        disabled.insert(
            "route_health_rows_json".to_owned(),
            json!(serde_json::to_string(&records).expect("route rows")),
        );
        assert!(project_evidence(&contract(), vec![disabled]).is_err());

        let mut raw_address = row();
        let mut records = serde_json::from_str::<Vec<Value>>(
            raw_address["route_health_rows_json"]
                .as_str()
                .expect("route-health JSON"),
        )
        .expect("route rows");
        records[0]["route_address"] = json!("security@example.com");
        raw_address.insert(
            "route_health_rows_json".to_owned(),
            json!(serde_json::to_string(&records).expect("route rows")),
        );
        assert!(project_evidence(&contract(), vec![raw_address]).is_err());
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
