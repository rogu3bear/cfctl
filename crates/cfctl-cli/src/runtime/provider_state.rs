use super::cloudflare_api::BASE_URL as API_BASE_URL;
use super::live_state_contracts::cloudflare_tunnel_configuration_read_contract_supported;
use super::live_state_contracts::d1_read_replication_read_contract_supported;
use super::live_state_contracts::dns_record_routing_contract_supported;
use super::live_state_contracts::global_warp_override_read_contract_supported;
use super::live_state_contracts::should_bind_cloudflare_tunnel_configuration_state;
use super::live_state_contracts::should_bind_d1_empty_database_state;
use super::live_state_contracts::should_bind_d1_read_replication_state;
use super::live_state_contracts::should_bind_dns_record_state;
use super::live_state_contracts::should_bind_global_warp_override_state;
use super::live_state_contracts::should_bind_warp_connector_configuration_state;
use super::live_state_contracts::should_bind_web_analytics_rum_state;
use super::live_state_contracts::warp_connector_configuration_read_contract_supported;
use super::live_state_contracts::web_analytics_rum_read_contract_supported;
use super::plan_secret::CLOUDFLARE_TUNNEL_CONFIGURATION_PATH;
use super::plan_secret::CLOUDFLARE_TUNNEL_CONFIGURATION_READ_CAPABILITY_ID;
use super::plan_secret::D1_READ_REPLICATION_PATH;
use super::plan_secret::D1_READ_REPLICATION_READ_CAPABILITY_ID;
use super::plan_secret::DNS_RECORD_DETAIL_PATH;
use super::plan_secret::DNS_RECORD_DETAIL_READ_CAPABILITY_ID;
use super::plan_secret::GLOBAL_WARP_OVERRIDE_MUTATION_CAPABILITY_ID;
use super::plan_secret::GLOBAL_WARP_OVERRIDE_PATH;
use super::plan_secret::GLOBAL_WARP_OVERRIDE_READ_CAPABILITY_ID;
use super::plan_secret::WARP_CONNECTOR_CONFIGURATION_PATH;
use super::plan_secret::WARP_CONNECTOR_CONFIGURATION_READ_CAPABILITY_ID;
use super::plan_secret::WEB_ANALYTICS_RUM_PATH;
use super::plan_secret::WEB_ANALYTICS_RUM_READ_CAPABILITY_ID;
use super::prelude::{
    AdapterStatus, AuthCredential, CallInput, CapabilityV1, CatalogSnapshot, CliError,
    CloudflareResponseV1, EvidenceClass, EvidenceV1, Executor, Map, Result, StateStore, Value,
    json,
};
use super::r2_credentials::preflight_call_input;
use super::support::capability_missing;
use super::support::http_client;
use cfctl_cloudflare::validate_request_contract;

pub(super) fn apply_dns_record_state_response(
    capability: &CapabilityV1,
    account_id: &str,
    zone_id: &str,
    dns_record_id: &str,
    response: &CloudflareResponseV1,
) -> Result<Value> {
    if !response.success || !(200..300).contains(&response.status) {
        return Err(CliError::Input(format!(
            "Cloudflare rejected the DNS record state read with HTTP {}; the mutation boundary was not crossed",
            response.status
        )));
    }
    if response.result.get("id").and_then(Value::as_str) != Some(dns_record_id) {
        return Err(CliError::Input(
            "DNS record state read returned a different or missing record id; the mutation boundary was not crossed"
                .to_owned(),
        ));
    }
    let prior_record = project_dns_record_snapshot(capability, &response.result)?;
    validate_request_contract(
        capability,
        &CallInput {
            selectors: json!({"zone_id":zone_id,"dns_record_id":dns_record_id}),
            query: json!({}),
            body: Some(prior_record.clone()),
            ..CallInput::default()
        },
    )?;
    Ok(json!({
        "schema_version": 1,
        "source_capability_id": DNS_RECORD_DETAIL_READ_CAPABILITY_ID,
        "source_path": DNS_RECORD_DETAIL_PATH,
        "target_capability_id": capability.id,
        "target_method": capability.method,
        "target_scope": "zone",
        "account_id": account_id,
        "zone_id": zone_id,
        "dns_record_id": dns_record_id,
        "prior_record": prior_record,
    }))
}

pub(super) fn project_dns_record_snapshot(
    capability: &CapabilityV1,
    source: &Value,
) -> Result<Value> {
    let record_type = source
        .get("type")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "DNS record state read omitted its bounded record type; the mutation boundary was not crossed"
                    .to_owned(),
            )
        })?;
    let paths = capability
        .request_object_paths_by_discriminator("type")
        .and_then(|branches| branches.get(record_type).cloned())
        .ok_or_else(|| {
            CliError::Input(format!(
                "DNS record type `{record_type}` is outside the reviewed restoration schema; the mutation boundary was not crossed"
            ))
        })?;
    let mut snapshot = serde_json::Map::new();
    for path in &paths {
        let Some(value) = value_at_dotted_path(source, path) else {
            continue;
        };
        if value.is_null() {
            continue;
        }
        insert_dotted_object_path(&mut snapshot, path, value.clone())?;
    }
    let snapshot = Value::Object(snapshot);
    if snapshot.get("type").and_then(Value::as_str) != Some(record_type)
        || snapshot
            .get("name")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || (paths.contains(&"content".to_owned()) && snapshot.get("content").is_none())
        || (paths.iter().any(|path| path.starts_with("data."))
            && snapshot
                .get("data")
                .and_then(Value::as_object)
                .is_none_or(serde_json::Map::is_empty))
    {
        return Err(CliError::Input(
            "DNS record state read omitted fields required to reconstruct the reviewed record type; the mutation boundary was not crossed"
                .to_owned(),
        ));
    }
    Ok(snapshot)
}

pub(super) fn value_at_dotted_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.')
        .try_fold(value, |current, segment| current.as_object()?.get(segment))
}

pub(super) fn insert_dotted_object_path(
    object: &mut serde_json::Map<String, Value>,
    path: &str,
    value: Value,
) -> Result<()> {
    let segments = path.split('.').collect::<Vec<_>>();
    insert_object_path_segments(object, &segments, value)
}

pub(super) fn insert_object_path_segments(
    object: &mut serde_json::Map<String, Value>,
    segments: &[&str],
    value: Value,
) -> Result<()> {
    let Some((segment, remaining)) = segments.split_first() else {
        return Err(CliError::Input(
            "DNS record restoration schema produced an empty writable path".to_owned(),
        ));
    };
    if remaining.is_empty() {
        object.insert((*segment).to_owned(), value);
        return Ok(());
    }
    let nested = object
        .entry((*segment).to_owned())
        .or_insert_with(|| Value::Object(serde_json::Map::new()))
        .as_object_mut()
        .ok_or_else(|| {
            CliError::Input(
                "DNS record restoration schema produced conflicting writable paths".to_owned(),
            )
        })?;
    insert_object_path_segments(nested, remaining, value)
}

pub(super) fn dns_record_detail_read_contract_supported(capability: &CapabilityV1) -> bool {
    capability.id == DNS_RECORD_DETAIL_READ_CAPABILITY_ID
        && capability.method == "GET"
        && capability.path == DNS_RECORD_DETAIL_PATH
        && capability.product == "DNS Records for a Zone"
        && capability.account_scope == "zone"
        && !capability.mutating
        && capability.request_schema.is_none()
        && matches!(
            capability.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        && dns_record_routing_contract_supported(capability)
        && capability
            .response_contract
            .as_ref()
            .is_some_and(|contract| {
                matches!(
                    contract.body_mode,
                    cfctl_core::ResponseBodyModeV1::CloudflareJsonEnvelope
                ) && contract.success_statuses == ["200"]
                    && contract.success_media_types == ["application/json"]
            })
}

pub(super) async fn read_live_dns_record_state(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: &AuthCredential,
) -> Result<(Value, EvidenceV1)> {
    if !should_bind_dns_record_state(capability) {
        return Err(CliError::Input(
            "DNS record mutation drifted from its governed prior-state contract".to_owned(),
        ));
    }
    let zone_id = input
        .selectors
        .get("zone_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input("DNS state precondition requires string selector `zone_id`".to_owned())
        })?;
    let dns_record_id = input
        .selectors
        .get("dns_record_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "DNS state precondition requires string selector `dns_record_id`".to_owned(),
            )
        })?;
    let source_capability = catalog
        .get(DNS_RECORD_DETAIL_READ_CAPABILITY_ID)
        .ok_or_else(|| capability_missing(DNS_RECORD_DETAIL_READ_CAPABILITY_ID))?;
    if !dns_record_detail_read_contract_supported(source_capability) {
        return Err(CliError::Input(
            "DNS state source capability drifted from the governed record detail read".to_owned(),
        ));
    }
    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let response = executor
        .execute_read(
            source_capability,
            &CallInput {
                selectors: json!({"zone_id":zone_id,"dns_record_id":dns_record_id}),
                query: json!({}),
                body: None,
                ..CallInput::default()
            },
            credential,
        )
        .await?;
    let receipt =
        apply_dns_record_state_response(capability, account_id, zone_id, dns_record_id, &response)?;
    let evidence = store.write_evidence(EvidenceClass::LiveRead, &receipt)?;
    Ok((receipt, evidence))
}

pub(super) fn apply_d1_read_replication_state_response(
    capability: &CapabilityV1,
    account_id: &str,
    database_id: &str,
    response: &CloudflareResponseV1,
) -> Result<Value> {
    if !response.success || !(200..300).contains(&response.status) {
        return Err(CliError::Input(format!(
            "Cloudflare rejected the D1 read-replication state read with HTTP {}; the mutation boundary was not crossed",
            response.status
        )));
    }
    let mode = response
        .result
        .pointer("/read_replication/mode")
        .and_then(Value::as_str)
        .filter(|mode| matches!(*mode, "auto" | "disabled"))
        .ok_or_else(|| {
            CliError::Input(
                "D1 state read omitted the bounded read_replication.mode value; the mutation boundary was not crossed"
                    .to_owned(),
            )
        })?;
    Ok(json!({
        "schema_version": 1,
        "source_capability_id": D1_READ_REPLICATION_READ_CAPABILITY_ID,
        "source_path": D1_READ_REPLICATION_PATH,
        "target_capability_id": capability.id,
        "target_method": capability.method,
        "target_scope": "account",
        "account_id": account_id,
        "database_id": database_id,
        "read_replication": {"mode": mode},
    }))
}

pub(super) async fn read_live_d1_read_replication_state(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: &AuthCredential,
) -> Result<(Value, EvidenceV1)> {
    if !should_bind_d1_read_replication_state(capability) {
        return Err(CliError::Input(
            "D1 read-replication mutation drifted from its governed prior-state contract"
                .to_owned(),
        ));
    }
    let selected_account = input
        .selectors
        .get("account_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "D1 state precondition requires string selector `account_id`".to_owned(),
            )
        })?;
    if selected_account != account_id {
        return Err(CliError::Input(format!(
            "D1 target account `{selected_account}` differs from selected account `{account_id}`; the mutation boundary was not crossed"
        )));
    }
    let database_id = input
        .selectors
        .get("database_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "D1 state precondition requires string selector `database_id`".to_owned(),
            )
        })?;
    let source_capability = catalog
        .get(D1_READ_REPLICATION_READ_CAPABILITY_ID)
        .ok_or_else(|| capability_missing(D1_READ_REPLICATION_READ_CAPABILITY_ID))?;
    if !d1_read_replication_read_contract_supported(source_capability) {
        return Err(CliError::Input(
            "D1 state source capability drifted from the governed database read".to_owned(),
        ));
    }
    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let response = executor
        .execute_read(
            source_capability,
            &CallInput {
                selectors: json!({"account_id": account_id, "database_id": database_id}),
                query: json!({}),
                body: None,
                ..CallInput::default()
            },
            credential,
        )
        .await?;
    let receipt =
        apply_d1_read_replication_state_response(capability, account_id, database_id, &response)?;
    let evidence = store.write_evidence(EvidenceClass::LiveRead, &receipt)?;
    Ok((receipt, evidence))
}

pub(super) fn apply_d1_empty_database_state_response(
    capability: &CapabilityV1,
    adapter_targets: &Value,
    account_id: &str,
    database_id: &str,
    response: &CloudflareResponseV1,
) -> Result<Value> {
    if !response.success || !(200..300).contains(&response.status) {
        return Err(CliError::Input(format!(
            "Cloudflare rejected the D1 empty-state read with HTTP {}; the compensation plan was not created",
            response.status
        )));
    }
    let uuid = response
        .result
        .get("uuid")
        .and_then(Value::as_str)
        .filter(|uuid| *uuid == database_id)
        .ok_or_else(|| {
            CliError::Input(
                "D1 empty-state read did not return the exact created database UUID; the compensation plan was not created"
                    .to_owned(),
            )
        })?;
    let name = response
        .result
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "D1 empty-state read omitted the database name; the compensation plan was not created"
                    .to_owned(),
            )
        })?;
    let num_tables = response
        .result
        .get("num_tables")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            CliError::Input(
                "D1 empty-state read omitted an integer num_tables value; the compensation plan was not created"
                    .to_owned(),
            )
        })?;
    if num_tables != 0 {
        return Err(CliError::Input(format!(
            "D1 database `{database_id}` now contains {num_tables} table(s); cfctl will not derive a destructive compensation plan"
        )));
    }
    let file_size = response
        .result
        .get("file_size")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            CliError::Input(
                "D1 empty-state read omitted an integer file_size value; the compensation plan was not created"
                    .to_owned(),
            )
        })?;
    let jurisdiction = response
        .result
        .get("jurisdiction")
        .filter(|value| value.is_null() || value.is_string())
        .cloned()
        .ok_or_else(|| {
            CliError::Input(
                "D1 empty-state read omitted its nullable jurisdiction; the compensation plan was not created"
                    .to_owned(),
            )
        })?;
    let replication_mode = response
        .result
        .pointer("/read_replication/mode")
        .and_then(Value::as_str)
        .filter(|mode| matches!(*mode, "auto" | "disabled"))
        .ok_or_else(|| {
            CliError::Input(
                "D1 empty-state read omitted the bounded read-replication mode; the compensation plan was not created"
                    .to_owned(),
            )
        })?;
    let (source_operation_id, source_receipt_hash) =
        d1_compensation_source_binding(adapter_targets)?;
    Ok(json!({
        "schema_version": 1,
        "source_capability_id": D1_READ_REPLICATION_READ_CAPABILITY_ID,
        "source_path": D1_READ_REPLICATION_PATH,
        "target_capability_id": capability.id,
        "target_method": capability.method,
        "target_path": capability.path,
        "target_scope": "account",
        "account_id": account_id,
        "database_id": uuid,
        "database_name": name,
        "num_tables": num_tables,
        "file_size": file_size,
        "jurisdiction": jurisdiction,
        "read_replication": {"mode": replication_mode},
        "compensates_operation_id": source_operation_id,
        "source_create_receipt_hash": source_receipt_hash,
    }))
}

pub(super) fn d1_compensation_source_binding(adapter_targets: &Value) -> Result<(&str, &str)> {
    let source_operation_id = adapter_targets
        .get("compensates_operation_id")
        .and_then(Value::as_str)
        .filter(|operation_id| !operation_id.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "D1 compensation target omitted its source operation ID; the compensation plan was not created"
                    .to_owned(),
            )
        })?;
    let source_receipt_hash = adapter_targets
        .get("source_receipt_hash")
        .and_then(Value::as_str)
        .filter(|hash| hash.starts_with("sha256:"))
        .ok_or_else(|| {
            CliError::Input(
                "D1 compensation target omitted its source create receipt hash; the compensation plan was not created"
                    .to_owned(),
            )
        })?;
    Ok((source_operation_id, source_receipt_hash))
}

pub(super) async fn read_live_d1_empty_database_state(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    adapter_targets: &Value,
    account_id: &str,
    credential: &AuthCredential,
) -> Result<(Value, EvidenceV1)> {
    if !should_bind_d1_empty_database_state(capability, adapter_targets) {
        return Err(CliError::Input(
            "D1 compensation drifted from its governed empty-database contract".to_owned(),
        ));
    }
    let selected_account = input
        .selectors
        .get("account_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "D1 empty-state precondition requires string selector `account_id`".to_owned(),
            )
        })?;
    if selected_account != account_id {
        return Err(CliError::Input(format!(
            "D1 compensation account `{selected_account}` differs from selected account `{account_id}`; the compensation plan was not created"
        )));
    }
    let database_id = input
        .selectors
        .get("database_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "D1 empty-state precondition requires string selector `database_id`".to_owned(),
            )
        })?;
    let source_capability = catalog
        .get(D1_READ_REPLICATION_READ_CAPABILITY_ID)
        .ok_or_else(|| capability_missing(D1_READ_REPLICATION_READ_CAPABILITY_ID))?;
    if !d1_read_replication_read_contract_supported(source_capability) {
        return Err(CliError::Input(
            "D1 empty-state source capability drifted from the governed database read".to_owned(),
        ));
    }
    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let response = executor
        .execute_read(
            source_capability,
            &CallInput {
                selectors: json!({"account_id": account_id, "database_id": database_id}),
                query: json!({"fields":[
                    "uuid", "name", "jurisdiction", "num_tables", "file_size", "read_replication"
                ]}),
                body: None,
                ..CallInput::default()
            },
            credential,
        )
        .await?;
    let receipt = apply_d1_empty_database_state_response(
        capability,
        adapter_targets,
        account_id,
        database_id,
        &response,
    )?;
    let evidence = store.write_evidence(EvidenceClass::LiveRead, &receipt)?;
    Ok((receipt, evidence))
}

pub(super) fn apply_cloudflare_tunnel_configuration_state_response(
    capability: &CapabilityV1,
    account_id: &str,
    tunnel_id: &str,
    response: &CloudflareResponseV1,
) -> Result<Value> {
    if !response.success || !(200..300).contains(&response.status) {
        return Err(CliError::Input(format!(
            "Cloudflare rejected the Tunnel configuration state read with HTTP {}; the mutation boundary was not crossed",
            response.status
        )));
    }
    let prior_config = response
        .result
        .get("config")
        .filter(|config| config.is_object())
        .cloned()
        .ok_or_else(|| {
            CliError::Input(
                "Tunnel configuration state read omitted an object `config`; initial configuration creation has no restorable prior snapshot and the mutation boundary was not crossed"
                    .to_owned(),
            )
        })?;
    let restore_input = CallInput {
        selectors: json!({"account_id": account_id, "tunnel_id": tunnel_id}),
        body: Some(json!({"config": prior_config})),
        ..CallInput::default()
    };
    preflight_call_input(capability, &restore_input, None).map_err(|error| {
        CliError::Input(format!(
            "live Tunnel configuration is outside cfctl's exact restorable request contract; the mutation boundary was not crossed: {error}"
        ))
    })?;
    let prior_config = restore_input
        .body
        .as_ref()
        .and_then(|body| body.get("config"))
        .cloned()
        .ok_or_else(|| {
            CliError::Input(
                "validated Tunnel configuration restore body omitted `config`; the mutation boundary was not crossed"
                    .to_owned(),
            )
        })?;
    Ok(json!({
        "schema_version": 1,
        "source_capability_id": CLOUDFLARE_TUNNEL_CONFIGURATION_READ_CAPABILITY_ID,
        "source_path": CLOUDFLARE_TUNNEL_CONFIGURATION_PATH,
        "target_capability_id": capability.id,
        "target_method": capability.method,
        "target_path": capability.path,
        "target_scope": "account",
        "account_id": account_id,
        "tunnel_id": tunnel_id,
        "prior_config": prior_config,
    }))
}

pub(super) async fn read_live_cloudflare_tunnel_configuration_state(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: &AuthCredential,
) -> Result<(Value, EvidenceV1)> {
    if !should_bind_cloudflare_tunnel_configuration_state(capability) {
        return Err(CliError::Input(
            "Tunnel configuration mutation drifted from its governed prior-state contract"
                .to_owned(),
        ));
    }
    let selected_account = input
        .selectors
        .get("account_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "Tunnel configuration state precondition requires string selector `account_id`"
                    .to_owned(),
            )
        })?;
    if selected_account != account_id {
        return Err(CliError::Input(format!(
            "Tunnel configuration target account `{selected_account}` differs from selected account `{account_id}`; the mutation boundary was not crossed"
        )));
    }
    let tunnel_id = input
        .selectors
        .get("tunnel_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "Tunnel configuration state precondition requires string selector `tunnel_id`"
                    .to_owned(),
            )
        })?;
    let source_capability = catalog
        .get(CLOUDFLARE_TUNNEL_CONFIGURATION_READ_CAPABILITY_ID)
        .ok_or_else(|| capability_missing(CLOUDFLARE_TUNNEL_CONFIGURATION_READ_CAPABILITY_ID))?;
    if !cloudflare_tunnel_configuration_read_contract_supported(source_capability) {
        return Err(CliError::Input(
            "Tunnel configuration state source capability drifted from the governed same-path read"
                .to_owned(),
        ));
    }
    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let response = executor
        .execute_read(
            source_capability,
            &CallInput {
                selectors: json!({"account_id": account_id, "tunnel_id": tunnel_id}),
                ..CallInput::default()
            },
            credential,
        )
        .await?;
    let receipt = apply_cloudflare_tunnel_configuration_state_response(
        capability, account_id, tunnel_id, &response,
    )?;
    let evidence = store.write_evidence(EvidenceClass::LiveRead, &receipt)?;
    Ok((receipt, evidence))
}

pub(super) fn warp_connector_configuration_restore_body(
    ha_mode: &str,
    config: Option<&Value>,
) -> Value {
    let mut body = Map::from_iter([("ha_mode".to_owned(), Value::String(ha_mode.to_owned()))]);
    if matches!(ha_mode, "aws" | "local")
        && let Some(config) = config.filter(|value| !value.is_null())
    {
        body.insert("config".to_owned(), config.clone());
    }
    Value::Object(body)
}

pub(super) fn apply_warp_connector_configuration_state_response(
    capability: &CapabilityV1,
    account_id: &str,
    tunnel_id: &str,
    response: &CloudflareResponseV1,
) -> Result<Value> {
    if !response.success || !(200..300).contains(&response.status) {
        return Err(CliError::Input(format!(
            "Cloudflare rejected the WARP Connector configuration state read with HTTP {}; the mutation boundary was not crossed",
            response.status
        )));
    }
    let prior_ha_mode = response
        .result
        .get("ha_mode")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "WARP Connector configuration state read omitted string `ha_mode`; the mutation boundary was not crossed"
                    .to_owned(),
            )
        })?;
    let prior_config = response
        .result
        .get("config")
        .cloned()
        .unwrap_or(Value::Null);
    let observed_state_input = CallInput {
        selectors: json!({"account_id": account_id, "tunnel_id": tunnel_id}),
        body: Some(json!({
            "ha_mode": prior_ha_mode,
            "config": prior_config,
        })),
        ..CallInput::default()
    };
    preflight_call_input(capability, &observed_state_input, None).map_err(|error| {
        CliError::Input(format!(
            "live WARP Connector configuration is outside cfctl's exact restorable HA contract; the mutation boundary was not crossed: {error}"
        ))
    })?;
    Ok(json!({
        "schema_version": 1,
        "source_capability_id": WARP_CONNECTOR_CONFIGURATION_READ_CAPABILITY_ID,
        "source_path": WARP_CONNECTOR_CONFIGURATION_PATH,
        "target_capability_id": capability.id,
        "target_method": capability.method,
        "target_path": capability.path,
        "target_scope": "account",
        "account_id": account_id,
        "tunnel_id": tunnel_id,
        "prior_ha_mode": prior_ha_mode,
        "prior_config": prior_config,
    }))
}

pub(super) async fn read_live_warp_connector_configuration_state(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: &AuthCredential,
) -> Result<(Value, EvidenceV1)> {
    if !should_bind_warp_connector_configuration_state(capability) {
        return Err(CliError::Input(
            "WARP Connector configuration mutation drifted from its governed prior-state contract"
                .to_owned(),
        ));
    }
    let selected_account = input
        .selectors
        .get("account_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "WARP Connector state precondition requires string selector `account_id`"
                    .to_owned(),
            )
        })?;
    if selected_account != account_id {
        return Err(CliError::Input(format!(
            "WARP Connector target account `{selected_account}` differs from selected account `{account_id}`; the mutation boundary was not crossed"
        )));
    }
    let tunnel_id = input
        .selectors
        .get("tunnel_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "WARP Connector state precondition requires string selector `tunnel_id`".to_owned(),
            )
        })?;
    let source_capability = catalog
        .get(WARP_CONNECTOR_CONFIGURATION_READ_CAPABILITY_ID)
        .ok_or_else(|| capability_missing(WARP_CONNECTOR_CONFIGURATION_READ_CAPABILITY_ID))?;
    if !warp_connector_configuration_read_contract_supported(source_capability) {
        return Err(CliError::Input(
            "WARP Connector state source capability drifted from the governed same-path read"
                .to_owned(),
        ));
    }
    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let response = executor
        .execute_read(
            source_capability,
            &CallInput {
                selectors: json!({"account_id": account_id, "tunnel_id": tunnel_id}),
                ..CallInput::default()
            },
            credential,
        )
        .await?;
    let receipt = apply_warp_connector_configuration_state_response(
        capability, account_id, tunnel_id, &response,
    )?;
    let evidence = store.write_evidence(EvidenceClass::LiveRead, &receipt)?;
    Ok((receipt, evidence))
}

pub(super) fn apply_web_analytics_rum_state_response(
    capability: &CapabilityV1,
    account_id: &str,
    zone_id: &str,
    response: &CloudflareResponseV1,
) -> Result<Value> {
    if !response.success || !(200..300).contains(&response.status) {
        return Err(CliError::Input(format!(
            "Cloudflare rejected the Web Analytics RUM state read with HTTP {}; the mutation boundary was not crossed",
            response.status
        )));
    }
    if response.result.get("id").and_then(Value::as_str) != Some("rum") {
        return Err(CliError::Input(
            "Web Analytics RUM state read did not identify setting `rum`; the mutation boundary was not crossed"
                .to_owned(),
        ));
    }
    if response.result.get("editable").and_then(Value::as_bool) != Some(true) {
        return Err(CliError::Input(
            "Web Analytics RUM state is not explicitly editable; the mutation boundary was not crossed"
                .to_owned(),
        ));
    }
    let prior_value = response
        .result
        .get("value")
        .and_then(Value::as_str)
        .filter(|value| matches!(*value, "on" | "off"))
        .ok_or_else(|| {
            CliError::Input(
                "Web Analytics RUM state is not an exactly restorable `on` or `off` value; `manual` and unknown states require operator inspection"
                    .to_owned(),
            )
        })?;
    Ok(json!({
        "schema_version": 1,
        "source_capability_id": WEB_ANALYTICS_RUM_READ_CAPABILITY_ID,
        "source_path": WEB_ANALYTICS_RUM_PATH,
        "target_capability_id": capability.id,
        "target_method": capability.method,
        "target_path": capability.path,
        "target_scope": "zone",
        "account_id": account_id,
        "zone_id": zone_id,
        "setting_id": "rum",
        "editable": true,
        "prior_value": prior_value,
    }))
}

pub(super) async fn read_live_web_analytics_rum_state(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: &AuthCredential,
) -> Result<(Value, EvidenceV1)> {
    if !should_bind_web_analytics_rum_state(capability) {
        return Err(CliError::Input(
            "Web Analytics RUM mutation drifted from its governed prior-state contract".to_owned(),
        ));
    }
    let zone_id = input
        .selectors
        .get("zone_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "Web Analytics RUM state precondition requires string selector `zone_id`"
                    .to_owned(),
            )
        })?;
    let source_capability = catalog
        .get(WEB_ANALYTICS_RUM_READ_CAPABILITY_ID)
        .ok_or_else(|| capability_missing(WEB_ANALYTICS_RUM_READ_CAPABILITY_ID))?;
    if !web_analytics_rum_read_contract_supported(source_capability) {
        return Err(CliError::Input(
            "Web Analytics RUM state source capability drifted from the governed same-path read"
                .to_owned(),
        ));
    }
    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let response = executor
        .execute_read(
            source_capability,
            &CallInput {
                selectors: json!({"zone_id": zone_id}),
                ..CallInput::default()
            },
            credential,
        )
        .await?;
    let receipt =
        apply_web_analytics_rum_state_response(capability, account_id, zone_id, &response)?;
    let evidence = store.write_evidence(EvidenceClass::LiveRead, &receipt)?;
    Ok((receipt, evidence))
}

pub(super) fn apply_global_warp_override_state_response(
    account_id: &str,
    response: &CloudflareResponseV1,
) -> Result<Value> {
    if !response.success || !(200..300).contains(&response.status) {
        return Err(CliError::Input(format!(
            "Cloudflare rejected the Global WARP override state read with HTTP {}; the mutation boundary was not crossed",
            response.status
        )));
    }
    let disconnect = response
        .result
        .get("disconnect")
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            CliError::Input(
                "Global WARP override state read omitted boolean `disconnect`; the mutation boundary was not crossed"
                    .to_owned(),
            )
        })?;
    Ok(json!({
        "schema_version": 1,
        "source_capability_id": GLOBAL_WARP_OVERRIDE_READ_CAPABILITY_ID,
        "source_path": GLOBAL_WARP_OVERRIDE_PATH,
        "target_capability_id": GLOBAL_WARP_OVERRIDE_MUTATION_CAPABILITY_ID,
        "target_scope": "account",
        "target_id": account_id,
        "disconnect": disconnect,
    }))
}

pub(super) async fn read_live_global_warp_override_state(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    account_id: &str,
    credential: &AuthCredential,
) -> Result<(Value, EvidenceV1)> {
    if !should_bind_global_warp_override_state(capability) {
        return Err(CliError::Input(
            "Global WARP override mutation drifted from its governed prior-state contract"
                .to_owned(),
        ));
    }
    let selected_account = input
        .selectors
        .get("account_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "Global WARP override state precondition requires string selector `account_id`"
                    .to_owned(),
            )
        })?;
    if selected_account != account_id {
        return Err(CliError::Input(format!(
            "Global WARP override target account `{selected_account}` differs from selected account `{account_id}`; the mutation boundary was not crossed"
        )));
    }
    let source_capability = catalog
        .get(GLOBAL_WARP_OVERRIDE_READ_CAPABILITY_ID)
        .ok_or_else(|| capability_missing(GLOBAL_WARP_OVERRIDE_READ_CAPABILITY_ID))?;
    if !global_warp_override_read_contract_supported(source_capability) {
        return Err(CliError::Input(
            "Global WARP override state source capability drifted from the governed account read"
                .to_owned(),
        ));
    }
    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let response = executor
        .execute_read(
            source_capability,
            &CallInput {
                selectors: json!({"account_id": account_id}),
                query: json!({}),
                body: None,
                ..CallInput::default()
            },
            credential,
        )
        .await?;
    let receipt = apply_global_warp_override_state_response(account_id, &response)?;
    let evidence = store.write_evidence(EvidenceClass::LiveRead, &receipt)?;
    Ok((receipt, evidence))
}
