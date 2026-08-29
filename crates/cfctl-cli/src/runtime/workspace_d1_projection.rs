use chrono::Utc;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tokio::time::Duration;

use super::{
    prelude::{
        AuthCredential, BTreeMap, BTreeSet, CallInput, CapabilityV1, CatalogSnapshot, CliError,
        OpenOptions, OpenOptionsExt, Path, PathBuf, PermissionsExt, PlanV1, ProfileMetadata, Read,
        Result, StateStore, Uuid, Write,
    },
    read_execution::credential_generation_for_read,
    support::cli_io,
    workspace_d1_migration,
};
use std::{fs, path::Component};

const TARGET_KEY: &str = "workspace_d1_policy_projection";
const QUERY_TIMEOUT: Duration = Duration::from_mins(2);
const APPLY_TIMEOUT: Duration = Duration::from_mins(5);
const MAX_PROJECTION_BYTES: u64 = 64 * 1024 * 1024;

pub(super) fn project_private_query_rows(
    sql: &str,
    rows: &[Map<String, Value>],
) -> Option<Result<()>> {
    if sql.starts_with("SELECT COUNT(*) AS route_count ") {
        return Some((|| {
            if rows.len() != 1 {
                return Err(CliError::Input(
                    "private D1 route-count readback had invalid cardinality".to_owned(),
                ));
            }
            exact_row_fields(&rows[0], &["route_count"])?;
            if rows[0].get("route_count").and_then(Value::as_u64).is_none() {
                return Err(CliError::Input(
                    "private D1 route-count readback had an invalid value".to_owned(),
                ));
            }
            Ok(())
        })());
    }
    if sql.starts_with("SELECT ")
        && sql.contains(" AS state_key, ")
        && sql.contains(" AS state_value FROM ")
    {
        return Some((|| {
            let expected_keys = projected_state_keys(sql).ok_or_else(|| {
                CliError::Input("private D1 runtime-state query contract was invalid".to_owned())
            })?;
            if rows.len() > 3 {
                return Err(CliError::Input(
                    "private D1 runtime-state readback exceeded its closed row limit".to_owned(),
                ));
            }
            for row in rows {
                exact_row_fields(row, &["state_key", "state_value"])?;
                let key = row
                    .get("state_key")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        CliError::Input("private D1 runtime-state key was invalid".to_owned())
                    })?;
                let value = row
                    .get("state_value")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        CliError::Input("private D1 runtime-state value was invalid".to_owned())
                    })?;
                if key.is_empty()
                    || key.len() > 128
                    || !expected_keys.contains(key)
                    || value.len() != 64
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return Err(CliError::Input(
                        "private D1 runtime-state readback was outside its closed value contract"
                            .to_owned(),
                    ));
                }
            }
            Ok(())
        })());
    }
    None
}

fn projected_state_keys(sql: &str) -> Option<BTreeSet<String>> {
    let values = sql.split_once(" IN ('")?.1.split_once("') ORDER BY ")?.0;
    let keys = values
        .split("','")
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    (keys.len() == 3 && keys.iter().all(|key| !key.is_empty() && key.len() <= 128)).then_some(keys)
}

fn exact_row_fields(row: &Map<String, Value>, expected: &[&str]) -> Result<()> {
    if row.len() != expected.len() || expected.iter().any(|field| !row.contains_key(*field)) {
        return Err(CliError::Input(
            "private D1 policy readback contained an unowned field".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn load(store: &StateStore, capability_id: &str) -> Result<Option<CapabilityV1>> {
    Ok(
        cfctl_workspace::load_workspace_d1_policy_projection_capability(
            &store.workspace_roots()?,
            capability_id,
        )?,
    )
}

pub(super) fn prepare_plan_target(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    profile: &ProfileMetadata,
    account_id: &str,
    source: &Path,
) -> Result<Option<Value>> {
    let Some(contract) = capability.workspace_d1_policy_projection.as_ref() else {
        return Ok(None);
    };
    let config_contract = config_contract(contract);
    let config = workspace_d1_migration::validated_config(&config_contract, input)?;
    let expected = expected_projection(input)?;
    let stage = stage_private_projection(store, source)?;
    let generation = credential_generation_for_read(profile)?;
    let recovery = workspace_d1_migration::fresh_recovery_proof(
        store,
        catalog,
        input,
        &profile.id,
        account_id,
        &generation,
        contract.recovery_max_age_seconds,
        Utc::now(),
    )?;
    Ok(Some(json!({
        "schema_version": 1,
        "repository_root": contract.repository_root,
        "repository_head": contract.repository_head,
        "operation_pack_sha256": contract.operation_pack_sha256,
        "production_config": config.path,
        "production_config_sha256": config.sha256,
        "database_binding": contract.database_binding,
        "database_name": config.database_name,
        "database_id": config.database_id,
        "account_id": account_id,
        "profile_id": profile.id,
        "credential_generation_id": generation,
        "private_stage": stage,
        "policy_sha256": expected.policy_sha256,
        "desired_state_sha256": expected.desired_state_sha256,
        "projection_sha256": expected.projection_sha256,
        "expected_route_count": expected.route_count,
        "recovery": recovery,
    })))
}

pub(super) fn local_artifact_paths(capability: &CapabilityV1) -> Result<Option<Vec<PathBuf>>> {
    let Some(contract) = capability.workspace_d1_policy_projection.as_ref() else {
        return Ok(None);
    };
    let root = Path::new(&contract.repository_root);
    let pack = root.join(&contract.operation_pack_path);
    Ok(Some(vec![
        pack.parent()
            .ok_or_else(|| {
                CliError::Input("workspace D1 projection pack has no parent".to_owned())
            })?
            .to_path_buf(),
    ]))
}

pub(super) fn validate_bound_plan(store: &StateStore, plan: &PlanV1) -> Result<()> {
    validate_bound_plan_inner(store, plan, true)
}

pub(super) fn validate_bound_plan_for_rectification(
    store: &StateStore,
    plan: &PlanV1,
) -> Result<()> {
    validate_bound_plan_inner(store, plan, false)
}

fn validate_bound_plan_inner(
    store: &StateStore,
    plan: &PlanV1,
    require_fresh_recovery: bool,
) -> Result<()> {
    let Some(contract) = plan.capability.workspace_d1_policy_projection.as_ref() else {
        return Ok(());
    };
    let current = load(store, &plan.capability.id)?.ok_or_else(|| {
        CliError::Input(
            "workspace D1 policy projection is no longer uniquely available; create a new plan"
                .to_owned(),
        )
    })?;
    if current.workspace_d1_policy_projection.as_ref() != Some(contract) {
        return Err(CliError::Input(
            "workspace D1 policy projection repository authority drifted; create a new plan"
                .to_owned(),
        ));
    }
    let input: CallInput = serde_json::from_value(plan.input.clone())?;
    let expected = expected_projection(&input)?;
    let config = workspace_d1_migration::validated_config(&config_contract(contract), &input)?;
    let target = target(plan)?;
    require_string(target, "repository_head", &contract.repository_head)?;
    require_string(
        target,
        "operation_pack_sha256",
        &contract.operation_pack_sha256,
    )?;
    require_string(target, "production_config", &config.path)?;
    require_string(target, "production_config_sha256", &config.sha256)?;
    require_string(target, "database_name", &config.database_name)?;
    require_string(target, "database_id", &config.database_id)?;
    require_string(target, "account_id", &plan.account_id)?;
    require_string(target, "policy_sha256", &expected.policy_sha256)?;
    require_string(
        target,
        "desired_state_sha256",
        &expected.desired_state_sha256,
    )?;
    require_string(target, "projection_sha256", &expected.projection_sha256)?;
    if target.get("expected_route_count").and_then(Value::as_u64) != Some(expected.route_count) {
        return Err(CliError::Input(
            "workspace D1 policy projection route count drifted; create a new plan".to_owned(),
        ));
    }
    validate_private_stage(store, target)?;
    if require_fresh_recovery {
        workspace_d1_migration::validate_recovery_target(
            store,
            target,
            &plan.catalog_hash,
            contract.recovery_max_age_seconds,
            Utc::now(),
        )
    } else {
        workspace_d1_migration::validate_recovery_target_identity(
            store,
            target,
            &plan.catalog_hash,
            Utc::now(),
        )
        .map(|_| ())
    }
}

pub(super) async fn run(
    store: &StateStore,
    plan: &PlanV1,
    credential: &AuthCredential,
) -> Result<Value> {
    validate_bound_plan(store, plan)?;
    let contract = plan
        .capability
        .workspace_d1_policy_projection
        .as_ref()
        .ok_or_else(|| {
            CliError::Input("workspace D1 policy projection contract is missing".to_owned())
        })?;
    let target = target(plan)?;
    let database_name = target_string(target, "database_name")?;
    let config = target_string(target, "production_config")?;
    let config_sha256 = target_string(target, "production_config_sha256")?;
    let stage = private_stage(target)?;
    let stage_path = private_stage_path(store, stage)?;

    let version = workspace_d1_migration::run_wrangler(
        &["--version".to_owned()],
        Path::new(&contract.repository_root),
        credential,
        &plan.account_id,
        &store.paths().cache_dir,
        QUERY_TIMEOUT,
    )
    .await
    .map_err(CliError::delegated_mutation_not_attempted)?;
    let observed_version = workspace_d1_migration::parse_wrangler_version(&version.stdout)?;
    if !version.success || observed_version != contract.wrangler_version {
        return Err(CliError::Input(format!(
            "workspace D1 projection requires Wrangler {}, observed {}",
            contract.wrangler_version, observed_version
        )));
    }
    let apply = workspace_d1_migration::run_wrangler_with_config_identity(
        &[
            "d1".to_owned(),
            "execute".to_owned(),
            database_name.to_owned(),
            "--remote".to_owned(),
            "--config".to_owned(),
            config.to_owned(),
            "--file".to_owned(),
            stage_path.display().to_string(),
        ],
        Path::new(&contract.repository_root),
        credential,
        &plan.account_id,
        &store.paths().cache_dir,
        APPLY_TIMEOUT,
        config_sha256,
        &contract.config_template_sha256,
        &contract.database_binding,
    )
    .await?;
    Ok(json!({
        "adapter": "workspace_d1_policy_projection_v1",
        "command": "wrangler d1 execute --file <private-stage>",
        "success": apply.success,
        "exit_status": apply.exit_status,
        "boundary_crossed": true,
        "wrangler_version": observed_version,
        "source_sha256": target_string(stage, "sha256")?,
        "source_bytes": stage.get("bytes").and_then(Value::as_u64),
        "policy_sha256": target_string(target, "policy_sha256")?,
        "desired_state_sha256": target_string(target, "desired_state_sha256")?,
        "projection_sha256": target_string(target, "projection_sha256")?,
        "expected_route_count": target.get("expected_route_count"),
        "credential_environment": ["CLOUDFLARE_API_TOKEN"],
        "recovery": target.get("recovery").cloned().unwrap_or(Value::Null),
        "provider_output_retained": false,
    }))
}

pub(super) async fn verify(
    store: &StateStore,
    plan: &PlanV1,
    credential: &AuthCredential,
) -> Value {
    match verify_inner(store, plan, credential).await {
        Ok(value) => value,
        Err(error) => json!({
            "passed": false,
            "basis": format!("workspace D1 policy projection readback failed closed: {error}"),
        }),
    }
}

pub(super) async fn verify_rectification(
    store: &StateStore,
    plan: &PlanV1,
    credential: &AuthCredential,
) -> Value {
    match verify_inner_with_authority(store, plan, credential, false).await {
        Ok(value) => value,
        Err(error) => json!({
            "passed": false,
            "basis": format!("workspace D1 policy projection rectification readback failed closed: {error}"),
        }),
    }
}

async fn verify_inner(
    store: &StateStore,
    plan: &PlanV1,
    credential: &AuthCredential,
) -> Result<Value> {
    verify_inner_with_authority(store, plan, credential, true).await
}

async fn verify_inner_with_authority(
    store: &StateStore,
    plan: &PlanV1,
    credential: &AuthCredential,
    require_fresh_recovery: bool,
) -> Result<Value> {
    if require_fresh_recovery {
        validate_bound_plan(store, plan)?;
    } else {
        validate_bound_plan_for_rectification(store, plan)?;
    }
    let contract = plan
        .capability
        .workspace_d1_policy_projection
        .as_ref()
        .ok_or_else(|| {
            CliError::Input("workspace D1 policy projection contract is missing".to_owned())
        })?;
    let target = target(plan)?;
    let database_name = target_string(target, "database_name")?;
    let config = target_string(target, "production_config")?;
    let config_sha256 = target_string(target, "production_config_sha256")?;
    let root = Path::new(&contract.repository_root);
    let policy_sha = target_string(target, "policy_sha256")?;
    let desired_sha = target_string(target, "desired_state_sha256")?;
    let projection_sha = target_string(target, "projection_sha256")?;
    let expected_count = target
        .get("expected_route_count")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            CliError::Input("workspace D1 target omitted expected_route_count".to_owned())
        })?;
    let count_sql = route_count_sql(contract, policy_sha)?;
    let count_rows = workspace_d1_migration::execute_json_query_with_config_identity(
        database_name,
        &contract.database_binding,
        config,
        &count_sql,
        root,
        credential,
        &plan.account_id,
        &store.paths().cache_dir,
        config_sha256,
        &contract.config_template_sha256,
    )
    .await?;
    let observed_count = count_rows
        .first()
        .and_then(|row| row.get("route_count"))
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            CliError::Input("workspace D1 route-count readback was invalid".to_owned())
        })?;
    let state_sql = format!(
        "SELECT {key_column} AS state_key, {value_column} AS state_value FROM {state_table} WHERE {key_column} IN ('{policy_key}','{desired_key}','{projection_key}') ORDER BY {key_column}",
        key_column = identifier(&contract.runtime_state_key_column)?,
        value_column = identifier(&contract.runtime_state_value_column)?,
        state_table = identifier(&contract.runtime_state_table)?,
        policy_key = state_key(&contract.active_policy_key)?,
        desired_key = state_key(&contract.desired_state_digest_key)?,
        projection_key = state_key(&contract.projection_digest_key)?,
    );
    let state_rows = workspace_d1_migration::execute_json_query_with_config_identity(
        database_name,
        &contract.database_binding,
        config,
        &state_sql,
        root,
        credential,
        &plan.account_id,
        &store.paths().cache_dir,
        config_sha256,
        &contract.config_template_sha256,
    )
    .await?;
    let observed = state_rows
        .into_iter()
        .filter_map(|row| {
            Some((
                row.get("state_key")?.as_str()?.to_owned(),
                row.get("state_value")?.as_str()?.to_owned(),
            ))
        })
        .collect::<BTreeMap<_, _>>();
    let digests_passed =
        digest_readbacks_match(contract, &observed, policy_sha, desired_sha, projection_sha)?;
    let passed = observed_count == expected_count && digests_passed;
    Ok(json!({
        "passed": passed,
        "basis": if passed {
            "D1 route count and compiler-owned active policy, desired-state, and projection digest readbacks match the reviewed plan"
        } else {
            "D1 route count or compiler-owned digest readback did not match the reviewed plan"
        },
        "expected_route_count": expected_count,
        "observed_route_count": observed_count,
        "policy_sha256": policy_sha,
        "desired_state_sha256": desired_sha,
        "projection_sha256": projection_sha,
        "recovery": target.get("recovery").cloned().unwrap_or(Value::Null),
        "private_rows_returned": false,
    }))
}

fn route_count_sql(
    contract: &cfctl_core::WorkspaceD1PolicyProjectionContractV1,
    policy_sha256: &str,
) -> Result<String> {
    Ok(format!(
        "SELECT COUNT(*) AS route_count FROM {route_table} WHERE {policy_column} = '{policy_sha256}'",
        route_table = identifier(&contract.route_table)?,
        policy_column = identifier(&contract.route_policy_sha_column)?,
        policy_sha256 = raw_sha256(policy_sha256)?,
    ))
}

fn digest_readbacks_match(
    contract: &cfctl_core::WorkspaceD1PolicyProjectionContractV1,
    observed: &BTreeMap<String, String>,
    policy_sha256: &str,
    desired_state_sha256: &str,
    projection_sha256: &str,
) -> Result<bool> {
    Ok(observed.len() == 3
        && observed
            .get(&contract.active_policy_key)
            .map(String::as_str)
            == Some(raw_sha256(policy_sha256)?)
        && observed
            .get(&contract.desired_state_digest_key)
            .map(String::as_str)
            == Some(raw_sha256(desired_state_sha256)?)
        && observed
            .get(&contract.projection_digest_key)
            .map(String::as_str)
            == Some(raw_sha256(projection_sha256)?))
}

fn raw_sha256(value: &str) -> Result<&str> {
    value
        .strip_prefix("sha256:")
        .filter(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or_else(|| CliError::Input("workspace D1 projection digest is invalid".to_owned()))
}

#[derive(Debug)]
struct ExpectedProjection {
    policy_sha256: String,
    desired_state_sha256: String,
    projection_sha256: String,
    route_count: u64,
}

fn expected_projection(input: &CallInput) -> Result<ExpectedProjection> {
    let hash = |key: &str| -> Result<String> {
        input
            .query
            .get(key)
            .and_then(Value::as_str)
            .filter(|value| is_sha256(value))
            .map(str::to_owned)
            .ok_or_else(|| {
                CliError::Input(format!(
                    "workspace D1 policy projection requires valid {key}"
                ))
            })
    };
    let route_count = input
        .query
        .get("expected_route_count")
        .and_then(Value::as_str)
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0 && *value <= 1_000_000)
        .ok_or_else(|| {
            CliError::Input(
                "workspace D1 policy projection expected_route_count is invalid".to_owned(),
            )
        })?;
    Ok(ExpectedProjection {
        policy_sha256: hash("policy_sha256")?,
        desired_state_sha256: hash("desired_state_sha256")?,
        projection_sha256: hash("projection_sha256")?,
        route_count,
    })
}

fn stage_private_projection(store: &StateStore, source: &Path) -> Result<Value> {
    if !source.is_absolute()
        || source
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(CliError::Input(
            "workspace D1 policy projection source must be an absolute normalized path".to_owned(),
        ));
    }
    let bytes = read_private_regular_file(source, MAX_PROJECTION_BYTES)?;
    if std::str::from_utf8(&bytes).is_err() {
        return Err(CliError::Input(
            "workspace D1 policy projection source is not UTF-8".to_owned(),
        ));
    }
    let stage_dir = store
        .paths()
        .data_dir
        .join("private-operation-stages")
        .join(Uuid::new_v4().to_string());
    fs::create_dir_all(&stage_dir).map_err(|error| cli_io(&stage_dir, error))?;
    #[cfg(unix)]
    fs::set_permissions(&stage_dir, fs::Permissions::from_mode(0o700))
        .map_err(|error| cli_io(&stage_dir, error))?;
    let stage_path = stage_dir.join("d1-policy-projection.sql");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    let mut staged = options
        .open(&stage_path)
        .map_err(|error| cli_io(&stage_path, error))?;
    staged
        .write_all(&bytes)
        .map_err(|error| cli_io(&stage_path, error))?;
    staged
        .sync_all()
        .map_err(|error| cli_io(&stage_path, error))?;
    drop(staged);
    let digest = sha256(&bytes);
    let stage_id = stage_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| CliError::Input("workspace D1 private stage ID is invalid".to_owned()))?;
    let target = json!({
        "schema_version": 1,
        "stage_id": stage_id,
        "sha256": digest,
        "bytes": bytes.len(),
        "unix_mode": if cfg!(unix) { Value::String("0600".to_owned()) } else { Value::Null },
        "content_in_plan": false,
        "path_in_plan": false,
    });
    let target_object = target.as_object().ok_or_else(|| {
        CliError::Input("workspace D1 private stage did not serialize as an object".to_owned())
    })?;
    validate_private_stage_object(store, target_object)?;
    Ok(target)
}

fn validate_private_stage(store: &StateStore, target: &Map<String, Value>) -> Result<()> {
    let stage = private_stage(target)?;
    validate_private_stage_object(store, stage)
}

fn validate_private_stage_object(store: &StateStore, stage: &Map<String, Value>) -> Result<()> {
    if stage.get("schema_version").and_then(Value::as_u64) != Some(1)
        || stage.get("content_in_plan").and_then(Value::as_bool) != Some(false)
        || stage.get("path_in_plan").and_then(Value::as_bool) != Some(false)
        || stage.get("path").is_some()
    {
        return Err(CliError::Input(
            "workspace D1 private stage contract is invalid".to_owned(),
        ));
    }
    let path = private_stage_path(store, stage)?;
    let expected_sha = target_string(stage, "sha256")?;
    if !is_sha256(expected_sha) {
        return Err(CliError::Input(
            "workspace D1 private stage digest is invalid".to_owned(),
        ));
    }
    let expected_bytes = stage
        .get("bytes")
        .and_then(Value::as_u64)
        .filter(|value| *value > 0 && *value <= MAX_PROJECTION_BYTES)
        .ok_or_else(|| CliError::Input("workspace D1 private stage size is invalid".to_owned()))?;
    let bytes = read_private_regular_file(&path, MAX_PROJECTION_BYTES)?;
    if bytes.len() as u64 != expected_bytes || sha256(&bytes) != expected_sha {
        return Err(CliError::Input(
            "workspace D1 private stage digest drifted; create a new plan".to_owned(),
        ));
    }
    Ok(())
}

fn private_stage_path(store: &StateStore, stage: &Map<String, Value>) -> Result<PathBuf> {
    let stage_id = target_string(stage, "stage_id")?;
    let parsed = Uuid::parse_str(stage_id)
        .map_err(|_| CliError::Input("workspace D1 private stage ID is not a UUID".to_owned()))?;
    if parsed.hyphenated().to_string() != stage_id {
        return Err(CliError::Input(
            "workspace D1 private stage ID is not canonical".to_owned(),
        ));
    }
    Ok(store
        .paths()
        .data_dir
        .join("private-operation-stages")
        .join(stage_id)
        .join("d1-policy-projection.sql"))
}

fn read_private_regular_file(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    reject_symlink_components(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let mut file = options.open(path).map_err(|error| cli_io(path, error))?;
    let metadata = file.metadata().map_err(|error| cli_io(path, error))?;
    #[cfg(unix)]
    let private_mode = metadata.permissions().mode() & 0o777 == 0o600;
    #[cfg(not(unix))]
    let private_mode = true;
    if !metadata.is_file() || !private_mode || metadata.len() == 0 || metadata.len() > maximum {
        return Err(CliError::Input(format!(
            "workspace D1 private file must be a non-empty mode-0600 regular file of at most {maximum} bytes"
        )));
    }
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| CliError::Input("workspace D1 private file exceeds this host".to_owned()))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.read_to_end(&mut bytes)
        .map_err(|error| cli_io(path, error))?;
    if bytes.len() as u64 != metadata.len() {
        return Err(CliError::Input(
            "workspace D1 private file changed while it was read".to_owned(),
        ));
    }
    Ok(bytes)
}

fn reject_symlink_components(path: &Path) -> Result<()> {
    let mut cursor = PathBuf::new();
    for component in path.components() {
        cursor.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&cursor).map_err(|error| cli_io(&cursor, error))?;
        if metadata.file_type().is_symlink() {
            return Err(CliError::Input(format!(
                "workspace D1 private path has symlink component `{}`",
                cursor.display()
            )));
        }
    }
    Ok(())
}

fn config_contract(
    contract: &cfctl_core::WorkspaceD1PolicyProjectionContractV1,
) -> cfctl_core::WorkspaceD1MigrationContractV1 {
    cfctl_core::WorkspaceD1MigrationContractV1 {
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
        recovery_capability_id: contract.recovery_capability_id.clone(),
        recovery_max_age_seconds: contract.recovery_max_age_seconds,
        rollback_capability_id: contract.rollback_capability_id.clone(),
    }
}

fn target(plan: &PlanV1) -> Result<&Map<String, Value>> {
    plan.targets
        .get("adapter")
        .and_then(|value| value.get(TARGET_KEY))
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CliError::Input(
                "workspace D1 policy projection plan omitted adapter authority".to_owned(),
            )
        })
}

fn private_stage(target: &Map<String, Value>) -> Result<&Map<String, Value>> {
    target
        .get("private_stage")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CliError::Input("workspace D1 policy projection plan omitted private stage".to_owned())
        })
}

fn target_string<'a>(target: &'a Map<String, Value>, field: &str) -> Result<&'a str> {
    target
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(format!(
                "workspace D1 policy projection target omitted {field}"
            ))
        })
}

fn require_string(target: &Map<String, Value>, field: &str, expected: &str) -> Result<()> {
    if target_string(target, field)? == expected {
        Ok(())
    } else {
        Err(CliError::Input(format!(
            "workspace D1 policy projection target {field} drifted; create a new plan"
        )))
    }
}

fn identifier(value: &str) -> Result<&str> {
    ((1..=128).contains(&value.len())
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'))
    .then_some(value)
    .ok_or_else(|| CliError::Input("workspace D1 projection identifier is invalid".to_owned()))
}

fn state_key(value: &str) -> Result<&str> {
    ((1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')))
    .then_some(value)
    .ok_or_else(|| CliError::Input("workspace D1 projection state key is invalid".to_owned()))
}

fn is_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests;
