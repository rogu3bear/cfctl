use std::{
    collections::BTreeMap,
    fs,
    fs::OpenOptions,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

use chrono::Utc;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tokio::time::Duration;

use super::{
    AuthCredential, CallInput, CapabilityV1, CatalogSnapshot, CliError, PlanV1, ProfileMetadata,
    Result, StateStore, Uuid, cli_io, credential_generation_for_read, workspace_d1_migration,
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

const TARGET_KEY: &str = "workspace_d1_policy_projection";
const QUERY_TIMEOUT: Duration = Duration::from_mins(2);
const APPLY_TIMEOUT: Duration = Duration::from_mins(5);
const MAX_PROJECTION_BYTES: u64 = 64 * 1024 * 1024;

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
    workspace_d1_migration::validate_recovery_target(
        store,
        target,
        &plan.catalog_hash,
        contract.recovery_max_age_seconds,
        Utc::now(),
    )
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
    let stage = private_stage(target)?;
    let stage_path = Path::new(target_string(stage, "path")?);

    let version = workspace_d1_migration::run_wrangler(
        &["--version".to_owned()],
        Path::new(&contract.repository_root),
        credential,
        &plan.account_id,
        &store.paths().cache_dir,
        QUERY_TIMEOUT,
    )
    .await?;
    let observed_version = workspace_d1_migration::parse_wrangler_version(&version.stdout)?;
    if !version.success || observed_version != contract.wrangler_version {
        return Err(CliError::Input(format!(
            "workspace D1 projection requires Wrangler {}, observed {}",
            contract.wrangler_version, observed_version
        )));
    }
    let apply = workspace_d1_migration::run_wrangler(
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

#[expect(
    clippy::too_many_lines,
    reason = "verification keeps the route-count and three digest readbacks in one body-free consistency decision"
)]
async fn verify_inner(
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
    let count_sql = format!(
        "SELECT COUNT(*) AS route_count FROM {route_table} WHERE {policy_column} = '{policy_sha}'",
        route_table = identifier(&contract.route_table)?,
        policy_column = identifier(&contract.route_policy_sha_column)?,
    );
    let count_rows = workspace_d1_migration::execute_json_query(
        database_name,
        config,
        &count_sql,
        root,
        credential,
        &plan.account_id,
        &store.paths().cache_dir,
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
    let state_rows = workspace_d1_migration::execute_json_query(
        database_name,
        config,
        &state_sql,
        root,
        credential,
        &plan.account_id,
        &store.paths().cache_dir,
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
    let digests_passed = observed.len() == 3
        && observed
            .get(&contract.active_policy_key)
            .map(String::as_str)
            == Some(policy_sha)
        && observed
            .get(&contract.desired_state_digest_key)
            .map(String::as_str)
            == Some(desired_sha)
        && observed
            .get(&contract.projection_digest_key)
            .map(String::as_str)
            == Some(projection_sha);
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
    let target = json!({
        "schema_version": 1,
        "path": stage_path,
        "sha256": digest,
        "bytes": bytes.len(),
        "unix_mode": if cfg!(unix) { Value::String("0600".to_owned()) } else { Value::Null },
        "content_in_plan": false,
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
    {
        return Err(CliError::Input(
            "workspace D1 private stage contract is invalid".to_owned(),
        ));
    }
    let path = Path::new(target_string(stage, "path")?);
    let stage_root = store.paths().data_dir.join("private-operation-stages");
    let stage_dir = path
        .parent()
        .ok_or_else(|| CliError::Input("workspace D1 private stage path is invalid".to_owned()))?;
    if !path.is_absolute()
        || path.file_name().and_then(|name| name.to_str()) != Some("d1-policy-projection.sql")
        || stage_dir.parent() != Some(stage_root.as_path())
        || stage_dir
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| Uuid::parse_str(name).ok())
            .is_none()
    {
        return Err(CliError::Input(
            "workspace D1 private stage escaped its exact managed directory".to_owned(),
        ));
    }
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
    let bytes = read_private_regular_file(path, MAX_PROJECTION_BYTES)?;
    if bytes.len() as u64 != expected_bytes || sha256(&bytes) != expected_sha {
        return Err(CliError::Input(
            "workspace D1 private stage digest drifted; create a new plan".to_owned(),
        ));
    }
    Ok(())
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
mod tests {
    use super::super::RuntimePaths;

    use super::*;

    #[test]
    fn expected_projection_accepts_only_bounded_hashes_and_counts() {
        let input: CallInput = serde_json::from_value(json!({
            "selectors": {},
            "query": {
                "policy_sha256": format!("sha256:{}", "a".repeat(64)),
                "desired_state_sha256": format!("sha256:{}", "b".repeat(64)),
                "projection_sha256": format!("sha256:{}", "c".repeat(64)),
                "expected_route_count": "141"
            }
        }))
        .expect("input");
        let expected = expected_projection(&input).expect("projection");
        assert_eq!(expected.route_count, 141);
    }

    #[cfg(unix)]
    #[test]
    fn private_projection_stage_is_mode_0600_and_body_free() {
        let root = tempfile::tempdir_in("/private/tmp").expect("root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("store");
        let source = root.path().join("projection.sql");
        fs::write(&source, "BEGIN; INSERT INTO routes VALUES (1); COMMIT;\n").expect("source");
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).expect("mode");
        let staged = stage_private_projection(&store, &source).expect("stage");
        assert_eq!(staged["content_in_plan"], false);
        assert!(!staged.to_string().contains("INSERT INTO"));
        let path = Path::new(staged["path"].as_str().expect("path"));
        let metadata = fs::metadata(path).expect("metadata");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn private_projection_rejects_a_symlinked_source_component() {
        let root = tempfile::tempdir_in("/private/tmp").expect("root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("store");
        let private_dir = root.path().join("private");
        fs::create_dir(&private_dir).expect("private directory");
        let source = private_dir.join("projection.sql");
        fs::write(&source, "BEGIN; COMMIT;\n").expect("source");
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).expect("mode");
        let linked_dir = root.path().join("linked-private");
        std::os::unix::fs::symlink(&private_dir, &linked_dir).expect("symlink");

        let error = stage_private_projection(&store, &linked_dir.join("projection.sql"))
            .expect_err("symlinked parent must fail closed");
        assert!(error.to_string().contains("symlink component"));
    }

    #[test]
    fn state_keys_and_identifiers_fail_closed() {
        assert!(identifier("alias_routes").is_ok());
        assert!(identifier("routes; DROP TABLE routes").is_err());
        assert!(state_key("active_policy_sha256").is_ok());
        assert!(state_key("active' OR 1=1").is_err());
    }
}
