use std::{
    collections::BTreeSet,
    env, fs,
    path::{Path, PathBuf},
};

use cfctl_core::hash_value;
use chrono::{Duration as ChronoDuration, Utc};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tokio::time::Duration;

use super::{
    governed_cli::{governed_cli_workspace_env, redact_subprocess_text},
    prelude::{
        AuthCredential, CallInput, CapabilityV1, CatalogSnapshot, CliError,
        OperationalProofOutcomeV1, PlanV1, ProfileMetadata, Result, StateStore,
    },
    read_execution::credential_generation_for_read,
    support::cli_io,
    worker_deployment::{self, validate_maildesk_verified_sender_domains},
    workspace_d1_evidence, workspace_d1_projection, workspace_d1_reply_admission,
};

const TARGET_KEY: &str = "workspace_d1_migration";
const QUERY_TIMEOUT: Duration = Duration::from_mins(2);
const APPLY_TIMEOUT: Duration = Duration::from_mins(5);

pub(super) fn load(store: &StateStore, capability_id: &str) -> Result<Option<CapabilityV1>> {
    Ok(cfctl_workspace::load_workspace_d1_migration_capability(
        &store.workspace_roots()?,
        capability_id,
    )?)
}

pub(super) fn prepare_plan_target(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    profile: &ProfileMetadata,
    account_id: &str,
) -> Result<Option<Value>> {
    let Some(contract) = capability.workspace_d1_migration.as_ref() else {
        return Ok(None);
    };
    let config = validated_config(contract, input)?;
    let generation = credential_generation_for_read(profile)?;
    let recovery = fresh_recovery_proof(
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
        "recovery": recovery,
    })))
}

pub(super) fn local_artifact_paths(capability: &CapabilityV1) -> Result<Option<Vec<PathBuf>>> {
    let Some(contract) = capability.workspace_d1_migration.as_ref() else {
        return Ok(None);
    };
    let root = Path::new(&contract.repository_root);
    Ok(Some(vec![
        root.join(&contract.operation_pack_path)
            .parent()
            .ok_or_else(|| {
                CliError::Input("workspace D1 operation pack has no parent directory".to_owned())
            })?
            .to_path_buf(),
        root.join(&contract.migrations_dir),
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
    let Some(contract) = plan.capability.workspace_d1_migration.as_ref() else {
        return Ok(());
    };
    let current = load(store, &plan.capability.id)?.ok_or_else(|| {
        CliError::Input(
            "workspace D1 migration operation is no longer uniquely available; create a new plan"
                .to_owned(),
        )
    })?;
    if current.workspace_d1_migration.as_ref() != Some(contract) {
        return Err(CliError::Input(
            "workspace D1 migration repository authority drifted; create a new plan".to_owned(),
        ));
    }
    let input: CallInput = serde_json::from_value(plan.input.clone())?;
    let config = validated_config(contract, &input)?;
    let target = target(plan)?;
    require_target_string(target, "repository_head", &contract.repository_head)?;
    require_target_string(
        target,
        "operation_pack_sha256",
        &contract.operation_pack_sha256,
    )?;
    require_target_string(target, "production_config", &config.path)?;
    require_target_string(target, "production_config_sha256", &config.sha256)?;
    require_target_string(target, "database_name", &config.database_name)?;
    require_target_string(target, "database_id", &config.database_id)?;
    require_target_string(target, "account_id", &plan.account_id)?;
    if require_fresh_recovery {
        validate_recovery_target(
            store,
            target,
            &plan.catalog_hash,
            contract.recovery_max_age_seconds,
            Utc::now(),
        )
    } else {
        validate_recovery_target_identity(store, target, &plan.catalog_hash, Utc::now()).map(|_| ())
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
        .workspace_d1_migration
        .as_ref()
        .ok_or_else(|| CliError::Input("workspace D1 migration contract is missing".to_owned()))?;
    let target = target(plan)?;
    let database_name = target_string(target, "database_name")?;
    let config = target_string(target, "production_config")?;
    let config_sha256 = target_string(target, "production_config_sha256")?;

    let version = run_wrangler(
        &["--version".to_owned()],
        Path::new(&contract.repository_root),
        credential,
        &plan.account_id,
        &store.paths().cache_dir,
        QUERY_TIMEOUT,
    )
    .await
    .map_err(CliError::delegated_mutation_not_attempted)?;
    let observed_version = parse_wrangler_version(&version.stdout)?;
    if !version.success || observed_version != contract.wrangler_version {
        return Err(CliError::Input(format!(
            "workspace D1 migration requires Wrangler {}, observed {}",
            contract.wrangler_version, observed_version
        )));
    }

    let before = read_ledger(
        database_name,
        config,
        Path::new(&contract.repository_root),
        credential,
        &plan.account_id,
        &store.paths().cache_dir,
        Some(config_sha256),
        Some(&contract.config_template_sha256),
    )
    .await
    .map_err(CliError::delegated_mutation_not_attempted)?;
    let declared = declared_migration_names(contract)?;
    if !is_prefix(&before, &declared) {
        return Err(CliError::Input(
            "remote Wrangler migration ledger is not a prefix of the repository declaration"
                .to_owned(),
        ));
    }
    if before.len() == declared.len() {
        return Err(CliError::Input(
            "workspace D1 migration has no pending migration; create no write plan".to_owned(),
        ));
    }

    let apply = run_wrangler_with_expected_config(
        &[
            "d1".to_owned(),
            "migrations".to_owned(),
            "apply".to_owned(),
            database_name.to_owned(),
            "--remote".to_owned(),
            "--config".to_owned(),
            config.to_owned(),
        ],
        Path::new(&contract.repository_root),
        credential,
        &plan.account_id,
        &store.paths().cache_dir,
        APPLY_TIMEOUT,
        Some(config_sha256),
        Some(&contract.config_template_sha256),
    )
    .await?;
    Ok(json!({
        "adapter": "workspace_d1_migration_v1",
        "command": "wrangler d1 migrations apply",
        "success": apply.success,
        "exit_status": apply.exit_status,
        "boundary_crossed": true,
        "wrangler_version": observed_version,
        "ledger_before": before,
        "declared_migrations": declared,
        "stdout": apply.stdout,
        "stderr": apply.stderr,
        "provider_output_retained": apply.provider_output_retained,
        "private_config_sha256": apply.private_config_sha256,
        "credential_environment": ["CLOUDFLARE_API_TOKEN"],
        "recovery": target.get("recovery").cloned().unwrap_or(Value::Null),
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
            "basis": format!("workspace D1 migration readback failed closed: {error}"),
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
            "basis": format!("workspace D1 migration rectification readback failed closed: {error}"),
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
        .workspace_d1_migration
        .as_ref()
        .ok_or_else(|| CliError::Input("workspace D1 migration contract is missing".to_owned()))?;
    let target = target(plan)?;
    let database_name = target_string(target, "database_name")?;
    let config = target_string(target, "production_config")?;
    let config_sha256 = target_string(target, "production_config_sha256")?;
    let root = Path::new(&contract.repository_root);
    let ledger = read_ledger(
        database_name,
        config,
        root,
        credential,
        &plan.account_id,
        &store.paths().cache_dir,
        Some(config_sha256),
        Some(&contract.config_template_sha256),
    )
    .await?;
    let declared = declared_migration_names(contract)?;
    if ledger.iter().any(|name| !declared.contains(name)) {
        return Err(CliError::Input(
            "Wrangler migration ledger contained an unowned migration identity".to_owned(),
        ));
    }
    let assertion_sql = compile_assertion_sql(&contract.assertions)?;
    let assertion_rows = execute_json_query_with_expected_config(
        database_name,
        config,
        &assertion_sql,
        root,
        credential,
        &plan.account_id,
        &store.paths().cache_dir,
        Some(config_sha256),
        Some(&contract.config_template_sha256),
    )
    .await?;
    let assertions_passed = assertion_rows_pass(&assertion_rows, contract.assertions.len());
    let passed = ledger == declared && assertions_passed;
    Ok(json!({
        "passed": passed,
        "basis": if passed {
            "Wrangler migration ledger exactly matches the repository declaration and every compiler-owned schema assertion passed"
        } else {
            "Wrangler migration ledger or compiler-owned schema assertion readback did not match"
        },
        "ledger": ledger,
        "declared_migrations": declared,
        "schema_assertions": assertion_rows,
        "recovery": target.get("recovery").cloned().unwrap_or(Value::Null),
    }))
}

fn assertion_rows_pass(rows: &[Map<String, Value>], expected_count: usize) -> bool {
    if rows.len() != expected_count {
        return false;
    }
    let mut observed = BTreeSet::new();
    for row in rows {
        let Some(label) = row.get("assertion").and_then(Value::as_str) else {
            return false;
        };
        if row.get("passed").and_then(Value::as_i64) != Some(1)
            || !observed.insert(label.to_owned())
        {
            return false;
        }
    }
    observed
        == (0..expected_count)
            .map(|index| format!("assertion_{index}"))
            .collect()
}

#[derive(Debug)]
pub(super) struct ValidatedConfig {
    pub(super) path: String,
    pub(super) sha256: String,
    pub(super) database_name: String,
    pub(super) database_id: String,
}

pub(super) fn validated_config(
    contract: &cfctl_core::WorkspaceD1MigrationContractV1,
    input: &CallInput,
) -> Result<ValidatedConfig> {
    let raw = input
        .query
        .get("config")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input("workspace D1 migration requires query config".to_owned())
        })?;
    let root = fs::canonicalize(&contract.repository_root)
        .map_err(|source| cli_io(Path::new(&contract.repository_root), source))?;
    let expected = root.join(&contract.production_config_path);
    let canonical = fs::canonicalize(raw).map_err(|source| cli_io(Path::new(raw), source))?;
    if canonical != expected {
        return Err(CliError::Input(format!(
            "workspace D1 migration config must be the contract path {}",
            expected.display()
        )));
    }
    let metadata = fs::symlink_metadata(&canonical).map_err(|source| cli_io(&canonical, source))?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > 1_048_576
    {
        return Err(CliError::Input(
            "workspace D1 migration production config must be a regular file of at most 1 MiB"
                .to_owned(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(CliError::Input(
                "workspace D1 migration production config must not grant group or world permissions"
                    .to_owned(),
            ));
        }
    }
    let production_bytes = fs::read(&canonical).map_err(|source| cli_io(&canonical, source))?;
    let template_path = root.join(&contract.config_template_path);
    let template_bytes =
        fs::read(&template_path).map_err(|source| cli_io(&template_path, source))?;
    if sha256(&template_bytes) != contract.config_template_sha256 {
        return Err(CliError::Input(
            "workspace D1 migration tracked config template drifted from its contract".to_owned(),
        ));
    }
    let template: toml::Value = toml::from_str(
        std::str::from_utf8(&template_bytes)
            .map_err(|_| CliError::Input("tracked Wrangler config is not UTF-8".to_owned()))?,
    )
    .map_err(|error| CliError::Input(format!("tracked Wrangler config is invalid: {error}")))?;
    let mut production = parse_private_production_config(&production_bytes)?;
    let identity = production_identity(&production, &contract.database_binding)?;
    normalize_production_identity(&mut production, &template, &contract.database_binding)?;
    if production != template {
        return Err(CliError::Input(
            "production Wrangler config differs from the tracked template outside the closed private-config overlay"
                .to_owned(),
        ));
    }
    let selected_database = input
        .selectors
        .get("database_id")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("workspace D1 migration requires database_id".to_owned()))?;
    if selected_database != identity.1 {
        return Err(CliError::Input(
            "workspace D1 migration database selector differs from production config".to_owned(),
        ));
    }
    Ok(ValidatedConfig {
        path: canonical.display().to_string(),
        sha256: sha256(&production_bytes),
        database_name: identity.0,
        database_id: identity.1,
    })
}

fn parse_private_production_config(bytes: &[u8]) -> Result<toml::Value> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| CliError::Input("production Wrangler config is not UTF-8".to_owned()))?;
    toml::from_str(text)
        .map_err(|_| CliError::Input("production Wrangler config is invalid".to_owned()))
}

fn production_identity(config: &toml::Value, binding: &str) -> Result<(String, String)> {
    let databases = config
        .get("d1_databases")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| CliError::Input("production config has no D1 databases".to_owned()))?;
    let matches = databases
        .iter()
        .filter(|entry| entry.get("binding").and_then(toml::Value::as_str) == Some(binding))
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(CliError::Input(
            "production config must contain exactly one contract D1 binding".to_owned(),
        ));
    }
    let name = matches[0]
        .get("database_name")
        .and_then(toml::Value::as_str)
        .filter(|value| safe_name(value))
        .ok_or_else(|| CliError::Input("production D1 database name is invalid".to_owned()))?;
    let id = matches[0]
        .get("database_id")
        .and_then(toml::Value::as_str)
        .filter(|value| canonical_uuid(value))
        .ok_or_else(|| CliError::Input("production D1 database id is invalid".to_owned()))?;
    if let Some(preview) = matches[0].get("preview_database_id") {
        let preview = preview
            .as_str()
            .filter(|value| canonical_uuid(value))
            .ok_or_else(|| {
                CliError::Input("production preview D1 database id is invalid".to_owned())
            })?;
        if preview != id {
            return Err(CliError::Input(
                "a production config that declares preview_database_id must bind it to the same D1 database; use a separate governed preview config for an isolated preview database"
                    .to_owned(),
            ));
        }
    }
    Ok((name.to_owned(), id.to_owned()))
}

fn normalize_production_identity(
    production: &mut toml::Value,
    template: &toml::Value,
    binding: &str,
) -> Result<()> {
    let template_name = template
        .get("name")
        .cloned()
        .ok_or_else(|| CliError::Input("tracked Wrangler Worker name is missing".to_owned()))?;
    production["name"] = template_name;
    let template_database = d1_entry(template, binding)?.clone();
    *d1_entry_mut(production, binding)? = template_database;
    normalize_sender_identity(production, template)?;
    normalize_relay_activation(production, template)?;
    normalize_verified_sender_domains(production, template)?;
    Ok(())
}

fn normalize_verified_sender_domains(
    production: &mut toml::Value,
    template: &toml::Value,
) -> Result<()> {
    const KEY: &str = "MAILDESK_VERIFIED_SENDER_DOMAINS";
    let template_value = template
        .get("vars")
        .and_then(toml::Value::as_table)
        .and_then(|vars| vars.get(KEY))
        .and_then(toml::Value::as_str)
        .filter(|value| value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "tracked Wrangler template must declare the empty verified-sender domain sentinel"
                    .to_owned(),
            )
        })?;
    let production_vars = production
        .get_mut("vars")
        .and_then(toml::Value::as_table_mut)
        .ok_or_else(|| {
            CliError::Input(
                "production Wrangler config must materialize verified-sender domains".to_owned(),
            )
        })?;
    let production_value = production_vars
        .get(KEY)
        .and_then(toml::Value::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "production Wrangler config must materialize verified-sender domains".to_owned(),
            )
        })?;
    validate_maildesk_verified_sender_domains(production_value)?;
    production_vars.insert(
        KEY.to_owned(),
        toml::Value::String(template_value.to_owned()),
    );
    Ok(())
}

fn normalize_relay_activation(production: &mut toml::Value, template: &toml::Value) -> Result<()> {
    let Some(production_vars) = production
        .get_mut("vars")
        .and_then(toml::Value::as_table_mut)
    else {
        return Ok(());
    };
    let template_vars = template.get("vars").and_then(toml::Value::as_table);
    for key in ["MAILDESK_INBOUND_RELAY_MODE", "MAILDESK_REPLY_RELAY_MODE"] {
        let Some(production_mode) = production_vars.get(key) else {
            continue;
        };
        let valid_mode =
            |value: &toml::Value| matches!(value.as_str(), Some("disabled" | "enabled"));
        if !valid_mode(production_mode) {
            return Err(CliError::Input(format!(
                "workspace D1 production {key} must be disabled or enabled"
            )));
        }
        let template_mode = template_vars
            .and_then(|values| values.get(key))
            .filter(|value| valid_mode(value))
            .ok_or_else(|| {
                CliError::Input(format!(
                    "workspace D1 production {key} has no canonical tracked-template authority"
                ))
            })?;
        production_vars.insert(key.to_owned(), template_mode.clone());
    }
    Ok(())
}

fn normalize_sender_identity(production: &mut toml::Value, template: &toml::Value) -> Result<()> {
    let Some(production_senders) = production
        .get_mut("send_email")
        .and_then(toml::Value::as_array_mut)
    else {
        return Ok(());
    };
    let Some(template_senders) = template.get("send_email").and_then(toml::Value::as_array) else {
        return Ok(());
    };
    if production_senders.len() != template_senders.len() {
        return Ok(());
    }
    for (production_sender, template_sender) in production_senders.iter_mut().zip(template_senders)
    {
        let Some(production_table) = production_sender.as_table_mut() else {
            continue;
        };
        let Some(addresses) = production_table.get("allowed_sender_addresses") else {
            continue;
        };
        validate_sender_addresses(addresses)?;
        if let Some(template_addresses) = template_sender.get("allowed_sender_addresses") {
            production_table.insert(
                "allowed_sender_addresses".to_owned(),
                template_addresses.clone(),
            );
        } else {
            production_table.remove("allowed_sender_addresses");
        }
    }
    Ok(())
}

fn validate_sender_addresses(value: &toml::Value) -> Result<()> {
    let valid = value.as_array().is_some_and(|addresses| {
        (1..=256).contains(&addresses.len())
            && addresses.iter().all(|address| {
                address.as_str().is_some_and(|address| {
                    (3..=320).contains(&address.len())
                        && !address
                            .bytes()
                            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
                        && address.split_once('@').is_some_and(|(local, domain)| {
                            !local.is_empty()
                                && !domain.is_empty()
                                && !domain.contains('@')
                                && !domain.starts_with('.')
                                && !domain.ends_with('.')
                        })
                })
            })
    });
    if valid {
        Ok(())
    } else {
        Err(CliError::Input(
            "workspace D1 production sender identity must be a bounded list of email addresses"
                .to_owned(),
        ))
    }
}

fn d1_entry<'a>(config: &'a toml::Value, binding: &str) -> Result<&'a toml::Value> {
    let databases = config
        .get("d1_databases")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| CliError::Input("Wrangler config has no D1 databases".to_owned()))?;
    let matches = databases
        .iter()
        .filter(|entry| entry.get("binding").and_then(toml::Value::as_str) == Some(binding))
        .collect::<Vec<_>>();
    if matches.len() == 1 {
        Ok(matches[0])
    } else {
        Err(CliError::Input(
            "Wrangler config D1 binding is missing or ambiguous".to_owned(),
        ))
    }
}

fn d1_entry_mut<'a>(config: &'a mut toml::Value, binding: &str) -> Result<&'a mut toml::Value> {
    let databases = config
        .get_mut("d1_databases")
        .and_then(toml::Value::as_array_mut)
        .ok_or_else(|| CliError::Input("Wrangler config has no D1 databases".to_owned()))?;
    let matching = databases
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.get("binding").and_then(toml::Value::as_str) == Some(binding))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if matching.len() == 1 {
        Ok(&mut databases[matching[0]])
    } else {
        Err(CliError::Input(
            "Wrangler config D1 binding is missing or ambiguous".to_owned(),
        ))
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "the recovery proof is valid only when target, catalog, profile, account, credential generation, freshness bound, and observation time are evaluated together"
)]
pub(super) fn fresh_recovery_proof(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    input: &CallInput,
    profile_id: &str,
    account_id: &str,
    generation: &str,
    max_age_seconds: u64,
    now: chrono::DateTime<Utc>,
) -> Result<Value> {
    let database_id = input
        .selectors
        .get("database_id")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("workspace D1 migration requires database_id".to_owned()))?;
    let bookmark_input = CallInput {
        selectors: json!({"account_id": account_id, "database_id": database_id}),
        query: json!({}),
        ..CallInput::default()
    };
    let input_hash = hash_value(&serde_json::to_value(bookmark_input)?)?;
    let floor = now - ChronoDuration::seconds(i64::try_from(max_age_seconds).unwrap_or(i64::MAX));
    let matches = store
        .list_operational_proofs()?
        .into_iter()
        .filter(|proof| {
            proof.capability_id == "d1-time-travel-get-bookmark"
                && proof.catalog_hash == catalog.schema_hash
                && proof.input_hash == input_hash
                && proof.profile_id.as_deref() == Some(profile_id)
                && proof.account_id.as_deref() == Some(account_id)
                && proof.credential_generation_id.as_deref() == Some(generation)
                && proof.outcome == OperationalProofOutcomeV1::Succeeded
                && proof.observed_at >= floor
                && proof.observed_at < now
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(CliError::Input(
            "workspace D1 migration requires exactly one fresh successful time-travel bookmark proof bound to the target, catalog, profile, account, and credential generation"
                .to_owned(),
        ));
    }
    let proof = &matches[0];
    let evidence = store.read_evidence_value(&proof.evidence.content_hash)?;
    let bookmark = evidence
        .pointer("/result/bookmark")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input("recovery evidence omitted the exact bookmark".to_owned())
        })?;
    if evidence.get("status").and_then(Value::as_u64) != Some(200)
        || evidence.get("success").and_then(Value::as_bool) != Some(true)
    {
        return Err(CliError::Input(
            "recovery evidence does not prove a successful bookmark read".to_owned(),
        ));
    }
    Ok(json!({
        "capability_id": proof.capability_id,
        "observed_at": proof.observed_at,
        "evidence_hash": proof.evidence.content_hash,
        "bookmark": bookmark,
        "bookmark_hash": hash_value(&Value::String(bookmark.to_owned()))?,
        "catalog_hash": proof.catalog_hash,
        "input_hash": proof.input_hash,
        "profile_id": profile_id,
        "account_id": account_id,
        "credential_generation_id": generation,
    }))
}

pub(super) fn validate_recovery_target(
    store: &StateStore,
    target: &Map<String, Value>,
    catalog_hash: &str,
    max_age_seconds: u64,
    now: chrono::DateTime<Utc>,
) -> Result<()> {
    let recovery = validate_recovery_target_identity(store, target, catalog_hash, now)?;
    let observed_at = recovery
        .get("observed_at")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("workspace D1 recovery time is missing".to_owned()))?
        .parse::<chrono::DateTime<Utc>>()
        .map_err(|_| CliError::Input("workspace D1 recovery time is invalid".to_owned()))?;
    let age = now.signed_duration_since(observed_at);
    if age > ChronoDuration::seconds(i64::try_from(max_age_seconds).unwrap_or(i64::MAX)) {
        return Err(CliError::Input(
            "workspace D1 recovery bookmark is no longer fresh; create a new plan".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn validate_recovery_target_identity<'a>(
    store: &StateStore,
    target: &'a Map<String, Value>,
    catalog_hash: &str,
    now: chrono::DateTime<Utc>,
) -> Result<&'a Map<String, Value>> {
    let recovery = target
        .get("recovery")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CliError::Input("workspace D1 plan omitted recovery authority".to_owned())
        })?;
    let observed_at = recovery
        .get("observed_at")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("workspace D1 recovery time is missing".to_owned()))?
        .parse::<chrono::DateTime<Utc>>()
        .map_err(|_| CliError::Input("workspace D1 recovery time is invalid".to_owned()))?;
    if now.signed_duration_since(observed_at) < ChronoDuration::zero() {
        return Err(CliError::Input(
            "workspace D1 recovery bookmark observation is in the future".to_owned(),
        ));
    }
    let evidence_hash = recovery_string(recovery, "evidence_hash")?;
    require_target_string(recovery, "catalog_hash", catalog_hash)?;
    require_target_string(recovery, "profile_id", target_string(target, "profile_id")?)?;
    require_target_string(recovery, "account_id", target_string(target, "account_id")?)?;
    require_target_string(
        recovery,
        "credential_generation_id",
        target_string(target, "credential_generation_id")?,
    )?;
    let evidence = store.read_evidence_value(evidence_hash)?;
    let bookmark = evidence
        .pointer("/result/bookmark")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("recovery evidence omitted bookmark readback".to_owned()))?;
    require_target_string(recovery, "bookmark", bookmark)?;
    require_target_string(
        recovery,
        "bookmark_hash",
        &hash_value(&Value::String(bookmark.to_owned()))?,
    )?;
    Ok(recovery)
}

fn target(plan: &PlanV1) -> Result<&Map<String, Value>> {
    plan.targets
        .get("adapter")
        .and_then(|value| value.get(TARGET_KEY))
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CliError::Input("workspace D1 migration plan omitted adapter authority".to_owned())
        })
}

fn target_string<'a>(target: &'a Map<String, Value>, field: &str) -> Result<&'a str> {
    target
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CliError::Input(format!("workspace D1 target omitted {field}")))
}

fn recovery_string<'a>(target: &'a Map<String, Value>, field: &str) -> Result<&'a str> {
    target_string(target, field)
}

fn require_target_string(target: &Map<String, Value>, field: &str, expected: &str) -> Result<()> {
    if target_string(target, field)? == expected {
        Ok(())
    } else {
        Err(CliError::Input(format!(
            "workspace D1 target {field} drifted; create a new plan"
        )))
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "both immutable config identities must remain explicit alongside the fixed ledger query authority and subprocess boundary inputs"
)]
async fn read_ledger(
    database: &str,
    config: &str,
    root: &Path,
    credential: &AuthCredential,
    account_id: &str,
    cache_dir: &Path,
    expected_config_sha256: Option<&str>,
    expected_template_sha256: Option<&str>,
) -> Result<Vec<String>> {
    let existence = execute_json_query_with_expected_config(
        database,
        config,
        "SELECT COUNT(*) AS present FROM sqlite_schema WHERE type = 'table' AND name = 'd1_migrations'",
        root,
        credential,
        account_id,
        cache_dir,
        expected_config_sha256,
        expected_template_sha256,
    )
    .await?;
    let present = existence
        .first()
        .and_then(|row| row.get("present"))
        .and_then(Value::as_i64)
        == Some(1);
    if !present {
        return Ok(Vec::new());
    }
    let rows = execute_json_query_with_expected_config(
        database,
        config,
        "SELECT name FROM d1_migrations ORDER BY id",
        root,
        credential,
        account_id,
        cache_dir,
        expected_config_sha256,
        expected_template_sha256,
    )
    .await?;
    rows.into_iter()
        .map(|row| {
            row.get("name")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| CliError::Input("Wrangler ledger row omitted name".to_owned()))
        })
        .collect()
}

#[expect(
    clippy::too_many_arguments,
    reason = "the two immutable config identities are boundary inputs alongside the fixed query authority"
)]
pub(super) async fn execute_json_query_with_config_identity(
    database: &str,
    config: &str,
    sql: &str,
    root: &Path,
    credential: &AuthCredential,
    account_id: &str,
    cache_dir: &Path,
    expected_config_sha256: &str,
    expected_template_sha256: &str,
) -> Result<Vec<Map<String, Value>>> {
    execute_json_query_with_expected_config(
        database,
        config,
        sql,
        root,
        credential,
        account_id,
        cache_dir,
        Some(expected_config_sha256),
        Some(expected_template_sha256),
    )
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "the exact config content identity is a security-boundary input alongside the fixed query authority"
)]
async fn execute_json_query_with_expected_config(
    database: &str,
    config: &str,
    sql: &str,
    root: &Path,
    credential: &AuthCredential,
    account_id: &str,
    cache_dir: &Path,
    expected_config_sha256: Option<&str>,
    expected_template_sha256: Option<&str>,
) -> Result<Vec<Map<String, Value>>> {
    let arguments = [
        "d1".to_owned(),
        "execute".to_owned(),
        database.to_owned(),
        "--remote".to_owned(),
        "--config".to_owned(),
        config.to_owned(),
        "--command".to_owned(),
        sql.to_owned(),
        "--json".to_owned(),
    ];
    let output = run_wrangler_with_expected_config(
        &arguments,
        root,
        credential,
        account_id,
        cache_dir,
        QUERY_TIMEOUT,
        expected_config_sha256,
        expected_template_sha256,
    )
    .await?;
    if output.success {
        return parse_query_rows(&output.stdout);
    }
    let failure = QueryFailureDiagnostic::from(&output);
    Err(CliError::Input(format!(
        "fixed Wrangler D1 readback failed (exit_status={}, stdout_hash={}, stderr_hash={})",
        failure.exit_status, failure.stdout_hash, failure.stderr_hash
    )))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QueryFailureDiagnostic {
    exit_status: String,
    stdout_hash: String,
    stderr_hash: String,
}

impl From<&WranglerOutput> for QueryFailureDiagnostic {
    fn from(output: &WranglerOutput) -> Self {
        Self {
            exit_status: output
                .exit_status
                .map_or_else(|| "signal".to_owned(), |status| status.to_string()),
            stdout_hash: sha256(output.stdout.as_bytes()),
            stderr_hash: sha256(output.stderr.as_bytes()),
        }
    }
}

#[derive(Debug)]
pub(super) struct WranglerOutput {
    pub(super) success: bool,
    pub(super) exit_status: Option<i32>,
    pub(super) stdout: String,
    pub(super) stderr: String,
    pub(super) provider_output_retained: bool,
    pub(super) private_config_sha256: Option<String>,
}

pub(super) async fn run_wrangler(
    arguments: &[String],
    root: &Path,
    credential: &AuthCredential,
    account_id: &str,
    cache_dir: &Path,
    timeout: Duration,
) -> Result<WranglerOutput> {
    run_wrangler_with_expected_config(
        arguments, root, credential, account_id, cache_dir, timeout, None, None,
    )
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "the two immutable config identities are boundary inputs, not ambient subprocess state"
)]
pub(super) async fn run_wrangler_with_config_identity(
    arguments: &[String],
    root: &Path,
    credential: &AuthCredential,
    account_id: &str,
    cache_dir: &Path,
    timeout: Duration,
    expected_config_sha256: &str,
    expected_template_sha256: &str,
) -> Result<WranglerOutput> {
    run_wrangler_with_expected_config(
        arguments,
        root,
        credential,
        account_id,
        cache_dir,
        timeout,
        Some(expected_config_sha256),
        Some(expected_template_sha256),
    )
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "the immutable config identity is a boundary input, not ambient subprocess state"
)]
async fn run_wrangler_with_expected_config(
    arguments: &[String],
    root: &Path,
    credential: &AuthCredential,
    account_id: &str,
    cache_dir: &Path,
    timeout: Duration,
    expected_config_sha256: Option<&str>,
    expected_template_sha256: Option<&str>,
) -> Result<WranglerOutput> {
    run_wrangler_program(
        Path::new("wrangler"),
        arguments,
        root,
        credential,
        account_id,
        cache_dir,
        timeout,
        expected_config_sha256,
        expected_template_sha256,
    )
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "the test seam retains both immutable config identities at the subprocess boundary"
)]
async fn run_wrangler_program(
    program: &Path,
    arguments: &[String],
    root: &Path,
    credential: &AuthCredential,
    account_id: &str,
    cache_dir: &Path,
    timeout: Duration,
    expected_config_sha256: Option<&str>,
    expected_template_sha256: Option<&str>,
) -> Result<WranglerOutput> {
    let mut execution_arguments = arguments.to_vec();
    let private_config = bind_private_config_from_arguments(
        &mut execution_arguments,
        expected_config_sha256,
        expected_template_sha256,
    )?;
    let token = credential.bearer_token().ok_or_else(|| {
        CliError::Input(
            "workspace D1 migrations require a scoped API-token profile; global-key execution is forbidden"
                .to_owned(),
        )
    })?;
    let mut command = processkit::Command::new(program)
        .args(&execution_arguments)
        .current_dir(root)
        .env_clear()
        .env("PATH", env::var_os("PATH").unwrap_or_default())
        .env("HOME", env::var_os("HOME").unwrap_or_default())
        .env("NO_COLOR", "1")
        .env("CLOUDFLARE_API_TOKEN", token)
        .stdin(processkit::Stdin::empty())
        .timeout(timeout);
    for (name, value) in governed_cli_workspace_env("wrangler", Some(account_id), cache_dir) {
        command = command.env(name, value);
    }
    let running = command
        .start()
        .await
        .map_err(|_| CliError::SubprocessNotStarted {
            label: "workspace D1 migration Wrangler".to_owned(),
        })?;
    let output =
        running
            .output_bytes()
            .await
            .map_err(|_| CliError::SubprocessReceiptUnavailable {
                label: "workspace D1 migration Wrangler".to_owned(),
            })?;
    if output.timed_out() {
        return Err(CliError::SubprocessTimeout {
            label: "workspace D1 migration Wrangler".to_owned(),
            timeout_seconds: timeout.as_secs(),
        });
    }
    if let Some(private_config) = private_config {
        let (success, stdout) = if output.is_success()
            && execution_arguments
                .iter()
                .any(|argument| argument == "--json")
        {
            match project_private_json_query_with_guard(
                output.stdout(),
                &execution_arguments,
                &private_config,
            ) {
                Ok(projected) => (true, projected),
                Err(()) => (false, String::new()),
            }
        } else {
            (output.is_success(), String::new())
        };
        return Ok(WranglerOutput {
            success,
            exit_status: output.code(),
            stdout,
            stderr: String::new(),
            provider_output_retained: false,
            private_config_sha256: Some(private_config.content_sha256().to_owned()),
        });
    }
    Ok(WranglerOutput {
        success: output.is_success(),
        exit_status: output.code(),
        stdout: redact_subprocess_text(&String::from_utf8_lossy(output.stdout()), credential),
        stderr: redact_subprocess_text(output.stderr(), credential),
        provider_output_retained: true,
        private_config_sha256: None,
    })
}

fn bind_private_config_from_arguments(
    arguments: &mut [String],
    expected_config_sha256: Option<&str>,
    expected_template_sha256: Option<&str>,
) -> Result<Option<worker_deployment::BoundPrivateConfig>> {
    if arguments
        .iter()
        .any(|argument| argument.starts_with("--config="))
    {
        return Err(CliError::Input(
            "workspace D1 Wrangler arguments must bind config as one exact --config path pair"
                .to_owned(),
        ));
    }
    let positions = arguments
        .windows(2)
        .enumerate()
        .filter_map(|(index, pair)| (pair[0] == "--config").then_some(index + 1))
        .collect::<Vec<_>>();
    if positions.is_empty() {
        return Ok(None);
    }
    if positions.len() != 1
        || arguments
            .last()
            .is_some_and(|argument| argument == "--config")
    {
        return Err(CliError::Input(
            "workspace D1 Wrangler arguments require exactly one complete --config path pair"
                .to_owned(),
        ));
    }
    let position = positions[0];
    let config = Path::new(&arguments[position]);
    let template = if config.file_name().and_then(std::ffi::OsStr::to_str)
        == Some("wrangler.production.toml")
    {
        config.with_file_name("wrangler.toml")
    } else {
        worker_deployment::private_config_template_path(config).ok_or_else(|| {
            CliError::Input(
                "workspace D1 closed operation contract requires a private production config"
                    .to_owned(),
            )
        })?
    };
    let bound = Some(
        worker_deployment::bind_private_config_path_with_template_for_execution(
            config,
            &template,
            expected_config_sha256,
            expected_template_sha256,
        )?,
    );
    if let Some(bound) = &bound {
        arguments[position] = bound.path().display().to_string();
    }
    Ok(bound)
}

#[cfg(test)]
fn project_private_json_query(
    stdout: &[u8],
    arguments: &[String],
) -> std::result::Result<String, ()> {
    project_private_json_query_inner(stdout, arguments, None)
}

fn project_private_json_query_with_guard(
    stdout: &[u8],
    arguments: &[String],
    private_config: &worker_deployment::BoundPrivateConfig,
) -> std::result::Result<String, ()> {
    project_private_json_query_inner(stdout, arguments, Some(private_config))
}

fn project_private_json_query_inner(
    stdout: &[u8],
    arguments: &[String],
    private_config: Option<&worker_deployment::BoundPrivateConfig>,
) -> std::result::Result<String, ()> {
    let text = std::str::from_utf8(stdout).map_err(|_| ())?;
    let sql = arguments
        .windows(2)
        .filter_map(|pair| (pair[0] == "--command").then_some(pair[1].as_str()))
        .collect::<Vec<_>>();
    if sql.len() != 1 {
        return Err(());
    }
    let rows = parse_query_rows(text).map_err(|_| ())?;
    project_migration_query_rows(sql[0], &rows)
        .or_else(|| workspace_d1_evidence::project_private_query_rows(sql[0], &rows))
        .or_else(|| workspace_d1_projection::project_private_query_rows(sql[0], &rows))
        .or_else(|| workspace_d1_reply_admission::project_private_query_rows(sql[0], &rows))
        .ok_or(())?
        .map_err(|_| ())?;
    if private_config.is_some_and(|private_config| {
        private_config.retained_rows_contain_private_representation(&rows)
    }) {
        return Err(());
    }
    serde_json::to_string(&json!([{"success": true, "results": rows}])).map_err(|_| ())
}

#[expect(
    clippy::case_sensitive_file_extension_comparisons,
    reason = "migration ledger names intentionally require the canonical lowercase .sql suffix; case-insensitive matching would widen the closed private query schema"
)]
fn project_migration_query_rows(sql: &str, rows: &[Map<String, Value>]) -> Option<Result<()>> {
    if sql.starts_with("SELECT COUNT(*) AS present FROM sqlite_schema ") {
        return Some((|| {
            if rows.len() != 1 || !exact_query_fields(&rows[0], &["present"]) {
                return Err(private_query_shape_error());
            }
            if !matches!(rows[0].get("present").and_then(Value::as_i64), Some(0 | 1)) {
                return Err(private_query_value_error());
            }
            Ok(())
        })());
    }
    if sql.starts_with("SELECT name FROM ") && sql.ends_with(" ORDER BY id") {
        return Some((|| {
            if rows.len() > 1_024 {
                return Err(private_query_shape_error());
            }
            for row in rows {
                if !exact_query_fields(row, &["name"])
                    || row.get("name").and_then(Value::as_str).is_none_or(|name| {
                        name.is_empty()
                            || name.len() > 255
                            || !name.ends_with(".sql")
                            || name.starts_with('.')
                            || name.bytes().any(|byte| {
                                !(byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
                            })
                    })
                {
                    return Err(private_query_value_error());
                }
            }
            Ok(())
        })());
    }
    if sql.starts_with("WITH assertions(assertion, passed) AS (VALUES ")
        && sql.ends_with(") SELECT assertion, passed FROM assertions")
    {
        return Some((|| {
            if rows.len() > 1_024 {
                return Err(private_query_shape_error());
            }
            for (index, row) in rows.iter().enumerate() {
                if !exact_query_fields(row, &["assertion", "passed"])
                    || row.get("assertion").and_then(Value::as_str)
                        != Some(format!("assertion_{index}").as_str())
                    || !matches!(row.get("passed").and_then(Value::as_i64), Some(0 | 1))
                {
                    return Err(private_query_value_error());
                }
            }
            Ok(())
        })());
    }
    None
}

fn exact_query_fields(row: &Map<String, Value>, fields: &[&str]) -> bool {
    row.len() == fields.len() && fields.iter().all(|field| row.contains_key(*field))
}

fn private_query_shape_error() -> CliError {
    CliError::Input("private D1 readback was outside its closed query schema".to_owned())
}

fn private_query_value_error() -> CliError {
    CliError::Input("private D1 readback contained an invalid typed value".to_owned())
}

pub(super) fn parse_query_rows(stdout: &str) -> Result<Vec<Map<String, Value>>> {
    let value: Value = serde_json::from_str(stdout.trim())
        .map_err(|error| CliError::Input(format!("Wrangler D1 readback was not JSON: {error}")))?;
    let envelopes = value
        .as_array()
        .ok_or_else(|| CliError::Input("Wrangler D1 readback was not an array".to_owned()))?;
    let mut rows = Vec::new();
    for envelope in envelopes {
        if envelope.get("success").and_then(Value::as_bool) != Some(true) {
            return Err(CliError::Input(
                "Wrangler D1 readback reported an unsuccessful query".to_owned(),
            ));
        }
        let results = envelope
            .get("results")
            .and_then(Value::as_array)
            .ok_or_else(|| CliError::Input("Wrangler D1 readback omitted results".to_owned()))?;
        for row in results {
            rows.push(
                row.as_object().cloned().ok_or_else(|| {
                    CliError::Input("Wrangler D1 result row is invalid".to_owned())
                })?,
            );
        }
    }
    Ok(rows)
}

fn declared_migration_names(
    contract: &cfctl_core::WorkspaceD1MigrationContractV1,
) -> Result<Vec<String>> {
    contract
        .migrations
        .iter()
        .map(|migration| {
            Path::new(&migration.path)
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| {
                    CliError::Input("declared migration path has no filename".to_owned())
                })
        })
        .collect()
}

fn is_prefix(observed: &[String], declared: &[String]) -> bool {
    observed.len() <= declared.len()
        && observed
            .iter()
            .zip(declared)
            .all(|(left, right)| left == right)
}

fn compile_assertion_sql(
    assertions: &[cfctl_core::WorkspaceD1SchemaAssertionV1],
) -> Result<String> {
    let mut values = Vec::new();
    for (index, assertion) in assertions.iter().enumerate() {
        let key = format!("assertion_{index}");
        let predicate = match assertion.kind.as_str() {
            "table_exists" => format!(
                "EXISTS (SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = '{}')",
                identifier(assertion.table.as_deref())?
            ),
            "column_exists" => format!(
                "EXISTS (SELECT 1 FROM pragma_table_info('{}') WHERE name = '{}')",
                identifier(assertion.table.as_deref())?,
                identifier(assertion.column.as_deref())?
            ),
            "index_exists" => format!(
                "EXISTS (SELECT 1 FROM sqlite_schema WHERE type = 'index' AND tbl_name = '{}' AND name = '{}')",
                identifier(assertion.table.as_deref())?,
                identifier(assertion.index.as_deref())?
            ),
            "foreign_key_check_empty" => {
                "NOT EXISTS (SELECT 1 FROM pragma_foreign_key_check)".to_owned()
            }
            _ => {
                return Err(CliError::Input(
                    "workspace D1 contract contains an unsupported schema assertion".to_owned(),
                ));
            }
        };
        values.push(format!("('{key}', CAST({predicate} AS INTEGER))"));
    }
    Ok(format!(
        "WITH assertions(assertion, passed) AS (VALUES {}) SELECT assertion, passed FROM assertions",
        values.join(", ")
    ))
}

fn identifier(value: Option<&str>) -> Result<&str> {
    value
        .filter(|value| {
            (1..=128).contains(&value.len())
                && value
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        })
        .ok_or_else(|| CliError::Input("workspace D1 assertion identifier is invalid".to_owned()))
}

pub(super) fn parse_wrangler_version(stdout: &str) -> Result<String> {
    stdout
        .split_whitespace()
        .find(|part| {
            let components = part.split('.').collect::<Vec<_>>();
            components.len() == 3
                && components.iter().all(|component| {
                    !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
                })
        })
        .map(str::to_owned)
        .ok_or_else(|| CliError::Input("Wrangler version output was invalid".to_owned()))
}

fn canonical_uuid(value: &str) -> bool {
    value != "00000000-0000-0000-0000-000000000000"
        && uuid::Uuid::parse_str(value).is_ok_and(|parsed| parsed.hyphenated().to_string() == value)
}

fn safe_name(value: &str) -> bool {
    (1..=63).contains(&value.len())
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value
            .bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

pub(super) fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests;
