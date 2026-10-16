use super::workspace_d1_execution::{
    MigrationSelection, execute_json_query_with_expected_config, parse_wrangler_version,
    run_wrangler, run_wrangler_with_migration_selection,
};
use super::workspace_d1_recovery::{
    fresh_recovery_proof, require_target_string, target_string, validate_recovery_target,
    validate_recovery_target_identity,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use cfctl_core::hash_value;
use chrono::{Duration as ChronoDuration, Utc};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tokio::time::Duration;

use super::{
    prelude::{
        AuthCredential, CallInput, CapabilityV1, CatalogSnapshot, CliError,
        OperationalProofOutcomeV1, PlanV1, ProfileMetadata, Result, StateStore,
    },
    read_execution::credential_generation_for_read,
    support::cli_io,
    workspace_d1_qualification,
};

const TARGET_KEY: &str = "workspace_d1_migration";
const QUERY_TIMEOUT: Duration = Duration::from_mins(2);
const APPLY_TIMEOUT: Duration = Duration::from_mins(5);

fn require_manifest_production_eligibility(
    contract: &cfctl_core::WorkspaceD1MigrationContractV1,
    evidence_joins: Option<&cfctl_core::WorkspaceD1EvidenceJoinsV1>,
) -> Result<()> {
    let Some(manifest) = contract.manifest_migration.as_ref() else {
        return Ok(());
    };
    if !manifest.require_exact_post_ledger
        || !manifest.require_exact_schema_sql
        || !manifest.require_foreign_key_check_empty
        || !manifest.require_integrity_check_ok
        || !manifest.require_unchanged_worker_identity
        || !manifest.require_old_worker_compatibility
    {
        return Err(CliError::Input(
            "workspace D1 manifest production eligibility requires exact post-ledger and schema verification, empty foreign-key checks, a successful integrity check, unchanged Worker identity, and old-Worker compatibility"
                .to_owned(),
        ));
    }
    let joins = evidence_joins.ok_or_else(|| {
        CliError::Input(
            "workspace D1 manifest production eligibility requires provider-isolated atomicity and old-Worker compatibility evidence through six distinct canonical evidence joins"
                .to_owned(),
        )
    })?;
    let hashes = [
        joins.atomicity_qualification_evidence_hash.as_str(),
        joins.old_worker_canary_evidence_hash.as_str(),
        joins.worker_deployments_evidence_hash.as_str(),
        joins.worker_version_evidence_hash.as_str(),
        joins.worker_settings_evidence_hash.as_str(),
        joins.worker_deployment_plan_hash.as_str(),
    ];
    if hashes.iter().any(|hash| !is_canonical_sha256(hash))
        || hashes.into_iter().collect::<BTreeSet<_>>().len() != 6
    {
        return Err(CliError::Input(
            "workspace D1 manifest production eligibility requires six distinct canonical SHA-256 evidence joins"
                .to_owned(),
        ));
    }
    Ok(())
}

fn is_canonical_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

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
    if contract.transition.is_some() {
        return super::workspace_d1_transition::prepare(
            store,
            contract,
            input,
            account_id,
            &profile.id,
            &credential_generation_for_read(profile)?,
            &catalog.schema_hash,
        );
    }
    let config = validated_config(contract, input)?;
    let evidence_joins = contract
        .manifest_migration
        .as_ref()
        .map(|_| workspace_d1_qualification::requested_evidence_joins(store, input))
        .transpose()?;
    require_manifest_production_eligibility(contract, evidence_joins.as_ref())?;
    if let Some(manifest) = &contract.manifest_migration
        && (account_id != manifest.account_id || profile.id != manifest.profile_id)
    {
        return Err(CliError::Input(
            "workspace D1 manifest operation account or profile differs from its closed contract"
                .to_owned(),
        ));
    }
    let generation = credential_generation_for_read(profile)?;
    let mut recovery = fresh_recovery_proof(
        store,
        catalog,
        input,
        &profile.id,
        account_id,
        &generation,
        contract.recovery_max_age_seconds,
        Utc::now(),
    )?;
    if contract.manifest_migration.is_some() {
        recovery
            .as_object_mut()
            .ok_or_else(|| {
                CliError::Input("workspace D1 recovery projection is invalid".to_owned())
            })?
            .insert(
                "full_export".to_owned(),
                fresh_full_export_proof(
                    store,
                    catalog,
                    input,
                    &profile.id,
                    account_id,
                    &generation,
                    contract.recovery_max_age_seconds,
                    Utc::now(),
                )?,
            );
    }
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
        "manifest_path": contract.manifest_migration.as_ref().map(|value| &value.manifest_path),
        "manifest_sha256": contract.manifest_migration.as_ref().map(|value| &value.manifest_sha256),
        "baseline_digest": contract.manifest_migration.as_ref().map(|value| &value.baseline_digest),
        "target_migration": contract.manifest_migration.as_ref().map(|value| &value.ledger_name),
        "target_git_blob_oid": contract.manifest_migration.as_ref().map(|value| &value.target_git_blob_oid),
        "target_sha256": contract.migrations.first().map(|value| &value.sha256),
        "target_path": contract.migrations.first().map(|value| &value.path),
        "wrangler_version": contract.wrangler_version,
        "wrangler_cli_sha256": contract.manifest_migration.as_ref().map(|value| &value.wrangler_cli_sha256),
        "evidence_joins": evidence_joins,
        "recovery": recovery,
    })))
}

pub(super) fn local_artifact_paths(capability: &CapabilityV1) -> Result<Option<Vec<PathBuf>>> {
    let Some(contract) = capability.workspace_d1_migration.as_ref() else {
        return Ok(None);
    };
    let root = Path::new(&contract.repository_root);
    let mut paths = vec![
        root.join(&contract.operation_pack_path)
            .parent()
            .ok_or_else(|| {
                CliError::Input("workspace D1 operation pack has no parent directory".to_owned())
            })?
            .to_path_buf(),
        root.join(&contract.migrations_dir),
    ];
    paths.extend(super::workspace_d1_transition::additional_artifact_paths(
        contract,
    ));
    paths.sort();
    paths.dedup();
    Ok(Some(paths))
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
    if contract.transition.is_some() {
        return super::workspace_d1_transition::validate_bound_plan(store, plan);
    }
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
    let evidence_joins = match target.get("evidence_joins") {
        None | Some(Value::Null) => None,
        Some(value) => Some(
            serde_json::from_value::<cfctl_core::WorkspaceD1EvidenceJoinsV1>(value.clone())
                .map_err(|_| {
                    CliError::Input(
                        "workspace D1 migration evidence joins are malformed; create a new plan"
                            .to_owned(),
                    )
                })?,
        ),
    };
    require_manifest_production_eligibility(contract, evidence_joins.as_ref())?;
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
    if let Some(manifest) = &contract.manifest_migration {
        require_target_string(target, "manifest_path", &manifest.manifest_path)?;
        require_target_string(target, "manifest_sha256", &manifest.manifest_sha256)?;
        require_target_string(target, "baseline_digest", &manifest.baseline_digest)?;
        require_target_string(target, "target_migration", &manifest.ledger_name)?;
        require_target_string(target, "target_git_blob_oid", &manifest.target_git_blob_oid)?;
        require_target_string(target, "wrangler_version", &contract.wrangler_version)?;
        require_target_string(target, "wrangler_cli_sha256", &manifest.wrangler_cli_sha256)?;
        require_target_string(
            target,
            "target_sha256",
            &contract
                .migrations
                .first()
                .ok_or_else(|| CliError::Input("workspace D1 target is missing".to_owned()))?
                .sha256,
        )?;
        require_target_string(
            target,
            "target_path",
            &contract
                .migrations
                .first()
                .ok_or_else(|| CliError::Input("workspace D1 target is missing".to_owned()))?
                .path,
        )?;
        if plan.account_id != manifest.account_id
            || target_string(target, "profile_id")? != manifest.profile_id
            || config.database_name != manifest.database_name
            || config.database_id != manifest.database_id
        {
            return Err(CliError::Input(
                "workspace D1 manifest operation provider identity drifted; create a new plan"
                    .to_owned(),
            ));
        }
        validate_pinned_wrangler(contract)?;
        validate_full_export_target(
            store,
            target,
            &plan.catalog_hash,
            contract.recovery_max_age_seconds,
            Utc::now(),
        )?;
    }
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

#[allow(clippy::too_many_lines)]
pub(super) async fn run(
    store: &StateStore,
    plan: &PlanV1,
    credential: &AuthCredential,
    boundary: &cfctl_core::BoundaryObservation,
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
        &contract.database_binding,
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
    let baseline_matches = if contract.manifest_migration.is_some() {
        before == expected_ledger_before(contract)?
    } else {
        is_prefix(&before, &declared)
    };
    if !baseline_matches {
        return Err(CliError::Input(
            "remote Wrangler migration ledger does not equal the exact planned baseline".to_owned(),
        ));
    }
    if before.len() == declared.len() {
        return Err(CliError::Input(
            "workspace D1 migration has no pending migration; create no write plan".to_owned(),
        ));
    }

    let migration_selection = contract.manifest_migration.as_ref().map(|manifest| {
        let root = Path::new(&contract.repository_root);
        MigrationSelection {
            dir: root.join(&contract.migrations_dir).display().to_string(),
            pattern: root
                .join(&manifest.migrations_pattern)
                .display()
                .to_string(),
            table: manifest.ledger_table.clone(),
        }
    });
    let apply = run_wrangler_with_migration_selection(
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
        Some(&contract.database_binding),
        migration_selection.as_ref(),
        boundary,
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

#[allow(clippy::too_many_lines)]
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
        &contract.database_binding,
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
        Some(&contract.database_binding),
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
    let integrity_rows = if contract
        .manifest_migration
        .as_ref()
        .is_some_and(|manifest| manifest.require_integrity_check_ok)
    {
        execute_json_query_with_expected_config(
            database_name,
            Some(&contract.database_binding),
            config,
            "PRAGMA integrity_check",
            root,
            credential,
            &plan.account_id,
            &store.paths().cache_dir,
            Some(config_sha256),
            Some(&contract.config_template_sha256),
        )
        .await?
    } else {
        Vec::new()
    };
    let integrity_passed = integrity_rows.is_empty()
        || (integrity_rows.len() == 1
            && integrity_rows[0]
                .get("integrity_check")
                .and_then(Value::as_str)
                == Some("ok"));
    let passed = ledger == declared && assertions_passed && integrity_passed;
    if let Some(manifest) = &contract.manifest_migration {
        let qualification_evidence_hashes = [
            workspace_d1_qualification::ATOMICITY_QUALIFICATION_PRECONDITION,
            workspace_d1_qualification::OLD_WORKER_CANARY_PRECONDITION,
            workspace_d1_qualification::WORKER_DEPLOYMENTS_PRECONDITION,
            workspace_d1_qualification::WORKER_VERSION_PRECONDITION,
            workspace_d1_qualification::WORKER_SETTINGS_PRECONDITION,
            workspace_d1_qualification::WORKER_DEPLOYMENT_PLAN_PRECONDITION,
        ]
        .into_iter()
        .map(|name| {
            plan.precondition_hashes
                .get(name)
                .cloned()
                .map(|hash| (name.to_owned(), hash))
                .ok_or_else(|| {
                    CliError::Input(format!(
                        "workspace D1 completion receipt omitted qualification identity `{name}`"
                    ))
                })
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
        return Ok(json!({
            "schema_version": 1,
            "kind": "workspace_d1_migration_completion_v1",
            "passed": passed,
            "operation_id": plan.operation_id,
            "plan_content_hash": plan.content_hash,
            "cfctl_build_identity_hash": hash_value(&serde_json::to_value(crate::build_identity::current_build_info())?)?,
            "repository_head": contract.repository_head,
            "operation_pack_sha256": contract.operation_pack_sha256,
            "manifest_path": manifest.manifest_path,
            "manifest_sha256": manifest.manifest_sha256,
            "account_id": plan.account_id,
            "profile_id": plan.profile_id,
            "database_name": database_name,
            "database_id": manifest.database_id,
            "database_binding": contract.database_binding,
            "wrangler_version": contract.wrangler_version,
            "wrangler_cli_sha256": manifest.wrangler_cli_sha256,
            "target_sequence": manifest.target_sequence,
            "target_name": manifest.ledger_name,
            "target_path": contract.migrations.first().map(|migration| &migration.path),
            "target_git_blob_oid": manifest.target_git_blob_oid,
            "target_sha256": contract.migrations.first().map(|migration| &migration.sha256),
            "post_ledger": ledger,
            "declared_ledger": declared,
            "schema_assertions": assertion_rows,
            "integrity_check": integrity_rows,
            "qualification_evidence_hashes": qualification_evidence_hashes,
            "recovery": target.get("recovery").cloned().unwrap_or(Value::Null),
            "provider_verified": passed,
            "repository_projection_performed": false,
        }));
    }
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
        "integrity_check": integrity_rows,
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

fn validated_config(
    contract: &cfctl_core::WorkspaceD1MigrationContractV1,
    input: &CallInput,
) -> Result<super::workspace_d1_config::ValidatedConfig> {
    let mut selected = input.clone();
    if let Some(manifest) = &contract.manifest_migration {
        if input.query.get("migration").and_then(Value::as_str) != Some(&manifest.ledger_name) {
            return Err(CliError::Input(
                "workspace D1 manifest operation requires its exact sole target migration"
                    .to_owned(),
            ));
        }
        selected.query["config"] =
            json!(Path::new(&contract.repository_root).join(&contract.production_config_path));
    }
    let config = super::workspace_d1_config::validated_config(contract.into(), &selected)?;
    if let Some(manifest) = &contract.manifest_migration
        && (config.database_name != manifest.database_name
            || config.database_id != manifest.database_id)
    {
        return Err(CliError::Input(
            "workspace D1 production identity differs from the manifest operation contract"
                .to_owned(),
        ));
    }
    Ok(config)
}

#[expect(
    clippy::too_many_arguments,
    reason = "the governed export anchor is valid only under the exact target, catalog, profile, credential generation, and freshness window"
)]
fn fresh_full_export_proof(
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
    let export_input = CallInput {
        selectors: json!({"account_id": account_id, "database_id": database_id}),
        query: json!({}),
        ..CallInput::default()
    };
    let input_hash = hash_value(&serde_json::to_value(export_input)?)?;
    let floor = now - ChronoDuration::seconds(i64::try_from(max_age_seconds).unwrap_or(i64::MAX));
    let matches = store
        .list_operational_proofs()?
        .into_iter()
        .filter(|proof| {
            proof.capability_id == "d1-full-export"
                && proof.catalog_hash == catalog.schema_hash
                && proof.input_hash == input_hash
                && proof.profile_id.as_deref() == Some(profile_id)
                && proof.account_id.as_deref() == Some(account_id)
                && proof.credential_generation_id.as_deref() == Some(generation)
                && proof.outcome == OperationalProofOutcomeV1::Succeeded
                && proof.observed_at >= floor
                && proof.observed_at < now
                && proof
                    .d1_full_export_governed_execution()
                    .is_some_and(|binding| {
                        binding.completion_status == "completed"
                            && binding.credential_generation_id == generation
                            && binding.profile_id == profile_id
                            && binding.catalog_hash == catalog.schema_hash
                            && binding.request_hash == input_hash
                    })
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(CliError::Input(
            "workspace D1 manifest migration requires exactly one fresh completed governed full export bound to the target, catalog, profile, and credential generation"
                .to_owned(),
        ));
    }
    let proof = &matches[0];
    let binding = proof
        .d1_full_export_governed_execution()
        .ok_or_else(|| CliError::Input("workspace D1 full export lost its binding".to_owned()))?;
    Ok(json!({
        "capability_id": proof.capability_id,
        "observed_at": proof.observed_at,
        "evidence_hash": proof.evidence.content_hash,
        "output_file_sha256": binding.output_file_sha256,
        "bookmark_hash": binding.at_bookmark_hash,
        "catalog_hash": proof.catalog_hash,
        "input_hash": proof.input_hash,
        "profile_id": profile_id,
        "account_id": account_id,
        "credential_generation_id": generation,
        "completion_status": binding.completion_status,
    }))
}

fn validate_full_export_target(
    store: &StateStore,
    target: &Map<String, Value>,
    catalog_hash: &str,
    max_age_seconds: u64,
    now: chrono::DateTime<Utc>,
) -> Result<()> {
    let export = target
        .get("recovery")
        .and_then(Value::as_object)
        .and_then(|recovery| recovery.get("full_export"))
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CliError::Input("workspace D1 plan omitted its full-export anchor".to_owned())
        })?;
    require_target_string(export, "catalog_hash", catalog_hash)?;
    require_target_string(export, "profile_id", target_string(target, "profile_id")?)?;
    require_target_string(export, "account_id", target_string(target, "account_id")?)?;
    require_target_string(
        export,
        "credential_generation_id",
        target_string(target, "credential_generation_id")?,
    )?;
    require_target_string(export, "completion_status", "completed")?;
    let evidence_hash = target_string(export, "evidence_hash")?;
    let evidence = store.read_evidence_value(evidence_hash)?;
    if evidence
        .pointer("/result/output_file/complete")
        .and_then(Value::as_bool)
        != Some(true)
        || evidence
            .pointer("/result/output_file/hash_matches")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err(CliError::Input(
            "workspace D1 full-export evidence is incomplete".to_owned(),
        ));
    }
    let observed_at = target_string(export, "observed_at")?
        .parse::<chrono::DateTime<Utc>>()
        .map_err(|_| CliError::Input("workspace D1 full-export time is invalid".to_owned()))?;
    if now.signed_duration_since(observed_at)
        > ChronoDuration::seconds(i64::try_from(max_age_seconds).unwrap_or(i64::MAX))
    {
        return Err(CliError::Input(
            "workspace D1 full-export anchor is no longer fresh; create a new plan".to_owned(),
        ));
    }
    Ok(())
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

#[expect(
    clippy::too_many_arguments,
    reason = "both immutable config identities must remain explicit alongside the fixed ledger query authority and subprocess boundary inputs"
)]
async fn read_ledger(
    database: &str,
    database_binding: &str,
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
        Some(database_binding),
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
        Some(database_binding),
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
    clippy::case_sensitive_file_extension_comparisons,
    reason = "migration ledger names intentionally require the canonical lowercase .sql suffix; case-insensitive matching would widen the closed private query schema"
)]
pub(super) fn project_private_query_rows(
    sql: &str,
    rows: &[Map<String, Value>],
) -> Option<Result<()>> {
    if sql == "PRAGMA integrity_check" {
        return Some((|| {
            if rows.len() != 1
                || !exact_query_fields(&rows[0], &["integrity_check"])
                || rows[0].get("integrity_check").and_then(Value::as_str) != Some("ok")
            {
                return Err(private_query_value_error());
            }
            Ok(())
        })());
    }
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

fn declared_migration_names(
    contract: &cfctl_core::WorkspaceD1MigrationContractV1,
) -> Result<Vec<String>> {
    let mut names = contract
        .manifest_migration
        .as_ref()
        .map(|manifest| {
            manifest
                .baseline
                .iter()
                .map(|entry| entry.name.clone())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    names.extend(
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
            .collect::<Result<Vec<_>>>()?,
    );
    Ok(names)
}

fn expected_ledger_before(
    contract: &cfctl_core::WorkspaceD1MigrationContractV1,
) -> Result<Vec<String>> {
    if let Some(manifest) = &contract.manifest_migration {
        return Ok(manifest
            .baseline
            .iter()
            .map(|entry| entry.name.clone())
            .collect());
    }
    let declared = declared_migration_names(contract)?;
    Ok(declared[..declared.len().saturating_sub(1)].to_vec())
}

fn validate_pinned_wrangler(contract: &cfctl_core::WorkspaceD1MigrationContractV1) -> Result<()> {
    let Some(manifest) = &contract.manifest_migration else {
        return Ok(());
    };
    let cli =
        Path::new(&contract.repository_root).join("node_modules/wrangler/wrangler-dist/cli.js");
    let bytes = fs::read(&cli).map_err(|source| cli_io(&cli, source))?;
    if sha256(&bytes) != manifest.wrangler_cli_sha256 {
        return Err(CliError::Input(
            "workspace D1 pinned Wrangler entrypoint hash drifted; create a new plan".to_owned(),
        ));
    }
    let source = std::str::from_utf8(&bytes).map_err(|_| {
        CliError::Input("workspace D1 pinned Wrangler entrypoint is not UTF-8".to_owned())
    })?;
    let migration_read = source
        .find("fs11__namespace.default.readFileSync(\n            `${migrationsPath}/${migration.name}`")
        .ok_or_else(|| CliError::Input("workspace D1 pinned Wrangler migration builder is unsupported".to_owned()))?;
    let ledger_insert = source[migration_read..]
        .find("INSERT INTO ${migrationsConfig.migrationsTableName} (name)")
        .map(|offset| migration_read + offset)
        .ok_or_else(|| {
            CliError::Input("workspace D1 pinned Wrangler ledger builder is unsupported".to_owned())
        })?;
    let submitted_query = source[ledger_insert..]
        .find("command: query")
        .map(|offset| ledger_insert + offset)
        .ok_or_else(|| {
            CliError::Input(
                "workspace D1 pinned Wrangler does not submit one combined migration query"
                    .to_owned(),
            )
        })?;
    if !(migration_read < ledger_insert && ledger_insert < submitted_query) {
        return Err(CliError::Input(
            "workspace D1 pinned Wrangler migration/ledger query ordering is unsupported"
                .to_owned(),
        ));
    }
    Ok(())
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
            "object_definition_equals" => {
                if assertion.table.is_some()
                    || assertion.column.is_some()
                    || assertion.index.is_some()
                {
                    return Err(CliError::Input(
                        "workspace D1 exact-object assertion mixed incompatible fields".to_owned(),
                    ));
                }
                let exact = assertion.exact_object.as_ref().ok_or_else(|| {
                    CliError::Input(
                        "workspace D1 exact-object assertion omitted its definition".to_owned(),
                    )
                })?;
                if !matches!(exact.object_type.as_str(), "index" | "trigger")
                    || identifier(Some(&exact.name)).is_err()
                    || exact
                        .table
                        .as_deref()
                        .is_none_or(|table| identifier(Some(table)).is_err())
                    || sha256(exact.definition.as_bytes()) != exact.definition_sha256
                {
                    return Err(CliError::Input(
                        "workspace D1 exact-object assertion identity or digest is invalid"
                            .to_owned(),
                    ));
                }
                format!(
                    "EXISTS (SELECT 1 FROM sqlite_schema WHERE type = '{}' AND name = '{}' AND tbl_name = '{}' AND sql = '{}')",
                    exact.object_type,
                    exact.name,
                    exact.table.as_deref().unwrap_or_default(),
                    sql_literal(&exact.definition)?,
                )
            }
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

fn sql_literal(value: &str) -> Result<String> {
    if value.is_empty() || value.len() > 32_768 || value.bytes().any(|byte| byte == 0) {
        return Err(CliError::Input(
            "workspace D1 exact schema definition is not a bounded SQL string".to_owned(),
        ));
    }
    Ok(value.replace('\'', "''"))
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

pub(super) fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests;
