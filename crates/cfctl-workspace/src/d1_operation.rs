mod transition;

use std::{
    collections::BTreeSet,
    fs,
    path::{Component, Path, PathBuf},
};

use cfctl_core::{
    AdapterStatus, BillingModelV1, CapabilityAuthorityScopeV1, CapabilityV1, CostExposureV1,
    CostV1, EffectClass, EntitlementV1, KnowledgeReferenceV1, Maturity, RiskClass, RollbackSpecV1,
    SelectorV1, VerificationSpecV1, WorkspaceD1ExactObjectAssertionV1,
    WorkspaceD1ManifestMigrationContractV1, WorkspaceD1MigrationContractV1,
    WorkspaceD1MigrationFileV1, WorkspaceD1MigrationLedgerEntryV1, WorkspaceD1SchemaAssertionV1,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::{Result, WorkspaceError, git_blob, git_optional};

const PACK_RELATIVE_PATH: &str = ".cfctl/operations/d1-migrations.toml";
const PACK_SCHEMA_VERSION: u8 = 1;

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
    migrations_dir: String,
    database_binding: String,
    wrangler_version: String,
    recovery_capability_id: String,
    recovery_max_age_seconds: u64,
    rollback_capability_id: String,
    migration: Vec<MigrationDeclaration>,
    assertion: Vec<WorkspaceD1SchemaAssertionV1>,
}

#[derive(Debug, Deserialize)]
struct MigrationDeclaration {
    path: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct OperationPackV2 {
    schema_version: u8,
    operation: Vec<OperationDeclarationV2>,
}

#[derive(Debug, Deserialize)]
struct OperationDeclarationV2 {
    id: String,
    title: String,
    description: String,
    authority: String,
    manifest_path: String,
    config_template: String,
    account_id: String,
    profile_id: String,
    database_name: String,
    database_id: String,
    database_binding: String,
    baseline_start_sequence: u64,
    baseline_end_sequence: u64,
    target_sequence: u64,
    migrations_dir: String,
    migrations_pattern: String,
    ledger_table: String,
    ledger_name: String,
    wrangler_version: String,
    wrangler_cli_sha256: String,
    recovery: RecoveryDeclarationV2,
    atomicity: AtomicityDeclarationV2,
    verification: VerificationDeclarationV2,
}

#[derive(Debug, Deserialize)]
struct RecoveryDeclarationV2 {
    full_export_capability_id: String,
    bookmark_capability_id: String,
    rollback_capability_id: String,
    requires_fresh_full_export: bool,
    requires_fresh_bookmark: bool,
    existing_anchor_reusable: bool,
}

#[derive(Debug, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
struct AtomicityDeclarationV2 {
    local_ddl_failure_zero_schema_delta: bool,
    local_ddl_failure_zero_ledger_delta: bool,
    local_ledger_failure_zero_schema_delta: bool,
    local_ledger_failure_zero_ledger_delta: bool,
    remote_ddl_failure_zero_schema_delta: bool,
    remote_ddl_failure_zero_ledger_delta: bool,
    remote_ledger_failure_zero_schema_delta: bool,
    remote_ledger_failure_zero_ledger_delta: bool,
}

#[derive(Debug, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
struct VerificationDeclarationV2 {
    require_exact_post_ledger: bool,
    forbidden_future_sequences: Vec<u64>,
    require_exact_schema_sql: bool,
    require_foreign_key_check_empty: bool,
    require_integrity_check_ok: bool,
    require_unchanged_worker_identity: bool,
    require_old_worker_compatibility: bool,
}

#[derive(Debug, Deserialize)]
struct MigrationManifestV1 {
    manifest_version: u8,
    migrations: Vec<MigrationManifestEntryV1>,
}

#[derive(Debug, Deserialize)]
struct MigrationManifestEntryV1 {
    sequence: u64,
    file: String,
    sha256: String,
    predecessor: Option<String>,
    production_applied: bool,
}

/// Loads one uniquely named D1 migration capability from clean repositories
/// under explicitly registered roots. An absent operation returns `None`;
/// duplicate ids, dirty repositories, symlinks, untracked pack inputs, and
/// hash drift all fail closed.
pub fn load_workspace_d1_migration_capability(
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
            "workspace operation id `{capability_id}` is ambiguous across {count} registered repositories"
        ))),
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one loader binds clean Git authority, closed migration inputs, config identity, and recovery semantics without a partially validated intermediate"
)]
fn load_from_repository(
    repository: &super::RepositoryNode,
    capability_id: &str,
) -> Result<Option<CapabilityV1>> {
    if !super::operation_identity::contains(&repository.path, PACK_RELATIVE_PATH, capability_id)? {
        return Ok(None);
    }
    if repository.git.dirty {
        return Err(invariant(format!(
            "workspace operation repository `{}` must be clean",
            repository.path.display()
        )));
    }
    let head = repository
        .git
        .head
        .as_deref()
        .filter(|value| is_lower_hex(value, 40))
        .ok_or_else(|| invariant("workspace operation repository has no canonical HEAD"))?;
    let origin = git_optional(&repository.path, &["config", "--get", "remote.origin.url"])?
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invariant("workspace operation repository has no origin"))?;
    let pack_bytes = committed_file(&repository.path, Path::new(PACK_RELATIVE_PATH))?;
    let pack_text = std::str::from_utf8(&pack_bytes)
        .map_err(|_| invariant("workspace operation pack is not UTF-8"))?;
    let pack_value: toml::Value = toml::from_str(pack_text)
        .map_err(|error| invariant(format!("workspace operation pack is invalid: {error}")))?;
    if pack_value
        .get("schema_version")
        .and_then(toml::Value::as_integer)
        == Some(3)
    {
        return transition::load(
            repository,
            capability_id,
            head,
            origin,
            &pack_bytes,
            pack_text,
        );
    }
    if pack_value
        .get("schema_version")
        .and_then(toml::Value::as_integer)
        == Some(2)
    {
        let pack: OperationPackV2 = toml::from_str(pack_text)
            .map_err(|error| invariant(format!("workspace operation pack is invalid: {error}")))?;
        return load_manifest_operation(repository, capability_id, head, origin, &pack_bytes, pack);
    }
    let pack: OperationPack = toml::from_str(pack_text)
        .map_err(|error| invariant(format!("workspace operation pack is invalid: {error}")))?;
    if pack.schema_version != PACK_SCHEMA_VERSION {
        return Err(invariant(
            "workspace operation pack schema version is unsupported",
        ));
    }
    let duplicate_ids = pack
        .operation
        .iter()
        .map(|operation| operation.id.as_str())
        .collect::<BTreeSet<_>>()
        .len()
        != pack.operation.len();
    if duplicate_ids {
        return Err(invariant("workspace operation pack contains duplicate ids"));
    }
    let Some(operation) = pack
        .operation
        .iter()
        .find(|operation| operation.id == capability_id)
    else {
        return Ok(None);
    };
    validate_operation(operation)?;

    let template_relative = safe_relative(&operation.config_template)?;
    let template = committed_file(&repository.path, &template_relative)?;
    let migration_dir = safe_relative(&operation.migrations_dir)?;
    let production_config = safe_relative(&operation.production_config)?;
    validate_closed_migration_directory(&repository.path, &migration_dir, &operation.migration)?;
    let mut migrations = Vec::new();
    let mut prior_path: Option<&str> = None;
    for migration in &operation.migration {
        if prior_path.is_some_and(|prior| prior >= migration.path.as_str()) {
            return Err(invariant(
                "workspace D1 migration paths must be unique and strictly ordered",
            ));
        }
        prior_path = Some(&migration.path);
        let relative = safe_relative(&migration.path)?;
        if relative.parent() != Some(migration_dir.as_path())
            || relative.extension().and_then(std::ffi::OsStr::to_str) != Some("sql")
        {
            return Err(invariant(
                "workspace D1 migrations must be direct .sql children of migrations_dir",
            ));
        }
        let bytes = committed_file(&repository.path, &relative)?;
        let observed = sha256(&bytes);
        if migration.sha256 != observed || !is_sha256(&migration.sha256) {
            return Err(invariant(format!(
                "workspace D1 migration `{}` does not match its declared SHA-256",
                migration.path
            )));
        }
        migrations.push(WorkspaceD1MigrationFileV1 {
            path: migration.path.clone(),
            sha256: migration.sha256.clone(),
        });
    }

    let contract = WorkspaceD1MigrationContractV1 {
        repository_root: repository.path.display().to_string(),
        repository_head: head.to_owned(),
        repository_origin: origin,
        operation_pack_path: PACK_RELATIVE_PATH.to_owned(),
        operation_pack_sha256: sha256(&pack_bytes),
        config_template_path: operation.config_template.clone(),
        config_template_sha256: sha256(&template),
        production_config_path: production_config.display().to_string(),
        migrations_dir: migration_dir.display().to_string(),
        database_binding: operation.database_binding.clone(),
        wrangler_version: operation.wrangler_version.clone(),
        migrations,
        assertions: operation.assertion.clone(),
        recovery_capability_id: operation.recovery_capability_id.clone(),
        recovery_max_age_seconds: operation.recovery_max_age_seconds,
        rollback_capability_id: operation.rollback_capability_id.clone(),
        transition: None,
        manifest_migration: None,
    };
    Ok(Some(capability(operation, contract)))
}

#[expect(
    clippy::too_many_lines,
    reason = "the v2 loader atomically binds manifest, baseline, sole target, pinned Wrangler, recovery, and verification authority"
)]
fn load_manifest_operation(
    repository: &super::RepositoryNode,
    capability_id: &str,
    head: &str,
    origin: String,
    pack_bytes: &[u8],
    pack: OperationPackV2,
) -> Result<Option<CapabilityV1>> {
    if pack.schema_version != 2 {
        return Err(invariant(
            "workspace operation pack schema version is unsupported",
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
        return Err(invariant("workspace operation pack contains duplicate ids"));
    }
    let Some(operation) = pack
        .operation
        .iter()
        .find(|operation| operation.id == capability_id)
    else {
        return Ok(None);
    };
    validate_manifest_operation(operation)?;

    let manifest_relative = safe_relative(&operation.manifest_path)?;
    let manifest_bytes = committed_file(&repository.path, &manifest_relative)?;
    let manifest: MigrationManifestV1 = serde_json::from_slice(&manifest_bytes)
        .map_err(|_| invariant("workspace D1 migration manifest is invalid"))?;
    if manifest.manifest_version != 1 {
        return Err(invariant(
            "workspace D1 migration manifest version is unsupported",
        ));
    }
    let unique_sequences = manifest
        .migrations
        .iter()
        .map(|entry| entry.sequence)
        .collect::<BTreeSet<_>>();
    let unique_names = manifest
        .migrations
        .iter()
        .map(|entry| entry.file.as_str())
        .collect::<BTreeSet<_>>();
    let pending = manifest
        .migrations
        .iter()
        .filter(|entry| !entry.production_applied)
        .collect::<Vec<_>>();
    let governed = manifest
        .migrations
        .iter()
        .filter(|entry| entry.sequence >= operation.baseline_start_sequence)
        .collect::<Vec<_>>();
    let mut pending_seen = false;
    for (index, entry) in governed.iter().enumerate() {
        let expected_sequence = checked_sequence_offset(
            operation.baseline_start_sequence,
            index,
            "manifest succession",
        )?;
        let expected_predecessor = index
            .checked_sub(1)
            .and_then(|previous| governed.get(previous))
            .map(|previous| previous.file.as_str());
        if entry.sequence != expected_sequence
            || !valid_migration_name(&entry.file)
            || !is_lower_hex(&entry.sha256, 64)
            || (index > 0 && entry.predecessor.as_deref() != expected_predecessor)
            || (pending_seen && entry.production_applied)
        {
            return Err(invariant(
                "workspace D1 manifest must be one contiguous applied prefix followed by one contiguous deferred suffix",
            ));
        }
        pending_seen |= !entry.production_applied;
    }
    if unique_sequences.len() != manifest.migrations.len()
        || unique_names.len() != manifest.migrations.len()
        || pending.is_empty()
        || pending[0].sequence != operation.target_sequence
        || pending[0].file != operation.ledger_name
    {
        return Err(invariant(
            "workspace D1 manifest must contain unique identities and select the first deferred migration as its sole immediate target",
        ));
    }
    let baseline = manifest
        .migrations
        .iter()
        .filter(|entry| {
            (operation.baseline_start_sequence..=operation.baseline_end_sequence)
                .contains(&entry.sequence)
        })
        .collect::<Vec<_>>();
    let expected_len = operation
        .baseline_end_sequence
        .checked_sub(operation.baseline_start_sequence)
        .and_then(|distance| distance.checked_add(1))
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(|| invariant("workspace D1 baseline range is invalid"))?;
    if baseline.len() != expected_len || !(1..=64).contains(&baseline.len()) {
        return Err(invariant(
            "workspace D1 manifest does not contain the exact bounded baseline",
        ));
    }
    for (offset, entry) in baseline.iter().enumerate() {
        let expected_sequence =
            checked_sequence_offset(operation.baseline_start_sequence, offset, "baseline")?;
        if entry.sequence != expected_sequence
            || !valid_migration_name(&entry.file)
            || !is_lower_hex(&entry.sha256, 64)
            || !entry.production_applied
            || (offset > 0
                && entry.predecessor.as_deref() != Some(baseline[offset - 1].file.as_str()))
        {
            return Err(invariant(
                "workspace D1 manifest baseline identity is invalid",
            ));
        }
    }
    let target = manifest
        .migrations
        .iter()
        .find(|entry| entry.sequence == operation.target_sequence)
        .ok_or_else(|| invariant("workspace D1 manifest omitted the sole target"))?;
    let migrations_dir = safe_relative(&operation.migrations_dir)?;
    let target_path = safe_relative(&operation.migrations_pattern)?;
    if target.file != operation.ledger_name
        || target.predecessor.as_deref() != baseline.last().map(|entry| entry.file.as_str())
        || target.production_applied
        || target_path.parent() != Some(migrations_dir.as_path())
        || target_path.file_name().and_then(std::ffi::OsStr::to_str) != Some(target.file.as_str())
        || !is_lower_hex(&target.sha256, 64)
    {
        return Err(invariant(
            "workspace D1 manifest target identity is invalid",
        ));
    }
    for entry in &pending {
        let relative = migrations_dir.join(&entry.file);
        let bytes = committed_file(&repository.path, &relative)?;
        if sha256(&bytes) != format!("sha256:{}", entry.sha256) {
            return Err(invariant(format!(
                "workspace D1 deferred migration `{}` differs from its committed manifest identity",
                entry.file
            )));
        }
    }
    let target_bytes = committed_file(&repository.path, &target_path)?;
    let target_blob_spec = format!("HEAD:{}", target_path.to_string_lossy());
    let target_git_blob_oid = git_optional(
        &repository.path,
        &["rev-parse", "--verify", &target_blob_spec],
    )?
    .filter(|value| is_lower_hex(value, 40))
    .ok_or_else(|| invariant("workspace D1 target has no canonical Git blob identity"))?;
    if sha256(&target_bytes) != format!("sha256:{}", target.sha256) {
        return Err(invariant(
            "workspace D1 target bytes differ from the manifest",
        ));
    }
    if target_bytes.contains(&b'\r') || !target_bytes.ends_with(b"\n") {
        return Err(invariant(
            "workspace D1 target must be exact LF text ending in a newline",
        ));
    }
    let assertions = derive_manifest_schema_assertions(&target_bytes)?;
    let template_relative = safe_relative(&operation.config_template)?;
    let template = committed_file(&repository.path, &template_relative)?;
    let production_config = template_relative.with_file_name("wrangler.production.toml");
    let baseline_names = baseline
        .iter()
        .map(|entry| entry.file.as_str())
        .collect::<Vec<_>>();
    let baseline_digest = sha256(format!("{}\n", baseline_names.join("\n")).as_bytes());
    let baseline = baseline
        .into_iter()
        .map(|entry| WorkspaceD1MigrationLedgerEntryV1 {
            sequence: entry.sequence,
            name: entry.file.clone(),
            sha256: format!("sha256:{}", entry.sha256),
        })
        .collect::<Vec<_>>();
    let manifest_contract = WorkspaceD1ManifestMigrationContractV1 {
        manifest_path: operation.manifest_path.clone(),
        manifest_sha256: sha256(&manifest_bytes),
        account_id: operation.account_id.clone(),
        profile_id: operation.profile_id.clone(),
        database_name: operation.database_name.clone(),
        database_id: operation.database_id.clone(),
        baseline_start_sequence: operation.baseline_start_sequence,
        baseline_end_sequence: operation.baseline_end_sequence,
        baseline,
        baseline_digest,
        target_sequence: operation.target_sequence,
        target_git_blob_oid,
        migrations_pattern: operation.migrations_pattern.clone(),
        ledger_table: operation.ledger_table.clone(),
        ledger_name: operation.ledger_name.clone(),
        wrangler_cli_sha256: format!("sha256:{}", operation.wrangler_cli_sha256),
        full_export_capability_id: operation.recovery.full_export_capability_id.clone(),
        require_exact_post_ledger: operation.verification.require_exact_post_ledger,
        forbidden_future_sequences: operation.verification.forbidden_future_sequences.clone(),
        require_exact_schema_sql: operation.verification.require_exact_schema_sql,
        require_foreign_key_check_empty: operation.verification.require_foreign_key_check_empty,
        require_integrity_check_ok: operation.verification.require_integrity_check_ok,
        require_unchanged_worker_identity: operation.verification.require_unchanged_worker_identity,
        require_old_worker_compatibility: operation.verification.require_old_worker_compatibility,
    };
    let contract = WorkspaceD1MigrationContractV1 {
        repository_root: repository.path.display().to_string(),
        repository_head: head.to_owned(),
        repository_origin: origin,
        operation_pack_path: PACK_RELATIVE_PATH.to_owned(),
        operation_pack_sha256: sha256(pack_bytes),
        config_template_path: operation.config_template.clone(),
        config_template_sha256: sha256(&template),
        production_config_path: production_config.display().to_string(),
        migrations_dir: operation.migrations_dir.clone(),
        database_binding: operation.database_binding.clone(),
        wrangler_version: operation.wrangler_version.clone(),
        migrations: vec![WorkspaceD1MigrationFileV1 {
            path: operation.migrations_pattern.clone(),
            sha256: format!("sha256:{}", target.sha256),
        }],
        assertions,
        recovery_capability_id: operation.recovery.bookmark_capability_id.clone(),
        recovery_max_age_seconds: 600,
        rollback_capability_id: operation.recovery.rollback_capability_id.clone(),
        transition: None,
        manifest_migration: Some(manifest_contract),
    };
    Ok(Some(capability_manifest(operation, contract)))
}

fn validate_manifest_operation(operation: &OperationDeclarationV2) -> Result<()> {
    let atomicity = &operation.atomicity;
    let expected_target_sequence = checked_target_sequence(operation.baseline_end_sequence)?;
    if !valid_operation_id(&operation.id)
        || operation.title.trim().is_empty()
        || operation.description.trim().is_empty()
        || operation.authority != "cfctl_native_workspace_operation"
        || !safe_identifier(&operation.database_binding)
        || !safe_identifier(&operation.ledger_table)
        || !valid_migration_name(&operation.ledger_name)
        || !valid_wrangler_version(&operation.wrangler_version)
        || !is_lower_hex(&operation.wrangler_cli_sha256, 64)
        || operation.baseline_start_sequence == 0
        || operation.baseline_end_sequence < operation.baseline_start_sequence
        || operation.target_sequence != expected_target_sequence
        || operation.recovery.full_export_capability_id != "d1-full-export"
        || operation.recovery.bookmark_capability_id != "d1-time-travel-get-bookmark"
        || operation.recovery.rollback_capability_id != "d1-restore-exact-bookmark"
        || !operation.recovery.requires_fresh_full_export
        || !operation.recovery.requires_fresh_bookmark
        || operation.recovery.existing_anchor_reusable
        || ![
            atomicity.local_ddl_failure_zero_schema_delta,
            atomicity.local_ddl_failure_zero_ledger_delta,
            atomicity.local_ledger_failure_zero_schema_delta,
            atomicity.local_ledger_failure_zero_ledger_delta,
            atomicity.remote_ddl_failure_zero_schema_delta,
            atomicity.remote_ddl_failure_zero_ledger_delta,
            atomicity.remote_ledger_failure_zero_schema_delta,
            atomicity.remote_ledger_failure_zero_ledger_delta,
        ]
        .into_iter()
        .all(std::convert::identity)
        || !operation.verification.require_exact_post_ledger
        || !operation.verification.require_exact_schema_sql
        || !operation.verification.require_foreign_key_check_empty
        || !operation.verification.require_integrity_check_ok
        || !operation.verification.require_unchanged_worker_identity
        || !operation.verification.require_old_worker_compatibility
    {
        return Err(invariant(
            "workspace D1 manifest operation contract is invalid",
        ));
    }
    Ok(())
}

fn checked_sequence_offset(start: u64, offset: usize, context: &str) -> Result<u64> {
    let offset = u64::try_from(offset)
        .map_err(|_| invariant(format!("workspace D1 {context} offset is too large")))?;
    start
        .checked_add(offset)
        .ok_or_else(|| invariant(format!("workspace D1 {context} sequence overflows u64")))
}

fn checked_target_sequence(baseline_end: u64) -> Result<u64> {
    baseline_end
        .checked_add(1)
        .ok_or_else(|| invariant("workspace D1 manifest target sequence overflows u64"))
}

#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn valid_migration_name(value: &str) -> bool {
    (5..=128).contains(&value.len())
        && value.ends_with(".sql")
        && !value.starts_with('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn derive_manifest_schema_assertions(bytes: &[u8]) -> Result<Vec<WorkspaceD1SchemaAssertionV1>> {
    let source = std::str::from_utf8(bytes)
        .map_err(|_| invariant("workspace D1 target migration is not UTF-8"))?;
    let statements = exact_migration_statements(source)?;
    let mut assertions = Vec::new();
    let mut seen: BTreeSet<(String, String, String)> = BTreeSet::new();
    for statement in &statements {
        let tokens = statement.split_whitespace().collect::<Vec<_>>();
        if tokens.len() >= 6 && tokens[..2] == ["ALTER", "TABLE"] {
            let table = tokens[2];
            let column = if tokens.get(3..5) == Some(&["ADD", "COLUMN"])
                || tokens.get(3..5) == Some(&["RENAME", "COLUMN"])
            {
                if tokens[3] == "ADD" {
                    tokens.get(5).copied()
                } else {
                    tokens
                        .iter()
                        .position(|token| *token == "TO")
                        .and_then(|position| tokens.get(position + 1).copied())
                }
            } else {
                None
            };
            if let Some(column) = column {
                let column = column.trim_end_matches(';');
                if safe_identifier(table)
                    && safe_identifier(column)
                    && seen.insert(("column".to_owned(), table.to_owned(), column.to_owned()))
                {
                    assertions.push(WorkspaceD1SchemaAssertionV1 {
                        kind: "column_exists".to_owned(),
                        table: Some(table.to_owned()),
                        column: Some(column.to_owned()),
                        index: None,
                        exact_object: None,
                    });
                }
            }
        }
        let exact = exact_object_from_statement(statement, &tokens)?;
        if let Some(exact) = exact {
            let table = exact.table.clone().unwrap_or_default();
            if seen.insert((exact.object_type.clone(), table, exact.name.clone())) {
                assertions.push(WorkspaceD1SchemaAssertionV1 {
                    kind: "object_definition_equals".to_owned(),
                    table: None,
                    column: None,
                    index: None,
                    exact_object: Some(exact),
                });
            }
        }
    }
    assertions.push(WorkspaceD1SchemaAssertionV1 {
        kind: "foreign_key_check_empty".to_owned(),
        table: None,
        column: None,
        index: None,
        exact_object: None,
    });
    if assertions.len() == 1 {
        return Err(invariant(
            "workspace D1 target yielded no compiler-owned schema assertions",
        ));
    }
    Ok(assertions)
}

fn exact_migration_statements(source: &str) -> Result<Vec<String>> {
    let mut statements = Vec::new();
    let mut current = String::new();
    let mut trigger = false;
    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || (current.is_empty() && trimmed.starts_with("--")) {
            continue;
        }
        if current.is_empty() {
            current.push_str(trimmed);
        } else {
            current.push('\n');
            current.push_str(line.trim_end());
        }
        if current.lines().count() == 1 {
            trigger = trimmed.starts_with("CREATE TRIGGER ");
        }
        let terminal = if trigger {
            trimmed == "END;"
        } else {
            trimmed.ends_with(';')
        };
        if terminal {
            let definition = current
                .strip_suffix(';')
                .unwrap_or(&current)
                .trim()
                .to_owned();
            if definition.is_empty() {
                return Err(invariant(
                    "workspace D1 migration contains an empty statement",
                ));
            }
            statements.push(definition);
            current.clear();
            trigger = false;
        }
    }
    if !current.trim().is_empty() {
        return Err(invariant(
            "workspace D1 migration contains an unterminated statement or trigger",
        ));
    }
    Ok(statements)
}

fn exact_object_from_statement(
    definition: &str,
    tokens: &[&str],
) -> Result<Option<WorkspaceD1ExactObjectAssertionV1>> {
    let (object_type, name) = match tokens {
        ["CREATE", "INDEX", name, ..] | ["CREATE", "UNIQUE", "INDEX", name, ..] => ("index", *name),
        ["CREATE", "TRIGGER", name, ..] => ("trigger", *name),
        _ => return Ok(None),
    };
    let table = tokens
        .windows(2)
        .find_map(|pair| (pair[0] == "ON").then(|| pair[1].split('(').next().unwrap_or_default()))
        .ok_or_else(|| invariant("workspace D1 exact schema object omitted its table"))?;
    if !safe_identifier(name) || !safe_identifier(table) || definition.len() > 32_768 {
        return Err(invariant(
            "workspace D1 exact schema object identity or definition is invalid",
        ));
    }
    Ok(Some(WorkspaceD1ExactObjectAssertionV1 {
        object_type: object_type.to_owned(),
        name: name.to_owned(),
        table: Some(table.to_owned()),
        definition: definition.to_owned(),
        definition_sha256: sha256(definition.as_bytes()),
    }))
}

fn capability_manifest(
    operation: &OperationDeclarationV2,
    contract: WorkspaceD1MigrationContractV1,
) -> CapabilityV1 {
    let compatibility = OperationDeclaration {
        id: operation.id.clone(),
        title: operation.title.clone(),
        description: operation.description.clone(),
        config_template: operation.config_template.clone(),
        production_config: operation.config_template.clone(),
        migrations_dir: operation.migrations_dir.clone(),
        database_binding: operation.database_binding.clone(),
        wrangler_version: operation.wrangler_version.clone(),
        recovery_capability_id: operation.recovery.bookmark_capability_id.clone(),
        recovery_max_age_seconds: 600,
        rollback_capability_id: operation.recovery.rollback_capability_id.clone(),
        migration: Vec::new(),
        assertion: Vec::new(),
    };
    let mut capability = capability(&compatibility, contract);
    capability.selectors = vec![
        selector("account_id", "path"),
        selector("database_id", "path"),
        selector("migration", "query"),
        selector("atomicity_evidence_hash", "query"),
        selector("old_worker_canary_evidence_hash", "query"),
    ];
    capability
}

fn validate_closed_migration_directory(
    repository: &Path,
    migration_dir: &Path,
    declarations: &[MigrationDeclaration],
) -> Result<()> {
    reject_symlinks(repository, migration_dir)?;
    let directory = repository.join(migration_dir);
    let metadata =
        fs::symlink_metadata(&directory).map_err(|source| super::io_error(&directory, source))?;
    if !metadata.file_type().is_dir() {
        return Err(invariant(
            "workspace D1 migrations_dir must be a real directory",
        ));
    }
    let declared = declarations
        .iter()
        .map(|migration| safe_relative(&migration.path))
        .collect::<Result<BTreeSet<_>>>()?;
    let mut observed = BTreeSet::new();
    for entry in fs::read_dir(&directory).map_err(|source| super::io_error(&directory, source))? {
        let entry = entry.map_err(|source| super::io_error(&directory, source))?;
        let entry_path = entry.path();
        let entry_metadata = fs::symlink_metadata(&entry_path)
            .map_err(|source| super::io_error(&entry_path, source))?;
        if !entry_metadata.file_type().is_file() || entry_metadata.file_type().is_symlink() {
            return Err(invariant(
                "workspace D1 migrations_dir contains a non-file or symlink entry",
            ));
        }
        let relative = entry_path
            .strip_prefix(repository)
            .map_err(|_| invariant("workspace D1 migration entry escaped its repository"))?
            .to_path_buf();
        observed.insert(relative);
    }
    if observed != declared {
        return Err(invariant(
            "workspace D1 migrations_dir must contain exactly the declared migration files",
        ));
    }
    Ok(())
}

fn validate_operation(operation: &OperationDeclaration) -> Result<()> {
    if !valid_operation_id(&operation.id)
        || operation.title.trim().is_empty()
        || operation.description.trim().is_empty()
        || operation.migration.is_empty()
        || operation.assertion.is_empty()
        || !safe_identifier(&operation.database_binding)
        || !valid_wrangler_version(&operation.wrangler_version)
        || operation.recovery_capability_id != "d1-time-travel-get-bookmark"
        || operation.recovery_max_age_seconds == 0
        || operation.recovery_max_age_seconds > 600
        || operation.rollback_capability_id != "d1-restore-exact-bookmark"
    {
        return Err(invariant(
            "workspace D1 migration identity, recovery, or closed declaration is invalid",
        ));
    }
    for assertion in &operation.assertion {
        let valid = match assertion.kind.as_str() {
            "table_exists" => {
                assertion.table.as_deref().is_some_and(safe_identifier)
                    && assertion.column.is_none()
                    && assertion.index.is_none()
                    && assertion.exact_object.is_none()
            }
            "column_exists" => {
                assertion.table.as_deref().is_some_and(safe_identifier)
                    && assertion.column.as_deref().is_some_and(safe_identifier)
                    && assertion.index.is_none()
                    && assertion.exact_object.is_none()
            }
            "index_exists" => {
                assertion.table.as_deref().is_some_and(safe_identifier)
                    && assertion.index.as_deref().is_some_and(safe_identifier)
                    && assertion.column.is_none()
                    && assertion.exact_object.is_none()
            }
            "foreign_key_check_empty" => {
                assertion.table.is_none()
                    && assertion.column.is_none()
                    && assertion.index.is_none()
                    && assertion.exact_object.is_none()
            }
            _ => false,
        };
        if !valid {
            return Err(invariant(
                "workspace D1 migration contains an unsupported or malformed schema assertion",
            ));
        }
    }
    Ok(())
}

fn capability(
    operation: &OperationDeclaration,
    contract: WorkspaceD1MigrationContractV1,
) -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        &operation.id,
        &operation.title,
        "POST",
        "wrangler d1 migrations apply",
    );
    capability.description = Some(operation.description.clone());
    capability.authority_scope = Some(CapabilityAuthorityScopeV1::WorkspaceOwned);
    "D1".clone_into(&mut capability.product);
    "workspace-operation-pack-v1".clone_into(&mut capability.source);
    "account".clone_into(&mut capability.account_scope);
    capability.selectors = vec![
        selector("account_id", "path"),
        selector("database_id", "path"),
        selector("config", "query"),
    ];
    capability.permissions = vec!["D1 Read".to_owned(), "D1 Write".to_owned()];
    capability.mutating = true;
    capability.risk = RiskClass::ScopedWrite;
    capability.effect = EffectClass::DataWrite;
    capability.maturity = Maturity::GenerallyAvailable;
    capability.entitlement = EntitlementV1 {
        available: Some(true),
        source: Some(
            "workspace operation requires an existing provider-read D1 database".to_owned(),
        ),
        ..EntitlementV1::default()
    };
    capability.cost = CostV1 {
        incremental: false,
        currency: None,
        maximum: None,
        basis: Some(
            "the operation creates no new billable resource; bounded D1 row writes remain subject to ordinary usage pricing"
                .to_owned(),
        ),
        known: true,
        billing_model: BillingModelV1::UsageBased,
        exposure: CostExposureV1::DownstreamUsage,
        references: vec![KnowledgeReferenceV1 {
            title: "Cloudflare D1 pricing".to_owned(),
            url: "https://developers.cloudflare.com/d1/platform/pricing/".to_owned(),
            source: "cloudflare-docs".to_owned(),
        }],
    };
    capability.verification = VerificationSpecV1 {
        required: true,
        strategy: "workspace_d1_migration_ledger_and_schema_assertions".to_owned(),
    };
    capability.rollback = RollbackSpecV1 {
        supported: false,
        strategy: None,
        warning: Some(
            "automatic rollback is forbidden; recovery requires a separately approved d1-restore-exact-bookmark plan bound to the fresh pre-migration bookmark"
                .to_owned(),
        ),
    };
    capability.adapter_status = AdapterStatus::DelegatedCli;
    capability.blocked_reason = None;
    capability.workspace_d1_migration = Some(contract);
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
    let worktree = fs::read(repository.join(&relative))
        .map_err(|source| super::io_error(&repository.join(&relative), source))?;
    let committed = git_blob(repository, &relative)?.ok_or_else(|| {
        invariant(format!(
            "workspace operation input `{}` is not tracked at HEAD",
            relative.display()
        ))
    })?;
    if worktree != committed {
        return Err(invariant(format!(
            "workspace operation input `{}` differs from HEAD",
            relative.display()
        )));
    }
    Ok(worktree)
}

fn reject_symlinks(repository: &Path, relative: &Path) -> Result<()> {
    let mut cursor = repository.to_path_buf();
    for component in relative.components() {
        cursor.push(component.as_os_str());
        let metadata =
            fs::symlink_metadata(&cursor).map_err(|source| super::io_error(&cursor, source))?;
        if metadata.file_type().is_symlink() {
            return Err(invariant(format!(
                "workspace operation input `{}` contains a symlink",
                relative.display()
            )));
        }
    }
    Ok(())
}

fn safe_relative(value: &str) -> Result<PathBuf> {
    let path = PathBuf::from(value);
    if value.is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir
                    | Component::CurDir
                    | Component::RootDir
                    | Component::Prefix(_)
            )
        })
    {
        return Err(invariant(
            "workspace operation paths must be normalized and relative",
        ));
    }
    Ok(path)
}

fn valid_operation_id(value: &str) -> bool {
    (3..=128).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')
        })
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
}

fn valid_wrangler_version(value: &str) -> bool {
    let components = value.split('.').collect::<Vec<_>>();
    components.len() == 3
        && components.iter().all(|component| {
            !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn safe_identifier(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_sha256(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|digest| is_lower_hex(digest, 64))
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
    use std::process::Command;

    use tempfile::TempDir;

    use super::*;

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
                "https://example.com/leptos-cf.git",
            ],
        );
        fs::create_dir_all(root.path().join(".cfctl/operations")).expect("pack dir");
        fs::create_dir_all(root.path().join("migrations")).expect("migration dir");
        let migration = b"CREATE TABLE todos(id INTEGER PRIMARY KEY);\n";
        fs::write(root.path().join("migrations/0001_initial.sql"), migration).expect("migration");
        fs::write(
            root.path().join("wrangler.toml"),
            "name = \"template\"\n[[d1_databases]]\nbinding = \"DB\"\ndatabase_name = \"template-db\"\ndatabase_id = \"00000000-0000-0000-0000-000000000000\"\n",
        )
        .expect("config");
        let migration_hash = sha256(migration);
        fs::write(
            root.path().join(PACK_RELATIVE_PATH),
            format!(
                r#"schema_version = 1

[[operation]]
id = "leptos-cf.d1-migrations-apply"
title = "Apply Leptos D1 migrations"
description = "Apply the exact committed migration set."
config_template = "wrangler.toml"
production_config = "wrangler.production.toml"
migrations_dir = "migrations"
database_binding = "DB"
wrangler_version = "4.120.1"
recovery_capability_id = "d1-time-travel-get-bookmark"
recovery_max_age_seconds = 600
rollback_capability_id = "d1-restore-exact-bookmark"

[[operation.migration]]
path = "migrations/0001_initial.sql"
sha256 = "{migration_hash}"

[[operation.assertion]]
kind = "table_exists"
table = "todos"

[[operation.assertion]]
kind = "foreign_key_check_empty"
"#
            ),
        )
        .expect("pack");
        git(root.path(), &["add", "."]);
        git(root.path(), &["commit", "-qm", "fixture"]);
        root
    }

    #[allow(clippy::too_many_lines)]
    fn manifest_fixture() -> TempDir {
        let root = tempfile::tempdir().expect("temp repository");
        git(root.path(), &["init", "-q"]);
        git(root.path(), &["config", "user.email", "test@example.com"]);
        git(root.path(), &["config", "user.name", "Test"]);
        git(
            root.path(),
            &["remote", "add", "origin", "https://example.com/mln-web.git"],
        );
        fs::create_dir_all(root.path().join(".cfctl/operations")).expect("pack dir");
        fs::create_dir_all(root.path().join(".control-plane")).expect("manifest dir");
        fs::create_dir_all(root.path().join("crates/founder/migrations/d1"))
            .expect("migration dir");
        fs::create_dir_all(root.path().join("workers/founder")).expect("config dir");
        let target_name = "0172_offer_authority_provenance.sql";
        let target_path = format!("crates/founder/migrations/d1/{target_name}");
        let target = b"ALTER TABLE existing ADD COLUMN governed INTEGER;\nCREATE TRIGGER governed_guard\nBEFORE INSERT ON existing\nBEGIN\n  SELECT RAISE(ABORT, 'guard');\nEND;\n";
        fs::write(root.path().join(&target_path), target).expect("target");
        fs::write(
            root.path().join("workers/founder/wrangler.toml"),
            "name = \"founder\"\n[[d1_databases]]\nbinding = \"FOUNDER_DB\"\ndatabase_name = \"founder\"\ndatabase_id = \"7c282983-2e48-4ea4-9f0d-09b0d718fe65\"\n",
        )
        .expect("config");
        let mut entries = Vec::new();
        for sequence in 116_u64..=171 {
            let name = format!("{sequence:04}_baseline.sql");
            entries.push(serde_json::json!({
                "sequence": sequence,
                "file": name,
                "sha256": hex::encode(Sha256::digest(format!("baseline-{sequence}"))),
                "predecessor": (sequence > 116).then(|| format!("{:04}_baseline.sql", sequence - 1)),
                "production_applied": true,
            }));
        }
        entries.push(serde_json::json!({
            "sequence": 172,
            "file": target_name,
            "sha256": hex::encode(Sha256::digest(target)),
            "predecessor": "0171_baseline.sql",
            "production_applied": false,
        }));
        fs::write(
            root.path()
                .join(".control-plane/d1_migration_manifest.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "manifest_version": 1,
                "migrations": entries,
            }))
            .expect("manifest JSON"),
        )
        .expect("manifest");
        fs::write(
            root.path().join(PACK_RELATIVE_PATH),
            format!(
                r#"schema_version = 2

[[operation]]
id = "mln-web.founder-d1-migration-apply"
title = "Apply one governed Founder D1 migration"
description = "Apply one exact target after an exact remote baseline."
authority = "cfctl_native_workspace_operation"
manifest_path = ".control-plane/d1_migration_manifest.json"
config_template = "workers/founder/wrangler.toml"
account_id = "ca30e922fda7f5578e49873542e4aaca"
profile_id = "mln-founder-d1"
database_name = "founder"
database_id = "7c282983-2e48-4ea4-9f0d-09b0d718fe65"
database_binding = "FOUNDER_DB"
baseline_start_sequence = 116
baseline_end_sequence = 171
target_sequence = 172
migrations_dir = "crates/founder/migrations/d1"
migrations_pattern = "{target_path}"
ledger_table = "d1_migrations"
ledger_name = "{target_name}"
wrangler_version = "4.100.0"
wrangler_cli_sha256 = "{}"

[operation.recovery]
full_export_capability_id = "d1-full-export"
bookmark_capability_id = "d1-time-travel-get-bookmark"
rollback_capability_id = "d1-restore-exact-bookmark"
requires_fresh_full_export = true
requires_fresh_bookmark = true
existing_anchor_reusable = false

[operation.atomicity]
local_ddl_failure_zero_schema_delta = true
local_ddl_failure_zero_ledger_delta = true
local_ledger_failure_zero_schema_delta = true
local_ledger_failure_zero_ledger_delta = true
remote_ddl_failure_zero_schema_delta = true
remote_ddl_failure_zero_ledger_delta = true
remote_ledger_failure_zero_schema_delta = true
remote_ledger_failure_zero_ledger_delta = true

[operation.verification]
require_exact_post_ledger = true
forbidden_future_sequences = [173, 174]
require_exact_schema_sql = true
require_foreign_key_check_empty = true
require_integrity_check_ok = true
require_unchanged_worker_identity = true
require_old_worker_compatibility = true
"#,
                "a".repeat(64)
            ),
        )
        .expect("pack");
        git(root.path(), &["add", "."]);
        git(root.path(), &["commit", "-qm", "fixture"]);
        root
    }

    #[test]
    fn loads_hash_bound_capability_from_clean_registered_repository() {
        let root = fixture();
        let capability = load_workspace_d1_migration_capability(
            &[root.path().to_path_buf()],
            "leptos-cf.d1-migrations-apply",
        )
        .expect("load")
        .expect("capability");
        assert_eq!(
            capability.authority_scope,
            Some(CapabilityAuthorityScopeV1::WorkspaceOwned)
        );
        assert_eq!(capability.adapter_status, AdapterStatus::DelegatedCli);
        assert!(capability.mutation_contract_gaps().is_empty());
        let contract = capability
            .workspace_d1_migration
            .as_ref()
            .expect("workspace contract");
        assert!(is_lower_hex(&contract.repository_head, 40));
        assert_eq!(contract.migrations.len(), 1);
        assert_eq!(contract.recovery_max_age_seconds, 600);
    }

    #[test]
    fn rejects_dirty_or_hash_drifted_operation_authority() {
        let root = fixture();
        fs::write(
            root.path().join("migrations/0001_initial.sql"),
            "CREATE TABLE drifted(id INTEGER);\n",
        )
        .expect("drift");
        let error = load_workspace_d1_migration_capability(
            &[root.path().to_path_buf()],
            "leptos-cf.d1-migrations-apply",
        )
        .expect_err("dirty repository fails closed");
        assert!(error.to_string().contains("must be clean"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_committed_symlink_inputs() {
        use std::os::unix::fs::symlink;

        let root = fixture();
        fs::write(root.path().join("outside.sql"), "SELECT 1;\n").expect("outside");
        fs::remove_file(root.path().join("migrations/0001_initial.sql")).expect("remove");
        symlink(
            root.path().join("outside.sql"),
            root.path().join("migrations/0001_initial.sql"),
        )
        .expect("symlink");
        git(root.path(), &["add", "."]);
        git(root.path(), &["commit", "-qm", "commit symlink"]);

        let error = load_workspace_d1_migration_capability(
            &[root.path().to_path_buf()],
            "leptos-cf.d1-migrations-apply",
        )
        .expect_err("symlink fails closed");
        assert!(
            error
                .to_string()
                .contains("contains a non-file or symlink entry"),
            "unexpected rejection: {error}"
        );
    }

    #[test]
    fn rejects_ambiguous_ids_across_registered_roots() {
        let first = fixture();
        let second = fixture();
        let error = load_workspace_d1_migration_capability(
            &[first.path().to_path_buf(), second.path().to_path_buf()],
            "leptos-cf.d1-migrations-apply",
        )
        .expect_err("duplicate id fails closed");
        assert!(error.to_string().contains("ambiguous across 2"));
    }

    #[test]
    fn rejects_gitignored_undeclared_migration_files() {
        let root = fixture();
        fs::write(
            root.path().join(".gitignore"),
            "migrations/9999_undeclared.sql\n",
        )
        .expect("ignore");
        git(root.path(), &["add", ".gitignore"]);
        git(
            root.path(),
            &["commit", "-qm", "ignore undeclared migration"],
        );
        fs::write(
            root.path().join("migrations/9999_undeclared.sql"),
            "DROP TABLE todos;\n",
        )
        .expect("ignored migration");

        let error = load_workspace_d1_migration_capability(
            &[root.path().to_path_buf()],
            "leptos-cf.d1-migrations-apply",
        )
        .expect_err("undeclared ignored migration fails closed");
        assert!(
            error
                .to_string()
                .contains("exactly the declared migration files")
        );
    }

    #[test]
    fn loads_manifest_baseline_and_one_target_without_local_baseline_files() {
        let root = manifest_fixture();
        let capability = load_workspace_d1_migration_capability(
            &[root.path().to_path_buf()],
            "mln-web.founder-d1-migration-apply",
        )
        .expect("load")
        .expect("capability");
        assert_eq!(capability.adapter_status, AdapterStatus::DelegatedCli);
        let contract = capability
            .workspace_d1_migration
            .as_ref()
            .expect("workspace contract");
        let manifest = contract
            .manifest_migration
            .as_ref()
            .expect("manifest contract");
        assert_eq!(manifest.baseline.len(), 56);
        assert_eq!(manifest.baseline[0].sequence, 116);
        assert_eq!(manifest.baseline[55].sequence, 171);
        assert_eq!(manifest.target_sequence, 172);
        assert_eq!(manifest.ledger_name, "0172_offer_authority_provenance.sql");
        assert_eq!(contract.migrations.len(), 1);
        let exact_objects = contract
            .assertions
            .iter()
            .filter_map(|assertion| assertion.exact_object.as_ref())
            .collect::<Vec<_>>();
        assert_eq!(exact_objects.len(), 1);
        assert_eq!(exact_objects[0].object_type, "trigger");
        assert_eq!(exact_objects[0].name, "governed_guard");
        assert!(exact_objects[0].definition.contains("SELECT RAISE"));
        assert_eq!(
            exact_objects[0].definition_sha256,
            sha256(exact_objects[0].definition.as_bytes())
        );
        assert_eq!(
            capability
                .selectors
                .iter()
                .map(|selector| selector.name.as_str())
                .collect::<Vec<_>>(),
            [
                "account_id",
                "database_id",
                "migration",
                "atomicity_evidence_hash",
                "old_worker_canary_evidence_hash",
            ]
        );
        assert!(capability.mutation_contract_gaps().is_empty());
    }

    #[test]
    fn selects_only_the_first_migration_from_a_contiguous_deferred_suffix() {
        let root = manifest_fixture();
        let manifest_path = root
            .path()
            .join(".control-plane/d1_migration_manifest.json");
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_path).expect("manifest bytes"))
                .expect("manifest JSON");
        let migrations = manifest["migrations"]
            .as_array_mut()
            .expect("migration array");
        for sequence in 173_u64..=175 {
            let file = format!("{sequence:04}_deferred.sql");
            let predecessor = if sequence == 173 {
                "0172_offer_authority_provenance.sql".to_owned()
            } else {
                format!("{:04}_deferred.sql", sequence - 1)
            };
            let bytes = format!("ALTER TABLE existing ADD COLUMN deferred_{sequence} INTEGER;\n");
            fs::write(
                root.path().join("crates/founder/migrations/d1").join(&file),
                &bytes,
            )
            .expect("deferred migration");
            migrations.push(serde_json::json!({
                "sequence": sequence,
                "file": file,
                "sha256": hex::encode(Sha256::digest(bytes.as_bytes())),
                "predecessor": predecessor,
                "production_applied": false,
            }));
        }
        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).expect("render manifest"),
        )
        .expect("write manifest");
        git(root.path(), &["add", "."]);
        git(root.path(), &["commit", "-qm", "deferred succession"]);

        let capability = load_workspace_d1_migration_capability(
            &[root.path().to_path_buf()],
            "mln-web.founder-d1-migration-apply",
        )
        .expect("load")
        .expect("capability");
        let contract = capability
            .workspace_d1_migration
            .expect("workspace contract");
        let selected = contract.manifest_migration.expect("manifest contract");
        assert_eq!(selected.target_sequence, 172);
        assert_eq!(selected.ledger_name, "0172_offer_authority_provenance.sql");
        assert_eq!(contract.migrations.len(), 1);
        assert_eq!(
            contract.migrations[0].path,
            "crates/founder/migrations/d1/0172_offer_authority_provenance.sql"
        );
    }

    #[test]
    fn manifest_sequence_arithmetic_fails_closed_at_u64_boundaries() {
        assert_eq!(
            checked_sequence_offset(u64::MAX - 1, 1, "test").expect("last sequence"),
            u64::MAX
        );
        assert!(checked_sequence_offset(u64::MAX, 1, "test").is_err());
        assert!(checked_sequence_offset(u64::MAX - 1, 2, "test").is_err());
        assert_eq!(
            checked_target_sequence(u64::MAX - 1).expect("last target"),
            u64::MAX
        );
        assert!(checked_target_sequence(u64::MAX).is_err());
    }

    #[test]
    fn schema_v2_pack_does_not_block_an_unrelated_workspace_intent() {
        let root = manifest_fixture();
        let capability = load_workspace_d1_migration_capability(
            &[root.path().to_path_buf()],
            "deploy JKCA workers",
        )
        .expect("valid schema-v2 pack must not block an unrelated workspace intent");
        assert!(capability.is_none());
    }

    #[test]
    fn manifest_operation_fails_closed_on_target_name_or_lf_drift() {
        let root = manifest_fixture();
        let pack = root.path().join(PACK_RELATIVE_PATH);
        let source = fs::read_to_string(&pack).expect("pack");
        fs::write(
            &pack,
            source.replace(
                "ledger_name = \"0172_offer_authority_provenance.sql\"",
                "ledger_name = \"0172_wrong.sql\"",
            ),
        )
        .expect("drift");
        git(root.path(), &["add", "."]);
        git(root.path(), &["commit", "-qm", "drift"]);
        assert!(
            load_workspace_d1_migration_capability(
                &[root.path().to_path_buf()],
                "mln-web.founder-d1-migration-apply",
            )
            .is_err()
        );
    }

    #[test]
    fn manifest_operation_requires_unique_identities_and_one_pending_target() {
        for mutation in ["duplicate-sequence", "duplicate-name", "second-pending"] {
            let root = manifest_fixture();
            let manifest_path = root
                .path()
                .join(".control-plane/d1_migration_manifest.json");
            let mut manifest: serde_json::Value =
                serde_json::from_slice(&fs::read(&manifest_path).expect("manifest bytes"))
                    .expect("manifest JSON");
            let migrations = manifest["migrations"]
                .as_array_mut()
                .expect("migration array");
            match mutation {
                "duplicate-sequence" => {
                    migrations[1]["sequence"] = migrations[0]["sequence"].clone();
                }
                "duplicate-name" => {
                    migrations[1]["file"] = migrations[0]["file"].clone();
                }
                "second-pending" => {
                    migrations[0]["production_applied"] = serde_json::Value::Bool(false);
                }
                _ => unreachable!("closed fixture mutation"),
            }
            fs::write(
                &manifest_path,
                serde_json::to_vec_pretty(&manifest).expect("render manifest"),
            )
            .expect("write drift");
            git(root.path(), &["add", "."]);
            git(root.path(), &["commit", "-qm", mutation]);
            let error = load_workspace_d1_migration_capability(
                &[root.path().to_path_buf()],
                "mln-web.founder-d1-migration-apply",
            )
            .expect_err("ambiguous manifest identity fails closed");
            assert!(error.to_string().contains("workspace D1 manifest"));
        }
    }

    #[test]
    fn exact_statement_parser_preserves_trigger_bodies_and_fails_closed() {
        let source = "CREATE INDEX idx_users ON users(id);\nCREATE TRIGGER users_guard\nBEFORE INSERT ON users\nBEGIN\n  SELECT RAISE(ABORT, 'guard');\nEND;\n";
        let statements = exact_migration_statements(source).expect("statements");
        assert_eq!(statements.len(), 2);
        assert_eq!(statements[0], "CREATE INDEX idx_users ON users(id)");
        assert_eq!(
            statements[1],
            "CREATE TRIGGER users_guard\nBEFORE INSERT ON users\nBEGIN\n  SELECT RAISE(ABORT, 'guard');\nEND"
        );
        let assertions = derive_manifest_schema_assertions(source.as_bytes()).expect("assertions");
        let exact = assertions
            .iter()
            .filter_map(|assertion| assertion.exact_object.as_ref())
            .collect::<Vec<_>>();
        assert_eq!(
            exact
                .iter()
                .map(|object| object.object_type.as_str())
                .collect::<Vec<_>>(),
            ["index", "trigger"]
        );
        assert!(
            exact_migration_statements(
                "CREATE TRIGGER users_guard BEFORE INSERT ON users BEGIN SELECT 1;"
            )
            .is_err()
        );
    }
}
