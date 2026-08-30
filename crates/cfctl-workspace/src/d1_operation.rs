use std::{
    collections::BTreeSet,
    fs,
    path::{Component, Path, PathBuf},
};

use cfctl_core::{
    AdapterStatus, BillingModelV1, CapabilityAuthorityScopeV1, CapabilityV1, CostExposureV1,
    CostV1, EffectClass, EntitlementV1, KnowledgeReferenceV1, Maturity, RiskClass, RollbackSpecV1,
    SelectorV1, VerificationSpecV1, WorkspaceD1MigrationContractV1, WorkspaceD1MigrationFileV1,
    WorkspaceD1SchemaAssertionV1,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::{RegisteredRoot, Result, WorkspaceError, WorkspaceGraph, git_blob, git_optional};

const PACK_RELATIVE_PATH: &str = ".cfctl/operations/d1-migrations.toml";
const PACK_SCHEMA_VERSION: u8 = 1;

#[derive(Debug, Deserialize)]
struct OperationPack {
    operation: Vec<OperationDeclaration>,
}

#[derive(Debug, Deserialize)]
struct OperationPackIndex {
    schema_version: u8,
    operation: Vec<OperationIdentity>,
}

#[derive(Debug, Deserialize)]
struct OperationIdentity {
    id: String,
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

/// Loads one uniquely named D1 migration capability from clean repositories
/// under explicitly registered roots. An absent operation returns `None`;
/// duplicate ids, dirty repositories, symlinks, untracked pack inputs, and
/// hash drift all fail closed.
pub fn load_workspace_d1_migration_capability(
    roots: &[PathBuf],
    capability_id: &str,
) -> Result<Option<CapabilityV1>> {
    let registered = roots
        .iter()
        .map(|path| RegisteredRoot::new(path))
        .collect::<Vec<_>>();
    let graph = WorkspaceGraph::discover(&registered)?;
    let mut matches = Vec::new();
    for repository in &graph.repositories {
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
    let pack_path = repository.path.join(PACK_RELATIVE_PATH);
    if !pack_path.is_file() {
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
    let index: OperationPackIndex = toml::from_str(pack_text)
        .map_err(|error| invariant(format!("workspace operation pack is invalid: {error}")))?;
    let duplicate_ids = index
        .operation
        .iter()
        .map(|operation| operation.id.as_str())
        .collect::<BTreeSet<_>>()
        .len()
        != index.operation.len();
    if duplicate_ids {
        return Err(invariant("workspace operation pack contains duplicate ids"));
    }
    if index.schema_version == 2 {
        if index
            .operation
            .iter()
            .all(|operation| operation.id != capability_id)
        {
            return Ok(None);
        }
        return Err(invariant(
            "workspace operation pack schema version is unsupported",
        ));
    }
    if index.schema_version != PACK_SCHEMA_VERSION {
        return Err(invariant(
            "workspace operation pack schema version is unsupported",
        ));
    }
    let pack: OperationPack = toml::from_str(pack_text)
        .map_err(|error| invariant(format!("workspace operation pack is invalid: {error}")))?;
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
    };
    Ok(Some(capability(operation, contract)))
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
            }
            "column_exists" => {
                assertion.table.as_deref().is_some_and(safe_identifier)
                    && assertion.column.as_deref().is_some_and(safe_identifier)
                    && assertion.index.is_none()
            }
            "index_exists" => {
                assertion.table.as_deref().is_some_and(safe_identifier)
                    && assertion.index.as_deref().is_some_and(safe_identifier)
                    && assertion.column.is_none()
            }
            "foreign_key_check_empty" => {
                assertion.table.is_none() && assertion.column.is_none() && assertion.index.is_none()
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
    fn schema_v2_pack_is_irrelevant_to_an_unrelated_intent_but_matching_ids_stay_unsupported() {
        let root = fixture();
        fs::write(
            root.path().join(PACK_RELATIVE_PATH),
            r#"schema_version = 2

[[operation]]
id = "mln-web.founder-d1-migration-apply"
title = "Future manifest operation"
manifest_path = ".control-plane/d1_migration_manifest.json"
"#,
        )
        .expect("schema-v2 pack");
        git(root.path(), &["add", "."]);
        git(root.path(), &["commit", "-qm", "schema-v2 fixture"]);

        assert!(
            load_workspace_d1_migration_capability(
                &[root.path().to_path_buf()],
                "deploy JKCA workers",
            )
            .expect("unrelated intent is not blocked")
            .is_none()
        );
        let error = load_workspace_d1_migration_capability(
            &[root.path().to_path_buf()],
            "mln-web.founder-d1-migration-apply",
        )
        .expect_err("matching schema-v2 capability remains unsupported");
        assert!(error.to_string().contains("schema version is unsupported"));
    }

    #[test]
    fn schema_v2_duplicate_ids_still_fail_closed_for_unrelated_intents() {
        let root = fixture();
        fs::write(
            root.path().join(PACK_RELATIVE_PATH),
            r#"schema_version = 2

[[operation]]
id = "mln-web.founder-d1-migration-apply"

[[operation]]
id = "mln-web.founder-d1-migration-apply"
"#,
        )
        .expect("duplicate schema-v2 pack");
        git(root.path(), &["add", "."]);
        git(
            root.path(),
            &["commit", "-qm", "duplicate schema-v2 fixture"],
        );

        let error = load_workspace_d1_migration_capability(
            &[root.path().to_path_buf()],
            "deploy JKCA workers",
        )
        .expect_err("duplicate authority is never ignored");
        assert!(error.to_string().contains("duplicate ids"));
    }

    #[test]
    fn non_v1_non_v2_schema_versions_stay_fail_closed_for_unrelated_intents() {
        for schema_version in [0, 3] {
            let root = fixture();
            fs::write(
                root.path().join(PACK_RELATIVE_PATH),
                format!(
                    r#"schema_version = {schema_version}

[[operation]]
id = "mln-web.founder-d1-migration-apply"
"#,
                ),
            )
            .expect("unsupported-version pack");
            git(root.path(), &["add", "."]);
            git(
                root.path(),
                &["commit", "-qm", "unsupported-version fixture"],
            );

            let error = load_workspace_d1_migration_capability(
                &[root.path().to_path_buf()],
                "deploy JKCA workers",
            )
            .expect_err("only schema v2 has the unrelated-intent exception");
            assert!(error.to_string().contains("schema version is unsupported"));
        }
    }
}
