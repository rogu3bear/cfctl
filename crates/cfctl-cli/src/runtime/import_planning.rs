use super::import_lineage::exact_durable_provider_complete_boundary;
use super::prelude::{
    CallInput, CapabilityV1, ChronoDuration, CliError, EvidenceClass, Map, Md5, OpenOptions,
    OperationalProofOutcomeV1, OperationalProofV1, Path, PathBuf, PlanStatus, PlanV1, Result,
    Sha256, StateStore, StdCommand, TransactionStageV1, Utc, Uuid, Value, env, json,
};
use super::prelude::{Digest, OpenOptionsExt, PermissionsExt, Read, Write, fs};
use cfctl_cloudflare::validate_reviewed_schema_migration_sql;
use cfctl_core::hash_value;

#[expect(
    clippy::too_many_lines,
    reason = "source identity and managed staging are one fail-closed boundary"
)]
pub(super) fn stage_approved_mln_migration(
    store: &StateStore,
    capability: &CapabilityV1,
    input: &CallInput,
    source: &Path,
) -> Result<Value> {
    if matches!(
        capability.id.as_str(),
        "d1-import-database" | "d1-apply-reviewed-schema-migration"
    ) {
        return stage_reviewed_git_d1_migration(store, capability, input, source);
    }
    let contract = capability
        .d1_approved_mln_import
        .as_ref()
        .ok_or_else(|| CliError::Input("approved MLN import contract is missing".to_owned()))?;
    if !source.is_absolute()
        || source.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(CliError::Input(
            "approved migration source must be an absolute normalized path".to_owned(),
        ));
    }
    let migration_id = input
        .body
        .as_ref()
        .and_then(|body| body.get("migration_id"))
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("approved migration_id is missing".to_owned()))?;
    let approved = contract
        .migrations
        .iter()
        .find(|migration| migration.migration_id == migration_id)
        .ok_or_else(|| CliError::Input("migration_id is not in the closed catalogue".to_owned()))?;
    let source_parent = source
        .parent()
        .ok_or_else(|| CliError::Input("approved migration source has no parent".to_owned()))?;
    let discovered_root = PathBuf::from(git_authority_output(
        source_parent,
        &["rev-parse", "--show-toplevel"],
    )?);
    let canonical_root = fs::canonicalize(&discovered_root).map_err(|source| CliError::Io {
        path: discovered_root.display().to_string(),
        source,
    })?;
    let expected_source = canonical_root.join(&approved.repository_relative_path);
    if source != expected_source {
        return Err(CliError::Input(format!(
            "migration {migration_id} source must be the exact reviewed repository path `{}`",
            expected_source.display()
        )));
    }
    let git_common_dir =
        validate_approved_mln_repository_authority(contract, approved, &canonical_root, None)?;
    let mut cursor = PathBuf::new();
    for component in source.components() {
        cursor.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&cursor).map_err(|source| CliError::Io {
            path: cursor.display().to_string(),
            source,
        })?;
        if metadata.file_type().is_symlink() {
            return Err(CliError::Input(format!(
                "approved migration source has symlink component `{}`",
                cursor.display()
            )));
        }
    }
    let mut source_options = OpenOptions::new();
    source_options.read(true);
    #[cfg(unix)]
    source_options.custom_flags(libc::O_NOFOLLOW);
    let mut source_file = source_options
        .open(source)
        .map_err(|source_error| CliError::Io {
            path: source.display().to_string(),
            source: source_error,
        })?;
    let metadata = source_file
        .metadata()
        .map_err(|source_error| CliError::Io {
            path: source.display().to_string(),
            source: source_error,
        })?;
    if !metadata.is_file() || metadata.len() != approved.bytes {
        return Err(CliError::Input(format!(
            "migration {migration_id} source is not a regular {}-byte file",
            approved.bytes
        )));
    }
    let capacity = usize::try_from(approved.bytes)
        .map_err(|_| CliError::Input("approved migration size exceeds this host".to_owned()))?;
    let mut bytes = Vec::with_capacity(capacity);
    source_file
        .read_to_end(&mut bytes)
        .map_err(|source_error| CliError::Io {
            path: source.display().to_string(),
            source: source_error,
        })?;
    let sha256 = hex::encode(Sha256::digest(&bytes));
    let md5 = hex::encode(Md5::digest(&bytes));
    if sha256 != approved.sha256 || md5 != approved.md5 || bytes.len() as u64 != approved.bytes {
        return Err(CliError::Input(format!(
            "migration {migration_id} source bytes do not match the approved SHA-256/MD5/size catalogue"
        )));
    }
    let stage_dir = store
        .paths()
        .data_dir
        .join("import-stages")
        .join(Uuid::new_v4().to_string());
    fs::create_dir_all(&stage_dir).map_err(|source| CliError::Io {
        path: stage_dir.display().to_string(),
        source,
    })?;
    #[cfg(unix)]
    fs::set_permissions(&stage_dir, fs::Permissions::from_mode(0o700)).map_err(|source| {
        CliError::Io {
            path: stage_dir.display().to_string(),
            source,
        }
    })?;
    let stage_path = stage_dir.join(&approved.basename);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    let mut stage = options.open(&stage_path).map_err(|source| CliError::Io {
        path: stage_path.display().to_string(),
        source,
    })?;
    stage.write_all(&bytes).map_err(|source| CliError::Io {
        path: stage_path.display().to_string(),
        source,
    })?;
    stage.sync_all().map_err(|source| CliError::Io {
        path: stage_path.display().to_string(),
        source,
    })?;
    drop(stage);
    let mut staged_options = OpenOptions::new();
    staged_options.read(true);
    #[cfg(unix)]
    staged_options.custom_flags(libc::O_NOFOLLOW);
    let mut staged_file = staged_options
        .open(&stage_path)
        .map_err(|source| CliError::Io {
            path: stage_path.display().to_string(),
            source,
        })?;
    let staged_metadata = staged_file.metadata().map_err(|source| CliError::Io {
        path: stage_path.display().to_string(),
        source,
    })?;
    if !staged_metadata.is_file() || staged_metadata.len() != approved.bytes {
        return Err(CliError::Input(
            "managed import stage is no longer the reviewed regular file".to_owned(),
        ));
    }
    let mut staged = Vec::with_capacity(capacity);
    staged_file
        .read_to_end(&mut staged)
        .map_err(|source| CliError::Io {
            path: stage_path.display().to_string(),
            source,
        })?;
    let staged_sha256 = hex::encode(Sha256::digest(&staged));
    let staged_md5 = hex::encode(Md5::digest(&staged));
    if staged.len() as u64 != approved.bytes
        || staged_sha256 != approved.sha256
        || staged_md5 != approved.md5
    {
        return Err(CliError::Input(
            "managed import stage did not reopen with the reviewed identity; preserve it for inspection and do not plan"
                .to_owned(),
        ));
    }
    let revalidated_common = validate_approved_mln_repository_authority(
        contract,
        approved,
        &canonical_root,
        Some(&bytes),
    )?;
    if revalidated_common != git_common_dir {
        return Err(CliError::Input(
            "reviewed MLN Git common directory changed while staging".to_owned(),
        ));
    }
    let source_authority = json!({
        "schema_version":1,
        "repository_id":contract.repository_id,
        "observed_worktree_root":canonical_root,
        "observed_git_common_dir":git_common_dir,
        "head":contract.repository_head,
        "repository_relative_path":approved.repository_relative_path,
        "git_blob_oid":approved.git_blob_oid,
    });
    Ok(json!({
        "schema_version":1,
        "migration_id":migration_id,
        "catalog_basename":approved.basename,
        "source_authority":source_authority,
        "source_authority_hash":hash_value(&source_authority)?,
        "bytes":approved.bytes,
        "sha256":format!("sha256:{}", approved.sha256),
        "md5":approved.md5,
        "stage_path":stage_path,
        "stage_lifecycle":"preserve_until_verified_or_explicitly_retired",
        "target":{
            "account_id":contract.account_id,
            "database_id":contract.database_id,
        },
        "prerequisites":input.body,
    }))
}

#[expect(
    clippy::too_many_lines,
    reason = "generic Git source identity, byte capture, and private staging are one fail-closed planning boundary"
)]
pub(super) fn stage_reviewed_git_d1_migration(
    store: &StateStore,
    capability: &CapabilityV1,
    input: &CallInput,
    source: &Path,
) -> Result<Value> {
    let contract = capability
        .d1_approved_mln_import
        .as_ref()
        .filter(|contract| contract.repository_id.is_empty() && contract.migrations.is_empty())
        .ok_or_else(|| {
            CliError::Input("provider-generic reviewed-Git import contract is missing".to_owned())
        })?;
    if !source.is_absolute()
        || source.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
        || source.extension().and_then(|value| value.to_str()) != Some("sql")
    {
        return Err(CliError::Input(
            "reviewed D1 migration source must be an absolute normalized `.sql` path".to_owned(),
        ));
    }
    let source_parent = source
        .parent()
        .ok_or_else(|| CliError::Input("reviewed migration source has no parent".to_owned()))?;
    let discovered_root = PathBuf::from(git_authority_output(
        source_parent,
        &["rev-parse", "--show-toplevel"],
    )?);
    let canonical_root = fs::canonicalize(&discovered_root).map_err(|source| CliError::Io {
        path: discovered_root.display().to_string(),
        source,
    })?;
    if canonical_root != discovered_root || !source.starts_with(&canonical_root) {
        return Err(CliError::Input(
            "reviewed migration source is outside its canonical Git worktree".to_owned(),
        ));
    }
    let relative = source
        .strip_prefix(&canonical_root)
        .ok()
        .and_then(Path::to_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input("reviewed migration path is not a portable Git path".to_owned())
        })?;
    let head = git_authority_output(&canonical_root, &["rev-parse", "HEAD"])?;
    let remote = git_authority_output(&canonical_root, &["remote", "get-url", "origin"])?;
    let repository_id = normalize_reviewed_git_repository_id(&remote)?;
    let tracked = git_authority_output(
        &canonical_root,
        &["ls-files", "--error-unmatch", "--", relative],
    )?;
    let blob_spec = format!("{head}:{relative}");
    let git_blob_oid = git_authority_output(&canonical_root, &["rev-parse", &blob_spec])?;
    let status = git_authority_output(
        &canonical_root,
        &["status", "--porcelain=v1", "--untracked-files=all"],
    )?;
    if tracked != relative || !status.is_empty() {
        return Err(CliError::Input(
            "reviewed migration repository must be clean and the source must be tracked at HEAD"
                .to_owned(),
        ));
    }
    let common = git_authority_output(&canonical_root, &["rev-parse", "--git-common-dir"])?;
    let common_path = if Path::new(&common).is_absolute() {
        PathBuf::from(common)
    } else {
        canonical_root.join(common)
    };
    let canonical_common = fs::canonicalize(&common_path).map_err(|source| CliError::Io {
        path: common_path.display().to_string(),
        source,
    })?;
    let mut cursor = PathBuf::new();
    for component in source.components() {
        cursor.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&cursor).map_err(|source| CliError::Io {
            path: cursor.display().to_string(),
            source,
        })?;
        if metadata.file_type().is_symlink() {
            return Err(CliError::Input(format!(
                "reviewed migration source has symlink component `{}`",
                cursor.display()
            )));
        }
    }
    let mut source_options = OpenOptions::new();
    source_options.read(true);
    #[cfg(unix)]
    source_options.custom_flags(libc::O_NOFOLLOW);
    let mut source_file = source_options
        .open(source)
        .map_err(|source_error| CliError::Io {
            path: source.display().to_string(),
            source: source_error,
        })?;
    let metadata = source_file
        .metadata()
        .map_err(|source_error| CliError::Io {
            path: source.display().to_string(),
            source: source_error,
        })?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > contract.max_source_bytes {
        return Err(CliError::Input(format!(
            "reviewed migration must be a non-empty regular file no larger than {} bytes",
            contract.max_source_bytes
        )));
    }
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| CliError::Input("reviewed migration size exceeds this host".to_owned()))?;
    let mut bytes = Vec::with_capacity(capacity);
    source_file
        .read_to_end(&mut bytes)
        .map_err(|source_error| CliError::Io {
            path: source.display().to_string(),
            source: source_error,
        })?;
    let blob_bytes = git_authority_bytes(&canonical_root, &["cat-file", "blob", &git_blob_oid])?;
    if bytes != blob_bytes || bytes.len() as u64 != metadata.len() {
        return Err(CliError::Input(
            "reviewed migration source differs from its exact HEAD Git blob".to_owned(),
        ));
    }
    let sha256 = hex::encode(Sha256::digest(&bytes));
    let md5 = hex::encode(Md5::digest(&bytes));
    let statement_count = if capability.id == "d1-apply-reviewed-schema-migration" {
        let sql = std::str::from_utf8(&bytes).map_err(|_| {
            CliError::Input("reviewed D1 schema migration must be UTF-8".to_owned())
        })?;
        Some(validate_reviewed_schema_migration_sql(sql)?)
    } else {
        None
    };
    let source_authority = json!({
        "schema_version":1,
        "repository_id":repository_id,
        "observed_worktree_root":canonical_root,
        "observed_git_common_dir":canonical_common,
        "head":head,
        "repository_relative_path":relative,
        "git_blob_oid":git_blob_oid,
    });
    let source_authority_hash = hash_value(&source_authority)?;
    let basename = source
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| CliError::Input("reviewed migration basename is not UTF-8".to_owned()))?;
    let stage_dir = store
        .paths()
        .data_dir
        .join("import-stages")
        .join(Uuid::new_v4().to_string());
    fs::create_dir_all(&stage_dir).map_err(|source| CliError::Io {
        path: stage_dir.display().to_string(),
        source,
    })?;
    #[cfg(unix)]
    fs::set_permissions(&stage_dir, fs::Permissions::from_mode(0o700)).map_err(|source| {
        CliError::Io {
            path: stage_dir.display().to_string(),
            source,
        }
    })?;
    let stage_path = stage_dir.join(basename);
    let mut stage_options = OpenOptions::new();
    stage_options.write(true).create_new(true);
    #[cfg(unix)]
    stage_options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    let mut stage = stage_options
        .open(&stage_path)
        .map_err(|source| CliError::Io {
            path: stage_path.display().to_string(),
            source,
        })?;
    stage.write_all(&bytes).map_err(|source| CliError::Io {
        path: stage_path.display().to_string(),
        source,
    })?;
    stage.sync_all().map_err(|source| CliError::Io {
        path: stage_path.display().to_string(),
        source,
    })?;
    drop(stage);
    let staged = fs::read(&stage_path).map_err(|source| CliError::Io {
        path: stage_path.display().to_string(),
        source,
    })?;
    if staged != bytes {
        return Err(CliError::Input(
            "private import stage did not reopen with the reviewed bytes".to_owned(),
        ));
    }
    let target = json!({
        "account_id":input.selectors.get("account_id"),
        "database_id":input.selectors.get("database_id"),
    });
    if target
        .pointer("/account_id")
        .and_then(Value::as_str)
        .is_none()
        || target
            .pointer("/database_id")
            .and_then(Value::as_str)
            .is_none()
    {
        return Err(CliError::Input(
            "reviewed D1 import target selectors are missing".to_owned(),
        ));
    }
    let mut staged = json!({
        "schema_version":1,
        "migration_id":source_authority_hash,
        "catalog_basename":basename,
        "source_authority":source_authority,
        "source_authority_hash":source_authority_hash,
        "bytes":bytes.len(),
        "sha256":format!("sha256:{sha256}"),
        "md5":md5,
        "stage_path":stage_path,
        "stage_lifecycle":"preserve_until_verified_or_explicitly_retired",
        "target":target,
        "prerequisites":input.body,
    });
    if let Some(statement_count) = statement_count {
        staged
            .as_object_mut()
            .ok_or_else(|| CliError::Input("reviewed migration stage is not an object".to_owned()))?
            .insert("statement_count".to_owned(), Value::from(statement_count));
    }
    Ok(staged)
}

pub(super) fn normalize_reviewed_git_repository_id(remote: &str) -> Result<String> {
    let trimmed = remote.trim().trim_end_matches(".git");
    if trimmed.contains('?') || trimmed.contains('#') || trimmed.contains('\n') {
        return Err(CliError::Input(
            "Git origin contains query, fragment, or control data and cannot be retained safely"
                .to_owned(),
        ));
    }
    let normalized = if let Some(rest) = trimmed.strip_prefix("https://") {
        if rest
            .split('/')
            .next()
            .is_none_or(|authority| authority.contains('@'))
        {
            return Err(CliError::Input(
                "Git HTTPS origin must not contain embedded credentials".to_owned(),
            ));
        }
        rest.to_owned()
    } else if let Some(rest) = trimmed.strip_prefix("ssh://git@") {
        rest.to_owned()
    } else if let Some(rest) = trimmed.strip_prefix("git@") {
        rest.replacen(':', "/", 1)
    } else {
        return Err(CliError::Input(
            "Git origin must be a credential-free HTTPS or git SSH repository identity".to_owned(),
        ));
    };
    if normalized.split('/').count() < 3 || normalized.contains('@') || normalized.contains(':') {
        return Err(CliError::Input(
            "Git origin is not a portable host/owner/repository identity".to_owned(),
        ));
    }
    Ok(normalized)
}

pub(super) fn git_authority_output(repository_root: &Path, arguments: &[&str]) -> Result<String> {
    let mut command = StdCommand::new("git");
    command.arg("-C").arg(repository_root).args(arguments);
    clear_git_authority_environment(&mut command);
    let output = command.output().map_err(|source| CliError::Io {
        path: repository_root.display().to_string(),
        source,
    })?;
    if !output.status.success() {
        return Err(CliError::Input(format!(
            "reviewed migration repository authority command `git {}` failed closed",
            arguments.join(" ")
        )));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|_| CliError::Input("Git authority output was not UTF-8".to_owned()))
}

pub(super) fn git_authority_bytes(repository_root: &Path, arguments: &[&str]) -> Result<Vec<u8>> {
    let mut command = StdCommand::new("git");
    command.arg("-C").arg(repository_root).args(arguments);
    clear_git_authority_environment(&mut command);
    let output = command.output().map_err(|source| CliError::Io {
        path: repository_root.display().to_string(),
        source,
    })?;
    if !output.status.success() {
        return Err(CliError::Input(format!(
            "reviewed migration repository authority command `git {}` failed closed",
            arguments.join(" ")
        )));
    }
    Ok(output.stdout)
}

pub(super) fn clear_git_authority_environment(command: &mut StdCommand) {
    for (name, _) in env::vars_os() {
        if name.as_encoded_bytes().starts_with(b"GIT_") {
            command.env_remove(name);
        }
    }
}

pub(super) fn validate_approved_mln_repository_authority(
    contract: &cfctl_core::D1ApprovedMlnImportContractV1,
    migration: &cfctl_core::D1ApprovedMlnMigrationV1,
    root: &Path,
    expected_bytes: Option<&[u8]>,
) -> Result<PathBuf> {
    let canonical_root = fs::canonicalize(root).map_err(|source| CliError::Io {
        path: root.display().to_string(),
        source,
    })?;
    if canonical_root != root {
        return Err(CliError::Input(
            "reviewed migration repository root is missing, substituted, or non-canonical"
                .to_owned(),
        ));
    }
    let top = git_authority_output(root, &["rev-parse", "--show-toplevel"])?;
    let head = git_authority_output(root, &["rev-parse", "HEAD"])?;
    let remote = git_authority_output(root, &["remote", "get-url", "origin"])?;
    let common = git_authority_output(root, &["rev-parse", "--git-common-dir"])?;
    let common_path = if Path::new(&common).is_absolute() {
        PathBuf::from(common)
    } else {
        root.join(common)
    };
    let canonical_common = fs::canonicalize(&common_path).map_err(|source| CliError::Io {
        path: common_path.display().to_string(),
        source,
    })?;
    if top != canonical_root.to_string_lossy()
        || head != contract.repository_head
        || normalize_reviewed_mln_repository_id(&remote).as_deref()
            != Some(contract.repository_id.as_str())
    {
        return Err(CliError::Input(
            "reviewed migration repository identity, canonical worktree root, or HEAD drifted"
                .to_owned(),
        ));
    }
    let relative = migration.repository_relative_path.as_str();
    let tracked = git_authority_output(root, &["ls-files", "--error-unmatch", "--", relative])?;
    let blob_spec = format!("{}:{relative}", contract.repository_head);
    let blob = git_authority_output(root, &["rev-parse", &blob_spec])?;
    let status =
        git_authority_output(root, &["status", "--porcelain=v1", "--untracked-files=all"])?;
    let blob_bytes = git_authority_bytes(root, &["cat-file", "blob", &migration.git_blob_oid])?;
    if tracked != relative || blob != migration.git_blob_oid || !status.is_empty() {
        return Err(CliError::Input(
            "reviewed migration is untracked, dirty, or does not match the pinned HEAD blob"
                .to_owned(),
        ));
    }
    if expected_bytes.is_some_and(|bytes| bytes != blob_bytes) {
        return Err(CliError::Input(
            "reviewed migration source bytes differ from the exact pinned Git blob".to_owned(),
        ));
    }
    Ok(canonical_common)
}

pub(super) fn normalize_reviewed_mln_repository_id(remote: &str) -> Option<String> {
    match remote {
        "https://github.com/rogu3bear/mln-web.git"
        | "https://github.com/rogu3bear/mln-web"
        | "git@github.com:rogu3bear/mln-web.git"
        | "git@github.com:rogu3bear/mln-web" => Some("github.com/rogu3bear/mln-web".to_owned()),
        "https://github.com/rogu3bear/osint-research-center.git"
        | "https://github.com/rogu3bear/osint-research-center"
        | "git@github.com:rogu3bear/osint-research-center.git"
        | "git@github.com:rogu3bear/osint-research-center" => {
            Some("github.com/rogu3bear/osint-research-center".to_owned())
        }
        _ => None,
    }
}

pub(super) fn required_body_string<'a>(
    body: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a str> {
    body.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input(format!("approved MLN import requires {field}")))
}

pub(super) const CLOSED_IMPORT_RECOVERY_BOOKMARK_MAX_AGE_MINUTES: i64 = 10;

pub(super) fn validate_closed_import_recovery_bookmark(
    store: &StateStore,
    input: &CallInput,
    body: &Map<String, Value>,
    contract: &cfctl_core::D1ApprovedMlnImportContractV1,
    context: ImportPrerequisiteContext<'_>,
    subject: &str,
) -> Result<()> {
    let evidence_hash = required_body_string(body, "pre_recovery_anchor_evidence_hash")?;
    let bookmark_hash = required_body_string(body, "pre_recovery_anchor_bookmark_hash")?;
    let expected_input_hash = hash_value(&serde_json::to_value(CallInput {
        selectors: input.selectors.clone(),
        query: json!({}),
        ..CallInput::default()
    })?)?;
    let freshness_floor =
        context.before - ChronoDuration::minutes(CLOSED_IMPORT_RECOVERY_BOOKMARK_MAX_AGE_MINUTES);
    let matches = store
        .list_operational_proofs()?
        .into_iter()
        .filter(|proof| {
            proof.capability_id == "d1-time-travel-get-bookmark"
                && proof.catalog_hash == context.catalog_hash
                && proof.input_hash == expected_input_hash
                && proof.profile_id.as_deref() == Some(context.profile_id)
                && proof.account_id.as_deref() == Some(contract.account_id.as_str())
                && proof.credential_generation_id.as_deref() == context.credential_generation_id
                && proof.outcome == OperationalProofOutcomeV1::Succeeded
                && proof.evidence.content_hash == evidence_hash
                && proof.observed_at >= freshness_floor
                && proof.observed_at < context.before
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(CliError::Input(format!(
            "{subject} import requires exactly one governed D1 time-travel bookmark read from the 10 minutes before planning, bound to the catalog, request, target, profile, credential generation, and evidence"
        )));
    }
    let evidence = store.read_evidence_value(evidence_hash)?;
    let bookmark = evidence
        .pointer("/result/bookmark")
        .and_then(Value::as_str)
        .filter(|bookmark| !bookmark.is_empty())
        .ok_or_else(|| {
            CliError::Input(format!(
                "{subject} recovery bookmark evidence omitted the exact bookmark"
            ))
        })?;
    if evidence.get("status").and_then(Value::as_u64) != Some(200)
        || evidence.get("success").and_then(Value::as_bool) != Some(true)
        || hash_value(&Value::String(bookmark.to_owned()))? != bookmark_hash
    {
        return Err(CliError::Input(format!(
            "{subject} recovery bookmark evidence or bookmark hash drifted"
        )));
    }
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "the closed 0142 then 0143 prerequisite graph is validated as one contract"
)]
pub(super) fn validate_approved_mln_import_prerequisites(
    store: &StateStore,
    capability: &CapabilityV1,
    input: &CallInput,
    context: ImportPrerequisiteContext<'_>,
) -> Result<()> {
    if matches!(
        capability.id.as_str(),
        "d1-import-database" | "d1-apply-reviewed-schema-migration"
    ) {
        return validate_reviewed_git_import_prerequisites(store, input, context);
    }
    let contract = capability
        .d1_approved_mln_import
        .as_ref()
        .ok_or_else(|| CliError::Input("approved MLN import contract is missing".to_owned()))?;
    let body = input
        .body
        .as_ref()
        .and_then(Value::as_object)
        .ok_or_else(|| CliError::Input("approved MLN import body is missing".to_owned()))?;
    let migration_id = body
        .get("migration_id")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("migration_id is missing".to_owned()))?;
    if capability.id == "d1-import-approved-osint-research-migration" {
        validate_closed_import_recovery_bookmark(
            store,
            input,
            body,
            contract,
            context,
            "OSINT Research",
        )?;
        return Ok(());
    }
    let pre_operation = body
        .get("pre_recovery_anchor_operation_id")
        .and_then(Value::as_str)
        .filter(|value| Uuid::parse_str(value).is_ok())
        .ok_or_else(|| {
            CliError::Input(
                "pre_recovery_anchor_operation_id must be a canonical operation id".to_owned(),
            )
        })?;
    let pre_evidence_hash = required_body_string(body, "pre_recovery_anchor_evidence_hash")?;
    let pre_output_sha256 = required_body_string(body, "pre_recovery_anchor_output_sha256")?;
    let pre_bookmark_hash = required_body_string(body, "pre_recovery_anchor_bookmark_hash")?;
    store.read_evidence_value(pre_evidence_hash)?;
    let expected_target_hash = hash_value(&json!({
        "account_id":contract.account_id,
        "database_id":contract.database_id,
    }))?;
    let expected_export_request_hash = hash_value(&serde_json::to_value(CallInput {
        selectors: input.selectors.clone(),
        query: json!({}),
        ..CallInput::default()
    })?)?;
    let pre_expectation = |before| D1RecoveryAnchorExpectation {
        operation_id: pre_operation,
        evidence_hash: pre_evidence_hash,
        output_sha256: Some(pre_output_sha256),
        bookmark_hash: pre_bookmark_hash,
        catalog_hash: context.catalog_hash,
        request_hash: &expected_export_request_hash,
        target_scope_hash: &expected_target_hash,
        account_id: &contract.account_id,
        profile_id: context.profile_id,
        credential_generation_id: context.credential_generation_id,
        after: None,
        before,
    };
    if migration_id == "0142" {
        validate_exact_d1_recovery_anchor(store, &pre_expectation(context.before))?;
        if context.import_operation_id == Some(pre_operation) {
            return Err(CliError::Input(
                "pre-0142 recovery anchor must be distinct from the import operation".to_owned(),
            ));
        }
        return Ok(());
    }
    let prior_operation = body
        .get("prior_0142_operation_id")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("0143 requires prior_0142_operation_id".to_owned()))?;
    let prior_hash = body
        .get("prior_0142_boundary_evidence_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input("0143 requires prior_0142_boundary_evidence_hash".to_owned())
        })?;
    let prior_proof_operation = body
        .get("prior_0142_schema_proof_operation_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input("0143 requires prior_0142_schema_proof_operation_id".to_owned())
        })?;
    let prior_verification_hash = body
        .get("prior_0142_verification_evidence_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input("0143 requires prior_0142_verification_evidence_hash".to_owned())
        })?;
    let prior_plan = store.load_plan(prior_operation)?;
    let prior_input: CallInput = serde_json::from_value(prior_plan.input.clone())?;
    let prior_exact = prior_plan.capability.id == capability.id
        && mln_0142_terminal_import_state(&prior_plan)
        && prior_plan.account_id == contract.account_id
        && prior_input.selectors == input.selectors
        && prior_input
            .body
            .as_ref()
            .and_then(|body| body.get("migration_id"))
            .and_then(Value::as_str)
            == Some("0142");
    let verification_artifact_matches = prior_plan
        .transaction_artifact(TransactionStageV1::VerificationResponsePersisted)
        .and_then(|artifact| artifact.get("evidence_hash"))
        .and_then(Value::as_str)
        == Some(prior_verification_hash);
    let verification_evidence = store.read_evidence_value(prior_verification_hash)?;
    let verification_receipt_matches = verification_evidence.get("state").and_then(Value::as_str)
        == Some("verified")
        && verification_evidence
            .get("operation_id")
            .and_then(Value::as_str)
            == Some(prior_operation)
        && verification_evidence
            .get("provider_complete_evidence_hash")
            .and_then(Value::as_str)
            == Some(prior_hash)
        && verification_evidence
            .get("post_import_operation_id")
            .and_then(Value::as_str)
            == Some(prior_proof_operation);
    let prior_boundary = exact_durable_provider_complete_boundary(store, prior_operation)?;
    let boundary_matches = prior_boundary.evidence_hash == prior_hash;
    let expected_final_bookmark_hash = prior_boundary
        .checkpoint
        .pointer("/receipt/final_bookmark")
        .and_then(Value::as_str)
        .and_then(|bookmark| hash_value(&Value::String(bookmark.to_owned())).ok());
    let schema_proofs = store
        .list_operational_proofs()?
        .into_iter()
        .filter(|proof| {
            proof.mln_0142_governed_execution().is_some_and(|binding| {
                proof.capability_id == "mln-0142-post-import-schema"
                    && binding.operation_id == prior_proof_operation
                    && binding.import_operation_id == prior_operation
                    && binding.import_boundary_evidence_hash == prior_hash
                    && binding.import_plan_hash == prior_plan.content_hash
                    && binding.import_source_sha256
                        == "sha256:07e1c5bd77dd529bfe58f0eee80ad29c40fdd0f3e9c9a37163cfaa0683124af0"
                    && binding.target_scope_hash == expected_target_hash
                    && Some(binding.final_bookmark_hash.as_str())
                        == expected_final_bookmark_hash.as_deref()
                    && binding.completion_status == "completed"
            })
        })
        .collect::<Vec<_>>();
    if !prior_exact
        || !verification_artifact_matches
        || !verification_receipt_matches
        || schema_proofs.len() != 1
        || !boundary_matches
    {
        return Err(CliError::Input(
            "0143 requires one terminal verified 0142 import joined to its exact schema proof, verification evidence, and provider boundary"
                .to_owned(),
        ));
    }
    validate_exact_d1_recovery_anchor(store, &pre_expectation(prior_plan.created_at))?;
    if pre_operation == prior_operation || context.import_operation_id == Some(pre_operation) {
        return Err(CliError::Input(
            "pre-0142 recovery anchor must be distinct from both import operations".to_owned(),
        ));
    }
    let anchor_operation = body
        .get("post_0142_anchor_operation_id")
        .and_then(Value::as_str)
        .filter(|value| Uuid::parse_str(value).is_ok())
        .ok_or_else(|| {
            CliError::Input("0143 requires a distinct post-0142 recovery anchor".to_owned())
        })?;
    if anchor_operation == pre_operation
        || anchor_operation == prior_operation
        || context.import_operation_id == Some(anchor_operation)
    {
        return Err(CliError::Input(
            "0143 post-0142 recovery anchor must be distinct from both imports and the pre-0142 anchor"
                .to_owned(),
        ));
    }
    let anchor_evidence_hash = body
        .get("post_0142_anchor_evidence_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input("0143 requires post_0142_anchor_evidence_hash".to_owned())
        })?;
    let anchor_bookmark_hash = body
        .get("post_0142_anchor_bookmark_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input("0143 requires post_0142_anchor_bookmark_hash".to_owned())
        })?;
    store.read_evidence_value(anchor_evidence_hash)?;
    let closed_at = prior_plan
        .transaction_journal
        .iter()
        .find(|checkpoint| checkpoint.stage == TransactionStageV1::Closed)
        .map(|checkpoint| checkpoint.recorded_at)
        .ok_or_else(|| {
            CliError::Input("verified 0142 omitted its terminal checkpoint".to_owned())
        })?;
    let cutoff = context.before;
    let expected_profile = context.profile_id;
    let current_generation = context.credential_generation_id;
    let prior_generation = schema_proofs[0]
        .mln_0142_governed_execution()
        .map(|binding| binding.credential_generation_id.as_str())
        .ok_or_else(|| CliError::Input("verified 0142 schema proof lost its binding".to_owned()))?;
    if current_generation != Some(prior_generation) {
        return Err(CliError::Input(
            "0143 selected credential generation drifted from verified 0142".to_owned(),
        ));
    }
    let anchor_expectation = D1RecoveryAnchorExpectation {
        operation_id: anchor_operation,
        evidence_hash: anchor_evidence_hash,
        output_sha256: None,
        bookmark_hash: anchor_bookmark_hash,
        catalog_hash: context.catalog_hash,
        request_hash: &expected_export_request_hash,
        target_scope_hash: &expected_target_hash,
        account_id: &contract.account_id,
        profile_id: expected_profile,
        credential_generation_id: current_generation,
        after: Some(closed_at),
        before: cutoff,
    };
    let anchor_completed_at = validate_exact_d1_recovery_anchor(store, &anchor_expectation)?;
    let invariant_operation = body
        .get("pre_import_invariant_operation_id")
        .and_then(Value::as_str)
        .filter(|value| Uuid::parse_str(value).is_ok())
        .ok_or_else(|| {
            CliError::Input(
                "0143 requires a canonical pre_import_invariant_operation_id".to_owned(),
            )
        })?;
    let invariant_evidence_hash = required_body_string(body, "pre_import_invariant_evidence_hash")?;
    store
        .read_evidence_value(invariant_evidence_hash)
        .map_err(|error| {
            CliError::Input(format!(
                "pre_import_invariant_evidence_hash does not resolve to immutable evidence: {error}"
            ))
        })?;
    let invariant_request_hash = hash_value(&serde_json::to_value(CallInput {
        selectors: input.selectors.clone(),
        query: json!({}),
        body: Some(json!({"migration_id":"0143","phase":"pre_import"})),
        ..CallInput::default()
    })?)?;
    validate_exact_mln_0143_pre_import(
        store,
        &Mln0143PreImportExpectation {
            operation_id: invariant_operation,
            evidence_hash: invariant_evidence_hash,
            catalog_hash: context.catalog_hash,
            request_hash: &invariant_request_hash,
            target_scope_hash: &expected_target_hash,
            account_id: &contract.account_id,
            profile_id: context.profile_id,
            credential_generation_id: context.credential_generation_id,
            capability_version: contract.pre_import_capability_version,
            validator_contract_hash: &contract.pre_import_validator_contract_hash,
            fixed_query_sha256: &contract.pre_import_fixed_query_sha256,
            after: anchor_completed_at,
            before: context.before,
        },
    )?;
    Ok(())
}

pub(super) fn validate_reviewed_git_import_prerequisites(
    store: &StateStore,
    input: &CallInput,
    context: ImportPrerequisiteContext<'_>,
) -> Result<()> {
    let body = input
        .body
        .as_ref()
        .and_then(Value::as_object)
        .ok_or_else(|| CliError::Input("reviewed D1 import body is missing".to_owned()))?;
    let operation_id = body
        .get("pre_recovery_anchor_operation_id")
        .and_then(Value::as_str)
        .filter(|value| Uuid::parse_str(value).is_ok())
        .ok_or_else(|| {
            CliError::Input(
                "pre_recovery_anchor_operation_id must be a canonical operation id".to_owned(),
            )
        })?;
    if context.import_operation_id == Some(operation_id) {
        return Err(CliError::Input(
            "pre-import recovery export must be distinct from the import operation".to_owned(),
        ));
    }
    let evidence_hash = required_body_string(body, "pre_recovery_anchor_evidence_hash")?;
    let output_sha256 = required_body_string(body, "pre_recovery_anchor_output_sha256")?;
    let bookmark_hash = required_body_string(body, "pre_recovery_anchor_bookmark_hash")?;
    store.read_evidence_value(evidence_hash)?;
    let account_id = input
        .selectors
        .get("account_id")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("reviewed import account_id is missing".to_owned()))?;
    let database_id = input
        .selectors
        .get("database_id")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("reviewed import database_id is missing".to_owned()))?;
    let expected_target_hash = hash_value(&json!({
        "account_id":account_id,
        "database_id":database_id,
    }))?;
    let expected_request_hash = hash_value(&serde_json::to_value(CallInput {
        selectors: input.selectors.clone(),
        query: json!({}),
        ..CallInput::default()
    })?)?;
    validate_exact_d1_recovery_anchor(
        store,
        &D1RecoveryAnchorExpectation {
            operation_id,
            evidence_hash,
            output_sha256: Some(output_sha256),
            bookmark_hash,
            catalog_hash: context.catalog_hash,
            request_hash: &expected_request_hash,
            target_scope_hash: &expected_target_hash,
            account_id,
            profile_id: context.profile_id,
            credential_generation_id: context.credential_generation_id,
            after: None,
            before: context.before,
        },
    )?;
    Ok(())
}

#[derive(Clone, Copy)]
pub(super) struct ImportPrerequisiteContext<'a> {
    pub(super) profile_id: &'a str,
    pub(super) credential_generation_id: Option<&'a str>,
    pub(super) catalog_hash: &'a str,
    pub(super) import_operation_id: Option<&'a str>,
    pub(super) before: chrono::DateTime<Utc>,
}

#[derive(Clone, Copy)]
pub(super) struct D1RecoveryAnchorExpectation<'a> {
    pub(super) operation_id: &'a str,
    pub(super) evidence_hash: &'a str,
    pub(super) output_sha256: Option<&'a str>,
    pub(super) bookmark_hash: &'a str,
    pub(super) catalog_hash: &'a str,
    pub(super) request_hash: &'a str,
    pub(super) target_scope_hash: &'a str,
    pub(super) account_id: &'a str,
    pub(super) profile_id: &'a str,
    pub(super) credential_generation_id: Option<&'a str>,
    pub(super) after: Option<chrono::DateTime<Utc>>,
    pub(super) before: chrono::DateTime<Utc>,
}

#[derive(Clone, Copy)]
pub(super) struct Mln0143PreImportExpectation<'a> {
    pub(super) operation_id: &'a str,
    pub(super) evidence_hash: &'a str,
    pub(super) catalog_hash: &'a str,
    pub(super) request_hash: &'a str,
    pub(super) target_scope_hash: &'a str,
    pub(super) account_id: &'a str,
    pub(super) profile_id: &'a str,
    pub(super) credential_generation_id: Option<&'a str>,
    pub(super) capability_version: u8,
    pub(super) validator_contract_hash: &'a str,
    pub(super) fixed_query_sha256: &'a str,
    pub(super) after: chrono::DateTime<Utc>,
    pub(super) before: chrono::DateTime<Utc>,
}

pub(super) fn d1_recovery_anchor_matches(
    proof: &OperationalProofV1,
    expected: &D1RecoveryAnchorExpectation<'_>,
) -> bool {
    proof
        .d1_full_export_governed_execution()
        .is_some_and(|binding| {
            binding.operation_id == expected.operation_id
                && proof.capability_id == "d1-full-export"
                && proof.evidence.content_hash == expected.evidence_hash
                && binding.manifest_evidence_hash == expected.evidence_hash
                && expected
                    .output_sha256
                    .is_none_or(|value| binding.output_file_sha256 == value)
                && binding.at_bookmark_hash == expected.bookmark_hash
                && proof.catalog_hash == expected.catalog_hash
                && binding.catalog_hash == expected.catalog_hash
                && proof.input_hash == expected.request_hash
                && binding.request_hash == expected.request_hash
                && binding.target_scope_hash == expected.target_scope_hash
                && proof.account_id.as_deref() == Some(expected.account_id)
                && proof.profile_id.as_deref() == Some(expected.profile_id)
                && binding.profile_id == expected.profile_id
                && Some(binding.credential_generation_id.as_str())
                    == expected.credential_generation_id
                && binding.completion_status == "completed"
                && expected
                    .after
                    .is_none_or(|after| binding.completed_at > after)
                && binding.completed_at < expected.before
        })
}

pub(super) fn validate_exact_d1_recovery_anchor(
    store: &StateStore,
    expected: &D1RecoveryAnchorExpectation<'_>,
) -> Result<chrono::DateTime<Utc>> {
    let matches = store
        .list_operational_proofs()?
        .into_iter()
        .filter(|proof| d1_recovery_anchor_matches(proof, expected))
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(CliError::Input(
            "approved MLN import requires exactly one completed governed D1 full-export anchor bound to the exact operation, evidence, output, bookmark, catalog, input, target, profile, credential generation, and chronology"
                .to_owned(),
        ));
    }
    matches[0]
        .d1_full_export_governed_execution()
        .map(|binding| binding.completed_at)
        .ok_or_else(|| CliError::Input("governed D1 export lost its execution binding".to_owned()))
}

pub(super) fn mln_0143_pre_import_authority_matches(
    proof: &OperationalProofV1,
    expected: &Mln0143PreImportExpectation<'_>,
) -> bool {
    proof.mln_0143_governed_execution().is_some_and(|binding| {
        let expected_profile_identity = hash_value(&json!({
            "profile_id":expected.profile_id,
            "credential_generation_id":expected.credential_generation_id,
        }))
        .ok();
        proof.capability_id == "mln-0143-data-invariants"
            && proof.outcome == OperationalProofOutcomeV1::Succeeded
            && proof.evidence.class == EvidenceClass::LiveRead
            && proof.catalog_hash == expected.catalog_hash
            && binding.catalog_hash == expected.catalog_hash
            && proof.input_hash == expected.request_hash
            && binding.request_hash == expected.request_hash
            && proof.account_id.as_deref() == Some(expected.account_id)
            && proof.profile_id.as_deref() == Some(expected.profile_id)
            && proof.credential_generation_id.as_deref() == expected.credential_generation_id
            && Some(binding.credential_generation_id.as_str()) == expected.credential_generation_id
            && Some(binding.profile_identity_hash.as_str()) == expected_profile_identity.as_deref()
            && binding.capability_id == "mln-0143-data-invariants"
            && binding.capability_version == expected.capability_version
            && binding.validator_contract_hash == expected.validator_contract_hash
            && binding.fixed_query_sha256 == expected.fixed_query_sha256
            && binding.target_scope_hash == expected.target_scope_hash
            && binding.phase == "pre_import"
            && binding.completion_status == "completed"
            && binding.cross_operation_lineage_hash.is_none()
            && binding.completed_at == proof.observed_at
            && binding.completed_at > expected.after
            && binding.completed_at < expected.before
    })
}

pub(super) fn mln_0143_pre_import_matches(
    proof: &OperationalProofV1,
    expected: &Mln0143PreImportExpectation<'_>,
) -> bool {
    mln_0143_pre_import_authority_matches(proof, expected)
        && proof.evidence.content_hash == expected.evidence_hash
        && proof.mln_0143_governed_execution().is_some_and(|binding| {
            binding.operation_id == expected.operation_id
                && binding.manifest_evidence_hash == expected.evidence_hash
        })
}

pub(super) fn validate_exact_mln_0143_pre_import(
    store: &StateStore,
    expected: &Mln0143PreImportExpectation<'_>,
) -> Result<()> {
    let proofs = store.list_operational_proofs()?;
    let current_authority = proofs
        .iter()
        .filter(|proof| mln_0143_pre_import_authority_matches(proof, expected))
        .count();
    let selected = proofs
        .iter()
        .filter(|proof| mln_0143_pre_import_matches(proof, expected))
        .count();
    if current_authority != 1 || selected != 1 {
        return Err(CliError::Input(
            "0143 requires exactly one selected completed pre_import proof bound to the current catalog, closed request, target, profile, credential generation, validator/query authority, and post-export-to-plan chronology; this ordered evidence does not prove absence of out-of-band provider writes"
                .to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn mln_0142_terminal_import_state(plan: &PlanV1) -> bool {
    plan.status == PlanStatus::Verified && plan.transaction_stage == TransactionStageV1::Closed
}

pub(super) fn validate_mln_0142_post_import_schema_input(
    store: &StateStore,
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<()> {
    let contract = capability
        .mln_0142_post_import_schema
        .as_ref()
        .ok_or_else(|| CliError::Input("MLN 0142 schema contract is missing".to_owned()))?;
    let body = input
        .body
        .as_ref()
        .and_then(Value::as_object)
        .ok_or_else(|| CliError::Input("MLN 0142 schema proof body is missing".to_owned()))?;
    let field = |name: &str| {
        body.get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| CliError::Input(format!("MLN 0142 schema proof requires `{name}`")))
    };
    let operation_id = field("import_operation_id")?;
    let boundary_hash = field("import_boundary_evidence_hash")?;
    let source_sha256 = field("import_source_sha256")?;
    let plan_hash = field("import_plan_hash")?;
    let final_bookmark_hash = field("final_bookmark_hash")?;
    let import_plan = store.load_plan(operation_id)?;
    let import_input: CallInput = serde_json::from_value(import_plan.input.clone())?;
    let exact_plan = import_plan.capability.id == "d1-import-approved-mln-migration"
        && import_plan.status == PlanStatus::Running
        && import_plan.transaction_stage == TransactionStageV1::SecretSinkPersisted
        && import_plan.content_hash == plan_hash
        && import_plan.account_id == contract.account_id
        && import_input.selectors == input.selectors
        && import_input
            .body
            .as_ref()
            .and_then(|value| value.get("migration_id"))
            .and_then(Value::as_str)
            == Some("0142");
    let boundary = exact_durable_provider_complete_boundary(store, operation_id)?;
    let boundary_matches = boundary.evidence_hash == boundary_hash
        && boundary
            .checkpoint
            .pointer("/receipt/source_sha256")
            .and_then(Value::as_str)
            == Some(source_sha256)
        && boundary
            .checkpoint
            .pointer("/receipt/final_bookmark")
            .and_then(Value::as_str)
            .and_then(|bookmark| hash_value(&Value::String(bookmark.to_owned())).ok())
            .as_deref()
            == Some(final_bookmark_hash);
    if !exact_plan
        || !boundary_matches
        || source_sha256 != contract.migration_sha256
        || field("trigger_definition_sha256")? != contract.trigger_definition_sha256
    {
        return Err(CliError::Input(
            "MLN 0142 schema proof must bind the exact running import plan, provider boundary, source, target, final bookmark, and trigger definition"
                .to_owned(),
        ));
    }
    Ok(())
}

pub(super) const SECURITY_IP_RULE_CREATE_ID: &str =
    "security-response-create-expiring-ip-access-rule";
pub(super) const SECURITY_IP_RULE_REMOVE_ID: &str =
    "security-response-remove-expired-ip-access-rule";
pub(super) const SECURITY_IP_RULE_STATE_CAPABILITY_ID: &str =
    "ip-access-rules-for-a-zone-list-ip-access-rules";
pub(super) const SECURITY_IP_RULE_COLLECTION_PATH: &str =
    "/zones/{zone_id}/firewall/access_rules/rules";
pub(super) const SECURITY_WAF_RULE_CREATE_ID: &str = "security-response-create-expiring-waf-rule";
pub(super) const SECURITY_WAF_RULE_REMOVE_ID: &str = "security-response-remove-expired-waf-rule";
pub(super) const SECURITY_WAF_RULE_STATE_CAPABILITY_ID: &str = "getZoneRuleset";
pub(super) const SECURITY_WAF_RULE_PARENT_PATH: &str = "/zones/{zone_id}/rulesets/{ruleset_id}";
pub(super) const SECURITY_LIST_MEMBER_CREATE_ID: &str =
    "security-response-add-expiring-list-member";
pub(super) const SECURITY_LIST_MEMBER_REMOVE_ID: &str =
    "security-response-remove-expired-list-member";
pub(super) const SECURITY_LIST_MEMBER_STATE_CAPABILITY_ID: &str = "lists-get-list-items";
pub(super) const SECURITY_LIST_METADATA_CAPABILITY_ID: &str = "lists-get-a-list";
pub(super) const SECURITY_LIST_MEMBER_COLLECTION_PATH: &str =
    "/accounts/{account_id}/rules/lists/{list_id}/items";
pub(super) const SECURITY_LIST_METADATA_PATH: &str = "/accounts/{account_id}/rules/lists/{list_id}";
pub(super) const SECURITY_ACTION_STATE_PRECONDITION: &str = "security_action_state";
