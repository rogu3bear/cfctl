use cfctl_core::workspace_d1::transition::{
    COMPILER_ID, Compiled, Declaration, MAX_ENVELOPE_BYTES, MAX_HISTORY, Segment, Source, Target,
    canonical_digest, lower_hex, validate_schedule,
};
use serde::Deserialize;

use super::{
    AdapterStatus, CapabilityV1, MigrationManifestV1, OperationDeclaration, PACK_RELATIVE_PATH,
    Result, RiskClass, WorkspaceD1MigrationContractV1, WorkspaceD1MigrationFileV1, capability,
    committed_file, git_optional, invariant, safe_identifier, safe_relative, selector, sha256,
    valid_operation_id,
};
use std::{collections::BTreeSet, path::Path};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pack {
    schema_version: u8,
    operation: Vec<Declaration>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoricalLedger {
    #[serde(rename = "_doc")]
    _documentation: Option<String>,
    migrations: Vec<HistoricalEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoricalEntry {
    file: String,
    sha256: String,
    applied_at: String,
}

pub(super) fn load(
    repository: &super::super::RepositoryNode,
    capability_id: &str,
    head: &str,
    origin: String,
    pack_bytes: &[u8],
    pack_text: &str,
) -> Result<Option<CapabilityV1>> {
    let pack: Pack = toml::from_str(pack_text)
        .map_err(|error| invariant(format!("V3 transition pack is invalid: {error}")))?;
    if pack.schema_version != 3
        || pack.operation.is_empty()
        || pack.operation.len() > MAX_HISTORY
        || pack
            .operation
            .iter()
            .map(|op| &op.id)
            .collect::<BTreeSet<_>>()
            .len()
            != pack.operation.len()
    {
        return Err(invariant(
            "V3 pack version, count or operation identities are invalid",
        ));
    }
    let Some(op) = pack.operation.iter().find(|op| op.id == capability_id) else {
        return Ok(None);
    };
    let compiled = compile_pack(&repository.path, &pack.operation)?
        .into_iter()
        .find(|c| c.declaration.id == capability_id)
        .ok_or_else(|| invariant("V3 selected operation was not compiled"))?;
    let template = committed_file(&repository.path, &safe_relative(&op.config_template)?)?;
    let common = OperationDeclaration {
        id: op.id.clone(),
        title: op.title.clone(),
        description: op.description.clone(),
        config_template: op.config_template.clone(),
        production_config: op.config_template.clone(),
        migrations_dir: op.migrations_dir.clone(),
        database_binding: op.database_binding.clone(),
        wrangler_version: String::new(),
        recovery_capability_id: "d1-full-export".to_owned(),
        recovery_max_age_seconds: 600,
        rollback_capability_id: "d1-restore-exact-bookmark".to_owned(),
        migration: Vec::new(),
        assertion: Vec::new(),
    };
    let contract = WorkspaceD1MigrationContractV1 {
        repository_root: repository.path.display().to_string(),
        repository_head: head.to_owned(),
        repository_origin: origin,
        operation_pack_path: PACK_RELATIVE_PATH.to_owned(),
        operation_pack_sha256: sha256(pack_bytes),
        config_template_path: op.config_template.clone(),
        config_template_sha256: sha256(&template),
        production_config_path: op.config_template.clone(),
        migrations_dir: op.migrations_dir.clone(),
        database_binding: op.database_binding.clone(),
        wrangler_version: String::new(),
        migrations: vec![WorkspaceD1MigrationFileV1 {
            path: op.target.source.path.clone(),
            sha256: op.target.source.sha256.clone(),
        }],
        assertions: Vec::new(),
        recovery_capability_id: "d1-full-export".to_owned(),
        recovery_max_age_seconds: 600,
        rollback_capability_id: "d1-restore-exact-bookmark".to_owned(),
        manifest_migration: None,
        transition: Some(Box::new(compiled)),
    };
    let mut result = capability(&common, contract);
    "workspace-operation-pack-v3".clone_into(&mut result.source);
    "workspace:d1-transition-envelope-v3".clone_into(&mut result.path);
    result.adapter_status = AdapterStatus::Blocked;
    result.risk = RiskClass::Irreversible;
    result.blocked_reason = Some("V3 source envelope compiled; production transport remains disabled pending executor-specific qualification and typed application state proof producers".to_owned());
    "workspace_d1_transition_envelope_v3".clone_into(&mut result.verification.strategy);
    result.selectors = vec![
        selector("account_id", "path"),
        selector("database_id", "path"),
    ];
    Ok(Some(result))
}

fn compile_pack(repository: &Path, operations: &[Declaration]) -> Result<Vec<Compiled>> {
    let first = operations
        .first()
        .ok_or_else(|| invariant("V3 pack is empty"))?;
    let expected: BTreeSet<_> = first
        .transition_schedule
        .iter()
        .map(|s| s.sequence)
        .collect();
    let actual: BTreeSet<_> = operations.iter().map(|op| op.target.sequence).collect();
    if actual != expected || actual.len() != operations.len() {
        return Err(invariant(
            "V3 frozen pack must contain exactly one declaration per scheduled target",
        ));
    }
    for op in operations {
        if op.manifest != first.manifest
            || op.historical_ledger != first.historical_ledger
            || op.transition_schedule != first.transition_schedule
            || op.account_id != first.account_id
            || op.profile_id != first.profile_id
            || op.database_id != first.database_id
            || op.database_binding != first.database_binding
            || op.config_template != first.config_template
            || op.migrations_dir != first.migrations_dir
        {
            return Err(invariant(
                "V3 frozen declarations disagree on source, target scope or phase schedule",
            ));
        }
    }
    operations
        .iter()
        .map(|op| compile(repository, op))
        .collect()
}

fn bound_source(repository: &Path, source: &Source) -> Result<Vec<u8>> {
    if !canonical_digest(&source.sha256) || !lower_hex(&source.git_blob_oid, 40) {
        return Err(invariant("V3 source digest or Git blob is not canonical"));
    }
    let relative = safe_relative(&source.path)?;
    let bytes = committed_file(repository, &relative)?;
    let spec = format!("HEAD:{}", source.path);
    if sha256(&bytes) != source.sha256
        || git_optional(repository, &["rev-parse", "--verify", &spec])?.as_deref()
            != Some(source.git_blob_oid.as_str())
    {
        return Err(invariant(
            "V3 source bytes, declared digest or committed blob disagree",
        ));
    }
    Ok(bytes)
}

#[expect(
    clippy::too_many_lines,
    reason = "one compiler binds historical identity, every scheduled SQL source and exact envelope segments without a partially admitted contract"
)]
fn compile(repository: &Path, op: &Declaration) -> Result<Compiled> {
    if !valid_operation_id(&op.id)
        || op.title.trim().is_empty()
        || op.description.trim().is_empty()
        || !lower_hex(&op.account_id, 32)
        || op.database_id.len() != 36
        || op.profile_id.is_empty()
        || !safe_identifier(&op.database_binding)
    {
        return Err(invariant("V3 operation identity or target is invalid"));
    }
    let manifest: MigrationManifestV1 =
        serde_json::from_slice(&bound_source(repository, &op.manifest)?)
            .map_err(|error| invariant(format!("V3 manifest is invalid: {error}")))?;
    let history: HistoricalLedger =
        serde_json::from_slice(&bound_source(repository, &op.historical_ledger)?)
            .map_err(|error| invariant(format!("V3 historical ledger is invalid: {error}")))?;
    if manifest.manifest_version != 1
        || manifest.migrations.is_empty()
        || manifest.migrations.len() > MAX_HISTORY
        || history.migrations.len() > MAX_HISTORY
    {
        return Err(invariant(
            "V3 manifest or history exceeds the closed 256-entry bound",
        ));
    }
    let mut names = BTreeSet::new();
    for (position, entry) in manifest.migrations.iter().enumerate() {
        if entry.sequence != u64::try_from(position + 1).unwrap_or(u64::MAX)
            || !names.insert(entry.file.as_str())
            || !lower_hex(&entry.sha256, 64)
            || Path::new(&entry.file).components().count() != 1
            || entry.predecessor.as_deref()
                != position
                    .checked_sub(1)
                    .map(|i| manifest.migrations[i].file.as_str())
        {
            return Err(invariant(
                "V3 manifest sequence, filename, digest or historical adjacency is invalid",
            ));
        }
        safe_relative(&entry.file)?;
    }
    let mut historical_sequences = Vec::new();
    let mut historical_names = BTreeSet::new();
    for entry in &history.migrations {
        let matched = manifest
            .migrations
            .iter()
            .find(|m| m.file == entry.file && m.sha256 == entry.sha256)
            .ok_or_else(|| {
                invariant("historical ledger identity is absent or differs from the manifest")
            })?;
        if !historical_names.insert(entry.file.as_str())
            || entry.applied_at.is_empty()
            || !matched.production_applied
        {
            return Err(invariant(
                "historical source ledger contains duplicate or contradictory membership",
            ));
        }
        historical_sequences.push(matched.sequence);
    }
    historical_sequences.sort_unstable();
    if manifest
        .migrations
        .iter()
        .any(|entry| entry.production_applied != historical_names.contains(entry.file.as_str()))
    {
        return Err(invariant(
            "manifest and historical source ledger membership disagree",
        ));
    }
    let pending: Vec<_> = manifest
        .migrations
        .iter()
        .filter(|m| !m.production_applied)
        .map(|m| m.sequence)
        .collect();
    validate_schedule(&op.transition_schedule, &pending).map_err(invariant)?;
    let directory = safe_relative(&op.migrations_dir)?;
    let mut scheduled_targets = Vec::new();
    for step in &op.transition_schedule {
        let entry = &manifest.migrations
            [usize::try_from(step.sequence - 1).map_err(|_| invariant("sequence overflow"))?];
        let path = directory.join(&entry.file);
        let spec = format!("HEAD:{}", path.display());
        let source = Source {
            path: path.display().to_string(),
            sha256: format!("sha256:{}", entry.sha256),
            git_blob_oid: git_optional(repository, &["rev-parse", "--verify", &spec])?
                .ok_or_else(|| invariant("scheduled SQL has no committed blob"))?,
        };
        bound_source(repository, &source)?;
        scheduled_targets.push(Target {
            sequence: step.sequence,
            file: entry.file.clone(),
            source,
        });
    }
    if scheduled_targets
        .iter()
        .find(|t| t.sequence == op.target.sequence)
        != Some(&op.target)
    {
        return Err(invariant(
            "V3 target sequence/file/hash/blob does not match its scheduled manifest identity",
        ));
    }
    let sources = [
        &op.assertions.preconditions,
        &op.assertions.capture,
        &op.target.source,
        &op.assertions.preservation,
        &op.assertions.cleanup,
    ];
    if sources
        .iter()
        .map(|s| &s.path)
        .collect::<BTreeSet<_>>()
        .len()
        != sources.len()
    {
        return Err(invariant(
            "V3 envelope segments must have distinct source paths",
        ));
    }
    let mut envelope = Vec::new();
    let mut segments = Vec::new();
    for source in sources {
        let bytes = bound_source(repository, source)?;
        if bytes.is_empty()
            || bytes.contains(&0)
            || std::str::from_utf8(&bytes).is_err()
            || !bytes.ends_with(b"\n")
        {
            return Err(invariant(
                "V3 SQL segments must be nonempty NUL-free UTF-8 ending in a newline; no rewriting is permitted",
            ));
        }
        if envelope
            .len()
            .checked_add(bytes.len())
            .is_none_or(|n| n > MAX_ENVELOPE_BYTES)
        {
            return Err(invariant("V3 envelope exceeds its byte bound"));
        }
        segments.push(Segment {
            source: source.clone(),
            offset: envelope.len(),
            length: bytes.len(),
        });
        envelope.extend_from_slice(&bytes);
    }
    Ok(Compiled {
        declaration: op.clone(),
        compiler_id: COMPILER_ID.to_owned(),
        envelope_sha256: sha256(&envelope),
        envelope_length: envelope.len(),
        segments,
        historical_sequences,
        scheduled_targets,
    })
}

#[cfg(test)]
mod tests;
