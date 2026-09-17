//! Generic workspace-owned pack loader (`schema_version = 2`).
//!
//! cfctl binds registration, clean HEAD (for execute), the committed pack,
//! and hashing. Application acceptance stays on existing typed validators
//! until semantic equivalence tests pass.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use cfctl_core::{CapabilityV1, WorkspaceOperationContractV1};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::{
    Result, WorkspaceError, git_blob, git_optional, operation_identity::WorkspaceOperationLoad,
    register_repository,
};

const OPERATIONS_PREFIX: &str = ".cfctl/operations";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct PackV2 {
    schema_version: u8,
    operation: Vec<OperationV2>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct OperationV2 {
    id: String,
    title: String,
    description: String,
    substrate: SubstrateV2,
    effect: EffectV2,
    #[serde(default)]
    input: Vec<InputV2>,
    verification: VerificationV2,
    #[serde(default)]
    evidence: Option<EvidenceV2>,
    #[serde(default)]
    projection: Option<ProjectionV2>,
    #[serde(default)]
    compensation: Option<CompensationV2>,
    #[serde(default)]
    compiler: Option<CompilerV2>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct SubstrateV2 {
    adapter: String,
    #[serde(default)]
    config_template: Option<String>,
    #[serde(default)]
    production_config: Option<String>,
    #[serde(default)]
    database_binding: Option<String>,
    #[serde(default)]
    tool: Option<String>,
    #[serde(default)]
    tool_version: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct EffectV2 {
    mutates: bool,
    #[serde(default)]
    performs_on_call: bool,
    #[serde(default)]
    tables: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct InputV2 {
    name: String,
    #[serde(rename = "type")]
    value_type: String,
    #[serde(default)]
    required: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct VerificationV2 {
    strategy: VerificationStrategyV2,
    #[serde(default)]
    digest: Vec<DigestV2>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum VerificationStrategyV2 {
    RowShape,
    AssertionRows,
    DigestReadback,
    CardinalityDigest,
}

impl VerificationStrategyV2 {
    fn as_str(self) -> &'static str {
        match self {
            Self::RowShape => "row_shape",
            Self::AssertionRows => "assertion_rows",
            Self::DigestReadback => "digest_readback",
            Self::CardinalityDigest => "cardinality_digest",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct DigestV2 {
    key: String,
    source: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct EvidenceV2 {
    adapter: String,
    #[serde(default)]
    required_keys: Vec<String>,
    #[serde(default)]
    exact_keys: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct ProjectionV2 {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    columns: Vec<String>,
    #[serde(default)]
    raw_digest_columns: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct CompensationV2 {
    #[serde(default)]
    recovery_capability_id: Option<String>,
    #[serde(default)]
    recovery_max_age_seconds: Option<u64>,
    #[serde(default)]
    rollback_capability_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct CompilerV2 {
    path: String,
    sha256: String,
    runtime: String,
    runtime_version: String,
    runtime_sha256: String,
    input_contract: String,
}

pub(super) fn load_selected(
    candidates: &[PathBuf],
    capability_id: &str,
    mode: WorkspaceOperationLoad,
) -> Result<Option<CapabilityV1>> {
    let mut matches = Vec::new();
    for candidate in candidates {
        for pack_path in committed_pack_paths(candidate)? {
            let Some(bytes) = git_blob(candidate, &pack_path)? else {
                continue;
            };
            if !pack_contains_id(&bytes, capability_id)? {
                continue;
            }
            let mut selected = BTreeMap::new();
            register_repository(candidate, &mut selected)?;
            let Some(repository) = selected.into_values().next() else {
                continue;
            };
            if let Some(capability) = bind_v2(&repository, capability_id, mode, &pack_path, &bytes)?
            {
                matches.push(capability);
            }
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

fn committed_pack_paths(repository: &Path) -> Result<Vec<PathBuf>> {
    let Some(listing) = git_optional(
        repository,
        &["ls-tree", "-r", "--name-only", "HEAD", OPERATIONS_PREFIX],
    )?
    else {
        return Ok(Vec::new());
    };
    Ok(listing
        .lines()
        .filter(|line| {
            line.starts_with(OPERATIONS_PREFIX)
                && Path::new(line)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("toml"))
        })
        .map(PathBuf::from)
        .collect())
}

fn pack_contains_id(bytes: &[u8], capability_id: &str) -> Result<bool> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| invariant("committed operation pack is not UTF-8".to_owned()))?;
    let value: toml::Value = toml::from_str(text)
        .map_err(|error| invariant(format!("committed operation pack is invalid: {error}")))?;
    Ok(value
        .get("schema_version")
        .and_then(toml::Value::as_integer)
        == Some(2)
        && value
            .get("operation")
            .and_then(toml::Value::as_array)
            .is_some_and(|operations| {
                operations.iter().any(|operation| {
                    operation.get("id").and_then(toml::Value::as_str) == Some(capability_id)
                })
            }))
}

fn bind_v2(
    repository: &super::RepositoryNode,
    capability_id: &str,
    mode: WorkspaceOperationLoad,
    pack_path: &Path,
    pack_bytes: &[u8],
) -> Result<Option<CapabilityV1>> {
    let pack: PackV2 = toml::from_str(
        std::str::from_utf8(pack_bytes)
            .map_err(|_| invariant("workspace operation pack is not UTF-8"))?,
    )
    .map_err(|error| invariant(format!("workspace operation pack is invalid: {error}")))?;
    if pack.schema_version != 2 {
        return Ok(None);
    }
    let Some(operation) = pack
        .operation
        .iter()
        .find(|operation| operation.id == capability_id)
    else {
        return Ok(None);
    };
    if mode.requires_clean_worktree() && repository.git.dirty {
        return Err(invariant(format!(
            "workspace operation repository `{}` must be clean",
            repository.path.display()
        )));
    }
    let head = repository
        .git
        .head
        .as_deref()
        .filter(|value| lower_hex(value, 40))
        .ok_or_else(|| invariant("workspace operation repository has no canonical HEAD"))?;
    let origin = git_optional(&repository.path, &["config", "--get", "remote.origin.url"])?
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invariant("workspace operation repository has no origin"))?;
    let bound = WorkspaceOperationContractV1 {
        repository_root: repository.path.display().to_string(),
        repository_head: head.to_owned(),
        repository_origin: origin.clone(),
        operation_pack_path: pack_path.display().to_string(),
        operation_pack_sha256: format!("sha256:{}", hex::encode(Sha256::digest(pack_bytes))),
        id: operation.id.clone(),
        substrate_adapter: operation.substrate.adapter.clone(),
        mutates: operation.effect.mutates,
        verification_strategy: operation.verification.strategy.as_str().to_owned(),
    };
    if bound.id != capability_id || bound.verification_strategy.is_empty() {
        return Err(invariant(
            "workspace operation identity drifted during bind",
        ));
    }
    bind_axes(
        repository, mode, pack_path, pack_bytes, head, origin, operation,
    )
}

fn bind_axes(
    repository: &super::RepositoryNode,
    mode: WorkspaceOperationLoad,
    pack_path: &Path,
    pack_bytes: &[u8],
    head: &str,
    origin: String,
    operation: &OperationV2,
) -> Result<Option<CapabilityV1>> {
    // Four axes, not a kind enum. Evidence is d1 + non-mutating + row_shape.
    // Typed Maildesk validators remain authoritative (row_shape is not enough).
    if operation.substrate.adapter == "d1"
        && !operation.effect.mutates
        && matches!(
            operation.verification.strategy,
            VerificationStrategyV2::RowShape
        )
        && operation.compiler.is_none()
    {
        let declaration =
            super::d1_evidence::OperationDeclaration {
                id: operation.id.clone(),
                title: operation.title.clone(),
                description: operation.description.clone(),
                config_template: operation.substrate.config_template.clone().ok_or_else(|| {
                    invariant("workspace D1 evidence pack omitted config_template")
                })?,
                production_config: operation.substrate.production_config.clone().ok_or_else(
                    || invariant("workspace D1 evidence pack omitted production_config"),
                )?,
                database_binding: operation.substrate.database_binding.clone().ok_or_else(
                    || invariant("workspace D1 evidence pack omitted database_binding"),
                )?,
                wrangler_version: operation
                    .substrate
                    .tool_version
                    .clone()
                    .ok_or_else(|| invariant("workspace D1 evidence pack omitted tool_version"))?,
                projection: operation
                    .projection
                    .as_ref()
                    .and_then(|projection| projection.name.clone())
                    .ok_or_else(|| {
                        invariant("workspace D1 evidence pack omitted projection.name")
                    })?,
            };
        if operation
            .substrate
            .tool
            .as_deref()
            .is_some_and(|tool| tool != "wrangler")
        {
            return Err(invariant(
                "workspace D1 evidence pack tool must be wrangler",
            ));
        }
        return super::d1_evidence::bind_declared(
            repository,
            mode,
            &pack_path.display().to_string(),
            pack_bytes,
            head,
            origin,
            &declaration,
        );
    }
    Err(invariant(format!(
        "workspace operation `{}` declares axes with no typed binder; existing validators remain authoritative",
        operation.id
    )))
}

fn invariant(message: impl Into<String>) -> WorkspaceError {
    WorkspaceError::DiscoveryInvariant(message.into())
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::{fs, process::Command};
    use tempfile::TempDir;

    fn git(root: &Path, arguments: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(arguments)
            .status()
            .expect("git command");
        assert!(status.success());
    }

    const V2_EVIDENCE: &str = r#"schema_version = 2

[[operation]]
id = "star-maildesk-cf.d1-evidence-read"
title = "Read Maildesk D1 evidence"
description = "Read one compiler-owned body-free evidence projection."

[operation.substrate]
adapter = "d1"
config_template = "wrangler.toml"
production_config = "wrangler.production.toml"
database_binding = "DB"
tool = "wrangler"
tool_version = "4.120.1"

[operation.effect]
mutates = false
performs_on_call = true

[operation.verification]
strategy = "row_shape"

[operation.projection]
name = "maildesk_v1"
columns = ["active_policy_digest"]
"#;

    fn fixture(pack: &str) -> TempDir {
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
                "https://example.com/star-maildesk-cf.git",
            ],
        );
        fs::create_dir_all(root.path().join(".cfctl/operations")).expect("pack dir");
        fs::write(
            root.path().join("wrangler.toml"),
            "name = \"template\"\n[[d1_databases]]\nbinding = \"DB\"\ndatabase_name = \"template-db\"\ndatabase_id = \"00000000-0000-0000-0000-000000000000\"\n",
        )
        .expect("config");
        fs::write(root.path().join(".cfctl/operations/d1-evidence.toml"), pack).expect("pack");
        git(root.path(), &["add", "."]);
        git(root.path(), &["commit", "-qm", "fixture"]);
        root
    }

    #[test]
    fn v2_evidence_pack_still_uses_typed_maildesk_validators() {
        let root = fixture(V2_EVIDENCE);
        let capability = crate::inspect_workspace_operation_capability(
            &[root.path().to_path_buf()],
            "star-maildesk-cf.d1-evidence-read",
        )
        .expect("inspect")
        .expect("capability");
        let contract = capability
            .workspace_d1_evidence
            .expect("typed evidence contract");
        assert_eq!(contract.projection, "maildesk_v1");
        assert_eq!(
            contract.query_sha256,
            format!(
                "sha256:{}",
                hex::encode(Sha256::digest(
                    crate::MAILDESK_D1_EVIDENCE_SQL_V1.as_bytes()
                ))
            )
        );
    }

    #[test]
    fn row_shape_cannot_replace_typed_projection_identity() {
        let pack = V2_EVIDENCE.replace("name = \"maildesk_v1\"", "name = \"caller_sql\"");
        let root = fixture(&pack);
        let error = crate::inspect_workspace_operation_capability(
            &[root.path().to_path_buf()],
            "star-maildesk-cf.d1-evidence-read",
        )
        .expect_err("typed validator remains authoritative");
        assert!(
            error.to_string().contains("fixed Maildesk projection"),
            "{error}"
        );
    }

    #[test]
    fn unknown_verification_strategy_fails_closed() {
        let pack =
            V2_EVIDENCE.replace("strategy = \"row_shape\"", "strategy = \"sql_from_caller\"");
        let root = fixture(&pack);
        let error = crate::inspect_workspace_operation_capability(
            &[root.path().to_path_buf()],
            "star-maildesk-cf.d1-evidence-read",
        )
        .expect_err("closed vocabulary");
        assert!(
            error.to_string().contains("invalid") || error.to_string().contains("unknown"),
            "{error}"
        );
    }

    #[test]
    fn inbound_acceptance_predicates_stay_on_typed_owner() {
        // Mapping table in docs/workspace-operation-format.md: no match /
        // multiple match / wrong identity remain owned by
        // project_inbound_acceptance. The generic loader must not admit a
        // row_shape pack that drops that projection name.
        let pack = V2_EVIDENCE
            .replace(
                "id = \"star-maildesk-cf.d1-evidence-read\"",
                "id = \"star-maildesk-cf.inbound-acceptance-read\"",
            )
            .replace("name = \"maildesk_v1\"", "name = \"row_shape_only\"");
        let root = fixture(&pack);
        let error = crate::inspect_workspace_operation_capability(
            &[root.path().to_path_buf()],
            "star-maildesk-cf.inbound-acceptance-read",
        )
        .expect_err("inbound acceptance stays on typed validators");
        assert!(
            error.to_string().contains("fixed Maildesk projection"),
            "{error}"
        );
    }

    #[test]
    fn remaining_axes_fail_closed_until_typed_cutover() {
        let pack = V2_EVIDENCE
            .replace("mutates = false", "mutates = true")
            .replace("strategy = \"row_shape\"", "strategy = \"digest_readback\"");
        let root = fixture(&pack);
        let error = crate::inspect_workspace_operation_capability(
            &[root.path().to_path_buf()],
            "star-maildesk-cf.d1-evidence-read",
        )
        .expect_err("policy/migration/reply stay on typed loaders");
        assert!(error.to_string().contains("no typed binder"), "{error}");
    }
}
