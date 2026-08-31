use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::EvidenceClass;

pub const WORKSPACE_D1_FOUNDER_CANARY_OWNER_REPOSITORY: &str = "mln-web";
pub const WORKSPACE_D1_FOUNDER_CANARY_CONTRACT_ID: &str =
    "mln-web.workspace-d1-old-worker-canary-v1";
pub const WORKSPACE_D1_FOUNDER_CANARY_CONTRACT_VERSION: u8 = 1;

/// One append-only migration file bound by a workspace-owned D1 operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceD1MigrationFileV1 {
    pub path: String,
    pub sha256: String,
}

/// One immutable remote-ledger identity derived from a tracked workspace
/// migration manifest. Baseline entries need not have local SQL files because
/// they are readback authority, not inputs to the sole pending migration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceD1MigrationLedgerEntryV1 {
    pub sequence: u64,
    pub name: String,
    pub sha256: String,
}

/// Closed manifest-selected extension of the workspace D1 migration contract.
/// The outer contract continues to own the target file and common execution
/// policy; this projection distinguishes the remote baseline from that target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct WorkspaceD1ManifestMigrationContractV1 {
    pub manifest_path: String,
    pub manifest_sha256: String,
    pub account_id: String,
    pub profile_id: String,
    pub database_name: String,
    pub database_id: String,
    pub baseline_start_sequence: u64,
    pub baseline_end_sequence: u64,
    pub baseline: Vec<WorkspaceD1MigrationLedgerEntryV1>,
    pub baseline_digest: String,
    pub target_sequence: u64,
    pub target_git_blob_oid: String,
    pub migrations_pattern: String,
    pub ledger_table: String,
    pub ledger_name: String,
    pub wrangler_cli_sha256: String,
    pub full_export_capability_id: String,
    pub require_exact_post_ledger: bool,
    pub forbidden_future_sequences: Vec<u64>,
    pub require_exact_schema_sql: bool,
    pub require_foreign_key_check_empty: bool,
    pub require_integrity_check_ok: bool,
    pub require_unchanged_worker_identity: bool,
    pub require_old_worker_compatibility: bool,
}

pub(crate) fn target_is_immediate_successor(baseline_end: u64, target: u64) -> bool {
    baseline_end.checked_add(1) == Some(target)
}

#[cfg(test)]
mod tests {
    use super::target_is_immediate_successor;

    #[test]
    fn manifest_target_successor_fails_closed_at_u64_max() {
        assert!(target_is_immediate_successor(u64::MAX - 1, u64::MAX));
        assert!(!target_is_immediate_successor(u64::MAX, 0));
        assert!(!target_is_immediate_successor(u64::MAX, u64::MAX));
    }
}

/// One exact schema object definition derived from reviewed migration bytes.
/// The definition is public source material, not provider output; its digest
/// prevents a caller from pairing a reviewed object name with different SQL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceD1ExactObjectAssertionV1 {
    pub object_type: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table: Option<String>,
    pub definition: String,
    pub definition_sha256: String,
}

/// A compiler-owned post-migration assertion. Optional fields are validated
/// against `kind`; callers cannot supply SQL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceD1SchemaAssertionV1 {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact_object: Option<WorkspaceD1ExactObjectAssertionV1>,
}

/// One exact before/after comparison derived from two independently
/// authenticated live-read receipts around a single attempted provider
/// operation. Equal semantic state is required; receipt identity equality is
/// forbidden because one observation cannot prove a temporal delta.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceD1ZeroDeltaComparisonV1 {
    pub observation: String,
    pub attempted_operation_id: String,
    pub attempted_plan_hash: String,
    pub before_proof_hash: String,
    pub before_evidence_hash: String,
    pub before_observed_at: DateTime<Utc>,
    pub after_proof_hash: String,
    pub after_evidence_hash: String,
    pub after_observed_at: DateTime<Utc>,
    pub semantic_state_sha256: String,
    pub zero_delta: bool,
}

/// Provider-isolated qualification body stored through
/// `EvidenceV1::PostChangeVerification`. This is the one atomicity join for a
/// workspace D1 migration; individual child reads remain `OperationalProofV1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct WorkspaceD1AtomicityQualificationV1 {
    pub schema_version: u8,
    pub kind: String,
    pub evidence_class: EvidenceClass,
    pub qualification_id: String,
    pub cfctl_candidate_hash: String,
    pub repository_head: String,
    pub operation_pack_sha256: String,
    pub catalog_hash: String,
    pub account_id: String,
    pub profile_id: String,
    pub credential_generation_id: String,
    pub isolated_database_id: String,
    pub isolated_database_identity_hash: String,
    pub wrangler_version: String,
    pub wrangler_cli_sha256: String,
    pub synthetic_migration_sha256: String,
    pub create_database_operation_id: String,
    pub create_database_plan_hash: String,
    pub get_database_proof_hash: String,
    pub get_database_evidence_hash: String,
    pub success_apply_operation_id: String,
    pub success_apply_plan_hash: String,
    pub ddl_failure_apply_operation_id: String,
    pub ddl_failure_apply_plan_hash: String,
    pub ledger_failure_apply_operation_id: String,
    pub ledger_failure_apply_plan_hash: String,
    pub full_export_proof_hash: String,
    pub full_export_evidence_hash: String,
    pub bookmark_proof_hash: String,
    pub bookmark_evidence_hash: String,
    pub restore_operation_id: String,
    pub restore_plan_hash: String,
    pub delete_database_operation_id: String,
    pub delete_database_plan_hash: String,
    pub create_database_evidence_hash: String,
    pub restore_evidence_hash: String,
    pub delete_database_evidence_hash: String,
    pub success_outcome_evidence_hash: String,
    pub ddl_failure_outcome_evidence_hash: String,
    pub ddl_failure_schema_delta: WorkspaceD1ZeroDeltaComparisonV1,
    pub ddl_failure_ledger_delta: WorkspaceD1ZeroDeltaComparisonV1,
    pub ledger_failure_outcome_evidence_hash: String,
    pub ledger_failure_schema_delta: WorkspaceD1ZeroDeltaComparisonV1,
    pub ledger_failure_ledger_delta: WorkspaceD1ZeroDeltaComparisonV1,
    pub cleanup_proof_hash: String,
    pub cleanup_evidence_hash: String,
    pub success_passed: bool,
    pub ddl_failure_observed: bool,
    pub ledger_failure_observed: bool,
    pub cleanup_database_absent: bool,
    pub completed_at: DateTime<Utc>,
}

/// Founder-owned behavioral canary receipt that cfctl may authenticate,
/// validate, and bind under the explicit cross-repository contract fields.
/// cfctl owns only the identity join; endpoint and request semantics remain in
/// the Founder workspace that produced the receipt under the authenticated contract.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceD1OldWorkerCanaryV1 {
    pub schema_version: u8,
    pub kind: String,
    pub evidence_class: EvidenceClass,
    pub owner_repository: String,
    pub cross_repository_contract_id: String,
    pub cross_repository_contract_version: u8,
    pub capability_id: String,
    pub workspace_contract_sha256: String,
    pub cfctl_candidate_hash: String,
    pub repository_head: String,
    pub operation_pack_sha256: String,
    pub catalog_hash: String,
    pub account_id: String,
    pub profile_id: String,
    pub credential_generation_id: String,
    pub database_id: String,
    pub migration_sha256: String,
    pub migration_operation_id: String,
    pub migration_plan_hash: String,
    pub migration_apply_evidence_hash: String,
    pub worker_script_name: String,
    pub worker_deployment_operation_id: String,
    pub worker_deployment_plan_hash: String,
    pub deployments_read_proof_hash: String,
    pub deployments_read_evidence_hash: String,
    pub version_detail_proof_hash: String,
    pub version_detail_evidence_hash: String,
    pub settings_proof_hash: String,
    pub settings_evidence_hash: String,
    pub deployment_id: String,
    pub version_id: String,
    pub request_sha256: String,
    pub result_sha256: String,
    pub semantic_assertions_sha256: String,
    pub declared_evidence_hashes: BTreeMap<String, String>,
    pub disposition: String,
    pub passed: bool,
    pub observed_at: DateTime<Utc>,
    pub canary_receipt_sha256: String,
    pub worker_identity_evidence_sha256: String,
}

/// Content-addressed evidence identities copied into the workspace adapter
/// target and `PlanV2` resource observations. Values are hashes only; evidence
/// bodies remain in the durable evidence store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceD1EvidenceJoinsV1 {
    pub atomicity_qualification_evidence_hash: String,
    pub old_worker_canary_evidence_hash: String,
    pub worker_deployments_evidence_hash: String,
    pub worker_version_evidence_hash: String,
    pub worker_settings_evidence_hash: String,
    pub worker_deployment_plan_hash: String,
}

/// Exact repository authority serialized into a workspace-owned D1 migration
/// plan. Provider identity and the fresh recovery proof are bound separately
/// in the plan adapter target because they are just-in-time inputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceD1MigrationContractV1 {
    pub repository_root: String,
    pub repository_head: String,
    pub repository_origin: String,
    pub operation_pack_path: String,
    pub operation_pack_sha256: String,
    pub config_template_path: String,
    pub config_template_sha256: String,
    pub production_config_path: String,
    pub migrations_dir: String,
    pub database_binding: String,
    pub wrangler_version: String,
    pub migrations: Vec<WorkspaceD1MigrationFileV1>,
    pub assertions: Vec<WorkspaceD1SchemaAssertionV1>,
    pub recovery_capability_id: String,
    pub recovery_max_age_seconds: u64,
    pub rollback_capability_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_migration: Option<WorkspaceD1ManifestMigrationContractV1>,
}

/// A workspace-owned D1 policy projection. The private SQL projection is
/// staged out of band; this contract contains only repository authority,
/// compiler-owned readback identifiers, and recovery requirements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceD1PolicyProjectionContractV1 {
    pub repository_root: String,
    pub repository_head: String,
    pub repository_origin: String,
    pub operation_pack_path: String,
    pub operation_pack_sha256: String,
    pub config_template_path: String,
    pub config_template_sha256: String,
    pub production_config_path: String,
    pub database_binding: String,
    pub wrangler_version: String,
    pub route_table: String,
    pub route_policy_sha_column: String,
    pub runtime_state_table: String,
    pub runtime_state_key_column: String,
    pub runtime_state_value_column: String,
    pub active_policy_key: String,
    pub desired_state_digest_key: String,
    pub projection_digest_key: String,
    pub recovery_capability_id: String,
    pub recovery_max_age_seconds: u64,
    pub rollback_capability_id: String,
}

/// Repository-owned contract for activating one compiler-produced Maildesk
/// reply admission. Candidate bytes remain in a private staged file; plans
/// carry only immutable digests and the distinct logical activation identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceD1ReplyAdmissionContractV1 {
    pub operation_kind: String,
    pub repository_root: String,
    pub repository_head: String,
    pub repository_origin: String,
    pub operation_pack_path: String,
    pub operation_pack_sha256: String,
    pub compiler_path: String,
    pub compiler_sha256: String,
    pub compiler_runtime: String,
    pub compiler_runtime_version: String,
    pub compiler_runtime_sha256: String,
    pub config_template_path: String,
    pub config_template_sha256: String,
    pub production_config_path: String,
    pub database_binding: String,
    pub wrangler_version: String,
    pub admission_table: String,
    pub input_contract: String,
    pub mutation_projection: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_projection: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_parameters: Vec<String>,
    pub recovery_capability_id: String,
    pub recovery_max_age_seconds: u64,
    pub rollback_capability_id: String,
}

/// Repository-bound, caller-invariant D1 evidence projection. The committed
/// query is executed only inside cfctl and its rows are reduced to the typed,
/// body-free `MaildeskD1EvidenceV1` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceD1EvidenceContractV1 {
    pub repository_root: String,
    pub repository_head: String,
    pub repository_origin: String,
    pub operation_pack_path: String,
    pub operation_pack_sha256: String,
    pub config_template_path: String,
    pub config_template_sha256: String,
    pub production_config_path: String,
    pub database_binding: String,
    pub wrangler_version: String,
    pub projection: String,
    pub query_sha256: String,
}
