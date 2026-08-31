use std::collections::{BTreeMap, BTreeSet};

use cfctl_cloudflare::{CallInput, CloudflareResponseV1};
use cfctl_core::{
    EvidenceClass, EvidenceV1, OperationalProofOutcomeV1, PlanStatus, PlanV2, TransactionStageV1,
    WorkspaceD1AtomicityQualificationV1, WorkspaceD1EvidenceJoinsV1,
    WorkspaceD1MigrationContractV1, WorkspaceD1OldWorkerCanaryV1, hash_value,
};
use cfctl_storage::StoredPlanRecord;
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use serde_json::{Value, json};

use super::prelude::{CliError, PlanV1, Result, StateStore};

pub(super) const ATOMICITY_QUALIFICATION_PRECONDITION: &str =
    "workspace_d1_atomicity_qualification";
pub(super) const OLD_WORKER_CANARY_PRECONDITION: &str = "workspace_d1_old_worker_canary";
pub(super) const WORKER_DEPLOYMENTS_PRECONDITION: &str = "workspace_d1_worker_deployments";
pub(super) const WORKER_VERSION_PRECONDITION: &str = "workspace_d1_worker_version";
pub(super) const WORKER_SETTINGS_PRECONDITION: &str = "workspace_d1_worker_settings";
pub(super) const WORKER_DEPLOYMENT_PLAN_PRECONDITION: &str = "workspace_d1_worker_deployment_plan";
const EVIDENCE_JOIN_PRECONDITIONS: [&str; 6] = [
    ATOMICITY_QUALIFICATION_PRECONDITION,
    OLD_WORKER_CANARY_PRECONDITION,
    WORKER_DEPLOYMENTS_PRECONDITION,
    WORKER_VERSION_PRECONDITION,
    WORKER_SETTINGS_PRECONDITION,
    WORKER_DEPLOYMENT_PLAN_PRECONDITION,
];
const EVIDENCE_JOIN_NAMESPACE_PREFIX: &str = "workspace_d1_";
const REQUIRED_CANARY_EVIDENCE: [&str; 6] = [
    "diagz_build_after",
    "diagz_build_before",
    "post_state",
    "pre_state",
    "recovery_bookmark",
    "schema_ledger",
];

pub(super) struct AtomicityExpectations<'a> {
    pub cfctl_candidate_hash: &'a str,
    pub repository_head: &'a str,
    pub operation_pack_sha256: &'a str,
    pub catalog_hash: &'a str,
    pub account_id: &'a str,
    pub profile_id: &'a str,
    pub credential_generation_id: &'a str,
    pub wrangler_version: &'a str,
    pub wrangler_cli_sha256: &'a str,
    pub synthetic_migration_sha256: &'a str,
    pub plans: &'a [PlanExpectation<'a>],
    pub proofs: &'a [ProofExpectation<'a>],
}

pub(super) struct PlanExpectation<'a> {
    pub role: &'a str,
    pub operation_id: &'a str,
    pub plan_content_hash: &'a str,
    pub pins_hash: &'a str,
    pub capability_id: &'a str,
    pub catalog_hash: &'a str,
    pub profile_id: &'a str,
    pub account_id: &'a str,
    pub credential_generation_id: &'a str,
    pub target_hash: &'a str,
    pub expected_status: PlanStatus,
    pub expected_stage: TransactionStageV1,
    pub expected_evidence_class: EvidenceClass,
    pub evidence_hash: &'a str,
}

pub(super) struct ProofExpectation<'a> {
    pub role: &'a str,
    pub proof_hash: &'a str,
    pub evidence_hash: &'a str,
    pub capability_id: &'a str,
    pub catalog_hash: &'a str,
    pub input_hash: &'a str,
    pub build_identity_hash: &'a str,
    pub profile_id: &'a str,
    pub account_id: &'a str,
    pub credential_generation_id: &'a str,
    pub expected_outcome: OperationalProofOutcomeV1,
}

pub(super) struct CanaryExpectations<'a> {
    pub capability_id: &'a str,
    pub workspace_contract_sha256: &'a str,
    pub cfctl_candidate_hash: &'a str,
    pub repository_head: &'a str,
    pub operation_pack_sha256: &'a str,
    pub catalog_hash: &'a str,
    pub account_id: &'a str,
    pub profile_id: &'a str,
    pub credential_generation_id: &'a str,
    pub database_id: &'a str,
    pub migration_sha256: &'a str,
    pub migration_operation_id: &'a str,
    pub migration_plan_hash: &'a str,
    pub migration_apply_evidence_hash: &'a str,
    pub worker_script_name: &'a str,
    pub deployment_id: &'a str,
    pub version_id: &'a str,
    pub worker_plan: PlanExpectation<'a>,
    pub worker_proofs: &'a [ProofExpectation<'a>],
}

struct OwnedPlanExpectation {
    role: &'static str,
    operation_id: String,
    plan_content_hash: String,
    pins_hash: String,
    capability_id: &'static str,
    catalog_hash: String,
    profile_id: String,
    account_id: String,
    credential_generation_id: String,
    target_hash: String,
    expected_status: PlanStatus,
    expected_stage: TransactionStageV1,
    evidence_hash: String,
    input: CallInput,
    workspace_d1_migration: Option<WorkspaceD1MigrationContractV1>,
}

impl OwnedPlanExpectation {
    fn borrowed(&self) -> PlanExpectation<'_> {
        PlanExpectation {
            role: self.role,
            operation_id: &self.operation_id,
            plan_content_hash: &self.plan_content_hash,
            pins_hash: &self.pins_hash,
            capability_id: self.capability_id,
            catalog_hash: &self.catalog_hash,
            profile_id: &self.profile_id,
            account_id: &self.account_id,
            credential_generation_id: &self.credential_generation_id,
            target_hash: &self.target_hash,
            expected_status: self.expected_status,
            expected_stage: self.expected_stage,
            expected_evidence_class: EvidenceClass::PostChangeVerification,
            evidence_hash: &self.evidence_hash,
        }
    }
}

struct OwnedProofExpectation {
    role: &'static str,
    proof_hash: String,
    evidence_hash: String,
    capability_id: &'static str,
    catalog_hash: String,
    input_hash: String,
    build_identity_hash: String,
    profile_id: String,
    account_id: String,
    credential_generation_id: String,
}

impl OwnedProofExpectation {
    fn borrowed(&self) -> ProofExpectation<'_> {
        ProofExpectation {
            role: self.role,
            proof_hash: &self.proof_hash,
            evidence_hash: &self.evidence_hash,
            capability_id: self.capability_id,
            catalog_hash: &self.catalog_hash,
            input_hash: &self.input_hash,
            build_identity_hash: &self.build_identity_hash,
            profile_id: &self.profile_id,
            account_id: &self.account_id,
            credential_generation_id: &self.credential_generation_id,
            expected_outcome: OperationalProofOutcomeV1::Succeeded,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ZeroDeltaObservationV1 {
    schema_version: u8,
    kind: String,
    observation: String,
    before_evidence_hash: String,
    after_evidence_hash: String,
}

pub(super) fn validate_atomicity_qualification(
    store: &StateStore,
    evidence: &EvidenceV1,
    expected: &AtomicityExpectations<'_>,
    now: DateTime<Utc>,
) -> Result<WorkspaceD1AtomicityQualificationV1> {
    require_post_change_evidence(evidence)?;
    let value = store.read_evidence_value(&evidence.content_hash)?;
    let receipt: WorkspaceD1AtomicityQualificationV1 = serde_json::from_value(value)
        .map_err(|_| CliError::Input("workspace D1 atomicity receipt is malformed".to_owned()))?;
    let plan_hashes = [
        &receipt.create_database_plan_hash,
        &receipt.success_apply_plan_hash,
        &receipt.ddl_failure_apply_plan_hash,
        &receipt.ledger_failure_apply_plan_hash,
        &receipt.restore_plan_hash,
        &receipt.delete_database_plan_hash,
    ];
    let outcome_hashes = [
        &receipt.success_outcome_evidence_hash,
        &receipt.ddl_failure_outcome_evidence_hash,
        &receipt.ddl_failure_zero_schema_delta_hash,
        &receipt.ddl_failure_zero_ledger_delta_hash,
        &receipt.ledger_failure_outcome_evidence_hash,
        &receipt.ledger_failure_zero_schema_delta_hash,
        &receipt.ledger_failure_zero_ledger_delta_hash,
        &receipt.cleanup_evidence_hash,
    ];
    let isolated_identity = hash_value(&json!({
        "account_id": receipt.account_id,
        "database_id": receipt.isolated_database_id,
    }))?;
    if receipt.schema_version != 1
        || receipt.kind != "workspace_d1_provider_atomicity_v1"
        || receipt.evidence_class != EvidenceClass::PostChangeVerification
        || uuid::Uuid::parse_str(&receipt.qualification_id)
            .ok()
            .is_none_or(|id| id.to_string() != receipt.qualification_id)
        || receipt.cfctl_candidate_hash != expected.cfctl_candidate_hash
        || receipt.repository_head != expected.repository_head
        || receipt.operation_pack_sha256 != expected.operation_pack_sha256
        || receipt.catalog_hash != expected.catalog_hash
        || receipt.account_id != expected.account_id
        || receipt.profile_id != expected.profile_id
        || receipt.credential_generation_id != expected.credential_generation_id
        || receipt.wrangler_version != expected.wrangler_version
        || receipt.wrangler_cli_sha256 != expected.wrangler_cli_sha256
        || receipt.synthetic_migration_sha256 != expected.synthetic_migration_sha256
        || !is_canonical_uuid(&receipt.success_apply_operation_id)
        || receipt.isolated_database_identity_hash != isolated_identity
        || !is_sha256(&receipt.cfctl_candidate_hash)
        || !is_git_oid(&receipt.repository_head)
        || !is_sha256(&receipt.operation_pack_sha256)
        || !is_sha256(&receipt.catalog_hash)
        || !is_lower_hex(&receipt.account_id, 32)
        || receipt.profile_id.is_empty()
        || !is_canonical_uuid(&receipt.credential_generation_id)
        || !is_canonical_uuid(&receipt.isolated_database_id)
        || !is_sha256(&receipt.isolated_database_identity_hash)
        || !is_sha256(&receipt.wrangler_cli_sha256)
        || !is_sha256(&receipt.synthetic_migration_sha256)
        || !plan_hashes.iter().all(|hash| is_sha256(hash))
        || plan_hashes.iter().collect::<BTreeSet<_>>().len() != plan_hashes.len()
        || !outcome_hashes.iter().all(|hash| is_sha256(hash))
        || !receipt.success_passed
        || !receipt.ddl_failure_observed
        || !receipt.ddl_failure_zero_schema_delta
        || !receipt.ddl_failure_zero_ledger_delta
        || !receipt.ledger_failure_observed
        || !receipt.ledger_failure_zero_schema_delta
        || !receipt.ledger_failure_zero_ledger_delta
        || !receipt.cleanup_database_absent
        || receipt.completed_at > now
        || evidence.generated_at < receipt.completed_at
        || evidence.generated_at > now
        || now.signed_duration_since(receipt.completed_at) > Duration::days(30)
    {
        return Err(CliError::Input(
            "workspace D1 atomicity qualification is incomplete, stale, or identity-drifted"
                .to_owned(),
        ));
    }
    validate_atomicity_children(store, &receipt, expected)?;
    Ok(receipt)
}

pub(super) fn validate_old_worker_canary(
    store: &StateStore,
    evidence: &EvidenceV1,
    expected: &CanaryExpectations<'_>,
    now: DateTime<Utc>,
) -> Result<WorkspaceD1OldWorkerCanaryV1> {
    require_post_change_evidence(evidence)?;
    let value = store.read_evidence_value(&evidence.content_hash)?;
    let receipt: WorkspaceD1OldWorkerCanaryV1 = serde_json::from_value(value)
        .map_err(|_| CliError::Input("workspace D1 old-Worker canary is malformed".to_owned()))?;
    let mut hashable = receipt.clone();
    hashable.canary_receipt_sha256.clear();
    let receipt_hash = hash_value(&serde_json::to_value(hashable)?)?;
    let worker_identity_hash = worker_identity_join_hash(&receipt)?;
    let evidence_hashes = [
        &receipt.deployments_read_evidence_hash,
        &receipt.version_detail_evidence_hash,
        &receipt.settings_evidence_hash,
        &receipt.migration_apply_evidence_hash,
        &receipt.worker_identity_evidence_sha256,
    ];
    if receipt.schema_version != 1
        || receipt.kind != "workspace_d1_old_worker_canary_v1"
        || receipt.evidence_class != EvidenceClass::PostChangeVerification
        || receipt.capability_id != expected.capability_id
        || receipt.workspace_contract_sha256 != expected.workspace_contract_sha256
        || receipt.cfctl_candidate_hash != expected.cfctl_candidate_hash
        || receipt.repository_head != expected.repository_head
        || receipt.operation_pack_sha256 != expected.operation_pack_sha256
        || receipt.catalog_hash != expected.catalog_hash
        || receipt.account_id != expected.account_id
        || receipt.profile_id != expected.profile_id
        || receipt.credential_generation_id != expected.credential_generation_id
        || receipt.database_id != expected.database_id
        || receipt.migration_sha256 != expected.migration_sha256
        || receipt.migration_operation_id != expected.migration_operation_id
        || receipt.migration_plan_hash != expected.migration_plan_hash
        || receipt.migration_apply_evidence_hash != expected.migration_apply_evidence_hash
        || receipt.worker_script_name != expected.worker_script_name
        || receipt.deployment_id != expected.deployment_id
        || receipt.version_id != expected.version_id
        || receipt.worker_deployment_operation_id != expected.worker_plan.operation_id
        || receipt.worker_deployment_plan_hash != expected.worker_plan.plan_content_hash
        || receipt.worker_identity_evidence_sha256 != worker_identity_hash
        || !is_sha256(&receipt.cfctl_candidate_hash)
        || !is_git_oid(&receipt.repository_head)
        || !is_sha256(&receipt.operation_pack_sha256)
        || !is_sha256(&receipt.catalog_hash)
        || !is_lower_hex(&receipt.account_id, 32)
        || receipt.profile_id.is_empty()
        || !is_canonical_uuid(&receipt.credential_generation_id)
        || !is_canonical_uuid(&receipt.database_id)
        || !is_canonical_uuid(&receipt.migration_operation_id)
        || receipt.worker_script_name.is_empty()
        || receipt.worker_script_name.len() > 255
        || !is_canonical_uuid(&receipt.worker_deployment_operation_id)
        || !is_sha256(&receipt.migration_sha256)
        || !is_sha256(&receipt.semantic_assertions_sha256)
        || receipt.canary_receipt_sha256 != receipt_hash
        || receipt.disposition != "pass"
        || !receipt.passed
        || !is_canonical_uuid(&receipt.deployment_id)
        || !is_canonical_uuid(&receipt.version_id)
        || !is_sha256(&receipt.migration_plan_hash)
        || !is_sha256(&receipt.worker_deployment_plan_hash)
        || !is_sha256(&receipt.request_sha256)
        || !is_sha256(&receipt.result_sha256)
        || !evidence_hashes.iter().all(|hash| is_sha256(hash))
        || receipt.declared_evidence_hashes.len() != REQUIRED_CANARY_EVIDENCE.len()
        || REQUIRED_CANARY_EVIDENCE
            .iter()
            .any(|name| !receipt.declared_evidence_hashes.contains_key(*name))
        || receipt
            .declared_evidence_hashes
            .iter()
            .any(|(name, hash)| !safe_claim_name(name) || !is_sha256(hash))
        || receipt.observed_at > now
        || evidence.generated_at < receipt.observed_at
        || evidence.generated_at > now
        || now.signed_duration_since(receipt.observed_at) > Duration::minutes(15)
    {
        return Err(CliError::Input(
            "workspace D1 old-Worker canary is missing, stale, failed, or identity-drifted"
                .to_owned(),
        ));
    }
    validate_plan(store, &expected.worker_plan, expected.cfctl_candidate_hash)?;
    if expected.worker_plan.capability_id != "worker-deployment-plan"
        || expected.worker_plan.catalog_hash != receipt.catalog_hash
        || expected.worker_plan.profile_id != receipt.profile_id
        || expected.worker_plan.account_id != receipt.account_id
        || expected.worker_plan.credential_generation_id != receipt.credential_generation_id
    {
        return Err(CliError::Input(
            "workspace D1 Worker deployment plan authority drifted".to_owned(),
        ));
    }
    validate_worker_proofs(store, &receipt, expected)?;
    Ok(receipt)
}

#[allow(clippy::too_many_lines)]
fn validate_atomicity_children(
    store: &StateStore,
    receipt: &WorkspaceD1AtomicityQualificationV1,
    expected: &AtomicityExpectations<'_>,
) -> Result<()> {
    let plan_claims = [
        (
            "create_database",
            receipt.create_database_operation_id.as_str(),
            receipt.create_database_plan_hash.as_str(),
            receipt.create_database_evidence_hash.as_str(),
        ),
        (
            "success_apply",
            receipt.success_apply_operation_id.as_str(),
            receipt.success_apply_plan_hash.as_str(),
            receipt.success_outcome_evidence_hash.as_str(),
        ),
        (
            "ddl_failure_apply",
            receipt.ddl_failure_apply_operation_id.as_str(),
            receipt.ddl_failure_apply_plan_hash.as_str(),
            receipt.ddl_failure_outcome_evidence_hash.as_str(),
        ),
        (
            "ledger_failure_apply",
            receipt.ledger_failure_apply_operation_id.as_str(),
            receipt.ledger_failure_apply_plan_hash.as_str(),
            receipt.ledger_failure_outcome_evidence_hash.as_str(),
        ),
        (
            "restore",
            receipt.restore_operation_id.as_str(),
            receipt.restore_plan_hash.as_str(),
            receipt.restore_evidence_hash.as_str(),
        ),
        (
            "delete_database",
            receipt.delete_database_operation_id.as_str(),
            receipt.delete_database_plan_hash.as_str(),
            receipt.delete_database_evidence_hash.as_str(),
        ),
    ];
    if expected.plans.len() != plan_claims.len() {
        return Err(CliError::Input(
            "workspace D1 atomicity plan role matrix is incomplete".to_owned(),
        ));
    }
    for (role, operation_id, plan_hash, evidence_hash) in plan_claims {
        let expectation = expected
            .plans
            .iter()
            .find(|candidate| candidate.role == role)
            .ok_or_else(|| {
                CliError::Input("workspace D1 atomicity plan role is missing".to_owned())
            })?;
        if operation_id != expectation.operation_id
            || plan_hash != expectation.plan_content_hash
            || evidence_hash != expectation.evidence_hash
            || expectation.catalog_hash != receipt.catalog_hash
            || expectation.profile_id != receipt.profile_id
            || expectation.account_id != receipt.account_id
            || expectation.credential_generation_id != receipt.credential_generation_id
        {
            return Err(CliError::Input(
                "workspace D1 atomicity plan identity drifted".to_owned(),
            ));
        }
        validate_plan(store, expectation, receipt.cfctl_candidate_hash.as_str())?;
    }

    let proof_claims = [
        (
            "get_database",
            receipt.get_database_proof_hash.as_str(),
            receipt.get_database_evidence_hash.as_str(),
        ),
        (
            "full_export",
            receipt.full_export_proof_hash.as_str(),
            receipt.full_export_evidence_hash.as_str(),
        ),
        (
            "bookmark",
            receipt.bookmark_proof_hash.as_str(),
            receipt.bookmark_evidence_hash.as_str(),
        ),
        (
            "ddl_zero_schema",
            receipt.ddl_failure_zero_schema_proof_hash.as_str(),
            receipt.ddl_failure_zero_schema_delta_hash.as_str(),
        ),
        (
            "ddl_zero_ledger",
            receipt.ddl_failure_zero_ledger_proof_hash.as_str(),
            receipt.ddl_failure_zero_ledger_delta_hash.as_str(),
        ),
        (
            "ledger_zero_schema",
            receipt.ledger_failure_zero_schema_proof_hash.as_str(),
            receipt.ledger_failure_zero_schema_delta_hash.as_str(),
        ),
        (
            "ledger_zero_ledger",
            receipt.ledger_failure_zero_ledger_proof_hash.as_str(),
            receipt.ledger_failure_zero_ledger_delta_hash.as_str(),
        ),
        (
            "cleanup_absence",
            receipt.cleanup_proof_hash.as_str(),
            receipt.cleanup_evidence_hash.as_str(),
        ),
    ];
    if expected.proofs.len() != proof_claims.len() {
        return Err(CliError::Input(
            "workspace D1 atomicity proof role matrix is incomplete".to_owned(),
        ));
    }
    for (role, proof_hash, evidence_hash) in proof_claims {
        let expectation = expected
            .proofs
            .iter()
            .find(|candidate| candidate.role == role)
            .ok_or_else(|| {
                CliError::Input("workspace D1 atomicity proof role is missing".to_owned())
            })?;
        if proof_hash != expectation.proof_hash || evidence_hash != expectation.evidence_hash {
            return Err(CliError::Input(
                "workspace D1 atomicity proof identity drifted".to_owned(),
            ));
        }
        if expectation.catalog_hash != receipt.catalog_hash
            || expectation.build_identity_hash != receipt.cfctl_candidate_hash
            || expectation.profile_id != receipt.profile_id
            || expectation.account_id != receipt.account_id
            || expectation.credential_generation_id != receipt.credential_generation_id
        {
            return Err(CliError::Input(
                "workspace D1 atomicity proof authority drifted".to_owned(),
            ));
        }
        let (proof, body) = validate_proof(store, expectation)?;
        if proof.observed_at > receipt.completed_at
            || receipt
                .completed_at
                .signed_duration_since(proof.observed_at)
                > Duration::days(30)
        {
            return Err(CliError::Input(
                "workspace D1 atomicity proof is stale or postdates qualification".to_owned(),
            ));
        }
        if matches!(
            role,
            "ddl_zero_schema" | "ddl_zero_ledger" | "ledger_zero_schema" | "ledger_zero_ledger"
        ) {
            validate_zero_delta_body(store, role, body)?;
        }
    }
    Ok(())
}

fn validate_plan(
    store: &StateStore,
    expected: &PlanExpectation<'_>,
    candidate_hash: &str,
) -> Result<()> {
    let plan = match store.load_stored_plan_record(expected.operation_id)? {
        StoredPlanRecord::Current(plan) => *plan,
        _ => {
            return Err(CliError::Input(
                "workspace D1 qualification child is not one current PlanV2".to_owned(),
            ));
        }
    };
    let pins_hash = hash_value(&serde_json::to_value(&plan.pins)?)?;
    let target_hash = hash_value(&plan.plan.targets)?;
    let evidence_hash = match expected.expected_evidence_class {
        EvidenceClass::Apply => plan
            .plan
            .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
            .and_then(|artifact| artifact.get("apply_evidence_hash"))
            .and_then(Value::as_str),
        EvidenceClass::PostChangeVerification => plan
            .plan
            .transaction_artifact(TransactionStageV1::VerificationResponsePersisted)
            .and_then(|artifact| artifact.get("evidence_hash"))
            .and_then(Value::as_str),
        _ => None,
    };
    if plan.plan.operation_id != expected.operation_id
        || plan.plan.content_hash != expected.plan_content_hash
        || pins_hash != expected.pins_hash
        || plan.plan.capability.id != expected.capability_id
        || plan.plan.catalog_hash != expected.catalog_hash
        || plan.plan.profile_id != expected.profile_id
        || plan.plan.account_id != expected.account_id
        || plan.pins.credential_generation_id != expected.credential_generation_id
        || target_hash != expected.target_hash
        || plan.plan.status != expected.expected_status
        || plan.plan.transaction_stage != expected.expected_stage
        || plan.pins.build_identity_hash != candidate_hash
        || plan.pins.catalog_hash != plan.plan.catalog_hash
        || evidence_hash != Some(expected.evidence_hash)
    {
        return Err(CliError::Input(
            "workspace D1 qualification child PlanV2 drifted".to_owned(),
        ));
    }
    store.read_evidence_value(expected.evidence_hash)?;
    Ok(())
}

fn validate_proof(
    store: &StateStore,
    expected: &ProofExpectation<'_>,
) -> Result<(cfctl_core::OperationalProofV1, Value)> {
    let proof = store.load_operational_proof(expected.proof_hash)?;
    if proof.evidence.class != EvidenceClass::LiveRead
        || proof.evidence.content_hash != expected.evidence_hash
        || proof.capability_id != expected.capability_id
        || proof.catalog_hash != expected.catalog_hash
        || proof.input_hash != expected.input_hash
        || proof.build_identity_hash.as_deref() != Some(expected.build_identity_hash)
        || proof.profile_id.as_deref() != Some(expected.profile_id)
        || proof.account_id.as_deref() != Some(expected.account_id)
        || proof.credential_generation_id.as_deref() != Some(expected.credential_generation_id)
        || proof.outcome != expected.expected_outcome
    {
        return Err(CliError::Input(
            "workspace D1 operational proof context drifted".to_owned(),
        ));
    }
    let body = store.read_evidence_value(expected.evidence_hash)?;
    Ok((proof, body))
}

fn validate_zero_delta_body(store: &StateStore, role: &str, body: Value) -> Result<()> {
    let observation: ZeroDeltaObservationV1 = serde_json::from_value(body).map_err(|_| {
        CliError::Input("workspace D1 zero-delta proof body is malformed".to_owned())
    })?;
    let expected_observation = if role.ends_with("_schema") {
        "schema"
    } else {
        "ledger"
    };
    if observation.schema_version != 1
        || observation.kind != "workspace_d1_zero_delta_observation_v1"
        || observation.observation != expected_observation
        || !is_sha256(&observation.before_evidence_hash)
        || observation.before_evidence_hash != observation.after_evidence_hash
    {
        return Err(CliError::Input(
            "workspace D1 zero-delta proof did not establish exact equality".to_owned(),
        ));
    }
    store.read_evidence_value(&observation.before_evidence_hash)?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_worker_proofs(
    store: &StateStore,
    receipt: &WorkspaceD1OldWorkerCanaryV1,
    expected: &CanaryExpectations<'_>,
) -> Result<()> {
    let claims = [
        (
            "deployments",
            receipt.deployments_read_proof_hash.as_str(),
            receipt.deployments_read_evidence_hash.as_str(),
        ),
        (
            "version",
            receipt.version_detail_proof_hash.as_str(),
            receipt.version_detail_evidence_hash.as_str(),
        ),
        (
            "settings",
            receipt.settings_proof_hash.as_str(),
            receipt.settings_evidence_hash.as_str(),
        ),
    ];
    if expected.worker_proofs.len() != claims.len() {
        return Err(CliError::Input(
            "workspace D1 Worker proof role matrix is incomplete".to_owned(),
        ));
    }
    let mut deployments = None;
    let mut version = None;
    let mut settings = None;
    for (role, proof_hash, evidence_hash) in claims {
        let proof = expected
            .worker_proofs
            .iter()
            .find(|candidate| candidate.role == role)
            .ok_or_else(|| {
                CliError::Input("workspace D1 Worker proof role is missing".to_owned())
            })?;
        if proof_hash != proof.proof_hash || evidence_hash != proof.evidence_hash {
            return Err(CliError::Input(
                "workspace D1 Worker proof identity drifted".to_owned(),
            ));
        }
        let (capability_id, selectors) = match role {
            "deployments" => (
                "worker-deployments-list-deployments",
                json!({"account_id":expected.account_id,"script_name":expected.worker_script_name}),
            ),
            "version" => (
                "worker-versions-get-version-detail",
                json!({
                    "account_id":expected.account_id,
                    "script_name":expected.worker_script_name,
                    "version_id":expected.version_id,
                }),
            ),
            "settings" => (
                "worker-script-get-settings",
                json!({"account_id":expected.account_id,"script_name":expected.worker_script_name}),
            ),
            _ => unreachable!(),
        };
        let input_hash = hash_value(&serde_json::to_value(CallInput {
            selectors,
            query: json!({}),
            body: None,
            if_match: None,
            if_none_match: None,
        })?)?;
        if proof.capability_id != capability_id
            || proof.catalog_hash != receipt.catalog_hash
            || proof.input_hash != input_hash
            || proof.build_identity_hash != receipt.cfctl_candidate_hash
            || proof.profile_id != receipt.profile_id
            || proof.account_id != receipt.account_id
            || proof.credential_generation_id != receipt.credential_generation_id
        {
            return Err(CliError::Input(
                "workspace D1 Worker proof target or authority drifted".to_owned(),
            ));
        }
        let (resolved, body) = validate_proof(store, proof)?;
        if resolved.observed_at > receipt.observed_at
            || receipt
                .observed_at
                .signed_duration_since(resolved.observed_at)
                > Duration::minutes(15)
        {
            return Err(CliError::Input(
                "workspace D1 Worker proof is stale or postdates canary".to_owned(),
            ));
        }
        let response: CloudflareResponseV1 = serde_json::from_value(body).map_err(|_| {
            CliError::Input("workspace D1 Worker proof body is malformed".to_owned())
        })?;
        match role {
            "deployments" => deployments = Some(response),
            "version" => version = Some(response),
            "settings" => settings = Some(response),
            _ => unreachable!(),
        }
    }
    let settings =
        settings.ok_or_else(|| CliError::Input("Worker settings proof is missing".to_owned()))?;
    let deployments = deployments
        .ok_or_else(|| CliError::Input("Worker deployments proof is missing".to_owned()))?;
    let version =
        version.ok_or_else(|| CliError::Input("Worker version proof is missing".to_owned()))?;
    let (deployment_id, version_id) =
        super::worker_deployment::current_active_deployment_identity(&deployments.result)?;
    if !settings.success
        || !(200..300).contains(&settings.status)
        || !deployments.success
        || !(200..300).contains(&deployments.status)
        || !version.success
        || !(200..300).contains(&version.status)
        || deployment_id != expected.deployment_id
        || version_id != expected.version_id
        || version.result.get("id").and_then(Value::as_str) != Some(expected.version_id)
    {
        return Err(CliError::Input(
            "workspace D1 Worker proof body identity drifted".to_owned(),
        ));
    }
    Ok(())
}

fn resolve_plan_expectation(
    store: &StateStore,
    role: &'static str,
    operation_id: &str,
    capability_id: &'static str,
    expected_status: PlanStatus,
    expected_stage: TransactionStageV1,
) -> Result<OwnedPlanExpectation> {
    let plan = match store.load_stored_plan_record(operation_id)? {
        StoredPlanRecord::Current(plan) => *plan,
        _ => {
            return Err(CliError::Input(
                "workspace D1 qualification child is not one current PlanV2".to_owned(),
            ));
        }
    };
    let evidence_hash = plan
        .plan
        .transaction_artifact(TransactionStageV1::VerificationResponsePersisted)
        .and_then(|artifact| artifact.get("evidence_hash"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "workspace D1 qualification child verification evidence is missing".to_owned(),
            )
        })?;
    let input: CallInput = serde_json::from_value(plan.plan.input.clone()).map_err(|_| {
        CliError::Input("workspace D1 qualification child input is malformed".to_owned())
    })?;
    Ok(OwnedPlanExpectation {
        role,
        operation_id: operation_id.to_owned(),
        plan_content_hash: plan.plan.content_hash.clone(),
        pins_hash: hash_value(&serde_json::to_value(&plan.pins)?)?,
        capability_id,
        catalog_hash: plan.plan.catalog_hash.clone(),
        profile_id: plan.plan.profile_id.clone(),
        account_id: plan.plan.account_id.clone(),
        credential_generation_id: plan.pins.credential_generation_id.clone(),
        target_hash: hash_value(&plan.plan.targets)?,
        expected_status,
        expected_stage,
        evidence_hash: evidence_hash.to_owned(),
        input,
        workspace_d1_migration: plan.plan.capability.workspace_d1_migration.clone(),
    })
}

fn resolve_proof_expectation(
    store: &StateStore,
    role: &'static str,
    proof_hash: &str,
    capability_id: &'static str,
    expected_input_hash: Option<&str>,
    expected_evidence_hash: Option<&str>,
) -> Result<OwnedProofExpectation> {
    let proof = store.load_operational_proof(proof_hash)?;
    if expected_evidence_hash.is_some_and(|expected| proof.evidence.content_hash != expected) {
        return Err(CliError::Input(
            "workspace D1 operational proof does not match the plan-bound evidence identity"
                .to_owned(),
        ));
    }
    Ok(OwnedProofExpectation {
        role,
        proof_hash: proof_hash.to_owned(),
        evidence_hash: proof.evidence.content_hash,
        capability_id,
        catalog_hash: proof.catalog_hash,
        input_hash: expected_input_hash.unwrap_or(&proof.input_hash).to_owned(),
        build_identity_hash: proof.build_identity_hash.unwrap_or_default(),
        profile_id: proof.profile_id.unwrap_or_default(),
        account_id: proof.account_id.unwrap_or_default(),
        credential_generation_id: proof.credential_generation_id.unwrap_or_default(),
    })
}

fn validate_d1_plan_target(
    store: &StateStore,
    operation_id: &str,
    account_id: &str,
    database_id: &str,
) -> Result<()> {
    let plan = match store.load_stored_plan_record(operation_id)? {
        StoredPlanRecord::Current(plan) => *plan,
        _ => {
            return Err(CliError::Input(
                "workspace D1 qualification child is not one current PlanV2".to_owned(),
            ));
        }
    };
    let input: CallInput = serde_json::from_value(plan.plan.input).map_err(|_| {
        CliError::Input("workspace D1 qualification child input is malformed".to_owned())
    })?;
    if input.selectors.get("account_id").and_then(Value::as_str) != Some(account_id)
        || input.selectors.get("database_id").and_then(Value::as_str) != Some(database_id)
    {
        return Err(CliError::Input(
            "workspace D1 qualification child target drifted".to_owned(),
        ));
    }
    Ok(())
}

fn validate_worker_plan_target(
    store: &StateStore,
    operation_id: &str,
    account_id: &str,
    worker_script_name: &str,
) -> Result<()> {
    let plan = match store.load_stored_plan_record(operation_id)? {
        StoredPlanRecord::Current(plan) => *plan,
        _ => {
            return Err(CliError::Input(
                "workspace D1 Worker deployment plan is not one current PlanV2".to_owned(),
            ));
        }
    };
    let input: CallInput = serde_json::from_value(plan.plan.input).map_err(|_| {
        CliError::Input("workspace D1 Worker deployment plan input is malformed".to_owned())
    })?;
    if input.selectors.get("account_id").and_then(Value::as_str) != Some(account_id)
        || input.selectors.get("script_name").and_then(Value::as_str) != Some(worker_script_name)
    {
        return Err(CliError::Input(
            "workspace D1 Worker deployment plan target drifted".to_owned(),
        ));
    }
    Ok(())
}

fn target_string<'a>(target: &'a Value, name: &str) -> Result<&'a str> {
    target.get(name).and_then(Value::as_str).ok_or_else(|| {
        CliError::Input(format!(
            "workspace D1 qualification plan target omitted `{name}`; create a new plan"
        ))
    })
}

fn single_migration_sha256<'a>(
    contract: &'a WorkspaceD1MigrationContractV1,
    role: &str,
) -> Result<&'a str> {
    let [migration] = contract.migrations.as_slice() else {
        return Err(CliError::Input(format!(
            "workspace D1 {role} contract does not bind exactly one migration"
        )));
    };
    if !is_sha256(&migration.sha256) {
        return Err(CliError::Input(format!(
            "workspace D1 {role} contract migration identity is malformed"
        )));
    }
    Ok(&migration.sha256)
}

fn evidence_join_pairs(joins: &WorkspaceD1EvidenceJoinsV1) -> [(&'static str, &str); 6] {
    [
        (
            ATOMICITY_QUALIFICATION_PRECONDITION,
            &joins.atomicity_qualification_evidence_hash,
        ),
        (
            OLD_WORKER_CANARY_PRECONDITION,
            &joins.old_worker_canary_evidence_hash,
        ),
        (
            WORKER_DEPLOYMENTS_PRECONDITION,
            &joins.worker_deployments_evidence_hash,
        ),
        (
            WORKER_VERSION_PRECONDITION,
            &joins.worker_version_evidence_hash,
        ),
        (
            WORKER_SETTINGS_PRECONDITION,
            &joins.worker_settings_evidence_hash,
        ),
        (
            WORKER_DEPLOYMENT_PLAN_PRECONDITION,
            &joins.worker_deployment_plan_hash,
        ),
    ]
}

fn validate_evidence_joins(joins: &WorkspaceD1EvidenceJoinsV1) -> Result<()> {
    let pairs = evidence_join_pairs(joins);
    if pairs.iter().any(|(_, hash)| !is_sha256(hash))
        || pairs
            .iter()
            .map(|(_, hash)| *hash)
            .collect::<BTreeSet<_>>()
            .len()
            != pairs.len()
    {
        return Err(CliError::Input(
            "workspace D1 production eligibility requires six distinct canonical SHA-256 evidence joins"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_evidence_join_key_set(hashes: &BTreeMap<String, String>, source: &str) -> Result<bool> {
    let expected = EVIDENCE_JOIN_PRECONDITIONS
        .into_iter()
        .collect::<BTreeSet<_>>();
    let actual = hashes
        .keys()
        .map(String::as_str)
        .filter(|name| name.starts_with(EVIDENCE_JOIN_NAMESPACE_PREFIX))
        .collect::<BTreeSet<_>>();
    if actual.is_empty() {
        return Ok(false);
    }
    if actual != expected {
        return Err(CliError::Input(format!(
            "workspace D1 {source} does not bind the exact qualification evidence key set; create a new plan"
        )));
    }
    Ok(true)
}

fn evidence_joins_from_hashes(
    hashes: &BTreeMap<String, String>,
    source: &str,
) -> Result<WorkspaceD1EvidenceJoinsV1> {
    if !validate_evidence_join_key_set(hashes, source)? {
        return Err(CliError::Input(format!(
            "workspace D1 {source} does not bind the exact six evidence identities; create a new plan"
        )));
    }
    let get = |name: &str| {
        hashes.get(name).cloned().ok_or_else(|| {
            CliError::Input(format!(
                "workspace D1 {source} does not bind the exact six evidence identities; create a new plan"
            ))
        })
    };
    let joins = WorkspaceD1EvidenceJoinsV1 {
        atomicity_qualification_evidence_hash: get(ATOMICITY_QUALIFICATION_PRECONDITION)?,
        old_worker_canary_evidence_hash: get(OLD_WORKER_CANARY_PRECONDITION)?,
        worker_deployments_evidence_hash: get(WORKER_DEPLOYMENTS_PRECONDITION)?,
        worker_version_evidence_hash: get(WORKER_VERSION_PRECONDITION)?,
        worker_settings_evidence_hash: get(WORKER_SETTINGS_PRECONDITION)?,
        worker_deployment_plan_hash: get(WORKER_DEPLOYMENT_PLAN_PRECONDITION)?,
    };
    validate_evidence_joins(&joins)?;
    Ok(joins)
}

fn evidence_join_hashes(joins: &WorkspaceD1EvidenceJoinsV1) -> BTreeMap<String, String> {
    evidence_join_pairs(joins)
        .into_iter()
        .map(|(name, hash)| (name.to_owned(), hash.to_owned()))
        .collect()
}

fn bound_execution_evidence_joins(
    execution: &PlanV2,
) -> Result<Option<WorkspaceD1EvidenceJoinsV1>> {
    let Some(contract) = execution.plan.capability.workspace_d1_migration.as_ref() else {
        return Ok(None);
    };
    if contract.manifest_migration.is_none() {
        return Ok(None);
    }
    let target_value = execution
        .plan
        .targets
        .pointer("/adapter/workspace_d1_migration/evidence_joins")
        .ok_or_else(|| {
            CliError::Input(
                "workspace D1 execution target does not bind the exact six evidence identities; create a new plan"
                    .to_owned(),
            )
        })?;
    let target: WorkspaceD1EvidenceJoinsV1 =
        serde_json::from_value(target_value.clone()).map_err(|_| {
            CliError::Input(
                "workspace D1 execution target evidence joins are malformed; create a new plan"
                    .to_owned(),
            )
        })?;
    validate_evidence_joins(&target)?;
    let preconditions =
        evidence_joins_from_hashes(&execution.plan.precondition_hashes, "PlanV1 preconditions")?;
    let observations = evidence_joins_from_hashes(
        &execution.pins.resource_observation_hashes,
        "PlanV2 resource observations",
    )?;
    if target != preconditions || preconditions != observations {
        return Err(CliError::Input(
            "workspace D1 execution target, PlanV1 preconditions, and PlanV2 resource observations do not bind the same six evidence identities; create a new plan"
                .to_owned(),
        ));
    }
    Ok(Some(preconditions))
}

#[allow(clippy::too_many_lines)]
pub(super) fn current_plan_evidence_hashes(
    store: &StateStore,
    plan: &PlanV1,
    now: DateTime<Utc>,
) -> Result<BTreeMap<String, String>> {
    let manifest_backed = plan
        .capability
        .workspace_d1_migration
        .as_ref()
        .and_then(|contract| contract.manifest_migration.as_ref())
        .is_some();
    let binds_evidence_joins =
        validate_evidence_join_key_set(&plan.precondition_hashes, "PlanV1 preconditions")?;
    if !manifest_backed {
        if !binds_evidence_joins {
            return Ok(BTreeMap::new());
        }
        return Err(CliError::Input(
            "workspace D1 qualification evidence joins require a manifest-backed execution contract; create a new plan"
                .to_owned(),
        ));
    }
    if !binds_evidence_joins {
        return Err(CliError::Input(
            "workspace D1 PlanV1 preconditions do not bind the exact six evidence identities; create a new plan"
                .to_owned(),
        ));
    }

    let execution = match store.load_stored_plan_record(&plan.operation_id)? {
        StoredPlanRecord::Current(plan_v2) if plan_v2.plan == *plan => *plan_v2,
        _ => {
            return Err(CliError::Input(
                "workspace D1 qualification execution plan is not the exact current PlanV2"
                    .to_owned(),
            ));
        }
    };
    if execution.pins.catalog_hash != plan.catalog_hash {
        return Err(CliError::Input(
            "workspace D1 qualification execution catalog identity drifted".to_owned(),
        ));
    }
    let joins = bound_execution_evidence_joins(&execution)?.ok_or_else(|| {
        CliError::Input(
            "workspace D1 manifest execution does not bind production eligibility; create a new plan"
                .to_owned(),
        )
    })?;
    let target = plan
        .targets
        .pointer("/adapter/workspace_d1_migration")
        .ok_or_else(|| {
            CliError::Input(
                "workspace D1 qualification plan target is missing; create a new plan".to_owned(),
            )
        })?;
    let atomicity_hash = &joins.atomicity_qualification_evidence_hash;
    let canary_hash = &joins.old_worker_canary_evidence_hash;
    let atomicity_evidence = store.load_evidence(atomicity_hash)?;
    let atomicity_value = store.read_evidence_value(atomicity_hash)?;
    let atomicity: WorkspaceD1AtomicityQualificationV1 = serde_json::from_value(atomicity_value)
        .map_err(|_| CliError::Input("workspace D1 atomicity receipt is malformed".to_owned()))?;
    let canary_evidence = store.load_evidence(canary_hash)?;
    let canary_value = store.read_evidence_value(canary_hash)?;
    let canary: WorkspaceD1OldWorkerCanaryV1 = serde_json::from_value(canary_value)
        .map_err(|_| CliError::Input("workspace D1 old-Worker canary is malformed".to_owned()))?;
    if canary.deployments_read_evidence_hash != joins.worker_deployments_evidence_hash
        || canary.version_detail_evidence_hash != joins.worker_version_evidence_hash
        || canary.settings_evidence_hash != joins.worker_settings_evidence_hash
        || canary.worker_deployment_plan_hash != joins.worker_deployment_plan_hash
    {
        return Err(CliError::Input(
            "workspace D1 old-Worker canary does not match the six plan-bound evidence identities"
                .to_owned(),
        ));
    }

    let plan_specs = [
        (
            "create_database",
            atomicity.create_database_operation_id.as_str(),
            "d1-create-database",
            PlanStatus::Verified,
            TransactionStageV1::Closed,
        ),
        (
            "success_apply",
            atomicity.success_apply_operation_id.as_str(),
            "mln-web.founder-d1-migration-apply",
            PlanStatus::Verified,
            TransactionStageV1::Closed,
        ),
        (
            "ddl_failure_apply",
            atomicity.ddl_failure_apply_operation_id.as_str(),
            "mln-web.founder-d1-migration-apply",
            PlanStatus::RectificationRequired,
            TransactionStageV1::VerificationResponsePersisted,
        ),
        (
            "ledger_failure_apply",
            atomicity.ledger_failure_apply_operation_id.as_str(),
            "mln-web.founder-d1-migration-apply",
            PlanStatus::RectificationRequired,
            TransactionStageV1::VerificationResponsePersisted,
        ),
        (
            "restore",
            atomicity.restore_operation_id.as_str(),
            "d1-restore-exact-bookmark",
            PlanStatus::Verified,
            TransactionStageV1::Closed,
        ),
        (
            "delete_database",
            atomicity.delete_database_operation_id.as_str(),
            "d1-delete-database",
            PlanStatus::Verified,
            TransactionStageV1::Closed,
        ),
    ];
    let owned_plans = plan_specs
        .into_iter()
        .map(|(role, operation, capability, status, stage)| {
            resolve_plan_expectation(
                store,
                capability_role(role),
                operation,
                capability,
                status,
                stage,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let success_plan = owned_plans
        .iter()
        .find(|candidate| candidate.role == "success_apply")
        .ok_or_else(|| {
            CliError::Input("workspace D1 success qualification child is missing".to_owned())
        })?;
    let success_contract = success_plan
        .workspace_d1_migration
        .as_ref()
        .ok_or_else(|| {
            CliError::Input(
                "workspace D1 success qualification child lacks a bound migration contract"
                    .to_owned(),
            )
        })?;
    let synthetic_migration_sha256 =
        single_migration_sha256(success_contract, "success child")?.to_owned();
    let qualification_account_id = success_plan
        .input
        .selectors
        .get("account_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "workspace D1 success qualification child omitted account_id".to_owned(),
            )
        })?
        .to_owned();
    let isolated_database_id = success_plan
        .input
        .selectors
        .get("database_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "workspace D1 success qualification child omitted database_id".to_owned(),
            )
        })?
        .to_owned();
    if qualification_account_id != plan.account_id {
        return Err(CliError::Input(
            "workspace D1 success qualification child account differs from the bound execution"
                .to_owned(),
        ));
    }
    let execution_contract = plan
        .capability
        .workspace_d1_migration
        .as_ref()
        .ok_or_else(|| CliError::Input("workspace D1 execution contract is missing".to_owned()))?;
    let workspace_contract_sha256 = hash_value(&serde_json::to_value(execution_contract)?)?;
    let migration_sha256 =
        single_migration_sha256(execution_contract, "production execution")?.to_owned();
    let plan_expectations = owned_plans
        .iter()
        .map(OwnedPlanExpectation::borrowed)
        .collect::<Vec<_>>();
    for plan in owned_plans
        .iter()
        .filter(|plan| plan.role != "create_database")
    {
        validate_d1_plan_target(
            store,
            &plan.operation_id,
            &qualification_account_id,
            &isolated_database_id,
        )?;
    }

    let d1_input_hash = hash_value(&serde_json::to_value(CallInput {
        selectors: json!({
            "account_id": qualification_account_id,
            "database_id": isolated_database_id,
        }),
        query: json!({}),
        ..CallInput::default()
    })?)?;
    let proof_specs = [
        (
            "get_database",
            atomicity.get_database_proof_hash.as_str(),
            atomicity.get_database_evidence_hash.as_str(),
            "d1-get-database",
        ),
        (
            "full_export",
            atomicity.full_export_proof_hash.as_str(),
            atomicity.full_export_evidence_hash.as_str(),
            "d1-full-export",
        ),
        (
            "bookmark",
            atomicity.bookmark_proof_hash.as_str(),
            atomicity.bookmark_evidence_hash.as_str(),
            "d1-time-travel-get-bookmark",
        ),
        (
            "ddl_zero_schema",
            atomicity.ddl_failure_zero_schema_proof_hash.as_str(),
            atomicity.ddl_failure_zero_schema_delta_hash.as_str(),
            "d1-schema-introspection",
        ),
        (
            "ddl_zero_ledger",
            atomicity.ddl_failure_zero_ledger_proof_hash.as_str(),
            atomicity.ddl_failure_zero_ledger_delta_hash.as_str(),
            "mln-web.founder-d1-migration-apply",
        ),
        (
            "ledger_zero_schema",
            atomicity.ledger_failure_zero_schema_proof_hash.as_str(),
            atomicity.ledger_failure_zero_schema_delta_hash.as_str(),
            "d1-schema-introspection",
        ),
        (
            "ledger_zero_ledger",
            atomicity.ledger_failure_zero_ledger_proof_hash.as_str(),
            atomicity.ledger_failure_zero_ledger_delta_hash.as_str(),
            "mln-web.founder-d1-migration-apply",
        ),
        (
            "cleanup_absence",
            atomicity.cleanup_proof_hash.as_str(),
            atomicity.cleanup_evidence_hash.as_str(),
            "d1-get-database",
        ),
    ];
    let owned_proofs = proof_specs
        .into_iter()
        .map(|(role, proof, _evidence, capability)| {
            resolve_proof_expectation(
                store,
                proof_role(role),
                proof,
                capability,
                Some(&d1_input_hash),
                None,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let proof_expectations = owned_proofs
        .iter()
        .map(OwnedProofExpectation::borrowed)
        .collect::<Vec<_>>();

    let worker_plan = resolve_worker_plan_expectation(
        store,
        &canary.worker_deployment_operation_id,
        &joins.worker_deployment_plan_hash,
    )?;
    let worker_script_name = worker_plan
        .input
        .selectors
        .get("script_name")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input("workspace D1 Worker deployment plan omitted script_name".to_owned())
        })?
        .to_owned();
    validate_worker_plan_target(
        store,
        &worker_plan.operation_id,
        &plan.account_id,
        &worker_script_name,
    )?;
    let worker_plan_expectation = worker_plan.borrowed();
    let worker_specs = [
        (
            "deployments",
            canary.deployments_read_proof_hash.as_str(),
            canary.deployments_read_evidence_hash.as_str(),
            "worker-deployments-list-deployments",
        ),
        (
            "version",
            canary.version_detail_proof_hash.as_str(),
            canary.version_detail_evidence_hash.as_str(),
            "worker-versions-get-version-detail",
        ),
        (
            "settings",
            canary.settings_proof_hash.as_str(),
            canary.settings_evidence_hash.as_str(),
            "worker-script-get-settings",
        ),
    ];
    let owned_worker_proofs = worker_specs
        .into_iter()
        .map(|(role, proof, evidence, capability)| {
            let bound_evidence = match role {
                "deployments" => &joins.worker_deployments_evidence_hash,
                "version" => &joins.worker_version_evidence_hash,
                "settings" => &joins.worker_settings_evidence_hash,
                _ => unreachable!(),
            };
            if evidence != bound_evidence {
                return Err(CliError::Input(
                    "workspace D1 old-Worker canary proof claim differs from the plan-bound evidence identity"
                        .to_owned(),
                ));
            }
            resolve_proof_expectation(
                store,
                worker_role(role),
                proof,
                capability,
                None,
                Some(bound_evidence),
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let worker_proof_expectations = owned_worker_proofs
        .iter()
        .map(OwnedProofExpectation::borrowed)
        .collect::<Vec<_>>();
    let deployments_expectation = worker_proof_expectations
        .iter()
        .find(|proof| proof.role == "deployments")
        .ok_or_else(|| {
            CliError::Input("workspace D1 Worker deployments proof is missing".to_owned())
        })?;
    let (_, deployments_body) = validate_proof(store, deployments_expectation)?;
    let deployments_response: CloudflareResponseV1 = serde_json::from_value(deployments_body)
        .map_err(|_| {
            CliError::Input("workspace D1 Worker deployments proof body is malformed".to_owned())
        })?;
    let (deployment_id, version_id) =
        super::worker_deployment::current_active_deployment_identity(&deployments_response.result)?;
    let deployment_id = deployment_id.to_owned();
    let version_id = version_id.to_owned();

    let atomicity_expected = AtomicityExpectations {
        cfctl_candidate_hash: &execution.pins.build_identity_hash,
        repository_head: target_string(target, "repository_head")?,
        operation_pack_sha256: target_string(target, "operation_pack_sha256")?,
        catalog_hash: &plan.catalog_hash,
        account_id: &plan.account_id,
        profile_id: &plan.profile_id,
        credential_generation_id: &execution.pins.credential_generation_id,
        wrangler_version: target_string(target, "wrangler_version")?,
        wrangler_cli_sha256: target_string(target, "wrangler_cli_sha256")?,
        synthetic_migration_sha256: &synthetic_migration_sha256,
        plans: &plan_expectations,
        proofs: &proof_expectations,
    };
    let canary_expected = CanaryExpectations {
        capability_id: &plan.capability.id,
        workspace_contract_sha256: &workspace_contract_sha256,
        cfctl_candidate_hash: &execution.pins.build_identity_hash,
        repository_head: target_string(target, "repository_head")?,
        operation_pack_sha256: target_string(target, "operation_pack_sha256")?,
        catalog_hash: &plan.catalog_hash,
        account_id: &plan.account_id,
        profile_id: &plan.profile_id,
        credential_generation_id: &execution.pins.credential_generation_id,
        database_id: &isolated_database_id,
        migration_sha256: &migration_sha256,
        migration_operation_id: &success_plan.operation_id,
        migration_plan_hash: &success_plan.plan_content_hash,
        migration_apply_evidence_hash: &success_plan.evidence_hash,
        worker_script_name: &worker_script_name,
        deployment_id: &deployment_id,
        version_id: &version_id,
        worker_plan: worker_plan_expectation,
        worker_proofs: &worker_proof_expectations,
    };
    validate_qualification_pair(
        store,
        &atomicity_evidence,
        &canary_evidence,
        &atomicity_expected,
        &canary_expected,
        now,
    )?;
    Ok(evidence_join_hashes(&joins))
}

fn resolve_worker_plan_expectation(
    store: &StateStore,
    operation_id: &str,
    expected_plan_hash: &str,
) -> Result<OwnedPlanExpectation> {
    let expectation = resolve_plan_expectation(
        store,
        "worker_deployment",
        operation_id,
        "worker-deployment-plan",
        PlanStatus::Verified,
        TransactionStageV1::Closed,
    )?;
    if expectation.plan_content_hash != expected_plan_hash {
        return Err(CliError::Input(
            "workspace D1 Worker deployment plan differs from the plan-bound content identity"
                .to_owned(),
        ));
    }
    Ok(expectation)
}

fn capability_role(role: &str) -> &'static str {
    match role {
        "create_database" => "create_database",
        "success_apply" => "success_apply",
        "ddl_failure_apply" => "ddl_failure_apply",
        "ledger_failure_apply" => "ledger_failure_apply",
        "restore" => "restore",
        "delete_database" => "delete_database",
        _ => unreachable!(),
    }
}

fn proof_role(role: &str) -> &'static str {
    match role {
        "get_database" => "get_database",
        "full_export" => "full_export",
        "bookmark" => "bookmark",
        "ddl_zero_schema" => "ddl_zero_schema",
        "ddl_zero_ledger" => "ddl_zero_ledger",
        "ledger_zero_schema" => "ledger_zero_schema",
        "ledger_zero_ledger" => "ledger_zero_ledger",
        "cleanup_absence" => "cleanup_absence",
        _ => unreachable!(),
    }
}

fn worker_role(role: &str) -> &'static str {
    match role {
        "deployments" => "deployments",
        "version" => "version",
        "settings" => "settings",
        _ => unreachable!(),
    }
}

pub(super) fn evidence_joins(
    atomicity_evidence: &EvidenceV1,
    canary_evidence: &EvidenceV1,
    canary: &WorkspaceD1OldWorkerCanaryV1,
) -> Result<WorkspaceD1EvidenceJoinsV1> {
    require_post_change_evidence(atomicity_evidence)?;
    require_post_change_evidence(canary_evidence)?;
    let joins = WorkspaceD1EvidenceJoinsV1 {
        atomicity_qualification_evidence_hash: atomicity_evidence.content_hash.clone(),
        old_worker_canary_evidence_hash: canary_evidence.content_hash.clone(),
        worker_deployments_evidence_hash: canary.deployments_read_evidence_hash.clone(),
        worker_version_evidence_hash: canary.version_detail_evidence_hash.clone(),
        worker_settings_evidence_hash: canary.settings_evidence_hash.clone(),
        worker_deployment_plan_hash: canary.worker_deployment_plan_hash.clone(),
    };
    validate_evidence_joins(&joins)?;
    Ok(joins)
}

pub(super) fn requested_evidence_joins(
    store: &StateStore,
    input: &CallInput,
) -> Result<WorkspaceD1EvidenceJoinsV1> {
    let atomicity_hash = input
        .query
        .get("atomicity_evidence_hash")
        .and_then(Value::as_str)
        .filter(|value| is_sha256(value))
        .ok_or_else(|| {
            CliError::Input(
                "workspace D1 manifest planning requires atomicity_evidence_hash".to_owned(),
            )
        })?;
    let canary_hash = input
        .query
        .get("old_worker_canary_evidence_hash")
        .and_then(Value::as_str)
        .filter(|value| is_sha256(value))
        .ok_or_else(|| {
            CliError::Input(
                "workspace D1 manifest planning requires old_worker_canary_evidence_hash"
                    .to_owned(),
            )
        })?;
    let atomicity_evidence = store.load_evidence(atomicity_hash)?;
    let canary_evidence = store.load_evidence(canary_hash)?;
    let canary: WorkspaceD1OldWorkerCanaryV1 =
        serde_json::from_value(store.read_evidence_value(canary_hash)?).map_err(|_| {
            CliError::Input("workspace D1 old-Worker canary is malformed".to_owned())
        })?;
    evidence_joins(&atomicity_evidence, &canary_evidence, &canary)
}

pub(super) fn validate_qualification_pair(
    store: &StateStore,
    atomicity_evidence: &EvidenceV1,
    canary_evidence: &EvidenceV1,
    atomicity_expected: &AtomicityExpectations<'_>,
    canary_expected: &CanaryExpectations<'_>,
    now: DateTime<Utc>,
) -> Result<WorkspaceD1EvidenceJoinsV1> {
    let atomicity =
        validate_atomicity_qualification(store, atomicity_evidence, atomicity_expected, now)?;
    let canary = validate_old_worker_canary(store, canary_evidence, canary_expected, now)?;
    if canary.migration_operation_id != atomicity.success_apply_operation_id
        || canary.migration_plan_hash != atomicity.success_apply_plan_hash
        || canary.migration_apply_evidence_hash != atomicity.success_outcome_evidence_hash
        || canary.account_id != atomicity.account_id
        || canary.profile_id != atomicity.profile_id
        || canary.credential_generation_id != atomicity.credential_generation_id
        || canary.database_id != atomicity.isolated_database_id
    {
        return Err(CliError::Input(
            "workspace D1 qualification evidence is not operation- and target-continuous"
                .to_owned(),
        ));
    }
    evidence_joins(atomicity_evidence, canary_evidence, &canary)
}

fn worker_identity_join_hash(receipt: &WorkspaceD1OldWorkerCanaryV1) -> Result<String> {
    Ok(hash_value(&json!({
        "worker_script_name":receipt.worker_script_name,
        "worker_deployment_operation_id":receipt.worker_deployment_operation_id,
        "worker_deployment_plan_hash":receipt.worker_deployment_plan_hash,
        "deployments_read_proof_hash":receipt.deployments_read_proof_hash,
        "deployments_read_evidence_hash":receipt.deployments_read_evidence_hash,
        "version_detail_proof_hash":receipt.version_detail_proof_hash,
        "version_detail_evidence_hash":receipt.version_detail_evidence_hash,
        "settings_proof_hash":receipt.settings_proof_hash,
        "settings_evidence_hash":receipt.settings_evidence_hash,
        "deployment_id":receipt.deployment_id,
        "version_id":receipt.version_id,
    }))?)
}

pub(super) fn bind_plan_evidence_hashes(plan: &mut PlanV1, adapter_targets: &Value) -> Result<()> {
    let Some(value) = adapter_targets.pointer("/workspace_d1_migration/evidence_joins") else {
        return Ok(());
    };
    let joins: WorkspaceD1EvidenceJoinsV1 =
        serde_json::from_value(value.clone()).map_err(|_| {
            CliError::Input("workspace D1 PlanV2 evidence joins are malformed".to_owned())
        })?;
    validate_evidence_joins(&joins)?;
    for (key, hash) in evidence_join_pairs(&joins) {
        plan.precondition_hashes
            .insert(key.to_owned(), hash.to_owned());
    }
    Ok(())
}

fn require_post_change_evidence(evidence: &EvidenceV1) -> Result<()> {
    if evidence.schema_version != 1
        || evidence.class != EvidenceClass::PostChangeVerification
        || !is_sha256(&evidence.content_hash)
    {
        return Err(CliError::Input(
            "workspace D1 qualification requires PostChangeVerification evidence".to_owned(),
        ));
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn is_canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value)
        .ok()
        .is_some_and(|parsed| parsed.to_string() == value)
}

fn is_git_oid(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && is_lower_hex(value, value.len())
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn safe_claim_name(value: &str) -> bool {
    (1..=96).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

#[cfg(test)]
mod tests;
