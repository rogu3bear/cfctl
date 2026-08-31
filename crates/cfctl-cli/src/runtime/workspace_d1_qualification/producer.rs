use std::collections::BTreeMap;

use cfctl_cloudflare::CallInput;
use cfctl_core::{
    EvidenceClass, PlanStatus, TransactionStageV1, WorkspaceD1AtomicityQualificationV1,
    WorkspaceD1OldWorkerCanaryV1, hash_value,
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{
    AtomicityExpectations, CanaryExpectations, OwnedPlanExpectation, OwnedProofExpectation,
    capability_role, resolve_plan_expectation, resolve_proof_expectation,
    resolve_worker_plan_expectation, single_migration_sha256, validate_qualification_pair,
    worker_identity_join_hash,
};
use crate::runtime::prelude::{
    CatalogSnapshot, CliError, Result, ResultEnvelopeV2, StateStore, VerificationState,
};

pub(crate) const CAPABILITY_ID: &str = "workspace-d1-qualification-produce";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProducerInputV1 {
    schema_version: u8,
    atomicity: AtomicityChildrenV1,
    old_worker_canary: OldWorkerCanaryInputV1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AtomicityChildrenV1 {
    create_database_operation_id: String,
    success_apply_operation_id: String,
    ddl_failure_apply_operation_id: String,
    ledger_failure_apply_operation_id: String,
    restore_operation_id: String,
    delete_database_operation_id: String,
    get_database_proof_hash: String,
    full_export_proof_hash: String,
    bookmark_proof_hash: String,
    ddl_failure_zero_schema_proof_hash: String,
    ddl_failure_zero_ledger_proof_hash: String,
    ledger_failure_zero_schema_proof_hash: String,
    ledger_failure_zero_ledger_proof_hash: String,
    cleanup_proof_hash: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OldWorkerCanaryInputV1 {
    worker_deployment_operation_id: String,
    deployments_read_proof_hash: String,
    version_detail_proof_hash: String,
    settings_proof_hash: String,
    request_sha256: String,
    result_sha256: String,
    semantic_assertions_sha256: String,
    declared_evidence_hashes: BTreeMap<String, String>,
    disposition: String,
}

pub(crate) fn produce(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    input: &CallInput,
) -> Result<ResultEnvelopeV2> {
    let body = input.body.clone().ok_or_else(|| {
        CliError::Input("workspace D1 qualification producer requires one closed JSON body".into())
    })?;
    let request: ProducerInputV1 = serde_json::from_value(body).map_err(|_| {
        CliError::Input("workspace D1 qualification producer input is malformed".into())
    })?;
    if request.schema_version != 1 || request.old_worker_canary.disposition != "pass" {
        return Err(CliError::Input(
            "workspace D1 qualification producer requires schema_version 1 and an explicit pass disposition"
                .into(),
        ));
    }
    produce_validated(store, catalog, request)
}

#[allow(clippy::too_many_lines)]
fn produce_validated(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    request: ProducerInputV1,
) -> Result<ResultEnvelopeV2> {
    let now = Utc::now();
    let atomic = request.atomicity;
    let plan_specs = [
        (
            "create_database",
            atomic.create_database_operation_id.as_str(),
            "d1-create-database",
            PlanStatus::Verified,
            TransactionStageV1::Closed,
        ),
        (
            "success_apply",
            atomic.success_apply_operation_id.as_str(),
            "mln-web.founder-d1-migration-apply",
            PlanStatus::Verified,
            TransactionStageV1::Closed,
        ),
        (
            "ddl_failure_apply",
            atomic.ddl_failure_apply_operation_id.as_str(),
            "mln-web.founder-d1-migration-apply",
            PlanStatus::RectificationRequired,
            TransactionStageV1::VerificationResponsePersisted,
        ),
        (
            "ledger_failure_apply",
            atomic.ledger_failure_apply_operation_id.as_str(),
            "mln-web.founder-d1-migration-apply",
            PlanStatus::RectificationRequired,
            TransactionStageV1::VerificationResponsePersisted,
        ),
        (
            "restore",
            atomic.restore_operation_id.as_str(),
            "d1-restore-exact-bookmark",
            PlanStatus::Verified,
            TransactionStageV1::Closed,
        ),
        (
            "delete_database",
            atomic.delete_database_operation_id.as_str(),
            "d1-delete-database",
            PlanStatus::Verified,
            TransactionStageV1::Closed,
        ),
    ];
    let plans = plan_specs
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
    let success = plan(&plans, "success_apply")?;
    if success.catalog_hash != catalog.schema_hash {
        return Err(CliError::Input(
            "workspace D1 qualification children use a stale catalog identity".into(),
        ));
    }
    let contract = success.workspace_d1_migration.as_ref().ok_or_else(|| {
        CliError::Input("workspace D1 success child lacks its migration contract".into())
    })?;
    let migration_sha256 = single_migration_sha256(contract, "qualification producer")?.to_owned();
    let database_id = selector(&success.input, "database_id")?.to_owned();
    let account_id = selector(&success.input, "account_id")?.to_owned();
    let target = stored_plan_target(store, &success.operation_id)?;
    let wrangler_cli_sha256 = target_string(&target, "wrangler_cli_sha256")?.to_owned();
    let repository_head = contract.repository_head.clone();
    let operation_pack_sha256 = contract.operation_pack_sha256.clone();
    let wrangler_version = contract.wrangler_version.clone();

    let d1_input_hash = hash_value(&serde_json::to_value(CallInput {
        selectors: json!({"account_id":account_id,"database_id":database_id}),
        query: json!({}),
        ..CallInput::default()
    })?)?;
    let proof_specs = [
        (
            "get_database",
            atomic.get_database_proof_hash.as_str(),
            "d1-get-database",
        ),
        (
            "full_export",
            atomic.full_export_proof_hash.as_str(),
            "d1-full-export",
        ),
        (
            "bookmark",
            atomic.bookmark_proof_hash.as_str(),
            "d1-time-travel-get-bookmark",
        ),
        (
            "ddl_zero_schema",
            atomic.ddl_failure_zero_schema_proof_hash.as_str(),
            "d1-schema-introspection",
        ),
        (
            "ddl_zero_ledger",
            atomic.ddl_failure_zero_ledger_proof_hash.as_str(),
            "mln-web.founder-d1-migration-apply",
        ),
        (
            "ledger_zero_schema",
            atomic.ledger_failure_zero_schema_proof_hash.as_str(),
            "d1-schema-introspection",
        ),
        (
            "ledger_zero_ledger",
            atomic.ledger_failure_zero_ledger_proof_hash.as_str(),
            "mln-web.founder-d1-migration-apply",
        ),
        (
            "cleanup_absence",
            atomic.cleanup_proof_hash.as_str(),
            "d1-get-database",
        ),
    ];
    let proofs = proof_specs
        .into_iter()
        .map(|(role, proof_hash, capability)| {
            resolve_proof_expectation(
                store,
                proof_role(role),
                proof_hash,
                capability,
                Some(&d1_input_hash),
                None,
            )
        })
        .collect::<Result<Vec<_>>>()?;

    let worker = request.old_worker_canary;
    let worker_plan = resolve_worker_plan_expectation(
        store,
        &worker.worker_deployment_operation_id,
        &stored_plan_hash(store, &worker.worker_deployment_operation_id)?,
    )?;
    let worker_script_name = selector(&worker_plan.input, "script_name")?.to_owned();
    let worker_specs = [
        (
            "deployments",
            worker.deployments_read_proof_hash.as_str(),
            "worker-deployments-list-deployments",
        ),
        (
            "version",
            worker.version_detail_proof_hash.as_str(),
            "worker-versions-get-version-detail",
        ),
        (
            "settings",
            worker.settings_proof_hash.as_str(),
            "worker-script-get-settings",
        ),
    ];
    let worker_proofs = worker_specs
        .into_iter()
        .map(|(role, proof_hash, capability)| {
            resolve_proof_expectation(store, worker_role(role), proof_hash, capability, None, None)
        })
        .collect::<Result<Vec<_>>>()?;
    let deployments = proof(&worker_proofs, "deployments")?;
    let deployment_body = store.read_evidence_value(&deployments.evidence_hash)?;
    let response: cfctl_cloudflare::CloudflareResponseV1 = serde_json::from_value(deployment_body)
        .map_err(|_| CliError::Input("workspace D1 deployments proof body is malformed".into()))?;
    let (deployment_id, version_id) =
        crate::runtime::worker_deployment::current_active_deployment_identity(&response.result)?;
    let deployment_id = deployment_id.to_owned();
    let version_id = version_id.to_owned();

    let plan_expectations = plans
        .iter()
        .map(OwnedPlanExpectation::borrowed)
        .collect::<Vec<_>>();
    let proof_expectations = proofs
        .iter()
        .map(OwnedProofExpectation::borrowed)
        .collect::<Vec<_>>();
    let worker_expectations = worker_proofs
        .iter()
        .map(OwnedProofExpectation::borrowed)
        .collect::<Vec<_>>();
    let atomic_expected = AtomicityExpectations {
        cfctl_candidate_hash: &success.build_identity_hash,
        repository_head: &repository_head,
        operation_pack_sha256: &operation_pack_sha256,
        catalog_hash: &catalog.schema_hash,
        account_id: &account_id,
        profile_id: &success.profile_id,
        credential_generation_id: &success.credential_generation_id,
        wrangler_version: &wrangler_version,
        wrangler_cli_sha256: &wrangler_cli_sha256,
        synthetic_migration_sha256: &migration_sha256,
        plans: &plan_expectations,
        proofs: &proof_expectations,
    };
    let workspace_contract_sha256 = hash_value(&serde_json::to_value(contract)?)?;
    let worker_plan_expectation = worker_plan.borrowed();
    let canary_expected = CanaryExpectations {
        capability_id: success.capability_id,
        workspace_contract_sha256: &workspace_contract_sha256,
        cfctl_candidate_hash: &success.build_identity_hash,
        repository_head: &repository_head,
        operation_pack_sha256: &operation_pack_sha256,
        catalog_hash: &catalog.schema_hash,
        account_id: &account_id,
        profile_id: &success.profile_id,
        credential_generation_id: &success.credential_generation_id,
        database_id: &database_id,
        migration_sha256: &migration_sha256,
        migration_operation_id: &success.operation_id,
        migration_plan_hash: &success.plan_content_hash,
        migration_apply_evidence_hash: &success.evidence_hash,
        worker_script_name: &worker_script_name,
        deployment_id: &deployment_id,
        version_id: &version_id,
        worker_plan: worker_plan_expectation,
        worker_proofs: &worker_expectations,
    };

    let atomicity = atomicity_receipt(
        &atomic,
        &plans,
        &proofs,
        &atomic_expected,
        &database_id,
        now,
    )?;
    let atomicity_evidence = store.write_evidence(
        EvidenceClass::PostChangeVerification,
        &serde_json::to_value(&atomicity)?,
    )?;
    let mut canary = WorkspaceD1OldWorkerCanaryV1 {
        schema_version: 1,
        kind: "workspace_d1_old_worker_canary_v1".into(),
        evidence_class: EvidenceClass::PostChangeVerification,
        capability_id: success.capability_id.into(),
        workspace_contract_sha256: workspace_contract_sha256.clone(),
        cfctl_candidate_hash: success.build_identity_hash.clone(),
        repository_head: repository_head.clone(),
        operation_pack_sha256: operation_pack_sha256.clone(),
        catalog_hash: catalog.schema_hash.clone(),
        account_id: account_id.clone(),
        profile_id: success.profile_id.clone(),
        credential_generation_id: success.credential_generation_id.clone(),
        database_id: database_id.clone(),
        migration_sha256: migration_sha256.clone(),
        migration_operation_id: success.operation_id.clone(),
        migration_plan_hash: success.plan_content_hash.clone(),
        migration_apply_evidence_hash: success.evidence_hash.clone(),
        worker_script_name: worker_script_name.clone(),
        worker_deployment_operation_id: worker_plan.operation_id.clone(),
        worker_deployment_plan_hash: worker_plan.plan_content_hash.clone(),
        deployments_read_proof_hash: proof(&worker_proofs, "deployments")?.proof_hash.clone(),
        deployments_read_evidence_hash: proof(&worker_proofs, "deployments")?.evidence_hash.clone(),
        version_detail_proof_hash: proof(&worker_proofs, "version")?.proof_hash.clone(),
        version_detail_evidence_hash: proof(&worker_proofs, "version")?.evidence_hash.clone(),
        settings_proof_hash: proof(&worker_proofs, "settings")?.proof_hash.clone(),
        settings_evidence_hash: proof(&worker_proofs, "settings")?.evidence_hash.clone(),
        deployment_id: deployment_id.clone(),
        version_id: version_id.clone(),
        request_sha256: worker.request_sha256,
        result_sha256: worker.result_sha256,
        semantic_assertions_sha256: worker.semantic_assertions_sha256,
        declared_evidence_hashes: worker.declared_evidence_hashes,
        disposition: "pass".into(),
        passed: true,
        observed_at: now,
        canary_receipt_sha256: String::new(),
        worker_identity_evidence_sha256: String::new(),
    };
    canary.worker_identity_evidence_sha256 = worker_identity_join_hash(&canary)?;
    canary.canary_receipt_sha256 = hash_value(&serde_json::to_value(&canary)?)?;
    let canary_evidence = store.write_evidence(
        EvidenceClass::PostChangeVerification,
        &serde_json::to_value(&canary)?,
    )?;
    let joins = validate_qualification_pair(
        store,
        &atomicity_evidence,
        &canary_evidence,
        &atomic_expected,
        &canary_expected,
        Utc::now(),
    )?;
    let mut envelope = ResultEnvelopeV2::success(
        "call",
        json!({
            "schema_version":1,
            "kind":"workspace_d1_qualification_producer_result_v1",
            "performed_provider_boundary":false,
            "atomicity_evidence":atomicity_evidence,
            "old_worker_canary_evidence":canary_evidence,
            "evidence_joins":joins,
            "secret_key_bytes_exposed":false,
        }),
    );
    envelope.capability_id = Some(CAPABILITY_ID.into());
    envelope.verification.state = VerificationState::Passed;
    envelope.verification.basis = Some(
        "both authenticated PostChangeVerification receipts passed the existing closed validators and yielded six distinct continuity joins"
            .into(),
    );
    envelope.evidence = vec![atomicity_evidence, canary_evidence];
    Ok(envelope)
}

fn atomicity_receipt(
    input: &AtomicityChildrenV1,
    plans: &[OwnedPlanExpectation],
    proofs: &[OwnedProofExpectation],
    expected: &AtomicityExpectations<'_>,
    database_id: &str,
    now: chrono::DateTime<Utc>,
) -> Result<WorkspaceD1AtomicityQualificationV1> {
    let p = |role| plan(plans, role);
    let r = |role| proof(proofs, role);
    Ok(WorkspaceD1AtomicityQualificationV1 {
        schema_version: 1,
        kind: "workspace_d1_provider_atomicity_v1".into(),
        evidence_class: EvidenceClass::PostChangeVerification,
        qualification_id: uuid::Uuid::new_v4().to_string(),
        cfctl_candidate_hash: expected.cfctl_candidate_hash.into(),
        repository_head: expected.repository_head.into(),
        operation_pack_sha256: expected.operation_pack_sha256.into(),
        catalog_hash: expected.catalog_hash.into(),
        account_id: expected.account_id.into(),
        profile_id: expected.profile_id.into(),
        credential_generation_id: expected.credential_generation_id.into(),
        isolated_database_id: database_id.into(),
        isolated_database_identity_hash: hash_value(
            &json!({"account_id":expected.account_id,"database_id":database_id}),
        )?,
        wrangler_version: expected.wrangler_version.into(),
        wrangler_cli_sha256: expected.wrangler_cli_sha256.into(),
        synthetic_migration_sha256: expected.synthetic_migration_sha256.into(),
        create_database_operation_id: input.create_database_operation_id.clone(),
        create_database_plan_hash: p("create_database")?.plan_content_hash.clone(),
        get_database_proof_hash: r("get_database")?.proof_hash.clone(),
        get_database_evidence_hash: r("get_database")?.evidence_hash.clone(),
        success_apply_operation_id: input.success_apply_operation_id.clone(),
        success_apply_plan_hash: p("success_apply")?.plan_content_hash.clone(),
        ddl_failure_apply_operation_id: input.ddl_failure_apply_operation_id.clone(),
        ddl_failure_apply_plan_hash: p("ddl_failure_apply")?.plan_content_hash.clone(),
        ledger_failure_apply_operation_id: input.ledger_failure_apply_operation_id.clone(),
        ledger_failure_apply_plan_hash: p("ledger_failure_apply")?.plan_content_hash.clone(),
        full_export_proof_hash: r("full_export")?.proof_hash.clone(),
        full_export_evidence_hash: r("full_export")?.evidence_hash.clone(),
        bookmark_proof_hash: r("bookmark")?.proof_hash.clone(),
        bookmark_evidence_hash: r("bookmark")?.evidence_hash.clone(),
        restore_operation_id: input.restore_operation_id.clone(),
        restore_plan_hash: p("restore")?.plan_content_hash.clone(),
        delete_database_operation_id: input.delete_database_operation_id.clone(),
        delete_database_plan_hash: p("delete_database")?.plan_content_hash.clone(),
        create_database_evidence_hash: p("create_database")?.evidence_hash.clone(),
        restore_evidence_hash: p("restore")?.evidence_hash.clone(),
        delete_database_evidence_hash: p("delete_database")?.evidence_hash.clone(),
        success_outcome_evidence_hash: p("success_apply")?.evidence_hash.clone(),
        ddl_failure_outcome_evidence_hash: p("ddl_failure_apply")?.evidence_hash.clone(),
        ddl_failure_zero_schema_proof_hash: r("ddl_zero_schema")?.proof_hash.clone(),
        ddl_failure_zero_schema_delta_hash: r("ddl_zero_schema")?.evidence_hash.clone(),
        ddl_failure_zero_ledger_proof_hash: r("ddl_zero_ledger")?.proof_hash.clone(),
        ddl_failure_zero_ledger_delta_hash: r("ddl_zero_ledger")?.evidence_hash.clone(),
        ledger_failure_outcome_evidence_hash: p("ledger_failure_apply")?.evidence_hash.clone(),
        ledger_failure_zero_schema_proof_hash: r("ledger_zero_schema")?.proof_hash.clone(),
        ledger_failure_zero_schema_delta_hash: r("ledger_zero_schema")?.evidence_hash.clone(),
        ledger_failure_zero_ledger_proof_hash: r("ledger_zero_ledger")?.proof_hash.clone(),
        ledger_failure_zero_ledger_delta_hash: r("ledger_zero_ledger")?.evidence_hash.clone(),
        cleanup_proof_hash: r("cleanup_absence")?.proof_hash.clone(),
        cleanup_evidence_hash: r("cleanup_absence")?.evidence_hash.clone(),
        success_passed: true,
        ddl_failure_observed: true,
        ddl_failure_zero_schema_delta: true,
        ddl_failure_zero_ledger_delta: true,
        ledger_failure_observed: true,
        ledger_failure_zero_schema_delta: true,
        ledger_failure_zero_ledger_delta: true,
        cleanup_database_absent: true,
        completed_at: now,
    })
}

fn plan<'a>(plans: &'a [OwnedPlanExpectation], role: &str) -> Result<&'a OwnedPlanExpectation> {
    plans
        .iter()
        .find(|value| value.role == role)
        .ok_or_else(|| {
            CliError::Input(format!(
                "workspace D1 qualification plan role `{role}` is missing"
            ))
        })
}
fn proof<'a>(proofs: &'a [OwnedProofExpectation], role: &str) -> Result<&'a OwnedProofExpectation> {
    proofs
        .iter()
        .find(|value| value.role == role)
        .ok_or_else(|| {
            CliError::Input(format!(
                "workspace D1 qualification proof role `{role}` is missing"
            ))
        })
}
fn selector<'a>(input: &'a CallInput, name: &str) -> Result<&'a str> {
    input
        .selectors
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input(format!("workspace D1 qualification child omitted `{name}`"))
        })
}
fn target_string<'a>(target: &'a Value, name: &str) -> Result<&'a str> {
    target
        .pointer(&format!("/adapter/workspace_d1_migration/{name}"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input(format!(
                "workspace D1 qualification target omitted `{name}`"
            ))
        })
}
fn stored_plan_target(store: &StateStore, operation_id: &str) -> Result<Value> {
    match store.load_stored_plan_record(operation_id)? {
        cfctl_storage::StoredPlanRecord::Current(plan) => Ok(plan.plan.targets),
        _ => Err(CliError::Input(
            "workspace D1 qualification child is not current PlanV2".into(),
        )),
    }
}
fn stored_plan_hash(store: &StateStore, operation_id: &str) -> Result<String> {
    match store.load_stored_plan_record(operation_id)? {
        cfctl_storage::StoredPlanRecord::Current(plan) => Ok(plan.plan.content_hash),
        _ => Err(CliError::Input(
            "workspace D1 Worker plan is not current PlanV2".into(),
        )),
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{CliError, Value, VerificationState, produce};

    #[test]
    fn producer_authenticates_both_receipts_and_returns_six_joins_without_provider_effect()
    -> std::result::Result<(), CliError> {
        let (_root, store, catalog, input) = super::super::tests::producer_fixture();
        let envelope = produce(&store, &catalog, &input)?;
        assert!(!envelope.performed);
        assert_eq!(envelope.verification.state, VerificationState::Passed);
        assert_eq!(envelope.evidence.len(), 2);
        assert_eq!(
            envelope
                .result
                .pointer("/evidence_joins")
                .and_then(Value::as_object)
                .map(serde_json::Map::len),
            Some(6)
        );
        Ok(())
    }

    #[test]
    fn producer_rejects_raw_receipt_injection_and_hold_disposition()
    -> std::result::Result<(), CliError> {
        let (_root, store, catalog, mut input) = super::super::tests::producer_fixture();
        input.body = Some(json!({"schema_version":1,"atomicity_receipt":{}}));
        assert!(produce(&store, &catalog, &input).is_err());

        let (_root, store, catalog, mut input) = super::super::tests::producer_fixture();
        let body = input
            .body
            .as_mut()
            .ok_or_else(|| CliError::Input("producer fixture body is missing".to_owned()))?;
        body["old_worker_canary"]["disposition"] = json!("hold");
        assert!(produce(&store, &catalog, &input).is_err());
        Ok(())
    }
}
