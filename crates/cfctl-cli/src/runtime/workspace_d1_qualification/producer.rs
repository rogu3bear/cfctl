use cfctl_cloudflare::CallInput;
use cfctl_core::{
    EvidenceClass, OperationalProofOutcomeV1, PlanStatus, TransactionStageV1,
    WorkspaceD1AtomicityQualificationV1, WorkspaceD1OldWorkerCanaryV1, hash_value,
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{
    AtomicityExpectations, CanaryExpectations, OwnedPlanExpectation, OwnedProofExpectation,
    capability_role, derive_zero_delta_comparison, resolve_plan_expectation,
    resolve_proof_expectation, resolve_worker_plan_expectation, single_migration_sha256,
    validate_old_worker_canary, validate_qualification_pair,
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
    ddl_failure_schema_before_proof_hash: String,
    ddl_failure_schema_after_proof_hash: String,
    ddl_failure_ledger_before_proof_hash: String,
    ddl_failure_ledger_after_proof_hash: String,
    ledger_failure_schema_before_proof_hash: String,
    ledger_failure_schema_after_proof_hash: String,
    ledger_failure_ledger_before_proof_hash: String,
    ledger_failure_ledger_after_proof_hash: String,
    cleanup_proof_hash: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OldWorkerCanaryInputV1 {
    founder_canary_evidence_hash: String,
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
    if request.schema_version != 1 {
        return Err(CliError::Input(
            "workspace D1 qualification producer requires schema_version 1".into(),
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
            OperationalProofOutcomeV1::Succeeded,
        ),
        (
            "full_export",
            atomic.full_export_proof_hash.as_str(),
            "d1-full-export",
            OperationalProofOutcomeV1::Succeeded,
        ),
        (
            "bookmark",
            atomic.bookmark_proof_hash.as_str(),
            "d1-time-travel-get-bookmark",
            OperationalProofOutcomeV1::Succeeded,
        ),
        (
            "ddl_schema_before",
            atomic.ddl_failure_schema_before_proof_hash.as_str(),
            "d1-schema-introspection",
            OperationalProofOutcomeV1::Succeeded,
        ),
        (
            "ddl_schema_after",
            atomic.ddl_failure_schema_after_proof_hash.as_str(),
            "d1-schema-introspection",
            OperationalProofOutcomeV1::Succeeded,
        ),
        (
            "ddl_ledger_before",
            atomic.ddl_failure_ledger_before_proof_hash.as_str(),
            "mln-web.founder-d1-migration-apply",
            OperationalProofOutcomeV1::Succeeded,
        ),
        (
            "ddl_ledger_after",
            atomic.ddl_failure_ledger_after_proof_hash.as_str(),
            "mln-web.founder-d1-migration-apply",
            OperationalProofOutcomeV1::Succeeded,
        ),
        (
            "ledger_schema_before",
            atomic.ledger_failure_schema_before_proof_hash.as_str(),
            "d1-schema-introspection",
            OperationalProofOutcomeV1::Succeeded,
        ),
        (
            "ledger_schema_after",
            atomic.ledger_failure_schema_after_proof_hash.as_str(),
            "d1-schema-introspection",
            OperationalProofOutcomeV1::Succeeded,
        ),
        (
            "ledger_ledger_before",
            atomic.ledger_failure_ledger_before_proof_hash.as_str(),
            "mln-web.founder-d1-migration-apply",
            OperationalProofOutcomeV1::Succeeded,
        ),
        (
            "ledger_ledger_after",
            atomic.ledger_failure_ledger_after_proof_hash.as_str(),
            "mln-web.founder-d1-migration-apply",
            OperationalProofOutcomeV1::Succeeded,
        ),
        (
            "cleanup_absence",
            atomic.cleanup_proof_hash.as_str(),
            "d1-get-database",
            OperationalProofOutcomeV1::Failed,
        ),
    ];
    let proofs = proof_specs
        .into_iter()
        .map(|(role, proof_hash, capability, outcome)| {
            resolve_proof_expectation(
                store,
                proof_role(role),
                proof_hash,
                capability,
                Some(&d1_input_hash),
                None,
                outcome,
            )
        })
        .collect::<Result<Vec<_>>>()?;

    let worker = request.old_worker_canary;
    let canary_evidence = store.load_evidence(&worker.founder_canary_evidence_hash)?;
    let canary: WorkspaceD1OldWorkerCanaryV1 =
        serde_json::from_value(store.read_evidence_value(&canary_evidence.content_hash)?)
            .map_err(|_| CliError::Input("Founder-owned old-Worker canary is malformed".into()))?;
    let worker_plan = resolve_worker_plan_expectation(
        store,
        &canary.worker_deployment_operation_id,
        &canary.worker_deployment_plan_hash,
    )?;
    let worker_script_name = selector(&worker_plan.input, "script_name")?.to_owned();
    let worker_specs = [
        (
            "deployments",
            canary.deployments_read_proof_hash.as_str(),
            "worker-deployments-list-deployments",
        ),
        (
            "version",
            canary.version_detail_proof_hash.as_str(),
            "worker-versions-get-version-detail",
        ),
        (
            "settings",
            canary.settings_proof_hash.as_str(),
            "worker-script-get-settings",
        ),
    ];
    let worker_proofs = worker_specs
        .into_iter()
        .map(|(role, proof_hash, capability)| {
            resolve_proof_expectation(
                store,
                worker_role(role),
                proof_hash,
                capability,
                None,
                None,
                OperationalProofOutcomeV1::Succeeded,
            )
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
    validate_old_worker_canary(store, &canary_evidence, &canary_expected, Utc::now())?;

    let atomicity = atomicity_receipt(
        store,
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
    store: &StateStore,
    input: &AtomicityChildrenV1,
    plans: &[OwnedPlanExpectation],
    proofs: &[OwnedProofExpectation],
    expected: &AtomicityExpectations<'_>,
    database_id: &str,
    now: chrono::DateTime<Utc>,
) -> Result<WorkspaceD1AtomicityQualificationV1> {
    let p = |role| plan(plans, role);
    let r = |role| proof(proofs, role);
    let delta = |observation, before_role, after_role, plan_role| {
        derive_zero_delta_comparison(
            store,
            observation,
            &r(before_role)?.borrowed(),
            &r(after_role)?.borrowed(),
            &p(plan_role)?.borrowed(),
        )
    };
    let ddl_failure_schema_delta = delta(
        "schema",
        "ddl_schema_before",
        "ddl_schema_after",
        "ddl_failure_apply",
    )?;
    let ddl_failure_ledger_delta = delta(
        "ledger",
        "ddl_ledger_before",
        "ddl_ledger_after",
        "ddl_failure_apply",
    )?;
    let ledger_failure_schema_delta = delta(
        "schema",
        "ledger_schema_before",
        "ledger_schema_after",
        "ledger_failure_apply",
    )?;
    let ledger_failure_ledger_delta = delta(
        "ledger",
        "ledger_ledger_before",
        "ledger_ledger_after",
        "ledger_failure_apply",
    )?;
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
        ddl_failure_schema_delta,
        ddl_failure_ledger_delta,
        ledger_failure_outcome_evidence_hash: p("ledger_failure_apply")?.evidence_hash.clone(),
        ledger_failure_schema_delta,
        ledger_failure_ledger_delta,
        cleanup_proof_hash: r("cleanup_absence")?.proof_hash.clone(),
        cleanup_evidence_hash: r("cleanup_absence")?.evidence_hash.clone(),
        success_passed: true,
        ddl_failure_observed: true,
        ledger_failure_observed: true,
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
fn proof_role(role: &str) -> &'static str {
    match role {
        "get_database" => "get_database",
        "full_export" => "full_export",
        "bookmark" => "bookmark",
        "ddl_schema_before" => "ddl_schema_before",
        "ddl_schema_after" => "ddl_schema_after",
        "ddl_ledger_before" => "ddl_ledger_before",
        "ddl_ledger_after" => "ddl_ledger_after",
        "ledger_schema_before" => "ledger_schema_before",
        "ledger_schema_after" => "ledger_schema_after",
        "ledger_ledger_before" => "ledger_ledger_before",
        "ledger_ledger_after" => "ledger_ledger_after",
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
    fn producer_rejects_raw_receipt_and_caller_authored_canary_injection()
    -> std::result::Result<(), CliError> {
        let (_root, store, catalog, mut input) = super::super::tests::producer_fixture();
        input.body = Some(json!({"schema_version":1,"atomicity_receipt":{}}));
        assert!(produce(&store, &catalog, &input).is_err());

        let (_root, store, catalog, mut input) = super::super::tests::producer_fixture();
        let body = input
            .body
            .as_mut()
            .ok_or_else(|| CliError::Input("producer fixture body is missing".to_owned()))?;
        body["old_worker_canary"]["disposition"] = json!("pass");
        assert!(produce(&store, &catalog, &input).is_err());
        Ok(())
    }

    #[test]
    fn producer_rejects_successful_database_detail_as_cleanup_absence() {
        let (_root, store, catalog, input) =
            super::super::tests::producer_fixture_with_successful_cleanup();

        assert!(produce(&store, &catalog, &input).is_err());
    }

    #[test]
    fn producer_rejects_identical_zero_delta_receipt_identity() {
        let (_root, store, catalog, input) =
            super::super::tests::producer_fixture_with_duplicate_delta_identity();

        assert!(produce(&store, &catalog, &input).is_err());
    }

    #[test]
    fn producer_rejects_caller_authored_canary_semantics() -> std::result::Result<(), CliError> {
        let (_root, store, catalog, mut input) = super::super::tests::producer_fixture();
        let body = input
            .body
            .as_mut()
            .ok_or_else(|| CliError::Input("producer fixture body is missing".to_owned()))?;
        body["old_worker_canary"]["semantic_assertions_sha256"] =
            json!("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        assert!(produce(&store, &catalog, &input).is_err());
        Ok(())
    }
}
