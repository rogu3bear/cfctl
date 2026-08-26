use super::import_failures::exact_durable_poll_exhaustion;
use super::import_planning::ImportPrerequisiteContext;
use super::import_planning::validate_approved_mln_import_prerequisites;
use super::import_resume::exact_durable_resume_provider_complete_boundary;
use super::import_resume::exact_resume_poll_exhaustion;
use super::import_resume::validate_managed_reviewed_git_stage_authority;
use super::prelude::{
    BTreeMap, BTreeSet, CallInput, CapabilityV1, CatalogSnapshot, CliError, PlanStatus, PlanV1,
    PlanV2, Result, StateStore, StoredPlanRecord, TransactionStageV1, Utc, Value, json,
};
use super::r2_credentials::preflight_call_input;
use cfctl_catalog::ingest_native_control_capabilities;
use cfctl_core::hash_value;

#[derive(Debug, Clone)]
pub(super) struct DurableProviderCompleteBoundary {
    pub(super) evidence_hash: String,
    pub(super) checkpoint: Value,
}

pub(super) fn trusted_native_capability(capability_id: &str) -> Result<CapabilityV1> {
    let mut trusted_catalog = CatalogSnapshot {
        schema_version: 1,
        generated_at: Utc::now(),
        source_url: "native://control".to_owned(),
        source_hash: "sha256:native-control".to_owned(),
        schema_hash: String::new(),
        capabilities: BTreeMap::new(),
    };
    ingest_native_control_capabilities(&mut trusted_catalog)?;
    trusted_catalog
        .capabilities
        .remove(capability_id)
        .ok_or_else(|| {
            CliError::Input(format!(
                "trusted native capability declaration `{capability_id}` is missing"
            ))
        })
}

#[expect(
    clippy::too_many_lines,
    reason = "trusted root admission joins native request, governed prerequisites, source, and stage"
)]
pub(super) fn validate_trusted_root_import_plan(
    store: &StateStore,
    plan_v2: &PlanV2,
) -> Result<()> {
    plan_v2.validate()?;
    let plan = &plan_v2.plan;
    let trusted = trusted_native_capability(&plan.capability.id)?;
    if plan.capability != trusted
        || plan_v2.pins.catalog_hash != plan.catalog_hash
        || plan.precondition_hashes.get("catalog") != Some(&plan.catalog_hash)
    {
        return Err(CliError::Input(
            "governed D1 import does not match its trusted native catalog declaration".to_owned(),
        ));
    }
    if matches!(
        plan.capability.id.as_str(),
        "d1-import-database" | "d1-apply-reviewed-schema-migration"
    ) {
        return validate_trusted_reviewed_git_root_plan(store, plan_v2, &trusted);
    }
    let contract = trusted
        .d1_approved_mln_import
        .as_ref()
        .ok_or_else(|| CliError::Input("trusted import contract is missing".to_owned()))?;
    let input: CallInput = serde_json::from_value(plan.input.clone())?;
    let migration_id = input
        .body
        .as_ref()
        .and_then(|body| body.get("migration_id"))
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("trusted import migration id is missing".to_owned()))?;
    let migration = contract
        .migrations
        .iter()
        .find(|migration| migration.migration_id == migration_id)
        .ok_or_else(|| CliError::Input("trusted import migration is not catalogued".to_owned()))?;
    if input.selectors
        != json!({
            "account_id":contract.account_id,
            "database_id":contract.database_id,
        })
        || input.query != json!({})
        || input.if_match.is_some()
        || input.if_none_match.is_some()
    {
        return Err(CliError::Input(
            "approved MLN import input is not the exact trusted migration request".to_owned(),
        ));
    }
    preflight_call_input(&trusted, &input, None)?;
    validate_approved_mln_import_prerequisites(
        store,
        &trusted,
        &input,
        ImportPrerequisiteContext {
            profile_id: &plan.profile_id,
            credential_generation_id: Some(&plan_v2.pins.credential_generation_id),
            catalog_hash: &plan.catalog_hash,
            import_operation_id: Some(&plan.operation_id),
            before: plan.created_at,
        },
    )?;
    let stage = plan
        .targets
        .pointer("/adapter/approved_mln_import")
        .ok_or_else(|| CliError::Input("trusted import managed stage is missing".to_owned()))?;
    let source = stage
        .get("source_authority")
        .ok_or_else(|| CliError::Input("trusted import source authority is missing".to_owned()))?;
    let target = json!({
        "account_id":contract.account_id,
        "database_id":contract.database_id,
    });
    let source_hash = hash_value(source)?;
    if plan.account_id != contract.account_id
        || source.get("schema_version").and_then(Value::as_u64) != Some(1)
        || source
            .get("observed_worktree_root")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || source
            .get("observed_git_common_dir")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || stage.get("schema_version").and_then(Value::as_u64) != Some(1)
        || stage.get("migration_id").and_then(Value::as_str) != Some(migration_id)
        || stage.get("catalog_basename").and_then(Value::as_str)
            != Some(migration.basename.as_str())
        || stage.get("bytes").and_then(Value::as_u64) != Some(migration.bytes)
        || stage.get("sha256").and_then(Value::as_str)
            != Some(format!("sha256:{}", migration.sha256).as_str())
        || stage.get("md5").and_then(Value::as_str) != Some(migration.md5.as_str())
        || stage.get("target") != Some(&target)
        || stage.get("source_authority_hash").and_then(Value::as_str) != Some(source_hash.as_str())
        || stage
            .get("stage_path")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || stage.get("stage_lifecycle").and_then(Value::as_str)
            != Some("preserve_until_verified_or_explicitly_retired")
        || stage.get("prerequisites") != input.body.as_ref()
        || source.get("repository_id").and_then(Value::as_str)
            != Some(contract.repository_id.as_str())
        || source.get("head").and_then(Value::as_str) != Some(contract.repository_head.as_str())
        || source
            .get("repository_relative_path")
            .and_then(Value::as_str)
            != Some(migration.repository_relative_path.as_str())
        || source.get("git_blob_oid").and_then(Value::as_str)
            != Some(migration.git_blob_oid.as_str())
    {
        return Err(CliError::Input(
            "approved MLN import source authority or managed stage drifted from the trusted migration"
                .to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn validate_trusted_reviewed_git_root_plan(
    store: &StateStore,
    plan_v2: &PlanV2,
    trusted: &CapabilityV1,
) -> Result<()> {
    let plan = &plan_v2.plan;
    let input: CallInput = serde_json::from_value(plan.input.clone())?;
    let stage = plan
        .targets
        .pointer("/adapter/approved_mln_import")
        .ok_or_else(|| CliError::Input("trusted reviewed-Git stage is missing".to_owned()))?;
    let target = stage
        .get("target")
        .ok_or_else(|| CliError::Input("trusted reviewed-Git target is missing".to_owned()))?;
    if input.selectors != *target
        || input.query != json!({})
        || input.if_match.is_some()
        || input.if_none_match.is_some()
        || stage.get("prerequisites") != input.body.as_ref()
        || plan.account_id
            != input
                .selectors
                .get("account_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
    {
        return Err(CliError::Input(
            "reviewed-Git root input, target, or prerequisite binding drifted".to_owned(),
        ));
    }
    preflight_call_input(trusted, &input, None)?;
    validate_approved_mln_import_prerequisites(
        store,
        trusted,
        &input,
        ImportPrerequisiteContext {
            profile_id: &plan.profile_id,
            credential_generation_id: Some(&plan_v2.pins.credential_generation_id),
            catalog_hash: &plan.catalog_hash,
            import_operation_id: Some(&plan.operation_id),
            before: plan.created_at,
        },
    )?;
    validate_managed_reviewed_git_stage_authority(plan)
}

#[expect(
    clippy::too_many_lines,
    reason = "canonical child admission joins journal, response, evidence, and terminal outcome"
)]
pub(super) fn validate_canonical_poll_child_lifecycle(
    store: &StateStore,
    current: &PlanV2,
) -> Result<Option<DurableProviderCompleteBoundary>> {
    let plan = &current.plan;
    plan.validate_transaction_journal()?;
    let terminal_status = match plan.status {
        PlanStatus::Running => PlanStatus::Running,
        PlanStatus::RectificationRequired => PlanStatus::RectificationRequired,
        _ => {
            return Err(CliError::Input(
                "poll child has no authentic terminal provider outcome".to_owned(),
            ));
        }
    };
    let expected = [
        (TransactionStageV1::ApprovalPersisted, PlanStatus::Approved),
        (
            TransactionStageV1::ConsumptionPersisted,
            PlanStatus::Consumed,
        ),
        (
            TransactionStageV1::BoundaryAttemptPersisted,
            PlanStatus::Consumed,
        ),
        (
            TransactionStageV1::BoundaryResponsePersisted,
            terminal_status,
        ),
        (TransactionStageV1::SecretSinkPersisted, terminal_status),
    ];
    if plan.transaction_stage != TransactionStageV1::SecretSinkPersisted
        || expected.into_iter().any(|(stage, status)| {
            plan.transaction_journal
                .iter()
                .filter(|checkpoint| checkpoint.stage == stage && checkpoint.plan_status == status)
                .count()
                != 1
        })
    {
        return Err(CliError::Input(
            "poll child journal does not match the exact production boundary lifecycle".to_owned(),
        ));
    }
    let response_artifact = plan
        .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
        .ok_or_else(|| {
            CliError::Input("poll child boundary response artifact is missing".to_owned())
        })?;
    let secret_artifact = plan
        .transaction_artifact(TransactionStageV1::SecretSinkPersisted)
        .ok_or_else(|| {
            CliError::Input("poll child secret lifecycle artifact is missing".to_owned())
        })?;
    if secret_artifact
        != &json!({
            "completed":true,
            "failure":Value::Null,
            "input_cleanup":{"required":false,"completed":true},
            "output_sink":{"required":false,"completed":true,"create_new":false,
                "format":Value::Null,"unix_mode":if cfg!(unix) { Value::String("0600".to_owned()) } else { Value::Null }},
            "path":Value::Null,
        })
    {
        return Err(CliError::Input(
            "poll child secret lifecycle artifact drifted".to_owned(),
        ));
    }
    if terminal_status == PlanStatus::Running {
        let boundary = exact_durable_resume_provider_complete_boundary(store, plan)?;
        let apply_hash = response_artifact
            .get("apply_evidence_hash")
            .and_then(Value::as_str)
            .filter(|hash| !hash.is_empty())
            .ok_or_else(|| {
                CliError::Input(
                    "completed poll child response artifact lacks apply evidence".to_owned(),
                )
            })?;
        let apply_response = store.read_evidence_value(apply_hash)?;
        let receipt = boundary
            .checkpoint
            .get("receipt")
            .ok_or_else(|| CliError::Input("provider completion receipt is missing".to_owned()))?;
        let exact_response = response_artifact.get("success").and_then(Value::as_bool)
            == Some(true)
            && response_artifact.get("http_status").and_then(Value::as_u64) == Some(200)
            && apply_response.get("status").and_then(Value::as_u64) == Some(200)
            && apply_response.get("success").and_then(Value::as_bool) == Some(true)
            && apply_response
                .get("errors")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
            && apply_response.pointer("/result/_cfctl") == Some(receipt)
            && apply_response
                .pointer("/result/type")
                .and_then(Value::as_str)
                == Some("import")
            && apply_response
                .pointer("/result/status")
                .and_then(Value::as_str)
                == Some("complete")
            && apply_response
                .pointer("/result/success")
                .and_then(Value::as_bool)
                == Some(true)
            && apply_response
                .pointer("/result/at_bookmark")
                .and_then(Value::as_str)
                == receipt.get("at_bookmark").and_then(Value::as_str)
            && apply_response
                .pointer("/result/result/final_bookmark")
                .and_then(Value::as_str)
                == receipt.get("final_bookmark").and_then(Value::as_str);
        if !exact_response {
            return Err(CliError::Input(
                "completed poll child apply evidence does not match provider completion".to_owned(),
            ));
        }
        Ok(Some(boundary))
    } else {
        let exhaustion = exact_resume_poll_exhaustion(store, plan)?;
        if response_artifact
            != &json!({
                "adapter":"dynamic_api",
                "performed":true,
                "success":false,
                "outcome":"poll_in_progress_exhausted",
                "receipt_available":true,
                "poll_exhaustion_evidence_hash":exhaustion.exhaustion_evidence.content_hash,
                "accepted_ingest_evidence_hash":exhaustion.accepted_ingest_evidence.content_hash,
            })
        {
            return Err(CliError::Input(
                "exhausted poll child lacks its exact exhaustion response artifact".to_owned(),
            ));
        }
        Ok(None)
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one fail-closed join authenticates every stored-plan, stage, ingest, and terminal receipt field"
)]
pub(super) fn exact_durable_provider_complete_boundary(
    store: &StateStore,
    operation_id: &str,
) -> Result<DurableProviderCompleteBoundary> {
    let StoredPlanRecord::Current(plan_v2) = store.load_stored_plan_record(operation_id)? else {
        return Err(CliError::Input(
            "durable provider completion requires the exact immutable PlanV2".to_owned(),
        ));
    };
    let plan = &plan_v2.plan;
    validate_trusted_root_import_plan(store, &plan_v2)?;
    if plan.operation_id != operation_id
        || plan.profile_id.is_empty()
        || plan.catalog_hash.is_empty()
        || plan_v2.pins.catalog_hash != plan.catalog_hash
        || plan_v2.pins.credential_generation_id.is_empty()
        || plan.precondition_hashes.get("catalog") != Some(&plan.catalog_hash)
    {
        return Err(CliError::Input(
            "durable provider completion lost its plan, catalog, profile, or credential binding"
                .to_owned(),
        ));
    }
    let input: CallInput = serde_json::from_value(plan.input.clone())?;
    let staged = plan
        .targets
        .pointer("/adapter/approved_mln_import")
        .ok_or_else(|| CliError::Input("managed import stage binding is missing".to_owned()))?;
    let source_authority = staged
        .get("source_authority")
        .ok_or_else(|| CliError::Input("managed source authority is missing".to_owned()))?;
    let expected_source_authority_hash = hash_value(source_authority)?;
    let expected_stage_identity_hash = hash_value(staged)?;
    let migration_id = staged
        .get("migration_id")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("import migration identity is missing".to_owned()))?;
    let expected_sha256 = staged
        .get("sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("managed source SHA-256 is missing".to_owned()))?;
    let expected_md5 = staged
        .get("md5")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("managed source MD5 is missing".to_owned()))?;
    let expected_bytes = staged
        .get("bytes")
        .and_then(Value::as_u64)
        .ok_or_else(|| CliError::Input("managed source size is missing".to_owned()))?;
    let target = staged
        .get("target")
        .cloned()
        .ok_or_else(|| CliError::Input("managed import target is missing".to_owned()))?;
    let legacy_catalog_matches = if plan.capability.id == "d1-import-database" {
        staged.get("source_authority_hash").and_then(Value::as_str) == Some(migration_id)
    } else {
        let contract = plan
            .capability
            .d1_approved_mln_import
            .as_ref()
            .ok_or_else(|| CliError::Input("approved import contract is missing".to_owned()))?;
        contract
            .migrations
            .iter()
            .find(|migration| migration.migration_id == migration_id)
            .is_some_and(|migration| {
                source_authority
                    .get("repository_id")
                    .and_then(Value::as_str)
                    == Some(contract.repository_id.as_str())
                    && source_authority.get("head").and_then(Value::as_str)
                        == Some(contract.repository_head.as_str())
                    && source_authority
                        .get("repository_relative_path")
                        .and_then(Value::as_str)
                        == Some(migration.repository_relative_path.as_str())
                    && source_authority.get("git_blob_oid").and_then(Value::as_str)
                        == Some(migration.git_blob_oid.as_str())
                    && staged.get("catalog_basename").and_then(Value::as_str)
                        == Some(migration.basename.as_str())
                    && expected_sha256 == format!("sha256:{}", migration.sha256)
                    && expected_md5 == migration.md5
                    && expected_bytes == migration.bytes
                    && target
                        == json!({
                            "account_id":contract.account_id,
                            "database_id":contract.database_id,
                        })
            })
    };
    if source_authority
        .get("schema_version")
        .and_then(Value::as_u64)
        != Some(1)
        || !legacy_catalog_matches
        || source_authority
            .get("observed_worktree_root")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || source_authority
            .get("observed_git_common_dir")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || staged.get("schema_version").and_then(Value::as_u64) != Some(1)
        || staged.get("source_authority_hash").and_then(Value::as_str)
            != Some(expected_source_authority_hash.as_str())
        || staged.get("migration_id").and_then(Value::as_str) != Some(migration_id)
        || target.get("account_id").and_then(Value::as_str) != Some(plan.account_id.as_str())
        || staged
            .get("stage_path")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || staged.get("stage_lifecycle").and_then(Value::as_str)
            != Some("preserve_until_verified_or_explicitly_retired")
        || staged.get("prerequisites") != input.body.as_ref()
    {
        return Err(CliError::Input(
            "durable provider completion lost its exact managed source or stage identity"
                .to_owned(),
        ));
    }
    let input_hash = hash_value(&plan.input)?;
    let checkpoints = store.read_d1_import_checkpoints(operation_id)?;
    let provider_complete = checkpoints
        .iter()
        .filter(|(_, checkpoint)| {
            checkpoint.get("step").and_then(Value::as_str) == Some("provider_complete")
        })
        .collect::<Vec<_>>();
    if provider_complete.is_empty() {
        return exact_linear_poll_child_provider_complete(store, plan);
    }
    if provider_complete.len() != 1 {
        return Err(CliError::Input(
            "approved MLN import requires exactly one total provider_complete checkpoint"
                .to_owned(),
        ));
    }
    let accepted_ingest_bookmarks =
        exact_accepted_ingest_bookmarks(store, plan, &checkpoints, &target, &input_hash);
    if accepted_ingest_bookmarks.len() != 1 {
        return Err(CliError::Input(
            "provider completion requires exactly one immutable accepted-ingest authority"
                .to_owned(),
        ));
    }
    let (hash, checkpoint) = provider_complete[0];
    let final_bookmark = checkpoint
        .pointer("/receipt/final_bookmark")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty());
    let accepted_bookmark = accepted_ingest_bookmarks.first().map(String::as_str);
    let exact = checkpoint.get("schema_version").and_then(Value::as_u64) == Some(1)
        && checkpoint.get("operation_id").and_then(Value::as_str) == Some(operation_id)
        && checkpoint.get("step").and_then(Value::as_str) == Some("provider_complete")
        && checkpoint.get("performed").and_then(Value::as_bool) == Some(true)
        && checkpoint
            .get("rectification_required")
            .and_then(Value::as_bool)
            == Some(false)
        && checkpoint
            .pointer("/receipt/provider")
            .and_then(Value::as_str)
            == Some("cloudflare")
        && checkpoint
            .pointer("/receipt/effect")
            .and_then(Value::as_str)
            == Some("d1_import_provider_complete")
        && checkpoint
            .pointer("/receipt/response_action")
            .and_then(Value::as_str)
            == Some("poll")
        && checkpoint
            .pointer("/receipt/no_replay")
            .and_then(Value::as_bool)
            == Some(true)
        && checkpoint.pointer("/receipt/state").and_then(Value::as_str)
            == Some("provider_complete")
        && checkpoint
            .pointer("/receipt/provider_status")
            .and_then(Value::as_str)
            == Some("complete")
        && checkpoint
            .pointer("/receipt/provider_success")
            .and_then(Value::as_bool)
            == Some(true)
        && checkpoint
            .pointer("/receipt/migration_id")
            .and_then(Value::as_str)
            == Some(migration_id)
        && checkpoint.pointer("/receipt/target") == Some(&target)
        && checkpoint
            .pointer("/receipt/plan_input_hash")
            .and_then(Value::as_str)
            == Some(input_hash.as_str())
        && checkpoint
            .pointer("/receipt/source_sha256")
            .and_then(Value::as_str)
            == Some(expected_sha256)
        && checkpoint
            .pointer("/receipt/source_md5")
            .and_then(Value::as_str)
            == Some(expected_md5)
        && checkpoint
            .pointer("/receipt/source_bytes")
            .and_then(Value::as_u64)
            == Some(expected_bytes)
        && checkpoint
            .pointer("/receipt/source_authority_hash")
            .and_then(Value::as_str)
            == Some(expected_source_authority_hash.as_str())
        && checkpoint
            .pointer("/receipt/stage_identity_hash")
            .and_then(Value::as_str)
            == Some(expected_stage_identity_hash.as_str())
        && checkpoint.pointer("/receipt/prerequisites") == input.body.as_ref()
        && checkpoint
            .pointer("/receipt/at_bookmark")
            .and_then(Value::as_str)
            == accepted_bookmark
        && final_bookmark.is_some();
    if !exact {
        return Err(CliError::Input(
            "approved MLN import lacks exact durable provider completion".to_owned(),
        ));
    }
    if store.read_evidence_value(hash)? != *checkpoint {
        return Err(CliError::Input(
            "provider_complete evidence does not match its immutable checkpoint".to_owned(),
        ));
    }
    Ok(DurableProviderCompleteBoundary {
        evidence_hash: hash.clone(),
        checkpoint: checkpoint.clone(),
    })
}

#[expect(
    clippy::too_many_lines,
    reason = "linear child completion joins every immutable root and parent authority pin"
)]
pub(super) fn exact_linear_poll_child_provider_complete(
    store: &StateStore,
    root: &PlanV1,
) -> Result<DurableProviderCompleteBoundary> {
    let resume_capability_id = if root.capability.id == "d1-import-database" {
        "d1-resume-database-import-poll"
    } else {
        "d1-resume-approved-mln-import-poll"
    };
    let canonical_capability = trusted_native_capability(resume_capability_id)?;
    let canonical_contract_hash = hash_value(&serde_json::to_value(&canonical_capability)?)?;
    let root_v2 = store.load_plan_v2(&root.operation_id)?;
    validate_trusted_root_import_plan(store, &root_v2)?;
    if root_v2.plan != *root {
        return Err(CliError::Input(
            "root import projection does not match its canonical PlanV2".to_owned(),
        ));
    }
    let root_contract = root
        .capability
        .d1_approved_mln_import
        .as_ref()
        .ok_or_else(|| CliError::Input("root approved import contract is missing".to_owned()))?;
    let canonical_contract = canonical_capability
        .d1_approved_mln_import_poll_resume
        .as_ref()
        .ok_or_else(|| {
            CliError::Input("trusted poll continuation contract is missing".to_owned())
        })?;
    let root_target = if root.capability.id == "d1-import-database" {
        root.targets
            .pointer("/adapter/approved_mln_import/target")
            .cloned()
            .ok_or_else(|| CliError::Input("reviewed root import target is missing".to_owned()))?
    } else {
        json!({
            "account_id":root_contract.account_id,
            "database_id":root_contract.database_id,
        })
    };
    let canonical_target_matches = if root.capability.id == "d1-import-database" {
        canonical_contract.account_id.is_empty()
            && canonical_contract.database_id.is_empty()
            && canonical_contract.root_capability_id == "d1-import-database"
            && root_target.get("account_id").and_then(Value::as_str)
                == Some(root.account_id.as_str())
    } else {
        root.account_id == root_contract.account_id
            && canonical_contract.account_id == root_contract.account_id
            && canonical_contract.database_id == root_contract.database_id
    };
    if !canonical_target_matches
        || root.targets.pointer("/adapter/approved_mln_import/target") != Some(&root_target)
    {
        return Err(CliError::Input(
            "root, managed stage, and trusted poll continuation target drifted".to_owned(),
        ));
    }
    let discovered = store
        .list_plans()?
        .into_iter()
        .filter(|candidate| {
            candidate.capability.id == resume_capability_id
                && candidate
                    .targets
                    .pointer("/adapter/approved_mln_import_poll_resume/root_operation_id")
                    .and_then(Value::as_str)
                    == Some(root.operation_id.as_str())
        })
        .collect::<Vec<_>>();
    let children = discovered
        .into_iter()
        .map(|projection| {
            let StoredPlanRecord::Current(current) =
                store.load_stored_plan_record(&projection.operation_id)?
            else {
                return Err(CliError::Input(
                    "every root-claiming poll child must have an authentic PlanV2 sidecar"
                        .to_owned(),
                ));
            };
            if serde_json::to_value(&projection)? != serde_json::to_value(&current.plan)?
                || current.pins.catalog_hash != current.plan.catalog_hash
                || current.pins.catalog_hash != root_v2.pins.catalog_hash
                || current.pins.credential_generation_id
                    != root_v2.pins.credential_generation_id
                || current.plan.capability.id != resume_capability_id
                || current.plan.capability != canonical_capability
                || current.plan.approval.is_none()
            {
                return Err(CliError::Input(
                    "poll child PlanV2 projection, pins, approval, consumption, or boundary lifecycle is invalid"
                        .to_owned(),
                ));
            }
            let authority = current
                .plan
                .targets
                .pointer("/adapter/approved_mln_import_poll_resume")
                .ok_or_else(|| CliError::Input("poll child authority is missing".to_owned()))?;
            let contract_hash = hash_value(&serde_json::to_value(&current.plan.capability)?)?;
            let contract = current
                .plan
                .capability
                .d1_approved_mln_import_poll_resume
                .as_ref()
                .ok_or_else(|| CliError::Input("poll child contract is missing".to_owned()))?;
            let target = if resume_capability_id == "d1-resume-database-import-poll" {
                authority
                    .get("target")
                    .cloned()
                    .ok_or_else(|| CliError::Input("poll child target is missing".to_owned()))?
            } else {
                json!({
                    "account_id":contract.account_id,
                    "database_id":contract.database_id,
                })
            };
            let input: CallInput = serde_json::from_value(current.plan.input.clone())?;
            let body = input
                .body
                .as_ref()
                .and_then(Value::as_object)
                .ok_or_else(|| CliError::Input("poll child input body is missing".to_owned()))?;
            let exact_input_fields = [
                "parent_operation_id",
                "parent_plan_hash",
                "exhaustion_evidence_hash",
                "accepted_ingest_evidence_hash",
                "accepted_bookmark_hash",
            ]
            .into_iter()
            .collect::<BTreeSet<_>>();
            if authority.get("profile_id").and_then(Value::as_str)
                != Some(root.profile_id.as_str())
                || current.plan.profile_id != root.profile_id
                || current.plan.account_id != root.account_id
                || authority
                    .get("credential_generation_id")
                    .and_then(Value::as_str)
                    != Some(root_v2.pins.credential_generation_id.as_str())
                || authority.get("catalog_hash").and_then(Value::as_str)
                    != Some(root.catalog_hash.as_str())
                || authority
                    .get("capability_contract_hash")
                    .and_then(Value::as_str)
                    != Some(canonical_contract_hash.as_str())
                || contract_hash != canonical_contract_hash
                || authority.get("root_operation_id").and_then(Value::as_str)
                    != Some(root.operation_id.as_str())
                || authority.get("root_plan_hash").and_then(Value::as_str)
                    != Some(root.content_hash.as_str())
                || authority.get("root_input") != Some(&root.input)
                || authority.get("root_stage")
                    != root.targets.pointer("/adapter/approved_mln_import")
                || authority.get("target") != Some(&target)
                || input.selectors != target
                || !input
                    .query
                    .as_object()
                    .is_none_or(serde_json::Map::is_empty)
                || input.if_match.is_some()
                || input.if_none_match.is_some()
                || body.keys().map(String::as_str).collect::<BTreeSet<_>>()
                    != exact_input_fields
                || body.get("parent_operation_id") != authority.get("parent_operation_id")
                || body.get("parent_plan_hash") != authority.get("parent_plan_hash")
                || body.get("exhaustion_evidence_hash")
                    != authority.get("parent_exhaustion_evidence_hash")
                || body.get("accepted_ingest_evidence_hash")
                    != authority.get("accepted_ingest_evidence_hash")
                || body.get("accepted_bookmark_hash")
                    != authority.get("accepted_bookmark_hash")
            {
                return Err(CliError::Input(
                    "poll child profile, credential, catalog, contract, input, or root authority drifted"
                        .to_owned(),
                ));
            }
            validate_canonical_poll_child_lifecycle(store, &current)?;
            Ok(current)
        })
        .collect::<Result<Vec<_>>>()?;
    let completed = children
        .iter()
        .filter_map(|child| {
            validate_canonical_poll_child_lifecycle(store, child)
                .ok()
                .flatten()
                .map(|boundary| (child, boundary))
        })
        .collect::<Vec<_>>();
    if completed.len() != 1 {
        return Err(CliError::Input(
            "root import requires exactly one authentic linear poll-child provider completion"
                .to_owned(),
        ));
    }
    let (terminal, boundary) = &completed[0];
    let mut current = terminal.as_ref();
    let mut visited = BTreeSet::new();
    loop {
        if !visited.insert(current.plan.operation_id.clone()) {
            return Err(CliError::Input(
                "poll continuation lineage contains a cycle".to_owned(),
            ));
        }
        let authority = current
            .plan
            .targets
            .pointer("/adapter/approved_mln_import_poll_resume")
            .ok_or_else(|| CliError::Input("poll child authority is missing".to_owned()))?;
        if authority.get("root_plan_hash").and_then(Value::as_str)
            != Some(root.content_hash.as_str())
            || current.plan.profile_id != root.profile_id
            || current.plan.catalog_hash != root.catalog_hash
            || current.plan.account_id != root.account_id
        {
            return Err(CliError::Input(
                "poll child drifted from root plan, profile, account, or catalog".to_owned(),
            ));
        }
        let parent_id = authority
            .get("parent_operation_id")
            .and_then(Value::as_str)
            .ok_or_else(|| CliError::Input("poll child parent is missing".to_owned()))?;
        let StoredPlanRecord::Current(parent_v2) = store.load_stored_plan_record(parent_id)? else {
            return Err(CliError::Input(
                "poll child parent is not an immutable PlanV2".to_owned(),
            ));
        };
        let parent = &parent_v2.plan;
        if authority.get("parent_plan_hash").and_then(Value::as_str)
            != Some(parent.content_hash.as_str())
            || parent.created_at >= current.plan.created_at
            || parent_v2.pins.credential_generation_id
                != store
                    .load_plan_v2(&root.operation_id)?
                    .pins
                    .credential_generation_id
        {
            return Err(CliError::Input(
                "poll child parent PlanV2, credential, or chronology drifted".to_owned(),
            ));
        }
        let parent_target = if parent.operation_id == root.operation_id {
            root_target.clone()
        } else {
            parent
                .targets
                .pointer("/adapter/approved_mln_import_poll_resume/target")
                .cloned()
                .ok_or_else(|| CliError::Input("poll child parent target is missing".to_owned()))?
        };
        if authority.get("target") != Some(&parent_target) {
            return Err(CliError::Input(
                "poll child target does not match its exact parent target".to_owned(),
            ));
        }
        let (exhaustion_hash, accepted_hash, bookmark) = if parent.operation_id == root.operation_id
        {
            let (exhaustion, checkpoint, accepted) = exact_durable_poll_exhaustion(store, parent)?;
            (
                exhaustion.content_hash,
                accepted.content_hash,
                checkpoint
                    .pointer("/receipt/at_bookmark")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .ok_or_else(|| {
                        CliError::Input("root exhaustion bookmark is missing".to_owned())
                    })?,
            )
        } else {
            let exhaustion = exact_resume_poll_exhaustion(store, parent)?;
            (
                exhaustion.exhaustion_evidence.content_hash,
                exhaustion.accepted_ingest_evidence.content_hash,
                exhaustion.accepted_bookmark,
            )
        };
        if authority
            .get("parent_exhaustion_evidence_hash")
            .and_then(Value::as_str)
            != Some(exhaustion_hash.as_str())
            || authority
                .get("accepted_ingest_evidence_hash")
                .and_then(Value::as_str)
                != Some(accepted_hash.as_str())
            || authority.get("accepted_bookmark").and_then(Value::as_str) != Some(bookmark.as_str())
            || authority
                .get("accepted_bookmark_hash")
                .and_then(Value::as_str)
                != hash_value(&Value::String(bookmark)).ok().as_deref()
        {
            return Err(CliError::Input(
                "poll child does not join its exact parent exhaustion and accepted bookmark"
                    .to_owned(),
            ));
        }
        if parent.operation_id == root.operation_id {
            break;
        }
        current = children
            .iter()
            .find(|candidate| candidate.plan.operation_id == parent.operation_id)
            .map(Box::as_ref)
            .ok_or_else(|| {
                CliError::Input("poll child chain escaped its exact root lineage".to_owned())
            })?;
    }
    Ok(boundary.clone())
}

pub(super) fn exact_accepted_ingest_bookmarks(
    store: &StateStore,
    plan: &PlanV1,
    checkpoints: &[(String, Value)],
    target: &Value,
    input_hash: &str,
) -> Vec<String> {
    let migration_id = plan
        .input
        .pointer("/body/migration_id")
        .or_else(|| {
            plan.targets
                .pointer("/adapter/approved_mln_import/migration_id")
        })
        .and_then(Value::as_str);
    checkpoints
        .iter()
        .filter_map(|(hash, checkpoint)| {
            let exact = checkpoint.get("schema_version").and_then(Value::as_u64) == Some(1)
                && checkpoint.get("operation_id").and_then(Value::as_str)
                    == Some(plan.operation_id.as_str())
                && checkpoint.get("step").and_then(Value::as_str) == Some("ingest_response")
                && checkpoint.get("performed").and_then(Value::as_bool) == Some(true)
                && checkpoint
                    .get("rectification_required")
                    .and_then(Value::as_bool)
                    == Some(false)
                && checkpoint
                    .pointer("/receipt/success")
                    .and_then(Value::as_bool)
                    == Some(true)
                && checkpoint
                    .pointer("/receipt/response_action")
                    .and_then(Value::as_str)
                    == Some("ingest")
                && checkpoint
                    .pointer("/receipt/provider")
                    .and_then(Value::as_str)
                    == Some("cloudflare")
                && checkpoint
                    .pointer("/receipt/effect")
                    .and_then(Value::as_str)
                    == Some("d1_import_ingest_accepted")
                && checkpoint
                    .pointer("/receipt/migration_id")
                    .and_then(Value::as_str)
                    == migration_id
                && checkpoint.pointer("/receipt/target") == Some(target)
                && checkpoint
                    .pointer("/receipt/plan_input_hash")
                    .and_then(Value::as_str)
                    == Some(input_hash)
                && checkpoint
                    .pointer("/receipt/no_replay")
                    .and_then(Value::as_bool)
                    == Some(false)
                && checkpoint
                    .pointer("/receipt/result/type")
                    .and_then(Value::as_str)
                    == Some("import")
                && matches!(
                    checkpoint
                        .pointer("/receipt/result/status")
                        .and_then(Value::as_str),
                    Some("active" | "pending")
                )
                && checkpoint
                    .pointer("/receipt/result/success")
                    .and_then(Value::as_bool)
                    == Some(true)
                && checkpoint
                    .pointer("/receipt/result/provider_error_present")
                    .and_then(Value::as_bool)
                    .is_none_or(|present| !present)
                && checkpoint.pointer("/receipt/result/error").is_none()
                && store
                    .read_evidence_value(hash)
                    .is_ok_and(|evidence| evidence == *checkpoint);
            exact.then(|| {
                checkpoint
                    .pointer("/receipt/result/at_bookmark")
                    .and_then(Value::as_str)
                    .filter(|bookmark| !bookmark.is_empty())
                    .map(str::to_owned)
            })?
        })
        .collect()
}

pub(super) fn import_plan_runtime_lineage(
    plan: &PlanV1,
) -> Result<(Value, String, Option<String>)> {
    if let Some(contract) = plan.capability.d1_approved_mln_import.as_ref() {
        let migration_id = plan
            .input
            .pointer("/body/migration_id")
            .or_else(|| {
                plan.targets
                    .pointer("/adapter/approved_mln_import/migration_id")
            })
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CliError::Input("approved MLN import migration id is missing".to_owned())
            })?;
        let target = if plan.capability.id == "d1-import-database" {
            plan.targets
                .pointer("/adapter/approved_mln_import/target")
                .cloned()
                .ok_or_else(|| CliError::Input("reviewed import target is missing".to_owned()))?
        } else {
            json!({"account_id":contract.account_id,"database_id":contract.database_id})
        };
        return Ok((target, migration_id.to_owned(), None));
    }
    let contract = plan
        .capability
        .d1_approved_mln_import_poll_resume
        .as_ref()
        .ok_or_else(|| {
            CliError::Input("approved MLN import poll contract is missing".to_owned())
        })?;
    let migration_id = plan
        .targets
        .pointer("/adapter/approved_mln_import_poll_resume/root_input/body/migration_id")
        .or_else(|| {
            plan.targets
                .pointer("/adapter/approved_mln_import_poll_resume/root_stage/migration_id")
        })
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("poll continuation migration id is missing".to_owned()))?;
    let bookmark = plan
        .targets
        .pointer("/adapter/approved_mln_import_poll_resume/accepted_bookmark")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("poll continuation bookmark is missing".to_owned()))?;
    let target = if plan.capability.id == "d1-resume-database-import-poll" {
        plan.targets
            .pointer("/adapter/approved_mln_import_poll_resume/target")
            .cloned()
            .ok_or_else(|| CliError::Input("poll continuation target is missing".to_owned()))?
    } else {
        json!({"account_id":contract.account_id,"database_id":contract.database_id})
    };
    Ok((target, migration_id.to_owned(), Some(bookmark.to_owned())))
}
