use super::api_boundary::ApiBoundaryResponseOutcome;
use super::api_boundary::api_plan_result_envelope;
use super::api_boundary::persist_secret_lifecycle;
use super::api_boundary::post_boundary_failure_envelope;
use super::api_boundary::process_api_boundary_response;
use super::api_boundary::process_api_transport_failure;
use super::api_boundary::verify_api_plan;
use super::import_failures::exact_durable_poll_exhaustion;
use super::import_failures::exact_in_progress_poll_receipt;
use super::import_failures::known_import_action_response_failure_envelope;
use super::import_failures::known_import_init_response_failure_envelope;
use super::import_failures::known_import_provider_failure_envelope;
use super::import_failures::known_import_upload_response_failure_envelope;
use super::import_lineage::DurableProviderCompleteBoundary;
use super::import_lineage::exact_durable_provider_complete_boundary;
use super::import_lineage::validate_trusted_root_import_plan;
use super::import_planning::git_authority_bytes;
use super::import_planning::git_authority_output;
use super::import_planning::normalize_reviewed_git_repository_id;
use super::import_planning::required_body_string;
use super::plan_commands::persist_transaction_stage;
use super::plan_commands::persist_transaction_stage_with_artifact;
use super::prelude::{
    AuthCredential, BTreeSet, CallInput, CapabilityV1, CliError, CloudflareError,
    D1ImportCheckpointV1, DateTime, ErrorV1, EvidenceClass, EvidenceV1, Executor, Md5, OpenOptions,
    Path, PathBuf, PlanStatus, PlanV1, Result, ResultEnvelopeV2, SecretStore, Sha256, StateStore,
    StoredPlanRecord, TransactionStageV1, Utc, Uuid, Value, VerificationState, json,
};
use super::prelude::{Digest, OpenOptionsExt, PermissionsExt, Read, fs};
use cfctl_cloudflare::validate_reviewed_schema_migration_sql;
use cfctl_core::hash_value;

#[derive(Debug, Clone)]
pub(super) struct ResumePollExhaustionAuthority {
    pub(super) exhaustion_evidence: EvidenceV1,
    pub(super) exhaustion_checkpoint: Value,
    pub(super) accepted_ingest_evidence: EvidenceV1,
    pub(super) accepted_bookmark: String,
    pub(super) root_operation_id: String,
    pub(super) root_plan_hash: String,
    pub(super) root_input: Value,
    pub(super) root_stage: Value,
}

pub(super) fn boundary_artifact_hash(plan: &PlanV1, stage: TransactionStageV1) -> Option<&str> {
    plan.transaction_journal
        .iter()
        .find(|checkpoint| checkpoint.stage == stage)
        .and_then(|checkpoint| checkpoint.artifact_hash.as_deref())
}

#[expect(
    clippy::too_many_lines,
    reason = "continuation exhaustion validates every receipt and inherited authority field"
)]
pub(super) fn exact_resume_poll_exhaustion(
    store: &StateStore,
    plan: &PlanV1,
) -> Result<ResumePollExhaustionAuthority> {
    let authority = plan
        .targets
        .pointer("/adapter/approved_mln_import_poll_resume")
        .and_then(Value::as_object)
        .ok_or_else(|| CliError::Input("poll continuation authority is missing".to_owned()))?;
    let root_operation_id = authority
        .get("root_operation_id")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("poll continuation root operation is missing".to_owned()))?;
    let root_plan_hash = authority
        .get("root_plan_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("poll continuation root plan hash is missing".to_owned()))?;
    let root_input = authority
        .get("root_input")
        .cloned()
        .ok_or_else(|| CliError::Input("poll continuation root input is missing".to_owned()))?;
    let root_stage = authority
        .get("root_stage")
        .cloned()
        .ok_or_else(|| CliError::Input("poll continuation root stage is missing".to_owned()))?;
    let accepted_hash = authority
        .get("accepted_ingest_evidence_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input("accepted-ingest evidence identity is missing".to_owned())
        })?;
    let accepted_bookmark = authority
        .get("accepted_bookmark")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CliError::Input("accepted-ingest bookmark is missing".to_owned()))?;
    let contract = plan
        .capability
        .d1_approved_mln_import_poll_resume
        .as_ref()
        .ok_or_else(|| CliError::Input("poll continuation contract is missing".to_owned()))?;
    let target = if plan.capability.id == "d1-resume-database-import-poll" {
        authority
            .get("target")
            .cloned()
            .ok_or_else(|| CliError::Input("poll continuation target is missing".to_owned()))?
    } else {
        json!({"account_id":contract.account_id,"database_id":contract.database_id})
    };
    let input_hash = hash_value(&plan.input)?;
    let migration_id = root_input
        .pointer("/body/migration_id")
        .or_else(|| root_stage.get("migration_id"))
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("root migration identity is missing".to_owned()))?;
    let source_sha256 = root_stage
        .get("sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("root source identity is missing".to_owned()))?;
    let checkpoints = store.read_d1_import_checkpoints(&plan.operation_id)?;
    let attempts = checkpoints
        .iter()
        .enumerate()
        .filter_map(|(index, (hash, checkpoint))| {
            let attempt = checkpoint
                .get("step")
                .and_then(Value::as_str)?
                .strip_prefix("poll_response_")?
                .parse::<u64>()
                .ok()?;
            exact_in_progress_poll_receipt(
                store,
                plan,
                hash,
                checkpoint,
                attempt,
                &target,
                &input_hash,
                migration_id,
                accepted_bookmark,
            )
            .then_some((index, attempt))
        })
        .collect::<Vec<_>>();
    let expected = (1..=contract.max_poll_attempts)
        .enumerate()
        .collect::<Vec<_>>();
    if attempts != expected {
        return Err(CliError::Input(
            "poll continuation exhaustion requires every bounded chronological in-progress receipt"
                .to_owned(),
        ));
    }
    let exhausted = checkpoints
        .iter()
        .enumerate()
        .filter(|(index, (_, checkpoint))| {
            *index == usize::try_from(contract.max_poll_attempts).unwrap_or(usize::MAX)
                && *index + 1 == checkpoints.len()
                && checkpoint.get("step").and_then(Value::as_str)
                    == Some("poll_in_progress_exhausted")
                && checkpoint.get("performed").and_then(Value::as_bool) == Some(true)
                && checkpoint
                    .get("rectification_required")
                    .and_then(Value::as_bool)
                    == Some(true)
                && checkpoint
                    .pointer("/receipt/provider")
                    .and_then(Value::as_str)
                    == Some("cloudflare")
                && checkpoint
                    .pointer("/receipt/effect")
                    .and_then(Value::as_str)
                    == Some("d1_import_poll_in_progress_exhausted")
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
                    == Some(source_sha256)
                && checkpoint
                    .pointer("/receipt/at_bookmark")
                    .and_then(Value::as_str)
                    == Some(accepted_bookmark)
                && checkpoint
                    .pointer("/receipt/attempt_count")
                    .and_then(Value::as_u64)
                    == Some(contract.max_poll_attempts)
                && checkpoint
                    .pointer("/receipt/attempt_bound")
                    .and_then(Value::as_u64)
                    == Some(contract.max_poll_attempts)
                && checkpoint
                    .pointer("/receipt/no_replay")
                    .and_then(Value::as_bool)
                    == Some(true)
                && checkpoint
                    .pointer("/receipt/outcome")
                    .and_then(Value::as_str)
                    == Some("poll_in_progress_exhausted")
                && checkpoint
                    .pointer("/receipt/receipt_available")
                    .and_then(Value::as_bool)
                    == Some(true)
        })
        .collect::<Vec<_>>();
    if exhausted.len() != 1 {
        return Err(CliError::Input(
            "poll continuation requires exactly one terminal exhaustion receipt".to_owned(),
        ));
    }
    let (_, (hash, checkpoint)) = exhausted[0];
    let accepted = store.read_evidence_value(accepted_hash)?;
    let root_input_hash = hash_value(&root_input)?;
    let accepted_exact = accepted.get("schema_version").and_then(Value::as_u64) == Some(1)
        && accepted.get("operation_id").and_then(Value::as_str) == Some(root_operation_id)
        && accepted.get("step").and_then(Value::as_str) == Some("ingest_response")
        && accepted.get("performed").and_then(Value::as_bool) == Some(true)
        && accepted
            .get("rectification_required")
            .and_then(Value::as_bool)
            == Some(false)
        && accepted
            .pointer("/receipt/http_status")
            .and_then(Value::as_u64)
            == Some(200)
        && accepted
            .pointer("/receipt/success")
            .and_then(Value::as_bool)
            == Some(true)
        && accepted
            .pointer("/receipt/response_action")
            .and_then(Value::as_str)
            == Some("ingest")
        && accepted
            .pointer("/receipt/provider")
            .and_then(Value::as_str)
            == Some("cloudflare")
        && accepted.pointer("/receipt/effect").and_then(Value::as_str)
            == Some("d1_import_ingest_accepted")
        && accepted
            .pointer("/receipt/migration_id")
            .and_then(Value::as_str)
            == Some(migration_id)
        && accepted.pointer("/receipt/target") == Some(&target)
        && accepted
            .pointer("/receipt/plan_input_hash")
            .and_then(Value::as_str)
            == Some(root_input_hash.as_str())
        && accepted
            .pointer("/receipt/no_replay")
            .and_then(Value::as_bool)
            == Some(false)
        && accepted
            .pointer("/receipt/result/type")
            .and_then(Value::as_str)
            == Some("import")
        && matches!(
            accepted
                .pointer("/receipt/result/status")
                .and_then(Value::as_str),
            Some("active" | "pending")
        )
        && accepted
            .pointer("/receipt/result/success")
            .and_then(Value::as_bool)
            == Some(true)
        && accepted
            .pointer("/receipt/result/at_bookmark")
            .and_then(Value::as_str)
            == Some(accepted_bookmark)
        && accepted
            .pointer("/receipt/errors")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty);
    if store.read_evidence_value(hash)? != *checkpoint || !accepted_exact {
        return Err(CliError::Input(
            "poll continuation exhaustion or accepted-ingest evidence drifted".to_owned(),
        ));
    }
    Ok(ResumePollExhaustionAuthority {
        exhaustion_evidence: EvidenceV1::new(
            EvidenceClass::Apply,
            hash,
            &store
                .paths()
                .data_dir
                .join("evidence")
                .join(format!("{}.json", hash.trim_start_matches("sha256:")))
                .display()
                .to_string(),
        ),
        exhaustion_checkpoint: checkpoint.clone(),
        accepted_ingest_evidence: EvidenceV1::new(
            EvidenceClass::Apply,
            accepted_hash,
            &store
                .paths()
                .data_dir
                .join("evidence")
                .join(format!(
                    "{}.json",
                    accepted_hash.trim_start_matches("sha256:")
                ))
                .display()
                .to_string(),
        ),
        accepted_bookmark: accepted_bookmark.to_owned(),
        root_operation_id: root_operation_id.to_owned(),
        root_plan_hash: root_plan_hash.to_owned(),
        root_input,
        root_stage,
    })
}

#[expect(
    clippy::too_many_lines,
    reason = "resume completion validates one exact durable checkpoint and every root-to-child lineage field together"
)]
pub(super) fn exact_durable_resume_provider_complete_boundary(
    store: &StateStore,
    plan: &PlanV1,
) -> Result<DurableProviderCompleteBoundary> {
    let authority = plan
        .targets
        .pointer("/adapter/approved_mln_import_poll_resume")
        .ok_or_else(|| CliError::Input("poll continuation authority is missing".to_owned()))?;
    let contract = plan
        .capability
        .d1_approved_mln_import_poll_resume
        .as_ref()
        .ok_or_else(|| CliError::Input("poll continuation contract is missing".to_owned()))?;
    let root_input = authority
        .get("root_input")
        .ok_or_else(|| CliError::Input("root input is missing".to_owned()))?;
    let root_stage = authority
        .get("root_stage")
        .ok_or_else(|| CliError::Input("root stage is missing".to_owned()))?;
    let migration_id = root_input
        .pointer("/body/migration_id")
        .or_else(|| root_stage.get("migration_id"))
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("root migration identity is missing".to_owned()))?;
    let accepted_bookmark = authority
        .get("accepted_bookmark")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("accepted bookmark is missing".to_owned()))?;
    let target = if plan.capability.id == "d1-resume-database-import-poll" {
        authority
            .get("target")
            .cloned()
            .ok_or_else(|| CliError::Input("poll continuation target is missing".to_owned()))?
    } else {
        json!({"account_id":contract.account_id,"database_id":contract.database_id})
    };
    let input_hash = hash_value(&plan.input)?;
    let checkpoints = store.read_d1_import_checkpoints(&plan.operation_id)?;
    let completed = checkpoints
        .iter()
        .filter(|(_, checkpoint)| {
            checkpoint.get("step").and_then(Value::as_str) == Some("provider_complete")
        })
        .collect::<Vec<_>>();
    if completed.len() != 1 {
        return Err(CliError::Input(
            "poll continuation requires exactly one provider completion".to_owned(),
        ));
    }
    let (hash, checkpoint) = completed[0];
    let exact = checkpoint.get("schema_version").and_then(Value::as_u64) == Some(1)
        && checkpoint.get("operation_id").and_then(Value::as_str)
            == Some(plan.operation_id.as_str())
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
            .pointer("/receipt/migration_id")
            .and_then(Value::as_str)
            == Some(migration_id)
        && checkpoint.pointer("/receipt/target") == Some(&target)
        && checkpoint
            .pointer("/receipt/plan_input_hash")
            .and_then(Value::as_str)
            == Some(input_hash.as_str())
        && checkpoint.pointer("/receipt/source_sha256") == root_stage.get("sha256")
        && checkpoint.pointer("/receipt/source_md5") == root_stage.get("md5")
        && checkpoint.pointer("/receipt/source_bytes") == root_stage.get("bytes")
        && checkpoint.pointer("/receipt/source_authority_hash")
            == root_stage.get("source_authority_hash")
        && checkpoint
            .pointer("/receipt/stage_identity_hash")
            .and_then(Value::as_str)
            == hash_value(root_stage).ok().as_deref()
        && checkpoint
            .pointer("/receipt/at_bookmark")
            .and_then(Value::as_str)
            == Some(accepted_bookmark)
        && checkpoint
            .pointer("/receipt/final_bookmark")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty())
        && checkpoint.pointer("/receipt/root_operation_id") == authority.get("root_operation_id")
        && checkpoint.pointer("/receipt/root_plan_hash") == authority.get("root_plan_hash")
        && checkpoint.pointer("/receipt/parent_operation_id")
            == authority.get("parent_operation_id")
        && checkpoint.pointer("/receipt/parent_exhaustion_evidence_hash")
            == authority.get("parent_exhaustion_evidence_hash");
    if !exact || store.read_evidence_value(hash)? != *checkpoint {
        return Err(CliError::Input(
            "poll continuation provider completion is not exact and durable".to_owned(),
        ));
    }
    Ok(DurableProviderCompleteBoundary {
        evidence_hash: hash.clone(),
        checkpoint: checkpoint.clone(),
    })
}

#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the child-plan admission joins immutable parent, root, evidence, and sibling authority"
)]
pub(super) fn validate_and_derive_resume_poll_authority(
    store: &StateStore,
    capability: &CapabilityV1,
    input: &CallInput,
    profile_id: &str,
    credential_generation_id: Option<&str>,
    catalog_hash: &str,
    before: DateTime<Utc>,
    child_operation_id: Option<&str>,
) -> Result<Value> {
    let contract = capability
        .d1_approved_mln_import_poll_resume
        .as_ref()
        .ok_or_else(|| CliError::Input("poll continuation contract is missing".to_owned()))?;
    let body = input
        .body
        .as_ref()
        .and_then(Value::as_object)
        .ok_or_else(|| CliError::Input("poll continuation body is missing".to_owned()))?;
    let expected = [
        "parent_operation_id",
        "parent_plan_hash",
        "exhaustion_evidence_hash",
        "accepted_ingest_evidence_hash",
        "accepted_bookmark_hash",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if body.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected {
        return Err(CliError::Input(
            "poll continuation accepts only the five immutable parent receipt identities"
                .to_owned(),
        ));
    }
    let field = |name| required_body_string(body, name);
    let parent_operation_id = field("parent_operation_id")?;
    Uuid::parse_str(parent_operation_id).map_err(|_| {
        CliError::Input("parent_operation_id must be one canonical UUID".to_owned())
    })?;
    let StoredPlanRecord::Current(parent_v2) =
        store.load_stored_plan_record(parent_operation_id)?
    else {
        return Err(CliError::Input(
            "poll continuation parent must be an immutable PlanV2".to_owned(),
        ));
    };
    let parent = &parent_v2.plan;
    let parent_target = if contract.root_capability_id == "d1-import-database" {
        if parent.capability.id == contract.root_capability_id {
            parent
                .targets
                .pointer("/adapter/approved_mln_import/target")
        } else {
            parent
                .targets
                .pointer("/adapter/approved_mln_import_poll_resume/target")
        }
        .cloned()
        .ok_or_else(|| CliError::Input("poll parent target is missing".to_owned()))?
    } else {
        json!({
            "account_id":contract.account_id,
            "database_id":contract.database_id,
        })
    };
    let parent_account_id = parent_target
        .get("account_id")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("poll parent account target is missing".to_owned()))?;
    if parent.content_hash != field("parent_plan_hash")?
        || parent_v2.pins.catalog_hash != parent.catalog_hash
        || parent_v2.pins.credential_generation_id.is_empty()
        || parent.created_at >= before
        || parent.profile_id != profile_id
        || parent.catalog_hash != catalog_hash
        || parent_v2.pins.credential_generation_id != credential_generation_id.unwrap_or_default()
        || parent.account_id != parent_account_id
        || input.selectors != parent_target
    {
        return Err(CliError::Input(
            "poll continuation parent PlanV2, chronology, profile, credential, account, or catalog drifted"
                .to_owned(),
        ));
    }
    let exhaustion = if parent.capability.id == contract.root_capability_id {
        validate_trusted_root_import_plan(store, &parent_v2)?;
        let (exhaustion_evidence, exhaustion_checkpoint, accepted_ingest_evidence) =
            exact_durable_poll_exhaustion(store, parent)?;
        let accepted_bookmark = exhaustion_checkpoint
            .pointer("/receipt/at_bookmark")
            .and_then(Value::as_str)
            .ok_or_else(|| CliError::Input("root exhaustion bookmark is missing".to_owned()))?
            .to_owned();
        ResumePollExhaustionAuthority {
            exhaustion_evidence,
            exhaustion_checkpoint,
            accepted_ingest_evidence,
            accepted_bookmark,
            root_operation_id: parent.operation_id.clone(),
            root_plan_hash: parent.content_hash.clone(),
            root_input: parent.input.clone(),
            root_stage: parent
                .targets
                .pointer("/adapter/approved_mln_import")
                .cloned()
                .ok_or_else(|| CliError::Input("root managed stage is missing".to_owned()))?,
        }
    } else if parent.capability.id == capability.id {
        exact_resume_poll_exhaustion(store, parent)?
    } else {
        return Err(CliError::Input(
            "poll continuation parent is neither the root import nor a poll child".to_owned(),
        ));
    };
    let accepted_bookmark_hash = hash_value(&Value::String(exhaustion.accepted_bookmark.clone()))?;
    if exhaustion.exhaustion_evidence.content_hash != field("exhaustion_evidence_hash")?
        || exhaustion.accepted_ingest_evidence.content_hash
            != field("accepted_ingest_evidence_hash")?
        || accepted_bookmark_hash != field("accepted_bookmark_hash")?
    {
        return Err(CliError::Input(
            "poll continuation caller receipt identities do not match canonical parent authority"
                .to_owned(),
        ));
    }
    let boundary = parent
        .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
        .ok_or_else(|| {
            CliError::Input("parent exhaustion boundary artifact is missing".to_owned())
        })?;
    if boundary.get("outcome").and_then(Value::as_str) != Some("poll_in_progress_exhausted")
        || boundary
            .get("poll_exhaustion_evidence_hash")
            .and_then(Value::as_str)
            != Some(exhaustion.exhaustion_evidence.content_hash.as_str())
        || boundary
            .get("accepted_ingest_evidence_hash")
            .and_then(Value::as_str)
            != Some(exhaustion.accepted_ingest_evidence.content_hash.as_str())
        || boundary_artifact_hash(parent, TransactionStageV1::BoundaryResponsePersisted)
            != hash_value(boundary).ok().as_deref()
    {
        return Err(CliError::Input(
            "parent BoundaryResponse artifact does not authenticate its exhaustion".to_owned(),
        ));
    }
    for sibling in store.list_plans()? {
        if child_operation_id == Some(sibling.operation_id.as_str()) {
            continue;
        }
        let sibling_authority = sibling
            .targets
            .pointer("/adapter/approved_mln_import_poll_resume");
        let same_exhaustion = sibling_authority
            .and_then(|value| value.get("parent_operation_id"))
            .and_then(Value::as_str)
            == Some(parent_operation_id)
            && sibling_authority
                .and_then(|value| value.get("parent_exhaustion_evidence_hash"))
                .and_then(Value::as_str)
                == Some(exhaustion.exhaustion_evidence.content_hash.as_str());
        if same_exhaustion {
            let crossed_consumption = sibling.transaction_journal.iter().any(|checkpoint| {
                matches!(
                    checkpoint.stage,
                    TransactionStageV1::ConsumptionPersisted
                        | TransactionStageV1::BoundaryAttemptPersisted
                        | TransactionStageV1::BoundaryResponsePersisted
                        | TransactionStageV1::VerificationAttemptPersisted
                        | TransactionStageV1::VerificationResponsePersisted
                        | TransactionStageV1::CompensationAttemptPersisted
                        | TransactionStageV1::CompensationResponsePersisted
                        | TransactionStageV1::Closed
                )
            });
            let provider_checkpoint_exists = !store
                .read_d1_import_checkpoints(&sibling.operation_id)?
                .is_empty();
            let replaceable = sibling.status == PlanStatus::Cancelled
                && !crossed_consumption
                && !provider_checkpoint_exists;
            if !replaceable {
                return Err(CliError::Input(
                    "this exact exhaustion already has a poll child or crossed child boundary"
                        .to_owned(),
                ));
            }
        }
    }
    let capability_contract_hash = hash_value(&serde_json::to_value(capability)?)?;
    Ok(json!({
        "schema_version":1,
        "parent_operation_id":parent.operation_id,
        "parent_plan_hash":parent.content_hash,
        "parent_boundary_artifact_hash":boundary_artifact_hash(parent,TransactionStageV1::BoundaryResponsePersisted),
        "parent_exhaustion_evidence_hash":exhaustion.exhaustion_evidence.content_hash,
        "accepted_ingest_evidence_hash":exhaustion.accepted_ingest_evidence.content_hash,
        "accepted_bookmark":exhaustion.accepted_bookmark,
        "accepted_bookmark_hash":accepted_bookmark_hash,
        "root_operation_id":exhaustion.root_operation_id,
        "root_plan_hash":exhaustion.root_plan_hash,
        "root_input":exhaustion.root_input,
        "root_stage":exhaustion.root_stage,
        "target":parent_target,
        "profile_id":profile_id,
        "credential_generation_id":credential_generation_id,
        "catalog_hash":catalog_hash,
        "capability_contract_hash":capability_contract_hash,
    }))
}

pub(super) fn known_import_poll_exhausted_envelope(
    store: &StateStore,
    plan: &mut PlanV1,
    secrets: &dyn SecretStore,
) -> ResultEnvelopeV2 {
    plan.status = PlanStatus::RectificationRequired;
    let authority = if plan.capability.d1_approved_mln_import.is_some() {
        exact_durable_poll_exhaustion(store, plan)
    } else {
        exact_resume_poll_exhaustion(store, plan).map(|authority| {
            (
                authority.exhaustion_evidence,
                authority.exhaustion_checkpoint,
                authority.accepted_ingest_evidence,
            )
        })
    };
    match authority {
        Ok((evidence, checkpoint, accepted_ingest_evidence)) => {
            let artifact = json!({
                "adapter":"dynamic_api",
                "performed":true,
                "success":false,
                "outcome":"poll_in_progress_exhausted",
                "receipt_available":true,
                "poll_exhaustion_evidence_hash":evidence.content_hash,
                "accepted_ingest_evidence_hash":accepted_ingest_evidence.content_hash,
            });
            let mut local_failures = Vec::new();
            if let Err(error) = persist_transaction_stage_with_artifact(
                store,
                plan,
                TransactionStageV1::BoundaryResponsePersisted,
                artifact,
            ) {
                local_failures.push(format!("poll-exhaustion receipt binding failed: {error}"));
            }
            if let Err(error) = persist_secret_lifecycle(store, plan, false, None, secrets) {
                local_failures.push(format!(
                    "poll-exhaustion secret lifecycle persistence failed: {error}"
                ));
            }
            let detail = if local_failures.is_empty() {
                "Cloudflare D1 import remains in progress after the approved poll bound".to_owned()
            } else {
                format!(
                    "Cloudflare D1 import remains in progress after the approved poll bound; {}",
                    local_failures.join("; ")
                )
            };
            post_boundary_failure_envelope(
                plan,
                json!({
                    "success":false,
                    "outcome":"poll_in_progress_exhausted",
                    "receipt_available":true,
                    "at_bookmark_hash":checkpoint.pointer("/receipt/at_bookmark").and_then(Value::as_str).and_then(|value| hash_value(&Value::String(value.to_owned())).ok()),
                    "attempt_count":checkpoint.pointer("/receipt/attempt_count"),
                    "attempt_bound":checkpoint.pointer("/receipt/attempt_bound"),
                    "accepted_ingest_evidence_hash":accepted_ingest_evidence.content_hash,
                }),
                Some(evidence),
                None,
                &CliError::Input(detail),
                true,
                "the exact accepted-ingest bookmark and every bounded in-progress poll receipt are durable; do not replay init/upload/ingest",
            )
        }
        Err(error) => post_boundary_failure_envelope(
            plan,
            json!({
                "success":false,
                "outcome":"poll_exhaustion_receipt_invalid",
                "receipt_available":false,
            }),
            None,
            None,
            &error,
            true,
            "poll exhaustion lineage could not be resolved exactly; do not replay any import stage",
        ),
    }
}

pub(super) fn approved_mln_import_execution_error_envelope(
    store: &StateStore,
    plan: &mut PlanV1,
    error: CloudflareError,
    secrets: &dyn SecretStore,
) -> ResultEnvelopeV2 {
    if matches!(error, CloudflareError::D1ImportProviderFailure) {
        return known_import_provider_failure_envelope(store, plan, secrets);
    }
    if matches!(
        error,
        CloudflareError::D1ImportUploadResponseIntegrityFailure
    ) {
        return known_import_upload_response_failure_envelope(store, plan, secrets);
    }
    if matches!(error, CloudflareError::D1ImportInitResponseFailure) {
        return known_import_init_response_failure_envelope(store, plan, secrets);
    }
    if matches!(
        error,
        CloudflareError::D1ImportIngestResponseFailure
            | CloudflareError::D1ImportPollResponseFailure
    ) {
        return known_import_action_response_failure_envelope(store, plan, error, secrets);
    }
    if matches!(error, CloudflareError::D1ImportPollInProgressExhausted) {
        return known_import_poll_exhausted_envelope(store, plan, secrets);
    }
    if !matches!(
        plan.status,
        PlanStatus::RectificationRequired | PlanStatus::Failed
    ) {
        plan.status = PlanStatus::RectificationRequired;
    }
    let _ = store.save_plan(plan);
    let mut envelope = process_api_transport_failure(store, plan, &CliError::from(error), secrets);
    envelope.performed = true;
    envelope
}

pub(super) fn persist_d1_import_checkpoint(
    store: &StateStore,
    operation_id: &str,
    checkpoint: &D1ImportCheckpointV1,
) -> std::result::Result<(), String> {
    let value = serde_json::to_value(checkpoint).map_err(|error| error.to_string())?;
    let checkpoint_hash = store
        .record_d1_import_checkpoint(operation_id, &value)
        .map_err(|error| error.to_string())?;
    let terminal_provider_failure = (checkpoint.step == "init_response"
        || checkpoint.step == "ingest_response"
        || checkpoint.step.starts_with("poll_response_"))
        && checkpoint
            .receipt
            .pointer("/result/status")
            .and_then(Value::as_str)
            == Some("error")
        && checkpoint
            .receipt
            .pointer("/result/success")
            .and_then(Value::as_bool)
            == Some(false);
    let durable_apply = checkpoint.step == "provider_complete"
        || checkpoint.step.starts_with("poll_response_")
        || terminal_provider_failure
        || (checkpoint.receipt.get("effect").and_then(Value::as_str) == Some("d1_import_response")
            && checkpoint.rectification_required)
        || checkpoint.receipt.get("effect").and_then(Value::as_str)
            == Some("d1_import_ingest_accepted")
        || checkpoint.receipt.get("effect").and_then(Value::as_str)
            == Some("d1_import_transport_uncertain")
        || checkpoint.receipt.get("effect").and_then(Value::as_str)
            == Some("d1_import_upload_response")
        || checkpoint.receipt.get("effect").and_then(Value::as_str)
            == Some("d1_import_poll_in_progress_exhausted");
    if durable_apply {
        let evidence = store
            .write_evidence(EvidenceClass::Apply, &value)
            .map_err(|error| error.to_string())?;
        if evidence.content_hash != checkpoint_hash {
            return Err(
                "D1 import checkpoint and immutable apply evidence hashes diverged".to_owned(),
            );
        }
    }
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "special import execution durably binds checkpoints evidence and pending verification"
)]
pub(super) async fn execute_approved_mln_import_plan(
    store: &StateStore,
    executor: &Executor,
    plan: &mut PlanV1,
    execution_input: &CallInput,
    credential: &AuthCredential,
    secrets: &dyn SecretStore,
) -> Result<ResultEnvelopeV2> {
    let stage_path = plan
        .targets
        .pointer("/adapter/approved_mln_import/stage_path")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| {
            CliError::Input(
                "approved MLN import plan omitted its managed stage identity; do not run"
                    .to_owned(),
            )
        })?;
    validate_managed_mln_stage_authority(plan)?;
    let checkpoint_operation_id = plan.operation_id.clone();
    let response = match Box::pin(executor.execute_d1_approved_mln_import(
        plan,
        execution_input,
        credential,
        &stage_path,
        |checkpoint: &D1ImportCheckpointV1| {
            persist_d1_import_checkpoint(store, &checkpoint_operation_id, checkpoint)
        },
    ))
    .await
    {
        Ok(response) => response,
        Err(error) => {
            return Ok(approved_mln_import_execution_error_envelope(
                store, plan, error, secrets,
            ));
        }
    };
    let (response_value, apply_evidence, lineage_evidence) =
        match process_api_boundary_response(store, plan, &response, secrets)? {
            ApiBoundaryResponseOutcome::Ready {
                response_value,
                apply_evidence,
                lineage_evidence,
            } => (response_value, apply_evidence, lineage_evidence),
            ApiBoundaryResponseOutcome::Recovery(envelope) => return Ok(envelope),
        };
    if !response.success {
        if !matches!(
            plan.status,
            PlanStatus::RectificationRequired | PlanStatus::Failed
        ) {
            plan.status = PlanStatus::RectificationRequired;
        }
        store.save_plan(plan)?;
        return Ok(post_boundary_failure_envelope(
            plan,
            response_value,
            Some(apply_evidence),
            lineage_evidence,
            &CliError::Input(
                "Cloudflare did not complete the approved import; preserve all checkpoints and do not replay"
                    .to_owned(),
            ),
            true,
            "the import boundary was crossed but provider completion was not proven",
        ));
    }
    if let Err(error) = exact_durable_provider_complete_boundary(store, plan.operation_id.as_str())
    {
        plan.status = PlanStatus::RectificationRequired;
        store.save_plan(plan)?;
        return Ok(post_boundary_failure_envelope(
            plan,
            response_value,
            Some(apply_evidence),
            lineage_evidence,
            &error,
            true,
            "the import boundary was crossed but exact durable provider completion was not proven",
        ));
    }
    if matches!(
        plan.capability.id.as_str(),
        "d1-import-approved-osint-research-migration" | "d1-import-database"
    ) {
        let subject = if plan.capability.id == "d1-import-database" {
            "reviewed-Git D1"
        } else {
            "OSINT Research"
        };
        let verification = match verify_api_plan(
            store,
            executor,
            plan,
            &response,
            execution_input,
            credential,
        )
        .await
        {
            Ok(verification) => verification,
            Err(error) => {
                return Ok(post_boundary_failure_envelope(
                    plan,
                    response_value,
                    Some(apply_evidence),
                    lineage_evidence,
                    &error,
                    true,
                    &format!(
                        "the {subject} import completed, but its schema-marker verification could not be persisted"
                    ),
                ));
            }
        };
        let finalization: Result<()> =
            if matches!(plan.status, PlanStatus::Verified | PlanStatus::Failed) {
                persist_transaction_stage(store, plan, TransactionStageV1::Closed)
            } else {
                store.save_plan(plan).map_err(CliError::from)
            };
        let finalization_error = finalization.err();
        return Ok(api_plan_result_envelope(
            plan,
            response_value,
            apply_evidence,
            lineage_evidence,
            verification,
            true,
            finalization_error.as_ref(),
        ));
    }
    if matches!(
        plan.status,
        PlanStatus::RectificationRequired | PlanStatus::Failed
    ) {
        store.save_plan(plan)?;
        return Ok(post_boundary_failure_envelope(
            plan,
            response_value,
            Some(apply_evidence),
            lineage_evidence,
            &CliError::Input(
                "approved MLN import ended in a terminal failure state; do not replay".to_owned(),
            ),
            true,
            "terminal import evidence cannot be overwritten by a pending-proof state",
        ));
    }
    plan.status = PlanStatus::Running;
    store.save_plan(plan)?;
    let mut envelope =
        ResultEnvelopeV2::success("plans run", response_value).with_evidence(apply_evidence);
    envelope.ok = false;
    envelope.performed = true;
    envelope.operation_id = Some(plan.operation_id.clone());
    envelope.capability_id = Some(plan.capability.id.clone());
    envelope.profile_id = Some(plan.profile_id.clone());
    envelope.account_id = Some(plan.account_id.clone());
    envelope.policy_decision = Some(plan.policy.clone());
    envelope.verification.state = VerificationState::Pending;
    envelope.verification.basis = Some(
        "provider_complete is durable; the operation remains unverified until the exact governed post_import MLN invariant proof is attached"
            .to_owned(),
    );
    envelope.error = Some(ErrorV1 {
        code: "CFCTL_D1_IMPORT_POST_IMPORT_PROOF_REQUIRED".to_owned(),
        message: "D1 import crossed the provider boundary but is not publication proof".to_owned(),
        next_step: Some(format!(
            "Run the exact mln-0143-data-invariants post_import read bound to operation {}, then run `cfctl plans rectify {}`.",
            plan.operation_id, plan.operation_id
        )),
    });
    if let Some(evidence) = lineage_evidence {
        envelope.evidence.push(evidence);
    }
    Ok(envelope)
}

pub(super) fn validate_managed_mln_stage_authority(plan: &PlanV1) -> Result<()> {
    if matches!(
        plan.capability.id.as_str(),
        "d1-import-database" | "d1-apply-reviewed-schema-migration"
    ) {
        return validate_managed_reviewed_git_stage_authority(plan);
    }
    let contract = plan
        .capability
        .d1_approved_mln_import
        .as_ref()
        .ok_or_else(|| CliError::Input("approved MLN import contract is missing".to_owned()))?;
    let migration_id = plan
        .input
        .get("body")
        .and_then(|body| body.get("migration_id"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input("managed import migration identity is missing".to_owned())
        })?;
    let migration = contract
        .migrations
        .iter()
        .find(|migration| migration.migration_id == migration_id)
        .ok_or_else(|| CliError::Input("managed import migration is not catalogued".to_owned()))?;
    let staged = plan
        .targets
        .pointer("/adapter/approved_mln_import")
        .ok_or_else(|| CliError::Input("managed import stage binding is missing".to_owned()))?;
    let authority = staged
        .get("source_authority")
        .ok_or_else(|| CliError::Input("managed source authority is missing".to_owned()))?;
    let authority_hash = hash_value(authority)?;
    let expected_sha256 = format!("sha256:{}", migration.sha256);
    if authority.get("schema_version").and_then(Value::as_u64) != Some(1)
        || authority.get("repository_id").and_then(Value::as_str)
            != Some(contract.repository_id.as_str())
        || authority.get("head").and_then(Value::as_str) != Some(contract.repository_head.as_str())
        || authority
            .get("repository_relative_path")
            .and_then(Value::as_str)
            != Some(migration.repository_relative_path.as_str())
        || authority.get("git_blob_oid").and_then(Value::as_str)
            != Some(migration.git_blob_oid.as_str())
        || authority
            .get("observed_worktree_root")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || authority
            .get("observed_git_common_dir")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || staged.get("source_authority_hash").and_then(Value::as_str)
            != Some(authority_hash.as_str())
        || staged.get("sha256").and_then(Value::as_str) != Some(expected_sha256.as_str())
        || staged.get("md5").and_then(Value::as_str) != Some(migration.md5.as_str())
        || staged.get("bytes").and_then(Value::as_u64) != Some(migration.bytes)
    {
        return Err(CliError::Input(
            "managed import stage lost its exact source-authority or byte identity".to_owned(),
        ));
    }
    let stage_path = staged
        .get("stage_path")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| CliError::Input("managed import stage path is missing".to_owned()))?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let mut file = options.open(&stage_path).map_err(|source| CliError::Io {
        path: stage_path.display().to_string(),
        source,
    })?;
    let metadata = file.metadata().map_err(|source| CliError::Io {
        path: stage_path.display().to_string(),
        source,
    })?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|source| CliError::Io {
            path: stage_path.display().to_string(),
            source,
        })?;
    if !metadata.is_file()
        || metadata.len() != migration.bytes
        || bytes.len() as u64 != migration.bytes
        || hex::encode(Sha256::digest(&bytes)) != migration.sha256
        || hex::encode(Md5::digest(&bytes)) != migration.md5
    {
        return Err(CliError::Input(
            "managed import stage no longer matches the consumed reviewed source".to_owned(),
        ));
    }
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "execution-time authority revalidates Git, target, content, and private-stage identities as one fail-closed boundary"
)]
pub(super) fn validate_managed_reviewed_git_stage_authority(plan: &PlanV1) -> Result<()> {
    let contract = plan
        .capability
        .d1_approved_mln_import
        .as_ref()
        .filter(|contract| contract.repository_id.is_empty() && contract.migrations.is_empty())
        .ok_or_else(|| {
            CliError::Input("provider-generic reviewed-Git import contract is missing".to_owned())
        })?;
    let staged = plan
        .targets
        .pointer("/adapter/approved_mln_import")
        .ok_or_else(|| CliError::Input("managed import stage binding is missing".to_owned()))?;
    let authority = staged
        .get("source_authority")
        .ok_or_else(|| CliError::Input("managed source authority is missing".to_owned()))?;
    let authority_hash = hash_value(authority)?;
    let root = authority
        .get("observed_worktree_root")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| CliError::Input("managed source worktree root is missing".to_owned()))?;
    let common = authority
        .get("observed_git_common_dir")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| {
            CliError::Input("managed source Git common directory is missing".to_owned())
        })?;
    let repository_id = authority
        .get("repository_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input("managed source repository identity is missing".to_owned())
        })?;
    let head = authority
        .get("head")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("managed source HEAD is missing".to_owned()))?;
    let relative = authority
        .get("repository_relative_path")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("managed source relative path is missing".to_owned()))?;
    let blob = authority
        .get("git_blob_oid")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("managed source Git blob is missing".to_owned()))?;
    let canonical_root = fs::canonicalize(&root).map_err(|source| CliError::Io {
        path: root.display().to_string(),
        source,
    })?;
    let canonical_common = fs::canonicalize(&common).map_err(|source| CliError::Io {
        path: common.display().to_string(),
        source,
    })?;
    let remote = git_authority_output(&canonical_root, &["remote", "get-url", "origin"])?;
    let blob_spec = format!("{head}:{relative}");
    let observed_blob = git_authority_output(&canonical_root, &["rev-parse", &blob_spec])?;
    let status = git_authority_output(
        &canonical_root,
        &["status", "--porcelain=v1", "--untracked-files=all"],
    )?;
    let observed_common =
        git_authority_output(&canonical_root, &["rev-parse", "--git-common-dir"])?;
    let observed_common = if Path::new(&observed_common).is_absolute() {
        PathBuf::from(observed_common)
    } else {
        canonical_root.join(observed_common)
    };
    let source_path = canonical_root.join(relative);
    let source_bytes = git_authority_bytes(&canonical_root, &["cat-file", "blob", blob])?;
    let worktree_bytes = fs::read(&source_path).map_err(|source| CliError::Io {
        path: source_path.display().to_string(),
        source,
    })?;
    if canonical_root != root
        || fs::canonicalize(observed_common).ok().as_ref() != Some(&canonical_common)
        || normalize_reviewed_git_repository_id(&remote)?.as_str() != repository_id
        || git_authority_output(&canonical_root, &["rev-parse", "HEAD"])? != head
        || observed_blob != blob
        || !status.is_empty()
        || source_bytes != worktree_bytes
    {
        return Err(CliError::Input(
            "reviewed Git source authority changed after planning; do not execute the import"
                .to_owned(),
        ));
    }
    let bytes = staged
        .get("bytes")
        .and_then(Value::as_u64)
        .filter(|bytes| *bytes > 0 && *bytes <= contract.max_source_bytes)
        .ok_or_else(|| CliError::Input("managed source size is outside its bound".to_owned()))?;
    let sha256 = staged
        .get("sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("managed source SHA-256 is missing".to_owned()))?;
    let md5 = staged
        .get("md5")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("managed source MD5 is missing".to_owned()))?;
    let target = json!({
        "account_id":plan.input.pointer("/selectors/account_id"),
        "database_id":plan.input.pointer("/selectors/database_id"),
    });
    if authority.get("schema_version").and_then(Value::as_u64) != Some(1)
        || staged.get("source_authority_hash").and_then(Value::as_str)
            != Some(authority_hash.as_str())
        || staged.get("migration_id").and_then(Value::as_str) != Some(authority_hash.as_str())
        || staged.get("target") != Some(&target)
        || source_bytes.len() as u64 != bytes
        || format!("sha256:{}", hex::encode(Sha256::digest(&source_bytes))) != sha256
        || hex::encode(Md5::digest(&source_bytes)) != md5
    {
        return Err(CliError::Input(
            "managed import stage lost its exact source, target, or byte identity".to_owned(),
        ));
    }
    let stage_path = staged
        .get("stage_path")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| CliError::Input("managed import stage path is missing".to_owned()))?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let mut file = options.open(&stage_path).map_err(|source| CliError::Io {
        path: stage_path.display().to_string(),
        source,
    })?;
    let metadata = file.metadata().map_err(|source| CliError::Io {
        path: stage_path.display().to_string(),
        source,
    })?;
    let mut staged_bytes = Vec::new();
    file.read_to_end(&mut staged_bytes)
        .map_err(|source| CliError::Io {
            path: stage_path.display().to_string(),
            source,
        })?;
    #[cfg(unix)]
    let private_mode = metadata.permissions().mode() & 0o777 == 0o600;
    #[cfg(not(unix))]
    let private_mode = true;
    if !metadata.is_file()
        || !private_mode
        || metadata.len() != bytes
        || staged_bytes != source_bytes
    {
        return Err(CliError::Input(
            "private managed import stage no longer matches the reviewed source".to_owned(),
        ));
    }
    if plan.capability.id == "d1-apply-reviewed-schema-migration" {
        let sql = std::str::from_utf8(&staged_bytes).map_err(|_| {
            CliError::Input("reviewed D1 schema migration must remain UTF-8".to_owned())
        })?;
        let statement_count = validate_reviewed_schema_migration_sql(sql)?;
        if staged.get("statement_count").and_then(Value::as_u64) != Some(statement_count) {
            return Err(CliError::Input(
                "reviewed D1 schema migration statement count drifted after planning".to_owned(),
            ));
        }
    }
    Ok(())
}
