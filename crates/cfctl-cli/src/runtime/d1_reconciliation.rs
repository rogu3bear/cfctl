//! Local, authenticated content reconciliation. Never changes a restore plan.
use super::prelude::{
    CallInput, CatalogSnapshot, CliError, EvidenceClass, ProfilesConfig, Result, ResultEnvelopeV2,
    StateStore, StoredPlanRecord, Utc, Value, VerificationState, json,
};
use cfctl_core::{
    D1FullExportGovernedExecutionBindingV1, OperationalProofOutcomeV1,
    d1_reconciliation::{RECONCILE_ID, ReconcileRequest, ReleaseBinding, STRATEGY},
    hash_value,
};
use cfctl_storage::PrivateDirectory;
use chrono::{DateTime, Duration};
use sha2::{Digest, Sha256};
use std::path::Path;

fn rejected(reason: &str) -> CliError {
    CliError::Input(format!("D1 content reconciliation rejected: {reason}"))
}

fn require(condition: bool, reason: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(rejected(reason))
    }
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| rejected("missing evidence field"))
}

fn timestamp(value: &Value) -> Result<DateTime<Utc>> {
    serde_json::from_value(value.clone()).map_err(Into::into)
}

fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(super) fn validate_window(binding: &ReleaseBinding, now: DateTime<Utc>) -> Result<()> {
    let window = &binding.window;
    require(
        hex(&binding.commit, 40)
            && hex(&binding.tree, 40)
            && hex(&binding.deploy_artifact_digest, 64)
            && hex(&binding.declaration_sha256, 64)
            && uuid::Uuid::parse_str(&window.window_id)
                .is_ok_and(|id| id.to_string() == window.window_id)
            && window.opened_at <= now
            && now < window.expires_at
            && window.expires_at - window.opened_at > Duration::zero()
            && window.expires_at - window.opened_at <= Duration::seconds(900),
        "invalid, expired, future or oversized release window",
    )
}

struct Export {
    binding: D1FullExportGovernedExecutionBindingV1,
    projection: Value,
    bytes: Vec<u8>,
    path: String,
    bookmark: String,
}

fn private_bytes(path: &str, maximum: u64) -> Result<Vec<u8>> {
    let path = Path::new(path);
    require(path.is_absolute(), "export path is not absolute")?;
    let parent = path
        .parent()
        .ok_or_else(|| rejected("export parent missing"))?;
    let directory = PrivateDirectory::open(parent)?;
    let name = path
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or_else(|| rejected("export name missing"))?;
    directory
        .read(name, maximum)?
        .ok_or_else(|| rejected("retained export missing"))
}

fn export(
    store: &StateStore,
    evidence_hash: &str,
    account: &str,
    database: &str,
) -> Result<Export> {
    let matches = store
        .list_operational_proofs()?
        .into_iter()
        .filter(|p| {
            p.evidence.content_hash == evidence_hash
                && p.d1_full_export_governed_execution().is_some()
        })
        .collect::<Vec<_>>();
    require(matches.len() == 1, "export lineage missing or ambiguous")?;
    let proof = &matches[0];
    let binding = proof
        .d1_full_export_governed_execution()
        .ok_or_else(|| rejected("export binding missing"))?
        .clone();
    let target = json!({"account_id":account,"database_id":database});
    let expected_input = CallInput {
        selectors: target.clone(),
        query: json!({}),
        ..CallInput::default()
    };
    require(
        proof.capability_id == "d1-full-export"
            && proof.outcome == OperationalProofOutcomeV1::Succeeded
            && proof.evidence.class == EvidenceClass::LiveRead
            && proof.account_id.as_deref() == Some(account)
            && binding.target_scope_hash == hash_value(&target)?
            && binding.request_hash == hash_value(&serde_json::to_value(expected_input)?)?
            && binding.manifest_evidence_hash == evidence_hash
            && binding.completion_status == "completed",
        "export scope or completion mismatch",
    )?;
    let (descriptor, value) = store.load_evidence_value(evidence_hash)?;
    let manifest = &value["result"];
    let output = &manifest["output_file"];
    let bookmark = text(&manifest["provider"], "at_bookmark")?.to_owned();
    let path = text(output, "path")?.to_owned();
    let byte_count = output["bytes"]
        .as_u64()
        .filter(|n| *n > 0 && *n <= 300_000_000)
        .ok_or_else(|| rejected("export byte bound invalid"))?;
    require(
        descriptor == proof.evidence
            && value["success"] == true
            && value["status"] == 200
            && value["errors"].as_array().is_some_and(Vec::is_empty)
            && manifest["database"] == target
            && output["complete"] == true
            && output["hash_matches"] == true
            && value["result_info"]["verification"]["passed"] == true
            && value["result_info"]["output"]["partial"] == false
            && output["sha256"] == binding.output_file_sha256
            && hash_value(&json!(bookmark))? == binding.at_bookmark_hash
            && timestamp(&manifest["provider"]["exported_at"])? <= binding.completed_at
            && binding.completed_at <= Utc::now(),
        "authenticated export manifest mismatch",
    )?;
    let bytes = private_bytes(&path, byte_count)?;
    require(
        bytes.len() as u64 == byte_count
            && format!("sha256:{}", hex::encode(Sha256::digest(&bytes)))
                == binding.output_file_sha256,
        "retained export bytes drifted",
    )?;
    let projection = json!({"binding":binding,
        "evidence":{"content_hash":descriptor.content_hash,"class":descriptor.class,"generated_at":descriptor.generated_at},
        "account_id":account,"database_id":database,"bookmark":bookmark,
        "output":{"sha256":binding.output_file_sha256,"bytes":byte_count,"complete":true,
            "hash_matches":true,"private_file_custody_verified":true}});
    Ok(Export {
        binding,
        projection,
        bytes,
        path,
        bookmark,
    })
}

#[expect(
    clippy::too_many_lines,
    reason = "all three export identities, chronology and the final mutable-custody recheck form one reconciliation gate"
)]
pub(super) fn reconcile(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    input: &CallInput,
) -> Result<ResultEnvelopeV2> {
    require(
        input.selectors == json!({})
            && input.query == json!({})
            && input.if_match.is_none()
            && input.if_none_match.is_none(),
        "unexpected selection",
    )?;
    let request: ReconcileRequest = serde_json::from_value(
        input
            .body
            .clone()
            .ok_or_else(|| rejected("request missing"))?,
    )?;
    validate_window(&request.release_binding, Utc::now())?;
    let _lock = store.lock_plan(&request.restore_operation_id)?;
    let StoredPlanRecord::Current(plan) =
        store.load_stored_plan_record(&request.restore_operation_id)?
    else {
        return Err(rejected("current original PlanV2 missing"));
    };
    let history = super::d1_restore_proof::failed_reconciliation_history(store, &plan)?;
    let account = &plan.plan.account_id;
    let database = text(&history["binding"], "database_id")?;
    let original_input = &history["binding"]["caller_inputs"];
    let source = export(
        store,
        text(original_input, "source_evidence_hash")?,
        account,
        database,
    )?;
    let historical = export(
        store,
        &request.historical_post_export_evidence_hash,
        account,
        database,
    )?;
    let current = export(
        store,
        &request.current_export_evidence_hash,
        account,
        database,
    )?;
    let window = &request.release_binding.window;
    require(
        source.binding.operation_id == text(original_input, "source_operation_id")?
            && source.bookmark == text(original_input, "target_bookmark")?
            && source.bookmark == text(original_input, "expected_current_bookmark")?
            && source.bookmark == text(&history["bookmarks"], "pre_restore_bookmark")?
            && source.binding.profile_id == plan.plan.profile_id
            && source.binding.credential_generation_id == plan.pins.credential_generation_id
            && source.binding.catalog_hash == plan.pins.catalog_hash,
        "original source export does not bind original same-checkpoint restore",
    )?;
    require(
        source.binding.completed_at <= timestamp(&history["boundary_at"])?
            && timestamp(&history["verification_at"])? < historical.binding.completed_at
            && historical.binding.completed_at < window.opened_at
            && window.opened_at <= current.binding.completed_at
            && current.binding.completed_at < Utc::now(),
        "historical/current chronology mismatch",
    )?;
    require(
        source.bytes == historical.bytes && source.bytes == current.bytes,
        "complete export content mismatch",
    )?;
    let profiles = ProfilesConfig::load(store)?;
    let profile = profiles.selected(Some(&current.binding.profile_id))?;
    require(
        profile.account_id.as_deref() == Some(account)
            && profile.credential_generation_id.as_deref()
                == Some(&current.binding.credential_generation_id)
            && current.binding.catalog_hash == catalog.schema_hash,
        "current export credential or catalog drift",
    )?;
    let result = json!({"schema_version":1,"qualification":"authenticated_same_checkpoint_content_reconciliation",
        "qualified":true,"verification_strategy":STRATEGY,"reconciliation_id":uuid::Uuid::new_v4().to_string(),
        "restore_operation_id":request.restore_operation_id,"historical_restore":history,
        "source_export":source.projection,"historical_post_export":historical.projection,"current_export":current.projection,
        "release_binding":request.release_binding,
        "comparison":{"source_equals_historical_post":true,"source_equals_current":true,
            "sql_sha256":source.binding.output_file_sha256,"bytes":source.bytes.len()},
        "limits":{"provider_requests":0,"original_operation_reclassified":false,"historical_rehearsal":true,
            "current_snapshot_contents_equal":true,"continuous_closure_observed":false,
            "changed_state_rollback_qualified":false,"application_admission_qualified":false,"write_authority_granted":false}});
    // Reacquire mutable local custody before signing the derived observation.
    for observed in [&source, &historical, &current] {
        require(
            private_bytes(&observed.path, observed.bytes.len() as u64)? == observed.bytes,
            "export changed during reconciliation",
        )?;
    }
    require(
        ProfilesConfig::load(store)?.selected(Some(&profile.id))? == profile,
        "profile changed during reconciliation",
    )?;
    require(
        CatalogSnapshot::load(&store.paths().catalog_file())?.schema_hash == catalog.schema_hash,
        "catalog changed during reconciliation",
    )?;
    validate_window(&request.release_binding, Utc::now())?;
    let evidence =
        store.write_observation_evidence(EvidenceClass::PostChangeVerification, &result)?;
    let mut envelope = ResultEnvelopeV2::success("call", result).with_evidence(evidence);
    envelope.capability_id = Some(RECONCILE_ID.into());
    envelope.verification.state = VerificationState::Passed;
    envelope.verification.basis = Some("Authenticated historical same-checkpoint and current complete SQL bytes match; original failure, application admission and write authority remain separate.".into());
    validate_window(&request.release_binding, envelope.generated_at)?;
    Ok(envelope)
}
