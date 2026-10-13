//! Native consumed-plan execution. Source compilation and live admission remain distinct.
use std::{
    cell::{Cell, RefCell},
    time::{Duration, Instant},
};

use cfctl_auth::AuthCredential;
use cfctl_cloudflare::{
    Executor,
    d1_transition::{Failure, import::ValidatedImport},
};
use cfctl_core::{
    ErrorV1, PlanV1, PlanV2, ResultEnvelopeV2, VerificationState,
    workspace_d1::transition::{
        application::TARGET_KIND,
        execution::{Checkpoint, Stage},
        proofs::{EXECUTION_KIND, ExecutionRecord, Identity, RuntimeBindingV4},
    },
};
use cfctl_storage::PrivateDirectory;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{
    CallInput, EvidenceClass, PlanStatus, Result, Scope, StateStore,
    WorkspaceD1MigrationContractV1, hash_value, invalid, v4,
};
use crate::runtime::{
    plan_commands::persist_transaction_stage_with_artifact,
    prelude::{ProfilesConfig, TransactionStageV1},
    read_execution::credential_generation_for_read,
    support::{http_client, load_workspace_capability},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Target {
    schema_version: u8,
    kind: String,
    identity: Identity,
    binding: RuntimeBindingV4,
    profile_id: String,
    credential_generation_id: String,
    catalog_hash: String,
    build_identity_hash: String,
}

impl Target {
    pub(super) fn new(
        contract: &WorkspaceD1MigrationContractV1,
        binding: &RuntimeBindingV4,
        scope: &Scope<'_>,
    ) -> Result<Self> {
        Ok(Self {
            schema_version: 1,
            kind: TARGET_KIND.into(),
            identity: Identity::from_contract(contract)?,
            binding: binding.clone(),
            profile_id: scope.profile.into(),
            credential_generation_id: scope.generation.into(),
            catalog_hash: scope.catalog.into(),
            build_identity_hash: scope.build.into(),
        })
    }

    fn checkpoint(&self, plan: &PlanV2) -> Result<Checkpoint> {
        let assurance = plan
            .plan
            .capability
            .workspace_d1_migration
            .as_ref()
            .and_then(|c| c.transition.as_ref())
            .and_then(|c| c.declaration.assurance.as_ref())
            .ok_or_else(|| invalid("native assurance missing"))?;
        let checkpoint = Checkpoint {
            schema_version: 1,
            operation_id: plan.plan.operation_id.clone(),
            identity: self.identity.clone(),
            plan_hash: plan.plan.content_hash.clone(),
            qualification_evidence_hash: self.binding.qualification_evidence_hash.clone(),
            assurance_sha256: hash_value(&serde_json::to_value(assurance)?)?,
            baseline_evidence_hash: self.binding.observed_baseline.evidence_hash.clone(),
            predecessor_evidence_hash: self
                .binding
                .completed
                .last()
                .map_or(&self.binding.observed_baseline.evidence_hash, |c| {
                    &c.preservation.evidence_hash
                })
                .clone(),
            stage: Stage::Prepared,
            previous_checkpoint_sha256: None,
            provider_receipt_sha256: None,
            bookmark_sha256: None,
        };
        checkpoint.validate().map_err(invalid)?;
        Ok(checkpoint)
    }
}

pub(in crate::runtime) fn validate_bound_plan(store: &StateStore, plan: &PlanV1) -> Result<()> {
    let contract = plan
        .capability
        .workspace_d1_migration
        .as_ref()
        .ok_or_else(|| invalid("native plan contract missing"))?;
    let current = load_workspace_capability(store, &plan.capability.id)?
        .ok_or_else(|| invalid("native source owner is no longer registered"))?;
    if current != plan.capability {
        return Err(invalid(
            "native capability or source changed after planning",
        ));
    }
    let profile_config = ProfilesConfig::load(store)?;
    let profile = profile_config.selected(Some(&plan.profile_id))?;
    let generation = credential_generation_for_read(profile)?;
    if profile.emergency_only
        || profile.kind != cfctl_auth::ProfileKind::ApiToken
        || profile.account_id.as_deref() != Some(plan.account_id.as_str())
    {
        return Err(invalid(
            "native transition requires its exact account-bound API-token profile",
        ));
    }
    let build = hash_value(&serde_json::to_value(
        crate::build_identity::current_build_info(),
    )?)?;
    let scope = Scope {
        account: &plan.account_id,
        profile: &plan.profile_id,
        generation: &generation,
        catalog: &plan.catalog_hash,
        build: &build,
    };
    let input: CallInput = serde_json::from_value(plan.input.clone())?;
    let target = super::prepare(
        store,
        contract,
        &input,
        scope.account,
        scope.profile,
        scope.generation,
        scope.catalog,
    )?
    .ok_or_else(|| invalid("native target missing"))?;
    if plan.targets.pointer("/adapter/workspace_d1_migration") != Some(&target) {
        return Err(invalid(
            "native exact runtime target changed after planning",
        ));
    }
    Ok(())
}

fn consumed(store: &StateStore, plan: &PlanV1) -> Result<(PlanV2, Target)> {
    validate_bound_plan(store, plan)?;
    let v2 = store.load_plan_v2(&plan.operation_id)?;
    v2.validate()?;
    let target: Target = serde_json::from_value(
        plan.targets
            .pointer("/adapter/workspace_d1_migration")
            .cloned()
            .ok_or_else(|| invalid("native target not pinned"))?,
    )?;
    if &v2.plan != plan
        || plan.status != PlanStatus::Running
        || plan.transaction_stage != TransactionStageV1::BoundaryAttemptPersisted
        || plan
            .approval
            .as_ref()
            .map(|a| a.approved_content_hash.as_str())
            != Some(plan.content_hash.as_str())
        || target.schema_version != 1
        || target.kind != TARGET_KIND
        || target.catalog_hash != v2.pins.catalog_hash
        || target.build_identity_hash != v2.pins.build_identity_hash
        || target.credential_generation_id != v2.pins.credential_generation_id
        || target.profile_id != plan.profile_id
    {
        return Err(invalid(
            "native execution requires its exact consumed approved PlanV2 and pins",
        ));
    }
    Ok((v2, target))
}

/// Deterministic create-only claim prevents a second dispatch even after a crash
/// before the plan's boundary-response checkpoint. It contains no credential.
fn claim(store: &StateStore, prepared: &Checkpoint) -> Result<PrivateDirectory> {
    let data_path = store
        .paths()
        .data_dir
        .canonicalize()
        .map_err(|_| invalid("native private custody root is unavailable"))?;
    let root = PrivateDirectory::create(&data_path.join("d1-transition-runs"))?;
    let directory = root
        .create_new_directory(&prepared.operation_id)
        .map_err(|_| invalid("native dispatch already claimed; reconcile without replay"))?;
    directory
        .publish_new_file(
            "claim.json",
            &serde_json::to_vec(prepared)?,
            Instant::now() + Duration::from_secs(5),
        )
        .map_err(|_| invalid("native dispatch claim was not durably published; do not replay"))?;
    Ok(directory)
}

pub(in crate::runtime) async fn execute(
    store: &StateStore,
    plan: &mut PlanV1,
    credential: &AuthCredential,
) -> Result<ResultEnvelopeV2> {
    let attempted = Cell::new(false);
    if let Ok(envelope) = Box::pin(execute_inner(store, plan, credential, &attempted)).await {
        return Ok(envelope);
    }
    // A consumed plan stays consumed even when a private publication or
    // journal write fails. Durable claim/checkpoint files remain the
    // recovery authority; no automatic second import is possible.
    plan.status = PlanStatus::RectificationRequired;
    let persisted = if plan.transaction_stage == TransactionStageV1::BoundaryAttemptPersisted {
        persist_transaction_stage_with_artifact(
            store,
            plan,
            TransactionStageV1::BoundaryResponsePersisted,
            json!({"adapter":"native_d1_transition_v3", "attempted":attempted.get(),
                "no_replay":true,"local_recording_failed":true}),
        )
        .is_ok()
    } else {
        store.save_plan(plan).is_ok()
    };
    let mut envelope = ResultEnvelopeV2::success(
        "plans run",
        json!({"no_replay":true,"private_checkpoints_retained":true,
            "rectification_persisted":persisted}),
    );
    envelope.ok = false;
    envelope.operation_id = Some(plan.operation_id.clone());
    envelope.performed = attempted.get();
    envelope.verification.state = VerificationState::Pending;
    envelope.error = Some(ErrorV1 {
        code:"CFCTL_D1_TRANSITION_RECORDING_FAILED".into(),
        message:"Native execution or durable recording failed; this consumed operation must not be replayed.".into(),
        next_step:Some("Preserve the plan, private claim and checkpoints; reconcile their exact provider disposition before any separately approved continuation.".into()),
    });
    Ok(envelope)
}

async fn execute_inner(
    store: &StateStore,
    plan: &mut PlanV1,
    credential: &AuthCredential,
    attempted: &Cell<bool>,
) -> Result<ResultEnvelopeV2> {
    let (v2, target) = consumed(store, plan)?;
    let checkpoint = target.checkpoint(&v2)?;
    let binding = ValidatedImport::from_consumed_plan(&v2, &checkpoint).map_err(invalid)?;
    let contract = plan
        .capability
        .workspace_d1_migration
        .as_ref()
        .ok_or_else(|| invalid("native source missing"))?;
    let bytes = cfctl_workspace::materialize_workspace_d1_transition_execution(contract)?;
    let directory = claim(store, &checkpoint)?;
    let executor = Executor::new(http_client()?, crate::runtime::cloudflare_api::BASE_URL)?;
    let record = RefCell::new(ExecutionRecord {
        schema_version: 1,
        kind: EXECUTION_KIND.into(),
        checkpoints: Vec::new(),
        checkpoint_evidence_hashes: Vec::new(),
    });
    let outcome = executor
        .execute_transition_import(
            &binding,
            &bytes,
            credential,
            |checkpoint| {
                persist_checkpoint(store, &directory, &record, checkpoint)?;
                if checkpoint.stage == Stage::DispatchIntent {
                    attempted.set(true);
                }
                Ok(())
            },
            |progress| v4::persist_import_progress(store, &directory, progress).map_err(|_| ()),
        )
        .await;
    finish(store, plan, &directory, record.into_inner(), outcome)
}

fn persist_checkpoint(
    store: &StateStore,
    directory: &PrivateDirectory,
    record: &RefCell<ExecutionRecord>,
    checkpoint: &Checkpoint,
) -> std::result::Result<(), ()> {
    let evidence = store
        .write_evidence(
            EvidenceClass::Apply,
            &serde_json::to_value(checkpoint).map_err(|_| ())?,
        )
        .map_err(|_| ())?;
    let mut record = record.borrow_mut();
    let name = format!("checkpoint-{}.json", record.checkpoints.len());
    directory
        .publish_new_file(
            &name,
            &serde_json::to_vec(
                &json!({"checkpoint":checkpoint,"evidence_hash":evidence.content_hash}),
            )
            .map_err(|_| ())?,
            Instant::now() + Duration::from_secs(5),
        )
        .map_err(|_| ())?;
    record.checkpoints.push(checkpoint.clone());
    record
        .checkpoint_evidence_hashes
        .push(evidence.content_hash);
    Ok(())
}

fn finish(
    store: &StateStore,
    plan: &mut PlanV1,
    directory: &PrivateDirectory,
    record: ExecutionRecord,
    outcome: std::result::Result<Checkpoint, Failure>,
) -> Result<ResultEnvelopeV2> {
    let attempted = record
        .checkpoints
        .iter()
        .any(|c| c.stage == Stage::DispatchIntent);
    let committed = outcome.as_ref().is_ok_and(|c| c.stage == Stage::Committed);
    let error = outcome.err().map(|e| e.classification);
    let value = serde_json::to_value(&record)?;
    let evidence = store.write_evidence(EvidenceClass::Apply, &value)?;
    directory.publish_new_file(
        "result.json",
        &serde_json::to_vec(&json!({
        "execution":record,"evidence_hash":evidence.content_hash,"error":error} ))?,
        Instant::now() + Duration::from_secs(5),
    ).map_err(|_| invalid("native result publication failed; preserve checkpoints and reconcile without replay"))?;
    plan.status = PlanStatus::RectificationRequired;
    persist_transaction_stage_with_artifact(
        store,
        plan,
        TransactionStageV1::BoundaryResponsePersisted,
        json!({"adapter":"native_d1_transition_v3","evidence_hash":evidence.content_hash,
            "committed":committed,"attempted":attempted,"no_replay":true}),
    )?;
    let mut envelope = ResultEnvelopeV2::success(
        "plans run",
        json!({"atomic_execution":record,"committed":committed,"no_replay":true,
        "private_resume_retained":true,"provider_rollback_qualified":false}),
    );
    envelope.ok = false;
    envelope.operation_id = Some(plan.operation_id.clone());
    envelope.capability_id = Some(plan.capability.id.clone());
    envelope.profile_id = Some(plan.profile_id.clone());
    envelope.account_id = Some(plan.account_id.clone());
    envelope.performed = attempted;
    envelope.evidence.push(evidence);
    envelope.verification.state = VerificationState::Pending;
    envelope.error = Some(ErrorV1 {
        code: "CFCTL_D1_TRANSITION_VERIFICATION_REQUIRED".into(),
        message: if committed {
            "Native import committed; exact terminal assertions and diagnostic verification remain required.".into()
        } else {
            format!(
                "Native import is not qualified terminal; {}; retain this operation without replay.",
                error.unwrap_or("provider outcome uncertain")
            )
        },
        next_step: Some(if committed {
            "Run the committed terminal assertion and assurance diagnostic reads, then call workspace-d1-transition-produce-proof with their exact native references and this operation ID.".into()
        } else {
            "Inspect plans status. A poll continuation needs its own exact approval and private bookmark; neither run nor ingest may be replayed. Provider error is not rollback proof.".into()
        }),
    });
    Ok(envelope)
}

#[cfg(test)]
mod tests;
