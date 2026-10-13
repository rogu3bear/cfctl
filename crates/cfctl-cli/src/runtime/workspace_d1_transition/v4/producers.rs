//! Authenticated local producers. Policy and rollback activation remain gated.
use super::{
    CallInput, Declaration, EvidenceClass, ExecutionRecord, Identity, PlanStatus, PolicyDecision,
    PopulationPhase, ProofRef, Qualification, Result, Scope, Stage, StateStore, TransportReceipt,
    Utc, Value, WorkspaceD1MigrationContractV1, canonical_digest, hash_value, invalid, json,
    observations, read, validate_qualification_record,
};
use cfctl_core::{
    EvidenceV1, OperationalProofOutcomeV1, OperationalProofScopeV1, OperationalProofV1,
    workspace_d1::transition::{
        Observation,
        admission::resource::{PopulationBinding, ReadPhase},
        proofs::{CaseRef, POLICY_KIND, POPULATION_CAPABILITY, POPULATION_KIND, Population},
    },
};
use sha2::{Digest, Sha256};

pub(super) fn population_source(
    store: &StateStore,
    identity: &Identity,
    database: &str,
    target: (&Observation, ReadPhase),
    reference: &ProofRef,
    scope: &Scope<'_>,
    now: chrono::DateTime<Utc>,
) -> Result<(OperationalProofV1, String)> {
    let (expected, _) = target;
    let proof = read(store, reference, scope, now)?;
    let value = store.read_evidence_value(&reference.evidence_hash)?;
    let capability = population_capability(store, identity, database, target, &value, scope)?;
    let contract = capability
        .workspace_d1_read_inventory
        .as_ref()
        .ok_or_else(|| invalid("synthetic population must use a native inventory"))?;
    if database == identity.database_id
        || contract.repository_head != identity.repository_head
        || contract.operation.account_id != scope.account
        || contract.operation.database_id != database
        || contract.operation.profile_id != scope.profile
        || contract.operation.inventory_path != expected.inventory.path
        || contract.operation.inventory_sha256 != expected.inventory.sha256
        || contract.inventory.private_output.is_some()
    {
        return Err(invalid(
            "synthetic population source, isolation or scope differs",
        ));
    }
    cfctl_workspace::materialize_workspace_d1_transition_source(
        std::path::Path::new(&contract.repository_root),
        &identity.repository_head,
        &expected.inventory,
    )
    .map_err(|_| invalid("synthetic inventory Git source identity differs"))?;
    let input = CallInput {
        selectors: json!({"account_id":scope.account,"database_id":database}),
        query: json!({}),
        body: Some(
            json!({"inventory_sha256":expected.inventory.sha256,"expected_credential_generation_id":scope.generation}),
        ),
        ..CallInput::default()
    };
    let validated = cfctl_cloudflare::d1_read_inventory::validate(&capability, &input)?;
    if proof.capability_id != expected.capability_id
        || proof.input_hash != hash_value(&serde_json::to_value(&input)?)?
    {
        return Err(invalid("synthetic population source call differs"));
    }
    observations::validate_value(
        &value,
        &proof,
        &validated,
        scope,
        chrono::DateTime::<Utc>::MIN_UTC,
        now,
    )?;
    let results = value
        .pointer("/execution/results")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("synthetic population results missing"))?;
    let states: Vec<_> = results
        .iter()
        .map(|result| {
            json!({"query_id":result["query_id"], "query_sha256":result["query_sha256"],
            "rows":result.pointer("/receipt/result/0/results")})
        })
        .collect();
    Ok((proof, hash_value(&json!(states))?))
}

pub(super) fn population_capability(
    store: &StateStore,
    identity: &Identity,
    database: &str,
    target: (&Observation, ReadPhase),
    value: &Value,
    scope: &Scope<'_>,
) -> Result<cfctl_core::CapabilityV1> {
    let (expected, phase) = target;
    Ok(if let Some(binding) = value.get("synthetic_binding") {
        let binding: PopulationBinding = serde_json::from_value(binding.clone())
            .map_err(|_| invalid("synthetic read binding is not the closed native record"))?;
        if &binding.resource.identity != identity
            || binding.resource.database_id != database
            || binding.phase != phase
        {
            return Err(invalid(
                "synthetic read create lineage, phase or target differs",
            ));
        }
        super::synthetic_read::validate_source(store, &binding, expected, scope)?
    } else {
        crate::runtime::support::load_workspace_capability(store, &expected.capability_id)?
            .ok_or_else(|| invalid("synthetic population read is not registered"))?
    })
}

/// Recompute the semantic digest from the original authenticated native results.
pub(super) fn validate_population(
    store: &StateStore,
    record: &Population,
    target: (&CaseRef, PopulationPhase),
    expected: &Identity,
    scope: &Scope<'_>,
    now: chrono::DateTime<Utc>,
) -> Result<()> {
    let (case, phase) = target;
    if record.phase != phase
        || record.schema_version != 1
        || record.kind != POPULATION_KIND
        || record.attempted_operation_id != case.effect.operation_id
        || record.database_id != case.synthetic_database_id
        || record.fixture_sha256 != case.fixture_sha256
        || &record.source_inventory != case.inventory(phase)
    {
        return Err(invalid(
            "qualification population receipt source or effect differs",
        ));
    }
    let (_, state) = population_source(
        store,
        expected,
        &record.database_id,
        (&record.source_inventory, phase.into()),
        &record.source,
        scope,
        now,
    )?;
    if record.semantic_state_sha256 != state {
        return Err(invalid(
            "synthetic population digest is not derived from native results",
        ));
    }
    Ok(())
}

pub(super) fn produce_population(
    store: &StateStore,
    expected: &Identity,
    target: (&CaseRef, PopulationPhase),
    source: &ProofRef,
    scope: &Scope<'_>,
) -> Result<ProofRef> {
    let (case, phase) = target;
    let (native, state) = population_source(
        store,
        expected,
        &case.synthetic_database_id,
        (case.inventory(phase), phase.into()),
        source,
        scope,
        Utc::now(),
    )?;
    let body = Population {
        schema_version: 1,
        kind: POPULATION_KIND.into(),
        phase,
        attempted_operation_id: case.effect.operation_id.clone(),
        database_id: case.synthetic_database_id.clone(),
        fixture_sha256: case.fixture_sha256.clone(),
        source_inventory: case.inventory(phase).clone(),
        source: source.clone(),
        semantic_state_sha256: state,
    };
    let evidence = store.write_evidence(EvidenceClass::LiveRead, &serde_json::to_value(&body)?)?;
    let mut proof = OperationalProofV1::new(
        native.observed_at,
        POPULATION_CAPABILITY,
        scope.catalog,
        &hash_value(&serde_json::to_value(&body)?)?,
        OperationalProofScopeV1::new(
            Some(scope.profile),
            Some(scope.account),
            Some(scope.generation),
        ),
        OperationalProofOutcomeV1::Succeeded,
        evidence.clone(),
    );
    proof.bind_build_identity_hash(scope.build)?;
    store.record_operational_proof(&proof)?;
    Ok(ProofRef {
        proof_hash: store.operational_proof_hash(&proof)?,
        evidence_hash: evidence.content_hash,
    })
}

pub(super) fn produce_qualification(
    store: &StateStore,
    record: &Qualification,
    expected: &Identity,
    bytes: usize,
    scope: &Scope<'_>,
) -> Result<EvidenceV1> {
    let now = Utc::now();
    validate_qualification_record(store, record, expected, bytes, scope, now, now, None)?;
    Ok(store.write_evidence(
        EvidenceClass::PostChangeVerification,
        &serde_json::to_value(record)?,
    )?)
}

#[expect(
    dead_code,
    reason = "policy decision producer is unregistered; requires an actual exact approved consumed native policy plan"
)]
pub(super) fn produce_policy(
    store: &StateStore,
    plan: &cfctl_core::PlanV2,
    contract: &WorkspaceD1MigrationContractV1,
) -> Result<EvidenceV1> {
    plan.validate()?;
    let compiled = contract
        .transition
        .as_ref()
        .ok_or_else(|| invalid("policy source transition missing"))?;
    let policy = compiled
        .assurance_policy
        .as_ref()
        .ok_or_else(|| invalid("managed policy source missing"))?;
    let declaration = compiled
        .declaration
        .assurance
        .as_ref()
        .ok_or_else(|| invalid("policy assurance declaration missing"))?;
    let identity = Identity::from_contract(contract)?;
    let Declaration::ManagedD1ApplicationV1 { policy: source, .. } = declaration else {
        return Err(invalid(
            "full mode does not accept a managed policy decision",
        ));
    };
    let body = PolicyDecision {
        schema_version: 1,
        kind: POLICY_KIND.into(),
        identity,
        policy_sha256: source.sha256.clone(),
        assurance_sha256: hash_value(&serde_json::to_value(declaration)?)?,
        release_id: policy.release_id.clone(),
    };
    if plan.plan.status != PlanStatus::Running
        || plan.plan.transaction_stage != cfctl_core::TransactionStageV1::BoundaryAttemptPersisted
        || plan.plan.capability.path != "workspace:d1-assurance-policy-v1"
        || plan
            .plan
            .approval
            .as_ref()
            .map(|approval| approval.approved_content_hash.as_str())
            != Some(plan.plan.content_hash.as_str())
        || plan.plan.account_id != compiled.declaration.account_id
        || plan.plan.profile_id != compiled.declaration.profile_id
        || plan
            .plan
            .targets
            .pointer("/adapter/workspace_d1_assurance_decision")
            != Some(&serde_json::to_value(&body)?)
    {
        return Err(invalid(
            "policy decision is not the exact explicit approved native target",
        ));
    }
    cfctl_workspace::materialize_workspace_d1_transition(contract)
        .map_err(|_| invalid("policy source changed"))?;
    Ok(store.write_evidence(
        EvidenceClass::PostChangeVerification,
        &serde_json::to_value(body)?,
    )?)
}

/// The caller supplies an already admitted private directory, never a new auth store.
pub(super) fn persist_import_progress(
    store: &StateStore,
    directory: &cfctl_storage::PrivateDirectory,
    progress: &cfctl_cloudflare::d1_transition::import::Progress,
) -> Result<String> {
    let mut artifact = None;
    if progress.at_bookmark.is_some()
        || progress.terminal_bookmark.is_some()
        || progress.provider_error.is_some()
    {
        let bytes = serde_json::to_vec(
            &json!({"schema_version":1,"kind":"workspace_d1_transition_private_progress_v1","operation_id":progress.operation_id,
            "database_id":progress.database_id,"at_bookmark":progress.at_bookmark, "terminal_bookmark":progress.terminal_bookmark,"provider_error":progress.provider_error}),
        )?;
        if bytes.len() > 131_072 {
            return Err(invalid("private import resume identity exceeds its bound"));
        }
        let name = format!(
            "{}-{}.resume.json",
            progress.operation_id,
            uuid::Uuid::new_v4()
        );
        directory
            .publish_new_file(
                &name,
                &bytes,
                std::time::Instant::now() + std::time::Duration::from_secs(5),
            )
            .map_err(|_| invalid("private import resume identity is not durably published"))?;
        artifact = Some(
            json!({"path":directory.location().join(&name),"name":name,"bytes":bytes.len(),"sha256":format!("sha256:{}",hex::encode(Sha256::digest(&bytes)))}),
        );
    }
    let value = if let Some(terminal) = &progress.terminal {
        store.write_evidence(EvidenceClass::Apply,&json!({"kind":"workspace_d1_transition_import_progress_v1",
            "operation_id":progress.operation_id,"database_id":progress.database_id,"phase":progress.phase,
            "private_progress":artifact}))?;
        serde_json::to_value(terminal)?
    } else {
        json!({"kind":"workspace_d1_transition_import_progress_v1","operation_id":progress.operation_id,
        "database_id":progress.database_id,"phase":progress.phase,"private_progress":artifact,
        "bookmark_sha256":progress.at_bookmark.as_ref().map(|bookmark| {
            format!("sha256:{}",hex::encode(Sha256::digest(bookmark.as_bytes())))
        })})
    };
    let evidence = store.write_evidence(EvidenceClass::Apply, &value)?;
    Ok(evidence.content_hash)
}

/// A provider SQL error alone is not rollback proof. This local producer requires
/// authenticated full synthetic population equality bracketing that exact error.
#[expect(
    dead_code,
    reason = "rollback reconciliation producer stays unregistered and never sends SQL"
)]
pub(super) fn reconcile_rollback(
    store: &StateStore,
    case: &CaseRef,
    expected: &Identity,
    checkpoint_evidence: &[String],
    provider_error_hash: &str,
    scope: &Scope<'_>,
) -> Result<EvidenceV1> {
    if !case.case.is_failure() {
        return Err(invalid(
            "rollback reconciliation requires a declared failure case",
        ));
    }
    let now = Utc::now();
    let (error_at, bookmark) = provider_error(
        store,
        provider_error_hash,
        &case.effect.operation_id,
        &case.synthetic_database_id,
        now,
    )?;
    validate_rollback_population(store, case, expected, scope, error_at, now)?;
    if checkpoint_evidence.len() < 2 || checkpoint_evidence.len() > 6 {
        return Err(invalid("rollback checkpoint bound differs"));
    }
    let mut checkpoints = Vec::new();
    let mut checkpoint_evidence_hashes = checkpoint_evidence.to_vec();
    for hash in checkpoint_evidence {
        let evidence = store.load_evidence(hash)?;
        if evidence.class != EvidenceClass::Apply || evidence.generated_at > error_at {
            return Err(invalid("rollback checkpoint provenance differs"));
        }
        let checkpoint: cfctl_core::workspace_d1::transition::execution::Checkpoint =
            serde_json::from_value(store.read_evidence_value(hash)?)
                .map_err(|_| invalid("rollback checkpoint malformed"))?;
        checkpoints.push(checkpoint);
    }
    let last = checkpoints
        .last()
        .ok_or_else(|| invalid("rollback checkpoint absent"))?
        .clone();
    let mut identity = expected.clone();
    identity.execution_sha256.clone_from(&case.fixture_sha256);
    if last.identity != identity || last.operation_id != case.effect.operation_id {
        return Err(invalid("rollback checkpoint source or effect differs"));
    }
    let receipt = TransportReceipt {
        schema_version: 1,
        kind: cfctl_core::workspace_d1::transition::proofs::TRANSPORT_RECEIPT_KIND.into(),
        operation_id: last.operation_id.clone(),
        database_id: case.synthetic_database_id.clone(),
        transport: cfctl_core::workspace_d1::transition::proofs::TRANSPORT.into(),
        execution_sha256: case.fixture_sha256.clone(),
        stage: Stage::RolledBack,
        bookmark_sha256: bookmark.clone(),
        provider_error_evidence_hash: Some(provider_error_hash.into()),
        continuation: None,
    };
    let terminal = store.write_evidence(EvidenceClass::Apply, &serde_json::to_value(receipt)?)?;
    cfctl_cloudflare::d1_transition::reconcile(
        &last,
        cfctl_cloudflare::d1_transition::Terminal::RolledBack {
            receipt_sha256: terminal.content_hash,
            bookmark_sha256: bookmark.clone(),
        },
        |checkpoint| {
            let evidence = store
                .write_evidence(
                    EvidenceClass::Apply,
                    &serde_json::to_value(checkpoint).map_err(|_| ())?,
                )
                .map_err(|_| ())?;
            checkpoint_evidence_hashes.push(evidence.content_hash);
            checkpoints.push(checkpoint.clone());
            Ok(())
        },
    )
    .map_err(|_| invalid("rollback checkpoint reconciliation remains uncertain"))?;
    let record = ExecutionRecord {
        schema_version: 1,
        kind: cfctl_core::workspace_d1::transition::proofs::EXECUTION_KIND.into(),
        checkpoints,
        checkpoint_evidence_hashes,
    };
    record.terminal().map_err(invalid)?;
    Ok(store.write_evidence(EvidenceClass::Apply, &serde_json::to_value(record)?)?)
}

pub(super) fn provider_error(
    store: &StateStore,
    hash: &str,
    operation: &str,
    database: &str,
    not_after: chrono::DateTime<Utc>,
) -> Result<(chrono::DateTime<Utc>, String)> {
    let error = store.load_evidence(hash)?;
    let body = store.read_evidence_value(hash)?;
    if error.class != EvidenceClass::Apply
        || error.generated_at > not_after
        || body.get("kind").and_then(Value::as_str)
            != Some("workspace_d1_transition_import_progress_v1")
        || body.get("phase").and_then(Value::as_str) != Some("provider_error")
        || body.get("operation_id").and_then(Value::as_str) != Some(operation)
        || body.get("database_id").and_then(Value::as_str) != Some(database)
    {
        return Err(invalid(
            "rollback reconciliation lacks its exact native provider error",
        ));
    }
    let bookmark = body
        .get("bookmark_sha256")
        .and_then(Value::as_str)
        .filter(|hash| canonical_digest(hash))
        .ok_or_else(|| invalid("rollback reconciliation lacks the provider-bound bookmark"))?;
    Ok((error.generated_at, bookmark.into()))
}

fn validate_rollback_population(
    store: &StateStore,
    case: &CaseRef,
    expected: &Identity,
    scope: &Scope<'_>,
    error_at: chrono::DateTime<Utc>,
    now: chrono::DateTime<Utc>,
) -> Result<()> {
    if case.before_population_inventory != case.after_population_inventory {
        return Err(invalid(
            "rollback population inventories use different hash domains",
        ));
    }
    let before = read(store, &case.before, scope, now)?;
    let after = read(store, &case.after, scope, now)?;
    if before.capability_id != POPULATION_CAPABILITY
        || after.capability_id != POPULATION_CAPABILITY
        || before.observed_at >= error_at
        || after.observed_at <= error_at
    {
        return Err(invalid(
            "rollback population does not bracket the provider error",
        ));
    }
    let before: Population =
        serde_json::from_value(store.read_evidence_value(&case.before.evidence_hash)?)
            .map_err(|_| invalid("rollback baseline population malformed"))?;
    let after: Population =
        serde_json::from_value(store.read_evidence_value(&case.after.evidence_hash)?)
            .map_err(|_| invalid("rollback terminal population malformed"))?;
    validate_population(
        store,
        &before,
        (case, PopulationPhase::Before),
        expected,
        scope,
        now,
    )?;
    validate_population(
        store,
        &after,
        (case, PopulationPhase::After),
        expected,
        scope,
        now,
    )?;
    if before.semantic_state_sha256 != after.semantic_state_sha256
        || after.semantic_state_sha256 != case.expected_after_state_sha256
    {
        return Err(invalid(
            "rollback altered synthetic schema, ledger or population",
        ));
    }
    Ok(())
}
