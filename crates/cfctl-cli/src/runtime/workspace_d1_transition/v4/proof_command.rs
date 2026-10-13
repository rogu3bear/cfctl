//! Public local proof production. This path never opens a provider credential.
use super::{Identity, Result, Scope, StateStore, invalid, producers, verification_producers};
use crate::runtime::{
    prelude::{CallInput, CatalogSnapshot, ProfilesConfig},
    read_execution::credential_generation_for_read,
};
use cfctl_core::{
    EvidenceV1, ResultEnvelopeV2, VerificationState,
    workspace_d1::transition::{
        application::{PRODUCER_ID, ProofRequest},
        proofs::CaseRef,
    },
};
use serde_json::json;

fn bound(
    store: &StateStore,
    capability_id: &str,
) -> Result<cfctl_workspace::BoundQualificationSource> {
    cfctl_workspace::load_workspace_d1_qualification_source(
        &store.workspace_roots()?,
        capability_id,
        cfctl_workspace::WorkspaceOperationLoad::Execute,
    )?
    .ok_or_else(|| invalid("proof source is not a unique registered qualification owner"))
}

fn case_source(bound: &cfctl_workspace::BoundQualificationSource, case: &CaseRef) -> Result<()> {
    let source = bound
        .pack
        .cases
        .iter()
        .find(|s| s.case == case.case)
        .ok_or_else(|| invalid("proof case is not committed"))?;
    if case.fixture_sha256 != source.execution.sha256
        || bound.source_lengths.get(&source.execution.path).copied() != Some(case.fixture_bytes)
        || case.before_population_inventory != source.before
        || case.after_population_inventory != source.after
        || case.expected_after_state_sha256 != source.expected_after_state_sha256
        || case.failure_sentinel != source.failure_sentinel
        || case.performance_max_seconds != source.performance_max_seconds
        || case.concurrency.as_ref().map(|v| &v.source) != source.concurrent_source.as_ref()
    {
        return Err(invalid(
            "proof case substituted its committed source or oracle",
        ));
    }
    cfctl_core::workspace_d1::transition::proofs::QualificationTarget::from_case(
        &Identity::from_contract(&bound.transition)?,
        case,
    )
    .validate()
    .map_err(invalid)
}

pub(in crate::runtime) fn run(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    input: &CallInput,
) -> Result<ResultEnvelopeV2> {
    if catalog.get(PRODUCER_ID) != Some(&cfctl_catalog::d1_transition_proof_capability()) {
        return Err(invalid(
            "local proof capability differs from its native contract",
        ));
    }
    if input.selectors != json!({})
        || input.query != json!({})
        || input.if_match.is_some()
        || input.if_none_match.is_some()
    {
        return Err(invalid(
            "local proof accepts only its closed body, without selectors or conditionals",
        ));
    }
    let request: ProofRequest = serde_json::from_value(
        input
            .body
            .clone()
            .ok_or_else(|| invalid("typed proof request body required"))?,
    )?;
    let contract = match &request {
        ProofRequest::Application { operation_id, .. } => store
            .load_plan_v2(operation_id)?
            .plan
            .capability
            .workspace_d1_migration
            .ok_or_else(|| invalid("application plan source missing"))?,
        ProofRequest::Population { capability_id, .. }
        | ProofRequest::Case { capability_id, .. }
        | ProofRequest::Writer { capability_id, .. }
        | ProofRequest::Poll { capability_id, .. }
        | ProofRequest::Aggregate { capability_id, .. } => bound(store, capability_id)?.transition,
    };
    let compiled = contract
        .transition
        .as_ref()
        .ok_or_else(|| invalid("proof source transition missing"))?;
    cfctl_workspace::materialize_workspace_d1_transition(&contract)?;
    let profiles = ProfilesConfig::load(store)?;
    let profile = profiles.selected(Some(&compiled.declaration.profile_id))?;
    if profile.kind != cfctl_auth::ProfileKind::ApiToken
        || profile.emergency_only
        || profile.account_id.as_deref() != Some(compiled.declaration.account_id.as_str())
    {
        return Err(invalid(
            "proof metadata is not the source's account-bound profile",
        ));
    }
    let generation = credential_generation_for_read(profile)?;
    let build = super::hash_value(&serde_json::to_value(
        crate::build_identity::current_build_info(),
    )?)?;
    let scope = Scope {
        account: &compiled.declaration.account_id,
        profile: &profile.id,
        generation: &generation,
        catalog: &catalog.schema_hash,
        build: &build,
    };
    let identity = Identity::from_contract(&contract)?;
    let (evidence, reference) = produce(
        store,
        &request,
        &identity,
        &scope,
        compiled.execution.execution_length,
    )?;
    let mut envelope = ResultEnvelopeV2::success(
        "call",
        json!({"local_only":true,
        "provider_requests":0,"proof_evidence_hash":evidence.content_hash,"identity":identity,
        "proof_reference":reference,
        "plan_status_changed":!matches!(request, ProofRequest::Population {..} | ProofRequest::Aggregate {..}),
        "provider_execution_authorized":false}),
    );
    envelope.capability_id = Some(PRODUCER_ID.into());
    envelope.profile_id = Some(profile.id.clone());
    envelope.account_id = Some(scope.account.into());
    if let ProofRequest::Application { operation_id, .. } = &request {
        envelope.operation_id = Some(operation_id.clone());
    }
    envelope.evidence.push(evidence);
    envelope.verification.state = VerificationState::Passed;
    envelope.verification.basis = Some(
        "Authenticated local proof derivation only; no provider call or plan approval.".into(),
    );
    Ok(envelope)
}

fn produce(
    store: &StateStore,
    request: &ProofRequest,
    identity: &Identity,
    scope: &Scope<'_>,
    bytes: usize,
) -> Result<(EvidenceV1, Option<super::ProofRef>)> {
    let evidence = match request {
        ProofRequest::Application {
            operation_id,
            terminal_assertions,
            diagnostic,
        } => {
            super::application::produce(store, operation_id, terminal_assertions, diagnostic, scope)
        }
        ProofRequest::Aggregate {
            capability_id,
            qualification,
        } => {
            let bound = bound(store, capability_id)?;
            for case in &qualification.cases {
                case_source(&bound, case)?;
            }
            producers::produce_qualification(store, qualification, identity, bytes, scope)
        }
        ProofRequest::Population {
            capability_id,
            case,
            phase,
            source,
        } => {
            case_source(&bound(store, capability_id)?, case)?;
            let proof =
                producers::produce_population(store, identity, (case, *phase), source, scope)?;
            return Ok((store.load_evidence(&proof.evidence_hash)?, Some(proof)));
        }
        ProofRequest::Case {
            capability_id,
            case,
        } => {
            case_source(&bound(store, capability_id)?, case)?;
            verification_producers::produce_case(store, case, identity, scope)
        }
        ProofRequest::Writer {
            capability_id,
            case,
        } => {
            case_source(&bound(store, capability_id)?, case)?;
            verification_producers::produce_writer(store, case, identity, scope)
        }
        ProofRequest::Poll {
            capability_id,
            case,
        } => {
            case_source(&bound(store, capability_id)?, case)?;
            verification_producers::produce_poll(store, case, identity, scope)
        }
    }?;
    Ok((evidence, None))
}
