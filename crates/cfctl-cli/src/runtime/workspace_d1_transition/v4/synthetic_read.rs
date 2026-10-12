//! Native synthetic inventory execution source; public catalog dispatch stays closed.
use super::{CallInput, Result, Scope, StateStore, Utc, hash_value, invalid, json, resource};
use crate::runtime::{
    cloudflare_api::BASE_URL,
    credential_resolution::{fresh_credential, platform_secrets},
    prelude::{CatalogSnapshot, CloudflareError, Executor, ProfilesConfig},
    read_execution::{ExecutedRead, credential_generation_for_read},
    support::http_client,
    workspace_d1_reads,
};
use cfctl_auth::ProfileKind;
use cfctl_core::{
    OperationalProofOutcomeV1, OperationalProofScopeV1, OperationalProofV1,
    workspace_d1::transition::{
        ProofRef,
        admission::resource::{PopulationBinding, PopulationRequest},
    },
};
use cfctl_workspace::WorkspaceOperationLoad;

fn native_input(capability: &cfctl_core::CapabilityV1, generation: &str) -> Result<CallInput> {
    let contract = capability
        .workspace_d1_read_inventory
        .as_ref()
        .ok_or_else(|| invalid("synthetic read projection missing"))?;
    Ok(CallInput {
        selectors: json!({"account_id":contract.operation.account_id,"database_id":contract.operation.database_id}),
        query: json!({}),
        body: Some(
            json!({"inventory_sha256":contract.operation.inventory_sha256,
            "expected_credential_generation_id":generation}),
        ),
        ..CallInput::default()
    })
}

#[expect(
    dead_code,
    reason = "native synthetic read producer is not publicly routed before lifecycle admission/review"
)]
pub(super) async fn execute(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability_id: &str,
    request: &PopulationRequest,
    profile_id: &str,
    account_id: &str,
) -> Result<(ExecutedRead, ProofRef)> {
    request.validate().map_err(invalid)?;
    let bound = cfctl_workspace::load_workspace_d1_qualification_source(
        &store.workspace_roots()?,
        capability_id,
        WorkspaceOperationLoad::Execute,
    )?
    .ok_or_else(|| invalid("synthetic population owner is not registered"))?;
    if request.schema_version != 1
        || !bound.pack.operation.iter().any(|op| {
            op.id == capability_id
                && op.role == cfctl_core::workspace_d1::transition::admission::Role::Population
        })
    {
        return Err(invalid(
            "synthetic read must select its committed population role",
        ));
    }
    let profiles = ProfilesConfig::load(store)?;
    let profile = profiles.selected(Some(profile_id))?;
    let generation = credential_generation_for_read(profile)?;
    if profile.kind != ProfileKind::ApiToken
        || profile.emergency_only
        || profile.account_id.as_deref() != Some(account_id)
        || generation != request.expected_credential_generation_id
    {
        return Err(invalid(
            "synthetic read account-bound profile generation differs",
        ));
    }
    let build = hash_value(&serde_json::to_value(
        crate::build_identity::current_build_info(),
    )?)?;
    let scope = Scope {
        account: account_id,
        profile: profile_id,
        generation: &generation,
        catalog: &catalog.schema_hash,
        build: &build,
    };
    let population = resource::prepare_population(
        store,
        &bound,
        (request.case, request.phase),
        &request.create,
        &scope,
    )?;
    let capability = cfctl_workspace::materialize_qualification_read_capability(
        &bound,
        &population,
        profile_id,
    )?;
    let input = native_input(&capability, &generation)?;
    let validated = cfctl_cloudflare::d1_read_inventory::validate(&capability, &input)?;
    // Source/create and SQL validation precede credential access.
    let credential = fresh_credential(profile, &platform_secrets(store)).await?;
    let executor = Executor::new(http_client()?, BASE_URL)?;
    let started = Utc::now();
    let result = executor
        .execute_d1_read_inventory(&validated, &credential, || {
            reacquire(store, &bound, request, &scope, &population, profile).map_err(|_| {
                CloudflareError::InvalidRequestBody("synthetic read binding changed".into())
            })
        })
        .await?;
    let binding = PopulationBinding {
        resource: population.resource,
        phase: request.phase,
    };
    let executed = workspace_d1_reads::persist_synthetic(
        store,
        catalog,
        &capability,
        &validated,
        profile,
        (started, &result),
        &binding,
    )?;
    let reference = record_native_proof(store, &scope, capability_id, &input, &executed)?;
    Ok((executed, reference))
}

fn reacquire(
    store: &StateStore,
    bound: &cfctl_workspace::BoundQualificationSource,
    request: &PopulationRequest,
    scope: &Scope<'_>,
    population: &cfctl_workspace::MaterializedPopulation,
    profile: &crate::runtime::prelude::ProfileMetadata,
) -> Result<()> {
    let current = resource::prepare_population(
        store,
        bound,
        (request.case, request.phase),
        &request.create,
        scope,
    )?;
    if &current != population
        || ProfilesConfig::load(store)?.selected(Some(scope.profile))? != profile
    {
        return Err(invalid(
            "synthetic read source, create or credential changed",
        ));
    }
    Ok(())
}

fn record_native_proof(
    store: &StateStore,
    scope: &Scope<'_>,
    capability_id: &str,
    input: &CallInput,
    executed: &ExecutedRead,
) -> Result<ProofRef> {
    let evidence = executed
        .envelope
        .evidence
        .first()
        .ok_or_else(|| invalid("synthetic read durable evidence missing"))?
        .clone();
    let mut proof = OperationalProofV1::new(
        Utc::now(),
        capability_id,
        scope.catalog,
        &hash_value(&serde_json::to_value(input)?)?,
        OperationalProofScopeV1::new(
            Some(scope.profile),
            Some(scope.account),
            Some(scope.generation),
        ),
        if executed.envelope.ok {
            OperationalProofOutcomeV1::Succeeded
        } else {
            OperationalProofOutcomeV1::Failed
        },
        evidence.clone(),
    );
    proof.bind_build_identity_hash(scope.build)?;
    store.record_operational_proof(&proof)?;
    let reference = ProofRef {
        proof_hash: store.operational_proof_hash(&proof)?,
        evidence_hash: evidence.content_hash,
    };
    Ok(reference)
}

/// Reconstruct the same current inventory and create lineage at proof consumption.
pub(super) fn validate_source(
    store: &StateStore,
    binding: &PopulationBinding,
    expected: &cfctl_core::workspace_d1::transition::Observation,
    scope: &Scope<'_>,
) -> Result<cfctl_core::CapabilityV1> {
    let bound = cfctl_workspace::load_workspace_d1_qualification_source(
        &store.workspace_roots()?,
        &expected.capability_id,
        WorkspaceOperationLoad::Execute,
    )?
    .ok_or_else(|| invalid("synthetic population source disappeared"))?;
    let population = resource::prepare_population(
        store,
        &bound,
        (binding.resource.case, binding.phase),
        &binding.resource.create,
        scope,
    )?;
    if population.resource != binding.resource || &population.source != expected {
        return Err(invalid(
            "synthetic observation resource or inventory substituted",
        ));
    }
    let capability = cfctl_workspace::materialize_qualification_read_capability(
        &bound,
        &population,
        scope.profile,
    )?;
    Ok(capability)
}
