//! Read-specific orchestration; application predicates and write callers stay separate.
use cfctl_auth::ProfileKind;
use cfctl_cloudflare::d1_read_inventory::{self, ValidatedD1ReadInventory};
use cfctl_core::d1_read_inventory::D1ReadInventoryResultV1;

use super::{
    cloudflare_api::BASE_URL,
    credential_resolution::{fresh_credential, platform_secrets},
    prelude::{
        CallInput, CapabilityV1, CatalogSnapshot, CliError, CloudflareError, ErrorV1,
        EvidenceClass, Executor, ProfileMetadata, ProfilesConfig, Result, ResultEnvelopeV2,
        StateStore, Utc, Uuid, VerificationState, json,
    },
    read_execution::{ExecutedRead, credential_generation_for_read},
    support::{http_client, load_workspace_capability},
};

pub(super) async fn execute(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    requested_profile: Option<&str>,
    requested_account: Option<&str>,
) -> Result<ExecutedRead> {
    // Both current source and the complete SQL/output population are checked
    // before selecting a profile or touching its credential store.
    let current = load_workspace_capability(store, &capability.id)?
        .ok_or_else(|| CliError::Input("reviewed D1 read owner is no longer registered".into()))?;
    if current.workspace_d1_read_inventory != capability.workspace_d1_read_inventory {
        return Err(CliError::Input(
            "reviewed D1 read source contract drifted".into(),
        ));
    }
    let validated = d1_read_inventory::validate(&current, input)?;
    let operation = &validated.contract().operation;
    if requested_profile != Some(operation.profile_id.as_str())
        || requested_account != Some(operation.account_id.as_str())
    {
        return Err(CliError::Input(
            "reviewed D1 reads require the exact explicit profile and account".into(),
        ));
    }
    let profiles = ProfilesConfig::load(store)?;
    let profile = profiles.selected(requested_profile)?;
    let generation = credential_generation_for_read(profile)?;
    if profile.kind != ProfileKind::ApiToken
        || profile.emergency_only
        || profile.account_id.as_deref() != Some(operation.account_id.as_str())
        || generation != validated.call().expected_credential_generation_id
    {
        return Err(CliError::Input(
            "reviewed D1 read account-bound API-token generation differs".into(),
        ));
    }
    let credential = fresh_credential(profile, &platform_secrets(store)).await?;
    let executor = Executor::new(http_client()?, BASE_URL)?;
    let started_at = Utc::now();
    let result = executor
        .execute_d1_read_inventory(&validated, &credential, || {
            reacquire(store, &validated, profile).map_err(|_| {
                CloudflareError::InvalidRequestBody(
                    "reviewed read owner or credential changed".into(),
                )
            })
        })
        .await?;
    persist(
        store, catalog, capability, &validated, profile, started_at, &result,
    )
}

fn reacquire(
    store: &StateStore,
    validated: &ValidatedD1ReadInventory,
    expected: &ProfileMetadata,
) -> Result<()> {
    cfctl_workspace::revalidate_workspace_d1_read_inventory(validated.contract())?;
    let current = ProfilesConfig::load(store)?;
    if current.selected(Some(&expected.id))? != expected {
        return Err(CliError::Input(
            "read credential metadata or generation drifted".into(),
        ));
    }
    Ok(())
}

/// This function is the actual durable observation path and is tested directly
/// with unapproved provider row material. Validation precedes serialization and
/// every store write, including failed/partial read records.
fn persist(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    validated: &ValidatedD1ReadInventory,
    profile: &ProfileMetadata,
    started_at: chrono::DateTime<Utc>,
    result: &D1ReadInventoryResultV1,
) -> Result<ExecutedRead> {
    d1_read_inventory::validate_result(validated, result)?;
    let contract = validated.contract();
    let generation = credential_generation_for_read(profile)?;
    if profile.id != contract.operation.profile_id
        || generation != validated.call().expected_credential_generation_id
        || profile.account_id.as_deref() != Some(contract.operation.account_id.as_str())
    {
        return Err(CliError::Input(
            "read observation credential join is inconsistent".into(),
        ));
    }
    let value = json!({
        "kind":"workspace_d1_read_inventory_v1", "run_id":Uuid::new_v4().to_string(),
        "started_at":started_at, "completed_at":Utc::now(), "non_atomic_observations":true,
        "capability_id":capability.id, "catalog_schema_hash":catalog.schema_hash,
        "build":crate::build_identity::current_build_info(),
        "profile_id":profile.id, "credential_generation_id":generation,
        "account_id":contract.operation.account_id, "database_id":contract.operation.database_id,
        "repository_root":contract.repository_root, "repository_head":contract.repository_head,
        "repository_tree":contract.repository_tree, "source_revision":contract.operation.source_revision,
        "source_inputs":contract.operation.source, "operation_pack_sha256":contract.operation_pack_sha256,
        "inventory_sha256":contract.operation.inventory_sha256,
        "contract_sha256":cfctl_core::hash_value(&serde_json::to_value(contract)?)?,
        "execution":result,
        "cost_limit":"Output limits and client deadlines do not establish a hard in-flight scan or currency ceiling.",
        "ordinary_application_behavior_verified":false
    });
    let evidence_class = if result.attempted_queries > 0 {
        EvidenceClass::LiveRead
    } else {
        EvidenceClass::LocalProof
    };
    let evidence = store.write_observation_evidence(evidence_class, &value)?;
    let mut envelope = ResultEnvelopeV2::success("call", value).with_evidence(evidence);
    envelope.capability_id = Some(capability.id.clone());
    envelope.profile_id = Some(profile.id.clone());
    envelope.account_id = Some(contract.operation.account_id.clone());
    envelope.ok = result.read_complete;
    envelope.performed = result.attempted_queries > 0;
    envelope.verification.state = VerificationState::NotApplicable;
    envelope.verification.basis = Some(
        "Qualified read population; application predicates are evaluated by the owning caller."
            .into(),
    );
    if !result.read_complete {
        envelope.error = Some(ErrorV1 { code:"CFCTL_D1_READ_INCOMPLETE".into(),
            message:"The reviewed D1 population contains rejected or unattempted reads.".into(),
            next_step:Some("Inspect the per-query classifications and remaining prerequisites; do not automatically replay this population.".into()) });
    }
    Ok(ExecutedRead {
        envelope,
        credential_generation_id: Some(generation),
    })
}

#[cfg(test)]
mod tests;
