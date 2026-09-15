//! Diagnostic reads are bound to rejected evidence, never arbitrary SQL.
use super::{
    cloudflare_api::BASE_URL,
    credential_resolution::{fresh_credential, platform_secrets},
    prelude::{
        CallInput, CatalogSnapshot, CliError, EvidenceClass, Executor, ProfilesConfig, Result,
        ResultEnvelopeV2, StateStore, Utc, VerificationState, json,
    },
    read_execution::{ExecutedRead, credential_generation_for_read},
    support::{http_client, load_workspace_capability},
};
use cfctl_auth::ProfileKind;
use cfctl_core::d1_reconciliation::{DIAGNOSTIC_ID, DiagnosticRequest};
use cfctl_storage::PrivateDirectory;
use sha2::{Digest, Sha256};
use std::{io::Write, path::Path};

#[cfg(test)]
mod tests;

fn retain_response(
    directory: &PrivateDirectory,
    name: &str,
    sink: &mut std::fs::File,
    bytes: &[u8],
) -> bool {
    sink.write_all(bytes).and_then(|()| sink.sync_all()).is_ok()
        && directory.sync().is_ok()
        && directory
            .read(name, 65_536)
            .is_ok_and(|retained| retained.as_deref() == Some(bytes))
}

fn reject() -> CliError {
    CliError::Input("D1 diagnostic requires authenticated rejected evidence, unchanged registered SQL and exact current account/profile/generation plus a new private --out file".into())
}

#[expect(
    clippy::too_many_lines,
    reason = "the single-attempt boundary keeps receipt admission, private custody and post-attempt evidence in one auditable sequence"
)]
pub(super) async fn execute(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    input: &CallInput,
    requested_profile: Option<&str>,
    requested_account: Option<&str>,
    output: Option<&Path>,
) -> Result<ExecutedRead> {
    let request: DiagnosticRequest =
        serde_json::from_value(input.body.clone().ok_or_else(reject)?)?;
    if input.selectors != json!({})
        || input.query != json!({})
        || input.if_match.is_some()
        || input.if_none_match.is_some()
    {
        return Err(reject());
    }
    let (evidence, failed) = store.load_evidence_value(&request.failed_evidence_hash)?;
    let capability =
        load_workspace_capability(store, &request.capability_id)?.ok_or_else(reject)?;
    let contract = capability
        .workspace_d1_read_inventory
        .as_ref()
        .ok_or_else(reject)?;
    let operation = &contract.operation;
    let query = contract
        .inventory
        .queries
        .iter()
        .find(|q| q.id == request.query_id)
        .ok_or_else(reject)?;
    let observations = failed["execution"]["results"]
        .as_array()
        .ok_or_else(reject)?;
    let rejected = observations
        .iter()
        .filter(|v| v["query_id"] == request.query_id)
        .collect::<Vec<_>>();
    if evidence.class != EvidenceClass::LiveRead
        || failed["kind"] != "workspace_d1_read_inventory_v1"
        || failed["capability_id"] != capability.id
        || failed["inventory_sha256"] != operation.inventory_sha256
        || failed["account_id"] != operation.account_id
        || failed["database_id"] != operation.database_id
        || failed["profile_id"] != operation.profile_id
        || failed["execution"]["read_complete"] != false
        || rejected.len() != 1
        || rejected[0]["status"] != "rejected"
        || rejected[0]["attempted"] != true
        || rejected[0]["query_sha256"] != query.sha256
        || !query.parameters.is_empty()
        || contract.inventory.private_output.is_some()
        || requested_profile != Some(operation.profile_id.as_str())
        || requested_account != Some(operation.account_id.as_str())
    {
        return Err(reject());
    }
    let read_input = CallInput {
        selectors: json!({"account_id":operation.account_id,"database_id":operation.database_id}),
        query: json!({}),
        body: Some(json!({"inventory_sha256":operation.inventory_sha256,
            "expected_credential_generation_id":request.expected_credential_generation_id})),
        ..CallInput::default()
    };
    let validated = cfctl_cloudflare::d1_read_inventory::validate(&capability, &read_input)?;
    let profiles = ProfilesConfig::load(store)?;
    let profile = profiles.selected(requested_profile)?;
    let generation = credential_generation_for_read(profile)?;
    if profile.kind != ProfileKind::ApiToken
        || profile.emergency_only
        || profile.account_id.as_deref() != requested_account
        || generation != request.expected_credential_generation_id
    {
        return Err(reject());
    }
    let output = output.filter(|p| p.is_absolute()).ok_or_else(reject)?;
    let directory = PrivateDirectory::open(output.parent().ok_or_else(reject)?)?;
    let name = output
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(reject)?;
    let secrets = platform_secrets(store);
    let credential = fresh_credential(profile, &secrets).await?;
    let executor = Executor::new(http_client()?, BASE_URL)?;
    if load_workspace_capability(store, &capability.id)?.as_ref() != Some(&capability)
        || ProfilesConfig::load(store)?.selected(Some(&profile.id))? != profile
    {
        return Err(reject());
    }
    let mut sink = directory.create_new_file(name)?;
    let started_at = Utc::now();
    let response = executor
        .diagnose_registered_d1_query(&validated, &request.query_id, &credential)
        .await;
    let (status, bytes, truncated, codes, transport_complete) = match response {
        Ok(value) => (
            Some(value.http_status),
            value.bytes,
            value.truncated,
            value.provider_error_codes,
            true,
        ),
        Err(_) => (None, Vec::new(), false, Vec::new(), false),
    };
    let sink_complete = retain_response(&directory, name, &mut sink, &bytes);
    let custody_current = directory.sync().is_ok()
        && load_workspace_capability(store, &capability.id)
            .is_ok_and(|current| current.as_ref() == Some(&capability))
        && ProfilesConfig::load(store).is_ok_and(|current| {
            current
                .selected(Some(&profile.id))
                .is_ok_and(|selected| selected == profile)
        });
    let complete = transport_complete && sink_complete && !truncated && custody_current;
    let result = json!({"schema_version":1,"kind":"registered_d1_failed_query_diagnostic",
        "failed_evidence_hash":evidence.content_hash,"failed_run_id":failed["run_id"],
        "capability_id":capability.id,"inventory_sha256":operation.inventory_sha256,
        "query_id":query.id,"query_sha256":query.sha256,
        "account_id":operation.account_id,"database_id":operation.database_id,"profile_id":profile.id,
        "credential_generation_id":generation,"catalog_hash":catalog.schema_hash,
        "historical_credential_generation_id":failed["credential_generation_id"],
        "started_at":started_at,"completed_at":Utc::now(),"provider_requests":1,"automatic_retries":0,
        "http_status":status,"provider_error_codes":codes,"response_bytes":bytes.len(),
        "response_sha256":format!("sha256:{}",hex::encode(Sha256::digest(&bytes))),
        "private_output_path":output,"private_output_complete":complete,"truncated":truncated,
        "registered_source_and_credential_current":custody_current,"readiness_qualified":false});
    let evidence = store.write_observation_evidence(EvidenceClass::LiveRead, &result)?;
    let mut envelope = ResultEnvelopeV2::success("call", result).with_evidence(evidence);
    envelope.capability_id = Some(DIAGNOSTIC_ID.into());
    envelope.profile_id = Some(profile.id.clone());
    envelope.account_id = Some(operation.account_id.clone());
    envelope.performed = true;
    envelope.ok = complete;
    envelope.verification.state = VerificationState::NotApplicable;
    if !complete {
        envelope.error = Some(cfctl_core::ErrorV1 { code:"CFCTL_D1_DIAGNOSTIC_INCOMPLETE".into(),
            message:"The single diagnostic attempt did not produce a complete retained response.".into(),
            next_step:Some("Preserve this diagnostic and private sink; do not automatically retry the query or population.".into()) });
    }
    Ok(ExecutedRead {
        envelope,
        credential_generation_id: Some(generation),
    })
}
