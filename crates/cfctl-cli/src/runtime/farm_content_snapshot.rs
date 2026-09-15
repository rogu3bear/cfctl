//! Account-bound read custody and immutable private output for Farm provenance.
use super::{
    credential_resolution::{fresh_credential, platform_secrets},
    prelude::{
        CallArgs, CallInput, CapabilityV1, CliError, EvidenceClass, Executor, ProfileMetadata,
        ProfilesConfig, Result, ResultEnvelopeV2, StateStore, VerificationState, json,
    },
    read_execution::{ExecutedRead, credential_generation_for_read},
};
use cfctl_auth::ProfileKind;
use cfctl_cloudflare::farm_content_snapshot::PrivateFarmSnapshot;
use cfctl_core::farm_content_snapshot::{ACCOUNT_ID, CAPABILITY_ID, MAX_RESPONSE_BYTES};
use cfctl_storage::PrivateDirectory;
use sha2::{Digest as _, Sha256};
use std::{io::Write as _, path::Path};

fn rejected() -> CliError {
    CliError::Input("Farm snapshot requires the exact native contract, explicit matching account/API-token profile, no caller input, and a new private --out file; no private values disclosed".into())
}

pub(super) fn preflight(cap: &CapabilityV1, args: &CallArgs) -> Result<()> {
    if cap != &cfctl_catalog::farm_content_snapshot_capability()
        || args.account.as_deref() != Some(ACCOUNT_ID)
        || args.profile.is_none()
        || args.out.is_none()
        || args.value_out.is_some()
        || args.source_file.is_some()
        || args.credential_in.is_some()
        || !args.selectors.is_empty()
        || !args.query.is_empty()
        || args.body_stdin
        || args.body_json.is_some()
        || args.if_match.is_some()
        || args.if_none_match.is_some()
    {
        return Err(rejected());
    }
    private_target(args.out.as_deref().ok_or_else(rejected)?)?;
    Ok(())
}

fn private_target(path: &Path) -> Result<(PrivateDirectory, String)> {
    let parent = path.parent().ok_or_else(rejected)?;
    if !path.is_absolute() || parent.canonicalize().map_err(|_| rejected())? != parent {
        return Err(rejected());
    }
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(rejected)?;
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err(rejected()),
    }
    Ok((
        PrivateDirectory::open(parent).map_err(|_| rejected())?,
        name.to_owned(),
    ))
}

fn validate_profile(profile: &ProfileMetadata, requested_account: Option<&str>) -> Result<String> {
    if requested_account != Some(ACCOUNT_ID)
        || profile.account_id.as_deref() != Some(ACCOUNT_ID)
        || profile.kind != ProfileKind::ApiToken
        || profile.emergency_only
    {
        return Err(rejected());
    }
    credential_generation_for_read(profile)
}

pub(super) async fn execute(
    store: &StateStore,
    capability: &CapabilityV1,
    input: &CallInput,
    requested_profile: Option<&str>,
    requested_account: Option<&str>,
    output: Option<&Path>,
) -> Result<ExecutedRead> {
    if capability != &cfctl_catalog::farm_content_snapshot_capability()
        || requested_profile.is_none()
        || input.body.is_some()
        || input.if_match.is_some()
        || input.if_none_match.is_some()
        || !input
            .selectors
            .as_object()
            .is_some_and(serde_json::Map::is_empty)
        || !input
            .query
            .as_object()
            .is_some_and(serde_json::Map::is_empty)
    {
        return Err(rejected());
    }
    let (directory, name) = private_target(output.ok_or_else(rejected)?)?;
    let profiles = ProfilesConfig::load(store)?;
    let profile = profiles.selected(requested_profile)?;
    let generation = validate_profile(profile, requested_account)?;
    let credential = fresh_credential(profile, &platform_secrets(store)).await?;
    let executor = Executor::new(
        super::support::http_client()?,
        super::cloudflare_api::BASE_URL,
    )?;
    let snapshot = executor.read_farm_content_snapshot(&credential).await?;
    if ProfilesConfig::load(store)?.selected(requested_profile)? != profile {
        return Err(rejected());
    }
    let result = publish(&directory, &name, &snapshot)?;
    let evidence = store.write_observation_evidence(EvidenceClass::LiveRead, &result)?;
    let mut envelope = ResultEnvelopeV2::success("call", result).with_evidence(evidence);
    envelope.capability_id = Some(CAPABILITY_ID.into());
    envelope.account_id = Some(ACCOUNT_ID.into());
    envelope.profile_id = Some(profile.id.clone());
    envelope.performed = true;
    envelope.verification.state = VerificationState::Passed;
    envelope.verification.basis = Some("single fixed SQL read, complete ordered revision history and CAS agreement, same mode-0600 output bytes read back and hashed".into());
    Ok(ExecutedRead {
        envelope,
        credential_generation_id: Some(generation),
    })
}

fn publish(
    directory: &PrivateDirectory,
    name: &str,
    snapshot: &PrivateFarmSnapshot,
) -> Result<serde_json::Value> {
    let mut file = directory.create_new_file(name).map_err(|_| rejected())?;
    let result = (|| {
        file.write_all(snapshot.private_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|_| rejected())?;
        directory.sync().map_err(|_| rejected())?;
        let readback = directory
            .read(name, MAX_RESPONSE_BYTES)
            .map_err(|_| rejected())?
            .ok_or_else(rejected)?;
        if readback != snapshot.private_bytes() {
            return Err(rejected());
        }
        let mut metadata = snapshot.metadata();
        metadata["output_file"] = json!({"mode":"0600", "bytes":readback.len(),
            "sha256":format!("sha256:{}", hex::encode(Sha256::digest(&readback))), "hash_matches":true});
        Ok(metadata)
    })();
    if result.is_err() {
        let _ = directory.remove(name);
    }
    result
}

#[cfg(test)]
mod tests;
