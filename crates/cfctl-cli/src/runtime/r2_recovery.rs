//! Native private capture storage and authenticated local revalidation.
use super::{CliError, Result};
use cfctl_cloudflare::{
    CallInput, CloudflareError, CloudflareResponseV1, Executor,
    r2_recovery::{CaptureFiles, CaptureProgress, CaptureReason, CaptureStage},
};
use cfctl_core::{
    CapabilityV1, EvidenceClass, OperationalProofOutcomeV1, ResultEnvelopeV2, VerificationState,
    hash_value,
    r2_recovery::{self as contract, CaptureManifestV1, CaptureReceiptV1},
};
use cfctl_storage::{PrivateDirectory, StateStore};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    path::{Component, Path},
};

struct CaptureDirectory(PrivateDirectory, PrivateDirectory);

fn private_failure() -> CloudflareError {
    CloudflareError::InvalidRequestBody("private capture requires a fresh owned mode-0700 directory and immutable mode-0600 files; no private value was disclosed".into())
}

impl CaptureFiles for CaptureDirectory {
    fn create_new(&self, name: &str) -> cfctl_cloudflare::Result<fs::File> {
        self.1.sync().map_err(|_| private_failure())?;
        self.0.create_new_file(name).map_err(|_| private_failure())
    }
    fn sync(&self) -> cfctl_cloudflare::Result<()> {
        self.1.sync().map_err(|_| private_failure())?;
        self.0.sync().map_err(|_| private_failure())
    }
}

pub(super) async fn capture(
    executor: &Executor,
    capability: &CapabilityV1,
    input: &CallInput,
    credential: &cfctl_auth::AuthCredential,
    path: &Path,
) -> Result<CloudflareResponseV1> {
    preflight_capture(capability, input, path)?;
    let parent = path.parent().ok_or_else(private_failure)?;
    // The owner selects an existing protected custody root. This command does
    // not create a destination, change its permissions, or grant retention.
    let parent = PrivateDirectory::open(parent).map_err(|_| private_failure())?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(private_failure)?;
    let child = parent
        .create_new_directory(name)
        .map_err(|_| private_failure())?;
    let files = CaptureDirectory(child, parent);
    let progress = cfctl_cloudflare::r2_recovery::CaptureProgress::default();
    let captured = executor
        .capture_private_r2_bucket_with_progress(capability, input, credential, &files, &progress)
        .await;
    let checked = captured.map_err(CliError::from).and_then(|receipt| {
        progress.stage(CaptureStage::LocalVerification);
        progress.expect(CaptureReason::LocalIntegrity);
        verify_private_files(&files.0, &receipt)?;
        progress.expect(CaptureReason::WindowExpired);
        receipt.window.validate(chrono::Utc::now()).map_err(|_| {
            CliError::Input("private capture verification exceeded its window".into())
        })?;
        Ok(receipt)
    });
    match checked {
        Ok(receipt) => Ok(CloudflareResponseV1 {
            status: 200,
            success: true,
            result: serde_json::to_value(receipt)?,
            errors: vec![],
            result_info: None,
            etag: None,
            cf_ray: None,
        }),
        Err(error) if progress.requests() == 0 => Err(error),
        Err(_) => Ok(incomplete_response(&progress)),
    }
}

fn incomplete_response(progress: &CaptureProgress) -> CloudflareResponseV1 {
    CloudflareResponseV1 {
        // The native operation has no single provider response. Real status, if
        // observed, is tied to its request ordinal in the diagnostic below.
        status: 0,
        success: false,
        result: json!({"capture_complete":false, "body_returned":false, "recovery_ready":false,
            "attempted_provider_requests":progress.requests(), "diagnostic":"private_capture_incomplete",
            "status_is_provider_response":false, "failure":progress.diagnostic(),
            "next_action":"preserve private partial files; inspect the window, bounds and provider contract before a separately admitted attempt"}),
        errors: vec![],
        result_info: None,
        etag: None,
        cf_ray: None,
    }
}

pub(super) fn preflight_capture(
    cap: &CapabilityV1,
    input: &CallInput,
    path: &Path,
) -> Result<contract::CaptureWindowV1> {
    if !contract::capability_matches(cap) {
        return Err(private_failure().into());
    }
    cfctl_cloudflare::validate_request_contract(cap, input)?;
    let window: contract::CaptureWindowV1 =
        serde_json::from_value(input.body.clone().ok_or_else(private_failure)?)
            .map_err(|_| private_failure())?;
    window
        .validate(chrono::Utc::now())
        .map_err(|_| CliError::Input("invalid or expired private capture window".into()))?;
    normalized_private_path(path)?;
    Ok(window)
}

fn normalized_private_path(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
        || path
            .parent()
            .is_none_or(|p| p.canonicalize().ok().as_deref() != Some(p))
    {
        return Err(private_failure().into());
    }
    Ok(())
}

fn verify_private_files(directory: &PrivateDirectory, receipt: &CaptureReceiptV1) -> Result<()> {
    let rejected = || {
        CliError::Input("private capture integrity failed; no private value was disclosed".into())
    };
    let encoded = directory
        .read("manifest.json", contract::MAX_MANIFEST_BYTES)
        .map_err(|_| rejected())?
        .ok_or_else(rejected)?;
    let hash = hex::encode(Sha256::digest(&encoded));
    if hash != receipt.manifest_sha256 {
        return Err(rejected());
    }
    let manifest: CaptureManifestV1 = serde_json::from_slice(&encoded).map_err(|_| rejected())?;
    if manifest.receipt(hash) != *receipt
        || manifest.schema_version != 1
        || manifest.objects.len() > contract::MAX_OBJECTS
        || manifest.total_bytes > contract::MAX_BYTES
        || !(2..=contract::MAX_PAGES).contains(&manifest.list_pages)
        || manifest.started_at < manifest.window.opened_at
        || manifest.completed_at < manifest.started_at
        || manifest.completed_at >= manifest.window.expires_at
    {
        return Err(rejected());
    }
    manifest
        .window
        .validate(manifest.started_at)
        .map_err(|_| rejected())?;
    let mut keys = BTreeSet::new();
    let mut total = 0_u64;
    for (index, object) in manifest.objects.iter().enumerate() {
        contract::validate_object(&object.provider_metadata).map_err(|_| rejected())?;
        if object.blob != format!("object-{index:04}.bin")
            || !contract::is_sha256(&object.sha256)
            || !keys.insert(
                object.provider_metadata["key"]
                    .as_str()
                    .ok_or_else(rejected)?,
            )
            || object.provider_metadata["size"].as_u64() != Some(object.byte_count)
        {
            return Err(rejected());
        }
        total = total
            .checked_add(object.byte_count)
            .filter(|n| *n <= contract::MAX_BYTES)
            .ok_or_else(rejected)?;
        let bytes = directory
            .read(&object.blob, object.byte_count)
            .map_err(|_| rejected())?
            .ok_or_else(rejected)?;
        if bytes.len() as u64 != object.byte_count
            || hex::encode(Sha256::digest(&bytes)) != object.sha256
        {
            return Err(rejected());
        }
    }
    if total != manifest.total_bytes {
        return Err(rejected());
    }
    directory.sync().map_err(|_| rejected())?;
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyInput {
    capture_evidence_hash: String,
    capture_run_id: String,
}

pub(super) fn verify(
    store: &StateStore,
    capability: &CapabilityV1,
    input: &CallInput,
    path: &Path,
) -> Result<ResultEnvelopeV2> {
    cfctl_cloudflare::validate_request_contract(capability, input)?;
    let rejected = || {
        CliError::Input("capture verification requires the exact authenticated successful native capture and matching private files".into())
    };
    if capability.id != contract::VERIFY_ID
        || !contract::capability_matches(capability)
        || input.if_match.is_some()
        || input.if_none_match.is_some()
        || input.query.as_object().is_none_or(|q| !q.is_empty())
        || input.selectors.as_object().is_none_or(|s| s.len() != 2)
    {
        return Err(rejected());
    }
    let request: VerifyInput =
        serde_json::from_value(input.body.clone().ok_or_else(rejected)?).map_err(|_| rejected())?;
    let evidence = store.read_evidence_value(&request.capture_evidence_hash)?;
    if evidence["success"] != true || evidence["status"] != 200 {
        return Err(rejected());
    }
    let receipt: CaptureReceiptV1 =
        serde_json::from_value(evidence["result"].clone()).map_err(|_| rejected())?;
    if receipt.run_id != request.capture_run_id
        || input.selectors["account_id"] != receipt.account_id
        || input.selectors["bucket_name"] != receipt.bucket_name
    {
        return Err(rejected());
    }
    let original_input = CallInput {
        selectors: input.selectors.clone(),
        query: json!({}),
        body: Some(serde_json::to_value(&receipt.window)?),
        ..CallInput::default()
    };
    let input_hash = hash_value(&serde_json::to_value(original_input)?)?;
    let proofs = store.list_operational_proofs()?;
    let matching = proofs
        .iter()
        .filter(|p| {
            p.capability_id == contract::CAPTURE_ID
                && p.evidence.content_hash == request.capture_evidence_hash
                && p.evidence.class == EvidenceClass::LiveRead
                && p.outcome == OperationalProofOutcomeV1::Succeeded
                && p.input_hash == input_hash
                && p.account_id.as_deref() == Some(receipt.account_id.as_str())
                && p.profile_id.is_some()
                && p.credential_generation_id.is_some()
                && p.build_identity_hash.is_some()
                && p.observed_at >= receipt.completed_at
        })
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err(rejected());
    }
    normalized_private_path(path)?;
    let directory = PrivateDirectory::open(path).map_err(|_| private_failure())?;
    verify_private_files(&directory, &receipt)?;
    let proof = matching[0];
    let mut envelope = ResultEnvelopeV2::success(
        "call",
        json!({
            "schema_version":1, "qualification":"authenticated_capture_integrity",
            "capture":receipt, "capture_evidence_hash":request.capture_evidence_hash,
            "catalog_hash":proof.catalog_hash, "build_identity_hash":proof.build_identity_hash,
            "credential_generation_id":proof.credential_generation_id,
            "provider_requests":0, "writer_exclusion_qualified":false,
            "d1_recovery_qualified":false, "retention_qualified":false,
            "conditional_restore_qualified":false, "recovery_ready":false
        }),
    )
    .with_evidence(proof.evidence.clone());
    envelope.capability_id = Some(contract::VERIFY_ID.into());
    envelope.account_id.clone_from(&proof.account_id);
    envelope.profile_id.clone_from(&proof.profile_id);
    envelope.verification.state = VerificationState::Passed;
    envelope.verification.basis = Some("authenticated native capture provenance and same private manifest/object bytes; capture integrity only".into());
    Ok(envelope)
}

#[cfg(test)]
#[path = "r2_recovery_tests.rs"]
mod tests;
