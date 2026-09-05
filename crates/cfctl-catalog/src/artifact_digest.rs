//! Body-free provider artifact digest capabilities.
use super::{
    AdapterStatus, BTreeMap, CapabilityV1, EffectClass, R2_OBJECT_PATH,
    R2PrivateObjectDigestContractV1, ResponseBodyModeV1, ResponseContractV1, RiskClass,
    RollbackSpecV1, VerificationSpecV1, official_reference, zero_direct_usage_cost,
};

pub(super) fn finalize_worker_version_artifact_digest(
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    let Some(mut digest) = capabilities.get("getWorkerVersion").cloned() else {
        return;
    };
    if digest.method != "GET"
        || digest.path != cfctl_core::WORKER_VERSION_ARTIFACT_PATH
        || digest.mutating
        || digest.adapter_status != AdapterStatus::DynamicApi
        || !digest
            .selectors
            .iter()
            .any(|selector| selector.name == "include" && selector.location == "query")
    {
        return;
    }
    cfctl_core::WORKER_VERSION_ARTIFACT_DIGEST_ID.clone_into(&mut digest.id);
    "Read immutable Worker module digests without returning code".clone_into(&mut digest.title);
    digest.description = Some("Requires one full canonical version UUID; fetches include=modules inside cfctl and returns only a complete bounded module digest manifest. Source, sourcemaps, bindings and asset JWTs are never retained. Maximum 256 modules, 32 MiB decoded and 64 MiB response. Static asset bytes are not qualified.".to_owned());
    if let Some(version) = digest
        .selectors
        .iter_mut()
        .find(|selector| selector.name == "version_id")
    {
        version.description = Some(
            "One full canonical lowercase version UUID; prefixes and latest are rejected."
                .to_owned(),
        );
    }
    digest.permissions = vec!["Workers Scripts Read".to_owned()];
    digest.risk = RiskClass::Read;
    digest.effect = EffectClass::ReadOnly;
    digest.adapter_status = AdapterStatus::Native;
    digest.blocked_reason = None;
    digest.verification.required = true;
    "worker_version_artifact_digest".clone_into(&mut digest.verification.strategy);
    capabilities.insert(digest.id.clone(), digest);
}

pub(super) fn finalize_r2_private_object_digest_contract(
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    let Some(raw) = capabilities.get("r2-get-object").cloned() else {
        return;
    };
    let selectors_are_exact = ["account_id", "bucket_name", "object_key"]
        .iter()
        .all(|name| {
            raw.selectors.iter().any(|selector| {
                selector.name == *name
                    && selector.location == "path"
                    && selector.required
                    && selector.value_type == "string"
            })
        });
    let raw_supported = raw.method == "GET"
        && raw.path == R2_OBJECT_PATH
        && raw.product == "R2 Object"
        && !raw.mutating
        && raw.request_schema.is_none()
        && selectors_are_exact;
    if raw_supported {
        let mut digest = raw;
        "r2-get-private-object-digest".clone_into(&mut digest.id);
        "Read one private R2 object digest without returning bytes".clone_into(&mut digest.title);
        digest.description = Some(
            "Streams one exact private object only inside cfctl and returns bounded identity, ETag, byte count, and SHA-256 evidence; object bytes never enter stdout, plans, receipts, logs, or files."
                .to_owned(),
        );
        digest.permissions = vec!["Workers R2 Storage Read".to_owned()];
        digest.risk = RiskClass::Read;
        digest.effect = EffectClass::ReadOnly;
        digest.adapter_status = AdapterStatus::Native;
        digest.blocked_reason = None;
        digest.response_contract = Some(ResponseContractV1 {
            success_statuses: vec!["200".to_owned()],
            success_media_types: vec!["application/octet-stream".to_owned()],
            body_mode: ResponseBodyModeV1::R2PrivateObjectDigest,
        });
        digest.verification = VerificationSpecV1 {
            required: true,
            strategy: "r2_private_object_digest".to_owned(),
        };
        digest.rollback = RollbackSpecV1 {
            supported: false,
            strategy: None,
            warning: None,
        };
        digest.r2_private_file_upload = None;
        digest.r2_private_object_digest = Some(R2PrivateObjectDigestContractV1 {
            max_object_bytes: 300_000_000,
        });
        zero_direct_usage_cost(
            &mut digest,
            "the digest is one R2 Class B read with no direct configuration charge and never retains object bytes",
            vec![official_reference(
                "R2 pricing",
                "https://developers.cloudflare.com/r2/pricing/",
            )],
        );
        capabilities.insert(digest.id.clone(), digest);
    }
    if let Some(raw) = capabilities.get_mut("r2-get-object") {
        raw.adapter_status = AdapterStatus::Blocked;
        raw.blocked_reason = Some(
            "raw R2 object bytes are intentionally unavailable; use r2-get-private-object-digest for body-free identity evidence"
                .to_owned(),
        );
    }
}
