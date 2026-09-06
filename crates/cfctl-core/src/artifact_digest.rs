use crate::{CapabilityV1, EffectClass, ResponseBodyModeV1, RiskClass};
use serde::{Deserialize, Serialize};

/// Native body-free module identity for one immutable Worker version.
pub const WORKER_VERSION_ARTIFACT_DIGEST_ID: &str = "worker-version-artifact-digest";
pub const WORKER_VERSION_ARTIFACT_PATH: &str =
    "/accounts/{account_id}/workers/workers/{worker_id}/versions/{version_id}";

/// A bounded R2 object read whose bytes may exist only inside the executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct R2PrivateObjectDigestContractV1 {
    pub max_object_bytes: u64,
}

/// Body-free identity receipt for one exact private R2 object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct R2PrivateObjectDigestV1 {
    pub schema_version: u8,
    pub account_id: String,
    pub bucket_name: String,
    pub object_key: String,
    pub byte_count: u64,
    pub etag: String,
    pub sha256: String,
    pub body_returned: bool,
}

pub(super) fn verification_supported(capability: &CapabilityV1) -> bool {
    match capability.verification.strategy.as_str() {
        "worker_version_artifact_digest" => {
            capability.id == WORKER_VERSION_ARTIFACT_DIGEST_ID
                && capability.method == "GET"
                && capability.path == WORKER_VERSION_ARTIFACT_PATH
                && !capability.mutating
                && capability.risk == RiskClass::Read
                && capability.effect == EffectClass::ReadOnly
                && capability.permissions == ["Workers Scripts Read"]
                && capability.request_schema.is_none()
                && capability
                    .response_contract
                    .as_ref()
                    .is_some_and(|response| {
                        response.success_statuses == ["200"]
                            && response.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
                    })
        }
        "r2_private_object_digest" => {
            capability.id == "r2-get-private-object-digest"
                && capability.method == "GET"
                && capability.path
                    == "/accounts/{account_id}/r2/buckets/{bucket_name}/objects/{object_key}"
                && !capability.mutating
                && capability.risk == RiskClass::Read
                && capability.effect == EffectClass::ReadOnly
                && capability.permissions == ["Workers R2 Storage Read"]
                && capability.request_schema.is_none()
                && capability
                    .r2_private_object_digest
                    .as_ref()
                    .is_some_and(|contract| {
                        contract.max_object_bytes > 0 && contract.max_object_bytes <= 300_000_000
                    })
                && capability
                    .response_contract
                    .as_ref()
                    .is_some_and(|response| {
                        response.success_statuses == ["200"]
                            && response.body_mode == ResponseBodyModeV1::R2PrivateObjectDigest
                    })
        }
        _ => false,
    }
}
