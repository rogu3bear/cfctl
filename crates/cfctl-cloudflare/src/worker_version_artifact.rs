//! Hash immutable Worker modules before any response can become durable evidence.
use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use cfctl_core::{CapabilityV1, WORKER_VERSION_ARTIFACT_DIGEST_ID, WORKER_VERSION_ARTIFACT_PATH};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{AuthCredential, CallInput, CloudflareError, CloudflareResponseV1, Executor, Result};

const MAX_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_MODULE_BYTES: usize = 32 * 1024 * 1024;
const MAX_MODULES: usize = 256;

fn invalid() -> CloudflareError {
    CloudflareError::InvalidRequestBody("Worker artifact digest requires an exact immutable version and a complete bounded module response".to_owned())
}

fn canonical_version(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| id.to_string() == value)
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

impl Executor {
    pub(super) async fn execute_worker_version_artifact_digest(
        &self,
        capability: &CapabilityV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<CloudflareResponseV1> {
        if capability.id != WORKER_VERSION_ARTIFACT_DIGEST_ID
            || capability.path != WORKER_VERSION_ARTIFACT_PATH
            || capability.method != "GET"
            || capability.mutating
            || capability.risk != cfctl_core::RiskClass::Read
            || capability.effect != cfctl_core::EffectClass::ReadOnly
            || capability.permissions != ["Workers Scripts Read"]
            || capability.verification.strategy != "worker_version_artifact_digest"
            || !capability.verification_contract_supported()
            || input.body.is_some()
            || input.if_match.is_some()
            || input.if_none_match.is_some()
        {
            return Err(invalid());
        }
        let selectors = input.selectors.as_object().ok_or_else(invalid)?;
        if selectors.len() != 3
            || !["account_id", "worker_id", "version_id"].iter().all(|key| {
                selectors
                    .get(*key)
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.is_empty())
            })
        {
            return Err(invalid());
        }
        let version = selectors["version_id"].as_str().ok_or_else(invalid)?;
        if !canonical_version(version) {
            return Err(invalid());
        }
        let query = input.query.as_object().ok_or_else(invalid)?;
        if query
            .iter()
            .any(|(key, value)| key != "include" || value.as_str() != Some("modules"))
        {
            return Err(invalid());
        }
        let mut exact = input.clone();
        exact.query = json!({"include":"modules"});
        let mut request = self.builder.build(capability, &exact)?;
        request.max_bytes = MAX_RESPONSE_BYTES;
        let mut response = self.send(&request, credential).await?;
        let projection = if response.success && response.status == 200 && response.errors.is_empty()
        {
            project(&response.result, version)
        } else {
            Err(invalid())
        };
        // Discard the entire provider value, including vars, bindings, JWTs and code,
        // on success and failure alike. Never include its text in a diagnostic.
        response.result = projection.unwrap_or_else(|_| {
            json!({
                "schema_version":1, "complete":false, "body_returned":false,
                "diagnostic":"worker_module_projection_rejected"
            })
        });
        response.success = response.success && response.result["complete"] == true;
        response.errors.clear();
        response.result_info = None;
        Ok(response)
    }
}

fn project(value: &Value, expected_version: &str) -> Result<Value> {
    if !canonical_version(expected_version) || value["id"].as_str() != Some(expected_version) {
        return Err(invalid());
    }
    let main = value["main_module"].as_str().ok_or_else(invalid)?;
    let modules = value["modules"].as_array().ok_or_else(invalid)?;
    if modules.is_empty() || modules.len() > MAX_MODULES {
        return Err(invalid());
    }
    let mut entries = BTreeMap::new();
    let mut total = 0_usize;
    for module in modules {
        let name = module["name"].as_str().ok_or_else(invalid)?;
        let content_type = module["content_type"].as_str().ok_or_else(invalid)?;
        let encoded = module["content_base64"].as_str().ok_or_else(invalid)?;
        if name.is_empty()
            || name.len() > 512
            || name.starts_with('/')
            || name.contains('\\')
            || name.chars().any(char::is_control)
            || name
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || content_type.is_empty()
            || content_type.len() > 128
            || !content_type.is_ascii()
            || content_type.chars().any(char::is_control)
            || entries.contains_key(name)
            || encoded.len() > MAX_MODULE_BYTES * 4 / 3 + 4
        {
            return Err(invalid());
        }
        let bytes = STANDARD.decode(encoded).map_err(|_| invalid())?;
        if STANDARD.encode(&bytes) != encoded {
            return Err(invalid());
        }
        total = total.checked_add(bytes.len()).ok_or_else(invalid)?;
        if total > MAX_MODULE_BYTES {
            return Err(invalid());
        }
        entries.insert(
            name.to_owned(),
            json!({
                "name":name, "content_type":content_type,
                "byte_count":bytes.len(), "sha256":digest(&bytes)
            }),
        );
    }
    if !entries.contains_key(main) {
        return Err(invalid());
    }
    let manifest = json!({"schema_version":1,"main_module":main,
        "modules":entries.into_values().collect::<Vec<_>>()});
    let bytes = serde_json::to_vec(&manifest).map_err(|_| invalid())?;
    Ok(json!({
        "schema_version":1,"version_id":expected_version,"complete":true,
        "body_returned":false,"provider_output_retained":false,
        "module_count":modules.len(),"byte_count":total,
        "manifest_sha256":digest(&bytes),"manifest":manifest,
        "static_asset_bytes_verified":false
    }))
}

#[cfg(test)]
mod tests;
