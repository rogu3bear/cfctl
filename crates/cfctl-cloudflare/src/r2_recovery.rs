//! Bounded private capture. A second complete listing detects observed drift;
//! it cannot establish writer exclusion or make REST replacement safe.
use super::{
    CallInput, CloudflareError, Executor, Result, apply_credential, exact_private_object_etag,
};
use cfctl_auth::AuthCredential;
use cfctl_core::{
    CapabilityV1, SelectorV1,
    r2_recovery::{
        self as contract, CaptureManifestV1, CaptureReceiptV1, CaptureRequestV2, CaptureWindowV1,
        CapturedObjectV1,
    },
};
use chrono::Utc;
use futures_util::StreamExt;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use std::{collections::BTreeMap, fs::File, io::Write, time::Duration};
use uuid::Uuid;

mod inventory;
mod s3_inventory;

/// Storage owns the private directory and descriptor-relative, create-only
/// files. The provider owns streaming and completeness, never path custody.
pub trait CaptureFiles {
    fn create_new(&self, name: &str) -> Result<File>;
    fn sync(&self) -> Result<()>;
}

/// Closed diagnostic vocabulary. Provider strings and private values cannot enter it.
#[derive(Clone, Copy, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureStage {
    #[default]
    Preflight,
    InitialInventory,
    InitialMetadata,
    ObjectRead,
    FinalMetadata,
    FinalInventory,
    Manifest,
    LocalVerification,
}

#[derive(Clone, Copy, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureReason {
    #[default]
    RequestContract,
    Transport,
    HttpResponse,
    BodyRead,
    BodyLimit,
    Json,
    Xml,
    RequestBounds,
    Envelope,
    ObjectMetadata,
    PopulationBounds,
    PaginationBounds,
    PaginationMetadata,
    PaginationCursor,
    PaginationTerminal,
    ObjectIdentity,
    ObjectSize,
    Storage,
    InventoryDrift,
    WindowExpired,
    ManifestEncoding,
    ManifestBounds,
    LocalIntegrity,
}

#[derive(Clone, Copy, Default, Serialize)]
pub struct CaptureDiagnosticV1 {
    pub stage: CaptureStage,
    pub reason: CaptureReason,
    pub request_ordinal: u32,
    /// Actual HTTP status of this request, if headers were received. Never synthetic.
    pub provider_http_status: Option<u16>,
}

#[derive(Default)]
pub struct CaptureProgress {
    diagnostic: Mutex<CaptureDiagnosticV1>,
}
impl CaptureProgress {
    fn update(&self, update: impl FnOnce(&mut CaptureDiagnosticV1)) {
        // A poisoned diagnostic must not hide the original capture failure.
        update(
            &mut self
                .diagnostic
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
    }

    pub fn stage(&self, stage: CaptureStage) {
        self.update(|d| d.stage = stage);
    }

    /// Set immediately before a fallible operation; only failed captures expose it.
    pub fn expect(&self, reason: CaptureReason) {
        self.update(|d| d.reason = reason);
    }

    fn begin_request(&self) -> Result<()> {
        self.expect(CaptureReason::RequestBounds);
        if self.requests() >= contract::MAX_REQUESTS {
            return Err(failure("private capture request budget exhausted"));
        }
        self.update(|d| {
            d.request_ordinal += 1;
            d.provider_http_status = None;
            d.reason = CaptureReason::Transport;
        });
        Ok(())
    }

    fn observed_status(&self, status: u16) {
        self.update(|d| d.provider_http_status = Some(status));
    }

    #[must_use]
    pub fn diagnostic(&self) -> CaptureDiagnosticV1 {
        *self
            .diagnostic
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[must_use]
    pub fn requests(&self) -> u32 {
        self.diagnostic().request_ordinal
    }
}

pub(crate) fn failure(message: &'static str) -> CloudflareError {
    CloudflareError::InvalidRequestBody(message.into())
}

fn io_failure(_: std::io::Error) -> CloudflareError {
    failure("private capture could not be durably written; no complete receipt")
}

impl Executor {
    pub async fn capture_private_r2_bucket(
        &self,
        capability: &CapabilityV1,
        input: &CallInput,
        credential: &AuthCredential,
        token_id: &str,
        files: &dyn CaptureFiles,
    ) -> Result<CaptureReceiptV1> {
        self.capture_private_r2_bucket_with_progress(
            capability,
            input,
            credential,
            token_id,
            files,
            &CaptureProgress::default(),
        )
        .await
    }

    pub async fn capture_private_r2_bucket_with_progress(
        &self,
        capability: &CapabilityV1,
        input: &CallInput,
        credential: &AuthCredential,
        token_id: &str,
        files: &dyn CaptureFiles,
        progress: &CaptureProgress,
    ) -> Result<CaptureReceiptV1> {
        if capability.id != contract::CAPTURE_ID
            || capability.verification.strategy != "r2_private_capture"
            || !contract::capability_matches(capability)
            || input.if_match.is_some()
            || input.if_none_match.is_some()
            || input.selectors.as_object().is_none_or(|s| s.len() != 2)
            || input.query.as_object().is_none_or(|s| !s.is_empty())
        {
            return Err(failure("private R2 capture contract or input drifted"));
        }
        let request: CaptureRequestV2 = serde_json::from_value(
            input
                .body
                .clone()
                .ok_or_else(|| failure("private capture version 2 request required"))?,
        )
        .map_err(|_| {
            failure("private capture requires version 2 window and token evidence hashes")
        })?;
        progress.expect(CaptureReason::WindowExpired);
        request.validate(Utc::now()).map_err(failure)?;
        if token_id.len() != 32
            || !token_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(failure(
                "private capture requires qualified current token identity",
            ));
        }
        let window = request.window;
        // Compilation validates selectors and the closed input schema. The
        // window body is local context and never travels to Cloudflare.
        progress.expect(CaptureReason::RequestContract);
        let request = self.builder.build_unchecked(capability, input)?;
        progress.expect(CaptureReason::WindowExpired);
        let remaining = (window.expires_at - Utc::now())
            .to_std()
            .map_err(|_| failure("private capture window expired"))?;
        tokio::time::timeout(
            remaining,
            self.capture_r2_window(
                capability,
                input,
                credential,
                token_id,
                files,
                window,
                request.url,
                progress,
            ),
        )
        .await
        .map_err(|_| {
            progress.expect(CaptureReason::WindowExpired);
            failure("private capture window exhausted; no complete receipt")
        })?
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "one exact capture binds input, credential, private sink, window, URL and attempt accounting"
    )]
    #[expect(
        clippy::too_many_lines,
        reason = "the private stream, shared budgets, before/after inventory and final durable manifest form one auditable capture boundary"
    )]
    async fn capture_r2_window(
        &self,
        capability: &CapabilityV1,
        input: &CallInput,
        credential: &AuthCredential,
        token_id: &str,
        files: &dyn CaptureFiles,
        window: CaptureWindowV1,
        list_url: url::Url,
        progress: &CaptureProgress,
    ) -> Result<CaptureReceiptV1> {
        let started_at = Utc::now();
        let mut budget = inventory::Budget::default();
        let account = input.selectors["account_id"]
            .as_str()
            .ok_or_else(|| failure("missing account"))?;
        let bucket = input.selectors["bucket_name"]
            .as_str()
            .ok_or_else(|| failure("missing bucket"))?;
        let transport = self.private_r2_transport();
        let context = inventory::InventoryContext {
            transport: &transport,
            account,
            bucket,
            token_id,
            credential,
            progress,
        };
        progress.stage(CaptureStage::InitialInventory);
        let initial = context.read(&mut budget).await?;
        progress.stage(CaptureStage::InitialMetadata);
        let original = self
            .capture_metadata(&list_url, credential, &initial, &mut budget, progress)
            .await?;
        let mut objects = Vec::new();
        let mut total_bytes = 0_u64;
        for (index, (key, metadata)) in original.iter().enumerate() {
            progress.stage(CaptureStage::ObjectRead);
            progress.expect(CaptureReason::WindowExpired);
            window.validate(Utc::now()).map_err(failure)?;
            progress.expect(CaptureReason::ObjectMetadata);
            let size = metadata["size"]
                .as_u64()
                .ok_or_else(|| failure("invalid private object size"))?;
            progress.expect(CaptureReason::PopulationBounds);
            total_bytes = total_bytes
                .checked_add(size)
                .filter(|s| *s <= contract::MAX_BYTES)
                .ok_or_else(|| failure("private capture aggregate byte budget exhausted"))?;
            let mut object_cap = capability.clone();
            object_cap.path = format!(
                "{}/{object_key}",
                contract::OBJECTS_PATH,
                object_key = "{object_key}"
            );
            object_cap.request_schema = None;
            object_cap.selectors.push(SelectorV1 {
                name: "object_key".into(),
                location: "path".into(),
                required: true,
                value_type: "string".into(),
                description: None,
                contract: None,
            });
            let mut object_input = input.clone();
            object_input.body = None;
            object_input.selectors["object_key"] = json!(key);
            progress.expect(CaptureReason::RequestContract);
            let object_url = self
                .builder
                .build_unchecked(&object_cap, &object_input)?
                .url;
            let response = self.capture_get(&object_url, credential, progress).await?;
            progress.expect(CaptureReason::ObjectIdentity);
            let etag = exact_private_object_etag(response.headers())?;
            if etag
                != format!(
                    "\"{}\"",
                    metadata["etag"]
                        .as_str()
                        .ok_or_else(|| failure("missing private object ETag"))?
                )
                || response.content_length().is_some_and(|n| n != size)
            {
                return Err(failure("private object identity drifted from enumeration"));
            }
            let blob = format!("object-{index:04}.bin");
            progress.expect(CaptureReason::Storage);
            let mut file = files.create_new(&blob)?;
            let mut stream = response.bytes_stream();
            let mut count = 0_u64;
            let mut digest = Sha256::new();
            loop {
                progress.expect(CaptureReason::BodyRead);
                let Some(chunk) = stream.next().await else {
                    break;
                };
                let chunk =
                    chunk.map_err(|_| failure("private object stream failed; no replay"))?;
                progress.expect(CaptureReason::ObjectSize);
                count = count
                    .checked_add(chunk.len() as u64)
                    .filter(|n| *n <= size)
                    .ok_or_else(|| failure("private object exceeded its enumerated size"))?;
                digest.update(&chunk);
                progress.expect(CaptureReason::Storage);
                file.write_all(&chunk).map_err(io_failure)?;
            }
            progress.expect(CaptureReason::ObjectSize);
            if count != size {
                return Err(failure("private object stream was incomplete"));
            }
            progress.expect(CaptureReason::Storage);
            file.sync_all().map_err(io_failure)?;
            files.sync()?;
            objects.push(CapturedObjectV1 {
                provider_metadata: metadata.clone(),
                blob,
                sha256: hex::encode(digest.finalize()),
                byte_count: count,
            });
        }
        progress.stage(CaptureStage::FinalInventory);
        let final_inventory = context.read(&mut budget).await?;
        progress.expect(CaptureReason::InventoryDrift);
        if initial != final_inventory {
            return Err(failure(
                "private bucket population or identity drifted during capture",
            ));
        }
        progress.stage(CaptureStage::FinalMetadata);
        let final_metadata = self
            .capture_metadata(
                &list_url,
                credential,
                &final_inventory,
                &mut budget,
                progress,
            )
            .await?;
        progress.expect(CaptureReason::InventoryDrift);
        if original != final_metadata {
            return Err(failure("private object metadata drifted during capture"));
        }
        progress.expect(CaptureReason::WindowExpired);
        window.validate(Utc::now()).map_err(failure)?;
        progress.stage(CaptureStage::Manifest);
        progress.expect(CaptureReason::RequestContract);
        let manifest = CaptureManifestV1 {
            schema_version: 1,
            run_id: Uuid::new_v4().to_string(),
            account_id: input.selectors["account_id"]
                .as_str()
                .ok_or_else(|| failure("missing capture account"))?
                .into(),
            bucket_name: input.selectors["bucket_name"]
                .as_str()
                .ok_or_else(|| failure("missing capture bucket"))?
                .into(),
            window,
            started_at,
            completed_at: Utc::now(),
            list_pages: budget.pages,
            total_bytes,
            objects,
        };
        progress.expect(CaptureReason::ManifestEncoding);
        let encoded = serde_json::to_vec(&manifest)
            .map_err(|_| failure("private manifest serialization failed"))?;
        progress.expect(CaptureReason::ManifestBounds);
        if encoded.len() as u64 > contract::MAX_MANIFEST_BYTES {
            return Err(failure("private manifest byte budget exhausted"));
        }
        progress.expect(CaptureReason::Storage);
        // The v1 manifest stays unchanged. This private companion reconstructs
        // the exact v2 input hash for authenticated historical verification.
        let request = serde_json::to_vec(&input.body)
            .map_err(|_| failure("private request encoding failed"))?;
        if request.len() as u64 > contract::MAX_REQUEST_BYTES {
            return Err(failure("private request bound exceeded"));
        }
        let mut request_file = files.create_new("request.json")?;
        request_file.write_all(&request).map_err(io_failure)?;
        request_file.sync_all().map_err(io_failure)?;
        let mut file = files.create_new("manifest.json")?;
        file.write_all(&encoded).map_err(io_failure)?;
        file.sync_all().map_err(io_failure)?;
        files.sync()?;
        progress.expect(CaptureReason::WindowExpired);
        manifest.window.validate(Utc::now()).map_err(failure)?;
        Ok(manifest.receipt(hex::encode(Sha256::digest(&encoded))))
    }

    async fn capture_get(
        &self,
        url: &url::Url,
        credential: &AuthCredential,
        progress: &CaptureProgress,
    ) -> Result<reqwest::Response> {
        progress.expect(CaptureReason::RequestContract);
        let outgoing = apply_credential(
            self.client
                .get(url.clone())
                .header(reqwest::header::ACCEPT_ENCODING, "identity")
                .timeout(Duration::from_mins(1)),
            credential,
        )?;
        progress.begin_request()?;
        let response = outgoing
            .send()
            .await
            .map_err(|_| failure("private capture request failed; no replay"))?;
        progress.observed_status(response.status().as_u16());
        progress.expect(CaptureReason::HttpResponse);
        if response.status().as_u16() != 200 || response.url() != url {
            return Err(failure(
                "private capture request did not return an exact HTTP 200; no replay",
            ));
        }
        Ok(response)
    }

    async fn capture_metadata(
        &self,
        base: &url::Url,
        credential: &AuthCredential,
        inventory: &BTreeMap<String, s3_inventory::Object>,
        budget: &mut inventory::Budget,
        progress: &CaptureProgress,
    ) -> Result<BTreeMap<String, Value>> {
        let mut records = BTreeMap::new();
        let mut retained = 0_u64;
        for (key, identity) in inventory {
            progress.expect(CaptureReason::BodyLimit);
            if budget.metadata_bytes >= contract::MAX_METADATA_BYTES {
                return Err(failure("private metadata byte budget exhausted"));
            }
            let url = crate::r2_metadata::member_url(base, key);
            let response = self.capture_get(&url, credential, progress).await?;
            let body = inventory::bounded_response(
                response,
                &mut budget.metadata_bytes,
                contract::MAX_METADATA_BYTES,
                progress,
            )
            .await?;
            progress.expect(CaptureReason::Json);
            let value = crate::r2_metadata::strict_json(&body)
                .map_err(|_| failure("invalid private metadata JSON"))?;
            progress.expect(CaptureReason::ObjectMetadata);
            let record = crate::r2_metadata::exact_member(&value, key)?;
            progress.expect(CaptureReason::ObjectIdentity);
            if !identity.matches(&record) {
                return Err(failure("S3 and REST object identities disagree"));
            }
            progress.expect(CaptureReason::ManifestBounds);
            retained = retained
                .checked_add(
                    serde_json::to_vec(&record)
                        .map_err(|_| failure("private metadata encoding failed"))?
                        .len() as u64,
                )
                .filter(|n| *n <= contract::MAX_MANIFEST_BYTES)
                .ok_or_else(|| failure("private metadata retention budget exhausted"))?;
            records.insert(key.clone(), record);
        }
        Ok(records)
    }
}

#[cfg(test)]
mod tests;
