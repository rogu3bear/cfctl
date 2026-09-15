//! Bounded private capture. A second complete listing detects observed drift;
//! it cannot establish writer exclusion or make REST replacement safe.
use super::{
    CallInput, CloudflareError, Executor, Result, apply_credential, exact_private_object_etag,
    read_bounded_body,
};
use cfctl_auth::AuthCredential;
use cfctl_core::{
    CapabilityV1, SelectorV1,
    r2_recovery::{
        self as contract, CaptureManifestV1, CaptureReceiptV1, CaptureWindowV1, CapturedObjectV1,
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
    ObjectRead,
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

    fn begin_request(&self) {
        self.update(|d| {
            d.request_ordinal += 1;
            d.provider_http_status = None;
            d.reason = CaptureReason::Transport;
        });
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

fn failure(message: &'static str) -> CloudflareError {
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
        files: &dyn CaptureFiles,
    ) -> Result<CaptureReceiptV1> {
        self.capture_private_r2_bucket_with_progress(
            capability,
            input,
            credential,
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
        let window: CaptureWindowV1 = serde_json::from_value(
            input
                .body
                .clone()
                .ok_or_else(|| failure("private capture window required"))?,
        )
        .map_err(|_| failure("invalid private capture window"))?;
        progress.expect(CaptureReason::WindowExpired);
        window.validate(Utc::now()).map_err(failure)?;
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
        files: &dyn CaptureFiles,
        window: CaptureWindowV1,
        list_url: url::Url,
        progress: &CaptureProgress,
    ) -> Result<CaptureReceiptV1> {
        let started_at = Utc::now();
        let mut pages = 0;
        progress.stage(CaptureStage::InitialInventory);
        let original = self
            .capture_r2_inventory(&list_url, credential, &mut pages, progress)
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
        let final_inventory = self
            .capture_r2_inventory(&list_url, credential, &mut pages, progress)
            .await?;
        progress.expect(CaptureReason::InventoryDrift);
        if original != final_inventory {
            return Err(failure(
                "private bucket population or metadata drifted during capture",
            ));
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
            list_pages: pages,
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
        let mut file = files.create_new("manifest.json")?;
        file.write_all(&encoded).map_err(io_failure)?;
        file.sync_all().map_err(io_failure)?;
        files.sync()?;
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
        progress.begin_request();
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

    async fn capture_r2_inventory(
        &self,
        base: &url::Url,
        credential: &AuthCredential,
        pages: &mut u32,
        progress: &CaptureProgress,
    ) -> Result<BTreeMap<String, Value>> {
        let mut objects = BTreeMap::new();
        let mut cursors = std::collections::BTreeSet::new();
        let mut cursor = String::new();
        let mut bytes = 0_u64;
        loop {
            progress.expect(CaptureReason::PaginationBounds);
            if *pages >= contract::MAX_PAGES {
                return Err(failure("private capture list-page budget exhausted"));
            }
            *pages += 1;
            let mut url = base.clone();
            url.query_pairs_mut()
                .append_pair("per_page", &contract::PAGE_SIZE.to_string());
            if !cursor.is_empty() {
                url.query_pairs_mut().append_pair("cursor", &cursor);
            }
            let response = self.capture_get(&url, credential, progress).await?;
            progress.expect(CaptureReason::BodyRead);
            let (body, truncated) = read_bounded_body(response, 2 * 1024 * 1024)
                .await
                .map_err(|_| failure("private enumeration response failed"))?;
            progress.expect(CaptureReason::BodyLimit);
            if truncated {
                return Err(failure(
                    "private enumeration response exceeded its byte bound",
                ));
            }
            progress.expect(CaptureReason::Json);
            let page: Value = serde_json::from_slice(&body)
                .map_err(|_| failure("invalid private enumeration response"))?;
            progress.expect(CaptureReason::Envelope);
            let rows = page["result"]
                .as_array()
                .ok_or_else(|| failure("private enumeration omitted its object population"))?;
            if page["success"] != true
                || page["errors"].as_array().is_none_or(|e| !e.is_empty())
                || rows.len() > contract::PAGE_SIZE as usize
            {
                return Err(failure("private enumeration response contract failed"));
            }
            for row in rows {
                progress.expect(CaptureReason::ObjectMetadata);
                contract::validate_object(row).map_err(failure)?;
                let key = row["key"]
                    .as_str()
                    .ok_or_else(|| failure("private object key missing"))?;
                progress.expect(CaptureReason::PopulationBounds);
                bytes = bytes
                    .checked_add(
                        row["size"]
                            .as_u64()
                            .ok_or_else(|| failure("private object size missing"))?,
                    )
                    .filter(|n| *n <= contract::MAX_BYTES)
                    .ok_or_else(|| failure("private capture byte budget exhausted"))?;
                if objects.insert(key.into(), row.clone()).is_some()
                    || objects.len() > contract::MAX_OBJECTS
                {
                    return Err(failure(
                        "private enumeration repeated a key or exceeded its population bound",
                    ));
                }
            }
            progress.expect(CaptureReason::PaginationMetadata);
            let info = &page["result_info"];
            if info["per_page"] != contract::PAGE_SIZE
                || info["delimited"].as_array().is_none_or(|d| !d.is_empty())
            {
                return Err(failure(
                    "private enumeration lacks unfiltered pagination evidence",
                ));
            }
            progress.expect(CaptureReason::PaginationCursor);
            let next = info["cursor"]
                .as_str()
                .ok_or_else(|| failure("private enumeration cursor is missing"))?;
            progress.expect(CaptureReason::PaginationTerminal);
            match info["is_truncated"].as_bool() {
                Some(false) if next.is_empty() => return Ok(objects),
                Some(true)
                    if !next.is_empty()
                        && next.len() <= 8192
                        && cursors.insert(next.to_owned()) =>
                {
                    cursor = next.into();
                }
                _ => {
                    return Err(failure(
                        "private enumeration lacks terminal evidence or repeats a cursor",
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
