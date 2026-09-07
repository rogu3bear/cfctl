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
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU32, Ordering};
use std::{collections::BTreeMap, fs::File, io::Write, time::Duration};
use uuid::Uuid;

/// Storage owns the private directory and descriptor-relative, create-only
/// files. The provider owns streaming and completeness, never path custody.
pub trait CaptureFiles {
    fn create_new(&self, name: &str) -> Result<File>;
    fn sync(&self) -> Result<()>;
}

#[derive(Default)]
pub struct CaptureProgress {
    requests: AtomicU32,
}
impl CaptureProgress {
    #[must_use]
    pub fn requests(&self) -> u32 {
        self.requests.load(Ordering::Relaxed)
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
        window.validate(Utc::now()).map_err(failure)?;
        // Compilation validates selectors and the closed input schema. The
        // window body is local context and never travels to Cloudflare.
        let request = self.builder.build_unchecked(capability, input)?;
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
        .map_err(|_| failure("private capture window exhausted; no complete receipt"))?
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
        let original = self
            .capture_r2_inventory(&list_url, credential, &mut pages, progress)
            .await?;
        let mut objects = Vec::new();
        let mut total_bytes = 0_u64;
        for (index, (key, metadata)) in original.iter().enumerate() {
            window.validate(Utc::now()).map_err(failure)?;
            let size = metadata["size"]
                .as_u64()
                .ok_or_else(|| failure("invalid private object size"))?;
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
            let object_url = self
                .builder
                .build_unchecked(&object_cap, &object_input)?
                .url;
            let response = self.capture_get(&object_url, credential, progress).await?;
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
            let mut file = files.create_new(&blob)?;
            let mut stream = response.bytes_stream();
            let mut count = 0_u64;
            let mut digest = Sha256::new();
            while let Some(chunk) = stream.next().await {
                let chunk =
                    chunk.map_err(|_| failure("private object stream failed; no replay"))?;
                count = count
                    .checked_add(chunk.len() as u64)
                    .filter(|n| *n <= size)
                    .ok_or_else(|| failure("private object exceeded its enumerated size"))?;
                digest.update(&chunk);
                file.write_all(&chunk).map_err(io_failure)?;
            }
            if count != size {
                return Err(failure("private object stream was incomplete"));
            }
            file.sync_all().map_err(io_failure)?;
            files.sync()?;
            objects.push(CapturedObjectV1 {
                provider_metadata: metadata.clone(),
                blob,
                sha256: hex::encode(digest.finalize()),
                byte_count: count,
            });
        }
        let final_inventory = self
            .capture_r2_inventory(&list_url, credential, &mut pages, progress)
            .await?;
        if original != final_inventory {
            return Err(failure(
                "private bucket population or metadata drifted during capture",
            ));
        }
        window.validate(Utc::now()).map_err(failure)?;
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
        let encoded = serde_json::to_vec(&manifest)
            .map_err(|_| failure("private manifest serialization failed"))?;
        if encoded.len() as u64 > contract::MAX_MANIFEST_BYTES {
            return Err(failure("private manifest byte budget exhausted"));
        }
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
        let outgoing = apply_credential(
            self.client
                .get(url.clone())
                .header(reqwest::header::ACCEPT_ENCODING, "identity")
                .timeout(Duration::from_mins(1)),
            credential,
        )?;
        progress.requests.fetch_add(1, Ordering::Relaxed);
        let response = outgoing
            .send()
            .await
            .map_err(|_| failure("private capture request failed; no replay"))?;
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
            let (body, truncated) = read_bounded_body(response, 2 * 1024 * 1024)
                .await
                .map_err(|_| failure("private enumeration response failed"))?;
            if truncated {
                return Err(failure(
                    "private enumeration response exceeded its byte bound",
                ));
            }
            let page: Value = serde_json::from_slice(&body)
                .map_err(|_| failure("invalid private enumeration response"))?;
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
                contract::validate_object(row).map_err(failure)?;
                let key = row["key"]
                    .as_str()
                    .ok_or_else(|| failure("private object key missing"))?;
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
            let info = &page["result_info"];
            if info["per_page"] != contract::PAGE_SIZE
                || info["delimited"].as_array().is_none_or(|d| !d.is_empty())
            {
                return Err(failure(
                    "private enumeration lacks unfiltered pagination evidence",
                ));
            }
            let next = info["cursor"]
                .as_str()
                .ok_or_else(|| failure("private enumeration cursor is missing"))?;
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
