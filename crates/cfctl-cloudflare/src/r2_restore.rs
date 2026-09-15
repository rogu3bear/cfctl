//! One conditional object write, with private before/after observations.
use super::r2_s3::{S3Target, S3Transport, rejected};
use super::{
    CallInput, CloudflareResponseV1, Executor, OperationVerificationV1, Result, apply_credential,
    read_bounded_body,
};
use cfctl_auth::AuthCredential;
use cfctl_core::{
    PlanStatus, PlanV1, TransactionStageV1, hash_value,
    r2_restore::{self as contract, RestoreSelectionV1, semantic_headers},
};
use chrono::Utc;
use futures_util::StreamExt;
use reqwest::Method;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
    time::Duration,
};
use url::Url;

#[derive(Default)]
pub struct RestoreProgress {
    requests: AtomicU32,
    put_attempted: AtomicBool,
}
impl RestoreProgress {
    #[must_use]
    pub fn requests(&self) -> u32 {
        self.requests.load(Ordering::Relaxed)
    }
    #[must_use]
    pub fn put_attempted(&self) -> bool {
        self.put_attempted.load(Ordering::Relaxed)
    }
    fn request(&self) -> Result<()> {
        if self.requests.fetch_add(1, Ordering::Relaxed) >= 5 {
            return Err(rejected());
        }
        Ok(())
    }
}

impl Executor {
    /// One bounded account-token observation for read-only rectification. The
    /// general paginated reader cannot enforce this operation's request bound.
    pub async fn execute_r2_restore_token_read(
        &self,
        capability: &cfctl_core::CapabilityV1,
        account: &str,
        credential: &AuthCredential,
    ) -> Result<CloudflareResponseV1> {
        if !contract::token_read_matches(capability, contract::TOKEN_VERIFY_PATH)
            || account.len() != 32
            || !account
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(rejected());
        }
        let input = CallInput {
            selectors: json!({"account_id":account}),
            query: json!({}),
            ..CallInput::default()
        };
        let request = self.builder.build(capability, &input)?;
        let outgoing = apply_credential(
            self.client
                .get(request.url.clone())
                .headers(request.headers)
                .timeout(Duration::from_secs(30)),
            credential,
        )?;
        let response = outgoing.send().await.map_err(|_| rejected())?;
        if response.status().as_u16() != 200 || response.url() != &request.url {
            return Err(rejected());
        }
        let (body, truncated) = read_bounded_body(response, contract::TOKEN_READ_MAX_BYTES)
            .await
            .map_err(|_| rejected())?;
        if truncated {
            return Err(rejected());
        }
        let value: Value = serde_json::from_slice(&body).map_err(|_| rejected())?;
        if value["success"] != true
            || value["errors"].as_array().is_none_or(|e| !e.is_empty())
            || !value["result"].is_object()
            || value.get("result_info").is_some_and(|v| !v.is_null())
        {
            return Err(rejected());
        }
        Ok(CloudflareResponseV1 {
            status: 200,
            success: true,
            result: value["result"].clone(),
            errors: vec![],
            result_info: None,
            etag: None,
            cf_ray: None,
        })
    }

    pub(crate) fn private_r2_transport(&self) -> S3Transport {
        let transport = S3Transport::new(self.client.clone());
        #[cfg(test)]
        let transport = {
            let mut transport = transport;
            transport.test_origin.clone_from(&self.r2_test_origin);
            transport
        };
        transport
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "one consumed native boundary joins the exact plan, catalog, input, private source, effect credential and request accounting"
    )]
    pub async fn execute_r2_private_restore(
        &self,
        plan: &mut PlanV1,
        catalog_hash: &str,
        input: &CallInput,
        selection: &RestoreSelectionV1,
        source: Vec<u8>,
        token_id: &str,
        credential: &AuthCredential,
        progress: &RestoreProgress,
    ) -> Result<CloudflareResponseV1> {
        if plan.status != PlanStatus::Consumed
            || plan.transaction_stage != TransactionStageV1::BoundaryAttemptPersisted
            || plan.catalog_hash != catalog_hash
            || !contract::capability_matches(&plan.capability)
            || plan.account_id != selection.account_id
            || input.selectors
                != json!({"account_id":selection.account_id,"bucket_name":selection.bucket_name})
            || input.query.as_object().is_none_or(|q| !q.is_empty())
            || input.if_match.is_some()
            || input.if_none_match.is_some()
            || input.body.as_ref()
                != Some(&serde_json::to_value(&selection.request).map_err(|_| rejected())?)
            || input
                != &serde_json::from_value::<CallInput>(plan.input.clone())
                    .map_err(|_| rejected())?
            || source.len() as u64 != selection.source.byte_count
            || hex::encode(Sha256::digest(&source)) != selection.source.sha256
        {
            return Err(rejected());
        }
        selection.validate(Utc::now()).map_err(|_| rejected())?;
        let list_url = self.builder.build_unchecked(&plan.capability, input)?.url;
        let remaining = (selection.window.expires_at - Utc::now())
            .to_std()
            .map_err(|_| rejected())?;
        // Claim this in-memory boundary before awaiting the first request. The
        // CLI has already persisted consumption, so neither retrying this
        // instance nor reloading the operation can replay a PUT.
        plan.status = PlanStatus::Running;
        let result = tokio::time::timeout(
            remaining,
            self.restore_one(selection, source, token_id, credential, &list_url, progress),
        )
        .await
        .map_err(|_| rejected())
        .and_then(std::convert::identity);
        let response = match result {
            Ok(response) => response,
            Err(error) => {
                plan.status = PlanStatus::RectificationRequired;
                return Err(error);
            }
        };
        plan.status = if response.success {
            PlanStatus::Running
        } else {
            PlanStatus::Failed
        };
        Ok(response)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the bounded pre-reads, exact condition, single PUT and body-free outcome form one auditable native mutation boundary"
    )]
    async fn restore_one(
        &self,
        selection: &RestoreSelectionV1,
        source: Vec<u8>,
        token_id: &str,
        credential: &AuthCredential,
        list_url: &Url,
        progress: &RestoreProgress,
    ) -> Result<CloudflareResponseV1> {
        let transport = self.private_r2_transport();
        let key = selection.source.provider_metadata["key"]
            .as_str()
            .ok_or_else(rejected)?;
        let target = S3Target {
            account: &selection.account_id,
            bucket: &selection.bucket_name,
            key,
        };
        let mut headers =
            semantic_headers(&selection.source.provider_metadata).map_err(|_| rejected())?;
        if let Some(current) = &selection.displaced {
            let etag = current.provider_metadata["etag"]
                .as_str()
                .ok_or_else(rejected)?;
            let seen = self
                .restore_object_digest(
                    &transport,
                    &target,
                    Some(etag),
                    token_id,
                    credential,
                    progress,
                )
                .await?;
            let metadata = self
                .restore_object_metadata(list_url, key, credential, progress)
                .await?;
            if seen.sha256 != current.sha256
                || seen.bytes != current.byte_count
                || metadata["etag"] != current.provider_metadata["etag"]
                || metadata["size"].as_u64() != Some(current.byte_count)
                || semantic_headers(&metadata).map_err(|_| rejected())?
                    != semantic_headers(&current.provider_metadata).map_err(|_| rejected())?
            {
                return Err(rejected());
            }
            headers.insert("if-match".into(), format!("\"{etag}\""));
        } else {
            progress.request()?;
            let response = transport
                .send(
                    &target,
                    Method::HEAD,
                    BTreeMap::new(),
                    None,
                    token_id,
                    credential,
                )
                .await?;
            if response.status().as_u16() != 404 {
                return Err(rejected());
            }
            headers.insert("if-none-match".into(), "*".into());
        }
        // ETag conditions bind content identity, not atomic metadata identity.
        // Writer exclusion is a separate mandatory combined-recovery gate.
        selection
            .window
            .validate(Utc::now())
            .map_err(|_| rejected())?;
        progress.request()?;
        progress.put_attempted.store(true, Ordering::Relaxed);
        let response = transport
            .send(
                &target,
                Method::PUT,
                headers,
                Some(source),
                token_id,
                credential,
            )
            .await?;
        let status = response.status().as_u16();
        if status != 200 && (!(400..500).contains(&status) || matches!(status, 408 | 429)) {
            return Err(rejected());
        }
        let etag = response
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let (_, truncated) = read_bounded_body(response, 16 * 1024)
            .await
            .map_err(|_| rejected())?;
        if truncated || (status == 200 && etag.as_deref().is_none_or(|s| !strong_etag(s))) {
            return Err(rejected());
        }
        Ok(CloudflareResponseV1 {
            status,
            success: status == 200,
            result: json!({"schema_version":1, "put_attempted":true,"conditional_write_succeeded":status == 200,
                "account_id":selection.account_id,"bucket_name":selection.bucket_name,
                "source_capture":selection.request.source_capture,"current_capture":selection.request.current_capture,
                "window":selection.window,"object_key_sha256":hex::encode(Sha256::digest(key.as_bytes())),
                "source_sha256":selection.source.sha256,"source_bytes":selection.source.byte_count,
                "displaced_bytes_preserved":selection.displaced.is_some(),
                "etag":etag,"provider_requests":progress.requests(),"body_returned":false,
                "metadata_atomic_precondition":false,"writer_exclusion_qualified":false,
                "combined_recovery_ready":false,"retention_qualified":false}),
            errors: vec![],
            result_info: None,
            etag,
            cf_ray: None,
        })
    }

    /// Read-only component verification; this may also rectify an uncertain
    /// historical attempt without replaying PUT or granting writer release.
    pub async fn verify_r2_private_restore(
        &self,
        plan: &PlanV1,
        input: &CallInput,
        selection: &RestoreSelectionV1,
        token_id: &str,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        if !contract::capability_matches(&plan.capability)
            || plan.account_id != selection.account_id
            || input.selectors
                != json!({"account_id":selection.account_id,"bucket_name":selection.bucket_name})
            || input.query.as_object().is_none_or(|q| !q.is_empty())
            || input.if_match.is_some()
            || input.if_none_match.is_some()
            || input.body.as_ref()
                != Some(&serde_json::to_value(&selection.request).map_err(|_| rejected())?)
            || input
                != &serde_json::from_value::<CallInput>(plan.input.clone())
                    .map_err(|_| rejected())?
        {
            return Err(rejected());
        }
        selection
            .validate(selection.window.opened_at)
            .map_err(|_| rejected())?;
        let list_url = self.builder.build_unchecked(&plan.capability, input)?.url;
        tokio::time::timeout(Duration::from_mins(15), async {
            let progress = RestoreProgress::default();
            let transport = self.private_r2_transport();
            let key = selection.source.provider_metadata["key"].as_str().ok_or_else(rejected)?;
            let target = S3Target { account: &selection.account_id, bucket: &selection.bucket_name, key };
            let seen = self.restore_object_digest(&transport, &target, None, token_id, credential, &progress).await?;
            let metadata = self.restore_object_metadata(&list_url, key, credential, &progress).await?;
            let stored_headers = semantic_headers(&metadata).map_err(|_| rejected())?;
            let expected_headers = semantic_headers(&selection.source.provider_metadata).map_err(|_| rejected())?;
            let passed = seen.bytes == selection.source.byte_count && seen.sha256 == selection.source.sha256
                && stored_headers == expected_headers
                && metadata["etag"].as_str().is_some_and(|e| seen.etag == format!("\"{e}\""))
                && metadata["size"].as_u64() == Some(seen.bytes);
            Ok(OperationVerificationV1 {
                strategy: contract::STRATEGY.into(), passed,
                basis: "observed current object bytes and stored semantic metadata compared with the authenticated source; no atomic metadata condition, writer exclusion or combined recovery qualification".into(),
                correlated_resource_id: None,
                readback: CloudflareResponseV1 {status:200,success:true,
                    result:json!({"schema_version":1,"account_id":selection.account_id,"bucket_name":selection.bucket_name,
                        "object_key_sha256":hex::encode(Sha256::digest(key.as_bytes())),"sha256":seen.sha256,
                        "byte_count":seen.bytes,"metadata_sha256":hash_value(&serde_json::to_value(stored_headers).map_err(|_| rejected())?).map_err(|_| rejected())?,
                        "observed_etag":seen.etag,"observed_last_modified":metadata["last_modified"],
                        "observed_at":Utc::now(),"provider_requests":progress.requests(),
                        "bytes_and_metadata_match":passed,"body_returned":false,"put_replayed":false,
                        "metadata_atomic_precondition":false,"writer_exclusion_qualified":false,
                        "combined_recovery_ready":false,"retention_qualified":false}),
                    errors:vec![],result_info:None,etag:Some(seen.etag),cf_ray:None},
            })
        }).await.map_err(|_| rejected())?
    }

    async fn restore_object_metadata(
        &self,
        base: &Url,
        key: &str,
        credential: &AuthCredential,
        progress: &RestoreProgress,
    ) -> Result<Value> {
        let url = crate::r2_metadata::member_url(base, key);
        let outgoing = apply_credential(
            self.client.get(url.clone()).timeout(Duration::from_mins(1)),
            credential,
        )?;
        progress.request()?;
        let response = outgoing.send().await.map_err(|_| rejected())?;
        if response.status().as_u16() != 200 || response.url() != &url {
            return Err(rejected());
        }
        let (body, truncated) = read_bounded_body(response, 2 * 1024 * 1024)
            .await
            .map_err(|_| rejected())?;
        if truncated {
            return Err(rejected());
        }
        let value: Value = serde_json::from_slice(&body).map_err(|_| rejected())?;
        crate::r2_metadata::exact_member(&value, key).map_err(|_| rejected())
    }

    async fn restore_object_digest(
        &self,
        transport: &S3Transport,
        target: &S3Target<'_>,
        expected_etag: Option<&str>,
        token_id: &str,
        credential: &AuthCredential,
        progress: &RestoreProgress,
    ) -> Result<ObjectDigest> {
        let mut headers = BTreeMap::new();
        if let Some(etag) = expected_etag {
            headers.insert("if-match".into(), format!("\"{etag}\""));
        }
        progress.request()?;
        let response = transport
            .send(target, Method::GET, headers, None, token_id, credential)
            .await?;
        if response.status().as_u16() != 200 {
            return Err(rejected());
        }
        let etag = response
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .filter(|v| strong_etag(v))
            .ok_or_else(rejected)?
            .to_owned();
        if expected_etag.is_some_and(|e| etag != format!("\"{e}\"")) {
            return Err(rejected());
        }
        let length = response.content_length();
        if length.is_some_and(|n| n > cfctl_core::r2_recovery::MAX_BYTES) {
            return Err(rejected());
        }
        let mut stream = response.bytes_stream();
        let mut bytes = 0_u64;
        let mut digest = Sha256::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| rejected())?;
            bytes = bytes
                .checked_add(chunk.len() as u64)
                .filter(|n| *n <= cfctl_core::r2_recovery::MAX_BYTES)
                .ok_or_else(rejected)?;
            digest.update(&chunk);
        }
        if length.is_some_and(|n| n != bytes) {
            return Err(rejected());
        }
        Ok(ObjectDigest {
            etag,
            bytes,
            sha256: hex::encode(digest.finalize()),
        })
    }
}

struct ObjectDigest {
    etag: String,
    bytes: u64,
    sha256: String,
}
fn strong_etag(etag: &str) -> bool {
    (3..=258).contains(&etag.len())
        && etag.starts_with('"')
        && etag.ends_with('"')
        && etag[1..etag.len() - 1]
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'"')
}

#[cfg(test)]
#[path = "r2_restore_tests.rs"]
mod tests;
