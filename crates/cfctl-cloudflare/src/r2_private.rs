//! Existing private digest executor.
use super::{
    AuthCredential, CallInput, CapabilityV1, CloudflareApiErrorV1, CloudflareError,
    CloudflareResponseV1, Digest, Duration, Executor, HeaderName, HeaderValue,
    R2PrivateObjectDigestV1, Result, RiskClass, Sha256, Value, apply_credential,
    exact_private_object_etag, read_bounded_body, sleep,
};
use futures_util::StreamExt;
impl Executor {
    /// Streams one exact private R2 object into an in-memory digest state. The
    /// object bytes are never materialized as a serializable value or retained
    /// in a file, error, response, receipt, or log.
    #[expect(
        clippy::too_many_lines,
        reason = "the private stream, retry, byte bound, ETag validation, and body-free receipt remain visible at one provider boundary"
    )]
    pub async fn execute_r2_private_object_digest(
        &self,
        capability: &CapabilityV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<CloudflareResponseV1> {
        let contract = capability
            .r2_private_object_digest
            .as_ref()
            .ok_or_else(|| {
                CloudflareError::InvalidRequestBody(
                    "R2 private object digest contract is missing".to_owned(),
                )
            })?;
        if capability.id != "r2-get-private-object-digest"
            || capability.method != "GET"
            || capability.path
                != "/accounts/{account_id}/r2/buckets/{bucket_name}/objects/{object_key}"
            || capability.mutating
            || capability.risk != RiskClass::Read
            || capability.effect != cfctl_core::EffectClass::ReadOnly
            || capability.permissions != ["Workers R2 Storage Read"]
            || contract.max_object_bytes == 0
            || contract.max_object_bytes > 300_000_000
            || input.body.is_some()
            || input
                .query
                .as_object()
                .is_none_or(|query| !query.is_empty())
        {
            return Err(CloudflareError::InvalidRequestBody(
                "R2 private object digest identity, effect, selectors, or bound drifted".to_owned(),
            ));
        }
        let selectors = input.selectors.as_object().ok_or_else(|| {
            CloudflareError::InvalidRequestBody(
                "R2 private object digest requires exact selectors".to_owned(),
            )
        })?;
        if selectors.len() != 3 {
            return Err(CloudflareError::InvalidRequestBody(
                "R2 private object digest accepts only account_id, bucket_name, and object_key"
                    .to_owned(),
            ));
        }
        let selector = |name: &str| {
            selectors
                .get(name)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| CloudflareError::MissingSelector(name.to_owned()))
        };
        let account_id = selector("account_id")?;
        let bucket_name = selector("bucket_name")?;
        let object_key = selector("object_key")?;
        let mut request = self.builder.build(capability, input)?;
        if request.body.is_some() || request.text_body.is_some() || request.binary_body.is_some() {
            return Err(CloudflareError::InvalidRequestBody(
                "R2 private object digest must be a body-free GET".to_owned(),
            ));
        }
        request.headers.insert(
            reqwest::header::ACCEPT,
            HeaderValue::from_static("application/octet-stream"),
        );
        let mut attempt = 0;
        loop {
            let response = apply_credential(
                self.client
                    .get(request.url.clone())
                    .headers(request.headers.clone())
                    .timeout(Duration::from_secs(request.timeout_seconds)),
                credential,
            )?
            .send()
            .await?;
            let status = response.status();
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(1)
                .min(30);
            if (status.as_u16() == 429 || status.is_server_error()) && attempt < self.max_retries {
                attempt += 1;
                sleep(Duration::from_secs(retry_after)).await;
                continue;
            }
            let status_code = status.as_u16();
            let cf_ray = response
                .headers()
                .get(HeaderName::from_static("cf-ray"))
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            if !status.is_success() {
                let _discarded = read_bounded_body(response, 1024 * 1024).await?;
                return Ok(CloudflareResponseV1 {
                    status: status_code,
                    success: false,
                    result: Value::Null,
                    errors: vec![CloudflareApiErrorV1 {
                        code: None,
                        message:
                            "R2 private object digest read failed; provider body was discarded"
                                .to_owned(),
                    }],
                    result_info: None,
                    etag: None,
                    cf_ray,
                });
            }
            if status_code != 200 {
                return Err(CloudflareError::UnexpectedSuccessStatus {
                    status: status_code,
                    expected: "200".to_owned(),
                });
            }
            if response
                .content_length()
                .is_some_and(|length| length > contract.max_object_bytes)
            {
                return Err(CloudflareError::InvalidRequestBody(
                    "R2 private object exceeds the digest-only read byte bound".to_owned(),
                ));
            }
            let etag = exact_private_object_etag(response.headers())?;
            let mut byte_count = 0_u64;
            let mut sha256 = Sha256::new();
            let mut body = response.bytes_stream();
            while let Some(chunk) = body.next().await {
                let chunk = chunk?;
                byte_count = byte_count
                    .checked_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX))
                    .ok_or_else(|| {
                        CloudflareError::InvalidRequestBody(
                            "R2 private object digest byte count overflowed".to_owned(),
                        )
                    })?;
                if byte_count > contract.max_object_bytes {
                    return Err(CloudflareError::InvalidRequestBody(
                        "R2 private object exceeds the digest-only read byte bound".to_owned(),
                    ));
                }
                sha256.update(&chunk);
            }
            let digest = R2PrivateObjectDigestV1 {
                schema_version: 1,
                account_id,
                bucket_name,
                object_key,
                byte_count,
                etag: etag.clone(),
                sha256: format!("sha256:{}", hex::encode(sha256.finalize())),
                body_returned: false,
            };
            return Ok(CloudflareResponseV1 {
                status: status_code,
                success: true,
                result: serde_json::to_value(digest)?,
                errors: Vec::new(),
                result_info: None,
                etag: Some(etag),
                cf_ray,
            });
        }
    }
}
