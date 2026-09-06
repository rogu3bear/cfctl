//! D1 import response validation, upload transport, and redacted checkpoints.
#[cfg(test)]
use super::D1ApprovedMlnImportContractV1;
use super::{
    CallInput, CloudflareError, CloudflareResponseV1, D1ImportCheckpointV1, D1ImportSourceBinding,
    Digest, Duration, HeaderMap, PlanStatus, PlanV1, Result, Sha256, StreamExt, Url, Value,
    hash_value, import_lineage_value, import_target, persist_import_poll_exhausted, timeout,
};

#[cfg(test)]
pub(super) fn validate_d1_import_upload_url(
    raw: &str,
    contract: &D1ApprovedMlnImportContractV1,
) -> Result<Url> {
    classify_d1_import_upload_url(raw, &contract.account_id, &contract.upload_url_suffix).map_err(
        |rejection| CloudflareError::InvalidRequestBody(rejection.provider_message().to_owned()),
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum D1ImportUploadUrlRejection {
    AuthorityOrShape,
    Signature,
}

#[cfg(test)]
impl D1ImportUploadUrlRejection {
    pub(super) const fn provider_message(self) -> &'static str {
        match self {
            Self::AuthorityOrShape => {
                "D1 import upload URL is not an provider-returned R2 account endpoint with a presigned HTTPS PUT URL"
            }
            Self::Signature => {
                "D1 import upload URL has an unsupported presigned signature contract"
            }
        }
    }
}

pub(super) fn classify_d1_import_upload_url(
    raw: &str,
    _account_id: &str,
    upload_url_suffix: &str,
) -> std::result::Result<Url, D1ImportUploadUrlRejection> {
    let raw_authority = raw
        .split_once("://")
        .map(|(_, remainder)| remainder.split(['/', '?', '#']).next().unwrap_or_default())
        .unwrap_or_default();
    let url = Url::parse(raw).map_err(|_| D1ImportUploadUrlRejection::AuthorityOrShape)?;
    let host = url.host_str().unwrap_or_default();
    // Authenticated D1 init delegates storage to an R2 account. That storage
    // account need not be the D1 customer account; init and ingest remain bound
    // to the reviewed D1 target. Accept only the documented S3 endpoint class.
    let storage_account = host.strip_suffix(".r2.cloudflarestorage.com");
    let documented_endpoint = upload_url_suffix == ".r2.cloudflarestorage.com"
        && storage_account.is_some_and(|account| {
            account.len() == 32
                && account
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        });
    let required_query_keys = [
        "X-Amz-Algorithm",
        "X-Amz-Credential",
        "X-Amz-Date",
        "X-Amz-Expires",
        "X-Amz-Signature",
        "X-Amz-SignedHeaders",
    ];
    let query_pairs = url.query_pairs().collect::<Vec<_>>();
    if raw_authority.contains('%')
        || url.scheme() != "https"
        || url.username() != ""
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port().is_some()
        || raw_authority != host
        || !documented_endpoint
        || url.path().is_empty()
        || url.path() == "/"
        || query_pairs.is_empty()
        || required_query_keys.iter().any(|required| {
            let matching = query_pairs
                .iter()
                .filter(|(key, _)| key == required)
                .collect::<Vec<_>>();
            matching.len() != 1 || matching[0].1.is_empty()
        })
    {
        return Err(D1ImportUploadUrlRejection::AuthorityOrShape);
    }
    let query_value = |name: &str| {
        query_pairs
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_ref())
            .unwrap_or_default()
    };
    let signature = query_value("X-Amz-Signature");
    if query_value("X-Amz-Algorithm") != "AWS4-HMAC-SHA256"
        || query_value("X-Amz-SignedHeaders") != "host"
        || signature.len() != 64
        || !signature.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(D1ImportUploadUrlRejection::Signature);
    }
    Ok(url)
}

pub(super) fn validated_d1_import_upload_etag(
    headers: &reqwest::header::HeaderMap,
    expected_md5: &str,
) -> Result<String> {
    let values = headers
        .get_all(reqwest::header::ETAG)
        .iter()
        .collect::<Vec<_>>();
    if values.len() != 1 {
        return Err(CloudflareError::InvalidRequestBody(
            "D1 import upload returned missing or ambiguous ETag; do not replay".to_owned(),
        ));
    }
    let raw = values[0].to_str().map_err(|_| {
        CloudflareError::InvalidRequestBody(
            "D1 import upload returned a non-text ETag; do not replay".to_owned(),
        )
    })?;
    if raw.is_empty()
        || raw.starts_with("W/")
        || raw.starts_with("w/")
        || raw.contains(',')
        || raw.trim() != raw
    {
        return Err(CloudflareError::InvalidRequestBody(
            "D1 import upload returned an unsupported ETag; do not replay".to_owned(),
        ));
    }
    let normalized = raw
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(raw);
    if normalized.len() != 32
        || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !normalized.eq_ignore_ascii_case(expected_md5)
    {
        return Err(CloudflareError::InvalidRequestBody(
            "D1 import upload ETag did not match the reviewed migration MD5; do not replay"
                .to_owned(),
        ));
    }
    Ok(normalized.to_ascii_lowercase())
}

pub(super) async fn bounded_d1_import_upload(
    client: &reqwest::Client,
    upload_url: Url,
    staged: Vec<u8>,
    timeout_seconds: u64,
    max_response_bytes: u64,
) -> Result<(reqwest::StatusCode, HeaderMap)> {
    timeout(Duration::from_secs(timeout_seconds), async {
        let response = client
            .put(upload_url)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .timeout(Duration::from_secs(timeout_seconds))
            .body(staged)
            .send()
            .await?;
        let status = response.status();
        let headers = response.headers().clone();
        let mut response_bytes = 0_u64;
        let mut body = response.bytes_stream();
        while let Some(chunk) = body.next().await {
            let chunk = chunk?;
            response_bytes = response_bytes
                .checked_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX))
                .ok_or_else(|| {
                    CloudflareError::InvalidRequestBody(
                        "D1 import upload response exceeded its bounded receipt".to_owned(),
                    )
                })?;
            if response_bytes > max_response_bytes {
                return Err(CloudflareError::InvalidRequestBody(
                    "D1 import upload response exceeded its bounded receipt".to_owned(),
                ));
            }
        }
        Ok((status, headers))
    })
    .await
    .map_err(|_| {
        CloudflareError::InvalidRequestBody(
            "D1 import upload exceeded its approved timeout; do not replay".to_owned(),
        )
    })?
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum D1ImportPollOutcome<'a> {
    InProgress,
    Complete(&'a str),
    ProviderError,
}

pub(super) fn d1_import_action_provider_error(response: &CloudflareResponseV1) -> bool {
    response.success
        && response.result.get("type").and_then(Value::as_str) == Some("import")
        && response.result.get("status").and_then(Value::as_str) == Some("error")
        && response.result.get("success").and_then(Value::as_bool) == Some(false)
}

pub(super) fn accepted_d1_import_init_response(response: &CloudflareResponseV1) -> Result<()> {
    if d1_import_action_provider_error(response) {
        return Err(CloudflareError::D1ImportProviderFailure);
    }
    let nested = [
        response.result.get("type"),
        response.result.get("status"),
        response.result.get("success"),
    ];
    if nested.iter().all(std::option::Option::is_none)
        || (nested[0].is_none()
            && nested[1].is_none()
            && response.result.get("success").and_then(Value::as_bool) == Some(true))
    {
        return Ok(());
    }
    let valid = response.result.get("type").and_then(Value::as_str) == Some("import")
        && matches!(
            response.result.get("status").and_then(Value::as_str),
            Some("active" | "pending")
        )
        && response.result.get("success").and_then(Value::as_bool) == Some(true);
    if valid {
        Ok(())
    } else {
        Err(CloudflareError::InvalidRequestBody(
            "D1 import init returned an unsupported nested state; do not replay".to_owned(),
        ))
    }
}

#[derive(Debug)]
pub(super) struct AcceptedD1ImportInit {
    pub(super) filename: String,
    pub(super) upload_url: Url,
}

pub(super) fn d1_import_filename_is_safe(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        && !value.starts_with('.')
        && !value.ends_with('.')
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum D1ImportInitRejection {
    TopLevel,
    NestedState,
    Filename,
    UploadUrlMissingOrNonString,
    UploadUrlAuthorityOrShape,
    UploadUrlSignature,
}

impl D1ImportInitRejection {
    pub(super) const fn receipt_label(self) -> &'static str {
        match self {
            Self::TopLevel => "top_level_rejected",
            Self::NestedState => "nested_state_rejected",
            Self::Filename => "filename_rejected",
            Self::UploadUrlMissingOrNonString => "upload_url_missing_or_non_string",
            Self::UploadUrlAuthorityOrShape => "upload_url_authority_or_shape_rejected",
            Self::UploadUrlSignature => "upload_url_signature_rejected",
        }
    }
}

pub(super) fn classify_d1_import_init_response(
    response: &CloudflareResponseV1,
    account_id: &str,
    upload_url_suffix: &str,
) -> std::result::Result<AcceptedD1ImportInit, D1ImportInitRejection> {
    if !response.success {
        return Err(D1ImportInitRejection::TopLevel);
    }
    if accepted_d1_import_init_response(response).is_err() {
        return Err(D1ImportInitRejection::NestedState);
    }
    let filename = response
        .result
        .get("filename")
        .and_then(Value::as_str)
        .filter(|value| d1_import_filename_is_safe(value))
        .ok_or(D1ImportInitRejection::Filename)?
        .to_owned();
    let upload_url_raw = response
        .result
        .get("upload_url")
        .and_then(Value::as_str)
        .ok_or(D1ImportInitRejection::UploadUrlMissingOrNonString)?;
    let upload_url = classify_d1_import_upload_url(upload_url_raw, account_id, upload_url_suffix)
        .map_err(|rejection| match rejection {
        D1ImportUploadUrlRejection::AuthorityOrShape => {
            D1ImportInitRejection::UploadUrlAuthorityOrShape
        }
        D1ImportUploadUrlRejection::Signature => D1ImportInitRejection::UploadUrlSignature,
    })?;
    Ok(AcceptedD1ImportInit {
        filename,
        upload_url,
    })
}

pub(super) fn accepted_d1_import_ingest_response(response: &CloudflareResponseV1) -> Result<&str> {
    if d1_import_action_provider_error(response) {
        return Err(CloudflareError::D1ImportProviderFailure);
    }
    let valid = response.success
        && response.result.get("type").and_then(Value::as_str) == Some("import")
        && matches!(
            response.result.get("status").and_then(Value::as_str),
            Some("active" | "pending" | "complete")
        )
        && response.result.get("success").and_then(Value::as_bool) == Some(true);
    if !valid {
        return Err(CloudflareError::InvalidRequestBody(
            "D1 import ingest returned an unsupported nested state; do not replay".to_owned(),
        ));
    }
    if response.result.get("status").and_then(Value::as_str) == Some("complete")
        && response
            .result
            .pointer("/result/final_bookmark")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err(CloudflareError::D1ImportIngestResponseFailure);
    }
    response
        .result
        .get("at_bookmark")
        .and_then(Value::as_str)
        .filter(|bookmark| !bookmark.is_empty())
        .ok_or_else(|| {
            CloudflareError::InvalidRequestBody(
                "D1 import ingest omitted at_bookmark; do not replay".to_owned(),
            )
        })
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum D1ImportIngestOutcome {
    InProgress(String),
    Complete {
        at_bookmark: String,
        final_bookmark: String,
    },
}

pub(super) fn classify_d1_import_ingest_response(
    response: &CloudflareResponseV1,
) -> std::result::Result<D1ImportIngestOutcome, ()> {
    let at_bookmark = accepted_d1_import_ingest_response(response)
        .map_err(|_| ())?
        .to_owned();
    if response.result.get("status").and_then(Value::as_str) == Some("complete") {
        let final_bookmark = response
            .result
            .pointer("/result/final_bookmark")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or(())?
            .to_owned();
        Ok(D1ImportIngestOutcome::Complete {
            at_bookmark,
            final_bookmark,
        })
    } else {
        Ok(D1ImportIngestOutcome::InProgress(at_bookmark))
    }
}

pub(super) fn validate_d1_import_poll_response<'a>(
    response: &'a CloudflareResponseV1,
    expected_at_bookmark: &str,
) -> Result<D1ImportPollOutcome<'a>> {
    let invalid = |detail: &str| {
        CloudflareError::InvalidRequestBody(format!("D1 import poll {detail}; do not replay"))
    };
    if response.result.get("type").and_then(Value::as_str) != Some("import") {
        return Err(invalid("omitted or changed type"));
    }
    let status = response
        .result
        .get("status")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("omitted status"))?;
    let provider_success = response
        .result
        .get("success")
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid("omitted nested success"))?;
    let at_bookmark = response
        .result
        .get("at_bookmark")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("omitted at_bookmark"))?;
    if at_bookmark != expected_at_bookmark {
        return Err(invalid("changed at_bookmark"));
    }
    match (status, provider_success) {
        ("active" | "pending", true) => Ok(D1ImportPollOutcome::InProgress),
        ("error", false) => Ok(D1ImportPollOutcome::ProviderError),
        ("complete", true) => response
            .result
            .pointer("/result/final_bookmark")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(D1ImportPollOutcome::Complete)
            .ok_or_else(|| invalid("omitted nested result.final_bookmark")),
        ("complete", false) => Err(invalid("reported complete with success false")),
        ("error", true) => Err(invalid("reported error with success true")),
        ("active" | "pending", false) => Err(invalid("reported progress with success false")),
        _ => Err(invalid("returned unknown status")),
    }
}

pub(super) fn accepted_d1_import_poll_outcome<'a>(
    response: &'a CloudflareResponseV1,
    expected_at_bookmark: &str,
) -> Result<D1ImportPollOutcome<'a>> {
    match validate_d1_import_poll_response(response, expected_at_bookmark)? {
        D1ImportPollOutcome::ProviderError => Err(CloudflareError::D1ImportProviderFailure),
        outcome => Ok(outcome),
    }
}

pub(super) fn classify_d1_import_poll_response<'a>(
    response: &'a CloudflareResponseV1,
    expected_at_bookmark: &str,
) -> std::result::Result<D1ImportPollOutcome<'a>, ()> {
    if !response.success {
        return Err(());
    }
    accepted_d1_import_poll_outcome(response, expected_at_bookmark).map_err(|_| ())
}

pub(super) fn projected_d1_import_type(source: &Value) -> Option<&'static str> {
    match source.get("type").and_then(Value::as_str) {
        Some("import") => Some("import"),
        _ => None,
    }
}

pub(super) fn projected_d1_import_status(source: &Value) -> Option<&'static str> {
    match source.get("status").and_then(Value::as_str) {
        Some("active") => Some("active"),
        Some("pending") => Some("pending"),
        Some("complete") => Some("complete"),
        Some("error") => Some("error"),
        _ => None,
    }
}

pub(super) fn sha256_string(value: &str) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(value.as_bytes())))
}

pub(super) fn projected_d1_import_init_result(
    plan: &PlanV1,
    response: &CloudflareResponseV1,
    init_classification_failure: Option<&str>,
) -> Value {
    let upload_url = response.result.get("upload_url").and_then(Value::as_str);
    let filename = response.result.get("filename").and_then(Value::as_str);
    let parsed_upload_url = upload_url.and_then(|value| Url::parse(value).ok());
    let upload_url_host = parsed_upload_url.as_ref().and_then(Url::host_str);
    let expected_upload_url_host =
        plan.capability
            .d1_approved_mln_import
            .as_ref()
            .and_then(|contract| {
                import_target(plan)
                    .and_then(|target| {
                        target
                            .get("account_id")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    })
                    .map(|account_id| format!("{account_id}{}", contract.upload_url_suffix))
            });
    serde_json::json!({
        "type":projected_d1_import_type(&response.result),
        "status":projected_d1_import_status(&response.result),
        "success":response.result.get("success").and_then(Value::as_bool),
        "at_bookmark_present":response.result.get("at_bookmark").is_some(),
        "at_bookmark_is_string":response.result.get("at_bookmark").and_then(Value::as_str).is_some(),
        "upload_url_present":upload_url.is_some(),
        "upload_url_sha256":upload_url.map(sha256_string),
        "upload_url_host_is_exact_account_endpoint":upload_url_host.zip(expected_upload_url_host.as_deref()).is_some_and(|(actual, expected)| actual == expected),
        "upload_url_host_is_cloudflare_r2":upload_url_host.is_some_and(|host| host.ends_with(".r2.cloudflarestorage.com")),
        "filename_present":filename.is_some(),
        "filename_sha256":filename.map(sha256_string),
        "filename_shape_valid":filename.is_some_and(d1_import_filename_is_safe),
        "provider_error_present":response.result.get("error").is_some(),
        "cfctl_classification_failure":init_classification_failure,
    })
}

pub(super) fn projected_d1_import_action_result(
    source: &Value,
    retain_validated_bookmarks: bool,
) -> Value {
    let at_bookmark = source
        .get("at_bookmark")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty());
    let final_bookmark = source
        .pointer("/result/final_bookmark")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty());
    serde_json::json!({
        "type":projected_d1_import_type(source),
        "status":projected_d1_import_status(source),
        "success":source.get("success").and_then(Value::as_bool),
        "at_bookmark":retain_validated_bookmarks.then_some(at_bookmark).flatten(),
        "at_bookmark_present":source.get("at_bookmark").is_some(),
        "at_bookmark_is_string":source.get("at_bookmark").and_then(Value::as_str).is_some(),
        "at_bookmark_sha256":at_bookmark.map(sha256_string),
        "result":{
            "final_bookmark":retain_validated_bookmarks.then_some(final_bookmark).flatten(),
            "final_bookmark_present":source.pointer("/result/final_bookmark").is_some(),
            "final_bookmark_is_string":source.pointer("/result/final_bookmark").and_then(Value::as_str).is_some(),
            "final_bookmark_sha256":final_bookmark.map(sha256_string),
        },
        "provider_error_present":source.get("error").is_some(),
    })
}

pub(super) fn persist_import_response<F>(
    persist: &mut F,
    plan: &PlanV1,
    step: &str,
    response: &CloudflareResponseV1,
    replacement_result: Option<Value>,
    init_classification_failure: Option<&str>,
    retain_validated_bookmarks: bool,
) -> Result<()>
where
    F: FnMut(&D1ImportCheckpointV1) -> std::result::Result<(), String>,
{
    let response_action = if step == "init_response" {
        "init"
    } else if step == "ingest_response" {
        "ingest"
    } else if step.starts_with("poll_response_") {
        "poll"
    } else {
        "unknown"
    };
    let target = import_target(plan);
    let migration_id = import_lineage_value(plan, "migration_id");
    let result = if response_action == "init" {
        projected_d1_import_init_result(plan, response, init_classification_failure)
    } else {
        let source = replacement_result.as_ref().unwrap_or(&response.result);
        projected_d1_import_action_result(source, retain_validated_bookmarks)
    };
    let successful_ingest = step == "ingest_response"
        && response.success
        && result.get("type").and_then(Value::as_str) == Some("import")
        && matches!(
            result.get("status").and_then(Value::as_str),
            Some("active" | "pending" | "complete")
        )
        && retain_validated_bookmarks
        && result.get("success").and_then(Value::as_bool) == Some(true);
    let terminal_provider_failure = result.get("status").and_then(Value::as_str) == Some("error")
        && result.get("success").and_then(Value::as_bool) == Some(false);
    let provider_error_present = result
        .get("provider_error_present")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let result = if terminal_provider_failure {
        serde_json::json!({
            "type":result.get("type"),
            "status":"error",
            "success":false,
            "at_bookmark":result.get("at_bookmark"),
            "provider_error_present":provider_error_present,
        })
    } else {
        result
    };
    persist(&D1ImportCheckpointV1 {
        schema_version: 1,
        operation_id: plan.operation_id.clone(),
        step: step.to_owned(),
        performed: true,
        rectification_required: matches!(plan.status, PlanStatus::RectificationRequired)
            || !response.success
            || terminal_provider_failure,
        receipt: serde_json::json!({
            "http_status":response.status,
            "success":response.success,
            "response_action":response_action,
            "provider":"cloudflare",
            "effect":if successful_ingest {"d1_import_ingest_accepted"} else {"d1_import_response"},
            "migration_id":migration_id,
            "target":target,
            "plan_input_hash":hash_value(&plan.input)?,
            "result":result,
            "errors":[],
            "provider_errors_present":!response.errors.is_empty(),
            "no_replay":terminal_provider_failure || result.get("status").and_then(Value::as_str) == Some("complete") || matches!(plan.status, PlanStatus::RectificationRequired),
            "etag_present":response.etag.is_some(),
            "etag_sha256":response.etag.as_ref().map(|value| format!("sha256:{}", hex::encode(Sha256::digest(value.as_bytes())))),
            "cf_ray":response.cf_ray,
        }),
    })
    .map_err(CloudflareError::InvalidRequestBody)
}

pub(super) fn persist_import_uncertainty<F>(
    persist: &mut F,
    plan: &PlanV1,
    step: &str,
) -> Result<()>
where
    F: FnMut(&D1ImportCheckpointV1) -> std::result::Result<(), String>,
{
    let target = import_target(plan).ok_or_else(|| {
        CloudflareError::InvalidRequestBody("approved MLN import contract is missing".to_owned())
    })?;
    let migration_id = import_lineage_value(plan, "migration_id");
    let transport_stage = if step.starts_with("poll_send_uncertain_") || step == "poll_exhausted" {
        "poll"
    } else {
        step.strip_suffix("_send_uncertain").unwrap_or(step)
    };
    persist(&D1ImportCheckpointV1 {
        schema_version: 1,
        operation_id: plan.operation_id.clone(),
        step: step.to_owned(),
        performed: true,
        rectification_required: true,
        receipt: serde_json::json!({
            "provider":"cloudflare",
            "effect":"d1_import_transport_uncertain",
            "transport_stage":transport_stage,
            "migration_id":migration_id,
            "target":target,
            "plan_input_hash":hash_value(&plan.input)?,
            "outcome":"unknown",
            "receipt_available":false,
            "no_replay":true,
        }),
    })
    .map_err(CloudflareError::InvalidRequestBody)
}

#[expect(
    clippy::too_many_arguments,
    reason = "completion binds source, target, response action and both validated bookmarks"
)]
pub(super) fn persist_import_complete<F>(
    persist: &mut F,
    plan: &mut PlanV1,
    input: &CallInput,
    migration: &D1ImportSourceBinding,
    response: &CloudflareResponseV1,
    response_action: &str,
    at_bookmark: &str,
    final_bookmark: &str,
) -> Result<CloudflareResponseV1>
where
    F: FnMut(&D1ImportCheckpointV1) -> std::result::Result<(), String>,
{
    let staged_identity = plan
        .targets
        .pointer("/adapter/approved_mln_import")
        .ok_or_else(|| {
            CloudflareError::InvalidRequestBody(
                "approved MLN import stage identity is missing".to_owned(),
            )
        })?;
    let boundary = D1ImportCheckpointV1 {
        schema_version: 1,
        operation_id: plan.operation_id.clone(),
        step: "provider_complete".to_owned(),
        performed: true,
        rectification_required: false,
        receipt: serde_json::json!({
            "provider":"cloudflare",
            "effect":"d1_import_provider_complete",
            "response_action":response_action,
            "no_replay":true,
            "migration_id":migration.migration_id,
            "source_sha256":format!("sha256:{}",migration.sha256),
            "source_md5":migration.md5,
            "source_bytes":migration.bytes,
            "source_authority_hash":staged_identity.get("source_authority_hash"),
            "stage_identity_hash":hash_value(staged_identity)?,
            "target":{"account_id":migration.account_id,"database_id":migration.database_id},
            "plan_input_hash":hash_value(&plan.input)?,
            "prerequisites":input.body,
            "at_bookmark":at_bookmark,
            "final_bookmark":final_bookmark,
            "provider_status":"complete",
            "provider_success":true,
            "state":"provider_complete",
        }),
    };
    persist(&boundary).map_err(CloudflareError::InvalidRequestBody)?;
    let mut completed = response.clone();
    completed.result["_cfctl"] = boundary.receipt;
    plan.status = PlanStatus::Running;
    Ok(completed)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests;

/// The post-upload protocol uses the same target-bound sender as init. Keeping
/// this phase together makes the immediate terminal branch and no-replay rule
/// explicit; persistence must finish before any subsequent request.
#[expect(
    clippy::too_many_lines,
    reason = "ingest and polling remain one ordered durable state machine"
)]
pub(super) async fn finish_d1_import<F, S, Fut>(
    plan: &mut PlanV1,
    input: &CallInput,
    migration: &D1ImportSourceBinding,
    filename: &str,
    max_poll_attempts: u64,
    send_provider: S,
    persist: &mut F,
) -> Result<CloudflareResponseV1>
where
    F: FnMut(&D1ImportCheckpointV1) -> std::result::Result<(), String>,
    S: Fn(Value) -> Fut,
    Fut: std::future::Future<Output = Result<CloudflareResponseV1>>,
{
    let ingest = match send_provider(serde_json::json!({
        "action":"ingest",
        "etag":migration.md5,
        "filename":filename,
    }))
    .await
    {
        Ok(response) => response,
        Err(error) => {
            plan.status = PlanStatus::RectificationRequired;
            persist_import_uncertainty(persist, plan, "ingest_send_uncertain")?;
            return Err(error);
        }
    };
    let Ok(ingest_outcome) = classify_d1_import_ingest_response(&ingest) else {
        plan.status = PlanStatus::RectificationRequired;
        persist_import_response(persist, plan, "ingest_response", &ingest, None, None, false)?;
        return Err(CloudflareError::D1ImportIngestResponseFailure);
    };
    persist_import_response(persist, plan, "ingest_response", &ingest, None, None, true)?;
    let at_bookmark = match ingest_outcome {
        D1ImportIngestOutcome::InProgress(bookmark) => bookmark,
        D1ImportIngestOutcome::Complete {
            at_bookmark,
            final_bookmark,
        } => {
            return persist_import_complete(
                persist,
                plan,
                input,
                migration,
                &ingest,
                "ingest",
                &at_bookmark,
                &final_bookmark,
            );
        }
    };
    for attempt in 1..=max_poll_attempts {
        let poll = match send_provider(serde_json::json!({
            "action":"poll",
            "current_bookmark":at_bookmark,
        }))
        .await
        {
            Ok(response) => response,
            Err(error) => {
                plan.status = PlanStatus::RectificationRequired;
                persist_import_uncertainty(
                    persist,
                    plan,
                    &format!("poll_send_uncertain_{attempt}"),
                )?;
                return Err(error);
            }
        };
        let Ok(poll_outcome) = classify_d1_import_poll_response(&poll, &at_bookmark) else {
            plan.status = PlanStatus::RectificationRequired;
            persist_import_response(
                persist,
                plan,
                &format!("poll_response_{attempt}"),
                &poll,
                None,
                None,
                false,
            )?;
            return Err(CloudflareError::D1ImportPollResponseFailure);
        };
        persist_import_response(
            persist,
            plan,
            &format!("poll_response_{attempt}"),
            &poll,
            None,
            None,
            true,
        )?;
        match poll_outcome {
            D1ImportPollOutcome::Complete(final_bookmark) => {
                return persist_import_complete(
                    persist,
                    plan,
                    input,
                    migration,
                    &poll,
                    "poll",
                    &at_bookmark,
                    final_bookmark,
                );
            }
            D1ImportPollOutcome::InProgress => {}
            D1ImportPollOutcome::ProviderError => unreachable!(
                "accepted_d1_import_poll_outcome converts provider failure to an error"
            ),
        }
    }
    plan.status = PlanStatus::RectificationRequired;
    persist_import_poll_exhausted(persist, plan, &at_bookmark)?;
    Err(CloudflareError::D1ImportPollInProgressExhausted)
}
