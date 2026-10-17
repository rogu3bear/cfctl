//! Opt-in first-page audit reads. No pagination, redirects, retries or alternate fetches.
use std::{net::IpAddr, time::Duration};

use chrono::DateTime;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{
    AuthCredential, CapabilityV1, CloudflareApiErrorV1, CloudflareError, CloudflareResponseV1,
    RequestBuilder, Result, apply_credential, header_text, parse_response, read_bounded_body,
};

pub const AUDIT_PAGE_ID: &str = "audit-logs-v2-get-account-audit-logs";
pub const AUDIT_PAGE_MAX_BYTES: u64 = 16_777_216;
const AUDIT_PAGE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Serialize)]
pub struct AuditPageBoundsV1 {
    pub schema: &'static str,
    pub input_sha256: String,
    pub max_requests: u32,
    pub max_pages: u32,
    pub max_rows: u64,
    pub max_response_body_bytes: u64,
    pub max_seconds: u64,
    pub retries: u32,
    pub redirects: u32,
    pub attempted_requests: u32,
    pub received_responses: u32,
    pub completed_responses: u32,
    pub returned_rows: Option<usize>,
    pub response_body_bytes: Option<usize>,
    pub response_body_sha256: Option<String>,
    pub http_status: Option<u16>,
    pub elapsed_ms: u64,
    pub continuation: &'static str,
    pub window_completeness: &'static str,
    pub failure: Option<&'static str>,
}

#[derive(Debug)]
pub struct BoundedAuditReadV1 {
    pub response: CloudflareResponseV1,
    pub bounds: AuditPageBoundsV1,
}

/// Validate before credential retrieval or any HTTP, including catalog refresh.
pub fn validate_audit_page_input(
    capability: &CapabilityV1,
    input: &super::CallInput,
) -> Result<u64> {
    let invalid = || CloudflareError::InvalidRequestBody("invalid bounded audit page input".into());
    if capability.id != AUDIT_PAGE_ID
        || capability.mutating
        || capability.method != "GET"
        || capability.path != "/accounts/{account_id}/logs/audit"
        || !matches!(
            capability.adapter_status,
            cfctl_core::AdapterStatus::Native | cfctl_core::AdapterStatus::DynamicApi
        )
        || capability.workflow.is_some()
        || capability.workspace_d1_read_inventory.is_some()
        || capability.mln_0143_data_invariants.is_some()
        || input.body.is_some()
        || input.if_match.is_some()
        || input.if_none_match.is_some()
    {
        return Err(invalid());
    }
    let selectors = input.selectors.as_object().ok_or_else(invalid)?;
    let account = selectors
        .get("account_id")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    if selectors.len() != 1
        || account.len() != 32
        || !account
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err(invalid());
    }
    let query = input.query.as_object().ok_or_else(invalid)?;
    if query.len() != 4
        || ["since", "before", "limit", "direction"]
            .iter()
            .any(|k| !query.contains_key(*k))
        || query["direction"] != "asc"
    {
        return Err(invalid());
    }
    let limit = query["limit"]
        .as_u64()
        .or_else(|| query["limit"].as_str()?.parse().ok())
        .filter(|v| (1..=100).contains(v))
        .ok_or_else(invalid)?;
    let since = DateTime::parse_from_rfc3339(query["since"].as_str().ok_or_else(invalid)?)
        .map_err(|_| invalid())?;
    let before = DateTime::parse_from_rfc3339(query["before"].as_str().ok_or_else(invalid)?)
        .map_err(|_| invalid())?;
    let delta = before.signed_duration_since(since);
    if since.offset().local_minus_utc() != 0
        || before.offset().local_minus_utc() != 0
        || delta <= chrono::Duration::zero()
        || delta > chrono::Duration::seconds(600)
    {
        return Err(invalid());
    }
    Ok(limit)
}

/// One audit GET through the native adapter. The caller supplies no alternate route or client.
pub async fn execute_bounded_audit_page(
    base_url: &str,
    force_ipv4: bool,
    capability: &CapabilityV1,
    input: &super::CallInput,
    credential: &AuthCredential,
) -> Result<BoundedAuditReadV1> {
    execute_with_deadline(
        base_url,
        force_ipv4,
        capability,
        input,
        credential,
        AUDIT_PAGE_TIMEOUT,
    )
    .await
}

async fn execute_with_deadline(
    base_url: &str,
    force_ipv4: bool,
    capability: &CapabilityV1,
    input: &super::CallInput,
    credential: &AuthCredential,
    deadline: Duration,
) -> Result<BoundedAuditReadV1> {
    let limit = validate_audit_page_input(capability, input)?;
    let request = RequestBuilder::new(base_url)?.build(capability, input)?;
    let rendered: std::collections::BTreeMap<_, _> =
        request.url.query_pairs().into_owned().collect();
    let expected: std::collections::BTreeMap<_, _> = input
        .query
        .as_object()
        .ok_or_else(|| CloudflareError::InvalidRequestBody("audit query required".into()))?
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                v.as_str().map_or_else(|| v.to_string(), str::to_owned),
            )
        })
        .collect();
    if rendered != expected || request.url.query_pairs().count() != expected.len() {
        return Err(CloudflareError::InvalidRequestBody(
            "audit rendered filters disagree with bounded input".into(),
        ));
    }
    let mut client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .connect_timeout(Duration::from_secs(10).min(deadline))
        .timeout(deadline)
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .user_agent(concat!("cfctl/", env!("CARGO_PKG_VERSION")));
    if force_ipv4 {
        client = client.local_address(IpAddr::from([0, 0, 0, 0]));
    }
    let client = client.build()?;
    let outgoing = apply_credential(client.get(request.url).headers(request.headers), credential)?;
    let mut bounds = AuditPageBoundsV1 {
        schema: "cfctl.audit-page-bounds/v1",
        input_sha256: cfctl_core::hash_value(&json!({"schema":"cfctl.audit-page-input/v1",
            "capability_id":capability.id,"input":input,"max_pages":1,"max_requests":1,
            "max_rows":limit,"max_bytes":AUDIT_PAGE_MAX_BYTES,"max_seconds":30,"retries":0,"redirects":0}))
            .map_err(|_| CloudflareError::InvalidRequestBody("audit input cannot be hashed".into()))?,
        max_requests: 1, max_pages: 1, max_rows: limit, max_response_body_bytes: AUDIT_PAGE_MAX_BYTES,
        max_seconds: 30, retries: 0, redirects: 0, attempted_requests: 1, received_responses: 0,
        completed_responses: 0, returned_rows: None, response_body_bytes: None,
        response_body_sha256: None, http_status: None, elapsed_ms: 0,
        continuation: "NOT_REPORTED", window_completeness: "NOT_ESTABLISHED", failure: None,
    };
    let started = std::time::Instant::now();
    let result = tokio::time::timeout(deadline, fetch_once(outgoing, limit, &mut bounds)).await;
    let response = match result {
        Ok(Ok(response)) => response,
        Ok(Err(reason)) => failed_response(&mut bounds, reason),
        Err(_) => failed_response(&mut bounds, "audit I/O deadline exceeded; no retry"),
    };
    bounds.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let response = if started.elapsed() > deadline && response.success {
        failed_response(
            &mut bounds,
            "audit deadline exceeded during response processing; no retry",
        )
    } else {
        response
    };
    Ok(BoundedAuditReadV1 { response, bounds })
}

fn failed_response(bounds: &mut AuditPageBoundsV1, reason: &'static str) -> CloudflareResponseV1 {
    bounds.failure = Some(reason);
    CloudflareResponseV1 {
        status: bounds.http_status.unwrap_or(0),
        success: false,
        result: Value::Null,
        result_info: None,
        errors: vec![CloudflareApiErrorV1 {
            code: None,
            message: reason.into(),
        }],
        etag: None,
        cf_ray: None,
    }
}

async fn fetch_once(
    outgoing: reqwest::RequestBuilder,
    limit: u64,
    bounds: &mut AuditPageBoundsV1,
) -> std::result::Result<CloudflareResponseV1, &'static str> {
    let response = outgoing
        .send()
        .await
        .map_err(|_| "transport failed; provider completion unknown; no retry")?;
    bounds.received_responses = 1;
    let status = response.status().as_u16();
    bounds.http_status = Some(status);
    if response
        .headers()
        .get(reqwest::header::CONTENT_ENCODING)
        .is_some_and(|v| v.as_bytes() != b"identity")
    {
        return Err("unexpected response encoding; decompression disabled");
    }
    if response
        .content_length()
        .is_some_and(|v| v > AUDIT_PAGE_MAX_BYTES)
    {
        return Err("response body exceeds the audit byte ceiling");
    }
    let etag = header_text(response.headers(), reqwest::header::ETAG);
    let cf_ray = header_text(
        response.headers(),
        reqwest::header::HeaderName::from_static("cf-ray"),
    );
    let (bytes, truncated) = read_bounded_body(response, AUDIT_PAGE_MAX_BYTES)
        .await
        .map_err(|_| "response body incomplete; no retry")?;
    bounds.response_body_bytes = Some(bytes.len());
    if truncated {
        return Err("response body exceeds the audit byte ceiling");
    }
    bounds.completed_responses = 1;
    bounds.response_body_sha256 = Some(format!("sha256:{}", hex::encode(Sha256::digest(&bytes))));
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|_| "audit response is not valid JSON")?;
    if !(200..300).contains(&status) {
        let mut response = parse_response(status, &value, etag, cf_ray);
        response.success = false;
        response.result = Value::Null;
        bounds.failure = Some("unsuccessful HTTP response; no retry or redirect");
        return Ok(response);
    }
    if value.get("success").and_then(Value::as_bool) != Some(true) {
        if value.get("success").and_then(Value::as_bool) == Some(false) {
            let mut response = parse_response(status, &value, etag, cf_ray);
            response.success = false;
            response.result = Value::Null;
            bounds.failure = Some("provider rejected the bounded audit read; no retry");
            return Ok(response);
        }
        return Err("audit response did not report success");
    }
    let rows = value
        .get("result")
        .and_then(Value::as_array)
        .ok_or("audit result is not an array")?;
    if rows.len() as u64 > limit {
        return Err("audit row count exceeds the requested bound");
    }
    if rows.iter().any(|row| !row.is_object()) {
        return Err("audit row is not an object");
    }
    bounds.returned_rows = Some(rows.len());
    bounds.continuation = continuation(value.get("result_info"))?;
    Ok(parse_response(status, &value, etag, cf_ray))
}

fn continuation(info: Option<&Value>) -> std::result::Result<&'static str, &'static str> {
    let Some(info) = info.filter(|v| !v.is_null()) else {
        return Ok("NOT_REPORTED");
    };
    let object = info
        .as_object()
        .ok_or("invalid audit pagination metadata")?;
    let mut present = false;
    for key in ["cursor", "next_cursor"] {
        if let Some(value) = object.get(key).filter(|v| !v.is_null()) {
            let cursor = value.as_str().ok_or("invalid audit pagination cursor")?;
            present |= !cursor.is_empty();
        }
    }
    if let Some(cursors) = object.get("cursors").filter(|v| !v.is_null()) {
        let cursors = cursors
            .as_object()
            .ok_or("invalid audit pagination cursors")?;
        if let Some(value) = cursors.get("after").filter(|v| !v.is_null()) {
            let cursor = value.as_str().ok_or("invalid audit pagination cursor")?;
            present |= !cursor.is_empty();
        }
    }
    match (object.get("page"), object.get("total_pages")) {
        (None, None) => Ok(if present { "PRESENT" } else { "NOT_REPORTED" }),
        (Some(page), Some(total)) => {
            let page = page
                .as_u64()
                .filter(|v| *v > 0)
                .ok_or("invalid audit page number")?;
            let total = total
                .as_u64()
                .filter(|v| *v >= page)
                .ok_or("invalid audit page total")?;
            Ok(if present || page < total {
                "PRESENT"
            } else {
                "TERMINAL_REPORTED"
            })
        }
        _ => Err("incomplete audit pagination metadata"),
    }
}

#[cfg(test)]
#[path = "audit_page_tests.rs"]
mod tests;
