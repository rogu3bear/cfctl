//! Exact authenticated capture members for one conditional R2 restore.
use crate::r2_recovery::{CaptureWindowV1, CapturedObjectV1, MAX_OBJECTS, is_sha256};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const RESTORE_ID: &str = "r2-restore-private-captured-object";
pub const STRATEGY: &str = "r2_authenticated_member_conditional_restore";
pub const TOKEN_VERIFY_PATH: &str = "/accounts/{account_id}/tokens/verify";
pub const TOKEN_POLICY_PATH: &str = "/accounts/{account_id}/tokens/{token_id}";
pub const TOKEN_READ_MAX_BYTES: u64 = 64 * 1024;

#[must_use]
pub fn token_read_matches(cap: &crate::CapabilityV1, path: &str) -> bool {
    matches!(path, TOKEN_VERIFY_PATH | TOKEN_POLICY_PATH)
        && cap.path == path
        && cap.method == "GET"
        && !cap.mutating
        && cap.account_scope == "account"
        && cap.risk == crate::RiskClass::Read
        && cap.effect == crate::EffectClass::ReadOnly
        && matches!(
            cap.adapter_status,
            crate::AdapterStatus::Native | crate::AdapterStatus::DynamicApi
        )
        && cap.request_schema.is_none()
        && cap.response_contract.as_ref().is_some_and(|r| {
            r.success_statuses == ["200"]
                && r.body_mode == crate::ResponseBodyModeV1::CloudflareJsonEnvelope
        })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureRefV1 {
    pub evidence_hash: String,
    pub run_id: String,
}

impl CaptureRefV1 {
    pub fn validate(&self) -> Result<(), &'static str> {
        if !self
            .evidence_hash
            .strip_prefix("sha256:")
            .is_some_and(is_sha256)
            || !uuid::Uuid::parse_str(&self.run_id).is_ok_and(|id| id.to_string() == self.run_id)
        {
            return Err("invalid authenticated capture reference");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum CurrentExpectationV1 {
    // A struct variant enforces deny_unknown_fields during tagged decoding.
    Absent {},
    Present { object_index: usize },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreRequestV1 {
    pub source_capture: CaptureRefV1,
    pub source_object_index: usize,
    pub current_capture: CaptureRefV1,
    pub expected_current: CurrentExpectationV1,
    pub token_verification_evidence_hash: String,
    pub token_policy_evidence_hash: String,
}

impl RestoreRequestV1 {
    pub fn validate(&self) -> Result<(), &'static str> {
        self.source_capture.validate()?;
        self.current_capture.validate()?;
        if self.source_object_index >= MAX_OBJECTS
            || matches!(self.expected_current, CurrentExpectationV1::Present {object_index} if object_index >= MAX_OBJECTS)
            || [
                &self.token_verification_evidence_hash,
                &self.token_policy_evidence_hash,
            ]
            .iter()
            .any(|h| !h.strip_prefix("sha256:").is_some_and(is_sha256))
        {
            return Err("invalid private restore member or credential evidence reference");
        }
        Ok(())
    }
}

/// Private managed selection, never a public provider response or plan body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreSelectionV1 {
    pub schema_version: u8,
    pub account_id: String,
    pub bucket_name: String,
    pub window: CaptureWindowV1,
    pub request: RestoreRequestV1,
    pub source: CapturedObjectV1,
    pub displaced: Option<CapturedObjectV1>,
}

/// The actual caller distinguishes a write's readback from read-only recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreObservationKindV1 {
    ImmediatePostWrite,
    ReadOnlyRectification,
}

/// Body-free byte and stored-semantic-metadata identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreObjectResultV1 {
    pub sha256: String,
    pub byte_count: u64,
    pub semantic_metadata_sha256: String,
}

/// Authenticated as part of the native verification body, then joined to the
/// immutable plan and capture references by historical plan inspection.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreVerificationBindingV1 {
    pub schema_version: u8,
    pub operation_id: String,
    pub plan_content_hash: String,
    pub request_hash: String,
    pub selection_sha256: String,
    pub source_capture: CaptureRefV1,
    pub source_object_index: usize,
    pub current_capture: CaptureRefV1,
    pub expected_current: CurrentExpectationV1,
    pub account_id: String,
    pub bucket_name: String,
    pub object_key_sha256: String,
    pub source_window: CaptureWindowV1,
    pub current_window: CaptureWindowV1,
    pub expected: RestoreObjectResultV1,
    pub observation_kind: RestoreObservationKindV1,
}

impl RestoreSelectionV1 {
    pub fn object_key_sha256(&self) -> Result<String, &'static str> {
        let key = self.source.provider_metadata["key"]
            .as_str()
            .filter(|key| key_supported(key))
            .ok_or("invalid private restore object key")?;
        Ok(hex::encode(Sha256::digest(key.as_bytes())))
    }

    pub fn expected_result(&self) -> Result<RestoreObjectResultV1, &'static str> {
        validate_member(&self.source)?;
        let metadata = serde_json::to_value(semantic_headers(&self.source.provider_metadata)?)
            .map_err(|_| "invalid private restore source metadata")?;
        Ok(RestoreObjectResultV1 {
            sha256: self.source.sha256.clone(),
            byte_count: self.source.byte_count,
            semantic_metadata_sha256: crate::hash_value(&metadata)
                .map_err(|_| "invalid private restore metadata digest")?,
        })
    }

    pub fn validate(&self, now: DateTime<Utc>) -> Result<(), &'static str> {
        self.request.validate()?;
        self.window.validate(now)?;
        if self.schema_version != 1
            || self.account_id.len() != 32
            || !self
                .account_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !(3..=63).contains(&self.bucket_name.len())
            || !self
                .bucket_name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            || self.bucket_name.starts_with('-')
            || self.bucket_name.ends_with('-')
        {
            return Err("invalid private restore target");
        }
        validate_member(&self.source)?;
        match (&self.request.expected_current, &self.displaced) {
            (CurrentExpectationV1::Absent {}, None) => {}
            (CurrentExpectationV1::Present { .. }, Some(displaced)) => {
                validate_member(displaced)?;
                if displaced.provider_metadata["key"] != self.source.provider_metadata["key"] {
                    return Err("private restore member target drifted");
                }
            }
            _ => return Err("private restore current condition drifted"),
        }
        Ok(())
    }
}

fn validate_member(member: &CapturedObjectV1) -> Result<(), &'static str> {
    crate::r2_recovery::validate_object(&member.provider_metadata)?;
    if !is_sha256(&member.sha256)
        || member.provider_metadata["key"]
            .as_str()
            .is_none_or(|key| !key_supported(key))
        || member.provider_metadata["size"].as_u64() != Some(member.byte_count)
    {
        return Err("invalid private restore member identity");
    }
    semantic_headers(&member.provider_metadata).map(|_| ())
}

#[must_use]
pub fn key_supported(key: &str) -> bool {
    !key.is_empty() && key.len() <= 1024 && !key.split('/').any(|part| matches!(part, "." | ".."))
}

/// Only losslessly representable metadata is accepted. The full original
/// record stays private; this projection identifies semantic stored metadata.
pub fn semantic_headers(record: &Value) -> Result<BTreeMap<String, String>, &'static str> {
    crate::r2_recovery::validate_object(record)?;
    let object = record
        .as_object()
        .ok_or("invalid private metadata record")?;
    if object.keys().any(|k| {
        ![
            "key",
            "size",
            "etag",
            "last_modified",
            "storage_class",
            "ssec",
            "http_metadata",
            "custom_metadata",
        ]
        .contains(&k.as_str())
    }) {
        return Err("private restore has unsupported provider metadata");
    }
    let mut headers = BTreeMap::new();
    headers.insert(
        "x-amz-storage-class".into(),
        match record["storage_class"].as_str() {
            Some("Standard") => "STANDARD",
            Some("InfrequentAccess") => "STANDARD_IA",
            _ => return Err("unsupported private storage class"),
        }
        .into(),
    );
    insert_http_metadata(object.get("http_metadata"), &mut headers)?;
    insert_custom_metadata(object.get("custom_metadata"), &mut headers)?;
    if headers
        .iter()
        .map(|(k, v)| k.len() + v.len())
        .sum::<usize>()
        > 8192
    {
        return Err("private restore metadata exceeds its bounded header budget");
    }
    Ok(headers)
}

fn insert_http_metadata(
    http: Option<&Value>,
    headers: &mut BTreeMap<String, String>,
) -> Result<(), &'static str> {
    if let Some(http) = http.filter(|v| !v.is_null()) {
        for (name, value) in http.as_object().ok_or("invalid private HTTP metadata")? {
            let header = match name.as_str() {
                "cacheControl" => "cache-control",
                "cacheExpiry" => "expires",
                "contentDisposition" => "content-disposition",
                "contentEncoding" => "content-encoding",
                "contentLanguage" => "content-language",
                "contentType" => "content-type",
                _ => return Err("private restore has unsupported HTTP metadata"),
            };
            if value.is_null() {
                continue;
            }
            let text = value.as_str().ok_or("invalid private HTTP metadata")?;
            let value = if header == "expires" {
                let expiry = DateTime::parse_from_rfc3339(text)
                    .map_err(|_| "unsupported private expiry metadata")?;
                if expiry.timestamp_subsec_nanos() != 0 {
                    return Err("private expiry cannot be represented losslessly by HTTP");
                }
                expiry
                    .with_timezone(&Utc)
                    .format("%a, %d %b %Y %H:%M:%S GMT")
                    .to_string()
            } else {
                checked_header_value(text)?.to_owned()
            };
            headers.insert(header.into(), value);
        }
    }
    Ok(())
}

fn insert_custom_metadata(
    custom: Option<&Value>,
    headers: &mut BTreeMap<String, String>,
) -> Result<(), &'static str> {
    if let Some(custom) = custom.filter(|v| !v.is_null()) {
        for (key, value) in custom
            .as_object()
            .ok_or("invalid private custom metadata")?
        {
            if key.is_empty()
                || key.len() > 128
                || !key.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_')
                })
            {
                return Err("private custom metadata key is not losslessly supported by S3");
            }
            headers.insert(
                format!("x-amz-meta-{key}"),
                checked_header_value(value.as_str().ok_or("invalid private custom metadata")?)?
                    .to_owned(),
            );
        }
    }
    Ok(())
}

fn checked_header_value(value: &str) -> Result<&str, &'static str> {
    if value.bytes().any(|b| !b.is_ascii_graphic() && b != b' ')
        || value.trim() != value
        || value.contains("  ")
    {
        return Err("private metadata value is not losslessly supported by S3");
    }
    Ok(value)
}

#[must_use]
pub fn capability_matches(cap: &crate::CapabilityV1) -> bool {
    cap.id == RESTORE_ID
        && cap.method == "PUT"
        && cap.path == crate::r2_recovery::OBJECTS_PATH
        && cap.mutating
        && cap.risk == crate::RiskClass::ScopedWrite
        && cap.effect == crate::EffectClass::DataWrite
        && cap.adapter_status == crate::AdapterStatus::Native
        && cap.permissions == ["Workers R2 Storage Write"]
        && cap.verification.required
        && cap.verification.strategy == STRATEGY
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;
    use serde_json::json;

    fn record() -> Value {
        json!({"key":"docs/zero-byte", "etag":"original-etag", "size":0,
            "last_modified":"2026-08-07T00:00:00Z", "storage_class":"Standard"})
    }

    #[test]
    fn preserves_absence_and_projects_only_lossless_semantic_metadata() {
        let mut record = record();
        let absent = semantic_headers(&record).expect("absent metadata");
        assert_eq!(
            absent,
            BTreeMap::from([("x-amz-storage-class".into(), "STANDARD".into())])
        );
        record["http_metadata"] = json!(null);
        record["custom_metadata"] = json!({});
        assert_eq!(semantic_headers(&record).expect("null and empty"), absent);
        record["http_metadata"] = json!({
            "contentType": "application/pdf", "contentDisposition":"attachment; filename=contract.pdf",
            "contentEncoding":"gzip", "contentLanguage":"en", "cacheControl":"no-store",
            "cacheExpiry":"2026-09-07T00:00:00-05:00"});
        record["custom_metadata"] = json!({"document-id":"private-id"});
        let headers = semantic_headers(&record).expect("representable metadata");
        assert_eq!(headers["expires"], "Mon, 07 Sep 2026 05:00:00 GMT");
        assert_eq!(headers["content-encoding"], "gzip");
        assert_eq!(headers["x-amz-meta-document-id"], "private-id");
        assert_eq!(headers.len(), 8);
        record["storage_class"] = json!("InfrequentAccess");
        assert_eq!(
            semantic_headers(&record).expect("IA")["x-amz-storage-class"],
            "STANDARD_IA"
        );
    }

    #[test]
    fn refuses_lossy_metadata_instead_of_normalizing_or_dropping_it() {
        for (path, value) in [
            ("provider_version", json!("unmodeled")),
            (
                "http_metadata",
                json!({"cacheExpiry":"2026-09-07T00:00:00.123Z"}),
            ),
            ("http_metadata", json!({"unmodeled":null})),
            ("http_metadata", json!({"contentType":" application/pdf"})),
            ("custom_metadata", json!({"MixedCase":"value"})),
            ("custom_metadata", json!({"lower":"é"})),
            ("custom_metadata", json!({"lower":"two  spaces"})),
            ("custom_metadata", json!({"lower":"line\r\nbreak"})),
            ("custom_metadata", json!({"lower":"x".repeat(8193)})),
        ] {
            let mut record = record();
            record[path] = value;
            assert!(semantic_headers(&record).is_err(), "{path}");
        }
    }

    #[test]
    fn closed_requests_cannot_inject_effect_or_custody_overrides() {
        let reference = json!({"evidence_hash":format!("sha256:{}", "a".repeat(64)),
            "run_id":uuid::Uuid::new_v4().to_string()});
        let request = json!({"source_capture":reference, "source_object_index":0,
            "current_capture":reference, "expected_current":{"state":"absent"},
            "token_verification_evidence_hash":format!("sha256:{}", "b".repeat(64)),
            "token_policy_evidence_hash":format!("sha256:{}", "c".repeat(64))});
        serde_json::from_value::<RestoreRequestV1>(request.clone())
            .expect("closed request")
            .validate()
            .expect("valid identity");
        for expected_current in [
            json!({"state":"absent"}),
            json!({"state":"present","object_index":0}),
        ] {
            let mut valid = request.clone();
            valid["expected_current"] = expected_current;
            let decoded = serde_json::from_value::<RestoreRequestV1>(valid.clone())
                .expect("both valid current conditions decode");
            decoded.validate().expect("valid member identity");
            assert_eq!(
                serde_json::to_value(decoded).expect("same wire JSON"),
                valid
            );
            for field in [
                "endpoint",
                "source_path",
                "writer_exclusion_qualified",
                "retention_qualified",
            ] {
                let mut injected = valid.clone();
                injected["expected_current"][field] = json!(true);
                assert!(
                    serde_json::from_value::<RestoreRequestV1>(injected).is_err(),
                    "{field}"
                );
            }
        }
        for field in [
            "endpoint",
            "source_path",
            "writer_exclusion_qualified",
            "retention_qualified",
        ] {
            let mut injected = request.clone();
            injected[field] = json!(true);
            assert!(serde_json::from_value::<RestoreRequestV1>(injected).is_err());
        }
        let mut injected = request;
        injected["expected_current"]["object_index"] = json!(0);
        assert!(serde_json::from_value::<RestoreRequestV1>(injected).is_err());
    }
}
