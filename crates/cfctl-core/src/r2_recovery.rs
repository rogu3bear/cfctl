//! Private R2 capture contracts. Capture integrity is a component of recovery,
//! not proof of writer exclusion, retention, D1 recovery, or a working restore.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

pub const CAPTURE_ID: &str = "r2-capture-private-bucket";
pub const VERIFY_ID: &str = "r2-verify-private-capture";
pub const OBJECTS_PATH: &str = "/accounts/{account_id}/r2/buckets/{bucket_name}/objects";
pub const MAX_BYTES: u64 = 300_000_000;
pub const MAX_PAGES: u32 = 10;
pub const PAGE_SIZE: u32 = 100;
pub const MAX_OBJECTS: usize = 1000;
pub const MAX_SECONDS: i64 = 900;
pub const MAX_MANIFEST_BYTES: u64 = 20 * 1024 * 1024;

/// Hash of the application's exact D1/writer/retention declaration. This is a
/// join key, not an assertion that cfctl has qualified that declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureWindowV1 {
    pub window_id: String,
    pub opened_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub recovery_binding_sha256: String,
}

impl CaptureWindowV1 {
    pub fn validate(&self, now: DateTime<Utc>) -> Result<(), &'static str> {
        if !Uuid::parse_str(&self.window_id).is_ok_and(|id| id.to_string() == self.window_id)
            || !is_sha256(&self.recovery_binding_sha256)
            || self.opened_at > now
            || self.expires_at <= now
            || self.expires_at <= self.opened_at
            || self.expires_at - self.opened_at > chrono::Duration::seconds(MAX_SECONDS)
        {
            return Err("invalid or expired private capture window");
        }
        Ok(())
    }
}

#[must_use]
pub fn capability_matches(cap: &crate::CapabilityV1) -> bool {
    (cap.id == CAPTURE_ID || cap.id == VERIFY_ID)
        && cap.method == "GET"
        && cap.path == OBJECTS_PATH
        && !cap.mutating
        && cap.risk == crate::RiskClass::Read
        && cap.effect == crate::EffectClass::ReadOnly
        && ((cap.id == CAPTURE_ID
            && cap.permissions == ["Workers R2 Storage Read"]
            && cap.verification.strategy == "r2_private_capture")
            || (cap.id == VERIFY_ID
                && cap.permissions.is_empty()
                && cap.verification.strategy == "private_capture_authenticated_local_integrity"))
        && cap.adapter_status == crate::AdapterStatus::Native
}

#[must_use]
pub fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Full provider list record stays private. Unknown fields are retained, not
/// discarded. Known metadata is type checked without filling absent fields.
pub fn validate_object(value: &Value) -> Result<(), &'static str> {
    let object = value.as_object().ok_or("invalid private object record")?;
    let string = |key: &str| object.get(key).and_then(Value::as_str);
    if string("key").is_none_or(|s| s.is_empty() || s.len() > 1024)
        || string("etag").is_none_or(|s| {
            s.is_empty() || s.len() > 256 || !s.bytes().all(|b| b.is_ascii_graphic() && b != b'"')
        })
        || object
            .get("size")
            .and_then(Value::as_u64)
            .is_none_or(|s| s > MAX_BYTES)
        || string("last_modified").is_none_or(|s| DateTime::parse_from_rfc3339(s).is_err())
        || !matches!(
            string("storage_class"),
            Some("Standard" | "InfrequentAccess")
        )
        || object
            .get("ssec")
            .is_some_and(|v| !matches!(v, Value::Bool(false) | Value::Null))
    {
        return Err("unsupported private object identity or size");
    }
    for field in ["http_metadata", "custom_metadata"] {
        let Some(metadata) = object.get(field).filter(|v| !v.is_null()) else {
            continue;
        };
        let map = metadata
            .as_object()
            .ok_or("invalid private object metadata")?;
        if field == "custom_metadata" && map.values().any(|v| !v.is_string()) {
            return Err("invalid private custom metadata");
        }
        if field == "http_metadata" {
            for name in [
                "cacheControl",
                "cacheExpiry",
                "contentDisposition",
                "contentEncoding",
                "contentLanguage",
                "contentType",
            ] {
                if map
                    .get(name)
                    .is_some_and(|v| !v.is_string() && !v.is_null())
                {
                    return Err("invalid private HTTP metadata");
                }
            }
        }
    }
    Ok(())
}

/// Private manifest entry. No provider key or metadata value is projected into
/// the public receipt. Blob names are generated indices, never provider paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedObjectV1 {
    pub provider_metadata: Value,
    pub blob: String,
    pub sha256: String,
    pub byte_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureManifestV1 {
    pub schema_version: u8,
    pub run_id: String,
    pub account_id: String,
    pub bucket_name: String,
    pub window: CaptureWindowV1,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub list_pages: u32,
    pub total_bytes: u64,
    pub objects: Vec<CapturedObjectV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureReceiptV1 {
    pub schema_version: u8,
    pub run_id: String,
    pub account_id: String,
    pub bucket_name: String,
    pub window: CaptureWindowV1,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub list_pages: u32,
    pub object_count: usize,
    pub total_bytes: u64,
    pub manifest_sha256: String,
    pub capture_complete: bool,
    pub body_returned: bool,
    pub recovery_ready: bool,
}

impl CaptureManifestV1 {
    #[must_use]
    pub fn receipt(&self, manifest_sha256: String) -> CaptureReceiptV1 {
        CaptureReceiptV1 {
            schema_version: 1,
            run_id: self.run_id.clone(),
            account_id: self.account_id.clone(),
            bucket_name: self.bucket_name.clone(),
            window: self.window.clone(),
            started_at: self.started_at,
            completed_at: self.completed_at,
            list_pages: self.list_pages,
            object_count: self.objects.len(),
            total_bytes: self.total_bytes,
            manifest_sha256,
            capture_complete: true,
            body_returned: false,
            recovery_ready: false,
        }
    }
}

#[cfg(test)]
mod window_tests {
    use super::*;

    #[test]
    fn the_nine_hundred_second_limit_preserves_submillisecond_precision() {
        let now = Utc::now();
        let mut window = CaptureWindowV1 {
            window_id: Uuid::new_v4().to_string(),
            opened_at: now,
            expires_at: now + chrono::Duration::seconds(MAX_SECONDS),
            recovery_binding_sha256: "a".repeat(64),
        };
        assert_eq!(window.validate(now), Ok(()));
        window.expires_at += chrono::Duration::nanoseconds(1);
        assert!(window.validate(now).is_err());
        window.expires_at -= chrono::Duration::nanoseconds(2);
        assert_eq!(window.validate(now), Ok(()));
        assert!(window.validate(window.expires_at).is_err());
    }
}
