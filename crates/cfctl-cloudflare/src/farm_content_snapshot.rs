//! Fixed, bounded D1 query. Private values never enter a public response type.
use cfctl_core::farm_content_snapshot::{
    ACCOUNT_ID, DATABASE_ID, MAX_RESPONSE_BYTES, MAX_REVISIONS, SNAPSHOT_SQL, TIMEOUT_SECONDS,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::time::Duration;

use crate::{
    AuthCredential, CloudflareError, Executor, Result, apply_credential, read_bounded_body,
};

#[must_use]
pub fn rejected() -> CloudflareError {
    CloudflareError::InvalidRequestBody("Farm snapshot rejected: target/authentication, provider response, completeness or bounds failed; no private values disclosed".into())
}

// Deliberately no Debug or public fields: callers can export only a validated
// value to their private sink, never serialize an unvalidated provider body.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Current {
    id: u32,
    schema_version: u32,
    version: u32,
    fields_json: String,
    updated_by: String,
    updated_at: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Revision {
    version: u32,
    schema_version: u32,
    fields_json: String,
    saved_by: String,
    saved_at: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    site_content: Vec<Current>,
    site_content_revisions: Vec<Revision>,
}

pub struct PrivateFarmSnapshot {
    bytes: Vec<u8>,
    version: u32,
    revisions: usize,
}

impl PrivateFarmSnapshot {
    #[must_use]
    pub fn private_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn metadata(&self) -> Value {
        json!({"schema_version":1, "account_id":ACCOUNT_ID, "database_id":DATABASE_ID,
            "complete":true, "current_cas_version":self.version,
            "revision_count":self.revisions, "body_returned":false,
            "consistency":"single_sqlite_read_statement", "continuation":null,
            "max_revisions":MAX_REVISIONS, "max_response_bytes":MAX_RESPONSE_BYTES,
            "timeout_seconds":TIMEOUT_SECONDS})
    }
}

impl Executor {
    /// No retry, dynamic SQL, redirects, pagination or mutation path.
    pub async fn read_farm_content_snapshot(
        &self,
        credential: &AuthCredential,
    ) -> Result<PrivateFarmSnapshot> {
        if credential.bearer_token().is_none() {
            return Err(rejected());
        }
        let mut url = self.builder.base_url.clone();
        url.path_segments_mut()
            .map_err(|()| rejected())?
            .pop_if_empty()
            .extend([
                "accounts",
                ACCOUNT_ID,
                "d1",
                "database",
                DATABASE_ID,
                "query",
            ]);
        let request = apply_credential(
            self.upload_client
                .post(url)
                .timeout(Duration::from_secs(TIMEOUT_SECONDS))
                .header(reqwest::header::ACCEPT, "application/json")
                .json(&json!({"sql":SNAPSHOT_SQL,"params":[]})),
            credential,
        )
        .map_err(|_| rejected())?;
        let response = request.send().await.map_err(|_| rejected())?;
        if response.status().as_u16() != 200
            || !response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| {
                    v.split(';')
                        .next()
                        .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"))
                })
        {
            return Err(rejected());
        }
        let (bytes, truncated) = read_bounded_body(response, MAX_RESPONSE_BYTES)
            .await
            .map_err(|_| rejected())?;
        if truncated {
            return Err(rejected());
        }
        decode(&bytes)
    }
}

fn decode(bytes: &[u8]) -> Result<PrivateFarmSnapshot> {
    if bytes.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(rejected());
    }
    let body: Value = serde_json::from_slice(bytes).map_err(|_| rejected())?;
    let results = body
        .get("result")
        .and_then(Value::as_array)
        .ok_or_else(rejected)?;
    if body.get("success") != Some(&json!(true))
        || results.len() != 1
        || body.get("errors").is_some_and(|v| v != &json!([]))
    {
        return Err(rejected());
    }
    let result = &results[0];
    let rows = result
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(rejected)?;
    if result.get("success") != Some(&json!(true))
        || rows.len() != 1
        || result.pointer("/meta/changed_db") != Some(&json!(false))
    {
        return Err(rejected());
    }
    let row = rows[0].as_object().ok_or_else(rejected)?;
    if row.len() != 1 {
        return Err(rejected());
    }
    let snapshot: Snapshot = serde_json::from_str(
        row.get("snapshot_json")
            .and_then(Value::as_str)
            .ok_or_else(rejected)?,
    )
    .map_err(|_| rejected())?;
    validate(&snapshot)?;
    let current = &snapshot.site_content[0];
    let bytes = serde_json::to_vec(&json!({"schema_version":1,"account_id":ACCOUNT_ID,
        "database_id":DATABASE_ID,"complete":true,
        "consistency":"single_sqlite_read_statement","snapshot":snapshot}))
    .map_err(|_| rejected())?;
    if bytes.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(rejected());
    }
    Ok(PrivateFarmSnapshot {
        bytes,
        version: current.version,
        revisions: snapshot.site_content_revisions.len(),
    })
}

fn validate(snapshot: &Snapshot) -> Result<()> {
    if snapshot.site_content.len() != 1 || snapshot.site_content_revisions.len() > MAX_REVISIONS {
        return Err(rejected());
    }
    let current = &snapshot.site_content[0];
    if current.id != 1
        || current.schema_version != 1
        || u64::from(current.version) != snapshot.site_content_revisions.len() as u64
        || !valid_fields(&current.fields_json)
        || current.updated_by.is_empty()
        || current.updated_at.is_empty()
    {
        return Err(rejected());
    }
    for (index, revision) in snapshot.site_content_revisions.iter().enumerate() {
        if u64::from(revision.version) != index as u64 + 1
            || revision.schema_version != 1
            || !valid_fields(&revision.fields_json)
            || revision.saved_by.is_empty()
            || revision.saved_at.is_empty()
        {
            return Err(rejected());
        }
    }
    if let Some(last) = snapshot.site_content_revisions.last()
        && (last.fields_json != current.fields_json
            || last.saved_by != current.updated_by
            || last.saved_at != current.updated_at)
    {
        return Err(rejected());
    }
    Ok(())
}

fn valid_fields(value: &str) -> bool {
    // Farm owns FieldValue's rich-text schema. This reader preserves those
    // objects verbatim; it does not interpret, flatten or apply their contents.
    serde_json::from_str::<Value>(value).is_ok_and(|v| v.is_object())
}

#[cfg(test)]
mod tests;
