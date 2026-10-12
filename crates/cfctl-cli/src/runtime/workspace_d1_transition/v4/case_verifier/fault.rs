use super::{Join, Result, TransportReceipt, Value, invalid};
use cfctl_cloudflare::d1_transition::import::PrivateImportErrorV1;
use serde::Deserialize;
use sha2::{Digest, Sha256};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateProgress {
    schema_version: u8,
    kind: String,
    operation_id: String,
    database_id: String,
    at_bookmark: Option<String>,
    terminal_bookmark: Option<String>,
    provider_error: Option<PrivateImportErrorV1>,
}
pub(super) fn verify(join: &Join<'_, '_>, receipt: &TransportReceipt) -> Result<()> {
    let sentinel = join
        .case
        .failure_sentinel
        .as_deref()
        .ok_or_else(|| invalid("case fault sentinel not source-bound"))?;
    let error_hash = receipt
        .provider_error_evidence_hash
        .as_deref()
        .ok_or_else(|| invalid("case error evidence missing"))?;
    let value = join.store.read_evidence_value(error_hash)?;
    let artifact = value
        .get("private_progress")
        .ok_or_else(|| invalid("native fault diagnostic was not privately retained"))?;
    let path = artifact
        .get("path")
        .and_then(Value::as_str)
        .map(std::path::Path::new)
        .ok_or_else(|| invalid("private fault path missing"))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| invalid("private fault filename invalid"))?;
    if artifact.get("name").and_then(Value::as_str) != Some(name) {
        return Err(invalid("private fault filename differs"));
    }
    let directory = cfctl_storage::PrivateDirectory::open(
        path.parent()
            .ok_or_else(|| invalid("private fault parent missing"))?,
    )
    .map_err(|_| invalid("private fault directory custody failed"))?;
    let bytes = directory
        .read(name, 131_072)
        .map_err(|_| invalid("private fault file custody failed"))?
        .ok_or_else(|| invalid("private fault artifact missing"))?;
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
    if artifact.get("sha256").and_then(Value::as_str) != Some(digest.as_str())
        || artifact.get("bytes").and_then(Value::as_u64) != Some(bytes.len() as u64)
    {
        return Err(invalid("private native fault artifact changed"));
    }
    let private: PrivateProgress =
        serde_json::from_slice(&bytes).map_err(|_| invalid("private fault artifact malformed"))?;
    let error = private
        .provider_error
        .as_ref()
        .ok_or_else(|| invalid("private native error response missing"))?;
    let bookmark = private
        .at_bookmark
        .as_deref()
        .ok_or_else(|| invalid("private fault bookmark missing"))?;
    let bookmark_hash = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(bookmark.as_bytes()))
    );
    if private.schema_version != 1
        || private.kind != "workspace_d1_transition_private_progress_v1"
        || private.operation_id != join.plan.plan.operation_id
        || private.database_id != join.case.synthetic_database_id
        || private.terminal_bookmark.is_some()
        || bookmark_hash != receipt.bookmark_sha256
        || error.operation_id != join.plan.plan.operation_id
        || error.plan_hash != join.plan.plan.content_hash
        || error.account_id != join.scope.account
        || error.database_id != join.case.synthetic_database_id
        || error.execution_sha256 != join.case.fixture_sha256
        || error
            .response
            .result
            .get("at_bookmark")
            .and_then(Value::as_str)
            != Some(bookmark)
        || !error.has_exact_message(sentinel)
    {
        return Err(invalid(
            "structured native error does not identify the exact approved fault stage",
        ));
    }
    Ok(())
}
