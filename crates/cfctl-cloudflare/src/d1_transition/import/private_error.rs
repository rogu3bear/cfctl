//! Raw provider diagnostics stay in the caller's existing private sink.
use super::{Progress, ValidatedImport, canonical_digest};
use crate::CloudflareResponseV1;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateImportErrorV1 {
    pub schema_version: u8,
    pub kind: String,
    pub operation_id: String,
    pub account_id: String,
    pub database_id: String,
    pub plan_hash: String,
    pub execution_sha256: String,
    pub action: String,
    pub response: CloudflareResponseV1,
}
impl PrivateImportErrorV1 {
    /// Exact structured messages only. Echoed SQL, substrings and unknown wrappers reject.
    #[must_use]
    pub fn has_exact_message(&self, expected: &str) -> bool {
        !expected.is_empty()
            && expected.len() <= 256
            && self.schema_version == 1
            && self.kind == "workspace_d1_transition_private_error_v1"
            && matches!(self.action.as_str(), "ingest" | "poll")
            && crate::d1_import::d1_import_action_provider_error(&self.response)
            && (self
                .response
                .errors
                .iter()
                .any(|error| error.message == expected)
                || self
                    .response
                    .result
                    .get("error")
                    .and_then(serde_json::Value::as_str)
                    == Some(expected)
                || self
                    .response
                    .result
                    .pointer("/error/message")
                    .and_then(serde_json::Value::as_str)
                    == Some(expected))
    }
}

pub(super) fn persist<S>(
    binding: &ValidatedImport,
    action: &str,
    response: &CloudflareResponseV1,
    bookmark: Option<&str>,
    sink: &mut S,
) -> Result<String, ()>
where
    S: FnMut(&Progress) -> Result<String, ()>,
{
    let error = PrivateImportErrorV1 {
        schema_version: 1,
        kind: "workspace_d1_transition_private_error_v1".into(),
        operation_id: binding.checkpoint.operation_id.clone(),
        account_id: binding.checkpoint.identity.account_id.clone(),
        database_id: binding.database_id.clone(),
        plan_hash: binding.checkpoint.plan_hash.clone(),
        execution_sha256: binding.checkpoint.identity.execution_sha256.clone(),
        action: action.into(),
        response: response.clone(),
    };
    let hash = sink(&Progress {
        operation_id: error.operation_id.clone(),
        database_id: error.database_id.clone(),
        phase: "provider_error",
        at_bookmark: bookmark.map(str::to_owned),
        terminal_bookmark: None,
        provider_error: Some(error),
        terminal: None,
    })?;
    if !canonical_digest(&hash) {
        return Err(());
    }
    Ok(hash)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn only_exact_structured_provider_error_messages_identify_a_fault() {
        let response: CloudflareResponseV1 = serde_json::from_value(serde_json::json!({
            "status":200,"success":true,
            "result":{"type":"import","status":"error","success":false,"at_bookmark":"synthetic-bookmark"},
            "errors":[{"code":7500,"message":"QUALIFIED_LEDGER_FAULT"}],
            "result_info":null,"etag":null,"cf_ray":null}))
        .unwrap();
        let mut error = PrivateImportErrorV1 {
            schema_version: 1,
            kind: "workspace_d1_transition_private_error_v1".into(),
            operation_id: "attempt".into(),
            account_id: "account".into(),
            database_id: "synthetic".into(),
            plan_hash: "plan".into(),
            execution_sha256: "fixture".into(),
            action: "poll".into(),
            response,
        };
        assert!(error.has_exact_message("QUALIFIED_LEDGER_FAULT"));
        assert!(!error.has_exact_message("LEDGER_FAULT"));
        assert!(!error.has_exact_message(""));
        error.response.errors[0].message =
            "SQL echo: RAISE(ABORT, 'QUALIFIED_LEDGER_FAULT')".into();
        assert!(!error.has_exact_message("QUALIFIED_LEDGER_FAULT"));
        error.response.errors.clear();
        error.response.result["error"] =
            serde_json::json!({"unknown_wrapper":"QUALIFIED_LEDGER_FAULT"});
        assert!(!error.has_exact_message("QUALIFIED_LEDGER_FAULT"));
        error.response.result["error"] = serde_json::json!({"message":"QUALIFIED_LEDGER_FAULT"});
        assert!(error.has_exact_message("QUALIFIED_LEDGER_FAULT"));
        error.response.success = false;
        assert!(!error.has_exact_message("QUALIFIED_LEDGER_FAULT"));
        error.response.success = true;
        error.response.result["status"] = serde_json::json!("complete");
        assert!(!error.has_exact_message("QUALIFIED_LEDGER_FAULT"));
        error.response.result["status"] = serde_json::json!("error");
        error.action = "init".into();
        assert!(!error.has_exact_message("QUALIFIED_LEDGER_FAULT"));
    }
}
