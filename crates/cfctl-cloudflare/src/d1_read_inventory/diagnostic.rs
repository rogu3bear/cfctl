//! One exact registered query, with bounded private diagnostic output.
use super::{ValidatedD1ReadInventory, invalid, validate_inventory};
use crate::{AuthCredential, Executor, Result, apply_credential, read_bounded_body};
use serde_json::{Value, json};
use std::time::Duration;

/// Raw bytes have no Debug/Serialize implementation and must enter a private sink.
pub struct FailedQueryDiagnostic {
    pub http_status: u16,
    pub bytes: Vec<u8>,
    pub truncated: bool,
    pub provider_error_codes: Vec<i64>,
}

impl Executor {
    pub async fn diagnose_registered_d1_query(
        &self,
        validated: &ValidatedD1ReadInventory,
        query_id: &str,
        credential: &AuthCredential,
    ) -> Result<FailedQueryDiagnostic> {
        validate_inventory(&validated.contract.inventory)?;
        let query = validated
            .contract
            .inventory
            .queries
            .iter()
            .find(|q| q.id == query_id)
            .ok_or_else(|| invalid("diagnostic query is not in the registered inventory"))?;
        if !query.parameters.is_empty() || validated.contract.inventory.private_output.is_some() {
            return Err(invalid(
                "diagnostic requires an ordinary non-parameterized registered read",
            ));
        }
        let operation = &validated.contract.operation;
        let mut url = self.builder.base_url.clone();
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|()| invalid("invalid D1 URL"))?;
            segments.pop_if_empty();
            segments.extend([
                "accounts",
                &operation.account_id,
                "d1",
                "database",
                &operation.database_id,
                "query",
            ]);
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .build()?;
        let request = client
            .post(url)
            .timeout(Duration::from_secs(30))
            .header(reqwest::header::ACCEPT, "application/json")
            .header(reqwest::header::ACCEPT_ENCODING, "identity")
            .json(&json!({"sql":query.sql,"params":[]}));
        let response = apply_credential(request, credential)?.send().await?;
        let http_status = response.status().as_u16();
        let (bytes, truncated) = read_bounded_body(response, 65_536).await?;
        let parsed = if truncated {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(Value::Null)
        };
        let provider_error_codes = parsed["errors"]
            .as_array()
            .into_iter()
            .flatten()
            .take(16)
            .filter_map(|error| error["code"].as_i64())
            .collect();
        Ok(FailedQueryDiagnostic {
            http_status,
            bytes,
            truncated,
            provider_error_codes,
        })
    }
}
