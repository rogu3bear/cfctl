use std::time::{Duration, Instant};

use cfctl_core::d1_read_inventory::{
    D1_READ_COMPILER_VERSION, D1ReadInventoryResultV1, D1ReadParameterEvidenceV1,
    D1ReadQueryResultV1, D1ReadQueryV1, D1ReadStatusV1,
};
use serde_json::{Value, json};

use super::{ValidatedD1ReadInventory, invalid, parameters, validate_inventory, value_allowed};
use crate::{AuthCredential, Executor, Result, apply_credential, read_bounded_body};

impl Executor {
    /// Each query crosses the existing credential/HTTP boundary once. There is
    /// no pagination, retry, file sink or generic-SQL capability involved.
    pub async fn execute_d1_read_inventory<F>(
        &self,
        validated: &ValidatedD1ReadInventory,
        credential: &AuthCredential,
        mut reacquire: F,
    ) -> Result<D1ReadInventoryResultV1>
    where
        F: FnMut() -> Result<()>,
    {
        validate_inventory(&validated.contract.inventory)?;
        reacquire()?;
        let inventory = &validated.contract.inventory;
        let start = Instant::now();
        let mut result = D1ReadInventoryResultV1 {
            schema_version: 1,
            compiler_version: D1_READ_COMPILER_VERSION,
            inventory_sha256: validated.call.inventory_sha256.clone(),
            read_complete: false,
            attempted_queries: 0,
            unattempted_queries: 0,
            rows_read: 0,
            response_bytes: 0,
            hard_scan_or_currency_ceiling_established: false,
            application_predicates_evaluated: false,
            results: Vec::new(),
        };
        let mut stopped = None;
        for query in &inventory.queries {
            let remaining = Duration::from_secs(inventory.limits.max_elapsed_seconds)
                .saturating_sub(start.elapsed());
            let classification = stopped.or_else(|| {
                if remaining.is_zero() {
                    Some("run_deadline")
                } else if result.rows_read >= inventory.limits.stop_after_rows_read {
                    Some("row_scan_stop")
                } else if result.response_bytes + query.output.max_bytes
                    > inventory.limits.max_total_response_bytes
                {
                    Some("response_byte_stop")
                } else {
                    None
                }
            });
            if let Some(reason) = classification {
                stopped = Some(reason);
                result
                    .results
                    .push(entry(query, D1ReadStatusV1::Unattempted, reason));
                continue;
            }
            if !dependencies_satisfied(query, &result.results) {
                result.results.push(entry(
                    query,
                    D1ReadStatusV1::Unattempted,
                    "dependency_unsatisfied",
                ));
                continue;
            }
            let Some(parameters) = parameters::bind(query, &result.results) else {
                result.results.push(entry(
                    query,
                    D1ReadStatusV1::Unattempted,
                    "parameter_source_unsatisfied",
                ));
                continue;
            };
            if reacquire().is_err() {
                stopped = Some("source_or_credential_drift");
                result.results.push(entry(
                    query,
                    D1ReadStatusV1::Unattempted,
                    "source_or_credential_drift",
                ));
                continue;
            }
            let remaining = Duration::from_secs(inventory.limits.max_elapsed_seconds)
                .saturating_sub(start.elapsed());
            if remaining.is_zero() {
                stopped = Some("run_deadline");
                result
                    .results
                    .push(entry(query, D1ReadStatusV1::Unattempted, "run_deadline"));
                continue;
            }
            let timeout = remaining.min(Duration::from_secs(30));
            let response = self
                .send_inventory_query(validated, query, &parameters.values, credential, timeout)
                .await;
            let observation = record_response(query, response, parameters.provenance, &mut result);
            if observation.status == D1ReadStatusV1::Rejected {
                stopped = Some("prior_read_rejected");
            }
            result.results.push(observation);
        }
        result.attempted_queries = result.results.iter().filter(|r| r.attempted).count() as u64;
        result.unattempted_queries = result.results.len() as u64 - result.attempted_queries;
        result.read_complete = result
            .results
            .iter()
            .all(|r| r.status == D1ReadStatusV1::Complete);
        validate_result(validated, &result)?;
        Ok(result)
    }

    async fn send_inventory_query(
        &self,
        validated: &ValidatedD1ReadInventory,
        query: &D1ReadQueryV1,
        parameters: &[Value],
        credential: &AuthCredential,
        timeout: Duration,
    ) -> Result<(u16, u64, Value)> {
        let operation = &validated.contract.operation;
        let mut url = self.builder.base_url.clone();
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|()| invalid("invalid D1 base URL"))?;
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
        // upload_client is the existing non-redirecting Executor client. Both
        // authentication and body limits use the canonical shared primitives.
        let outgoing = apply_credential(
            self.upload_client
                .post(url)
                .timeout(timeout)
                .header(reqwest::header::ACCEPT, "application/json")
                .json(&json!({"sql":query.sql,"params":parameters})),
            credential,
        )?;
        let response = outgoing.send().await?;
        let status = response.status().as_u16();
        let media = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                v.split(';')
                    .next()
                    .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"))
            });
        let (bytes, truncated) = read_bounded_body(response, query.output.max_bytes).await?;
        if truncated || !media || status != 200 {
            // Failure bodies can echo SQL or private data; never return them.
            return Ok((status, bytes.len() as u64, Value::Null));
        }
        let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        Ok((status, bytes.len() as u64, body))
    }
}

fn record_response(
    query: &D1ReadQueryV1,
    response: Result<(u16, u64, Value)>,
    provenance: Vec<D1ReadParameterEvidenceV1>,
    result: &mut D1ReadInventoryResultV1,
) -> D1ReadQueryResultV1 {
    let mut observation = entry(
        query,
        D1ReadStatusV1::Rejected,
        "transport_or_response_rejected",
    );
    observation.attempted = true;
    observation.parameter_provenance = provenance;
    if let Ok((status, bytes, body)) = response {
        observation.http_status = Some(status);
        observation.response_bytes = Some(bytes);
        result.response_bytes += bytes;
        if let Ok(rows_read) = qualify_receipt(query, status, &body) {
            observation.status = D1ReadStatusV1::Complete;
            observation.classification = "complete_read".into();
            observation.rows_read = Some(rows_read);
            result.rows_read = result.rows_read.saturating_add(rows_read);
            observation.receipt = Some(body);
        } else {
            observation.classification = "provider_shape_or_output_policy_rejected".into();
        }
    }
    observation
}

fn entry(query: &D1ReadQueryV1, status: D1ReadStatusV1, reason: &str) -> D1ReadQueryResultV1 {
    D1ReadQueryResultV1 {
        query_id: query.id.clone(),
        query_sha256: query.sha256.clone(),
        phase: query.phase.clone(),
        witnesses: query.witnesses.clone(),
        parameter_provenance: Vec::new(),
        status,
        attempted: false,
        classification: reason.into(),
        http_status: None,
        rows_read: None,
        response_bytes: None,
        receipt: None,
    }
}

fn dependencies_satisfied(query: &D1ReadQueryV1, previous: &[D1ReadQueryResultV1]) -> bool {
    query.requires.iter().all(|dependency| {
        previous
            .iter()
            .find(|r| r.query_id == dependency.query_id)
            .is_some_and(|prior| {
                prior.status == D1ReadStatusV1::Complete
                    && match (&dependency.column, &dependency.equals) {
                        (None, None) => true,
                        (Some(column), Some(value)) => prior
                            .receipt
                            .as_ref()
                            .and_then(|body| body.pointer("/result/0/results"))
                            .and_then(Value::as_array)
                            .is_some_and(|rows| {
                                rows.iter().any(|row| row.get(column) == Some(value))
                            }),
                        _ => false,
                    }
            })
    })
}

fn qualify_receipt(
    query: &D1ReadQueryV1,
    status: u16,
    body: &Value,
) -> std::result::Result<u64, ()> {
    let object = body.as_object().ok_or(())?;
    if status != 200
        || object
            .keys()
            .any(|key| !["success", "result", "errors", "messages"].contains(&key.as_str()))
        || body.get("success") != Some(&Value::Bool(true))
        || ["errors", "messages"].iter().any(|field| {
            body.get(*field)
                .is_some_and(|v| v.as_array().is_none_or(|a| !a.is_empty()))
        })
    {
        return Err(());
    }
    let batches = body
        .get("result")
        .and_then(Value::as_array)
        .filter(|a| a.len() == 1)
        .ok_or(())?;
    let batch = batches[0].as_object().ok_or(())?;
    if batch
        .keys()
        .any(|key| !["success", "results", "meta"].contains(&key.as_str()))
        || batch.get("success") != Some(&Value::Bool(true))
    {
        return Err(());
    }
    let rows = batch.get("results").and_then(Value::as_array).ok_or(())?;
    if (rows.len() as u64) < query.output.min_rows || rows.len() as u64 > query.output.max_rows {
        return Err(());
    }
    for row in rows {
        let fields = row.as_object().ok_or(())?;
        if fields.len() != query.output.columns.len()
            || query.output.columns.iter().any(|column| {
                fields
                    .get(&column.name)
                    .is_none_or(|value| !value_allowed(column, value))
            })
        {
            return Err(());
        }
    }
    let meta = batch.get("meta").and_then(Value::as_object).ok_or(())?;
    if ["rows_written", "changes"]
        .iter()
        .any(|key| meta.get(*key).and_then(Value::as_u64) != Some(0))
        || meta.get("changed_db") != Some(&Value::Bool(false))
        || meta.get("total_attempts").and_then(Value::as_u64) != Some(1)
        || meta
            .get("duration")
            .and_then(Value::as_f64)
            .is_none_or(|v| !v.is_finite() || v < 0.0)
    {
        return Err(());
    }
    for (key, value) in meta {
        let valid = match key.as_str() {
            "rows_written" | "changes" | "rows_read" | "last_row_id" | "size_after"
            | "total_attempts" => value.as_u64().is_some(),
            "changed_db" | "served_by_primary" => value.is_boolean(),
            "duration" => value.as_f64().is_some_and(|v| v.is_finite() && v >= 0.0),
            "served_by" | "served_by_colo" | "served_by_region" => {
                value.as_str().is_some_and(|v| {
                    !v.is_empty()
                        && v.len() <= 64
                        && v.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
                })
            }
            "timings" => value.as_object().is_some_and(|v| {
                v.len() == 1
                    && v.get("sql_duration_ms")
                        .and_then(Value::as_f64)
                        .is_some_and(|n| n.is_finite() && n >= 0.0)
            }),
            _ => false,
        };
        if !valid {
            return Err(());
        }
    }
    meta.get("rows_read").and_then(Value::as_u64).ok_or(())
}

/// Required again immediately before the real observation store. A fabricated
/// or altered response cannot reach persistence through a compatibility view.
pub fn validate_result(
    validated: &ValidatedD1ReadInventory,
    result: &D1ReadInventoryResultV1,
) -> Result<()> {
    let queries = &validated.contract.inventory.queries;
    if result.schema_version != 1
        || result.compiler_version != D1_READ_COMPILER_VERSION
        || result.inventory_sha256 != validated.call.inventory_sha256
        || result.results.len() != queries.len()
        || result.hard_scan_or_currency_ceiling_established
        || result.application_predicates_evaluated
    {
        return Err(invalid("read result identity drifted before observation"));
    }
    let mut rows_read = 0_u64;
    let mut bytes = 0_u64;
    let mut attempted = 0_u64;
    for (index, (query, observation)) in queries.iter().zip(&result.results).enumerate() {
        if observation.query_id != query.id
            || observation.query_sha256 != query.sha256
            || observation.phase != query.phase
            || observation.witnesses != query.witnesses
        {
            return Err(invalid(
                "read result query/witness join drifted before observation",
            ));
        }
        if observation.attempted {
            let previous = &result.results[..index];
            let bound = parameters::bind(query, previous)
                .ok_or_else(|| invalid("attempted read has no qualified parameter source"))?;
            if !dependencies_satisfied(query, previous)
                || observation.parameter_provenance != bound.provenance
            {
                return Err(invalid("read dependency or parameter provenance drifted"));
            }
        } else if !observation.parameter_provenance.is_empty() {
            return Err(invalid("unattempted read contains parameter provenance"));
        }
        attempted += u64::from(observation.attempted);
        bytes = bytes.saturating_add(observation.response_bytes.unwrap_or(0));
        if observation
            .response_bytes
            .is_some_and(|b| b > query.output.max_bytes)
        {
            return Err(invalid("read result byte bound exceeded"));
        }
        match observation.status {
            D1ReadStatusV1::Complete => {
                let body = observation
                    .receipt
                    .as_ref()
                    .ok_or_else(|| invalid("qualified receipt missing"))?;
                if serde_json::to_vec(body)
                    .map_err(cfctl_core::CoreError::Serialization)?
                    .len() as u64
                    > query.output.max_bytes
                {
                    return Err(invalid("qualified receipt exceeds its durable byte bound"));
                }
                let count = qualify_receipt(query, observation.http_status.unwrap_or(0), body)
                    .map_err(|()| invalid("unapproved row material refused before observation"))?;
                if !observation.attempted
                    || observation.rows_read != Some(count)
                    || observation.response_bytes.is_none()
                    || observation.classification != "complete_read"
                {
                    return Err(invalid("complete read metadata inconsistent"));
                }
                rows_read = rows_read.saturating_add(count);
            }
            D1ReadStatusV1::Rejected | D1ReadStatusV1::Unattempted => {
                validate_incomplete_entry(observation)?;
            }
        }
    }
    if result.rows_read != rows_read
        || result.response_bytes != bytes
        || result.attempted_queries != attempted
        || result.unattempted_queries != queries.len() as u64 - attempted
        || result.read_complete
            != result
                .results
                .iter()
                .all(|r| r.status == D1ReadStatusV1::Complete)
        || bytes > validated.contract.inventory.limits.max_total_response_bytes
    {
        return Err(invalid(
            "read result completeness or accounting inconsistent",
        ));
    }
    Ok(())
}

fn validate_incomplete_entry(observation: &D1ReadQueryResultV1) -> Result<()> {
    if observation.receipt.is_some()
        || observation.rows_read.is_some()
        || (observation.status == D1ReadStatusV1::Rejected && !observation.attempted)
        || (observation.status == D1ReadStatusV1::Unattempted
            && (observation.attempted
                || observation.http_status.is_some()
                || observation.response_bytes.is_some()))
        || ![
            "transport_or_response_rejected",
            "provider_shape_or_output_policy_rejected",
            "run_deadline",
            "row_scan_stop",
            "response_byte_stop",
            "dependency_unsatisfied",
            "parameter_source_unsatisfied",
            "source_or_credential_drift",
            "prior_read_rejected",
        ]
        .contains(&observation.classification.as_str())
    {
        return Err(invalid(
            "rejected or unattempted read contains unsafe material",
        ));
    }
    Ok(())
}
