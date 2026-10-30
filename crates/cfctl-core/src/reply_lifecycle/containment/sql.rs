//! Fixed, body-free SQL. The entire returned import must execute atomically.
//! A false assertion deliberately raises a `SQLite` error; zero changed rows are
//! never success. No transaction wrappers, helper tables, or caller SQL exist.

use super::compiled::hash_text;
use super::validation::{digest, require};
use super::{
    CompiledReplyContainmentV3 as Candidate, ContainmentError, ContainmentResult,
    ReplyContainmentActionV3 as Action, ReplyContainmentRequestV3 as Request,
    ReplyContainmentSourceStateV3 as Source,
};
use serde_json::{Value, json};
use std::fmt::Write as _;

fn quoted(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}
fn nullable(value: Option<&str>) -> String {
    value.map_or_else(|| "NULL".into(), quoted)
}
fn bare(value: &str) -> ContainmentResult<&str> {
    require(digest(value), "SQL digest requires canonical sha256 prefix")?;
    value
        .strip_prefix("sha256:")
        .ok_or(ContainmentError("SQL digest missing prefix"))
}
fn scalar(value: &Value) -> ContainmentResult<String> {
    match value {
        Value::Null => Ok("NULL".into()),
        Value::Bool(value) => Ok(u8::from(*value).to_string()),
        Value::Number(value) if value.is_u64() => Ok(value.to_string()),
        Value::String(value) => Ok(quoted(value)),
        _ => Err(ContainmentError("SQL record contains a non-scalar value")),
    }
}
fn insert(table: &'static str, values: &[(&'static str, Value)]) -> ContainmentResult<String> {
    let columns = values
        .iter()
        .map(|(key, _)| *key)
        .collect::<Vec<_>>()
        .join(",");
    let values = values
        .iter()
        .map(|(_, value)| scalar(value))
        .collect::<ContainmentResult<Vec<_>>>()?
        .join(",");
    Ok(format!(
        "INSERT INTO {table} ({columns}) VALUES ({values});\n"
    ))
}
fn assertion(predicate: &str) -> String {
    format!("SELECT CASE WHEN ({predicate}) THEN 1 ELSE json('{{') END;\n")
}

/// These are exact relational inputs, not hashes echoed from the request.
fn source_predicate(state: &Source) -> ContainmentResult<String> {
    let admission = &state.reply_admission;
    let status = serde_json::to_value(admission.status)
        .map_err(|_| ContainmentError("status serialization failed"))?;
    let claim = admission
        .claimed_attempt_sha256
        .as_deref()
        .map(bare)
        .transpose()?;
    Ok(format!(
        "rr.id = {relay} AND ra.id = {admission} AND ra.relay_id = rr.id AND ra.route_id = rr.route_id AND ra.thread_id = rr.thread_id AND rr.route_id = {route} AND ra.thread_id = {thread} AND rr.revoked_at IS {revoked} AND rr.superseded_by_relay_id IS {superseded} AND rr.expires_at = {relay_expiry} AND ra.status = {status} AND ra.transaction_sha256 = {transaction} AND ra.correlation_sha256 = {correlation} AND ra.scope_manifest_sha256 = {scope} AND ra.candidate_sha256 = {candidate} AND ra.claimed_attempt_id IS {claim_id} AND ra.claimed_payload_sha256 IS {payload} AND ra.claimed_attempt_sha256 IS {claim} AND ra.provider_boundary_at IS {boundary} AND ra.terminal_at IS {terminal} AND ra.expires_at = {admission_expiry}",
        relay = quoted(&state.relay.id),
        admission = quoted(&admission.id),
        route = quoted(&state.route_id),
        thread = quoted(&admission.thread_id),
        revoked = nullable(state.relay.revoked_at.as_deref()),
        superseded = nullable(state.relay.superseded_by_relay_id.as_deref()),
        relay_expiry = quoted(&state.relay.expires_at),
        status = scalar(&status)?,
        transaction = quoted(bare(&admission.transaction_sha256)?),
        correlation = quoted(bare(&admission.correlation_sha256)?),
        scope = quoted(bare(&admission.scope_manifest_sha256)?),
        candidate = quoted(bare(&admission.candidate_sha256)?),
        claim = nullable(claim),
        claim_id = nullable(admission.claimed_attempt_id.as_deref()),
        payload = nullable(
            admission
                .claimed_payload_sha256
                .as_deref()
                .map(bare)
                .transpose()?
        ),
        boundary = nullable(admission.provider_boundary_at.as_deref()),
        terminal = nullable(admission.terminal_at.as_deref()),
        admission_expiry = quoted(&admission.expires_at)
    ))
}

const JOIN: &str = "reply_relays rr JOIN reply_admissions ra ON ra.relay_id = rr.id JOIN alias_routes ar ON ar.id = rr.route_id JOIN threads th ON th.id = rr.thread_id LEFT JOIN relay_attempts att ON att.id = ra.claimed_attempt_id AND att.relay_id = rr.id AND att.admission_id = ra.id AND att.admission_kind = 'canary' AND att.transaction_sha256 = ra.transaction_sha256 AND att.attempt_sha256 = ra.claimed_attempt_sha256 AND att.claimed_payload_sha256 = ra.claimed_payload_sha256";

/// Exactly one related source row, projected without body, addresses, tokens,
/// message IDs, or unselected database columns.
pub fn pre_read(request: &Request) -> ContainmentResult<String> {
    source_query(request, "")
}

fn source_query(request: &Request, extra_columns: &str) -> ContainmentResult<String> {
    request.validate()?;
    let replacement = request
        .replacement
        .as_ref()
        .map_or_else(|| "NULL".into(), |value| quoted(&value.relay_id));
    let source = &request.source;
    Ok(format!(
        "SELECT json_object('route_id',rr.route_id,'relay',json_object('id',rr.id,'route_id',rr.route_id,'thread_id',rr.thread_id,'revoked_at',rr.revoked_at,'superseded_by_relay_id',rr.superseded_by_relay_id,'expires_at',rr.expires_at),'reply_admission',json_object('id',ra.id,'thread_id',ra.thread_id,'route_id',ra.route_id,'relay_id',ra.relay_id,'status',ra.status,'transaction_sha256','sha256:'||ra.transaction_sha256,'correlation_sha256','sha256:'||ra.correlation_sha256,'scope_manifest_sha256','sha256:'||ra.scope_manifest_sha256,'candidate_sha256','sha256:'||ra.candidate_sha256,'claimed_attempt_id',ra.claimed_attempt_id,'claimed_attempt_sha256',CASE WHEN ra.claimed_attempt_sha256 IS NULL THEN NULL ELSE 'sha256:'||ra.claimed_attempt_sha256 END,'claimed_payload_sha256',CASE WHEN ra.claimed_payload_sha256 IS NULL THEN NULL ELSE 'sha256:'||ra.claimed_payload_sha256 END,'provider_boundary_at',ra.provider_boundary_at,'terminal_at',ra.terminal_at,'expires_at',ra.expires_at),'replacement',CASE WHEN rp.id IS NULL THEN NULL ELSE json_object('id',rp.id,'route_id',rp.route_id,'thread_id',rp.thread_id,'revoked_at',rp.revoked_at,'superseded_by_relay_id',rp.superseded_by_relay_id,'expires_at',rp.expires_at,'created_at',rp.created_at) END) AS cfctl_reply_containment_source,att.id AS attempt_id,att.status AS attempt_status,att.provider_message_id AS private_provider_message_id,att.error_code AS attempt_error_code,att.updated_at AS attempt_updated_at{extra_columns} FROM {JOIN} LEFT JOIN reply_relays rp ON rp.id = {replacement} WHERE rr.id = {relay} AND ra.id = {admission} AND rr.route_id = {route} AND ra.route_id = rr.route_id AND ra.thread_id = rr.thread_id LIMIT 2",
        relay = quoted(&source.relay_id),
        admission = quoted(&source.reply_admission_id),
        route = quoted(&source.route_id)
    ))
}

/// A `PlanV2` binding is supplied only after native plan integrity validation.
/// The semantic bundle digest never substitutes for `PlanV2.content_hash`.
pub fn mutation(
    candidate: &Candidate,
    operation_id: &str,
    plan_content_hash: &str,
    private_provider_message_id: Option<&str>,
) -> ContainmentResult<String> {
    candidate.request.validate()?;
    require(
        super::validation::reference(operation_id),
        "invalid native plan operation identity",
    )?;
    require(
        digest(plan_content_hash),
        "invalid native plan content hash",
    )?;
    let predicate = source_predicate(&candidate.state)?;
    let attempt = attempt_predicate(candidate, private_provider_message_id)?;
    let eligibility=match candidate.request.action {
        Action::PreSendRollback=>"julianday(rr.expires_at)>julianday('now') AND julianday(ra.expires_at)>julianday('now')".into(),
        Action::PostBoundaryContainment=>"ra.provider_boundary_at IS NOT NULL".into(),
        Action::Replacement=>replacement_predicate(candidate)?,
    };
    let mut sql = assertion(&format!(
        "(SELECT count(*) FROM {JOIN} WHERE {predicate} AND {attempt} AND {eligibility})=1"
    ));
    sql.push_str(&plan_record(
        candidate,
        operation_id,
        plan_content_hash,
        false,
    )?);
    sql.push_str(&match candidate.request.action {
        Action::PreSendRollback => revoke(candidate, true)?,
        Action::PostBoundaryContainment => revoke(candidate, false)?,
        Action::Replacement => replace(candidate)?,
    });
    if candidate.request.action != Action::Replacement {
        sql.push_str(&quarantine(candidate, plan_content_hash)?);
    }
    sql.push_str(&plan_record(
        candidate,
        operation_id,
        plan_content_hash,
        true,
    )?);
    Ok(sql)
}

fn attempt_predicate(candidate: &Candidate, private_id: Option<&str>) -> ContainmentResult<String> {
    let Some(attempt) = &candidate.attempt else {
        require(private_id.is_none(), "unexpected provider message identity")?;
        return Ok("ra.claimed_attempt_id IS NULL AND att.id IS NULL".into());
    };
    require(
        private_id.map(hash_text) == attempt.provider_message_id_sha256,
        "private provider message identity differs from observed hash",
    )?;
    let admission = &candidate.state.reply_admission;
    Ok(format!(
        "att.id = {} AND att.status = {} AND att.provider_message_id IS {} AND att.error_code IS {} AND att.updated_at = {}",
        nullable(admission.claimed_attempt_id.as_deref()),
        scalar(&json!(attempt.status))?,
        nullable(private_id),
        nullable(attempt.error_code.as_deref()),
        quoted(&attempt.updated_at)
    ))
}

fn revoke(candidate: &Candidate, pre_send: bool) -> ContainmentResult<String> {
    let request = &candidate.request;
    let state = &candidate.state;
    let mut sql = format!(
        "UPDATE reply_relays SET revoked_at=coalesce(revoked_at,{}),revocation_reason=CASE WHEN revoked_at IS NULL THEN {} ELSE revocation_reason END WHERE id={};\n",
        quoted(&request.requested_at),
        scalar(&json!(request.reason))?,
        quoted(&state.relay.id)
    );
    sql.push_str(&assertion("changes()=1"));
    if pre_send {
        writeln!(sql,"UPDATE reply_admissions SET status='revoked',revoked_at={},terminal_at={} WHERE id={} AND status IN ('admitted','claimed') AND provider_boundary_at IS NULL AND terminal_at IS NULL AND claimed_attempt_id IS {} AND claimed_attempt_sha256 IS {} AND claimed_payload_sha256 IS {};",quoted(&request.requested_at),quoted(&request.requested_at),quoted(&state.reply_admission.id),nullable(state.reply_admission.claimed_attempt_id.as_deref()),nullable(state.reply_admission.claimed_attempt_sha256.as_deref().map(bare).transpose()?),nullable(state.reply_admission.claimed_payload_sha256.as_deref().map(bare).transpose()?)).map_err(|_|ContainmentError("SQL formatting failed"))?;
        sql.push_str(&assertion("changes()=1"));
    }
    Ok(sql)
}

fn replacement_predicate(candidate: &Candidate) -> ContainmentResult<String> {
    let state = &candidate.state;
    let replacement = state
        .replacement
        .as_ref()
        .ok_or(ContainmentError("replacement missing"))?;
    let prior = candidate
        .prior
        .as_ref()
        .ok_or(ContainmentError("prior native read missing"))?;
    Ok(format!(
        "EXISTS (SELECT 1 FROM reply_relays rp WHERE rp.id={} AND rp.route_id=rr.route_id AND rp.thread_id=rr.thread_id AND rp.revoked_at IS NULL AND rp.superseded_by_relay_id IS NULL AND rp.created_at={} AND rp.expires_at={} AND julianday(rp.expires_at)>julianday('now')) AND (rr.revoked_at IS NOT NULL OR julianday(rr.expires_at)<=julianday('now')) AND rr.superseded_by_relay_id IS NULL AND EXISTS (SELECT 1 FROM reply_containment_plan_records pr JOIN route_outbound_quarantines q ON q.containment_plan_sha256=pr.plan_sha256 AND q.route_id=pr.route_id AND q.relay_id=pr.relay_id AND q.reply_admission_id=pr.reply_admission_id WHERE pr.containment_transaction_sha256={} AND pr.controller_transaction_sha256={} AND pr.plan_sha256={} AND pr.operation_id_sha256={} AND pr.outcome='performed' AND pr.match_count=1 AND pr.route_id=rr.route_id AND pr.relay_id=rr.id AND pr.reply_admission_id=ra.id AND q.action='quarantine' AND NOT EXISTS (SELECT 1 FROM route_outbound_quarantines released WHERE released.release_of_quarantine_id=q.id AND released.action='release'))",
        quoted(&replacement.id),
        quoted(&replacement.created_at),
        quoted(&replacement.expires_at),
        quoted(bare(&prior.binding.containment_transaction_sha256)?),
        quoted(bare(&prior.binding.controller_transaction_sha256)?),
        quoted(bare(&prior.plan.content_hash)?),
        quoted(bare(&hash_text(&prior.plan.operation_id))?)
    ))
}

fn replace(candidate: &Candidate) -> ContainmentResult<String> {
    let state = &candidate.state;
    let request = &candidate.request;
    let replacement = state
        .replacement
        .as_ref()
        .ok_or(ContainmentError("replacement missing"))?;
    let prior = candidate
        .prior
        .as_ref()
        .ok_or(ContainmentError("prior native read missing"))?;
    let mut sql = insert(
        "reply_relay_replacements",
        &[
            (
                "id",
                json!(format!(
                    "relay-supersession:{}",
                    &candidate.transaction[7..39]
                )),
            ),
            ("source_relay_id", json!(state.relay.id)),
            ("replacement_relay_id", json!(replacement.id)),
            (
                "controller_transaction_sha256",
                json!(bare(&request.controller.transaction_sha256)?),
            ),
            (
                "source_containment_receipt_sha256",
                json!(bare(&prior.read_content_hash)?),
            ),
            ("created_at", json!(request.requested_at)),
        ],
    )?;
    writeln!(sql,"UPDATE reply_relays SET superseded_by_relay_id={},supersession_controller_transaction_sha256={} WHERE id={} AND superseded_by_relay_id IS NULL;",quoted(&replacement.id),quoted(bare(&request.controller.transaction_sha256)?),quoted(&state.relay.id)).map_err(|_|ContainmentError("SQL formatting failed"))?;
    sql.push_str(&assertion("changes()=1"));
    Ok(sql)
}

fn quarantine(candidate: &Candidate, plan_hash: &str) -> ContainmentResult<String> {
    let request = &candidate.request;
    let state = &candidate.state;
    let prefix = &candidate.transaction[7..39];
    insert(
        "route_outbound_quarantines",
        &[
            ("id", json!(format!("route-quarantine:{prefix}"))),
            ("route_id", json!(state.route_id)),
            ("relay_id", json!(state.relay.id)),
            ("reply_admission_id", json!(state.reply_admission.id)),
            (
                "controller_transaction_sha256",
                json!(bare(&request.controller.transaction_sha256)?),
            ),
            ("action", json!("quarantine")),
            ("reason", json!(request.reason)),
            ("containment_plan_sha256", json!(bare(plan_hash)?)),
            ("source_containment_plan_sha256", Value::Null),
            ("release_of_quarantine_id", Value::Null),
            ("quarantined_at", json!(request.requested_at)),
        ],
    )
}

fn plan_record(
    candidate: &Candidate,
    operation_id: &str,
    plan_hash: &str,
    performed: bool,
) -> ContainmentResult<String> {
    let request = &candidate.request;
    let state = &candidate.state;
    let prefix = &candidate.transaction[7..39];
    let planned_id = format!("containment-plan:{prefix}");
    insert(
        "reply_containment_plan_records",
        &[
            (
                "id",
                json!(if performed {
                    format!("{planned_id}:performed")
                } else {
                    planned_id.clone()
                }),
            ),
            (
                "controller_transaction_sha256",
                json!(bare(&request.controller.transaction_sha256)?),
            ),
            (
                "containment_transaction_sha256",
                json!(bare(&candidate.transaction)?),
            ),
            ("route_id", json!(state.route_id)),
            ("relay_id", json!(state.relay.id)),
            ("reply_admission_id", json!(state.reply_admission.id)),
            ("plan_sha256", json!(bare(plan_hash)?)),
            (
                "pre_read_receipt_sha256",
                json!(bare(&candidate.pre_read_hash)?),
            ),
            ("authority_sha256", json!(bare(&candidate.authority_hash)?)),
            (
                "operation_id_sha256",
                if performed {
                    json!(bare(&hash_text(operation_id))?)
                } else {
                    Value::Null
                },
            ),
            ("operation_kind", json!(request.action)),
            (
                "cannot_unsend",
                json!(request.action == Action::PostBoundaryContainment),
            ),
            (
                "terminal_provider_evidence_sha256",
                json!(if request.action == Action::PostBoundaryContainment {
                    candidate.attempt_hash.as_deref().map(bare).transpose()?
                } else {
                    None
                }),
            ),
            (
                "outcome",
                json!(if performed { "performed" } else { "planned" }),
            ),
            (
                "match_count",
                if performed { json!(1) } else { Value::Null },
            ),
            (
                "prior_record_id",
                if performed {
                    json!(planned_id)
                } else {
                    Value::Null
                },
            ),
            ("observed_at", json!(request.requested_at)),
        ],
    )
}

/// Read all outcome facts in the same database snapshot as the source rows.
pub fn readback(
    candidate: &Candidate,
    operation_id: &str,
    plan_hash: &str,
) -> ContainmentResult<String> {
    require(
        super::validation::reference(operation_id) && digest(plan_hash),
        "invalid readback plan identity",
    )?;
    let state = &candidate.state;
    let route = quoted(&state.route_id);
    let relay = quoted(&state.relay.id);
    let admission = quoted(&state.reply_admission.id);
    let effective_plan = if candidate.request.action == Action::Replacement {
        &candidate
            .prior
            .as_ref()
            .ok_or(ContainmentError("prior read missing"))?
            .plan
            .content_hash
    } else {
        plan_hash
    };
    let replacement = if candidate.request.action == Action::Replacement {
        let target = state
            .replacement
            .as_ref()
            .ok_or(ContainmentError("replacement missing"))?;
        let prior = candidate
            .prior
            .as_ref()
            .ok_or(ContainmentError("prior read missing"))?;
        format!(
            "EXISTS (SELECT 1 FROM reply_relay_replacements replacement JOIN reply_relays source ON source.id=replacement.source_relay_id WHERE replacement.source_relay_id={relay} AND replacement.replacement_relay_id={} AND replacement.controller_transaction_sha256={} AND replacement.source_containment_receipt_sha256={} AND source.superseded_by_relay_id=replacement.replacement_relay_id AND source.supersession_controller_transaction_sha256=replacement.controller_transaction_sha256)",
            quoted(&target.id),
            quoted(bare(&candidate.request.controller.transaction_sha256)?),
            quoted(bare(&prior.read_content_hash)?)
        )
    } else {
        "NULL".into()
    };
    let columns = format!(
        ",(SELECT count(*) FROM reply_containment_plan_records pr WHERE pr.containment_transaction_sha256={} AND pr.controller_transaction_sha256={} AND pr.plan_sha256={} AND pr.operation_id_sha256={} AND pr.route_id={route} AND pr.relay_id={relay} AND pr.reply_admission_id={admission} AND pr.outcome='performed' AND pr.match_count=1) AS plan_count,EXISTS (SELECT 1 FROM route_outbound_quarantines q WHERE q.route_id={route} AND q.relay_id={relay} AND q.reply_admission_id={admission} AND q.containment_plan_sha256={} AND q.action='quarantine' AND NOT EXISTS (SELECT 1 FROM route_outbound_quarantines released WHERE released.release_of_quarantine_id=q.id AND released.action='release')) AS route_quarantined,{replacement} AS replacement_matches",
        quoted(bare(&candidate.transaction)?),
        quoted(bare(&candidate.request.controller.transaction_sha256)?),
        quoted(bare(plan_hash)?),
        quoted(bare(&hash_text(operation_id))?),
        quoted(bare(effective_plan)?)
    );
    source_query(&candidate.request, &columns)
}
