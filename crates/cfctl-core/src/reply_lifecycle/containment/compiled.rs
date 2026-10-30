use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use super::read::validate_pre_read;
use super::validation::require;
use super::{
    ContainmentError, ContainmentResult, ReplyContainmentActionV3 as Action,
    ReplyContainmentAttemptObservationV1 as Attempt, ReplyContainmentPriorReadV3 as Prior,
    ReplyContainmentRequestV3 as Request, ReplyContainmentSourceStateV3 as Source,
};

/// A semantic candidate is not a native `PlanV2` and grants no execution authority.
/// Its fields are private so the SQL producer accepts only exact compiler output.
#[derive(Debug, Clone)]
pub struct CompiledReplyContainmentV3 {
    pub(super) request: Request,
    pub(super) state: Source,
    pub(super) attempt: Option<Attempt>,
    pub(super) prior: Option<Prior>,
    pub(super) transaction: String,
    pub(super) pre_read_hash: String,
    pub(super) semantic_bundle: String,
    pub(super) attempt_hash: Option<String>,
    pub(super) authority_hash: String,
    pub(super) compiled: Value,
}

fn hash(value: &Value) -> ContainmentResult<String> {
    crate::hash_value(value).map_err(|_| ContainmentError("canonical hash failed"))
}

pub(super) fn hash_text(value: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{}", hex::encode(Sha256::digest(value.as_bytes())))
}

impl CompiledReplyContainmentV3 {
    /// Runtime must separately authenticate the native pre-read's stored origin.
    /// This boundary verifies its complete semantics and the pinned compiler's output.
    pub fn bind(
        request: Request,
        pre_read: &Value,
        actual: &Value,
        now: DateTime<Utc>,
    ) -> ContainmentResult<Self> {
        request.validate_fresh(now)?;
        let observed = validate_pre_read(&request, pre_read, now)?;
        let state = observed.state;
        let attempt = observed.attempt;
        let prior = observed.prior;
        let pre_read_hash = hash(pre_read)?;
        let operation = pre_read["operation_id"]
            .as_str()
            .ok_or(ContainmentError("pre-read operation is missing"))?;
        let transaction = hash(
            &json!({"request":request,"pre_read_receipt_sha256":pre_read_hash,"pre_read_operation_id":operation}),
        )?;
        let attempt_hash = attempt
            .as_ref()
            .map(|value| hash(&json!(value)))
            .transpose()?;
        let authority_hash = hash(&json!(request.control_plane))?;
        let records = records(
            &request,
            &state,
            prior.as_ref(),
            &transaction,
            &pre_read_hash,
            &authority_hash,
            attempt_hash.as_deref(),
        )?;
        let semantic_bundle = hash(
            &json!({"capability_id":super::super::ReplyContainmentOperationV3::Apply.capability_id(),"transaction_sha256":transaction,"records":records}),
        )?;
        let binding = json!({
            "containment_transaction_sha256":transaction,"controller_transaction_sha256":request.controller.transaction_sha256,
            "source_admission_transaction_sha256":state.reply_admission.transaction_sha256,
            "correlation_sha256":request.controller.correlation_sha256,"scope_manifest_sha256":request.controller.scope_manifest_sha256,
            "source_state_sha256":hash(&json!(state))?,"route_ref_sha256":hash_text(&state.route_id),
            "relay_ref_sha256":hash_text(&state.relay.id),"reply_admission_ref_sha256":hash_text(&state.reply_admission.id),
            "attempt_observation_sha256":attempt_hash,
        });
        let expected = json!({"schema_version":3,"kind":"maildesk_reply_containment","status":"plan_required",
            "performed":false,"provider_boundary_performed":false,"send_blocked":false,"replay_allowed":false,
            "corrective_send_allowed":false,"retry_allowed":false,"cannot_unsend":request.action==Action::PostBoundaryContainment,
            "attempt_observation_sha256":attempt_hash,"source_state":state,"attempt_observation":attempt,"prior_containment":prior,"readback_binding":binding,"authority":request.control_plane,
            "pre_read_operation_id":operation,"pre_read_receipt_sha256":pre_read_hash,"request_sha256":hash(&json!(request))?,
            "transaction_sha256":transaction,"plan":{"capability_id":super::super::ReplyContainmentOperationV3::Apply.capability_id(),
                "effect":"plan_v2_required","semantic_bundle_sha256":semantic_bundle,"records":records},
            "rollback":{"strategy":"new_controller_transaction","old_relay_reactivation_allowed":false,"old_relay_expiry_extension_allowed":false},"body_free":true});
        require(
            actual == &expected,
            "compiler output differs from fixed containment semantics",
        )?;
        Ok(Self {
            request,
            state,
            attempt,
            prior,
            transaction,
            pre_read_hash,
            semantic_bundle,
            attempt_hash,
            authority_hash,
            compiled: expected,
        })
    }

    #[must_use]
    pub fn request(&self) -> &Request {
        &self.request
    }
    #[must_use]
    pub fn compiled(&self) -> &Value {
        &self.compiled
    }
    #[must_use]
    pub fn semantic_bundle(&self) -> &str {
        &self.semantic_bundle
    }
    #[must_use]
    pub fn transaction(&self) -> &str {
        &self.transaction
    }
}

fn records(
    request: &Request,
    state: &Source,
    prior: Option<&Prior>,
    transaction: &str,
    pre_read_hash: &str,
    authority_hash: &str,
    attempt_hash: Option<&str>,
) -> ContainmentResult<Vec<Value>> {
    let prefix = transaction
        .get(7..39)
        .ok_or(ContainmentError("transaction hash is invalid"))?;
    let controller = &request.controller.transaction_sha256;
    let admission = &state.reply_admission;
    let mut rows = Vec::new();
    if request.action == Action::Replacement {
        let replacement = state
            .replacement
            .as_ref()
            .ok_or(ContainmentError("replacement missing"))?;
        rows.push(json!({"kind":"relay_supersession","id":format!("relay-supersession:{prefix}"),"controller_transaction_sha256":controller,
            "source_relay_id":state.relay.id,"replacement_relay_id":replacement.id,"route_id":state.route_id,"thread_id":admission.thread_id,
            "source_admission_transaction_sha256":admission.transaction_sha256,"source_containment_read_content_hash":prior.ok_or(ContainmentError("prior read missing"))?.read_content_hash,
            "replacement_expires_at":replacement.expires_at,"replacement_created_at":replacement.created_at,
            "source_relay_reactivation_allowed":false,"source_relay_expiry_extension_allowed":false}));
    } else {
        rows.push(json!({"kind":"relay_revocation","id":format!("relay-revocation:{prefix}"),"controller_transaction_sha256":controller,
            "relay_id":state.relay.id,"reason":request.reason,"revoked_at":state.relay.revoked_at.as_ref().unwrap_or(&request.requested_at),
            "expected_revoked_at":state.relay.revoked_at,"expected_expires_at":state.relay.expires_at,"expected_superseded_by_relay_id":state.relay.superseded_by_relay_id}));
        let mut admission_row = json!({"id":format!("admission-containment:{prefix}"),"controller_transaction_sha256":controller,
            "reply_admission_id":admission.id,"reply_admission_transaction_sha256":admission.transaction_sha256,"expected_status":admission.status,
            "expected_claimed_attempt_id":admission.claimed_attempt_id,"expected_claimed_payload_sha256":admission.claimed_payload_sha256,"expected_claimed_attempt_sha256":admission.claimed_attempt_sha256,"expected_provider_boundary_at":admission.provider_boundary_at,
            "expected_terminal_at":admission.terminal_at,"expected_expires_at":admission.expires_at});
        let map = admission_row
            .as_object_mut()
            .ok_or(ContainmentError("admission row is not object"))?;
        if request.action == Action::PostBoundaryContainment {
            map.insert("kind".into(), json!("reply_admission_assertion"));
            map.insert("preserve_original_row".into(), json!(true));
        } else {
            map.insert("kind".into(), json!("reply_admission_revocation"));
            map.insert("terminal_status".into(), json!("revoked"));
            map.insert("revoked_at".into(), json!(request.requested_at));
        }
        rows.push(admission_row);
        rows.push(json!({"kind":"route_outbound_quarantine","id":format!("route-quarantine:{prefix}"),"controller_transaction_sha256":controller,
            "route_id":state.route_id,"relay_id":state.relay.id,"reply_admission_id":admission.id,"action":"quarantine","reason":request.reason,"quarantined_at":request.requested_at}));
    }
    rows.push(json!({"kind":"containment_plan","id":format!("containment-plan:{prefix}"),"controller_transaction_sha256":controller,
        "transaction_sha256":transaction,"correlation_sha256":request.controller.correlation_sha256,"scope_manifest_sha256":request.controller.scope_manifest_sha256,
        "operation_kind":request.action,"cannot_unsend":request.action==Action::PostBoundaryContainment,"attempt_observation_sha256":attempt_hash,
        "authority_sha256":authority_hash,"pre_read_receipt_sha256":pre_read_hash,"source_state_sha256":hash(&json!(state))?,
        "route_id":state.route_id,"relay_id":state.relay.id,"reply_admission_id":admission.id,"outcome":"planned","record_count":rows.len()+1}));
    Ok(rows)
}
