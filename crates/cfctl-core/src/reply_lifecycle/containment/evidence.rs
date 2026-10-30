//! Fixed-origin, complete native read artifacts. Storage identity is the hash
//! of the exact pretty-JSON body, separate from semantic canonical hashes.

use super::validation::{closed, digest, reference, require, time};
use super::{
    ContainmentError, ContainmentResult, ReplyContainmentAttemptObservationV1,
    ReplyContainmentAuthorityV3, ReplyContainmentBindingV3, ReplyContainmentPriorReadV3,
    ReplyContainmentSourceStateV3,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeReadPhaseV3 {
    PreRead,
    Readback,
}
impl NativeReadPhaseV3 {
    #[must_use]
    pub const fn producer(self) -> &'static str {
        match self {
            Self::PreRead => "maildesk_reply_containment_pre_read_v3",
            Self::Readback => "maildesk_reply_containment_readback_v3",
        }
    }
    #[must_use]
    pub fn origin(self) -> Value {
        json!({"native_producer":self.producer(),"version":3})
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreReadResultV3 {
    pub adapter: String,
    pub authority: ReplyContainmentAuthorityV3,
    pub observed_at: String,
    pub provider_output_retained: bool,
    pub body_returned: bool,
    pub request_sha256: String,
    pub source_state: ReplyContainmentSourceStateV3,
    pub source_state_sha256: String,
    pub match_count: u64,
    pub relationship_verified: bool,
    pub attempt_observation: Option<ReplyContainmentAttemptObservationV1>,
    pub attempt_observation_sha256: Option<String>,
    pub prior_containment: Option<ReplyContainmentPriorReadV3>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "Versioned wire receipt records independent safety and verification facts"
)]
pub struct ReadbackResultV3 {
    pub adapter: String,
    pub authority: ReplyContainmentAuthorityV3,
    pub observed_at: String,
    pub provider_output_retained: bool,
    pub body_returned: bool,
    pub status: String,
    pub match_count: u64,
    pub containment_applied: bool,
    pub send_blocked: bool,
    pub replay_allowed: bool,
    pub cannot_unsend: bool,
    pub semantic_bundle_sha256: String,
    pub plan_content_hash: String,
    pub containment_operation_id: String,
    pub binding: ReplyContainmentBindingV3,
    pub relay_terminal: bool,
    pub route_quarantined: bool,
    pub admission_history_preserved: bool,
    pub replacement_lineage_verified: Option<bool>,
}

/// Constructed only by the native read boundary, never by evidence import.
#[derive(Debug, Clone)]
pub struct NativeContainmentReadV3 {
    phase: NativeReadPhaseV3,
    body: Value,
}
impl NativeContainmentReadV3 {
    pub fn new(envelope: &crate::ResultEnvelopeV2) -> ContainmentResult<Self> {
        let phase = match envelope.capability_id.as_deref() {
            Some("star-maildesk-cf.reply-containment-pre-read") => NativeReadPhaseV3::PreRead,
            Some("star-maildesk-cf.reply-containment-read") => NativeReadPhaseV3::Readback,
            _ => return Err(ContainmentError("not a native containment read")),
        };
        require(
            envelope.schema_version == 2
                && envelope.command == "call"
                && envelope.ok
                && envelope.performed
                && envelope.error.is_none()
                && envelope.verification.state == crate::VerificationState::Passed
                && envelope.operation_id.as_deref().is_some_and(reference)
                && envelope.profile_id.as_deref().is_some_and(reference)
                && envelope.account_id.as_deref().is_some_and(reference),
            "native read envelope is incomplete",
        )?;
        if let Some(policy) = &envelope.policy_decision {
            require(
                policy.schema_version == 1
                    && policy.disposition == crate::PolicyDisposition::AutoExecute,
                "native read was not admitted",
            )?;
        }
        match phase {
            NativeReadPhaseV3::PreRead => validate_pre_result(&envelope.result)?,
            NativeReadPhaseV3::Readback => validate_post_result(&envelope.result)?,
        }
        let authority: ReplyContainmentAuthorityV3 = closed(envelope.result["authority"].clone())?;
        require(
            [
                &authority.cfctl_build_sha256,
                &authority.profile_sha256,
                &authority.account_sha256,
                &authority.production_database_sha256,
                &authority.credential_generation_sha256,
            ]
            .iter()
            .all(|value| digest(value)),
            "native read authority digest invalid",
        )?;
        require(
            envelope
                .profile_id
                .as_deref()
                .is_some_and(|value| super::compiled::hash_text(value) == authority.profile_sha256)
                && envelope.account_id.as_deref().is_some_and(|value| {
                    super::compiled::hash_text(value) == authority.account_sha256
                }),
            "outer and inner read authority differ",
        )?;
        if phase == NativeReadPhaseV3::Readback {
            require(
                envelope.operation_id.as_deref()
                    != envelope.result["containment_operation_id"].as_str(),
                "read and mutation must have distinct operation identities",
            )?;
        }
        let body = serde_json::to_value(envelope)
            .map_err(|_| ContainmentError("native read serialization failed"))?;
        require(
            crate::redact_json(&body) == body,
            "native read contains private or unsupported content",
        )?;
        Ok(Self { phase, body })
    }
    pub fn from_value(body: Value) -> ContainmentResult<Self> {
        let envelope = closed(body)?;
        Self::new(&envelope)
    }
    #[must_use]
    pub const fn phase(&self) -> NativeReadPhaseV3 {
        self.phase
    }
    #[must_use]
    pub const fn body(&self) -> &Value {
        &self.body
    }
    pub fn storage_content_hash(&self) -> ContainmentResult<String> {
        use sha2::{Digest, Sha256};
        let bytes = serde_json::to_vec_pretty(&self.body)
            .map_err(|_| ContainmentError("native read serialization failed"))?;
        Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
    }
}

fn validate_pre_result(value: &Value) -> ContainmentResult<()> {
    let result: PreReadResultV3 = closed(value.clone())?;
    require(
        result.adapter == NativeReadPhaseV3::PreRead.producer()
            && !result.body_returned
            && !result.provider_output_retained
            && result.match_count == 1
            && result.relationship_verified
            && digest(&result.request_sha256)
            && digest(&result.source_state_sha256),
        "pre-read result is incomplete",
    )?;
    require(
        crate::hash_value(&json!(result.source_state))
            .ok()
            .as_deref()
            == Some(&result.source_state_sha256),
        "source state hash differs",
    )?;
    time(&result.observed_at)?;
    Ok(())
}
fn validate_post_result(value: &Value) -> ContainmentResult<()> {
    let result: ReadbackResultV3 = closed(value.clone())?;
    require(
        result.adapter == NativeReadPhaseV3::Readback.producer()
            && !result.body_returned
            && !result.provider_output_retained
            && !result.replay_allowed
            && digest(&result.semantic_bundle_sha256)
            && digest(&result.plan_content_hash)
            && reference(&result.containment_operation_id),
        "post-read identity is invalid",
    )?;
    let complete = result.match_count == 1
        && result.containment_applied
        && result.send_blocked
        && result.relay_terminal
        && result.route_quarantined
        && result.admission_history_preserved
        && result.replacement_lineage_verified != Some(false);
    require(
        (result.status == "performed" && complete)
            || (result.status == "ambiguous"
                && !result.containment_applied
                && !result.send_blocked),
        "post-read result is incoherent",
    )?;
    time(&result.observed_at)?;
    Ok(())
}
