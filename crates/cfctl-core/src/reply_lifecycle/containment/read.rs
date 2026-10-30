use super::compiled::hash_text;
use super::validation::{closed, require, time};
use super::{
    ContainmentError, ContainmentResult, ReplyContainmentAttemptObservationV1 as Attempt,
    ReplyContainmentPriorReadV3 as Prior, ReplyContainmentRequestV3 as Request,
    ReplyContainmentSourceStateV3 as Source,
};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};

pub(super) struct PreparedRead {
    pub state: Source,
    pub attempt: Option<Attempt>,
    pub prior: Option<Prior>,
}

fn hash(value: &Value) -> ContainmentResult<String> {
    crate::hash_value(value).map_err(|_| ContainmentError("canonical hash failed"))
}

pub(super) fn validate_pre_read(
    request: &Request,
    envelope: &Value,
    now: DateTime<Utc>,
) -> ContainmentResult<PreparedRead> {
    validate_envelope(request, envelope)?;
    let result = &envelope["result"];
    let observed = time(
        result["observed_at"]
            .as_str()
            .ok_or(ContainmentError("observation missing"))?,
    )?;
    require(
        observed >= time(&request.requested_at)?
            && (-30_000..=300_000)
                .contains(&now.signed_duration_since(observed).num_milliseconds()),
        "observation stale or before request",
    )?;
    let state: Source = closed(result["source_state"].clone())?;
    state.validate(request, now.max(observed))?;
    let attempt: Option<Attempt> = closed(result["attempt_observation"].clone())?;
    let prior: Option<Prior> = closed(result["prior_containment"].clone())?;
    require(
        attempt.is_some() == state.reply_admission.claimed_attempt_id.is_some(),
        "attempt observation missing or unexpected",
    )?;
    if let Some(attempt) = &attempt {
        attempt.validate(&state, observed)?;
    }
    require(
        prior.is_some() == request.replacement.is_some(),
        "prior containment missing or unexpected",
    )?;
    if let Some(prior) = &prior {
        prior.validate(request, &state, observed)?;
    }
    let attempt_hash = attempt
        .as_ref()
        .map(|attempt| hash(&json!(attempt)))
        .transpose()?;
    let expected = json!({"adapter":"maildesk_reply_containment_pre_read_v3","authority":request.control_plane,
        "observed_at":result["observed_at"],"provider_output_retained":false,"body_returned":false,
        "request_sha256":hash(&json!(request))?,"source_state":state,"source_state_sha256":hash(&json!(state))?,
        "match_count":1,"relationship_verified":true,"attempt_observation":attempt,"attempt_observation_sha256":attempt_hash,"prior_containment":prior});
    require(
        result == &expected,
        "pre-read does not match exact source/provenance contract",
    )?;
    Ok(PreparedRead {
        state,
        attempt,
        prior,
    })
}

fn validate_envelope(request: &Request, envelope: &Value) -> ContainmentResult<()> {
    let parsed: crate::ResultEnvelopeV2 = serde_json::from_value(envelope.clone())
        .map_err(|_| ContainmentError("read is not native v2 envelope"))?;
    let keys = [
        "schema_version",
        "generated_at",
        "ok",
        "command",
        "capability_id",
        "operation_id",
        "profile_id",
        "account_id",
        "performed",
        "policy_decision",
        "verification",
        "evidence",
        "result",
        "error",
        "attestation",
    ];
    require(
        envelope.as_object().is_some_and(|value| {
            value.len() == keys.len() && keys.iter().all(|key| value.contains_key(*key))
        }),
        "native envelope is not closed",
    )?;
    require(
        parsed.schema_version == 2
            && parsed.ok
            && parsed.performed
            && parsed.error.is_none()
            && parsed.command == "call"
            && parsed.capability_id.as_deref()
                == Some(super::super::ReplyContainmentOperationV3::PreRead.capability_id())
            && parsed.verification.state == crate::VerificationState::Passed
            && parsed
                .operation_id
                .as_deref()
                .is_some_and(super::validation::reference),
        "read is not a verified native success",
    )?;
    if let Some(policy) = parsed.policy_decision {
        require(
            policy.schema_version == 1
                && policy.disposition == crate::PolicyDisposition::AutoExecute
                && envelope["policy_decision"]
                    .as_object()
                    .is_some_and(|value| value.len() == 4),
            "read policy did not admit execution",
        )?;
    }
    require(
        parsed
            .profile_id
            .as_deref()
            .is_some_and(|value| hash_text(value) == request.control_plane.profile_sha256)
            && parsed
                .account_id
                .as_deref()
                .is_some_and(|value| hash_text(value) == request.control_plane.account_sha256),
        "read profile/account mismatch",
    )
}
