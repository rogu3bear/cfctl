//! Reduces the fixed private D1 projection to a public body-free observation.

use super::compiled::hash_text;
use super::validation::{closed, require};
use super::{
    ContainmentError, ContainmentResult, ReplyContainmentAttemptObservationV1 as Attempt,
    ReplyContainmentPriorReadV3 as Prior, ReplyContainmentRequestV3 as Request,
    ReplyContainmentSourceStateV3 as Source, evidence::PreReadResultV3,
};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};

pub const ROW_KEYS: [&str; 6] = [
    "cfctl_reply_containment_source",
    "attempt_id",
    "attempt_status",
    "private_provider_message_id",
    "attempt_error_code",
    "attempt_updated_at",
];

/// The raw ID is retained only for a private CAS comparison, never serialized.
pub struct SourceObservationV3 {
    pub source: Source,
    pub attempt: Option<Attempt>,
    private_provider_message_id: Option<String>,
}
impl SourceObservationV3 {
    pub fn from_row(row: &Map<String, Value>) -> ContainmentResult<Self> {
        require(
            ROW_KEYS.iter().all(|key| row.contains_key(*key)),
            "private D1 row fields missing",
        )?;
        let source: Source = closed(
            serde_json::from_str(
                row[ROW_KEYS[0]]
                    .as_str()
                    .ok_or(ContainmentError("source projection must be encoded JSON"))?,
            )
            .map_err(|_| ContainmentError("source projection malformed"))?,
        )?;
        let private_provider_message_id = nullable(row, "private_provider_message_id")?;
        require(
            private_provider_message_id
                .as_ref()
                .is_none_or(|value| value.len() <= 4096),
            "provider message identity exceeds bound",
        )?;
        let id = nullable(row, "attempt_id")?;
        let attempt = if source.reply_admission.claimed_attempt_id.is_some() {
            require(
                id == source.reply_admission.claimed_attempt_id,
                "stored claim has no exact related attempt",
            )?;
            let admission = &source.reply_admission;
            Some(Attempt {
                schema_version: 1,
                kind: "maildesk_reply_attempt_observation".into(),
                admission_ref_sha256: hash_text(&admission.id),
                relay_ref_sha256: hash_text(&source.relay.id),
                source_admission_transaction_sha256: admission.transaction_sha256.clone(),
                attempt_ref_sha256: hash_text(
                    id.as_deref().ok_or(ContainmentError("claim missing"))?,
                ),
                attempt_sha256: admission
                    .claimed_attempt_sha256
                    .clone()
                    .ok_or(ContainmentError("claim digest missing"))?,
                claimed_payload_sha256: admission
                    .claimed_payload_sha256
                    .clone()
                    .ok_or(ContainmentError("claim payload missing"))?,
                status: serde_json::from_value(row["attempt_status"].clone())
                    .map_err(|_| ContainmentError("attempt status outside closed domain"))?,
                provider_message_id_sha256: private_provider_message_id.as_deref().map(hash_text),
                error_code: nullable(row, "attempt_error_code")?,
                updated_at: nullable(row, "attempt_updated_at")?
                    .ok_or(ContainmentError("attempt update missing"))?,
            })
        } else {
            require(
                id.is_none()
                    && private_provider_message_id.is_none()
                    && row["attempt_status"].is_null()
                    && row["attempt_error_code"].is_null()
                    && row["attempt_updated_at"].is_null(),
                "unclaimed source contains attempt state",
            )?;
            None
        };
        Ok(Self {
            source,
            attempt,
            private_provider_message_id,
        })
    }
    #[must_use]
    pub fn private_provider_message_id(&self) -> Option<&str> {
        self.private_provider_message_id.as_deref()
    }

    pub fn pre_read(
        &self,
        request: &Request,
        prior: Option<Prior>,
        observed: DateTime<Utc>,
    ) -> ContainmentResult<PreReadResultV3> {
        request.validate_fresh(observed)?;
        self.source.validate(request, observed)?;
        if let Some(attempt) = &self.attempt {
            attempt.validate(&self.source, observed)?;
        }
        require(
            prior.is_some() == request.replacement.is_some(),
            "prior native read missing or unexpected",
        )?;
        if let Some(prior) = &prior {
            prior.validate(request, &self.source, observed)?;
        }
        let hash = |value: &Value| {
            crate::hash_value(value).map_err(|_| ContainmentError("observation hash failed"))
        };
        Ok(PreReadResultV3 {
            adapter: "maildesk_reply_containment_pre_read_v3".into(),
            authority: request.control_plane.clone(),
            observed_at: observed.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            provider_output_retained: false,
            body_returned: false,
            request_sha256: hash(&json!(request))?,
            source_state: self.source.clone(),
            source_state_sha256: hash(&json!(self.source))?,
            match_count: 1,
            relationship_verified: true,
            attempt_observation: self.attempt.clone(),
            attempt_observation_sha256: self
                .attempt
                .as_ref()
                .map(|value| hash(&json!(value)))
                .transpose()?,
            prior_containment: prior,
        })
    }
}
fn nullable(row: &Map<String, Value>, key: &str) -> ContainmentResult<Option<String>> {
    if row[key].is_null() {
        Ok(None)
    } else {
        row[key]
            .as_str()
            .map(|value| Some(value.to_owned()))
            .ok_or(ContainmentError("private row field must be nullable text"))
    }
}

impl super::CompiledReplyContainmentV3 {
    /// The caller binds this query and plan identity to an authenticated stored
    /// `PlanV2`; this function only reduces its actual database readback.
    pub fn readback(
        &self,
        row: &Map<String, Value>,
        plan: &super::ReplyContainmentPlanBindingV3,
        observed: DateTime<Utc>,
    ) -> ContainmentResult<super::evidence::ReadbackResultV3> {
        let actual = SourceObservationV3::from_row(row)?;
        let mut expected = self.state.clone();
        match self.request.action {
            super::ReplyContainmentActionV3::PreSendRollback => {
                expected.relay.revoked_at = Some(self.request.requested_at.clone());
                expected.reply_admission.status = super::ReplyContainmentAdmissionStatusV3::Revoked;
                expected.reply_admission.terminal_at = Some(self.request.requested_at.clone());
            }
            super::ReplyContainmentActionV3::PostBoundaryContainment => {
                expected
                    .relay
                    .revoked_at
                    .get_or_insert_with(|| self.request.requested_at.clone());
            }
            super::ReplyContainmentActionV3::Replacement => {
                expected.relay.superseded_by_relay_id = Some(
                    expected
                        .replacement
                        .as_ref()
                        .ok_or(ContainmentError("replacement missing"))?
                        .id
                        .clone(),
                );
            }
        }
        let count = row["plan_count"]
            .as_u64()
            .ok_or(ContainmentError("invalid readback match count"))?;
        let quarantine = boolean(row, "route_quarantined")?;
        let replacement = if self.request.replacement.is_some() {
            Some(boolean(row, "replacement_matches")?)
        } else {
            require(
                row["replacement_matches"].is_null(),
                "unexpected replacement outcome",
            )?;
            None
        };
        let relay_terminal = actual.source.relay.revoked_at.is_some()
            || actual.source.relay.superseded_by_relay_id.is_some()
            || super::validation::time(&actual.source.relay.expires_at)? <= observed;
        let history = actual.source.reply_admission == expected.reply_admission;
        let complete = count == 1
            && actual.source == expected
            && actual.attempt == self.attempt
            && quarantine
            && relay_terminal
            && history
            && replacement != Some(false);
        Ok(super::evidence::ReadbackResultV3 {
            adapter: "maildesk_reply_containment_readback_v3".into(),
            authority: self.request.control_plane.clone(),
            observed_at: observed.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            provider_output_retained: false,
            body_returned: false,
            status: if complete {
                "performed".into()
            } else {
                "ambiguous".into()
            },
            match_count: count,
            containment_applied: complete,
            send_blocked: complete,
            replay_allowed: false,
            cannot_unsend: self.request.action
                == super::ReplyContainmentActionV3::PostBoundaryContainment,
            semantic_bundle_sha256: self.semantic_bundle.clone(),
            plan_content_hash: plan.content_hash.clone(),
            containment_operation_id: plan.operation_id.clone(),
            binding: closed(self.compiled["readback_binding"].clone())?,
            relay_terminal,
            route_quarantined: quarantine,
            admission_history_preserved: history,
            replacement_lineage_verified: replacement,
        })
    }
}
fn boolean(row: &Map<String, Value>, key: &str) -> ContainmentResult<bool> {
    match row[key].as_u64() {
        Some(0) => Ok(false),
        Some(1) => Ok(true),
        _ => Err(ContainmentError("invalid database boolean")),
    }
}
