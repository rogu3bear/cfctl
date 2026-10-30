use super::compiled::hash_text;
use super::{
    ContainmentError, ContainmentResult, ReplyContainmentActionV3 as Action,
    ReplyContainmentAdmissionStatusV3 as Status, ReplyContainmentAttemptObservationV1 as Attempt,
    ReplyContainmentPriorReadV3 as Prior, ReplyContainmentRequestV3 as Request,
    ReplyContainmentSourceStateV3 as Source,
};
use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

pub(super) fn require(condition: bool, reason: &'static str) -> ContainmentResult<()> {
    condition.then_some(()).ok_or(ContainmentError(reason))
}
pub(super) fn digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|raw| hex(raw, 64))
}
fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
pub(super) fn reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 240
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b":._%/-".contains(&byte))
}
pub(super) fn time(value: &str) -> ContainmentResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .or_else(|_| {
            NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S").map(|value| value.and_utc())
        })
        .map_err(|_| ContainmentError("timestamp must be RFC3339 or canonical SQLite UTC"))
}
pub(super) fn closed<T: DeserializeOwned + Serialize>(value: Value) -> ContainmentResult<T> {
    let parsed: T = serde_json::from_value(value.clone())
        .map_err(|_| ContainmentError("value is outside the closed v3 shape"))?;
    require(
        serde_json::to_value(&parsed).ok().as_ref() == Some(&value),
        "required nullable field missing or noncanonical shape",
    )?;
    Ok(parsed)
}
fn hashes(values: &[&str]) -> ContainmentResult<()> {
    require(
        values.iter().all(|value| digest(value)),
        "hash requires one sha256 prefix and lower hex",
    )
}
fn refs(values: &[&str]) -> ContainmentResult<()> {
    require(
        values.iter().all(|value| reference(value)),
        "invalid source reference",
    )
}
impl Request {
    pub fn from_value(value: Value) -> ContainmentResult<Self> {
        let request: Self = closed(value)?;
        request.validate()?;
        Ok(request)
    }
    pub fn validate(&self) -> ContainmentResult<()> {
        require(
            self.schema_version == 3
                && !self.candidate.dirty
                && hex(&self.candidate.head, 40)
                && hex(&self.candidate.tree, 40),
            "clean v3 source identity required",
        )?;
        let authority = &self.control_plane;
        let controller = &self.controller;
        hashes(&[
            &authority.cfctl_build_sha256,
            &authority.profile_sha256,
            &authority.account_sha256,
            &authority.production_database_sha256,
            &authority.credential_generation_sha256,
            &controller.transaction_sha256,
            &controller.correlation_sha256,
            &controller.scope_manifest_sha256,
        ])?;
        refs(&[
            &self.source.route_id,
            &self.source.relay_id,
            &self.source.reply_admission_id,
        ])?;
        time(&self.requested_at)?;
        if self.action == Action::Replacement {
            let replacement = self
                .replacement
                .as_ref()
                .ok_or(ContainmentError("replacement locator missing"))?;
            refs(&[&replacement.relay_id])?;
            hashes(&[&replacement.source_containment_read_content_hash])?;
            require(
                replacement.relay_id != self.source.relay_id,
                "replacement must be distinct",
            )?;
        } else {
            require(self.replacement.is_none(), "unexpected replacement locator")?;
        }
        Ok(())
    }
    pub fn validate_fresh(&self, now: DateTime<Utc>) -> ContainmentResult<()> {
        self.validate()?;
        require(
            (-30_000..=300_000).contains(
                &now.signed_duration_since(time(&self.requested_at)?)
                    .num_milliseconds(),
            ),
            "request is stale or future dated",
        )
    }
}
impl Source {
    pub fn from_value(value: Value) -> ContainmentResult<Self> {
        closed(value)
    }
    pub fn validate(&self, request: &Request, at: DateTime<Utc>) -> ContainmentResult<()> {
        let relay = &self.relay;
        let admission = &self.reply_admission;
        let controller = &request.controller;
        refs(&[
            &self.route_id,
            &relay.id,
            &relay.route_id,
            &relay.thread_id,
            &admission.id,
            &admission.route_id,
            &admission.relay_id,
            &admission.thread_id,
        ])?;
        require(
            self.route_id == request.source.route_id
                && relay.id == request.source.relay_id
                && admission.id == request.source.reply_admission_id
                && relay.route_id == self.route_id
                && admission.route_id == self.route_id
                && admission.relay_id == relay.id
                && admission.thread_id == relay.thread_id,
            "observed relationship differs from locator",
        )?;
        hashes(&[
            &admission.transaction_sha256,
            &admission.correlation_sha256,
            &admission.scope_manifest_sha256,
            &admission.candidate_sha256,
        ])?;
        require(
            controller.transaction_sha256 != admission.transaction_sha256
                && controller.correlation_sha256 == admission.correlation_sha256
                && controller.scope_manifest_sha256 == admission.scope_manifest_sha256,
            "source scope or new controller mismatch",
        )?;
        validate_claim(admission)?;
        for stamp in [
            &relay.revoked_at,
            &admission.provider_boundary_at,
            &admission.terminal_at,
        ]
        .into_iter()
        .flatten()
        {
            time(stamp)?;
        }
        if let Some(id) = &relay.superseded_by_relay_id {
            refs(&[id])?;
        }
        let terminal = relay.revoked_at.is_some()
            || relay.superseded_by_relay_id.is_some()
            || time(&relay.expires_at)? <= at;
        let expiry = time(&admission.expires_at)?;
        match request.action {
            Action::PreSendRollback => require(
                !terminal
                    && expiry > at
                    && matches!(admission.status, Status::Admitted | Status::Claimed)
                    && admission.provider_boundary_at.is_none()
                    && admission.terminal_at.is_none()
                    && self.replacement.is_none(),
                "pre-send containment no longer eligible",
            )?,
            Action::PostBoundaryContainment => require(
                admission.provider_boundary_at.is_some()
                    && matches!(
                        admission.status,
                        Status::Sending
                            | Status::ProviderAccepted
                            | Status::Failed
                            | Status::RecoveryRequired
                    )
                    && self.replacement.is_none(),
                "post-boundary containment ineligible",
            )?,
            Action::Replacement => self.validate_replacement(request, at, terminal)?,
        }
        Ok(())
    }
    fn validate_replacement(
        &self,
        request: &Request,
        at: DateTime<Utc>,
        terminal: bool,
    ) -> ContainmentResult<()> {
        let replacement = self
            .replacement
            .as_ref()
            .ok_or(ContainmentError("observed replacement missing"))?;
        let locator = request
            .replacement
            .as_ref()
            .ok_or(ContainmentError("replacement locator missing"))?;
        refs(&[
            &replacement.id,
            &replacement.route_id,
            &replacement.thread_id,
        ])?;
        let created = time(&replacement.created_at)?;
        let expires = time(&replacement.expires_at)?;
        require(
            terminal
                && self.relay.superseded_by_relay_id.is_none()
                && replacement.id == locator.relay_id
                && replacement.id != self.relay.id
                && replacement.route_id == self.route_id
                && replacement.thread_id == self.reply_admission.thread_id
                && replacement.revoked_at.is_none()
                && replacement.superseded_by_relay_id.is_none()
                && created <= at
                && expires > at
                && expires > created,
            "replacement lineage or freshness invalid",
        )
    }
}
impl Attempt {
    pub(super) fn validate(
        &self,
        state: &Source,
        observed: DateTime<Utc>,
    ) -> ContainmentResult<()> {
        let admission = &state.reply_admission;
        require(
            self.schema_version == 1 && self.kind == "maildesk_reply_attempt_observation",
            "invalid attempt observation schema",
        )?;
        require(
            self.admission_ref_sha256 == hash_text(&admission.id)
                && self.relay_ref_sha256 == hash_text(&state.relay.id)
                && self.source_admission_transaction_sha256 == admission.transaction_sha256
                && admission
                    .claimed_attempt_id
                    .as_deref()
                    .is_some_and(|value| hash_text(value) == self.attempt_ref_sha256)
                && admission.claimed_attempt_sha256.as_deref() == Some(&self.attempt_sha256)
                && admission.claimed_payload_sha256.as_deref()
                    == Some(&self.claimed_payload_sha256),
            "attempt identity differs from immutable claim",
        )?;
        if let Some(hash) = &self.provider_message_id_sha256 {
            hashes(&[hash])?;
        }
        if let Some(code) = &self.error_code {
            require(
                !code.is_empty()
                    && code.len() <= 96
                    && code
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte)),
                "attempt error code is not bounded",
            )?;
        }
        require(
            time(&self.updated_at)? <= observed,
            "attempt update is after observation",
        )
    }
}
impl Prior {
    pub(super) fn validate(
        &self,
        request: &Request,
        state: &Source,
        observed: DateTime<Utc>,
    ) -> ContainmentResult<()> {
        let locator = request
            .replacement
            .as_ref()
            .ok_or(ContainmentError("unexpected prior read"))?;
        require(
            self.read_content_hash == locator.source_containment_read_content_hash
                && self.origin == "maildesk_reply_containment_readback_v3"
                && self.performed
                && self.send_blocked,
            "prior read is not performed native containment",
        )?;
        hashes(&[&self.read_content_hash, &self.plan.content_hash])?;
        refs(&[&self.read_operation_id, &self.plan.operation_id])?;
        require(
            self.read_operation_id != self.plan.operation_id
                && !self.candidate.dirty
                && hex(&self.candidate.head, 40)
                && hex(&self.candidate.tree, 40),
            "prior operation or source identity invalid",
        )?;
        let b = &self.binding;
        hashes(&[
            &b.containment_transaction_sha256,
            &b.controller_transaction_sha256,
            &b.source_admission_transaction_sha256,
            &b.correlation_sha256,
            &b.scope_manifest_sha256,
            &b.source_state_sha256,
            &b.route_ref_sha256,
            &b.relay_ref_sha256,
            &b.reply_admission_ref_sha256,
        ])?;
        if let Some(hash) = &b.attempt_observation_sha256 {
            hashes(&[hash])?;
        }
        require(
            b.controller_transaction_sha256 != request.controller.transaction_sha256
                && b.source_admission_transaction_sha256
                    == state.reply_admission.transaction_sha256
                && b.correlation_sha256 == request.controller.correlation_sha256
                && b.scope_manifest_sha256 == request.controller.scope_manifest_sha256
                && b.route_ref_sha256 == hash_text(&state.route_id)
                && b.relay_ref_sha256 == hash_text(&state.relay.id)
                && b.reply_admission_ref_sha256 == hash_text(&state.reply_admission.id)
                && time(&self.observed_at)? <= observed,
            "prior read source or controller mismatch",
        )
    }
}

fn validate_claim(admission: &super::ReplyContainmentAdmissionV3) -> ContainmentResult<()> {
    let claims = [
        admission.claimed_attempt_id.is_some(),
        admission.claimed_attempt_sha256.is_some(),
        admission.claimed_payload_sha256.is_some(),
    ];
    require(
        claims.iter().all(|v| *v) || claims.iter().all(|v| !*v),
        "partial claim identity",
    )?;
    require(
        admission.status != Status::Admitted || !claims[0],
        "unclaimed admission contains claim",
    )?;
    require(
        !matches!(
            admission.status,
            Status::Claimed
                | Status::Sending
                | Status::ProviderAccepted
                | Status::Failed
                | Status::RecoveryRequired
        ) || claims[0],
        "claimed admission missing claim",
    )?;
    if let Some(id) = &admission.claimed_attempt_id {
        refs(&[id])?;
    }
    for hash in [
        &admission.claimed_attempt_sha256,
        &admission.claimed_payload_sha256,
    ]
    .into_iter()
    .flatten()
    {
        hashes(&[hash])?;
    }
    Ok(())
}
