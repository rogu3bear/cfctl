//! Closed, body-free request and source-state models for containment v3.

use serde::{Deserialize, Serialize};

mod compiled;
pub mod evidence;
pub mod observation;
mod read;
pub mod sql;
mod validation;
pub use compiled::CompiledReplyContainmentV3;

#[derive(Debug, thiserror::Error)]
#[error("invalid containment v3 contract: {0}")]
pub struct ContainmentError(pub &'static str);

pub type ContainmentResult<T> = std::result::Result<T, ContainmentError>;

#[cfg(test)]
mod regression_tests;
#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplyContainmentActionV3 {
    PreSendRollback,
    PostBoundaryContainment,
    Replacement,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplyContainmentAuthorityV3 {
    pub cfctl_build_sha256: String,
    pub profile_sha256: String,
    pub account_sha256: String,
    pub production_database_sha256: String,
    pub credential_generation_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplyContainmentCandidateV3 {
    pub head: String,
    pub tree: String,
    pub dirty: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplyContainmentControllerV3 {
    pub transaction_sha256: String,
    pub correlation_sha256: String,
    pub scope_manifest_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplyContainmentRelayV3 {
    pub id: String,
    pub route_id: String,
    pub thread_id: String,
    pub revoked_at: Option<String>,
    pub superseded_by_relay_id: Option<String>,
    pub expires_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplyContainmentAdmissionStatusV3 {
    Admitted,
    Claimed,
    Sending,
    ProviderAccepted,
    Failed,
    RecoveryRequired,
    Revoked,
    Expired,
    Superseded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplyContainmentAdmissionV3 {
    pub id: String,
    pub thread_id: String,
    pub route_id: String,
    pub relay_id: String,
    pub status: ReplyContainmentAdmissionStatusV3,
    pub transaction_sha256: String,
    pub correlation_sha256: String,
    pub scope_manifest_sha256: String,
    pub candidate_sha256: String,
    pub claimed_attempt_id: Option<String>,
    pub claimed_attempt_sha256: Option<String>,
    pub claimed_payload_sha256: Option<String>,
    pub provider_boundary_at: Option<String>,
    pub terminal_at: Option<String>,
    pub expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplyContainmentObservedReplacementV3 {
    pub id: String,
    pub route_id: String,
    pub thread_id: String,
    pub revoked_at: Option<String>,
    pub superseded_by_relay_id: Option<String>,
    pub expires_at: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplyContainmentAttemptStatusV1 {
    Receiving,
    Queued,
    Authorized,
    ProviderAccepted,
    Failed,
    RecoveryRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplyContainmentAttemptObservationV1 {
    pub schema_version: u8,
    pub kind: String,
    pub admission_ref_sha256: String,
    pub relay_ref_sha256: String,
    pub source_admission_transaction_sha256: String,
    pub attempt_ref_sha256: String,
    pub attempt_sha256: String,
    pub claimed_payload_sha256: String,
    pub status: ReplyContainmentAttemptStatusV1,
    pub provider_message_id_sha256: Option<String>,
    pub error_code: Option<String>,
    pub updated_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplyContainmentReasonV3 {
    WrongIdentity,
    PrivateIdentityExposure,
    DuplicateSend,
    AmbiguousProviderResult,
    UnauthorizedOperator,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplyContainmentRequestV3 {
    #[serde(deserialize_with = "super::version_three")]
    pub schema_version: u8,
    pub action: ReplyContainmentActionV3,
    pub candidate: ReplyContainmentCandidateV3,
    pub control_plane: ReplyContainmentAuthorityV3,
    pub controller: ReplyContainmentControllerV3,
    pub source: ReplyContainmentSourceLocatorV3,
    pub reason: ReplyContainmentReasonV3,
    pub requested_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement: Option<ReplyContainmentReplacementLocatorV3>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplyContainmentSourceLocatorV3 {
    pub route_id: String,
    pub relay_id: String,
    pub reply_admission_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplyContainmentReplacementLocatorV3 {
    pub relay_id: String,
    pub source_containment_read_content_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplyContainmentSourceStateV3 {
    pub route_id: String,
    pub relay: ReplyContainmentRelayV3,
    pub reply_admission: ReplyContainmentAdmissionV3,
    pub replacement: Option<ReplyContainmentObservedReplacementV3>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplyContainmentPlanBindingV3 {
    pub operation_id: String,
    pub content_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplyContainmentBindingV3 {
    pub containment_transaction_sha256: String,
    pub controller_transaction_sha256: String,
    pub source_admission_transaction_sha256: String,
    pub correlation_sha256: String,
    pub scope_manifest_sha256: String,
    pub source_state_sha256: String,
    pub route_ref_sha256: String,
    pub relay_ref_sha256: String,
    pub reply_admission_ref_sha256: String,
    pub attempt_observation_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplyContainmentPriorReadV3 {
    pub read_content_hash: String,
    pub origin: String,
    pub read_operation_id: String,
    pub plan: ReplyContainmentPlanBindingV3,
    pub candidate: ReplyContainmentCandidateV3,
    pub binding: ReplyContainmentBindingV3,
    pub observed_at: String,
    pub performed: bool,
    pub send_blocked: bool,
}
