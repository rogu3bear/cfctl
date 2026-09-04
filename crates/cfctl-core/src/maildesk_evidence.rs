//! Body-free public Maildesk operational evidence contract.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Body-free operational evidence emitted by a workspace-owned Maildesk D1
/// projection. No message, address, recipient, subject, arbitrary row, or SQL
/// field exists in this public type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaildeskD1EvidenceV1 {
    pub schema_version: u8,
    pub active_policy_digest: String,
    pub desired_state_digest: String,
    pub semantic_projection_digest: String,
    pub immutable_policy_object_key: String,
    /// Absent only in historical aggregates; current queries require this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision_r2_key: Option<String>,
    /// Independent projection state, never substituted with the runtime digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projection_policy_sha256: Option<String>,
    pub expected_domain_count: u64,
    pub projected_domain_count: u64,
    pub expected_route_count: u64,
    pub projected_route_count: u64,
    pub approved_schema_present: bool,
    pub approved_table_presence: BTreeMap<String, bool>,
    pub audit_event_counts: BTreeMap<String, u64>,
    pub queue_correlation_count: u64,
    pub dlq_correlation_count: u64,
    pub body_returned: bool,
}
