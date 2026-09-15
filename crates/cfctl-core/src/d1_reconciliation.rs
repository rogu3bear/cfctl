//! Read-only reconciliation and failed-query diagnostic request contracts.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const RECONCILE_ID: &str = "d1-reconcile-same-checkpoint-restore";
pub const DIAGNOSTIC_ID: &str = "workspace-d1-diagnose-failed-query";
pub const STRATEGY: &str = "d1_authenticated_complete_export_bytes_equal";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Window {
    pub window_id: String,
    pub opened_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseBinding {
    pub commit: String,
    pub tree: String,
    pub deploy_artifact_digest: String,
    pub declaration_sha256: String,
    pub window: Window,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconcileRequest {
    pub restore_operation_id: String,
    pub historical_post_export_evidence_hash: String,
    pub current_export_evidence_hash: String,
    pub release_binding: ReleaseBinding,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticRequest {
    pub failed_evidence_hash: String,
    pub capability_id: String,
    pub query_id: String,
    pub expected_credential_generation_id: String,
}
