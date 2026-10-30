use cfctl_core::ReplyContainmentOperationV3;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::{Result, invalid};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Pack {
    pub schema_version: u8,
    pub operation: Vec<Operation>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Operation {
    pub id: String,
    pub title: String,
    pub description: String,
    pub compiler_path: String,
    pub compiler_sha256: String,
    pub compiler_runtime: String,
    pub compiler_runtime_version: String,
    pub compiler_runtime_sha256: String,
    pub input_contract: String,
    pub config_template: String,
    pub production_config: String,
    pub database_binding: String,
    pub wrangler_version: String,
    pub projection: Option<String>,
    pub mutation_projection: Option<String>,
    pub caller_sql_allowed: bool,
    pub provider_output_retained: bool,
    pub body_returned: bool,
    pub performs_on_call: Option<bool>,
    pub recovery_capability_id: Option<String>,
    pub recovery_max_age_seconds: Option<u64>,
    pub rollback_capability_id: Option<String>,
    #[serde(default)]
    pub parameters: Vec<String>,
    #[serde(default)]
    pub authority_bindings: Vec<String>,
    #[serde(default)]
    pub transaction_bindings: Vec<String>,
    pub performed_requires_exact_match_count: Option<u8>,
    pub ambiguous_never_proves_containment: Option<bool>,
}

impl Operation {
    pub fn same_source_binding(&self, other: &Self) -> bool {
        self.compiler_path == other.compiler_path
            && self.compiler_sha256 == other.compiler_sha256
            && self.compiler_runtime == other.compiler_runtime
            && self.compiler_runtime_version == other.compiler_runtime_version
            && self.compiler_runtime_sha256 == other.compiler_runtime_sha256
            && self.config_template == other.config_template
            && self.production_config == other.production_config
            && self.database_binding == other.database_binding
            && self.wrangler_version == other.wrangler_version
            && self.input_contract == other.input_contract
    }

    pub fn kind(&self) -> Result<ReplyContainmentOperationV3> {
        for kind in [
            ReplyContainmentOperationV3::PreRead,
            ReplyContainmentOperationV3::Apply,
            ReplyContainmentOperationV3::Read,
        ] {
            if self.id == kind.capability_id() {
                return Ok(kind);
            }
        }
        Err(invalid(
            "containment operation id is outside the closed lifecycle",
        ))
    }

    pub fn validate(&self) -> Result<()> {
        let kind = self.kind()?;
        if self.title.trim().is_empty()
            || self.title.len() > 256
            || self.description.trim().is_empty()
            || self.description.len() > 4096
            || self.input_contract != "maildesk_reply_containment_v3"
            || self.compiler_path != "scripts/compile-reply-containment.ts"
            || self.compiler_runtime != "bun"
            || self.compiler_runtime_version != "1.3.14"
            || self.wrangler_version != "4.110.0"
            || !digest(&self.compiler_sha256)
            || !digest(&self.compiler_runtime_sha256)
            || self.database_binding != "DB"
            || self.caller_sql_allowed
            || self.provider_output_retained
            || self.body_returned
        {
            return Err(invalid(
                "containment declaration widens its supported contract",
            ));
        }
        let apply = kind == ReplyContainmentOperationV3::Apply;
        let read = kind == ReplyContainmentOperationV3::Read;
        let expected_projection = match kind {
            ReplyContainmentOperationV3::PreRead => Some("maildesk_reply_containment_pre_read_v3"),
            ReplyContainmentOperationV3::Apply => None,
            ReplyContainmentOperationV3::Read => Some("maildesk_reply_containment_readback_v3"),
        };
        if self.projection.as_deref() != expected_projection
            || self.mutation_projection.as_deref()
                != apply.then_some("maildesk_reply_containment_v3")
            || self.performs_on_call != apply.then_some(false)
            || self.recovery_capability_id.as_deref()
                != apply.then_some("d1-time-travel-get-bookmark")
            || self.rollback_capability_id.as_deref()
                != apply.then_some("d1-restore-exact-bookmark")
            || (apply
                && !self
                    .recovery_max_age_seconds
                    .is_some_and(|age| (1..=600).contains(&age)))
            || (!apply && self.recovery_max_age_seconds.is_some())
            || self.performed_requires_exact_match_count != read.then_some(1)
            || self.ambiguous_never_proves_containment != read.then_some(true)
        {
            return Err(invalid(
                "containment projection or recovery declaration is invalid",
            ));
        }
        if read {
            if self.parameters != READ_PARAMETERS
                || self.authority_bindings != AUTHORITY_BINDINGS
                || self.transaction_bindings != TRANSACTION_BINDINGS
            {
                return Err(invalid(
                    "containment readback omits an exact identity binding",
                ));
            }
        } else if !self.parameters.is_empty()
            || !self.authority_bindings.is_empty()
            || !self.transaction_bindings.is_empty()
        {
            return Err(invalid(
                "containment operation contains readback-only selectors",
            ));
        }
        Ok(())
    }
}

const READ_PARAMETERS: [&str; 4] = [
    "containment_transaction_sha256",
    "semantic_bundle_sha256",
    "plan_content_hash",
    "containment_operation_id",
];
const AUTHORITY_BINDINGS: [&str; 5] = [
    "cfctl_build_sha256",
    "profile_sha256",
    "account_sha256",
    "credential_generation_sha256",
    "production_database_sha256",
];
const TRANSACTION_BINDINGS: [&str; 11] = [
    "controller_transaction_sha256",
    "source_admission_transaction_sha256",
    "source_state_sha256",
    "correlation_sha256",
    "scope_manifest_sha256",
    "route_ref_sha256",
    "relay_ref_sha256",
    "reply_admission_ref_sha256",
    "attempt_observation_sha256",
    "semantic_bundle_sha256",
    "plan_content_hash",
];

pub(super) fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|value| lower_hex(value, 64))
}

pub(super) fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
