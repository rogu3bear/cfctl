//! Disjoint reply lifecycle contracts carried by the existing capability slot.
//!
//! Admission v1 keeps its original serialized representation. Containment has
//! its own discriminator and payload so an activation cannot be interpreted as
//! a revocation, or vice versa. Neither branch accepts the other's fields.

use serde::{Deserialize, Deserializer, Serialize};

use crate::WorkspaceD1ReplyAdmissionContractV1;

pub mod containment;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WorkspaceD1ReplyLifecycleContract {
    Containment(WorkspaceD1ReplyContainmentContractV3),
    Admission(WorkspaceD1ReplyAdmissionContractV1),
}

impl WorkspaceD1ReplyLifecycleContract {
    #[must_use]
    pub fn admission(&self) -> Option<&WorkspaceD1ReplyAdmissionContractV1> {
        match self {
            Self::Admission(contract) => Some(contract),
            Self::Containment(_) => None,
        }
    }

    #[must_use]
    pub fn containment(&self) -> Option<&WorkspaceD1ReplyContainmentContractV3> {
        match self {
            Self::Containment(contract) => Some(contract),
            Self::Admission(_) => None,
        }
    }
}

impl From<WorkspaceD1ReplyAdmissionContractV1> for WorkspaceD1ReplyLifecycleContract {
    fn from(value: WorkspaceD1ReplyAdmissionContractV1) -> Self {
        Self::Admission(value)
    }
}

impl From<WorkspaceD1ReplyContainmentContractV3> for WorkspaceD1ReplyLifecycleContract {
    fn from(value: WorkspaceD1ReplyContainmentContractV3) -> Self {
        Self::Containment(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplyContainmentSchemaV3 {
    #[serde(rename = "maildesk_reply_containment_v3")]
    V3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplyContainmentOperationV3 {
    PreRead,
    Apply,
    Read,
}

impl ReplyContainmentOperationV3 {
    #[must_use]
    pub const fn capability_id(self) -> &'static str {
        match self {
            Self::PreRead => "star-maildesk-cf.reply-containment-pre-read",
            Self::Apply => "star-maildesk-cf.reply-containment-apply",
            Self::Read => "star-maildesk-cf.reply-containment-read",
        }
    }
}

/// Immutable source and tool bindings for the containment-v2 handler.
/// The handler owns request schemas, SQL, state transitions and readback; this
/// declaration does not grant caller-selected SQL or activation semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceD1ReplyContainmentContractV3 {
    pub contract: ReplyContainmentSchemaV3,
    #[serde(deserialize_with = "version_three")]
    pub schema_version: u8,
    pub operation_kind: ReplyContainmentOperationV3,
    pub repository_root: String,
    pub repository_head: String,
    pub repository_tree: String,
    pub repository_origin: String,
    pub operation_pack_path: String,
    pub operation_pack_sha256: String,
    pub compiler_path: String,
    pub compiler_sha256: String,
    pub compiler_runtime: String,
    pub compiler_runtime_version: String,
    pub compiler_runtime_sha256: String,
    pub config_template_path: String,
    pub config_template_sha256: String,
    pub production_config_path: String,
    pub database_binding: String,
    pub wrangler_version: String,
    pub input_contract: String,
    pub recovery_capability_id: String,
    pub recovery_max_age_seconds: u64,
    pub rollback_capability_id: String,
}

fn version_three<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u8, D::Error> {
    let value = u8::deserialize(deserializer)?;
    if value != 3 {
        return Err(serde::de::Error::custom(
            "containment contract requires schema 3",
        ));
    }
    Ok(value)
}

impl WorkspaceD1ReplyContainmentContractV3 {
    pub(crate) fn verification_supported(&self, capability: &crate::CapabilityV1) -> bool {
        let apply = self.operation_kind == ReplyContainmentOperationV3::Apply;
        let strategy = match self.operation_kind {
            ReplyContainmentOperationV3::PreRead => "workspace_d1_reply_containment_pre_read_v3",
            ReplyContainmentOperationV3::Apply => "workspace_d1_reply_containment_apply_v3",
            ReplyContainmentOperationV3::Read => "workspace_d1_reply_containment_readback_v3",
        };
        capability.id == self.operation_kind.capability_id()
            && capability.authority_scope == Some(crate::CapabilityAuthorityScopeV1::WorkspaceOwned)
            && capability.adapter_status == crate::AdapterStatus::DelegatedCli
            && capability.execution_supported
            && capability.mutating == apply
            && capability.method == if apply { "POST" } else { "GET" }
            && capability.risk
                == if apply {
                    crate::RiskClass::IdentityOrOwnership
                } else {
                    crate::RiskClass::Read
                }
            && capability.effect
                == if apply {
                    crate::EffectClass::IdentityOrOwnership
                } else {
                    crate::EffectClass::ReadOnly
                }
            && capability.verification.strategy == strategy
            && self.schema_version == 3
            && self.input_contract == "maildesk_reply_containment_v3"
            && self.compiler_runtime == "bun"
            && self.compiler_runtime_version == "1.3.14"
            && self.wrangler_version == "4.110.0"
            && self.database_binding == "DB"
            && !self.repository_root.is_empty()
            && !self.repository_head.is_empty()
            && !self.repository_tree.is_empty()
            && !self.operation_pack_sha256.is_empty()
            && !self.compiler_sha256.is_empty()
            && !self.compiler_runtime_sha256.is_empty()
            && !self.config_template_sha256.is_empty()
            && (!apply
                || (self.recovery_capability_id == "d1-time-travel-get-bookmark"
                    && (1..=600).contains(&self.recovery_max_age_seconds)
                    && self.rollback_capability_id == "d1-restore-exact-bookmark"))
    }
}

#[cfg(test)]
mod tests;
