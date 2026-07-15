//! Versioned domain contracts for the cfctl v2 control plane.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

/// Errors shared by the deterministic planner, policy engine, and executors.
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("failed to serialize hash-bound content: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("operation {operation_id} is in state {actual:?}; expected {expected}")]
    InvalidPlanState {
        operation_id: String,
        actual: PlanStatus,
        expected: &'static str,
    },
    #[error("operation {operation_id} expired at {expires_at}")]
    PlanExpired {
        operation_id: String,
        expires_at: DateTime<Utc>,
    },
    #[error("approval must be an explicit yes bound to the operation id")]
    ExplicitApprovalRequired,
    #[error("operation {0} requires an explicit maximum cost ceiling")]
    CostCeilingRequired(String),
    #[error(
        "operation {operation_id} has declared maximum cost {required_currency}:{required_amount}, above the approved ceiling"
    )]
    CostCeilingTooLow {
        operation_id: String,
        required_currency: String,
        required_amount: f64,
    },
    #[error("operation {0} no longer matches its approved content hash")]
    PlanDrifted(String),
    #[error("operation {operation_id} has an invalid transaction journal: {reason}")]
    InvalidTransactionJournal {
        operation_id: String,
        reason: String,
    },
}

pub type Result<T> = std::result::Result<T, CoreError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterStatus {
    Native,
    DynamicApi,
    DelegatedCli,
    GovernedUi,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskClass {
    Read,
    ScopedWrite,
    CrossConfig,
    Destructive,
    SecretSensitive,
    ExternalCommunication,
    IdentityOrOwnership,
    Spend,
    Irreversible,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectClass {
    ReadOnly,
    ReversibleWrite,
    Destructive,
    ExternalCommunication,
    IdentityOrOwnership,
    Spend,
    Irreversible,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Maturity {
    GenerallyAvailable,
    Beta,
    Experimental,
    Deprecated,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuerySerializationV1 {
    pub style: String,
    pub explode: bool,
    pub allow_reserved: bool,
    pub allow_empty_value: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SelectorContractV1 {
    pub schema: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<QuerySerializationV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SelectorV1 {
    pub name: String,
    pub location: String,
    pub required: bool,
    pub value_type: String,
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract: Option<SelectorContractV1>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BillingModelV1 {
    None,
    Fixed,
    UsageBased,
    Subscription,
    PassThrough,
    Contract,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CostExposureV1 {
    #[default]
    None,
    DownstreamUsage,
    AccountQuote,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnowledgeReferenceV1 {
    pub title: String,
    pub url: String,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CostV1 {
    pub incremental: bool,
    pub currency: Option<String>,
    pub maximum: Option<f64>,
    pub basis: Option<String>,
    pub known: bool,
    #[serde(default)]
    pub billing_model: BillingModelV1,
    #[serde(default)]
    pub exposure: CostExposureV1,
    #[serde(default)]
    pub references: Vec<KnowledgeReferenceV1>,
}

impl Default for CostV1 {
    fn default() -> Self {
        Self {
            incremental: false,
            currency: None,
            maximum: Some(0.0),
            basis: Some("no incremental cost metadata declared".to_owned()),
            known: true,
            billing_model: BillingModelV1::None,
            exposure: CostExposureV1::None,
            references: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntitlementV1 {
    pub available: Option<bool>,
    pub plans: BTreeMap<String, bool>,
    pub blocker: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub requires_live_resolution: bool,
    #[serde(default)]
    pub observed_plan: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationSpecV1 {
    pub required: bool,
    pub strategy: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackSpecV1 {
    pub supported: bool,
    pub strategy: Option<String>,
    pub warning: Option<String>,
}

/// Hash-bound coordinates for proving and compensating a newly created
/// Cloudflare resource. The identity pointer is relative to the API response's
/// `result` object; callers must not infer any of these values from mutable
/// runtime input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatedResourceContractV1 {
    pub detail_path: String,
    pub identity_selector: String,
    pub response_result_identity_pointer: String,
    pub read_capability_id: String,
    pub delete_capability_id: String,
    /// Canonical top-level request fields that the exact-resource response
    /// schema declares and the live verifier is therefore allowed to compare.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verified_response_fields: Vec<String>,
}

/// Hash-bound coordinates for proving and compensating a newly created
/// Cloudflare resource through its complete parent collection when the API has
/// no exact-resource read endpoint. Every allowlisted field is declared on the
/// collection item schema and the returned creation identity remains the only
/// value used to select the item and build an exact delete compensation plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatedCollectionResourceContractV1 {
    pub collection_path: String,
    pub identity_selector: String,
    pub response_result_identity_pointer: String,
    pub response_item_identity_pointer: String,
    pub read_capability_id: String,
    pub delete_capability_id: String,
    pub verified_response_fields: Vec<String>,
    /// When true, verification succeeds only after the live response proves
    /// every numbered page was collected through numeric `page` and
    /// `total_pages` metadata.
    #[serde(default, skip_serializing_if = "is_false")]
    pub requires_page_number_completion: bool,
}

/// Hash-bound coordinates for proving an exact resource deletion through a
/// schema-proven parent collection when the API has no detail read endpoint.
/// The identity pointer is relative to each item in the collection response's
/// `result` array.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeletedResourceContractV1 {
    pub collection_path: String,
    pub identity_selector: String,
    pub response_item_identity_pointer: String,
    pub read_capability_id: String,
    /// When true, verification succeeds only after the live response proves
    /// every numbered page was collected through numeric `page` and
    /// `total_pages` metadata.
    #[serde(default, skip_serializing_if = "is_false")]
    pub requires_page_number_completion: bool,
}

/// Hash-bound coordinates for proving an exact resource update through a
/// schema-proven parent collection when the API has no detail read endpoint.
/// The allowlisted fields must be declared on every collection item schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdatedResourceContractV1 {
    pub collection_path: String,
    pub identity_selector: String,
    pub response_item_identity_pointer: String,
    pub read_capability_id: String,
    pub verified_response_fields: Vec<String>,
    /// When true, verification succeeds only after the live response proves
    /// every numbered page was collected through numeric `page` and
    /// `total_pages` metadata.
    #[serde(default, skip_serializing_if = "is_false")]
    pub requires_page_number_completion: bool,
}

/// Hash-bound same-path GET used to verify an exact delete or an update.
/// Update contracts carry the canonical request fields proven observable on
/// the response schema; delete contracts intentionally carry no fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SamePathReadContractV1 {
    pub path: String,
    pub read_capability_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verified_response_fields: Vec<String>,
}

// Serde skip predicates receive a shared reference to the field value.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityV1 {
    pub schema_version: u8,
    pub id: String,
    pub title: String,
    pub description: Option<String>,
    pub product: String,
    pub source: String,
    pub method: String,
    pub path: String,
    pub account_scope: String,
    pub selectors: Vec<SelectorV1>,
    pub permissions: Vec<String>,
    pub mutating: bool,
    pub risk: RiskClass,
    pub effect: EffectClass,
    pub maturity: Maturity,
    pub entitlement: EntitlementV1,
    pub cost: CostV1,
    pub verification: VerificationSpecV1,
    pub rollback: RollbackSpecV1,
    #[serde(default)]
    pub created_resource: Option<CreatedResourceContractV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_collection_resource: Option<CreatedCollectionResourceContractV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_resource: Option<DeletedResourceContractV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_resource: Option<UpdatedResourceContractV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub same_path_read: Option<SamePathReadContractV1>,
    pub adapter_status: AdapterStatus,
    pub blocked_reason: Option<String>,
    pub request_schema: Option<Value>,
}

impl CapabilityV1 {
    #[must_use]
    pub fn new(id: &str, title: &str, method: &str, path: &str) -> Self {
        let normalized_method = method.to_ascii_uppercase();
        let is_read = matches!(normalized_method.as_str(), "GET" | "HEAD" | "OPTIONS");
        let cost = if is_read {
            CostV1::default()
        } else {
            CostV1 {
                incremental: false,
                currency: None,
                maximum: None,
                basis: Some("official API schema does not declare operation pricing".to_owned()),
                known: false,
                billing_model: BillingModelV1::Unknown,
                exposure: CostExposureV1::None,
                references: Vec::new(),
            }
        };
        Self {
            schema_version: 1,
            id: id.to_owned(),
            title: title.to_owned(),
            description: None,
            product: "Cloudflare API".to_owned(),
            source: "cloudflare-api-schemas".to_owned(),
            method: normalized_method,
            path: path.to_owned(),
            account_scope: infer_scope(path).to_owned(),
            selectors: Vec::new(),
            permissions: Vec::new(),
            mutating: !is_read,
            risk: if is_read {
                RiskClass::Read
            } else {
                RiskClass::Unknown
            },
            effect: if is_read {
                EffectClass::ReadOnly
            } else {
                EffectClass::Unknown
            },
            maturity: Maturity::Unknown,
            entitlement: EntitlementV1::default(),
            cost,
            verification: VerificationSpecV1 {
                required: !is_read,
                strategy: if is_read {
                    "not_applicable"
                } else {
                    "required"
                }
                .to_owned(),
            },
            rollback: RollbackSpecV1 {
                supported: false,
                strategy: None,
                warning: if is_read {
                    None
                } else {
                    Some("rollback semantics have not been declared".to_owned())
                },
            },
            created_resource: None,
            created_collection_resource: None,
            deleted_resource: None,
            updated_resource: None,
            same_path_read: None,
            adapter_status: AdapterStatus::DynamicApi,
            blocked_reason: None,
            request_schema: None,
        }
    }

    /// Returns the missing safety metadata that prevents a mutating capability
    /// from crossing an execution boundary.
    #[must_use]
    pub fn mutation_contract_gaps(&self) -> Vec<String> {
        if !self.mutating {
            return Vec::new();
        }

        let mut gaps = Vec::new();
        if self.risk == RiskClass::Unknown {
            gaps.push("operation-specific risk classification is missing".to_owned());
        }
        if self.effect == EffectClass::Unknown {
            gaps.push("operation-specific effect classification is missing".to_owned());
        }
        if !self.cost.known {
            if self.cost.references.is_empty() {
                gaps.push("operation-specific incremental cost is unknown".to_owned());
            } else {
                gaps.push(format!(
                    "operation-specific cost is not bounded; review official pricing reference(s): {}",
                    self.cost
                        .references
                        .iter()
                        .map(|reference| reference.url.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }
        if !self.verification_contract_declared() {
            gaps.push("operation-specific verification is not declared".to_owned());
        } else if !self.verification_contract_supported() {
            gaps.push(format!(
                "declared verification strategy is unsupported: {}",
                self.verification.strategy
            ));
        }

        if !self.rollback_contract_declared() {
            gaps.push(
                "operation-specific rollback or irreversibility behavior is not declared"
                    .to_owned(),
            );
        } else if !self.rollback_contract_supported() {
            gaps.push(format!(
                "declared rollback strategy is unsupported: {}",
                self.rollback.strategy.as_deref().unwrap_or("<missing>")
            ));
        }
        let dynamic_api_contract = self.adapter_status == AdapterStatus::DynamicApi
            || (self.adapter_status == AdapterStatus::Blocked
                && self
                    .blocked_reason
                    .as_deref()
                    .is_some_and(|reason| reason.starts_with("operation contract incomplete:")));
        if dynamic_api_contract && self.permissions.is_empty() {
            gaps.push("required Cloudflare permission lane is not declared".to_owned());
        }
        let plan_gated = self.entitlement.plans.values().any(|available| !available);
        if plan_gated && self.entitlement.available != Some(true) {
            gaps.push(
                "account entitlement has not been resolved for this plan-gated operation"
                    .to_owned(),
            );
        }
        gaps
    }

    #[must_use]
    pub fn verification_contract_declared(&self) -> bool {
        !self.verification.required
            || !matches!(
                self.verification.strategy.as_str(),
                "" | "required" | "post_change_read_or_operation_specific_verifier"
            )
    }

    /// Returns whether the selected adapter has an implementation for this
    /// capability's exact verification strategy and resource shape.
    #[must_use]
    pub fn verification_contract_supported(&self) -> bool {
        if !self.mutating {
            return true;
        }
        if !self.verification.required {
            return self.risk == RiskClass::SecretSensitive
                && self.verification.strategy == "sink_write_and_source_response_status";
        }

        match self.verification.strategy.as_str() {
            "api_token_details_match_created_id_and_active_status" => {
                self.method == "POST"
                    && matches!(
                        self.id.as_str(),
                        "account-api-tokens-create-token" | "user-api-tokens-create-token"
                    )
            }
            "api_token_details_report_active_after_value_roll" => {
                self.method == "PUT"
                    && matches!(
                        self.id.as_str(),
                        "account-api-tokens-roll-token" | "user-api-tokens-roll-token"
                    )
            }
            "api_token_details_returns_not_found_after_revoke" => {
                self.method == "DELETE"
                    && matches!(
                        self.id.as_str(),
                        "account-api-tokens-delete-token" | "user-api-tokens-delete-token"
                    )
            }
            "dns_record_details_match_created_id_and_planned_fields" => {
                self.method == "POST" && self.id == "dns-records-for-a-zone-create-dns-record"
            }
            "dns_record_details_match_planned_id_and_fields" => {
                matches!(self.method.as_str(), "PATCH" | "PUT")
                    && matches!(
                        self.id.as_str(),
                        "dns-records-for-a-zone-patch-dns-record"
                            | "dns-records-for-a-zone-update-dns-record"
                    )
            }
            "dns_record_details_returns_not_found_after_delete" => {
                self.method == "DELETE" && self.id == "dns-records-for-a-zone-delete-dns-record"
            }
            "same_resource_returns_not_found_after_delete" => {
                self.method == "DELETE"
                    && path_targets_exact_resource(&self.path)
                    && self.request_schema.is_none()
                    && self.same_path_readback_selectors_supported()
                    && self.same_path_read_contract_supported(false)
            }
            "parent_collection_omits_deleted_resource_id" => {
                self.method == "DELETE"
                    && self.request_schema.is_none()
                    && self
                        .selectors
                        .iter()
                        .all(|selector| selector.location == "path")
                    && self.deleted_resource_contract_supported()
            }
            "parent_collection_item_contains_planned_fields_after_update" => {
                matches!(self.method.as_str(), "PATCH" | "PUT")
                    && self
                        .selectors
                        .iter()
                        .all(|selector| selector.location == "path")
                    && self.updated_resource_contract_supported()
            }
            "same_resource_contains_planned_fields_after_update" => {
                matches!(self.method.as_str(), "PATCH" | "PUT")
                    && path_targets_exact_resource(&self.path)
                    && self.same_path_readback_selectors_supported()
                    && self.same_path_read_contract_supported(true)
            }
            "same_path_result_contains_planned_fields_after_update" => {
                matches!(self.method.as_str(), "PATCH" | "PUT")
                    && self.same_path_readback_selectors_supported()
                    && self.same_path_read_contract_supported(true)
            }
            "same_path_result_contains_planned_fields_after_mutation" => {
                self.method == "POST"
                    && self.same_path_readback_selectors_supported()
                    && self.same_path_read_contract_supported(true)
            }
            "created_resource_contains_planned_fields_by_returned_id" => {
                self.method == "POST" && self.created_resource_contract_supported()
            }
            "parent_collection_contains_created_resource_id_and_planned_fields" => {
                self.method == "POST" && self.created_collection_resource_contract_supported()
            }
            _ => false,
        }
    }

    #[must_use]
    pub fn rollback_contract_declared(&self) -> bool {
        if self.rollback.supported {
            self.rollback
                .strategy
                .as_deref()
                .is_some_and(|strategy| !strategy.trim().is_empty())
        } else {
            self.rollback.warning.as_deref().is_some_and(|warning| {
                !warning.trim().is_empty() && warning != "rollback semantics have not been declared"
            })
        }
    }

    /// Returns whether a declared automatic rollback strategy can be turned
    /// into a separate, hash-bound compensation plan by the runtime.
    #[must_use]
    pub fn rollback_contract_supported(&self) -> bool {
        if !self.mutating || !self.rollback.supported {
            return true;
        }
        match self.rollback.strategy.as_deref() {
            Some("revoke_created_api_token_by_returned_id_if_downstream_installation_fails") => {
                self.method == "POST"
                    && matches!(
                        self.id.as_str(),
                        "account-api-tokens-create-token" | "user-api-tokens-create-token"
                    )
            }
            Some("delete_created_dns_record_by_returned_id") => {
                self.method == "POST" && self.id == "dns-records-for-a-zone-create-dns-record"
            }
            Some("delete_created_resource_by_returned_id") => {
                self.method == "POST"
                    && (self.created_resource_contract_supported()
                        || self.created_collection_resource_contract_supported())
            }
            _ => false,
        }
    }

    /// Returns the canonical top-level fields of an object request schema.
    /// Direct properties and fields from fully object-shaped compositions are
    /// combined into a deterministic allowlist. Catalog classifiers require a
    /// readback schema to declare that full union, while the runtime compares
    /// only fields present in the validated, hash-bound plan body.
    #[must_use]
    pub fn request_object_fields(&self) -> Option<Vec<String>> {
        let fields = request_object_property_schemas(self.request_schema.as_ref()?)?;
        Some(fields.into_keys().collect())
    }

    /// Returns the canonical top-level request fields that a response
    /// readback can observe. Fully write-only inputs remain valid request
    /// fields but are deliberately absent from this list. A schema with
    /// `properties` and no explicit type is object-shaped for this purpose;
    /// any explicit non-object type remains ineligible.
    #[must_use]
    pub fn verifiable_request_object_fields(&self) -> Option<Vec<String>> {
        let fields = request_object_property_schemas(self.request_schema.as_ref()?)?;
        let fields = fields
            .into_iter()
            .filter(|(_, schemas)| !property_schemas_are_write_only(schemas))
            .map(|(name, _)| name)
            .collect::<Vec<_>>();
        if fields.is_empty() {
            return None;
        }
        Some(fields)
    }

    /// Returns whether a top-level request field is explicitly declared as
    /// write-only by the hash-bound request schema.
    #[must_use]
    pub fn request_object_field_is_write_only(&self, field: &str) -> bool {
        self.request_schema
            .as_ref()
            .and_then(request_object_property_schemas)
            .and_then(|fields| fields.get(field).cloned())
            .is_some_and(|schemas| property_schemas_are_write_only(&schemas))
    }

    fn verified_response_fields_match_request_schema(&self, fields: &[String]) -> bool {
        match self.request_schema.as_ref() {
            None => true,
            Some(_) => self
                .verifiable_request_object_fields()
                .is_some_and(|request_fields| fields == request_fields),
        }
    }

    fn created_resource_contract_supported(&self) -> bool {
        self.created_resource.as_ref().is_some_and(|target| {
            let expected_path = format!(
                "{}/{{{}}}",
                self.path.trim_end_matches('/'),
                target.identity_selector
            );
            !target.identity_selector.is_empty()
                && target.detail_path == expected_path
                && response_identity_pointer_supported(
                    &target.identity_selector,
                    &target.response_result_identity_pointer,
                )
                && !target.read_capability_id.is_empty()
                && !target.delete_capability_id.is_empty()
                && !target.verified_response_fields.is_empty()
                && self
                    .verified_response_fields_match_request_schema(&target.verified_response_fields)
                && target
                    .verified_response_fields
                    .iter()
                    .all(|field| !field.is_empty() && !field.contains('/'))
                && target
                    .verified_response_fields
                    .windows(2)
                    .all(|fields| fields[0] < fields[1])
        })
    }

    fn same_path_read_contract_supported(&self, require_fields: bool) -> bool {
        self.same_path_read.as_ref().is_some_and(|target| {
            if target.path != self.path || target.read_capability_id.is_empty() {
                return false;
            }
            if !require_fields {
                return target.verified_response_fields.is_empty();
            }
            let Some(request_fields) = self.verifiable_request_object_fields() else {
                return false;
            };
            !request_fields.is_empty() && target.verified_response_fields == request_fields
        })
    }

    fn same_path_readback_selectors_supported(&self) -> bool {
        let mut routing_headers = 0_u8;
        for selector in &self.selectors {
            if selector.location == "path" {
                continue;
            }
            if selector.location == "header"
                && selector.name == "cf-r2-jurisdiction"
                && !selector.required
                && selector.value_type == "string"
                && matches!(self.product.as_str(), "R2 Bucket" | "R2 Object")
            {
                routing_headers += 1;
                if routing_headers > 1 {
                    return false;
                }
                continue;
            }
            return false;
        }
        true
    }

    fn created_collection_resource_contract_supported(&self) -> bool {
        self.created_collection_resource
            .as_ref()
            .is_some_and(|target| {
                !target.identity_selector.is_empty()
                    && self.path == target.collection_path
                    && target.response_result_identity_pointer
                        == target.response_item_identity_pointer
                    && response_identity_pointer_supported(
                        &target.identity_selector,
                        &target.response_result_identity_pointer,
                    )
                    && !target.read_capability_id.is_empty()
                    && !target.delete_capability_id.is_empty()
                    && !target.verified_response_fields.is_empty()
                    && self.verified_response_fields_match_request_schema(
                        &target.verified_response_fields,
                    )
                    && target
                        .verified_response_fields
                        .iter()
                        .all(|field| !field.is_empty() && !field.contains('/'))
                    && target
                        .verified_response_fields
                        .windows(2)
                        .all(|fields| fields[0] < fields[1])
            })
    }

    fn deleted_resource_contract_supported(&self) -> bool {
        self.deleted_resource.as_ref().is_some_and(|target| {
            let expected_path = format!(
                "{}/{{{}}}",
                target.collection_path.trim_end_matches('/'),
                target.identity_selector
            );
            !target.identity_selector.is_empty()
                && self.path == expected_path
                && response_identity_pointer_supported(
                    &target.identity_selector,
                    &target.response_item_identity_pointer,
                )
                && !target.read_capability_id.is_empty()
        })
    }

    fn updated_resource_contract_supported(&self) -> bool {
        self.updated_resource.as_ref().is_some_and(|target| {
            let expected_path = format!(
                "{}/{{{}}}",
                target.collection_path.trim_end_matches('/'),
                target.identity_selector
            );
            let Some(request_fields) = self.verifiable_request_object_fields() else {
                return false;
            };
            !target.identity_selector.is_empty()
                && self.path == expected_path
                && response_identity_pointer_supported(
                    &target.identity_selector,
                    &target.response_item_identity_pointer,
                )
                && !target.read_capability_id.is_empty()
                && !request_fields.is_empty()
                && target.verified_response_fields == request_fields
                && target
                    .verified_response_fields
                    .iter()
                    .all(|field| !field.is_empty() && !field.contains('/'))
                && target
                    .verified_response_fields
                    .windows(2)
                    .all(|fields| fields[0] < fields[1])
        })
    }
}

fn response_identity_pointer_supported(selector: &str, pointer: &str) -> bool {
    (selector_can_be_response_id(selector) && pointer == "/id")
        || (!selector
            .chars()
            .any(|character| matches!(character, '/' | '~'))
            && pointer.strip_prefix('/') == Some(selector))
}

const MAX_REQUEST_OBJECT_SCHEMA_DEPTH: usize = 64;
const MAX_REQUEST_OBJECT_SCHEMA_STEPS: usize = 4_096;

fn request_object_property_schemas(schema: &Value) -> Option<BTreeMap<String, Vec<&Value>>> {
    let mut fields = BTreeMap::new();
    let mut remaining_steps = MAX_REQUEST_OBJECT_SCHEMA_STEPS;
    if collect_composed_object_property_schemas(schema, 0, &mut remaining_steps, &mut fields)
        != RequestObjectSchemaCollection::Object
        || fields.is_empty()
    {
        return None;
    }
    Some(fields)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RequestObjectSchemaCollection {
    Object,
    Ineligible,
    LimitExceeded,
}

fn collect_composed_object_property_schemas<'a>(
    schema: &'a Value,
    depth: usize,
    remaining_steps: &mut usize,
    fields: &mut BTreeMap<String, Vec<&'a Value>>,
) -> RequestObjectSchemaCollection {
    if depth > MAX_REQUEST_OBJECT_SCHEMA_DEPTH || *remaining_steps == 0 {
        return RequestObjectSchemaCollection::LimitExceeded;
    }
    *remaining_steps -= 1;
    match schema.get("type") {
        None => {}
        Some(Value::String(value_type)) if value_type == "object" => {}
        _ => return RequestObjectSchemaCollection::Ineligible,
    }
    let mut local_fields = BTreeMap::<String, Vec<&Value>>::new();
    if let Some(properties) = schema.get("properties") {
        let Some(properties) = properties.as_object() else {
            return RequestObjectSchemaCollection::Ineligible;
        };
        for (name, property_schema) in properties {
            local_fields
                .entry(name.clone())
                .or_default()
                .push(property_schema);
        }
    }
    if let Some(all_of) = schema.get("allOf") {
        let Some(members) = all_of.as_array().filter(|members| !members.is_empty()) else {
            return RequestObjectSchemaCollection::Ineligible;
        };
        for member in members {
            let outcome = collect_composed_object_property_schemas(
                member,
                depth + 1,
                remaining_steps,
                &mut local_fields,
            );
            if outcome != RequestObjectSchemaCollection::Object {
                return outcome;
            }
        }
    }
    for composition in ["oneOf", "anyOf"] {
        let Some(members) = schema.get(composition) else {
            continue;
        };
        let Some(members) = members.as_array().filter(|members| !members.is_empty()) else {
            return RequestObjectSchemaCollection::Ineligible;
        };
        let mut alternative_fields = BTreeMap::new();
        let mut object_shaped = true;
        for member in members {
            match collect_composed_object_property_schemas(
                member,
                depth + 1,
                remaining_steps,
                &mut alternative_fields,
            ) {
                RequestObjectSchemaCollection::Object => {}
                RequestObjectSchemaCollection::Ineligible => {
                    object_shaped = false;
                    break;
                }
                RequestObjectSchemaCollection::LimitExceeded => {
                    return RequestObjectSchemaCollection::LimitExceeded;
                }
            }
        }
        if object_shaped {
            merge_request_object_property_schemas(&mut local_fields, alternative_fields);
        } else if local_fields.is_empty() {
            // A non-object alternative cannot use an object readback contract.
            // Keep explicit universal fields when present to preserve the
            // existing object-body lane, but never infer branch-only fields.
            return RequestObjectSchemaCollection::Ineligible;
        }
    }
    merge_request_object_property_schemas(fields, local_fields);
    RequestObjectSchemaCollection::Object
}

fn merge_request_object_property_schemas<'a>(
    fields: &mut BTreeMap<String, Vec<&'a Value>>,
    additional: BTreeMap<String, Vec<&'a Value>>,
) {
    for (name, schemas) in additional {
        fields.entry(name).or_default().extend(schemas);
    }
}

fn property_schemas_are_write_only(schemas: &[&Value]) -> bool {
    if schemas.is_empty() {
        return false;
    }
    let mut remaining_steps = MAX_REQUEST_OBJECT_SCHEMA_STEPS;
    schemas
        .iter()
        .all(|schema| schema_declares_write_only(schema, 0, &mut remaining_steps))
}

fn schema_declares_write_only(schema: &Value, depth: usize, remaining_steps: &mut usize) -> bool {
    if depth > MAX_REQUEST_OBJECT_SCHEMA_DEPTH || *remaining_steps == 0 {
        return false;
    }
    *remaining_steps -= 1;
    if schema.get("writeOnly").and_then(Value::as_bool) == Some(true) {
        return true;
    }
    if schema
        .get("allOf")
        .and_then(Value::as_array)
        .is_some_and(|members| {
            members
                .iter()
                .any(|member| schema_declares_write_only(member, depth + 1, remaining_steps))
        })
    {
        return true;
    }
    ["oneOf", "anyOf"].iter().any(|composition| {
        schema
            .get(*composition)
            .and_then(Value::as_array)
            .is_some_and(|members| {
                !members.is_empty()
                    && members.iter().all(|member| {
                        schema_declares_write_only(member, depth + 1, remaining_steps)
                    })
            })
    })
}

fn path_targets_exact_resource(path: &str) -> bool {
    path.rsplit('/').next().is_some_and(|segment| {
        segment.starts_with('{') && segment.ends_with('}') && segment.len() > 2
    })
}

fn selector_can_be_response_id(selector: &str) -> bool {
    matches!(selector, "id" | "identifier")
        || selector.ends_with("_id")
        || selector.ends_with("_identifier")
}

fn infer_scope(path: &str) -> &'static str {
    if path.contains("/zones/{") {
        "zone"
    } else if path.contains("/accounts/{") {
        "account"
    } else if path.contains("/user") {
        "user"
    } else {
        "global"
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuideStage {
    Discover,
    Authenticate,
    SelectAccount,
    CheckEntitlement,
    InspectCurrentState,
    LoadStandards,
    MapDependencies,
    CalculateCost,
    BuildPlan,
    RequestApproval,
    AcquireLocks,
    Execute,
    Verify,
    Rectify,
    CloseWithEvidence,
}

impl GuideStage {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Discover => "discover",
            Self::Authenticate => "authenticate",
            Self::SelectAccount => "select_account",
            Self::CheckEntitlement => "check_entitlement",
            Self::InspectCurrentState => "inspect_current_state",
            Self::LoadStandards => "load_standards",
            Self::MapDependencies => "map_dependencies",
            Self::CalculateCost => "calculate_cost",
            Self::BuildPlan => "build_plan",
            Self::RequestApproval => "request_approval",
            Self::AcquireLocks => "acquire_locks",
            Self::Execute => "execute",
            Self::Verify => "verify",
            Self::Rectify => "rectify",
            Self::CloseWithEvidence => "close_with_evidence",
        }
    }
}

#[must_use]
pub fn guide_stages() -> &'static [GuideStage; 15] {
    &[
        GuideStage::Discover,
        GuideStage::Authenticate,
        GuideStage::SelectAccount,
        GuideStage::CheckEntitlement,
        GuideStage::InspectCurrentState,
        GuideStage::LoadStandards,
        GuideStage::MapDependencies,
        GuideStage::CalculateCost,
        GuideStage::BuildPlan,
        GuideStage::RequestApproval,
        GuideStage::AcquireLocks,
        GuideStage::Execute,
        GuideStage::Verify,
        GuideStage::Rectify,
        GuideStage::CloseWithEvidence,
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDisposition {
    AutoExecute,
    ApprovalRequired,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDecisionV1 {
    pub schema_version: u8,
    pub disposition: PolicyDisposition,
    pub reasons: Vec<String>,
    pub requires_cost_ceiling: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanStatus {
    Draft,
    Approved,
    Running,
    Consumed,
    Verified,
    Failed,
    RectificationRequired,
    Rectified,
    Expired,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionStageV1 {
    #[default]
    PlanPrepared,
    ApprovalPersisted,
    ConsumptionPersisted,
    BoundaryAttemptPersisted,
    BoundaryResponsePersisted,
    SecretSinkPersisted,
    VerificationAttemptPersisted,
    VerificationResponsePersisted,
    CompensationAttemptPersisted,
    CompensationResponsePersisted,
    Closed,
}

impl TransactionStageV1 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PlanPrepared => "plan_prepared",
            Self::ApprovalPersisted => "approval_persisted",
            Self::ConsumptionPersisted => "consumption_persisted",
            Self::BoundaryAttemptPersisted => "boundary_attempt_persisted",
            Self::BoundaryResponsePersisted => "boundary_response_persisted",
            Self::SecretSinkPersisted => "secret_sink_persisted",
            Self::VerificationAttemptPersisted => "verification_attempt_persisted",
            Self::VerificationResponsePersisted => "verification_response_persisted",
            Self::CompensationAttemptPersisted => "compensation_attempt_persisted",
            Self::CompensationResponsePersisted => "compensation_response_persisted",
            Self::Closed => "closed",
        }
    }

    const fn rank(self) -> u8 {
        match self {
            Self::PlanPrepared => 0,
            Self::ApprovalPersisted => 1,
            Self::ConsumptionPersisted => 2,
            Self::BoundaryAttemptPersisted => 3,
            Self::BoundaryResponsePersisted => 4,
            Self::SecretSinkPersisted => 5,
            Self::VerificationAttemptPersisted => 6,
            Self::VerificationResponsePersisted => 7,
            Self::CompensationAttemptPersisted => 8,
            Self::CompensationResponsePersisted => 9,
            Self::Closed => 10,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionCheckpointV1 {
    pub stage: TransactionStageV1,
    pub recorded_at: DateTime<Utc>,
    pub plan_content_hash: String,
    pub plan_status: PlanStatus,
    pub previous_checkpoint_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_hash: Option<String>,
    pub checkpoint_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MoneyV1 {
    pub currency: String,
    pub amount: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalV1 {
    pub approved_at: DateTime<Utc>,
    pub approved_content_hash: String,
    pub max_cost: Option<MoneyV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlanV1 {
    pub schema_version: u8,
    pub operation_id: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub profile_id: String,
    pub account_id: String,
    pub catalog_hash: String,
    #[serde(default = "default_permission_lane")]
    pub permission_lane: String,
    #[serde(default)]
    pub precondition_hashes: BTreeMap<String, String>,
    pub capability: CapabilityV1,
    pub targets: Value,
    pub input: Value,
    pub affected_repositories: Vec<String>,
    pub affected_resources: Vec<String>,
    pub local_diffs: Vec<Value>,
    pub cloudflare_diffs: Vec<Value>,
    pub verification_steps: Vec<String>,
    pub compensation_steps: Vec<String>,
    pub non_reversible_warnings: Vec<String>,
    pub policy: PolicyDecisionV1,
    pub status: PlanStatus,
    pub approval: Option<ApprovalV1>,
    pub content_hash: String,
    #[serde(default)]
    pub transaction_stage: TransactionStageV1,
    #[serde(default)]
    pub transaction_journal: Vec<TransactionCheckpointV1>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub transaction_artifacts: BTreeMap<String, Value>,
}

fn default_permission_lane() -> String {
    "unspecified".to_owned()
}

impl PlanV1 {
    pub fn draft(
        profile_id: &str,
        account_id: &str,
        catalog_hash: &str,
        capability: CapabilityV1,
        targets: Value,
    ) -> Result<Self> {
        let created_at = Utc::now();
        let mut plan = Self {
            schema_version: 1,
            operation_id: Uuid::new_v4().to_string(),
            created_at,
            expires_at: created_at + Duration::hours(24),
            profile_id: profile_id.to_owned(),
            account_id: account_id.to_owned(),
            catalog_hash: catalog_hash.to_owned(),
            permission_lane: "unspecified".to_owned(),
            precondition_hashes: BTreeMap::new(),
            capability,
            targets,
            input: Value::Null,
            affected_repositories: Vec::new(),
            affected_resources: Vec::new(),
            local_diffs: Vec::new(),
            cloudflare_diffs: Vec::new(),
            verification_steps: Vec::new(),
            compensation_steps: Vec::new(),
            non_reversible_warnings: Vec::new(),
            policy: PolicyDecisionV1 {
                schema_version: 1,
                disposition: PolicyDisposition::ApprovalRequired,
                reasons: vec!["policy has not classified this operation".to_owned()],
                requires_cost_ceiling: false,
            },
            status: PlanStatus::Draft,
            approval: None,
            content_hash: String::new(),
            transaction_stage: TransactionStageV1::PlanPrepared,
            transaction_journal: Vec::new(),
            transaction_artifacts: BTreeMap::new(),
        };
        plan.refresh_hash()?;
        plan.record_transaction_stage(TransactionStageV1::PlanPrepared)?;
        Ok(plan)
    }

    pub fn refresh_hash(&mut self) -> Result<()> {
        self.content_hash = hash_value(&self.hashable_content())?;
        Ok(())
    }

    pub fn approve(&mut self, explicit_yes: bool, max_cost: Option<MoneyV1>) -> Result<()> {
        if !explicit_yes {
            return Err(CoreError::ExplicitApprovalRequired);
        }
        if self.status != PlanStatus::Draft {
            return Err(CoreError::InvalidPlanState {
                operation_id: self.operation_id.clone(),
                actual: self.status,
                expected: "draft",
            });
        }
        if Utc::now() > self.expires_at {
            self.status = PlanStatus::Expired;
            return Err(CoreError::PlanExpired {
                operation_id: self.operation_id.clone(),
                expires_at: self.expires_at,
            });
        }
        if self.policy.requires_cost_ceiling && max_cost.is_none() {
            return Err(CoreError::CostCeilingRequired(self.operation_id.clone()));
        }
        if let (Some(required), Some(currency), Some(approved)) = (
            self.capability.cost.maximum,
            self.capability.cost.currency.as_deref(),
            max_cost.as_ref(),
        ) && (!approved.currency.eq_ignore_ascii_case(currency) || approved.amount < required)
        {
            return Err(CoreError::CostCeilingTooLow {
                operation_id: self.operation_id.clone(),
                required_currency: currency.to_owned(),
                required_amount: required,
            });
        }
        let current_hash = hash_value(&self.hashable_content())?;
        if current_hash != self.content_hash {
            return Err(CoreError::InvalidPlanState {
                operation_id: self.operation_id.clone(),
                actual: self.status,
                expected: "unchanged hash-bound draft",
            });
        }
        self.approval = Some(ApprovalV1 {
            approved_at: Utc::now(),
            approved_content_hash: self.content_hash.clone(),
            max_cost,
        });
        self.status = PlanStatus::Approved;
        self.record_transaction_stage(TransactionStageV1::ApprovalPersisted)?;
        Ok(())
    }

    pub fn mark_consumed(&mut self) -> Result<()> {
        if Utc::now() > self.expires_at {
            self.status = PlanStatus::Expired;
            return Err(CoreError::PlanExpired {
                operation_id: self.operation_id.clone(),
                expires_at: self.expires_at,
            });
        }
        let current_hash = hash_value(&self.hashable_content())?;
        if current_hash != self.content_hash {
            return Err(CoreError::PlanDrifted(self.operation_id.clone()));
        }
        match self.status {
            PlanStatus::Approved => {
                let approval_matches = self
                    .approval
                    .as_ref()
                    .is_some_and(|approval| approval.approved_content_hash == self.content_hash);
                if !approval_matches {
                    return Err(CoreError::PlanDrifted(self.operation_id.clone()));
                }
            }
            PlanStatus::Draft
                if self.policy.disposition == PolicyDisposition::AutoExecute
                    && self.approval.is_none() => {}
            _ => {
                return Err(CoreError::InvalidPlanState {
                    operation_id: self.operation_id.clone(),
                    actual: self.status,
                    expected: "approved or policy-authorized auto-execute draft",
                });
            }
        }
        self.status = PlanStatus::Consumed;
        self.record_transaction_stage(TransactionStageV1::ConsumptionPersisted)?;
        Ok(())
    }

    /// Appends a forward-only, hash-chained transaction checkpoint. Runtime
    /// persistence is performed by the caller immediately after this method.
    pub fn record_transaction_stage(&mut self, stage: TransactionStageV1) -> Result<()> {
        self.record_transaction_stage_inner(stage, None)
    }

    /// Appends a checkpoint whose non-secret receipt is independently hashed
    /// and linked into the transaction chain. Artifacts are mutable execution
    /// facts rather than reviewed plan content, so their integrity is carried
    /// by the checkpoint instead of the approval hash.
    pub fn record_transaction_stage_with_artifact(
        &mut self,
        stage: TransactionStageV1,
        artifact: Value,
    ) -> Result<()> {
        self.record_transaction_stage_inner(stage, Some(artifact))
    }

    #[must_use]
    pub fn transaction_artifact(&self, stage: TransactionStageV1) -> Option<&Value> {
        self.transaction_artifacts.get(stage.as_str())
    }

    fn record_transaction_stage_inner(
        &mut self,
        stage: TransactionStageV1,
        artifact: Option<Value>,
    ) -> Result<()> {
        if self.transaction_journal.is_empty() {
            if stage != TransactionStageV1::PlanPrepared {
                return Err(self.invalid_transaction_journal(
                    "the first checkpoint must be plan_prepared".to_owned(),
                ));
            }
        } else {
            self.validate_transaction_journal_inner(false)?;
            if stage.rank() <= self.transaction_stage.rank() {
                return Err(self.invalid_transaction_journal(format!(
                    "checkpoint {stage:?} does not advance past {:?}",
                    self.transaction_stage
                )));
            }
        }
        if artifact
            .as_ref()
            .is_some_and(|value| redact_json(value) != *value)
        {
            return Err(self.invalid_transaction_journal(format!(
                "checkpoint {stage:?} artifact contains secret-bearing fields"
            )));
        }
        let recorded_at = Utc::now();
        let previous_checkpoint_hash = self
            .transaction_journal
            .last()
            .map(|checkpoint| checkpoint.checkpoint_hash.clone());
        let artifact_hash = artifact.as_ref().map(hash_value).transpose()?;
        let checkpoint_hash = self.transaction_checkpoint_hash(
            stage,
            recorded_at,
            &self.content_hash,
            self.status,
            previous_checkpoint_hash.as_deref(),
            artifact_hash.as_deref(),
        )?;
        if let Some(artifact) = artifact {
            self.transaction_artifacts
                .insert(stage.as_str().to_owned(), artifact);
        }
        self.transaction_journal.push(TransactionCheckpointV1 {
            stage,
            recorded_at,
            plan_content_hash: self.content_hash.clone(),
            plan_status: self.status,
            previous_checkpoint_hash,
            artifact_hash,
            checkpoint_hash,
        });
        self.transaction_stage = stage;
        Ok(())
    }

    /// Validates stage ordering and the complete checkpoint hash chain.
    pub fn validate_transaction_journal(&self) -> Result<()> {
        self.validate_transaction_journal_inner(true)
    }

    fn validate_transaction_journal_inner(&self, bind_current_status: bool) -> Result<()> {
        if self.transaction_journal.is_empty() {
            return if self.status == PlanStatus::Draft
                && self.transaction_stage == TransactionStageV1::PlanPrepared
            {
                Ok(())
            } else {
                Err(self
                    .invalid_transaction_journal("a non-draft plan has no checkpoints".to_owned()))
            };
        }
        let mut previous_stage: Option<TransactionStageV1> = None;
        let mut previous_hash: Option<&str> = None;
        let mut artifact_count = 0_usize;
        for checkpoint in &self.transaction_journal {
            if let Some(stage) = previous_stage
                && checkpoint.stage.rank() <= stage.rank()
            {
                return Err(self.invalid_transaction_journal(format!(
                    "checkpoint {:?} is not forward-only",
                    checkpoint.stage
                )));
            }
            if checkpoint.previous_checkpoint_hash.as_deref() != previous_hash {
                return Err(self.invalid_transaction_journal(format!(
                    "checkpoint {:?} does not link to its predecessor",
                    checkpoint.stage
                )));
            }
            match (
                checkpoint.artifact_hash.as_deref(),
                self.transaction_artifacts.get(checkpoint.stage.as_str()),
            ) {
                (Some(expected_hash), Some(artifact)) => {
                    if redact_json(artifact) != *artifact || hash_value(artifact)? != expected_hash
                    {
                        return Err(self.invalid_transaction_journal(format!(
                            "checkpoint {:?} artifact hash does not match",
                            checkpoint.stage
                        )));
                    }
                    artifact_count += 1;
                }
                (None, None) => {}
                _ => {
                    return Err(self.invalid_transaction_journal(format!(
                        "checkpoint {:?} artifact presence does not match",
                        checkpoint.stage
                    )));
                }
            }
            let expected = self.transaction_checkpoint_hash(
                checkpoint.stage,
                checkpoint.recorded_at,
                &checkpoint.plan_content_hash,
                checkpoint.plan_status,
                checkpoint.previous_checkpoint_hash.as_deref(),
                checkpoint.artifact_hash.as_deref(),
            )?;
            if checkpoint.checkpoint_hash != expected {
                return Err(self.invalid_transaction_journal(format!(
                    "checkpoint {:?} hash does not match",
                    checkpoint.stage
                )));
            }
            previous_stage = Some(checkpoint.stage);
            previous_hash = Some(checkpoint.checkpoint_hash.as_str());
        }
        if artifact_count != self.transaction_artifacts.len() {
            return Err(self.invalid_transaction_journal(
                "transaction artifacts contain a receipt without a matching checkpoint".to_owned(),
            ));
        }
        if previous_stage != Some(self.transaction_stage) {
            return Err(self.invalid_transaction_journal(
                "current transaction stage does not match the journal tail".to_owned(),
            ));
        }
        if bind_current_status
            && self
                .transaction_journal
                .last()
                .is_some_and(|checkpoint| checkpoint.plan_status != self.status)
        {
            return Err(self.invalid_transaction_journal(
                "current plan status does not match the journal tail".to_owned(),
            ));
        }
        Ok(())
    }

    fn transaction_checkpoint_hash(
        &self,
        stage: TransactionStageV1,
        recorded_at: DateTime<Utc>,
        plan_content_hash: &str,
        plan_status: PlanStatus,
        previous_checkpoint_hash: Option<&str>,
        artifact_hash: Option<&str>,
    ) -> Result<String> {
        let mut value = serde_json::json!({
            "operation_id": self.operation_id,
            "plan_content_hash": plan_content_hash,
            "plan_status": plan_status,
            "stage": stage,
            "recorded_at": recorded_at,
            "previous_checkpoint_hash": previous_checkpoint_hash,
        });
        if let Some(artifact_hash) = artifact_hash
            && let Some(object) = value.as_object_mut()
        {
            object.insert(
                "artifact_hash".to_owned(),
                Value::String(artifact_hash.to_owned()),
            );
        }
        hash_value(&value)
    }

    fn invalid_transaction_journal(&self, reason: String) -> CoreError {
        CoreError::InvalidTransactionJournal {
            operation_id: self.operation_id.clone(),
            reason,
        }
    }

    fn hashable_content(&self) -> Value {
        serde_json::json!({
            "schema_version": self.schema_version,
            "operation_id": self.operation_id,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "profile_id": self.profile_id,
            "account_id": self.account_id,
            "catalog_hash": self.catalog_hash,
            "permission_lane": self.permission_lane,
            "precondition_hashes": self.precondition_hashes,
            "capability": self.capability,
            "targets": self.targets,
            "input": self.input,
            "affected_repositories": self.affected_repositories,
            "affected_resources": self.affected_resources,
            "local_diffs": self.local_diffs,
            "cloudflare_diffs": self.cloudflare_diffs,
            "verification_steps": self.verification_steps,
            "compensation_steps": self.compensation_steps,
            "non_reversible_warnings": self.non_reversible_warnings,
            "policy": self.policy,
        })
    }
}

pub fn hash_value(value: &Value) -> Result<String> {
    let encoded = serde_json::to_vec(value)?;
    let digest = Sha256::digest(encoded);
    Ok(format!("sha256:{}", hex::encode(digest)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClass {
    SourceConfig,
    LiveRead,
    Preview,
    Apply,
    PostChangeVerification,
    AgentAction,
    LocalProof,
    Release,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceV1 {
    pub schema_version: u8,
    pub generated_at: DateTime<Utc>,
    pub class: EvidenceClass,
    pub content_hash: String,
    pub path: String,
    pub metadata: Value,
}

impl EvidenceV1 {
    #[must_use]
    pub fn new(class: EvidenceClass, content_hash: &str, path: &str) -> Self {
        Self {
            schema_version: 1,
            generated_at: Utc::now(),
            class,
            content_hash: content_hash.to_owned(),
            path: path.to_owned(),
            metadata: Value::Null,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationState {
    NotApplicable,
    Pending,
    Passed,
    Failed,
    Unsupported,
}

impl VerificationState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotApplicable => "not_applicable",
            Self::Pending => "pending",
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationStatusV1 {
    pub state: VerificationState,
    pub basis: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorV1 {
    pub code: String,
    pub message: String,
    pub next_step: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResultEnvelopeV2 {
    pub schema_version: u8,
    pub generated_at: DateTime<Utc>,
    pub ok: bool,
    pub command: String,
    pub capability_id: Option<String>,
    pub operation_id: Option<String>,
    pub profile_id: Option<String>,
    pub account_id: Option<String>,
    pub performed: bool,
    pub policy_decision: Option<PolicyDecisionV1>,
    pub verification: VerificationStatusV1,
    pub evidence: Vec<EvidenceV1>,
    pub result: Value,
    pub error: Option<ErrorV1>,
}

impl ResultEnvelopeV2 {
    #[must_use]
    pub fn success(command: &str, result: Value) -> Self {
        let result = redact_json(&result);
        Self {
            schema_version: 2,
            generated_at: Utc::now(),
            ok: true,
            command: command.to_owned(),
            capability_id: None,
            operation_id: None,
            profile_id: None,
            account_id: None,
            performed: false,
            policy_decision: None,
            verification: VerificationStatusV1 {
                state: VerificationState::NotApplicable,
                basis: None,
            },
            evidence: Vec::new(),
            result,
            error: None,
        }
    }

    #[must_use]
    pub fn with_evidence(mut self, evidence: EvidenceV1) -> Self {
        self.evidence.push(evidence);
        self
    }

    #[must_use]
    pub fn failure(command: &str, code: &str, message: &str, next_step: Option<&str>) -> Self {
        Self {
            schema_version: 2,
            generated_at: Utc::now(),
            ok: false,
            command: command.to_owned(),
            capability_id: None,
            operation_id: None,
            profile_id: None,
            account_id: None,
            performed: false,
            policy_decision: None,
            verification: VerificationStatusV1 {
                state: VerificationState::Pending,
                basis: None,
            },
            evidence: Vec::new(),
            result: Value::Null,
            error: Some(ErrorV1 {
                code: code.to_owned(),
                message: message.to_owned(),
                next_step: next_step.map(str::to_owned),
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentActionKind {
    InterpretIntent,
    PreparePullRequest,
    MergePullRequest,
    ObserveUi,
    ChangeUi,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentActionV1 {
    pub schema_version: u8,
    pub action_id: String,
    pub operation_id: Option<String>,
    pub kind: AgentActionKind,
    pub agent: String,
    pub account_id: Option<String>,
    pub target: Value,
    pub instructions: String,
    pub content_hash: String,
}

#[must_use]
pub fn redact_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, item)| {
                    if is_sensitive_key(key) {
                        (key.clone(), Value::String("[REDACTED]".to_owned()))
                    } else {
                        (key.clone(), redact_json(item))
                    }
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(redact_json).collect()),
        _ => value.clone(),
    }
}

fn is_sensitive_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase();
    [
        "access_token",
        "refresh_token",
        "api_token",
        "api_key",
        "global_key",
        "client_secret",
        "private_key",
        "authorization",
        "password",
        "cookie",
        "secret",
        "token",
    ]
    .iter()
    .any(|sensitive| normalized == *sensitive || normalized.ends_with(&format!("_{sensitive}")))
}
