//! Cloudflare capability catalog normalization and indexing.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use cfctl_core::{
    AdapterStatus, AnalyticsQueryContractV1, AnalyticsQueryKindV1,
    AsyncCollectionMutationContractV1, BillingModelV1, CapabilityAuthorityScopeV1, CapabilityV1,
    CostExposureV1, CostV1, CreatedCollectionResourceContractV1, CreatedNestedResourceContractV1,
    CreatedResourceContractV1, D1FullExportContractV1, D1SchemaIntrospectionContractV1,
    DeletedNestedResourceContractV1, DeletedResourceContractV1, EffectClass,
    EmailRoutingSubdomainDnsContractV1, EmailSendingDnsRepairContractV1, EntitlementProbeV1,
    EntitlementV1, EventBatchContractV1, GraphqlAnalyticsContractV1, KnowledgeReferenceV1,
    Maturity, Mln0142PostImportSchemaContractV1, Mln0143DataInvariantsContractV1, OutputFormatV1,
    PaginationModeV1, QuerySerializationV1, R2LogRetrievalContractV1,
    R2PrivateFileUploadContractV1, ResponseBodyModeV1, ResponseContractV1, RiskClass,
    SamePathReadContractV1, SecurityActionContractV1, SecurityActionKindV1,
    SecurityActionSafetyProfileV1, SelectorContractV1, SelectorV1, TimeRangeContractV1,
    TimestampFormatV1, UpdatedResourceContractV1, WorkflowContractV1, WorkflowStepV1, hash_value,
    request_header_is_reserved,
};
use chrono::{DateTime, Utc};
use futures_util::{StreamExt, stream};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

pub const OFFICIAL_OPENAPI_URL: &str =
    "https://raw.githubusercontent.com/cloudflare/api-schemas/main/openapi.json";
pub const OFFICIAL_DOCS_INDEX_URL: &str = "https://developers.cloudflare.com/llms.txt";
pub const OFFICIAL_CHANGELOG_URL: &str = "https://developers.cloudflare.com/changelog/";

/// Frozen migration debt from before workspace-owned operation packs existed.
/// Adding an id here is a public architecture decision, not the normal path for
/// extending cfctl. Keep this sorted for the fail-closed binary search below.
pub const LEGACY_EMBEDDED_CAPABILITY_IDS: [&str; 5] = [
    "d1-import-approved-mln-migration",
    "d1-import-approved-osint-research-migration",
    "d1-resume-approved-mln-import-poll",
    "mln-0142-post-import-schema",
    "mln-0143-data-invariants",
];

fn legacy_embedded_contract_matches(capability: &CapabilityV1) -> bool {
    match capability.id.as_str() {
        "d1-import-approved-mln-migration" => capability
            .d1_approved_mln_import
            .as_ref()
            .is_some_and(|contract| contract.repository_id == "github.com/rogu3bear/mln-web"),
        "d1-import-approved-osint-research-migration" => capability
            .d1_approved_mln_import
            .as_ref()
            .is_some_and(|contract| {
                contract.repository_id == "github.com/rogu3bear/osint-research-center"
            }),
        "d1-resume-approved-mln-import-poll" => capability
            .d1_approved_mln_import_poll_resume
            .as_ref()
            .is_some_and(|contract| {
                contract.root_capability_id == "d1-import-approved-mln-migration"
            }),
        "mln-0142-post-import-schema" => capability.mln_0142_post_import_schema.is_some(),
        "mln-0143-data-invariants" => capability.mln_0143_data_invariants.is_some(),
        _ => false,
    }
}

#[cfg(test)]
mod maildesk_provider_contract_tests {
    use super::*;

    fn blocked_mutation(id: &str, method: &str, path: &str, product: &str) -> CapabilityV1 {
        let mut capability = CapabilityV1::new(id, id, method, path);
        product.clone_into(&mut capability.product);
        capability.mutating = true;
        capability.adapter_status = AdapterStatus::Blocked;
        capability.blocked_reason = Some("operation contract incomplete: fixture".to_owned());
        capability.response_contract = Some(ResponseContractV1 {
            success_statuses: vec!["200".to_owned()],
            success_media_types: vec!["application/json".to_owned()],
            body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
        });
        capability.verification.required = true;
        capability.verification.strategy =
            "post_change_read_or_operation_specific_verifier".to_owned();
        capability.rollback.warning = Some("rollback semantics have not been declared".to_owned());
        capability
    }

    fn read(id: &str, path: &str, product: &str) -> CapabilityV1 {
        let mut capability = CapabilityV1::new(id, id, "GET", path);
        product.clone_into(&mut capability.product);
        capability.adapter_status = AdapterStatus::DynamicApi;
        capability
    }

    fn object_key_selector(description: &str) -> SelectorV1 {
        SelectorV1 {
            name: "object_key".to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: Some(description.to_owned()),
            contract: None,
        }
    }

    #[test]
    fn r2_private_upload_is_create_only_body_private_and_readback_bound() {
        let mut capabilities = BTreeMap::new();
        let mut upload = blocked_mutation("r2-put-object", "PUT", R2_OBJECT_PATH, "R2 Object");
        upload.selectors = vec![
            object_key_selector("Slashes MUST NOT be percent-encoded"),
            SelectorV1 {
                name: "Content-Type".to_owned(),
                location: "header".to_owned(),
                required: false,
                value_type: "string".to_owned(),
                description: None,
                contract: None,
            },
        ];
        capabilities.insert(upload.id.clone(), upload);
        capabilities.insert(
            "r2-get-object".to_owned(),
            read("r2-get-object", R2_OBJECT_PATH, "R2 Object"),
        );
        let mut delete =
            blocked_mutation("r2-delete-object", "DELETE", R2_OBJECT_PATH, "R2 Object");
        delete.permissions = vec!["Workers R2 Storage Write".to_owned()];
        capabilities.insert(delete.id.clone(), delete);

        finalize_r2_private_file_upload_contract(&mut capabilities);
        let upload = &capabilities["r2-put-object"];
        assert_eq!(
            upload.adapter_status,
            AdapterStatus::DynamicApi,
            "{:?}",
            upload.blocked_reason
        );
        assert_eq!(
            upload.verification.strategy,
            "r2_private_file_upload_etag_and_conditional_read"
        );
        assert!(upload.request_schema.is_none());
        assert!(
            upload
                .selectors
                .iter()
                .find(|selector| selector.name == "Content-Type")
                .is_some_and(|selector| selector.required)
        );
        assert!(
            upload
                .r2_private_file_upload
                .as_ref()
                .is_some_and(|contract| {
                    contract.require_if_none_match_star
                        && contract.read_capability_id == "r2-get-object"
                        && contract.delete_capability_id == "r2-delete-object"
                })
        );
    }

    #[test]
    fn r2_lifecycle_is_destructive_full_snapshot_restorable() {
        let mut lifecycle = blocked_mutation(
            "r2-put-bucket-lifecycle-configuration",
            "PUT",
            R2_LIFECYCLE_PATH,
            "R2 Bucket",
        );
        lifecycle.request_schema = Some(serde_json::json!({
            "type":"object",
            "properties":{"rules":{"type":"array"}},
            "x-cfctl-body-required":true
        }));
        lifecycle.verification.strategy =
            "same_path_result_contains_planned_fields_after_update".to_owned();
        lifecycle.same_path_read = Some(SamePathReadContractV1 {
            path: R2_LIFECYCLE_PATH.to_owned(),
            read_capability_id: "r2-get-bucket-lifecycle-configuration".to_owned(),
            verified_response_fields: vec!["rules".to_owned()],
        });
        let mut capabilities = BTreeMap::from([
            (lifecycle.id.clone(), lifecycle),
            (
                "r2-get-bucket-lifecycle-configuration".to_owned(),
                read(
                    "r2-get-bucket-lifecycle-configuration",
                    R2_LIFECYCLE_PATH,
                    "R2 Bucket",
                ),
            ),
        ]);
        finalize_r2_lifecycle_contract(&mut capabilities);
        let lifecycle = &capabilities["r2-put-bucket-lifecycle-configuration"];
        assert_eq!(lifecycle.adapter_status, AdapterStatus::DynamicApi);
        assert_eq!(lifecycle.risk, RiskClass::Destructive);
        assert_eq!(lifecycle.effect, EffectClass::Destructive);
        assert_eq!(
            lifecycle
                .request_schema
                .as_ref()
                .and_then(|schema| schema
                    .pointer("/properties/rules/x-cfctl-verification-array-identity"))
                .and_then(Value::as_str),
            Some("id")
        );
        assert_eq!(
            lifecycle.rollback.strategy.as_deref(),
            Some("restore_same_path_prior_snapshot")
        );
        assert!(
            lifecycle
                .rollback
                .warning
                .as_deref()
                .is_some_and(|warning| warning.contains("cannot be recovered"))
        );
    }

    #[test]
    fn email_preview_is_read_only_and_subdomain_enable_cannot_target_apex() {
        let mut preview = blocked_mutation(
            "email-sending-subdomains-preview-sending-subdomain",
            "POST",
            "/zones/{zone_id}/email/sending/subdomains/preview",
            "Email Sending subdomains",
        );
        preview.description =
            Some("This is a read-only dry-run — no records are created or modified.".to_owned());
        preview.request_schema = Some(serde_json::json!({
            "type":"object","required":["name"],"properties":{"name":{"type":"string"}},
            "x-cfctl-body-required":true
        }));
        let mut enable = blocked_mutation(
            "email-routing-settings-enable-email-routing-dns",
            "POST",
            EMAIL_ROUTING_DNS_PATH,
            "Email Routing settings",
        );
        enable.request_schema = Some(serde_json::json!({
            "type":"object","nullable":true,"properties":{"name":{"type":"string"}},
            "x-cfctl-body-required":false
        }));
        enable.selectors = vec![SelectorV1 {
            name: "zone_id".to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        }];
        let mut dns_read = read(
            "email-routing-settings-email-routing-dns-settings",
            EMAIL_ROUTING_DNS_PATH,
            "Email Routing settings",
        );
        dns_read.selectors = vec![SelectorV1 {
            name: "subdomain".to_owned(),
            location: "query".to_owned(),
            required: false,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        }];
        let mut capabilities = vec![
            (preview.id.clone(), preview),
            (enable.id.clone(), enable),
            (dns_read.id.clone(), dns_read),
        ]
        .into_iter()
        .collect();
        finalize_email_sending_contracts(&mut capabilities);
        finalize_email_routing_subdomain_contract(&mut capabilities);

        let preview = &capabilities["email-sending-subdomains-preview-sending-subdomain"];
        assert!(!preview.mutating);
        assert_eq!(preview.risk, RiskClass::Read);
        assert_eq!(preview.effect, EffectClass::ReadOnly);
        assert_eq!(preview.permissions, ["Email Sending Read"]);

        let enable = &capabilities["email-routing-settings-enable-email-routing-dns"];
        assert_eq!(
            enable.adapter_status,
            AdapterStatus::DynamicApi,
            "{:?}",
            enable.blocked_reason
        );
        assert_eq!(enable.permissions, ["DNS Write", "Zone Settings Write"]);
        assert_eq!(
            enable
                .request_schema
                .as_ref()
                .and_then(|schema| schema.get("additionalProperties")),
            Some(&Value::Bool(false))
        );
        assert_eq!(
            enable
                .request_schema
                .as_ref()
                .and_then(|schema| schema.get("x-cfctl-body-required")),
            Some(&Value::Bool(true))
        );
        assert_eq!(
            enable
                .request_schema
                .as_ref()
                .and_then(|schema| schema.get("nullable")),
            None
        );
        assert!(enable.rollback.warning.as_deref().is_some_and(|warning| {
            warning.contains("no subdomain-scoped provider delete is proven")
                && warning.contains("exact DNS-record and routing-rule restoration")
                && warning.contains("never use zone-wide Email Routing disable")
                && warning.contains("apex MX and routing must remain untouched")
        }));
    }
}

const fn authority_scope_name(scope: Option<CapabilityAuthorityScopeV1>) -> &'static str {
    match scope {
        Some(CapabilityAuthorityScopeV1::ProviderGeneric) => "provider_generic",
        Some(CapabilityAuthorityScopeV1::CfctlProduct) => "cfctl_product",
        Some(CapabilityAuthorityScopeV1::WorkspaceOwned) => "workspace_owned",
        Some(CapabilityAuthorityScopeV1::LegacyEmbedded) => "legacy_embedded",
        None => "unclassified",
    }
}

#[derive(Debug, Error)]
pub enum CatalogError {
    #[error("OpenAPI document does not contain an object at `paths`")]
    MissingPaths,
    #[error("duplicate operation id `{0}`")]
    DuplicateOperation(String),
    #[error("unsupported OpenAPI parameter reference `{0}`")]
    UnsupportedParameterReference(String),
    #[error("OpenAPI parameter reference `{0}` does not resolve")]
    UnresolvedParameterReference(String),
    #[error("OpenAPI parameter reference depth exceeds the safety limit at `{0}`")]
    ParameterReferenceDepth(String),
    #[error("OpenAPI parameter is missing string field `{0}`")]
    InvalidParameter(String),
    #[error("duplicate `{location}` parameter `{name}`")]
    DuplicateParameter { location: String, name: String },
    #[error("unsupported OpenAPI response reference `{0}`")]
    UnsupportedResponseReference(String),
    #[error("OpenAPI response reference `{0}` does not resolve")]
    UnresolvedResponseReference(String),
    #[error("OpenAPI response reference depth exceeds the safety limit at `{0}`")]
    ResponseReferenceDepth(String),
    #[error("catalog content hash mismatch: recorded {recorded}, actual {actual}")]
    ContentHashMismatch { recorded: String, actual: String },
    #[error("catalog capability authority contract is invalid: {0}")]
    InvalidAuthorityContract(String),
    #[error(transparent)]
    Core(#[from] cfctl_core::CoreError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error("catalog I/O failed for {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error(transparent)]
    Sql(#[from] rusqlite::Error),
}

pub type Result<T> = std::result::Result<T, CatalogError>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CatalogSnapshot {
    pub schema_version: u8,
    pub generated_at: DateTime<Utc>,
    pub source_url: String,
    #[serde(default)]
    pub source_hash: String,
    pub schema_hash: String,
    pub capabilities: BTreeMap<String, CapabilityV1>,
}

impl CatalogSnapshot {
    pub fn refresh_hash(&mut self) -> Result<()> {
        self.validate_authority_contracts()?;
        self.schema_hash = hash_value(&serde_json::to_value(&self.capabilities)?)?;
        Ok(())
    }

    pub fn validate_hash(&self) -> Result<()> {
        self.validate_authority_contracts()?;
        let actual = hash_value(&serde_json::to_value(&self.capabilities)?)?;
        if self.schema_hash != actual {
            return Err(CatalogError::ContentHashMismatch {
                recorded: self.schema_hash.clone(),
                actual,
            });
        }
        Ok(())
    }

    /// Enforces the ownership boundary introduced with catalog schema v2.
    ///
    /// Schema v1 remains hash-readable so an installed pre-v2 catalog can be
    /// preserved during sync. It does not acquire authority metadata by
    /// inference. Every newly normalized v2 snapshot must classify every
    /// capability, and its frozen embedded-workspace set cannot grow through a
    /// generic constructor or a plausible-looking label.
    pub fn validate_authority_contracts(&self) -> Result<()> {
        if self.schema_version < 2 {
            return Ok(());
        }
        for capability in self.capabilities.values() {
            let scope = capability.authority_scope.ok_or_else(|| {
                CatalogError::InvalidAuthorityContract(format!(
                    "`{}` is unclassified in a v2 snapshot",
                    capability.id
                ))
            })?;
            let legacy_contract_matches = legacy_embedded_contract_matches(capability);
            let embeds_workspace_contract = capability.mln_0142_post_import_schema.is_some()
                || capability.mln_0143_data_invariants.is_some()
                || capability
                    .d1_approved_mln_import
                    .as_ref()
                    .is_some_and(|contract| {
                        !contract.repository_id.is_empty()
                            || !contract.repository_head.is_empty()
                            || !contract.account_id.is_empty()
                            || !contract.database_id.is_empty()
                            || !contract.migrations.is_empty()
                    })
                || capability
                    .d1_approved_mln_import_poll_resume
                    .as_ref()
                    .is_some_and(|contract| {
                        !contract.account_id.is_empty()
                            || !contract.database_id.is_empty()
                            || contract.root_capability_id != "d1-import-database"
                    });
            match scope {
                CapabilityAuthorityScopeV1::LegacyEmbedded if !legacy_contract_matches => {
                    return Err(CatalogError::InvalidAuthorityContract(format!(
                        "`{}` is not one of the frozen exact legacy contracts",
                        capability.id
                    )));
                }
                CapabilityAuthorityScopeV1::WorkspaceOwned => {
                    return Err(CatalogError::InvalidAuthorityContract(format!(
                        "`{}` is workspace-owned but was inserted into the provider catalog; workspace operations require a separate typed declaration loader",
                        capability.id
                    )));
                }
                CapabilityAuthorityScopeV1::ProviderGeneric
                | CapabilityAuthorityScopeV1::CfctlProduct
                    if embeds_workspace_contract
                        || LEGACY_EMBEDDED_CAPABILITY_IDS
                            .binary_search(&capability.id.as_str())
                            .is_ok() =>
                {
                    return Err(CatalogError::InvalidAuthorityContract(format!(
                        "`{}` embeds application authority but is classified as {scope:?}",
                        capability.id
                    )));
                }
                CapabilityAuthorityScopeV1::LegacyEmbedded
                | CapabilityAuthorityScopeV1::ProviderGeneric
                | CapabilityAuthorityScopeV1::CfctlProduct => {}
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn get(&self, id: &str) -> Option<&CapabilityV1> {
        self.capabilities.get(id)
    }

    /// Rank capabilities against the intent, keeping the numeric relevance
    /// score. Deterministic: sorted by score descending, then id ascending.
    /// `search` discards the scores; a caller that needs an ambiguity margin
    /// (e.g. the deterministic resolver) uses this instead.
    #[must_use]
    pub fn search_scored(&self, query: &str) -> Vec<(&CapabilityV1, usize)> {
        let terms = intent_terms(query);
        let mut ranked: Vec<(&CapabilityV1, usize)> = self
            .capabilities
            .values()
            .filter_map(|capability| {
                let score = intent_score(capability, &terms);
                (score > 0).then_some((capability, score))
            })
            .collect();
        ranked.sort_by(|(left, left_score), (right, right_score)| {
            right_score
                .cmp(left_score)
                .then_with(|| left.id.cmp(&right.id))
        });
        ranked
    }

    #[must_use]
    pub fn search(&self, query: &str) -> Vec<&CapabilityV1> {
        self.search_scored(query)
            .into_iter()
            .map(|(capability, _score)| capability)
            .collect()
    }

    #[must_use]
    pub fn diff(old: &Self, new: &Self) -> Vec<CatalogChangeV1> {
        let ids: BTreeSet<&String> = old
            .capabilities
            .keys()
            .chain(new.capabilities.keys())
            .collect();
        ids.into_iter()
            .filter_map(
                |id| match (old.capabilities.get(id), new.capabilities.get(id)) {
                    (None, Some(_)) => Some(CatalogChangeV1 {
                        id: id.clone(),
                        kind: CatalogChangeKind::Added,
                    }),
                    (Some(_), None) => Some(CatalogChangeV1 {
                        id: id.clone(),
                        kind: CatalogChangeKind::Removed,
                    }),
                    (Some(before), Some(after)) if before != after => Some(CatalogChangeV1 {
                        id: id.clone(),
                        kind: CatalogChangeKind::Changed,
                    }),
                    _ => None,
                },
            )
            .collect()
    }

    #[must_use]
    pub fn coverage(&self) -> CatalogCoverageV1 {
        let mut adapter_statuses = BTreeMap::new();
        let mut authority_scopes = BTreeMap::new();
        let mut sources = BTreeMap::new();
        let mut mutating = 0;
        let mut blocked = 0;
        let mut entitlement_metadata = 0;
        let mut plan_gated = 0;
        let mut cost_references = 0;
        let mut verification_contracts = 0;
        let mut rollback_contracts = 0;
        let mut complete_mutation_contracts = 0;
        let mut capabilities_with_mutation_contract_gaps = 0;
        let mut blocked_adapters_without_contract_gaps = 0;
        let mut mutation_contract_gap_counts = BTreeMap::new();
        for capability in self.capabilities.values() {
            *authority_scopes
                .entry(authority_scope_name(capability.authority_scope).to_owned())
                .or_insert(0) += 1;
            *adapter_statuses
                .entry(adapter_status_name(capability.adapter_status).to_owned())
                .or_insert(0) += 1;
            let source = if capability.source.starts_with("wrangler ") {
                "wrangler"
            } else if capability.source.starts_with("cloudflared ") {
                "cloudflared"
            } else if capability.adapter_status == AdapterStatus::GovernedUi {
                "governed_ui"
            } else {
                "cloudflare_openapi"
            };
            *sources.entry(source.to_owned()).or_insert(0) += 1;
            mutating += usize::from(capability.mutating);
            blocked += usize::from(capability.adapter_status == AdapterStatus::Blocked);
            entitlement_metadata += usize::from(!capability.entitlement.plans.is_empty());
            plan_gated += usize::from(
                capability
                    .entitlement
                    .plans
                    .values()
                    .any(|available| !available),
            );
            cost_references += usize::from(!capability.cost.references.is_empty());
            verification_contracts +=
                usize::from(capability.mutating && capability.verification_contract_declared());
            rollback_contracts +=
                usize::from(capability.mutating && capability.rollback_contract_declared());
            let contract_gaps = capability.mutation_contract_gaps();
            capabilities_with_mutation_contract_gaps +=
                usize::from(capability.mutating && !contract_gaps.is_empty());
            blocked_adapters_without_contract_gaps += usize::from(
                capability.adapter_status == AdapterStatus::Blocked && contract_gaps.is_empty(),
            );
            for gap in &contract_gaps {
                *mutation_contract_gap_counts
                    .entry(mutation_contract_gap_code(gap).to_owned())
                    .or_insert(0) += 1;
            }
            complete_mutation_contracts += usize::from(
                capability.mutating
                    && capability.adapter_status != AdapterStatus::Blocked
                    && contract_gaps.is_empty(),
            );
        }
        let telemetry_ledger = telemetry_coverage_ledger(self);
        let telemetry_targeted = TelemetryCoverageSummaryV1::from_entries(&telemetry_ledger);
        CatalogCoverageV1 {
            schema_hash: self.schema_hash.clone(),
            total: self.capabilities.len(),
            reads: self.capabilities.len().saturating_sub(mutating),
            mutating,
            blocked,
            entitlement_metadata,
            plan_gated,
            cost_references,
            verification_contracts,
            rollback_contracts,
            complete_mutation_contracts,
            capabilities_with_mutation_contract_gaps,
            blocked_adapters_without_contract_gaps,
            mutation_contract_gap_counts,
            adapter_statuses,
            authority_scopes,
            sources,
            telemetry_targeted,
            telemetry_ledger,
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate_hash()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| catalog_io(parent, source))?;
        }
        let encoded = serde_json::to_vec_pretty(self)?;
        fs::write(path, encoded).map_err(|source| catalog_io(path, source))
    }

    pub fn load(path: &Path) -> Result<Self> {
        let encoded = fs::read(path).map_err(|source| catalog_io(path, source))?;
        let snapshot: Self = serde_json::from_slice(&encoded)?;
        snapshot.validate_hash()?;
        Ok(snapshot)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CatalogCoverageV1 {
    pub schema_hash: String,
    pub total: usize,
    pub reads: usize,
    pub mutating: usize,
    pub blocked: usize,
    pub entitlement_metadata: usize,
    pub plan_gated: usize,
    pub cost_references: usize,
    pub verification_contracts: usize,
    pub rollback_contracts: usize,
    pub complete_mutation_contracts: usize,
    pub capabilities_with_mutation_contract_gaps: usize,
    pub blocked_adapters_without_contract_gaps: usize,
    pub mutation_contract_gap_counts: BTreeMap<String, usize>,
    pub adapter_statuses: BTreeMap<String, usize>,
    pub authority_scopes: BTreeMap<String, usize>,
    pub sources: BTreeMap<String, usize>,
    pub telemetry_targeted: TelemetryCoverageSummaryV1,
    pub telemetry_ledger: Vec<TelemetryCoverageEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryCoverageSummaryV1 {
    pub total: usize,
    pub executable: usize,
    pub blocked: usize,
    pub reads: usize,
    pub mutations: usize,
    pub complete_mutations: usize,
    pub upstream_absent: usize,
}

impl TelemetryCoverageSummaryV1 {
    fn from_entries(entries: &[TelemetryCoverageEntryV1]) -> Self {
        Self {
            total: entries.len(),
            executable: entries
                .iter()
                .filter(|entry| entry.adapter_status != AdapterStatus::Blocked)
                .count(),
            blocked: entries
                .iter()
                .filter(|entry| entry.adapter_status == AdapterStatus::Blocked)
                .count(),
            reads: entries
                .iter()
                .filter(|entry| entry.operation_kind == "read")
                .count(),
            mutations: entries
                .iter()
                .filter(|entry| entry.operation_kind == "mutation")
                .count(),
            complete_mutations: entries
                .iter()
                .filter(|entry| {
                    entry.operation_kind == "mutation"
                        && entry.contract_state == "plan_apply_verify_contract_complete"
                })
                .count(),
            upstream_absent: entries
                .iter()
                .filter(|entry| entry.capability_id.is_none())
                .count(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TelemetryCoverageEntryV1 {
    pub domain: String,
    pub product: String,
    pub api_operation_or_dataset: String,
    pub capability_id: Option<String>,
    pub operation_kind: String,
    pub adapter_status: AdapterStatus,
    pub contract_state: String,
    pub permission_owner: String,
    pub permission_mode: String,
    pub required_permissions: Vec<String>,
    pub entitlement: EntitlementV1,
    pub cost: CostV1,
    pub verification_method: String,
    pub rollback_method: Option<String>,
    pub fixture_coverage: String,
    pub live_read_proof_status: String,
    pub live_mutation_drill_status: String,
    pub remaining_blocker: Option<String>,
}

#[derive(Clone, Copy)]
struct TelemetryCoverageSpec {
    domain: &'static str,
    product: &'static str,
    authority: &'static str,
    capability_id: Option<&'static str>,
    operation_kind: &'static str,
    fixture_coverage: &'static str,
    upstream_blocker: Option<&'static str>,
}

fn telemetry_coverage_ledger(snapshot: &CatalogSnapshot) -> Vec<TelemetryCoverageEntryV1> {
    telemetry_coverage_specs()
        .iter()
        .map(|spec| telemetry_coverage_entry(snapshot, *spec))
        .collect()
}

#[expect(
    clippy::too_many_lines,
    reason = "the coverage row is a single auditable projection of one capability contract"
)]
fn telemetry_coverage_entry(
    snapshot: &CatalogSnapshot,
    spec: TelemetryCoverageSpec,
) -> TelemetryCoverageEntryV1 {
    let capability = spec
        .capability_id
        .and_then(|capability_id| snapshot.get(capability_id));
    let adapter_status = capability.map_or(AdapterStatus::Blocked, |capability| {
        capability.adapter_status
    });
    let contract_state = match capability {
        None if spec.capability_id.is_none() => "upstream_api_absent",
        None => "capability_missing_from_current_catalog",
        Some(capability) if capability.adapter_status == AdapterStatus::Blocked => {
            "blocked_with_typed_diagnostic"
        }
        Some(capability)
            if capability.mutating && capability.mutation_contract_gaps().is_empty() =>
        {
            "plan_apply_verify_contract_complete"
        }
        Some(capability)
            if capability.analytics_query.is_some() || capability.r2_log_retrieval.is_some() =>
        {
            "bounded_query_contract_complete"
        }
        Some(capability) if capability.workflow.is_some() => "governed_composition_recipe",
        Some(_) => "typed_read_contract_complete",
    }
    .to_owned();
    let permission_owner = capability.map_or_else(
        || "not_applicable".to_owned(),
        |capability| {
            if capability.path.starts_with("/user") || capability.account_scope == "user" {
                "user_owned".to_owned()
            } else {
                "account_owned".to_owned()
            }
        },
    );
    let required_permissions = capability
        .map(|capability| capability.permissions.clone())
        .unwrap_or_default();
    let has_read = required_permissions
        .iter()
        .any(|permission| permission.ends_with(" Read"));
    let has_write = required_permissions
        .iter()
        .any(|permission| permission.ends_with(" Write") || permission.ends_with(" Edit"));
    let permission_mode = if required_permissions.is_empty() {
        "not_declared_upstream"
    } else if has_read && has_write {
        "all_of_for_governed_lifecycle"
    } else if required_permissions.len() > 1 {
        "any_of_upstream"
    } else {
        "all_of"
    }
    .to_owned();
    let entitlement = capability.map_or_else(
        || EntitlementV1 {
            available: None,
            plans: BTreeMap::new(),
            blocker: spec.upstream_blocker.map(str::to_owned),
            source: None,
            requires_live_resolution: false,
            observed_plan: None,
            probe: None,
        },
        |capability| capability.entitlement.clone(),
    );
    let cost = capability.map_or_else(
        || CostV1 {
            incremental: false,
            currency: None,
            maximum: None,
            basis: Some("no public operation exists from which to derive cost".to_owned()),
            known: false,
            billing_model: BillingModelV1::Unknown,
            exposure: CostExposureV1::None,
            references: Vec::new(),
        },
        |capability| capability.cost.clone(),
    );
    let verification_method = capability.map_or_else(
        || "unavailable".to_owned(),
        |capability| {
            if capability.mutating {
                capability.verification.strategy.clone()
            } else if capability.analytics_query.is_some() {
                "bounded_result_envelope_and_content_addressed_read_receipt".to_owned()
            } else if capability.r2_log_retrieval.is_some() {
                "bounded_private_file_hash_receipt".to_owned()
            } else {
                "content_addressed_live_read_receipt".to_owned()
            }
        },
    );
    let rollback_method = capability.and_then(|capability| {
        capability
            .rollback
            .strategy
            .clone()
            .or_else(|| capability.rollback.warning.clone())
    });
    let remaining_blocker = capability
        .and_then(|capability| capability.blocked_reason.clone())
        .or_else(|| spec.upstream_blocker.map(str::to_owned))
        .or_else(|| {
            (capability.is_none() && spec.capability_id.is_some()).then(|| {
                "operation is absent from the current generated Cloudflare catalog".to_owned()
            })
        });
    TelemetryCoverageEntryV1 {
        domain: spec.domain.to_owned(),
        product: spec.product.to_owned(),
        api_operation_or_dataset: spec.authority.to_owned(),
        capability_id: spec.capability_id.map(str::to_owned),
        operation_kind: spec.operation_kind.to_owned(),
        adapter_status,
        contract_state,
        permission_owner,
        permission_mode,
        required_permissions,
        entitlement,
        cost,
        verification_method,
        rollback_method,
        fixture_coverage: spec.fixture_coverage.to_owned(),
        live_read_proof_status: if spec.operation_kind == "read" {
            "not_recorded_in_catalog_snapshot; inspect evidence receipts".to_owned()
        } else {
            "not_applicable".to_owned()
        },
        live_mutation_drill_status: if spec.operation_kind == "mutation" {
            "not_authorized".to_owned()
        } else {
            "not_applicable".to_owned()
        },
        remaining_blocker,
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the explicit telemetry coverage matrix is intentionally reviewable as one ordered ledger"
)]
fn telemetry_coverage_specs() -> Vec<TelemetryCoverageSpec> {
    vec![
        telemetry_spec(
            "analytics",
            "Web Analytics",
            "GET account RUM sites",
            Some("web-analytics-list-sites"),
            "read",
            "openapi_contract",
            None,
        ),
        telemetry_spec(
            "analytics",
            "Web Analytics",
            "POST account RUM site",
            Some("web-analytics-create-site"),
            "mutation",
            "mutation_contract_fixture",
            None,
        ),
        telemetry_spec(
            "analytics",
            "Web Analytics",
            "PUT account RUM site",
            Some("web-analytics-update-site"),
            "mutation",
            "mutation_contract_fixture",
            None,
        ),
        telemetry_spec(
            "analytics",
            "Browser Insights and RUM",
            "GET zone RUM status",
            Some("web-analytics-get-rum-status"),
            "read",
            "openapi_contract",
            None,
        ),
        telemetry_spec(
            "analytics",
            "Browser Insights and RUM",
            "PATCH zone RUM status",
            Some("web-analytics-toggle-rum"),
            "mutation",
            "mutation_contract_fixture",
            None,
        ),
        telemetry_spec(
            "analytics",
            "Web Analytics rules",
            "POST RUM ruleset rule",
            Some("web-analytics-create-rule"),
            "mutation",
            "openapi_contract",
            None,
        ),
        telemetry_spec(
            "analytics",
            "GraphQL HTTP analytics",
            "httpRequestsAdaptiveGroups zone",
            Some("graphql-analytics-zone-http-requests"),
            "read",
            "graphql_contract_and_response_fixture",
            None,
        ),
        telemetry_spec(
            "analytics",
            "GraphQL HTTP analytics",
            "httpRequests1dGroups zone-wide daily unique IPs",
            Some("graphql-analytics-zone-http-unique-ips-daily"),
            "read",
            "graphql_contract_and_response_fixture",
            None,
        ),
        telemetry_spec(
            "analytics",
            "Web Analytics and RUM",
            "rumPageloadEventsAdaptiveGroups hostname visits",
            Some("graphql-analytics-account-rum-pageload-visits"),
            "read",
            "graphql_contract_and_response_fixture",
            None,
        ),
        telemetry_spec(
            "analytics",
            "Web Analytics and RUM",
            "account RUM dataset settings",
            Some("graphql-analytics-account-rum-dataset-settings"),
            "read",
            "graphql_contract_and_response_fixture",
            None,
        ),
        telemetry_spec(
            "analytics",
            "GraphQL HTTP analytics",
            "httpRequestsAdaptiveGroups selected account zones",
            Some("graphql-analytics-account-http-requests"),
            "read",
            "graphql_contract_and_response_fixture",
            None,
        ),
        telemetry_spec(
            "analytics",
            "Analytics Engine",
            "GET bounded Analytics Engine SQL",
            Some("analytics-engine-sql-query-get"),
            "read",
            "json_ndjson_csv_streaming_fixtures",
            None,
        ),
        telemetry_spec(
            "analytics",
            "Workers Analytics",
            "POST Workers observability telemetry query",
            Some("telemetry.query"),
            "read",
            "bounded_query_contract_fixture",
            None,
        ),
        telemetry_spec(
            "analytics",
            "DNS analytics",
            "GET zone DNS analytics table",
            Some("dns-analytics-table"),
            "read",
            "openapi_contract",
            None,
        ),
        telemetry_spec(
            "analytics",
            "Cache analytics",
            "httpRequestsAdaptiveGroups cache dimensions",
            Some("graphql-analytics-zone-http-requests"),
            "read",
            "graphql_contract_and_response_fixture",
            None,
        ),
        telemetry_spec(
            "analytics",
            "Load Balancing health",
            "GET account pool health",
            Some("account-load-balancer-pools-pool-health-details"),
            "read",
            "openapi_contract",
            None,
        ),
        telemetry_spec(
            "analytics",
            "Rate-limit analytics",
            "GET deprecated zone rate-limit analytics",
            Some("rate-limit-analytics-get-zone-analytics"),
            "read",
            "openapi_contract",
            Some(
                "the legacy rate-limiting analytics API is deprecated in favor of Ruleset Engine telemetry",
            ),
        ),
        telemetry_spec(
            "analytics",
            "Network analytics",
            "GET Spectrum analytics by time",
            Some("spectrum-analytics-(-by-time)-get-analytics-by-time"),
            "read",
            "openapi_contract",
            None,
        ),
        telemetry_spec(
            "analytics",
            "Pages analytics",
            "public Pages analytics API",
            None,
            "read",
            "not_applicable",
            Some(
                "Cloudflare does not expose a public Pages analytics results API in the current schema",
            ),
        ),
        telemetry_spec(
            "logs_observability",
            "Log Explorer",
            "POST account Log Explorer typed SQL",
            Some("accounts-logs-explorer-query-post"),
            "read",
            "typed_sql_and_envelope_fixture",
            None,
        ),
        telemetry_spec(
            "logs_observability",
            "Log Explorer",
            "POST zone Log Explorer typed SQL",
            Some("zones-logs-explorer-query-post"),
            "read",
            "typed_sql_and_envelope_fixture",
            None,
        ),
        telemetry_spec(
            "logs_observability",
            "Workers logs and traces",
            "POST Workers observability telemetry query",
            Some("telemetry.query"),
            "read",
            "bounded_query_contract_fixture",
            None,
        ),
        telemetry_spec(
            "logs_observability",
            "Workers observability settings",
            "PATCH Worker script settings",
            Some("workers-observability-settings-update"),
            "mutation",
            "mutation_contract_fixture",
            None,
        ),
        telemetry_spec(
            "logs_observability",
            "Worker tail sessions",
            "POST leased Worker tail with sink-only URL",
            Some("worker-tail-logs-start-tail"),
            "mutation",
            "secret_sink_and_exact_delete_lifecycle_fixture",
            None,
        ),
        telemetry_spec(
            "logs_observability",
            "Logpush",
            "GET account Logpush jobs",
            Some("get-accounts-account_id-logpush-jobs"),
            "read",
            "openapi_contract",
            None,
        ),
        telemetry_spec(
            "logs_observability",
            "Logpush",
            "POST account Logpush job",
            Some("post-accounts-account_id-logpush-jobs"),
            "mutation",
            "mutation_contract_fixture",
            None,
        ),
        telemetry_spec(
            "logs_observability",
            "Logpush",
            "PATCH-safe account Logpush job",
            Some("logpush-account-job-settings-update"),
            "mutation",
            "mutation_contract_fixture",
            None,
        ),
        telemetry_spec(
            "logs_observability",
            "Logpush R2 destinations",
            "POST zone Logpush job with validated destination",
            Some("post-zones-zone_id-logpush-jobs"),
            "mutation",
            "mutation_contract_fixture",
            None,
        ),
        telemetry_spec(
            "logs_observability",
            "Logpull",
            "GET bounded R2 log retrieval with out-of-band credentials",
            Some("logpull-retrieve-logs"),
            "read",
            "credential_header_injection_and_private_stream_fixture",
            None,
        ),
        telemetry_spec(
            "logs_observability",
            "Audit logs",
            "GET account audit logs v2",
            Some("audit-logs-v2-get-account-audit-logs"),
            "read",
            "openapi_contract",
            None,
        ),
        telemetry_spec(
            "logs_observability",
            "Access and Zero Trust logs",
            "Log Explorer access_requests dataset",
            Some("accounts-logs-explorer-query-post"),
            "read",
            "typed_sql_and_envelope_fixture",
            None,
        ),
        telemetry_spec(
            "security_response",
            "Security Events",
            "firewallEventsAdaptive",
            Some("graphql-analytics-zone-firewall-events"),
            "read",
            "graphql_bounded_sample_and_response_fixture",
            None,
        ),
        telemetry_spec(
            "security_response",
            "WAF and custom rulesets",
            "POST empty custom zone ruleset",
            Some("security-response-create-empty-custom-ruleset"),
            "mutation",
            "narrowed_create_read_delete_lifecycle_fixture",
            None,
        ),
        telemetry_spec(
            "security_response",
            "WAF individual rules",
            "POST evidence-bound expiring zone ruleset rule",
            Some("security-response-create-expiring-waf-rule"),
            "mutation",
            "security_action_nested_resource_fixture",
            None,
        ),
        telemetry_spec(
            "security_response",
            "WAF individual rules",
            "DELETE verified expired zone ruleset rule",
            Some("security-response-remove-expired-waf-rule"),
            "mutation",
            "security_action_nested_resource_fixture",
            None,
        ),
        telemetry_spec(
            "security_response",
            "Managed rules",
            "GET zone entrypoint ruleset",
            Some("getZoneEntrypointRuleset"),
            "read",
            "openapi_contract",
            None,
        ),
        telemetry_spec(
            "security_response",
            "Legacy rate limits",
            "POST zone rate limit",
            Some("rate-limits-for-a-zone-create-a-rate-limit"),
            "mutation",
            "mutation_contract_fixture",
            Some("Cloudflare deprecates this API in favor of Ruleset Engine rate limiting"),
        ),
        telemetry_spec(
            "security_response",
            "Cloudflare Lists",
            "POST account list",
            Some("lists-create-a-list"),
            "mutation",
            "openapi_contract",
            None,
        ),
        telemetry_spec(
            "security_response",
            "Cloudflare List members",
            "POST one evidence-bound asynchronous expiring list item",
            Some("security-response-add-expiring-list-member"),
            "mutation",
            "async_operation_correlation_cursor_and_security_action_fixture",
            None,
        ),
        telemetry_spec(
            "security_response",
            "Cloudflare List members",
            "DELETE one correlated expired list item",
            Some("security-response-remove-expired-list-member"),
            "mutation",
            "async_operation_absence_cursor_and_expiry_fixture",
            None,
        ),
        telemetry_spec(
            "security_response",
            "Expiring IP enforcement",
            "POST evidence-bound zone IP Access rule",
            Some("security-response-create-expiring-ip-access-rule"),
            "mutation",
            "security_action_contract_and_runtime_fixture",
            None,
        ),
        telemetry_spec(
            "security_response",
            "Expiring IP enforcement",
            "DELETE verified expired zone IP Access rule",
            Some("security-response-remove-expired-ip-access-rule"),
            "mutation",
            "security_action_contract_and_runtime_fixture",
            None,
        ),
        telemetry_spec(
            "security_response",
            "Bot Management",
            "GET zone bot configuration",
            Some("bot-management-for-a-zone-get-config"),
            "read",
            "openapi_contract",
            None,
        ),
        telemetry_spec(
            "security_response",
            "DDoS visibility",
            "firewallEventsAdaptive DDoS sources",
            Some("graphql-analytics-zone-firewall-events"),
            "read",
            "graphql_bounded_sample_and_response_fixture",
            None,
        ),
        telemetry_spec(
            "security_response",
            "Availability and security alerts",
            "POST notification policy",
            Some("notification-policies-create-a-notification-policy"),
            "mutation",
            "openapi_contract",
            None,
        ),
        telemetry_spec(
            "data_governance",
            "Dataset retention and limits",
            "GraphQL zone dataset settings",
            Some("graphql-analytics-zone-dataset-settings"),
            "read",
            "graphql_contract_and_response_fixture",
            None,
        ),
        telemetry_spec(
            "data_governance",
            "Logpush fields and filters",
            "GET zone Logpush dataset fields",
            Some("get-zones-zone_id-logpush-datasets-dataset_id-fields"),
            "read",
            "openapi_contract",
            None,
        ),
        telemetry_spec(
            "data_governance",
            "Log Explorer dataset schema",
            "GET account available datasets",
            Some("accounts-logs-explorer-datasets-available-list"),
            "read",
            "openapi_contract",
            None,
        ),
        telemetry_spec(
            "data_governance",
            "Dataset localization",
            "public telemetry dataset localization control",
            None,
            "read",
            "not_applicable",
            Some(
                "no universal public localization API exists; product-specific controls must remain explicit",
            ),
        ),
    ]
}

const fn telemetry_spec(
    domain: &'static str,
    product: &'static str,
    authority: &'static str,
    capability_id: Option<&'static str>,
    operation_kind: &'static str,
    fixture_coverage: &'static str,
    upstream_blocker: Option<&'static str>,
) -> TelemetryCoverageSpec {
    TelemetryCoverageSpec {
        domain,
        product,
        authority,
        capability_id,
        operation_kind,
        fixture_coverage,
        upstream_blocker,
    }
}

pub struct CatalogIndex {
    connection: Connection,
}

impl CatalogIndex {
    pub fn rebuild(path: &Path, snapshot: &CatalogSnapshot) -> Result<Self> {
        snapshot.validate_hash()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| catalog_io(parent, source))?;
        }
        let mut connection = Connection::open(path)?;
        let transaction = connection.transaction()?;
        transaction.execute_batch(
            "DROP TABLE IF EXISTS capabilities;
             DROP TABLE IF EXISTS metadata;
             CREATE TABLE capabilities (
               id TEXT PRIMARY KEY NOT NULL,
               title TEXT NOT NULL,
               product TEXT NOT NULL,
               description TEXT NOT NULL,
               document TEXT NOT NULL
             );
             CREATE TABLE metadata (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL);",
        )?;
        {
            let mut insert = transaction.prepare(
                "INSERT INTO capabilities (id, title, product, description, document)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
            )?;
            for capability in snapshot.capabilities.values() {
                insert.execute(params![
                    capability.id,
                    capability.title,
                    capability.product,
                    capability.description.as_deref().unwrap_or_default(),
                    serde_json::to_string(capability)?,
                ])?;
            }
        }
        transaction.execute(
            "INSERT INTO metadata (key, value) VALUES ('schema_hash', ?1)",
            [&snapshot.schema_hash],
        )?;
        transaction.commit()?;
        Ok(Self { connection })
    }

    pub fn open(path: &Path) -> Result<Self> {
        Ok(Self {
            connection: Connection::open(path)?,
        })
    }

    pub fn search(&self, query: &str, limit: usize) -> Result<Vec<CapabilityV1>> {
        let terms = intent_terms(query);
        let mut statement = self
            .connection
            .prepare("SELECT document FROM capabilities ORDER BY id")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut ranked = Vec::new();
        for row in rows {
            let document = row?;
            let capability: CapabilityV1 = serde_json::from_str(&document)?;
            let score = intent_score(&capability, &terms);
            if score > 0 {
                ranked.push((capability, score));
            }
        }
        ranked.sort_by(|(left, left_score), (right, right_score)| {
            right_score
                .cmp(left_score)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(ranked
            .into_iter()
            .take(limit)
            .map(|(capability, _score)| capability)
            .collect())
    }

    pub fn schema_hash(&self) -> Result<String> {
        Ok(self.connection.query_row(
            "SELECT value FROM metadata WHERE key = 'schema_hash'",
            [],
            |row| row.get(0),
        )?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfficialTextFeedsV1 {
    pub fetched_at: DateTime<Utc>,
    pub docs_index_url: String,
    pub docs_index: String,
    #[serde(default)]
    pub product_indexes: BTreeMap<String, String>,
    #[serde(default)]
    pub unread_product_indexes: BTreeMap<String, String>,
    pub changelog_url: String,
    pub changelog: String,
}

/// Attaches cost and entitlement knowledge from the official Cloudflare
/// product indexes without converting variable downstream pricing into a
/// fictitious executable cost ceiling.
pub fn attach_official_product_knowledge(
    snapshot: &mut CatalogSnapshot,
    feeds: &OfficialTextFeedsV1,
) -> Result<()> {
    let pricing = official_pricing_references(feeds);
    for capability in snapshot.capabilities.values_mut() {
        if !capability.entitlement.plans.is_empty() {
            capability
                .entitlement
                .source
                .get_or_insert_with(|| "official OpenAPI x-cfPlanAvailability".to_owned());
            let plan_gated = capability
                .entitlement
                .plans
                .values()
                .any(|available| !available);
            capability.entitlement.requires_live_resolution =
                capability.entitlement.probe.is_some()
                    || (plan_gated && supports_live_zone_entitlement_resolution(capability));
            capability.entitlement.blocker =
                if plan_gated && !capability.entitlement.requires_live_resolution {
                    Some(unsupported_entitlement_resolution_reason(capability))
                } else {
                    None
                };
        }

        let mut matches: Vec<_> = pricing
            .iter()
            .filter(|entry| pricing_product_matches(capability, entry))
            .collect();
        let most_specific = matches
            .iter()
            .map(|entry| entry.product_terms.len())
            .max()
            .unwrap_or_default();
        matches.retain(|entry| entry.product_terms.len() == most_specific);
        let has_pricing_match = !matches.is_empty();
        for entry in matches {
            if capability
                .cost
                .references
                .iter()
                .any(|reference| reference.url == entry.reference.url)
            {
                continue;
            }
            capability.cost.references.push(entry.reference.clone());
            capability.cost.billing_model =
                merge_billing_model(capability.cost.billing_model, entry.billing_model);
        }
        capability
            .cost
            .references
            .sort_by(|left, right| left.url.cmp(&right.url));
        if has_pricing_match {
            capability.cost.exposure = if capability.cost.billing_model == BillingModelV1::Contract
            {
                CostExposureV1::AccountQuote
            } else {
                CostExposureV1::DownstreamUsage
            };
            if capability.mutating
                && !capability.cost.known
                && cost_basis_is_schema_placeholder(capability.cost.basis.as_deref())
            {
                capability.cost.basis = Some(
                    "official product pricing is linked, but the mutation does not declare a hard ceiling for downstream resource or usage charges"
                        .to_owned(),
                );
            }
        }
        refresh_dynamic_mutation_contract(capability);
    }
    snapshot.refresh_hash()
}

fn cost_basis_is_schema_placeholder(basis: Option<&str>) -> bool {
    matches!(
        basis,
        None | Some(
            "official API schema does not declare operation pricing"
                | "official schema does not declare a hard price ceiling"
        )
    )
}

fn supports_live_zone_entitlement_resolution(capability: &CapabilityV1) -> bool {
    capability.account_scope == "zone"
        && capability.selectors.iter().any(|selector| {
            selector.location == "path" && selector.required && selector.name == "zone_id"
        })
}

fn unsupported_entitlement_resolution_reason(capability: &CapabilityV1) -> String {
    if capability.account_scope == "zone" {
        return "live zone entitlement resolution is unsupported because the operation has no exact required zone_id selector for the zone subscription join"
            .to_owned();
    }
    format!(
        "live {} entitlement resolution is unsupported because the official plan matrix has no product-scoped subscription join key for this operation",
        capability.account_scope
    )
}

#[derive(Debug)]
struct ProductPricingReference {
    product_slug: String,
    product_terms: BTreeSet<String>,
    billing_model: BillingModelV1,
    reference: KnowledgeReferenceV1,
}

fn official_pricing_references(feeds: &OfficialTextFeedsV1) -> Vec<ProductPricingReference> {
    let mut references = Vec::new();
    for (index_url, index) in &feeds.product_indexes {
        let Some(product_slug) = index_url
            .strip_prefix("https://developers.cloudflare.com/")
            .and_then(|path| path.strip_suffix("/llms.txt"))
        else {
            continue;
        };
        let product_terms = product_terms(product_slug);
        if product_terms.is_empty() {
            continue;
        }
        for line in index.lines().filter(|line| {
            line.to_ascii_lowercase().contains("pricing") && markdown_link(line).is_some()
        }) {
            let Some(url) = markdown_link(line) else {
                continue;
            };
            references.push(ProductPricingReference {
                product_slug: product_slug.to_owned(),
                product_terms: product_terms.clone(),
                billing_model: billing_model_from_pricing_line(line),
                reference: KnowledgeReferenceV1 {
                    title: markdown_title(line).unwrap_or("Pricing").to_owned(),
                    url: url.to_owned(),
                    source: index_url.clone(),
                },
            });
        }
    }
    references
}

fn product_terms(product_slug: &str) -> BTreeSet<String> {
    match product_slug {
        "analytics" => ["analytics", "engine"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        "cloudflare-for-platforms" => ["workers", "platforms"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        _ => normalized_tokens(product_slug)
            .into_iter()
            .filter(|term| !matches!(term.as_str(), "cloudflare" | "for" | "the" | "api"))
            .collect(),
    }
}

fn pricing_product_matches(capability: &CapabilityV1, entry: &ProductPricingReference) -> bool {
    let product = capability.product.to_ascii_lowercase();
    let path_root = first_resource_segment(&capability.path);
    match entry.product_slug.as_str() {
        "ai-search" => return product.starts_with("ai search") || product.starts_with("autorag"),
        "workers-ai" => return product.starts_with("workers ai"),
        "ai-gateway" => return product.starts_with("ai gateway"),
        "cloudflare-for-platforms" => return product.starts_with("workers for platforms"),
        "workers-vpc" => return product == "connectivity services",
        "durable-objects" => return product.starts_with("durable objects"),
        "log-explorer" => return product.starts_with("log explorer"),
        "images" => return product.starts_with("cloudflare images"),
        "kv" => return normalized_tokens(&product).contains("kv"),
        "pipelines" => return product.contains("pipeline"),
        "pages" => {
            return product.starts_with("pages ") || path_root.is_some_and(|root| root == "pages");
        }
        _ => {}
    }

    let mut product_root_tokens = normalized_tokens(&product);
    if let Some(root) = path_root {
        product_root_tokens.extend(normalized_tokens(root));
    }
    if entry.product_terms.len() > 1 {
        return entry
            .product_terms
            .iter()
            .all(|term| product_root_tokens.contains(term));
    }
    let Some(term) = entry.product_terms.first() else {
        return false;
    };
    let product_tokens = normalized_token_sequence(&capability.product);
    product_tokens
        .first()
        .is_some_and(|first| token_stem_matches(first, term))
        || path_root.is_some_and(|root| {
            normalized_token_sequence(root)
                .first()
                .is_some_and(|first| token_stem_matches(first, term))
        })
}

fn normalized_token_sequence(value: &str) -> Vec<String> {
    value
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

fn first_resource_segment(path: &str) -> Option<&str> {
    path.split('/')
        .filter(|segment| !segment.is_empty())
        .find(|segment| {
            !matches!(*segment, "accounts" | "zones" | "user") && !segment.starts_with('{')
        })
}

fn token_stem_matches(left: &str, right: &str) -> bool {
    left == right || left.trim_end_matches('s') == right.trim_end_matches('s')
}

fn normalized_tokens(value: &str) -> BTreeSet<String> {
    value
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

fn markdown_title(line: &str) -> Option<&str> {
    let start = line.find('[')? + 1;
    let remainder = line.get(start..)?;
    remainder.get(..remainder.find(']')?)
}

fn billing_model_from_pricing_line(line: &str) -> BillingModelV1 {
    let line = line.to_ascii_lowercase();
    if line.contains("pass through") || line.contains("pass-through") {
        BillingModelV1::PassThrough
    } else if [
        "usage",
        "request",
        "storage",
        "cpu",
        "operation",
        "token",
        "minute",
        "data",
        "dimension",
        "overage",
        "inference",
        "vCPU",
    ]
    .iter()
    .any(|term| line.contains(&term.to_ascii_lowercase()))
    {
        BillingModelV1::UsageBased
    } else if line.contains("contract") || line.contains("account team") {
        BillingModelV1::Contract
    } else if line.contains("plan") || line.contains("subscription") {
        BillingModelV1::Subscription
    } else {
        BillingModelV1::Unknown
    }
}

fn merge_billing_model(left: BillingModelV1, right: BillingModelV1) -> BillingModelV1 {
    use BillingModelV1::{Contract, Fixed, None, PassThrough, Subscription, Unknown, UsageBased};
    match (left, right) {
        (Contract, _) | (_, Contract) => Contract,
        (PassThrough, _) | (_, PassThrough) => PassThrough,
        (UsageBased, _) | (_, UsageBased) => UsageBased,
        (Subscription, _) | (_, Subscription) => Subscription,
        (Fixed, _) | (_, Fixed) => Fixed,
        (None, None) => None,
        _ => Unknown,
    }
}

pub async fn fetch_official_text_feeds(client: &reqwest::Client) -> Result<OfficialTextFeedsV1> {
    let docs_index = client
        .get(OFFICIAL_DOCS_INDEX_URL)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    let changelog = client
        .get(OFFICIAL_CHANGELOG_URL)
        .header(reqwest::header::ACCEPT, "text/markdown")
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    let product_index_results = stream::iter(markdown_links(&docs_index, "/llms.txt"))
        .map(|url| {
            let client = client.clone();
            async move {
                let result = async {
                    client
                        .get(&url)
                        .send()
                        .await?
                        .error_for_status()?
                        .text()
                        .await
                }
                .await;
                (url, result)
            }
        })
        .buffer_unordered(8)
        .collect::<Vec<_>>()
        .await;
    let mut product_indexes = BTreeMap::new();
    let mut unread_product_indexes = BTreeMap::new();
    for (url, result) in product_index_results {
        match result {
            Ok(text) => {
                product_indexes.insert(url, text);
            }
            Err(error) => {
                unread_product_indexes.insert(url, error.to_string());
            }
        }
    }
    Ok(OfficialTextFeedsV1 {
        fetched_at: Utc::now(),
        docs_index_url: OFFICIAL_DOCS_INDEX_URL.to_owned(),
        docs_index,
        product_indexes,
        unread_product_indexes,
        changelog_url: OFFICIAL_CHANGELOG_URL.to_owned(),
        changelog,
    })
}

#[must_use]
pub fn markdown_link(line: &str) -> Option<&str> {
    let start = line.find("](")? + 2;
    let remainder = line.get(start..)?;
    let end = remainder.find(')')?;
    remainder.get(..end)
}

#[must_use]
pub fn markdown_links(text: &str, suffix: &str) -> BTreeSet<String> {
    text.lines()
        .filter_map(markdown_link)
        .filter(|url| url.ends_with(suffix))
        .map(str::to_owned)
        .collect()
}

pub fn ingest_cli_help(snapshot: &mut CatalogSnapshot, program: &str, version: &str, help: &str) {
    let mut in_commands = false;
    for line in help.lines() {
        let trimmed = line.trim();
        if trimmed == "COMMANDS" || trimmed == "COMMANDS:" {
            in_commands = true;
            continue;
        }
        if in_commands && (trimmed == "GLOBAL FLAGS" || trimmed == "GLOBAL OPTIONS:") {
            break;
        }
        if !in_commands || trimmed.is_empty() || trimmed.ends_with(':') {
            continue;
        }
        let command_text = if program == "wrangler" {
            let Some(command) = trimmed.strip_prefix("wrangler ") else {
                continue;
            };
            command
        } else {
            trimmed
        };
        let command = command_text
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .trim_end_matches(',');
        if command.is_empty() || matches!(command, "help" | "h") {
            continue;
        }
        let id = format!("{program}.{command}");
        if snapshot.capabilities.contains_key(&id) {
            continue;
        }
        let is_read = matches!(
            command,
            "docs" | "whoami" | "deployments" | "tail" | "version" | "types" | "complete"
        );
        let mut capability = CapabilityV1::new(
            &id,
            command_text,
            if is_read { "GET" } else { "POST" },
            &format!("{program} {command}"),
        );
        capability.source = format!("{program} {version} help");
        "CLI".clone_into(&mut capability.method);
        capability.product = if program == "wrangler" {
            "Wrangler".to_owned()
        } else {
            "cloudflared".to_owned()
        };
        capability.adapter_status = AdapterStatus::DelegatedCli;
        if command == "delete" {
            capability.risk = RiskClass::Destructive;
            capability.effect = EffectClass::Destructive;
        } else if !is_read {
            capability.risk = RiskClass::Unknown;
            capability.effect = EffectClass::Unknown;
        }
        classify_delegated_cli_capability(&mut capability);
        snapshot.capabilities.insert(id, capability);
    }
}

/// Add the exact Wrangler Pages upload command only when the installed
/// Wrangler help proves that command and every selector cfctl relies on are
/// present. The top-level Wrangler help exposes only the aggregate `pages`
/// command, which is not specific enough to govern a deployment.
pub fn ingest_wrangler_pages_deploy_help(
    snapshot: &mut CatalogSnapshot,
    version: &str,
    help: &str,
) {
    if ![
        "wrangler pages deploy [directory]",
        "--project-name",
        "--branch",
        "--commit-hash",
        "--commit-message",
    ]
    .iter()
    .all(|marker| help.contains(marker))
    {
        return;
    }

    let mut capability = CapabilityV1::new(
        "wrangler.pages-deploy",
        "Deploy a directory to Cloudflare Pages",
        "POST",
        "wrangler pages deploy",
    );
    capability.source = format!("wrangler {version} pages deploy help");
    "CLI".clone_into(&mut capability.method);
    "Cloudflare Pages".clone_into(&mut capability.product);
    capability.adapter_status = AdapterStatus::DelegatedCli;
    capability.risk = RiskClass::CrossConfig;
    capability.effect = EffectClass::ReversibleWrite;
    capability.cost.known = true;
    capability.cost.incremental = false;
    capability.cost.billing_model = BillingModelV1::UsageBased;
    capability.cost.exposure = CostExposureV1::DownstreamUsage;
    capability.cost.maximum = Some(0.0);
    capability.cost.basis = Some(
        "uploading a Pages deployment has no direct per-deployment charge; the deployed site can create plan-specific Functions and bandwidth usage"
            .to_owned(),
    );
    capability.cost.references = vec![KnowledgeReferenceV1 {
        title: "Cloudflare Pages Functions pricing".to_owned(),
        url: "https://developers.cloudflare.com/pages/functions/pricing/".to_owned(),
        source: "official Cloudflare docs".to_owned(),
    }];
    capability.verification.required = true;
    "wrangler_pages_new_deployment_succeeds_by_returned_id"
        .clone_into(&mut capability.verification.strategy);
    capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: PAGES_DEPLOYMENT_DETAIL_PATH.to_owned(),
        identity_selector: "deployment_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        read_capability_id: PAGES_DEPLOYMENT_READ_CAPABILITY_ID.to_owned(),
        delete_capability_id: PAGES_DEPLOYMENT_DELETE_CAPABILITY_ID.to_owned(),
        verified_response_fields: vec!["environment".to_owned(), "project_name".to_owned()],
    });
    capability.rollback.supported = false;
    capability.rollback.warning = Some(
        "automatic rollback is not implemented; restoration requires a separate reviewed Pages deployment plan for a known prior artifact and commit, does not erase the failed deployment or Functions side effects, and cannot refund usage"
            .to_owned(),
    );
    capability.selectors = [
        (
            "argument",
            true,
            "Absolute or workspace-relative directory containing the built Pages artifact",
        ),
        (
            "project_name",
            true,
            "Existing Cloudflare Pages project name",
        ),
        (
            "branch",
            true,
            "Production branch recorded on the deployment",
        ),
        (
            "commit_hash",
            true,
            "Exact source commit recorded on and verified against the deployment",
        ),
        (
            "commit_message",
            false,
            "Optional source commit message recorded on the deployment",
        ),
    ]
    .into_iter()
    .map(|(name, required, description)| SelectorV1 {
        name: name.to_owned(),
        location: "query".to_owned(),
        required,
        value_type: "string".to_owned(),
        description: Some(description.to_owned()),
        contract: None,
    })
    .collect();
    snapshot
        .capabilities
        .insert(capability.id.clone(), capability);
}

/// Add the two exact Worker Versions mutation commands only when the installed
/// Wrangler help proves the command shapes and every control cfctl relies on.
/// Keeping upload and traffic promotion separate lets operators review the
/// inert artifact before granting a second authority to serve it.
pub fn ingest_wrangler_worker_versions_help(
    snapshot: &mut CatalogSnapshot,
    version: &str,
    upload_help: &str,
    deploy_help: &str,
) {
    ingest_wrangler_versions_upload_help(snapshot, version, upload_help);
    ingest_wrangler_versions_deploy_help(snapshot, version, deploy_help);
}

fn ingest_wrangler_versions_upload_help(
    snapshot: &mut CatalogSnapshot,
    version: &str,
    upload_help: &str,
) {
    if [
        "wrangler versions upload [path]",
        "--config",
        "--message",
        "--name",
    ]
    .iter()
    .all(|marker| upload_help.contains(marker))
    {
        let mut capability = CapabilityV1::new(
            "wrangler.versions-upload",
            "Upload an inert Cloudflare Worker version",
            "POST",
            "wrangler versions upload",
        );
        capability.source = format!("wrangler {version} versions upload help");
        "CLI".clone_into(&mut capability.method);
        "Cloudflare Workers".clone_into(&mut capability.product);
        classify_wrangler_worker_versions_capability(&mut capability);
        "wrangler_worker_version_reports_expected_message"
            .clone_into(&mut capability.verification.strategy);
        capability.rollback.warning = Some(
            "the uploaded version is inert until separately promoted; automatic deletion of an uploaded version is not implemented"
                .to_owned(),
        );
        capability.selectors = [
            (
                "config",
                true,
                "Absolute path to the reviewed Wrangler configuration",
            ),
            (
                "message",
                true,
                "Reviewed source identity recorded on and verified against the uploaded version",
            ),
            (
                "argument",
                false,
                "Optional Worker entry path resolved from the reviewed config directory",
            ),
            (
                "name",
                true,
                "Exact Worker name; must match the reviewed config",
            ),
        ]
        .into_iter()
        .map(|(name, required, description)| SelectorV1 {
            name: name.to_owned(),
            location: "query".to_owned(),
            required,
            value_type: "string".to_owned(),
            description: Some(description.to_owned()),
            contract: None,
        })
        .collect();
        snapshot
            .capabilities
            .insert(capability.id.clone(), capability);
    }
}

fn ingest_wrangler_versions_deploy_help(
    snapshot: &mut CatalogSnapshot,
    version: &str,
    deploy_help: &str,
) {
    if [
        "wrangler versions deploy [version-specs..]",
        "--config",
        "--message",
        "--yes",
    ]
    .iter()
    .all(|marker| deploy_help.contains(marker))
    {
        let mut capability = CapabilityV1::new(
            "wrangler.versions-deploy",
            "Promote one Cloudflare Worker version to all production traffic",
            "POST",
            "wrangler versions deploy --yes",
        );
        capability.source = format!("wrangler {version} versions deploy help");
        "CLI".clone_into(&mut capability.method);
        "Cloudflare Workers".clone_into(&mut capability.product);
        classify_wrangler_worker_versions_capability(&mut capability);
        "wrangler_worker_versions_deployment_reports_expected_traffic"
            .clone_into(&mut capability.verification.strategy);
        capability.rollback.warning = Some(
            "rollback requires a separate reviewed versions-deploy plan that targets a known prior version at 100 percent"
                .to_owned(),
        );
        capability.selectors = [
            (
                "argument",
                true,
                "Exactly one reviewed Worker version in UUID@100 form",
            ),
            (
                "config",
                true,
                "Absolute path to the reviewed Wrangler configuration",
            ),
            (
                "message",
                true,
                "Reviewed deployment reason recorded by Wrangler",
            ),
            ("name", false, "Optional Worker name override"),
        ]
        .into_iter()
        .map(|(name, required, description)| SelectorV1 {
            name: name.to_owned(),
            location: "query".to_owned(),
            required,
            value_type: "string".to_owned(),
            description: Some(description.to_owned()),
            contract: None,
        })
        .collect();
        snapshot
            .capabilities
            .insert(capability.id.clone(), capability);
    }
}

fn classify_wrangler_worker_versions_capability(capability: &mut CapabilityV1) {
    capability.adapter_status = AdapterStatus::DelegatedCli;
    capability.risk = RiskClass::CrossConfig;
    capability.effect = EffectClass::ReversibleWrite;
    capability.cost.known = true;
    capability.cost.incremental = false;
    capability.cost.billing_model = BillingModelV1::UsageBased;
    capability.cost.exposure = CostExposureV1::DownstreamUsage;
    capability.cost.maximum = Some(0.0);
    capability.cost.basis = Some(
        "creating or promoting a Worker version has no direct per-operation charge; a promoted Worker can create plan-specific downstream usage"
            .to_owned(),
    );
    capability.cost.references = vec![KnowledgeReferenceV1 {
        title: "Cloudflare Workers pricing".to_owned(),
        url: "https://developers.cloudflare.com/workers/platform/pricing/".to_owned(),
        source: "official Cloudflare docs".to_owned(),
    }];
    capability.verification.required = true;
    capability.rollback.supported = false;
    capability.permissions = vec![
        "Workers Scripts Write".to_owned(),
        "Workers Scripts Read".to_owned(),
    ];
}

fn classify_delegated_cli_capability(capability: &mut CapabilityV1) {
    match capability.id.as_str() {
        "wrangler.deploy" => classify_wrangler_deploy_capability(capability),
        "cloudflared.tunnel" => classify_cloudflared_quick_tunnel_capability(capability),
        _ => {}
    }
}

fn classify_wrangler_deploy_capability(capability: &mut CapabilityV1) {
    capability.risk = RiskClass::CrossConfig;
    capability.effect = EffectClass::ReversibleWrite;
    capability.cost.known = true;
    capability.cost.incremental = false;
    capability.cost.exposure = CostExposureV1::DownstreamUsage;
    capability.cost.basis = Some(
        "publishing a Worker has no direct per-deploy charge; the deployed Worker can create plan-specific downstream usage"
            .to_owned(),
    );
    capability.cost.references = vec![KnowledgeReferenceV1 {
        title: "Cloudflare Workers pricing".to_owned(),
        url: "https://developers.cloudflare.com/workers/platform/pricing/".to_owned(),
        source: "official Cloudflare docs".to_owned(),
    }];
    capability.verification.required = true;
    "wrangler_deployment_status_reports_promoted_version"
        .clone_into(&mut capability.verification.strategy);
    capability.rollback.supported = false;
    capability.rollback.warning = Some(
        "automatic rollback is not implemented; rollback requires a separate reviewed wrangler rollback plan targeting a known prior version"
            .to_owned(),
    );
    capability.permissions = vec![
        "Workers Scripts Write".to_owned(),
        "Workers Scripts Read".to_owned(),
    ];
    capability.selectors = vec![
        SelectorV1 {
            name: "config".to_owned(),
            location: "query".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: Some("Absolute reviewed Wrangler configuration path".to_owned()),
            contract: None,
        },
        SelectorV1 {
            name: "name".to_owned(),
            location: "query".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: Some(
                "Exact Worker service name; must match the reviewed config".to_owned(),
            ),
            contract: None,
        },
        SelectorV1 {
            name: "message".to_owned(),
            location: "query".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: Some(
                "Exact source and artifact identity generated from the reviewed config".to_owned(),
            ),
            contract: None,
        },
        SelectorV1 {
            name: "var".to_owned(),
            location: "query".to_owned(),
            required: false,
            value_type: "string".to_owned(),
            description: Some("One deploy-time Worker variable in KEY:VALUE form".to_owned()),
            contract: None,
        },
    ];
}

fn classify_cloudflared_quick_tunnel_capability(capability: &mut CapabilityV1) {
    "Start a temporary TryCloudflare Quick Tunnel to a loopback web server"
        .clone_into(&mut capability.title);
    capability.description = Some(
        "Publishes one reviewed loopback HTTP origin at a random trycloudflare.com URL for development and testing only"
            .to_owned(),
    );
    capability.risk = RiskClass::ExternalCommunication;
    capability.effect = EffectClass::ExternalCommunication;
    capability.maturity = Maturity::Experimental;
    capability.entitlement.available = Some(true);
    capability.entitlement.source = Some(
        "Cloudflare documents TryCloudflare Quick Tunnels as free and available without adding a site to Cloudflare DNS"
            .to_owned(),
    );
    capability.cost.known = true;
    capability.cost.incremental = false;
    capability.cost.maximum = Some(0.0);
    capability.cost.exposure = CostExposureV1::None;
    capability.cost.basis =
        Some("Cloudflare documents TryCloudflare Quick Tunnels as free".to_owned());
    capability.cost.references = vec![KnowledgeReferenceV1 {
        title: "Cloudflare Quick Tunnels".to_owned(),
        url: "https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/trycloudflare/".to_owned(),
        source: "official Cloudflare docs".to_owned(),
    }];
    capability.verification.required = true;
    "trycloudflare_https_url_reaches_reviewed_origin"
        .clone_into(&mut capability.verification.strategy);
    capability.rollback.supported = false;
    capability.rollback.warning = Some(
        "stopping the recorded cloudflared process removes the temporary public URL; automatic process termination is not yet implemented and shutdown must be separately confirmed"
            .to_owned(),
    );
    capability.selectors = vec![
        SelectorV1 {
            name: "url".to_owned(),
            location: "query".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: Some(
                "Loopback HTTP origin with an explicit port, for example http://127.0.0.1:3300"
                    .to_owned(),
            ),
            contract: None,
        },
        SelectorV1 {
            name: "health_path".to_owned(),
            location: "query".to_owned(),
            required: false,
            value_type: "string".to_owned(),
            description: Some(
                "Relative public path used for post-start HTTP verification; defaults to /"
                    .to_owned(),
            ),
            contract: None,
        },
    ];
}

pub fn ingest_governed_ui_capabilities(snapshot: &mut CatalogSnapshot) {
    for (id, title, risk, effect, blocker) in [
        (
            "cloudflare-ui.oauth-authorize",
            "Authorize an OAuth application in the Cloudflare consent UI",
            RiskClass::IdentityOrOwnership,
            EffectClass::IdentityOrOwnership,
            None,
        ),
        (
            "cloudflare-ui.oauth-promote-public",
            "Permanently promote a verified OAuth application to public visibility",
            RiskClass::Irreversible,
            EffectClass::Irreversible,
            Some("requires verified publisher-domain ownership and permanent user approval"),
        ),
        (
            "cloudflare-ui.dashboard-session-inspect",
            "Inspect account state that is available only in an authenticated dashboard session",
            RiskClass::Read,
            EffectClass::ReadOnly,
            Some("use only after API and CLI coverage prove insufficient"),
        ),
    ] {
        let mut capability = CapabilityV1::new(
            id,
            title,
            if effect == EffectClass::ReadOnly {
                "GET"
            } else {
                "POST"
            },
            "https://dash.cloudflare.com/",
        );
        "Cloudflare dashboard governed fallback".clone_into(&mut capability.source);
        "Cloudflare Dashboard".clone_into(&mut capability.product);
        "UI".clone_into(&mut capability.method);
        capability.risk = risk;
        capability.effect = effect;
        capability.adapter_status = AdapterStatus::GovernedUi;
        capability.blocked_reason = blocker.map(str::to_owned);
        capability.selectors.push(SelectorV1 {
            name: "account_id".to_owned(),
            location: "target".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: Some("Exact Cloudflare account bound to the UI session".to_owned()),
            contract: None,
        });
        if id.starts_with("cloudflare-ui.oauth-") {
            capability.selectors.push(SelectorV1 {
                name: "client_id".to_owned(),
                location: "target".to_owned(),
                required: true,
                value_type: "string".to_owned(),
                description: Some("Exact OAuth client displayed in the dashboard".to_owned()),
                contract: None,
            });
        }
        snapshot.capabilities.insert(id.to_owned(), capability);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogChangeKind {
    Added,
    Changed,
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogChangeV1 {
    pub id: String,
    pub kind: CatalogChangeKind,
}

pub fn normalize_openapi(document: &Value) -> Result<CatalogSnapshot> {
    let paths = document
        .get("paths")
        .and_then(Value::as_object)
        .ok_or(CatalogError::MissingPaths)?;
    let mut capabilities = BTreeMap::new();

    for (path, path_item) in paths {
        let Some(operations) = path_item.as_object() else {
            continue;
        };
        for method in ["get", "head", "options", "post", "put", "patch", "delete"] {
            let Some(operation) = operations.get(method) else {
                continue;
            };
            let Some(operation_object) = operation.as_object() else {
                continue;
            };
            let id = operation_object
                .get("operationId")
                .and_then(Value::as_str)
                .map_or_else(|| fallback_id(method, path), str::to_owned);
            if capabilities.contains_key(&id) {
                return Err(CatalogError::DuplicateOperation(id));
            }
            let title = operation_object
                .get("summary")
                .and_then(Value::as_str)
                .unwrap_or(&id);
            let mut capability = CapabilityV1::new(&id, title, method, path);
            capability.description = operation_object
                .get("description")
                .and_then(Value::as_str)
                .map(str::to_owned);
            operation_object
                .get("tags")
                .and_then(Value::as_array)
                .and_then(|tags| tags.first())
                .and_then(Value::as_str)
                .unwrap_or("Cloudflare API")
                .clone_into(&mut capability.product);
            capability.selectors = shared_and_operation_parameters(document, path_item, operation)?
                .into_iter()
                .map(|parameter| selector_from_parameter(document, parameter))
                .collect::<Result<Vec<_>>>()?;
            capability.permissions = operation_object
                .get("x-api-token-group")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect();
            capability.request_schema = request_schema_contract(document, operation);
            capability.response_contract =
                success_response_contract(document, operation, capability.mutating)?;
            capability.entitlement.plans = operation_object
                .get("x-cfPlanAvailability")
                .and_then(Value::as_object)
                .map(|availability| {
                    availability
                        .iter()
                        .filter_map(|(plan, enabled)| {
                            enabled.as_bool().map(|value| (plan.clone(), value))
                        })
                        .collect()
                })
                .unwrap_or_default();
            capability.maturity = maturity(operation_object);
            classify(&mut capability);
            block_required_reserved_header_selectors(&mut capability);
            block_incomplete_dynamic_mutation(&mut capability);
            capabilities.insert(id, capability);
        }
    }

    apply_post_normalization_contracts(document, &mut capabilities);

    let source_hash = hash_value(document)?;
    let mut snapshot = CatalogSnapshot {
        schema_version: 2,
        generated_at: Utc::now(),
        source_url: OFFICIAL_OPENAPI_URL.to_owned(),
        source_hash,
        schema_hash: String::new(),
        capabilities,
    };
    snapshot.refresh_hash()?;
    Ok(snapshot)
}

/// Overlays the small set of telemetry contracts that cannot be generated
/// honestly from Cloudflare's REST `OpenAPI` alone. REST operations are only
/// promoted when their current operation identity still matches; GraphQL and
/// native workflows are additive, fixed-document capabilities.
pub fn ingest_telemetry_capabilities(snapshot: &mut CatalogSnapshot) -> Result<()> {
    finalize_event_subscription_lifecycle(snapshot);
    finalize_realtimekit_webhook_lifecycle(snapshot);
    reserve_queue_message_operations_for_event_consumer(snapshot);
    let event_batch = event_batch_capability(snapshot);
    snapshot
        .capabilities
        .insert(event_batch.id.clone(), event_batch);
    block_deprecated_pipeline_update(snapshot);
    finalize_analytics_engine_query(snapshot);
    finalize_log_explorer_queries(snapshot);
    finalize_logpull_retrieval(snapshot);
    finalize_workers_observability_reads(snapshot);
    finalize_telemetry_mutations(snapshot);
    block_misleading_live_tail_heartbeat_identity(snapshot);
    for capability in graphql_analytics_capabilities()? {
        snapshot
            .capabilities
            .insert(capability.id.clone(), capability);
    }
    for capability in telemetry_workflow_capabilities() {
        snapshot
            .capabilities
            .insert(capability.id.clone(), capability);
    }
    snapshot.refresh_hash()
}

/// Adds operation-specific native control-plane capabilities whose wire
/// contracts cannot be represented safely by Cloudflare's raw `OpenAPI`
/// operation. These capabilities compile closed inputs into fixed requests;
/// they never expose the underlying generic provider operation.
pub fn ingest_native_control_capabilities(snapshot: &mut CatalogSnapshot) -> Result<()> {
    for capability in vec![
        mln_0143_data_invariants_capability(),
        mln_0142_post_import_schema_capability(),
        d1_schema_introspection_capability(),
        d1_full_export_capability(),
        d1_restore_exact_bookmark_capability(),
        d1_import_database_capability(),
        d1_reviewed_schema_migration_capability(),
        d1_resume_database_import_poll_capability(),
        d1_import_approved_mln_migration_capability(),
        d1_import_approved_osint_research_migration_capability(),
        d1_resume_approved_mln_import_poll_capability(),
    ]
    .into_boxed_slice()
    {
        snapshot
            .capabilities
            .insert(capability.id.clone(), capability);
    }
    snapshot.refresh_hash()
}

fn d1_import_database_capability() -> CapabilityV1 {
    let hash = serde_json::json!({
        "type":"string","pattern":"^sha256:[0-9a-f]{64}$","minLength":71,"maxLength":71
    });
    let operation = serde_json::json!({
        "type":"string","format":"uuid","minLength":36,"maxLength":36
    });
    let mut capability = CapabilityV1::new(
        "d1-import-database",
        "Import one reviewed Git migration into D1",
        "POST",
        "/accounts/{account_id}/d1/database/{database_id}/import",
    );
    capability.authority_scope = Some(CapabilityAuthorityScopeV1::ProviderGeneric);
    capability.description = Some(
        "Stage one clean tracked SQL file from an exact Git HEAD into a private immutable plan target, then execute Cloudflare's import protocol without accepting caller action, upload URL, filename, ETag, or bookmark controls. Planning requires one exact governed full-export recovery anchor for the same target, profile, credential generation, and catalog. Provider completion verifies the import transaction; schema meaning remains a separate governed D1 introspection receipt."
            .to_owned(),
    );
    "D1".clone_into(&mut capability.product);
    "cfctl native reviewed-Git D1 import adapter".clone_into(&mut capability.source);
    "account".clone_into(&mut capability.account_scope);
    capability.aliases = vec![
        "apply reviewed D1 migration".to_owned(),
        "import tracked SQL into D1".to_owned(),
    ];
    capability.permissions = vec!["D1 Write".to_owned()];
    capability.mutating = true;
    capability.risk = RiskClass::Irreversible;
    capability.effect = EffectClass::DataWrite;
    capability.maturity = Maturity::GenerallyAvailable;
    capability.adapter_status = AdapterStatus::Native;
    capability.blocked_reason = None;
    capability.cost = d1_import_cost();
    capability.entitlement.available = Some(true);
    capability.verification.required = true;
    "d1_import_provider_completion_matches_reviewed_source"
        .clone_into(&mut capability.verification.strategy);
    capability.rollback.supported = true;
    capability.rollback.strategy =
        Some("no_automatic_rollback_use_separately_approved_bookmark_restore".to_owned());
    capability.rollback.warning = Some(
        "Import is irreversible in place. Recovery requires a separately planned exact-bookmark restore to the bound pre-import export after quiescence and impact review."
            .to_owned(),
    );
    capability.selectors = [
        ("account_id", 32_u64, 32_u64),
        ("database_id", 36_u64, 36_u64),
    ]
    .map(|(name, min, max)| SelectorV1 {
        name: name.to_owned(),
        location: "path".to_owned(),
        required: true,
        value_type: "string".to_owned(),
        description: Some(format!("Exact D1 {name} bound into the immutable plan.")),
        contract: Some(SelectorContractV1 {
            schema: serde_json::json!({"type":"string","minLength":min,"maxLength":max}),
            query: None,
        }),
    })
    .to_vec();
    capability.request_schema = Some(serde_json::json!({
        "type":"object","additionalProperties":false,"x-cfctl-body-required":true,
        "required":[
            "pre_recovery_anchor_operation_id",
            "pre_recovery_anchor_evidence_hash",
            "pre_recovery_anchor_output_sha256",
            "pre_recovery_anchor_bookmark_hash"
        ],
        "properties":{
            "pre_recovery_anchor_operation_id":operation,
            "pre_recovery_anchor_evidence_hash":hash,
            "pre_recovery_anchor_output_sha256":hash,
            "pre_recovery_anchor_bookmark_hash":hash
        }
    }));
    capability.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".to_owned()],
        success_media_types: vec!["application/json".to_owned()],
        body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
    });
    capability.d1_approved_mln_import = Some(cfctl_core::D1ApprovedMlnImportContractV1 {
        repository_id: String::new(),
        repository_head: String::new(),
        pre_import_capability_version: 0,
        pre_import_validator_contract_hash: String::new(),
        pre_import_fixed_query_sha256: String::new(),
        account_id: String::new(),
        database_id: String::new(),
        import_path: capability.path.clone(),
        migrations: Vec::new(),
        max_source_bytes: 64 * 1024 * 1024,
        max_response_bytes: 1024 * 1024,
        max_poll_attempts: 120,
        max_timeout_seconds: 30,
        upload_url_suffix: ".r2.cloudflarestorage.com".to_owned(),
        requires_create_new_mode_0600_stage: true,
    });
    capability
}

fn d1_reviewed_schema_migration_capability() -> CapabilityV1 {
    let mut capability = d1_import_database_capability();
    "d1-apply-reviewed-schema-migration".clone_into(&mut capability.id);
    "Apply one reviewed Git schema migration to D1".clone_into(&mut capability.title);
    capability.description = Some(
        "Stage one clean tracked SQL file from an exact Git HEAD, prove a same-target governed full-export recovery anchor, and submit one authenticated D1 query batch. A local SQLite authorizer admits only `PRAGMA foreign_keys`, `CREATE TABLE`, and `CREATE INDEX`; caller SQL and data mutations are rejected. The provider response must report one successful result for every admitted statement, after which schema meaning remains a separate governed introspection receipt."
            .to_owned(),
    );
    "cfctl native reviewed-Git D1 schema migration adapter".clone_into(&mut capability.source);
    "/accounts/{account_id}/d1/database/{database_id}/query".clone_into(&mut capability.path);
    capability.aliases = vec![
        "apply reviewed D1 schema migration".to_owned(),
        "create reviewed D1 tables and indexes".to_owned(),
    ];
    "d1_reviewed_schema_batch_reports_every_statement_success"
        .clone_into(&mut capability.verification.strategy);
    capability.cost.basis = Some(
        "D1 schema execution has no separate operation charge; ordinary D1 rows-written accounting remains"
            .to_owned(),
    );
    if let Some(contract) = capability.d1_approved_mln_import.as_mut() {
        contract.import_path.clone_from(&capability.path);
        contract.max_source_bytes = 1024 * 1024;
        contract.max_poll_attempts = 0;
        contract.upload_url_suffix.clear();
    }
    capability
}

fn d1_import_cost() -> CostV1 {
    CostV1 {
        incremental: false,
        currency: None,
        maximum: Some(0.0),
        basis: Some(
            "D1 import has no separate operation charge; ordinary D1 storage, rows-written, and rows-read accounting remains"
                .to_owned(),
        ),
        known: true,
        billing_model: BillingModelV1::UsageBased,
        exposure: CostExposureV1::DownstreamUsage,
        references: vec![KnowledgeReferenceV1 {
            title: "D1 pricing".to_owned(),
            url: "https://developers.cloudflare.com/d1/platform/pricing/".to_owned(),
            source: "official Cloudflare docs".to_owned(),
        }],
    }
}

fn d1_resume_database_import_poll_capability() -> CapabilityV1 {
    let hash = serde_json::json!({
        "type":"string","pattern":"^sha256:[0-9a-f]{64}$","minLength":71,"maxLength":71
    });
    let operation = serde_json::json!({
        "type":"string","format":"uuid","minLength":36,"maxLength":36
    });
    let mut capability = CapabilityV1::new(
        "d1-resume-database-import-poll",
        "Resume polling one reviewed D1 import",
        "POST",
        "/accounts/{account_id}/d1/database/{database_id}/import",
    );
    capability.authority_scope = Some(CapabilityAuthorityScopeV1::ProviderGeneric);
    capability.description = Some(
        "Create a separately approved poll-only child of one exact durable provider-generic D1 import exhaustion. The runtime derives source, target, profile, credential generation, catalog, accepted bookmark, and provider request from immutable parent authority and never replays init, upload, or ingest."
            .to_owned(),
    );
    "D1".clone_into(&mut capability.product);
    "cfctl native reviewed-Git D1 import poll continuation".clone_into(&mut capability.source);
    "account".clone_into(&mut capability.account_scope);
    capability.aliases = vec!["continue reviewed D1 import polling".to_owned()];
    capability.permissions = vec!["D1 Write".to_owned()];
    capability.mutating = true;
    capability.risk = RiskClass::Irreversible;
    capability.effect = EffectClass::DataWrite;
    capability.maturity = Maturity::GenerallyAvailable;
    capability.adapter_status = AdapterStatus::Native;
    capability.cost = CostV1 {
        incremental: false,
        currency: None,
        maximum: Some(0.0),
        basis: Some("Bounded D1 import polling has no incremental operation charge.".to_owned()),
        known: true,
        billing_model: BillingModelV1::UsageBased,
        exposure: CostExposureV1::DownstreamUsage,
        references: vec![KnowledgeReferenceV1 {
            title: "D1 pricing".to_owned(),
            url: "https://developers.cloudflare.com/d1/platform/pricing/".to_owned(),
            source: "official Cloudflare docs".to_owned(),
        }],
    };
    capability.entitlement.available = Some(true);
    capability.verification.required = true;
    "d1_import_provider_completion_matches_reviewed_source"
        .clone_into(&mut capability.verification.strategy);
    capability.rollback.supported = true;
    capability.rollback.strategy =
        Some("no_automatic_rollback_use_separately_approved_bookmark_restore".to_owned());
    capability.rollback.warning = Some(
        "Polling may observe completion. Recovery remains a separately approved exact-bookmark restore."
            .to_owned(),
    );
    capability.selectors = [
        ("account_id", 32_u64, 32_u64),
        ("database_id", 36_u64, 36_u64),
    ]
    .map(|(name, min, max)| SelectorV1 {
        name: name.to_owned(),
        location: "path".to_owned(),
        required: true,
        value_type: "string".to_owned(),
        description: Some(format!(
            "Target {name} derived from the immutable import root."
        )),
        contract: Some(SelectorContractV1 {
            schema: serde_json::json!({"type":"string","minLength":min,"maxLength":max}),
            query: None,
        }),
    })
    .to_vec();
    capability.request_schema = Some(serde_json::json!({
        "type":"object","additionalProperties":false,"x-cfctl-body-required":true,
        "required":[
            "parent_operation_id","parent_plan_hash","exhaustion_evidence_hash",
            "accepted_ingest_evidence_hash","accepted_bookmark_hash"
        ],
        "properties":{
            "parent_operation_id":operation,
            "parent_plan_hash":hash,
            "exhaustion_evidence_hash":hash,
            "accepted_ingest_evidence_hash":hash,
            "accepted_bookmark_hash":hash
        }
    }));
    capability.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".to_owned()],
        success_media_types: vec!["application/json".to_owned()],
        body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
    });
    capability.d1_approved_mln_import_poll_resume =
        Some(cfctl_core::D1ApprovedMlnImportPollResumeContractV1 {
            root_capability_id: "d1-import-database".to_owned(),
            account_id: String::new(),
            database_id: String::new(),
            import_path: capability.path.clone(),
            max_response_bytes: 1024 * 1024,
            max_poll_attempts: 120,
            max_timeout_seconds: 30,
        });
    capability
}

const MLN_0142_TRIGGER_DEFINITION: &str = r"CREATE TRIGGER document_render_jobs_terminal_generation_guard
BEFORE UPDATE OF state ON document_render_jobs
FOR EACH ROW
WHEN NEW.state IN ('ready', 'failed')
 AND (
   OLD.state <> 'rendering'
   OR OLD.attempts < 1
   OR OLD.claimed_by IS NULL
   OR trim(OLD.claimed_by) = ''
   OR NEW.attempts <> OLD.attempts
   OR NEW.claimed_by IS NOT OLD.claimed_by
 )
BEGIN
  SELECT RAISE(ABORT, 'document_render_terminal_generation_stale');
END";

fn mln_0142_post_import_schema_capability() -> CapabilityV1 {
    const ACCOUNT: &str = "ca30e922fda7f5578e49873542e4aaca";
    const DATABASE: &str = "7c282983-2e48-4ea4-9f0d-09b0d718fe65";
    const SOURCE: &str = "sha256:07e1c5bd77dd529bfe58f0eee80ad29c40fdd0f3e9c9a37163cfaa0683124af0";
    const DEFINITION: &str =
        "sha256:cb32c4ed1b14799465b90693ac73cf03d4650c3db573f080acc3d3b4cc436c2b";
    let mut capability = d1_schema_introspection_capability();
    "mln-0142-post-import-schema".clone_into(&mut capability.id);
    capability.authority_scope = Some(CapabilityAuthorityScopeV1::LegacyEmbedded);
    "Prove MLN 0142 post-import trigger authority".clone_into(&mut capability.title);
    capability.description = Some(
        "Run one exact compiler-owned equality assertion for the reviewed MLNavigator 0142 trigger and bind the result to its durable import boundary."
            .to_owned(),
    );
    capability.aliases = vec!["verify MLN 0142 migration".to_owned()];
    capability.selectors[0].contract = Some(SelectorContractV1 {
        schema: serde_json::json!({"type":"string","enum":[ACCOUNT]}),
        query: None,
    });
    capability.selectors[1].contract = Some(SelectorContractV1 {
        schema: serde_json::json!({"type":"string","enum":[DATABASE]}),
        query: None,
    });
    let hash = serde_json::json!({"type":"string","pattern":"^sha256:[0-9a-f]{64}$"});
    capability.request_schema = Some(serde_json::json!({
        "type":"object",
        "additionalProperties":false,
        "x-cfctl-body-required":true,
        "required":[
            "assertion","import_operation_id","import_boundary_evidence_hash",
            "import_source_sha256","import_plan_hash","final_bookmark_hash",
            "trigger_definition_sha256"
        ],
        "properties":{
            "assertion":{"type":"string","enum":["mln_0142_trigger_definition"]},
            "import_operation_id":{"type":"string","format":"uuid"},
            "import_boundary_evidence_hash":hash,
            "import_source_sha256":{"type":"string","enum":[SOURCE]},
            "import_plan_hash":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},
            "final_bookmark_hash":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},
            "trigger_definition_sha256":{"type":"string","enum":[DEFINITION]}
        }
    }));
    capability.mln_0142_post_import_schema = Some(Mln0142PostImportSchemaContractV1 {
        account_id: ACCOUNT.to_owned(),
        database_id: DATABASE.to_owned(),
        migration_sha256: SOURCE.to_owned(),
        trigger_name: "document_render_jobs_terminal_generation_guard".to_owned(),
        trigger_definition: MLN_0142_TRIGGER_DEFINITION.to_owned(),
        trigger_definition_sha256: DEFINITION.to_owned(),
        capability_version: 1,
    });
    capability
}

#[expect(
    clippy::too_many_lines,
    reason = "the two-entry migration catalogue and immutable receipt prerequisites remain visible in one declaration"
)]
fn d1_import_approved_mln_migration_capability() -> CapabilityV1 {
    let account_id = "ca30e922fda7f5578e49873542e4aaca";
    let database_id = "7c282983-2e48-4ea4-9f0d-09b0d718fe65";
    let hash = serde_json::json!({
        "type":"string","pattern":"^sha256:[0-9a-f]{64}$","minLength":71,"maxLength":71
    });
    let operation = serde_json::json!({
        "type":"string","pattern":"^[0-9a-f]{8}-[0-9a-f-]{27,72}$","minLength":36,"maxLength":80
    });
    let mut capability = CapabilityV1::new(
        "d1-import-approved-mln-migration",
        "Import one approved MLNavigator migration",
        "POST",
        "/accounts/{account_id}/d1/database/{database_id}/import",
    );
    capability.authority_scope = Some(CapabilityAuthorityScopeV1::LegacyEmbedded);
    capability.description = Some(
        "Stage and import exactly MLNavigator migration 0142 or 0143. The reviewed source is one exact clean Git repository revision, relative path, and blob; local origin configuration establishes snapshot identity, not hosted ownership. For 0143, the shared admission and consumption gate requires verified 0142 closure, then the governed recovery export, then exactly one current-authority pre_import proof, all before the immutable plan cutoff. This is evidence chronology, not a claim that out-of-band provider writes were absent. A 0143 post-restore proof must restore the exact post-0142 recovery anchor and re-prove the exact 0142 terminal-generation trigger. A 0142 rollback is a different boundary: it must target the pre-0142 anchor and separately prove that the 0142 trigger is absent; it cannot use the 0143 post-restore contract. The plan binds reviewed source bytes, the phase-specific recovery anchor with its provider bookmark, and proof authority; provider completion remains unverified until the governed post-import proof is attached."
            .to_owned(),
    );
    "D1".clone_into(&mut capability.product);
    "cfctl native closed MLNavigator migration import adapter".clone_into(&mut capability.source);
    "account".clone_into(&mut capability.account_scope);
    capability.aliases = vec![
        "apply MLN migration 0142".to_owned(),
        "apply MLN migration 0143".to_owned(),
    ];
    capability.permissions = vec!["D1 Write".to_owned()];
    capability.mutating = true;
    capability.risk = RiskClass::Irreversible;
    capability.effect = cfctl_core::EffectClass::DataWrite;
    capability.maturity = Maturity::GenerallyAvailable;
    capability.adapter_status = AdapterStatus::Native;
    capability.cost = CostV1 {
        incremental: false,
        currency: None,
        maximum: Some(0.0),
        basis: Some("D1 import has no incremental operation charge; ordinary D1 storage and rows-written accounting remains".to_owned()),
        known: true,
        billing_model: BillingModelV1::UsageBased,
        exposure: CostExposureV1::DownstreamUsage,
        references: vec![KnowledgeReferenceV1 {
            title: "D1 pricing".to_owned(),
            url: "https://developers.cloudflare.com/d1/platform/pricing/".to_owned(),
            source: "official Cloudflare docs".to_owned(),
        }],
    };
    capability.entitlement.available = Some(true);
    capability.verification.required = true;
    "mln_import_requires_governed_post_import_proof"
        .clone_into(&mut capability.verification.strategy);
    capability.rollback.supported = true;
    capability.rollback.strategy =
        Some("no_automatic_rollback_use_separately_approved_bookmark_restore".to_owned());
    capability.rollback.warning = Some(
        "There is no automatic rollback. Recovery requires a new explicitly approved exact-bookmark restore after quiescence and impact review. Restore 0143 only to its post-0142 anchor and prove the 0142 terminal trigger remains exact; restore 0142 only to its pre-0142 anchor and prove that trigger is absent."
            .to_owned(),
    );
    capability.selectors = [("account_id", account_id), ("database_id", database_id)]
        .map(|(name, value)| SelectorV1 {
            name: name.to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: Some(format!("Pinned MLNavigator {name}.")),
            contract: Some(SelectorContractV1 {
                schema: serde_json::json!({"type":"string","enum":[value]}),
                query: None,
            }),
        })
        .to_vec();
    capability.request_schema = Some(serde_json::json!({
        "type":"object","additionalProperties":false,"x-cfctl-body-required":true,
        "required":[
            "migration_id","pre_recovery_anchor_operation_id",
            "pre_recovery_anchor_evidence_hash","pre_recovery_anchor_output_sha256",
            "pre_recovery_anchor_bookmark_hash"
        ],
        "properties":{
            "migration_id":{"type":"string","enum":["0142","0143"]},
            "pre_recovery_anchor_operation_id":operation,
            "pre_recovery_anchor_evidence_hash":hash,
            "pre_recovery_anchor_output_sha256":hash,
            "pre_recovery_anchor_bookmark_hash":hash,
            "prior_0142_operation_id":operation,
            "prior_0142_boundary_evidence_hash":hash,
            "prior_0142_schema_proof_operation_id":operation,
            "prior_0142_verification_evidence_hash":hash,
            "post_0142_anchor_operation_id":operation,
            "post_0142_anchor_evidence_hash":hash,
            "post_0142_anchor_bookmark_hash":hash,
            "pre_import_invariant_operation_id":operation,
            "pre_import_invariant_evidence_hash":hash
        },
        "allOf":[
            {"if":{"properties":{"migration_id":{"const":"0142"}}},
             "then":{"not":{"anyOf":[
                 {"required":["prior_0142_operation_id"]},{"required":["prior_0142_boundary_evidence_hash"]},
                 {"required":["prior_0142_schema_proof_operation_id"]},{"required":["prior_0142_verification_evidence_hash"]},
                 {"required":["post_0142_anchor_operation_id"]},{"required":["post_0142_anchor_evidence_hash"]},
                 {"required":["post_0142_anchor_bookmark_hash"]},
                 {"required":["pre_import_invariant_operation_id"]},{"required":["pre_import_invariant_evidence_hash"]}
             ]}}},
            {"if":{"properties":{"migration_id":{"const":"0143"}}},
             "then":{"required":[
                 "prior_0142_operation_id","prior_0142_boundary_evidence_hash",
                 "prior_0142_schema_proof_operation_id","prior_0142_verification_evidence_hash",
                 "post_0142_anchor_operation_id","post_0142_anchor_evidence_hash",
                 "post_0142_anchor_bookmark_hash",
                 "pre_import_invariant_operation_id","pre_import_invariant_evidence_hash"
             ]}}
        ]
    }));
    capability.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".to_owned()],
        success_media_types: vec!["application/json".to_owned()],
        body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
    });
    let invariant_contract = mln_0143_data_invariants_capability()
        .mln_0143_data_invariants
        .unwrap_or_else(|| unreachable!("native MLN invariant contract"));
    capability.d1_approved_mln_import = Some(cfctl_core::D1ApprovedMlnImportContractV1 {
        repository_id: "github.com/rogu3bear/mln-web".to_owned(),
        repository_head: "7cb0327c084ce956d728aa7d9df467cea8ed44fb".to_owned(),
        pre_import_capability_version: invariant_contract.capability_version,
        pre_import_validator_contract_hash: invariant_contract.validator_contract_hash,
        pre_import_fixed_query_sha256: invariant_contract.fixed_query_sha256,
        account_id: account_id.to_owned(),
        database_id: database_id.to_owned(),
        import_path: capability.path.clone(),
        migrations: vec![
            cfctl_core::D1ApprovedMlnMigrationV1 {
                migration_id: "0142".to_owned(),
                basename: "0142_document_render_claim_generation.sql".to_owned(),
                repository_relative_path:
                    "crates/founder/migrations/d1/0142_document_render_claim_generation.sql"
                        .to_owned(),
                git_blob_oid: "408607c6fed6a5d9c10e80d6bacb2ee355817953".to_owned(),
                bytes: 1031,
                sha256: "07e1c5bd77dd529bfe58f0eee80ad29c40fdd0f3e9c9a37163cfaa0683124af0"
                    .to_owned(),
                md5: "5dc9f871404bc6aede1dbf8becf881e5".to_owned(),
            },
            cfctl_core::D1ApprovedMlnMigrationV1 {
                migration_id: "0143".to_owned(),
                basename: "0143_advisor_final_equity_instrument.sql".to_owned(),
                repository_relative_path:
                    "crates/founder/migrations/d1/0143_advisor_final_equity_instrument.sql"
                        .to_owned(),
                git_blob_oid: "4538523205bc1a3a2e68029aa040a06cd17946a8".to_owned(),
                bytes: 9736,
                sha256: "9b089ead4c284fe92f8a9f81296ac34aa98702585305e36b5c4f345fe774871d"
                    .to_owned(),
                md5: "bd50b7e05cc13c20f17eb8748472eb4b".to_owned(),
            },
        ],
        max_source_bytes: 16 * 1024 * 1024,
        max_response_bytes: 1024 * 1024,
        max_poll_attempts: 120,
        max_timeout_seconds: 30,
        upload_url_suffix: ".r2.cloudflarestorage.com".to_owned(),
        requires_create_new_mode_0600_stage: true,
    });
    capability
}

#[expect(
    clippy::too_many_lines,
    reason = "the six-entry closed migration catalogue and recovery contract remain reviewable in one declaration"
)]
fn d1_import_approved_osint_research_migration_capability() -> CapabilityV1 {
    let account_id = "ca30e922fda7f5578e49873542e4aaca";
    let database_id = "1c1ce476-73ab-4dd6-a2e2-de0c155ade61";
    let hash = serde_json::json!({
        "type":"string","pattern":"^sha256:[0-9a-f]{64}$","minLength":71,"maxLength":71
    });
    let mut capability = CapabilityV1::new(
        "d1-import-approved-osint-research-migration",
        "Import one approved OSINT Research Center migration",
        "POST",
        "/accounts/{account_id}/d1/database/{database_id}/import",
    );
    capability.authority_scope = Some(CapabilityAuthorityScopeV1::LegacyEmbedded);
    capability.description = Some(
        "Stage and import exactly one reviewed OSINT Research Center migration from 0028 through 0034. The adapter pins the private repository, clean release HEAD, relative path, Git blob, source hashes, account, and database. Every plan requires one governed current time-travel bookmark read created before the plan, and execution closes only after a compiler-owned schema-marker readback proves that exact migration's durable effect. No caller SQL or provider protocol control is accepted."
            .to_owned(),
    );
    "D1".clone_into(&mut capability.product);
    "cfctl native closed OSINT Research Center migration import adapter"
        .clone_into(&mut capability.source);
    "account".clone_into(&mut capability.account_scope);
    capability.aliases = vec![
        "apply OSINT Research migration".to_owned(),
        "migrate OSINT Research Center D1".to_owned(),
        "apply Research migrations 0028 through 0034".to_owned(),
    ];
    capability.permissions = vec!["D1 Write".to_owned()];
    capability.mutating = true;
    capability.risk = RiskClass::Irreversible;
    capability.effect = EffectClass::DataWrite;
    capability.maturity = Maturity::GenerallyAvailable;
    capability.adapter_status = AdapterStatus::Native;
    capability.cost = CostV1 {
        incremental: false,
        currency: None,
        maximum: Some(0.0),
        basis: Some(
            "D1 import and schema readback have no incremental operation charge; ordinary D1 storage, rows-written, and rows-read accounting remains"
                .to_owned(),
        ),
        known: true,
        billing_model: BillingModelV1::UsageBased,
        exposure: CostExposureV1::DownstreamUsage,
        references: vec![KnowledgeReferenceV1 {
            title: "D1 pricing".to_owned(),
            url: "https://developers.cloudflare.com/d1/platform/pricing/".to_owned(),
            source: "official Cloudflare docs".to_owned(),
        }],
    };
    capability.entitlement.available = Some(true);
    capability.verification.required = true;
    "osint_research_migration_schema_marker_is_present"
        .clone_into(&mut capability.verification.strategy);
    capability.rollback.supported = true;
    capability.rollback.strategy =
        Some("no_automatic_rollback_use_separately_approved_bookmark_restore".to_owned());
    capability.rollback.warning = Some(
        "There is no automatic rollback. Recovery requires a separately planned and approved exact-bookmark restore to the bound pre-migration time-travel bookmark after quiescence and impact review."
            .to_owned(),
    );
    capability.selectors = [("account_id", account_id), ("database_id", database_id)]
        .map(|(name, value)| SelectorV1 {
            name: name.to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: Some(format!("Pinned OSINT Research Center {name}.")),
            contract: Some(SelectorContractV1 {
                schema: serde_json::json!({"type":"string","enum":[value]}),
                query: None,
            }),
        })
        .to_vec();
    capability.request_schema = Some(serde_json::json!({
        "type":"object","additionalProperties":false,"x-cfctl-body-required":true,
        "required":[
            "migration_id","pre_recovery_anchor_evidence_hash",
            "pre_recovery_anchor_bookmark_hash"
        ],
        "properties":{
            "migration_id":{"type":"string","enum":["0028","0029","0030","0031","0032","0033","0034"]},
            "pre_recovery_anchor_evidence_hash":hash,
            "pre_recovery_anchor_bookmark_hash":hash
        }
    }));
    capability.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".to_owned()],
        success_media_types: vec!["application/json".to_owned()],
        body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
    });
    capability.d1_approved_mln_import = Some(cfctl_core::D1ApprovedMlnImportContractV1 {
        repository_id: "github.com/rogu3bear/osint-research-center".to_owned(),
        repository_head: "af3da8cd20d2f6acd0dd4948319d45dbe8561b53".to_owned(),
        pre_import_capability_version: 0,
        pre_import_validator_contract_hash: String::new(),
        pre_import_fixed_query_sha256: String::new(),
        account_id: account_id.to_owned(),
        database_id: database_id.to_owned(),
        import_path: capability.path.clone(),
        migrations: vec![
            cfctl_core::D1ApprovedMlnMigrationV1 {
                migration_id: "0028".to_owned(),
                basename: "0028_founder_people_handoff.sql".to_owned(),
                repository_relative_path: "migrations/d1/0028_founder_people_handoff.sql"
                    .to_owned(),
                git_blob_oid: "d463d2223051da863ac468e92914fbf88debd1fa".to_owned(),
                bytes: 2_853,
                sha256: "a2ac89e3db1efed7fcb4d07637e713f49c508164a127cdf1d2a81a60c86a2ae0"
                    .to_owned(),
                md5: "653f14485ff316a6573252abeff0e605".to_owned(),
            },
            cfctl_core::D1ApprovedMlnMigrationV1 {
                migration_id: "0029".to_owned(),
                basename: "0029_research_lifecycle_authority.sql".to_owned(),
                repository_relative_path: "migrations/d1/0029_research_lifecycle_authority.sql"
                    .to_owned(),
                git_blob_oid: "7e42628430d1847e636a268a6dc6f2352f9574d8".to_owned(),
                bytes: 7_057,
                sha256: "597ed8cca3965ad83126f2853996f1ff3f1a77fadf3f080dcd3d330e53126e9b"
                    .to_owned(),
                md5: "79c69abe2e316c758918c1d77dd8e6ee".to_owned(),
            },
            cfctl_core::D1ApprovedMlnMigrationV1 {
                migration_id: "0030".to_owned(),
                basename: "0030_operator_live_proof.sql".to_owned(),
                repository_relative_path: "migrations/d1/0030_operator_live_proof.sql".to_owned(),
                git_blob_oid: "5f021f1d811bbf0baf7ab4f5388895a1ff58b7f0".to_owned(),
                bytes: 1_961,
                sha256: "333e78871eaa036ade54481b1d036d20dadfa33bec3cf1a707c849dd59f13b19"
                    .to_owned(),
                md5: "125f2558dc535debc05a20d215b06029".to_owned(),
            },
            cfctl_core::D1ApprovedMlnMigrationV1 {
                migration_id: "0031".to_owned(),
                basename: "0031_job_retry_authority.sql".to_owned(),
                repository_relative_path: "migrations/d1/0031_job_retry_authority.sql".to_owned(),
                git_blob_oid: "f5742a397eade5526a42f6719d67c6a91b93a166".to_owned(),
                bytes: 448,
                sha256: "285eb5451cec6c6dcd316f7237d58179f76e55565e43a0e12232d1d9ff240465"
                    .to_owned(),
                md5: "7a75624927e38519d8b451a87a7d8aeb".to_owned(),
            },
            cfctl_core::D1ApprovedMlnMigrationV1 {
                migration_id: "0032".to_owned(),
                basename: "0032_durable_action_receipts.sql".to_owned(),
                repository_relative_path: "migrations/d1/0032_durable_action_receipts.sql"
                    .to_owned(),
                git_blob_oid: "161a19a300ce8596bde864136deaa1acf839ba3f".to_owned(),
                bytes: 1_284,
                sha256: "9727c9382f521d0e8a659a022a5440f6ef556c33a5efbfb71a78430ccc62b183"
                    .to_owned(),
                md5: "09ffafb383ba2cdbff7d769b5bba2819".to_owned(),
            },
            cfctl_core::D1ApprovedMlnMigrationV1 {
                migration_id: "0033".to_owned(),
                basename: "0033_deployment_authority.sql".to_owned(),
                repository_relative_path: "migrations/d1/0033_deployment_authority.sql".to_owned(),
                git_blob_oid: "bc91f79798399f92bb26421521d755ddac7c7ba4".to_owned(),
                bytes: 2_170,
                sha256: "183910767ab00b7a41bc2fb9f3f54f4db2978e779204a823509d20abf146bb9e"
                    .to_owned(),
                md5: "0c2da569b6e9dc9125667830174a6fbc".to_owned(),
            },
            cfctl_core::D1ApprovedMlnMigrationV1 {
                migration_id: "0034".to_owned(),
                basename: "0034_audit_hash_authority.sql".to_owned(),
                repository_relative_path: "migrations/d1/0034_audit_hash_authority.sql".to_owned(),
                git_blob_oid: "8015fac654607ac7f43f104236243e852fddc300".to_owned(),
                bytes: 2_901,
                sha256: "0240b298382402198043369f9afe3f8fdb353ecc16e22e669e644e5faeb58710"
                    .to_owned(),
                md5: "88bd54cd5a408fe3234513af4abd3d8d".to_owned(),
            },
        ],
        max_source_bytes: 16 * 1024 * 1024,
        max_response_bytes: 1024 * 1024,
        max_poll_attempts: 120,
        max_timeout_seconds: 30,
        upload_url_suffix: ".r2.cloudflarestorage.com".to_owned(),
        requires_create_new_mode_0600_stage: true,
    });
    capability
}
fn d1_resume_approved_mln_import_poll_capability() -> CapabilityV1 {
    let account_id = "ca30e922fda7f5578e49873542e4aaca";
    let database_id = "7c282983-2e48-4ea4-9f0d-09b0d718fe65";
    let hash = serde_json::json!({
        "type":"string","pattern":"^sha256:[0-9a-f]{64}$","minLength":71,"maxLength":71
    });
    let operation = serde_json::json!({
        "type":"string","format":"uuid","minLength":36,"maxLength":36
    });
    let mut capability = CapabilityV1::new(
        "d1-resume-approved-mln-import-poll",
        "Resume polling one approved MLNavigator import",
        "POST",
        "/accounts/{account_id}/d1/database/{database_id}/import",
    );
    capability.authority_scope = Some(CapabilityAuthorityScopeV1::LegacyEmbedded);
    capability.description = Some(
        "Create a separately approved poll-only child of one exact durable MLNavigator import exhaustion. The runtime derives the root migration, source, target, credential, catalog, accepted bookmark, and provider request from immutable parent authority. It never replays init, upload, or ingest; each exhaustion admits at most one non-cancelled child."
            .to_owned(),
    );
    "D1".clone_into(&mut capability.product);
    "cfctl native closed MLNavigator import poll continuation".clone_into(&mut capability.source);
    "account".clone_into(&mut capability.account_scope);
    capability.aliases = vec!["continue approved MLN import polling".to_owned()];
    capability.permissions = vec!["D1 Write".to_owned()];
    capability.mutating = true;
    capability.risk = RiskClass::Irreversible;
    capability.effect = EffectClass::DataWrite;
    capability.maturity = Maturity::GenerallyAvailable;
    capability.adapter_status = AdapterStatus::Native;
    capability.cost = CostV1 {
        incremental: false,
        currency: None,
        maximum: Some(0.0),
        basis: Some("Bounded D1 import polling has no incremental operation charge.".to_owned()),
        known: true,
        billing_model: BillingModelV1::UsageBased,
        exposure: CostExposureV1::DownstreamUsage,
        references: vec![KnowledgeReferenceV1 {
            title: "D1 pricing".to_owned(),
            url: "https://developers.cloudflare.com/d1/platform/pricing/".to_owned(),
            source: "official Cloudflare docs".to_owned(),
        }],
    };
    capability.entitlement.available = Some(true);
    capability.verification.required = true;
    "mln_import_requires_governed_post_import_proof"
        .clone_into(&mut capability.verification.strategy);
    capability.rollback.supported = true;
    capability.rollback.strategy =
        Some("no_automatic_rollback_use_separately_approved_bookmark_restore".to_owned());
    capability.rollback.warning = Some(
        "Polling may observe provider completion. Recovery remains a separately approved exact-bookmark restore."
            .to_owned(),
    );
    capability.selectors = [("account_id", account_id), ("database_id", database_id)]
        .map(|(name, value)| SelectorV1 {
            name: name.to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: Some(format!("Pinned MLNavigator {name}.")),
            contract: Some(SelectorContractV1 {
                schema: serde_json::json!({"type":"string","enum":[value]}),
                query: None,
            }),
        })
        .to_vec();
    capability.request_schema = Some(serde_json::json!({
        "type":"object","additionalProperties":false,"x-cfctl-body-required":true,
        "required":[
            "parent_operation_id","parent_plan_hash","exhaustion_evidence_hash",
            "accepted_ingest_evidence_hash","accepted_bookmark_hash"
        ],
        "properties":{
            "parent_operation_id":operation,
            "parent_plan_hash":hash,
            "exhaustion_evidence_hash":hash,
            "accepted_ingest_evidence_hash":hash,
            "accepted_bookmark_hash":hash
        }
    }));
    capability.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".to_owned()],
        success_media_types: vec!["application/json".to_owned()],
        body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
    });
    capability.d1_approved_mln_import_poll_resume =
        Some(cfctl_core::D1ApprovedMlnImportPollResumeContractV1 {
            root_capability_id: "d1-import-approved-mln-migration".to_owned(),
            account_id: account_id.to_owned(),
            database_id: database_id.to_owned(),
            import_path: capability.path.clone(),
            max_response_bytes: 1024 * 1024,
            max_poll_attempts: 120,
            max_timeout_seconds: 30,
        });
    capability
}

#[expect(
    clippy::too_many_lines,
    reason = "the closed MLN phase and lineage schema stays visible beside its pinned target contract"
)]
fn mln_0143_data_invariants_capability() -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        "mln-0143-data-invariants",
        "Prove MLNavigator migration 0143 data invariants",
        "POST",
        "/accounts/{account_id}/d1/database/{database_id}/query",
    );
    capability.authority_scope = Some(CapabilityAuthorityScopeV1::LegacyEmbedded);
    capability.description = Some(
        "Run fixed compiler-owned reads for the bounded pre-import, post-import, or post-restore MLNavigator 0143 boundary. Raw evidence rows and identifiers are digested in volatile memory and never persisted."
            .to_owned(),
    );
    "D1".clone_into(&mut capability.product);
    "cfctl native closed MLN 0143 invariant adapter".clone_into(&mut capability.source);
    "account".clone_into(&mut capability.account_scope);
    capability.aliases = vec![
        "verify MLN advisor instrument migration data".to_owned(),
        "prove MLN 0143 restore boundary".to_owned(),
    ];
    capability.permissions = vec!["D1 Read".to_owned()];
    capability.mutating = false;
    capability.risk = RiskClass::Read;
    capability.effect = EffectClass::ReadOnly;
    capability.maturity = Maturity::GenerallyAvailable;
    capability.adapter_status = AdapterStatus::Native;
    capability.cost = CostV1 {
        incremental:false,
        currency:None,
        maximum:None,
        basis:Some("one bounded fixed D1 read has no separate operation charge; ordinary rows-read accounting may apply".to_owned()),
        known:true,
        billing_model:BillingModelV1::UsageBased,
        exposure:CostExposureV1::DownstreamUsage,
        references:vec![KnowledgeReferenceV1 {
            title:"D1 pricing".to_owned(),
            url:"https://developers.cloudflare.com/d1/platform/pricing/".to_owned(),
            source:"official Cloudflare docs".to_owned(),
        }],
    };
    capability.entitlement.available = Some(true);
    capability.verification.required = false;
    "not_applicable".clone_into(&mut capability.verification.strategy);
    capability.rollback.supported = false;
    capability.selectors = vec![
        SelectorV1 {
            name:"account_id".to_owned(), location:"path".to_owned(), required:true,
            value_type:"string".to_owned(),
            description:Some("Pinned MLNavigator Cloudflare account; intended identity, not live ownership proof.".to_owned()),
            contract:Some(SelectorContractV1 {
                schema:serde_json::json!({"type":"string","enum":["ca30e922fda7f5578e49873542e4aaca"]}),
                query:None,
            }),
        },
        SelectorV1 {
            name:"database_id".to_owned(), location:"path".to_owned(), required:true,
            value_type:"string".to_owned(),
            description:Some("Pinned MLNavigator Founder D1 database.".to_owned()),
            contract:Some(SelectorContractV1 {
                schema:serde_json::json!({"type":"string","enum":["7c282983-2e48-4ea4-9f0d-09b0d718fe65"]}),
                query:None,
            }),
        },
    ];
    let hash = serde_json::json!({
        "type":"string","pattern":"^sha256:[0-9a-f]{64}$","minLength":71,"maxLength":71
    });
    capability.request_schema = Some(serde_json::json!({
        "type":"object","x-cfctl-body-required":true,
        "oneOf":[
            {
                "type":"object","additionalProperties":false,
                "required":["migration_id","phase"],
                "properties":{
                    "migration_id":{"type":"string","enum":["0143"]},
                    "phase":{"type":"string","enum":["pre_import"]}
                }
            },
            {
                "type":"object","additionalProperties":false,
                "required":[
                    "migration_id","phase","pre_import_evidence_hash",
                    "import_operation_id","import_boundary_evidence_hash",
                    "import_source_sha256","import_plan_hash"
                ],
                "properties":{
                    "migration_id":{"type":"string","enum":["0143"]},
                    "phase":{"type":"string","enum":["post_import"]},
                    "pre_import_evidence_hash":hash,
                    "import_operation_id":{"type":"string","minLength":36,"maxLength":80},
                    "import_boundary_evidence_hash":hash,
                    "import_source_sha256":hash,
                    "import_plan_hash":hash
                }
            },
            {
                "type":"object","additionalProperties":false,
                "required":[
                    "migration_id","phase","pre_import_evidence_hash","post_import_evidence_hash",
                    "import_operation_id","import_boundary_evidence_hash",
                    "import_source_sha256","import_plan_hash",
                    "restore_operation_id","restore_evidence_hash",
                    "restore_previous_bookmark_hash","restore_requested_bookmark_hash",
                    "restore_observed_bookmark_hash"
                ],
                "properties":{
                    "migration_id":{"type":"string","enum":["0143"]},
                    "phase":{"type":"string","enum":["post_restore"]},
                    "pre_import_evidence_hash":hash,
                    "post_import_evidence_hash":hash,
                    "import_operation_id":{"type":"string","minLength":36,"maxLength":80},
                    "import_boundary_evidence_hash":hash,
                    "import_source_sha256":hash,
                    "import_plan_hash":hash,
                    "restore_operation_id":{"type":"string","minLength":36,"maxLength":80},
                    "restore_evidence_hash":hash,
                    "restore_previous_bookmark_hash":hash,
                    "restore_requested_bookmark_hash":hash,
                    "restore_observed_bookmark_hash":hash
                }
            }
        ]
    }));
    capability.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".to_owned()],
        success_media_types: vec!["application/json".to_owned()],
        body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
    });
    let mut contract = Mln0143DataInvariantsContractV1 {
        account_id: "ca30e922fda7f5578e49873542e4aaca".to_owned(),
        database_id: "7c282983-2e48-4ea4-9f0d-09b0d718fe65".to_owned(),
        migration_sha256: "9b089ead4c284fe92f8a9f81296ac34aa98702585305e36b5c4f345fe774871d"
            .to_owned(),
        prior_0142_trigger_definition_hash:
            "sha256:7e68876f488b0117133c09de1cb0bbbd7a5a73ee705dd2888f480a2bdd1531e1".to_owned(),
        trigger_definition_hashes: vec![
            "sha256:d858df9c22c19df241e5045eca9635c4fb786000428707a821090daeacc69072".to_owned(),
            "sha256:e9205a4863c717c901ec3ac87089555a9af7eac14d5f38fbf40bff775ad8497c".to_owned(),
            "sha256:3ca04f9fc717104d2ee0da719e2c473a756d3345f4e222d52c4d0f76237a184b".to_owned(),
        ],
        fixed_query_sha256:
            "sha256:5437f47c76377bf228f4b0113784294c880e42a9ef59b5f24a94cb7147e5383c".to_owned(),
        pre_table_definition_hash:
            "sha256:8aa5012ace3d946354e0baba7e645646ac97373b42e7c3d61e79b67a5f689fea".to_owned(),
        post_table_definition_hash:
            "sha256:2fbdacd011abca8024507b99d179071b8b920271576e4cb3a2f06c4f3ffd2d7f".to_owned(),
        validator_contract_hash: String::new(),
        capability_version: 5,
        max_evidence_rows: 256,
        probe_rows: 257,
        max_bytes: 1024 * 1024,
        max_timeout_seconds: 30,
    };
    contract.validator_contract_hash = contract
        .expected_validator_contract_hash()
        .unwrap_or_default();
    capability.mln_0143_data_invariants = Some(contract);
    capability
}

#[expect(
    clippy::too_many_lines,
    reason = "the exact destructive restore contract stays visible as one auditable catalog declaration"
)]
fn d1_restore_exact_bookmark_capability() -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        "d1-restore-exact-bookmark",
        "Restore D1 database to exact bookmark",
        "POST",
        "/accounts/{account_id}/d1/database/{database_id}/time_travel/restore",
    );
    capability.description = Some(
        "Destructively overwrite one exact D1 database from an exact time-travel bookmark after verifying its expected current bookmark. In-flight queries are cancelled. Recovery is a separately approved new restore plan using the returned previous_bookmark; it is never automatic."
            .to_owned(),
    );
    "D1".clone_into(&mut capability.product);
    "cfctl native governed D1 exact-bookmark recovery adapter".clone_into(&mut capability.source);
    "account".clone_into(&mut capability.account_scope);
    capability.aliases = vec![
        "restore D1 exact bookmark".to_owned(),
        "recover D1 database from bookmark".to_owned(),
    ];
    capability.permissions = vec!["D1 Write".to_owned()];
    capability.mutating = true;
    capability.risk = RiskClass::Recovery;
    capability.effect = EffectClass::DataWrite;
    capability.maturity = Maturity::GenerallyAvailable;
    capability.adapter_status = AdapterStatus::Native;
    capability.cost = CostV1 {
        incremental: false,
        currency: None,
        maximum: Some(0.0),
        basis: Some(
            "D1 Time Travel restore has no incremental provider operation charge; ordinary D1 storage and usage pricing remains unchanged"
                .to_owned(),
        ),
        known: true,
        billing_model: BillingModelV1::UsageBased,
        exposure: CostExposureV1::DownstreamUsage,
        references: vec![
            KnowledgeReferenceV1 {
                title: "D1 Time Travel".to_owned(),
                url: "https://developers.cloudflare.com/d1/reference/time-travel/".to_owned(),
                source: "official Cloudflare docs".to_owned(),
            },
            KnowledgeReferenceV1 {
                title: "D1 pricing".to_owned(),
                url: "https://developers.cloudflare.com/d1/platform/pricing/".to_owned(),
                source: "official Cloudflare docs".to_owned(),
            },
        ],
    };
    capability.entitlement.available = Some(true);
    capability.entitlement.plans =
        BTreeMap::from([("free".to_owned(), true), ("paid".to_owned(), true)]);
    capability.entitlement.source =
        Some("https://developers.cloudflare.com/d1/reference/time-travel/".to_owned());
    capability.verification.required = true;
    "d1_current_bookmark_equals_restore_result_bookmark"
        .clone_into(&mut capability.verification.strategy);
    capability.rollback.supported = true;
    capability.rollback.strategy =
        Some("new_approved_exact_bookmark_restore_from_previous_bookmark".to_owned());
    capability.rollback.warning = Some(
        "Undo is never automatic: create and explicitly approve a new d1-restore-exact-bookmark plan whose target_bookmark is this operation's returned previous_bookmark, after a fresh expected-current-bookmark read."
            .to_owned(),
    );
    capability.selectors = ["account_id", "database_id"]
        .map(|name| SelectorV1 {
            name: name.to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: Some(format!("Exact Cloudflare {name}.")),
            contract: Some(SelectorContractV1 {
                schema: if name == "account_id" {
                    serde_json::json!({"type":"string","minLength":32,"maxLength":32})
                } else {
                    serde_json::json!({"type":"string","minLength":36,"maxLength":36})
                },
                query: None,
            }),
        })
        .to_vec();
    capability.request_schema = Some(serde_json::json!({
        "type":"object",
        "additionalProperties":false,
        "required":[
            "target_bookmark",
            "expected_current_bookmark",
            "source_operation_id",
            "source_evidence_hash"
        ],
        "properties":{
            "target_bookmark":{"type":"string","minLength":1,"maxLength":512},
            "expected_current_bookmark":{"type":"string","minLength":1,"maxLength":512},
            "source_operation_id":{"type":"string","minLength":1,"maxLength":80},
            "source_evidence_hash":{
                "type":"string",
                "pattern":"^sha256:[0-9a-f]{64}$",
                "minLength":71,
                "maxLength":71
            }
        },
        "x-cfctl-body-required":true
    }));
    capability.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".to_owned()],
        success_media_types: vec!["application/json".to_owned()],
        body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
    });
    capability.d1_restore_exact_bookmark = Some(cfctl_core::D1RestoreExactBookmarkContractV1 {
        bookmark_path: "/accounts/{account_id}/d1/database/{database_id}/time_travel/bookmark"
            .to_owned(),
        restore_path: "/accounts/{account_id}/d1/database/{database_id}/time_travel/restore"
            .to_owned(),
        max_response_bytes: 64 * 1024,
        max_timeout_seconds: 30,
        post_retry_count: 0,
    });
    capability
}

fn d1_full_export_capability() -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        "d1-full-export",
        "Export full D1 database to SQL",
        "POST",
        "/accounts/{account_id}/d1/database/{database_id}/export",
    );
    capability.description = Some("Create a provider-consistent full schema-and-data SQL export at one caller-specified new local file. Caller SQL, table filters, apply, and restore are excluded.".to_owned());
    "D1".clone_into(&mut capability.product);
    "cfctl native governed D1 full-export adapter".clone_into(&mut capability.source);
    "account".clone_into(&mut capability.account_scope);
    capability.aliases = vec![
        "snapshot D1 before migration".to_owned(),
        "export complete D1 database".to_owned(),
    ];
    capability.permissions = vec!["D1 Read".to_owned()];
    capability.mutating = false;
    capability.risk = RiskClass::Read;
    capability.effect = EffectClass::ReadOnly;
    capability.maturity = Maturity::GenerallyAvailable;
    capability.adapter_status = AdapterStatus::Native;
    capability.cost = CostV1 {
        incremental: false, currency: None, maximum: None,
        basis: Some("provider export and download have no declared direct operation charge".to_owned()),
        known: true, billing_model: BillingModelV1::UsageBased,
        exposure: CostExposureV1::DownstreamUsage,
        references: vec![KnowledgeReferenceV1 {
            title: "Export D1 Database as SQL".to_owned(),
            url: "https://developers.cloudflare.com/api/resources/d1/subresources/database/methods/export/".to_owned(),
            source: "official Cloudflare API docs".to_owned(),
        }],
    };
    capability.entitlement.available = Some(true);
    capability.verification.required = true;
    "same_output_file_exists_and_sha256_matches".clone_into(&mut capability.verification.strategy);
    capability.rollback.supported = false;
    capability.rollback.warning = Some("The file is a pre-migration snapshot only; applying or restoring it is outside this capability.".to_owned());
    capability.selectors = ["account_id", "database_id"]
        .map(|name| SelectorV1 {
            name: name.to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: Some(SelectorContractV1 {
                schema: if name == "account_id" {
                    serde_json::json!({"type":"string","minLength":32,"maxLength":32})
                } else {
                    serde_json::json!({"type":"string","minLength":36,"maxLength":36})
                },
                query: None,
            }),
        })
        .to_vec();
    capability.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".to_owned()],
        success_media_types: vec!["application/json".to_owned()],
        body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
    });
    capability.d1_full_export = Some(D1FullExportContractV1 {
        max_bytes: 10 * 1024 * 1024 * 1024,
        max_poll_response_bytes: 1024 * 1024,
        max_poll_attempts: 120,
        max_timeout_seconds: 30,
        max_download_seconds: 3600,
        requires_new_mode_0600_file: true,
    });
    capability
}

#[expect(
    clippy::too_many_lines,
    reason = "the closed D1 assertion variants remain visible beside their exact native contract"
)]
fn d1_schema_introspection_capability() -> CapabilityV1 {
    const ID: &str = "d1-schema-introspection";
    let mut capability = CapabilityV1::new(
        ID,
        "Assert bounded D1 schema state",
        "POST",
        "/accounts/{account_id}/d1/database/{database_id}/query",
    );
    capability.description = Some(
        "Run one closed, compiler-owned sqlite_schema or table-valued PRAGMA assertion without accepting caller SQL."
            .to_owned(),
    );
    "D1".clone_into(&mut capability.product);
    "cfctl native D1 schema assertion adapter".clone_into(&mut capability.source);
    "account".clone_into(&mut capability.account_scope);
    capability.aliases = vec![
        "check D1 migration schema".to_owned(),
        "inspect D1 table column index trigger check constraint".to_owned(),
        "verify D1 foreign keys".to_owned(),
    ];
    capability.permissions = vec!["D1 Read".to_owned()];
    capability.mutating = false;
    capability.risk = RiskClass::Read;
    capability.effect = EffectClass::ReadOnly;
    capability.maturity = Maturity::GenerallyAvailable;
    capability.adapter_status = AdapterStatus::Native;
    capability.blocked_reason = None;
    capability.cost = CostV1 {
        incremental: false,
        currency: None,
        maximum: None,
        basis: Some(
            "one bounded metadata assertion has no separate operation charge; ordinary D1 rows-read accounting may apply"
                .to_owned(),
        ),
        known: true,
        billing_model: BillingModelV1::UsageBased,
        exposure: CostExposureV1::DownstreamUsage,
        references: vec![KnowledgeReferenceV1 {
            title: "D1 pricing".to_owned(),
            url: "https://developers.cloudflare.com/d1/platform/pricing/".to_owned(),
            source: "official Cloudflare docs".to_owned(),
        }],
    };
    capability.entitlement.available = Some(true);
    capability.entitlement.plans =
        BTreeMap::from([("free".to_owned(), true), ("paid".to_owned(), true)]);
    capability.entitlement.source =
        Some("https://developers.cloudflare.com/d1/platform/pricing/".to_owned());
    capability.verification.required = false;
    "not_applicable".clone_into(&mut capability.verification.strategy);
    capability.rollback.supported = false;
    capability.rollback.strategy = None;
    capability.rollback.warning = None;
    capability.selectors = vec![
        SelectorV1 {
            name: "account_id".to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: Some("Exact Cloudflare account identifier.".to_owned()),
            contract: Some(SelectorContractV1 {
                schema: serde_json::json!({
                    "type":"string",
                    "minLength":32,
                    "maxLength":32
                }),
                query: None,
            }),
        },
        SelectorV1 {
            name: "database_id".to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: Some("Exact D1 database UUID.".to_owned()),
            contract: Some(SelectorContractV1 {
                schema: serde_json::json!({
                    "type":"string",
                    "minLength":36,
                    "maxLength":36
                }),
                query: None,
            }),
        },
    ];
    let name = serde_json::json!({"type":"string","minLength":1,"maxLength":255});
    capability.request_schema = Some(serde_json::json!({
        "type":"object",
        "x-cfctl-body-required":true,
        "oneOf":[
            {
                "type":"object",
                "additionalProperties":false,
                "required":["assertion","table"],
                "properties":{
                    "assertion":{"type":"string","enum":["table_exists"]},
                    "table":name
                }
            },
            {
                "type":"object",
                "additionalProperties":false,
                "required":["assertion","table","column"],
                "properties":{
                    "assertion":{"type":"string","enum":["column_exists"]},
                    "table":name,
                    "column":name
                }
            },
            {
                "type":"object",
                "additionalProperties":false,
                "required":["assertion","index"],
                "properties":{
                    "assertion":{"type":"string","enum":["index_exists"]},
                    "index":name
                }
            },
            {
                "type":"object",
                "additionalProperties":false,
                "required":["assertion","trigger"],
                "properties":{
                    "assertion":{"type":"string","enum":["trigger_exists"]},
                    "trigger":name
                }
            },
            {
                "type":"object",
                "additionalProperties":false,
                "required":["assertion","object_type","name","fragment"],
                "properties":{
                    "assertion":{"type":"string","enum":["schema_contains"]},
                    "object_type":{"type":"string","enum":["table","index","trigger"]},
                    "name":name,
                    "fragment":{"type":"string","minLength":1,"maxLength":512}
                }
            },
            {
                "type":"object",
                "additionalProperties":false,
                "required":["assertion"],
                "properties":{
                    "assertion":{"type":"string","enum":["foreign_key_check_empty"]}
                }
            }
        ]
    }));
    capability.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".to_owned()],
        success_media_types: vec!["application/json".to_owned()],
        body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
    });
    capability.d1_schema_introspection = Some(D1SchemaIntrospectionContractV1 {
        max_rows: 1,
        max_bytes: 64 * 1024,
        max_timeout_seconds: 10,
    });
    capability
}

fn reserve_queue_message_operations_for_event_consumer(snapshot: &mut CatalogSnapshot) {
    for (id, path) in [
        (
            "queues-pull-messages",
            "/accounts/{account_id}/queues/{queue_id}/messages/pull",
        ),
        (
            "queues-ack-messages",
            "/accounts/{account_id}/queues/{queue_id}/messages/ack",
        ),
    ] {
        let Some(capability) = snapshot.capabilities.get_mut(id) else {
            continue;
        };
        let identity_ok = capability.method == "POST"
            && capability.path == path
            && capability.permissions == ["Queues Write", "Workers Scripts Write"];
        capability.adapter_status = AdapterStatus::Blocked;
        capability.blocked_reason = Some(if identity_ok {
            "blocked by design for generic `cfctl call`: raw Queue pull and acknowledgement are executable only inside one approved `events-consume-queue-batch` plan"
                .to_owned()
        } else {
            "schema drift: Queue pull/ack identity or permission changed; the event-consumer adapter remains unavailable until the new contract is reviewed"
                .to_owned()
        });
    }
}

fn event_batch_capability(snapshot: &CatalogSnapshot) -> CapabilityV1 {
    use cfctl_core::{
        EVENT_BATCH_CAPABILITY_ID, QUEUE_ACK_CAPABILITY_ID, QUEUE_ACK_PATH,
        QUEUE_PULL_CAPABILITY_ID, QUEUE_PULL_PATH, RollbackSpecV1, VerificationSpecV1,
    };

    let permissions = vec![
        "Queues Write".to_owned(),
        "Workers Scripts Write".to_owned(),
    ];
    let raw_identity_matches = [
        (QUEUE_PULL_CAPABILITY_ID, QUEUE_PULL_PATH),
        (QUEUE_ACK_CAPABILITY_ID, QUEUE_ACK_PATH),
    ]
    .into_iter()
    .all(|(id, path)| {
        snapshot.get(id).is_some_and(|capability| {
            capability.method == "POST"
                && capability.path == path
                && capability.permissions == permissions
                && capability
                    .response_contract
                    .as_ref()
                    .is_some_and(|contract| {
                        contract.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
                    })
        })
    });
    let (pricing_reference, schema_reference) = event_batch_references();
    let mut capability = CapabilityV1::new(
        EVENT_BATCH_CAPABILITY_ID,
        "Consume one governed Cloudflare event Queue batch",
        "POST",
        "/cfctl/events/queue-batches/{account_id}/{queue_id}/{subscription_id}",
    );
    capability.description = Some(
        "Pull one bounded Queue batch, validate and durably commit every event receipt and reconciliation job, then acknowledge only the exact committed leases."
            .to_owned(),
    );
    "Events".clone_into(&mut capability.product);
    "cfctl native event batch adapter".clone_into(&mut capability.source);
    "account".clone_into(&mut capability.account_scope);
    capability.aliases = vec![
        "consume event queue batch".to_owned(),
        "pull and acknowledge Cloudflare events".to_owned(),
    ];
    capability.permissions.clone_from(&permissions);
    capability.selectors = ["account_id", "queue_id", "subscription_id"]
        .into_iter()
        .map(|name| SelectorV1 {
            name: name.to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        })
        .collect();
    capability.risk = RiskClass::Irreversible;
    capability.effect = EffectClass::Irreversible;
    capability.maturity = Maturity::GenerallyAvailable;
    capability.entitlement.available = Some(true);
    capability.cost = event_batch_cost(&pricing_reference);
    capability.verification = VerificationSpecV1 {
        required: true,
        strategy: "event_batch_registry_commit_and_queue_acknowledgement_receipt".to_owned(),
    };
    capability.rollback = RollbackSpecV1 {
        supported: false,
        strategy: None,
        warning: Some(
            "Queue acknowledgement is irreversible; redelivery is not requested after the exact leases are acknowledged."
                .to_owned(),
        ),
    };
    capability.request_schema = Some(event_batch_request_schema());
    capability.event_batch = Some(EventBatchContractV1 {
        pull_capability_id: QUEUE_PULL_CAPABILITY_ID.to_owned(),
        pull_path: QUEUE_PULL_PATH.to_owned(),
        acknowledge_capability_id: QUEUE_ACK_CAPABILITY_ID.to_owned(),
        acknowledge_path: QUEUE_ACK_PATH.to_owned(),
        required_permissions: permissions,
        max_batch_size: 100,
        max_visibility_timeout_ms: 43_200_000,
        max_message_bytes: 131_072,
        billing_chunk_bytes: 65_536,
        price_per_million_operations: 0.40,
        pricing_reference,
        schema_reference,
    });
    capability.adapter_status = if raw_identity_matches {
        AdapterStatus::Native
    } else {
        AdapterStatus::Blocked
    };
    capability.blocked_reason = (!raw_identity_matches).then(|| {
        "schema drift: exact Queue pull/ack identity, permissions, or response contract changed; event batch planning is blocked pending review"
            .to_owned()
    });
    capability
}

fn event_batch_cost(pricing_reference: &KnowledgeReferenceV1) -> CostV1 {
    CostV1 {
        incremental: true,
        currency: Some("USD".to_owned()),
        maximum: Some(0.00016),
        basis: Some(
            "100 messages x read and delete x at most two 64 KB billing chunks x USD 0.40 per million operations"
                .to_owned(),
        ),
        known: true,
        billing_model: BillingModelV1::UsageBased,
        exposure: CostExposureV1::DownstreamUsage,
        references: vec![pricing_reference.clone()],
    }
}

fn event_batch_references() -> (KnowledgeReferenceV1, KnowledgeReferenceV1) {
    let reference = |title: &str, url: &str| KnowledgeReferenceV1 {
        title: title.to_owned(),
        url: url.to_owned(),
        source: "official Cloudflare documentation".to_owned(),
    };
    (
        reference(
            "Cloudflare Queues pricing",
            "https://developers.cloudflare.com/queues/platform/pricing/",
        ),
        reference(
            "Cloudflare Queues pull consumers",
            "https://developers.cloudflare.com/queues/configuration/pull-consumers/",
        ),
    )
}

fn event_batch_request_schema() -> Value {
    serde_json::json!({
        "type":"object",
        "required":["batch_size","visibility_timeout_ms"],
        "properties":{
            "batch_size":{"type":"integer","minimum":1,"maximum":100},
            "visibility_timeout_ms":{"type":"integer","minimum":1000,"maximum":43_200_000}
        },
        "additionalProperties":false,
        "x-cfctl-body-required":true
    })
}

fn block_deprecated_pipeline_update(snapshot: &mut CatalogSnapshot) {
    const ID: &str = "putV4AccountsByAccount_idPipelinesByPipeline_name_deprecated";
    let Some(capability) = snapshot.capabilities.get_mut(ID) else {
        return;
    };
    capability.adapter_status = AdapterStatus::Blocked;
    capability.blocked_reason = Some(
        "blocked by design: Cloudflare Pipelines SQL configuration is immutable; replace it through separately reviewed delete and create plans instead of modeling this deprecated PUT as an update"
            .to_owned(),
    );
}

const EVENT_SUBSCRIPTION_COLLECTION_PATH: &str =
    "/accounts/{account_id}/event_subscriptions/subscriptions";
const EVENT_SUBSCRIPTION_DETAIL_PATH: &str =
    "/accounts/{account_id}/event_subscriptions/subscriptions/{subscription_id}";

fn event_source_variant(source_type: &str, fields: &[&str]) -> Value {
    let mut properties = serde_json::Map::from_iter([(
        "type".to_owned(),
        serde_json::json!({"type":"string","enum":[source_type]}),
    )]);
    for field in fields {
        properties.insert((*field).to_owned(), serde_json::json!({"type":"string"}));
    }
    let mut required = vec!["type"];
    required.extend(fields.iter().copied());
    serde_json::json!({
        "type":"object",
        "additionalProperties":false,
        "required":required,
        "properties":properties
    })
}

fn add_current_event_subscription_sources(schema: &mut Value) -> bool {
    let Some(variants) = schema
        .pointer_mut("/properties/source/oneOf")
        .and_then(Value::as_array_mut)
    else {
        return false;
    };
    let declared = variants
        .iter()
        .filter_map(|variant| variant.pointer("/properties/type/enum/0"))
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    for (source_type, fields) in [
        ("access", Vec::<&str>::new()),
        ("artifacts", Vec::<&str>::new()),
        ("artifacts.repo", vec!["namespace", "repo_name"]),
        ("email.sending", vec!["domain"]),
    ] {
        if !declared.contains(source_type) {
            variants.push(event_source_variant(source_type, &fields));
        }
    }
    true
}

fn finalize_event_subscription_lifecycle(snapshot: &mut CatalogSnapshot) {
    const CREATE: &str = "subscriptions-create";
    const READ: &str = "subscriptions-get";
    const LIST: &str = "subscriptions-list";
    const UPDATE: &str = "subscriptions-patch";
    const DELETE: &str = "subscriptions-delete";
    let identity_ok = snapshot.capabilities.get(CREATE).is_some_and(|capability| {
        capability.method == "POST" && capability.path == EVENT_SUBSCRIPTION_COLLECTION_PATH
    }) && snapshot.capabilities.get(READ).is_some_and(|capability| {
        capability.method == "GET" && capability.path == EVENT_SUBSCRIPTION_DETAIL_PATH
    }) && snapshot.capabilities.get(LIST).is_some_and(|capability| {
        capability.method == "GET" && capability.path == EVENT_SUBSCRIPTION_COLLECTION_PATH
    }) && snapshot.capabilities.get(UPDATE).is_some_and(|capability| {
        capability.method == "PATCH" && capability.path == EVENT_SUBSCRIPTION_DETAIL_PATH
    }) && snapshot.capabilities.get(DELETE).is_some_and(|capability| {
        capability.method == "DELETE" && capability.path == EVENT_SUBSCRIPTION_DETAIL_PATH
    });
    if !identity_ok {
        for id in [CREATE, UPDATE] {
            if let Some(capability) = snapshot.capabilities.get_mut(id) {
                capability.adapter_status = AdapterStatus::Blocked;
                capability.blocked_reason = Some(
                    "schema drift: Event Subscription create/read/update/delete no longer matches the reviewed Queue lifecycle"
                        .to_owned(),
                );
            }
        }
        return;
    }

    for id in [LIST, READ, DELETE] {
        if let Some(capability) = snapshot.capabilities.get_mut(id) {
            capability.aliases.extend([
                "Cloudflare Event Subscriptions".to_owned(),
                "real-time event sources to Queue".to_owned(),
            ]);
        }
    }
    for id in [CREATE, UPDATE] {
        let Some(capability) = snapshot.capabilities.get_mut(id) else {
            continue;
        };
        let Some(schema) = capability.request_schema.as_mut() else {
            capability.adapter_status = AdapterStatus::Blocked;
            capability.blocked_reason = Some(
                "schema drift: Event Subscription mutation has no typed request schema".to_owned(),
            );
            continue;
        };
        let has_source = schema.pointer("/properties/source").is_some();
        if (id == CREATE || has_source) && !add_current_event_subscription_sources(schema) {
            capability.adapter_status = AdapterStatus::Blocked;
            capability.blocked_reason = Some(
                "schema drift: Event Subscription source union cannot be safely extended"
                    .to_owned(),
            );
            continue;
        }
        capability.aliases = vec![
            "Cloudflare Event Subscription Queue bridge".to_owned(),
            "subscribe Access Artifacts Email Sending events".to_owned(),
            "real-time resource event reconciliation".to_owned(),
        ];
        capability.risk = RiskClass::ScopedWrite;
        capability.effect = EffectClass::ReversibleWrite;
        zero_cost_mutation(
            capability,
            "creating or changing the subscription has no direct configuration charge; resulting Queue operations remain usage-based and are bounded separately by the event-consumer authority",
            official_reference(
                "Event Subscription schemas",
                "https://developers.cloudflare.com/queues/event-subscriptions/events-schemas/",
            ),
        );
        if id == UPDATE {
            capability.verification.required = true;
            "same_resource_contains_planned_fields_after_update"
                .clone_into(&mut capability.verification.strategy);
            capability.same_path_read = Some(SamePathReadContractV1 {
                path: EVENT_SUBSCRIPTION_DETAIL_PATH.to_owned(),
                read_capability_id: READ.to_owned(),
                verified_response_fields: vec![
                    "destination".to_owned(),
                    "enabled".to_owned(),
                    "events".to_owned(),
                    "name".to_owned(),
                ],
            });
            capability.rollback.supported = true;
            capability.rollback.strategy = Some("restore_same_path_prior_snapshot".to_owned());
            capability.rollback.warning = Some(
                "rollback restores the exact pre-change subscription through a separately reviewed plan; already-enqueued events remain durable"
                    .to_owned(),
            );
        }
        refresh_dynamic_mutation_contract(capability);
    }
}

const REALTIMEKIT_WEBHOOK_COLLECTION_PATH: &str =
    "/accounts/{account_id}/realtime/kit/{app_id}/webhooks";
const REALTIMEKIT_WEBHOOK_DETAIL_PATH: &str =
    "/accounts/{account_id}/realtime/kit/{app_id}/webhooks/{webhook_id}";
const REALTIMEKIT_WEBHOOK_FIELDS: &[&str] = &["enabled", "events", "name", "url"];

#[expect(
    clippy::too_many_lines,
    reason = "the exact RealtimeKit CRUD identities, data-envelope protocol, verifier, cost, and compensation contracts are reviewed together"
)]
fn finalize_realtimekit_webhook_lifecycle(snapshot: &mut CatalogSnapshot) {
    const CREATE: &str = "addWebhook";
    const LIST: &str = "getAllWebhooks";
    const READ: &str = "getWebhook";
    const PATCH: &str = "editWebhook";
    const REPLACE: &str = "replaceWebhook";
    const DELETE: &str = "deleteWebhook";
    let identities = [
        (CREATE, "POST", REALTIMEKIT_WEBHOOK_COLLECTION_PATH),
        (LIST, "GET", REALTIMEKIT_WEBHOOK_COLLECTION_PATH),
        (READ, "GET", REALTIMEKIT_WEBHOOK_DETAIL_PATH),
        (PATCH, "PATCH", REALTIMEKIT_WEBHOOK_DETAIL_PATH),
        (REPLACE, "PUT", REALTIMEKIT_WEBHOOK_DETAIL_PATH),
        (DELETE, "DELETE", REALTIMEKIT_WEBHOOK_DETAIL_PATH),
    ];
    let identity_ok = identities.iter().all(|(id, method, path)| {
        snapshot.capabilities.get(*id).is_some_and(|capability| {
            capability.method == *method
                && capability.path == *path
                && capability.permissions == ["Realtime Admin", "Realtime"]
        })
    });
    if !identity_ok {
        for id in [CREATE, PATCH, REPLACE] {
            if let Some(capability) = snapshot.capabilities.get_mut(id) {
                capability.adapter_status = AdapterStatus::Blocked;
                capability.blocked_reason = Some(
                    "schema drift: RealtimeKit webhook CRUD no longer matches the reviewed data-envelope lifecycle"
                        .to_owned(),
                );
            }
        }
        return;
    }

    for (id, _, _) in identities {
        let Some(capability) = snapshot.capabilities.get_mut(id) else {
            return;
        };
        capability.response_contract = Some(ResponseContractV1 {
            success_statuses: capability.response_contract.as_ref().map_or_else(
                || vec!["200".to_owned()],
                |contract| contract.success_statuses.clone(),
            ),
            success_media_types: vec!["application/json".to_owned()],
            body_mode: ResponseBodyModeV1::CloudflareDataEnvelope,
        });
        capability.aliases.extend([
            "meeting event webhook API".to_owned(),
            "signed meeting webhook delivery".to_owned(),
        ]);
        capability.entitlement.requires_live_resolution = true;
        capability.entitlement.source =
            Some("https://developers.cloudflare.com/realtime/realtimekit/webhooks/".to_owned());
    }

    for id in [CREATE, PATCH, REPLACE] {
        let Some(capability) = snapshot.capabilities.get_mut(id) else {
            return;
        };
        capability.risk = RiskClass::ExternalCommunication;
        capability.effect = EffectClass::ExternalCommunication;
        zero_cost_mutation(
            capability,
            "registering or changing a webhook has no direct operation charge; RealtimeKit session usage remains governed by its separate product pricing",
            official_reference(
                "RealtimeKit webhooks",
                "https://developers.cloudflare.com/realtime/realtimekit/webhooks/",
            ),
        );
        if id == CREATE {
            capability.created_resource = Some(CreatedResourceContractV1 {
                detail_path: REALTIMEKIT_WEBHOOK_DETAIL_PATH.to_owned(),
                identity_selector: "webhook_id".to_owned(),
                response_result_identity_pointer: "/id".to_owned(),
                read_capability_id: READ.to_owned(),
                delete_capability_id: DELETE.to_owned(),
                verified_response_fields: REALTIMEKIT_WEBHOOK_FIELDS
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
            });
            capability.verification.required = true;
            "created_resource_contains_planned_fields_by_returned_id"
                .clone_into(&mut capability.verification.strategy);
            capability.rollback.supported = true;
            capability.rollback.strategy =
                Some("delete_created_resource_by_returned_id".to_owned());
            capability.rollback.warning = Some(
                "compensation deletes only the returned webhook id through a separately reviewed plan; deliveries already accepted by the endpoint are outside rollback"
                    .to_owned(),
            );
        } else {
            if id == PATCH
                && let Some(schema) = capability.request_schema.as_mut()
            {
                schema["minProperties"] = serde_json::json!(1);
            }
            capability.same_path_read = Some(SamePathReadContractV1 {
                path: REALTIMEKIT_WEBHOOK_DETAIL_PATH.to_owned(),
                read_capability_id: READ.to_owned(),
                verified_response_fields: REALTIMEKIT_WEBHOOK_FIELDS
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
            });
            capability.verification.required = true;
            "same_resource_contains_planned_fields_after_update"
                .clone_into(&mut capability.verification.strategy);
            capability.rollback.supported = true;
            capability.rollback.strategy = Some("restore_same_path_prior_snapshot".to_owned());
            capability.rollback.warning = Some(
                "rollback restores the exact pre-change webhook through a separately reviewed plan; deliveries already accepted by either endpoint are outside rollback"
                    .to_owned(),
            );
        }
        refresh_dynamic_mutation_contract(capability);
    }
}

const LIVE_TAIL_HEARTBEAT_MISLEADING_ID: &str = "telemetry.live-tail.heartbeat.get";
const LIVE_TAIL_HEARTBEAT_PATH: &str =
    "/accounts/{account_id}/workers/observability/telemetry/live-tail/heartbeat";

/// The upstream operation id ends in `.get`, but the wire operation is a POST
/// with a mutating classification. Keep it discoverable as catalog debt while
/// preventing a future generic classifier from presenting it as an ordinary
/// read or contract-ready mutation.
fn block_misleading_live_tail_heartbeat_identity(snapshot: &mut CatalogSnapshot) {
    let Some(capability) = snapshot
        .capabilities
        .get_mut(LIVE_TAIL_HEARTBEAT_MISLEADING_ID)
    else {
        return;
    };
    let exact_known_identity =
        capability.method == "POST" && capability.path == LIVE_TAIL_HEARTBEAT_PATH;
    capability.adapter_status = AdapterStatus::Blocked;
    capability.blocked_reason = Some(if exact_known_identity {
        "blocked by design: upstream operation id ends in `.get`, but the exact wire operation is a mutating POST; classify its effect, cost, verification, rollback, and stable public identity before promotion"
            .to_owned()
    } else {
        format!(
            "blocked by design: the reserved misleading heartbeat operation identity drifted from the reviewed POST {}; reclassify the new {} {} contract before promotion",
            LIVE_TAIL_HEARTBEAT_PATH, capability.method, capability.path
        )
    });
}

const LOGPULL_RETRIEVE_ID: &str = "logpull-retrieve-logs";
const LOGPULL_RETRIEVE_PATH: &str = "/accounts/{account_id}/logs/retrieve";

/// Graduates only Cloudflare's exact Logs Engine retrieval operation from the
/// generic reserved-header blocker. The public selector surface loses both R2
/// credential headers; the executor can recreate them only from the typed,
/// out-of-band bundle described by `R2LogRetrievalContractV1` and must stream
/// the bounded response to a new private file.
#[expect(
    clippy::too_many_lines,
    reason = "the private Logpull overlay keeps its bounded query, credential, cost, and receipt contract together"
)]
fn finalize_logpull_retrieval(snapshot: &mut CatalogSnapshot) {
    let Some(capability) = snapshot.capabilities.get_mut(LOGPULL_RETRIEVE_ID) else {
        return;
    };
    let selector_shape = [
        ("account_id", "path", true),
        ("R2-Access-Key-Id", "header", true),
        ("R2-Secret-Access-Key", "header", true),
        ("start", "query", true),
        ("end", "query", true),
        ("bucket", "query", true),
        ("prefix", "query", false),
    ];
    let identity_supported = capability.method == "GET"
        && capability.path == LOGPULL_RETRIEVE_PATH
        && capability.product == "Logpull"
        && capability.account_scope == "account"
        && !capability.mutating
        && capability.request_schema.is_none()
        && capability.selectors.len() == selector_shape.len()
        && selector_shape.iter().all(|(name, location, required)| {
            capability.selectors.iter().any(|selector| {
                selector.name == *name
                    && selector.location == *location
                    && selector.required == *required
                    && selector.value_type == "string"
            })
        })
        && capability.permissions == ["Logs Write", "Logs Read"]
        && capability
            .response_contract
            .as_ref()
            .is_some_and(|response| {
                response.success_statuses == ["200"]
                    && response.success_media_types == ["application/json"]
                    && response.body_mode == ResponseBodyModeV1::JsonValue
            });
    if !identity_supported {
        capability.adapter_status = AdapterStatus::Blocked;
        capability.blocked_reason = Some(
            "schema drift: Logs Engine retrieval no longer matches the pinned account, R2 credential-header, RFC3339 range, bucket, and JSON stream contract"
                .to_owned(),
        );
        return;
    }

    capability
        .selectors
        .retain(|selector| selector.location != "header");
    capability.permissions = vec!["Logs Read".to_owned()];
    capability.aliases = vec![
        "Logpull".to_owned(),
        "Logs Engine".to_owned(),
        "retrieve R2 logs".to_owned(),
        "export retained logs by time range".to_owned(),
    ];
    capability.description = Some(
        "Streams one explicit RFC3339 time window from one R2 log bucket to a new mode-0600 file. R2 credentials come only from a closed out-of-band bundle, never selectors, argv, stdout, plans, logs, or evidence. The receipt reports the time bounds, hashed bucket/prefix, byte bound, bytes written, completeness, and content hash."
            .to_owned(),
    );
    capability.r2_log_retrieval = Some(R2LogRetrievalContractV1 {
        access_key_input_field: "access_key_id".to_owned(),
        secret_access_key_input_field: "secret_access_key".to_owned(),
        access_key_header: "R2-Access-Key-Id".to_owned(),
        secret_access_key_header: "R2-Secret-Access-Key".to_owned(),
        start_query_selector: "start".to_owned(),
        end_query_selector: "end".to_owned(),
        bucket_query_selector: "bucket".to_owned(),
        prefix_query_selector: "prefix".to_owned(),
        // R2 has no product retention ceiling, so cfctl uses a generous but
        // finite lookback and a deliberately narrow per-call window.
        max_lookback_seconds: 10 * 365 * 24 * 60 * 60,
        max_window_seconds: 60 * 60,
        max_bytes: 256 * 1024 * 1024,
        max_timeout_seconds: 120,
        output_media_types: vec!["application/json".to_owned()],
        requires_new_mode_0600_file: true,
    });
    capability.risk = RiskClass::Read;
    capability.effect = EffectClass::ReadOnly;
    capability.adapter_status = AdapterStatus::DynamicApi;
    capability.blocked_reason = None;
    capability.entitlement.available = None;
    capability.entitlement.requires_live_resolution = true;
    capability.entitlement.source =
        Some("https://developers.cloudflare.com/logs/r2-log-retrieval/".to_owned());
    capability.cost.incremental = true;
    capability.cost.known = false;
    capability.cost.maximum = None;
    capability.cost.currency = None;
    capability.cost.billing_model = BillingModelV1::UsageBased;
    capability.cost.exposure = CostExposureV1::DownstreamUsage;
    capability.cost.basis = Some(
        "the retrieval is bounded to 256 MiB but R2 Class B retrieval and storage charges depend on the account and cannot be converted to a universal currency ceiling before the read"
            .to_owned(),
    );
    capability.cost.references = vec![
        official_reference(
            "Logs Engine R2 retrieval",
            "https://developers.cloudflare.com/logs/r2-log-retrieval/",
        ),
        official_reference(
            "R2 pricing",
            "https://developers.cloudflare.com/r2/pricing/",
        ),
    ];
    capability.verification.required = false;
    "bounded_file_hash_receipt".clone_into(&mut capability.verification.strategy);
    capability.rollback.warning = None;
}

#[expect(
    clippy::too_many_lines,
    reason = "the account and zone Log Explorer overlays share one symmetric contract definition"
)]
fn finalize_log_explorer_queries(snapshot: &mut CatalogSnapshot) {
    for id in [
        "accounts-logs-explorer-query-get",
        "zones-logs-explorer-query-get",
    ] {
        if let Some(capability) = snapshot.capabilities.get_mut(id) {
            capability.adapter_status = AdapterStatus::Blocked;
            capability.blocked_reason = Some(
                "blocked by design: raw Log Explorer SQL query parameters are not a public cfctl surface; use the typed POST capability for the same scope"
                    .to_owned(),
            );
        }
    }

    for (id, path, scope) in [
        (
            "accounts-logs-explorer-query-post",
            "/accounts/{account_id}/logs/explorer/query/sql",
            "account",
        ),
        (
            "zones-logs-explorer-query-post",
            "/zones/{zone_id}/logs/explorer/query/sql",
            "zone",
        ),
    ] {
        let Some(capability) = snapshot.capabilities.get_mut(id) else {
            continue;
        };
        let identity_supported = capability.method == "POST"
            && capability.path == path
            && capability
                .permissions
                .iter()
                .any(|permission| permission == "Logs Read")
            && capability
                .response_contract
                .as_ref()
                .is_some_and(|response| {
                    response.success_statuses == ["200"]
                        && response
                            .success_media_types
                            .iter()
                            .any(|media| media == "application/json")
                        && response.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
                });
        if !identity_supported {
            capability.adapter_status = AdapterStatus::Blocked;
            capability.blocked_reason = Some(format!(
                "schema drift: {scope} Log Explorer SQL no longer matches the governed POST, Logs Read, and JSON response contract"
            ));
            continue;
        }
        capability
            .selectors
            .retain(|selector| selector.location != "query");
        capability.permissions = vec!["Logs Read".to_owned()];
        capability.aliases = vec![
            "Log Explorer".to_owned(),
            format!("query {scope} logs"),
            "Access logs Zero Trust logs audit logs security events".to_owned(),
            "bounded log SQL".to_owned(),
        ];
        capability.description = Some(format!(
            "Runs a compiler-rendered, single-statement SELECT over one {scope}-scoped Log Explorer dataset with an explicit timestamp field, time window, row, byte, and timeout bound. Raw SQL is never accepted."
        ));
        capability.request_schema = Some(structured_log_explorer_schema());
        capability.analytics_query = Some(AnalyticsQueryContractV1 {
            kind: AnalyticsQueryKindV1::LogExplorerSql,
            dataset: None,
            dataset_pointer: Some("/dataset".to_owned()),
            time_range: Some(TimeRangeContractV1 {
                start_pointer: "/start".to_owned(),
                end_pointer: "/end".to_owned(),
                timestamp_format: TimestampFormatV1::Rfc3339,
                max_lookback_seconds: 30 * 24 * 60 * 60,
                max_window_seconds: 24 * 60 * 60,
            }),
            row_limit_pointer: Some("/limit".to_owned()),
            max_rows: 5_000,
            max_bytes: 32 * 1024 * 1024,
            max_timeout_seconds: 30,
            allowed_output_formats: vec![OutputFormatV1::Json],
            default_output_format: OutputFormatV1::Json,
            pagination: PaginationModeV1::TimeWindow,
            read_only: true,
            freshness: Some(
                "dataset ingestion freshness is returned as upstream data, never inferred by cfctl"
                    .to_owned(),
            ),
            sampling: Some(
                "Log Explorer queries operate on retained ingested logs; missing records are not interpreted as unsampled truth"
                    .to_owned(),
            ),
        });
        capability.mutating = false;
        capability.risk = RiskClass::Read;
        capability.effect = EffectClass::ReadOnly;
        capability.adapter_status = AdapterStatus::DynamicApi;
        capability.blocked_reason = None;
        capability.entitlement.available = None;
        capability.entitlement.requires_live_resolution = true;
        capability.entitlement.source =
            Some("https://developers.cloudflare.com/log-explorer/pricing/".to_owned());
        capability.cost.known = true;
        capability.cost.incremental = false;
        capability.cost.maximum = Some(0.0);
        capability.cost.billing_model = BillingModelV1::UsageBased;
        capability.cost.exposure = CostExposureV1::DownstreamUsage;
        capability.cost.basis = Some(
            "queries have no additional charge; Log Explorer ingestion and retained storage are paid usage and require a live entitlement check"
                .to_owned(),
        );
        capability.cost.references = vec![official_reference(
            "Log Explorer pricing and availability",
            "https://developers.cloudflare.com/log-explorer/pricing/",
        )];
        capability.verification.required = false;
        "not_applicable".clone_into(&mut capability.verification.strategy);
        capability.rollback.warning = None;
    }
}

fn structured_log_explorer_schema() -> Value {
    serde_json::json!({
        "type":"object",
        "additionalProperties":false,
        "required":["dataset","timestamp_field","start","end","columns","limit","timeout_seconds"],
        "properties":{
            "dataset":{"type":"string","pattern":"^[A-Za-z_][A-Za-z0-9_]{0,63}$"},
            "timestamp_field":{"type":"string","pattern":"^[A-Za-z_][A-Za-z0-9_]{0,63}$"},
            "start":{"type":"string","format":"date-time"},
            "end":{"type":"string","format":"date-time"},
            "columns":{"type":"array","minItems":1,"maxItems":50,"uniqueItems":true,"items":{"type":"string","pattern":"^[A-Za-z_][A-Za-z0-9_]{0,63}$"}},
            "aggregates":{"type":"array","maxItems":20,"items":{"type":"object","additionalProperties":false,"required":["function","alias"],"properties":{"function":{"type":"string","enum":["count","sum","avg","min","max"]},"field":{"type":"string","pattern":"^[A-Za-z_][A-Za-z0-9_]{0,63}$"},"alias":{"type":"string","pattern":"^[A-Za-z_][A-Za-z0-9_]{0,63}$"}}}},
            "filters":{"type":"array","maxItems":20,"items":{"type":"object","additionalProperties":false,"required":["field","operator","value"],"properties":{"field":{"type":"string","pattern":"^[A-Za-z_][A-Za-z0-9_]{0,63}$"},"operator":{"type":"string","enum":["eq","ne","gt","gte","lt","lte","in","not_in"]},"value":{}}}},
            "group_by":{"type":"array","maxItems":20,"uniqueItems":true,"items":{"type":"string","pattern":"^[A-Za-z_][A-Za-z0-9_]{0,63}$"}},
            "order_by":{"type":"array","maxItems":10,"items":{"type":"object","additionalProperties":false,"required":["field","direction"],"properties":{"field":{"type":"string","pattern":"^[A-Za-z_][A-Za-z0-9_]{0,63}$"},"direction":{"type":"string","enum":["asc","desc"]}}}},
            "limit":{"type":"integer","minimum":1,"maximum":5000},
            "timeout_seconds":{"type":"integer","minimum":1,"maximum":30}
        },
        "x-cfctl-body-required":true
    })
}

fn finalize_telemetry_mutations(snapshot: &mut CatalogSnapshot) {
    finalize_web_analytics_site_lifecycle(snapshot);
    finalize_web_analytics_rule_lifecycle(snapshot);
    finalize_workers_observability_settings(snapshot);
    finalize_worker_tail_lifecycle(snapshot);
    finalize_logpush_lifecycle(snapshot);
    finalize_security_response_lifecycle(snapshot);
    finalize_custom_waf_ruleset_lifecycle(snapshot);
    finalize_waf_security_response_lifecycle(snapshot);
    finalize_rate_limit_lifecycle(snapshot);
    finalize_notification_policy_lifecycle(snapshot);
    finalize_list_container_lifecycle(snapshot);
    finalize_list_member_lifecycle(snapshot);
}

const WORKER_TAIL_CREATE_ID: &str = "worker-tail-logs-start-tail";
const WORKER_TAIL_LIST_ID: &str = "worker-tail-logs-list-tails";
const WORKER_TAIL_DELETE_ID: &str = "worker-tail-logs-delete-tail";
const WORKER_TAIL_COLLECTION_PATH: &str =
    "/accounts/{account_id}/workers/scripts/{script_name}/tails";
const WORKER_TAIL_DETAIL_PATH: &str =
    "/accounts/{account_id}/workers/scripts/{script_name}/tails/{id}";

#[expect(
    clippy::too_many_lines,
    reason = "the bounded Worker tail lifecycle is reviewed as one create, verify, sink, and delete contract"
)]
fn finalize_worker_tail_lifecycle(snapshot: &mut CatalogSnapshot) {
    let identity_ok = snapshot
        .capabilities
        .get(WORKER_TAIL_CREATE_ID)
        .is_some_and(|capability| {
            capability.method == "POST"
                && capability.path == WORKER_TAIL_COLLECTION_PATH
                && capability.request_schema.is_none()
        })
        && snapshot
            .capabilities
            .get(WORKER_TAIL_LIST_ID)
            .is_some_and(|capability| {
                capability.method == "GET"
                    && capability.path == WORKER_TAIL_COLLECTION_PATH
                    && !capability.mutating
            })
        && snapshot
            .capabilities
            .get(WORKER_TAIL_DELETE_ID)
            .is_some_and(|capability| {
                capability.method == "DELETE" && capability.path == WORKER_TAIL_DETAIL_PATH
            });
    if !identity_ok {
        if let Some(capability) = snapshot.capabilities.get_mut(WORKER_TAIL_CREATE_ID) {
            capability.adapter_status = AdapterStatus::Blocked;
            capability.blocked_reason = Some(
                "schema drift: Worker tail create/list/delete no longer matches the governed leased-session lifecycle"
                    .to_owned(),
            );
        }
        return;
    }

    if let Some(capability) = snapshot.capabilities.get_mut(WORKER_TAIL_LIST_ID) {
        capability.permissions = vec!["Workers Tail Read".to_owned()];
        capability.aliases = vec![
            "inspect active Worker tail sessions".to_owned(),
            "Worker log tail leases".to_owned(),
        ];
    }

    if let Some(capability) = snapshot.capabilities.get_mut(WORKER_TAIL_DELETE_ID) {
        capability.permissions = vec![
            "Workers Tail Read".to_owned(),
            "Workers Scripts Write".to_owned(),
        ];
        capability.request_schema = None;
        capability.risk = RiskClass::Destructive;
        capability.effect = EffectClass::Destructive;
        attach_live_read_entitlement_probe(
            capability,
            WORKER_TAIL_LIST_ID,
            WORKER_TAIL_COLLECTION_PATH,
        );
        capability.entitlement.source = Some(
            "https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/tail/"
                .to_owned(),
        );
        zero_cost_mutation(
            capability,
            "ending one exact tail lease has no direct operation charge and stops its bounded log stream",
            official_reference(
                "Workers Tail API",
                "https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/tail/",
            ),
        );
        capability.verification.required = true;
        "parent_collection_omits_deleted_resource_id"
            .clone_into(&mut capability.verification.strategy);
        capability.deleted_resource = Some(DeletedResourceContractV1 {
            collection_path: WORKER_TAIL_COLLECTION_PATH.to_owned(),
            identity_selector: "id".to_owned(),
            response_item_identity_pointer: "/id".to_owned(),
            read_capability_id: WORKER_TAIL_LIST_ID.to_owned(),
            requires_page_number_completion: false,
        });
        capability.rollback.supported = false;
        capability.rollback.strategy = None;
        capability.rollback.warning = Some(
            "ending a tail lease is irreversible for that session; a replacement requires a separately reviewed start-tail plan and yields a new secret URL"
                .to_owned(),
        );
        refresh_dynamic_mutation_contract(capability);
    }

    if let Some(capability) = snapshot.capabilities.get_mut(WORKER_TAIL_CREATE_ID) {
        capability.permissions = vec![
            "Workers Tail Read".to_owned(),
            "Workers Scripts Write".to_owned(),
        ];
        capability.aliases = vec![
            "bounded Worker tail session".to_owned(),
            "tail Worker logs".to_owned(),
            "stream Worker exceptions".to_owned(),
            "inspect Worker invocations live".to_owned(),
        ];
        capability.description = Some(
            "Creates one Cloudflare-expiring Worker tail lease, sinks its bearer WebSocket URL only to a new mode-0600 JSON file, verifies the returned lease ID in the live tail collection, and binds exact deletion as compensation. The URL is never printed or written to evidence."
                .to_owned(),
        );
        capability.risk = RiskClass::SecretSensitive;
        capability.effect = EffectClass::ReversibleWrite;
        attach_live_read_entitlement_probe(
            capability,
            WORKER_TAIL_LIST_ID,
            WORKER_TAIL_COLLECTION_PATH,
        );
        capability.entitlement.source = Some(
            "https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/tail/"
                .to_owned(),
        );
        zero_cost_mutation(
            capability,
            "creating one Cloudflare-expiring tail lease has no direct operation charge; the session is bounded by the upstream expiry and exact-delete compensation",
            official_reference(
                "Workers Tail API",
                "https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/tail/",
            ),
        );
        capability.verification.required = true;
        "worker_tail_collection_contains_created_lease_id"
            .clone_into(&mut capability.verification.strategy);
        capability.created_collection_resource = Some(CreatedCollectionResourceContractV1 {
            collection_path: WORKER_TAIL_COLLECTION_PATH.to_owned(),
            identity_selector: "id".to_owned(),
            response_result_identity_pointer: "/id".to_owned(),
            response_item_identity_pointer: "/id".to_owned(),
            read_capability_id: WORKER_TAIL_LIST_ID.to_owned(),
            delete_capability_id: WORKER_TAIL_DELETE_ID.to_owned(),
            verified_response_fields: Vec::new(),
            requires_page_number_completion: false,
        });
        capability.rollback.supported = true;
        capability.rollback.strategy = Some("delete_created_resource_by_returned_id".to_owned());
        capability.rollback.warning = Some(
            "compensation creates a separate exact tail-delete plan from the returned lease ID; the secret URL remains sink-only"
                .to_owned(),
        );
        refresh_dynamic_mutation_contract(capability);
    }
}

const CUSTOM_WAF_RULESET_SOURCE_CREATE_ID: &str = "createZoneRuleset";
const CUSTOM_WAF_RULESET_CREATE_ID: &str = "security-response-create-empty-custom-ruleset";
const CUSTOM_WAF_RULESET_LIST_ID: &str = "listZoneRulesets";
const CUSTOM_WAF_RULESET_READ_ID: &str = "getZoneRuleset";
const CUSTOM_WAF_RULESET_DELETE_ID: &str = "deleteZoneRuleset";
const CUSTOM_WAF_RULESET_COLLECTION_PATH: &str = "/zones/{zone_id}/rulesets";
const CUSTOM_WAF_RULESET_DETAIL_PATH: &str = "/zones/{zone_id}/rulesets/{ruleset_id}";

fn empty_custom_waf_ruleset_schema() -> Value {
    serde_json::json!({
        "type":"object",
        "additionalProperties":false,
        "required":["description","kind","name","phase","rules"],
        "properties":{
            "description":{"type":"string","maxLength":500},
            "kind":{"type":"string","const":"custom"},
            "name":{"type":"string","minLength":1,"maxLength":100},
            "phase":{"type":"string","const":"http_request_firewall_custom"},
            "rules":{"type":"array","maxItems":0,"items":{}}
        },
        "x-cfctl-body-required":true
    })
}

#[expect(
    clippy::too_many_lines,
    reason = "the safe empty-ruleset create and exact delete lifecycle is one auditable overlay"
)]
fn finalize_custom_waf_ruleset_lifecycle(snapshot: &mut CatalogSnapshot) {
    let identity_ok = snapshot
        .capabilities
        .get(CUSTOM_WAF_RULESET_SOURCE_CREATE_ID)
        .is_some_and(|capability| {
            capability.method == "POST" && capability.path == CUSTOM_WAF_RULESET_COLLECTION_PATH
        })
        && snapshot
            .capabilities
            .get(CUSTOM_WAF_RULESET_LIST_ID)
            .is_some_and(|capability| {
                capability.method == "GET"
                    && capability.path == CUSTOM_WAF_RULESET_COLLECTION_PATH
                    && !capability.mutating
            })
        && snapshot
            .capabilities
            .get(CUSTOM_WAF_RULESET_READ_ID)
            .is_some_and(|capability| {
                capability.method == "GET"
                    && capability.path == CUSTOM_WAF_RULESET_DETAIL_PATH
                    && !capability.mutating
            })
        && snapshot
            .capabilities
            .get(CUSTOM_WAF_RULESET_DELETE_ID)
            .is_some_and(|capability| {
                capability.method == "DELETE" && capability.path == CUSTOM_WAF_RULESET_DETAIL_PATH
            });
    if !identity_ok {
        return;
    }

    if let Some(capability) = snapshot.capabilities.get_mut(CUSTOM_WAF_RULESET_DELETE_ID) {
        capability.permissions = vec!["Zone WAF Read".to_owned(), "Zone WAF Write".to_owned()];
        capability.request_schema = None;
        capability.risk = RiskClass::Destructive;
        capability.effect = EffectClass::Destructive;
        attach_live_read_entitlement_probe(
            capability,
            CUSTOM_WAF_RULESET_LIST_ID,
            CUSTOM_WAF_RULESET_COLLECTION_PATH,
        );
        capability.entitlement.source = Some(
            "https://developers.cloudflare.com/ruleset-engine/rulesets-api/delete/".to_owned(),
        );
        zero_cost_mutation(
            capability,
            "deleting one exact ruleset has no direct operation charge; the removed configuration cannot be reconstructed without its prior snapshot",
            official_reference(
                "Delete a Ruleset Engine ruleset",
                "https://developers.cloudflare.com/ruleset-engine/rulesets-api/delete/",
            ),
        );
        capability.verification.required = true;
        "same_resource_returns_not_found_after_delete"
            .clone_into(&mut capability.verification.strategy);
        capability.same_path_read = Some(SamePathReadContractV1 {
            path: CUSTOM_WAF_RULESET_DETAIL_PATH.to_owned(),
            read_capability_id: CUSTOM_WAF_RULESET_READ_ID.to_owned(),
            verified_response_fields: Vec::new(),
        });
        capability.rollback.supported = false;
        capability.rollback.strategy = None;
        capability.rollback.warning = Some(
            "ruleset deletion is irreversible; capture the complete current ruleset before approval and use create/update operations to reconstruct it if needed"
                .to_owned(),
        );
        refresh_dynamic_mutation_contract(capability);
    }

    if let Some(source) = snapshot
        .capabilities
        .get(CUSTOM_WAF_RULESET_SOURCE_CREATE_ID)
        .cloned()
    {
        let mut capability = source;
        CUSTOM_WAF_RULESET_CREATE_ID.clone_into(&mut capability.id);
        "Create an empty custom WAF ruleset".clone_into(&mut capability.title);
        capability.description = Some(
            "Creates one dormant, empty zone custom ruleset in the fixed http_request_firewall_custom phase. Arbitrary rules, expressions, entry-point kinds, and other phases are rejected; add evidence-bound rules through the typed security-response capability."
                .to_owned(),
        );
        capability.aliases = vec![
            "bootstrap custom WAF ruleset".to_owned(),
            "create empty security ruleset".to_owned(),
            "prepare expiring WAF actions".to_owned(),
        ];
        "cfctl-safe-ruleset-v1+cloudflare-rulesets-api".clone_into(&mut capability.source);
        capability.permissions = vec!["Zone WAF Read".to_owned(), "Zone WAF Write".to_owned()];
        capability.request_schema = Some(empty_custom_waf_ruleset_schema());
        capability.risk = RiskClass::CrossConfig;
        capability.effect = EffectClass::ReversibleWrite;
        attach_live_read_entitlement_probe(
            &mut capability,
            CUSTOM_WAF_RULESET_LIST_ID,
            CUSTOM_WAF_RULESET_COLLECTION_PATH,
        );
        capability.entitlement.source =
            Some("https://developers.cloudflare.com/waf/custom-rulesets/".to_owned());
        zero_cost_mutation(
            &mut capability,
            "creating an empty dormant custom WAF ruleset has no direct operation charge; rule quotas and deployment entitlement remain plan-governed",
            official_reference(
                "Create a Ruleset Engine ruleset",
                "https://developers.cloudflare.com/ruleset-engine/rulesets-api/create/",
            ),
        );
        capability.verification.required = true;
        "created_resource_contains_planned_fields_by_returned_id"
            .clone_into(&mut capability.verification.strategy);
        capability.created_resource = Some(CreatedResourceContractV1 {
            detail_path: CUSTOM_WAF_RULESET_DETAIL_PATH.to_owned(),
            identity_selector: "ruleset_id".to_owned(),
            response_result_identity_pointer: "/id".to_owned(),
            read_capability_id: CUSTOM_WAF_RULESET_READ_ID.to_owned(),
            delete_capability_id: CUSTOM_WAF_RULESET_DELETE_ID.to_owned(),
            verified_response_fields: vec![
                "description".to_owned(),
                "kind".to_owned(),
                "name".to_owned(),
                "phase".to_owned(),
                "rules".to_owned(),
            ],
        });
        capability.rollback.supported = true;
        capability.rollback.strategy = Some("delete_created_resource_by_returned_id".to_owned());
        capability.rollback.warning = Some(
            "rollback is a separate exact-ruleset delete plan derived only from the returned ID; the create contract proves the ruleset was empty"
                .to_owned(),
        );
        capability.adapter_status = AdapterStatus::DynamicApi;
        capability.blocked_reason = None;
        refresh_dynamic_mutation_contract(&mut capability);
        snapshot
            .capabilities
            .insert(CUSTOM_WAF_RULESET_CREATE_ID.to_owned(), capability);
    }

    if let Some(capability) = snapshot
        .capabilities
        .get_mut(CUSTOM_WAF_RULESET_SOURCE_CREATE_ID)
    {
        capability.adapter_status = AdapterStatus::Blocked;
        capability.blocked_reason = Some(
            "blocked by design: arbitrary ruleset kinds, phases, and embedded rules are not a public cfctl surface; use `security-response-create-empty-custom-ruleset` and typed rule capabilities"
                .to_owned(),
        );
    }
}

fn zero_cost_mutation(capability: &mut CapabilityV1, basis: &str, reference: KnowledgeReferenceV1) {
    capability.cost.incremental = false;
    capability.cost.currency = None;
    capability.cost.maximum = Some(0.0);
    capability.cost.known = true;
    capability.cost.billing_model = BillingModelV1::Subscription;
    capability.cost.exposure = CostExposureV1::DownstreamUsage;
    capability.cost.basis = Some(basis.to_owned());
    capability.cost.references = vec![reference];
}

fn attach_live_read_entitlement_probe(
    capability: &mut CapabilityV1,
    capability_id: &str,
    path: &str,
) {
    let mut selector_names = path
        .split('/')
        .filter_map(|segment| {
            segment
                .strip_prefix('{')
                .and_then(|segment| segment.strip_suffix('}'))
        })
        .map(str::to_owned)
        .collect::<Vec<_>>();
    selector_names.sort();
    selector_names.dedup();
    capability.entitlement.available = None;
    capability.entitlement.blocker = None;
    capability.entitlement.requires_live_resolution = true;
    capability.entitlement.observed_plan = None;
    capability.entitlement.probe = Some(EntitlementProbeV1 {
        capability_id: capability_id.to_owned(),
        path: path.to_owned(),
        selector_names,
    });
}

#[expect(
    clippy::too_many_lines,
    reason = "Web Analytics create, update, verify, and delete contracts are intentionally co-located"
)]
fn finalize_web_analytics_site_lifecycle(snapshot: &mut CatalogSnapshot) {
    const CREATE: &str = "web-analytics-create-site";
    const READ: &str = "web-analytics-get-site";
    const UPDATE: &str = "web-analytics-update-site";
    const DELETE: &str = "web-analytics-delete-site";
    const COLLECTION: &str = "/accounts/{account_id}/rum/site_info";
    const DETAIL: &str = "/accounts/{account_id}/rum/site_info/{site_id}";
    let identity_ok = snapshot.capabilities.get(CREATE).is_some_and(|capability| {
        capability.method == "POST"
            && capability.path == COLLECTION
            && capability.permissions == ["Account Settings Write"]
    }) && snapshot.capabilities.get(READ).is_some_and(|capability| {
        capability.method == "GET" && capability.path == DETAIL && !capability.mutating
    }) && snapshot
        .capabilities
        .get(UPDATE)
        .is_some_and(|capability| capability.method == "PUT" && capability.path == DETAIL)
        && snapshot
            .capabilities
            .get(DELETE)
            .is_some_and(|capability| capability.method == "DELETE" && capability.path == DETAIL);
    if !identity_ok {
        for id in [CREATE, UPDATE] {
            if let Some(capability) = snapshot.capabilities.get_mut(id) {
                capability.adapter_status = AdapterStatus::Blocked;
                capability.blocked_reason = Some(
                    "schema drift: Web Analytics site lifecycle no longer matches the governed create/read/update/delete contract"
                        .to_owned(),
                );
            }
        }
        return;
    }

    if let Some(capability) = snapshot.capabilities.get_mut(CREATE) {
        capability.aliases = vec![
            "create Web Analytics site".to_owned(),
            "bootstrap browser analytics".to_owned(),
            "configure RUM site".to_owned(),
        ];
        capability.request_schema = Some(serde_json::json!({
            "type":"object",
            "additionalProperties":false,
            "required":["host"],
            "properties":{
                "auto_install":{"type":"boolean"},
                "host":{"type":"string","minLength":1,"maxLength":253,"pattern":"^[A-Za-z0-9.-]+$"},
                "zone_tag":{"type":"string","minLength":32,"maxLength":32}
            },
            "x-cfctl-body-required":true
        }));
        capability.risk = RiskClass::ScopedWrite;
        capability.effect = EffectClass::ReversibleWrite;
        capability.entitlement.available = Some(true);
        zero_cost_mutation(
            capability,
            "creating the site has no direct operation charge; Web Analytics retention and volume remain plan-governed",
            official_reference(
                "Web Analytics configuration API",
                "https://developers.cloudflare.com/api/resources/rum/subresources/site_info/methods/create/",
            ),
        );
        capability.verification.required = true;
        "created_resource_contains_planned_fields_by_returned_id"
            .clone_into(&mut capability.verification.strategy);
        capability.created_resource = Some(CreatedResourceContractV1 {
            detail_path: DETAIL.to_owned(),
            identity_selector: "site_id".to_owned(),
            response_result_identity_pointer: "/site_tag".to_owned(),
            read_capability_id: READ.to_owned(),
            delete_capability_id: DELETE.to_owned(),
            verified_response_fields: vec![
                "auto_install".to_owned(),
                "host".to_owned(),
                "zone_tag".to_owned(),
            ],
        });
        capability.rollback.supported = true;
        capability.rollback.strategy = Some("delete_created_resource_by_returned_id".to_owned());
        capability.rollback.warning = Some(
            "rollback is a separate exact-site delete plan; deleting the site invalidates its token and snippet"
                .to_owned(),
        );
        refresh_dynamic_mutation_contract(capability);
    }

    if let Some(capability) = snapshot.capabilities.get_mut(UPDATE) {
        if let Some(schema) = capability
            .request_schema
            .as_mut()
            .and_then(Value::as_object_mut)
        {
            schema.insert("additionalProperties".to_owned(), Value::Bool(false));
            schema.insert("minProperties".to_owned(), Value::from(1));
        }
        capability.aliases = vec![
            "update Web Analytics site".to_owned(),
            "enable disable Web Analytics".to_owned(),
            "configure browser insights".to_owned(),
        ];
        capability.risk = RiskClass::ScopedWrite;
        capability.effect = EffectClass::ReversibleWrite;
        capability.entitlement.available = Some(true);
        zero_cost_mutation(
            capability,
            "updating site collection and RUM settings has no direct operation charge; downstream analytics volume remains plan-governed",
            official_reference(
                "Web Analytics site update API",
                "https://developers.cloudflare.com/api/resources/rum/subresources/site_info/methods/update/",
            ),
        );
        capability.verification.required = true;
        "same_resource_contains_planned_fields_after_update"
            .clone_into(&mut capability.verification.strategy);
        capability.same_path_read = Some(SamePathReadContractV1 {
            path: DETAIL.to_owned(),
            read_capability_id: READ.to_owned(),
            verified_response_fields: vec![
                "auto_install".to_owned(),
                "enabled".to_owned(),
                "host".to_owned(),
                "lite".to_owned(),
                "zone_tag".to_owned(),
            ],
        });
        capability.rollback.supported = true;
        capability.rollback.strategy = Some("restore_same_path_prior_snapshot".to_owned());
        capability.rollback.warning = Some(
            "cfctl captures and rechecks the exact site state before applying; rollback is a separately reviewed restoration plan"
                .to_owned(),
        );
        refresh_dynamic_mutation_contract(capability);
    }

    if let Some(capability) = snapshot.capabilities.get_mut(DELETE) {
        capability.aliases = vec![
            "delete Web Analytics site".to_owned(),
            "remove RUM site".to_owned(),
        ];
        capability.risk = RiskClass::Destructive;
        capability.effect = EffectClass::Destructive;
        capability.entitlement.available = Some(true);
        zero_cost_mutation(
            capability,
            "deleting a Web Analytics site has no direct operation charge",
            official_reference(
                "Web Analytics site delete API",
                "https://developers.cloudflare.com/api/resources/rum/subresources/site_info/methods/delete/",
            ),
        );
        capability.verification.required = true;
        "same_resource_returns_not_found_after_delete"
            .clone_into(&mut capability.verification.strategy);
        capability.same_path_read = Some(SamePathReadContractV1 {
            path: DETAIL.to_owned(),
            read_capability_id: READ.to_owned(),
            verified_response_fields: Vec::new(),
        });
        capability.rollback.supported = false;
        capability.rollback.strategy = None;
        capability.rollback.warning = Some(
            "site deletion is irreversible because recreation issues new site identity and snippet material"
                .to_owned(),
        );
        refresh_dynamic_mutation_contract(capability);
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "Web Analytics rule create and exact delete contracts are intentionally co-located"
)]
fn finalize_web_analytics_rule_lifecycle(snapshot: &mut CatalogSnapshot) {
    const CREATE: &str = "web-analytics-create-rule";
    const LIST: &str = "web-analytics-list-rules";
    const UPDATE: &str = "web-analytics-update-rule";
    const BULK_UPDATE: &str = "web-analytics-modify-rules";
    const DELETE: &str = "web-analytics-delete-rule";
    const CREATE_PATH: &str = "/accounts/{account_id}/rum/v2/{ruleset_id}/rule";
    const LIST_PATH: &str = "/accounts/{account_id}/rum/v2/{ruleset_id}/rules";
    const DETAIL_PATH: &str = "/accounts/{account_id}/rum/v2/{ruleset_id}/rule/{rule_id}";
    let identity_ok =
        snapshot.capabilities.get(CREATE).is_some_and(|capability| {
            capability.method == "POST" && capability.path == CREATE_PATH
        }) && snapshot.capabilities.get(LIST).is_some_and(|capability| {
            capability.method == "GET" && capability.path == LIST_PATH && !capability.mutating
        }) && snapshot.capabilities.get(DELETE).is_some_and(|capability| {
            capability.method == "DELETE" && capability.path == DETAIL_PATH
        });
    if !identity_ok {
        if let Some(capability) = snapshot.capabilities.get_mut(CREATE) {
            capability.adapter_status = AdapterStatus::Blocked;
            capability.blocked_reason = Some(
                "schema drift: Web Analytics rule create/list/delete no longer matches the governed lifecycle"
                    .to_owned(),
            );
        }
        return;
    }

    if let Some(capability) = snapshot.capabilities.get_mut(LIST) {
        capability.permissions = vec!["Account Settings Read".to_owned()];
        capability.aliases = vec![
            "list Web Analytics rules".to_owned(),
            "inspect RUM include exclude rules".to_owned(),
        ];
    }

    if let Some(capability) = snapshot.capabilities.get_mut(CREATE) {
        capability.permissions = vec![
            "Account Settings Read".to_owned(),
            "Account Settings Write".to_owned(),
        ];
        capability.aliases = vec![
            "create Web Analytics rule".to_owned(),
            "configure RUM host path collection rule".to_owned(),
            "include exclude browser analytics traffic".to_owned(),
        ];
        capability.request_schema = Some(serde_json::json!({
            "type":"object",
            "additionalProperties":false,
            "required":["host","inclusive","paths"],
            "properties":{
                "host":{"type":"string","minLength":1,"maxLength":253,"pattern":"^[A-Za-z0-9.*-]+$"},
                "inclusive":{"type":"boolean"},
                "is_paused":{"type":"boolean"},
                "paths":{"type":"array","minItems":1,"maxItems":50,"uniqueItems":true,"items":{"type":"string","minLength":1,"maxLength":2048}}
            },
            "x-cfctl-body-required":true
        }));
        capability.risk = RiskClass::ScopedWrite;
        capability.effect = EffectClass::ReversibleWrite;
        attach_live_read_entitlement_probe(capability, LIST, LIST_PATH);
        zero_cost_mutation(
            capability,
            "creating a Web Analytics collection rule has no direct operation charge; it changes which browser measurements are collected",
            official_reference(
                "Create Web Analytics rule",
                "https://developers.cloudflare.com/api/resources/rum/subresources/rules/methods/create/",
            ),
        );
        capability.verification.required = true;
        "web_analytics_rule_list_contains_created_id_and_planned_fields"
            .clone_into(&mut capability.verification.strategy);
        capability.created_resource = Some(CreatedResourceContractV1 {
            detail_path: DETAIL_PATH.to_owned(),
            identity_selector: "rule_id".to_owned(),
            response_result_identity_pointer: "/id".to_owned(),
            read_capability_id: LIST.to_owned(),
            delete_capability_id: DELETE.to_owned(),
            verified_response_fields: vec![
                "host".to_owned(),
                "inclusive".to_owned(),
                "is_paused".to_owned(),
                "paths".to_owned(),
            ],
        });
        capability.rollback.supported = true;
        capability.rollback.strategy = Some("delete_created_resource_by_returned_id".to_owned());
        capability.rollback.warning = Some(
            "rollback is a separately approved exact-rule delete and cannot retract browser measurements already collected"
                .to_owned(),
        );
        capability.adapter_status = AdapterStatus::DynamicApi;
        capability.blocked_reason = None;
        refresh_dynamic_mutation_contract(capability);
    }

    if let Some(capability) = snapshot.capabilities.get_mut(DELETE) {
        capability.permissions = vec![
            "Account Settings Read".to_owned(),
            "Account Settings Write".to_owned(),
        ];
        capability.aliases = vec![
            "delete Web Analytics rule".to_owned(),
            "remove RUM host path rule".to_owned(),
        ];
        capability.risk = RiskClass::Destructive;
        capability.effect = EffectClass::Destructive;
        attach_live_read_entitlement_probe(capability, LIST, LIST_PATH);
        zero_cost_mutation(
            capability,
            "deleting one exact Web Analytics rule has no direct operation charge",
            official_reference(
                "Delete Web Analytics rule",
                "https://developers.cloudflare.com/api/resources/rum/subresources/rules/methods/delete/",
            ),
        );
        capability.verification.required = true;
        "web_analytics_rule_list_omits_deleted_id"
            .clone_into(&mut capability.verification.strategy);
        capability.same_path_read = Some(SamePathReadContractV1 {
            path: LIST_PATH.to_owned(),
            read_capability_id: LIST.to_owned(),
            verified_response_fields: Vec::new(),
        });
        capability.rollback.supported = false;
        capability.rollback.strategy = None;
        capability.rollback.warning = Some(
            "rule deletion cannot restore the original identity; recreation requires a separately reviewed plan"
                .to_owned(),
        );
        capability.adapter_status = AdapterStatus::DynamicApi;
        capability.blocked_reason = None;
        refresh_dynamic_mutation_contract(capability);
    }

    for id in [UPDATE, BULK_UPDATE] {
        if let Some(capability) = snapshot.capabilities.get_mut(id) {
            capability.adapter_status = AdapterStatus::Blocked;
            capability.blocked_reason = Some(
                "blocked by design: in-place Web Analytics rule replacement has no exact item read for a hash-bound prior-state snapshot; use the governed exact delete and create lifecycle"
                    .to_owned(),
            );
        }
    }
}

fn workers_observability_settings_schema() -> Value {
    serde_json::json!({
        "type":"object",
        "additionalProperties":false,
        "required":["observability"],
        "properties":{
            "observability":{
                "type":"object",
                "additionalProperties":false,
                "required":["enabled"],
                "properties":{
                    "enabled":{"type":"boolean"},
                    "head_sampling_rate":{"type":"number","minimum":0,"maximum":1},
                    "logs":{
                        "type":"object",
                        "additionalProperties":false,
                        "required":["enabled","invocation_logs"],
                        "properties":{
                            "enabled":{"type":"boolean"},
                            "invocation_logs":{"type":"boolean"},
                            "persist":{"type":"boolean"},
                            "head_sampling_rate":{"type":"number","minimum":0,"maximum":1},
                            "destinations":{"type":"array","maxItems":10,"uniqueItems":true,"items":{"type":"string","minLength":1,"maxLength":128}}
                        }
                    },
                    "traces":{
                        "type":"object",
                        "additionalProperties":false,
                        "properties":{
                            "enabled":{"type":"boolean"},
                            "persist":{"type":"boolean"},
                            "head_sampling_rate":{"type":"number","minimum":0,"maximum":1},
                            "propagation_policy":{"type":"string","enum":["authenticated","accept"]},
                            "destinations":{"type":"array","maxItems":10,"uniqueItems":true,"items":{"type":"string","minLength":1,"maxLength":128}}
                        }
                    }
                }
            }
        },
        "x-cfctl-body-required":true
    })
}

fn finalize_workers_observability_settings(snapshot: &mut CatalogSnapshot) {
    const SOURCE: &str = "worker-script-settings-patch-settings";
    const READ: &str = "worker-script-settings-get-settings";
    const ID: &str = "workers-observability-settings-update";
    const PATH: &str = "/accounts/{account_id}/workers/scripts/{script_name}/script-settings";
    let Some(source) = snapshot.capabilities.get(SOURCE).cloned() else {
        return;
    };
    let identity_ok = source.method == "PATCH"
        && source.path == PATH
        && source.permissions == ["Workers Scripts Write"]
        && snapshot.capabilities.get(READ).is_some_and(|capability| {
            capability.method == "GET" && capability.path == PATH && !capability.mutating
        });
    if !identity_ok {
        let mut blocked = source;
        ID.clone_into(&mut blocked.id);
        blocked.adapter_status = AdapterStatus::Blocked;
        blocked.blocked_reason = Some(
            "schema drift: Workers script observability no longer matches the governed settings read/write pair"
                .to_owned(),
        );
        snapshot.capabilities.insert(ID.to_owned(), blocked);
        return;
    }
    let mut capability = source;
    ID.clone_into(&mut capability.id);
    "Update bounded Workers observability and trace settings".clone_into(&mut capability.title);
    capability.description = Some(
        "Configures only the observability subtree with bounded sampling and destination counts; bindings, tags, and tail consumers remain outside this capability."
            .to_owned(),
    );
    capability.aliases = vec![
        "configure Workers logs traces sampling".to_owned(),
        "enable Worker observability".to_owned(),
        "automatic traces invocation logs".to_owned(),
    ];
    capability.request_schema = Some(workers_observability_settings_schema());
    capability.risk = RiskClass::ScopedWrite;
    capability.effect = EffectClass::ReversibleWrite;
    zero_cost_mutation(
        &mut capability,
        "the settings update has no direct operation charge; log ingestion, retention, and destination usage remain governed by the Workers plan",
        official_reference(
            "Workers observability settings API",
            "https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/script_settings/methods/edit/",
        ),
    );
    capability.verification.required = true;
    "same_path_result_contains_planned_fields_after_update"
        .clone_into(&mut capability.verification.strategy);
    capability.same_path_read = Some(SamePathReadContractV1 {
        path: PATH.to_owned(),
        read_capability_id: READ.to_owned(),
        verified_response_fields: vec!["observability".to_owned()],
    });
    capability.rollback.supported = true;
    capability.rollback.strategy = Some("restore_same_path_prior_snapshot".to_owned());
    capability.rollback.warning = Some(
        "cfctl captures and rechecks the exact observability subtree before applying; rollback is a separately reviewed restoration plan"
            .to_owned(),
    );
    capability.adapter_status = AdapterStatus::DynamicApi;
    capability.blocked_reason = None;
    refresh_dynamic_mutation_contract(&mut capability);
    snapshot.capabilities.insert(ID.to_owned(), capability);
}

struct LogpushLifecycleSpec<'a> {
    scope: &'a str,
    collection_path: &'a str,
    detail_path: &'a str,
    list_id: &'a str,
    create_id: &'a str,
    read_id: &'a str,
    update_id: &'a str,
    safe_update_id: &'a str,
    delete_id: &'a str,
}

fn finalize_logpush_lifecycle(snapshot: &mut CatalogSnapshot) {
    for spec in [
        LogpushLifecycleSpec {
            scope: "zone",
            collection_path: "/zones/{zone_id}/logpush/jobs",
            detail_path: "/zones/{zone_id}/logpush/jobs/{job_id}",
            list_id: "get-zones-zone_id-logpush-jobs",
            create_id: "post-zones-zone_id-logpush-jobs",
            read_id: "get-zones-zone_id-logpush-jobs-job_id",
            update_id: "put-zones-zone_id-logpush-jobs-job_id",
            safe_update_id: "logpush-zone-job-settings-update",
            delete_id: "delete-zones-zone_id-logpush-jobs-job_id",
        },
        LogpushLifecycleSpec {
            scope: "account",
            collection_path: "/accounts/{account_id}/logpush/jobs",
            detail_path: "/accounts/{account_id}/logpush/jobs/{job_id}",
            list_id: "get-accounts-account_id-logpush-jobs",
            create_id: "post-accounts-account_id-logpush-jobs",
            read_id: "get-accounts-account_id-logpush-jobs-job_id",
            update_id: "put-accounts-account_id-logpush-jobs-job_id",
            safe_update_id: "logpush-account-job-settings-update",
            delete_id: "delete-accounts-account_id-logpush-jobs-job_id",
        },
    ] {
        finalize_one_logpush_lifecycle(snapshot, &spec);
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one parameterized Logpush family overlay keeps create, safe update, verification, and delete symmetric"
)]
fn finalize_one_logpush_lifecycle(snapshot: &mut CatalogSnapshot, spec: &LogpushLifecycleSpec<'_>) {
    let identity_ok = snapshot
        .capabilities
        .get(spec.create_id)
        .is_some_and(|capability| {
            capability.method == "POST"
                && capability.path == spec.collection_path
                && capability.permissions == ["Logs Write"]
        })
        && snapshot
            .capabilities
            .get(spec.list_id)
            .is_some_and(|capability| {
                capability.method == "GET"
                    && capability.path == spec.collection_path
                    && !capability.mutating
            })
        && snapshot
            .capabilities
            .get(spec.read_id)
            .is_some_and(|capability| {
                capability.method == "GET"
                    && capability.path == spec.detail_path
                    && !capability.mutating
            })
        && snapshot
            .capabilities
            .get(spec.update_id)
            .is_some_and(|capability| {
                capability.method == "PUT" && capability.path == spec.detail_path
            })
        && snapshot
            .capabilities
            .get(spec.delete_id)
            .is_some_and(|capability| {
                capability.method == "DELETE" && capability.path == spec.detail_path
            });
    if !identity_ok {
        if let Some(source) = snapshot.capabilities.get(spec.update_id).cloned() {
            let mut blocked = source;
            spec.safe_update_id.clone_into(&mut blocked.id);
            blocked.adapter_status = AdapterStatus::Blocked;
            blocked.blocked_reason = Some(format!(
                "schema drift: {} Logpush lifecycle no longer matches the governed create/read/update/delete contract",
                spec.scope
            ));
            snapshot
                .capabilities
                .insert(spec.safe_update_id.to_owned(), blocked);
        }
        return;
    }

    if let Some(capability) = snapshot.capabilities.get_mut(spec.list_id) {
        capability.permissions = vec!["Logs Read".to_owned()];
    }

    if let Some(capability) = snapshot.capabilities.get_mut(spec.create_id) {
        harden_logpush_create_schema(capability.request_schema.as_mut());
        capability.aliases = vec![
            format!("create {} Logpush pipeline", spec.scope),
            "deliver logs to R2 or external destination".to_owned(),
            "configure Logpush fields filters sampling health".to_owned(),
        ];
        capability.risk = RiskClass::ExternalCommunication;
        capability.effect = EffectClass::ExternalCommunication;
        capability.permissions = vec!["Logs Read".to_owned(), "Logs Write".to_owned()];
        attach_live_read_entitlement_probe(capability, spec.list_id, spec.collection_path);
        zero_cost_mutation(
            capability,
            "creating the control-plane job has no direct operation charge; destination storage, egress, and subscribed Logpush usage remain downstream cost exposure",
            official_reference(
                "Create Logpush job",
                "https://developers.cloudflare.com/api/resources/logpush/subresources/jobs/methods/create/",
            ),
        );
        capability.verification.required = true;
        "created_resource_contains_planned_fields_by_returned_id"
            .clone_into(&mut capability.verification.strategy);
        let verified_response_fields = capability
            .verifiable_request_object_fields()
            .unwrap_or_default();
        capability.created_resource = Some(CreatedResourceContractV1 {
            detail_path: spec.detail_path.to_owned(),
            identity_selector: "job_id".to_owned(),
            response_result_identity_pointer: "/id".to_owned(),
            read_capability_id: spec.read_id.to_owned(),
            delete_capability_id: spec.delete_id.to_owned(),
            verified_response_fields,
        });
        capability.rollback.supported = true;
        capability.rollback.strategy = Some("delete_created_resource_by_returned_id".to_owned());
        capability.rollback.warning = Some(
            "rollback is a separate exact-job delete plan and does not remove objects already delivered to the destination"
                .to_owned(),
        );
        capability.adapter_status = AdapterStatus::DynamicApi;
        capability.blocked_reason = None;
        refresh_dynamic_mutation_contract(capability);
    }

    let source_update = snapshot.capabilities.get(spec.update_id).cloned();
    if let Some(mut capability) = source_update {
        spec.safe_update_id.clone_into(&mut capability.id);
        capability.title = format!("Update bounded {} Logpush job settings", spec.scope);
        capability.description = Some(
            "Updates enablement, filtering, batching, field selection, formatting, and sampling on one exact Logpush job. Destination credentials and ownership challenges are excluded; change those through a replacement pipeline so secrets never enter a plan receipt."
                .to_owned(),
        );
        capability.aliases = vec![
            format!("update {} Logpush job", spec.scope),
            "configure Logpush sampling fields filters".to_owned(),
            "enable disable Logpush pipeline".to_owned(),
        ];
        harden_logpush_safe_update_schema(capability.request_schema.as_mut());
        capability.risk = RiskClass::ExternalCommunication;
        capability.effect = EffectClass::ReversibleWrite;
        capability.permissions = vec!["Logs Read".to_owned(), "Logs Write".to_owned()];
        attach_live_read_entitlement_probe(&mut capability, spec.list_id, spec.collection_path);
        zero_cost_mutation(
            &mut capability,
            "updating the control-plane job has no direct operation charge; changed sampling and delivery volume can alter downstream storage and egress usage",
            official_reference(
                "Update Logpush job",
                "https://developers.cloudflare.com/api/resources/logpush/subresources/jobs/methods/update/",
            ),
        );
        capability.verification.required = true;
        "same_resource_contains_planned_fields_after_update"
            .clone_into(&mut capability.verification.strategy);
        capability.same_path_read = Some(SamePathReadContractV1 {
            path: spec.detail_path.to_owned(),
            read_capability_id: spec.read_id.to_owned(),
            verified_response_fields: capability
                .verifiable_request_object_fields()
                .unwrap_or_default(),
        });
        capability.rollback.supported = true;
        capability.rollback.strategy = Some("restore_same_path_prior_snapshot".to_owned());
        capability.rollback.warning = Some(
            "cfctl captures and rechecks every writable job setting before applying; rollback is a separately reviewed restoration plan and cannot retract delivered logs"
                .to_owned(),
        );
        capability.adapter_status = AdapterStatus::DynamicApi;
        capability.blocked_reason = None;
        refresh_dynamic_mutation_contract(&mut capability);
        snapshot
            .capabilities
            .insert(spec.safe_update_id.to_owned(), capability);
    }

    if let Some(capability) = snapshot.capabilities.get_mut(spec.update_id) {
        capability.adapter_status = AdapterStatus::Blocked;
        capability.blocked_reason = Some(
            "blocked by design: the upstream PUT can replace secret-bearing destination configuration, but cfctl cannot persist that prior secret in an immutable plan; use the bounded Logpush settings update or create a replacement pipeline"
                .to_owned(),
        );
    }

    if let Some(capability) = snapshot.capabilities.get_mut(spec.delete_id) {
        capability.aliases = vec![
            format!("delete {} Logpush job", spec.scope),
            "remove Logpush pipeline".to_owned(),
        ];
        capability.risk = RiskClass::Destructive;
        capability.effect = EffectClass::Destructive;
        capability.permissions = vec!["Logs Read".to_owned(), "Logs Write".to_owned()];
        attach_live_read_entitlement_probe(capability, spec.list_id, spec.collection_path);
        zero_cost_mutation(
            capability,
            "deleting the control-plane job has no direct operation charge and does not remove logs already delivered",
            official_reference(
                "Delete Logpush job",
                "https://developers.cloudflare.com/api/resources/logpush/subresources/jobs/methods/delete/",
            ),
        );
        capability.verification.required = true;
        "same_resource_returns_not_found_after_delete"
            .clone_into(&mut capability.verification.strategy);
        capability.same_path_read = Some(SamePathReadContractV1 {
            path: spec.detail_path.to_owned(),
            read_capability_id: spec.read_id.to_owned(),
            verified_response_fields: Vec::new(),
        });
        capability.rollback.supported = false;
        capability.rollback.strategy = None;
        capability.rollback.warning = Some(
            "job deletion cannot restore the exact pipeline identity; recreate it through a separately reviewed create plan, and treat already delivered logs as outside rollback"
                .to_owned(),
        );
        capability.adapter_status = AdapterStatus::DynamicApi;
        capability.blocked_reason = None;
        refresh_dynamic_mutation_contract(capability);
    }
}

fn harden_logpush_create_schema(schema: Option<&mut Value>) {
    let Some(root) = schema.and_then(Value::as_object_mut) else {
        return;
    };
    root.insert("additionalProperties".to_owned(), Value::Bool(false));
    root.insert(
        "required".to_owned(),
        serde_json::json!(["dataset", "destination_conf", "enabled"]),
    );
    if let Some(properties) = root.get_mut("properties").and_then(Value::as_object_mut) {
        for field in ["destination_conf", "ownership_challenge"] {
            if let Some(property) = properties.get_mut(field).and_then(Value::as_object_mut) {
                property.insert("writeOnly".to_owned(), Value::Bool(true));
                property.insert(
                    "x-cfctl-verification-observable".to_owned(),
                    Value::Bool(false),
                );
            }
        }
        harden_logpush_output_options(properties);
    }
}

fn harden_logpush_safe_update_schema(schema: Option<&mut Value>) {
    let Some(root) = schema.and_then(Value::as_object_mut) else {
        return;
    };
    root.insert("additionalProperties".to_owned(), Value::Bool(false));
    root.insert("minProperties".to_owned(), Value::from(1));
    if let Some(properties) = root.get_mut("properties").and_then(Value::as_object_mut) {
        properties.remove("destination_conf");
        properties.remove("ownership_challenge");
        harden_logpush_output_options(properties);
    }
}

fn harden_logpush_output_options(properties: &mut serde_json::Map<String, Value>) {
    let Some(output_schema) = properties
        .get_mut("output_options")
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    output_schema.insert("additionalProperties".to_owned(), Value::Bool(false));
    let Some(output) = output_schema
        .get_mut("properties")
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    if let Some(fields) = output.get_mut("field_names").and_then(Value::as_object_mut) {
        fields.insert("minItems".to_owned(), Value::from(1));
        fields.insert("maxItems".to_owned(), Value::from(200));
        fields.insert("uniqueItems".to_owned(), Value::Bool(true));
    }
}

const SECURITY_IP_RULE_CREATE_ID: &str = "security-response-create-expiring-ip-access-rule";
const SECURITY_IP_RULE_REMOVE_ID: &str = "security-response-remove-expired-ip-access-rule";
const SECURITY_IP_RULE_SOURCE_CREATE_ID: &str =
    "ip-access-rules-for-a-zone-create-an-ip-access-rule";
const SECURITY_IP_RULE_LIST_ID: &str = "ip-access-rules-for-a-zone-list-ip-access-rules";
const SECURITY_IP_RULE_DELETE_ID: &str = "ip-access-rules-for-a-zone-delete-an-ip-access-rule";
const SECURITY_IP_RULE_UPDATE_ID: &str = "ip-access-rules-for-a-zone-update-an-ip-access-rule";
const SECURITY_IP_RULE_COLLECTION: &str = "/zones/{zone_id}/firewall/access_rules/rules";
const SECURITY_IP_RULE_DETAIL: &str = "/zones/{zone_id}/firewall/access_rules/rules/{rule_id}";

fn security_ip_rule_wire_schema() -> Value {
    serde_json::json!({
        "type":"object",
        "additionalProperties":false,
        "required":["configuration","mode","notes"],
        "properties":{
            "configuration":{
                "type":"object",
                "additionalProperties":false,
                "required":["target","value"],
                "properties":{
                    "target":{"type":"string","enum":["ip","ip6","ip_range","asn","country"]},
                    "value":{"type":"string","minLength":1,"maxLength":64}
                }
            },
            "mode":{"type":"string","enum":["managed_challenge","block"]},
            "notes":{"type":"string","minLength":1,"maxLength":500}
        },
        "x-cfctl-body-required":true
    })
}

fn security_ip_rule_create_input_schema() -> Value {
    serde_json::json!({
        "type":"object",
        "additionalProperties":false,
        "required":["actor","evidence_ref","reason","target"],
        "properties":{
            "action":{"type":"string","enum":["managed_challenge","block"],"default":"managed_challenge"},
            "actor":{"type":"string","minLength":1,"maxLength":80,"pattern":"^[A-Za-z0-9._:@+ -]+$"},
            "evidence_ref":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},
            "expires_at":{"type":"string","format":"date-time","description":"Defaults to 24 hours from plan creation; maximum seven days."},
            "reason":{"type":"string","minLength":4,"maxLength":160},
            "target":{
                "type":"object",
                "additionalProperties":false,
                "required":["type","value"],
                "properties":{
                    "type":{"type":"string","enum":["ip","ip_range","asn","country"]},
                    "value":{"type":"string","minLength":1,"maxLength":64}
                }
            },
            "operator_ip":{"type":"string","minLength":2,"maxLength":64,"description":"Required for a block so cfctl can reject direct self-blocking."},
            "confirm_broad_scope":{"type":"boolean","description":"Required for ASN and country targets; those targets are managed-challenge only and limited to one hour."},
            "confirm_block":{"type":"boolean","description":"Required for block; permanent blocks are not accepted by this capability."}
        },
        "x-cfctl-body-required":true
    })
}

fn security_ip_rule_remove_input_schema() -> Value {
    serde_json::json!({
        "type":"object",
        "additionalProperties":false,
        "required":["actor","evidence_ref","expires_at","reason","source_operation_id"],
        "properties":{
            "actor":{"type":"string","minLength":1,"maxLength":80,"pattern":"^[A-Za-z0-9._:@+ -]+$"},
            "evidence_ref":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},
            "expires_at":{"type":"string","format":"date-time"},
            "reason":{"type":"string","minLength":4,"maxLength":160},
            "source_operation_id":{"type":"string","minLength":1,"maxLength":80}
        },
        "x-cfctl-body-required":true
    })
}

#[expect(
    clippy::too_many_lines,
    reason = "the evidence-bound IP action and exact expiry removal are one safety lifecycle"
)]
fn finalize_security_response_lifecycle(snapshot: &mut CatalogSnapshot) {
    let identity_ok = snapshot
        .capabilities
        .get(SECURITY_IP_RULE_SOURCE_CREATE_ID)
        .is_some_and(|capability| {
            capability.method == "POST"
                && capability.path == SECURITY_IP_RULE_COLLECTION
                && capability.permissions == ["Firewall Services Write"]
        })
        && snapshot
            .capabilities
            .get(SECURITY_IP_RULE_LIST_ID)
            .is_some_and(|capability| {
                capability.method == "GET"
                    && capability.path == SECURITY_IP_RULE_COLLECTION
                    && !capability.mutating
            })
        && snapshot
            .capabilities
            .get(SECURITY_IP_RULE_DELETE_ID)
            .is_some_and(|capability| {
                capability.method == "DELETE" && capability.path == SECURITY_IP_RULE_DETAIL
            });
    if !identity_ok {
        if let Some(source) = snapshot
            .capabilities
            .get(SECURITY_IP_RULE_SOURCE_CREATE_ID)
            .cloned()
        {
            let mut blocked = source;
            SECURITY_IP_RULE_CREATE_ID.clone_into(&mut blocked.id);
            blocked.adapter_status = AdapterStatus::Blocked;
            blocked.blocked_reason = Some(
                "schema drift: zone IP Access rule create/list/delete no longer matches the evidence-bound security-response lifecycle"
                    .to_owned(),
            );
            snapshot
                .capabilities
                .insert(SECURITY_IP_RULE_CREATE_ID.to_owned(), blocked);
        }
        return;
    }

    if let Some(capability) = snapshot.capabilities.get_mut(SECURITY_IP_RULE_DELETE_ID) {
        // The upstream `cascade` body is optional and is not needed for exact
        // rule deletion. cfctl deliberately exposes the no-cascade subset so
        // compensation and expiry removal share one deterministic wire shape.
        capability.request_schema = None;
        capability.permissions = vec![
            "Firewall Services Read".to_owned(),
            "Firewall Services Write".to_owned(),
        ];
        capability.risk = RiskClass::IdentityOrOwnership;
        capability.effect = EffectClass::Destructive;
        zero_cost_mutation(
            capability,
            "removing an IP Access rule has no direct operation charge",
            official_reference(
                "Delete zone IP Access rule",
                "https://developers.cloudflare.com/api/resources/firewall/subresources/access_rules/subresources/rules/methods/delete/",
            ),
        );
        capability.verification.required = true;
        "parent_collection_omits_deleted_resource_id"
            .clone_into(&mut capability.verification.strategy);
        capability.deleted_resource = Some(DeletedResourceContractV1 {
            collection_path: SECURITY_IP_RULE_COLLECTION.to_owned(),
            identity_selector: "rule_id".to_owned(),
            response_item_identity_pointer: "/id".to_owned(),
            read_capability_id: SECURITY_IP_RULE_LIST_ID.to_owned(),
            requires_page_number_completion: true,
        });
        capability.rollback.supported = false;
        capability.rollback.strategy = None;
        capability.rollback.warning = Some(
            "rule removal restores traffic eligibility but cannot restore the original rule identity; recreation requires a separately reviewed evidence-bound plan"
                .to_owned(),
        );
        capability.adapter_status = AdapterStatus::DynamicApi;
        capability.blocked_reason = None;
        refresh_dynamic_mutation_contract(capability);
    }

    if let Some(source) = snapshot
        .capabilities
        .get(SECURITY_IP_RULE_SOURCE_CREATE_ID)
        .cloned()
    {
        let mut capability = source;
        SECURITY_IP_RULE_CREATE_ID.clone_into(&mut capability.id);
        "Create an evidence-bound expiring zone security action".clone_into(&mut capability.title);
        capability.description = Some(
            "Creates one bounded zone IP Access rule from a normalized IP, prefix, ASN, or country target. cfctl defaults to Managed Challenge, requires a telemetry evidence receipt, records an operator and reason, rejects permanent actions, and hash-binds a removal deadline plus exact delete rollback. Anonymous analytics is never treated as person identity."
                .to_owned(),
        );
        capability.aliases = vec![
            "expiring managed challenge".to_owned(),
            "challenge suspicious source from security events".to_owned(),
            "temporary IP block".to_owned(),
            "telemetry derived enforcement".to_owned(),
            "IP blocking".to_owned(),
        ];
        "cfctl-security-action-v1+cloudflare-api-schemas".clone_into(&mut capability.source);
        capability.permissions = vec![
            "Firewall Services Read".to_owned(),
            "Firewall Services Write".to_owned(),
        ];
        capability.request_schema = Some(security_ip_rule_wire_schema());
        capability.risk = RiskClass::IdentityOrOwnership;
        capability.effect = EffectClass::ReversibleWrite;
        zero_cost_mutation(
            &mut capability,
            "the rule write has no direct operation charge; challenged or blocked traffic can change application behavior and downstream usage",
            official_reference(
                "Create zone IP Access rule",
                "https://developers.cloudflare.com/api/resources/firewall/subresources/access_rules/subresources/rules/methods/create/",
            ),
        );
        capability.verification.required = true;
        "parent_collection_contains_created_resource_id_and_planned_fields"
            .clone_into(&mut capability.verification.strategy);
        capability.created_resource = None;
        capability.created_collection_resource = Some(CreatedCollectionResourceContractV1 {
            collection_path: SECURITY_IP_RULE_COLLECTION.to_owned(),
            identity_selector: "rule_id".to_owned(),
            response_result_identity_pointer: "/id".to_owned(),
            response_item_identity_pointer: "/id".to_owned(),
            read_capability_id: SECURITY_IP_RULE_LIST_ID.to_owned(),
            delete_capability_id: SECURITY_IP_RULE_DELETE_ID.to_owned(),
            verified_response_fields: vec![
                "configuration".to_owned(),
                "mode".to_owned(),
                "notes".to_owned(),
            ],
            requires_page_number_completion: true,
        });
        capability.rollback.supported = true;
        capability.rollback.strategy = Some("delete_created_resource_by_returned_id".to_owned());
        capability.rollback.warning = Some(
            "rollback is a separate exact-rule delete plan derived only from the returned rule ID; cfctl also records the mandatory removal deadline"
                .to_owned(),
        );
        capability.security_action = Some(SecurityActionContractV1 {
            kind: SecurityActionKindV1::CreateExpiring,
            input_schema: security_ip_rule_create_input_schema(),
            default_action: Some("managed_challenge".to_owned()),
            allowed_actions: vec!["managed_challenge".to_owned(), "block".to_owned()],
            allowed_target_types: vec![
                "asn".to_owned(),
                "country".to_owned(),
                "ip".to_owned(),
                "ip_range".to_owned(),
            ],
            default_ttl_seconds: 86_400,
            max_ttl_seconds: 604_800,
            current_state_capability_id: SECURITY_IP_RULE_LIST_ID.to_owned(),
            safety_profile: SecurityActionSafetyProfileV1::TelemetryDerivedStrict,
        });
        capability.adapter_status = AdapterStatus::DynamicApi;
        capability.blocked_reason = None;
        refresh_dynamic_mutation_contract(&mut capability);
        snapshot
            .capabilities
            .insert(SECURITY_IP_RULE_CREATE_ID.to_owned(), capability);
    }

    if let Some(source) = snapshot
        .capabilities
        .get(SECURITY_IP_RULE_DELETE_ID)
        .cloned()
    {
        let mut capability = source;
        SECURITY_IP_RULE_REMOVE_ID.clone_into(&mut capability.id);
        "Remove an expired evidence-bound zone security action".clone_into(&mut capability.title);
        capability.description = Some(
            "Removes one exact IP Access rule only after its cfctl evidence marker and removal deadline are proven against the complete live rule collection."
                .to_owned(),
        );
        capability.aliases = vec![
            "remove expired enforcement action".to_owned(),
            "expire temporary block".to_owned(),
            "rollback managed challenge".to_owned(),
        ];
        "cfctl-security-action-v1+cloudflare-api-schemas".clone_into(&mut capability.source);
        // The upstream delete operation currently declares an optional
        // `cascade` request object. Expiry removal intentionally exposes no
        // such choice: the runtime renders an empty wire body after validating
        // the separate governance schema below. Removing the optional wire
        // schema makes that safe subset explicit and lets the generic
        // collection-absence verifier prove exactly the operation cfctl sends.
        capability.request_schema = None;
        capability.security_action = Some(SecurityActionContractV1 {
            kind: SecurityActionKindV1::RemoveExpired,
            input_schema: security_ip_rule_remove_input_schema(),
            default_action: None,
            allowed_actions: Vec::new(),
            allowed_target_types: Vec::new(),
            default_ttl_seconds: 0,
            max_ttl_seconds: 0,
            current_state_capability_id: SECURITY_IP_RULE_LIST_ID.to_owned(),
            safety_profile: SecurityActionSafetyProfileV1::TelemetryDerivedStrict,
        });
        refresh_dynamic_mutation_contract(&mut capability);
        snapshot
            .capabilities
            .insert(SECURITY_IP_RULE_REMOVE_ID.to_owned(), capability);
    }

    if let Some(capability) = snapshot.capabilities.get_mut(SECURITY_IP_RULE_UPDATE_ID) {
        capability.adapter_status = AdapterStatus::Blocked;
        capability.blocked_reason = Some(
            "blocked by missing cfctl contract: the zone API has no exact rule-detail read for a pre-change snapshot; use the evidence-bound remove and recreate lifecycle instead of an unverifiable in-place update"
                .to_owned(),
        );
    }
}

const WAF_RULE_SOURCE_CREATE_ID: &str = "createZoneRulesetRule";
const WAF_RULE_CREATE_ID: &str = "security-response-create-expiring-waf-rule";
const WAF_RULE_REMOVE_ID: &str = "security-response-remove-expired-waf-rule";
const WAF_RULE_READ_ID: &str = "getZoneRuleset";
const WAF_RULE_DELETE_ID: &str = "deleteZoneRulesetRule";
const WAF_RULE_PARENT_PATH: &str = "/zones/{zone_id}/rulesets/{ruleset_id}";
const WAF_RULE_COLLECTION_PATH: &str = "/zones/{zone_id}/rulesets/{ruleset_id}/rules";
const WAF_RULE_DETAIL_PATH: &str = "/zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}";

fn waf_security_rule_wire_schema() -> Value {
    serde_json::json!({
        "type":"object",
        "additionalProperties":false,
        "required":["action","description","enabled","expression","ref"],
        "properties":{
            "action":{"type":"string","enum":["block","js_challenge","log","managed_challenge","skip"]},
            "action_parameters":{
                "type":"object",
                "additionalProperties":false,
                "required":["phases"],
                "properties":{
                    "phases":{
                        "type":"array",
                        "minItems":1,
                        "maxItems":1,
                        "uniqueItems":true,
                        "items":{"type":"string","enum":["http_request_firewall_managed"]}
                    }
                }
            },
            "description":{"type":"string","minLength":1,"maxLength":500},
            "enabled":{"type":"boolean","const":true},
            "expression":{"type":"string","minLength":1,"maxLength":4096},
            "ref":{"type":"string","pattern":"^cfctl_security_[0-9a-f]{24}$"}
        },
        "x-cfctl-body-required":true
    })
}

fn waf_security_rule_input_schema() -> Value {
    serde_json::json!({
        "type":"object",
        "additionalProperties":false,
        "required":["actor","evidence_ref","reason","target"],
        "properties":{
            "action":{"type":"string","enum":["block","js_challenge","log","managed_challenge","skip"],"default":"managed_challenge"},
            "actor":{"type":"string","minLength":1,"maxLength":80,"pattern":"^[A-Za-z0-9._:@+ -]+$"},
            "evidence_ref":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},
            "expires_at":{"type":"string","format":"date-time","description":"Defaults to 24 hours from plan creation; maximum seven days."},
            "reason":{"type":"string","minLength":4,"maxLength":160},
            "target":{
                "type":"object",
                "additionalProperties":false,
                "required":["type","value"],
                "properties":{
                    "type":{"type":"string","enum":["asn","country","hostname","ip","ip_range","ja4","path"]},
                    "value":{"type":"string","minLength":1,"maxLength":2048}
                }
            },
            "operator_ip":{"type":"string","minLength":2,"maxLength":64,"description":"Required for block so cfctl can reject direct self-blocking for IP targets."},
            "confirm_broad_scope":{"type":"boolean","description":"Required for IP ranges, ASNs, countries, and skip actions after reviewing the blast radius."},
            "confirm_block":{"type":"boolean","description":"Required for block; permanent blocks are rejected."},
            "confirm_skip":{"type":"boolean","description":"Required for skip; cfctl only skips the managed WAF phase and limits the action to one hour."},
            "confirm_enterprise_bot_management":{"type":"boolean","description":"Required for JA4 because Cloudflare documents the field as Enterprise with Bot Management."}
        },
        "x-cfctl-body-required":true
    })
}

#[expect(
    clippy::too_many_lines,
    reason = "the evidence-bound WAF action and exact expiry removal are one safety lifecycle"
)]
fn finalize_waf_security_response_lifecycle(snapshot: &mut CatalogSnapshot) {
    let identity_ok = snapshot
        .capabilities
        .get(WAF_RULE_SOURCE_CREATE_ID)
        .is_some_and(|capability| {
            capability.method == "POST" && capability.path == WAF_RULE_COLLECTION_PATH
        })
        && snapshot
            .capabilities
            .get(WAF_RULE_READ_ID)
            .is_some_and(|capability| {
                capability.method == "GET"
                    && capability.path == WAF_RULE_PARENT_PATH
                    && !capability.mutating
            })
        && snapshot
            .capabilities
            .get(WAF_RULE_DELETE_ID)
            .is_some_and(|capability| {
                capability.method == "DELETE" && capability.path == WAF_RULE_DETAIL_PATH
            });
    if !identity_ok {
        if let Some(source) = snapshot
            .capabilities
            .get(WAF_RULE_SOURCE_CREATE_ID)
            .cloned()
        {
            let mut blocked = source;
            WAF_RULE_CREATE_ID.clone_into(&mut blocked.id);
            blocked.adapter_status = AdapterStatus::Blocked;
            blocked.blocked_reason = Some(
                "schema drift: Ruleset Engine zone rule create/read/delete no longer matches the governed nested-resource lifecycle"
                    .to_owned(),
            );
            snapshot
                .capabilities
                .insert(WAF_RULE_CREATE_ID.to_owned(), blocked);
        }
        return;
    }

    if let Some(capability) = snapshot.capabilities.get_mut(WAF_RULE_DELETE_ID) {
        capability.permissions = vec!["Zone WAF Read".to_owned(), "Zone WAF Write".to_owned()];
        capability.request_schema = None;
        capability.risk = RiskClass::IdentityOrOwnership;
        capability.effect = EffectClass::Destructive;
        zero_cost_mutation(
            capability,
            "deleting one exact custom WAF rule has no direct operation charge; traffic handling changes immediately",
            official_reference(
                "Delete zone ruleset rule",
                "https://developers.cloudflare.com/api/resources/rulesets/subresources/rules/methods/delete/",
            ),
        );
        capability.verification.required = true;
        "parent_object_omits_deleted_nested_resource_id"
            .clone_into(&mut capability.verification.strategy);
        capability.deleted_nested_resource = Some(DeletedNestedResourceContractV1 {
            parent_path: WAF_RULE_PARENT_PATH.to_owned(),
            collection_path: WAF_RULE_COLLECTION_PATH.to_owned(),
            items_pointer: "/rules".to_owned(),
            identity_selector: "rule_id".to_owned(),
            response_item_identity_pointer: "/id".to_owned(),
            read_capability_id: WAF_RULE_READ_ID.to_owned(),
        });
        capability.rollback.supported = false;
        capability.rollback.strategy = None;
        capability.rollback.warning = Some(
            "rule deletion is not identity-reversible; recreation requires a separately reviewed evidence-bound plan"
                .to_owned(),
        );
        capability.adapter_status = AdapterStatus::DynamicApi;
        capability.blocked_reason = None;
        refresh_dynamic_mutation_contract(capability);
    }

    if let Some(source) = snapshot
        .capabilities
        .get(WAF_RULE_SOURCE_CREATE_ID)
        .cloned()
    {
        let mut capability = source;
        WAF_RULE_CREATE_ID.clone_into(&mut capability.id);
        "Create an evidence-bound expiring zone WAF rule".clone_into(&mut capability.title);
        capability.description = Some(
            "Compiles one normalized IP, prefix, ASN, country, hostname, exact path, or JA4 target into a fixed Ruleset Engine expression. Managed Challenge is the default; every action carries evidence, actor, reason, expiry, conflict detection, blast-radius metadata, exact nested-resource verification, and deletion rollback. Raw expressions are never accepted."
                .to_owned(),
        );
        capability.aliases = vec![
            "expiring WAF custom rule".to_owned(),
            "managed challenge hostname path fingerprint".to_owned(),
            "block challenge skip log suspicious source".to_owned(),
            "telemetry derived Ruleset Engine enforcement".to_owned(),
        ];
        "cfctl-security-action-v1+cloudflare-rulesets-api".clone_into(&mut capability.source);
        capability.permissions = vec!["Zone WAF Read".to_owned(), "Zone WAF Write".to_owned()];
        capability.request_schema = Some(waf_security_rule_wire_schema());
        capability.risk = RiskClass::IdentityOrOwnership;
        capability.effect = EffectClass::ReversibleWrite;
        capability.entitlement.available = None;
        capability.entitlement.requires_live_resolution = true;
        capability.entitlement.source =
            Some("https://developers.cloudflare.com/waf/custom-rules/".to_owned());
        zero_cost_mutation(
            &mut capability,
            "the rule write has no direct operation charge; plan rule quotas, Log action, and JA4/Bot Management availability are resolved against live state and Cloudflare entitlement responses",
            official_reference(
                "WAF custom rules availability and limits",
                "https://developers.cloudflare.com/waf/custom-rules/",
            ),
        );
        capability.verification.required = true;
        "parent_object_contains_created_nested_resource_by_correlation"
            .clone_into(&mut capability.verification.strategy);
        capability.created_nested_resource = Some(CreatedNestedResourceContractV1 {
            parent_path: WAF_RULE_PARENT_PATH.to_owned(),
            items_pointer: "/rules".to_owned(),
            identity_selector: "rule_id".to_owned(),
            response_item_identity_pointer: "/id".to_owned(),
            correlation_field: "ref".to_owned(),
            read_capability_id: WAF_RULE_READ_ID.to_owned(),
            delete_capability_id: WAF_RULE_DELETE_ID.to_owned(),
            delete_path: WAF_RULE_DETAIL_PATH.to_owned(),
            verified_response_fields: vec![
                "action".to_owned(),
                "action_parameters".to_owned(),
                "description".to_owned(),
                "enabled".to_owned(),
                "expression".to_owned(),
                "ref".to_owned(),
            ],
        });
        capability.rollback.supported = true;
        capability.rollback.strategy = Some("delete_created_resource_by_returned_id".to_owned());
        capability.rollback.warning = Some(
            "rollback is a separate exact-rule delete plan derived only from the correlated returned rule ID; cfctl also records the mandatory expiry"
                .to_owned(),
        );
        capability.security_action = Some(SecurityActionContractV1 {
            kind: SecurityActionKindV1::CreateExpiring,
            input_schema: waf_security_rule_input_schema(),
            default_action: Some("managed_challenge".to_owned()),
            allowed_actions: vec![
                "block".to_owned(),
                "js_challenge".to_owned(),
                "log".to_owned(),
                "managed_challenge".to_owned(),
                "skip".to_owned(),
            ],
            allowed_target_types: vec![
                "asn".to_owned(),
                "country".to_owned(),
                "hostname".to_owned(),
                "ip".to_owned(),
                "ip_range".to_owned(),
                "ja4".to_owned(),
                "path".to_owned(),
            ],
            default_ttl_seconds: 86_400,
            max_ttl_seconds: 604_800,
            current_state_capability_id: WAF_RULE_READ_ID.to_owned(),
            safety_profile: SecurityActionSafetyProfileV1::TelemetryDerivedStrict,
        });
        capability.adapter_status = AdapterStatus::DynamicApi;
        capability.blocked_reason = None;
        refresh_dynamic_mutation_contract(&mut capability);
        snapshot
            .capabilities
            .insert(WAF_RULE_CREATE_ID.to_owned(), capability);
    }

    if let Some(capability) = snapshot.capabilities.get_mut(WAF_RULE_SOURCE_CREATE_ID) {
        capability.adapter_status = AdapterStatus::Blocked;
        capability.blocked_reason = Some(
            "blocked by design: arbitrary Ruleset Engine rule bodies and expressions are not a public cfctl surface; use `security-response-create-expiring-waf-rule`"
                .to_owned(),
        );
    }

    if let Some(source) = snapshot.capabilities.get(WAF_RULE_DELETE_ID).cloned() {
        let mut capability = source;
        WAF_RULE_REMOVE_ID.clone_into(&mut capability.id);
        "Remove an expired evidence-bound zone WAF rule".clone_into(&mut capability.title);
        capability.description = Some(
            "Removes one exact WAF rule only after its verified cfctl source operation, evidence reference, expiry, and unchanged live rule body are proven."
                .to_owned(),
        );
        capability.aliases = vec![
            "remove expired WAF enforcement".to_owned(),
            "expire managed challenge custom rule".to_owned(),
            "rollback telemetry derived WAF action".to_owned(),
        ];
        capability.security_action = Some(SecurityActionContractV1 {
            kind: SecurityActionKindV1::RemoveExpired,
            input_schema: security_ip_rule_remove_input_schema(),
            default_action: None,
            allowed_actions: Vec::new(),
            allowed_target_types: Vec::new(),
            default_ttl_seconds: 0,
            max_ttl_seconds: 0,
            current_state_capability_id: WAF_RULE_READ_ID.to_owned(),
            safety_profile: SecurityActionSafetyProfileV1::TelemetryDerivedStrict,
        });
        refresh_dynamic_mutation_contract(&mut capability);
        snapshot
            .capabilities
            .insert(WAF_RULE_REMOVE_ID.to_owned(), capability);
    }
}

fn harden_rate_limit_schema(schema: Option<&mut Value>) {
    let Some(root) = schema.and_then(Value::as_object_mut) else {
        return;
    };
    root.insert("additionalProperties".to_owned(), Value::Bool(false));
    let Some(properties) = root.get_mut("properties").and_then(Value::as_object_mut) else {
        return;
    };
    for name in ["action", "match"] {
        if let Some(branches) = properties
            .get_mut(name)
            .and_then(|schema| schema.get_mut(if name == "action" { "anyOf" } else { "oneOf" }))
            .and_then(Value::as_array_mut)
        {
            for branch in branches {
                if let Some(branch) = branch.as_object_mut() {
                    branch.insert("additionalProperties".to_owned(), Value::Bool(false));
                }
            }
        }
    }
    if let Some(threshold) = properties
        .get_mut("threshold")
        .and_then(Value::as_object_mut)
    {
        threshold.insert("maximum".to_owned(), Value::from(1_000_000));
    }
}

fn finalize_rate_limit_lifecycle(snapshot: &mut CatalogSnapshot) {
    const CREATE: &str = "rate-limits-for-a-zone-create-a-rate-limit";
    const READ: &str = "rate-limits-for-a-zone-get-a-rate-limit";
    const UPDATE: &str = "rate-limits-for-a-zone-update-a-rate-limit";
    const DELETE: &str = "rate-limits-for-a-zone-delete-a-rate-limit";
    const COLLECTION: &str = "/zones/{zone_id}/rate_limits";
    const DETAIL: &str = "/zones/{zone_id}/rate_limits/{rate_limit_id}";
    let identity_ok = snapshot.capabilities.get(CREATE).is_some_and(|capability| {
        capability.method == "POST"
            && capability.path == COLLECTION
            && capability.permissions == ["Firewall Services Write"]
    }) && snapshot.capabilities.get(READ).is_some_and(|capability| {
        capability.method == "GET" && capability.path == DETAIL && !capability.mutating
    }) && snapshot
        .capabilities
        .get(UPDATE)
        .is_some_and(|capability| capability.method == "PUT" && capability.path == DETAIL)
        && snapshot
            .capabilities
            .get(DELETE)
            .is_some_and(|capability| capability.method == "DELETE" && capability.path == DETAIL);
    if !identity_ok {
        for id in [CREATE, UPDATE] {
            if let Some(capability) = snapshot.capabilities.get_mut(id) {
                capability.adapter_status = AdapterStatus::Blocked;
                capability.blocked_reason = Some(
                    "schema drift: zone rate-limit create/read/update/delete no longer matches the governed lifecycle"
                        .to_owned(),
                );
            }
        }
        return;
    }

    if let Some(capability) = snapshot.capabilities.get_mut(CREATE) {
        harden_rate_limit_schema(capability.request_schema.as_mut());
        capability.aliases = vec![
            "create rate limiting rule".to_owned(),
            "configure managed challenge rate limit".to_owned(),
            "protect route from request flood".to_owned(),
        ];
        capability.permissions = vec![
            "Firewall Services Read".to_owned(),
            "Firewall Services Write".to_owned(),
        ];
        capability.risk = RiskClass::IdentityOrOwnership;
        capability.effect = EffectClass::ReversibleWrite;
        capability.maturity = Maturity::Deprecated;
        zero_cost_mutation(
            capability,
            "creating the rate-limit configuration has no direct operation charge; enforcement changes request handling and downstream usage",
            official_reference(
                "Create zone rate limit",
                "https://developers.cloudflare.com/api/resources/rate_limits/methods/create/",
            ),
        );
        refresh_dynamic_mutation_contract(capability);
    }

    if let Some(capability) = snapshot.capabilities.get_mut(UPDATE) {
        harden_rate_limit_schema(capability.request_schema.as_mut());
        capability.aliases = vec![
            "update rate limiting rule".to_owned(),
            "change rate-limit threshold period action".to_owned(),
        ];
        capability.permissions = vec![
            "Firewall Services Read".to_owned(),
            "Firewall Services Write".to_owned(),
        ];
        capability.risk = RiskClass::IdentityOrOwnership;
        capability.effect = EffectClass::ReversibleWrite;
        capability.maturity = Maturity::Deprecated;
        zero_cost_mutation(
            capability,
            "updating the rate-limit configuration has no direct operation charge; enforcement changes request handling and downstream usage",
            official_reference(
                "Update zone rate limit",
                "https://developers.cloudflare.com/api/resources/rate_limits/methods/update/",
            ),
        );
        capability.rollback.supported = true;
        capability.rollback.strategy = Some("restore_same_path_prior_snapshot".to_owned());
        capability.rollback.warning = Some(
            "cfctl captures and rechecks the exact rate-limit body before applying; rollback is a separately reviewed restoration plan"
                .to_owned(),
        );
        refresh_dynamic_mutation_contract(capability);
    }
}

fn finalize_notification_policy_lifecycle(snapshot: &mut CatalogSnapshot) {
    const CREATE: &str = "notification-policies-create-a-notification-policy";
    const READ: &str = "notification-policies-get-a-notification-policy";
    const UPDATE: &str = "notification-policies-update-a-notification-policy";
    const DELETE: &str = "notification-policies-delete-a-notification-policy";
    const COLLECTION: &str = "/accounts/{account_id}/alerting/v3/policies";
    const DETAIL: &str = "/accounts/{account_id}/alerting/v3/policies/{policy_id}";
    let accepted_permissions = ["Notifications Write", "Account Settings Write"];
    let identity_ok = snapshot.capabilities.get(CREATE).is_some_and(|capability| {
        capability.method == "POST"
            && capability.path == COLLECTION
            && capability.created_resource.is_some()
            && capability.permissions == accepted_permissions
    }) && snapshot.capabilities.get(READ).is_some_and(|capability| {
        capability.method == "GET" && capability.path == DETAIL && !capability.mutating
    }) && snapshot.capabilities.get(UPDATE).is_some_and(|capability| {
        capability.method == "PUT"
            && capability.path == DETAIL
            && capability.same_path_read.is_some()
    }) && snapshot
        .capabilities
        .get(DELETE)
        .is_some_and(|capability| capability.method == "DELETE" && capability.path == DETAIL);
    if !identity_ok {
        for id in [CREATE, UPDATE] {
            if let Some(capability) = snapshot.capabilities.get_mut(id) {
                capability.adapter_status = AdapterStatus::Blocked;
                capability.blocked_reason = Some(
                    "schema drift: notification policy create/read/update/delete no longer matches the governed external-communication lifecycle"
                        .to_owned(),
                );
            }
        }
        return;
    }
    for id in [CREATE, UPDATE] {
        let Some(capability) = snapshot.capabilities.get_mut(id) else {
            return;
        };
        capability.aliases = vec![
            "security availability alert policy".to_owned(),
            "Logpush health notification".to_owned(),
            "DDoS WAF bot traffic alert".to_owned(),
        ];
        capability.risk = RiskClass::ExternalCommunication;
        capability.effect = EffectClass::ExternalCommunication;
        capability.entitlement.requires_live_resolution = true;
        capability.entitlement.source = Some(
            "https://developers.cloudflare.com/api/resources/alerting/subresources/available_alerts/"
                .to_owned(),
        );
        zero_cost_mutation(
            capability,
            "creating or updating the policy has no direct operation charge; delivery eligibility and destination readiness require live account resolution",
            official_reference(
                "Notification policy API",
                "https://developers.cloudflare.com/api/resources/alerting/subresources/policies/",
            ),
        );
        if id == UPDATE {
            capability.rollback.supported = true;
            capability.rollback.strategy = Some("restore_same_path_prior_snapshot".to_owned());
            capability.rollback.warning = Some(
                "cfctl captures and rechecks the exact policy before sending; rollback is a separately reviewed restoration plan and can itself send or suppress notifications"
                    .to_owned(),
            );
        }
        refresh_dynamic_mutation_contract(capability);
    }
}

fn finalize_list_container_lifecycle(snapshot: &mut CatalogSnapshot) {
    const CREATE: &str = "lists-create-a-list";
    const READ: &str = "lists-get-a-list";
    const UPDATE: &str = "lists-update-a-list";
    const DELETE: &str = "lists-delete-a-list";
    const COLLECTION: &str = "/accounts/{account_id}/rules/lists";
    const DETAIL: &str = "/accounts/{account_id}/rules/lists/{list_id}";
    let identity_ok = snapshot.capabilities.get(CREATE).is_some_and(|capability| {
        capability.method == "POST"
            && capability.path == COLLECTION
            && capability.permissions == ["Account Filter Lists Edit"]
            && capability.created_resource.is_some()
    }) && snapshot.capabilities.get(READ).is_some_and(|capability| {
        capability.method == "GET" && capability.path == DETAIL && !capability.mutating
    }) && snapshot.capabilities.get(UPDATE).is_some_and(|capability| {
        capability.method == "PUT"
            && capability.path == DETAIL
            && capability.same_path_read.is_some()
    }) && snapshot
        .capabilities
        .get(DELETE)
        .is_some_and(|capability| capability.method == "DELETE" && capability.path == DETAIL);
    if !identity_ok {
        for id in [CREATE, UPDATE] {
            if let Some(capability) = snapshot.capabilities.get_mut(id) {
                capability.adapter_status = AdapterStatus::Blocked;
                capability.blocked_reason = Some(
                    "schema drift: Cloudflare List create/read/update/delete no longer matches the governed container lifecycle"
                        .to_owned(),
                );
            }
        }
        return;
    }
    for id in [CREATE, UPDATE] {
        let Some(capability) = snapshot.capabilities.get_mut(id) else {
            return;
        };
        capability.aliases = vec![
            "create governed IP ASN hostname list".to_owned(),
            "manage WAF target list".to_owned(),
            "Cloudflare custom list".to_owned(),
        ];
        capability.risk = RiskClass::ScopedWrite;
        capability.effect = EffectClass::ReversibleWrite;
        zero_cost_mutation(
            capability,
            "the list container has no direct operation charge; member modification quotas and any referencing rules remain separate governed effects",
            official_reference(
                "Lists API limits",
                "https://developers.cloudflare.com/waf/tools/lists/lists-api/",
            ),
        );
        if id == UPDATE {
            capability.rollback.supported = true;
            capability.rollback.strategy = Some("restore_same_path_prior_snapshot".to_owned());
            capability.rollback.warning = Some(
                "cfctl captures and rechecks the exact list metadata before applying; rollback restores only that metadata and never changes members"
                    .to_owned(),
            );
        }
        refresh_dynamic_mutation_contract(capability);
    }
}

const LIST_MEMBER_SOURCE_CREATE_ID: &str = "lists-create-list-items";
const LIST_MEMBER_SOURCE_DELETE_ID: &str = "lists-delete-list-items";
const LIST_MEMBER_CREATE_ID: &str = "security-response-add-expiring-list-member";
const LIST_MEMBER_REMOVE_ID: &str = "security-response-remove-expired-list-member";
const LIST_MEMBER_READ_ID: &str = "lists-get-list-items";
const LIST_METADATA_READ_ID: &str = "lists-get-a-list";
const LIST_BULK_STATUS_ID: &str = "lists-get-bulk-operation-status";
const LIST_MEMBER_COLLECTION: &str = "/accounts/{account_id}/rules/lists/{list_id}/items";
const LIST_METADATA_PATH: &str = "/accounts/{account_id}/rules/lists/{list_id}";
const LIST_BULK_STATUS_PATH: &str =
    "/accounts/{account_id}/rules/lists/bulk_operations/{operation_id}";

fn governed_list_member_wire_schema() -> Value {
    serde_json::json!({
        "type":"array",
        "minItems":1,
        "maxItems":1,
        "items":{
            "oneOf":[
                {
                    "type":"object",
                    "additionalProperties":false,
                    "required":["comment","ip"],
                    "properties":{
                        "comment":{"type":"string","minLength":1,"maxLength":500},
                        "ip":{"type":"string","minLength":2,"maxLength":64}
                    }
                },
                {
                    "type":"object",
                    "additionalProperties":false,
                    "required":["asn","comment"],
                    "properties":{
                        "asn":{"type":"integer","minimum":1,"maximum":4_294_967_295_u64},
                        "comment":{"type":"string","minLength":1,"maxLength":500}
                    }
                },
                {
                    "type":"object",
                    "additionalProperties":false,
                    "required":["comment","hostname"],
                    "properties":{
                        "comment":{"type":"string","minLength":1,"maxLength":500},
                        "hostname":{
                            "type":"object",
                            "additionalProperties":false,
                            "required":["url_hostname"],
                            "properties":{
                                "url_hostname":{"type":"string","minLength":1,"maxLength":253}
                            }
                        }
                    }
                }
            ]
        },
        "x-cfctl-body-required":true
    })
}

fn governed_list_member_delete_wire_schema() -> Value {
    serde_json::json!({
        "type":"object",
        "additionalProperties":false,
        "required":["items"],
        "properties":{
            "items":{
                "type":"array",
                "minItems":1,
                "maxItems":1,
                "items":{
                    "type":"object",
                    "additionalProperties":false,
                    "required":["id"],
                    "properties":{"id":{"type":"string","minLength":32,"maxLength":32}}
                }
            }
        },
        "x-cfctl-body-required":true
    })
}

fn governed_list_member_input_schema() -> Value {
    serde_json::json!({
        "type":"object",
        "additionalProperties":false,
        "required":["actor","confirm_consumer_scope","evidence_ref","reason","target"],
        "properties":{
            "action":{"type":"string","enum":["managed_challenge","block"],"default":"managed_challenge","description":"Expected action of every reviewed consumer; the list itself is neutral data."},
            "actor":{"type":"string","minLength":1,"maxLength":80,"pattern":"^[A-Za-z0-9._:@+ -]+$"},
            "confirm_block":{"type":"boolean"},
            "confirm_broad_scope":{"type":"boolean"},
            "confirm_consumer_scope":{"type":"boolean","description":"Confirms the operator reviewed every rule that consumes this list; cfctl does not infer consumer semantics from the member write."},
            "evidence_ref":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},
            "expires_at":{"type":"string","format":"date-time","description":"Defaults to 24 hours; maximum seven days."},
            "operator_ip":{"type":"string","minLength":2,"maxLength":64},
            "reason":{"type":"string","minLength":4,"maxLength":160},
            "target":{
                "type":"object",
                "additionalProperties":false,
                "required":["type","value"],
                "properties":{
                    "type":{"type":"string","enum":["asn","hostname","ip","ip_range"]},
                    "value":{"type":"string","minLength":1,"maxLength":253}
                }
            }
        },
        "x-cfctl-body-required":true
    })
}

fn governed_list_member_remove_input_schema() -> Value {
    serde_json::json!({
        "type":"object",
        "additionalProperties":false,
        "required":["actor","evidence_ref","expires_at","member_id","reason","source_operation_id"],
        "properties":{
            "actor":{"type":"string","minLength":1,"maxLength":80,"pattern":"^[A-Za-z0-9._:@+ -]+$"},
            "evidence_ref":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},
            "expires_at":{"type":"string","format":"date-time"},
            "member_id":{"type":"string","minLength":32,"maxLength":32},
            "reason":{"type":"string","minLength":4,"maxLength":160},
            "source_operation_id":{"type":"string","minLength":1,"maxLength":80}
        },
        "x-cfctl-body-required":true
    })
}

fn list_member_async_contract(create: bool) -> AsyncCollectionMutationContractV1 {
    AsyncCollectionMutationContractV1 {
        operation_status_path: LIST_BULK_STATUS_PATH.to_owned(),
        operation_status_capability_id: LIST_BULK_STATUS_ID.to_owned(),
        operation_id_selector: "operation_id".to_owned(),
        apply_operation_id_pointer: "/operation_id".to_owned(),
        status_operation_id_pointer: "/id".to_owned(),
        status_state_pointer: "/status".to_owned(),
        pending_states: vec!["pending".to_owned(), "running".to_owned()],
        completed_state: "completed".to_owned(),
        failed_state: "failed".to_owned(),
        max_poll_attempts: 30,
        poll_interval_ms: 1_000,
        collection_path: LIST_MEMBER_COLLECTION.to_owned(),
        collection_capability_id: LIST_MEMBER_READ_ID.to_owned(),
        collection_metadata_path: LIST_METADATA_PATH.to_owned(),
        collection_metadata_capability_id: LIST_METADATA_READ_ID.to_owned(),
        collection_item_identity_pointer: "/id".to_owned(),
        correlation_field: create.then(|| "comment".to_owned()),
        remove_capability_id: create.then(|| LIST_MEMBER_REMOVE_ID.to_owned()),
        requires_cursor_completion: true,
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the asynchronous List add and exact expiry removal share one correlated lifecycle"
)]
fn finalize_list_member_lifecycle(snapshot: &mut CatalogSnapshot) {
    let identity_ok = snapshot
        .capabilities
        .get(LIST_MEMBER_SOURCE_CREATE_ID)
        .is_some_and(|capability| {
            capability.method == "POST"
                && capability.path == LIST_MEMBER_COLLECTION
                && capability.permissions == ["Account Filter Lists Edit"]
                && capability
                    .request_schema
                    .as_ref()
                    .and_then(|schema| schema.get("type"))
                    .and_then(Value::as_str)
                    == Some("array")
        })
        && snapshot
            .capabilities
            .get(LIST_MEMBER_SOURCE_DELETE_ID)
            .is_some_and(|capability| {
                capability.method == "DELETE" && capability.path == LIST_MEMBER_COLLECTION
            })
        && snapshot
            .capabilities
            .get(LIST_MEMBER_READ_ID)
            .is_some_and(|capability| {
                capability.method == "GET"
                    && capability.path == LIST_MEMBER_COLLECTION
                    && !capability.mutating
            })
        && snapshot
            .capabilities
            .get(LIST_METADATA_READ_ID)
            .is_some_and(|capability| {
                capability.method == "GET"
                    && capability.path == LIST_METADATA_PATH
                    && !capability.mutating
            })
        && snapshot
            .capabilities
            .get(LIST_BULK_STATUS_ID)
            .is_some_and(|capability| {
                capability.method == "GET"
                    && capability.path == LIST_BULK_STATUS_PATH
                    && !capability.mutating
            });
    if !identity_ok {
        for id in [LIST_MEMBER_SOURCE_CREATE_ID, LIST_MEMBER_SOURCE_DELETE_ID] {
            if let Some(capability) = snapshot.capabilities.get_mut(id) {
                capability.adapter_status = AdapterStatus::Blocked;
                capability.blocked_reason = Some(
                    "schema drift: Cloudflare Lists members no longer match the governed asynchronous add/status/read/remove lifecycle"
                        .to_owned(),
                );
            }
        }
        return;
    }

    let Some(source_create) = snapshot
        .capabilities
        .get(LIST_MEMBER_SOURCE_CREATE_ID)
        .cloned()
    else {
        return;
    };
    let mut create = source_create;
    LIST_MEMBER_CREATE_ID.clone_into(&mut create.id);
    "Add one evidence-bound expiring Cloudflare List member".clone_into(&mut create.title);
    create.description = Some(
        "Adds one normalized IP, prefix, ASN, or exact hostname to one reviewed Cloudflare List. cfctl defaults the expected consumer action to Managed Challenge, requires evidence, actor, reason, expiry, and consumer-scope confirmation, polls the asynchronous bulk operation, correlates the exact member, and records its identity for verified removal. The list member is not represented as a person identity."
            .to_owned(),
    );
    create.aliases = vec![
        "add expiring IP to Cloudflare list".to_owned(),
        "temporary ASN list member".to_owned(),
        "hostname security list member".to_owned(),
        "telemetry derived list enforcement".to_owned(),
    ];
    "cfctl-security-action-v1+cloudflare-api-schemas".clone_into(&mut create.source);
    create.permissions = vec![
        "Account Filter Lists Edit".to_owned(),
        "Account Filter Lists Read".to_owned(),
    ];
    create.request_schema = Some(governed_list_member_wire_schema());
    create.risk = RiskClass::IdentityOrOwnership;
    create.effect = EffectClass::ReversibleWrite;
    attach_live_read_entitlement_probe(&mut create, LIST_MEMBER_READ_ID, LIST_MEMBER_COLLECTION);
    create.entitlement.source = Some(
        "https://developers.cloudflare.com/api/resources/rules/subresources/lists/subresources/items/methods/create/"
            .to_owned(),
    );
    zero_cost_mutation(
        &mut create,
        "the member write has no direct operation charge; list quotas and every consuming rule remain separate governed effects",
        official_reference(
            "Cloudflare Lists API limits",
            "https://developers.cloudflare.com/waf/tools/lists/lists-api/",
        ),
    );
    create.verification.required = true;
    "async_list_operation_completes_and_correlated_member_exists"
        .clone_into(&mut create.verification.strategy);
    create.async_collection_mutation = Some(list_member_async_contract(true));
    create.rollback.supported = true;
    create.rollback.strategy = Some("remove_async_created_list_member_by_correlated_id".to_owned());
    create.rollback.warning = Some(
        "removal is a separate exact-member plan derived from the correlated verification receipt; it cannot reverse traffic decisions already made by consuming rules"
            .to_owned(),
    );
    create.security_action = Some(SecurityActionContractV1 {
        kind: SecurityActionKindV1::AddExpiringListMember,
        input_schema: governed_list_member_input_schema(),
        default_action: Some("managed_challenge".to_owned()),
        allowed_actions: vec!["managed_challenge".to_owned(), "block".to_owned()],
        allowed_target_types: vec![
            "asn".to_owned(),
            "hostname".to_owned(),
            "ip".to_owned(),
            "ip_range".to_owned(),
        ],
        default_ttl_seconds: 86_400,
        max_ttl_seconds: 604_800,
        current_state_capability_id: LIST_MEMBER_READ_ID.to_owned(),
        safety_profile: SecurityActionSafetyProfileV1::TelemetryDerivedStrict,
    });
    create.adapter_status = AdapterStatus::DynamicApi;
    create.blocked_reason = None;
    refresh_dynamic_mutation_contract(&mut create);
    snapshot
        .capabilities
        .insert(LIST_MEMBER_CREATE_ID.to_owned(), create);

    let Some(source_remove) = snapshot
        .capabilities
        .get(LIST_MEMBER_SOURCE_DELETE_ID)
        .cloned()
    else {
        return;
    };
    let mut remove = source_remove;
    LIST_MEMBER_REMOVE_ID.clone_into(&mut remove.id);
    "Remove one expired evidence-bound Cloudflare List member".clone_into(&mut remove.title);
    remove.description = Some(
        "Removes exactly one List member only after its verified source operation, expiry, live identity, and audit correlation have been rechecked. The asynchronous delete is polled to completion and the complete cursor-paginated collection must omit the member."
            .to_owned(),
    );
    remove.aliases = vec![
        "remove expired list enforcement".to_owned(),
        "delete verified Cloudflare list member".to_owned(),
    ];
    "cfctl-security-action-v1+cloudflare-api-schemas".clone_into(&mut remove.source);
    remove.permissions = vec![
        "Account Filter Lists Edit".to_owned(),
        "Account Filter Lists Read".to_owned(),
    ];
    remove.request_schema = Some(governed_list_member_delete_wire_schema());
    remove.risk = RiskClass::IdentityOrOwnership;
    remove.effect = EffectClass::Destructive;
    attach_live_read_entitlement_probe(&mut remove, LIST_MEMBER_READ_ID, LIST_MEMBER_COLLECTION);
    remove.entitlement.source = Some(
        "https://developers.cloudflare.com/api/resources/rules/subresources/lists/subresources/items/methods/delete/"
            .to_owned(),
    );
    zero_cost_mutation(
        &mut remove,
        "removing one exact list member has no direct operation charge and cannot reverse traffic decisions already made",
        official_reference(
            "Delete Cloudflare List items",
            "https://developers.cloudflare.com/api/resources/rules/subresources/lists/subresources/items/methods/delete/",
        ),
    );
    remove.verification.required = true;
    "async_list_operation_completes_and_members_absent"
        .clone_into(&mut remove.verification.strategy);
    remove.async_collection_mutation = Some(list_member_async_contract(false));
    remove.rollback.supported = false;
    remove.rollback.strategy = None;
    remove.rollback.warning = Some(
        "member removal cannot restore the original identity or undo prior consumer effects; recreation requires a separately reviewed expiring add plan"
            .to_owned(),
    );
    remove.security_action = Some(SecurityActionContractV1 {
        kind: SecurityActionKindV1::RemoveExpiredListMember,
        input_schema: governed_list_member_remove_input_schema(),
        default_action: None,
        allowed_actions: Vec::new(),
        allowed_target_types: vec![
            "asn".to_owned(),
            "hostname".to_owned(),
            "ip".to_owned(),
            "ip_range".to_owned(),
        ],
        default_ttl_seconds: 0,
        max_ttl_seconds: 0,
        current_state_capability_id: LIST_MEMBER_READ_ID.to_owned(),
        safety_profile: SecurityActionSafetyProfileV1::TelemetryDerivedStrict,
    });
    remove.adapter_status = AdapterStatus::DynamicApi;
    remove.blocked_reason = None;
    refresh_dynamic_mutation_contract(&mut remove);
    snapshot
        .capabilities
        .insert(LIST_MEMBER_REMOVE_ID.to_owned(), remove);

    for id in [LIST_MEMBER_SOURCE_CREATE_ID, LIST_MEMBER_SOURCE_DELETE_ID] {
        let Some(capability) = snapshot.capabilities.get_mut(id) else {
            return;
        };
        capability.adapter_status = AdapterStatus::Blocked;
        capability.blocked_reason = Some(
            "blocked by design: raw asynchronous multi-item List writes bypass evidence, expiry, consumer-scope review, exact member correlation, and verified removal; use the governed single-member security-response capability"
                .to_owned(),
        );
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the bounded SQL and negotiated response contract is reviewed as one overlay"
)]
fn finalize_analytics_engine_query(snapshot: &mut CatalogSnapshot) {
    let Some(capability) = snapshot
        .capabilities
        .get_mut("analytics-engine-sql-query-get")
    else {
        return;
    };
    let identity_supported = capability.method == "GET"
        && capability.path == "/accounts/{account_id}/analytics_engine/sql"
        && capability.permissions == ["Account Analytics Read"]
        && capability
            .response_contract
            .as_ref()
            .is_some_and(|response| {
                response.success_statuses == ["200"]
                    && response
                        .success_media_types
                        .iter()
                        .any(|media| media == "application/json")
                    && response
                        .success_media_types
                        .iter()
                        .any(|media| media == "application/x-ndjson")
            });
    if !identity_supported {
        capability.adapter_status = AdapterStatus::Blocked;
        capability.blocked_reason = Some(
            "schema drift: Analytics Engine SQL no longer matches the governed GET, permission, and response contract"
                .to_owned(),
        );
        return;
    }
    capability
        .selectors
        .retain(|selector| !(selector.location == "query" && selector.name == "query"));
    capability.aliases = vec![
        "Analytics Engine".to_owned(),
        "Analytics Engine SQL".to_owned(),
        "query dataset".to_owned(),
        "stream analytics results".to_owned(),
        "export analytics".to_owned(),
    ];
    capability.description = Some(
        "Runs a compiler-rendered, single-statement SELECT over one Analytics Engine dataset with explicit time, row, byte, timeout, and output bounds. Raw SQL is not accepted."
            .to_owned(),
    );
    capability.request_schema = Some(structured_analytics_engine_schema());
    capability.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".to_owned()],
        success_media_types: vec![
            "application/json".to_owned(),
            "application/x-ndjson".to_owned(),
            "text/csv".to_owned(),
        ],
        body_mode: ResponseBodyModeV1::NegotiatedRows,
    });
    capability.analytics_query = Some(AnalyticsQueryContractV1 {
        kind: AnalyticsQueryKindV1::StructuredSql,
        dataset: None,
        dataset_pointer: Some("/dataset".to_owned()),
        time_range: Some(TimeRangeContractV1 {
            start_pointer: "/start".to_owned(),
            end_pointer: "/end".to_owned(),
            timestamp_format: TimestampFormatV1::Rfc3339,
            max_lookback_seconds: 90 * 24 * 60 * 60,
            max_window_seconds: 7 * 24 * 60 * 60,
        }),
        row_limit_pointer: Some("/limit".to_owned()),
        max_rows: 10_000,
        max_bytes: 64 * 1024 * 1024,
        max_timeout_seconds: 60,
        allowed_output_formats: vec![
            OutputFormatV1::Json,
            OutputFormatV1::Ndjson,
            OutputFormatV1::Csv,
        ],
        default_output_format: OutputFormatV1::Ndjson,
        pagination: PaginationModeV1::BoundedResult,
        read_only: true,
        freshness: Some("dataset-defined; reported in the query receipt".to_owned()),
        sampling: Some("dataset-defined; cfctl never infers unsampled results".to_owned()),
    });
    capability.adapter_status = AdapterStatus::DynamicApi;
    capability.blocked_reason = None;
    capability.risk = RiskClass::Read;
    capability.effect = EffectClass::ReadOnly;
    capability.mutating = false;
    capability.cost.known = true;
    capability.cost.incremental = false;
    capability.cost.maximum = Some(0.0);
    capability.cost.billing_model = BillingModelV1::UsageBased;
    capability.cost.exposure = CostExposureV1::DownstreamUsage;
    capability.cost.basis = Some(
        "Cloudflare currently documents Analytics Engine SQL queries as not separately billed; bounded query volume remains visible in the receipt because upstream pricing may change"
            .to_owned(),
    );
    capability.cost.references = vec![official_reference(
        "Analytics Engine pricing",
        "https://developers.cloudflare.com/analytics/analytics-engine/pricing/",
    )];
    capability.verification.required = false;
    "not_applicable".clone_into(&mut capability.verification.strategy);
    capability.rollback.warning = None;

    if let Some(post) = snapshot
        .capabilities
        .get_mut("analytics-engine-sql-query-post")
    {
        post.adapter_status = AdapterStatus::Blocked;
        post.blocked_reason = Some(
            "blocked by design: raw SQL bodies are not a public cfctl surface; use `analytics-engine-sql-query-get`, which compiles a bounded typed SELECT"
                .to_owned(),
        );
    }
}

fn structured_analytics_engine_schema() -> Value {
    serde_json::json!({
        "type":"object",
        "additionalProperties":false,
        "required":["dataset","start","end","columns","limit","format","timeout_seconds"],
        "properties":{
            "dataset":{"type":"string","pattern":"^[A-Za-z_][A-Za-z0-9_]{0,63}$"},
            "start":{"type":"string","format":"date-time"},
            "end":{"type":"string","format":"date-time"},
            "columns":{"type":"array","minItems":1,"maxItems":50,"uniqueItems":true,"items":{"type":"string","pattern":"^[A-Za-z_][A-Za-z0-9_]{0,63}$"}},
            "aggregates":{"type":"array","maxItems":20,"items":{"type":"object","additionalProperties":false,"required":["function","alias"],"properties":{"function":{"type":"string","enum":["count","sum","avg","min","max"]},"field":{"type":"string","pattern":"^[A-Za-z_][A-Za-z0-9_]{0,63}$"},"alias":{"type":"string","pattern":"^[A-Za-z_][A-Za-z0-9_]{0,63}$"}}}},
            "filters":{"type":"array","maxItems":20,"items":{"type":"object","additionalProperties":false,"required":["field","operator","value"],"properties":{"field":{"type":"string","pattern":"^[A-Za-z_][A-Za-z0-9_]{0,63}$"},"operator":{"type":"string","enum":["eq","ne","gt","gte","lt","lte","in","not_in"]},"value":{}}}},
            "group_by":{"type":"array","maxItems":20,"uniqueItems":true,"items":{"type":"string","pattern":"^[A-Za-z_][A-Za-z0-9_]{0,63}$"}},
            "order_by":{"type":"array","maxItems":10,"items":{"type":"object","additionalProperties":false,"required":["field","direction"],"properties":{"field":{"type":"string","pattern":"^[A-Za-z_][A-Za-z0-9_]{0,63}$"},"direction":{"type":"string","enum":["asc","desc"]}}}},
            "limit":{"type":"integer","minimum":1,"maximum":10000},
            "format":{"type":"string","enum":["json","ndjson","csv"]},
            "timeout_seconds":{"type":"integer","minimum":1,"maximum":60}
        },
        "x-cfctl-body-required":true
    })
}

fn finalize_workers_observability_reads(snapshot: &mut CatalogSnapshot) {
    for (id, dataset_pointer, start_pointer, end_pointer, row_pointer) in [
        ("telemetry.keys.list", "/datasets", "/from", "/to", "/limit"),
        (
            "telemetry.values.list",
            "/datasets",
            "/timeframe/from",
            "/timeframe/to",
            "/limit",
        ),
        (
            "telemetry.query",
            "/parameters/datasets",
            "/timeframe/from",
            "/timeframe/to",
            "/parameters/limit",
        ),
    ] {
        let Some(capability) = snapshot.capabilities.get_mut(id) else {
            continue;
        };
        if capability.method != "POST"
            || !capability
                .path
                .starts_with("/accounts/{account_id}/workers/observability/telemetry/")
            || capability.permissions != ["Workers Observability Write"]
            || capability
                .response_contract
                .as_ref()
                .is_none_or(|response| {
                    response.body_mode != ResponseBodyModeV1::CloudflareJsonEnvelope
                })
        {
            capability.adapter_status = AdapterStatus::Blocked;
            capability.blocked_reason = Some(format!(
                "schema drift: `{id}` no longer matches the fixed Workers observability read contract"
            ));
            continue;
        }
        harden_workers_observability_schema(id, capability.request_schema.as_mut());
        capability.mutating = false;
        capability.risk = RiskClass::Read;
        capability.effect = EffectClass::ReadOnly;
        capability.adapter_status = AdapterStatus::DynamicApi;
        capability.blocked_reason = None;
        capability.aliases = workers_observability_aliases(id);
        capability.analytics_query = Some(AnalyticsQueryContractV1 {
            kind: AnalyticsQueryKindV1::WorkersObservability,
            dataset: None,
            dataset_pointer: Some(dataset_pointer.to_owned()),
            time_range: Some(TimeRangeContractV1 {
                start_pointer: start_pointer.to_owned(),
                end_pointer: end_pointer.to_owned(),
                timestamp_format: TimestampFormatV1::UnixMilliseconds,
                max_lookback_seconds: 7 * 24 * 60 * 60,
                max_window_seconds: 60 * 60,
            }),
            row_limit_pointer: Some(row_pointer.to_owned()),
            max_rows: 2_000,
            max_bytes: 16 * 1024 * 1024,
            max_timeout_seconds: 30,
            allowed_output_formats: vec![OutputFormatV1::Json],
            default_output_format: OutputFormatV1::Json,
            pagination: PaginationModeV1::TimeWindow,
            read_only: true,
            freshness: Some(
                "Workers observability ingestion freshness is upstream-reported".to_owned(),
            ),
            sampling: Some(
                "sampling follows the selected Worker's observability settings".to_owned(),
            ),
        });
        capability.cost.known = true;
        capability.cost.incremental = false;
        capability.cost.maximum = Some(0.0);
        capability.cost.billing_model = BillingModelV1::Subscription;
        capability.cost.exposure = CostExposureV1::DownstreamUsage;
        capability.cost.basis = Some(
            "the bounded read has no direct operation charge; Workers logging retention and ingestion remain governed by the account plan"
                .to_owned(),
        );
        capability.verification.required = false;
        "not_applicable".clone_into(&mut capability.verification.strategy);
        capability.rollback.warning = None;
    }
}

fn harden_workers_observability_schema(id: &str, schema: Option<&mut Value>) {
    let Some(root) = schema.and_then(Value::as_object_mut) else {
        return;
    };
    root.insert("additionalProperties".to_owned(), Value::Bool(false));
    let required = match id {
        "telemetry.keys.list" => serde_json::json!(["datasets", "from", "to", "limit"]),
        "telemetry.values.list" => {
            serde_json::json!(["datasets", "timeframe", "key", "type", "limit"])
        }
        _ => serde_json::json!(["queryId", "timeframe", "view", "parameters"]),
    };
    root.insert("required".to_owned(), required);
    let Some(properties) = root.get_mut("properties").and_then(Value::as_object_mut) else {
        return;
    };
    if let Some(datasets) = if id == "telemetry.query" {
        properties
            .get_mut("parameters")
            .and_then(Value::as_object_mut)
            .and_then(|parameters| parameters.get_mut("properties"))
            .and_then(Value::as_object_mut)
            .and_then(|properties| properties.get_mut("datasets"))
    } else {
        properties.get_mut("datasets")
    }
    .and_then(Value::as_object_mut)
    {
        datasets.insert("minItems".to_owned(), Value::from(1));
        datasets.insert("maxItems".to_owned(), Value::from(20));
        datasets.insert("uniqueItems".to_owned(), Value::Bool(true));
    }
    if id == "telemetry.query" {
        if let Some(parameters) = properties
            .get_mut("parameters")
            .and_then(Value::as_object_mut)
        {
            parameters.insert("additionalProperties".to_owned(), Value::Bool(false));
            parameters.insert(
                "required".to_owned(),
                serde_json::json!(["datasets", "limit"]),
            );
            if let Some(limit) = parameters
                .get_mut("properties")
                .and_then(Value::as_object_mut)
                .and_then(|properties| properties.get_mut("limit"))
                .and_then(Value::as_object_mut)
            {
                limit.insert("minimum".to_owned(), Value::from(1));
                limit.insert("maximum".to_owned(), Value::from(2_000));
            }
        }
    } else if let Some(limit) = properties.get_mut("limit").and_then(Value::as_object_mut) {
        limit.insert("type".to_owned(), Value::String("integer".to_owned()));
        limit.insert("minimum".to_owned(), Value::from(1));
        limit.insert("maximum".to_owned(), Value::from(2_000));
    }
}

fn workers_observability_aliases(id: &str) -> Vec<String> {
    let mut aliases = vec![
        "Workers logs".to_owned(),
        "Workers traces".to_owned(),
        "Workers observability".to_owned(),
        "exceptions invocations CPU time subrequests latency".to_owned(),
    ];
    aliases.push(
        match id {
            "telemetry.keys.list" => "discover telemetry fields",
            "telemetry.values.list" => "discover telemetry values",
            _ => "query Worker logs traces exceptions and invocation metrics",
        }
        .to_owned(),
    );
    aliases
}

fn graphql_analytics_capabilities() -> Result<Vec<CapabilityV1>> {
    Ok(vec![
        zone_http_graphql_capability()?,
        zone_http_unique_ips_daily_graphql_capability()?,
        account_rum_pageload_visits_graphql_capability()?,
        account_rum_dataset_settings_graphql_capability()?,
        account_http_graphql_capability()?,
        zone_firewall_graphql_capability()?,
        zone_dataset_settings_graphql_capability()?,
    ])
}

fn zone_http_graphql_capability() -> Result<CapabilityV1> {
    let document = "query CfctlZoneHttpAnalytics($zoneTag: string!, $start: Time!, $end: Time!, $limit: Int!) { viewer { zones(filter: {zoneTag: $zoneTag}) { series: httpRequestsAdaptiveGroups(filter: {datetime_geq: $start, datetime_lt: $end}, limit: $limit, orderBy: [datetimeHour_ASC]) { count avg { sampleInterval } sum { edgeResponseBytes visits } dimensions { datetimeHour cacheStatus edgeResponseStatus clientRequestHTTPHost clientRequestPath } } } } }";
    graphql_capability(GraphqlCapabilitySpec {
        id: "graphql-analytics-zone-http-requests",
        title: "Query bounded zone HTTP analytics",
        aliases: &[
            "zone traffic requests bandwidth cache status codes",
            "host traffic route traffic",
            "GraphQL analytics HTTP",
        ],
        operation_name: "CfctlZoneHttpAnalytics",
        document,
        dataset: "httpRequestsAdaptiveGroups",
        selectors: vec![graphql_selector("zone_id", "Exact zone scope")],
        selector_variables: [("zone_id", "zoneTag")].as_slice(),
        body_variables: &[("start", "start"), ("end", "end"), ("limit", "limit")],
        response_pointer: "/viewer/zones/0/series",
        expected_fields: &["avg", "count", "dimensions", "sum"],
        cursor_fields: &[],
        cursor_input_pointers: &[],
        request_schema: graphql_time_request_schema("httpRequestsAdaptiveGroups", 5_000, false),
        max_rows: 5_000,
        pagination: PaginationModeV1::TimeWindow,
    })
}

fn zone_http_unique_ips_daily_graphql_capability() -> Result<CapabilityV1> {
    let document = "query CfctlZoneHttpUniqueIpsDaily($zoneTag: string!, $start: Date!, $end: Date!, $limit: Int!) { viewer { zones(filter: {zoneTag: $zoneTag}) { series: httpRequests1dGroups(filter: {date_geq: $start, date_leq: $end}, limit: $limit, orderBy: [date_ASC]) { dimensions { date } uniq { uniques } } } } }";
    let mut capability = graphql_capability(GraphqlCapabilitySpec {
        id: "graphql-analytics-zone-http-unique-ips-daily",
        title: "Query bounded zone-wide daily HTTP unique IP counts",
        aliases: &[
            "zone-wide daily unique IP rollup",
            "month to date zone unique IP rows",
            "GraphQL daily HTTP zone analytics",
        ],
        operation_name: "CfctlZoneHttpUniqueIpsDaily",
        document,
        dataset: "httpRequests1dGroups",
        selectors: vec![graphql_selector("zone_id", "Exact zone scope")],
        selector_variables: &[("zone_id", "zoneTag")],
        body_variables: &[("start", "start"), ("end", "end"), ("limit", "limit")],
        response_pointer: "/viewer/zones/0/series",
        expected_fields: &["dimensions", "uniq"],
        cursor_fields: &[],
        cursor_input_pointers: &[],
        request_schema: graphql_date_request_schema("httpRequests1dGroups", 31),
        max_rows: 31,
        pagination: PaginationModeV1::BoundedResult,
    })?;
    capability.description = Some(
        "Returns daily unique-client-IP counts for the entire selected zone. Cloudflare's httpRequests1dGroups contract exposes only the date dimension and does not accept a hostname filter, so this capability cannot prove apex-only or subdomain-only traffic."
            .to_owned(),
    );
    if let Some(query) = capability.analytics_query.as_mut() {
        query.time_range = Some(TimeRangeContractV1 {
            start_pointer: "/start".to_owned(),
            end_pointer: "/end".to_owned(),
            timestamp_format: TimestampFormatV1::Date,
            max_lookback_seconds: 366 * 24 * 60 * 60,
            max_window_seconds: 31 * 24 * 60 * 60,
        });
        query.sampling = Some(
            "httpRequests1dGroups is a pre-aggregated zone-wide daily rollup; uniq.uniques is the number of unique client IPs within each day, summing rows does not deduplicate an IP seen on multiple days, and no hostname dimension or filter is available"
                .to_owned(),
        );
    }
    Ok(capability)
}

fn account_rum_pageload_visits_graphql_capability() -> Result<CapabilityV1> {
    let document = "query CfctlAccountRumPageloadVisits($accountTag: string!, $hostname: string!, $start: Date!, $end: Date!, $limit: Int!) { viewer { accounts(filter: {accountTag: $accountTag}) { series: rumPageloadEventsAdaptiveGroups(filter: {bot: 0, date_geq: $start, date_leq: $end, requestHost: $hostname}, limit: $limit, orderBy: [date_ASC]) { avg { sampleInterval } count dimensions { date requestHost } sum { visits } } } } }";
    let mut capability = graphql_capability(GraphqlCapabilitySpec {
        id: "graphql-analytics-account-rum-pageload-visits",
        title: "Query hostname-bound daily Web Analytics visits",
        aliases: &[
            "hostname Web Analytics visits month to date",
            "RUM page loads visits by host",
            "daily non-bot browser visits",
        ],
        operation_name: "CfctlAccountRumPageloadVisits",
        document,
        dataset: "rumPageloadEventsAdaptiveGroups",
        selectors: vec![graphql_selector(
            "account_id",
            "Exact account governance and GraphQL scope",
        )],
        selector_variables: &[("account_id", "accountTag")],
        body_variables: &[
            ("hostname", "hostname"),
            ("start", "start"),
            ("end", "end"),
            ("limit", "limit"),
        ],
        response_pointer: "/viewer/accounts/0/series",
        expected_fields: &["avg", "count", "dimensions", "sum"],
        cursor_fields: &[],
        cursor_input_pointers: &[],
        request_schema: graphql_rum_visits_request_schema(),
        max_rows: 31,
        pagination: PaginationModeV1::BoundedResult,
    })?;
    capability.description = Some(
        "Returns Cloudflare Web Analytics page views and visits for one exact requestHost, grouped by inclusive calendar date and excluding rows Cloudflare classifies as bots. It covers only instrumented RUM traffic; `sum.visits` is not a unique-person or unique-IP metric."
            .to_owned(),
    );
    capability.permissions = vec!["Account Analytics Read".to_owned()];
    if let Some(query) = capability.analytics_query.as_mut() {
        query.time_range = Some(TimeRangeContractV1 {
            start_pointer: "/start".to_owned(),
            end_pointer: "/end".to_owned(),
            timestamp_format: TimestampFormatV1::Date,
            max_lookback_seconds: 31 * 24 * 60 * 60,
            max_window_seconds: 31 * 24 * 60 * 60,
        });
        query.freshness = Some(
            "inspect the account RUM dataset settings capability before relying on current-day completeness"
                .to_owned(),
        );
        query.sampling = Some(
            "rumPageloadEventsAdaptiveGroups uses adaptive sampling and reports avg.sampleInterval; sum.visits counts page views whose document referrer does not match the hostname and does not identify unique people"
                .to_owned(),
        );
    }
    Ok(capability)
}

fn account_rum_dataset_settings_graphql_capability() -> Result<CapabilityV1> {
    let document = "query CfctlAccountRumAnalyticsSettings($accountTag: string!) { viewer { accounts(filter: {accountTag: $accountTag}) { settings { rumPageloadEventsAdaptiveGroups { availableFields enabled maxDuration maxNumberOfFields maxPageSize notOlderThan } } } } }";
    let mut capability = graphql_capability(GraphqlCapabilitySpec {
        id: "graphql-analytics-account-rum-dataset-settings",
        title: "Inspect Web Analytics RUM retention and query limits",
        aliases: &[
            "RUM retention sampling freshness limits",
            "Web Analytics GraphQL dataset settings",
            "RUM available fields page size lookback",
        ],
        operation_name: "CfctlAccountRumAnalyticsSettings",
        document,
        dataset: "settings",
        selectors: vec![graphql_selector(
            "account_id",
            "Exact account governance and GraphQL scope",
        )],
        selector_variables: &[("account_id", "accountTag")],
        body_variables: &[],
        response_pointer: "/viewer/accounts/0/settings",
        expected_fields: &["rumPageloadEventsAdaptiveGroups"],
        cursor_fields: &[],
        cursor_input_pointers: &[],
        request_schema: serde_json::json!({
            "type":"object",
            "additionalProperties":false,
            "properties":{},
            "x-cfctl-body-required":true
        }),
        max_rows: 1,
        pagination: PaginationModeV1::BoundedResult,
    })?;
    capability.permissions = vec!["Account Analytics Read".to_owned()];
    Ok(capability)
}

fn account_http_graphql_capability() -> Result<CapabilityV1> {
    let document = "query CfctlAccountHttpAnalytics($zoneTags: [string!]!, $start: Time!, $end: Time!, $limit: Int!) { viewer { zones(filter: {zoneTag_in: $zoneTags}) { zoneTag series: httpRequestsAdaptiveGroups(filter: {datetime_geq: $start, datetime_lt: $end}, limit: $limit, orderBy: [datetimeHour_ASC]) { count sum { edgeResponseBytes visits } dimensions { datetimeHour cacheStatus edgeResponseStatus clientRequestHTTPHost clientRequestPath } } } } }";
    graphql_capability(GraphqlCapabilitySpec {
        id: "graphql-analytics-account-http-requests",
        title: "Query bounded HTTP analytics across selected account zones",
        aliases: &[
            "account traffic requests bandwidth cache status codes",
            "multi zone HTTP analytics",
            "account GraphQL analytics",
        ],
        operation_name: "CfctlAccountHttpAnalytics",
        document,
        dataset: "httpRequestsAdaptiveGroups",
        selectors: vec![target_selector(
            "account_id",
            "Exact account governance scope",
        )],
        selector_variables: &[],
        body_variables: &[
            ("zone_ids", "zoneTags"),
            ("start", "start"),
            ("end", "end"),
            ("limit", "limit"),
        ],
        response_pointer: "/viewer/zones",
        expected_fields: &["series", "zoneTag"],
        cursor_fields: &[],
        cursor_input_pointers: &[],
        request_schema: graphql_time_request_schema("httpRequestsAdaptiveGroups", 1_000, true),
        max_rows: 10,
        pagination: PaginationModeV1::BoundedResult,
    })
}

fn zone_firewall_graphql_capability() -> Result<CapabilityV1> {
    let document = "query CfctlZoneFirewallEvents($zoneTag: string!, $start: Time!, $end: Time!, $limit: Int!) { viewer { zones(filter: {zoneTag: $zoneTag}) { events: firewallEventsAdaptive(filter: {datetime_geq: $start, datetime_lt: $end}, limit: $limit, orderBy: [datetime_ASC, rayName_ASC]) { action clientAsn clientCountryName clientIP clientRequestHTTPHost clientRequestPath datetime rayName source userAgent } } } }";
    let mut capability = graphql_capability(GraphqlCapabilitySpec {
        id: "graphql-analytics-zone-firewall-events",
        title: "Query bounded firewall and Security Events analytics",
        aliases: &[
            "firewall events Security Events WAF outcomes",
            "bot traffic DDoS managed challenge block skip allow",
            "suspicious IP ASN country hostname path fingerprint",
        ],
        operation_name: "CfctlZoneFirewallEvents",
        document,
        dataset: "firewallEventsAdaptive",
        selectors: vec![graphql_selector("zone_id", "Exact zone scope")],
        selector_variables: &[("zone_id", "zoneTag")],
        body_variables: &[("start", "start"), ("end", "end"), ("limit", "limit")],
        response_pointer: "/viewer/zones/0/events",
        expected_fields: &[
            "action",
            "clientAsn",
            "clientCountryName",
            "clientIP",
            "clientRequestHTTPHost",
            "clientRequestPath",
            "datetime",
            "rayName",
            "source",
            "userAgent",
        ],
        cursor_fields: &[],
        cursor_input_pointers: &[],
        request_schema: graphql_time_request_schema("firewallEventsAdaptive", 1_000, false),
        max_rows: 1_000,
        pagination: PaginationModeV1::BoundedResult,
    })?;
    if let Some(query) = capability.analytics_query.as_mut() {
        query.sampling = Some(
            "Cloudflare Security Events are sampled, and one request can emit multiple events with the same timestamp and Ray ID; cfctl returns one bounded page and does not claim lossless continuation or exhaustive coverage"
                .to_owned(),
        );
    }
    Ok(capability)
}

fn zone_dataset_settings_graphql_capability() -> Result<CapabilityV1> {
    let document = "query CfctlZoneAnalyticsSettings($zoneTag: string!) { viewer { zones(filter: {zoneTag: $zoneTag}) { settings { httpRequestsAdaptiveGroups { availableFields enabled maxDuration maxNumberOfFields maxPageSize notOlderThan } httpRequests1dGroups { availableFields enabled maxDuration maxNumberOfFields maxPageSize notOlderThan } firewallEventsAdaptive { availableFields enabled maxDuration maxNumberOfFields maxPageSize notOlderThan } } } } }";
    graphql_capability(GraphqlCapabilitySpec {
        id: "graphql-analytics-zone-dataset-settings",
        title: "Inspect GraphQL analytics retention and query limits",
        aliases: &[
            "analytics retention sampling freshness limits",
            "GraphQL dataset settings entitlement",
            "maximum lookback page size fields",
        ],
        operation_name: "CfctlZoneAnalyticsSettings",
        document,
        dataset: "settings",
        selectors: vec![graphql_selector("zone_id", "Exact zone scope")],
        selector_variables: &[("zone_id", "zoneTag")],
        body_variables: &[],
        response_pointer: "/viewer/zones/0/settings",
        expected_fields: &[
            "firewallEventsAdaptive",
            "httpRequests1dGroups",
            "httpRequestsAdaptiveGroups",
        ],
        cursor_fields: &[],
        cursor_input_pointers: &[],
        request_schema: serde_json::json!({
            "type":"object",
            "additionalProperties":false,
            "properties":{},
            "x-cfctl-body-required":true
        }),
        max_rows: 1,
        pagination: PaginationModeV1::BoundedResult,
    })
}

struct GraphqlCapabilitySpec<'a> {
    id: &'a str,
    title: &'a str,
    aliases: &'a [&'a str],
    operation_name: &'a str,
    document: &'a str,
    dataset: &'a str,
    selectors: Vec<SelectorV1>,
    selector_variables: &'a [(&'a str, &'a str)],
    body_variables: &'a [(&'a str, &'a str)],
    response_pointer: &'a str,
    expected_fields: &'a [&'a str],
    cursor_fields: &'a [&'a str],
    cursor_input_pointers: &'a [(&'a str, &'a str)],
    request_schema: Value,
    max_rows: u64,
    pagination: PaginationModeV1,
}

#[expect(
    clippy::too_many_lines,
    reason = "the fixed GraphQL document, bounds, fingerprint, entitlement, and cost form one contract"
)]
fn graphql_capability(spec: GraphqlCapabilitySpec<'_>) -> Result<CapabilityV1> {
    let mut capability = CapabilityV1::new(spec.id, spec.title, "POST", "/graphql");
    capability.description = Some(
        "Executes one fingerprinted Cloudflare GraphQL Analytics query. Callers may supply only declared variables; arbitrary documents and mutations are rejected."
            .to_owned(),
    );
    "GraphQL Analytics".clone_into(&mut capability.product);
    "https://developers.cloudflare.com/analytics/graphql-api/".clone_into(&mut capability.source);
    if spec
        .selectors
        .iter()
        .any(|selector| selector.name == "account_id")
    {
        "account"
    } else {
        "zone"
    }
    .clone_into(&mut capability.account_scope);
    capability.selectors = spec.selectors;
    capability.aliases = spec.aliases.iter().map(ToString::to_string).collect();
    capability.permissions = vec![
        "Account Analytics Read".to_owned(),
        "Analytics Read".to_owned(),
    ];
    capability.mutating = false;
    capability.risk = RiskClass::Read;
    capability.effect = EffectClass::ReadOnly;
    capability.verification.required = false;
    "not_applicable".clone_into(&mut capability.verification.strategy);
    capability.rollback.supported = false;
    capability.rollback.strategy = None;
    capability.rollback.warning = None;
    capability.maturity = Maturity::GenerallyAvailable;
    capability.adapter_status = AdapterStatus::Native;
    capability.blocked_reason = None;
    capability.request_schema = Some(spec.request_schema);
    capability.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".to_owned()],
        success_media_types: vec!["application/json".to_owned()],
        body_mode: ResponseBodyModeV1::GraphqlJson,
    });
    capability.analytics_query = Some(AnalyticsQueryContractV1 {
        kind: AnalyticsQueryKindV1::GraphqlAnalytics,
        dataset: Some(spec.dataset.to_owned()),
        dataset_pointer: if spec.dataset == "settings" {
            None
        } else {
            Some("/dataset".to_owned())
        },
        time_range: (spec.dataset != "settings").then(|| TimeRangeContractV1 {
            start_pointer: "/start".to_owned(),
            end_pointer: "/end".to_owned(),
            timestamp_format: TimestampFormatV1::Rfc3339,
            max_lookback_seconds: 31 * 24 * 60 * 60,
            max_window_seconds: 24 * 60 * 60,
        }),
        row_limit_pointer: (spec.dataset != "settings").then(|| "/limit".to_owned()),
        max_rows: spec.max_rows,
        max_bytes: 16 * 1024 * 1024,
        max_timeout_seconds: 30,
        allowed_output_formats: vec![OutputFormatV1::Json],
        default_output_format: OutputFormatV1::Json,
        pagination: spec.pagination,
        read_only: true,
        freshness: Some("inspect the dataset settings capability for upstream limits".to_owned()),
        sampling: Some("adaptive datasets are sampled; cfctl reports the dataset without inferring unsampled identity".to_owned()),
    });
    let mut graphql = GraphqlAnalyticsContractV1 {
        operation_name: spec.operation_name.to_owned(),
        document: spec.document.to_owned(),
        dataset: spec.dataset.to_owned(),
        selector_variables: spec
            .selector_variables
            .iter()
            .map(|(selector, variable)| ((*selector).to_owned(), (*variable).to_owned()))
            .collect(),
        body_variables: spec
            .body_variables
            .iter()
            .map(|(field, variable)| ((*field).to_owned(), (*variable).to_owned()))
            .collect(),
        response_data_pointer: spec.response_pointer.to_owned(),
        expected_row_fields: spec
            .expected_fields
            .iter()
            .map(ToString::to_string)
            .collect(),
        cursor_fields: spec.cursor_fields.iter().map(ToString::to_string).collect(),
        cursor_input_pointer: None,
        cursor_input_pointers: spec
            .cursor_input_pointers
            .iter()
            .map(|(field, pointer)| ((*field).to_owned(), (*pointer).to_owned()))
            .collect(),
        schema_fingerprint: String::new(),
    };
    graphql.refresh_schema_fingerprint()?;
    capability.graphql = Some(graphql);
    capability.entitlement.source = Some(
        "https://developers.cloudflare.com/analytics/graphql-api/features/discovery/settings/"
            .to_owned(),
    );
    capability.entitlement.requires_live_resolution = true;
    capability.cost.basis = Some(
        "the read has no direct operation charge; Cloudflare GraphQL rate and node limits are enforced independently of product retention and sampling"
            .to_owned(),
    );
    capability.cost.references = vec![official_reference(
        "GraphQL Analytics limits",
        "https://developers.cloudflare.com/analytics/graphql-api/limits/",
    )];
    Ok(capability)
}

fn graphql_time_request_schema(dataset: &str, max_rows: u64, multi_zone: bool) -> Value {
    let mut properties = serde_json::json!({
        "dataset":{"type":"string","enum":[dataset]},
        "start":{"type":"string","format":"date-time"},
        "end":{"type":"string","format":"date-time"},
        "limit":{"type":"integer","minimum":1,"maximum":max_rows},
        "timeout_seconds":{"type":"integer","minimum":1,"maximum":30}
    });
    let mut required = vec!["dataset", "start", "end", "limit"];
    if multi_zone {
        if let Some(properties) = properties.as_object_mut() {
            properties.insert(
                "zone_ids".to_owned(),
                serde_json::json!({"type":"array","minItems":1,"maxItems":10,"uniqueItems":true,"items":{"type":"string","minLength":1,"maxLength":32}}),
            );
        }
        required.push("zone_ids");
    }
    serde_json::json!({
        "type":"object",
        "additionalProperties":false,
        "required":required,
        "properties":properties,
        "x-cfctl-body-required":true
    })
}

fn graphql_date_request_schema(dataset: &str, max_rows: u64) -> Value {
    serde_json::json!({
        "type":"object",
        "additionalProperties":false,
        "required":["dataset","start","end","limit"],
        "properties":{
            "dataset":{"type":"string","enum":[dataset]},
            "start":{"type":"string","format":"date"},
            "end":{"type":"string","format":"date"},
            "limit":{"type":"integer","minimum":1,"maximum":max_rows},
            "timeout_seconds":{"type":"integer","minimum":1,"maximum":30}
        },
        "x-cfctl-body-required":true,
        "x-cfctl-result-scope":"entire_zone_no_hostname_filter"
    })
}

fn graphql_rum_visits_request_schema() -> Value {
    serde_json::json!({
        "type":"object",
        "additionalProperties":false,
        "required":["dataset","hostname","start","end","limit"],
        "properties":{
            "dataset":{"type":"string","enum":["rumPageloadEventsAdaptiveGroups"]},
            "hostname":{"type":"string","format":"hostname","minLength":1,"maxLength":253},
            "start":{"type":"string","format":"date"},
            "end":{"type":"string","format":"date"},
            "limit":{"type":"integer","minimum":1,"maximum":31},
            "timeout_seconds":{"type":"integer","minimum":1,"maximum":30}
        },
        "x-cfctl-body-required":true,
        "x-cfctl-result-scope":"exact_request_host_non_bot_rum"
    })
}

fn graphql_selector(name: &str, description: &str) -> SelectorV1 {
    SelectorV1 {
        name: name.to_owned(),
        location: "graphql".to_owned(),
        required: true,
        value_type: "string".to_owned(),
        description: Some(description.to_owned()),
        contract: Some(SelectorContractV1 {
            schema: serde_json::json!({"type":"string","minLength":1,"maxLength":32}),
            query: None,
        }),
    }
}

fn target_selector(name: &str, description: &str) -> SelectorV1 {
    let mut selector = graphql_selector(name, description);
    "target".clone_into(&mut selector.location);
    selector
}

#[expect(
    clippy::too_many_lines,
    reason = "the ordered governed workflow inventory is intentionally reviewable as one table"
)]
fn telemetry_workflow_capabilities() -> Vec<CapabilityV1> {
    vec![
        control_plane_workflow_capability(
            "workflow.registry.reconcile-estate",
            "Discover and reconcile the Cloudflare resource registry",
            "Preview bounded inventory reads across account audit, events, Queues, Access, Gateway, and Rulesets without treating source config or events as live resource truth.",
            "Registry",
            &[
                "registry control plane",
                "discover Cloudflare resources",
                "reconcile Cloudflare estate",
            ],
            &[
                ("audit", "audit-logs-v2-get-account-audit-logs", false),
                ("subscriptions", "subscriptions-list", false),
                ("queues", "queues-list", false),
                (
                    "access",
                    "access-policies-list-access-reusable-policies",
                    false,
                ),
                (
                    "gateway",
                    "zero-trust-gateway-rules-list-zero-trust-gateway-rules",
                    false,
                ),
                ("rulesets", "listAccountRulesets", false),
            ],
        ),
        control_plane_workflow_capability(
            "workflow.events.reconcile-control-plane",
            "Reconcile the real-time Cloudflare event control plane",
            "Preview Event Subscription, Queue, and Audit Logs v2 reads that feed durable local reconciliation; events remain triggers rather than observed resource truth.",
            "Events",
            &[
                "real-time control plane",
                "event subscription queue reconciliation",
                "consume Cloudflare event batch",
            ],
            &[
                ("subscriptions", "subscriptions-list", false),
                ("queues", "queues-list", false),
                ("audit", "audit-logs-v2-get-account-audit-logs", false),
            ],
        ),
        control_plane_workflow_capability(
            "workflow.policy.audit-cloudflare",
            "Audit Cloudflare Access, Gateway, and Rulesets policy",
            "Preview the live reads needed to compare Access, Gateway, and Rulesets policy while preserving each future mutation's independent plan and approval lifecycle.",
            "Cloudflare policy",
            &[
                "Gateway policy",
                "Access Gateway Rulesets policy",
                "Cloudflare product policy",
            ],
            &[
                (
                    "access",
                    "access-policies-list-access-reusable-policies",
                    false,
                ),
                (
                    "gateway",
                    "zero-trust-gateway-rules-list-zero-trust-gateway-rules",
                    false,
                ),
                ("rulesets", "listAccountRulesets", false),
            ],
        ),
        control_plane_workflow_capability(
            "workflow.realtimekit.webhook-lifecycle",
            "Manage RealtimeKit webhooks lifecycle",
            "Preview RealtimeKit webhook inventory, create, and exact-resource update components; every write remains a separate governed plan with post-change verification.",
            "RealtimeKit",
            &[
                "RealtimeKit webhooks",
                "RealtimeKit webhook configuration",
                "meeting webhook lifecycle",
            ],
            &[
                ("list", "getAllWebhooks", false),
                ("create", "addWebhook", true),
                ("update", "editWebhook", true),
            ],
        ),
        workflow_capability(
            "workflow.telemetry.bootstrap-worker-observability",
            "Bootstrap observability for a Worker",
            "Inspect settings, plan bounded logging and tracing changes, then verify telemetry freshness.",
            &[
                ("inspect", "worker-script-get-settings", false),
                ("configure", "workers-observability-settings-update", true),
                ("verify", "telemetry.query", false),
            ],
        ),
        workflow_capability(
            "workflow.telemetry.bootstrap-web-analytics-rum",
            "Bootstrap Web Analytics and RUM for a site",
            "Validate the host, create or inspect the site, configure RUM, and verify the resulting state.",
            &[
                ("validate", "web-analytics-validate-site-hostname", false),
                ("site", "web-analytics-create-site", true),
                ("rum", "web-analytics-toggle-rum", true),
                ("verify", "web-analytics-get-rum-status", false),
            ],
        ),
        workflow_capability(
            "workflow.telemetry.privacy-bounded-pipeline",
            "Create a privacy-bounded analytics pipeline",
            "Discover fields, validate destination ownership, plan a minimized Logpush job, and verify job health.",
            &[
                (
                    "fields",
                    "get-zones-zone_id-logpush-datasets-dataset_id-fields",
                    false,
                ),
                (
                    "destination",
                    "post-zones-zone_id-logpush-validate-destination",
                    false,
                ),
                ("create", "post-zones-zone_id-logpush-jobs", true),
                ("verify", "get-zones-zone_id-logpush-jobs-job_id", false),
            ],
        ),
        workflow_capability(
            "workflow.telemetry.worker-traces-logpush",
            "Configure Workers traces plus Logpush",
            "Plan observability sampling and a workers_trace_events destination as separately approved components.",
            &[
                ("settings", "workers-observability-settings-update", true),
                (
                    "destination",
                    "post-accounts-account_id-logpush-validate-destination",
                    false,
                ),
                ("logpush", "post-accounts-account_id-logpush-jobs", true),
                ("verify", "telemetry.query", false),
            ],
        ),
        workflow_capability(
            "workflow.security.investigate-source",
            "Investigate a suspicious source",
            "Query bounded security events and normalize a source without identifying a person.",
            &[("events", "graphql-analytics-zone-firewall-events", false)],
        ),
        workflow_capability(
            "workflow.security.propose-expiring-managed-challenge",
            "Turn security evidence into an expiring managed-challenge proposal",
            "Bind a security-event receipt to a scoped, expiring proposal; applying the rule remains a separate approved plan.",
            &[
                ("events", "graphql-analytics-zone-firewall-events", false),
                ("proposal", SECURITY_IP_RULE_CREATE_ID, true),
            ],
        ),
        workflow_capability(
            "workflow.telemetry.verify-freshness",
            "Verify telemetry freshness after deployment",
            "Inspect upstream dataset limits and query a bounded recent window.",
            &[
                ("limits", "graphql-analytics-zone-dataset-settings", false),
                ("http", "graphql-analytics-zone-http-requests", false),
                ("worker", "telemetry.query", false),
            ],
        ),
        workflow_capability(
            "workflow.telemetry.audit-account",
            "Audit telemetry coverage across an account",
            "Enumerate bounded HTTP analytics, Worker observability, Web Analytics, Logpush, and audit-log capabilities.",
            &[
                ("http", "graphql-analytics-account-http-requests", false),
                ("workers", "telemetry.keys.list", false),
                ("sites", "web-analytics-list-sites", false),
                ("logpush", "get-accounts-account_id-logpush-jobs", false),
            ],
        ),
        workflow_capability(
            "workflow.telemetry.audit-governance",
            "Audit telemetry retention, sampling, destinations, permissions, and entitlements",
            "Return current dataset limits and configuration reads without turning unknown entitlement into success.",
            &[
                ("settings", "graphql-analytics-zone-dataset-settings", false),
                ("worker", "worker-script-get-settings", false),
                (
                    "destinations",
                    "get-accounts-account_id-logpush-jobs",
                    false,
                ),
            ],
        ),
        workflow_capability(
            "workflow.security.remove-expired-enforcement",
            "Remove an expired enforcement action",
            "Read the exact managed rule, then create a separate removal plan bound to its expiry receipt.",
            &[("remove", SECURITY_IP_RULE_REMOVE_ID, true)],
        ),
        workflow_capability(
            "workflow.telemetry.export-evidence-packet",
            "Export an operator telemetry evidence packet",
            "Collect available content-addressed read and mutation lifecycle checkpoints across plan, apply, verification, compensation, and closure without embedding inputs, artifacts, telemetry, or credentials.",
            &[("inventory", "workflow.telemetry.audit-governance", false)],
        ),
    ]
}

fn control_plane_workflow_capability(
    id: &str,
    title: &str,
    purpose: &str,
    product: &str,
    aliases: &[&str],
    steps: &[(&str, &str, bool)],
) -> CapabilityV1 {
    let mut capability = workflow_capability(id, title, purpose, steps);
    product.clone_into(&mut capability.product);
    capability
        .aliases
        .extend(aliases.iter().map(ToString::to_string));
    capability
}

fn workflow_capability(
    id: &str,
    title: &str,
    purpose: &str,
    steps: &[(&str, &str, bool)],
) -> CapabilityV1 {
    let mut capability = CapabilityV1::new(id, title, "GET", &format!("/cfctl/workflows/{id}"));
    capability.description = Some(purpose.to_owned());
    "Telemetry workflows".clone_into(&mut capability.product);
    "cfctl-native-workflow".clone_into(&mut capability.source);
    "workflow".clone_into(&mut capability.account_scope);
    capability.aliases = vec![title.to_owned(), purpose.to_owned()];
    capability.adapter_status = AdapterStatus::Native;
    capability.maturity = Maturity::GenerallyAvailable;
    capability.workflow = Some(WorkflowContractV1 {
        purpose: purpose.to_owned(),
        steps: steps
            .iter()
            .enumerate()
            .map(|(index, (step, capability_id, mutating))| WorkflowStepV1 {
                id: (*step).to_owned(),
                capability_id: (*capability_id).to_owned(),
                purpose: format!("Run `{capability_id}` as workflow step `{step}`"),
                mutating: *mutating,
                depends_on: index
                    .checked_sub(1)
                    .map(|previous| vec![steps[previous].0.to_owned()])
                    .unwrap_or_default(),
            })
            .collect(),
        preserves_component_approval: true,
        exports_evidence_packet: id.ends_with("export-evidence-packet"),
        proof_freshness_seconds: workflow_proof_freshness_seconds(id),
    });
    capability
}

fn workflow_proof_freshness_seconds(id: &str) -> u64 {
    match id {
        // Security investigation and deploy verification should not borrow an
        // old observation merely because it exists in the evidence store.
        "workflow.security.investigate-source" | "workflow.telemetry.verify-freshness" => 300,
        // Configuration workflows are still previews, but a recent read can
        // save an operator from repeating discovery while they fill selectors.
        "workflow.telemetry.bootstrap-worker-observability"
        | "workflow.telemetry.bootstrap-web-analytics-rum"
        | "workflow.telemetry.privacy-bounded-pipeline"
        | "workflow.telemetry.worker-traces-logpush" => 900,
        // Account/governance inventory changes less rapidly. The label remains
        // workflow-scoped and never claims upstream dataset completeness.
        "workflow.telemetry.audit-account"
        | "workflow.telemetry.audit-governance"
        | "workflow.telemetry.export-evidence-packet"
        | "workflow.registry.reconcile-estate"
        | "workflow.events.reconcile-control-plane"
        | "workflow.policy.audit-cloudflare" => 3_600,
        // Mutation-oriented recipes cannot use an old read as authority.
        _ => 0,
    }
}

fn official_reference(title: &str, url: &str) -> KnowledgeReferenceV1 {
    KnowledgeReferenceV1 {
        title: title.to_owned(),
        url: url.to_owned(),
        source: "official Cloudflare docs".to_owned(),
    }
}

const R2_OBJECT_PATH: &str = "/accounts/{account_id}/r2/buckets/{bucket_name}/objects/{object_key}";
const R2_LIFECYCLE_PATH: &str = "/accounts/{account_id}/r2/buckets/{bucket_name}/lifecycle";
const EMAIL_SENDING_COLLECTION_PATH: &str = "/zones/{zone_id}/email/sending/subdomains";
const EMAIL_SENDING_DETAIL_PATH: &str = "/zones/{zone_id}/email/sending/subdomains/{subdomain_id}";
const EMAIL_SENDING_DNS_PATH: &str = "/zones/{zone_id}/email/sending/subdomains/{subdomain_id}/dns";
const EMAIL_SENDING_DNS_STATUS_PATH: &str =
    "/zones/{zone_id}/email/sending/subdomains/{subdomain_id}/dns/status";
const EMAIL_ROUTING_DNS_PATH: &str = "/zones/{zone_id}/email/routing/dns";

fn zero_direct_usage_cost(
    capability: &mut CapabilityV1,
    basis: &str,
    references: Vec<KnowledgeReferenceV1>,
) {
    capability.cost = CostV1 {
        incremental: false,
        currency: None,
        maximum: Some(0.0),
        basis: Some(basis.to_owned()),
        known: true,
        billing_model: BillingModelV1::UsageBased,
        exposure: CostExposureV1::DownstreamUsage,
        references,
    };
}

fn finalize_r2_private_file_upload_contract(capabilities: &mut BTreeMap<String, CapabilityV1>) {
    let read_supported = capabilities
        .get("r2-get-object")
        .is_some_and(|capability| capability.method == "GET" && capability.path == R2_OBJECT_PATH);
    let delete_supported = capabilities
        .get("r2-delete-object")
        .is_some_and(|capability| {
            capability.method == "DELETE"
                && capability.path == R2_OBJECT_PATH
                && capability.permissions == ["Workers R2 Storage Write"]
        });
    let Some(capability) = capabilities.get_mut("r2-put-object") else {
        return;
    };
    let operation_supported = capability.method == "PUT"
        && capability.path == R2_OBJECT_PATH
        && capability.product == "R2 Object"
        && capability.request_schema.is_none()
        && capability
            .response_contract
            .as_ref()
            .is_some_and(|response| {
                response.success_statuses == ["200"]
                    && response.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
            })
        && capability.selectors.iter().any(|selector| {
            selector.name == "object_key"
                && selector.location == "path"
                && selector.required
                && selector
                    .description
                    .as_deref()
                    .is_some_and(|description| description.contains("MUST NOT be percent-encoded"))
        });
    if !operation_supported || !read_supported || !delete_supported {
        capability.adapter_status = AdapterStatus::Blocked;
        capability.blocked_reason = Some(
            "R2 create-only private-file upload, conditional readback, or exact delete contract drifted"
                .to_owned(),
        );
        return;
    }
    let Some(content_type) = capability
        .selectors
        .iter_mut()
        .find(|selector| selector.name == "Content-Type" && selector.location == "header")
    else {
        capability.adapter_status = AdapterStatus::Blocked;
        capability.blocked_reason = Some("R2 upload Content-Type selector drifted".to_owned());
        return;
    };
    content_type.required = true;
    capability.permissions = vec!["Workers R2 Storage Write".to_owned()];
    capability.risk = RiskClass::ScopedWrite;
    capability.effect = EffectClass::ReversibleWrite;
    zero_direct_usage_cost(
        capability,
        "the upload is one R2 Class A operation with no direct configuration charge; retained bytes and later reads incur ordinary R2 storage and operation usage",
        vec![official_reference(
            "R2 pricing",
            "https://developers.cloudflare.com/r2/pricing/",
        )],
    );
    capability.entitlement.source =
        Some("https://developers.cloudflare.com/r2/platform/limits/".to_owned());
    capability.verification.required = true;
    "r2_private_file_upload_etag_and_conditional_read"
        .clone_into(&mut capability.verification.strategy);
    capability.rollback.supported = false;
    capability.rollback.strategy = None;
    capability.rollback.warning = Some(
        "the immutable upload is create-only; rollback is a separately reviewed exact-object delete plan, while replacement requires a new digest-addressed key"
            .to_owned(),
    );
    capability.r2_private_file_upload = Some(R2PrivateFileUploadContractV1 {
        max_source_bytes: 300_000_000,
        allowed_content_types: vec![
            "application/json".to_owned(),
            "application/octet-stream".to_owned(),
        ],
        require_if_none_match_star: true,
        read_capability_id: "r2-get-object".to_owned(),
        delete_capability_id: "r2-delete-object".to_owned(),
        etag_algorithm: "md5".to_owned(),
    });
    refresh_dynamic_mutation_contract(capability);
}

fn finalize_r2_lifecycle_contract(capabilities: &mut BTreeMap<String, CapabilityV1>) {
    let read_supported = capabilities
        .get("r2-get-bucket-lifecycle-configuration")
        .is_some_and(|capability| {
            capability.method == "GET" && capability.path == R2_LIFECYCLE_PATH
        });
    let Some(capability) = capabilities.get_mut("r2-put-bucket-lifecycle-configuration") else {
        return;
    };
    let supported = read_supported
        && capability.method == "PUT"
        && capability.path == R2_LIFECYCLE_PATH
        && capability.request_schema.as_ref().is_some_and(|schema| {
            schema
                .pointer("/properties/rules/type")
                .and_then(Value::as_str)
                == Some("array")
        })
        && capability.same_path_read.as_ref().is_some_and(|read| {
            read.path == R2_LIFECYCLE_PATH
                && read.read_capability_id == "r2-get-bucket-lifecycle-configuration"
                && read.verified_response_fields == ["rules"]
        });
    if !supported {
        capability.adapter_status = AdapterStatus::Blocked;
        capability.blocked_reason = Some(
            "R2 lifecycle complete-replacement or same-path snapshot contract drifted".to_owned(),
        );
        return;
    }
    if let Some(rules) = capability
        .request_schema
        .as_mut()
        .and_then(|schema| schema.pointer_mut("/properties/rules"))
    {
        rules["x-cfctl-verification-array-identity"] = Value::String("id".to_owned());
    }
    capability.permissions = vec!["Workers R2 Storage Write".to_owned()];
    capability.risk = RiskClass::Destructive;
    capability.effect = EffectClass::Destructive;
    zero_direct_usage_cost(
        capability,
        "replacing lifecycle configuration has no direct configuration charge; resulting storage duration and operations remain ordinary R2 usage",
        vec![official_reference(
            "R2 object lifecycles",
            "https://developers.cloudflare.com/r2/buckets/object-lifecycles/",
        )],
    );
    capability.rollback.supported = true;
    capability.rollback.strategy = Some("restore_same_path_prior_snapshot".to_owned());
    capability.rollback.warning = Some(
        "the plan binds the complete prior lifecycle snapshot for a separately approved restoration; objects already expired by the changed policy cannot be recovered"
            .to_owned(),
    );
    refresh_dynamic_mutation_contract(capability);
}

fn email_sending_cost(capability: &mut CapabilityV1, action: &str) {
    zero_direct_usage_cost(
        capability,
        &format!(
            "{action} has no direct configuration-operation charge; arbitrary-recipient Email Sending requires current Workers Paid entitlement and outbound volume beyond included usage is billed at the current Email Service rate"
        ),
        vec![official_reference(
            "Email Service pricing",
            "https://developers.cloudflare.com/email-service/platform/pricing/",
        )],
    );
}

fn attach_email_sending_entitlement(capability: &mut CapabilityV1) {
    capability.entitlement.plans.clear();
    capability.entitlement.source =
        Some("https://developers.cloudflare.com/email-service/platform/pricing/".to_owned());
    attach_live_read_entitlement_probe(
        capability,
        "email-sending-subdomains-list-sending-subdomains",
        EMAIL_SENDING_COLLECTION_PATH,
    );
}

#[expect(
    clippy::too_many_lines,
    reason = "Email Sending preview, lifecycle, DNS repair, permissions, cost, and live entitlement form one fail-closed provider contract"
)]
fn finalize_email_sending_contracts(capabilities: &mut BTreeMap<String, CapabilityV1>) {
    for id in [
        "email-sending-subdomains-list-sending-subdomains",
        "email-sending-subdomains-get-sending-subdomain",
        "email-sending-subdomains-get-sending-subdomain-dns",
        "email-sending-subdomains-get-sending-subdomain-dns-status",
    ] {
        if let Some(capability) = capabilities.get_mut(id) {
            capability.permissions = vec!["Email Sending Read".to_owned()];
        }
    }

    if let Some(preview) =
        capabilities.get_mut("email-sending-subdomains-preview-sending-subdomain")
    {
        let supported = preview.method == "POST"
            && preview.path == "/zones/{zone_id}/email/sending/subdomains/preview"
            && preview.request_schema.as_ref().is_some_and(|schema| {
                schema.pointer("/required/0").and_then(Value::as_str) == Some("name")
            })
            && preview.description.as_deref().is_some_and(|description| {
                description.contains("read-only dry-run")
                    && description.contains("no records are created or modified")
            });
        if supported {
            preview.mutating = false;
            preview.risk = RiskClass::Read;
            preview.effect = EffectClass::ReadOnly;
            preview.permissions = vec!["Email Sending Read".to_owned()];
            preview.cost = CostV1::default();
            preview.verification.required = false;
            "not_applicable".clone_into(&mut preview.verification.strategy);
            preview.rollback.supported = false;
            preview.rollback.strategy = None;
            preview.rollback.warning = None;
            preview.adapter_status = AdapterStatus::DynamicApi;
            preview.blocked_reason = None;
        } else {
            preview.adapter_status = AdapterStatus::Blocked;
            preview.blocked_reason =
                Some("Email Sending DNS preview no longer proves read-only behavior".to_owned());
        }
    }

    let detail_read_supported = capabilities
        .get("email-sending-subdomains-get-sending-subdomain")
        .is_some_and(|capability| {
            capability.method == "GET" && capability.path == EMAIL_SENDING_DETAIL_PATH
        });
    let delete_supported = capabilities
        .get("email-sending-subdomains-delete-sending-subdomain")
        .is_some_and(|capability| {
            capability.method == "DELETE" && capability.path == EMAIL_SENDING_DETAIL_PATH
        });
    if let Some(create) = capabilities.get_mut("email-sending-subdomains-create-sending-subdomain")
    {
        let supported = detail_read_supported
            && delete_supported
            && create.method == "POST"
            && create.path == EMAIL_SENDING_COLLECTION_PATH
            && create.request_schema.as_ref().is_some_and(|schema| {
                schema.pointer("/required/0").and_then(Value::as_str) == Some("name")
            });
        if supported {
            create.permissions = vec!["Email Sending Write".to_owned()];
            create.risk = RiskClass::ExternalCommunication;
            create.effect = EffectClass::ExternalCommunication;
            email_sending_cost(create, "onboarding a sending subdomain");
            attach_email_sending_entitlement(create);
            create.created_resource = Some(CreatedResourceContractV1 {
                detail_path: EMAIL_SENDING_DETAIL_PATH.to_owned(),
                identity_selector: "subdomain_id".to_owned(),
                response_result_identity_pointer: "/tag".to_owned(),
                read_capability_id: "email-sending-subdomains-get-sending-subdomain".to_owned(),
                delete_capability_id: "email-sending-subdomains-delete-sending-subdomain"
                    .to_owned(),
                verified_response_fields: vec!["name".to_owned()],
            });
            "created_resource_contains_planned_fields_by_returned_id"
                .clone_into(&mut create.verification.strategy);
            create.rollback.supported = true;
            create.rollback.strategy = Some("delete_created_resource_by_returned_id".to_owned());
            create.rollback.warning = Some(
                "rollback is a separately reviewed exact sending-subdomain delete; it removes provider-managed sending DNS records but cannot undo messages already delivered"
                    .to_owned(),
            );
            refresh_dynamic_mutation_contract(create);
        } else {
            create.adapter_status = AdapterStatus::Blocked;
            create.blocked_reason =
                Some("Email Sending create/read/delete lifecycle contract drifted".to_owned());
        }
    }

    if let Some(update) = capabilities.get_mut("email-sending-subdomains-update-sending-subdomain")
    {
        let supported = detail_read_supported
            && update.method == "PATCH"
            && update.path == EMAIL_SENDING_DETAIL_PATH
            && update.request_schema.as_ref().is_some_and(|schema| {
                schema.pointer("/required/0").and_then(Value::as_str) == Some("preview_enabled")
            })
            && update.same_path_read.as_ref().is_some_and(|read| {
                read.read_capability_id == "email-sending-subdomains-get-sending-subdomain"
                    && read.verified_response_fields == ["preview_enabled"]
            });
        if supported {
            update.permissions = vec!["Email Sending Write".to_owned()];
            update.risk = RiskClass::ScopedWrite;
            update.effect = EffectClass::ReversibleWrite;
            email_sending_cost(update, "changing Email preview preference");
            attach_email_sending_entitlement(update);
            update.rollback.supported = true;
            update.rollback.strategy = Some("restore_same_path_prior_snapshot".to_owned());
            update.rollback.warning = Some(
                "rollback is a separately reviewed restore of the exact prior preview_enabled value; content already retained while preview was enabled is not recalled"
                    .to_owned(),
            );
            refresh_dynamic_mutation_contract(update);
        } else {
            update.adapter_status = AdapterStatus::Blocked;
            update.blocked_reason = Some(
                "Email Sending preview-preference update/readback contract drifted".to_owned(),
            );
        }
    }

    if let Some(delete) = capabilities.get_mut("email-sending-subdomains-delete-sending-subdomain")
        && detail_read_supported
        && delete.method == "DELETE"
        && delete.path == EMAIL_SENDING_DETAIL_PATH
    {
        delete.permissions = vec!["Email Sending Write".to_owned()];
        delete.risk = RiskClass::Destructive;
        delete.effect = EffectClass::Destructive;
        email_sending_cost(delete, "deleting a sending subdomain");
        attach_email_sending_entitlement(delete);
        delete.rollback.supported = false;
        delete.rollback.strategy = None;
        delete.rollback.warning = Some(
            "deletion disables sending and removes provider-managed DNS records; recreation and any DNS restoration require separate reviewed operations, and delivered messages cannot be undone"
                .to_owned(),
        );
        refresh_dynamic_mutation_contract(delete);
    }

    let status_read_supported = capabilities
        .get("email-sending-subdomains-get-sending-subdomain-dns-status")
        .is_some_and(|capability| {
            capability.method == "GET" && capability.path == EMAIL_SENDING_DNS_STATUS_PATH
        });
    if let Some(repair) = capabilities.get_mut("email-sending-subdomains-fix-sending-subdomain-dns")
    {
        if status_read_supported
            && repair.method == "POST"
            && repair.path == EMAIL_SENDING_DNS_PATH
            && repair.request_schema.is_none()
        {
            repair.permissions = vec![
                "DNS Write".to_owned(),
                "Email Sending Read".to_owned(),
                "Email Sending Write".to_owned(),
            ];
            repair.risk = RiskClass::ScopedWrite;
            repair.effect = EffectClass::ReversibleWrite;
            email_sending_cost(repair, "repairing provider-managed sending DNS records");
            attach_email_sending_entitlement(repair);
            repair.email_sending_dns_repair = Some(EmailSendingDnsRepairContractV1 {
                status_read_capability_id:
                    "email-sending-subdomains-get-sending-subdomain-dns-status".to_owned(),
                status_read_path: EMAIL_SENDING_DNS_STATUS_PATH.to_owned(),
            });
            "email_sending_dns_status_reports_ready".clone_into(&mut repair.verification.strategy);
            repair.rollback.supported = false;
            repair.rollback.strategy = None;
            repair.rollback.warning = Some(
                "DNS repair is idempotent but not automatically reversible; provider-managed record removal or exact prior-record restoration requires separate reviewed DNS and sending-domain plans"
                    .to_owned(),
            );
            refresh_dynamic_mutation_contract(repair);
        } else {
            repair.adapter_status = AdapterStatus::Blocked;
            repair.blocked_reason =
                Some("Email Sending DNS repair or live status-read contract drifted".to_owned());
        }
    }
}

fn finalize_email_routing_subdomain_contract(capabilities: &mut BTreeMap<String, CapabilityV1>) {
    let read_supported = capabilities
        .get("email-routing-settings-email-routing-dns-settings")
        .is_some_and(|capability| {
            capability.method == "GET"
                && capability.path == EMAIL_ROUTING_DNS_PATH
                && capability.selectors.iter().any(|selector| {
                    selector.name == "subdomain"
                        && selector.location == "query"
                        && !selector.required
                })
        });
    let Some(enable) = capabilities.get_mut("email-routing-settings-enable-email-routing-dns")
    else {
        return;
    };
    if !read_supported
        || enable.method != "POST"
        || enable.path != EMAIL_ROUTING_DNS_PATH
        || !enable.request_schema.as_ref().is_some_and(|schema| {
            schema.pointer("/properties/name/type") == Some(&Value::String("string".to_owned()))
        })
    {
        enable.adapter_status = AdapterStatus::Blocked;
        enable.blocked_reason =
            Some("Email Routing subdomain enable or DNS readback contract drifted".to_owned());
        return;
    }
    enable.request_schema = Some(serde_json::json!({
        "type":"object",
        "additionalProperties":false,
        "required":["name"],
        "properties":{
            "name":{"type":"string","minLength":1,"maxLength":253}
        },
        "x-cfctl-body-required":true
    }));
    enable.permissions = vec!["DNS Write".to_owned(), "Zone Settings Write".to_owned()];
    enable.risk = RiskClass::ScopedWrite;
    enable.effect = EffectClass::ReversibleWrite;
    zero_direct_usage_cost(
        enable,
        "enabling Email Routing for one explicit subdomain and creating its required DNS records has no direct operation charge; Email Routing is free",
        vec![official_reference(
            "Email Routing subdomains",
            "https://developers.cloudflare.com/email-routing/setup/subdomains/",
        )],
    );
    enable.entitlement.available = Some(true);
    enable.entitlement.requires_live_resolution = false;
    enable.email_routing_subdomain_dns = Some(EmailRoutingSubdomainDnsContractV1 {
        read_capability_id: "email-routing-settings-email-routing-dns-settings".to_owned(),
        read_path: EMAIL_ROUTING_DNS_PATH.to_owned(),
        request_name_field: "name".to_owned(),
        read_query_field: "subdomain".to_owned(),
    });
    "email_routing_subdomain_dns_records_match".clone_into(&mut enable.verification.strategy);
    enable.rollback.supported = false;
    enable.rollback.strategy = None;
    enable.rollback.warning = Some(
        "no subdomain-scoped provider delete is proven; rollback requires separately reviewed exact DNS-record and routing-rule restoration bound to the complete prior snapshots; never use zone-wide Email Routing disable as subdomain compensation, and apex MX and routing must remain untouched"
            .to_owned(),
    );
    refresh_dynamic_mutation_contract(enable);
}

fn apply_post_normalization_contracts(
    document: &Value,
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    finalize_pages_deployment_id_selector_contracts(capabilities);
    finalize_pages_production_deployment_contract(document, capabilities);
    finalize_worker_script_secret_contracts(document, capabilities);
    classify_exact_resource_contracts(document, capabilities);
    finalize_singleton_resource_delete_contracts(document, capabilities);
    classify_parent_collection_delete_contracts(document, capabilities);
    classify_parent_collection_update_contracts(document, capabilities);
    classify_access_service_token_create_contract(document, capabilities);
    classify_access_service_token_refresh_contract(document, capabilities);
    classify_created_resource_contracts(document, capabilities);
    classify_created_collection_resource_contracts(document, capabilities);
    finalize_pages_project_create_contract(document, capabilities);
    finalize_pages_domain_create_contract(document, capabilities);
    finalize_worker_custom_domain_attach_contract(document, capabilities);
    classify_global_warp_override_contract(document, capabilities);
    classify_same_path_object_mutation_contracts(document, capabilities);
    finalize_r2_bucket_create_contract(document, capabilities);
    finalize_d1_database_create_contract(document, capabilities);
    finalize_workers_kv_namespace_contracts(document, capabilities);
    finalize_r2_temporary_credentials_contract(document, capabilities);
    finalize_zone_cache_purge_contracts(document, capabilities);
    finalize_websocket_zone_setting_contract(document, capabilities);
    finalize_oauth_client_create_update_contracts(document, capabilities);
    finalize_oauth_client_secret_rotation_contract(document, capabilities);
    finalize_global_warp_override_rollback_contract(capabilities);
    finalize_d1_read_replication_rollback_contract(capabilities);
    finalize_cloudflare_tunnel_configuration_rollback_contract(capabilities);
    finalize_warp_connector_configuration_rollback_contract(capabilities);
    finalize_web_analytics_rum_rollback_contract(document, capabilities);
    finalize_dns_record_rollback_contract(document, capabilities);
    finalize_dns_record_delete_response_contract(capabilities);
    finalize_queue_consumer_contracts(document, capabilities);
    finalize_r2_private_file_upload_contract(capabilities);
    finalize_r2_lifecycle_contract(capabilities);
    finalize_email_sending_contracts(capabilities);
    finalize_email_routing_subdomain_contract(capabilities);
    finalize_email_routing_rules_read_projection(capabilities);
    finalize_worker_script_delete_contract(capabilities);
    finalize_access_application_create_contract(document, capabilities);
    finalize_access_application_login_methods_contract(document, capabilities);
    finalize_access_human_policy_contract(document, capabilities);
    for capability in capabilities.values_mut() {
        block_unsupported_response_contract(capability);
    }
}

fn finalize_email_routing_rules_read_projection(capabilities: &mut BTreeMap<String, CapabilityV1>) {
    let Some(capability) = capabilities.get_mut(cfctl_core::EMAIL_ROUTING_RULES_LIST_CAPABILITY_ID)
    else {
        return;
    };
    if !cfctl_core::is_email_routing_rules_list_capability(capability) {
        capability.adapter_status = AdapterStatus::Blocked;
        capability.blocked_reason = Some(
            "Email Routing rules no longer match the pinned typed read-projection contract"
                .to_owned(),
        );
        return;
    }
    capability.description = Some(
        "Lists routing rules as cfctl's bounded `EmailRoutingRuleSetV1` projection; raw non-Worker action values never enter stdout or evidence."
            .to_owned(),
    );
    capability.aliases.extend([
        "typed Email Routing rule set".to_owned(),
        "privacy-safe Email Routing inventory".to_owned(),
    ]);
    capability.aliases.sort();
    capability.aliases.dedup();
}

const PAGES_DEPLOYMENT_CREATE_CAPABILITY_ID: &str = "pages-deployment-create-deployment";
const PAGES_DEPLOYMENT_READ_CAPABILITY_ID: &str = "pages-deployment-get-deployment-info";
const PAGES_DEPLOYMENT_DELETE_CAPABILITY_ID: &str = "pages-deployment-delete-deployment";
const PAGES_DEPLOYMENT_COLLECTION_PATH: &str =
    "/accounts/{account_id}/pages/projects/{project_name}/deployments";
const PAGES_DEPLOYMENT_DETAIL_PATH: &str =
    "/accounts/{account_id}/pages/projects/{project_name}/deployments/{deployment_id}";

#[expect(
    clippy::too_many_lines,
    reason = "the exact Pages create, companion, response, cost, verification, and rollback invariants form one fail-closed classifier"
)]
fn finalize_pages_production_deployment_contract(
    document: &Value,
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    // Cloudflare exposes `force` as an optional bypass for normal delete
    // protections. It is not part of the governed deployment lifecycle and
    // must remain unexpressable through cfctl.
    let delete_force_safely_stripped = capabilities
        .get_mut(PAGES_DEPLOYMENT_DELETE_CAPABILITY_ID)
        .is_some_and(|delete| {
            let force_is_exact_optional_boolean = delete.selectors.len() == 4
                && delete
                    .selectors
                    .iter()
                    .filter(|selector| selector.name == "force")
                    .count()
                    == 1
                && delete.selectors.iter().any(|selector| {
                    selector.name == "force"
                        && selector.location == "query"
                        && !selector.required
                        && selector.value_type == "boolean"
                })
                && ["account_id", "project_name", "deployment_id"]
                    .iter()
                    .all(|name| {
                        delete.selectors.iter().any(|selector| {
                            selector.name == *name
                                && selector.location == "path"
                                && selector.required
                                && selector.value_type == "string"
                        })
                    });
            if !force_is_exact_optional_boolean {
                return false;
            }
            delete.selectors.retain(|selector| selector.name != "force");
            true
        });
    let companions_supported = delete_force_safely_stripped
        && capabilities
            .get(PAGES_DEPLOYMENT_READ_CAPABILITY_ID)
            .is_some_and(|read| {
                read.method == "GET"
                    && read.path == PAGES_DEPLOYMENT_DETAIL_PATH
                    && read.product == "Pages Deployment"
                    && read.permissions == ["Pages Read", "Pages Write"]
                    && read.request_schema.is_none()
                    && read
                        .selectors
                        .iter()
                        .all(|selector| selector.location == "path")
                    && read.response_contract.as_ref().is_some_and(|response| {
                        response.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
                            && response.success_statuses == ["200"]
                            && response.success_media_types == ["application/json"]
                    })
            })
        && capabilities
            .get(PAGES_DEPLOYMENT_DELETE_CAPABILITY_ID)
            .is_some_and(|delete| {
                delete.method == "DELETE"
                    && delete.path == PAGES_DEPLOYMENT_DETAIL_PATH
                    && delete.product == "Pages Deployment"
                    && delete.permissions == ["Pages Write"]
                    && delete.request_schema.is_none()
                    && delete
                        .selectors
                        .iter()
                        .all(|selector| selector.location == "path")
            });
    let Some(create_operation) = document
        .get("paths")
        .and_then(Value::as_object)
        .and_then(|paths| paths.get(PAGES_DEPLOYMENT_COLLECTION_PATH))
        .and_then(|path| path.get("post"))
    else {
        return;
    };
    let Some(read_operation) = document
        .get("paths")
        .and_then(Value::as_object)
        .and_then(|paths| paths.get(PAGES_DEPLOYMENT_DETAIL_PATH))
        .and_then(|path| path.get("get"))
    else {
        return;
    };
    let response_shape_supported = [create_operation, read_operation].iter().all(|operation| {
        ["id", "environment", "project_name"]
            .iter()
            .all(|field| success_response_declares_result_string_field(document, operation, field))
            && operation
                .get("responses")
                .and_then(Value::as_object)
                .into_iter()
                .flatten()
                .filter(|(status, _)| status.starts_with('2'))
                .filter_map(|(_, response)| response.pointer("/content/application~1json/schema"))
                .any(|schema| {
                    schema_declares_string_path(
                        document,
                        schema,
                        &["result", "latest_stage", "status"],
                        0,
                    )
                })
    });
    let Some(create) = capabilities.get_mut(PAGES_DEPLOYMENT_CREATE_CAPABILITY_ID) else {
        return;
    };
    let identity_supported = create.method == "POST"
        && create.path == PAGES_DEPLOYMENT_COLLECTION_PATH
        && create.product == "Pages Deployment"
        && create.title == "Create deployment"
        && create.description.as_deref()
            == Some(
                "Start a new deployment from production. The repository and account must have already been authorized on the Cloudflare Pages dashboard.",
            )
        && create.maturity == Maturity::GenerallyAvailable
        && create.permissions == ["Pages Write"]
        && create.request_schema.is_none()
        && create
            .selectors
            .iter()
            .all(|selector| selector.location == "path")
        && create.response_contract.as_ref().is_some_and(|response| {
            response.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
                && response.success_statuses == ["200"]
                && response.success_media_types == ["application/json"]
        });
    if !(identity_supported && companions_supported && response_shape_supported) {
        return;
    }

    create.risk = RiskClass::CrossConfig;
    create.effect = EffectClass::ReversibleWrite;
    create.cost.known = true;
    create.cost.incremental = false;
    create.cost.maximum = Some(0.0);
    create.cost.billing_model = BillingModelV1::UsageBased;
    create.cost.exposure = CostExposureV1::DownstreamUsage;
    create.cost.basis = Some(
        "starting a Pages production deployment has no direct API-operation charge; the build, Functions, and bandwidth can create plan-specific downstream usage"
            .to_owned(),
    );
    create.created_resource = Some(CreatedResourceContractV1 {
        detail_path: PAGES_DEPLOYMENT_DETAIL_PATH.to_owned(),
        identity_selector: "deployment_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        read_capability_id: PAGES_DEPLOYMENT_READ_CAPABILITY_ID.to_owned(),
        delete_capability_id: PAGES_DEPLOYMENT_DELETE_CAPABILITY_ID.to_owned(),
        verified_response_fields: vec!["environment".to_owned(), "project_name".to_owned()],
    });
    "pages_production_deployment_succeeds_by_returned_id"
        .clone_into(&mut create.verification.strategy);
    create.rollback.supported = false;
    create.rollback.strategy = None;
    create.rollback.warning = Some(
        "restoring production traffic requires a separate reviewed Pages rollback to a known successful deployment; rollback does not erase the deployment, reverse Pages Functions side effects, or refund usage"
            .to_owned(),
    );
    // The exact operation, companions, and response shapes above have replaced
    // the generic incomplete contract. Re-enter the dynamic adapter lane before
    // recomputing gaps so core support is evaluated against its real carrier.
    create.adapter_status = AdapterStatus::DynamicApi;
    create.blocked_reason = None;
    refresh_dynamic_mutation_contract(create);
}

const PAGES_DEPLOYMENT_DETAIL_PATH_PREFIX: &str =
    "/accounts/{account_id}/pages/projects/{project_name}/deployments/{deployment_id}";

/// Cloudflare Pages deployment identifiers are UUIDs. The generated `OpenAPI`
/// currently reuses the 32-character account identifier bound for this path
/// selector, which rejects the API's canonical 36-character deployment IDs
/// before a governed read can reach the provider. Keep this correction scoped
/// to Pages deployment-resource paths and preserve every other selector bound.
fn finalize_pages_deployment_id_selector_contracts(
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    for capability in capabilities.values_mut().filter(|capability| {
        capability
            .path
            .starts_with(PAGES_DEPLOYMENT_DETAIL_PATH_PREFIX)
    }) {
        let Some(selector) = capability.selectors.iter_mut().find(|selector| {
            selector.name == "deployment_id"
                && selector.location == "path"
                && selector.value_type == "string"
        }) else {
            continue;
        };
        selector.contract = Some(SelectorContractV1 {
            schema: serde_json::json!({
                "type": "string",
                "minLength": 36,
                "maxLength": 36,
                "pattern": "^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"
            }),
            query: None,
        });
    }
}

const PAGES_PROJECT_CREATE_CAPABILITY_ID: &str = "pages-project-create-project";
const PAGES_PROJECT_READ_CAPABILITY_ID: &str = "pages-project-get-project";
const PAGES_PROJECT_DELETE_CAPABILITY_ID: &str = "pages-project-delete-project";
const PAGES_PROJECT_COLLECTION_PATH: &str = "/accounts/{account_id}/pages/projects";
const PAGES_PROJECT_DETAIL_PATH: &str = "/accounts/{account_id}/pages/projects/{project_name}";

fn finalize_pages_project_create_contract(
    document: &Value,
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    let companions_supported = capabilities
        .get(PAGES_PROJECT_READ_CAPABILITY_ID)
        .is_some_and(|capability| {
            capability.method == "GET"
                && capability.path == PAGES_PROJECT_DETAIL_PATH
                && capability.product == "Pages Project"
                && capability
                    .selectors
                    .iter()
                    .all(|selector| selector.location == "path")
        })
        && capabilities
            .get(PAGES_PROJECT_DELETE_CAPABILITY_ID)
            .is_some_and(|capability| {
                capability.method == "DELETE"
                    && capability.path == PAGES_PROJECT_DETAIL_PATH
                    && capability.product == "Pages Project"
                    && capability.permissions == ["Pages Write"]
            });
    let create_operation =
        document.pointer("/paths/~1accounts~1{account_id}~1pages~1projects/post");
    let read_operation =
        document.pointer("/paths/~1accounts~1{account_id}~1pages~1projects~1{project_name}/get");
    let response_fields = ["build_config", "name", "production_branch", "source"];
    let response_supported = create_operation.is_some_and(|operation| {
        success_response_declares_result_string_field(document, operation, "name")
            && success_response_declares_result_fields(document, operation, &response_fields)
    }) && read_operation.is_some_and(|operation| {
        success_response_declares_result_string_field(document, operation, "name")
            && success_response_declares_result_fields(document, operation, &response_fields)
    });

    let Some(capability) = capabilities.get_mut(PAGES_PROJECT_CREATE_CAPABILITY_ID) else {
        return;
    };
    let create_supported = capability.method == "POST"
        && capability.path == PAGES_PROJECT_COLLECTION_PATH
        && capability.product == "Pages Project"
        && capability.permissions == ["Pages Write"]
        && pages_project_upstream_request_supported(capability.request_schema.as_ref());
    if !create_supported || !companions_supported || !response_supported {
        capability.created_resource = None;
        capability.adapter_status = AdapterStatus::Blocked;
        capability.blocked_reason = Some(format!(
            "Pages Git-integrated project create, exact readback, delete, or response contract drifted (create={create_supported}, companions={companions_supported}, response={response_supported})"
        ));
        return;
    }

    capability.request_schema = Some(pages_git_project_create_request_schema());
    capability.risk = RiskClass::CrossConfig;
    capability.effect = EffectClass::ReversibleWrite;
    capability.cost = CostV1::default();
    capability.cost.billing_model = BillingModelV1::UsageBased;
    capability.cost.exposure = CostExposureV1::DownstreamUsage;
    capability.cost.maximum = Some(0.0);
    capability.cost.basis = Some(
        "creating one Git-integrated Pages project has no direct API-operation charge; the closed request contract excludes deployment configuration and resource bindings, but Git integration starts and continues builds/deployments, and any Pages Functions present in repository output plus build quotas remain plan-specific downstream exposure"
            .to_owned(),
    );
    capability.cost.references = vec![
        official_reference(
            "Cloudflare Pages pricing",
            "https://developers.cloudflare.com/pages/functions/pricing/",
        ),
        official_reference(
            "Cloudflare Pages Git integration",
            "https://developers.cloudflare.com/pages/configuration/git-integration/",
        ),
    ];
    capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: PAGES_PROJECT_DETAIL_PATH.to_owned(),
        identity_selector: "project_name".to_owned(),
        response_result_identity_pointer: "/name".to_owned(),
        read_capability_id: PAGES_PROJECT_READ_CAPABILITY_ID.to_owned(),
        delete_capability_id: PAGES_PROJECT_DELETE_CAPABILITY_ID.to_owned(),
        verified_response_fields: response_fields.map(str::to_owned).to_vec(),
    });
    capability.verification.required = true;
    "created_resource_contains_planned_fields_by_returned_id"
        .clone_into(&mut capability.verification.strategy);
    capability.rollback.supported = true;
    capability.rollback.strategy = Some("delete_created_resource_by_returned_id".to_owned());
    capability.rollback.warning = Some(
        "compensation creates a separate exact-project deletion plan that must be reviewed and explicitly approved; deletion removes the Pages project and deployments but does not delete the connected Git repository"
            .to_owned(),
    );
    refresh_dynamic_mutation_contract(capability);
}

fn pages_project_upstream_request_supported(schema: Option<&Value>) -> bool {
    let Some(schema) = schema else {
        return false;
    };
    let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
        return false;
    };
    let has_string = |object: &serde_json::Map<String, Value>, field: &str| {
        object
            .get(field)
            .and_then(|field| field.get("type"))
            .and_then(Value::as_str)
            == Some("string")
    };
    let Some(build) = properties
        .get("build_config")
        .and_then(|value| value.get("properties"))
        .and_then(Value::as_object)
    else {
        return false;
    };
    let Some(source) = properties
        .get("source")
        .and_then(|value| value.get("properties"))
        .and_then(Value::as_object)
    else {
        return false;
    };
    let Some(source_config) = source
        .get("config")
        .and_then(|value| value.get("properties"))
        .and_then(Value::as_object)
    else {
        return false;
    };
    let source_types = source
        .get("type")
        .and_then(|value| value.get("enum"))
        .and_then(Value::as_array);
    let required = schema.get("required").and_then(Value::as_array);
    let source_required = properties
        .get("source")
        .and_then(|value| value.get("required"))
        .and_then(Value::as_array);
    schema.get("type").and_then(Value::as_str) == Some("object")
        && required.is_some_and(|required| {
            ["name", "production_branch"]
                .iter()
                .all(|field| required.contains(&Value::String((*field).to_owned())))
        })
        && has_string(properties, "name")
        && has_string(properties, "production_branch")
        && ["build_command", "destination_dir", "root_dir"]
            .iter()
            .all(|field| has_string(build, field))
        && source_types.is_some_and(|types| types.contains(&Value::String("github".to_owned())))
        && source_required.is_some_and(|required| {
            ["type", "config"]
                .iter()
                .all(|field| required.contains(&Value::String((*field).to_owned())))
        })
        && [
            "owner",
            "owner_id",
            "production_branch",
            "repo_id",
            "repo_name",
        ]
        .iter()
        .all(|field| has_string(source_config, field))
        && [
            "deployments_enabled",
            "pr_comments_enabled",
            "production_deployments_enabled",
        ]
        .iter()
        .all(|field| {
            source_config
                .get(*field)
                .and_then(|value| value.get("type"))
                .and_then(Value::as_str)
                == Some("boolean")
        })
        && source_config
            .get("preview_deployment_setting")
            .and_then(|value| value.get("enum"))
            .and_then(Value::as_array)
            .is_some_and(|values| {
                ["all", "none", "custom"]
                    .iter()
                    .all(|value| values.contains(&Value::String((*value).to_owned())))
            })
}

fn pages_git_project_create_request_schema() -> Value {
    serde_json::json!({
        "type":"object",
        "additionalProperties":false,
        "x-cfctl-body-required":true,
        "required":["name","production_branch","build_config","source"],
        "properties":{
            "name":{"type":"string","minLength":1},
            "production_branch":{"type":"string","enum":["main"]},
            "build_config":{
                "type":"object",
                "additionalProperties":false,
                "required":["build_command","destination_dir"],
                "properties":{
                    "build_command":{"type":"string","minLength":1},
                    "destination_dir":{"type":"string","minLength":1},
                    "root_dir":{"type":"string"}
                }
            },
            "source":{
                "type":"object",
                "additionalProperties":false,
                "required":["type","config"],
                "properties":{
                    "type":{"type":"string","enum":["github"]},
                    "config":{
                        "type":"object",
                        "additionalProperties":false,
                        "required":[
                            "deployments_enabled","owner","owner_id","preview_deployment_setting",
                            "production_branch","production_deployments_enabled","repo_id","repo_name"
                        ],
                        "properties":{
                            "deployments_enabled":{"type":"boolean","enum":[true]},
                            "owner":{"type":"string","minLength":1},
                            "owner_id":{"type":"string","minLength":1},
                            "preview_deployment_setting":{"type":"string","enum":["all"]},
                            "production_branch":{"type":"string","enum":["main"]},
                            "production_deployments_enabled":{"type":"boolean","enum":[true]},
                            "repo_id":{"type":"string","minLength":1},
                            "repo_name":{"type":"string","minLength":1}
                        }
                    }
                }
            }
        }
    })
}

const PAGES_DOMAIN_CREATE_CAPABILITY_ID: &str = "pages-domains-add-domain";
const PAGES_DOMAIN_READ_CAPABILITY_ID: &str = "pages-domains-get-domain";
const PAGES_DOMAIN_DELETE_CAPABILITY_ID: &str = "pages-domains-delete-domain";
const PAGES_DOMAIN_COLLECTION_PATH: &str =
    "/accounts/{account_id}/pages/projects/{project_name}/domains";
const PAGES_DOMAIN_DETAIL_PATH: &str =
    "/accounts/{account_id}/pages/projects/{project_name}/domains/{domain_name}";

fn finalize_pages_domain_create_contract(
    document: &Value,
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    let companions_supported = capabilities
        .get(PAGES_DOMAIN_READ_CAPABILITY_ID)
        .is_some_and(|capability| {
            capability.method == "GET"
                && capability.path == PAGES_DOMAIN_DETAIL_PATH
                && capability.product == "Pages Domains"
                && capability
                    .selectors
                    .iter()
                    .all(|selector| selector.location == "path")
        })
        && capabilities
            .get(PAGES_DOMAIN_DELETE_CAPABILITY_ID)
            .is_some_and(|capability| {
                capability.method == "DELETE"
                    && capability.path == PAGES_DOMAIN_DETAIL_PATH
                    && capability.product == "Pages Domains"
            });
    let create_operation = document
        .pointer("/paths/~1accounts~1{account_id}~1pages~1projects~1{project_name}~1domains/post");
    let read_operation = document.pointer(
        "/paths/~1accounts~1{account_id}~1pages~1projects~1{project_name}~1domains~1{domain_name}/get",
    );
    let response_supported = create_operation.is_some_and(|operation| {
        success_response_declares_result_string_field(document, operation, "name")
    }) && read_operation.is_some_and(|operation| {
        success_response_declares_result_string_field(document, operation, "name")
    });

    let Some(capability) = capabilities.get_mut(PAGES_DOMAIN_CREATE_CAPABILITY_ID) else {
        return;
    };
    let create_supported = capability.method == "POST"
        && capability.path == PAGES_DOMAIN_COLLECTION_PATH
        && capability.product == "Pages Domains"
        && capability.permissions == ["Pages Write"]
        && capability.request_schema.as_ref()
            == Some(&serde_json::json!({
                "properties": {"name": {"type": "string"}},
                "required": ["name"],
                "type": "object",
                "x-cfctl-body-required": true
            }));
    if !create_supported || !companions_supported || !response_supported {
        capability.created_resource = None;
        capability.adapter_status = AdapterStatus::Blocked;
        capability.blocked_reason = Some(format!(
            "Pages domain create, exact readback, delete, or response contract drifted (create={create_supported}, companions={companions_supported}, response={response_supported})"
        ));
        return;
    }

    capability.risk = RiskClass::CrossConfig;
    capability.effect = EffectClass::ReversibleWrite;
    capability.cost = CostV1::default();
    capability.cost.billing_model = BillingModelV1::UsageBased;
    capability.cost.exposure = CostExposureV1::DownstreamUsage;
    capability.cost.maximum = Some(0.0);
    capability.cost.basis = Some(
        "attaching a custom domain has no direct operation charge; ordinary Pages Functions and bandwidth usage remains plan-specific"
            .to_owned(),
    );
    capability.cost.references = vec![official_reference(
        "Cloudflare Pages Functions pricing",
        "https://developers.cloudflare.com/pages/functions/pricing/",
    )];
    capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: PAGES_DOMAIN_DETAIL_PATH.to_owned(),
        identity_selector: "domain_name".to_owned(),
        response_result_identity_pointer: "/name".to_owned(),
        read_capability_id: PAGES_DOMAIN_READ_CAPABILITY_ID.to_owned(),
        delete_capability_id: PAGES_DOMAIN_DELETE_CAPABILITY_ID.to_owned(),
        verified_response_fields: vec!["name".to_owned()],
    });
    capability.verification.required = true;
    "created_resource_contains_planned_fields_by_returned_id"
        .clone_into(&mut capability.verification.strategy);
    capability.rollback.supported = true;
    capability.rollback.strategy = Some("delete_created_resource_by_returned_id".to_owned());
    capability.rollback.warning = Some(
        "compensation creates a separate exact-domain delete plan that must be reviewed and explicitly approved"
            .to_owned(),
    );
    refresh_dynamic_mutation_contract(capability);
}

const WORKER_DOMAIN_ATTACH_CAPABILITY_ID: &str = "workers.domains.update";
const WORKER_DOMAIN_READ_CAPABILITY_ID: &str = "workers.domains.get";
const WORKER_DOMAIN_DELETE_CAPABILITY_ID: &str = "workers.domains.delete";
const WORKER_DOMAIN_COLLECTION_PATH: &str = "/accounts/{account_id}/workers/domains";
const WORKER_DOMAIN_DETAIL_PATH: &str = "/accounts/{account_id}/workers/domains/{domain_id}";
const WORKER_DOMAIN_DNS_LIST_CAPABILITY_ID: &str = "dns-records-for-a-zone-list-dns-records";
const WORKER_DOMAIN_DNS_LIST_PATH: &str = "/zones/{zone_id}/dns_records";
const WORKER_DOMAIN_ATTACH_LIFECYCLE_PERMISSIONS: [&str; 2] = ["Workers Scripts Write", "DNS Read"];

fn worker_domain_path_selectors_supported(capability: &CapabilityV1, expected: &[&str]) -> bool {
    capability.selectors.len() == expected.len()
        && expected.iter().all(|name| {
            capability.selectors.iter().any(|selector| {
                selector.name == *name
                    && selector.location == "path"
                    && selector.required
                    && selector.value_type == "string"
            })
        })
}

fn worker_domain_upstream_request_supported(schema: Option<&Value>) -> bool {
    schema
        == Some(&serde_json::json!({
            "allOf": [
                {
                    "properties": {
                        "hostname": {"type": "string"},
                        "service": {"type": "string"},
                        "zone_id": {"type": "string"},
                        "zone_name": {"type": "string"}
                    },
                    "required": ["zone_id", "zone_name", "hostname", "service"],
                    "type": "object"
                },
                {
                    "required": ["hostname", "service"],
                    "type": "object"
                }
            ],
            "x-cfctl-body-required": true
        }))
}

fn worker_domain_attach_request_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "x-cfctl-body-required": true,
        "required": ["hostname", "service", "zone_id"],
        "properties": {
            "hostname": {"type": "string", "minLength": 1, "maxLength": 253},
            "service": {"type": "string", "minLength": 1},
            "zone_id": {"type": "string", "minLength": 32, "maxLength": 32}
        }
    })
}

fn worker_domain_companions_supported(capabilities: &BTreeMap<String, CapabilityV1>) -> bool {
    capabilities
        .get(WORKER_DOMAIN_READ_CAPABILITY_ID)
        .is_some_and(|capability| {
            capability.method == "GET"
                && capability.path == WORKER_DOMAIN_DETAIL_PATH
                && capability.product == "Domains"
                && capability.account_scope == "account"
                && capability.permissions == ["Workers Scripts Write", "Workers Scripts Read"]
                && worker_domain_path_selectors_supported(capability, &["account_id", "domain_id"])
        })
        && capabilities
            .get(WORKER_DOMAIN_DELETE_CAPABILITY_ID)
            .is_some_and(|capability| {
                capability.method == "DELETE"
                    && capability.path == WORKER_DOMAIN_DETAIL_PATH
                    && capability.product == "Domains"
                    && capability.account_scope == "account"
                    && capability.permissions == ["Workers Scripts Write"]
                    && capability.request_schema.is_none()
                    && worker_domain_path_selectors_supported(
                        capability,
                        &["account_id", "domain_id"],
                    )
            })
}

fn worker_domain_dns_conflict_read_supported(
    capabilities: &BTreeMap<String, CapabilityV1>,
) -> bool {
    capabilities
        .get(WORKER_DOMAIN_DNS_LIST_CAPABILITY_ID)
        .is_some_and(|capability| {
            capability.method == "GET"
                && capability.path == WORKER_DOMAIN_DNS_LIST_PATH
                && capability.product == "DNS Records for a Zone"
                && capability.account_scope == "zone"
                && !capability.mutating
                && capability.request_schema.is_none()
                && capability
                    .permissions
                    .iter()
                    .any(|permission| permission == "DNS Read")
                && capability.selectors.iter().any(|selector| {
                    selector.name == "zone_id"
                        && selector.location == "path"
                        && selector.required
                        && selector.value_type == "string"
                })
                && capability.selectors.iter().any(|selector| {
                    selector.name == "name.exact"
                        && selector.location == "query"
                        && !selector.required
                        && selector.value_type == "string"
                })
                && capability
                    .response_contract
                    .as_ref()
                    .is_some_and(|contract| {
                        contract.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
                            && contract.success_statuses == ["200"]
                            && contract.success_media_types == ["application/json"]
                    })
        })
}

fn worker_domain_responses_supported(document: &Value) -> bool {
    let attach_operation =
        document.pointer("/paths/~1accounts~1{account_id}~1workers~1domains/put");
    let read_operation =
        document.pointer("/paths/~1accounts~1{account_id}~1workers~1domains~1{domain_id}/get");
    let response_fields = [
        "cert_id",
        "hostname",
        "id",
        "service",
        "zone_id",
        "zone_name",
    ];
    attach_operation.is_some_and(|operation| {
        success_response_declares_result_string_field(document, operation, "id")
            && success_response_declares_result_fields(document, operation, &response_fields)
    }) && read_operation.is_some_and(|operation| {
        success_response_declares_result_string_field(document, operation, "id")
            && success_response_declares_result_fields(document, operation, &response_fields)
    })
}

fn finalize_worker_custom_domain_attach_contract(
    document: &Value,
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    let companions_supported = worker_domain_companions_supported(capabilities);
    let dns_conflict_read_supported = worker_domain_dns_conflict_read_supported(capabilities);
    let response_supported = worker_domain_responses_supported(document);

    let Some(capability) = capabilities.get_mut(WORKER_DOMAIN_ATTACH_CAPABILITY_ID) else {
        return;
    };
    let attach_supported = capability.method == "PUT"
        && capability.path == WORKER_DOMAIN_COLLECTION_PATH
        && capability.product == "Domains"
        && capability.account_scope == "account"
        && capability.permissions == ["Workers Scripts Write"]
        && worker_domain_path_selectors_supported(capability, &["account_id"])
        && worker_domain_upstream_request_supported(capability.request_schema.as_ref());
    if !attach_supported
        || !companions_supported
        || !dns_conflict_read_supported
        || !response_supported
    {
        capability.created_resource = None;
        capability.adapter_status = AdapterStatus::Blocked;
        capability.blocked_reason = Some(format!(
            "Worker custom-domain attach, exact readback, detach, DNS conflict read, request, permission, or response contract drifted (attach={attach_supported}, companions={companions_supported}, dns_conflict_read={dns_conflict_read_supported}, response={response_supported})"
        ));
        return;
    }

    capability.permissions = WORKER_DOMAIN_ATTACH_LIFECYCLE_PERMISSIONS
        .into_iter()
        .map(str::to_owned)
        .collect();
    capability.request_schema = Some(worker_domain_attach_request_schema());
    capability.risk = RiskClass::CrossConfig;
    capability.effect = EffectClass::ReversibleWrite;
    capability.entitlement.available = Some(true);
    capability.entitlement.source = Some(
        "https://developers.cloudflare.com/workers/configuration/routing/custom-domains/"
            .to_owned(),
    );
    capability.cost = CostV1::default();
    capability.cost.billing_model = BillingModelV1::UsageBased;
    capability.cost.exposure = CostExposureV1::DownstreamUsage;
    capability.cost.maximum = Some(0.0);
    capability.cost.basis = Some(
        "attaching one exact hostname to a Worker has no direct attachment charge; traffic routed through the Worker retains plan-specific request and CPU usage exposure"
            .to_owned(),
    );
    capability.cost.references = vec![
        official_reference(
            "Cloudflare Workers custom domains",
            "https://developers.cloudflare.com/workers/configuration/routing/custom-domains/",
        ),
        official_reference(
            "Cloudflare Workers pricing",
            "https://developers.cloudflare.com/workers/platform/pricing/",
        ),
    ];
    capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: WORKER_DOMAIN_DETAIL_PATH.to_owned(),
        identity_selector: "domain_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        read_capability_id: WORKER_DOMAIN_READ_CAPABILITY_ID.to_owned(),
        delete_capability_id: WORKER_DOMAIN_DELETE_CAPABILITY_ID.to_owned(),
        verified_response_fields: vec![
            "hostname".to_owned(),
            "service".to_owned(),
            "zone_id".to_owned(),
        ],
    });
    capability.verification.required = true;
    "created_resource_contains_planned_fields_by_returned_id"
        .clone_into(&mut capability.verification.strategy);
    capability.rollback.supported = true;
    capability.rollback.strategy = Some("delete_created_resource_by_returned_id".to_owned());
    capability.rollback.warning = Some(
        "compensation creates a separate exact-domain detach plan that must be reviewed and explicitly approved; detaching does not remove an associated Advanced Certificate and cannot undo traffic already served"
            .to_owned(),
    );
    refresh_dynamic_mutation_contract(capability);
}

fn classify_same_path_object_mutation_contracts(
    document: &Value,
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    let readback_targets = capabilities
        .values()
        .filter_map(|capability| {
            if capability.method != "GET" {
                return None;
            }
            let routing_headers = same_path_readback_routing_headers(capability)?;
            Some((
                (
                    capability.path.clone(),
                    capability.product.clone(),
                    routing_headers,
                ),
                capability.id.clone(),
            ))
        })
        .collect::<BTreeMap<_, _>>();

    for capability in capabilities.values_mut() {
        if !matches!(capability.method.as_str(), "PATCH" | "POST" | "PUT")
            || capability.verification.strategy != "post_change_read_or_operation_specific_verifier"
        {
            continue;
        }
        let Some(routing_headers) = same_path_mutation_routing_headers(capability) else {
            continue;
        };
        let Some(read_capability_id) = readback_targets.get(&(
            capability.path.clone(),
            capability.product.clone(),
            routing_headers,
        )) else {
            continue;
        };
        let Some(fields) = canonical_verifiable_request_object_fields(capability) else {
            continue;
        };
        let Some(read_operation) = document
            .get("paths")
            .and_then(Value::as_object)
            .and_then(|paths| paths.get(&capability.path))
            .and_then(|path| path.get("get"))
        else {
            continue;
        };
        let field_names = fields.iter().map(String::as_str).collect::<Vec<_>>();
        if !success_response_declares_result_fields(document, read_operation, &field_names) {
            continue;
        }

        capability.same_path_read = Some(SamePathReadContractV1 {
            path: capability.path.clone(),
            read_capability_id: read_capability_id.clone(),
            verified_response_fields: fields,
        });
        if capability.method == "POST" {
            "same_path_result_contains_planned_fields_after_mutation"
                .clone_into(&mut capability.verification.strategy);
        } else {
            "same_path_result_contains_planned_fields_after_update"
                .clone_into(&mut capability.verification.strategy);
        }
        capability.rollback.supported = false;
        capability.rollback.strategy = None;
        if capability.rollback.warning.as_deref()
            == Some("rollback semantics have not been declared")
        {
            capability.rollback.warning = Some(if capability.method == "POST" {
                "automatic reversal is unsupported because the plan does not bind prior state; reversal requires a separately reviewed operation built from trusted evidence"
                    .to_owned()
            } else {
                "automatic restoration is unsupported because the plan does not bind a pre-change snapshot; restoration requires a separately reviewed update plan built from trusted evidence"
                    .to_owned()
            });
        }
        refresh_dynamic_mutation_contract(capability);
    }
}

fn classify_global_warp_override_contract(
    document: &Value,
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    let Some(capability) = capabilities.get_mut("devices-resilience-set-global-warp-override")
    else {
        return;
    };
    if !global_warp_override_source_contract_supported(document, capability) {
        return;
    }

    let Some(request_schema) = capability
        .request_schema
        .as_mut()
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    let Some(justification) = request_schema
        .get_mut("properties")
        .and_then(Value::as_object_mut)
        .and_then(|properties| properties.get_mut("justification"))
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    justification.insert(
        "x-cfctl-verification-observable".to_owned(),
        Value::Bool(false),
    );
    request_schema.insert("additionalProperties".to_owned(), Value::Bool(false));

    capability.risk = RiskClass::CrossConfig;
    capability.effect = EffectClass::ReversibleWrite;
    capability.entitlement.available = Some(true);
    capability.entitlement.plans =
        BTreeMap::from([("free".to_owned(), true), ("paid".to_owned(), true)]);
    capability.entitlement.source = Some(
        "https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/configure/settings/"
            .to_owned(),
    );
    capability.cost = cfctl_core::CostV1::default();
    capability.cost.billing_model = BillingModelV1::Subscription;
    capability.cost.exposure = CostExposureV1::DownstreamUsage;
    capability.cost.basis = Some(
        "Cloudflare documents the global disconnect setting as available on all Zero Trust plans; setting or clearing it has no direct incremental operation charge, while existing Zero Trust subscription and seat charges remain unchanged"
            .to_owned(),
    );
    capability.cost.references = vec![
        KnowledgeReferenceV1 {
            title: "Set Global WARP override state".to_owned(),
            url: "https://developers.cloudflare.com/api/resources/zero_trust/subresources/devices/subresources/resilience/subresources/global_warp_override/methods/create/"
                .to_owned(),
            source: "official Cloudflare API reference".to_owned(),
        },
        KnowledgeReferenceV1 {
            title: "Cloudflare One Client device settings".to_owned(),
            url: "https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/configure/settings/"
                .to_owned(),
            source: "official Cloudflare docs".to_owned(),
        },
    ];
    capability.rollback.supported = false;
    capability.rollback.strategy = None;
    capability.rollback.warning = Some(
        "automatic restoration remains unavailable until cfctl proves an exact same-path state readback contract. Cloudflare documents that this account-wide control requires the Super Administrator role and may take up to 10 minutes to propagate to devices"
            .to_owned(),
    );
    refresh_dynamic_mutation_contract(capability);
}

fn finalize_global_warp_override_rollback_contract(
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    let Some(capability) = capabilities.get_mut("devices-resilience-set-global-warp-override")
    else {
        return;
    };
    capability.rollback.supported = true;
    capability.rollback.strategy =
        Some("restore_global_warp_override_prior_disconnect_state".to_owned());
    if !capability.rollback_contract_supported() {
        capability.rollback.supported = false;
        capability.rollback.strategy = None;
        return;
    }
    capability.rollback.warning = Some(
        "rectification derives a separate hash-bound restoration plan from the prior disconnect state; it never runs automatically and requires explicit approval. Cloudflare documents that this account-wide control requires the Super Administrator role and may take up to 10 minutes to propagate to devices"
            .to_owned(),
    );
    refresh_dynamic_mutation_contract(capability);
}

fn finalize_d1_read_replication_rollback_contract(
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    for capability_id in ["d1-update-database", "d1-update-partial-database"] {
        let Some(capability) = capabilities.get_mut(capability_id) else {
            continue;
        };
        capability.rollback.supported = true;
        capability.rollback.strategy = Some("restore_d1_read_replication_prior_mode".to_owned());
        if !capability.rollback_contract_supported() {
            capability.rollback.supported = false;
            capability.rollback.strategy = None;
            continue;
        }
        capability.rollback.warning = Some(
            "rectification derives a separate hash-bound restoration plan from the prior read-replication mode; it never runs automatically and requires explicit approval"
                .to_owned(),
        );
        refresh_dynamic_mutation_contract(capability);
    }
}

const DNS_RECORD_DETAIL_PATH: &str = cfctl_core::DNS_RECORD_DETAIL_PATH;
const DNS_RECORD_DETAIL_READ_CAPABILITY_ID: &str = cfctl_core::DNS_RECORD_DETAIL_READ_CAPABILITY_ID;
const DNS_RECORD_RESTORE_FIELDS: [&str; 11] = [
    "comment",
    "content",
    "data",
    "name",
    "priority",
    "private_routing",
    "proxied",
    "settings",
    "tags",
    "ttl",
    "type",
];

fn finalize_dns_record_rollback_contract(
    document: &Value,
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    let source_supported = capabilities
        .get(DNS_RECORD_DETAIL_READ_CAPABILITY_ID)
        .is_some_and(dns_record_detail_read_contract_supported)
        && document
            .get("paths")
            .and_then(Value::as_object)
            .and_then(|paths| paths.get(DNS_RECORD_DETAIL_PATH))
            .and_then(|path| path.get("get"))
            .is_some_and(|operation| {
                let mut fields = DNS_RECORD_RESTORE_FIELDS.to_vec();
                fields.push("id");
                fields.sort_unstable();
                success_response_declares_result_field_union(document, operation, &fields)
            });
    if !source_supported {
        return;
    }
    for capability_id in [
        "dns-records-for-a-zone-update-dns-record",
        "dns-records-for-a-zone-patch-dns-record",
    ] {
        let Some(capability) = capabilities.get_mut(capability_id) else {
            continue;
        };
        if !dns_record_detail_routing_contract_supported(capability) {
            continue;
        }
        capability.same_path_read = Some(SamePathReadContractV1 {
            path: DNS_RECORD_DETAIL_PATH.to_owned(),
            read_capability_id: DNS_RECORD_DETAIL_READ_CAPABILITY_ID.to_owned(),
            verified_response_fields: DNS_RECORD_RESTORE_FIELDS
                .iter()
                .map(ToString::to_string)
                .collect(),
        });
        capability.rollback.supported = true;
        capability.rollback.strategy =
            Some("restore_dns_record_prior_snapshot_with_put".to_owned());
        if !capability.rollback_contract_supported() {
            capability.rollback.supported = false;
            capability.rollback.strategy = None;
            capability.same_path_read = None;
            continue;
        }
        capability.rollback.warning = Some(
            "rectification derives a separate hash-bound DNS record PUT plan from the prior writable record snapshot; it never runs automatically and requires explicit approval"
                .to_owned(),
        );
        refresh_dynamic_mutation_contract(capability);
    }
}

/// Cloudflare's `OpenAPI` under-declares the DNS record delete 200-response:
/// the declared schema carries no top-level boolean `success`, so the derived
/// body mode lands `Unsupported` and the one remaining member of an otherwise
/// fully-governed lifecycle stays blocked. The live API answers with the full
/// envelope — `{"result":{"id":…},"success":true,"errors":[],"messages":[]}`,
/// HTTP 200, `application/json`, observed live 2026-07-19 against a real zone
/// record — so the honest repair is to pin the body mode to what Cloudflare
/// actually returns. Identity is positively re-confirmed first so the pin can
/// never leak to another capability, and the pin flips only the exact
/// `Unsupported` + 200-json contract it was written against.
fn finalize_dns_record_delete_response_contract(capabilities: &mut BTreeMap<String, CapabilityV1>) {
    let Some(capability) = capabilities.get_mut("dns-records-for-a-zone-delete-dns-record") else {
        return;
    };
    let identity_confirmed = capability.method == "DELETE"
        && capability.path == DNS_RECORD_DETAIL_PATH
        && capability.mutating
        && capability.request_schema.is_none()
        && capability.selectors.len() == 2
        && ["zone_id", "dns_record_id"].iter().all(|name| {
            capability.selectors.iter().any(|selector| {
                selector.name == *name && selector.location == "path" && selector.required
            })
        });
    if !identity_confirmed {
        return;
    }
    let Some(response) = capability.response_contract.as_mut() else {
        return;
    };
    if response.body_mode != ResponseBodyModeV1::Unsupported
        || response.success_statuses != ["200"]
        || response.success_media_types != ["application/json"]
    {
        return;
    }
    response.body_mode = ResponseBodyModeV1::CloudflareJsonEnvelope;
    refresh_dynamic_mutation_contract(capability);
}

fn dns_record_detail_read_contract_supported(capability: &CapabilityV1) -> bool {
    capability.id == DNS_RECORD_DETAIL_READ_CAPABILITY_ID
        && capability.method == "GET"
        && capability.path == DNS_RECORD_DETAIL_PATH
        && capability.product == "DNS Records for a Zone"
        && capability.account_scope == "zone"
        && !capability.mutating
        && capability.request_schema.is_none()
        && dns_record_detail_routing_contract_supported(capability)
        && capability
            .response_contract
            .as_ref()
            .is_some_and(|contract| {
                contract.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
                    && contract.success_statuses == ["200"]
                    && contract.success_media_types == ["application/json"]
            })
}

fn dns_record_detail_routing_contract_supported(capability: &CapabilityV1) -> bool {
    capability.path == DNS_RECORD_DETAIL_PATH
        && capability.selectors.len() == 3
        && ["zone_id", "dns_record_id"].iter().all(|name| {
            capability.selectors.iter().any(|selector| {
                selector.name == *name && selector.location == "path" && selector.required
            })
        })
        && capability.selectors.iter().any(|selector| {
            selector.name == "include_shadow_metadata"
                && selector.location == "query"
                && !selector.required
                && selector.value_type == "boolean"
                && selector.contract.as_ref().is_some_and(|contract| {
                    contract.schema.get("type").and_then(Value::as_str) == Some("boolean")
                        && contract.query.as_ref().is_some_and(|query| {
                            query.style == "form"
                                && query.explode
                                && !query.allow_reserved
                                && !query.allow_empty_value
                        })
                })
        })
}

fn global_warp_override_source_contract_supported(
    document: &Value,
    capability: &CapabilityV1,
) -> bool {
    if capability.method != "POST"
        || capability.path != "/accounts/{account_id}/devices/resilience/disconnect"
        || capability.product != "Devices Resilience"
        || capability.title != "Set Global WARP override state"
        || capability.description.as_deref() != Some("Sets the Global WARP override state.")
        || capability.maturity != Maturity::GenerallyAvailable
        || capability.permissions != ["Zero Trust Resilience Write"]
        || capability.selectors.len() != 1
        || !capability.selectors.iter().any(|selector| {
            selector.name == "account_id" && selector.location == "path" && selector.required
        })
    {
        return false;
    }
    let Some(operation) =
        document.pointer("/paths/~1accounts~1{account_id}~1devices~1resilience~1disconnect/post")
    else {
        return false;
    };
    let Some(source_schema) = operation
        .pointer("/requestBody/content/application~1json/schema")
        .map(|schema| resolve_local_schema(document, schema))
    else {
        return false;
    };
    let Some(source_properties) = source_schema.get("properties").and_then(Value::as_object) else {
        return false;
    };
    if source_schema.get("type").and_then(Value::as_str) != Some("object")
        || source_schema.get("required") != Some(&serde_json::json!(["disconnect"]))
        || source_properties.len() != 2
    {
        return false;
    }
    let source_property_matches = |name: &str, expected_type: &str, description: &str| {
        source_properties
            .get(name)
            .map(|schema| resolve_local_schema(document, schema))
            .is_some_and(|schema| {
                schema.get("type").and_then(Value::as_str) == Some(expected_type)
                    && schema.get("description").and_then(Value::as_str) == Some(description)
                    && schema.get("x-auditable").and_then(Value::as_bool) == Some(true)
            })
    };
    if !source_property_matches(
        "disconnect",
        "boolean",
        "Disconnects all devices on the account using Global WARP override.",
    ) || !source_property_matches(
        "justification",
        "string",
        "Reasoning for setting the Global WARP override state. This will be surfaced in the audit log.",
    ) {
        return false;
    }

    capability.request_schema.as_ref().is_some_and(|schema| {
        schema.get("type").and_then(Value::as_str) == Some("object")
            && schema.get("required") == Some(&serde_json::json!(["disconnect"]))
            && schema.get("x-cfctl-body-required").and_then(Value::as_bool) == Some(true)
            && schema
                .get("properties")
                .and_then(Value::as_object)
                .is_some_and(|properties| {
                    properties.len() == 2
                        && properties.get("disconnect")
                            == Some(&serde_json::json!({"type":"boolean"}))
                        && properties.get("justification")
                            == Some(&serde_json::json!({"type":"string"}))
                })
    })
}

fn classify_created_resource_contracts(
    document: &Value,
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    let read_targets = capabilities
        .values()
        .filter(|capability| {
            capability.method == "GET"
                && path_targets_exact_resource(&capability.path)
                && !capability
                    .selectors
                    .iter()
                    .any(|selector| selector.location != "path")
        })
        .map(|capability| {
            (
                (capability.path.clone(), capability.product.clone()),
                (capability.id.clone(), capability.selectors.clone()),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let delete_targets = capabilities
        .values()
        .filter(|capability| {
            capability.method == "DELETE"
                && path_targets_exact_resource(&capability.path)
                && (capability.request_schema.is_none()
                    || capability.required_empty_request_body_contract())
                && capability
                    .selectors
                    .iter()
                    .all(|selector| selector.location == "path")
        })
        .map(|capability| {
            (
                (capability.path.clone(), capability.product.clone()),
                (capability.id.clone(), capability.selectors.clone()),
            )
        })
        .collect::<BTreeMap<_, _>>();

    for capability in capabilities.values_mut() {
        if capability.method != "POST"
            || capability.verification.strategy != "post_change_read_or_operation_specific_verifier"
            || capability
                .selectors
                .iter()
                .any(|selector| selector.location != "path")
        {
            continue;
        }
        let Some(target) =
            created_resource_contract(document, capability, &read_targets, &delete_targets)
        else {
            continue;
        };

        capability.created_resource = Some(target);
        "created_resource_contains_planned_fields_by_returned_id"
            .clone_into(&mut capability.verification.strategy);
        capability.rollback.supported = true;
        capability.rollback.strategy = Some("delete_created_resource_by_returned_id".to_owned());
        capability.rollback.warning = Some(
            "compensation creates a separate exact-resource delete plan that must be reviewed and explicitly approved"
                .to_owned(),
        );
        refresh_dynamic_mutation_contract(capability);
    }
}

fn created_resource_contract(
    document: &Value,
    capability: &CapabilityV1,
    read_targets: &ExactReadTargets,
    delete_targets: &ExactDeleteTargets,
) -> Option<CreatedResourceContractV1> {
    let create_operation = document.get("paths")?.get(&capability.path)?.get("post")?;
    let verified_response_fields = canonical_verifiable_request_object_fields(capability)?;
    let field_names = verified_response_fields
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();

    let candidates = read_targets
        .iter()
        .filter_map(
            |((detail_path, product), (read_capability_id, read_selectors))| {
                if product != &capability.product {
                    return None;
                }
                let identity_selector = direct_child_selector(&capability.path, detail_path)?;
                let (delete_capability_id, delete_selectors) =
                    delete_targets.get(&(detail_path.clone(), product.clone()))?;
                if !selector_can_be_response_id(&identity_selector)
                    && (!selectors_have_required_string_path_selector(
                        read_selectors,
                        &identity_selector,
                    ) || !selectors_have_required_string_path_selector(
                        delete_selectors,
                        &identity_selector,
                    ))
                {
                    return None;
                }
                let read_operation = document.get("paths")?.get(detail_path)?.get("get")?;
                let response_result_identity_pointer = response_identity_fields(&identity_selector)
                    .into_iter()
                    .find(|identity_field| {
                        success_response_declares_result_string_field(
                            document,
                            create_operation,
                            identity_field,
                        ) && success_response_declares_result_string_field(
                            document,
                            read_operation,
                            identity_field,
                        )
                    })
                    .map(|identity_field| format!("/{identity_field}"))?;
                if !success_response_declares_result_fields(document, read_operation, &field_names)
                {
                    return None;
                }
                Some(CreatedResourceContractV1 {
                    detail_path: detail_path.clone(),
                    identity_selector,
                    response_result_identity_pointer,
                    read_capability_id: read_capability_id.clone(),
                    delete_capability_id: delete_capability_id.clone(),
                    verified_response_fields: verified_response_fields.clone(),
                })
            },
        )
        .collect::<Vec<_>>();
    let [target] = candidates.as_slice() else {
        return None;
    };
    Some(target.clone())
}

fn direct_child_selector(collection_path: &str, detail_path: &str) -> Option<String> {
    let prefix = format!("{}/", collection_path.trim_end_matches('/'));
    let segment = detail_path.strip_prefix(&prefix)?;
    if segment.contains('/') {
        return None;
    }
    segment
        .strip_prefix('{')
        .and_then(|segment| segment.strip_suffix('}'))
        .filter(|selector| !selector.is_empty())
        .map(str::to_owned)
}

type CollectionReadTargets = BTreeMap<(String, String), (String, Vec<SelectorV1>)>;
type ExactReadTargets = BTreeMap<(String, String), (String, Vec<SelectorV1>)>;
type SamePathReadbackTargets = BTreeMap<(String, String, Vec<String>), String>;
type ExactDeleteTargets = BTreeMap<(String, String), (String, Vec<SelectorV1>)>;

fn classify_created_collection_resource_contracts(
    document: &Value,
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    let list_targets: CollectionReadTargets = capabilities
        .values()
        .filter(|capability| capability.method == "GET")
        .map(|capability| {
            (
                (capability.path.clone(), capability.product.clone()),
                (capability.id.clone(), capability.selectors.clone()),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let delete_targets: ExactDeleteTargets = capabilities
        .values()
        .filter(|capability| {
            capability.method == "DELETE"
                && path_targets_exact_resource(&capability.path)
                && (capability.request_schema.is_none()
                    || capability.required_empty_request_body_contract())
                && capability
                    .selectors
                    .iter()
                    .all(|selector| selector.location == "path")
        })
        .map(|capability| {
            (
                (capability.path.clone(), capability.product.clone()),
                (capability.id.clone(), capability.selectors.clone()),
            )
        })
        .collect::<BTreeMap<_, _>>();

    for capability in capabilities.values_mut() {
        if capability.method != "POST"
            || capability.verification.strategy != "post_change_read_or_operation_specific_verifier"
            || capability
                .selectors
                .iter()
                .any(|selector| selector.location != "path")
        {
            continue;
        }
        let Some(target) = created_collection_resource_contract(
            document,
            capability,
            &list_targets,
            &delete_targets,
        ) else {
            continue;
        };

        capability.created_collection_resource = Some(target);
        "parent_collection_contains_created_resource_id_and_planned_fields"
            .clone_into(&mut capability.verification.strategy);
        capability.rollback.supported = true;
        capability.rollback.strategy = Some("delete_created_resource_by_returned_id".to_owned());
        capability.rollback.warning = Some(
            "compensation creates a separate exact-resource delete plan that must be reviewed and explicitly approved"
                .to_owned(),
        );
        refresh_dynamic_mutation_contract(capability);
    }
}

fn created_collection_resource_contract(
    document: &Value,
    capability: &CapabilityV1,
    list_targets: &CollectionReadTargets,
    delete_targets: &ExactDeleteTargets,
) -> Option<CreatedCollectionResourceContractV1> {
    let create_operation = document.get("paths")?.get(&capability.path)?.get("post")?;
    let verified_response_fields = canonical_verifiable_request_object_fields(capability)?;

    let (read_capability_id, read_selectors) =
        list_targets.get(&(capability.path.clone(), capability.product.clone()))?;
    let read_operation = document.get("paths")?.get(&capability.path)?.get("get")?;
    let field_names = verified_response_fields
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let delete_candidates = delete_targets
        .iter()
        .filter_map(
            |((delete_path, product), (delete_capability_id, delete_selectors))| {
                if product != &capability.product {
                    return None;
                }
                let identity_selector = direct_child_selector(&capability.path, delete_path)?;
                if !selector_can_be_response_id(&identity_selector)
                    && !selectors_have_required_string_path_selector(
                        delete_selectors,
                        &identity_selector,
                    )
                {
                    return None;
                }
                let (identity_field, requires_page_number_completion) =
                    response_identity_fields(&identity_selector)
                        .into_iter()
                        .find_map(|identity_field| {
                            if !success_response_declares_result_string_field(
                                document,
                                create_operation,
                                identity_field,
                            ) {
                                return None;
                            }
                            complete_collection_readback_contract(
                                document,
                                read_operation,
                                read_selectors,
                                identity_field,
                                &field_names,
                            )
                            .map(|pagination| (identity_field, pagination))
                        })?;
                let response_identity_pointer = format!("/{identity_field}");
                Some((
                    identity_selector,
                    response_identity_pointer,
                    delete_capability_id.clone(),
                    requires_page_number_completion,
                ))
            },
        )
        .collect::<Vec<_>>();
    let [
        (
            identity_selector,
            response_identity_pointer,
            delete_capability_id,
            requires_page_number_completion,
        ),
    ] = delete_candidates.as_slice()
    else {
        return None;
    };

    Some(CreatedCollectionResourceContractV1 {
        collection_path: capability.path.clone(),
        identity_selector: identity_selector.clone(),
        response_result_identity_pointer: response_identity_pointer.clone(),
        response_item_identity_pointer: response_identity_pointer.clone(),
        read_capability_id: read_capability_id.clone(),
        delete_capability_id: delete_capability_id.clone(),
        verified_response_fields,
        requires_page_number_completion: *requires_page_number_completion,
    })
}

fn classify_exact_resource_contracts(
    document: &Value,
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    let readback_targets = same_path_readback_targets(capabilities, false);
    let delete_readback_targets = same_path_readback_targets(capabilities, true);

    for capability in capabilities.values_mut() {
        let contract_incomplete = capability.adapter_status == AdapterStatus::DynamicApi
            || (capability.adapter_status == AdapterStatus::Blocked
                && capability
                    .blocked_reason
                    .as_deref()
                    .is_some_and(|reason| reason.starts_with("operation contract incomplete:")));
        if !contract_incomplete
            || capability.verification.strategy != "post_change_read_or_operation_specific_verifier"
            || !path_targets_exact_resource(&capability.path)
        {
            continue;
        }
        let Some(routing_headers) = same_path_mutation_routing_headers(capability) else {
            continue;
        };
        if capability.method == "DELETE" && !declares_exact_resource_deletion(capability) {
            continue;
        }
        let target_key = (
            capability.path.clone(),
            capability.product.clone(),
            routing_headers,
        );
        let read_capability_id = if capability.method == "DELETE" {
            delete_readback_targets.get(&target_key)
        } else {
            readback_targets.get(&target_key)
        };
        let Some(read_capability_id) = read_capability_id else {
            continue;
        };

        match capability.method.as_str() {
            "DELETE" => {
                if !narrow_required_open_delete_body(capability) {
                    continue;
                }
                capability.same_path_read = Some(SamePathReadContractV1 {
                    path: capability.path.clone(),
                    read_capability_id: read_capability_id.clone(),
                    verified_response_fields: Vec::new(),
                });
                capability.cost = cfctl_core::CostV1::default();
                capability.cost.basis = Some(
                    "deleting an existing resource has no incremental operation charge; refunds, retained usage, and downstream billing are not claimed"
                        .to_owned(),
                );
                "same_resource_returns_not_found_after_delete"
                    .clone_into(&mut capability.verification.strategy);
                capability.rollback.warning = Some(
                    "deletion is irreversible without a prior resource snapshot; any recreation must be a separately reviewed plan"
                        .to_owned(),
                );
            }
            "PATCH" | "PUT" => {
                let Some(fields) = canonical_verifiable_request_object_fields(capability) else {
                    continue;
                };
                let Some(read_operation) = document
                    .get("paths")
                    .and_then(Value::as_object)
                    .and_then(|paths| paths.get(&capability.path))
                    .and_then(|path| path.get("get"))
                else {
                    continue;
                };
                let field_names = fields.iter().map(String::as_str).collect::<Vec<_>>();
                if !success_response_declares_result_fields(document, read_operation, &field_names)
                {
                    continue;
                }
                capability.same_path_read = Some(SamePathReadContractV1 {
                    path: capability.path.clone(),
                    read_capability_id: read_capability_id.clone(),
                    verified_response_fields: fields,
                });
                "same_resource_contains_planned_fields_after_update"
                    .clone_into(&mut capability.verification.strategy);
                if capability.rollback.warning.as_deref()
                    == Some("rollback semantics have not been declared")
                {
                    capability.rollback.warning = Some(
                        "automatic restoration is unsupported because the plan does not bind a pre-change snapshot; restoration requires a separately reviewed update plan built from trusted evidence"
                            .to_owned(),
                    );
                }
            }
            _ => continue,
        }
        capability.rollback.supported = false;
        capability.rollback.strategy = None;
        refresh_dynamic_mutation_contract(capability);
    }
}

/// Confirms an operation's 2xx success response declares its `result` as a
/// single object rather than an array. This is the structural proof that a
/// same-path GET is a singleton readback (delete-then-not-found is valid) and
/// not a collection list (where a delete would leave an empty array, never a
/// not-found), which is the one signal the terminal-literal path shape cannot
/// distinguish on its own.
fn success_response_result_is_single_object(document: &Value, operation: &Value) -> bool {
    operation
        .get("responses")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter(|(status, _)| status.starts_with('2'))
        .filter_map(|(_, response)| response.pointer("/content/application~1json/schema"))
        .any(|schema| schema_result_is_object_not_array(document, schema, 0))
}

fn schema_result_is_object_not_array(document: &Value, schema: &Value, depth: usize) -> bool {
    if depth > 32 {
        return false;
    }
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        return reference
            .strip_prefix('#')
            .and_then(|pointer| document.pointer(pointer))
            .is_some_and(|resolved| {
                schema_result_is_object_not_array(document, resolved, depth + 1)
            });
    }
    if let Some(result) = schema
        .get("properties")
        .and_then(Value::as_object)
        .and_then(|properties| properties.get("result"))
    {
        return schema_is_object_not_array(document, result, depth + 1);
    }
    schema
        .get("allOf")
        .and_then(Value::as_array)
        .is_some_and(|members| {
            members
                .iter()
                .any(|member| schema_result_is_object_not_array(document, member, depth + 1))
        })
}

fn schema_is_object_not_array(document: &Value, schema: &Value, depth: usize) -> bool {
    if depth > 32 {
        return false;
    }
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        return reference
            .strip_prefix('#')
            .and_then(|pointer| document.pointer(pointer))
            .is_some_and(|resolved| schema_is_object_not_array(document, resolved, depth + 1));
    }
    match schema.get("type").and_then(Value::as_str) {
        // Only an explicit object is a singleton; "array" and every other
        // scalar type fall through to false (a collection or non-resource).
        Some("object") => true,
        Some(_) => false,
        None => {
            schema
                .get("properties")
                .and_then(Value::as_object)
                .is_some_and(|properties| !properties.is_empty())
                || schema
                    .get("allOf")
                    .and_then(Value::as_array)
                    .is_some_and(|members| {
                        members
                            .iter()
                            .any(|member| schema_is_object_not_array(document, member, depth + 1))
                    })
        }
    }
}

/// Closes the delete contract for singleton sub-resource deletes that the
/// `classify_exact_resource_contracts` id-parameter heuristic under-covers
/// (terminal-literal paths such as `/apps/{app_id}/ca`). Applies the identical
/// readback-verified delete contract, but only when every safety condition
/// holds: the operation is a declared delete, its permission lane is already
/// declared (never fabricated), a same-path GET readback exists, that readback
/// returns a single object (not a collection), and no pricing reference is
/// attached (paid-operation deletes are left for human review). risk/effect are
/// already Destructive from the generic classifier; this only fills the
/// cost/verification/rollback gaps. Fabricates nothing: verification is
/// readback-real.
fn finalize_singleton_resource_delete_contracts(
    document: &Value,
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    let delete_readback_targets = same_path_readback_targets(capabilities, true);
    let candidates: Vec<String> = capabilities
        .values()
        .filter_map(|capability| {
            let contract_incomplete = capability.adapter_status == AdapterStatus::Blocked
                && capability
                    .blocked_reason
                    .as_deref()
                    .is_some_and(|reason| reason.starts_with("operation contract incomplete:"));
            if !contract_incomplete
                || capability.method != "DELETE"
                || capability.verification.strategy
                    != "post_change_read_or_operation_specific_verifier"
                || path_targets_exact_resource(&capability.path)
                || !path_targets_singleton_subresource(&capability.path)
                || !declares_exact_resource_deletion(capability)
                || capability.permissions.is_empty()
                || !capability.cost.references.is_empty()
            {
                return None;
            }
            let routing_headers = same_path_mutation_routing_headers(capability)?;
            let key = (
                capability.path.clone(),
                capability.product.clone(),
                routing_headers,
            );
            if !delete_readback_targets.contains_key(&key) {
                return None;
            }
            let get_operation = document
                .get("paths")
                .and_then(Value::as_object)
                .and_then(|paths| paths.get(&capability.path))
                .and_then(|path_item| path_item.get("get"))?;
            if !success_response_result_is_single_object(document, get_operation) {
                return None;
            }
            Some(capability.id.clone())
        })
        .collect();

    for id in candidates {
        let read_capability_id = {
            let capability = &capabilities[&id];
            same_path_mutation_routing_headers(capability).and_then(|routing_headers| {
                delete_readback_targets
                    .get(&(
                        capability.path.clone(),
                        capability.product.clone(),
                        routing_headers,
                    ))
                    .cloned()
            })
        };
        let Some(read_capability_id) = read_capability_id else {
            continue;
        };
        let Some(capability) = capabilities.get_mut(&id) else {
            continue;
        };
        if !narrow_required_open_delete_body(capability) {
            continue;
        }
        capability.same_path_read = Some(SamePathReadContractV1 {
            path: capability.path.clone(),
            read_capability_id,
            verified_response_fields: Vec::new(),
        });
        capability.cost = cfctl_core::CostV1::default();
        capability.cost.basis = Some(
            "deleting an existing resource has no incremental operation charge; refunds, retained usage, and downstream billing are not claimed"
                .to_owned(),
        );
        "same_resource_returns_not_found_after_delete"
            .clone_into(&mut capability.verification.strategy);
        capability.rollback.supported = false;
        capability.rollback.strategy = None;
        capability.rollback.warning = Some(
            "deletion is irreversible without a prior resource snapshot; any recreation must be a separately reviewed plan"
                .to_owned(),
        );
        refresh_dynamic_mutation_contract(capability);
    }
}

fn same_path_readback_targets(
    capabilities: &BTreeMap<String, CapabilityV1>,
    allow_delete_projections: bool,
) -> SamePathReadbackTargets {
    capabilities
        .values()
        .filter_map(|capability| {
            if capability.method != "GET" {
                return None;
            }
            let routing_headers = if allow_delete_projections {
                same_path_delete_readback_routing_headers(capability)?
            } else {
                same_path_readback_routing_headers(capability)?
            };
            Some((
                (
                    capability.path.clone(),
                    capability.product.clone(),
                    routing_headers,
                ),
                capability.id.clone(),
            ))
        })
        .collect()
}

fn same_path_mutation_routing_headers(capability: &CapabilityV1) -> Option<Vec<String>> {
    same_path_routing_headers(capability, false, false)
}

fn same_path_readback_routing_headers(capability: &CapabilityV1) -> Option<Vec<String>> {
    same_path_routing_headers(capability, true, false)
}

fn same_path_delete_readback_routing_headers(capability: &CapabilityV1) -> Option<Vec<String>> {
    same_path_routing_headers(capability, true, true)
}

fn same_path_routing_headers(
    capability: &CapabilityV1,
    allow_readback_controls: bool,
    allow_omitted_optional_query: bool,
) -> Option<Vec<String>> {
    let mut routing_headers = Vec::new();
    for selector in &capability.selectors {
        if selector.location == "path" {
            continue;
        }
        if allow_omitted_optional_query
            && safe_omitted_delete_readback_projection(capability, selector)
        {
            continue;
        }
        if allow_readback_controls && safe_omitted_readback_projection(capability, selector) {
            continue;
        }
        if allow_readback_controls
            && selector.location == "header"
            && !selector.required
            && selector.value_type == "string"
            && matches!(
                selector.name.to_ascii_lowercase().as_str(),
                "if-none-match" | "if-modified-since"
            )
        {
            continue;
        }
        if selector.location == "header"
            && selector.name == "cf-r2-jurisdiction"
            && !selector.required
            && selector.value_type == "string"
            && matches!(capability.product.as_str(), "R2 Bucket" | "R2 Object")
            && routing_headers.is_empty()
        {
            routing_headers.push(selector.name.clone());
            continue;
        }
        return None;
    }
    Some(routing_headers)
}

fn declares_exact_resource_deletion(capability: &CapabilityV1) -> bool {
    if capability.method != "DELETE" {
        return false;
    }
    let declaration = capability.title.to_ascii_lowercase();
    [
        "delete",
        "remove",
        "revoke",
        "destroy",
        "decommission",
        "leave",
        "unprotect",
        "detach",
    ]
    .iter()
    .any(|term| declaration.contains(term))
}

fn narrow_required_open_delete_body(capability: &mut CapabilityV1) -> bool {
    let Some(schema) = capability.request_schema.as_mut() else {
        return true;
    };
    let Some(contract) = schema.as_object_mut() else {
        return false;
    };
    let properties_are_open = contract
        .get("properties")
        .and_then(Value::as_object)
        .is_none_or(serde_json::Map::is_empty);
    let required_is_empty = contract
        .get("required")
        .and_then(Value::as_array)
        .is_none_or(Vec::is_empty);
    let empty_object_is_valid = contract.get("type").and_then(Value::as_str) == Some("object")
        && contract
            .get("x-cfctl-body-required")
            .and_then(Value::as_bool)
            == Some(true)
        && properties_are_open
        && required_is_empty
        && ["allOf", "oneOf", "anyOf"]
            .iter()
            .all(|composition| !contract.contains_key(*composition))
        && contract
            .get("minProperties")
            .and_then(Value::as_u64)
            .is_none_or(|minimum| minimum == 0)
        && contract.get("enum").is_none();
    if !empty_object_is_valid {
        return false;
    }
    contract.insert("properties".to_owned(), Value::Object(Map::new()));
    contract.insert("additionalProperties".to_owned(), Value::Bool(false));
    true
}

fn safe_omitted_readback_projection(capability: &CapabilityV1, selector: &SelectorV1) -> bool {
    capability.product == "D1"
        && capability.path == "/accounts/{account_id}/d1/database/{database_id}"
        && selector.location == "query"
        && selector.name == "fields"
        && !selector.required
        && selector.value_type == "array"
        && selector.description.as_deref().is_some_and(|description| {
            description.contains("When omitted") && description.contains("all fields are returned.")
        })
}

fn safe_omitted_delete_readback_projection(
    capability: &CapabilityV1,
    selector: &SelectorV1,
) -> bool {
    if selector.location != "query" || selector.required {
        return false;
    }
    let Some(description) = selector.description.as_deref() else {
        return false;
    };
    match (
        capability.product.as_str(),
        capability.path.as_str(),
        selector.name.as_str(),
        selector.value_type.as_str(),
    ) {
        (
            "Physical Devices",
            "/accounts/{account_id}/devices/physical-devices/{device_id}",
            "include",
            "string",
        )
        | (
            "Registrations",
            "/accounts/{account_id}/devices/registrations/{registration_id}",
            "include",
            "string",
        ) => {
            description.contains("additional information")
                && description.contains("included in")
                && description.contains("response")
        }
        (
            "API Shield Labels",
            "/zones/{zone_id}/api_gateway/labels/user/{name}",
            "with_mapped_resource_counts",
            "boolean",
        ) => description.contains("Include `mapped_resources` for each label"),
        (
            "Schema Validation",
            "/zones/{zone_id}/schema_validation/schemas/{schema_id}",
            "omit_source",
            "boolean",
        ) => {
            description.contains("Omit the source-files")
                && description.contains("only retrieve their meta-data")
        }
        _ => false,
    }
}

fn canonical_request_object_fields(capability: &CapabilityV1) -> Option<Vec<String>> {
    capability.request_object_fields()
}

fn canonical_verifiable_request_object_fields(capability: &CapabilityV1) -> Option<Vec<String>> {
    capability.verifiable_request_object_fields()
}

fn classify_parent_collection_delete_contracts(
    document: &Value,
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    let list_targets: CollectionReadTargets = capabilities
        .values()
        .filter(|capability| capability.method == "GET")
        .map(|capability| {
            (
                (capability.path.clone(), capability.product.clone()),
                (capability.id.clone(), capability.selectors.clone()),
            )
        })
        .collect::<BTreeMap<_, _>>();

    for capability in capabilities.values_mut() {
        if capability.method != "DELETE"
            || capability.verification.strategy != "post_change_read_or_operation_specific_verifier"
            || !path_targets_exact_resource(&capability.path)
            || capability.request_schema.is_some()
            || capability
                .selectors
                .iter()
                .any(|selector| selector.location != "path")
        {
            continue;
        }
        let Some((collection_path, identity_segment)) = capability.path.rsplit_once('/') else {
            continue;
        };
        let Some(identity_selector) = identity_segment
            .strip_prefix('{')
            .and_then(|segment| segment.strip_suffix('}'))
            .filter(|selector| !selector.is_empty())
        else {
            continue;
        };
        if !selector_can_be_response_id(identity_selector)
            && !capability_has_required_string_path_selector(capability, identity_selector)
        {
            continue;
        }
        let Some((read_capability_id, read_selectors)) =
            list_targets.get(&(collection_path.to_owned(), capability.product.clone()))
        else {
            continue;
        };
        let Some(read_operation) = document
            .get("paths")
            .and_then(Value::as_object)
            .and_then(|paths| paths.get(collection_path))
            .and_then(|path| path.get("get"))
        else {
            continue;
        };
        let Some((response_item_identity_pointer, requires_page_number_completion)) =
            collection_readback_identity_contract(
                document,
                read_operation,
                read_selectors,
                identity_selector,
                &[],
            )
        else {
            continue;
        };

        capability.deleted_resource = Some(DeletedResourceContractV1 {
            collection_path: collection_path.to_owned(),
            identity_selector: identity_selector.to_owned(),
            response_item_identity_pointer,
            read_capability_id: read_capability_id.clone(),
            requires_page_number_completion,
        });
        capability.cost = cfctl_core::CostV1::default();
        capability.cost.exposure = CostExposureV1::DownstreamUsage;
        capability.cost.basis = Some(
            "deleting an existing resource has no incremental operation charge; refunds, retained usage, and downstream billing are not claimed"
                .to_owned(),
        );
        "parent_collection_omits_deleted_resource_id"
            .clone_into(&mut capability.verification.strategy);
        capability.rollback.supported = false;
        capability.rollback.strategy = None;
        capability.rollback.warning = Some(
            "deletion is irreversible without a prior resource snapshot; any recreation must be a separately reviewed plan"
                .to_owned(),
        );
        refresh_dynamic_mutation_contract(capability);
    }
}

fn classify_parent_collection_update_contracts(
    document: &Value,
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    let list_targets = capabilities
        .values()
        .filter(|capability| capability.method == "GET")
        .map(|capability| {
            (
                (capability.path.clone(), capability.product.clone()),
                (capability.id.clone(), capability.selectors.clone()),
            )
        })
        .collect::<BTreeMap<_, _>>();

    for capability in capabilities.values_mut() {
        if !matches!(capability.method.as_str(), "PATCH" | "PUT")
            || capability.verification.strategy != "post_change_read_or_operation_specific_verifier"
            || !path_targets_exact_resource(&capability.path)
            || capability
                .selectors
                .iter()
                .any(|selector| selector.location != "path")
        {
            continue;
        }
        let Some((collection_path, identity_segment)) = capability.path.rsplit_once('/') else {
            continue;
        };
        let Some(identity_selector) = identity_segment
            .strip_prefix('{')
            .and_then(|segment| segment.strip_suffix('}'))
            .filter(|selector| !selector.is_empty())
        else {
            continue;
        };
        if !selector_can_be_response_id(identity_selector)
            && !capability_has_required_string_path_selector(capability, identity_selector)
        {
            continue;
        }
        let Some((read_capability_id, read_selectors)) =
            list_targets.get(&(collection_path.to_owned(), capability.product.clone()))
        else {
            continue;
        };
        let Some(read_operation) = document
            .get("paths")
            .and_then(Value::as_object)
            .and_then(|paths| paths.get(collection_path))
            .and_then(|path| path.get("get"))
        else {
            continue;
        };
        let Some(verified_response_fields) = canonical_verifiable_request_object_fields(capability)
        else {
            continue;
        };
        let field_names = verified_response_fields
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let Some((response_item_identity_pointer, requires_page_number_completion)) =
            collection_readback_identity_contract(
                document,
                read_operation,
                read_selectors,
                identity_selector,
                &field_names,
            )
        else {
            continue;
        };

        capability.updated_resource = Some(UpdatedResourceContractV1 {
            collection_path: collection_path.to_owned(),
            identity_selector: identity_selector.to_owned(),
            response_item_identity_pointer,
            read_capability_id: read_capability_id.clone(),
            verified_response_fields,
            requires_page_number_completion,
        });
        "parent_collection_item_contains_planned_fields_after_update"
            .clone_into(&mut capability.verification.strategy);
        capability.rollback.supported = false;
        capability.rollback.strategy = None;
        capability.rollback.warning = Some(
            "automatic restoration is unsupported because the plan does not bind a pre-change snapshot; restoration requires a separately reviewed update plan built from trusted evidence"
                .to_owned(),
        );
        refresh_dynamic_mutation_contract(capability);
    }
}

fn capability_has_required_string_path_selector(
    capability: &CapabilityV1,
    selector_name: &str,
) -> bool {
    selectors_have_required_string_path_selector(&capability.selectors, selector_name)
}

fn selectors_have_required_string_path_selector(
    selectors: &[SelectorV1],
    selector_name: &str,
) -> bool {
    selectors.iter().any(|selector| {
        selector.name == selector_name
            && selector.location == "path"
            && selector.required
            && selector.value_type == "string"
    })
}

fn selector_can_be_response_id(selector: &str) -> bool {
    matches!(selector, "id" | "identifier")
        || selector.ends_with("_id")
        || selector.ends_with("_identifier")
}

fn response_identity_fields(identity_selector: &str) -> Vec<&str> {
    let mut identity_fields = Vec::new();
    if selector_can_be_response_id(identity_selector) {
        identity_fields.push("id");
    }
    if !identity_selector.contains(['/', '~']) && !identity_fields.contains(&identity_selector) {
        identity_fields.push(identity_selector);
    }
    identity_fields
}

fn collection_readback_identity_contract(
    document: &Value,
    operation: &Value,
    selectors: &[SelectorV1],
    identity_selector: &str,
    verified_item_fields: &[&str],
) -> Option<(String, bool)> {
    response_identity_fields(identity_selector)
        .into_iter()
        .find_map(|identity_field| {
            complete_collection_readback_contract(
                document,
                operation,
                selectors,
                identity_field,
                verified_item_fields,
            )
            .map(|requires_page_number_completion| {
                (
                    format!("/{identity_field}"),
                    requires_page_number_completion,
                )
            })
        })
}

fn complete_collection_readback_contract(
    document: &Value,
    operation: &Value,
    selectors: &[SelectorV1],
    identity_field: &str,
    verified_item_fields: &[&str],
) -> Option<bool> {
    if selectors
        .iter()
        .any(|selector| selector.required && selector.location != "path")
    {
        return None;
    }

    let query_names = selectors
        .iter()
        .filter(|selector| selector.location == "query")
        .map(|selector| selector.name.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    let page_number_pagination = query_names.contains("page") || query_names.contains("per_page");
    let unsupported_pagination = query_names.iter().any(|name| {
        matches!(
            name.as_str(),
            "cursor"
                | "limit"
                | "offset"
                | "after"
                | "before"
                | "starting_after"
                | "ending_before"
                | "continuation_token"
                | "page_token"
        ) || (name.contains("page") && !matches!(name.as_str(), "page" | "per_page"))
    });
    if unsupported_pagination {
        return None;
    }
    if !success_response_declares_complete_collection(
        document,
        operation,
        page_number_pagination,
        identity_field,
        verified_item_fields,
    ) {
        return None;
    }
    Some(page_number_pagination)
}

fn path_targets_exact_resource(path: &str) -> bool {
    path.rsplit('/').next().is_some_and(|segment| {
        segment.starts_with('{') && segment.ends_with('}') && segment.len() > 2
    })
}

/// A singleton sub-resource path: terminal literal segment beneath an
/// identified parent parameter (e.g. `/apps/{app_id}/ca`). Mirrors the core
/// predicate of the same name; kept a necessary-but-not-sufficient signal, with
/// the single-object readback response as the sufficient singleton proof.
fn path_targets_singleton_subresource(path: &str) -> bool {
    let terminal_is_literal = path.rsplit('/').next().is_some_and(|segment| {
        !(segment.is_empty() || segment.starts_with('{') && segment.ends_with('}'))
    });
    terminal_is_literal && path.contains('{')
}

pub async fn fetch_official(client: &reqwest::Client) -> Result<CatalogSnapshot> {
    let document = client
        .get(OFFICIAL_OPENAPI_URL)
        .send()
        .await?
        .error_for_status()?
        .json::<Value>()
        .await?;
    normalize_openapi(&document)
}

fn request_schema_contract(document: &Value, operation: &Value) -> Option<Value> {
    let schema = operation.pointer("/requestBody/content/application~1json/schema")?;
    let mut active_references = BTreeSet::new();
    let mut contract =
        normalize_request_schema_contract(document, schema, 0, &mut active_references)
            .as_object()
            .cloned()
            .unwrap_or_default();
    contract.insert(
        "x-cfctl-body-required".to_owned(),
        operation
            .pointer("/requestBody/required")
            .cloned()
            .unwrap_or(Value::Bool(false)),
    );
    Some(Value::Object(contract))
}

fn success_response_contract(
    document: &Value,
    operation: &Value,
    mutating: bool,
) -> Result<Option<ResponseContractV1>> {
    let responses = operation.get("responses").and_then(Value::as_object);
    let mut success_statuses = BTreeSet::new();
    let mut success_media_types = BTreeSet::new();
    let mut every_success_is_cloudflare_json = true;
    let mut every_success_is_json = true;
    let mut every_success_is_empty = true;
    if let Some(responses) = responses {
        for (status, response) in responses {
            if !is_success_response_status(status) {
                continue;
            }
            success_statuses.insert(status.to_ascii_uppercase());
            let response = resolve_local_response(document, response, 0)?;
            let media = response
                .get("content")
                .and_then(Value::as_object)
                .map(|content| content.keys().cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            success_media_types.extend(media.iter().cloned());
            if media.is_empty() {
                every_success_is_cloudflare_json = false;
                every_success_is_json = false;
                continue;
            }
            every_success_is_empty = false;
            if media.as_slice() != ["application/json"] {
                every_success_is_cloudflare_json = false;
                every_success_is_json = false;
                continue;
            }
            let envelope_proven = response
                .pointer("/content/application~1json/schema")
                .is_some_and(|schema| {
                    schema_declares_boolean_path(document, schema, &["success"], 0)
                });
            every_success_is_cloudflare_json &= envelope_proven;
        }
    }
    let success_statuses: Vec<String> = success_statuses.into_iter().collect();
    Ok(Some(ResponseContractV1 {
        success_statuses: success_statuses.clone(),
        success_media_types: success_media_types.into_iter().collect(),
        body_mode: if success_statuses.is_empty() {
            ResponseBodyModeV1::Unsupported
        } else if every_success_is_cloudflare_json {
            ResponseBodyModeV1::CloudflareJsonEnvelope
        } else if every_success_is_json && !mutating {
            ResponseBodyModeV1::JsonValue
        } else if every_success_is_empty {
            ResponseBodyModeV1::Empty
        } else {
            ResponseBodyModeV1::Unsupported
        },
    }))
}

fn is_success_response_status(status: &str) -> bool {
    status.len() == 3
        && status.as_bytes()[0] == b'2'
        && status
            .as_bytes()
            .iter()
            .skip(1)
            .all(|byte| byte.is_ascii_digit() || byte.eq_ignore_ascii_case(&b'X'))
}

fn resolve_local_response<'a>(
    document: &'a Value,
    response: &'a Value,
    depth: u8,
) -> Result<&'a Value> {
    let Some(reference) = response.get("$ref") else {
        return Ok(response);
    };
    let reference = reference
        .as_str()
        .ok_or_else(|| CatalogError::UnsupportedResponseReference("non-string $ref".to_owned()))?;
    if depth >= 16 {
        return Err(CatalogError::ResponseReferenceDepth(reference.to_owned()));
    }
    let pointer = reference
        .strip_prefix('#')
        .filter(|pointer| pointer.starts_with('/'))
        .ok_or_else(|| CatalogError::UnsupportedResponseReference(reference.to_owned()))?;
    let resolved = document
        .pointer(pointer)
        .ok_or_else(|| CatalogError::UnresolvedResponseReference(reference.to_owned()))?;
    resolve_local_response(document, resolved, depth + 1)
}

const MAX_REQUEST_SCHEMA_CONTRACT_DEPTH: usize = 16;

fn normalize_request_schema_contract(
    document: &Value,
    schema: &Value,
    depth: usize,
    active_references: &mut BTreeSet<String>,
) -> Value {
    let reference = schema
        .get("$ref")
        .and_then(Value::as_str)
        .filter(|reference| reference.starts_with("#/"));
    let inserted_reference =
        reference.is_some_and(|reference| active_references.insert(reference.to_owned()));
    if reference.is_some() && !inserted_reference {
        return Value::Object(Map::new());
    }
    let resolved = resolve_local_schema(document, schema);
    let mut contract = Map::new();
    copy_request_schema_value_constraints(resolved, &mut contract);
    copy_request_schema_required(document, resolved, &mut contract);
    if let Some(additional) = resolved.get("additionalProperties") {
        let additional = if additional.is_object() {
            if depth < MAX_REQUEST_SCHEMA_CONTRACT_DEPTH {
                normalize_request_schema_contract(
                    document,
                    additional,
                    depth + 1,
                    active_references,
                )
            } else {
                Value::Object(Map::new())
            }
        } else {
            additional.clone()
        };
        contract.insert("additionalProperties".to_owned(), additional);
    }
    if depth < MAX_REQUEST_SCHEMA_CONTRACT_DEPTH {
        for composition in ["allOf", "oneOf", "anyOf"] {
            if let Some(members) = resolved.get(composition).and_then(Value::as_array) {
                contract.insert(
                    composition.to_owned(),
                    Value::Array(
                        members
                            .iter()
                            .map(|member| {
                                normalize_request_schema_contract(
                                    document,
                                    member,
                                    depth + 1,
                                    active_references,
                                )
                            })
                            .collect(),
                    ),
                );
            }
        }
        if let Some(properties) = resolved.get("properties").and_then(Value::as_object) {
            let properties = properties
                .iter()
                .filter(|(_, property)| !request_property_is_read_only(document, property))
                .map(|(name, property)| {
                    (
                        name.clone(),
                        normalize_request_schema_contract(
                            document,
                            property,
                            depth + 1,
                            active_references,
                        ),
                    )
                })
                .collect();
            contract.insert("properties".to_owned(), Value::Object(properties));
        }
        if let Some(items) = resolved.get("items") {
            contract.insert(
                "items".to_owned(),
                normalize_request_schema_contract(document, items, depth + 1, active_references),
            );
        }
    }
    if inserted_reference && let Some(reference) = reference {
        active_references.remove(reference);
    }
    Value::Object(contract)
}

fn copy_request_schema_value_constraints(resolved: &Value, contract: &mut Map<String, Value>) {
    for key in [
        "type",
        "writeOnly",
        "enum",
        "format",
        "nullable",
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "minLength",
        "maxLength",
        "minItems",
        "maxItems",
        "uniqueItems",
        "minProperties",
        "maxProperties",
    ] {
        if let Some(value) = resolved.get(key) {
            contract.insert(key.to_owned(), value.clone());
        }
    }
    if let Some(multiple) = resolved
        .get("multipleOf")
        .filter(|value| value.as_f64().is_some_and(|multiple| multiple > 0.0))
    {
        contract.insert("multipleOf".to_owned(), multiple.clone());
    }
}

fn copy_request_schema_required(
    document: &Value,
    resolved: &Value,
    contract: &mut Map<String, Value>,
) {
    let Some(required) = resolved.get("required").and_then(Value::as_array) else {
        return;
    };
    let properties = resolved.get("properties").and_then(Value::as_object);
    let writable_required = required
        .iter()
        .filter(|entry| {
            entry.as_str().is_none_or(|name| {
                properties
                    .and_then(|properties| properties.get(name))
                    .is_none_or(|property| !request_property_is_read_only(document, property))
            })
        })
        .cloned()
        .collect();
    contract.insert("required".to_owned(), Value::Array(writable_required));
}

fn request_property_is_read_only(document: &Value, property: &Value) -> bool {
    resolve_local_schema(document, property)
        .get("readOnly")
        .and_then(Value::as_bool)
        == Some(true)
}

fn success_response_declares_result_string_field(
    document: &Value,
    operation: &Value,
    field: &str,
) -> bool {
    operation
        .get("responses")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter(|(status, _)| status.starts_with('2'))
        .filter_map(|(_, response)| response.pointer("/content/application~1json/schema"))
        .any(|schema| schema_declares_string_path(document, schema, &["result", field], 0))
}

fn success_response_declares_complete_collection(
    document: &Value,
    operation: &Value,
    requires_page_number_completion: bool,
    identity_field: &str,
    verified_item_fields: &[&str],
) -> bool {
    operation
        .get("responses")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter(|(status, _)| status.starts_with('2'))
        .filter_map(|(_, response)| response.pointer("/content/application~1json/schema"))
        .any(|schema| {
            schema_declares_result_array_string_field(document, schema, identity_field, 0)
                && (verified_item_fields.is_empty()
                    || schema_declares_result_array_item_fields(
                        document,
                        schema,
                        verified_item_fields,
                        0,
                    ))
                && (!requires_page_number_completion
                    || [["result_info", "page"], ["result_info", "total_pages"]]
                        .iter()
                        .all(|path| schema_declares_numeric_path(document, schema, path, 0)))
        })
}

fn schema_declares_result_array_item_fields(
    document: &Value,
    schema: &Value,
    fields: &[&str],
    depth: usize,
) -> bool {
    if depth > 32 {
        return false;
    }
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        return reference
            .strip_prefix('#')
            .and_then(|pointer| document.pointer(pointer))
            .is_some_and(|resolved| {
                schema_declares_result_array_item_fields(document, resolved, fields, depth + 1)
            });
    }
    if let Some(result) = schema
        .get("properties")
        .and_then(Value::as_object)
        .and_then(|properties| properties.get("result"))
        && schema_declares_array_item_fields(document, result, fields, depth + 1)
    {
        return true;
    }
    if schema
        .get("allOf")
        .and_then(Value::as_array)
        .is_some_and(|members| {
            members.iter().any(|member| {
                schema_declares_result_array_item_fields(document, member, fields, depth + 1)
            })
        })
    {
        return true;
    }
    for alternative in ["oneOf", "anyOf"] {
        if let Some(members) = schema.get(alternative).and_then(Value::as_array) {
            return !members.is_empty()
                && members.iter().all(|member| {
                    schema_declares_result_array_item_fields(document, member, fields, depth + 1)
                });
        }
    }
    false
}

fn schema_declares_array_item_fields(
    document: &Value,
    schema: &Value,
    fields: &[&str],
    depth: usize,
) -> bool {
    if depth > 32 {
        return false;
    }
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        return reference
            .strip_prefix('#')
            .and_then(|pointer| document.pointer(pointer))
            .is_some_and(|resolved| {
                schema_declares_array_item_fields(document, resolved, fields, depth + 1)
            });
    }
    if schema.get("type").and_then(Value::as_str) == Some("array")
        && schema.get("items").is_some_and(|items| {
            fields
                .iter()
                .all(|field| schema_declares_path(document, items, &[*field], depth + 1))
        })
    {
        return true;
    }
    if schema
        .get("allOf")
        .and_then(Value::as_array)
        .is_some_and(|members| {
            members.iter().any(|member| {
                schema_declares_array_item_fields(document, member, fields, depth + 1)
            })
        })
    {
        return true;
    }
    for alternative in ["oneOf", "anyOf"] {
        if let Some(members) = schema.get(alternative).and_then(Value::as_array) {
            return !members.is_empty()
                && members.iter().all(|member| {
                    schema_declares_array_item_fields(document, member, fields, depth + 1)
                });
        }
    }
    false
}

fn schema_declares_result_array_string_field(
    document: &Value,
    schema: &Value,
    field: &str,
    depth: usize,
) -> bool {
    if depth > 32 {
        return false;
    }
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        return reference
            .strip_prefix('#')
            .and_then(|pointer| document.pointer(pointer))
            .is_some_and(|resolved| {
                schema_declares_result_array_string_field(document, resolved, field, depth + 1)
            });
    }
    if let Some(result) = schema
        .get("properties")
        .and_then(Value::as_object)
        .and_then(|properties| properties.get("result"))
        && schema_declares_array_item_string_field(document, result, field, depth + 1)
    {
        return true;
    }
    if schema
        .get("allOf")
        .and_then(Value::as_array)
        .is_some_and(|members| {
            members.iter().any(|member| {
                schema_declares_result_array_string_field(document, member, field, depth + 1)
            })
        })
    {
        return true;
    }
    for alternative in ["oneOf", "anyOf"] {
        if let Some(members) = schema.get(alternative).and_then(Value::as_array) {
            return !members.is_empty()
                && members.iter().all(|member| {
                    schema_declares_result_array_string_field(document, member, field, depth + 1)
                });
        }
    }
    false
}

fn schema_declares_array_item_string_field(
    document: &Value,
    schema: &Value,
    field: &str,
    depth: usize,
) -> bool {
    if depth > 32 {
        return false;
    }
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        return reference
            .strip_prefix('#')
            .and_then(|pointer| document.pointer(pointer))
            .is_some_and(|resolved| {
                schema_declares_array_item_string_field(document, resolved, field, depth + 1)
            });
    }
    if schema.get("type").and_then(Value::as_str) == Some("array")
        && schema
            .get("items")
            .is_some_and(|items| schema_declares_string_path(document, items, &[field], depth + 1))
    {
        return true;
    }
    if schema
        .get("allOf")
        .and_then(Value::as_array)
        .is_some_and(|members| {
            members.iter().any(|member| {
                schema_declares_array_item_string_field(document, member, field, depth + 1)
            })
        })
    {
        return true;
    }
    for alternative in ["oneOf", "anyOf"] {
        if let Some(members) = schema.get(alternative).and_then(Value::as_array) {
            return !members.is_empty()
                && members.iter().all(|member| {
                    schema_declares_array_item_string_field(document, member, field, depth + 1)
                });
        }
    }
    false
}

fn success_response_declares_result_fields(
    document: &Value,
    operation: &Value,
    fields: &[&str],
) -> bool {
    operation
        .get("responses")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter(|(status, _)| status.starts_with('2'))
        .filter_map(|(_, response)| response.pointer("/content/application~1json/schema"))
        .any(|schema| {
            fields
                .iter()
                .all(|field| schema_declares_path(document, schema, &["result", *field], 0))
        })
}

fn success_response_omits_or_marks_write_only_result_fields(
    document: &Value,
    operation: &Value,
    fields: &[&str],
) -> bool {
    operation
        .get("responses")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter(|(status, _)| status.starts_with('2'))
        .filter_map(|(_, response)| response.pointer("/content/application~1json/schema"))
        .any(|schema| {
            fields.iter().all(|field| {
                schema_path_write_only_state(document, schema, &["result", *field], 0)
                    .is_none_or(|write_only| write_only)
            })
        })
}

fn schema_path_write_only_state(
    document: &Value,
    schema: &Value,
    path: &[&str],
    depth: usize,
) -> Option<bool> {
    if depth > 32 {
        return Some(false);
    }
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        let Some(resolved) = reference
            .strip_prefix('#')
            .and_then(|pointer| document.pointer(pointer))
        else {
            return Some(false);
        };
        return schema_path_write_only_state(document, resolved, path, depth + 1);
    }
    if path.is_empty() {
        return Some(schema.get("writeOnly").and_then(Value::as_bool) == Some(true));
    }

    let mut found = None;
    if let Some(property) = schema
        .get("properties")
        .and_then(Value::as_object)
        .and_then(|properties| properties.get(path[0]))
        && let Some(write_only) =
            schema_path_write_only_state(document, property, &path[1..], depth + 1)
    {
        found = Some(write_only);
    }
    for composition in ["allOf", "oneOf", "anyOf"] {
        if let Some(members) = schema.get(composition).and_then(Value::as_array) {
            for member in members {
                if let Some(write_only) =
                    schema_path_write_only_state(document, member, path, depth + 1)
                {
                    found = Some(found.unwrap_or(true) && write_only);
                }
            }
        }
    }
    found
}

fn success_response_declares_result_field_union(
    document: &Value,
    operation: &Value,
    fields: &[&str],
) -> bool {
    operation
        .get("responses")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter(|(status, _)| status.starts_with('2'))
        .filter_map(|(_, response)| response.pointer("/content/application~1json/schema"))
        .any(|schema| {
            fields.iter().all(|field| {
                schema_declares_path_in_union(document, schema, &["result", *field], 0)
            })
        })
}

fn schema_declares_path_in_union(
    document: &Value,
    schema: &Value,
    path: &[&str],
    depth: usize,
) -> bool {
    if depth > 32 {
        return false;
    }
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        return reference
            .strip_prefix('#')
            .and_then(|pointer| document.pointer(pointer))
            .is_some_and(|resolved| {
                schema_declares_path_in_union(document, resolved, path, depth + 1)
            });
    }
    if path.is_empty() {
        return true;
    }
    if let Some(property) = schema
        .get("properties")
        .and_then(Value::as_object)
        .and_then(|properties| properties.get(path[0]))
    {
        return schema_declares_path_in_union(document, property, &path[1..], depth + 1);
    }
    ["allOf", "oneOf", "anyOf"].iter().any(|composition| {
        schema
            .get(composition)
            .and_then(Value::as_array)
            .is_some_and(|members| {
                members
                    .iter()
                    .any(|member| schema_declares_path_in_union(document, member, path, depth + 1))
            })
    })
}

fn schema_declares_path(document: &Value, schema: &Value, path: &[&str], depth: usize) -> bool {
    if depth > 32 {
        return false;
    }
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        return reference
            .strip_prefix('#')
            .and_then(|pointer| document.pointer(pointer))
            .is_some_and(|resolved| schema_declares_path(document, resolved, path, depth + 1));
    }
    if path.is_empty() {
        return true;
    }
    if let Some(property) = schema
        .get("properties")
        .and_then(Value::as_object)
        .and_then(|properties| properties.get(path[0]))
    {
        return schema_declares_path(document, property, &path[1..], depth + 1);
    }
    if schema
        .get("allOf")
        .and_then(Value::as_array)
        .is_some_and(|members| {
            members
                .iter()
                .any(|member| schema_declares_path(document, member, path, depth + 1))
        })
    {
        return true;
    }
    for alternative in ["oneOf", "anyOf"] {
        if let Some(members) = schema.get(alternative).and_then(Value::as_array) {
            return !members.is_empty()
                && members
                    .iter()
                    .all(|member| schema_declares_path(document, member, path, depth + 1));
        }
    }
    false
}

fn schema_declares_string_path(
    document: &Value,
    schema: &Value,
    path: &[&str],
    depth: usize,
) -> bool {
    if depth > 32 {
        return false;
    }
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        return reference
            .strip_prefix('#')
            .and_then(|pointer| document.pointer(pointer))
            .is_some_and(|resolved| {
                schema_declares_string_path(document, resolved, path, depth + 1)
            });
    }
    if path.is_empty() {
        return schema.get("type").and_then(Value::as_str) == Some("string")
            || schema
                .get("allOf")
                .and_then(Value::as_array)
                .is_some_and(|members| {
                    members.iter().any(|member| {
                        schema_declares_string_path(document, member, path, depth + 1)
                    })
                });
    }
    if let Some(property) = schema
        .get("properties")
        .and_then(Value::as_object)
        .and_then(|properties| properties.get(path[0]))
    {
        return schema_declares_string_path(document, property, &path[1..], depth + 1);
    }
    if schema
        .get("allOf")
        .and_then(Value::as_array)
        .is_some_and(|members| {
            members
                .iter()
                .any(|member| schema_declares_string_path(document, member, path, depth + 1))
        })
    {
        return true;
    }
    for alternative in ["oneOf", "anyOf"] {
        if let Some(members) = schema.get(alternative).and_then(Value::as_array) {
            return !members.is_empty()
                && members
                    .iter()
                    .all(|member| schema_declares_string_path(document, member, path, depth + 1));
        }
    }
    false
}

fn schema_declares_boolean_path(
    document: &Value,
    schema: &Value,
    path: &[&str],
    depth: usize,
) -> bool {
    if depth > 32 {
        return false;
    }
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        return reference
            .strip_prefix('#')
            .and_then(|pointer| document.pointer(pointer))
            .is_some_and(|resolved| {
                schema_declares_boolean_path(document, resolved, path, depth + 1)
            });
    }
    if path.is_empty() {
        return schema.get("type").and_then(Value::as_str) == Some("boolean")
            || schema
                .get("allOf")
                .and_then(Value::as_array)
                .is_some_and(|members| {
                    members.iter().any(|member| {
                        schema_declares_boolean_path(document, member, path, depth + 1)
                    })
                });
    }
    if let Some(property) = schema
        .get("properties")
        .and_then(Value::as_object)
        .and_then(|properties| properties.get(path[0]))
    {
        return schema_declares_boolean_path(document, property, &path[1..], depth + 1);
    }
    if schema
        .get("allOf")
        .and_then(Value::as_array)
        .is_some_and(|members| {
            members
                .iter()
                .any(|member| schema_declares_boolean_path(document, member, path, depth + 1))
        })
    {
        return true;
    }
    for alternative in ["oneOf", "anyOf"] {
        if let Some(members) = schema.get(alternative).and_then(Value::as_array) {
            return !members.is_empty()
                && members
                    .iter()
                    .all(|member| schema_declares_boolean_path(document, member, path, depth + 1));
        }
    }
    false
}

fn schema_declares_numeric_path(
    document: &Value,
    schema: &Value,
    path: &[&str],
    depth: usize,
) -> bool {
    if depth > 32 {
        return false;
    }
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        return reference
            .strip_prefix('#')
            .and_then(|pointer| document.pointer(pointer))
            .is_some_and(|resolved| {
                schema_declares_numeric_path(document, resolved, path, depth + 1)
            });
    }
    if path.is_empty() {
        return matches!(
            schema.get("type").and_then(Value::as_str),
            Some("integer" | "number")
        ) || schema
            .get("allOf")
            .and_then(Value::as_array)
            .is_some_and(|members| {
                members
                    .iter()
                    .any(|member| schema_declares_numeric_path(document, member, path, depth + 1))
            });
    }
    if let Some(property) = schema
        .get("properties")
        .and_then(Value::as_object)
        .and_then(|properties| properties.get(path[0]))
    {
        return schema_declares_numeric_path(document, property, &path[1..], depth + 1);
    }
    if schema
        .get("allOf")
        .and_then(Value::as_array)
        .is_some_and(|members| {
            members
                .iter()
                .any(|member| schema_declares_numeric_path(document, member, path, depth + 1))
        })
    {
        return true;
    }
    for alternative in ["oneOf", "anyOf"] {
        if let Some(members) = schema.get(alternative).and_then(Value::as_array) {
            return !members.is_empty()
                && members
                    .iter()
                    .all(|member| schema_declares_numeric_path(document, member, path, depth + 1));
        }
    }
    false
}

fn resolve_local_schema<'a>(document: &'a Value, schema: &'a Value) -> &'a Value {
    schema
        .get("$ref")
        .and_then(Value::as_str)
        .and_then(|reference| reference.strip_prefix('#'))
        .and_then(|pointer| document.pointer(pointer))
        .unwrap_or(schema)
}

fn fallback_id(method: &str, path: &str) -> String {
    format!(
        "{}-{}",
        method,
        path.trim_matches('/')
            .replace(['/', '{', '}'], "-")
            .replace("--", "-")
    )
}

fn shared_and_operation_parameters<'a>(
    document: &'a Value,
    path_item: &'a Value,
    operation: &'a Value,
) -> Result<Vec<&'a Value>> {
    let shared = path_item
        .get("parameters")
        .and_then(Value::as_array)
        .into_iter()
        .flatten();
    let operation = operation
        .get("parameters")
        .and_then(Value::as_array)
        .into_iter()
        .flatten();
    let mut merged = Vec::new();
    let mut shared_keys = BTreeSet::new();
    for parameter in shared {
        let parameter = resolve_local_parameter(document, parameter, 0)?;
        let key = parameter_identity(parameter)?;
        if !shared_keys.insert(key.clone()) {
            return Err(CatalogError::DuplicateParameter {
                location: key.0,
                name: key.1,
            });
        }
        merged.push(parameter);
    }
    let mut operation_keys = BTreeSet::new();
    for parameter in operation {
        let parameter = resolve_local_parameter(document, parameter, 0)?;
        let key = parameter_identity(parameter)?;
        if !operation_keys.insert(key.clone()) {
            return Err(CatalogError::DuplicateParameter {
                location: key.0,
                name: key.1,
            });
        }
        if let Some(index) = merged
            .iter()
            .position(|candidate| parameter_identity(candidate).is_ok_and(|value| value == key))
        {
            merged[index] = parameter;
        } else {
            merged.push(parameter);
        }
    }
    Ok(merged)
}

fn resolve_local_parameter<'a>(
    document: &'a Value,
    parameter: &'a Value,
    depth: u8,
) -> Result<&'a Value> {
    let Some(reference) = parameter.get("$ref") else {
        return Ok(parameter);
    };
    let reference = reference
        .as_str()
        .ok_or_else(|| CatalogError::InvalidParameter("$ref".to_owned()))?;
    if depth >= 16 {
        return Err(CatalogError::ParameterReferenceDepth(reference.to_owned()));
    }
    let pointer = reference
        .strip_prefix('#')
        .filter(|pointer| pointer.starts_with('/'))
        .ok_or_else(|| CatalogError::UnsupportedParameterReference(reference.to_owned()))?;
    let resolved = document
        .pointer(pointer)
        .ok_or_else(|| CatalogError::UnresolvedParameterReference(reference.to_owned()))?;
    resolve_local_parameter(document, resolved, depth + 1)
}

fn parameter_identity(parameter: &Value) -> Result<(String, String)> {
    let location = parameter
        .get("in")
        .and_then(Value::as_str)
        .ok_or_else(|| CatalogError::InvalidParameter("in".to_owned()))?;
    let name = parameter
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| CatalogError::InvalidParameter("name".to_owned()))?;
    Ok((location.to_owned(), name.to_owned()))
}

fn selector_from_parameter(document: &Value, parameter: &Value) -> Result<SelectorV1> {
    let (location, name) = parameter_identity(parameter)?;
    let schema = parameter.get("schema");
    let mut active_references = BTreeSet::new();
    let normalized_schema = schema.map(|schema| {
        normalize_request_schema_contract(document, schema, 0, &mut active_references)
    });
    let query = (location == "query").then(|| {
        let style = parameter
            .get("style")
            .and_then(Value::as_str)
            .unwrap_or("form")
            .to_owned();
        QuerySerializationV1 {
            explode: parameter
                .get("explode")
                .and_then(Value::as_bool)
                .unwrap_or(style == "form"),
            style,
            allow_reserved: parameter
                .get("allowReserved")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            allow_empty_value: parameter
                .get("allowEmptyValue")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        }
    });
    let contract = (normalized_schema.is_some() || query.is_some()).then(|| SelectorContractV1 {
        schema: normalized_schema.unwrap_or_else(|| Value::Object(Map::new())),
        query,
    });
    Ok(SelectorV1 {
        name,
        location,
        required: parameter
            .get("required")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        value_type: schema
            .and_then(|schema| local_schema_value_type(document, schema, 0))
            .unwrap_or_else(|| "unknown".to_owned()),
        description: parameter
            .get("description")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| schema.and_then(|schema| local_schema_description(document, schema, 0))),
        contract,
    })
}

fn local_schema_value_type(document: &Value, schema: &Value, depth: u8) -> Option<String> {
    if depth > 16 {
        return None;
    }
    if let Some(value_type) = schema.get("type").and_then(Value::as_str) {
        return Some(value_type.to_owned());
    }
    if let Some(resolved) = schema
        .get("$ref")
        .and_then(Value::as_str)
        .and_then(|reference| reference.strip_prefix('#'))
        .and_then(|pointer| document.pointer(pointer))
    {
        return local_schema_value_type(document, resolved, depth + 1);
    }
    if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        let mut resolved = values.iter().map(json_value_type);
        let first = resolved.next()??;
        return resolved
            .all(|value_type| value_type == Some(first))
            .then(|| first.to_owned());
    }
    if let Some(members) = schema.get("allOf").and_then(Value::as_array) {
        let mut resolved = members
            .iter()
            .filter_map(|member| local_schema_value_type(document, member, depth + 1));
        let first = resolved.next()?;
        return resolved
            .all(|value_type| value_type == first)
            .then_some(first);
    }
    for alternative in ["oneOf", "anyOf"] {
        let Some(members) = schema.get(alternative).and_then(Value::as_array) else {
            continue;
        };
        let mut resolved = members
            .iter()
            .map(|member| local_schema_value_type(document, member, depth + 1));
        let first = resolved.next()??;
        return resolved
            .all(|value_type| value_type.as_deref() == Some(first.as_str()))
            .then_some(first);
    }
    None
}

fn json_value_type(value: &Value) -> Option<&'static str> {
    match value {
        Value::Bool(_) => Some("boolean"),
        Value::Number(number) if number.is_i64() || number.is_u64() => Some("integer"),
        Value::Number(_) => Some("number"),
        Value::String(_) => Some("string"),
        Value::Array(_) => Some("array"),
        Value::Object(_) => Some("object"),
        Value::Null => None,
    }
}

fn local_schema_description(document: &Value, schema: &Value, depth: u8) -> Option<String> {
    if depth > 16 {
        return None;
    }
    if let Some(description) = schema.get("description").and_then(Value::as_str) {
        return Some(description.to_owned());
    }
    if let Some(resolved) = schema
        .get("$ref")
        .and_then(Value::as_str)
        .and_then(|reference| reference.strip_prefix('#'))
        .and_then(|pointer| document.pointer(pointer))
    {
        return local_schema_description(document, resolved, depth + 1);
    }
    if let Some(members) = schema.get("allOf").and_then(Value::as_array) {
        return members
            .iter()
            .find_map(|member| local_schema_description(document, member, depth + 1));
    }
    for alternative in ["oneOf", "anyOf"] {
        let Some(members) = schema.get(alternative).and_then(Value::as_array) else {
            continue;
        };
        let mut resolved = members
            .iter()
            .map(|member| local_schema_description(document, member, depth + 1));
        let first = resolved.next()??;
        return resolved
            .all(|description| description.as_deref() == Some(first.as_str()))
            .then_some(first);
    }
    None
}

fn maturity(operation: &serde_json::Map<String, Value>) -> Maturity {
    match operation.get("x-fern-availability").and_then(Value::as_str) {
        Some("generally-available") => Maturity::GenerallyAvailable,
        Some("beta") => Maturity::Beta,
        Some("experimental") => Maturity::Experimental,
        Some("deprecated") => Maturity::Deprecated,
        _ if operation
            .get("deprecated")
            .and_then(Value::as_bool)
            .unwrap_or(false) =>
        {
            Maturity::Deprecated
        }
        _ => Maturity::Unknown,
    }
}

fn classify(capability: &mut CapabilityV1) {
    let text = format!(
        "{} {} {}",
        capability.id,
        capability.title,
        capability.description.as_deref().unwrap_or_default()
    )
    .to_ascii_lowercase();

    let returns_sensitive_value = capability.path.ends_with("/token")
        || capability.path.ends_with("/upload-token")
        || capability.id == "ai-search-fetch-tokens"
        || capability.id == "containerWranglerSsh";
    if returns_sensitive_value {
        capability.mutating = true;
        capability.risk = RiskClass::SecretSensitive;
        capability.effect = EffectClass::IdentityOrOwnership;
        capability.adapter_status = AdapterStatus::Native;
        capability.cost = cfctl_core::CostV1::default();
        capability.verification.required = false;
        "sink_write_and_source_response_status".clone_into(&mut capability.verification.strategy);
        capability.rollback.warning = Some(
            "retrieved credentials are delivered only to an explicit local sink and are never recorded in evidence"
                .to_owned(),
        );
        return;
    }

    if capability.method == "GET" || capability.method == "HEAD" || capability.method == "OPTIONS" {
        capability.risk = RiskClass::Read;
        capability.effect = EffectClass::ReadOnly;
        capability.verification.required = false;
        "not_applicable".clone_into(&mut capability.verification.strategy);
        return;
    }
    if classify_operation_specific_contract(capability) {
        return;
    }
    if capability.method == "DELETE"
        || ["delete", "purge", "revoke", "remove"]
            .iter()
            .any(|term| text.contains(term))
    {
        capability.risk = RiskClass::Destructive;
        capability.effect = EffectClass::Destructive;
    } else if ["send email", "email send", "send message", "notification"]
        .iter()
        .any(|term| text.contains(term))
    {
        capability.risk = RiskClass::ExternalCommunication;
        capability.effect = EffectClass::ExternalCommunication;
    } else if [
        "billing",
        "subscription",
        "purchase",
        "registrar",
        "domain transfer",
    ]
    .iter()
    .any(|term| text.contains(term))
    {
        capability.risk = RiskClass::Spend;
        capability.effect = EffectClass::Spend;
        capability.cost.incremental = true;
        capability.cost.known = false;
        capability.cost.maximum = None;
        capability.cost.basis =
            Some("official schema does not declare a hard price ceiling".to_owned());
    } else if ["member", "role", "ownership", "oauth client", "api token"]
        .iter()
        .any(|term| text.contains(term))
    {
        capability.risk = RiskClass::IdentityOrOwnership;
        capability.effect = EffectClass::IdentityOrOwnership;
    } else {
        capability.risk = RiskClass::Unknown;
        capability.effect = EffectClass::Unknown;
    }

    if text.contains("not implemented") {
        capability.adapter_status = AdapterStatus::Blocked;
        capability.blocked_reason =
            Some("official schema marks the operation as not implemented".to_owned());
    }
    capability.verification.required = true;
    "post_change_read_or_operation_specific_verifier"
        .clone_into(&mut capability.verification.strategy);
}

fn classify_operation_specific_contract(capability: &mut CapabilityV1) -> bool {
    if [
        "account-api-tokens-create-token",
        "account-api-tokens-roll-token",
        "account-api-tokens-delete-token",
        "user-api-tokens-create-token",
        "user-api-tokens-roll-token",
        "user-api-tokens-delete-token",
    ]
    .contains(&capability.id.as_str())
    {
        classify_api_token_lifecycle(capability);
    } else if [
        "account-api-tokens-update-token",
        "user-api-tokens-update-token",
    ]
    .contains(&capability.id.as_str())
    {
        block_api_token_update_by_doctrine(capability);
    } else if r2_bucket_create_operation_supported(capability) {
        classify_r2_bucket_create(capability);
    } else if d1_database_create_operation_supported(capability) {
        classify_d1_database_create(capability);
    } else if let Some(kind) = worker_script_secret_operation_kind(capability) {
        classify_worker_script_secret_operation(capability, kind);
    } else if WORKERS_KV_NAMESPACE_MUTATION_IDS.contains(&capability.id.as_str()) {
        if let Some(kind) = workers_kv_namespace_operation_kind(capability) {
            classify_workers_kv_namespace_operation(capability, kind);
        }
    } else if r2_temporary_credentials_operation_supported(capability) {
        classify_r2_temporary_credentials(capability);
    } else if email_routing_mutation_supported(capability) {
        classify_email_routing_mutation(capability);
    } else if email_routing_settings_toggle_supported(capability) {
        classify_email_routing_settings_toggle(capability);
    } else if zone_cache_purge_operation_supported(capability) {
        classify_zone_cache_purge(capability);
    } else if let Some(kind) = oauth_client_secret_operation_kind(capability) {
        classify_oauth_client_secret_operation(capability, kind);
    } else if is_workers_ai_model_run(capability) {
        classify_workers_ai_model_run(capability);
    } else if is_d1_read_replication_update(capability) {
        classify_d1_read_replication_update(capability);
    } else if is_dns_record_lifecycle(&capability.id) {
        classify_dns_record_lifecycle(capability);
    } else if access_service_token_update_contract_supported(capability) {
        classify_access_service_token_update(capability);
    } else if let Some(kind) = access_authorization_configuration_kind(capability) {
        classify_access_authorization_configuration(capability, kind);
    } else if turnstile_widget_rotation_contract_supported(capability) {
        classify_turnstile_widget_rotation(capability);
    } else if turnstile_widget_create_contract_supported(capability) {
        classify_turnstile_widget_create(capability);
    } else if turnstile_widget_update_contract_supported(capability) {
        classify_turnstile_widget_update(capability);
    } else if let Some(kind) = load_balancing_configuration_kind(capability) {
        classify_load_balancing_configuration(capability, kind);
    } else if is_email_security_settings_configuration(capability) {
        classify_email_security_settings_configuration(capability);
    } else if let Some(kind) = cloudflare_tunnel_lifecycle_kind(capability) {
        classify_cloudflare_tunnel_lifecycle(capability, kind);
    } else if cloudflare_tunnel_configuration_contract_supported(capability) {
        classify_cloudflare_tunnel_configuration(capability);
    } else if warp_connector_configuration_contract_supported(capability) {
        classify_warp_connector_configuration(capability);
    } else if web_analytics_rum_contract_supported(capability) {
        classify_web_analytics_rum(capability);
    } else if let Some(kind) = queue_configuration_kind(capability) {
        classify_queue_configuration(capability, kind);
    } else {
        return false;
    }
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkerScriptSecretOperationKind {
    Put,
    Delete,
}

const WORKER_SCRIPT_SECRET_COLLECTION_PATH: &str =
    "/accounts/{account_id}/workers/scripts/{script_name}/secrets";
const WORKER_SCRIPT_SECRET_DETAIL_PATH: &str =
    "/accounts/{account_id}/workers/scripts/{script_name}/secrets/{secret_name}";
const WORKER_SCRIPT_SECRET_READ_CAPABILITY_ID: &str = "worker-get-script-secret";

fn worker_script_secret_operation_kind(
    capability: &CapabilityV1,
) -> Option<WorkerScriptSecretOperationKind> {
    if capability.product != "Worker Script"
        || capability.permissions != ["Workers Scripts Write"]
        || !worker_script_secret_response_contract_supported(capability)
    {
        return None;
    }
    match (
        capability.id.as_str(),
        capability.method.as_str(),
        capability.path.as_str(),
    ) {
        ("worker-put-script-secret", "PUT", WORKER_SCRIPT_SECRET_COLLECTION_PATH)
            if capability.title == "Add script secret"
                && capability.description.as_deref() == Some("Add a secret to a script.")
                && worker_script_secret_put_selectors_supported(capability)
                && worker_script_secret_put_request_contract_supported(capability) =>
        {
            Some(WorkerScriptSecretOperationKind::Put)
        }
        ("worker-delete-script-secret", "DELETE", WORKER_SCRIPT_SECRET_DETAIL_PATH)
            if capability.title == "Delete script secret"
                && capability.description.as_deref() == Some("Remove a secret from a script.")
                && capability.request_schema.is_none()
                && worker_script_secret_detail_selectors_supported(capability) =>
        {
            Some(WorkerScriptSecretOperationKind::Delete)
        }
        _ => None,
    }
}

fn worker_script_secret_response_contract_supported(capability: &CapabilityV1) -> bool {
    capability
        .response_contract
        .as_ref()
        .is_some_and(|response| {
            response.success_statuses == ["200"]
                && response.success_media_types == ["application/json"]
                && response.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
        })
}

fn worker_script_secret_put_selectors_supported(capability: &CapabilityV1) -> bool {
    worker_script_secret_path_selectors_supported(capability, false)
}

fn worker_script_secret_detail_selectors_supported(capability: &CapabilityV1) -> bool {
    worker_script_secret_path_selectors_supported(capability, true)
        && capability.selectors.iter().any(|selector| {
            selector.name == "url_encoded"
                && selector.location == "query"
                && !selector.required
                && selector.value_type == "boolean"
                && selector.description.as_deref()
                    == Some("Flag that indicates whether the secret name is URL encoded.")
                && selector.contract.as_ref().is_some_and(|contract| {
                    contract.schema == serde_json::json!({"type":"boolean"})
                        && contract.query.as_ref().is_some_and(|query| {
                            query.style == "form"
                                && query.explode
                                && !query.allow_reserved
                                && !query.allow_empty_value
                        })
                })
        })
}

fn worker_script_secret_path_selectors_supported(
    capability: &CapabilityV1,
    includes_secret_name: bool,
) -> bool {
    let expected_len = if includes_secret_name { 4 } else { 2 };
    if capability.selectors.len() != expected_len {
        return false;
    }
    let expected = [
        (
            "account_id",
            "Identifier.",
            serde_json::json!({"maxLength":32,"type":"string"}),
        ),
        (
            "script_name",
            "Name of the script, used in URLs and route configuration.",
            serde_json::json!({"type":"string"}),
        ),
        (
            "secret_name",
            "A JavaScript variable name for the secret binding.",
            serde_json::json!({"type":"string"}),
        ),
    ];
    expected[..if includes_secret_name { 3 } else { 2 }]
        .iter()
        .all(|(name, description, schema)| {
            capability.selectors.iter().any(|selector| {
                selector.name == *name
                    && selector.location == "path"
                    && selector.required
                    && selector.value_type == "string"
                    && selector.description.as_deref() == Some(*description)
                    && selector.contract.as_ref().is_some_and(|contract| {
                        contract.schema == *schema && contract.query.is_none()
                    })
            })
        })
}

fn worker_script_secret_put_request_contract_supported(capability: &CapabilityV1) -> bool {
    capability.request_schema.as_ref()
        == Some(&serde_json::json!({
            "type": "object",
            "oneOf": [
                {
                    "type": "object",
                    "required": ["name", "type", "text"],
                    "properties": {
                        "name": {"type": "string"},
                        "type": {"type": "string", "enum": ["secret_text"]},
                        "text": {"type": "string", "writeOnly": true}
                    }
                },
                {
                    "type": "object",
                    "required": ["name", "type", "format", "algorithm", "usages"],
                    "properties": {
                        "name": {"type": "string"},
                        "type": {"type": "string", "enum": ["secret_key"]},
                        "format": {"type": "string", "enum": ["raw", "pkcs8", "spki", "jwk"]},
                        "algorithm": {"type": "object"},
                        "usages": {
                            "type": "array",
                            "items": {"type": "string", "enum": ["encrypt", "decrypt", "sign", "verify", "deriveKey", "deriveBits", "wrapKey", "unwrapKey"]}
                        },
                        "key_base64": {"type": "string", "writeOnly": true},
                        "key_jwk": {"type": "object", "writeOnly": true}
                    }
                }
            ],
            "x-cfctl-body-required": true
        }))
}

fn classify_worker_script_secret_operation(
    capability: &mut CapabilityV1,
    kind: WorkerScriptSecretOperationKind,
) {
    capability.cost = cfctl_core::CostV1::default();
    capability.cost.billing_model = BillingModelV1::Subscription;
    capability.cost.exposure = CostExposureV1::DownstreamUsage;
    capability.cost.basis = Some(
        "adding, replacing, or deleting one Worker secret binding does not purchase a plan or add a direct operation charge, so the direct incremental ceiling is zero; the deployed Worker remains subject to its existing plan and downstream usage charges"
            .to_owned(),
    );
    capability.cost.references = vec![
        KnowledgeReferenceV1 {
            title: "Workers script secrets API".to_owned(),
            url: "https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/secrets/"
                .to_owned(),
            source: "official Cloudflare API reference".to_owned(),
        },
        KnowledgeReferenceV1 {
            title: "Workers secrets".to_owned(),
            url: "https://developers.cloudflare.com/workers/configuration/secrets/".to_owned(),
            source: "official Cloudflare docs".to_owned(),
        },
        KnowledgeReferenceV1 {
            title: "Workers pricing".to_owned(),
            url: "https://developers.cloudflare.com/workers/platform/pricing/".to_owned(),
            source: "official Cloudflare docs".to_owned(),
        },
    ];
    capability.entitlement.available = Some(true);
    capability.entitlement.plans =
        BTreeMap::from([("free".to_owned(), true), ("paid".to_owned(), true)]);
    capability.entitlement.source =
        Some("https://developers.cloudflare.com/workers/platform/pricing/".to_owned());
    capability.entitlement.blocker = None;
    capability.entitlement.requires_live_resolution = false;
    capability.verification.required = true;
    capability.rollback.supported = false;
    capability.rollback.strategy = None;
    match kind {
        WorkerScriptSecretOperationKind::Put => {
            capability.risk = RiskClass::SecretSensitive;
            capability.effect = EffectClass::IdentityOrOwnership;
            "worker_script_secret_reports_planned_name_and_type_after_put"
                .clone_into(&mut capability.verification.strategy);
            capability.rollback.warning = Some(
                "the API is an upsert and never returns the prior value, so cfctl cannot restore a replaced secret automatically; preserve the prior value in its trusted source and use a separately reviewed plan if restoration is required"
                    .to_owned(),
            );
        }
        WorkerScriptSecretOperationKind::Delete => {
            capability
                .selectors
                .retain(|selector| selector.location == "path");
            capability.risk = RiskClass::Destructive;
            capability.effect = EffectClass::Irreversible;
            "same_resource_returns_not_found_after_delete"
                .clone_into(&mut capability.verification.strategy);
            capability.rollback.warning = Some(
                "deletion is irreversible because Cloudflare never returns the secret value and cfctl cannot restore it; recreate it only from a trusted source through a separately reviewed plan"
                    .to_owned(),
            );
        }
    }
}

fn finalize_worker_script_secret_contracts(
    document: &Value,
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    let read_supported = capabilities
        .get(WORKER_SCRIPT_SECRET_READ_CAPABILITY_ID)
        .is_some_and(|capability| {
            capability.id == WORKER_SCRIPT_SECRET_READ_CAPABILITY_ID
                && capability.title == "Get secret binding"
                && capability.description.as_deref()
                    == Some("Get a given secret binding (value omitted) on a script.")
                && capability.method == "GET"
                && capability.path == WORKER_SCRIPT_SECRET_DETAIL_PATH
                && capability.product == "Worker Script"
                && capability.permissions.is_empty()
                && capability.request_schema.is_none()
                && worker_script_secret_detail_selectors_supported(capability)
                && worker_script_secret_response_contract_supported(capability)
        })
        && document
            .pointer("/paths/~1accounts~1{account_id}~1workers~1scripts~1{script_name}~1secrets~1{secret_name}/get")
            .is_some_and(|operation| {
                success_response_declares_result_fields(document, operation, &["name", "type"])
                    && success_response_omits_or_marks_write_only_result_fields(
                        document,
                        operation,
                        &["text", "key_base64", "key_jwk"],
                    )
            });
    if !read_supported {
        return;
    }

    let put_response_supported = document
        .pointer("/paths/~1accounts~1{account_id}~1workers~1scripts~1{script_name}~1secrets/put")
        .is_some_and(|operation| {
            success_response_declares_result_fields(document, operation, &["name", "type"])
                && success_response_omits_or_marks_write_only_result_fields(
                    document,
                    operation,
                    &["text", "key_base64", "key_jwk"],
                )
        });
    if put_response_supported
        && let Some(capability) = capabilities.get_mut("worker-put-script-secret")
        && worker_script_secret_operation_kind(capability)
            == Some(WorkerScriptSecretOperationKind::Put)
    {
        capability.same_path_read = Some(SamePathReadContractV1 {
            path: WORKER_SCRIPT_SECRET_DETAIL_PATH.to_owned(),
            read_capability_id: WORKER_SCRIPT_SECRET_READ_CAPABILITY_ID.to_owned(),
            verified_response_fields: vec!["name".to_owned(), "type".to_owned()],
        });
        // Cloudflare's OpenAPI declares only 200 for this operation, but the
        // live API answers a successful secret put with 201 Created. Pinning
        // 200 alone sent every successful put into post-boundary recovery:
        // the secret was created, and cfctl could not confirm it. Observed
        // live 2026-07-19; the upstream schema is the defect, so widen the
        // pin to the statuses Cloudflare actually returns rather than
        // accepting any success status.
        if let Some(response) = capability.response_contract.as_mut()
            && response.success_statuses == ["200"]
        {
            response.success_statuses = vec!["200".to_owned(), "201".to_owned()];
        }
        refresh_dynamic_mutation_contract(capability);
    }

    if let Some(capability) = capabilities.get_mut("worker-delete-script-secret")
        && capability.method == "DELETE"
        && capability.path == WORKER_SCRIPT_SECRET_DETAIL_PATH
        && capability.product == "Worker Script"
        && capability.permissions == ["Workers Scripts Write"]
        && capability.request_schema.is_none()
        && capability.selectors.len() == 3
        && capability
            .selectors
            .iter()
            .all(|selector| selector.location == "path")
    {
        capability.same_path_read = Some(SamePathReadContractV1 {
            path: WORKER_SCRIPT_SECRET_DETAIL_PATH.to_owned(),
            read_capability_id: WORKER_SCRIPT_SECRET_READ_CAPABILITY_ID.to_owned(),
            verified_response_fields: Vec::new(),
        });
        refresh_dynamic_mutation_contract(capability);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkersKvNamespaceOperationKind {
    Create,
    Rename,
    Delete,
}

const WORKERS_KV_NAMESPACE_COLLECTION_PATH: &str = "/accounts/{account_id}/storage/kv/namespaces";
const WORKERS_KV_NAMESPACE_DETAIL_PATH: &str =
    "/accounts/{account_id}/storage/kv/namespaces/{namespace_id}";
const WORKERS_KV_NAMESPACE_READ_CAPABILITY_ID: &str = "workers-kv-namespace-get-a-namespace";
const WORKERS_KV_NAMESPACE_MUTATION_IDS: [&str; 3] = [
    "workers-kv-namespace-create-a-namespace",
    "workers-kv-namespace-rename-a-namespace",
    "workers-kv-namespace-remove-a-namespace",
];

fn workers_kv_namespace_operation_kind(
    capability: &CapabilityV1,
) -> Option<WorkersKvNamespaceOperationKind> {
    if capability.product != "Workers KV Namespace"
        || capability.account_scope != "account"
        || capability.permissions != ["Workers KV Storage Write"]
        || !workers_kv_namespace_response_contract_supported(capability)
    {
        return None;
    }
    match (
        capability.id.as_str(),
        capability.method.as_str(),
        capability.path.as_str(),
    ) {
        (
            "workers-kv-namespace-create-a-namespace",
            "POST",
            WORKERS_KV_NAMESPACE_COLLECTION_PATH,
        ) if capability.title == "Create a Namespace"
            && capability.description.as_deref()
                == Some(
                    "Creates a namespace under the given title. A `400` is returned if the account already owns a namespace with this title. A namespace must be explicitly deleted to be replaced.",
                )
            && workers_kv_namespace_selectors_supported(capability, false)
            && workers_kv_namespace_title_request_supported(capability) =>
        {
            Some(WorkersKvNamespaceOperationKind::Create)
        }
        ("workers-kv-namespace-rename-a-namespace", "PUT", WORKERS_KV_NAMESPACE_DETAIL_PATH)
            if capability.title == "Rename a Namespace"
                && capability.description.as_deref() == Some("Modifies a namespace's title.")
                && workers_kv_namespace_selectors_supported(capability, true)
                && workers_kv_namespace_title_request_supported(capability) =>
        {
            Some(WorkersKvNamespaceOperationKind::Rename)
        }
        ("workers-kv-namespace-remove-a-namespace", "DELETE", WORKERS_KV_NAMESPACE_DETAIL_PATH)
            if capability.title == "Remove a Namespace"
                && capability.description.as_deref()
                    == Some("Deletes the namespace corresponding to the given ID.")
                && workers_kv_namespace_selectors_supported(capability, true)
                && capability.request_schema.is_none() =>
        {
            Some(WorkersKvNamespaceOperationKind::Delete)
        }
        _ => None,
    }
}

fn workers_kv_namespace_response_contract_supported(capability: &CapabilityV1) -> bool {
    capability
        .response_contract
        .as_ref()
        .is_some_and(|response| {
            response.success_statuses == ["200"]
                && response.success_media_types == ["application/json"]
                && response.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
        })
}

fn workers_kv_namespace_selectors_supported(
    capability: &CapabilityV1,
    includes_namespace_id: bool,
) -> bool {
    let expected = if includes_namespace_id {
        [
            ("account_id", "Identifier."),
            ("namespace_id", "Namespace identifier tag."),
        ]
        .as_slice()
    } else {
        [("account_id", "Identifier.")].as_slice()
    };
    capability.selectors.len() == expected.len()
        && expected.iter().all(|(name, description)| {
            capability.selectors.iter().any(|selector| {
                selector.name == *name
                    && selector.location == "path"
                    && selector.required
                    && selector.value_type == "string"
                    && selector.description.as_deref() == Some(*description)
                    && selector.contract.as_ref().is_some_and(|contract| {
                        contract.schema == serde_json::json!({"maxLength":32,"type":"string"})
                            && contract.query.is_none()
                    })
            })
        })
}

fn workers_kv_namespace_title_request_supported(capability: &CapabilityV1) -> bool {
    capability.request_schema.as_ref()
        == Some(&serde_json::json!({
            "type": "object",
            "required": ["title"],
            "properties": {
                "title": {"maxLength": 512, "type": "string"}
            },
            "x-cfctl-body-required": true
        }))
}

fn workers_kv_namespace_references() -> Vec<KnowledgeReferenceV1> {
    vec![
        KnowledgeReferenceV1 {
            title: "Workers KV namespace API".to_owned(),
            url: "https://developers.cloudflare.com/api/resources/kv/".to_owned(),
            source: "official Cloudflare API reference".to_owned(),
        },
        KnowledgeReferenceV1 {
            title: "Workers KV pricing".to_owned(),
            url: "https://developers.cloudflare.com/kv/platform/pricing/".to_owned(),
            source: "official Cloudflare docs".to_owned(),
        },
        KnowledgeReferenceV1 {
            title: "Workers KV changelog".to_owned(),
            url: "https://developers.cloudflare.com/changelog/product/kv/".to_owned(),
            source: "official Cloudflare changelog".to_owned(),
        },
    ]
}

fn classify_workers_kv_namespace_operation(
    capability: &mut CapabilityV1,
    kind: WorkersKvNamespaceOperationKind,
) {
    capability.entitlement.available = Some(true);
    capability.entitlement.plans =
        BTreeMap::from([("free".to_owned(), true), ("paid".to_owned(), true)]);
    capability.entitlement.blocker = None;
    capability.entitlement.source =
        Some("https://developers.cloudflare.com/kv/platform/pricing/".to_owned());
    capability.entitlement.requires_live_resolution = false;
    capability.cost = cfctl_core::CostV1::default();
    capability.cost.billing_model = BillingModelV1::UsageBased;
    capability.cost.exposure = CostExposureV1::DownstreamUsage;
    capability.cost.references = workers_kv_namespace_references();
    capability.verification.required = true;
    "post_change_read_or_operation_specific_verifier"
        .clone_into(&mut capability.verification.strategy);
    capability.rollback.supported = false;
    capability.rollback.strategy = None;
    match kind {
        WorkersKvNamespaceOperationKind::Create => {
            capability.risk = RiskClass::ScopedWrite;
            capability.effect = EffectClass::ReversibleWrite;
            capability.cost.basis = Some(
                "the namespace-management request does not read, write, delete, or list a KV key and has no direct incremental operation charge; later KV key operations and stored data remain usage-billed"
                    .to_owned(),
            );
            capability.rollback.warning = Some(
                "compensation requires an exact returned namespace identifier and a separately reviewed delete plan"
                    .to_owned(),
            );
        }
        WorkersKvNamespaceOperationKind::Rename => {
            capability.risk = RiskClass::ScopedWrite;
            capability.effect = EffectClass::ReversibleWrite;
            capability.cost.basis = Some(
                "renaming a namespace does not read, write, delete, or list a KV key and has no direct incremental operation charge; later KV key operations and stored data remain usage-billed"
                    .to_owned(),
            );
            capability.rollback.warning = Some(
                "automatic restoration is unsupported because the plan does not bind a pre-change snapshot; restoration requires a separately reviewed rename plan built from trusted evidence"
                    .to_owned(),
            );
        }
        WorkersKvNamespaceOperationKind::Delete => {
            capability.risk = RiskClass::Destructive;
            capability.effect = EffectClass::Irreversible;
            capability.cost.incremental = true;
            capability.cost.currency = None;
            capability.cost.maximum = None;
            capability.cost.known = false;
            capability.cost.basis = Some(
                "Cloudflare prices KV key deletions, but whether removing a populated namespace bills deletion of its contained keys is not documented; cfctl therefore cannot declare a finite operation ceiling"
                    .to_owned(),
            );
            capability.rollback.warning = Some(
                "namespace deletion and loss of all contained values are irreversible without a prior export or trusted snapshot; recreation requires separately reviewed namespace and key-write plans"
                    .to_owned(),
            );
        }
    }
}

fn finalize_workers_kv_namespace_contracts(
    document: &Value,
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    let read_supported = capabilities
        .get(WORKERS_KV_NAMESPACE_READ_CAPABILITY_ID)
        .is_some_and(|capability| {
            capability.id == WORKERS_KV_NAMESPACE_READ_CAPABILITY_ID
                && capability.title == "Get a Namespace"
                && capability.description.as_deref()
                    == Some("Get the namespace corresponding to the given ID.")
                && capability.method == "GET"
                && capability.path == WORKERS_KV_NAMESPACE_DETAIL_PATH
                && capability.product == "Workers KV Namespace"
                && capability.account_scope == "account"
                && capability.permissions == ["Workers KV Storage Write", "Workers KV Storage Read"]
                && capability.request_schema.is_none()
                && workers_kv_namespace_selectors_supported(capability, true)
                && workers_kv_namespace_response_contract_supported(capability)
        })
        && document
            .pointer("/paths/~1accounts~1{account_id}~1storage~1kv~1namespaces~1{namespace_id}/get")
            .is_some_and(|operation| {
                success_response_declares_result_fields(document, operation, &["id", "title"])
            });

    for capability_id in WORKERS_KV_NAMESPACE_MUTATION_IDS {
        let Some(capability) = capabilities.get_mut(capability_id) else {
            continue;
        };
        let Some(kind) = workers_kv_namespace_operation_kind(capability) else {
            continue;
        };
        let operation_response_supported = match kind {
            WorkersKvNamespaceOperationKind::Create => document
                .pointer("/paths/~1accounts~1{account_id}~1storage~1kv~1namespaces/post")
                .is_some_and(|operation| {
                    success_response_declares_result_fields(document, operation, &["id", "title"])
                }),
            WorkersKvNamespaceOperationKind::Rename => document
                .pointer(
                    "/paths/~1accounts~1{account_id}~1storage~1kv~1namespaces~1{namespace_id}/put",
                )
                .is_some_and(|operation| {
                    success_response_declares_result_fields(document, operation, &["id", "title"])
                }),
            WorkersKvNamespaceOperationKind::Delete => true,
        };
        if !read_supported || !operation_response_supported {
            capability.created_resource = None;
            capability.same_path_read = None;
            capability.adapter_status = AdapterStatus::Blocked;
            capability.blocked_reason =
                Some("Workers KV namespace source or exact readback contract drifted".to_owned());
            continue;
        }

        classify_workers_kv_namespace_operation(capability, kind);
        match kind {
            WorkersKvNamespaceOperationKind::Create => {
                capability.created_resource = Some(CreatedResourceContractV1 {
                    detail_path: WORKERS_KV_NAMESPACE_DETAIL_PATH.to_owned(),
                    identity_selector: "namespace_id".to_owned(),
                    response_result_identity_pointer: "/id".to_owned(),
                    read_capability_id: WORKERS_KV_NAMESPACE_READ_CAPABILITY_ID.to_owned(),
                    delete_capability_id: "workers-kv-namespace-remove-a-namespace".to_owned(),
                    verified_response_fields: vec!["title".to_owned()],
                });
                "created_resource_contains_planned_fields_by_returned_id"
                    .clone_into(&mut capability.verification.strategy);
                capability.rollback.supported = true;
                // Graduated from the generic delete strategy: rollback of a
                // cfctl-created namespace derives a delete gated on a live
                // empty-namespace proof, which bounds the otherwise-unknown
                // per-key deletion cost to zero. Populated namespaces and
                // arbitrary (non-cfctl-created) namespaces stay blocked.
                capability.rollback.strategy = Some(
                    "delete_created_empty_kv_namespace_by_returned_id_if_unchanged".to_owned(),
                );
                capability.rollback.warning = Some(
                    "compensation creates a separate namespace delete plan that must be reviewed and explicitly approved, and runs only if the namespace is still provably empty; a populated namespace fails closed, and arbitrary namespace deletion remains blocked"
                        .to_owned(),
                );
            }
            WorkersKvNamespaceOperationKind::Rename => {
                capability.same_path_read = Some(SamePathReadContractV1 {
                    path: WORKERS_KV_NAMESPACE_DETAIL_PATH.to_owned(),
                    read_capability_id: WORKERS_KV_NAMESPACE_READ_CAPABILITY_ID.to_owned(),
                    verified_response_fields: vec!["title".to_owned()],
                });
                "same_resource_contains_planned_fields_after_update"
                    .clone_into(&mut capability.verification.strategy);
            }
            WorkersKvNamespaceOperationKind::Delete => {
                capability.same_path_read = Some(SamePathReadContractV1 {
                    path: WORKERS_KV_NAMESPACE_DETAIL_PATH.to_owned(),
                    read_capability_id: WORKERS_KV_NAMESPACE_READ_CAPABILITY_ID.to_owned(),
                    verified_response_fields: Vec::new(),
                });
                "same_resource_returns_not_found_after_delete"
                    .clone_into(&mut capability.verification.strategy);
            }
        }
        refresh_dynamic_mutation_contract(capability);
    }
}

const R2_TEMPORARY_CREDENTIALS_CAPABILITY_ID: &str = "r2-create-temp-access-credentials";
const R2_TEMPORARY_CREDENTIALS_PATH: &str = "/accounts/{account_id}/r2/temp-access-credentials";
const USER_TOKEN_VERIFY_CAPABILITY_ID: &str = "user-api-tokens-verify-token";
const USER_TOKEN_VERIFY_PATH: &str = "/user/tokens/verify";
const R2_TEMPORARY_CREDENTIAL_PERMISSIONS: [&str; 6] = [
    "Workers R2 Storage Write",
    "Workers R2 Storage Read",
    "Workers R2 Storage Bucket Item Write",
    "Workers R2 Storage Bucket Item Read",
    "Workers R2 Data Catalog Write",
    "Workers R2 Data Catalog Read",
];

const ZONE_CACHE_PURGE_BASE_IDS: [&str; 2] = ["zone-purge", "zone-environment-purge"];
const ZONE_CACHE_PURGE_PERMISSION: &str = "Cache Purge";
const CACHE_PURGE_DOCS_URL: &str = "https://developers.cloudflare.com/cache/how-to/purge-cache/";
const CACHE_PURGE_BY_TAGS_DOCS_URL: &str =
    "https://developers.cloudflare.com/cache/how-to/purge-cache/purge-cache-by-cache-tags/";
const CACHE_PURGE_VERIFICATION_STRATEGY: &str = "cache_purge_response_reports_target_zone_id";

fn r2_temporary_credentials_operation_supported(capability: &CapabilityV1) -> bool {
    capability.id == R2_TEMPORARY_CREDENTIALS_CAPABILITY_ID
        && capability.title == "Create Temporary Access Credentials"
        && capability.description.as_deref()
            == Some(
                "Creates temporary access credentials on a bucket that can be optionally scoped to prefixes or objects.",
            )
        && capability.method == "POST"
        && capability.path == R2_TEMPORARY_CREDENTIALS_PATH
        && capability.product == "R2 Bucket"
        && capability.account_scope == "account"
        && capability.permissions.is_empty()
        && capability.selectors.len() == 1
        && capability.selectors.first().is_some_and(|selector| {
            selector.name == "account_id"
                && selector.location == "path"
                && selector.required
                && selector.value_type == "string"
                && selector.description.as_deref() == Some("Account ID.")
                && selector.contract.as_ref().is_some_and(|contract| {
                    contract.schema == serde_json::json!({"maxLength":32,"type":"string"})
                        && contract.query.is_none()
                })
        })
        && capability.request_schema.as_ref()
            == Some(&serde_json::json!({
                "type":"object",
                "required":["bucket","permission","ttlSeconds","parentAccessKeyId"],
                "properties":{
                    "bucket":{"type":"string"},
                    "objects":{"type":"array","items":{"type":"string"}},
                    "parentAccessKeyId":{"type":"string"},
                    "permission":{"type":"string","enum":["admin-read-write","admin-read-only","object-read-write","object-read-only"]},
                    "prefixes":{"type":"array","items":{"type":"string"}},
                    "ttlSeconds":{"type":"number","maximum":604_800}
                },
                "x-cfctl-body-required":true
            }))
        && capability
            .response_contract
            .as_ref()
            .is_some_and(|response| {
                response.success_statuses == ["200"]
                    && response.success_media_types == ["application/json"]
                    && response.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
            })
}

fn classify_r2_temporary_credentials(capability: &mut CapabilityV1) {
    capability.permissions = R2_TEMPORARY_CREDENTIAL_PERMISSIONS
        .iter()
        .map(ToString::to_string)
        .collect();
    capability.risk = RiskClass::SecretSensitive;
    capability.effect = EffectClass::IdentityOrOwnership;
    capability.cost = cfctl_core::CostV1::default();
    capability.cost.billing_model = BillingModelV1::UsageBased;
    capability.cost.exposure = CostExposureV1::DownstreamUsage;
    capability.cost.basis = Some(
        "minting the temporary credential has no direct operation charge and cannot activate or purchase R2; storage and Class A/Class B operations performed with the credential remain usage-billed"
            .to_owned(),
    );
    capability.cost.references = vec![
        KnowledgeReferenceV1 {
            title: "R2 temporary credentials".to_owned(),
            url: "https://developers.cloudflare.com/r2/api/s3/temporary-credentials/".to_owned(),
            source: "official Cloudflare docs".to_owned(),
        },
        KnowledgeReferenceV1 {
            title: "R2 pricing".to_owned(),
            url: "https://developers.cloudflare.com/r2/pricing/".to_owned(),
            source: "official Cloudflare docs".to_owned(),
        },
    ];
    capability.entitlement.available = Some(true);
    capability.entitlement.plans = BTreeMap::from([("r2_active_subscription".to_owned(), true)]);
    capability.entitlement.source =
        Some("https://developers.cloudflare.com/r2/api/tokens/".to_owned());
    capability.entitlement.blocker = None;
    capability.entitlement.requires_live_resolution = false;
    capability.verification.required = false;
    "sink_write_and_source_response_status".clone_into(&mut capability.verification.strategy);
    capability.rollback.supported = false;
    capability.rollback.strategy = None;
    capability.rollback.warning = Some(
        "the temporary credential expires automatically at its hash-bound TTL and cannot be revoked individually; revoking the parent API token invalidates every derived credential and requires a separate destructive plan"
            .to_owned(),
    );
}

fn finalize_r2_temporary_credentials_contract(
    document: &Value,
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    let verify_supported = capabilities
        .get(USER_TOKEN_VERIFY_CAPABILITY_ID)
        .is_some_and(|capability| {
            capability.id == USER_TOKEN_VERIFY_CAPABILITY_ID
                && capability.title == "Verify Token"
                && capability.method == "GET"
                && capability.path == USER_TOKEN_VERIFY_PATH
                && capability.product == "User API Tokens"
                && capability.account_scope == "user"
                && capability.selectors.is_empty()
                && capability.permissions.is_empty()
                && capability.request_schema.is_none()
                && capability
                    .response_contract
                    .as_ref()
                    .is_some_and(|response| {
                        response.success_statuses == ["200"]
                            && response.success_media_types == ["application/json"]
                            && response.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
                    })
        })
        && document
            .pointer("/paths/~1user~1tokens~1verify/get")
            .is_some_and(|operation| {
                success_response_declares_result_fields(document, operation, &["id", "status"])
                    && success_response_declares_result_string_field(document, operation, "id")
                    && success_response_declares_result_string_field(document, operation, "status")
            });
    let response_supported = document
        .pointer("/paths/~1accounts~1{account_id}~1r2~1temp-access-credentials/post")
        .is_some_and(|operation| {
            ["accessKeyId", "secretAccessKey", "sessionToken"]
                .iter()
                .all(|field| {
                    success_response_declares_result_string_field(document, operation, field)
                })
                && ["secretAccessKey", "sessionToken"].iter().all(|field| {
                    success_response_result_field_boolean_annotation(
                        document,
                        operation,
                        field,
                        "x-sensitive",
                    )
                })
        });

    let Some(capability) = capabilities.get_mut(R2_TEMPORARY_CREDENTIALS_CAPABILITY_ID) else {
        return;
    };
    let request_supported = capability.permissions
        == R2_TEMPORARY_CREDENTIAL_PERMISSIONS
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
        && capability.request_schema.as_ref()
            == Some(&serde_json::json!({
                "type":"object",
                "required":["bucket","permission","ttlSeconds","parentAccessKeyId"],
                "properties":{
                    "bucket":{"type":"string"},
                    "objects":{"type":"array","items":{"type":"string"}},
                    "parentAccessKeyId":{"type":"string"},
                    "permission":{"type":"string","enum":["admin-read-write","admin-read-only","object-read-write","object-read-only"]},
                    "prefixes":{"type":"array","items":{"type":"string"}},
                    "ttlSeconds":{"type":"number","maximum":604_800}
                },
                "x-cfctl-body-required":true
            }));
    if !request_supported || !verify_supported || !response_supported {
        capability.adapter_status = AdapterStatus::Blocked;
        capability.blocked_reason = Some(
            "R2 temporary-credential request, one-time response, or active parent-token verification contract drifted"
                .to_owned(),
        );
        return;
    }
    if let Some(parent) = capability
        .request_schema
        .as_mut()
        .and_then(|schema| schema.pointer_mut("/properties/parentAccessKeyId"))
        .and_then(Value::as_object_mut)
    {
        parent.insert(
            "x-cfctl-derived-from-active-profile".to_owned(),
            Value::Bool(true),
        );
    }
    refresh_dynamic_mutation_contract(capability);
}

/// Recognizes the two zone cache-purge write operations. The finalizer, not the
/// classifier, resolves the honest entitlement split, so the guard is narrow: a
/// base purge id issued as a POST. The derived `-tagged` variants never reach
/// this guard because they are inserted after classification.
fn zone_cache_purge_operation_supported(capability: &CapabilityV1) -> bool {
    ZONE_CACHE_PURGE_BASE_IDS.contains(&capability.id.as_str()) && capability.method == "POST"
}

/// Email Routing create/update mutations whose only blocking gaps are
/// risk/effect/cost. Their verification (created-resource / same-path update)
/// and rollback are already bound by the generic post-normalization
/// classifiers; this only supplies the missing risk/effect/cost so the contract
/// completes. Table is (id, method, product, permission) and the guard matches a
/// capability against its row exactly — fail-closed on any drift. The PATCH
/// `update-destination-address` op is deliberately excluded: its only writable
/// field (`status`) is absent from the readback result, so it cannot be
/// readback-verified and stays blocked.
const EMAIL_ROUTING_MUTATION_CONTRACTS: &[(&str, &str, &str, &str)] = &[
    (
        "email-routing-destination-addresses-create-a-destination-address",
        "POST",
        "Email Routing destination addresses",
        "Email Routing Addresses Write",
    ),
    (
        "email-routing-routing-rules-create-routing-rule",
        "POST",
        "Email Routing routing rules",
        "Email Routing Rules Write",
    ),
    (
        "email-routing-routing-rules-update-routing-rule",
        "PUT",
        "Email Routing routing rules",
        "Email Routing Rules Write",
    ),
    (
        "email-routing-routing-rules-update-catch-all-rule",
        "PUT",
        "Email Routing routing rules",
        "Email Routing Rules Write",
    ),
];

fn email_routing_mutation_supported(capability: &CapabilityV1) -> bool {
    EMAIL_ROUTING_MUTATION_CONTRACTS
        .iter()
        .any(|(id, method, product, permission)| {
            capability.id == *id
                && capability.method == *method
                && capability.product == *product
                && capability.permissions == [*permission]
                && capability
                    .response_contract
                    .as_ref()
                    .is_some_and(|contract| {
                        contract.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
                    })
        })
}

fn classify_email_routing_mutation(capability: &mut CapabilityV1) {
    capability.risk = RiskClass::ScopedWrite;
    capability.effect = EffectClass::ReversibleWrite;
    capability.cost = cfctl_core::CostV1::default();
    capability.cost.known = true;
    capability.cost.incremental = false;
    capability.cost.maximum = Some(0.0);
    capability.cost.billing_model = BillingModelV1::None;
    capability.cost.exposure = CostExposureV1::None;
    capability.cost.basis = Some(
        "creating or updating an Email Routing destination address or routing rule has no direct per-operation charge; Email Routing is a free zone feature"
            .to_owned(),
    );
    capability.cost.references = vec![KnowledgeReferenceV1 {
        title: "Email Routing".to_owned(),
        url: "https://developers.cloudflare.com/email-routing/".to_owned(),
        source: "official Cloudflare docs".to_owned(),
    }];
    capability.entitlement.available = Some(true);
    // Returning true from classify_operation_specific_contract short-circuits
    // the sentinel that classify() would otherwise set at its tail; restore it
    // so the generic post-normalization classifiers bind the real created-
    // resource / same-path-update verifier and rollback contract.
    capability.verification.required = true;
    "post_change_read_or_operation_specific_verifier"
        .clone_into(&mut capability.verification.strategy);
}

/// The Email Routing enable/disable toggles, paired with the intended
/// `enabled` state each one reports. Only the two crisply-verifiable toggles
/// are listed: `unlock`, `enable-dns`, and `disable-dns` return the settings
/// object rather than the sub-resource they mutate, so they lack a crisp
/// operation-specific verifier and stay honestly blocked.
const EMAIL_ROUTING_SETTINGS_TOGGLES: &[(&str, bool)] = &[
    ("email-routing-settings-enable-email-routing", true),
    ("email-routing-settings-disable-email-routing", false),
];

fn email_routing_settings_toggle_supported(capability: &CapabilityV1) -> bool {
    EMAIL_ROUTING_SETTINGS_TOGGLES
        .iter()
        .any(|(id, _)| capability.id == *id)
        && capability.method == "POST"
        && capability.product == "Email Routing settings"
        && capability.permissions == ["Zone Settings Write"]
        && capability
            .response_contract
            .as_ref()
            .is_some_and(|contract| {
                contract.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
            })
}

/// Closes the Email Routing enable/disable toggles. Unlike the create/update
/// mutations, these action endpoints have no same-path readback of a resource,
/// so the generic classifiers cannot bind a verifier — this classifier sets the
/// operation-specific `enabled`-state verifier directly (the cache-purge model)
/// so it survives the generic post-normalization pass, which only rebinds
/// capabilities still carrying the sentinel strategy. The generic "disable"
/// keyword heuristic would mark disable Destructive; that is legitimately
/// superseded here — the toggle is a scoped, reversible setting change.
fn classify_email_routing_settings_toggle(capability: &mut CapabilityV1) {
    let enabling = capability.id == "email-routing-settings-enable-email-routing";
    capability.risk = RiskClass::ScopedWrite;
    capability.effect = EffectClass::ReversibleWrite;
    capability.cost = cfctl_core::CostV1::default();
    capability.cost.known = true;
    capability.cost.incremental = false;
    capability.cost.maximum = Some(0.0);
    capability.cost.billing_model = BillingModelV1::None;
    capability.cost.exposure = CostExposureV1::None;
    capability.cost.basis = Some(
        "enabling or disabling Email Routing toggles a free zone setting and carries no direct per-operation charge"
            .to_owned(),
    );
    capability.cost.references = vec![KnowledgeReferenceV1 {
        title: "Email Routing".to_owned(),
        url: "https://developers.cloudflare.com/email-routing/".to_owned(),
        source: "official Cloudflare docs".to_owned(),
    }];
    capability.entitlement.available = Some(true);
    // The toggle is logically reversible by its inverse, but cfctl has no
    // registered auto-compensation for it, so rollback stays unsupported with an
    // explanatory warning (the cache-purge model). Disabling additionally drops
    // in-flight mail, which re-enabling cannot recover — stated plainly.
    capability.rollback.supported = false;
    capability.rollback.strategy = None;
    capability.rollback.warning = Some(if enabling {
        "reversible by disabling Email Routing (POST /zones/{zone_id}/email/routing/disable); cfctl does not auto-compensate, so reversal is a separate governed operation"
            .to_owned()
    } else {
        "reversible by re-enabling Email Routing (POST /zones/{zone_id}/email/routing/enable); cfctl does not auto-compensate. While routing is disabled, inbound messages are not routed and are not retroactively delivered after re-enabling"
            .to_owned()
    });
    capability.verification.required = true;
    "email_routing_settings_response_reports_enabled_state"
        .clone_into(&mut capability.verification.strategy);
}

/// Classifies the base cache-purge capability. Verification is left at the
/// generic placeholder here; `finalize_zone_cache_purge_contracts` upgrades it
/// to the operation-specific verifier only after validating the request and
/// response contracts against the official document.
fn classify_zone_cache_purge(capability: &mut CapabilityV1) {
    capability.risk = RiskClass::Destructive;
    capability.effect = EffectClass::Destructive;
    capability.cost = cfctl_core::CostV1::default();
    capability.cost.known = true;
    capability.cost.incremental = false;
    capability.cost.maximum = Some(0.0);
    capability.cost.billing_model = BillingModelV1::UsageBased;
    capability.cost.exposure = CostExposureV1::DownstreamUsage;
    capability.cost.basis = Some(
        "purging cache has no direct per-request charge; the origin re-fetch it forces is billed only as ordinary downstream usage. Cache-tag, host, and prefix purge is Enterprise-only and is modeled as the separate `-tagged` capability."
            .to_owned(),
    );
    capability.cost.references = vec![
        KnowledgeReferenceV1 {
            title: "Purge cache".to_owned(),
            url: CACHE_PURGE_DOCS_URL.to_owned(),
            source: "official Cloudflare docs".to_owned(),
        },
        KnowledgeReferenceV1 {
            title: "Purge cache by cache-tags".to_owned(),
            url: CACHE_PURGE_BY_TAGS_DOCS_URL.to_owned(),
            source: "official Cloudflare docs".to_owned(),
        },
    ];
    capability.entitlement.available = Some(true);
    capability.entitlement.plans = zone_cache_purge_all_plans();
    capability.entitlement.blocker = None;
    capability.entitlement.source = Some(CACHE_PURGE_DOCS_URL.to_owned());
    capability.entitlement.requires_live_resolution = false;
    capability.verification.required = true;
    "post_change_read_or_operation_specific_verifier"
        .clone_into(&mut capability.verification.strategy);
    capability.rollback.supported = false;
    capability.rollback.strategy = None;
    capability.rollback.warning = Some(
        "a cache purge is irreversible — content is re-fetched from origin on next request; no snapshot restores prior cache state"
            .to_owned(),
    );
}

fn zone_cache_purge_all_plans() -> BTreeMap<String, bool> {
    ["free", "pro", "business", "enterprise"]
        .into_iter()
        .map(|plan| (plan.to_owned(), true))
        .collect()
}

fn zone_cache_purge_enterprise_only_plans() -> BTreeMap<String, bool> {
    ["free", "pro", "business", "enterprise"]
        .into_iter()
        .map(|plan| (plan.to_owned(), plan == "enterprise"))
        .collect()
}

/// A request-body variant is Enterprise-scoped when it declares any of the
/// cache-tag, host, or prefix purge selectors; every other declared variant
/// (`purge_everything` and both `files` shapes) is available on all plans.
fn cache_purge_variant_is_enterprise(variant: &Value) -> bool {
    variant
        .get("properties")
        .and_then(Value::as_object)
        .is_some_and(|properties| {
            ["tags", "hosts", "prefixes"]
                .iter()
                .any(|key| properties.contains_key(*key))
        })
}

/// Confirms the official request body is the full six-variant `anyOf` the split
/// depends on: three Enterprise selectors (tags, hosts, prefixes) and three
/// all-plan selectors (`purge_everything` and both `files` shapes).
fn cache_purge_request_schema_declares_all_variants(schema: &Value) -> bool {
    let Some(variants) = schema.get("anyOf").and_then(Value::as_array) else {
        return false;
    };
    let declared_keys: BTreeSet<&str> = variants
        .iter()
        .filter_map(|variant| variant.get("properties").and_then(Value::as_object))
        .flat_map(serde_json::Map::keys)
        .map(String::as_str)
        .collect();
    let enterprise_variants = variants
        .iter()
        .filter(|variant| cache_purge_variant_is_enterprise(variant))
        .count();
    schema.get("x-cfctl-body-required").and_then(Value::as_bool) == Some(true)
        && variants.len() == 6
        && enterprise_variants == 3
        && variants.len() - enterprise_variants == 3
        && ["tags", "hosts", "prefixes", "purge_everything", "files"]
            .iter()
            .all(|key| declared_keys.contains(key))
}

/// Filters the request `anyOf` in place to only the requested entitlement tier,
/// preserving the surrounding schema wrapper (including `x-cfctl-body-required`).
fn narrow_cache_purge_request_schema(schema: &mut Value, keep_enterprise: bool) {
    if let Some(variants) = schema.get_mut("anyOf").and_then(Value::as_array_mut) {
        variants.retain(|variant| cache_purge_variant_is_enterprise(variant) == keep_enterprise);
    }
}

const fn zone_cache_purge_operation_pointer(base_id: &str) -> Option<&'static str> {
    match base_id.as_bytes() {
        b"zone-purge" => Some("/paths/~1zones~1{zone_id}~1purge_cache/post"),
        b"zone-environment-purge" => {
            Some("/paths/~1zones~1{zone_id}~1environments~1{environment_id}~1purge_cache/post")
        }
        _ => None,
    }
}

/// Finalizes both zone cache-purge capabilities: it validates each base against
/// the official document, narrows the base to the all-plan body variants, and
/// derives the Enterprise-only `-tagged` capability from the pre-narrow base so
/// that a plan-gated agent cannot even plan a tag, host, or prefix purge through
/// the base id. Validation is fail-closed: on drift the base stays blocked and
/// no `-tagged` capability is inserted.
fn finalize_zone_cache_purge_contracts(
    document: &Value,
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    for base_id in ZONE_CACHE_PURGE_BASE_IDS {
        finalize_zone_cache_purge_contract(document, capabilities, base_id);
    }
}

fn finalize_zone_cache_purge_contract(
    document: &Value,
    capabilities: &mut BTreeMap<String, CapabilityV1>,
    base_id: &str,
) {
    let Some(capability) = capabilities.get(base_id) else {
        return;
    };
    if !zone_cache_purge_operation_supported(capability) {
        return;
    }
    let permission_supported = capability.permissions == [ZONE_CACHE_PURGE_PERMISSION];
    let request_supported = capability
        .request_schema
        .as_ref()
        .is_some_and(cache_purge_request_schema_declares_all_variants);
    let response_supported = zone_cache_purge_operation_pointer(base_id)
        .and_then(|pointer| document.pointer(pointer))
        .is_some_and(|operation| {
            success_response_declares_result_string_field(document, operation, "id")
        });

    let Some(capability) = capabilities.get_mut(base_id) else {
        return;
    };
    if !permission_supported || !request_supported || !response_supported {
        capability.adapter_status = AdapterStatus::Blocked;
        capability.blocked_reason = Some(
            "zone cache-purge Cache Purge permission, six-variant request body, or result.id response contract drifted"
                .to_owned(),
        );
        return;
    }

    // Clone before narrowing so the Enterprise variant inherits the full base
    // contract and only its own request body is restricted.
    let mut derived = capability.clone();

    if let Some(schema) = capability.request_schema.as_mut() {
        narrow_cache_purge_request_schema(schema, false);
    }
    CACHE_PURGE_VERIFICATION_STRATEGY.clone_into(&mut capability.verification.strategy);
    refresh_dynamic_mutation_contract(capability);

    let tagged_id = format!("{base_id}-tagged");
    tagged_id.clone_into(&mut derived.id);
    derived.title = format!(
        "{} (Enterprise cache-tag, host, and prefix purge)",
        derived.title
    );
    derived.description = Some(format!(
        "Enterprise-only cache purge scoped by cache-tag, host, or prefix. Split from `{base_id}`: this capability accepts only the tags, hosts, or prefixes selectors and is gated to the Enterprise plan, so a lower-tier profile cannot plan a tag, host, or prefix purge."
    ));
    derived.cost.basis = Some(
        "purging cache has no direct per-request charge; the origin re-fetch it forces is billed only as ordinary downstream usage. Cache-tag, host, and prefix purge requires an Enterprise plan."
            .to_owned(),
    );
    if let Some(schema) = derived.request_schema.as_mut() {
        narrow_cache_purge_request_schema(schema, true);
    }
    derived.entitlement.available = Some(true);
    derived.entitlement.plans = zone_cache_purge_enterprise_only_plans();
    CACHE_PURGE_VERIFICATION_STRATEGY.clone_into(&mut derived.verification.strategy);
    refresh_dynamic_mutation_contract(&mut derived);
    capabilities.insert(derived.id.clone(), derived);
}

fn success_response_result_field_boolean_annotation(
    document: &Value,
    operation: &Value,
    field: &str,
    annotation: &str,
) -> bool {
    operation
        .get("responses")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter(|(status, _)| status.starts_with('2'))
        .filter_map(|(_, response)| response.pointer("/content/application~1json/schema"))
        .any(|schema| {
            schema_path_boolean_annotation(document, schema, &["result", field], annotation, 0)
        })
}

fn schema_path_boolean_annotation(
    document: &Value,
    schema: &Value,
    path: &[&str],
    annotation: &str,
    depth: usize,
) -> bool {
    if depth > 32 {
        return false;
    }
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        return reference
            .strip_prefix('#')
            .and_then(|pointer| document.pointer(pointer))
            .is_some_and(|resolved| {
                schema_path_boolean_annotation(document, resolved, path, annotation, depth + 1)
            });
    }
    if path.is_empty() {
        return schema.get(annotation).and_then(Value::as_bool) == Some(true);
    }
    if let Some(property) = schema
        .get("properties")
        .and_then(Value::as_object)
        .and_then(|properties| properties.get(path[0]))
        && schema_path_boolean_annotation(document, property, &path[1..], annotation, depth + 1)
    {
        return true;
    }
    ["allOf", "oneOf", "anyOf"].iter().any(|composition| {
        schema
            .get(composition)
            .and_then(Value::as_array)
            .is_some_and(|members| {
                members.iter().any(|member| {
                    schema_path_boolean_annotation(document, member, path, annotation, depth + 1)
                })
            })
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OAuthClientSecretOperationKind {
    Rotate,
    DeleteOld,
}

const OAUTH_CLIENT_COLLECTION_PATH: &str = "/accounts/{account_id}/oauth_clients";
const OAUTH_CLIENT_DETAIL_PATH: &str = "/accounts/{account_id}/oauth_clients/{oauth_client_id}";
const OAUTH_CLIENT_CREATE_CAPABILITY_ID: &str = "oauth-clients-create";
const OAUTH_CLIENT_UPDATE_CAPABILITY_ID: &str = "oauth-clients-update";
const OAUTH_CLIENT_SECRET_PATH: &str =
    "/accounts/{account_id}/oauth_clients/{oauth_client_id}/rotate_secret";
const OAUTH_CLIENT_DETAIL_READ_CAPABILITY_ID: &str = "oauth-clients-get";
const OAUTH_CLIENT_DELETE_CAPABILITY_ID: &str = "oauth-clients-delete";
const OAUTH_CLIENT_LIFECYCLE_PERMISSIONS: [&str; 2] = ["OAuth Client Write", "OAuth Client Read"];
const OAUTH_CLIENT_CONFIGURATION_FIELDS: [&str; 12] = [
    "allowed_cors_origins",
    "client_name",
    "client_uri",
    "grant_types",
    "logo_uri",
    "policy_uri",
    "post_logout_redirect_uris",
    "redirect_uris",
    "response_types",
    "scopes",
    "token_endpoint_auth_method",
    "tos_uri",
];

fn oauth_client_collection_selectors_supported(capability: &CapabilityV1) -> bool {
    capability.selectors.len() == 1
        && capability.selectors.iter().any(|selector| {
            selector.name == "account_id"
                && selector.location == "path"
                && selector.required
                && selector.value_type == "string"
                && selector.contract.as_ref().is_some_and(|contract| {
                    contract.schema
                        == serde_json::json!({
                            "allOf":[{"maxLength":32,"minLength":32,"type":"string"}]
                        })
                        && contract.query.is_none()
                })
        })
}

fn oauth_client_configuration_properties() -> Value {
    serde_json::json!({
        "allowed_cors_origins":{"items":{"type":"string"},"type":"array"},
        "client_name":{"type":"string"},
        "client_uri":{"type":"string"},
        "grant_types":{"items":{"enum":["authorization_code","refresh_token"],"type":"string"},"type":"array"},
        "logo_uri":{"type":"string"},
        "policy_uri":{"type":"string"},
        "post_logout_redirect_uris":{"items":{"type":"string"},"type":"array"},
        "redirect_uris":{"items":{"type":"string"},"type":"array"},
        "response_types":{"items":{"enum":["token","id_token","code"],"type":"string"},"type":"array"},
        "scopes":{"items":{"type":"string"},"type":"array"},
        "token_endpoint_auth_method":{"enum":["none","client_secret_basic","client_secret_post"],"type":"string"},
        "tos_uri":{"type":"string"}
    })
}

fn oauth_client_upstream_create_schema() -> Value {
    serde_json::json!({
        "allOf":[
            {"properties":oauth_client_configuration_properties(),"type":"object"},
            {
                "required":["client_name","grant_types","redirect_uris","response_types","scopes","token_endpoint_auth_method"],
                "type":"object"
            }
        ],
        "x-cfctl-body-required":true
    })
}

fn oauth_client_upstream_update_schema() -> Value {
    serde_json::json!({
        "allOf":[
            {"properties":oauth_client_configuration_properties(),"type":"object"},
            {"properties":{"visibility":{"enum":["public"],"type":"string"}},"type":"object"}
        ],
        "x-cfctl-body-required":true
    })
}

fn oauth_client_closed_create_schema() -> Value {
    serde_json::json!({
        "type":"object",
        "additionalProperties":false,
        "required":["client_name","grant_types","redirect_uris","response_types","scopes","token_endpoint_auth_method"],
        "properties":oauth_client_configuration_properties(),
        "x-cfctl-body-required":true
    })
}

fn oauth_client_closed_update_schema() -> Value {
    let mut properties = oauth_client_configuration_properties();
    properties["visibility"] = serde_json::json!({"enum":["public"],"type":"string"});
    serde_json::json!({
        "type":"object",
        "additionalProperties":false,
        "minProperties":1,
        "properties":properties,
        "x-cfctl-body-required":true
    })
}

fn oauth_client_secret_operation_kind(
    capability: &CapabilityV1,
) -> Option<OAuthClientSecretOperationKind> {
    if capability.product != "OAuth Clients"
        || capability.path != OAUTH_CLIENT_SECRET_PATH
        || capability.permissions != ["OAuth Client Write"]
        || capability.request_schema.is_some()
        || !oauth_client_selectors_supported(capability)
        || !capability
            .response_contract
            .as_ref()
            .is_some_and(oauth_client_json_response_supported)
        || !oauth_client_all_plan_entitlement_supported(capability)
    {
        return None;
    }
    match (capability.id.as_str(), capability.method.as_str()) {
        ("oauth-clients-rotate-secret", "POST")
            if capability
                .description
                .as_deref()
                .is_some_and(|description| {
                    description.contains("Creates a second client secret")
                        && description.contains("has_rotated_secret")
                        && description.contains("set to `true`")
                }) =>
        {
            Some(OAuthClientSecretOperationKind::Rotate)
        }
        ("oauth-clients-delete-rotated-secret", "DELETE")
            if capability
                .description
                .as_deref()
                .is_some_and(|description| {
                    description.contains("Removes the old client secret after a rotation")
                        && description.contains("keeping only the new one")
                        && description.contains("has_rotated_secret")
                }) =>
        {
            Some(OAuthClientSecretOperationKind::DeleteOld)
        }
        _ => None,
    }
}

fn oauth_client_selectors_supported(capability: &CapabilityV1) -> bool {
    let expected = [
        (
            "account_id",
            serde_json::json!({"allOf":[{"maxLength":32,"minLength":32,"type":"string"}]}),
        ),
        ("oauth_client_id", serde_json::json!({"type":"string"})),
    ];
    capability.selectors.len() == expected.len()
        && expected.iter().all(|(name, schema)| {
            capability.selectors.iter().any(|selector| {
                selector.name == *name
                    && selector.location == "path"
                    && selector.required
                    && selector.value_type == "string"
                    && selector.contract.as_ref().is_some_and(|contract| {
                        contract.schema == *schema && contract.query.is_none()
                    })
            })
        })
}

fn oauth_client_json_response_supported(response: &ResponseContractV1) -> bool {
    response.success_statuses == ["200"]
        && response.success_media_types == ["application/json"]
        && response.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
}

fn oauth_client_all_plan_entitlement_supported(capability: &CapabilityV1) -> bool {
    capability.entitlement.plans
        == BTreeMap::from([
            ("business".to_owned(), true),
            ("enterprise".to_owned(), true),
            ("free".to_owned(), true),
            ("pro".to_owned(), true),
        ])
}

fn oauth_client_detail_read_supported(
    document: &Value,
    capabilities: &BTreeMap<String, CapabilityV1>,
) -> bool {
    let fields = OAUTH_CLIENT_CONFIGURATION_FIELDS
        .iter()
        .copied()
        .chain(["client_id", "visibility"])
        .collect::<Vec<_>>();
    capabilities
        .get(OAUTH_CLIENT_DETAIL_READ_CAPABILITY_ID)
        .is_some_and(|capability| {
            capability.id == OAUTH_CLIENT_DETAIL_READ_CAPABILITY_ID
                && capability.method == "GET"
                && capability.path == OAUTH_CLIENT_DETAIL_PATH
                && capability.product == "OAuth Clients"
                && capability.account_scope == "account"
                && capability.permissions == ["OAuth Client Read"]
                && capability.request_schema.is_none()
                && oauth_client_selectors_supported(capability)
                && oauth_client_all_plan_entitlement_supported(capability)
                && capability
                    .response_contract
                    .as_ref()
                    .is_some_and(oauth_client_json_response_supported)
        })
        && document
            .pointer("/paths/~1accounts~1{account_id}~1oauth_clients~1{oauth_client_id}/get")
            .is_some_and(|operation| {
                success_response_declares_result_string_field(document, operation, "client_id")
                    && success_response_declares_result_fields(document, operation, &fields)
            })
}

fn oauth_client_delete_supported(capabilities: &BTreeMap<String, CapabilityV1>) -> bool {
    capabilities
        .get(OAUTH_CLIENT_DELETE_CAPABILITY_ID)
        .is_some_and(|capability| {
            capability.id == OAUTH_CLIENT_DELETE_CAPABILITY_ID
                && capability.method == "DELETE"
                && capability.path == OAUTH_CLIENT_DETAIL_PATH
                && capability.product == "OAuth Clients"
                && capability.account_scope == "account"
                && capability.permissions == ["OAuth Client Write"]
                && capability.request_schema.is_none()
                && oauth_client_selectors_supported(capability)
                && oauth_client_all_plan_entitlement_supported(capability)
                && capability.verification.strategy
                    == "same_resource_returns_not_found_after_delete"
                && capability.same_path_read.as_ref().is_some_and(|read| {
                    read.path == OAUTH_CLIENT_DETAIL_PATH
                        && read.read_capability_id == OAUTH_CLIENT_DETAIL_READ_CAPABILITY_ID
                        && read.verified_response_fields.is_empty()
                })
                && capability.mutation_contract_gaps().is_empty()
        })
}

fn classify_oauth_client_cost_and_entitlement(capability: &mut CapabilityV1) {
    capability.cost = CostV1::default();
    capability.cost.basis = Some(
        "creating or updating one OAuth client does not purchase a plan or add a direct operation charge, so the direct incremental ceiling is zero"
            .to_owned(),
    );
    capability.cost.references = vec![official_reference(
        "Create your OAuth client",
        "https://developers.cloudflare.com/fundamentals/oauth/create-an-oauth-client/",
    )];
    capability.entitlement.available = Some(true);
    capability.entitlement.source = Some("official OpenAPI x-cfPlanAvailability".to_owned());
    capability.entitlement.blocker = None;
    capability.entitlement.requires_live_resolution = false;
}

fn finalize_oauth_client_create_update_contracts(
    document: &Value,
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    let companions_supported = oauth_client_detail_read_supported(document, capabilities)
        && oauth_client_delete_supported(capabilities);
    let create_response_supported = document
        .pointer("/paths/~1accounts~1{account_id}~1oauth_clients/post")
        .is_some_and(|operation| {
            success_response_declares_result_string_field(document, operation, "client_id")
                && success_response_declares_result_string_field(
                    document,
                    operation,
                    "client_secret",
                )
        });

    finalize_oauth_client_create_contract(
        capabilities,
        companions_supported && create_response_supported,
    );
    finalize_oauth_client_update_contract(capabilities, companions_supported);
}

fn finalize_oauth_client_create_contract(
    capabilities: &mut BTreeMap<String, CapabilityV1>,
    companions_supported: bool,
) {
    if let Some(capability) = capabilities.get_mut(OAUTH_CLIENT_CREATE_CAPABILITY_ID) {
        let create_supported = capability.id == OAUTH_CLIENT_CREATE_CAPABILITY_ID
            && capability.method == "POST"
            && capability.path == OAUTH_CLIENT_COLLECTION_PATH
            && capability.product == "OAuth Clients"
            && capability.account_scope == "account"
            && capability.permissions == ["OAuth Client Write"]
            && oauth_client_collection_selectors_supported(capability)
            && oauth_client_all_plan_entitlement_supported(capability)
            && capability.request_schema.as_ref() == Some(&oauth_client_upstream_create_schema())
            && capability
                .response_contract
                .as_ref()
                .is_some_and(oauth_client_json_response_supported);
        if create_supported && companions_supported {
            capability.permissions = OAUTH_CLIENT_LIFECYCLE_PERMISSIONS
                .into_iter()
                .map(str::to_owned)
                .collect();
            capability.request_schema = Some(oauth_client_closed_create_schema());
            capability.risk = RiskClass::IdentityOrOwnership;
            capability.effect = EffectClass::IdentityOrOwnership;
            classify_oauth_client_cost_and_entitlement(capability);
            capability.created_resource = Some(CreatedResourceContractV1 {
                detail_path: OAUTH_CLIENT_DETAIL_PATH.to_owned(),
                identity_selector: "oauth_client_id".to_owned(),
                response_result_identity_pointer: "/client_id".to_owned(),
                read_capability_id: OAUTH_CLIENT_DETAIL_READ_CAPABILITY_ID.to_owned(),
                delete_capability_id: OAUTH_CLIENT_DELETE_CAPABILITY_ID.to_owned(),
                verified_response_fields: OAUTH_CLIENT_CONFIGURATION_FIELDS
                    .iter()
                    .map(|field| (*field).to_owned())
                    .collect(),
            });
            capability.verification.required = true;
            "created_resource_contains_planned_fields_by_returned_id"
                .clone_into(&mut capability.verification.strategy);
            capability.rollback.supported = false;
            capability.rollback.strategy = None;
            capability.rollback.warning = Some(
                "OAuth client creation is not automatically rolled back; removing a failed private client requires a separately reviewed and explicitly approved destructive delete plan bound to the returned client_id"
                    .to_owned(),
            );
            refresh_dynamic_mutation_contract(capability);
        } else {
            capability.created_resource = None;
            capability.adapter_status = AdapterStatus::Blocked;
            capability.blocked_reason = Some(
                "OAuth client create, secret response, detail read, delete, request, permission, entitlement, or response contract drifted"
                    .to_owned(),
            );
        }
    }
}

fn finalize_oauth_client_update_contract(
    capabilities: &mut BTreeMap<String, CapabilityV1>,
    companions_supported: bool,
) {
    if let Some(capability) = capabilities.get_mut(OAUTH_CLIENT_UPDATE_CAPABILITY_ID) {
        let update_fields = OAUTH_CLIENT_CONFIGURATION_FIELDS
            .iter()
            .copied()
            .chain(["visibility"])
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let update_supported = capability.id == OAUTH_CLIENT_UPDATE_CAPABILITY_ID
            && capability.method == "PATCH"
            && capability.path == OAUTH_CLIENT_DETAIL_PATH
            && capability.product == "OAuth Clients"
            && capability.account_scope == "account"
            && capability.permissions == ["OAuth Client Write"]
            && oauth_client_selectors_supported(capability)
            && oauth_client_all_plan_entitlement_supported(capability)
            && capability.request_schema.as_ref() == Some(&oauth_client_upstream_update_schema())
            && capability
                .response_contract
                .as_ref()
                .is_some_and(oauth_client_json_response_supported);
        if update_supported && companions_supported {
            capability.permissions = OAUTH_CLIENT_LIFECYCLE_PERMISSIONS
                .into_iter()
                .map(str::to_owned)
                .collect();
            capability.request_schema = Some(oauth_client_closed_update_schema());
            capability.risk = RiskClass::IdentityOrOwnership;
            capability.effect = EffectClass::IdentityOrOwnership;
            classify_oauth_client_cost_and_entitlement(capability);
            capability.verification.required = true;
            "same_resource_contains_planned_fields_after_update"
                .clone_into(&mut capability.verification.strategy);
            capability.same_path_read = Some(SamePathReadContractV1 {
                path: OAUTH_CLIENT_DETAIL_PATH.to_owned(),
                read_capability_id: OAUTH_CLIENT_DETAIL_READ_CAPABILITY_ID.to_owned(),
                verified_response_fields: update_fields,
            });
            capability.rollback.supported = false;
            capability.rollback.strategy = None;
            capability.rollback.warning = Some(
                "cfctl hash-binds and rechecks the exact existing client before update; metadata restoration requires a separate snapshot-bound update, while promotion to public is permanent because Cloudflare does not permit demotion"
                    .to_owned(),
            );
            refresh_dynamic_mutation_contract(capability);
        } else {
            capability.adapter_status = AdapterStatus::Blocked;
            capability.blocked_reason = Some(
                "OAuth client update, detail read, delete, request, permission, entitlement, or response contract drifted"
                    .to_owned(),
            );
        }
    }
}

fn classify_oauth_client_secret_operation(
    capability: &mut CapabilityV1,
    kind: OAuthClientSecretOperationKind,
) {
    capability.cost = cfctl_core::CostV1::default();
    capability.cost.basis = Some(
        "rotating or deleting one OAuth client secret does not purchase a plan or add usage charges, so the direct incremental ceiling is zero"
            .to_owned(),
    );
    capability.cost.references = vec![KnowledgeReferenceV1 {
        title: "Create your OAuth client".to_owned(),
        url: "https://developers.cloudflare.com/fundamentals/oauth/create-an-oauth-client/"
            .to_owned(),
        source: "official Cloudflare docs".to_owned(),
    }];
    capability.entitlement.available = Some(true);
    capability.entitlement.source = Some("official OpenAPI x-cfPlanAvailability".to_owned());
    capability.verification.required = true;
    capability.rollback.supported = false;
    capability.rollback.strategy = None;
    match kind {
        OAuthClientSecretOperationKind::Rotate => {
            capability.risk = RiskClass::SecretSensitive;
            capability.effect = EffectClass::IdentityOrOwnership;
            "oauth_client_reports_rotated_secret_after_value_roll"
                .clone_into(&mut capability.verification.strategy);
            capability.rollback.warning = Some(
                "rotation creates a second secret but cannot restore a one-secret state that keeps only the old value; keep the old secret active, install and verify the new sink, and do not delete the old secret until every dependent has cut over"
                    .to_owned(),
            );
        }
        OAuthClientSecretOperationKind::DeleteOld => {
            capability.risk = RiskClass::Destructive;
            capability.effect = EffectClass::Irreversible;
            "oauth_client_reports_no_rotated_secret_after_old_secret_delete"
                .clone_into(&mut capability.verification.strategy);
            capability.rollback.warning = Some(
                "deleting the old OAuth client secret is irreversible and the value cannot be restored; run it only after every dependent has been verified against the new secret"
                    .to_owned(),
            );
        }
    }
}

fn finalize_oauth_client_secret_rotation_contract(
    document: &Value,
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    let read_supported = capabilities
        .get(OAUTH_CLIENT_DETAIL_READ_CAPABILITY_ID)
        .is_some_and(|capability| {
            capability.id == OAUTH_CLIENT_DETAIL_READ_CAPABILITY_ID
                && capability.method == "GET"
                && capability.path == OAUTH_CLIENT_DETAIL_PATH
                && capability.product == "OAuth Clients"
                && capability.permissions == ["OAuth Client Read"]
                && capability.request_schema.is_none()
                && oauth_client_selectors_supported(capability)
                && capability
                    .response_contract
                    .as_ref()
                    .is_some_and(oauth_client_json_response_supported)
        })
        && document
            .pointer("/paths/~1accounts~1{account_id}~1oauth_clients~1{oauth_client_id}/get")
            .is_some_and(|operation| {
                success_response_declares_result_fields(
                    document,
                    operation,
                    &["client_id", "has_rotated_secret"],
                )
            });
    if !read_supported {
        return;
    }
    for (capability_id, method, response_fields) in [
        (
            "oauth-clients-rotate-secret",
            "post",
            ["client_secret"].as_slice(),
        ),
        (
            "oauth-clients-delete-rotated-secret",
            "delete",
            ["id"].as_slice(),
        ),
    ] {
        let response_supported = document
            .pointer(&format!(
                "/paths/~1accounts~1{{account_id}}~1oauth_clients~1{{oauth_client_id}}~1rotate_secret/{method}"
            ))
            .is_some_and(|operation| {
                success_response_declares_result_field_union(document, operation, response_fields)
            });
        if !response_supported {
            continue;
        }
        let Some(capability) = capabilities.get_mut(capability_id) else {
            continue;
        };
        capability.permissions = OAUTH_CLIENT_LIFECYCLE_PERMISSIONS
            .into_iter()
            .map(str::to_owned)
            .collect();
        capability.same_path_read = Some(SamePathReadContractV1 {
            path: OAUTH_CLIENT_DETAIL_PATH.to_owned(),
            read_capability_id: OAUTH_CLIENT_DETAIL_READ_CAPABILITY_ID.to_owned(),
            verified_response_fields: vec!["client_id".to_owned(), "has_rotated_secret".to_owned()],
        });
        refresh_dynamic_mutation_contract(capability);
    }
}

fn turnstile_widget_rotation_contract_supported(capability: &CapabilityV1) -> bool {
    capability.id == "accounts-turnstile-widget-rotate-secret"
        && capability.method == "POST"
        && capability.path == "/accounts/{account_id}/challenges/widgets/{sitekey}/rotate_secret"
        && capability.product == "Turnstile"
        && capability
            .description
            .as_deref()
            .is_some_and(|description| {
                let description = description.to_ascii_lowercase();
                description.contains("previous secret remains valid for 2 hours")
                    && description
                        .contains("secrets cannot be rotated again during the grace period")
            })
        && turnstile_widget_write_permissions_supported(capability)
        && turnstile_widget_detail_selectors_supported(capability)
        && capability
            .response_contract
            .as_ref()
            .is_some_and(turnstile_widget_response_contract_supported)
        && turnstile_widget_rotation_request_contract_supported(capability)
}

fn turnstile_widget_create_contract_supported(capability: &CapabilityV1) -> bool {
    capability.id == "accounts-turnstile-widget-create"
        && capability.method == "POST"
        && capability.path == "/accounts/{account_id}/challenges/widgets"
        && capability.product == "Turnstile"
        && turnstile_widget_write_permissions_supported(capability)
        && turnstile_widget_collection_selectors_supported(capability)
        && capability
            .response_contract
            .as_ref()
            .is_some_and(turnstile_widget_response_contract_supported)
        && turnstile_widget_configuration_request_contract_supported(capability)
}

fn turnstile_widget_update_contract_supported(capability: &CapabilityV1) -> bool {
    capability.id == "accounts-turnstile-widget-update"
        && capability.method == "PUT"
        && capability.path == "/accounts/{account_id}/challenges/widgets/{sitekey}"
        && capability.product == "Turnstile"
        && turnstile_widget_write_permissions_supported(capability)
        && capability
            .response_contract
            .as_ref()
            .is_some_and(turnstile_widget_response_contract_supported)
        && turnstile_widget_configuration_request_contract_supported(capability)
}

fn turnstile_widget_write_permissions_supported(capability: &CapabilityV1) -> bool {
    capability.permissions.len() == 2
        && capability
            .permissions
            .iter()
            .any(|permission| permission == "Turnstile Sites Write")
        && capability
            .permissions
            .iter()
            .any(|permission| permission == "Account Settings Write")
}

fn turnstile_widget_response_contract_supported(response: &ResponseContractV1) -> bool {
    response.success_statuses == ["200"]
        && response.success_media_types == ["application/json"]
        && response.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
}

fn turnstile_widget_collection_selectors_supported(capability: &CapabilityV1) -> bool {
    let expected = [
        (
            "account_id",
            "path",
            true,
            serde_json::json!({"maxLength":32,"type":"string"}),
        ),
        (
            "page",
            "query",
            false,
            serde_json::json!({"minimum":1,"type":"number"}),
        ),
        (
            "per_page",
            "query",
            false,
            serde_json::json!({"maximum":1000,"minimum":5,"type":"number"}),
        ),
        (
            "order",
            "query",
            false,
            serde_json::json!({"enum":["id","sitekey","name","created_on","modified_on"],"type":"string"}),
        ),
        (
            "direction",
            "query",
            false,
            serde_json::json!({"enum":["asc","desc"],"type":"string"}),
        ),
        (
            "filter",
            "query",
            false,
            serde_json::json!({"type":"string"}),
        ),
    ];
    capability.selectors.len() == expected.len()
        && expected.iter().all(|(name, location, required, schema)| {
            capability
                .selectors
                .iter()
                .find(|selector| selector.name == *name && selector.location == *location)
                .is_some_and(|selector| {
                    selector.required == *required
                        && selector.contract.as_ref().is_some_and(|contract| {
                            contract.schema == *schema
                                && if *location == "query" {
                                    contract.query.as_ref().is_some_and(|query| {
                                        query.style == "form"
                                            && query.explode
                                            && !query.allow_reserved
                                            && !query.allow_empty_value
                                    })
                                } else {
                                    contract.query.is_none()
                                }
                        })
                })
        })
}

fn turnstile_widget_detail_selectors_supported(capability: &CapabilityV1) -> bool {
    let expected = [
        (
            "account_id",
            serde_json::json!({"maxLength":32,"type":"string"}),
        ),
        (
            "sitekey",
            serde_json::json!({"maxLength":32,"type":"string"}),
        ),
    ];
    capability.selectors.len() == expected.len()
        && expected.iter().all(|(name, schema)| {
            capability.selectors.iter().any(|selector| {
                selector.name == *name
                    && selector.location == "path"
                    && selector.required
                    && selector.value_type == "string"
                    && selector.contract.as_ref().is_some_and(|contract| {
                        contract.schema == *schema && contract.query.is_none()
                    })
            })
        })
}

fn turnstile_widget_rotation_request_contract_supported(capability: &CapabilityV1) -> bool {
    capability.request_schema.as_ref().is_some_and(|schema| {
        schema.get("type").and_then(Value::as_str) == Some("object")
            && schema.get("x-cfctl-body-required").and_then(Value::as_bool) == Some(true)
            && schema.get("required").is_none()
            && canonical_request_object_fields(capability)
                == Some(vec!["invalidate_immediately".to_owned()])
            && schema
                .pointer("/properties/invalidate_immediately/type")
                .and_then(Value::as_str)
                == Some("boolean")
    })
}

fn turnstile_widget_configuration_request_contract_supported(capability: &CapabilityV1) -> bool {
    let Some(schema) = capability.request_schema.as_ref() else {
        return false;
    };
    let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
        return false;
    };
    let boolean_field = |name: &str| {
        properties
            .get(name)
            .and_then(|property| property.get("type"))
            .and_then(Value::as_str)
            == Some("boolean")
    };
    let enum_field = |name: &str, values: Value| {
        properties.get(name).is_some_and(|property| {
            property.get("type").and_then(Value::as_str) == Some("string")
                && property.get("enum") == Some(&values)
        })
    };

    schema.get("type").and_then(Value::as_str) == Some("object")
        && schema.get("x-cfctl-body-required").and_then(Value::as_bool) == Some(true)
        && schema.get("required") == Some(&serde_json::json!(["name", "mode", "domains"]))
        && canonical_request_object_fields(capability)
            == Some(vec![
                "bot_fight_mode".to_owned(),
                "clearance_level".to_owned(),
                "domains".to_owned(),
                "ephemeral_id".to_owned(),
                "mode".to_owned(),
                "name".to_owned(),
                "offlabel".to_owned(),
                "region".to_owned(),
            ])
        && boolean_field("bot_fight_mode")
        && boolean_field("ephemeral_id")
        && boolean_field("offlabel")
        && enum_field(
            "clearance_level",
            serde_json::json!(["no_clearance", "jschallenge", "managed", "interactive"]),
        )
        && enum_field(
            "mode",
            serde_json::json!(["non-interactive", "invisible", "managed"]),
        )
        && enum_field("region", serde_json::json!(["world", "china"]))
        && properties.get("domains").is_some_and(|domains| {
            domains.get("type").and_then(Value::as_str) == Some("array")
                && domains.get("maxLength").and_then(Value::as_u64) == Some(10)
                && domains
                    .get("items")
                    .and_then(|items| items.get("type"))
                    .and_then(Value::as_str)
                    == Some("string")
        })
        && properties.get("name").is_some_and(|name| {
            name.get("type").and_then(Value::as_str) == Some("string")
                && name.get("minLength").and_then(Value::as_u64) == Some(1)
                && name.get("maxLength").and_then(Value::as_u64) == Some(254)
        })
}

fn classify_turnstile_widget_create(capability: &mut CapabilityV1) {
    capability
        .selectors
        .retain(|selector| selector.location == "path");
    capability.risk = RiskClass::SecretSensitive;
    capability.effect = EffectClass::IdentityOrOwnership;
    capability.verification.required = true;
    "post_change_read_or_operation_specific_verifier"
        .clone_into(&mut capability.verification.strategy);
    classify_turnstile_widget_cost_and_entitlement(
        capability,
        "creating a Turnstile widget consumes widget capacity but does not purchase a plan or add a usage charge, so its direct incremental ceiling is zero; Free accounts remain limited to 20 widgets and Enterprise capacity is separately negotiated",
    );
}

fn classify_turnstile_widget_rotation(capability: &mut CapabilityV1) {
    capability.risk = RiskClass::SecretSensitive;
    capability.effect = EffectClass::IdentityOrOwnership;
    if let Some(schema) = capability
        .request_schema
        .as_mut()
        .and_then(Value::as_object_mut)
    {
        schema.insert(
            "required".to_owned(),
            serde_json::json!(["invalidate_immediately"]),
        );
    }
    capability.verification.required = false;
    "sink_write_and_source_response_status".clone_into(&mut capability.verification.strategy);
    capability.rollback.supported = false;
    capability.rollback.strategy = None;
    capability.rollback.warning = Some(
        "secret rotation is irreversible: `invalidate_immediately=true` invalidates the previous secret at once, while `false` preserves it for only 2 hours and blocks another rotation during that grace period; install and verify the new sink before dependent cutover"
            .to_owned(),
    );
    classify_turnstile_widget_cost_and_entitlement(
        capability,
        "rotating an existing Turnstile widget secret does not purchase a plan, add a widget, or add usage charges, so its direct incremental ceiling is zero; widget capacity and Enterprise terms remain part of the account's existing subscription",
    );
}

fn classify_turnstile_widget_update(capability: &mut CapabilityV1) {
    capability.risk = RiskClass::CrossConfig;
    capability.effect = EffectClass::ReversibleWrite;
    classify_turnstile_widget_cost_and_entitlement(
        capability,
        "updating an existing Turnstile widget does not purchase a plan, add a widget, or add usage charges, so its direct incremental ceiling is zero; Enterprise-only fields remain subject to the account's separately negotiated subscription",
    );
    capability.verification.required = true;
    "post_change_read_or_operation_specific_verifier"
        .clone_into(&mut capability.verification.strategy);
}

fn classify_turnstile_widget_cost_and_entitlement(capability: &mut CapabilityV1, basis: &str) {
    capability.cost = cfctl_core::CostV1::default();
    capability.cost.billing_model = BillingModelV1::Subscription;
    capability.cost.exposure = CostExposureV1::AccountQuote;
    capability.cost.basis = Some(basis.to_owned());
    capability.cost.references = vec![
        KnowledgeReferenceV1 {
            title: "Cloudflare Turnstile plans".to_owned(),
            url: "https://developers.cloudflare.com/turnstile/plans/".to_owned(),
            source: "official Cloudflare docs".to_owned(),
        },
        KnowledgeReferenceV1 {
            title: "Create and manage Turnstile widgets using the API".to_owned(),
            url: "https://developers.cloudflare.com/turnstile/get-started/widget-management/api/"
                .to_owned(),
            source: "official Cloudflare docs".to_owned(),
        },
    ];
    capability.entitlement.available = Some(true);
    capability.entitlement.plans =
        BTreeMap::from([("free".to_owned(), true), ("enterprise".to_owned(), true)]);
    capability.entitlement.source =
        Some("https://developers.cloudflare.com/turnstile/plans/".to_owned());
    capability.entitlement.blocker = None;
    capability.entitlement.requires_live_resolution = false;
}

fn is_workers_ai_model_run(capability: &CapabilityV1) -> bool {
    capability.method == "POST"
        && capability.id.starts_with("workers-ai-post-run-")
        && capability.product.starts_with("Workers AI")
        && capability
            .path
            .starts_with("/accounts/{account_id}/ai/run/")
        && capability.permissions.len() == 2
        && capability
            .permissions
            .iter()
            .any(|permission| permission == "Workers AI Write")
        && capability
            .permissions
            .iter()
            .any(|permission| permission == "Workers AI Read")
}

fn block_required_reserved_header_selectors(capability: &mut CapabilityV1) {
    let reserved = capability
        .selectors
        .iter()
        .filter(|selector| {
            selector.location == "header"
                && selector.required
                && request_header_is_reserved(&selector.name)
        })
        .map(|selector| selector.name.clone())
        .collect::<Vec<_>>();
    if reserved.is_empty() {
        return;
    }
    capability.adapter_status = AdapterStatus::Blocked;
    capability.blocked_reason = Some(format!(
        "required credential or transport header selector(s) are reserved for governed runtime handling: {}",
        reserved.join(", ")
    ));
}

fn block_unsupported_response_contract(capability: &mut CapabilityV1) {
    let Some(response) = capability
        .response_contract
        .as_ref()
        .filter(|response| response.body_mode == ResponseBodyModeV1::Unsupported)
    else {
        return;
    };
    if capability.adapter_status == AdapterStatus::Blocked {
        return;
    }
    capability.adapter_status = AdapterStatus::Blocked;
    capability.blocked_reason = Some(if response.success_statuses.is_empty() {
        "response contract unsupported: the official schema declares no 2xx success response"
            .to_owned()
    } else if response.success_media_types == ["application/json"] {
        "response contract unsupported: successful response representations do not prove one Cloudflare JSON envelope or empty-body contract"
            .to_owned()
    } else {
        format!(
            "response contract unsupported: declared successful media types are {}; the executor currently requires exactly application/json",
            response.success_media_types.join(", ")
        )
    });
}

fn classify_workers_ai_model_run(capability: &mut CapabilityV1) {
    capability.risk = RiskClass::Spend;
    capability.effect = EffectClass::Spend;
    capability.cost.incremental = true;
    capability.cost.currency = None;
    capability.cost.maximum = None;
    capability.cost.known = false;
    capability.cost.billing_model = BillingModelV1::UsageBased;
    capability.cost.exposure = CostExposureV1::DownstreamUsage;
    capability.cost.basis = Some(
        "Workers AI inference has input- and output-dependent metered usage; the OpenAPI request schema does not declare enough bounds to derive a hard ceiling"
            .to_owned(),
    );
    capability.verification.required = true;
    "post_change_read_or_operation_specific_verifier"
        .clone_into(&mut capability.verification.strategy);
    capability.rollback.supported = false;
    capability.rollback.strategy = None;
    capability.rollback.warning = Some(
        "completed inference and any resulting billed usage cannot be rolled back; submit a separately reviewed request if another inference is needed"
            .to_owned(),
    );
}

fn is_d1_read_replication_update(capability: &CapabilityV1) -> bool {
    matches!(
        capability.id.as_str(),
        "d1-update-database" | "d1-update-partial-database"
    ) && matches!(capability.method.as_str(), "PUT" | "PATCH")
        && capability.product == "D1"
        && capability.path == "/accounts/{account_id}/d1/database/{database_id}"
        && capability.permissions.len() == 1
        && capability.permissions[0] == "D1 Write"
        && canonical_request_object_fields(capability)
            .is_some_and(|fields| fields.len() == 1 && fields[0] == "read_replication")
        && d1_read_replication_request_contract_supported(capability)
}

fn d1_read_replication_request_contract_supported(capability: &CapabilityV1) -> bool {
    let Some(replication) = capability
        .request_schema
        .as_ref()
        .and_then(|schema| schema.get("properties"))
        .and_then(Value::as_object)
        .and_then(|properties| properties.get("read_replication"))
    else {
        return false;
    };
    let properties = replication.get("properties").and_then(Value::as_object);
    replication.get("type").and_then(Value::as_str) == Some("object")
        && replication.get("required") == Some(&serde_json::json!(["mode"]))
        && properties.is_some_and(|properties| {
            properties.len() == 1
                && properties.get("mode").is_some_and(|mode| {
                    mode.get("type").and_then(Value::as_str) == Some("string")
                        && mode.get("enum") == Some(&serde_json::json!(["auto", "disabled"]))
                })
        })
}

const R2_BUCKET_CREATE_CAPABILITY_ID: &str = "r2-create-bucket";
const R2_BUCKET_READ_CAPABILITY_ID: &str = "r2-get-bucket";
const R2_BUCKET_DELETE_CAPABILITY_ID: &str = "r2-delete-bucket";
const R2_BUCKET_COLLECTION_PATH: &str = "/accounts/{account_id}/r2/buckets";
const R2_BUCKET_DETAIL_PATH: &str = "/accounts/{account_id}/r2/buckets/{bucket_name}";

fn r2_bucket_create_operation_supported(capability: &CapabilityV1) -> bool {
    capability.id == R2_BUCKET_CREATE_CAPABILITY_ID
        && capability.title == "Create Bucket"
        && capability.description.as_deref() == Some("Creates a new R2 bucket.")
        && capability.method == "POST"
        && capability.path == R2_BUCKET_COLLECTION_PATH
        && capability.product == "R2 Bucket"
        && capability.account_scope == "account"
        && capability.permissions == ["Workers R2 Storage Write"]
        && r2_bucket_selectors_supported(capability, false)
        && capability.request_schema.as_ref()
            == Some(&serde_json::json!({
                "properties": {
                    "locationHint": {
                        "enum": ["apac", "eeur", "enam", "weur", "wnam", "oc"],
                        "type": "string"
                    },
                    "name": {"maxLength": 64, "minLength": 3, "type": "string"},
                    "storageClass": {
                        "enum": ["Standard", "InfrequentAccess"],
                        "type": "string"
                    }
                },
                "required": ["name"],
                "type": "object",
                "x-cfctl-body-required": true
            }))
        && r2_bucket_response_contract_supported(capability)
}

fn r2_bucket_selectors_supported(capability: &CapabilityV1, includes_bucket_name: bool) -> bool {
    let expected_len = if includes_bucket_name { 3 } else { 2 };
    capability.selectors.len() == expected_len
        && capability.selectors.iter().any(|selector| {
            selector.name == "account_id"
                && selector.location == "path"
                && selector.required
                && selector.value_type == "string"
                && selector.description.as_deref() == Some("Account ID.")
                && selector.contract.as_ref().is_some_and(|contract| {
                    contract.schema == serde_json::json!({"maxLength":32,"type":"string"})
                        && contract.query.is_none()
                })
        })
        && (!includes_bucket_name
            || capability.selectors.iter().any(|selector| {
                selector.name == "bucket_name"
                    && selector.location == "path"
                    && selector.required
                    && selector.value_type == "string"
                    && selector.description.as_deref() == Some("Name of the bucket.")
                    && selector.contract.as_ref().is_some_and(|contract| {
                        contract.schema
                            == serde_json::json!({"maxLength":64,"minLength":3,"type":"string"})
                            && contract.query.is_none()
                    })
            }))
        && capability.selectors.iter().any(|selector| {
            selector.name == "cf-r2-jurisdiction"
                && selector.location == "header"
                && !selector.required
                && selector.value_type == "string"
                && selector.description.as_deref()
                    == Some(
                        "Jurisdiction where objects in this bucket are guaranteed to be stored.",
                    )
                && selector.contract.as_ref().is_some_and(|contract| {
                    contract.schema
                        == serde_json::json!({"enum":["default","eu","fedramp"],"type":"string"})
                        && contract.query.is_none()
                })
        })
}

fn r2_bucket_response_contract_supported(capability: &CapabilityV1) -> bool {
    capability
        .response_contract
        .as_ref()
        .is_some_and(|response| {
            response.success_statuses == ["200"]
                && response.success_media_types == ["application/json"]
                && response.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
        })
}

fn r2_bucket_references() -> Vec<KnowledgeReferenceV1> {
    vec![
        KnowledgeReferenceV1 {
            title: "R2 Create Bucket API".to_owned(),
            url: "https://developers.cloudflare.com/api/resources/r2/subresources/buckets/methods/create/"
                .to_owned(),
            source: "official Cloudflare API reference".to_owned(),
        },
        KnowledgeReferenceV1 {
            title: "R2 pricing".to_owned(),
            url: "https://developers.cloudflare.com/r2/pricing/".to_owned(),
            source: "official Cloudflare docs".to_owned(),
        },
        KnowledgeReferenceV1 {
            title: "R2 storage classes".to_owned(),
            url: "https://developers.cloudflare.com/r2/buckets/storage-classes/".to_owned(),
            source: "official Cloudflare docs".to_owned(),
        },
        KnowledgeReferenceV1 {
            title: "R2 data location".to_owned(),
            url: "https://developers.cloudflare.com/r2/reference/data-location/".to_owned(),
            source: "official Cloudflare docs".to_owned(),
        },
    ]
}

fn classify_r2_bucket_create(capability: &mut CapabilityV1) {
    capability.risk = RiskClass::ScopedWrite;
    capability.effect = EffectClass::ReversibleWrite;
    capability.cost.incremental = true;
    capability.cost.currency = Some("USD".to_owned());
    capability.cost.maximum = Some(0.000_009);
    capability.cost.known = true;
    capability.cost.billing_model = BillingModelV1::UsageBased;
    capability.cost.exposure = CostExposureV1::DownstreamUsage;
    capability.cost.basis = Some(
        "Cloudflare classifies PutBucket as one Class A operation; the ceiling uses the current higher Infrequent Access rate of USD 9.00 per million requests, while later storage, data retrieval, and Class A/Class B operations remain usage-billed"
            .to_owned(),
    );
    capability.cost.references = r2_bucket_references();
    capability.entitlement.available = Some(true);
    capability.entitlement.plans = BTreeMap::from([("r2_active_subscription".to_owned(), true)]);
    capability.entitlement.blocker = None;
    capability.entitlement.source =
        Some("https://developers.cloudflare.com/r2/api/tokens/".to_owned());
    capability.entitlement.requires_live_resolution = false;
    capability.verification.required = true;
    "post_change_read_or_operation_specific_verifier"
        .clone_into(&mut capability.verification.strategy);
    capability.rollback.supported = false;
    capability.rollback.strategy = None;
    capability.rollback.warning = Some(
        "compensation is possible only through a separately reviewed exact-bucket delete plan while the newly created bucket remains empty"
            .to_owned(),
    );
}

fn r2_bucket_read_contract_supported(
    document: &Value,
    capabilities: &BTreeMap<String, CapabilityV1>,
) -> bool {
    capabilities
        .get(R2_BUCKET_READ_CAPABILITY_ID)
        .is_some_and(|capability| {
            capability.id == R2_BUCKET_READ_CAPABILITY_ID
                && capability.title == "Get Bucket"
                && capability.description.as_deref()
                    == Some("Gets properties of an existing R2 bucket.")
                && capability.method == "GET"
                && capability.path == R2_BUCKET_DETAIL_PATH
                && capability.product == "R2 Bucket"
                && capability.account_scope == "account"
                && capability.permissions.is_empty()
                && capability.request_schema.is_none()
                && r2_bucket_selectors_supported(capability, true)
                && r2_bucket_response_contract_supported(capability)
        })
        && r2_bucket_response_fields_supported(document, "get")
}

fn r2_bucket_delete_contract_supported(capabilities: &BTreeMap<String, CapabilityV1>) -> bool {
    capabilities
        .get(R2_BUCKET_DELETE_CAPABILITY_ID)
        .is_some_and(|capability| {
            capability.id == R2_BUCKET_DELETE_CAPABILITY_ID
                && capability.title == "Delete Bucket"
                && capability.description.as_deref() == Some("Deletes an existing R2 bucket.")
                && capability.method == "DELETE"
                && capability.path == R2_BUCKET_DETAIL_PATH
                && capability.product == "R2 Bucket"
                && capability.account_scope == "account"
                && capability.permissions == ["Workers R2 Storage Write"]
                && capability.request_schema.is_none()
                && r2_bucket_selectors_supported(capability, true)
                && r2_bucket_response_contract_supported(capability)
                && capability.verification.strategy
                    == "same_resource_returns_not_found_after_delete"
                && capability.verification_contract_supported()
        })
}

fn r2_bucket_response_fields_supported(document: &Value, method: &str) -> bool {
    let pointer = format!(
        "/paths/~1accounts~1{{account_id}}~1r2~1buckets{}/{}",
        if method == "post" {
            ""
        } else {
            "~1{bucket_name}"
        },
        method
    );
    document.pointer(&pointer).is_some_and(|operation| {
        success_response_declares_result_fields(
            document,
            operation,
            &[
                "creation_date",
                "jurisdiction",
                "location",
                "name",
                "storage_class",
            ],
        )
    })
}

fn annotate_r2_bucket_verification_projection(capability: &mut CapabilityV1) -> bool {
    let Some(properties) = capability
        .request_schema
        .as_mut()
        .and_then(|schema| schema.get_mut("properties"))
        .and_then(Value::as_object_mut)
    else {
        return false;
    };
    let Some(location_hint) = properties
        .get_mut("locationHint")
        .and_then(Value::as_object_mut)
    else {
        return false;
    };
    location_hint.insert(
        "x-cfctl-verification-observable".to_owned(),
        Value::Bool(false),
    );
    let Some(storage_class) = properties
        .get_mut("storageClass")
        .and_then(Value::as_object_mut)
    else {
        return false;
    };
    storage_class.insert(
        "x-cfctl-verification-response-field".to_owned(),
        Value::String("storage_class".to_owned()),
    );
    true
}

fn finalize_r2_bucket_create_contract(
    document: &Value,
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    let read_supported = r2_bucket_read_contract_supported(document, capabilities);
    let delete_supported = r2_bucket_delete_contract_supported(capabilities);
    let create_response_supported = r2_bucket_response_fields_supported(document, "post");
    let Some(capability) = capabilities.get_mut(R2_BUCKET_CREATE_CAPABILITY_ID) else {
        return;
    };
    if !r2_bucket_create_operation_supported(capability)
        || !read_supported
        || !delete_supported
        || !create_response_supported
    {
        capability.created_resource = None;
        capability.adapter_status = AdapterStatus::Blocked;
        capability.blocked_reason = Some(
            "R2 bucket create, exact readback, or empty-bucket compensation contract drifted"
                .to_owned(),
        );
        return;
    }

    classify_r2_bucket_create(capability);
    if !annotate_r2_bucket_verification_projection(capability) {
        capability.adapter_status = AdapterStatus::Blocked;
        capability.blocked_reason =
            Some("R2 bucket request annotations could not be bound".to_owned());
        return;
    }
    capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: R2_BUCKET_DETAIL_PATH.to_owned(),
        identity_selector: "bucket_name".to_owned(),
        response_result_identity_pointer: "/name".to_owned(),
        read_capability_id: R2_BUCKET_READ_CAPABILITY_ID.to_owned(),
        delete_capability_id: R2_BUCKET_DELETE_CAPABILITY_ID.to_owned(),
        verified_response_fields: vec!["name".to_owned(), "storageClass".to_owned()],
    });
    "created_resource_contains_planned_fields_by_returned_id"
        .clone_into(&mut capability.verification.strategy);
    capability.rollback.supported = true;
    capability.rollback.strategy = Some("delete_created_resource_by_returned_id".to_owned());
    capability.rollback.warning = Some(
        "compensation creates a separately reviewed and explicitly approved exact-bucket delete plan; it can succeed only while the newly created bucket remains empty"
            .to_owned(),
    );
    refresh_dynamic_mutation_contract(capability);
}

const D1_DATABASE_CREATE_CAPABILITY_ID: &str = "d1-create-database";
const D1_DATABASE_READ_CAPABILITY_ID: &str = "d1-get-database";
const D1_DATABASE_DELETE_CAPABILITY_ID: &str = "d1-delete-database";
const D1_DATABASE_COLLECTION_PATH: &str = "/accounts/{account_id}/d1/database";
const D1_DATABASE_DETAIL_PATH: &str = "/accounts/{account_id}/d1/database/{database_id}";

fn d1_account_selector_supported(capability: &CapabilityV1) -> bool {
    capability.selectors.iter().any(|selector| {
        selector.name == "account_id"
            && selector.location == "path"
            && selector.required
            && selector.value_type == "string"
            && selector.description.as_deref() == Some("Account identifier tag.")
            && selector.contract.as_ref().is_some_and(|contract| {
                contract.schema == serde_json::json!({"maxLength":32,"type":"string"})
                    && contract.query.is_none()
            })
    })
}

fn d1_database_create_operation_supported(capability: &CapabilityV1) -> bool {
    capability.id == D1_DATABASE_CREATE_CAPABILITY_ID
        && capability.title == "Create D1 Database"
        && capability.description.as_deref() == Some("Returns the created D1 database.")
        && capability.method == "POST"
        && capability.path == D1_DATABASE_COLLECTION_PATH
        && capability.product == "D1"
        && capability.account_scope == "account"
        && capability.permissions == ["D1 Write"]
        && capability.selectors.len() == 1
        && d1_account_selector_supported(capability)
        && capability.request_schema.as_ref()
            == Some(&serde_json::json!({
                "properties": {
                    "jurisdiction": {"enum": ["eu", "fedramp", "us"], "type": "string"},
                    "name": {"type": "string"},
                    "primary_location_hint": {
                        "enum": ["wnam", "enam", "weur", "eeur", "apac", "oc"],
                        "type": "string"
                    },
                    "read_replication": {
                        "properties": {
                            "mode": {"enum": ["auto", "disabled"], "type": "string"}
                        },
                        "required": ["mode"],
                        "type": "object"
                    }
                },
                "required": ["name"],
                "type": "object",
                "x-cfctl-body-required": true
            }))
        && capability
            .response_contract
            .as_ref()
            .is_some_and(|response| {
                response.success_statuses == ["200"]
                    && response.success_media_types == ["application/json"]
                    && response.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
            })
}

fn d1_database_read_contract_supported(
    document: &Value,
    capabilities: &BTreeMap<String, CapabilityV1>,
) -> bool {
    capabilities
        .get(D1_DATABASE_READ_CAPABILITY_ID)
        .is_some_and(|capability| {
            capability.id == D1_DATABASE_READ_CAPABILITY_ID
                && capability.title == "Get D1 Database"
                && capability.description.as_deref()
                    == Some("Returns the specified D1 database.")
                && capability.method == "GET"
                && capability.path == D1_DATABASE_DETAIL_PATH
                && capability.product == "D1"
                && capability.account_scope == "account"
                && capability.permissions == ["D1 Read", "D1 Write"]
                && capability.request_schema.is_none()
                && capability.selectors.len() == 3
                && d1_account_selector_supported(capability)
                && capability.selectors.iter().any(|selector| {
                    selector.name == "database_id"
                        && selector.location == "path"
                        && selector.required
                        && selector.value_type == "string"
                        && selector.contract.as_ref().is_some_and(|contract| {
                            contract.schema
                                == serde_json::json!({"oneOf":[{"type":"string"},{"type":"string"}]})
                                && contract.query.is_none()
                        })
                })
                && capability.selectors.iter().any(|selector| {
                    selector.name == "fields"
                        && selector.location == "query"
                        && !selector.required
                        && selector.value_type == "array"
                        && selector.contract.as_ref().is_some_and(|contract| {
                            contract.schema
                                == serde_json::json!({
                                    "items": {
                                        "enum": [
                                            "uuid", "name", "created_at", "version",
                                            "jurisdiction", "num_tables", "file_size",
                                            "running_in_region", "read_replication"
                                        ],
                                        "type":"string"
                                    },
                                    "type":"array"
                                })
                                && contract.query.as_ref().is_some_and(|query| {
                                    query.style == "form"
                                        && !query.explode
                                        && !query.allow_reserved
                                        && !query.allow_empty_value
                                })
                        })
                })
                && capability.response_contract.as_ref().is_some_and(|response| {
                    response.success_statuses == ["200"]
                        && response.success_media_types == ["application/json"]
                        && response.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
                })
        })
        && document
            .pointer("/paths/~1accounts~1{account_id}~1d1~1database~1{database_id}/get")
            .is_some_and(|operation| {
                success_response_declares_result_fields(
                    document,
                    operation,
                    &[
                        "file_size",
                        "jurisdiction",
                        "name",
                        "num_tables",
                        "read_replication",
                        "uuid",
                    ],
                )
            })
}

fn d1_database_delete_contract_supported(capabilities: &BTreeMap<String, CapabilityV1>) -> bool {
    capabilities
        .get(D1_DATABASE_DELETE_CAPABILITY_ID)
        .is_some_and(|capability| {
            capability.id == D1_DATABASE_DELETE_CAPABILITY_ID
                && capability.title == "Delete D1 Database"
                && capability.description.as_deref() == Some("Deletes the specified D1 database.")
                && capability.method == "DELETE"
                && capability.path == D1_DATABASE_DETAIL_PATH
                && capability.product == "D1"
                && capability.account_scope == "account"
                && capability.permissions == ["D1 Write"]
                && capability.request_schema.is_none()
                && capability.selectors.len() == 2
                && d1_account_selector_supported(capability)
                && capability.selectors.iter().any(|selector| {
                    selector.name == "database_id"
                        && selector.location == "path"
                        && selector.required
                        && selector.value_type == "string"
                        && selector.description.as_deref() == Some("D1 database identifier (UUID).")
                        && selector.contract.as_ref().is_some_and(|contract| {
                            contract.schema == serde_json::json!({"type":"string"})
                                && contract.query.is_none()
                        })
                })
                && capability
                    .response_contract
                    .as_ref()
                    .is_some_and(|response| {
                        response.success_statuses == ["200"]
                            && response.success_media_types == ["application/json"]
                            && response.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
                    })
                && capability.verification.strategy
                    == "same_resource_returns_not_found_after_delete"
                && capability.verification_contract_supported()
        })
}

fn d1_database_references() -> Vec<KnowledgeReferenceV1> {
    vec![
        KnowledgeReferenceV1 {
            title: "Create D1 Database API".to_owned(),
            url: "https://developers.cloudflare.com/api/resources/d1/subresources/database/methods/create/"
                .to_owned(),
            source: "official Cloudflare API reference".to_owned(),
        },
        KnowledgeReferenceV1 {
            title: "D1 pricing".to_owned(),
            url: "https://developers.cloudflare.com/d1/platform/pricing/".to_owned(),
            source: "official Cloudflare docs".to_owned(),
        },
        KnowledgeReferenceV1 {
            title: "D1 limits".to_owned(),
            url: "https://developers.cloudflare.com/d1/platform/limits/".to_owned(),
            source: "official Cloudflare docs".to_owned(),
        },
        KnowledgeReferenceV1 {
            title: "D1 data location".to_owned(),
            url: "https://developers.cloudflare.com/d1/configuration/data-location/".to_owned(),
            source: "official Cloudflare docs".to_owned(),
        },
    ]
}

fn classify_d1_database_create(capability: &mut CapabilityV1) {
    capability.risk = RiskClass::ScopedWrite;
    capability.effect = EffectClass::ReversibleWrite;
    capability.cost = cfctl_core::CostV1::default();
    capability.cost.billing_model = BillingModelV1::UsageBased;
    capability.cost.exposure = CostExposureV1::DownstreamUsage;
    capability.cost.basis = Some(
        "database creation has no fixed API-operation charge; an empty D1 database uses approximately 12 KB against account storage, while later rows read, rows written, and storage remain usage-billed and read replicas add no separate replica charge"
            .to_owned(),
    );
    capability.cost.references = d1_database_references();
    capability.entitlement.available = Some(true);
    capability.entitlement.plans =
        BTreeMap::from([("free".to_owned(), true), ("paid".to_owned(), true)]);
    capability.entitlement.blocker = None;
    capability.entitlement.source =
        Some("https://developers.cloudflare.com/d1/platform/pricing/".to_owned());
    capability.entitlement.requires_live_resolution = false;
    capability.verification.required = true;
    "post_change_read_or_operation_specific_verifier"
        .clone_into(&mut capability.verification.strategy);
    capability.rollback.supported = false;
    capability.rollback.strategy = None;
    capability.rollback.warning = Some(
        "compensation is possible only through a separately reviewed delete plan that binds and rechecks the created database's live empty-state receipt"
            .to_owned(),
    );
}

fn finalize_d1_database_create_contract(
    document: &Value,
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    let create_supported = capabilities
        .get(D1_DATABASE_CREATE_CAPABILITY_ID)
        .is_some_and(d1_database_create_operation_supported);
    let read_supported = d1_database_read_contract_supported(document, capabilities);
    let delete_supported = d1_database_delete_contract_supported(capabilities);
    let create_response_supported = document
        .pointer("/paths/~1accounts~1{account_id}~1d1~1database/post")
        .is_some_and(|operation| {
            success_response_declares_result_fields(
                document,
                operation,
                &["jurisdiction", "name", "read_replication", "uuid"],
            )
        });
    let Some(capability) = capabilities.get_mut(D1_DATABASE_CREATE_CAPABILITY_ID) else {
        return;
    };
    if !create_supported || !read_supported || !delete_supported || !create_response_supported {
        capability.created_resource = None;
        capability.adapter_status = AdapterStatus::Blocked;
        capability.blocked_reason = Some(format!(
            "D1 create, exact readback, or guarded empty-database compensation contract drifted (create={create_supported}, read={read_supported}, delete={delete_supported}, response={create_response_supported})"
        ));
        return;
    }

    classify_d1_database_create(capability);
    let Some(location_hint) = capability
        .request_schema
        .as_mut()
        .and_then(|schema| schema.get_mut("properties"))
        .and_then(Value::as_object_mut)
        .and_then(|properties| properties.get_mut("primary_location_hint"))
        .and_then(Value::as_object_mut)
    else {
        capability.adapter_status = AdapterStatus::Blocked;
        capability.blocked_reason =
            Some("D1 location-hint verification annotation could not be bound".to_owned());
        return;
    };
    location_hint.insert(
        "x-cfctl-verification-observable".to_owned(),
        Value::Bool(false),
    );
    capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: D1_DATABASE_DETAIL_PATH.to_owned(),
        identity_selector: "database_id".to_owned(),
        response_result_identity_pointer: "/uuid".to_owned(),
        read_capability_id: D1_DATABASE_READ_CAPABILITY_ID.to_owned(),
        delete_capability_id: D1_DATABASE_DELETE_CAPABILITY_ID.to_owned(),
        verified_response_fields: vec![
            "jurisdiction".to_owned(),
            "name".to_owned(),
            "read_replication".to_owned(),
        ],
    });
    "created_resource_contains_planned_fields_by_returned_id"
        .clone_into(&mut capability.verification.strategy);
    capability.rollback.supported = true;
    capability.rollback.strategy =
        Some("delete_created_empty_d1_database_by_returned_uuid_if_unchanged".to_owned());
    capability.rollback.warning = Some(
        "rectification creates a separate hash-bound delete plan only after a live empty-state read; it rechecks that exact receipt before execution, never runs automatically, and requires explicit approval"
            .to_owned(),
    );
    refresh_dynamic_mutation_contract(capability);
}

fn classify_d1_read_replication_update(capability: &mut CapabilityV1) {
    capability.adapter_status = AdapterStatus::DynamicApi;
    capability.risk = RiskClass::ScopedWrite;
    capability.effect = EffectClass::ReversibleWrite;
    capability.cost = cfctl_core::CostV1::default();
    capability.cost.exposure = CostExposureV1::DownstreamUsage;
    capability.cost.basis = Some(
        "enabling or disabling D1 read replication has no incremental operation or replica charge; ordinary rows-read, rows-written, and storage billing continues"
            .to_owned(),
    );
    capability.cost.references = vec![
        KnowledgeReferenceV1 {
            title: "D1 pricing".to_owned(),
            url: "https://developers.cloudflare.com/d1/platform/pricing/".to_owned(),
            source: "official Cloudflare docs".to_owned(),
        },
        KnowledgeReferenceV1 {
            title: "D1 global read replication".to_owned(),
            url: "https://developers.cloudflare.com/d1/best-practices/read-replication/".to_owned(),
            source: "official Cloudflare docs".to_owned(),
        },
    ];
    capability.verification.required = true;
    "post_change_read_or_operation_specific_verifier"
        .clone_into(&mut capability.verification.strategy);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccessAuthorizationConfigurationKind {
    Group,
    IdentityProvider,
    Policy,
}

struct AccessAuthorizationConfigurationContract {
    id: &'static str,
    method: &'static str,
    path: &'static str,
    product: &'static str,
    permission: &'static str,
    kind: AccessAuthorizationConfigurationKind,
}

const ACCESS_AUTHORIZATION_CONFIGURATION_CONTRACTS: &[AccessAuthorizationConfigurationContract] = &[
    AccessAuthorizationConfigurationContract {
        id: "access-groups-create-an-access-group",
        method: "POST",
        path: "/accounts/{account_id}/access/groups",
        product: "Access groups",
        permission: "Access: Organizations, Identity Providers, and Groups Write",
        kind: AccessAuthorizationConfigurationKind::Group,
    },
    AccessAuthorizationConfigurationContract {
        id: "access-groups-update-an-access-group",
        method: "PUT",
        path: "/accounts/{account_id}/access/groups/{group_id}",
        product: "Access groups",
        permission: "Access: Organizations, Identity Providers, and Groups Write",
        kind: AccessAuthorizationConfigurationKind::Group,
    },
    AccessAuthorizationConfigurationContract {
        id: "zone-level-access-groups-create-an-access-group",
        method: "POST",
        path: "/zones/{zone_id}/access/groups",
        product: "Zone-Level Access groups",
        permission: "Access: Organizations, Identity Providers, and Groups Write",
        kind: AccessAuthorizationConfigurationKind::Group,
    },
    AccessAuthorizationConfigurationContract {
        id: "zone-level-access-groups-update-an-access-group",
        method: "PUT",
        path: "/zones/{zone_id}/access/groups/{group_id}",
        product: "Zone-Level Access groups",
        permission: "Access: Organizations, Identity Providers, and Groups Write",
        kind: AccessAuthorizationConfigurationKind::Group,
    },
    AccessAuthorizationConfigurationContract {
        id: "access-identity-providers-add-an-access-identity-provider",
        method: "POST",
        path: "/accounts/{account_id}/access/identity_providers",
        product: "Access identity providers",
        permission: "Access: Organizations, Identity Providers, and Groups Write",
        kind: AccessAuthorizationConfigurationKind::IdentityProvider,
    },
    AccessAuthorizationConfigurationContract {
        id: "access-identity-providers-update-an-access-identity-provider",
        method: "PUT",
        path: "/accounts/{account_id}/access/identity_providers/{identity_provider_id}",
        product: "Access identity providers",
        permission: "Access: Organizations, Identity Providers, and Groups Write",
        kind: AccessAuthorizationConfigurationKind::IdentityProvider,
    },
    AccessAuthorizationConfigurationContract {
        id: "zone-level-access-identity-providers-add-an-access-identity-provider",
        method: "POST",
        path: "/zones/{zone_id}/access/identity_providers",
        product: "Zone-Level Access identity providers",
        permission: "Access: Organizations, Identity Providers, and Groups Write",
        kind: AccessAuthorizationConfigurationKind::IdentityProvider,
    },
    AccessAuthorizationConfigurationContract {
        id: "zone-level-access-identity-providers-update-an-access-identity-provider",
        method: "PUT",
        path: "/zones/{zone_id}/access/identity_providers/{identity_provider_id}",
        product: "Zone-Level Access identity providers",
        permission: "Access: Organizations, Identity Providers, and Groups Write",
        kind: AccessAuthorizationConfigurationKind::IdentityProvider,
    },
    AccessAuthorizationConfigurationContract {
        id: "access-policies-create-an-access-policy",
        method: "POST",
        path: "/accounts/{account_id}/access/apps/{app_id}/policies",
        product: "Access application-scoped policies",
        permission: "Access: Apps and Policies Write",
        kind: AccessAuthorizationConfigurationKind::Policy,
    },
    AccessAuthorizationConfigurationContract {
        id: "access-policies-update-an-access-policy",
        method: "PUT",
        path: "/accounts/{account_id}/access/apps/{app_id}/policies/{policy_id}",
        product: "Access application-scoped policies",
        permission: "Access: Apps and Policies Write",
        kind: AccessAuthorizationConfigurationKind::Policy,
    },
    AccessAuthorizationConfigurationContract {
        id: "access-policies-create-an-access-reusable-policy",
        method: "POST",
        path: "/accounts/{account_id}/access/policies",
        product: "Access reusable policies",
        permission: "Access: Apps and Policies Write",
        kind: AccessAuthorizationConfigurationKind::Policy,
    },
    AccessAuthorizationConfigurationContract {
        id: "access-policies-update-an-access-reusable-policy",
        method: "PUT",
        path: "/accounts/{account_id}/access/policies/{policy_id}",
        product: "Access reusable policies",
        permission: "Access: Apps and Policies Write",
        kind: AccessAuthorizationConfigurationKind::Policy,
    },
    AccessAuthorizationConfigurationContract {
        id: "zone-level-access-policies-create-an-access-policy",
        method: "POST",
        path: "/zones/{zone_id}/access/apps/{app_id}/policies",
        product: "Zone-Level Access policies",
        permission: "Access: Apps and Policies Write",
        kind: AccessAuthorizationConfigurationKind::Policy,
    },
    AccessAuthorizationConfigurationContract {
        id: "zone-level-access-policies-update-an-access-policy",
        method: "PUT",
        path: "/zones/{zone_id}/access/apps/{app_id}/policies/{policy_id}",
        product: "Zone-Level Access policies",
        permission: "Access: Apps and Policies Write",
        kind: AccessAuthorizationConfigurationKind::Policy,
    },
];

const ACCOUNT_ACCESS_SERVICE_TOKEN_CREATE_CAPABILITY_ID: &str =
    "access-service-tokens-create-a-service-token";
const ACCESS_SERVICE_TOKEN_GET_CAPABILITY_ID: &str = "access-service-tokens-get-a-service-token";
const ACCESS_SERVICE_TOKEN_DELETE_CAPABILITY_ID: &str =
    "access-service-tokens-delete-a-service-token";
const ACCESS_SERVICE_TOKEN_REFRESH_CAPABILITY_ID: &str =
    "access-service-tokens-refresh-a-service-token";
const ACCESS_SERVICE_TOKEN_COLLECTION_PATH: &str = "/accounts/{account_id}/access/service_tokens";
const ACCESS_SERVICE_TOKEN_DETAIL_PATH: &str =
    "/accounts/{account_id}/access/service_tokens/{service_token_id}";
const ACCESS_SERVICE_TOKEN_REFRESH_PATH: &str =
    "/accounts/{account_id}/access/service_tokens/{service_token_id}/refresh";

struct AccessServiceTokenCreateContract {
    id: &'static str,
    collection_path: &'static str,
    detail_path: &'static str,
    product: &'static str,
    scope_selector: &'static str,
    read_id: &'static str,
    delete_id: &'static str,
    description: &'static str,
}

struct AccessServiceTokenUpdateContract {
    id: &'static str,
    detail_path: &'static str,
    product: &'static str,
    scope_selector: &'static str,
}

const ACCESS_SERVICE_TOKEN_CREATE_CONTRACTS: &[AccessServiceTokenCreateContract] = &[
    AccessServiceTokenCreateContract {
        id: ACCOUNT_ACCESS_SERVICE_TOKEN_CREATE_CAPABILITY_ID,
        collection_path: ACCESS_SERVICE_TOKEN_COLLECTION_PATH,
        detail_path: ACCESS_SERVICE_TOKEN_DETAIL_PATH,
        product: "Access service tokens",
        scope_selector: "account_id",
        read_id: ACCESS_SERVICE_TOKEN_GET_CAPABILITY_ID,
        delete_id: ACCESS_SERVICE_TOKEN_DELETE_CAPABILITY_ID,
        description: "Generates a new service token. **Note:** This is the only time you can get the Client Secret. If you lose the Client Secret, you will have to rotate the Client Secret or create a new service token.",
    },
    AccessServiceTokenCreateContract {
        id: "zone-level-access-service-tokens-create-a-service-token",
        collection_path: "/zones/{zone_id}/access/service_tokens",
        detail_path: "/zones/{zone_id}/access/service_tokens/{service_token_id}",
        product: "Zone-Level Access service tokens",
        scope_selector: "zone_id",
        read_id: "zone-level-access-service-tokens-get-a-service-token",
        delete_id: "zone-level-access-service-tokens-delete-a-service-token",
        description: "Generates a new service token. **Note:** This is the only time you can get the Client Secret. If you lose the Client Secret, you will have to create a new service token.",
    },
];

const ACCESS_SERVICE_TOKEN_UPDATE_CONTRACTS: &[AccessServiceTokenUpdateContract] = &[
    AccessServiceTokenUpdateContract {
        id: "access-service-tokens-update-a-service-token",
        detail_path: ACCESS_SERVICE_TOKEN_DETAIL_PATH,
        product: "Access service tokens",
        scope_selector: "account_id",
    },
    AccessServiceTokenUpdateContract {
        id: "zone-level-access-service-tokens-update-a-service-token",
        detail_path: "/zones/{zone_id}/access/service_tokens/{service_token_id}",
        product: "Zone-Level Access service tokens",
        scope_selector: "zone_id",
    },
];

fn apply_access_service_token_commercial_contract(capability: &mut CapabilityV1) {
    capability.cost = cfctl_core::CostV1::default();
    capability.cost.billing_model = BillingModelV1::Subscription;
    capability.cost.exposure = CostExposureV1::AccountQuote;
    capability.cost.basis = Some(
        "creating, updating, or refreshing an Access service token has no direct operation charge; the account's service-token capacity and any separately negotiated increase remain part of its existing Zero Trust subscription"
            .to_owned(),
    );
    capability.cost.references = vec![
        KnowledgeReferenceV1 {
            title: "Cloudflare Access service tokens".to_owned(),
            url: "https://developers.cloudflare.com/cloudflare-one/access-controls/service-credentials/service-tokens/"
                .to_owned(),
            source: "official Cloudflare docs".to_owned(),
        },
        KnowledgeReferenceV1 {
            title: "Cloudflare One account limits".to_owned(),
            url: "https://developers.cloudflare.com/cloudflare-one/account-limits/".to_owned(),
            source: "official Cloudflare docs".to_owned(),
        },
        KnowledgeReferenceV1 {
            title: "Create an Access service token".to_owned(),
            url: "https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/service_tokens/methods/create/"
                .to_owned(),
            source: "official Cloudflare API".to_owned(),
        },
        KnowledgeReferenceV1 {
            title: "Update an Access service token".to_owned(),
            url: "https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/service_tokens/methods/update/"
                .to_owned(),
            source: "official Cloudflare API".to_owned(),
        },
        KnowledgeReferenceV1 {
            title: "Refresh an Access service token".to_owned(),
            url: "https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/service_tokens/methods/refresh/"
                .to_owned(),
            source: "official Cloudflare API".to_owned(),
        },
        KnowledgeReferenceV1 {
            title: "Cloudflare Zero Trust and SASE plans".to_owned(),
            url: "https://www.cloudflare.com/plans/zero-trust-services/".to_owned(),
            source: "official Cloudflare pricing".to_owned(),
        },
    ];
    capability.entitlement.available = Some(true);
    capability.entitlement.plans = BTreeMap::from([
        ("free".to_owned(), true),
        ("pay_as_you_go".to_owned(), true),
        ("contract".to_owned(), true),
    ]);
    capability.entitlement.blocker = None;
    capability.entitlement.source =
        Some("https://www.cloudflare.com/plans/zero-trust-services/".to_owned());
    capability.entitlement.requires_live_resolution = false;
}

fn access_service_token_update_contract_supported(capability: &CapabilityV1) -> bool {
    ACCESS_SERVICE_TOKEN_UPDATE_CONTRACTS
        .iter()
        .any(|contract| {
            capability.id == contract.id
                && capability.method == "PUT"
                && capability.path == contract.detail_path
                && capability.product == contract.product
                && capability.permissions == ["Access: Service Tokens Write"]
                && capability.description.as_deref() == Some("Updates a configured service token.")
                && access_service_token_detail_selectors_supported(
                    capability,
                    contract.scope_selector,
                )
                && access_service_token_source_update_request_supported(capability)
                && access_service_token_response_contract_supported(
                    capability.response_contract.as_ref(),
                    "200",
                )
        })
}

fn classify_access_service_token_update(capability: &mut CapabilityV1) {
    capability.request_schema = Some(serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "duration": {"type": "string"},
            "name": {"type": "string"}
        },
        "x-cfctl-body-required": true
    }));
    capability.risk = RiskClass::IdentityOrOwnership;
    capability.effect = EffectClass::IdentityOrOwnership;
    apply_access_service_token_commercial_contract(capability);
    capability.rollback.supported = false;
    capability.rollback.strategy = None;
    capability.rollback.warning = Some(
        "changing duration resets credential expiration, so cfctl cannot restore the exact prior expiration; name or duration restoration requires a separately reviewed update plan built from trusted evidence"
            .to_owned(),
    );
    capability.verification.required = true;
    "post_change_read_or_operation_specific_verifier"
        .clone_into(&mut capability.verification.strategy);
}

fn classify_access_service_token_create_contract(
    document: &Value,
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    for contract in ACCESS_SERVICE_TOKEN_CREATE_CONTRACTS {
        if !access_service_token_create_contract_supported(document, capabilities, contract) {
            continue;
        }
        let Some(capability) = capabilities.get_mut(contract.id) else {
            continue;
        };

        capability.request_schema = Some(serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["name"],
            "properties": {
                "duration": {"type": "string"},
                "name": {"type": "string"}
            },
            "x-cfctl-body-required": true
        }));
        capability.risk = RiskClass::SecretSensitive;
        capability.effect = EffectClass::IdentityOrOwnership;
        apply_access_service_token_commercial_contract(capability);
        capability.verification.required = true;
        "post_change_read_or_operation_specific_verifier"
            .clone_into(&mut capability.verification.strategy);
        refresh_dynamic_mutation_contract(capability);
    }
}

fn classify_access_service_token_refresh_contract(
    document: &Value,
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    if !access_service_token_refresh_contract_supported(document, capabilities) {
        return;
    }
    let Some(capability) = capabilities.get_mut(ACCESS_SERVICE_TOKEN_REFRESH_CAPABILITY_ID) else {
        return;
    };

    capability.risk = RiskClass::Irreversible;
    capability.effect = EffectClass::Irreversible;
    apply_access_service_token_commercial_contract(capability);
    capability.verification.required = true;
    "access_service_token_reports_refreshed_expiration"
        .clone_into(&mut capability.verification.strategy);
    capability.same_path_read = Some(SamePathReadContractV1 {
        path: ACCESS_SERVICE_TOKEN_DETAIL_PATH.to_owned(),
        read_capability_id: ACCESS_SERVICE_TOKEN_GET_CAPABILITY_ID.to_owned(),
        verified_response_fields: vec!["expires_at".to_owned(), "id".to_owned()],
    });
    capability.rollback.supported = false;
    capability.rollback.strategy = None;
    capability.rollback.warning = Some(
        "the one-year extension resets expiration relative to refresh time and cannot restore the prior expiration; shortening or otherwise correcting lifetime requires a separately reviewed operation built from trusted evidence"
            .to_owned(),
    );
    refresh_dynamic_mutation_contract(capability);
}

fn access_service_token_refresh_contract_supported(
    document: &Value,
    capabilities: &BTreeMap<String, CapabilityV1>,
) -> bool {
    let Some(refresh) = capabilities.get(ACCESS_SERVICE_TOKEN_REFRESH_CAPABILITY_ID) else {
        return false;
    };
    let Some(read) = capabilities.get(ACCESS_SERVICE_TOKEN_GET_CAPABILITY_ID) else {
        return false;
    };
    if refresh.method != "POST"
        || refresh.path != ACCESS_SERVICE_TOKEN_REFRESH_PATH
        || refresh.product != "Access service tokens"
        || refresh.permissions != ["Access: Service Tokens Write"]
        || refresh.description.as_deref() != Some("Refreshes the expiration of a service token.")
        || refresh.request_schema.is_some()
        || !access_service_token_detail_selectors_supported(refresh, "account_id")
        || !access_service_token_response_contract_supported(
            refresh.response_contract.as_ref(),
            "200",
        )
        || read.method != "GET"
        || read.path != ACCESS_SERVICE_TOKEN_DETAIL_PATH
        || read.product != "Access service tokens"
        || read.permissions.len() != 2
        || !read
            .permissions
            .iter()
            .any(|permission| permission == "Access: Service Tokens Write")
        || !read
            .permissions
            .iter()
            .any(|permission| permission == "Access: Service Tokens Read")
        || !access_service_token_detail_selectors_supported(read, "account_id")
        || !access_service_token_response_contract_supported(read.response_contract.as_ref(), "200")
    {
        return false;
    }

    let Some(refresh_operation) = document
        .get("paths")
        .and_then(Value::as_object)
        .and_then(|paths| paths.get(ACCESS_SERVICE_TOKEN_REFRESH_PATH))
        .and_then(|path| path.get("post"))
    else {
        return false;
    };
    let Some(read_operation) = document
        .get("paths")
        .and_then(Value::as_object)
        .and_then(|paths| paths.get(ACCESS_SERVICE_TOKEN_DETAIL_PATH))
        .and_then(|path| path.get("get"))
    else {
        return false;
    };
    ["id", "expires_at"].iter().all(|field| {
        success_response_declares_result_string_field(document, refresh_operation, field)
            && success_response_declares_result_string_field(document, read_operation, field)
    })
}

fn access_service_token_create_contract_supported(
    document: &Value,
    capabilities: &BTreeMap<String, CapabilityV1>,
    contract: &AccessServiceTokenCreateContract,
) -> bool {
    let Some(create) = capabilities.get(contract.id) else {
        return false;
    };
    let Some(read) = capabilities.get(contract.read_id) else {
        return false;
    };
    let Some(delete) = capabilities.get(contract.delete_id) else {
        return false;
    };
    if create.method != "POST"
        || create.path != contract.collection_path
        || create.product != contract.product
        || create.permissions != ["Access: Service Tokens Write"]
        || !access_service_token_collection_selectors_supported(create, contract.scope_selector)
        || !access_service_token_source_create_request_supported(create)
        || create.description.as_deref() != Some(contract.description)
        || !access_service_token_response_contract_supported(
            create.response_contract.as_ref(),
            "201",
        )
        || read.method != "GET"
        || read.path != contract.detail_path
        || read.product != contract.product
        || read.permissions.len() != 2
        || !read
            .permissions
            .iter()
            .any(|permission| permission == "Access: Service Tokens Write")
        || !read
            .permissions
            .iter()
            .any(|permission| permission == "Access: Service Tokens Read")
        || !access_service_token_detail_selectors_supported(read, contract.scope_selector)
        || !access_service_token_response_contract_supported(read.response_contract.as_ref(), "200")
        || delete.method != "DELETE"
        || delete.path != contract.detail_path
        || delete.product != contract.product
        || delete.permissions != ["Access: Service Tokens Write"]
        || delete.request_schema.is_some()
        || !access_service_token_detail_selectors_supported(delete, contract.scope_selector)
        || !access_service_token_response_contract_supported(
            delete.response_contract.as_ref(),
            "200",
        )
    {
        return false;
    }

    let Some(create_operation) = document
        .get("paths")
        .and_then(Value::as_object)
        .and_then(|paths| paths.get(contract.collection_path))
        .and_then(|path| path.get("post"))
    else {
        return false;
    };
    let Some(read_operation) = document
        .get("paths")
        .and_then(Value::as_object)
        .and_then(|paths| paths.get(contract.detail_path))
        .and_then(|path| path.get("get"))
    else {
        return false;
    };
    ["id", "client_id", "client_secret"].iter().all(|field| {
        success_response_declares_result_string_field(document, create_operation, field)
    }) && ["id", "client_id", "duration", "name"]
        .iter()
        .all(|field| success_response_declares_result_string_field(document, read_operation, field))
}

fn access_service_token_response_contract_supported(
    response: Option<&ResponseContractV1>,
    status: &str,
) -> bool {
    response.is_some_and(|response| {
        response.success_statuses == [status]
            && response.success_media_types == ["application/json"]
            && response.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
    })
}

fn access_service_token_collection_selectors_supported(
    capability: &CapabilityV1,
    scope_selector: &str,
) -> bool {
    capability.selectors.len() == 1
        && access_service_token_selector_supported(capability, scope_selector, 32)
}

fn access_service_token_detail_selectors_supported(
    capability: &CapabilityV1,
    scope_selector: &str,
) -> bool {
    capability.selectors.len() == 2
        && access_service_token_selector_supported(capability, scope_selector, 32)
        && access_service_token_selector_supported(capability, "service_token_id", 36)
}

fn access_service_token_selector_supported(
    capability: &CapabilityV1,
    name: &str,
    max_length: u64,
) -> bool {
    capability.selectors.iter().any(|selector| {
        selector.name == name
            && selector.location == "path"
            && selector.required
            && selector.value_type == "string"
            && selector.contract.as_ref().is_some_and(|contract| {
                contract.schema == serde_json::json!({"maxLength":max_length,"type":"string"})
                    && contract.query.is_none()
            })
    })
}

fn access_service_token_source_create_request_supported(capability: &CapabilityV1) -> bool {
    let Some(schema) = capability.request_schema.as_ref() else {
        return false;
    };
    let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
        return false;
    };
    if schema
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|value_type| value_type != "object")
        || schema.get("required") != Some(&serde_json::json!(["name"]))
        || schema.get("x-cfctl-body-required").and_then(Value::as_bool) != Some(true)
        || properties.len() != 4
    {
        return false;
    }
    properties.get("client_secret_version") == Some(&serde_json::json!({"type":"number"}))
        && properties.get("duration") == Some(&serde_json::json!({"type":"string"}))
        && properties.get("name") == Some(&serde_json::json!({"type":"string"}))
        && properties.get("previous_client_secret_expires_at")
            == Some(&serde_json::json!({"format":"date-time","type":"string"}))
}

fn access_service_token_source_update_request_supported(capability: &CapabilityV1) -> bool {
    let Some(schema) = capability.request_schema.as_ref() else {
        return false;
    };
    let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
        return false;
    };
    if schema
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|value_type| value_type != "object")
        || schema.get("required").is_some()
        || schema.get("x-cfctl-body-required").and_then(Value::as_bool) != Some(true)
        || properties.len() != 4
    {
        return false;
    }
    properties.get("client_secret_version") == Some(&serde_json::json!({"type":"number"}))
        && properties.get("duration") == Some(&serde_json::json!({"type":"string"}))
        && properties.get("name") == Some(&serde_json::json!({"type":"string"}))
        && properties.get("previous_client_secret_expires_at")
            == Some(&serde_json::json!({"format":"date-time","type":"string"}))
}

fn access_authorization_configuration_kind(
    capability: &CapabilityV1,
) -> Option<AccessAuthorizationConfigurationKind> {
    ACCESS_AUTHORIZATION_CONFIGURATION_CONTRACTS
        .iter()
        .find(|contract| {
            capability.id == contract.id
                && capability.method == contract.method
                && capability.path == contract.path
                && capability.product == contract.product
                && !capability.permissions.is_empty()
                && capability
                    .permissions
                    .iter()
                    .all(|actual| actual == contract.permission)
        })
        .map(|contract| contract.kind)
}

fn classify_access_authorization_configuration(
    capability: &mut CapabilityV1,
    kind: AccessAuthorizationConfigurationKind,
) {
    capability.risk = match kind {
        AccessAuthorizationConfigurationKind::IdentityProvider => RiskClass::IdentityOrOwnership,
        AccessAuthorizationConfigurationKind::Group
        | AccessAuthorizationConfigurationKind::Policy => RiskClass::CrossConfig,
    };
    capability.effect = match kind {
        AccessAuthorizationConfigurationKind::IdentityProvider => EffectClass::IdentityOrOwnership,
        AccessAuthorizationConfigurationKind::Group
        | AccessAuthorizationConfigurationKind::Policy => EffectClass::ReversibleWrite,
    };
    capability.cost = cfctl_core::CostV1::default();
    capability.cost.billing_model = BillingModelV1::Subscription;
    capability.cost.exposure = CostExposureV1::DownstreamUsage;
    capability.cost.basis = Some(
        "creating or updating Access authorization configuration has no direct operation charge and does not itself consume a user seat; users who subsequently authenticate or generate Gateway activity can consume seats under the account's Free, pay-as-you-go, or contract plan"
            .to_owned(),
    );
    capability.cost.references = vec![
        KnowledgeReferenceV1 {
            title: "Cloudflare Zero Trust and SASE plans".to_owned(),
            url: "https://www.cloudflare.com/plans/zero-trust-services/".to_owned(),
            source: "official Cloudflare pricing".to_owned(),
        },
        KnowledgeReferenceV1 {
            title: "Cloudflare One seat management".to_owned(),
            url: "https://developers.cloudflare.com/cloudflare-one/team-and-resources/users/seat-management/"
                .to_owned(),
            source: "official Cloudflare docs".to_owned(),
        },
    ];
    capability.cost.references.push(match kind {
        AccessAuthorizationConfigurationKind::Group => KnowledgeReferenceV1 {
            title: "Cloudflare Access rule groups".to_owned(),
            url: "https://developers.cloudflare.com/cloudflare-one/access-controls/policies/groups/"
                .to_owned(),
            source: "official Cloudflare docs".to_owned(),
        },
        AccessAuthorizationConfigurationKind::IdentityProvider => KnowledgeReferenceV1 {
            title: "Cloudflare Access identity providers".to_owned(),
            url: "https://developers.cloudflare.com/cloudflare-one/integrations/identity-providers/"
                .to_owned(),
            source: "official Cloudflare docs".to_owned(),
        },
        AccessAuthorizationConfigurationKind::Policy => KnowledgeReferenceV1 {
            title: "Manage Cloudflare Access policies".to_owned(),
            url: "https://developers.cloudflare.com/cloudflare-one/access-controls/policies/policy-management/"
                .to_owned(),
            source: "official Cloudflare docs".to_owned(),
        },
    });
    capability.entitlement.available = Some(true);
    capability.entitlement.plans = BTreeMap::from([
        ("free".to_owned(), true),
        ("pay_as_you_go".to_owned(), true),
        ("contract".to_owned(), true),
    ]);
    capability.entitlement.source =
        Some("https://www.cloudflare.com/plans/zero-trust-services/".to_owned());
    capability.verification.required = true;
    "post_change_read_or_operation_specific_verifier"
        .clone_into(&mut capability.verification.strategy);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoadBalancingConfigurationKind {
    MonitorOrPool,
    LoadBalancer,
}

struct LoadBalancingConfigurationContract {
    create_id: &'static str,
    patch_id: &'static str,
    update_id: &'static str,
    collection_path: &'static str,
    detail_path: &'static str,
    product: &'static str,
    permission: &'static str,
    kind: LoadBalancingConfigurationKind,
}

const LOAD_BALANCING_CONFIGURATION_CONTRACTS: &[LoadBalancingConfigurationContract] = &[
    LoadBalancingConfigurationContract {
        create_id: "account-load-balancer-monitors-create-monitor",
        patch_id: "account-load-balancer-monitors-patch-monitor",
        update_id: "account-load-balancer-monitors-update-monitor",
        collection_path: "/accounts/{account_id}/load_balancers/monitors",
        detail_path: "/accounts/{account_id}/load_balancers/monitors/{monitor_id}",
        product: "Account Load Balancer Monitors",
        permission: "Load Balancing: Monitors and Pools Write",
        kind: LoadBalancingConfigurationKind::MonitorOrPool,
    },
    LoadBalancingConfigurationContract {
        create_id: "account-load-balancer-pools-create-pool",
        patch_id: "account-load-balancer-pools-patch-pool",
        update_id: "account-load-balancer-pools-update-pool",
        collection_path: "/accounts/{account_id}/load_balancers/pools",
        detail_path: "/accounts/{account_id}/load_balancers/pools/{pool_id}",
        product: "Account Load Balancer Pools",
        permission: "Load Balancing: Monitors and Pools Write",
        kind: LoadBalancingConfigurationKind::MonitorOrPool,
    },
    LoadBalancingConfigurationContract {
        create_id: "load-balancer-monitors-create-monitor",
        patch_id: "load-balancer-monitors-patch-monitor",
        update_id: "load-balancer-monitors-update-monitor",
        collection_path: "/user/load_balancers/monitors",
        detail_path: "/user/load_balancers/monitors/{monitor_id}",
        product: "Load Balancer Monitors",
        permission: "Load Balancing: Monitors and Pools Write",
        kind: LoadBalancingConfigurationKind::MonitorOrPool,
    },
    LoadBalancingConfigurationContract {
        create_id: "load-balancer-pools-create-pool",
        patch_id: "load-balancer-pools-patch-pool",
        update_id: "load-balancer-pools-update-pool",
        collection_path: "/user/load_balancers/pools",
        detail_path: "/user/load_balancers/pools/{pool_id}",
        product: "Load Balancer Pools",
        permission: "Load Balancing: Monitors and Pools Write",
        kind: LoadBalancingConfigurationKind::MonitorOrPool,
    },
    LoadBalancingConfigurationContract {
        create_id: "account-load-balancers-create-account-load-balancer",
        patch_id: "account-load-balancers-patch-account-load-balancer",
        update_id: "account-load-balancers-update-account-load-balancer",
        collection_path: "/accounts/{account_id}/load_balancers",
        detail_path: "/accounts/{account_id}/load_balancers/{load_balancer_id}",
        product: "Account Load Balancers",
        permission: "Load Balancers Account Write",
        kind: LoadBalancingConfigurationKind::LoadBalancer,
    },
    LoadBalancingConfigurationContract {
        create_id: "load-balancers-create-load-balancer",
        patch_id: "load-balancers-patch-load-balancer",
        update_id: "load-balancers-update-load-balancer",
        collection_path: "/zones/{zone_id}/load_balancers",
        detail_path: "/zones/{zone_id}/load_balancers/{load_balancer_id}",
        product: "Load Balancers",
        permission: "Load Balancers Write",
        kind: LoadBalancingConfigurationKind::LoadBalancer,
    },
];

fn load_balancing_configuration_kind(
    capability: &CapabilityV1,
) -> Option<LoadBalancingConfigurationKind> {
    LOAD_BALANCING_CONFIGURATION_CONTRACTS
        .iter()
        .find(|contract| {
            let route_matches = if capability.id == contract.create_id {
                capability.method == "POST" && capability.path == contract.collection_path
            } else if capability.id == contract.patch_id {
                capability.method == "PATCH" && capability.path == contract.detail_path
            } else if capability.id == contract.update_id {
                capability.method == "PUT" && capability.path == contract.detail_path
            } else {
                false
            };
            route_matches
                && capability.product == contract.product
                && capability.permissions.len() == 1
                && capability.permissions[0] == contract.permission
        })
        .map(|contract| contract.kind)
}

fn classify_load_balancing_configuration(
    capability: &mut CapabilityV1,
    kind: LoadBalancingConfigurationKind,
) {
    capability.cost.billing_model = BillingModelV1::UsageBased;
    capability.cost.exposure = CostExposureV1::DownstreamUsage;
    capability.cost.references = vec![
        KnowledgeReferenceV1 {
            title: "Enable Load Balancing".to_owned(),
            url: "https://developers.cloudflare.com/load-balancing/get-started/enable-load-balancing/"
                .to_owned(),
            source: "official Cloudflare docs".to_owned(),
        },
        KnowledgeReferenceV1 {
            title: "Load Balancing quickstart".to_owned(),
            url: "https://developers.cloudflare.com/load-balancing/get-started/quickstart/"
                .to_owned(),
            source: "official Cloudflare docs".to_owned(),
        },
        KnowledgeReferenceV1 {
            title: "Load Balancing quota errors".to_owned(),
            url: "https://developers.cloudflare.com/load-balancing/troubleshooting/common-error-codes/"
                .to_owned(),
            source: "official Cloudflare docs".to_owned(),
        },
    ];
    capability.entitlement.available = None;
    capability.entitlement.plans.clear();
    capability.entitlement.blocker = Some(
        "paid account add-on entitlement is unresolved because the official API contract does not publish an exact product-scoped subscription join key for Load Balancing on the selected account"
            .to_owned(),
    );
    capability.entitlement.source = Some(
        "https://developers.cloudflare.com/load-balancing/get-started/enable-load-balancing/"
            .to_owned(),
    );
    capability.entitlement.requires_live_resolution = false;

    match kind {
        LoadBalancingConfigurationKind::MonitorOrPool => {
            capability.risk = RiskClass::CrossConfig;
            capability.effect = EffectClass::ReversibleWrite;
            capability.cost.incremental = false;
            capability.cost.currency = None;
            capability.cost.maximum = Some(0.0);
            capability.cost.known = true;
            capability.cost.basis = Some(
                "creating or updating a monitor or pool does not purchase or upgrade the paid add-on and Cloudflare rejects objects beyond the account quota; referenced pools can reroute traffic and attached monitors can generate health-probe traffic under the existing usage-based subscription"
                    .to_owned(),
            );
        }
        LoadBalancingConfigurationKind::LoadBalancer => {
            capability.risk = RiskClass::Spend;
            capability.effect = EffectClass::Spend;
            capability.cost.incremental = true;
            capability.cost.currency = None;
            capability.cost.maximum = None;
            capability.cost.known = false;
            capability.cost.basis = Some(
                "creating or updating a traffic-serving load balancer can add usage under the paid Load Balancing add-on; the request and account contract do not provide a hard monetary ceiling"
                    .to_owned(),
            );
        }
    }
    capability.verification.required = true;
    "post_change_read_or_operation_specific_verifier"
        .clone_into(&mut capability.verification.strategy);
}

struct EmailSecuritySettingsConfigurationContract {
    create_id: &'static str,
    update_id: &'static str,
    collection_path: &'static str,
    detail_path: &'static str,
}

const EMAIL_SECURITY_SETTINGS_CONFIGURATION_CONTRACTS:
    &[EmailSecuritySettingsConfigurationContract] = &[
    EmailSecuritySettingsConfigurationContract {
        create_id: "email_security_create_allow_policy",
        update_id: "email_security_update_allow_policy",
        collection_path: "/accounts/{account_id}/email-security/settings/allow_policies",
        detail_path: "/accounts/{account_id}/email-security/settings/allow_policies/{policy_id}",
    },
    EmailSecuritySettingsConfigurationContract {
        create_id: "email_security_create_blocked_sender",
        update_id: "email_security_update_blocked_sender",
        collection_path: "/accounts/{account_id}/email-security/settings/block_senders",
        detail_path: "/accounts/{account_id}/email-security/settings/block_senders/{pattern_id}",
    },
    EmailSecuritySettingsConfigurationContract {
        create_id: "email_security_create_domains",
        update_id: "email_security_update_domain",
        collection_path: "/accounts/{account_id}/email-security/settings/domains",
        detail_path: "/accounts/{account_id}/email-security/settings/domains/{domain_id}",
    },
    EmailSecuritySettingsConfigurationContract {
        create_id: "email_security_create_impersonation_registry",
        update_id: "email_security_update_impersonation_registry",
        collection_path: "/accounts/{account_id}/email-security/settings/impersonation_registry",
        detail_path: "/accounts/{account_id}/email-security/settings/impersonation_registry/{impersonation_registry_id}",
    },
    EmailSecuritySettingsConfigurationContract {
        create_id: "email_security_create_sending_domain_restriction",
        update_id: "email_security_update_sending_domain_restriction",
        collection_path: "/accounts/{account_id}/email-security/settings/sending_domain_restrictions",
        detail_path: "/accounts/{account_id}/email-security/settings/sending_domain_restrictions/{sending_domain_restriction_id}",
    },
    EmailSecuritySettingsConfigurationContract {
        create_id: "email_security_create_trusted_domain",
        update_id: "email_security_update_trusted_domain",
        collection_path: "/accounts/{account_id}/email-security/settings/trusted_domains",
        detail_path: "/accounts/{account_id}/email-security/settings/trusted_domains/{trusted_domain_id}",
    },
    EmailSecuritySettingsConfigurationContract {
        create_id: "email_security_create_url_ignore_pattern",
        update_id: "email_security_update_url_ignore_pattern",
        collection_path: "/accounts/{account_id}/email-security/settings/url_ignore_patterns",
        detail_path: "/accounts/{account_id}/email-security/settings/url_ignore_patterns/{pattern_id}",
    },
];

fn is_email_security_settings_configuration(capability: &CapabilityV1) -> bool {
    EMAIL_SECURITY_SETTINGS_CONFIGURATION_CONTRACTS
        .iter()
        .any(|contract| {
            let route_matches = if capability.id == contract.create_id {
                capability.method == "POST" && capability.path == contract.collection_path
            } else if capability.id == contract.update_id {
                capability.method == "PATCH" && capability.path == contract.detail_path
            } else {
                false
            };
            route_matches
                && capability.product == "Email Security Settings"
                && capability.permissions.len() == 1
                && capability.permissions[0] == "Cloud Email Security: Write"
        })
}

fn classify_email_security_settings_configuration(capability: &mut CapabilityV1) {
    capability.risk = RiskClass::CrossConfig;
    capability.effect = EffectClass::ReversibleWrite;
    capability.verification.required = true;
    "post_change_read_or_operation_specific_verifier"
        .clone_into(&mut capability.verification.strategy);
    capability.cost = cfctl_core::CostV1::default();
    capability.cost.billing_model = BillingModelV1::Contract;
    capability.cost.exposure = CostExposureV1::AccountQuote;
    capability.cost.basis = Some(
        "this settings request does not purchase Email Security, add licensed inboxes, or change the account package, so its direct incremental ceiling is zero; protection continues under the account's separately negotiated Email Security contract"
            .to_owned(),
    );
    capability.cost.references = vec![
        KnowledgeReferenceV1 {
            title: "Zero Trust and SASE pricing".to_owned(),
            url: "https://www.cloudflare.com/plans/zero-trust-services/".to_owned(),
            source: "official Cloudflare pricing".to_owned(),
        },
        KnowledgeReferenceV1 {
            title: "Email Security detection settings".to_owned(),
            url: "https://developers.cloudflare.com/cloudflare-one/email-security/settings/detection-settings/"
                .to_owned(),
            source: "official Cloudflare docs".to_owned(),
        },
    ];
    capability.entitlement.available = None;
    capability.entitlement.plans.clear();
    capability.entitlement.blocker = Some(
        "paid Email Security add-on entitlement is unresolved because the official API contract does not publish an exact product-scoped subscription join key for the selected account"
            .to_owned(),
    );
    capability.entitlement.source =
        Some("https://www.cloudflare.com/plans/zero-trust-services/".to_owned());
    capability.entitlement.requires_live_resolution = false;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloudflareTunnelLifecycleKind {
    CreateRemoteManaged,
    UpdateName,
}

struct CloudflareTunnelLifecycleContract {
    id: &'static str,
    method: &'static str,
    path: &'static str,
    kind: CloudflareTunnelLifecycleKind,
}

const CLOUDFLARE_TUNNEL_LIFECYCLE_CONTRACTS: &[CloudflareTunnelLifecycleContract] = &[
    CloudflareTunnelLifecycleContract {
        id: "cloudflare-tunnel-create-a-cloudflare-tunnel",
        method: "POST",
        path: "/accounts/{account_id}/cfd_tunnel",
        kind: CloudflareTunnelLifecycleKind::CreateRemoteManaged,
    },
    CloudflareTunnelLifecycleContract {
        id: "cloudflare-tunnel-update-a-cloudflare-tunnel",
        method: "PATCH",
        path: "/accounts/{account_id}/cfd_tunnel/{tunnel_id}",
        kind: CloudflareTunnelLifecycleKind::UpdateName,
    },
];

fn cloudflare_tunnel_lifecycle_kind(
    capability: &CapabilityV1,
) -> Option<CloudflareTunnelLifecycleKind> {
    CLOUDFLARE_TUNNEL_LIFECYCLE_CONTRACTS
        .iter()
        .find(|contract| {
            capability.id == contract.id
                && capability.method == contract.method
                && capability.path == contract.path
                && capability.product == "Cloudflare Tunnel"
                && capability.permissions
                    == [
                        "Cloudflare One Connectors Write",
                        "Cloudflare One Connector: cloudflared Write",
                        "Cloudflare Tunnel Write",
                    ]
                && capability
                    .response_contract
                    .as_ref()
                    .is_some_and(|response| {
                        response.success_statuses == ["200"]
                            && response.success_media_types == ["application/json"]
                            && response.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
                    })
                && cloudflare_tunnel_request_contract_supported(capability, contract.kind)
        })
        .map(|contract| contract.kind)
}

fn cloudflare_tunnel_request_contract_supported(
    capability: &CapabilityV1,
    kind: CloudflareTunnelLifecycleKind,
) -> bool {
    let Some(schema) = capability.request_schema.as_ref() else {
        return false;
    };
    let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
        return false;
    };
    let string_field = |field: &str| {
        properties
            .get(field)
            .and_then(|field| field.get("type"))
            .and_then(Value::as_str)
            == Some("string")
    };
    let common_shape = schema.get("type").and_then(Value::as_str) == Some("object")
        && schema.get("x-cfctl-body-required").and_then(Value::as_bool) == Some(true)
        && string_field("name")
        && string_field("tunnel_secret");
    if !common_shape {
        return false;
    }
    match kind {
        CloudflareTunnelLifecycleKind::CreateRemoteManaged => {
            properties.len() == 3
                && schema.get("required") == Some(&serde_json::json!(["name"]))
                && string_field("config_src")
                && properties
                    .get("config_src")
                    .and_then(|field| field.get("enum"))
                    == Some(&serde_json::json!(["local", "cloudflare"]))
        }
        CloudflareTunnelLifecycleKind::UpdateName => {
            properties.len() == 2
                && schema
                    .get("required")
                    .and_then(Value::as_array)
                    .is_none_or(Vec::is_empty)
        }
    }
}

fn classify_cloudflare_tunnel_lifecycle(
    capability: &mut CapabilityV1,
    kind: CloudflareTunnelLifecycleKind,
) {
    capability.risk = RiskClass::CrossConfig;
    capability.effect = EffectClass::ReversibleWrite;
    capability.cost = cfctl_core::CostV1::default();
    capability.cost.exposure = CostExposureV1::DownstreamUsage;
    capability.cost.basis = Some(
        "creating or renaming a Cloudflare Tunnel has no direct per-operation charge; traffic, users, logs, and separately enabled Cloudflare One services can retain plan-specific downstream cost and limits"
            .to_owned(),
    );
    capability.cost.references = vec![
        KnowledgeReferenceV1 {
            title: "Cloudflare One plans and pricing".to_owned(),
            url: "https://www.cloudflare.com/plans/zero-trust-services/".to_owned(),
            source: "official Cloudflare pricing".to_owned(),
        },
        KnowledgeReferenceV1 {
            title: "Cloudflare One overview".to_owned(),
            url: "https://developers.cloudflare.com/cloudflare-one/".to_owned(),
            source: "official Cloudflare docs".to_owned(),
        },
        KnowledgeReferenceV1 {
            title: "Cloudflare One account limits".to_owned(),
            url: "https://developers.cloudflare.com/cloudflare-one/account-limits/".to_owned(),
            source: "official Cloudflare docs".to_owned(),
        },
        KnowledgeReferenceV1 {
            title: "Create a Cloudflare Tunnel".to_owned(),
            url: "https://developers.cloudflare.com/api/resources/zero_trust/subresources/tunnels/subresources/cloudflared/methods/create/"
                .to_owned(),
            source: "official Cloudflare API".to_owned(),
        },
    ];
    capability.entitlement.available = Some(true);
    capability.entitlement.plans = BTreeMap::from([
        ("zero_trust_free".to_owned(), true),
        ("zero_trust_pay_as_you_go".to_owned(), true),
        ("zero_trust_contract".to_owned(), true),
    ]);
    capability.entitlement.blocker = None;
    capability.entitlement.source =
        Some("https://developers.cloudflare.com/cloudflare-one/".to_owned());
    capability.entitlement.requires_live_resolution = false;
    capability.verification.required = true;
    "post_change_read_or_operation_specific_verifier"
        .clone_into(&mut capability.verification.strategy);

    capability.request_schema = Some(match kind {
        CloudflareTunnelLifecycleKind::CreateRemoteManaged => serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["config_src", "name"],
            "properties": {
                "config_src": {"type": "string", "enum": ["cloudflare"]},
                "name": {"type": "string"}
            },
            "x-cfctl-body-required": true
        }),
        CloudflareTunnelLifecycleKind::UpdateName => serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["name"],
            "properties": {"name": {"type": "string"}},
            "x-cfctl-body-required": true
        }),
    });
}

const CLOUDFLARE_TUNNEL_CONFIGURATION_MUTATION_CAPABILITY_ID: &str =
    "cloudflare-tunnel-configuration-put-configuration";
const CLOUDFLARE_TUNNEL_CONFIGURATION_READ_CAPABILITY_ID: &str =
    "cloudflare-tunnel-configuration-get-configuration";
const CLOUDFLARE_TUNNEL_CONFIGURATION_PATH: &str =
    "/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations";

fn cloudflare_tunnel_configuration_identity_supported(capability: &CapabilityV1) -> bool {
    capability.id == CLOUDFLARE_TUNNEL_CONFIGURATION_MUTATION_CAPABILITY_ID
        && capability.method == "PUT"
        && capability.path == CLOUDFLARE_TUNNEL_CONFIGURATION_PATH
        && capability.product == "Cloudflare Tunnel Configuration"
        && capability.account_scope == "account"
        && capability.permissions
            == [
                "Cloudflare One Connectors Write",
                "Cloudflare One Connector: cloudflared Write",
                "Cloudflare Tunnel Write",
            ]
        && capability.selectors.len() == 2
        && ["account_id", "tunnel_id"].iter().all(|name| {
            capability.selectors.iter().any(|selector| {
                selector.name == *name && selector.location == "path" && selector.required
            })
        })
        && capability
            .response_contract
            .as_ref()
            .is_some_and(|response| {
                response.success_statuses == ["200"]
                    && response.success_media_types == ["application/json"]
                    && response.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
            })
}

fn exact_schema_keys(schema: &Value, expected: &[&str]) -> bool {
    schema.as_object().is_some_and(|object| {
        object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
    })
}

fn exact_primitive_schema(schema: Option<&Value>, expected_type: &str) -> bool {
    schema.is_some_and(|schema| {
        exact_schema_keys(schema, &["type"])
            && schema.get("type").and_then(Value::as_str) == Some(expected_type)
    })
}

fn cloudflare_tunnel_origin_request_source_schema_supported(schema: &Value) -> bool {
    if !exact_schema_keys(schema, &["properties", "type"])
        || schema.get("type").and_then(Value::as_str) != Some("object")
    {
        return false;
    }
    let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
        return false;
    };
    let expected_fields = [
        "access",
        "caPool",
        "connectTimeout",
        "disableChunkedEncoding",
        "http2Origin",
        "httpHostHeader",
        "keepAliveConnections",
        "keepAliveTimeout",
        "matchSNItoHost",
        "noHappyEyeballs",
        "noTLSVerify",
        "originServerName",
        "proxyType",
        "tcpKeepAlive",
        "tlsTimeout",
    ];
    if properties.len() != expected_fields.len()
        || !expected_fields
            .iter()
            .all(|field| properties.contains_key(*field))
    {
        return false;
    }
    let Some(access) = properties.get("access") else {
        return false;
    };
    if !exact_schema_keys(access, &["properties", "required", "type"])
        || access.get("type").and_then(Value::as_str) != Some("object")
        || access.get("required") != Some(&serde_json::json!(["audTag", "teamName"]))
    {
        return false;
    }
    let Some(access_properties) = access.get("properties").and_then(Value::as_object) else {
        return false;
    };
    if access_properties.len() != 3
        || !["audTag", "required", "teamName"]
            .iter()
            .all(|field| access_properties.contains_key(*field))
        || !exact_primitive_schema(access_properties.get("required"), "boolean")
        || !exact_primitive_schema(access_properties.get("teamName"), "string")
    {
        return false;
    }
    let Some(audience_tags) = access_properties.get("audTag") else {
        return false;
    };
    if !exact_schema_keys(audience_tags, &["items", "type"])
        || audience_tags.get("type").and_then(Value::as_str) != Some("array")
        || !exact_primitive_schema(audience_tags.get("items"), "string")
    {
        return false;
    }
    [
        ("caPool", "string"),
        ("connectTimeout", "integer"),
        ("disableChunkedEncoding", "boolean"),
        ("http2Origin", "boolean"),
        ("httpHostHeader", "string"),
        ("keepAliveConnections", "integer"),
        ("keepAliveTimeout", "integer"),
        ("matchSNItoHost", "boolean"),
        ("noHappyEyeballs", "boolean"),
        ("noTLSVerify", "boolean"),
        ("originServerName", "string"),
        ("proxyType", "string"),
        ("tcpKeepAlive", "integer"),
        ("tlsTimeout", "integer"),
    ]
    .iter()
    .all(|(field, expected_type)| exact_primitive_schema(properties.get(*field), expected_type))
}

fn cloudflare_tunnel_configuration_source_schema_supported(schema: &Value) -> bool {
    if !exact_schema_keys(schema, &["properties", "type", "x-cfctl-body-required"])
        || schema.get("type").and_then(Value::as_str) != Some("object")
        || schema.get("x-cfctl-body-required").and_then(Value::as_bool) != Some(true)
    {
        return false;
    }
    let Some(root_properties) = schema.get("properties").and_then(Value::as_object) else {
        return false;
    };
    let Some(config) = root_properties
        .get("config")
        .filter(|_| root_properties.len() == 1)
    else {
        return false;
    };
    if !exact_schema_keys(config, &["properties", "type"])
        || config.get("type").and_then(Value::as_str) != Some("object")
    {
        return false;
    }
    let Some(config_properties) = config.get("properties").and_then(Value::as_object) else {
        return false;
    };
    if config_properties.len() != 2
        || !["ingress", "originRequest"]
            .iter()
            .all(|field| config_properties.contains_key(*field))
    {
        return false;
    }
    let Some(ingress) = config_properties.get("ingress") else {
        return false;
    };
    if !exact_schema_keys(ingress, &["items", "minItems", "type"])
        || ingress.get("type").and_then(Value::as_str) != Some("array")
        || ingress.get("minItems").and_then(Value::as_u64) != Some(1)
    {
        return false;
    }
    let Some(item) = ingress.get("items") else {
        return false;
    };
    if !exact_schema_keys(item, &["properties", "required", "type"])
        || item.get("type").and_then(Value::as_str) != Some("object")
        || item.get("required") != Some(&serde_json::json!(["hostname", "service"]))
    {
        return false;
    }
    let Some(item_properties) = item.get("properties").and_then(Value::as_object) else {
        return false;
    };
    item_properties.len() == 4
        && ["hostname", "originRequest", "path", "service"]
            .iter()
            .all(|field| item_properties.contains_key(*field))
        && exact_primitive_schema(item_properties.get("hostname"), "string")
        && exact_primitive_schema(item_properties.get("path"), "string")
        && exact_primitive_schema(item_properties.get("service"), "string")
        && item_properties.get("originRequest") == config_properties.get("originRequest")
        && config_properties
            .get("originRequest")
            .is_some_and(cloudflare_tunnel_origin_request_source_schema_supported)
}

fn cloudflare_tunnel_configuration_contract_supported(capability: &CapabilityV1) -> bool {
    cloudflare_tunnel_configuration_identity_supported(capability)
        && capability
            .request_schema
            .as_ref()
            .is_some_and(cloudflare_tunnel_configuration_source_schema_supported)
}

fn harden_cloudflare_tunnel_configuration_request_schema(schema: &mut Value) -> bool {
    let Some(root) = schema.as_object_mut() else {
        return false;
    };
    root.insert("required".to_owned(), serde_json::json!(["config"]));
    root.insert("additionalProperties".to_owned(), Value::Bool(false));
    let Some(config) = schema
        .pointer_mut("/properties/config")
        .and_then(Value::as_object_mut)
    else {
        return false;
    };
    config.insert("required".to_owned(), serde_json::json!(["ingress"]));
    config.insert("additionalProperties".to_owned(), Value::Bool(false));
    for pointer in [
        "/properties/config/properties/ingress/items",
        "/properties/config/properties/ingress/items/properties/originRequest",
        "/properties/config/properties/ingress/items/properties/originRequest/properties/access",
        "/properties/config/properties/originRequest",
        "/properties/config/properties/originRequest/properties/access",
    ] {
        let Some(object) = schema.pointer_mut(pointer).and_then(Value::as_object_mut) else {
            return false;
        };
        object.insert("additionalProperties".to_owned(), Value::Bool(false));
    }
    true
}

fn classify_cloudflare_tunnel_configuration(capability: &mut CapabilityV1) {
    let Some(request_schema) = capability.request_schema.as_mut() else {
        return;
    };
    if !harden_cloudflare_tunnel_configuration_request_schema(request_schema) {
        return;
    }
    capability.risk = RiskClass::CrossConfig;
    capability.effect = EffectClass::ReversibleWrite;
    capability.cost = cfctl_core::CostV1::default();
    capability.cost.exposure = CostExposureV1::DownstreamUsage;
    capability.cost.basis = Some(
        "replacing a remotely managed Tunnel configuration has no direct per-operation charge; exposed traffic, users, logs, Access applications, and separately enabled Cloudflare One services can retain plan-specific downstream cost and limits"
            .to_owned(),
    );
    capability.cost.references = vec![
        KnowledgeReferenceV1 {
            title: "Put Cloudflare Tunnel configuration".to_owned(),
            url: "https://developers.cloudflare.com/api/resources/zero_trust/subresources/tunnels/subresources/cloudflared/subresources/configurations/methods/update/"
                .to_owned(),
            source: "official Cloudflare API".to_owned(),
        },
        KnowledgeReferenceV1 {
            title: "Cloudflare Tunnel configuration".to_owned(),
            url: "https://developers.cloudflare.com/tunnel/configuration/".to_owned(),
            source: "official Cloudflare docs".to_owned(),
        },
        KnowledgeReferenceV1 {
            title: "Cloudflare One plans and pricing".to_owned(),
            url: "https://www.cloudflare.com/plans/zero-trust-services/".to_owned(),
            source: "official Cloudflare pricing".to_owned(),
        },
    ];
    capability.entitlement.available = Some(true);
    capability.entitlement.plans = BTreeMap::from([
        ("zero_trust_free".to_owned(), true),
        ("zero_trust_pay_as_you_go".to_owned(), true),
        ("zero_trust_contract".to_owned(), true),
    ]);
    capability.entitlement.blocker = None;
    capability.entitlement.source = Some("https://developers.cloudflare.com/tunnel/".to_owned());
    capability.entitlement.requires_live_resolution = false;
    capability.verification.required = true;
    "post_change_read_or_operation_specific_verifier"
        .clone_into(&mut capability.verification.strategy);
    capability.rollback.supported = false;
    capability.rollback.strategy = None;
    capability.rollback.warning = Some(
        "automatic restoration is unavailable unless cfctl binds the exact live pre-change Tunnel configuration; creating an initial configuration without prior state remains blocked from this reversible lane"
            .to_owned(),
    );
}

fn cloudflare_tunnel_configuration_hardened_request_supported(capability: &CapabilityV1) -> bool {
    let Some(schema) = capability.request_schema.as_ref() else {
        return false;
    };
    let mut source_shape = schema.clone();
    let Some(root) = source_shape.as_object_mut() else {
        return false;
    };
    if root.remove("required") != Some(serde_json::json!(["config"]))
        || root.remove("additionalProperties") != Some(Value::Bool(false))
    {
        return false;
    }
    let Some(config) = source_shape
        .pointer_mut("/properties/config")
        .and_then(Value::as_object_mut)
    else {
        return false;
    };
    if config.remove("required") != Some(serde_json::json!(["ingress"]))
        || config.remove("additionalProperties") != Some(Value::Bool(false))
    {
        return false;
    }
    for pointer in [
        "/properties/config/properties/ingress/items",
        "/properties/config/properties/ingress/items/properties/originRequest",
        "/properties/config/properties/ingress/items/properties/originRequest/properties/access",
        "/properties/config/properties/originRequest",
        "/properties/config/properties/originRequest/properties/access",
    ] {
        let Some(object) = source_shape
            .pointer_mut(pointer)
            .and_then(Value::as_object_mut)
        else {
            return false;
        };
        if object.remove("additionalProperties") != Some(Value::Bool(false)) {
            return false;
        }
    }
    cloudflare_tunnel_configuration_source_schema_supported(&source_shape)
}

fn cloudflare_tunnel_configuration_read_contract_supported(capability: &CapabilityV1) -> bool {
    capability.id == CLOUDFLARE_TUNNEL_CONFIGURATION_READ_CAPABILITY_ID
        && capability.method == "GET"
        && capability.path == CLOUDFLARE_TUNNEL_CONFIGURATION_PATH
        && capability.product == "Cloudflare Tunnel Configuration"
        && capability.account_scope == "account"
        && !capability.mutating
        && capability.request_schema.is_none()
        && capability.permissions
            == [
                "Cloudflare One Connectors Write",
                "Cloudflare One Connectors Read",
                "Cloudflare One Connector: cloudflared Write",
                "Cloudflare One Connector: cloudflared Read",
                "Cloudflare Tunnel Write",
                "Cloudflare Tunnel Read",
            ]
        && capability.selectors.len() == 2
        && ["account_id", "tunnel_id"].iter().all(|name| {
            capability.selectors.iter().any(|selector| {
                selector.name == *name && selector.location == "path" && selector.required
            })
        })
        && capability
            .response_contract
            .as_ref()
            .is_some_and(|response| {
                response.success_statuses == ["200"]
                    && response.success_media_types == ["application/json"]
                    && response.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
            })
}

fn finalize_cloudflare_tunnel_configuration_rollback_contract(
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    let source_supported = capabilities
        .get(CLOUDFLARE_TUNNEL_CONFIGURATION_READ_CAPABILITY_ID)
        .is_some_and(cloudflare_tunnel_configuration_read_contract_supported);
    let Some(capability) =
        capabilities.get_mut(CLOUDFLARE_TUNNEL_CONFIGURATION_MUTATION_CAPABILITY_ID)
    else {
        return;
    };
    if !cloudflare_tunnel_configuration_identity_supported(capability)
        || !cloudflare_tunnel_configuration_hardened_request_supported(capability)
    {
        return;
    }
    if !source_supported {
        capability.risk = RiskClass::Unknown;
        capability.effect = EffectClass::Unknown;
        capability.cost.known = false;
        capability.cost.maximum = None;
        refresh_dynamic_mutation_contract(capability);
        return;
    }
    capability.rollback.supported = true;
    capability.rollback.strategy =
        Some("restore_cloudflare_tunnel_configuration_prior_snapshot".to_owned());
    if !capability.rollback_contract_supported() {
        capability.rollback.supported = false;
        capability.rollback.strategy = None;
        return;
    }
    capability.rollback.warning = Some(
        "rectification derives a separate hash-bound Tunnel configuration PUT plan from the exact prior routing snapshot; it never runs automatically and requires explicit approval"
            .to_owned(),
    );
    refresh_dynamic_mutation_contract(capability);
}

const WARP_CONNECTOR_CONFIGURATION_MUTATION_CAPABILITY_ID: &str =
    "cloudflare-tunnel-configuration-update-warp-connector-configuration";
const WARP_CONNECTOR_CONFIGURATION_READ_CAPABILITY_ID: &str =
    "cloudflare-tunnel-configuration-get-warp-connector-configuration";
const WARP_CONNECTOR_CONFIGURATION_PATH: &str =
    "/accounts/{account_id}/warp_connector/{tunnel_id}/configurations";

fn warp_connector_configuration_identity_supported(capability: &CapabilityV1) -> bool {
    capability.id == WARP_CONNECTOR_CONFIGURATION_MUTATION_CAPABILITY_ID
        && capability.method == "PUT"
        && capability.path == WARP_CONNECTOR_CONFIGURATION_PATH
        && capability.product == "Cloudflare Tunnel Configuration"
        && capability.account_scope == "account"
        && capability.permissions
            == [
                "Cloudflare One Connectors Write",
                "Cloudflare One Connector: WARP Write",
            ]
        && capability.selectors.len() == 2
        && ["account_id", "tunnel_id"].iter().all(|name| {
            capability.selectors.iter().any(|selector| {
                selector.name == *name && selector.location == "path" && selector.required
            })
        })
        && capability
            .response_contract
            .as_ref()
            .is_some_and(|response| {
                response.success_statuses == ["200"]
                    && response.success_media_types == ["application/json"]
                    && response.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
            })
}

fn warp_connector_vip_array_source_schema_supported(schema: &Value, required: bool) -> bool {
    let expected_keys = if required {
        &["items", "maxItems", "minItems", "type"][..]
    } else {
        &["items", "maxItems", "type"][..]
    };
    if !exact_schema_keys(schema, expected_keys)
        || schema.get("type").and_then(Value::as_str) != Some("array")
        || schema.get("maxItems").and_then(Value::as_u64) != Some(8)
        || (required && schema.get("minItems").and_then(Value::as_u64) != Some(1))
    {
        return false;
    }
    let Some(item) = schema.get("items") else {
        return false;
    };
    if !exact_schema_keys(item, &["properties", "required", "type"])
        || item.get("type").and_then(Value::as_str) != Some("object")
        || item.get("required") != Some(&serde_json::json!(["address"]))
    {
        return false;
    }
    item.get("properties")
        .and_then(Value::as_object)
        .is_some_and(|properties| {
            properties.len() == 1 && exact_primitive_schema(properties.get("address"), "string")
        })
}

fn warp_connector_configuration_source_schema_supported(schema: &Value) -> bool {
    if !exact_schema_keys(
        schema,
        &["properties", "required", "type", "x-cfctl-body-required"],
    ) || schema.get("type").and_then(Value::as_str) != Some("object")
        || schema.get("required") != Some(&serde_json::json!(["ha_mode"]))
        || schema.get("x-cfctl-body-required").and_then(Value::as_bool) != Some(true)
    {
        return false;
    }
    let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
        return false;
    };
    if properties.len() != 2 {
        return false;
    }
    let Some(config) = properties.get("config") else {
        return false;
    };
    let Some(ha_mode) = properties.get("ha_mode") else {
        return false;
    };
    if !exact_schema_keys(ha_mode, &["enum", "type"])
        || ha_mode.get("type").and_then(Value::as_str) != Some("string")
        || ha_mode.get("enum") != Some(&serde_json::json!(["none", "disabled", "aws", "local"]))
        || !exact_schema_keys(config, &["nullable", "oneOf", "type"])
        || config.get("nullable").and_then(Value::as_bool) != Some(true)
        || config.get("type").and_then(Value::as_str) != Some("object")
    {
        return false;
    }
    let Some(branches) = config.get("oneOf").and_then(Value::as_array) else {
        return false;
    };
    if branches.len() != 3 {
        return false;
    }
    let aws = &branches[0];
    let local = &branches[1];
    let empty = &branches[2];
    let aws_supported = exact_schema_keys(aws, &["properties", "required", "type"])
        && aws.get("type").and_then(Value::as_str) == Some("object")
        && aws.get("required") == Some(&serde_json::json!(["fnr_id"]))
        && aws
            .get("properties")
            .and_then(Value::as_object)
            .is_some_and(|properties| {
                properties.len() == 1 && exact_primitive_schema(properties.get("fnr_id"), "string")
            });
    let local_supported = exact_schema_keys(local, &["properties", "required", "type"])
        && local.get("type").and_then(Value::as_str) == Some("object")
        && local.get("required") == Some(&serde_json::json!(["vips"]))
        && local
            .get("properties")
            .and_then(Value::as_object)
            .is_some_and(|properties| {
                properties.len() == 2
                    && properties.get("vips").is_some_and(|schema| {
                        warp_connector_vip_array_source_schema_supported(schema, true)
                    })
                    && properties.get("vips_previous").is_some_and(|schema| {
                        warp_connector_vip_array_source_schema_supported(schema, false)
                    })
            });
    let empty_supported = exact_schema_keys(empty, &["additionalProperties", "type"])
        && empty.get("additionalProperties").and_then(Value::as_bool) == Some(false)
        && empty.get("type").and_then(Value::as_str) == Some("object");
    aws_supported && local_supported && empty_supported
}

fn warp_connector_configuration_contract_supported(capability: &CapabilityV1) -> bool {
    warp_connector_configuration_identity_supported(capability)
        && capability
            .request_schema
            .as_ref()
            .is_some_and(warp_connector_configuration_source_schema_supported)
}

fn harden_warp_connector_configuration_request_schema(schema: &mut Value) -> bool {
    for pointer in [
        "",
        "/properties/config/oneOf/0",
        "/properties/config/oneOf/1",
        "/properties/config/oneOf/1/properties/vips/items",
        "/properties/config/oneOf/1/properties/vips_previous/items",
    ] {
        let Some(object) = schema.pointer_mut(pointer).and_then(Value::as_object_mut) else {
            return false;
        };
        object.insert("additionalProperties".to_owned(), Value::Bool(false));
    }
    true
}

fn classify_warp_connector_configuration(capability: &mut CapabilityV1) {
    let Some(request_schema) = capability.request_schema.as_mut() else {
        return;
    };
    if !harden_warp_connector_configuration_request_schema(request_schema) {
        return;
    }
    capability.risk = RiskClass::CrossConfig;
    capability.effect = EffectClass::ReversibleWrite;
    capability.cost = cfctl_core::CostV1::default();
    capability.cost.exposure = CostExposureV1::DownstreamUsage;
    capability.cost.basis = Some(
        "updating Cloudflare Mesh high-availability configuration has no direct per-operation charge; routed Cloudflare One traffic and provider-side infrastructure such as AWS network interfaces can retain usage-based cost and plan limits"
            .to_owned(),
    );
    capability.cost.references = vec![
        KnowledgeReferenceV1 {
            title: "Update WARP Connector configuration".to_owned(),
            url: "https://developers.cloudflare.com/api/go/resources/zero_trust/subresources/tunnels/subresources/warp_connector/subresources/configurations/methods/update/"
                .to_owned(),
            source: "official Cloudflare API".to_owned(),
        },
        KnowledgeReferenceV1 {
            title: "Cloudflare Mesh high availability".to_owned(),
            url: "https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-mesh/high-availability/"
                .to_owned(),
            source: "official Cloudflare docs".to_owned(),
        },
        KnowledgeReferenceV1 {
            title: "Cloudflare One plans and pricing".to_owned(),
            url: "https://www.cloudflare.com/plans/zero-trust-services/".to_owned(),
            source: "official Cloudflare pricing".to_owned(),
        },
    ];
    capability.entitlement.available = Some(true);
    capability.entitlement.plans = BTreeMap::from([
        ("zero_trust_free".to_owned(), true),
        ("zero_trust_pay_as_you_go".to_owned(), true),
        ("zero_trust_contract".to_owned(), true),
    ]);
    capability.entitlement.blocker = None;
    capability.entitlement.source = Some(
        "https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-mesh/get-started/"
            .to_owned(),
    );
    capability.entitlement.requires_live_resolution = false;
    capability.verification.required = true;
    "post_change_read_or_operation_specific_verifier"
        .clone_into(&mut capability.verification.strategy);
    capability.rollback.supported = false;
    capability.rollback.strategy = None;
    capability.rollback.warning = Some(
        "automatic restoration is unavailable unless cfctl binds the exact live pre-change Cloudflare Mesh high-availability configuration"
            .to_owned(),
    );
}

fn warp_connector_configuration_hardened_request_supported(capability: &CapabilityV1) -> bool {
    let Some(schema) = capability.request_schema.as_ref() else {
        return false;
    };
    let mut source_shape = schema.clone();
    for pointer in [
        "",
        "/properties/config/oneOf/0",
        "/properties/config/oneOf/1",
        "/properties/config/oneOf/1/properties/vips/items",
        "/properties/config/oneOf/1/properties/vips_previous/items",
    ] {
        let Some(object) = source_shape
            .pointer_mut(pointer)
            .and_then(Value::as_object_mut)
        else {
            return false;
        };
        if object.remove("additionalProperties") != Some(Value::Bool(false)) {
            return false;
        }
    }
    warp_connector_configuration_source_schema_supported(&source_shape)
}

fn warp_connector_configuration_read_contract_supported(capability: &CapabilityV1) -> bool {
    capability.id == WARP_CONNECTOR_CONFIGURATION_READ_CAPABILITY_ID
        && capability.method == "GET"
        && capability.path == WARP_CONNECTOR_CONFIGURATION_PATH
        && capability.product == "Cloudflare Tunnel Configuration"
        && capability.account_scope == "account"
        && !capability.mutating
        && capability.request_schema.is_none()
        && capability.permissions
            == [
                "Cloudflare One Connectors Write",
                "Cloudflare One Connectors Read",
                "Cloudflare One Connector: WARP Write",
                "Cloudflare One Connector: WARP Read",
            ]
        && capability.selectors.len() == 2
        && ["account_id", "tunnel_id"].iter().all(|name| {
            capability.selectors.iter().any(|selector| {
                selector.name == *name && selector.location == "path" && selector.required
            })
        })
        && capability
            .response_contract
            .as_ref()
            .is_some_and(|response| {
                response.success_statuses == ["200"]
                    && response.success_media_types == ["application/json"]
                    && response.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
            })
}

fn finalize_warp_connector_configuration_rollback_contract(
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    let source_supported = capabilities
        .get(WARP_CONNECTOR_CONFIGURATION_READ_CAPABILITY_ID)
        .is_some_and(warp_connector_configuration_read_contract_supported);
    let Some(capability) =
        capabilities.get_mut(WARP_CONNECTOR_CONFIGURATION_MUTATION_CAPABILITY_ID)
    else {
        return;
    };
    if !warp_connector_configuration_identity_supported(capability)
        || !warp_connector_configuration_hardened_request_supported(capability)
    {
        return;
    }
    if !source_supported {
        capability.risk = RiskClass::Unknown;
        capability.effect = EffectClass::Unknown;
        capability.cost.known = false;
        capability.cost.maximum = None;
        refresh_dynamic_mutation_contract(capability);
        return;
    }
    capability.rollback.supported = true;
    capability.rollback.strategy =
        Some("restore_warp_connector_configuration_prior_snapshot".to_owned());
    if !capability.rollback_contract_supported() {
        capability.rollback.supported = false;
        capability.rollback.strategy = None;
        return;
    }
    capability.rollback.warning = Some(
        "rectification derives a separate hash-bound WARP Connector configuration PUT plan from the exact prior high-availability snapshot; it never runs automatically and requires explicit approval"
            .to_owned(),
    );
    refresh_dynamic_mutation_contract(capability);
}

const GENERIC_ZONE_SETTING_READ_CAPABILITY_ID: &str = "zone-settings-get-single-setting";
const GENERIC_ZONE_SETTING_MUTATION_CAPABILITY_ID: &str = "zone-settings-edit-single-setting";
const GENERIC_ZONE_SETTING_PATH: &str = "/zones/{zone_id}/settings/{setting_id}";
const WEBSOCKET_ZONE_SETTING_READ_CAPABILITY_ID: &str = "zone-settings-get-websockets-setting";
const WEBSOCKET_ZONE_SETTING_MUTATION_CAPABILITY_ID: &str = "zone-settings-configure-websockets";
const WEBSOCKET_ZONE_SETTING_PATH: &str = "/zones/{zone_id}/settings/websockets";
const WEBSOCKET_DOCS_URL: &str = "https://developers.cloudflare.com/network/websockets/";

fn websocket_zone_setting_response_supported(capability: &CapabilityV1) -> bool {
    capability
        .response_contract
        .as_ref()
        .is_some_and(|response| {
            response.success_statuses == ["200"]
                && response.success_media_types == ["application/json"]
                && response.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
        })
}

fn generic_zone_setting_selector_contract_supported(capability: &CapabilityV1) -> bool {
    capability.selectors.len() == 2
        && ["setting_id", "zone_id"].iter().all(|name| {
            capability.selectors.iter().any(|selector| {
                selector.name == *name
                    && selector.location == "path"
                    && selector.required
                    && selector.value_type == "string"
            })
        })
}

fn generic_zone_setting_read_contract_supported(capability: &CapabilityV1) -> bool {
    capability.id == GENERIC_ZONE_SETTING_READ_CAPABILITY_ID
        && capability.method == "GET"
        && capability.path == GENERIC_ZONE_SETTING_PATH
        && capability.product == "Zone Settings"
        && capability.account_scope == "zone"
        && !capability.mutating
        && capability.request_schema.is_none()
        && capability.permissions == ["Zone Settings Write", "Zone Settings Read"]
        && generic_zone_setting_selector_contract_supported(capability)
        && websocket_zone_setting_response_supported(capability)
}

fn generic_zone_setting_mutation_contract_supported(capability: &CapabilityV1) -> bool {
    capability.id == GENERIC_ZONE_SETTING_MUTATION_CAPABILITY_ID
        && capability.method == "PATCH"
        && capability.path == GENERIC_ZONE_SETTING_PATH
        && capability.product == "Zone Settings"
        && capability.account_scope == "zone"
        && capability.mutating
        && capability.request_schema.is_some()
        && capability.permissions == ["Zone Settings Write"]
        && generic_zone_setting_selector_contract_supported(capability)
        && websocket_zone_setting_response_supported(capability)
}

fn schema_union_contains_reference(
    document: &Value,
    schema_pointer: &str,
    reference: &str,
) -> bool {
    document
        .pointer(schema_pointer)
        .and_then(|schema| schema.get("oneOf"))
        .and_then(Value::as_array)
        .is_some_and(|members| {
            members
                .iter()
                .any(|member| member.get("$ref").and_then(Value::as_str) == Some(reference))
        })
}

fn exact_string_array(value: Option<&Value>, expected: &[&str]) -> bool {
    let Some(values) = value.and_then(Value::as_array) else {
        return false;
    };
    values.len() == expected.len()
        && values
            .iter()
            .map(Value::as_str)
            .collect::<Option<BTreeSet<_>>>()
            == Some(expected.iter().copied().collect())
}

fn websocket_value_schema_supported(document: &Value) -> bool {
    let Some(schema) = document.pointer("/components/schemas/zones_websockets_value") else {
        return false;
    };
    if schema.get("type").and_then(Value::as_str) != Some("string")
        || schema.get("default").and_then(Value::as_str) != Some("off")
    {
        return false;
    }
    exact_string_array(schema.get("enum"), &["off", "on"])
}

fn websocket_setting_schema_supported(document: &Value) -> bool {
    let Some(base) = document.pointer("/components/schemas/zones_base") else {
        return false;
    };
    let base_supported = exact_string_array(base.get("required"), &["id", "value"])
        && base
            .pointer("/properties/editable/type")
            .and_then(Value::as_str)
            == Some("boolean")
        && base.pointer("/properties/id/type").and_then(Value::as_str) == Some("string")
        && base.pointer("/properties/value").is_some();
    if !base_supported {
        return false;
    }
    let Some(schema) = document.pointer("/components/schemas/zones_websockets") else {
        return false;
    };
    let Some(members) = schema.get("allOf").and_then(Value::as_array) else {
        return false;
    };
    let websocket_uses_base = members.len() == 2
        && members.iter().any(|member| {
            member.get("$ref").and_then(Value::as_str) == Some("#/components/schemas/zones_base")
        });
    let websocket_fields_supported = members.iter().any(|member| {
        member.pointer("/properties/id/enum") == Some(&serde_json::json!(["websockets"]))
            && member
                .pointer("/properties/value/$ref")
                .and_then(Value::as_str)
                == Some("#/components/schemas/zones_websockets_value")
    });
    websocket_uses_base
        && websocket_fields_supported
        && schema_union_contains_reference(
            document,
            "/components/schemas/zones_setting",
            "#/components/schemas/zones_websockets",
        )
        && schema_union_contains_reference(
            document,
            "/components/schemas/zones_setting_value",
            "#/components/schemas/zones_websockets_value",
        )
        && websocket_value_schema_supported(document)
}

fn schema_contains_result_reference(schema: &Value, reference: &str, depth: usize) -> bool {
    if depth > 32 {
        return false;
    }
    schema
        .pointer("/properties/result/$ref")
        .and_then(Value::as_str)
        == Some(reference)
        || schema
            .get("allOf")
            .and_then(Value::as_array)
            .is_some_and(|members| {
                members
                    .iter()
                    .any(|member| schema_contains_result_reference(member, reference, depth + 1))
            })
}

fn operation_returns_zone_setting(operation: &Value) -> bool {
    operation
        .get("responses")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter(|(status, _)| status.starts_with('2'))
        .filter_map(|(_, response)| response.pointer("/content/application~1json/schema"))
        .any(|schema| {
            schema_contains_result_reference(schema, "#/components/schemas/zones_setting", 0)
        })
}

fn websocket_source_operations_supported(document: &Value) -> bool {
    let Some(path_item) = document
        .get("paths")
        .and_then(Value::as_object)
        .and_then(|paths| paths.get(GENERIC_ZONE_SETTING_PATH))
    else {
        return false;
    };
    let (Some(read), Some(update)) = (path_item.get("get"), path_item.get("patch")) else {
        return false;
    };
    update
        .pointer("/requestBody/required")
        .and_then(Value::as_bool)
        == Some(true)
        && update
            .pointer("/requestBody/content/application~1json/schema/$ref")
            .and_then(Value::as_str)
            == Some("#/components/schemas/zones_zone_settings_single_request")
        && operation_returns_zone_setting(read)
        && operation_returns_zone_setting(update)
        && websocket_setting_schema_supported(document)
}

fn websocket_all_plan_entitlement() -> EntitlementV1 {
    EntitlementV1 {
        available: Some(true),
        plans: BTreeMap::from([
            ("business".to_owned(), true),
            ("enterprise".to_owned(), true),
            ("free".to_owned(), true),
            ("pro".to_owned(), true),
        ]),
        blocker: None,
        source: Some(WEBSOCKET_DOCS_URL.to_owned()),
        requires_live_resolution: false,
        observed_plan: None,
        probe: None,
    }
}

fn derived_websocket_zone_setting_read(mut capability: CapabilityV1) -> CapabilityV1 {
    WEBSOCKET_ZONE_SETTING_READ_CAPABILITY_ID.clone_into(&mut capability.id);
    "Get WebSockets status".clone_into(&mut capability.title);
    capability.description = Some(
        "Reads the zone's WebSockets on/off setting through the exact WebSockets setting path."
            .to_owned(),
    );
    "Network".clone_into(&mut capability.product);
    WEBSOCKET_ZONE_SETTING_PATH.clone_into(&mut capability.path);
    capability
        .selectors
        .retain(|selector| selector.name == "zone_id" && selector.location == "path");
    capability.aliases = vec![
        "get websocket status".to_owned(),
        "show websockets setting".to_owned(),
        "read websocket configuration".to_owned(),
    ];
    capability.entitlement = websocket_all_plan_entitlement();
    capability.adapter_status = AdapterStatus::DynamicApi;
    capability.blocked_reason = None;
    capability
}

fn derived_websocket_zone_setting_update(mut capability: CapabilityV1) -> Option<CapabilityV1> {
    WEBSOCKET_ZONE_SETTING_MUTATION_CAPABILITY_ID.clone_into(&mut capability.id);
    "Configure WebSockets support".clone_into(&mut capability.title);
    capability.description = Some(
        "Enables or disables proxied WebSockets for one zone through the exact WebSockets setting path."
            .to_owned(),
    );
    "Network".clone_into(&mut capability.product);
    WEBSOCKET_ZONE_SETTING_PATH.clone_into(&mut capability.path);
    capability
        .selectors
        .retain(|selector| selector.name == "zone_id" && selector.location == "path");
    capability.aliases = vec![
        "support websockets".to_owned(),
        "enable websockets".to_owned(),
        "disable websockets".to_owned(),
        "turn websocket on off".to_owned(),
    ];
    capability.request_schema = Some(serde_json::json!({
        "additionalProperties": false,
        "properties": {
            "value": {"enum": ["on", "off"], "type": "string"}
        },
        "required": ["value"],
        "type": "object",
        "x-cfctl-body-required": true
    }));
    capability.risk = RiskClass::CrossConfig;
    capability.effect = EffectClass::ReversibleWrite;
    capability.entitlement = websocket_all_plan_entitlement();
    capability.cost = CostV1::default();
    capability.cost.billing_model = BillingModelV1::UsageBased;
    capability.cost.exposure = CostExposureV1::DownstreamUsage;
    capability.cost.basis = Some(
        "changing the setting has no direct operation charge; the initial WebSocket request and downstream traffic remain subject to the zone's usage and plan terms"
            .to_owned(),
    );
    capability.cost.references = vec![
        official_reference("Cloudflare WebSockets", WEBSOCKET_DOCS_URL),
        official_reference(
            "Edit zone setting",
            "https://developers.cloudflare.com/api/resources/zones/subresources/settings/methods/edit/",
        ),
    ];
    capability.verification.required = true;
    "same_path_result_contains_planned_fields_after_update"
        .clone_into(&mut capability.verification.strategy);
    capability.same_path_read = Some(SamePathReadContractV1 {
        path: WEBSOCKET_ZONE_SETTING_PATH.to_owned(),
        read_capability_id: WEBSOCKET_ZONE_SETTING_READ_CAPABILITY_ID.to_owned(),
        verified_response_fields: vec!["value".to_owned()],
    });
    capability.rollback.supported = true;
    capability.rollback.strategy = Some("restore_same_path_prior_snapshot".to_owned());
    capability.rollback.warning = Some(
        "cfctl captures and rechecks the exact prior WebSockets value before applying; rollback is a separately reviewed restoration plan"
            .to_owned(),
    );
    capability.adapter_status = AdapterStatus::DynamicApi;
    capability.blocked_reason = None;
    refresh_dynamic_mutation_contract(&mut capability);
    (capability.adapter_status == AdapterStatus::DynamicApi).then_some(capability)
}

/// Derive a literal `WebSockets` surface only while the generic official zone
/// setting path proves the exact `WebSockets` schema, permissions, and readback.
/// The generic mutation remains blocked so callers cannot select an arbitrary
/// setting id or smuggle another setting's request shape through this contract.
fn finalize_websocket_zone_setting_contract(
    document: &Value,
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    if capabilities.contains_key(WEBSOCKET_ZONE_SETTING_READ_CAPABILITY_ID)
        || capabilities.contains_key(WEBSOCKET_ZONE_SETTING_MUTATION_CAPABILITY_ID)
        || !websocket_source_operations_supported(document)
    {
        return;
    }
    let Some(source_read) = capabilities
        .get(GENERIC_ZONE_SETTING_READ_CAPABILITY_ID)
        .filter(|capability| generic_zone_setting_read_contract_supported(capability))
        .cloned()
    else {
        return;
    };
    let Some(source_update) = capabilities
        .get(GENERIC_ZONE_SETTING_MUTATION_CAPABILITY_ID)
        .filter(|capability| generic_zone_setting_mutation_contract_supported(capability))
        .cloned()
    else {
        return;
    };

    let read = derived_websocket_zone_setting_read(source_read);
    let Some(update) = derived_websocket_zone_setting_update(source_update) else {
        return;
    };

    capabilities.insert(WEBSOCKET_ZONE_SETTING_READ_CAPABILITY_ID.to_owned(), read);
    capabilities.insert(
        WEBSOCKET_ZONE_SETTING_MUTATION_CAPABILITY_ID.to_owned(),
        update,
    );
}

const WEB_ANALYTICS_RUM_MUTATION_CAPABILITY_ID: &str = "web-analytics-toggle-rum";
const WEB_ANALYTICS_RUM_READ_CAPABILITY_ID: &str = "web-analytics-get-rum-status";
const WEB_ANALYTICS_RUM_PATH: &str = "/zones/{zone_id}/settings/rum";

fn web_analytics_plan_availability_supported(capability: &CapabilityV1) -> bool {
    capability.entitlement.plans
        == BTreeMap::from([
            ("business".to_owned(), true),
            ("enterprise".to_owned(), true),
            ("free".to_owned(), true),
            ("pro".to_owned(), true),
        ])
}

fn web_analytics_rum_identity_supported(capability: &CapabilityV1) -> bool {
    capability.id == WEB_ANALYTICS_RUM_MUTATION_CAPABILITY_ID
        && capability.method == "PATCH"
        && capability.path == WEB_ANALYTICS_RUM_PATH
        && capability.product == "Web Analytics"
        && capability.account_scope == "zone"
        && capability.permissions == ["Zone Settings Write"]
        && capability.selectors.len() == 1
        && capability.selectors.iter().any(|selector| {
            selector.name == "zone_id"
                && selector.location == "path"
                && selector.required
                && selector.value_type == "string"
        })
        && web_analytics_plan_availability_supported(capability)
        && capability
            .response_contract
            .as_ref()
            .is_some_and(|response| {
                response.success_statuses == ["200"]
                    && response.success_media_types == ["application/json"]
                    && response.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
            })
}

fn web_analytics_rum_source_schema_supported(schema: &Value) -> bool {
    if !exact_schema_keys(schema, &["properties", "type", "x-cfctl-body-required"])
        || schema.get("type").and_then(Value::as_str) != Some("object")
        || schema.get("x-cfctl-body-required").and_then(Value::as_bool) != Some(true)
    {
        return false;
    }
    schema
        .get("properties")
        .and_then(Value::as_object)
        .is_some_and(|properties| {
            properties.len() == 1 && exact_primitive_schema(properties.get("value"), "string")
        })
}

fn web_analytics_rum_contract_supported(capability: &CapabilityV1) -> bool {
    web_analytics_rum_identity_supported(capability)
        && capability
            .request_schema
            .as_ref()
            .is_some_and(web_analytics_rum_source_schema_supported)
}

fn harden_web_analytics_rum_request_schema(schema: &mut Value) -> bool {
    let Some(root) = schema.as_object_mut() else {
        return false;
    };
    root.insert("additionalProperties".to_owned(), Value::Bool(false));
    root.insert("required".to_owned(), serde_json::json!(["value"]));
    let Some(value) = root
        .get_mut("properties")
        .and_then(Value::as_object_mut)
        .and_then(|properties| properties.get_mut("value"))
        .and_then(Value::as_object_mut)
    else {
        return false;
    };
    value.insert("enum".to_owned(), serde_json::json!(["on", "off"]));
    true
}

fn classify_web_analytics_rum(capability: &mut CapabilityV1) {
    let Some(request_schema) = capability.request_schema.as_mut() else {
        return;
    };
    if !harden_web_analytics_rum_request_schema(request_schema) {
        return;
    }
    capability.risk = RiskClass::CrossConfig;
    capability.effect = EffectClass::ReversibleWrite;
    capability.cost = cfctl_core::CostV1::default();
    capability.cost.basis = Some(
        "toggling Web Analytics RUM has no direct per-operation charge; Cloudflare documents Web Analytics as available on every plan"
            .to_owned(),
    );
    capability.cost.references = vec![
        KnowledgeReferenceV1 {
            title: "Web Analytics overview".to_owned(),
            url: "https://developers.cloudflare.com/web-analytics/".to_owned(),
            source: "official Cloudflare docs".to_owned(),
        },
        KnowledgeReferenceV1 {
            title: "Web Analytics configuration".to_owned(),
            url: "https://developers.cloudflare.com/web-analytics/get-started/".to_owned(),
            source: "official Cloudflare docs".to_owned(),
        },
        KnowledgeReferenceV1 {
            title: "Cloudflare public OpenAPI schema".to_owned(),
            url: "https://github.com/cloudflare/api-schemas/blob/main/openapi.json".to_owned(),
            source: "official Cloudflare API schema".to_owned(),
        },
    ];
    capability.entitlement.available = Some(true);
    capability.entitlement.blocker = None;
    capability.entitlement.source =
        Some("https://developers.cloudflare.com/web-analytics/".to_owned());
    capability.entitlement.requires_live_resolution = false;
    capability.verification.required = true;
    "post_change_read_or_operation_specific_verifier"
        .clone_into(&mut capability.verification.strategy);
    capability.rollback.supported = false;
    capability.rollback.strategy = None;
    capability.rollback.warning = Some(
        "automatic restoration is unavailable unless cfctl binds an editable on/off live RUM value; manual state cannot be restored by the toggle endpoint"
            .to_owned(),
    );
}

fn web_analytics_rum_hardened_request_supported(capability: &CapabilityV1) -> bool {
    let Some(schema) = capability.request_schema.as_ref() else {
        return false;
    };
    let mut source_shape = schema.clone();
    let Some(root) = source_shape.as_object_mut() else {
        return false;
    };
    if root.remove("additionalProperties") != Some(Value::Bool(false))
        || root.remove("required") != Some(serde_json::json!(["value"]))
    {
        return false;
    }
    let Some(value) = root
        .get_mut("properties")
        .and_then(Value::as_object_mut)
        .and_then(|properties| properties.get_mut("value"))
        .and_then(Value::as_object_mut)
    else {
        return false;
    };
    if value.remove("enum") != Some(serde_json::json!(["on", "off"])) {
        return false;
    }
    web_analytics_rum_source_schema_supported(&source_shape)
}

fn web_analytics_rum_read_contract_supported(document: &Value, capability: &CapabilityV1) -> bool {
    let response_fields_supported = document
        .get("paths")
        .and_then(Value::as_object)
        .and_then(|paths| paths.get(WEB_ANALYTICS_RUM_PATH))
        .and_then(|path| path.get("get"))
        .is_some_and(|operation| {
            success_response_declares_result_fields(
                document,
                operation,
                &["editable", "id", "value"],
            )
        });
    capability.id == WEB_ANALYTICS_RUM_READ_CAPABILITY_ID
        && capability.method == "GET"
        && capability.path == WEB_ANALYTICS_RUM_PATH
        && capability.product == "Web Analytics"
        && capability.account_scope == "zone"
        && !capability.mutating
        && capability.request_schema.is_none()
        && capability.permissions == ["Zone Settings Write", "Zone Settings Read"]
        && capability.selectors.len() == 1
        && capability.selectors.iter().any(|selector| {
            selector.name == "zone_id"
                && selector.location == "path"
                && selector.required
                && selector.value_type == "string"
        })
        && web_analytics_plan_availability_supported(capability)
        && response_fields_supported
        && capability
            .response_contract
            .as_ref()
            .is_some_and(|response| {
                response.success_statuses == ["200"]
                    && response.success_media_types == ["application/json"]
                    && response.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
            })
}

fn finalize_web_analytics_rum_rollback_contract(
    document: &Value,
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    let source_supported = capabilities
        .get(WEB_ANALYTICS_RUM_READ_CAPABILITY_ID)
        .is_some_and(|capability| web_analytics_rum_read_contract_supported(document, capability));
    let Some(capability) = capabilities.get_mut(WEB_ANALYTICS_RUM_MUTATION_CAPABILITY_ID) else {
        return;
    };
    if !web_analytics_rum_identity_supported(capability)
        || !web_analytics_rum_hardened_request_supported(capability)
    {
        return;
    }
    if !source_supported {
        capability.risk = RiskClass::Unknown;
        capability.effect = EffectClass::Unknown;
        capability.cost.known = false;
        capability.cost.maximum = None;
        refresh_dynamic_mutation_contract(capability);
        return;
    }
    capability.rollback.supported = true;
    capability.rollback.strategy = Some("restore_web_analytics_rum_prior_value".to_owned());
    if !capability.rollback_contract_supported() {
        capability.rollback.supported = false;
        capability.rollback.strategy = None;
        return;
    }
    capability.rollback.warning = Some(
        "rectification derives a separate hash-bound RUM PATCH plan from the exact prior on/off value; it never runs automatically and requires explicit approval"
            .to_owned(),
    );
    refresh_dynamic_mutation_contract(capability);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueueConfigurationKind {
    Create,
    Update,
    ConsumerCreate,
    ConsumerUpdate,
}

struct QueueConfigurationContract {
    id: &'static str,
    method: &'static str,
    path: &'static str,
    kind: QueueConfigurationKind,
}

const QUEUE_CONFIGURATION_CONTRACTS: &[QueueConfigurationContract] = &[
    QueueConfigurationContract {
        id: "queues-create",
        method: "POST",
        path: "/accounts/{account_id}/queues",
        kind: QueueConfigurationKind::Create,
    },
    QueueConfigurationContract {
        id: "queues-update",
        method: "PUT",
        path: "/accounts/{account_id}/queues/{queue_id}",
        kind: QueueConfigurationKind::Update,
    },
    QueueConfigurationContract {
        id: "queues-update-partial",
        method: "PATCH",
        path: "/accounts/{account_id}/queues/{queue_id}",
        kind: QueueConfigurationKind::Update,
    },
    QueueConfigurationContract {
        id: "queues-create-consumer",
        method: "POST",
        path: "/accounts/{account_id}/queues/{queue_id}/consumers",
        kind: QueueConfigurationKind::ConsumerCreate,
    },
    QueueConfigurationContract {
        id: "queues-update-consumer",
        method: "PUT",
        path: "/accounts/{account_id}/queues/{queue_id}/consumers/{consumer_id}",
        kind: QueueConfigurationKind::ConsumerUpdate,
    },
];

const ACCESS_APP_COLLECTION_PATH: &str = "/accounts/{account_id}/access/apps";
const ACCESS_APP_DETAIL_PATH: &str = "/accounts/{account_id}/access/apps/{app_id}";
const ACCESS_APP_UPDATE_REQUEST_SCHEMA_POINTER: &str = "/paths/~1accounts~1{account_id}~1access~1apps~1{app_id}/put/requestBody/content/application~1json/schema";
const ACCESS_APP_LOGIN_METHODS_CAPABILITY_ID: &str =
    "access-applications-update-self-hosted-login-methods";
const ACCESS_APP_LAUNCHER_LOGIN_METHODS_CAPABILITY_ID: &str =
    "access-applications-update-app-launcher-login-methods";
const ACCESS_APP_UPDATE_CAPABILITY_ID: &str = "access-applications-update-an-access-application";
const ACCESS_APP_READ_CAPABILITY_ID: &str = "access-applications-get-an-access-application";
const ACCESS_HUMAN_POLICY_UPDATE_CAPABILITY_ID: &str =
    "access-policies-update-human-access-controls";
const ACCESS_POLICY_UPDATE_CAPABILITY_ID: &str = "access-policies-update-an-access-policy";
const ACCESS_POLICY_READ_CAPABILITY_ID: &str = "access-policies-get-an-access-policy";
const ACCESS_POLICY_DETAIL_PATH: &str =
    "/accounts/{account_id}/access/apps/{app_id}/policies/{policy_id}";
const ACCESS_POLICY_UPDATE_REQUEST_SCHEMA_POINTER: &str = "/paths/~1accounts~1{account_id}~1access~1apps~1{app_id}~1policies~1{policy_id}/put/requestBody/content/application~1json/schema";

/// Exact Cloudflare Access identity-provider identifier renderings accepted by
/// the API: 32 hexadecimal characters or the canonical 36-character
/// hyphenated UUID form.
#[must_use]
pub fn access_identity_provider_id_schema() -> Value {
    serde_json::json!({
        "oneOf":[
            {
                "type":"string",
                "minLength":32,
                "maxLength":32,
                "format":"cloudflare-uuid",
                "pattern":"^[0-9A-Fa-f]{32}$"
            },
            {
                "type":"string",
                "minLength":36,
                "maxLength":36,
                "format":"cloudflare-uuid",
                "pattern":"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"
            }
        ]
    })
}

/// Complete provider body used internally when materializing a self-hosted
/// Access application login-method update.
#[must_use]
pub fn access_application_login_methods_materialized_schema() -> Value {
    serde_json::json!({
        "type":"object",
        "additionalProperties":false,
        "required":[
            "allowed_idps",
            "app_launcher_visible",
            "auto_redirect_to_identity",
            "destinations",
            "domain",
            "enable_binding_cookie",
            "http_only_cookie_attribute",
            "name",
            "options_preflight_bypass",
            "policies",
            "self_hosted_domains",
            "session_duration",
            "type"
        ],
        "properties":{
            "allowed_idps":{
                "type":"array",
                "minItems":1,
                "maxItems":25,
                "uniqueItems":true,
                "items":access_identity_provider_id_schema()
            },
            "app_launcher_visible":{"type":"boolean"},
            "auto_redirect_to_identity":{"type":"boolean"},
            "destinations":{
                "type":"array",
                "items":{
                    "type":"object",
                    "additionalProperties":false,
                    "required":["type","uri"],
                    "properties":{
                        "type":{"type":"string","enum":["public"]},
                        "uri":{"type":"string","minLength":1}
                    }
                }
            },
            "domain":{"type":"string","minLength":1},
            "eager_redirect_cookie_setting":{"type":"boolean"},
            "enable_binding_cookie":{"type":"boolean"},
            "http_only_cookie_attribute":{"type":"boolean"},
            "name":{"type":"string","minLength":1},
            "options_preflight_bypass":{"type":"boolean"},
            "path_cookie_attribute":{"type":"boolean"},
            "policies":{
                "type":"array",
                "minItems":1,
                "items":{
                    "type":"object",
                    "additionalProperties":false,
                    "required":["id","precedence"],
                    "properties":{
                        "id":{"type":"string","minLength":1,"maxLength":36},
                        "precedence":{"type":"integer","minimum":1}
                    }
                }
            },
            "same_site_cookie_attribute":{"type":"string"},
            "self_hosted_domains":{
                "type":"array",
                "uniqueItems":true,
                "items":{"type":"string","minLength":1}
            },
            "session_duration":{"type":"string","minLength":1},
            "tags":{
                "type":"array",
                "items":{"type":"string"}
            },
            "type":{"type":"string","enum":["self_hosted"]}
        },
        "x-cfctl-body-required":true
    })
}

fn access_app_launcher_login_methods_schema() -> Value {
    serde_json::json!({
        "type":"object",
        "additionalProperties":false,
        "required":[
            "allowed_idps",
            "auto_redirect_to_identity",
            "landing_page_design",
            "policies",
            "session_duration",
            "skip_app_launcher_login_page",
            "type"
        ],
        "properties":{
            "allowed_idps":{
                "type":"array",
                "minItems":1,
                "maxItems":25,
                "uniqueItems":true,
                "items":access_identity_provider_id_schema()
            },
            "app_launcher_logo_url":{"type":"string"},
            "auto_redirect_to_identity":{"type":"boolean"},
            "bg_color":{"type":"string"},
            "custom_deny_url":{"type":"string"},
            "custom_non_identity_deny_url":{"type":"string"},
            "custom_pages":{
                "type":"array",
                "uniqueItems":true,
                "items":{"type":"string","minLength":1}
            },
            "footer_links":{
                "type":"array",
                "items":{
                    "type":"object",
                    "additionalProperties":false,
                    "required":["name","url"],
                    "properties":{
                        "name":{"type":"string","minLength":1},
                        "url":{"type":"string","minLength":1}
                    }
                }
            },
            "header_bg_color":{"type":"string"},
            "landing_page_design":{
                "type":"object",
                "additionalProperties":false,
                "properties":{
                    "button_color":{"type":"string"},
                    "button_text_color":{"type":"string"},
                    "image_url":{"type":"string"},
                    "message":{"type":"string"},
                    "title":{"type":"string"}
                }
            },
            "policies":{
                "type":"array",
                "minItems":1,
                "items":{
                    "type":"object",
                    "additionalProperties":false,
                    "required":["id","precedence"],
                    "properties":{
                        "id":{"type":"string","minLength":1,"maxLength":36},
                        "precedence":{"type":"integer","minimum":1}
                    }
                }
            },
            "session_duration":{"type":"string","minLength":1},
            "skip_app_launcher_login_page":{"type":"boolean"},
            "type":{"type":"string","enum":["app_launcher"]}
        },
        "x-cfctl-body-required":true
    })
}

fn access_application_update_identity_supported(capability: &CapabilityV1) -> bool {
    capability.method == "PUT"
        && capability.path == ACCESS_APP_DETAIL_PATH
        && capability.product == "Access applications"
        && capability.account_scope == "account"
        && capability.permissions == ["Access: Apps and Policies Write"]
        && capability.selectors.len() == 2
        && ["account_id", "app_id"].iter().all(|name| {
            capability.selectors.iter().any(|selector| {
                selector.name == *name
                    && selector.location == "path"
                    && selector.required
                    && selector.value_type == "string"
            })
        })
        && capability
            .response_contract
            .as_ref()
            .is_some_and(|response| {
                response.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
                    && response.success_statuses == ["200"]
                    && response.success_media_types == ["application/json"]
            })
}

fn access_application_read_identity_supported(
    capabilities: &BTreeMap<String, CapabilityV1>,
) -> bool {
    capabilities
        .get(ACCESS_APP_READ_CAPABILITY_ID)
        .is_some_and(|read| {
            read.method == "GET"
                && read.path == ACCESS_APP_DETAIL_PATH
                && read.product == "Access applications"
                && !read.mutating
                && read.request_schema.is_none()
                && read.selectors.len() == 2
                && ["account_id", "app_id"].iter().all(|name| {
                    read.selectors.iter().any(|selector| {
                        selector.name == *name
                            && selector.location == "path"
                            && selector.required
                            && selector.value_type == "string"
                    })
                })
                && read.response_contract.as_ref().is_some_and(|response| {
                    response.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
                        && response.success_statuses == ["200"]
                        && response.success_media_types == ["application/json"]
                })
        })
}

fn access_application_missing_readback_fields(
    document: &Value,
    app_type: &str,
    verified_response_fields: &[String],
) -> Vec<String> {
    let read_operation =
        document.pointer("/paths/~1accounts~1{account_id}~1access~1apps~1{app_id}/get");
    read_operation.map_or_else(
        || verified_response_fields.to_vec(),
        |operation| {
            verified_response_fields
                .iter()
                .filter(|field| {
                    !success_response_declares_access_application_variant_field(
                        document, operation, app_type, field,
                    )
                })
                .cloned()
                .collect()
        },
    )
}

fn success_response_declares_access_application_variant_field(
    document: &Value,
    operation: &Value,
    app_type: &str,
    field: &str,
) -> bool {
    operation
        .get("responses")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter(|(status, _)| status.starts_with('2'))
        .filter_map(|(_, response)| response.pointer("/content/application~1json/schema"))
        .any(|schema| {
            access_application_response_declares_variant_field(document, schema, app_type, field, 0)
        })
}

fn access_application_response_declares_variant_field(
    document: &Value,
    schema: &Value,
    app_type: &str,
    field: &str,
    depth: usize,
) -> bool {
    if depth > 32 {
        return false;
    }
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        return reference
            .strip_prefix('#')
            .and_then(|pointer| document.pointer(pointer))
            .is_some_and(|resolved| {
                access_application_response_declares_variant_field(
                    document,
                    resolved,
                    app_type,
                    field,
                    depth + 1,
                )
            });
    }
    if let Some(result) = schema
        .get("properties")
        .and_then(Value::as_object)
        .and_then(|properties| properties.get("result"))
    {
        return access_application_result_variant_declares_field(
            document,
            result,
            app_type,
            field,
            depth + 1,
        );
    }
    schema
        .get("allOf")
        .and_then(Value::as_array)
        .is_some_and(|members| {
            members.iter().any(|member| {
                access_application_response_declares_variant_field(
                    document,
                    member,
                    app_type,
                    field,
                    depth + 1,
                )
            })
        })
}

fn access_application_result_variant_declares_field(
    document: &Value,
    schema: &Value,
    app_type: &str,
    field: &str,
    depth: usize,
) -> bool {
    if depth > 32 {
        return false;
    }
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        return reference
            .strip_prefix('#')
            .and_then(|pointer| document.pointer(pointer))
            .is_some_and(|resolved| {
                access_application_result_variant_declares_field(
                    document,
                    resolved,
                    app_type,
                    field,
                    depth + 1,
                )
            });
    }
    for composition in ["oneOf", "anyOf"] {
        if let Some(members) = schema.get(composition).and_then(Value::as_array) {
            let matching = members
                .iter()
                .filter(|member| {
                    access_application_schema_matches_type(document, member, app_type, depth + 1)
                })
                .collect::<Vec<_>>();
            let [matching] = matching.as_slice() else {
                return false;
            };
            return schema_declares_path(document, matching, &[field], depth + 1);
        }
    }
    schema_declares_path(document, schema, &[field], depth + 1)
}

fn access_application_schema_matches_type(
    document: &Value,
    schema: &Value,
    app_type: &str,
    depth: usize,
) -> bool {
    access_application_schema_type_annotation(document, schema, app_type, depth).unwrap_or(false)
}

fn access_application_schema_type_annotation(
    document: &Value,
    schema: &Value,
    app_type: &str,
    depth: usize,
) -> Option<bool> {
    if depth > 32 {
        return None;
    }
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        return reference
            .strip_prefix('#')
            .and_then(|pointer| document.pointer(pointer))
            .and_then(|resolved| {
                access_application_schema_type_annotation(document, resolved, app_type, depth + 1)
            });
    }
    if let Some(matches) = schema
        .get("properties")
        .and_then(Value::as_object)
        .and_then(|properties| properties.get("type"))
        .and_then(|type_schema| {
            access_application_type_schema_annotation(
                document,
                type_schema,
                app_type,
                depth + 1,
                true,
            )
        })
    {
        return Some(matches);
    }
    schema
        .get("allOf")
        .and_then(Value::as_array)
        .and_then(|members| {
            members.iter().rev().find_map(|member| {
                access_application_schema_type_annotation(document, member, app_type, depth + 1)
            })
        })
}

fn access_application_type_schema_annotation(
    document: &Value,
    schema: &Value,
    app_type: &str,
    depth: usize,
    allow_local_example: bool,
) -> Option<bool> {
    if depth > 32 {
        return None;
    }
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        return reference
            .strip_prefix('#')
            .and_then(|pointer| document.pointer(pointer))
            .and_then(|resolved| {
                access_application_type_schema_annotation(
                    document,
                    resolved,
                    app_type,
                    depth + 1,
                    false,
                )
            });
    }
    if let Some(constant) = schema.get("const") {
        return Some(constant.as_str() == Some(app_type));
    }
    if let Some(values) = schema.get("enum") {
        let values = values.as_array()?;
        if !values.iter().any(|value| value.as_str() == Some(app_type)) {
            return Some(false);
        }
        if values.len() == 1 {
            return Some(true);
        }
    }
    if allow_local_example && let Some(example) = schema.get("example") {
        return Some(example.as_str() == Some(app_type));
    }
    schema
        .get("allOf")
        .and_then(Value::as_array)
        .and_then(|members| {
            members.iter().rev().find_map(|member| {
                access_application_type_schema_annotation(
                    document,
                    member,
                    app_type,
                    depth + 1,
                    allow_local_example,
                )
            })
        })
}

/// Derives one narrow Access application update from the polymorphic generic
/// PUT. The runtime accepts only a desired non-empty `allowed_idps` set from
/// the caller, reads the exact live application variant, and materializes the
/// variant's closed full-body schema before a plan is persisted.
///
/// This keeps the generic 13-variant update blocked while restoring the v1
/// preservation invariant: read-only fields are dropped, policy objects are
/// reduced to `{id, precedence}`, and every other configured mutable field is
/// replayed and verified by the same-path GET.
struct AccessApplicationLoginMethodsContractSpec {
    capability_id: &'static str,
    app_type: &'static str,
    title: &'static str,
    description: &'static str,
    aliases: &'static [&'static str],
    request_schema: Value,
}

fn access_application_source_request_body_compatible(
    document: &Value,
    source_schema: &Value,
    curated_schema: &Value,
) -> bool {
    let Some(curated_properties) = curated_schema.get("properties").and_then(Value::as_object)
    else {
        return false;
    };
    let mut active_references = BTreeSet::new();
    curated_properties.keys().all(|field| {
        source_schema_declares_top_level_field(
            document,
            source_schema,
            field,
            0,
            &mut active_references,
        )
    }) && source_schema_accepts_curated(
        document,
        source_schema,
        curated_schema,
        0,
        &mut active_references,
    )
}

fn access_source_annotation_keyword(key: &str) -> bool {
    key.starts_with("x-")
        || matches!(
            key,
            "$comment"
                | "default"
                | "deprecated"
                | "description"
                | "discriminator"
                | "example"
                | "examples"
                | "externalDocs"
                | "readOnly"
                | "title"
                | "writeOnly"
                | "xml"
        )
}

fn access_source_schema_uses_supported_keywords(source: &Map<String, Value>) -> bool {
    source.keys().all(|key| {
        access_source_annotation_keyword(key)
            || matches!(
                key.as_str(),
                "type"
                    | "enum"
                    | "const"
                    | "format"
                    | "pattern"
                    | "nullable"
                    | "minimum"
                    | "maximum"
                    | "exclusiveMinimum"
                    | "exclusiveMaximum"
                    | "multipleOf"
                    | "minLength"
                    | "maxLength"
                    | "minItems"
                    | "maxItems"
                    | "uniqueItems"
                    | "items"
                    | "minProperties"
                    | "maxProperties"
                    | "required"
                    | "properties"
                    | "additionalProperties"
                    | "allOf"
                    | "oneOf"
                    | "anyOf"
            )
    })
}

fn access_source_reference_target<'a>(
    document: &'a Value,
    source: &'a Map<String, Value>,
) -> std::result::Result<Option<(String, &'a Value)>, ()> {
    let Some(reference) = source.get("$ref") else {
        return Ok(None);
    };
    if source
        .keys()
        .any(|key| key != "$ref" && !access_source_annotation_keyword(key))
    {
        return Err(());
    }
    let reference = reference.as_str().ok_or(())?;
    let pointer = reference
        .strip_prefix('#')
        .filter(|pointer| pointer.starts_with('/'))
        .ok_or(())?;
    let target = document.pointer(pointer).ok_or(())?;
    Ok(Some((reference.to_owned(), target)))
}

fn source_schema_declares_top_level_field(
    document: &Value,
    source_schema: &Value,
    field: &str,
    depth: usize,
    active_references: &mut BTreeSet<String>,
) -> bool {
    if depth >= MAX_REQUEST_SCHEMA_CONTRACT_DEPTH {
        return false;
    }
    let Some(source) = source_schema.as_object() else {
        return false;
    };
    let Ok(reference) = access_source_reference_target(document, source) else {
        return false;
    };
    if let Some((reference, target)) = reference {
        if !active_references.insert(reference.clone()) {
            return false;
        }
        let declared = source_schema_declares_top_level_field(
            document,
            target,
            field,
            depth + 1,
            active_references,
        );
        active_references.remove(&reference);
        return declared;
    }
    if !access_source_schema_uses_supported_keywords(source) {
        return false;
    }
    if source_schema
        .get("properties")
        .and_then(Value::as_object)
        .is_some_and(|properties| properties.contains_key(field))
    {
        return true;
    }
    ["allOf", "oneOf", "anyOf"].into_iter().any(|composition| {
        source_schema
            .get(composition)
            .and_then(Value::as_array)
            .is_some_and(|members| {
                !members.is_empty()
                    && members.iter().any(|member| {
                        source_schema_declares_top_level_field(
                            document,
                            member,
                            field,
                            depth + 1,
                            active_references,
                        )
                    })
            })
    })
}

fn source_schema_accepts_curated(
    document: &Value,
    source_schema: &Value,
    curated_schema: &Value,
    depth: usize,
    active_references: &mut BTreeSet<String>,
) -> bool {
    if depth >= MAX_REQUEST_SCHEMA_CONTRACT_DEPTH {
        return false;
    }
    let Some(source) = source_schema.as_object() else {
        return false;
    };
    let Ok(reference) = access_source_reference_target(document, source) else {
        return false;
    };
    if let Some((reference, target)) = reference {
        if !active_references.insert(reference.clone()) {
            return false;
        }
        let accepted = source_schema_accepts_curated(
            document,
            target,
            curated_schema,
            depth + 1,
            active_references,
        );
        active_references.remove(&reference);
        return accepted;
    }
    if !access_source_schema_uses_supported_keywords(source) {
        return false;
    }
    let Some(curated) = curated_schema.as_object() else {
        return false;
    };

    let curated_one_of = schema_composition_members(curated, "oneOf");
    let curated_any_of = schema_composition_members(curated, "anyOf");
    if curated_one_of.is_err()
        || curated_any_of.is_err()
        || (curated_one_of.as_ref().is_ok_and(Option::is_some)
            && curated_any_of.as_ref().is_ok_and(Option::is_some))
    {
        return false;
    }
    if let Some(members) = curated_one_of
        .ok()
        .flatten()
        .or_else(|| curated_any_of.ok().flatten())
    {
        return curated_composition_is_accepted(
            document,
            source_schema,
            curated,
            members,
            depth,
            active_references,
        );
    }
    if curated.get("allOf").is_some() {
        return false;
    }
    source_direct_constraints_accept_curated(document, source, curated, depth, active_references)
        && source_compositions_accept_curated(
            document,
            source,
            curated_schema,
            depth,
            active_references,
        )
}

fn curated_composition_is_accepted(
    document: &Value,
    source_schema: &Value,
    curated: &Map<String, Value>,
    members: &[Value],
    depth: usize,
    active_references: &mut BTreeSet<String>,
) -> bool {
    !members.is_empty()
        && !schema_has_direct_constraints(curated)
        && members.iter().all(|member| {
            source_schema_accepts_curated(
                document,
                source_schema,
                member,
                depth + 1,
                active_references,
            )
        })
}

fn source_compositions_accept_curated(
    document: &Value,
    source: &Map<String, Value>,
    curated_schema: &Value,
    depth: usize,
    active_references: &mut BTreeSet<String>,
) -> bool {
    let Ok(source_all_of) = schema_composition_members(source, "allOf") else {
        return false;
    };
    if source_all_of.is_some_and(|members| {
        members.is_empty()
            || !members.iter().all(|member| {
                source_schema_accepts_curated(
                    document,
                    member,
                    curated_schema,
                    depth + 1,
                    active_references,
                )
            })
    }) {
        return false;
    }

    let source_one_of = schema_composition_members(source, "oneOf");
    let source_any_of = schema_composition_members(source, "anyOf");
    if source_one_of.is_err()
        || source_any_of.is_err()
        || (source_one_of.as_ref().is_ok_and(Option::is_some)
            && source_any_of.as_ref().is_ok_and(Option::is_some))
    {
        return false;
    }
    if let Some(members) = source_one_of.ok().flatten() {
        return source_one_of_accepts_curated(
            document,
            members,
            curated_schema,
            depth + 1,
            active_references,
        );
    }
    source_any_of.ok().flatten().is_none_or(|members| {
        !members.is_empty()
            && members.iter().any(|member| {
                source_schema_accepts_curated(
                    document,
                    member,
                    curated_schema,
                    depth + 1,
                    active_references,
                )
            })
    })
}

fn source_one_of_accepts_curated(
    document: &Value,
    members: &[Value],
    curated_schema: &Value,
    depth: usize,
    active_references: &mut BTreeSet<String>,
) -> bool {
    if members.is_empty() {
        return false;
    }
    let mut accepting_member = None;
    for (index, member) in members.iter().enumerate() {
        if source_schema_accepts_curated(document, member, curated_schema, depth, active_references)
            && accepting_member.replace(index).is_some()
        {
            return false;
        }
    }
    let Some(accepting_member) = accepting_member else {
        return false;
    };
    members.iter().enumerate().all(|(index, member)| {
        index == accepting_member
            || source_schema_is_provably_disjoint(
                document,
                member,
                curated_schema,
                depth,
                active_references,
            )
    })
}

fn source_schema_is_provably_disjoint(
    document: &Value,
    source_schema: &Value,
    curated_schema: &Value,
    depth: usize,
    active_references: &mut BTreeSet<String>,
) -> bool {
    if depth >= MAX_REQUEST_SCHEMA_CONTRACT_DEPTH {
        return false;
    }
    let Some(source) = source_schema.as_object() else {
        return false;
    };
    let Ok(reference) = access_source_reference_target(document, source) else {
        return false;
    };
    if let Some((reference, target)) = reference {
        if !active_references.insert(reference.clone()) {
            return false;
        }
        let disjoint = source_schema_is_provably_disjoint(
            document,
            target,
            curated_schema,
            depth + 1,
            active_references,
        );
        active_references.remove(&reference);
        return disjoint;
    }
    if !access_source_schema_uses_supported_keywords(source) {
        return false;
    }
    let Some(curated) = curated_schema.as_object() else {
        return false;
    };

    if ["oneOf", "anyOf"]
        .into_iter()
        .any(|composition| curated.contains_key(composition))
    {
        return curated_union_compositions_prove_disjoint(
            document,
            source_schema,
            curated,
            depth,
            active_references,
        );
    }
    if let Some(members) = curated.get("allOf") {
        let Some(members) = members.as_array().filter(|members| !members.is_empty()) else {
            return false;
        };
        if curated_all_of_proves_disjoint(
            document,
            source_schema,
            members,
            depth,
            active_references,
        ) {
            return true;
        }
    }
    if !scalar_constraints_are_well_formed(source, curated) {
        return false;
    }
    if scalar_constraints_prove_disjoint(source, curated) {
        return true;
    }
    if source_union_composition_is_empty(source) {
        return false;
    }
    if source_compositions_prove_disjoint(
        document,
        source,
        curated_schema,
        depth,
        active_references,
    ) {
        return true;
    }
    required_object_property_proves_disjoint(document, source, curated, depth, active_references)
}

fn curated_union_compositions_prove_disjoint(
    document: &Value,
    source_schema: &Value,
    curated: &Map<String, Value>,
    depth: usize,
    active_references: &mut BTreeSet<String>,
) -> bool {
    for composition in ["oneOf", "anyOf"] {
        if let Some(members) = curated.get(composition) {
            let Some(members) = members.as_array().filter(|members| !members.is_empty()) else {
                return false;
            };
            return members.iter().all(|member| {
                source_schema_is_provably_disjoint(
                    document,
                    source_schema,
                    member,
                    depth + 1,
                    active_references,
                )
            });
        }
    }
    false
}

fn curated_all_of_proves_disjoint(
    document: &Value,
    source_schema: &Value,
    members: &[Value],
    depth: usize,
    active_references: &mut BTreeSet<String>,
) -> bool {
    members.iter().any(|member| {
        source_schema_is_provably_disjoint(
            document,
            source_schema,
            member,
            depth + 1,
            active_references,
        )
    })
}

fn scalar_constraints_are_well_formed(
    source: &Map<String, Value>,
    curated: &Map<String, Value>,
) -> bool {
    schema_possible_types(source).is_ok()
        && schema_possible_types(curated).is_ok()
        && schema_finite_values(source).is_ok()
        && schema_finite_values(curated).is_ok()
}

fn scalar_constraints_prove_disjoint(
    source: &Map<String, Value>,
    curated: &Map<String, Value>,
) -> bool {
    let (Ok(source_types), Ok(curated_types)) = (
        schema_possible_types(source),
        schema_possible_types(curated),
    ) else {
        return false;
    };
    if let (Some(source_types), Some(curated_types)) =
        (source_types.as_ref(), curated_types.as_ref())
        && !json_schema_type_sets_overlap(source_types, curated_types)
    {
        return true;
    }

    let (Ok(source_values), Ok(curated_values)) =
        (schema_finite_values(source), schema_finite_values(curated))
    else {
        return false;
    };
    matches!(
        (source_values.as_ref(), curated_values.as_ref()),
        (Some(source_values), Some(curated_values))
            if source_values
                .iter()
                .all(|source_value| !curated_values.contains(source_value))
    )
}

fn source_union_composition_is_empty(source: &Map<String, Value>) -> bool {
    ["oneOf", "anyOf"].into_iter().any(|composition| {
        matches!(
            schema_composition_members(source, composition),
            Ok(Some(members)) if members.is_empty()
        )
    })
}

fn source_compositions_prove_disjoint(
    document: &Value,
    source: &Map<String, Value>,
    curated_schema: &Value,
    depth: usize,
    active_references: &mut BTreeSet<String>,
) -> bool {
    if let Ok(Some(members)) = schema_composition_members(source, "allOf")
        && !members.is_empty()
        && members.iter().any(|member| {
            source_schema_is_provably_disjoint(
                document,
                member,
                curated_schema,
                depth + 1,
                active_references,
            )
        })
    {
        return true;
    }
    for composition in ["oneOf", "anyOf"] {
        if let Ok(Some(members)) = schema_composition_members(source, composition)
            && members.iter().all(|member| {
                source_schema_is_provably_disjoint(
                    document,
                    member,
                    curated_schema,
                    depth + 1,
                    active_references,
                )
            })
        {
            return true;
        }
    }
    false
}

fn required_object_property_proves_disjoint(
    document: &Value,
    source: &Map<String, Value>,
    curated: &Map<String, Value>,
    depth: usize,
    active_references: &mut BTreeSet<String>,
) -> bool {
    let Ok(curated_types) = schema_possible_types(curated) else {
        return false;
    };
    if curated_types
        .as_ref()
        .is_none_or(|types| types != &BTreeSet::from(["object".to_owned()]))
    {
        return false;
    }
    let (Ok(source_required), Ok(curated_required)) = (
        schema_required_fields(source),
        schema_required_fields(curated),
    ) else {
        return false;
    };
    let source_properties = match source.get("properties") {
        None => None,
        Some(Value::Object(properties)) => Some(properties),
        Some(_) => return false,
    };
    let curated_properties = match curated.get("properties") {
        None => None,
        Some(Value::Object(properties)) => Some(properties),
        Some(_) => return false,
    };
    let (Ok(source_additional), Ok(curated_additional)) = (
        schema_allowance(source.get("additionalProperties")),
        schema_allowance(curated.get("additionalProperties")),
    ) else {
        return false;
    };
    if source_required.iter().any(|field| {
        let source_property = source_properties
            .and_then(|properties| properties.get(field))
            .map_or(source_additional, SchemaAllowance::Schema);
        let curated_property = curated_properties
            .and_then(|properties| properties.get(field))
            .map_or(curated_additional, SchemaAllowance::Schema);
        match (source_property, curated_property) {
            (SchemaAllowance::Forbidden, _) | (_, SchemaAllowance::Forbidden) => true,
            (
                SchemaAllowance::Schema(source_property),
                SchemaAllowance::Schema(curated_property),
            ) => source_schema_is_provably_disjoint(
                document,
                source_property,
                curated_property,
                depth + 1,
                active_references,
            ),
            _ => false,
        }
    }) {
        return true;
    }
    curated_required.iter().any(|field| {
        let source_property = source_properties
            .and_then(|properties| properties.get(field))
            .map_or(source_additional, SchemaAllowance::Schema);
        let curated_property = curated_properties
            .and_then(|properties| properties.get(field))
            .map_or(curated_additional, SchemaAllowance::Schema);
        match (source_property, curated_property) {
            (SchemaAllowance::Forbidden, SchemaAllowance::Schema(_)) => true,
            (
                SchemaAllowance::Schema(source_property),
                SchemaAllowance::Schema(curated_property),
            ) => source_schema_is_provably_disjoint(
                document,
                source_property,
                curated_property,
                depth + 1,
                active_references,
            ),
            _ => false,
        }
    })
}

fn json_schema_type_sets_overlap(left: &BTreeSet<String>, right: &BTreeSet<String>) -> bool {
    left.iter().any(|left_type| {
        right.iter().any(|right_type| {
            left_type == right_type
                || matches!(
                    (left_type.as_str(), right_type.as_str()),
                    ("number", "integer") | ("integer", "number")
                )
        })
    })
}

fn schema_composition_members<'a>(
    schema: &'a Map<String, Value>,
    key: &str,
) -> std::result::Result<Option<&'a [Value]>, ()> {
    schema
        .get(key)
        .map(|value| value.as_array().map(Vec::as_slice).ok_or(()))
        .transpose()
}

fn schema_has_direct_constraints(schema: &Map<String, Value>) -> bool {
    [
        "type",
        "enum",
        "const",
        "format",
        "pattern",
        "nullable",
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "multipleOf",
        "minLength",
        "maxLength",
        "minItems",
        "maxItems",
        "uniqueItems",
        "minProperties",
        "maxProperties",
        "required",
        "properties",
        "additionalProperties",
        "items",
    ]
    .iter()
    .any(|key| schema.contains_key(*key))
}

fn source_direct_constraints_accept_curated(
    document: &Value,
    source: &Map<String, Value>,
    curated: &Map<String, Value>,
    depth: usize,
    active_references: &mut BTreeSet<String>,
) -> bool {
    let Ok(source_types) = schema_possible_types(source) else {
        return false;
    };
    let Ok(curated_types) = schema_possible_types(curated) else {
        return false;
    };
    if source_types.as_ref().is_some_and(|source_types| {
        curated_types.as_ref().is_none_or(|curated_types| {
            curated_types.iter().any(|curated_type| {
                !(source_types.contains(curated_type)
                    || curated_type == "integer" && source_types.contains("number"))
            })
        })
    }) {
        return false;
    }

    let Ok(source_values) = schema_finite_values(source) else {
        return false;
    };
    let Ok(curated_values) = schema_finite_values(curated) else {
        return false;
    };
    if source_values.as_ref().is_some_and(|source_values| {
        curated_values.as_ref().is_none_or(|curated_values| {
            curated_values
                .iter()
                .any(|curated_value| !source_values.contains(curated_value))
        })
    }) {
        return false;
    }

    let curated_may_be_string = schema_may_include_type(curated_types.as_ref(), "string");
    if curated_may_be_string
        && (!source_exact_constraint_accepts_curated(source, curated, "format")
            || !source_exact_constraint_accepts_curated(source, curated, "pattern")
            || !source_minimum_u64_accepts_curated(source, curated, "minLength")
            || !source_maximum_u64_accepts_curated(source, curated, "maxLength"))
    {
        return false;
    }

    let curated_may_be_number = schema_may_include_type(curated_types.as_ref(), "number")
        || schema_may_include_type(curated_types.as_ref(), "integer");
    if curated_may_be_number
        && (!source_numeric_lower_bound_accepts_curated(source, curated)
            || !source_numeric_upper_bound_accepts_curated(source, curated)
            || !source_exact_constraint_accepts_curated(source, curated, "multipleOf"))
    {
        return false;
    }

    let source_has_array_constraints = ["minItems", "maxItems", "uniqueItems", "items"]
        .iter()
        .any(|key| source.contains_key(*key));
    if source_has_array_constraints
        && schema_may_include_type(curated_types.as_ref(), "array")
        && !source_array_constraints_accept_curated(
            document,
            source,
            curated,
            depth,
            active_references,
        )
    {
        return false;
    }

    let source_has_object_constraints = [
        "minProperties",
        "maxProperties",
        "required",
        "properties",
        "additionalProperties",
    ]
    .iter()
    .any(|key| source.contains_key(*key));
    !source_has_object_constraints
        || !schema_may_include_type(curated_types.as_ref(), "object")
        || source_object_constraints_accept_curated(
            document,
            source,
            curated,
            depth,
            active_references,
        )
}

fn schema_possible_types(
    schema: &Map<String, Value>,
) -> std::result::Result<Option<BTreeSet<String>>, ()> {
    let mut types = match schema.get("type") {
        None => None,
        Some(Value::String(value)) => Some(BTreeSet::from([value.clone()])),
        Some(Value::Array(values)) if !values.is_empty() => {
            let types = values
                .iter()
                .map(Value::as_str)
                .collect::<Option<Vec<_>>>()
                .ok_or(())?;
            Some(types.into_iter().map(str::to_owned).collect())
        }
        Some(_) => return Err(()),
    };
    if let Some(nullable) = schema.get("nullable") {
        let nullable = nullable.as_bool().ok_or(())?;
        if nullable && let Some(types) = types.as_mut() {
            types.insert("null".to_owned());
        }
    }
    Ok(types)
}

fn schema_may_include_type(types: Option<&BTreeSet<String>>, expected: &str) -> bool {
    types.is_none_or(|types| types.contains(expected))
}

fn schema_finite_values(
    schema: &Map<String, Value>,
) -> std::result::Result<Option<Vec<&Value>>, ()> {
    let enumeration = schema
        .get("enum")
        .map(|value| {
            value
                .as_array()
                .filter(|values| !values.is_empty())
                .ok_or(())
        })
        .transpose()?;
    if let Some(constant) = schema.get("const") {
        if enumeration.is_some_and(|values| !values.contains(constant)) {
            return Err(());
        }
        return Ok(Some(vec![constant]));
    }
    Ok(enumeration.map(|values| values.iter().collect()))
}

fn source_exact_constraint_accepts_curated(
    source: &Map<String, Value>,
    curated: &Map<String, Value>,
    key: &str,
) -> bool {
    source
        .get(key)
        .is_none_or(|source_value| curated.get(key) == Some(source_value))
}

fn source_minimum_u64_accepts_curated(
    source: &Map<String, Value>,
    curated: &Map<String, Value>,
    key: &str,
) -> bool {
    let Some(source_minimum) = source.get(key) else {
        return true;
    };
    let Some(source_minimum) = source_minimum.as_u64() else {
        return false;
    };
    curated
        .get(key)
        .and_then(Value::as_u64)
        .is_some_and(|curated_minimum| curated_minimum >= source_minimum)
        || source_minimum == 0
}

fn source_maximum_u64_accepts_curated(
    source: &Map<String, Value>,
    curated: &Map<String, Value>,
    key: &str,
) -> bool {
    let Some(source_maximum) = source.get(key) else {
        return true;
    };
    let Some(source_maximum) = source_maximum.as_u64() else {
        return false;
    };
    curated
        .get(key)
        .and_then(Value::as_u64)
        .is_some_and(|curated_maximum| curated_maximum <= source_maximum)
}

fn schema_numeric_lower_bound(
    schema: &Map<String, Value>,
) -> std::result::Result<Option<(f64, bool)>, ()> {
    let minimum = schema
        .get("minimum")
        .map(|value| value.as_f64().ok_or(()))
        .transpose()?;
    let exclusive = match schema.get("exclusiveMinimum") {
        None | Some(Value::Bool(false)) => None,
        Some(Value::Bool(true)) => Some((minimum.ok_or(())?, true)),
        Some(value) => Some((value.as_f64().ok_or(())?, true)),
    };
    Ok(stricter_numeric_lower_bound(
        minimum.map(|minimum| (minimum, false)),
        exclusive,
    ))
}

fn schema_numeric_upper_bound(
    schema: &Map<String, Value>,
) -> std::result::Result<Option<(f64, bool)>, ()> {
    let maximum = schema
        .get("maximum")
        .map(|value| value.as_f64().ok_or(()))
        .transpose()?;
    let exclusive = match schema.get("exclusiveMaximum") {
        None | Some(Value::Bool(false)) => None,
        Some(Value::Bool(true)) => Some((maximum.ok_or(())?, true)),
        Some(value) => Some((value.as_f64().ok_or(())?, true)),
    };
    Ok(stricter_numeric_upper_bound(
        maximum.map(|maximum| (maximum, false)),
        exclusive,
    ))
}

fn stricter_numeric_lower_bound(
    left: Option<(f64, bool)>,
    right: Option<(f64, bool)>,
) -> Option<(f64, bool)> {
    match (left, right) {
        (None, bound) | (bound, None) => bound,
        (Some((left, left_exclusive)), Some((right, right_exclusive))) => {
            if left > right {
                Some((left, left_exclusive))
            } else if right > left {
                Some((right, right_exclusive))
            } else {
                Some((left, left_exclusive || right_exclusive))
            }
        }
    }
}

fn stricter_numeric_upper_bound(
    left: Option<(f64, bool)>,
    right: Option<(f64, bool)>,
) -> Option<(f64, bool)> {
    match (left, right) {
        (None, bound) | (bound, None) => bound,
        (Some((left, left_exclusive)), Some((right, right_exclusive))) => {
            if left < right {
                Some((left, left_exclusive))
            } else if right < left {
                Some((right, right_exclusive))
            } else {
                Some((left, left_exclusive || right_exclusive))
            }
        }
    }
}

fn source_numeric_lower_bound_accepts_curated(
    source: &Map<String, Value>,
    curated: &Map<String, Value>,
) -> bool {
    let (Ok(source), Ok(curated)) = (
        schema_numeric_lower_bound(source),
        schema_numeric_lower_bound(curated),
    ) else {
        return false;
    };
    source.is_none_or(|(source_value, source_exclusive)| {
        curated.is_some_and(|(curated_value, curated_exclusive)| {
            match curated_value.partial_cmp(&source_value) {
                Some(std::cmp::Ordering::Greater) => true,
                Some(std::cmp::Ordering::Equal) => !source_exclusive || curated_exclusive,
                Some(std::cmp::Ordering::Less) | None => false,
            }
        })
    })
}

fn source_numeric_upper_bound_accepts_curated(
    source: &Map<String, Value>,
    curated: &Map<String, Value>,
) -> bool {
    let (Ok(source), Ok(curated)) = (
        schema_numeric_upper_bound(source),
        schema_numeric_upper_bound(curated),
    ) else {
        return false;
    };
    source.is_none_or(|(source_value, source_exclusive)| {
        curated.is_some_and(|(curated_value, curated_exclusive)| {
            match curated_value.partial_cmp(&source_value) {
                Some(std::cmp::Ordering::Less) => true,
                Some(std::cmp::Ordering::Equal) => !source_exclusive || curated_exclusive,
                Some(std::cmp::Ordering::Greater) | None => false,
            }
        })
    })
}

fn source_array_constraints_accept_curated(
    document: &Value,
    source: &Map<String, Value>,
    curated: &Map<String, Value>,
    depth: usize,
    active_references: &mut BTreeSet<String>,
) -> bool {
    if !source_minimum_u64_accepts_curated(source, curated, "minItems")
        || !source_maximum_u64_accepts_curated(source, curated, "maxItems")
    {
        return false;
    }
    if curated.get("maxItems").and_then(Value::as_u64) == Some(0) {
        return true;
    }
    if let Some(unique) = source.get("uniqueItems") {
        let Some(unique) = unique.as_bool() else {
            return false;
        };
        if unique && curated.get("uniqueItems").and_then(Value::as_bool) != Some(true) {
            return false;
        }
    }
    match source.get("items") {
        None | Some(Value::Bool(true)) => true,
        Some(Value::Bool(false)) => false,
        Some(source_items) if source_items.is_object() => {
            curated.get("items").is_some_and(|curated_items| {
                curated_items.is_object()
                    && source_schema_accepts_curated(
                        document,
                        source_items,
                        curated_items,
                        depth + 1,
                        active_references,
                    )
            })
        }
        Some(_) => false,
    }
}

#[derive(Clone, Copy)]
enum SchemaAllowance<'a> {
    Any,
    Forbidden,
    Schema(&'a Value),
}

fn schema_allowance(value: Option<&Value>) -> std::result::Result<SchemaAllowance<'_>, ()> {
    match value {
        None | Some(Value::Bool(true)) => Ok(SchemaAllowance::Any),
        Some(Value::Bool(false)) => Ok(SchemaAllowance::Forbidden),
        Some(value) if value.is_object() => Ok(SchemaAllowance::Schema(value)),
        Some(_) => Err(()),
    }
}

fn source_allowance_accepts_curated(
    document: &Value,
    source: SchemaAllowance<'_>,
    curated: SchemaAllowance<'_>,
    depth: usize,
    active_references: &mut BTreeSet<String>,
) -> bool {
    match (source, curated) {
        (SchemaAllowance::Any, _) | (_, SchemaAllowance::Forbidden) => true,
        (SchemaAllowance::Forbidden, _) | (SchemaAllowance::Schema(_), SchemaAllowance::Any) => {
            false
        }
        (SchemaAllowance::Schema(source), SchemaAllowance::Schema(curated)) => {
            source_schema_accepts_curated(document, source, curated, depth + 1, active_references)
        }
    }
}

fn schema_required_fields(
    schema: &Map<String, Value>,
) -> std::result::Result<BTreeSet<String>, ()> {
    schema.get("required").map_or_else(
        || Ok(BTreeSet::new()),
        |required| {
            required
                .as_array()
                .ok_or(())?
                .iter()
                .map(|field| field.as_str().map(str::to_owned).ok_or(()))
                .collect()
        },
    )
}

fn source_object_constraints_accept_curated(
    document: &Value,
    source: &Map<String, Value>,
    curated: &Map<String, Value>,
    depth: usize,
    active_references: &mut BTreeSet<String>,
) -> bool {
    if !source_minimum_u64_accepts_curated(source, curated, "minProperties")
        || !source_maximum_u64_accepts_curated(source, curated, "maxProperties")
    {
        return false;
    }
    let (Ok(source_required), Ok(curated_required)) = (
        schema_required_fields(source),
        schema_required_fields(curated),
    ) else {
        return false;
    };
    if !source_required.is_subset(&curated_required) {
        return false;
    }
    let source_properties = match source.get("properties") {
        None => None,
        Some(Value::Object(properties)) => Some(properties),
        Some(_) => return false,
    };
    let curated_properties = match curated.get("properties") {
        None => None,
        Some(Value::Object(properties)) => Some(properties),
        Some(_) => return false,
    };
    let (Ok(source_additional), Ok(curated_additional)) = (
        schema_allowance(source.get("additionalProperties")),
        schema_allowance(curated.get("additionalProperties")),
    ) else {
        return false;
    };

    if curated_properties.is_some_and(|properties| {
        properties.iter().any(|(name, curated_property)| {
            let source_allowance = source_properties
                .and_then(|properties| properties.get(name))
                .map_or(source_additional, SchemaAllowance::Schema);
            !source_allowance_accepts_curated(
                document,
                source_allowance,
                SchemaAllowance::Schema(curated_property),
                depth,
                active_references,
            )
        })
    }) {
        return false;
    }

    if source_properties.is_some_and(|properties| {
        properties.iter().any(|(name, source_property)| {
            curated_properties.is_none_or(|properties| !properties.contains_key(name))
                && !source_allowance_accepts_curated(
                    document,
                    SchemaAllowance::Schema(source_property),
                    curated_additional,
                    depth,
                    active_references,
                )
        })
    }) {
        return false;
    }

    source_allowance_accepts_curated(
        document,
        source_additional,
        curated_additional,
        depth,
        active_references,
    )
}

fn insert_access_application_login_methods_contract(
    document: &Value,
    capabilities: &mut BTreeMap<String, CapabilityV1>,
    source: &CapabilityV1,
    spec: AccessApplicationLoginMethodsContractSpec,
) {
    let mut capability = source.clone();
    spec.capability_id.clone_into(&mut capability.id);
    spec.title.clone_into(&mut capability.title);
    capability.description = Some(spec.description.to_owned());
    capability.aliases = spec
        .aliases
        .iter()
        .map(|alias| (*alias).to_owned())
        .collect();

    let source_identity_supported = access_application_update_identity_supported(&capability);
    let read_identity_supported = access_application_read_identity_supported(capabilities);
    let source_request_schema = document.pointer(ACCESS_APP_UPDATE_REQUEST_SCHEMA_POINTER);
    let source_request_schema_present = source_request_schema.is_some();
    let source_request_body_compatible = source_request_schema.is_some_and(|source_schema| {
        access_application_source_request_body_compatible(
            document,
            source_schema,
            &spec.request_schema,
        )
    });

    capability.request_schema = Some(spec.request_schema);
    let verified_response_fields = capability
        .verifiable_request_object_fields()
        .unwrap_or_default();
    let missing_readback_fields = access_application_missing_readback_fields(
        document,
        spec.app_type,
        &verified_response_fields,
    );

    if !source_identity_supported
        || !read_identity_supported
        || !source_request_schema_present
        || !source_request_body_compatible
        || verified_response_fields.is_empty()
        || !missing_readback_fields.is_empty()
    {
        let mut drift = Vec::new();
        if !source_identity_supported {
            drift.push("update identity".to_owned());
        }
        if !read_identity_supported {
            drift.push("detail-read identity".to_owned());
        }
        if !source_request_schema_present {
            drift.push("source PUT request body".to_owned());
        }
        if source_request_schema_present && !source_request_body_compatible {
            drift.push("source PUT request body incompatibility".to_owned());
        }
        if verified_response_fields.is_empty() {
            drift.push("closed mutable request fields".to_owned());
        }
        if !missing_readback_fields.is_empty() {
            drift.push(format!(
                "readback field(s) {}",
                missing_readback_fields.join(",")
            ));
        }
        capability.adapter_status = AdapterStatus::Blocked;
        capability.blocked_reason = Some(format!(
            "schema drift: the Access application update/read pair no longer exposes the preservation-safe login-method contract ({})",
            drift.join("; ")
        ));
        capabilities.insert(spec.capability_id.to_owned(), capability);
        return;
    }

    capability.risk = RiskClass::IdentityOrOwnership;
    capability.effect = EffectClass::IdentityOrOwnership;
    zero_cost_mutation(
        &mut capability,
        "changing an Access application identity-provider allowlist has no per-operation charge; Access seat and plan billing are unchanged",
        official_reference(
            "Update an Access application",
            "https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/applications/methods/update/",
        ),
    );
    capability.verification.required = true;
    "same_path_result_contains_planned_fields_after_update"
        .clone_into(&mut capability.verification.strategy);
    capability.same_path_read = Some(SamePathReadContractV1 {
        path: ACCESS_APP_DETAIL_PATH.to_owned(),
        read_capability_id: ACCESS_APP_READ_CAPABILITY_ID.to_owned(),
        verified_response_fields,
    });
    capability.rollback.supported = true;
    capability.rollback.strategy = Some("restore_same_path_prior_snapshot".to_owned());
    capability.rollback.warning = Some(
        "cfctl binds and rechecks the exact pre-change application snapshot; rollback is a separate approval-required restoration plan and does not invalidate sessions already issued"
            .to_owned(),
    );
    capability.adapter_status = AdapterStatus::DynamicApi;
    capability.blocked_reason = None;
    refresh_dynamic_mutation_contract(&mut capability);
    capabilities.insert(spec.capability_id.to_owned(), capability);
}

fn finalize_access_application_login_methods_contract(
    document: &Value,
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    let Some(source) = capabilities.get(ACCESS_APP_UPDATE_CAPABILITY_ID).cloned() else {
        return;
    };
    insert_access_application_login_methods_contract(
        document,
        capabilities,
        &source,
        AccessApplicationLoginMethodsContractSpec {
            capability_id: ACCESS_APP_LOGIN_METHODS_CAPABILITY_ID,
            app_type: "self_hosted",
            title: "Update self-hosted Access application login methods",
            description: "Sets the non-empty identity-provider allowlist on one exact public self-hosted Access application. cfctl first reads the live application and builds a full mutable PUT body so policies, domains, cookie settings, launcher visibility, and redirect behavior are preserved.",
            aliases: &[
                "set Access application identity providers",
                "remove GitHub login from Access application",
                "allow Access one-time PIN login",
            ],
            request_schema: access_application_login_methods_materialized_schema(),
        },
    );
    insert_access_application_login_methods_contract(
        document,
        capabilities,
        &source,
        AccessApplicationLoginMethodsContractSpec {
            capability_id: ACCESS_APP_LAUNCHER_LOGIN_METHODS_CAPABILITY_ID,
            app_type: "app_launcher",
            title: "Update Access App Launcher login methods",
            description: "Sets the non-empty identity-provider allowlist on the exact account App Launcher. cfctl first reads the live launcher and builds a preservation-safe PUT body so authentication routing, policy links, session duration, and configured launcher design remain unchanged.",
            aliases: &[
                "set App Launcher identity providers",
                "allow one-time PIN for MFA enrollment",
                "remove GitHub login from App Launcher",
            ],
            request_schema: access_app_launcher_login_methods_schema(),
        },
    );
}

fn access_human_policy_identity_rule_schema() -> Value {
    serde_json::json!({
        "oneOf":[
            {
                "type":"object",
                "additionalProperties":false,
                "required":["email"],
                "properties":{
                    "email":{
                        "type":"object",
                        "additionalProperties":false,
                        "required":["email"],
                        "properties":{
                            "email":{
                                "type":"string",
                                "format":"email",
                                "minLength":3,
                                "maxLength":254
                            }
                        }
                    }
                }
            },
            {
                "type":"object",
                "additionalProperties":false,
                "required":["email_domain"],
                "properties":{
                    "email_domain":{
                        "type":"object",
                        "additionalProperties":false,
                        "required":["domain"],
                        "properties":{
                            "domain":{
                                "type":"string",
                                "format":"hostname",
                                "minLength":3,
                                "maxLength":253
                            }
                        }
                    }
                }
            }
        ]
    })
}

fn access_human_policy_schema() -> Value {
    let identity_rule = access_human_policy_identity_rule_schema();
    serde_json::json!({
        "type":"object",
        "additionalProperties":false,
        "required":[
            "name",
            "decision",
            "include",
            "exclude",
            "require",
            "precedence"
        ],
        "properties":{
            "name":{"type":"string","minLength":1,"maxLength":350},
            "decision":{"type":"string","enum":["allow"]},
            "include":{
                "type":"array",
                "minItems":1,
                "maxItems":100,
                "uniqueItems":true,
                "items":identity_rule.clone()
            },
            "exclude":{
                "type":"array",
                "maxItems":100,
                "uniqueItems":true,
                "items":identity_rule
            },
            "require":{"type":"array","maxItems":0},
            "precedence":{"type":"integer","minimum":1},
            "session_duration":{"type":"string","minLength":2,"maxLength":16},
            "mfa_config":{
                "type":"object",
                "additionalProperties":false,
                "required":["allowed_authenticators","mfa_disabled"],
                "properties":{
                    "allowed_authenticators":{
                        "type":"array",
                        "minItems":1,
                        "maxItems":3,
                        "uniqueItems":true,
                        "items":{
                            "type":"string",
                            "enum":["totp","biometrics","security_key"]
                        }
                    },
                    "mfa_disabled":{"type":"boolean"},
                    "session_duration":{"type":"string","minLength":2,"maxLength":16}
                }
            }
        },
        "x-cfctl-body-required":true
    })
}

fn access_policy_update_identity_supported(capability: &CapabilityV1) -> bool {
    capability.method == "PUT"
        && capability.path == ACCESS_POLICY_DETAIL_PATH
        && capability.product == "Access application-scoped policies"
        && capability.account_scope == "account"
        && capability.permissions == ["Access: Apps and Policies Write"]
        && capability.selectors.len() == 3
        && ["account_id", "app_id", "policy_id"].iter().all(|name| {
            capability.selectors.iter().any(|selector| {
                selector.name == *name
                    && selector.location == "path"
                    && selector.required
                    && selector.value_type == "string"
            })
        })
        && capability
            .response_contract
            .as_ref()
            .is_some_and(|response| {
                response.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
                    && response.success_statuses == ["200"]
                    && response.success_media_types == ["application/json"]
            })
}

fn access_policy_read_identity_supported(capabilities: &BTreeMap<String, CapabilityV1>) -> bool {
    capabilities
        .get(ACCESS_POLICY_READ_CAPABILITY_ID)
        .is_some_and(|read| {
            read.method == "GET"
                && read.path == ACCESS_POLICY_DETAIL_PATH
                && read.product == "Access application-scoped policies"
                && !read.mutating
                && read.request_schema.is_none()
                && read.selectors.len() == 3
                && ["account_id", "app_id", "policy_id"].iter().all(|name| {
                    read.selectors.iter().any(|selector| {
                        selector.name == *name
                            && selector.location == "path"
                            && selector.required
                            && selector.value_type == "string"
                    })
                })
                && read.response_contract.as_ref().is_some_and(|response| {
                    response.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
                        && response.success_statuses == ["200"]
                        && response.success_media_types == ["application/json"]
                })
        })
}

fn access_policy_missing_readback_fields(
    document: &Value,
    verified_response_fields: &[String],
) -> Vec<String> {
    let read_operation = document.pointer(
        "/paths/~1accounts~1{account_id}~1access~1apps~1{app_id}~1policies~1{policy_id}/get",
    );
    read_operation.map_or_else(
        || verified_response_fields.to_vec(),
        |operation| {
            verified_response_fields
                .iter()
                .filter(|field| {
                    !success_response_declares_result_field_union(document, operation, &[field])
                })
                .cloned()
                .collect()
        },
    )
}

/// Derives a closed, application-scoped Access policy update for human
/// eligibility and independent MFA. The broad Cloudflare policy union remains
/// available for other callers, while this contract admits only allow
/// policies composed of email/domain selectors, an empty `require` set, and
/// the documented TOTP/biometric/security-key MFA controls.
///
/// The runtime accepts only the intended eligibility/MFA subset from a caller,
/// reads the exact live policy, rejects unclassified fields, and materializes
/// the full closed PUT body. Its prior-state projection preserves optional
/// field absence, making a separately approved restoration plan honest.
fn finalize_access_human_policy_contract(
    document: &Value,
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    let Some(source) = capabilities
        .get(ACCESS_POLICY_UPDATE_CAPABILITY_ID)
        .cloned()
    else {
        return;
    };
    let mut capability = source;
    ACCESS_HUMAN_POLICY_UPDATE_CAPABILITY_ID.clone_into(&mut capability.id);
    "Update human Access eligibility and independent MFA".clone_into(&mut capability.title);
    capability.description = Some(
        "Updates one exact application-scoped human allow policy. cfctl first reads the live policy and builds a preservation-safe full body from the requested email/domain eligibility or independent MFA changes; service tokens, bypass/non-identity decisions, device rules, external evaluation, arbitrary rule variants, and unclassified live fields are rejected."
            .to_owned(),
    );
    capability.aliases = vec![
        "allow Access OTP users to enroll MFA".to_owned(),
        "enable Access TOTP and biometrics".to_owned(),
        "add human email to App Launcher policy".to_owned(),
    ];
    "cfctl-safe-human-access-policy-v1+cloudflare-access-api".clone_into(&mut capability.source);

    let source_identity_supported = access_policy_update_identity_supported(&capability);
    let read_identity_supported = access_policy_read_identity_supported(capabilities);
    let curated_request_schema = access_human_policy_schema();
    let source_request_schema = document.pointer(ACCESS_POLICY_UPDATE_REQUEST_SCHEMA_POINTER);
    let source_request_schema_present = source_request_schema.is_some();
    let source_request_body_compatible = source_request_schema.is_some_and(|source_schema| {
        access_application_source_request_body_compatible(
            document,
            source_schema,
            &curated_request_schema,
        )
    });

    capability.request_schema = Some(curated_request_schema);
    let verified_response_fields = capability
        .verifiable_request_object_fields()
        .unwrap_or_default();
    let missing_readback_fields =
        access_policy_missing_readback_fields(document, &verified_response_fields);

    if !source_identity_supported
        || !read_identity_supported
        || !source_request_schema_present
        || !source_request_body_compatible
        || verified_response_fields.is_empty()
        || !missing_readback_fields.is_empty()
    {
        let mut drift = Vec::new();
        if !source_identity_supported {
            drift.push("update identity".to_owned());
        }
        if !read_identity_supported {
            drift.push("detail-read identity".to_owned());
        }
        if !source_request_schema_present {
            drift.push("source PUT request body".to_owned());
        }
        if source_request_schema_present && !source_request_body_compatible {
            drift.push("source PUT request body incompatibility".to_owned());
        }
        if verified_response_fields.is_empty() {
            drift.push("closed human policy fields".to_owned());
        }
        if !missing_readback_fields.is_empty() {
            drift.push(format!(
                "readback field(s) {}",
                missing_readback_fields.join(",")
            ));
        }
        capability.adapter_status = AdapterStatus::Blocked;
        capability.blocked_reason = Some(format!(
            "schema drift: the Access policy update/read pair no longer exposes the closed human eligibility and MFA contract ({})",
            drift.join("; ")
        ));
        capabilities.insert(
            ACCESS_HUMAN_POLICY_UPDATE_CAPABILITY_ID.to_owned(),
            capability,
        );
        return;
    }

    capability.risk = RiskClass::IdentityOrOwnership;
    capability.effect = EffectClass::IdentityOrOwnership;
    capability.verification.required = true;
    "same_path_result_contains_planned_fields_after_update"
        .clone_into(&mut capability.verification.strategy);
    capability.same_path_read = Some(SamePathReadContractV1 {
        path: ACCESS_POLICY_DETAIL_PATH.to_owned(),
        read_capability_id: ACCESS_POLICY_READ_CAPABILITY_ID.to_owned(),
        verified_response_fields,
    });
    capability.rollback.supported = true;
    capability.rollback.strategy = Some("restore_same_path_prior_snapshot".to_owned());
    capability.rollback.warning = Some(
        "cfctl binds and rechecks the exact pre-change human policy snapshot, including optional-field absence; rollback is a separate approval-required restoration plan and does not invalidate sessions already issued"
            .to_owned(),
    );
    capability.adapter_status = AdapterStatus::DynamicApi;
    capability.blocked_reason = None;
    refresh_dynamic_mutation_contract(&mut capability);
    capabilities.insert(
        ACCESS_HUMAN_POLICY_UPDATE_CAPABILITY_ID.to_owned(),
        capability,
    );
}

/// Govern Access application creation. The delete side is already governed by
/// the generic exact-resource path; the get and list readbacks exist. Create
/// stays blocked under the generic binder because the request body is a 13-way
/// `anyOf` over app types with no universally-required field — the generic
/// union of variant fields is not an honest verified set. This finalizer binds
/// a curated created-resource contract over `name` and `type`, which are
/// present in every variant and declared on both the create and get responses,
/// and routes it to a dedicated curated-fields strategy. Update stays blocked:
/// there is no honest universal update-field contract across the union.
fn finalize_access_application_create_contract(
    document: &Value,
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    let read_supported = capabilities
        .get("access-applications-get-an-access-application")
        .is_some_and(|capability| {
            capability.method == "GET"
                && capability.path == ACCESS_APP_DETAIL_PATH
                && capability.product == "Access applications"
                && capability
                    .selectors
                    .iter()
                    .all(|selector| selector.location == "path")
        })
        && capabilities
            .get("access-applications-delete-an-access-application")
            .is_some_and(|capability| {
                capability.method == "DELETE" && capability.path == ACCESS_APP_DETAIL_PATH
            });
    if !read_supported {
        return;
    }
    // `name`, `type`, and the returned `id` must be observable on both the
    // create and the detail-read responses for the curated verification to be
    // honest.
    let create_operation = document.pointer("/paths/~1accounts~1{account_id}~1access~1apps/post");
    let read_operation =
        document.pointer("/paths/~1accounts~1{account_id}~1access~1apps~1{app_id}/get");
    let (Some(create_operation), Some(read_operation)) = (create_operation, read_operation) else {
        return;
    };
    let fields_observable =
        ["name", "type"].iter().all(|field| {
            success_response_declares_result_string_field(document, create_operation, field)
                && success_response_declares_result_string_field(document, read_operation, field)
        }) && success_response_declares_result_string_field(document, create_operation, "id")
            && success_response_declares_result_string_field(document, read_operation, "id");
    if !fields_observable {
        return;
    }
    let Some(capability) = capabilities.get_mut("access-applications-add-an-application") else {
        return;
    };
    if capability.method != "POST"
        || capability.path != ACCESS_APP_COLLECTION_PATH
        || capability.product != "Access applications"
        || capability.request_schema.is_none()
    {
        return;
    }
    // Access applications gate authentication in front of resources, so
    // creation is identity-affecting and must land approval-required, never
    // policy auto-execute.
    capability.risk = RiskClass::IdentityOrOwnership;
    capability.effect = EffectClass::IdentityOrOwnership;
    capability.cost = cfctl_core::CostV1::default();
    capability.cost.billing_model = BillingModelV1::Subscription;
    capability.cost.exposure = CostExposureV1::DownstreamUsage;
    capability.cost.basis = Some(
        "creating an Access application has no per-operation charge; Access is seat and plan billed, unaffected by the number of application objects"
            .to_owned(),
    );
    capability.cost.references = vec![KnowledgeReferenceV1 {
        title: "Cloudflare Access pricing".to_owned(),
        url: "https://developers.cloudflare.com/cloudflare-one/policies/access/".to_owned(),
        source: "official Cloudflare docs".to_owned(),
    }];
    capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: ACCESS_APP_DETAIL_PATH.to_owned(),
        identity_selector: "app_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        read_capability_id: "access-applications-get-an-access-application".to_owned(),
        delete_capability_id: "access-applications-delete-an-access-application".to_owned(),
        verified_response_fields: vec!["name".to_owned(), "type".to_owned()],
    });
    "created_access_application_contains_planned_fields_by_returned_id"
        .clone_into(&mut capability.verification.strategy);
    capability.rollback.supported = true;
    capability.rollback.strategy = Some("delete_created_resource_by_returned_id".to_owned());
    capability.rollback.warning = Some(
        "compensation creates a separate exact Access application delete plan that must be reviewed and explicitly approved; deleting an application removes its policies and revokes access it granted"
            .to_owned(),
    );
    refresh_dynamic_mutation_contract(capability);
}

const WORKER_SCRIPT_DELETE_PATH: &str = "/accounts/{account_id}/workers/scripts/{script_name}";
const WORKER_SCRIPT_SETTINGS_PATH: &str =
    "/accounts/{account_id}/workers/scripts/{script_name}/settings";

/// Govern Worker script deletion. The script's own GET returns the raw module
/// body (blocked, non-JSON), so the not-found readback is bound to the
/// `/settings` sub-path via a dedicated verification strategy. The `force`
/// query selector is stripped rather than declared: cfctl never bypasses
/// Cloudflare's in-use refusals, so a script bound as a queue consumer or
/// hosting Durable Objects keeps its upstream guard, and anything in use must
/// be unbound through its own governed capability first.
fn finalize_worker_script_delete_contract(capabilities: &mut BTreeMap<String, CapabilityV1>) {
    let settings_read_supported =
        capabilities
            .get("worker-script-get-settings")
            .is_some_and(|capability| {
                capability.method == "GET"
                    && capability.path == WORKER_SCRIPT_SETTINGS_PATH
                    && capability.product == "Worker Script"
                    && capability
                        .selectors
                        .iter()
                        .all(|selector| selector.location == "path")
            });
    if !settings_read_supported {
        return;
    }
    let Some(capability) = capabilities.get_mut("worker-script-delete-worker") else {
        return;
    };
    let identity_confirmed = capability.method == "DELETE"
        && capability.path == WORKER_SCRIPT_DELETE_PATH
        && capability.product == "Worker Script"
        && capability.mutating
        && capability.request_schema.is_none()
        && capability.permissions == ["Workers Scripts Write"]
        && capability
            .response_contract
            .as_ref()
            .is_some_and(|response| {
                response.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
                    && response.success_statuses == ["200"]
            })
        && ["account_id", "script_name"].iter().all(|name| {
            capability.selectors.iter().any(|selector| {
                selector.name == *name && selector.location == "path" && selector.required
            })
        });
    if !identity_confirmed {
        return;
    }
    capability
        .selectors
        .retain(|selector| selector.location == "path");
    capability.risk = RiskClass::Destructive;
    capability.effect = EffectClass::Irreversible;
    capability.cost = cfctl_core::CostV1::default();
    capability.cost.billing_model = BillingModelV1::UsageBased;
    capability.cost.exposure = CostExposureV1::DownstreamUsage;
    capability.cost.basis = Some(
        "deleting a script has no per-operation charge; Workers billing is request and CPU usage, which ends when the script is gone"
            .to_owned(),
    );
    capability.cost.references = vec![KnowledgeReferenceV1 {
        title: "Workers pricing".to_owned(),
        url: "https://developers.cloudflare.com/workers/platform/pricing/".to_owned(),
        source: "official Cloudflare docs".to_owned(),
    }];
    capability.verification.required = true;
    "worker_script_settings_returns_not_found_after_delete"
        .clone_into(&mut capability.verification.strategy);
    capability.same_path_read = Some(SamePathReadContractV1 {
        path: WORKER_SCRIPT_SETTINGS_PATH.to_owned(),
        read_capability_id: "worker-script-get-settings".to_owned(),
        verified_response_fields: Vec::new(),
    });
    capability.rollback.supported = false;
    capability.rollback.strategy = None;
    capability.rollback.warning = Some(
        "deletion is irreversible and destroys any Durable Object storage hosted by the script; redeployment is a separately reviewed wrangler.deploy plan, and in-use bindings (queue consumers, service bindings) must be removed through their own governed capabilities first — cfctl never passes Cloudflare's force bypass"
            .to_owned(),
    );
    refresh_dynamic_mutation_contract(capability);
}

const QUEUE_CONSUMER_DETAIL_PATH: &str =
    "/accounts/{account_id}/queues/{queue_id}/consumers/{consumer_id}";

/// Queue consumers are a discriminated `oneOf` (worker | `http_pull`) in both
/// the request body and the response `result`, which sinks the generic
/// created-resource and same-path binders: they demand a single object shape.
/// Both variants declare `consumer_id`, so identity readback is provable
/// across the union, and the runtime compares only fields present in the
/// planned body — so binding the canonical request-field union is honest even
/// though `script_name` exists only on the worker variant.
fn finalize_queue_consumer_contracts(
    document: &Value,
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    let read_supported = capabilities
        .get("queues-get-consumer")
        .is_some_and(|capability| {
            capability.method == "GET"
                && capability.path == QUEUE_CONSUMER_DETAIL_PATH
                && capability.product == "Queue"
                && capability
                    .selectors
                    .iter()
                    .all(|selector| selector.location == "path")
        })
        && document
            .pointer(
                "/paths/~1accounts~1{account_id}~1queues~1{queue_id}~1consumers~1{consumer_id}/get",
            )
            .is_some_and(|operation| {
                success_response_declares_result_string_field(document, operation, "consumer_id")
            });
    let delete_supported = capabilities
        .get("queues-delete-consumer")
        .is_some_and(|capability| {
            capability.method == "DELETE" && capability.path == QUEUE_CONSUMER_DETAIL_PATH
        });
    if !read_supported || !delete_supported {
        return;
    }

    let create_declares_identity = document
        .pointer("/paths/~1accounts~1{account_id}~1queues~1{queue_id}~1consumers/post")
        .is_some_and(|operation| {
            success_response_declares_result_string_field(document, operation, "consumer_id")
        });
    if create_declares_identity
        && let Some(capability) = capabilities.get_mut("queues-create-consumer")
        && queue_configuration_kind(capability) == Some(QueueConfigurationKind::ConsumerCreate)
        && let Some(fields) = canonical_verifiable_request_object_fields(capability)
    {
        capability.created_resource = Some(CreatedResourceContractV1 {
            detail_path: QUEUE_CONSUMER_DETAIL_PATH.to_owned(),
            identity_selector: "consumer_id".to_owned(),
            response_result_identity_pointer: "/consumer_id".to_owned(),
            read_capability_id: "queues-get-consumer".to_owned(),
            delete_capability_id: "queues-delete-consumer".to_owned(),
            verified_response_fields: fields,
        });
        "created_resource_contains_planned_fields_by_returned_id"
            .clone_into(&mut capability.verification.strategy);
        capability.rollback.supported = true;
        capability.rollback.strategy = Some("delete_created_resource_by_returned_id".to_owned());
        capability.rollback.warning = Some(
            "compensation creates a separate exact consumer delete plan that must be reviewed and explicitly approved"
                .to_owned(),
        );
        refresh_dynamic_mutation_contract(capability);
    }

    if let Some(capability) = capabilities.get_mut("queues-update-consumer")
        && queue_configuration_kind(capability) == Some(QueueConfigurationKind::ConsumerUpdate)
        && let Some(fields) = canonical_verifiable_request_object_fields(capability)
    {
        capability.same_path_read = Some(SamePathReadContractV1 {
            path: QUEUE_CONSUMER_DETAIL_PATH.to_owned(),
            read_capability_id: "queues-get-consumer".to_owned(),
            verified_response_fields: fields,
        });
        "same_resource_contains_planned_fields_after_update"
            .clone_into(&mut capability.verification.strategy);
        refresh_dynamic_mutation_contract(capability);
    }
}

fn queue_configuration_kind(capability: &CapabilityV1) -> Option<QueueConfigurationKind> {
    QUEUE_CONFIGURATION_CONTRACTS
        .iter()
        .find(|contract| {
            capability.id == contract.id
                && capability.method == contract.method
                && capability.path == contract.path
                && capability.product == "Queue"
                && capability.permissions.len() == 2
                && capability.permissions[0] == "Queues Write"
                && capability.permissions[1] == "Workers Scripts Write"
                && queue_configuration_request_contract_supported(capability, contract.kind)
        })
        .map(|contract| contract.kind)
}

fn queue_configuration_request_contract_supported(
    capability: &CapabilityV1,
    kind: QueueConfigurationKind,
) -> bool {
    if matches!(
        kind,
        QueueConfigurationKind::ConsumerCreate | QueueConfigurationKind::ConsumerUpdate
    ) {
        // The consumer body is a discriminated `oneOf` (worker | http_pull).
        // Require exactly that shape with a string `type` discriminator on
        // every member, without over-pinning variant internals.
        return capability
            .request_schema
            .as_ref()
            .and_then(|schema| schema.get("oneOf"))
            .and_then(Value::as_array)
            .is_some_and(|members| {
                members.len() == 2
                    && members.iter().all(|member| {
                        member.get("type").and_then(Value::as_str) == Some("object")
                            && member
                                .pointer("/properties/type/type")
                                .and_then(Value::as_str)
                                == Some("string")
                    })
            });
    }
    let Some(properties) = capability
        .request_schema
        .as_ref()
        .and_then(|schema| schema.get("properties"))
        .and_then(Value::as_object)
    else {
        return false;
    };
    let queue_name_is_string = properties
        .get("queue_name")
        .and_then(|field| field.get("type"))
        .and_then(Value::as_str)
        == Some("string");
    match kind {
        // Consumer kinds return through the discriminated-oneOf check above
        // and never reach the top-level-properties matching below.
        QueueConfigurationKind::ConsumerCreate | QueueConfigurationKind::ConsumerUpdate => false,
        QueueConfigurationKind::Create => properties.len() == 1 && queue_name_is_string,
        QueueConfigurationKind::Update => {
            let settings = properties.get("settings");
            let settings_properties = settings
                .and_then(|settings| settings.get("properties"))
                .and_then(Value::as_object);
            properties.len() == 2
                && queue_name_is_string
                && settings
                    .and_then(|settings| settings.get("type"))
                    .and_then(Value::as_str)
                    == Some("object")
                && settings_properties.is_some_and(|settings_properties| {
                    settings_properties.len() == 3
                        && settings_properties
                            .get("delivery_delay")
                            .and_then(|field| field.get("type"))
                            .and_then(Value::as_str)
                            == Some("number")
                        && settings_properties
                            .get("delivery_paused")
                            .and_then(|field| field.get("type"))
                            .and_then(Value::as_str)
                            == Some("boolean")
                        && settings_properties
                            .get("message_retention_period")
                            .and_then(|field| field.get("type"))
                            .and_then(Value::as_str)
                            == Some("number")
                })
        }
    }
}

fn classify_queue_configuration(capability: &mut CapabilityV1, kind: QueueConfigurationKind) {
    capability.verification.required = true;
    "post_change_read_or_operation_specific_verifier"
        .clone_into(&mut capability.verification.strategy);
    capability.cost = cfctl_core::CostV1::default();
    capability.cost.billing_model = BillingModelV1::UsageBased;
    capability.cost.exposure = CostExposureV1::DownstreamUsage;
    capability.cost.basis = Some(
        "the queue-management request does not write, read, or delete messages, so its direct incremental ceiling is zero; downstream message operations remain usage-based under Workers Free or Paid included quantities and overage terms, and retention limits are plan-dependent"
            .to_owned(),
    );
    capability.cost.references = vec![
        KnowledgeReferenceV1 {
            title: "Queues pricing".to_owned(),
            url: "https://developers.cloudflare.com/queues/platform/pricing/".to_owned(),
            source: "official Cloudflare docs".to_owned(),
        },
        KnowledgeReferenceV1 {
            title: "Queues limits".to_owned(),
            url: "https://developers.cloudflare.com/queues/platform/limits/".to_owned(),
            source: "official Cloudflare docs".to_owned(),
        },
        KnowledgeReferenceV1 {
            title: "Queues on Workers Free".to_owned(),
            url: "https://developers.cloudflare.com/changelog/post/2026-02-04-queues-free-plan/"
                .to_owned(),
            source: "official Cloudflare changelog".to_owned(),
        },
    ];
    capability.entitlement.available = Some(true);
    capability.entitlement.plans = BTreeMap::from([
        ("workers_free".to_owned(), true),
        ("workers_paid".to_owned(), true),
    ]);
    capability.entitlement.blocker = None;
    capability.entitlement.source = Some(
        "https://developers.cloudflare.com/changelog/post/2026-02-04-queues-free-plan/".to_owned(),
    );
    capability.entitlement.requires_live_resolution = false;

    match kind {
        QueueConfigurationKind::Create => {
            capability.risk = RiskClass::CrossConfig;
            capability.effect = EffectClass::ReversibleWrite;
        }
        QueueConfigurationKind::Update => {
            capability.risk = RiskClass::Destructive;
            capability.effect = EffectClass::Destructive;
            capability.rollback.supported = false;
            capability.rollback.strategy = None;
            capability.rollback.warning = Some(
                "changing retention can cause queued messages to expire and changing delivery state affects connected consumers; configuration restoration requires a separately reviewed update, and expired messages cannot be restored"
                    .to_owned(),
            );
        }
        QueueConfigurationKind::ConsumerCreate => {
            capability.risk = RiskClass::ScopedWrite;
            capability.effect = EffectClass::ReversibleWrite;
        }
        QueueConfigurationKind::ConsumerUpdate => {
            capability.risk = RiskClass::ScopedWrite;
            capability.effect = EffectClass::ReversibleWrite;
            capability.rollback.supported = false;
            capability.rollback.strategy = None;
            capability.rollback.warning = Some(
                "the plan does not snapshot prior consumer settings; restoration requires a separately reviewed consumer update built from trusted evidence"
                    .to_owned(),
            );
        }
    }
}

fn is_dns_record_lifecycle(capability_id: &str) -> bool {
    [
        "dns-records-for-a-zone-create-dns-record",
        "dns-records-for-a-zone-patch-dns-record",
        "dns-records-for-a-zone-update-dns-record",
        "dns-records-for-a-zone-delete-dns-record",
    ]
    .contains(&capability_id)
}

fn classify_dns_record_lifecycle(capability: &mut CapabilityV1) {
    capability.adapter_status = AdapterStatus::DynamicApi;
    capability.cost = cfctl_core::CostV1::default();
    capability.cost.exposure = CostExposureV1::DownstreamUsage;
    capability.cost.basis = Some(
        "official Cloudflare DNS API access has no direct incremental charge; DNS query volume on Enterprise and products reached through the record can have plan-specific downstream pricing"
            .to_owned(),
    );
    capability.cost.references = vec![
        KnowledgeReferenceV1 {
            title: "Cloudflare DNS product".to_owned(),
            url: "https://www.cloudflare.com/products/dns/".to_owned(),
            source: "official Cloudflare product page".to_owned(),
        },
        KnowledgeReferenceV1 {
            title: "Cloudflare DNS pricing FAQ".to_owned(),
            url: "https://developers.cloudflare.com/dns/faq/".to_owned(),
            source: "official Cloudflare docs".to_owned(),
        },
    ];
    capability.verification.required = true;

    if capability.id.ends_with("create-dns-record") {
        capability.risk = RiskClass::ScopedWrite;
        capability.effect = EffectClass::ReversibleWrite;
        "dns_record_details_match_created_id_and_planned_fields"
            .clone_into(&mut capability.verification.strategy);
        capability.rollback.supported = true;
        capability.rollback.strategy = Some("delete_created_dns_record_by_returned_id".to_owned());
        capability.rollback.warning = Some(
            "compensation creates a separate DNS-record delete plan that must be reviewed and explicitly approved"
                .to_owned(),
        );
    } else if capability.id.ends_with("delete-dns-record") {
        capability.risk = RiskClass::Destructive;
        capability.effect = EffectClass::Destructive;
        "dns_record_details_returns_not_found_after_delete"
            .clone_into(&mut capability.verification.strategy);
        capability.rollback.supported = false;
        capability.rollback.strategy = None;
        capability.rollback.warning = Some(
            "deletion cannot be reversed without a prior record snapshot; recreation must be a separately reviewed plan"
                .to_owned(),
        );
    } else {
        capability.risk = RiskClass::ScopedWrite;
        capability.effect = EffectClass::ReversibleWrite;
        "dns_record_details_match_planned_id_and_fields"
            .clone_into(&mut capability.verification.strategy);
        capability.rollback.supported = false;
        capability.rollback.strategy = None;
        capability.rollback.warning = Some(
            "automatic restoration is blocked because the plan does not capture a prior record snapshot; create a separate restoration plan from trusted source or live evidence"
                .to_owned(),
        );
    }
}

fn classify_api_token_lifecycle(capability: &mut CapabilityV1) {
    capability.adapter_status = AdapterStatus::Native;
    capability.cost = cfctl_core::CostV1::default();
    capability.verification.required = true;
    if capability.id.ends_with("create-token") {
        capability.risk = RiskClass::SecretSensitive;
        capability.effect = EffectClass::IdentityOrOwnership;
        "api_token_details_match_created_id_and_active_status"
            .clone_into(&mut capability.verification.strategy);
        capability.rollback.supported = true;
        capability.rollback.strategy = Some(
            "revoke_created_api_token_by_returned_id_if_downstream_installation_fails".to_owned(),
        );
        capability.rollback.warning = Some(
            "credential values are emitted once and must be delivered to an explicit sink"
                .to_owned(),
        );
    } else if capability.id.ends_with("roll-token") {
        capability.risk = RiskClass::SecretSensitive;
        capability.effect = EffectClass::IdentityOrOwnership;
        "api_token_details_report_active_after_value_roll"
            .clone_into(&mut capability.verification.strategy);
        capability.rollback.supported = false;
        capability.rollback.strategy = None;
        capability.rollback.warning = Some(
            "rolling is irreversible because the old token value stops working; install and verify the new sink before dependent cutover"
                .to_owned(),
        );
    } else {
        capability.risk = RiskClass::Destructive;
        capability.effect = EffectClass::Destructive;
        "api_token_details_returns_not_found_after_revoke"
            .clone_into(&mut capability.verification.strategy);
        capability.rollback.supported = false;
        capability.rollback.strategy = None;
        capability.rollback.warning = Some(
            "token revocation is irreversible; mint a separately reviewed replacement instead of attempting restoration"
                .to_owned(),
        );
    }
}

/// Blocks generic API-token update as doctrine rather than as a schema gap.
///
/// The rest of the token lifecycle is governed (create/roll/delete above), so
/// leaving update to the generic blocker would tell an agent the wrong story:
/// that filling in risk/effect/cost would unlock it. It would not. Token
/// mutation is reserved to the inventory-bound `keys` workflow, which reads the
/// live permission inventory before it writes; see `docs/runbooks/cfctl.md`.
///
/// The reason prefix is load-bearing. `refresh_dynamic_mutation_contract` only
/// re-evaluates a blocked capability whose reason starts with
/// `"operation contract incomplete:"`, so a doctrine prefix is immune to being
/// silently promoted the day a generic classifier learns to fill those fields.
/// Contract facts are deliberately left unset — inventing them to make the gap
/// list empty would fabricate a contract nobody reviewed.
fn block_api_token_update_by_doctrine(capability: &mut CapabilityV1) {
    capability.adapter_status = AdapterStatus::Blocked;
    capability.blocked_reason = Some(
        "blocked by design: token mutation is reserved to the inventory-bound keys workflow; a generic token update would bypass fresh permission-inventory review and hash-bound approval"
            .to_owned(),
    );
}

fn block_incomplete_dynamic_mutation(capability: &mut CapabilityV1) {
    if capability.adapter_status != AdapterStatus::DynamicApi || !capability.mutating {
        return;
    }
    refresh_dynamic_mutation_contract(capability);
}

/// Re-evaluates an `OpenAPI` mutation after runtime-bound contract metadata,
/// such as a live entitlement decision, has been attached.
pub fn refresh_dynamic_mutation_contract(capability: &mut CapabilityV1) {
    let is_incomplete_dynamic = capability.adapter_status == AdapterStatus::DynamicApi
        || (capability.adapter_status == AdapterStatus::Blocked
            && capability
                .blocked_reason
                .as_deref()
                .is_some_and(|reason| reason.starts_with("operation contract incomplete:")));
    if !is_incomplete_dynamic || !capability.mutating {
        return;
    }
    let gaps = capability.mutation_contract_gaps();
    if gaps.is_empty() {
        capability.adapter_status = AdapterStatus::DynamicApi;
        capability.blocked_reason = None;
        return;
    }
    capability.adapter_status = AdapterStatus::Blocked;
    capability.blocked_reason = Some(format!(
        "operation contract incomplete: {}",
        gaps.join("; ")
    ));
}

fn intent_terms(query: &str) -> Vec<Vec<String>> {
    query
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|term| !term.is_empty())
        .map(str::to_ascii_lowercase)
        .filter(|term| {
            !matches!(
                term.as_str(),
                "a" | "an" | "the" | "please" | "safely" | "cloudflare" | "for" | "to" | "with"
            )
        })
        .map(|term| match term.as_str() {
            "remove" | "revoke" => vec![term, "delete".to_owned()],
            "mint" | "issue" => vec![term, "create".to_owned()],
            "rotate" => vec![term, "roll".to_owned()],
            _ => vec![term],
        })
        .collect()
}

fn intent_score(capability: &CapabilityV1, terms: &[Vec<String>]) -> usize {
    let fields = [
        (capability.id.to_ascii_lowercase(), 6_usize),
        (capability.title.to_ascii_lowercase(), 8),
        (capability.product.to_ascii_lowercase(), 4),
        (capability.aliases.join(" ").to_ascii_lowercase(), 7),
        (
            capability
                .description
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase(),
            1,
        ),
        (mutation_contract_search_text(capability), 5),
    ];
    terms
        .iter()
        .map(|alternatives| {
            fields
                .iter()
                .filter_map(|(field, weight)| {
                    alternatives
                        .iter()
                        .any(|term| field.contains(term))
                        .then_some(*weight)
                })
                .max()
                .unwrap_or_default()
        })
        .sum()
}

fn mutation_contract_search_text(capability: &CapabilityV1) -> String {
    let mut terms = vec![adapter_status_name(capability.adapter_status).replace('_', " ")];
    if let Some(reason) = capability.blocked_reason.as_deref() {
        terms.push(reason.to_ascii_lowercase());
    }
    for gap in capability.mutation_contract_gaps() {
        let code = mutation_contract_gap_code(&gap);
        terms.push(code.to_owned());
        terms.push(code.replace('_', " "));
    }
    terms.join(" ")
}

fn catalog_io(path: &Path, source: std::io::Error) -> CatalogError {
    CatalogError::Io {
        path: path.display().to_string(),
        source,
    }
}

fn mutation_contract_gap_code(gap: &str) -> &'static str {
    match gap {
        "operation-specific risk classification is missing" => "risk_unknown",
        "operation-specific effect classification is missing" => "effect_unknown",
        "operation-specific incremental cost is unknown" => "cost_unknown",
        "operation-specific verification is not declared" => "verification_missing",
        _ if gap.starts_with("declared verification strategy is unsupported:") => {
            "verification_unsupported"
        }
        "operation-specific rollback or irreversibility behavior is not declared" => {
            "rollback_or_irreversibility_missing"
        }
        _ if gap.starts_with("declared rollback strategy is unsupported:") => {
            "rollback_unsupported"
        }
        "required Cloudflare permission lane is not declared" => "permission_lane_missing",
        _ if gap.contains("entitlement") => "entitlement_unresolved",
        _ if gap.starts_with("operation-specific cost is not bounded;") => "cost_unbounded",
        _ if gap.starts_with("known incremental cost has no ") => "cost_invalid",
        _ => "unclassified",
    }
}

const fn adapter_status_name(status: AdapterStatus) -> &'static str {
    match status {
        AdapterStatus::Native => "native",
        AdapterStatus::DynamicApi => "dynamic_api",
        AdapterStatus::DelegatedCli => "delegated_cli",
        AdapterStatus::GovernedUi => "governed_ui",
        AdapterStatus::Blocked => "blocked",
    }
}

#[cfg(test)]
mod email_routing_tests {
    use super::*;

    fn envelope_response() -> ResponseContractV1 {
        ResponseContractV1 {
            success_statuses: vec!["200".to_owned()],
            success_media_types: vec!["application/json".to_owned()],
            body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
        }
    }

    fn cap(id: &str, method: &str, product: &str, permission: &str) -> CapabilityV1 {
        let mut capability = CapabilityV1::new(id, "t", method, "/p");
        product.clone_into(&mut capability.product);
        capability.permissions = vec![permission.to_owned()];
        capability.response_contract = Some(envelope_response());
        capability
    }

    #[test]
    fn guard_matches_only_the_four_in_scope_ops() {
        // Exactly the four rows in EMAIL_ROUTING_MUTATION_CONTRACTS match.
        for (id, method, product, permission) in EMAIL_ROUTING_MUTATION_CONTRACTS {
            assert!(
                email_routing_mutation_supported(&cap(id, method, product, permission)),
                "expected {id} to match"
            );
        }
        // The PATCH update-destination-address is deliberately excluded (its
        // status field is not readback-verifiable) — it is not in the table.
        assert!(!email_routing_mutation_supported(&cap(
            "email-routing-destination-addresses-update-destination-address",
            "PATCH",
            "Email Routing destination addresses",
            "Email Routing Addresses Write",
        )));
    }

    #[test]
    fn guard_fails_closed_on_drift() {
        let base = (
            "email-routing-routing-rules-create-routing-rule",
            "POST",
            "Email Routing routing rules",
            "Email Routing Rules Write",
        );
        // wrong permission
        assert!(!email_routing_mutation_supported(&cap(
            base.0,
            base.1,
            base.2,
            "Zone Write"
        )));
        // wrong product
        assert!(!email_routing_mutation_supported(&cap(
            base.0, base.1, "Zone", base.3
        )));
        // wrong method
        assert!(!email_routing_mutation_supported(&cap(
            base.0, "DELETE", base.2, base.3
        )));
        // empty permission (never fabricated)
        let mut no_perm = cap(base.0, base.1, base.2, base.3);
        no_perm.permissions.clear();
        assert!(!email_routing_mutation_supported(&no_perm));
        // non-envelope response
        let mut no_env = cap(base.0, base.1, base.2, base.3);
        no_env.response_contract = None;
        assert!(!email_routing_mutation_supported(&no_env));
    }

    #[test]
    fn classifier_sets_scoped_write_zero_cost_and_the_sentinel() {
        let mut capability = cap(
            "email-routing-routing-rules-create-routing-rule",
            "POST",
            "Email Routing routing rules",
            "Email Routing Rules Write",
        );
        classify_email_routing_mutation(&mut capability);
        assert_eq!(capability.risk, RiskClass::ScopedWrite);
        assert_eq!(capability.effect, EffectClass::ReversibleWrite);
        assert!(capability.cost.known);
        assert!(!capability.cost.incremental);
        assert_eq!(capability.cost.maximum, Some(0.0));
        assert_eq!(capability.entitlement.available, Some(true));
        // Sentinel restored so the generic post-normalization classifiers bind
        // the real created-resource / same-path verifier.
        assert_eq!(
            capability.verification.strategy,
            "post_change_read_or_operation_specific_verifier"
        );
        assert!(capability.verification.required);
    }

    fn settings_toggle(id: &str) -> CapabilityV1 {
        let mut capability = cap(id, "POST", "Email Routing settings", "Zone Settings Write");
        // The action endpoints target zone-scoped setting paths.
        "/zones/{zone_id}/email/routing/enable".clone_into(&mut capability.path);
        capability.account_scope = "zone".to_owned();
        capability
    }

    #[test]
    fn settings_guard_matches_only_enable_and_disable() {
        for (id, _) in EMAIL_ROUTING_SETTINGS_TOGGLES {
            assert!(
                email_routing_settings_toggle_supported(&settings_toggle(id)),
                "expected {id} to match"
            );
        }
        // unlock / enable-dns return the settings object rather than the
        // sub-resource they mutate, so they are deliberately out of scope.
        assert!(!email_routing_settings_toggle_supported(&settings_toggle(
            "email-routing-settings-unlock-email-routing"
        )));
        assert!(!email_routing_settings_toggle_supported(&settings_toggle(
            "email-routing-settings-enable-email-routing-dns"
        )));
    }

    #[test]
    fn settings_guard_fails_closed_on_drift() {
        let id = "email-routing-settings-enable-email-routing";
        // wrong method
        let mut wrong_method = settings_toggle(id);
        "GET".clone_into(&mut wrong_method.method);
        assert!(!email_routing_settings_toggle_supported(&wrong_method));
        // wrong permission
        let mut wrong_perm = settings_toggle(id);
        wrong_perm.permissions = vec!["Zone Write".to_owned()];
        assert!(!email_routing_settings_toggle_supported(&wrong_perm));
        // empty permission (never fabricated)
        let mut no_perm = settings_toggle(id);
        no_perm.permissions.clear();
        assert!(!email_routing_settings_toggle_supported(&no_perm));
        // wrong product
        let mut wrong_product = settings_toggle(id);
        "Zone".clone_into(&mut wrong_product.product);
        assert!(!email_routing_settings_toggle_supported(&wrong_product));
        // non-envelope response
        let mut no_env = settings_toggle(id);
        no_env.response_contract = None;
        assert!(!email_routing_settings_toggle_supported(&no_env));
    }

    #[test]
    fn settings_classifier_closes_the_contract_with_the_direct_verifier() {
        for (id, _) in EMAIL_ROUTING_SETTINGS_TOGGLES {
            let mut capability = settings_toggle(id);
            capability.mutating = true;
            capability.adapter_status = AdapterStatus::DynamicApi;
            classify_email_routing_settings_toggle(&mut capability);
            assert_eq!(capability.risk, RiskClass::ScopedWrite, "{id}");
            assert_eq!(capability.effect, EffectClass::ReversibleWrite, "{id}");
            assert!(
                capability.cost.known && !capability.cost.incremental,
                "{id}"
            );
            assert_eq!(capability.cost.maximum, Some(0.0), "{id}");
            assert_eq!(capability.entitlement.available, Some(true), "{id}");
            // The operation-specific verifier is set directly (not the
            // sentinel), because these toggles have no same-path readback.
            assert_eq!(
                capability.verification.strategy,
                "email_routing_settings_response_reports_enabled_state",
                "{id}"
            );
            assert!(capability.verification_contract_supported(), "{id}");
            // Contract is complete: no residual mutation gaps → unblocked.
            assert!(
                capability.mutation_contract_gaps().is_empty(),
                "{id} residual gaps: {:?}",
                capability.mutation_contract_gaps()
            );
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod search_scored_tests {
    use super::*;
    use std::collections::BTreeMap;

    fn snapshot(caps: Vec<CapabilityV1>) -> CatalogSnapshot {
        let mut capabilities = BTreeMap::new();
        for capability in caps {
            capabilities.insert(capability.id.clone(), capability);
        }
        CatalogSnapshot {
            schema_version: 2,
            generated_at: DateTime::from_timestamp(0, 0).expect("epoch is valid"),
            source_url: "test".to_owned(),
            source_hash: String::new(),
            schema_hash: String::new(),
            capabilities,
        }
    }

    #[test]
    fn search_scored_exposes_scores_and_ranks_title_over_description() {
        // "email routing" is in the first capability's title (high weight) but
        // only the second's description (weight 1), so the first must rank above.
        let mut strong = CapabilityV1::new("z-strong", "Enable Email Routing", "POST", "/p");
        strong.product = "Email Routing".to_owned();
        let mut weak = CapabilityV1::new("a-weak", "Widgets", "GET", "/p");
        weak.description = Some("manages email routing incidentally".to_owned());

        let snap = snapshot(vec![strong, weak]);
        let scored = snap.search_scored("email routing");

        assert_eq!(scored.len(), 2);
        assert_eq!(scored[0].0.id, "z-strong");
        assert!(
            scored[0].1 > scored[1].1,
            "a title match must outscore a description-only match"
        );
        // search() is the score-dropping projection of the same ordering.
        let ids: Vec<&str> = snap
            .search("email routing")
            .iter()
            .map(|capability| capability.id.as_str())
            .collect();
        assert_eq!(ids, vec!["z-strong", "a-weak"]);
    }

    #[test]
    fn search_scored_is_empty_when_nothing_matches() {
        let snap = snapshot(vec![CapabilityV1::new("a", "Widgets", "GET", "/p")]);
        assert!(snap.search_scored("nonexistent zzz term").is_empty());
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod telemetry_identity_hygiene_tests {
    use super::*;

    #[test]
    fn mutating_post_with_get_identity_stays_doctrine_blocked() {
        let mut capability = CapabilityV1::new(
            LIVE_TAIL_HEARTBEAT_MISLEADING_ID,
            "Live Tail heartbeat",
            "POST",
            LIVE_TAIL_HEARTBEAT_PATH,
        );
        capability.mutating = true;
        capability.adapter_status = AdapterStatus::DynamicApi;
        let mut snapshot = CatalogSnapshot {
            schema_version: 1,
            generated_at: Utc::now(),
            source_url: "test://telemetry".to_owned(),
            source_hash: "sha256:test".to_owned(),
            schema_hash: String::new(),
            capabilities: BTreeMap::from([(capability.id.clone(), capability)]),
        };

        block_misleading_live_tail_heartbeat_identity(&mut snapshot);
        let blocked = snapshot
            .get(LIVE_TAIL_HEARTBEAT_MISLEADING_ID)
            .expect("capability remains discoverable");
        assert_eq!(blocked.adapter_status, AdapterStatus::Blocked);
        assert!(
            blocked
                .blocked_reason
                .as_deref()
                .unwrap_or_default()
                .contains("mutating POST")
        );
    }

    #[test]
    fn misleading_heartbeat_identity_drift_stays_blocked() {
        let capability = CapabilityV1::new(
            LIVE_TAIL_HEARTBEAT_MISLEADING_ID,
            "Live Tail heartbeat",
            "GET",
            "/accounts/{account_id}/workers/observability/telemetry/live-tail/new-heartbeat",
        );
        let mut snapshot = CatalogSnapshot {
            schema_version: 1,
            generated_at: Utc::now(),
            source_url: "test://telemetry".to_owned(),
            source_hash: "sha256:test".to_owned(),
            schema_hash: String::new(),
            capabilities: BTreeMap::from([(capability.id.clone(), capability)]),
        };

        block_misleading_live_tail_heartbeat_identity(&mut snapshot);
        let blocked = snapshot
            .get(LIVE_TAIL_HEARTBEAT_MISLEADING_ID)
            .expect("drifted capability remains discoverable");
        assert_eq!(blocked.adapter_status, AdapterStatus::Blocked);
        assert!(
            blocked
                .blocked_reason
                .as_deref()
                .unwrap_or_default()
                .contains("identity drifted")
        );
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod control_plane_overlay_tests {
    use super::*;

    #[test]
    fn event_subscription_source_union_includes_current_access_artifacts_and_email_sources() {
        let mut schema = serde_json::json!({
            "type":"object",
            "properties":{
                "source":{
                    "oneOf":[{
                        "type":"object",
                        "properties":{"type":{"type":"string","enum":["r2"]}}
                    }]
                }
            }
        });
        assert!(add_current_event_subscription_sources(&mut schema));
        let variants = schema
            .pointer("/properties/source/oneOf")
            .and_then(Value::as_array)
            .expect("source union");
        let by_type = variants
            .iter()
            .filter_map(|variant| {
                variant
                    .pointer("/properties/type/enum/0")
                    .and_then(Value::as_str)
                    .map(|source_type| (source_type, variant))
            })
            .collect::<BTreeMap<_, _>>();
        for source_type in ["access", "artifacts", "artifacts.repo", "email.sending"] {
            assert!(by_type.contains_key(source_type), "missing {source_type}");
        }
        assert_eq!(
            by_type["artifacts.repo"]["required"],
            serde_json::json!(["type", "namespace", "repo_name"])
        );
        assert_eq!(
            by_type["email.sending"]["required"],
            serde_json::json!(["type", "domain"])
        );
    }

    #[test]
    fn control_plane_workflows_win_the_four_regression_intents() {
        let capabilities = telemetry_workflow_capabilities()
            .into_iter()
            .map(|capability| (capability.id.clone(), capability))
            .collect();
        let snapshot = CatalogSnapshot {
            schema_version: 1,
            generated_at: Utc::now(),
            source_url: "test://workflows".to_owned(),
            source_hash: "sha256:test".to_owned(),
            schema_hash: String::new(),
            capabilities,
        };
        for (intent, expected) in [
            (
                "registry control plane",
                "workflow.registry.reconcile-estate",
            ),
            (
                "real-time control plane",
                "workflow.events.reconcile-control-plane",
            ),
            ("Gateway policy", "workflow.policy.audit-cloudflare"),
            (
                "RealtimeKit webhooks",
                "workflow.realtimekit.webhook-lifecycle",
            ),
        ] {
            let ranked = snapshot.search_scored(intent);
            assert_eq!(
                ranked.first().map(|(capability, _)| capability.id.as_str()),
                Some(expected),
                "{intent}"
            );
            let top = ranked.first().map_or(0, |(_, score)| *score);
            let next = ranked.get(1).map_or(0, |(_, score)| *score);
            assert!(
                top >= next.saturating_add(5),
                "{intent} margin was only {top}-{next}"
            );
        }
    }

    #[test]
    fn queue_pull_ack_and_deprecated_pipeline_update_remain_explicitly_reserved() {
        let mut pull = CapabilityV1::new(
            "queues-pull-messages",
            "Pull messages",
            "POST",
            "/accounts/{account_id}/queues/{queue_id}/messages/pull",
        );
        pull.permissions = vec![
            "Queues Write".to_owned(),
            "Workers Scripts Write".to_owned(),
        ];
        let mut acknowledge = CapabilityV1::new(
            "queues-ack-messages",
            "Acknowledge messages",
            "POST",
            "/accounts/{account_id}/queues/{queue_id}/messages/ack",
        );
        acknowledge.permissions = pull.permissions.clone();
        let pipeline = CapabilityV1::new(
            "putV4AccountsByAccount_idPipelinesByPipeline_name_deprecated",
            "Deprecated Pipeline update",
            "PUT",
            "/accounts/{account_id}/pipelines/{pipeline_name}",
        );
        let mut snapshot = CatalogSnapshot {
            schema_version: 1,
            generated_at: Utc::now(),
            source_url: "test://reserved".to_owned(),
            source_hash: "sha256:test".to_owned(),
            schema_hash: String::new(),
            capabilities: vec![pull, acknowledge, pipeline]
                .into_iter()
                .map(|capability| (capability.id.clone(), capability))
                .collect(),
        };
        reserve_queue_message_operations_for_event_consumer(&mut snapshot);
        block_deprecated_pipeline_update(&mut snapshot);
        for id in ["queues-pull-messages", "queues-ack-messages"] {
            let capability = snapshot.get(id).expect("Queue capability");
            assert_eq!(capability.adapter_status, AdapterStatus::Blocked);
            assert!(
                capability
                    .blocked_reason
                    .as_deref()
                    .unwrap_or_default()
                    .contains("events-consume-queue-batch")
            );
        }
        assert!(
            snapshot
                .get("putV4AccountsByAccount_idPipelinesByPipeline_name_deprecated")
                .and_then(|capability| capability.blocked_reason.as_deref())
                .unwrap_or_default()
                .contains("delete and create")
        );
    }
}
