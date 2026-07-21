//! Versioned domain contracts for the cfctl v2 control plane.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

/// Exact sorted inventory of the executable v2 top-level command surface.
///
/// The CLI tests bind this contract to the live Clap tree, while `xtask`
/// uses it to reject stale checked-in command examples.
pub const PUBLIC_V2_SUBCOMMANDS: &[&str] = &[
    "agents",
    "auth",
    "call",
    "catalog",
    "docs",
    "doctor",
    "guide",
    "keys",
    "migrate",
    "plans",
    "resolve",
    "update",
    "version",
    "workspace",
];

/// One node in the exact public v2 command tree below the top level.
///
/// `PUBLIC_V2_SUBCOMMANDS` single-sources the top-level verbs; this tree extends
/// the same single-source contract one (or more) levels deeper for every verb
/// that itself takes subcommands. A leaf subcommand carries an empty
/// `subcommands` slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandNodeV1 {
    /// Exact clap-facing (kebab-cased) name of this subcommand.
    pub name: &'static str,
    /// Direct child subcommands, sorted, or empty for a leaf.
    pub subcommands: &'static [CommandNodeV1],
}

impl CommandNodeV1 {
    const fn leaf(name: &'static str) -> Self {
        Self {
            name,
            subcommands: &[],
        }
    }
}

/// Exact sorted inventory of every public v2 subcommand below each verb that
/// takes subcommands. Verbs without subcommands (`call`, `resolve`, `guide`,
/// `doctor`, `version`, `update`) are absent by design.
///
/// The CLI test binds this tree to the live clap tree recursively, while `xtask`
/// uses it to reject stale checked-in `cfctl <verb> <sub>` examples.
pub const PUBLIC_V2_COMMAND_TREE: &[CommandNodeV1] = &[
    CommandNodeV1 {
        name: "agents",
        subcommands: &[
            CommandNodeV1::leaf("doctor"),
            CommandNodeV1::leaf("install"),
            CommandNodeV1::leaf("sync"),
        ],
    },
    CommandNodeV1 {
        name: "auth",
        subcommands: &[
            CommandNodeV1::leaf("import-api-token"),
            CommandNodeV1::leaf("import-global-key"),
            CommandNodeV1::leaf("login"),
            CommandNodeV1::leaf("logout"),
            CommandNodeV1::leaf("profiles"),
            CommandNodeV1::leaf("status"),
            CommandNodeV1::leaf("use"),
        ],
    },
    CommandNodeV1 {
        name: "catalog",
        subcommands: &[
            CommandNodeV1::leaf("changes"),
            CommandNodeV1::leaf("coverage"),
            CommandNodeV1::leaf("search"),
            CommandNodeV1::leaf("show"),
            CommandNodeV1::leaf("sync"),
        ],
    },
    CommandNodeV1 {
        name: "docs",
        subcommands: &[
            CommandNodeV1::leaf("changes"),
            CommandNodeV1::leaf("coverage"),
            CommandNodeV1::leaf("search"),
        ],
    },
    CommandNodeV1 {
        name: "keys",
        subcommands: &[
            CommandNodeV1::leaf("mint"),
            CommandNodeV1::leaf("permissions"),
            CommandNodeV1 {
                name: "policy",
                subcommands: &[
                    CommandNodeV1::leaf("approve"),
                    CommandNodeV1::leaf("create"),
                    CommandNodeV1::leaf("list"),
                    CommandNodeV1::leaf("revoke"),
                ],
            },
            CommandNodeV1::leaf("revoke"),
            CommandNodeV1::leaf("rotate"),
        ],
    },
    CommandNodeV1 {
        name: "migrate",
        subcommands: &[CommandNodeV1::leaf("v1")],
    },
    CommandNodeV1 {
        name: "plans",
        subcommands: &[
            CommandNodeV1::leaf("approve"),
            CommandNodeV1::leaf("cancel"),
            CommandNodeV1::leaf("rectify"),
            CommandNodeV1::leaf("resume"),
            CommandNodeV1::leaf("run"),
            CommandNodeV1::leaf("show"),
            CommandNodeV1::leaf("status"),
        ],
    },
    CommandNodeV1 {
        name: "workspace",
        subcommands: &[
            CommandNodeV1::leaf("add"),
            CommandNodeV1::leaf("audit"),
            CommandNodeV1::leaf("discover"),
            CommandNodeV1::leaf("graph"),
        ],
    },
];

/// Provenance source for the exact binary build identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildIdentitySourceV1 {
    ReleaseEnv,
    GitCheckout,
    Unknown,
}

/// Stable, timestamp-free identity for one cfctl binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildInfoV1 {
    pub schema_version: u8,
    pub version: String,
    pub git_commit: Option<String>,
    pub identity_source: BuildIdentitySourceV1,
}

/// Frozen top-level verbs from the retired shell control plane that must
/// always reach the deterministic parser. Without this boundary, a stale
/// multi-token v1 command would be mistaken for natural-language intent and
/// could launch an agent instead of failing closed.
pub const RETIRED_V1_PUBLIC_VERBS: &[&str] = &[
    "admin",
    "apply",
    "audit",
    "bootstrap",
    "can",
    "classify",
    "cloudflared",
    "diff",
    "env",
    "explain",
    "form-intake",
    "get",
    "hostname",
    "lanes",
    "list",
    "locks",
    "maildesk-cf",
    "ownership",
    "previews",
    "skills",
    "snapshot",
    "standards",
    "surfaces",
    "token",
    "verify",
    "wrangler",
];

/// Frozen surface identifiers used to distinguish concrete v1 command shapes
/// from legitimate natural-language requests that begin with words such as
/// `list`, `explain`, or `verify`.
pub const RETIRED_V1_SURFACES: &[&str] = &[
    "access.app",
    "access.group",
    "access.idp",
    "access.login_method",
    "access.organization",
    "access.policy",
    "access.service_token",
    "api_gateway.discovery",
    "api_gateway.operation",
    "api_gateway.schema",
    "audit.log",
    "d1.database",
    "dns.record",
    "edge.certificate",
    "email.routing_rule",
    "form.intake",
    "logpush.job",
    "maildesk-cf",
    "pages.project",
    "pages.secret",
    "queue",
    "r2.bucket",
    "security.txt",
    "sender_domain",
    "tunnel",
    "turnstile.widget",
    "vulnerability_scanner.credential_set",
    "vulnerability_scanner.scan",
    "vulnerability_scanner.target_environment",
    "waiting_room",
    "worker.route",
    "worker.script",
    "worker.secret",
    "workflow",
    "zone",
    "zone.ruleset",
    "zone.setting",
];

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
    #[error("operation {operation_id} has an invalid cost ceiling: {reason}")]
    InvalidCostCeiling {
        operation_id: String,
        reason: String,
    },
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
    #[error("standing authority {authority_id} denied the operation: {reason}")]
    StandingAuthorityDenied {
        authority_id: String,
        reason: String,
    },
    #[error("standing authority {authority_id} is {actual}; expected {expected}")]
    InvalidStandingAuthorityState {
        authority_id: String,
        actual: String,
        expected: &'static str,
    },
    #[error("standing authority {authority_id} expired at {expires_at}")]
    StandingAuthorityExpired {
        authority_id: String,
        expires_at: DateTime<Utc>,
    },
    #[error("operation {operation_id} has an invalid transaction journal: {reason}")]
    InvalidTransactionJournal {
        operation_id: String,
        reason: String,
    },
    #[error(
        "GraphQL analytics contract `{operation_name}` no longer matches its schema fingerprint"
    )]
    GraphqlSchemaFingerprintDrift { operation_name: String },
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseBodyModeV1 {
    CloudflareJsonEnvelope,
    JsonValue,
    GraphqlJson,
    NegotiatedRows,
    Empty,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseContractV1 {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub success_statuses: Vec<String>,
    pub success_media_types: Vec<String>,
    pub body_mode: ResponseBodyModeV1,
}

/// Output representations that a bounded analytics query may negotiate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputFormatV1 {
    Json,
    Ndjson,
    Csv,
}

/// The protocol-specific validator and renderer used for an analytics read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalyticsQueryKindV1 {
    StructuredSql,
    LogExplorerSql,
    GraphqlAnalytics,
    WorkersObservability,
}

/// Timestamp wire representation at the pointers declared by a query contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimestampFormatV1 {
    Rfc3339,
    UnixSeconds,
    UnixMilliseconds,
}

/// How a caller can continue a bounded result without an unbounded hidden loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaginationModeV1 {
    BoundedResult,
    OrderedKeyset,
    TimeWindow,
    UpstreamPage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeRangeContractV1 {
    pub start_pointer: String,
    pub end_pointer: String,
    pub timestamp_format: TimestampFormatV1,
    pub max_lookback_seconds: u64,
    pub max_window_seconds: u64,
}

/// Hash-bound limits for one query family. The pointers are JSON pointers into
/// the caller's typed request body; they are never arbitrary expressions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalyticsQueryContractV1 {
    pub kind: AnalyticsQueryKindV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset_pointer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_range: Option<TimeRangeContractV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub row_limit_pointer: Option<String>,
    pub max_rows: u64,
    pub max_bytes: u64,
    pub max_timeout_seconds: u64,
    pub allowed_output_formats: Vec<OutputFormatV1>,
    pub default_output_format: OutputFormatV1,
    pub pagination: PaginationModeV1,
    pub read_only: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub freshness: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sampling: Option<String>,
}

/// A bounded Logs Engine retrieval whose R2 credentials are supplied through
/// one out-of-band bundle and may only become the two pinned request headers.
/// The credential values are deliberately absent from `CallInput`, plans,
/// receipts, and catalog selectors; only this operation-specific runtime may
/// materialize them at the HTTP boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct R2LogRetrievalContractV1 {
    pub access_key_input_field: String,
    pub secret_access_key_input_field: String,
    pub access_key_header: String,
    pub secret_access_key_header: String,
    pub start_query_selector: String,
    pub end_query_selector: String,
    pub bucket_query_selector: String,
    pub prefix_query_selector: String,
    pub max_lookback_seconds: u64,
    pub max_window_seconds: u64,
    pub max_bytes: u64,
    pub max_timeout_seconds: u64,
    pub output_media_types: Vec<String>,
    pub requires_new_mode_0600_file: bool,
}

/// A fixed Cloudflare GraphQL Analytics document. Callers supply only values
/// named by the two maps; they can never replace or extend the document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphqlAnalyticsContractV1 {
    pub operation_name: String,
    pub document: String,
    pub dataset: String,
    #[serde(default)]
    pub selector_variables: BTreeMap<String, String>,
    #[serde(default)]
    pub body_variables: BTreeMap<String, String>,
    pub response_data_pointer: String,
    #[serde(default)]
    pub expected_row_fields: Vec<String>,
    #[serde(default)]
    pub cursor_fields: Vec<String>,
    /// Legacy single-field cursor input retained for stored v2 catalog
    /// compatibility. New ordered-keyset contracts bind every response cursor
    /// field through `cursor_input_pointers`; a multi-field cursor with only
    /// this pointer is rejected rather than silently dropping its tie-breaker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor_input_pointer: Option<String>,
    /// Response cursor field to typed caller-body JSON pointer. The complete
    /// mapping is fingerprinted with the fixed document so continuation
    /// receipts cannot omit a declared ordering tie-breaker.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub cursor_input_pointers: BTreeMap<String, String>,
    pub schema_fingerprint: String,
}

impl GraphqlAnalyticsContractV1 {
    fn fingerprint_payload(&self) -> Value {
        let mut payload = serde_json::json!({
            "operation_name": self.operation_name,
            "document": self.document,
            "dataset": self.dataset,
            "selector_variables": self.selector_variables,
            "body_variables": self.body_variables,
            "response_data_pointer": self.response_data_pointer,
            "expected_row_fields": self.expected_row_fields,
            "cursor_fields": self.cursor_fields,
            "cursor_input_pointer": self.cursor_input_pointer,
        });
        if !self.cursor_input_pointers.is_empty()
            && let Some(object) = payload.as_object_mut()
        {
            object.insert(
                "cursor_input_pointers".to_owned(),
                serde_json::json!(self.cursor_input_pointers),
            );
        }
        payload
    }

    pub fn refresh_schema_fingerprint(&mut self) -> Result<()> {
        self.schema_fingerprint = hash_value(&self.fingerprint_payload())?;
        Ok(())
    }

    pub fn validate_schema_fingerprint(&self) -> Result<()> {
        let actual = hash_value(&self.fingerprint_payload())?;
        if actual == self.schema_fingerprint {
            Ok(())
        } else {
            Err(CoreError::GraphqlSchemaFingerprintDrift {
                operation_name: self.operation_name.clone(),
            })
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowStepV1 {
    pub id: String,
    pub capability_id: String,
    pub purpose: String,
    pub mutating: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<String>,
}

/// A native composition recipe. It does not aggregate mutation authority:
/// every mutating component still produces and consumes its own `PlanV1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowContractV1 {
    pub purpose: String,
    pub steps: Vec<WorkflowStepV1>,
    pub preserves_component_approval: bool,
    pub exports_evidence_packet: bool,
    /// Maximum age at which a prior component read can be described as fresh
    /// in this workflow's preview. Zero means the workflow never labels prior
    /// evidence fresh. This is workflow policy, not a claim about upstream
    /// retention or dataset completeness.
    #[serde(default)]
    pub proof_freshness_seconds: u64,
}

/// Governance carried beside one telemetry-derived security action. The
/// caller-facing schema is intentionally separate from `request_schema`: the
/// latter is the exact Cloudflare wire body, while this schema requires the
/// evidence, actor, reason, expiry, and blast-radius acknowledgements that
/// cfctl validates and records before it renders that wire body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityActionKindV1 {
    CreateExpiring,
    RemoveExpired,
    AddExpiringListMember,
    RemoveExpiredListMember,
}

/// Fixed safety invariants for a telemetry-derived enforcement lifecycle.
/// The profile is intentionally indivisible: callers cannot disable evidence,
/// actor, reason, or anonymous-identity protections one flag at a time.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityActionSafetyProfileV1 {
    #[default]
    TelemetryDerivedStrict,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityActionContractV1 {
    pub kind: SecurityActionKindV1,
    pub input_schema: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_action: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_actions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_target_types: Vec<String>,
    pub default_ttl_seconds: u64,
    pub max_ttl_seconds: u64,
    pub current_state_capability_id: String,
    #[serde(default)]
    pub safety_profile: SecurityActionSafetyProfileV1,
}

#[must_use]
pub fn request_header_is_reserved(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
            | "host"
            | "x-auth-email"
            | "x-auth-key"
            | "idempotency-key"
            | "if-match"
            | "if-none-match"
            | "content-length"
            | "accept-encoding"
            | "transfer-encoding"
            | "connection"
            | "upgrade"
            | "te"
            | "trailer"
            | "expect"
            | "r2-access-key-id"
            | "r2-secret-access-key"
    )
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

/// A read-only API operation whose successful execution proves that the
/// selected account or zone can access a product surface before cfctl creates
/// a mutation plan. A rejected probe never becomes a negative entitlement
/// assertion because Cloudflare may use the same status for missing token
/// permission, plan entitlement, or product configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntitlementProbeV1 {
    pub capability_id: String,
    pub path: String,
    pub selector_names: Vec<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe: Option<EntitlementProbeV1>,
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

/// Hash-bound coordinates for proving and compensating a resource created
/// inside a parent object. Some Cloudflare APIs (notably Ruleset Engine) return
/// the updated parent ruleset rather than the newly-created child rule. The
/// caller-provided correlation field is therefore the only permitted way to
/// locate exactly one child and lift its schema-proven identity into the
/// boundary receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatedNestedResourceContractV1 {
    pub parent_path: String,
    pub items_pointer: String,
    pub identity_selector: String,
    pub response_item_identity_pointer: String,
    pub correlation_field: String,
    pub read_capability_id: String,
    pub delete_capability_id: String,
    pub delete_path: String,
    pub verified_response_fields: Vec<String>,
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

/// Hash-bound coordinates for proving that an exact nested resource no longer
/// exists in its parent object's complete child array.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeletedNestedResourceContractV1 {
    pub parent_path: String,
    pub collection_path: String,
    pub items_pointer: String,
    pub identity_selector: String,
    pub response_item_identity_pointer: String,
    pub read_capability_id: String,
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

/// Hash-bound lifecycle for a Cloudflare mutation that first returns a bulk
/// operation identity and only materializes its collection change after that
/// operation reaches a terminal state. The verifier may poll only the pinned
/// status path and then read only the pinned collection; arbitrary async API
/// traversal is deliberately not expressible through this contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsyncCollectionMutationContractV1 {
    pub operation_status_path: String,
    pub operation_status_capability_id: String,
    pub operation_id_selector: String,
    pub apply_operation_id_pointer: String,
    pub status_operation_id_pointer: String,
    pub status_state_pointer: String,
    pub pending_states: Vec<String>,
    pub completed_state: String,
    pub failed_state: String,
    pub max_poll_attempts: u16,
    pub poll_interval_ms: u64,
    pub collection_path: String,
    pub collection_capability_id: String,
    pub collection_metadata_path: String,
    pub collection_metadata_capability_id: String,
    pub collection_item_identity_pointer: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remove_capability_id: Option<String>,
    pub requires_cursor_completion: bool,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
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
    pub created_nested_resource: Option<CreatedNestedResourceContractV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_resource: Option<DeletedResourceContractV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_nested_resource: Option<DeletedNestedResourceContractV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_resource: Option<UpdatedResourceContractV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub same_path_read: Option<SamePathReadContractV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub async_collection_mutation: Option<AsyncCollectionMutationContractV1>,
    pub adapter_status: AdapterStatus,
    pub blocked_reason: Option<String>,
    pub request_schema: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_contract: Option<ResponseContractV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analytics_query: Option<AnalyticsQueryContractV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r2_log_retrieval: Option<R2LogRetrievalContractV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graphql: Option<GraphqlAnalyticsContractV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow: Option<WorkflowContractV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_action: Option<SecurityActionContractV1>,
}

/// Cloudflare's DNS record detail path. This is wire contract, not a local
/// naming choice: the catalog derives the read capability from it, the planner
/// pins it as a rollback and same-path-read target, and the executor builds
/// verification readbacks against it. It lives here so those four crates bind
/// one authority instead of four literals.
pub const DNS_RECORD_DETAIL_PATH: &str = "/zones/{zone_id}/dns_records/{dns_record_id}";

/// The capability id the catalog derives for [`DNS_RECORD_DETAIL_PATH`]. Pinned
/// by `dns_record_detail_constants_pin_the_wire_contract`; every consumer reads
/// this constant rather than restating the slug.
pub const DNS_RECORD_DETAIL_READ_CAPABILITY_ID: &str = "dns-records-for-a-zone-dns-record-details";

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
            aliases: Vec::new(),
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
            created_nested_resource: None,
            deleted_resource: None,
            deleted_nested_resource: None,
            updated_resource: None,
            same_path_read: None,
            async_collection_mutation: None,
            adapter_status: AdapterStatus::DynamicApi,
            blocked_reason: None,
            request_schema: None,
            response_contract: None,
            analytics_query: None,
            r2_log_retrieval: None,
            graphql: None,
            workflow: None,
            security_action: None,
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
        } else if self.cost.incremental {
            if !self
                .cost
                .currency
                .as_deref()
                .is_some_and(valid_currency_code)
            {
                gaps.push("known incremental cost has no valid three-letter currency".to_owned());
            }
            if !self.cost.maximum.is_some_and(valid_non_negative_amount) {
                gaps.push("known incremental cost has no finite non-negative maximum".to_owned());
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
        if self.security_action.is_some() && !self.security_action_contract_supported() {
            gaps.push("telemetry-derived security action safety contract is malformed".to_owned());
        }
        if self.entitlement.probe.is_some() && !self.entitlement_probe_contract_supported() {
            gaps.push("declared live entitlement probe is malformed".to_owned());
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
        if self.entitlement.available != Some(true) {
            if let Some(blocker) = self.entitlement.blocker.as_ref() {
                gaps.push(blocker.clone());
            } else if self.entitlement.probe.is_none()
                && self.entitlement.plans.values().any(|available| !available)
            {
                gaps.push(
                    "account entitlement has not been resolved for this plan-gated operation"
                        .to_owned(),
                );
            }
        }
        gaps
    }

    fn entitlement_probe_contract_supported(&self) -> bool {
        self.entitlement.probe.as_ref().is_some_and(|probe| {
            matches!(self.account_scope.as_str(), "account" | "zone")
                && self.entitlement.requires_live_resolution
                && !probe.capability_id.is_empty()
                && probe.path.starts_with('/')
                && !probe.selector_names.is_empty()
                && probe
                    .selector_names
                    .windows(2)
                    .all(|names| names[0] < names[1])
                && probe.selector_names.iter().all(|name| {
                    !name.is_empty()
                        && self.selectors.iter().any(|selector| {
                            selector.name == *name
                                && selector.location == "path"
                                && selector.required
                        })
                        && probe.path.contains(&format!("{{{name}}}"))
                })
        })
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
    // The one match arm per supported strategy pushes this gate past the
    // pedantic line ceiling; the strategies are intentionally enumerated in one
    // place so the supported set stays auditable.
    #[must_use]
    #[allow(clippy::too_many_lines)]
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
            "oauth_client_reports_rotated_secret_after_value_roll"
            | "oauth_client_reports_no_rotated_secret_after_old_secret_delete"
            | "worker_script_secret_reports_planned_name_and_type_after_put" => {
                secret_lifecycle_verification_contract_supported(self)
            }
            "access_service_token_reports_refreshed_expiration" => {
                access_service_token_refresh_verification_contract_supported(self)
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
                // Accepts both an id-parameter-terminated resource path and a
                // singleton sub-resource path (terminal literal segment under an
                // identified parent, e.g. `/apps/{app_id}/ca`). Both are proven
                // single resources by the bound same-path readback contract; the
                // catalog only binds `same_path_read` on a singleton after
                // confirming its readback GET returns a single object, not a
                // collection, so delete-then-not-found is a valid readback here.
                self.method == "DELETE"
                    && (path_targets_exact_resource(&self.path)
                        || path_targets_singleton_subresource(&self.path))
                    && (self.request_schema.is_none()
                        || self.required_empty_request_body_contract())
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
            "parent_object_omits_deleted_nested_resource_id" => {
                self.method == "DELETE"
                    && self.request_schema.is_none()
                    && self
                        .selectors
                        .iter()
                        .all(|selector| selector.location == "path")
                    && self.deleted_nested_resource_contract_supported()
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
            // A Worker script has no same-path JSON readback — the script GET
            // returns the raw module body — so deletion is verified against
            // the script's `/settings` sub-path, which answers 404 once the
            // script is gone. Identity-bound to the exact delete operation.
            // cfctl deliberately never expresses Cloudflare's `force` bypass,
            // so upstream in-use refusals (bound queue consumers, Durable
            // Objects) remain live guards; the contract requires path-only
            // selectors to keep that unexpressable.
            "worker_script_settings_returns_not_found_after_delete" => {
                self.id == "worker-script-delete-worker"
                    && self.method == "DELETE"
                    && self.path == "/accounts/{account_id}/workers/scripts/{script_name}"
                    && self.request_schema.is_none()
                    && self
                        .selectors
                        .iter()
                        .all(|selector| selector.location == "path")
                    && ["account_id", "script_name"].iter().all(|name| {
                        self.selectors.iter().any(|selector| {
                            selector.name == *name
                                && selector.location == "path"
                                && selector.required
                        })
                    })
                    && self.same_path_read.as_ref().is_some_and(|target| {
                        target.path
                            == "/accounts/{account_id}/workers/scripts/{script_name}/settings"
                            && target.read_capability_id == "worker-script-get-settings"
                            && target.verified_response_fields.is_empty()
                    })
            }
            "created_resource_contains_planned_fields_by_returned_id" => {
                self.method == "POST" && self.created_resource_contract_supported()
            }
            // An Access application body is a 13-way `anyOf` over app types
            // with no universally-required field, so the generic binder — which
            // unions every variant's fields — cannot produce an honest verified
            // set. This strategy binds a curated set of fields present and
            // observable across every variant (`name`, `type`), verified the
            // same way the generic evaluator does: the runtime compares only
            // fields actually present in the planned body, so a curated subset
            // is honest. Identity-bound to the exact create operation.
            "created_access_application_contains_planned_fields_by_returned_id" => {
                self.id == "access-applications-add-an-application"
                    && self.method == "POST"
                    && self.path == "/accounts/{account_id}/access/apps"
                    && self
                        .created_resource_contract_supported_with_curated_fields(&["name", "type"])
            }
            "parent_collection_contains_created_resource_id_and_planned_fields" => {
                self.method == "POST" && self.created_collection_resource_contract_supported()
            }
            "worker_tail_collection_contains_created_lease_id" => {
                self.worker_tail_created_collection_contract_supported()
            }
            "async_list_operation_completes_and_correlated_member_exists" => {
                self.async_list_mutation_contract_supported(true)
            }
            "async_list_operation_completes_and_members_absent" => {
                self.async_list_mutation_contract_supported(false)
            }
            "parent_object_contains_created_nested_resource_by_correlation" => {
                self.method == "POST" && self.created_nested_resource_contract_supported()
            }
            "web_analytics_rule_list_contains_created_id_and_planned_fields" => {
                self.id == "web-analytics-create-rule"
                    && self.method == "POST"
                    && self.path == "/accounts/{account_id}/rum/v2/{ruleset_id}/rule"
                    && self.permissions == ["Account Settings Read", "Account Settings Write"]
                    && self.created_resource_contract_supported()
                    && self.created_resource.as_ref().is_some_and(|target| {
                        target.detail_path
                            == "/accounts/{account_id}/rum/v2/{ruleset_id}/rule/{rule_id}"
                            && target.identity_selector == "rule_id"
                            && target.response_result_identity_pointer == "/id"
                            && target.read_capability_id == "web-analytics-list-rules"
                            && target.delete_capability_id == "web-analytics-delete-rule"
                    })
            }
            "web_analytics_rule_list_omits_deleted_id" => {
                self.id == "web-analytics-delete-rule"
                    && self.method == "DELETE"
                    && self.path == "/accounts/{account_id}/rum/v2/{ruleset_id}/rule/{rule_id}"
                    && self.request_schema.is_none()
                    && self.permissions == ["Account Settings Read", "Account Settings Write"]
                    && self
                        .selectors
                        .iter()
                        .all(|selector| selector.location == "path")
                    && self.same_path_read.as_ref().is_some_and(|target| {
                        target.path == "/accounts/{account_id}/rum/v2/{ruleset_id}/rules"
                            && target.read_capability_id == "web-analytics-list-rules"
                            && target.verified_response_fields.is_empty()
                    })
            }
            // Cache purge cannot be verified by readback: there is no
            // "is-this-cached?" GET. The executor asserts only that Cloudflare
            // accepted the purge and echoed the target zone id in `result.id`;
            // the basis string states plainly this proves acceptance and
            // scoping, not eviction. Bound to the exact purge ids (including
            // the derived Enterprise-scoped `-tagged` variants).
            "cache_purge_response_reports_target_zone_id" => {
                self.method == "POST"
                    && matches!(
                        self.id.as_str(),
                        "zone-purge"
                            | "zone-purge-tagged"
                            | "zone-environment-purge"
                            | "zone-environment-purge-tagged"
                    )
            }
            "wrangler_deployment_status_reports_promoted_version" => {
                self.id == "wrangler.deploy"
                    && self.method == "CLI"
                    && self.path == "wrangler deploy"
                    && self.adapter_status == AdapterStatus::DelegatedCli
                    && self.selectors.iter().any(|selector| {
                        selector.name == "config"
                            && selector.location == "query"
                            && selector.required
                            && selector.value_type == "string"
                    })
            }
            // The Email Routing enable/disable toggles have no same-path
            // readback of a resource, so verification asserts the toggle's own
            // `result.enabled` boolean in the settings object the action
            // endpoint returns. The basis states plainly this proves the
            // setting now reports the intended value, not that MX/DNS
            // propagation or live mail delivery has converged. Bound to the
            // exact enable/disable ids.
            "email_routing_settings_response_reports_enabled_state" => {
                self.method == "POST"
                    && matches!(
                        self.id.as_str(),
                        "email-routing-settings-enable-email-routing"
                            | "email-routing-settings-disable-email-routing"
                    )
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
                self.delete_created_resource_rollback_supported()
            }
            Some("remove_async_created_list_member_by_correlated_id") => {
                self.async_list_mutation_contract_supported(true)
                    && self.verification.strategy
                        == "async_list_operation_completes_and_correlated_member_exists"
            }
            Some("delete_created_empty_d1_database_by_returned_uuid_if_unchanged") => {
                d1_database_create_rollback_contract_supported(self)
            }
            Some("delete_created_empty_kv_namespace_by_returned_id_if_unchanged") => {
                kv_namespace_create_rollback_contract_supported(self)
            }
            Some("restore_global_warp_override_prior_disconnect_state") => {
                self.global_warp_override_rollback_supported()
            }
            Some("restore_d1_read_replication_prior_mode") => {
                matches!(
                    (self.id.as_str(), self.method.as_str()),
                    ("d1-update-database", "PUT") | ("d1-update-partial-database", "PATCH")
                ) && self.product == "D1"
                    && self.path == "/accounts/{account_id}/d1/database/{database_id}"
                    && self.account_scope == "account"
                    && self.verification.strategy
                        == "same_resource_contains_planned_fields_after_update"
                    && self.verification_contract_supported()
                    && d1_read_replication_request_contract_supported(self)
                    && self.same_path_read.as_ref().is_some_and(|read| {
                        read.path == "/accounts/{account_id}/d1/database/{database_id}"
                            && read.read_capability_id == "d1-get-database"
                            && read.verified_response_fields == ["read_replication"]
                    })
            }
            Some("restore_cloudflare_tunnel_configuration_prior_snapshot") => {
                cloudflare_tunnel_configuration_rollback_contract_supported(self)
            }
            Some("restore_warp_connector_configuration_prior_snapshot") => {
                warp_connector_configuration_rollback_contract_supported(self)
            }
            Some("restore_web_analytics_rum_prior_value") => {
                web_analytics_rum_rollback_contract_supported(self)
            }
            Some("restore_dns_record_prior_snapshot_with_put") => {
                matches!(
                    (self.id.as_str(), self.method.as_str()),
                    ("dns-records-for-a-zone-update-dns-record", "PUT")
                        | ("dns-records-for-a-zone-patch-dns-record", "PATCH")
                ) && self.product == "DNS Records for a Zone"
                    && self.path == DNS_RECORD_DETAIL_PATH
                    && self.account_scope == "zone"
                    && self.verification.strategy
                        == "dns_record_details_match_planned_id_and_fields"
                    && self.verification_contract_supported()
                    && dns_record_update_request_contract_supported(self)
                    && self.same_path_read.as_ref().is_some_and(|read| {
                        read.path == DNS_RECORD_DETAIL_PATH
                            && read.read_capability_id == DNS_RECORD_DETAIL_READ_CAPABILITY_ID
                            && read.verified_response_fields
                                == [
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
                                ]
                    })
            }
            Some("restore_same_path_prior_snapshot") => {
                self.same_path_prior_snapshot_rollback_supported()
            }
            _ => false,
        }
    }

    fn global_warp_override_rollback_supported(&self) -> bool {
        self.id == "devices-resilience-set-global-warp-override"
            && self.method == "POST"
            && self.path == "/accounts/{account_id}/devices/resilience/disconnect"
            && self.account_scope == "account"
            && self.verification.strategy
                == "same_path_result_contains_planned_fields_after_mutation"
            && self.verification_contract_supported()
            && self.same_path_read.as_ref().is_some_and(|read| {
                read.read_capability_id == "devices-resilience-retrieve-global-warp-override"
                    && read.verified_response_fields == ["disconnect"]
            })
    }

    fn same_path_prior_snapshot_rollback_supported(&self) -> bool {
        matches!(self.method.as_str(), "PATCH" | "PUT")
            && matches!(
                self.verification.strategy.as_str(),
                "same_resource_contains_planned_fields_after_update"
                    | "same_path_result_contains_planned_fields_after_update"
            )
            && self.verification_contract_supported()
            && self.same_path_readback_selectors_supported()
            && self.same_path_read_contract_supported(true)
    }

    /// A security action is executable only when its caller schema and safety
    /// bounds are complete and the ordinary verifier/rollback contracts can
    /// still prove the Cloudflare-side lifecycle.
    #[must_use]
    pub fn security_action_contract_supported(&self) -> bool {
        let Some(contract) = self.security_action.as_ref() else {
            return true;
        };
        let schema_is_closed_object = contract.input_schema.get("type").and_then(Value::as_str)
            == Some("object")
            && contract
                .input_schema
                .get("additionalProperties")
                .and_then(Value::as_bool)
                == Some(false)
            && contract
                .input_schema
                .get("required")
                .and_then(Value::as_array)
                .is_some_and(|required| !required.is_empty());
        let common = self.mutating
            && schema_is_closed_object
            && !contract.current_state_capability_id.is_empty()
            && contract.safety_profile == SecurityActionSafetyProfileV1::TelemetryDerivedStrict;
        if !common {
            return false;
        }
        match contract.kind {
            SecurityActionKindV1::CreateExpiring => {
                self.method == "POST"
                    && contract.default_ttl_seconds >= 300
                    && contract.max_ttl_seconds >= contract.default_ttl_seconds
                    && contract.max_ttl_seconds <= 604_800
                    && contract.default_action.as_ref().is_some_and(|action| {
                        action == "managed_challenge"
                            && contract
                                .allowed_actions
                                .iter()
                                .any(|allowed| allowed == action)
                    })
                    && !contract.allowed_target_types.is_empty()
                    && self.verification_contract_supported()
                    && self.rollback.supported
                    && self.rollback_contract_supported()
            }
            SecurityActionKindV1::RemoveExpired => {
                self.method == "DELETE"
                    && contract.default_ttl_seconds == 0
                    && contract.max_ttl_seconds == 0
                    && contract.default_action.is_none()
                    && contract.allowed_actions.is_empty()
                    && self.verification_contract_supported()
                    && !self.rollback.supported
            }
            SecurityActionKindV1::AddExpiringListMember => {
                self.method == "POST"
                    && contract.default_ttl_seconds >= 300
                    && contract.max_ttl_seconds >= contract.default_ttl_seconds
                    && contract.max_ttl_seconds <= 604_800
                    && contract.default_action.as_deref() == Some("managed_challenge")
                    && contract
                        .allowed_actions
                        .iter()
                        .any(|action| action == "managed_challenge")
                    && !contract.allowed_target_types.is_empty()
                    && self.async_list_mutation_contract_supported(true)
                    && self.verification_contract_supported()
                    && self.rollback.supported
                    && self.rollback_contract_supported()
            }
            SecurityActionKindV1::RemoveExpiredListMember => {
                self.method == "DELETE"
                    && contract.default_ttl_seconds == 0
                    && contract.max_ttl_seconds == 0
                    && contract.default_action.is_none()
                    && contract.allowed_actions.is_empty()
                    && self.async_list_mutation_contract_supported(false)
                    && self.verification_contract_supported()
                    && !self.rollback.supported
            }
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

    /// Returns the exact writable leaf paths for every branch selected by a
    /// single-string discriminator. Direct fields and nested `allOf`
    /// compositions are unioned, while `oneOf` and `anyOf` remain isolated by
    /// discriminator value. Ambiguous, duplicated, or over-budget schemas fail
    /// closed.
    #[must_use]
    pub fn request_object_paths_by_discriminator(
        &self,
        discriminator: &str,
    ) -> Option<BTreeMap<String, Vec<String>>> {
        let schema = self.request_schema.as_ref()?;
        let mut branches = Vec::new();
        let mut remaining_steps = MAX_REQUEST_OBJECT_SCHEMA_STEPS;
        collect_discriminated_object_branches(
            schema,
            discriminator,
            0,
            &mut remaining_steps,
            &mut branches,
        )?;
        if branches.is_empty() {
            return None;
        }
        let mut paths_by_value = BTreeMap::new();
        for (value, branch) in branches {
            let mut fields = BTreeMap::new();
            if collect_composed_object_property_schemas(
                branch,
                0,
                &mut remaining_steps,
                &mut fields,
            ) != RequestObjectSchemaCollection::Object
            {
                return None;
            }
            let mut paths = BTreeSet::new();
            for (name, schemas) in fields {
                collect_request_property_paths(
                    &schemas,
                    &name,
                    0,
                    &mut remaining_steps,
                    &mut paths,
                )?;
            }
            if paths.is_empty()
                || paths_by_value
                    .insert(value, paths.into_iter().collect())
                    .is_some()
            {
                return None;
            }
        }
        Some(paths_by_value)
    }

    /// Returns the canonical top-level request fields that a response
    /// readback can observe. Fully write-only inputs and fields explicitly
    /// marked `x-cfctl-verification-observable: false` remain valid request
    /// fields but are deliberately absent from this list. A schema with
    /// `properties` and no explicit type is object-shaped for this purpose;
    /// any explicit non-object type remains ineligible.
    #[must_use]
    pub fn verifiable_request_object_fields(&self) -> Option<Vec<String>> {
        let fields = request_object_property_schemas(self.request_schema.as_ref()?)?;
        let fields = fields
            .into_iter()
            .filter(|(_, schemas)| !property_schemas_are_verification_omitted(schemas))
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

    /// Returns whether a top-level request field is deliberately omitted from
    /// state readback verification. This includes write-only values and a
    /// catalog-pinned `x-cfctl-verification-observable: false` annotation.
    #[must_use]
    pub fn request_object_field_is_verification_omitted(&self, field: &str) -> bool {
        self.request_schema
            .as_ref()
            .and_then(request_object_property_schemas)
            .and_then(|fields| fields.get(field).cloned())
            .is_some_and(|schemas| property_schemas_are_verification_omitted(&schemas))
    }

    /// Returns a catalog-pinned response field name when an operation's read
    /// model spells a verifiable request field differently. Conflicting or
    /// unsafe annotations fail closed by returning no mapping.
    #[must_use]
    pub fn request_object_field_verification_response_field(&self, field: &str) -> Option<String> {
        let schemas = self
            .request_schema
            .as_ref()
            .and_then(request_object_property_schemas)?
            .remove(field)?;
        let mut names = BTreeSet::new();
        let mut remaining_steps = MAX_REQUEST_OBJECT_SCHEMA_STEPS;
        for schema in schemas {
            collect_verification_response_field_names(schema, 0, &mut remaining_steps, &mut names);
        }
        if names.len() == 1 {
            names.into_iter().next()
        } else {
            None
        }
    }

    /// Returns whether this capability's pinned request contract requires one
    /// exact empty JSON object. Catalog classifiers may deliberately narrow an
    /// official open object to this safe subset, but only when `{}` is valid
    /// under the source schema.
    #[must_use]
    pub fn required_empty_request_body_contract(&self) -> bool {
        self.request_schema.as_ref().is_some_and(|schema| {
            schema.get("type").and_then(Value::as_str) == Some("object")
                && schema
                    .get("properties")
                    .and_then(Value::as_object)
                    .is_some_and(serde_json::Map::is_empty)
                && schema.get("additionalProperties").and_then(Value::as_bool) == Some(false)
                && schema
                    .get("required")
                    .and_then(Value::as_array)
                    .is_none_or(Vec::is_empty)
                && schema.get("x-cfctl-body-required").and_then(Value::as_bool) == Some(true)
                && ["allOf", "oneOf", "anyOf"]
                    .iter()
                    .all(|composition| schema.get(*composition).is_none())
                && schema
                    .get("minProperties")
                    .and_then(Value::as_u64)
                    .is_none_or(|minimum| minimum == 0)
                && schema.get("enum").is_none()
        })
    }

    fn verified_response_fields_match_request_schema(&self, fields: &[String]) -> bool {
        match self.request_schema.as_ref() {
            None => true,
            Some(_) => self
                .verifiable_request_object_fields()
                .is_some_and(|request_fields| fields == request_fields),
        }
    }

    fn delete_created_resource_rollback_supported(&self) -> bool {
        self.method == "POST"
            && self.id != "d1-create-database"
            && (self.created_resource_contract_supported()
                || self.created_collection_resource_contract_supported()
                || self.created_nested_resource_contract_supported()
                || self.worker_tail_created_collection_contract_supported()
                || (self.id == "access-applications-add-an-application"
                    && self.created_resource_contract_supported_with_curated_fields(&[
                        "name", "type",
                    ])))
    }

    fn created_resource_contract_supported(&self) -> bool {
        self.created_resource_contract_structurally_supported(|target| {
            self.verified_response_fields_match_request_schema(&target.verified_response_fields)
        })
    }

    /// Like `created_resource_contract_supported`, but the verified fields are
    /// a caller-curated set rather than the full request-field union. For
    /// bodies whose polymorphic `anyOf` has no universally-required field, the
    /// union is not an honest verified set; a curated set of fields present in
    /// every variant is. The runtime compares only fields present in the
    /// planned body, so verifying against a subset never over-asserts.
    fn created_resource_contract_supported_with_curated_fields(&self, curated: &[&str]) -> bool {
        self.created_resource_contract_structurally_supported(|target| {
            target.verified_response_fields.len() == curated.len()
                && target
                    .verified_response_fields
                    .iter()
                    .zip(curated)
                    .all(|(field, expected)| field == expected)
        })
    }

    fn created_resource_contract_structurally_supported(
        &self,
        fields_valid: impl Fn(&CreatedResourceContractV1) -> bool,
    ) -> bool {
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
                && self.same_path_readback_selectors_supported()
                && !target.verified_response_fields.is_empty()
                && fields_valid(target)
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

    fn worker_tail_created_collection_contract_supported(&self) -> bool {
        self.id == "worker-tail-logs-start-tail"
            && self.method == "POST"
            && self.path == "/accounts/{account_id}/workers/scripts/{script_name}/tails"
            && self.product == "Worker Tail Logs"
            && self.account_scope == "account"
            && self.request_schema.is_none()
            && self.risk == RiskClass::SecretSensitive
            && self.effect == EffectClass::ReversibleWrite
            && self.permissions == ["Workers Tail Read", "Workers Scripts Write"]
            && self
                .selectors
                .iter()
                .all(|selector| selector.location == "path")
            && ["account_id", "script_name"].iter().all(|name| {
                self.selectors.iter().any(|selector| {
                    selector.name == *name && selector.location == "path" && selector.required
                })
            })
            && self
                .created_collection_resource
                .as_ref()
                .is_some_and(|target| {
                    target.collection_path
                        == "/accounts/{account_id}/workers/scripts/{script_name}/tails"
                        && target.identity_selector == "id"
                        && target.response_result_identity_pointer == "/id"
                        && target.response_item_identity_pointer == "/id"
                        && target.read_capability_id == "worker-tail-logs-list-tails"
                        && target.delete_capability_id == "worker-tail-logs-delete-tail"
                        && target.verified_response_fields.is_empty()
                        && !target.requires_page_number_completion
                })
    }

    fn async_list_mutation_contract_supported(&self, create: bool) -> bool {
        const COLLECTION: &str = "/accounts/{account_id}/rules/lists/{list_id}/items";
        const STATUS: &str = "/accounts/{account_id}/rules/lists/bulk_operations/{operation_id}";
        let expected_id = if create {
            "security-response-add-expiring-list-member"
        } else {
            "security-response-remove-expired-list-member"
        };
        let expected_method = if create { "POST" } else { "DELETE" };
        self.id == expected_id
            && self.method == expected_method
            && self.path == COLLECTION
            && self.product == "Lists"
            && self.account_scope == "account"
            && self.risk == RiskClass::IdentityOrOwnership
            && self.effect
                == if create {
                    EffectClass::ReversibleWrite
                } else {
                    EffectClass::Destructive
                }
            && self.permissions == ["Account Filter Lists Edit", "Account Filter Lists Read"]
            && self
                .selectors
                .iter()
                .all(|selector| selector.location == "path")
            && ["account_id", "list_id"].iter().all(|name| {
                self.selectors.iter().any(|selector| {
                    selector.name == *name && selector.location == "path" && selector.required
                })
            })
            && self
                .async_collection_mutation
                .as_ref()
                .is_some_and(|contract| {
                    contract.operation_status_path == STATUS
                        && contract.operation_status_capability_id
                            == "lists-get-bulk-operation-status"
                        && contract.operation_id_selector == "operation_id"
                        && contract.apply_operation_id_pointer == "/operation_id"
                        && contract.status_operation_id_pointer == "/id"
                        && contract.status_state_pointer == "/status"
                        && contract.pending_states == ["pending", "running"]
                        && contract.completed_state == "completed"
                        && contract.failed_state == "failed"
                        && contract.max_poll_attempts == 30
                        && contract.poll_interval_ms == 1_000
                        && contract.collection_path == COLLECTION
                        && contract.collection_capability_id == "lists-get-list-items"
                        && contract.collection_metadata_path
                            == "/accounts/{account_id}/rules/lists/{list_id}"
                        && contract.collection_metadata_capability_id == "lists-get-a-list"
                        && contract.collection_item_identity_pointer == "/id"
                        && contract.requires_cursor_completion
                        && if create {
                            contract.correlation_field.as_deref() == Some("comment")
                                && contract.remove_capability_id.as_deref()
                                    == Some("security-response-remove-expired-list-member")
                        } else {
                            contract.correlation_field.is_none()
                                && contract.remove_capability_id.is_none()
                        }
                })
    }

    fn created_nested_resource_contract_supported(&self) -> bool {
        self.created_nested_resource.as_ref().is_some_and(|target| {
            let expected_delete_path = format!(
                "{}/{{{}}}",
                self.path.trim_end_matches('/'),
                target.identity_selector
            );
            !target.parent_path.is_empty()
                && !target.items_pointer.is_empty()
                && target.items_pointer.starts_with('/')
                && !target.identity_selector.is_empty()
                && response_identity_pointer_supported(
                    &target.identity_selector,
                    &target.response_item_identity_pointer,
                )
                && !target.correlation_field.is_empty()
                && !target.correlation_field.contains('/')
                && !target.read_capability_id.is_empty()
                && !target.delete_capability_id.is_empty()
                && target.delete_path == expected_delete_path
                && !target.verified_response_fields.is_empty()
                && target
                    .verified_response_fields
                    .binary_search(&target.correlation_field)
                    .is_ok()
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

    fn deleted_nested_resource_contract_supported(&self) -> bool {
        self.deleted_nested_resource.as_ref().is_some_and(|target| {
            let expected_path = format!(
                "{}/{{{}}}",
                target.collection_path.trim_end_matches('/'),
                target.identity_selector
            );
            !target.parent_path.is_empty()
                && !target.collection_path.is_empty()
                && !target.items_pointer.is_empty()
                && target.items_pointer.starts_with('/')
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

fn secret_lifecycle_verification_contract_supported(capability: &CapabilityV1) -> bool {
    match capability.verification.strategy.as_str() {
        "oauth_client_reports_rotated_secret_after_value_roll"
        | "oauth_client_reports_no_rotated_secret_after_old_secret_delete" => {
            oauth_client_secret_verification_contract_supported(capability)
                && capability.same_path_readback_selectors_supported()
        }
        "worker_script_secret_reports_planned_name_and_type_after_put" => {
            worker_script_secret_put_verification_contract_supported(capability)
        }
        _ => false,
    }
}

fn oauth_client_secret_verification_contract_supported(capability: &CapabilityV1) -> bool {
    let operation_supported = matches!(
        (
            capability.id.as_str(),
            capability.method.as_str(),
            capability.verification.strategy.as_str(),
        ),
        (
            "oauth-clients-rotate-secret",
            "POST",
            "oauth_client_reports_rotated_secret_after_value_roll",
        ) | (
            "oauth-clients-delete-rotated-secret",
            "DELETE",
            "oauth_client_reports_no_rotated_secret_after_old_secret_delete",
        )
    );
    operation_supported
        && capability.product == "OAuth Clients"
        && capability.account_scope == "account"
        && capability.permissions == ["OAuth Client Write"]
        && capability.path == "/accounts/{account_id}/oauth_clients/{oauth_client_id}/rotate_secret"
        && capability.request_schema.is_none()
        && capability.selectors.len() == 2
        && ["account_id", "oauth_client_id"].iter().all(|name| {
            capability.selectors.iter().any(|selector| {
                selector.name == *name
                    && selector.location == "path"
                    && selector.required
                    && selector.value_type == "string"
            })
        })
        && capability.same_path_read.as_ref().is_some_and(|read| {
            read.path == "/accounts/{account_id}/oauth_clients/{oauth_client_id}"
                && read.read_capability_id == "oauth-clients-get"
                && read.verified_response_fields == ["client_id", "has_rotated_secret"]
        })
}

fn worker_script_secret_put_verification_contract_supported(capability: &CapabilityV1) -> bool {
    capability.id == "worker-put-script-secret"
        && capability.method == "PUT"
        && capability.product == "Worker Script"
        && capability.account_scope == "account"
        && capability.permissions == ["Workers Scripts Write"]
        && capability.path == "/accounts/{account_id}/workers/scripts/{script_name}/secrets"
        && capability.selectors.len() == 2
        && [
            (
                "account_id",
                serde_json::json!({"maxLength":32,"type":"string"}),
            ),
            ("script_name", serde_json::json!({"type":"string"})),
        ]
        .iter()
        .all(|(name, schema)| {
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
        && capability.request_schema.as_ref()
            == Some(&serde_json::json!({
                "type":"object",
                "oneOf":[
                    {
                        "type":"object",
                        "required":["name","type","text"],
                        "properties":{
                            "name":{"type":"string"},
                            "type":{"type":"string","enum":["secret_text"]},
                            "text":{"type":"string","writeOnly":true}
                        }
                    },
                    {
                        "type":"object",
                        "required":["name","type","format","algorithm","usages"],
                        "properties":{
                            "name":{"type":"string"},
                            "type":{"type":"string","enum":["secret_key"]},
                            "format":{"type":"string","enum":["raw","pkcs8","spki","jwk"]},
                            "algorithm":{"type":"object"},
                            "usages":{"type":"array","items":{"type":"string","enum":["encrypt","decrypt","sign","verify","deriveKey","deriveBits","wrapKey","unwrapKey"]}},
                            "key_base64":{"type":"string","writeOnly":true},
                            "key_jwk":{"type":"object","writeOnly":true}
                        }
                    }
                ],
                "x-cfctl-body-required":true
            }))
        && capability.same_path_read.as_ref().is_some_and(|read| {
            read.path
                == "/accounts/{account_id}/workers/scripts/{script_name}/secrets/{secret_name}"
                && read.read_capability_id == "worker-get-script-secret"
                && read.verified_response_fields == ["name", "type"]
        })
}

fn access_service_token_refresh_verification_contract_supported(capability: &CapabilityV1) -> bool {
    capability.id == "access-service-tokens-refresh-a-service-token"
        && capability.method == "POST"
        && capability.product == "Access service tokens"
        && capability.account_scope == "account"
        && capability.permissions == ["Access: Service Tokens Write"]
        && capability.path
            == "/accounts/{account_id}/access/service_tokens/{service_token_id}/refresh"
        && capability.request_schema.is_none()
        && capability.selectors.len() == 2
        && access_service_token_refresh_selector_supported(capability, "account_id", 32)
        && access_service_token_refresh_selector_supported(capability, "service_token_id", 36)
        && capability.same_path_read.as_ref().is_some_and(|read| {
            read.path == "/accounts/{account_id}/access/service_tokens/{service_token_id}"
                && read.read_capability_id == "access-service-tokens-get-a-service-token"
                && read.verified_response_fields == ["expires_at", "id"]
        })
}

fn access_service_token_refresh_selector_supported(
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

/// Response-field names that carry secret material in Cloudflare create
/// responses (e.g. an API token's `value`, an R2 credential's `secretAccessKey`).
/// A verification or identity pointer must never resolve to one of these:
/// lifting a secret into an identity slot would echo it into a readback URL or a
/// journal artifact.
///
/// This is the exact set consumed by `redact_secret_payload` in
/// `cfctl-cli/src/runtime.rs`, which matches its arms against this constant and
/// sinks every one of these keys to `[SUNK]` before an envelope is printed or
/// journalled. The `cfctl-cli` test `secret_payload_redaction_mirrors_the_core_set`
/// binds the two together so they cannot drift.
///
/// This is deliberately NOT the set used by `redact_json`/`is_sensitive_key`
/// (above, in this file). That pass is a narrower, suffix-matching
/// defense-in-depth layer over a different slice of key names (e.g.
/// `authorization`, `password`, `cookie`, `*_token`) and sinks to `[REDACTED]`;
/// it is not this identity-pointer guard and must not be conflated with it.
pub const SECRET_FIELD_NAMES: &[&str] = &[
    "value",
    "token",
    "secret",
    "access_token",
    "client_secret",
    "text",
    "key_base64",
    "key_jwk",
    "accessKeyId",
    "secretAccessKey",
    "sessionToken",
];

/// The subset of [`SECRET_FIELD_NAMES`] whose keys carry a single opaque secret
/// string that `find_secret_value` in `cfctl-cli` extracts for a `--value-out`
/// sink.
///
/// The six excluded names are excluded deliberately, and widening this to the
/// full set would be a bug rather than a hardening:
/// - `accessKeyId`/`secretAccessKey`/`sessionToken` and the Access
///   `client_id`/`client_secret` pair are multi-field credential bundles that
///   dedicated extractors emit before the generic scan is ever reached.
/// - `text`/`key_base64`/`key_jwk` are worker-secret *request* fields. That
///   capability is write-only input, never a secret-output read, so matching
///   them here could only latch onto an unrelated response field of the same
///   name.
///
/// `secret_sink_value_keys_are_a_subset_of_secret_field_names` binds this to the
/// redaction set: everything extractable is redactable, but not the reverse.
pub const SECRET_SINK_VALUE_KEYS: &[&str] =
    &["value", "token", "secret", "access_token", "client_secret"];

/// Returns whether an RFC 6901 JSON pointer's leaf segment names a known secret
/// field. Used as a fail-closed guard so a drifted catalog identity pointer can
/// never dereference secret material as a resource identity.
#[must_use]
pub fn pointer_names_secret_field(pointer: &str) -> bool {
    pointer
        .rsplit('/')
        .next()
        .is_some_and(|leaf| SECRET_FIELD_NAMES.contains(&leaf))
}

fn response_identity_pointer_supported(selector: &str, pointer: &str) -> bool {
    // Fail closed: an identity pointer that names a secret field is never
    // supported, regardless of selector shape. Guards against a catalog whose
    // identity pointer drifts onto secret material.
    if pointer_names_secret_field(pointer) {
        return false;
    }
    (selector_can_be_response_id(selector) && pointer == "/id")
        || (selector.ends_with("_name") && pointer == "/name")
        || (selector == "database_id" && pointer == "/uuid")
        || (selector == "site_id" && pointer == "/site_tag")
        || (!selector
            .chars()
            .any(|character| matches!(character, '/' | '~'))
            && pointer.strip_prefix('/') == Some(selector))
}

fn d1_database_create_request_contract_supported(capability: &CapabilityV1) -> bool {
    capability.request_schema.as_ref()
        == Some(&serde_json::json!({
            "properties": {
                "jurisdiction": {"enum": ["eu", "fedramp"], "type": "string"},
                "name": {"type": "string"},
                "primary_location_hint": {
                    "enum": ["wnam", "enam", "weur", "eeur", "apac", "oc"],
                    "type": "string",
                    "x-cfctl-verification-observable": false
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
}

fn kv_namespace_create_rollback_contract_supported(capability: &CapabilityV1) -> bool {
    capability.id == "workers-kv-namespace-create-a-namespace"
        && capability.method == "POST"
        && capability.path == "/accounts/{account_id}/storage/kv/namespaces"
        && capability.product == "Workers KV Namespace"
        && capability.account_scope == "account"
        && capability.mutating
        && capability.verification.strategy
            == "created_resource_contains_planned_fields_by_returned_id"
        && capability.verification_contract_supported()
        && capability.created_resource_contract_supported()
        && capability.created_resource.as_ref().is_some_and(|target| {
            target.detail_path == "/accounts/{account_id}/storage/kv/namespaces/{namespace_id}"
                && target.identity_selector == "namespace_id"
                && target.response_result_identity_pointer == "/id"
                && target.delete_capability_id == "workers-kv-namespace-remove-a-namespace"
        })
}

fn d1_database_create_rollback_contract_supported(capability: &CapabilityV1) -> bool {
    capability.id == "d1-create-database"
        && capability.title == "Create D1 Database"
        && capability.method == "POST"
        && capability.path == "/accounts/{account_id}/d1/database"
        && capability.product == "D1"
        && capability.account_scope == "account"
        && capability.mutating
        && capability.permissions == ["D1 Write"]
        && capability.risk == RiskClass::ScopedWrite
        && capability.effect == EffectClass::ReversibleWrite
        && capability.verification.strategy
            == "created_resource_contains_planned_fields_by_returned_id"
        && capability.verification_contract_supported()
        && d1_database_create_request_contract_supported(capability)
        && capability.created_resource_contract_supported()
        && capability.created_resource.as_ref().is_some_and(|target| {
            target.detail_path == "/accounts/{account_id}/d1/database/{database_id}"
                && target.identity_selector == "database_id"
                && target.response_result_identity_pointer == "/uuid"
                && target.read_capability_id == "d1-get-database"
                && target.delete_capability_id == "d1-delete-database"
        })
}

fn d1_read_replication_request_contract_supported(capability: &CapabilityV1) -> bool {
    let Some(schema) = capability.request_schema.as_ref() else {
        return false;
    };
    let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
        return false;
    };
    let Some(replication) = properties.get("read_replication") else {
        return false;
    };
    let replication_properties = replication.get("properties").and_then(Value::as_object);
    schema.get("type").and_then(Value::as_str) == Some("object")
        && properties.len() == 1
        && replication.get("type").and_then(Value::as_str) == Some("object")
        && replication.get("required")
            == Some(&Value::Array(vec![Value::String("mode".to_owned())]))
        && replication_properties.is_some_and(|properties| {
            properties.len() == 1
                && properties.get("mode").is_some_and(|mode| {
                    mode.get("type").and_then(Value::as_str) == Some("string")
                        && mode.get("enum")
                            == Some(&Value::Array(vec![
                                Value::String("auto".to_owned()),
                                Value::String("disabled".to_owned()),
                            ]))
                })
        })
}

const CLOUDFLARE_TUNNEL_CONFIGURATION_REQUEST_SCHEMA_HASH: &str =
    "sha256:0d3afbf113085d7fe33fb84c2e0194f9b2adffb96917e78d1f9c6e3cef57c2ed";

fn cloudflare_tunnel_configuration_rollback_contract_supported(capability: &CapabilityV1) -> bool {
    capability.id == "cloudflare-tunnel-configuration-put-configuration"
        && capability.method == "PUT"
        && capability.product == "Cloudflare Tunnel Configuration"
        && capability.path == "/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations"
        && capability.account_scope == "account"
        && capability.verification.strategy
            == "same_path_result_contains_planned_fields_after_update"
        && capability.verification_contract_supported()
        && cloudflare_tunnel_configuration_request_contract_supported(capability)
        && capability.same_path_read.as_ref().is_some_and(|read| {
            read.path == "/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations"
                && read.read_capability_id == "cloudflare-tunnel-configuration-get-configuration"
                && read.verified_response_fields == ["config"]
        })
}

fn cloudflare_tunnel_configuration_request_contract_supported(capability: &CapabilityV1) -> bool {
    capability
        .request_schema
        .as_ref()
        .and_then(|schema| canonical_hash_value(schema).ok())
        .as_deref()
        == Some(CLOUDFLARE_TUNNEL_CONFIGURATION_REQUEST_SCHEMA_HASH)
}

const WARP_CONNECTOR_CONFIGURATION_REQUEST_SCHEMA_HASH: &str =
    "sha256:4e5032c727efe10cba31c324f8141a1ea723a8f7ddf4779882e0f06665edef5e";

fn warp_connector_configuration_rollback_contract_supported(capability: &CapabilityV1) -> bool {
    capability.id == "cloudflare-tunnel-configuration-update-warp-connector-configuration"
        && capability.method == "PUT"
        && capability.product == "Cloudflare Tunnel Configuration"
        && capability.path == "/accounts/{account_id}/warp_connector/{tunnel_id}/configurations"
        && capability.account_scope == "account"
        && capability.verification.strategy
            == "same_path_result_contains_planned_fields_after_update"
        && capability.verification_contract_supported()
        && warp_connector_configuration_request_contract_supported(capability)
        && capability.same_path_read.as_ref().is_some_and(|read| {
            read.path == "/accounts/{account_id}/warp_connector/{tunnel_id}/configurations"
                && read.read_capability_id
                    == "cloudflare-tunnel-configuration-get-warp-connector-configuration"
                && read.verified_response_fields == ["config", "ha_mode"]
        })
}

fn warp_connector_configuration_request_contract_supported(capability: &CapabilityV1) -> bool {
    capability
        .request_schema
        .as_ref()
        .and_then(|schema| canonical_hash_value(schema).ok())
        .as_deref()
        == Some(WARP_CONNECTOR_CONFIGURATION_REQUEST_SCHEMA_HASH)
}

const WEB_ANALYTICS_RUM_REQUEST_SCHEMA_HASH: &str =
    "sha256:9499b763c96acee1138259b42b03394f697b0b812266c7b8b085cf3bb1fcc65d";

fn web_analytics_rum_rollback_contract_supported(capability: &CapabilityV1) -> bool {
    capability.id == "web-analytics-toggle-rum"
        && capability.method == "PATCH"
        && capability.product == "Web Analytics"
        && capability.path == "/zones/{zone_id}/settings/rum"
        && capability.account_scope == "zone"
        && capability.verification.strategy
            == "same_path_result_contains_planned_fields_after_update"
        && capability.verification_contract_supported()
        && capability
            .request_schema
            .as_ref()
            .and_then(|schema| canonical_hash_value(schema).ok())
            .as_deref()
            == Some(WEB_ANALYTICS_RUM_REQUEST_SCHEMA_HASH)
        && capability.same_path_read.as_ref().is_some_and(|read| {
            read.path == "/zones/{zone_id}/settings/rum"
                && read.read_capability_id == "web-analytics-get-rum-status"
                && read.verified_response_fields == ["value"]
        })
}

const DNS_RECORD_UPDATE_REQUEST_SCHEMA_HASH: &str =
    "sha256:13a888c46013d663dc09187c7a625ab91a8d9ffbcdc68ce4a294e14d3ab279f9";

fn dns_record_update_request_contract_supported(capability: &CapabilityV1) -> bool {
    capability
        .request_schema
        .as_ref()
        .and_then(|schema| canonical_hash_value(schema).ok())
        .as_deref()
        == Some(DNS_RECORD_UPDATE_REQUEST_SCHEMA_HASH)
}

const MAX_REQUEST_OBJECT_SCHEMA_DEPTH: usize = 64;
const MAX_REQUEST_OBJECT_SCHEMA_STEPS: usize = 4_096;

fn collect_discriminated_object_branches<'a>(
    schema: &'a Value,
    discriminator: &str,
    depth: usize,
    remaining_steps: &mut usize,
    branches: &mut Vec<(String, &'a Value)>,
) -> Option<()> {
    if depth > MAX_REQUEST_OBJECT_SCHEMA_DEPTH || *remaining_steps == 0 {
        return None;
    }
    *remaining_steps -= 1;
    let mut direct_fields = BTreeMap::new();
    collect_direct_and_all_of_property_schemas(schema, depth, remaining_steps, &mut direct_fields)?;
    if let Some(value) = direct_fields
        .get(discriminator)
        .and_then(|schemas| exact_single_string_enum(schemas))
    {
        branches.push((value, schema));
        return Some(());
    }
    for composition in ["oneOf", "anyOf"] {
        let Some(members) = schema.get(composition) else {
            continue;
        };
        let members = members.as_array().filter(|members| !members.is_empty())?;
        for member in members {
            collect_discriminated_object_branches(
                member,
                discriminator,
                depth + 1,
                remaining_steps,
                branches,
            )?;
        }
    }
    Some(())
}

fn collect_direct_and_all_of_property_schemas<'a>(
    schema: &'a Value,
    depth: usize,
    remaining_steps: &mut usize,
    fields: &mut BTreeMap<String, Vec<&'a Value>>,
) -> Option<()> {
    if depth > MAX_REQUEST_OBJECT_SCHEMA_DEPTH || *remaining_steps == 0 {
        return None;
    }
    *remaining_steps -= 1;
    match schema.get("type") {
        None => {}
        Some(Value::String(value_type)) if value_type == "object" => {}
        _ => return Some(()),
    }
    if let Some(properties) = schema.get("properties") {
        for (name, property_schema) in properties.as_object()? {
            fields
                .entry(name.clone())
                .or_default()
                .push(property_schema);
        }
    }
    if let Some(members) = schema.get("allOf") {
        for member in members.as_array().filter(|members| !members.is_empty())? {
            collect_direct_and_all_of_property_schemas(member, depth + 1, remaining_steps, fields)?;
        }
    }
    Some(())
}

fn exact_single_string_enum(schemas: &[&Value]) -> Option<String> {
    let mut values = BTreeSet::new();
    for schema in schemas {
        if schema.get("type").and_then(Value::as_str) != Some("string") {
            return None;
        }
        let entries = schema.get("enum")?.as_array()?;
        if entries.len() != 1 {
            return None;
        }
        values.insert(entries.first()?.as_str()?.to_owned());
    }
    let mut values = values.into_iter();
    let value = values.next()?;
    values.next().is_none().then_some(value)
}

fn collect_request_property_paths(
    schemas: &[&Value],
    prefix: &str,
    depth: usize,
    remaining_steps: &mut usize,
    paths: &mut BTreeSet<String>,
) -> Option<()> {
    if depth > MAX_REQUEST_OBJECT_SCHEMA_DEPTH || *remaining_steps == 0 || schemas.is_empty() {
        return None;
    }
    let mut nested_fields = BTreeMap::new();
    let mut object_schemas = 0_usize;
    let mut scalar_schemas = 0_usize;
    for schema in schemas {
        let mut fields = BTreeMap::new();
        match collect_composed_object_property_schemas(
            schema,
            depth + 1,
            remaining_steps,
            &mut fields,
        ) {
            RequestObjectSchemaCollection::Object if !fields.is_empty() => {
                object_schemas += 1;
                merge_request_object_property_schemas(&mut nested_fields, fields);
            }
            RequestObjectSchemaCollection::Object | RequestObjectSchemaCollection::Ineligible => {
                scalar_schemas += 1;
            }
            RequestObjectSchemaCollection::LimitExceeded => return None,
        }
    }
    if object_schemas > 0 && scalar_schemas > 0 {
        return None;
    }
    if object_schemas == 0 {
        paths.insert(prefix.to_owned());
        return Some(());
    }
    for (name, schemas) in nested_fields {
        collect_request_property_paths(
            &schemas,
            &format!("{prefix}.{name}"),
            depth + 1,
            remaining_steps,
            paths,
        )?;
    }
    Some(())
}

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

fn property_schemas_are_verification_omitted(schemas: &[&Value]) -> bool {
    if schemas.is_empty() {
        return false;
    }
    let mut remaining_steps = MAX_REQUEST_OBJECT_SCHEMA_STEPS;
    schemas
        .iter()
        .all(|schema| schema_declares_verification_omitted(schema, 0, &mut remaining_steps))
}

fn collect_verification_response_field_names(
    schema: &Value,
    depth: usize,
    remaining_steps: &mut usize,
    names: &mut BTreeSet<String>,
) {
    if depth > MAX_REQUEST_OBJECT_SCHEMA_DEPTH || *remaining_steps == 0 {
        return;
    }
    *remaining_steps -= 1;
    if let Some(name) = schema
        .get("x-cfctl-verification-response-field")
        .and_then(Value::as_str)
        .filter(|name| {
            !name.is_empty()
                && name
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '_')
        })
    {
        names.insert(name.to_owned());
    }
    for composition in ["allOf", "oneOf", "anyOf"] {
        for member in schema
            .get(composition)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            collect_verification_response_field_names(member, depth + 1, remaining_steps, names);
        }
    }
}

fn schema_declares_verification_omitted(
    schema: &Value,
    depth: usize,
    remaining_steps: &mut usize,
) -> bool {
    if depth > MAX_REQUEST_OBJECT_SCHEMA_DEPTH || *remaining_steps == 0 {
        return false;
    }
    *remaining_steps -= 1;
    if schema.get("writeOnly").and_then(Value::as_bool) == Some(true)
        || schema
            .get("x-cfctl-verification-observable")
            .and_then(Value::as_bool)
            == Some(false)
    {
        return true;
    }
    if schema
        .get("allOf")
        .and_then(Value::as_array)
        .is_some_and(|members| {
            members.iter().any(|member| {
                schema_declares_verification_omitted(member, depth + 1, remaining_steps)
            })
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
                        schema_declares_verification_omitted(member, depth + 1, remaining_steps)
                    })
            })
    })
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

/// A singleton sub-resource path: a terminal literal segment (not a path
/// parameter) beneath at least one identified parent parameter — e.g.
/// `/accounts/{account_id}/access/apps/{app_id}/ca`. Structurally this is a
/// necessary-but-not-sufficient signal (a collection path like `.../rules` also
/// matches); the sufficient proof that it is a single resource is the bound
/// same-path readback contract, which the catalog only attaches after
/// confirming the readback GET returns a single object rather than an array.
fn path_targets_singleton_subresource(path: &str) -> bool {
    let terminal_is_literal = path.rsplit('/').next().is_some_and(|segment| {
        !(segment.is_empty() || segment.starts_with('{') && segment.ends_with('}'))
    });
    terminal_is_literal && path.contains('{')
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

/// Machine-readable availability state for one capability-guide stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuideContractStateV1 {
    Available,
    Blocked,
    ManualReview,
    NotApplicable,
    LiveReadRequired,
}

/// One safe next action emitted by a guide document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuideActionV1 {
    pub summary: String,
    pub argv: Vec<String>,
}

/// Typed form of one stage in the existing capability-guide JSON contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityGuideStageV1 {
    pub stage: usize,
    pub name: GuideStage,
    pub capability_id: String,
    pub required: bool,
    pub contract_state: GuideContractStateV1,
    pub summary: String,
    pub evidence_class: EvidenceClass,
    pub commands: Vec<Vec<String>>,
}

/// Typed form of the existing `cfctl guide <capability-id>` JSON payload.
///
/// This deliberately has no additional discriminator or schema field so its
/// serialized shape remains compatible with the previously untyped payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityGuideV1 {
    pub capability: CapabilityV1,
    pub contract_state: GuideContractStateV1,
    pub blocking_gaps: Vec<String>,
    pub blocked_reason: Option<String>,
    pub call_argv: Option<Vec<String>>,
    pub post_resolution_call_argv: Vec<String>,
    pub next_action: GuideActionV1,
    pub stages: Vec<CapabilityGuideStageV1>,
}

/// Stable system-level topics exposed through `cfctl guide --topic`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuideTopicV1 {
    System,
    StandingAuthority,
}

impl GuideTopicV1 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::StandingAuthority => "standing-authority",
        }
    }

    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::System => "How cfctl works",
            Self::StandingAuthority => "Standing authority lifecycle",
        }
    }
}

/// The five operator questions every system-level guide must answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuideQuestionV1 {
    MutatesCloudflare,
    GrantsAuthority,
    PersistsState,
    FailureRecovery,
    NextAction,
}

impl GuideQuestionV1 {
    #[must_use]
    pub const fn prompt(self) -> &'static str {
        match self {
            Self::MutatesCloudflare => "Will this mutate Cloudflare now?",
            Self::GrantsAuthority => "What grants authority?",
            Self::PersistsState => "What is persisted?",
            Self::FailureRecovery => "What happens after a failure or crash?",
            Self::NextAction => "What should I do next?",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuideCloudflareEffectV1 {
    None,
    Read,
    Write,
}

impl GuideCloudflareEffectV1 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuideAnswerV1 {
    pub question: GuideQuestionV1,
    pub answer: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuideFlowStepV1 {
    pub stage: u8,
    pub name: String,
    pub summary: String,
    pub cloudflare_effect: GuideCloudflareEffectV1,
    pub durable_state: Option<String>,
}

/// Versioned system explanation projected into CLI JSON and checked-in docs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuideTopicDocumentV1 {
    pub schema_version: u8,
    pub topic: GuideTopicV1,
    pub title: String,
    pub summary: String,
    pub answers: Vec<GuideAnswerV1>,
    pub flow: Vec<GuideFlowStepV1>,
    pub commands: Vec<Vec<String>>,
    pub next_action: GuideActionV1,
}

#[must_use]
pub fn guide_topic_document(topic: GuideTopicV1) -> GuideTopicDocumentV1 {
    match topic {
        GuideTopicV1::System => system_guide_document(),
        GuideTopicV1::StandingAuthority => standing_authority_guide_document(),
    }
}

#[must_use]
pub fn render_guide_topic_markdown(topic: GuideTopicV1) -> String {
    let document = guide_topic_document(topic);
    render_guide_topic_document_markdown(&document)
}

/// Render an already-materialized topic document without consulting mutable
/// runtime state. This keeps human CLI output and checked-in projections on
/// the exact same typed document.
#[must_use]
pub fn render_guide_topic_document_markdown(document: &GuideTopicDocumentV1) -> String {
    let mut markdown = format!("## {}\n\n{}\n\n", document.title, document.summary);
    for answer in &document.answers {
        if write!(
            markdown,
            "**{}** {}\n\n",
            answer.question.prompt(),
            answer.answer
        )
        .is_err()
        {
            return markdown;
        }
    }
    markdown.push_str("### Lifecycle\n\n");
    for step in &document.flow {
        let durable_state = step
            .durable_state
            .as_deref()
            .map_or_else(String::new, |state| format!(" Durable state: {state}"));
        if writeln!(
            markdown,
            "{}. **{}** (`{}`) — {}{}",
            step.stage,
            step.name,
            step.cloudflare_effect.as_str(),
            step.summary,
            durable_state
        )
        .is_err()
        {
            return markdown;
        }
    }
    markdown.push_str("\n### Commands\n\n```bash\n");
    for command in &document.commands {
        markdown.push_str(&command.join(" "));
        markdown.push('\n');
    }
    markdown.push_str("```\n");
    markdown
}

fn guide_answer(question: GuideQuestionV1, answer: &str) -> GuideAnswerV1 {
    GuideAnswerV1 {
        question,
        answer: answer.to_owned(),
    }
}

fn guide_flow_step(
    stage: u8,
    name: &str,
    summary: &str,
    cloudflare_effect: GuideCloudflareEffectV1,
    durable_state: Option<&str>,
) -> GuideFlowStepV1 {
    GuideFlowStepV1 {
        stage,
        name: name.to_owned(),
        summary: summary.to_owned(),
        cloudflare_effect,
        durable_state: durable_state.map(str::to_owned),
    }
}

fn guide_argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(ToString::to_string).collect()
}

fn system_guide_document() -> GuideTopicDocumentV1 {
    let next_argv = guide_argv(&["cfctl", "resolve", "<intent>", "--json"]);
    GuideTopicDocumentV1 {
        schema_version: 1,
        topic: GuideTopicV1::System,
        title: GuideTopicV1::System.title().to_owned(),
        summary: "cfctl is a local-first, catalog-driven control plane: it separates intent, live reads, durable authority, one Cloudflare boundary, verification, and evidence.".to_owned(),
        answers: system_guide_answers(),
        flow: system_guide_flow(),
        commands: system_guide_commands(&next_argv),
        next_action: GuideActionV1 {
            summary: "Resolve the intended Cloudflare outcome to one catalog capability.".to_owned(),
            argv: next_argv,
        },
    }
}

fn system_guide_answers() -> Vec<GuideAnswerV1> {
    vec![
        guide_answer(
            GuideQuestionV1::MutatesCloudflare,
            "Discovery, guides, workspace inspection, and read capabilities do not write Cloudflare. A mutating `cfctl call` creates a plan; `cfctl plans run` is the normal write boundary. A token command with `--under-policy` may plan and run in one invocation only under an explicitly approved standing authority. Agent output, guide output, and approval alone do not mutate Cloudflare.",
        ),
        guide_answer(
            GuideQuestionV1::GrantsAuthority,
            "The deterministic policy engine grants automatic admission only to the narrow safe class. Otherwise authority is either explicit approval of one reviewed operation ID or explicit approval of one bounded standing token policy. A model never grants authority.",
        ),
        guide_answer(
            GuideQuestionV1::PersistsState,
            "Under its managed state root, cfctl persists profile metadata, the live CapabilityV1 catalog and official-doc caches, workspace registrations and imports, plans, approval and admission checkpoints, transaction journals, standing-authority records, locks, and redacted evidence. Credential values remain in the platform secret store or an explicit mode-0600 sink. The source checkout's compat/v1 tree is inert migration evidence, not runtime state or a live catalog.",
        ),
        guide_answer(
            GuideQuestionV1::FailureRecovery,
            "Once consumption or a boundary attempt is durable, cfctl never guesses that replay is safe. Inspect `plans status`; use `plans rectify` to reconcile durable receipts and verification without replaying the original Cloudflare mutation.",
        ),
        guide_answer(
            GuideQuestionV1::NextAction,
            "Run `cfctl version --json` and both doctors before work; running-build, PATH-build, or managed-instruction drift is unhealthy. Read token permissions only with an explicit account context (`keys permissions --account`, adding `--user` only to select user ownership). Nested fixture basenames are skipped during broader workspace scans; fixture directories are opt-in roots and must be registered directly. Then resolve the intent deterministically (`cfctl resolve`), browse with `cfctl catalog search` only when exploring, and inspect the selected capability and its capability-specific guide before calling it.",
        ),
    ]
}

fn system_guide_flow() -> Vec<GuideFlowStepV1> {
    vec![
        guide_flow_step(
            1,
            "Orient",
            "Check running and PATH build identity, local state, credentials, catalog health, and agent integration.",
            GuideCloudflareEffectV1::None,
            None,
        ),
        guide_flow_step(
            2,
            "Discover",
            "Resolve the intent to the catalog-selected capability and adapter; browse the catalog when exploring.",
            GuideCloudflareEffectV1::None,
            None,
        ),
        guide_flow_step(
            3,
            "Read",
            "Inspect exact live Cloudflare state and registered-workspace impact.",
            GuideCloudflareEffectV1::Read,
            Some("redacted live-read and source-config evidence"),
        ),
        guide_flow_step(
            4,
            "Plan",
            "Bind the request, account, catalog, impact, cost, verification, and compensation contracts.",
            GuideCloudflareEffectV1::None,
            Some("hash-bound PlanV1 and PlanPrepared checkpoint"),
        ),
        guide_flow_step(
            5,
            "Admit",
            "Apply policy, bind any explicit approval, acquire locks, and recheck drift.",
            GuideCloudflareEffectV1::None,
            Some("approval, standing reservation, and consumption checkpoints"),
        ),
        guide_flow_step(
            6,
            "Execute",
            "Persist the boundary attempt, then cross exactly one catalog-selected adapter boundary.",
            GuideCloudflareEffectV1::Write,
            Some("boundary-attempt and response checkpoints"),
        ),
        guide_flow_step(
            7,
            "Verify",
            "Run the operation-specific verifier or record why rectification is required.",
            GuideCloudflareEffectV1::Read,
            Some("sink and verification receipts"),
        ),
        guide_flow_step(
            8,
            "Close or rectify",
            "Close with evidence or reconcile the durable journal; any compensation is a new plan with independent authority.",
            GuideCloudflareEffectV1::None,
            Some("terminal plan status and content-addressed evidence"),
        ),
    ]
}

fn system_guide_commands(next_argv: &[String]) -> Vec<Vec<String>> {
    vec![
        guide_argv(&["cfctl", "version", "--json"]),
        guide_argv(&["cfctl", "doctor", "--json"]),
        guide_argv(&["cfctl", "agents", "doctor", "--json"]),
        guide_argv(&[
            "cfctl",
            "keys",
            "permissions",
            "--account",
            "<account-id>",
            "--json",
        ]),
        guide_argv(&[
            "cfctl",
            "keys",
            "permissions",
            "--user",
            "--account",
            "<account-id>",
            "--json",
        ]),
        guide_argv(&["cfctl", "guide", "--topic", "standing-authority", "--json"]),
        next_argv.to_vec(),
        guide_argv(&["cfctl", "catalog", "search", "<intent>", "--json"]),
        guide_argv(&["cfctl", "catalog", "show", "<capability-id>", "--json"]),
        guide_argv(&["cfctl", "guide", "<capability-id>", "--json"]),
        guide_argv(&["cfctl", "call", "<capability-id>", "--json"]),
        guide_argv(&["cfctl", "plans", "show", "<operation-id>", "--json"]),
        guide_argv(&[
            "cfctl",
            "plans",
            "approve",
            "<operation-id>",
            "--yes",
            "--json",
        ]),
        guide_argv(&["cfctl", "plans", "run", "<operation-id>", "--json"]),
        guide_argv(&["cfctl", "plans", "status", "<operation-id>", "--json"]),
        guide_argv(&["cfctl", "plans", "rectify", "<operation-id>", "--json"]),
    ]
}

fn standing_authority_guide_document() -> GuideTopicDocumentV1 {
    let next_argv = guide_argv(&[
        "cfctl",
        "keys",
        "permissions",
        "--account",
        "<account-id>",
        "--json",
    ]);
    GuideTopicDocumentV1 {
        schema_version: 1,
        topic: GuideTopicV1::StandingAuthority,
        title: GuideTopicV1::StandingAuthority.title().to_owned(),
        summary: "Standing authority is the bounded token-lifecycle exception: one explicitly approved local policy may admit matching token mints and lineage-bound revocations without per-operation approval.".to_owned(),
        answers: standing_authority_guide_answers(),
        flow: standing_authority_guide_flow(),
        commands: standing_authority_guide_commands(&next_argv),
        next_action: GuideActionV1 {
            summary: "Read the account permission inventory before drafting a policy.".to_owned(),
            argv: next_argv,
        },
    }
}

fn standing_authority_guide_answers() -> Vec<GuideAnswerV1> {
    vec![
        guide_answer(
            GuideQuestionV1::MutatesCloudflare,
            "Permission reads and policy create, list, approve, and revoke are local or read-only. A matching `keys mint --under-policy` or lineage-bound token revoke may cross the Cloudflare boundary after durable admission.",
        ),
        guide_answer(
            GuideQuestionV1::GrantsAuthority,
            "Only `cfctl keys policy approve <authority-id> --yes` activates the exact reviewed policy. Its account, capabilities, permission allowlist, token-name prefix, child TTL, rate budget, expiry, and content hash remain binding.",
        ),
        guide_answer(
            GuideQuestionV1::PersistsState,
            "cfctl persists the schema-v1 authority document, approval, run reservations, plan journals, reconciled minted-token lineage, and redacted evidence. The one-time token value goes only to the requested mode-0600 sink.",
        ),
        guide_answer(
            GuideQuestionV1::FailureRecovery,
            "Revocation blocks runs not yet durably admitted; an already durably admitted run may finish. A validated boundary receipt is reconciled into lineage even after sink or verification failure, and later recovery never replays the Cloudflare mutation.",
        ),
        guide_answer(
            GuideQuestionV1::NextAction,
            "Read the fresh account permission inventory, then create a narrow policy using exact permission IDs or unambiguous exact names.",
        ),
    ]
}

fn standing_authority_guide_flow() -> Vec<GuideFlowStepV1> {
    vec![
        guide_flow_step(
            1,
            "Read permissions",
            "Fetch one fresh account-owned permission inventory.",
            GuideCloudflareEffectV1::Read,
            Some("live permission receipt"),
        ),
        guide_flow_step(
            2,
            "Create policy",
            "Resolve the allowlist and bind every standing-authority limit.",
            GuideCloudflareEffectV1::None,
            Some("pending StandingAuthorityV1"),
        ),
        guide_flow_step(
            3,
            "Approve policy",
            "Review the exact authority ID and activate it with explicit `--yes`.",
            GuideCloudflareEffectV1::None,
            Some("approved authority content hash"),
        ),
        guide_flow_step(
            4,
            "Admit child",
            "Recheck the child subset and complete allowlist, reserve the run under lock, and consume the child plan.",
            GuideCloudflareEffectV1::None,
            Some("run reservation and plan consumption"),
        ),
        guide_flow_step(
            5,
            "Execute child",
            "Release the authority lock, then mint or revoke exactly within the approved bounds.",
            GuideCloudflareEffectV1::Write,
            Some("boundary attempt and response"),
        ),
        guide_flow_step(
            6,
            "Sink and reconcile",
            "Write the one-time secret sink and reconcile any created token ID from the validated response.",
            GuideCloudflareEffectV1::None,
            Some("secret-sink receipt and minted-token lineage"),
        ),
        guide_flow_step(
            7,
            "Verify",
            "Verify the remote token identity and status or require rectification without replay.",
            GuideCloudflareEffectV1::Read,
            Some("verification receipt and final plan status"),
        ),
        guide_flow_step(
            8,
            "Revoke policy",
            "Close future admission immediately; already minted child tokens remain separate resources.",
            GuideCloudflareEffectV1::None,
            Some("monotonic revoked authority status"),
        ),
    ]
}

fn standing_authority_guide_commands(next_argv: &[String]) -> Vec<Vec<String>> {
    vec![
        next_argv.to_vec(),
        guide_argv(&[
            "cfctl",
            "keys",
            "policy",
            "create",
            "--account",
            "<account-id>",
            "--name-prefix",
            "<token-prefix>",
            "--permission",
            "<permission-group-id>",
            "--max-child-ttl-hours",
            "24",
            "--max-runs-per-day",
            "4",
            "--expires-days",
            "30",
            "--json",
        ]),
        guide_argv(&["cfctl", "keys", "policy", "list", "--json"]),
        guide_argv(&[
            "cfctl",
            "keys",
            "policy",
            "approve",
            "<authority-id>",
            "--yes",
            "--json",
        ]),
        guide_argv(&[
            "cfctl",
            "keys",
            "mint",
            "--name",
            "<token-name>",
            "--permission",
            "<permission-group-id>",
            "--account",
            "<account-id>",
            "--ttl-hours",
            "12",
            "--value-out",
            "<new-mode-0600-path>",
            "--under-policy",
            "<authority-id>",
            "--json",
        ]),
        guide_argv(&["cfctl", "keys", "policy", "list", "--json"]),
        guide_argv(&[
            "cfctl",
            "keys",
            "policy",
            "revoke",
            "<authority-id>",
            "--json",
        ]),
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
    Cancelled,
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
    /// When the plan's latent authority was explicitly retired. Outside the
    /// reviewed content hash, like `status` and `approval`, so cancellation
    /// bookkeeping cannot drift an approved hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancelled_at: Option<DateTime<Utc>>,
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
            cancelled_at: None,
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

    pub fn approve(&mut self, explicit_yes: bool, mut max_cost: Option<MoneyV1>) -> Result<()> {
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
        if let Some(approved) = max_cost.as_mut() {
            validate_money(approved).map_err(|reason| CoreError::InvalidCostCeiling {
                operation_id: self.operation_id.clone(),
                reason,
            })?;
            approved.currency.make_ascii_uppercase();
        }
        if self.capability.cost.incremental && self.capability.cost.known {
            let required =
                self.capability
                    .cost
                    .maximum
                    .ok_or_else(|| CoreError::InvalidCostCeiling {
                        operation_id: self.operation_id.clone(),
                        reason: "known incremental cost has no declared maximum".to_owned(),
                    })?;
            let currency = self.capability.cost.currency.as_deref().ok_or_else(|| {
                CoreError::InvalidCostCeiling {
                    operation_id: self.operation_id.clone(),
                    reason: "known incremental cost has no declared currency".to_owned(),
                }
            })?;
            validate_money_fields(currency, required).map_err(|reason| {
                CoreError::InvalidCostCeiling {
                    operation_id: self.operation_id.clone(),
                    reason: format!("declared catalog maximum is invalid: {reason}"),
                }
            })?;
            if let Some(approved) = max_cost.as_ref()
                && (!approved.currency.eq_ignore_ascii_case(currency) || approved.amount < required)
            {
                return Err(CoreError::CostCeilingTooLow {
                    operation_id: self.operation_id.clone(),
                    required_currency: currency.to_owned(),
                    required_amount: required,
                });
            }
        }
        let current_hash = hash_value(&self.hashable_content())?;
        if current_hash != self.content_hash {
            return Err(CoreError::InvalidPlanState {
                operation_id: self.operation_id.clone(),
                actual: self.status,
                expected: "unchanged hash-bound draft",
            });
        }
        let approval = ApprovalV1 {
            approved_at: Utc::now(),
            approved_content_hash: self.content_hash.clone(),
            max_cost,
        };
        let receipt = self.approval_receipt(&approval);
        self.approval = Some(approval);
        self.status = PlanStatus::Approved;
        if let Err(error) = self
            .record_transaction_stage_with_artifact(TransactionStageV1::ApprovalPersisted, receipt)
        {
            self.approval = None;
            self.status = PlanStatus::Draft;
            return Err(error);
        }
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

    /// Consumes an unapproved, approval-required draft under a hash-bound
    /// standing authority instead of a per-operation approval. The caller
    /// must have validated the authority's blast-radius bounds against the
    /// exact execution input first; this method re-checks plan integrity and
    /// the authority's operational state, then records the authority binding
    /// in the transaction journal so every unattended consumption is
    /// attributable to the exact approved grant.
    pub fn mark_consumed_via_standing_authority(
        &mut self,
        authority: &StandingAuthorityV1,
    ) -> Result<()> {
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
        if self.status != PlanStatus::Draft
            || self.approval.is_some()
            || self.policy.disposition != PolicyDisposition::ApprovalRequired
        {
            return Err(CoreError::InvalidPlanState {
                operation_id: self.operation_id.clone(),
                actual: self.status,
                expected: "unapproved approval-required draft for standing-authority consumption",
            });
        }
        authority.ensure_operational()?;
        if authority.account_id != self.account_id {
            return Err(CoreError::StandingAuthorityDenied {
                authority_id: authority.authority_id.clone(),
                reason: format!(
                    "plan account `{}` is outside the authority's pinned account",
                    self.account_id
                ),
            });
        }
        if !authority
            .capability_ids
            .iter()
            .any(|capability_id| capability_id == &self.capability.id)
        {
            return Err(CoreError::StandingAuthorityDenied {
                authority_id: authority.authority_id.clone(),
                reason: format!(
                    "capability `{}` is outside the authority's allowlist",
                    self.capability.id
                ),
            });
        }
        self.status = PlanStatus::Consumed;
        if let Err(error) = self.record_transaction_stage_with_artifact(
            TransactionStageV1::ConsumptionPersisted,
            serde_json::json!({
                "standing_authority_id": authority.authority_id,
                "standing_authority_content_hash": authority.content_hash,
            }),
        ) {
            self.status = PlanStatus::Draft;
            return Err(error);
        }
        Ok(())
    }

    /// Retires the plan's latent authority immediately.
    ///
    /// A draft or approved plan is standing permission to mutate; standing
    /// authorities could always be revoked at any moment, but a plan could
    /// only be consumed or waited out. Cancellation is the symmetric verb.
    ///
    /// It deliberately skips the expiry and content-drift checks the
    /// execution path enforces: refusing to de-authorize a drifted or expired
    /// plan would preserve exactly the authority the caller is retiring.
    /// The transition is journaled as the terminal `Closed` checkpoint — the
    /// transaction closes without a boundary attempt — so the hash chain
    /// stays coherent; a plan whose journal is already corrupt belongs to
    /// storage integrity and `plans rectify`, not to cancellation.
    /// Re-cancelling is a no-op success so a retried cancel never reads as
    /// failure, and the original timestamp is kept. Consumed and later states
    /// are history, not authority, and stay immutable.
    pub fn cancel(&mut self) -> Result<()> {
        match self.status {
            PlanStatus::Draft | PlanStatus::Approved | PlanStatus::Expired => {
                let previous_status = self.status;
                self.status = PlanStatus::Cancelled;
                self.cancelled_at = Some(Utc::now());
                if let Err(error) = self.record_transaction_stage(TransactionStageV1::Closed) {
                    self.status = previous_status;
                    self.cancelled_at = None;
                    return Err(error);
                }
                Ok(())
            }
            PlanStatus::Cancelled => Ok(()),
            _ => Err(CoreError::InvalidPlanState {
                operation_id: self.operation_id.clone(),
                actual: self.status,
                expected: "draft, approved, or expired",
            }),
        }
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
        self.validate_approval_checkpoint(bind_current_status)?;
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

    fn validate_approval_checkpoint(&self, bind_current_status: bool) -> Result<()> {
        let has_approval_checkpoint = self
            .transaction_journal
            .iter()
            .any(|checkpoint| checkpoint.stage == TransactionStageV1::ApprovalPersisted);
        if has_approval_checkpoint {
            let approval = self.approval.as_ref().ok_or_else(|| {
                self.invalid_transaction_journal(
                    "approval checkpoint has no current approval".to_owned(),
                )
            })?;
            if approval.approved_content_hash != self.content_hash {
                return Err(self.invalid_transaction_journal(
                    "approval content hash does not match the current plan".to_owned(),
                ));
            }
            if let Some(max_cost) = approval.max_cost.as_ref()
                && let Err(reason) = validate_money(max_cost)
            {
                return Err(self.invalid_transaction_journal(format!(
                    "approval cost ceiling is invalid: {reason}"
                )));
            }
            let expected_receipt = self.approval_receipt(approval);
            if self.transaction_artifact(TransactionStageV1::ApprovalPersisted)
                != Some(&expected_receipt)
            {
                return Err(self.invalid_transaction_journal(
                    "approval checkpoint does not bind the current approval".to_owned(),
                ));
            }
        } else if bind_current_status && self.approval.is_some() {
            return Err(self.invalid_transaction_journal(
                "current approval has no approval checkpoint".to_owned(),
            ));
        }
        Ok(())
    }

    fn approval_receipt(&self, approval: &ApprovalV1) -> Value {
        serde_json::json!({
            "schema_version": 1,
            "operation_id": self.operation_id,
            "approved_at": approval.approved_at,
            "approved_content_hash": approval.approved_content_hash,
            "max_cost": approval.max_cost,
        })
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

fn validate_money(money: &MoneyV1) -> std::result::Result<(), String> {
    validate_money_fields(&money.currency, money.amount)
}

fn validate_money_fields(currency: &str, amount: f64) -> std::result::Result<(), String> {
    if !valid_currency_code(currency) {
        return Err("currency must be a three-letter ASCII code".to_owned());
    }
    if !amount.is_finite() {
        return Err("amount must be finite".to_owned());
    }
    if amount < 0.0 {
        return Err("amount must not be negative".to_owned());
    }
    Ok(())
}

fn valid_currency_code(currency: &str) -> bool {
    currency.len() == 3 && currency.bytes().all(|byte| byte.is_ascii_alphabetic())
}

fn valid_non_negative_amount(amount: f64) -> bool {
    amount.is_finite() && amount >= 0.0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StandingAuthorityStatus {
    PendingApproval,
    Active,
    Revoked,
}

impl StandingAuthorityStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PendingApproval => "pending_approval",
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StandingAuthorityRunV1 {
    pub at: DateTime<Utc>,
    pub operation_id: String,
    pub capability_id: String,
}

/// A one-time-approved, hash-bound, TTL- and scope-bounded authorization
/// under which recurring token-lifecycle plans may be consumed unattended.
/// The bounds are the defensibility core: an authority can only produce
/// strictly-weaker, name-scoped, expiring child tokens, and can only revoke
/// tokens it minted itself. Granting one is itself an explicit approval
/// ceremony; revocation is immediate and unconditional.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StandingAuthorityV1 {
    pub schema_version: u8,
    pub authority_id: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub account_id: String,
    /// When set, child tokens may additionally bind this one zone's resource.
    /// Absent means the authority is account-scoped only, which is how every
    /// authority drafted before zone support behaves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone_id: Option<String>,
    pub capability_ids: Vec<String>,
    pub permission_group_ids: Vec<String>,
    pub permission_inventory_hash: String,
    pub max_child_ttl_hours: u32,
    pub name_prefix: String,
    pub max_runs_per_day: u32,
    pub status: StandingAuthorityStatus,
    pub approval: Option<ApprovalV1>,
    #[serde(default)]
    pub minted_token_ids: Vec<String>,
    #[serde(default)]
    pub run_log: Vec<StandingAuthorityRunV1>,
    pub content_hash: String,
}

impl StandingAuthorityV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn draft(
        account_id: &str,
        zone_id: Option<&str>,
        capability_ids: Vec<String>,
        mut permission_group_ids: Vec<String>,
        permission_inventory_hash: &str,
        max_child_ttl_hours: u32,
        name_prefix: &str,
        max_runs_per_day: u32,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        permission_group_ids.sort();
        permission_group_ids.dedup();
        let mut authority = Self {
            schema_version: 1,
            authority_id: Uuid::new_v4().to_string(),
            created_at: Utc::now(),
            expires_at,
            account_id: account_id.to_owned(),
            zone_id: zone_id.map(str::to_owned),
            capability_ids,
            permission_group_ids,
            permission_inventory_hash: permission_inventory_hash.to_owned(),
            max_child_ttl_hours,
            name_prefix: name_prefix.to_owned(),
            max_runs_per_day,
            status: StandingAuthorityStatus::PendingApproval,
            approval: None,
            minted_token_ids: Vec::new(),
            run_log: Vec::new(),
            content_hash: String::new(),
        };
        authority.refresh_hash()?;
        Ok(authority)
    }

    /// The reviewed grant content. Excludes status, approval, and the
    /// mutable run accounting so post-approval bookkeeping cannot drift the
    /// approved hash.
    ///
    /// `zone_id` is included only when present, so an account-scoped authority
    /// hashes exactly as it did before zone support existed and previously
    /// approved authorities keep validating.
    fn hashable_content(&self) -> Value {
        let mut content = serde_json::json!({
            "schema_version": self.schema_version,
            "authority_id": self.authority_id,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "account_id": self.account_id,
            "capability_ids": self.capability_ids,
            "permission_group_ids": self.permission_group_ids,
            "permission_inventory_hash": self.permission_inventory_hash,
            "max_child_ttl_hours": self.max_child_ttl_hours,
            "name_prefix": self.name_prefix,
            "max_runs_per_day": self.max_runs_per_day,
        });
        if let Some(zone_id) = &self.zone_id
            && let Some(object) = content.as_object_mut()
        {
            object.insert("zone_id".to_owned(), Value::String(zone_id.clone()));
        }
        content
    }

    /// Every token resource a child minted under this authority may bind.
    /// The account resource is always permitted; the zone resource only when
    /// the authority pinned that zone at draft time.
    #[must_use]
    pub fn allowed_token_resources(&self) -> Vec<String> {
        let mut resources = vec![format!("com.cloudflare.api.account.{}", self.account_id)];
        if let Some(zone_id) = &self.zone_id {
            resources.push(format!("com.cloudflare.api.account.zone.{zone_id}"));
        }
        resources
    }

    pub fn refresh_hash(&mut self) -> Result<()> {
        self.content_hash = hash_value(&self.hashable_content())?;
        Ok(())
    }

    pub fn approve(&mut self, explicit_yes: bool) -> Result<()> {
        if !explicit_yes {
            return Err(CoreError::ExplicitApprovalRequired);
        }
        if self.status != StandingAuthorityStatus::PendingApproval {
            return Err(CoreError::InvalidStandingAuthorityState {
                authority_id: self.authority_id.clone(),
                actual: self.status.as_str().to_owned(),
                expected: "pending_approval",
            });
        }
        if Utc::now() > self.expires_at {
            return Err(CoreError::StandingAuthorityExpired {
                authority_id: self.authority_id.clone(),
                expires_at: self.expires_at,
            });
        }
        let current_hash = hash_value(&self.hashable_content())?;
        if current_hash != self.content_hash {
            return Err(CoreError::InvalidStandingAuthorityState {
                authority_id: self.authority_id.clone(),
                actual: "hash-drifted".to_owned(),
                expected: "unchanged hash-bound grant",
            });
        }
        self.approval = Some(ApprovalV1 {
            approved_at: Utc::now(),
            approved_content_hash: self.content_hash.clone(),
            max_cost: None,
        });
        self.status = StandingAuthorityStatus::Active;
        Ok(())
    }

    /// Revocation is the fail-closed direction: always permitted, from any
    /// state, effective immediately.
    pub fn revoke(&mut self) {
        self.status = StandingAuthorityStatus::Revoked;
    }

    /// The operator-visible status at a specific time. Expiry is derived so
    /// the durable schema remains v1, while revocation retains precedence as
    /// the monotonic fail-closed state.
    #[must_use]
    pub fn effective_status(&self, now: DateTime<Utc>) -> &'static str {
        if self.status == StandingAuthorityStatus::Revoked {
            StandingAuthorityStatus::Revoked.as_str()
        } else if now > self.expires_at {
            "expired"
        } else {
            self.status.as_str()
        }
    }

    /// Active, unexpired, and still carrying an approval bound to the exact
    /// current grant content.
    pub fn ensure_operational(&self) -> Result<()> {
        self.ensure_operational_at(Utc::now())
    }

    fn ensure_operational_at(&self, now: DateTime<Utc>) -> Result<()> {
        if self.status != StandingAuthorityStatus::Active {
            return Err(CoreError::InvalidStandingAuthorityState {
                authority_id: self.authority_id.clone(),
                actual: self.status.as_str().to_owned(),
                expected: "active",
            });
        }
        if now > self.expires_at {
            return Err(CoreError::StandingAuthorityExpired {
                authority_id: self.authority_id.clone(),
                expires_at: self.expires_at,
            });
        }
        let current_hash = hash_value(&self.hashable_content())?;
        let approval_matches = self
            .approval
            .as_ref()
            .is_some_and(|approval| approval.approved_content_hash == current_hash);
        if current_hash != self.content_hash || !approval_matches {
            return Err(CoreError::InvalidStandingAuthorityState {
                authority_id: self.authority_id.clone(),
                actual: "hash-drifted".to_owned(),
                expected: "approval bound to the current grant content",
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn runs_in_last_day(&self, now: DateTime<Utc>) -> usize {
        self.run_log
            .iter()
            .filter(|run| now - run.at <= Duration::hours(24))
            .count()
    }

    fn ensure_run_budget(&self, now: DateTime<Utc>) -> Result<()> {
        if self.runs_in_last_day(now) >= self.max_runs_per_day as usize {
            return Err(CoreError::StandingAuthorityDenied {
                authority_id: self.authority_id.clone(),
                reason: format!(
                    "run budget exhausted: {} runs in the last 24h against a limit of {}",
                    self.runs_in_last_day(now),
                    self.max_runs_per_day
                ),
            });
        }
        Ok(())
    }

    fn denied(&self, reason: String) -> CoreError {
        CoreError::StandingAuthorityDenied {
            authority_id: self.authority_id.clone(),
            reason,
        }
    }

    /// Validates the freshly normalized metadata for the authority's complete
    /// permission allowlist against the exact inventory reviewed at approval.
    /// Callers may derive this value from a larger live inventory; unrelated
    /// additions therefore do not broaden or invalidate the grant.
    pub fn validate_permission_inventory(&self, normalized_full_allowlist: &Value) -> Result<()> {
        let current_hash = hash_value(normalized_full_allowlist)?;
        if current_hash != self.permission_inventory_hash {
            return Err(self.denied(
                "complete permission allowlist metadata drifted from the approved inventory hash"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Bounds check for minting a child token. Every bound is mandatory: a
    /// child must carry the pinned name prefix, request only allowlisted
    /// permission groups, and declare an expiry within the authority's
    /// maximum child TTL.
    pub fn authorize_token_create(
        &self,
        now: DateTime<Utc>,
        child_name: &str,
        requested_group_ids: &[String],
        requested_resources: &[String],
        child_expires_at: Option<DateTime<Utc>>,
    ) -> Result<()> {
        self.ensure_operational_at(now)?;
        self.ensure_run_budget(now)?;
        if !child_name.starts_with(&self.name_prefix) {
            return Err(self.denied(format!(
                "child token name `{child_name}` does not carry the pinned prefix `{}`",
                self.name_prefix
            )));
        }
        if requested_group_ids.is_empty() {
            return Err(self.denied("child token requests no permission groups".to_owned()));
        }
        // The allowlist bounds which permission groups a child may carry; this
        // bounds what those groups may act on. Without it an authority pinned
        // to one account or zone could mint a child bound elsewhere.
        if requested_resources.is_empty() {
            return Err(self.denied("child token binds no resource".to_owned()));
        }
        let allowed = self.allowed_token_resources();
        for resource in requested_resources {
            if !allowed.contains(resource) {
                return Err(self.denied(format!(
                    "child token resource `{resource}` is outside this authority's bound scope ({})",
                    allowed.join(", ")
                )));
            }
        }
        for group_id in requested_group_ids {
            if !self.permission_group_ids.contains(group_id) {
                return Err(self.denied(format!(
                    "permission group `{group_id}` is outside the approved allowlist"
                )));
            }
        }
        let Some(child_expires_at) = child_expires_at else {
            return Err(self.denied(
                "child token declares no expiry; standing mints must be short-lived".to_owned(),
            ));
        };
        let max_ttl = Duration::hours(i64::from(self.max_child_ttl_hours));
        if child_expires_at - now > max_ttl {
            return Err(self.denied(format!(
                "child token expiry exceeds the {}h maximum child TTL",
                self.max_child_ttl_hours
            )));
        }
        Ok(())
    }

    /// Bounds check for revoking a token: a standing authority may only
    /// delete tokens it minted itself (lineage bound).
    pub fn authorize_token_delete(&self, now: DateTime<Utc>, token_id: &str) -> Result<()> {
        self.ensure_operational_at(now)?;
        self.ensure_run_budget(now)?;
        if !self
            .minted_token_ids
            .iter()
            .any(|minted| minted == token_id)
        {
            return Err(self.denied(format!(
                "token `{token_id}` was not minted under this authority; lineage bound refuses the revoke"
            )));
        }
        Ok(())
    }

    /// Durably-accountable admission point for a standing run. The caller
    /// supplies one timestamp for the operational and rolling-budget checks
    /// and for the reservation itself.
    pub fn reserve_run(
        &mut self,
        now: DateTime<Utc>,
        operation_id: &str,
        capability_id: &str,
    ) -> Result<()> {
        self.ensure_operational_at(now)?;
        if self
            .run_log
            .iter()
            .any(|run| run.operation_id == operation_id)
        {
            return Err(self.denied(format!(
                "operation `{operation_id}` is already reserved under this authority"
            )));
        }
        self.ensure_run_budget(now)?;
        self.run_log.push(StandingAuthorityRunV1 {
            at: now,
            operation_id: operation_id.to_owned(),
            capability_id: capability_id.to_owned(),
        });
        Ok(())
    }

    /// Reconciles the lineage index without changing the durable authority
    /// status. In particular, a late post-boundary receipt cannot resurrect a
    /// revoked grant.
    pub fn record_minted_token(&mut self, token_id: &str) {
        if !self.minted_token_ids.iter().any(|id| id == token_id) {
            self.minted_token_ids.push(token_id.to_owned());
        }
    }
}

pub fn hash_value(value: &Value) -> Result<String> {
    let encoded = serde_json::to_vec(value)?;
    let digest = Sha256::digest(encoded);
    Ok(format!("sha256:{}", hex::encode(digest)))
}

fn canonical_hash_value(value: &Value) -> Result<String> {
    hash_value(&canonical_json_value(value))
}

fn canonical_json_value(value: &Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, value)| (key.clone(), canonical_json_value(value)))
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.iter().map(canonical_json_value).collect()),
        _ => value.clone(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClass {
    SourceConfig,
    LiveRead,
    Preview,
    Apply,
    StandingApply,
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

/// Outcome of one account-scoped operation that crossed a live read boundary.
/// This is deliberately narrower than `ResultEnvelopeV2`: workflow previews,
/// source audits, plans, and agent actions are evidence but are not operational
/// proof of a Cloudflare read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationalProofOutcomeV1 {
    Succeeded,
    Failed,
}

/// The identity scope attached to one operational proof. Keeping profile and
/// account together prevents constructors from silently swapping adjacent
/// optional string arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationalProofScopeV1 {
    pub profile_id: Option<String>,
    pub account_id: Option<String>,
}

impl OperationalProofScopeV1 {
    #[must_use]
    pub fn new(profile_id: Option<&str>, account_id: Option<&str>) -> Self {
        Self {
            profile_id: profile_id.map(str::to_owned),
            account_id: account_id.map(str::to_owned),
        }
    }
}

/// Durable index row binding a live-read receipt to the exact public contract,
/// account context, and redacted input identity that produced it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperationalProofV1 {
    pub schema_version: u8,
    pub observed_at: DateTime<Utc>,
    pub capability_id: String,
    pub catalog_hash: String,
    pub input_hash: String,
    pub profile_id: Option<String>,
    pub account_id: Option<String>,
    pub outcome: OperationalProofOutcomeV1,
    pub evidence: EvidenceV1,
}

impl OperationalProofV1 {
    #[must_use]
    pub fn new(
        observed_at: DateTime<Utc>,
        capability_id: &str,
        catalog_hash: &str,
        input_hash: &str,
        scope: OperationalProofScopeV1,
        outcome: OperationalProofOutcomeV1,
        evidence: EvidenceV1,
    ) -> Self {
        Self {
            schema_version: 1,
            observed_at,
            capability_id: capability_id.to_owned(),
            catalog_hash: catalog_hash.to_owned(),
            input_hash: input_hash.to_owned(),
            profile_id: scope.profile_id,
            account_id: scope.account_id,
            outcome,
            evidence,
        }
    }

    #[must_use]
    pub fn freshness(
        &self,
        now: DateTime<Utc>,
        current_catalog_hash: &str,
        max_age_seconds: u64,
    ) -> OperationalProofFreshnessV1 {
        if self.catalog_hash != current_catalog_hash {
            return OperationalProofFreshnessV1::CatalogDrifted;
        }
        if self.outcome == OperationalProofOutcomeV1::Failed {
            return OperationalProofFreshnessV1::Failed;
        }
        if max_age_seconds == 0 {
            return OperationalProofFreshnessV1::Stale;
        }
        let age = now.signed_duration_since(self.observed_at);
        if age < Duration::zero()
            || age > Duration::seconds(i64::try_from(max_age_seconds).unwrap_or(i64::MAX))
        {
            OperationalProofFreshnessV1::Stale
        } else {
            OperationalProofFreshnessV1::Fresh
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationalProofFreshnessV1 {
    Fresh,
    Stale,
    CatalogDrifted,
    Failed,
    NotRecorded,
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
        "destination_conf",
        "ownership_challenge",
        "authorization",
        "password",
        "cookie",
        "secret",
        "token",
    ]
    .iter()
    .any(|sensitive| normalized == *sensitive || normalized.ends_with(&format!("_{sensitive}")))
}
