//! Typed Cloudflare request construction and governed execution.

use std::{
    collections::BTreeSet,
    fs::OpenOptions,
    io::{self, Read},
    net::{Ipv4Addr, Ipv6Addr},
    path::{Component, Path, PathBuf},
    time::Duration,
};

use cfctl_auth::AuthCredential;
use cfctl_core::{
    AdapterStatus, AnalyticsQueryContractV1, AnalyticsQueryKindV1, CapabilityV1,
    D1ApprovedMlnImportContractV1, D1FullExportContractV1, D1RestoreExactBookmarkContractV1,
    D1SchemaIntrospectionContractV1, GraphqlAnalyticsContractV1, Mln0143DataInvariantsContractV1,
    OutputFormatV1, PaginationModeV1, PlanStatus, PlanV1, R2LogRetrievalContractV1,
    ResponseBodyModeV1, ResponseContractV1, RiskClass, SelectorContractV1, SelectorV1,
    TimestampFormatV1, TransactionStageV1, hash_value, request_header_is_reserved,
};
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use md5::Md5;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::time::sleep;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use url::Url;

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const _: () = assert!(libc::O_NOFOLLOW == 0x8000);

#[derive(Debug, Error)]
pub enum CloudflareError {
    #[error("invalid Cloudflare API base URL: {0}")]
    Url(#[from] url::ParseError),
    #[error("selector `{0}` is required to construct the request path")]
    MissingSelector(String),
    #[error("catalog header selector `{0}` is required")]
    MissingHeaderSelector(String),
    #[error("selector `{0}` must be a string, number, or boolean")]
    InvalidSelector(String),
    #[error(
        "selector input must be an object of catalog-declared path, header, or target controls"
    )]
    InvalidSelectorObject,
    #[error("selector `{0}` is not declared by the catalog capability or request path")]
    UndeclaredSelector(String),
    #[error("catalog selector `{name}` does not satisfy its pinned schema: {reason}")]
    InvalidSelectorSchema { name: String, reason: String },
    #[error("query input must be an object of catalog-declared controls")]
    InvalidQueryObject,
    #[error("query control `{0}` is not declared by the catalog capability")]
    UndeclaredQuerySelector(String),
    #[error("catalog query control `{0}` is required")]
    MissingQuerySelector(String),
    #[error("catalog query control `{name}` must have type `{expected}`")]
    InvalidQuerySelector { name: String, expected: String },
    #[error("catalog query control `{name}` does not satisfy its pinned schema: {reason}")]
    InvalidQuerySelectorSchema { name: String, reason: String },
    #[error("catalog query control `{name}` uses unsupported serialization: {reason}")]
    UnsupportedQuerySerialization { name: String, reason: String },
    #[error("required request body is missing for capability `{0}`")]
    MissingRequestBody(String),
    #[error("request body does not satisfy the pinned schema: {0}")]
    InvalidRequestBody(String),
    #[error("analytics query violates its bounded read contract: {0}")]
    InvalidAnalyticsQuery(String),
    #[error("R2 log retrieval violates its bounded read contract: {0}")]
    InvalidR2LogRetrieval(String),
    #[error("R2 log retrieval requires an out-of-band credential bundle")]
    R2LogCredentialsRequired,
    #[error("R2 log retrieval requires a new mode-0600 output file")]
    R2LogOutputFileRequired,
    #[error("GraphQL Analytics response drifted from the pinned contract at `{pointer}`")]
    GraphqlSchemaDrift { pointer: String },
    #[error("analytics output file `{path}` could not be created or written: {source}")]
    OutputFile {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("catalog response contract is unsupported by the executor: {0}")]
    UnsupportedResponseContract(String),
    #[error(
        "Cloudflare returned HTTP {status} with response media `{received}`, which is not declared by the pinned success contract"
    )]
    UnexpectedResponseMediaType { status: u16, received: String },
    #[error("Cloudflare returned HTTP {status} without the pinned JSON success envelope")]
    InvalidResponseEnvelope { status: u16 },
    #[error(
        "Cloudflare returned successful HTTP {status}, which is not in the pinned response statuses: {expected}"
    )]
    UnexpectedSuccessStatus { status: u16, expected: String },
    #[error(
        "Cloudflare returned HTTP {status} with {received_bytes} body bytes despite the pinned empty response contract"
    )]
    UnexpectedResponseBody { status: u16, received_bytes: usize },
    #[error("capability `{0}` mutates state and requires a consumable approved plan")]
    ApprovedPlanRequired(String),
    #[error("plan or capability `{capability_id}` is not an exact consumed event batch contract")]
    InvalidEventBatchPlan { capability_id: String },
    #[error("Cloudflare API base URL cannot accept path segments")]
    InvalidBaseUrl,
    #[error("invalid HTTP method `{0}`")]
    InvalidMethod(String),
    #[error("invalid authentication header")]
    InvalidAuthenticationHeader,
    #[error("invalid conditional request header")]
    InvalidConditionalHeader,
    #[error("catalog header selector `{0}` is reserved and cannot be set through selectors")]
    ReservedHeaderSelector(String),
    #[error("catalog header selector `{0}` has an invalid name or value")]
    InvalidHeaderSelector(String),
    #[error("Cloudflare reported {0} pages, above the governed pagination limit")]
    PaginationLimit(u64),
    #[error("Cloudflare cursor pagination repeated a cursor; completion cannot be proven")]
    PaginationCursorLoop,
    #[error("Cloudflare cursor pagination omitted cursor metadata before completion")]
    PaginationCursorMetadataMissing,
    #[error("Cloudflare request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("approved plan pins catalog {planned}, but the current catalog is {current}")]
    CatalogDrift { planned: String, current: String },
    #[error("approved plan cannot be executed: {0}")]
    Plan(#[from] cfctl_core::CoreError),
    #[error("verification strategy `{0}` is not implemented by the selected adapter")]
    UnsupportedVerificationStrategy(String),
    #[error("verification target is missing from the mutation result: {0}")]
    MissingVerificationTarget(String),
}

pub type Result<T> = std::result::Result<T, CloudflareError>;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CallInput {
    pub selectors: Value,
    pub query: Value,
    pub body: Option<Value>,
    #[serde(default)]
    pub if_match: Option<String>,
    #[serde(default)]
    pub if_none_match: Option<String>,
}

/// Ephemeral credentials for the exact Logs Engine retrieval adapter. The
/// type is intentionally not serializable so it cannot enter `CallInput`, a
/// plan, or evidence by accident.
#[derive(Clone)]
pub struct R2LogRetrievalCredentials {
    access_key_id: String,
    secret_access_key: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct D1ImportCheckpointV1 {
    pub schema_version: u8,
    pub operation_id: String,
    pub step: String,
    pub performed: bool,
    pub rectification_required: bool,
    pub receipt: Value,
}

impl R2LogRetrievalCredentials {
    pub fn new(access_key_id: String, secret_access_key: String) -> Result<Self> {
        validate_r2_credential_value("access_key_id", &access_key_id)?;
        validate_r2_credential_value("secret_access_key", &secret_access_key)?;
        Ok(Self {
            access_key_id,
            secret_access_key,
        })
    }
}

impl std::fmt::Debug for R2LogRetrievalCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("R2LogRetrievalCredentials")
            .field("access_key_id", &"[REDACTED]")
            .field("secret_access_key", &"[REDACTED]")
            .finish()
    }
}

fn validate_r2_credential_value(field: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 512
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(CloudflareError::InvalidR2LogRetrieval(format!(
            "credential field `{field}` must be a non-empty, unpadded value of at most 512 bytes"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq)]
pub struct PreparedRequest {
    pub method: String,
    pub url: Url,
    pub headers: HeaderMap,
    pub body: Option<Value>,
    pub text_body: Option<String>,
    pub response_contract: Option<ResponseContractV1>,
    pub analytics_query: Option<AnalyticsQueryContractV1>,
    pub d1_schema_introspection: Option<D1SchemaIntrospectionContractV1>,
    pub mln_0143_data_invariants: Option<Mln0143DataInvariantsContractV1>,
    pub d1_full_export: Option<D1FullExportContractV1>,
    pub d1_restore_exact_bookmark: Option<D1RestoreExactBookmarkContractV1>,
    pub r2_log_retrieval: Option<R2LogRetrievalContractV1>,
    pub graphql: Option<GraphqlAnalyticsContractV1>,
    pub output_format: OutputFormatV1,
    pub max_rows: u64,
    pub max_bytes: u64,
    pub timeout_seconds: u64,
    pub query_receipt: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct RequestBuilder {
    base_url: Url,
}

impl RequestBuilder {
    pub fn new(base_url: &str) -> Result<Self> {
        Ok(Self {
            base_url: Url::parse(base_url)?,
        })
    }

    pub fn build(&self, capability: &CapabilityV1, input: &CallInput) -> Result<PreparedRequest> {
        if capability.mutating {
            return Err(CloudflareError::ApprovedPlanRequired(capability.id.clone()));
        }
        self.build_unchecked(capability, input)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "request construction keeps validation, typed rendering, and bounded response metadata in one fail-closed path"
    )]
    pub fn build_unchecked(
        &self,
        capability: &CapabilityV1,
        input: &CallInput,
    ) -> Result<PreparedRequest> {
        validate_request_contract(capability, input)?;
        let mut url = self.base_url.clone();
        let selectors = input.selectors.as_object();
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|()| CloudflareError::InvalidBaseUrl)?;
            segments.pop_if_empty();
            for segment in capability.path.trim_start_matches('/').split('/') {
                if let Some(key) = segment.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
                    let value = selectors
                        .and_then(|map| map.get(key))
                        .ok_or_else(|| CloudflareError::MissingSelector(key.to_owned()))?;
                    let rendered = scalar(value)
                        .ok_or_else(|| CloudflareError::InvalidSelector(key.to_owned()))?;
                    segments.push(&rendered);
                } else {
                    segments.push(segment);
                }
            }
        }
        if let Some(query) = input.query.as_object().filter(|query| !query.is_empty()) {
            let mut pairs = url.query_pairs_mut();
            for (key, value) in query {
                let selector = capability
                    .selectors
                    .iter()
                    .find(|selector| selector.location == "query" && selector.name == *key)
                    .ok_or_else(|| CloudflareError::UndeclaredQuerySelector(key.clone()))?;
                let (explode, _) = validated_query_serialization(selector)?;
                match value {
                    Value::Array(values) => {
                        let rendered = values
                            .iter()
                            .map(scalar)
                            .collect::<Option<Vec<_>>>()
                            .ok_or_else(|| CloudflareError::InvalidQuerySelector {
                                name: key.clone(),
                                expected: selector.value_type.clone(),
                            })?;
                        if rendered.is_empty() {
                            pairs.append_pair(key, "");
                        } else if explode {
                            for rendered in rendered {
                                pairs.append_pair(key, &rendered);
                            }
                        } else {
                            pairs.append_pair(key, &rendered.join(","));
                        }
                    }
                    _ => {
                        if let Some(rendered) = scalar(value) {
                            pairs.append_pair(key, &rendered);
                        }
                    }
                }
            }
        }
        let mut headers = HeaderMap::new();
        add_declared_header_selectors(&mut headers, capability, selectors)?;
        add_conditional_header(
            &mut headers,
            reqwest::header::IF_MATCH,
            input.if_match.as_ref(),
        )?;
        add_conditional_header(
            &mut headers,
            reqwest::header::IF_NONE_MATCH,
            input.if_none_match.as_ref(),
        )?;
        let (output_format, max_rows, max_bytes, timeout_seconds) =
            read_runtime_options(capability, input)?;
        let (body, text_body) = if capability.d1_full_export.is_some() {
            (Some(serde_json::json!({"output_format":"polling"})), None)
        } else if capability.d1_restore_exact_bookmark.is_some() {
            let target = input
                .body
                .as_ref()
                .and_then(|body| body.get("target_bookmark"))
                .and_then(Value::as_str)
                .ok_or_else(|| CloudflareError::MissingRequestBody(capability.id.clone()))?;
            (Some(serde_json::json!({"bookmark":target})), None)
        } else if capability.mln_0143_data_invariants.is_some() {
            (
                Some(render_mln_0143_data_invariants_body(
                    input.body.as_ref().ok_or_else(|| {
                        CloudflareError::MissingRequestBody(capability.id.clone())
                    })?,
                )?),
                None,
            )
        } else if capability.d1_schema_introspection.is_some() {
            (
                Some(render_d1_schema_introspection_body(
                    input.body.as_ref().ok_or_else(|| {
                        CloudflareError::MissingRequestBody(capability.id.clone())
                    })?,
                )?),
                None,
            )
        } else {
            match capability
                .analytics_query
                .as_ref()
                .map(|contract| contract.kind)
            {
                Some(AnalyticsQueryKindV1::StructuredSql) => {
                    let sql = render_structured_analytics_sql(
                        input.body.as_ref().ok_or_else(|| {
                            CloudflareError::MissingRequestBody(capability.id.clone())
                        })?,
                        output_format,
                    )?;
                    url.query_pairs_mut().append_pair("query", &sql);
                    (None, None)
                }
                Some(AnalyticsQueryKindV1::LogExplorerSql) => {
                    let sql = render_structured_log_explorer_sql(input.body.as_ref().ok_or_else(
                        || CloudflareError::MissingRequestBody(capability.id.clone()),
                    )?)?;
                    headers.insert(
                        reqwest::header::CONTENT_TYPE,
                        HeaderValue::from_static("text/plain"),
                    );
                    (None, Some(sql))
                }
                Some(AnalyticsQueryKindV1::GraphqlAnalytics) => {
                    let graphql = capability.graphql.as_ref().ok_or_else(|| {
                        CloudflareError::InvalidAnalyticsQuery(
                            "GraphQL query contract is missing its fixed document".to_owned(),
                        )
                    })?;
                    (Some(graphql_request_body(graphql, input)?), None)
                }
                _ => (input.body.clone(), None),
            }
        };
        headers.insert(
            reqwest::header::ACCEPT,
            HeaderValue::from_static(output_media_type(output_format)),
        );
        Ok(PreparedRequest {
            method: capability.method.clone(),
            url,
            headers,
            body,
            text_body,
            response_contract: capability.response_contract.clone(),
            analytics_query: capability.analytics_query.clone(),
            d1_schema_introspection: capability.d1_schema_introspection.clone(),
            mln_0143_data_invariants: capability.mln_0143_data_invariants.clone(),
            d1_full_export: capability.d1_full_export.clone(),
            d1_restore_exact_bookmark: capability.d1_restore_exact_bookmark.clone(),
            r2_log_retrieval: capability.r2_log_retrieval.clone(),
            graphql: capability.graphql.clone(),
            output_format,
            max_rows,
            max_bytes,
            timeout_seconds,
            query_receipt: d1_full_export_receipt(capability, input)
                .or_else(|| mln_0143_data_invariants_receipt(capability, input))
                .or_else(|| d1_schema_introspection_receipt(capability, input))
                .or_else(|| analytics_query_receipt(capability, input, output_format))
                .or_else(|| r2_log_retrieval_receipt(capability, input)),
        })
    }
}

fn d1_full_export_receipt(capability: &CapabilityV1, input: &CallInput) -> Option<Value> {
    let contract = capability.d1_full_export.as_ref()?;
    Some(serde_json::json!({
        "capability_id": capability.id,
        "kind": "d1_full_export",
        "account_id": input.selectors.get("account_id"),
        "database_id": input.selectors.get("database_id"),
        "caller_sql": false,
        "scope": "full_schema_and_data",
        "byte_limit": contract.max_bytes,
        "requires_new_mode_0600_file": contract.requires_new_mode_0600_file,
    }))
}

fn d1_schema_introspection_receipt(capability: &CapabilityV1, input: &CallInput) -> Option<Value> {
    let contract = capability.d1_schema_introspection.as_ref()?;
    let body = input.body.as_ref()?;
    let assertion = body.get("assertion")?.as_str()?;
    let input_hash = hash_value(body).ok()?;
    Some(serde_json::json!({
        "capability_id": capability.id,
        "kind": "d1_schema_introspection",
        "assertion": assertion,
        "assertion_input_sha256": input_hash,
        "row_limit": contract.max_rows,
        "byte_limit": contract.max_bytes,
        "timeout_seconds": contract.max_timeout_seconds,
        "read_only": true,
        "caller_sql": d1_schema_introspection_caller_sql(body),
    }))
}

fn d1_schema_introspection_caller_sql(body: &Value) -> bool {
    body.as_object()
        .is_some_and(|body| body.contains_key("sql"))
}

// Reviewed from MLN migrations 0110 and 0143. These are the exact table
// definitions SQLite records, excluding only comments and formatting.
const MLN_0143_PRE_TABLE_SQL: &str = r"CREATE TABLE equity_issuance_evidence_links (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    issuance_event_id TEXT NOT NULL REFERENCES equity_issuance_events(id) ON DELETE CASCADE,
    evidence_kind TEXT NOT NULL CHECK (evidence_kind IN (
        'board_consent',
        'stock_purchase_agreement',
        'restricted_stock_purchase_agreement',
        'safe_agreement',
        'advisor_agreement',
        'election_83b',
        'consideration',
        'funds_evidence',
        'signature',
        'stock_ledger',
        'document_hash',
        'other'
    )),
    document_id TEXT REFERENCES documents(id) ON DELETE SET NULL,
    company_event_id TEXT REFERENCES company_events(id) ON DELETE SET NULL,
    document_hash TEXT,
    required INTEGER NOT NULL DEFAULT 1 CHECK (required IN (0, 1)),
    created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
)";

const MLN_0143_POST_TABLE_SQL: &str = r"CREATE TABLE equity_issuance_evidence_links (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    issuance_event_id TEXT NOT NULL REFERENCES equity_issuance_events(id) ON DELETE CASCADE,
    evidence_kind TEXT NOT NULL CHECK (evidence_kind IN (
        'board_consent',
        'stock_purchase_agreement',
        'restricted_stock_purchase_agreement',
        'advisor_equity_instrument',
        'safe_agreement',
        'advisor_agreement',
        'election_83b',
        'consideration',
        'funds_evidence',
        'signature',
        'stock_ledger',
        'document_hash',
        'other'
    )),
    document_id TEXT REFERENCES documents(id) ON DELETE SET NULL,
    company_event_id TEXT REFERENCES company_events(id) ON DELETE SET NULL,
    document_hash TEXT,
    required INTEGER NOT NULL DEFAULT 1 CHECK (required IN (0, 1)),
    created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
)";

const MLN_0143_QUERY: &str = r"WITH evidence_projection AS (
 SELECT id,org_id,issuance_event_id,evidence_kind,document_id,company_event_id,document_hash,required,created_by,created_at,
        COUNT(*) OVER() AS projection_total
 FROM equity_issuance_evidence_links ORDER BY id LIMIT 257
), evidence_payload AS (
 SELECT COALESCE(json_group_array(json_object(
   'id',id,'org_id',org_id,'issuance_event_id',issuance_event_id,'evidence_kind',evidence_kind,
   'document_id',document_id,'company_event_id',company_event_id,'document_hash',document_hash,
   'required',required,'created_by',created_by,'created_at',created_at)), '[]') AS evidence_rows,
   COUNT(*) AS evidence_received, COALESCE(MAX(projection_total),0) AS evidence_window_total
 FROM evidence_projection
), packet_projection AS (
 SELECT profile,evidence_kind,signature_required,sort_order,
        COUNT(*) OVER() AS projection_total
 FROM issuance_profile_packet_kinds ORDER BY profile,evidence_kind LIMIT 513
), packet_payload AS (
 SELECT COALESCE(json_group_array(json_object(
   'profile',profile,'evidence_kind',evidence_kind,
   'signature_required',signature_required,'sort_order',sort_order)),'[]') AS packet_rows,
   COUNT(*) AS packet_received, COALESCE(MAX(projection_total),0) AS packet_window_total
 FROM packet_projection
)
SELECT evidence_rows,evidence_received,evidence_window_total,
 packet_rows,packet_received,packet_window_total,
 (SELECT COUNT(*) FROM equity_issuance_evidence_links) AS evidence_total,
 (SELECT COUNT(*) FROM issuance_profile_packet_kinds) AS packet_total,
 (SELECT COALESCE(json_group_array(json_object('evidence_kind',evidence_kind,'count',kind_count)),'[]')
  FROM (SELECT evidence_kind,COUNT(*) AS kind_count FROM equity_issuance_evidence_links GROUP BY evidence_kind ORDER BY evidence_kind)) AS evidence_kind_counts,
 (SELECT sql FROM sqlite_schema WHERE type='table' AND name='equity_issuance_evidence_links') AS table_sql,
 (SELECT COALESCE(json_group_array(name),'[]') FROM (SELECT name FROM pragma_table_info('equity_issuance_evidence_links') ORDER BY cid)) AS column_names,
 (SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name='equity_issuance_evidence_links_0143_old') AS old_table_count,
 (SELECT sql FROM sqlite_schema WHERE type='index' AND name='idx_equity_issuance_evidence_event') AS event_index_sql,
 (SELECT [unique] FROM pragma_index_list('equity_issuance_evidence_links') WHERE name='idx_equity_issuance_evidence_event') AS event_index_unique,
 (SELECT COALESCE(json_group_array(name),'[]') FROM (SELECT name FROM pragma_index_info('idx_equity_issuance_evidence_event') ORDER BY seqno)) AS event_index_columns,
 (SELECT sql FROM sqlite_schema WHERE type='index' AND name='idx_equity_issuance_evidence_document') AS document_index_sql,
 (SELECT [unique] FROM pragma_index_list('equity_issuance_evidence_links') WHERE name='idx_equity_issuance_evidence_document') AS document_index_unique,
 (SELECT COALESCE(json_group_array(name),'[]') FROM (SELECT name FROM pragma_index_info('idx_equity_issuance_evidence_document') ORDER BY seqno)) AS document_index_columns,
 (SELECT sql FROM sqlite_schema WHERE type='index' AND name='idx_equity_issuance_evidence_unique_hash') AS unique_hash_index_sql,
 (SELECT tbl_name FROM sqlite_schema WHERE type='index' AND name='idx_equity_issuance_evidence_unique_hash') AS unique_hash_index_table,
 (SELECT [unique] FROM pragma_index_list('equity_issuance_evidence_links') WHERE name='idx_equity_issuance_evidence_unique_hash') AS unique_hash_index_unique,
 (SELECT partial FROM pragma_index_list('equity_issuance_evidence_links') WHERE name='idx_equity_issuance_evidence_unique_hash') AS unique_hash_index_partial,
 (SELECT COALESCE(json_group_array(name),'[]') FROM (SELECT name FROM pragma_index_info('idx_equity_issuance_evidence_unique_hash') ORDER BY seqno)) AS unique_hash_index_columns,
 (SELECT sql FROM sqlite_schema WHERE type='trigger' AND name='trg_advisor_equity_instrument_evidence_contract') AS trigger_contract_sql,
 (SELECT sql FROM sqlite_schema WHERE type='trigger' AND name='trg_advisor_equity_instrument_evidence_immutable') AS trigger_immutable_sql,
 (SELECT sql FROM sqlite_schema WHERE type='trigger' AND name='trg_advisor_grant_final_instrument_required') AS trigger_final_required_sql,
 (SELECT COUNT(*) FROM pragma_foreign_key_check) AS foreign_key_violations,
 (SELECT COUNT(*) FROM (SELECT 1 FROM equity_issuance_evidence_links WHERE document_hash IS NOT NULL GROUP BY org_id,issuance_event_id,evidence_kind,document_hash HAVING COUNT(*)>1)) AS duplicate_hash_groups,
 (SELECT COUNT(*) FROM equity_issuance_evidence_links WHERE evidence_kind NOT IN (
   'board_consent','stock_purchase_agreement','restricted_stock_purchase_agreement',
   'advisor_equity_instrument','safe_agreement','advisor_agreement','election_83b',
   'consideration','funds_evidence','signature','stock_ledger','document_hash','other'
 )) AS invalid_evidence_kinds,
 (SELECT COUNT(*) FROM equity_issuance_events event
  WHERE event.issuance_profile='advisor_grant' AND event.status IN ('documents_generated','ready_to_execute','executed')
  AND NOT EXISTS (SELECT 1 FROM equity_issuance_evidence_links evidence WHERE evidence.org_id=event.org_id
    AND evidence.issuance_event_id=event.id AND evidence.evidence_kind='advisor_equity_instrument'
    AND evidence.required=1 AND evidence.document_id IS NOT NULL AND COALESCE(trim(evidence.document_hash),'')<>'')) AS invalid_advanced_events
 FROM evidence_payload,packet_payload";

fn render_mln_0143_data_invariants_body(body: &Value) -> Result<Value> {
    let object = body.as_object().ok_or_else(|| {
        CloudflareError::InvalidAnalyticsQuery(
            "MLN 0143 invariant input must be an object".to_owned(),
        )
    })?;
    let phase = object.get("phase").and_then(Value::as_str).ok_or_else(|| {
        CloudflareError::InvalidAnalyticsQuery("MLN 0143 invariant phase is missing".to_owned())
    })?;
    if !matches!(phase, "pre_import" | "post_import" | "post_restore") {
        return Err(CloudflareError::InvalidAnalyticsQuery(
            "MLN 0143 invariant phase is unsupported".to_owned(),
        ));
    }
    Ok(serde_json::json!({"sql":MLN_0143_QUERY,"params":[]}))
}

fn mln_0143_data_invariants_receipt(capability: &CapabilityV1, input: &CallInput) -> Option<Value> {
    let contract = capability.mln_0143_data_invariants.as_ref()?;
    let body = input.body.as_ref()?;
    Some(serde_json::json!({
        "capability_id":capability.id,
        "kind":"mln_0143_data_invariants",
        "migration_id":"0143",
        "phase":body.get("phase"),
        "pre_import_evidence_hash":body.get("pre_import_evidence_hash"),
        "post_import_evidence_hash":body.get("post_import_evidence_hash"),
        "import_operation_id":body.get("import_operation_id"),
        "import_boundary_evidence_hash":body.get("import_boundary_evidence_hash"),
        "import_source_sha256":body.get("import_source_sha256"),
        "import_plan_hash":body.get("import_plan_hash"),
        "restore_operation_id":body.get("restore_operation_id"),
        "restore_evidence_hash":body.get("restore_evidence_hash"),
        "restore_previous_bookmark_hash":body.get("restore_previous_bookmark_hash"),
        "restore_requested_bookmark_hash":body.get("restore_requested_bookmark_hash"),
        "restore_observed_bookmark_hash":body.get("restore_observed_bookmark_hash"),
        "migration_sha256":contract.migration_sha256,
        "target_scope_hash":hash_value(&serde_json::json!({
            "account_id":contract.account_id,
            "database_id":contract.database_id,
        })).ok()?,
        "row_limit":contract.max_evidence_rows,
        "probe_rows":contract.probe_rows,
        "byte_limit":contract.max_bytes,
        "timeout_seconds":contract.max_timeout_seconds,
        "read_only":true,
        "caller_sql":false,
    }))
}

fn r2_log_retrieval_receipt(capability: &CapabilityV1, input: &CallInput) -> Option<Value> {
    let contract = capability.r2_log_retrieval.as_ref()?;
    let query = input.query.as_object()?;
    let hash = |selector: &str| {
        query
            .get(selector)
            .and_then(Value::as_str)
            .map(|value| format!("sha256:{}", hex::encode(Sha256::digest(value.as_bytes()))))
    };
    Some(serde_json::json!({
        "capability_id": capability.id,
        "kind": "r2_log_retrieval",
        "start": query.get(&contract.start_query_selector),
        "end": query.get(&contract.end_query_selector),
        "bucket_sha256": hash(&contract.bucket_query_selector),
        "prefix_sha256": hash(&contract.prefix_query_selector),
        "byte_limit": contract.max_bytes,
        "timeout_seconds": contract.max_timeout_seconds,
        "output_file_required": contract.requires_new_mode_0600_file,
        "credential_transport": "out_of_band_fixed_headers",
    }))
}

fn analytics_query_receipt(
    capability: &CapabilityV1,
    input: &CallInput,
    output_format: OutputFormatV1,
) -> Option<Value> {
    let contract = capability.analytics_query.as_ref()?;
    let body = input.body.as_ref();
    Some(serde_json::json!({
        "capability_id": capability.id,
        "kind": contract.kind,
        "dataset": contract.dataset.clone().map(Value::String).or_else(|| {
            contract.dataset_pointer.as_deref().and_then(|pointer| body?.pointer(pointer)).cloned()
        }),
        "start": contract.time_range.as_ref().and_then(|time| body?.pointer(&time.start_pointer)).cloned(),
        "end": contract.time_range.as_ref().and_then(|time| body?.pointer(&time.end_pointer)).cloned(),
        "row_limit": contract.row_limit_pointer.as_deref().and_then(|pointer| body?.pointer(pointer)).cloned().unwrap_or(Value::from(contract.max_rows)),
        "byte_limit": contract.max_bytes,
        "timeout_seconds": body.and_then(|value| value.get("timeout_seconds")).cloned().unwrap_or(Value::from(contract.max_timeout_seconds)),
        "output_format": output_format,
        "pagination": contract.pagination,
        "freshness": contract.freshness,
        "sampling": contract.sampling,
        "read_only": contract.read_only,
    }))
}

fn read_runtime_options(
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<(OutputFormatV1, u64, u64, u64)> {
    if let Some(contract) = capability.mln_0143_data_invariants.as_ref() {
        return Ok((
            OutputFormatV1::Json,
            1,
            contract.max_bytes,
            contract.max_timeout_seconds,
        ));
    }
    if let Some(contract) = capability.d1_schema_introspection.as_ref() {
        return Ok((
            OutputFormatV1::Json,
            contract.max_rows,
            contract.max_bytes,
            contract.max_timeout_seconds,
        ));
    }
    if let Some(contract) = capability.d1_full_export.as_ref() {
        return Ok((
            OutputFormatV1::Json,
            1,
            contract.max_bytes,
            contract.max_timeout_seconds,
        ));
    }
    if let Some(contract) = capability.d1_restore_exact_bookmark.as_ref() {
        return Ok((
            OutputFormatV1::Json,
            1,
            contract.max_response_bytes,
            contract.max_timeout_seconds,
        ));
    }
    let Some(contract) = capability.analytics_query.as_ref() else {
        return Ok(capability.r2_log_retrieval.as_ref().map_or(
            (OutputFormatV1::Json, 10_000, 16 * 1024 * 1024, 30),
            |contract| {
                (
                    OutputFormatV1::Json,
                    contract.max_bytes,
                    contract.max_bytes,
                    contract.max_timeout_seconds,
                )
            },
        ));
    };
    let body = input.body.as_ref().and_then(Value::as_object);
    let output_format = body
        .and_then(|body| body.get("format"))
        .and_then(Value::as_str)
        .map(parse_output_format)
        .transpose()?
        .unwrap_or(contract.default_output_format);
    let max_rows = contract
        .row_limit_pointer
        .as_deref()
        .and_then(|pointer| input.body.as_ref()?.pointer(pointer))
        .and_then(Value::as_u64)
        .unwrap_or(contract.max_rows);
    let timeout_seconds = body
        .and_then(|body| body.get("timeout_seconds"))
        .and_then(Value::as_u64)
        .unwrap_or(contract.max_timeout_seconds);
    Ok((output_format, max_rows, contract.max_bytes, timeout_seconds))
}

fn render_d1_schema_introspection_body(body: &Value) -> Result<Value> {
    let body = body.as_object().ok_or_else(|| {
        CloudflareError::InvalidAnalyticsQuery(
            "D1 schema assertion input must be an object".to_owned(),
        )
    })?;
    let assertion = body
        .get("assertion")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CloudflareError::InvalidAnalyticsQuery("D1 schema assertion kind is missing".to_owned())
        })?;
    let allowed_fields: &[&str] = match assertion {
        "table_exists" => &["assertion", "table"],
        "column_exists" => &["assertion", "table", "column"],
        "index_exists" => &["assertion", "index"],
        "trigger_exists" => &["assertion", "trigger"],
        "schema_contains" => &["assertion", "object_type", "name", "fragment"],
        "foreign_key_check_empty" => &["assertion"],
        _ => {
            return Err(CloudflareError::InvalidAnalyticsQuery(format!(
                "unsupported D1 schema assertion `{assertion}`"
            )));
        }
    };
    if let Some(field) = body
        .keys()
        .find(|field| !allowed_fields.contains(&field.as_str()))
    {
        return Err(CloudflareError::InvalidAnalyticsQuery(format!(
            "D1 schema assertion `{assertion}` does not accept field `{field}`"
        )));
    }
    let bounded = |field: &str, maximum: usize| -> Result<String> {
        body.get(field)
            .and_then(Value::as_str)
            .filter(|value| {
                !value.is_empty()
                    && value.len() <= maximum
                    && !value.chars().any(char::is_control)
            })
            .map(str::to_owned)
            .ok_or_else(|| {
                CloudflareError::InvalidAnalyticsQuery(format!(
                    "D1 schema assertion field `{field}` must be a non-empty control-free string of at most {maximum} bytes"
                ))
            })
    };
    let (sql, params) = match assertion {
        "table_exists" => (
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1) AS present",
            vec![Value::String(bounded("table", 255)?)],
        ),
        "column_exists" => (
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info(?1) WHERE name = ?2) AS present",
            vec![
                Value::String(bounded("table", 255)?),
                Value::String(bounded("column", 255)?),
            ],
        ),
        "index_exists" => (
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'index' AND name = ?1) AS present",
            vec![Value::String(bounded("index", 255)?)],
        ),
        "trigger_exists" => (
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'trigger' AND name = ?1) AS present",
            vec![Value::String(bounded("trigger", 255)?)],
        ),
        "schema_contains" => (
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = ?1 AND name = ?2 AND instr(COALESCE(sql, ''), ?3) > 0) AS present",
            vec![
                Value::String(
                    body.get("object_type")
                        .and_then(Value::as_str)
                        .filter(|value| matches!(*value, "table" | "index" | "trigger"))
                        .ok_or_else(|| {
                            CloudflareError::InvalidAnalyticsQuery(
                                "D1 schema object_type must be table, index, or trigger".to_owned(),
                            )
                        })?
                        .to_owned(),
                ),
                Value::String(bounded("name", 255)?),
                Value::String(bounded("fragment", 512)?),
            ],
        ),
        "foreign_key_check_empty" => (
            "SELECT NOT EXISTS(SELECT 1 FROM pragma_foreign_key_check LIMIT 1) AS present",
            Vec::new(),
        ),
        _ => unreachable!("assertion variants were closed above"),
    };
    Ok(serde_json::json!({"sql":sql,"params":params}))
}

fn d1_schema_introspection_request_schema() -> Value {
    let name = serde_json::json!({"type":"string","minLength":1,"maxLength":255});
    serde_json::json!({
        "type":"object",
        "x-cfctl-body-required":true,
        "oneOf":[
            {"type":"object","additionalProperties":false,"required":["assertion","table"],"properties":{"assertion":{"type":"string","enum":["table_exists"]},"table":name}},
            {"type":"object","additionalProperties":false,"required":["assertion","table","column"],"properties":{"assertion":{"type":"string","enum":["column_exists"]},"table":name,"column":name}},
            {"type":"object","additionalProperties":false,"required":["assertion","index"],"properties":{"assertion":{"type":"string","enum":["index_exists"]},"index":name}},
            {"type":"object","additionalProperties":false,"required":["assertion","trigger"],"properties":{"assertion":{"type":"string","enum":["trigger_exists"]},"trigger":name}},
            {"type":"object","additionalProperties":false,"required":["assertion","object_type","name","fragment"],"properties":{"assertion":{"type":"string","enum":["schema_contains"]},"object_type":{"type":"string","enum":["table","index","trigger"]},"name":name,"fragment":{"type":"string","minLength":1,"maxLength":512}}},
            {"type":"object","additionalProperties":false,"required":["assertion"],"properties":{"assertion":{"type":"string","enum":["foreign_key_check_empty"]}}}
        ]
    })
}

#[cfg(test)]
mod d1_schema_introspection_tests {
    use super::{d1_schema_introspection_caller_sql, render_d1_schema_introspection_body};
    use serde_json::json;

    #[test]
    fn renderer_rejects_unknown_fields_for_every_assertion_without_schema_help() {
        for body in [
            json!({"assertion":"table_exists","table":"users","sql":"SELECT 1"}),
            json!({"assertion":"column_exists","table":"users","column":"id","params":[]}),
            json!({"assertion":"index_exists","index":"idx_users","unexpected":true}),
            json!({"assertion":"trigger_exists","trigger":"users_guard","unexpected":true}),
            json!({"assertion":"schema_contains","object_type":"table","name":"users","fragment":"id","unexpected":true}),
            json!({"assertion":"foreign_key_check_empty","unexpected":true}),
        ] {
            assert!(render_d1_schema_introspection_body(&body).is_err());
        }
    }

    #[test]
    fn caller_sql_receipt_fact_reflects_actual_body_field_presence() {
        assert!(!d1_schema_introspection_caller_sql(
            &json!({"assertion":"foreign_key_check_empty"})
        ));
        assert!(d1_schema_introspection_caller_sql(
            &json!({"assertion":"foreign_key_check_empty","sql":"SELECT 1"})
        ));
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod mln_0143_invariant_tests {
    use super::{
        CloudflareResponseV1, MLN_0143_POST_TABLE_SQL, MLN_0143_PRE_TABLE_SQL,
        Mln0143DataInvariantsContractV1, OutputFormatV1, PreparedRequest, Url, normalized_sql_hash,
        reviewed_table_sql_hash, sanitize_mln_0143_data_invariants_response,
    };
    use reqwest::header::HeaderMap;
    use serde_json::{Value, json};

    fn prepared(phase: &str) -> PreparedRequest {
        let mut contract = Mln0143DataInvariantsContractV1 {
            account_id: "ca30e922fda7f5578e49873542e4aaca".to_owned(),
            database_id: "7c282983-2e48-4ea4-9f0d-09b0d718fe65".to_owned(),
            migration_sha256: "9b089ead4c284fe92f8a9f81296ac34aa98702585305e36b5c4f345fe774871d"
                .to_owned(),
            trigger_definition_hashes: Vec::new(),
            fixed_query_sha256:
                "sha256:25f81a01063e72e59da8b216a08673ec70b887a016ccba5d1a4fd12fd2cfc28d".to_owned(),
            pre_table_definition_hash:
                "sha256:8aa5012ace3d946354e0baba7e645646ac97373b42e7c3d61e79b67a5f689fea".to_owned(),
            post_table_definition_hash:
                "sha256:2fbdacd011abca8024507b99d179071b8b920271576e4cb3a2f06c4f3ffd2d7f".to_owned(),
            validator_contract_hash: String::new(),
            capability_version: 3,
            max_evidence_rows: 256,
            probe_rows: 257,
            max_bytes: 1024 * 1024,
            max_timeout_seconds: 30,
        };
        contract.validator_contract_hash = contract
            .expected_validator_contract_hash()
            .expect("validator contract");
        PreparedRequest {
            method: "POST".to_owned(),
            url: Url::parse("https://example.invalid/query").expect("URL"),
            headers: HeaderMap::new(),
            body: None,
            text_body: None,
            response_contract: None,
            analytics_query: None,
            d1_schema_introspection: None,
            mln_0143_data_invariants: Some(contract),
            d1_full_export: None,
            d1_restore_exact_bookmark: None,
            r2_log_retrieval: None,
            graphql: None,
            output_format: OutputFormatV1::Json,
            max_rows: 1,
            max_bytes: 1024 * 1024,
            timeout_seconds: 30,
            query_receipt: Some(json!({
                "phase":phase,
                "pre_import_evidence_hash":null,
                "post_import_evidence_hash":null
            })),
        }
    }

    fn evidence_row(index: usize) -> Value {
        json!({
            "id":format!("private-id-{index}"),
            "org_id":"private-org",
            "issuance_event_id":"private-event",
            "evidence_kind":"board_consent",
            "document_id":"private-document",
            "company_event_id":null,
            "document_hash":"sha256:private",
            "required":1,
            "created_by":"private-user",
            "created_at":"2026-07-30T00:00:00Z"
        })
    }

    fn pre_response(count: usize) -> CloudflareResponseV1 {
        let rows = (0..count).map(evidence_row).collect::<Vec<_>>();
        CloudflareResponseV1 {
            status: 200,
            success: true,
            result: json!([{
                "success":true,
                "meta":{"rows_read":count + 20,"rows_written":0,"duration":0.25},
                "results":[{
                    "evidence_rows":serde_json::to_string(&rows).expect("rows JSON"),
                    "evidence_received":count,
                    "evidence_window_total":count,
                    "evidence_total":count,
                    "packet_rows":"[{\"profile\":\"advisor_grant\",\"evidence_kind\":\"advisor_agreement\",\"signature_required\":1,\"sort_order\":1},{\"profile\":\"advisor_grant\",\"evidence_kind\":\"board_consent\",\"signature_required\":1,\"sort_order\":0},{\"profile\":\"advisor_grant\",\"evidence_kind\":\"election_83b\",\"signature_required\":0,\"sort_order\":2}]",
                    "packet_received":3,
                    "packet_window_total":3,
                    "packet_total":3,
                    "evidence_kind_counts":"[{\"evidence_kind\":\"board_consent\",\"count\":1}]",
                    "table_sql":MLN_0143_PRE_TABLE_SQL,
                    "column_names":"[\"id\",\"org_id\",\"issuance_event_id\",\"evidence_kind\",\"document_id\",\"company_event_id\",\"document_hash\",\"required\",\"created_by\",\"created_at\"]",
                    "old_table_count":0,
                    "event_index_sql":"CREATE INDEX idx_equity_issuance_evidence_event ON equity_issuance_evidence_links(org_id, issuance_event_id, evidence_kind)",
                    "event_index_unique":0,
                    "event_index_columns":"[\"org_id\",\"issuance_event_id\",\"evidence_kind\"]",
                    "document_index_sql":"CREATE INDEX idx_equity_issuance_evidence_document ON equity_issuance_evidence_links(org_id, document_id)",
                    "document_index_unique":0,
                    "document_index_columns":"[\"org_id\",\"document_id\"]",
                    "unique_hash_index_sql":"CREATE UNIQUE INDEX idx_equity_issuance_evidence_unique_hash ON equity_issuance_evidence_links(org_id, issuance_event_id, evidence_kind, document_hash) WHERE document_hash IS NOT NULL",
                    "unique_hash_index_table":"equity_issuance_evidence_links",
                    "unique_hash_index_unique":1,
                    "unique_hash_index_partial":1,
                    "unique_hash_index_columns":"[\"org_id\",\"issuance_event_id\",\"evidence_kind\",\"document_hash\"]",
                    "trigger_contract_sql":null,
                    "trigger_immutable_sql":null,
                    "trigger_final_required_sql":null,
                    "foreign_key_violations":0,
                    "duplicate_hash_groups":0,
                    "invalid_evidence_kinds":0,
                    "invalid_advanced_events":0
                }]
            }]),
            errors: Vec::new(),
            result_info: None,
            etag: None,
            cf_ray: None,
        }
    }

    #[test]
    fn pre_import_accepts_exactly_256_and_discards_private_rows() {
        let request = prepared("pre_import");
        let mut response = pre_response(256);
        sanitize_mln_0143_data_invariants_response(&mut response, &request)
            .expect("256 rows fit the safe bound");
        let encoded = serde_json::to_string(&response).expect("response JSON");
        for private in [
            "private-id",
            "private-org",
            "private-event",
            "private-document",
            "private-user",
            "sha256:private",
        ] {
            assert!(!encoded.contains(private), "{private}");
        }
        assert_eq!(response.result["projection"]["count"], 256);
        assert_eq!(response.result["complete"], true);
    }

    #[test]
    fn pre_import_rejects_the_257th_row_without_retaining_rows() {
        let request = prepared("pre_import");
        let mut response = pre_response(257);
        let error = sanitize_mln_0143_data_invariants_response(&mut response, &request)
            .expect_err("257 rows exceed the safe bound");
        assert!(
            error
                .to_string()
                .contains("invariant_not_feasible_under_safe_bounds")
        );
    }

    #[test]
    fn packet_projection_requires_complete_unsaturated_full_table() {
        let request = prepared("pre_import");
        let mut response = pre_response(0);
        response.result[0]["results"][0]["packet_total"] = json!(513);
        response.result[0]["results"][0]["packet_window_total"] = json!(513);
        response.result[0]["results"][0]["packet_received"] = json!(513);
        assert!(sanitize_mln_0143_data_invariants_response(&mut response, &request).is_err());

        let mut incomplete = pre_response(0);
        incomplete.result[0]["results"][0]["packet_total"] = json!(4);
        assert!(sanitize_mln_0143_data_invariants_response(&mut incomplete, &request).is_err());
    }

    #[test]
    fn pre_import_rejects_provider_metadata_ambiguity() {
        let request = prepared("pre_import");
        let mut response = pre_response(0);
        response.result[0]["meta"]
            .as_object_mut()
            .expect("meta")
            .remove("rows_read");
        assert!(sanitize_mln_0143_data_invariants_response(&mut response, &request).is_err());
    }

    #[test]
    fn top_level_provider_failures_are_sunk_before_result_processing() {
        let request = prepared("pre_import");
        let private_id = "mln-private-id-sentinel";
        let private_hash = "sha256:mln-private-document-hash-sentinel";
        let mut provider_error = pre_response(0);
        provider_error.errors.push(super::CloudflareApiErrorV1 {
            code: Some(10_001),
            message: format!("{private_id} {private_hash}"),
        });
        let error = sanitize_mln_0143_data_invariants_response(&mut provider_error, &request)
            .expect_err("top-level provider error must fail closed");
        let observable = format!(
            "{error} {}",
            serde_json::to_string(&provider_error).expect("scrubbed response JSON")
        );
        assert!(!observable.contains(private_id));
        assert!(!observable.contains(private_hash));
        assert!(provider_error.errors.is_empty());
        assert!(provider_error.result.is_null());

        let mut unsuccessful = pre_response(0);
        unsuccessful.success = false;
        let error = sanitize_mln_0143_data_invariants_response(&mut unsuccessful, &request)
            .expect_err("success=false must fail closed");
        assert!(matches!(
            error,
            super::CloudflareError::InvalidResponseEnvelope { status: 200 }
        ));
        assert!(unsuccessful.errors.is_empty());
        assert!(unsuccessful.result.is_null());
    }

    #[test]
    fn both_non_unique_indexes_fail_closed_on_absence_order_or_uniqueness_drift() {
        let request = prepared("pre_import");
        for (sql_field, unique_field, columns_field, wrong_columns) in [
            (
                "event_index_sql",
                "event_index_unique",
                "event_index_columns",
                "[\"evidence_kind\",\"issuance_event_id\",\"org_id\"]",
            ),
            (
                "document_index_sql",
                "document_index_unique",
                "document_index_columns",
                "[\"document_id\",\"org_id\"]",
            ),
        ] {
            let mut absent = pre_response(0);
            absent.result[0]["results"][0][sql_field] = Value::Null;
            assert!(
                sanitize_mln_0143_data_invariants_response(&mut absent, &request).is_err(),
                "{sql_field} absence"
            );

            let mut reordered = pre_response(0);
            reordered.result[0]["results"][0][columns_field] =
                Value::String(wrong_columns.to_owned());
            assert!(
                sanitize_mln_0143_data_invariants_response(&mut reordered, &request).is_err(),
                "{columns_field} order"
            );

            let mut unique = pre_response(0);
            unique.result[0]["results"][0][unique_field] = json!(1);
            assert!(
                sanitize_mln_0143_data_invariants_response(&mut unique, &request).is_err(),
                "{unique_field} drift"
            );
        }
    }

    #[test]
    fn unique_hash_index_fails_closed_on_structural_or_predicate_drift() {
        let request = prepared("pre_import");
        for (field, value, label) in [
            (
                "unique_hash_index_table",
                json!("other_table"),
                "wrong table",
            ),
            (
                "unique_hash_index_columns",
                json!(
                    "[\"org_id\",\"issuance_event_id\",\"evidence_kind\",\"document_hash\",\"id\"]"
                ),
                "extra column",
            ),
            (
                "unique_hash_index_columns",
                json!("[\"org_id\",\"evidence_kind\",\"issuance_event_id\",\"document_hash\"]"),
                "reordered column",
            ),
            ("unique_hash_index_unique", json!(0), "nonunique"),
            ("unique_hash_index_partial", json!(0), "nonpartial"),
            (
                "unique_hash_index_sql",
                json!(
                    "CREATE UNIQUE INDEX idx_equity_issuance_evidence_unique_hash ON equity_issuance_evidence_links(org_id, issuance_event_id, evidence_kind, document_hash) WHERE document_hash IS NOT NULL AND evidence_kind != 'other'"
                ),
                "predicate drift",
            ),
        ] {
            let mut response = pre_response(0);
            response.result[0]["results"][0][field] = value;
            assert!(
                sanitize_mln_0143_data_invariants_response(&mut response, &request).is_err(),
                "{label}"
            );
        }
    }

    #[test]
    fn pre_import_rejects_invalid_advanced_advisor_events() {
        let request = prepared("pre_import");
        let mut response = pre_response(0);
        response.result[0]["results"][0]["invalid_advanced_events"] = json!(1);
        assert!(sanitize_mln_0143_data_invariants_response(&mut response, &request).is_err());
    }

    #[test]
    fn reviewed_table_hash_rejects_inert_allowlist_text_in_both_phases() {
        let old_kinds = "'board_consent','stock_purchase_agreement','restricted_stock_purchase_agreement','safe_agreement','advisor_agreement','election_83b','consideration','funds_evidence','signature','stock_ledger','document_hash','other'";
        let new_kinds = "'board_consent','stock_purchase_agreement','restricted_stock_purchase_agreement','advisor_equity_instrument','safe_agreement','advisor_agreement','election_83b','consideration','funds_evidence','signature','stock_ledger','document_hash','other'";
        for (reviewed, kinds) in [
            (MLN_0143_PRE_TABLE_SQL, old_kinds),
            (MLN_0143_POST_TABLE_SQL, new_kinds),
        ] {
            let reviewed_hash = reviewed_table_sql_hash(reviewed).expect("reviewed SQL hash");
            let escaped_kinds = kinds.replace('\'', "''");
            for spoof in [
                format!(
                    "CREATE TABLE equity_issuance_evidence_links (evidence_kind TEXT /* CHECK (evidence_kind IN ({kinds})) */)"
                ),
                format!(
                    "CREATE TABLE equity_issuance_evidence_links (evidence_kind TEXT -- CHECK (evidence_kind IN ({kinds}))\n)"
                ),
                format!(
                    "CREATE TABLE equity_issuance_evidence_links (evidence_kind TEXT DEFAULT 'CHECK (evidence_kind IN ({escaped_kinds}))')"
                ),
            ] {
                assert_ne!(
                    reviewed_table_sql_hash(&spoof),
                    Some(reviewed_hash.clone()),
                    "inert SQL cannot satisfy the reviewed table definition"
                );
            }
        }
    }

    #[test]
    fn post_import_requires_the_new_packet_and_all_three_trigger_definitions() {
        let mut request = prepared("post_import");
        let trigger_sql = [
            "CREATE TRIGGER trg_advisor_equity_instrument_evidence_contract BEFORE INSERT ON x BEGIN SELECT 1; END",
            "CREATE TRIGGER trg_advisor_equity_instrument_evidence_immutable BEFORE UPDATE ON x BEGIN SELECT 1; END",
            "CREATE TRIGGER trg_advisor_grant_final_instrument_required BEFORE UPDATE ON x BEGIN SELECT 1; END",
        ];
        request
            .mln_0143_data_invariants
            .as_mut()
            .expect("contract")
            .trigger_definition_hashes = trigger_sql
            .iter()
            .map(|sql| normalized_sql_hash(sql))
            .collect();
        let mut response = pre_response(0);
        let row = response.result[0]["results"][0]
            .as_object_mut()
            .expect("result row");
        row.insert(
            "table_sql".to_owned(),
            Value::String(MLN_0143_POST_TABLE_SQL.to_owned()),
        );
        row.insert(
            "packet_rows".to_owned(),
            Value::String("[{\"profile\":\"advisor_grant\",\"evidence_kind\":\"advisor_agreement\",\"signature_required\":1,\"sort_order\":1},{\"profile\":\"advisor_grant\",\"evidence_kind\":\"advisor_equity_instrument\",\"signature_required\":1,\"sort_order\":2},{\"profile\":\"advisor_grant\",\"evidence_kind\":\"board_consent\",\"signature_required\":1,\"sort_order\":0}]".to_owned()),
        );
        for (field, sql) in [
            ("trigger_contract_sql", trigger_sql[0]),
            ("trigger_immutable_sql", trigger_sql[1]),
            ("trigger_final_required_sql", trigger_sql[2]),
        ] {
            row.insert(field.to_owned(), Value::String(sql.to_owned()));
        }
        row.insert("invalid_advanced_events".to_owned(), json!(0));
        let mut invalid_post = response.clone();
        invalid_post.result[0]["results"][0]["invalid_advanced_events"] = json!(1);
        assert!(sanitize_mln_0143_data_invariants_response(&mut invalid_post, &request).is_err());
        let mut restore_request = request.clone();
        restore_request
            .query_receipt
            .as_mut()
            .expect("query receipt")["phase"] = json!("post_restore");
        let mut invalid_restore = response.clone();
        invalid_restore.result[0]["results"][0]["invalid_advanced_events"] = json!(1);
        assert!(
            sanitize_mln_0143_data_invariants_response(&mut invalid_restore, &restore_request)
                .is_err()
        );
        sanitize_mln_0143_data_invariants_response(&mut response, &request)
            .expect("exact post-import state");
        assert_eq!(
            response.result["trigger_definition_hashes"]
                .as_array()
                .expect("trigger hashes")
                .len(),
            3
        );
    }
}

fn parse_output_format(value: &str) -> Result<OutputFormatV1> {
    match value {
        "json" => Ok(OutputFormatV1::Json),
        "ndjson" => Ok(OutputFormatV1::Ndjson),
        "csv" => Ok(OutputFormatV1::Csv),
        _ => Err(CloudflareError::InvalidAnalyticsQuery(format!(
            "output format `{value}` is not declared"
        ))),
    }
}

const fn output_media_type(format: OutputFormatV1) -> &'static str {
    match format {
        OutputFormatV1::Json => "application/json",
        OutputFormatV1::Ndjson => "application/x-ndjson",
        OutputFormatV1::Csv => "text/csv",
    }
}

fn graphql_request_body(contract: &GraphqlAnalyticsContractV1, input: &CallInput) -> Result<Value> {
    contract.validate_schema_fingerprint()?;
    let selectors = input.selectors.as_object().ok_or_else(|| {
        CloudflareError::InvalidAnalyticsQuery(
            "GraphQL selectors must be an object of fixed variable bindings".to_owned(),
        )
    })?;
    let body = input
        .body
        .as_ref()
        .and_then(Value::as_object)
        .ok_or_else(|| CloudflareError::MissingRequestBody(contract.operation_name.clone()))?;
    let mut variables = serde_json::Map::new();
    for (selector, variable) in &contract.selector_variables {
        let value = selectors.get(selector).cloned().ok_or_else(|| {
            CloudflareError::InvalidAnalyticsQuery(format!(
                "GraphQL selector `{selector}` is missing"
            ))
        })?;
        variables.insert(variable.clone(), value);
    }
    for (field, variable) in &contract.body_variables {
        let value = body.get(field).cloned().ok_or_else(|| {
            CloudflareError::InvalidAnalyticsQuery(format!(
                "GraphQL variable field `{field}` is missing"
            ))
        })?;
        variables.insert(variable.clone(), value);
    }
    Ok(serde_json::json!({
        "query": contract.document,
        "operationName": contract.operation_name,
        "variables": variables,
    }))
}

fn render_structured_analytics_sql(body: &Value, format: OutputFormatV1) -> Result<String> {
    render_structured_select_sql(body, "timestamp", true, Some(format))
}

fn render_structured_log_explorer_sql(body: &Value) -> Result<String> {
    let timestamp_field = body
        .get("timestamp_field")
        .and_then(Value::as_str)
        .filter(|value| valid_sql_identifier(value))
        .ok_or_else(|| {
            CloudflareError::InvalidAnalyticsQuery(
                "timestamp_field must be one plain SQL identifier".to_owned(),
            )
        })?;
    render_structured_select_sql(body, timestamp_field, false, None)
}

#[expect(
    clippy::too_many_lines,
    reason = "the structured read-only SQL renderer validates each clause before assembling one statement"
)]
fn render_structured_select_sql(
    body: &Value,
    timestamp_field: &str,
    clickhouse_time: bool,
    format: Option<OutputFormatV1>,
) -> Result<String> {
    let body = body.as_object().ok_or_else(|| {
        CloudflareError::InvalidAnalyticsQuery("structured SQL input must be an object".to_owned())
    })?;
    let dataset = body
        .get("dataset")
        .and_then(Value::as_str)
        .filter(|value| valid_sql_identifier(value))
        .ok_or_else(|| {
            CloudflareError::InvalidAnalyticsQuery(
                "dataset must be one plain SQL identifier".to_owned(),
            )
        })?;
    let start = body.get("start").and_then(Value::as_str).ok_or_else(|| {
        CloudflareError::InvalidAnalyticsQuery("start timestamp is missing".to_owned())
    })?;
    let end = body.get("end").and_then(Value::as_str).ok_or_else(|| {
        CloudflareError::InvalidAnalyticsQuery("end timestamp is missing".to_owned())
    })?;
    let mut projections = body
        .get("columns")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|field| sql_identifier_value(field, "column"))
        .collect::<Result<Vec<_>>>()?;
    for aggregate in body
        .get("aggregates")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let aggregate = aggregate.as_object().ok_or_else(|| {
            CloudflareError::InvalidAnalyticsQuery("aggregate must be an object".to_owned())
        })?;
        let function = aggregate
            .get("function")
            .and_then(Value::as_str)
            .filter(|function| matches!(*function, "count" | "sum" | "avg" | "min" | "max"))
            .ok_or_else(|| {
                CloudflareError::InvalidAnalyticsQuery(
                    "aggregate function must be count, sum, avg, min, or max".to_owned(),
                )
            })?;
        let expression = if function == "count" {
            "count(*)".to_owned()
        } else {
            let field = aggregate
                .get("field")
                .and_then(Value::as_str)
                .filter(|field| valid_sql_identifier(field))
                .ok_or_else(|| {
                    CloudflareError::InvalidAnalyticsQuery(format!(
                        "aggregate `{function}` requires one plain field identifier"
                    ))
                })?;
            format!("{function}({field})")
        };
        let alias = aggregate
            .get("alias")
            .and_then(Value::as_str)
            .filter(|alias| valid_sql_identifier(alias))
            .ok_or_else(|| {
                CloudflareError::InvalidAnalyticsQuery(
                    "aggregate alias must be one plain identifier".to_owned(),
                )
            })?;
        projections.push(format!("{expression} AS {alias}"));
    }
    if projections.is_empty() {
        return Err(CloudflareError::InvalidAnalyticsQuery(
            "at least one column or aggregate is required".to_owned(),
        ));
    }

    let mut predicates = if clickhouse_time {
        vec![
            format!(
                "{timestamp_field} >= toDateTime64('{}', 3)",
                sql_quote(start)
            ),
            format!("{timestamp_field} < toDateTime64('{}', 3)", sql_quote(end)),
        ]
    } else {
        vec![
            format!("{timestamp_field} >= '{}'", sql_quote(start)),
            format!("{timestamp_field} < '{}'", sql_quote(end)),
        ]
    };
    for filter in body
        .get("filters")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        predicates.push(render_structured_filter(filter)?);
    }

    let mut sql = format!(
        "SELECT {} FROM {} WHERE {}",
        projections.join(", "),
        dataset,
        predicates.join(" AND ")
    );
    let group_by = sql_identifier_array(body.get("group_by"), "group_by")?;
    if !group_by.is_empty() {
        sql.push_str(" GROUP BY ");
        sql.push_str(&group_by.join(", "));
    }
    let order_by = body
        .get("order_by")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|order| {
            let order = order.as_object().ok_or_else(|| {
                CloudflareError::InvalidAnalyticsQuery(
                    "order_by entries must be objects".to_owned(),
                )
            })?;
            let field = order
                .get("field")
                .and_then(Value::as_str)
                .filter(|field| valid_sql_identifier(field))
                .ok_or_else(|| {
                    CloudflareError::InvalidAnalyticsQuery(
                        "order_by field must be one plain identifier".to_owned(),
                    )
                })?;
            let direction = match order.get("direction").and_then(Value::as_str) {
                Some("asc") => "ASC",
                Some("desc") => "DESC",
                _ => {
                    return Err(CloudflareError::InvalidAnalyticsQuery(
                        "order_by direction must be asc or desc".to_owned(),
                    ));
                }
            };
            Ok(format!("{field} {direction}"))
        })
        .collect::<Result<Vec<_>>>()?;
    if !order_by.is_empty() {
        sql.push_str(" ORDER BY ");
        sql.push_str(&order_by.join(", "));
    }
    let limit = body.get("limit").and_then(Value::as_u64).ok_or_else(|| {
        CloudflareError::InvalidAnalyticsQuery("positive row limit is missing".to_owned())
    })?;
    sql.push_str(" LIMIT ");
    sql.push_str(&limit.to_string());
    if let Some(format) = format {
        let output = match format {
            OutputFormatV1::Json => "JSON",
            OutputFormatV1::Ndjson => "JSONEachRow",
            OutputFormatV1::Csv => "CSVWithNames",
        };
        sql.push_str(" FORMAT ");
        sql.push_str(output);
    }
    Ok(sql)
}

fn render_structured_filter(value: &Value) -> Result<String> {
    let filter = value.as_object().ok_or_else(|| {
        CloudflareError::InvalidAnalyticsQuery("filter must be an object".to_owned())
    })?;
    let field = filter
        .get("field")
        .and_then(Value::as_str)
        .filter(|field| valid_sql_identifier(field))
        .ok_or_else(|| {
            CloudflareError::InvalidAnalyticsQuery(
                "filter field must be one plain identifier".to_owned(),
            )
        })?;
    let operator = filter.get("operator").and_then(Value::as_str);
    let scalar_operator = match operator {
        Some("eq") => Some("="),
        Some("ne") => Some("!="),
        Some("gt") => Some(">"),
        Some("gte") => Some(">="),
        Some("lt") => Some("<"),
        Some("lte") => Some("<="),
        Some("in" | "not_in") => None,
        _ => {
            return Err(CloudflareError::InvalidAnalyticsQuery(
                "filter operator must be eq, ne, gt, gte, lt, lte, in, or not_in".to_owned(),
            ));
        }
    };
    let value = filter.get("value").ok_or_else(|| {
        CloudflareError::InvalidAnalyticsQuery("filter value is missing".to_owned())
    })?;
    if let Some(operator) = scalar_operator {
        return Ok(format!("{field} {operator} {}", sql_literal(value)?));
    }
    let values = value
        .as_array()
        .filter(|values| !values.is_empty() && values.len() <= 100)
        .ok_or_else(|| {
            CloudflareError::InvalidAnalyticsQuery(
                "in and not_in filters require between 1 and 100 scalar values".to_owned(),
            )
        })?
        .iter()
        .map(sql_literal)
        .collect::<Result<Vec<_>>>()?;
    let operator = if operator == Some("in") {
        "IN"
    } else {
        "NOT IN"
    };
    Ok(format!("{field} {operator} ({})", values.join(", ")))
}

fn sql_literal(value: &Value) -> Result<String> {
    match value {
        Value::String(value) => Ok(format!("'{}'", sql_quote(value))),
        Value::Number(value) => Ok(value.to_string()),
        Value::Bool(value) => Ok(if *value { "true" } else { "false" }.to_owned()),
        _ => Err(CloudflareError::InvalidAnalyticsQuery(
            "filter values must be strings, numbers, or booleans".to_owned(),
        )),
    }
}

fn sql_identifier_array(value: Option<&Value>, label: &str) -> Result<Vec<String>> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|value| sql_identifier_value(value, label))
        .collect()
}

fn sql_identifier_value(value: &Value, label: &str) -> Result<String> {
    value
        .as_str()
        .filter(|value| valid_sql_identifier(value))
        .map(str::to_owned)
        .ok_or_else(|| {
            CloudflareError::InvalidAnalyticsQuery(format!(
                "{label} values must be plain identifiers"
            ))
        })
}

fn valid_sql_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|character| character.is_ascii_alphabetic() || character == '_')
        && value.len() <= 64
        && characters.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

fn sql_quote(value: &str) -> String {
    value.replace('\'', "''")
}

fn add_declared_header_selectors(
    headers: &mut HeaderMap,
    capability: &CapabilityV1,
    selectors: Option<&serde_json::Map<String, Value>>,
) -> Result<()> {
    for selector in capability
        .selectors
        .iter()
        .filter(|selector| selector.location == "header")
    {
        let Some(value) = selectors.and_then(|values| values.get(&selector.name)) else {
            if selector.required {
                return Err(CloudflareError::MissingHeaderSelector(
                    selector.name.clone(),
                ));
            }
            continue;
        };
        if request_header_is_reserved(&selector.name) {
            return Err(CloudflareError::ReservedHeaderSelector(
                selector.name.clone(),
            ));
        }
        let rendered = if selector.name == "cf-r2-jurisdiction" {
            value.as_str().map(str::to_owned)
        } else {
            scalar(value)
        }
        .ok_or_else(|| CloudflareError::InvalidHeaderSelector(selector.name.clone()))?;
        let name = HeaderName::from_bytes(selector.name.as_bytes())
            .map_err(|_| CloudflareError::InvalidHeaderSelector(selector.name.clone()))?;
        let value = HeaderValue::from_str(&rendered)
            .map_err(|_| CloudflareError::InvalidHeaderSelector(selector.name.clone()))?;
        headers.insert(name, value);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CloudflareApiErrorV1 {
    pub code: Option<i64>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CloudflareResponseV1 {
    pub status: u16,
    pub success: bool,
    pub result: Value,
    pub errors: Vec<CloudflareApiErrorV1>,
    pub result_info: Option<Value>,
    pub etag: Option<String>,
    pub cf_ray: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperationVerificationV1 {
    pub strategy: String,
    pub passed: bool,
    pub basis: String,
    pub readback: CloudflareResponseV1,
    /// Exact non-secret resource identity discovered only after a governed
    /// asynchronous verifier correlates the materialized resource. This is
    /// never populated by ordinary readback strategies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlated_resource_id: Option<Value>,
}

#[derive(Clone)]
pub struct Executor {
    client: reqwest::Client,
    builder: RequestBuilder,
    max_retries: usize,
}

/// A Queue transport that can exist only for one consumed, boundary-attempted
/// event-batch plan. Raw pull and acknowledgement remain private implementation
/// details and cannot be reached with caller-supplied authority.
pub struct EventBatchTransport<'a> {
    executor: &'a Executor,
    pull: &'a CapabilityV1,
    acknowledge: &'a CapabilityV1,
    account_id: String,
    queue_id: String,
    batch_size: u32,
    visibility_timeout_ms: u64,
}

impl<'a> EventBatchTransport<'a> {
    fn from_consumed_plan(
        executor: &'a Executor,
        plan: &PlanV1,
        pull: &'a CapabilityV1,
        acknowledge: &'a CapabilityV1,
    ) -> Result<Self> {
        let contract = plan.capability.event_batch.as_ref().ok_or_else(|| {
            CloudflareError::InvalidEventBatchPlan {
                capability_id: plan.capability.id.clone(),
            }
        })?;
        if plan.status != PlanStatus::Consumed
            || plan.transaction_stage != TransactionStageV1::BoundaryAttemptPersisted
            || !plan.capability.event_batch_contract_supported()
            || !raw_event_batch_operation_matches(
                pull,
                &contract.pull_capability_id,
                &contract.pull_path,
                &contract.required_permissions,
            )
            || !raw_event_batch_operation_matches(
                acknowledge,
                &contract.acknowledge_capability_id,
                &contract.acknowledge_path,
                &contract.required_permissions,
            )
        {
            return Err(CloudflareError::InvalidEventBatchPlan {
                capability_id: plan.capability.id.clone(),
            });
        }
        let input: CallInput = serde_json::from_value(plan.input.clone()).map_err(|_| {
            CloudflareError::InvalidEventBatchPlan {
                capability_id: plan.capability.id.clone(),
            }
        })?;
        let account_id = required_string(&input.selectors, "account_id", &plan.capability.id)?;
        let queue_id = required_string(&input.selectors, "queue_id", &plan.capability.id)?;
        let body = input
            .body
            .as_ref()
            .ok_or_else(|| CloudflareError::InvalidEventBatchPlan {
                capability_id: plan.capability.id.clone(),
            })?;
        let batch_size = body
            .get("batch_size")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .filter(|value| (1..=contract.max_batch_size).contains(value))
            .ok_or_else(|| CloudflareError::InvalidEventBatchPlan {
                capability_id: plan.capability.id.clone(),
            })?;
        let visibility_timeout_ms = body
            .get("visibility_timeout_ms")
            .and_then(Value::as_u64)
            .filter(|value| (1_000..=contract.max_visibility_timeout_ms).contains(value))
            .ok_or_else(|| CloudflareError::InvalidEventBatchPlan {
                capability_id: plan.capability.id.clone(),
            })?;
        Ok(Self {
            executor,
            pull,
            acknowledge,
            account_id,
            queue_id,
            batch_size,
            visibility_timeout_ms,
        })
    }

    pub async fn pull(&self, credential: &AuthCredential) -> Result<CloudflareResponseV1> {
        self.execute(
            self.pull,
            CallInput {
                selectors: serde_json::json!({
                    "account_id": self.account_id,
                    "queue_id": self.queue_id,
                }),
                body: Some(serde_json::json!({
                    "batch_size": self.batch_size,
                    "visibility_timeout_ms": self.visibility_timeout_ms,
                })),
                ..CallInput::default()
            },
            credential,
        )
        .await
    }

    pub async fn acknowledge(
        &self,
        lease_ids: &[String],
        credential: &AuthCredential,
    ) -> Result<CloudflareResponseV1> {
        let unique = lease_ids.iter().collect::<BTreeSet<_>>();
        if lease_ids.is_empty()
            || lease_ids.len() > usize::try_from(self.batch_size).unwrap_or(usize::MAX)
            || unique.len() != lease_ids.len()
            || lease_ids.iter().any(String::is_empty)
        {
            return Err(CloudflareError::InvalidEventBatchPlan {
                capability_id: self.acknowledge.id.clone(),
            });
        }
        self.execute(
            self.acknowledge,
            CallInput {
                selectors: serde_json::json!({
                    "account_id": self.account_id,
                    "queue_id": self.queue_id,
                }),
                body: Some(serde_json::json!({
                    "acks": lease_ids
                        .iter()
                        .map(|lease_id| serde_json::json!({"lease_id":lease_id}))
                        .collect::<Vec<_>>(),
                    "retries": [],
                })),
                ..CallInput::default()
            },
            credential,
        )
        .await
    }

    async fn execute(
        &self,
        capability: &CapabilityV1,
        input: CallInput,
        credential: &AuthCredential,
    ) -> Result<CloudflareResponseV1> {
        let request = self.executor.builder.build_unchecked(capability, &input)?;
        self.executor.send(&request, credential).await
    }
}

fn raw_event_batch_operation_matches(
    capability: &CapabilityV1,
    expected_id: &str,
    expected_path: &str,
    expected_permissions: &[String],
) -> bool {
    capability.id == expected_id
        && capability.method == "POST"
        && capability.path == expected_path
        && capability.permissions == expected_permissions
        && capability
            .response_contract
            .as_ref()
            .is_some_and(|contract| {
                contract.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
            })
}

fn required_string(value: &Value, key: &str, capability_id: &str) -> Result<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| CloudflareError::InvalidEventBatchPlan {
            capability_id: capability_id.to_owned(),
        })
}

impl Executor {
    pub fn new(client: reqwest::Client, base_url: &str) -> Result<Self> {
        Ok(Self {
            client,
            builder: RequestBuilder::new(base_url)?,
            max_retries: 3,
        })
    }

    #[must_use]
    pub const fn with_max_retries(mut self, max_retries: usize) -> Self {
        self.max_retries = max_retries;
        self
    }

    pub async fn execute_read(
        &self,
        capability: &CapabilityV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<CloudflareResponseV1> {
        if capability.r2_log_retrieval.is_some() {
            return Err(CloudflareError::R2LogCredentialsRequired);
        }
        let request = self.builder.build(capability, input)?;
        self.send_paginated(&request, credential).await
    }

    pub fn event_batch_transport<'a>(
        &'a self,
        plan: &PlanV1,
        pull: &'a CapabilityV1,
        acknowledge: &'a CapabilityV1,
    ) -> Result<EventBatchTransport<'a>> {
        EventBatchTransport::from_consumed_plan(self, plan, pull, acknowledge)
    }

    /// Executes a bounded analytics read and writes only the declared output to
    /// a newly-created mode-0600 file. The returned envelope contains a hash
    /// receipt instead of duplicating query rows on stdout.
    pub async fn execute_read_to_file(
        &self,
        capability: &CapabilityV1,
        input: &CallInput,
        credential: &AuthCredential,
        output_path: &Path,
    ) -> Result<CloudflareResponseV1> {
        if capability.r2_log_retrieval.is_some() {
            return Err(CloudflareError::R2LogCredentialsRequired);
        }
        if capability.d1_full_export.is_some() {
            let request = self.builder.build(capability, input)?;
            let output_path = validate_d1_export_output_path(output_path)?;
            return Box::pin(self.execute_d1_full_export_to_file(
                &request,
                credential,
                &output_path,
            ))
            .await;
        }
        if capability.analytics_query.is_none() {
            return Err(CloudflareError::InvalidAnalyticsQuery(
                "file output is restricted to bounded analytics capabilities".to_owned(),
            ));
        }
        let request = self.builder.build(capability, input)?;
        self.send_paginated_with_output(&request, credential, Some(output_path))
            .await
    }

    async fn execute_d1_full_export_to_file(
        &self,
        request: &PreparedRequest,
        credential: &AuthCredential,
        output_path: &Path,
    ) -> Result<CloudflareResponseV1> {
        let contract = request.d1_full_export.as_ref().ok_or_else(|| {
            CloudflareError::InvalidAnalyticsQuery("D1 full-export contract is missing".to_owned())
        })?;
        let mut bookmark = None;
        for _ in 0..contract.max_poll_attempts {
            let mut poll = request.clone();
            poll.max_bytes = contract.max_poll_response_bytes;
            poll.body = Some(bookmark.as_deref().map_or_else(
                || serde_json::json!({"output_format":"polling"}),
                |bookmark| serde_json::json!({"output_format":"polling","current_bookmark":bookmark}),
            ));
            let response = self.send(&poll, credential).await?;
            if !response.success {
                return Ok(response);
            }
            bookmark = response
                .result
                .get("at_bookmark")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .or(bookmark);
            match response.result.get("status").and_then(Value::as_str) {
                Some("complete") => {
                    let signed_url = response
                        .result
                        .pointer("/result/signed_url")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            CloudflareError::InvalidAnalyticsQuery(
                                "completed D1 export omitted signed_url".to_owned(),
                            )
                        })?;
                    let url = Url::parse(signed_url)?;
                    if url.scheme() != request.url.scheme()
                        || url.host_str().is_none()
                        || !url.username().is_empty()
                        || url.password().is_some()
                    {
                        return Err(CloudflareError::InvalidAnalyticsQuery(
                            "D1 export returned an unsafe signed URL".to_owned(),
                        ));
                    }
                    let filename = response
                        .result
                        .pointer("/result/filename")
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                    let download = self
                        .client
                        .get(url)
                        .timeout(Duration::from_secs(contract.max_download_seconds))
                        .send()
                        .await?;
                    if !download.status().is_success() {
                        return Err(CloudflareError::InvalidAnalyticsQuery(format!(
                            "D1 export download failed with HTTP {}",
                            download.status().as_u16()
                        )));
                    }
                    return stream_d1_export_response(
                        download,
                        request,
                        output_path,
                        bookmark,
                        filename,
                    )
                    .await;
                }
                Some("error") => {
                    return Err(CloudflareError::InvalidAnalyticsQuery(
                        response
                            .result
                            .get("error")
                            .and_then(Value::as_str)
                            .unwrap_or("provider D1 export failed")
                            .to_owned(),
                    ));
                }
                _ => sleep(Duration::from_millis(100)).await,
            }
        }
        Err(CloudflareError::InvalidAnalyticsQuery(
            "D1 full export did not complete within the governed polling bound".to_owned(),
        ))
    }

    /// Executes the one pinned Logs Engine retrieval with its two ephemeral R2
    /// headers and streams the response directly to a newly-created private
    /// file. Neither credential can enter a serializable request or receipt.
    pub async fn execute_r2_log_retrieval_to_file(
        &self,
        capability: &CapabilityV1,
        input: &CallInput,
        credential: &AuthCredential,
        r2_credentials: &R2LogRetrievalCredentials,
        output_path: &Path,
    ) -> Result<CloudflareResponseV1> {
        let contract = capability
            .r2_log_retrieval
            .as_ref()
            .ok_or(CloudflareError::R2LogOutputFileRequired)?;
        if !contract.requires_new_mode_0600_file {
            return Err(CloudflareError::InvalidR2LogRetrieval(
                "the catalog must require a new private output file".to_owned(),
            ));
        }
        let request = self.builder.build(capability, input)?;
        self.send_r2_log_retrieval_to_file(&request, credential, r2_credentials, output_path)
            .await
    }

    pub async fn execute_consumed_plan(
        &self,
        plan: &mut PlanV1,
        current_catalog_hash: &str,
        credential: &AuthCredential,
    ) -> Result<CloudflareResponseV1> {
        let input: CallInput = serde_json::from_value(plan.input.clone())
            .map_err(cfctl_core::CoreError::Serialization)?;
        self.execute_consumed_plan_with_input(plan, current_catalog_hash, credential, &input)
            .await
    }

    pub async fn execute_consumed_plan_with_input(
        &self,
        plan: &mut PlanV1,
        current_catalog_hash: &str,
        credential: &AuthCredential,
        input: &CallInput,
    ) -> Result<CloudflareResponseV1> {
        if plan.catalog_hash != current_catalog_hash {
            return Err(CloudflareError::CatalogDrift {
                planned: plan.catalog_hash.clone(),
                current: current_catalog_hash.to_owned(),
            });
        }
        if plan.status != PlanStatus::Consumed {
            return Err(CloudflareError::Plan(
                cfctl_core::CoreError::InvalidPlanState {
                    operation_id: plan.operation_id.clone(),
                    actual: plan.status,
                    expected: "durably persisted consumed plan",
                },
            ));
        }
        validate_verification_preconditions(&plan.capability, input)?;
        if plan.capability.d1_restore_exact_bookmark.is_some() {
            return self
                .execute_d1_restore_exact_bookmark(plan, input, credential)
                .await;
        }
        if plan.capability.d1_approved_mln_import.is_some() {
            return Err(CloudflareError::InvalidRequestBody(
                "approved MLN import requires the durable checkpoint executor; generic mutation execution is blocked"
                    .to_owned(),
            ));
        }
        let mut request = self.builder.build_unchecked(&plan.capability, input)?;
        request.headers.insert(
            HeaderName::from_static("idempotency-key"),
            HeaderValue::from_str(&plan.operation_id)
                .map_err(|_| CloudflareError::InvalidConditionalHeader)?,
        );
        match self.send(&request, credential).await {
            Ok(response) => {
                plan.status = if response.success {
                    PlanStatus::Running
                } else {
                    PlanStatus::Failed
                };
                Ok(response)
            }
            Err(error) => {
                plan.status = PlanStatus::Failed;
                Err(error)
            }
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the pre-read, single boundary attempt, response validation, and post-read remain one auditable recovery state machine"
    )]
    async fn execute_d1_restore_exact_bookmark(
        &self,
        plan: &mut PlanV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<CloudflareResponseV1> {
        let contract = plan
            .capability
            .d1_restore_exact_bookmark
            .as_ref()
            .ok_or_else(|| {
                CloudflareError::InvalidRequestBody(
                    "D1 exact-bookmark restore contract is missing".to_owned(),
                )
            })?;
        let caller_body = input
            .body
            .as_ref()
            .ok_or_else(|| CloudflareError::MissingRequestBody(plan.capability.id.clone()))?;
        let value = |name: &str| {
            caller_body
                .get(name)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    CloudflareError::InvalidRequestBody(format!(
                        "D1 exact-bookmark restore requires non-empty `{name}`"
                    ))
                })
        };
        let target_bookmark = value("target_bookmark")?;
        let expected_current_bookmark = value("expected_current_bookmark")?;
        let source_operation_id = value("source_operation_id")?;
        let source_evidence_hash = value("source_evidence_hash")?;
        let request_digest = hash_value(caller_body)?;
        let mut bookmark_capability = CapabilityV1::new(
            "d1-current-time-travel-bookmark",
            "Read current D1 time-travel bookmark",
            "GET",
            &contract.bookmark_path,
        );
        "D1".clone_into(&mut bookmark_capability.product);
        "account".clone_into(&mut bookmark_capability.account_scope);
        bookmark_capability.permissions = vec!["D1 Read".to_owned()];
        bookmark_capability.selectors = plan.capability.selectors.clone();
        bookmark_capability.response_contract = plan.capability.response_contract.clone();
        let bookmark_input = CallInput {
            selectors: input.selectors.clone(),
            query: serde_json::json!({}),
            body: None,
            ..CallInput::default()
        };
        let bookmark_request = self.builder.build(&bookmark_capability, &bookmark_input)?;
        let pre = self.send(&bookmark_request, credential).await?;
        let pre_bookmark = required_d1_bookmark(&pre, "pre-restore")?;
        if pre_bookmark != expected_current_bookmark {
            return Err(CloudflareError::InvalidRequestBody(format!(
                "D1 expected current bookmark `{expected_current_bookmark}` did not match live bookmark `{pre_bookmark}`; restore POST was not attempted"
            )));
        }
        let mut restore_request = self.builder.build_unchecked(&plan.capability, input)?;
        restore_request.headers.insert(
            HeaderName::from_static("idempotency-key"),
            HeaderValue::from_str(&plan.operation_id)
                .map_err(|_| CloudflareError::InvalidConditionalHeader)?,
        );
        // The destructive restore boundary is attempted exactly once. A 429,
        // 5xx, timeout, or transport uncertainty is returned to the plan
        // runtime for rectification and is never replayed here.
        let restore = self
            .clone()
            .with_max_retries(0)
            .send(&restore_request, credential)
            .await?;
        if !restore.success {
            plan.status = PlanStatus::Failed;
            return Ok(restore);
        }
        let returned_bookmark = restore
            .result
            .get("bookmark")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
        let previous_bookmark = restore
            .result
            .get("previous_bookmark")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
        let message = restore
            .result
            .get("message")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
        let mut response = restore;
        response.result["_cfctl"] = serde_json::json!({
            "target_bookmark":target_bookmark,
            "expected_current_bookmark":expected_current_bookmark,
            "pre_restore_bookmark":pre_bookmark,
            "returned_bookmark":returned_bookmark,
            "previous_bookmark":previous_bookmark,
            "source_operation_id":source_operation_id,
            "source_evidence_hash":source_evidence_hash,
            "request_digest":request_digest,
            "provider_message":message,
            "post_retry_count":contract.post_retry_count,
            "performed":true,
            "verified":false,
        });
        plan.status = PlanStatus::Running;
        Ok(response)
    }

    /// Executes the closed D1 import protocol. The caller must durably persist
    /// every emitted checkpoint before this method advances to the next
    /// request. A checkpoint failure or uncertain provider send stops the
    /// state machine; no init, upload, or ingest request is replayed.
    #[expect(
        clippy::too_many_lines,
        reason = "the import protocol is one linear durable checkpoint state machine"
    )]
    pub async fn execute_d1_approved_mln_import<F>(
        &self,
        plan: &mut PlanV1,
        input: &CallInput,
        credential: &AuthCredential,
        stage_path: &Path,
        mut persist: F,
    ) -> Result<CloudflareResponseV1>
    where
        F: FnMut(&D1ImportCheckpointV1) -> std::result::Result<(), String>,
    {
        let contract = plan
            .capability
            .d1_approved_mln_import
            .as_ref()
            .ok_or_else(|| {
                CloudflareError::InvalidRequestBody(
                    "approved MLN import contract is missing".to_owned(),
                )
            })?;
        validate_d1_approved_mln_import_contract(&plan.capability, input)?;
        let migration_id = input
            .body
            .as_ref()
            .and_then(|body| body.get("migration_id"))
            .and_then(Value::as_str)
            .ok_or_else(|| CloudflareError::MissingRequestBody(plan.capability.id.clone()))?;
        let migration = contract
            .migrations
            .iter()
            .find(|migration| migration.migration_id == migration_id)
            .ok_or_else(|| {
                CloudflareError::InvalidRequestBody(
                    "migration is absent from the approved catalogue".to_owned(),
                )
            })?;
        if stage_path.file_name().and_then(|name| name.to_str())
            != Some(migration.basename.as_str())
        {
            return Err(CloudflareError::InvalidRequestBody(
                "managed stage basename drifted from the plan".to_owned(),
            ));
        }
        let mut stage_options = OpenOptions::new();
        stage_options.read(true);
        #[cfg(unix)]
        stage_options.custom_flags(libc::O_NOFOLLOW);
        let mut stage_file =
            stage_options
                .open(stage_path)
                .map_err(|source| CloudflareError::OutputFile {
                    path: stage_path.display().to_string(),
                    source,
                })?;
        let stage_metadata =
            stage_file
                .metadata()
                .map_err(|source| CloudflareError::OutputFile {
                    path: stage_path.display().to_string(),
                    source,
                })?;
        if !stage_metadata.is_file() || stage_metadata.len() != migration.bytes {
            return Err(CloudflareError::InvalidRequestBody(
                "managed stage is no longer the approved regular file".to_owned(),
            ));
        }
        let capacity = usize::try_from(migration.bytes).map_err(|_| {
            CloudflareError::InvalidRequestBody(
                "approved migration size exceeds this host".to_owned(),
            )
        })?;
        let mut staged = Vec::with_capacity(capacity);
        stage_file
            .read_to_end(&mut staged)
            .map_err(|source| CloudflareError::OutputFile {
                path: stage_path.display().to_string(),
                source,
            })?;
        let staged_sha = hex::encode(Sha256::digest(&staged));
        let staged_md5 = hex::encode(Md5::digest(&staged));
        if staged.len() as u64 != migration.bytes
            || staged_sha != migration.sha256
            || staged_md5 != migration.md5
        {
            return Err(CloudflareError::InvalidRequestBody(
                "managed stage bytes drifted after planning".to_owned(),
            ));
        }
        let provider_capability = import_provider_capability(&plan.capability);
        let send_provider = |body: Value| {
            let provider_capability = provider_capability.clone();
            let request_input = CallInput {
                selectors: input.selectors.clone(),
                query: serde_json::json!({}),
                body: Some(body),
                ..CallInput::default()
            };
            async move {
                let request = self
                    .builder
                    .build_unchecked(&provider_capability, &request_input)?;
                self.clone()
                    .with_max_retries(0)
                    .send(&request, credential)
                    .await
            }
        };
        let init = match send_provider(serde_json::json!({
            "action":"init",
            "etag":migration.md5,
        }))
        .await
        {
            Ok(response) => response,
            Err(error) => {
                persist_import_uncertainty(&mut persist, plan, "init_send_uncertain")?;
                plan.status = PlanStatus::RectificationRequired;
                return Err(error);
            }
        };
        if !init.success {
            persist_import_response(&mut persist, plan, "init_response", &init, None)?;
            plan.status = PlanStatus::Failed;
            return Ok(init);
        }
        let upload_url_raw = init.result.get("upload_url").and_then(Value::as_str);
        let filename_raw = init.result.get("filename").and_then(Value::as_str);
        persist_import_response(
            &mut persist,
            plan,
            "init_response",
            &init,
            Some(serde_json::json!({
                "filename":filename_raw,
                "upload_url_sha256":upload_url_raw.map(|value| format!("sha256:{}", hex::encode(Sha256::digest(value.as_bytes())))),
            })),
        )?;
        let Some(upload_url_raw) = upload_url_raw else {
            plan.status = PlanStatus::RectificationRequired;
            return Err(CloudflareError::InvalidRequestBody(
                "D1 import init omitted upload_url; do not replay".to_owned(),
            ));
        };
        let Some(filename) = filename_raw.filter(|value| !value.is_empty() && value.len() <= 512)
        else {
            plan.status = PlanStatus::RectificationRequired;
            return Err(CloudflareError::InvalidRequestBody(
                "D1 import init omitted filename; do not replay".to_owned(),
            ));
        };
        let upload_url = match validate_d1_import_upload_url(upload_url_raw, contract) {
            Ok(url) => url,
            Err(error) => {
                plan.status = PlanStatus::RectificationRequired;
                return Err(error);
            }
        };
        let upload = match self
            .client
            .put(upload_url)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(staged)
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) => {
                persist_import_uncertainty(&mut persist, plan, "upload_send_uncertain")?;
                plan.status = PlanStatus::RectificationRequired;
                return Err(CloudflareError::Http(error));
            }
        };
        let upload_status = upload.status().as_u16();
        let upload_receipt = D1ImportCheckpointV1 {
            schema_version: 1,
            operation_id: plan.operation_id.clone(),
            step: "upload_response".to_owned(),
            performed: true,
            rectification_required: !upload.status().is_success(),
            receipt: serde_json::json!({"http_status":upload_status,"success":upload.status().is_success()}),
        };
        persist(&upload_receipt).map_err(CloudflareError::InvalidRequestBody)?;
        if !upload.status().is_success() {
            plan.status = PlanStatus::RectificationRequired;
            return Err(CloudflareError::InvalidRequestBody(format!(
                "D1 import upload returned HTTP {upload_status}; do not replay"
            )));
        }
        let ingest = match send_provider(serde_json::json!({
            "action":"ingest",
            "etag":migration.md5,
            "filename":filename,
        }))
        .await
        {
            Ok(response) => response,
            Err(error) => {
                persist_import_uncertainty(&mut persist, plan, "ingest_send_uncertain")?;
                plan.status = PlanStatus::RectificationRequired;
                return Err(error);
            }
        };
        persist_import_response(&mut persist, plan, "ingest_response", &ingest, None)?;
        if !ingest.success {
            plan.status = PlanStatus::RectificationRequired;
            return Ok(ingest);
        }
        let Some(at_bookmark) = ingest
            .result
            .get("at_bookmark")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        else {
            plan.status = PlanStatus::RectificationRequired;
            return Err(CloudflareError::InvalidRequestBody(
                "D1 import ingest omitted at_bookmark; do not replay".to_owned(),
            ));
        };
        let at_bookmark = at_bookmark.to_owned();
        for attempt in 1..=contract.max_poll_attempts {
            let poll = match send_provider(serde_json::json!({
                "action":"poll",
                "current_bookmark":at_bookmark,
            }))
            .await
            {
                Ok(response) => response,
                Err(error) => {
                    persist_import_uncertainty(
                        &mut persist,
                        plan,
                        &format!("poll_send_uncertain_{attempt}"),
                    )?;
                    plan.status = PlanStatus::RectificationRequired;
                    return Err(error);
                }
            };
            persist_import_response(
                &mut persist,
                plan,
                &format!("poll_response_{attempt}"),
                &poll,
                None,
            )?;
            if !poll.success {
                plan.status = PlanStatus::RectificationRequired;
                return Ok(poll);
            }
            match poll
                .result
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
            {
                "complete" => {
                    let Some(final_bookmark) = poll
                        .result
                        .get("final_bookmark")
                        .and_then(Value::as_str)
                        .filter(|value| !value.is_empty())
                    else {
                        plan.status = PlanStatus::RectificationRequired;
                        return Err(CloudflareError::InvalidRequestBody(
                            "completed D1 import omitted final_bookmark; do not replay".to_owned(),
                        ));
                    };
                    let boundary = D1ImportCheckpointV1 {
                        schema_version: 1,
                        operation_id: plan.operation_id.clone(),
                        step: "provider_complete".to_owned(),
                        performed: true,
                        rectification_required: false,
                        receipt: serde_json::json!({
                            "migration_id":migration_id,
                            "source_sha256":format!("sha256:{}",migration.sha256),
                            "source_md5":migration.md5,
                            "source_bytes":migration.bytes,
                            "target":{"account_id":contract.account_id,"database_id":contract.database_id},
                            "plan_input_hash":hash_value(&plan.input)?,
                            "prerequisites":input.body,
                            "at_bookmark":at_bookmark,
                            "final_bookmark":final_bookmark,
                            "state":"provider_complete",
                        }),
                    };
                    persist(&boundary).map_err(CloudflareError::InvalidRequestBody)?;
                    let mut completed = poll;
                    completed.result["_cfctl"] = boundary.receipt;
                    plan.status = PlanStatus::Running;
                    return Ok(completed);
                }
                "error" => {
                    plan.status = PlanStatus::RectificationRequired;
                    return Ok(poll);
                }
                "active" | "pending" => {}
                _ => {
                    plan.status = PlanStatus::RectificationRequired;
                    return Err(CloudflareError::InvalidRequestBody(
                        "D1 import poll returned unknown status; do not replay".to_owned(),
                    ));
                }
            }
        }
        persist_import_uncertainty(&mut persist, plan, "poll_exhausted")?;
        plan.status = PlanStatus::RectificationRequired;
        Err(CloudflareError::InvalidRequestBody(
            "D1 import poll bound exhausted; resume only the existing bookmark poll".to_owned(),
        ))
    }

    /// Runs the operation-specific live readback declared by a plan. Unknown
    /// strategy names fail closed rather than silently becoming generic checks.
    pub async fn verify_plan(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        let input: CallInput = serde_json::from_value(plan.input.clone())
            .map_err(cfctl_core::CoreError::Serialization)?;
        self.verify_plan_with_input(plan, apply_response, &input, credential)
            .await
    }

    /// Runs the operation-specific verifier with the exact execution input
    /// already validated by the caller. This lane is required for secret
    /// request bodies because the durable plan contains only a hash-bound
    /// credential-store reference, never the value-bearing body.
    pub async fn verify_plan_with_input(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        let strategy = plan.capability.verification.strategy.as_str();
        validate_verification_preconditions(&plan.capability, input)?;
        if strategy == "d1_current_bookmark_equals_restore_result_bookmark" {
            return self
                .verify_d1_restore_exact_bookmark(plan, apply_response, input, credential)
                .await;
        }
        if strategy.starts_with("api_token_details_") {
            return self
                .verify_api_token(plan, apply_response, input, credential)
                .await;
        }

        if strategy.starts_with("dns_record_details_") {
            return self
                .verify_dns_record(plan, apply_response, input, credential)
                .await;
        }

        if strategy.starts_with("oauth_client_") {
            return self
                .verify_oauth_client_secret_rotation(plan, apply_response, input, credential)
                .await;
        }

        if strategy == "worker_script_secret_reports_planned_name_and_type_after_put" {
            return self
                .verify_worker_script_secret_put(plan, apply_response, input, credential)
                .await;
        }

        if strategy == "access_service_token_reports_refreshed_expiration" {
            return self
                .verify_access_service_token_refresh(plan, apply_response, input, credential)
                .await;
        }

        if strategy == "cache_purge_response_reports_target_zone_id" {
            return self.verify_cache_purge(plan, apply_response, input);
        }

        if strategy == "email_routing_settings_response_reports_enabled_state" {
            return self.verify_email_routing_settings(plan, apply_response);
        }

        if strategy.starts_with("async_list_operation_") {
            return self
                .verify_async_list_mutation(plan, apply_response, input, credential)
                .await;
        }

        if is_delete_verifier(strategy) {
            return self
                .verify_resource_delete(plan, apply_response, input, credential)
                .await;
        }
        if is_update_verifier(strategy) {
            return self
                .verify_resource_update(plan, apply_response, input, credential)
                .await;
        }
        if is_create_verifier(strategy) {
            return self
                .verify_resource_create(plan, apply_response, input, credential)
                .await;
        }

        Err(CloudflareError::UnsupportedVerificationStrategy(
            strategy.to_owned(),
        ))
    }

    async fn verify_d1_restore_exact_bookmark(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        let contract = plan
            .capability
            .d1_restore_exact_bookmark
            .as_ref()
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "D1 exact-bookmark restore verification contract is missing".to_owned(),
                )
            })?;
        let returned_bookmark = required_d1_bookmark(apply_response, "restore")?;
        let previous_bookmark = apply_response
            .result
            .get("previous_bookmark")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "D1 restore response omitted required previous_bookmark".to_owned(),
                )
            })?;
        apply_response
            .result
            .get("message")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "D1 restore response omitted required message".to_owned(),
                )
            })?;
        let mut bookmark_capability = CapabilityV1::new(
            "d1-current-time-travel-bookmark",
            "Read current D1 time-travel bookmark",
            "GET",
            &contract.bookmark_path,
        );
        "D1".clone_into(&mut bookmark_capability.product);
        "account".clone_into(&mut bookmark_capability.account_scope);
        bookmark_capability.permissions = vec!["D1 Read".to_owned()];
        bookmark_capability.selectors = plan.capability.selectors.clone();
        bookmark_capability.response_contract = plan.capability.response_contract.clone();
        let request = self.builder.build(
            &bookmark_capability,
            &CallInput {
                selectors: input.selectors.clone(),
                query: serde_json::json!({}),
                body: None,
                ..CallInput::default()
            },
        )?;
        let mut readback = self.send(&request, credential).await?;
        let post_bookmark = required_d1_bookmark(&readback, "post-restore")?.to_owned();
        let passed = post_bookmark == returned_bookmark;
        let mut receipt = apply_response
            .result
            .get("_cfctl")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        receipt["post_restore_bookmark"] = Value::String(post_bookmark.clone());
        receipt["previous_bookmark"] = Value::String(previous_bookmark.to_owned());
        receipt["performed"] = Value::Bool(true);
        receipt["verified"] = Value::Bool(passed);
        readback.result["_cfctl"] = receipt;
        Ok(OperationVerificationV1 {
            strategy: plan.capability.verification.strategy.clone(),
            passed,
            basis: if passed {
                "the exact post-restore current bookmark equals Cloudflare's returned restore bookmark"
                    .to_owned()
            } else {
                format!(
                    "D1 post-restore bookmark `{post_bookmark}` did not equal returned restore bookmark `{returned_bookmark}`"
                )
            },
            readback,
            correlated_resource_id: None,
        })
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the asynchronous verifier is one bounded state machine from operation identity through complete collection proof"
    )]
    async fn verify_async_list_mutation(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        let contract = plan
            .capability
            .async_collection_mutation
            .as_ref()
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "the hash-bound asynchronous collection contract is absent".to_owned(),
                )
            })?;
        let operation_id = apply_response
            .result
            .pointer(&contract.apply_operation_id_pointer)
            .and_then(Value::as_str)
            .filter(|identity| !identity.is_empty())
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "Cloudflare accepted the List mutation without a non-empty bulk operation identity"
                        .to_owned(),
                )
            })?;
        let account_id = input
            .selectors
            .get("account_id")
            .and_then(Value::as_str)
            .filter(|identity| !identity.is_empty())
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "the asynchronous List verifier requires an exact account selector".to_owned(),
                )
            })?;
        let list_id = input
            .selectors
            .get("list_id")
            .and_then(Value::as_str)
            .filter(|identity| !identity.is_empty())
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "the asynchronous List verifier requires an exact list selector".to_owned(),
                )
            })?;

        let status_capability = CapabilityV1::new(
            &contract.operation_status_capability_id,
            "Asynchronous List operation status verification readback",
            "GET",
            &contract.operation_status_path,
        );
        let status_request = self.builder.build(
            &status_capability,
            &CallInput {
                selectors: serde_json::json!({
                    "account_id":account_id,
                    contract.operation_id_selector.clone():operation_id,
                }),
                query: serde_json::json!({}),
                body: None,
                ..CallInput::default()
            },
        )?;
        let mut terminal = None;
        for attempt in 0..contract.max_poll_attempts {
            let response = self.send(&status_request, credential).await?;
            let returned_id = response
                .result
                .pointer(&contract.status_operation_id_pointer)
                .and_then(Value::as_str);
            if !response.success || returned_id != Some(operation_id) {
                return Err(CloudflareError::MissingVerificationTarget(
                    "the bulk-operation status readback did not prove the exact operation identity"
                        .to_owned(),
                ));
            }
            let status = response
                .result
                .pointer(&contract.status_state_pointer)
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    CloudflareError::MissingVerificationTarget(
                        "the bulk-operation status readback omitted its bounded state".to_owned(),
                    )
                })?;
            if status == contract.completed_state || status == contract.failed_state {
                terminal = Some(response);
                break;
            }
            if !contract
                .pending_states
                .iter()
                .any(|pending| pending == status)
            {
                return Err(CloudflareError::MissingVerificationTarget(format!(
                    "the bulk-operation status `{status}` is outside the hash-bound state machine"
                )));
            }
            if attempt + 1 < contract.max_poll_attempts {
                sleep(Duration::from_millis(contract.poll_interval_ms)).await;
            }
        }
        let Some(status_readback) = terminal else {
            let readback = async_list_receipt_response(AsyncListReceipt {
                status: 200,
                operation_id,
                operation_status: "timeout",
                cursor_complete: false,
                match_count: 0,
                resource_id: None,
                resource_hash: None,
                failure: None,
            });
            return Ok(OperationVerificationV1 {
                strategy: plan.capability.verification.strategy.clone(),
                passed: false,
                basis: format!(
                    "Cloudflare did not report a terminal List bulk-operation state within {} hash-bound poll attempts",
                    contract.max_poll_attempts
                ),
                readback,
                correlated_resource_id: None,
            });
        };
        let terminal_status = status_readback
            .result
            .pointer(&contract.status_state_pointer)
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "the terminal bulk-operation readback omitted its validated state".to_owned(),
                )
            })?;
        if terminal_status == contract.failed_state {
            let readback = async_list_receipt_response(AsyncListReceipt {
                status: status_readback.status,
                operation_id,
                operation_status: terminal_status,
                cursor_complete: false,
                match_count: 0,
                resource_id: None,
                resource_hash: None,
                failure: status_readback.result.get("error").cloned(),
            });
            return Ok(OperationVerificationV1 {
                strategy: plan.capability.verification.strategy.clone(),
                passed: false,
                basis: "Cloudflare reported that the exact List bulk operation failed; the collection mutation is not verified"
                    .to_owned(),
                readback,
                correlated_resource_id: None,
            });
        }

        let collection_capability = CapabilityV1::new(
            &contract.collection_capability_id,
            "Asynchronous List collection verification readback",
            "GET",
            &contract.collection_path,
        );
        let mut collection_request = self.builder.build(
            &collection_capability,
            &CallInput {
                selectors: serde_json::json!({"account_id":account_id,"list_id":list_id}),
                query: serde_json::json!({}),
                body: None,
                ..CallInput::default()
            },
        )?;
        set_query_parameter(&mut collection_request.url, "per_page", "500");
        let collection = self.send_paginated(&collection_request, credential).await?;
        let cursor_complete = !contract.requires_cursor_completion
            || collection.result_info.as_ref().is_some_and(|info| {
                info.get("cfctl_cursor_complete").and_then(Value::as_bool) == Some(true)
            });
        let items = collection.result.as_array().ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "the List verification readback did not return an item array".to_owned(),
            )
        })?;
        let create = plan.capability.verification.strategy
            == "async_list_operation_completes_and_correlated_member_exists";
        if create {
            let planned = input
                .body
                .as_ref()
                .and_then(Value::as_array)
                .and_then(|items| (items.len() == 1).then(|| &items[0]))
                .ok_or_else(|| {
                    CloudflareError::MissingVerificationTarget(
                        "the governed List add must contain exactly one planned item".to_owned(),
                    )
                })?;
            let correlation = planned
                .get("comment")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    CloudflareError::MissingVerificationTarget(
                        "the governed List add omitted its correlation comment".to_owned(),
                    )
                })?;
            let matching = items
                .iter()
                .filter(|item| item.get("comment").and_then(Value::as_str) == Some(correlation))
                .collect::<Vec<_>>();
            let projection_matches = matching
                .first()
                .and_then(|item| governed_list_item_projection(item))
                == governed_list_item_projection(planned);
            let resource_id = matching.first().and_then(|item| {
                item.pointer(&contract.collection_item_identity_pointer)
                    .and_then(Value::as_str)
                    .filter(|identity| !identity.is_empty())
            });
            let passed = apply_response.success
                && collection.success
                && cursor_complete
                && matching.len() == 1
                && projection_matches
                && resource_id.is_some();
            let projection_hash = matching
                .first()
                .and_then(|item| governed_list_item_projection(item))
                .map(|projection| hash_value(&projection))
                .transpose()?;
            let readback = async_list_receipt_response(AsyncListReceipt {
                status: collection.status,
                operation_id,
                operation_status: terminal_status,
                cursor_complete,
                match_count: matching.len(),
                resource_id,
                resource_hash: projection_hash.as_deref(),
                failure: None,
            });
            let basis = if passed {
                "Cloudflare completed the exact bulk operation and the complete cursor-paginated List contained one schema-matching member with a correlated identity"
                    .to_owned()
            } else {
                format!(
                    "List add verification failed (apply success={}, collection success={}, cursor complete={}, correlation matches={}, projection matches={}, identity present={})",
                    apply_response.success,
                    collection.success,
                    cursor_complete,
                    matching.len(),
                    projection_matches,
                    resource_id.is_some()
                )
            };
            return Ok(OperationVerificationV1 {
                strategy: plan.capability.verification.strategy.clone(),
                passed,
                basis,
                readback,
                correlated_resource_id: resource_id
                    .map(|identity| Value::String(identity.to_owned())),
            });
        }

        let deleted_ids = governed_list_delete_ids(input)?;
        let live_ids = items
            .iter()
            .map(|item| {
                item.pointer(&contract.collection_item_identity_pointer)
                    .and_then(Value::as_str)
                    .filter(|identity| !identity.is_empty())
            })
            .collect::<Vec<_>>();
        let identity_shape_valid = live_ids.iter().all(Option::is_some);
        let all_absent = deleted_ids
            .iter()
            .all(|deleted| live_ids.iter().all(|live| *live != Some(deleted.as_str())));
        let passed = apply_response.success
            && collection.success
            && cursor_complete
            && identity_shape_valid
            && all_absent;
        let deleted_ids_hash = hash_value(&serde_json::json!(deleted_ids))?;
        let readback = async_list_receipt_response(AsyncListReceipt {
            status: collection.status,
            operation_id,
            operation_status: terminal_status,
            cursor_complete,
            match_count: deleted_ids.len(),
            resource_id: None,
            resource_hash: Some(&deleted_ids_hash),
            failure: None,
        });
        let basis = if passed {
            "Cloudflare completed the exact bulk delete and the complete cursor-paginated List omitted every planned member identity"
                .to_owned()
        } else {
            format!(
                "List removal verification failed (apply success={}, collection success={}, cursor complete={}, item identities valid={}, every removed identity absent={})",
                apply_response.success,
                collection.success,
                cursor_complete,
                identity_shape_valid,
                all_absent
            )
        };
        Ok(OperationVerificationV1 {
            strategy: plan.capability.verification.strategy.clone(),
            passed,
            basis,
            readback,
            correlated_resource_id: None,
        })
    }

    async fn verify_api_token(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        let strategy = plan.capability.verification.strategy.as_str();
        let (token_id, expectation) = token_verification_target(strategy, input, apply_response)?;
        let account_scoped = plan.capability.path.starts_with("/accounts/");
        let details_path = if account_scoped {
            "/accounts/{account_id}/tokens/{token_id}"
        } else {
            "/user/tokens/{token_id}"
        };
        let details = CapabilityV1::new(
            "api-token-verification-readback",
            "API token verification readback",
            "GET",
            details_path,
        );
        let selectors = if account_scoped {
            serde_json::json!({"account_id": plan.account_id, "token_id": token_id})
        } else {
            serde_json::json!({"token_id": token_id})
        };
        let request = self.builder.build(
            &details,
            &CallInput {
                selectors,
                query: Value::Object(serde_json::Map::new()),
                body: None,
                ..CallInput::default()
            },
        )?;
        let readback = self.send(&request, credential).await?;
        let (passed, basis) = evaluate_token_readback(expectation, &token_id, &readback);
        Ok(OperationVerificationV1 {
            strategy: strategy.to_owned(),
            passed,
            basis,
            readback,
            correlated_resource_id: None,
        })
    }

    /// Verifies a cache purge by asserting Cloudflare accepted the request and
    /// echoed the target zone id in `result.id`. There is no readback that can
    /// prove cache eviction, so this is deliberately a no-readback verifier:
    /// the `apply_response` itself is the evidence, and the basis states plainly
    /// that it proves acceptance and scoping, not eviction.
    // Takes `&self` to sit uniformly beside the async `verify_*` siblings the
    // dispatcher calls as methods, though this no-readback verifier needs no
    // client state of its own.
    #[allow(clippy::unused_self)]
    fn verify_cache_purge(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        input: &CallInput,
    ) -> Result<OperationVerificationV1> {
        let strategy = plan.capability.verification.strategy.clone();
        let zone_id = input
            .selectors
            .as_object()
            .and_then(|selectors| selectors.get("zone_id"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "the planned cache purge zone_id selector is absent".to_owned(),
                )
            })?;
        let returned_id = apply_response.result.pointer("/id").and_then(Value::as_str);
        let (passed, basis) = match returned_id {
            Some(id) if id == zone_id => (
                true,
                format!(
                    "Cloudflare accepted the cache purge and echoed the target zone id `{zone_id}` in result.id; this proves the purge was accepted and scoped to the target zone, not that cached content was evicted (no readback can verify eviction)"
                ),
            ),
            Some(id) => (
                false,
                format!(
                    "cache purge response reported zone id `{id}`, which does not match the target zone `{zone_id}`; the purge scope cannot be confirmed"
                ),
            ),
            None => (
                false,
                "cache purge response did not report a result.id; acceptance and scope cannot be confirmed".to_owned(),
            ),
        };
        Ok(OperationVerificationV1 {
            strategy,
            passed,
            basis,
            readback: apply_response.clone(),
            correlated_resource_id: None,
        })
    }

    /// Verifies an Email Routing enable/disable toggle by asserting the settings
    /// object the action endpoint returns reports `enabled` at the intended
    /// value (`true` for enable, `false` for disable). Like the cache-purge
    /// verifier this is deliberately a no-readback verifier: the `apply_response`
    /// is the evidence, and the basis states plainly it proves the setting now
    /// reports the intended value, not that MX/DNS propagation or live mail
    /// delivery has converged.
    // Takes `&self` to sit uniformly beside the async `verify_*` siblings the
    // dispatcher calls as methods, though this no-readback verifier needs no
    // client state of its own.
    #[allow(clippy::unused_self)]
    fn verify_email_routing_settings(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
    ) -> Result<OperationVerificationV1> {
        let strategy = plan.capability.verification.strategy.clone();
        let expected_enabled = match plan.capability.id.as_str() {
            "email-routing-settings-enable-email-routing" => true,
            "email-routing-settings-disable-email-routing" => false,
            other => {
                return Err(CloudflareError::MissingVerificationTarget(format!(
                    "the Email Routing settings verifier is bound to an unexpected capability `{other}`"
                )));
            }
        };
        let reported = apply_response
            .result
            .pointer("/enabled")
            .and_then(Value::as_bool);
        let (passed, basis) = match reported {
            Some(state) if state == expected_enabled => (
                true,
                format!(
                    "Cloudflare accepted the request and its Email Routing settings response reports enabled={state}, matching the intended state; this proves the routing setting now reports the target value, not that MX/DNS propagation or live mail delivery has converged"
                ),
            ),
            Some(state) => (
                false,
                format!(
                    "Email Routing settings response reports enabled={state}, but the operation intended enabled={expected_enabled}; the setting change cannot be confirmed"
                ),
            ),
            None => (
                false,
                "Email Routing settings response did not report a boolean result.enabled; the setting change cannot be confirmed".to_owned(),
            ),
        };
        Ok(OperationVerificationV1 {
            strategy,
            passed,
            basis,
            readback: apply_response.clone(),
            correlated_resource_id: None,
        })
    }

    async fn verify_worker_script_secret_put(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        let target = plan.capability.same_path_read.as_ref().ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "the hash-bound Worker script secret readback contract is absent".to_owned(),
            )
        })?;
        let body = input
            .body
            .as_ref()
            .and_then(Value::as_object)
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "the planned Worker script secret body is absent or not an object".to_owned(),
                )
            })?;
        let secret_name = body.get("name").and_then(Value::as_str).ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "the planned Worker script secret name is absent".to_owned(),
            )
        })?;
        let secret_type = body.get("type").and_then(Value::as_str).ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "the planned Worker script secret type is absent".to_owned(),
            )
        })?;
        let mut selectors = input.selectors.as_object().cloned().ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "the planned Worker script selectors are not an object".to_owned(),
            )
        })?;
        selectors.insert(
            "secret_name".to_owned(),
            Value::String(secret_name.to_owned()),
        );
        let details = same_path_verification_capability(
            &plan.capability,
            &target.read_capability_id,
            "Worker script secret verification readback",
            &target.path,
        );
        let request = self.builder.build(
            &details,
            &CallInput {
                selectors: Value::Object(selectors),
                query: Value::Object(serde_json::Map::new()),
                body: None,
                ..CallInput::default()
            },
        )?;
        let readback = self.send(&request, credential).await?;
        let (passed, basis) = evaluate_worker_script_secret_put_readback(
            secret_name,
            secret_type,
            apply_response,
            &readback,
        );
        Ok(OperationVerificationV1 {
            strategy: plan.capability.verification.strategy.clone(),
            passed,
            basis,
            readback,
            correlated_resource_id: None,
        })
    }

    async fn verify_dns_record(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        let strategy = plan.capability.verification.strategy.as_str();
        let (zone_id, record_id, expectation) =
            dns_record_verification_target(strategy, input, apply_response)?;
        let details = CapabilityV1::new(
            "dns-record-verification-readback",
            "DNS record verification readback",
            "GET",
            cfctl_core::DNS_RECORD_DETAIL_PATH,
        );
        let request = self.builder.build(
            &details,
            &CallInput {
                selectors: serde_json::json!({
                    "zone_id": zone_id,
                    "dns_record_id": record_id,
                }),
                query: Value::Object(serde_json::Map::new()),
                body: None,
                ..CallInput::default()
            },
        )?;
        let readback = self.send(&request, credential).await?;
        let (passed, basis) = evaluate_dns_record_readback(
            expectation,
            &record_id,
            input.body.as_ref(),
            apply_response,
            &readback,
        )?;
        Ok(OperationVerificationV1 {
            strategy: strategy.to_owned(),
            passed,
            basis,
            readback,
            correlated_resource_id: None,
        })
    }

    async fn verify_oauth_client_secret_rotation(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        let strategy = plan.capability.verification.strategy.as_str();
        let target = plan.capability.same_path_read.as_ref().ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "the hash-bound OAuth client detail readback contract is absent".to_owned(),
            )
        })?;
        let oauth_client_id = input
            .selectors
            .get("oauth_client_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "the planned OAuth client selector is absent or empty".to_owned(),
                )
            })?;
        let details = same_path_verification_capability(
            &plan.capability,
            &target.read_capability_id,
            "OAuth client secret rotation verification readback",
            &target.path,
        );
        let request = self.builder.build(
            &details,
            &CallInput {
                selectors: input.selectors.clone(),
                query: Value::Object(serde_json::Map::new()),
                body: None,
                ..CallInput::default()
            },
        )?;
        let readback = self.send(&request, credential).await?;
        let (passed, basis) = evaluate_oauth_client_secret_readback(
            strategy,
            oauth_client_id,
            apply_response,
            &readback,
        )?;
        Ok(OperationVerificationV1 {
            strategy: strategy.to_owned(),
            passed,
            basis,
            readback,
            correlated_resource_id: None,
        })
    }

    async fn verify_access_service_token_refresh(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        let target = plan.capability.same_path_read.as_ref().ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "the hash-bound Access service-token detail readback contract is absent".to_owned(),
            )
        })?;
        let service_token_id = input
            .selectors
            .get("service_token_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "the planned Access service-token selector is absent or empty".to_owned(),
                )
            })?;
        let details = same_path_verification_capability(
            &plan.capability,
            &target.read_capability_id,
            "Access service-token refresh verification readback",
            &target.path,
        );
        let request = self.builder.build(
            &details,
            &CallInput {
                selectors: input.selectors.clone(),
                query: Value::Object(serde_json::Map::new()),
                body: None,
                ..CallInput::default()
            },
        )?;
        let readback = self.send(&request, credential).await?;
        let (passed, basis) = evaluate_access_service_token_refresh_readback(
            service_token_id,
            apply_response,
            &readback,
        );
        Ok(OperationVerificationV1 {
            strategy: plan.capability.verification.strategy.clone(),
            passed,
            basis,
            readback,
            correlated_resource_id: None,
        })
    }

    async fn verify_resource_create(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        match plan.capability.verification.strategy.as_str() {
            "created_resource_contains_planned_fields_by_returned_id"
            | "created_access_application_contains_planned_fields_by_returned_id" => {
                self.verify_created_resource(plan, apply_response, input, credential)
                    .await
            }
            "parent_collection_contains_created_resource_id_and_planned_fields"
            | "worker_tail_collection_contains_created_lease_id" => {
                self.verify_created_collection_resource(plan, apply_response, input, credential)
                    .await
            }
            "parent_object_contains_created_nested_resource_by_correlation" => {
                self.verify_created_nested_resource(plan, apply_response, input, credential)
                    .await
            }
            "web_analytics_rule_list_contains_created_id_and_planned_fields" => {
                self.verify_web_analytics_rule_create(plan, apply_response, input, credential)
                    .await
            }
            strategy => Err(CloudflareError::UnsupportedVerificationStrategy(
                strategy.to_owned(),
            )),
        }
    }

    async fn verify_resource_delete(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        match plan.capability.verification.strategy.as_str() {
            "same_resource_returns_not_found_after_delete" => {
                self.verify_exact_resource_delete(plan, apply_response, input, credential)
                    .await
            }
            "worker_script_settings_returns_not_found_after_delete" => {
                self.verify_worker_script_delete(plan, apply_response, input, credential)
                    .await
            }
            "parent_collection_omits_deleted_resource_id" => {
                self.verify_parent_collection_delete(plan, apply_response, input, credential)
                    .await
            }
            "parent_object_omits_deleted_nested_resource_id" => {
                self.verify_parent_object_nested_delete(plan, apply_response, input, credential)
                    .await
            }
            "web_analytics_rule_list_omits_deleted_id" => {
                self.verify_web_analytics_rule_delete(plan, apply_response, input, credential)
                    .await
            }
            strategy => Err(CloudflareError::UnsupportedVerificationStrategy(
                strategy.to_owned(),
            )),
        }
    }

    /// A Worker script's own GET returns the raw module body, so deletion is
    /// proven against the script's `/settings` sub-path, which answers 404
    /// once the script is gone.
    async fn verify_worker_script_delete(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        let target = plan.capability.same_path_read.as_ref().ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "the hash-bound Worker script settings readback contract is absent".to_owned(),
            )
        })?;
        let details = same_path_verification_capability(
            &plan.capability,
            &target.read_capability_id,
            "Worker script deletion settings readback",
            &target.path,
        );
        let request = self.builder.build(
            &details,
            &CallInput {
                selectors: input.selectors.clone(),
                query: Value::Object(serde_json::Map::new()),
                body: None,
                ..CallInput::default()
            },
        )?;
        let readback = self.send(&request, credential).await?;
        let passed = apply_response.success && readback.status == 404 && !readback.success;
        let basis = if passed {
            "the script's settings sub-path returned not found after deletion".to_owned()
        } else {
            format!(
                "Worker script deletion was not proven (apply success={}, settings readback HTTP {}, readback success={})",
                apply_response.success, readback.status, readback.success
            )
        };
        Ok(OperationVerificationV1 {
            strategy: plan.capability.verification.strategy.clone(),
            passed,
            basis,
            readback,
            correlated_resource_id: None,
        })
    }

    async fn verify_exact_resource_delete(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        let target = plan.capability.same_path_read.as_ref().ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "the hash-bound same-path delete readback contract is absent".to_owned(),
            )
        })?;
        let details = same_path_verification_capability(
            &plan.capability,
            &target.read_capability_id,
            "Exact resource deletion verification readback",
            &target.path,
        );
        let request = self.builder.build(
            &details,
            &CallInput {
                selectors: input.selectors.clone(),
                query: Value::Object(serde_json::Map::new()),
                body: None,
                ..CallInput::default()
            },
        )?;
        let readback = self.send(&request, credential).await?;
        let passed = apply_response.success && readback.status == 404 && !readback.success;
        let basis = if passed {
            "the exact planned resource path returned not found after deletion".to_owned()
        } else {
            format!(
                "exact resource deletion was not proven (apply success={}, readback HTTP {}, readback success={})",
                apply_response.success, readback.status, readback.success
            )
        };
        Ok(OperationVerificationV1 {
            strategy: plan.capability.verification.strategy.clone(),
            passed,
            basis,
            readback,
            correlated_resource_id: None,
        })
    }

    async fn verify_parent_collection_delete(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        let target = plan.capability.deleted_resource.as_ref().ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "the hash-bound deleted-resource contract is absent".to_owned(),
            )
        })?;
        let deleted_identity = input
            .selectors
            .get(&target.identity_selector)
            .and_then(Value::as_str)
            .filter(|identity| !identity.is_empty())
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "the planned delete selector has no non-empty resource identity".to_owned(),
                )
            })?;
        let mut selectors = input.selectors.as_object().cloned().ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "planned delete selectors are not an object".to_owned(),
            )
        })?;
        selectors.remove(&target.identity_selector);
        let collection = CapabilityV1::new(
            &target.read_capability_id,
            "Deleted resource collection verification readback",
            "GET",
            &target.collection_path,
        );
        let request = self.builder.build(
            &collection,
            &CallInput {
                selectors: Value::Object(selectors),
                query: Value::Object(serde_json::Map::new()),
                body: None,
                ..CallInput::default()
            },
        )?;
        let readback = self.send_paginated(&request, credential).await?;
        let pagination_complete =
            collection_pagination_complete(target.requires_page_number_completion, &readback);
        let identities = readback.result.as_array().map(|items| {
            items
                .iter()
                .map(|item| {
                    item.pointer(&target.response_item_identity_pointer)
                        .and_then(Value::as_str)
                        .filter(|identity| !identity.is_empty())
                })
                .collect::<Vec<_>>()
        });
        let identity_shape_valid = identities
            .as_ref()
            .is_some_and(|identities| identities.iter().all(Option::is_some));
        let deleted_identity_absent = identities.as_ref().is_some_and(|identities| {
            identities
                .iter()
                .all(|identity| *identity != Some(deleted_identity))
        });
        let passed = apply_response.success
            && readback.success
            && pagination_complete
            && identity_shape_valid
            && deleted_identity_absent;
        let basis = if passed {
            "the complete schema-proven parent collection omitted the exact deleted resource identity"
                .to_owned()
        } else {
            format!(
                "parent collection did not prove deletion (apply success={}, readback HTTP {}, readback success={}, pagination complete={}, result array={}, item identities valid={}, deleted identity absent={})",
                apply_response.success,
                readback.status,
                readback.success,
                pagination_complete,
                identities.is_some(),
                identity_shape_valid,
                deleted_identity_absent
            )
        };
        Ok(OperationVerificationV1 {
            strategy: plan.capability.verification.strategy.clone(),
            passed,
            basis,
            readback,
            correlated_resource_id: None,
        })
    }

    async fn verify_exact_resource_update(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        let operation = if plan.capability.verification.strategy
            == "same_path_result_contains_planned_fields_after_mutation"
        {
            "mutation"
        } else {
            "update"
        };
        let target = plan.capability.same_path_read.as_ref().ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(format!(
                "the hash-bound same-path {operation} readback contract is absent"
            ))
        })?;
        let planned = input
            .body
            .as_ref()
            .and_then(Value::as_object)
            .filter(|body| !body.is_empty())
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(format!(
                    "planned {operation} body is absent, empty, or not an object"
                ))
            })?;
        let readback_title = format!("Exact resource {operation} verification readback");
        let details = same_path_verification_capability(
            &plan.capability,
            &target.read_capability_id,
            &readback_title,
            &target.path,
        );
        let request = self.builder.build(
            &details,
            &CallInput {
                selectors: input.selectors.clone(),
                query: Value::Object(serde_json::Map::new()),
                body: None,
                ..CallInput::default()
            },
        )?;
        let readback = self.send(&request, credential).await?;
        let mismatches =
            mismatched_verifiable_planned_fields(&plan.capability, planned, &readback.result);
        let passed = apply_response.success && readback.success && mismatches.is_empty();
        let basis = if passed {
            format!("the exact resource readback contained every planned {operation} field")
        } else {
            format!(
                "exact resource {operation} was not proven (apply success={}, readback HTTP {}, readback success={}, fields={})",
                apply_response.success,
                readback.status,
                readback.success,
                render_field_names(&mismatches)
            )
        };
        Ok(OperationVerificationV1 {
            strategy: plan.capability.verification.strategy.clone(),
            passed,
            basis,
            readback,
            correlated_resource_id: None,
        })
    }

    async fn verify_resource_update(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        match plan.capability.verification.strategy.as_str() {
            "same_resource_contains_planned_fields_after_update"
            | "same_path_result_contains_planned_fields_after_update"
            | "same_path_result_contains_planned_fields_after_mutation" => {
                self.verify_exact_resource_update(plan, apply_response, input, credential)
                    .await
            }
            "parent_collection_item_contains_planned_fields_after_update" => {
                self.verify_parent_collection_update(plan, apply_response, input, credential)
                    .await
            }
            strategy => Err(CloudflareError::UnsupportedVerificationStrategy(
                strategy.to_owned(),
            )),
        }
    }

    async fn verify_parent_collection_update(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        let target = plan.capability.updated_resource.as_ref().ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "the hash-bound updated-resource contract is absent".to_owned(),
            )
        })?;
        let updated_identity = input
            .selectors
            .get(&target.identity_selector)
            .and_then(Value::as_str)
            .filter(|identity| !identity.is_empty())
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "the planned update selector has no non-empty resource identity".to_owned(),
                )
            })?;
        let planned = input
            .body
            .as_ref()
            .and_then(Value::as_object)
            .filter(|body| !body.is_empty())
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "planned update body is absent, empty, or not an object".to_owned(),
                )
            })?;
        let mut selectors = input.selectors.as_object().cloned().ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "planned update selectors are not an object".to_owned(),
            )
        })?;
        selectors.remove(&target.identity_selector);
        let collection = CapabilityV1::new(
            &target.read_capability_id,
            "Updated resource collection verification readback",
            "GET",
            &target.collection_path,
        );
        let request = self.builder.build(
            &collection,
            &CallInput {
                selectors: Value::Object(selectors),
                query: Value::Object(serde_json::Map::new()),
                body: None,
                ..CallInput::default()
            },
        )?;
        let readback = self.send_paginated(&request, credential).await?;
        let pagination_complete =
            collection_pagination_complete(target.requires_page_number_completion, &readback);
        let items = readback.result.as_array();
        let identity_shape_valid = items.is_some_and(|items| {
            items.iter().all(|item| {
                item.pointer(&target.response_item_identity_pointer)
                    .and_then(Value::as_str)
                    .is_some_and(|identity| !identity.is_empty())
            })
        });
        let matching_items = items
            .into_iter()
            .flatten()
            .filter(|item| {
                item.pointer(&target.response_item_identity_pointer)
                    .and_then(Value::as_str)
                    == Some(updated_identity)
            })
            .collect::<Vec<_>>();
        let planned_fields_match = matching_items.first().is_some_and(|item| {
            mismatched_verifiable_planned_fields(&plan.capability, planned, item).is_empty()
        });
        let passed = apply_response.success
            && readback.success
            && pagination_complete
            && identity_shape_valid
            && matching_items.len() == 1
            && planned_fields_match;
        let basis = if passed {
            "the complete schema-proven parent collection contained exactly one matching identity with every planned update field"
                .to_owned()
        } else {
            format!(
                "parent collection did not prove update (apply success={}, readback HTTP {}, readback success={}, pagination complete={}, result array={}, item identities valid={}, identity matches={}, planned fields match={})",
                apply_response.success,
                readback.status,
                readback.success,
                pagination_complete,
                items.is_some(),
                identity_shape_valid,
                matching_items.len(),
                planned_fields_match
            )
        };
        Ok(OperationVerificationV1 {
            strategy: plan.capability.verification.strategy.clone(),
            passed,
            basis,
            readback,
            correlated_resource_id: None,
        })
    }

    async fn verify_created_resource(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        let target = plan.capability.created_resource.as_ref().ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "the hash-bound created-resource contract is absent".to_owned(),
            )
        })?;
        let planned = input
            .body
            .as_ref()
            .and_then(Value::as_object)
            .filter(|body| !body.is_empty())
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "planned create body is absent, empty, or not an object".to_owned(),
                )
            })?;
        let resource_id = apply_response
            .result
            .pointer(&target.response_result_identity_pointer)
            .and_then(resource_identity_value)
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "the successful creation response has no non-empty string or integer schema-proven identity"
                        .to_owned(),
                )
            })?;
        let mut selectors = input.selectors.as_object().cloned().ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "planned create selectors are not an object".to_owned(),
            )
        })?;
        selectors.insert(target.identity_selector.clone(), resource_id.clone());
        let mut details = CapabilityV1::new(
            &target.read_capability_id,
            "Created resource verification readback",
            "GET",
            &target.detail_path,
        );
        details.selectors.clone_from(&plan.capability.selectors);
        let request = self.builder.build(
            &details,
            &CallInput {
                selectors: Value::Object(selectors),
                query: Value::Object(serde_json::Map::new()),
                body: None,
                ..CallInput::default()
            },
        )?;
        let readback = self.send(&request, credential).await?;
        let readback_identity = readback
            .result
            .pointer(&target.response_result_identity_pointer)
            .and_then(resource_identity_value);
        let mut mismatches =
            mismatched_verifiable_planned_fields(&plan.capability, planned, &readback.result);
        extend_r2_bucket_create_mismatches(plan, input, &readback.result, &mut mismatches);
        let passed = apply_response.success
            && readback.success
            && readback_identity.as_ref() == Some(&resource_id)
            && mismatches.is_empty();
        let basis = if passed {
            "the exact created-resource readback matched the returned identity and every planned field"
                .to_owned()
        } else {
            format!(
                "created resource was not proven (apply success={}, readback HTTP {}, readback success={}, identity match={}, fields={})",
                apply_response.success,
                readback.status,
                readback.success,
                readback_identity.as_ref() == Some(&resource_id),
                render_field_names(&mismatches)
            )
        };
        Ok(OperationVerificationV1 {
            strategy: plan.capability.verification.strategy.clone(),
            passed,
            basis,
            readback,
            correlated_resource_id: None,
        })
    }

    #[expect(
        clippy::too_many_lines,
        reason = "collection verification keeps pagination completeness, identity shape, and planned-field proof together"
    )]
    async fn verify_created_collection_resource(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        let target = plan
            .capability
            .created_collection_resource
            .as_ref()
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "the hash-bound created-collection-resource contract is absent".to_owned(),
                )
            })?;
        let worker_tail = is_worker_tail_create_capability(&plan.capability);
        let planned = if worker_tail {
            None
        } else {
            Some(
                input
                    .body
                    .as_ref()
                    .and_then(Value::as_object)
                    .filter(|body| !body.is_empty())
                    .ok_or_else(|| {
                        CloudflareError::MissingVerificationTarget(
                            "planned create body is absent, empty, or not an object".to_owned(),
                        )
                    })?,
            )
        };
        let resource_id = apply_response
            .result
            .pointer(&target.response_result_identity_pointer)
            .and_then(Value::as_str)
            .filter(|identity| !identity.is_empty())
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "the successful creation response has no non-empty schema-proven identity"
                        .to_owned(),
                )
            })?;
        let collection = CapabilityV1::new(
            &target.read_capability_id,
            "Created resource collection verification readback",
            "GET",
            &target.collection_path,
        );
        let request = self.builder.build(
            &collection,
            &CallInput {
                selectors: input.selectors.clone(),
                query: Value::Object(serde_json::Map::new()),
                body: None,
                ..CallInput::default()
            },
        )?;
        let readback = self.send_paginated(&request, credential).await?;
        let pagination_complete =
            collection_pagination_complete(target.requires_page_number_completion, &readback);
        let items = readback.result.as_array();
        let identity_shape_valid = items.is_some_and(|items| {
            items.iter().all(|item| {
                item.pointer(&target.response_item_identity_pointer)
                    .and_then(Value::as_str)
                    .is_some_and(|identity| !identity.is_empty())
            })
        });
        let matching_items = items
            .into_iter()
            .flatten()
            .filter(|item| {
                item.pointer(&target.response_item_identity_pointer)
                    .and_then(Value::as_str)
                    == Some(resource_id)
            })
            .collect::<Vec<_>>();
        let planned_fields_match = worker_tail
            || planned.is_some_and(|planned| {
                matching_items.first().is_some_and(|item| {
                    mismatched_verifiable_planned_fields(&plan.capability, planned, item).is_empty()
                })
            });
        let passed = apply_response.success
            && readback.success
            && pagination_complete
            && identity_shape_valid
            && matching_items.len() == 1
            && planned_fields_match;
        let basis = if passed {
            if worker_tail {
                "the live Worker tail collection contained exactly one lease with the returned creation identity; the bearer URL remained sink-only"
                    .to_owned()
            } else {
                "the complete schema-proven parent collection contained exactly one returned creation identity with every planned field"
                    .to_owned()
            }
        } else {
            format!(
                "parent collection did not prove creation (apply success={}, readback HTTP {}, readback success={}, pagination complete={}, result array={}, item identities valid={}, identity matches={}, planned fields match={})",
                apply_response.success,
                readback.status,
                readback.success,
                pagination_complete,
                items.is_some(),
                identity_shape_valid,
                matching_items.len(),
                planned_fields_match
            )
        };
        Ok(OperationVerificationV1 {
            strategy: plan.capability.verification.strategy.clone(),
            passed,
            basis,
            readback,
            correlated_resource_id: None,
        })
    }

    #[expect(
        clippy::too_many_lines,
        reason = "nested-resource verification correlates apply and live parent readbacks in one proof path"
    )]
    async fn verify_created_nested_resource(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        let target = plan
            .capability
            .created_nested_resource
            .as_ref()
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "the hash-bound created-nested-resource contract is absent".to_owned(),
                )
            })?;
        let planned = input
            .body
            .as_ref()
            .and_then(Value::as_object)
            .filter(|body| !body.is_empty())
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "planned nested-resource create body is absent, empty, or not an object"
                        .to_owned(),
                )
            })?;
        let correlation = planned
            .get(&target.correlation_field)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "planned nested-resource correlation value is absent or empty".to_owned(),
                )
            })?;
        let apply_items = apply_response
            .result
            .pointer(&target.items_pointer)
            .and_then(Value::as_array);
        let apply_matches = apply_items
            .into_iter()
            .flatten()
            .filter(|item| {
                item.get(&target.correlation_field).and_then(Value::as_str) == Some(correlation)
            })
            .collect::<Vec<_>>();
        let resource_id = (apply_matches.len() == 1)
            .then(|| {
                apply_matches[0]
                    .pointer(&target.response_item_identity_pointer)
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
            })
            .flatten();
        let apply_fields_match = apply_matches.first().is_some_and(|item| {
            mismatched_verifiable_planned_fields(&plan.capability, planned, item).is_empty()
        });

        let parent = CapabilityV1::new(
            &target.read_capability_id,
            "Created nested resource parent verification readback",
            "GET",
            &target.parent_path,
        );
        let request = self.builder.build(
            &parent,
            &CallInput {
                selectors: input.selectors.clone(),
                query: Value::Object(serde_json::Map::new()),
                body: None,
                ..CallInput::default()
            },
        )?;
        let readback = self.send(&request, credential).await?;
        let readback_items = readback
            .result
            .pointer(&target.items_pointer)
            .and_then(Value::as_array);
        let readback_matches = readback_items
            .into_iter()
            .flatten()
            .filter(|item| {
                item.get(&target.correlation_field).and_then(Value::as_str) == Some(correlation)
                    && item
                        .pointer(&target.response_item_identity_pointer)
                        .and_then(Value::as_str)
                        == resource_id
            })
            .collect::<Vec<_>>();
        let readback_fields_match = readback_matches.first().is_some_and(|item| {
            mismatched_verifiable_planned_fields(&plan.capability, planned, item).is_empty()
        });
        let passed = apply_response.success
            && readback.success
            && resource_id.is_some()
            && apply_matches.len() == 1
            && apply_fields_match
            && readback_matches.len() == 1
            && readback_fields_match;
        let basis = if passed {
            format!(
                "the apply response and live parent readback each contained exactly one nested resource correlated by `{}` with the same schema-proven identity and every planned field",
                target.correlation_field
            )
        } else {
            format!(
                "nested resource was not proven (apply success={}, apply items={}, apply matches={}, identity present={}, apply fields match={}, readback HTTP {}, readback success={}, readback items={}, readback matches={}, readback fields match={})",
                apply_response.success,
                apply_items.is_some(),
                apply_matches.len(),
                resource_id.is_some(),
                apply_fields_match,
                readback.status,
                readback.success,
                readback_items.is_some(),
                readback_matches.len(),
                readback_fields_match,
            )
        };
        Ok(OperationVerificationV1 {
            strategy: plan.capability.verification.strategy.clone(),
            passed,
            basis,
            readback,
            correlated_resource_id: None,
        })
    }

    async fn verify_parent_object_nested_delete(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        let target = plan
            .capability
            .deleted_nested_resource
            .as_ref()
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "the hash-bound deleted-nested-resource contract is absent".to_owned(),
                )
            })?;
        let resource_id = input
            .selectors
            .get(&target.identity_selector)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "planned nested-resource delete identity is absent or empty".to_owned(),
                )
            })?;
        let mut selectors = input.selectors.as_object().cloned().ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "planned nested-resource delete selectors are not an object".to_owned(),
            )
        })?;
        selectors.remove(&target.identity_selector);
        let parent = CapabilityV1::new(
            &target.read_capability_id,
            "Deleted nested resource parent verification readback",
            "GET",
            &target.parent_path,
        );
        let request = self.builder.build(
            &parent,
            &CallInput {
                selectors: Value::Object(selectors),
                query: Value::Object(serde_json::Map::new()),
                body: None,
                ..CallInput::default()
            },
        )?;
        let readback = self.send(&request, credential).await?;
        let items = readback
            .result
            .pointer(&target.items_pointer)
            .and_then(Value::as_array);
        let matching = items
            .into_iter()
            .flatten()
            .filter(|item| {
                item.pointer(&target.response_item_identity_pointer)
                    .and_then(Value::as_str)
                    == Some(resource_id)
            })
            .count();
        let passed = apply_response.success && readback.success && items.is_some() && matching == 0;
        let basis = if passed {
            "the live parent object omitted the exact nested resource identity after deletion"
                .to_owned()
        } else {
            format!(
                "nested-resource deletion was not proven (apply success={}, readback HTTP {}, readback success={}, child array={}, identity matches={matching})",
                apply_response.success,
                readback.status,
                readback.success,
                items.is_some(),
            )
        };
        Ok(OperationVerificationV1 {
            strategy: plan.capability.verification.strategy.clone(),
            passed,
            basis,
            readback,
            correlated_resource_id: None,
        })
    }

    async fn verify_web_analytics_rule_create(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        let target = plan.capability.created_resource.as_ref().ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "the hash-bound Web Analytics rule creation contract is absent".to_owned(),
            )
        })?;
        let planned = input
            .body
            .as_ref()
            .and_then(Value::as_object)
            .filter(|body| !body.is_empty())
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "planned Web Analytics rule body is absent, empty, or not an object".to_owned(),
                )
            })?;
        let resource_id = apply_response
            .result
            .pointer(&target.response_result_identity_pointer)
            .and_then(Value::as_str)
            .filter(|identity| !identity.is_empty())
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "the successful Web Analytics rule response has no schema-proven identity"
                        .to_owned(),
                )
            })?;
        let list = CapabilityV1::new(
            &target.read_capability_id,
            "Web Analytics rule list verification readback",
            "GET",
            "/accounts/{account_id}/rum/v2/{ruleset_id}/rules",
        );
        let request = self.builder.build(
            &list,
            &CallInput {
                selectors: input.selectors.clone(),
                query: Value::Object(serde_json::Map::new()),
                body: None,
                ..CallInput::default()
            },
        )?;
        let readback = self.send(&request, credential).await?;
        let rules = readback.result.pointer("/rules").and_then(Value::as_array);
        let identity_shape_valid = rules.is_some_and(|rules| {
            rules.iter().all(|rule| {
                rule.get("id")
                    .and_then(Value::as_str)
                    .is_some_and(|identity| !identity.is_empty())
            })
        });
        let matching = rules
            .into_iter()
            .flatten()
            .filter(|rule| rule.get("id").and_then(Value::as_str) == Some(resource_id))
            .collect::<Vec<_>>();
        let fields_match = matching.first().is_some_and(|rule| {
            mismatched_verifiable_planned_fields(&plan.capability, planned, rule).is_empty()
        });
        let passed = apply_response.success
            && readback.success
            && identity_shape_valid
            && matching.len() == 1
            && fields_match;
        let basis = if passed {
            "the live Web Analytics rules list contained exactly one returned creation identity with every planned field"
                .to_owned()
        } else {
            format!(
                "Web Analytics rule creation was not proven (apply success={}, readback HTTP {}, readback success={}, rules array={}, item identities valid={}, identity matches={}, planned fields match={})",
                apply_response.success,
                readback.status,
                readback.success,
                rules.is_some(),
                identity_shape_valid,
                matching.len(),
                fields_match
            )
        };
        Ok(OperationVerificationV1 {
            strategy: plan.capability.verification.strategy.clone(),
            passed,
            basis,
            readback,
            correlated_resource_id: None,
        })
    }

    async fn verify_web_analytics_rule_delete(
        &self,
        plan: &PlanV1,
        apply_response: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        let resource_id = input
            .selectors
            .get("rule_id")
            .and_then(Value::as_str)
            .filter(|identity| !identity.is_empty())
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "planned Web Analytics rule deletion identity is absent or empty".to_owned(),
                )
            })?;
        let mut selectors = input.selectors.as_object().cloned().ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "planned Web Analytics rule deletion selectors are not an object".to_owned(),
            )
        })?;
        selectors.remove("rule_id");
        let list = CapabilityV1::new(
            "web-analytics-list-rules",
            "Web Analytics rule list deletion readback",
            "GET",
            "/accounts/{account_id}/rum/v2/{ruleset_id}/rules",
        );
        let request = self.builder.build(
            &list,
            &CallInput {
                selectors: Value::Object(selectors),
                query: Value::Object(serde_json::Map::new()),
                body: None,
                ..CallInput::default()
            },
        )?;
        let readback = self.send(&request, credential).await?;
        let rules = readback.result.pointer("/rules").and_then(Value::as_array);
        let matching = rules
            .into_iter()
            .flatten()
            .filter(|rule| rule.get("id").and_then(Value::as_str) == Some(resource_id))
            .count();
        let passed = apply_response.success && readback.success && rules.is_some() && matching == 0;
        let basis = if passed {
            "the complete live Web Analytics rules list omitted the exact deleted identity"
                .to_owned()
        } else {
            format!(
                "Web Analytics rule deletion was not proven (apply success={}, readback HTTP {}, readback success={}, rules array={}, identity matches={matching})",
                apply_response.success,
                readback.status,
                readback.success,
                rules.is_some()
            )
        };
        Ok(OperationVerificationV1 {
            strategy: plan.capability.verification.strategy.clone(),
            passed,
            basis,
            readback,
            correlated_resource_id: None,
        })
    }

    async fn send(
        &self,
        request: &PreparedRequest,
        credential: &AuthCredential,
    ) -> Result<CloudflareResponseV1> {
        self.send_with_output(request, credential, None).await
    }

    async fn send_with_output(
        &self,
        request: &PreparedRequest,
        credential: &AuthCredential,
        output_path: Option<&Path>,
    ) -> Result<CloudflareResponseV1> {
        let method = Method::from_bytes(request.method.as_bytes())
            .map_err(|_| CloudflareError::InvalidMethod(request.method.clone()))?;
        let mut attempt = 0;
        loop {
            let mut outgoing = self
                .client
                .request(method.clone(), request.url.clone())
                .headers(request.headers.clone())
                .timeout(Duration::from_secs(request.timeout_seconds));
            outgoing = apply_credential(outgoing, credential)?;
            if let Some(body) = &request.text_body {
                outgoing = outgoing.body(body.clone());
            } else if let Some(body) = &request.body {
                outgoing = outgoing.json(body);
            }
            let response = outgoing.send().await?;
            let status = response.status();
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(1)
                .min(30);
            if (status.as_u16() == 429 || status.is_server_error()) && attempt < self.max_retries {
                attempt += 1;
                sleep(Duration::from_secs(retry_after)).await;
                continue;
            }
            let status_code = status.as_u16();
            let etag = header_text(response.headers(), reqwest::header::ETAG);
            let cf_ray = response
                .headers()
                .get(HeaderName::from_static("cf-ray"))
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let content_type = header_text(response.headers(), reqwest::header::CONTENT_TYPE);
            if status.is_success()
                && let Some(contract) = request.response_contract.as_ref()
            {
                if !contract.success_statuses.is_empty()
                    && !contract
                        .success_statuses
                        .iter()
                        .any(|expected| response_status_matches(expected, status_code))
                {
                    return Err(CloudflareError::UnexpectedSuccessStatus {
                        status: status_code,
                        expected: contract.success_statuses.join(", "),
                    });
                }
                return parse_success_response(
                    response,
                    request,
                    contract,
                    status_code,
                    content_type,
                    etag,
                    cf_ray,
                    output_path,
                )
                .await;
            }
            let (bytes, _) = read_bounded_body(response, request.max_bytes).await?;
            let body = serde_json::from_slice::<Value>(&bytes).unwrap_or_else(|_| {
                serde_json::json!({
                    "success": false,
                    "errors": [{"message":"Cloudflare returned a non-JSON error response"}]
                })
            });
            return Ok(parse_response(status_code, &body, etag, cf_ray));
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "R2 retrieval keeps private header injection, retry bounds, media validation, and file streaming in one secret-safe path"
    )]
    async fn send_r2_log_retrieval_to_file(
        &self,
        request: &PreparedRequest,
        credential: &AuthCredential,
        r2_credentials: &R2LogRetrievalCredentials,
        output_path: &Path,
    ) -> Result<CloudflareResponseV1> {
        let contract = request.r2_log_retrieval.as_ref().ok_or_else(|| {
            CloudflareError::InvalidR2LogRetrieval(
                "prepared request omitted its pinned retrieval contract".to_owned(),
            )
        })?;
        let method = Method::from_bytes(request.method.as_bytes())
            .map_err(|_| CloudflareError::InvalidMethod(request.method.clone()))?;
        let access_header =
            HeaderName::from_bytes(contract.access_key_header.as_bytes()).map_err(|_| {
                CloudflareError::InvalidR2LogRetrieval(
                    "the pinned access-key header name is invalid".to_owned(),
                )
            })?;
        let secret_header = HeaderName::from_bytes(contract.secret_access_key_header.as_bytes())
            .map_err(|_| {
                CloudflareError::InvalidR2LogRetrieval(
                    "the pinned secret-key header name is invalid".to_owned(),
                )
            })?;
        let access_value = HeaderValue::from_str(&r2_credentials.access_key_id).map_err(|_| {
            CloudflareError::InvalidR2LogRetrieval(
                "the R2 access-key value is not a valid HTTP header value".to_owned(),
            )
        })?;
        let secret_value =
            HeaderValue::from_str(&r2_credentials.secret_access_key).map_err(|_| {
                CloudflareError::InvalidR2LogRetrieval(
                    "the R2 secret-key value is not a valid HTTP header value".to_owned(),
                )
            })?;
        let mut attempt = 0;
        loop {
            let outgoing = apply_credential(
                self.client
                    .request(method.clone(), request.url.clone())
                    .headers(request.headers.clone())
                    .header(access_header.clone(), access_value.clone())
                    .header(secret_header.clone(), secret_value.clone())
                    .timeout(Duration::from_secs(request.timeout_seconds)),
                credential,
            )?;
            let response = outgoing.send().await?;
            let status = response.status();
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(1)
                .min(30);
            if (status.as_u16() == 429 || status.is_server_error()) && attempt < self.max_retries {
                attempt += 1;
                sleep(Duration::from_secs(retry_after)).await;
                continue;
            }

            let status_code = status.as_u16();
            let etag = header_text(response.headers(), reqwest::header::ETAG);
            let cf_ray = response
                .headers()
                .get(HeaderName::from_static("cf-ray"))
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let content_type = header_text(response.headers(), reqwest::header::CONTENT_TYPE);
            if !status.is_success() {
                let (bytes, _) =
                    read_bounded_body(response, request.max_bytes.min(1024 * 1024)).await?;
                let body = serde_json::from_slice::<Value>(&bytes).unwrap_or_else(|_| {
                    serde_json::json!({
                        "success": false,
                        "errors": [{"message":"Cloudflare returned a non-JSON retrieval error response"}]
                    })
                });
                return Ok(parse_response(status_code, &body, etag, cf_ray));
            }
            let response_contract = request.response_contract.as_ref().ok_or_else(|| {
                CloudflareError::InvalidR2LogRetrieval(
                    "retrieval response contract is missing".to_owned(),
                )
            })?;
            if !response_contract.success_statuses.is_empty()
                && !response_contract
                    .success_statuses
                    .iter()
                    .any(|expected| response_status_matches(expected, status_code))
            {
                return Err(CloudflareError::UnexpectedSuccessStatus {
                    status: status_code,
                    expected: response_contract.success_statuses.join(", "),
                });
            }
            require_declared_media_type(status_code, content_type.as_deref(), response_contract)?;
            if !contract.output_media_types.iter().any(|expected| {
                content_type
                    .as_deref()
                    .and_then(normalized_media_type)
                    .zip(normalized_media_type(expected))
                    .is_some_and(|(received, expected)| received.eq_ignore_ascii_case(expected))
            }) {
                return Err(CloudflareError::UnexpectedResponseMediaType {
                    status: status_code,
                    received: content_type.unwrap_or_else(|| "missing".to_owned()),
                });
            }
            return stream_r2_log_response(
                response,
                request,
                status_code,
                etag,
                cf_ray,
                output_path,
            )
            .await;
        }
    }

    async fn send_paginated(
        &self,
        request: &PreparedRequest,
        credential: &AuthCredential,
    ) -> Result<CloudflareResponseV1> {
        self.send_paginated_with_output(request, credential, None)
            .await
    }

    async fn send_paginated_with_output(
        &self,
        request: &PreparedRequest,
        credential: &AuthCredential,
        output_path: Option<&Path>,
    ) -> Result<CloudflareResponseV1> {
        let mut combined = self
            .send_with_output(request, credential, output_path)
            .await?;
        if output_path.is_some() {
            return Ok(combined);
        }
        if !combined.success || !request.method.eq_ignore_ascii_case("GET") {
            return Ok(combined);
        }
        if let Some((current_page, total_pages)) = pagination_bounds(combined.result_info.as_ref())
        {
            if total_pages > 1_000 {
                return Err(CloudflareError::PaginationLimit(total_pages));
            }
            let Some(results) = combined.result.as_array_mut() else {
                return Ok(combined);
            };
            for page in (current_page + 1)..=total_pages {
                let mut page_request = request.clone();
                set_query_parameter(&mut page_request.url, "page", &page.to_string());
                let response = self.send(&page_request, credential).await?;
                if !response.success {
                    return Ok(response);
                }
                if let Some(page_results) = response.result.as_array() {
                    results.extend(page_results.iter().cloned());
                }
                combined.etag = response.etag;
                combined.cf_ray = response.cf_ray;
            }
            if let Some(result_info) = combined.result_info.as_mut().and_then(Value::as_object_mut)
            {
                result_info.insert("page".to_owned(), Value::from(total_pages));
                result_info.insert("count".to_owned(), Value::from(results.len()));
            }
            return Ok(combined);
        }

        let mut next_cursor = match cursor_after(combined.result_info.as_ref()) {
            CursorState::NotPresent => return Ok(combined),
            CursorState::Complete => None,
            CursorState::Next(cursor) => Some(cursor),
        };
        let Some(results) = combined.result.as_array_mut() else {
            return Ok(combined);
        };
        let mut observed = BTreeSet::new();
        let mut pages = 1_u64;
        while let Some(cursor) = next_cursor {
            if pages >= 1_000 {
                return Err(CloudflareError::PaginationLimit(pages + 1));
            }
            if !observed.insert(cursor.clone()) {
                return Err(CloudflareError::PaginationCursorLoop);
            }
            let mut page_request = request.clone();
            set_query_parameter(&mut page_request.url, "cursor", &cursor);
            let response = self.send(&page_request, credential).await?;
            if !response.success {
                return Ok(response);
            }
            let Some(page_results) = response.result.as_array() else {
                return Err(CloudflareError::InvalidResponseEnvelope {
                    status: response.status,
                });
            };
            results.extend(page_results.iter().cloned());
            pages += 1;
            next_cursor = match cursor_after(response.result_info.as_ref()) {
                CursorState::NotPresent => {
                    return Err(CloudflareError::PaginationCursorMetadataMissing);
                }
                CursorState::Complete => None,
                CursorState::Next(cursor) => Some(cursor),
            };
            combined.etag = response.etag;
            combined.cf_ray = response.cf_ray;
            combined.result_info = response.result_info;
        }
        if let Some(result_info) = combined.result_info.as_mut().and_then(Value::as_object_mut) {
            result_info.insert("count".to_owned(), Value::from(results.len()));
            result_info.insert("cfctl_cursor_complete".to_owned(), Value::Bool(true));
            result_info.insert("cfctl_pages".to_owned(), Value::from(pages));
        }
        Ok(combined)
    }
}

fn required_d1_bookmark<'a>(response: &'a CloudflareResponseV1, phase: &str) -> Result<&'a str> {
    if !response.success {
        return Err(CloudflareError::MissingVerificationTarget(format!(
            "D1 {phase} bookmark read was unsuccessful"
        )));
    }
    response
        .result
        .get("bookmark")
        .and_then(Value::as_str)
        .filter(|bookmark| !bookmark.is_empty())
        .ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(format!(
                "D1 {phase} response omitted required bookmark"
            ))
        })
}

#[expect(
    clippy::too_many_arguments,
    reason = "response parsing receives the immutable request contract plus exact upstream metadata without hidden shared state"
)]
async fn parse_success_response(
    response: reqwest::Response,
    request: &PreparedRequest,
    contract: &ResponseContractV1,
    status: u16,
    content_type: Option<String>,
    etag: Option<String>,
    cf_ray: Option<String>,
    output_path: Option<&Path>,
) -> Result<CloudflareResponseV1> {
    if contract.body_mode != ResponseBodyModeV1::Empty {
        require_declared_media_type(status, content_type.as_deref(), contract)?;
    }
    match contract.body_mode {
        ResponseBodyModeV1::CloudflareJsonEnvelope => {
            require_json_media(status, content_type.as_deref())?;
            let (bytes, truncated) = read_bounded_body(response, request.max_bytes).await?;
            if truncated {
                if request.analytics_query.is_some()
                    || request.d1_schema_introspection.is_some()
                    || request.mln_0143_data_invariants.is_some()
                {
                    return Ok(partial_output_response(
                        status,
                        Value::Null,
                        request,
                        0,
                        bytes.len() as u64,
                        true,
                        true,
                        "analytics JSON envelope exceeded its byte limit",
                        etag,
                        cf_ray,
                    ));
                }
                return Err(CloudflareError::InvalidResponseEnvelope { status });
            }
            let body = parse_json_bytes(&bytes, status)?;
            if body.get("success").and_then(Value::as_bool).is_none() {
                return Err(CloudflareError::InvalidResponseEnvelope { status });
            }
            let parsed = parse_response(status, &body, etag, cf_ray);
            if request.analytics_query.is_some()
                || request.d1_schema_introspection.is_some()
                || request.mln_0143_data_invariants.is_some()
            {
                bound_enveloped_query_response(parsed, request, bytes.len() as u64, output_path)
                    .await
            } else {
                Ok(parsed)
            }
        }
        ResponseBodyModeV1::CloudflareDataEnvelope => {
            require_json_media(status, content_type.as_deref())?;
            let (bytes, truncated) = read_bounded_body(response, request.max_bytes).await?;
            if truncated {
                return Err(CloudflareError::InvalidResponseEnvelope { status });
            }
            let body = parse_json_bytes(&bytes, status)?;
            if body.get("success").and_then(Value::as_bool).is_none()
                || body.get("data").is_none_or(Value::is_null)
            {
                return Err(CloudflareError::InvalidResponseEnvelope { status });
            }
            Ok(parse_data_response(status, &body, etag, cf_ray))
        }
        ResponseBodyModeV1::JsonValue => {
            require_json_media(status, content_type.as_deref())?;
            parse_bare_json_response(response, request, status, etag, cf_ray, output_path).await
        }
        ResponseBodyModeV1::GraphqlJson => {
            require_json_media(status, content_type.as_deref())?;
            parse_graphql_response(response, request, status, etag, cf_ray, output_path).await
        }
        ResponseBodyModeV1::NegotiatedRows => {
            let media = content_type
                .as_deref()
                .and_then(normalized_media_type)
                .unwrap_or("missing");
            if is_application_json(media) {
                parse_bare_json_response(response, request, status, etag, cf_ray, output_path).await
            } else if is_ndjson_media(media) {
                parse_ndjson_response(response, request, status, etag, cf_ray, output_path).await
            } else if media.eq_ignore_ascii_case("text/csv") {
                parse_csv_response(response, request, status, etag, cf_ray, output_path).await
            } else {
                Err(CloudflareError::UnexpectedResponseMediaType {
                    status,
                    received: content_type.unwrap_or_else(|| "missing".to_owned()),
                })
            }
        }
        ResponseBodyModeV1::Empty => {
            let (body, _) = read_bounded_body(response, request.max_bytes).await?;
            if !body.is_empty() {
                return Err(CloudflareError::UnexpectedResponseBody {
                    status,
                    received_bytes: body.len(),
                });
            }
            Ok(parse_response(status, &Value::Null, etag, cf_ray))
        }
        ResponseBodyModeV1::Unsupported => Err(CloudflareError::UnsupportedResponseContract(
            contract.success_media_types.join(", "),
        )),
    }
}

async fn bound_enveloped_query_response(
    mut response: CloudflareResponseV1,
    request: &PreparedRequest,
    bytes: u64,
    output_path: Option<&Path>,
) -> Result<CloudflareResponseV1> {
    if request.mln_0143_data_invariants.is_some() {
        if bytes >= request.max_bytes {
            return Err(CloudflareError::InvalidAnalyticsQuery(
                "invariant_not_feasible_under_safe_bounds".to_owned(),
            ));
        }
        sanitize_mln_0143_data_invariants_response(&mut response, request)?;
    }
    if request.d1_schema_introspection.is_some() {
        validate_d1_schema_assertion_response(&response)?;
    }
    let mut truncated = false;
    let max_rows = bounded_usize(request.max_rows);
    let rows = if let Some(rows) = response.result.as_array_mut() {
        if rows.len() > max_rows {
            rows.truncate(max_rows);
            truncated = true;
        }
        rows.len() as u64
    } else {
        u64::from(!response.result.is_null())
    };
    if let Some(path) = output_path {
        let canonical =
            serde_json::to_vec(&response.result).map_err(cfctl_core::CoreError::Serialization)?;
        response.result =
            file_receipt(path, &canonical, rows, response.success && !truncated).await?;
    }
    response.result_info = Some(output_result_info(
        request,
        rows,
        bytes,
        truncated,
        !response.success,
    ));
    Ok(response)
}

fn validate_d1_schema_assertion_response(response: &CloudflareResponseV1) -> Result<()> {
    let Some(result) = response
        .result
        .as_array()
        .filter(|results| results.len() == 1)
        .and_then(|results| results.first())
    else {
        return Err(CloudflareError::InvalidResponseEnvelope {
            status: response.status,
        });
    };
    let present = result
        .pointer("/results")
        .and_then(Value::as_array)
        .filter(|rows| rows.len() == 1)
        .and_then(|rows| rows.first())
        .and_then(|row| row.get("present"));
    let valid_present = present.is_some_and(|present| {
        present.is_boolean() || present.as_u64().is_some_and(|value| matches!(value, 0 | 1))
    });
    let no_writes = result.pointer("/meta/rows_written").and_then(Value::as_u64) == Some(0);
    if result.get("success").and_then(Value::as_bool) != Some(true) || !valid_present || !no_writes
    {
        return Err(CloudflareError::InvalidResponseEnvelope {
            status: response.status,
        });
    }
    Ok(())
}

fn normalized_sql_hash(value: &str) -> String {
    let normalized = value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    format!(
        "sha256:{}",
        hex::encode(Sha256::digest(normalized.as_bytes()))
    )
}

fn reviewed_table_sql_hash(value: &str) -> Option<String> {
    #[derive(Clone, Copy)]
    enum State {
        Normal,
        SingleQuote,
        DoubleQuote,
        LineComment,
        BlockComment,
    }

    let mut state = State::Normal;
    let mut chars = value.chars().peekable();
    let mut normalized = String::new();
    let mut pending_space = false;
    while let Some(character) = chars.next() {
        match state {
            State::Normal => match character {
                '-' if chars.peek() == Some(&'-') => {
                    chars.next();
                    state = State::LineComment;
                    pending_space = true;
                }
                '/' if chars.peek() == Some(&'*') => {
                    chars.next();
                    state = State::BlockComment;
                    pending_space = true;
                }
                '\'' => {
                    if pending_space && !normalized.is_empty() {
                        normalized.push(' ');
                    }
                    pending_space = false;
                    normalized.push(character);
                    state = State::SingleQuote;
                }
                '"' => {
                    if pending_space && !normalized.is_empty() {
                        normalized.push(' ');
                    }
                    pending_space = false;
                    normalized.push(character);
                    state = State::DoubleQuote;
                }
                character if character.is_whitespace() => pending_space = true,
                character => {
                    if pending_space && !normalized.is_empty() {
                        normalized.push(' ');
                    }
                    pending_space = false;
                    normalized.extend(character.to_lowercase());
                }
            },
            State::SingleQuote => {
                normalized.push(character);
                if character == '\'' {
                    if chars.peek() == Some(&'\'') {
                        if let Some(escaped) = chars.next() {
                            normalized.push(escaped);
                        }
                    } else {
                        state = State::Normal;
                    }
                }
            }
            State::DoubleQuote => {
                normalized.push(character);
                if character == '"' {
                    if chars.peek() == Some(&'"') {
                        if let Some(escaped) = chars.next() {
                            normalized.push(escaped);
                        }
                    } else {
                        state = State::Normal;
                    }
                }
            }
            State::LineComment => {
                if matches!(character, '\n' | '\r') {
                    state = State::Normal;
                }
            }
            State::BlockComment => {
                if character == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    state = State::Normal;
                }
            }
        }
    }
    if !matches!(state, State::Normal | State::LineComment) {
        return None;
    }
    Some(format!(
        "sha256:{}",
        hex::encode(Sha256::digest(normalized.as_bytes()))
    ))
}

fn invariant_response_error(status: u16) -> CloudflareError {
    CloudflareError::InvalidResponseEnvelope { status }
}

#[expect(
    clippy::too_many_lines,
    reason = "the privacy boundary and every phase-specific invariant remain together and auditable"
)]
fn sanitize_mln_0143_data_invariants_response(
    response: &mut CloudflareResponseV1,
    request: &PreparedRequest,
) -> Result<()> {
    if !response.success || !response.errors.is_empty() {
        response.result = Value::Null;
        response.errors.clear();
        response.result_info = None;
        return Err(invariant_response_error(response.status));
    }
    let contract = request
        .mln_0143_data_invariants
        .as_ref()
        .ok_or_else(|| invariant_response_error(response.status))?;
    let phase = request
        .query_receipt
        .as_ref()
        .and_then(|receipt| receipt.get("phase"))
        .and_then(Value::as_str)
        .ok_or_else(|| invariant_response_error(response.status))?;
    let statement = response
        .result
        .as_array()
        .filter(|results| results.len() == 1)
        .and_then(|results| results.first())
        .ok_or_else(|| invariant_response_error(response.status))?;
    let row = statement
        .get("results")
        .and_then(Value::as_array)
        .filter(|rows| rows.len() == 1)
        .and_then(|rows| rows.first())
        .and_then(Value::as_object)
        .ok_or_else(|| invariant_response_error(response.status))?;
    let meta = statement
        .get("meta")
        .and_then(Value::as_object)
        .ok_or_else(|| invariant_response_error(response.status))?;
    let timeout_seconds = u32::try_from(contract.max_timeout_seconds).map_or(f64::MAX, f64::from);
    let duration = meta
        .get("duration")
        .and_then(Value::as_f64)
        .filter(|duration| duration.is_finite() && *duration >= 0.0 && *duration < timeout_seconds);
    if statement.get("success").and_then(Value::as_bool) != Some(true)
        || meta.get("rows_written").and_then(Value::as_u64) != Some(0)
        || meta.get("rows_read").and_then(Value::as_u64).is_none()
        || duration.is_none()
    {
        return Err(invariant_response_error(response.status));
    }
    let number = |name: &str| {
        row.get(name)
            .and_then(Value::as_u64)
            .ok_or_else(|| invariant_response_error(response.status))
    };
    let text = |name: &str| {
        row.get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| invariant_response_error(response.status))
    };
    let evidence_rows: Value = serde_json::from_str(text("evidence_rows")?)
        .map_err(|_| invariant_response_error(response.status))?;
    let evidence_rows = evidence_rows
        .as_array()
        .ok_or_else(|| invariant_response_error(response.status))?;
    let total = number("evidence_total")?;
    let window_total = number("evidence_window_total")?;
    let received = number("evidence_received")?;
    if total > contract.max_evidence_rows
        || window_total != total
        || received != total
        || received != evidence_rows.len() as u64
        || received >= contract.probe_rows
    {
        return Err(CloudflareError::InvalidAnalyticsQuery(
            "invariant_not_feasible_under_safe_bounds".to_owned(),
        ));
    }
    let expected_fields = [
        "id",
        "org_id",
        "issuance_event_id",
        "evidence_kind",
        "document_id",
        "company_event_id",
        "document_hash",
        "required",
        "created_by",
        "created_at",
    ];
    if evidence_rows.iter().any(|row| {
        row.as_object().is_none_or(|row| {
            row.len() != expected_fields.len()
                || expected_fields
                    .iter()
                    .any(|field| !row.contains_key(*field))
        })
    }) {
        return Err(invariant_response_error(response.status));
    }
    let table_sql = text("table_sql")?;
    let pre = matches!(phase, "pre_import" | "post_restore");
    let expected_table_sql = if pre {
        MLN_0143_PRE_TABLE_SQL
    } else {
        MLN_0143_POST_TABLE_SQL
    };
    let expected_table_hash = if pre {
        &contract.pre_table_definition_hash
    } else {
        &contract.post_table_definition_hash
    };
    if reviewed_table_sql_hash(table_sql).as_ref() != Some(expected_table_hash)
        || reviewed_table_sql_hash(expected_table_sql).as_ref() != Some(expected_table_hash)
    {
        return Err(invariant_response_error(response.status));
    }
    let columns: Value = serde_json::from_str(text("column_names")?)
        .map_err(|_| invariant_response_error(response.status))?;
    let expected_columns = serde_json::json!([
        "id",
        "org_id",
        "issuance_event_id",
        "evidence_kind",
        "document_id",
        "company_event_id",
        "document_hash",
        "required",
        "created_by",
        "created_at"
    ]);
    if columns != expected_columns
        || number("old_table_count")? != 0
        || number("foreign_key_violations")? != 0
        || number("duplicate_hash_groups")? != 0
        || number("invalid_evidence_kinds")? != 0
    {
        return Err(invariant_response_error(response.status));
    }
    for (sql_field, unique_field, columns_field, index_name, expected_columns) in [
        (
            "event_index_sql",
            "event_index_unique",
            "event_index_columns",
            "idx_equity_issuance_evidence_event",
            serde_json::json!(["org_id", "issuance_event_id", "evidence_kind"]),
        ),
        (
            "document_index_sql",
            "document_index_unique",
            "document_index_columns",
            "idx_equity_issuance_evidence_document",
            serde_json::json!(["org_id", "document_id"]),
        ),
    ] {
        let sql = text(sql_field)?
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_lowercase();
        let columns: Value = serde_json::from_str(text(columns_field)?)
            .map_err(|_| invariant_response_error(response.status))?;
        if number(unique_field)? != 0
            || columns != expected_columns
            || !sql.starts_with(&format!("create index {index_name} on "))
            || sql.contains("create unique index")
        {
            return Err(invariant_response_error(response.status));
        }
    }
    let index_normalized = text("unique_hash_index_sql")?
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    let index_columns: Value = serde_json::from_str(text("unique_hash_index_columns")?)
        .map_err(|_| invariant_response_error(response.status))?;
    let expected_index_prefix = "create unique index idx_equity_issuance_evidence_unique_hash on equity_issuance_evidence_links";
    let Some((definition, predicate)) = index_normalized.rsplit_once(" where ") else {
        return Err(invariant_response_error(response.status));
    };
    if text("unique_hash_index_table")? != "equity_issuance_evidence_links"
        || number("unique_hash_index_unique")? != 1
        || number("unique_hash_index_partial")? != 1
        || index_columns
            != serde_json::json!([
                "org_id",
                "issuance_event_id",
                "evidence_kind",
                "document_hash"
            ])
        || !definition.starts_with(expected_index_prefix)
        || predicate != "document_hash is not null"
    {
        return Err(invariant_response_error(response.status));
    }
    let packet_rows: Value = serde_json::from_str(text("packet_rows")?)
        .map_err(|_| invariant_response_error(response.status))?;
    let packet_rows = packet_rows
        .as_array()
        .ok_or_else(|| invariant_response_error(response.status))?;
    let packet_total = number("packet_total")?;
    let packet_window_total = number("packet_window_total")?;
    let packet_received = number("packet_received")?;
    if packet_total > 512
        || packet_window_total != packet_total
        || packet_received != packet_total
        || packet_received != packet_rows.len() as u64
        || packet_received >= 513
        || packet_rows.iter().any(|row| {
            row.as_object().is_none_or(|row| {
                row.len() != 4
                    || ![
                        "profile",
                        "evidence_kind",
                        "signature_required",
                        "sort_order",
                    ]
                    .iter()
                    .all(|field| row.contains_key(*field))
            })
        })
    {
        return Err(invariant_response_error(response.status));
    }
    let advisor_rows = packet_rows
        .iter()
        .filter(|row| row.get("profile").and_then(Value::as_str) == Some("advisor_grant"))
        .cloned()
        .collect::<Vec<_>>();
    let expected_packet = if pre {
        serde_json::json!([
            {"profile":"advisor_grant","evidence_kind":"advisor_agreement","signature_required":1,"sort_order":1},
            {"profile":"advisor_grant","evidence_kind":"board_consent","signature_required":1,"sort_order":0},
            {"profile":"advisor_grant","evidence_kind":"election_83b","signature_required":0,"sort_order":2}
        ])
    } else {
        serde_json::json!([
            {"profile":"advisor_grant","evidence_kind":"advisor_agreement","signature_required":1,"sort_order":1},
            {"profile":"advisor_grant","evidence_kind":"advisor_equity_instrument","signature_required":1,"sort_order":2},
            {"profile":"advisor_grant","evidence_kind":"board_consent","signature_required":1,"sort_order":0}
        ])
    };
    if Value::Array(advisor_rows) != expected_packet {
        return Err(invariant_response_error(response.status));
    }
    let non_target_packet_rows = packet_rows
        .iter()
        .filter(|row| {
            let profile = row.get("profile").and_then(Value::as_str);
            let kind = row.get("evidence_kind").and_then(Value::as_str);
            profile != Some("advisor_grant")
                || !matches!(kind, Some("election_83b" | "advisor_equity_instrument"))
        })
        .cloned()
        .collect::<Vec<_>>();
    let trigger_fields = [
        "trigger_contract_sql",
        "trigger_immutable_sql",
        "trigger_final_required_sql",
    ];
    if number("invalid_advanced_events")? != 0 {
        return Err(invariant_response_error(response.status));
    }
    let trigger_hashes = if pre {
        if trigger_fields
            .iter()
            .any(|field| !row.get(*field).is_none_or(Value::is_null))
        {
            return Err(invariant_response_error(response.status));
        }
        Vec::new()
    } else {
        let hashes = trigger_fields
            .iter()
            .map(|field| text(field).map(normalized_sql_hash))
            .collect::<Result<Vec<_>>>()?;
        if hashes != contract.trigger_definition_hashes {
            return Err(invariant_response_error(response.status));
        }
        hashes
    };
    let kind_counts: Value = serde_json::from_str(text("evidence_kind_counts")?)
        .map_err(|_| invariant_response_error(response.status))?;
    let manifest = serde_json::json!({
        "schema_version":1,
        "capability_id":"mln-0143-data-invariants",
        "capability_version":contract.capability_version,
        "validator_contract_hash":contract.validator_contract_hash,
        "migration_id":"0143",
        "migration_sha256":contract.migration_sha256,
        "phase":phase,
        "target_scope_hash":hash_value(&serde_json::json!({
            "account_id":contract.account_id,
            "database_id":contract.database_id,
        }))?,
        "complete":true,
        "projection":{
            "digest":hash_value(&Value::Array(evidence_rows.clone()))?,
            "count":total,
            "counts_by_kind":kind_counts,
        },
        "semantic_schema_hash":reviewed_table_sql_hash(table_sql).ok_or_else(|| invariant_response_error(response.status))?,
        "packet_hash":hash_value(&Value::Array(packet_rows.clone()))?,
        "packet_count":packet_total,
        "packet_non_target_hash":hash_value(&Value::Array(non_target_packet_rows.clone()))?,
        "packet_non_target_count":non_target_packet_rows.len(),
        "trigger_definition_hashes":trigger_hashes,
        "assertions":{
            "old_table_absent":true,
            "unique_hash_index_present":true,
            "event_index_exact_non_unique_shape":true,
            "document_index_exact_non_unique_shape":true,
            "foreign_key_check_empty":true,
            "duplicate_hash_groups_zero":true,
            "invalid_evidence_kinds_zero":true,
            "invalid_advanced_events_zero":true,
        },
        "query":{
            "sha256":contract.fixed_query_sha256,
            "row_limit":contract.max_evidence_rows,
            "probe_rows":contract.probe_rows,
            "byte_limit":contract.max_bytes,
            "timeout_seconds":contract.max_timeout_seconds,
            "received_rows":received,
            "provider_rows_read":meta.get("rows_read"),
            "provider_duration":duration,
            "bounds_saturated":false,
        },
        "lineage":{
            "pre_import_evidence_hash":request.query_receipt.as_ref().and_then(|v| v.get("pre_import_evidence_hash")),
            "post_import_evidence_hash":request.query_receipt.as_ref().and_then(|v| v.get("post_import_evidence_hash")),
            "import_operation_id":request.query_receipt.as_ref().and_then(|v| v.get("import_operation_id")),
            "import_boundary_evidence_hash":request.query_receipt.as_ref().and_then(|v| v.get("import_boundary_evidence_hash")),
            "import_source_sha256":request.query_receipt.as_ref().and_then(|v| v.get("import_source_sha256")),
            "import_plan_hash":request.query_receipt.as_ref().and_then(|v| v.get("import_plan_hash")),
            "restore_operation_id":request.query_receipt.as_ref().and_then(|v| v.get("restore_operation_id")),
            "restore_evidence_hash":request.query_receipt.as_ref().and_then(|v| v.get("restore_evidence_hash")),
            "restore_previous_bookmark_hash":request.query_receipt.as_ref().and_then(|v| v.get("restore_previous_bookmark_hash")),
            "restore_requested_bookmark_hash":request.query_receipt.as_ref().and_then(|v| v.get("restore_requested_bookmark_hash")),
            "restore_observed_bookmark_hash":request.query_receipt.as_ref().and_then(|v| v.get("restore_observed_bookmark_hash")),
        },
        "privacy":"raw rows, row fingerprints, MLN identifiers, and document hashes were discarded before evidence persistence",
    });
    response.result = manifest;
    response.errors.clear();
    Ok(())
}

fn require_declared_media_type(
    status: u16,
    content_type: Option<&str>,
    contract: &ResponseContractV1,
) -> Result<()> {
    let received = content_type
        .and_then(normalized_media_type)
        .unwrap_or("missing");
    if contract.success_media_types.iter().any(|declared| {
        normalized_media_type(declared)
            .is_some_and(|declared| declared.eq_ignore_ascii_case(received))
    }) {
        return Ok(());
    }
    Err(CloudflareError::UnexpectedResponseMediaType {
        status,
        received: content_type.unwrap_or("missing").to_owned(),
    })
}

fn require_json_media(status: u16, content_type: Option<&str>) -> Result<()> {
    if content_type.is_some_and(is_application_json) {
        return Ok(());
    }
    Err(CloudflareError::UnexpectedResponseMediaType {
        status,
        received: content_type.unwrap_or("missing").to_owned(),
    })
}

fn normalized_media_type(content_type: &str) -> Option<&str> {
    content_type.split(';').next().map(str::trim)
}

fn is_ndjson_media(content_type: &str) -> bool {
    matches!(
        normalized_media_type(content_type),
        Some(media)
            if media.eq_ignore_ascii_case("application/x-ndjson")
                || media.eq_ignore_ascii_case("application/ndjson")
    )
}

async fn read_bounded_body(response: reqwest::Response, max_bytes: u64) -> Result<(Vec<u8>, bool)> {
    let limit = usize::try_from(max_bytes).unwrap_or(usize::MAX);
    let mut stream = response.bytes_stream();
    let mut body = Vec::with_capacity(limit.min(64 * 1024));
    let mut truncated = false;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        let remaining = limit.saturating_sub(body.len());
        if chunk.len() > remaining {
            body.extend_from_slice(&chunk[..remaining]);
            truncated = true;
            break;
        }
        body.extend_from_slice(&chunk);
    }
    Ok((body, truncated))
}

fn parse_json_bytes(bytes: &[u8], status: u16) -> Result<Value> {
    serde_json::from_slice(bytes).map_err(|_| CloudflareError::InvalidResponseEnvelope { status })
}

fn bounded_usize(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

async fn parse_bare_json_response(
    response: reqwest::Response,
    request: &PreparedRequest,
    status: u16,
    etag: Option<String>,
    cf_ray: Option<String>,
    output_path: Option<&Path>,
) -> Result<CloudflareResponseV1> {
    let (bytes, byte_truncated) = read_bounded_body(response, request.max_bytes).await?;
    if byte_truncated {
        return Ok(partial_output_response(
            status,
            Value::Null,
            request,
            0,
            bytes.len() as u64,
            true,
            true,
            "analytics JSON exceeded its byte limit",
            etag,
            cf_ray,
        ));
    }
    let mut value = parse_json_bytes(&bytes, status)?;
    let mut truncated = false;
    let max_rows = bounded_usize(request.max_rows);
    let rows = if let Some(rows) = value.as_array_mut() {
        if rows.len() > max_rows {
            rows.truncate(max_rows);
            truncated = true;
        }
        rows.len() as u64
    } else {
        u64::from(!value.is_null())
    };
    let result = if let Some(path) = output_path {
        let canonical = serde_json::to_vec(&value).map_err(cfctl_core::CoreError::Serialization)?;
        file_receipt(path, &canonical, rows, !truncated).await?
    } else {
        value
    };
    Ok(CloudflareResponseV1 {
        status,
        success: true,
        result,
        errors: Vec::new(),
        result_info: Some(output_result_info(
            request,
            rows,
            bytes.len() as u64,
            truncated,
            false,
        )),
        etag,
        cf_ray,
    })
}

#[expect(
    clippy::too_many_lines,
    reason = "GraphQL parsing validates fingerprint, errors, data shape, rows, continuation, and output receipt as one drift boundary"
)]
async fn parse_graphql_response(
    response: reqwest::Response,
    request: &PreparedRequest,
    status: u16,
    etag: Option<String>,
    cf_ray: Option<String>,
    output_path: Option<&Path>,
) -> Result<CloudflareResponseV1> {
    let (bytes, truncated) = read_bounded_body(response, request.max_bytes).await?;
    if truncated {
        return Ok(partial_output_response(
            status,
            Value::Null,
            request,
            0,
            bytes.len() as u64,
            true,
            true,
            "GraphQL Analytics response exceeded its byte limit",
            etag,
            cf_ray,
        ));
    }
    let body = parse_json_bytes(&bytes, status)?;
    let graphql = request.graphql.as_ref().ok_or_else(|| {
        CloudflareError::InvalidAnalyticsQuery(
            "GraphQL response has no pinned schema contract".to_owned(),
        )
    })?;
    graphql.validate_schema_fingerprint()?;
    let upstream_errors = body
        .get("errors")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|error| CloudflareApiErrorV1 {
            code: None,
            message: error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("Cloudflare GraphQL returned an unspecified error")
                .to_owned(),
        })
        .collect::<Vec<_>>();
    if !upstream_errors.is_empty() {
        return Ok(CloudflareResponseV1 {
            status,
            success: false,
            result: Value::Null,
            errors: upstream_errors,
            result_info: Some(output_result_info(
                request,
                0,
                bytes.len() as u64,
                false,
                false,
            )),
            etag,
            cf_ray,
        });
    }
    let mut result = body
        .get("data")
        .and_then(|data| data.pointer(&graphql.response_data_pointer))
        .cloned()
        .ok_or_else(|| CloudflareError::GraphqlSchemaDrift {
            pointer: format!("/data{}", graphql.response_data_pointer),
        })?;
    let rows = graphql_rows(&result);
    for row in &rows {
        for field in &graphql.expected_row_fields {
            if row.get(field).is_none() {
                return Err(CloudflareError::GraphqlSchemaDrift {
                    pointer: format!("/data{}/0/{field}", graphql.response_data_pointer),
                });
            }
        }
    }
    let continuation = graphql_continuation(request, graphql, &rows)?;
    let mut row_count = rows.len() as u64;
    let mut row_truncated = false;
    let max_rows = bounded_usize(request.max_rows);
    if let Some(values) = result.as_array_mut()
        && values.len() > max_rows
    {
        values.truncate(max_rows);
        row_count = values.len() as u64;
        row_truncated = true;
    }
    let result = if let Some(path) = output_path {
        let canonical =
            serde_json::to_vec(&result).map_err(cfctl_core::CoreError::Serialization)?;
        file_receipt(path, &canonical, row_count, !row_truncated).await?
    } else {
        result
    };
    let mut result_info =
        output_result_info(request, row_count, bytes.len() as u64, row_truncated, false);
    if let Some(continuation) = continuation
        && let Some(info) = result_info.as_object_mut()
    {
        info.insert("continuation".to_owned(), continuation);
    }
    Ok(CloudflareResponseV1 {
        status,
        success: true,
        result,
        errors: Vec::new(),
        result_info: Some(result_info),
        etag,
        cf_ray,
    })
}

fn graphql_continuation(
    request: &PreparedRequest,
    graphql: &GraphqlAnalyticsContractV1,
    rows: &[&Value],
) -> Result<Option<Value>> {
    if request
        .analytics_query
        .as_ref()
        .is_none_or(|query| query.pagination != PaginationModeV1::OrderedKeyset)
    {
        return Ok(None);
    }
    let Some(last) = rows.last() else {
        return Ok(None);
    };
    let bindings = graphql_cursor_bindings(graphql)?;
    let mut cursor = serde_json::Map::new();
    let mut next_body_patch = serde_json::Map::new();
    for (field, pointer) in bindings {
        let value =
            last.get(field)
                .cloned()
                .ok_or_else(|| CloudflareError::GraphqlSchemaDrift {
                    pointer: format!("/cursor/{field}"),
                })?;
        if value.is_null() {
            return Err(CloudflareError::GraphqlSchemaDrift {
                pointer: format!("/cursor/{field}"),
            });
        }
        let input_field = top_level_cursor_input_field(pointer)?;
        cursor.insert(field.to_owned(), value.clone());
        next_body_patch.insert(input_field.to_owned(), value);
    }
    Ok(Some(serde_json::json!({
        "mode": "ordered_keyset",
        "cursor": cursor,
        "next_body_patch": next_body_patch,
        "more_possible": rows.len() >= bounded_usize(request.max_rows),
    })))
}

fn graphql_rows(value: &Value) -> Vec<&Value> {
    value
        .as_array()
        .map_or_else(|| vec![value], |rows| rows.iter().collect())
}

async fn parse_ndjson_response(
    response: reqwest::Response,
    request: &PreparedRequest,
    status: u16,
    etag: Option<String>,
    cf_ray: Option<String>,
    output_path: Option<&Path>,
) -> Result<CloudflareResponseV1> {
    let mut stream = response.bytes_stream();
    let mut pending = Vec::new();
    let mut rows = Vec::new();
    let mut raw_bytes = 0_u64;
    let mut truncated = false;
    let mut partial = false;
    let max_rows = bounded_usize(request.max_rows);
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        let remaining = bounded_usize(request.max_bytes.saturating_sub(raw_bytes));
        if remaining == 0 {
            truncated = true;
            break;
        }
        let accepted = chunk.len().min(remaining);
        pending.extend_from_slice(&chunk[..accepted]);
        raw_bytes += accepted as u64;
        if accepted < chunk.len() {
            truncated = true;
        }
        while let Some(newline) = pending.iter().position(|byte| *byte == b'\n') {
            let mut line = pending.drain(..=newline).collect::<Vec<_>>();
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            if line.is_empty() {
                continue;
            }
            if let Ok(row) = serde_json::from_slice::<Value>(&line) {
                rows.push(row);
            } else {
                partial = true;
                break;
            }
            if rows.len() >= max_rows {
                truncated = true;
                break;
            }
        }
        if partial || truncated {
            break;
        }
    }
    if !partial && !truncated && !pending.is_empty() {
        if pending.last() == Some(&b'\r') {
            pending.pop();
        }
        if !pending.is_empty() {
            match serde_json::from_slice::<Value>(&pending) {
                Ok(row) => rows.push(row),
                Err(_) => partial = true,
            }
        }
    }
    if rows.len() > max_rows {
        rows.truncate(max_rows);
        truncated = true;
    }
    let row_count = rows.len() as u64;
    let result = if let Some(path) = output_path {
        let mut canonical = Vec::new();
        for row in &rows {
            serde_json::to_writer(&mut canonical, row)
                .map_err(cfctl_core::CoreError::Serialization)?;
            canonical.push(b'\n');
        }
        file_receipt(path, &canonical, row_count, !partial && !truncated).await?
    } else {
        Value::Array(rows)
    };
    let mut errors = Vec::new();
    if partial {
        errors.push(CloudflareApiErrorV1 {
            code: None,
            message: "analytics stream ended after an invalid NDJSON record".to_owned(),
        });
    }
    Ok(CloudflareResponseV1 {
        status,
        success: !partial,
        result,
        errors,
        result_info: Some(output_result_info(
            request, row_count, raw_bytes, truncated, partial,
        )),
        etag,
        cf_ray,
    })
}

async fn parse_csv_response(
    response: reqwest::Response,
    request: &PreparedRequest,
    status: u16,
    etag: Option<String>,
    cf_ray: Option<String>,
    output_path: Option<&Path>,
) -> Result<CloudflareResponseV1> {
    let (bytes, byte_truncated) = read_bounded_body(response, request.max_bytes).await?;
    let (rows, malformed) = csv_record_count(&bytes, request.max_rows);
    let truncated = byte_truncated || rows >= request.max_rows;
    let result = if let Some(path) = output_path {
        file_receipt(path, &bytes, rows, !truncated && !malformed).await?
    } else {
        Value::String(String::from_utf8_lossy(&bytes).into_owned())
    };
    let errors = malformed
        .then(|| CloudflareApiErrorV1 {
            code: None,
            message: "analytics CSV ended inside a quoted record".to_owned(),
        })
        .into_iter()
        .collect();
    Ok(CloudflareResponseV1 {
        status,
        success: !malformed,
        result,
        errors,
        result_info: Some(output_result_info(
            request,
            rows,
            bytes.len() as u64,
            truncated,
            malformed,
        )),
        etag,
        cf_ray,
    })
}

fn csv_record_count(bytes: &[u8], max_rows: u64) -> (u64, bool) {
    let mut quoted = false;
    let mut records = 0_u64;
    let mut index = 0;
    while index < bytes.len() && records <= max_rows {
        match bytes[index] {
            b'"' if quoted && bytes.get(index + 1) == Some(&b'"') => index += 1,
            b'"' => quoted = !quoted,
            b'\n' if !quoted => records += 1,
            _ => {}
        }
        index += 1;
    }
    let records = if records > 0 {
        records.saturating_sub(1)
    } else {
        0
    };
    (records.min(max_rows), quoted)
}

#[expect(
    clippy::too_many_arguments,
    reason = "a partial receipt records every bounded output and upstream identity field explicitly"
)]
fn partial_output_response(
    status: u16,
    result: Value,
    request: &PreparedRequest,
    rows: u64,
    bytes: u64,
    truncated: bool,
    partial: bool,
    message: &str,
    etag: Option<String>,
    cf_ray: Option<String>,
) -> CloudflareResponseV1 {
    CloudflareResponseV1 {
        status,
        success: false,
        result,
        errors: vec![CloudflareApiErrorV1 {
            code: None,
            message: message.to_owned(),
        }],
        result_info: Some(output_result_info(request, rows, bytes, truncated, partial)),
        etag,
        cf_ray,
    }
}

fn output_result_info(
    request: &PreparedRequest,
    rows: u64,
    bytes: u64,
    truncated: bool,
    partial: bool,
) -> Value {
    let row_limit = if request.r2_log_retrieval.is_none() {
        Value::from(request.max_rows)
    } else {
        Value::Null
    };
    let coverage = request
        .analytics_query
        .as_ref()
        .map(|contract| {
            let limit_reached = rows >= request.max_rows;
            let classification = if partial || truncated {
                "partial_response"
            } else if contract.sampling.is_some() {
                "bounded_sample"
            } else if limit_reached {
                "bounded_result_at_limit"
            } else {
                "bounded_response"
            };
            serde_json::json!({
                "classification": classification,
                "limit_reached": limit_reached,
                "dataset_completeness": "not_proven",
            })
        })
        .or_else(|| {
            request.mln_0143_data_invariants.as_ref().map(|_| {
                serde_json::json!({
                    "classification": if partial || truncated {
                        "partial_response"
                    } else {
                        "complete_invariant_manifest"
                    },
                    "limit_reached":false,
                    "dataset_completeness":"proven_under_closed_safe_bounds",
                })
            })
        })
        .or_else(|| {
            request.d1_schema_introspection.as_ref().map(|_| {
                serde_json::json!({
                    "classification": if partial || truncated {
                        "partial_response"
                    } else if rows == 1 {
                        "complete_assertion_response"
                    } else {
                        "invalid_assertion_response"
                    },
                    "limit_reached": rows > 1,
                    "dataset_completeness": "not_applicable",
                })
            })
        });
    serde_json::json!({
        "query": request.query_receipt,
        "coverage": coverage,
        "output": {
            "format": request.output_format,
            "rows": rows,
            "bytes": bytes,
            "row_limit": row_limit,
            "byte_limit": request.max_bytes,
            "truncated": truncated,
            "partial": partial,
        }
    })
}

async fn stream_r2_log_response(
    response: reqwest::Response,
    request: &PreparedRequest,
    status: u16,
    etag: Option<String>,
    cf_ray: Option<String>,
    output_path: &Path,
) -> Result<CloudflareResponseV1> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options
        .open(output_path)
        .map_err(|source| CloudflareError::OutputFile {
            path: output_path.display().to_string(),
            source,
        })?;
    let mut file = tokio::fs::File::from_std(file);
    let mut stream = response.bytes_stream();
    let mut hasher = Sha256::new();
    let mut bytes_written = 0_u64;
    let mut newline_count = 0_u64;
    let mut last_byte = None;
    let mut truncated = false;
    let mut partial = false;
    while let Some(chunk) = stream.next().await {
        let Ok(chunk) = chunk else {
            partial = true;
            break;
        };
        let remaining = bounded_usize(request.max_bytes.saturating_sub(bytes_written));
        if remaining == 0 {
            truncated = true;
            break;
        }
        let accepted = chunk.len().min(remaining);
        let bytes = &chunk[..accepted];
        file.write_all(bytes)
            .await
            .map_err(|source| CloudflareError::OutputFile {
                path: output_path.display().to_string(),
                source,
            })?;
        hasher.update(bytes);
        bytes_written += accepted as u64;
        newline_count = newline_count.saturating_add(
            u64::try_from(memchr::memchr_iter(b'\n', bytes).count()).unwrap_or(u64::MAX),
        );
        last_byte = bytes.last().copied().or(last_byte);
        if accepted < chunk.len() {
            truncated = true;
            break;
        }
    }
    file.flush()
        .await
        .map_err(|source| CloudflareError::OutputFile {
            path: output_path.display().to_string(),
            source,
        })?;
    let rows =
        newline_count + u64::from(bytes_written > 0 && last_byte.is_some_and(|byte| byte != b'\n'));
    let complete = !partial && !truncated;
    let digest = hex::encode(hasher.finalize());
    let result = serde_json::json!({
        "output_file": {
            "path": output_path,
            "sha256": format!("sha256:{digest}"),
            "rows": rows,
            "bytes": bytes_written,
            "complete": complete,
        }
    });
    let mut errors = Vec::new();
    if truncated {
        errors.push(CloudflareApiErrorV1 {
            code: None,
            message:
                "R2 log retrieval reached its governed byte limit; the file receipt is partial"
                    .to_owned(),
        });
    }
    if partial {
        errors.push(CloudflareApiErrorV1 {
            code: None,
            message: "R2 log retrieval stream failed after a partial file was written".to_owned(),
        });
    }
    Ok(CloudflareResponseV1 {
        status,
        success: complete,
        result,
        errors,
        result_info: Some(output_result_info(
            request,
            rows,
            bytes_written,
            truncated,
            partial,
        )),
        etag,
        cf_ray,
    })
}

#[expect(
    clippy::too_many_lines,
    reason = "the D1 export keeps streaming, cleanup, same-path verification, and its receipt in one fail-closed ownership boundary"
)]
async fn stream_d1_export_response(
    response: reqwest::Response,
    request: &PreparedRequest,
    output_path: &Path,
    bookmark: Option<String>,
    provider_filename: Option<String>,
) -> Result<CloudflareResponseV1> {
    let contract = request.d1_full_export.as_ref().ok_or_else(|| {
        CloudflareError::InvalidAnalyticsQuery("D1 full-export contract is missing".to_owned())
    })?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    let file = options
        .open(output_path)
        .map_err(|source| CloudflareError::OutputFile {
            path: output_path.display().to_string(),
            source,
        })?;
    let mut cleanup = CreatedOutputGuard::new(output_path);
    let result = async {
        let mut file = tokio::fs::File::from_std(file);
        let mut stream = response.bytes_stream();
        let mut hasher = Sha256::new();
        let mut bytes_written = 0_u64;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            let remaining = contract.max_bytes.saturating_sub(bytes_written);
            if chunk.len() as u64 > remaining {
                return Err(CloudflareError::InvalidAnalyticsQuery(
                    "D1 export exceeded its governed byte bound".to_owned(),
                ));
            }
            file.write_all(&chunk)
                .await
                .map_err(|source| CloudflareError::OutputFile {
                    path: output_path.display().to_string(),
                    source,
                })?;
            hasher.update(&chunk);
            bytes_written += chunk.len() as u64;
        }
        file.flush()
            .await
            .map_err(|source| CloudflareError::OutputFile {
                path: output_path.display().to_string(),
                source,
            })?;
        drop(file);
        let digest = format!("sha256:{}", hex::encode(hasher.finalize()));
        let mut verification_file =
            std::fs::File::open(output_path).map_err(|source| CloudflareError::OutputFile {
                path: output_path.display().to_string(),
                source,
            })?;
        let mut verification_hasher = Sha256::new();
        let mut verification_bytes = 0_u64;
        let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
        loop {
            let read =
                std::io::Read::read(&mut verification_file, &mut buffer).map_err(|source| {
                    CloudflareError::OutputFile {
                        path: output_path.display().to_string(),
                        source,
                    }
                })?;
            if read == 0 {
                break;
            }
            verification_hasher.update(&buffer[..read]);
            verification_bytes += read as u64;
        }
        let verification_digest = format!("sha256:{}", hex::encode(verification_hasher.finalize()));
        if verification_bytes != bytes_written || verification_digest != digest {
            return Err(CloudflareError::InvalidAnalyticsQuery(
                "D1 export same-path hash verification failed".to_owned(),
            ));
        }
        Ok((bytes_written, digest))
    }
    .await;
    let (bytes_written, digest) = match result {
        Ok(success) => {
            cleanup.disarm();
            success
        }
        Err(failure) => {
            return match cleanup.remove() {
                Ok(()) => Err(failure),
                Err(cleanup) => Err(CloudflareError::InvalidAnalyticsQuery(format!(
                    "{failure}; cleanup of newly-created `{}` failed: {cleanup}",
                    output_path.display()
                ))),
            };
        }
    };
    Ok(CloudflareResponseV1 {
        status: 200,
        success: true,
        result: serde_json::json!({
            "output_file": {
                "path": output_path,
                "sha256": digest,
                "bytes": bytes_written,
                "exists": true,
                "hash_matches": true,
                "complete": true,
            },
            "database": {
                "account_id": request.query_receipt.as_ref().and_then(|value| value.get("account_id")),
                "database_id": request.query_receipt.as_ref().and_then(|value| value.get("database_id")),
            },
            "provider": {
                "at_bookmark": bookmark,
                "filename": provider_filename,
                "exported_at": Utc::now(),
            },
        }),
        errors: Vec::new(),
        result_info: Some(serde_json::json!({
            "query": request.query_receipt,
            "output": {"bytes": bytes_written, "byte_limit": contract.max_bytes, "partial": false},
            "verification": {"strategy":"same_output_file_exists_and_sha256_matches","passed":true},
        })),
        etag: None,
        cf_ray: None,
    })
}

async fn file_receipt(path: &Path, bytes: &[u8], rows: u64, complete: bool) -> Result<Value> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options
        .open(path)
        .map_err(|source| CloudflareError::OutputFile {
            path: path.display().to_string(),
            source,
        })?;
    let mut file = tokio::fs::File::from_std(file);
    file.write_all(bytes)
        .await
        .map_err(|source| CloudflareError::OutputFile {
            path: path.display().to_string(),
            source,
        })?;
    file.flush()
        .await
        .map_err(|source| CloudflareError::OutputFile {
            path: path.display().to_string(),
            source,
        })?;
    let digest = hex::encode(Sha256::digest(bytes));
    Ok(serde_json::json!({
        "output_file": {
            "path": path,
            "sha256": format!("sha256:{digest}"),
            "rows": rows,
            "bytes": bytes.len(),
            "complete": complete,
        }
    }))
}

fn add_conditional_header(
    headers: &mut HeaderMap,
    name: HeaderName,
    value: Option<&String>,
) -> Result<()> {
    if let Some(value) = value {
        headers.insert(
            name,
            HeaderValue::from_str(value).map_err(|_| CloudflareError::InvalidConditionalHeader)?,
        );
    }
    Ok(())
}

fn pagination_bounds(result_info: Option<&Value>) -> Option<(u64, u64)> {
    let result_info = result_info?;
    let current = result_info.get("page").and_then(Value::as_u64).unwrap_or(1);
    let total = result_info.get("total_pages").and_then(Value::as_u64)?;
    (total > current).then_some((current, total))
}

enum CursorState {
    NotPresent,
    Complete,
    Next(String),
}

fn cursor_after(result_info: Option<&Value>) -> CursorState {
    let Some(cursors) = result_info
        .and_then(|info| info.get("cursors"))
        .and_then(Value::as_object)
    else {
        return CursorState::NotPresent;
    };
    cursors
        .get("after")
        .and_then(Value::as_str)
        .filter(|cursor| !cursor.is_empty())
        .map_or(CursorState::Complete, |cursor| {
            CursorState::Next(cursor.to_owned())
        })
}

fn governed_list_item_projection(item: &Value) -> Option<Value> {
    let object = item.as_object()?;
    let comment = object
        .get("comment")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())?;
    let mut targets = Vec::new();
    if let Some(ip) = object.get("ip").and_then(Value::as_str) {
        targets.push(serde_json::json!({"comment":comment,"ip":ip}));
    }
    if let Some(asn) = object.get("asn").and_then(Value::as_u64) {
        targets.push(serde_json::json!({"asn":asn,"comment":comment}));
    }
    if let Some(hostname) = item
        .pointer("/hostname/url_hostname")
        .and_then(Value::as_str)
    {
        targets.push(serde_json::json!({
            "comment":comment,
            "hostname":{"url_hostname":hostname},
        }));
    }
    (targets.len() == 1).then(|| targets.remove(0))
}

fn governed_list_delete_ids(input: &CallInput) -> Result<Vec<String>> {
    let items = input
        .body
        .as_ref()
        .and_then(|body| body.get("items"))
        .and_then(Value::as_array)
        .filter(|items| items.len() == 1)
        .ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "the governed List removal must contain exactly one member identity".to_owned(),
            )
        })?;
    items
        .iter()
        .map(|item| {
            item.get("id")
                .and_then(Value::as_str)
                .filter(|identity| !identity.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| {
                    CloudflareError::MissingVerificationTarget(
                        "the governed List removal contains an invalid member identity".to_owned(),
                    )
                })
        })
        .collect()
}

struct AsyncListReceipt<'a> {
    status: u16,
    operation_id: &'a str,
    operation_status: &'a str,
    cursor_complete: bool,
    match_count: usize,
    resource_id: Option<&'a str>,
    resource_hash: Option<&'a str>,
    failure: Option<Value>,
}

fn async_list_receipt_response(receipt: AsyncListReceipt<'_>) -> CloudflareResponseV1 {
    CloudflareResponseV1 {
        status: receipt.status,
        success: true,
        result: serde_json::json!({
            "schema_version":1,
            "operation_id":receipt.operation_id,
            "operation_status":receipt.operation_status,
            "cursor_complete":receipt.cursor_complete,
            "match_count":receipt.match_count,
            "resource_id":receipt.resource_id,
            "resource_hash":receipt.resource_hash,
            "failure_hash":receipt.failure.as_ref().and_then(|value| hash_value(value).ok()),
            "redaction":"list member target and audit comment omitted; only hashes and Cloudflare identities are retained",
        }),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    }
}

fn collection_pagination_complete(required: bool, readback: &CloudflareResponseV1) -> bool {
    !required
        || readback.result_info.as_ref().is_some_and(|result_info| {
            let page = result_info.get("page").and_then(Value::as_u64);
            let total_pages = result_info.get("total_pages").and_then(Value::as_u64);
            page.is_some_and(|page| page > 0 && Some(page) == total_pages)
        })
}

fn set_query_parameter(url: &mut Url, name: &str, value: &str) {
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(key, _)| key != name)
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    url.query_pairs_mut()
        .clear()
        .extend_pairs(pairs)
        .append_pair(name, value);
}

fn header_text(headers: &HeaderMap, name: HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn is_application_json(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
}

fn response_status_matches(expected: &str, received: u16) -> bool {
    if expected.parse::<u16>() == Ok(received) {
        return true;
    }
    let expected = expected.as_bytes();
    let received = received.to_string();
    expected.len() == received.len()
        && expected
            .iter()
            .zip(received.as_bytes())
            .all(|(expected, received)| {
                expected.eq_ignore_ascii_case(&b'X') || expected == received
            })
}

fn apply_credential(
    request: reqwest::RequestBuilder,
    credential: &AuthCredential,
) -> Result<reqwest::RequestBuilder> {
    if let Some(token) = credential.bearer_token() {
        let value = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| CloudflareError::InvalidAuthenticationHeader)?;
        return Ok(request.header(reqwest::header::AUTHORIZATION, value));
    }
    let email = credential
        .global_email()
        .ok_or(CloudflareError::InvalidAuthenticationHeader)?;
    let key = credential
        .global_key()
        .ok_or(CloudflareError::InvalidAuthenticationHeader)?;
    let email_value =
        HeaderValue::from_str(email).map_err(|_| CloudflareError::InvalidAuthenticationHeader)?;
    let key_value =
        HeaderValue::from_str(key).map_err(|_| CloudflareError::InvalidAuthenticationHeader)?;
    Ok(request
        .header(HeaderName::from_static("x-auth-email"), email_value)
        .header(HeaderName::from_static("x-auth-key"), key_value))
}

fn parse_response(
    status: u16,
    body: &Value,
    etag: Option<String>,
    cf_ray: Option<String>,
) -> CloudflareResponseV1 {
    let errors = body
        .get("errors")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|error| CloudflareApiErrorV1 {
            code: error.get("code").and_then(Value::as_i64),
            message: error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("Cloudflare returned an unspecified error")
                .to_owned(),
        })
        .collect();
    CloudflareResponseV1 {
        status,
        success: body
            .get("success")
            .and_then(Value::as_bool)
            .unwrap_or((200..300).contains(&status)),
        result: body.get("result").cloned().unwrap_or(Value::Null),
        errors,
        result_info: body.get("result_info").cloned(),
        etag,
        cf_ray,
    }
}

fn parse_data_response(
    status: u16,
    body: &Value,
    etag: Option<String>,
    cf_ray: Option<String>,
) -> CloudflareResponseV1 {
    CloudflareResponseV1 {
        status,
        success: body
            .get("success")
            .and_then(Value::as_bool)
            .unwrap_or((200..300).contains(&status)),
        result: body.get("data").cloned().unwrap_or(Value::Null),
        errors: Vec::new(),
        result_info: None,
        etag,
        cf_ray,
    }
}

fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenVerificationExpectation {
    Active,
    Revoked,
}

fn token_verification_target(
    strategy: &str,
    input: &CallInput,
    apply_response: &CloudflareResponseV1,
) -> Result<(String, TokenVerificationExpectation)> {
    match strategy {
        "api_token_details_match_created_id_and_active_status" => apply_response
            .result
            .get("id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(|token_id| (token_id.to_owned(), TokenVerificationExpectation::Active))
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget("created token id is absent".to_owned())
            }),
        "api_token_details_report_active_after_value_roll" => {
            planned_token_id(input).map(|token_id| (token_id, TokenVerificationExpectation::Active))
        }
        "api_token_details_returns_not_found_after_revoke" => planned_token_id(input)
            .map(|token_id| (token_id, TokenVerificationExpectation::Revoked)),
        other => Err(CloudflareError::UnsupportedVerificationStrategy(
            other.to_owned(),
        )),
    }
}

fn planned_token_id(input: &CallInput) -> Result<String> {
    input
        .selectors
        .get("token_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "planned token_id selector is absent".to_owned(),
            )
        })
}

fn evaluate_token_readback(
    expectation: TokenVerificationExpectation,
    token_id: &str,
    readback: &CloudflareResponseV1,
) -> (bool, String) {
    match expectation {
        TokenVerificationExpectation::Active => {
            let readback_id = readback.result.get("id").and_then(Value::as_str);
            let readback_status = readback.result.get("status").and_then(Value::as_str);
            let passed = readback.success
                && readback_id == Some(token_id)
                && readback_status == Some("active");
            let basis = if passed {
                format!("live token details matched `{token_id}` with active status")
            } else {
                format!(
                    "live token details did not match active token `{token_id}` (status {}, id {})",
                    readback_status.unwrap_or("missing"),
                    readback_id.unwrap_or("missing")
                )
            };
            (passed, basis)
        }
        TokenVerificationExpectation::Revoked => {
            let passed = readback.status == 404 && !readback.success;
            let basis = if passed {
                format!("live token details returned not found for revoked token `{token_id}`")
            } else {
                format!(
                    "revoked token `{token_id}` still produced HTTP {} with success={}",
                    readback.status, readback.success
                )
            };
            (passed, basis)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DnsRecordVerificationExpectation {
    MatchesPlannedFields,
    Deleted,
}

fn dns_record_verification_target(
    strategy: &str,
    input: &CallInput,
    apply_response: &CloudflareResponseV1,
) -> Result<(String, String, DnsRecordVerificationExpectation)> {
    let zone_id = planned_selector(input, "zone_id")?;
    match strategy {
        "dns_record_details_match_created_id_and_planned_fields" => apply_response
            .result
            .get("id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(|record_id| {
                (
                    zone_id,
                    record_id.to_owned(),
                    DnsRecordVerificationExpectation::MatchesPlannedFields,
                )
            })
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(
                    "created DNS record id is absent".to_owned(),
                )
            }),
        "dns_record_details_match_planned_id_and_fields" => Ok((
            zone_id,
            planned_selector(input, "dns_record_id")?,
            DnsRecordVerificationExpectation::MatchesPlannedFields,
        )),
        "dns_record_details_returns_not_found_after_delete" => Ok((
            zone_id,
            planned_selector(input, "dns_record_id")?,
            DnsRecordVerificationExpectation::Deleted,
        )),
        other => Err(CloudflareError::UnsupportedVerificationStrategy(
            other.to_owned(),
        )),
    }
}

fn planned_selector(input: &CallInput, name: &str) -> Result<String> {
    input
        .selectors
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(format!("planned {name} selector is absent"))
        })
}

fn evaluate_dns_record_readback(
    expectation: DnsRecordVerificationExpectation,
    record_id: &str,
    planned_body: Option<&Value>,
    apply_response: &CloudflareResponseV1,
    readback: &CloudflareResponseV1,
) -> Result<(bool, String)> {
    if expectation == DnsRecordVerificationExpectation::Deleted {
        let passed = readback.status == 404 && !readback.success;
        let basis = if passed {
            format!("live DNS record details returned not found for deleted record `{record_id}`")
        } else {
            format!(
                "deleted DNS record `{record_id}` still produced HTTP {} with success={}",
                readback.status, readback.success
            )
        };
        return Ok((passed, basis));
    }

    let planned = planned_body.and_then(Value::as_object).ok_or_else(|| {
        CloudflareError::MissingVerificationTarget(
            "planned DNS record request body is absent or not an object".to_owned(),
        )
    })?;
    let apply_id = apply_response.result.get("id").and_then(Value::as_str);
    let readback_id = readback.result.get("id").and_then(Value::as_str);
    let apply_mismatches = mismatched_planned_fields(planned, &apply_response.result);
    let readback_mismatches = mismatched_planned_fields(planned, &readback.result);
    let passed = apply_response.success
        && readback.success
        && apply_id == Some(record_id)
        && readback_id == Some(record_id)
        && apply_mismatches.is_empty()
        && readback_mismatches.is_empty();
    let basis = if passed {
        format!(
            "mutation response and live DNS record details matched record `{record_id}` and every planned field"
        )
    } else {
        format!(
            "DNS record `{record_id}` verification mismatch (apply success={}, apply id={}, readback success={}, readback id={}, apply fields={}, readback fields={})",
            apply_response.success,
            apply_id.unwrap_or("missing"),
            readback.success,
            readback_id.unwrap_or("missing"),
            render_field_names(&apply_mismatches),
            render_field_names(&readback_mismatches),
        )
    };
    Ok((passed, basis))
}

fn mismatched_planned_fields(
    planned: &serde_json::Map<String, Value>,
    actual: &Value,
) -> Vec<String> {
    planned
        .iter()
        .filter(|(name, planned_value)| {
            actual
                .get(name.as_str())
                .is_none_or(|actual_value| !contains_planned_value(actual_value, planned_value))
        })
        .map(|(name, _)| name.clone())
        .collect()
}

fn mismatched_verifiable_planned_fields(
    capability: &CapabilityV1,
    planned: &serde_json::Map<String, Value>,
    actual: &Value,
) -> Vec<String> {
    let schema = capability.request_schema.as_ref();
    planned
        .iter()
        .filter(|(name, planned_value)| {
            let mut path = vec![RequestSchemaPathStep::Property((*name).clone())];
            let response_field =
                verification_response_field(capability, name).unwrap_or_else(|| (*name).clone());
            !contains_verifiable_planned_value(
                actual.get(response_field.as_str()),
                planned_value,
                schema,
                &mut path,
                0,
            )
        })
        .map(|(name, _)| name.clone())
        .collect()
}

fn verification_response_field(capability: &CapabilityV1, request_field: &str) -> Option<String> {
    if capability.id != "r2-create-bucket"
        || capability.method != "POST"
        || capability.product != "R2 Bucket"
        || capability.path != "/accounts/{account_id}/r2/buckets"
        || request_field != "storageClass"
    {
        return None;
    }
    capability
        .request_object_field_verification_response_field(request_field)
        .filter(|response_field| response_field == "storage_class")
}

fn extend_r2_bucket_create_mismatches(
    plan: &PlanV1,
    input: &CallInput,
    actual: &Value,
    mismatches: &mut Vec<String>,
) {
    if plan.capability.id != "r2-create-bucket"
        || plan.capability.product != "R2 Bucket"
        || plan.capability.path != "/accounts/{account_id}/r2/buckets"
    {
        return;
    }
    if input
        .selectors
        .get("cf-r2-jurisdiction")
        .is_some_and(|planned_jurisdiction| {
            actual.get("jurisdiction") != Some(planned_jurisdiction)
        })
    {
        mismatches.push("cf-r2-jurisdiction".to_owned());
    }
    mismatches.sort();
    mismatches.dedup();
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RequestSchemaPathStep {
    Property(String),
    Item,
}

fn contains_verifiable_planned_value(
    actual: Option<&Value>,
    planned: &Value,
    schema: Option<&Value>,
    path: &mut Vec<RequestSchemaPathStep>,
    depth: usize,
) -> bool {
    if depth > MAX_REQUEST_VALIDATION_DEPTH {
        return false;
    }
    if schema.is_some_and(|schema| request_schema_path_is_verification_omitted(schema, path)) {
        return true;
    }
    let Some(actual) = actual else {
        return false;
    };
    match (actual, planned) {
        (Value::Object(actual), Value::Object(planned)) => planned.iter().all(|(name, value)| {
            path.push(RequestSchemaPathStep::Property(name.clone()));
            let matches =
                contains_verifiable_planned_value(actual.get(name), value, schema, path, depth + 1);
            path.pop();
            matches
        }),
        (Value::Array(actual), Value::Array(planned)) => {
            if actual.len() != planned.len() {
                return false;
            }
            path.push(RequestSchemaPathStep::Item);
            let matches = actual.iter().zip(planned).all(|(actual, planned)| {
                contains_verifiable_planned_value(Some(actual), planned, schema, path, depth + 1)
            });
            path.pop();
            matches
        }
        _ => actual == planned,
    }
}

fn request_schema_path_is_verification_omitted(
    schema: &Value,
    path: &[RequestSchemaPathStep],
) -> bool {
    let mut remaining_steps = MAX_REQUEST_SCHEMA_PROJECTION_STEPS;
    let Some(candidates) = request_schema_path_candidates(schema, path, 0, &mut remaining_steps)
    else {
        return false;
    };
    !candidates.is_empty()
        && candidates.iter().all(|candidate| {
            schema_declares_verification_omitted(candidate, 0, &mut remaining_steps)
        })
}

const MAX_REQUEST_SCHEMA_PROJECTION_STEPS: usize = 4_096;

fn request_schema_path_candidates<'a>(
    schema: &'a Value,
    path: &[RequestSchemaPathStep],
    depth: usize,
    remaining_steps: &mut usize,
) -> Option<Vec<&'a Value>> {
    if depth > MAX_REQUEST_VALIDATION_DEPTH || *remaining_steps == 0 {
        return None;
    }
    *remaining_steps -= 1;
    let Some((step, remaining)) = path.split_first() else {
        return Some(vec![schema]);
    };
    let mut candidates = Vec::new();
    let child = match step {
        RequestSchemaPathStep::Property(name) => schema
            .get("properties")
            .and_then(Value::as_object)
            .and_then(|properties| properties.get(name)),
        RequestSchemaPathStep::Item => schema.get("items"),
    };
    if let Some(child) = child {
        candidates.extend(request_schema_path_candidates(
            child,
            remaining,
            depth + 1,
            remaining_steps,
        )?);
    }
    for composition in ["allOf", "oneOf", "anyOf"] {
        for member in schema
            .get(composition)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            candidates.extend(request_schema_path_candidates(
                member,
                path,
                depth + 1,
                remaining_steps,
            )?);
        }
    }
    Some(candidates)
}

fn schema_declares_verification_omitted(
    schema: &Value,
    depth: usize,
    remaining_steps: &mut usize,
) -> bool {
    if depth > MAX_REQUEST_VALIDATION_DEPTH || *remaining_steps == 0 {
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

#[cfg(test)]
mod request_schema_projection_tests {
    use super::{RequestSchemaPathStep, request_schema_path_is_verification_omitted};

    #[test]
    fn write_only_projection_fails_closed_when_schema_work_is_exhausted() {
        let branches = (0..5_000)
            .map(|_| {
                serde_json::json!({
                    "type":"object",
                    "properties":{
                        "secret":{"type":"string", "writeOnly":true}
                    }
                })
            })
            .collect::<Vec<_>>();
        let schema = serde_json::json!({"oneOf":branches});
        let path = [RequestSchemaPathStep::Property("secret".to_owned())];

        assert!(!request_schema_path_is_verification_omitted(&schema, &path));
    }
}

fn contains_planned_value(actual: &Value, planned: &Value) -> bool {
    match (actual, planned) {
        (Value::Object(actual), Value::Object(planned)) => planned.iter().all(|(name, value)| {
            actual
                .get(name)
                .is_some_and(|actual_value| contains_planned_value(actual_value, value))
        }),
        _ => actual == planned,
    }
}

fn render_field_names(fields: &[String]) -> String {
    if fields.is_empty() {
        "none".to_owned()
    } else {
        fields.join(",")
    }
}

fn evaluate_oauth_client_secret_readback(
    strategy: &str,
    oauth_client_id: &str,
    apply_response: &CloudflareResponseV1,
    readback: &CloudflareResponseV1,
) -> Result<(bool, String)> {
    let readback_identity_matches =
        readback.result.get("client_id").and_then(Value::as_str) == Some(oauth_client_id);
    let apply_status_matches = apply_response.status == 200;
    let readback_status_matches = readback.status == 200;
    let rotated_state = readback
        .result
        .get("has_rotated_secret")
        .and_then(Value::as_bool);
    match strategy {
        "oauth_client_reports_rotated_secret_after_value_roll" => {
            let client_secret_present = apply_response
                .result
                .get("client_secret")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty());
            let rotated_state_matches = rotated_state == Some(true);
            let passed = apply_response.success
                && apply_status_matches
                && client_secret_present
                && readback.success
                && readback_status_matches
                && readback_identity_matches
                && rotated_state_matches;
            let basis = format!(
                "OAuth client rotation proof (apply HTTP {}, apply success={}, one-time client secret present={}, readback HTTP {}, readback success={}, readback client identity matches={}, has_rotated_secret=true={})",
                apply_response.status,
                apply_response.success,
                client_secret_present,
                readback.status,
                readback.success,
                readback_identity_matches,
                rotated_state_matches
            );
            Ok((passed, basis))
        }
        "oauth_client_reports_no_rotated_secret_after_old_secret_delete" => {
            let apply_identity_matches =
                apply_response.result.get("id").and_then(Value::as_str) == Some(oauth_client_id);
            let rotated_state_matches = rotated_state == Some(false);
            let passed = apply_response.success
                && apply_status_matches
                && apply_identity_matches
                && readback.success
                && readback_status_matches
                && readback_identity_matches
                && rotated_state_matches;
            let basis = format!(
                "OAuth client old-secret deletion proof (apply HTTP {}, apply success={}, apply identity matches={}, readback HTTP {}, readback success={}, readback client identity matches={}, has_rotated_secret=false={})",
                apply_response.status,
                apply_response.success,
                apply_identity_matches,
                readback.status,
                readback.success,
                readback_identity_matches,
                rotated_state_matches
            );
            Ok((passed, basis))
        }
        _ => Err(CloudflareError::UnsupportedVerificationStrategy(
            strategy.to_owned(),
        )),
    }
}

fn evaluate_worker_script_secret_put_readback(
    planned_name: &str,
    planned_type: &str,
    apply_response: &CloudflareResponseV1,
    readback: &CloudflareResponseV1,
) -> (bool, String) {
    let apply_name_matches =
        apply_response.result.get("name").and_then(Value::as_str) == Some(planned_name);
    let apply_type_matches =
        apply_response.result.get("type").and_then(Value::as_str) == Some(planned_type);
    let readback_name_matches =
        readback.result.get("name").and_then(Value::as_str) == Some(planned_name);
    let readback_type_matches =
        readback.result.get("type").and_then(Value::as_str) == Some(planned_type);
    // A successful put answers 201 Created, not 200, even though Cloudflare's
    // OpenAPI declares only 200. Requiring 200 here failed every genuine
    // success while the basis printed a truthful "apply HTTP 201" — reporting
    // the status as a value rather than as a match hid which condition
    // actually failed, so the match is now explicit in both.
    let apply_status_matches = matches!(apply_response.status, 200 | 201);
    let readback_status_matches = readback.status == 200;
    let passed = apply_status_matches
        && apply_response.success
        && apply_name_matches
        && apply_type_matches
        && readback_status_matches
        && readback.success
        && readback_name_matches
        && readback_type_matches;
    let basis = format!(
        "Worker script secret proof (apply HTTP {} accepted={}, apply success={}, apply name matches={}, apply type matches={}, readback HTTP {} accepted={}, readback success={}, readback name matches={}, readback type matches={})",
        apply_response.status,
        apply_status_matches,
        apply_response.success,
        apply_name_matches,
        apply_type_matches,
        readback.status,
        readback_status_matches,
        readback.success,
        readback_name_matches,
        readback_type_matches
    );
    (passed, basis)
}

fn evaluate_access_service_token_refresh_readback(
    service_token_id: &str,
    apply_response: &CloudflareResponseV1,
    readback: &CloudflareResponseV1,
) -> (bool, String) {
    let apply_identity_matches =
        apply_response.result.get("id").and_then(Value::as_str) == Some(service_token_id);
    let readback_identity_matches =
        readback.result.get("id").and_then(Value::as_str) == Some(service_token_id);
    let apply_expiration = apply_response
        .result
        .get("expires_at")
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok());
    let readback_expiration = readback
        .result
        .get("expires_at")
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok());
    let apply_expiration_future = apply_expiration
        .as_ref()
        .is_some_and(|expiration| expiration.timestamp() > Utc::now().timestamp());
    let expiration_matches = apply_expiration
        .as_ref()
        .zip(readback_expiration.as_ref())
        .is_some_and(|(apply, readback)| apply == readback);
    let passed = apply_response.status == 200
        && apply_response.success
        && apply_identity_matches
        && apply_expiration_future
        && readback.status == 200
        && readback.success
        && readback_identity_matches
        && expiration_matches;
    let basis = format!(
        "Access service-token refresh proof (apply HTTP {}, apply success={}, apply identity matches={}, apply expiration is valid and future={}, readback HTTP {}, readback success={}, readback identity matches={}, expiration matches={})",
        apply_response.status,
        apply_response.success,
        apply_identity_matches,
        apply_expiration_future,
        readback.status,
        readback.success,
        readback_identity_matches,
        expiration_matches
    );
    (passed, basis)
}

fn validate_verification_preconditions(capability: &CapabilityV1, input: &CallInput) -> Result<()> {
    let strategy = capability.verification.strategy.as_str();
    if !capability.verification_contract_supported() {
        return Err(CloudflareError::UnsupportedVerificationStrategy(
            strategy.to_owned(),
        ));
    }
    if matches!(
        strategy,
        "oauth_client_reports_rotated_secret_after_value_roll"
            | "oauth_client_reports_no_rotated_secret_after_old_secret_delete"
    ) {
        return validate_oauth_client_secret_target(capability, input);
    }
    if strategy == "worker_script_secret_reports_planned_name_and_type_after_put" {
        return validate_worker_script_secret_put_target(capability, input);
    }
    if strategy == "worker_script_settings_returns_not_found_after_delete" {
        return validate_worker_script_delete_target(capability, input);
    }
    if strategy == "access_service_token_reports_refreshed_expiration" {
        return validate_access_service_token_refresh_target(capability, input);
    }
    if strategy.starts_with("async_list_operation_") {
        return validate_async_list_mutation_target(capability, input);
    }
    let body_label = match strategy {
        "created_resource_contains_planned_fields_by_returned_id"
        | "created_access_application_contains_planned_fields_by_returned_id"
        | "parent_collection_contains_created_resource_id_and_planned_fields"
        | "parent_object_contains_created_nested_resource_by_correlation"
        | "web_analytics_rule_list_contains_created_id_and_planned_fields"
        | "dns_record_details_match_created_id_and_planned_fields" => Some("create"),
        "same_resource_contains_planned_fields_after_update"
        | "same_path_result_contains_planned_fields_after_update"
        | "parent_collection_item_contains_planned_fields_after_update"
        | "dns_record_details_match_planned_id_and_fields" => Some("update"),
        "same_path_result_contains_planned_fields_after_mutation" => Some("mutation"),
        _ => None,
    };
    if let Some(label) = body_label {
        input
            .body
            .as_ref()
            .and_then(Value::as_object)
            .filter(|body| !body.is_empty())
            .ok_or_else(|| {
                CloudflareError::MissingVerificationTarget(format!(
                    "planned {label} body is absent, empty, or not an object"
                ))
            })?;
    }
    match strategy {
        "same_resource_returns_not_found_after_delete" => {
            validate_same_path_delete_target(capability, input)
        }
        "same_resource_contains_planned_fields_after_update"
        | "same_path_result_contains_planned_fields_after_update"
        | "same_path_result_contains_planned_fields_after_mutation" => {
            validate_same_path_update_target(capability, input)
        }
        "created_resource_contains_planned_fields_by_returned_id"
        | "web_analytics_rule_list_contains_created_id_and_planned_fields" => {
            validate_created_resource_target(capability, input)
        }
        "created_access_application_contains_planned_fields_by_returned_id" => {
            validate_access_application_create_target(capability, input)
        }
        "parent_collection_contains_created_resource_id_and_planned_fields"
        | "worker_tail_collection_contains_created_lease_id" => {
            validate_created_collection_resource_target(capability, input)
        }
        "parent_object_contains_created_nested_resource_by_correlation" => {
            validate_created_nested_resource_target(capability, input)
        }
        "parent_collection_omits_deleted_resource_id" => {
            validate_deleted_resource_target(capability, input)
        }
        "parent_object_omits_deleted_nested_resource_id" => {
            validate_deleted_nested_resource_target(capability, input)
        }
        "web_analytics_rule_list_omits_deleted_id" => {
            validate_web_analytics_rule_delete_target(capability, input)
        }
        "parent_collection_item_contains_planned_fields_after_update" => {
            validate_updated_resource_target(capability, input)
        }
        _ => Ok(()),
    }
}

fn validate_async_list_mutation_target(capability: &CapabilityV1, input: &CallInput) -> Result<()> {
    let selectors = input.selectors.as_object().ok_or_else(|| {
        CloudflareError::MissingVerificationTarget(
            "the governed List selectors are not an object".to_owned(),
        )
    })?;
    if selectors.len() != 2
        || ["account_id", "list_id"].iter().any(|name| {
            selectors
                .get(*name)
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
        })
        || !clean_verification_query(input)
        || capability.async_collection_mutation.is_none()
    {
        return Err(CloudflareError::MissingVerificationTarget(
            "the governed List operation is broader than its exact account, list, and body-only contract"
                .to_owned(),
        ));
    }
    match capability.verification.strategy.as_str() {
        "async_list_operation_completes_and_correlated_member_exists" => {
            let item = input
                .body
                .as_ref()
                .and_then(Value::as_array)
                .filter(|items| items.len() == 1)
                .and_then(|items| items.first())
                .ok_or_else(|| {
                    CloudflareError::MissingVerificationTarget(
                        "the governed List add must carry exactly one item".to_owned(),
                    )
                })?;
            if governed_list_item_projection(item).is_none() {
                return Err(CloudflareError::MissingVerificationTarget(
                    "the governed List add item lacks one exact IP, ASN, or hostname plus its correlation comment"
                        .to_owned(),
                ));
            }
            Ok(())
        }
        "async_list_operation_completes_and_members_absent" => {
            governed_list_delete_ids(input).map(|_| ())
        }
        strategy => Err(CloudflareError::UnsupportedVerificationStrategy(
            strategy.to_owned(),
        )),
    }
}

fn validate_worker_script_secret_put_target(
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<()> {
    let target = capability.same_path_read.as_ref().ok_or_else(|| {
        CloudflareError::MissingVerificationTarget(
            "the hash-bound Worker script secret readback contract is absent".to_owned(),
        )
    })?;
    if target.path != "/accounts/{account_id}/workers/scripts/{script_name}/secrets/{secret_name}"
        || target.read_capability_id != "worker-get-script-secret"
        || target.verified_response_fields != ["name", "type"]
        || !clean_verification_query(input)
    {
        return Err(CloudflareError::MissingVerificationTarget(
            "the Worker script secret operation does not match its hash-bound exact readback contract"
                .to_owned(),
        ));
    }
    let selectors = input.selectors.as_object().ok_or_else(|| {
        CloudflareError::MissingVerificationTarget(
            "the planned Worker script selectors are not an object".to_owned(),
        )
    })?;
    if selectors.len() != 2
        || ["account_id", "script_name"].iter().any(|name| {
            selectors
                .get(*name)
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
        })
    {
        return Err(CloudflareError::MissingVerificationTarget(
            "the planned Worker script selectors are missing, empty, or broader than the exact account and script target"
                .to_owned(),
        ));
    }
    validate_request_contract(capability, input)?;
    let body = input
        .body
        .as_ref()
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "the planned Worker script secret body is absent or not an object".to_owned(),
            )
        })?;
    if body
        .get("name")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
        || !matches!(
            body.get("type").and_then(Value::as_str),
            Some("secret_text" | "secret_key")
        )
    {
        return Err(CloudflareError::MissingVerificationTarget(
            "the planned Worker script secret name or type is absent or invalid".to_owned(),
        ));
    }
    Ok(())
}

/// The Access application create validator. Unlike the generic created-resource
/// validator, it does NOT require every planned field to be a verified field:
/// an Access app body carries variant-specific fields (`domain`, `saas_app`, …)
/// that are legitimately part of the create but not part of the curated
/// `[name, type]` verification set. It confirms the curated contract's shape
/// and that the planned body actually carries the curated fields, then lets
/// variant fields through unverified — the runtime evaluator only compares the
/// curated set on readback, so this never over-asserts, and a curated-field
/// drift (proven separately) still faults.
fn validate_access_application_create_target(
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<()> {
    let target = capability.created_resource.as_ref().ok_or_else(|| {
        CloudflareError::MissingVerificationTarget(
            "the hash-bound Access application create contract is absent".to_owned(),
        )
    })?;
    if target.detail_path != "/accounts/{account_id}/access/apps/{app_id}"
        || target.identity_selector != "app_id"
        || target.response_result_identity_pointer != "/id"
        || target.read_capability_id != "access-applications-get-an-access-application"
        || target.verified_response_fields != ["name", "type"]
        || !clean_verification_query(input)
    {
        return Err(CloudflareError::MissingVerificationTarget(
            "the Access application create does not match its hash-bound curated readback contract"
                .to_owned(),
        ));
    }
    let planned = input
        .body
        .as_ref()
        .and_then(Value::as_object)
        .filter(|body| !body.is_empty())
        .ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "planned Access application create body is absent, empty, or not an object"
                    .to_owned(),
            )
        })?;
    // The curated fields must actually be present to be verifiable.
    for field in &target.verified_response_fields {
        if planned
            .get(field)
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            return Err(CloudflareError::MissingVerificationTarget(format!(
                "the planned Access application is missing its verifiable `{field}`"
            )));
        }
    }
    let selectors = input.selectors.as_object().ok_or_else(|| {
        CloudflareError::MissingVerificationTarget(
            "the planned Access application selectors are not an object".to_owned(),
        )
    })?;
    if selectors.len() != 1
        || selectors
            .get("account_id")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err(CloudflareError::MissingVerificationTarget(
            "the planned Access application selectors are missing, empty, or broader than the exact account target"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_oauth_client_secret_target(capability: &CapabilityV1, input: &CallInput) -> Result<()> {
    let target = capability.same_path_read.as_ref().ok_or_else(|| {
        CloudflareError::MissingVerificationTarget(
            "the hash-bound OAuth client detail readback contract is absent".to_owned(),
        )
    })?;
    if target.path != "/accounts/{account_id}/oauth_clients/{oauth_client_id}"
        || target.read_capability_id != "oauth-clients-get"
        || target.verified_response_fields != ["client_id", "has_rotated_secret"]
        || capability.request_schema.is_some()
        || input.body.is_some()
        || !clean_verification_query(input)
    {
        return Err(CloudflareError::MissingVerificationTarget(
            "the OAuth client secret operation does not match its hash-bound body-free detail readback contract"
                .to_owned(),
        ));
    }
    let selectors = input.selectors.as_object().ok_or_else(|| {
        CloudflareError::MissingVerificationTarget(
            "the planned OAuth client selectors are not an object".to_owned(),
        )
    })?;
    if selectors.len() != 2
        || ["account_id", "oauth_client_id"].iter().any(|name| {
            selectors
                .get(*name)
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
        })
    {
        return Err(CloudflareError::MissingVerificationTarget(
            "the planned OAuth client selectors are missing, empty, or broader than the exact account and client target"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_access_service_token_refresh_target(
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<()> {
    let target = capability.same_path_read.as_ref().ok_or_else(|| {
        CloudflareError::MissingVerificationTarget(
            "the hash-bound Access service-token detail readback contract is absent".to_owned(),
        )
    })?;
    if target.path != "/accounts/{account_id}/access/service_tokens/{service_token_id}"
        || target.read_capability_id != "access-service-tokens-get-a-service-token"
        || target.verified_response_fields != ["expires_at", "id"]
        || capability.request_schema.is_some()
        || input.body.is_some()
        || !clean_verification_query(input)
    {
        return Err(CloudflareError::MissingVerificationTarget(
            "the Access service-token refresh does not match its hash-bound body-free detail readback contract"
                .to_owned(),
        ));
    }
    let selectors = input.selectors.as_object().ok_or_else(|| {
        CloudflareError::MissingVerificationTarget(
            "the planned Access service-token selectors are not an object".to_owned(),
        )
    })?;
    if selectors.len() != 2
        || ["account_id", "service_token_id"].iter().any(|name| {
            selectors
                .get(*name)
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
        })
    {
        return Err(CloudflareError::MissingVerificationTarget(
            "the planned Access service-token selectors are missing, empty, or broader than the exact account and token target"
                .to_owned(),
        ));
    }
    Ok(())
}

fn clean_verification_query(input: &CallInput) -> bool {
    input.query.is_null()
        || input
            .query
            .as_object()
            .is_some_and(serde_json::Map::is_empty)
}

fn same_path_verification_capability(
    mutation: &CapabilityV1,
    read_capability_id: &str,
    title: &str,
    path: &str,
) -> CapabilityV1 {
    let mut readback = CapabilityV1::new(read_capability_id, title, "GET", path);
    readback.product.clone_from(&mutation.product);
    readback.selectors = mutation
        .selectors
        .iter()
        .filter(|selector| same_path_routing_header(mutation, selector))
        .cloned()
        .collect();
    readback
}

fn same_path_routing_header(capability: &CapabilityV1, selector: &SelectorV1) -> bool {
    selector.location == "header"
        && selector.name == "cf-r2-jurisdiction"
        && !selector.required
        && selector.value_type == "string"
        && matches!(capability.product.as_str(), "R2 Bucket" | "R2 Object")
}

fn validate_worker_script_delete_target(
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<()> {
    let target = capability.same_path_read.as_ref().ok_or_else(|| {
        CloudflareError::MissingVerificationTarget(
            "the hash-bound Worker script settings readback contract is absent".to_owned(),
        )
    })?;
    if target.path != "/accounts/{account_id}/workers/scripts/{script_name}/settings"
        || target.read_capability_id != "worker-script-get-settings"
        || !target.verified_response_fields.is_empty()
        || !clean_verification_query(input)
        || input.body.is_some()
    {
        return Err(CloudflareError::MissingVerificationTarget(
            "the Worker script delete does not match its hash-bound settings readback contract"
                .to_owned(),
        ));
    }
    let selectors = input.selectors.as_object().ok_or_else(|| {
        CloudflareError::MissingVerificationTarget(
            "the planned Worker script selectors are not an object".to_owned(),
        )
    })?;
    if selectors.len() != 2
        || ["account_id", "script_name"].iter().any(|name| {
            selectors
                .get(*name)
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
        })
    {
        return Err(CloudflareError::MissingVerificationTarget(
            "the planned Worker script selectors are missing, empty, or broader than the exact account and script target"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_same_path_delete_target(capability: &CapabilityV1, input: &CallInput) -> Result<()> {
    let target = capability.same_path_read.as_ref().ok_or_else(|| {
        CloudflareError::MissingVerificationTarget(
            "the hash-bound same-path delete readback contract is absent".to_owned(),
        )
    })?;
    if target.path != capability.path
        || target.read_capability_id.is_empty()
        || !target.verified_response_fields.is_empty()
    {
        return Err(CloudflareError::MissingVerificationTarget(
            "the exact delete contains inputs outside its hash-bound same-path readback contract"
                .to_owned(),
        ));
    }
    if capability.request_schema.is_none() {
        if input.body.is_some() {
            return Err(CloudflareError::MissingVerificationTarget(
                "the exact delete contains inputs outside its hash-bound same-path readback contract"
                    .to_owned(),
            ));
        }
    } else if !capability.required_empty_request_body_contract()
        || !input
            .body
            .as_ref()
            .and_then(Value::as_object)
            .is_some_and(serde_json::Map::is_empty)
    {
        return Err(CloudflareError::MissingVerificationTarget(
            "the exact delete does not match its hash-bound required empty body contract"
                .to_owned(),
        ));
    }
    if !clean_verification_query(input) {
        return Err(CloudflareError::MissingVerificationTarget(
            "the planned delete contains query controls outside the hash-bound same-path readback contract"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_same_path_update_target(capability: &CapabilityV1, input: &CallInput) -> Result<()> {
    let operation = if capability.verification.strategy
        == "same_path_result_contains_planned_fields_after_mutation"
    {
        "mutation"
    } else {
        "update"
    };
    let target = capability.same_path_read.as_ref().ok_or_else(|| {
        CloudflareError::MissingVerificationTarget(format!(
            "the hash-bound same-path {operation} readback contract is absent"
        ))
    })?;
    if target.path != capability.path
        || target.read_capability_id.is_empty()
        || target.verified_response_fields.is_empty()
        || target
            .verified_response_fields
            .windows(2)
            .any(|fields| fields[0] >= fields[1])
    {
        return Err(CloudflareError::MissingVerificationTarget(format!(
            "the hash-bound same-path {operation} readback contract is malformed"
        )));
    }
    if !clean_verification_query(input) {
        return Err(CloudflareError::MissingVerificationTarget(format!(
            "the planned {operation} contains query controls outside the hash-bound same-path readback contract"
        )));
    }
    let Some(planned) = input.body.as_ref().and_then(Value::as_object) else {
        return Err(CloudflareError::MissingVerificationTarget(format!(
            "planned {operation} body is absent, empty, or not an object"
        )));
    };
    if planned.keys().any(|field| {
        !planned_field_is_bound_to_readback(capability, &target.verified_response_fields, field)
    }) {
        return Err(CloudflareError::MissingVerificationTarget(format!(
            "the planned {operation} contains a field outside the hash-bound same-path readback fields"
        )));
    }
    Ok(())
}

fn validate_created_resource_target(capability: &CapabilityV1, input: &CallInput) -> Result<()> {
    let target = capability.created_resource.as_ref().ok_or_else(|| {
        CloudflareError::MissingVerificationTarget(
            "the hash-bound created-resource contract is absent".to_owned(),
        )
    })?;
    let expected_suffix = format!("/{{{}}}", target.identity_selector);
    if target.identity_selector.is_empty()
        || !target.detail_path.ends_with(&expected_suffix)
        || !response_identity_pointer_supported(
            &target.identity_selector,
            &target.response_result_identity_pointer,
        )
        || target.read_capability_id.is_empty()
        || target.delete_capability_id.is_empty()
        || target.verified_response_fields.is_empty()
        || target
            .verified_response_fields
            .iter()
            .any(|field| field.is_empty() || field.contains('/'))
        || target
            .verified_response_fields
            .windows(2)
            .any(|fields| fields[0] >= fields[1])
    {
        return Err(CloudflareError::MissingVerificationTarget(
            "the hash-bound created-resource contract is malformed".to_owned(),
        ));
    }
    if !clean_verification_query(input) {
        return Err(CloudflareError::MissingVerificationTarget(
            "the planned create contains query controls outside the hash-bound exact readback contract"
                .to_owned(),
        ));
    }
    let Some(planned) = input.body.as_ref().and_then(Value::as_object) else {
        return Err(CloudflareError::MissingVerificationTarget(
            "planned create body is absent, empty, or not an object".to_owned(),
        ));
    };
    if planned.keys().any(|field| {
        !planned_field_is_bound_to_readback(capability, &target.verified_response_fields, field)
    }) {
        return Err(CloudflareError::MissingVerificationTarget(
            "the planned create contains a field outside the hash-bound exact readback fields"
                .to_owned(),
        ));
    }
    Ok(())
}

fn selector_can_be_response_id(selector: &str) -> bool {
    matches!(selector, "id" | "identifier")
        || selector.ends_with("_id")
        || selector.ends_with("_identifier")
}

/// Returns a resource identity in the exact JSON scalar type Cloudflare used.
/// Most APIs return string IDs, while Logpush returns an integer job ID. The
/// type is retained so a verification readback and a later compensation plan
/// satisfy the selector schema instead of stringifying an integer path value.
fn resource_identity_value(value: &Value) -> Option<Value> {
    match value {
        Value::String(identity) if !identity.is_empty() => Some(value.clone()),
        Value::Number(identity) if identity.is_u64() || identity.is_i64() => Some(value.clone()),
        _ => None,
    }
}

// Kept in sync with `cfctl_core::response_identity_pointer_supported` — the
// classifier gate (core) and the executor verify gate (here) must accept the
// same identity pointers, or a capability the catalog marks `dynamic_api` fails
// closed at verify time. The `database_id`->`/uuid` branch mirrors core so D1
// database creates (identity `database_id`, pointer `/uuid`) verify instead of
// falsely landing in RectificationRequired after a successful create.
fn response_identity_pointer_supported(selector: &str, pointer: &str) -> bool {
    // Fail closed: an identity pointer that names a secret field is never
    // supported (mirrors the core gate), so no verifier dereferences secret
    // material as a resource identity.
    if cfctl_core::pointer_names_secret_field(pointer) {
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

#[cfg(test)]
mod identity_pointer_parity_tests {
    use super::response_identity_pointer_supported;

    #[test]
    fn executor_gate_matches_core_including_database_id_uuid() {
        // Regression: the D1 create contract (identity `database_id`, pointer
        // `/uuid`) is classified `dynamic_api` by the core gate, so the executor
        // gate must accept it too — otherwise a successful create verifies
        // false and lands in RectificationRequired.
        assert!(response_identity_pointer_supported("database_id", "/uuid"));
        // Standard identities still hold.
        assert!(response_identity_pointer_supported("id", "/id"));
        assert!(response_identity_pointer_supported("widget_name", "/name"));
        assert!(response_identity_pointer_supported("slug", "/slug"));
        // The secret-field guard still fails closed for every shape.
        assert!(!response_identity_pointer_supported("value", "/value"));
        assert!(!response_identity_pointer_supported(
            "secretAccessKey",
            "/secretAccessKey"
        ));
        // A pointer that does not match its selector is rejected.
        assert!(!response_identity_pointer_supported("database_id", "/name"));
    }
}

fn validate_created_collection_resource_target(
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<()> {
    let target = capability
        .created_collection_resource
        .as_ref()
        .ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "the hash-bound created-collection-resource contract is absent".to_owned(),
            )
        })?;
    if is_worker_tail_create_capability(capability) {
        if target.collection_path != capability.path
            || target.identity_selector != "id"
            || target.response_result_identity_pointer != "/id"
            || target.response_item_identity_pointer != "/id"
            || target.read_capability_id != "worker-tail-logs-list-tails"
            || target.delete_capability_id != "worker-tail-logs-delete-tail"
            || !target.verified_response_fields.is_empty()
            || target.requires_page_number_completion
            || input.body.is_some()
            || !clean_verification_query(input)
        {
            return Err(CloudflareError::MissingVerificationTarget(
                "the hash-bound Worker tail lease verification target is malformed".to_owned(),
            ));
        }
        return Ok(());
    }
    if target.collection_path != capability.path
        || target.identity_selector.is_empty()
        || target.response_result_identity_pointer != target.response_item_identity_pointer
        || !response_identity_pointer_supported(
            &target.identity_selector,
            &target.response_result_identity_pointer,
        )
        || target.read_capability_id.is_empty()
        || target.delete_capability_id.is_empty()
        || target.verified_response_fields.is_empty()
        || target
            .verified_response_fields
            .iter()
            .any(|field| field.is_empty() || field.contains('/'))
        || target
            .verified_response_fields
            .windows(2)
            .any(|fields| fields[0] >= fields[1])
    {
        return Err(CloudflareError::MissingVerificationTarget(
            "the hash-bound created-collection-resource contract is malformed".to_owned(),
        ));
    }
    if !clean_verification_query(input) {
        return Err(CloudflareError::MissingVerificationTarget(
            "the planned create contains query controls outside the hash-bound collection readback contract"
                .to_owned(),
        ));
    }
    let Some(planned) = input.body.as_ref().and_then(Value::as_object) else {
        return Err(CloudflareError::MissingVerificationTarget(
            "planned create body is absent, empty, or not an object".to_owned(),
        ));
    };
    if planned.keys().any(|field| {
        !planned_field_is_bound_to_readback(capability, &target.verified_response_fields, field)
    }) {
        return Err(CloudflareError::MissingVerificationTarget(
            "the planned create contains a field outside the hash-bound collection readback fields"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_deleted_resource_target(capability: &CapabilityV1, input: &CallInput) -> Result<()> {
    let target = capability.deleted_resource.as_ref().ok_or_else(|| {
        CloudflareError::MissingVerificationTarget(
            "the hash-bound deleted-resource contract is absent".to_owned(),
        )
    })?;
    let expected_path = format!(
        "{}/{{{}}}",
        target.collection_path.trim_end_matches('/'),
        target.identity_selector
    );
    if target.identity_selector.is_empty()
        || capability.path != expected_path
        || !response_identity_pointer_supported(
            &target.identity_selector,
            &target.response_item_identity_pointer,
        )
        || target.read_capability_id.is_empty()
        || input
            .selectors
            .get(&target.identity_selector)
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err(CloudflareError::MissingVerificationTarget(
            "the hash-bound deleted-resource contract is malformed".to_owned(),
        ));
    }
    if input.body.is_some() {
        return Err(CloudflareError::MissingVerificationTarget(
            "the planned delete body is outside the hash-bound collection readback contract"
                .to_owned(),
        ));
    }
    if !clean_verification_query(input) {
        return Err(CloudflareError::MissingVerificationTarget(
            "the planned delete contains query controls outside the hash-bound collection readback contract"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_created_nested_resource_target(
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<()> {
    let target = capability.created_nested_resource.as_ref().ok_or_else(|| {
        CloudflareError::MissingVerificationTarget(
            "the hash-bound created-nested-resource contract is absent".to_owned(),
        )
    })?;
    let expected_delete_path = format!(
        "{}/{{{}}}",
        capability.path.trim_end_matches('/'),
        target.identity_selector
    );
    if target.parent_path.is_empty()
        || target.items_pointer.is_empty()
        || !target.items_pointer.starts_with('/')
        || target.identity_selector.is_empty()
        || !response_identity_pointer_supported(
            &target.identity_selector,
            &target.response_item_identity_pointer,
        )
        || target.correlation_field.is_empty()
        || target.read_capability_id.is_empty()
        || target.delete_capability_id.is_empty()
        || target.delete_path != expected_delete_path
        || target.verified_response_fields.is_empty()
        || target
            .verified_response_fields
            .binary_search(&target.correlation_field)
            .is_err()
    {
        return Err(CloudflareError::MissingVerificationTarget(
            "the hash-bound created-nested-resource contract is malformed".to_owned(),
        ));
    }
    if !clean_verification_query(input) {
        return Err(CloudflareError::MissingVerificationTarget(
            "the planned nested-resource create contains query controls outside the hash-bound parent readback contract"
                .to_owned(),
        ));
    }
    let planned = input
        .body
        .as_ref()
        .and_then(Value::as_object)
        .filter(|body| !body.is_empty())
        .ok_or_else(|| {
            CloudflareError::MissingVerificationTarget(
                "planned nested-resource create body is absent, empty, or not an object".to_owned(),
            )
        })?;
    if planned
        .get(&target.correlation_field)
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
        || planned.keys().any(|field| {
            !planned_field_is_bound_to_readback(capability, &target.verified_response_fields, field)
        })
    {
        return Err(CloudflareError::MissingVerificationTarget(
            "the planned nested-resource create is missing its correlation value or contains a field outside the hash-bound readback fields"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_deleted_nested_resource_target(
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<()> {
    let target = capability.deleted_nested_resource.as_ref().ok_or_else(|| {
        CloudflareError::MissingVerificationTarget(
            "the hash-bound deleted-nested-resource contract is absent".to_owned(),
        )
    })?;
    let expected_path = format!(
        "{}/{{{}}}",
        target.collection_path.trim_end_matches('/'),
        target.identity_selector
    );
    if target.parent_path.is_empty()
        || target.collection_path.is_empty()
        || target.items_pointer.is_empty()
        || !target.items_pointer.starts_with('/')
        || capability.path != expected_path
        || !response_identity_pointer_supported(
            &target.identity_selector,
            &target.response_item_identity_pointer,
        )
        || target.read_capability_id.is_empty()
        || input
            .selectors
            .get(&target.identity_selector)
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || input.body.is_some()
        || !clean_verification_query(input)
    {
        return Err(CloudflareError::MissingVerificationTarget(
            "the hash-bound deleted-nested-resource target is malformed".to_owned(),
        ));
    }
    Ok(())
}

fn validate_web_analytics_rule_delete_target(
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<()> {
    if capability.id != "web-analytics-delete-rule"
        || input
            .selectors
            .get("account_id")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || input
            .selectors
            .get("ruleset_id")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || input
            .selectors
            .get("rule_id")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || input.body.is_some()
        || !clean_verification_query(input)
    {
        return Err(CloudflareError::MissingVerificationTarget(
            "the hash-bound Web Analytics rule deletion target is malformed".to_owned(),
        ));
    }
    Ok(())
}

fn validate_updated_resource_target(capability: &CapabilityV1, input: &CallInput) -> Result<()> {
    let target = capability.updated_resource.as_ref().ok_or_else(|| {
        CloudflareError::MissingVerificationTarget(
            "the hash-bound updated-resource contract is absent".to_owned(),
        )
    })?;
    let expected_path = format!(
        "{}/{{{}}}",
        target.collection_path.trim_end_matches('/'),
        target.identity_selector
    );
    if target.identity_selector.is_empty()
        || capability.path != expected_path
        || !response_identity_pointer_supported(
            &target.identity_selector,
            &target.response_item_identity_pointer,
        )
        || target.read_capability_id.is_empty()
        || input
            .selectors
            .get(&target.identity_selector)
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err(CloudflareError::MissingVerificationTarget(
            "the hash-bound updated-resource contract is malformed".to_owned(),
        ));
    }
    if !clean_verification_query(input) {
        return Err(CloudflareError::MissingVerificationTarget(
            "the planned update contains query controls outside the hash-bound collection readback contract"
                .to_owned(),
        ));
    }
    let Some(planned) = input.body.as_ref().and_then(Value::as_object) else {
        return Err(CloudflareError::MissingVerificationTarget(
            "planned update body is absent, empty, or not an object".to_owned(),
        ));
    };
    if planned.keys().any(|field| {
        !planned_field_is_bound_to_readback(capability, &target.verified_response_fields, field)
    }) {
        return Err(CloudflareError::MissingVerificationTarget(
            "the planned update contains a field outside the hash-bound collection readback fields"
                .to_owned(),
        ));
    }
    Ok(())
}

fn planned_field_is_bound_to_readback(
    capability: &CapabilityV1,
    verified_response_fields: &[String],
    field: &str,
) -> bool {
    verified_response_fields
        .binary_search_by(|candidate| candidate.as_str().cmp(field))
        .is_ok()
        || capability.request_object_field_is_verification_omitted(field)
}

fn is_update_verifier(strategy: &str) -> bool {
    matches!(
        strategy,
        "same_resource_contains_planned_fields_after_update"
            | "same_path_result_contains_planned_fields_after_update"
            | "same_path_result_contains_planned_fields_after_mutation"
            | "parent_collection_item_contains_planned_fields_after_update"
    )
}

fn is_create_verifier(strategy: &str) -> bool {
    matches!(
        strategy,
        "created_resource_contains_planned_fields_by_returned_id"
            | "created_access_application_contains_planned_fields_by_returned_id"
            | "parent_collection_contains_created_resource_id_and_planned_fields"
            | "worker_tail_collection_contains_created_lease_id"
            | "parent_object_contains_created_nested_resource_by_correlation"
            | "web_analytics_rule_list_contains_created_id_and_planned_fields"
    )
}

fn is_worker_tail_create_capability(capability: &CapabilityV1) -> bool {
    capability.id == "worker-tail-logs-start-tail"
        && capability.method == "POST"
        && capability.path == "/accounts/{account_id}/workers/scripts/{script_name}/tails"
        && capability.product == "Worker Tail Logs"
        && capability.account_scope == "account"
        && capability.request_schema.is_none()
        && capability.risk == RiskClass::SecretSensitive
        && capability.permissions == ["Workers Tail Read", "Workers Scripts Write"]
        && capability.verification.strategy == "worker_tail_collection_contains_created_lease_id"
}

fn is_delete_verifier(strategy: &str) -> bool {
    matches!(
        strategy,
        "same_resource_returns_not_found_after_delete"
            | "worker_script_settings_returns_not_found_after_delete"
            | "parent_collection_omits_deleted_resource_id"
            | "parent_object_omits_deleted_nested_resource_id"
            | "web_analytics_rule_list_omits_deleted_id"
    )
}

pub fn validate_request_contract(capability: &CapabilityV1, input: &CallInput) -> Result<()> {
    validate_response_contract(capability)?;
    validate_selector_contract(capability, &input.selectors)?;
    validate_query_contract(capability, &input.query)?;
    validate_request_body(capability, input.body.as_ref())?;
    validate_d1_full_export_contract(capability, input)?;
    validate_d1_restore_exact_bookmark_contract(capability, input)?;
    validate_d1_approved_mln_import_contract(capability, input)?;
    validate_d1_schema_introspection_contract(capability, input)?;
    validate_mln_0143_data_invariants_contract(capability, input)?;
    validate_analytics_query_contract(capability, input)?;
    validate_r2_log_retrieval_contract(capability, input)
}

fn mln_0143_request_schema() -> Value {
    let hash = serde_json::json!({
        "type":"string",
        "pattern":"^sha256:[0-9a-f]{64}$",
        "minLength":71,
        "maxLength":71
    });
    serde_json::json!({
        "type":"object",
        "additionalProperties":false,
        "x-cfctl-body-required":true,
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
                "required":["migration_id","phase","pre_import_evidence_hash","import_operation_id","import_boundary_evidence_hash","import_source_sha256","import_plan_hash"],
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
                "required":["migration_id","phase","pre_import_evidence_hash","post_import_evidence_hash","import_operation_id","import_boundary_evidence_hash","import_source_sha256","import_plan_hash","restore_operation_id","restore_evidence_hash","restore_previous_bookmark_hash","restore_requested_bookmark_hash","restore_observed_bookmark_hash"],
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
    })
}

fn validate_mln_0143_data_invariants_contract(
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<()> {
    let Some(contract) = capability.mln_0143_data_invariants.as_ref() else {
        return Ok(());
    };
    let account = input.selectors.get("account_id").and_then(Value::as_str);
    let database = input.selectors.get("database_id").and_then(Value::as_str);
    let supported = capability.id == "mln-0143-data-invariants"
        && capability.method == "POST"
        && capability.path == "/accounts/{account_id}/d1/database/{database_id}/query"
        && capability.product == "D1"
        && capability.account_scope == "account"
        && !capability.mutating
        && capability.risk == RiskClass::Read
        && capability.effect == cfctl_core::EffectClass::ReadOnly
        && capability.adapter_status == AdapterStatus::Native
        && capability.permissions == ["D1 Read"]
        && capability.request_schema.as_ref() == Some(&mln_0143_request_schema())
        && capability.analytics_query.is_none()
        && capability.d1_schema_introspection.is_none()
        && capability.d1_full_export.is_none()
        && capability.d1_restore_exact_bookmark.is_none()
        && capability.r2_log_retrieval.is_none()
        && account == Some(contract.account_id.as_str())
        && database == Some(contract.database_id.as_str())
        && contract.migration_sha256
            == "9b089ead4c284fe92f8a9f81296ac34aa98702585305e36b5c4f345fe774871d"
        && contract.trigger_definition_hashes
            == [
                "sha256:d858df9c22c19df241e5045eca9635c4fb786000428707a821090daeacc69072",
                "sha256:e9205a4863c717c901ec3ac87089555a9af7eac14d5f38fbf40bff775ad8497c",
                "sha256:3ca04f9fc717104d2ee0da719e2c473a756d3345f4e222d52c4d0f76237a184b",
            ]
        && contract.fixed_query_sha256
            == "sha256:25f81a01063e72e59da8b216a08673ec70b887a016ccba5d1a4fd12fd2cfc28d"
        && hash_value(&Value::String(MLN_0143_QUERY.to_owned()))
            .is_ok_and(|hash| hash == contract.fixed_query_sha256)
        && contract.pre_table_definition_hash
            == "sha256:8aa5012ace3d946354e0baba7e645646ac97373b42e7c3d61e79b67a5f689fea"
        && contract.post_table_definition_hash
            == "sha256:2fbdacd011abca8024507b99d179071b8b920271576e4cb3a2f06c4f3ffd2d7f"
        && contract
            .expected_validator_contract_hash()
            .is_ok_and(|hash| hash == contract.validator_contract_hash)
        && contract.capability_version == 3
        && contract.max_evidence_rows == 256
        && contract.probe_rows == 257
        && (1..=1024 * 1024).contains(&contract.max_bytes)
        && (1..=30).contains(&contract.max_timeout_seconds)
        && input
            .query
            .as_object()
            .is_some_and(serde_json::Map::is_empty);
    if !supported {
        return Err(CloudflareError::InvalidAnalyticsQuery(
            "MLN 0143 invariant identity, target, request schema, or safe bounds drifted"
                .to_owned(),
        ));
    }
    render_mln_0143_data_invariants_body(input.body.as_ref().ok_or_else(|| {
        CloudflareError::InvalidAnalyticsQuery("MLN 0143 invariant body is missing".to_owned())
    })?)?;
    Ok(())
}

fn validate_d1_restore_exact_bookmark_contract(
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<()> {
    let Some(contract) = capability.d1_restore_exact_bookmark.as_ref() else {
        return Ok(());
    };
    let body = input.body.as_ref().and_then(Value::as_object);
    let keys = body
        .map(|body| body.keys().map(String::as_str).collect::<BTreeSet<_>>())
        .unwrap_or_default();
    let expected = [
        "expected_current_bookmark",
        "source_evidence_hash",
        "source_operation_id",
        "target_bookmark",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let supported = capability.id == "d1-restore-exact-bookmark"
        && capability.method == "POST"
        && capability.path
            == "/accounts/{account_id}/d1/database/{database_id}/time_travel/restore"
        && capability.product == "D1"
        && capability.account_scope == "account"
        && capability.adapter_status == AdapterStatus::Native
        && d1_restore_selectors_are_pinned(&capability.selectors)
        && capability.mutating
        && capability.risk == RiskClass::Recovery
        && capability.effect == cfctl_core::EffectClass::DataWrite
        && capability.permissions == ["D1 Write"]
        && capability.analytics_query.is_none()
        && capability.d1_schema_introspection.is_none()
        && capability.d1_full_export.is_none()
        && capability.r2_log_retrieval.is_none()
        && (input.query.is_null()
            || input
                .query
                .as_object()
                .is_some_and(serde_json::Map::is_empty))
        && keys == expected
        && contract.bookmark_path
            == "/accounts/{account_id}/d1/database/{database_id}/time_travel/bookmark"
        && contract.restore_path == capability.path
        && (1..=1024 * 1024).contains(&contract.max_response_bytes)
        && (1..=30).contains(&contract.max_timeout_seconds)
        && contract.post_retry_count == 0;
    if !supported {
        return Err(CloudflareError::InvalidRequestBody(
            "D1 exact-bookmark restore identity, closed input, permission, or no-retry bounds drifted"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_d1_approved_mln_import_contract(
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<()> {
    let Some(contract) = capability.d1_approved_mln_import.as_ref() else {
        return Ok(());
    };
    let body = input.body.as_ref().and_then(Value::as_object);
    let migration_id = body
        .and_then(|body| body.get("migration_id"))
        .and_then(Value::as_str);
    let required_common = [
        "migration_id",
        "pre_snapshot_operation_id",
        "pre_snapshot_evidence_hash",
        "pre_export_operation_id",
        "pre_export_evidence_hash",
        "pre_bookmark_operation_id",
        "pre_bookmark_evidence_hash",
    ];
    let required_0143 = [
        "prior_0142_operation_id",
        "prior_0142_boundary_evidence_hash",
        "post_0142_anchor_operation_id",
        "post_0142_anchor_evidence_hash",
        "pre_import_invariant_operation_id",
        "pre_import_invariant_evidence_hash",
    ];
    let keys = body
        .map(|body| body.keys().map(String::as_str).collect::<BTreeSet<_>>())
        .unwrap_or_default();
    let expected = required_common
        .into_iter()
        .chain(
            (migration_id == Some("0143"))
                .then_some(required_0143)
                .into_iter()
                .flatten(),
        )
        .collect::<BTreeSet<_>>();
    let account = input.selectors.get("account_id").and_then(Value::as_str);
    let database = input.selectors.get("database_id").and_then(Value::as_str);
    let supported = capability.id == "d1-import-approved-mln-migration"
        && capability.method == "POST"
        && capability.path == contract.import_path
        && capability.path == "/accounts/{account_id}/d1/database/{database_id}/import"
        && capability.product == "D1"
        && capability.account_scope == "account"
        && capability.adapter_status == AdapterStatus::Native
        && capability.mutating
        && capability.risk == RiskClass::Irreversible
        && capability.effect == cfctl_core::EffectClass::DataWrite
        && capability.permissions == ["D1 Write"]
        && account == Some(contract.account_id.as_str())
        && database == Some(contract.database_id.as_str())
        && migration_id.is_some_and(|id| matches!(id, "0142" | "0143"))
        && keys == expected
        && contract.migrations.len() == 2
        && contract.migrations[0].migration_id == "0142"
        && contract.migrations[0].basename == "0142_document_render_claim_generation.sql"
        && contract.migrations[0].bytes == 1031
        && contract.migrations[0].sha256
            == "07e1c5bd77dd529bfe58f0eee80ad29c40fdd0f3e9c9a37163cfaa0683124af0"
        && contract.migrations[0].md5 == "5dc9f871404bc6aede1dbf8becf881e5"
        && contract.migrations[1].migration_id == "0143"
        && contract.migrations[1].basename == "0143_advisor_final_equity_instrument.sql"
        && contract.migrations[1].bytes == 9736
        && contract.migrations[1].sha256
            == "9b089ead4c284fe92f8a9f81296ac34aa98702585305e36b5c4f345fe774871d"
        && contract.migrations[1].md5 == "bd50b7e05cc13c20f17eb8748472eb4b"
        && contract.requires_create_new_mode_0600_stage
        && contract.upload_url_suffix == ".cloudflare.com"
        && (1..=1024 * 1024).contains(&contract.max_response_bytes)
        && (1..=120).contains(&contract.max_poll_attempts)
        && (1..=30).contains(&contract.max_timeout_seconds)
        && capability.analytics_query.is_none()
        && capability.d1_schema_introspection.is_none()
        && capability.mln_0143_data_invariants.is_none()
        && capability.d1_full_export.is_none()
        && capability.d1_restore_exact_bookmark.is_none()
        && capability.r2_log_retrieval.is_none()
        && input
            .query
            .as_object()
            .is_some_and(serde_json::Map::is_empty);
    if !supported {
        return Err(CloudflareError::InvalidRequestBody(
            "approved MLN import identity, target, closed prerequisites, or bounds drifted"
                .to_owned(),
        ));
    }
    Ok(())
}

fn import_provider_capability(import: &CapabilityV1) -> CapabilityV1 {
    let mut provider = CapabilityV1::new(
        "cfctl-private-d1-import-protocol",
        "Private D1 import protocol",
        "POST",
        &import.path,
    );
    "D1".clone_into(&mut provider.product);
    "account".clone_into(&mut provider.account_scope);
    provider.permissions = vec!["D1 Write".to_owned()];
    provider.selectors.clone_from(&import.selectors);
    provider.request_schema = Some(serde_json::json!({
        "type":"object","additionalProperties":false,"required":["action"],
        "properties":{
            "action":{"type":"string","enum":["init","ingest","poll"]},
            "etag":{"type":"string","pattern":"^[0-9a-f]{32}$"},
            "filename":{"type":"string","minLength":1,"maxLength":512},
            "current_bookmark":{"type":"string","minLength":1,"maxLength":512}
        }
    }));
    provider
        .response_contract
        .clone_from(&import.response_contract);
    provider
}

fn validate_d1_import_upload_url(
    raw: &str,
    contract: &D1ApprovedMlnImportContractV1,
) -> Result<Url> {
    let url = Url::parse(raw)?;
    let host = url.host_str().unwrap_or_default();
    if url.scheme() != "https"
        || url.username() != ""
        || url.password().is_some()
        || url.fragment().is_some()
        || !(host == "cloudflare.com" || host.ends_with(&contract.upload_url_suffix))
    {
        return Err(CloudflareError::InvalidRequestBody(
            "D1 import upload URL is not a credential-free Cloudflare-owned HTTPS URL".to_owned(),
        ));
    }
    Ok(url)
}

fn persist_import_response<F>(
    persist: &mut F,
    plan: &PlanV1,
    step: &str,
    response: &CloudflareResponseV1,
    replacement_result: Option<Value>,
) -> Result<()>
where
    F: FnMut(&D1ImportCheckpointV1) -> std::result::Result<(), String>,
{
    persist(&D1ImportCheckpointV1 {
        schema_version: 1,
        operation_id: plan.operation_id.clone(),
        step: step.to_owned(),
        performed: true,
        rectification_required: !response.success,
        receipt: serde_json::json!({
            "http_status":response.status,
            "success":response.success,
            "result":replacement_result.unwrap_or_else(|| response.result.clone()),
            "errors":response.errors,
            "etag":response.etag,
            "cf_ray":response.cf_ray,
        }),
    })
    .map_err(CloudflareError::InvalidRequestBody)
}

fn persist_import_uncertainty<F>(persist: &mut F, plan: &PlanV1, step: &str) -> Result<()>
where
    F: FnMut(&D1ImportCheckpointV1) -> std::result::Result<(), String>,
{
    persist(&D1ImportCheckpointV1 {
        schema_version: 1,
        operation_id: plan.operation_id.clone(),
        step: step.to_owned(),
        performed: true,
        rectification_required: true,
        receipt: serde_json::json!({
            "outcome":"unknown",
            "receipt_available":false,
            "no_replay":true,
        }),
    })
    .map_err(CloudflareError::InvalidRequestBody)
}

#[cfg(test)]
mod approved_mln_import_tests {
    use super::validate_d1_import_upload_url;
    use cfctl_core::D1ApprovedMlnImportContractV1;

    fn contract() -> D1ApprovedMlnImportContractV1 {
        D1ApprovedMlnImportContractV1 {
            account_id: "ca30e922fda7f5578e49873542e4aaca".to_owned(),
            database_id: "7c282983-2e48-4ea4-9f0d-09b0d718fe65".to_owned(),
            import_path: "/accounts/{account_id}/d1/database/{database_id}/import".to_owned(),
            migrations: Vec::new(),
            max_response_bytes: 1_048_576,
            max_poll_attempts: 120,
            max_timeout_seconds: 300,
            upload_url_suffix: ".cloudflare.com".to_owned(),
            requires_create_new_mode_0600_stage: true,
        }
    }

    #[test]
    fn approved_import_upload_url_is_https_cloudflare_owned_and_has_no_userinfo_or_fragment() {
        let contract = contract();
        assert!(
            validate_d1_import_upload_url(
                "https://upload.cloudflare.com/import?id=opaque",
                &contract
            )
            .is_ok()
        );
        for rejected in [
            "http://upload.cloudflare.com/import",
            "https://attacker.example/import",
            "https://user@upload.cloudflare.com/import",
            "https://upload.cloudflare.com/import#secret",
            "https://cloudflare.com.attacker.example/import",
        ] {
            assert!(
                validate_d1_import_upload_url(rejected, &contract).is_err(),
                "{rejected}"
            );
        }
    }
}

fn d1_restore_selectors_are_pinned(selectors: &[SelectorV1]) -> bool {
    selectors.len() == 2
        && selectors
            .iter()
            .zip([
                (
                    "account_id",
                    serde_json::json!({"type":"string","minLength":32,"maxLength":32}),
                ),
                (
                    "database_id",
                    serde_json::json!({"type":"string","minLength":36,"maxLength":36}),
                ),
            ])
            .all(|(selector, (name, schema))| {
                selector.name == name
                    && selector.location == "path"
                    && selector.required
                    && selector.value_type == "string"
                    && selector.contract.as_ref().is_some_and(|contract| {
                        contract.schema == schema && contract.query.is_none()
                    })
            })
}

fn validate_d1_full_export_contract(capability: &CapabilityV1, input: &CallInput) -> Result<()> {
    let Some(contract) = capability.d1_full_export.as_ref() else {
        return Ok(());
    };
    let supported = capability.id == "d1-full-export"
        && capability.method == "POST"
        && capability.path == "/accounts/{account_id}/d1/database/{database_id}/export"
        && capability.product == "D1"
        && capability.account_scope == "account"
        && capability.adapter_status == AdapterStatus::Native
        && capability.selectors == expected_d1_full_export_selectors()
        && !capability.mutating
        && capability.risk == RiskClass::Read
        && capability.effect == cfctl_core::EffectClass::ReadOnly
        && capability.permissions == ["D1 Read"]
        && capability.analytics_query.is_none()
        && capability.d1_schema_introspection.is_none()
        && capability.r2_log_retrieval.is_none()
        && capability.request_schema.is_none()
        && input.body.is_none()
        && input
            .query
            .as_object()
            .is_some_and(serde_json::Map::is_empty)
        && contract.requires_new_mode_0600_file
        && contract.max_bytes > 0
        && (1..=1024 * 1024).contains(&contract.max_poll_response_bytes)
        && (1..=120).contains(&contract.max_poll_attempts)
        && (1..=30).contains(&contract.max_timeout_seconds)
        && (1..=3600).contains(&contract.max_download_seconds);
    if !supported {
        return Err(CloudflareError::InvalidAnalyticsQuery(
            "D1 full export identity, input closure, permission, or runtime bounds drifted"
                .to_owned(),
        ));
    }
    Ok(())
}

fn expected_d1_full_export_selectors() -> Vec<SelectorV1> {
    ["account_id", "database_id"]
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
        .to_vec()
}

fn validate_d1_export_output_path(output_path: &Path) -> Result<PathBuf> {
    if output_path.file_name().is_none()
        || output_path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::CurDir | Component::Prefix(_)
            )
        })
    {
        return Err(output_path_error(
            output_path,
            "D1 export output must be a normalized file path without traversal",
        ));
    }
    let absolute = if output_path.is_absolute() {
        output_path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|source| CloudflareError::OutputFile {
                path: output_path.display().to_string(),
                source,
            })?
            .join(output_path)
    };
    let file_name = absolute
        .file_name()
        .ok_or_else(|| output_path_error(output_path, "D1 export output must name a file"))?;
    let parent = absolute.parent().ok_or_else(|| {
        output_path_error(
            output_path,
            "D1 export output must have an existing parent directory",
        )
    })?;
    for ancestor in parent.ancestors() {
        let metadata =
            std::fs::symlink_metadata(ancestor).map_err(|source| CloudflareError::OutputFile {
                path: output_path.display().to_string(),
                source,
            })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(output_path_error(
                output_path,
                "D1 export output parent components must be real directories, not symlinks",
            ));
        }
    }
    match std::fs::symlink_metadata(&absolute) {
        Ok(_) => {
            return Err(CloudflareError::OutputFile {
                path: output_path.display().to_string(),
                source: io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "D1 export output must be a new file",
                ),
            });
        }
        Err(source) if source.kind() != io::ErrorKind::NotFound => {
            return Err(CloudflareError::OutputFile {
                path: output_path.display().to_string(),
                source,
            });
        }
        Err(_) => {}
    }
    let canonical_parent =
        std::fs::canonicalize(parent).map_err(|source| CloudflareError::OutputFile {
            path: output_path.display().to_string(),
            source,
        })?;
    Ok(canonical_parent.join(file_name))
}

fn output_path_error(path: &Path, message: &str) -> CloudflareError {
    CloudflareError::OutputFile {
        path: path.display().to_string(),
        source: io::Error::new(io::ErrorKind::InvalidInput, message),
    }
}

struct CreatedOutputGuard {
    path: PathBuf,
    armed: bool,
}

impl CreatedOutputGuard {
    fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }

    fn remove(&mut self) -> io::Result<()> {
        std::fs::remove_file(&self.path)?;
        self.disarm();
        Ok(())
    }
}

impl Drop for CreatedOutputGuard {
    fn drop(&mut self) {
        if self.armed {
            let _cleanup = std::fs::remove_file(&self.path);
        }
    }
}

fn validate_response_contract(capability: &CapabilityV1) -> Result<()> {
    if let Some(response) = capability
        .response_contract
        .as_ref()
        .filter(|response| response.body_mode == ResponseBodyModeV1::Unsupported)
    {
        return Err(CloudflareError::UnsupportedResponseContract(
            response.success_media_types.join(", "),
        ));
    }
    Ok(())
}

fn validate_d1_schema_introspection_contract(
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<()> {
    let Some(contract) = capability.d1_schema_introspection.as_ref() else {
        return Ok(());
    };
    let identity_supported = capability.id == "d1-schema-introspection"
        && capability.method == "POST"
        && capability.path == "/accounts/{account_id}/d1/database/{database_id}/query"
        && capability.product == "D1"
        && capability.account_scope == "account"
        && !capability.mutating
        && capability.risk == RiskClass::Read
        && capability.effect == cfctl_core::EffectClass::ReadOnly
        && capability.adapter_status == cfctl_core::AdapterStatus::Native
        && capability.permissions == ["D1 Read"]
        && capability.analytics_query.is_none()
        && capability.graphql.is_none()
        && capability.r2_log_retrieval.is_none()
        && capability
            .request_schema
            .as_ref()
            .is_some_and(|schema| schema == &d1_schema_introspection_request_schema())
        && capability.selectors.len() == 2
        && ["account_id", "database_id"].iter().all(|name| {
            capability.selectors.iter().any(|selector| {
                selector.name == *name
                    && selector.location == "path"
                    && selector.required
                    && selector.value_type == "string"
            })
        })
        && contract.max_rows == 1
        && (1..=64 * 1024).contains(&contract.max_bytes)
        && (1..=10).contains(&contract.max_timeout_seconds)
        && capability
            .response_contract
            .as_ref()
            .is_some_and(|response| {
                response.success_statuses == ["200"]
                    && response.success_media_types == ["application/json"]
                    && response.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
            });
    if !identity_supported {
        return Err(CloudflareError::InvalidAnalyticsQuery(
            "D1 schema introspection identity, permission, response, or runtime bounds drifted"
                .to_owned(),
        ));
    }
    if input
        .query
        .as_object()
        .is_none_or(|query| !query.is_empty())
    {
        return Err(CloudflareError::InvalidAnalyticsQuery(
            "D1 schema introspection does not accept query controls".to_owned(),
        ));
    }
    render_d1_schema_introspection_body(input.body.as_ref().ok_or_else(|| {
        CloudflareError::InvalidAnalyticsQuery("D1 schema assertion body is missing".to_owned())
    })?)?;
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "one fail-closed validator binds shared bounds and every typed analytics adapter before execution"
)]
fn validate_analytics_query_contract(capability: &CapabilityV1, input: &CallInput) -> Result<()> {
    let Some(contract) = capability.analytics_query.as_ref() else {
        if capability.graphql.is_some() {
            return Err(CloudflareError::InvalidAnalyticsQuery(
                "a GraphQL document must be paired with a bounded analytics query contract"
                    .to_owned(),
            ));
        }
        return Ok(());
    };
    if !contract.read_only || capability.mutating {
        return Err(CloudflareError::InvalidAnalyticsQuery(
            "analytics query capabilities must be explicitly read-only".to_owned(),
        ));
    }
    if contract.max_rows == 0 || contract.max_bytes == 0 || contract.max_timeout_seconds == 0 {
        return Err(CloudflareError::InvalidAnalyticsQuery(
            "row, byte, and timeout bounds must all be positive".to_owned(),
        ));
    }
    let body = input
        .body
        .as_ref()
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CloudflareError::InvalidAnalyticsQuery(
                "bounded analytics input must be an object".to_owned(),
            )
        })?;

    if let Some(pointer) = contract.dataset_pointer.as_deref() {
        let dataset = input
            .body
            .as_ref()
            .and_then(|body| body.pointer(pointer))
            .ok_or_else(|| {
                CloudflareError::InvalidAnalyticsQuery(format!("dataset is missing at `{pointer}`"))
            })?;
        if let Some(expected) = contract.dataset.as_deref() {
            if dataset.as_str() != Some(expected) {
                return Err(CloudflareError::InvalidAnalyticsQuery(format!(
                    "dataset must be the fixed `{expected}` dataset"
                )));
            }
        } else if matches!(
            contract.kind,
            AnalyticsQueryKindV1::StructuredSql | AnalyticsQueryKindV1::LogExplorerSql
        ) && !dataset.as_str().is_some_and(valid_sql_identifier)
        {
            return Err(CloudflareError::InvalidAnalyticsQuery(
                "dataset must be one plain identifier".to_owned(),
            ));
        } else if contract.kind == AnalyticsQueryKindV1::WorkersObservability
            && !dataset_is_bounded(dataset)
        {
            return Err(CloudflareError::InvalidAnalyticsQuery(
                "observability datasets must be a non-empty bounded string or string list"
                    .to_owned(),
            ));
        }
    }

    if let Some(time) = contract.time_range.as_ref() {
        let start = input
            .body
            .as_ref()
            .and_then(|body| body.pointer(&time.start_pointer))
            .ok_or_else(|| {
                CloudflareError::InvalidAnalyticsQuery(format!(
                    "start time is missing at `{}`",
                    time.start_pointer
                ))
            })?;
        let end = input
            .body
            .as_ref()
            .and_then(|body| body.pointer(&time.end_pointer))
            .ok_or_else(|| {
                CloudflareError::InvalidAnalyticsQuery(format!(
                    "end time is missing at `{}`",
                    time.end_pointer
                ))
            })?;
        let start = analytics_timestamp(start, time.timestamp_format)?;
        let end = analytics_timestamp(end, time.timestamp_format)?;
        let now = Utc::now();
        if end <= start {
            return Err(CloudflareError::InvalidAnalyticsQuery(
                "end time must be after start time".to_owned(),
            ));
        }
        let window = (end - start).num_seconds();
        if window > i64::try_from(time.max_window_seconds).unwrap_or(i64::MAX) {
            return Err(CloudflareError::InvalidAnalyticsQuery(format!(
                "time window exceeds the {} second maximum",
                time.max_window_seconds
            )));
        }
        if (now - start).num_seconds()
            > i64::try_from(time.max_lookback_seconds).unwrap_or(i64::MAX)
        {
            return Err(CloudflareError::InvalidAnalyticsQuery(format!(
                "start time exceeds the {} second maximum lookback",
                time.max_lookback_seconds
            )));
        }
        if (end - now).num_seconds() > 300 {
            return Err(CloudflareError::InvalidAnalyticsQuery(
                "end time cannot be more than five minutes in the future".to_owned(),
            ));
        }
    }

    if let Some(pointer) = contract.row_limit_pointer.as_deref() {
        let rows = input
            .body
            .as_ref()
            .and_then(|body| body.pointer(pointer))
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                CloudflareError::InvalidAnalyticsQuery(format!(
                    "row limit is missing or invalid at `{pointer}`"
                ))
            })?;
        if rows == 0 || rows > contract.max_rows {
            return Err(CloudflareError::InvalidAnalyticsQuery(format!(
                "row limit must be between 1 and {}",
                contract.max_rows
            )));
        }
    }
    let output_format = body
        .get("format")
        .and_then(Value::as_str)
        .map(parse_output_format)
        .transpose()?
        .unwrap_or(contract.default_output_format);
    if !contract.allowed_output_formats.contains(&output_format) {
        return Err(CloudflareError::InvalidAnalyticsQuery(
            "requested output format is outside the capability contract".to_owned(),
        ));
    }
    let timeout = body
        .get("timeout_seconds")
        .and_then(Value::as_u64)
        .unwrap_or(contract.max_timeout_seconds);
    if timeout == 0 || timeout > contract.max_timeout_seconds {
        return Err(CloudflareError::InvalidAnalyticsQuery(format!(
            "timeout must be between 1 and {} seconds",
            contract.max_timeout_seconds
        )));
    }

    match contract.kind {
        AnalyticsQueryKindV1::StructuredSql => {
            if !capability.method.eq_ignore_ascii_case("GET")
                || capability.path != "/accounts/{account_id}/analytics_engine/sql"
                || capability.graphql.is_some()
                || capability
                    .selectors
                    .iter()
                    .any(|selector| selector.location == "query" && selector.name == "query")
            {
                return Err(CloudflareError::InvalidAnalyticsQuery(
                    "structured SQL must use the fixed Analytics Engine GET adapter without a raw query selector"
                        .to_owned(),
                ));
            }
            render_structured_analytics_sql(
                input.body.as_ref().ok_or_else(|| {
                    CloudflareError::InvalidAnalyticsQuery(
                        "structured SQL input body is missing".to_owned(),
                    )
                })?,
                output_format,
            )?;
        }
        AnalyticsQueryKindV1::LogExplorerSql => {
            let fixed_path = matches!(
                capability.path.as_str(),
                "/accounts/{account_id}/logs/explorer/query/sql"
                    | "/zones/{zone_id}/logs/explorer/query/sql"
            );
            if !capability.method.eq_ignore_ascii_case("POST")
                || !fixed_path
                || capability.graphql.is_some()
                || output_format != OutputFormatV1::Json
                || capability
                    .selectors
                    .iter()
                    .any(|selector| selector.location == "query" && selector.name == "query")
                || capability
                    .response_contract
                    .as_ref()
                    .is_none_or(|response| {
                        response.body_mode != ResponseBodyModeV1::CloudflareJsonEnvelope
                    })
            {
                return Err(CloudflareError::InvalidAnalyticsQuery(
                    "Log Explorer SQL must use a fixed account or zone POST adapter with a compiler-rendered text body"
                        .to_owned(),
                ));
            }
            render_structured_log_explorer_sql(input.body.as_ref().ok_or_else(|| {
                CloudflareError::InvalidAnalyticsQuery(
                    "structured Log Explorer input body is missing".to_owned(),
                )
            })?)?;
        }
        AnalyticsQueryKindV1::GraphqlAnalytics => {
            if !capability.method.eq_ignore_ascii_case("POST")
                || capability.path != "/graphql"
                || output_format != OutputFormatV1::Json
                || capability
                    .response_contract
                    .as_ref()
                    .is_none_or(|response| response.body_mode != ResponseBodyModeV1::GraphqlJson)
            {
                return Err(CloudflareError::InvalidAnalyticsQuery(
                    "GraphQL analytics must use the fixed POST /graphql JSON adapter".to_owned(),
                ));
            }
            let graphql = capability.graphql.as_ref().ok_or_else(|| {
                CloudflareError::InvalidAnalyticsQuery(
                    "GraphQL analytics is missing its fixed document contract".to_owned(),
                )
            })?;
            graphql.validate_schema_fingerprint()?;
            let document = graphql.document.trim_start();
            if !document.starts_with("query ")
                || document.contains("mutation ")
                || document.contains("subscription ")
                || graphql.dataset != contract.dataset.as_deref().unwrap_or_default()
            {
                return Err(CloudflareError::InvalidAnalyticsQuery(
                    "only the fingerprinted read-only GraphQL query document is permitted"
                        .to_owned(),
                ));
            }
            validate_graphql_pagination_contract(contract, graphql, input)?;
        }
        AnalyticsQueryKindV1::WorkersObservability => {
            if !capability.method.eq_ignore_ascii_case("POST") || capability.graphql.is_some() {
                return Err(CloudflareError::InvalidAnalyticsQuery(
                    "Workers observability reads must use their fixed POST query adapter"
                        .to_owned(),
                ));
            }
        }
    }
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "the private retrieval validator binds capability identity, selectors, media, time, byte, and timeout limits together"
)]
fn validate_r2_log_retrieval_contract(capability: &CapabilityV1, input: &CallInput) -> Result<()> {
    let Some(contract) = capability.r2_log_retrieval.as_ref() else {
        return Ok(());
    };
    let identity_supported = capability.id == "logpull-retrieve-logs"
        && capability.method == "GET"
        && capability.path == "/accounts/{account_id}/logs/retrieve"
        && capability.product == "Logpull"
        && capability.account_scope == "account"
        && !capability.mutating
        && capability.permissions == ["Logs Read"]
        && capability.analytics_query.is_none()
        && capability.graphql.is_none()
        && capability.request_schema.is_none()
        && capability
            .selectors
            .iter()
            .all(|selector| selector.location != "header")
        && contract.access_key_input_field == "access_key_id"
        && contract.secret_access_key_input_field == "secret_access_key"
        && contract
            .access_key_header
            .eq_ignore_ascii_case("R2-Access-Key-Id")
        && contract
            .secret_access_key_header
            .eq_ignore_ascii_case("R2-Secret-Access-Key")
        && contract.start_query_selector == "start"
        && contract.end_query_selector == "end"
        && contract.bucket_query_selector == "bucket"
        && contract.prefix_query_selector == "prefix"
        && contract.requires_new_mode_0600_file
        && contract.max_lookback_seconds > 0
        && contract.max_window_seconds > 0
        && contract.max_window_seconds <= 24 * 60 * 60
        && contract.max_bytes > 0
        && contract.max_bytes <= 1024 * 1024 * 1024
        && contract.max_timeout_seconds > 0
        && contract.max_timeout_seconds <= 300
        && contract.output_media_types == ["application/json"]
        && capability
            .response_contract
            .as_ref()
            .is_some_and(|response| {
                response.success_statuses == ["200"]
                    && response.success_media_types == ["application/json"]
                    && response.body_mode == ResponseBodyModeV1::JsonValue
            });
    if !identity_supported {
        return Err(CloudflareError::InvalidR2LogRetrieval(
            "catalog identity or credential, range, output, permission, and response bounds drifted"
                .to_owned(),
        ));
    }
    if input.body.is_some() {
        return Err(CloudflareError::InvalidR2LogRetrieval(
            "retrieval accepts selectors and query controls only, not a request body".to_owned(),
        ));
    }
    let query = input.query.as_object().ok_or_else(|| {
        CloudflareError::InvalidR2LogRetrieval("query controls must be an object".to_owned())
    })?;
    let query_string = |name: &str| -> Result<&str> {
        query.get(name).and_then(Value::as_str).ok_or_else(|| {
            CloudflareError::InvalidR2LogRetrieval(format!(
                "required query control `{name}` must be a string"
            ))
        })
    };
    let start_text = query_string(&contract.start_query_selector)?;
    let end_text = query_string(&contract.end_query_selector)?;
    let start = DateTime::parse_from_rfc3339(start_text)
        .map_err(|_| {
            CloudflareError::InvalidR2LogRetrieval("start must be an RFC3339 timestamp".to_owned())
        })?
        .with_timezone(&Utc);
    let end = DateTime::parse_from_rfc3339(end_text)
        .map_err(|_| {
            CloudflareError::InvalidR2LogRetrieval("end must be an RFC3339 timestamp".to_owned())
        })?
        .with_timezone(&Utc);
    let now = Utc::now();
    if end <= start {
        return Err(CloudflareError::InvalidR2LogRetrieval(
            "end time must be after start time".to_owned(),
        ));
    }
    if (end - start).num_seconds() > i64::try_from(contract.max_window_seconds).unwrap_or(i64::MAX)
    {
        return Err(CloudflareError::InvalidR2LogRetrieval(format!(
            "time window exceeds the {} second maximum",
            contract.max_window_seconds
        )));
    }
    if (now - start).num_seconds()
        > i64::try_from(contract.max_lookback_seconds).unwrap_or(i64::MAX)
    {
        return Err(CloudflareError::InvalidR2LogRetrieval(format!(
            "start time exceeds the {} second maximum lookback",
            contract.max_lookback_seconds
        )));
    }
    if (end - now).num_seconds() > 300 {
        return Err(CloudflareError::InvalidR2LogRetrieval(
            "end time cannot be more than five minutes in the future".to_owned(),
        ));
    }
    let bucket = query_string(&contract.bucket_query_selector)?;
    if !valid_r2_bucket_name(bucket) {
        return Err(CloudflareError::InvalidR2LogRetrieval(
            "bucket must be a 3-63 character lowercase R2 bucket name".to_owned(),
        ));
    }
    if let Some(prefix) = query
        .get(&contract.prefix_query_selector)
        .and_then(Value::as_str)
        && (prefix.is_empty() || prefix.len() > 1024 || prefix.chars().any(char::is_control))
    {
        return Err(CloudflareError::InvalidR2LogRetrieval(
            "prefix must be a non-empty control-free value of at most 1024 bytes".to_owned(),
        ));
    }
    Ok(())
}

fn valid_r2_bucket_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    (3..=63).contains(&bytes.len())
        && bytes
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn top_level_cursor_input_field(pointer: &str) -> Result<&str> {
    let field = pointer
        .strip_prefix('/')
        .filter(|field| !field.is_empty() && !field.contains('/') && !field.contains('~'));
    field.ok_or_else(|| {
        CloudflareError::InvalidAnalyticsQuery(
            "GraphQL cursor inputs must be unescaped top-level body pointers".to_owned(),
        )
    })
}

fn graphql_cursor_bindings(graphql: &GraphqlAnalyticsContractV1) -> Result<Vec<(&str, &str)>> {
    if graphql.cursor_fields.is_empty() {
        return Err(CloudflareError::InvalidAnalyticsQuery(
            "ordered-keyset GraphQL pagination requires response cursor fields".to_owned(),
        ));
    }
    if graphql.cursor_input_pointers.is_empty() {
        if graphql.cursor_fields.len() != 1 {
            return Err(CloudflareError::InvalidAnalyticsQuery(
                "a multi-field GraphQL cursor requires one pinned input pointer per response field"
                    .to_owned(),
            ));
        }
        let pointer = graphql.cursor_input_pointer.as_deref().ok_or_else(|| {
            CloudflareError::InvalidAnalyticsQuery(
                "ordered-keyset GraphQL pagination requires a pinned cursor input".to_owned(),
            )
        })?;
        top_level_cursor_input_field(pointer)?;
        return Ok(vec![(graphql.cursor_fields[0].as_str(), pointer)]);
    }
    if graphql.cursor_input_pointer.is_some()
        || graphql.cursor_input_pointers.len() != graphql.cursor_fields.len()
    {
        return Err(CloudflareError::InvalidAnalyticsQuery(
            "GraphQL cursor bindings must map every response field exactly once".to_owned(),
        ));
    }
    let mut pointers = BTreeSet::new();
    graphql
        .cursor_fields
        .iter()
        .map(|field| {
            let pointer = graphql.cursor_input_pointers.get(field).ok_or_else(|| {
                CloudflareError::InvalidAnalyticsQuery(format!(
                    "GraphQL cursor field `{field}` has no pinned body input"
                ))
            })?;
            top_level_cursor_input_field(pointer)?;
            if !pointers.insert(pointer.as_str()) {
                return Err(CloudflareError::InvalidAnalyticsQuery(
                    "GraphQL cursor input pointers must be unique".to_owned(),
                ));
            }
            Ok((field.as_str(), pointer.as_str()))
        })
        .collect()
}

fn validate_graphql_pagination_contract(
    query: &AnalyticsQueryContractV1,
    graphql: &GraphqlAnalyticsContractV1,
    input: &CallInput,
) -> Result<()> {
    if query.pagination != PaginationModeV1::OrderedKeyset {
        if graphql.cursor_input_pointer.is_some()
            || !graphql.cursor_input_pointers.is_empty()
            || !graphql.cursor_fields.is_empty()
        {
            return Err(CloudflareError::InvalidAnalyticsQuery(
                "GraphQL cursor fields and inputs are only valid for ordered-keyset pagination"
                    .to_owned(),
            ));
        }
        return Ok(());
    }
    let bindings = graphql_cursor_bindings(graphql)?;
    let time = query.time_range.as_ref().ok_or_else(|| {
        CloudflareError::InvalidAnalyticsQuery(
            "ordered-keyset GraphQL pagination requires a bounded time range".to_owned(),
        )
    })?;
    let body = input.body.as_ref().ok_or_else(|| {
        CloudflareError::InvalidAnalyticsQuery("GraphQL input body is missing".to_owned())
    })?;
    let start = body.pointer(&time.start_pointer).ok_or_else(|| {
        CloudflareError::InvalidAnalyticsQuery("GraphQL start time is missing".to_owned())
    })?;
    let end = body.pointer(&time.end_pointer).ok_or_else(|| {
        CloudflareError::InvalidAnalyticsQuery("GraphQL end time is missing".to_owned())
    })?;
    for (_, pointer) in &bindings {
        let input_field = top_level_cursor_input_field(pointer)?;
        if body.pointer(pointer).is_none() {
            return Err(CloudflareError::InvalidAnalyticsQuery(format!(
                "GraphQL continuation cursor is missing at `{pointer}`"
            )));
        }
        if graphql
            .body_variables
            .get(input_field)
            .is_none_or(|variable| !graphql.document.contains(&format!("${variable}")))
        {
            return Err(CloudflareError::InvalidAnalyticsQuery(format!(
                "GraphQL cursor input `{pointer}` is not bound by the fixed document"
            )));
        }
    }
    let time_cursor_pointer = bindings
        .first()
        .map(|(_, pointer)| *pointer)
        .ok_or_else(|| {
            CloudflareError::InvalidAnalyticsQuery(
                "GraphQL continuation has no time cursor binding".to_owned(),
            )
        })?;
    let cursor = body.pointer(time_cursor_pointer).ok_or_else(|| {
        CloudflareError::InvalidAnalyticsQuery(
            "GraphQL continuation time cursor is missing".to_owned(),
        )
    })?;
    let start = analytics_timestamp(start, time.timestamp_format)?;
    let end = analytics_timestamp(end, time.timestamp_format)?;
    let cursor = analytics_timestamp(cursor, time.timestamp_format)?;
    if cursor < start || cursor >= end {
        return Err(CloudflareError::InvalidAnalyticsQuery(
            "GraphQL continuation cursor must be within the requested time range".to_owned(),
        ));
    }
    Ok(())
}

fn dataset_is_bounded(value: &Value) -> bool {
    value.as_str().is_some_and(|value| !value.is_empty())
        || value.as_array().is_some_and(|values| {
            !values.is_empty()
                && values.len() <= 20
                && values
                    .iter()
                    .all(|value| value.as_str().is_some_and(|value| !value.is_empty()))
        })
}

fn analytics_timestamp(value: &Value, format: TimestampFormatV1) -> Result<DateTime<Utc>> {
    match format {
        TimestampFormatV1::Rfc3339 => value
            .as_str()
            .ok_or_else(|| {
                CloudflareError::InvalidAnalyticsQuery(
                    "time values must use RFC 3339 strings".to_owned(),
                )
            })?
            .parse::<DateTime<Utc>>()
            .map_err(|_| {
                CloudflareError::InvalidAnalyticsQuery(
                    "time values must be valid RFC 3339 timestamps".to_owned(),
                )
            }),
        TimestampFormatV1::UnixSeconds | TimestampFormatV1::UnixMilliseconds => {
            let value = value.as_i64().ok_or_else(|| {
                CloudflareError::InvalidAnalyticsQuery(
                    "time values must be signed Unix timestamps".to_owned(),
                )
            })?;
            let (seconds, nanos) = if format == TimestampFormatV1::UnixMilliseconds {
                (
                    value.div_euclid(1_000),
                    u32::try_from(value.rem_euclid(1_000)).unwrap_or_default() * 1_000_000,
                )
            } else {
                (value, 0)
            };
            DateTime::from_timestamp(seconds, nanos).ok_or_else(|| {
                CloudflareError::InvalidAnalyticsQuery("time value is out of range".to_owned())
            })
        }
    }
}

fn validate_selector_contract(capability: &CapabilityV1, selectors: &Value) -> Result<()> {
    let values = match selectors {
        Value::Null => None,
        Value::Object(values) => Some(values),
        _ => return Err(CloudflareError::InvalidSelectorObject),
    };
    if let Some(values) = values {
        for (name, value) in values {
            let selector = capability
                .selectors
                .iter()
                .find(|selector| selector.location != "query" && selector.name == *name);
            let Some(selector) = selector else {
                if path_declares_selector(&capability.path, name) {
                    if scalar(value).is_none() {
                        return Err(CloudflareError::InvalidSelector(name.clone()));
                    }
                    continue;
                }
                return Err(CloudflareError::UndeclaredSelector(name.clone()));
            };
            if selector.location == "header" && request_header_is_reserved(name) {
                return Err(CloudflareError::ReservedHeaderSelector(name.clone()));
            }
            if scalar(value).is_none() {
                return Err(CloudflareError::InvalidSelector(name.clone()));
            }
            let schema = selector.contract.as_ref().map(|contract| &contract.schema);
            let Some(canonical) =
                canonical_selector_value_for_schema(value, &selector.value_type, schema)
            else {
                return Err(CloudflareError::InvalidSelector(name.clone()));
            };
            if let Some(schema) = schema {
                validate_request_schema_value(schema, &canonical, "", 0).map_err(|error| {
                    let reason = match error {
                        CloudflareError::InvalidRequestBody(reason) => reason,
                        other => other.to_string(),
                    };
                    CloudflareError::InvalidSelectorSchema {
                        name: name.clone(),
                        reason,
                    }
                })?;
            }
        }
    }
    for selector in capability
        .selectors
        .iter()
        .filter(|selector| selector.location != "query" && selector.required)
    {
        if values.is_none_or(|values| !values.contains_key(&selector.name)) {
            return if selector.location == "header" {
                Err(CloudflareError::MissingHeaderSelector(
                    selector.name.clone(),
                ))
            } else {
                Err(CloudflareError::MissingSelector(selector.name.clone()))
            };
        }
    }
    for name in path_selector_names(&capability.path) {
        if values.is_none_or(|values| !values.contains_key(name)) {
            return Err(CloudflareError::MissingSelector(name.to_owned()));
        }
    }
    Ok(())
}

fn path_selector_names(path: &str) -> impl Iterator<Item = &str> {
    path.trim_start_matches('/')
        .split('/')
        .filter_map(|segment| {
            segment
                .strip_prefix('{')
                .and_then(|segment| segment.strip_suffix('}'))
        })
}

fn path_declares_selector(path: &str, name: &str) -> bool {
    path_selector_names(path).any(|selector| selector == name)
}

fn validate_query_contract(capability: &CapabilityV1, query: &Value) -> Result<()> {
    let values = match query {
        Value::Null => None,
        Value::Object(values) => Some(values),
        _ => return Err(CloudflareError::InvalidQueryObject),
    };
    if let Some(values) = values {
        for (name, value) in values {
            let selector = capability
                .selectors
                .iter()
                .find(|selector| selector.location == "query" && selector.name == *name)
                .ok_or_else(|| CloudflareError::UndeclaredQuerySelector(name.clone()))?;
            let (_, allow_empty) = validated_query_serialization(selector)?;
            if query_value_is_empty(value) && allow_empty {
                continue;
            }
            let Some(canonical) = canonical_query_value(value, &selector.value_type, selector)
            else {
                return Err(CloudflareError::InvalidQuerySelector {
                    name: name.clone(),
                    expected: selector.value_type.clone(),
                });
            };
            if let Some(schema) = selector.contract.as_ref().map(|contract| &contract.schema) {
                validate_request_schema_value(schema, &canonical, "", 0).map_err(|error| {
                    let reason = match error {
                        CloudflareError::InvalidRequestBody(reason) => reason,
                        other => other.to_string(),
                    };
                    CloudflareError::InvalidQuerySelectorSchema {
                        name: name.clone(),
                        reason,
                    }
                })?;
            }
        }
    }
    for selector in capability
        .selectors
        .iter()
        .filter(|selector| selector.location == "query" && selector.required)
    {
        if values.is_none_or(|values| !values.contains_key(&selector.name)) {
            return Err(CloudflareError::MissingQuerySelector(selector.name.clone()));
        }
    }
    Ok(())
}

fn validated_query_serialization(selector: &SelectorV1) -> Result<(bool, bool)> {
    let query = selector
        .contract
        .as_ref()
        .and_then(|contract| contract.query.as_ref());
    let style = query.map_or("form", |query| query.style.as_str());
    if style != "form" {
        return Err(CloudflareError::UnsupportedQuerySerialization {
            name: selector.name.clone(),
            reason: format!("style `{style}` is not implemented"),
        });
    }
    if query.is_some_and(|query| query.allow_reserved) {
        return Err(CloudflareError::UnsupportedQuerySerialization {
            name: selector.name.clone(),
            reason: "allowReserved=true cannot be encoded by the governed URL builder".to_owned(),
        });
    }
    Ok((
        query.is_none_or(|query| query.explode),
        query.is_some_and(|query| query.allow_empty_value),
    ))
}

fn query_value_is_empty(value: &Value) -> bool {
    value.as_str() == Some("") || value.as_array().is_some_and(Vec::is_empty)
}

fn canonical_query_value(value: &Value, expected: &str, selector: &SelectorV1) -> Option<Value> {
    let schema = selector.contract.as_ref().map(|contract| &contract.schema);
    canonical_selector_value_for_schema(value, expected, schema)
}

fn canonical_selector_value_for_schema(
    value: &Value,
    expected: &str,
    schema: Option<&Value>,
) -> Option<Value> {
    match expected {
        "string" => value.as_str().map(|value| Value::String(value.to_owned())),
        "boolean" => value.as_bool().map(Value::Bool).or_else(|| {
            value.as_str().and_then(|value| match value {
                "true" => Some(Value::Bool(true)),
                "false" => Some(Value::Bool(false)),
                _ => None,
            })
        }),
        "integer" => value
            .as_i64()
            .map(serde_json::Number::from)
            .or_else(|| value.as_u64().map(serde_json::Number::from))
            .or_else(|| {
                value.as_str().and_then(|value| {
                    value
                        .parse::<i64>()
                        .map(serde_json::Number::from)
                        .or_else(|_| value.parse::<u64>().map(serde_json::Number::from))
                        .ok()
                })
            })
            .map(Value::Number),
        "number" => value.as_number().cloned().map(Value::Number).or_else(|| {
            value
                .as_str()
                .and_then(|value| serde_json::from_str::<Value>(value).ok())
                .filter(Value::is_number)
        }),
        "array" => {
            let values = value.as_array()?;
            if values.is_empty() {
                return None;
            }
            let item_schema = schema.and_then(|schema| schema.get("items"));
            let item_type = item_schema.and_then(schema_value_type).unwrap_or("unknown");
            if matches!(item_type, "array" | "object") {
                return None;
            }
            values
                .iter()
                .map(|value| canonical_selector_value_for_schema(value, item_type, item_schema))
                .collect::<Option<Vec<_>>>()
                .map(Value::Array)
        }
        "unknown" => scalar(value).map(|_| value.clone()),
        _ => None,
    }
}

fn schema_value_type(schema: &Value) -> Option<&str> {
    schema.get("type").and_then(Value::as_str).or_else(|| {
        let values = schema.get("enum")?.as_array()?;
        let first = values.first()?;
        let value_type = json_value_type(first)?;
        values
            .iter()
            .all(|value| json_value_type(value) == Some(value_type))
            .then_some(value_type)
    })
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

fn validate_request_body(capability: &CapabilityV1, body: Option<&Value>) -> Result<()> {
    let Some(schema) = capability.request_schema.as_ref() else {
        return Ok(());
    };
    if body.is_none()
        && schema
            .get("x-cfctl-body-required")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    {
        return Err(CloudflareError::MissingRequestBody(capability.id.clone()));
    }
    let Some(body) = body else {
        return Ok(());
    };
    validate_request_schema_value(schema, body, "", 0)
}

const MAX_REQUEST_VALIDATION_DEPTH: usize = 64;

fn validate_request_schema_value(
    schema: &Value,
    value: &Value,
    path: &str,
    depth: usize,
) -> Result<()> {
    let mut remaining_steps = MAX_REQUEST_VALIDATION_STEPS;
    validate_request_schema_value_inner(
        schema,
        value,
        path,
        depth,
        &mut remaining_steps,
        &BTreeSet::new(),
    )
}

const MAX_REQUEST_VALIDATION_STEPS: usize = 65_536;
const REQUEST_VALIDATION_DEPTH_LIMIT_REASON: &str =
    "pinned schema exceeds the validation depth limit";
const REQUEST_VALIDATION_WORK_LIMIT_REASON: &str =
    "request body exceeds the pinned validation work limit";

fn validate_request_schema_value_inner(
    schema: &Value,
    value: &Value,
    path: &str,
    depth: usize,
    remaining_steps: &mut usize,
    inherited_object_properties: &BTreeSet<String>,
) -> Result<()> {
    if depth > MAX_REQUEST_VALIDATION_DEPTH {
        return Err(CloudflareError::InvalidRequestBody(
            REQUEST_VALIDATION_DEPTH_LIMIT_REASON.to_owned(),
        ));
    }
    let Some(next_steps) = remaining_steps.checked_sub(1) else {
        return Err(CloudflareError::InvalidRequestBody(
            REQUEST_VALIDATION_WORK_LIMIT_REASON.to_owned(),
        ));
    };
    *remaining_steps = next_steps;
    if value.is_null()
        && (schema.get("nullable").and_then(Value::as_bool) == Some(true)
            || schema
                .get("enum")
                .and_then(Value::as_array)
                .is_some_and(|values| values.contains(value)))
    {
        return Ok(());
    }
    if let Some(expected) = schema.get("type").and_then(Value::as_str)
        && !json_type_matches(value, expected)
    {
        let reason = if path.is_empty() {
            format!("expected top-level {expected}")
        } else {
            format!("property `{path}` must be {expected}")
        };
        return Err(CloudflareError::InvalidRequestBody(reason));
    }
    if schema
        .get("enum")
        .and_then(Value::as_array)
        .is_some_and(|values| !values.contains(value))
    {
        let location = if path.is_empty() {
            "top-level value".to_owned()
        } else {
            format!("property `{path}`")
        };
        return Err(CloudflareError::InvalidRequestBody(format!(
            "{location} is not one of the pinned enum values"
        )));
    }
    validate_request_schema_bounds(schema, value, path, depth, remaining_steps)?;
    if let Some(object) = value.as_object() {
        let mut allowed_properties = inherited_object_properties.clone();
        collect_composed_property_names(schema, &mut allowed_properties, 0);
        validate_request_object(
            schema,
            object,
            path,
            depth,
            remaining_steps,
            &allowed_properties,
        )?;
    }
    if let Some(array) = value.as_array()
        && let Some(items) = schema.get("items")
    {
        for item in array {
            validate_request_schema_value_inner(
                items,
                item,
                path,
                depth + 1,
                remaining_steps,
                &BTreeSet::new(),
            )?;
        }
    }
    validate_schema_composition(
        schema,
        value,
        path,
        depth,
        remaining_steps,
        inherited_object_properties,
    )?;
    Ok(())
}

fn validate_request_schema_bounds(
    schema: &Value,
    value: &Value,
    path: &str,
    depth: usize,
    remaining_steps: &mut usize,
) -> Result<()> {
    if let Some(multiple) = schema.get("multipleOf")
        && let Some(number) = value.as_number()
    {
        let valid = multiple
            .as_number()
            .and_then(|multiple| exact_decimal_multiple(number, multiple))
            .unwrap_or(false);
        if !valid {
            return invalid_request_bound(path, "is not a multiple of the pinned multipleOf value");
        }
    }
    if let Some(number) = value.as_f64() {
        if let Some(minimum) = schema.get("minimum").and_then(Value::as_f64) {
            let exclusive = schema
                .get("exclusiveMinimum")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if number < minimum || (exclusive && number <= minimum) {
                return invalid_request_bound(
                    path,
                    if exclusive {
                        "must be above the pinned minimum"
                    } else {
                        "is below the pinned minimum"
                    },
                );
            }
        }
        if let Some(maximum) = schema.get("maximum").and_then(Value::as_f64) {
            let exclusive = schema
                .get("exclusiveMaximum")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if number > maximum || (exclusive && number >= maximum) {
                return invalid_request_bound(
                    path,
                    if exclusive {
                        "must be below the pinned maximum"
                    } else {
                        "is above the pinned maximum"
                    },
                );
            }
        }
    }
    if let Some(text) = value.as_str() {
        let length = usize_as_u64(text.chars().count());
        validate_length_bounds(schema, path, length, "characters", "minLength", "maxLength")?;
        validate_string_format(schema, text, path)?;
    }
    if let Some(array) = value.as_array() {
        validate_length_bounds(
            schema,
            path,
            usize_as_u64(array.len()),
            "items",
            "minItems",
            "maxItems",
        )?;
        if schema.get("uniqueItems").and_then(Value::as_bool) == Some(true) {
            let mut items = BTreeSet::new();
            for item in array {
                let encoded = schema_equality_key(item, depth + 1, remaining_steps)?;
                if !items.insert(encoded) {
                    return invalid_request_bound(
                        path,
                        "contains duplicate items disallowed by the pinned schema",
                    );
                }
            }
        }
    }
    if let Some(object) = value.as_object() {
        validate_length_bounds(
            schema,
            path,
            usize_as_u64(object.len()),
            "properties",
            "minProperties",
            "maxProperties",
        )?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct DecimalMagnitude {
    coefficient: u128,
    exponent: i32,
}

fn exact_decimal_multiple(
    number: &serde_json::Number,
    multiple: &serde_json::Number,
) -> Option<bool> {
    let value = decimal_magnitude(number)?;
    let divisor = decimal_magnitude(multiple)?;
    if divisor.coefficient == 0 || multiple.to_string().starts_with('-') {
        return None;
    }
    if value.coefficient == 0 {
        return Some(true);
    }

    let common = greatest_common_divisor(value.coefficient, divisor.coefficient);
    let numerator = value.coefficient / common;
    let denominator = divisor.coefficient / common;
    let exponent_difference = value.exponent.checked_sub(divisor.exponent)?;
    if exponent_difference >= 0 {
        let available_tens = u32::try_from(exponent_difference).ok()?;
        let (denominator, twos) = remove_factor(denominator, 2);
        let (denominator, fives) = remove_factor(denominator, 5);
        return Some(denominator == 1 && twos <= available_tens && fives <= available_tens);
    }

    let required_tens = exponent_difference.unsigned_abs();
    let (_, twos) = remove_factor(numerator, 2);
    let (_, fives) = remove_factor(numerator, 5);
    Some(twos >= required_tens && fives >= required_tens)
}

fn decimal_magnitude(number: &serde_json::Number) -> Option<DecimalMagnitude> {
    let rendered = number.to_string();
    let unsigned = rendered
        .strip_prefix('-')
        .or_else(|| rendered.strip_prefix('+'))
        .unwrap_or(&rendered);
    let (mantissa, explicit_exponent) =
        if let Some((mantissa, exponent)) = unsigned.split_once(['e', 'E']) {
            (mantissa, exponent.parse::<i32>().ok()?)
        } else {
            (unsigned, 0)
        };
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let mut digits = String::with_capacity(whole.len() + fraction.len());
    digits.push_str(whole);
    digits.push_str(fraction);
    let mut coefficient = digits.parse::<u128>().ok()?;
    let fractional_digits = i32::try_from(fraction.len()).ok()?;
    let mut exponent = explicit_exponent.checked_sub(fractional_digits)?;
    if coefficient == 0 {
        return Some(DecimalMagnitude {
            coefficient,
            exponent: 0,
        });
    }
    while coefficient.is_multiple_of(10) {
        coefficient /= 10;
        exponent = exponent.checked_add(1)?;
    }
    Some(DecimalMagnitude {
        coefficient,
        exponent,
    })
}

fn greatest_common_divisor(mut left: u128, mut right: u128) -> u128 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

fn remove_factor(mut value: u128, factor: u128) -> (u128, u32) {
    let mut count = 0_u32;
    while value.is_multiple_of(factor) {
        value /= factor;
        count = count.saturating_add(1);
    }
    (value, count)
}

fn validate_string_format(schema: &Value, value: &str, path: &str) -> Result<()> {
    let Some(format) = schema.get("format").and_then(Value::as_str) else {
        return Ok(());
    };
    let valid = match format {
        "date-time" => DateTime::parse_from_rfc3339(value).is_ok(),
        "hostname" => is_valid_hostname(value),
        "ipv4" => value.parse::<Ipv4Addr>().is_ok(),
        "ipv6" => value.parse::<Ipv6Addr>().is_ok(),
        _ => true,
    };
    if valid {
        return Ok(());
    }
    invalid_request_bound(path, &format!("does not match the pinned {format} format"))
}

fn is_valid_hostname(value: &str) -> bool {
    if value == "." {
        return true;
    }
    let hostname = value.strip_suffix('.').unwrap_or(value);
    !hostname.is_empty()
        && hostname.len() <= 253
        && hostname.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

fn validate_length_bounds(
    schema: &Value,
    path: &str,
    length: u64,
    units: &str,
    minimum_key: &str,
    maximum_key: &str,
) -> Result<()> {
    if schema
        .get(minimum_key)
        .and_then(Value::as_u64)
        .is_some_and(|minimum| length < minimum)
    {
        return invalid_request_bound(
            path,
            &format!("has fewer {units} than the pinned {minimum_key}"),
        );
    }
    if schema
        .get(maximum_key)
        .and_then(Value::as_u64)
        .is_some_and(|maximum| length > maximum)
    {
        return invalid_request_bound(
            path,
            &format!("has more {units} than the pinned {maximum_key}"),
        );
    }
    Ok(())
}

fn usize_as_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn invalid_request_bound(path: &str, reason: &str) -> Result<()> {
    Err(CloudflareError::InvalidRequestBody(format!(
        "{} {reason}",
        request_schema_location(path)
    )))
}

fn schema_equality_key(value: &Value, depth: usize, remaining_steps: &mut usize) -> Result<String> {
    let mut key = String::new();
    append_schema_equality_key(value, &mut key, depth, remaining_steps)?;
    Ok(key)
}

fn append_schema_equality_key(
    value: &Value,
    key: &mut String,
    depth: usize,
    remaining_steps: &mut usize,
) -> Result<()> {
    if depth > MAX_REQUEST_VALIDATION_DEPTH {
        return Err(CloudflareError::InvalidRequestBody(
            REQUEST_VALIDATION_DEPTH_LIMIT_REASON.to_owned(),
        ));
    }
    let Some(next_steps) = remaining_steps.checked_sub(1) else {
        return Err(CloudflareError::InvalidRequestBody(
            REQUEST_VALIDATION_WORK_LIMIT_REASON.to_owned(),
        ));
    };
    *remaining_steps = next_steps;
    match value {
        Value::Null => key.push('z'),
        Value::Bool(value) => key.push_str(if *value { "b1" } else { "b0" }),
        Value::Number(value) => {
            key.push('n');
            key.push_str(&schema_number_equality_key(value));
            key.push(';');
        }
        Value::String(value) => append_length_prefixed_string('s', value, key),
        Value::Array(values) => {
            key.push('[');
            for value in values {
                append_schema_equality_key(value, key, depth + 1, remaining_steps)?;
            }
            key.push(']');
        }
        Value::Object(values) => {
            key.push('{');
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_unstable_by_key(|(left, _)| *left);
            for (name, value) in entries {
                append_length_prefixed_string('k', name, key);
                append_schema_equality_key(value, key, depth + 1, remaining_steps)?;
            }
            key.push('}');
        }
    }
    Ok(())
}

fn append_length_prefixed_string(prefix: char, value: &str, key: &mut String) {
    key.push(prefix);
    key.push_str(&value.len().to_string());
    key.push(':');
    key.push_str(value);
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::float_cmp
)]
fn schema_number_equality_key(number: &serde_json::Number) -> String {
    if let Some(value) = number.as_i64() {
        return value.to_string();
    }
    if let Some(value) = number.as_u64() {
        return value.to_string();
    }
    let Some(value) = number.as_f64() else {
        return number.to_string();
    };
    if value == 0.0 {
        return "0".to_owned();
    }
    if value.fract() == 0.0 {
        if (-9_223_372_036_854_775_808.0..0.0).contains(&value) {
            let integer = value as i64;
            if integer as f64 == value {
                return integer.to_string();
            }
        }
        if (0.0..18_446_744_073_709_551_616.0).contains(&value) {
            let integer = value as u64;
            if integer as f64 == value {
                return integer.to_string();
            }
        }
    }
    format!("f{:016x}", value.to_bits())
}

fn validate_schema_composition(
    schema: &Value,
    value: &Value,
    path: &str,
    depth: usize,
    remaining_steps: &mut usize,
    inherited_object_properties: &BTreeSet<String>,
) -> Result<()> {
    let mut direct_properties = inherited_object_properties.clone();
    direct_properties.extend(
        schema
            .get("properties")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
            .map(|(name, _)| name.clone()),
    );

    if let Some(members) = schema.get("allOf").and_then(Value::as_array) {
        if members.is_empty() {
            return invalid_empty_composition(path, "allOf");
        }
        let mut sibling_properties = direct_properties.clone();
        for member in members {
            collect_composed_property_names(member, &mut sibling_properties, 0);
        }
        for member in members {
            validate_request_schema_value_inner(
                member,
                value,
                path,
                depth + 1,
                remaining_steps,
                &sibling_properties,
            )?;
        }
    }

    if let Some(members) = schema.get("oneOf").and_then(Value::as_array) {
        if members.is_empty() {
            return invalid_empty_composition(path, "oneOf");
        }
        let mut matches = 0_usize;
        let mut distinct_members = BTreeSet::new();
        for member in members {
            let equality_key = schema_equality_key(member, depth + 1, remaining_steps)?;
            if !distinct_members.insert(equality_key) {
                continue;
            }
            match validate_request_schema_value_inner(
                member,
                value,
                path,
                depth + 1,
                remaining_steps,
                &direct_properties,
            ) {
                Ok(()) => matches += 1,
                Err(error) if validation_error_aborts_composition(&error) => return Err(error),
                Err(_) => {}
            }
        }
        if matches != 1 {
            return Err(CloudflareError::InvalidRequestBody(format!(
                "{} must match exactly one pinned oneOf alternative",
                request_schema_location(path)
            )));
        }
    }

    if let Some(members) = schema.get("anyOf").and_then(Value::as_array) {
        if members.is_empty() {
            return invalid_empty_composition(path, "anyOf");
        }
        let mut sibling_properties = direct_properties.clone();
        for member in members {
            collect_composed_property_names(member, &mut sibling_properties, 0);
        }
        let mut matches = false;
        for member in members {
            match validate_request_schema_value_inner(
                member,
                value,
                path,
                depth + 1,
                remaining_steps,
                &sibling_properties,
            ) {
                Ok(()) => {
                    matches = true;
                    break;
                }
                Err(error) if validation_error_aborts_composition(&error) => return Err(error),
                Err(_) => {}
            }
        }
        if !matches {
            return Err(CloudflareError::InvalidRequestBody(format!(
                "{} must match at least one pinned anyOf alternative",
                request_schema_location(path)
            )));
        }
    }
    Ok(())
}

fn validation_error_aborts_composition(error: &CloudflareError) -> bool {
    matches!(
        error,
        CloudflareError::InvalidRequestBody(reason)
            if reason == REQUEST_VALIDATION_DEPTH_LIMIT_REASON
                || reason == REQUEST_VALIDATION_WORK_LIMIT_REASON
                || reason.contains("declares an empty pinned")
    )
}

fn collect_composed_property_names(
    schema: &Value,
    properties: &mut BTreeSet<String>,
    depth: usize,
) {
    if depth > MAX_REQUEST_VALIDATION_DEPTH {
        return;
    }
    properties.extend(
        schema
            .get("properties")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
            .map(|(name, _)| name.clone()),
    );
    for composition in ["allOf", "oneOf", "anyOf"] {
        for member in schema
            .get(composition)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            collect_composed_property_names(member, properties, depth + 1);
        }
    }
}

fn invalid_empty_composition(path: &str, composition: &str) -> Result<()> {
    Err(CloudflareError::InvalidRequestBody(format!(
        "{} declares an empty pinned {composition} contract",
        request_schema_location(path)
    )))
}

fn request_schema_location(path: &str) -> String {
    if path.is_empty() {
        "top-level value".to_owned()
    } else {
        format!("property `{path}`")
    }
}

fn validate_request_object(
    schema: &Value,
    object: &serde_json::Map<String, Value>,
    path: &str,
    depth: usize,
    remaining_steps: &mut usize,
    allowed_properties: &BTreeSet<String>,
) -> Result<()> {
    for required in schema
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        if !object.contains_key(required) {
            return Err(CloudflareError::InvalidRequestBody(format!(
                "missing required property `{}`",
                request_property_path(path, required)
            )));
        }
    }
    let properties = schema.get("properties").and_then(Value::as_object);
    let additional = schema.get("additionalProperties");
    for (name, value) in object {
        if let Some(property) = properties.and_then(|properties| properties.get(name)) {
            validate_request_schema_value_inner(
                property,
                value,
                &request_property_path(path, name),
                depth + 1,
                remaining_steps,
                &BTreeSet::new(),
            )?;
            continue;
        }
        match additional {
            Some(Value::Bool(false)) => {
                let location = if path.is_empty() {
                    "request body"
                } else {
                    path
                };
                return Err(CloudflareError::InvalidRequestBody(format!(
                    "object at `{location}` contains a property disallowed by the pinned schema"
                )));
            }
            Some(additional_schema) if additional_schema.is_object() => {
                validate_request_schema_value_inner(
                    additional_schema,
                    value,
                    path,
                    depth + 1,
                    remaining_steps,
                    &BTreeSet::new(),
                )?;
            }
            None if properties.is_some() && !allowed_properties.contains(name) => {
                let location = if path.is_empty() {
                    "request body"
                } else {
                    path
                };
                return Err(CloudflareError::InvalidRequestBody(format!(
                    "object at `{location}` contains a property outside the pinned contract"
                )));
            }
            _ => {}
        }
    }
    Ok(())
}

fn request_property_path(parent: &str, property: &str) -> String {
    if parent.is_empty() {
        property.to_owned()
    } else {
        format!("{parent}.{property}")
    }
}

fn json_type_matches(value: &Value, expected: &str) -> bool {
    match expected {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "number" => value.is_number(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        _ => true,
    }
}
