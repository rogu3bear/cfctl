//! Shared typed read rendering contracts.
use serde::{Deserialize, Serialize};

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

/// A fixed, read-only compiler contract for D1 schema assertions. Callers
/// supply only the closed assertion object declared by the capability request
/// schema; the executor owns every SQL token sent to Cloudflare.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct D1SchemaIntrospectionContractV1 {
    pub max_rows: u64,
    pub max_bytes: u64,
    pub max_timeout_seconds: u64,
}
