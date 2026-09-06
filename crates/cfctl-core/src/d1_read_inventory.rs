//! Committed, application-owned D1 read populations. These are not caller SQL.
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const D1_READ_PACK_PATH: &str = ".cfctl/operations/d1-reads.toml";
pub const D1_READ_COMPILER_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct D1ReadSourceV1 {
    pub path: String,
    pub sha256: String,
}

/// No executable DDL: the compiler creates only empty ordinary tables itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct D1ReadTableV1 {
    pub name: String,
    pub columns: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum D1ReadValueKindV1 {
    Integer,
    Real,
    Text,
    Boolean,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct D1ReadColumnV1 {
    pub name: String,
    pub kind: D1ReadValueKindV1,
    pub nullable: bool,
    /// Required for text; forbidden for other kinds. Always at most 8192.
    pub max_bytes: Option<u64>,
    /// Optional finite value allowlist, applied before any durable observation.
    pub allowed_values: Option<Vec<Value>>,
    pub min_integer: Option<i64>,
    pub max_integer: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct D1ReadOutputV1 {
    pub columns: Vec<D1ReadColumnV1>,
    #[serde(default)]
    pub min_rows: u64,
    pub max_rows: u64,
    /// Includes the entire provider JSON envelope, not just the result rows.
    pub max_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct D1ReadDependencyV1 {
    pub query_id: String,
    /// Both absent means the earlier read must have completed successfully.
    pub column: Option<String>,
    pub equals: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct D1ReadWitnessV1 {
    pub id: String,
    pub ordinal: u64,
    pub group: String,
    pub source_reference: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct D1ReadQueryV1 {
    pub id: String,
    pub sql: String,
    pub sha256: String,
    pub phase: String,
    pub requires: Vec<D1ReadDependencyV1>,
    #[serde(default)]
    pub parameters: Vec<D1ReadParameterV1>,
    pub output: D1ReadOutputV1,
    pub witnesses: Vec<D1ReadWitnessV1>,
}

/// A numbered `SQLite` placeholder sourced only from an earlier qualified row.
/// No parameter value can enter through the public call body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct D1ReadParameterV1 {
    pub index: u32,
    pub from_query: String,
    pub row_index: u64,
    pub column: String,
    pub kind: D1ReadValueKindV1,
    pub trim: bool,
    pub nonempty: bool,
    pub max_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct D1ReadParameterEvidenceV1 {
    pub index: u32,
    pub from_query: String,
    pub from_query_sha256: String,
    pub row_index: u64,
    pub column: String,
    pub value_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct D1ReadLimitsV1 {
    pub max_total_response_bytes: u64,
    pub max_elapsed_seconds: u64,
    /// Stops subsequent dispatch after the reported cumulative value is reached.
    /// It cannot cap scans or currency charged by an in-flight query.
    pub stop_after_rows_read: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct D1ReadInventoryV1 {
    pub schema_version: u8,
    pub query_count: u64,
    pub witness_count: u64,
    pub tables: Vec<D1ReadTableV1>,
    pub functions: Vec<String>,
    pub limits: D1ReadLimitsV1,
    pub queries: Vec<D1ReadQueryV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct D1ReadOperationV1 {
    pub id: String,
    pub title: String,
    pub description: String,
    pub account_id: String,
    pub database_id: String,
    pub profile_id: String,
    pub source_revision: String,
    pub source: Vec<D1ReadSourceV1>,
    pub inventory_path: String,
    pub inventory_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct D1ReadPackV1 {
    pub schema_version: u8,
    pub operation: Vec<D1ReadOperationV1>,
}

/// Identity is derived from Git by the loader, never asserted by pack contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceD1ReadInventoryContractV1 {
    pub repository_root: String,
    pub repository_head: String,
    pub repository_tree: String,
    pub repository_origin: String,
    pub operation_pack_sha256: String,
    pub operation: D1ReadOperationV1,
    pub inventory: D1ReadInventoryV1,
}

/// The only call body: no SQL, parameters, phases, subsets or output overrides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct D1ReadCallV1 {
    pub inventory_sha256: String,
    pub expected_credential_generation_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum D1ReadStatusV1 {
    Complete,
    Rejected,
    Unattempted,
}

/// Errors carry fixed classifications, never rejected provider material.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct D1ReadQueryResultV1 {
    pub query_id: String,
    pub query_sha256: String,
    pub phase: String,
    pub witnesses: Vec<D1ReadWitnessV1>,
    pub parameter_provenance: Vec<D1ReadParameterEvidenceV1>,
    pub status: D1ReadStatusV1,
    pub attempted: bool,
    pub classification: String,
    pub http_status: Option<u16>,
    pub rows_read: Option<u64>,
    pub response_bytes: Option<u64>,
    /// The qualified native receipt; no compatibility wrapping or predicates.
    pub receipt: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct D1ReadInventoryResultV1 {
    pub schema_version: u8,
    pub compiler_version: u8,
    pub inventory_sha256: String,
    pub read_complete: bool,
    pub attempted_queries: u64,
    pub unattempted_queries: u64,
    pub rows_read: u64,
    pub response_bytes: u64,
    pub hard_scan_or_currency_ceiling_established: bool,
    pub application_predicates_evaluated: bool,
    pub results: Vec<D1ReadQueryResultV1>,
}
