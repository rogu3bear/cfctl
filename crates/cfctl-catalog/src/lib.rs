//! Cloudflare capability catalog normalization and indexing.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use cfctl_core::{
    AdapterStatus, CapabilityV1, EffectClass, Maturity, RiskClass, SelectorV1, hash_value,
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

#[derive(Debug, Error)]
pub enum CatalogError {
    #[error("OpenAPI document does not contain an object at `paths`")]
    MissingPaths,
    #[error("duplicate operation id `{0}`")]
    DuplicateOperation(String),
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
    pub schema_hash: String,
    pub capabilities: BTreeMap<String, CapabilityV1>,
}

impl CatalogSnapshot {
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&CapabilityV1> {
        self.capabilities.get(id)
    }

    #[must_use]
    pub fn search(&self, query: &str) -> Vec<&CapabilityV1> {
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
        let mut sources = BTreeMap::new();
        let mut mutating = 0;
        let mut blocked = 0;
        for capability in self.capabilities.values() {
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
        }
        CatalogCoverageV1 {
            schema_hash: self.schema_hash.clone(),
            total: self.capabilities.len(),
            reads: self.capabilities.len().saturating_sub(mutating),
            mutating,
            blocked,
            adapter_statuses,
            sources,
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| catalog_io(parent, source))?;
        }
        let encoded = serde_json::to_vec_pretty(self)?;
        fs::write(path, encoded).map_err(|source| catalog_io(path, source))
    }

    pub fn load(path: &Path) -> Result<Self> {
        let encoded = fs::read(path).map_err(|source| catalog_io(path, source))?;
        Ok(serde_json::from_slice(&encoded)?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogCoverageV1 {
    pub schema_hash: String,
    pub total: usize,
    pub reads: usize,
    pub mutating: usize,
    pub blocked: usize,
    pub adapter_statuses: BTreeMap<String, usize>,
    pub sources: BTreeMap<String, usize>,
}

pub struct CatalogIndex {
    connection: Connection,
}

impl CatalogIndex {
    pub fn rebuild(path: &Path, snapshot: &CatalogSnapshot) -> Result<Self> {
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
        snapshot.capabilities.insert(id, capability);
    }
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
        });
        if id.starts_with("cloudflare-ui.oauth-") {
            capability.selectors.push(SelectorV1 {
                name: "client_id".to_owned(),
                location: "target".to_owned(),
                required: true,
                value_type: "string".to_owned(),
                description: Some("Exact OAuth client displayed in the dashboard".to_owned()),
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
            capability.selectors = shared_and_operation_parameters(path_item, operation)
                .into_iter()
                .filter_map(selector_from_parameter)
                .collect();
            capability.permissions = operation_object
                .get("x-api-token-group")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect();
            capability.request_schema = request_schema_contract(document, operation);
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
            block_incomplete_dynamic_mutation(&mut capability);
            capabilities.insert(id, capability);
        }
    }

    Ok(CatalogSnapshot {
        schema_version: 1,
        generated_at: Utc::now(),
        source_url: OFFICIAL_OPENAPI_URL.to_owned(),
        schema_hash: hash_value(document)?,
        capabilities,
    })
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
    let resolved = resolve_local_schema(document, schema);
    let mut contract = Map::new();
    for key in ["type", "required", "enum", "additionalProperties"] {
        if let Some(value) = resolved.get(key) {
            contract.insert(key.to_owned(), value.clone());
        }
    }
    if let Some(properties) = resolved.get("properties").and_then(Value::as_object) {
        let properties = properties
            .iter()
            .map(|(name, property)| {
                let property = resolve_local_schema(document, property);
                let shape = ["type", "enum", "format", "nullable"]
                    .into_iter()
                    .filter_map(|key| {
                        property
                            .get(key)
                            .cloned()
                            .map(|value| (key.to_owned(), value))
                    })
                    .collect();
                (name.clone(), Value::Object(shape))
            })
            .collect();
        contract.insert("properties".to_owned(), Value::Object(properties));
    }
    contract.insert(
        "x-cfctl-body-required".to_owned(),
        operation
            .pointer("/requestBody/required")
            .cloned()
            .unwrap_or(Value::Bool(false)),
    );
    Some(Value::Object(contract))
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
    path_item: &'a Value,
    operation: &'a Value,
) -> Vec<&'a Value> {
    path_item
        .get("parameters")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .chain(
            operation
                .get("parameters")
                .and_then(Value::as_array)
                .into_iter()
                .flatten(),
        )
        .collect()
}

fn selector_from_parameter(parameter: &Value) -> Option<SelectorV1> {
    let name = parameter.get("name")?.as_str()?.to_owned();
    let location = parameter.get("in")?.as_str()?.to_owned();
    Some(SelectorV1 {
        name,
        location,
        required: parameter
            .get("required")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        value_type: parameter
            .pointer("/schema/type")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned(),
        description: parameter
            .get("description")
            .or_else(|| parameter.pointer("/schema/description"))
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
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
        return;
    } else if capability.method == "DELETE"
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

fn block_incomplete_dynamic_mutation(capability: &mut CapabilityV1) {
    if capability.adapter_status != AdapterStatus::DynamicApi || !capability.mutating {
        return;
    }
    let gaps = capability.mutation_contract_gaps();
    if gaps.is_empty() {
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
        (
            capability
                .description
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase(),
            1,
        ),
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

fn catalog_io(path: &Path, source: std::io::Error) -> CatalogError {
    CatalogError::Io {
        path: path.display().to_string(),
        source,
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
