//! Cloudflare capability catalog normalization and indexing.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use cfctl_core::{
    AdapterStatus, BillingModelV1, CapabilityV1, CostExposureV1,
    CreatedCollectionResourceContractV1, CreatedResourceContractV1, DeletedResourceContractV1,
    EffectClass, KnowledgeReferenceV1, Maturity, QuerySerializationV1, ResponseBodyModeV1,
    ResponseContractV1, RiskClass, SamePathReadContractV1, SelectorContractV1, SelectorV1,
    UpdatedResourceContractV1, hash_value, request_header_is_reserved,
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
        self.schema_hash = hash_value(&serde_json::to_value(&self.capabilities)?)?;
        Ok(())
    }

    pub fn validate_hash(&self) -> Result<()> {
        let actual = hash_value(&serde_json::to_value(&self.capabilities)?)?;
        if self.schema_hash != actual {
            return Err(CatalogError::ContentHashMismatch {
                recorded: self.schema_hash.clone(),
                actual,
            });
        }
        Ok(())
    }

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
            sources,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    pub sources: BTreeMap<String, usize>,
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
                plan_gated && supports_live_zone_entitlement_resolution(capability);
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
        if !capability.cost.references.is_empty() {
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
            capability.response_contract = success_response_contract(document, operation)?;
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

    classify_exact_resource_contracts(document, &mut capabilities);
    classify_parent_collection_delete_contracts(document, &mut capabilities);
    classify_parent_collection_update_contracts(document, &mut capabilities);
    classify_created_resource_contracts(document, &mut capabilities);
    classify_created_collection_resource_contracts(document, &mut capabilities);
    classify_global_warp_override_contract(document, &mut capabilities);
    classify_same_path_object_mutation_contracts(document, &mut capabilities);
    finalize_global_warp_override_rollback_contract(&mut capabilities);
    finalize_d1_read_replication_rollback_contract(&mut capabilities);
    finalize_cloudflare_tunnel_configuration_rollback_contract(&mut capabilities);
    finalize_warp_connector_configuration_rollback_contract(&mut capabilities);
    finalize_dns_record_rollback_contract(document, &mut capabilities);
    for capability in capabilities.values_mut() {
        block_unsupported_response_contract(capability);
    }

    let source_hash = hash_value(document)?;
    let mut snapshot = CatalogSnapshot {
        schema_version: 1,
        generated_at: Utc::now(),
        source_url: OFFICIAL_OPENAPI_URL.to_owned(),
        source_hash,
        schema_hash: String::new(),
        capabilities,
    };
    snapshot.refresh_hash()?;
    Ok(snapshot)
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

const DNS_RECORD_DETAIL_PATH: &str = "/zones/{zone_id}/dns_records/{dns_record_id}";
const DNS_RECORD_DETAIL_READ_CAPABILITY_ID: &str = "dns-records-for-a-zone-dns-record-details";
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
) -> Result<Option<ResponseContractV1>> {
    let responses = operation.get("responses").and_then(Value::as_object);
    let mut success_statuses = BTreeSet::new();
    let mut success_media_types = BTreeSet::new();
    let mut every_success_is_cloudflare_json = true;
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
                continue;
            }
            every_success_is_empty = false;
            if media.as_slice() != ["application/json"] {
                every_success_is_cloudflare_json = false;
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
    } else if is_workers_ai_model_run(capability) {
        classify_workers_ai_model_run(capability);
    } else if is_d1_read_replication_update(capability) {
        classify_d1_read_replication_update(capability);
    } else if is_dns_record_lifecycle(&capability.id) {
        classify_dns_record_lifecycle(capability);
    } else if let Some(kind) = access_authorization_configuration_kind(capability) {
        classify_access_authorization_configuration(capability, kind);
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
    } else if let Some(kind) = queue_configuration_kind(capability) {
        classify_queue_configuration(capability, kind);
    } else {
        return false;
    }
    true
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueueConfigurationKind {
    Create,
    Update,
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
];

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
        if capability.id == "user-api-tokens-create-token" {
            capability.adapter_status = AdapterStatus::Blocked;
            capability.blocked_reason = Some(
                "user-token minting is blocked until a dedicated live permission inventory and least-privilege policy workflow is implemented"
                    .to_owned(),
            );
        }
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
