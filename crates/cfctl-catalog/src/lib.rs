//! Cloudflare capability catalog normalization and indexing.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use cfctl_core::{
    AdapterStatus, BillingModelV1, CapabilityV1, CostExposureV1,
    CreatedCollectionResourceContractV1, CreatedResourceContractV1, DeletedResourceContractV1,
    EffectClass, KnowledgeReferenceV1, Maturity, RiskClass, SamePathReadContractV1, SelectorV1,
    UpdatedResourceContractV1, hash_value,
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
            capability.entitlement.source =
                Some("official OpenAPI x-cfPlanAvailability".to_owned());
            capability.entitlement.requires_live_resolution = capability
                .entitlement
                .plans
                .values()
                .any(|available| !available);
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
            if capability.mutating && !capability.cost.known {
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
    let mut creates_with_schema_proven_string_ids = BTreeSet::new();

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
                .filter_map(|parameter| selector_from_parameter(document, parameter))
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
            if method == "post" && success_response_declares_result_string_id(document, operation) {
                creates_with_schema_proven_string_ids.insert(id.clone());
            }
            classify(&mut capability);
            block_incomplete_dynamic_mutation(&mut capability);
            capabilities.insert(id, capability);
        }
    }

    classify_exact_resource_contracts(document, &mut capabilities);
    classify_parent_collection_delete_contracts(document, &mut capabilities);
    classify_parent_collection_update_contracts(document, &mut capabilities);
    classify_same_path_object_update_contracts(document, &mut capabilities);
    classify_created_resource_contracts(
        document,
        &mut capabilities,
        &creates_with_schema_proven_string_ids,
    );
    classify_created_collection_resource_contracts(
        document,
        &mut capabilities,
        &creates_with_schema_proven_string_ids,
    );

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

fn classify_same_path_object_update_contracts(
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
        if !matches!(capability.method.as_str(), "PATCH" | "PUT")
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
        let Some(fields) = canonical_request_object_fields(capability) else {
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
        "same_path_result_contains_planned_fields_after_update"
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

fn classify_created_resource_contracts(
    document: &Value,
    capabilities: &mut BTreeMap<String, CapabilityV1>,
    creates_with_schema_proven_string_ids: &BTreeSet<String>,
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
                capability.id.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let delete_targets = capabilities
        .values()
        .filter(|capability| {
            capability.method == "DELETE"
                && path_targets_exact_resource(&capability.path)
                && capability.request_schema.is_none()
                && capability
                    .selectors
                    .iter()
                    .all(|selector| selector.location == "path")
        })
        .map(|capability| {
            (
                (capability.path.clone(), capability.product.clone()),
                capability.id.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();

    for capability in capabilities.values_mut() {
        if capability.method != "POST"
            || capability.verification.strategy != "post_change_read_or_operation_specific_verifier"
            || !creates_with_schema_proven_string_ids.contains(&capability.id)
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
    let mut verified_response_fields = capability
        .request_schema
        .as_ref()
        .filter(|schema| schema.get("type").and_then(Value::as_str) == Some("object"))?
        .get("properties")?
        .as_object()?
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    if verified_response_fields.is_empty() {
        return None;
    }
    verified_response_fields.sort();
    verified_response_fields.dedup();
    let field_names = verified_response_fields
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();

    let candidates = read_targets
        .iter()
        .filter_map(|((detail_path, product), read_capability_id)| {
            if product != &capability.product {
                return None;
            }
            let identity_selector = direct_child_selector(&capability.path, detail_path)?;
            if !selector_can_be_response_id(&identity_selector) {
                return None;
            }
            let delete_capability_id =
                delete_targets.get(&(detail_path.clone(), product.clone()))?;
            let read_operation = document.get("paths")?.get(detail_path)?.get("get")?;
            if !success_response_declares_result_string_id(document, read_operation)
                || !success_response_declares_result_fields(document, read_operation, &field_names)
            {
                return None;
            }
            Some(CreatedResourceContractV1 {
                detail_path: detail_path.clone(),
                identity_selector,
                response_result_identity_pointer: "/id".to_owned(),
                read_capability_id: read_capability_id.clone(),
                delete_capability_id: delete_capability_id.clone(),
                verified_response_fields: verified_response_fields.clone(),
            })
        })
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
type ExactReadTargets = BTreeMap<(String, String), String>;
type ExactDeleteTargets = BTreeMap<(String, String), String>;

fn classify_created_collection_resource_contracts(
    document: &Value,
    capabilities: &mut BTreeMap<String, CapabilityV1>,
    creates_with_schema_proven_string_ids: &BTreeSet<String>,
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
                && capability.request_schema.is_none()
                && capability
                    .selectors
                    .iter()
                    .all(|selector| selector.location == "path")
        })
        .map(|capability| {
            (
                (capability.path.clone(), capability.product.clone()),
                capability.id.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();

    for capability in capabilities.values_mut() {
        if capability.method != "POST"
            || capability.verification.strategy != "post_change_read_or_operation_specific_verifier"
            || !creates_with_schema_proven_string_ids.contains(&capability.id)
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
    let mut verified_response_fields = capability
        .request_schema
        .as_ref()
        .filter(|schema| schema.get("type").and_then(Value::as_str) == Some("object"))?
        .get("properties")?
        .as_object()?
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    if verified_response_fields.is_empty() {
        return None;
    }
    verified_response_fields.sort();
    verified_response_fields.dedup();

    let (read_capability_id, read_selectors) =
        list_targets.get(&(capability.path.clone(), capability.product.clone()))?;
    let read_operation = document.get("paths")?.get(&capability.path)?.get("get")?;
    let field_names = verified_response_fields
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let requires_page_number_completion = complete_collection_readback_contract(
        document,
        read_operation,
        read_selectors,
        &field_names,
    )?;
    let delete_candidates = delete_targets
        .iter()
        .filter_map(|((delete_path, product), delete_capability_id)| {
            if product != &capability.product {
                return None;
            }
            let identity_selector = direct_child_selector(&capability.path, delete_path)?;
            selector_can_be_response_id(&identity_selector)
                .then(|| (identity_selector, delete_capability_id.clone()))
        })
        .collect::<Vec<_>>();
    let [(identity_selector, delete_capability_id)] = delete_candidates.as_slice() else {
        return None;
    };

    Some(CreatedCollectionResourceContractV1 {
        collection_path: capability.path.clone(),
        identity_selector: identity_selector.clone(),
        response_result_identity_pointer: "/id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: read_capability_id.clone(),
        delete_capability_id: delete_capability_id.clone(),
        verified_response_fields,
        requires_page_number_completion,
    })
}

fn classify_exact_resource_contracts(
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
        let Some(read_capability_id) = readback_targets.get(&(
            capability.path.clone(),
            capability.product.clone(),
            routing_headers,
        )) else {
            continue;
        };

        match capability.method.as_str() {
            "DELETE" => {
                if capability.request_schema.is_some() {
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
                let Some(fields) = canonical_request_object_fields(capability) else {
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
                capability.rollback.warning = Some(
                    "automatic restoration is unsupported because the plan does not bind a pre-change snapshot; restoration requires a separately reviewed update plan built from trusted evidence"
                        .to_owned(),
                );
            }
            _ => continue,
        }
        capability.rollback.supported = false;
        capability.rollback.strategy = None;
        refresh_dynamic_mutation_contract(capability);
    }
}

fn same_path_mutation_routing_headers(capability: &CapabilityV1) -> Option<Vec<String>> {
    same_path_routing_headers(capability, false)
}

fn same_path_readback_routing_headers(capability: &CapabilityV1) -> Option<Vec<String>> {
    same_path_routing_headers(capability, true)
}

fn same_path_routing_headers(
    capability: &CapabilityV1,
    allow_readback_controls: bool,
) -> Option<Vec<String>> {
    let mut routing_headers = Vec::new();
    for selector in &capability.selectors {
        if selector.location == "path" {
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

fn canonical_request_object_fields(capability: &CapabilityV1) -> Option<Vec<String>> {
    let mut fields = capability
        .request_schema
        .as_ref()
        .filter(|schema| schema.get("type").and_then(Value::as_str) == Some("object"))?
        .get("properties")?
        .as_object()?
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    if fields.is_empty() {
        return None;
    }
    fields.sort();
    fields.dedup();
    Some(fields)
}

fn classify_parent_collection_delete_contracts(
    document: &Value,
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    let list_targets = capabilities
        .values()
        .filter(|capability| capability.method == "GET")
        .filter_map(|capability| {
            let operation = document.get("paths")?.get(&capability.path)?.get("get")?;
            complete_collection_readback_contract(document, operation, &capability.selectors, &[])
                .map(|requires_page_number_completion| {
                    (
                        (capability.path.clone(), capability.product.clone()),
                        (capability.id.clone(), requires_page_number_completion),
                    )
                })
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
        let Some((read_capability_id, requires_page_number_completion)) =
            list_targets.get(&(collection_path.to_owned(), capability.product.clone()))
        else {
            continue;
        };

        capability.deleted_resource = Some(DeletedResourceContractV1 {
            collection_path: collection_path.to_owned(),
            identity_selector: identity_selector.to_owned(),
            response_item_identity_pointer: "/id".to_owned(),
            read_capability_id: read_capability_id.clone(),
            requires_page_number_completion: *requires_page_number_completion,
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
            .filter(|selector| selector_can_be_response_id(selector))
        else {
            continue;
        };
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
        let Some(mut verified_response_fields) = capability
            .request_schema
            .as_ref()
            .filter(|schema| schema.get("type").and_then(Value::as_str) == Some("object"))
            .and_then(|schema| schema.get("properties"))
            .and_then(Value::as_object)
            .map(|properties| properties.keys().cloned().collect::<Vec<_>>())
            .filter(|fields| !fields.is_empty())
        else {
            continue;
        };
        verified_response_fields.sort();
        verified_response_fields.dedup();
        let field_names = verified_response_fields
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let Some(requires_page_number_completion) = complete_collection_readback_contract(
            document,
            read_operation,
            read_selectors,
            &field_names,
        ) else {
            continue;
        };

        capability.updated_resource = Some(UpdatedResourceContractV1 {
            collection_path: collection_path.to_owned(),
            identity_selector: identity_selector.to_owned(),
            response_item_identity_pointer: "/id".to_owned(),
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

fn selector_can_be_response_id(selector: &str) -> bool {
    selector == "id" || selector.ends_with("_id") || selector.ends_with("_identifier")
}

fn complete_collection_readback_contract(
    document: &Value,
    operation: &Value,
    selectors: &[SelectorV1],
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
    for key in [
        "type",
        "required",
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

fn success_response_declares_result_string_id(document: &Value, operation: &Value) -> bool {
    operation
        .get("responses")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter(|(status, _)| status.starts_with('2'))
        .filter_map(|(_, response)| response.pointer("/content/application~1json/schema"))
        .any(|schema| schema_declares_string_path(document, schema, &["result", "id"], 0))
}

fn success_response_declares_complete_collection(
    document: &Value,
    operation: &Value,
    requires_page_number_completion: bool,
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
            schema_declares_result_array_string_id(document, schema, 0)
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

fn schema_declares_result_array_string_id(document: &Value, schema: &Value, depth: usize) -> bool {
    if depth > 32 {
        return false;
    }
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        return reference
            .strip_prefix('#')
            .and_then(|pointer| document.pointer(pointer))
            .is_some_and(|resolved| {
                schema_declares_result_array_string_id(document, resolved, depth + 1)
            });
    }
    if let Some(result) = schema
        .get("properties")
        .and_then(Value::as_object)
        .and_then(|properties| properties.get("result"))
        && schema_declares_array_item_string_id(document, result, depth + 1)
    {
        return true;
    }
    if schema
        .get("allOf")
        .and_then(Value::as_array)
        .is_some_and(|members| {
            members
                .iter()
                .any(|member| schema_declares_result_array_string_id(document, member, depth + 1))
        })
    {
        return true;
    }
    for alternative in ["oneOf", "anyOf"] {
        if let Some(members) = schema.get(alternative).and_then(Value::as_array) {
            return !members.is_empty()
                && members.iter().all(|member| {
                    schema_declares_result_array_string_id(document, member, depth + 1)
                });
        }
    }
    false
}

fn schema_declares_array_item_string_id(document: &Value, schema: &Value, depth: usize) -> bool {
    if depth > 32 {
        return false;
    }
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        return reference
            .strip_prefix('#')
            .and_then(|pointer| document.pointer(pointer))
            .is_some_and(|resolved| {
                schema_declares_array_item_string_id(document, resolved, depth + 1)
            });
    }
    if schema.get("type").and_then(Value::as_str) == Some("array")
        && schema
            .get("items")
            .is_some_and(|items| schema_declares_string_path(document, items, &["id"], depth + 1))
    {
        return true;
    }
    if schema
        .get("allOf")
        .and_then(Value::as_array)
        .is_some_and(|members| {
            members
                .iter()
                .any(|member| schema_declares_array_item_string_id(document, member, depth + 1))
        })
    {
        return true;
    }
    for alternative in ["oneOf", "anyOf"] {
        if let Some(members) = schema.get(alternative).and_then(Value::as_array) {
            return !members.is_empty()
                && members.iter().all(|member| {
                    schema_declares_array_item_string_id(document, member, depth + 1)
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

fn selector_from_parameter(document: &Value, parameter: &Value) -> Option<SelectorV1> {
    let name = parameter.get("name")?.as_str()?.to_owned();
    let location = parameter.get("in")?.as_str()?.to_owned();
    let schema = parameter.get("schema");
    Some(SelectorV1 {
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
    } else if is_d1_read_replication_update(capability) {
        classify_d1_read_replication_update(capability);
        return;
    } else if is_dns_record_lifecycle(&capability.id) {
        classify_dns_record_lifecycle(capability);
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
        "account entitlement has not been resolved for this plan-gated operation" => {
            "entitlement_unresolved"
        }
        _ if gap.starts_with("operation-specific cost is not bounded;") => "cost_unbounded",
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
