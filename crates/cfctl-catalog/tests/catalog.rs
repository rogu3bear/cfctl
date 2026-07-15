#![allow(clippy::expect_used, clippy::unwrap_used)]

use cfctl_catalog::{
    CatalogChangeKind, CatalogIndex, CatalogSnapshot, ingest_cli_help, markdown_link,
    markdown_links, normalize_openapi,
};
use cfctl_core::{AdapterStatus, EffectClass, RiskClass};
use serde_json::json;

fn fixture() -> serde_json::Value {
    json!({
        "openapi": "3.0.3",
        "info": {"title":"Cloudflare API","version":"4.0.0"},
        "servers": [{"url":"https://api.cloudflare.com/client/v4"}],
        "paths": {
            "/zones/{zone_id}/dns_records": {
                "get": {
                    "operationId":"dns-records-list",
                    "summary":"List DNS Records",
                    "tags":["DNS Records"],
                    "parameters":[{"in":"path","name":"zone_id","required":true,"schema":{"type":"string"}}],
                    "x-cfPlanAvailability":{"free":true,"pro":true,"business":true,"enterprise":true}
                }
            },
            "/zones/{zone_id}/dns_records/{record_id}": {
                "delete": {
                    "operationId":"dns-records-delete",
                    "summary":"Delete DNS Record",
                    "tags":["DNS Records"],
                    "parameters":[
                        {"in":"path","name":"zone_id","required":true,"schema":{"type":"string"}},
                        {"in":"path","name":"record_id","required":true,"schema":{"type":"string"}}
                    ]
                }
            }
        }
    })
}

#[test]
fn official_docs_indexes_expose_product_and_page_links_deterministically() {
    let directory = "- [Browser Run](https://developers.cloudflare.com/browser-run/llms.txt): docs";
    let product = "- [Get started](https://developers.cloudflare.com/browser-run/get-started/index.md): first steps";
    assert_eq!(
        markdown_link(directory),
        Some("https://developers.cloudflare.com/browser-run/llms.txt")
    );
    assert!(
        markdown_links(&format!("{directory}\n{product}"), "/llms.txt")
            .contains("https://developers.cloudflare.com/browser-run/llms.txt")
    );
}

#[test]
fn request_contract_resolves_local_schema_without_copying_secret_values() {
    let mut document = fixture();
    document["components"]["schemas"]["CreateRecord"] = json!({
        "type": "object",
        "required": ["name"],
        "properties": {
            "name": {"type": "string", "description": "record name"},
            "ttl": {"type": "integer"}
        }
    });
    document["paths"]["/zones/{zone_id}/dns_records"]["post"] = json!({
        "operationId": "dns-records-create",
        "summary": "Create DNS Record",
        "tags": ["DNS Records"],
        "requestBody": {
            "required": true,
            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/CreateRecord"}}}
        }
    });
    let snapshot = normalize_openapi(&document).expect("catalog");
    let schema = snapshot
        .get("dns-records-create")
        .and_then(|capability| capability.request_schema.as_ref())
        .expect("request contract");
    assert_eq!(schema["type"], "object");
    assert_eq!(schema["x-cfctl-body-required"], true);
    assert_eq!(schema["properties"]["ttl"]["type"], "integer");
    assert!(schema["properties"]["name"].get("description").is_none());
}

#[test]
fn official_cli_help_becomes_delegated_capabilities() {
    let mut snapshot = normalize_openapi(&fixture()).expect("catalog");
    ingest_cli_help(
        &mut snapshot,
        "wrangler",
        "4.107.0",
        "COMMANDS\n  wrangler deploy [path]  Deploy a Worker\n  wrangler tail [worker]  Tail logs\n",
    );
    let deploy = snapshot.get("wrangler.deploy").expect("deploy capability");
    assert_eq!(deploy.adapter_status, AdapterStatus::DelegatedCli);
    assert!(deploy.mutating);
    assert!(
        !snapshot
            .get("wrangler.tail")
            .expect("tail capability")
            .mutating
    );
}

#[test]
fn sqlite_index_is_rebuildable_from_the_authoritative_snapshot() {
    let snapshot = normalize_openapi(&fixture()).expect("catalog");
    let root = tempfile::tempdir().expect("temp catalog");
    let index = CatalogIndex::rebuild(&root.path().join("catalog.sqlite3"), &snapshot)
        .expect("rebuild index");
    let results = index.search("zones delete", 10).expect("indexed search");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, "dns-records-delete");
    assert_eq!(
        index.schema_hash().expect("schema hash"),
        snapshot.schema_hash
    );
}

#[test]
fn sqlite_search_tolerates_natural_language_and_ranks_the_intended_operation() {
    let snapshot = normalize_openapi(&fixture()).expect("catalog");
    let root = tempfile::tempdir().expect("temp catalog");
    let index = CatalogIndex::rebuild(&root.path().join("catalog.sqlite3"), &snapshot)
        .expect("rebuild index");

    let results = index
        .search("please remove the dns record safely", 10)
        .expect("natural language search");

    assert_eq!(
        results.first().map(|capability| capability.id.as_str()),
        Some("dns-records-delete")
    );
}

#[test]
fn normalizes_every_openapi_operation_into_a_searchable_capability() {
    let snapshot = normalize_openapi(&fixture()).expect("fixture should normalize");
    assert_eq!(snapshot.capabilities.len(), 2);
    assert!(snapshot.schema_hash.starts_with("sha256:"));

    let read = snapshot.get("dns-records-list").expect("read exists");
    assert_eq!(read.risk, RiskClass::Read);
    assert_eq!(read.effect, EffectClass::ReadOnly);
    assert_eq!(read.adapter_status, AdapterStatus::DynamicApi);
    assert_eq!(read.account_scope, "zone");

    let delete = snapshot.get("dns-records-delete").expect("delete exists");
    assert_eq!(delete.risk, RiskClass::Destructive);
    assert_eq!(delete.effect, EffectClass::Destructive);
    assert!(delete.verification.required);
    assert_eq!(delete.adapter_status, AdapterStatus::Blocked);
    assert!(
        delete
            .blocked_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("cost")
                && reason.contains("verification")
                && reason.contains("rollback"))
    );
}

#[test]
fn coverage_diff_reports_new_changed_and_removed_operations() {
    let old = normalize_openapi(&fixture()).expect("old fixture");
    let mut next_value = fixture();
    next_value["paths"]["/zones/{zone_id}/dns_records"]["get"]["summary"] =
        json!("List all DNS Records");
    next_value["paths"]
        .as_object_mut()
        .expect("fixture paths object")
        .remove("/zones/{zone_id}/dns_records/{record_id}");
    next_value["paths"]["/accounts/{account_id}/workers/scripts"]["get"] = json!({
        "operationId":"workers-list-scripts",
        "summary":"List Workers",
        "tags":["Workers"]
    });
    let next = normalize_openapi(&next_value).expect("next fixture");

    let changes = CatalogSnapshot::diff(&old, &next);
    assert!(
        changes
            .iter()
            .any(|c| c.id == "dns-records-list" && c.kind == CatalogChangeKind::Changed)
    );
    assert!(
        changes
            .iter()
            .any(|c| c.id == "dns-records-delete" && c.kind == CatalogChangeKind::Removed)
    );
    assert!(
        changes
            .iter()
            .any(|c| c.id == "workers-list-scripts" && c.kind == CatalogChangeKind::Added)
    );
}

#[test]
fn search_matches_ids_titles_products_and_descriptions() {
    let snapshot = normalize_openapi(&fixture()).expect("fixture should normalize");
    assert_eq!(snapshot.search("dns record").len(), 2);
    assert_eq!(snapshot.search("workers").len(), 0);
}

#[test]
fn credential_returning_get_is_approval_gated_and_sink_only() {
    let mut document = fixture();
    document["paths"]["/accounts/{account_id}/cfd_tunnel/{tunnel_id}/token"]["get"] = json!({
        "operationId":"cloudflare-tunnel-get-a-cloudflare-tunnel-token",
        "summary":"Get a Cloudflare Tunnel token",
        "tags":["Cloudflare Tunnel"]
    });
    let snapshot = normalize_openapi(&document).expect("credential catalog");
    let capability = snapshot
        .get("cloudflare-tunnel-get-a-cloudflare-tunnel-token")
        .expect("tunnel token capability");
    assert_eq!(capability.risk, RiskClass::SecretSensitive);
    assert_eq!(capability.adapter_status, AdapterStatus::Native);
    assert!(capability.mutating);
    assert!(!capability.verification.required);
}

#[test]
fn account_token_mutations_have_complete_native_execution_contracts() {
    let mut document = fixture();
    document["paths"]["/accounts/{account_id}/tokens"]["post"] = json!({
        "operationId":"account-api-tokens-create-token",
        "summary":"Create Token",
        "tags":["Account Owned API Tokens"],
        "x-api-token-group":["Account API Tokens Write"]
    });
    document["paths"]["/accounts/{account_id}/tokens/{token_id}/value"]["put"] = json!({
        "operationId":"account-api-tokens-roll-token",
        "summary":"Roll Token",
        "tags":["Account Owned API Tokens"],
        "x-api-token-group":["Account API Tokens Write"]
    });
    document["paths"]["/accounts/{account_id}/tokens/{token_id}"]["delete"] = json!({
        "operationId":"account-api-tokens-delete-token",
        "summary":"Delete Token",
        "tags":["Account Owned API Tokens"],
        "x-api-token-group":["Account API Tokens Write"]
    });

    let snapshot = normalize_openapi(&document).expect("token catalog");
    for id in [
        "account-api-tokens-create-token",
        "account-api-tokens-roll-token",
        "account-api-tokens-delete-token",
    ] {
        let capability = snapshot.get(id).expect("token capability");
        assert_eq!(capability.adapter_status, AdapterStatus::Native);
        assert!(capability.cost.known);
        assert!(capability.mutation_contract_gaps().is_empty());
        assert!(
            !capability
                .verification
                .strategy
                .contains("operation_specific")
        );
    }

    assert!(
        snapshot
            .get("account-api-tokens-create-token")
            .expect("create token")
            .rollback
            .supported
    );
    assert!(
        snapshot
            .get("account-api-tokens-roll-token")
            .expect("roll token")
            .rollback
            .warning
            .as_deref()
            .is_some_and(|warning| warning.contains("old token value"))
    );
}
