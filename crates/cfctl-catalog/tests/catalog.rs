#![allow(clippy::expect_used, clippy::unwrap_used)]

use cfctl_catalog::{
    CatalogChangeKind, CatalogIndex, CatalogSnapshot, OfficialTextFeedsV1,
    attach_official_product_knowledge, ingest_cli_help, markdown_link, markdown_links,
    normalize_openapi,
};
use cfctl_core::{
    AdapterStatus, BillingModelV1, CapabilityV1, CostExposureV1, DeletedResourceContractV1,
    EffectClass, KnowledgeReferenceV1, RiskClass, hash_value,
};
use chrono::Utc;
use serde_json::{Value, json};

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

fn assert_nested_replication_schema(schema: &serde_json::Value) {
    assert_eq!(schema["properties"]["replication"]["type"], "object");
    assert_eq!(
        schema["properties"]["replication"]["required"],
        json!(["mode"])
    );
    assert_eq!(
        schema["properties"]["replication"]["properties"]["mode"]["enum"],
        json!(["auto", "disabled"])
    );
    assert!(
        schema["properties"]["replication"]
            .get("description")
            .is_none()
    );
    assert!(
        schema["properties"]["replication"]["properties"]["mode"]
            .get("description")
            .is_none()
    );
}

#[test]
fn request_contract_resolves_local_schema_without_copying_secret_values() {
    let mut document = fixture();
    install_request_contract_fixture(&mut document);
    let snapshot = normalize_openapi(&document).expect("catalog");
    let schema = snapshot
        .get("dns-records-create")
        .and_then(|capability| capability.request_schema.as_ref())
        .expect("request contract");
    assert_eq!(schema["type"], "object");
    assert_eq!(schema["x-cfctl-body-required"], true);
    assert_request_schema_bounds(schema);
    assert_nested_replication_schema(schema);
    assert!(schema["properties"]["name"].get("description").is_none());

    let capability = snapshot
        .get("dns-records-create")
        .expect("create capability");
    let jurisdiction = capability
        .selectors
        .iter()
        .find(|selector| selector.name == "cf-r2-jurisdiction")
        .expect("jurisdiction selector");
    assert_eq!(jurisdiction.value_type, "string");
    assert_eq!(
        jurisdiction.description.as_deref(),
        Some("jurisdiction selector")
    );
    assert_eq!(
        capability
            .selectors
            .iter()
            .find(|selector| selector.name == "deploy")
            .expect("deploy selector")
            .value_type,
        "boolean"
    );
    let ambiguous = capability
        .selectors
        .iter()
        .find(|selector| selector.name == "ambiguous")
        .expect("ambiguous selector");
    assert_eq!(ambiguous.value_type, "unknown");
    assert!(ambiguous.description.is_none());
}

#[test]
fn request_contract_omits_read_only_properties_and_their_required_entries() {
    let mut document = fixture();
    document["components"]["schemas"]["ServerIdentifier"] = json!({
        "type": "string",
        "readOnly": true
    });
    document["components"]["schemas"]["CreateWidget"] = json!({
        "type": "object",
        "required": ["name", "server_id", "created_at", "secret"],
        "properties": {
            "name": {"type": "string"},
            "server_id": {"$ref": "#/components/schemas/ServerIdentifier"},
            "created_at": {"type": "string", "readOnly": true},
            "secret": {"type": "string", "writeOnly": true}
        }
    });
    document["paths"]["/accounts/{account_id}/widgets"]["post"] = json!({
        "operationId": "widgets-create",
        "summary": "Create widget",
        "tags": ["Widgets"],
        "requestBody": {
            "required": true,
            "content": {"application/json": {"schema": {
                "$ref": "#/components/schemas/CreateWidget"
            }}}
        }
    });

    let snapshot = normalize_openapi(&document).expect("catalog");
    let schema = snapshot
        .get("widgets-create")
        .and_then(|capability| capability.request_schema.as_ref())
        .expect("request contract");

    assert_eq!(schema["required"], json!(["name", "secret"]));
    assert_eq!(schema["properties"]["name"]["type"], "string");
    assert_eq!(schema["properties"]["secret"]["type"], "string");
    assert!(schema["properties"].get("server_id").is_none());
    assert!(schema["properties"].get("created_at").is_none());
}

fn install_request_contract_fixture(document: &mut Value) {
    document["components"]["schemas"]["Jurisdiction"] = json!({
        "type": "string",
        "description": "jurisdiction selector"
    });
    document["components"]["schemas"]["DeployFlag"] = json!({"type": "boolean"});
    document["components"]["schemas"]["Replication"] = json!({
        "type": "object",
        "required": ["mode"],
        "description": "replication configuration",
        "properties": {
            "mode": {
                "type": "string",
                "enum": ["auto", "disabled"],
                "description": "replication mode"
            }
        }
    });
    document["components"]["schemas"]["CreateRecord"] = json!({
        "type": "object",
        "required": ["name"],
        "minProperties": 1,
        "maxProperties": 4,
        "properties": {
            "name": {
                "type": "string",
                "minLength": 1,
                "maxLength": 253,
                "pattern": "^[^.]+$",
                "description": "record name"
            },
            "ttl": {
                "type": "integer",
                "minimum": 1,
                "maximum": 86400,
                "multipleOf": 1
            },
            "tags": {
                "type": "array",
                "minItems": 1,
                "maxItems": 3,
                "uniqueItems": true,
                "items": {"type": "string"}
            },
            "replication": {"$ref": "#/components/schemas/Replication"}
        }
    });
    document["paths"]["/zones/{zone_id}/dns_records"]["post"] = json!({
        "operationId": "dns-records-create",
        "summary": "Create DNS Record",
        "tags": ["DNS Records"],
        "parameters": [
            {
                "in": "header",
                "name": "cf-r2-jurisdiction",
                "schema": {"$ref": "#/components/schemas/Jurisdiction"}
            },
            {
                "in": "query",
                "name": "deploy",
                "schema": {"allOf": [{"$ref": "#/components/schemas/DeployFlag"}]}
            },
            {
                "in": "query",
                "name": "ambiguous",
                "schema": {
                    "oneOf": [
                        {"type": "string", "description": "string mode"},
                        {"type": "integer", "description": "numeric mode"}
                    ]
                }
            }
        ],
        "requestBody": {
            "required": true,
            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/CreateRecord"}}}
        }
    });
}

fn assert_request_schema_bounds(schema: &Value) {
    assert_eq!(schema["properties"]["ttl"]["type"], "integer");
    assert_eq!(schema["properties"]["ttl"]["minimum"], 1);
    assert_eq!(schema["properties"]["ttl"]["maximum"], 86400);
    assert_eq!(schema["properties"]["ttl"]["multipleOf"], 1);
    assert_eq!(schema["properties"]["name"]["minLength"], 1);
    assert_eq!(schema["properties"]["name"]["maxLength"], 253);
    assert!(schema["properties"]["name"].get("pattern").is_none());
    assert_eq!(schema["properties"]["tags"]["minItems"], 1);
    assert_eq!(schema["properties"]["tags"]["maxItems"], 3);
    assert_eq!(schema["properties"]["tags"]["uniqueItems"], true);
    assert_eq!(schema["minProperties"], 1);
    assert_eq!(schema["maxProperties"], 4);
}

#[test]
fn recursive_request_schema_contract_stops_at_the_active_reference() {
    let document = json!({
        "openapi": "3.0.3",
        "info": {"title":"Cloudflare API","version":"4.0.0"},
        "components": {"schemas": {"Node": {
            "type": "object",
            "properties": {"next": {"$ref": "#/components/schemas/Node"}}
        }}},
        "paths": {"/accounts/{account_id}/nodes": {"post": {
            "operationId": "nodes-create",
            "summary": "Create node",
            "tags": ["Nodes"],
            "requestBody": {"content": {"application/json": {"schema": {
                "$ref": "#/components/schemas/Node"
            }}}}
        }}}
    });
    let snapshot = normalize_openapi(&document).expect("recursive catalog");
    let schema = snapshot
        .get("nodes-create")
        .and_then(|capability| capability.request_schema.as_ref())
        .expect("bounded recursive contract");
    assert_eq!(schema["type"], "object");
    assert_eq!(schema["properties"]["next"], json!({}));
}

#[test]
fn request_contract_preserves_bounded_schema_composition_without_prose() {
    let document = json!({
        "openapi": "3.0.3",
        "info": {"title":"Cloudflare API","version":"4.0.0"},
        "components": {"schemas": {
            "StringResources": {
                "type": "object",
                "description": "flat resource map",
                "additionalProperties": {"type": "string", "description": "resource selector"}
            },
            "NestedResources": {
                "type": "object",
                "additionalProperties": {
                    "type": "object",
                    "additionalProperties": {"type": "string"}
                }
            },
            "Resources": {
                "oneOf": [
                    {"$ref": "#/components/schemas/StringResources"},
                    {"$ref": "#/components/schemas/NestedResources"}
                ]
            },
            "BaseSettings": {
                "type": "object",
                "required": ["mode"],
                "properties": {"mode": {"type": "string", "enum": ["on", "off"]}}
            },
            "Settings": {
                "allOf": [
                    {"$ref": "#/components/schemas/BaseSettings"},
                    {
                        "type": "object",
                        "required": ["enabled"],
                        "properties": {"enabled": {"type": "boolean"}}
                    }
                ]
            },
            "CreateToken": {
                "type": "object",
                "required": ["resources", "settings"],
                "properties": {
                    "resources": {"$ref": "#/components/schemas/Resources"},
                    "settings": {"$ref": "#/components/schemas/Settings"},
                    "signal": {
                        "anyOf": [
                            {"type": "string", "enum": ["automatic"]},
                            {"type": "integer"}
                        ]
                    }
                }
            }
        }},
        "paths": {"/accounts/{account_id}/tokens": {"post": {
            "operationId": "account-api-tokens-create-token",
            "summary": "Create token",
            "tags": ["API Tokens"],
            "requestBody": {"required": true, "content": {"application/json": {"schema": {
                "$ref": "#/components/schemas/CreateToken"
            }}}}
        }}}
    });
    let snapshot = normalize_openapi(&document).expect("composed catalog");
    let schema = snapshot
        .get("account-api-tokens-create-token")
        .and_then(|capability| capability.request_schema.as_ref())
        .expect("composed request contract");

    assert_eq!(
        schema["properties"]["resources"]["oneOf"][0],
        json!({"type": "object", "additionalProperties": {"type": "string"}})
    );
    assert_eq!(
        schema["properties"]["resources"]["oneOf"][1]["additionalProperties"]["additionalProperties"]
            ["type"],
        "string"
    );
    assert_eq!(
        schema["properties"]["settings"]["allOf"][0]["required"],
        json!(["mode"])
    );
    assert_eq!(
        schema["properties"]["settings"]["allOf"][1]["properties"]["enabled"]["type"],
        "boolean"
    );
    assert_eq!(
        schema["properties"]["signal"]["anyOf"][0]["enum"],
        json!(["automatic"])
    );
    assert!(
        !schema.to_string().contains("description"),
        "descriptive source prose must not enter the pinned request contract"
    );
}

#[test]
fn selector_types_follow_homogeneous_enums_without_guessing_mixed_values() {
    let mut document = fixture();
    let parameters = document["paths"]["/zones/{zone_id}/dns_records"]["get"]["parameters"]
        .as_array_mut()
        .expect("parameters");
    parameters.push(json!({
        "in": "query",
        "name": "sort",
        "schema": {"enum": ["asc", "desc"]}
    }));
    parameters.push(json!({
        "in": "query",
        "name": "mixed-enum",
        "schema": {"enum": ["auto", 1]}
    }));

    let snapshot = normalize_openapi(&document).expect("catalog");
    let capability = snapshot.get("dns-records-list").expect("list capability");
    let selector_type = |name| {
        capability
            .selectors
            .iter()
            .find(|selector| selector.name == name)
            .expect("selector")
            .value_type
            .as_str()
    };
    assert_eq!(selector_type("sort"), "string");
    assert_eq!(selector_type("mixed-enum"), "unknown");
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
fn stored_catalog_rejects_capability_drift_from_its_content_hash() {
    let snapshot = normalize_openapi(&fixture()).expect("catalog");
    let root = tempfile::tempdir().expect("temp catalog");
    let path = root.path().join("catalog.json");
    snapshot.save(&path).expect("save catalog");

    let mut drifted = snapshot.clone();
    "api_token_details_match_created_id_and_active_status".clone_into(
        &mut drifted
            .capabilities
            .get_mut("dns-records-delete")
            .expect("delete capability")
            .verification
            .strategy,
    );
    assert!(drifted.save(&root.path().join("drifted.json")).is_err());
    assert!(CatalogIndex::rebuild(&root.path().join("drifted.sqlite3"), &drifted).is_err());

    let mut stored: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("read stored catalog"))
            .expect("decode stored catalog");
    stored["capabilities"]["dns-records-delete"]["verification"]["strategy"] =
        json!("api_token_details_match_created_id_and_active_status");
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&stored).expect("encode tampered catalog"),
    )
    .expect("write tampered catalog");

    let error = CatalogSnapshot::load(&path)
        .expect_err("capability drift must not load")
        .to_string();

    assert!(error.contains("catalog content hash mismatch"), "{error}");
}

#[test]
fn legacy_catalog_hash_survives_absent_optional_resource_contracts() {
    let snapshot = normalize_openapi(&fixture()).expect("catalog");
    let mut stored = serde_json::to_value(&snapshot).expect("serialize catalog");
    let capabilities = stored["capabilities"]
        .as_object_mut()
        .expect("capabilities object");
    for capability in capabilities.values_mut() {
        capability
            .as_object_mut()
            .expect("capability object")
            .remove("deleted_resource");
        capability
            .as_object_mut()
            .expect("capability object")
            .remove("updated_resource");
        capability
            .as_object_mut()
            .expect("capability object")
            .remove("same_path_read");
    }
    stored["schema_hash"] = json!(hash_value(&stored["capabilities"]).expect("legacy hash"));

    let loaded: CatalogSnapshot = serde_json::from_value(stored).expect("legacy catalog decodes");

    loaded
        .validate_hash()
        .expect("legacy catalog hash remains valid");
}

#[test]
fn legacy_delete_contract_hash_survives_an_absent_default_pagination_flag() {
    let mut snapshot = normalize_openapi(&fixture()).expect("catalog");
    snapshot
        .capabilities
        .get_mut("dns-records-delete")
        .expect("delete capability")
        .deleted_resource = Some(DeletedResourceContractV1 {
        collection_path: "/zones/{zone_id}/dns_records".to_owned(),
        identity_selector: "record_id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "dns-records-list".to_owned(),
        requires_page_number_completion: false,
    });
    snapshot.refresh_hash().expect("refresh catalog hash");
    let stored = serde_json::to_value(&snapshot).expect("serialize catalog");
    assert!(
        stored["capabilities"]["dns-records-delete"]["deleted_resource"]
            .get("requires_page_number_completion")
            .is_none()
    );

    let loaded: CatalogSnapshot = serde_json::from_value(stored).expect("legacy catalog decodes");

    loaded
        .validate_hash()
        .expect("legacy delete contract hash remains valid");
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
fn search_exposes_exact_mutation_contract_debt() {
    let document = json!({
        "openapi":"3.0.3",
        "info":{"title":"Cloudflare API","version":"4.0.0"},
        "paths": {
            "/accounts/{account_id}/widgets": {
                "post": {
                    "operationId":"widgets-create",
                    "summary":"Create Widget",
                    "tags":["Widgets"],
                    "parameters":[
                        {"in":"path","name":"account_id","required":true,"schema":{"type":"string"}}
                    ]
                }
            }
        }
    });
    let mut snapshot = normalize_openapi(&document).expect("catalog");
    snapshot
        .capabilities
        .get_mut("widgets-create")
        .expect("widget capability")
        .cost
        .references
        .push(KnowledgeReferenceV1 {
            title: "Widget pricing".to_owned(),
            url: "https://developers.cloudflare.com/widgets/pricing/".to_owned(),
            source: "official fixture".to_owned(),
        });
    snapshot.refresh_hash().expect("refresh catalog hash");

    for query in [
        "verification missing",
        "rollback irreversibility missing",
        "cost unbounded",
        "permission lane missing",
    ] {
        assert_eq!(
            snapshot
                .search(query)
                .first()
                .map(|capability| capability.id.as_str()),
            Some("widgets-create"),
            "in-memory search did not expose {query}"
        );
    }

    let root = tempfile::tempdir().expect("temp catalog");
    let index = CatalogIndex::rebuild(&root.path().join("catalog.sqlite3"), &snapshot)
        .expect("rebuild index");
    for query in [
        "verification_missing",
        "rollback_or_irreversibility_missing",
        "cost_unbounded",
        "permission_lane_missing",
    ] {
        assert_eq!(
            index
                .search(query, 10)
                .expect("indexed safety search")
                .first()
                .map(|capability| capability.id.as_str()),
            Some("widgets-create"),
            "indexed search did not expose {query}"
        );
    }
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

#[test]
fn user_token_creation_stays_blocked_without_a_permission_inventory_workflow() {
    let mut document = fixture();
    document["paths"]["/user/tokens"]["post"] = json!({
        "operationId":"user-api-tokens-create-token",
        "summary":"Create Token",
        "tags":["User API Tokens"],
        "x-api-token-group":["API Tokens Write"]
    });

    let snapshot = normalize_openapi(&document).expect("user token catalog");
    let capability = snapshot
        .get("user-api-tokens-create-token")
        .expect("user token create");

    assert_eq!(capability.adapter_status, AdapterStatus::Blocked);
    assert!(
        capability
            .blocked_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("permission inventory"))
    );
    let coverage = snapshot.coverage();
    assert_eq!(coverage.complete_mutation_contracts, 0);
    assert_eq!(coverage.blocked_adapters_without_contract_gaps, 1);
}

#[test]
fn coverage_names_every_unresolved_mutation_contract_class() {
    let document = json!({
        "openapi":"3.0.3",
        "info":{"title":"Cloudflare API","version":"4.0.0"},
        "paths": {
            "/accounts/{account_id}/widgets": {
                "post": {
                    "operationId":"widgets-create",
                    "summary":"Create Widget",
                    "tags":["Widgets"],
                    "x-cfPlanAvailability":{"free":false,"pro":false,"business":false,"enterprise":true},
                    "parameters":[
                        {"in":"path","name":"account_id","required":true,"schema":{"type":"string"}}
                    ]
                }
            }
        }
    });

    let mut snapshot = normalize_openapi(&document).expect("catalog");
    let coverage = snapshot.coverage();

    assert_eq!(coverage.capabilities_with_mutation_contract_gaps, 1);
    assert_eq!(coverage.blocked_adapters_without_contract_gaps, 0);
    for gap in [
        "risk_unknown",
        "effect_unknown",
        "cost_unknown",
        "verification_missing",
        "rollback_or_irreversibility_missing",
        "permission_lane_missing",
        "entitlement_unresolved",
    ] {
        assert_eq!(
            coverage.mutation_contract_gap_counts.get(gap),
            Some(&1),
            "missing coverage for {gap}"
        );
    }
    assert_eq!(
        coverage.mutation_contract_gap_counts.get("unclassified"),
        None
    );

    snapshot
        .capabilities
        .get_mut("widgets-create")
        .expect("widget capability")
        .cost
        .references
        .push(KnowledgeReferenceV1 {
            title: "Widget pricing".to_owned(),
            url: "https://developers.cloudflare.com/widgets/pricing/".to_owned(),
            source: "official fixture".to_owned(),
        });
    let priced_coverage = snapshot.coverage();
    assert_eq!(
        priced_coverage
            .mutation_contract_gap_counts
            .get("cost_unbounded"),
        Some(&1)
    );
    assert_eq!(
        priced_coverage
            .mutation_contract_gap_counts
            .get("cost_unknown"),
        None
    );
}

#[test]
fn coverage_names_declared_but_unsupported_runtime_contracts() {
    let mut snapshot = normalize_openapi(&fixture()).expect("catalog");
    let capability = snapshot
        .capabilities
        .get_mut("dns-records-delete")
        .expect("delete capability");
    capability.verification.strategy = "phantom_readback".to_owned();
    capability.rollback.supported = true;
    capability.rollback.strategy = Some("phantom_restore".to_owned());

    let coverage = snapshot.coverage();

    assert_eq!(
        coverage
            .mutation_contract_gap_counts
            .get("verification_unsupported"),
        Some(&1)
    );
    assert_eq!(
        coverage
            .mutation_contract_gap_counts
            .get("rollback_unsupported"),
        Some(&1)
    );
    assert_eq!(
        coverage.mutation_contract_gap_counts.get("unclassified"),
        None
    );
}

#[test]
fn dns_record_crud_has_complete_operation_specific_contracts() {
    let mut document = fixture();
    document["paths"]["/zones/{zone_id}/dns_records"]["post"] = json!({
        "operationId":"dns-records-for-a-zone-create-dns-record",
        "summary":"Create DNS Record",
        "tags":["DNS Records for a Zone"],
        "x-api-token-group":["DNS Write"],
        "x-cfPlanAvailability":{"free":true,"pro":true,"business":true,"enterprise":true}
    });
    for (method, id, summary) in [
        (
            "patch",
            "dns-records-for-a-zone-patch-dns-record",
            "Update DNS Record",
        ),
        (
            "put",
            "dns-records-for-a-zone-update-dns-record",
            "Overwrite DNS Record",
        ),
        (
            "delete",
            "dns-records-for-a-zone-delete-dns-record",
            "Delete DNS Record",
        ),
    ] {
        document["paths"]["/zones/{zone_id}/dns_records/{dns_record_id}"][method] = json!({
            "operationId":id,
            "summary":summary,
            "tags":["DNS Records for a Zone"],
            "x-api-token-group":["DNS Write"],
            "x-cfPlanAvailability":{"free":true,"pro":true,"business":true,"enterprise":true},
            "parameters":[
                {"in":"path","name":"zone_id","required":true,"schema":{"type":"string"}},
                {"in":"path","name":"dns_record_id","required":true,"schema":{"type":"string"}}
            ]
        });
    }

    let snapshot = normalize_openapi(&document).expect("DNS record catalog");
    for id in [
        "dns-records-for-a-zone-create-dns-record",
        "dns-records-for-a-zone-patch-dns-record",
        "dns-records-for-a-zone-update-dns-record",
        "dns-records-for-a-zone-delete-dns-record",
    ] {
        let capability = snapshot.get(id).expect("DNS record capability");
        assert_eq!(capability.adapter_status, AdapterStatus::DynamicApi);
        assert!(capability.cost.known);
        assert_eq!(capability.cost.maximum, Some(0.0));
        assert_eq!(capability.cost.exposure, CostExposureV1::DownstreamUsage);
        assert_eq!(capability.cost.references.len(), 2);
        assert!(
            capability
                .cost
                .references
                .iter()
                .any(|reference| reference.url == "https://developers.cloudflare.com/dns/faq/")
        );
        assert!(capability.mutation_contract_gaps().is_empty());
    }

    let create = snapshot
        .get("dns-records-for-a-zone-create-dns-record")
        .expect("create DNS record");
    assert_eq!(create.risk, RiskClass::ScopedWrite);
    assert_eq!(create.effect, EffectClass::ReversibleWrite);
    assert!(create.rollback.supported);
    assert_eq!(
        create.rollback.strategy.as_deref(),
        Some("delete_created_dns_record_by_returned_id")
    );

    let delete = snapshot
        .get("dns-records-for-a-zone-delete-dns-record")
        .expect("delete DNS record");
    assert_eq!(delete.risk, RiskClass::Destructive);
    assert!(
        delete
            .rollback
            .warning
            .as_deref()
            .is_some_and(|warning| warning.contains("prior record snapshot"))
    );
}

#[test]
fn exact_resource_deletes_pair_with_same_path_readback_contracts() {
    let document = json!({
        "openapi": "3.0.3",
        "info": {"title":"Cloudflare API","version":"4.0.0"},
        "paths": {
            "/accounts/{account_id}/widgets/{widget_id}": {
                "parameters": [
                    {"in":"path","name":"account_id","required":true,"schema":{"type":"string"}},
                    {"in":"path","name":"widget_id","required":true,"schema":{"type":"string"}}
                ],
                "get": {
                    "operationId":"widgets-get",
                    "summary":"Get Widget",
                    "tags":["R2 Object"],
                    "parameters":[
                        {"in":"header","name":"cf-r2-jurisdiction","required":false,"schema":{"type":"string"}},
                        {"in":"header","name":"If-None-Match","required":false,"schema":{"type":"string"}},
                        {"in":"header","name":"If-Modified-Since","required":false,"schema":{"type":"string"}}
                    ],
                    "x-api-token-group":["Widgets Read"]
                },
                "delete": {
                    "operationId":"widgets-delete",
                    "summary":"Delete Widget",
                    "tags":["R2 Object"],
                    "parameters":[
                        {"in":"header","name":"cf-r2-jurisdiction","required":false,"schema":{"type":"string"}}
                    ],
                    "x-api-token-group":["Widgets Write"]
                }
            },
            "/accounts/{account_id}/widgets": {
                "get": {
                    "operationId":"widgets-list",
                    "summary":"List Widgets",
                    "tags":["Widgets"]
                },
                "delete": {
                    "operationId":"widgets-delete-all",
                    "summary":"Delete All Widgets",
                    "tags":["Widgets"],
                    "x-api-token-group":["Widgets Write"]
                }
            }
        }
    });

    let snapshot = normalize_openapi(&document).expect("widget catalog");
    let exact = snapshot.get("widgets-delete").expect("exact delete");
    assert_eq!(exact.adapter_status, AdapterStatus::DynamicApi);
    assert_eq!(exact.risk, RiskClass::Destructive);
    assert_eq!(exact.effect, EffectClass::Destructive);
    assert_eq!(exact.cost.maximum, Some(0.0));
    assert_eq!(
        exact.verification.strategy,
        "same_resource_returns_not_found_after_delete"
    );
    let target = exact
        .same_path_read
        .as_ref()
        .expect("hash-bound same-path readback");
    assert_eq!(target.path, exact.path);
    assert_eq!(target.read_capability_id, "widgets-get");
    assert!(target.verified_response_fields.is_empty());
    assert!(!exact.rollback.supported);
    assert!(
        exact
            .rollback
            .warning
            .as_deref()
            .is_some_and(|warning| warning.contains("prior resource snapshot"))
    );
    assert!(exact.mutation_contract_gaps().is_empty());

    let collection = snapshot
        .get("widgets-delete-all")
        .expect("collection delete");
    assert_eq!(collection.adapter_status, AdapterStatus::Blocked);
    assert_ne!(
        collection.verification.strategy,
        "same_resource_returns_not_found_after_delete"
    );
}

#[test]
fn exact_resource_deletes_reject_broadening_inputs_and_required_read_controls() {
    let document = json!({
        "openapi": "3.0.3",
        "info": {"title":"Cloudflare API","version":"4.0.0"},
        "paths": {
            "/accounts/{account_id}/widgets/{widget_id}": {
                "parameters": [
                    {"in":"path","name":"account_id","required":true,"schema":{"type":"string"}},
                    {"in":"path","name":"widget_id","required":true,"schema":{"type":"string"}}
                ],
                "get": {
                    "operationId":"widgets-get",
                    "summary":"Get Widget",
                    "tags":["Widgets"]
                },
                "delete": {
                    "operationId":"widgets-delete",
                    "summary":"Delete Widget",
                    "tags":["Widgets"],
                    "x-api-token-group":["Widgets Write"]
                }
            }
        }
    });

    let mut body = document.clone();
    body["paths"]["/accounts/{account_id}/widgets/{widget_id}"]["delete"]["requestBody"] = json!({"content":{"application/json":{"schema":{
        "type":"object","properties":{"cascade":{"type":"boolean"}}
    }}}});
    let body_snapshot = normalize_openapi(&body).expect("delete-body catalog");
    assert_ne!(
        body_snapshot
            .get("widgets-delete")
            .expect("delete widget")
            .verification
            .strategy,
        "same_resource_returns_not_found_after_delete"
    );

    let mut delete_query = document.clone();
    delete_query["paths"]["/accounts/{account_id}/widgets/{widget_id}"]["delete"]["parameters"] = json!([
        {"in":"query","name":"cascade","required":false,"schema":{"type":"boolean"}}
    ]);
    let delete_query_snapshot = normalize_openapi(&delete_query).expect("delete-query catalog");
    assert_ne!(
        delete_query_snapshot
            .get("widgets-delete")
            .expect("delete widget")
            .verification
            .strategy,
        "same_resource_returns_not_found_after_delete"
    );

    let mut required_read_query = document;
    required_read_query["paths"]["/accounts/{account_id}/widgets/{widget_id}"]["get"]["parameters"] = json!([
        {"in":"query","name":"view","required":true,"schema":{"type":"string"}}
    ]);
    let read_query_snapshot =
        normalize_openapi(&required_read_query).expect("required-read-query catalog");
    assert_ne!(
        read_query_snapshot
            .get("widgets-delete")
            .expect("delete widget")
            .verification
            .strategy,
        "same_resource_returns_not_found_after_delete"
    );
}

fn assert_d1_update_contract(update: &CapabilityV1) {
    assert_eq!(
        update.verification.strategy,
        "same_resource_contains_planned_fields_after_update"
    );
    assert_eq!(update.adapter_status, AdapterStatus::DynamicApi);
    assert_eq!(update.risk, RiskClass::ScopedWrite);
    assert_eq!(update.effect, EffectClass::ReversibleWrite);
    assert_eq!(update.cost.maximum, Some(0.0));
    assert_eq!(update.cost.references.len(), 2);
    assert!(
        update
            .cost
            .basis
            .as_deref()
            .is_some_and(|basis| basis.contains("no incremental operation or replica charge"))
    );
    assert!(!update.rollback.supported);
    assert_eq!(
        update.request_schema.as_ref().expect("request schema")["properties"]["read_replication"]["properties"]
            ["mode"]["enum"],
        json!(["auto", "disabled"])
    );
}

#[test]
fn d1_database_readback_omits_only_the_documented_fields_projection() {
    let document = json!({
        "openapi": "3.0.3",
        "info": {"title":"Cloudflare API","version":"4.0.0"},
        "components": {"schemas": {"D1ReadReplication": {
            "type": "object",
            "required": ["mode"],
            "properties": {"mode": {"type": "string", "enum": ["auto", "disabled"]}}
        }}},
        "paths": {
            "/accounts/{account_id}/d1/database/{database_id}": {
                "parameters": [
                    {"in":"path","name":"account_id","required":true,"schema":{"type":"string"}},
                    {"in":"path","name":"database_id","required":true,"schema":{"type":"string"}}
                ],
                "get": {
                    "operationId":"d1-get-database",
                    "summary":"Get D1 Database",
                    "tags":["D1"],
                    "parameters":[{
                        "description":"Comma-separated list of fields to include in the response. When omitted, all fields are returned.",
                        "in":"query",
                        "name":"fields",
                        "required":false,
                        "schema":{"type":"array","items":{"type":"string"}}
                    }],
                    "responses":{"200":{"description":"ok","content":{"application/json":{"schema":{
                        "type":"object","properties":{"result":{"type":"object","properties":{
                            "read_replication":{"type":"object"}
                        }}}
                    }}}}}
                },
                "patch": {
                    "operationId":"d1-update-partial-database",
                    "summary":"Update D1 Database partially",
                    "tags":["D1"],
                    "x-api-token-group":["D1 Write"],
                    "requestBody":{"content":{"application/json":{"schema":{
                        "type":"object","properties":{"read_replication":{
                            "$ref":"#/components/schemas/D1ReadReplication"
                        }}
                    }}}}
                },
                "delete": {
                    "operationId":"d1-delete-database",
                    "summary":"Delete D1 Database",
                    "tags":["D1"],
                    "x-api-token-group":["D1 Write"]
                }
            }
        }
    });

    let snapshot = normalize_openapi(&document).expect("D1 catalog");
    assert_eq!(
        snapshot
            .get("d1-delete-database")
            .expect("delete D1 database")
            .verification
            .strategy,
        "same_resource_returns_not_found_after_delete"
    );
    let update = snapshot
        .get("d1-update-partial-database")
        .expect("update D1 database");
    assert_d1_update_contract(update);

    let mut drifted_mode = document.clone();
    drifted_mode["components"]["schemas"]["D1ReadReplication"]["properties"]["mode"]["enum"] =
        json!(["auto", "disabled", "experimental"]);
    let drifted_snapshot = normalize_openapi(&drifted_mode).expect("drifted D1 catalog");
    assert_eq!(
        drifted_snapshot
            .get("d1-update-partial-database")
            .expect("drifted update")
            .adapter_status,
        AdapterStatus::Blocked
    );

    let mut unrelated = document;
    unrelated["paths"]["/accounts/{account_id}/d1/database/{database_id}"]["get"]["tags"] =
        json!(["Widgets"]);
    unrelated["paths"]["/accounts/{account_id}/d1/database/{database_id}"]["delete"]["tags"] =
        json!(["Widgets"]);
    let unrelated_snapshot = normalize_openapi(&unrelated).expect("unrelated catalog");
    assert_ne!(
        unrelated_snapshot
            .get("d1-delete-database")
            .expect("unrelated delete")
            .verification
            .strategy,
        "same_resource_returns_not_found_after_delete"
    );
    assert_eq!(
        unrelated_snapshot
            .get("d1-update-partial-database")
            .expect("unrelated update")
            .adapter_status,
        AdapterStatus::Blocked
    );
}

#[test]
fn exact_resource_deletes_use_schema_proven_parent_collection_readback() {
    let document = json!({
        "openapi": "3.0.3",
        "info": {"title":"Cloudflare API","version":"4.0.0"},
        "paths": {
            "/accounts/{account_id}/widgets": {
                "parameters": [
                    {"in":"path","name":"account_id","required":true,"schema":{"type":"string"}}
                ],
                "get": {
                    "operationId":"widgets-list",
                    "summary":"List Widgets",
                    "tags":["Widgets"],
                    "x-api-token-group":["Widgets Read"],
                    "responses":{"200":{"description":"ok","content":{"application/json":{"schema":{
                        "type":"object",
                        "properties":{"result":{"type":"array","items":{"type":"object","properties":{
                            "id":{"type":"string"},"name":{"type":"string"}
                        }}}}
                    }}}}}
                }
            },
            "/accounts/{account_id}/widgets/{widget_id}": {
                "parameters": [
                    {"in":"path","name":"account_id","required":true,"schema":{"type":"string"}},
                    {"in":"path","name":"widget_id","required":true,"schema":{"type":"string"}}
                ],
                "delete": {
                    "operationId":"widgets-delete",
                    "summary":"Delete Widget",
                    "tags":["Widgets"],
                    "x-api-token-group":["Widgets Write"]
                }
            }
        }
    });

    let snapshot = normalize_openapi(&document).expect("widget catalog");
    let capability = snapshot.get("widgets-delete").expect("delete widget");
    assert_eq!(capability.adapter_status, AdapterStatus::DynamicApi);
    assert_eq!(
        capability.verification.strategy,
        "parent_collection_omits_deleted_resource_id"
    );
    let target = capability
        .deleted_resource
        .as_ref()
        .expect("deleted-resource contract");
    assert_eq!(target.collection_path, "/accounts/{account_id}/widgets");
    assert_eq!(target.identity_selector, "widget_id");
    assert_eq!(target.response_item_identity_pointer, "/id");
    assert_eq!(target.read_capability_id, "widgets-list");
    assert!(!target.requires_page_number_completion);
    assert_eq!(capability.cost.exposure, CostExposureV1::DownstreamUsage);
    assert!(capability.mutation_contract_gaps().is_empty());
}

#[test]
fn parent_collection_delete_contracts_reject_unverifiable_pagination_and_broadening_bodies() {
    let mut document = json!({
        "openapi": "3.0.3",
        "info": {"title":"Cloudflare API","version":"4.0.0"},
        "paths": {
            "/accounts/{account_id}/widgets": {
                "get": {
                    "operationId":"widgets-list",
                    "summary":"List Widgets",
                    "tags":["Widgets"],
                    "parameters":[
                        {"in":"path","name":"account_id","required":true,"schema":{"type":"string"}},
                        {"in":"query","name":"page","schema":{"type":"integer"}},
                        {"in":"query","name":"per_page","schema":{"type":"integer"}}
                    ],
                    "responses":{"200":{"description":"ok","content":{"application/json":{"schema":{
                        "type":"object",
                        "properties":{"result":{"type":"array","items":{"type":"object","properties":{
                            "id":{"type":"string"}
                        }}}}
                    }}}}}
                }
            },
            "/accounts/{account_id}/widgets/{widget_id}": {
                "parameters": [
                    {"in":"path","name":"account_id","required":true,"schema":{"type":"string"}},
                    {"in":"path","name":"widget_id","required":true,"schema":{"type":"string"}}
                ],
                "delete": {
                    "operationId":"widgets-delete",
                    "summary":"Delete Widget",
                    "tags":["Widgets"],
                    "x-api-token-group":["Widgets Write"]
                }
            }
        }
    });

    let paginated = normalize_openapi(&document).expect("paginated catalog");
    let delete = paginated.get("widgets-delete").expect("delete widget");
    assert!(delete.deleted_resource.is_none());
    assert_ne!(
        delete.verification.strategy,
        "parent_collection_omits_deleted_resource_id"
    );

    document["paths"]["/accounts/{account_id}/widgets"]["get"]["responses"]["200"]["content"]["application/json"]
        ["schema"]["properties"]["result_info"] = json!({
        "type":"object",
        "properties":{"page":{"type":"integer"},"total_pages":{"type":"integer"}}
    });
    let supported = normalize_openapi(&document).expect("supported paginated catalog");
    let target = supported
        .get("widgets-delete")
        .and_then(|capability| capability.deleted_resource.as_ref())
        .expect("page-number collection contract");
    assert!(target.requires_page_number_completion);

    document["paths"]["/accounts/{account_id}/widgets/{widget_id}"]["delete"]["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{
        "type":"object","properties":{"cascade":{"type":"boolean"}}
    }}}});

    let broadening = normalize_openapi(&document).expect("broadening catalog");
    let delete = broadening.get("widgets-delete").expect("delete widget");
    assert!(delete.deleted_resource.is_none());
    assert_ne!(
        delete.verification.strategy,
        "parent_collection_omits_deleted_resource_id"
    );
}

#[test]
fn exact_resource_updates_use_schema_proven_parent_collection_fields() {
    let document = json!({
        "openapi": "3.0.3",
        "info": {"title":"Cloudflare API","version":"4.0.0"},
        "paths": {
            "/accounts/{account_id}/widgets": {
                "get": {
                    "operationId":"widgets-list",
                    "summary":"List Widgets",
                    "tags":["Widgets"],
                    "parameters":[
                        {"in":"path","name":"account_id","required":true,"schema":{"type":"string"}}
                    ],
                    "responses":{"200":{"description":"ok","content":{"application/json":{"schema":{
                        "type":"object",
                        "properties":{"result":{"type":"array","items":{"type":"object","properties":{
                            "id":{"type":"string"},"enabled":{"type":"boolean"},"name":{"type":"string"}
                        }}}}
                    }}}}}
                }
            },
            "/accounts/{account_id}/widgets/{widget_id}": {
                "parameters": [
                    {"in":"path","name":"account_id","required":true,"schema":{"type":"string"}},
                    {"in":"path","name":"widget_id","required":true,"schema":{"type":"string"}}
                ],
                "patch": {
                    "operationId":"widgets-update",
                    "summary":"Update Widget",
                    "tags":["Widgets"],
                    "x-api-token-group":["Widgets Write"],
                    "requestBody":{"required":true,"content":{"application/json":{"schema":{
                        "type":"object","properties":{"name":{"type":"string"},"enabled":{"type":"boolean"}}
                    }}}}
                }
            }
        }
    });

    let snapshot = normalize_openapi(&document).expect("widget catalog");
    let capability = snapshot.get("widgets-update").expect("update widget");
    assert_eq!(
        capability.verification.strategy,
        "parent_collection_item_contains_planned_fields_after_update"
    );
    let target = capability
        .updated_resource
        .as_ref()
        .expect("updated-resource contract");
    assert_eq!(target.collection_path, "/accounts/{account_id}/widgets");
    assert_eq!(target.identity_selector, "widget_id");
    assert_eq!(target.response_item_identity_pointer, "/id");
    assert_eq!(target.read_capability_id, "widgets-list");
    assert_eq!(target.verified_response_fields, ["enabled", "name"]);
    assert!(!target.requires_page_number_completion);
    assert!(
        capability
            .mutation_contract_gaps()
            .iter()
            .all(|gap| !gap.contains("verification") && !gap.contains("rollback"))
    );
}

#[test]
fn parent_collection_update_contracts_reject_unobservable_fields_and_update_modes() {
    let mut document = json!({
        "openapi": "3.0.3",
        "info": {"title":"Cloudflare API","version":"4.0.0"},
        "paths": {
            "/accounts/{account_id}/widgets": {
                "get": {
                    "operationId":"widgets-list",
                    "summary":"List Widgets",
                    "tags":["Widgets"],
                    "responses":{"200":{"description":"ok","content":{"application/json":{"schema":{
                        "type":"object","properties":{"result":{"type":"array","items":{"type":"object","properties":{
                            "id":{"type":"string"},"name":{"type":"string"}
                        }}}}
                    }}}}}
                }
            },
            "/accounts/{account_id}/widgets/{widget_id}": {
                "parameters": [
                    {"in":"path","name":"account_id","required":true,"schema":{"type":"string"}},
                    {"in":"path","name":"widget_id","required":true,"schema":{"type":"string"}}
                ],
                "patch": {
                    "operationId":"widgets-update",
                    "summary":"Update Widget",
                    "tags":["Widgets"],
                    "x-api-token-group":["Widgets Write"],
                    "requestBody":{"required":true,"content":{"application/json":{"schema":{
                        "type":"object","properties":{"name":{"type":"string"},"hidden":{"type":"boolean"}}
                    }}}}
                }
            }
        }
    });

    let unobservable = normalize_openapi(&document).expect("unobservable catalog");
    assert!(
        unobservable
            .get("widgets-update")
            .expect("update widget")
            .updated_resource
            .is_none()
    );

    document["paths"]["/accounts/{account_id}/widgets/{widget_id}"]["patch"]["requestBody"]["content"]
        ["application/json"]["schema"]["properties"] = json!({"name":{"type":"string"}});
    document["paths"]["/accounts/{account_id}/widgets/{widget_id}"]["patch"]["parameters"] =
        json!([{"in":"query","name":"mode","schema":{"type":"string"}}]);
    let modal = normalize_openapi(&document).expect("modal catalog");
    assert!(
        modal
            .get("widgets-update")
            .expect("update widget")
            .updated_resource
            .is_none()
    );

    document["paths"]["/accounts/{account_id}/widgets/{widget_id}"]["patch"]["parameters"] =
        json!([]);
    let paths = document["paths"].as_object_mut().expect("paths object");
    let mut detail = paths
        .remove("/accounts/{account_id}/widgets/{widget_id}")
        .expect("detail path");
    detail["parameters"][1]["name"] = json!("widget_slug");
    paths.insert(
        "/accounts/{account_id}/widgets/{widget_slug}".to_owned(),
        detail,
    );
    let slug_target = normalize_openapi(&document).expect("slug-target catalog");
    assert!(
        slug_target
            .get("widgets-update")
            .expect("update widget")
            .updated_resource
            .is_none()
    );
}

fn exact_resource_update_fixture() -> serde_json::Value {
    json!({
        "openapi": "3.0.3",
        "info": {"title":"Cloudflare API","version":"4.0.0"},
        "paths": {
            "/accounts/{account_id}/widgets/{widget_id}": {
                "parameters": [
                    {"in":"path","name":"account_id","required":true,"schema":{"type":"string"}},
                    {"in":"path","name":"widget_id","required":true,"schema":{"type":"string"}}
                ],
                "get": {
                    "operationId":"widgets-get",
                    "summary":"Get Widget",
                    "tags":["R2 Bucket"],
                    "parameters":[
                        {"in":"header","name":"cf-r2-jurisdiction","required":false,"schema":{"type":"string"}}
                    ],
                    "responses":{"200":{"description":"ok","content":{"application/json":{"schema":{
                        "type":"object","properties":{"result":{"type":"object","properties":{
                            "name":{"type":"string"},"enabled":{"type":"boolean"}
                        }}}
                    }}}}}
                },
                "patch": {
                    "operationId":"widgets-patch",
                    "summary":"Patch Widget",
                    "tags":["R2 Bucket"],
                    "parameters":[
                        {"in":"header","name":"cf-r2-jurisdiction","required":false,"schema":{"type":"string"}}
                    ],
                    "x-api-token-group":["Widgets Write"],
                    "requestBody":{"required":true,"content":{"application/json":{"schema":{
                        "type":"object","properties":{"enabled":{"type":"boolean"},"name":{"type":"string"}}
                    }}}}
                },
                "put": {
                    "operationId":"widgets-update",
                    "summary":"Update Widget",
                    "tags":["R2 Bucket"],
                    "parameters":[
                        {"in":"header","name":"cf-r2-jurisdiction","required":false,"schema":{"type":"string"}}
                    ],
                    "x-api-token-group":["Widgets Write"],
                    "requestBody":{"required":true,"content":{"application/json":{"schema":{
                        "type":"object","properties":{"enabled":{"type":"boolean"},"name":{"type":"string"}}
                    }}}}
                }
            },
            "/accounts/{account_id}/widgets": {
                "get": {
                    "operationId":"widgets-list",
                    "summary":"List Widgets",
                    "tags":["Widgets"]
                },
                "put": {
                    "operationId":"widgets-replace-all",
                    "summary":"Replace All Widgets",
                    "tags":["Widgets"],
                    "x-api-token-group":["Widgets Write"]
                }
            }
        }
    })
}

#[test]
fn exact_resource_updates_pair_with_same_path_field_readback_contracts() {
    let document = exact_resource_update_fixture();

    let snapshot = normalize_openapi(&document).expect("widget catalog");
    for id in ["widgets-patch", "widgets-update"] {
        let exact = snapshot.get(id).expect("exact update");
        assert_eq!(
            exact.verification.strategy,
            "same_resource_contains_planned_fields_after_update"
        );
        let target = exact
            .same_path_read
            .as_ref()
            .expect("hash-bound same-path readback");
        assert_eq!(target.path, exact.path);
        assert_eq!(target.read_capability_id, "widgets-get");
        assert_eq!(target.verified_response_fields, ["enabled", "name"]);
        assert!(!exact.rollback.supported);
        assert!(
            exact
                .rollback
                .warning
                .as_deref()
                .is_some_and(|warning| warning.contains("pre-change snapshot"))
        );
        let gaps = exact.mutation_contract_gaps();
        assert!(gaps.iter().all(|gap| !gap.contains("verification")));
        assert!(gaps.iter().all(|gap| !gap.contains("rollback")));
        assert_eq!(exact.adapter_status, AdapterStatus::Blocked);
    }

    let collection = snapshot
        .get("widgets-replace-all")
        .expect("collection update");
    assert_ne!(
        collection.verification.strategy,
        "same_resource_contains_planned_fields_after_update"
    );
    let coverage = snapshot.coverage();
    assert_eq!(coverage.verification_contracts, 2);
    assert_eq!(coverage.rollback_contracts, 2);

    let mut hidden_field = document.clone();
    hidden_field["paths"]["/accounts/{account_id}/widgets/{widget_id}"]["patch"]["requestBody"]["content"]
        ["application/json"]["schema"]["properties"]["hidden"] = json!({"type":"boolean"});
    let hidden_snapshot = normalize_openapi(&hidden_field).expect("hidden-field update catalog");
    assert_ne!(
        hidden_snapshot
            .get("widgets-patch")
            .expect("patch widget")
            .verification
            .strategy,
        "same_resource_contains_planned_fields_after_update"
    );

    let mut update_query = document.clone();
    update_query["paths"]["/accounts/{account_id}/widgets/{widget_id}"]["patch"]["parameters"] =
        json!([{"in":"query","name":"mode","schema":{"type":"string"}}]);
    let update_query_snapshot = normalize_openapi(&update_query).expect("update-query catalog");
    assert_ne!(
        update_query_snapshot
            .get("widgets-patch")
            .expect("patch widget")
            .verification
            .strategy,
        "same_resource_contains_planned_fields_after_update"
    );

    let mut required_read_query = document;
    required_read_query["paths"]["/accounts/{account_id}/widgets/{widget_id}"]["get"]["parameters"] = json!([
        {"in":"query","name":"view","required":true,"schema":{"type":"string"}}
    ]);
    let read_query_snapshot =
        normalize_openapi(&required_read_query).expect("required-read-query update catalog");
    assert_ne!(
        read_query_snapshot
            .get("widgets-patch")
            .expect("patch widget")
            .verification
            .strategy,
        "same_resource_contains_planned_fields_after_update"
    );
}

#[test]
fn update_contract_accepts_properties_without_an_explicit_object_type() {
    let mut implicit_object = exact_resource_update_fixture();
    implicit_object["paths"]["/accounts/{account_id}/widgets/{widget_id}"]["patch"]["requestBody"]
        ["content"]["application/json"]["schema"]
        .as_object_mut()
        .expect("patch request schema")
        .remove("type");
    let implicit_snapshot =
        normalize_openapi(&implicit_object).expect("implicit-object update catalog");
    assert_eq!(
        implicit_snapshot
            .get("widgets-patch")
            .expect("implicit-object patch")
            .verification
            .strategy,
        "same_resource_contains_planned_fields_after_update"
    );

    implicit_object["paths"]["/accounts/{account_id}/widgets/{widget_id}"]["patch"]["requestBody"]
        ["content"]["application/json"]["schema"]["type"] = json!("string");
    let non_object_snapshot =
        normalize_openapi(&implicit_object).expect("explicit non-object update catalog");
    assert_ne!(
        non_object_snapshot
            .get("widgets-patch")
            .expect("non-object patch")
            .verification
            .strategy,
        "same_resource_contains_planned_fields_after_update"
    );
}

#[test]
fn update_contract_unions_all_of_fields_and_excludes_write_only_inputs() {
    let mut document = exact_resource_update_fixture();
    document["paths"]["/accounts/{account_id}/widgets/{widget_id}"]["patch"]["requestBody"]["content"]
        ["application/json"]["schema"] = json!({
        "allOf": [
            {
                "type":"object",
                "properties": {
                    "name":{"type":"string"},
                    "secret":{"type":"string", "writeOnly":true}
                }
            },
            {
                "properties": {
                    "enabled":{"type":"boolean"}
                }
            }
        ]
    });

    let snapshot = normalize_openapi(&document).expect("allOf update catalog");
    let patch = snapshot.get("widgets-patch").expect("allOf patch");
    assert_eq!(
        patch.verification.strategy,
        "same_resource_contains_planned_fields_after_update"
    );
    assert_eq!(
        patch
            .same_path_read
            .as_ref()
            .expect("same-path readback")
            .verified_response_fields,
        ["enabled", "name"]
    );
    assert!(patch.request_object_field_is_write_only("secret"));

    document["paths"]["/accounts/{account_id}/widgets/{widget_id}"]["patch"]["requestBody"]["content"]
        ["application/json"]["schema"]["allOf"][1]["type"] = json!("string");
    let conflicting = normalize_openapi(&document).expect("conflicting allOf catalog");
    assert_ne!(
        conflicting
            .get("widgets-patch")
            .expect("conflicting patch")
            .verification
            .strategy,
        "same_resource_contains_planned_fields_after_update"
    );

    document["paths"]["/accounts/{account_id}/widgets/{widget_id}"]["patch"]["requestBody"]["content"]
        ["application/json"]["schema"] = json!({
        "oneOf": [
            {"type":"object", "properties":{
                "name":{"type":"string"},
                "secret":{"type":"string", "writeOnly":true}
            }},
            {"type":"object", "properties":{"enabled":{"type":"boolean"}}}
        ]
    });
    let alternatives = normalize_openapi(&document).expect("oneOf update catalog");
    let patch = alternatives.get("widgets-patch").expect("oneOf patch");
    assert_eq!(
        patch.verification.strategy,
        "same_resource_contains_planned_fields_after_update"
    );
    assert_eq!(
        patch
            .same_path_read
            .as_ref()
            .expect("alternative readback")
            .verified_response_fields,
        ["enabled", "name"]
    );
    assert!(patch.request_object_field_is_write_only("secret"));

    document["paths"]["/accounts/{account_id}/widgets/{widget_id}"]["patch"]["requestBody"]["content"]
        ["application/json"]["schema"]["properties"] = json!({"name":{"type":"string"}});
    let direct_with_alternatives =
        normalize_openapi(&document).expect("direct fields with oneOf catalog");
    let patch = direct_with_alternatives
        .get("widgets-patch")
        .expect("direct-field oneOf patch");
    assert_eq!(
        patch.verification.strategy,
        "same_resource_contains_planned_fields_after_update"
    );
    assert_eq!(
        patch
            .same_path_read
            .as_ref()
            .expect("direct-field readback")
            .verified_response_fields,
        ["enabled", "name"]
    );
}

#[test]
fn same_path_object_updates_require_schema_proven_readback_fields() {
    let document = json!({
        "openapi":"3.0.3",
        "info":{"title":"Cloudflare API","version":"4.0.0"},
        "paths": {
            "/zones/{zone_id}/settings/example": {
                "get": {
                    "operationId":"settings-get",
                    "tags":["R2 Bucket"],
                    "parameters":[
                        {"in":"header","name":"cf-r2-jurisdiction","required":false,"schema":{"type":"string"}}
                    ],
                    "responses":{"200":{"description":"ok","content":{"application/json":{"schema":{
                        "type":"object",
                        "properties":{"result":{"type":"object","properties":{
                            "mode":{"type":"string"},"enabled":{"type":"boolean"}
                        }}}
                    }}}}}
                },
                "put": {
                    "operationId":"settings-update",
                    "tags":["R2 Bucket"],
                    "parameters":[
                        {"in":"header","name":"cf-r2-jurisdiction","required":false,"schema":{"type":"string"}}
                    ],
                    "x-api-token-group":["Settings Write"],
                    "requestBody":{"required":true,"content":{"application/json":{"schema":{
                        "type":"object",
                        "properties":{"mode":{"type":"string"},"enabled":{"type":"boolean"}}
                    }}}}
                }
            },
            "/zones/{zone_id}/settings/partial": {
                "get": {
                    "operationId":"partial-settings-get",
                    "tags":["Partial Settings"],
                    "responses":{"200":{"description":"ok","content":{"application/json":{"schema":{
                        "type":"object",
                        "properties":{"result":{"type":"object","properties":{"mode":{"type":"string"}}}}
                    }}}}}
                },
                "patch": {
                    "operationId":"partial-settings-update",
                    "tags":["Partial Settings"],
                    "x-api-token-group":["Settings Write"],
                    "requestBody":{"required":true,"content":{"application/json":{"schema":{
                        "type":"object",
                        "properties":{"mode":{"type":"string"},"hidden":{"type":"boolean"}}
                    }}}}
                }
            }
        }
    });

    let snapshot = normalize_openapi(&document).expect("settings catalog");
    let update = snapshot.get("settings-update").expect("settings update");
    assert_eq!(
        update.verification.strategy,
        "same_path_result_contains_planned_fields_after_update"
    );
    let target = update
        .same_path_read
        .as_ref()
        .expect("hash-bound same-path readback");
    assert_eq!(target.path, update.path);
    assert_eq!(target.read_capability_id, "settings-get");
    assert_eq!(target.verified_response_fields, ["enabled", "mode"]);
    assert!(!update.rollback.supported);
    assert!(
        update
            .rollback
            .warning
            .as_deref()
            .is_some_and(|warning| warning.contains("pre-change snapshot"))
    );
    let partial = snapshot
        .get("partial-settings-update")
        .expect("partial update");
    assert_ne!(
        partial.verification.strategy,
        "same_path_result_contains_planned_fields_after_update"
    );

    let mut header_control = document;
    header_control["paths"]["/zones/{zone_id}/settings/example"]["put"]["parameters"] = json!([
        {"in":"header","name":"x-setting-scope","schema":{"type":"string"}}
    ]);
    let header_snapshot = normalize_openapi(&header_control).expect("header-control catalog");
    assert_ne!(
        header_snapshot
            .get("settings-update")
            .expect("settings update")
            .verification
            .strategy,
        "same_path_result_contains_planned_fields_after_update"
    );
}

fn create_lifecycle_fixture() -> serde_json::Value {
    json!({
        "openapi": "3.0.3",
        "info": {"title":"Cloudflare API","version":"4.0.0"},
        "components": {
            "schemas": {
                "Widget": {
                    "type": "object",
                    "properties": {
                        "id": {"type":"string"},
                        "name": {"type":"string"}
                    }
                },
                "WidgetResponse": {
                    "type": "object",
                    "properties": {
                        "success": {"type":"boolean"},
                        "result": {"$ref":"#/components/schemas/Widget"}
                    }
                }
            }
        },
        "paths": {
            "/accounts/{account_id}/widgets": {
                "post": {
                    "operationId":"widgets-create",
                    "summary":"Create Widget",
                    "tags":["Widgets"],
                    "x-api-token-group":["Widgets Write"],
                    "requestBody": {
                        "required": true,
                        "content": {"application/json": {"schema": {
                            "type": "object",
                            "required": ["name"],
                            "properties": {"name": {"type": "string"}}
                        }}}
                    },
                    "responses": {
                        "201": {
                            "description":"Widget created",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref":"#/components/schemas/WidgetResponse"}
                                }
                            }
                        }
                    }
                }
            },
            "/accounts/{account_id}/widgets/{widget_id}": {
                "parameters": [
                    {"in":"path","name":"account_id","required":true,"schema":{"type":"string"}},
                    {"in":"path","name":"widget_id","required":true,"schema":{"type":"string"}}
                ],
                "get": {
                    "operationId":"widgets-get",
                    "summary":"Get Widget",
                    "tags":["Widgets"],
                    "responses": {
                        "200": {
                            "description":"Widget",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref":"#/components/schemas/WidgetResponse"}
                                }
                            }
                        }
                    }
                },
                "delete": {
                    "operationId":"widgets-delete",
                    "summary":"Delete Widget",
                    "tags":["Widgets"],
                    "x-api-token-group":["Widgets Write"]
                }
            }
        }
    })
}

#[test]
fn create_contract_binds_a_schema_proven_id_and_exact_read_delete_pair() {
    let document = create_lifecycle_fixture();

    let snapshot = normalize_openapi(&document).expect("widget catalog");
    let create = snapshot.get("widgets-create").expect("create widget");
    assert_eq!(
        create.verification.strategy,
        "created_resource_contains_planned_fields_by_returned_id"
    );
    assert!(create.rollback.supported);
    assert_eq!(
        create.rollback.strategy.as_deref(),
        Some("delete_created_resource_by_returned_id")
    );
    let target = create
        .created_resource
        .as_ref()
        .expect("created-resource target");
    assert_eq!(
        target.detail_path,
        "/accounts/{account_id}/widgets/{widget_id}"
    );
    assert_eq!(target.identity_selector, "widget_id");
    assert_eq!(target.response_result_identity_pointer, "/id");
    assert_eq!(target.read_capability_id, "widgets-get");
    assert_eq!(target.delete_capability_id, "widgets-delete");
    assert_eq!(target.verified_response_fields, vec!["name"]);

    let mut implicit_object = document;
    implicit_object["paths"]["/accounts/{account_id}/widgets"]["post"]["requestBody"]
        ["content"]["application/json"]["schema"]
        .as_object_mut()
        .expect("create request schema")
        .remove("type");
    let implicit_snapshot =
        normalize_openapi(&implicit_object).expect("implicit-object create catalog");
    assert_eq!(
        implicit_snapshot
            .get("widgets-create")
            .expect("implicit-object create")
            .verification
            .strategy,
        "created_resource_contains_planned_fields_by_returned_id"
    );
}

#[test]
fn create_contract_rejects_an_undocumented_response_identity() {
    let mut document = create_lifecycle_fixture();
    document["paths"]["/accounts/{account_id}/widgets"]["post"]["responses"]["201"]["content"]["application/json"]
        ["schema"] = json!({
        "type":"object",
        "properties":{"result":{"type":"object"}}
    });

    let snapshot = normalize_openapi(&document).expect("opaque widget catalog");
    let opaque = snapshot.get("widgets-create").expect("opaque create");
    assert_ne!(
        opaque.verification.strategy,
        "created_resource_contains_planned_fields_by_returned_id"
    );
    assert!(!opaque.rollback.supported);
}

#[test]
fn create_contract_rejects_a_detail_read_without_a_string_identity() {
    let mut document = create_lifecycle_fixture();
    document["paths"]["/accounts/{account_id}/widgets/{widget_id}"]["get"]["responses"]["200"]["content"]
        ["application/json"]["schema"] = json!({
        "type":"object",
        "properties":{"result":{"type":"object","properties":{
            "id":{"type":"integer"},
            "name":{"type":"string"}
        }}}
    });

    let snapshot = normalize_openapi(&document).expect("integer-id detail catalog");
    let create = snapshot.get("widgets-create").expect("create widget");
    assert!(create.created_resource.is_none());
    assert_ne!(
        create.verification.strategy,
        "created_resource_contains_planned_fields_by_returned_id"
    );
}

#[test]
fn create_contract_rejects_ambiguous_direct_child_resource_paths() {
    let mut document = create_lifecycle_fixture();
    let mut alternative = document["paths"]["/accounts/{account_id}/widgets/{widget_id}"].clone();
    alternative["parameters"][1]["name"] = json!("widget_identifier");
    alternative["get"]["operationId"] = json!("widgets-get-by-identifier");
    alternative["delete"]["operationId"] = json!("widgets-delete-by-identifier");
    document["paths"]["/accounts/{account_id}/widgets/{widget_identifier}"] = alternative;

    let snapshot = normalize_openapi(&document).expect("ambiguous widget catalog");
    let ambiguous = snapshot.get("widgets-create").expect("ambiguous create");
    assert!(ambiguous.created_resource.is_none());
    assert_ne!(
        ambiguous.verification.strategy,
        "created_resource_contains_planned_fields_by_returned_id"
    );
    assert!(!ambiguous.rollback.supported);
}

#[test]
fn create_contract_rejects_fields_that_the_exact_read_cannot_prove() {
    let mut document = create_lifecycle_fixture();
    document["paths"]["/accounts/{account_id}/widgets"]["post"]["requestBody"]["content"]["application/json"]
        ["schema"]["properties"]["secret"] = json!({"type":"string"});

    let snapshot = normalize_openapi(&document).expect("hidden-field widget catalog");
    let create = snapshot.get("widgets-create").expect("create widget");

    assert!(create.created_resource.is_none());
    assert_ne!(
        create.verification.strategy,
        "created_resource_contains_planned_fields_by_returned_id"
    );
    assert!(!create.rollback.supported);
}

#[test]
fn create_contract_rejects_non_id_children_and_broadening_read_or_delete_inputs() {
    let mut non_id_document = create_lifecycle_fixture();
    let detail = non_id_document["paths"]
        .as_object_mut()
        .expect("paths")
        .remove("/accounts/{account_id}/widgets/{widget_id}")
        .expect("detail path");
    non_id_document["paths"]["/accounts/{account_id}/widgets/{slug}"] = detail;
    let non_id = normalize_openapi(&non_id_document).expect("non-id widget catalog");
    assert!(
        non_id
            .get("widgets-create")
            .expect("create widget")
            .created_resource
            .is_none()
    );

    let mut required_query_document = create_lifecycle_fixture();
    required_query_document["paths"]["/accounts/{account_id}/widgets/{widget_id}"]["get"]["parameters"] = json!([
        {"in":"query","name":"expand","required":true,"schema":{"type":"string"}}
    ]);
    let required_query =
        normalize_openapi(&required_query_document).expect("required-query widget catalog");
    assert!(
        required_query
            .get("widgets-create")
            .expect("create widget")
            .created_resource
            .is_none()
    );

    let mut delete_body_document = create_lifecycle_fixture();
    delete_body_document["paths"]["/accounts/{account_id}/widgets/{widget_id}"]["delete"]["requestBody"] = json!({
        "required":true,
        "content":{"application/json":{"schema":{
            "type":"object","properties":{"cascade":{"type":"boolean"}}
        }}}
    });
    let delete_body = normalize_openapi(&delete_body_document).expect("delete-body widget catalog");
    assert!(
        delete_body
            .get("widgets-create")
            .expect("create widget")
            .created_resource
            .is_none()
    );

    let mut create_query_document = create_lifecycle_fixture();
    create_query_document["paths"]["/accounts/{account_id}/widgets"]["post"]["parameters"] =
        json!([{"in":"query","name":"deploy","schema":{"type":"boolean"}}]);
    let create_query =
        normalize_openapi(&create_query_document).expect("create-query widget catalog");
    assert!(
        create_query
            .get("widgets-create")
            .expect("create widget")
            .created_resource
            .is_none()
    );
}

fn create_collection_schemas() -> serde_json::Value {
    json!({
        "Widget": {
            "type": "object",
            "properties": {
                "id": {"type":"string"},
                "name": {"type":"string"},
                "enabled": {"type":"boolean"}
            }
        },
        "WidgetResponse": {
            "type": "object",
            "properties": {
                "success": {"type":"boolean"},
                "result": {"$ref":"#/components/schemas/Widget"}
            }
        },
        "WidgetCollectionResponse": {
            "type": "object",
            "properties": {
                "success": {"type":"boolean"},
                "result": {
                    "type":"array",
                    "items":{"$ref":"#/components/schemas/Widget"}
                },
                "result_info": {
                    "type":"object",
                    "properties": {
                        "page":{"type":"integer"},
                        "total_pages":{"type":"integer"}
                    }
                }
            }
        }
    })
}

fn create_collection_lifecycle_fixture() -> serde_json::Value {
    json!({
        "openapi": "3.0.3",
        "info": {"title":"Cloudflare API","version":"4.0.0"},
        "components": {"schemas": create_collection_schemas()},
        "paths": {
            "/accounts/{account_id}/widgets": {
                "parameters": [
                    {"in":"path","name":"account_id","required":true,"schema":{"type":"string"}}
                ],
                "get": {
                    "operationId":"widgets-list",
                    "summary":"List Widgets",
                    "tags":["Widgets"],
                    "parameters":[
                        {"in":"query","name":"page","required":false,"schema":{"type":"integer"}},
                        {"in":"query","name":"per_page","required":false,"schema":{"type":"integer"}}
                    ],
                    "responses": {
                        "200": {
                            "description":"Widgets",
                            "content": {
                                "application/json": {
                                    "schema":{"$ref":"#/components/schemas/WidgetCollectionResponse"}
                                }
                            }
                        }
                    }
                },
                "post": {
                    "operationId":"widgets-create",
                    "summary":"Create Widget",
                    "tags":["Widgets"],
                    "x-api-token-group":["Widgets Write"],
                    "requestBody": {
                        "required":true,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type":"object",
                                    "properties": {
                                        "name":{"type":"string"},
                                        "enabled":{"type":"boolean"}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "201": {
                            "description":"Widget created",
                            "content": {
                                "application/json": {
                                    "schema":{"$ref":"#/components/schemas/WidgetResponse"}
                                }
                            }
                        }
                    }
                }
            },
            "/accounts/{account_id}/widgets/{widget_id}": {
                "parameters": [
                    {"in":"path","name":"account_id","required":true,"schema":{"type":"string"}},
                    {"in":"path","name":"widget_id","required":true,"schema":{"type":"string"}}
                ],
                "delete": {
                    "operationId":"widgets-delete",
                    "summary":"Delete Widget",
                    "tags":["Widgets"],
                    "x-api-token-group":["Widgets Write"]
                }
            }
        }
    })
}

#[test]
fn create_contract_uses_a_complete_parent_collection_when_detail_read_is_absent() {
    let snapshot = normalize_openapi(&create_collection_lifecycle_fixture())
        .expect("collection-backed widget catalog");
    let create = snapshot.get("widgets-create").expect("create widget");

    assert_eq!(
        create.verification.strategy,
        "parent_collection_contains_created_resource_id_and_planned_fields"
    );
    assert_eq!(
        create.rollback.strategy.as_deref(),
        Some("delete_created_resource_by_returned_id")
    );
    let target = create
        .created_collection_resource
        .as_ref()
        .expect("created collection resource target");
    assert_eq!(target.collection_path, "/accounts/{account_id}/widgets");
    assert_eq!(target.identity_selector, "widget_id");
    assert_eq!(target.response_result_identity_pointer, "/id");
    assert_eq!(target.response_item_identity_pointer, "/id");
    assert_eq!(target.read_capability_id, "widgets-list");
    assert_eq!(target.delete_capability_id, "widgets-delete");
    assert_eq!(target.verified_response_fields, ["enabled", "name"]);
    assert!(target.requires_page_number_completion);
}

#[test]
fn create_contract_separates_write_only_inputs_from_observable_readback_fields() {
    let mut document = create_collection_lifecycle_fixture();
    document["paths"]["/accounts/{account_id}/widgets"]["post"]["requestBody"]["content"]["application/json"]
        ["schema"]["properties"]["secret"] = json!({
        "type": "string",
        "writeOnly": true
    });
    document["paths"]["/accounts/{account_id}/widgets"]["post"]["requestBody"]["content"]["application/json"]
        ["schema"]["properties"]["credentials"] = json!({
        "type": "object",
        "properties": {
            "username": {"type": "string"},
            "password": {"type": "string", "writeOnly": true}
        }
    });
    document["components"]["schemas"]["Widget"]["properties"]["credentials"] = json!({
        "type": "object",
        "properties": {"username": {"type": "string"}}
    });

    let snapshot = normalize_openapi(&document).expect("write-only catalog");
    let create = snapshot.get("widgets-create").expect("create widget");
    let request = create.request_schema.as_ref().expect("request schema");
    assert_eq!(request["properties"]["secret"]["writeOnly"], true);
    assert_eq!(
        request["properties"]["credentials"]["properties"]["password"]["writeOnly"],
        true
    );
    assert_eq!(
        create
            .created_collection_resource
            .as_ref()
            .expect("observable collection readback")
            .verified_response_fields,
        ["credentials", "enabled", "name"]
    );
}

#[test]
fn create_collection_contract_rejects_unobservable_fields_non_id_children_and_incomplete_pages() {
    let mut hidden_field = create_collection_lifecycle_fixture();
    hidden_field["components"]["schemas"]["Widget"]["properties"]
        .as_object_mut()
        .expect("widget properties")
        .remove("enabled");
    let hidden = normalize_openapi(&hidden_field).expect("hidden-field catalog");
    assert!(
        hidden
            .get("widgets-create")
            .expect("create widget")
            .created_collection_resource
            .is_none()
    );

    let mut non_id_child = create_collection_lifecycle_fixture();
    let child = non_id_child["paths"]
        .as_object_mut()
        .expect("paths")
        .remove("/accounts/{account_id}/widgets/{widget_id}")
        .expect("widget child");
    non_id_child["paths"]
        .as_object_mut()
        .expect("paths")
        .insert(
            "/accounts/{account_id}/widgets/{widget_key}".to_owned(),
            child,
        );
    let non_id = normalize_openapi(&non_id_child).expect("non-id child catalog");
    assert!(
        non_id
            .get("widgets-create")
            .expect("create widget")
            .created_collection_resource
            .is_none()
    );

    let mut incomplete_pages = create_collection_lifecycle_fixture();
    incomplete_pages["components"]["schemas"]["WidgetCollectionResponse"]["properties"]
        ["result_info"]["properties"]
        .as_object_mut()
        .expect("pagination properties")
        .remove("total_pages");
    let incomplete = normalize_openapi(&incomplete_pages).expect("incomplete page catalog");
    assert!(
        incomplete
            .get("widgets-create")
            .expect("create widget")
            .created_collection_resource
            .is_none()
    );
}

fn pricing_feeds_fixture() -> OfficialTextFeedsV1 {
    OfficialTextFeedsV1 {
        fetched_at: Utc::now(),
        docs_index_url: "https://developers.cloudflare.com/llms.txt".to_owned(),
        docs_index: String::new(),
        product_indexes: [
            (
                "https://developers.cloudflare.com/d1/llms.txt".to_owned(),
                "- [Pricing](https://developers.cloudflare.com/d1/platform/pricing/index.md): D1 pricing based on rows read, rows written, and storage with scale-to-zero billing."
                    .to_owned(),
            ),
            (
                "https://developers.cloudflare.com/pages/llms.txt".to_owned(),
                "- [Pricing](https://developers.cloudflare.com/pages/functions/pricing/index.md): Pages Functions requests are billed as Workers requests."
                    .to_owned(),
            ),
            (
                "https://developers.cloudflare.com/realtime/llms.txt".to_owned(),
                "- [Pricing](https://developers.cloudflare.com/realtime/sfu/pricing/index.md): Realtime SFU pricing."
                    .to_owned(),
            ),
            (
                "https://developers.cloudflare.com/workers-ai/llms.txt".to_owned(),
                "- [Pricing](https://developers.cloudflare.com/workers-ai/platform/pricing/index.md): Workers AI pricing is based on Neurons."
                    .to_owned(),
            ),
        ]
        .into_iter()
        .collect(),
        unread_product_indexes: std::collections::BTreeMap::default(),
        changelog_url: "https://developers.cloudflare.com/changelog/".to_owned(),
        changelog: String::new(),
    }
}

#[test]
fn official_product_indexes_attach_pricing_without_claiming_a_bounded_cost() {
    let mut document = fixture();
    document["paths"]["/accounts/{account_id}/d1/database"]["post"] = json!({
        "operationId":"d1-database-create",
        "summary":"Create D1 database",
        "tags":["D1 Database"],
        "x-api-token-group":["D1 Write"],
        "x-cfPlanAvailability":{"free":true,"pro":true,"business":true,"enterprise":true}
    });
    document["paths"]["/accounts/{account_id}/access/custom_pages"]["post"] = json!({
        "operationId":"access-custom-pages-create-a-custom-page",
        "summary":"Create a custom page",
        "tags":["Access custom pages"],
        "x-api-token-group":["Access Apps and Policies Write"]
    });
    document["paths"]["/radar/bgp/routes/realtime"]["get"] = json!({
        "operationId":"radar-get-bgp-routes-realtime",
        "summary":"Get real-time BGP routes for a prefix",
        "tags":["Radar BGP"]
    });
    document["paths"]["/radar/ai/inference/summary/model"]["get"] = json!({
        "operationId":"radar-get-ai-inference-summary-by-model",
        "summary":"Get Workers AI models summary",
        "tags":["Radar AI Inference"]
    });
    let mut snapshot = normalize_openapi(&document).expect("catalog");

    attach_official_product_knowledge(&mut snapshot, &pricing_feeds_fixture())
        .expect("knowledge attaches");

    let capability = snapshot.get("d1-database-create").expect("D1 create");
    assert_eq!(capability.cost.billing_model, BillingModelV1::UsageBased);
    assert_eq!(capability.cost.exposure, CostExposureV1::DownstreamUsage);
    assert!(!capability.cost.known);
    assert_eq!(capability.cost.references.len(), 1);
    assert_eq!(
        capability.cost.references[0].url,
        "https://developers.cloudflare.com/d1/platform/pricing/index.md"
    );
    assert_eq!(
        capability.entitlement.source.as_deref(),
        Some("official OpenAPI x-cfPlanAvailability")
    );
    assert!(
        snapshot
            .get("access-custom-pages-create-a-custom-page")
            .expect("Access custom page")
            .cost
            .references
            .is_empty()
    );
    assert!(
        snapshot
            .get("radar-get-bgp-routes-realtime")
            .expect("Radar realtime")
            .cost
            .references
            .is_empty()
    );
    assert!(
        snapshot
            .get("radar-get-ai-inference-summary-by-model")
            .expect("Radar AI inference")
            .cost
            .references
            .is_empty()
    );
    assert!(
        capability
            .blocked_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("official pricing reference"))
    );
    let coverage = snapshot.coverage();
    assert_eq!(coverage.entitlement_metadata, 2);
    assert_eq!(coverage.plan_gated, 0);
    assert_eq!(coverage.cost_references, 1);
    assert_eq!(coverage.complete_mutation_contracts, 0);
}

#[test]
fn executable_catalog_hash_changes_when_a_local_contract_changes() {
    let mut snapshot = normalize_openapi(&fixture()).expect("catalog");
    let source_hash = snapshot.source_hash.clone();
    let original_catalog_hash = snapshot.schema_hash.clone();
    snapshot
        .capabilities
        .get_mut("dns-records-delete")
        .expect("delete")
        .rollback
        .warning = Some("deletion is irreversible".to_owned());

    snapshot.refresh_hash().expect("hash refreshes");

    assert_eq!(snapshot.source_hash, source_hash);
    assert_ne!(snapshot.schema_hash, original_catalog_hash);
}
