#![allow(clippy::expect_used, clippy::unwrap_used)]

use cfctl_catalog::{
    CatalogChangeKind, CatalogIndex, CatalogSnapshot, OfficialTextFeedsV1,
    attach_official_product_knowledge, ingest_cli_help, markdown_link, markdown_links,
    normalize_openapi,
};
use cfctl_core::{
    AdapterStatus, BillingModelV1, CostExposureV1, DeletedResourceContractV1, EffectClass,
    KnowledgeReferenceV1, RiskClass, hash_value,
};
use chrono::Utc;
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
fn legacy_catalog_hash_survives_an_absent_deleted_resource_contract() {
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
                    "tags":["Widgets"],
                    "x-api-token-group":["Widgets Read"]
                },
                "delete": {
                    "operationId":"widgets-delete",
                    "summary":"Delete Widget",
                    "tags":["Widgets"],
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
fn exact_resource_updates_pair_with_same_path_field_readback_contracts() {
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
                "patch": {
                    "operationId":"widgets-patch",
                    "summary":"Patch Widget",
                    "tags":["Widgets"],
                    "x-api-token-group":["Widgets Write"]
                },
                "put": {
                    "operationId":"widgets-update",
                    "summary":"Update Widget",
                    "tags":["Widgets"],
                    "x-api-token-group":["Widgets Write"]
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
    });

    let snapshot = normalize_openapi(&document).expect("widget catalog");
    for id in ["widgets-patch", "widgets-update"] {
        let exact = snapshot.get(id).expect("exact update");
        assert_eq!(
            exact.verification.strategy,
            "same_resource_contains_planned_fields_after_update"
        );
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
                    "tags":["Example Settings"],
                    "responses":{"200":{"description":"ok","content":{"application/json":{"schema":{
                        "type":"object",
                        "properties":{"result":{"type":"object","properties":{
                            "mode":{"type":"string"},"enabled":{"type":"boolean"}
                        }}}
                    }}}}}
                },
                "put": {
                    "operationId":"settings-update",
                    "tags":["Example Settings"],
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
fn create_contract_rejects_ambiguous_direct_child_resource_paths() {
    let mut document = create_lifecycle_fixture();
    document["paths"]["/accounts/{account_id}/widgets/{widget_key}"] = json!({
        "get": {
            "operationId":"widgets-get-by-key",
            "summary":"Get Widget by Key",
            "tags":["Widgets"]
        },
        "delete": {
            "operationId":"widgets-delete-by-key",
            "summary":"Delete Widget by Key",
            "tags":["Widgets"],
            "x-api-token-group":["Widgets Write"]
        }
    });

    let snapshot = normalize_openapi(&document).expect("ambiguous widget catalog");
    let ambiguous = snapshot.get("widgets-create").expect("ambiguous create");
    assert!(ambiguous.created_resource.is_none());
    assert_ne!(
        ambiguous.verification.strategy,
        "created_resource_contains_planned_fields_by_returned_id"
    );
    assert!(!ambiguous.rollback.supported);
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
