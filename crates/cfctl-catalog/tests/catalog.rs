#![allow(clippy::expect_used, clippy::unwrap_used)]

use cfctl_catalog::{
    CatalogChangeKind, CatalogIndex, CatalogSnapshot, OfficialTextFeedsV1,
    attach_official_product_knowledge, ingest_cli_help, markdown_link, markdown_links,
    normalize_openapi,
};
use cfctl_core::{
    AdapterStatus, BillingModelV1, CapabilityV1, CostExposureV1, DeletedResourceContractV1,
    EffectClass, KnowledgeReferenceV1, ResponseBodyModeV1, RiskClass, hash_value,
};
use chrono::Utc;
use serde_json::{Value, json};

fn fixture() -> serde_json::Value {
    json!({
        "openapi": "3.0.3",
        "info": {"title":"Cloudflare API","version":"4.0.0"},
        "servers": [{"url":"https://api.cloudflare.com/client/v4"}],
        "components": {
            "schemas": {
                "ApiEnvelope": {
                    "type": "object",
                    "required": ["success"],
                    "properties": {"success": {"type": "boolean"}}
                }
            },
            "responses": {
                "ApiEnvelope": {
                    "description": "Cloudflare API envelope",
                    "content": {"application/json": {"schema": {
                        "$ref": "#/components/schemas/ApiEnvelope"
                    }}}
                }
            }
        },
        "paths": {
            "/zones/{zone_id}/dns_records": {
                "get": {
                    "operationId":"dns-records-list",
                    "summary":"List DNS Records",
                    "tags":["DNS Records"],
                    "parameters":[{"in":"path","name":"zone_id","required":true,"schema":{"type":"string"}}],
                    "responses": {"200": {"$ref": "#/components/responses/ApiEnvelope"}},
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
                    ],
                    "responses": {"200": {"$ref": "#/components/responses/ApiEnvelope"}}
                }
            }
        }
    })
}

fn cloudflare_envelope_responses() -> Value {
    json!({
        "200": {
            "description": "Cloudflare API envelope",
            "content": {"application/json": {"schema": {
                "type": "object",
                "required": ["success"],
                "properties": {"success": {"type": "boolean"}}
            }}}
        }
    })
}

/// The response shape Cloudflare's `OpenAPI` actually declares for the DNS
/// record delete: a bare `result` object with no top-level `success` boolean.
/// The live API returns the full envelope (observed 2026-07-19); the schema
/// under-declares it. Fixtures must reproduce what the schema says so the
/// finalizer pin — not a flattering fixture — is what makes the delete
/// executable.
fn bare_result_id_responses() -> Value {
    json!({
        "200": {
            "description": "bare result without envelope fields",
            "content": {"application/json": {"schema": {
                "type": "object",
                "properties": {"result": {
                    "type": "object",
                    "properties": {"id": {"type": "string"}}
                }}
            }}}
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

fn d1_database_create_fixture() -> Value {
    let account = json!({
        "description":"Account identifier tag.",
        "in":"path",
        "name":"account_id",
        "required":true,
        "schema":{"maxLength":32,"type":"string"}
    });
    let database_id = json!({
        "description":"D1 database identifier (UUID).",
        "in":"path",
        "name":"database_id",
        "required":true,
        "schema":{"type":"string"}
    });
    let database = json!({
        "type":"object",
        "properties":{
            "created_at":{"type":"string"},
            "file_size":{"type":"number"},
            "jurisdiction":{"type":["string","null"]},
            "name":{"type":"string"},
            "num_tables":{"type":"number"},
            "read_replication":{"type":"object","properties":{"mode":{"type":"string"}}},
            "uuid":{"type":"string"},
            "version":{"type":"string"}
        }
    });
    let response = json!({"200":{"description":"ok","content":{"application/json":{"schema":{
        "type":"object","required":["success"],"properties":{
            "success":{"type":"boolean"},"result":database
        }
    }}}}});
    json!({
        "openapi":"3.0.3",
        "info":{"title":"Cloudflare API","version":"4.0.0"},
        "paths":{
            "/accounts/{account_id}/d1/database":{
                "post":{
                    "operationId":"d1-create-database",
                    "summary":"Create D1 Database",
                    "description":"Returns the created D1 database.",
                    "tags":["D1"],
                    "x-api-token-group":["D1 Write"],
                    "parameters":[account.clone()],
                    "requestBody":{"required":true,"content":{"application/json":{"schema":{
                        "type":"object",
                        "required":["name"],
                        "properties":{
                            "jurisdiction":{"type":"string","enum":["eu","fedramp"]},
                            "name":{"type":"string"},
                            "primary_location_hint":{"type":"string","enum":["wnam","enam","weur","eeur","apac","oc"]},
                            "read_replication":{"type":"object","required":["mode"],"properties":{
                                "mode":{"type":"string","enum":["auto","disabled"]}
                            }}
                        }
                    }}}},
                    "responses":response.clone()
                }
            },
            "/accounts/{account_id}/d1/database/{database_id}":{
                "get":{
                    "operationId":"d1-get-database",
                    "summary":"Get D1 Database",
                    "description":"Returns the specified D1 database.",
                    "tags":["D1"],
                    "x-api-token-group":["D1 Read","D1 Write"],
                    "parameters":[account.clone(),{
                        "in":"path","name":"database_id","required":true,
                        "schema":{"oneOf":[{"type":"string"},{"type":"string"}]}
                    },{
                        "description":"Comma-separated list of fields to include in the response. When omitted, all fields are returned.",
                        "in":"query","name":"fields","required":false,
                        "style":"form","explode":false,
                        "schema":{"type":"array","items":{"type":"string","enum":[
                            "uuid","name","created_at","version","jurisdiction","num_tables","file_size","running_in_region","read_replication"
                        ]}}
                    }],
                    "responses":response.clone()
                },
                "delete":{
                    "operationId":"d1-delete-database",
                    "summary":"Delete D1 Database",
                    "description":"Deletes the specified D1 database.",
                    "tags":["D1"],
                    "x-api-token-group":["D1 Write"],
                    "parameters":[account,database_id],
                    "responses":cloudflare_envelope_responses()
                }
            }
        }
    })
}

#[test]
fn d1_database_create_has_exact_readback_usage_cost_and_guarded_empty_database_compensation() {
    let snapshot = normalize_openapi(&d1_database_create_fixture()).expect("D1 create catalog");
    let create = snapshot
        .get("d1-create-database")
        .expect("create D1 database");

    assert_eq!(
        create.adapter_status,
        AdapterStatus::DynamicApi,
        "{:?}",
        create.blocked_reason
    );
    assert_eq!(create.risk, RiskClass::ScopedWrite);
    assert_eq!(create.effect, EffectClass::ReversibleWrite);
    assert!(create.cost.known);
    assert!(!create.cost.incremental);
    assert_eq!(create.cost.maximum, Some(0.0));
    assert_eq!(create.cost.billing_model, BillingModelV1::UsageBased);
    assert_eq!(create.cost.exposure, CostExposureV1::DownstreamUsage);
    assert_eq!(create.entitlement.available, Some(true));
    assert_eq!(create.entitlement.plans.get("free"), Some(&true));
    assert_eq!(create.entitlement.plans.get("paid"), Some(&true));
    assert_eq!(
        create.verification.strategy,
        "created_resource_contains_planned_fields_by_returned_id"
    );
    let target = create
        .created_resource
        .as_ref()
        .expect("created D1 contract");
    assert_eq!(target.identity_selector, "database_id");
    assert_eq!(target.response_result_identity_pointer, "/uuid");
    assert_eq!(target.read_capability_id, "d1-get-database");
    assert_eq!(target.delete_capability_id, "d1-delete-database");
    assert_eq!(
        target.verified_response_fields,
        ["jurisdiction", "name", "read_replication"]
    );
    assert_eq!(
        create.request_schema.as_ref().expect("request schema")["properties"]["primary_location_hint"]
            ["x-cfctl-verification-observable"],
        false
    );
    assert!(create.rollback.supported);
    assert_eq!(
        create.rollback.strategy.as_deref(),
        Some("delete_created_empty_d1_database_by_returned_uuid_if_unchanged")
    );
    assert!(create.rollback.warning.as_deref().is_some_and(|warning| {
        warning.contains("empty-state") && warning.contains("explicit approval")
    }));
    assert!(
        create.mutation_contract_gaps().is_empty(),
        "{:?}",
        create.mutation_contract_gaps()
    );
}

#[test]
fn d1_database_create_classifier_rejects_request_response_read_and_delete_drift() {
    let mut request = d1_database_create_fixture();
    request["paths"]["/accounts/{account_id}/d1/database"]["post"]["requestBody"]["content"]["application/json"]
        ["schema"]["properties"]["read_replication"]["properties"]["mode"]["enum"] =
        json!(["auto", "disabled", "experimental"]);
    assert_eq!(
        normalize_openapi(&request)
            .expect("request drift")
            .get("d1-create-database")
            .expect("create")
            .adapter_status,
        AdapterStatus::Blocked
    );

    let mut response = d1_database_create_fixture();
    response["paths"]["/accounts/{account_id}/d1/database"]["post"]["responses"]["200"]["content"]
        ["application/json"]["schema"]["properties"]["result"]["properties"]
        .as_object_mut()
        .expect("result fields")
        .remove("uuid");
    assert_eq!(
        normalize_openapi(&response)
            .expect("response drift")
            .get("d1-create-database")
            .expect("create")
            .adapter_status,
        AdapterStatus::Blocked
    );

    let mut read = d1_database_create_fixture();
    read["paths"]["/accounts/{account_id}/d1/database/{database_id}"]["get"]["operationId"] =
        json!("untrusted-d1-read");
    assert_eq!(
        normalize_openapi(&read)
            .expect("read drift")
            .get("d1-create-database")
            .expect("create")
            .adapter_status,
        AdapterStatus::Blocked
    );

    let mut delete = d1_database_create_fixture();
    delete["paths"]["/accounts/{account_id}/d1/database/{database_id}"]["delete"]["x-api-token-group"] =
        json!(["D1 Read"]);
    assert_eq!(
        normalize_openapi(&delete)
            .expect("delete drift")
            .get("d1-create-database")
            .expect("create")
            .adapter_status,
        AdapterStatus::Blocked
    );
}

fn r2_bucket_response() -> Value {
    json!({
        "200": {
            "description": "R2 bucket response.",
            "content": {"application/json": {"schema": {"allOf": [
                {"$ref": "#/components/schemas/api-response-common"},
                {"type": "object", "properties": {
                    "result": {"$ref": "#/components/schemas/r2-bucket"}
                }}
            ]}}}
        }
    })
}

fn r2_bucket_fixture() -> Value {
    let account = json!({
        "in": "path",
        "name": "account_id",
        "required": true,
        "description": "Account ID.",
        "schema": {"$ref": "#/components/schemas/identifier"}
    });
    let bucket = json!({
        "in": "path",
        "name": "bucket_name",
        "required": true,
        "description": "Name of the bucket.",
        "schema": {"$ref": "#/components/schemas/bucket-name"}
    });
    let jurisdiction = json!({
        "in": "header",
        "name": "cf-r2-jurisdiction",
        "required": false,
        "description": "Jurisdiction where objects in this bucket are guaranteed to be stored.",
        "schema": {"$ref": "#/components/schemas/jurisdiction"}
    });
    let response = r2_bucket_response();
    json!({
        "openapi": "3.0.3",
        "info": {"title": "Cloudflare API", "version": "4.0.0"},
        "servers": [{"url": "https://api.cloudflare.com/client/v4"}],
        "components": {"schemas": {
            "identifier": {"type": "string", "maxLength": 32},
            "bucket-name": {"type": "string", "minLength": 3, "maxLength": 64},
            "jurisdiction": {"type": "string", "enum": ["default", "eu", "fedramp"]},
            "location": {"type": "string", "enum": ["apac", "eeur", "enam", "weur", "wnam", "oc"]},
            "storage-class": {"type": "string", "enum": ["Standard", "InfrequentAccess"]},
            "api-response-common": {
                "type": "object",
                "required": ["success"],
                "properties": {"success": {"type": "boolean", "enum": [true]}}
            },
            "r2-bucket-create": {
                "type": "object",
                "required": ["name"],
                "properties": {
                    "name": {"$ref": "#/components/schemas/bucket-name"},
                    "locationHint": {"$ref": "#/components/schemas/location"},
                    "storageClass": {"$ref": "#/components/schemas/storage-class"}
                }
            },
            "r2-bucket": {
                "type": "object",
                "properties": {
                    "creation_date": {"type": "string"},
                    "jurisdiction": {"$ref": "#/components/schemas/jurisdiction"},
                    "location": {"$ref": "#/components/schemas/location"},
                    "name": {"$ref": "#/components/schemas/bucket-name"},
                    "storage_class": {"$ref": "#/components/schemas/storage-class"}
                }
            }
        }},
        "paths": {
            "/accounts/{account_id}/r2/buckets": {
                "post": {
                    "operationId": "r2-create-bucket",
                    "summary": "Create Bucket",
                    "description": "Creates a new R2 bucket.",
                    "tags": ["R2 Bucket"],
                    "x-api-token-group": ["Workers R2 Storage Write"],
                    "parameters": [account.clone(), jurisdiction.clone()],
                    "requestBody": {"required": true, "content": {"application/json": {
                        "schema": {"$ref": "#/components/schemas/r2-bucket-create"}
                    }}},
                    "responses": response.clone()
                }
            },
            "/accounts/{account_id}/r2/buckets/{bucket_name}": {
                "get": {
                    "operationId": "r2-get-bucket",
                    "summary": "Get Bucket",
                    "description": "Gets properties of an existing R2 bucket.",
                    "tags": ["R2 Bucket"],
                    "parameters": [account.clone(), bucket.clone(), jurisdiction.clone()],
                    "responses": response
                },
                "delete": {
                    "operationId": "r2-delete-bucket",
                    "summary": "Delete Bucket",
                    "description": "Deletes an existing R2 bucket.",
                    "tags": ["R2 Bucket"],
                    "x-api-token-group": ["Workers R2 Storage Write"],
                    "parameters": [bucket, account, jurisdiction],
                    "responses": {"200": {"description": "Delete bucket response", "content": {
                        "application/json": {"schema": {"allOf": [
                            {"$ref": "#/components/schemas/api-response-common"},
                            {"type": "object", "properties": {"result": {"type": "object", "nullable": true}}}
                        ]}}
                    }}}
                }
            }
        }
    })
}

#[test]
fn r2_bucket_create_has_paid_ceiling_exact_readback_and_reviewed_empty_bucket_compensation() {
    let snapshot = normalize_openapi(&r2_bucket_fixture()).expect("R2 bucket catalog");
    let create = snapshot.get("r2-create-bucket").expect("create R2 bucket");

    assert_eq!(
        create.adapter_status,
        AdapterStatus::DynamicApi,
        "{:?}",
        create.blocked_reason
    );
    assert_eq!(create.risk, RiskClass::ScopedWrite);
    assert_eq!(create.effect, EffectClass::ReversibleWrite);
    assert!(create.cost.known);
    assert!(create.cost.incremental);
    assert_eq!(create.cost.currency.as_deref(), Some("USD"));
    assert_eq!(create.cost.maximum, Some(0.000_009));
    assert_eq!(create.cost.billing_model, BillingModelV1::UsageBased);
    assert_eq!(create.cost.exposure, CostExposureV1::DownstreamUsage);
    assert_eq!(create.entitlement.available, Some(true));
    assert_eq!(
        create.entitlement.plans.get("r2_active_subscription"),
        Some(&true)
    );
    assert_eq!(
        create.verification.strategy,
        "created_resource_contains_planned_fields_by_returned_id"
    );
    let target = create
        .created_resource
        .as_ref()
        .expect("created bucket contract");
    assert_eq!(
        target.detail_path,
        "/accounts/{account_id}/r2/buckets/{bucket_name}"
    );
    assert_eq!(target.identity_selector, "bucket_name");
    assert_eq!(target.response_result_identity_pointer, "/name");
    assert_eq!(target.read_capability_id, "r2-get-bucket");
    assert_eq!(target.delete_capability_id, "r2-delete-bucket");
    assert_eq!(target.verified_response_fields, ["name", "storageClass"]);
    assert_eq!(
        create.request_schema.as_ref().expect("request schema")["properties"]["locationHint"]["x-cfctl-verification-observable"],
        false
    );
    assert_eq!(
        create.request_schema.as_ref().expect("request schema")["properties"]["storageClass"]["x-cfctl-verification-response-field"],
        "storage_class"
    );
    assert!(
        create.request_schema.as_ref().expect("request schema")["properties"]["storageClass"]
            .get("x-cfctl-verification-observable")
            .is_none()
    );
    assert!(create.rollback.supported);
    assert_eq!(
        create.rollback.strategy.as_deref(),
        Some("delete_created_resource_by_returned_id")
    );
    assert!(create.rollback.warning.as_deref().is_some_and(|warning| {
        warning.contains("empty") && warning.contains("separately reviewed")
    }));
    assert!(create.mutation_contract_gaps().is_empty());
}

#[test]
fn r2_bucket_create_classifier_rejects_permission_request_response_and_readback_drift() {
    let mut permission = r2_bucket_fixture();
    permission["paths"]["/accounts/{account_id}/r2/buckets"]["post"]["x-api-token-group"] =
        json!(["Workers R2 Storage Read"]);
    assert_eq!(
        normalize_openapi(&permission)
            .expect("permission-drifted catalog")
            .get("r2-create-bucket")
            .expect("create bucket")
            .adapter_status,
        AdapterStatus::Blocked
    );

    let mut request = r2_bucket_fixture();
    request["components"]["schemas"]["storage-class"]["enum"] = json!(["Standard"]);
    assert_eq!(
        normalize_openapi(&request)
            .expect("request-drifted catalog")
            .get("r2-create-bucket")
            .expect("create bucket")
            .adapter_status,
        AdapterStatus::Blocked
    );

    let mut response = r2_bucket_fixture();
    response["components"]["schemas"]["r2-bucket"]["properties"]
        .as_object_mut()
        .expect("bucket fields")
        .remove("storage_class");
    assert_eq!(
        normalize_openapi(&response)
            .expect("response-drifted catalog")
            .get("r2-create-bucket")
            .expect("create bucket")
            .adapter_status,
        AdapterStatus::Blocked
    );

    let mut readback = r2_bucket_fixture();
    readback["paths"]["/accounts/{account_id}/r2/buckets/{bucket_name}"]["get"]["operationId"] =
        json!("untrusted-r2-bucket-readback");
    assert_eq!(
        normalize_openapi(&readback)
            .expect("readback-drifted catalog")
            .get("r2-create-bucket")
            .expect("create bucket")
            .adapter_status,
        AdapterStatus::Blocked
    );
}

fn workers_script_secret_request_schema() -> Value {
    json!({
        "type": "object",
        "oneOf": [
            {
                "type": "object",
                "required": ["name", "type", "text"],
                "properties": {
                    "name": {"type": "string"},
                    "type": {"type": "string", "enum": ["secret_text"]},
                    "text": {"type": "string", "writeOnly": true}
                }
            },
            {
                "type": "object",
                "required": ["name", "type", "format", "algorithm", "usages"],
                "properties": {
                    "name": {"type": "string"},
                    "type": {"type": "string", "enum": ["secret_key"]},
                    "format": {"type": "string", "enum": ["raw", "pkcs8", "spki", "jwk"]},
                    "algorithm": {"type": "object"},
                    "usages": {
                        "type": "array",
                        "items": {"type": "string", "enum": ["encrypt", "decrypt", "sign", "verify", "deriveKey", "deriveBits", "wrapKey", "unwrapKey"]}
                    },
                    "key_base64": {"type": "string", "writeOnly": true},
                    "key_jwk": {"type": "object", "writeOnly": true}
                }
            }
        ]
    })
}

fn workers_script_secret_result_schema(secret_schema: Value) -> Value {
    json!({
        "type": "object",
        "required": ["success"],
        "properties": {
            "success": {"type": "boolean"},
            "result": secret_schema
        }
    })
}

fn workers_script_secret_fixture() -> Value {
    let account = json!({
        "in": "path",
        "name": "account_id",
        "required": true,
        "description": "Identifier.",
        "schema": {"type": "string", "maxLength": 32}
    });
    let script = json!({
        "in": "path",
        "name": "script_name",
        "required": true,
        "description": "Name of the script, used in URLs and route configuration.",
        "schema": {"type": "string"}
    });
    let secret_name = json!({
        "in": "path",
        "name": "secret_name",
        "required": true,
        "description": "A JavaScript variable name for the secret binding.",
        "schema": {"type": "string"}
    });
    let url_encoded = json!({
        "in": "query",
        "name": "url_encoded",
        "required": false,
        "description": "Flag that indicates whether the secret name is URL encoded.",
        "schema": {"type": "boolean"}
    });
    let secret_schema = workers_script_secret_request_schema();
    let secret_result = workers_script_secret_result_schema(secret_schema.clone());
    let empty_result = json!({
        "type": "object",
        "required": ["success"],
        "properties": {
            "success": {"type": "boolean"},
            "result": {"type": "object"}
        }
    });
    json!({
        "openapi": "3.0.3",
        "info": {"title": "Cloudflare API", "version": "4.0.0"},
        "servers": [{"url": "https://api.cloudflare.com/client/v4"}],
        "paths": {
            "/accounts/{account_id}/workers/scripts/{script_name}/secrets": {
                "put": {
                    "operationId": "worker-put-script-secret",
                    "summary": "Add script secret",
                    "description": "Add a secret to a script.",
                    "tags": ["Worker Script"],
                    "x-api-token-group": ["Workers Scripts Write"],
                    "parameters": [account.clone(), script.clone()],
                    "requestBody": {"required": true, "content": {"application/json": {"schema": secret_schema}}},
                    "responses": {"200": {"description": "Secret metadata", "content": {"application/json": {"schema": secret_result.clone()}}}}
                }
            },
            "/accounts/{account_id}/workers/scripts/{script_name}/secrets/{secret_name}": {
                "get": {
                    "operationId": "worker-get-script-secret",
                    "summary": "Get secret binding",
                    "description": "Get a given secret binding (value omitted) on a script.",
                    "tags": ["Worker Script"],
                    "parameters": [account.clone(), script.clone(), secret_name.clone(), url_encoded.clone()],
                    "responses": {"200": {"description": "Secret metadata", "content": {"application/json": {"schema": secret_result}}}}
                },
                "delete": {
                    "operationId": "worker-delete-script-secret",
                    "summary": "Delete script secret",
                    "description": "Remove a secret from a script.",
                    "tags": ["Worker Script"],
                    "x-api-token-group": ["Workers Scripts Write"],
                    "parameters": [account, script, secret_name, url_encoded],
                    "responses": {"200": {"description": "Deleted", "content": {"application/json": {"schema": empty_result}}}}
                }
            }
        }
    })
}

#[test]
fn workers_script_secret_put_and_delete_are_secret_safe_exact_lifecycles() {
    let snapshot =
        normalize_openapi(&workers_script_secret_fixture()).expect("Workers secret catalog");

    let put = snapshot
        .get("worker-put-script-secret")
        .expect("secret put capability");
    assert_eq!(
        put.adapter_status,
        AdapterStatus::DynamicApi,
        "{:?}",
        put.blocked_reason
    );
    assert_eq!(put.risk, RiskClass::SecretSensitive);
    assert_eq!(put.effect, EffectClass::IdentityOrOwnership);
    assert!(put.cost.known);
    assert_eq!(put.cost.maximum, Some(0.0));
    assert_eq!(put.cost.billing_model, BillingModelV1::Subscription);
    assert_eq!(put.cost.exposure, CostExposureV1::DownstreamUsage);
    assert_eq!(
        put.verification.strategy,
        "worker_script_secret_reports_planned_name_and_type_after_put"
    );
    // Cloudflare's OpenAPI declares only 200, but a successful put answers
    // 201 Created. Pinning 200 alone drove every real success into
    // post-boundary recovery, so the contract carries both observed statuses
    // — and no others.
    assert_eq!(
        put.response_contract
            .as_ref()
            .expect("secret put response contract")
            .success_statuses,
        ["200", "201"]
    );
    assert!(!put.rollback.supported);
    assert!(
        put.rollback
            .warning
            .as_deref()
            .is_some_and(|warning| warning.contains("prior value") && warning.contains("cannot"))
    );
    assert!(put.request_object_field_is_write_only("text"));
    assert!(put.request_object_field_is_write_only("key_base64"));
    assert!(put.request_object_field_is_write_only("key_jwk"));
    let put_read = put.same_path_read.as_ref().expect("exact secret readback");
    assert_eq!(
        put_read.path,
        "/accounts/{account_id}/workers/scripts/{script_name}/secrets/{secret_name}"
    );
    assert_eq!(put_read.read_capability_id, "worker-get-script-secret");
    assert_eq!(put_read.verified_response_fields, ["name", "type"]);
    assert!(put.verification_contract_supported());
    assert!(put.mutation_contract_gaps().is_empty());

    let delete = snapshot
        .get("worker-delete-script-secret")
        .expect("secret delete capability");
    assert_eq!(
        delete.adapter_status,
        AdapterStatus::DynamicApi,
        "{:?}",
        delete.blocked_reason
    );
    assert_eq!(delete.risk, RiskClass::Destructive);
    assert_eq!(delete.effect, EffectClass::Irreversible);
    assert!(delete.cost.known);
    assert_eq!(delete.cost.maximum, Some(0.0));
    assert_eq!(
        delete.verification.strategy,
        "same_resource_returns_not_found_after_delete"
    );
    assert!(
        delete
            .selectors
            .iter()
            .all(|selector| selector.location == "path")
    );
    let delete_read = delete
        .same_path_read
        .as_ref()
        .expect("exact delete readback");
    assert_eq!(delete_read.path, delete.path);
    assert!(delete_read.verified_response_fields.is_empty());
    assert!(!delete.rollback.supported);
    assert!(
        delete
            .rollback
            .warning
            .as_deref()
            .is_some_and(|warning| warning.contains("secret value") && warning.contains("cannot"))
    );
    assert!(delete.verification_contract_supported());
    assert!(delete.mutation_contract_gaps().is_empty());
}

#[test]
fn workers_script_secret_accepts_official_referenced_response_shape() {
    let mut document = workers_script_secret_fixture();
    let secret = document["paths"]
        ["/accounts/{account_id}/workers/scripts/{script_name}/secrets/{secret_name}"]["get"]
        ["responses"]["200"]["content"]["application/json"]["schema"]["properties"]["result"]
        .take();
    document["components"] = json!({
        "schemas": {
            "ApiEnvelope": {
                "type": "object",
                "required": ["success"],
                "properties": {"success": {"type": "boolean"}}
            },
            "WorkerSecret": secret
        }
    });
    let response = json!({
        "allOf": [
            {"$ref": "#/components/schemas/ApiEnvelope"},
            {
                "type": "object",
                "properties": {
                    "result": {"$ref": "#/components/schemas/WorkerSecret"}
                }
            }
        ]
    });
    document["paths"]["/accounts/{account_id}/workers/scripts/{script_name}/secrets"]["put"]["responses"]
        ["200"]["content"]["application/json"]["schema"] = response.clone();
    document["paths"]["/accounts/{account_id}/workers/scripts/{script_name}/secrets/{secret_name}"]
        ["get"]["responses"]["200"]["content"]["application/json"]["schema"] = response;

    let snapshot = normalize_openapi(&document).expect("official-shaped Workers secret catalog");
    for capability_id in ["worker-put-script-secret", "worker-delete-script-secret"] {
        let capability = snapshot.get(capability_id).expect("secret capability");
        assert_eq!(
            capability.adapter_status,
            AdapterStatus::DynamicApi,
            "{capability_id}: {:?}",
            capability.blocked_reason
        );
        assert!(capability.verification_contract_supported());
    }
}

#[test]
fn workers_script_secret_classifier_rejects_permission_schema_and_readback_drift() {
    let mut permission = workers_script_secret_fixture();
    permission["paths"]["/accounts/{account_id}/workers/scripts/{script_name}/secrets"]["put"]["x-api-token-group"] =
        json!(["Workers Scripts Read"]);
    let snapshot = normalize_openapi(&permission).expect("permission-drifted catalog");
    assert_eq!(
        snapshot
            .get("worker-put-script-secret")
            .expect("put")
            .adapter_status,
        AdapterStatus::Blocked
    );

    let mut secret_marker = workers_script_secret_fixture();
    secret_marker["paths"]["/accounts/{account_id}/workers/scripts/{script_name}/secrets"]["put"]
        ["requestBody"]["content"]["application/json"]["schema"]["oneOf"][0]
        ["properties"]["text"]
        .as_object_mut()
        .expect("text schema")
        .remove("writeOnly");
    let snapshot = normalize_openapi(&secret_marker).expect("writeOnly-drifted catalog");
    assert_eq!(
        snapshot
            .get("worker-put-script-secret")
            .expect("put")
            .adapter_status,
        AdapterStatus::Blocked
    );

    let mut readback = workers_script_secret_fixture();
    readback["paths"]["/accounts/{account_id}/workers/scripts/{script_name}/secrets/{secret_name}"]
        ["get"]["responses"]["200"]["content"]["application/json"]["schema"]["properties"]["result"]
        ["oneOf"][0]["properties"]
        .as_object_mut()
        .expect("readback properties")
        .remove("type");
    let snapshot = normalize_openapi(&readback).expect("readback-drifted catalog");
    let put = snapshot.get("worker-put-script-secret").expect("put");
    assert_eq!(put.adapter_status, AdapterStatus::Blocked);
    assert!(put.same_path_read.is_none());

    let mut response_leak = workers_script_secret_fixture();
    response_leak["paths"]["/accounts/{account_id}/workers/scripts/{script_name}/secrets/{secret_name}"]
        ["get"]["responses"]["200"]["content"]["application/json"]["schema"]["properties"]["result"]
        ["oneOf"][0]["properties"]["text"]
        .as_object_mut()
        .expect("response secret text schema")
        .remove("writeOnly");
    let snapshot = normalize_openapi(&response_leak).expect("response-leak catalog");
    let put = snapshot.get("worker-put-script-secret").expect("put");
    assert_eq!(put.adapter_status, AdapterStatus::Blocked);
    assert!(put.same_path_read.is_none());
}

fn workers_kv_namespace_response() -> Value {
    json!({
        "200": {
            "description": "Workers KV namespace response.",
            "content": {"application/json": {"schema": {
                "allOf": [
                    {"$ref": "#/components/schemas/workers-kv_api-response-common"},
                    {"type": "object", "properties": {
                        "result": {"$ref": "#/components/schemas/workers-kv_namespace"}
                    }}
                ]
            }}}
        }
    })
}

fn workers_kv_namespace_delete_response() -> Value {
    json!({
        "200": {
            "description": "Remove a Namespace response.",
            "content": {"application/json": {"schema": {
                "allOf": [
                    {"$ref": "#/components/schemas/workers-kv_api-response-common"},
                    {"type": "object", "properties": {
                        "result": {"type": "object", "nullable": true}
                    }}
                ]
            }}}
        }
    })
}

fn workers_kv_namespace_components() -> Value {
    json!({
        "schemas": {
            "workers-kv_identifier": {
                "description": "Identifier.",
                "maxLength": 32,
                "readOnly": true,
                "type": "string"
            },
            "workers-kv_namespace_identifier": {
                "description": "Namespace identifier tag.",
                "maxLength": 32,
                "readOnly": true,
                "type": "string"
            },
            "workers-kv_namespace_title": {
                "description": "A human-readable string name for a Namespace.",
                "maxLength": 512,
                "type": "string"
            },
            "workers-kv_create_rename_namespace_body": {
                "type": "object",
                "required": ["title"],
                "properties": {
                    "title": {"$ref": "#/components/schemas/workers-kv_namespace_title"}
                }
            },
            "workers-kv_namespace": {
                "type": "object",
                "required": ["id", "title"],
                "properties": {
                    "id": {"$ref": "#/components/schemas/workers-kv_namespace_identifier"},
                    "title": {"$ref": "#/components/schemas/workers-kv_namespace_title"},
                    "supports_url_encoding": {"type": "boolean", "readOnly": true}
                }
            },
            "workers-kv_api-response-common": {
                "type": "object",
                "required": ["success"],
                "properties": {"success": {"type": "boolean", "enum": [true]}}
            }
        }
    })
}

fn workers_kv_namespace_fixture() -> Value {
    let account = json!({
        "in": "path",
        "name": "account_id",
        "required": true,
        "schema": {"$ref": "#/components/schemas/workers-kv_identifier"}
    });
    let namespace = json!({
        "in": "path",
        "name": "namespace_id",
        "required": true,
        "schema": {"$ref": "#/components/schemas/workers-kv_namespace_identifier"}
    });
    let namespace_response = workers_kv_namespace_response();
    json!({
        "openapi": "3.0.3",
        "info": {"title": "Cloudflare API", "version": "4.0.0"},
        "servers": [{"url": "https://api.cloudflare.com/client/v4"}],
        "components": workers_kv_namespace_components(),
        "paths": {
            "/accounts/{account_id}/storage/kv/namespaces": {
                "post": {
                    "operationId": "workers-kv-namespace-create-a-namespace",
                    "summary": "Create a Namespace",
                    "description": "Creates a namespace under the given title. A `400` is returned if the account already owns a namespace with this title. A namespace must be explicitly deleted to be replaced.",
                    "tags": ["Workers KV Namespace"],
                    "x-api-token-group": ["Workers KV Storage Write"],
                    "parameters": [account.clone()],
                    "requestBody": {"required": true, "content": {"application/json": {
                        "schema": {"$ref": "#/components/schemas/workers-kv_create_rename_namespace_body"}
                    }}},
                    "responses": namespace_response.clone()
                }
            },
            "/accounts/{account_id}/storage/kv/namespaces/{namespace_id}": {
                "get": {
                    "operationId": "workers-kv-namespace-get-a-namespace",
                    "summary": "Get a Namespace",
                    "description": "Get the namespace corresponding to the given ID.",
                    "tags": ["Workers KV Namespace"],
                    "x-api-token-group": ["Workers KV Storage Write", "Workers KV Storage Read"],
                    "parameters": [namespace.clone(), account.clone()],
                    "responses": namespace_response.clone()
                },
                "put": {
                    "operationId": "workers-kv-namespace-rename-a-namespace",
                    "summary": "Rename a Namespace",
                    "description": "Modifies a namespace's title.",
                    "tags": ["Workers KV Namespace"],
                    "x-api-token-group": ["Workers KV Storage Write"],
                    "parameters": [namespace.clone(), account.clone()],
                    "requestBody": {"required": true, "content": {"application/json": {
                        "schema": {"$ref": "#/components/schemas/workers-kv_create_rename_namespace_body"}
                    }}},
                    "responses": namespace_response
                },
                "delete": {
                    "operationId": "workers-kv-namespace-remove-a-namespace",
                    "summary": "Remove a Namespace",
                    "description": "Deletes the namespace corresponding to the given ID.",
                    "tags": ["Workers KV Namespace"],
                    "x-api-token-group": ["Workers KV Storage Write"],
                    "parameters": [namespace, account],
                    "requestBody": {"required": true, "content": {"application/json": {}}},
                    "responses": workers_kv_namespace_delete_response()
                }
            }
        }
    })
}

fn assert_workers_kv_namespace_create(create: &CapabilityV1) {
    assert_eq!(
        create.adapter_status,
        AdapterStatus::DynamicApi,
        "{:?}",
        create.blocked_reason
    );
    assert_eq!(create.risk, RiskClass::ScopedWrite);
    assert_eq!(create.effect, EffectClass::ReversibleWrite);
    assert!(create.cost.known);
    assert_eq!(create.cost.maximum, Some(0.0));
    assert_eq!(create.cost.billing_model, BillingModelV1::UsageBased);
    assert_eq!(create.cost.exposure, CostExposureV1::DownstreamUsage);
    assert_eq!(create.entitlement.available, Some(true));
    assert_eq!(create.entitlement.plans.get("free"), Some(&true));
    assert_eq!(create.entitlement.plans.get("paid"), Some(&true));
    assert_eq!(
        create.verification.strategy,
        "created_resource_contains_planned_fields_by_returned_id"
    );
    let created = create
        .created_resource
        .as_ref()
        .expect("created namespace contract");
    assert_eq!(
        created.detail_path,
        "/accounts/{account_id}/storage/kv/namespaces/{namespace_id}"
    );
    assert_eq!(created.identity_selector, "namespace_id");
    assert_eq!(created.response_result_identity_pointer, "/id");
    assert_eq!(
        created.read_capability_id,
        "workers-kv-namespace-get-a-namespace"
    );
    assert_eq!(
        created.delete_capability_id,
        "workers-kv-namespace-remove-a-namespace"
    );
    assert_eq!(created.verified_response_fields, ["title"]);
    assert!(create.rollback.supported);
    assert_eq!(
        create.rollback.strategy.as_deref(),
        Some("delete_created_resource_by_returned_id")
    );
    assert!(create.mutation_contract_gaps().is_empty());
}

fn assert_workers_kv_namespace_rename(rename: &CapabilityV1) {
    assert_eq!(
        rename.adapter_status,
        AdapterStatus::DynamicApi,
        "{:?}",
        rename.blocked_reason
    );
    assert_eq!(rename.risk, RiskClass::ScopedWrite);
    assert_eq!(rename.effect, EffectClass::ReversibleWrite);
    assert!(rename.cost.known);
    assert_eq!(rename.cost.maximum, Some(0.0));
    assert_eq!(rename.entitlement.available, Some(true));
    assert_eq!(
        rename.verification.strategy,
        "same_resource_contains_planned_fields_after_update"
    );
    let read = rename.same_path_read.as_ref().expect("rename readback");
    assert_eq!(
        read.read_capability_id,
        "workers-kv-namespace-get-a-namespace"
    );
    assert_eq!(read.verified_response_fields, ["title"]);
    assert!(!rename.rollback.supported);
    assert!(
        rename
            .rollback
            .warning
            .as_deref()
            .is_some_and(|warning| warning.contains("pre-change snapshot"))
    );
    assert!(rename.mutation_contract_gaps().is_empty());
}

fn assert_workers_kv_namespace_delete_is_cost_blocked(delete: &CapabilityV1) {
    assert_eq!(delete.adapter_status, AdapterStatus::Blocked);
    assert_eq!(delete.risk, RiskClass::Destructive);
    assert_eq!(delete.effect, EffectClass::Irreversible);
    assert!(!delete.cost.known);
    assert_eq!(delete.cost.maximum, None);
    assert_eq!(delete.cost.billing_model, BillingModelV1::UsageBased);
    assert_eq!(delete.cost.exposure, CostExposureV1::DownstreamUsage);
    assert!(delete.cost.basis.as_deref().is_some_and(
        |basis| basis.contains("populated namespace") && basis.contains("not documented")
    ));
    assert_eq!(delete.entitlement.available, Some(true));
    assert_eq!(
        delete.verification.strategy,
        "same_resource_returns_not_found_after_delete"
    );
    let read = delete.same_path_read.as_ref().expect("delete readback");
    assert_eq!(
        read.read_capability_id,
        "workers-kv-namespace-get-a-namespace"
    );
    assert!(read.verified_response_fields.is_empty());
    assert!(!delete.rollback.supported);
    assert!(delete.rollback.warning.as_deref().is_some_and(|warning| {
        warning.contains("all contained values") && warning.contains("irreversible")
    }));
    assert!(delete.verification_contract_supported());
    assert_eq!(delete.mutation_contract_gaps().len(), 1);
    assert!(delete.mutation_contract_gaps()[0].contains("cost is not bounded"));
}

#[test]
fn workers_kv_namespace_lifecycle_has_exact_routes_costs_and_recovery_contracts() {
    let snapshot = normalize_openapi(&workers_kv_namespace_fixture()).expect("Workers KV catalog");
    assert_workers_kv_namespace_create(
        snapshot
            .get("workers-kv-namespace-create-a-namespace")
            .expect("create namespace"),
    );
    assert_workers_kv_namespace_rename(
        snapshot
            .get("workers-kv-namespace-rename-a-namespace")
            .expect("rename namespace"),
    );
    assert_workers_kv_namespace_delete_is_cost_blocked(
        snapshot
            .get("workers-kv-namespace-remove-a-namespace")
            .expect("remove namespace"),
    );
}

#[test]
fn workers_kv_namespace_classifier_rejects_legacy_route_and_contract_drift() {
    let mut legacy = workers_kv_namespace_fixture();
    let collection = legacy["paths"]
        .as_object_mut()
        .expect("paths")
        .remove("/accounts/{account_id}/storage/kv/namespaces")
        .expect("collection path");
    let detail = legacy["paths"]
        .as_object_mut()
        .expect("paths")
        .remove("/accounts/{account_id}/storage/kv/namespaces/{namespace_id}")
        .expect("detail path");
    legacy["paths"]["/accounts/{account_id}/workers/namespaces"] = collection;
    legacy["paths"]["/accounts/{account_id}/workers/namespaces/{namespace_id}"] = detail;
    let snapshot = normalize_openapi(&legacy).expect("legacy Workers KV catalog");
    for capability_id in [
        "workers-kv-namespace-create-a-namespace",
        "workers-kv-namespace-rename-a-namespace",
        "workers-kv-namespace-remove-a-namespace",
    ] {
        assert_eq!(
            snapshot
                .get(capability_id)
                .expect("namespace mutation")
                .adapter_status,
            AdapterStatus::Blocked
        );
    }

    let mut permission = workers_kv_namespace_fixture();
    permission["paths"]["/accounts/{account_id}/storage/kv/namespaces"]["post"]["x-api-token-group"] =
        json!(["Workers KV Storage Read"]);
    let snapshot = normalize_openapi(&permission).expect("permission-drifted catalog");
    assert_eq!(
        snapshot
            .get("workers-kv-namespace-create-a-namespace")
            .expect("create")
            .adapter_status,
        AdapterStatus::Blocked
    );

    let mut request = workers_kv_namespace_fixture();
    request["components"]["schemas"]["workers-kv_namespace_title"]["maxLength"] = json!(1024);
    let snapshot = normalize_openapi(&request).expect("request-drifted catalog");
    for capability_id in [
        "workers-kv-namespace-create-a-namespace",
        "workers-kv-namespace-rename-a-namespace",
    ] {
        assert_eq!(
            snapshot
                .get(capability_id)
                .expect("namespace write")
                .adapter_status,
            AdapterStatus::Blocked
        );
    }

    let mut readback = workers_kv_namespace_fixture();
    readback["paths"]["/accounts/{account_id}/storage/kv/namespaces/{namespace_id}"]["get"]["operationId"] =
        json!("workers-kv-namespace-untrusted-readback");
    let snapshot = normalize_openapi(&readback).expect("readback-drifted catalog");
    for capability_id in [
        "workers-kv-namespace-create-a-namespace",
        "workers-kv-namespace-rename-a-namespace",
        "workers-kv-namespace-remove-a-namespace",
    ] {
        assert_eq!(
            snapshot
                .get(capability_id)
                .expect("namespace mutation")
                .adapter_status,
            AdapterStatus::Blocked
        );
    }
}

fn r2_temporary_credentials_fixture() -> Value {
    json!({
        "openapi": "3.0.3",
        "info": {"title": "Cloudflare API", "version": "4.0.0"},
        "servers": [{"url": "https://api.cloudflare.com/client/v4"}],
        "components": {
            "schemas": {
                "identifier": {"type": "string", "maxLength": 32},
                "api-response-common": {
                    "type": "object",
                    "required": ["success"],
                    "properties": {"success": {"type": "boolean"}}
                },
                "token-verify-result": {
                    "type": "object",
                    "required": ["id", "status"],
                    "properties": {
                        "id": {"type": "string", "maxLength": 32},
                        "status": {"type": "string", "enum": ["active", "disabled", "expired"]},
                        "expires_on": {"type": "string", "format": "date-time"},
                        "not_before": {"type": "string", "format": "date-time"}
                    }
                },
                "temporary-credentials-request": {
                    "type": "object",
                    "required": ["bucket", "permission", "ttlSeconds", "parentAccessKeyId"],
                    "properties": {
                        "bucket": {"type": "string"},
                        "objects": {"type": "array", "items": {"type": "string"}},
                        "parentAccessKeyId": {"type": "string"},
                        "permission": {
                            "type": "string",
                            "enum": [
                                "admin-read-write",
                                "admin-read-only",
                                "object-read-write",
                                "object-read-only"
                            ]
                        },
                        "prefixes": {"type": "array", "items": {"type": "string"}},
                        "ttlSeconds": {"type": "number", "maximum": 604_800}
                    }
                },
                "temporary-credentials-result": {
                    "type": "object",
                    "properties": {
                        "accessKeyId": {"type": "string"},
                        "secretAccessKey": {"type": "string", "x-sensitive": true},
                        "sessionToken": {"type": "string", "x-sensitive": true}
                    }
                }
            }
        },
        "paths": {
            "/user/tokens/verify": {
                "get": {
                    "operationId": "user-api-tokens-verify-token",
                    "summary": "Verify Token",
                    "tags": ["User API Tokens"],
                    "responses": {"200": {"description": "Verify token response", "content": {
                        "application/json": {"schema": {"allOf": [
                            {"$ref": "#/components/schemas/api-response-common"},
                            {"type": "object", "properties": {
                                "result": {"$ref": "#/components/schemas/token-verify-result"}
                            }}
                        ]}}
                    }}}
                }
            },
            "/accounts/{account_id}/r2/temp-access-credentials": {
                "post": {
                    "operationId": "r2-create-temp-access-credentials",
                    "summary": "Create Temporary Access Credentials",
                    "description": "Creates temporary access credentials on a bucket that can be optionally scoped to prefixes or objects.",
                    "tags": ["R2 Bucket"],
                    "parameters": [{
                        "in": "path",
                        "name": "account_id",
                        "required": true,
                        "schema": {"$ref": "#/components/schemas/identifier"},
                        "description": "Account ID."
                    }],
                    "requestBody": {"required": true, "content": {"application/json": {
                        "schema": {"$ref": "#/components/schemas/temporary-credentials-request"}
                    }}},
                    "responses": {"200": {"description": "Temporary credentials response", "content": {
                        "application/json": {"schema": {"allOf": [
                            {"$ref": "#/components/schemas/api-response-common"},
                            {"type": "object", "properties": {
                                "result": {"$ref": "#/components/schemas/temporary-credentials-result"}
                            }}
                        ]}}
                    }}}
                }
            }
        }
    })
}

#[test]
fn r2_temporary_credentials_are_parent_bound_sink_only_and_zero_direct_cost() {
    let snapshot = normalize_openapi(&r2_temporary_credentials_fixture())
        .expect("R2 temporary credentials catalog");
    let capability = snapshot
        .get("r2-create-temp-access-credentials")
        .expect("R2 temporary credentials");

    assert_eq!(
        capability.adapter_status,
        AdapterStatus::DynamicApi,
        "{:?}",
        capability.blocked_reason
    );
    assert_eq!(capability.risk, RiskClass::SecretSensitive);
    assert_eq!(capability.effect, EffectClass::IdentityOrOwnership);
    assert_eq!(
        capability.permissions,
        [
            "Workers R2 Storage Write",
            "Workers R2 Storage Read",
            "Workers R2 Storage Bucket Item Write",
            "Workers R2 Storage Bucket Item Read",
            "Workers R2 Data Catalog Write",
            "Workers R2 Data Catalog Read",
        ]
    );
    assert!(capability.cost.known);
    assert!(!capability.cost.incremental);
    assert_eq!(capability.cost.maximum, Some(0.0));
    assert_eq!(capability.cost.billing_model, BillingModelV1::UsageBased);
    assert_eq!(capability.cost.exposure, CostExposureV1::DownstreamUsage);
    assert_eq!(capability.entitlement.available, Some(true));
    assert_eq!(
        capability.entitlement.plans.get("r2_active_subscription"),
        Some(&true)
    );
    assert!(!capability.entitlement.requires_live_resolution);
    assert_eq!(
        capability.verification.strategy,
        "sink_write_and_source_response_status"
    );
    assert!(!capability.verification.required);
    assert!(!capability.rollback.supported);
    assert!(
        capability
            .rollback
            .warning
            .as_deref()
            .is_some_and(|warning| {
                warning.contains("expires automatically")
                    && warning.contains("parent API token")
                    && warning.contains("cannot be revoked individually")
            })
    );
    assert_eq!(
        capability
            .request_schema
            .as_ref()
            .and_then(|schema| schema
                .pointer("/properties/parentAccessKeyId/x-cfctl-derived-from-active-profile"))
            .and_then(Value::as_bool),
        Some(true)
    );
    assert!(capability.mutation_contract_gaps().is_empty());
}

#[test]
fn r2_temporary_credentials_classifier_rejects_request_response_and_verify_drift() {
    let mut ttl = r2_temporary_credentials_fixture();
    ttl["components"]["schemas"]["temporary-credentials-request"]["properties"]["ttlSeconds"]["maximum"] =
        json!(1_209_600);
    assert_eq!(
        normalize_openapi(&ttl)
            .expect("TTL-drifted catalog")
            .get("r2-create-temp-access-credentials")
            .expect("R2 temporary credentials")
            .adapter_status,
        AdapterStatus::Blocked
    );

    let mut response = r2_temporary_credentials_fixture();
    response["components"]["schemas"]["temporary-credentials-result"]["properties"]
        .as_object_mut()
        .expect("result properties")
        .remove("sessionToken");
    assert_eq!(
        normalize_openapi(&response)
            .expect("response-drifted catalog")
            .get("r2-create-temp-access-credentials")
            .expect("R2 temporary credentials")
            .adapter_status,
        AdapterStatus::Blocked
    );

    let mut verify = r2_temporary_credentials_fixture();
    verify["paths"]["/user/tokens/verify"]["get"]["operationId"] = json!("untrusted-token-verify");
    assert_eq!(
        normalize_openapi(&verify)
            .expect("verify-drifted catalog")
            .get("r2-create-temp-access-credentials")
            .expect("R2 temporary credentials")
            .adapter_status,
        AdapterStatus::Blocked
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
fn selector_contract_preserves_bounded_query_schema_and_serialization() {
    let mut document = fixture();
    document["paths"]["/zones/{zone_id}/dns_records"]["get"]["parameters"]
        .as_array_mut()
        .expect("parameters")
        .push(json!({
            "in": "query",
            "name": "tags",
            "style": "form",
            "explode": false,
            "allowReserved": false,
            "allowEmptyValue": false,
            "schema": {
                "type": "array",
                "minItems": 1,
                "maxItems": 2,
                "uniqueItems": true,
                "items": {"type": "string", "enum": ["one", "two"]}
            }
        }));

    let snapshot = normalize_openapi(&document).expect("catalog");
    let contract = snapshot
        .get("dns-records-list")
        .expect("list capability")
        .selectors
        .iter()
        .find(|selector| selector.name == "tags")
        .and_then(|selector| selector.contract.as_ref())
        .expect("selector contract");
    assert_eq!(contract.schema["type"], "array");
    assert_eq!(contract.schema["minItems"], 1);
    assert_eq!(contract.schema["maxItems"], 2);
    assert_eq!(contract.schema["uniqueItems"], true);
    assert_eq!(contract.schema["items"]["enum"], json!(["one", "two"]));
    assert!(
        !contract.schema.to_string().contains("description"),
        "descriptive source prose must not enter the executable selector schema"
    );
    let query = contract.query.as_ref().expect("query serialization");
    assert_eq!(query.style, "form");
    assert!(!query.explode);
    assert!(!query.allow_reserved);
    assert!(!query.allow_empty_value);
}

#[test]
fn selector_contract_resolves_local_parameter_references_and_operation_overrides() {
    let mut document = fixture();
    document["components"]["parameters"] = json!({
        "AccountId": {
            "in": "path",
            "name": "account_id",
            "required": true,
            "schema": {"type": "string"}
        },
        "PerPage": {
            "in": "query",
            "name": "per_page",
            "required": true,
            "schema": {"type": "integer"}
        }
    });
    document["paths"]["/accounts/{account_id}/widgets"] = json!({
        "parameters": [
            {"$ref": "#/components/parameters/AccountId"},
            {
                "in": "query",
                "name": "scope",
                "schema": {"type": "string"}
            }
        ],
        "get": {
            "operationId": "widgets-list",
            "summary": "List Widgets",
            "parameters": [
                {"$ref": "#/components/parameters/PerPage"},
                {
                    "in": "query",
                    "name": "scope",
                    "required": true,
                    "schema": {"type": "boolean"}
                }
            ]
        }
    });

    let snapshot = normalize_openapi(&document).expect("catalog");
    let capability = snapshot.get("widgets-list").expect("list capability");
    let selector = |name: &str| {
        capability
            .selectors
            .iter()
            .find(|selector| selector.name == name)
            .expect("selector")
    };
    assert_eq!(capability.selectors.len(), 3);
    assert_eq!(selector("account_id").location, "path");
    assert!(selector("account_id").required);
    assert_eq!(selector("per_page").value_type, "integer");
    assert!(selector("per_page").required);
    assert_eq!(selector("scope").value_type, "boolean");
    assert!(selector("scope").required);
}

#[test]
fn selector_contract_rejects_untrusted_broken_and_duplicate_parameters() {
    let mut external = fixture();
    external["paths"]["/zones/{zone_id}/dns_records"]["get"]["parameters"] = json!([{
        "$ref": "https://example.invalid/parameters.json#/Page"
    }]);
    let error = normalize_openapi(&external)
        .expect_err("external parameter references must fail closed")
        .to_string();
    assert!(error.contains("unsupported") && error.contains("example.invalid"));

    let mut unresolved = fixture();
    unresolved["paths"]["/zones/{zone_id}/dns_records"]["get"]["parameters"] = json!([{
        "$ref": "#/components/parameters/Missing"
    }]);
    let error = normalize_openapi(&unresolved)
        .expect_err("broken local parameter references must fail closed")
        .to_string();
    assert!(error.contains("does not resolve") && error.contains("Missing"));

    let mut duplicate = fixture();
    duplicate["paths"]["/zones/{zone_id}/dns_records"]["get"]["parameters"] = json!([
        {"in":"path", "name":"zone_id", "required":true, "schema":{"type":"string"}},
        {"in":"path", "name":"zone_id", "required":true, "schema":{"type":"string"}}
    ]);
    let error = normalize_openapi(&duplicate)
        .expect_err("duplicates inside one parameter scope must fail closed")
        .to_string();
    assert!(error.contains("duplicate") && error.contains("zone_id"));
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
    assert_eq!(deploy.risk, RiskClass::CrossConfig);
    assert_eq!(deploy.effect, EffectClass::ReversibleWrite);
    assert!(deploy.cost.known);
    assert!(!deploy.cost.incremental);
    assert_eq!(
        deploy.verification.strategy,
        "wrangler_deployment_status_reports_promoted_version"
    );
    assert!(deploy.verification_contract_supported());
    assert!(deploy.mutation_contract_gaps().is_empty());
    assert!(deploy.selectors.iter().any(|selector| {
        selector.name == "config" && selector.location == "query" && selector.required
    }));
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
        for selector in capability["selectors"]
            .as_array_mut()
            .expect("selector array")
        {
            selector
                .as_object_mut()
                .expect("selector object")
                .remove("contract");
        }
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
        "tags":["Cloudflare Tunnel"],
        "responses": cloudflare_envelope_responses()
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
fn required_credential_headers_block_dynamic_execution() {
    let mut document = fixture();
    document["paths"]["/accounts/{account_id}/logs/list"] = json!({
        "get": {
            "operationId": "logpull-list",
            "summary": "List log files",
            "parameters": [
                {"in":"path", "name":"account_id", "required":true, "schema":{"type":"string"}},
                {"in":"header", "name":"R2-Access-Key-Id", "required":true, "schema":{"type":"string"}},
                {"in":"header", "name":"R2-Secret-Access-Key", "required":true, "schema":{"type":"string"}}
            ]
        }
    });

    let snapshot = normalize_openapi(&document).expect("catalog");
    let capability = snapshot.get("logpull-list").expect("logpull capability");
    assert_eq!(capability.adapter_status, AdapterStatus::Blocked);
    let reason = capability
        .blocked_reason
        .as_deref()
        .expect("blocked reason");
    assert!(reason.contains("R2-Access-Key-Id") && reason.contains("credential"));
}

#[test]
fn declared_success_responses_require_one_proven_cloudflare_json_envelope() {
    let mut document = fixture();
    document["components"]["schemas"]["ApiEnvelope"] = json!({
        "type": "object",
        "required": ["success", "result"],
        "properties": {
            "success": {"type": "boolean"},
            "result": {"type": "object"},
            "errors": {"type": "array"}
        }
    });
    document["components"]["responses"]["ApiEnvelopeResponse"] = json!({
        "description": "ok",
        "content": {
            "application/json": {
                "schema": {"$ref":"#/components/schemas/ApiEnvelope"}
            }
        }
    });
    for (id, suffix, content) in [
        (
            "widgets-json",
            "json",
            json!({"application/json":{"schema":{"$ref":"#/components/schemas/ApiEnvelope"}}}),
        ),
        (
            "widgets-binary",
            "binary",
            json!({"application/octet-stream":{"schema":{"type":"string", "format":"binary"}}}),
        ),
        (
            "widgets-mixed",
            "mixed",
            json!({
                "application/json":{"schema":{"$ref":"#/components/schemas/ApiEnvelope"}},
                "text/event-stream":{"schema":{"type":"string"}}
            }),
        ),
        (
            "widgets-raw-json",
            "raw-json",
            json!({"application/json":{"schema":{
                "type":"object",
                "properties":{"result":{"type":"object"}}
            }}}),
        ),
    ] {
        document["paths"][format!("/accounts/{{account_id}}/widgets/{suffix}")]["get"] = json!({
        "operationId": id,
        "summary": id,
        "responses": {"200":{"description":"ok", "content":content}}
        });
    }
    document["paths"]["/accounts/{account_id}/widgets/json"]["get"]["responses"]["200"] =
        json!({"$ref":"#/components/responses/ApiEnvelopeResponse"});

    let snapshot = normalize_openapi(&document).expect("catalog");
    let supported = snapshot.get("widgets-json").expect("JSON capability");
    let response = supported
        .response_contract
        .as_ref()
        .expect("response contract");
    assert_eq!(response.success_media_types, vec!["application/json"]);
    assert_eq!(response.success_statuses, vec!["200"]);
    assert_eq!(
        response.body_mode,
        ResponseBodyModeV1::CloudflareJsonEnvelope
    );
    assert_eq!(supported.adapter_status, AdapterStatus::DynamicApi);

    for id in ["widgets-binary", "widgets-mixed", "widgets-raw-json"] {
        let capability = snapshot.get(id).expect("unsupported capability");
        assert_eq!(capability.adapter_status, AdapterStatus::Blocked);
        assert!(
            capability
                .blocked_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("response contract")),
            "{id} must name its response-contract blocker"
        );
    }
}

#[test]
fn response_contract_distinguishes_empty_and_undocumented_successes() {
    let mut document = fixture();
    document["components"]["schemas"]["ApiEnvelope"] = json!({
        "type": "object",
        "required": ["success"],
        "properties": {"success": {"type": "boolean"}}
    });
    document["paths"]["/accounts/{account_id}/empty"]["get"] = json!({
        "operationId": "widgets-empty",
        "responses": {"204": {"description": "No content"}}
    });
    document["paths"]["/accounts/{account_id}/websocket"]["get"] = json!({
        "operationId": "widgets-websocket",
        "responses": {"101": {"description": "Switching protocols"}}
    });
    document["paths"]["/accounts/{account_id}/undocumented"]["get"] = json!({
        "operationId": "widgets-undocumented"
    });
    document["paths"]["/accounts/{account_id}/mixed-empty"]["get"] = json!({
        "operationId": "widgets-mixed-empty",
        "responses": {
            "200": {
                "description": "ok",
                "content": {"application/json": {"schema": {
                    "$ref": "#/components/schemas/ApiEnvelope"
                }}}
            },
            "204": {"description": "No content"}
        }
    });

    let snapshot = normalize_openapi(&document).expect("catalog");
    let empty = snapshot.get("widgets-empty").expect("empty capability");
    let response = empty.response_contract.as_ref().expect("empty contract");
    assert_eq!(response.success_statuses, vec!["204"]);
    assert!(response.success_media_types.is_empty());
    assert_eq!(response.body_mode, ResponseBodyModeV1::Empty);
    assert_eq!(empty.adapter_status, AdapterStatus::DynamicApi);

    for id in [
        "widgets-websocket",
        "widgets-undocumented",
        "widgets-mixed-empty",
    ] {
        let capability = snapshot.get(id).expect("unsupported capability");
        assert_eq!(capability.adapter_status, AdapterStatus::Blocked, "{id}");
        assert_eq!(
            capability
                .response_contract
                .as_ref()
                .expect("explicit response contract")
                .body_mode,
            ResponseBodyModeV1::Unsupported,
            "{id}"
        );
        assert!(
            capability
                .blocked_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("response contract")),
            "{id} must name its response-contract blocker"
        );
    }
}

#[test]
fn late_catalog_classifiers_cannot_bypass_unsupported_response_contracts() {
    let mut document = fixture();
    document["paths"]["/accounts/{account_id}/tokens"]["post"] = json!({
        "operationId":"account-api-tokens-create-token",
        "summary":"Create Token",
        "tags":["Account Owned API Tokens"],
        "x-api-token-group":["Account API Tokens Write"]
    });
    document["paths"]["/zones/{zone_id}/dns_records"]["post"] = json!({
        "operationId":"dns-records-for-a-zone-create-dns-record",
        "summary":"Create DNS Record",
        "tags":["DNS Records for a Zone"],
        "x-api-token-group":["DNS Write"],
        "x-cfPlanAvailability":{"free":true,"pro":true,"business":true,"enterprise":true}
    });

    let snapshot = normalize_openapi(&document).expect("catalog");
    for id in [
        "account-api-tokens-create-token",
        "dns-records-for-a-zone-create-dns-record",
    ] {
        let capability = snapshot.get(id).expect("classified capability");
        assert_eq!(
            capability
                .response_contract
                .as_ref()
                .expect("response contract")
                .body_mode,
            ResponseBodyModeV1::Unsupported,
            "{id}"
        );
        assert_eq!(capability.adapter_status, AdapterStatus::Blocked, "{id}");
        assert!(
            capability
                .blocked_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("response contract")),
            "{id}"
        );
    }
}

#[test]
fn response_contract_rejects_external_broken_and_cyclic_references() {
    for (name, reference) in [
        ("external", "https://example.invalid/response.json"),
        ("broken", "#/components/responses/Missing"),
    ] {
        let mut document = fixture();
        document["paths"][format!("/accounts/{{account_id}}/{name}")]["get"] = json!({
            "operationId": format!("response-{name}"),
            "responses": {"200":{"$ref":reference}}
        });
        let error = normalize_openapi(&document).expect_err("untrusted response reference");
        match name {
            "external" => assert!(matches!(
                error,
                cfctl_catalog::CatalogError::UnsupportedResponseReference(_)
            )),
            "broken" => assert!(matches!(
                error,
                cfctl_catalog::CatalogError::UnresolvedResponseReference(_)
            )),
            _ => unreachable!(),
        }
    }

    let mut document = fixture();
    document["components"]["responses"]["CycleA"] = json!({"$ref":"#/components/responses/CycleB"});
    document["components"]["responses"]["CycleB"] = json!({"$ref":"#/components/responses/CycleA"});
    document["paths"]["/accounts/{account_id}/cycle"]["get"] = json!({
        "operationId": "response-cycle",
        "responses": {"200":{"$ref":"#/components/responses/CycleA"}}
    });
    let error = normalize_openapi(&document).expect_err("cyclic response reference");
    assert!(matches!(
        error,
        cfctl_catalog::CatalogError::ResponseReferenceDepth(_)
    ));
}

#[test]
fn account_token_mutations_have_complete_native_execution_contracts() {
    let mut document = fixture();
    document["paths"]["/accounts/{account_id}/tokens"]["post"] = json!({
        "operationId":"account-api-tokens-create-token",
        "summary":"Create Token",
        "tags":["Account Owned API Tokens"],
        "x-api-token-group":["Account API Tokens Write"],
        "responses": cloudflare_envelope_responses()
    });
    document["paths"]["/accounts/{account_id}/tokens/{token_id}/value"]["put"] = json!({
        "operationId":"account-api-tokens-roll-token",
        "summary":"Roll Token",
        "tags":["Account Owned API Tokens"],
        "x-api-token-group":["Account API Tokens Write"],
        "responses": cloudflare_envelope_responses()
    });
    document["paths"]["/accounts/{account_id}/tokens/{token_id}"]["delete"] = json!({
        "operationId":"account-api-tokens-delete-token",
        "summary":"Delete Token",
        "tags":["Account Owned API Tokens"],
        "x-api-token-group":["Account API Tokens Write"],
        "responses": cloudflare_envelope_responses()
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
fn user_token_creation_uses_the_inventory_bound_native_lifecycle() {
    let mut document = fixture();
    document["paths"]["/user/tokens"]["post"] = json!({
        "operationId":"user-api-tokens-create-token",
        "summary":"Create Token",
        "tags":["User API Tokens"],
        "x-api-token-group":["API Tokens Write"],
        "responses": cloudflare_envelope_responses()
    });

    let snapshot = normalize_openapi(&document).expect("user token catalog");
    let capability = snapshot
        .get("user-api-tokens-create-token")
        .expect("user token create");

    assert_eq!(capability.adapter_status, AdapterStatus::Native);
    assert!(capability.blocked_reason.is_none());
    assert_eq!(
        capability.verification.strategy,
        "api_token_details_match_created_id_and_active_status"
    );
    assert_eq!(
        capability.rollback.strategy.as_deref(),
        Some("revoke_created_api_token_by_returned_id_if_downstream_installation_fails")
    );
    let coverage = snapshot.coverage();
    assert_eq!(coverage.complete_mutation_contracts, 1);
    assert_eq!(coverage.blocked_adapters_without_contract_gaps, 0);
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
fn coverage_classifies_malformed_known_incremental_costs() {
    let mut snapshot = normalize_openapi(&fixture()).expect("catalog");
    let capability = snapshot
        .capabilities
        .get_mut("dns-records-delete")
        .expect("delete capability");
    capability.cost.incremental = true;
    capability.cost.known = true;
    capability.cost.currency = Some("USD".to_owned());
    capability.cost.maximum = Some(f64::INFINITY);

    let coverage = snapshot.coverage();

    assert_eq!(
        coverage.mutation_contract_gap_counts.get("cost_invalid"),
        Some(&1)
    );
    assert_eq!(
        coverage.mutation_contract_gap_counts.get("unclassified"),
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
        "x-cfPlanAvailability":{"free":true,"pro":true,"business":true,"enterprise":true},
        "responses": cloudflare_envelope_responses()
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
        // The delete's declared 200 schema carries no `success` boolean — the
        // live under-declaration that kept it blocked. The finalizer pin, not
        // an envelope-declaring fixture, must be what governs it.
        let responses = if method == "delete" {
            bare_result_id_responses()
        } else {
            cloudflare_envelope_responses()
        };
        document["paths"]["/zones/{zone_id}/dns_records/{dns_record_id}"][method] = json!({
            "operationId":id,
            "summary":summary,
            "tags":["DNS Records for a Zone"],
            "x-api-token-group":["DNS Write"],
            "x-cfPlanAvailability":{"free":true,"pro":true,"business":true,"enterprise":true},
            "parameters":[
                {"in":"path","name":"zone_id","required":true,"schema":{"type":"string"}},
                {"in":"path","name":"dns_record_id","required":true,"schema":{"type":"string"}}
            ],
            "responses": responses
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
    // The fixture's delete schema deliberately omits the `success` envelope
    // (the live under-declaration), so DynamicApi status above proves the
    // finalizer pin fired — assert the pinned mode explicitly.
    assert_eq!(
        delete
            .response_contract
            .as_ref()
            .expect("delete response contract")
            .body_mode,
        ResponseBodyModeV1::CloudflareJsonEnvelope
    );
}

#[test]
fn dns_record_delete_envelope_pin_does_not_leak_to_other_capabilities() {
    // A non-DNS delete with the exact same under-declared bare-result shape
    // must stay blocked: the pin is identity-bound, not shape-bound.
    let mut document = fixture();
    document["paths"]["/zones/{zone_id}/page_shield/policies/{policy_id}"]["delete"] = json!({
        "operationId":"page-shield-delete-a-page-shield-policy",
        "summary":"Delete policy",
        "tags":["Page Shield"],
        "x-api-token-group":["Page Shield"],
        "x-cfPlanAvailability":{"free":true,"pro":true,"business":true,"enterprise":true},
        "parameters":[
            {"in":"path","name":"zone_id","required":true,"schema":{"type":"string"}},
            {"in":"path","name":"policy_id","required":true,"schema":{"type":"string"}}
        ],
        "responses": bare_result_id_responses()
    });
    let snapshot = normalize_openapi(&document).expect("page shield catalog");
    let capability = snapshot
        .get("page-shield-delete-a-page-shield-policy")
        .expect("page shield delete");
    assert_eq!(
        capability
            .response_contract
            .as_ref()
            .expect("response contract")
            .body_mode,
        ResponseBodyModeV1::Unsupported,
        "the DNS delete pin must not repair other under-declared responses"
    );
    assert_eq!(capability.adapter_status, AdapterStatus::Blocked);
    // The precise blocked_reason wording is owned by gap-precedence (contract
    // gaps outrank the response-contract blocker); the leak property under
    // test is the unrepaired body mode and the blocked status above.
    assert!(capability.blocked_reason.is_some());
}

#[test]
fn dns_record_updates_bind_the_exact_detail_read_and_reviewed_restore_contract() {
    let mut document = fixture();
    let request_schema: Value = serde_json::from_str(include_str!(
        "../../cfctl-core/tests/fixtures/dns-record-update-request-schema.json"
    ))
    .expect("pinned DNS record update request schema");
    let parameters = json!([
        {"in":"path","name":"zone_id","required":true,"schema":{"type":"string","maxLength":32}},
        {"in":"path","name":"dns_record_id","required":true,"schema":{"type":"string","maxLength":32}},
        {"in":"query","name":"include_shadow_metadata","required":false,"schema":{"type":"boolean"}}
    ]);
    document["paths"]["/zones/{zone_id}/dns_records/{dns_record_id}"]["get"] = json!({
        "operationId":"dns-records-for-a-zone-dns-record-details",
        "summary":"DNS Record Details",
        "tags":["DNS Records for a Zone"],
        "x-api-token-group":["DNS Read"],
        "parameters":parameters,
        "responses":{"200":{"description":"details","content":{"application/json":{"schema":{
            "type":"object",
            "required":["success","result"],
            "properties":{
                "success":{"type":"boolean"},
                "result":{"type":"object","allOf":[
                    {"anyOf":[
                        {"type":"object","properties":{
                            "comment":{},"content":{},"name":{},"priority":{},"proxied":{},
                            "settings":{},"tags":{},"ttl":{},"type":{}
                        }},
                        {"type":"object","properties":{
                            "comment":{},"data":{},"name":{},"priority":{},"private_routing":{},
                            "proxied":{},"settings":{},"tags":{},"ttl":{},"type":{}
                        }}
                    ]},
                    {"type":"object","properties":{"id":{"type":"string"}}}
                ]}
            }
        }}}}}
    });
    for (method, id) in [
        ("put", "dns-records-for-a-zone-update-dns-record"),
        ("patch", "dns-records-for-a-zone-patch-dns-record"),
    ] {
        document["paths"]["/zones/{zone_id}/dns_records/{dns_record_id}"][method] = json!({
            "operationId":id,
            "summary":"Update DNS Record",
            "tags":["DNS Records for a Zone"],
            "x-api-token-group":["DNS Write"],
            "x-cfPlanAvailability":{"free":true,"pro":true,"business":true,"enterprise":true},
            "parameters":parameters,
            "requestBody":{"required":true,"content":{"application/json":{"schema":request_schema}}},
            "responses":cloudflare_envelope_responses()
        });
    }

    let snapshot = normalize_openapi(&document).expect("DNS update catalog");
    for id in [
        "dns-records-for-a-zone-update-dns-record",
        "dns-records-for-a-zone-patch-dns-record",
    ] {
        let capability = snapshot.get(id).expect("DNS update capability");
        assert!(capability.rollback.supported);
        assert_eq!(
            capability.rollback.strategy.as_deref(),
            Some("restore_dns_record_prior_snapshot_with_put")
        );
        assert_eq!(
            capability
                .same_path_read
                .as_ref()
                .expect("DNS detail read")
                .read_capability_id,
            "dns-records-for-a-zone-dns-record-details"
        );
        assert!(capability.rollback_contract_supported());
    }

    document["paths"]["/zones/{zone_id}/dns_records/{dns_record_id}"]["get"]
        ["responses"]["200"]["content"]["application/json"]["schema"]["properties"]["result"]
        ["allOf"][0]["anyOf"][1]["properties"]
        .as_object_mut()
        .expect("response alternative fields")
        .remove("private_routing");
    let narrowed = normalize_openapi(&document).expect("narrowed DNS response catalog");
    for id in [
        "dns-records-for-a-zone-update-dns-record",
        "dns-records-for-a-zone-patch-dns-record",
    ] {
        let capability = narrowed.get(id).expect("DNS update capability");
        assert!(!capability.rollback.supported);
        assert!(capability.same_path_read.is_none());
    }
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
                    "x-api-token-group":["Widgets Read"],
                    "responses": cloudflare_envelope_responses()
                },
                "delete": {
                    "operationId":"widgets-delete",
                    "summary":"Delete Widget",
                    "tags":["R2 Object"],
                    "parameters":[
                        {"in":"header","name":"cf-r2-jurisdiction","required":false,"schema":{"type":"string"}}
                    ],
                    "x-api-token-group":["Widgets Write"],
                    "responses": cloudflare_envelope_responses()
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

fn singleton_result_object_responses() -> Value {
    json!({
        "200": {"description":"envelope","content":{"application/json":{"schema":{
            "type":"object","properties":{
                "result":{"type":"object","properties":{"id":{"type":"string"}}},
                "success":{"type":"boolean"}
            }}}}}
    })
}

fn singleton_result_array_responses() -> Value {
    json!({
        "200": {"description":"envelope","content":{"application/json":{"schema":{
            "type":"object","properties":{
                "result":{"type":"array","items":{"type":"object","properties":{"id":{"type":"string"}}}},
                "success":{"type":"boolean"}
            }}}}}
    })
}

#[test]
fn singleton_subresource_delete_closes_with_single_object_readback() {
    // Terminal-literal path (`/gizmo/config`) under an identified parent: a
    // singleton the id-parameter heuristic under-covers. Same-path GET returns
    // a single object, so delete-then-not-found is a valid readback.
    let document = json!({
        "openapi":"3.0.3","info":{"title":"Cloudflare API","version":"4.0.0"},
        "paths":{
            "/accounts/{account_id}/gizmo/config":{
                "parameters":[{"in":"path","name":"account_id","required":true,"schema":{"type":"string"}}],
                "get":{"operationId":"gizmo-config-get","summary":"Get Gizmo Config","tags":["Gizmo"],
                    "x-api-token-group":["Gizmo Read"],"responses": singleton_result_object_responses()},
                "delete":{"operationId":"gizmo-config-delete","summary":"Delete Gizmo Config","tags":["Gizmo"],
                    "x-api-token-group":["Gizmo Write"],"responses": singleton_result_object_responses()}
            }
        }
    });
    let snapshot = normalize_openapi(&document).expect("gizmo catalog");
    let del = snapshot
        .get("gizmo-config-delete")
        .expect("singleton delete");
    assert_eq!(
        del.adapter_status,
        AdapterStatus::DynamicApi,
        "reason={:?}",
        del.blocked_reason
    );
    assert_eq!(del.risk, RiskClass::Destructive);
    assert_eq!(del.effect, EffectClass::Destructive);
    assert_eq!(del.cost.maximum, Some(0.0));
    assert_eq!(
        del.verification.strategy,
        "same_resource_returns_not_found_after_delete"
    );
    let target = del.same_path_read.as_ref().expect("same-path readback");
    assert_eq!(target.path, del.path);
    assert_eq!(target.read_capability_id, "gizmo-config-get");
    assert!(!del.rollback.supported);
    assert!(
        del.rollback
            .warning
            .as_deref()
            .is_some_and(|warning| warning.contains("prior resource snapshot"))
    );
    assert!(del.mutation_contract_gaps().is_empty());
}

#[test]
fn singleton_subresource_delete_stays_blocked_when_readback_is_a_collection() {
    // Same terminal-literal shape, but the GET returns an ARRAY: this is a
    // collection, where a delete leaves an empty list, never a not-found. The
    // single-object gate must refuse to auto-close it.
    let document = json!({
        "openapi":"3.0.3","info":{"title":"Cloudflare API","version":"4.0.0"},
        "paths":{
            "/accounts/{account_id}/gizmo/entries":{
                "parameters":[{"in":"path","name":"account_id","required":true,"schema":{"type":"string"}}],
                "get":{"operationId":"gizmo-entries-get","summary":"List Gizmo Entries","tags":["Gizmo"],
                    "x-api-token-group":["Gizmo Read"],"responses": singleton_result_array_responses()},
                "delete":{"operationId":"gizmo-entries-delete","summary":"Delete Gizmo Entries","tags":["Gizmo"],
                    "x-api-token-group":["Gizmo Write"],"responses": singleton_result_array_responses()}
            }
        }
    });
    let snapshot = normalize_openapi(&document).expect("gizmo catalog");
    let del = snapshot
        .get("gizmo-entries-delete")
        .expect("collection delete");
    assert_eq!(
        del.adapter_status,
        AdapterStatus::Blocked,
        "a collection delete must not receive the same-resource-not-found contract"
    );
    assert_ne!(
        del.verification.strategy,
        "same_resource_returns_not_found_after_delete"
    );
}

#[test]
fn singleton_subresource_delete_requires_a_declared_permission_lane() {
    // Never fabricate a permission: a singleton delete whose OpenAPI omits
    // `x-api-token-group` stays blocked on the permission gap.
    let document = json!({
        "openapi":"3.0.3","info":{"title":"Cloudflare API","version":"4.0.0"},
        "paths":{
            "/accounts/{account_id}/gizmo/config":{
                "parameters":[{"in":"path","name":"account_id","required":true,"schema":{"type":"string"}}],
                "get":{"operationId":"gizmo-config-get","summary":"Get Gizmo Config","tags":["Gizmo"],
                    "x-api-token-group":["Gizmo Read"],"responses": singleton_result_object_responses()},
                "delete":{"operationId":"gizmo-config-delete","summary":"Delete Gizmo Config","tags":["Gizmo"],
                    "responses": singleton_result_object_responses()}
            }
        }
    });
    let snapshot = normalize_openapi(&document).expect("gizmo catalog");
    let del = snapshot
        .get("gizmo-config-delete")
        .expect("singleton delete");
    assert_eq!(
        del.adapter_status,
        AdapterStatus::Blocked,
        "a missing permission lane must not be fabricated"
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

#[test]
fn exact_resource_deletes_narrow_open_bodies_and_omit_optional_read_controls() {
    let document = json!({
        "openapi": "3.0.3",
        "info": {"title":"Cloudflare API","version":"4.0.0"},
        "paths": {
            "/zones/{zone_id}/schema_validation/schemas/{schema_id}": {
                "parameters": [
                    {"in":"path","name":"zone_id","required":true,"schema":{"type":"string"}},
                    {"in":"path","name":"schema_id","required":true,"schema":{"type":"string"}}
                ],
                "get": {
                    "operationId":"schema-validation-get-schema",
                    "summary":"Get details of a schema",
                    "tags":["Schema Validation"],
                    "parameters":[
                        {
                            "description":"Omit the source-files of schemas and only retrieve their meta-data.",
                            "in":"query",
                            "name":"omit_source",
                            "required":false,
                            "schema":{"type":"boolean"}
                        }
                    ],
                    "responses": cloudflare_envelope_responses()
                },
                "delete": {
                    "operationId":"schema-validation-delete-schema",
                    "summary":"Delete a schema",
                    "description":"Permanently deletes the schema.",
                    "tags":["Schema Validation"],
                    "x-api-token-group":["Schema Validation Write"],
                    "requestBody":{"required":true,"content":{"application/json":{"schema":{
                        "type":"object"
                    }}}},
                    "responses": cloudflare_envelope_responses()
                }
            },
            "/accounts/{account_id}/jobs/{job_id}": {
                "parameters": [
                    {"in":"path","name":"account_id","required":true,"schema":{"type":"string"}},
                    {"in":"path","name":"job_id","required":true,"schema":{"type":"string"}}
                ],
                "get": {
                    "operationId":"jobs-get",
                    "summary":"Get Job",
                    "tags":["Jobs"],
                    "responses": cloudflare_envelope_responses()
                },
                "delete": {
                    "operationId":"jobs-delete-cancel",
                    "summary":"Cancel Job",
                    "description":"Cancels a running job without deleting its history.",
                    "tags":["Jobs"],
                    "x-api-token-group":["Jobs Write"],
                    "responses": cloudflare_envelope_responses()
                }
            }
        }
    });

    let snapshot = normalize_openapi(&document).expect("delete catalog");
    let deletion = snapshot
        .get("schema-validation-delete-schema")
        .expect("delete schema");
    assert_eq!(
        deletion.verification.strategy,
        "same_resource_returns_not_found_after_delete"
    );
    assert_eq!(
        deletion
            .same_path_read
            .as_ref()
            .expect("same-path readback")
            .read_capability_id,
        "schema-validation-get-schema"
    );
    assert_eq!(
        deletion.request_schema.as_ref().expect("narrow body")["properties"],
        json!({})
    );
    assert!(deletion.mutation_contract_gaps().is_empty());

    let cancellation = snapshot.get("jobs-delete-cancel").expect("cancel job");
    assert_ne!(
        cancellation.verification.strategy,
        "same_resource_returns_not_found_after_delete"
    );
    assert!(cancellation.same_path_read.is_none());
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
    assert!(update.rollback.supported);
    assert_eq!(
        update.rollback.strategy.as_deref(),
        Some("restore_d1_read_replication_prior_mode")
    );
    assert!(update.rollback.warning.as_deref().is_some_and(|warning| {
        warning.contains("separate hash-bound restoration plan")
            && warning.contains("explicit approval")
    }));
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
                    }}}},
                    "responses": cloudflare_envelope_responses()
                },
                "delete": {
                    "operationId":"d1-delete-database",
                    "summary":"Delete D1 Database",
                    "tags":["D1"],
                    "x-api-token-group":["D1 Write"],
                    "responses": cloudflare_envelope_responses()
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
                    "x-api-token-group":["Widgets Write"],
                    "responses": cloudflare_envelope_responses()
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
fn parent_collection_contracts_bind_a_schema_proven_selector_named_identity() {
    let mut document = json!({
        "openapi":"3.0.3",
        "info":{"title":"Cloudflare API","version":"4.0.0"},
        "paths":{
            "/accounts/{account_id}/widgets":{
                "get":{
                    "operationId":"widgets-list",
                    "summary":"List Widgets",
                    "tags":["Widgets"],
                    "parameters":[
                        {"in":"path","name":"account_id","required":true,"schema":{"type":"string"}}
                    ],
                    "responses":{"200":{"description":"ok","content":{"application/json":{"schema":{
                        "type":"object",
                        "properties":{"result":{"type":"array","items":{"type":"object","properties":{
                            "slug":{"type":"string"},"name":{"type":"string"}
                        }}}}
                    }}}}}
                }
            },
            "/accounts/{account_id}/widgets/{slug}":{
                "parameters":[
                    {"in":"path","name":"account_id","required":true,"schema":{"type":"string"}},
                    {"in":"path","name":"slug","required":true,"schema":{"type":"string"}}
                ],
                "delete":{
                    "operationId":"widgets-delete",
                    "summary":"Delete Widget",
                    "tags":["Widgets"],
                    "x-api-token-group":["Widgets Write"]
                },
                "patch":{
                    "operationId":"widgets-update",
                    "summary":"Update Widget",
                    "tags":["Widgets"],
                    "x-api-token-group":["Widgets Write"],
                    "requestBody":{"required":true,"content":{"application/json":{"schema":{
                        "type":"object","properties":{"name":{"type":"string"}}
                    }}}}
                }
            }
        }
    });

    let snapshot = normalize_openapi(&document).expect("selector identity catalog");
    let deleted = snapshot
        .get("widgets-delete")
        .and_then(|capability| capability.deleted_resource.as_ref())
        .expect("selector-backed delete contract");
    assert_eq!(deleted.identity_selector, "slug");
    assert_eq!(deleted.response_item_identity_pointer, "/slug");
    let updated = snapshot
        .get("widgets-update")
        .and_then(|capability| capability.updated_resource.as_ref())
        .expect("selector-backed update contract");
    assert_eq!(updated.identity_selector, "slug");
    assert_eq!(updated.response_item_identity_pointer, "/slug");
    assert_eq!(updated.verified_response_fields, ["name"]);

    document["paths"]["/accounts/{account_id}/widgets"]["get"]["responses"]["200"]["content"]["application/json"]
        ["schema"]["properties"]["result"]["items"]["properties"]["slug"]["type"] =
        json!("integer");
    let incompatible =
        normalize_openapi(&document).expect("incompatible selector identity catalog");
    assert!(
        incompatible
            .get("widgets-delete")
            .expect("delete widget")
            .deleted_resource
            .is_none()
    );
    assert!(
        incompatible
            .get("widgets-update")
            .expect("update widget")
            .updated_resource
            .is_none()
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
                        "properties":{
                            "mode":{"type":"string"},
                            "enabled":{"type":"boolean"},
                            "owner_worker_tag":{"type":"string","writeOnly":true}
                        }
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
    assert!(update.request_object_field_is_write_only("owner_worker_tag"));
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

fn same_path_post_mutation_fixture() -> serde_json::Value {
    json!({
        "openapi":"3.0.3",
        "info":{"title":"Cloudflare API","version":"4.0.0"},
        "paths": {
            "/accounts/{account_id}/settings/example": {
                "get": {
                    "operationId":"settings-get",
                    "tags":["Account Settings"],
                    "responses":{"200":{"description":"ok","content":{"application/json":{"schema":{
                        "type":"object",
                        "properties":{"result":{"type":"object","properties":{
                            "enabled":{"type":"boolean"},"mode":{"type":"string"}
                        }}}
                    }}}}}
                },
                "post": {
                    "operationId":"settings-apply",
                    "tags":["Account Settings"],
                    "x-api-token-group":["Settings Write"],
                    "requestBody":{"required":true,"content":{"application/json":{"schema":{
                        "type":"object",
                        "properties":{"mode":{"type":"string"},"enabled":{"type":"boolean"}}
                    }}}}
                }
            },
            "/accounts/{account_id}/settings/incomplete": {
                "get": {
                    "operationId":"incomplete-settings-get",
                    "tags":["Incomplete Settings"],
                    "responses":{"200":{"description":"ok","content":{"application/json":{"schema":{
                        "type":"object",
                        "properties":{"result":{"type":"object","properties":{"mode":{"type":"string"}}}}
                    }}}}}
                },
                "post": {
                    "operationId":"incomplete-settings-apply",
                    "tags":["Incomplete Settings"],
                    "x-api-token-group":["Settings Write"],
                    "requestBody":{"required":true,"content":{"application/json":{"schema":{
                        "type":"object",
                        "properties":{"mode":{"type":"string"},"hidden":{"type":"boolean"}}
                    }}}}
                }
            },
            "/accounts/{account_id}/widgets": {
                "get": {
                    "operationId":"widgets-list-shaped-as-object",
                    "tags":["Widgets"],
                    "responses":{"200":{"description":"ok","content":{"application/json":{"schema":{
                        "type":"object",
                        "properties":{"result":{"type":"object","properties":{"name":{"type":"string"}}}}
                    }}}}}
                },
                "post": {
                    "operationId":"widgets-create",
                    "tags":["Widgets"],
                    "x-api-token-group":["Widgets Write"],
                    "requestBody":{"required":true,"content":{"application/json":{"schema":{
                        "type":"object","properties":{"name":{"type":"string"}}
                    }}}},
                    "responses":{"201":{"description":"created","content":{"application/json":{"schema":{
                        "type":"object","properties":{"result":{"type":"object","properties":{
                            "id":{"type":"string"},"name":{"type":"string"}
                        }}}
                    }}}}}
                }
            },
            "/accounts/{account_id}/widgets/{widget_id}": {
                "get": {
                    "operationId":"widgets-get",
                    "tags":["Widgets"],
                    "responses":{"200":{"description":"ok","content":{"application/json":{"schema":{
                        "type":"object","properties":{"result":{"type":"object","properties":{
                            "id":{"type":"string"},"name":{"type":"string"}
                        }}}
                    }}}}}
                },
                "delete": {
                    "operationId":"widgets-delete",
                    "tags":["Widgets"],
                    "x-api-token-group":["Widgets Write"]
                }
            }
        }
    })
}

#[test]
fn same_path_post_mutations_require_schema_proven_readback_fields() {
    let document = same_path_post_mutation_fixture();
    let snapshot = normalize_openapi(&document).expect("settings catalog");
    let mutation = snapshot.get("settings-apply").expect("settings apply");
    assert_eq!(
        mutation.verification.strategy,
        "same_path_result_contains_planned_fields_after_mutation"
    );
    let target = mutation
        .same_path_read
        .as_ref()
        .expect("hash-bound same-path readback");
    assert_eq!(target.path, mutation.path);
    assert_eq!(target.read_capability_id, "settings-get");
    assert_eq!(target.verified_response_fields, ["enabled", "mode"]);
    assert!(!mutation.rollback.supported);
    assert!(mutation.rollback.warning.as_deref().is_some_and(|warning| {
        warning.contains("prior state") && warning.contains("separately reviewed")
    }));
    assert_ne!(
        snapshot
            .get("incomplete-settings-apply")
            .expect("incomplete settings apply")
            .verification
            .strategy,
        "same_path_result_contains_planned_fields_after_mutation"
    );
    let create = snapshot.get("widgets-create").expect("widgets create");
    assert_eq!(
        create.verification.strategy,
        "created_resource_contains_planned_fields_by_returned_id"
    );
    assert!(create.created_resource.is_some());
    assert!(create.same_path_read.is_none());
}

fn global_warp_override_fixture() -> serde_json::Value {
    json!({
        "openapi":"3.0.3",
        "info":{"title":"Cloudflare API","version":"4.0.0"},
        "components":{"schemas":{
            "Disconnect":{
                "type":"boolean",
                "description":"Disconnects all devices on the account using Global WARP override.",
                "x-auditable":true
            },
            "Justification":{
                "type":"string",
                "description":"Reasoning for setting the Global WARP override state. This will be surfaced in the audit log.",
                "x-auditable":true
            },
            "OverrideRequest":{
                "type":"object",
                "required":["disconnect"],
                "properties":{
                    "disconnect":{"$ref":"#/components/schemas/Disconnect"},
                    "justification":{"$ref":"#/components/schemas/Justification"}
                }
            },
            "OverrideResult":{
                "type":"object",
                "properties":{
                    "disconnect":{"$ref":"#/components/schemas/Disconnect"},
                    "timestamp":{"type":"string","format":"date-time"}
                }
            },
            "OverrideResponse":{
                "type":"object",
                "properties":{
                    "success":{"type":"boolean"},
                    "result":{"$ref":"#/components/schemas/OverrideResult"}
                }
            }
        }},
        "paths":{
            "/accounts/{account_id}/devices/resilience/disconnect":{
                "get":{
                    "operationId":"devices-resilience-retrieve-global-warp-override",
                    "summary":"Retrieve Global WARP override state",
                    "description":"Fetch the Global WARP override state.",
                    "tags":["Devices Resilience"],
                    "parameters":[{
                        "in":"path","name":"account_id","required":true,
                        "schema":{"type":"string"}
                    }],
                    "x-api-token-group":[
                        "Zero Trust Resilience Read",
                        "Zero Trust Resilience Write",
                        "Zero Trust Read",
                        "Zero Trust Write"
                    ],
                    "x-fern-availability":"generally-available",
                    "responses":{"200":{
                        "description":"Fetch Global WARP override state response.",
                        "content":{"application/json":{"schema":{
                            "$ref":"#/components/schemas/OverrideResponse"
                        }}}
                    }}
                },
                "post":{
                    "operationId":"devices-resilience-set-global-warp-override",
                    "summary":"Set Global WARP override state",
                    "description":"Sets the Global WARP override state.",
                    "tags":["Devices Resilience"],
                    "parameters":[{
                        "in":"path","name":"account_id","required":true,
                        "schema":{"type":"string"}
                    }],
                    "x-api-token-group":["Zero Trust Resilience Write"],
                    "x-fern-availability":"generally-available",
                    "requestBody":{"required":true,"content":{"application/json":{"schema":{
                        "$ref":"#/components/schemas/OverrideRequest"
                    }}}},
                    "responses":{"200":{
                        "description":"Set Global WARP override state response.",
                        "content":{"application/json":{"schema":{
                            "$ref":"#/components/schemas/OverrideResponse"
                        }}}
                    }}
                }
            }
        }
    })
}

#[test]
fn global_warp_override_has_an_exact_audit_aware_state_contract() {
    let document = global_warp_override_fixture();
    let snapshot = normalize_openapi(&document).expect("Global WARP override catalog");
    let mutation = snapshot
        .get("devices-resilience-set-global-warp-override")
        .expect("set Global WARP override");

    assert_eq!(mutation.risk, RiskClass::CrossConfig);
    assert_eq!(mutation.effect, EffectClass::ReversibleWrite);
    assert_eq!(mutation.adapter_status, AdapterStatus::DynamicApi);
    assert!(mutation.mutation_contract_gaps().is_empty());
    assert!(mutation.cost.known);
    assert!(!mutation.cost.incremental);
    assert_eq!(mutation.cost.maximum, Some(0.0));
    assert_eq!(mutation.cost.billing_model, BillingModelV1::Subscription);
    assert_eq!(mutation.cost.exposure, CostExposureV1::DownstreamUsage);
    assert!(mutation.cost.references.iter().any(|reference| {
        reference.url
            == "https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/configure/settings/"
    }));
    assert_eq!(mutation.entitlement.available, Some(true));
    assert_eq!(mutation.entitlement.plans.get("free"), Some(&true));
    assert_eq!(mutation.entitlement.plans.get("paid"), Some(&true));
    assert_eq!(
        mutation.entitlement.source.as_deref(),
        Some(
            "https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/configure/settings/"
        )
    );
    assert_eq!(
        mutation.verification.strategy,
        "same_path_result_contains_planned_fields_after_mutation"
    );
    assert_eq!(
        mutation
            .same_path_read
            .as_ref()
            .expect("exact state readback")
            .verified_response_fields,
        ["disconnect"]
    );
    assert_eq!(
        mutation.request_schema.as_ref().expect("request schema")["properties"]["justification"]["x-cfctl-verification-observable"],
        false
    );
    assert_eq!(
        mutation.request_schema.as_ref().expect("request schema")["additionalProperties"],
        false
    );
    assert!(mutation.rollback.warning.as_deref().is_some_and(|warning| {
        warning.contains("separate hash-bound restoration plan")
            && warning.contains("explicit approval")
            && warning.contains("Super Administrator")
            && warning.contains("10 minutes")
    }));
    assert!(mutation.rollback.supported);
    assert_eq!(
        mutation.rollback.strategy.as_deref(),
        Some("restore_global_warp_override_prior_disconnect_state")
    );

    let mut drifted = document;
    drifted["components"]["schemas"]["Justification"]["description"] =
        json!("An unclassified free-form field.");
    let drifted_snapshot = normalize_openapi(&drifted).expect("drifted catalog");
    let drifted_mutation = drifted_snapshot
        .get("devices-resilience-set-global-warp-override")
        .expect("drifted Global WARP override");
    assert_eq!(drifted_mutation.risk, RiskClass::Unknown);
    assert_ne!(
        drifted_mutation.verification.strategy,
        "same_path_result_contains_planned_fields_after_mutation"
    );
    assert_eq!(drifted_mutation.adapter_status, AdapterStatus::Blocked);

    let mut enriched = snapshot;
    attach_official_product_knowledge(&mut enriched, &pricing_feeds_fixture())
        .expect("attach official knowledge");
    assert_eq!(
        enriched
            .get("devices-resilience-set-global-warp-override")
            .expect("enriched Global WARP override")
            .entitlement
            .source
            .as_deref(),
        Some(
            "https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/configure/settings/"
        )
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

struct AccessConfigurationFixture {
    collection_path: &'static str,
    detail_path: &'static str,
    create_id: &'static str,
    update_id: &'static str,
    read_id: &'static str,
    delete_id: &'static str,
    product: &'static str,
    permission: &'static str,
    expected_risk: RiskClass,
    expected_effect: EffectClass,
}

fn access_configuration_fixture(case: &AccessConfigurationFixture) -> serde_json::Value {
    let mut document = create_lifecycle_fixture();
    let mut collection = document["paths"]
        .as_object_mut()
        .expect("paths")
        .remove("/accounts/{account_id}/widgets")
        .expect("widget collection");
    collection["post"]["operationId"] = json!(case.create_id);
    collection["post"]["tags"] = json!([case.product]);
    collection["post"]["x-api-token-group"] = json!([case.permission]);

    let mut detail = document["paths"]
        .as_object_mut()
        .expect("paths")
        .remove("/accounts/{account_id}/widgets/{widget_id}")
        .expect("widget detail");
    let identity_selector = case
        .detail_path
        .rsplit_once('{')
        .and_then(|(_, suffix)| suffix.strip_suffix('}'))
        .expect("identity selector");
    detail["parameters"][1]["name"] = json!(identity_selector);
    detail["get"]["operationId"] = json!(case.read_id);
    detail["get"]["tags"] = json!([case.product]);
    detail["delete"]["operationId"] = json!(case.delete_id);
    detail["delete"]["tags"] = json!([case.product]);
    detail["delete"]["x-api-token-group"] = json!([case.permission]);
    detail["put"] = json!({
        "operationId": case.update_id,
        "summary": "Update Access configuration",
        "tags": [case.product],
        "x-api-token-group": [case.permission],
        "requestBody": {
            "required": true,
            "content": {"application/json": {"schema": {
                "type": "object",
                "required": ["name"],
                "properties": {"name": {"type": "string"}}
            }}}
        },
        "responses": {
            "200": {
                "description": "Access configuration updated",
                "content": {
                    "application/json": {
                        "schema": {"$ref": "#/components/schemas/WidgetResponse"}
                    }
                }
            }
        }
    });
    document["paths"][case.collection_path] = collection;
    document["paths"][case.detail_path] = detail;
    document
}

#[test]
fn access_authorization_configuration_has_exact_cost_entitlement_and_risk_contracts() {
    let fixtures = [
        AccessConfigurationFixture {
            collection_path: "/accounts/{account_id}/access/groups",
            detail_path: "/accounts/{account_id}/access/groups/{group_id}",
            create_id: "access-groups-create-an-access-group",
            update_id: "access-groups-update-an-access-group",
            read_id: "access-groups-get-an-access-group",
            delete_id: "access-groups-delete-an-access-group",
            product: "Access groups",
            permission: "Access: Organizations, Identity Providers, and Groups Write",
            expected_risk: RiskClass::CrossConfig,
            expected_effect: EffectClass::ReversibleWrite,
        },
        AccessConfigurationFixture {
            collection_path: "/accounts/{account_id}/access/identity_providers",
            detail_path: "/accounts/{account_id}/access/identity_providers/{identity_provider_id}",
            create_id: "access-identity-providers-add-an-access-identity-provider",
            update_id: "access-identity-providers-update-an-access-identity-provider",
            read_id: "access-identity-providers-get-an-access-identity-provider",
            delete_id: "access-identity-providers-delete-an-access-identity-provider",
            product: "Access identity providers",
            permission: "Access: Organizations, Identity Providers, and Groups Write",
            expected_risk: RiskClass::IdentityOrOwnership,
            expected_effect: EffectClass::IdentityOrOwnership,
        },
        AccessConfigurationFixture {
            collection_path: "/accounts/{account_id}/access/policies",
            detail_path: "/accounts/{account_id}/access/policies/{policy_id}",
            create_id: "access-policies-create-an-access-reusable-policy",
            update_id: "access-policies-update-an-access-reusable-policy",
            read_id: "access-policies-get-an-access-reusable-policy",
            delete_id: "access-policies-delete-an-access-reusable-policy",
            product: "Access reusable policies",
            permission: "Access: Apps and Policies Write",
            expected_risk: RiskClass::CrossConfig,
            expected_effect: EffectClass::ReversibleWrite,
        },
    ];

    for case in fixtures {
        let document = access_configuration_fixture(&case);
        let snapshot = normalize_openapi(&document).expect("Access configuration catalog");
        for id in [case.create_id, case.update_id] {
            let capability = snapshot.get(id).expect("Access configuration mutation");
            assert_eq!(capability.adapter_status, AdapterStatus::DynamicApi);
            assert_eq!(capability.risk, case.expected_risk);
            assert_eq!(capability.effect, case.expected_effect);
            assert!(capability.cost.known);
            assert!(!capability.cost.incremental);
            assert_eq!(capability.cost.maximum, Some(0.0));
            assert_eq!(capability.cost.billing_model, BillingModelV1::Subscription);
            assert_eq!(capability.cost.exposure, CostExposureV1::DownstreamUsage);
            assert!(capability.cost.references.iter().any(|reference| {
                reference.url == "https://www.cloudflare.com/plans/zero-trust-services/"
            }));
            assert!(capability.cost.references.iter().any(|reference| {
                reference.url
                    == "https://developers.cloudflare.com/cloudflare-one/team-and-resources/users/seat-management/"
            }));
            assert_eq!(capability.entitlement.available, Some(true));
            assert_eq!(capability.entitlement.plans.get("free"), Some(&true));
            assert_eq!(
                capability.entitlement.plans.get("pay_as_you_go"),
                Some(&true)
            );
            assert_eq!(capability.entitlement.plans.get("contract"), Some(&true));
            assert!(capability.mutation_contract_gaps().is_empty());
        }
    }
}

#[test]
fn access_authorization_configuration_classifier_rejects_retargeting_and_permission_drift() {
    let groups = AccessConfigurationFixture {
        collection_path: "/accounts/{account_id}/access/groups",
        detail_path: "/accounts/{account_id}/access/groups/{group_id}",
        create_id: "access-groups-create-an-access-group",
        update_id: "access-groups-update-an-access-group",
        read_id: "access-groups-get-an-access-group",
        delete_id: "access-groups-delete-an-access-group",
        product: "Access groups",
        permission: "Access: Organizations, Identity Providers, and Groups Write",
        expected_risk: RiskClass::CrossConfig,
        expected_effect: EffectClass::ReversibleWrite,
    };
    let mut retargeted = access_configuration_fixture(&groups);
    let collection = retargeted["paths"]
        .as_object_mut()
        .expect("paths")
        .remove("/accounts/{account_id}/access/groups")
        .expect("Access groups collection");
    retargeted["paths"]["/accounts/{account_id}/access/group_templates"] = collection;
    let retargeted_snapshot = normalize_openapi(&retargeted).expect("retargeted Access catalog");
    let retargeted_create = retargeted_snapshot
        .get("access-groups-create-an-access-group")
        .expect("retargeted create");
    assert_eq!(retargeted_create.risk, RiskClass::Unknown);
    assert!(!retargeted_create.cost.known);
    assert_eq!(retargeted_create.adapter_status, AdapterStatus::Blocked);

    let policies = AccessConfigurationFixture {
        collection_path: "/accounts/{account_id}/access/policies",
        detail_path: "/accounts/{account_id}/access/policies/{policy_id}",
        create_id: "access-policies-create-an-access-reusable-policy",
        update_id: "access-policies-update-an-access-reusable-policy",
        read_id: "access-policies-get-an-access-reusable-policy",
        delete_id: "access-policies-delete-an-access-reusable-policy",
        product: "Access reusable policies",
        permission: "Access: Apps and Policies Write",
        expected_risk: RiskClass::CrossConfig,
        expected_effect: EffectClass::ReversibleWrite,
    };
    let mut permission_drift = access_configuration_fixture(&policies);
    permission_drift["paths"]["/accounts/{account_id}/access/policies"]["post"]["x-api-token-group"] =
        json!(["Account Settings Write"]);
    let permission_snapshot =
        normalize_openapi(&permission_drift).expect("permission-drifted Access catalog");
    let drifted_create = permission_snapshot
        .get("access-policies-create-an-access-reusable-policy")
        .expect("permission-drifted create");
    assert_eq!(drifted_create.risk, RiskClass::Unknown);
    assert!(!drifted_create.cost.known);
    assert_eq!(drifted_create.adapter_status, AdapterStatus::Blocked);
}

fn access_service_token_fixture() -> serde_json::Value {
    let mut fixture = json!({
        "openapi": "3.0.3",
        "info": {"title":"Cloudflare API","version":"4.0.0"},
        "components": {
            "schemas": {
                "ServiceToken": {
                    "type":"object",
                    "properties": {
                        "id":{"type":"string"},
                        "client_id":{"type":"string"},
                        "client_secret":{"type":"string"},
                        "client_secret_version":{"type":"number"},
                        "created_at":{"type":"string","format":"date-time"},
                        "duration":{"type":"string"},
                        "expires_at":{"type":"string","format":"date-time"},
                        "name":{"type":"string"},
                        "previous_client_secret_expires_at":{"type":"string","format":"date-time"},
                        "updated_at":{"type":"string","format":"date-time"}
                    }
                },
                "ServiceTokenResponse": {
                    "type":"object",
                    "properties": {
                        "success":{"type":"boolean"},
                        "result":{"$ref":"#/components/schemas/ServiceToken"}
                    }
                }
            }
        },
        "paths": {
            "/accounts/{account_id}/access/service_tokens": {
                "parameters":[
                    {"in":"path","name":"account_id","required":true,"description":"Identifier.","schema":{"type":"string","maxLength":32}}
                ],
                "post": {
                    "operationId":"access-service-tokens-create-a-service-token",
                    "summary":"Create a service token",
                    "description":"Generates a new service token. **Note:** This is the only time you can get the Client Secret. If you lose the Client Secret, you will have to rotate the Client Secret or create a new service token.",
                    "tags":["Access service tokens"],
                    "x-api-token-group":["Access: Service Tokens Write"],
                    "requestBody": {
                        "required":true,
                        "content":{"application/json":{"schema":{
                            "type":"object",
                            "required":["name"],
                            "properties":{
                                "client_secret_version":{"type":"number"},
                                "duration":{"type":"string"},
                                "name":{"type":"string"},
                                "previous_client_secret_expires_at":{"type":"string","format":"date-time"}
                            }
                        }}}
                    },
                    "responses":{"201":{
                        "description":"Service token created",
                        "content":{"application/json":{"schema":{"$ref":"#/components/schemas/ServiceTokenResponse"}}}
                    }}
                }
            }
        }
    });
    fixture["paths"]
        .as_object_mut()
        .expect("Access service-token paths")
        .insert(
            "/accounts/{account_id}/access/service_tokens/{service_token_id}".to_owned(),
            access_service_token_detail_fixture(),
        );
    fixture["paths"]
        .as_object_mut()
        .expect("Access service-token paths")
        .insert(
            "/accounts/{account_id}/access/service_tokens/{service_token_id}/rotate".to_owned(),
            access_service_token_rotate_fixture(),
        );
    fixture["paths"]
        .as_object_mut()
        .expect("Access service-token paths")
        .insert(
            "/accounts/{account_id}/access/service_tokens/{service_token_id}/refresh".to_owned(),
            access_service_token_refresh_fixture(),
        );
    fixture["paths"]["/accounts/{account_id}/access/service_tokens/{service_token_id}"]
        .as_object_mut()
        .expect("Access service-token detail operations")
        .insert("put".to_owned(), access_service_token_update_fixture());
    fixture
}

fn zone_access_service_token_fixture() -> serde_json::Value {
    let mut fixture = access_service_token_fixture();
    let paths = fixture["paths"]
        .as_object_mut()
        .expect("Access service-token paths");
    let mut collection = paths
        .remove("/accounts/{account_id}/access/service_tokens")
        .expect("account service-token collection");
    let mut detail = paths
        .remove("/accounts/{account_id}/access/service_tokens/{service_token_id}")
        .expect("account service-token detail");

    collection["parameters"][0]["name"] = json!("zone_id");
    collection["post"]["operationId"] =
        json!("zone-level-access-service-tokens-create-a-service-token");
    collection["post"]["description"] = json!(
        "Generates a new service token. **Note:** This is the only time you can get the Client Secret. If you lose the Client Secret, you will have to create a new service token."
    );
    collection["post"]["tags"] = json!(["Zone-Level Access service tokens"]);

    for parameter in detail["parameters"]
        .as_array_mut()
        .expect("service-token detail parameters")
    {
        if parameter["name"] == "account_id" {
            parameter["name"] = json!("zone_id");
        }
    }
    detail["get"]["operationId"] = json!("zone-level-access-service-tokens-get-a-service-token");
    detail["get"]["tags"] = json!(["Zone-Level Access service tokens"]);
    detail["delete"]["operationId"] =
        json!("zone-level-access-service-tokens-delete-a-service-token");
    detail["delete"]["tags"] = json!(["Zone-Level Access service tokens"]);
    detail["put"]["operationId"] = json!("zone-level-access-service-tokens-update-a-service-token");
    detail["put"]["tags"] = json!(["Zone-Level Access service tokens"]);

    paths.clear();
    paths.insert(
        "/zones/{zone_id}/access/service_tokens".to_owned(),
        collection,
    );
    paths.insert(
        "/zones/{zone_id}/access/service_tokens/{service_token_id}".to_owned(),
        detail,
    );
    fixture
}

fn access_service_token_detail_fixture() -> serde_json::Value {
    json!({
        "parameters":[
            {"in":"path","name":"service_token_id","required":true,"description":"UUID.","schema":{"type":"string","maxLength":36}},
            {"in":"path","name":"account_id","required":true,"description":"Identifier.","schema":{"type":"string","maxLength":32}}
        ],
        "get": {
            "operationId":"access-service-tokens-get-a-service-token",
            "summary":"Get a service token",
            "tags":["Access service tokens"],
            "x-api-token-group":["Access: Service Tokens Write","Access: Service Tokens Read"],
            "responses":{"200":{
                "description":"Service token",
                "content":{"application/json":{"schema":{"$ref":"#/components/schemas/ServiceTokenResponse"}}}
            }}
        },
        "delete": {
            "operationId":"access-service-tokens-delete-a-service-token",
            "summary":"Delete a service token",
            "tags":["Access service tokens"],
            "x-api-token-group":["Access: Service Tokens Write"],
            "responses":{"200":{
                "description":"Service token deleted",
                "content":{"application/json":{"schema":{"$ref":"#/components/schemas/ServiceTokenResponse"}}}
            }}
        }
    })
}

fn access_service_token_refresh_fixture() -> serde_json::Value {
    json!({
        "parameters":[
            {"in":"path","name":"service_token_id","required":true,"description":"UUID.","schema":{"type":"string","maxLength":36}},
            {"in":"path","name":"account_id","required":true,"description":"Identifier.","schema":{"type":"string","maxLength":32}}
        ],
        "post": {
            "operationId":"access-service-tokens-refresh-a-service-token",
            "summary":"Refresh a service token",
            "description":"Refreshes the expiration of a service token.",
            "tags":["Access service tokens"],
            "x-api-token-group":["Access: Service Tokens Write"],
            "responses":{"200":{
                "description":"Service token refreshed",
                "content":{"application/json":{"schema":{"$ref":"#/components/schemas/ServiceTokenResponse"}}}
            }}
        }
    })
}

fn access_service_token_update_fixture() -> serde_json::Value {
    json!({
        "operationId":"access-service-tokens-update-a-service-token",
        "summary":"Update a service token",
        "description":"Updates a configured service token.",
        "tags":["Access service tokens"],
        "x-api-token-group":["Access: Service Tokens Write"],
        "requestBody": {
            "required":true,
            "content":{"application/json":{"schema":{
                "type":"object",
                "properties":{
                    "client_secret_version":{"type":"number"},
                    "duration":{"type":"string"},
                    "name":{"type":"string"},
                    "previous_client_secret_expires_at":{"type":"string","format":"date-time"}
                }
            }}}
        },
        "responses":{"200":{
            "description":"Service token updated",
            "content":{"application/json":{"schema":{"$ref":"#/components/schemas/ServiceTokenResponse"}}}
        }}
    })
}

fn access_service_token_rotate_fixture() -> serde_json::Value {
    json!({
        "parameters":[
            {"in":"path","name":"service_token_id","required":true,"description":"UUID.","schema":{"type":"string","maxLength":36}},
            {"in":"path","name":"account_id","required":true,"description":"Identifier.","schema":{"type":"string","maxLength":32}}
        ],
        "post": {
            "operationId":"access-service-tokens-rotate-a-service-token",
            "summary":"Rotate a service token",
            "description":"Generates a new Client Secret for a service token and revokes the old one.",
            "tags":["Access service tokens"],
            "requestBody": {
                "required":false,
                "content":{"application/json":{"schema":{
                    "type":"object",
                    "properties":{"previous_client_secret_expires_at":{"type":"string","format":"date-time"}}
                }}}
            },
            "responses":{"200":{
                "description":"Service token rotated",
                "content":{"application/json":{"schema":{"$ref":"#/components/schemas/ServiceTokenResponse"}}}
            }}
        }
    })
}

#[test]
fn access_service_token_creation_is_a_secret_safe_exact_resource_lifecycle() {
    let snapshot =
        normalize_openapi(&access_service_token_fixture()).expect("Access token catalog");
    let create = snapshot
        .get("access-service-tokens-create-a-service-token")
        .expect("Access service-token create");

    assert_eq!(create.adapter_status, AdapterStatus::DynamicApi);
    assert_eq!(create.risk, RiskClass::SecretSensitive);
    assert_eq!(create.effect, EffectClass::IdentityOrOwnership);
    assert!(create.cost.known);
    assert!(!create.cost.incremental);
    assert_eq!(create.cost.maximum, Some(0.0));
    assert_eq!(create.cost.billing_model, BillingModelV1::Subscription);
    assert_eq!(create.cost.exposure, CostExposureV1::AccountQuote);
    assert!(create.cost.references.iter().any(|reference| {
        reference.url
            == "https://developers.cloudflare.com/cloudflare-one/access-controls/service-credentials/service-tokens/"
    }));
    assert!(create.cost.references.iter().any(|reference| {
        reference.url == "https://developers.cloudflare.com/cloudflare-one/account-limits/"
    }));
    assert_eq!(create.entitlement.available, Some(true));
    assert_eq!(create.entitlement.plans.get("free"), Some(&true));
    assert_eq!(create.entitlement.plans.get("pay_as_you_go"), Some(&true));
    assert_eq!(create.entitlement.plans.get("contract"), Some(&true));
    assert_eq!(
        create.verification.strategy,
        "created_resource_contains_planned_fields_by_returned_id"
    );
    let target = create
        .created_resource
        .as_ref()
        .expect("exact resource target");
    assert_eq!(
        target.detail_path,
        "/accounts/{account_id}/access/service_tokens/{service_token_id}"
    );
    assert_eq!(target.identity_selector, "service_token_id");
    assert_eq!(target.response_result_identity_pointer, "/id");
    assert_eq!(
        target.read_capability_id,
        "access-service-tokens-get-a-service-token"
    );
    assert_eq!(
        target.delete_capability_id,
        "access-service-tokens-delete-a-service-token"
    );
    assert_eq!(target.verified_response_fields, ["duration", "name"]);
    assert_eq!(
        create.rollback.strategy.as_deref(),
        Some("delete_created_resource_by_returned_id")
    );
    assert_eq!(
        create
            .request_schema
            .as_ref()
            .expect("narrow create schema"),
        &json!({
            "type":"object",
            "additionalProperties":false,
            "required":["name"],
            "properties":{
                "duration":{"type":"string"},
                "name":{"type":"string"}
            },
            "x-cfctl-body-required":true
        })
    );
    assert!(create.mutation_contract_gaps().is_empty());

    let rotate = snapshot
        .get("access-service-tokens-rotate-a-service-token")
        .expect("Access service-token rotate");
    assert_eq!(rotate.adapter_status, AdapterStatus::Blocked);
    assert!(rotate.permissions.is_empty());
    assert!(rotate.blocked_reason.as_deref().is_some_and(|reason| {
        reason.contains("required Cloudflare permission lane is not declared")
    }));
}

#[test]
fn zone_access_service_token_creation_is_a_secret_safe_exact_resource_lifecycle() {
    let snapshot = normalize_openapi(&zone_access_service_token_fixture())
        .expect("zone Access service-token catalog");
    let create = snapshot
        .get("zone-level-access-service-tokens-create-a-service-token")
        .expect("zone Access service-token create");

    assert_eq!(create.adapter_status, AdapterStatus::DynamicApi);
    assert_eq!(create.risk, RiskClass::SecretSensitive);
    assert_eq!(create.effect, EffectClass::IdentityOrOwnership);
    assert!(create.cost.known);
    assert!(!create.cost.incremental);
    assert_eq!(create.cost.maximum, Some(0.0));
    assert_eq!(create.cost.billing_model, BillingModelV1::Subscription);
    assert_eq!(create.cost.exposure, CostExposureV1::AccountQuote);
    assert_eq!(create.entitlement.available, Some(true));
    assert_eq!(
        create.verification.strategy,
        "created_resource_contains_planned_fields_by_returned_id"
    );
    let target = create
        .created_resource
        .as_ref()
        .expect("exact zone service-token target");
    assert_eq!(
        target.detail_path,
        "/zones/{zone_id}/access/service_tokens/{service_token_id}"
    );
    assert_eq!(target.identity_selector, "service_token_id");
    assert_eq!(target.response_result_identity_pointer, "/id");
    assert_eq!(
        target.read_capability_id,
        "zone-level-access-service-tokens-get-a-service-token"
    );
    assert_eq!(
        target.delete_capability_id,
        "zone-level-access-service-tokens-delete-a-service-token"
    );
    assert_eq!(target.verified_response_fields, ["duration", "name"]);
    assert_eq!(
        create.rollback.strategy.as_deref(),
        Some("delete_created_resource_by_returned_id")
    );
    assert_eq!(
        create
            .request_schema
            .as_ref()
            .expect("narrow zone create schema"),
        &json!({
            "type":"object",
            "additionalProperties":false,
            "required":["name"],
            "properties":{
                "duration":{"type":"string"},
                "name":{"type":"string"}
            },
            "x-cfctl-body-required":true
        })
    );
    assert!(create.mutation_contract_gaps().is_empty());
}

#[test]
fn zone_access_service_token_creation_rejects_authority_and_schema_drift() {
    let blocked = |document: serde_json::Value| {
        normalize_openapi(&document)
            .expect("drifted zone Access service-token catalog")
            .get("zone-level-access-service-tokens-create-a-service-token")
            .expect("zone Access service-token create")
            .adapter_status
            == AdapterStatus::Blocked
    };

    let mut permission = zone_access_service_token_fixture();
    permission["paths"]["/zones/{zone_id}/access/service_tokens"]["post"]["x-api-token-group"] =
        json!(["Account Settings Write"]);
    assert!(blocked(permission));

    let mut request = zone_access_service_token_fixture();
    request["paths"]["/zones/{zone_id}/access/service_tokens"]["post"]["requestBody"]["content"]
        ["application/json"]["schema"]["properties"]["tamper_mode"] = json!({"type":"boolean"});
    assert!(blocked(request));

    let mut secret = zone_access_service_token_fixture();
    secret["components"]["schemas"]["ServiceToken"]["properties"]["client_secret"]["type"] =
        json!("integer");
    assert!(blocked(secret));
}

#[test]
fn zone_access_service_token_update_excludes_rotation_controls_and_reads_back_metadata() {
    let snapshot = normalize_openapi(&zone_access_service_token_fixture())
        .expect("zone Access service-token catalog");
    let update = snapshot
        .get("zone-level-access-service-tokens-update-a-service-token")
        .expect("zone Access service-token update");

    assert_eq!(update.adapter_status, AdapterStatus::DynamicApi);
    assert_eq!(update.risk, RiskClass::IdentityOrOwnership);
    assert_eq!(update.effect, EffectClass::IdentityOrOwnership);
    assert!(update.cost.known);
    assert_eq!(update.entitlement.available, Some(true));
    assert_eq!(
        update.verification.strategy,
        "same_resource_contains_planned_fields_after_update"
    );
    let readback = update
        .same_path_read
        .as_ref()
        .expect("zone service-token update readback");
    assert_eq!(
        readback.path,
        "/zones/{zone_id}/access/service_tokens/{service_token_id}"
    );
    assert_eq!(
        readback.read_capability_id,
        "zone-level-access-service-tokens-get-a-service-token"
    );
    assert_eq!(readback.verified_response_fields, ["duration", "name"]);
    assert_eq!(
        update
            .request_schema
            .as_ref()
            .expect("narrow zone update schema"),
        &json!({
            "type":"object",
            "additionalProperties":false,
            "properties":{
                "duration":{"type":"string"},
                "name":{"type":"string"}
            },
            "x-cfctl-body-required":true
        })
    );
    assert!(!update.rollback.supported);
    assert!(update.rollback.warning.as_deref().is_some_and(|warning| {
        warning.contains("exact prior expiration") && warning.contains("separately reviewed")
    }));
    assert!(update.mutation_contract_gaps().is_empty());
}

#[test]
fn zone_access_service_token_update_rejects_authority_and_schema_drift() {
    let update_is_blocked = |document: serde_json::Value| {
        normalize_openapi(&document)
            .expect("drifted zone Access service-token catalog")
            .get("zone-level-access-service-tokens-update-a-service-token")
            .expect("zone Access service-token update")
            .adapter_status
            == AdapterStatus::Blocked
    };

    let mut permission = zone_access_service_token_fixture();
    permission["paths"]["/zones/{zone_id}/access/service_tokens/{service_token_id}"]["put"]["x-api-token-group"] =
        json!(["Account Settings Write"]);
    assert!(update_is_blocked(permission));

    let mut request = zone_access_service_token_fixture();
    request["paths"]["/zones/{zone_id}/access/service_tokens/{service_token_id}"]["put"]["requestBody"]
        ["content"]["application/json"]["schema"]["properties"]["client_secret_version"]["type"] =
        json!("string");
    assert!(update_is_blocked(request));
}

#[test]
fn access_service_token_update_excludes_rotation_controls_and_reads_back_metadata() {
    let snapshot =
        normalize_openapi(&access_service_token_fixture()).expect("Access token catalog");
    let update = snapshot
        .get("access-service-tokens-update-a-service-token")
        .expect("Access service-token update");

    assert_eq!(update.adapter_status, AdapterStatus::DynamicApi);
    assert_eq!(update.risk, RiskClass::IdentityOrOwnership);
    assert_eq!(update.effect, EffectClass::IdentityOrOwnership);
    assert!(update.cost.known);
    assert_eq!(update.entitlement.available, Some(true));
    assert_eq!(
        update.verification.strategy,
        "same_resource_contains_planned_fields_after_update"
    );
    assert_eq!(
        update
            .same_path_read
            .as_ref()
            .expect("service-token update readback")
            .verified_response_fields,
        ["duration", "name"]
    );
    assert_eq!(
        update
            .request_schema
            .as_ref()
            .expect("narrow update schema"),
        &json!({
            "type":"object",
            "additionalProperties":false,
            "properties":{
                "duration":{"type":"string"},
                "name":{"type":"string"}
            },
            "x-cfctl-body-required":true
        })
    );
    assert!(!update.rollback.supported);
    assert!(update.rollback.warning.as_deref().is_some_and(|warning| {
        warning.contains("exact prior expiration") && warning.contains("separately reviewed")
    }));
    assert!(update.mutation_contract_gaps().is_empty());
}

#[test]
fn access_service_token_refresh_is_an_exact_irreversible_expiry_extension() {
    let snapshot =
        normalize_openapi(&access_service_token_fixture()).expect("Access token catalog");
    let refresh = snapshot
        .get("access-service-tokens-refresh-a-service-token")
        .expect("Access service-token refresh");

    assert_eq!(refresh.adapter_status, AdapterStatus::DynamicApi);
    assert_eq!(refresh.risk, RiskClass::Irreversible);
    assert_eq!(refresh.effect, EffectClass::Irreversible);
    assert!(refresh.request_schema.is_none());
    assert!(refresh.cost.known);
    assert!(!refresh.cost.incremental);
    assert_eq!(refresh.cost.maximum, Some(0.0));
    assert_eq!(refresh.entitlement.available, Some(true));
    assert_eq!(
        refresh.verification.strategy,
        "access_service_token_reports_refreshed_expiration"
    );
    let readback = refresh
        .same_path_read
        .as_ref()
        .expect("exact service-token detail readback");
    assert_eq!(
        readback.path,
        "/accounts/{account_id}/access/service_tokens/{service_token_id}"
    );
    assert_eq!(
        readback.read_capability_id,
        "access-service-tokens-get-a-service-token"
    );
    assert_eq!(readback.verified_response_fields, ["expires_at", "id"]);
    assert!(!refresh.rollback.supported);
    assert!(refresh.rollback.warning.as_deref().is_some_and(|warning| {
        warning.contains("cannot restore the prior expiration")
            && warning.contains("one-year extension")
    }));
    assert!(refresh.mutation_contract_gaps().is_empty());
}

#[test]
fn access_service_token_classifiers_reject_authority_and_schema_drift() {
    let blocked = |document: serde_json::Value| {
        normalize_openapi(&document)
            .expect("drifted Access service-token catalog")
            .get("access-service-tokens-create-a-service-token")
            .expect("Access service-token create")
            .adapter_status
            == AdapterStatus::Blocked
    };

    let mut permission = access_service_token_fixture();
    permission["paths"]["/accounts/{account_id}/access/service_tokens"]["post"]["x-api-token-group"] =
        json!(["Account Settings Write"]);
    assert!(blocked(permission));

    let mut request = access_service_token_fixture();
    request["paths"]["/accounts/{account_id}/access/service_tokens"]["post"]["requestBody"]["content"]
        ["application/json"]["schema"]["properties"]["tamper_mode"] = json!({"type":"boolean"});
    assert!(blocked(request));

    let mut update_permission = access_service_token_fixture();
    update_permission["paths"]["/accounts/{account_id}/access/service_tokens/{service_token_id}"]
        ["put"]["x-api-token-group"] = json!(["Account Settings Write"]);
    let update_snapshot =
        normalize_openapi(&update_permission).expect("permission-drifted service-token catalog");
    assert_eq!(
        update_snapshot
            .get("access-service-tokens-update-a-service-token")
            .expect("permission-drifted update")
            .adapter_status,
        AdapterStatus::Blocked
    );

    let mut update_request = access_service_token_fixture();
    update_request["paths"]["/accounts/{account_id}/access/service_tokens/{service_token_id}"]["put"]
        ["requestBody"]["content"]["application/json"]["schema"]["properties"]["client_secret_version"]
        ["type"] = json!("string");
    let update_snapshot =
        normalize_openapi(&update_request).expect("request-drifted service-token catalog");
    assert_eq!(
        update_snapshot
            .get("access-service-tokens-update-a-service-token")
            .expect("request-drifted update")
            .adapter_status,
        AdapterStatus::Blocked
    );

    let mut refresh_permission = access_service_token_fixture();
    refresh_permission["paths"]["/accounts/{account_id}/access/service_tokens/{service_token_id}/refresh"]
        ["post"]["x-api-token-group"] = json!(["Account Settings Write"]);
    let refresh_snapshot =
        normalize_openapi(&refresh_permission).expect("permission-drifted service-token catalog");
    assert_eq!(
        refresh_snapshot
            .get("access-service-tokens-refresh-a-service-token")
            .expect("permission-drifted refresh")
            .adapter_status,
        AdapterStatus::Blocked
    );

    let mut refresh_response = access_service_token_fixture();
    refresh_response["components"]["schemas"]["ServiceToken"]["properties"]["expires_at"]["type"] =
        json!("number");
    let refresh_snapshot =
        normalize_openapi(&refresh_response).expect("response-drifted service-token catalog");
    assert_eq!(
        refresh_snapshot
            .get("access-service-tokens-refresh-a-service-token")
            .expect("response-drifted refresh")
            .adapter_status,
        AdapterStatus::Blocked
    );

    let mut secret = access_service_token_fixture();
    secret["components"]["schemas"]["ServiceToken"]["properties"]["client_secret"]["type"] =
        json!("integer");
    assert!(blocked(secret));

    let mut detail = access_service_token_fixture();
    detail["components"]["schemas"]["ServiceToken"]["properties"]
        .as_object_mut()
        .expect("service-token fields")
        .remove("client_id");
    assert!(blocked(detail));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoadBalancingFixtureKind {
    MonitorOrPool,
    LoadBalancer,
}

struct LoadBalancingConfigurationFixture {
    collection_path: &'static str,
    detail_path: &'static str,
    create_id: &'static str,
    patch_id: &'static str,
    update_id: &'static str,
    read_id: &'static str,
    delete_id: &'static str,
    product: &'static str,
    permission: &'static str,
    kind: LoadBalancingFixtureKind,
}

fn load_balancing_configuration_fixture(
    case: &LoadBalancingConfigurationFixture,
) -> serde_json::Value {
    let mut document = create_lifecycle_fixture();
    let mut collection = document["paths"]
        .as_object_mut()
        .expect("paths")
        .remove("/accounts/{account_id}/widgets")
        .expect("widget collection");
    collection["post"]["operationId"] = json!(case.create_id);
    collection["post"]["tags"] = json!([case.product]);
    collection["post"]["x-api-token-group"] = json!([case.permission]);

    let mut detail = document["paths"]
        .as_object_mut()
        .expect("paths")
        .remove("/accounts/{account_id}/widgets/{widget_id}")
        .expect("widget detail");
    let identity_selector = case
        .detail_path
        .rsplit_once('{')
        .and_then(|(_, suffix)| suffix.strip_suffix('}'))
        .expect("identity selector");
    let scope_selector = if case.collection_path.starts_with("/accounts/") {
        Some("account_id")
    } else if case.collection_path.starts_with("/zones/") {
        Some("zone_id")
    } else {
        None
    };
    collection["parameters"] = scope_selector.map_or_else(
        || json!([]),
        |selector| {
            json!([{
                "in":"path","name":selector,"required":true,"schema":{"type":"string"}
            }])
        },
    );
    detail["parameters"] = json!([]);
    if let Some(selector) = scope_selector {
        detail["parameters"]
            .as_array_mut()
            .expect("detail parameters")
            .push(json!({
                "in":"path","name":selector,"required":true,"schema":{"type":"string"}
            }));
    }
    detail["parameters"]
        .as_array_mut()
        .expect("detail parameters")
        .push(json!({
            "in":"path","name":identity_selector,"required":true,"schema":{"type":"string"}
        }));
    detail["get"]["operationId"] = json!(case.read_id);
    detail["get"]["tags"] = json!([case.product]);
    detail["delete"]["operationId"] = json!(case.delete_id);
    detail["delete"]["tags"] = json!([case.product]);
    detail["delete"]["x-api-token-group"] = json!([case.permission]);
    let update = json!({
        "summary": "Update Load Balancing configuration",
        "tags": [case.product],
        "x-api-token-group": [case.permission],
        "requestBody": {
            "required": true,
            "content": {"application/json": {"schema": {
                "type": "object",
                "required": ["name"],
                "properties": {"name": {"type": "string"}}
            }}}
        },
        "responses": {
            "200": {
                "description": "Load Balancing configuration updated",
                "content": {
                    "application/json": {
                        "schema": {"$ref": "#/components/schemas/WidgetResponse"}
                    }
                }
            }
        }
    });
    detail["patch"] = update.clone();
    detail["patch"]["operationId"] = json!(case.patch_id);
    detail["put"] = update;
    detail["put"]["operationId"] = json!(case.update_id);
    document["paths"][case.collection_path] = collection;
    document["paths"][case.detail_path] = detail;
    document
}

fn load_balancing_configuration_fixtures() -> [LoadBalancingConfigurationFixture; 6] {
    [
        LoadBalancingConfigurationFixture {
            collection_path: "/accounts/{account_id}/load_balancers/monitors",
            detail_path: "/accounts/{account_id}/load_balancers/monitors/{monitor_id}",
            create_id: "account-load-balancer-monitors-create-monitor",
            patch_id: "account-load-balancer-monitors-patch-monitor",
            update_id: "account-load-balancer-monitors-update-monitor",
            read_id: "account-load-balancer-monitors-monitor-details",
            delete_id: "account-load-balancer-monitors-delete-monitor",
            product: "Account Load Balancer Monitors",
            permission: "Load Balancing: Monitors and Pools Write",
            kind: LoadBalancingFixtureKind::MonitorOrPool,
        },
        LoadBalancingConfigurationFixture {
            collection_path: "/accounts/{account_id}/load_balancers/pools",
            detail_path: "/accounts/{account_id}/load_balancers/pools/{pool_id}",
            create_id: "account-load-balancer-pools-create-pool",
            patch_id: "account-load-balancer-pools-patch-pool",
            update_id: "account-load-balancer-pools-update-pool",
            read_id: "account-load-balancer-pools-pool-details",
            delete_id: "account-load-balancer-pools-delete-pool",
            product: "Account Load Balancer Pools",
            permission: "Load Balancing: Monitors and Pools Write",
            kind: LoadBalancingFixtureKind::MonitorOrPool,
        },
        LoadBalancingConfigurationFixture {
            collection_path: "/user/load_balancers/monitors",
            detail_path: "/user/load_balancers/monitors/{monitor_id}",
            create_id: "load-balancer-monitors-create-monitor",
            patch_id: "load-balancer-monitors-patch-monitor",
            update_id: "load-balancer-monitors-update-monitor",
            read_id: "load-balancer-monitors-monitor-details",
            delete_id: "load-balancer-monitors-delete-monitor",
            product: "Load Balancer Monitors",
            permission: "Load Balancing: Monitors and Pools Write",
            kind: LoadBalancingFixtureKind::MonitorOrPool,
        },
        LoadBalancingConfigurationFixture {
            collection_path: "/user/load_balancers/pools",
            detail_path: "/user/load_balancers/pools/{pool_id}",
            create_id: "load-balancer-pools-create-pool",
            patch_id: "load-balancer-pools-patch-pool",
            update_id: "load-balancer-pools-update-pool",
            read_id: "load-balancer-pools-pool-details",
            delete_id: "load-balancer-pools-delete-pool",
            product: "Load Balancer Pools",
            permission: "Load Balancing: Monitors and Pools Write",
            kind: LoadBalancingFixtureKind::MonitorOrPool,
        },
        LoadBalancingConfigurationFixture {
            collection_path: "/accounts/{account_id}/load_balancers",
            detail_path: "/accounts/{account_id}/load_balancers/{load_balancer_id}",
            create_id: "account-load-balancers-create-account-load-balancer",
            patch_id: "account-load-balancers-patch-account-load-balancer",
            update_id: "account-load-balancers-update-account-load-balancer",
            read_id: "account-load-balancers-get-account-load-balancer",
            delete_id: "account-load-balancers-delete-account-load-balancer",
            product: "Account Load Balancers",
            permission: "Load Balancers Account Write",
            kind: LoadBalancingFixtureKind::LoadBalancer,
        },
        LoadBalancingConfigurationFixture {
            collection_path: "/zones/{zone_id}/load_balancers",
            detail_path: "/zones/{zone_id}/load_balancers/{load_balancer_id}",
            create_id: "load-balancers-create-load-balancer",
            patch_id: "load-balancers-patch-load-balancer",
            update_id: "load-balancers-update-load-balancer",
            read_id: "load-balancers-load-balancer-details",
            delete_id: "load-balancers-delete-load-balancer",
            product: "Load Balancers",
            permission: "Load Balancers Write",
            kind: LoadBalancingFixtureKind::LoadBalancer,
        },
    ]
}

#[test]
fn load_balancing_configuration_has_exact_cost_entitlement_and_risk_contracts() {
    for case in load_balancing_configuration_fixtures() {
        let document = load_balancing_configuration_fixture(&case);
        let snapshot = normalize_openapi(&document).expect("Load Balancing catalog");
        for id in [case.create_id, case.patch_id, case.update_id] {
            let capability = snapshot.get(id).expect("Load Balancing mutation");
            assert_eq!(capability.adapter_status, AdapterStatus::Blocked);
            assert_eq!(capability.cost.billing_model, BillingModelV1::UsageBased);
            assert_eq!(capability.cost.exposure, CostExposureV1::DownstreamUsage);
            assert!(capability.cost.references.iter().any(|reference| {
                reference.url
                    == "https://developers.cloudflare.com/load-balancing/get-started/enable-load-balancing/"
            }));
            assert!(capability.cost.references.iter().any(|reference| {
                reference.url
                    == "https://developers.cloudflare.com/load-balancing/get-started/quickstart/"
            }));
            assert_eq!(capability.entitlement.available, None);
            assert!(capability.entitlement.plans.is_empty());
            assert!(!capability.entitlement.requires_live_resolution);
            assert!(
                capability
                    .entitlement
                    .blocker
                    .as_deref()
                    .is_some_and(|blocker| {
                        blocker.contains("paid account add-on")
                            && blocker.contains("product-scoped subscription join key")
                            && blocker.contains("Load Balancing")
                    })
            );
            assert_eq!(
                capability.entitlement.source.as_deref(),
                Some(
                    "https://developers.cloudflare.com/load-balancing/get-started/enable-load-balancing/"
                )
            );

            match case.kind {
                LoadBalancingFixtureKind::MonitorOrPool => {
                    assert_eq!(capability.risk, RiskClass::CrossConfig);
                    assert_eq!(capability.effect, EffectClass::ReversibleWrite);
                    assert!(capability.cost.known);
                    assert!(!capability.cost.incremental);
                    assert_eq!(capability.cost.maximum, Some(0.0));
                    assert_eq!(capability.mutation_contract_gaps().len(), 1);
                    assert!(capability.mutation_contract_gaps()[0].contains("entitlement"));
                }
                LoadBalancingFixtureKind::LoadBalancer => {
                    assert_eq!(capability.risk, RiskClass::Spend);
                    assert_eq!(capability.effect, EffectClass::Spend);
                    assert!(!capability.cost.known);
                    assert!(capability.cost.incremental);
                    assert_eq!(capability.cost.maximum, None);
                    let gaps = capability.mutation_contract_gaps();
                    assert_eq!(gaps.len(), 2);
                    assert!(gaps.iter().any(|gap| gap.contains("cost is not bounded")));
                    assert!(gaps.iter().any(|gap| gap.contains("entitlement")));
                }
            }
        }
    }

    let case = load_balancing_configuration_fixtures()
        .into_iter()
        .find(|case| case.kind == LoadBalancingFixtureKind::LoadBalancer)
        .expect("load balancer fixture");
    let mut enriched = normalize_openapi(&load_balancing_configuration_fixture(&case))
        .expect("Load Balancing catalog");
    let expected_basis = enriched
        .get(case.create_id)
        .expect("load balancer create")
        .cost
        .basis
        .clone();
    attach_official_product_knowledge(&mut enriched, &pricing_feeds_fixture())
        .expect("official pricing enrichment");
    assert_eq!(
        enriched
            .get(case.create_id)
            .expect("enriched load balancer create")
            .cost
            .basis,
        expected_basis
    );
}

#[test]
fn load_balancing_configuration_classifier_rejects_retargeting_and_permission_drift() {
    let case = load_balancing_configuration_fixtures()
        .into_iter()
        .next()
        .expect("monitor fixture");
    let mut retargeted = load_balancing_configuration_fixture(&case);
    let collection = retargeted["paths"]
        .as_object_mut()
        .expect("paths")
        .remove(case.collection_path)
        .expect("monitor collection");
    retargeted["paths"]["/accounts/{account_id}/load_balancers/monitor_templates"] = collection;
    let retargeted_snapshot = normalize_openapi(&retargeted).expect("retargeted catalog");
    let retargeted_create = retargeted_snapshot
        .get(case.create_id)
        .expect("retargeted create");
    assert_eq!(retargeted_create.risk, RiskClass::Unknown);
    assert!(!retargeted_create.cost.known);
    assert!(retargeted_create.entitlement.blocker.is_none());

    let mut permission_drift = load_balancing_configuration_fixture(&case);
    permission_drift["paths"][case.collection_path]["post"]["x-api-token-group"] =
        json!(["Account Settings Write"]);
    let permission_snapshot = normalize_openapi(&permission_drift).expect("permission drift");
    let drifted_create = permission_snapshot
        .get(case.create_id)
        .expect("permission-drifted create");
    assert_eq!(drifted_create.risk, RiskClass::Unknown);
    assert!(!drifted_create.cost.known);
    assert!(drifted_create.entitlement.blocker.is_none());
}

struct EmailSecuritySettingsFixture {
    collection_path: &'static str,
    detail_path: &'static str,
    create_id: &'static str,
    update_id: &'static str,
    read_id: &'static str,
    delete_id: &'static str,
}

fn email_security_settings_fixture(case: &EmailSecuritySettingsFixture) -> serde_json::Value {
    let mut document = create_lifecycle_fixture();
    let mut collection = document["paths"]
        .as_object_mut()
        .expect("paths")
        .remove("/accounts/{account_id}/widgets")
        .expect("widget collection");
    collection["post"]["operationId"] = json!(case.create_id);
    collection["post"]["tags"] = json!(["Email Security Settings"]);
    collection["post"]["x-api-token-group"] = json!(["Cloud Email Security: Write"]);

    let mut detail = document["paths"]
        .as_object_mut()
        .expect("paths")
        .remove("/accounts/{account_id}/widgets/{widget_id}")
        .expect("widget detail");
    let identity_selector = case
        .detail_path
        .rsplit_once('{')
        .and_then(|(_, suffix)| suffix.strip_suffix('}'))
        .expect("identity selector");
    detail["parameters"] = json!([
        {"in":"path","name":"account_id","required":true,"schema":{"type":"string"}},
        {"in":"path","name":identity_selector,"required":true,"schema":{"type":"string"}}
    ]);
    detail["get"]["operationId"] = json!(case.read_id);
    detail["get"]["tags"] = json!(["Email Security Settings"]);
    detail["delete"]["operationId"] = json!(case.delete_id);
    detail["delete"]["tags"] = json!(["Email Security Settings"]);
    detail["delete"]["x-api-token-group"] = json!(["Cloud Email Security: Write"]);
    detail["patch"] = json!({
        "operationId": case.update_id,
        "summary": "Update Email Security setting",
        "tags": ["Email Security Settings"],
        "x-api-token-group": ["Cloud Email Security: Write"],
        "requestBody": {
            "required": true,
            "content": {"application/json": {"schema": {
                "type": "object",
                "minProperties": 1,
                "properties": {"name": {"type": "string"}}
            }}}
        },
        "responses": {
            "200": {
                "description": "Email Security setting updated",
                "content": {
                    "application/json": {
                        "schema": {"$ref": "#/components/schemas/WidgetResponse"}
                    }
                }
            }
        }
    });
    document["paths"][case.collection_path] = collection;
    document["paths"][case.detail_path] = detail;
    document
}

fn email_security_settings_fixtures() -> [EmailSecuritySettingsFixture; 7] {
    [
        EmailSecuritySettingsFixture {
            collection_path: "/accounts/{account_id}/email-security/settings/allow_policies",
            detail_path: "/accounts/{account_id}/email-security/settings/allow_policies/{policy_id}",
            create_id: "email_security_create_allow_policy",
            update_id: "email_security_update_allow_policy",
            read_id: "email_security_get_allow_policy",
            delete_id: "email_security_delete_allow_policy",
        },
        EmailSecuritySettingsFixture {
            collection_path: "/accounts/{account_id}/email-security/settings/block_senders",
            detail_path: "/accounts/{account_id}/email-security/settings/block_senders/{pattern_id}",
            create_id: "email_security_create_blocked_sender",
            update_id: "email_security_update_blocked_sender",
            read_id: "email_security_get_blocked_sender",
            delete_id: "email_security_delete_blocked_sender",
        },
        EmailSecuritySettingsFixture {
            collection_path: "/accounts/{account_id}/email-security/settings/domains",
            detail_path: "/accounts/{account_id}/email-security/settings/domains/{domain_id}",
            create_id: "email_security_create_domains",
            update_id: "email_security_update_domain",
            read_id: "email_security_get_domain",
            delete_id: "email_security_delete_domain",
        },
        EmailSecuritySettingsFixture {
            collection_path: "/accounts/{account_id}/email-security/settings/impersonation_registry",
            detail_path: "/accounts/{account_id}/email-security/settings/impersonation_registry/{impersonation_registry_id}",
            create_id: "email_security_create_impersonation_registry",
            update_id: "email_security_update_impersonation_registry",
            read_id: "email_security_get_impersonation_registry",
            delete_id: "email_security_delete_impersonation_registry",
        },
        EmailSecuritySettingsFixture {
            collection_path: "/accounts/{account_id}/email-security/settings/sending_domain_restrictions",
            detail_path: "/accounts/{account_id}/email-security/settings/sending_domain_restrictions/{sending_domain_restriction_id}",
            create_id: "email_security_create_sending_domain_restriction",
            update_id: "email_security_update_sending_domain_restriction",
            read_id: "email_security_get_sending_domain_restriction",
            delete_id: "email_security_delete_sending_domain_restriction",
        },
        EmailSecuritySettingsFixture {
            collection_path: "/accounts/{account_id}/email-security/settings/trusted_domains",
            detail_path: "/accounts/{account_id}/email-security/settings/trusted_domains/{trusted_domain_id}",
            create_id: "email_security_create_trusted_domain",
            update_id: "email_security_update_trusted_domain",
            read_id: "email_security_get_trusted_domain",
            delete_id: "email_security_delete_trusted_domain",
        },
        EmailSecuritySettingsFixture {
            collection_path: "/accounts/{account_id}/email-security/settings/url_ignore_patterns",
            detail_path: "/accounts/{account_id}/email-security/settings/url_ignore_patterns/{pattern_id}",
            create_id: "email_security_create_url_ignore_pattern",
            update_id: "email_security_update_url_ignore_pattern",
            read_id: "email_security_get_url_ignore_pattern",
            delete_id: "email_security_delete_url_ignore_pattern",
        },
    ]
}

#[test]
fn email_security_settings_have_exact_cost_entitlement_and_risk_contracts() {
    for case in email_security_settings_fixtures() {
        let snapshot = normalize_openapi(&email_security_settings_fixture(&case))
            .expect("Email Security settings catalog");
        for id in [case.create_id, case.update_id] {
            let capability = snapshot.get(id).expect("Email Security setting mutation");
            assert_eq!(capability.adapter_status, AdapterStatus::Blocked);
            assert_eq!(capability.risk, RiskClass::CrossConfig);
            assert_eq!(capability.effect, EffectClass::ReversibleWrite);
            assert!(capability.cost.known);
            assert!(!capability.cost.incremental);
            assert_eq!(capability.cost.maximum, Some(0.0));
            assert_eq!(capability.cost.billing_model, BillingModelV1::Contract);
            assert_eq!(capability.cost.exposure, CostExposureV1::AccountQuote);
            assert!(capability.cost.references.iter().any(|reference| {
                reference.url == "https://www.cloudflare.com/plans/zero-trust-services/"
            }));
            assert!(capability.cost.references.iter().any(|reference| {
                reference.url
                    == "https://developers.cloudflare.com/cloudflare-one/email-security/settings/detection-settings/"
            }));
            assert_eq!(capability.entitlement.available, None);
            assert!(capability.entitlement.plans.is_empty());
            assert!(!capability.entitlement.requires_live_resolution);
            assert!(
                capability
                    .entitlement
                    .blocker
                    .as_deref()
                    .is_some_and(|blocker| {
                        blocker.contains("paid Email Security add-on")
                            && blocker.contains("product-scoped subscription join key")
                    })
            );
            assert_eq!(
                capability.entitlement.source.as_deref(),
                Some("https://www.cloudflare.com/plans/zero-trust-services/")
            );
            let gaps = capability.mutation_contract_gaps();
            assert_eq!(gaps.len(), 1, "{id}: {gaps:?}");
            assert!(gaps[0].contains("entitlement"));
        }

        let create = snapshot
            .get(case.create_id)
            .expect("Email Security setting create");
        assert!(create.created_resource.is_some());
        assert!(create.rollback.supported);
        let update = snapshot
            .get(case.update_id)
            .expect("Email Security setting update");
        assert!(update.same_path_read.is_some());
        assert!(!update.rollback.supported);
    }
}

#[test]
fn email_security_settings_classifier_rejects_retargeting_and_permission_drift() {
    let case = email_security_settings_fixtures()
        .into_iter()
        .next()
        .expect("Email Security fixture");
    let mut retargeted = email_security_settings_fixture(&case);
    let collection = retargeted["paths"]
        .as_object_mut()
        .expect("paths")
        .remove(case.collection_path)
        .expect("Email Security collection");
    retargeted["paths"]["/accounts/{account_id}/email-security/settings/allow_policy_templates"] =
        collection;
    let retargeted_snapshot = normalize_openapi(&retargeted).expect("retargeted catalog");
    let retargeted_create = retargeted_snapshot
        .get(case.create_id)
        .expect("retargeted create");
    assert_eq!(retargeted_create.risk, RiskClass::Unknown);
    assert!(!retargeted_create.cost.known);
    assert!(retargeted_create.entitlement.blocker.is_none());

    let mut permission_drift = email_security_settings_fixture(&case);
    permission_drift["paths"][case.collection_path]["post"]["x-api-token-group"] =
        json!(["Account Settings Write"]);
    let permission_snapshot = normalize_openapi(&permission_drift).expect("permission drift");
    let drifted_create = permission_snapshot
        .get(case.create_id)
        .expect("permission-drifted create");
    assert_eq!(drifted_create.risk, RiskClass::Unknown);
    assert!(!drifted_create.cost.known);
    assert!(drifted_create.entitlement.blocker.is_none());
}

fn turnstile_widget_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "properties": {
            "bot_fight_mode": {"type":"boolean"},
            "clearance_level": {
                "type":"string",
                "enum":["no_clearance","jschallenge","managed","interactive"]
            },
            "domains": {"type":"array","items":{"type":"string"},"maxLength":10},
            "ephemeral_id": {"type":"boolean"},
            "mode": {"type":"string","enum":["non-interactive","invisible","managed"]},
            "name": {"type":"string","minLength":1,"maxLength":254},
            "offlabel": {"type":"boolean"},
            "region": {"type":"string","enum":["world","china"]},
            "secret": {"type":"string"},
            "sitekey": {"type":"string","maxLength":32}
        }
    })
}

fn turnstile_widget_request_schema() -> serde_json::Value {
    let mut schema = turnstile_widget_schema();
    let properties = schema["properties"]
        .as_object_mut()
        .expect("widget properties");
    properties.remove("secret");
    properties.remove("sitekey");
    schema["required"] = json!(["name", "mode", "domains"]);
    schema
}

fn turnstile_widget_collection_fixture() -> serde_json::Value {
    json!({
        "parameters": [
            {"in":"path","name":"account_id","required":true,"schema":{"type":"string","maxLength":32}},
            {"in":"query","name":"page","required":false,"schema":{"type":"number","minimum":1}},
            {"in":"query","name":"per_page","required":false,"schema":{"type":"number","minimum":5,"maximum":1000}},
            {"in":"query","name":"order","required":false,"schema":{"type":"string","enum":["id","sitekey","name","created_on","modified_on"]}},
            {"in":"query","name":"direction","required":false,"schema":{"type":"string","enum":["asc","desc"]}},
            {"in":"query","name":"filter","required":false,"schema":{"type":"string"}}
        ],
        "post": {
            "operationId":"accounts-turnstile-widget-create",
            "summary":"Create a Turnstile Widget",
            "tags":["Turnstile"],
            "x-api-token-group":["Turnstile Sites Write","Account Settings Write"],
            "requestBody": {
                "required": true,
                "content":{"application/json":{"schema":turnstile_widget_request_schema()}}
            },
            "responses": {
                "200": {
                    "description":"Widget created",
                    "content":{"application/json":{"schema":{"$ref":"#/components/schemas/WidgetResponse"}}}
                }
            }
        }
    })
}

fn turnstile_widget_detail_fixture() -> serde_json::Value {
    json!({
        "parameters": [
            {"in":"path","name":"account_id","required":true,"schema":{"type":"string","maxLength":32}},
            {"in":"path","name":"sitekey","required":true,"schema":{"type":"string","maxLength":32}}
        ],
        "get": {
            "operationId":"accounts-turnstile-widget-get",
            "summary":"Turnstile Widget Details",
            "tags":["Turnstile"],
            "responses": {
                "200": {
                    "description":"Widget",
                    "content":{"application/json":{"schema":{"$ref":"#/components/schemas/WidgetResponse"}}}
                }
            }
        },
        "delete": {
            "operationId":"accounts-turnstile-widget-delete",
            "summary":"Delete a Turnstile Widget",
            "tags":["Turnstile"],
            "x-api-token-group":["Turnstile Sites Write","Account Settings Write"],
            "responses": {
                "200": {
                    "description":"Widget deleted",
                    "content":{"application/json":{"schema":{"$ref":"#/components/schemas/WidgetResponse"}}}
                }
            }
        },
        "put": {
            "operationId":"accounts-turnstile-widget-update",
            "summary":"Update a Turnstile Widget",
            "description":"Update the configuration of a widget.",
            "tags":["Turnstile"],
            "x-api-token-group":["Turnstile Sites Write","Account Settings Write"],
            "requestBody": {
                "required": true,
                "content":{"application/json":{"schema":turnstile_widget_request_schema()}}
            },
            "responses": {
                "200": {
                    "description":"Widget updated",
                    "content":{"application/json":{"schema":{"$ref":"#/components/schemas/WidgetResponse"}}}
                }
            }
        }
    })
}

fn turnstile_widget_rotate_fixture() -> serde_json::Value {
    json!({
        "parameters": [
            {"in":"path","name":"account_id","required":true,"schema":{"type":"string","maxLength":32}},
            {"in":"path","name":"sitekey","required":true,"schema":{"type":"string","maxLength":32}}
        ],
        "post": {
            "operationId":"accounts-turnstile-widget-rotate-secret",
            "summary":"Rotate Secret for a Turnstile Widget",
            "description":"Generate a new secret key for this widget. If `invalidate_immediately` is set to `false`, the previous secret remains valid for 2 hours. Secrets cannot be rotated again during the grace period.",
            "tags":["Turnstile"],
            "x-api-token-group":["Turnstile Sites Write","Account Settings Write"],
            "requestBody": {
                "required": true,
                "content":{"application/json":{"schema":{
                    "type":"object",
                    "properties":{"invalidate_immediately":{"type":"boolean"}}
                }}}
            },
            "responses": {
                "200": {
                    "description":"Secret rotated",
                    "content":{"application/json":{"schema":{"$ref":"#/components/schemas/WidgetResponse"}}}
                }
            }
        }
    })
}

fn turnstile_widget_update_fixture() -> serde_json::Value {
    json!({
        "openapi": "3.0.3",
        "info": {"title":"Cloudflare API","version":"4.0.0"},
        "components": {"schemas": {
            "Widget": turnstile_widget_schema(),
            "WidgetResponse": {
                "type": "object",
                "properties": {
                    "success": {"type":"boolean"},
                    "result": {"$ref":"#/components/schemas/Widget"}
                }
            }
        }},
        "paths": {
            "/accounts/{account_id}/challenges/widgets": turnstile_widget_collection_fixture(),
            "/accounts/{account_id}/challenges/widgets/{sitekey}": turnstile_widget_detail_fixture(),
            "/accounts/{account_id}/challenges/widgets/{sitekey}/rotate_secret": turnstile_widget_rotate_fixture()
        }
    })
}

#[test]
fn turnstile_widget_update_has_exact_cost_entitlement_and_risk_contracts() {
    let snapshot =
        normalize_openapi(&turnstile_widget_update_fixture()).expect("Turnstile catalog");
    let update = snapshot
        .get("accounts-turnstile-widget-update")
        .expect("Turnstile update");

    assert_eq!(update.adapter_status, AdapterStatus::DynamicApi);
    assert_eq!(update.risk, RiskClass::CrossConfig);
    assert_eq!(update.effect, EffectClass::ReversibleWrite);
    assert!(update.cost.known);
    assert!(!update.cost.incremental);
    assert_eq!(update.cost.maximum, Some(0.0));
    assert_eq!(update.cost.billing_model, BillingModelV1::Subscription);
    assert_eq!(update.cost.exposure, CostExposureV1::AccountQuote);
    assert!(update.cost.references.iter().any(|reference| {
        reference.url == "https://developers.cloudflare.com/turnstile/plans/"
    }));
    assert!(update.cost.references.iter().any(|reference| {
        reference.url
            == "https://developers.cloudflare.com/turnstile/get-started/widget-management/api/"
    }));
    assert_eq!(update.entitlement.available, Some(true));
    assert_eq!(update.entitlement.plans.get("free"), Some(&true));
    assert_eq!(update.entitlement.plans.get("enterprise"), Some(&true));
    assert_eq!(
        update.entitlement.source.as_deref(),
        Some("https://developers.cloudflare.com/turnstile/plans/")
    );
    assert!(update.same_path_read.is_some());
    assert!(!update.rollback.supported);
    assert!(update.mutation_contract_gaps().is_empty());
}

#[test]
fn turnstile_widget_create_sinks_secret_and_binds_sitekey_lifecycle() {
    let snapshot =
        normalize_openapi(&turnstile_widget_update_fixture()).expect("Turnstile catalog");
    let create = snapshot
        .get("accounts-turnstile-widget-create")
        .expect("Turnstile create");

    assert_eq!(
        create.adapter_status,
        AdapterStatus::DynamicApi,
        "{:?}",
        create.mutation_contract_gaps()
    );
    assert_eq!(create.risk, RiskClass::SecretSensitive);
    assert_eq!(create.effect, EffectClass::IdentityOrOwnership);
    assert!(create.cost.known);
    assert!(!create.cost.incremental);
    assert_eq!(create.cost.maximum, Some(0.0));
    assert_eq!(create.cost.billing_model, BillingModelV1::Subscription);
    assert_eq!(create.cost.exposure, CostExposureV1::AccountQuote);
    assert_eq!(create.entitlement.available, Some(true));
    assert_eq!(create.entitlement.plans.get("free"), Some(&true));
    assert_eq!(create.entitlement.plans.get("enterprise"), Some(&true));
    assert_eq!(
        create.verification.strategy,
        "created_resource_contains_planned_fields_by_returned_id"
    );
    let target = create
        .created_resource
        .as_ref()
        .expect("created widget target");
    assert_eq!(target.identity_selector, "sitekey");
    assert_eq!(target.response_result_identity_pointer, "/sitekey");
    assert_eq!(target.read_capability_id, "accounts-turnstile-widget-get");
    assert_eq!(
        target.delete_capability_id,
        "accounts-turnstile-widget-delete"
    );
    assert_eq!(
        create.rollback.strategy.as_deref(),
        Some("delete_created_resource_by_returned_id")
    );
    assert!(
        create
            .selectors
            .iter()
            .all(|selector| selector.location == "path")
    );
    assert!(create.mutation_contract_gaps().is_empty());
}

#[test]
fn turnstile_widget_rotation_requires_an_explicit_secret_cutover() {
    let snapshot =
        normalize_openapi(&turnstile_widget_update_fixture()).expect("Turnstile catalog");
    let rotate = snapshot
        .get("accounts-turnstile-widget-rotate-secret")
        .expect("Turnstile rotation");

    assert_eq!(rotate.adapter_status, AdapterStatus::DynamicApi);
    assert_eq!(rotate.risk, RiskClass::SecretSensitive);
    assert_eq!(rotate.effect, EffectClass::IdentityOrOwnership);
    assert!(rotate.cost.known);
    assert!(!rotate.cost.incremental);
    assert_eq!(rotate.cost.maximum, Some(0.0));
    assert_eq!(rotate.cost.billing_model, BillingModelV1::Subscription);
    assert_eq!(rotate.cost.exposure, CostExposureV1::AccountQuote);
    assert_eq!(rotate.entitlement.available, Some(true));
    assert!(!rotate.verification.required);
    assert_eq!(
        rotate.verification.strategy,
        "sink_write_and_source_response_status"
    );
    assert!(!rotate.rollback.supported);
    assert!(rotate.rollback.warning.as_deref().is_some_and(|warning| {
        warning.contains("irreversible")
            && warning.contains("2 hours")
            && warning.contains("invalidate_immediately")
    }));
    assert_eq!(
        rotate
            .request_schema
            .as_ref()
            .and_then(|schema| schema.get("required")),
        Some(&json!(["invalidate_immediately"]))
    );
    assert!(rotate.mutation_contract_gaps().is_empty());
}

#[test]
fn turnstile_widget_rotation_classifier_rejects_route_permission_and_schema_drift() {
    let mut retargeted = turnstile_widget_update_fixture();
    let operation = retargeted["paths"]
        .as_object_mut()
        .expect("paths")
        .remove("/accounts/{account_id}/challenges/widgets/{sitekey}/rotate_secret")
        .expect("rotation");
    retargeted["paths"]["/accounts/{account_id}/challenges/widgets/{sitekey}/rotate_credentials"] =
        operation;
    let retargeted_snapshot = normalize_openapi(&retargeted).expect("retargeted rotation");
    let retargeted_rotate = retargeted_snapshot
        .get("accounts-turnstile-widget-rotate-secret")
        .expect("retargeted rotate");
    assert_eq!(retargeted_rotate.risk, RiskClass::Unknown);
    assert!(!retargeted_rotate.cost.known);

    let mut permission_drift = turnstile_widget_update_fixture();
    permission_drift["paths"]["/accounts/{account_id}/challenges/widgets/{sitekey}/rotate_secret"]
        ["post"]["x-api-token-group"] = json!(["Account Settings Write"]);
    let permission_snapshot = normalize_openapi(&permission_drift).expect("permission drift");
    let drifted_permission = permission_snapshot
        .get("accounts-turnstile-widget-rotate-secret")
        .expect("permission-drifted rotate");
    assert_eq!(drifted_permission.risk, RiskClass::Unknown);
    assert!(!drifted_permission.cost.known);

    let mut schema_drift = turnstile_widget_update_fixture();
    schema_drift["paths"]["/accounts/{account_id}/challenges/widgets/{sitekey}/rotate_secret"]["post"]
        ["requestBody"]["content"]["application/json"]["schema"]["properties"]["grace_period_seconds"] =
        json!({"type":"integer"});
    let schema_snapshot = normalize_openapi(&schema_drift).expect("schema drift");
    let drifted_schema = schema_snapshot
        .get("accounts-turnstile-widget-rotate-secret")
        .expect("schema-drifted rotate");
    assert_eq!(drifted_schema.risk, RiskClass::Unknown);
    assert!(!drifted_schema.cost.known);
}

#[test]
fn turnstile_widget_create_classifier_rejects_query_permission_and_identity_drift() {
    let mut query_drift = turnstile_widget_update_fixture();
    query_drift["paths"]["/accounts/{account_id}/challenges/widgets"]["parameters"]
        .as_array_mut()
        .expect("collection parameters")
        .push(json!({
            "in":"query",
            "name":"provision_enterprise_capacity",
            "required":false,
            "schema":{"type":"boolean"}
        }));
    let query_snapshot = normalize_openapi(&query_drift).expect("query drift");
    let drifted_query = query_snapshot
        .get("accounts-turnstile-widget-create")
        .expect("query-drifted create");
    assert_eq!(drifted_query.risk, RiskClass::Unknown);
    assert!(!drifted_query.cost.known);

    let mut permission_drift = turnstile_widget_update_fixture();
    permission_drift["paths"]["/accounts/{account_id}/challenges/widgets"]["post"]["x-api-token-group"] =
        json!(["Account Settings Write"]);
    let permission_snapshot = normalize_openapi(&permission_drift).expect("permission drift");
    let drifted_permission = permission_snapshot
        .get("accounts-turnstile-widget-create")
        .expect("permission-drifted create");
    assert_eq!(drifted_permission.risk, RiskClass::Unknown);
    assert!(!drifted_permission.cost.known);

    let mut identity_drift = turnstile_widget_update_fixture();
    identity_drift["components"]["schemas"]["Widget"]["properties"]["sitekey"]["type"] =
        json!("integer");
    let identity_snapshot = normalize_openapi(&identity_drift).expect("identity drift");
    let drifted_identity = identity_snapshot
        .get("accounts-turnstile-widget-create")
        .expect("identity-drifted create");
    assert_eq!(drifted_identity.adapter_status, AdapterStatus::Blocked);
    assert_eq!(drifted_identity.risk, RiskClass::SecretSensitive);
    assert!(drifted_identity.created_resource.is_none());
    assert!(
        drifted_identity
            .mutation_contract_gaps()
            .iter()
            .any(|gap| gap.contains("verification"))
    );
}

#[test]
fn turnstile_widget_update_classifier_rejects_route_permission_and_schema_drift() {
    let mut retargeted = turnstile_widget_update_fixture();
    let operations = retargeted["paths"]
        .as_object_mut()
        .expect("paths")
        .remove("/accounts/{account_id}/challenges/widgets/{sitekey}")
        .expect("Turnstile detail");
    retargeted["paths"]["/accounts/{account_id}/challenges/widget_templates/{sitekey}"] =
        operations;
    let retargeted_snapshot = normalize_openapi(&retargeted).expect("retargeted catalog");
    let retargeted_update = retargeted_snapshot
        .get("accounts-turnstile-widget-update")
        .expect("retargeted update");
    assert_eq!(retargeted_update.risk, RiskClass::Unknown);
    assert!(!retargeted_update.cost.known);

    let mut permission_drift = turnstile_widget_update_fixture();
    permission_drift["paths"]["/accounts/{account_id}/challenges/widgets/{sitekey}"]["put"]["x-api-token-group"] =
        json!(["Account Settings Write"]);
    let permission_snapshot = normalize_openapi(&permission_drift).expect("permission drift");
    let drifted_permission = permission_snapshot
        .get("accounts-turnstile-widget-update")
        .expect("permission-drifted update");
    assert_eq!(drifted_permission.risk, RiskClass::Unknown);
    assert!(!drifted_permission.cost.known);

    let mut schema_drift = turnstile_widget_update_fixture();
    schema_drift["paths"]["/accounts/{account_id}/challenges/widgets/{sitekey}"]["put"]["requestBody"]
        ["content"]["application/json"]["schema"]["properties"]["billing_tier"] =
        json!({"type":"string"});
    let schema_snapshot = normalize_openapi(&schema_drift).expect("schema drift");
    let drifted_schema = schema_snapshot
        .get("accounts-turnstile-widget-update")
        .expect("schema-drifted update");
    assert_eq!(drifted_schema.risk, RiskClass::Unknown);
    assert!(!drifted_schema.cost.known);
}

fn oauth_client_rotation_fixture() -> serde_json::Value {
    json!({
        "openapi": "3.0.3",
        "info": {"title":"OAuth client rotation fixture","version":"1"},
        "components": {
            "schemas": {
                "Identifier": {"type":"string","minLength":32,"maxLength":32},
                "ApiEnvelope": {
                    "type":"object",
                    "required":["success","result"],
                    "properties": {
                        "success":{"type":"boolean"},
                        "errors":{"type":"array"},
                        "messages":{"type":"array"},
                        "result":{"type":"object"}
                    }
                }
            }
        },
        "paths": {
            "/accounts/{account_id}/oauth_clients/{oauth_client_id}": {
                "get": {
                    "operationId":"oauth-clients-get",
                    "summary":"OAuth Client Details",
                    "description":"Get details of a specific OAuth client.",
                    "tags":["OAuth Clients"],
                    "x-api-token-group":["OAuth Client Read"],
                    "x-cfPlanAvailability":{"business":true,"enterprise":true,"free":true,"pro":true},
                    "parameters": [
                        {"in":"path","name":"account_id","required":true,"schema":{"allOf":[{"$ref":"#/components/schemas/Identifier"}]}},
                        {"in":"path","name":"oauth_client_id","required":true,"schema":{"type":"string"}}
                    ],
                    "responses": {
                        "200": {
                            "description":"OAuth Client Details response",
                            "content":{"application/json":{"schema":{
                                "allOf":[
                                    {"$ref":"#/components/schemas/ApiEnvelope"},
                                    {"type":"object","properties":{"result":{"type":"object","required":["client_id","visibility"],"properties":{
                                        "client_id":{"type":"string"},
                                        "visibility":{"type":"string","enum":["public","private"]},
                                        "has_rotated_secret":{"type":"boolean","readOnly":true}
                                    }}}}
                                ]
                            }}}
                        }
                    }
                }
            },
            "/accounts/{account_id}/oauth_clients/{oauth_client_id}/rotate_secret": {
                "post": {
                    "operationId":"oauth-clients-rotate-secret",
                    "summary":"Rotate OAuth Client Secret",
                    "description":"Creates a second client secret so you can update your client configuration before deleting the old one. The `has_rotated_secret` field on the client will be set to `true`.",
                    "tags":["OAuth Clients"],
                    "x-api-token-group":["OAuth Client Write"],
                    "x-cfPlanAvailability":{"business":true,"enterprise":true,"free":true,"pro":true},
                    "parameters": [
                        {"in":"path","name":"account_id","required":true,"schema":{"allOf":[{"$ref":"#/components/schemas/Identifier"}]}},
                        {"in":"path","name":"oauth_client_id","required":true,"schema":{"type":"string"}}
                    ],
                    "responses": {
                        "200": {
                            "description":"Rotate OAuth Client Secret response",
                            "content":{"application/json":{"schema":{
                                "allOf":[
                                    {"$ref":"#/components/schemas/ApiEnvelope"},
                                    {"type":"object","properties":{"result":{"type":"object","properties":{"client_secret":{"type":"string","readOnly":true,"x-sensitive":true}}}}}
                                ]
                            }}}
                        }
                    }
                },
                "delete": {
                    "operationId":"oauth-clients-delete-rotated-secret",
                    "summary":"Delete Rotated OAuth Client Secret",
                    "description":"Removes the old client secret after a rotation, keeping only the new one. Use this after you have updated your client configuration to use the new secret. The `has_rotated_secret` field on the client indicates whether there is an old secret to delete.",
                    "tags":["OAuth Clients"],
                    "x-api-token-group":["OAuth Client Write"],
                    "x-cfPlanAvailability":{"business":true,"enterprise":true,"free":true,"pro":true},
                    "parameters": [
                        {"in":"path","name":"account_id","required":true,"schema":{"allOf":[{"$ref":"#/components/schemas/Identifier"}]}},
                        {"in":"path","name":"oauth_client_id","required":true,"schema":{"type":"string"}}
                    ],
                    "responses": {
                        "200": {
                            "description":"Delete Rotated OAuth Client Secret response",
                            "content":{"application/json":{"schema":{
                                "allOf":[
                                    {"$ref":"#/components/schemas/ApiEnvelope"},
                                    {"type":"object","properties":{"result":{"type":"object","required":["id"],"properties":{"id":{"$ref":"#/components/schemas/Identifier"}}}}}
                                ]
                            }}}
                        }
                    }
                }
            }
        }
    })
}

#[test]
fn oauth_client_rotation_is_a_sink_bound_two_secret_cutover() {
    let snapshot = normalize_openapi(&oauth_client_rotation_fixture()).expect("OAuth catalog");
    let rotate = snapshot
        .get("oauth-clients-rotate-secret")
        .expect("OAuth rotation");
    let delete_old = snapshot
        .get("oauth-clients-delete-rotated-secret")
        .expect("OAuth old-secret delete");

    assert_eq!(rotate.adapter_status, AdapterStatus::DynamicApi);
    assert_eq!(rotate.risk, RiskClass::SecretSensitive);
    assert_eq!(rotate.effect, EffectClass::IdentityOrOwnership);
    assert!(rotate.cost.known);
    assert!(!rotate.cost.incremental);
    assert_eq!(rotate.cost.maximum, Some(0.0));
    assert_eq!(rotate.entitlement.available, Some(true));
    assert_eq!(
        rotate.verification.strategy,
        "oauth_client_reports_rotated_secret_after_value_roll"
    );
    assert_eq!(
        rotate
            .same_path_read
            .as_ref()
            .expect("rotation readback")
            .verified_response_fields,
        ["client_id", "has_rotated_secret"]
    );
    assert!(!rotate.rollback.supported);
    assert!(
        rotate
            .rollback
            .warning
            .as_deref()
            .is_some_and(|warning| warning.contains("do not delete the old secret"))
    );
    assert!(rotate.mutation_contract_gaps().is_empty());

    assert_eq!(delete_old.adapter_status, AdapterStatus::DynamicApi);
    assert_eq!(delete_old.risk, RiskClass::Destructive);
    assert_eq!(delete_old.effect, EffectClass::Irreversible);
    assert!(delete_old.cost.known);
    assert_eq!(delete_old.cost.maximum, Some(0.0));
    assert_eq!(delete_old.entitlement.available, Some(true));
    assert_eq!(
        delete_old.verification.strategy,
        "oauth_client_reports_no_rotated_secret_after_old_secret_delete"
    );
    assert_eq!(
        delete_old
            .same_path_read
            .as_ref()
            .expect("delete readback")
            .verified_response_fields,
        ["client_id", "has_rotated_secret"]
    );
    assert!(!delete_old.rollback.supported);
    assert!(
        delete_old
            .rollback
            .warning
            .as_deref()
            .is_some_and(|warning| warning.contains("cannot be restored"))
    );
    assert!(delete_old.mutation_contract_gaps().is_empty());
}

#[test]
fn oauth_client_rotation_classifier_rejects_permission_response_state_and_plan_drift() {
    let blocked = |document: serde_json::Value, capability_id: &str| {
        normalize_openapi(&document)
            .expect("drifted OAuth catalog")
            .get(capability_id)
            .expect("OAuth capability")
            .adapter_status
            == AdapterStatus::Blocked
    };

    let mut permission = oauth_client_rotation_fixture();
    permission["paths"]["/accounts/{account_id}/oauth_clients/{oauth_client_id}/rotate_secret"]["post"]
        ["x-api-token-group"] = json!(["Account Settings Write"]);
    assert!(blocked(permission, "oauth-clients-rotate-secret"));

    let mut response = oauth_client_rotation_fixture();
    response["paths"]["/accounts/{account_id}/oauth_clients/{oauth_client_id}/rotate_secret"]["post"]
        ["responses"]["200"]["content"]["application/json"]["schema"]["allOf"][1]["properties"]["result"]
        ["properties"] = json!({"replacement":{"type":"string"}});
    assert!(blocked(response, "oauth-clients-rotate-secret"));

    let mut state = oauth_client_rotation_fixture();
    state["paths"]["/accounts/{account_id}/oauth_clients/{oauth_client_id}"]["get"]
        ["responses"]["200"]["content"]["application/json"]["schema"]["allOf"][1]
        ["properties"]["result"]["properties"]
        .as_object_mut()
        .expect("detail properties")
        .remove("has_rotated_secret");
    assert!(blocked(state.clone(), "oauth-clients-rotate-secret"));
    assert!(blocked(state, "oauth-clients-delete-rotated-secret"));

    let mut plan = oauth_client_rotation_fixture();
    plan["paths"]["/accounts/{account_id}/oauth_clients/{oauth_client_id}/rotate_secret"]["delete"]
        ["x-cfPlanAvailability"]["free"] = json!(false);
    assert!(blocked(plan, "oauth-clients-delete-rotated-secret"));
}

fn queue_configuration_fixture() -> serde_json::Value {
    let mut document = create_lifecycle_fixture();
    document["components"]["schemas"]["Widget"]["properties"] = json!({
        "queue_id": {"type": "string"},
        "queue_name": {"type": "string"},
        "settings": {
            "type": "object",
            "properties": {
                "delivery_delay": {"type": "number"},
                "delivery_paused": {"type": "boolean"},
                "message_retention_period": {"type": "number"}
            }
        }
    });

    let mut collection = document["paths"]
        .as_object_mut()
        .expect("paths")
        .remove("/accounts/{account_id}/widgets")
        .expect("widget collection");
    collection["post"]["operationId"] = json!("queues-create");
    collection["post"]["summary"] = json!("Create Queue");
    collection["post"]["tags"] = json!(["Queue"]);
    collection["post"]["x-api-token-group"] = json!(["Queues Write", "Workers Scripts Write"]);
    collection["post"]["requestBody"]["content"]["application/json"]["schema"] = json!({
        "type": "object",
        "required": ["queue_name"],
        "properties": {"queue_name": {"type": "string"}}
    });

    let mut detail = document["paths"]
        .as_object_mut()
        .expect("paths")
        .remove("/accounts/{account_id}/widgets/{widget_id}")
        .expect("widget detail");
    detail["parameters"] = json!([
        {"in":"path","name":"account_id","required":true,"schema":{"type":"string"}},
        {"in":"path","name":"queue_id","required":true,"schema":{"type":"string"}}
    ]);
    detail["get"]["operationId"] = json!("queues-get");
    detail["get"]["tags"] = json!(["Queue"]);
    detail["delete"]["operationId"] = json!("queues-delete");
    detail["delete"]["tags"] = json!(["Queue"]);
    detail["delete"]["x-api-token-group"] = json!(["Queues Write", "Workers Scripts Write"]);
    let update = json!({
        "summary": "Update Queue",
        "tags": ["Queue"],
        "x-api-token-group": ["Queues Write", "Workers Scripts Write"],
        "requestBody": {
            "content": {"application/json": {"schema": {
                "type": "object",
                "properties": {
                    "queue_name": {"type": "string"},
                    "settings": {
                        "type": "object",
                        "properties": {
                            "delivery_delay": {"type": "number"},
                            "delivery_paused": {"type": "boolean"},
                            "message_retention_period": {"type": "number"}
                        }
                    }
                }
            }}}
        },
        "responses": {
            "200": {
                "description": "Queue updated",
                "content": {
                    "application/json": {
                        "schema": {"$ref": "#/components/schemas/WidgetResponse"}
                    }
                }
            }
        }
    });
    detail["put"] = update.clone();
    detail["put"]["operationId"] = json!("queues-update");
    detail["patch"] = update;
    detail["patch"]["operationId"] = json!("queues-update-partial");
    document["paths"]["/accounts/{account_id}/queues"] = collection;
    document["paths"]["/accounts/{account_id}/queues/{queue_id}"] = detail;
    document
}

#[test]
fn queue_configuration_has_exact_cost_entitlement_risk_and_data_loss_contracts() {
    let snapshot = normalize_openapi(&queue_configuration_fixture()).expect("Queue catalog");
    let create = snapshot.get("queues-create").expect("queue create");
    assert_eq!(create.adapter_status, AdapterStatus::DynamicApi);
    assert_eq!(create.risk, RiskClass::CrossConfig);
    assert_eq!(create.effect, EffectClass::ReversibleWrite);
    assert!(create.rollback.supported);
    assert_eq!(
        create.rollback.strategy.as_deref(),
        Some("delete_created_resource_by_returned_id")
    );

    for capability in [
        create,
        snapshot.get("queues-update").expect("queue update"),
        snapshot
            .get("queues-update-partial")
            .expect("queue partial update"),
    ] {
        assert_eq!(capability.adapter_status, AdapterStatus::DynamicApi);
        assert!(capability.cost.known);
        assert!(!capability.cost.incremental);
        assert_eq!(capability.cost.maximum, Some(0.0));
        assert_eq!(capability.cost.billing_model, BillingModelV1::UsageBased);
        assert_eq!(capability.cost.exposure, CostExposureV1::DownstreamUsage);
        assert!(capability.cost.references.iter().any(|reference| {
            reference.url == "https://developers.cloudflare.com/queues/platform/pricing/"
        }));
        assert!(capability.cost.references.iter().any(|reference| {
            reference.url == "https://developers.cloudflare.com/queues/platform/limits/"
        }));
        assert_eq!(capability.entitlement.available, Some(true));
        assert_eq!(
            capability.entitlement.plans.get("workers_free"),
            Some(&true)
        );
        assert_eq!(
            capability.entitlement.plans.get("workers_paid"),
            Some(&true)
        );
        assert!(!capability.entitlement.requires_live_resolution);
        assert_eq!(
            capability.entitlement.source.as_deref(),
            Some("https://developers.cloudflare.com/changelog/post/2026-02-04-queues-free-plan/")
        );
        assert!(capability.mutation_contract_gaps().is_empty());
    }

    for id in ["queues-update", "queues-update-partial"] {
        let update = snapshot.get(id).expect("queue update");
        assert_eq!(update.risk, RiskClass::Destructive);
        assert_eq!(update.effect, EffectClass::Destructive);
        assert!(update.same_path_read.is_some());
        assert!(!update.rollback.supported);
        assert!(
            update.rollback.warning.as_deref().is_some_and(|warning| {
                warning.contains("retention")
                    && warning.contains("expired messages")
                    && warning.contains("cannot be restored")
            }),
            "{id}: {:?}",
            update.rollback.warning
        );
    }
}

#[test]
fn queue_configuration_classifier_rejects_permission_and_request_schema_drift() {
    let mut permission_drift = queue_configuration_fixture();
    permission_drift["paths"]["/accounts/{account_id}/queues"]["post"]["x-api-token-group"] =
        json!(["Queues Write"]);
    let permission_snapshot = normalize_openapi(&permission_drift).expect("permission drift");
    let drifted_create = permission_snapshot
        .get("queues-create")
        .expect("permission-drifted queue create");
    assert_eq!(drifted_create.risk, RiskClass::Unknown);
    assert!(!drifted_create.cost.known);
    assert_eq!(drifted_create.entitlement.available, None);

    let mut create_schema_drift = queue_configuration_fixture();
    create_schema_drift["paths"]["/accounts/{account_id}/queues"]["post"]["requestBody"]["content"]
        ["application/json"]["schema"]["properties"]["billing_plan"] = json!({"type": "string"});
    let create_schema_snapshot =
        normalize_openapi(&create_schema_drift).expect("create schema drift");
    let drifted_create = create_schema_snapshot
        .get("queues-create")
        .expect("schema-drifted queue create");
    assert_eq!(drifted_create.risk, RiskClass::Unknown);
    assert!(!drifted_create.cost.known);
    assert_eq!(drifted_create.entitlement.available, None);

    let mut update_schema_drift = queue_configuration_fixture();
    update_schema_drift["paths"]["/accounts/{account_id}/queues/{queue_id}"]["patch"]["requestBody"]
        ["content"]["application/json"]["schema"]["properties"]["settings"]["properties"]["subscription_tier"] =
        json!({"type": "string"});
    let update_schema_snapshot =
        normalize_openapi(&update_schema_drift).expect("update schema drift");
    let drifted_update = update_schema_snapshot
        .get("queues-update-partial")
        .expect("schema-drifted queue update");
    assert_eq!(drifted_update.risk, RiskClass::Unknown);
    assert!(!drifted_update.cost.known);
    assert_eq!(drifted_update.entitlement.available, None);
}

fn cloudflare_tunnel_lifecycle_fixture() -> serde_json::Value {
    let mut document = create_lifecycle_fixture();
    document["components"]["schemas"]["Widget"]["properties"] = json!({
        "id": {"type": "string", "format": "uuid"},
        "name": {"type": "string"},
        "config_src": {"type": "string", "enum": ["local", "cloudflare"]}
    });

    let mut collection = document["paths"]
        .as_object_mut()
        .expect("paths")
        .remove("/accounts/{account_id}/widgets")
        .expect("widget collection");
    collection["post"]["operationId"] = json!("cloudflare-tunnel-create-a-cloudflare-tunnel");
    collection["post"]["summary"] = json!("Create a Cloudflare Tunnel");
    collection["post"]["tags"] = json!(["Cloudflare Tunnel"]);
    collection["post"]["x-api-token-group"] = json!([
        "Cloudflare One Connectors Write",
        "Cloudflare One Connector: cloudflared Write",
        "Cloudflare Tunnel Write"
    ]);
    collection["post"]["requestBody"]["content"]["application/json"]["schema"] = json!({
        "type": "object",
        "required": ["name"],
        "properties": {
            "config_src": {"type": "string", "enum": ["local", "cloudflare"]},
            "name": {"type": "string"},
            "tunnel_secret": {"type": "string"}
        }
    });
    let create_response = collection["post"]["responses"]
        .as_object_mut()
        .expect("create responses")
        .remove("201")
        .expect("created response");
    collection["post"]["responses"] = json!({"200": create_response});

    let mut detail = document["paths"]
        .as_object_mut()
        .expect("paths")
        .remove("/accounts/{account_id}/widgets/{widget_id}")
        .expect("widget detail");
    detail["parameters"][1]["name"] = json!("tunnel_id");
    detail["parameters"][1]["schema"] = json!({"type": "string", "format": "uuid"});
    detail["get"]["operationId"] = json!("cloudflare-tunnel-get-a-cloudflare-tunnel");
    detail["get"]["summary"] = json!("Get a Cloudflare Tunnel");
    detail["get"]["tags"] = json!(["Cloudflare Tunnel"]);
    detail["delete"]["operationId"] = json!("cloudflare-tunnel-delete-a-cloudflare-tunnel");
    detail["delete"]["summary"] = json!("Delete a Cloudflare Tunnel");
    detail["delete"]["tags"] = json!(["Cloudflare Tunnel"]);
    detail["delete"]["x-api-token-group"] = json!([
        "Cloudflare One Connectors Write",
        "Cloudflare One Connector: cloudflared Write",
        "Cloudflare Tunnel Write"
    ]);
    detail["delete"]["requestBody"] = json!({
        "required": true,
        "content": {"application/json": {"schema": {
            "type": "object",
            "properties": {}
        }}}
    });
    detail["delete"]["responses"] = json!({
        "200": {
            "description": "Tunnel deleted",
            "content": {"application/json": {
                "schema": {"$ref": "#/components/schemas/WidgetResponse"}
            }}
        }
    });
    detail["patch"] = json!({
        "operationId": "cloudflare-tunnel-update-a-cloudflare-tunnel",
        "summary": "Update a Cloudflare Tunnel",
        "tags": ["Cloudflare Tunnel"],
        "x-api-token-group": [
            "Cloudflare One Connectors Write",
            "Cloudflare One Connector: cloudflared Write",
            "Cloudflare Tunnel Write"
        ],
        "requestBody": {
            "required": true,
            "content": {"application/json": {"schema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "tunnel_secret": {"type": "string"}
                }
            }}}
        },
        "responses": {
            "200": {
                "description": "Tunnel updated",
                "content": {"application/json": {
                    "schema": {"$ref": "#/components/schemas/WidgetResponse"}
                }}
            }
        }
    });
    document["paths"]["/accounts/{account_id}/cfd_tunnel"] = collection;
    document["paths"]["/accounts/{account_id}/cfd_tunnel/{tunnel_id}"] = detail;
    document
}

#[test]
fn cloudflare_tunnel_lifecycle_exposes_a_secret_safe_remote_management_lane() {
    let snapshot =
        normalize_openapi(&cloudflare_tunnel_lifecycle_fixture()).expect("Tunnel catalog");
    let create = snapshot
        .get("cloudflare-tunnel-create-a-cloudflare-tunnel")
        .expect("Tunnel create");
    assert_eq!(create.adapter_status, AdapterStatus::DynamicApi);
    assert_eq!(create.risk, RiskClass::CrossConfig);
    assert_eq!(create.effect, EffectClass::ReversibleWrite);
    assert_eq!(
        create.request_schema,
        Some(json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["config_src", "name"],
            "properties": {
                "config_src": {"type": "string", "enum": ["cloudflare"]},
                "name": {"type": "string"}
            },
            "x-cfctl-body-required": true
        }))
    );
    assert!(create.cost.known);
    assert_eq!(create.cost.maximum, Some(0.0));
    assert_eq!(create.cost.exposure, CostExposureV1::DownstreamUsage);
    assert_eq!(create.entitlement.available, Some(true));
    assert_eq!(create.entitlement.plans.get("zero_trust_free"), Some(&true));
    assert_eq!(
        create.entitlement.plans.get("zero_trust_pay_as_you_go"),
        Some(&true)
    );
    assert_eq!(
        create.entitlement.plans.get("zero_trust_contract"),
        Some(&true)
    );
    let created = create
        .created_resource
        .as_ref()
        .expect("exact created Tunnel contract");
    assert_eq!(created.identity_selector, "tunnel_id");
    assert_eq!(created.response_result_identity_pointer, "/id");
    assert_eq!(
        created.read_capability_id,
        "cloudflare-tunnel-get-a-cloudflare-tunnel"
    );
    assert_eq!(
        created.delete_capability_id,
        "cloudflare-tunnel-delete-a-cloudflare-tunnel"
    );
    assert_eq!(created.verified_response_fields, ["config_src", "name"]);
    assert!(create.rollback.supported);
    assert_eq!(
        create.rollback.strategy.as_deref(),
        Some("delete_created_resource_by_returned_id")
    );
    assert!(create.mutation_contract_gaps().is_empty());

    let update = snapshot
        .get("cloudflare-tunnel-update-a-cloudflare-tunnel")
        .expect("Tunnel update");
    assert_eq!(update.adapter_status, AdapterStatus::DynamicApi);
    assert_eq!(update.risk, RiskClass::CrossConfig);
    assert_eq!(update.effect, EffectClass::ReversibleWrite);
    assert_eq!(
        update.request_schema,
        Some(json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["name"],
            "properties": {"name": {"type": "string"}},
            "x-cfctl-body-required": true
        }))
    );
    let readback = update
        .same_path_read
        .as_ref()
        .expect("exact Tunnel update readback");
    assert_eq!(
        readback.read_capability_id,
        "cloudflare-tunnel-get-a-cloudflare-tunnel"
    );
    assert_eq!(readback.verified_response_fields, ["name"]);
    assert!(!update.rollback.supported);
    assert!(update.rollback.warning.as_deref().is_some_and(|warning| {
        warning.contains("pre-change snapshot") && warning.contains("separately reviewed")
    }));
    assert!(update.mutation_contract_gaps().is_empty());
}

#[test]
fn cloudflare_tunnel_lifecycle_rejects_permission_and_source_schema_drift() {
    let mut permission_drift = cloudflare_tunnel_lifecycle_fixture();
    permission_drift["paths"]["/accounts/{account_id}/cfd_tunnel"]["post"]["x-api-token-group"] =
        json!(["Cloudflare Tunnel Write"]);
    let permission_snapshot = normalize_openapi(&permission_drift).expect("permission drift");
    let drifted_create = permission_snapshot
        .get("cloudflare-tunnel-create-a-cloudflare-tunnel")
        .expect("permission-drifted Tunnel create");
    assert_eq!(drifted_create.adapter_status, AdapterStatus::Blocked);
    assert_eq!(drifted_create.risk, RiskClass::Unknown);
    assert!(
        drifted_create
            .request_schema
            .as_ref()
            .and_then(|schema| schema.pointer("/properties/tunnel_secret"))
            .is_some()
    );

    let mut schema_drift = cloudflare_tunnel_lifecycle_fixture();
    schema_drift["paths"]["/accounts/{account_id}/cfd_tunnel/{tunnel_id}"]["patch"]["requestBody"]
        ["content"]["application/json"]["schema"]["properties"]["billing_tier"] =
        json!({"type": "string"});
    let schema_snapshot = normalize_openapi(&schema_drift).expect("schema drift");
    let drifted_update = schema_snapshot
        .get("cloudflare-tunnel-update-a-cloudflare-tunnel")
        .expect("schema-drifted Tunnel update");
    assert_eq!(drifted_update.adapter_status, AdapterStatus::Blocked);
    assert_eq!(drifted_update.risk, RiskClass::Unknown);
    assert!(!drifted_update.cost.known);
}

fn cloudflare_tunnel_origin_request_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "properties": {
            "access": {
                "type": "object",
                "required": ["audTag", "teamName"],
                "properties": {
                    "audTag": {"type": "array", "items": {"type": "string"}},
                    "required": {"type": "boolean"},
                    "teamName": {"type": "string"}
                }
            },
            "caPool": {"type": "string"},
            "connectTimeout": {"type": "integer"},
            "disableChunkedEncoding": {"type": "boolean"},
            "http2Origin": {"type": "boolean"},
            "httpHostHeader": {"type": "string"},
            "keepAliveConnections": {"type": "integer"},
            "keepAliveTimeout": {"type": "integer"},
            "matchSNItoHost": {"type": "boolean"},
            "noHappyEyeballs": {"type": "boolean"},
            "noTLSVerify": {"type": "boolean"},
            "originServerName": {"type": "string"},
            "proxyType": {"type": "string"},
            "tcpKeepAlive": {"type": "integer"},
            "tlsTimeout": {"type": "integer"}
        }
    })
}

fn cloudflare_tunnel_configuration_fixture() -> serde_json::Value {
    let mut document = cloudflare_tunnel_lifecycle_fixture();
    let origin_request = cloudflare_tunnel_origin_request_schema();
    document["components"]["schemas"]["Widget"]["properties"]["config"] = json!({
        "type": "object",
        "properties": {
            "ingress": {"type": "array"},
            "originRequest": {"type": "object"}
        }
    });
    let response = json!({
        "description": "Tunnel configuration",
        "content": {"application/json": {
            "schema": {"$ref": "#/components/schemas/WidgetResponse"}
        }}
    });
    document["paths"]["/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations"] = json!({
        "parameters": [
            {
                "in": "path",
                "name": "account_id",
                "required": true,
                "schema": {"type": "string", "maxLength": 32}
            },
            {
                "in": "path",
                "name": "tunnel_id",
                "required": true,
                "schema": {"type": "string", "format": "uuid", "maxLength": 36}
            }
        ],
        "get": {
            "operationId": "cloudflare-tunnel-configuration-get-configuration",
            "summary": "Get configuration",
            "tags": ["Cloudflare Tunnel Configuration"],
            "x-api-token-group": [
                "Cloudflare One Connectors Write",
                "Cloudflare One Connectors Read",
                "Cloudflare One Connector: cloudflared Write",
                "Cloudflare One Connector: cloudflared Read",
                "Cloudflare Tunnel Write",
                "Cloudflare Tunnel Read"
            ],
            "responses": {"200": response.clone()}
        },
        "put": {
            "operationId": "cloudflare-tunnel-configuration-put-configuration",
            "summary": "Put configuration",
            "tags": ["Cloudflare Tunnel Configuration"],
            "x-api-token-group": [
                "Cloudflare One Connectors Write",
                "Cloudflare One Connector: cloudflared Write",
                "Cloudflare Tunnel Write"
            ],
            "requestBody": {
                "required": true,
                "content": {"application/json": {"schema": {
                    "type": "object",
                    "properties": {
                        "config": {
                            "type": "object",
                            "properties": {
                                "ingress": {
                                    "type": "array",
                                    "minItems": 1,
                                    "items": {
                                        "type": "object",
                                        "required": ["hostname", "service"],
                                        "properties": {
                                            "hostname": {"type": "string"},
                                            "originRequest": origin_request.clone(),
                                            "path": {"type": "string"},
                                            "service": {"type": "string"}
                                        }
                                    }
                                },
                                "originRequest": origin_request
                            }
                        }
                    }
                }}}
            },
            "responses": {"200": response}
        }
    });
    document
}

#[test]
fn cloudflare_tunnel_configuration_binds_a_reversible_full_routing_replacement() {
    let snapshot = normalize_openapi(&cloudflare_tunnel_configuration_fixture())
        .expect("Tunnel configuration catalog");
    let capability = snapshot
        .get("cloudflare-tunnel-configuration-put-configuration")
        .expect("Tunnel configuration PUT");

    assert_eq!(
        capability.adapter_status,
        AdapterStatus::DynamicApi,
        "{capability:#?}"
    );
    assert_eq!(capability.risk, RiskClass::CrossConfig);
    assert_eq!(capability.effect, EffectClass::ReversibleWrite);
    let request = capability.request_schema.as_ref().expect("request schema");
    assert_eq!(request.get("required"), Some(&json!(["config"])));
    assert_eq!(request.get("additionalProperties"), Some(&json!(false)));
    assert_eq!(
        request.pointer("/properties/config/required"),
        Some(&json!(["ingress"]))
    );
    for pointer in [
        "/properties/config/additionalProperties",
        "/properties/config/properties/ingress/items/additionalProperties",
        "/properties/config/properties/ingress/items/properties/originRequest/additionalProperties",
        "/properties/config/properties/ingress/items/properties/originRequest/properties/access/additionalProperties",
        "/properties/config/properties/originRequest/additionalProperties",
        "/properties/config/properties/originRequest/properties/access/additionalProperties",
    ] {
        assert_eq!(request.pointer(pointer), Some(&json!(false)), "{pointer}");
    }
    assert!(capability.cost.known);
    assert_eq!(capability.cost.maximum, Some(0.0));
    assert_eq!(capability.cost.exposure, CostExposureV1::DownstreamUsage);
    assert_eq!(capability.entitlement.available, Some(true));
    assert_eq!(
        capability.entitlement.plans.get("zero_trust_free"),
        Some(&true)
    );
    assert_eq!(
        capability.verification.strategy,
        "same_path_result_contains_planned_fields_after_update"
    );
    assert_eq!(
        capability
            .same_path_read
            .as_ref()
            .expect("same-path read")
            .read_capability_id,
        "cloudflare-tunnel-configuration-get-configuration"
    );
    assert!(capability.rollback.supported);
    assert_eq!(
        capability.rollback.strategy.as_deref(),
        Some("restore_cloudflare_tunnel_configuration_prior_snapshot")
    );
    assert!(capability.mutation_contract_gaps().is_empty());
}

#[test]
fn cloudflare_tunnel_configuration_rejects_permission_and_nested_schema_drift() {
    let mut permission_drift = cloudflare_tunnel_configuration_fixture();
    permission_drift["paths"]["/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations"]["put"]
        ["x-api-token-group"] = json!(["Cloudflare Tunnel Write"]);
    let permission_snapshot = normalize_openapi(&permission_drift).expect("permission drift");
    let drifted_permission = permission_snapshot
        .get("cloudflare-tunnel-configuration-put-configuration")
        .expect("permission-drifted Tunnel configuration");
    assert_eq!(drifted_permission.adapter_status, AdapterStatus::Blocked);
    assert_eq!(drifted_permission.risk, RiskClass::Unknown);

    let mut schema_drift = cloudflare_tunnel_configuration_fixture();
    schema_drift["paths"]["/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations"]["put"]
        ["requestBody"]["content"]["application/json"]["schema"]["properties"]["config"]["properties"]
        ["originRequest"]["properties"]["proxyProtocol"] = json!({"type": "string"});
    let schema_snapshot = normalize_openapi(&schema_drift).expect("nested schema drift");
    let drifted_schema = schema_snapshot
        .get("cloudflare-tunnel-configuration-put-configuration")
        .expect("schema-drifted Tunnel configuration");
    assert_eq!(drifted_schema.adapter_status, AdapterStatus::Blocked);
    assert_eq!(drifted_schema.risk, RiskClass::Unknown);
    assert!(!drifted_schema.cost.known);

    let mut read_drift = cloudflare_tunnel_configuration_fixture();
    read_drift["paths"]["/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations"]["get"]["x-api-token-group"] =
        json!(["Cloudflare Tunnel Read"]);
    let read_snapshot = normalize_openapi(&read_drift).expect("read contract drift");
    let drifted_read = read_snapshot
        .get("cloudflare-tunnel-configuration-put-configuration")
        .expect("read-drifted Tunnel configuration");
    assert_eq!(drifted_read.adapter_status, AdapterStatus::Blocked);
    assert_eq!(drifted_read.risk, RiskClass::Unknown);
    assert!(!drifted_read.cost.known);
}

fn warp_connector_configuration_schema() -> serde_json::Value {
    json!({
        "nullable": true,
        "oneOf": [
            {
                "type": "object",
                "required": ["fnr_id"],
                "properties": {"fnr_id": {"type": "string"}}
            },
            {
                "type": "object",
                "required": ["vips"],
                "properties": {
                    "vips": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 8,
                        "items": {
                            "type": "object",
                            "required": ["address"],
                            "properties": {"address": {"type": "string"}}
                        }
                    },
                    "vips_previous": {
                        "type": "array",
                        "maxItems": 8,
                        "items": {
                            "type": "object",
                            "required": ["address"],
                            "properties": {"address": {"type": "string"}}
                        }
                    }
                }
            },
            {"type": "object", "additionalProperties": false}
        ],
        "type": "object"
    })
}

fn warp_connector_configuration_fixture() -> serde_json::Value {
    let mut document = cloudflare_tunnel_lifecycle_fixture();
    document["components"]["schemas"]["Widget"]["properties"]["config"] =
        warp_connector_configuration_schema();
    document["components"]["schemas"]["Widget"]["properties"]["ha_mode"] = json!({
        "type": "string",
        "enum": ["none", "disabled", "aws", "local"]
    });
    let response = json!({
        "description": "WARP Connector configuration",
        "content": {"application/json": {
            "schema": {"$ref": "#/components/schemas/WidgetResponse"}
        }}
    });
    let config = warp_connector_configuration_schema();
    document["paths"]["/accounts/{account_id}/warp_connector/{tunnel_id}/configurations"] = json!({
        "parameters": [
            {
                "in": "path",
                "name": "account_id",
                "required": true,
                "schema": {"type": "string", "maxLength": 32}
            },
            {
                "in": "path",
                "name": "tunnel_id",
                "required": true,
                "schema": {"type": "string", "format": "uuid", "maxLength": 36}
            }
        ],
        "get": {
            "operationId": "cloudflare-tunnel-configuration-get-warp-connector-configuration",
            "summary": "Get WARP Connector configuration",
            "tags": ["Cloudflare Tunnel Configuration"],
            "x-api-token-group": [
                "Cloudflare One Connectors Write",
                "Cloudflare One Connectors Read",
                "Cloudflare One Connector: WARP Write",
                "Cloudflare One Connector: WARP Read"
            ],
            "responses": {"200": response.clone()}
        },
        "put": {
            "operationId": "cloudflare-tunnel-configuration-update-warp-connector-configuration",
            "summary": "Update WARP Connector configuration",
            "tags": ["Cloudflare Tunnel Configuration"],
            "x-api-token-group": [
                "Cloudflare One Connectors Write",
                "Cloudflare One Connector: WARP Write"
            ],
            "requestBody": {
                "required": true,
                "content": {"application/json": {"schema": {
                    "type": "object",
                    "required": ["ha_mode"],
                    "properties": {
                        "config": config,
                        "ha_mode": {
                            "type": "string",
                            "enum": ["none", "disabled", "aws", "local"]
                        }
                    }
                }}}
            },
            "responses": {"200": response}
        }
    });
    document
}

#[test]
fn warp_connector_configuration_binds_reversible_mesh_ha_state() {
    let snapshot = normalize_openapi(&warp_connector_configuration_fixture())
        .expect("WARP Connector configuration catalog");
    let capability = snapshot
        .get("cloudflare-tunnel-configuration-update-warp-connector-configuration")
        .expect("WARP Connector configuration update");

    assert_eq!(capability.adapter_status, AdapterStatus::DynamicApi);
    assert_eq!(capability.risk, RiskClass::CrossConfig);
    assert_eq!(capability.effect, EffectClass::ReversibleWrite);
    let request = capability.request_schema.as_ref().expect("request schema");
    for pointer in [
        "/additionalProperties",
        "/properties/config/oneOf/0/additionalProperties",
        "/properties/config/oneOf/1/additionalProperties",
        "/properties/config/oneOf/1/properties/vips/items/additionalProperties",
        "/properties/config/oneOf/1/properties/vips_previous/items/additionalProperties",
    ] {
        assert_eq!(request.pointer(pointer), Some(&json!(false)), "{pointer}");
    }
    assert!(capability.cost.known);
    assert_eq!(capability.cost.maximum, Some(0.0));
    assert_eq!(capability.cost.exposure, CostExposureV1::DownstreamUsage);
    assert_eq!(capability.entitlement.available, Some(true));
    assert_eq!(
        capability.entitlement.plans.get("zero_trust_free"),
        Some(&true)
    );
    assert_eq!(
        capability
            .same_path_read
            .as_ref()
            .expect("same-path read")
            .read_capability_id,
        "cloudflare-tunnel-configuration-get-warp-connector-configuration"
    );
    assert_eq!(
        capability
            .same_path_read
            .as_ref()
            .expect("same-path read")
            .verified_response_fields,
        ["config", "ha_mode"]
    );
    assert!(capability.rollback.supported);
    assert_eq!(
        capability.rollback.strategy.as_deref(),
        Some("restore_warp_connector_configuration_prior_snapshot")
    );
    assert!(capability.mutation_contract_gaps().is_empty());
}

#[test]
fn warp_connector_configuration_rejects_permission_schema_and_read_drift() {
    let mut permission_drift = warp_connector_configuration_fixture();
    permission_drift["paths"]["/accounts/{account_id}/warp_connector/{tunnel_id}/configurations"]
        ["put"]["x-api-token-group"] = json!(["Cloudflare One Connectors Write"]);
    let snapshot = normalize_openapi(&permission_drift).expect("permission drift");
    let capability = snapshot
        .get("cloudflare-tunnel-configuration-update-warp-connector-configuration")
        .expect("permission-drifted WARP Connector configuration");
    assert_eq!(capability.adapter_status, AdapterStatus::Blocked);
    assert_eq!(capability.risk, RiskClass::Unknown);

    let mut schema_drift = warp_connector_configuration_fixture();
    schema_drift["paths"]["/accounts/{account_id}/warp_connector/{tunnel_id}/configurations"]["put"]
        ["requestBody"]["content"]["application/json"]["schema"]["properties"]["config"]["oneOf"]
        [1]["properties"]["routing_table"] = json!({"type": "string"});
    let snapshot = normalize_openapi(&schema_drift).expect("schema drift");
    let capability = snapshot
        .get("cloudflare-tunnel-configuration-update-warp-connector-configuration")
        .expect("schema-drifted WARP Connector configuration");
    assert_eq!(capability.adapter_status, AdapterStatus::Blocked);
    assert_eq!(capability.risk, RiskClass::Unknown);
    assert!(!capability.cost.known);

    let mut read_drift = warp_connector_configuration_fixture();
    read_drift["paths"]["/accounts/{account_id}/warp_connector/{tunnel_id}/configurations"]["get"]
        ["x-api-token-group"] = json!(["Cloudflare One Connector: WARP Read"]);
    let snapshot = normalize_openapi(&read_drift).expect("read drift");
    let capability = snapshot
        .get("cloudflare-tunnel-configuration-update-warp-connector-configuration")
        .expect("read-drifted WARP Connector configuration");
    assert_eq!(capability.adapter_status, AdapterStatus::Blocked);
    assert_eq!(capability.risk, RiskClass::Unknown);
    assert!(!capability.cost.known);
}

fn web_analytics_rum_fixture() -> serde_json::Value {
    let response = json!({
        "description": "Cloudflare API envelope",
        "content": {"application/json": {"schema": {
            "type": "object",
            "required": ["success", "result"],
            "properties": {
                "success": {"type": "boolean"},
                "result": {
                    "type": "object",
                    "properties": {
                        "editable": {"type": "boolean"},
                        "id": {"type": "string"},
                        "value": {"type": "string"}
                    }
                }
            }
        }}}
    });
    json!({
        "openapi": "3.0.3",
        "info": {"title": "Cloudflare API", "version": "4.0.0"},
        "servers": [{"url": "https://api.cloudflare.com/client/v4"}],
        "paths": {
            "/zones/{zone_id}/settings/rum": {
                "parameters": [{
                    "in": "path",
                    "name": "zone_id",
                    "required": true,
                    "schema": {"type": "string", "maxLength": 32}
                }],
                "get": {
                    "operationId": "web-analytics-get-rum-status",
                    "summary": "Get RUM status",
                    "tags": ["Web Analytics"],
                    "x-api-token-group": ["Zone Settings Write", "Zone Settings Read"],
                    "x-cfPlanAvailability": {
                        "free": true,
                        "pro": true,
                        "business": true,
                        "enterprise": true
                    },
                    "responses": {"200": response.clone()}
                },
                "patch": {
                    "operationId": "web-analytics-toggle-rum",
                    "summary": "Toggle RUM on/off for a zone",
                    "tags": ["Web Analytics"],
                    "x-api-token-group": ["Zone Settings Write"],
                    "x-cfPlanAvailability": {
                        "free": true,
                        "pro": true,
                        "business": true,
                        "enterprise": true
                    },
                    "requestBody": {
                        "required": true,
                        "content": {"application/json": {"schema": {
                            "type": "object",
                            "properties": {"value": {"type": "string"}}
                        }}}
                    },
                    "responses": {"200": response}
                }
            }
        }
    })
}

#[test]
fn web_analytics_rum_toggle_binds_exact_reversible_state() {
    let snapshot =
        normalize_openapi(&web_analytics_rum_fixture()).expect("Web Analytics RUM catalog");
    let capability = snapshot
        .get("web-analytics-toggle-rum")
        .expect("Web Analytics RUM toggle");

    assert_eq!(capability.adapter_status, AdapterStatus::DynamicApi);
    assert_eq!(capability.risk, RiskClass::CrossConfig);
    assert_eq!(capability.effect, EffectClass::ReversibleWrite);
    let request = capability.request_schema.as_ref().expect("request schema");
    assert_eq!(
        request.pointer("/additionalProperties"),
        Some(&json!(false))
    );
    assert_eq!(request.pointer("/required"), Some(&json!(["value"])));
    assert_eq!(
        request.pointer("/properties/value/enum"),
        Some(&json!(["on", "off"]))
    );
    assert!(capability.cost.known);
    assert_eq!(capability.cost.maximum, Some(0.0));
    assert_eq!(capability.cost.billing_model, BillingModelV1::None);
    assert_eq!(capability.cost.exposure, CostExposureV1::None);
    assert_eq!(capability.entitlement.available, Some(true));
    for plan in ["free", "pro", "business", "enterprise"] {
        assert_eq!(capability.entitlement.plans.get(plan), Some(&true));
    }
    let read = capability.same_path_read.as_ref().expect("same-path read");
    assert_eq!(read.read_capability_id, "web-analytics-get-rum-status");
    assert_eq!(read.verified_response_fields, ["value"]);
    assert!(capability.rollback.supported);
    assert_eq!(
        capability.rollback.strategy.as_deref(),
        Some("restore_web_analytics_rum_prior_value")
    );
    assert!(capability.mutation_contract_gaps().is_empty());

    let mut enriched = snapshot;
    attach_official_product_knowledge(&mut enriched, &pricing_feeds_fixture())
        .expect("official product knowledge");
    let enriched_capability = enriched
        .get("web-analytics-toggle-rum")
        .expect("enriched Web Analytics RUM toggle");
    assert_eq!(enriched_capability.cost.billing_model, BillingModelV1::None);
    assert_eq!(enriched_capability.cost.exposure, CostExposureV1::None);
    assert_eq!(enriched_capability.cost.maximum, Some(0.0));
}

#[test]
fn web_analytics_rum_toggle_rejects_permission_schema_and_read_drift() {
    let mut permission_drift = web_analytics_rum_fixture();
    permission_drift["paths"]["/zones/{zone_id}/settings/rum"]["patch"]["x-api-token-group"] =
        json!(["Zone Settings Read"]);
    let snapshot = normalize_openapi(&permission_drift).expect("permission drift");
    let capability = snapshot
        .get("web-analytics-toggle-rum")
        .expect("permission-drifted Web Analytics RUM toggle");
    assert_eq!(capability.adapter_status, AdapterStatus::Blocked);
    assert_eq!(capability.risk, RiskClass::Unknown);

    let mut schema_drift = web_analytics_rum_fixture();
    schema_drift["paths"]["/zones/{zone_id}/settings/rum"]["patch"]["requestBody"]["content"]["application/json"]
        ["schema"]["properties"]["rules"] = json!({"type": "array"});
    let snapshot = normalize_openapi(&schema_drift).expect("schema drift");
    let capability = snapshot
        .get("web-analytics-toggle-rum")
        .expect("schema-drifted Web Analytics RUM toggle");
    assert_eq!(capability.adapter_status, AdapterStatus::Blocked);
    assert_eq!(capability.risk, RiskClass::Unknown);
    assert!(!capability.cost.known);

    let mut read_drift = web_analytics_rum_fixture();
    read_drift["paths"]["/zones/{zone_id}/settings/rum"]["get"]["x-api-token-group"] =
        json!(["Zone Settings Read"]);
    let snapshot = normalize_openapi(&read_drift).expect("read drift");
    let capability = snapshot
        .get("web-analytics-toggle-rum")
        .expect("read-drifted Web Analytics RUM toggle");
    assert_eq!(capability.adapter_status, AdapterStatus::Blocked);
    assert_eq!(capability.risk, RiskClass::Unknown);
    assert!(!capability.cost.known);
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
fn create_contracts_bind_a_schema_proven_selector_named_identity() {
    let mut exact_document = create_lifecycle_fixture();
    exact_document["components"]["schemas"]["Widget"]["properties"]
        .as_object_mut()
        .expect("widget properties")
        .remove("id");
    exact_document["components"]["schemas"]["Widget"]["properties"]["slug"] =
        json!({"type":"string"});
    let mut exact_child = exact_document["paths"]
        .as_object_mut()
        .expect("paths")
        .remove("/accounts/{account_id}/widgets/{widget_id}")
        .expect("widget child");
    exact_child["parameters"][1]["name"] = json!("slug");
    exact_document["paths"]["/accounts/{account_id}/widgets/{slug}"] = exact_child;

    let exact = normalize_openapi(&exact_document).expect("selector-backed exact create");
    let exact_target = exact
        .get("widgets-create")
        .and_then(|capability| capability.created_resource.as_ref())
        .expect("selector-backed exact create contract");
    assert_eq!(exact_target.identity_selector, "slug");
    assert_eq!(exact_target.response_result_identity_pointer, "/slug");

    let mut collection_document = create_collection_lifecycle_fixture();
    collection_document["components"]["schemas"]["Widget"]["properties"]
        .as_object_mut()
        .expect("widget properties")
        .remove("id");
    collection_document["components"]["schemas"]["Widget"]["properties"]["slug"] =
        json!({"type":"string"});
    let mut collection_child = collection_document["paths"]
        .as_object_mut()
        .expect("paths")
        .remove("/accounts/{account_id}/widgets/{widget_id}")
        .expect("widget child");
    collection_child["parameters"][1]["name"] = json!("slug");
    collection_document["paths"]["/accounts/{account_id}/widgets/{slug}"] = collection_child;

    let collection =
        normalize_openapi(&collection_document).expect("selector-backed collection create");
    let collection_target = collection
        .get("widgets-create")
        .and_then(|capability| capability.created_collection_resource.as_ref())
        .expect("selector-backed collection create contract");
    assert_eq!(collection_target.identity_selector, "slug");
    assert_eq!(collection_target.response_result_identity_pointer, "/slug");
    assert_eq!(collection_target.response_item_identity_pointer, "/slug");

    collection_document["components"]["schemas"]["Widget"]["properties"]["slug"]["type"] =
        json!("integer");
    let incompatible =
        normalize_openapi(&collection_document).expect("incompatible selector create");
    assert!(
        incompatible
            .get("widgets-create")
            .expect("create widget")
            .created_collection_resource
            .is_none()
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
fn workers_ai_model_runs_are_metered_irreversible_actions_without_a_fictitious_ceiling() {
    let mut document = fixture();
    document["paths"]["/accounts/{account_id}/ai/run/@cf/example/model"]["post"] = json!({
        "operationId": "workers-ai-post-run-cf-example-model",
        "summary": "Execute a Workers AI model",
        "tags": ["Workers AI Text Generation"],
        "parameters": [
            {"in":"path","name":"account_id","required":true,"schema":{"type":"string"}},
            {"in":"query","name":"queueRequest","schema":{"type":"string"}},
            {"in":"query","name":"tags","schema":{"type":"string"}}
        ],
        "x-api-token-group": ["Workers AI Write", "Workers AI Read"],
        "requestBody": {"content":{"application/json":{"schema":{
            "type":"object",
            "required":["prompt"],
            "properties":{
                "prompt":{"type":"string","minLength":1},
                "max_tokens":{"type":"integer"},
                "stream":{"type":"boolean"}
            }
        }}}},
        "x-cfPlanAvailability":{"free":true,"pro":true,"business":true,"enterprise":true}
    });
    document["paths"]["/accounts/{account_id}/ai/configure"]["post"] = json!({
        "operationId": "workers-ai-configure",
        "summary": "Configure Workers AI",
        "tags": ["Workers AI"],
        "x-api-token-group": ["Workers AI Write", "Workers AI Read"]
    });

    let snapshot = normalize_openapi(&document).expect("catalog");
    let run = snapshot
        .get("workers-ai-post-run-cf-example-model")
        .expect("Workers AI run");
    assert_eq!(run.risk, RiskClass::Spend);
    assert_eq!(run.effect, EffectClass::Spend);
    assert!(run.cost.incremental);
    assert!(!run.cost.known);
    assert_eq!(run.cost.maximum, None);
    assert_eq!(run.cost.billing_model, BillingModelV1::UsageBased);
    assert_eq!(run.cost.exposure, CostExposureV1::DownstreamUsage);
    assert!(run.cost.basis.as_deref().is_some_and(|basis| {
        basis.contains("Workers AI") && basis.contains("input") && basis.contains("hard ceiling")
    }));
    assert!(!run.rollback.supported);
    assert!(run.rollback.warning.as_deref().is_some_and(|warning| {
        warning.contains("inference")
            && warning.contains("cannot be rolled back")
            && warning.contains("billed usage")
    }));
    assert!(run.blocked_reason.as_deref().is_some_and(|reason| {
        reason.contains("operation-specific incremental cost is unknown")
            && reason.contains("operation-specific verification is not declared")
            && !reason.contains("operation-specific risk classification is missing")
            && !reason.contains("operation-specific effect classification is missing")
            && !reason
                .contains("operation-specific rollback or irreversibility behavior is not declared")
    }));

    let nearby = snapshot
        .get("workers-ai-configure")
        .expect("nearby Workers AI mutation");
    assert_eq!(nearby.risk, RiskClass::Unknown);
    assert_eq!(nearby.effect, EffectClass::Unknown);
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
fn plan_gate_resolution_requires_a_scope_specific_subscription_join() {
    let document = json!({
        "openapi":"3.0.3",
        "info":{"title":"Cloudflare API","version":"4.0.0"},
        "paths": {
            "/accounts/{account_id}/widgets": {
                "post": {
                    "operationId":"account-widgets-create",
                    "summary":"Create account widget",
                    "tags":["Widgets"],
                    "parameters":[
                        {"in":"path","name":"account_id","required":true,"schema":{"type":"string"}}
                    ],
                    "x-cfPlanAvailability":{"free":false,"pro":true,"business":true,"enterprise":true}
                }
            },
            "/zones/{zone_id}/widgets": {
                "post": {
                    "operationId":"zone-widgets-create",
                    "summary":"Create zone widget",
                    "tags":["Widgets"],
                    "parameters":[
                        {"in":"path","name":"zone_id","required":true,"schema":{"type":"string"}}
                    ],
                    "x-cfPlanAvailability":{"free":false,"pro":true,"business":true,"enterprise":true}
                }
            }
        }
    });
    let mut snapshot = normalize_openapi(&document).expect("catalog");

    attach_official_product_knowledge(&mut snapshot, &pricing_feeds_fixture())
        .expect("knowledge attaches");

    let account = snapshot
        .get("account-widgets-create")
        .expect("account operation");
    assert!(!account.entitlement.requires_live_resolution);
    assert!(
        account
            .entitlement
            .blocker
            .as_deref()
            .is_some_and(|blocker| { blocker.contains("product-scoped subscription join key") })
    );
    assert!(
        account
            .mutation_contract_gaps()
            .iter()
            .any(|gap| { gap.contains("product-scoped subscription join key") })
    );

    let zone = snapshot.get("zone-widgets-create").expect("zone operation");
    assert!(zone.entitlement.requires_live_resolution);
    assert!(zone.entitlement.blocker.is_none());
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

fn zone_cache_purge_request_body() -> Value {
    json!({
        "required": true,
        "content": {"application/json": {"schema": {"anyOf": [
            {"type": "object", "properties": {"tags": {"type": "array", "items": {"type": "string"}}}},
            {"type": "object", "properties": {"hosts": {"type": "array", "items": {"type": "string"}}}},
            {"type": "object", "properties": {"prefixes": {"type": "array", "items": {"type": "string"}}}},
            {"type": "object", "properties": {"purge_everything": {"type": "boolean"}}},
            {"type": "object", "properties": {"files": {"type": "array", "items": {"type": "string"}}}},
            {"type": "object", "properties": {"files": {"type": "array", "items": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "headers": {"type": "object", "additionalProperties": {"type": "string"}}
                }
            }}}}
        ]}}}
    })
}

fn zone_cache_purge_success_response() -> Value {
    json!({"200": {"description": "Purge response", "content": {
        "application/json": {"schema": {"allOf": [
            {"$ref": "#/components/schemas/api-response-common"},
            {"type": "object", "properties": {
                "result": {"$ref": "#/components/schemas/purge-result"}
            }}
        ]}}
    }}})
}

fn zone_cache_purge_fixture() -> Value {
    json!({
        "openapi": "3.0.3",
        "info": {"title": "Cloudflare API", "version": "4.0.0"},
        "servers": [{"url": "https://api.cloudflare.com/client/v4"}],
        "components": {
            "schemas": {
                "identifier": {"type": "string", "maxLength": 32},
                "api-response-common": {
                    "type": "object",
                    "required": ["success"],
                    "properties": {"success": {"type": "boolean"}}
                },
                "purge-result": {
                    "type": "object",
                    "properties": {"id": {"type": "string"}}
                }
            }
        },
        "paths": {
            "/zones/{zone_id}/purge_cache": {
                "post": {
                    "operationId": "zone-purge",
                    "summary": "Purge Cached Content",
                    "tags": ["Zone"],
                    "x-api-token-group": ["Cache Purge"],
                    "parameters": [{
                        "in": "path",
                        "name": "zone_id",
                        "required": true,
                        "schema": {"$ref": "#/components/schemas/identifier"},
                        "description": "Zone ID."
                    }],
                    "requestBody": zone_cache_purge_request_body(),
                    "responses": zone_cache_purge_success_response()
                }
            },
            "/zones/{zone_id}/environments/{environment_id}/purge_cache": {
                "post": {
                    "operationId": "zone-environment-purge",
                    "summary": "Purge Cached Content by Environment",
                    "tags": ["Zone"],
                    "x-api-token-group": ["Cache Purge"],
                    "parameters": [
                        {
                            "in": "path",
                            "name": "zone_id",
                            "required": true,
                            "schema": {"$ref": "#/components/schemas/identifier"},
                            "description": "Zone ID."
                        },
                        {
                            "in": "path",
                            "name": "environment_id",
                            "required": true,
                            "schema": {"$ref": "#/components/schemas/identifier"},
                            "description": "Environment ID."
                        }
                    ],
                    "requestBody": zone_cache_purge_request_body(),
                    "responses": zone_cache_purge_success_response()
                }
            }
        }
    })
}

fn purge_variant_keys(capability: &CapabilityV1) -> std::collections::BTreeSet<String> {
    capability
        .request_schema
        .as_ref()
        .and_then(|schema| schema.get("anyOf"))
        .and_then(Value::as_array)
        .map(|variants| {
            variants
                .iter()
                .filter_map(|variant| variant.get("properties").and_then(Value::as_object))
                .flat_map(|properties| properties.keys().cloned())
                .collect()
        })
        .unwrap_or_default()
}

fn assert_zone_cache_purge_split(snapshot: &CatalogSnapshot, base_id: &str) {
    let base = snapshot
        .get(base_id)
        .unwrap_or_else(|| panic!("{base_id} present"));
    assert_eq!(
        base.adapter_status,
        AdapterStatus::DynamicApi,
        "{base_id}: {:?}",
        base.blocked_reason
    );
    assert_eq!(base.risk, RiskClass::Destructive);
    assert_eq!(base.effect, EffectClass::Destructive);
    assert!(base.cost.known);
    assert!(!base.cost.incremental);
    assert_eq!(base.cost.maximum, Some(0.0));
    assert_eq!(base.cost.billing_model, BillingModelV1::UsageBased);
    assert_eq!(base.cost.exposure, CostExposureV1::DownstreamUsage);
    assert_eq!(base.entitlement.available, Some(true));
    for plan in ["free", "pro", "business", "enterprise"] {
        assert_eq!(
            base.entitlement.plans.get(plan),
            Some(&true),
            "{base_id} base plan {plan}"
        );
    }
    assert_eq!(
        base.verification.strategy,
        "cache_purge_response_reports_target_zone_id"
    );
    assert!(base.verification.required);
    assert!(!base.rollback.supported);
    assert!(
        base.rollback
            .warning
            .as_deref()
            .is_some_and(|warning| warning.contains("irreversible"))
    );
    assert!(
        base.mutation_contract_gaps().is_empty(),
        "{base_id} gaps: {:?}",
        base.mutation_contract_gaps()
    );

    // Honest split: the all-plan base must not accept a tag, host, or prefix purge.
    let base_keys = purge_variant_keys(base);
    assert!(
        base_keys.contains("purge_everything"),
        "{base_id} base keys"
    );
    assert!(base_keys.contains("files"), "{base_id} base keys");
    assert!(!base_keys.contains("tags"), "{base_id} base keys");
    assert!(!base_keys.contains("hosts"), "{base_id} base keys");
    assert!(!base_keys.contains("prefixes"), "{base_id} base keys");

    let tagged_id = format!("{base_id}-tagged");
    let tagged = snapshot
        .get(&tagged_id)
        .unwrap_or_else(|| panic!("{tagged_id} present"));
    assert_eq!(
        tagged.adapter_status,
        AdapterStatus::DynamicApi,
        "{tagged_id}: {:?}",
        tagged.blocked_reason
    );
    assert_eq!(tagged.entitlement.available, Some(true));
    assert_eq!(tagged.entitlement.plans.get("free"), Some(&false));
    assert_eq!(tagged.entitlement.plans.get("pro"), Some(&false));
    assert_eq!(tagged.entitlement.plans.get("business"), Some(&false));
    assert_eq!(tagged.entitlement.plans.get("enterprise"), Some(&true));
    assert_eq!(
        tagged.verification.strategy,
        "cache_purge_response_reports_target_zone_id"
    );
    assert!(
        tagged.mutation_contract_gaps().is_empty(),
        "{tagged_id} gaps: {:?}",
        tagged.mutation_contract_gaps()
    );

    // Honest split: the Enterprise capability must accept only tag, host, or prefix purge.
    let tagged_keys = purge_variant_keys(tagged);
    assert!(tagged_keys.contains("tags"), "{tagged_id} keys");
    assert!(tagged_keys.contains("hosts"), "{tagged_id} keys");
    assert!(tagged_keys.contains("prefixes"), "{tagged_id} keys");
    assert!(
        !tagged_keys.contains("purge_everything"),
        "{tagged_id} keys"
    );
    assert!(!tagged_keys.contains("files"), "{tagged_id} keys");
}

#[test]
fn zone_cache_purge_splits_basic_and_enterprise_by_entitlement() {
    let snapshot =
        normalize_openapi(&zone_cache_purge_fixture()).expect("zone cache purge catalog");
    assert_zone_cache_purge_split(&snapshot, "zone-purge");
    assert_zone_cache_purge_split(&snapshot, "zone-environment-purge");
}

#[test]
fn zone_cache_purge_classifier_fails_closed_on_permission_or_response_drift() {
    let mut permission = zone_cache_purge_fixture();
    permission["paths"]["/zones/{zone_id}/purge_cache"]["post"]["x-api-token-group"] =
        json!(["Zone Settings Write"]);
    let snapshot = normalize_openapi(&permission).expect("permission-drifted catalog");
    assert_eq!(
        snapshot
            .get("zone-purge")
            .expect("zone-purge present")
            .adapter_status,
        AdapterStatus::Blocked
    );
    assert!(
        snapshot.get("zone-purge-tagged").is_none(),
        "no Enterprise capability may be derived from a drifted base"
    );

    let mut response = zone_cache_purge_fixture();
    response["components"]["schemas"]["purge-result"]["properties"]
        .as_object_mut()
        .expect("purge-result properties")
        .remove("id");
    let snapshot = normalize_openapi(&response).expect("response-drifted catalog");
    assert_eq!(
        snapshot
            .get("zone-purge")
            .expect("zone-purge present")
            .adapter_status,
        AdapterStatus::Blocked
    );
    assert!(
        snapshot.get("zone-purge-tagged").is_none(),
        "no Enterprise capability may be derived when result.id is undeclared"
    );
}
