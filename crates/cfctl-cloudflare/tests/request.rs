#![allow(clippy::expect_used, clippy::unwrap_used)]

use cfctl_auth::AuthCredential;
use cfctl_cloudflare::{
    CallInput, CloudflareError, CloudflareResponseV1, Executor, RequestBuilder,
};
use cfctl_core::{
    CapabilityV1, CreatedCollectionResourceContractV1, CreatedResourceContractV1,
    DeletedResourceContractV1, PlanStatus, PlanV1, QuerySerializationV1, ResponseBodyModeV1,
    ResponseContractV1, SamePathReadContractV1, SelectorContractV1, SelectorV1,
    UpdatedResourceContractV1,
};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

async fn json_response_sequence_server(
    bodies: Vec<&'static str>,
) -> (String, tokio::task::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let mut requests = Vec::new();
        for body in bodies {
            let (mut stream, _) = listener.accept().await.expect("accept request");
            let mut buffer = vec![0_u8; 8192];
            let read = stream.read(&mut buffer).await.expect("read request");
            requests.push(String::from_utf8_lossy(&buffer[..read]).to_string());
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write response");
        }
        requests
    });
    (address.to_string(), server)
}

async fn single_raw_response_server(
    status: &'static str,
    content_type: &'static str,
    body: &'static str,
) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept request");
        let mut buffer = vec![0_u8; 8192];
        let _ = stream.read(&mut buffer).await.expect("read request");
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write response");
    });
    (address.to_string(), server)
}

#[test]
fn request_builder_resolves_path_and_query_selectors_without_leaking_auth() {
    let mut capability = CapabilityV1::new(
        "dns-records-list",
        "List DNS records",
        "GET",
        "/zones/{zone_id}/dns_records",
    );
    capability.selectors = vec![
        SelectorV1 {
            name: "zone_id".to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        },
        SelectorV1 {
            name: "name".to_owned(),
            location: "query".to_owned(),
            required: false,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        },
    ];
    let request = RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("valid base URL")
        .build(
            &capability,
            &CallInput {
                selectors: json!({"zone_id":"zone a"}),
                query: json!({"name":"www.example.com"}),
                body: None,
                if_none_match: Some("etag-1".to_owned()),
                ..CallInput::default()
            },
        )
        .expect("request should build");

    assert_eq!(
        request.url.as_str(),
        "https://api.cloudflare.com/client/v4/zones/zone%20a/dns_records?name=www.example.com"
    );
    assert!(request.headers.get("authorization").is_none());
    assert_eq!(
        request
            .headers
            .get("if-none-match")
            .and_then(|value| value.to_str().ok()),
        Some("etag-1")
    );
}

#[test]
fn request_builder_rejects_query_controls_outside_the_catalog_contract() {
    let mut capability = CapabilityV1::new(
        "workers-ai-run",
        "Run model",
        "GET",
        "/accounts/{account_id}/ai/run/{model_name}",
    );
    capability.selectors = vec![
        SelectorV1 {
            name: "account_id".to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        },
        SelectorV1 {
            name: "model_name".to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        },
        SelectorV1 {
            name: "queueRequest".to_owned(),
            location: "query".to_owned(),
            required: true,
            value_type: "boolean".to_owned(),
            description: None,
            contract: None,
        },
    ];
    let builder = RequestBuilder::new("https://api.cloudflare.com/client/v4").expect("builder");
    let selectors = json!({"account_id":"account-1", "model_name":"@cf/example/model"});

    let undeclared = builder
        .build(
            &capability,
            &CallInput {
                selectors: selectors.clone(),
                query: json!({"queueRequest":"true", "bypass":"1"}),
                ..CallInput::default()
            },
        )
        .expect_err("undeclared query controls must fail closed");
    assert!(matches!(
        undeclared,
        CloudflareError::UndeclaredQuerySelector(name) if name == "bypass"
    ));

    let missing = builder
        .build(
            &capability,
            &CallInput {
                selectors: selectors.clone(),
                query: json!({}),
                ..CallInput::default()
            },
        )
        .expect_err("required query controls must be present");
    assert!(matches!(
        missing,
        CloudflareError::MissingQuerySelector(name) if name == "queueRequest"
    ));

    let invalid = builder
        .build(
            &capability,
            &CallInput {
                selectors: selectors.clone(),
                query: json!({"queueRequest":{"nested":true}}),
                ..CallInput::default()
            },
        )
        .expect_err("query controls must satisfy their catalog type");
    assert!(matches!(
        invalid,
        CloudflareError::InvalidQuerySelector { name, expected }
            if name == "queueRequest" && expected == "boolean"
    ));

    let request = builder
        .build(
            &capability,
            &CallInput {
                selectors,
                query: json!({"queueRequest":"true"}),
                ..CallInput::default()
            },
        )
        .expect("CLI string form of a declared boolean query should build");
    assert_eq!(request.url.query(), Some("queueRequest=true"));
}

fn query_selector(
    name: &str,
    value_type: &str,
    schema: Value,
    explode: bool,
    allow_empty_value: bool,
) -> SelectorV1 {
    SelectorV1 {
        name: name.to_owned(),
        location: "query".to_owned(),
        required: false,
        value_type: value_type.to_owned(),
        description: None,
        contract: Some(SelectorContractV1 {
            schema,
            query: Some(QuerySerializationV1 {
                style: "form".to_owned(),
                explode,
                allow_reserved: false,
                allow_empty_value,
            }),
        }),
    }
}

fn query_contract_capability() -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        "items-list",
        "List items",
        "GET",
        "/accounts/{account_id}/items",
    );
    capability.selectors = vec![
        SelectorV1 {
            name: "account_id".to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        },
        query_selector(
            "tags",
            "array",
            json!({
                    "type":"array",
                    "minItems":1,
                    "maxItems":2,
                    "uniqueItems":true,
                    "items":{"type":"string", "enum":["one","two"]}
            }),
            false,
            false,
        ),
        query_selector(
            "limit",
            "integer",
            json!({"type":"integer", "minimum":1, "maximum":10}),
            true,
            false,
        ),
        query_selector(
            "empty",
            "integer",
            json!({"type":"integer", "minimum":1}),
            true,
            true,
        ),
    ];
    capability
}

#[test]
fn request_builder_enforces_query_schema_and_exact_form_serialization() {
    let capability = query_contract_capability();
    let builder = RequestBuilder::new("https://api.cloudflare.com/client/v4").expect("builder");
    let request = builder
        .build(
            &capability,
            &CallInput {
                selectors: json!({"account_id":"account-1"}),
                query: json!({"tags":["one","two"], "limit":"5"}),
                ..CallInput::default()
            },
        )
        .expect("valid pinned query contract");
    assert_eq!(
        request.url.query_pairs().collect::<Vec<_>>(),
        vec![
            ("limit".into(), "5".into()),
            ("tags".into(), "one,two".into())
        ]
    );

    let invalid_enum = builder
        .build(
            &capability,
            &CallInput {
                selectors: json!({"account_id":"account-1"}),
                query: json!({"tags":["one","three"]}),
                ..CallInput::default()
            },
        )
        .expect_err("array items must satisfy their pinned enum");
    assert!(matches!(
        invalid_enum,
        CloudflareError::InvalidQuerySelectorSchema { name, .. } if name == "tags"
    ));

    let invalid_bound = builder
        .build(
            &capability,
            &CallInput {
                selectors: json!({"account_id":"account-1"}),
                query: json!({"limit":"11"}),
                ..CallInput::default()
            },
        )
        .expect_err("numeric query bounds must be enforced");
    assert!(matches!(
        invalid_bound,
        CloudflareError::InvalidQuerySelectorSchema { name, .. } if name == "limit"
    ));
}

#[test]
fn request_builder_preserves_allowed_empty_queries_and_rejects_unsupported_styles() {
    let capability = query_contract_capability();
    let builder = RequestBuilder::new("https://api.cloudflare.com/client/v4").expect("builder");
    let empty = builder
        .build(
            &capability,
            &CallInput {
                selectors: json!({"account_id":"account-1"}),
                query: json!({"empty":""}),
                ..CallInput::default()
            },
        )
        .expect("allowEmptyValue must preserve an explicit empty query control");
    assert_eq!(
        empty.url.query_pairs().collect::<Vec<_>>(),
        vec![("empty".into(), "".into())]
    );

    let mut unsupported = capability.clone();
    unsupported
        .selectors
        .iter_mut()
        .find(|selector| selector.name == "tags")
        .and_then(|selector| selector.contract.as_mut())
        .and_then(|contract| contract.query.as_mut())
        .expect("query contract")
        .style = "pipeDelimited".to_owned();
    let error = builder
        .build(
            &unsupported,
            &CallInput {
                selectors: json!({"account_id":"account-1"}),
                query: json!({"tags":["one","two"]}),
                ..CallInput::default()
            },
        )
        .expect_err("unsupported query styles must fail during contract preflight");
    assert!(matches!(
        error,
        CloudflareError::UnsupportedQuerySerialization { name, .. } if name == "tags"
    ));
}

#[test]
fn request_builder_rejects_nested_query_collections_before_rendering() {
    let mut nested = query_contract_capability();
    let builder = RequestBuilder::new("https://api.cloudflare.com/client/v4").expect("builder");
    nested.selectors.push(query_selector(
        "nested",
        "array",
        json!({"type":"array", "items":{"type":"array", "items":{"type":"string"}}}),
        false,
        false,
    ));
    let error = builder
        .build(
            &nested,
            &CallInput {
                selectors: json!({"account_id":"account-1"}),
                query: json!({"nested":[["one","two"]]}),
                ..CallInput::default()
            },
        )
        .expect_err("nested query collections cannot be represented as URL scalar controls");
    assert!(matches!(
        error,
        CloudflareError::InvalidQuerySelector { name, .. } if name == "nested"
    ));
}

#[test]
fn request_builder_sends_only_catalog_declared_header_selectors() {
    let mut capability = CapabilityV1::new(
        "r2-get-bucket",
        "Get R2 bucket",
        "GET",
        "/accounts/{account_id}/r2/buckets/{bucket_name}",
    );
    capability.selectors = vec![SelectorV1 {
        name: "cf-r2-jurisdiction".to_owned(),
        location: "header".to_owned(),
        required: false,
        value_type: "unknown".to_owned(),
        description: None,
        contract: None,
    }];
    let request = RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("valid base URL")
        .build(
            &capability,
            &CallInput {
                selectors: json!({
                    "account_id":"account-1",
                    "bucket_name":"bucket-1",
                    "cf-r2-jurisdiction":"eu"
                }),
                ..CallInput::default()
            },
        )
        .expect("declared header should build");

    assert_eq!(
        request
            .headers
            .get("cf-r2-jurisdiction")
            .and_then(|value| value.to_str().ok()),
        Some("eu")
    );
    let error = RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("valid base URL")
        .build(
            &capability,
            &CallInput {
                selectors: json!({
                    "account_id":"account-1",
                    "bucket_name":"bucket-1",
                    "cf-r2-jurisdiction":true
                }),
                ..CallInput::default()
            },
        )
        .expect_err("R2 jurisdiction must remain a string")
        .to_string();
    assert!(error.contains("cf-r2-jurisdiction"));
}

#[test]
fn request_builder_rejects_missing_required_or_reserved_header_selectors() {
    let mut capability = CapabilityV1::new("header-read", "Header read", "GET", "/header-read");
    capability.selectors = vec![SelectorV1 {
        name: "Tus-Resumable".to_owned(),
        location: "header".to_owned(),
        required: true,
        value_type: "string".to_owned(),
        description: None,
        contract: None,
    }];
    let builder = RequestBuilder::new("https://api.cloudflare.com/client/v4").expect("builder");
    let missing = builder
        .build(&capability, &CallInput::default())
        .expect_err("required header must fail closed");
    assert!(
        matches!(missing, CloudflareError::MissingHeaderSelector(name) if name == "Tus-Resumable")
    );

    capability.selectors[0].name = "Authorization".to_owned();
    let reserved = builder
        .build(
            &capability,
            &CallInput {
                selectors: json!({"Authorization":"must-not-be-forwarded"}),
                ..CallInput::default()
            },
        )
        .expect_err("auth headers must be reserved");
    assert!(
        matches!(reserved, CloudflareError::ReservedHeaderSelector(name) if name == "Authorization")
    );

    capability.selectors[0].name = "R2-Secret-Access-Key".to_owned();
    let reserved = builder
        .build(
            &capability,
            &CallInput {
                selectors: json!({"R2-Secret-Access-Key":"must-not-be-forwarded"}),
                ..CallInput::default()
            },
        )
        .expect_err("schema-declared service credentials must remain in governed auth storage");
    assert!(matches!(
        reserved,
        CloudflareError::ReservedHeaderSelector(name) if name == "R2-Secret-Access-Key"
    ));
}

#[test]
fn request_builder_rejects_undeclared_and_schema_invalid_selectors() {
    let mut capability = CapabilityV1::new(
        "version-get",
        "Get version",
        "GET",
        "/accounts/{account_id}/versions/{version}",
    );
    capability.selectors = vec![
        SelectorV1 {
            name: "account_id".to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: Some(SelectorContractV1 {
                schema: json!({"type":"string", "minLength":1}),
                query: None,
            }),
        },
        SelectorV1 {
            name: "version".to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "integer".to_owned(),
            description: None,
            contract: Some(SelectorContractV1 {
                schema: json!({"type":"integer", "minimum":1, "maximum":10}),
                query: None,
            }),
        },
        SelectorV1 {
            name: "X-Mode".to_owned(),
            location: "header".to_owned(),
            required: false,
            value_type: "string".to_owned(),
            description: None,
            contract: Some(SelectorContractV1 {
                schema: json!({"type":"string", "enum":["safe","strict"]}),
                query: None,
            }),
        },
    ];
    let builder = RequestBuilder::new("https://api.cloudflare.com/client/v4").expect("builder");

    let undeclared = builder
        .build(
            &capability,
            &CallInput {
                selectors: json!({"account_id":"a", "version":"1", "bypass":"true"}),
                ..CallInput::default()
            },
        )
        .expect_err("undeclared selectors must not be ignored");
    assert!(matches!(
        undeclared,
        CloudflareError::UndeclaredSelector(name) if name == "bypass"
    ));

    for (name, selectors) in [
        ("version", json!({"account_id":"a", "version":"11"})),
        (
            "X-Mode",
            json!({"account_id":"a", "version":"1", "X-Mode":"unsafe"}),
        ),
    ] {
        let error = builder
            .build(
                &capability,
                &CallInput {
                    selectors,
                    ..CallInput::default()
                },
            )
            .expect_err("selector must satisfy its pinned schema");
        assert!(matches!(
            error,
            CloudflareError::InvalidSelectorSchema { name: actual, .. } if actual == name
        ));
    }
}

#[test]
fn mutating_request_requires_a_consumable_approved_plan() {
    let capability = CapabilityV1::new(
        "dns-records-delete",
        "Delete DNS record",
        "DELETE",
        "/zones/{zone_id}/dns_records/{record_id}",
    );
    let result = RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("valid base URL")
        .build(
            &capability,
            &CallInput {
                selectors: json!({"zone_id":"z","record_id":"r"}),
                query: json!({}),
                body: None,
                ..CallInput::default()
            },
        );
    assert!(result.is_err());
}

#[test]
fn unchecked_request_validates_required_body_shape_from_pinned_schema() {
    let mut capability = CapabilityV1::new("record-create", "Create record", "POST", "/records");
    capability.request_schema = Some(json!({
        "type": "object",
        "required": ["name"],
        "properties": {"name": {"type": "string"}, "ttl": {"type": "integer"}},
        "x-cfctl-body-required": true
    }));
    let builder = RequestBuilder::new("https://api.cloudflare.com/client/v4").expect("builder");
    assert!(
        builder
            .build_unchecked(&capability, &CallInput::default())
            .is_err()
    );
    let wrong = CallInput {
        body: Some(json!({"name": "www", "ttl": "automatic"})),
        ..CallInput::default()
    };
    assert!(builder.build_unchecked(&capability, &wrong).is_err());
    let valid = CallInput {
        body: Some(json!({"name": "www", "ttl": 300})),
        ..CallInput::default()
    };
    assert!(builder.build_unchecked(&capability, &valid).is_ok());
}

#[test]
fn unchecked_request_closes_an_explicitly_empty_property_contract() {
    let mut capability = CapabilityV1::new("server-state", "Server state", "POST", "/state");
    capability.request_schema = Some(json!({
        "type": "object",
        "properties": {}
    }));
    let error = RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("builder")
        .build_unchecked(
            &capability,
            &CallInput {
                body: Some(json!({"server_id": "must-not-be-writable"})),
                ..CallInput::default()
            },
        )
        .expect_err("an empty pinned property set must not become an open object");

    assert!(matches!(
        error,
        CloudflareError::InvalidRequestBody(reason)
            if reason.contains("outside the pinned contract")
    ));
}

#[test]
fn unchecked_request_validates_nested_required_fields_and_enums() {
    let mut capability =
        CapabilityV1::new("d1-update", "Update D1 database", "PATCH", "/database/id");
    capability.request_schema = Some(json!({
        "type": "object",
        "properties": {
            "read_replication": {
                "type": "object",
                "required": ["mode"],
                "properties": {
                    "mode": {"type": "string", "enum": ["auto", "disabled"]}
                }
            }
        }
    }));
    let builder = RequestBuilder::new("https://api.cloudflare.com/client/v4").expect("builder");

    for body in [
        json!({"read_replication": {}}),
        json!({"read_replication": {"mode": "experimental"}}),
        json!({"read_replication": {"mode": "auto", "surprise": true}}),
    ] {
        let error = builder
            .build_unchecked(
                &capability,
                &CallInput {
                    body: Some(body),
                    ..CallInput::default()
                },
            )
            .expect_err("invalid nested body must fail before network execution");
        assert!(matches!(error, CloudflareError::InvalidRequestBody(_)));
    }

    for mode in ["auto", "disabled"] {
        let input = CallInput {
            body: Some(json!({"read_replication": {"mode": mode}})),
            ..CallInput::default()
        };
        assert!(builder.build_unchecked(&capability, &input).is_ok());
    }
}

#[test]
fn unchecked_request_validates_nested_array_item_enums() {
    let mut capability = CapabilityV1::new("route-update", "Update routes", "PATCH", "/routes");
    capability.request_schema = Some(json!({
        "type": "object",
        "properties": {
            "modes": {
                "type": "array",
                "items": {"type": "string", "enum": ["active", "passive"]}
            }
        }
    }));
    let builder = RequestBuilder::new("https://api.cloudflare.com/client/v4").expect("builder");
    let invalid = CallInput {
        body: Some(json!({"modes": ["active", "experimental"]})),
        ..CallInput::default()
    };
    assert!(builder.build_unchecked(&capability, &invalid).is_err());

    let valid = CallInput {
        body: Some(json!({"modes": ["active", "passive"]})),
        ..CallInput::default()
    };
    assert!(builder.build_unchecked(&capability, &valid).is_ok());
}

#[test]
fn unchecked_request_enforces_scalar_and_collection_bounds() {
    let mut capability = CapabilityV1::new("bounded-create", "Create", "POST", "/bounded");
    capability.request_schema = Some(json!({
        "type": "object",
        "minProperties": 5,
        "maxProperties": 5,
        "required": ["count", "ratio", "name", "items", "labels"],
        "properties": {
            "count": {"type": "integer", "minimum": 1, "maximum": 10},
            "ratio": {
                "type": "number",
                "minimum": 0,
                "exclusiveMinimum": true,
                "maximum": 1,
                "exclusiveMaximum": true
            },
            "name": {"type": "string", "minLength": 2, "maxLength": 4},
            "items": {
                "type": "array",
                "minItems": 1,
                "maxItems": 2,
                "uniqueItems": true,
                "items": {"type": "string"}
            },
            "labels": {
                "type": "object",
                "minProperties": 1,
                "maxProperties": 2,
                "additionalProperties": {"type": "string"}
            }
        }
    }));
    let builder = RequestBuilder::new("https://api.cloudflare.com/client/v4").expect("builder");
    let valid = CallInput {
        body: Some(json!({
            "count": 1,
            "ratio": 0.5,
            "name": "éß",
            "items": ["a", "b"],
            "labels": {"environment": "test"}
        })),
        ..CallInput::default()
    };
    assert!(builder.build_unchecked(&capability, &valid).is_ok());

    for body in [
        json!({"count": 0, "ratio": 0.5, "name": "ok", "items": ["a"], "labels": {"a":"b"}}),
        json!({"count": 11, "ratio": 0.5, "name": "ok", "items": ["a"], "labels": {"a":"b"}}),
        json!({"count": 1, "ratio": 0, "name": "ok", "items": ["a"], "labels": {"a":"b"}}),
        json!({"count": 1, "ratio": 1, "name": "ok", "items": ["a"], "labels": {"a":"b"}}),
        json!({"count": 1, "ratio": 0.5, "name": "x", "items": ["a"], "labels": {"a":"b"}}),
        json!({"count": 1, "ratio": 0.5, "name": "abcde", "items": ["a"], "labels": {"a":"b"}}),
        json!({"count": 1, "ratio": 0.5, "name": "ok", "items": [], "labels": {"a":"b"}}),
        json!({"count": 1, "ratio": 0.5, "name": "ok", "items": ["a", "b", "c"], "labels": {"a":"b"}}),
        json!({"count": 1, "ratio": 0.5, "name": "ok", "items": ["a", "a"], "labels": {"a":"b"}}),
        json!({"count": 1, "ratio": 0.5, "name": "ok", "items": ["a"], "labels": {}}),
        json!({"count": 1, "ratio": 0.5, "name": "ok", "items": ["a"], "labels": {"a":"b", "c":"d", "e":"f"}}),
        json!({"count": 1, "ratio": 0.5, "name": "ok", "items": ["a"], "labels": {"a":"b"}, "extra": true}),
    ] {
        let error = builder
            .build_unchecked(
                &capability,
                &CallInput {
                    body: Some(body),
                    ..CallInput::default()
                },
            )
            .expect_err("out-of-contract bounds must fail before request construction");
        assert!(matches!(error, CloudflareError::InvalidRequestBody(_)));
    }
}

#[test]
fn unchecked_request_enforces_exact_decimal_multiples() {
    let mut capability = CapabilityV1::new("multiple-create", "Create", "POST", "/multiple");
    capability.request_schema = Some(json!({
        "type": "object",
        "required": ["tenths", "cents", "whole"],
        "properties": {
            "tenths": {"type": "number", "multipleOf": 0.1},
            "cents": {"type": "number", "multipleOf": 0.01},
            "whole": {"type": "number", "multipleOf": 1}
        }
    }));
    let builder = RequestBuilder::new("https://api.cloudflare.com/client/v4").expect("builder");
    for body in [
        json!({"tenths": 0.3, "cents": 1.23, "whole": 3}),
        json!({"tenths": -1.2, "cents": 0, "whole": -4.0}),
        json!({"tenths": 1e20, "cents": 1e-2, "whole": 1e3}),
    ] {
        assert!(
            builder
                .build_unchecked(
                    &capability,
                    &CallInput {
                        body: Some(body),
                        ..CallInput::default()
                    }
                )
                .is_ok()
        );
    }

    for (field, value) in [
        ("tenths", json!(0.300_000_000_000_000_04)),
        ("cents", json!(1.234)),
        ("whole", json!(3.1)),
    ] {
        let mut body = json!({"tenths": 0.3, "cents": 1.23, "whole": 3});
        body[field] = value;
        let error = builder
            .build_unchecked(
                &capability,
                &CallInput {
                    body: Some(body),
                    ..CallInput::default()
                },
            )
            .expect_err("non-multiples must fail before request construction");
        assert!(matches!(
            error,
            CloudflareError::InvalidRequestBody(reason)
                if reason.contains("multipleOf") && !reason.contains("0.30000000000000004")
        ));
    }
}

#[test]
fn unchecked_request_rejects_invalid_multiple_contracts() {
    let builder = RequestBuilder::new("https://api.cloudflare.com/client/v4").expect("builder");
    for invalid_multiple in [json!(0), json!(-0.1), json!("0.1")] {
        let mut capability = CapabilityV1::new("multiple-create", "Create", "POST", "/multiple");
        capability.request_schema = Some(json!({
            "type": "number",
            "multipleOf": invalid_multiple
        }));
        let error = builder
            .build_unchecked(
                &capability,
                &CallInput {
                    body: Some(json!(1)),
                    ..CallInput::default()
                },
            )
            .expect_err("invalid multipleOf contracts must fail closed");
        assert!(matches!(error, CloudflareError::InvalidRequestBody(_)));
    }
}

#[test]
fn unchecked_request_enforces_executable_string_formats() {
    let mut capability = CapabilityV1::new("formatted-create", "Create", "POST", "/formatted");
    capability.request_schema = Some(json!({
        "type": "object",
        "required": ["timestamp", "hostname", "ipv4", "ipv6"],
        "properties": {
            "timestamp": {"type": "string", "format": "date-time"},
            "hostname": {"type": "string", "format": "hostname"},
            "ipv4": {"type": "string", "format": "ipv4"},
            "ipv6": {"type": "string", "format": "ipv6"}
        }
    }));
    let builder = RequestBuilder::new("https://api.cloudflare.com/client/v4").expect("builder");
    let valid = CallInput {
        body: Some(json!({
            "timestamp": "2026-07-15T03:45:00-05:00",
            "hostname": "service.example.com.",
            "ipv4": "192.0.2.1",
            "ipv6": "2001:db8::1"
        })),
        ..CallInput::default()
    };
    assert!(builder.build_unchecked(&capability, &valid).is_ok());
    let mut root_hostname = valid.clone();
    root_hostname.body.as_mut().expect("valid body")["hostname"] = json!(".");
    assert!(builder.build_unchecked(&capability, &root_hostname).is_ok());

    for (field, value) in [
        ("timestamp", "2026-07-15 03:45:00"),
        ("hostname", "_invalid.example.com"),
        ("ipv4", "999.0.2.1"),
        ("ipv6", "2001:db8::1::1"),
    ] {
        let mut body = valid.body.clone().expect("valid body");
        body[field] = json!(value);
        let error = builder
            .build_unchecked(
                &capability,
                &CallInput {
                    body: Some(body),
                    ..CallInput::default()
                },
            )
            .expect_err("invalid executable formats must fail before request construction");
        assert!(matches!(
            error,
            CloudflareError::InvalidRequestBody(reason)
                if reason.contains("pinned") && !reason.contains(value)
        ));
    }
}

#[test]
fn unchecked_request_treats_equivalent_json_numbers_as_duplicate_items() {
    let mut capability = CapabilityV1::new("unique-create", "Create", "POST", "/unique");
    capability.request_schema = Some(json!({
        "type": "array",
        "uniqueItems": true
    }));
    let error = RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("builder")
        .build_unchecked(
            &capability,
            &CallInput {
                body: Some(json!([1, 1.0])),
                ..CallInput::default()
            },
        )
        .expect_err("mathematically equal JSON numbers are duplicate items");
    assert!(matches!(error, CloudflareError::InvalidRequestBody(_)));
}

#[test]
fn unchecked_request_bounds_unique_item_fingerprint_depth() {
    let mut capability = CapabilityV1::new("unique-create", "Create", "POST", "/unique");
    capability.request_schema = Some(json!({
        "type": "array",
        "uniqueItems": true
    }));
    let mut nested = json!(null);
    for _ in 0..65 {
        nested = json!([nested]);
    }
    let result = RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("builder")
        .build_unchecked(
            &capability,
            &CallInput {
                body: Some(json!([nested])),
                ..CallInput::default()
            },
        );
    let Err(error) = result else {
        panic!("uniqueItems fingerprinting must honor the schema depth ceiling");
    };
    assert!(matches!(
        error,
        CloudflareError::InvalidRequestBody(reason)
            if reason == "pinned schema exceeds the validation depth limit"
    ));
}

#[test]
fn unchecked_request_bounds_unique_item_fingerprint_work() {
    let mut capability = CapabilityV1::new("unique-create", "Create", "POST", "/unique");
    capability.request_schema = Some(json!({
        "type": "array",
        "uniqueItems": true
    }));
    let nested = Value::Array((0..65_535).map(|_| json!("item")).collect());
    let result = RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("builder")
        .build_unchecked(
            &capability,
            &CallInput {
                body: Some(json!([nested])),
                ..CallInput::default()
            },
        );
    let Err(error) = result else {
        panic!("uniqueItems fingerprinting must honor the validation work limit");
    };
    assert!(matches!(
        error,
        CloudflareError::InvalidRequestBody(reason)
            if reason == "request body exceeds the pinned validation work limit"
    ));
}

#[test]
fn unchecked_request_enforces_composed_request_schemas() {
    let capability = composed_request_capability();
    let builder = RequestBuilder::new("https://api.cloudflare.com/client/v4").expect("builder");

    for resources in [
        json!({"com.cloudflare.api.account.a": "*"}),
        json!({"com.cloudflare.api.account.a": {"com.cloudflare.api.zone.z": "*"}}),
    ] {
        let input = CallInput {
            selectors: json!({"account_id": "a"}),
            body: Some(json!({
                "resources": resources,
                "settings": {"mode": "on", "enabled": true},
                "signal": "automatic",
                "placement": {"scope": "account", "before": "rule-a"}
            })),
            ..CallInput::default()
        };
        assert!(builder.build_unchecked(&capability, &input).is_ok());
    }

    assert_invalid_composed_bodies(&builder, &capability);
}

fn composed_request_capability() -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        "token-create",
        "Create token",
        "POST",
        "/accounts/{account_id}/tokens",
    );
    capability.request_schema = Some(json!({
        "type": "object",
        "required": ["resources", "settings"],
        "properties": {
            "resources": {
                "oneOf": [
                    {"type": "object", "additionalProperties": {"type": "string"}},
                    {
                        "type": "object",
                        "additionalProperties": {
                            "type": "object",
                            "additionalProperties": {"type": "string"}
                        }
                    }
                ]
            },
            "settings": {
                "allOf": [
                    {
                        "type": "object",
                        "required": ["mode"],
                        "properties": {"mode": {"type": "string", "enum": ["on", "off"]}}
                    },
                    {
                        "type": "object",
                        "required": ["enabled"],
                        "properties": {"enabled": {"type": "boolean"}}
                    }
                ]
            },
            "signal": {
                "anyOf": [
                    {"type": "string", "enum": ["automatic"]},
                    {"type": "integer"}
                ]
            },
            "placement": {
                "type": "object",
                "required": ["scope"],
                "properties": {"scope": {"type": "string"}},
                "oneOf": [
                    {
                        "type": "object",
                        "required": ["before"],
                        "properties": {"before": {"type": "string"}}
                    },
                    {
                        "type": "object",
                        "required": ["after"],
                        "properties": {"after": {"type": "string"}}
                    }
                ]
            }
        }
    }));
    capability
}

fn assert_invalid_composed_bodies(builder: &RequestBuilder, capability: &CapabilityV1) {
    for body in [
        json!({
            "resources": {},
            "settings": {"mode": "on", "enabled": true}
        }),
        json!({
            "resources": {"com.cloudflare.api.account.a": 7},
            "settings": {"mode": "on", "enabled": true}
        }),
        json!({
            "resources": {"com.cloudflare.api.account.a": "*"},
            "settings": {"mode": "on"}
        }),
        json!({
            "resources": {"com.cloudflare.api.account.a": "*"},
            "settings": {"mode": "on", "enabled": true, "surprise": true}
        }),
        json!({
            "resources": {"com.cloudflare.api.account.a": "*"},
            "settings": {"mode": "on", "enabled": true},
            "signal": false
        }),
        json!({
            "resources": {"com.cloudflare.api.account.a": "*"},
            "settings": {"mode": "on", "enabled": true},
            "placement": {
                "scope": "account",
                "before": "rule-a",
                "after": "rule-b"
            }
        }),
        json!({
            "resources": {"com.cloudflare.api.account.a": "*"},
            "settings": {"mode": "on", "enabled": true},
            "placement": {"scope": "account", "before": "rule-a", "unknown": true}
        }),
    ] {
        let error = builder
            .build_unchecked(
                capability,
                &CallInput {
                    selectors: json!({"account_id": "a"}),
                    body: Some(body),
                    ..CallInput::default()
                },
            )
            .expect_err("invalid composed body must fail before network execution");
        assert!(matches!(error, CloudflareError::InvalidRequestBody(_)));
    }
}

#[test]
fn unchecked_request_honors_explicit_additional_property_denial_in_all_of() {
    let mut capability = CapabilityV1::new("strict-create", "Create", "POST", "/strict");
    capability.request_schema = Some(json!({
        "allOf": [
            {
                "type": "object",
                "properties": {"known": {"type": "string"}},
                "additionalProperties": false
            },
            {
                "type": "object",
                "properties": {"sibling": {"type": "string"}}
            }
        ]
    }));
    let error = RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("builder")
        .build_unchecked(
            &capability,
            &CallInput {
                body: Some(json!({"known": "yes", "sibling": "still disallowed"})),
                ..CallInput::default()
            },
        )
        .expect_err("explicit additionalProperties false must override inferred sibling fields");
    assert!(matches!(error, CloudflareError::InvalidRequestBody(_)));
}

#[test]
fn unchecked_request_bounds_schema_validation_work() {
    let mut capability = CapabilityV1::new("bulk-create", "Create", "POST", "/bulk");
    capability.request_schema = Some(json!({
        "type": "array",
        "items": {"type": "string"}
    }));
    let error = RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("builder")
        .build_unchecked(
            &capability,
            &CallInput {
                body: Some(Value::Array((0..65_536).map(|_| json!("item")).collect())),
                ..CallInput::default()
            },
        )
        .expect_err("unbounded request validation must fail closed");
    assert!(matches!(
        error,
        CloudflareError::InvalidRequestBody(reason)
            if reason == "request body exceeds the pinned validation work limit"
    ));
}

#[test]
fn unchecked_request_never_treats_one_of_budget_exhaustion_as_a_mismatch() {
    let mut capability = CapabilityV1::new("ambiguous-create", "Create", "POST", "/ambiguous");
    capability.request_schema = Some(json!({
        "oneOf": [
            {"type": "array", "items": {"type": "string"}},
            {"type": "array", "items": {"type": "string"}}
        ]
    }));
    let result = RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("builder")
        .build_unchecked(
            &capability,
            &CallInput {
                body: Some(Value::Array((0..65_533).map(|_| json!("item")).collect())),
                ..CallInput::default()
            },
        );
    let Err(error) = result else {
        panic!("an unevaluated oneOf branch must never authorize a request");
    };
    assert!(matches!(
        error,
        CloudflareError::InvalidRequestBody(reason)
            if reason == "request body exceeds the pinned validation work limit"
    ));
}

#[tokio::test]
async fn executor_retries_rate_limits_and_applies_only_the_selected_credential() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let mut requests = Vec::new();
        for attempt in 0..2 {
            let (mut stream, _) = listener.accept().await.expect("accept request");
            let mut buffer = vec![0_u8; 8192];
            let read = stream.read(&mut buffer).await.expect("read request");
            requests.push(String::from_utf8_lossy(&buffer[..read]).to_string());
            let (status, body) = if attempt == 0 {
                (
                    "429 Too Many Requests",
                    r#"{"success":false,"errors":[{"code":10000,"message":"retry"}]}"#,
                )
            } else {
                (
                    "200 OK",
                    r#"{"success":true,"result":[{"id":"zone-1"}],"errors":[]}"#,
                )
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nRetry-After: 0\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write response");
        }
        requests
    });
    let capability = CapabilityV1::new("zones-list", "List zones", "GET", "/zones");
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");
    let response = executor
        .execute_read(
            &capability,
            &CallInput::default(),
            &AuthCredential::Bearer {
                token: "selected-token".to_owned(),
            },
        )
        .await
        .expect("eventual response");
    assert!(response.success);
    let requests = server.await.expect("fake server joins");
    assert_eq!(requests.len(), 2);
    assert!(
        requests
            .iter()
            .all(|request| request.contains("authorization: Bearer selected-token"))
    );
    assert!(
        requests
            .iter()
            .all(|request| !request.contains("x-auth-key"))
    );
}

#[tokio::test]
async fn executor_enforces_pinned_json_response_contract_without_echoing_bodies() {
    let mut capability = CapabilityV1::new("zones-list", "List zones", "GET", "/zones");
    capability.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".to_owned()],
        success_media_types: vec!["application/json".to_owned()],
        body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
    });
    let credential = AuthCredential::Bearer {
        token: "selected-token".to_owned(),
    };

    let (address, server) = single_raw_response_server(
        "200 OK",
        "text/plain",
        r#"{"success":true,"result":{"private":"media-marker"}}"#,
    )
    .await;
    let error = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .execute_read(&capability, &CallInput::default(), &credential)
    .await
    .expect_err("unexpected success media must fail closed");
    assert!(matches!(
        error,
        CloudflareError::UnexpectedResponseMediaType { status: 200, .. }
    ));
    assert!(!error.to_string().contains("media-marker"));
    server.await.expect("server joins");

    let (address, server) = single_raw_response_server(
        "200 OK",
        "application/json; charset=utf-8",
        r#"{"result":{"private":"envelope-marker"}}"#,
    )
    .await;
    let error = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .execute_read(&capability, &CallInput::default(), &credential)
    .await
    .expect_err("a JSON object without the pinned envelope must fail closed");
    assert!(matches!(
        error,
        CloudflareError::InvalidResponseEnvelope { status: 200 }
    ));
    assert!(!error.to_string().contains("envelope-marker"));
    server.await.expect("server joins");

    let (address, server) = single_raw_response_server(
        "200 OK",
        "application/json; charset=utf-8",
        r#"{"success":true,"result":[{"id":"zone-1"}],"errors":[]}"#,
    )
    .await;
    let response = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .execute_read(&capability, &CallInput::default(), &credential)
    .await
    .expect("the pinned JSON envelope should be accepted");
    assert!(response.success);
    server.await.expect("server joins");
}

#[tokio::test]
async fn executor_enforces_pinned_empty_responses_and_success_statuses() {
    let mut capability = CapabilityV1::new("empty-read", "Empty read", "GET", "/empty");
    capability.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".to_owned()],
        success_media_types: Vec::new(),
        body_mode: ResponseBodyModeV1::Empty,
    });
    let credential = AuthCredential::Bearer {
        token: "selected-token".to_owned(),
    };

    let (address, server) = single_raw_response_server("200 OK", "text/plain", "").await;
    let response = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .execute_read(&capability, &CallInput::default(), &credential)
    .await
    .expect("the pinned empty response should be accepted");
    assert!(response.success);
    assert_eq!(response.status, 200);
    assert_eq!(response.result, Value::Null);
    server.await.expect("server joins");

    let mut status_class_capability = capability.clone();
    status_class_capability
        .response_contract
        .as_mut()
        .expect("response contract")
        .success_statuses = vec!["2XX".to_owned()];
    let (address, server) = single_raw_response_server("202 Accepted", "text/plain", "").await;
    let response = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .execute_read(&status_class_capability, &CallInput::default(), &credential)
    .await
    .expect("the pinned OpenAPI status class should be accepted");
    assert_eq!(response.status, 202);
    server.await.expect("server joins");

    let (address, server) =
        single_raw_response_server("200 OK", "text/plain", "private-body-marker").await;
    let error = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .execute_read(&capability, &CallInput::default(), &credential)
    .await
    .expect_err("a body must violate the pinned empty response");
    assert!(matches!(
        error,
        CloudflareError::UnexpectedResponseBody {
            status: 200,
            received_bytes: 19
        }
    ));
    assert!(!error.to_string().contains("private-body-marker"));
    server.await.expect("server joins");

    let (address, server) = single_raw_response_server("201 Created", "text/plain", "").await;
    let error = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .execute_read(&capability, &CallInput::default(), &credential)
    .await
    .expect_err("an undeclared success status must fail closed");
    assert!(matches!(
        error,
        CloudflareError::UnexpectedSuccessStatus { status: 201, .. }
    ));
    server.await.expect("server joins");
}

#[test]
fn request_builder_rejects_an_unsupported_pinned_response_contract() {
    let mut capability = CapabilityV1::new("object-read", "Read object", "GET", "/object");
    capability.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".to_owned()],
        success_media_types: vec!["application/octet-stream".to_owned()],
        body_mode: ResponseBodyModeV1::Unsupported,
    });
    let error = RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("builder")
        .build(&capability, &CallInput::default())
        .expect_err("unsupported response contracts must fail before authentication");
    assert!(matches!(
        error,
        CloudflareError::UnsupportedResponseContract(media)
            if media == "application/octet-stream"
    ));
}

#[tokio::test]
async fn executor_refuses_a_plan_that_was_not_durably_marked_consumed() {
    let capability = CapabilityV1::new("zones-delete", "Delete zone", "DELETE", "/zones/{zone_id}");
    let mut plan = PlanV1::draft(
        "profile",
        "account",
        "sha256:catalog",
        capability,
        json!({"zone_id":"zone"}),
    )
    .expect("draft plan");
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"zone_id":"zone"}),
        query: json!({}),
        body: None,
        ..CallInput::default()
    })
    .expect("input");
    plan.refresh_hash().expect("refresh hash");
    plan.approve(true, None).expect("approve");
    let executor = Executor::new(reqwest::Client::new(), "http://127.0.0.1:9").expect("executor");
    let error = executor
        .execute_consumed_plan(
            &mut plan,
            "sha256:catalog",
            &AuthCredential::Bearer {
                token: "token".to_owned(),
            },
        )
        .await
        .expect_err("unconsumed plan must fail before network");
    assert!(
        error
            .to_string()
            .contains("durably persisted consumed plan")
    );
}

#[tokio::test]
async fn executor_rejects_a_grafted_verifier_before_the_mutation_boundary() {
    let mut capability = CapabilityV1::new(
        "widgets-create",
        "Create widget",
        "POST",
        "/accounts/{account_id}/widgets",
    );
    capability.verification.strategy =
        "api_token_details_match_created_id_and_active_status".to_owned();
    let mut plan = PlanV1::draft(
        "profile",
        "account",
        "sha256:catalog",
        capability,
        json!({}),
    )
    .expect("draft plan");
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account"}),
        query: json!({}),
        body: Some(json!({"name":"test"})),
        ..CallInput::default()
    })
    .expect("input");
    plan.refresh_hash().expect("refresh hash");
    plan.approve(true, None).expect("approve");
    plan.mark_consumed().expect("consume");
    let executor = Executor::new(reqwest::Client::new(), "http://127.0.0.1:9").expect("executor");

    let error = executor
        .execute_consumed_plan(
            &mut plan,
            "sha256:catalog",
            &AuthCredential::Bearer {
                token: "token".to_owned(),
            },
        )
        .await
        .expect_err("unsupported verifier must fail before network");

    assert!(matches!(
        error,
        CloudflareError::UnsupportedVerificationStrategy(strategy)
            if strategy == "api_token_details_match_created_id_and_active_status"
    ));
}

#[tokio::test]
async fn executor_collects_all_cloudflare_result_pages() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let mut requests = Vec::new();
        for page in 1..=2 {
            let (mut stream, _) = listener.accept().await.expect("accept request");
            let mut buffer = vec![0_u8; 8192];
            let read = stream.read(&mut buffer).await.expect("read request");
            requests.push(String::from_utf8_lossy(&buffer[..read]).to_string());
            let body = format!(
                r#"{{"success":true,"result":[{{"id":"zone-{page}"}}],"errors":[],"result_info":{{"page":{page},"total_pages":2,"total_count":2}}}}"#
            );
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nETag: page-{page}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write response");
        }
        requests
    });
    let capability = CapabilityV1::new("zones-list", "List zones", "GET", "/zones");
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");
    let response = executor
        .execute_read(
            &capability,
            &CallInput::default(),
            &AuthCredential::Bearer {
                token: "token".to_owned(),
            },
        )
        .await
        .expect("paginated response");
    assert_eq!(response.result.as_array().expect("result array").len(), 2);
    assert_eq!(response.etag.as_deref(), Some("page-2"));
    let requests = server.await.expect("server joins");
    assert_eq!(requests.len(), 2);
    assert!(requests[1].contains("page=2"));
}

#[tokio::test]
async fn consumed_mutation_carries_plan_id_as_idempotency_key() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept request");
        let mut buffer = vec![0_u8; 8192];
        let read = stream.read(&mut buffer).await.expect("read request");
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let body = r#"{"success":true,"result":{"id":"record-1"},"errors":[]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCF-Ray: test-ray\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write response");
        request
    });
    let mut capability =
        CapabilityV1::new("zone-delete", "Delete zone", "DELETE", "/zones/{zone_id}");
    capability.verification.strategy = "same_resource_returns_not_found_after_delete".to_owned();
    capability.same_path_read = Some(SamePathReadContractV1 {
        path: "/zones/{zone_id}".to_owned(),
        read_capability_id: "zone-get".to_owned(),
        verified_response_fields: Vec::new(),
    });
    let mut plan = PlanV1::draft(
        "profile",
        "account",
        "sha256:catalog",
        capability,
        json!({}),
    )
    .expect("draft plan");
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"zone_id":"zone-1"}),
        query: json!({}),
        body: None,
        ..CallInput::default()
    })
    .expect("serialize input");
    plan.refresh_hash().expect("refresh hash");
    plan.approve(true, None).expect("approve");
    plan.mark_consumed().expect("consume");
    let operation_id = plan.operation_id.clone();
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");
    let response = executor
        .execute_consumed_plan(
            &mut plan,
            "sha256:catalog",
            &AuthCredential::Bearer {
                token: "token".to_owned(),
            },
        )
        .await
        .expect("mutation response");
    assert_eq!(response.cf_ray.as_deref(), Some("test-ray"));
    let request = server.await.expect("server joins");
    assert!(request.contains(&format!("idempotency-key: {operation_id}")));
}

#[tokio::test]
async fn account_token_creation_is_verified_by_id_and_active_readback() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let read = stream.read(&mut buffer).await.expect("read verification");
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let body = r#"{"success":true,"result":{"id":"token-1","status":"active"},"errors":[]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
        request
    });
    let plan = token_plan(
        "account-api-tokens-create-token",
        "POST",
        "/accounts/{account_id}/tokens",
        "api_token_details_match_created_id_and_active_status",
        json!({"account_id":"account-1"}),
    );
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"token-1","status":"active","value":"one-time-secret"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");
    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed);
    assert!(verification.basis.contains("token-1"));
    let request = server.await.expect("server joins");
    assert!(
        request.starts_with("GET /client/v4/accounts/account-1/tokens/token-1 "),
        "{request}"
    );
    assert!(request.contains("authorization: Bearer governing-token"));
}

#[tokio::test]
async fn account_token_revocation_is_verified_by_not_found_readback() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let read = stream.read(&mut buffer).await.expect("read verification");
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let body =
            r#"{"success":false,"result":null,"errors":[{"code":1001,"message":"not found"}]}"#;
        let response = format!(
            "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
        request
    });
    let plan = token_plan(
        "account-api-tokens-delete-token",
        "DELETE",
        "/accounts/{account_id}/tokens/{token_id}",
        "api_token_details_returns_not_found_after_revoke",
        json!({"account_id":"account-1", "token_id":"token-1"}),
    );
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"token-1"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed);
    let request = server.await.expect("server joins");
    assert!(
        request.starts_with("GET /client/v4/accounts/account-1/tokens/token-1 "),
        "{request}"
    );
}

#[tokio::test]
async fn dns_record_creation_is_verified_by_created_id_and_planned_fields() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let read = stream.read(&mut buffer).await.expect("read verification");
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let body = r#"{"success":true,"result":{"id":"record-1","type":"A","name":"www.example.com","content":"192.0.2.1","ttl":300},"errors":[]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
        request
    });
    let planned_fields = json!({
        "type":"A",
        "name":"www.example.com",
        "content":"192.0.2.1",
        "ttl":300
    });
    let plan = dns_record_plan(
        "dns-records-for-a-zone-create-dns-record",
        "POST",
        "/zones/{zone_id}/dns_records",
        "dns_record_details_match_created_id_and_planned_fields",
        json!({"zone_id":"zone-1"}),
        Some(planned_fields.clone()),
    );
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"record-1", "type":"A", "name":"www.example.com", "content":"192.0.2.1", "ttl":300}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed, "{}", verification.basis);
    let request = server.await.expect("server joins");
    assert!(
        request.starts_with("GET /client/v4/zones/zone-1/dns_records/record-1 "),
        "{request}"
    );
}

#[tokio::test]
async fn dns_record_deletion_is_verified_by_not_found_readback() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let read = stream.read(&mut buffer).await.expect("read verification");
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let body =
            r#"{"success":false,"result":null,"errors":[{"code":81044,"message":"not found"}]}"#;
        let response = format!(
            "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
        request
    });
    let plan = dns_record_plan(
        "dns-records-for-a-zone-delete-dns-record",
        "DELETE",
        "/zones/{zone_id}/dns_records/{dns_record_id}",
        "dns_record_details_returns_not_found_after_delete",
        json!({"zone_id":"zone-1", "dns_record_id":"record-1"}),
        None,
    );
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"record-1"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed, "{}", verification.basis);
    let request = server.await.expect("server joins");
    assert!(
        request.starts_with("GET /client/v4/zones/zone-1/dns_records/record-1 "),
        "{request}"
    );
}

#[tokio::test]
async fn exact_resource_deletion_is_verified_by_same_path_not_found_readback() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let read = stream.read(&mut buffer).await.expect("read verification");
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let body =
            r#"{"success":false,"result":null,"errors":[{"code":1001,"message":"not found"}]}"#;
        let response = format!(
            "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
        request
    });
    let mut plan = dns_record_plan(
        "widgets-delete",
        "DELETE",
        "/accounts/{account_id}/widgets/{widget_id}",
        "same_resource_returns_not_found_after_delete",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        None,
    );
    plan.capability.product = "R2 Bucket".to_owned();
    plan.capability.selectors.push(SelectorV1 {
        name: "cf-r2-jurisdiction".to_owned(),
        location: "header".to_owned(),
        required: false,
        value_type: "string".to_owned(),
        description: None,
        contract: None,
    });
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({
            "account_id":"account-1",
            "widget_id":"widget-1",
            "cf-r2-jurisdiction":"eu"
        }),
        query: json!({}),
        body: None,
        if_match: Some("mutation-only-etag".to_owned()),
        ..CallInput::default()
    })
    .expect("input");
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"widget-1"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed, "{}", verification.basis);
    let request = server.await.expect("server joins");
    assert!(
        request.starts_with("GET /client/v4/accounts/account-1/widgets/widget-1 "),
        "{request}"
    );
    assert!(!request.contains("mutation-only"));
    assert!(request.contains("cf-r2-jurisdiction: eu\r\n"));
}

#[tokio::test]
async fn exact_resource_deletion_rejects_a_still_present_readback_without_echoing_values() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let _ = stream.read(&mut buffer).await.expect("read verification");
        let body = r#"{"success":true,"result":{"id":"secret-widget-id"},"errors":[]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
    });
    let plan = dns_record_plan(
        "widgets-delete",
        "DELETE",
        "/accounts/{account_id}/widgets/{widget_id}",
        "same_resource_returns_not_found_after_delete",
        json!({"account_id":"account-1", "widget_id":"secret-widget-id"}),
        None,
    );
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"secret-widget-id"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(!verification.passed);
    assert!(verification.basis.contains("readback HTTP 200"));
    assert!(!verification.basis.contains("secret-widget-id"));
    server.await.expect("server joins");
}

#[tokio::test]
async fn exact_resource_deletion_is_verified_by_complete_parent_collection_absence() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let mut requests = Vec::new();
        for page in 1..=2 {
            let (mut stream, _) = listener.accept().await.expect("accept verification");
            let mut buffer = vec![0_u8; 8192];
            let read = stream.read(&mut buffer).await.expect("read verification");
            requests.push(String::from_utf8_lossy(&buffer[..read]).to_string());
            let body = if page == 1 {
                r#"{"success":true,"result":[{"id":"widget-2"}],"result_info":{"page":1,"total_pages":2}}"#
            } else {
                r#"{"success":true,"result":[{"id":"widget-3"}],"result_info":{"page":2,"total_pages":2}}"#
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write verification");
        }
        requests
    });
    let mut plan = dns_record_plan(
        "widgets-delete",
        "DELETE",
        "/accounts/{account_id}/widgets/{widget_id}",
        "parent_collection_omits_deleted_resource_id",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        None,
    );
    plan.capability.deleted_resource = Some(DeletedResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        requires_page_number_completion: true,
    });
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"widget-1"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed, "{}", verification.basis);
    let requests = server.await.expect("server joins");
    assert!(requests[0].starts_with("GET /client/v4/accounts/account-1/widgets "));
    assert!(requests[1].starts_with("GET /client/v4/accounts/account-1/widgets?page=2 "));
    assert!(requests.iter().all(|request| !request.contains("widget-1")));
}

#[tokio::test]
async fn parent_collection_deletion_uses_the_hash_bound_selector_identity_pointer() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let read = stream.read(&mut buffer).await.expect("read verification");
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let body = r#"{"success":true,"result":[{"slug":"other-widget"}]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
        request
    });
    let mut plan = dns_record_plan(
        "widgets-delete",
        "DELETE",
        "/accounts/{account_id}/widgets/{slug}",
        "parent_collection_omits_deleted_resource_id",
        json!({"account_id":"account-1", "slug":"target-widget"}),
        None,
    );
    plan.capability.deleted_resource = Some(DeletedResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "slug".to_owned(),
        response_item_identity_pointer: "/slug".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        requires_page_number_completion: false,
    });
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed, "{}", verification.basis);
    let request = server.await.expect("server joins");
    assert!(request.starts_with("GET /client/v4/accounts/account-1/widgets "));
    assert!(!request.contains("target-widget"));
}

#[tokio::test]
async fn paginated_parent_collection_verification_requires_live_completion_metadata() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let _ = stream.read(&mut buffer).await.expect("read verification");
        let body = r#"{"success":true,"result":[{"id":"widget-2"}]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
    });
    let mut plan = dns_record_plan(
        "widgets-delete",
        "DELETE",
        "/accounts/{account_id}/widgets/{widget_id}",
        "parent_collection_omits_deleted_resource_id",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        None,
    );
    plan.capability.deleted_resource = Some(DeletedResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        requires_page_number_completion: true,
    });
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"widget-1"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(!verification.passed);
    assert!(verification.basis.contains("pagination complete=false"));
    assert!(verification.basis.contains("deleted identity absent=true"));
    server.await.expect("server joins");
}

#[tokio::test]
async fn parent_collection_verifier_rejects_a_present_deleted_identity_without_echoing_it() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let _ = stream.read(&mut buffer).await.expect("read verification");
        let body = r#"{"success":true,"result":[{"id":"secret-widget-id"}]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
    });
    let mut plan = dns_record_plan(
        "widgets-delete",
        "DELETE",
        "/accounts/{account_id}/widgets/{widget_id}",
        "parent_collection_omits_deleted_resource_id",
        json!({"account_id":"account-1", "widget_id":"secret-widget-id"}),
        None,
    );
    plan.capability.deleted_resource = Some(DeletedResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        requires_page_number_completion: false,
    });
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"secret-widget-id"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(!verification.passed);
    assert!(verification.basis.contains("deleted identity absent=false"));
    assert!(!verification.basis.contains("secret-widget-id"));
    server.await.expect("server joins");
}

#[tokio::test]
async fn exact_resource_update_is_verified_by_complete_parent_collection_fields() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let mut requests = Vec::new();
        for page in 1..=2 {
            let (mut stream, _) = listener.accept().await.expect("accept verification");
            let mut buffer = vec![0_u8; 8192];
            let read = stream.read(&mut buffer).await.expect("read verification");
            requests.push(String::from_utf8_lossy(&buffer[..read]).to_string());
            let body = if page == 1 {
                r#"{"success":true,"result":[{"id":"widget-2","name":"other","enabled":false}],"result_info":{"page":1,"total_pages":2}}"#
            } else {
                r#"{"success":true,"result":[{"id":"widget-1","name":"after","enabled":true}],"result_info":{"page":2,"total_pages":2}}"#
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write verification");
        }
        requests
    });
    let mut plan = dns_record_plan(
        "widgets-update",
        "PATCH",
        "/accounts/{account_id}/widgets/{widget_id}",
        "parent_collection_item_contains_planned_fields_after_update",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        Some(json!({"name":"after", "enabled":true})),
    );
    plan.capability.updated_resource = Some(UpdatedResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        verified_response_fields: vec!["enabled".to_owned(), "name".to_owned()],
        requires_page_number_completion: true,
    });
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed, "{}", verification.basis);
    let requests = server.await.expect("server joins");
    assert!(requests[0].starts_with("GET /client/v4/accounts/account-1/widgets "));
    assert!(requests[1].starts_with("GET /client/v4/accounts/account-1/widgets?page=2 "));
    assert!(requests.iter().all(|request| !request.contains("widget-1")));
}

#[tokio::test]
async fn parent_collection_update_rejects_field_drift_without_echoing_values() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let _ = stream.read(&mut buffer).await.expect("read verification");
        let body =
            r#"{"success":true,"result":[{"id":"widget-1","name":"unexpected-live-value"}]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
    });
    let mut plan = dns_record_plan(
        "widgets-update",
        "PATCH",
        "/accounts/{account_id}/widgets/{widget_id}",
        "parent_collection_item_contains_planned_fields_after_update",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        Some(json!({"name":"planned-secret-like-value"})),
    );
    plan.capability.updated_resource = Some(UpdatedResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
        requires_page_number_completion: false,
    });
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(!verification.passed);
    assert!(verification.basis.contains("planned fields match=false"));
    assert!(!verification.basis.contains("planned-secret-like-value"));
    assert!(!verification.basis.contains("unexpected-live-value"));
    server.await.expect("server joins");
}

#[tokio::test]
async fn parent_collection_update_rejects_unbound_fields_before_the_mutation_boundary() {
    let mut plan = dns_record_plan(
        "widgets-update",
        "PATCH",
        "/accounts/{account_id}/widgets/{widget_id}",
        "parent_collection_item_contains_planned_fields_after_update",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        Some(json!({"name":"planned"})),
    );
    plan.capability.updated_resource = Some(UpdatedResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
        requires_page_number_completion: false,
    });
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-1", "widget_id":"widget-1"}),
        query: json!({}),
        body: Some(json!({"name":"planned", "hidden":true})),
        ..CallInput::default()
    })
    .expect("input");
    plan.status = PlanStatus::Consumed;
    let input: CallInput = serde_json::from_value(plan.input.clone()).expect("input");
    let catalog_hash = plan.catalog_hash.clone();
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .execute_consumed_plan_with_input(
            &mut plan,
            &catalog_hash,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
            &input,
        )
        .await
        .expect_err("unbound field must fail before network execution")
        .to_string();

    assert!(error.contains("outside the hash-bound collection readback fields"));
    assert_eq!(plan.status, PlanStatus::Consumed);
}

#[tokio::test]
async fn parent_collection_update_rejects_query_controls_before_the_mutation_boundary() {
    let mut plan = dns_record_plan(
        "widgets-update",
        "PATCH",
        "/accounts/{account_id}/widgets/{widget_id}",
        "parent_collection_item_contains_planned_fields_after_update",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        Some(json!({"name":"planned"})),
    );
    plan.capability.updated_resource = Some(UpdatedResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
        requires_page_number_completion: false,
    });
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-1", "widget_id":"widget-1"}),
        query: json!({"mode":"must-not-cross-boundary"}),
        body: Some(json!({"name":"planned"})),
        ..CallInput::default()
    })
    .expect("input");
    plan.status = PlanStatus::Consumed;
    let input: CallInput = serde_json::from_value(plan.input.clone()).expect("input");
    let catalog_hash = plan.catalog_hash.clone();
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .execute_consumed_plan_with_input(
            &mut plan,
            &catalog_hash,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
            &input,
        )
        .await
        .expect_err("query controls must fail before network execution")
        .to_string();

    assert!(error.contains("query controls outside the hash-bound collection readback contract"));
    assert!(!error.contains("must-not-cross-boundary"));
    assert_eq!(plan.status, PlanStatus::Consumed);
}

#[tokio::test]
async fn parent_collection_delete_rejects_broadening_inputs_before_the_mutation_boundary() {
    let mut plan = dns_record_plan(
        "widgets-delete",
        "DELETE",
        "/accounts/{account_id}/widgets/{widget_id}",
        "parent_collection_omits_deleted_resource_id",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        None,
    );
    plan.capability.deleted_resource = Some(DeletedResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        requires_page_number_completion: false,
    });
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-1", "widget_id":"widget-1"}),
        query: json!({"cascade":true}),
        body: Some(json!({"reason":"must-not-cross-boundary"})),
        ..CallInput::default()
    })
    .expect("input");
    plan.status = PlanStatus::Consumed;
    let input: CallInput = serde_json::from_value(plan.input.clone()).expect("input");
    let catalog_hash = plan.catalog_hash.clone();
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .execute_consumed_plan_with_input(
            &mut plan,
            &catalog_hash,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
            &input,
        )
        .await
        .expect_err("broadening inputs must fail before network execution")
        .to_string();

    assert!(error.contains("outside the hash-bound collection readback contract"));
    assert!(!error.contains("must-not-cross-boundary"));
    assert_eq!(plan.status, PlanStatus::Consumed);
}

#[tokio::test]
async fn created_resource_is_verified_through_a_complete_parent_collection() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let mut requests = Vec::new();
        for page in 1..=2 {
            let (mut stream, _) = listener.accept().await.expect("accept verification");
            let mut buffer = vec![0_u8; 8192];
            let read = stream.read(&mut buffer).await.expect("read verification");
            requests.push(String::from_utf8_lossy(&buffer[..read]).to_string());
            let body = if page == 1 {
                r#"{"success":true,"result":[{"slug":"widget-other","name":"other","enabled":false}],"result_info":{"page":1,"total_pages":2}}"#
            } else {
                r#"{"success":true,"result":[{"slug":"secret-created-slug","name":"planned-secret-like-name","enabled":true}],"result_info":{"page":2,"total_pages":2}}"#
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write verification");
        }
        requests
    });
    let mut plan = dns_record_plan(
        "widgets-create",
        "POST",
        "/accounts/{account_id}/widgets",
        "parent_collection_contains_created_resource_id_and_planned_fields",
        json!({"account_id":"account-1"}),
        Some(json!({"name":"planned-secret-like-name", "enabled":true})),
    );
    plan.capability.created_collection_resource = Some(CreatedCollectionResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "slug".to_owned(),
        response_result_identity_pointer: "/slug".to_owned(),
        response_item_identity_pointer: "/slug".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        delete_capability_id: "widgets-delete".to_owned(),
        verified_response_fields: vec!["enabled".to_owned(), "name".to_owned()],
        requires_page_number_completion: true,
    });
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-1"}),
        query: json!({}),
        body: Some(json!({"name":"planned-secret-like-name", "enabled":true})),
        if_match: Some("mutation-etag".to_owned()),
        ..CallInput::default()
    })
    .expect("input");
    let apply = CloudflareResponseV1 {
        status: 201,
        success: true,
        result: json!({"slug":"secret-created-slug"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed, "{}", verification.basis);
    let requests = server.await.expect("server joins");
    assert!(requests[0].starts_with("GET /client/v4/accounts/account-1/widgets "));
    assert!(requests[1].starts_with("GET /client/v4/accounts/account-1/widgets?page=2 "));
    assert!(requests.iter().all(|request| {
        !request.contains("secret-created-slug")
            && !request.contains("planned-secret-like-name")
            && !request.contains("mutation_mode")
            && !request.contains("mutation-etag")
    }));
}

#[tokio::test]
async fn parent_collection_create_rejects_field_drift_without_echoing_values() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let _ = stream.read(&mut buffer).await.expect("read verification");
        let body = r#"{"success":true,"result":[{"id":"secret-created-id","name":"unexpected-live-value"}]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
    });
    let mut plan = dns_record_plan(
        "widgets-create",
        "POST",
        "/accounts/{account_id}/widgets",
        "parent_collection_contains_created_resource_id_and_planned_fields",
        json!({"account_id":"account-1"}),
        Some(json!({"name":"planned-secret-like-name"})),
    );
    plan.capability.created_collection_resource = Some(CreatedCollectionResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        delete_capability_id: "widgets-delete".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
        requires_page_number_completion: false,
    });
    let apply = CloudflareResponseV1 {
        status: 201,
        success: true,
        result: json!({"id":"secret-created-id"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(!verification.passed);
    assert!(verification.basis.contains("planned fields match=false"));
    assert!(!verification.basis.contains("secret-created-id"));
    assert!(!verification.basis.contains("planned-secret-like-name"));
    assert!(!verification.basis.contains("unexpected-live-value"));
    server.await.expect("server joins");
}

#[tokio::test]
async fn parent_collection_create_rejects_unbound_fields_before_the_mutation_boundary() {
    let mut plan = dns_record_plan(
        "widgets-create",
        "POST",
        "/accounts/{account_id}/widgets",
        "parent_collection_contains_created_resource_id_and_planned_fields",
        json!({"account_id":"account-1"}),
        Some(json!({"hidden":true})),
    );
    plan.capability.created_collection_resource = Some(CreatedCollectionResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        delete_capability_id: "widgets-delete".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
        requires_page_number_completion: false,
    });
    plan.status = PlanStatus::Consumed;
    let input: CallInput = serde_json::from_value(plan.input.clone()).expect("input");
    let catalog_hash = plan.catalog_hash.clone();
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .execute_consumed_plan_with_input(
            &mut plan,
            &catalog_hash,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
            &input,
        )
        .await
        .expect_err("unbound field must fail before network execution")
        .to_string();

    assert!(error.contains("outside the hash-bound collection readback fields"));
    assert_eq!(plan.status, PlanStatus::Consumed);
}

#[tokio::test]
async fn exact_resource_update_is_verified_by_same_path_planned_fields() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let read = stream.read(&mut buffer).await.expect("read verification");
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let body = r#"{"success":true,"result":{"id":"widget-1","name":"after","settings":{"enabled":true,"mode":"strict"},"server_default":"kept"},"errors":[]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
        request
    });
    let mut plan = dns_record_plan(
        "widgets-update",
        "PATCH",
        "/accounts/{account_id}/widgets/{widget_id}",
        "same_resource_contains_planned_fields_after_update",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        Some(json!({
            "name":"after",
            "settings":{"enabled":true,"mode":"strict"},
            "secret":"must-not-be-returned"
        })),
    );
    plan.capability.request_schema = Some(all_of_update_request_schema());
    plan.capability
        .same_path_read
        .as_mut()
        .expect("same-path readback")
        .verified_response_fields = vec!["name".to_owned(), "settings".to_owned()];
    plan.capability.product = "R2 Object".to_owned();
    plan.capability.selectors.push(SelectorV1 {
        name: "cf-r2-jurisdiction".to_owned(),
        location: "header".to_owned(),
        required: false,
        value_type: "string".to_owned(),
        description: None,
        contract: None,
    });
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({
            "account_id":"account-1",
            "widget_id":"widget-1",
            "cf-r2-jurisdiction":"fedramp"
        }),
        query: json!({}),
        body: Some(json!({
            "name":"after",
            "settings":{"enabled":true,"mode":"strict"},
            "secret":"must-not-be-returned"
        })),
        if_match: Some("mutation-etag".to_owned()),
        ..CallInput::default()
    })
    .expect("input");
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"widget-1"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed, "{}", verification.basis);
    let request = server.await.expect("server joins");
    assert!(request.starts_with("GET /client/v4/accounts/account-1/widgets/widget-1 "));
    assert!(!request.contains("mutation_mode"));
    assert!(!request.contains("mutation-etag"));
    assert!(!verification.basis.contains("must-not-be-returned"));
    assert!(request.contains("cf-r2-jurisdiction: fedramp\r\n"));
}

fn all_of_update_request_schema() -> Value {
    json!({
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
                    "settings":{
                        "type":"object",
                        "properties": {
                            "enabled":{"type":"boolean"},
                            "mode":{"type":"string"}
                        }
                    }
                }
            }
        ]
    })
}

#[tokio::test]
async fn exact_resource_update_projects_branch_local_write_only_inputs() {
    let (address, server) = json_response_sequence_server(vec![
        r#"{"success":true,"result":{"id":"widget-1","name":"after","config":{"client_id":"public-id"}},"errors":[]}"#,
    ])
    .await;
    let mut plan = dns_record_plan(
        "widgets-update",
        "PATCH",
        "/accounts/{account_id}/widgets/{widget_id}",
        "same_resource_contains_planned_fields_after_update",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        Some(json!({
            "name":"after",
            "secret":"must-not-be-returned",
            "config":{
                "client_id":"public-id",
                "client_secret":"nested-must-not-be-returned"
            }
        })),
    );
    plan.capability.request_schema = Some(json!({
        "oneOf": [
            {
                "type":"object",
                "required":["name", "secret", "config"],
                "properties": {
                    "name":{"type":"string"},
                    "secret":{"type":"string", "writeOnly":true},
                    "config":{
                        "type":"object",
                        "required":["client_id", "client_secret"],
                        "properties":{
                            "client_id":{"type":"string"},
                            "client_secret":{"type":"string", "writeOnly":true}
                        }
                    }
                }
            },
            {
                "type":"object",
                "required":["enabled"],
                "properties":{"enabled":{"type":"boolean"}}
            }
        ]
    }));
    plan.capability
        .same_path_read
        .as_mut()
        .expect("same-path readback")
        .verified_response_fields =
        vec!["config".to_owned(), "enabled".to_owned(), "name".to_owned()];
    let input = CallInput {
        selectors: json!({"account_id":"account-1", "widget_id":"widget-1"}),
        body: Some(json!({
            "name":"after",
            "secret":"must-not-be-returned",
            "config":{
                "client_id":"public-id",
                "client_secret":"nested-must-not-be-returned"
            }
        })),
        ..CallInput::default()
    };
    RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("builder")
        .build_unchecked(&plan.capability, &input)
        .expect("hash-bound body should match exactly one request branch");
    plan.input = serde_json::to_value(input).expect("input");
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"widget-1"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("branch-local write-only input should remain outside readback");

    assert!(verification.passed, "{}", verification.basis);
    assert!(!verification.basis.contains("must-not-be-returned"));
    assert!(!verification.basis.contains("nested-must-not-be-returned"));
    let requests = server.await.expect("server joins");
    assert_eq!(requests.len(), 1);
}

#[tokio::test]
async fn created_resource_is_read_back_by_hash_bound_identity_and_planned_fields() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let read = stream.read(&mut buffer).await.expect("read verification");
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let body = r#"{"success":true,"result":{"slug":"widget-one","name":"created","settings":{"enabled":true},"server_default":"kept"},"errors":[]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
        request
    });
    let mut plan = dns_record_plan(
        "widgets-create",
        "POST",
        "/accounts/{account_id}/widgets",
        "created_resource_contains_planned_fields_by_returned_id",
        json!({"account_id":"account-1"}),
        Some(json!({"name":"created", "settings":{"enabled":true}})),
    );
    plan.capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: "/accounts/{account_id}/widgets/{slug}".to_owned(),
        identity_selector: "slug".to_owned(),
        response_result_identity_pointer: "/slug".to_owned(),
        read_capability_id: "widgets-get".to_owned(),
        delete_capability_id: "widgets-delete".to_owned(),
        verified_response_fields: vec!["name".to_owned(), "settings".to_owned()],
    });
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-1"}),
        query: json!({}),
        body: Some(json!({"name":"created", "settings":{"enabled":true}})),
        if_match: Some("mutation-etag".to_owned()),
        ..CallInput::default()
    })
    .expect("input");
    let apply = CloudflareResponseV1 {
        status: 201,
        success: true,
        result: json!({"slug":"widget-one"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed, "{}", verification.basis);
    let request = server.await.expect("server joins");
    assert!(request.starts_with("GET /client/v4/accounts/account-1/widgets/widget-one "));
    assert!(!request.contains("mutation_mode"));
    assert!(!request.contains("mutation-etag"));
    assert!(!request.contains("\"name\":\"created\""));
}

#[tokio::test]
async fn created_resource_verification_projects_write_only_request_values() {
    let (address, server) = json_response_sequence_server(vec![
            r#"{"success":true,"result":{"id":"widget-1","name":"created","credentials":{"username":"operator"},"headers":[{"name":"Authorization"}]},"errors":[]}"#,
            r#"{"success":true,"result":{"id":"widget-1","name":"created","credentials":{"username":"different"},"headers":[{"name":"Authorization"}]},"errors":[]}"#,
        ])
        .await;
    let mut plan = dns_record_plan(
        "widgets-create",
        "POST",
        "/accounts/{account_id}/widgets",
        "created_resource_contains_planned_fields_by_returned_id",
        json!({"account_id":"account-1"}),
        Some(json!({
            "name":"created",
            "secret":"must-not-be-returned",
            "credentials":{"username":"operator","password":"must-not-be-returned"},
            "headers":[{"name":"Authorization","value":"must-not-be-returned"}]
        })),
    );
    plan.capability.request_schema = Some(json!({
        "type":"object",
        "properties": {
            "name":{"type":"string"},
            "secret":{"type":"string","writeOnly":true},
            "credentials":{
                "type":"object",
                "properties":{
                    "username":{"type":"string"},
                    "password":{"type":"string","writeOnly":true}
                }
            },
            "headers":{
                "type":"array",
                "items":{
                    "type":"object",
                    "properties":{
                        "name":{"type":"string"},
                        "value":{"type":"string","writeOnly":true}
                    }
                }
            }
        }
    }));
    plan.capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: "/accounts/{account_id}/widgets/{widget_id}".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-get".to_owned(),
        delete_capability_id: "widgets-delete".to_owned(),
        verified_response_fields: vec!["credentials", "headers", "name"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
    });
    let apply = CloudflareResponseV1 {
        status: 201,
        success: true,
        result: json!({"id":"widget-1"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("write-only inputs should not be required in a readback");
    assert!(verification.passed, "{}", verification.basis);
    assert!(!verification.basis.contains("must-not-be-returned"));
    let drifted = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("observable sibling drift should produce a failed verification result");
    assert!(!drifted.passed, "{}", drifted.basis);
    assert!(drifted.basis.contains("credentials"), "{}", drifted.basis);
    assert!(!drifted.basis.contains("must-not-be-returned"));
    let requests = server.await.expect("server joins");
    assert_eq!(requests.len(), 2);
    assert!(
        requests
            .iter()
            .all(|request| request
                .starts_with("GET /client/v4/accounts/account-1/widgets/widget-1 "))
    );
}

#[tokio::test]
async fn created_resource_verification_fails_closed_without_returned_identity() {
    let mut plan = dns_record_plan(
        "widgets-create",
        "POST",
        "/accounts/{account_id}/widgets",
        "created_resource_contains_planned_fields_by_returned_id",
        json!({"account_id":"account-1"}),
        Some(json!({"name":"secret-like-planned-name"})),
    );
    plan.capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: "/accounts/{account_id}/widgets/{widget_id}".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-get".to_owned(),
        delete_capability_id: "widgets-delete".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
    });
    let apply = CloudflareResponseV1 {
        status: 201,
        success: true,
        result: json!({"name":"secret-like-live-name"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect_err("missing identity must fail closed")
        .to_string();

    assert!(error.contains("identity"));
    assert!(!error.contains("secret-like-planned-name"));
    assert!(!error.contains("secret-like-live-name"));
}

#[tokio::test]
async fn created_resource_without_planned_fields_is_rejected_before_the_mutation_boundary() {
    let mut plan = dns_record_plan(
        "widgets-create",
        "POST",
        "/accounts/{account_id}/widgets",
        "created_resource_contains_planned_fields_by_returned_id",
        json!({"account_id":"account-1"}),
        Some(json!({})),
    );
    plan.capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: "/accounts/{account_id}/widgets/{widget_id}".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-get".to_owned(),
        delete_capability_id: "widgets-delete".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
    });
    plan.status = PlanStatus::Consumed;
    let input: CallInput = serde_json::from_value(plan.input.clone()).expect("input");
    let catalog_hash = plan.catalog_hash.clone();
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .execute_consumed_plan_with_input(
            &mut plan,
            &catalog_hash,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
            &input,
        )
        .await
        .expect_err("empty planned fields must fail before network execution")
        .to_string();

    assert!(error.contains("planned create body"));
    assert_eq!(plan.status, PlanStatus::Consumed);
}

#[tokio::test]
async fn created_resource_with_an_unbound_field_is_rejected_before_the_mutation_boundary() {
    let mut plan = dns_record_plan(
        "widgets-create",
        "POST",
        "/accounts/{account_id}/widgets",
        "created_resource_contains_planned_fields_by_returned_id",
        json!({"account_id":"account-1"}),
        Some(json!({"name":"created", "secret":"must-not-cross-boundary"})),
    );
    plan.capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: "/accounts/{account_id}/widgets/{widget_id}".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-get".to_owned(),
        delete_capability_id: "widgets-delete".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
    });
    plan.status = PlanStatus::Consumed;
    let input: CallInput = serde_json::from_value(plan.input.clone()).expect("input");
    let catalog_hash = plan.catalog_hash.clone();
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .execute_consumed_plan_with_input(
            &mut plan,
            &catalog_hash,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
            &input,
        )
        .await
        .expect_err("an unbound field must fail before network execution")
        .to_string();

    assert!(error.contains("outside the hash-bound exact readback fields"));
    assert!(!error.contains("must-not-cross-boundary"));
    assert_eq!(plan.status, PlanStatus::Consumed);
}

#[tokio::test]
async fn exact_create_rejects_query_controls_before_the_mutation_boundary() {
    let mut plan = dns_record_plan(
        "widgets-create",
        "POST",
        "/accounts/{account_id}/widgets",
        "created_resource_contains_planned_fields_by_returned_id",
        json!({"account_id":"account-1"}),
        Some(json!({"name":"created"})),
    );
    plan.capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: "/accounts/{account_id}/widgets/{widget_id}".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-get".to_owned(),
        delete_capability_id: "widgets-delete".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
    });
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-1"}),
        query: json!({"deploy":"must-not-cross-boundary"}),
        body: Some(json!({"name":"created"})),
        ..CallInput::default()
    })
    .expect("input");
    plan.status = PlanStatus::Consumed;
    let input: CallInput = serde_json::from_value(plan.input.clone()).expect("input");
    let catalog_hash = plan.catalog_hash.clone();
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .execute_consumed_plan_with_input(
            &mut plan,
            &catalog_hash,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
            &input,
        )
        .await
        .expect_err("query controls must fail before network execution")
        .to_string();

    assert!(error.contains("query controls outside the hash-bound exact readback contract"));
    assert!(!error.contains("must-not-cross-boundary"));
    assert_eq!(plan.status, PlanStatus::Consumed);
}

#[tokio::test]
async fn collection_create_rejects_query_controls_before_the_mutation_boundary() {
    let mut plan = dns_record_plan(
        "widgets-create",
        "POST",
        "/accounts/{account_id}/widgets",
        "parent_collection_contains_created_resource_id_and_planned_fields",
        json!({"account_id":"account-1"}),
        Some(json!({"name":"created"})),
    );
    plan.capability.created_collection_resource = Some(CreatedCollectionResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        delete_capability_id: "widgets-delete".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
        requires_page_number_completion: false,
    });
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-1"}),
        query: json!({"mode":"must-not-cross-boundary"}),
        body: Some(json!({"name":"created"})),
        ..CallInput::default()
    })
    .expect("input");
    plan.status = PlanStatus::Consumed;
    let input: CallInput = serde_json::from_value(plan.input.clone()).expect("input");
    let catalog_hash = plan.catalog_hash.clone();
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .execute_consumed_plan_with_input(
            &mut plan,
            &catalog_hash,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
            &input,
        )
        .await
        .expect_err("query controls must fail before network execution")
        .to_string();

    assert!(error.contains("query controls outside the hash-bound collection readback contract"));
    assert!(!error.contains("must-not-cross-boundary"));
    assert_eq!(plan.status, PlanStatus::Consumed);
}

#[tokio::test]
async fn same_path_delete_rejects_broadening_inputs_before_the_mutation_boundary() {
    let mut plan = dns_record_plan(
        "widgets-delete",
        "DELETE",
        "/accounts/{account_id}/widgets/{widget_id}",
        "same_resource_returns_not_found_after_delete",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        None,
    );
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-1", "widget_id":"widget-1"}),
        query: json!({"cascade":true}),
        body: Some(json!({"reason":"must-not-cross-boundary"})),
        ..CallInput::default()
    })
    .expect("input");
    plan.status = PlanStatus::Consumed;
    let input: CallInput = serde_json::from_value(plan.input.clone()).expect("input");
    let catalog_hash = plan.catalog_hash.clone();
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .execute_consumed_plan_with_input(
            &mut plan,
            &catalog_hash,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
            &input,
        )
        .await
        .expect_err("broadening delete inputs must fail before network execution")
        .to_string();

    assert!(error.contains("outside its hash-bound same-path readback contract"));
    assert!(!error.contains("must-not-cross-boundary"));
    assert_eq!(plan.status, PlanStatus::Consumed);
}

#[tokio::test]
async fn same_path_delete_accepts_only_its_hash_bound_required_empty_body() {
    let (address, server) =
        json_response_sequence_server(vec![r#"{"success":true,"result":null,"errors":[]}"#]).await;
    let mut plan = dns_record_plan(
        "widgets-delete",
        "DELETE",
        "/accounts/{account_id}/widgets/{widget_id}",
        "same_resource_returns_not_found_after_delete",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        Some(json!({})),
    );
    plan.capability.request_schema = Some(json!({
        "type":"object",
        "properties":{},
        "additionalProperties":false,
        "x-cfctl-body-required":true
    }));
    plan.status = PlanStatus::Consumed;
    let input: CallInput = serde_json::from_value(plan.input.clone()).expect("input");
    let catalog_hash = plan.catalog_hash.clone();
    let response = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .execute_consumed_plan_with_input(
        &mut plan,
        &catalog_hash,
        &AuthCredential::Bearer {
            token: "governing-token".to_owned(),
        },
        &input,
    )
    .await
    .expect("strict empty body reaches the boundary");

    assert!(response.success);
    let requests = server.await.expect("server joins");
    assert!(requests[0].starts_with("DELETE /client/v4/accounts/account-1/widgets/widget-1 "));
    assert!(requests[0].ends_with("{}"));

    let mut broadened = dns_record_plan(
        "widgets-delete",
        "DELETE",
        "/accounts/{account_id}/widgets/{widget_id}",
        "same_resource_returns_not_found_after_delete",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        Some(json!({"cascade":"must-not-cross-boundary"})),
    );
    broadened.capability.request_schema = Some(json!({
        "type":"object",
        "properties":{},
        "additionalProperties":false,
        "x-cfctl-body-required":true
    }));
    broadened.status = PlanStatus::Consumed;
    let input: CallInput = serde_json::from_value(broadened.input.clone()).expect("input");
    let catalog_hash = broadened.catalog_hash.clone();
    let error = Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4")
        .expect("executor")
        .execute_consumed_plan_with_input(
            &mut broadened,
            &catalog_hash,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
            &input,
        )
        .await
        .expect_err("non-empty body must fail before the network boundary")
        .to_string();
    assert!(error.contains("hash-bound required empty body"));
    assert!(!error.contains("must-not-cross-boundary"));
    assert_eq!(broadened.status, PlanStatus::Consumed);
}

#[tokio::test]
async fn same_path_delete_rejects_query_controls_before_the_mutation_boundary() {
    let mut plan = dns_record_plan(
        "widgets-delete",
        "DELETE",
        "/accounts/{account_id}/widgets/{widget_id}",
        "same_resource_returns_not_found_after_delete",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        None,
    );
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-1", "widget_id":"widget-1"}),
        query: json!({"cascade":"must-not-cross-boundary"}),
        ..CallInput::default()
    })
    .expect("input");
    plan.status = PlanStatus::Consumed;
    let input: CallInput = serde_json::from_value(plan.input.clone()).expect("input");
    let catalog_hash = plan.catalog_hash.clone();
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .execute_consumed_plan_with_input(
            &mut plan,
            &catalog_hash,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
            &input,
        )
        .await
        .expect_err("query controls must fail before network execution")
        .to_string();

    assert!(error.contains("query controls outside the hash-bound same-path readback contract"));
    assert!(!error.contains("must-not-cross-boundary"));
    assert_eq!(plan.status, PlanStatus::Consumed);
}

#[tokio::test]
async fn same_path_update_rejects_unbound_fields_before_the_mutation_boundary() {
    let mut plan = dns_record_plan(
        "widgets-update",
        "PATCH",
        "/accounts/{account_id}/widgets/{widget_id}",
        "same_resource_contains_planned_fields_after_update",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        Some(json!({"name":"planned"})),
    );
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-1", "widget_id":"widget-1"}),
        query: json!({}),
        body: Some(json!({"name":"planned", "secret":"must-not-cross-boundary"})),
        ..CallInput::default()
    })
    .expect("input");
    plan.status = PlanStatus::Consumed;
    let input: CallInput = serde_json::from_value(plan.input.clone()).expect("input");
    let catalog_hash = plan.catalog_hash.clone();
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .execute_consumed_plan_with_input(
            &mut plan,
            &catalog_hash,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
            &input,
        )
        .await
        .expect_err("an unbound update field must fail before network execution")
        .to_string();

    assert!(error.contains("outside the hash-bound same-path readback fields"));
    assert!(!error.contains("must-not-cross-boundary"));
    assert_eq!(plan.status, PlanStatus::Consumed);
}

#[tokio::test]
async fn same_path_update_rejects_query_controls_before_the_mutation_boundary() {
    let mut plan = dns_record_plan(
        "widgets-update",
        "PATCH",
        "/accounts/{account_id}/widgets/{widget_id}",
        "same_resource_contains_planned_fields_after_update",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        Some(json!({"name":"planned"})),
    );
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-1", "widget_id":"widget-1"}),
        query: json!({"mode":"must-not-cross-boundary"}),
        body: Some(json!({"name":"planned"})),
        ..CallInput::default()
    })
    .expect("input");
    plan.status = PlanStatus::Consumed;
    let input: CallInput = serde_json::from_value(plan.input.clone()).expect("input");
    let catalog_hash = plan.catalog_hash.clone();
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .execute_consumed_plan_with_input(
            &mut plan,
            &catalog_hash,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
            &input,
        )
        .await
        .expect_err("query controls must fail before network execution")
        .to_string();

    assert!(error.contains("query controls outside the hash-bound same-path readback contract"));
    assert!(!error.contains("must-not-cross-boundary"));
    assert_eq!(plan.status, PlanStatus::Consumed);
}

#[tokio::test]
async fn exact_resource_update_rejects_field_drift_without_echoing_values() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let _ = stream.read(&mut buffer).await.expect("read verification");
        let body = r#"{"success":true,"result":{"settings":{"mode":"unexpected-live-value"}},"errors":[]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
    });
    let plan = dns_record_plan(
        "widgets-update",
        "PUT",
        "/accounts/{account_id}/widgets/{widget_id}",
        "same_resource_contains_planned_fields_after_update",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        Some(json!({"settings":{"mode":"planned-secret-like-value"}})),
    );
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(!verification.passed);
    assert!(verification.basis.contains("settings"));
    assert!(!verification.basis.contains("planned-secret-like-value"));
    assert!(!verification.basis.contains("unexpected-live-value"));
    server.await.expect("server joins");
}

#[tokio::test]
async fn same_path_object_update_verifies_schema_proven_fields_with_a_clean_get() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let read = stream.read(&mut buffer).await.expect("read verification");
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let body = r#"{"success":true,"result":{"mode":"strict","nested":{"enabled":true},"server_default":"kept"},"errors":[]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
        request
    });
    let mut plan = dns_record_plan(
        "settings-update",
        "PUT",
        "/zones/{zone_id}/settings/example",
        "same_path_result_contains_planned_fields_after_update",
        json!({"zone_id":"zone-1"}),
        Some(json!({"mode":"strict", "nested":{"enabled":true}})),
    );
    plan.capability.request_schema = Some(json!({
        "type":"object",
        "properties":{"mode":{"type":"string"},"nested":{"type":"object"}}
    }));
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"zone_id":"zone-1"}),
        query: json!({}),
        body: Some(json!({"mode":"strict", "nested":{"enabled":true}})),
        if_match: Some("mutation-etag".to_owned()),
        ..CallInput::default()
    })
    .expect("input");
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed, "{}", verification.basis);
    let request = server.await.expect("server joins");
    assert!(request.starts_with("GET /client/v4/zones/zone-1/settings/example "));
    assert!(!request.contains("mutation_mode"));
    assert!(!request.contains("mutation-etag"));
}

#[tokio::test]
async fn same_path_post_mutation_omits_an_audit_only_field_from_clean_readback() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let read = stream.read(&mut buffer).await.expect("read verification");
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let body = r#"{"success":true,"result":{"disconnect":true},"errors":[]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
        request
    });
    let mut plan = dns_record_plan(
        "settings-apply",
        "POST",
        "/accounts/{account_id}/settings/example",
        "same_path_result_contains_planned_fields_after_mutation",
        json!({"account_id":"account-1"}),
        Some(json!({
            "disconnect":true,
            "justification":"planned-audit-only-value"
        })),
    );
    plan.capability.request_schema = Some(json!({
        "type":"object",
        "properties":{
            "disconnect":{"type":"boolean"},
            "justification":{
                "type":"string",
                "x-cfctl-verification-observable":false
            }
        }
    }));
    plan.capability
        .same_path_read
        .as_mut()
        .expect("same-path readback")
        .verified_response_fields = vec!["disconnect".to_owned()];
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed, "{}", verification.basis);
    assert!(verification.basis.contains("planned mutation field"));
    assert!(!verification.basis.contains("planned update field"));
    assert!(!verification.basis.contains("planned-audit-only-value"));
    let request = server.await.expect("server joins");
    assert!(request.starts_with("GET /client/v4/accounts/account-1/settings/example "));
}

#[tokio::test]
async fn dns_record_verification_rejects_live_field_drift_without_echoing_values() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let _ = stream.read(&mut buffer).await.expect("read verification");
        let body = r#"{"success":true,"result":{"id":"record-1","type":"TXT","name":"www.example.com","content":"unexpected-live-value","ttl":300},"errors":[]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
    });
    let plan = dns_record_plan(
        "dns-records-for-a-zone-patch-dns-record",
        "PATCH",
        "/zones/{zone_id}/dns_records/{dns_record_id}",
        "dns_record_details_match_planned_id_and_fields",
        json!({"zone_id":"zone-1", "dns_record_id":"record-1"}),
        Some(json!({
            "type":"TXT",
            "name":"www.example.com",
            "content":"planned-secret-like-value",
            "ttl":300
        })),
    );
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({
            "id":"record-1",
            "type":"TXT",
            "name":"www.example.com",
            "content":"planned-secret-like-value",
            "ttl":300
        }),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(!verification.passed);
    assert!(verification.basis.contains("content"));
    assert!(!verification.basis.contains("planned-secret-like-value"));
    assert!(!verification.basis.contains("unexpected-live-value"));
    server.await.expect("server joins");
}

#[tokio::test]
async fn oauth_client_rotation_verifies_two_secret_overlap_without_echoing_secret() {
    let (address, server) = json_response_sequence_server(vec![
        r#"{"success":true,"result":{"client_id":"oauth-client-1","has_rotated_secret":true},"errors":[]}"#,
    ])
    .await;
    let plan = oauth_client_secret_plan(
        "oauth-clients-rotate-secret",
        "POST",
        "oauth_client_reports_rotated_secret_after_value_roll",
    );
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"client_secret":"one-time-secret-must-not-echo"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("rotation verification");

    assert!(verification.passed, "{}", verification.basis);
    assert!(!verification.basis.contains("one-time-secret-must-not-echo"));
    assert!(
        !verification
            .readback
            .result
            .to_string()
            .contains("one-time-secret")
    );
    let requests = server.await.expect("server joins");
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0].starts_with("GET /client/v4/accounts/account-1/oauth_clients/oauth-client-1 ")
    );
}

#[tokio::test]
async fn access_service_token_refresh_verifies_exact_identity_and_expiration_readback() {
    let (address, server) = json_response_sequence_server(vec![
        r#"{"success":true,"result":{"id":"service-token-1","expires_at":"2099-07-15T22:00:00Z"},"errors":[]}"#,
    ])
    .await;
    let plan = access_service_token_refresh_plan();
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({
            "id":"service-token-1",
            "expires_at":"2099-07-15T22:00:00Z"
        }),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("refresh verification");

    assert!(verification.passed, "{}", verification.basis);
    assert!(verification.basis.contains("expiration matches=true"));
    assert!(!verification.basis.contains("2099-07-15"));
    let requests = server.await.expect("server joins");
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0].starts_with(
            "GET /client/v4/accounts/account-1/access/service_tokens/service-token-1 "
        )
    );
}

#[tokio::test]
async fn access_service_token_refresh_rejects_expiration_readback_drift_without_echoing_values() {
    let (address, server) = json_response_sequence_server(vec![
        r#"{"success":true,"result":{"id":"service-token-1","expires_at":"2098-07-15T22:00:00Z"},"errors":[]}"#,
    ])
    .await;
    let plan = access_service_token_refresh_plan();
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({
            "id":"service-token-1",
            "expires_at":"2099-07-15T22:00:00Z"
        }),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("refresh verification");

    assert!(!verification.passed);
    assert!(verification.basis.contains("expiration matches=false"));
    assert!(!verification.basis.contains("2099-07-15"));
    assert!(!verification.basis.contains("2098-07-15"));
    server.await.expect("server joins");
}

#[tokio::test]
async fn access_service_token_refresh_rejects_a_grafted_permission_before_network() {
    let mut plan = access_service_token_refresh_plan();
    plan.capability.permissions = vec!["Account Settings Write".to_owned()];
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({
            "id":"service-token-1",
            "expires_at":"2099-07-15T22:00:00Z"
        }),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect_err("a grafted refresh verifier must fail before network")
        .to_string();

    assert!(error.contains("not implemented"));
    assert!(!error.contains("2099-07-15"));
}

#[tokio::test]
async fn oauth_client_old_secret_delete_verifies_one_secret_state() {
    let (address, server) = json_response_sequence_server(vec![
        r#"{"success":true,"result":{"client_id":"oauth-client-1","has_rotated_secret":false},"errors":[]}"#,
    ])
    .await;
    let plan = oauth_client_secret_plan(
        "oauth-clients-delete-rotated-secret",
        "DELETE",
        "oauth_client_reports_no_rotated_secret_after_old_secret_delete",
    );
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"oauth-client-1"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("old-secret deletion verification");

    assert!(verification.passed, "{}", verification.basis);
    let requests = server.await.expect("server joins");
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0].starts_with("GET /client/v4/accounts/account-1/oauth_clients/oauth-client-1 ")
    );
}

#[tokio::test]
async fn oauth_client_rotation_rejects_a_readback_without_two_secret_overlap() {
    let (address, server) = json_response_sequence_server(vec![
        r#"{"success":true,"result":{"client_id":"oauth-client-1","has_rotated_secret":false},"errors":[]}"#,
    ])
    .await;
    let plan = oauth_client_secret_plan(
        "oauth-clients-rotate-secret",
        "POST",
        "oauth_client_reports_rotated_secret_after_value_roll",
    );
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"client_secret":"one-time-secret-must-not-echo"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("rotation verification");

    assert!(!verification.passed);
    assert!(verification.basis.contains("has_rotated_secret=true"));
    assert!(!verification.basis.contains("one-time-secret-must-not-echo"));
    server.await.expect("server joins");
}

#[tokio::test]
async fn oauth_client_rotation_rejects_an_apply_outside_the_exact_success_status() {
    let (address, server) = json_response_sequence_server(vec![
        r#"{"success":true,"result":{"client_id":"oauth-client-1","has_rotated_secret":true},"errors":[]}"#,
    ])
    .await;
    let plan = oauth_client_secret_plan(
        "oauth-clients-rotate-secret",
        "POST",
        "oauth_client_reports_rotated_secret_after_value_roll",
    );
    let apply = CloudflareResponseV1 {
        status: 201,
        success: true,
        result: json!({"client_secret":"one-time-secret-must-not-echo"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("rotation verification");

    assert!(!verification.passed);
    assert!(verification.basis.contains("apply HTTP 201"));
    assert!(!verification.basis.contains("one-time-secret-must-not-echo"));
    server.await.expect("server joins");
}

#[tokio::test]
async fn oauth_client_old_secret_delete_rejects_a_different_result_identity() {
    let (address, server) = json_response_sequence_server(vec![
        r#"{"success":true,"result":{"client_id":"oauth-client-1","has_rotated_secret":false},"errors":[]}"#,
    ])
    .await;
    let plan = oauth_client_secret_plan(
        "oauth-clients-delete-rotated-secret",
        "DELETE",
        "oauth_client_reports_no_rotated_secret_after_old_secret_delete",
    );
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"different-oauth-client"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("old-secret deletion verification");

    assert!(!verification.passed);
    assert!(verification.basis.contains("apply identity matches=false"));
    server.await.expect("server joins");
}

#[tokio::test]
async fn oauth_client_verifier_rejects_a_grafted_permission_before_network() {
    let mut plan = oauth_client_secret_plan(
        "oauth-clients-rotate-secret",
        "POST",
        "oauth_client_reports_rotated_secret_after_value_roll",
    );
    plan.capability.permissions = vec!["Account Settings Write".to_owned()];
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"client_secret":"must-not-cross-boundary"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect_err("a grafted OAuth verifier must fail before network")
        .to_string();

    assert!(error.contains("not implemented"));
    assert!(!error.contains("must-not-cross-boundary"));
}

fn dns_record_plan(
    id: &str,
    method: &str,
    path: &str,
    verification_strategy: &str,
    selectors: serde_json::Value,
    body: Option<serde_json::Value>,
) -> PlanV1 {
    let mut capability = CapabilityV1::new(id, id, method, path);
    verification_strategy.clone_into(&mut capability.verification.strategy);
    if matches!(
        verification_strategy,
        "same_resource_returns_not_found_after_delete"
    ) {
        capability.same_path_read = Some(SamePathReadContractV1 {
            path: path.to_owned(),
            read_capability_id: format!("{id}-readback"),
            verified_response_fields: Vec::new(),
        });
    } else if matches!(
        verification_strategy,
        "same_resource_contains_planned_fields_after_update"
            | "same_path_result_contains_planned_fields_after_update"
            | "same_path_result_contains_planned_fields_after_mutation"
            | "parent_collection_item_contains_planned_fields_after_update"
    ) {
        let mut fields = body
            .as_ref()
            .and_then(serde_json::Value::as_object)
            .map(|body| body.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        fields.sort();
        fields.dedup();
        let properties = fields
            .iter()
            .map(|field| (field.clone(), json!({})))
            .collect::<serde_json::Map<_, _>>();
        capability.request_schema = Some(json!({
            "type":"object",
            "properties": properties
        }));
        capability.same_path_read = Some(SamePathReadContractV1 {
            path: path.to_owned(),
            read_capability_id: format!("{id}-readback"),
            verified_response_fields: fields,
        });
    }
    let mut plan = PlanV1::draft(
        "profile",
        "account-1",
        "sha256:catalog",
        capability,
        json!({}),
    )
    .expect("plan");
    plan.input = serde_json::to_value(CallInput {
        selectors,
        query: json!({}),
        body,
        ..CallInput::default()
    })
    .expect("input");
    plan
}

fn oauth_client_secret_plan(id: &str, method: &str, verification_strategy: &str) -> PlanV1 {
    let mut capability = CapabilityV1::new(
        id,
        id,
        method,
        "/accounts/{account_id}/oauth_clients/{oauth_client_id}/rotate_secret",
    );
    "OAuth Clients".clone_into(&mut capability.product);
    capability.permissions = vec!["OAuth Client Write".to_owned()];
    verification_strategy.clone_into(&mut capability.verification.strategy);
    capability.selectors = vec![
        SelectorV1 {
            name: "account_id".to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        },
        SelectorV1 {
            name: "oauth_client_id".to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        },
    ];
    capability.same_path_read = Some(SamePathReadContractV1 {
        path: "/accounts/{account_id}/oauth_clients/{oauth_client_id}".to_owned(),
        read_capability_id: "oauth-clients-get".to_owned(),
        verified_response_fields: vec!["client_id".to_owned(), "has_rotated_secret".to_owned()],
    });
    let mut plan = PlanV1::draft(
        "profile",
        "account-1",
        "sha256:catalog",
        capability,
        json!({}),
    )
    .expect("plan");
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({
            "account_id":"account-1",
            "oauth_client_id":"oauth-client-1"
        }),
        query: json!({}),
        body: None,
        ..CallInput::default()
    })
    .expect("input");
    plan
}

fn access_service_token_refresh_plan() -> PlanV1 {
    let mut capability = CapabilityV1::new(
        "access-service-tokens-refresh-a-service-token",
        "Refresh a service token",
        "POST",
        "/accounts/{account_id}/access/service_tokens/{service_token_id}/refresh",
    );
    "Access service tokens".clone_into(&mut capability.product);
    capability.permissions = vec!["Access: Service Tokens Write".to_owned()];
    capability.selectors = vec![
        SelectorV1 {
            name: "service_token_id".to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: Some(SelectorContractV1 {
                schema: json!({"maxLength":36,"type":"string"}),
                query: None,
            }),
        },
        SelectorV1 {
            name: "account_id".to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: Some(SelectorContractV1 {
                schema: json!({"maxLength":32,"type":"string"}),
                query: None,
            }),
        },
    ];
    "access_service_token_reports_refreshed_expiration"
        .clone_into(&mut capability.verification.strategy);
    capability.same_path_read = Some(SamePathReadContractV1 {
        path: "/accounts/{account_id}/access/service_tokens/{service_token_id}".to_owned(),
        read_capability_id: "access-service-tokens-get-a-service-token".to_owned(),
        verified_response_fields: vec!["expires_at".to_owned(), "id".to_owned()],
    });
    let mut plan = PlanV1::draft(
        "profile",
        "account-1",
        "sha256:catalog",
        capability,
        json!({}),
    )
    .expect("plan");
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({
            "account_id":"account-1",
            "service_token_id":"service-token-1"
        }),
        query: json!({}),
        body: None,
        ..CallInput::default()
    })
    .expect("input");
    plan
}

fn token_plan(
    id: &str,
    method: &str,
    path: &str,
    verification_strategy: &str,
    selectors: serde_json::Value,
) -> PlanV1 {
    let mut capability = CapabilityV1::new(id, id, method, path);
    verification_strategy.clone_into(&mut capability.verification.strategy);
    let mut plan = PlanV1::draft(
        "profile",
        "account-1",
        "sha256:catalog",
        capability,
        json!({}),
    )
    .expect("plan");
    plan.input = serde_json::to_value(CallInput {
        selectors,
        query: json!({}),
        body: Some(json!({})),
        ..CallInput::default()
    })
    .expect("input");
    plan
}
