#![allow(clippy::expect_used)]
mod reconciliation;
use super::*;
use cfctl_auth::AuthCredential;
use cfctl_core::d1_read_inventory::*;
use serde_json::json;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

const EXAMPLE: &str =
    include_str!("../../../cfctl-workspace/tests/fixtures/d1-reads/inventory.json");
const QUALIFIED: &str = include_str!(
    "../../../cfctl-workspace/tests/fixtures/d1-reads/qualified-provider-response.json"
);

fn inventory() -> D1ReadInventoryV1 {
    serde_json::from_str(EXAMPLE).expect("synthetic inventory")
}

#[test]
fn sequence_high_water_marks_and_direct_foreign_key_metadata_are_read_only() {
    for (sql, names) in [
        (
            "SELECT name, seq FROM sqlite_sequence WHERE name IN ('signatures', 'audit_log', 'signature_placements') ORDER BY name;",
            vec!["name", "seq"],
        ),
        (
            "PRAGMA foreign_key_check;",
            vec!["table", "rowid", "parent", "fkid"],
        ),
    ] {
        let mut fixture = inventory();
        let query = &mut fixture.queries[1];
        query.sql = sql.into();
        query.sha256 = sha256(sql.as_bytes());
        query.output.columns = names
            .into_iter()
            .map(|name| {
                let text = matches!(name, "name" | "table" | "parent");
                D1ReadColumnV1 {
                    name: name.into(),
                    kind: if text {
                        D1ReadValueKindV1::Text
                    } else {
                        D1ReadValueKindV1::Integer
                    },
                    nullable: true,
                    max_bytes: text.then_some(128),
                    allowed_values: None,
                    min_integer: None,
                    max_integer: None,
                }
            })
            .collect();
        validate_inventory(&fixture).expect("closed sequence and foreign-key metadata");
    }
}

fn prepared(inventory: D1ReadInventoryV1) -> (CapabilityV1, CallInput) {
    let inventory_sha256 = sha256(&serde_json::to_vec(&inventory).expect("inventory"));
    let mut capability = CapabilityV1::new(
        "example.d1-read-inventory",
        "Read example",
        "POST",
        "/accounts/{account_id}/d1/database/{database_id}/query",
    );
    capability.authority_scope = Some(CapabilityAuthorityScopeV1::WorkspaceOwned);
    capability.adapter_status = AdapterStatus::Native;
    capability.mutating = false;
    capability.risk = RiskClass::Read;
    capability.effect = EffectClass::ReadOnly;
    capability.permissions = vec!["D1 Read".into()];
    capability.workspace_d1_read_inventory = Some(WorkspaceD1ReadInventoryContractV1 {
        repository_root: "/synthetic-repository".into(),
        repository_head: "a".repeat(40),
        repository_tree: "b".repeat(40),
        repository_origin: "https://example.invalid/test.git".into(),
        operation_pack_sha256: sha256(b"pack"),
        operation: D1ReadOperationV1 {
            id: capability.id.clone(),
            title: capability.title.clone(),
            description: "Synthetic read test".into(),
            account_id: "a".repeat(32),
            database_id: "11111111-2222-4333-8444-555555555555".into(),
            profile_id: "example-read".into(),
            source_revision: "a".repeat(40),
            source: vec![D1ReadSourceV1 {
                path: "source.txt".into(),
                sha256: sha256(b"source"),
            }],
            inventory_path: "inventory.json".into(),
            inventory_sha256: inventory_sha256.clone(),
        },
        inventory,
    });
    let input = CallInput {
        selectors: json!({"account_id":"a".repeat(32),"database_id":"11111111-2222-4333-8444-555555555555"}),
        query: json!({}),
        body: Some(json!({"inventory_sha256":inventory_sha256,
            "expected_credential_generation_id":"22222222-2222-4222-8222-222222222222"})),
        ..CallInput::default()
    };
    (capability, input)
}

#[test]
fn every_reviewed_founder_and_sign_query_and_witness_passes_actual_compiler() {
    let bindings: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/d1-read-inventory/population-bindings.json"
    ))
    .expect("population bindings");
    for (owner, bytes, query_count, witness_count) in [
        (
            "founder",
            include_bytes!("../../tests/fixtures/d1-read-inventory/founder.json").as_slice(),
            504,
            621,
        ),
        (
            "sign",
            include_bytes!("../../tests/fixtures/d1-read-inventory/sign.json").as_slice(),
            40,
            40,
        ),
        (
            "sign_r4",
            include_bytes!("../../tests/fixtures/d1-read-inventory/sign-r4.json").as_slice(),
            54,
            54,
        ),
        (
            "founder_r4",
            include_bytes!("../../tests/fixtures/d1-read-inventory/founder-r4.json").as_slice(),
            504,
            621,
        ),
        (
            "founder_reconciliation",
            include_bytes!("../../tests/fixtures/d1-read-inventory/founder-reconciliation.json")
                .as_slice(),
            3,
            3,
        ),
    ] {
        let inventory: D1ReadInventoryV1 =
            serde_json::from_slice(bytes).expect("actual query population");
        assert_eq!(bindings[owner]["fixture_sha256"], sha256(bytes));
        assert_eq!(inventory.query_count, query_count);
        assert_eq!(inventory.witness_count, witness_count);
        for (query, original) in inventory.queries.iter().zip(
            bindings[owner]["queries"]
                .as_array()
                .expect("original query joins"),
        ) {
            assert_eq!(
                query.sha256,
                original["sha256"].as_str().expect("source SQL digest")
            );
            assert_eq!(
                serde_json::to_value(
                    query
                        .witnesses
                        .iter()
                        .map(|w| w.ordinal)
                        .collect::<Vec<_>>()
                )
                .expect("ordinals"),
                original["witness_ordinals"]
            );
        }
        validate_inventory(&inventory).unwrap_or_else(|error| panic!("{owner}: {error}"));
    }
}

#[test]
fn writes_unsupported_syntax_functions_and_bad_final_queries_fail_preflight() {
    for sql in [
        "DELETE FROM items;",
        "UPDATE items SET status='bad';",
        "INSERT INTO items(id) VALUES(1);",
        "CREATE TABLE stolen(id);",
        "DROP TABLE items;",
        "BEGIN;",
        "ATTACH ':memory:' AS other;",
        "PRAGMA writable_schema=ON;",
        "PRAGMA foreign_keys=OFF;",
        "PRAGMA journal_mode;",
        "SELECT 1; DELETE FROM items;",
        "SELECT load_extension('x');",
        "SELECT randomblob(99999999);",
        "SELECT ? AS n;",
        "SELECT * FROM unknown_table;",
        "SELECT private_value FROM items;",
        "SELECT COUNT(*) AS n FROM temp.items;",
        "EXPLAIN SELECT 1;",
        "VALUES(1);",
        "WITH RECURSIVE x(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM x) SELECT COUNT(*) AS n FROM x;",
        "WITH /*comment*/ RECURSIVE x AS (SELECT 1) SELECT COUNT(*) AS n FROM x;",
        "SELECT 'unterminated",
        "SELECT 1 /*unterminated",
        "SELECT 1\0;",
    ] {
        let mut fixture = inventory();
        fixture.queries[1].sql = sql.into();
        fixture.queries[1].sha256 = sha256(sql.as_bytes());
        assert!(
            validate_inventory(&fixture).is_err(),
            "unexpectedly accepted {sql}"
        );
    }
    let mut duplicate = inventory();
    duplicate.queries[1].witnesses[0].ordinal = 1;
    assert!(validate_inventory(&duplicate).is_err());
    let mut future = inventory();
    future.queries[0].requires = vec![D1ReadDependencyV1 {
        query_id: "count".into(),
        column: None,
        equals: None,
    }];
    assert!(validate_inventory(&future).is_err());
    let mut digest_drift = inventory();
    digest_drift.queries[1].sql.push(' ');
    assert!(validate_inventory(&digest_drift).is_err());
}

#[test]
fn target_body_and_generation_drift_are_rejected_without_a_transport() {
    let (capability, input) = prepared(inventory());
    assert!(validate(&capability, &input).is_ok());
    let mut changed = input.clone();
    changed.selectors["account_id"] = json!("b".repeat(32));
    assert!(validate(&capability, &changed).is_err());
    let mut changed = input.clone();
    changed.body.as_mut().expect("body")["sql"] = json!("SELECT 1");
    assert!(validate(&capability, &changed).is_err());
    let mut changed = input.clone();
    changed.body.as_mut().expect("body")["expected_credential_generation_id"] =
        json!("not-a-generation");
    assert!(validate(&capability, &changed).is_err());
    let mut changed = capability.clone();
    changed.mutating = true;
    assert!(validate(&changed, &input).is_err());
}

struct TestServer {
    url: String,
    count: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<Value>>>,
    handle: tokio::task::JoinHandle<()>,
}

async fn server(responses: Vec<(u16, Value)>) -> TestServer {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("local listener");
    let address = listener.local_addr().expect("address");
    let count = Arc::new(AtomicUsize::new(0));
    let observed = count.clone();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let captured = requests.clone();
    let handle = tokio::spawn(async move {
        for (status, value) in responses {
            let (mut socket, _) = listener.accept().await.expect("connection");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];
            loop {
                let n = socket.read(&mut buffer).await.expect("request bytes");
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..n]);
                if let Some(end) = request.windows(4).position(|v| v == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..end]);
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length: ")
                                .and_then(|s| s.parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    if request.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            let text = String::from_utf8_lossy(&request);
            assert!(text.starts_with("POST /accounts/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/d1/database/11111111-2222-4333-8444-555555555555/query "));
            assert!(text.contains("\"sql\":"));
            let end = request
                .windows(4)
                .position(|v| v == b"\r\n\r\n")
                .expect("headers end");
            captured
                .lock()
                .expect("requests")
                .push(serde_json::from_slice(&request[end + 4..]).expect("request JSON"));
            observed.fetch_add(1, Ordering::SeqCst);
            let body = serde_json::to_vec(&value).expect("response body");
            let header = format!(
                "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            socket.write_all(header.as_bytes()).await.expect("header");
            socket.write_all(&body).await.expect("response");
        }
    });
    TestServer {
        url: format!("http://{address}"),
        count,
        requests,
        handle,
    }
}

fn provider(rows: Value) -> Value {
    let mut body: Value = serde_json::from_str(QUALIFIED).expect("qualified fixture");
    body["result"][0]["results"] = rows;
    body
}

async fn run(fixture: D1ReadInventoryV1, responses: Vec<(u16, Value)>) -> D1ReadInventoryResultV1 {
    let (capability, input) = prepared(fixture);
    let validated = validate(&capability, &input).expect("validated fixture");
    let TestServer {
        url, count, handle, ..
    } = server(responses).await;
    let executor = crate::Executor::new(reqwest::Client::new(), &url).expect("executor");
    let result = executor
        .execute_d1_read_inventory(
            &validated,
            &AuthCredential::Bearer {
                token: "synthetic-token".into(),
            },
            || Ok(()),
        )
        .await
        .expect("read execution");
    assert_eq!(
        count.load(Ordering::SeqCst) as u64,
        result.attempted_queries
    );
    handle.abort();
    result
}

#[tokio::test]
async fn complete_population_preserves_provider_receipts_and_witnesses() {
    let result = run(
        inventory(),
        vec![
            (200, provider(json!([{"name":"items"}]))),
            (200, provider(json!([{"n":0}]))),
        ],
    )
    .await;
    assert!(result.read_complete);
    assert_eq!(result.attempted_queries, 2);
    assert_eq!(result.unattempted_queries, 0);
    assert!(!result.application_predicates_evaluated);
    assert_eq!(
        result.results[1]
            .receipt
            .as_ref()
            .expect("qualified receipt")["result"][0]["results"][0]["n"],
        0
    );
}

#[tokio::test]
async fn absent_table_skips_dependent_query_even_when_name_is_in_sql() {
    let result = run(inventory(), vec![(200, provider(json!([])))]).await;
    assert!(!result.read_complete);
    assert_eq!(result.attempted_queries, 1);
    assert_eq!(result.results[1].classification, "dependency_unsatisfied");
    assert!(result.results[1].receipt.is_none());
}

#[tokio::test]
async fn failed_http_is_not_retried_and_error_material_is_not_returned() {
    for status in [403, 429, 500] {
        let result = run(
            inventory(),
            vec![(
                status,
                json!({"success":false,"errors":[{"message":"PRIVATE_ERROR_MARKER"}]}),
            )],
        )
        .await;
        assert_eq!(result.attempted_queries, 1);
        assert!(!result.read_complete);
        assert!(
            !serde_json::to_string(&result)
                .expect("safe result")
                .contains("PRIVATE_ERROR_MARKER")
        );
    }
}

#[tokio::test]
async fn unexpected_row_types_fields_and_write_metadata_are_refused() {
    for mut body in [
        provider(json!([{"name":"items","secret":"PRIVATE_ROW_MARKER"}])),
        provider(json!([{"name":33}])),
        provider(json!([{"name":"PRIVATE_ROW_MARKER".repeat(100)}])),
    ] {
        body["messages"] = json!([]);
        let result = run(inventory(), vec![(200, body)]).await;
        assert_eq!(result.attempted_queries, 1);
        assert!(!result.read_complete);
        assert!(result.results[0].receipt.is_none());
        assert!(
            !serde_json::to_string(&result)
                .expect("safe result")
                .contains("PRIVATE_ROW_MARKER")
        );
    }
    for key in ["rows_written", "changes", "changed_db", "rows_read"] {
        let mut body = provider(json!([{"name":"items"}]));
        body["result"][0]["meta"]
            .as_object_mut()
            .expect("meta")
            .remove(key);
        assert!(
            !run(inventory(), vec![(200, body)]).await.read_complete,
            "missing {key}"
        );
    }
    for (key, value) in [
        ("rows_written", json!(1)),
        ("changes", json!(1)),
        ("changed_db", json!(true)),
    ] {
        let mut body = provider(json!([{"name":"items"}]));
        body["result"][0]["meta"][key] = value;
        assert!(
            !run(inventory(), vec![(200, body)]).await.read_complete,
            "nonzero {key}"
        );
    }
}

#[tokio::test]
async fn result_bounds_scan_stops_and_generation_drift_stop_later_dispatch() {
    let mut fixture = inventory();
    fixture.limits.stop_after_rows_read = 1;
    let result = run(fixture, vec![(200, provider(json!([{"name":"items"}])))]).await;
    assert_eq!(result.results[1].classification, "row_scan_stop");
    let mut fixture = inventory();
    fixture.queries[0].output.max_rows = 1;
    assert!(
        !run(
            fixture,
            vec![(200, provider(json!([{"name":"items"},{"name":"items"}])))]
        )
        .await
        .read_complete
    );
    let mut fixture = inventory();
    fixture.queries[0].output.max_bytes = 512;
    assert!(
        !run(
            fixture,
            vec![(200, provider(json!([{"name":"x".repeat(2048)}])))]
        )
        .await
        .read_complete
    );
    let (capability, input) = prepared(inventory());
    let validated = validate(&capability, &input).expect("valid");
    let TestServer {
        url, count, handle, ..
    } = server(vec![(200, provider(json!([{"name":"items"}])))]).await;
    let executor = crate::Executor::new(reqwest::Client::new(), &url).expect("executor");
    let mut checks = 0;
    let result = executor
        .execute_d1_read_inventory(
            &validated,
            &AuthCredential::Bearer {
                token: "synthetic-token".into(),
            },
            || {
                checks += 1;
                if checks > 2 {
                    Err(invalid("drift"))
                } else {
                    Ok(())
                }
            },
        )
        .await
        .expect("bounded result");
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert_eq!(
        result.results[1].classification,
        "source_or_credential_drift"
    );
    handle.abort();
}
