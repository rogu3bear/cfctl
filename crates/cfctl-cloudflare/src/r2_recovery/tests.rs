#![allow(clippy::expect_used, clippy::unwrap_used)]
use super::*;
use std::os::unix::fs::OpenOptionsExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
const CANARY: &str = "private-r2-diagnostic-canary";
const TOKEN_ID: &str = "0123456789abcdef0123456789abcdef";
const NS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";
fn credential() -> AuthCredential {
    AuthCredential::Bearer {
        token: CANARY.into(),
    }
}
fn wire(status: u16, body: &str, extra: &str) -> String {
    format!(
        "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n{body}",
        body.len()
    )
}
fn xml(rows: &str, fields: &str) -> String {
    format!(
        "<ListBucketResult xmlns=\"{NS}\"><Name>fixture-bucket</Name><EncodingType>url</EncodingType>{rows}{fields}</ListBucketResult>"
    )
}
fn listing(rows: &str, fields: &str) -> String {
    wire(200, &xml(rows, fields), "")
}
fn terminal() -> &'static str {
    "<IsTruncated>false</IsTruncated>"
}
fn row(key: &str, size: u64) -> String {
    format!(
        "<Contents><Key>{key}</Key><ETag>&quot;one&quot;</ETag><Size>{size}</Size><LastModified>2026-09-07T00:00:00Z</LastModified><StorageClass>STANDARD</StorageClass></Contents>"
    )
}
fn record(key: &str, size: u64) -> Value {
    json!({"key":key,"size":size,"etag":"one","last_modified":"2026-09-07T00:00:00Z","storage_class":"Standard", "custom_metadata":{"private-owner":"opaque"},"unknown_field":{"retained":true}})
}
fn metadata(rows: Vec<Value>) -> String {
    wire(
        200,
        &json!({"success":true,"errors":[],"result":rows,"result_info":null}).to_string(),
        "",
    )
}
async fn server(responses: Vec<String>) -> (Executor, tokio::task::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let mut requests = Vec::new();
        for response in responses {
            let (mut stream, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let mut bytes = Vec::new();
            let mut buf = [0; 4096];
            while !bytes.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = stream.read(&mut buf).await.unwrap();
                assert!(n > 0 && bytes.len() < 32768);
                bytes.extend_from_slice(&buf[..n]);
            }
            requests.push(String::from_utf8(bytes).unwrap());
            let _ = stream.write_all(response.as_bytes()).await;
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(40), listener.accept())
                .await
                .is_err(),
            "unexpected retry/request"
        );
        requests
    });
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .build()
        .unwrap();
    let mut executor = Executor::new(client, &origin).unwrap();
    executor.r2_test_origin = Some(url::Url::parse(&origin).unwrap());
    (executor, task)
}
struct Files {
    root: tempfile::TempDir,
    fail: bool,
}
impl Files {
    fn new(fail: bool) -> Self {
        Self {
            root: tempfile::tempdir().unwrap(),
            fail,
        }
    }
}
impl CaptureFiles for Files {
    fn create_new(&self, name: &str) -> Result<File> {
        if self.fail {
            return Err(failure(CANARY));
        }
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.root.path().join(name))
            .map_err(io_failure)
    }
    fn sync(&self) -> Result<()> {
        Ok(())
    }
}
fn capability() -> CapabilityV1 {
    let mut cap = CapabilityV1::new(
        contract::CAPTURE_ID,
        "fixture",
        "GET",
        contract::OBJECTS_PATH,
    );
    cap.adapter_status = cfctl_core::AdapterStatus::Native;
    cap.permissions = vec!["Workers R2 Storage Read".into()];
    cap.verification.strategy = "r2_private_capture".into();
    cap.selectors = ["account_id", "bucket_name"]
        .map(|name| SelectorV1 {
            name: name.into(),
            location: "path".into(),
            required: true,
            value_type: "string".into(),
            description: None,
            contract: None,
        })
        .to_vec();
    cap
}
fn input() -> CallInput {
    CallInput {
        selectors: json!({"account_id":"a".repeat(32),"bucket_name":"fixture-bucket"}),
        query: json!({}),
        body: Some(json!({"schema_version":2,"window":CaptureWindowV1 {
            window_id:Uuid::new_v4().to_string(), opened_at:Utc::now()-chrono::Duration::seconds(1),
            expires_at:Utc::now()+chrono::Duration::seconds(60),recovery_binding_sha256:"b".repeat(64)
        },"token_verification_evidence_hash":format!("sha256:{}","c".repeat(64)),"token_policy_evidence_hash":format!("sha256:{}","d".repeat(64))})),
        ..CallInput::default()
    }
}
fn diagnostic(
    progress: &CaptureProgress,
    stage: &str,
    reason: &str,
    count: u32,
    status: Option<u16>,
) {
    let value = serde_json::to_value(progress.diagnostic()).unwrap();
    assert_eq!(
        value,
        json!({"stage":stage,"reason":reason,"request_ordinal":count,"provider_http_status":status})
    );
    assert!(!value.to_string().contains(CANARY));
}
async fn fails(responses: Vec<String>, stage: &str, reason: &str) {
    let count = responses.len();
    let (executor, job) = server(responses).await;
    let progress = CaptureProgress::default();
    let files = Files::new(false);
    let error = Box::pin(executor.capture_private_r2_bucket_with_progress(
        &capability(),
        &input(),
        &credential(),
        TOKEN_ID,
        &files,
        &progress,
    ))
    .await
    .unwrap_err();
    assert!(!error.to_string().contains(CANARY));
    assert!(!files.root.path().join("manifest.json").exists());
    diagnostic(
        &progress,
        stage,
        reason,
        u32::try_from(count).unwrap(),
        Some(200),
    );
    assert_eq!(job.await.unwrap().len(), count);
}

#[tokio::test]
async fn captures_empty_and_populated_buckets_with_complete_private_metadata() {
    for size in [None, Some(0), Some(4)] {
        let rows = size.map_or_else(String::new, |n| row(CANARY, n));
        let mut responses = vec![listing(&rows, terminal())];
        let body = if size == Some(0) { "" } else { "data" };
        if let Some(n) = size {
            // A bounded collateral prefix record is allowed. result_info=null
            // never acts as a terminal signal for positive membership.
            responses.push(metadata(vec![
                record(&format!("{CANARY}-collateral"), 1),
                record(CANARY, n),
            ]));
            responses.push(wire(200, body, "ETag: \"one\"\r\n"));
        }
        responses.push(listing(&rows, terminal()));
        if let Some(n) = size {
            responses.push(metadata(vec![record(CANARY, n)]));
        }
        let (executor, job) = server(responses).await;
        let files = Files::new(false);
        let receipt = executor
            .capture_private_r2_bucket(&capability(), &input(), &credential(), TOKEN_ID, &files)
            .await
            .unwrap();
        assert_eq!(receipt.list_pages, 2);
        assert_eq!(receipt.total_bytes, size.unwrap_or(0));
        assert!(!receipt.recovery_ready);
        let manifest: CaptureManifestV1 = serde_json::from_slice(
            &std::fs::read(files.root.path().join("manifest.json")).unwrap(),
        )
        .unwrap();
        if let Some(n) = size {
            assert_eq!(manifest.objects[0].provider_metadata, record(CANARY, n));
            assert_eq!(
                std::fs::read(files.root.path().join("object-0000.bin")).unwrap(),
                body.as_bytes()
            );
        }
        let public = serde_json::to_string(&receipt).unwrap();
        for private in [CANARY, "private-owner", "opaque"] {
            assert!(!public.contains(private));
        }
        let requests = job.await.unwrap();
        assert_eq!(requests.len(), if size.is_some() { 5 } else { 2 });
        assert!(requests[0].starts_with(
            "GET /fixture-bucket?encoding-type=url&list-type=2&max-keys=100 HTTP/1.1"
        ));
        assert!(requests[0].contains("AWS4-HMAC-SHA256 Credential="));
        assert!(!requests[0].contains(CANARY));
        assert!(
            requests
                .iter()
                .all(|r| !r.contains("recovery_binding_sha256"))
        );
    }
}

#[tokio::test]
async fn rejects_metadata_only_drift_and_join_mismatches_without_success_receipt() {
    let first = listing(&row(CANARY, 4), terminal());
    let mut changed = record(CANARY, 4);
    changed["http_metadata"] = Value::Null; // absent and null differ
    fails(
        vec![
            first.clone(),
            metadata(vec![record(CANARY, 4)]),
            wire(200, "data", "ETag: \"one\"\r\n"),
            first.clone(),
            metadata(vec![changed]),
        ],
        "final_metadata",
        "inventory_drift",
    )
    .await;
    for (field, value) in [
        ("etag", json!("other")),
        ("size", json!(3)),
        ("last_modified", json!("2026-09-07T00:00:01Z")),
        ("storage_class", json!("InfrequentAccess")),
    ] {
        let mut record = record(CANARY, 4);
        record[field] = value;
        fails(
            vec![first.clone(), metadata(vec![record])],
            "initial_metadata",
            "object_identity",
        )
        .await;
    }
    for rows in [vec![], vec![record(CANARY, 4), record(CANARY, 4)]] {
        fails(
            vec![first.clone(), metadata(rows)],
            "initial_metadata",
            "object_metadata",
        )
        .await;
    }
    fails(
        vec![
            first.clone(),
            metadata(vec![record(CANARY, 4)]),
            wire(200, "data", "ETag: \"other\"\r\n"),
        ],
        "object_read",
        "object_identity",
    )
    .await;
    fails(
        vec![listing("", terminal()), first],
        "final_inventory",
        "inventory_drift",
    )
    .await;
}

#[tokio::test]
async fn signed_cursor_is_opaque_and_both_inventories_share_page_budget() {
    let cursor = "opaque /+%=雪";
    let truncated = format!(
        "<IsTruncated>true</IsTruncated><NextContinuationToken>{cursor}</NextContinuationToken>"
    );
    let (executor, job) = server(vec![
        listing("", &truncated),
        listing("", terminal()),
        listing("", terminal()),
    ])
    .await;
    executor
        .capture_private_r2_bucket(
            &capability(),
            &input(),
            &credential(),
            TOKEN_ID,
            &Files::new(false),
        )
        .await
        .unwrap();
    let requests = job.await.unwrap();
    assert!(requests[1].starts_with("GET /fixture-bucket?continuation-token=opaque%20%2F%2B%25%3D%E9%9B%AA&encoding-type=url&list-type=2&max-keys=100 "));
    fails(
        vec![listing("", &truncated), listing("", &truncated)],
        "initial_inventory",
        "pagination_terminal",
    )
    .await;
    let responses = (1..=10)
        .map(|n| {
            listing(
                "",
                &format!(
                    "<IsTruncated>{}</IsTruncated>{}",
                    n != 10,
                    if n == 10 {
                        String::new()
                    } else {
                        format!("<NextContinuationToken>{n}</NextContinuationToken>")
                    }
                ),
            )
        })
        .collect();
    fails(responses, "final_inventory", "pagination_bounds").await;
}

#[test]
fn strict_xml_accepts_optional_echoes_namespaces_empty_elements_and_encoded_keys() {
    let progress = CaptureProgress::default();
    let key = "docs/雪 %2F+";
    let source = xml(
        &row("docs%2F%E9%9B%AA%20%252F%2B", 4),
        &format!(
            "{}<Prefix/><KeyCount>1</KeyCount><MaxKeys>100</MaxKeys>",
            terminal()
        ),
    );
    let parsed = s3_inventory::parse(source.as_bytes(), "fixture-bucket", None, &progress).unwrap();
    assert!(parsed.rows[0].matches(&record(key, 4)));
    let prefixed = source
        .replace("xmlns=", "xmlns:s=")
        .replace('<', "<s:")
        .replace("<s:/", "</s:");
    s3_inventory::parse(
        format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>{prefixed}").as_bytes(),
        "fixture-bucket",
        None,
        &progress,
    )
    .unwrap();
    // XML document version, manifest version, and list-type=2 are independent.
    assert!(
        s3_inventory::parse(
            xml("", terminal()).as_bytes(),
            "fixture-bucket",
            None,
            &progress
        )
        .is_ok()
    );
}

#[test]
fn strict_xml_rejects_ambiguous_unsupported_and_nonterminal_shapes() {
    let basic = xml("", terminal());
    let cases = vec![
        basic.replace(terminal(), ""),
        basic.replace("false", "maybe"),
        basic.replace(terminal(), "<IsTruncated>true</IsTruncated>"),
        basic.replace(
            terminal(),
            "<IsTruncated>false</IsTruncated><NextContinuationToken>extra</NextContinuationToken>",
        ),
        basic.replace(
            terminal(),
            "<IsTruncated>false</IsTruncated><IsTruncated>false</IsTruncated>",
        ),
        basic.replace(
            terminal(),
            "<CommonPrefixes/><IsTruncated>false</IsTruncated>",
        ),
        basic.replace(NS, "urn:wrong"),
        format!("{basic}{basic}"),
        format!("<!DOCTYPE x [<!ENTITY e 'secret'>]>{basic}"),
        basic.replace("fixture-bucket", "&custom;"),
        xml(&row("bad%XX", 4), terminal()),
        xml(&row("bad%FF", 4), terminal()),
        xml(
            &row("key", 4).replace("<Size>4</Size>", "<Size>4</Size><Size>4</Size>"),
            terminal(),
        ),
        xml("", &format!("{}<KeyCount>1</KeyCount>", terminal())),
        xml("", &format!("{}<MaxKeys>1000</MaxKeys>", terminal())),
        xml(
            "",
            &format!(
                "{}<ContinuationToken>unsent</ContinuationToken>",
                terminal()
            ),
        ),
    ];
    for source in cases {
        assert!(
            s3_inventory::parse(
                source.as_bytes(),
                "fixture-bucket",
                None,
                &CaptureProgress::default()
            )
            .is_err(),
            "{source}"
        );
    }
}

#[tokio::test]
async fn rejects_duplicate_inventory_keys_and_nested_metadata_json_keys() {
    fails(
        vec![listing(
            &format!("{}{}", row(CANARY, 4), row(CANARY, 4)),
            terminal(),
        )],
        "initial_inventory",
        "population_bounds",
    )
    .await;
    let duplicate = metadata(vec![record(CANARY, 4)])
        .replace("\"retained\":true", "\"retained\":true,\"retained\":false");
    // Reframe body because duplicate insertion changes Content-Length.
    let body = duplicate.split("\r\n\r\n").nth(1).unwrap();
    fails(
        vec![listing(&row(CANARY, 4), terminal()), wire(200, body, "")],
        "initial_metadata",
        "json",
    )
    .await;
}

#[tokio::test]
async fn errors_and_timeout_preserve_exact_request_status_without_retry() {
    for (response, reason, status) in [
        (wire(503, CANARY, ""), "http_response", 503),
        (
            wire(302, CANARY, "Location: /other\r\n"),
            "http_response",
            302,
        ),
        (wire(200, CANARY, ""), "xml", 200),
        (
            wire(200, &"x".repeat(2 * 1024 * 1024 + 1), ""),
            "body_limit",
            200,
        ),
        (
            "HTTP/1.1 200 OK\r\nContent-Length: 999\r\nConnection: close\r\n\r\nshort".into(),
            "body_read",
            200,
        ),
    ] {
        let (executor, job) = server(vec![response]).await;
        let progress = CaptureProgress::default();
        assert!(
            executor
                .capture_private_r2_bucket_with_progress(
                    &capability(),
                    &input(),
                    &credential(),
                    TOKEN_ID,
                    &Files::new(false),
                    &progress
                )
                .await
                .is_err()
        );
        diagnostic(&progress, "initial_inventory", reason, 1, Some(status));
        job.await.unwrap();
    }
    let (executor, job) = server(vec![listing("", terminal())]).await;
    let progress = CaptureProgress::default();
    let transport = executor.private_r2_transport();
    let credential = credential();
    let context = inventory::InventoryContext {
        transport: &transport,
        account: &"a".repeat(32),
        bucket: "fixture-bucket",
        token_id: TOKEN_ID,
        credential: &credential,
        progress: &progress,
    };
    context
        .read(&mut inventory::Budget::default())
        .await
        .unwrap();
    job.await.unwrap();
    progress.stage(CaptureStage::FinalInventory);
    assert!(
        context
            .read(&mut inventory::Budget::default())
            .await
            .is_err()
    );
    diagnostic(&progress, "final_inventory", "transport", 2, None);
}

#[tokio::test]
async fn window_timeout_and_storage_failure_never_issue_complete_receipt() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let job = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        drop(stream);
    });
    let mut executor = Executor::new(reqwest::Client::new(), &origin).unwrap();
    executor.r2_test_origin = Some(url::Url::parse(&origin).unwrap());
    let mut request = input();
    request.body.as_mut().unwrap()["window"]["expires_at"] =
        json!(Utc::now() + chrono::Duration::milliseconds(300));
    let progress = CaptureProgress::default();
    assert!(
        executor
            .capture_private_r2_bucket_with_progress(
                &capability(),
                &request,
                &credential(),
                TOKEN_ID,
                &Files::new(false),
                &progress
            )
            .await
            .is_err()
    );
    diagnostic(&progress, "initial_inventory", "window_expired", 1, None);
    job.abort();
    let (executor, job) = server(vec![listing("", terminal()), listing("", terminal())]).await;
    let progress = CaptureProgress::default();
    assert!(
        executor
            .capture_private_r2_bucket_with_progress(
                &capability(),
                &input(),
                &credential(),
                TOKEN_ID,
                &Files::new(true),
                &progress
            )
            .await
            .is_err()
    );
    diagnostic(&progress, "manifest", "storage", 2, Some(200));
    job.await.unwrap();
}

#[tokio::test]
async fn exhausted_shared_budgets_stop_before_another_request() {
    let (executor, job) = server(vec![]).await;
    let progress = CaptureProgress::default();
    let transport = executor.private_r2_transport();
    let token = credential();
    let context = inventory::InventoryContext {
        transport: &transport,
        account: &"a".repeat(32),
        bucket: "fixture-bucket",
        token_id: TOKEN_ID,
        credential: &token,
        progress: &progress,
    };
    let mut budget = inventory::Budget {
        xml_bytes: contract::MAX_XML_BYTES,
        ..Default::default()
    };
    assert!(context.read(&mut budget).await.is_err());
    assert_eq!(progress.requests(), 0);
    progress.update(|d| d.request_ordinal = contract::MAX_REQUESTS);
    assert!(progress.begin_request().is_err());
    assert_eq!(progress.requests(), contract::MAX_REQUESTS);
    assert!(job.await.unwrap().is_empty());
}

#[tokio::test]
async fn metadata_aggregate_and_body_size_fail_closed() {
    let (executor, job) = server(vec![wire(200, "data", "")]).await;
    let transport = executor.private_r2_transport();
    let response = transport
        .list(
            &"a".repeat(32),
            "fixture-bucket",
            None,
            TOKEN_ID,
            &credential(),
        )
        .await
        .unwrap();
    let mut bytes = contract::MAX_METADATA_BYTES - 2;
    assert!(
        inventory::bounded_response(
            response,
            &mut bytes,
            contract::MAX_METADATA_BYTES,
            &CaptureProgress::default()
        )
        .await
        .is_err()
    );
    job.await.unwrap();
    fails(
        vec![
            listing(&row(CANARY, 4), terminal()),
            metadata(vec![record(CANARY, 4)]),
            wire(200, "too-long", "ETag: \"one\"\r\n"),
        ],
        "object_read",
        "object_identity",
    )
    .await;
    let source = xml(
        &row("archive", 0).replace("STANDARD", "STANDARD_IA"),
        terminal(),
    );
    let parsed = s3_inventory::parse(
        source.as_bytes(),
        "fixture-bucket",
        None,
        &CaptureProgress::default(),
    )
    .unwrap();
    let mut metadata = record("archive", 0);
    metadata["storage_class"] = json!("InfrequentAccess");
    assert!(parsed.rows[0].matches(&metadata));
}
