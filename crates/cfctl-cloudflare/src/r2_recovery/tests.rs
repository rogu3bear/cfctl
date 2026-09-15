#![allow(clippy::expect_used, clippy::unwrap_used)]
use super::*;
use std::os::unix::fs::OpenOptionsExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

const CANARY: &str = "private-r2-diagnostic-canary";

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

fn page(rows: Value, info: Value) -> String {
    wire(
        200,
        &json!({"success":true,"errors":[],"result":rows,"result_info":info}).to_string(),
        "",
    )
}

fn terminal() -> Value {
    json!({"per_page":100,"delimited":[],"cursor":"","is_truncated":false})
}

fn record() -> Value {
    json!({"key":CANARY,"size":4,"etag":"one","last_modified":"2026-09-07T00:00:00Z","storage_class":"Standard"})
}

async fn server(responses: Vec<String>) -> (Executor, url::Url, tokio::task::JoinHandle<usize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let url = url::Url::parse(&format!("{origin}/objects")).expect("URL");
    let count = responses.len();
    let task = tokio::spawn(async move {
        for response in responses {
            let (mut stream, _) = tokio::time::timeout(Duration::from_secs(3), listener.accept())
                .await
                .expect("request deadline")
                .expect("accept");
            let mut bytes = Vec::new();
            let mut buf = [0; 4096];
            while !bytes.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf))
                    .await
                    .expect("read deadline")
                    .expect("read");
                assert!(n > 0 && bytes.len() < 16384);
                bytes.extend_from_slice(&buf[..n]);
            }
            // Oversize response tests may intentionally close the reader early.
            let _ = stream.write_all(response.as_bytes()).await;
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(40), listener.accept())
                .await
                .is_err(),
            "unexpected retry or extra request"
        );
        count
    });
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .build()
        .expect("client");
    (Executor::new(client, &origin).expect("executor"), url, task)
}

fn assert_diagnostic(
    progress: &CaptureProgress,
    stage: &str,
    reason: &str,
    ordinal: u32,
    status: Option<u16>,
) {
    let value = serde_json::to_value(progress.diagnostic()).expect("safe diagnostic");
    assert_eq!(
        value,
        json!({"stage":stage,"reason":reason,"request_ordinal":ordinal,"provider_http_status":status})
    );
    assert!(!value.to_string().contains(CANARY));
}

#[tokio::test]
async fn initial_inventory_failure_categories_keep_provider_values_private() {
    let mut missing = terminal();
    missing.as_object_mut().expect("info").remove("cursor");
    let mut contradictory = terminal();
    contradictory["cursor"] = json!(CANARY);
    let mut delimited = terminal();
    delimited["delimited"] = json!([CANARY]);
    let mut false_page = terminal();
    false_page["is_truncated"] = json!(true);
    let mut missing_per_page = terminal();
    missing_per_page
        .as_object_mut()
        .expect("info")
        .remove("per_page");
    let cases = vec![
        (wire(503, CANARY, ""), "http_response", 503),
        (
            wire(302, CANARY, "Location: /do-not-follow\r\n"),
            "http_response",
            302,
        ),
        (wire(200, CANARY, ""), "json", 200),
        (
            "HTTP/1.1 200 OK\r\nContent-Length: 999\r\nConnection: close\r\n\r\nshort".into(),
            "body_read",
            200,
        ),
        (
            wire(200, &"x".repeat(2 * 1024 * 1024 + 1), ""),
            "body_limit",
            200,
        ),
        (
            wire(
                200,
                &json!({"success":false,"errors":[{"message":CANARY}],"result":[]}).to_string(),
                "",
            ),
            "envelope",
            200,
        ),
        (
            wire(
                200,
                &json!({"success":true,"errors":[],"result":[]}).to_string(),
                "",
            ),
            "pagination_metadata",
            200,
        ),
        (page(json!([]), Value::Null), "pagination_metadata", 200),
        (
            page(json!([]), missing_per_page),
            "pagination_metadata",
            200,
        ),
        (page(json!([]), delimited), "pagination_metadata", 200),
        (page(json!([]), missing), "pagination_cursor", 200),
        (page(json!([]), contradictory), "pagination_terminal", 200),
        (page(json!([]), false_page), "pagination_terminal", 200),
        (
            page(json!([{"key":CANARY}]), terminal()),
            "object_metadata",
            200,
        ),
    ];
    for (response, reason, status) in cases {
        let (executor, url, task) = server(vec![response]).await;
        let progress = CaptureProgress::default();
        progress.stage(CaptureStage::InitialInventory);
        assert!(
            executor
                .capture_r2_inventory(&url, &credential(), &mut 0, &progress)
                .await
                .is_err(),
            "{reason}"
        );
        assert_diagnostic(&progress, "initial_inventory", reason, 1, Some(status));
        assert_eq!(task.await.expect("server"), 1);
    }
}

#[tokio::test]
async fn later_transport_failure_clears_prior_http_status_and_never_retries() {
    let (executor, url, task) = server(vec![page(json!([]), terminal())]).await;
    let progress = CaptureProgress::default();
    progress.stage(CaptureStage::InitialInventory);
    executor
        .capture_r2_inventory(&url, &credential(), &mut 0, &progress)
        .await
        .expect("first read");
    task.await.expect("server closes listener");
    progress.stage(CaptureStage::FinalInventory);
    assert!(
        executor
            .capture_r2_inventory(&url, &credential(), &mut 1, &progress)
            .await
            .is_err()
    );
    assert_diagnostic(&progress, "final_inventory", "transport", 2, None);
}

#[tokio::test]
async fn explicit_pagination_completes_but_repeated_cursor_fails() {
    let truncated = json!({"per_page":100,"delimited":[],"cursor":CANARY,"is_truncated":true});
    for repeated in [false, true] {
        let last = if repeated {
            truncated.clone()
        } else {
            terminal()
        };
        let (executor, url, task) = server(vec![
            page(json!([]), truncated.clone()),
            page(json!([]), last),
        ])
        .await;
        let progress = CaptureProgress::default();
        progress.stage(CaptureStage::InitialInventory);
        let mut pages = 0;
        let result = executor
            .capture_r2_inventory(&url, &credential(), &mut pages, &progress)
            .await;
        assert_eq!(result.is_ok(), !repeated);
        assert_eq!(pages, 2);
        if repeated {
            assert_diagnostic(
                &progress,
                "initial_inventory",
                "pagination_terminal",
                2,
                Some(200),
            );
        }
        assert_eq!(task.await.expect("server"), 2);
    }
}

struct Files {
    root: tempfile::TempDir,
    fail: bool,
}
impl Files {
    fn new(fail: bool) -> Self {
        Self {
            root: tempfile::tempdir().expect("files"),
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
        body: Some(json!(CaptureWindowV1 {
            window_id: Uuid::new_v4().to_string(),
            opened_at: Utc::now() - chrono::Duration::seconds(1),
            expires_at: Utc::now() + chrono::Duration::seconds(60),
            recovery_binding_sha256: "b".repeat(64)
        })),
        ..CallInput::default()
    }
}

#[tokio::test]
async fn empty_and_populated_captures_still_require_second_inventory_and_manifest() {
    for populated in [false, true] {
        let rows = if populated {
            json!([record()])
        } else {
            json!([])
        };
        let mut responses = vec![page(rows.clone(), terminal())];
        if populated {
            responses.push(wire(200, "data", "ETag: \"one\"\r\n"));
        }
        responses.push(page(rows, terminal()));
        let count = responses.len();
        let (executor, _, task) = server(responses).await;
        let progress = CaptureProgress::default();
        let files = Files::new(false);
        let receipt = executor
            .capture_private_r2_bucket_with_progress(
                &capability(),
                &input(),
                &credential(),
                &files,
                &progress,
            )
            .await
            .expect("complete capture");
        assert_eq!(receipt.list_pages, 2);
        assert!(files.root.path().join("manifest.json").exists());
        assert_eq!(task.await.expect("server"), count);
    }
}

#[tokio::test]
async fn second_inventory_drift_and_storage_failures_remain_incomplete() {
    let cases = vec![
        (
            vec![
                page(json!([]), terminal()),
                page(json!([record()]), terminal()),
            ],
            false,
            "final_inventory",
            "inventory_drift",
            2,
        ),
        (
            vec![page(json!([]), terminal()), page(json!([]), terminal())],
            true,
            "manifest",
            "storage",
            2,
        ),
        (
            vec![
                page(json!([record()]), terminal()),
                wire(200, "data", "ETag: \"wrong\"\r\n"),
            ],
            false,
            "object_read",
            "object_identity",
            2,
        ),
        (
            vec![
                page(json!([record()]), terminal()),
                wire(200, "data", "ETag: \"one\"\r\n"),
            ],
            true,
            "object_read",
            "storage",
            2,
        ),
    ];
    for (responses, fail, stage, reason, count) in cases {
        let (executor, _, task) = server(responses).await;
        let progress = CaptureProgress::default();
        let files = Files::new(fail);
        assert!(
            executor
                .capture_private_r2_bucket_with_progress(
                    &capability(),
                    &input(),
                    &credential(),
                    &files,
                    &progress
                )
                .await
                .is_err()
        );
        assert_diagnostic(&progress, stage, reason, count, Some(200));
        assert!(!files.root.path().join("manifest.json").exists());
        assert_eq!(task.await.expect("server"), count as usize);
    }
}

#[tokio::test]
async fn window_timeout_reports_active_phase_without_inventing_http_status() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        tokio::time::sleep(Duration::from_secs(2)).await;
        drop(stream);
    });
    let executor = Executor::new(reqwest::Client::new(), &origin).expect("executor");
    let mut input = input();
    input.body.as_mut().expect("window")["expires_at"] =
        json!(Utc::now() + chrono::Duration::milliseconds(500));
    let progress = CaptureProgress::default();
    assert!(
        executor
            .capture_private_r2_bucket_with_progress(
                &capability(),
                &input,
                &credential(),
                &Files::new(false),
                &progress
            )
            .await
            .is_err()
    );
    assert_diagnostic(&progress, "initial_inventory", "window_expired", 1, None);
    task.abort();
}
