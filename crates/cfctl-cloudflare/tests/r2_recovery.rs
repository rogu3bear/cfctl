#![allow(clippy::expect_used, clippy::unwrap_used)]
use cfctl_auth::AuthCredential;
use cfctl_cloudflare::{CallInput, Executor, r2_recovery::CaptureFiles};
use cfctl_core::{
    AdapterStatus, CapabilityV1, EffectClass, RiskClass, SelectorV1,
    r2_recovery::{self as contract, CaptureManifestV1},
};
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use std::{
    fs::{File, OpenOptions},
    os::unix::fs::OpenOptionsExt,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

struct Files(tempfile::TempDir);
impl CaptureFiles for Files {
    fn create_new(&self, name: &str) -> cfctl_cloudflare::Result<File> {
        Ok(OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(self.0.path().join(name))
            .expect("create fixture"))
    }
    fn sync(&self) -> cfctl_cloudflare::Result<()> {
        Ok(())
    }
}

fn capability() -> CapabilityV1 {
    let mut cap = CapabilityV1::new(
        contract::CAPTURE_ID,
        "capture",
        "GET",
        contract::OBJECTS_PATH,
    );
    cap.adapter_status = AdapterStatus::Native;
    cap.risk = RiskClass::Read;
    cap.effect = EffectClass::ReadOnly;
    cap.mutating = false;
    cap.verification.strategy = "r2_private_capture".into();
    cap.permissions = vec!["Workers R2 Storage Read".into()];
    cap.selectors = ["account_id", "bucket_name"]
        .map(|s| SelectorV1 {
            name: s.into(),
            location: "path".into(),
            required: true,
            value_type: "string".into(),
            description: None,
            contract: None,
        })
        .to_vec();
    cap.request_schema = Some(json!({"type":"object"}));
    cap
}

fn input() -> CallInput {
    CallInput {
        selectors: json!({"account_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bucket_name":"private-pdfs"}),
        query: json!({}),
        body: Some(
            json!({"window_id":"11111111-1111-4111-8111-111111111111", "opened_at":Utc::now()-Duration::seconds(1),
            "expires_at":Utc::now()+Duration::seconds(60),"recovery_binding_sha256":"b".repeat(64)}),
        ),
        ..CallInput::default()
    }
}

fn metadata() -> Value {
    json!({"key":"docs/private-example", "size":4, "etag":"content-identity", "last_modified":"2026-09-07T00:00:00Z", "storage_class":"Standard", "custom_metadata":{"owner":"private-owner"}, "unknown_provider_field":{"nested":true}})
}

fn page(rows: Vec<Value>, next: &str, truncated: bool) -> String {
    json!({"success":true,"errors":[],"result":rows,"result_info":{"per_page":100,"delimited":[],"cursor":next,"is_truncated":truncated}}).to_string()
}

fn response(body: &str, extra: &str, status: u16) -> String {
    format!(
        "HTTP/1.1 {status} Result\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n{body}",
        body.len()
    )
}

async fn server(responses: Vec<String>) -> (Executor, tokio::task::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    let job = tokio::spawn(async move {
        let mut requests = Vec::new();
        for response in responses {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut data = vec![0; 8192];
            let count = stream.read(&mut data).await.expect("request");
            requests.push(String::from_utf8_lossy(&data[..count]).to_string());
            stream
                .write_all(response.as_bytes())
                .await
                .expect("response");
        }
        requests
    });
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client");
    (
        Executor::new(client, &format!("http://{address}")).expect("executor"),
        job,
    )
}

fn credential() -> AuthCredential {
    AuthCredential::Bearer {
        token: "fixture-only".into(),
    }
}

#[tokio::test]
async fn captures_bytes_and_all_metadata_without_public_values() {
    let list = page(vec![metadata()], "", false);
    let (executor, job) = server(vec![
        response(&list, "", 200),
        response("%PDF", "ETag: \"content-identity\"\r\n", 200),
        response(&list, "", 200),
    ])
    .await;
    let files = Files(tempfile::tempdir().expect("private fixture"));
    let receipt = executor
        .capture_private_r2_bucket(&capability(), &input(), &credential(), &files)
        .await
        .expect("capture");
    let manifest: CaptureManifestV1 = serde_json::from_slice(
        &std::fs::read(files.0.path().join("manifest.json")).expect("manifest"),
    )
    .expect("decode");
    assert_eq!(manifest.objects[0].provider_metadata, metadata());
    assert!(
        manifest.objects[0]
            .provider_metadata
            .get("http_metadata")
            .is_none()
    );
    assert_eq!(
        std::fs::read(files.0.path().join("object-0000.bin")).expect("blob"),
        b"%PDF"
    );
    assert!(!receipt.recovery_ready);
    assert_eq!(receipt.list_pages, 2);
    let public = serde_json::to_string(&receipt).expect("receipt");
    for private in ["%PDF", "private-owner", "docs/private-example"] {
        assert!(!public.contains(private));
    }
    let requests = job.await.expect("server");
    assert_eq!(requests.len(), 3);
    assert!(
        requests
            .iter()
            .all(|r| r.starts_with("GET ") && !r.contains("recovery_binding_sha256"))
    );
}

#[tokio::test]
async fn refuses_incomplete_duplicate_and_drifting_inventories() {
    let first = page(vec![metadata()], "", false);
    let mut changed = metadata();
    changed["http_metadata"] = json!({"contentType":"application/pdf"});
    let cases = vec![
        vec![
            response(&page(vec![], "repeat", true), "", 200),
            response(&page(vec![], "repeat", true), "", 200),
        ],
        vec![response(
            &json!({"success":true,"errors":[],"result":[],"result_info":null}).to_string(),
            "",
            200,
        )],
        vec![response(
            &page(vec![metadata(), metadata()], "", false),
            "",
            200,
        )],
        vec![
            response(&first, "", 200),
            response("%PDF", "ETag: \"different\"\r\n", 200),
        ],
        vec![
            response(&first, "", 200),
            response("%PDF", "ETag: \"content-identity\"\r\n", 200),
            response(&page(vec![changed], "", false), "", 200),
        ],
        vec![response("provider private error", "", 503)],
    ];
    for responses in cases {
        let count = responses.len();
        let (executor, job) = server(responses).await;
        let files = Files(tempfile::tempdir().expect("private fixture"));
        let error = executor
            .capture_private_r2_bucket(&capability(), &input(), &credential(), &files)
            .await
            .expect_err("must fail");
        assert!(!error.to_string().contains("provider private error"));
        assert!(!files.0.path().join("manifest.json").exists());
        assert_eq!(job.await.expect("server").len(), count);
    }
}

#[tokio::test]
async fn counts_both_passes_against_one_page_budget() {
    let mut responses = Vec::new();
    for n in 1..10 {
        responses.push(response(&page(vec![], &n.to_string(), true), "", 200));
    }
    responses.push(response(&page(vec![], "", false), "", 200));
    let (executor, job) = server(responses).await;
    let files = Files(tempfile::tempdir().expect("private fixture"));
    let error = executor
        .capture_private_r2_bucket(&capability(), &input(), &credential(), &files)
        .await
        .expect_err("second pass has no budget");
    assert!(error.to_string().contains("page budget"));
    assert_eq!(job.await.expect("server").len(), 10);
    assert!(!files.0.path().join("manifest.json").exists());
}

#[tokio::test]
async fn empty_object_and_terminal_empty_bucket_are_qualified_captures_only() {
    let list = page(vec![], "", false);
    let (executor, job) = server(vec![response(&list, "", 200), response(&list, "", 200)]).await;
    let files = Files(tempfile::tempdir().expect("private fixture"));
    let receipt = executor
        .capture_private_r2_bucket(&capability(), &input(), &credential(), &files)
        .await
        .expect("empty capture");
    assert_eq!(receipt.object_count, 0);
    assert_eq!(receipt.total_bytes, 0);
    assert!(!receipt.recovery_ready);
    assert_eq!(job.await.expect("server").len(), 2);
    let mut empty = metadata();
    empty["size"] = json!(0);
    let list = page(vec![empty], "", false);
    let (executor, job) = server(vec![
        response(&list, "", 200),
        response("", "ETag: \"content-identity\"\r\n", 200),
        response(&list, "", 200),
    ])
    .await;
    let files = Files(tempfile::tempdir().expect("private fixture"));
    assert_eq!(
        executor
            .capture_private_r2_bucket(&capability(), &input(), &credential(), &files)
            .await
            .expect("empty object")
            .total_bytes,
        0
    );
    assert_eq!(job.await.expect("server").len(), 3);
}
