#![allow(clippy::expect_used, clippy::unwrap_used)]
use super::*;
use cfctl_core::{
    AdapterStatus, CapabilityV1, EffectClass, ResponseBodyModeV1, ResponseContractV1, RiskClass,
    SelectorV1,
    r2_recovery::{CaptureWindowV1, CapturedObjectV1},
    r2_restore::{CaptureRefV1, CurrentExpectationV1, RestoreRequestV1},
};
use chrono::Duration as ChronoDuration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

fn member(bytes: &[u8], etag: &str, owner: &str) -> CapturedObjectV1 {
    CapturedObjectV1 {
        provider_metadata: json!({"key":"docs/private","size":bytes.len(),"etag":etag,
            "last_modified":"2026-09-07T00:00:00Z","storage_class":"Standard","custom_metadata":{"owner":owner}}),
        blob: "object-0000.bin".into(),
        sha256: hex::encode(Sha256::digest(bytes)),
        byte_count: bytes.len() as u64,
    }
}

fn selection(present: bool) -> RestoreSelectionV1 {
    let capture = || CaptureRefV1 {
        evidence_hash: format!("sha256:{}", "a".repeat(64)),
        run_id: uuid::Uuid::new_v4().to_string(),
    };
    RestoreSelectionV1 {
        schema_version: 1,
        account_id: "a".repeat(32),
        bucket_name: "private-pdfs".into(),
        window: CaptureWindowV1 {
            window_id: uuid::Uuid::new_v4().to_string(),
            opened_at: Utc::now() - ChronoDuration::seconds(1),
            expires_at: Utc::now() + ChronoDuration::seconds(60),
            recovery_binding_sha256: "b".repeat(64),
        },
        request: RestoreRequestV1 {
            source_capture: capture(),
            source_object_index: 0,
            current_capture: capture(),
            expected_current: if present {
                CurrentExpectationV1::Present { object_index: 0 }
            } else {
                CurrentExpectationV1::Absent {}
            },
            token_verification_evidence_hash: format!("sha256:{}", "c".repeat(64)),
            token_policy_evidence_hash: format!("sha256:{}", "d".repeat(64)),
        },
        source: member(b"%PDF", "old-etag", "private-owner"),
        displaced: present.then(|| member(b"CURR", "current-etag", "current-owner")),
    }
}

fn plan(selection: &RestoreSelectionV1) -> (PlanV1, CallInput) {
    let mut cap = CapabilityV1::new(
        contract::RESTORE_ID,
        "fixture",
        "PUT",
        cfctl_core::r2_recovery::OBJECTS_PATH,
    );
    cap.adapter_status = AdapterStatus::Native;
    cap.mutating = true;
    cap.risk = RiskClass::ScopedWrite;
    cap.effect = EffectClass::DataWrite;
    cap.permissions = vec!["Workers R2 Storage Write".into()];
    cap.verification.required = true;
    cap.verification.strategy = contract::STRATEGY.into();
    cap.request_schema = Some(json!({"type":"object"}));
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
    let input = CallInput {
        selectors: json!({"account_id":selection.account_id,"bucket_name":selection.bucket_name}),
        query: json!({}),
        body: Some(serde_json::to_value(&selection.request).expect("request")),
        ..CallInput::default()
    };
    let mut plan =
        PlanV1::draft("fixture", &selection.account_id, "catalog", cap, json!({})).expect("plan");
    plan.input = serde_json::to_value(&input).expect("input");
    plan.status = PlanStatus::Consumed;
    plan.transaction_stage = TransactionStageV1::BoundaryAttemptPersisted;
    (plan, input)
}

fn response(status: u16, body: &str, extra: &str) -> String {
    format!(
        "HTTP/1.1 {status} Result\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n{body}",
        body.len()
    )
}
fn metadata(record: &Value) -> String {
    response(
        200,
        &json!({"success":true,"errors":[],"result":[record],"result_info":null}).to_string(),
        "Content-Type: application/json\r\n",
    )
}
fn object(bytes: &str, etag: &str) -> String {
    // Serving headers can contain a default absent from stored metadata.
    response(
        200,
        bytes,
        &format!("ETag: \"{etag}\"\r\nContent-Type: application/octet-stream\r\n"),
    )
}
fn credential() -> AuthCredential {
    AuthCredential::Bearer {
        token: "synthetic-provider-fixture-only".into(),
    }
}

async fn server(responses: Vec<String>) -> (Executor, tokio::task::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("loopback");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let task = tokio::spawn(async move {
        let mut requests = Vec::new();
        for response in responses {
            let (mut stream, _) = tokio::time::timeout(Duration::from_secs(3), listener.accept())
                .await
                .expect("bounded request")
                .expect("accept");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 8192];
            loop {
                let size = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buffer))
                    .await
                    .expect("bounded input")
                    .expect("read");
                assert!(size > 0);
                request.extend_from_slice(&buffer[..size]);
                assert!(request.len() < 32 * 1024);
                if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&request[..end]);
                    let length = head
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length: ")
                                .and_then(|v| v.parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    if request.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            requests.push(String::from_utf8(request).expect("fixture ASCII"));
            stream
                .write_all(response.as_bytes())
                .await
                .expect("response");
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(40), listener.accept())
                .await
                .is_err(),
            "unexpected retry or extra request"
        );
        requests
    });
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("client");
    let mut executor = Executor::new(client, &origin).expect("executor");
    executor.r2_test_origin = Some(Url::parse(&origin).expect("origin"));
    (executor, task)
}

fn token_capability() -> CapabilityV1 {
    let mut cap = CapabilityV1::new(
        "fixture-token-verify",
        "fixture token metadata",
        "GET",
        contract::TOKEN_VERIFY_PATH,
    );
    cap.account_scope = "account".into();
    cap.adapter_status = AdapterStatus::DynamicApi;
    cap.risk = RiskClass::Read;
    cap.effect = EffectClass::ReadOnly;
    cap.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".into()],
        success_media_types: vec!["application/json".into()],
        body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
    });
    cap
}

#[tokio::test]
async fn rectification_token_read_is_single_request_without_pagination_or_retries() {
    let token = json!({"id":"a".repeat(32),"status":"active"});
    for (status, result, result_info, passed) in [
        (200, token.clone(), Value::Null, true),
        (200, json!([token.clone()]), json!({"cursor":"more"}), false),
        (
            200,
            json!([token.clone()]),
            json!({"page":1,"per_page":1,"total_pages":2,"total_count":2}),
            false,
        ),
        (200, token.clone(), json!({"cursor":"more"}), false),
        (429, token.clone(), Value::Null, false),
        (503, token, Value::Null, false),
    ] {
        let body = json!({"success":true,"errors":[],"result":result,"result_info":result_info});
        let (executor, requests) = server(vec![response(
            status,
            &body.to_string(),
            "Content-Type: application/json\r\n",
        )])
        .await;
        let result = executor
            .execute_r2_restore_token_read(&token_capability(), &"a".repeat(32), &credential())
            .await;
        assert_eq!(result.is_ok(), passed);
        let requests = requests.await.expect("requests");
        assert_eq!(requests.len(), 1);
        assert!(requests[0].starts_with(&format!(
            "GET /accounts/{}/tokens/verify HTTP/1.1",
            "a".repeat(32)
        )));
    }
}

#[tokio::test]
async fn rectification_token_read_refuses_truncation_and_unqualified_targets() {
    let (executor, requests) = server(vec![response(
        200,
        &" ".repeat(64 * 1024 + 1),
        "Content-Type: application/json\r\n",
    )])
    .await;
    assert!(
        executor
            .execute_r2_restore_token_read(&token_capability(), &"a".repeat(32), &credential(),)
            .await
            .is_err()
    );
    assert_eq!(requests.await.expect("bounded response").len(), 1);

    let (executor, requests) = server(vec![]).await;
    let mut cap = token_capability();
    cap.path = "/user/tokens/verify".into();
    assert!(
        executor
            .execute_r2_restore_token_read(&cap, &"a".repeat(32), &credential())
            .await
            .is_err()
    );
    assert!(
        executor
            .execute_r2_restore_token_read(&token_capability(), "wrong-account", &credential())
            .await
            .is_err()
    );
    assert!(requests.await.expect("no requests").is_empty());
}

#[tokio::test]
async fn restores_present_bytes_and_metadata_without_claiming_atomic_metadata() {
    let selection = selection(true);
    let current = &selection
        .displaced
        .as_ref()
        .expect("current")
        .provider_metadata;
    let mut restored = selection.source.provider_metadata.clone();
    restored["etag"] = json!("new-etag");
    let (executor, requests) = server(vec![
        object("CURR", "current-etag"),
        metadata(current),
        response(200, "", "ETag: \"new-etag\"\r\n"),
        object("%PDF", "new-etag"),
        metadata(&restored),
    ])
    .await;
    let (mut plan, input) = plan(&selection);
    let progress = RestoreProgress::default();
    let applied = executor
        .execute_r2_private_restore(
            &mut plan,
            "catalog",
            &input,
            &selection,
            b"%PDF".to_vec(),
            &"1".repeat(32),
            &credential(),
            &progress,
        )
        .await
        .expect("conditional restore");
    assert!(applied.success);
    assert!(
        applied.result["displaced_bytes_preserved"]
            .as_bool()
            .expect("preservation")
    );
    let verified = executor
        .verify_r2_private_restore(&plan, &input, &selection, &"1".repeat(32), &credential())
        .await
        .expect("readback");
    assert!(verified.passed);
    assert_eq!(
        verified.readback.result["metadata_atomic_precondition"],
        false
    );
    assert_eq!(verified.readback.result["combined_recovery_ready"], false);
    let public = format!(
        "{}{}",
        serde_json::to_string(&applied).expect("receipt"),
        serde_json::to_string(&verified).expect("verification")
    );
    for private in [
        "docs/private",
        "private-owner",
        "current-owner",
        "%PDF",
        "CURR",
    ] {
        assert!(!public.contains(private));
    }
    let sent = requests.await.expect("server");
    assert_eq!(sent.len(), 5);
    let put = sent[2].to_ascii_lowercase();
    assert!(put.starts_with("put /private-pdfs/docs/private "));
    assert!(put.contains("if-match: \"current-etag\""));
    assert!(put.contains("x-amz-meta-owner: private-owner"));
    assert!(!put.contains("content-type:"));
    assert!(sent[2].ends_with("%PDF"));
}

#[tokio::test]
async fn absent_condition_and_provider_failure_never_replay_put() {
    for status in [200, 201, 204, 307, 408, 412, 429, 503] {
        let selection = selection(false);
        let (mut plan, input) = plan(&selection);
        let (executor, requests) = server(vec![
            response(404, "", ""),
            response(status, "", "ETag: \"new-etag\"\r\n"),
        ])
        .await;
        let progress = RestoreProgress::default();
        let result = executor
            .execute_r2_private_restore(
                &mut plan,
                "catalog",
                &input,
                &selection,
                b"%PDF".to_vec(),
                &"1".repeat(32),
                &credential(),
                &progress,
            )
            .await;
        if matches!(status, 200 | 412) {
            assert_eq!(result.expect("definitive response").success, status == 200);
        } else {
            assert!(result.is_err());
        }
        assert!(progress.put_attempted());
        assert!(
            executor
                .execute_r2_private_restore(
                    &mut plan,
                    "catalog",
                    &input,
                    &selection,
                    b"%PDF".to_vec(),
                    &"1".repeat(32),
                    &credential(),
                    &RestoreProgress::default(),
                )
                .await
                .is_err(),
            "a returned or uncertain attempt cannot run again"
        );
        let sent = requests.await.expect("server");
        assert_eq!(sent.len(), 2);
        assert!(sent[1].to_ascii_lowercase().contains("if-none-match: *"));
    }
}

#[tokio::test]
async fn current_content_or_etag_drift_stops_before_metadata_or_put() {
    for (body, etag) in [("DRFT", "current-etag"), ("CURR", "changed-etag")] {
        let selection = selection(true);
        let (mut plan, input) = plan(&selection);
        let mut responses = vec![object(body, etag)];
        if etag == "current-etag" {
            responses.push(metadata(
                &selection
                    .displaced
                    .as_ref()
                    .expect("current")
                    .provider_metadata,
            ));
        }
        let expected_requests = responses.len();
        let (executor, requests) = server(responses).await;
        let progress = RestoreProgress::default();
        assert!(
            executor
                .execute_r2_private_restore(
                    &mut plan,
                    "catalog",
                    &input,
                    &selection,
                    b"%PDF".to_vec(),
                    &"1".repeat(32),
                    &credential(),
                    &progress,
                )
                .await
                .is_err()
        );
        assert!(!progress.put_attempted());
        assert_eq!(requests.await.expect("server").len(), expected_requests);
    }
}

#[tokio::test]
async fn source_bytes_and_plan_input_are_bound_before_network_access() {
    for wrong_bytes in [false, true] {
        let selection = selection(false);
        let (mut plan, mut input) = plan(&selection);
        let source = if wrong_bytes { b"EVIL" } else { b"%PDF" };
        if !wrong_bytes {
            input.selectors["bucket_name"] = json!("different-bucket");
        }
        let (executor, requests) = server(vec![]).await;
        let progress = RestoreProgress::default();
        assert!(
            executor
                .execute_r2_private_restore(
                    &mut plan,
                    "catalog",
                    &input,
                    &selection,
                    source.to_vec(),
                    &"1".repeat(32),
                    &credential(),
                    &progress,
                )
                .await
                .is_err()
        );
        assert_eq!(progress.requests(), 0);
        assert!(!progress.put_attempted());
        assert!(requests.await.expect("server").is_empty());
    }
}

#[tokio::test]
async fn successful_put_without_a_strong_etag_remains_uncertain() {
    let selection = selection(false);
    let (mut plan, input) = plan(&selection);
    let (executor, requests) = server(vec![response(404, "", ""), response(200, "", "")]).await;
    let progress = RestoreProgress::default();
    assert!(
        executor
            .execute_r2_private_restore(
                &mut plan,
                "catalog",
                &input,
                &selection,
                b"%PDF".to_vec(),
                &"1".repeat(32),
                &credential(),
                &progress,
            )
            .await
            .is_err()
    );
    assert!(progress.put_attempted());
    assert_eq!(plan.status, PlanStatus::RectificationRequired);
    assert_eq!(requests.await.expect("server").len(), 2);
}

#[tokio::test]
async fn oversized_successful_put_response_is_uncertain_without_replay() {
    let selection = selection(false);
    let (mut plan, input) = plan(&selection);
    let (executor, requests) = server(vec![
        response(404, "", ""),
        response(200, &"x".repeat(16 * 1024 + 1), "ETag: \"new-etag\"\r\n"),
    ])
    .await;
    let progress = RestoreProgress::default();
    assert!(
        executor
            .execute_r2_private_restore(
                &mut plan,
                "catalog",
                &input,
                &selection,
                b"%PDF".to_vec(),
                &"1".repeat(32),
                &credential(),
                &progress,
            )
            .await
            .is_err()
    );
    assert!(progress.put_attempted());
    assert_eq!(plan.status, PlanStatus::RectificationRequired);
    assert_eq!(requests.await.expect("server").len(), 2);
}

#[tokio::test]
async fn same_body_etag_with_changed_metadata_stops_before_put() {
    let selection = selection(true);
    let (mut plan, input) = plan(&selection);
    let mut drifted = selection
        .displaced
        .as_ref()
        .expect("current")
        .provider_metadata
        .clone();
    drifted["custom_metadata"]["owner"] = json!("concurrent-owner");
    let (executor, requests) =
        server(vec![object("CURR", "current-etag"), metadata(&drifted)]).await;
    let progress = RestoreProgress::default();
    assert!(
        executor
            .execute_r2_private_restore(
                &mut plan,
                "catalog",
                &input,
                &selection,
                b"%PDF".to_vec(),
                &"1".repeat(32),
                &credential(),
                &progress
            )
            .await
            .is_err()
    );
    assert!(!progress.put_attempted());
    assert_eq!(requests.await.expect("server").len(), 2);
}

#[tokio::test]
async fn read_only_rectification_accepts_old_window_but_not_metadata_mismatch() {
    let mut selection = selection(false);
    selection.window.opened_at -= ChronoDuration::days(30);
    selection.window.expires_at -= ChronoDuration::days(30);
    let (plan, input) = plan(&selection);
    let mut observed = selection.source.provider_metadata.clone();
    observed["etag"] = json!("new-etag");
    observed["http_metadata"] = json!({"contentType":"application/pdf"});
    let (executor, requests) = server(vec![object("%PDF", "new-etag"), metadata(&observed)]).await;
    let verified = executor
        .verify_r2_private_restore(&plan, &input, &selection, &"1".repeat(32), &credential())
        .await
        .expect("read-only historical target");
    assert!(!verified.passed);
    assert_eq!(requests.await.expect("server").len(), 2);
}

#[tokio::test]
async fn expired_window_or_unconsumed_plan_cannot_contact_provider() {
    for expired in [false, true] {
        let mut selection = selection(false);
        if expired {
            selection.window.opened_at -= ChronoDuration::hours(1);
            selection.window.expires_at -= ChronoDuration::hours(1);
        }
        let (mut plan, input) = plan(&selection);
        if !expired {
            plan.status = PlanStatus::Approved;
        }
        let (executor, requests) = server(vec![]).await;
        let progress = RestoreProgress::default();
        assert!(
            executor
                .execute_r2_private_restore(
                    &mut plan,
                    "catalog",
                    &input,
                    &selection,
                    b"%PDF".to_vec(),
                    &"1".repeat(32),
                    &credential(),
                    &progress
                )
                .await
                .is_err()
        );
        assert_eq!(progress.requests(), 0);
        assert!(requests.await.expect("server").is_empty());
    }
}
