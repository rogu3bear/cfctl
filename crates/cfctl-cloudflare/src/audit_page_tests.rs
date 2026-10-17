#![allow(clippy::expect_used, clippy::unwrap_used)]
use super::*;
use cfctl_core::{AdapterStatus, SelectorV1};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

fn fixture() -> (CapabilityV1, super::super::CallInput, AuthCredential) {
    let mut cap = CapabilityV1::new(
        AUDIT_PAGE_ID,
        "audit fixture",
        "GET",
        "/accounts/{account_id}/logs/audit",
    );
    cap.adapter_status = AdapterStatus::Native;
    cap.selectors = ["account_id", "since", "before", "limit", "direction"]
        .into_iter()
        .map(|name| SelectorV1 {
            name: name.into(),
            location: if name == "account_id" {
                "path"
            } else {
                "query"
            }
            .into(),
            required: true,
            value_type: "string".into(),
            description: None,
            contract: None,
        })
        .collect();
    let input = super::super::CallInput {
        selectors: json!({"account_id":"a".repeat(32)}),
        query: json!({"since":"2026-10-17T02:20:52Z","before":"2026-10-17T02:30:52Z","limit":"100","direction":"asc"}),
        ..super::super::CallInput::default()
    };
    (
        cap,
        input,
        AuthCredential::Bearer {
            token: "synthetic-audit-token".into(),
        },
    )
}

struct Server {
    url: String,
    count: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn server(
    status: u16,
    headers: &str,
    body: Vec<u8>,
    delay: Duration,
    chunked: bool,
) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let count = Arc::new(AtomicUsize::new(0));
    let observed = count.clone();
    let headers = headers.to_owned();
    let task = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut request = Vec::new();
            loop {
                let mut part = [0; 1024];
                let n = socket.read(&mut part).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&part[..n]);
                if request.windows(4).any(|v| v == b"\r\n\r\n") {
                    break;
                }
            }
            observed.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(delay).await;
            let framing = if chunked {
                "Transfer-Encoding: chunked\r\n".into()
            } else {
                format!("Content-Length: {}\r\n", body.len())
            };
            let head = format!(
                "HTTP/1.1 {status} fixture\r\nConnection: close\r\nContent-Type: application/json\r\n{headers}{framing}\r\n"
            );
            let _ = socket.write_all(head.as_bytes()).await;
            if chunked {
                let _ = socket
                    .write_all(format!("{:x}\r\n", body.len()).as_bytes())
                    .await;
                let _ = socket.write_all(&body).await;
                let _ = socket.write_all(b"\r\n0\r\n\r\n").await;
            } else {
                let _ = socket.write_all(&body).await;
            }
        }
    });
    Server { url, count, task }
}

async fn read(server: &Server) -> BoundedAuditReadV1 {
    let (cap, input, credential) = fixture();
    let result = execute_bounded_audit_page(&server.url, false, &cap, &input, &credential)
        .await
        .unwrap();
    assert_eq!(server.count.load(Ordering::SeqCst), 1);
    assert_eq!(result.bounds.attempted_requests, 1);
    assert_eq!(result.bounds.window_completeness, "NOT_ESTABLISHED");
    result
}

#[tokio::test]
async fn first_cursor_or_page_is_never_followed() {
    for (info, continuation) in [
        (json!({"cursors":{"after":"next"}}), "PRESENT"),
        (json!({"page":1,"total_pages":20}), "PRESENT"),
        (json!({"count":1}), "NOT_REPORTED"),
    ] {
        let s = server(
            200,
            "",
            serde_json::to_vec(
                &json!({"success":true,"result":[{"id":"event"}],"result_info":info}),
            )
            .unwrap(),
            Duration::ZERO,
            false,
        )
        .await;
        let out = read(&s).await;
        assert!(out.response.success);
        assert_eq!(out.bounds.returned_rows, Some(1));
        assert_eq!(out.bounds.continuation, continuation);
    }
}

#[tokio::test]
async fn redirects_rate_limits_and_server_failures_have_one_request() {
    for status in [301, 302, 307, 308, 429, 500, 503] {
        let s = server(
            status,
            "Location: /second\r\nRetry-After: 0\r\n",
            br#"{"success":false,"errors":[{"code":9109,"message":"fixture denied"}]}"#.to_vec(),
            Duration::ZERO,
            false,
        )
        .await;
        let out = read(&s).await;
        assert!(!out.response.success);
        assert_eq!(out.response.status, status);
        assert_eq!(out.response.errors[0].code, Some(9109));
        assert_eq!(out.bounds.retries, 0);
        assert_eq!(out.bounds.redirects, 0);
    }
}

#[tokio::test]
async fn row_bound_and_malformed_shapes_fail_without_exporting_rows() {
    let bodies = [json!({"success":true,"result":vec![json!({"id":"event"});101]}).to_string(),
        json!({"success":true,"result":{}}).to_string(),
        json!({"success":true,"result":[null]}).to_string(),
        json!({"success":true,"result":[],"result_info":{"page":2,"total_pages":1}}).to_string(),
        json!({"success":true,"result":[],"result_info":{"cursors":{"after":false}}}).to_string(),
        json!({"success":true,"result":[],"result_info":{"cursor":"next","page":2,"total_pages":1}}).to_string(),
        "broken JSON".into()];
    for body in bodies {
        let s = server(200, "", body.into_bytes(), Duration::ZERO, false).await;
        let out = read(&s).await;
        assert!(!out.response.success);
        assert_eq!(out.response.result, Value::Null);
        assert!(out.bounds.failure.is_some());
    }
    let s = server(
        200,
        "",
        serde_json::to_vec(&json!({"success":true,"result":vec![json!({"id":"event"});100]}))
            .unwrap(),
        Duration::ZERO,
        false,
    )
    .await;
    assert!(read(&s).await.response.success);
}

#[tokio::test]
async fn body_ceiling_is_enforced_with_length_and_chunked_transfer() {
    let prefix = b"{\"success\":true,\"result\":[],\"padding\":\"";
    let suffix = b"\"}";
    let mut body = prefix.to_vec();
    body.extend(vec![
        b'x';
        usize::try_from(AUDIT_PAGE_MAX_BYTES)
            .expect("16 MiB fits usize")
            - prefix.len()
            - suffix.len()
    ]);
    body.extend(suffix);
    let s = server(200, "", body.clone(), Duration::ZERO, false).await;
    assert!(read(&s).await.response.success);
    body.push(b' ');
    for chunked in [false, true] {
        let s = server(200, "", body.clone(), Duration::ZERO, chunked).await;
        let out = read(&s).await;
        assert!(!out.response.success);
        assert!(
            out.bounds
                .response_body_bytes
                .is_none_or(|n| n as u64 <= AUDIT_PAGE_MAX_BYTES)
        );
        assert!(out.bounds.response_body_sha256.is_none());
    }
}

#[tokio::test]
async fn encoded_responses_are_not_automatically_decompressed() {
    let s = server(
        200,
        "Content-Encoding: gzip\r\n",
        b"not inspected or decompressed".to_vec(),
        Duration::ZERO,
        false,
    )
    .await;
    let out = read(&s).await;
    assert!(!out.response.success);
    assert_eq!(out.bounds.completed_responses, 0);
}

#[tokio::test]
async fn timeout_and_cancellation_do_not_send_again() {
    let s = server(
        200,
        "",
        br#"{"success":true,"result":[]}"#.to_vec(),
        Duration::from_secs(1),
        false,
    )
    .await;
    let (cap, input, credential) = fixture();
    let out = execute_with_deadline(
        &s.url,
        false,
        &cap,
        &input,
        &credential,
        Duration::from_millis(40),
    )
    .await
    .unwrap();
    assert!(!out.response.success);
    assert_eq!(out.bounds.attempted_requests, 1);
    assert_eq!(s.count.load(Ordering::SeqCst), 1);
    let s = server(200, "", Vec::new(), Duration::from_secs(1), false).await;
    let url = s.url.clone();
    let task = tokio::spawn(async move {
        execute_bounded_audit_page(&url, false, &cap, &input, &credential).await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while s.count.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert_eq!(s.count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn incomplete_and_delayed_chunked_bodies_preserve_unknown_completion() {
    for delayed in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let count = Arc::new(AtomicUsize::new(0));
        let seen = count.clone();
        let task = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0; 4096];
                let _ = socket.read(&mut buf).await;
                seen.fetch_add(1, Ordering::SeqCst);
                if delayed {
                    let _ = socket.write_all(b"HTTP/1.1 200 fixture\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\r\n{\r\n").await;
                    tokio::time::sleep(Duration::from_secs(1)).await;
                } else {
                    let _ = socket.write_all(b"HTTP/1.1 200 fixture\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{\"success\":").await;
                }
            }
        });
        let s = Server { url, count, task };
        let (cap, input, credential) = fixture();
        let out = execute_with_deadline(
            &s.url,
            false,
            &cap,
            &input,
            &credential,
            Duration::from_millis(80),
        )
        .await
        .unwrap();
        assert_eq!(s.count.load(Ordering::SeqCst), 1);
        assert!(!out.response.success);
        assert_eq!(out.bounds.received_responses, 1);
        assert_eq!(out.bounds.completed_responses, 0);
        assert!(out.bounds.response_body_sha256.is_none());
    }
}

#[tokio::test]
async fn production_thirty_second_deadline_is_enforced() {
    let s = server(
        200,
        "",
        br#"{"success":true,"result":[]}"#.to_vec(),
        Duration::from_secs(35),
        false,
    )
    .await;
    let started = std::time::Instant::now();
    let out = read(&s).await;
    assert!(!out.response.success);
    assert_eq!(out.bounds.max_seconds, 30);
    assert!((29_000..=33_000).contains(&out.bounds.elapsed_ms));
    assert!(started.elapsed() < Duration::from_secs(34));
    assert_eq!(out.bounds.completed_responses, 0);
}

#[test]
fn invalid_modes_filters_and_intervals_fail_before_a_sender_exists() {
    let (cap, input, _) = fixture();
    for field in ["page", "cursor", "arbitrary"] {
        let mut input = input.clone();
        input.query[field] = json!("1");
        assert!(validate_audit_page_input(&cap, &input).is_err());
    }
    for limit in [json!(0), json!(101), json!(true), json!("-1")] {
        let mut input = input.clone();
        input.query["limit"] = limit;
        assert!(validate_audit_page_input(&cap, &input).is_err());
    }
    let mut wrong = cap.clone();
    wrong.mutating = true;
    assert!(validate_audit_page_input(&wrong, &input).is_err());
    let mut wrong = input.clone();
    wrong.query["before"] = json!("2026-10-17T02:31:52Z");
    assert!(validate_audit_page_input(&cap, &wrong).is_err());
    let mut wrong = input.clone();
    wrong.query["before"] = wrong.query["since"].clone();
    assert!(validate_audit_page_input(&cap, &wrong).is_err());
}
