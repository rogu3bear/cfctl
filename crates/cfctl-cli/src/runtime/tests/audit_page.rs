use super::*;
use crate::source_checkout::SourceCheckoutArgs;
use clap::Parser as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

fn arguments() -> CallArgs {
    CallArgs {
        max_pages: Some(1),
        source_checkout: SourceCheckoutArgs::default(),
        capability_id: cfctl_cloudflare::AUDIT_PAGE_ID.into(),
        selectors: vec![("account_id".into(), "a".repeat(32))],
        query: [
            ("since", "2026-10-17T02:20:52Z"),
            ("before", "2026-10-17T02:30:52Z"),
            ("limit", "100"),
            ("direction", "asc"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect(),
        profile: Some("fixture".into()),
        account: Some("a".repeat(32)),
        body_json: None,
        body_stdin: false,
        if_match: None,
        if_none_match: None,
        value_out: None,
        credential_in: None,
        out: None,
        source_file: None,
    }
}

fn catalog() -> CatalogSnapshot {
    let mut cap = CapabilityV1::new(
        cfctl_cloudflare::AUDIT_PAGE_ID,
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
    let mut catalog = test_catalog();
    catalog.capabilities.insert(cap.id.clone(), cap);
    catalog.refresh_hash().expect("catalog hash");
    catalog
}

fn fixture(private: bool) -> (tempfile::TempDir, StorageStateStore) {
    let root = tempfile::tempdir().expect("isolated runtime");
    let paths =
        RuntimePaths::from_root(&root.path().canonicalize().expect("physical fixture root"));
    if private {
        fs::create_dir_all(&paths.data_dir).expect("private data");
        fs::set_permissions(&paths.data_dir, fs::Permissions::from_mode(0o700))
            .expect("private directory");
        cfctl_storage::PrivateDirectory::create(&paths.data_dir.join("auth"))
            .expect("private fixture auth directory");
        cfctl_storage::PrivateDirectory::create(&paths.data_dir.join("auth/secrets"))
            .expect("private fixture secret directory");
        let marker = cfctl_storage::ArchivedRuntimeV1 {
            schema_version: 1,
            epoch_id: Uuid::new_v4().to_string(),
            config_dir: paths.config_dir.clone(),
            data_dir: paths.data_dir.clone(),
            cache_dir: paths.cache_dir.clone(),
            continuity: "unavailable_fresh_authority".into(),
        };
        let path = paths.data_dir.join(cfctl_storage::PRIVATE_MODE_FILE);
        fs::write(&path, serde_json::to_vec(&marker).expect("marker json"))
            .expect("fixture marker");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("private marker");
    }
    let store = StateStore::open(paths).expect("state store");
    store
        .write_json(&store.paths().catalog_file(), &catalog())
        .expect("cached catalog");
    let mut profiles = ProfilesConfig::default();
    profiles.profiles.insert(
        "fixture".into(),
        ProfileMetadata::new("fixture", ProfileKind::ApiToken, Some(&"a".repeat(32))),
    );
    profiles.current_profile = Some("fixture".into());
    profiles.save(&store).expect("fixture profiles");
    // No credential is installed until a test explicitly needs its loopback sender.
    (root, store)
}

#[test]
fn audit_page_parser_accepts_exactly_one_and_preserves_the_default() {
    for value in ["0", "2", "-1", "1000", "invalid"] {
        assert!(
            crate::Cli::try_parse_from([
                "cfctl",
                "call",
                cfctl_cloudflare::AUDIT_PAGE_ID,
                "--max-pages",
                value
            ])
            .is_err()
        );
    }
    let parsed = crate::Cli::try_parse_from([
        "cfctl",
        "call",
        cfctl_cloudflare::AUDIT_PAGE_ID,
        "--max-pages",
        "1",
    ])
    .expect("one page");
    assert!(matches!(
        parsed.command,
        Some(crate::Command::Call(CallArgs {
            max_pages: Some(1),
            ..
        }))
    ));
    let parsed = crate::Cli::try_parse_from(["cfctl", "call", cfctl_cloudflare::AUDIT_PAGE_ID])
        .expect("ordinary read");
    assert!(matches!(
        parsed.command,
        Some(crate::Command::Call(CallArgs {
            max_pages: None,
            ..
        }))
    ));
    let audit = catalog();
    let guide = guide_document(audit.get(cfctl_cloudflare::AUDIT_PAGE_ID).expect("audit"));
    assert!(
        guide
            .stages
            .iter()
            .any(|s| s.summary.contains("--max-pages 1"))
    );
    assert!(
        guide
            .call_argv
            .as_ref()
            .is_some_and(|a| !a.iter().any(|v| v == "--max-pages"))
    );
    assert!(
        !guide_document(test_catalog().get("accounts-list").expect("ordinary"))
            .stages
            .iter()
            .any(|s| s.summary.contains("--max-pages"))
    );
}

#[tokio::test]
async fn audit_page_rejects_mode_and_catalog_drift_before_authentication() {
    let (_root, store) = fixture(true);
    let mut variants = Vec::new();
    let mut a = arguments();
    a.max_pages = Some(2);
    variants.push(a);
    let mut a = arguments();
    a.capability_id = "accounts-list".into();
    variants.push(a);
    let mut a = arguments();
    a.body_json = Some("{}".into());
    variants.push(a);
    let mut a = arguments();
    a.body_stdin = true;
    variants.push(a);
    let mut a = arguments();
    a.out = Some(PathBuf::from("unused"));
    variants.push(a);
    let mut a = arguments();
    a.value_out = Some(PathBuf::from("unused"));
    variants.push(a);
    let mut a = arguments();
    a.source_file = Some(PathBuf::from("unused"));
    variants.push(a);
    let mut a = arguments();
    a.credential_in = Some(PathBuf::from("unused"));
    variants.push(a);
    let mut a = arguments();
    a.if_match = Some("etag".into());
    variants.push(a);
    let mut a = arguments();
    a.profile = None;
    variants.push(a);
    let mut a = arguments();
    a.account = None;
    variants.push(a);
    let mut a = arguments();
    a.query.push(("limit".into(), "1".into()));
    variants.push(a);
    for a in variants {
        let error = Box::pin(call_command(&store, a))
            .await
            .expect_err("local mode rejection");
        assert!(error.to_string().contains("--max-pages 1"), "{error}");
    }
    let mut drift = catalog();
    drift
        .capabilities
        .get_mut(cfctl_cloudflare::AUDIT_PAGE_ID)
        .expect("capability")
        .mutating = true;
    drift.refresh_hash().expect("hash");
    store
        .write_json(&store.paths().catalog_file(), &drift)
        .expect("catalog");
    let error = Box::pin(call_command(&store, arguments()))
        .await
        .expect_err("catalog method fence");
    assert!(error.to_string().contains("exact non-mutating"), "{error}");
    let file = fs::File::options()
        .write(true)
        .open(store.paths().catalog_file())
        .expect("fixture catalog");
    file.set_times(
        fs::FileTimes::new()
            .set_modified(std::time::SystemTime::now() - Duration::from_secs(86_401)),
    )
    .expect("stale fixture catalog timestamp");
    let error = Box::pin(call_command(&store, arguments()))
        .await
        .expect_err("no automatic stale-catalog fetch");
    assert!(
        error
            .to_string()
            .contains("automatic synchronization is disabled"),
        "{error}"
    );
    fs::remove_file(store.paths().catalog_file()).expect("remove isolated fixture only");
    let error = Box::pin(call_command(&store, arguments()))
        .await
        .expect_err("no automatic catalog fetch");
    assert!(
        error
            .to_string()
            .contains("automatic synchronization is disabled"),
        "{error}"
    );
}

#[tokio::test]
async fn audit_page_profile_account_generation_and_private_runtime_are_fenced() {
    let (_root, store) = fixture(false);
    let error = Box::pin(call_command(&store, arguments()))
        .await
        .expect_err("no platform secrets");
    assert!(error.to_string().contains("private_file"), "{error}");
    let (_root, store) = fixture(true);
    for (kind, message) in [
        (ProfileKind::OAuth, "OAuth refresh"),
        (ProfileKind::GlobalKey, "global-key"),
    ] {
        let mut profiles = ProfilesConfig::load(&store).expect("profiles");
        profiles.profiles.get_mut("fixture").expect("profile").kind = kind;
        profiles.save(&store).expect("save");
        let error = Box::pin(call_command(&store, arguments()))
            .await
            .expect_err("non API-token profile rejected before refresh or retrieval");
        assert!(error.to_string().contains(message), "{error}");
    }
    let mut profiles = ProfilesConfig::load(&store).expect("profiles");
    let profile = profiles.profiles.get_mut("fixture").expect("profile");
    profile.kind = ProfileKind::ApiToken;
    profile.account_id = Some("b".repeat(32));
    profiles.save(&store).expect("save");
    let error = Box::pin(call_command(&store, arguments()))
        .await
        .expect_err("explicit account override cannot bypass profile pin");
    let message = error.to_string();
    assert!(
        message.contains(&"a".repeat(32))
            && message.contains(&"b".repeat(32))
            && (message.contains("agreement") || message.contains("pinned to account")),
        "{error}"
    );
    let profile = profiles.profiles.get_mut("fixture").expect("profile");
    profile.account_id = Some("a".repeat(32));
    profile.credential_generation_id = None;
    profiles.save(&store).expect("save");
    let error = Box::pin(call_command(&store, arguments()))
        .await
        .expect_err("generation required");
    assert!(
        error.to_string().contains("no credential generation"),
        "{error}"
    );
    let profile = profiles.profiles.get_mut("fixture").expect("profile");
    profile.credential_generation_id = Some(Uuid::new_v4().to_string());
    profile.managed_api_token = Some(cfctl_auth::ManagedApiTokenV1 {
        schema_version: 1,
        token_id: "fixture-only".into(),
        expires_at: Utc::now() - ChronoDuration::seconds(1),
        standing_authority_id: "fixture".into(),
        pending_revoke_token_id: None,
        pending_revoke_operation_id: None,
        pending_revoke_slot_id: None,
    });
    profiles.save(&store).expect("save");
    let error = Box::pin(call_command(&store, arguments()))
        .await
        .expect_err("expired profile cannot send");
    assert!(error.to_string().contains("has expired"), "{error}");
    assert!(store.list_operational_proofs().expect("proofs").is_empty());
}

async fn serve_audit_fixture(
    listener: tokio::net::TcpListener,
    status: u16,
    body: serde_json::Value,
    requests: Arc<AtomicUsize>,
) {
    while let Ok((mut socket, _)) = listener.accept().await {
        let mut request = Vec::new();
        loop {
            let mut bytes = [0; 1024];
            let n = socket.read(&mut bytes).await.expect("request");
            request.extend_from_slice(&bytes[..n]);
            if n == 0 || request.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        requests.fetch_add(1, Ordering::SeqCst);
        let line = std::str::from_utf8(&request)
            .expect("HTTP request")
            .lines()
            .next()
            .expect("request line");
        assert!(line.starts_with(&format!("GET /accounts/{}/logs/audit?", "a".repeat(32))));
        assert!(line.contains("limit=100"));
        assert!(line.contains("direction=asc"));
        assert!(!line.contains("cursor="));
        assert!(!line.contains("page="));
        let body = serde_json::to_vec(&body).expect("body");
        let head = format!(
            "HTTP/1.1 {status} fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        socket.write_all(head.as_bytes()).await.expect("headers");
        socket.write_all(&body).await.expect("body");
    }
}

#[tokio::test]
async fn audit_page_loopback_receipt_is_content_addressed_scoped_and_not_indexed() {
    for (status, body) in [
        (
            200,
            json!({"success":true,"result":[{"id":"fixture-event"}],"result_info":{"cursors":{"after":"do-not-follow"}}}),
        ),
        (
            503,
            json!({"success":false,"errors":[{"code":10000,"message":"fixture failure"}]}),
        ),
    ] {
        let (_root, store) = fixture(true);
        platform_secrets(&store)
            .store_api_token("fixture", "synthetic-audit-token")
            .expect("isolated synthetic secret");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback fixture");
        let url = format!("http://{}", listener.local_addr().expect("address"));
        let count = Arc::new(AtomicUsize::new(0));
        let server = tokio::spawn(serve_audit_fixture(listener, status, body, count.clone()));
        let envelope = with_test_audit_base_url(url, Box::pin(call_command(&store, arguments())))
            .await
            .expect("bounded call envelope");
        server.abort();
        let _ = server.await;
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert_eq!(envelope.ok, status == 200);
        assert!(envelope.performed);
        assert_eq!(envelope.result["operational_proof_indexed"], false);
        assert_eq!(
            envelope.result["cfctl_read_bounds"]["bounds"]["attempted_requests"],
            1
        );
        assert_eq!(
            envelope.result["cfctl_read_bounds"]["bounds"]["window_completeness"],
            "NOT_ESTABLISHED"
        );
        assert_eq!(
            envelope.result["cfctl_read_bounds"]["scope"]["profile_id"],
            "fixture"
        );
        assert_eq!(
            envelope.result["cfctl_read_bounds"]["scope"]["catalog_hash"],
            catalog().schema_hash
        );
        let scope = &envelope.result["cfctl_read_bounds"]["scope"];
        assert_eq!(
            envelope.result["cfctl_read_scope_sha256"],
            hash_value(scope).expect("scope digest")
        );
        let evidence = envelope.evidence.first().expect("LiveRead evidence");
        assert_eq!(evidence.class, EvidenceClass::LiveRead);
        assert_eq!(
            store
                .read_evidence_value(&evidence.content_hash)
                .expect("content addressed receipt"),
            envelope.result
        );
        assert!(
            store
                .list_operational_proofs()
                .expect("proof index")
                .is_empty()
        );
        assert!(
            !serde_json::to_string(&envelope)
                .expect("envelope JSON")
                .contains("synthetic-audit-token")
        );
    }
}
