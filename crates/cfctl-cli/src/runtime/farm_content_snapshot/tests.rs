#![allow(clippy::expect_used, clippy::unwrap_used)]
use super::*;
use clap::Parser as _;
use std::os::unix::fs::{PermissionsExt as _, symlink};

fn args(output: &Path) -> CallArgs {
    let cli = crate::Cli::try_parse_from([
        "cfctl",
        "call",
        CAPABILITY_ID,
        "--profile",
        "farm-read",
        "--account",
        ACCOUNT_ID,
        "--out",
        output.to_str().unwrap(),
        "--json",
    ])
    .unwrap();
    let Some(crate::Command::Call(args)) = cli.command else {
        panic!("call");
    };
    args
}

fn root() -> tempfile::TempDir {
    let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    root
}

#[tokio::test]
async fn farm_snapshot_call_dispatch_rejects_sql_before_auth_or_network() {
    let root = root();
    let store = super::super::tests::authenticated_test_store(
        cfctl_storage::RuntimePaths::from_root(&root.path().join("state")),
    );
    let mut catalog = cfctl_catalog::CatalogSnapshot {
        schema_version: 1,
        generated_at: chrono::Utc::now(),
        source_url: "synthetic".into(),
        source_hash: String::new(),
        schema_hash: String::new(),
        capabilities: std::collections::BTreeMap::new(),
    };
    cfctl_catalog::ingest_native_control_capabilities(&mut catalog).unwrap();
    assert_eq!(
        catalog.get(CAPABILITY_ID),
        Some(&cfctl_catalog::farm_content_snapshot_capability())
    );
    catalog.save(&store.paths().catalog_file()).unwrap();
    let output = root.path().join("snapshot.json");
    let mut call = args(&output);
    call.body_json = Some("private SQL is not JSON".into());
    let error = Box::pin(super::super::call_command::call_command(&store, call))
        .await
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("Farm snapshot requires"));
    assert!(!error.contains("private SQL"));
    assert!(!output.exists());
}

#[test]
fn farm_snapshot_public_contract_and_private_destination_fail_closed() {
    let root = root();
    let path = root.path().join("snapshot.json");
    let cap = cfctl_catalog::farm_content_snapshot_capability();
    preflight(&cap, &args(&path)).unwrap();
    let input = super::super::call_input::call_input(&cap, &args(&path)).unwrap();
    super::super::r2_credentials::preflight_call_input(&cap, &input.input, None).unwrap();
    assert!(!path.exists());
    for field in [
        "account",
        "profile",
        "body",
        "selectors",
        "query",
        "value",
        "match",
    ] {
        let mut input = args(&path);
        match field {
            "account" => input.account = Some("wrong".into()),
            "profile" => input.profile = None,
            "body" => input.body_json = Some("private invalid JSON".into()),
            "selectors" => input.selectors.push(("database_id".into(), "other".into())),
            "query" => input
                .query
                .push(("sql".into(), "DELETE FROM site_content".into())),
            "value" => input.value_out = Some(path.clone()),
            "match" => input.if_match = Some("other".into()),
            _ => unreachable!(),
        }
        assert!(preflight(&cap, &input).is_err(), "{field}");
    }
    let mut drift = cap;
    drift.permissions.clear();
    assert!(preflight(&drift, &args(&path)).is_err());
    std::fs::write(&path, "preserve").unwrap();
    assert!(
        preflight(
            &cfctl_catalog::farm_content_snapshot_capability(),
            &args(&path)
        )
        .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"preserve");
    symlink(&path, root.path().join("link")).unwrap();
    assert!(private_target(&root.path().join("link")).is_err());
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(private_target(&root.path().join("new")).is_err());
}

#[test]
fn farm_snapshot_profile_and_generated_guide_preserve_target_and_sink() {
    let mut profile: ProfileMetadata = serde_json::from_value(json!({"schema_version":1,
        "id":"farm-read","kind":"api_token","account_id":ACCOUNT_ID,
        "oauth_client_id":null,"emergency_only":false,
        "credential_generation_id":"11111111-1111-4111-8111-111111111111"}))
    .unwrap();
    validate_profile(&profile, Some(ACCOUNT_ID)).unwrap();
    assert!(validate_profile(&profile, Some("wrong")).is_err());
    profile.account_id = Some("wrong".into());
    assert!(validate_profile(&profile, Some(ACCOUNT_ID)).is_err());
    profile.account_id = Some(ACCOUNT_ID.into());
    profile.emergency_only = true;
    assert!(validate_profile(&profile, Some(ACCOUNT_ID)).is_err());
    profile.emergency_only = false;
    profile.credential_generation_id = None;
    assert!(validate_profile(&profile, Some(ACCOUNT_ID)).is_err());
    let guide = super::super::guide_generation::guide_document(
        &cfctl_catalog::farm_content_snapshot_capability(),
    );
    let document = serde_json::to_value(guide).unwrap().to_string();
    for required in [
        CAPABILITY_ID,
        ACCOUNT_ID,
        "--profile",
        "--out",
        "D1 Read",
        "0700",
    ] {
        assert!(document.contains(required), "missing {required}");
    }
}

#[tokio::test]
async fn farm_snapshot_private_readback_and_evidence_never_disclose_values() {
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpListener,
    };
    let data = json!({"site_content":[{"id":1,"schema_version":1,"version":0,
        "fields_json":r#"{"hero":{"segments":[{"kind":"text","text":"private content"}]}}"#,"updated_by":"private actor",
        "updated_at":"private timestamp"}],"site_content_revisions":[]});
    let body = json!({"success":true,"errors":[],"result":[{"success":true,
        "meta":{"changed_db":false},"results":[{"snapshot_json":data.to_string()}]}]})
    .to_string();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut received = Vec::new();
        loop {
            let mut bytes = [0; 4096];
            let n = socket.read(&mut bytes).await.unwrap();
            assert!(n > 0);
            received.extend_from_slice(&bytes[..n]);
            if let Some(split) = received.windows(4).position(|s| s == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&received[..split]).to_ascii_lowercase();
                let length: usize = headers
                    .lines()
                    .find_map(|s| s.strip_prefix("content-length: "))
                    .unwrap()
                    .parse()
                    .unwrap();
                if received.len() >= split + 4 + length {
                    break;
                }
            }
        }
        socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
    });
    let executor = Executor::new(reqwest::Client::new(), &format!("http://{address}")).unwrap();
    let snapshot = executor
        .read_farm_content_snapshot(&cfctl_auth::AuthCredential::Bearer {
            token: "synthetic".into(),
        })
        .await
        .unwrap();
    server.await.unwrap();
    let root = root();
    let (directory, name) = private_target(&root.path().join("private.json")).unwrap();
    let metadata = publish(&directory, &name, &snapshot).unwrap();
    let bytes = std::fs::read(root.path().join(&name)).unwrap();
    assert_eq!(bytes, snapshot.private_bytes());
    assert_eq!(
        std::fs::metadata(root.path().join(&name))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        metadata["output_file"]["sha256"],
        format!("sha256:{}", hex::encode(Sha256::digest(&bytes)))
    );
    assert!(publish(&directory, &name, &snapshot).is_err());
    let store = super::super::tests::authenticated_test_store(
        cfctl_storage::RuntimePaths::from_root(&root.path().join("state")),
    );
    let evidence = store
        .write_observation_evidence(EvidenceClass::LiveRead, &metadata)
        .unwrap();
    let persisted = store
        .read_evidence_value(&evidence.content_hash)
        .unwrap()
        .to_string();
    for secret in [
        "private content",
        "private actor",
        "private timestamp",
        "fields_json",
    ] {
        assert!(!metadata.to_string().contains(secret));
        assert!(!persisted.contains(secret));
    }
}
