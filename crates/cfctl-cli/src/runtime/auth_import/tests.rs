#![allow(clippy::expect_used)]

use super::{USER_VERIFY, import_api_token_using, unchanged_profiles, user_token_problem};
use crate::{AuthCommand, Cli, Command, ImportApiTokenArgs, profiles::ProfilesConfig};
use cfctl_auth::{AuthCredential, MemorySecretStore, ProfileKind, ProfileMetadata, SecretStore};
use cfctl_catalog::CatalogSnapshot;
use cfctl_cloudflare::Executor;
use cfctl_core::{CapabilityV1, ResponseBodyModeV1, ResponseContractV1, VerificationState};
use cfctl_storage::{RuntimePaths, StateStore};
use chrono::{Duration, Utc};
use clap::Parser;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::thread::JoinHandle;

const TOKEN: &str = "synthetic-user-token-never-retain";

fn arguments(path: &Path, flags: &[&str]) -> ImportApiTokenArgs {
    let mut argv = vec![
        "cfctl",
        "auth",
        "import-api-token",
        "--profile",
        "new-user",
        "--account",
        "account-a",
        "--value-in",
        path.to_str().expect("fixture path"),
    ];
    argv.extend_from_slice(flags);
    let cli = Cli::try_parse_from(argv).expect("public import syntax");
    let Some(Command::Auth(auth)) = cli.command else {
        panic!("auth command")
    };
    let AuthCommand::ImportApiToken(arguments) = auth.command else {
        panic!("token import")
    };
    arguments
}

fn seeded_runtime(root: &Path) -> (StateStore, ProfilesConfig, MemorySecretStore) {
    let store = StateStore::open(RuntimePaths::from_root(root)).expect("isolated runtime");
    let mut profiles = ProfilesConfig::default();
    profiles.profiles.insert(
        "existing".to_owned(),
        ProfileMetadata::new("existing", ProfileKind::ApiToken, Some("account-a")),
    );
    profiles.current_profile = Some("existing".to_owned());
    profiles.save(&store).expect("seed profiles");
    let secrets = MemorySecretStore::default();
    secrets
        .store_api_token("existing", "synthetic-existing-token")
        .expect("seed credential");
    let mut capability = CapabilityV1::new(
        USER_VERIFY,
        "Verify user token",
        "GET",
        "/user/tokens/verify",
    );
    capability.account_scope = "user".to_owned();
    capability.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".to_owned()],
        success_media_types: vec!["application/json".to_owned()],
        body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
    });
    let mut catalog = CatalogSnapshot {
        schema_version: 2,
        generated_at: Utc::now(),
        source_url: "synthetic".to_owned(),
        source_hash: String::new(),
        schema_hash: String::new(),
        capabilities: BTreeMap::from([(USER_VERIFY.to_owned(), capability)]),
    };
    catalog.refresh_hash().expect("catalog hash");
    catalog
        .save(&store.paths().catalog_file())
        .expect("catalog fixture");
    (store, profiles, secrets)
}

fn token_file() -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("private input");
    file.write_all(TOKEN.as_bytes()).expect("synthetic input");
    file
}

fn verification_server(status: u16, result: &Value) -> (Executor, JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback fixture");
    let address = listener.local_addr().expect("fixture address");
    listener.set_nonblocking(true).expect("bounded listener");
    let body =
        json!({"success":status == 200,"errors":[],"messages":[],"result":result}).to_string();
    let server = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(error) => panic!("verification fixture did not receive request: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("bounded read");
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0_u8];
            stream.read_exact(&mut byte).expect("request header");
            request.push(byte[0]);
            assert!(request.len() < 8192);
        }
        write!(stream, "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).expect("fixture response");
        String::from_utf8(request).expect("ASCII headers")
    });
    let executor = Executor::new(
        reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("fixture client"),
        &format!("http://{address}"),
    )
    .expect("fixture executor")
    .with_max_retries(0);
    (executor, server)
}

#[tokio::test]
async fn qualified_import_preserves_selection_and_binds_evidence_to_stored_generation() {
    let root = tempfile::tempdir().expect("runtime root");
    let (store, mut profiles, secrets) = seeded_runtime(root.path());
    let existing = serde_json::to_value(&profiles.profiles["existing"]).expect("metadata");
    let file = token_file();
    let cutoff = (Utc::now() + Duration::hours(2)).to_rfc3339();
    let args = arguments(
        file.path(),
        &[
            "--verify-user",
            "--expires-before",
            &cutoff,
            "--create-only",
            "--no-select",
        ],
    );
    let (executor, server) = verification_server(
        200,
        &json!({
            "id":"user-token-id", "status":"active", "expires_on":Utc::now() + Duration::hours(1),
            "value":TOKEN,
        }),
    );
    let envelope = import_api_token_using(&store, &mut profiles, &secrets, &args, Some(&executor))
        .await
        .expect("qualified import");
    let request = server.join().expect("verification request");
    assert!(request.starts_with("GET /user/tokens/verify HTTP/1.1\r\n"));
    assert!(
        request
            .to_ascii_lowercase()
            .contains(&format!("authorization: bearer {TOKEN}"))
    );
    assert!(!request.contains("synthetic-existing-token"));
    assert!(envelope.ok);
    assert_eq!(envelope.verification.state, VerificationState::Passed);
    assert_eq!(
        envelope.result["credential_verification"]["permissions_verified"],
        false
    );
    assert_eq!(profiles.current_profile.as_deref(), Some("existing"));
    assert_eq!(
        serde_json::to_value(&profiles.profiles["existing"]).expect("metadata"),
        existing
    );
    assert_eq!(envelope.result["selection_changed"], false);
    assert_eq!(envelope.result["selected"], false);
    let profile = &profiles.profiles["new-user"];
    assert_eq!(
        envelope.result["credential_generation_id"],
        json!(profile.credential_generation_id)
    );
    assert!(
        matches!(secrets.load_profile_credential(profile).expect("stored token"), AuthCredential::Bearer {token} if token == TOKEN)
    );
    assert!(
        !serde_json::to_string(&envelope)
            .expect("envelope")
            .contains(TOKEN)
    );
    let evidence =
        std::fs::read_to_string(&envelope.evidence[0].path).expect("retained observation");
    assert!(!evidence.contains(TOKEN));
    assert!(
        evidence.contains(
            profile
                .credential_generation_id
                .as_deref()
                .expect("generation")
        )
    );
    assert!(envelope.attestation.is_some());
    unchanged_profiles(&store, &profiles).expect("durable profile state agrees");
}

#[tokio::test]
async fn rejected_user_tokens_never_write_credentials_or_profiles() {
    let now = Utc::now();
    for (status, result) in [
        (401, Value::Null),
        (
            200,
            json!({"id":"expired","status":"active","expires_on":now - Duration::seconds(1)}),
        ),
        (200, json!({"id":"unbounded","status":"active"})),
        (
            200,
            json!({"id":"too-long","status":"active","expires_on":now + Duration::days(2)}),
        ),
    ] {
        let root = tempfile::tempdir().expect("runtime root");
        let (store, mut profiles, secrets) = seeded_runtime(root.path());
        let before = serde_json::to_value(&profiles).expect("original metadata");
        let file = token_file();
        let cutoff = (now + Duration::hours(2)).to_rfc3339();
        let args = arguments(file.path(), &["--verify-user", "--expires-before", &cutoff]);
        let (executor, server) = verification_server(status, &result);
        let envelope =
            import_api_token_using(&store, &mut profiles, &secrets, &args, Some(&executor))
                .await
                .expect("rejection envelope");
        server.join().expect("verification request");
        assert!(!envelope.ok);
        assert_eq!(envelope.verification.state, VerificationState::Failed);
        assert_eq!(serde_json::to_value(&profiles).expect("metadata"), before);
        unchanged_profiles(&store, &profiles).expect("no durable profile mutation");
        assert!(
            secrets
                .locate_api_token("new-user")
                .expect("new credential location")
                .is_none()
        );
        assert!(
            !serde_json::to_string(&envelope)
                .expect("envelope")
                .contains(TOKEN)
        );
    }
}

#[tokio::test]
async fn create_only_rejects_a_collision_before_opening_secret_input() {
    let root = tempfile::tempdir().expect("runtime root");
    let (store, mut profiles, secrets) = seeded_runtime(root.path());
    let mut args = arguments(&root.path().join("does-not-exist"), &["--create-only"]);
    args.profile = "existing".to_owned();
    let error = import_api_token_using(&store, &mut profiles, &secrets, &args, None)
        .await
        .expect_err("refuse collision first");
    assert!(
        error
            .to_string()
            .contains("--create-only profile already exists")
    );
    unchanged_profiles(&store, &profiles).expect("no mutation");
}

#[tokio::test]
async fn no_select_preserves_an_absent_current_profile() {
    let root = tempfile::tempdir().expect("runtime root");
    let (store, mut profiles, secrets) = seeded_runtime(root.path());
    profiles.current_profile = None;
    profiles.save(&store).expect("clear initial selection");
    let file = token_file();
    let args = arguments(file.path(), &["--create-only", "--no-select"]);
    let envelope = import_api_token_using(&store, &mut profiles, &secrets, &args, None)
        .await
        .expect("unselected import");
    assert!(envelope.ok);
    assert_eq!(profiles.current_profile, None);
    assert_eq!(envelope.result["selection_changed"], false);
    unchanged_profiles(&store, &profiles).expect("selection remains absent on disk");
}

#[tokio::test]
async fn profile_drift_or_missing_catalog_stops_intake_before_storage() {
    let root = tempfile::tempdir().expect("runtime root");
    let (store, mut profiles, secrets) = seeded_runtime(root.path());
    let file = token_file();
    let args = arguments(file.path(), &["--create-only", "--no-select"]);
    let mut concurrent = profiles.clone();
    concurrent.current_profile = None;
    concurrent
        .save(&store)
        .expect("other actor changed selection");
    let error = import_api_token_using(&store, &mut profiles, &secrets, &args, None)
        .await
        .expect_err("drift rejection");
    assert!(error.to_string().contains("profile state changed"));
    unchanged_profiles(&store, &concurrent).expect("other actor preserved");
    std::fs::remove_file(store.paths().catalog_file()).expect("remove synthetic catalog");
    let args = arguments(&root.path().join("does-not-exist"), &["--verify-user"]);
    let error = import_api_token_using(&store, &mut profiles, &secrets, &args, None)
        .await
        .expect_err("catalog required before input");
    assert!(error.to_string().contains("requires a current catalog"));
    assert!(
        secrets
            .locate_api_token("new-user")
            .expect("credential location")
            .is_none()
    );
}

#[test]
fn qualification_rejects_invalid_status_activation_and_expiry() {
    let now = Utc::now();
    for result in [
        json!({"id":"revoked","status":"disabled"}),
        json!({"status":"active"}),
        json!({"id":"bad-date","status":"active","expires_on":"invalid"}),
        json!({"id":"future","status":"active","not_before":now + Duration::hours(1)}),
    ] {
        assert!(user_token_problem(&result, None, now).is_some());
    }
    assert!(user_token_problem(&json!({"id":"unbounded","status":"active"}), None, now).is_none());
}

#[test]
fn parser_rejects_ambiguous_secret_sources_and_unverified_expiry() {
    for flags in [
        vec!["--prompt", "--stdin"],
        vec!["--prompt", "--value-in", "/tmp/input"],
        vec!["--stdin", "--expires-before", "2099-01-01T00:00:00Z"],
    ] {
        let mut argv = vec![
            "cfctl",
            "auth",
            "import-api-token",
            "--account",
            "account-a",
        ];
        argv.extend(flags);
        assert!(Cli::try_parse_from(argv).is_err());
    }
}
