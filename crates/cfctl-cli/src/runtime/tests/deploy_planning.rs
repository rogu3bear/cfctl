use super::super::credential_resolution::TEST_SECRETS;
use super::super::deploy::{BEFORE_CALL_TEST_HOOK, TEST_CWD, deploy_command};
use super::super::plan_create::WORKER_STATE_TEST_URL;
use super::*;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const PROFILE: &str = "upload-fixture";
const ACCOUNT: &str = "0123456789abcdef0123456789abcdef";

fn change_selected_profile(store: &StorageStateStore) {
    let mut profiles = ProfilesConfig::load(store).expect("load profiles at call boundary");
    profiles.current_profile = Some("other".into());
    profiles.save(store).expect("concurrent selection change");
}

fn fixture(store: &StorageStateStore, source: &Path) {
    fs::create_dir_all(source.join("build")).expect("source");
    fs::write(source.join("build/worker.js"), "export default {};\n").expect("artifact");
    fs::write(
        source.join("wrangler.toml"),
        "name = \"fixture-worker\"\nmain = \"build/worker.js\"\n",
    )
    .expect("config");
    fs::write(source.join("cfctl.toml"), format!(
        "schema_version = 1\n[target.site]\nlane = \"worker\"\nname = \"fixture-worker\"\nconfig = \"wrangler.toml\"\nprofile_id = {PROFILE:?}\naccount_id = {ACCOUNT:?}\n"
    )).expect("control");
    for arguments in [
        vec!["init", "-q"],
        vec!["add", "."],
        vec![
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ],
    ] {
        assert!(
            StdCommand::new("git")
                .arg("-C")
                .arg(source)
                .args(arguments)
                .status()
                .expect("git")
                .success()
        );
    }
    store
        .register_workspace(source, Some(ACCOUNT.to_owned()))
        .expect("register");
    let profiles = ProfilesConfig {
        current_profile: Some(PROFILE.into()),
        profiles: BTreeMap::from([
            (
                PROFILE.into(),
                ProfileMetadata::new(PROFILE, ProfileKind::ApiToken, Some(ACCOUNT)),
            ),
            (
                "other".into(),
                ProfileMetadata::new("other", ProfileKind::ApiToken, Some("other-account")),
            ),
        ]),
        ..ProfilesConfig::default()
    };
    profiles.save(store).expect("profiles");
    let mut catalog = test_catalog();
    cfctl_catalog::ingest_wrangler_worker_versions_help(
        &mut catalog,
        "fixture",
        "wrangler versions upload [path] --config --message --name",
        "",
    );
    let mut settings = CapabilityV1::new(
        worker_deployment::SETTINGS_CAPABILITY_ID,
        "Read settings",
        "GET",
        worker_deployment::SETTINGS_PATH,
    );
    settings.adapter_status = AdapterStatus::DynamicApi;
    settings.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".into()],
        success_media_types: vec!["application/json".into()],
        body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
    });
    catalog.capabilities.insert(settings.id.clone(), settings);
    catalog.refresh_hash().expect("hash");
    catalog
        .save(&store.paths().catalog_file())
        .expect("catalog");
}

#[tokio::test]
async fn deploy_persists_a_real_plan_and_keeps_validated_pins_across_selection_change() {
    for race in [false, true] {
        let root = tempfile::tempdir().expect("root");
        let source = root.path().join("source");
        let store = authenticated_test_store(RuntimePaths::from_root(&root.path().join("state")));
        fixture(&store, &source);
        let secrets = Arc::new(MemorySecretStore::default());
        secrets
            .store_api_token(PROFILE, "local-fixture-token")
            .expect("synthetic token");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("local fixture");
        let base = format!("http://{}", listener.local_addr().expect("address"));
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("settings read");
            let mut request = Vec::new();
            while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                let mut bytes = [0; 1024];
                let count = socket.read(&mut bytes).await.expect("request");
                assert!(count > 0 && request.len() < 16_384);
                request.extend_from_slice(&bytes[..count]);
            }
            let request = String::from_utf8(request).expect("request text");
            assert!(request.starts_with(&format!(
                "GET /accounts/{ACCOUNT}/workers/scripts/fixture-worker/settings "
            )));
            assert!(
                request
                    .to_lowercase()
                    .contains("authorization: bearer local-fixture-token")
            );
            let body = r#"{"success":false,"result":null,"errors":[{"code":10007,"message":"not found"}],"messages":[]}"#;
            socket.write_all(format!("HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.expect("response");
        });
        let call = TEST_CWD.scope(
            source,
            TEST_SECRETS.scope(
                secrets,
                WORKER_STATE_TEST_URL.scope(
                    base,
                    deploy_command(
                        &store,
                        crate::DeployArgs {
                            target: "site".into(),
                        },
                    ),
                ),
            ),
        );
        let envelope = if race {
            BEFORE_CALL_TEST_HOOK
                .scope(change_selected_profile, call)
                .await
        } else {
            call.await
        }
        .expect("public deploy creates a persisted plan");
        server.await.expect("fixture completed");
        let operation = envelope.operation_id.as_deref().expect("operation ID");
        let plan = load_validated_plan(&store, operation).expect("authenticated durable readback");
        assert_eq!(envelope.command, "deploy");
        assert_eq!(plan.profile_id, PROFILE);
        assert_eq!(plan.account_id, ACCOUNT);
        assert_eq!(plan.capability.id, "wrangler.versions-upload");
        assert!(plan.approval.is_none());
        assert_ne!(plan.status, PlanStatus::Verified);
        assert_eq!(
            ProfilesConfig::load(&store)
                .expect("profiles")
                .current_profile
                .as_deref(),
            Some(if race { "other" } else { PROFILE })
        );
        assert!(
            plan.precondition_hashes
                .contains_key("worker_deployment_state")
        );
    }
}
