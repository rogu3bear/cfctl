use super::super::api_execution::{
    FINALIZATION_TEST_HOOK, FinalizationTestStage, execute_api_plan_with_executor,
};
use super::*;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

fn mutation_plan(store: &StorageStateStore) -> (PlanV1, CallInput) {
    let path = "/zones/{zone_id}/dns_records/{record_id}";
    let mut capability = CapabilityV1::new(
        "dns-records-for-a-zone-delete-dns-record",
        "Delete one record",
        "DELETE",
        path,
    );
    capability.verification.strategy = "same_resource_returns_not_found_after_delete".into();
    capability.same_path_read = Some(SamePathReadContractV1 {
        path: path.into(),
        read_capability_id: "dns-records-for-a-zone-dns-record-details".into(),
        verified_response_fields: Vec::new(),
    });
    capability.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".into()],
        success_media_types: vec!["application/json".into()],
        body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
    });
    assert!(capability.verification_contract_supported());
    let input = CallInput {
        selectors: json!({"zone_id":"zone-fixture", "record_id":"record-fixture"}),
        query: json!({}),
        ..CallInput::default()
    };
    let mut plan = PlanV1::draft(
        "fixture",
        "account-fixture",
        "catalog-fixture",
        capability,
        json!({}),
    )
    .expect("plan");
    plan.input = serde_json::to_value(&input).expect("input");
    plan.refresh_hash().expect("bind input");
    plan.approve(true, None).expect("approve");
    plan.mark_consumed().expect("consume");
    plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("intent");
    store.save_plan(&plan).expect("durable intent");
    (plan, input)
}

fn secret_plan(store: &StorageStateStore, sink: &Path, cleanup: bool) -> (PlanV1, CallInput) {
    let mut capability = CapabilityV1::new(
        "account-api-tokens-create-token",
        "Secret fixture",
        "POST",
        "/accounts/{account_id}/tokens",
    );
    capability.risk = RiskClass::SecretSensitive;
    capability.verification.required = false;
    capability.verification.strategy = "sink_write_and_source_response_status".into();
    let input = CallInput {
        selectors: json!({"account_id":"account-fixture"}),
        query: json!({}),
        body: Some(json!({"name":"fixture"})),
        ..CallInput::default()
    };
    let mut targets = json!({"adapter":{"value_out":sink}});
    if cleanup {
        targets["adapter"]["secret_body_ref"] = json!("synthetic-input-reference");
    }
    let mut plan = PlanV1::draft(
        "fixture",
        "account-fixture",
        "catalog-fixture",
        capability,
        targets,
    )
    .expect("plan");
    plan.input = serde_json::to_value(&input).expect("input");
    plan.refresh_hash().expect("bind input");
    plan.approve(true, None).expect("approve");
    plan.mark_consumed().expect("consume");
    plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("intent");
    store.save_plan(&plan).expect("persist intent");
    (plan, input)
}

async fn successful_transport(
    secret: bool,
    requests: usize,
) -> (Executor, tokio::task::JoinHandle<usize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("loopback");
    let address = listener.local_addr().expect("address");
    let server = tokio::spawn(async move {
        for ordinal in 0..requests {
            let (mut socket, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
                .await
                .expect("bounded accept")
                .expect("request");
            let mut bytes = [0; 8192];
            let length = socket.read(&mut bytes).await.expect("request bytes");
            let request = String::from_utf8_lossy(&bytes[..length]);
            let (status, body) = if secret {
                assert!(request.starts_with("POST /accounts/account-fixture/tokens "));
                (
                    200,
                    r#"{"success":true,"result":{"id":"created-fixture","value":"POST-RESPONSE-PRIVATE-SENTINEL"},"errors":[]}"#,
                )
            } else if ordinal == 0 {
                assert!(
                    request.starts_with("DELETE /zones/zone-fixture/dns_records/record-fixture ")
                );
                (
                    200,
                    r#"{"success":true,"result":{"id":"record-fixture"},"errors":[]}"#,
                )
            } else {
                assert!(request.starts_with("GET /zones/zone-fixture/dns_records/record-fixture "));
                (404, r#"{"success":false,"result":null,"errors":[]}"#)
            };
            let wire = format!(
                "HTTP/1.1 {status} Result\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(wire.as_bytes()).await.expect("response");
        }
        requests
    });
    (
        Executor::new(reqwest::Client::new(), &format!("http://{address}")).expect("executor"),
        server,
    )
}

#[tokio::test]
async fn mutation_boundary_local_validation_and_sink_refusal_preserve_consumed_identity() {
    for occupied_sink in [false, true] {
        let root = tempfile::tempdir().expect("test root");
        let store = authenticated_test_store(RuntimePaths::from_root(root.path()));
        let sink = root.path().join("sink");
        let (mut plan, mut input) = if occupied_sink {
            let fixture = secret_plan(&store, &sink, false);
            fs::write(&sink, "existing-private-material").expect("occupied sink");
            fixture
        } else {
            mutation_plan(&store)
        };
        if !occupied_sink {
            input.selectors = json!({});
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("loopback");
        let executor = Executor::new(
            reqwest::Client::new(),
            &format!("http://{}", listener.local_addr().expect("address")),
        )
        .expect("executor");
        let envelope = execute_api_plan_with_executor(
            &store,
            &executor,
            "catalog-fixture",
            &mut plan,
            &input,
            &AuthCredential::Bearer {
                token: "synthetic-only".into(),
            },
            &MemorySecretStore::default(),
        )
        .await
        .expect("local failure retains the exact consumed operation envelope");
        assert!(!envelope.ok);
        assert!(!envelope.performed);
        assert_eq!(
            envelope.operation_id.as_deref(),
            Some(plan.operation_id.as_str())
        );
        assert_eq!(envelope.account_id.as_deref(), Some("account-fixture"));
        assert_eq!(envelope.profile_id.as_deref(), Some("fixture"));
        assert_ne!(envelope.verification.state, VerificationState::Passed);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
        assert!(
            store
                .load_plan(&plan.operation_id)
                .expect("retained operation")
                .mark_consumed()
                .is_err()
        );
        if occupied_sink {
            assert_eq!(
                fs::read_to_string(sink).expect("retained sink"),
                "existing-private-material"
            );
        }
    }
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "One fault matrix preserves the same real response across six independent persistence and finalization stages."
)]
async fn mutation_boundary_response_survives_each_local_finalization_failure() {
    for failure in [
        "apply",
        "journal",
        "sink",
        "cleanup",
        "verification",
        "closure",
    ] {
        let root = tempfile::tempdir().expect("test root");
        let store = authenticated_test_store(RuntimePaths::from_root(root.path()));
        let sink = root.path().join("sink");
        let secret = matches!(failure, "sink" | "cleanup");
        let (mut plan, input) = if secret {
            secret_plan(&store, &sink, failure == "cleanup")
        } else {
            mutation_plan(&store)
        };
        let phase = match failure {
            "verification" => FinalizationTestStage::Verification,
            "closure" => FinalizationTestStage::Closure,
            _ => FinalizationTestStage::Response,
        };
        let plan_path = store
            .paths()
            .data_dir
            .join("plans")
            .join(format!("{}.json", plan.operation_id));
        let evidence_path = store.paths().data_dir.join("evidence");
        let failure_sink = sink.clone();
        let hook: Arc<dyn Fn(FinalizationTestStage) + Send + Sync> = Arc::new(move |observed| {
            if observed != phase {
                return;
            }
            match failure {
                "apply" => {
                    fs::rename(&evidence_path, evidence_path.with_extension("retained"))
                        .expect("retain evidence directory");
                    fs::write(&evidence_path, "injected failure").expect("block evidence");
                }
                "journal" | "verification" | "closure" => {
                    fs::rename(&plan_path, plan_path.with_extension("retained"))
                        .expect("retain consumed record");
                    fs::create_dir(&plan_path).expect("block plan checkpoint");
                }
                "sink" => {
                    fs::create_dir(&failure_sink).expect("injected occupied sink");
                }
                "cleanup" => {}
                _ => unreachable!("closed fixture"),
            }
        });
        let requests = if failure == "closure" { 2 } else { 1 };
        let (executor, server) = successful_transport(secret, requests).await;
        let memory = MemorySecretStore::default();
        let secrets: &dyn SecretStore = if failure == "cleanup" {
            &DeleteFailingSecretStore
        } else {
            &memory
        };
        let credential = AuthCredential::Bearer {
            token: "synthetic-only".into(),
        };
        let envelope = FINALIZATION_TEST_HOOK
            .scope(
                hook,
                execute_api_plan_with_executor(
                    &store,
                    &executor,
                    "catalog-fixture",
                    &mut plan,
                    &input,
                    &credential,
                    secrets,
                ),
            )
            .await
            .expect("post-response recovery envelope");
        assert_eq!(server.await.expect("server"), requests);
        assert!(!envelope.ok, "{failure}");
        assert!(envelope.performed, "{failure}");
        assert_eq!(envelope.result["status"], 200, "{failure}");
        assert_eq!(envelope.result["success"], true, "{failure}");
        assert_eq!(
            envelope.operation_id.as_deref(),
            Some(plan.operation_id.as_str())
        );
        assert!(
            !serde_json::to_string(&envelope)
                .expect("envelope")
                .contains("POST-RESPONSE-PRIVATE-SENTINEL")
        );
        assert!(
            envelope
                .error
                .as_ref()
                .expect("error")
                .next_step
                .as_deref()
                .is_some_and(|s| s.contains("Do not replay"))
        );
        if failure == "closure" {
            assert_eq!(
                envelope.verification.state,
                VerificationState::Passed,
                "the proved readback and failed closure remain separate"
            );
        } else {
            assert_ne!(envelope.verification.state, VerificationState::Passed);
        }
    }
}

async fn mutation_response(
    status: u16,
    body: &'static str,
) -> (Executor, tokio::task::JoinHandle<usize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("loopback");
    let address = listener.local_addr().expect("address");
    let server = tokio::spawn(async move {
        let mut dispatches = 0;
        loop {
            let wait = if dispatches == 0 {
                Duration::from_secs(5)
            } else {
                Duration::from_millis(100)
            };
            let incoming = tokio::time::timeout(wait, listener.accept()).await;
            let Ok(Ok((mut socket, _))) = incoming else {
                assert!(dispatches > 0, "expected one actual dispatch");
                break;
            };
            dispatches += 1;
            assert!(dispatches <= 4, "bounded retry fixture");
            let mut request = [0; 8192];
            let count = socket.read(&mut request).await.expect("request");
            assert!(
                String::from_utf8_lossy(&request[..count])
                    .starts_with("DELETE /zones/zone-fixture/dns_records/record-fixture ")
            );
            let response = format!(
                "HTTP/1.1 {status} Result\r\nContent-Type: application/json\r\nContent-Length: {}\r\nRetry-After: 0\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            socket
                .write_all(response.as_bytes())
                .await
                .expect("response");
            drop(socket);
        }
        dispatches
    });
    let executor = Executor::new(reqwest::Client::new(), &format!("http://{address}"))
        .expect("local executor");
    (executor, server)
}

#[tokio::test]
async fn mutation_boundary_rejection_is_performed_independently_of_provider_success() {
    for status in [403, 200, 429, 503] {
        let root = tempfile::tempdir().expect("test root");
        let store = authenticated_test_store(RuntimePaths::from_root(root.path()));
        let (mut plan, input) = mutation_plan(&store);
        let (executor, server) = mutation_response(status, r#"{"success":false,"result":null,"errors":[{"code":10000,"message":"fixture denial"}]}"#).await;
        let envelope = execute_api_plan_with_executor(
            &store,
            &executor,
            "catalog-fixture",
            &mut plan,
            &input,
            &AuthCredential::Bearer {
                token: "synthetic-only".into(),
            },
            &MemorySecretStore::default(),
        )
        .await
        .expect("failed mutation envelope");
        assert_eq!(server.await.expect("server"), 1);
        assert!(!envelope.ok);
        assert!(
            envelope.performed,
            "an observed rejected request crossed the boundary"
        );
        assert_ne!(envelope.verification.state, VerificationState::Passed);
        assert_eq!(
            envelope.operation_id.as_deref(),
            Some(plan.operation_id.as_str())
        );
        assert_eq!(envelope.result["status"], status);
        assert_eq!(envelope.result["success"], false);
        assert!(
            store
                .load_plan(&plan.operation_id)
                .expect("retained operation")
                .mark_consumed()
                .is_err()
        );
    }
}

#[tokio::test]
async fn mutation_boundary_malformed_response_retains_dispatch_and_no_replay() {
    let root = tempfile::tempdir().expect("test root");
    let store = authenticated_test_store(RuntimePaths::from_root(root.path()));
    let (mut plan, input) = mutation_plan(&store);
    let (executor, server) = mutation_response(200, "not JSON").await;
    let envelope = execute_api_plan_with_executor(
        &store,
        &executor,
        "catalog-fixture",
        &mut plan,
        &input,
        &AuthCredential::Bearer {
            token: "synthetic-only".into(),
        },
        &MemorySecretStore::default(),
    )
    .await
    .expect("uncertain mutation envelope");
    assert_eq!(server.await.expect("server"), 1);
    assert!(!envelope.ok);
    assert!(
        envelope.performed,
        "malformed response cannot erase dispatch"
    );
    assert_ne!(envelope.verification.state, VerificationState::Passed);
    assert!(
        store
            .load_plan(&plan.operation_id)
            .expect("retained operation")
            .mark_consumed()
            .is_err()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn mutation_boundary_launched_process_cannot_be_erased_by_receipt_boolean() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = tempfile::tempdir().expect("test root");
    let store = StorageStateStore::open(RuntimePaths::from_root(root.path()))
        .expect("store without evidence authority injects a post-response failure");
    let program = root.path().join("fixture.sh");
    fs::write(&program, "#!/bin/sh\nexit 9\n").expect("process fixture");
    fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).expect("mode");
    let cache = root.path().join("process-cache");
    fs::create_dir(&cache).expect("cache");
    let mut capability = CapabilityV1::new("wrangler.deploy", "Fixture", "CLI", "wrangler deploy");
    capability.adapter_status = AdapterStatus::DelegatedCli;
    let mut plan = PlanV1::draft(
        "fixture",
        "account",
        "catalog-fixture",
        capability,
        json!({}),
    )
    .expect("plan");
    plan.approve(true, None).expect("approval");
    plan.mark_consumed().expect("consumption");
    plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("intent");
    store.save_plan(&plan).expect("persist intent");
    let input = CallInput {
        selectors: json!({}),
        query: json!({}),
        ..CallInput::default()
    };
    let credential = AuthCredential::Bearer {
        token: "synthetic-process-token".into(),
    };
    let boundary = cfctl_core::BoundaryObservation::default();
    let mut receipt = run_delegated_cli_with_timeout(
        &plan.capability,
        &input,
        &credential,
        Some("account"),
        &cache,
        Some(&program),
        Some(Path::new("/bin/sh")),
        Duration::from_secs(1),
        Some(&boundary),
    )
    .await
    .expect("actual subprocess result");
    assert_eq!(receipt["exit_status"], 9);
    // A receipt's claim is deliberately inconsistent with the observed launch.
    // Post-response storage failure must not use this untrusted flag as custody.
    receipt["boundary_crossed"] = json!(false);
    let catalog = CatalogSnapshot {
        schema_version: 1,
        generated_at: Utc::now(),
        source_url: String::new(),
        source_hash: String::new(),
        schema_hash: "catalog-fixture".into(),
        capabilities: BTreeMap::new(),
    };
    let envelope = complete_delegated_plan(
        &store,
        &catalog,
        &mut plan,
        &input,
        &credential,
        &MemorySecretStore::default(),
        DelegatedReceipt {
            value: receipt,
            boundary,
        },
    )
    .await;
    assert!(!envelope.ok);
    assert!(
        envelope.performed,
        "the actual process launch survives contradictory receipt metadata"
    );
    assert_eq!(
        envelope.operation_id.as_deref(),
        Some(plan.operation_id.as_str())
    );
    assert_eq!(envelope.result["exit_status"], 9);
    assert_ne!(envelope.verification.state, VerificationState::Passed);
}

#[cfg(unix)]
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "One actual process, persisted verification and final-save fault prove the complete retention sequence."
)]
async fn delegated_final_save_failure_retains_durable_verification_facts() {
    use super::super::api_execution::{FINALIZATION_TEST_HOOK, FinalizationTestStage};
    use std::os::unix::fs::PermissionsExt as _;
    let root = tempfile::tempdir().expect("runtime");
    let store = authenticated_test_store(RuntimePaths::from_root(root.path()));
    let program = root.path().join("success.sh");
    fs::write(&program, "#!/bin/sh\nexit 0\n").expect("actual process fixture");
    fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).expect("mode");
    let mut capability = CapabilityV1::new("wrangler.deploy", "Fixture", "CLI", "wrangler deploy");
    capability.adapter_status = AdapterStatus::DelegatedCli;
    // Exercise the actual verifier's local refusal, without provider access.
    capability.verification.strategy = "fixture_unavailable".into();
    let mut plan = PlanV1::draft(
        "fixture",
        "account",
        "catalog-fixture",
        capability,
        json!({}),
    )
    .expect("plan");
    plan.approve(true, None).expect("approve");
    plan.mark_consumed().expect("consume");
    plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("intent");
    store.save_plan(&plan).expect("persist intent");
    let cache = root.path().join("process-cache");
    fs::create_dir(&cache).expect("cache");
    let input = CallInput {
        selectors: json!({}),
        query: json!({}),
        ..CallInput::default()
    };
    let credential = AuthCredential::Bearer {
        token: "synthetic-only".into(),
    };
    let boundary = cfctl_core::BoundaryObservation::default();
    let receipt = run_delegated_cli_with_timeout(
        &plan.capability,
        &input,
        &credential,
        Some("account"),
        &cache,
        Some(&program),
        Some(Path::new("/bin/sh")),
        Duration::from_secs(1),
        Some(&boundary),
    )
    .await
    .expect("real process receipt");
    assert_eq!(receipt["exit_status"], 0);
    let plans = store.paths().data_dir.join("plans");
    let retained = root.path().join("retained-plans");
    let fault = std::sync::Arc::new(move |stage| {
        if stage == FinalizationTestStage::Closure {
            fs::rename(&plans, &retained).expect("preserve consumed journal");
            fs::write(&plans, "block final save").expect("final save fault");
        }
    });
    let catalog = CatalogSnapshot {
        schema_version: 1,
        generated_at: Utc::now(),
        source_url: String::new(),
        source_hash: String::new(),
        schema_hash: "catalog-fixture".into(),
        capabilities: BTreeMap::new(),
    };
    let envelope = FINALIZATION_TEST_HOOK
        .scope(
            fault,
            complete_delegated_plan(
                &store,
                &catalog,
                &mut plan,
                &input,
                &credential,
                &MemorySecretStore::default(),
                DelegatedReceipt {
                    value: receipt,
                    boundary,
                },
            ),
        )
        .await;
    assert!(!envelope.ok);
    assert!(envelope.performed);
    assert_eq!(
        envelope.operation_id.as_deref(),
        Some(plan.operation_id.as_str())
    );
    assert_eq!(envelope.result["exit_status"], 0);
    assert_eq!(
        envelope.verification.state,
        VerificationState::Failed,
        "a final local save failure must not erase a completed verification result"
    );
    assert!(
        envelope
            .verification
            .basis
            .as_deref()
            .is_some_and(|basis| basis.contains("fixture_unavailable"))
    );
    let verification = envelope
        .evidence
        .iter()
        .find(|item| item.class == EvidenceClass::PostChangeVerification)
        .expect("retain already persisted verification evidence");
    let value = store
        .read_evidence_value(&verification.content_hash)
        .expect("read verification");
    assert_eq!(value["passed"], false);
    assert!(plan.mark_consumed().is_err());
}

#[cfg(unix)]
#[test]
fn private_credential_capture_refuses_terminal_symlinks_and_hard_links() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    let root = tempfile::tempdir().expect("test root");
    let path = root.path().join("credential");
    fs::write(&path, "private-custody-sentinel\n").expect("fixture");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
    let link = root.path().join("alias");
    symlink(&path, &link).expect("terminal symlink");
    let result = read_secret_file(&link);
    assert!(
        result.is_err(),
        "a terminal symlink is not borrowed private custody"
    );
    let error = result.expect_err("symlink rejected").to_string();
    assert!(!error.contains("private-custody-sentinel"));
    fs::hard_link(&path, root.path().join("second-name")).expect("hard link");
    let error = read_secret_file(&path)
        .expect_err("multiple links rejected")
        .to_string();
    assert!(!error.contains("private-custody-sentinel"));
}

#[cfg(unix)]
#[tokio::test]
async fn mutation_boundary_timeout_retains_launch_without_a_receipt() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = tempfile::tempdir().expect("root");
    let store = authenticated_test_store(RuntimePaths::from_root(root.path()));
    let (mut plan, _) = mutation_plan(&store);
    let program = root.path().join("timeout.sh");
    fs::write(&program, "#!/bin/sh\nexec /bin/sleep 5\n").expect("fixture");
    fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).expect("mode");
    let cache = root.path().join("timeout-process-cache");
    fs::create_dir(&cache).expect("cache");
    let capability = CapabilityV1::new("wrangler.deploy", "Fixture", "CLI", "wrangler deploy");
    let input = CallInput {
        selectors: json!({}),
        query: json!({}),
        ..CallInput::default()
    };
    let boundary = cfctl_core::BoundaryObservation::default();
    let error = run_delegated_cli_with_timeout(
        &capability,
        &input,
        &AuthCredential::Bearer {
            token: "synthetic-only".into(),
        },
        Some("account"),
        &cache,
        Some(&program),
        Some(Path::new("/bin/sh")),
        Duration::from_millis(30),
        Some(&boundary),
    )
    .await
    .expect_err("timeout after launch");
    assert!(matches!(error, CliError::SubprocessTimeout { .. }));
    super::super::plan_commands::persist_delegated_pre_response_failure(
        &store,
        &mut plan,
        &MemorySecretStore::default(),
        &boundary,
    )
    .expect("retained uncertainty");
    let envelope = super::super::plan_commands::delegated_pre_response_failure_envelope(
        &plan, &error, &boundary,
    );
    assert!(!envelope.ok);
    assert!(envelope.performed);
    assert_eq!(
        envelope.operation_id.as_deref(),
        Some(plan.operation_id.as_str())
    );
    assert!(
        store
            .load_plan(&plan.operation_id)
            .expect("plan")
            .mark_consumed()
            .is_err()
    );
}

#[tokio::test]
async fn mutation_boundary_concurrent_run_cannot_pass_the_existing_plan_lock() {
    let root = tempfile::tempdir().expect("root");
    let store = authenticated_test_store(RuntimePaths::from_root(root.path()));
    let (mut plan, input) = mutation_plan(&store);
    // run_plan owns this same lock for its entire admission/dispatch/finalization
    // sequence. Hold it around the injected real executor to avoid credentials.
    let lock = store
        .lock_plan(&plan.operation_id)
        .expect("first runner lock");
    let selector = crate::PlanSelector {
        operation_id: plan.operation_id.clone(),
    };
    let (executor, server) =
        mutation_response(403, r#"{"success":false,"result":null,"errors":[]}"#).await;
    let credential = AuthCredential::Bearer {
        token: "synthetic-only".into(),
    };
    let secrets = MemorySecretStore::default();
    let (first, second) = tokio::join!(
        execute_api_plan_with_executor(
            &store,
            &executor,
            "catalog-fixture",
            &mut plan,
            &input,
            &credential,
            &secrets
        ),
        super::super::plan_commands::run_plan(&store, &selector),
    );
    assert!(first.expect("first response").performed);
    assert!(matches!(
        second,
        Err(CliError::Storage(cfctl_storage::StorageError::PlanLocked(
            _
        )))
    ));
    assert_eq!(server.await.expect("server"), 1);
    drop(lock);
    assert!(
        store
            .load_plan(&selector.operation_id)
            .expect("plan")
            .mark_consumed()
            .is_err()
    );
}

#[cfg(unix)]
#[test]
fn private_credential_capture_enforces_a_credential_specific_byte_bound() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = tempfile::tempdir().expect("root");
    let path = root.path().join("secret");
    fs::write(&path, "x".repeat(64 * 1024)).expect("at limit");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
    assert_eq!(read_secret_file(&path).expect("at limit").len(), 64 * 1024);
    fs::write(&path, "x".repeat(64 * 1024 + 1)).expect("first excess byte");
    assert!(
        read_secret_file(&path).is_err(),
        "first excess credential byte must refuse"
    );
}

#[test]
fn private_credential_stdin_is_bounded_and_preserves_whitespace() {
    use super::super::support::{MAX_CREDENTIAL_INPUT_BYTES, read_credential_stream};
    assert_eq!(
        read_credential_stream(&b"  token\n"[..]).expect("whitespace"),
        "  token\n"
    );
    let bytes =
        vec![b'x'; usize::try_from(MAX_CREDENTIAL_INPUT_BYTES).expect("finite fixture bound")];
    assert_eq!(
        read_credential_stream(bytes.as_slice())
            .expect("limit")
            .len(),
        bytes.len()
    );
    let excess = vec![b'x'; bytes.len() + 1];
    let error = read_credential_stream(excess.as_slice()).expect_err("first excess byte");
    assert!(!error.to_string().contains("xxxxxxxx"));
    assert!(read_credential_stream(&[0xff][..]).is_err());
}

#[tokio::test]
async fn mutation_boundary_transport_does_not_follow_a_write_redirect() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("loopback");
    let address = listener.local_addr().expect("address");
    let server = tokio::spawn(async move {
        let mut requests = 0;
        loop {
            let wait = if requests == 0 {
                Duration::from_secs(5)
            } else {
                Duration::from_millis(150)
            };
            let Ok(Ok((mut socket, _))) = tokio::time::timeout(wait, listener.accept()).await
            else {
                break;
            };
            requests += 1;
            let mut bytes = [0; 8192];
            let count = socket.read(&mut bytes).await.expect("request");
            assert!(String::from_utf8_lossy(&bytes[..count]).starts_with("DELETE "));
            let body = r#"{"success":false,"result":null,"errors":[]}"#;
            let status = if requests == 1 {
                "307 Temporary Redirect"
            } else {
                "403 Forbidden"
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nLocation: /redirected-write\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            socket
                .write_all(response.as_bytes())
                .await
                .expect("response");
        }
        requests
    });
    let root = tempfile::tempdir().expect("runtime");
    let store = authenticated_test_store(RuntimePaths::from_root(root.path()));
    let (mut plan, input) = mutation_plan(&store);
    let client = super::super::support::mutation_http_client()
        .expect("production mutation transport policy");
    let executor = Executor::new(client, &format!("http://{address}")).expect("local origin");
    let envelope = execute_api_plan_with_executor(
        &store,
        &executor,
        "catalog-fixture",
        &mut plan,
        &input,
        &AuthCredential::Bearer {
            token: "synthetic-only".into(),
        },
        &MemorySecretStore::default(),
    )
    .await
    .expect("response");
    assert!(!envelope.ok);
    assert!(envelope.performed);
    assert_eq!(
        server.await.expect("server"),
        1,
        "redirecting must not repeat or widen the consumed write"
    );
    assert_eq!(envelope.result["status"], 307);
}

#[test]
fn governed_ui_local_persistence_failure_retains_action_and_consumed_identity() {
    for journal_failure in [false, true] {
        let root = tempfile::tempdir().expect("runtime");
        let paths = RuntimePaths::from_root(root.path());
        let store = if journal_failure {
            authenticated_test_store(paths)
        } else {
            StorageStateStore::open(paths).expect("missing evidence authority fixture")
        };
        let mut capability = CapabilityV1::new(
            "fixture.ui",
            "Governed UI",
            "UI",
            "https://dash.cloudflare.com",
        );
        capability.adapter_status = AdapterStatus::GovernedUi;
        let mut plan = PlanV1::draft(
            "fixture",
            "account-fixture",
            "catalog-fixture",
            capability,
            json!({}),
        )
        .expect("UI plan");
        let input = CallInput::default();
        plan.approve(true, None).expect("approve");
        plan.mark_consumed().expect("consume");
        plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
            .expect("intent");
        store.save_plan(&plan).expect("persist consumed identity");
        if journal_failure {
            let plans = store.paths().data_dir.join("plans");
            fs::rename(&plans, root.path().join("retained-plans")).expect("retain consumed record");
            fs::write(&plans, "block journal publication").expect("journal fault");
        }
        let envelope =
            execute_governed_ui_plan(&store, &mut plan, &input, &MemorySecretStore::default())
                .expect("operation-bound local UI failure");
        assert!(!envelope.ok);
        assert!(
            !envelope.performed,
            "this producer creates a handoff artifact and launches no UI"
        );
        assert_eq!(
            envelope.operation_id.as_deref(),
            Some(plan.operation_id.as_str())
        );
        assert!(envelope.result.get("agent_action").is_some());
        assert!(envelope.error.is_some());
        if journal_failure {
            assert!(
                !envelope.evidence.is_empty(),
                "preserve the action already persisted"
            );
        }
    }
}
