//! Exercise the real default executor and durable verification boundary together.
#![allow(clippy::unwrap_used)]
use super::{compensation, tests::fixture};
use crate::runtime::api_boundary::{process_api_boundary_response, verify_api_plan};
use cfctl_auth::{AuthCredential, EvidenceKeyManager, MemorySecretStore, SecretBackend};
use cfctl_cloudflare::{CallInput, Executor};
use cfctl_core::{EvidenceClass, PlanStatus, TransactionStageV1, VerificationState};
use cfctl_storage::{RuntimePaths, StateStore};
use serde_json::{Value, json};
use std::{path::Path, sync::Arc};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
};

fn authenticated_store(root: &Path) -> StateStore {
    let store = StateStore::open(RuntimePaths::from_root(root)).unwrap();
    let manager = Arc::new(
        EvidenceKeyManager::new(
            Arc::new(MemorySecretStore::default()),
            store.evidence_location_identity(),
            SecretBackend::Memory,
        )
        .unwrap(),
    );
    let identity = format!("sha256:{}", "a".repeat(64));
    manager.initialize(&identity).unwrap();
    store.initialize_evidence_root_identity(&identity).unwrap();
    store.with_evidence_authenticator(manager).unwrap()
}

async fn serve(listener: TcpListener, status: u16, parent: Value) -> Vec<String> {
    let mut methods = Vec::new();
    for (method, code, body) in [
        (
            "PATCH",
            status,
            json!({"success":false,"errors":[{"code":1000,"message":"ambiguous"}],"result":null}),
        ),
        (
            "GET",
            200,
            json!({"success":true,"errors":[],"result":parent}),
        ),
    ] {
        let (socket, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(socket);
        let mut first = String::new();
        reader.read_line(&mut first).await.unwrap();
        assert!(first.starts_with(&format!("{method} /zones/")));
        methods.push(method.to_owned());
        let mut length = 0;
        loop {
            let mut line = String::new();
            assert_ne!(reader.read_line(&mut line).await.unwrap(), 0);
            if line == "\r\n" {
                break;
            }
            assert!(!line.to_ascii_lowercase().starts_with("idempotency-key:"));
            if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                length = value.trim().parse().unwrap();
            }
        }
        reader.read_exact(&mut vec![0; length]).await.unwrap();
        let body = body.to_string();
        reader.get_mut().write_all(format!(
            "HTTP/1.1 {code} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()
        ).as_bytes()).await.unwrap();
    }
    methods
}

#[tokio::test]
async fn custom_challenge_ambiguous_patch_is_single_attempt_and_keeps_authenticated_readback() {
    for status in [429, 503] {
        let root =
            tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
        let store = authenticated_store(root.path());
        let (mut plan, mut after) = fixture();
        // The PATCH may have applied, then another writer changed a sibling.
        after["rules"][1]["action"] = json!("skip");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(serve(listener, status, after.clone()));
        // Keep the normal retry setting: the capability must enforce one PATCH.
        let executor = Executor::new(reqwest::Client::new(), &origin).unwrap();
        let credential = AuthCredential::Bearer {
            token: "synthetic".into(),
        };
        let input: CallInput = serde_json::from_value(plan.input.clone()).unwrap();
        plan.refresh_hash().unwrap();
        plan.approve(true, None).unwrap();
        plan.mark_consumed().unwrap();
        plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
            .unwrap();
        let response = executor
            .execute_consumed_plan_with_input(&mut plan, "catalog", &credential, &input)
            .await
            .unwrap();
        assert_eq!(response.status, status);
        assert_eq!(plan.status, PlanStatus::RectificationRequired);
        process_api_boundary_response(&store, &mut plan, &response, &MemorySecretStore::default())
            .unwrap();
        assert_eq!(
            store.load_plan(&plan.operation_id).unwrap().status,
            PlanStatus::RectificationRequired
        );
        let outcome = verify_api_plan(&store, &executor, &mut plan, &response, &input, &credential)
            .await
            .unwrap();
        assert_eq!(plan.status, PlanStatus::RectificationRequired);
        assert_eq!(outcome.state, VerificationState::Failed);
        assert!(outcome.basis.contains("ambiguous"));
        let evidence = outcome.evidence.unwrap();
        let (authenticated, value) = store.load_evidence_value(&evidence.content_hash).unwrap();
        assert_eq!(authenticated.class, EvidenceClass::PostChangeVerification);
        assert_eq!(value["readback"]["result"], after);
        assert!(compensation(&store, &plan).is_err());
        assert!(
            executor
                .execute_consumed_plan_with_input(&mut plan, "catalog", &credential, &input)
                .await
                .is_err()
        );
        assert_eq!(server.await.unwrap(), ["PATCH", "GET"]);
    }
}
