#![allow(clippy::expect_used, clippy::unwrap_used)]
use cfctl_auth::AuthCredential;
use cfctl_cloudflare::{CallInput, Executor, r2_recovery::CaptureFiles};
use cfctl_core::{
    AdapterStatus, CapabilityV1, EffectClass, RiskClass, SelectorV1,
    r2_recovery::{self as contract},
};
use chrono::{Duration, Utc};
use serde_json::json;
use std::{
    fs::{File, OpenOptions},
    os::unix::fs::OpenOptionsExt,
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

fn credential() -> AuthCredential {
    AuthCredential::Bearer {
        token: "fixture-only".into(),
    }
}

#[tokio::test]
async fn rejects_legacy_flat_requests_before_network_or_private_writes() {
    let executor = Executor::new(reqwest::Client::new(), "http://127.0.0.1:1").unwrap();
    let files = Files(tempfile::tempdir().unwrap());
    let error = executor
        .capture_private_r2_bucket(
            &capability(),
            &input(),
            &credential(),
            "0123456789abcdef0123456789abcdef",
            &files,
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("version 2"));
    assert_eq!(std::fs::read_dir(files.0.path()).unwrap().count(), 0);
}
