use super::super::private_output::{persist as persist_private, prepare};
use super::*;
use cfctl_cloudflare::d1_read_inventory::PrivateD1ReadResult;
use cfctl_core::d1_read_inventory::D1PrivateReadArtifactV1;
use std::{
    os::unix::fs::PermissionsExt,
    time::{Duration, Instant},
};

#[test]
fn generated_private_artifact_example_roundtrips_through_exact_rust_types() {
    let value: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../cfctl-workspace/tests/fixtures/d1-reads/private-artifact.json"
    )))
    .expect("synthetic wire example");
    let artifact: D1PrivateReadArtifactV1 =
        serde_json::from_value(value.clone()).expect("typed wire artifact");
    assert_eq!(
        serde_json::to_value(artifact).expect("serialize exact wire"),
        value
    );
}

fn private_result(text: &str) -> PrivateD1ReadResult {
    PrivateD1ReadResult {
        attempted: true,
        classification: "complete_read",
        http_status: Some(200),
        response_bytes: 512,
        rows_read: 1,
        deadline: Instant::now() + Duration::from_secs(30),
        provider_response: Some(json!({"success":true,"errors":[],"messages":[],
            "result":[{"success":true,"results":[{"name":text}],"meta":{
                "rows_read":1,"rows_written":0,"changes":0,"changed_db":false,
                "duration":0.1,"total_attempts":1,"served_by_primary":true}}]})),
    }
}

#[test]
fn private_loader_guide_and_actual_persistence_preserve_rows_only_in_private_artifact() {
    let (_owner, capability, input) = fixture_file("private-inventory.json");
    let validated = d1_read_inventory::validate(&capability, &input).expect("validated");
    let guide = super::super::super::guide_generation::guide_document(&capability);
    let arguments = guide.call_argv.expect("private guide");
    assert!(
        arguments
            .windows(2)
            .any(|p| p == ["--out", "<new-file-in-owned-mode-0700-directory>"])
    );
    assert_eq!(guide.next_action.argv, arguments);
    let runtime = tempfile::tempdir().expect("runtime");
    let store = super::super::super::tests::authenticated_test_store(RuntimePaths::from_root(
        runtime.path(),
    ));
    let destination = tempfile::tempdir().expect("private output");
    fs::set_permissions(destination.path(), fs::Permissions::from_mode(0o700)).expect("mode");
    let path = destination
        .path()
        .canonicalize()
        .expect("canonical")
        .join("artifact.json");
    let sink = prepare(&validated, Some(&path))
        .expect("preflight")
        .expect("private sink");
    let canary = "PRIVATE_CANARY {\"key\":1,\"key\":2} 雪";
    let executed = persist_private(
        &store,
        &catalog(),
        &capability,
        &validated,
        &profile(),
        Utc::now(),
        private_result(canary),
        &sink,
    )
    .expect("publish");
    assert!(executed.envelope.ok && executed.envelope.performed);
    let public = serde_json::to_string(&executed.envelope).expect("public JSON");
    assert!(!public.contains("PRIVATE_CANARY"));
    assert!(!public.contains("provider_response"));
    for bytes in files(runtime.path()).values() {
        assert!(!String::from_utf8_lossy(bytes).contains("PRIVATE_CANARY"));
    }
    let bytes = fs::read(&path).expect("artifact");
    let artifact: D1PrivateReadArtifactV1 = serde_json::from_slice(&bytes).expect("typed artifact");
    assert_eq!(
        artifact
            .provider_response
            .pointer("/result/0/results/0/name"),
        Some(&json!(canary))
    );
    assert_eq!(artifact.binding.contract, *validated.contract());
    assert_eq!(
        artifact.binding.credential_generation_id.to_string(),
        validated.call().expected_credential_generation_id
    );
    assert!(public.contains(&hex::encode(Sha256::digest(&bytes))));
    assert_eq!(
        fs::metadata(&path).expect("metadata").permissions().mode() & 0o7777,
        0o600
    );
    assert!(prepare(&validated, Some(&path)).is_err());
    let mut serialized = serde_json::to_value(&artifact).expect("artifact JSON");
    serialized["unexpected"] = json!(true);
    assert!(serde_json::from_value::<D1PrivateReadArtifactV1>(serialized).is_err());
}

#[tokio::test]
async fn private_missing_or_unsafe_destination_fails_before_profile_access() {
    let (owner, capability, input) = fixture_file("private-inventory.json");
    let runtime = tempfile::tempdir().expect("runtime");
    let store = super::super::super::tests::authenticated_test_store(RuntimePaths::from_root(
        runtime.path(),
    ));
    store
        .register_workspace(owner.path(), Some("a".repeat(32)))
        .expect("register");
    let unsafe_root = tempfile::tempdir().expect("unsafe directory");
    fs::set_permissions(unsafe_root.path(), fs::Permissions::from_mode(0o755)).expect("mode");
    let path = unsafe_root.path().join("artifact.json");
    for output in [None, Some(path.as_path())] {
        let error = execute(
            &store,
            &catalog(),
            &capability,
            &input,
            Some("example-read"),
            Some(&"a".repeat(32)),
            output,
        )
        .await
        .expect_err("preflight");
        assert!(error.to_string().contains("private"));
        assert!(!store.paths().profiles_file().exists());
    }
}

#[test]
fn private_failure_deadline_and_artifact_bound_never_publish_or_disclose_rows() {
    let (_owner, mut capability, input) = fixture_file("private-inventory.json");
    for case in 0..4 {
        let runtime = tempfile::tempdir().expect("runtime");
        let store = super::super::super::tests::authenticated_test_store(RuntimePaths::from_root(
            runtime.path(),
        ));
        let destination = tempfile::tempdir().expect("destination");
        fs::set_permissions(destination.path(), fs::Permissions::from_mode(0o700)).expect("mode");
        let path = destination
            .path()
            .canonicalize()
            .expect("canonical")
            .join("artifact.json");
        capability
            .workspace_d1_read_inventory
            .as_mut()
            .expect("contract")
            .inventory
            .private_output
            .as_mut()
            .expect("private")
            .max_artifact_bytes = if case == 3 { 1 } else { 262_144 };
        let validated = d1_read_inventory::validate(&capability, &input).expect("validated");
        let sink = prepare(&validated, Some(&path))
            .expect("preflight")
            .expect("sink");
        let mut result = private_result("PRIVATE_CANARY");
        match case {
            0 => {
                result.provider_response.as_mut().expect("body")["result"][0]["meta"]["served_by_primary"] =
                    json!(false);
            }
            1 => {
                result.deadline = Instant::now();
            }
            2 => {
                result.provider_response = None;
                result.classification = "transport_or_response_rejected";
            }
            _ => {}
        }
        let executed = persist_private(
            &store,
            &catalog(),
            &capability,
            &validated,
            &profile(),
            Utc::now(),
            result,
            &sink,
        )
        .expect("fixed failure receipt");
        assert!(!executed.envelope.ok);
        assert!(executed.envelope.performed);
        assert!(!path.exists());
        assert!(
            !serde_json::to_string(&executed.envelope)
                .expect("public")
                .contains("PRIVATE_CANARY")
        );
        for bytes in files(runtime.path()).values() {
            assert!(!String::from_utf8_lossy(bytes).contains("PRIVATE_CANARY"));
        }
    }
}

#[test]
fn post_publication_evidence_failure_preserves_file_and_reports_attempted_incomplete_custody() {
    let (_owner, capability, input) = fixture_file("private-inventory.json");
    let validated = d1_read_inventory::validate(&capability, &input).expect("validated");
    let runtime = tempfile::tempdir().expect("runtime");
    let store = StateStore::open(RuntimePaths::from_root(runtime.path()))
        .expect("store without authenticator");
    let destination = tempfile::tempdir().expect("destination");
    fs::set_permissions(destination.path(), fs::Permissions::from_mode(0o700)).expect("mode");
    let path = destination
        .path()
        .canonicalize()
        .expect("canonical")
        .join("artifact.json");
    let sink = prepare(&validated, Some(&path))
        .expect("preflight")
        .expect("sink");
    let executed = persist_private(
        &store,
        &catalog(),
        &capability,
        &validated,
        &profile(),
        Utc::now(),
        private_result("PRIVATE_CANARY"),
        &sink,
    )
    .expect("fixed failure receipt");
    assert!(!executed.envelope.ok && executed.envelope.performed);
    assert_eq!(
        executed.envelope.result["classification"],
        "private_observation_incomplete"
    );
    assert_eq!(executed.envelope.result["possibly_published"], true);
    assert!(executed.envelope.result["artifact"].is_null());
    assert!(path.is_file());
    assert!(
        !serde_json::to_string(&executed.envelope)
            .expect("public")
            .contains("PRIVATE_CANARY")
    );
}
