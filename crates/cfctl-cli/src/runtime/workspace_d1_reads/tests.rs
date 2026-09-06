#![allow(clippy::expect_used)]
use super::*;
use cfctl_core::d1_read_inventory::{D1ReadQueryResultV1, D1ReadStatusV1};
use cfctl_storage::RuntimePaths;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .expect("git");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("Git output")
        .trim()
        .into()
}
fn commit(root: &Path) {
    git(root, &["add", "."]);
    git(
        root,
        &[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ],
    );
}
fn fixture(invalid: bool) -> (tempfile::TempDir, CapabilityV1, CallInput) {
    fixture_file(if invalid {
        "invalid-final-write.json"
    } else {
        "inventory.json"
    })
}
fn fixture_file(filename: &str) -> (tempfile::TempDir, CapabilityV1, CallInput) {
    let root = tempfile::tempdir().expect("source root");
    let data =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../cfctl-workspace/tests/fixtures/d1-reads");
    fs::create_dir_all(root.path().join(".cfctl/operations")).expect("pack directory");
    git(root.path(), &["init", "-q"]);
    git(
        root.path(),
        &[
            "remote",
            "add",
            "origin",
            "https://example.invalid/source.git",
        ],
    );
    fs::copy(data.join("source.txt"), root.path().join("source.txt")).expect("source");
    commit(root.path());
    let source = git(root.path(), &["rev-parse", "HEAD"]);
    let inventory = fs::read(data.join(filename)).expect("inventory");
    let hash = format!("sha256:{}", hex::encode(Sha256::digest(&inventory)));
    fs::write(root.path().join("inventory.json"), inventory).expect("inventory bytes");
    let pack = fs::read_to_string(data.join("pack-template.toml"))
        .expect("pack")
        .replace("SOURCE_COMMIT_40_HEX", &source);
    let mut pack: toml::Value = toml::from_str(&pack).expect("pack TOML");
    pack["operation"][0]["inventory_sha256"] = toml::Value::String(hash.clone());
    fs::write(
        root.path().join(".cfctl/operations/d1-reads.toml"),
        toml::to_string(&pack).expect("pack serialization"),
    )
    .expect("pack bytes");
    commit(root.path());
    let capability = cfctl_workspace::load_workspace_operation_capability(
        &[root.path().to_path_buf()],
        "example.d1-read-inventory",
    )
    .expect("load")
    .expect("capability");
    let input = CallInput {
        selectors: json!({"account_id":"a".repeat(32),"database_id":"11111111-2222-4333-8444-555555555555"}),
        query: json!({}),
        body: Some(
            json!({"inventory_sha256":hash,"expected_credential_generation_id":"22222222-2222-4222-8222-222222222222"}),
        ),
        ..CallInput::default()
    };
    (root, capability, input)
}
fn catalog() -> CatalogSnapshot {
    CatalogSnapshot {
        schema_version: 1,
        generated_at: Utc::now(),
        source_url: "https://example.invalid/catalog".into(),
        source_hash: "fixture".into(),
        schema_hash: "sha256:fixture".into(),
        capabilities: BTreeMap::new(),
    }
}
fn profile() -> ProfileMetadata {
    serde_json::from_value(json!({"schema_version":1,"id":"example-read","kind":"api_token","account_id":"a".repeat(32),"oauth_client_id":null,
        "oauth_scopes":[],"credential_generation_id":"22222222-2222-4222-8222-222222222222","emergency_only":false})).expect("synthetic profile")
}
fn result(validated: &ValidatedD1ReadInventory) -> D1ReadInventoryResultV1 {
    let results = validated.contract().inventory.queries.iter().enumerate().map(|(i,q)| {
        let receipt = json!({"success":true,"errors":[],"messages":[],"result":[{"success":true,"results":if i==0 {json!([{"name":"items"}])} else {json!([{"n":0}])},"meta":{"rows_read":1,"rows_written":0,"changes":0,"changed_db":false,"duration":0.1,"total_attempts":1}}]});
        D1ReadQueryResultV1 { query_id:q.id.clone(),query_sha256:q.sha256.clone(),phase:q.phase.clone(),witnesses:q.witnesses.clone(),parameter_provenance:Vec::new(),status:D1ReadStatusV1::Complete,attempted:true,classification:"complete_read".into(),http_status:Some(200),rows_read:Some(1),response_bytes:Some(512),receipt:Some(receipt) }
    }).collect();
    D1ReadInventoryResultV1 {
        schema_version: 1,
        compiler_version: 1,
        inventory_sha256: validated.call().inventory_sha256.clone(),
        read_complete: true,
        attempted_queries: 2,
        unattempted_queries: 0,
        rows_read: 2,
        response_bytes: 1024,
        hard_scan_or_currency_ceiling_established: false,
        application_predicates_evaluated: false,
        results,
    }
}
fn files(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut found = BTreeMap::new();
    for entry in fs::read_dir(root).expect("directory") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            found.extend(files(&path));
        } else {
            found.insert(path.clone(), fs::read(path).expect("file"));
        }
    }
    found
}

#[test]
fn generated_guide_carries_the_required_explicit_profile_and_exact_target() {
    let (_owner, capability, _) = fixture(false);
    let guide = super::super::guide_generation::guide_document(&capability);
    let arguments = guide.call_argv.expect("available native read guide");
    assert_eq!(
        arguments,
        [
            "cfctl",
            "call",
            "example.d1-read-inventory",
            "--profile",
            "example-read",
            "--account",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--selector",
            "account_id=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--selector",
            "database_id=11111111-2222-4333-8444-555555555555",
            "--body-stdin",
            "--json"
        ]
    );
    assert_eq!(guide.next_action.argv, arguments);
}

#[test]
fn unapproved_rows_are_rejected_before_the_actual_observation_store() {
    let (_owner, capability, input) = fixture(false);
    let validated = d1_read_inventory::validate(&capability, &input).expect("validated population");
    let runtime = tempfile::tempdir().expect("runtime");
    let store =
        super::super::tests::authenticated_test_store(RuntimePaths::from_root(runtime.path()));
    let attestation = super::super::plan_commands::observation_attestation(&store, &capability)
        .expect("observation attestation");
    let scoped = store.with_observation_attestation(&attestation);
    let good = result(&validated);
    let accepted = persist(
        &scoped,
        &catalog(),
        &capability,
        &validated,
        &profile(),
        Utc::now(),
        &good,
    )
    .expect("actual durable qualified observation");
    assert!(accepted.envelope.ok);
    assert_eq!(
        accepted.envelope.result["execution"]["results"][0]["receipt"]["result"][0]["results"][0]["name"],
        "items"
    );
    let before = files(runtime.path());
    let mut bad = good.clone();
    bad.results[0].receipt.as_mut().expect("receipt")["result"][0]["results"][0]["private_value"] =
        json!("PRIVATE_DURABLE_MARKER");
    let error = persist(
        &scoped,
        &catalog(),
        &capability,
        &validated,
        &profile(),
        Utc::now(),
        &bad,
    )
    .expect_err("unexpected row must be refused");
    assert!(error.to_string().contains("unapproved row material"));
    assert!(!error.to_string().contains("PRIVATE_DURABLE_MARKER"));
    assert_eq!(
        before,
        files(runtime.path()),
        "rejected provider material must not change any durable runtime file"
    );
    let mut bad = good;
    bad.results[0].receipt.as_mut().expect("receipt")["result"][0]["meta"]["rows_written"] =
        json!(1);
    assert!(
        persist(
            &scoped,
            &catalog(),
            &capability,
            &validated,
            &profile(),
            Utc::now(),
            &bad
        )
        .is_err()
    );
    assert_eq!(before, files(runtime.path()));
}

#[tokio::test]
async fn bad_final_query_is_refused_before_missing_profile_or_credential_access() {
    let (owner, capability, input) = fixture(true);
    let runtime = tempfile::tempdir().expect("runtime");
    let store =
        super::super::tests::authenticated_test_store(RuntimePaths::from_root(runtime.path()));
    store
        .register_workspace(owner.path(), Some("a".repeat(32)))
        .expect("registered source");
    let error = execute(
        &store,
        &catalog(),
        &capability,
        &input,
        Some("example-read"),
        Some(&"a".repeat(32)),
    )
    .await
    .expect_err("final DELETE is rejected locally");
    assert!(error.to_string().contains("read query identity"), "{error}");
    assert!(!store.paths().profiles_file().exists());
}

fn reconciliation_result(validated: &ValidatedD1ReadInventory) -> D1ReadInventoryResultV1 {
    let bodies: Vec<serde_json::Value> = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../cfctl-workspace/tests/fixtures/d1-reads/reconciliation-qualified-responses.json"
    )))
    .expect("synthetic receipts");
    let source = &validated.contract().inventory.queries[0];
    let results = validated
        .contract()
        .inventory
        .queries
        .iter()
        .zip(bodies)
        .map(|(q, receipt)| {
            let provenance = q
                .parameters
                .iter()
                .map(
                    |p| cfctl_core::d1_read_inventory::D1ReadParameterEvidenceV1 {
                        index: p.index,
                        from_query: p.from_query.clone(),
                        from_query_sha256: source.sha256.clone(),
                        row_index: p.row_index,
                        column: p.column.clone(),
                        value_sha256: cfctl_core::hash_value(&json!("example-organization"))
                            .expect("digest"),
                    },
                )
                .collect();
            D1ReadQueryResultV1 {
                query_id: q.id.clone(),
                query_sha256: q.sha256.clone(),
                phase: q.phase.clone(),
                witnesses: q.witnesses.clone(),
                parameter_provenance: provenance,
                status: D1ReadStatusV1::Complete,
                attempted: true,
                classification: "complete_read".into(),
                http_status: Some(200),
                rows_read: receipt
                    .pointer("/result/0/meta/rows_read")
                    .and_then(serde_json::Value::as_u64),
                response_bytes: Some(512),
                receipt: Some(receipt),
            }
        })
        .collect::<Vec<_>>();
    D1ReadInventoryResultV1 {
        schema_version: 1,
        compiler_version: 1,
        inventory_sha256: validated.call().inventory_sha256.clone(),
        read_complete: true,
        attempted_queries: 3,
        unattempted_queries: 0,
        rows_read: results.iter().map(|r| r.rows_read.unwrap_or(0)).sum(),
        response_bytes: 1536,
        hard_scan_or_currency_ceiling_established: false,
        application_predicates_evaluated: false,
        results,
    }
}

#[test]
fn altered_parameter_provenance_cannot_cross_the_actual_observation_store() {
    let (_owner, capability, input) = fixture_file("reconciliation-inventory.json");
    let validated = d1_read_inventory::validate(&capability, &input).expect("whole population");
    let runtime = tempfile::tempdir().expect("runtime");
    let store =
        super::super::tests::authenticated_test_store(RuntimePaths::from_root(runtime.path()));
    let attestation = super::super::plan_commands::observation_attestation(&store, &capability)
        .expect("attestation");
    let scoped = store.with_observation_attestation(&attestation);
    let good = reconciliation_result(&validated);
    persist(
        &scoped,
        &catalog(),
        &capability,
        &validated,
        &profile(),
        Utc::now(),
        &good,
    )
    .expect("qualified persistence");
    let before = files(runtime.path());
    for changed_source in [false, true] {
        let mut bad = good.clone();
        if changed_source {
            bad.results[0].receipt.as_mut().expect("receipt")["result"][0]["results"][0]["id"] =
                json!("altered-organization");
        } else {
            bad.results[1].parameter_provenance[0].value_sha256 =
                cfctl_core::hash_value(&json!("replacement")).expect("digest");
        }
        assert!(
            persist(
                &scoped,
                &catalog(),
                &capability,
                &validated,
                &profile(),
                Utc::now(),
                &bad
            )
            .is_err()
        );
        assert_eq!(
            before,
            files(runtime.path()),
            "no altered value/provenance may be persisted"
        );
    }
}
