use super::*;
mod failed_reconciliation;

const RESTORE_ID: &str = "d1-restore-exact-bookmark";
const CONTEXT: &str = "d1_restore_execution";
const ACCOUNT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DATABASE: &str = "11111111-1111-4111-8111-111111111111";

fn catalog() -> CatalogSnapshot {
    let mut catalog = CatalogSnapshot {
        schema_version: 1,
        generated_at: Utc::now(),
        source_url: "fixture://d1-restore".to_owned(),
        source_hash: hash_value(&json!("fixture-source")).expect("source hash"),
        schema_hash: hash_value(&json!("fixture-catalog")).expect("catalog hash"),
        capabilities: BTreeMap::new(),
    };
    ingest_native_control_capabilities(&mut catalog).expect("native catalog");
    catalog
}

fn input() -> CallInput {
    CallInput {
        selectors: json!({"account_id":ACCOUNT,"database_id":DATABASE}),
        query: json!({}),
        body: Some(json!({
            "target_bookmark":"target /+&?=#",
            "expected_current_bookmark":"current-bookmark",
            "source_operation_id":"caller-source-operation-without-export-record",
            "source_evidence_hash":format!("sha256:{}", "b".repeat(64)),
        })),
        ..CallInput::default()
    }
}

fn pending_plan(store: &StorageStateStore) -> PlanV1 {
    pending_plan_with_input(store, &input())
}

fn pending_plan_with_input(store: &StorageStateStore, input: &CallInput) -> PlanV1 {
    let catalog = catalog();
    let mut plan = PlanV1::draft(
        "restore-fixture",
        ACCOUNT,
        &catalog.schema_hash,
        catalog.get(RESTORE_ID).expect("restore capability").clone(),
        json!({"account_id":ACCOUNT,"database_id":DATABASE}),
    )
    .expect("draft restore");
    plan.input = serde_json::to_value(input).expect("input JSON");
    "api_token".clone_into(&mut plan.permission_lane);
    plan.refresh_hash().expect("input-bound plan");
    plan.approve(true, None).expect("explicit restore approval");
    plan.mark_consumed().expect("consume restore");
    plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("boundary attempt");
    let pins = PlanPinsV2 {
        build_identity_hash: hash_value(&json!("historical-build")).expect("build hash"),
        catalog_hash: plan.catalog_hash.clone(),
        credential_generation_id: "22222222-2222-4222-8222-222222222222".to_owned(),
        admission_policy_hash: hash_value(&json!("policy")).expect("policy hash"),
        authority_hash: Some(hash_value(&json!("authority")).expect("authority hash")),
        workspace_graph_hash: hash_value(&json!("workspace")).expect("workspace hash"),
        resource_observation_hashes: BTreeMap::new(),
        cost_budget: None,
    };
    store
        .save_plan_v2(&PlanV2::new(plan.clone(), pins).expect("pinned plan"))
        .expect("persist pinned plan");
    plan
}

struct MockServer(tokio::task::JoinHandle<Vec<String>>);

impl Drop for MockServer {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn mock_server() -> (String, MockServer) {
    mock_server_with_results(vec![
        json!({"bookmark":"current-bookmark"}),
        json!({"bookmark":"returned-bookmark","previous_bookmark":"previous-bookmark", "message":"restored"}),
        json!({"bookmark":"returned-bookmark"}),
    ]).await
}

async fn mock_server_with_results(results: Vec<Value>) -> (String, MockServer) {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("local mock listener");
    let address = listener.local_addr().expect("local mock address");
    let task = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(10), async move {
            let mut requests = Vec::new();
            for result in results {
                let (mut stream, _) = listener.accept().await.expect("mock connection");
                let mut request = Vec::new();
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let mut chunk = [0_u8; 2048];
                    let count = stream.read(&mut chunk).await.expect("mock request");
                    assert!(count > 0 && request.len() + count <= 16384);
                    request.extend_from_slice(&chunk[..count]);
                }
                requests.push(String::from_utf8(request).expect("mock request UTF-8"));
                let body = json!({"success":true,"errors":[],"result":result}).to_string();
                stream.write_all(format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()
                ).as_bytes()).await.expect("mock response");
            }
            requests
        }).await.expect("bounded mock transaction")
    });
    (format!("http://{address}/client/v4"), MockServer(task))
}

async fn executed_plan(store: &StorageStateStore) -> PlanV1 {
    let mut plan = pending_plan(store);
    let (url, mut server) = mock_server().await;
    let executor = Executor::new(reqwest::Client::new(), &url).expect("mock executor");
    let credential = AuthCredential::Bearer {
        token: "fixture-token".to_owned(),
    };
    let apply = executor
        .execute_consumed_plan_with_input(&mut plan, &catalog().schema_hash, &credential, &input())
        .await
        .expect("native restore execution");
    assert!(matches!(
        process_api_boundary_response(store, &mut plan, &apply, &MemorySecretStore::default())
            .expect("persist native apply"),
        ApiBoundaryResponseOutcome::Ready { .. }
    ));
    let outcome = verify_api_plan(store, &executor, &mut plan, &apply, &input(), &credential)
        .await
        .expect("native verification and signed context");
    assert_eq!(outcome.state, VerificationState::Passed);
    persist_transaction_stage(store, &mut plan, TransactionStageV1::Closed)
        .expect("close native restore");
    let requests = (&mut server.0).await.expect("mock completion");
    assert_eq!(requests.len(), 3);
    assert!(requests[0].starts_with("GET ") && requests[2].starts_with("GET "));
    assert!(requests[1].starts_with(&format!(
        "POST /client/v4/accounts/{ACCOUNT}/d1/database/{DATABASE}/time_travel/restore?bookmark=target+%2F%2B%26%3F%3D%23 "
    )));
    assert!(requests[1].ends_with("\r\n\r\n"));
    plan
}

struct Fixture {
    root: tempfile::TempDir,
    store: StorageStateStore,
    plan: PlanV1,
}

impl Fixture {
    async fn new() -> Self {
        let root = tempfile::tempdir().expect("restore fixture root");
        let store = authenticated_test_store(RuntimePaths::from_root(root.path()));
        let plan = Box::pin(executed_plan(&store)).await;
        Self { root, store, plan }
    }

    fn show(&self) -> ResultEnvelopeV2 {
        show_plan(
            &self.store,
            &PlanSelector {
                operation_id: self.plan.operation_id.clone(),
            },
        )
        .expect("readable restore plan")
    }

    fn verification(&self) -> (EvidenceV1, Value) {
        let hash = self
            .plan
            .transaction_artifact(TransactionStageV1::VerificationResponsePersisted)
            .expect("verification artifact")["evidence_hash"]
            .as_str()
            .expect("verification hash");
        self.store
            .load_evidence_value(hash)
            .expect("authenticated verification")
    }

    fn apply(&self) -> (EvidenceV1, Value) {
        let hash = self
            .plan
            .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
            .expect("apply artifact")["apply_evidence_hash"]
            .as_str()
            .expect("apply hash");
        self.store
            .load_evidence_value(hash)
            .expect("authenticated apply")
    }

    fn save(&self) {
        let mut document = self
            .store
            .load_plan_v2(&self.plan.operation_id)
            .expect("stored pins");
        document
            .refresh_from_plan(self.plan.clone())
            .expect("valid rewritten journal");
        self.store
            .save_plan_v2(&document)
            .expect("save rewritten plan");
    }

    fn replace_verification(&mut self, descriptor: &EvidenceV1, body: &Value) {
        self.plan.transaction_journal.retain(|checkpoint| {
            !matches!(
                checkpoint.stage,
                TransactionStageV1::VerificationResponsePersisted | TransactionStageV1::Closed
            )
        });
        self.plan
            .transaction_artifacts
            .remove(TransactionStageV1::VerificationResponsePersisted.as_str());
        self.plan
            .transaction_artifacts
            .remove(TransactionStageV1::Closed.as_str());
        self.plan.transaction_stage = TransactionStageV1::VerificationAttemptPersisted;
        self.plan.status = PlanStatus::Verified;
        self.plan.record_transaction_stage_with_artifact(
            TransactionStageV1::VerificationResponsePersisted,
            json!({"state":"passed","basis_hash":hash_value(&body["basis"]).expect("basis hash"),
                "evidence_hash":descriptor.content_hash,"resource_id":null}),
        ).expect("replacement verification checkpoint");
        self.plan
            .record_transaction_stage(TransactionStageV1::Closed)
            .expect("reclose fixture");
        self.save();
    }

    fn assert_unqualified(&self, reason: &str) {
        let envelope = self.show();
        let projection = &envelope.result["d1_restore_verification"];
        assert_eq!(projection["qualified"], false);
        assert_eq!(projection["qualification"], "unqualified");
        assert_eq!(projection["reason"], reason);
        assert_eq!(projection["provider_requests"], 0);
        assert_eq!(envelope.verification.state, VerificationState::Failed);
    }
}

/// Deliberately forge every unkeyed plan/journal hash, preserving timestamps.
/// Rejection must come from the authenticated execution binding, not a broken
/// JSON self-hash or an accidentally invalid journal in the adversarial fixture.
fn rehash_plan(plan: &mut PlanV1) {
    let previous_content_hash = plan.content_hash.clone();
    plan.refresh_hash().expect("recompute unkeyed plan hash");
    if let Some(approval) = plan.approval.as_mut() {
        approval
            .approved_content_hash
            .clone_from(&plan.content_hash);
        plan.transaction_artifacts.insert(TransactionStageV1::ApprovalPersisted.as_str().to_owned(),
            json!({"schema_version":1,"operation_id":plan.operation_id,
                "approved_at":approval.approved_at,"approved_content_hash":approval.approved_content_hash,
                "max_cost":approval.max_cost}));
    }
    let mut previous = None;
    for checkpoint in &mut plan.transaction_journal {
        if checkpoint.plan_content_hash == previous_content_hash {
            checkpoint.plan_content_hash.clone_from(&plan.content_hash);
        }
        checkpoint.previous_checkpoint_hash.clone_from(&previous);
        checkpoint.artifact_hash = plan
            .transaction_artifacts
            .get(checkpoint.stage.as_str())
            .map(|artifact| hash_value(artifact).expect("unkeyed artifact hash"));
        let mut content = json!({"operation_id":plan.operation_id,
            "plan_content_hash":checkpoint.plan_content_hash,"plan_status":checkpoint.plan_status,
            "stage":checkpoint.stage,"recorded_at":checkpoint.recorded_at,
            "previous_checkpoint_hash":checkpoint.previous_checkpoint_hash});
        if let Some(hash) = &checkpoint.artifact_hash {
            content["artifact_hash"] = json!(hash);
        }
        checkpoint.checkpoint_hash = hash_value(&content).expect("unkeyed checkpoint hash");
        previous = Some(checkpoint.checkpoint_hash.clone());
    }
    plan.validate_transaction_journal()
        .expect("fully valid forged journal");
}

fn overwrite_unkeyed_plan_files(store: &StorageStateStore, document: &PlanV2) {
    for (directory, body) in [
        (
            "plans-v2",
            serde_json::to_vec_pretty(document).expect("fixture PlanV2 JSON"),
        ),
        (
            "plans",
            serde_json::to_vec_pretty(&document.plan).expect("fixture projection JSON"),
        ),
    ] {
        fs::write(
            store
                .paths()
                .data_dir
                .join(directory)
                .join(format!("{}.json", document.plan.operation_id)),
            body,
        )
        .expect("overwrite only isolated unkeyed fixture files");
    }
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    walkdir::WalkDir::new(root)
        .into_iter()
        .map(|entry| entry.expect("fixture entry"))
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| {
            (
                entry.path().to_path_buf(),
                fs::read(entry.path()).expect("fixture bytes"),
            )
        })
        .collect()
}

#[tokio::test]
async fn d1_restore_proof_native_producer_and_both_inspection_commands_join_exact_execution() {
    let fixture = Fixture::new().await;
    let before = snapshot(fixture.root.path());
    let show = plans_command(
        &fixture.store,
        PlansCommand::Show(PlanSelector {
            operation_id: fixture.plan.operation_id.clone(),
        }),
    )
    .await
    .expect("plans show");
    let status = plans_command(
        &fixture.store,
        PlansCommand::Status(PlanSelector {
            operation_id: fixture.plan.operation_id.clone(),
        }),
    )
    .await
    .expect("plans status");
    assert_eq!(show.result, status.result);
    let projection = &show.result["d1_restore_verification"];
    let document = fixture
        .store
        .load_plan_v2(&fixture.plan.operation_id)
        .expect("native PlanV2");
    let (apply, _) = fixture.apply();
    let (verified, verification) = fixture.verification();
    assert_eq!(show.verification.state, VerificationState::Passed);
    assert_eq!(projection["qualified"], true);
    assert_eq!(
        projection["qualification"],
        "authenticated_restore_verification"
    );
    assert_eq!(projection["binding"], verification[CONTEXT]);
    let binding = &projection["binding"];
    assert_eq!(binding["operation_id"], fixture.plan.operation_id);
    assert_eq!(binding["capability_id"], RESTORE_ID);
    assert_eq!(binding["plan_content_hash"], fixture.plan.content_hash);
    assert_eq!(
        binding["pins_hash"],
        hash_value(&json!(document.pins)).expect("pins hash")
    );
    assert_eq!(binding["profile_id"], "restore-fixture");
    assert_eq!(
        binding["credential_generation_id"],
        document.pins.credential_generation_id
    );
    assert_eq!(binding["account_id"], ACCOUNT);
    assert_eq!(binding["database_id"], DATABASE);
    assert_eq!(binding["caller_inputs"], input().body.expect("caller body"));
    assert_eq!(binding["apply_evidence_hash"], apply.content_hash);
    assert_eq!(
        projection["evidence"]["verification"]["content_hash"],
        verified.content_hash
    );
    assert_eq!(projection["evidence"]["apply"]["class"], "apply");
    assert_eq!(
        projection["evidence"]["verification"]["class"],
        "post_change_verification"
    );
    assert_eq!(
        projection["bookmarks"]["pre_restore_bookmark"],
        "current-bookmark"
    );
    assert_eq!(
        projection["bookmarks"]["post_restore_bookmark"],
        "returned-bookmark"
    );
    assert_eq!(projection["readback_passed"], true);
    assert_eq!(projection["provider_requests"], 0);
    for field in [
        "current_provider_state_qualified",
        "source_export_lineage_qualified",
        "changed_state_rollback_qualified",
        "write_authority_granted",
    ] {
        assert_eq!(projection[field], false, "{field}");
    }
    assert!(!fixture.store.paths().catalog_file().exists());
    assert!(!fixture.store.paths().profiles_file().exists());
    assert_eq!(
        snapshot(fixture.root.path()),
        before,
        "inspection writes no state"
    );
}

#[tokio::test]
async fn d1_restore_proof_rejects_cross_operation_authenticated_receipts_even_with_same_apply() {
    let mut fixture = Fixture::new().await;
    let first_operation = fixture.plan.operation_id.clone();
    let first_apply = fixture.apply().0;
    let (first_descriptor, first_verification) = fixture.verification();
    fixture.plan = Box::pin(executed_plan(&fixture.store)).await;
    assert_ne!(fixture.plan.operation_id, first_operation);
    // Content-addressed Apply bytes may be identical across executions. Fresh
    // operation-bound verification still qualifies the second native execution.
    assert_eq!(fixture.apply().0, first_apply);
    assert_eq!(
        fixture.show().result["d1_restore_verification"]["qualified"],
        true
    );
    fixture.replace_verification(&first_descriptor, &first_verification);
    fixture.assert_unqualified("restore_execution_binding_mismatch");
}

#[tokio::test]
async fn d1_restore_proof_rejects_fabricated_operation_and_every_rebound_plan_identity() {
    let fixture = Fixture::new().await;
    let original = fixture
        .store
        .load_plan_v2(&fixture.plan.operation_id)
        .expect("original PlanV2");
    for field in [
        "operation",
        "input",
        "database",
        "account",
        "target",
        "profile",
        "generation",
        "catalog",
        "build",
        "authority",
        "capability",
        "request_hash",
    ] {
        let mut forged = original.clone();
        match field {
            "operation" => forged.plan.operation_id = Uuid::new_v4().to_string(),
            "input" => forged.plan.input["body"]["source_operation_id"] = json!("borrowed-source"),
            "database" => {
                forged.plan.input["selectors"]["database_id"] = json!(Uuid::new_v4().to_string());
            }
            "account" => {
                forged.plan.account_id = "c".repeat(32);
                forged.plan.input["selectors"]["account_id"] = json!(forged.plan.account_id);
            }
            "target" => forged.plan.targets["database_id"] = json!(Uuid::new_v4().to_string()),
            "profile" => "different-profile".clone_into(&mut forged.plan.profile_id),
            "generation" => forged.pins.credential_generation_id = Uuid::new_v4().to_string(),
            "catalog" => {
                forged.plan.catalog_hash = hash_value(&json!("other-catalog")).expect("hash");
                forged
                    .pins
                    .catalog_hash
                    .clone_from(&forged.plan.catalog_hash);
            }
            "build" => {
                forged.pins.build_identity_hash = hash_value(&json!("other-build")).expect("hash");
            }
            "authority" => {
                forged.pins.authority_hash =
                    Some(hash_value(&json!("other-authority")).expect("hash"));
            }
            "capability" => {
                forged.plan.capability.description = Some("different contract identity".to_owned());
            }
            "request_hash" => forged.plan.input["if_match"] = json!("different-request"),
            _ => unreachable!(),
        }
        rehash_plan(&mut forged.plan);
        let forged = PlanV2::new(forged.plan, forged.pins).expect("self-consistent forged PlanV2");
        // The normal writer correctly refuses replacing execution pins. Model
        // tampering with the unkeyed on-disk records, without weakening that
        // writer or changing either authenticated evidence body/descriptor.
        if forged.plan.operation_id != original.plan.operation_id {
            fixture
                .store
                .save_plan_v2(&forged)
                .expect("create isolated forged operation");
        }
        overwrite_unkeyed_plan_files(&fixture.store, &forged);
        assert_eq!(
            fixture
                .store
                .load_plan_v2(&forged.plan.operation_id)
                .expect("forged plan passes native self-hash validation"),
            forged
        );
        let envelope = show_plan(
            &fixture.store,
            &PlanSelector {
                operation_id: forged.plan.operation_id,
            },
        )
        .expect("forged plan remains readable");
        let projection = &envelope.result["d1_restore_verification"];
        assert_eq!(projection["qualified"], false, "{field}");
        assert_eq!(
            projection["reason"], "restore_execution_binding_mismatch",
            "{field}"
        );
        overwrite_unkeyed_plan_files(&fixture.store, &original);
    }
}

#[tokio::test]
async fn d1_restore_proof_rejects_missing_or_tampered_bodies_and_descriptors() {
    for artifact in ["apply", "verification"] {
        for corruption in [
            "missing-body",
            "changed-body",
            "missing-descriptor",
            "changed-descriptor",
        ] {
            let fixture = Fixture::new().await;
            let descriptor = if artifact == "apply" {
                fixture.apply().0
            } else {
                fixture.verification().0
            };
            let descriptor_path = fixture
                .store
                .paths()
                .data_dir
                .join("evidence-descriptors")
                .join(format!("{}.json", &descriptor.content_hash[7..]));
            let path = if corruption.ends_with("descriptor") {
                descriptor_path
            } else {
                PathBuf::from(descriptor.path)
            };
            if corruption.starts_with("missing") {
                fs::remove_file(path).expect("remove only the isolated fixture artifact");
            } else {
                fs::write(path, b"{}").expect("tamper only the isolated fixture artifact");
            }
            fixture.assert_unqualified(if artifact == "apply" {
                "apply_evidence_unavailable_or_unauthenticated"
            } else {
                "verification_evidence_unavailable_or_unauthenticated"
            });
        }
    }
}

#[tokio::test]
async fn d1_restore_proof_rejects_old_unattested_or_wrong_class_verification() {
    for variant in ["old-unbound", "unattested", "wrong-class"] {
        let mut fixture = Fixture::new().await;
        let (_, mut body) = fixture.verification();
        body["fixture_variant"] = json!(variant);
        if variant == "old-unbound" {
            body.as_object_mut()
                .expect("verification object")
                .remove(CONTEXT);
        }
        let descriptor = match variant {
            "unattested" => fixture
                .store
                .write_audit_evidence(EvidenceClass::PostChangeVerification, &body),
            "wrong-class" => fixture.store.write_evidence(EvidenceClass::Apply, &body),
            _ => fixture
                .store
                .write_evidence(EvidenceClass::PostChangeVerification, &body),
        }
        .expect("replacement isolated evidence");
        fixture.replace_verification(&descriptor, &body);
        fixture.assert_unqualified(match variant {
            "old-unbound" => "historical_unbound_verification",
            "unattested" => "verification_evidence_unavailable_or_unauthenticated",
            _ => "wrong_verification_evidence_class",
        });
    }
}

#[tokio::test]
async fn d1_restore_proof_rejects_wrong_class_or_unattested_apply() {
    for unattested in [false, true] {
        let mut fixture = Fixture::new().await;
        let (_, mut body) = fixture.apply();
        body["fixture_variant"] = json!(unattested);
        let descriptor = if unattested {
            fixture
                .store
                .write_audit_evidence(EvidenceClass::Apply, &body)
        } else {
            fixture
                .store
                .write_evidence(EvidenceClass::PostChangeVerification, &body)
        }
        .expect("replacement apply fixture");
        fixture
            .plan
            .transaction_artifacts
            .get_mut(TransactionStageV1::BoundaryResponsePersisted.as_str())
            .expect("boundary artifact")["apply_evidence_hash"] = json!(descriptor.content_hash);
        rehash_plan(&mut fixture.plan);
        fixture.save();
        fixture.assert_unqualified(if unattested {
            "apply_evidence_unavailable_or_unauthenticated"
        } else {
            "wrong_apply_evidence_class"
        });
    }
}

#[tokio::test]
async fn d1_restore_proof_rejects_authenticated_bookmark_input_status_and_context_mismatches() {
    for pointer in [
        "/passed",
        "/strategy",
        "/readback/success",
        "/readback/status",
        "/readback/result/bookmark",
        "/readback/result/_cfctl/pre_restore_bookmark",
        "/readback/result/_cfctl/source_evidence_hash",
        "/readback/result/_cfctl/request_digest",
        "/readback/result/_cfctl/verified",
        "/d1_restore_execution/apply_evidence_hash",
        "/d1_restore_execution/verification_attempt_checkpoint_hash",
    ] {
        let mut fixture = Fixture::new().await;
        let (_, mut body) = fixture.verification();
        *body.pointer_mut(pointer).expect("mismatch target") = match pointer {
            "/passed" | "/readback/success" | "/readback/result/_cfctl/verified" => json!(false),
            "/readback/status" => json!(500),
            _ => json!("mismatched"),
        };
        let descriptor = fixture
            .store
            .write_evidence(EvidenceClass::PostChangeVerification, &body)
            .expect("authenticated but mismatched observation");
        fixture.replace_verification(&descriptor, &body);
        assert_eq!(
            fixture.show().result["d1_restore_verification"]["qualified"],
            false,
            "{pointer}"
        );
    }
}

#[tokio::test]
async fn d1_restore_proof_requires_verified_closed_lifecycle_and_exact_terminal_reference() {
    for variant in [
        "not-closed",
        "failed",
        "terminal-state",
        "terminal-basis",
        "prefix",
        "chronology",
    ] {
        let mut fixture = Fixture::new().await;
        match variant {
            "not-closed" => {
                fixture.plan.transaction_journal.pop();
                fixture.plan.transaction_stage = TransactionStageV1::VerificationResponsePersisted;
            }
            "failed" => {
                fixture.plan.status = PlanStatus::Failed;
                fixture
                    .plan
                    .transaction_journal
                    .last_mut()
                    .expect("closed checkpoint")
                    .plan_status = PlanStatus::Failed;
            }
            "prefix" => {
                fixture.plan.transaction_journal[1].recorded_at += ChronoDuration::nanoseconds(1);
            }
            "chronology" => {
                fixture
                    .plan
                    .transaction_journal
                    .last_mut()
                    .expect("closed checkpoint")
                    .recorded_at = fixture.plan.created_at - ChronoDuration::seconds(1);
            }
            field => {
                let key = if field == "terminal-state" {
                    "state"
                } else {
                    "basis_hash"
                };
                fixture
                    .plan
                    .transaction_artifacts
                    .get_mut(TransactionStageV1::VerificationResponsePersisted.as_str())
                    .expect("terminal artifact")[key] = json!("different");
            }
        }
        rehash_plan(&mut fixture.plan);
        fixture.save();
        fixture.assert_unqualified(match variant {
            "not-closed" | "failed" => "restore_lifecycle_not_verified_closed",
            "prefix" => "restore_execution_binding_mismatch",
            "chronology" => "invalid_restore_chronology",
            _ => "verification_reference_mismatch",
        });
    }
}

#[tokio::test]
async fn d1_restore_proof_missing_plan_v2_or_projection_drift_never_qualifies() {
    for missing in [false, true] {
        let fixture = Fixture::new().await;
        let plans = fixture.store.paths().data_dir.join("plans");
        if missing {
            fs::remove_file(
                fixture
                    .store
                    .paths()
                    .data_dir
                    .join("plans-v2")
                    .join(format!("{}.json", fixture.plan.operation_id)),
            )
            .expect("remove isolated required PlanV2");
        } else {
            let mut projection = fixture.plan.clone();
            projection.input["body"]["target_bookmark"] = json!("drifted-projection");
            rehash_plan(&mut projection);
            fs::write(
                plans.join(format!("{}.json", fixture.plan.operation_id)),
                serde_json::to_vec_pretty(&projection).expect("encode drifted projection"),
            )
            .expect("write isolated projection drift");
        }
        fixture.assert_unqualified("plan_projection_drift");
    }
}
