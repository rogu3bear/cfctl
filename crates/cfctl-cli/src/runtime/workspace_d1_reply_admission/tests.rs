#![allow(clippy::wildcard_imports, reason = "white-box domain tests")]

use super::super::RuntimePaths;

use super::*;

#[test]
fn reply_admission_separates_d1_read_and_apply_timeouts() {
    assert_eq!(READ_TIMEOUT, Duration::from_mins(2));
    assert_eq!(APPLY_TIMEOUT, Duration::from_mins(5));
}

#[test]
fn candidate_validation_precedes_credential_generation_binding() {
    let mut profile = ProfileMetadata::new(
        "profile-without-generation",
        cfctl_auth::ProfileKind::ApiToken,
        Some("account"),
    );
    profile.credential_generation_id = None;

    let error = control_plane_binding::validate_candidate(
        b"not-json",
        &profile,
        "account",
        "production-database",
    )
    .err()
    .expect("candidate validation must fail before credential generation binding");

    assert_eq!(
        error.to_string(),
        "reply-admission candidate is not valid JSON"
    );
}

fn prefixed(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

#[expect(
    clippy::too_many_lines,
    reason = "the fixture intentionally spells the complete closed Maildesk candidate contract"
)]
fn candidate() -> Value {
    let transaction = prefixed('1');
    let candidate = json!({"dirty":false,"head":"a".repeat(40),"tree":"b".repeat(40)});
    let candidate_sha = bare_hex_sha(&canonical_json_bytes(&candidate));
    let apple_mail_inbox_source = json!({
        "schema_version":2,
        "kind":"maildesk_apple_mail_inbox_receipt",
        "performed":true,
        "body_free":true,
        "route_ref_sha256":prefixed('1'),
        "domain_sha256":prefixed('2'),
        "public_role_identity_sha256":prefixed('3'),
        "policy_sha256":prefixed('8'),
        "provider_accepted_at":"2030-01-01T00:00:00.000Z",
        "observed_at":"2030-01-01T00:00:30.000Z",
        "correlation_sha256":prefixed('6'),
        "match_count":1,
        "opaque_relay_recipient_sha256":prefixed('0'),
        "selection_basis":"provider_acceptance_interval_and_public_role_identity",
        "subject_used":false,
        "body_used":false,
        "private_identity_retained":false,
    });
    let apple_mail_inbox_source_sha = hash_json(&apple_mail_inbox_source);
    let receipt = |byte: char| {
        json!({
            "receipt_kind":"body_free_test_receipt",
            "receipt_sha256":prefixed(byte),
            "observed_at":"2030-01-01T00:00:00.000Z",
            "expires_at":"2030-01-01T00:15:00.000Z",
            "binding":{},
        })
    };
    let mut prerequisites = json!({
        "configured_policy":receipt('a'),
        "edge_activation":receipt('b'),
        "sender_domain":receipt('c'),
        "inbound_acceptance":receipt('d'),
        "apple_mail_inbox":receipt('e'),
        "operator_authorization":receipt('f'),
        "opaque_relay":receipt('0'),
    });
    prerequisites["apple_mail_inbox"]["receipt_sha256"] =
        Value::String(apple_mail_inbox_source_sha.clone());
    let projection = json!({
        "schema_version":1,
        "transaction_sha256":transaction,
        "candidate":candidate,
        "candidate_sha256":candidate_sha,
        "control_plane":{
            "account_sha256":prefixed('2'),
            "activation_operation_id":"controller:activation:one",
            "cfctl_build_sha256":prefixed('3'),
            "credential_generation_sha256":prefixed('4'),
            "profile_sha256":prefixed('5'),
            "production_database_sha256":prefixed('f'),
        },
        "correlation_sha256":prefixed('6'),
        "scope_manifest_sha256":prefixed('7'),
        "inbound_delivery_id":"inbound:one",
        "relay_id":"relay:one",
        "thread_id":"thread:one",
        "route_id":"route:one",
        "policy_sha256":prefixed('8'),
        "desired_state_sha256":prefixed('9'),
        "operator_set_sha256":prefixed('a'),
        "admitted_operator_sha256":prefixed('b'),
        "public_identity":"security@example.com",
        "sender_domain":"example.com",
        "identity_profile_ref":"identity:one",
        "identity_profile_sha256":prefixed('c'),
        "display_name":"Example Security",
        "signature_profile_ref":"signature:one",
        "signature_sha256":prefixed('d'),
        "sender_adapter":"cloudflare_email_service",
        "prerequisites":prerequisites,
        "evidence_bundle_sha256":prefixed('e'),
        "evidence_observed_at":"2030-01-01T00:00:00.000Z",
        "admitted_at":"2030-01-01T00:01:00.000Z",
        "expires_at":"2030-01-01T00:15:00.000Z",
    });
    let record = json!({
        "id":format!("reply-admission:{}", "1".repeat(32)),
        "schema_version":1,
        "transaction_sha256":"1".repeat(64),
        "correlation_sha256":"6".repeat(64),
        "candidate_sha256":candidate_sha,
        "scope_manifest_sha256":"7".repeat(64),
        "inbound_delivery_id":"inbound:one",
        "relay_id":"relay:one",
        "thread_id":"thread:one",
        "route_id":"route:one",
        "policy_sha256":"8".repeat(64),
        "desired_state_sha256":"9".repeat(64),
        "operator_set_sha256":"a".repeat(64),
        "admitted_operator_ref":"b".repeat(64),
        "public_identity":"security@example.com",
        "sender_domain":"example.com",
        "identity_profile_ref":"identity:one",
        "identity_profile_sha256":"c".repeat(64),
        "display_name":"Example Security",
        "signature_profile_ref":"signature:one",
        "signature_sha256":"d".repeat(64),
        "sender_adapter":"cloudflare_email_service",
        "configured_policy_receipt_sha256":"a".repeat(64),
        "edge_activation_receipt_sha256":"b".repeat(64),
        "sender_domain_receipt_sha256":"c".repeat(64),
        "inbound_acceptance_receipt_sha256":"d".repeat(64),
        "apple_mail_inbox_receipt_sha256":apple_mail_inbox_source_sha.trim_start_matches("sha256:"),
        "operator_authorization_receipt_sha256":"f".repeat(64),
        "opaque_relay_receipt_sha256":"0".repeat(64),
        "evidence_bundle_sha256":"e".repeat(64),
        "evidence_observed_at":"2030-01-01T00:00:00.000Z",
        "admitted_at":"2030-01-01T00:01:00.000Z",
        "expires_at":"2030-01-01T00:15:00.000Z",
        "status":"admitted",
    });
    let source_binding = json!({
        "correlation_sha256":prefixed('6'),"scope_manifest_sha256":prefixed('7'),
        "inbound_delivery_id":"inbound:one","relay_id":"relay:one","thread_id":"thread:one",
        "route_id":"route:one","policy_sha256":prefixed('8'),"desired_state_sha256":prefixed('9'),
        "operator_set_sha256":prefixed('a'),"admitted_operator_sha256":prefixed('b'),
        "identity_profile_sha256":prefixed('c'),
    });
    let source_receipt = |plane: &str, result: Value| {
        json!({
            "adapter":format!("workspace_{plane}_v1"),"authority_sha256":prefixed('1'),
            "binding":source_binding,"body_free":true,"body_returned":false,
            "candidate_sha256":candidate_sha,"capability_id":format!("maildesk.{plane}"),
            "control_plane_sha256":prefixed('2'),"expires_at":"2030-01-01T00:15:00.000Z",
            "kind":format!("maildesk_{plane}_receipt"),"match_count":1,
            "observed_at":"2030-01-01T00:00:00.000Z","operation_id":format!("operation:{plane}"),
            "performed":true,"provider_output_retained":false,"result":result,
            "schema_version":1,"success":true,
        })
    };
    let source_prerequisites = json!({
        "configured_policy":source_receipt("configured_policy",json!({"desired_state_sha256":prefixed('9'),"policy_sha256":prefixed('8'),"status":"configured"})),
        "edge_activation":source_receipt("edge_activation",json!({"edge_state_sha256":prefixed('3'),"status":"active"})),
        "sender_domain":source_receipt("sender_domain",json!({"sender_domain_sha256":prefixed('4'),"status":"verified"})),
        "inbound_acceptance":source_receipt("inbound_acceptance",json!({"inbound_delivery_id":"inbound:one","provider_accepted_at":"2030-01-01T00:00:00.000Z","status":"accepted"})),
        "apple_mail_inbox":apple_mail_inbox_source,
        "operator_authorization":source_receipt("operator_authorization",json!({"admitted_operator_sha256":prefixed('b'),"operator_set_sha256":prefixed('a'),"status":"authorized"})),
        "opaque_relay":source_receipt("opaque_relay",json!({"opaque_relay_recipient_sha256":prefixed('0'),"relay_id":"relay:one","status":"authorized"})),
    });
    json!({
        "kind":"maildesk_reply_admission_candidate","schema_version":1,
        "transaction_sha256":transaction,
        "activation_record_sha256":hash_json(&record),
        "pre_send_identity_projection_sha256":hash_json(&projection),
        "pre_send_identity_projection":projection,"source_prerequisites":source_prerequisites,
        "activation":{"capability_id":"star-maildesk-cf.reply-admission-activate","effect":"plan_v2_required","record":record},
        "body_free":true,
    })
}

#[test]
fn compiled_candidate_binds_distinct_logical_activation_and_hashes() {
    let bytes = serde_json::to_vec(&candidate()).expect("candidate bytes");
    let admitted = validate_candidate_bytes(&bytes).expect("valid candidate");
    assert_eq!(
        admitted.logical_activation_id,
        format!("reply-admission:{}", "1".repeat(32))
    );
    assert_eq!(
        admitted.activation_operation_id,
        "controller:activation:one"
    );
    assert_ne!(
        admitted.logical_activation_id,
        "00000000-0000-4000-8000-000000000000"
    );
    assert_eq!(admitted.source_sha256, hex_sha(&bytes));
    let sql = insert_sql("reply_admissions", &admitted.record).expect("compiler SQL");
    assert!(sql.starts_with("INSERT INTO reply_admissions"));
    assert!(!sql.contains("controller:activation:one"));
}

#[test]
fn compiled_candidate_accepts_router_owned_public_address_profile_refs() {
    let mut value = candidate();
    value["pre_send_identity_projection"]["identity_profile_ref"] =
        Value::String("security@example.com".to_owned());
    value["activation"]["record"]["identity_profile_ref"] =
        Value::String("security@example.com".to_owned());
    value["pre_send_identity_projection_sha256"] =
        Value::String(hash_json(&value["pre_send_identity_projection"]));
    value["activation_record_sha256"] = Value::String(hash_json(&value["activation"]["record"]));

    validate_candidate_bytes(&serde_json::to_vec(&value).expect("candidate bytes"))
        .expect("public-address identity profile ref");

    for invalid in ["Security@example.com", "security@@example.com", "security@"] {
        let mut value = candidate();
        value["pre_send_identity_projection"]["identity_profile_ref"] =
            Value::String(invalid.to_owned());
        value["activation"]["record"]["identity_profile_ref"] = Value::String(invalid.to_owned());
        value["pre_send_identity_projection_sha256"] =
            Value::String(hash_json(&value["pre_send_identity_projection"]));
        value["activation_record_sha256"] =
            Value::String(hash_json(&value["activation"]["record"]));

        assert!(
            validate_candidate_bytes(&serde_json::to_vec(&value).expect("candidate bytes"))
                .is_err(),
            "invalid public-address profile ref must fail closed: {invalid}",
        );
    }
}

#[test]
fn candidate_tampering_and_caller_sql_fail_closed() {
    let mut value = candidate();
    value["activation"]["record"]["status"] = Value::String("revoked".to_owned());
    assert!(validate_candidate_bytes(&serde_json::to_vec(&value).expect("bytes")).is_err());
    let mut value = candidate();
    value["sql"] = Value::String("DELETE FROM reply_admissions".to_owned());
    assert!(validate_candidate_bytes(&serde_json::to_vec(&value).expect("bytes")).is_err());

    let mut value = candidate();
    value["pre_send_identity_projection"]["candidate_sha256"] = Value::String(prefixed('f'));
    value["pre_send_identity_projection_sha256"] =
        Value::String(hash_json(&value["pre_send_identity_projection"]));
    assert!(validate_candidate_bytes(&serde_json::to_vec(&value).expect("bytes")).is_err());

    let mut value = candidate();
    value["source_prerequisites"]["configured_policy"]["private_address"] =
        Value::String("operator@example.net".to_owned());
    assert!(validate_candidate_bytes(&serde_json::to_vec(&value).expect("bytes")).is_err());

    for (field, invalid) in [
        ("match_count", json!(0)),
        ("subject_used", json!(true)),
        ("body_used", json!(true)),
        ("private_identity_retained", json!(true)),
    ] {
        let mut value = candidate();
        value["source_prerequisites"]["apple_mail_inbox"][field] = invalid;
        assert!(
            validate_candidate_bytes(&serde_json::to_vec(&value).expect("bytes")).is_err(),
            "invalid Apple Mail source field must fail closed: {field}",
        );
    }

    let mut value = candidate();
    value["source_prerequisites"]["apple_mail_inbox"]["observed_at"] =
        Value::String("2030-01-01T00:01:00.000Z".to_owned());
    assert!(validate_candidate_bytes(&serde_json::to_vec(&value).expect("bytes")).is_err());
}

#[test]
fn read_projection_requires_one_exact_active_record_and_retains_no_provider_row() {
    let bytes = serde_json::to_vec(&candidate()).expect("candidate bytes");
    let admitted = validate_candidate_bytes(&bytes).expect("valid candidate");
    let exact_row = admitted.record.clone();
    let success = project_read_receipt(
        &admitted,
        std::slice::from_ref(&exact_row),
        "2030-01-01T00:02:00.000Z",
        "4.120.1",
    );
    assert!(read_receipt_is_complete(&success));
    assert_eq!(success["status"], "active");
    assert_eq!(success["match_count"], 1);
    assert_eq!(
        success["activation_operation_id"],
        "controller:activation:one"
    );
    assert_eq!(success["production_database_sha256"], prefixed('f'));
    assert_eq!(success["provider_output_retained"], false);
    assert_eq!(success["record_content_retained"], false);
    assert_eq!(success["body_returned"], false);
    let encoded = success.to_string();
    assert!(!encoded.contains("claimed_attempt_id"));
    assert!(!encoded.contains("provider_boundary_at"));
    let mut expanded = success.clone();
    expanded["provider_payload"] = json!({"forbidden":true});
    assert!(!read_receipt_is_complete(&expanded));

    let missing = project_read_receipt(&admitted, &[], "2030-01-01T00:02:00.000Z", "4.120.1");
    assert!(!read_receipt_is_complete(&missing));
    assert_eq!(missing["status"], "missing");
    assert_eq!(missing["match_count"], 0);
    assert_eq!(missing["production_database_sha256"], prefixed('f'));
    assert!(missing.get("pre_send_identity_projection").is_none());

    let multiple = project_read_receipt(
        &admitted,
        &[exact_row.clone(), exact_row],
        "2030-01-01T00:02:00.000Z",
        "4.120.1",
    );
    assert!(!read_receipt_is_complete(&multiple));
    assert_eq!(multiple["status"], "ambiguous");
    assert_eq!(multiple["match_count"], 2);
    assert_eq!(multiple["production_database_sha256"], prefixed('f'));
    assert!(multiple.get("pre_send_identity_projection").is_none());
}

#[test]
fn read_projection_rejects_one_mismatched_or_non_active_record() {
    let bytes = serde_json::to_vec(&candidate()).expect("candidate bytes");
    let admitted = validate_candidate_bytes(&bytes).expect("valid candidate");
    let mut drifted = admitted.record.clone();
    drifted.insert(
        "display_name".to_owned(),
        Value::String("Wrong Identity".to_owned()),
    );
    let mismatch =
        project_read_receipt(&admitted, &[drifted], "2030-01-01T00:02:00.000Z", "4.120.1");
    assert_eq!(mismatch["status"], "invalid");
    assert!(!read_receipt_is_complete(&mismatch));

    let mut claimed = admitted.record.clone();
    claimed.insert("status".to_owned(), Value::String("claimed".to_owned()));
    let terminal =
        project_read_receipt(&admitted, &[claimed], "2030-01-01T00:02:00.000Z", "4.120.1");
    assert_eq!(terminal["status"], "invalid");
    assert!(!read_receipt_is_complete(&terminal));
}

#[cfg(unix)]
#[test]
fn private_candidate_stage_is_body_free_mode_0600_and_digest_bound() {
    let root = tempfile::tempdir().expect("state root");
    // macOS exposes its temporary directory through the `/var` compatibility
    // symlink. Bind the test store to the resolved root so the assertion
    // exercises caller-controlled symlink rejection, not that system alias.
    let resolved_root = root.path().canonicalize().expect("resolved state root");
    let store = StateStore::open(RuntimePaths::from_root(&resolved_root)).expect("state store");
    let bytes = serde_json::to_vec(&candidate()).expect("candidate bytes");
    let stage = stage_private_candidate(&store, &bytes).expect("private stage");
    assert_eq!(stage["content_in_plan"], false);
    assert_eq!(stage["path_in_plan"], false);
    assert!(!stage.to_string().contains("security@example.com"));
    let object = stage.as_object().expect("stage object");
    let path = private_stage_path(&store, object).expect("stage path");
    assert_eq!(
        fs::metadata(path).expect("metadata").permissions().mode() & 0o777,
        0o600
    );
    validate_private_stage_object(&store, object).expect("valid stage");
}

#[test]
fn reply_admission_compiler_support_is_exact_and_relative() {
    assert_eq!(
        compiler_support_relative_path(Path::new("scripts/reply-admission-receipt.ts"))
            .expect("known compiler support path"),
        PathBuf::from("scripts/apple-mail-inbox-receipt.ts"),
    );

    for unsupported in [
        "reply-admission-receipt.ts",
        "scripts/other-compiler.ts",
        "../scripts/reply-admission-receipt.ts",
    ] {
        assert!(
            compiler_support_relative_path(Path::new(unsupported)).is_err(),
            "unsupported compiler path must fail closed: {unsupported}",
        );
    }
}

#[cfg(unix)]
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the test builds a complete committed compiler fixture and verifies private staging cleanup"
)]
fn staged_reply_admission_compiler_executes_with_committed_support_module() {
    let fixture = tempfile::tempdir().expect("fixture root");
    let fixture_root = fixture
        .path()
        .canonicalize()
        .expect("canonical fixture root");
    let repository_root = fixture_root
        .join("maildesk")
        .canonicalize()
        .unwrap_or_else(|_| {
            fs::create_dir(fixture_root.join("maildesk")).expect("repository directory");
            fixture_root
                .join("maildesk")
                .canonicalize()
                .expect("canonical repository")
        });
    fs::create_dir_all(repository_root.join("scripts")).expect("scripts directory");
    let compiler = br#"import { seal } from "./apple-mail-inbox-receipt";
import { readFileSync, writeFileSync } from "node:fs";
const args = process.argv.slice(2);
const input = args[args.indexOf("--input") + 1];
const output = args[args.indexOf("--out") + 1];
writeFileSync(output, JSON.stringify({ sealed: seal(JSON.parse(readFileSync(input, "utf8")).value) }), { mode: 0o600 });
"#;
    let support = br"export function seal(value: string): string { return `committed:${value}`; }
";
    fs::write(
        repository_root.join("scripts/reply-admission-receipt.ts"),
        compiler,
    )
    .expect("compiler fixture");
    fs::write(
        repository_root.join("scripts/apple-mail-inbox-receipt.ts"),
        support,
    )
    .expect("support fixture");
    for args in [
        vec!["init", "-q"],
        vec!["add", "scripts"],
        vec![
            "-c",
            "user.name=cfctl test",
            "-c",
            "user.email=cfctl-test@example.com",
            "commit",
            "-qm",
            "fixture",
        ],
    ] {
        assert!(
            Command::new("git")
                .current_dir(&repository_root)
                .args(args)
                .status()
                .expect("git fixture command")
                .success()
        );
    }
    let head = Command::new("git")
        .current_dir(&repository_root)
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("fixture HEAD");
    let head = String::from_utf8(head.stdout)
        .expect("UTF-8 HEAD")
        .trim()
        .to_owned();

    fs::write(
        repository_root.join("scripts/apple-mail-inbox-receipt.ts"),
        "throw new Error('dirty worktree support must not execute');\n",
    )
    .expect("dirty support fixture");

    let bun = which::which("bun").expect("bun");
    let bun = fs::canonicalize(bun).expect("canonical bun");
    let bun_bytes = fs::read(&bun).expect("bun bytes");
    let bun_version = Command::new(&bun)
        .arg("--version")
        .output()
        .expect("bun version");
    let contract = WorkspaceD1ReplyAdmissionContractV1 {
        operation_kind: "activate".to_owned(),
        repository_root: repository_root.display().to_string(),
        repository_head: head,
        repository_origin: "fixture".to_owned(),
        operation_pack_path: ".cfctl/operations/d1-reply-admission.toml".to_owned(),
        operation_pack_sha256: prefixed('1'),
        compiler_path: "scripts/reply-admission-receipt.ts".to_owned(),
        compiler_sha256: hex_sha(compiler),
        compiler_runtime: "bun".to_owned(),
        compiler_runtime_version: String::from_utf8(bun_version.stdout)
            .expect("UTF-8 bun version")
            .trim()
            .to_owned(),
        compiler_runtime_sha256: hex_sha(&bun_bytes),
        config_template_path: "wrangler.toml".to_owned(),
        config_template_sha256: prefixed('2'),
        production_config_path: "wrangler.production.toml".to_owned(),
        database_binding: "DB".to_owned(),
        wrangler_version: "4.120.1".to_owned(),
        admission_table: "reply_admissions".to_owned(),
        input_contract: "maildesk_reply_admission_compiler_input_v1".to_owned(),
        mutation_projection: "maildesk_reply_admission_insert_v1".to_owned(),
        read_projection: None,
        read_parameters: Vec::new(),
        recovery_capability_id: "d1-time-travel-get-bookmark".to_owned(),
        recovery_max_age_seconds: 600,
        rollback_capability_id: "d1-restore-exact-bookmark".to_owned(),
    };
    let state_root = fixture_root.join("state");
    let store = StateStore::open(RuntimePaths::from_root(&state_root)).expect("state store");
    let source = fixture_root.join("source.json");
    write_private_file(&source, br#"{"value":"candidate"}"#).expect("private source");
    let source = fs::canonicalize(source).expect("canonical private source");
    let runtime = compiler_runtime(&store, &contract).expect("compiler runtime");
    let compiled_output = compile_private_candidate(&store, &contract, &source, &runtime)
        .expect("staged compiler with committed support");
    assert_eq!(
        serde_json::from_slice::<Value>(&compiled_output).expect("compiled JSON"),
        json!({"sealed":"committed:candidate"}),
    );
    assert!(
        fs::read_dir(store.paths().data_dir.join("private-operation-stages"))
            .expect("private stages")
            .next()
            .is_none(),
        "private compiler stages must be removed",
    );

    let mut unsupported_contract = contract.clone();
    unsupported_contract.compiler_path = "scripts/other-compiler.ts".to_owned();
    let error = compile_private_candidate(&store, &unsupported_contract, &source, &runtime)
        .expect_err("unsupported compiler path");
    assert!(error.to_string().contains("no admitted support module"));
    assert!(
        fs::read_dir(store.paths().data_dir.join("private-operation-stages"))
            .expect("private stages after unsupported compiler")
            .next()
            .is_none(),
        "unsupported compiler path must not retain a private candidate stage",
    );
}
