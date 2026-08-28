use super::*;

#[test]
pub(super) fn read_import_secret_requires_exactly_one_out_of_band_source() {
    let neither = read_import_secret(false, None, "API token").expect_err("no source rejected");
    let neither = neither.to_string();
    assert!(neither.contains("--stdin"), "{neither}");
    assert!(neither.contains("--value-in"), "{neither}");

    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("token");
    std::fs::write(&path, "cfat_from_file").expect("write token file");
    let both =
        read_import_secret(true, Some(&path), "API token").expect_err("two sources rejected");
    assert!(both.to_string().contains("not both"), "{both}");
}

#[test]
pub(super) fn force_ipv4_flag_parses_affirmative_values_only() {
    for on in ["1", "true", "yes", "on"] {
        assert!(force_ipv4_from(Some(on)), "{on} should enable IPv4");
    }
    for off in [Some("0"), Some("false"), Some(""), None] {
        assert!(!force_ipv4_from(off), "{off:?} should not enable IPv4");
    }
}

#[test]
pub(super) fn http_client_builds_in_both_egress_modes() {
    // Default builder is valid.
    http_client().expect("default client builds");
    // The IPv4-bound builder is also valid (binds a v4 source address).
    reqwest::Client::builder()
        .local_address(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
        .build()
        .expect("ipv4-bound client builds");
}

#[cfg(unix)]
#[test]
pub(super) fn read_secret_file_reads_mode_0600_and_rejects_group_readable() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("token");
    std::fs::write(&path, "cfat_from_file\n").expect("write token file");

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod 600");
    let value = read_secret_file(&path).expect("read 0600 file");
    assert_eq!(value.trim(), "cfat_from_file");

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).expect("chmod 640");
    let leaky = read_secret_file(&path).expect_err("group-readable rejected");
    let leaky = leaky.to_string();
    assert!(leaky.contains("group or others"), "{leaky}");
    assert!(leaky.contains("chmod 600"), "{leaky}");
}

#[cfg(unix)]
#[test]
pub(super) fn r2_log_retrieval_credentials_require_a_closed_private_json_bundle() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("r2-credentials.json");
    std::fs::write(
        &path,
        r#"{"access_key_id":"r2-access-test","secret_access_key":"r2-secret-test"}"#,
    )
    .expect("write credential bundle");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod 600");
    let credentials = read_r2_log_retrieval_credentials(&path).expect("closed private bundle");
    let debug = format!("{credentials:?}");
    assert!(!debug.contains("r2-access-test"));
    assert!(!debug.contains("r2-secret-test"));
    assert!(debug.contains("[REDACTED]"));

    std::fs::write(
            &path,
            r#"{"access_key_id":"r2-access-test","secret_access_key":"r2-secret-test","header":"arbitrary"}"#,
        )
        .expect("write extra field");
    let extra = read_r2_log_retrieval_credentials(&path)
        .expect_err("unknown credential fields fail closed")
        .to_string();
    assert!(extra.contains("exactly"), "{extra}");
    assert!(!extra.contains("r2-secret-test"));

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).expect("chmod 640");
    let leaky = read_r2_log_retrieval_credentials(&path)
        .expect_err("group-readable bundle rejected")
        .to_string();
    assert!(leaky.contains("--credential-in"), "{leaky}");
    assert!(leaky.contains("chmod 600"), "{leaky}");
}

#[test]
pub(super) fn cancel_plan_retires_an_approved_plan_on_the_store_path() {
    let root = tempfile::tempdir().expect("runtime root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let capability = CapabilityV1::new(
        "dns.records.update",
        "Update DNS record",
        "PUT",
        "/zones/{zone_id}/dns_records/{record_id}",
    );
    let plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
        json!({"zone_id":"zone-a","record_id":"record-a"}),
    )
    .expect("draft plan");
    let operation_id = plan.operation_id.clone();
    save_current_test_plan(&store, &plan);
    approve_plan(
        &store,
        &PlanApproveArgs {
            operation_id: operation_id.clone(),
            yes: true,
            max_cost: None,
        },
    )
    .expect("approve");

    let envelope = cancel_plan(
        &store,
        &PlanSelector {
            operation_id: operation_id.clone(),
        },
    )
    .expect("an approved plan cancels");
    assert!(envelope.ok);
    assert_eq!(envelope.result["status"], "cancelled");
    assert!(
        envelope.result["cancelled_at"].as_str().is_some(),
        "cancellation is timestamped in the envelope"
    );
    assert!(
        !envelope.evidence.is_empty(),
        "cancellation writes the retired plan as evidence"
    );

    // The persisted state is monotonic: the cancelled plan can be
    // neither re-approved nor rerun through the store path.
    let stored = store.load_plan(&operation_id).expect("reload");
    assert_eq!(plan_status_label(stored.status), "cancelled");
    let error = approve_plan(
        &store,
        &PlanApproveArgs {
            operation_id: operation_id.clone(),
            yes: true,
            max_cost: None,
        },
    )
    .expect_err("cancelled plans refuse re-approval");
    assert!(
        error.to_string().contains("cancelled") || error.to_string().contains("expected draft"),
        "{error}"
    );

    // The recovery guidance names the retirement, not a retry.
    let guidance = plan_state_next_step(&operation_id, cfctl_core::PlanStatus::Cancelled, "draft");
    assert!(guidance.contains("cancelled"), "{guidance}");
    assert!(guidance.contains("cfctl call"), "{guidance}");
}

#[test]
pub(super) fn approve_plan_requires_explicit_yes_on_the_store_path() {
    let root = tempfile::tempdir().expect("runtime root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let capability = CapabilityV1::new(
        "dns.records.update",
        "Update DNS record",
        "PUT",
        "/zones/{zone_id}/dns_records/{record_id}",
    );
    let plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
        json!({"zone_id":"zone-a","record_id":"record-a"}),
    )
    .expect("draft plan");
    let operation_id = plan.operation_id.clone();
    save_current_test_plan(&store, &plan);

    let error = approve_plan(
        &store,
        &PlanApproveArgs {
            operation_id: operation_id.clone(),
            yes: false,
            max_cost: None,
        },
    )
    .expect_err("store path must refuse chat/intent without --yes");
    assert!(
        error
            .to_string()
            .contains("approval must be an explicit yes bound to the operation id"),
        "{error}"
    );
    let reloaded = store.load_plan(&operation_id).expect("plan remains draft");
    assert_eq!(reloaded.status, PlanStatus::Draft);
    assert!(reloaded.approval.is_none());
}

#[test]
pub(super) fn approve_plan_rejects_hash_drifted_store_draft_before_authority() {
    let root = tempfile::tempdir().expect("runtime root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let capability = CapabilityV1::new(
        "dns.records.update",
        "Update DNS record",
        "PUT",
        "/zones/{zone_id}/dns_records/{record_id}",
    );
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
        json!({"zone_id":"zone-a","record_id":"record-a"}),
    )
    .expect("draft plan");
    let operation_id = plan.operation_id.clone();
    let bound_hash = plan.content_hash.clone();
    save_current_test_plan(&store, &plan);

    plan.targets = json!({"zone_id":"zone-b","record_id":"record-a"});
    assert_eq!(plan.content_hash, bound_hash);
    store
        .save_plan(&plan)
        .expect("persist drifted targets without rehash");

    let error = approve_plan(
        &store,
        &PlanApproveArgs {
            operation_id: operation_id.clone(),
            yes: true,
            max_cost: None,
        },
    )
    .expect_err("store path must refuse hash-drifted draft");
    assert!(
        error.to_string().contains("unchanged hash-bound draft"),
        "{error}"
    );
    let reloaded = store.load_plan(&operation_id).expect("still draft");
    assert_eq!(reloaded.status, PlanStatus::Draft);
    assert!(reloaded.approval.is_none());

    plan.refresh_hash()
        .expect("operator rebinds reviewed content");
    store.save_plan(&plan).expect("persist rehashed draft");
    let approved = approve_plan(
        &store,
        &PlanApproveArgs {
            operation_id: operation_id.clone(),
            yes: true,
            max_cost: None,
        },
    )
    .expect("rehashed draft may approve with explicit yes");
    assert_eq!(approved.command, "plans approve");
    assert!(approved.ok);
    let reloaded = store.load_plan(&operation_id).expect("approved plan");
    assert_eq!(reloaded.status, PlanStatus::Approved);
    assert_eq!(
        reloaded
            .approval
            .as_ref()
            .map(|approval| approval.approved_content_hash.as_str()),
        Some(reloaded.content_hash.as_str())
    );
}

#[test]
pub(super) fn secret_response_preserves_safe_receipt_metadata() {
    let response = json!({
        "status": 200,
        "success": true,
        "result": {
            "id": "token-id",
            "name": "automation token",
            "status": "active",
            "value": "must-not-survive"
        }
    });

    let redacted = redact_secret_result(&response);

    assert_eq!(redacted["result"]["id"], "token-id");
    assert_eq!(redacted["result"]["status"], "active");
    assert_eq!(redacted["result"]["value"], "[SUNK]");
    assert!(!redacted.to_string().contains("must-not-survive"));
}

#[test]
pub(super) fn verification_evidence_redacts_secret_readback_fields_storage_redaction_misses() {
    let root = tempfile::tempdir().expect("runtime root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let capability = r2_temporary_credentials_capability();
    assert!(should_redact_secret_response(&capability));
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
        json!({"selectors":{"account_id":"account-a"}}),
    )
    .expect("plan");
    // A verifier readback carrying camelCase secret fields the storage-layer
    // `redact_json` does not catch (no `_secret`/`_token` suffix). Only the
    // defensive `redact_secret_result` pass on this evidence class stops them.
    let verification = OperationVerificationV1 {
        strategy: "sink_write_and_source_response_status".to_owned(),
        passed: true,
        basis: "sink-only receipt".to_owned(),
        readback: CloudflareResponseV1 {
            status: 200,
            success: true,
            result: json!({
                "accessKeyId":"AKIAEXAMPLE",
                "secretAccessKey":"must-not-survive",
                "sessionToken":"also-must-not-survive"
            }),
            errors: vec![],
            result_info: None,
            etag: None,
            cf_ray: None,
        },
        correlated_resource_id: None,
    };
    let outcome =
        verification_outcome(&store, &mut plan, verification).expect("verification outcome");
    let evidence = outcome.evidence.expect("post-change evidence recorded");
    let stored = fs::read_to_string(&evidence.path).expect("evidence file");
    assert!(
        !stored.contains("must-not-survive"),
        "secretAccessKey leaked into verification evidence: {stored}"
    );
    assert!(
        !stored.contains("also-must-not-survive"),
        "sessionToken leaked into verification evidence: {stored}"
    );
    assert!(stored.contains("[SUNK]"), "expected redaction marker");
}

#[test]
pub(super) fn boundary_artifact_never_lifts_a_secret_field_into_resource_id() {
    let mut capability = CapabilityV1::new(
        "tokens-create",
        "Create token",
        "POST",
        "/accounts/{account_id}/tokens",
    );
    // A (hypothetically drifted) identity pointer naming a secret field.
    capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: "/accounts/{account_id}/tokens/{value}".to_owned(),
        identity_selector: "value".to_owned(),
        response_result_identity_pointer: "/value".to_owned(),
        read_capability_id: "tokens-get".to_owned(),
        delete_capability_id: "tokens-delete".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
    });
    let plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
        json!({}),
    )
    .expect("plan");
    let response = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"abc","value":"super-secret-token"}),
        errors: vec![],
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let artifact = boundary_response_artifact(&plan, &response, None);
    assert!(
        artifact["resource_id"].is_null(),
        "a secret field must never be lifted into resource_id: {artifact}"
    );
    assert!(!artifact.to_string().contains("super-secret-token"));
}

pub(super) fn r2_temporary_credentials_capability() -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        "r2-create-temp-access-credentials",
        "Create Temporary Access Credentials",
        "POST",
        "/accounts/{account_id}/r2/temp-access-credentials",
    );
    capability.product = "R2 Bucket".to_owned();
    capability.account_scope = "account".to_owned();
    capability.permissions = vec![
        "Workers R2 Storage Write".to_owned(),
        "Workers R2 Storage Read".to_owned(),
        "Workers R2 Storage Bucket Item Write".to_owned(),
        "Workers R2 Storage Bucket Item Read".to_owned(),
        "Workers R2 Data Catalog Write".to_owned(),
        "Workers R2 Data Catalog Read".to_owned(),
    ];
    capability.risk = RiskClass::SecretSensitive;
    capability.effect = EffectClass::IdentityOrOwnership;
    capability.verification.required = false;
    capability.verification.strategy = "sink_write_and_source_response_status".to_owned();
    capability.request_schema = Some(json!({
        "type":"object",
        "required":["bucket","permission","ttlSeconds","parentAccessKeyId"],
        "properties":{
            "bucket":{"type":"string"},
            "objects":{"type":"array","items":{"type":"string"}},
            "parentAccessKeyId":{"type":"string","x-cfctl-derived-from-active-profile":true},
            "permission":{"type":"string","enum":["admin-read-write","admin-read-only","object-read-write","object-read-only"]},
            "prefixes":{"type":"array","items":{"type":"string"}},
            "ttlSeconds":{"type":"number","maximum":604_800}
        },
        "x-cfctl-body-required":true
    }));
    capability
}

#[test]
pub(super) fn r2_parent_identity_is_derived_from_the_active_profile_and_hash_bound() {
    let capability = r2_temporary_credentials_capability();
    let mut input = CallInput {
        selectors: json!({"account_id":"account-a"}),
        body: Some(json!({
            "bucket":"uploads",
            "permission":"object-read-write",
            "ttlSeconds":900,
            "prefixes":["user-7/"]
        })),
        ..CallInput::default()
    };
    prepare_r2_temporary_credentials_input(&capability, &mut input)
        .expect("cfctl parent placeholder");
    assert_eq!(
        input.body.as_ref().expect("body")["parentAccessKeyId"],
        "$cfctl_active_profile_token_id"
    );

    let receipt = apply_r2_parent_token_response(
        &capability,
        "account-a",
        &mut input,
        &CloudflareResponseV1 {
            status: 200,
            success: true,
            result: json!({"id":"0123456789abcdef0123456789abcdef","status":"active"}),
            errors: vec![],
            result_info: None,
            etag: None,
            cf_ray: None,
        },
    )
    .expect("active parent token receipt");
    assert_eq!(
        input.body.as_ref().expect("body")["parentAccessKeyId"],
        "0123456789abcdef0123456789abcdef"
    );
    assert_eq!(receipt["token_status"], "active");
    assert_eq!(receipt["account_id"], "account-a");
    assert_eq!(
        receipt["parent_permission_contract"]["rule"],
        "temporary_scope_must_not_exceed_parent"
    );
    assert_eq!(
        receipt["parent_permission_contract"]["requested_scope"],
        "object-read-write"
    );
    assert_eq!(
        receipt["parent_permission_contract"]["allowed_capabilities"],
        json!(["object_read", "object_write", "object_list"])
    );

    let plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
        json!({"live_preconditions":{"r2_parent_token":receipt.clone()}}),
    )
    .expect("plan");
    let mut plan = plan;
    plan.permission_lane = "api_token".to_owned();
    plan.input = serde_json::to_value(&input).expect("plan input");
    plan.precondition_hashes.insert(
        "r2_parent_token".to_owned(),
        hash_value(&receipt).expect("receipt hash"),
    );
    assert_eq!(
        required_r2_parent_token_precondition(&plan).expect("precondition"),
        plan.precondition_hashes
            .get("r2_parent_token")
            .map(String::as_str)
    );
}

#[test]
pub(super) fn r2_parent_identity_rejects_caller_control_and_inactive_tokens() {
    let capability = r2_temporary_credentials_capability();
    let mut controlled = CallInput {
        body: Some(json!({
            "bucket":"uploads",
            "permission":"object-read-only",
            "ttlSeconds":900,
            "parentAccessKeyId":"attacker-selected-token"
        })),
        ..CallInput::default()
    };
    let error = prepare_r2_temporary_credentials_input(&capability, &mut controlled)
        .expect_err("caller-selected parent must fail")
        .to_string();
    assert!(error.contains("omit `parentAccessKeyId`"), "{error}");

    let mut derived = CallInput {
        body: Some(json!({
            "bucket":"uploads",
            "permission":"object-read-only",
            "ttlSeconds":900
        })),
        ..CallInput::default()
    };
    prepare_r2_temporary_credentials_input(&capability, &mut derived)
        .expect("cfctl parent placeholder");
    let error = apply_r2_parent_token_response(
        &capability,
        "account-a",
        &mut derived,
        &CloudflareResponseV1 {
            status: 200,
            success: true,
            result: json!({"id":"0123456789abcdef0123456789abcdef","status":"disabled"}),
            errors: vec![],
            result_info: None,
            etag: None,
            cf_ray: None,
        },
    )
    .expect_err("inactive token must fail")
    .to_string();
    assert!(error.contains("not active"), "{error}");
}

#[test]
pub(super) fn r2_temporary_credentials_use_a_complete_mode_0600_json_sink() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("r2-temporary-credentials.json");
    let capability = r2_temporary_credentials_capability();
    let plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
        json!({"adapter":{"value_out":path}}),
    )
    .expect("plan");
    let result = json!({
        "accessKeyId":"temporary-access-key",
        "secretAccessKey":"temporary-secret-key-must-not-leak",
        "sessionToken":"temporary-session-token-must-not-leak"
    });

    sink_secret_result(&plan, &result).expect("complete credential sink");
    let payload: Value =
        serde_json::from_str(&fs::read_to_string(&path).expect("credential bundle contents"))
            .expect("credential bundle JSON");
    assert_eq!(payload, result);
    assert_eq!(
        secret_sink_format(&plan.capability),
        Some("r2_temporary_credentials_json")
    );
    assert_eq!(
        capability_call_argv(&plan.capability)
            .iter()
            .find(|argument| argument.contains("0600"))
            .map(String::as_str),
        Some("<new-mode-0600-json-path>")
    );
    let mut risk_metadata_drift = plan.capability.clone();
    risk_metadata_drift.risk = RiskClass::Unknown;
    assert!(is_secret_output_capability(&risk_metadata_drift));
    assert_eq!(
        secret_sink_format(&risk_metadata_drift),
        Some("r2_temporary_credentials_json")
    );
    let redacted = redact_secret_result(&json!({"success":true,"result":result}));
    assert_eq!(redacted["result"]["accessKeyId"], "[SUNK]");
    assert_eq!(redacted["result"]["secretAccessKey"], "[SUNK]");
    assert_eq!(redacted["result"]["sessionToken"], "[SUNK]");
    assert!(!redacted.to_string().contains("must-not-leak"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path)
                .expect("sink metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
pub(super) fn r2_temporary_credentials_reject_incomplete_bundle_before_file_creation() {
    for result in [
        json!({"accessKeyId":"key","secretAccessKey":"secret"}),
        json!({"accessKeyId":"key","sessionToken":"session"}),
        json!({"secretAccessKey":"secret","sessionToken":"session"}),
    ] {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("r2-temporary-credentials.json");
        let plan = PlanV1::draft(
            "profile-a",
            "account-a",
            "catalog-sha",
            r2_temporary_credentials_capability(),
            json!({"adapter":{"value_out":path}}),
        )
        .expect("plan");
        assert!(sink_secret_result(&plan, &result).is_err());
        assert!(!path.exists());
    }
}

pub(super) fn worker_tail_create_capability() -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        "worker-tail-logs-start-tail",
        "Start Tail",
        "POST",
        "/accounts/{account_id}/workers/scripts/{script_name}/tails",
    );
    capability.product = "Worker Tail Logs".to_owned();
    capability.account_scope = "account".to_owned();
    capability.permissions = vec![
        "Workers Tail Read".to_owned(),
        "Workers Scripts Write".to_owned(),
    ];
    capability.risk = RiskClass::SecretSensitive;
    capability.verification.strategy =
        "worker_tail_collection_contains_created_lease_id".to_owned();
    capability
}

#[test]
pub(super) fn worker_tail_lease_uses_complete_json_sink_and_capability_scoped_url_redaction() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("worker-tail-lease.json");
    let capability = worker_tail_create_capability();
    let plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
        json!({"adapter":{"value_out":path}}),
    )
    .expect("plan");
    let result = json!({
        "id":"tail-lease-1",
        "expires_at":"2026-07-21T18:00:00Z",
        "url":"wss://tail.example.invalid/bearer-must-not-leak",
        "extra":"not-sink-authorized"
    });

    sink_secret_result(&plan, &result).expect("complete tail lease sink");
    let payload: Value =
        serde_json::from_str(&fs::read_to_string(&path).expect("tail lease contents"))
            .expect("tail lease JSON");
    assert_eq!(
        payload,
        json!({
            "expires_at":"2026-07-21T18:00:00Z",
            "id":"tail-lease-1",
            "url":"wss://tail.example.invalid/bearer-must-not-leak"
        })
    );
    assert!(!payload.to_string().contains("not-sink-authorized"));
    assert_eq!(
        secret_sink_format(&plan.capability),
        Some("worker_tail_lease_json")
    );
    assert_eq!(
        capability_call_argv(&plan.capability)
            .iter()
            .find(|argument| argument.contains("0600"))
            .map(String::as_str),
        Some("<new-mode-0600-json-path>")
    );

    let redacted_create =
        redact_response_for_capability(&plan.capability, &json!({"success":true,"result":result}));
    assert_eq!(redacted_create["result"]["id"], "tail-lease-1");
    assert_eq!(redacted_create["result"]["url"], "[SUNK]");
    assert!(!redacted_create.to_string().contains("bearer-must-not-leak"));

    let mut list = CapabilityV1::new(
        "worker-tail-logs-list-tails",
        "List Tails",
        "GET",
        "/accounts/{account_id}/workers/scripts/{script_name}/tails",
    );
    list.product = "Worker Tail Logs".to_owned();
    list.account_scope = "account".to_owned();
    list.permissions = vec!["Workers Tail Read".to_owned()];
    let redacted_list = redact_response_for_capability(
        &list,
        &json!({"result":[{"id":"tail-lease-1","url":"wss://private"}]}),
    );
    assert_eq!(redacted_list["result"][0]["url"], "[SUNK]");

    let ordinary = CapabilityV1::new("zones-get", "Get zone", "GET", "/zones/{zone_id}");
    let ordinary_response = json!({"result":{"url":"https://example.com"}});
    assert_eq!(
        redact_response_for_capability(&ordinary, &ordinary_response),
        ordinary_response,
        "URL redaction must remain scoped to the exact tail operations"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path)
                .expect("tail sink metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
pub(super) fn worker_tail_lease_rejects_incomplete_sink_payloads_before_file_creation() {
    for result in [
        json!({"id":"tail","expires_at":"2026-07-21T18:00:00Z"}),
        json!({"id":"tail","url":"wss://private"}),
        json!({"expires_at":"2026-07-21T18:00:00Z","url":"wss://private"}),
    ] {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("worker-tail-lease.json");
        let plan = PlanV1::draft(
            "profile-a",
            "account-a",
            "catalog-sha",
            worker_tail_create_capability(),
            json!({"adapter":{"value_out":path}}),
        )
        .expect("plan");
        assert!(sink_secret_result(&plan, &result).is_err());
        assert!(!path.exists());
    }
}

#[test]
pub(super) fn sink_only_verification_basis_names_the_durable_secret_receipt() {
    let mut capability = CapabilityV1::new(
        "accounts-turnstile-widget-rotate-secret",
        "Rotate Turnstile secret",
        "POST",
        "/accounts/{account_id}/challenges/widgets/{sitekey}/rotate_secret",
    );
    capability.risk = RiskClass::SecretSensitive;
    capability.verification.required = false;
    capability.verification.strategy = "sink_write_and_source_response_status".to_owned();

    assert_eq!(
        non_readback_verification_basis(&capability),
        "Cloudflare returned success and the required sink-only secret output was durably persisted"
    );
    let guide = guide_json(&capability);
    let verify_stage = guide["stages"]
        .as_array()
        .expect("guide stages")
        .iter()
        .find(|stage| stage["name"] == "verify")
        .expect("verify stage");
    assert_eq!(verify_stage["required"], false);
    assert_eq!(verify_stage["contract_state"], "not_applicable");
    assert!(
        verify_stage["summary"]
            .as_str()
            .is_some_and(|summary| summary.contains("durable sink-only secret receipt"))
    );
}

#[test]
pub(super) fn resource_metadata_is_not_mistaken_for_a_secret_value() {
    assert_eq!(
        find_secret_value(&json!({"id":"token-id","status":"active"})),
        None
    );
    assert_eq!(
        find_secret_value(&json!({
            "id": "token-id",
            "nested": {"value": "one-time-secret"}
        })),
        Some("one-time-secret")
    );
}

#[test]
pub(super) fn oauth_client_secret_is_extracted_and_redacted_as_sink_only_material() {
    let response = json!({
        "success": true,
        "result": {
            "client_secret": "oauth-client-secret-must-not-survive",
            "client_id": "public-client-id"
        }
    });

    assert_eq!(
        find_secret_value(&response["result"]),
        Some("oauth-client-secret-must-not-survive")
    );
    let redacted = redact_secret_result(&response);
    assert_eq!(redacted["result"]["client_secret"], "[SUNK]");
    assert_eq!(redacted["result"]["client_id"], "public-client-id");
    assert!(!redacted.to_string().contains("must-not-survive"));
}

#[test]
pub(super) fn access_service_token_credentials_are_sunk_as_a_complete_json_bundle() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("access-service-token.json");
    let mut capability = CapabilityV1::new(
        "access-service-tokens-create-a-service-token",
        "Create a service token",
        "POST",
        "/accounts/{account_id}/access/service_tokens",
    );
    capability.product = "Access service tokens".to_owned();
    capability.permissions = vec!["Access: Service Tokens Write".to_owned()];
    capability.risk = RiskClass::SecretSensitive;
    capability.verification.strategy =
        "created_resource_contains_planned_fields_by_returned_id".to_owned();
    let plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
        json!({"adapter":{"value_out":path}}),
    )
    .expect("plan");

    let written = sink_secret_result(
        &plan,
        &json!({
            "id":"service-token-id",
            "client_id":"service-token-client-id.access",
            "client_secret":"service-token-secret-must-not-leak",
            "name":"deployment automation"
        }),
    )
    .expect("credential bundle");
    assert_eq!(written, path);
    let payload: Value =
        serde_json::from_str(&fs::read_to_string(&path).expect("credential bundle contents"))
            .expect("credential bundle JSON");
    assert_eq!(
        payload,
        json!({
            "client_id":"service-token-client-id.access",
            "client_secret":"service-token-secret-must-not-leak"
        })
    );
    assert!(!payload.to_string().contains("service-token-id"));
    assert!(!payload.to_string().contains("deployment automation"));
    assert_eq!(
        capability_call_argv(&plan.capability)
            .iter()
            .find(|argument| argument.contains("0600"))
            .map(String::as_str),
        Some("<new-mode-0600-json-path>")
    );
    let mut risk_metadata_drift = plan.capability.clone();
    risk_metadata_drift.risk = RiskClass::Unknown;
    assert!(is_secret_output_capability(&risk_metadata_drift));
    assert_eq!(
        secret_sink_format(&risk_metadata_drift),
        Some("access_service_token_json")
    );
    assert_eq!(
        capability_call_argv(&risk_metadata_drift)
            .iter()
            .find(|argument| argument.contains("0600"))
            .map(String::as_str),
        Some("<new-mode-0600-json-path>")
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path)
                .expect("credential bundle metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
pub(super) fn zone_access_service_token_credentials_use_the_complete_json_sink_despite_risk_drift()
{
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("zone-access-service-token.json");
    let mut capability = CapabilityV1::new(
        "zone-level-access-service-tokens-create-a-service-token",
        "Create a service token",
        "POST",
        "/zones/{zone_id}/access/service_tokens",
    );
    capability.product = "Zone-Level Access service tokens".to_owned();
    capability.permissions = vec!["Access: Service Tokens Write".to_owned()];
    capability.risk = RiskClass::Unknown;
    capability.verification.strategy =
        "created_resource_contains_planned_fields_by_returned_id".to_owned();
    let plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
        json!({"adapter":{"value_out":path}}),
    )
    .expect("plan");

    let written = sink_secret_result(
        &plan,
        &json!({
            "id":"zone-service-token-id",
            "client_id":"zone-service-token-client-id.access",
            "client_secret":"zone-service-token-secret-must-not-leak",
            "name":"zone deployment automation"
        }),
    )
    .expect("zone credential bundle");
    assert_eq!(written, path);
    let payload: Value =
        serde_json::from_str(&fs::read_to_string(&path).expect("credential bundle contents"))
            .expect("credential bundle JSON");
    assert_eq!(
        payload,
        json!({
            "client_id":"zone-service-token-client-id.access",
            "client_secret":"zone-service-token-secret-must-not-leak"
        })
    );
    assert_eq!(
        secret_sink_format(&plan.capability),
        Some("access_service_token_json")
    );
    assert_eq!(
        capability_call_argv(&plan.capability)
            .iter()
            .find(|argument| argument.contains("0600"))
            .map(String::as_str),
        Some("<new-mode-0600-json-path>")
    );
}

#[test]
pub(super) fn access_service_token_sink_rejects_incomplete_credentials_before_file_creation() {
    for result in [
        json!({"client_id":"service-token-client-id.access"}),
        json!({"client_secret":"service-token-secret"}),
        json!({"client_id":"","client_secret":"service-token-secret"}),
    ] {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("access-service-token.json");
        let mut capability = CapabilityV1::new(
            "access-service-tokens-create-a-service-token",
            "Create a service token",
            "POST",
            "/accounts/{account_id}/access/service_tokens",
        );
        capability.product = "Access service tokens".to_owned();
        capability.permissions = vec!["Access: Service Tokens Write".to_owned()];
        capability.risk = RiskClass::SecretSensitive;
        capability.verification.strategy =
            "created_resource_contains_planned_fields_by_returned_id".to_owned();
        let plan = PlanV1::draft(
            "profile-a",
            "account-a",
            "catalog-sha",
            capability,
            json!({"adapter":{"value_out":path}}),
        )
        .expect("plan");

        assert!(sink_secret_result(&plan, &result).is_err());
        assert!(!path.exists());
    }
}

#[test]
pub(super) fn metadata_only_secret_response_is_rejected_without_creating_a_sink() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("credential.txt");
    let capability = CapabilityV1::new(
        "account-api-tokens-create-token",
        "Create account token",
        "POST",
        "/accounts/{account_id}/tokens",
    );
    let plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        capability,
        json!({"adapter":{"value_out":path}}),
    )
    .expect("plan");

    assert!(sink_secret_result(&plan, &json!({"id":"token-id","status":"active"})).is_err());
    assert!(!path.exists());
}
#[test]
pub(super) fn planning_only_plan_cannot_enter_approval_or_execution_contract() {
    let root = tempfile::tempdir().expect("state root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let mut capability = CapabilityV1::new(
        WORKER_DEPLOYMENT_PLAN_CAPABILITY_ID,
        "Compile Worker deployment",
        "POST",
        "/cfctl/plans/accounts/{account_id}/workers/deployment",
    );
    capability.execution_supported = false;
    let plan = PlanV1::draft(
        "profile-a",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "sha256:catalog",
        capability,
        json!({"adapter":{"worker_deployment":{"service_name":"relay-router"}}}),
    )
    .expect("planning-only draft");
    let error = ensure_plan_execution_contract(&store, &plan)
        .expect_err("planning-only plan must fail closed")
        .to_string();
    assert!(error.contains("has no execution authority"));
}

#[tokio::test]
pub(super) async fn planning_only_plan_cannot_enter_rectification() {
    let root = tempfile::tempdir().expect("state root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let mut capability = CapabilityV1::new(
        WORKER_DEPLOYMENT_PLAN_CAPABILITY_ID,
        "Compile Worker deployment",
        "POST",
        "/cfctl/plans/accounts/{account_id}/workers/deployment",
    );
    capability.execution_supported = false;
    let plan = PlanV1::draft(
        "profile-a",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "sha256:catalog",
        capability,
        json!({"adapter":{"worker_deployment":{"service_name":"relay-router"}}}),
    )
    .expect("planning-only draft");
    save_current_test_plan(&store, &plan);
    let error = Box::pin(rectify_plan(
        &store,
        &PlanSelector {
            operation_id: plan.operation_id,
        },
    ))
    .await
    .expect_err("planning-only rectification must fail closed")
    .to_string();
    assert!(error.contains("has no execution authority"));
}
