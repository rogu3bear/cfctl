#![allow(clippy::wildcard_imports, reason = "white-box domain tests")]

use cfctl_cloudflare::CloudflareApiErrorV1;
use cfctl_core::ResponseBodyModeV1;
use serde_json::json;

use super::provider_contract::activation_apply_schema_supported;
use super::*;

fn response(result: Value, count: usize) -> CloudflareResponseV1 {
    CloudflareResponseV1 {
        status: 200,
        success: true,
        result,
        errors: Vec::new(),
        result_info: Some(json!({
            "page":1,
            "total_pages":1,
            "total_count":count,
            "count":count,
            "cfctl_pages":1,
            "cfctl_page_complete":true,
        })),
        etag: None,
        cf_ray: None,
    }
}

fn target() -> Target {
    Target {
        account_id: "private-account".to_owned(),
        reply_domain: "reply.example.com".to_owned(),
        worker_script_name: "maildesk-relay-router".to_owned(),
    }
}

#[test]
fn exact_subdomain_dns_and_parent_zone_catch_all_form_one_body_free_ingress_proof() {
    let target = target();
    let zone = response(
        json!([{"id":"private-zone","name":"example.com","status":"active","account":{"id":"private-account"}}]),
        1,
    );
    assert_eq!(
        project_zone(&zone, &target.account_id, "example.com").expect("zone"),
        ZoneState::Active(ParentZone {
            id: "private-zone".to_owned(),
            name: "example.com".to_owned(),
        })
    );
    let dns = CloudflareResponseV1 {
        result: json!({
            "errors":[],
            "record":CANONICAL_MX.map(|content| json!({
                "type":"MX","name":"reply.example.com","content":content,
            })),
        }),
        result_info: None,
        ..response(Value::Null, 0)
    };
    assert_eq!(
        project_subdomain_dns(&dns, &target.reply_domain).expect("dns"),
        "ok"
    );
    let catch_all = CloudflareResponseV1 {
        result: json!({
            "id":"0123456789abcdef0123456789abcdef",
            "enabled":true,
            "source":"api",
            "name":"",
            "matchers":[{"type":"all"}],
            "actions":[{"type":"worker","value":[target.worker_script_name.clone()]}],
        }),
        result_info: None,
        ..response(Value::Null, 0)
    };
    assert!(
        project_catch_all(&catch_all, &target)
            .expect("parent-zone catch-all")
            .desired_shape
    );
    let receipt = success(&target, "ok", "ok");
    assert!(receipt_is_complete(&receipt));
    let serialized = serde_json::to_string(&receipt).expect("receipt");
    assert!(!serialized.contains("reply.example.com"));
    assert!(!serialized.contains("maildesk-relay-router"));
    assert!(!serialized.contains("private-zone"));
    assert!(!serialized.contains("private-account"));
}

#[test]
fn documented_dns_response_variants_project_with_coherent_optional_metadata() {
    let target = target();
    let records = CANONICAL_MX.map(|content| {
        json!({
            "type":"MX",
            "name":"reply.example.com",
            "content":content,
        })
    });
    let collection = CloudflareResponseV1 {
        result: json!(records),
        result_info: Some(json!({
            "page":1,
            "per_page":20,
            "total_pages":1,
            "total_count":3,
            "count":3,
        })),
        ..response(Value::Null, 0)
    };
    assert_eq!(
        project_subdomain_dns(&collection, &target.reply_domain).expect("collection"),
        "ok"
    );

    let object_without_optional_errors = CloudflareResponseV1 {
        result: json!({"record":records}),
        result_info: None,
        ..response(Value::Null, 0)
    };
    assert_eq!(
        project_subdomain_dns(&object_without_optional_errors, &target.reply_domain)
            .expect("object response"),
        "ok"
    );

    let live_object_variant = CloudflareResponseV1 {
        result: json!({"errors":null,"records":records}),
        result_info: None,
        ..response(Value::Null, 0)
    };
    assert_eq!(
        project_subdomain_dns(&live_object_variant, &target.reply_domain)
            .expect("live object response"),
        "ok"
    );
}

#[test]
fn dns_object_variants_reject_ambiguous_or_malformed_collection_keys() {
    let target = target();
    let records = CANONICAL_MX.map(|content| {
        json!({
            "type":"MX",
            "name":"reply.example.com",
            "content":content,
        })
    });
    for result in [
        json!({"errors":{},"records":records}),
        json!({"errors":null,"records":{}}),
        json!({"errors":null,"record":records,"records":records}),
        json!({"errors":null}),
    ] {
        let response = CloudflareResponseV1 {
            result,
            result_info: None,
            ..response(Value::Null, 0)
        };
        let failure =
            project_subdomain_dns(&response, &target.reply_domain).expect_err("malformed");
        assert_eq!(failure["status"], "dns_projection_malformed");
        assert_eq!(failure["provider_output_retained"], false);
    }
}

#[test]
fn collection_dns_metadata_conflicts_and_unknown_cursors_fail_closed() {
    let target = target();
    let records = CANONICAL_MX.map(|content| {
        json!({
            "type":"MX",
            "name":"reply.example.com",
            "content":content,
        })
    });
    for result_info in [
        json!({}),
        json!({
            "page":1,
            "count":3,
        }),
        json!({
            "page":1,
            "per_page":20,
            "total_pages":2,
            "total_count":3,
            "count":3,
        }),
        json!({
            "page":1,
            "per_page":20,
            "total_pages":1,
            "total_count":4,
            "count":3,
        }),
        json!({
            "page":1,
            "per_page":20,
            "total_pages":1,
            "total_count":3,
            "count":3,
            "cursor":"private-provider-cursor",
        }),
        json!({
            "page":1,
            "per_page":20,
            "total_pages":1,
            "total_count":3,
            "count":3,
            "cfctl_pages":1,
        }),
    ] {
        let response = CloudflareResponseV1 {
            result: json!(records),
            result_info: Some(result_info),
            ..response(Value::Null, 0)
        };
        let failure =
            project_subdomain_dns(&response, &target.reply_domain).expect_err("incomplete");
        assert_eq!(failure["status"], "dns_read_incomplete");
        let serialized = serde_json::to_string(&failure).expect("body-free failure");
        assert!(!serialized.contains("provider-cursor"));
        assert_eq!(failure["provider_output_retained"], false);
    }
}

#[test]
fn typed_missing_and_drift_remain_distinct_from_ambiguous_or_incomplete_reads() {
    let target = target();
    assert_eq!(
        project_zone(&response(json!([]), 0), &target.account_id, "example.com").expect("missing"),
        ZoneState::Missing
    );
    let ambiguous = project_zone(
        &response(
            json!([
                {"id":"one","name":"example.com","status":"active","account":{"id":"private-account"}},
                {"id":"two","name":"example.com","status":"active","account":{"id":"private-account"}},
            ]),
            2,
        ),
        &target.account_id,
        "example.com",
    )
    .expect_err("ambiguous");
    assert_eq!(ambiguous["status"], "zone_cardinality_ambiguous");
    assert_eq!(ambiguous["match_count"], 2);
    assert!(!receipt_is_complete(&ambiguous));

    let mut incomplete = response(json!({"errors":[],"record":[]}), 0);
    incomplete.success = false;
    let failure = project_subdomain_dns(&incomplete, &target.reply_domain).expect_err("incomplete");
    assert_eq!(failure["status"], "dns_read_incomplete");
    assert_eq!(failure["provider_output_retained"], false);
}

#[test]
fn noncanonical_subdomain_mx_is_drift_without_provider_retention() {
    let target = target();
    let dns = CloudflareResponseV1 {
        result: json!({"errors":[],"record":[
            {"type":"MX","name":"reply.example.com","content":"route1.mx.cloudflare.net"},
            {"type":"MX","name":"reply.example.com","content":"wrong.mx.example.net"}
        ]}),
        result_info: None,
        ..response(Value::Null, 0)
    };
    assert_eq!(
        project_subdomain_dns(&dns, &target.reply_domain).expect("dns"),
        "drift"
    );
    let receipt = success(&target, "drift", "ok");
    assert!(receipt_is_complete(&receipt));
    assert!(
        !serde_json::to_string(&receipt)
            .expect("receipt")
            .contains("wrong")
    );
}

#[test]
fn provider_errors_and_malformed_rows_fail_closed_body_free() {
    let target = target();
    let mut denied = response(json!([{"private":"provider-payload"}]), 1);
    denied.success = false;
    denied.errors = vec![CloudflareApiErrorV1 {
        code: Some(9109),
        message: "private provider marker".to_owned(),
    }];
    let failure = project_zone(&denied, &target.account_id, "example.com").expect_err("denied");
    let serialized = serde_json::to_string(&failure).expect("failure");
    assert!(!serialized.contains("provider-payload"));
    assert!(!serialized.contains("provider marker"));
    assert_eq!(failure["provider_output_retained"], false);
    assert_eq!(failure["body_returned"], false);

    let mut expanded = json!({
        "adapter":cfctl_workspace::MAILDESK_REPLY_SUBDOMAIN_INGRESS_PROJECTION,
        "success":true,
        "boundary_crossed":true,
        "schema_version":1,
        "reply_domain_sha256":sha256(target.reply_domain.as_bytes()),
        "worker_target_sha256":sha256(target.worker_script_name.as_bytes()),
        "dns_scope":"exact_reply_subdomain",
        "routing_scope":"parent_zone_catch_all_to_worker_covering_exact_reply_subdomain",
        "dns":"ok",
        "routing_rule":"ok",
        "provider_output_retained":false,
        "body_returned":false,
    });
    assert!(receipt_is_complete(&expanded));
    expanded["routing_scope"] = json!("exact_reply_subdomain_catch_all_to_worker");
    assert!(!receipt_is_complete(&expanded));
    expanded["routing_scope"] =
        json!("parent_zone_catch_all_to_worker_covering_exact_reply_subdomain");
    expanded["provider_payload"] = json!({"raw":true});
    assert!(!receipt_is_complete(&expanded));
}

#[test]
fn incomplete_dns_metadata_and_duplicate_mx_fail_closed() {
    let target = target();
    let records = CANONICAL_MX
        .map(|content| json!({"type":"MX","name":"reply.example.com","content":content}));
    let mut incomplete = CloudflareResponseV1 {
        result: json!({"errors":[],"record":records}),
        result_info: Some(json!({
            "page":1,
            "total_pages":2,
            "total_count":3,
            "count":3,
            "cfctl_pages":1,
            "cfctl_page_complete":false,
        })),
        ..response(Value::Null, 0)
    };
    let failure = project_subdomain_dns(&incomplete, &target.reply_domain).expect_err("incomplete");
    assert_eq!(failure["status"], "dns_read_incomplete");
    assert_eq!(failure["provider_output_retained"], false);

    incomplete.result_info = Some(json!({
        "page":2,
        "total_pages":2,
        "total_count":3,
        "count":3,
        "cfctl_pages":2,
        "cfctl_page_complete":true,
    }));
    let later_page =
        project_subdomain_dns(&incomplete, &target.reply_domain).expect_err("later page");
    assert_eq!(later_page["status"], "dns_read_incomplete");
    assert_eq!(later_page["provider_output_retained"], false);

    incomplete.result_info = None;
    incomplete.result = json!({"errors":[],"record":[
        {"type":"MX","name":"reply.example.com","content":"route1.mx.cloudflare.net"},
        {"type":"MX","name":"reply.example.com","content":"route1.mx.cloudflare.net"},
        {"type":"MX","name":"reply.example.com","content":"route2.mx.cloudflare.net"},
        {"type":"MX","name":"reply.example.com","content":"route3.mx.cloudflare.net"}
    ]});
    assert_eq!(
        project_subdomain_dns(&incomplete, &target.reply_domain).expect("duplicate drift"),
        "drift"
    );
}

#[test]
fn subdomain_dns_permission_drift_is_rejected_by_preflight_contract() {
    let mut zone = provider_capability(
        ZONE_LIST_ID,
        ZONE_LIST_PATH,
        &["Zone Zone Read"],
        &[
            ("name", "query"),
            ("account.id", "query"),
            ("page", "query"),
            ("per_page", "query"),
        ],
    );
    let mut dns = provider_capability(
        SUBDOMAIN_DNS_ID,
        SUBDOMAIN_DNS_PATH,
        &["Zone Settings Read"],
        &[("zone_id", "path"), ("subdomain", "query")],
    );
    let mut catch_all = provider_capability(
        CATCH_ALL_GET_ID,
        CATCH_ALL_GET_PATH,
        &["Email Routing Rules Read"],
        &[("zone_id", "path")],
    );
    assert!(validate_provider_contracts(&zone, &dns, &catch_all).is_ok());
    dns.permissions.clear();
    assert!(validate_provider_contracts(&zone, &dns, &catch_all).is_err());
    zone.permissions.clear();
    dns.permissions.push("Zone Settings Read".to_owned());
    assert!(validate_provider_contracts(&zone, &dns, &catch_all).is_err());
    zone.permissions.push("Zone Zone Read".to_owned());
    catch_all.permissions.clear();
    assert!(validate_provider_contracts(&zone, &dns, &catch_all).is_err());
}

#[test]
fn parent_candidates_exclude_reply_domain() {
    assert_eq!(
        parent_zone_candidates("reply.mail.example.com"),
        ["mail.example.com", "example.com"]
    );
}

#[test]
fn profile_binding_admits_only_exact_account_or_explicit_emergency_global_key() {
    let generation = "11111111-1111-4111-8111-111111111111";
    let mut account_token =
        ProfileMetadata::new("account-token", ProfileKind::ApiToken, Some("account-a"));
    account_token.credential_generation_id = Some(generation.to_owned());
    assert!(profile_is_bound_for_read(
        &account_token,
        "account-a",
        None,
        generation
    ));
    assert!(!profile_is_bound_for_read(
        &account_token,
        "account-b",
        Some("account-b"),
        generation
    ));

    let mut emergency = ProfileMetadata::new("emergency-read", ProfileKind::GlobalKey, None);
    emergency.credential_generation_id = Some(generation.to_owned());
    assert!(profile_is_bound_for_read(
        &emergency,
        "explicit-account",
        Some("explicit-account"),
        generation
    ));
    assert!(!profile_is_bound_for_read(
        &emergency,
        "explicit-account",
        None,
        generation
    ));
    assert!(!profile_is_bound_for_read(
        &emergency,
        "explicit-account",
        Some("another-account"),
        generation
    ));
    emergency.emergency_only = false;
    assert!(!profile_is_bound_for_read(
        &emergency,
        "explicit-account",
        Some("explicit-account"),
        generation
    ));

    emergency.account_id = Some("explicit-account".to_owned());
    assert!(!profile_is_bound_for_read(
        &emergency,
        "explicit-account",
        Some("explicit-account"),
        generation
    ));
    emergency.emergency_only = true;
    assert!(!profile_is_bound_for_read(
        &emergency,
        "explicit-account",
        Some("explicit-account"),
        generation
    ));

    let mut unbound_token = ProfileMetadata::new("unbound-token", ProfileKind::ApiToken, None);
    unbound_token.credential_generation_id = Some(generation.to_owned());
    assert!(!profile_is_bound_for_read(
        &unbound_token,
        "explicit-account",
        Some("explicit-account"),
        generation
    ));
    assert!(!profile_is_bound_for_read(
        &account_token,
        "account-a",
        Some("account-a"),
        "22222222-2222-4222-8222-222222222222"
    ));
}

#[test]
fn activation_worker_inventory_requires_one_exact_complete_script_tag() {
    let target = target();
    let workers = response(
        json!([{
            "name":target.worker_script_name,
            "id":"0123456789abcdef0123456789abcdef"
        }]),
        1,
    );
    assert_eq!(
        project_worker_tag(&workers, &target).expect("exact worker"),
        "0123456789abcdef0123456789abcdef"
    );

    let ambiguous = response(
        json!([
            {"name":target.worker_script_name,"id":"0123456789abcdef0123456789abcdef"},
            {"name":target.worker_script_name,"id":"fedcba9876543210fedcba9876543210"}
        ]),
        2,
    );
    let failure = project_worker_tag(&ambiguous, &target).expect_err("ambiguous");
    assert_eq!(failure["status"], "worker_cardinality_ambiguous");
    assert_eq!(failure["match_count"], 2);
    let serialized = serde_json::to_string(&failure).expect("body-free");
    assert!(!serialized.contains("0123456789abcdef"));
    assert!(!serialized.contains(&target.worker_script_name));
}

#[test]
fn catch_all_projection_binds_state_and_proves_shape_without_retaining_provider_rule() {
    let target = target();
    let current = CloudflareResponseV1 {
        result: json!({
            "id":"0123456789abcdef0123456789abcdef",
            "enabled":false,
            "source":"api",
            "name":"",
            "matchers":[{"type":"all"}],
            "actions":[{"type":"drop"}],
        }),
        result_info: None,
        ..response(Value::Null, 0)
    };
    let projected = project_catch_all(&current, &target).expect("canonical default");
    assert!(is_sha256(&projected.state_sha256));
    assert!(!projected.desired_shape);
    assert!(!projected.source_wrangler);

    let desired = CloudflareResponseV1 {
        result: json!({
            "id":"0123456789abcdef0123456789abcdef",
            "enabled":true,
            "source":"wrangler",
            "name":"",
            "matchers":[{"type":"all"}],
            "actions":[{"type":"worker","value":[target.worker_script_name]}],
        }),
        result_info: None,
        ..response(Value::Null, 0)
    };
    let projected = project_catch_all(&desired, &target).expect("desired catch-all");
    assert!(projected.desired_shape);
    assert!(projected.source_wrangler);
    let serialized = json!({
        "state_sha256":projected.state_sha256,
        "desired_shape":projected.desired_shape,
        "source_wrangler":projected.source_wrangler,
    })
    .to_string();
    assert!(!serialized.contains("0123456789abcdef"));
    assert!(!serialized.contains(&target.worker_script_name));

    let mut ambiguous = desired;
    ambiguous.result["actions"] = json!([
        {"type":"worker","value":[target.worker_script_name.clone()]},
        {"type":"drop"}
    ]);
    let failure = project_catch_all(&ambiguous, &target).expect_err("ambiguous actions");
    assert_eq!(failure["status"], "catch_all_projection_malformed");
}

#[test]
fn catalog_native_catch_all_update_uses_the_same_provider_zone_lock() {
    let root = tempfile::tempdir().expect("temporary state root");
    let store =
        StateStore::open(cfctl_storage::RuntimePaths::from_root(root.path())).expect("state store");
    let account = "a".repeat(32);
    let zone = "b".repeat(32);
    let mut capability = CapabilityV1::new(
        CATCH_ALL_UPDATE_ID,
        "Update catch-all",
        "PUT",
        CATCH_ALL_UPDATE_PATH,
    );
    capability.mutating = true;
    let plan = PlanV1::draft("profile", &account, "catalog", capability, json!({}))
        .expect("draft direct catch-all plan");
    let input = CallInput {
        selectors: json!({"zone_id":zone}),
        ..CallInput::default()
    };
    let lock = acquire_activation_target_lock(&store, &plan, &input)
        .expect("lock resolution")
        .expect("direct catch-all lock");
    assert!(matches!(
        store.lock_email_routing_catch_all(&account, &"b".repeat(32)),
        Err(cfctl_storage::StorageError::EmailRoutingCatchAllLocked { .. })
    ));
    drop(lock);
    assert!(
        store
            .lock_email_routing_catch_all(&account, &"b".repeat(32))
            .is_ok()
    );
}

#[test]
fn activation_account_plan_accepts_only_one_exact_non_destructive_catch_all() {
    let target = target();
    let parent_zone = ParentZone {
        id: "0123456789abcdef0123456789abcdef".to_owned(),
        name: "example.com".to_owned(),
    };
    let exact = CloudflareResponseV1 {
        result: json!({"zones":[{
            "zone_id":parent_zone.id,
            "zone_name":parent_zone.name,
            "changes":[{
                "type":"added",
                "target":format!("*@{}",target.reply_domain)
            }]
        }]}),
        result_info: None,
        ..response(Value::Null, 0)
    };
    let projected = project_activation_account_plan(&exact, &target, &parent_zone)
        .expect("exact parent-zone plan");
    assert_eq!(projected.change_type, "added");
    assert_eq!(projected.zone_id, "0123456789abcdef0123456789abcdef");
    let updated_without_optional_zone_name = CloudflareResponseV1 {
        result: json!({"zones":[{
            "zone_id":"0123456789abcdef0123456789abcdef",
            "changes":[{
                "type":"updated",
                "target":format!("*@{}",target.reply_domain)
            }]
        }]}),
        result_info: None,
        ..response(Value::Null, 0)
    };
    assert_eq!(
        project_activation_account_plan(
            &updated_without_optional_zone_name,
            &target,
            &parent_zone,
        )
        .expect("provider-declared non-destructive update")
        .change_type,
        "updated"
    );

    for (status, zones) in [
        ("account_plan_no_change", json!([])),
        (
            "account_plan_change_not_additive",
            json!([{
                "zone_id":"0123456789abcdef0123456789abcdef",
                "zone_name":parent_zone.name,
                "changes":[{
                    "type":"conflict",
                    "target":format!("*@{}",target.reply_domain),
                    "remote":{"private":"must-not-retain"}
                }]
            }]),
        ),
        (
            "account_plan_cardinality_ambiguous",
            json!([
                {"zone_id":"0123456789abcdef0123456789abcdef","zone_name":parent_zone.name,"changes":[]},
                {"zone_id":"fedcba9876543210fedcba9876543210","zone_name":parent_zone.name,"changes":[]}
            ]),
        ),
    ] {
        let provider = CloudflareResponseV1 {
            result: json!({"zones":zones}),
            result_info: None,
            ..response(Value::Null, 0)
        };
        let failure = project_activation_account_plan(&provider, &target, &parent_zone)
            .expect_err("unsafe plan must fail closed");
        assert_eq!(failure["status"], status);
        let serialized = serde_json::to_string(&failure).expect("body-free");
        assert!(!serialized.contains("must-not-retain"));
        assert!(!serialized.contains(&target.reply_domain));
    }
}

#[test]
fn activation_execution_rebinds_zone_owner_plan_and_exact_apply_payload() {
    let target = target();
    let parent_zone_id = "0123456789abcdef0123456789abcdef";
    let worker_tag = "fedcba9876543210fedcba9876543210";
    let provider_request = activation_provider_request(&target, worker_tag);
    let apply_body = activation_apply_body(&target.worker_script_name, worker_tag);
    assert_eq!(apply_body["source"], "wrangler");
    assert_eq!(apply_body["owner_worker_tag"], worker_tag);
    assert!(apply_body.get("name").is_none());

    let bound_value = json!({
        "zone_id":parent_zone_id,
        "parent_zone_sha256":sha256(parent_zone_id.as_bytes()),
        "worker_tag_sha256":sha256(worker_tag.as_bytes()),
        "provider_request_sha256":hash_value(&provider_request).expect("request hash"),
        "apply_body_sha256":hash_value(&apply_body).expect("apply hash"),
        "change_type":"added",
    });
    let bound = bound_value.as_object().expect("bound target");
    let plan = ActivationPlan {
        zone_id: parent_zone_id.to_owned(),
        change_type: "added".to_owned(),
    };
    assert_eq!(
        fresh_activation_state_drift(
            bound,
            parent_zone_id,
            worker_tag,
            &provider_request,
            &apply_body,
            &plan,
        ),
        None
    );

    assert_eq!(
        fresh_activation_state_drift(
            bound,
            parent_zone_id,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &provider_request,
            &apply_body,
            &plan,
        ),
        Some("fresh_worker_identity_drifted")
    );
    let changed_plan = ActivationPlan {
        zone_id: parent_zone_id.to_owned(),
        change_type: "updated".to_owned(),
    };
    assert_eq!(
        fresh_activation_state_drift(
            bound,
            parent_zone_id,
            worker_tag,
            &provider_request,
            &apply_body,
            &changed_plan,
        ),
        Some("fresh_account_plan_drifted")
    );
    let wrong_zone_plan = ActivationPlan {
        zone_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        change_type: "added".to_owned(),
    };
    assert_eq!(
        fresh_activation_state_drift(
            bound,
            parent_zone_id,
            worker_tag,
            &provider_request,
            &apply_body,
            &wrong_zone_plan,
        ),
        Some("fresh_parent_zone_drifted")
    );

    let failure_receipt = json!({
        "adapter":ACTIVATION_APPLY_PROJECTION,
        "success":false,
        "boundary_crossed":false,
        "schema_version":1,
        "cfctl_operation_id":"00000000-0000-4000-8000-000000000000",
        "reply_domain_sha256":sha256(target.reply_domain.as_bytes()),
        "worker_target_sha256":sha256(target.worker_script_name.as_bytes()),
        "status":"fresh_account_plan_drifted",
        "provider_status":Value::Null,
        "failure_code":"CFCTL_WORKSPACE_REPLY_SUBDOMAIN_FRESH_PRECONDITION_FAILED",
        "provider_output_retained":false,
        "body_returned":false,
    });
    assert!(is_unperformed_fresh_precondition_failure(&failure_receipt));
    let mut promoted = failure_receipt.clone();
    promoted["boundary_crossed"] = Value::Bool(true);
    assert!(!is_unperformed_fresh_precondition_failure(&promoted));
}

#[test]
fn activation_apply_schema_must_preserve_owner_source_and_exact_rule_shape() {
    let schema = json!({
        "type":"object",
        "x-cfctl-body-required":true,
        "required":["actions","matchers"],
        "properties":{
            "actions":{
                "minItems":1,
                "maxItems":1,
                "items":{"properties":{
                    "type":{"enum":["drop","forward","worker"]},
                    "value":{"maxItems":1}
                }}
            },
            "matchers":{"items":{"properties":{"type":{"enum":["all"]}}}},
            "enabled":{"enum":[true,false]},
            "source":{"enum":["api","wrangler"]},
            "owner_worker_tag":{"type":"string","maxLength":32,"writeOnly":true}
        }
    });
    assert!(activation_apply_schema_supported(&schema));
    for pointer in [
        "/properties/owner_worker_tag",
        "/properties/source",
        "/properties/enabled",
        "/properties/actions/items/properties/type",
        "/properties/matchers/items/properties/type",
    ] {
        let mut drifted = schema.clone();
        *drifted.pointer_mut(pointer).expect("schema pointer") = Value::Null;
        assert!(
            !activation_apply_schema_supported(&drifted),
            "drifted schema pointer {pointer} must fail closed"
        );
    }
}

fn provider_capability(
    id: &str,
    path: &str,
    permissions: &[&str],
    selectors: &[(&str, &str)],
) -> CapabilityV1 {
    let mut capability = CapabilityV1::new(id, id, "GET", path);
    capability.adapter_status = AdapterStatus::DynamicApi;
    capability.permissions = permissions
        .iter()
        .map(|permission| (*permission).to_owned())
        .collect();
    capability.selectors = selectors
        .iter()
        .map(|(name, location)| cfctl_core::SelectorV1 {
            name: (*name).to_owned(),
            location: (*location).to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        })
        .collect();
    capability.response_contract = Some(cfctl_core::ResponseContractV1 {
        success_statuses: vec!["200".to_owned()],
        success_media_types: vec!["application/json".to_owned()],
        body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
    });
    capability
}
