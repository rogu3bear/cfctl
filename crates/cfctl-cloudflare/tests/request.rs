#![allow(clippy::expect_used, clippy::unwrap_used)]

use cfctl_auth::AuthCredential;
use cfctl_cloudflare::{
    CallInput, CloudflareError, CloudflareResponseV1, Executor, R2LogRetrievalCredentials,
    RequestBuilder, validate_request_contract,
};
use cfctl_core::{
    AdapterStatus, AnalyticsQueryContractV1, AnalyticsQueryKindV1,
    AsyncCollectionMutationContractV1, CapabilityV1, CreatedCollectionResourceContractV1,
    CreatedNestedResourceContractV1, CreatedResourceContractV1,
    D1ApprovedMlnImportPollResumeContractV1, D1FullExportContractV1,
    D1RestoreExactBookmarkContractV1, D1SchemaIntrospectionContractV1,
    DeletedNestedResourceContractV1, DeletedResourceContractV1, EffectClass,
    EmailRoutingSubdomainDnsContractV1, EmailSendingDnsRepairContractV1, EventBatchContractV1,
    GraphqlAnalyticsContractV1, KnowledgeReferenceV1, OutputFormatV1, PaginationModeV1, PlanStatus,
    PlanV1, QUEUE_ACK_CAPABILITY_ID, QUEUE_ACK_PATH, QUEUE_PULL_CAPABILITY_ID, QUEUE_PULL_PATH,
    QuerySerializationV1, R2LogRetrievalContractV1, R2PrivateFileUploadContractV1,
    ResponseBodyModeV1, ResponseContractV1, RiskClass, SamePathReadContractV1, SelectorContractV1,
    SelectorV1, TimeRangeContractV1, TimestampFormatV1, TransactionStageV1,
    UpdatedResourceContractV1,
};
use chrono::{Duration, SecondsFormat, Utc};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

async fn json_response_sequence_server(
    bodies: Vec<impl Into<String>>,
) -> (String, tokio::task::JoinHandle<Vec<String>>) {
    let bodies = bodies.into_iter().map(Into::into).collect::<Vec<String>>();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let mut requests = Vec::new();
        for body in bodies {
            let (mut stream, _) = listener.accept().await.expect("accept request");
            let mut buffer = vec![0_u8; 8192];
            let read = stream.read(&mut buffer).await.expect("read request");
            requests.push(String::from_utf8_lossy(&buffer[..read]).to_string());
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write response");
        }
        requests
    });
    (address.to_string(), server)
}

async fn single_raw_response_server(
    status: impl Into<String>,
    content_type: impl Into<String>,
    body: impl Into<String>,
) -> (String, tokio::task::JoinHandle<()>) {
    let status = status.into();
    let content_type = content_type.into();
    let body = body.into();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept request");
        let mut buffer = vec![0_u8; 8192];
        let _ = stream.read(&mut buffer).await.expect("read request");
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write response");
    });
    (address.to_string(), server)
}

async fn single_not_modified_server(etag: &str) -> (String, tokio::task::JoinHandle<String>) {
    let etag = etag.to_owned();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept request");
        let mut buffer = vec![0_u8; 8192];
        let read = stream.read(&mut buffer).await.expect("read request");
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let response =
            format!("HTTP/1.1 304 Not Modified\r\nETag: {etag}\r\nConnection: close\r\n\r\n");
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write response");
        request
    });
    (address.to_string(), server)
}

fn r2_private_upload_capability() -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        "r2-put-object",
        "Upload Object",
        "PUT",
        "/accounts/{account_id}/r2/buckets/{bucket_name}/objects/{object_key}",
    );
    capability.adapter_status = AdapterStatus::DynamicApi;
    capability.mutating = true;
    capability.risk = RiskClass::ScopedWrite;
    capability.effect = EffectClass::ReversibleWrite;
    capability.permissions = vec!["Workers R2 Storage Write".to_owned()];
    capability.selectors = ["account_id", "bucket_name", "object_key"]
        .map(|name| SelectorV1 {
            name: name.to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        })
        .to_vec();
    capability.r2_private_file_upload = Some(R2PrivateFileUploadContractV1 {
        max_source_bytes: 300_000_000,
        allowed_content_types: vec!["application/json".to_owned()],
        require_if_none_match_star: true,
        read_capability_id: "r2-get-object".to_owned(),
        delete_capability_id: "r2-delete-object".to_owned(),
        etag_algorithm: "md5".to_owned(),
    });
    capability
}

#[test]
fn r2_object_keys_preserve_literal_slash_segments() {
    let request = RequestBuilder::new("https://api.cloudflare.test/client/v4")
        .expect("builder")
        .build_unchecked(
            &r2_private_upload_capability(),
            &CallInput {
                selectors: json!({
                    "account_id":"account",
                    "bucket_name":"bucket",
                    "object_key":"config/policy/sha256.json"
                }),
                if_none_match: Some("*".to_owned()),
                ..CallInput::default()
            },
        )
        .expect("R2 request");
    assert_eq!(
        request.url.as_str(),
        "https://api.cloudflare.test/client/v4/accounts/account/r2/buckets/bucket/objects/config/policy/sha256.json"
    );
    assert!(!request.url.as_str().contains("%2F"));
}

#[test]
fn r2_object_keys_reject_empty_and_dot_segments() {
    let capability = r2_private_upload_capability();
    for object_key in ["/leading", "trailing/", "double//slash", "a/../b", "a/./b"] {
        let error = RequestBuilder::new("https://api.cloudflare.test/client/v4")
            .expect("builder")
            .build_unchecked(
                &capability,
                &CallInput {
                    selectors: json!({
                        "account_id":"account",
                        "bucket_name":"bucket",
                        "object_key":object_key
                    }),
                    if_none_match: Some("*".to_owned()),
                    ..CallInput::default()
                },
            )
            .expect_err("unsafe object key must fail closed");
        assert!(matches!(error, CloudflareError::InvalidSelector(name) if name == "object_key"));
    }
}

#[tokio::test]
async fn r2_private_upload_verifier_proves_etag_without_reading_object_bytes() {
    let md5 = "0123456789abcdef0123456789abcdef";
    let quoted_etag = format!("\"{md5}\"");
    let (address, server) = single_not_modified_server(&quoted_etag).await;
    let mut capability = r2_private_upload_capability();
    capability.verification.required = true;
    capability.verification.strategy =
        "r2_private_file_upload_etag_and_conditional_read".to_owned();
    let input = CallInput {
        selectors: json!({
            "account_id":"account",
            "bucket_name":"bucket",
            "object_key":"config/policy/digest.json"
        }),
        if_none_match: Some("*".to_owned()),
        ..CallInput::default()
    };
    let mut plan =
        PlanV1::draft("profile", "account", "catalog", capability, json!({})).expect("plan");
    plan.input = serde_json::to_value(&input).expect("input");
    plan.targets = json!({"adapter":{"r2_private_file_upload":{"source_md5":md5}}});
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"uploaded":true}),
        errors: Vec::new(),
        result_info: None,
        etag: Some(quoted_etag),
        cf_ray: None,
    };
    let verification = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .verify_plan_with_input(
        &plan,
        &apply,
        &input,
        &AuthCredential::Bearer {
            token: "selected-token".to_owned(),
        },
    )
    .await
    .expect("verification");
    assert!(verification.passed);
    assert_eq!(
        verification.readback.result.get("object_identity_proven"),
        Some(&json!(true))
    );
    assert_eq!(
        verification.readback.result.get("body_read"),
        None,
        "body-read transport metadata is replaced by the body-free proof receipt"
    );
    let request = server.await.expect("server joins");
    assert!(request.starts_with(
        "GET /client/v4/accounts/account/r2/buckets/bucket/objects/config/policy/digest.json "
    ));
    assert!(
        request
            .to_ascii_lowercase()
            .contains("if-none-match: \"0123456789abcdef0123456789abcdef\"")
    );
}

fn path_selector(name: &str) -> SelectorV1 {
    SelectorV1 {
        name: name.to_owned(),
        location: "path".to_owned(),
        required: true,
        value_type: "string".to_owned(),
        description: None,
        contract: None,
    }
}

#[tokio::test]
async fn email_sending_dns_verifier_requires_ready_conflict_free_live_status() {
    let response = json!({
        "success":true,
        "result":{
            "status":"ready",
            "errors":[],
            "records":[{
                "type":"TXT",
                "name":"mail.example.com",
                "content":"private-provider-record-content"
            }]
        },
        "errors":[]
    });
    let (address, server) = json_response_sequence_server(vec![response.to_string()]).await;
    let mut capability = CapabilityV1::new(
        "email-sending-subdomains-fix-sending-subdomain-dns",
        "Repair Email Sending DNS",
        "POST",
        "/zones/{zone_id}/email/sending/subdomains/{subdomain_id}/dns",
    );
    capability.mutating = true;
    capability.risk = RiskClass::ScopedWrite;
    capability.effect = EffectClass::ReversibleWrite;
    capability.permissions = vec![
        "DNS Write".to_owned(),
        "Email Sending Read".to_owned(),
        "Email Sending Write".to_owned(),
    ];
    capability.selectors = vec![path_selector("zone_id"), path_selector("subdomain_id")];
    capability.verification.required = true;
    capability.verification.strategy = "email_sending_dns_status_reports_ready".to_owned();
    capability.email_sending_dns_repair = Some(EmailSendingDnsRepairContractV1 {
        status_read_capability_id: "email-sending-subdomains-get-sending-subdomain-dns-status"
            .to_owned(),
        status_read_path: "/zones/{zone_id}/email/sending/subdomains/{subdomain_id}/dns/status"
            .to_owned(),
    });
    let input = CallInput {
        selectors: json!({"zone_id":"zone","subdomain_id":"sender-id"}),
        ..CallInput::default()
    };
    let mut plan =
        PlanV1::draft("profile", "account", "catalog", capability, json!({})).expect("plan");
    plan.input = serde_json::to_value(&input).expect("input");
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let verification = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .verify_plan_with_input(
        &plan,
        &apply,
        &input,
        &AuthCredential::Bearer {
            token: "selected-token".to_owned(),
        },
    )
    .await
    .expect("verification");
    assert!(verification.passed);
    assert_eq!(verification.readback.result["status_ready"], true);
    assert_eq!(verification.readback.result["errors_empty"], true);
    assert_eq!(verification.readback.result["records_present"], true);
    assert!(
        !verification
            .readback
            .result
            .to_string()
            .contains("private-provider-record-content")
    );
    let requests = server.await.expect("server");
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0].starts_with(
            "GET /client/v4/zones/zone/email/sending/subdomains/sender-id/dns/status "
        )
    );
}

#[tokio::test]
async fn email_routing_subdomain_verifier_binds_exact_requested_name() {
    let response = json!({
        "success":true,
        "result":{
            "errors":[],
            "record":[
                {"type":"MX","name":"reply.maildesk.example.com","content":"mx.example.net"},
                {"type":"TXT","name":"reply.maildesk.example.com","content":"provider-secret"}
            ]
        },
        "errors":[]
    });
    let (address, server) = json_response_sequence_server(vec![response.to_string()]).await;
    let mut capability = CapabilityV1::new(
        "email-routing-settings-enable-email-routing-dns",
        "Enable explicit Email Routing subdomain",
        "POST",
        "/zones/{zone_id}/email/routing/dns",
    );
    capability.mutating = true;
    capability.risk = RiskClass::ScopedWrite;
    capability.effect = EffectClass::ReversibleWrite;
    capability.permissions = vec!["DNS Write".to_owned(), "Zone Settings Write".to_owned()];
    capability.selectors = vec![path_selector("zone_id")];
    capability.request_schema = Some(json!({
        "type":"object",
        "additionalProperties":false,
        "required":["name"],
        "properties":{"name":{"type":"string","minLength":1,"maxLength":253}},
        "x-cfctl-body-required":true
    }));
    capability.verification.required = true;
    capability.verification.strategy = "email_routing_subdomain_dns_records_match".to_owned();
    capability.email_routing_subdomain_dns = Some(EmailRoutingSubdomainDnsContractV1 {
        read_capability_id: "email-routing-settings-email-routing-dns-settings".to_owned(),
        read_path: "/zones/{zone_id}/email/routing/dns".to_owned(),
        request_name_field: "name".to_owned(),
        read_query_field: "subdomain".to_owned(),
    });
    let input = CallInput {
        selectors: json!({"zone_id":"zone"}),
        body: Some(json!({"name":"reply.maildesk.example.com"})),
        ..CallInput::default()
    };
    let mut plan =
        PlanV1::draft("profile", "account", "catalog", capability, json!({})).expect("plan");
    plan.input = serde_json::to_value(&input).expect("input");
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let verification = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .verify_plan_with_input(
        &plan,
        &apply,
        &input,
        &AuthCredential::Bearer {
            token: "selected-token".to_owned(),
        },
    )
    .await
    .expect("verification");
    assert!(verification.passed);
    assert_eq!(verification.readback.result["record_count"], 2);
    assert_eq!(verification.readback.result["records_match"], true);
    assert!(
        !verification
            .readback
            .result
            .to_string()
            .contains("provider-secret")
    );
    let requests = server.await.expect("server");
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with(
        "GET /client/v4/zones/zone/email/routing/dns?subdomain=reply.maildesk.example.com "
    ));
}

fn d1_approved_mln_import_poll_resume_fixture(
    max_poll_attempts: u64,
) -> (CapabilityV1, CallInput, Value) {
    let account_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let database_id = "11111111-2222-4333-8444-555555555555";
    let mut capability = CapabilityV1::new(
        "d1-resume-approved-mln-import-poll",
        "Resume approved MLN import polling",
        "POST",
        "/accounts/{account_id}/d1/database/{database_id}/import",
    );
    "D1".clone_into(&mut capability.product);
    "account".clone_into(&mut capability.account_scope);
    capability.adapter_status = AdapterStatus::Native;
    capability.mutating = true;
    capability.permissions = vec!["D1 Write".to_owned()];
    capability.risk = RiskClass::Irreversible;
    capability.effect = EffectClass::DataWrite;
    capability.selectors = ["account_id", "database_id"]
        .map(|name| SelectorV1 {
            name: name.to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        })
        .to_vec();
    capability.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".to_owned()],
        success_media_types: vec!["application/json".to_owned()],
        body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
    });
    capability.d1_approved_mln_import_poll_resume = Some(D1ApprovedMlnImportPollResumeContractV1 {
        root_capability_id: "d1-import-approved-mln-migration".to_owned(),
        account_id: account_id.to_owned(),
        database_id: database_id.to_owned(),
        import_path: "/accounts/{account_id}/d1/database/{database_id}/import".to_owned(),
        max_response_bytes: 1024 * 1024,
        max_poll_attempts,
        max_timeout_seconds: 1,
    });
    let input = CallInput {
        selectors: json!({"account_id":account_id,"database_id":database_id}),
        query: json!({}),
        body: Some(json!({
            "parent_operation_id":"parent-operation",
            "parent_plan_hash":format!("sha256:{}", "1".repeat(64)),
            "exhaustion_evidence_hash":format!("sha256:{}", "2".repeat(64)),
            "accepted_ingest_evidence_hash":format!("sha256:{}", "3".repeat(64)),
            "accepted_bookmark_hash":format!("sha256:{}", "4".repeat(64)),
        })),
        ..CallInput::default()
    };
    let targets = json!({
        "adapter":{
            "approved_mln_import_poll_resume":{
                "accepted_bookmark":"derived-bookmark",
                "root_operation_id":"root-operation",
                "root_plan_hash":format!("sha256:{}", "5".repeat(64)),
                "parent_operation_id":"parent-operation",
                "parent_exhaustion_evidence_hash":format!("sha256:{}", "2".repeat(64)),
                "root_input":{"body":{"migration_id":"0143"}},
                "root_stage":{
                    "sha256":format!("sha256:{}", "6".repeat(64)),
                    "md5":"0123456789abcdef0123456789abcdef",
                    "bytes":123,
                    "source_authority_hash":format!("sha256:{}", "7".repeat(64)),
                }
            }
        }
    });
    (capability, input, targets)
}

fn d1_approved_mln_import_poll_resume_plan(max_poll_attempts: u64) -> (PlanV1, CallInput) {
    let (capability, input, targets) =
        d1_approved_mln_import_poll_resume_fixture(max_poll_attempts);
    let mut plan = PlanV1::draft(
        "profile",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "sha256:catalog",
        capability,
        targets,
    )
    .expect("draft poll continuation");
    plan.input = serde_json::to_value(&input).expect("plan input");
    (plan, input)
}

fn assert_exact_poll_request(request: &str) {
    assert!(request.starts_with(
        "POST /accounts/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/d1/database/11111111-2222-4333-8444-555555555555/import "
    ));
    let body = request
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .expect("request body");
    assert_eq!(
        serde_json::from_str::<Value>(body).expect("JSON request body"),
        json!({"action":"poll","current_bookmark":"derived-bookmark"})
    );
    for forbidden in [
        "init",
        "ingest",
        "upload",
        "filename",
        "etag",
        "migration_id",
        "max_poll_attempts",
        "max_timeout_seconds",
    ] {
        assert!(!body.contains(forbidden), "{forbidden}");
    }
}

#[tokio::test]
async fn d1_approved_mln_import_poll_resume_sends_only_exact_derived_poll_until_complete() {
    let (address, server) = json_response_sequence_server(vec![
        r#"{"success":true,"result":{"type":"import","status":"pending","success":true,"at_bookmark":"derived-bookmark"},"errors":[]}"#,
        r#"{"success":true,"result":{"type":"import","status":"complete","success":true,"at_bookmark":"derived-bookmark","result":{"final_bookmark":"final-bookmark"}},"errors":[]}"#,
    ])
    .await;
    let (mut plan, input) = d1_approved_mln_import_poll_resume_plan(3);
    let mut checkpoints = Vec::new();
    let response = Executor::new(reqwest::Client::new(), &format!("http://{address}"))
        .expect("executor")
        .execute_d1_approved_mln_import_poll_resume(
            &mut plan,
            &input,
            &AuthCredential::Bearer {
                token: "token".to_owned(),
            },
            "derived-bookmark",
            |checkpoint| {
                checkpoints.push(checkpoint.clone());
                Ok(())
            },
        )
        .await
        .expect("completed poll continuation");
    assert_eq!(
        response.result["_cfctl"]["final_bookmark"],
        "final-bookmark"
    );
    assert_eq!(plan.status, PlanStatus::Running);
    assert_eq!(
        checkpoints.last().expect("completion").step,
        "provider_complete"
    );
    let requests = server.await.expect("server");
    assert_eq!(requests.len(), 2);
    for request in &requests {
        assert_exact_poll_request(request);
    }
}

#[tokio::test]
async fn d1_approved_mln_import_poll_resume_exhausts_at_exact_bound_with_only_poll_requests() {
    let pending = r#"{"success":true,"result":{"type":"import","status":"active","success":true,"at_bookmark":"derived-bookmark"},"errors":[]}"#;
    let (address, server) = json_response_sequence_server(vec![pending, pending]).await;
    let (mut plan, input) = d1_approved_mln_import_poll_resume_plan(2);
    let mut checkpoints = Vec::new();
    let error = Executor::new(reqwest::Client::new(), &format!("http://{address}"))
        .expect("executor")
        .execute_d1_approved_mln_import_poll_resume(
            &mut plan,
            &input,
            &AuthCredential::Bearer {
                token: "token".to_owned(),
            },
            "derived-bookmark",
            |checkpoint| {
                checkpoints.push(checkpoint.clone());
                Ok(())
            },
        )
        .await
        .expect_err("bounded polling must exhaust");
    assert!(matches!(
        error,
        CloudflareError::D1ImportPollInProgressExhausted
    ));
    assert_eq!(plan.status, PlanStatus::RectificationRequired);
    assert_eq!(
        checkpoints.last().expect("exhaustion").step,
        "poll_in_progress_exhausted"
    );
    let requests = server.await.expect("server");
    assert_eq!(requests.len(), 2);
    for request in &requests {
        assert_exact_poll_request(request);
    }
}

#[tokio::test]
async fn d1_approved_mln_import_poll_resume_provider_error_stops_after_one_exact_poll() {
    let (address, server) = json_response_sequence_server(vec![
        r#"{"success":true,"result":{"type":"import","status":"error","success":false,"at_bookmark":"derived-bookmark","error":"provider rejected"},"errors":[]}"#,
    ])
    .await;
    let (mut plan, input) = d1_approved_mln_import_poll_resume_plan(3);
    let mut checkpoints = Vec::new();
    let error = Executor::new(reqwest::Client::new(), &format!("http://{address}"))
        .expect("executor")
        .execute_d1_approved_mln_import_poll_resume(
            &mut plan,
            &input,
            &AuthCredential::Bearer {
                token: "token".to_owned(),
            },
            "derived-bookmark",
            |checkpoint| {
                checkpoints.push(checkpoint.clone());
                Ok(())
            },
        )
        .await
        .expect_err("provider error must fail closed");
    assert!(matches!(
        error,
        CloudflareError::D1ImportPollResponseFailure
    ));
    assert_eq!(plan.status, PlanStatus::RectificationRequired);
    assert_eq!(checkpoints.len(), 1);
    assert_eq!(checkpoints[0].step, "poll_response_1");
    let requests = server.await.expect("server");
    assert_eq!(requests.len(), 1);
    assert_exact_poll_request(&requests[0]);
}

#[tokio::test]
async fn d1_approved_mln_import_poll_resume_rejects_bookmark_drift_before_transport() {
    let (mut plan, input) = d1_approved_mln_import_poll_resume_plan(3);
    let error = Executor::new(reqwest::Client::new(), "http://127.0.0.1:1")
        .expect("executor")
        .execute_d1_approved_mln_import_poll_resume(
            &mut plan,
            &input,
            &AuthCredential::Bearer {
                token: "token".to_owned(),
            },
            "caller-controlled-bookmark",
            |_| Ok(()),
        )
        .await
        .expect_err("bookmark drift must fail before transport");
    assert!(matches!(error, CloudflareError::InvalidRequestBody(_)));
    assert_eq!(plan.status, PlanStatus::Draft);
}

fn d1_restore_exact_bookmark_capability() -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        "d1-restore-exact-bookmark",
        "Restore D1 database to exact bookmark",
        "POST",
        "/accounts/{account_id}/d1/database/{database_id}/time_travel/restore",
    );
    "D1".clone_into(&mut capability.product);
    "account".clone_into(&mut capability.account_scope);
    capability.adapter_status = AdapterStatus::Native;
    capability.permissions = vec!["D1 Write".to_owned()];
    capability.risk = RiskClass::Recovery;
    capability.effect = EffectClass::DataWrite;
    "d1_current_bookmark_equals_restore_result_bookmark"
        .clone_into(&mut capability.verification.strategy);
    capability.rollback.supported = true;
    capability.rollback.strategy =
        Some("new_approved_exact_bookmark_restore_from_previous_bookmark".to_owned());
    capability.selectors = ["account_id", "database_id"]
        .map(|name| SelectorV1 {
            name: name.to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: Some(SelectorContractV1 {
                schema: if name == "account_id" {
                    json!({"type":"string","minLength":32,"maxLength":32})
                } else {
                    json!({"type":"string","minLength":36,"maxLength":36})
                },
                query: None,
            }),
        })
        .to_vec();
    capability.request_schema = Some(json!({
        "type":"object",
        "additionalProperties":false,
        "required":["target_bookmark","expected_current_bookmark","source_operation_id","source_evidence_hash"],
        "properties":{
            "target_bookmark":{"type":"string","minLength":1},
            "expected_current_bookmark":{"type":"string","minLength":1},
            "source_operation_id":{"type":"string","minLength":1},
            "source_evidence_hash":{"type":"string","minLength":1}
        }
    }));
    capability.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".to_owned()],
        success_media_types: vec!["application/json".to_owned()],
        body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
    });
    capability.d1_restore_exact_bookmark = Some(D1RestoreExactBookmarkContractV1 {
        bookmark_path: "/accounts/{account_id}/d1/database/{database_id}/time_travel/bookmark"
            .to_owned(),
        restore_path: "/accounts/{account_id}/d1/database/{database_id}/time_travel/restore"
            .to_owned(),
        max_response_bytes: 64 * 1024,
        max_timeout_seconds: 30,
        post_retry_count: 0,
    });
    capability
}

#[tokio::test]
async fn d1_restore_prechecks_posts_once_and_postchecks_exact_returned_bookmark() {
    let (address, server) = json_response_sequence_server(vec![
        r#"{"success":true,"result":{"bookmark":"current-7"},"errors":[]}"#,
        r#"{"success":true,"result":{"bookmark":"restored-8","message":"Database restored","previous_bookmark":"current-7"},"errors":[]}"#,
        r#"{"success":true,"result":{"bookmark":"restored-8"},"errors":[]}"#,
    ])
    .await;
    let capability = d1_restore_exact_bookmark_capability();
    let input = CallInput {
        selectors: json!({
            "account_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "database_id":"11111111-2222-3333-4444-555555555555"
        }),
        body: Some(json!({
            "target_bookmark":"target-1",
            "expected_current_bookmark":"current-7",
            "source_operation_id":"source-op",
            "source_evidence_hash":format!("sha256:{}", "a".repeat(64))
        })),
        ..CallInput::default()
    };
    let mut plan = PlanV1::draft(
        "profile",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "sha256:catalog",
        capability,
        json!({}),
    )
    .expect("draft plan");
    plan.input = serde_json::to_value(&input).expect("plan input");
    plan.refresh_hash().expect("refresh plan");
    plan.approve(true, None).expect("approve plan");
    plan.mark_consumed().expect("consume plan");
    let response = Executor::new(reqwest::Client::new(), &format!("http://{address}"))
        .expect("executor")
        .execute_consumed_plan_with_input(
            &mut plan,
            "sha256:catalog",
            &AuthCredential::Bearer {
                token: "token".to_owned(),
            },
            &input,
        )
        .await
        .expect("restore");
    assert!(response.success);
    assert_eq!(response.result["bookmark"], "restored-8");
    assert_eq!(response.result["previous_bookmark"], "current-7");
    assert_eq!(
        response.result["_cfctl"]["pre_restore_bookmark"],
        "current-7"
    );
    assert_eq!(
        response.result["_cfctl"]["source_operation_id"],
        "source-op"
    );
    assert_eq!(response.result["_cfctl"]["verified"], false);
    let verification = Executor::new(reqwest::Client::new(), &format!("http://{address}"))
        .expect("executor")
        .verify_plan_with_input(
            &plan,
            &response,
            &input,
            &AuthCredential::Bearer {
                token: "token".to_owned(),
            },
        )
        .await
        .expect("verification");
    assert!(verification.passed);
    assert_eq!(
        verification.readback.result["_cfctl"]["post_restore_bookmark"],
        "restored-8"
    );
    assert_eq!(verification.readback.result["_cfctl"]["verified"], true);
    let requests = server.await.expect("server");
    assert_eq!(requests.len(), 3);
    assert!(requests[0].starts_with("GET "));
    assert!(requests[1].starts_with("POST "));
    assert!(requests[2].starts_with("GET "));
    assert!(requests[1].contains(r#"{"bookmark":"target-1"}"#));
    assert!(!requests[1].contains("source_operation_id"));
    assert!(!requests[1].contains("expected_current_bookmark"));
}

#[tokio::test]
async fn d1_restore_preserves_success_response_when_post_read_fails() {
    let (address, server) = json_response_sequence_server(vec![
        r#"{"success":true,"result":{"bookmark":"current-7"},"errors":[]}"#,
        r#"{"success":true,"result":{"bookmark":"restored-8","message":"Database restored","previous_bookmark":"current-7"},"errors":[]}"#,
    ])
    .await;
    let capability = d1_restore_exact_bookmark_capability();
    let input = CallInput {
        selectors: json!({
            "account_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "database_id":"11111111-2222-3333-4444-555555555555"
        }),
        body: Some(json!({
            "target_bookmark":"target-1",
            "expected_current_bookmark":"current-7",
            "source_operation_id":"source-op",
            "source_evidence_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        })),
        ..CallInput::default()
    };
    let mut plan = PlanV1::draft(
        "profile",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "sha256:catalog",
        capability,
        json!({}),
    )
    .expect("draft plan");
    plan.input = serde_json::to_value(&input).expect("plan input");
    plan.refresh_hash().expect("refresh plan");
    plan.approve(true, None).expect("approve plan");
    plan.mark_consumed().expect("consume plan");
    let executor =
        Executor::new(reqwest::Client::new(), &format!("http://{address}")).expect("executor");
    let response = executor
        .execute_consumed_plan_with_input(
            &mut plan,
            "sha256:catalog",
            &AuthCredential::Bearer {
                token: "token".to_owned(),
            },
            &input,
        )
        .await
        .expect("successful POST response");
    assert_eq!(server.await.expect("server").len(), 2);
    let error = executor
        .verify_plan_with_input(
            &plan,
            &response,
            &input,
            &AuthCredential::Bearer {
                token: "token".to_owned(),
            },
        )
        .await
        .expect_err("post-read must fail");
    assert!(matches!(error, CloudflareError::Http(_)));
    assert!(response.success);
    assert_eq!(response.result["bookmark"], "restored-8");
    assert_eq!(response.result["previous_bookmark"], "current-7");
    assert_eq!(response.result["_cfctl"]["performed"], true);
    assert_eq!(response.result["_cfctl"]["verified"], false);
}

#[tokio::test]
async fn d1_restore_preserves_success_response_when_post_read_mismatches() {
    let (address, server) = json_response_sequence_server(vec![
        r#"{"success":true,"result":{"bookmark":"current-7"},"errors":[]}"#,
        r#"{"success":true,"result":{"bookmark":"restored-8","message":"Database restored","previous_bookmark":"current-7"},"errors":[]}"#,
        r#"{"success":true,"result":{"bookmark":"unexpected-9"},"errors":[]}"#,
    ])
    .await;
    let capability = d1_restore_exact_bookmark_capability();
    let input = CallInput {
        selectors: json!({
            "account_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "database_id":"11111111-2222-3333-4444-555555555555"
        }),
        body: Some(json!({
            "target_bookmark":"target-1",
            "expected_current_bookmark":"current-7",
            "source_operation_id":"source-op",
            "source_evidence_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        })),
        ..CallInput::default()
    };
    let mut plan = PlanV1::draft(
        "profile",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "sha256:catalog",
        capability,
        json!({}),
    )
    .expect("draft plan");
    plan.input = serde_json::to_value(&input).expect("plan input");
    plan.refresh_hash().expect("refresh plan");
    plan.approve(true, None).expect("approve plan");
    plan.mark_consumed().expect("consume plan");
    let executor =
        Executor::new(reqwest::Client::new(), &format!("http://{address}")).expect("executor");
    let response = executor
        .execute_consumed_plan_with_input(
            &mut plan,
            "sha256:catalog",
            &AuthCredential::Bearer {
                token: "token".to_owned(),
            },
            &input,
        )
        .await
        .expect("successful POST response");
    let verification = executor
        .verify_plan_with_input(
            &plan,
            &response,
            &input,
            &AuthCredential::Bearer {
                token: "token".to_owned(),
            },
        )
        .await
        .expect("mismatch verification");
    assert_eq!(server.await.expect("server").len(), 3);
    assert!(!verification.passed);
    assert!(verification.basis.contains("unexpected-9"));
    assert!(response.success);
    assert_eq!(response.result["bookmark"], "restored-8");
    assert_eq!(response.result["previous_bookmark"], "current-7");
    assert_eq!(response.result["_cfctl"]["performed"], true);
    assert_eq!(response.result["_cfctl"]["verified"], false);
    assert_eq!(
        verification.readback.result["_cfctl"]["previous_bookmark"],
        "current-7"
    );
    assert_eq!(
        verification.readback.result["_cfctl"]["post_restore_bookmark"],
        "unexpected-9"
    );
    assert_eq!(verification.readback.result["_cfctl"]["performed"], true);
    assert_eq!(verification.readback.result["_cfctl"]["verified"], false);
}

#[tokio::test]
async fn d1_restore_expected_bookmark_mismatch_fails_before_post() {
    let (address, server) = json_response_sequence_server(vec![
        r#"{"success":true,"result":{"bookmark":"unexpected"},"errors":[]}"#,
    ])
    .await;
    let capability = d1_restore_exact_bookmark_capability();
    let input = CallInput {
        selectors: json!({
            "account_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "database_id":"11111111-2222-3333-4444-555555555555"
        }),
        body: Some(json!({
            "target_bookmark":"target-1",
            "expected_current_bookmark":"expected",
            "source_operation_id":"source-op",
            "source_evidence_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        })),
        ..CallInput::default()
    };
    let mut plan = PlanV1::draft(
        "profile",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "sha256:catalog",
        capability,
        json!({}),
    )
    .expect("draft plan");
    plan.input = serde_json::to_value(&input).expect("plan input");
    plan.refresh_hash().expect("refresh plan");
    plan.approve(true, None).expect("approve plan");
    plan.mark_consumed().expect("consume plan");
    let error = Executor::new(reqwest::Client::new(), &format!("http://{address}"))
        .expect("executor")
        .execute_consumed_plan_with_input(
            &mut plan,
            "sha256:catalog",
            &AuthCredential::Bearer {
                token: "token".to_owned(),
            },
            &input,
        )
        .await
        .expect_err("bookmark drift");
    assert!(error.to_string().contains("expected current bookmark"));
    assert_eq!(server.await.expect("server").len(), 1);
}

#[tokio::test]
async fn d1_restore_does_not_retry_post_after_provider_500() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("address");
    let server = tokio::spawn(async move {
        let mut requests = Vec::new();
        for (status, body) in [
            (
                "200 OK",
                r#"{"success":true,"result":{"bookmark":"current-7"},"errors":[]}"#,
            ),
            (
                "500 Internal Server Error",
                r#"{"success":false,"result":{},"errors":[{"message":"uncertain"}]}"#,
            ),
        ] {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buffer = [0_u8; 8192];
            let read = stream.read(&mut buffer).await.expect("read");
            requests.push(String::from_utf8_lossy(&buffer[..read]).to_string());
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .expect("write");
        }
        let retried =
            tokio::time::timeout(std::time::Duration::from_millis(150), listener.accept())
                .await
                .is_ok();
        (requests, retried)
    });
    let capability = d1_restore_exact_bookmark_capability();
    let input = CallInput {
        selectors: json!({
            "account_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "database_id":"11111111-2222-3333-4444-555555555555"
        }),
        body: Some(json!({
            "target_bookmark":"target-1",
            "expected_current_bookmark":"current-7",
            "source_operation_id":"source-op",
            "source_evidence_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        })),
        ..CallInput::default()
    };
    let mut plan = PlanV1::draft(
        "profile",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "sha256:catalog",
        capability,
        json!({}),
    )
    .expect("draft plan");
    plan.input = serde_json::to_value(&input).expect("plan input");
    plan.refresh_hash().expect("refresh plan");
    plan.approve(true, None).expect("approve plan");
    plan.mark_consumed().expect("consume plan");
    let response = Executor::new(reqwest::Client::new(), &format!("http://{address}"))
        .expect("executor")
        .execute_consumed_plan_with_input(
            &mut plan,
            "sha256:catalog",
            &AuthCredential::Bearer {
                token: "token".to_owned(),
            },
            &input,
        )
        .await
        .expect("provider rejection is a response");
    assert!(!response.success);
    let (requests, retried) = server.await.expect("server");
    assert_eq!(requests.len(), 2);
    assert!(requests[1].starts_with("POST "));
    assert!(!retried, "destructive restore POST must never retry");
}

#[test]
fn request_builder_resolves_path_and_query_selectors_without_leaking_auth() {
    let mut capability = CapabilityV1::new(
        "dns-records-list",
        "List DNS records",
        "GET",
        "/zones/{zone_id}/dns_records",
    );
    capability.selectors = vec![
        SelectorV1 {
            name: "zone_id".to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        },
        SelectorV1 {
            name: "name".to_owned(),
            location: "query".to_owned(),
            required: false,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        },
    ];
    let request = RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("valid base URL")
        .build(
            &capability,
            &CallInput {
                selectors: json!({"zone_id":"zone a"}),
                query: json!({"name":"www.example.com"}),
                body: None,
                if_none_match: Some("etag-1".to_owned()),
                ..CallInput::default()
            },
        )
        .expect("request should build");

    assert_eq!(
        request.url.as_str(),
        "https://api.cloudflare.com/client/v4/zones/zone%20a/dns_records?name=www.example.com"
    );
    assert!(request.headers.get("authorization").is_none());
    assert_eq!(
        request
            .headers
            .get("if-none-match")
            .and_then(|value| value.to_str().ok()),
        Some("etag-1")
    );
}

#[test]
fn request_builder_rejects_query_controls_outside_the_catalog_contract() {
    let mut capability = CapabilityV1::new(
        "workers-ai-run",
        "Run model",
        "GET",
        "/accounts/{account_id}/ai/run/{model_name}",
    );
    capability.selectors = vec![
        SelectorV1 {
            name: "account_id".to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        },
        SelectorV1 {
            name: "model_name".to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        },
        SelectorV1 {
            name: "queueRequest".to_owned(),
            location: "query".to_owned(),
            required: true,
            value_type: "boolean".to_owned(),
            description: None,
            contract: None,
        },
    ];
    let builder = RequestBuilder::new("https://api.cloudflare.com/client/v4").expect("builder");
    let selectors = json!({"account_id":"account-1", "model_name":"@cf/example/model"});

    let undeclared = builder
        .build(
            &capability,
            &CallInput {
                selectors: selectors.clone(),
                query: json!({"queueRequest":"true", "bypass":"1"}),
                ..CallInput::default()
            },
        )
        .expect_err("undeclared query controls must fail closed");
    assert!(matches!(
        undeclared,
        CloudflareError::UndeclaredQuerySelector(name) if name == "bypass"
    ));

    let missing = builder
        .build(
            &capability,
            &CallInput {
                selectors: selectors.clone(),
                query: json!({}),
                ..CallInput::default()
            },
        )
        .expect_err("required query controls must be present");
    assert!(matches!(
        missing,
        CloudflareError::MissingQuerySelector(name) if name == "queueRequest"
    ));

    let invalid = builder
        .build(
            &capability,
            &CallInput {
                selectors: selectors.clone(),
                query: json!({"queueRequest":{"nested":true}}),
                ..CallInput::default()
            },
        )
        .expect_err("query controls must satisfy their catalog type");
    assert!(matches!(
        invalid,
        CloudflareError::InvalidQuerySelector { name, expected }
            if name == "queueRequest" && expected == "boolean"
    ));

    let request = builder
        .build(
            &capability,
            &CallInput {
                selectors,
                query: json!({"queueRequest":"true"}),
                ..CallInput::default()
            },
        )
        .expect("CLI string form of a declared boolean query should build");
    assert_eq!(request.url.query(), Some("queueRequest=true"));
}

fn query_selector(
    name: &str,
    value_type: &str,
    schema: Value,
    explode: bool,
    allow_empty_value: bool,
) -> SelectorV1 {
    SelectorV1 {
        name: name.to_owned(),
        location: "query".to_owned(),
        required: false,
        value_type: value_type.to_owned(),
        description: None,
        contract: Some(SelectorContractV1 {
            schema,
            query: Some(QuerySerializationV1 {
                style: "form".to_owned(),
                explode,
                allow_reserved: false,
                allow_empty_value,
            }),
        }),
    }
}

fn query_contract_capability() -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        "items-list",
        "List items",
        "GET",
        "/accounts/{account_id}/items",
    );
    capability.selectors = vec![
        SelectorV1 {
            name: "account_id".to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        },
        query_selector(
            "tags",
            "array",
            json!({
                    "type":"array",
                    "minItems":1,
                    "maxItems":2,
                    "uniqueItems":true,
                    "items":{"type":"string", "enum":["one","two"]}
            }),
            false,
            false,
        ),
        query_selector(
            "limit",
            "integer",
            json!({"type":"integer", "minimum":1, "maximum":10}),
            true,
            false,
        ),
        query_selector(
            "empty",
            "integer",
            json!({"type":"integer", "minimum":1}),
            true,
            true,
        ),
    ];
    capability
}

#[test]
fn request_builder_enforces_query_schema_and_exact_form_serialization() {
    let capability = query_contract_capability();
    let builder = RequestBuilder::new("https://api.cloudflare.com/client/v4").expect("builder");
    let request = builder
        .build(
            &capability,
            &CallInput {
                selectors: json!({"account_id":"account-1"}),
                query: json!({"tags":["one","two"], "limit":"5"}),
                ..CallInput::default()
            },
        )
        .expect("valid pinned query contract");
    assert_eq!(
        request.url.query_pairs().collect::<Vec<_>>(),
        vec![
            ("limit".into(), "5".into()),
            ("tags".into(), "one,two".into())
        ]
    );

    let invalid_enum = builder
        .build(
            &capability,
            &CallInput {
                selectors: json!({"account_id":"account-1"}),
                query: json!({"tags":["one","three"]}),
                ..CallInput::default()
            },
        )
        .expect_err("array items must satisfy their pinned enum");
    assert!(matches!(
        invalid_enum,
        CloudflareError::InvalidQuerySelectorSchema { name, .. } if name == "tags"
    ));

    let invalid_bound = builder
        .build(
            &capability,
            &CallInput {
                selectors: json!({"account_id":"account-1"}),
                query: json!({"limit":"11"}),
                ..CallInput::default()
            },
        )
        .expect_err("numeric query bounds must be enforced");
    assert!(matches!(
        invalid_bound,
        CloudflareError::InvalidQuerySelectorSchema { name, .. } if name == "limit"
    ));
}

#[test]
fn request_builder_preserves_allowed_empty_queries_and_rejects_unsupported_styles() {
    let capability = query_contract_capability();
    let builder = RequestBuilder::new("https://api.cloudflare.com/client/v4").expect("builder");
    let empty = builder
        .build(
            &capability,
            &CallInput {
                selectors: json!({"account_id":"account-1"}),
                query: json!({"empty":""}),
                ..CallInput::default()
            },
        )
        .expect("allowEmptyValue must preserve an explicit empty query control");
    assert_eq!(
        empty.url.query_pairs().collect::<Vec<_>>(),
        vec![("empty".into(), "".into())]
    );

    let mut unsupported = capability.clone();
    unsupported
        .selectors
        .iter_mut()
        .find(|selector| selector.name == "tags")
        .and_then(|selector| selector.contract.as_mut())
        .and_then(|contract| contract.query.as_mut())
        .expect("query contract")
        .style = "pipeDelimited".to_owned();
    let error = builder
        .build(
            &unsupported,
            &CallInput {
                selectors: json!({"account_id":"account-1"}),
                query: json!({"tags":["one","two"]}),
                ..CallInput::default()
            },
        )
        .expect_err("unsupported query styles must fail during contract preflight");
    assert!(matches!(
        error,
        CloudflareError::UnsupportedQuerySerialization { name, .. } if name == "tags"
    ));
}

#[test]
fn request_builder_rejects_nested_query_collections_before_rendering() {
    let mut nested = query_contract_capability();
    let builder = RequestBuilder::new("https://api.cloudflare.com/client/v4").expect("builder");
    nested.selectors.push(query_selector(
        "nested",
        "array",
        json!({"type":"array", "items":{"type":"array", "items":{"type":"string"}}}),
        false,
        false,
    ));
    let error = builder
        .build(
            &nested,
            &CallInput {
                selectors: json!({"account_id":"account-1"}),
                query: json!({"nested":[["one","two"]]}),
                ..CallInput::default()
            },
        )
        .expect_err("nested query collections cannot be represented as URL scalar controls");
    assert!(matches!(
        error,
        CloudflareError::InvalidQuerySelector { name, .. } if name == "nested"
    ));
}

#[test]
fn request_builder_sends_only_catalog_declared_header_selectors() {
    let mut capability = CapabilityV1::new(
        "r2-get-bucket",
        "Get R2 bucket",
        "GET",
        "/accounts/{account_id}/r2/buckets/{bucket_name}",
    );
    capability.selectors = vec![SelectorV1 {
        name: "cf-r2-jurisdiction".to_owned(),
        location: "header".to_owned(),
        required: false,
        value_type: "unknown".to_owned(),
        description: None,
        contract: None,
    }];
    let request = RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("valid base URL")
        .build(
            &capability,
            &CallInput {
                selectors: json!({
                    "account_id":"account-1",
                    "bucket_name":"bucket-1",
                    "cf-r2-jurisdiction":"eu"
                }),
                ..CallInput::default()
            },
        )
        .expect("declared header should build");

    assert_eq!(
        request
            .headers
            .get("cf-r2-jurisdiction")
            .and_then(|value| value.to_str().ok()),
        Some("eu")
    );
    let error = RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("valid base URL")
        .build(
            &capability,
            &CallInput {
                selectors: json!({
                    "account_id":"account-1",
                    "bucket_name":"bucket-1",
                    "cf-r2-jurisdiction":true
                }),
                ..CallInput::default()
            },
        )
        .expect_err("R2 jurisdiction must remain a string")
        .to_string();
    assert!(error.contains("cf-r2-jurisdiction"));
}

#[test]
fn request_builder_rejects_missing_required_or_reserved_header_selectors() {
    let mut capability = CapabilityV1::new("header-read", "Header read", "GET", "/header-read");
    capability.selectors = vec![SelectorV1 {
        name: "Tus-Resumable".to_owned(),
        location: "header".to_owned(),
        required: true,
        value_type: "string".to_owned(),
        description: None,
        contract: None,
    }];
    let builder = RequestBuilder::new("https://api.cloudflare.com/client/v4").expect("builder");
    let missing = builder
        .build(&capability, &CallInput::default())
        .expect_err("required header must fail closed");
    assert!(
        matches!(missing, CloudflareError::MissingHeaderSelector(name) if name == "Tus-Resumable")
    );

    capability.selectors[0].name = "Authorization".to_owned();
    let reserved = builder
        .build(
            &capability,
            &CallInput {
                selectors: json!({"Authorization":"must-not-be-forwarded"}),
                ..CallInput::default()
            },
        )
        .expect_err("auth headers must be reserved");
    assert!(
        matches!(reserved, CloudflareError::ReservedHeaderSelector(name) if name == "Authorization")
    );

    capability.selectors[0].name = "R2-Secret-Access-Key".to_owned();
    let reserved = builder
        .build(
            &capability,
            &CallInput {
                selectors: json!({"R2-Secret-Access-Key":"must-not-be-forwarded"}),
                ..CallInput::default()
            },
        )
        .expect_err("schema-declared service credentials must remain in governed auth storage");
    assert!(matches!(
        reserved,
        CloudflareError::ReservedHeaderSelector(name) if name == "R2-Secret-Access-Key"
    ));
}

#[test]
fn request_builder_rejects_undeclared_and_schema_invalid_selectors() {
    let mut capability = CapabilityV1::new(
        "version-get",
        "Get version",
        "GET",
        "/accounts/{account_id}/versions/{version}",
    );
    capability.selectors = vec![
        SelectorV1 {
            name: "account_id".to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: Some(SelectorContractV1 {
                schema: json!({"type":"string", "minLength":1}),
                query: None,
            }),
        },
        SelectorV1 {
            name: "version".to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "integer".to_owned(),
            description: None,
            contract: Some(SelectorContractV1 {
                schema: json!({"type":"integer", "minimum":1, "maximum":10}),
                query: None,
            }),
        },
        SelectorV1 {
            name: "X-Mode".to_owned(),
            location: "header".to_owned(),
            required: false,
            value_type: "string".to_owned(),
            description: None,
            contract: Some(SelectorContractV1 {
                schema: json!({"type":"string", "enum":["safe","strict"]}),
                query: None,
            }),
        },
    ];
    let builder = RequestBuilder::new("https://api.cloudflare.com/client/v4").expect("builder");

    let undeclared = builder
        .build(
            &capability,
            &CallInput {
                selectors: json!({"account_id":"a", "version":"1", "bypass":"true"}),
                ..CallInput::default()
            },
        )
        .expect_err("undeclared selectors must not be ignored");
    assert!(matches!(
        undeclared,
        CloudflareError::UndeclaredSelector(name) if name == "bypass"
    ));

    for (name, selectors) in [
        ("version", json!({"account_id":"a", "version":"11"})),
        (
            "X-Mode",
            json!({"account_id":"a", "version":"1", "X-Mode":"unsafe"}),
        ),
    ] {
        let error = builder
            .build(
                &capability,
                &CallInput {
                    selectors,
                    ..CallInput::default()
                },
            )
            .expect_err("selector must satisfy its pinned schema");
        assert!(matches!(
            error,
            CloudflareError::InvalidSelectorSchema { name: actual, .. } if actual == name
        ));
    }
}

#[test]
fn request_builder_treats_identical_one_of_branches_as_one_pinned_alternative() {
    let mut capability = CapabilityV1::new(
        "d1-get-database",
        "Get D1 database",
        "GET",
        "/accounts/{account_id}/d1/database/{database_id}",
    );
    capability.selectors = vec![
        SelectorV1 {
            name: "account_id".to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: Some(SelectorContractV1 {
                schema: json!({"type":"string"}),
                query: None,
            }),
        },
        SelectorV1 {
            name: "database_id".to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: Some(SelectorContractV1 {
                schema: json!({"oneOf":[{"type":"string"},{"type":"string"}]}),
                query: None,
            }),
        },
    ];

    let request = RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("builder")
        .build(
            &capability,
            &CallInput {
                selectors: json!({
                    "account_id":"account-1",
                    "database_id":"7c282983-2e48-4ea4-9f0d-09b0d718fe65"
                }),
                ..CallInput::default()
            },
        )
        .expect("identical pinned alternatives represent one semantic branch");

    assert_eq!(
        request.url.path(),
        "/client/v4/accounts/account-1/d1/database/7c282983-2e48-4ea4-9f0d-09b0d718fe65"
    );
}

#[test]
fn mutating_request_requires_a_consumable_approved_plan() {
    let capability = CapabilityV1::new(
        "dns-records-delete",
        "Delete DNS record",
        "DELETE",
        "/zones/{zone_id}/dns_records/{record_id}",
    );
    let result = RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("valid base URL")
        .build(
            &capability,
            &CallInput {
                selectors: json!({"zone_id":"z","record_id":"r"}),
                query: json!({}),
                body: None,
                ..CallInput::default()
            },
        );
    assert!(result.is_err());
}

fn queue_event_batch_operations() -> (Vec<String>, CapabilityV1, CapabilityV1) {
    let permissions = vec![
        "Queues Write".to_owned(),
        "Workers Scripts Write".to_owned(),
    ];
    let mut pull = CapabilityV1::new(
        QUEUE_PULL_CAPABILITY_ID,
        "Pull Queue messages",
        "POST",
        QUEUE_PULL_PATH,
    );
    pull.mutating = true;
    pull.permissions.clone_from(&permissions);
    pull.selectors = ["account_id", "queue_id"]
        .into_iter()
        .map(|name| SelectorV1 {
            name: name.to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        })
        .collect();
    pull.request_schema = Some(json!({
        "type":"object",
        "required":["visibility_timeout_ms","batch_size"],
        "properties":{
            "visibility_timeout_ms":{"type":"integer"},
            "batch_size":{"type":"integer"}
        },
        "additionalProperties":false,
        "x-cfctl-body-required":true
    }));
    pull.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".to_owned()],
        success_media_types: vec!["application/json".to_owned()],
        body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
    });
    let mut acknowledge = CapabilityV1::new(
        QUEUE_ACK_CAPABILITY_ID,
        "Acknowledge Queue messages",
        "POST",
        QUEUE_ACK_PATH,
    );
    acknowledge.mutating = true;
    acknowledge.permissions.clone_from(&permissions);
    acknowledge.selectors.clone_from(&pull.selectors);
    acknowledge.request_schema = Some(json!({
        "type":"object",
        "required":["acks","retries"],
        "properties":{
            "acks":{"type":"array"},
            "retries":{"type":"array"}
        },
        "additionalProperties":false,
        "x-cfctl-body-required":true
    }));
    acknowledge
        .response_contract
        .clone_from(&pull.response_contract);
    (permissions, pull, acknowledge)
}

fn consumed_event_batch_plan(permissions: Vec<String>) -> PlanV1 {
    let reference = |title: &str, url: &str| KnowledgeReferenceV1 {
        title: title.to_owned(),
        url: url.to_owned(),
        source: "official Cloudflare documentation".to_owned(),
    };
    let mut capability = CapabilityV1::new(
        cfctl_core::EVENT_BATCH_CAPABILITY_ID,
        "Consume event batch",
        "POST",
        "/cfctl/events/queue-batches/{account_id}/{queue_id}/{subscription_id}",
    );
    capability.adapter_status = AdapterStatus::Native;
    capability.event_batch = Some(EventBatchContractV1 {
        pull_capability_id: QUEUE_PULL_CAPABILITY_ID.to_owned(),
        pull_path: QUEUE_PULL_PATH.to_owned(),
        acknowledge_capability_id: QUEUE_ACK_CAPABILITY_ID.to_owned(),
        acknowledge_path: QUEUE_ACK_PATH.to_owned(),
        required_permissions: permissions,
        max_batch_size: 100,
        max_visibility_timeout_ms: 43_200_000,
        max_message_bytes: 131_072,
        billing_chunk_bytes: 65_536,
        price_per_million_operations: 0.40,
        pricing_reference: reference(
            "Cloudflare Queues pricing",
            "https://developers.cloudflare.com/queues/platform/pricing/",
        ),
        schema_reference: reference(
            "Cloudflare Queues pull consumers",
            "https://developers.cloudflare.com/queues/configuration/pull-consumers/",
        ),
    });
    let input = CallInput {
        selectors: json!({
            "account_id":"account-a",
            "queue_id":"queue-a",
            "subscription_id":"subscription-a"
        }),
        body: Some(json!({"visibility_timeout_ms":60000,"batch_size":10})),
        ..CallInput::default()
    };
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "sha256:catalog",
        capability,
        json!({}),
    )
    .expect("event batch plan");
    plan.input = serde_json::to_value(&input).expect("plan input");
    plan.refresh_hash().expect("refresh plan hash");
    plan.approve(true, None).expect("approve plan");
    plan.mark_consumed().expect("consume plan");
    plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)
        .expect("persist boundary attempt");
    plan
}

#[tokio::test]
async fn event_batch_transport_executes_only_the_consumed_plan_bound_queue_operations() {
    let (address, server) = json_response_sequence_server(vec![
        r#"{"success":true,"result":{"messages":[{"id":"message-a","lease_id":"lease-a","body":"e30=","metadata":{"CF-Content-Type":"json"}}]},"errors":[]}"#,
        r#"{"success":true,"result":{},"errors":[]}"#,
    ])
    .await;
    let (permissions, pull, acknowledge) = queue_event_batch_operations();
    let plan = consumed_event_batch_plan(permissions);
    let credential = AuthCredential::Bearer {
        token: "selected-token".to_owned(),
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");
    let transport = executor
        .event_batch_transport(&plan, &pull, &acknowledge)
        .expect("exact consumed event batch transport");
    let response = transport
        .pull(&credential)
        .await
        .expect("exact Queue pull executes");
    assert!(response.success);
    let response = transport
        .acknowledge(&["lease-a".to_owned()], &credential)
        .await
        .expect("exact Queue acknowledgement executes");
    assert!(response.success);
    let requests = server.await.expect("server joins");
    assert!(
        requests[0]
            .contains("POST /client/v4/accounts/account-a/queues/queue-a/messages/pull HTTP/1.1")
    );
    assert!(requests[0].contains("authorization: Bearer selected-token"));
    assert!(requests[0].contains("\"batch_size\":10"));
    assert!(
        requests[1]
            .contains("POST /client/v4/accounts/account-a/queues/queue-a/messages/ack HTTP/1.1")
    );
    assert!(requests[1].contains("\"lease_id\":\"lease-a\""));

    let mut lookalike = pull.clone();
    lookalike.id = "queues-pull-messages-lookalike".to_owned();
    let Err(error) = executor.event_batch_transport(&plan, &lookalike, &acknowledge) else {
        panic!("lookalike identity must fail before network access");
    };
    assert!(matches!(
        error,
        CloudflareError::InvalidEventBatchPlan { .. }
    ));

    let mut permission_drift = pull;
    permission_drift.permissions = vec!["Queues Write".to_owned()];
    let Err(error) = executor.event_batch_transport(&plan, &permission_drift, &acknowledge) else {
        panic!("permission drift must fail before network access");
    };
    assert!(matches!(
        error,
        CloudflareError::InvalidEventBatchPlan { .. }
    ));
}

#[test]
fn unchecked_request_validates_required_body_shape_from_pinned_schema() {
    let mut capability = CapabilityV1::new("record-create", "Create record", "POST", "/records");
    capability.request_schema = Some(json!({
        "type": "object",
        "required": ["name"],
        "properties": {"name": {"type": "string"}, "ttl": {"type": "integer"}},
        "x-cfctl-body-required": true
    }));
    let builder = RequestBuilder::new("https://api.cloudflare.com/client/v4").expect("builder");
    assert!(
        builder
            .build_unchecked(&capability, &CallInput::default())
            .is_err()
    );
    let wrong = CallInput {
        body: Some(json!({"name": "www", "ttl": "automatic"})),
        ..CallInput::default()
    };
    assert!(builder.build_unchecked(&capability, &wrong).is_err());
    let valid = CallInput {
        body: Some(json!({"name": "www", "ttl": 300})),
        ..CallInput::default()
    };
    assert!(builder.build_unchecked(&capability, &valid).is_ok());
}

#[test]
fn websocket_zone_setting_request_is_plan_gated_and_exactly_bounded() {
    let mut capability = CapabilityV1::new(
        "zone-settings-configure-websockets",
        "Configure WebSockets support",
        "PATCH",
        "/zones/{zone_id}/settings/websockets",
    );
    capability.selectors = vec![SelectorV1 {
        name: "zone_id".to_owned(),
        location: "path".to_owned(),
        required: true,
        value_type: "string".to_owned(),
        description: None,
        contract: None,
    }];
    capability.request_schema = Some(json!({
        "additionalProperties": false,
        "properties": {
            "value": {"enum": ["on", "off"], "type": "string"}
        },
        "required": ["value"],
        "type": "object",
        "x-cfctl-body-required": true
    }));
    let builder = RequestBuilder::new("https://api.cloudflare.com/client/v4").expect("builder");
    let input = CallInput {
        selectors: json!({"zone_id": "zone-1"}),
        body: Some(json!({"value": "on"})),
        ..CallInput::default()
    };

    assert!(matches!(
        builder.build(&capability, &input),
        Err(CloudflareError::ApprovedPlanRequired(id))
            if id == "zone-settings-configure-websockets"
    ));
    let request = builder
        .build_unchecked(&capability, &input)
        .expect("approved-plan transport request");
    assert_eq!(request.method, "PATCH");
    assert_eq!(
        request.url.as_str(),
        "https://api.cloudflare.com/client/v4/zones/zone-1/settings/websockets"
    );
    assert_eq!(request.body, Some(json!({"value": "on"})));

    for body in [
        json!({"value": "auto"}),
        json!({"value": "on", "setting_id": "other"}),
    ] {
        assert!(
            builder
                .build_unchecked(
                    &capability,
                    &CallInput {
                        selectors: json!({"zone_id": "zone-1"}),
                        body: Some(body),
                        ..CallInput::default()
                    }
                )
                .is_err()
        );
    }
}

#[test]
fn unchecked_request_closes_an_explicitly_empty_property_contract() {
    let mut capability = CapabilityV1::new("server-state", "Server state", "POST", "/state");
    capability.request_schema = Some(json!({
        "type": "object",
        "properties": {}
    }));
    let error = RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("builder")
        .build_unchecked(
            &capability,
            &CallInput {
                body: Some(json!({"server_id": "must-not-be-writable"})),
                ..CallInput::default()
            },
        )
        .expect_err("an empty pinned property set must not become an open object");

    assert!(matches!(
        error,
        CloudflareError::InvalidRequestBody(reason)
            if reason.contains("outside the pinned contract")
    ));
}

#[test]
fn unchecked_request_validates_nested_required_fields_and_enums() {
    let mut capability =
        CapabilityV1::new("d1-update", "Update D1 database", "PATCH", "/database/id");
    capability.request_schema = Some(json!({
        "type": "object",
        "properties": {
            "read_replication": {
                "type": "object",
                "required": ["mode"],
                "properties": {
                    "mode": {"type": "string", "enum": ["auto", "disabled"]}
                }
            }
        }
    }));
    let builder = RequestBuilder::new("https://api.cloudflare.com/client/v4").expect("builder");

    for body in [
        json!({"read_replication": {}}),
        json!({"read_replication": {"mode": "experimental"}}),
        json!({"read_replication": {"mode": "auto", "surprise": true}}),
    ] {
        let error = builder
            .build_unchecked(
                &capability,
                &CallInput {
                    body: Some(body),
                    ..CallInput::default()
                },
            )
            .expect_err("invalid nested body must fail before network execution");
        assert!(matches!(error, CloudflareError::InvalidRequestBody(_)));
    }

    for mode in ["auto", "disabled"] {
        let input = CallInput {
            body: Some(json!({"read_replication": {"mode": mode}})),
            ..CallInput::default()
        };
        assert!(builder.build_unchecked(&capability, &input).is_ok());
    }
}

#[test]
fn unchecked_request_validates_nested_array_item_enums() {
    let mut capability = CapabilityV1::new("route-update", "Update routes", "PATCH", "/routes");
    capability.request_schema = Some(json!({
        "type": "object",
        "properties": {
            "modes": {
                "type": "array",
                "items": {"type": "string", "enum": ["active", "passive"]}
            }
        }
    }));
    let builder = RequestBuilder::new("https://api.cloudflare.com/client/v4").expect("builder");
    let invalid = CallInput {
        body: Some(json!({"modes": ["active", "experimental"]})),
        ..CallInput::default()
    };
    assert!(builder.build_unchecked(&capability, &invalid).is_err());

    let valid = CallInput {
        body: Some(json!({"modes": ["active", "passive"]})),
        ..CallInput::default()
    };
    assert!(builder.build_unchecked(&capability, &valid).is_ok());
}

#[test]
fn unchecked_request_enforces_scalar_and_collection_bounds() {
    let mut capability = CapabilityV1::new("bounded-create", "Create", "POST", "/bounded");
    capability.request_schema = Some(json!({
        "type": "object",
        "minProperties": 5,
        "maxProperties": 5,
        "required": ["count", "ratio", "name", "items", "labels"],
        "properties": {
            "count": {"type": "integer", "minimum": 1, "maximum": 10},
            "ratio": {
                "type": "number",
                "minimum": 0,
                "exclusiveMinimum": true,
                "maximum": 1,
                "exclusiveMaximum": true
            },
            "name": {"type": "string", "minLength": 2, "maxLength": 4},
            "items": {
                "type": "array",
                "minItems": 1,
                "maxItems": 2,
                "uniqueItems": true,
                "items": {"type": "string"}
            },
            "labels": {
                "type": "object",
                "minProperties": 1,
                "maxProperties": 2,
                "additionalProperties": {"type": "string"}
            }
        }
    }));
    let builder = RequestBuilder::new("https://api.cloudflare.com/client/v4").expect("builder");
    let valid = CallInput {
        body: Some(json!({
            "count": 1,
            "ratio": 0.5,
            "name": "éß",
            "items": ["a", "b"],
            "labels": {"environment": "test"}
        })),
        ..CallInput::default()
    };
    assert!(builder.build_unchecked(&capability, &valid).is_ok());

    for body in [
        json!({"count": 0, "ratio": 0.5, "name": "ok", "items": ["a"], "labels": {"a":"b"}}),
        json!({"count": 11, "ratio": 0.5, "name": "ok", "items": ["a"], "labels": {"a":"b"}}),
        json!({"count": 1, "ratio": 0, "name": "ok", "items": ["a"], "labels": {"a":"b"}}),
        json!({"count": 1, "ratio": 1, "name": "ok", "items": ["a"], "labels": {"a":"b"}}),
        json!({"count": 1, "ratio": 0.5, "name": "x", "items": ["a"], "labels": {"a":"b"}}),
        json!({"count": 1, "ratio": 0.5, "name": "abcde", "items": ["a"], "labels": {"a":"b"}}),
        json!({"count": 1, "ratio": 0.5, "name": "ok", "items": [], "labels": {"a":"b"}}),
        json!({"count": 1, "ratio": 0.5, "name": "ok", "items": ["a", "b", "c"], "labels": {"a":"b"}}),
        json!({"count": 1, "ratio": 0.5, "name": "ok", "items": ["a", "a"], "labels": {"a":"b"}}),
        json!({"count": 1, "ratio": 0.5, "name": "ok", "items": ["a"], "labels": {}}),
        json!({"count": 1, "ratio": 0.5, "name": "ok", "items": ["a"], "labels": {"a":"b", "c":"d", "e":"f"}}),
        json!({"count": 1, "ratio": 0.5, "name": "ok", "items": ["a"], "labels": {"a":"b"}, "extra": true}),
    ] {
        let error = builder
            .build_unchecked(
                &capability,
                &CallInput {
                    body: Some(body),
                    ..CallInput::default()
                },
            )
            .expect_err("out-of-contract bounds must fail before request construction");
        assert!(matches!(error, CloudflareError::InvalidRequestBody(_)));
    }
}

#[test]
fn unchecked_request_enforces_exact_decimal_multiples() {
    let mut capability = CapabilityV1::new("multiple-create", "Create", "POST", "/multiple");
    capability.request_schema = Some(json!({
        "type": "object",
        "required": ["tenths", "cents", "whole"],
        "properties": {
            "tenths": {"type": "number", "multipleOf": 0.1},
            "cents": {"type": "number", "multipleOf": 0.01},
            "whole": {"type": "number", "multipleOf": 1}
        }
    }));
    let builder = RequestBuilder::new("https://api.cloudflare.com/client/v4").expect("builder");
    for body in [
        json!({"tenths": 0.3, "cents": 1.23, "whole": 3}),
        json!({"tenths": -1.2, "cents": 0, "whole": -4.0}),
        json!({"tenths": 1e20, "cents": 1e-2, "whole": 1e3}),
    ] {
        assert!(
            builder
                .build_unchecked(
                    &capability,
                    &CallInput {
                        body: Some(body),
                        ..CallInput::default()
                    }
                )
                .is_ok()
        );
    }

    for (field, value) in [
        ("tenths", json!(0.300_000_000_000_000_04)),
        ("cents", json!(1.234)),
        ("whole", json!(3.1)),
    ] {
        let mut body = json!({"tenths": 0.3, "cents": 1.23, "whole": 3});
        body[field] = value;
        let error = builder
            .build_unchecked(
                &capability,
                &CallInput {
                    body: Some(body),
                    ..CallInput::default()
                },
            )
            .expect_err("non-multiples must fail before request construction");
        assert!(matches!(
            error,
            CloudflareError::InvalidRequestBody(reason)
                if reason.contains("multipleOf") && !reason.contains("0.30000000000000004")
        ));
    }
}

#[test]
fn unchecked_request_rejects_invalid_multiple_contracts() {
    let builder = RequestBuilder::new("https://api.cloudflare.com/client/v4").expect("builder");
    for invalid_multiple in [json!(0), json!(-0.1), json!("0.1")] {
        let mut capability = CapabilityV1::new("multiple-create", "Create", "POST", "/multiple");
        capability.request_schema = Some(json!({
            "type": "number",
            "multipleOf": invalid_multiple
        }));
        let error = builder
            .build_unchecked(
                &capability,
                &CallInput {
                    body: Some(json!(1)),
                    ..CallInput::default()
                },
            )
            .expect_err("invalid multipleOf contracts must fail closed");
        assert!(matches!(error, CloudflareError::InvalidRequestBody(_)));
    }
}

#[test]
fn unchecked_request_enforces_executable_string_formats() {
    let mut capability = CapabilityV1::new("formatted-create", "Create", "POST", "/formatted");
    capability.request_schema = Some(json!({
        "type": "object",
        "required": ["timestamp", "hostname", "ipv4", "ipv6", "cloudflare_uuid"],
        "properties": {
            "timestamp": {"type": "string", "format": "date-time"},
            "hostname": {"type": "string", "format": "hostname"},
            "ipv4": {"type": "string", "format": "ipv4"},
            "ipv6": {"type": "string", "format": "ipv6"},
            "cloudflare_uuid": {"type": "string", "format": "cloudflare-uuid"}
        }
    }));
    let builder = RequestBuilder::new("https://api.cloudflare.com/client/v4").expect("builder");
    let valid = CallInput {
        body: Some(json!({
            "timestamp": "2026-07-15T03:45:00-05:00",
            "hostname": "service.example.com.",
            "ipv4": "192.0.2.1",
            "ipv6": "2001:db8::1",
            "cloudflare_uuid": "699d98642c564d2e855e9661899b7252"
        })),
        ..CallInput::default()
    };
    assert!(builder.build_unchecked(&capability, &valid).is_ok());
    let mut root_hostname = valid.clone();
    root_hostname.body.as_mut().expect("valid body")["hostname"] = json!(".");
    assert!(builder.build_unchecked(&capability, &root_hostname).is_ok());
    let mut canonical_uuid = valid.clone();
    canonical_uuid.body.as_mut().expect("valid body")["cloudflare_uuid"] =
        json!("7b0bc477-5d42-4dab-b0ea-c97d0aef7810");
    assert!(
        builder
            .build_unchecked(&capability, &canonical_uuid)
            .is_ok()
    );

    for (field, value) in [
        ("timestamp", "2026-07-15 03:45:00"),
        ("hostname", "_invalid.example.com"),
        ("ipv4", "999.0.2.1"),
        ("ipv6", "2001:db8::1::1"),
        ("cloudflare_uuid", "7b0bc4775-d42-4dab-b0ea-c97d0aef7810"),
    ] {
        let mut body = valid.body.clone().expect("valid body");
        body[field] = json!(value);
        let error = builder
            .build_unchecked(
                &capability,
                &CallInput {
                    body: Some(body),
                    ..CallInput::default()
                },
            )
            .expect_err("invalid executable formats must fail before request construction");
        assert!(matches!(
            error,
            CloudflareError::InvalidRequestBody(reason)
                if reason.contains("pinned") && !reason.contains(value)
        ));
    }
}

#[test]
fn unchecked_request_enforces_bounded_ascii_email_format() {
    let mut capability = CapabilityV1::new("email-create", "Create", "POST", "/email");
    capability.request_schema = Some(json!({
        "type":"object",
        "required":["email"],
        "properties":{"email":{"type":"string","format":"email"}}
    }));
    let builder = RequestBuilder::new("https://api.cloudflare.com/client/v4").expect("builder");
    for email in ["person@example.com", "o'connor+founder@sub.example.com"] {
        assert!(
            builder
                .build_unchecked(
                    &capability,
                    &CallInput {
                        body: Some(json!({"email":email})),
                        ..CallInput::default()
                    }
                )
                .is_ok(),
            "ordinary ASCII mailbox was rejected: {email}"
        );
    }
    let local = "a".repeat(64);
    let domain = |last_label_length| {
        format!(
            "{}.{}.{}",
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(last_label_length)
        )
    };
    let at_limit = format!("{local}@{}", domain(61));
    let over_limit = format!("{local}@{}", domain(62));
    assert_eq!(at_limit.len(), 254);
    assert_eq!(over_limit.len(), 255);
    assert!(
        builder
            .build_unchecked(
                &capability,
                &CallInput {
                    body: Some(json!({"email":at_limit})),
                    ..CallInput::default()
                }
            )
            .is_ok(),
        "a valid 254-byte mailbox must remain inside the pinned schema"
    );
    assert!(
        builder
            .build_unchecked(
                &capability,
                &CallInput {
                    body: Some(json!({"email":over_limit})),
                    ..CallInput::default()
                }
            )
            .is_err(),
        "a valid-shape 255-byte mailbox must exceed the pinned schema"
    );

    let oversized_local = format!("{}@example.com", "a".repeat(65));
    for email in [
        oversized_local.as_str(),
        "pérson@example.com",
        "person.example.com",
        "person@@example.com",
        "@example.com",
        "person@",
        ".person@example.com",
        "person.@example.com",
        "person..tag@example.com",
        "person tag@example.com",
        "person@example..com",
        "person@-example.com",
        "person@example.com.",
        "person@.",
    ] {
        let error = builder
            .build_unchecked(
                &capability,
                &CallInput {
                    body: Some(json!({"email":email})),
                    ..CallInput::default()
                },
            )
            .expect_err("malformed email must fail before request construction");
        assert!(matches!(
            error,
            CloudflareError::InvalidRequestBody(reason)
                if reason.contains("pinned email format") && !reason.contains(email)
        ));
    }
}

#[test]
fn unchecked_request_treats_equivalent_json_numbers_as_duplicate_items() {
    let mut capability = CapabilityV1::new("unique-create", "Create", "POST", "/unique");
    capability.request_schema = Some(json!({
        "type": "array",
        "uniqueItems": true
    }));
    let error = RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("builder")
        .build_unchecked(
            &capability,
            &CallInput {
                body: Some(json!([1, 1.0])),
                ..CallInput::default()
            },
        )
        .expect_err("mathematically equal JSON numbers are duplicate items");
    assert!(matches!(error, CloudflareError::InvalidRequestBody(_)));
}

#[test]
fn unchecked_request_bounds_unique_item_fingerprint_depth() {
    let mut capability = CapabilityV1::new("unique-create", "Create", "POST", "/unique");
    capability.request_schema = Some(json!({
        "type": "array",
        "uniqueItems": true
    }));
    let mut nested = json!(null);
    for _ in 0..65 {
        nested = json!([nested]);
    }
    let result = RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("builder")
        .build_unchecked(
            &capability,
            &CallInput {
                body: Some(json!([nested])),
                ..CallInput::default()
            },
        );
    let Err(error) = result else {
        panic!("uniqueItems fingerprinting must honor the schema depth ceiling");
    };
    assert!(matches!(
        error,
        CloudflareError::InvalidRequestBody(reason)
            if reason == "pinned schema exceeds the validation depth limit"
    ));
}

#[test]
fn unchecked_request_bounds_unique_item_fingerprint_work() {
    let mut capability = CapabilityV1::new("unique-create", "Create", "POST", "/unique");
    capability.request_schema = Some(json!({
        "type": "array",
        "uniqueItems": true
    }));
    let nested = Value::Array((0..65_535).map(|_| json!("item")).collect());
    let result = RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("builder")
        .build_unchecked(
            &capability,
            &CallInput {
                body: Some(json!([nested])),
                ..CallInput::default()
            },
        );
    let Err(error) = result else {
        panic!("uniqueItems fingerprinting must honor the validation work limit");
    };
    assert!(matches!(
        error,
        CloudflareError::InvalidRequestBody(reason)
            if reason == "request body exceeds the pinned validation work limit"
    ));
}

#[test]
fn unchecked_request_enforces_composed_request_schemas() {
    let capability = composed_request_capability();
    let builder = RequestBuilder::new("https://api.cloudflare.com/client/v4").expect("builder");

    for resources in [
        json!({"com.cloudflare.api.account.a": "*"}),
        json!({"com.cloudflare.api.account.a": {"com.cloudflare.api.zone.z": "*"}}),
    ] {
        let input = CallInput {
            selectors: json!({"account_id": "a"}),
            body: Some(json!({
                "resources": resources,
                "settings": {"mode": "on", "enabled": true},
                "signal": "automatic",
                "placement": {"scope": "account", "before": "rule-a"}
            })),
            ..CallInput::default()
        };
        assert!(builder.build_unchecked(&capability, &input).is_ok());
    }

    assert_invalid_composed_bodies(&builder, &capability);
}

fn composed_request_capability() -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        "token-create",
        "Create token",
        "POST",
        "/accounts/{account_id}/tokens",
    );
    capability.request_schema = Some(json!({
        "type": "object",
        "required": ["resources", "settings"],
        "properties": {
            "resources": {
                "oneOf": [
                    {"type": "object", "additionalProperties": {"type": "string"}},
                    {
                        "type": "object",
                        "additionalProperties": {
                            "type": "object",
                            "additionalProperties": {"type": "string"}
                        }
                    }
                ]
            },
            "settings": {
                "allOf": [
                    {
                        "type": "object",
                        "required": ["mode"],
                        "properties": {"mode": {"type": "string", "enum": ["on", "off"]}}
                    },
                    {
                        "type": "object",
                        "required": ["enabled"],
                        "properties": {"enabled": {"type": "boolean"}}
                    }
                ]
            },
            "signal": {
                "anyOf": [
                    {"type": "string", "enum": ["automatic"]},
                    {"type": "integer"}
                ]
            },
            "placement": {
                "type": "object",
                "required": ["scope"],
                "properties": {"scope": {"type": "string"}},
                "oneOf": [
                    {
                        "type": "object",
                        "required": ["before"],
                        "properties": {"before": {"type": "string"}}
                    },
                    {
                        "type": "object",
                        "required": ["after"],
                        "properties": {"after": {"type": "string"}}
                    }
                ]
            }
        }
    }));
    capability
}

fn assert_invalid_composed_bodies(builder: &RequestBuilder, capability: &CapabilityV1) {
    for body in [
        json!({
            "resources": {},
            "settings": {"mode": "on", "enabled": true}
        }),
        json!({
            "resources": {"com.cloudflare.api.account.a": 7},
            "settings": {"mode": "on", "enabled": true}
        }),
        json!({
            "resources": {"com.cloudflare.api.account.a": "*"},
            "settings": {"mode": "on"}
        }),
        json!({
            "resources": {"com.cloudflare.api.account.a": "*"},
            "settings": {"mode": "on", "enabled": true, "surprise": true}
        }),
        json!({
            "resources": {"com.cloudflare.api.account.a": "*"},
            "settings": {"mode": "on", "enabled": true},
            "signal": false
        }),
        json!({
            "resources": {"com.cloudflare.api.account.a": "*"},
            "settings": {"mode": "on", "enabled": true},
            "placement": {
                "scope": "account",
                "before": "rule-a",
                "after": "rule-b"
            }
        }),
        json!({
            "resources": {"com.cloudflare.api.account.a": "*"},
            "settings": {"mode": "on", "enabled": true},
            "placement": {"scope": "account", "before": "rule-a", "unknown": true}
        }),
    ] {
        let error = builder
            .build_unchecked(
                capability,
                &CallInput {
                    selectors: json!({"account_id": "a"}),
                    body: Some(body),
                    ..CallInput::default()
                },
            )
            .expect_err("invalid composed body must fail before network execution");
        assert!(matches!(error, CloudflareError::InvalidRequestBody(_)));
    }
}

#[test]
fn unchecked_request_honors_explicit_additional_property_denial_in_all_of() {
    let mut capability = CapabilityV1::new("strict-create", "Create", "POST", "/strict");
    capability.request_schema = Some(json!({
        "allOf": [
            {
                "type": "object",
                "properties": {"known": {"type": "string"}},
                "additionalProperties": false
            },
            {
                "type": "object",
                "properties": {"sibling": {"type": "string"}}
            }
        ]
    }));
    let error = RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("builder")
        .build_unchecked(
            &capability,
            &CallInput {
                body: Some(json!({"known": "yes", "sibling": "still disallowed"})),
                ..CallInput::default()
            },
        )
        .expect_err("explicit additionalProperties false must override inferred sibling fields");
    assert!(matches!(error, CloudflareError::InvalidRequestBody(_)));
}

#[test]
fn unchecked_request_bounds_schema_validation_work() {
    let mut capability = CapabilityV1::new("bulk-create", "Create", "POST", "/bulk");
    capability.request_schema = Some(json!({
        "type": "array",
        "items": {"type": "string"}
    }));
    let error = RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("builder")
        .build_unchecked(
            &capability,
            &CallInput {
                body: Some(Value::Array((0..65_536).map(|_| json!("item")).collect())),
                ..CallInput::default()
            },
        )
        .expect_err("unbounded request validation must fail closed");
    assert!(matches!(
        error,
        CloudflareError::InvalidRequestBody(reason)
            if reason == "request body exceeds the pinned validation work limit"
    ));
}

#[test]
fn unchecked_request_never_treats_one_of_budget_exhaustion_as_a_mismatch() {
    let mut capability = CapabilityV1::new("ambiguous-create", "Create", "POST", "/ambiguous");
    capability.request_schema = Some(json!({
        "oneOf": [
            {"type": "array", "items": {"type": "string"}},
            {"type": "array", "items": {"type": "string"}}
        ]
    }));
    let result = RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("builder")
        .build_unchecked(
            &capability,
            &CallInput {
                body: Some(Value::Array((0..65_533).map(|_| json!("item")).collect())),
                ..CallInput::default()
            },
        );
    let Err(error) = result else {
        panic!("an unevaluated oneOf branch must never authorize a request");
    };
    assert!(matches!(
        error,
        CloudflareError::InvalidRequestBody(reason)
            if reason == "request body exceeds the pinned validation work limit"
    ));
}

#[tokio::test]
async fn executor_retries_rate_limits_and_applies_only_the_selected_credential() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let mut requests = Vec::new();
        for attempt in 0..2 {
            let (mut stream, _) = listener.accept().await.expect("accept request");
            let mut buffer = vec![0_u8; 8192];
            let read = stream.read(&mut buffer).await.expect("read request");
            requests.push(String::from_utf8_lossy(&buffer[..read]).to_string());
            let (status, body) = if attempt == 0 {
                (
                    "429 Too Many Requests",
                    r#"{"success":false,"errors":[{"code":10000,"message":"retry"}]}"#,
                )
            } else {
                (
                    "200 OK",
                    r#"{"success":true,"result":[{"id":"zone-1"}],"errors":[]}"#,
                )
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nRetry-After: 0\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write response");
        }
        requests
    });
    let capability = CapabilityV1::new("zones-list", "List zones", "GET", "/zones");
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");
    let response = executor
        .execute_read(
            &capability,
            &CallInput::default(),
            &AuthCredential::Bearer {
                token: "selected-token".to_owned(),
            },
        )
        .await
        .expect("eventual response");
    assert!(response.success);
    let requests = server.await.expect("fake server joins");
    assert_eq!(requests.len(), 2);
    assert!(
        requests
            .iter()
            .all(|request| request.contains("authorization: Bearer selected-token"))
    );
    assert!(
        requests
            .iter()
            .all(|request| !request.contains("x-auth-key"))
    );
}

#[tokio::test]
async fn executor_enforces_pinned_json_response_contract_without_echoing_bodies() {
    let mut capability = CapabilityV1::new("zones-list", "List zones", "GET", "/zones");
    capability.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".to_owned()],
        success_media_types: vec!["application/json".to_owned()],
        body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
    });
    let credential = AuthCredential::Bearer {
        token: "selected-token".to_owned(),
    };

    let (address, server) = single_raw_response_server(
        "200 OK",
        "text/plain",
        r#"{"success":true,"result":{"private":"media-marker"}}"#,
    )
    .await;
    let error = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .execute_read(&capability, &CallInput::default(), &credential)
    .await
    .expect_err("unexpected success media must fail closed");
    assert!(matches!(
        error,
        CloudflareError::UnexpectedResponseMediaType { status: 200, .. }
    ));
    assert!(!error.to_string().contains("media-marker"));
    server.await.expect("server joins");

    let (address, server) = single_raw_response_server(
        "200 OK",
        "application/json; charset=utf-8",
        r#"{"result":{"private":"envelope-marker"}}"#,
    )
    .await;
    let error = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .execute_read(&capability, &CallInput::default(), &credential)
    .await
    .expect_err("a JSON object without the pinned envelope must fail closed");
    assert!(matches!(
        error,
        CloudflareError::InvalidResponseEnvelope { status: 200 }
    ));
    assert!(!error.to_string().contains("envelope-marker"));
    server.await.expect("server joins");

    let (address, server) = single_raw_response_server(
        "200 OK",
        "application/json; charset=utf-8",
        r#"{"success":true,"result":[{"id":"zone-1"}],"errors":[]}"#,
    )
    .await;
    let response = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .execute_read(&capability, &CallInput::default(), &credential)
    .await
    .expect("the pinned JSON envelope should be accepted");
    assert!(response.success);
    server.await.expect("server joins");
}

#[tokio::test]
async fn executor_parses_realtimekit_data_envelopes_without_losing_resource_identity() {
    let mut capability = CapabilityV1::new(
        "getWebhook",
        "Fetch details of a webhook",
        "GET",
        "/accounts/account-a/realtime/kit/app-a/webhooks/webhook-a",
    );
    capability.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".to_owned()],
        success_media_types: vec!["application/json".to_owned()],
        body_mode: ResponseBodyModeV1::CloudflareDataEnvelope,
    });
    let (address, server) = single_raw_response_server(
        "200 OK",
        "application/json",
        r#"{"success":true,"data":{"id":"webhook-a","enabled":true}}"#,
    )
    .await;
    let response = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .execute_read(
        &capability,
        &CallInput::default(),
        &AuthCredential::Bearer {
            token: "selected-token".to_owned(),
        },
    )
    .await
    .expect("data envelope is supported");
    assert!(response.success);
    assert_eq!(response.result["id"], "webhook-a");
    assert_eq!(response.result["enabled"], true);
    server.await.expect("server joins");
}

#[tokio::test]
async fn executor_enforces_pinned_empty_responses_and_success_statuses() {
    let mut capability = CapabilityV1::new("empty-read", "Empty read", "GET", "/empty");
    capability.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".to_owned()],
        success_media_types: Vec::new(),
        body_mode: ResponseBodyModeV1::Empty,
    });
    let credential = AuthCredential::Bearer {
        token: "selected-token".to_owned(),
    };

    let (address, server) = single_raw_response_server("200 OK", "text/plain", "").await;
    let response = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .execute_read(&capability, &CallInput::default(), &credential)
    .await
    .expect("the pinned empty response should be accepted");
    assert!(response.success);
    assert_eq!(response.status, 200);
    assert_eq!(response.result, Value::Null);
    server.await.expect("server joins");

    let mut status_class_capability = capability.clone();
    status_class_capability
        .response_contract
        .as_mut()
        .expect("response contract")
        .success_statuses = vec!["2XX".to_owned()];
    let (address, server) = single_raw_response_server("202 Accepted", "text/plain", "").await;
    let response = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .execute_read(&status_class_capability, &CallInput::default(), &credential)
    .await
    .expect("the pinned OpenAPI status class should be accepted");
    assert_eq!(response.status, 202);
    server.await.expect("server joins");

    let (address, server) =
        single_raw_response_server("200 OK", "text/plain", "private-body-marker").await;
    let error = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .execute_read(&capability, &CallInput::default(), &credential)
    .await
    .expect_err("a body must violate the pinned empty response");
    assert!(matches!(
        error,
        CloudflareError::UnexpectedResponseBody {
            status: 200,
            received_bytes: 19
        }
    ));
    assert!(!error.to_string().contains("private-body-marker"));
    server.await.expect("server joins");

    let (address, server) = single_raw_response_server("201 Created", "text/plain", "").await;
    let error = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .execute_read(&capability, &CallInput::default(), &credential)
    .await
    .expect_err("an undeclared success status must fail closed");
    assert!(matches!(
        error,
        CloudflareError::UnexpectedSuccessStatus { status: 201, .. }
    ));
    server.await.expect("server joins");
}

fn bounded_analytics_contract(kind: AnalyticsQueryKindV1) -> AnalyticsQueryContractV1 {
    AnalyticsQueryContractV1 {
        kind,
        dataset: None,
        dataset_pointer: Some("/dataset".to_owned()),
        time_range: Some(TimeRangeContractV1 {
            start_pointer: "/start".to_owned(),
            end_pointer: "/end".to_owned(),
            timestamp_format: TimestampFormatV1::Rfc3339,
            max_lookback_seconds: 86_400,
            max_window_seconds: 3_600,
        }),
        row_limit_pointer: Some("/limit".to_owned()),
        max_rows: 3,
        max_bytes: 1_024,
        max_timeout_seconds: 30,
        allowed_output_formats: vec![
            OutputFormatV1::Json,
            OutputFormatV1::Ndjson,
            OutputFormatV1::Csv,
        ],
        default_output_format: OutputFormatV1::Ndjson,
        pagination: PaginationModeV1::BoundedResult,
        read_only: true,
        freshness: Some("upstream reported".to_owned()),
        sampling: Some("upstream reported".to_owned()),
    }
}

fn bounded_query_body(format: &str, limit: u64) -> Value {
    let end = Utc::now();
    let start = end - Duration::minutes(10);
    json!({
        "dataset":"worker_events",
        "start":start.to_rfc3339_opts(SecondsFormat::Secs, true),
        "end":end.to_rfc3339_opts(SecondsFormat::Secs, true),
        "columns":["blob1"],
        "aggregates":[{"function":"count","alias":"rows"}],
        "filters":[],
        "group_by":["blob1"],
        "order_by":[{"field":"blob1","direction":"asc"}],
        "limit":limit,
        "format":format,
        "timeout_seconds":10
    })
}

fn structured_sql_capability() -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        "analytics-engine-sql-query-get",
        "Run bounded Analytics Engine SQL",
        "GET",
        "/accounts/{account_id}/analytics_engine/sql",
    );
    capability.analytics_query = Some(bounded_analytics_contract(
        AnalyticsQueryKindV1::StructuredSql,
    ));
    capability.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".to_owned()],
        success_media_types: vec![
            "application/json".to_owned(),
            "application/x-ndjson".to_owned(),
            "text/csv".to_owned(),
        ],
        body_mode: ResponseBodyModeV1::NegotiatedRows,
    });
    capability.selectors = vec![SelectorV1 {
        name: "account_id".to_owned(),
        location: "path".to_owned(),
        required: true,
        value_type: "string".to_owned(),
        description: None,
        contract: None,
    }];
    capability.request_schema = Some(json!({
        "type":"object",
        "additionalProperties":false,
        "required":["dataset","start","end","columns","limit","format","timeout_seconds"],
        "properties":{
            "dataset":{"type":"string","pattern":"^[A-Za-z_][A-Za-z0-9_]{0,63}$"},
            "start":{"type":"string","format":"date-time"},
            "end":{"type":"string","format":"date-time"},
            "columns":{"type":"array","minItems":1,"maxItems":20,"items":{"type":"string"}},
            "aggregates":{"type":"array"},
            "filters":{"type":"array"},
            "group_by":{"type":"array"},
            "order_by":{"type":"array"},
            "limit":{"type":"integer","minimum":1,"maximum":3},
            "format":{"type":"string","enum":["json","ndjson","csv"]},
            "timeout_seconds":{"type":"integer","minimum":1,"maximum":30}
        },
        "x-cfctl-body-required":true
    }));
    capability
}

fn r2_log_retrieval_capability(max_bytes: u64) -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        "logpull-retrieve-logs",
        "Retrieve logs",
        "GET",
        "/accounts/{account_id}/logs/retrieve",
    );
    "Logpull".clone_into(&mut capability.product);
    capability.permissions = vec!["Logs Read".to_owned()];
    capability.selectors = vec![
        SelectorV1 {
            name: "account_id".to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        },
        SelectorV1 {
            name: "start".to_owned(),
            location: "query".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        },
        SelectorV1 {
            name: "end".to_owned(),
            location: "query".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        },
        SelectorV1 {
            name: "bucket".to_owned(),
            location: "query".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        },
        SelectorV1 {
            name: "prefix".to_owned(),
            location: "query".to_owned(),
            required: false,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        },
    ];
    capability.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".to_owned()],
        success_media_types: vec!["application/json".to_owned()],
        body_mode: ResponseBodyModeV1::JsonValue,
    });
    capability.r2_log_retrieval = Some(R2LogRetrievalContractV1 {
        access_key_input_field: "access_key_id".to_owned(),
        secret_access_key_input_field: "secret_access_key".to_owned(),
        access_key_header: "R2-Access-Key-Id".to_owned(),
        secret_access_key_header: "R2-Secret-Access-Key".to_owned(),
        start_query_selector: "start".to_owned(),
        end_query_selector: "end".to_owned(),
        bucket_query_selector: "bucket".to_owned(),
        prefix_query_selector: "prefix".to_owned(),
        max_lookback_seconds: 10 * 365 * 24 * 60 * 60,
        max_window_seconds: 3_600,
        max_bytes,
        max_timeout_seconds: 120,
        output_media_types: vec!["application/json".to_owned()],
        requires_new_mode_0600_file: true,
    });
    capability
}

fn r2_log_retrieval_input() -> CallInput {
    let end = Utc::now();
    let start = end - Duration::minutes(5);
    CallInput {
        selectors: json!({"account_id":"account-1"}),
        query: json!({
            "start":start.to_rfc3339_opts(SecondsFormat::Secs, true),
            "end":end.to_rfc3339_opts(SecondsFormat::Secs, true),
            "bucket":"cloudflare-logs",
            "prefix":"http_requests/example.com/{DATE}"
        }),
        ..CallInput::default()
    }
}

fn log_explorer_capability() -> CapabilityV1 {
    let mut capability = structured_sql_capability();
    "zones-logs-explorer-query-post".clone_into(&mut capability.id);
    "POST".clone_into(&mut capability.method);
    "/zones/{zone_id}/logs/explorer/query/sql".clone_into(&mut capability.path);
    "zone_id".clone_into(&mut capability.selectors[0].name);
    let query = capability
        .analytics_query
        .as_mut()
        .expect("analytics contract");
    query.kind = AnalyticsQueryKindV1::LogExplorerSql;
    query.allowed_output_formats = vec![OutputFormatV1::Json];
    query.default_output_format = OutputFormatV1::Json;
    capability.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".to_owned()],
        success_media_types: vec!["application/json".to_owned()],
        body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
    });
    let schema = capability
        .request_schema
        .as_mut()
        .and_then(Value::as_object_mut)
        .expect("request schema");
    schema
        .get_mut("required")
        .and_then(Value::as_array_mut)
        .expect("required")
        .retain(|field| field.as_str() != Some("format"));
    schema
        .get_mut("required")
        .and_then(Value::as_array_mut)
        .expect("required")
        .push(json!("timestamp_field"));
    let properties = schema
        .get_mut("properties")
        .and_then(Value::as_object_mut)
        .expect("properties");
    properties.remove("format");
    properties.insert(
        "timestamp_field".to_owned(),
        json!({"type":"string","pattern":"^[A-Za-z_][A-Za-z0-9_]{0,63}$"}),
    );
    capability
}

fn bounded_log_explorer_body(limit: u64) -> Value {
    let mut body = bounded_query_body("json", limit);
    body.as_object_mut().expect("body object").remove("format");
    body["timestamp_field"] = json!("EdgeStartTimestamp");
    body
}

#[test]
fn request_builder_renders_only_structured_read_only_analytics_sql() {
    let capability = structured_sql_capability();
    let request = RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("builder")
        .build(
            &capability,
            &CallInput {
                selectors: json!({"account_id":"account-1"}),
                body: Some(bounded_query_body("ndjson", 3)),
                ..CallInput::default()
            },
        )
        .expect("structured query should render");
    let sql = request
        .url
        .query_pairs()
        .find_map(|(name, value)| (name == "query").then_some(value.into_owned()))
        .expect("rendered SQL query");
    assert!(sql.starts_with("SELECT "));
    assert!(sql.contains("FROM worker_events"));
    assert!(sql.contains("timestamp >= toDateTime64("));
    assert!(sql.ends_with("LIMIT 3 FORMAT JSONEachRow"));
    assert!(!sql.contains(';'));
    assert!(
        request.body.is_none(),
        "typed input must not be sent as a GET body"
    );
    assert_eq!(
        request
            .headers
            .get("accept")
            .and_then(|value| value.to_str().ok()),
        Some("application/x-ndjson")
    );

    let mut invalid = bounded_query_body("ndjson", 3);
    invalid["dataset"] = json!("events; DROP TABLE events");
    let error = RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("builder")
        .build(
            &capability,
            &CallInput {
                selectors: json!({"account_id":"account-1"}),
                body: Some(invalid),
                ..CallInput::default()
            },
        )
        .expect_err("untyped SQL fragments must fail closed");
    assert!(matches!(error, CloudflareError::InvalidAnalyticsQuery(_)));
}

#[tokio::test]
async fn log_explorer_uses_only_compiler_rendered_text_sql_and_bounds_enveloped_rows() {
    let capability = log_explorer_capability();
    let input = CallInput {
        selectors: json!({"zone_id":"zone-1"}),
        body: Some(bounded_log_explorer_body(2)),
        ..CallInput::default()
    };
    let request = RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("builder")
        .build(&capability, &input)
        .expect("typed Log Explorer query");
    let sql = request.text_body.as_deref().expect("compiled text body");
    assert!(sql.starts_with("SELECT "));
    assert!(sql.contains("FROM worker_events"));
    assert!(sql.contains("EdgeStartTimestamp >= '"));
    assert!(sql.ends_with("LIMIT 2"));
    assert!(!sql.contains(';'));
    assert!(request.url.query().is_none());
    assert!(request.body.is_none());
    assert_eq!(
        request
            .headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("text/plain")
    );

    let (address, server) = json_response_sequence_server(vec![
        r#"{"success":true,"errors":[],"messages":[],"result":[{"row":1},{"row":2},{"row":3}]}"#,
    ])
    .await;
    let response = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .execute_read(
        &capability,
        &input,
        &AuthCredential::Bearer {
            token: "selected-token".to_owned(),
        },
    )
    .await
    .expect("bounded Log Explorer response");
    assert_eq!(response.result.as_array().map(Vec::len), Some(2));
    assert_eq!(
        response
            .result_info
            .as_ref()
            .and_then(|value| value.pointer("/output/truncated")),
        Some(&json!(true))
    );
    let requests = server.await.expect("server joins");
    assert!(
        requests[0]
            .to_ascii_lowercase()
            .contains("content-type: text/plain")
    );
    assert!(requests[0].contains("SELECT "));
}

fn graphql_http_capability() -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        "graphql-analytics-zone-http-requests",
        "Query zone HTTP analytics",
        "POST",
        "/graphql",
    );
    capability.mutating = false;
    let mut query = bounded_analytics_contract(AnalyticsQueryKindV1::GraphqlAnalytics);
    query.dataset = Some("httpRequestsAdaptiveGroups".to_owned());
    query.allowed_output_formats = vec![OutputFormatV1::Json];
    query.default_output_format = OutputFormatV1::Json;
    capability.analytics_query = Some(query);
    let mut graphql = GraphqlAnalyticsContractV1 {
        operation_name: "CfctlZoneHttp".to_owned(),
        document: "query CfctlZoneHttp($zoneTag: string, $start: Time, $end: Time, $limit: Int) { viewer { zones(filter: {zoneTag: $zoneTag}) { series: httpRequestsAdaptiveGroups(filter: {datetime_geq: $start, datetime_lt: $end}, limit: $limit, orderBy: [datetimeHour_ASC]) { count } } } }".to_owned(),
        dataset: "httpRequestsAdaptiveGroups".to_owned(),
        selector_variables: [("zone_id".to_owned(), "zoneTag".to_owned())]
            .into_iter()
            .collect(),
        body_variables: [
            ("start".to_owned(), "start".to_owned()),
            ("end".to_owned(), "end".to_owned()),
            ("limit".to_owned(), "limit".to_owned()),
        ]
        .into_iter()
        .collect(),
        response_data_pointer: "/viewer/zones/0/series".to_owned(),
        expected_row_fields: vec!["count".to_owned()],
        cursor_fields: Vec::new(),
        cursor_input_pointer: None,
        cursor_input_pointers: std::collections::BTreeMap::new(),
        schema_fingerprint: String::new(),
    };
    graphql.refresh_schema_fingerprint().expect("fingerprint");
    capability.graphql = Some(graphql);
    capability.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".to_owned()],
        success_media_types: vec!["application/json".to_owned()],
        body_mode: ResponseBodyModeV1::GraphqlJson,
    });
    capability.selectors = vec![SelectorV1 {
        name: "zone_id".to_owned(),
        location: "graphql".to_owned(),
        required: true,
        value_type: "string".to_owned(),
        description: None,
        contract: None,
    }];
    capability.request_schema = Some(json!({
        "type":"object",
        "additionalProperties":false,
        "required":["dataset","start","end","limit"],
        "properties":{
            "dataset":{"type":"string","enum":["httpRequestsAdaptiveGroups"]},
            "start":{"type":"string","format":"date-time"},
            "end":{"type":"string","format":"date-time"},
            "limit":{"type":"integer","minimum":1,"maximum":3}
        },
        "x-cfctl-body-required":true
    }));
    capability
}

fn graphql_daily_unique_ips_capability() -> CapabilityV1 {
    let mut capability = graphql_http_capability();
    "graphql-analytics-zone-http-unique-ips-daily".clone_into(&mut capability.id);
    let query = capability
        .analytics_query
        .as_mut()
        .expect("analytics contract");
    query.dataset = Some("httpRequests1dGroups".to_owned());
    query.max_rows = 31;
    query.pagination = PaginationModeV1::BoundedResult;
    query.time_range = Some(TimeRangeContractV1 {
        start_pointer: "/start".to_owned(),
        end_pointer: "/end".to_owned(),
        timestamp_format: TimestampFormatV1::Date,
        max_lookback_seconds: 366 * 24 * 60 * 60,
        max_window_seconds: 31 * 24 * 60 * 60,
    });
    query.sampling =
        Some("daily unique client IPs; summing rows does not deduplicate across days".to_owned());
    let graphql = capability.graphql.as_mut().expect("GraphQL contract");
    "CfctlZoneHttpUniqueIpsDaily".clone_into(&mut graphql.operation_name);
    "query CfctlZoneHttpUniqueIpsDaily($zoneTag: string!, $start: Date!, $end: Date!, $limit: Int!) { viewer { zones(filter: {zoneTag: $zoneTag}) { series: httpRequests1dGroups(filter: {date_geq: $start, date_leq: $end}, limit: $limit, orderBy: [date_ASC]) { dimensions { date } uniq { uniques } } } } }".clone_into(&mut graphql.document);
    "httpRequests1dGroups".clone_into(&mut graphql.dataset);
    graphql.expected_row_fields = vec!["dimensions".to_owned(), "uniq".to_owned()];
    graphql.refresh_schema_fingerprint().expect("fingerprint");
    capability.request_schema = Some(json!({
        "type":"object",
        "additionalProperties":false,
        "required":["dataset","start","end","limit"],
        "properties":{
            "dataset":{"type":"string","enum":["httpRequests1dGroups"]},
            "start":{"type":"string","format":"date"},
            "end":{"type":"string","format":"date"},
            "limit":{"type":"integer","minimum":1,"maximum":31}
        },
        "x-cfctl-body-required":true
    }));
    capability
}

fn graphql_rum_pageload_visits_capability() -> CapabilityV1 {
    let mut capability = graphql_daily_unique_ips_capability();
    "graphql-analytics-account-rum-pageload-visits".clone_into(&mut capability.id);
    "account".clone_into(&mut capability.account_scope);
    capability.selectors = vec![SelectorV1 {
        name: "account_id".to_owned(),
        location: "graphql".to_owned(),
        required: true,
        value_type: "string".to_owned(),
        description: None,
        contract: None,
    }];
    let query = capability
        .analytics_query
        .as_mut()
        .expect("analytics contract");
    query.dataset = Some("rumPageloadEventsAdaptiveGroups".to_owned());
    query.sampling =
        Some("adaptive RUM visits; page views, not unique people, with sample interval".to_owned());
    let graphql = capability.graphql.as_mut().expect("GraphQL contract");
    "CfctlAccountRumPageloadVisits".clone_into(&mut graphql.operation_name);
    "query CfctlAccountRumPageloadVisits($accountTag: string!, $hostname: string!, $start: Date!, $end: Date!, $limit: Int!) { viewer { accounts(filter: {accountTag: $accountTag}) { series: rumPageloadEventsAdaptiveGroups(filter: {bot: 0, date_geq: $start, date_leq: $end, requestHost: $hostname}, limit: $limit, orderBy: [date_ASC]) { avg { sampleInterval } count dimensions { date requestHost } sum { visits } } } } }".clone_into(&mut graphql.document);
    "rumPageloadEventsAdaptiveGroups".clone_into(&mut graphql.dataset);
    graphql.selector_variables = [("account_id".to_owned(), "accountTag".to_owned())]
        .into_iter()
        .collect();
    graphql
        .body_variables
        .insert("hostname".to_owned(), "hostname".to_owned());
    "/viewer/accounts/0/series".clone_into(&mut graphql.response_data_pointer);
    graphql.expected_row_fields = vec![
        "avg".to_owned(),
        "count".to_owned(),
        "dimensions".to_owned(),
        "sum".to_owned(),
    ];
    graphql.refresh_schema_fingerprint().expect("fingerprint");
    capability.request_schema = Some(json!({
        "type":"object",
        "additionalProperties":false,
        "required":["dataset","hostname","start","end","limit"],
        "properties":{
            "dataset":{"type":"string","enum":["rumPageloadEventsAdaptiveGroups"]},
            "hostname":{"type":"string","format":"hostname","minLength":1,"maxLength":253},
            "start":{"type":"string","format":"date"},
            "end":{"type":"string","format":"date"},
            "limit":{"type":"integer","minimum":1,"maximum":31}
        },
        "x-cfctl-body-required":true
    }));
    capability
}

fn graphql_firewall_capability() -> CapabilityV1 {
    let mut capability = graphql_http_capability();
    "graphql-analytics-zone-firewall-events".clone_into(&mut capability.id);
    let query = capability
        .analytics_query
        .as_mut()
        .expect("analytics contract");
    query.dataset = Some("firewallEventsAdaptive".to_owned());
    query.pagination = PaginationModeV1::BoundedResult;
    query.sampling = Some(
        "sampled bounded page; dataset completeness and lossless continuation are not claimed"
            .to_owned(),
    );
    let graphql = capability.graphql.as_mut().expect("GraphQL contract");
    "CfctlZoneFirewallEvents".clone_into(&mut graphql.operation_name);
    "query CfctlZoneFirewallEvents($zoneTag: string!, $start: Time!, $end: Time!, $limit: Int!) { viewer { zones(filter: {zoneTag: $zoneTag}) { series: firewallEventsAdaptive(filter: {datetime_geq: $start, datetime_lt: $end}, limit: $limit, orderBy: [datetime_ASC, rayName_ASC]) { datetime rayName } } } }".clone_into(&mut graphql.document);
    "firewallEventsAdaptive".clone_into(&mut graphql.dataset);
    graphql.expected_row_fields = vec!["datetime".to_owned(), "rayName".to_owned()];
    graphql.cursor_fields.clear();
    graphql.cursor_input_pointer = None;
    graphql.cursor_input_pointers.clear();
    graphql.refresh_schema_fingerprint().expect("fingerprint");
    capability.request_schema = Some(json!({
        "type":"object",
        "additionalProperties":false,
        "required":["dataset","start","end","limit"],
        "properties":{
            "dataset":{"type":"string","enum":["firewallEventsAdaptive"]},
            "start":{"type":"string","format":"date-time"},
            "end":{"type":"string","format":"date-time"},
            "limit":{"type":"integer","minimum":1,"maximum":3}
        },
        "x-cfctl-body-required":true
    }));
    capability
}

fn graphql_unique_test_cursor_capability() -> CapabilityV1 {
    let mut capability = graphql_firewall_capability();
    let query = capability
        .analytics_query
        .as_mut()
        .expect("analytics contract");
    query.dataset = Some("syntheticUniqueEvents".to_owned());
    query.pagination = PaginationModeV1::OrderedKeyset;
    query.sampling = None;
    let graphql = capability.graphql.as_mut().expect("GraphQL contract");
    "CfctlSyntheticUniqueEvents".clone_into(&mut graphql.operation_name);
    "query CfctlSyntheticUniqueEvents($zoneTag: string!, $start: Time!, $end: Time!, $after: Time!, $afterEventId: string!, $limit: Int!) { viewer { zones(filter: {zoneTag: $zoneTag}) { series: syntheticUniqueEvents(filter: {datetime_geq: $start, datetime_lt: $end, OR: [{datetime_gt: $after}, {datetime: $after, eventId_gt: $afterEventId}]}, limit: $limit, orderBy: [datetime_ASC, eventId_ASC]) { datetime eventId } } } }".clone_into(&mut graphql.document);
    "syntheticUniqueEvents".clone_into(&mut graphql.dataset);
    graphql
        .body_variables
        .insert("after".to_owned(), "after".to_owned());
    graphql
        .body_variables
        .insert("after_event_id".to_owned(), "afterEventId".to_owned());
    graphql.expected_row_fields = vec!["datetime".to_owned(), "eventId".to_owned()];
    graphql.cursor_fields = vec!["datetime".to_owned(), "eventId".to_owned()];
    graphql.cursor_input_pointers = [
        ("datetime".to_owned(), "/after".to_owned()),
        ("eventId".to_owned(), "/after_event_id".to_owned()),
    ]
    .into_iter()
    .collect();
    graphql.refresh_schema_fingerprint().expect("fingerprint");
    capability.request_schema = Some(json!({
        "type":"object",
        "additionalProperties":false,
        "required":["dataset","start","end","after","after_event_id","limit"],
        "properties":{
            "dataset":{"type":"string","enum":["syntheticUniqueEvents"]},
            "start":{"type":"string","format":"date-time"},
            "end":{"type":"string","format":"date-time"},
            "after":{"type":"string","format":"date-time"},
            "after_event_id":{"type":"string"},
            "limit":{"type":"integer","minimum":1,"maximum":3}
        },
        "x-cfctl-body-required":true
    }));
    capability
}

fn assert_bounded_sample_receipt(response: &CloudflareResponseV1) {
    let info = response.result_info.as_ref().expect("result info");
    assert!(response.success);
    assert_eq!(response.result.as_array().map(Vec::len), Some(2));
    assert!(
        info.get("continuation").is_none(),
        "Security Events must not issue a cursor that can omit duplicate event keys"
    );
    assert_eq!(
        info.pointer("/coverage/classification"),
        Some(&json!("bounded_sample"))
    );
    assert_eq!(info.pointer("/coverage/limit_reached"), Some(&json!(true)));
    assert_eq!(
        info.pointer("/coverage/dataset_completeness"),
        Some(&json!("not_proven"))
    );
    assert_eq!(
        info.pointer("/query/pagination"),
        Some(&json!("bounded_result"))
    );
    assert!(
        info.pointer("/query/sampling")
            .and_then(Value::as_str)
            .is_some_and(|value| value.contains("lossless continuation are not claimed"))
    );
}

#[tokio::test]
async fn executor_sends_only_the_pinned_graphql_document_and_detects_response_drift() {
    let capability = graphql_http_capability();
    let body = bounded_query_body("ndjson", 2);
    let graphql_body = json!({
        "dataset":"httpRequestsAdaptiveGroups",
        "start":body["start"],
        "end":body["end"],
        "limit":2
    });
    let (address, server) = json_response_sequence_server(vec![
        r#"{"data":{"viewer":{"zones":[{"series":[{"count":2}]}]}},"errors":null}"#,
    ])
    .await;
    let response = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .execute_read(
        &capability,
        &CallInput {
            selectors: json!({"zone_id":"zone-1"}),
            body: Some(graphql_body.clone()),
            ..CallInput::default()
        },
        &AuthCredential::Bearer {
            token: "selected-token".to_owned(),
        },
    )
    .await
    .expect("GraphQL response");
    assert!(response.success);
    assert_eq!(response.result, json!([{"count":2}]));
    let requests = server.await.expect("server joins");
    assert!(requests[0].contains("CfctlZoneHttp"));
    assert!(requests[0].contains("\"zoneTag\":\"zone-1\""));
    assert!(!requests[0].contains("mutation"));

    let (address, server) = json_response_sequence_server(vec![
        r#"{"data":{"viewer":{"zones":[{"series":[{"unexpected":2}]}]}},"errors":null}"#,
    ])
    .await;
    let error = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .execute_read(
        &capability,
        &CallInput {
            selectors: json!({"zone_id":"zone-1"}),
            body: Some(graphql_body),
            ..CallInput::default()
        },
        &AuthCredential::Bearer {
            token: "selected-token".to_owned(),
        },
    )
    .await
    .expect_err("response schema drift must fail closed");
    assert!(matches!(error, CloudflareError::GraphqlSchemaDrift { .. }));
    server.await.expect("server joins");
}

#[tokio::test]
async fn daily_unique_ips_use_inclusive_dates_and_a_pinned_daily_rollup() {
    let capability = graphql_daily_unique_ips_capability();
    let end = Utc::now().date_naive();
    let start = end - Duration::days(29);
    let start = start.format("%Y-%m-%d").to_string();
    let end = end.format("%Y-%m-%d").to_string();
    let input = CallInput {
        selectors: json!({"zone_id":"zone-1"}),
        body: Some(json!({
            "dataset":"httpRequests1dGroups",
            "start":start,
            "end":end,
            "limit":30
        })),
        ..CallInput::default()
    };
    let (address, server) = json_response_sequence_server(vec![
        json!({
            "data":{"viewer":{"zones":[{"series":[
                {"dimensions":{"date":start},"uniq":{"uniques":42}},
                {"dimensions":{"date":end},"uniq":{"uniques":17}}
            ]}]}}
        })
        .to_string(),
    ])
    .await;
    let response = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .execute_read(
        &capability,
        &input,
        &AuthCredential::Bearer {
            token: "selected-token".to_owned(),
        },
    )
    .await
    .expect("daily visitor GraphQL response");
    assert_eq!(
        response.result,
        json!([
            {"dimensions":{"date":start},"uniq":{"uniques":42}},
            {"dimensions":{"date":end},"uniq":{"uniques":17}}
        ])
    );
    let requests = server.await.expect("server joins");
    assert!(requests[0].contains("CfctlZoneHttpUniqueIpsDaily"));
    assert!(requests[0].contains("httpRequests1dGroups"));
    assert!(requests[0].contains("date_leq"));
    assert!(requests[0].contains("\"zoneTag\":\"zone-1\""));
    assert!(!requests[0].contains("mutation"));

    let too_wide_start = Utc::now().date_naive() - Duration::days(31);
    let too_wide = CallInput {
        selectors: json!({"zone_id":"zone-1"}),
        body: Some(json!({
            "dataset":"httpRequests1dGroups",
            "start":too_wide_start.format("%Y-%m-%d").to_string(),
            "end":Utc::now().date_naive().format("%Y-%m-%d").to_string(),
            "limit":31
        })),
        ..CallInput::default()
    };
    assert!(matches!(
        validate_request_contract(&capability, &too_wide),
        Err(CloudflareError::InvalidAnalyticsQuery(message))
            if message.contains("31 day") || message.contains("2678400 second")
    ));

    let malformed = CallInput {
        selectors: json!({"zone_id":"zone-1"}),
        body: Some(json!({
            "dataset":"httpRequests1dGroups",
            "start":"2026-07-01T00:00:00Z",
            "end":"2026-07-30",
            "limit":30
        })),
        ..CallInput::default()
    };
    assert!(matches!(
        validate_request_contract(&capability, &malformed),
        Err(CloudflareError::InvalidAnalyticsQuery(message))
            if message.contains("YYYY-MM-DD")
    ));
}

#[tokio::test]
async fn rum_pageload_visits_bind_exact_hostname_account_and_date_window() {
    let capability = graphql_rum_pageload_visits_capability();
    let end = Utc::now().date_naive();
    let start = end - Duration::days(6);
    let start = start.format("%Y-%m-%d").to_string();
    let end = end.format("%Y-%m-%d").to_string();
    let input = CallInput {
        selectors: json!({"account_id":"account-1"}),
        body: Some(json!({
            "dataset":"rumPageloadEventsAdaptiveGroups",
            "hostname":"jkca.me",
            "start":start,
            "end":end,
            "limit":7
        })),
        ..CallInput::default()
    };
    let (address, server) = json_response_sequence_server(vec![
        json!({
            "data":{"viewer":{"accounts":[{"series":[
                {
                    "avg":{"sampleInterval":1.0},
                    "count":24,
                    "dimensions":{"date":start,"requestHost":"jkca.me"},
                    "sum":{"visits":11}
                },
                {
                    "avg":{"sampleInterval":1.0},
                    "count":16,
                    "dimensions":{"date":end,"requestHost":"jkca.me"},
                    "sum":{"visits":7}
                }
            ]}]}}
        })
        .to_string(),
    ])
    .await;
    let response = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .execute_read(
        &capability,
        &input,
        &AuthCredential::Bearer {
            token: "selected-token".to_owned(),
        },
    )
    .await
    .expect("hostname-bound RUM response");
    assert_eq!(response.result.as_array().map(Vec::len), Some(2));
    let requests = server.await.expect("server joins");
    assert!(requests[0].contains("CfctlAccountRumPageloadVisits"));
    assert!(requests[0].contains("rumPageloadEventsAdaptiveGroups"));
    assert!(requests[0].contains("requestHost"));
    assert!(requests[0].contains("\"hostname\":\"jkca.me\""));
    assert!(requests[0].contains("\"accountTag\":\"account-1\""));
    assert!(requests[0].contains("bot: 0"));
    assert!(!requests[0].contains("mutation"));

    let invalid_hostname = CallInput {
        selectors: json!({"account_id":"account-1"}),
        body: Some(json!({
            "dataset":"rumPageloadEventsAdaptiveGroups",
            "hostname":"https://jkca.me/path",
            "start":start,
            "end":end,
            "limit":7
        })),
        ..CallInput::default()
    };
    assert!(validate_request_contract(&capability, &invalid_hostname).is_err());
}

#[tokio::test]
async fn graphql_firewall_events_are_one_bounded_sample_without_continuation() {
    let capability = graphql_firewall_capability();
    let end = Utc::now();
    let start = end - Duration::minutes(10);
    let event_time = start + Duration::minutes(1);
    let event_time = event_time.to_rfc3339_opts(SecondsFormat::Secs, true);
    let input_body = json!({
        "dataset":"firewallEventsAdaptive",
        "start":start.to_rfc3339_opts(SecondsFormat::Secs, true),
        "end":end.to_rfc3339_opts(SecondsFormat::Secs, true),
        "limit":2
    });
    let (address, server) = json_response_sequence_server(vec![
        json!({
            "data":{"viewer":{"zones":[{"series":[
                {"datetime":event_time,"rayName":"ray-shared"},
                {"datetime":event_time,"rayName":"ray-shared"}
            ]}]}}
        })
        .to_string(),
    ])
    .await;
    let response = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .execute_read(
        &capability,
        &CallInput {
            selectors: json!({"zone_id":"zone-1"}),
            body: Some(input_body.clone()),
            ..CallInput::default()
        },
        &AuthCredential::Bearer {
            token: "selected-token".to_owned(),
        },
    )
    .await
    .expect("bounded sampled GraphQL response");
    assert_bounded_sample_receipt(&response);
    let requests = server.await.expect("server joins");
    assert!(requests[0].contains("orderBy: [datetime_ASC, rayName_ASC]"));
    assert!(!requests[0].contains("afterRayName"));
    assert!(!requests[0].contains("datetime_gt"));

    let mut legacy_body = input_body;
    legacy_body["after"] = legacy_body["start"].clone();
    legacy_body["after_ray_name"] = json!("ray-shared");
    RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("builder")
        .build(
            &capability,
            &CallInput {
                selectors: json!({"zone_id":"zone-1"}),
                body: Some(legacy_body),
                ..CallInput::default()
            },
        )
        .expect_err("undeclared continuation inputs must fail closed");
}

#[tokio::test]
async fn graphql_ordered_keyset_binds_each_field_for_a_unique_test_cursor() {
    let capability = graphql_unique_test_cursor_capability();
    let end = Utc::now();
    let start = end - Duration::minutes(10);
    let event_time = (start + Duration::minutes(1)).to_rfc3339_opts(SecondsFormat::Secs, true);
    let input_body = json!({
        "dataset":"syntheticUniqueEvents",
        "start":start.to_rfc3339_opts(SecondsFormat::Secs, true),
        "end":end.to_rfc3339_opts(SecondsFormat::Secs, true),
        "after":start.to_rfc3339_opts(SecondsFormat::Secs, true),
        "after_event_id":"",
        "limit":2
    });
    let (address, server) = json_response_sequence_server(vec![
        json!({
            "data":{"viewer":{"zones":[{"series":[
                {"datetime":event_time,"eventId":"event-a"},
                {"datetime":event_time,"eventId":"event-b"}
            ]}]}}
        })
        .to_string(),
    ])
    .await;
    let response = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .execute_read(
        &capability,
        &CallInput {
            selectors: json!({"zone_id":"zone-1"}),
            body: Some(input_body.clone()),
            ..CallInput::default()
        },
        &AuthCredential::Bearer {
            token: "selected-token".to_owned(),
        },
    )
    .await
    .expect("unique ordered keyset response");
    let next_body_patch = response
        .result_info
        .as_ref()
        .and_then(|value| value.pointer("/continuation/next_body_patch"))
        .and_then(Value::as_object)
        .cloned()
        .expect("composite continuation patch");
    assert_eq!(next_body_patch.get("after"), Some(&json!(event_time)));
    assert_eq!(
        next_body_patch.get("after_event_id"),
        Some(&json!("event-b"))
    );
    let requests = server.await.expect("server joins");
    assert!(requests[0].contains("orderBy: [datetime_ASC, eventId_ASC]"));

    let mut incomplete = capability;
    let graphql = incomplete.graphql.as_mut().expect("GraphQL contract");
    graphql.cursor_input_pointers.clear();
    graphql.cursor_input_pointer = Some("/after".to_owned());
    graphql
        .refresh_schema_fingerprint()
        .expect("legacy fingerprint");
    let error = RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("builder")
        .build(
            &incomplete,
            &CallInput {
                selectors: json!({"zone_id":"zone-1"}),
                body: Some(input_body),
                ..CallInput::default()
            },
        )
        .expect_err("a multi-field cursor cannot use one legacy input pointer");
    assert!(matches!(error, CloudflareError::InvalidAnalyticsQuery(_)));
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one streaming matrix covers row, byte, malformed-record, partial-stream, and private-file receipts"
)]
async fn executor_streams_ndjson_with_limits_partial_failures_and_private_file_receipts() {
    let capability = structured_sql_capability();
    let credential = AuthCredential::Bearer {
        token: "selected-token".to_owned(),
    };

    let (address, server) = single_raw_response_server(
        "200 OK",
        "application/x-ndjson",
        "{\"row\":1}\n{\"row\":2}\n{malformed}\n",
    )
    .await;
    let partial = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .execute_read(
        &capability,
        &CallInput {
            selectors: json!({"account_id":"account-1"}),
            body: Some(bounded_query_body("ndjson", 3)),
            ..CallInput::default()
        },
        &credential,
    )
    .await
    .expect("malformed stream is a deterministic partial envelope");
    assert!(!partial.success);
    assert_eq!(partial.result, json!([{"row":1},{"row":2}]));
    assert_eq!(
        partial
            .result_info
            .as_ref()
            .and_then(|v| v.pointer("/output/partial"))
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(partial.errors.len(), 1);
    assert!(!partial.errors[0].message.contains("malformed"));
    server.await.expect("server joins");

    let (address, server) = single_raw_response_server(
        "200 OK",
        "application/x-ndjson",
        "{\"row\":1}\n{\"row\":2}\n{\"row\":3}\n",
    )
    .await;
    let truncated = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .execute_read(
        &capability,
        &CallInput {
            selectors: json!({"account_id":"account-1"}),
            body: Some(bounded_query_body("ndjson", 2)),
            ..CallInput::default()
        },
        &credential,
    )
    .await
    .expect("row limit is a successful truncated receipt");
    assert!(truncated.success);
    assert_eq!(truncated.result.as_array().map(Vec::len), Some(2));
    assert_eq!(
        truncated
            .result_info
            .as_ref()
            .and_then(|v| v.pointer("/output/truncated"))
            .and_then(Value::as_bool),
        Some(true)
    );
    server.await.expect("server joins");

    let directory = tempfile::tempdir().expect("tempdir");
    let output = directory.path().join("analytics.ndjson");
    let (address, server) = single_raw_response_server(
        "200 OK",
        "application/x-ndjson",
        "{\"row\":1}\n{\"row\":2}\n",
    )
    .await;
    let receipt = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .execute_read_to_file(
        &capability,
        &CallInput {
            selectors: json!({"account_id":"account-1"}),
            body: Some(bounded_query_body("ndjson", 3)),
            ..CallInput::default()
        },
        &credential,
        &output,
    )
    .await
    .expect("private output receipt");
    assert!(receipt.success);
    assert!(
        receipt
            .result
            .pointer("/output_file/sha256")
            .and_then(Value::as_str)
            .is_some()
    );
    assert_eq!(
        std::fs::read_to_string(&output).expect("output"),
        "{\"row\":1}\n{\"row\":2}\n"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&output)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    server.await.expect("server joins");
}

#[tokio::test]
async fn r2_log_retrieval_injects_only_ephemeral_headers_and_returns_a_private_file_receipt() {
    let capability = r2_log_retrieval_capability(1024);
    let input = r2_log_retrieval_input();
    let credential = AuthCredential::Bearer {
        token: "selected-api-token".to_owned(),
    };
    let r2_credentials =
        R2LogRetrievalCredentials::new("r2-access-test".to_owned(), "r2-secret-test".to_owned())
            .expect("valid ephemeral credentials");
    let directory = tempfile::tempdir().expect("tempdir");
    let output = directory.path().join("retrieved.ndjson");
    let body = "{\"RayID\":\"one\"}\n{\"RayID\":\"two\"}\n";
    let (address, server) = json_response_sequence_server(vec![body]).await;
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let response = executor
        .execute_r2_log_retrieval_to_file(
            &capability,
            &input,
            &credential,
            &r2_credentials,
            &output,
        )
        .await
        .expect("bounded retrieval");
    assert!(response.success);
    assert_eq!(std::fs::read_to_string(&output).expect("output"), body);
    assert_eq!(
        response.result.pointer("/output_file/complete"),
        Some(&json!(true))
    );
    assert!(
        response
            .result_info
            .as_ref()
            .and_then(|value| value.pointer("/query/bucket_sha256"))
            .and_then(Value::as_str)
            .is_some()
    );
    let serialized = serde_json::to_string(&response).expect("serialize receipt");
    for secret in ["r2-access-test", "r2-secret-test", "cloudflare-logs"] {
        assert!(!serialized.contains(secret));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&output)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let requests = server.await.expect("server joins");
    let request = requests.first().expect("request captured");
    assert!(
        request
            .lines()
            .any(|line| { line.eq_ignore_ascii_case("r2-access-key-id: r2-access-test") })
    );
    assert!(
        request
            .lines()
            .any(|line| { line.eq_ignore_ascii_case("r2-secret-access-key: r2-secret-test") })
    );
    assert!(
        request
            .lines()
            .any(|line| { line.eq_ignore_ascii_case("authorization: Bearer selected-api-token") })
    );
    assert!(request.starts_with("GET /client/v4/accounts/account-1/logs/retrieve?"));
    assert!(!format!("{r2_credentials:?}").contains("r2-secret-test"));
}

#[tokio::test]
async fn r2_log_retrieval_fails_closed_without_the_specialized_path_and_on_byte_truncation() {
    let capability = r2_log_retrieval_capability(24);
    let input = r2_log_retrieval_input();
    let credential = AuthCredential::Bearer {
        token: "selected-api-token".to_owned(),
    };
    let no_bundle = Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4")
        .expect("executor")
        .execute_read(&capability, &input, &credential)
        .await
        .expect_err("ordinary executor cannot omit the R2 bundle");
    assert!(matches!(
        no_bundle,
        CloudflareError::R2LogCredentialsRequired
    ));

    let r2_credentials =
        R2LogRetrievalCredentials::new("r2-access".to_owned(), "r2-secret".to_owned())
            .expect("credentials");
    let directory = tempfile::tempdir().expect("tempdir");
    let output = directory.path().join("partial.ndjson");
    let body = format!("{{\"payload\":\"{}\"}}\n", "x".repeat(100));
    let (address, server) = json_response_sequence_server(vec![body]).await;
    let response = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .execute_r2_log_retrieval_to_file(&capability, &input, &credential, &r2_credentials, &output)
    .await
    .expect("truncation becomes a receipt");
    assert!(!response.success);
    assert_eq!(std::fs::metadata(&output).expect("output").len(), 24);
    assert_eq!(
        response
            .result_info
            .as_ref()
            .and_then(|value| value.pointer("/output/truncated")),
        Some(&json!(true))
    );
    assert_eq!(
        response.result.pointer("/output_file/complete"),
        Some(&json!(false))
    );
    server.await.expect("server joins");
}

#[test]
fn r2_log_retrieval_rejects_unbounded_windows_bad_buckets_and_catalog_grafts() {
    let capability = r2_log_retrieval_capability(1024);
    let mut input = r2_log_retrieval_input();
    input.query["bucket"] = json!("Bad_Bucket");
    let error = RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("builder")
        .build(&capability, &input)
        .expect_err("bad bucket");
    assert!(matches!(error, CloudflareError::InvalidR2LogRetrieval(_)));

    let mut long_window = r2_log_retrieval_input();
    let end = Utc::now();
    long_window.query["start"] =
        json!((end - Duration::hours(2)).to_rfc3339_opts(SecondsFormat::Secs, true));
    long_window.query["end"] = json!(end.to_rfc3339_opts(SecondsFormat::Secs, true));
    let error = RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("builder")
        .build(&capability, &long_window)
        .expect_err("long window");
    assert!(matches!(error, CloudflareError::InvalidR2LogRetrieval(_)));

    let mut graft = capability;
    graft.id = "arbitrary-r2-download".to_owned();
    let error = RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("builder")
        .build(&graft, &r2_log_retrieval_input())
        .expect_err("contract cannot be grafted");
    assert!(matches!(error, CloudflareError::InvalidR2LogRetrieval(_)));
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one negotiation matrix proves JSON, CSV, empty, malformed, and byte-bounded responses"
)]
async fn executor_negotiates_json_csv_empty_and_byte_bounded_analytics_results() {
    let capability = structured_sql_capability();
    let credential = AuthCredential::Bearer {
        token: "selected-token".to_owned(),
    };

    let (address, server) =
        single_raw_response_server("200 OK", "application/json", "[{\"row\":1},{\"row\":2}]").await;
    let json_response = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .execute_read(
        &capability,
        &CallInput {
            selectors: json!({"account_id":"account-1"}),
            body: Some(bounded_query_body("json", 3)),
            ..CallInput::default()
        },
        &credential,
    )
    .await
    .expect("JSON analytics response");
    assert_eq!(json_response.result.as_array().map(Vec::len), Some(2));
    assert_eq!(
        json_response
            .result_info
            .as_ref()
            .and_then(|value| value.pointer("/output/format")),
        Some(&json!("json"))
    );
    server.await.expect("server joins");

    let (address, server) =
        single_raw_response_server("200 OK", "text/csv; charset=utf-8", "row,value\n1,a\n2,b\n")
            .await;
    let csv_response = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .execute_read(
        &capability,
        &CallInput {
            selectors: json!({"account_id":"account-1"}),
            body: Some(bounded_query_body("csv", 3)),
            ..CallInput::default()
        },
        &credential,
    )
    .await
    .expect("CSV analytics response");
    assert!(csv_response.success);
    assert_eq!(
        csv_response
            .result_info
            .as_ref()
            .and_then(|value| value.pointer("/output/rows")),
        Some(&json!(2))
    );
    server.await.expect("server joins");

    let (address, server) = single_raw_response_server("200 OK", "application/x-ndjson", "").await;
    let empty = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .execute_read(
        &capability,
        &CallInput {
            selectors: json!({"account_id":"account-1"}),
            body: Some(bounded_query_body("ndjson", 3)),
            ..CallInput::default()
        },
        &credential,
    )
    .await
    .expect("empty NDJSON response");
    assert_eq!(empty.result, json!([]));
    assert!(empty.success);
    server.await.expect("server joins");

    let mut large_capability = capability.clone();
    large_capability
        .analytics_query
        .as_mut()
        .expect("analytics contract")
        .max_rows = 100;
    large_capability.request_schema.as_mut().expect("schema")["properties"]["limit"]["maximum"] =
        json!(100);
    let oversized = format!("{{\"payload\":\"{}\"}}\n", "x".repeat(1_100));
    let (address, server) =
        single_raw_response_server("200 OK", "application/x-ndjson", &oversized).await;
    let bounded = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .execute_read(
        &large_capability,
        &CallInput {
            selectors: json!({"account_id":"account-1"}),
            body: Some(bounded_query_body("ndjson", 100)),
            ..CallInput::default()
        },
        &credential,
    )
    .await
    .expect("byte-bounded stream receipt");
    assert_eq!(
        bounded
            .result_info
            .as_ref()
            .and_then(|value| value.pointer("/output/truncated")),
        Some(&json!(true))
    );
    assert_eq!(
        bounded
            .result_info
            .as_ref()
            .and_then(|value| value.pointer("/output/bytes")),
        Some(&json!(1_024))
    );
    server.await.expect("server joins");
}

#[tokio::test]
async fn executor_rejects_a_success_media_type_not_declared_by_the_capability() {
    let mut capability = structured_sql_capability();
    capability
        .response_contract
        .as_mut()
        .expect("response contract")
        .success_media_types = vec!["application/x-ndjson".to_owned()];
    let (address, server) = single_raw_response_server("200 OK", "application/json", "[]").await;
    let error = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .execute_read(
        &capability,
        &CallInput {
            selectors: json!({"account_id":"account-1"}),
            body: Some(bounded_query_body("json", 3)),
            ..CallInput::default()
        },
        &AuthCredential::Bearer {
            token: "selected-token".to_owned(),
        },
    )
    .await
    .expect_err("undeclared JSON representation must fail closed");
    assert!(matches!(
        error,
        CloudflareError::UnexpectedResponseMediaType { status: 200, .. }
    ));
    server.await.expect("server joins");
}

#[test]
fn request_builder_rejects_an_unsupported_pinned_response_contract() {
    let mut capability = CapabilityV1::new("object-read", "Read object", "GET", "/object");
    capability.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".to_owned()],
        success_media_types: vec!["application/octet-stream".to_owned()],
        body_mode: ResponseBodyModeV1::Unsupported,
    });
    let error = RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("builder")
        .build(&capability, &CallInput::default())
        .expect_err("unsupported response contracts must fail before authentication");
    assert!(matches!(
        error,
        CloudflareError::UnsupportedResponseContract(media)
            if media == "application/octet-stream"
    ));
}

#[tokio::test]
async fn executor_refuses_a_plan_that_was_not_durably_marked_consumed() {
    let capability = CapabilityV1::new("zones-delete", "Delete zone", "DELETE", "/zones/{zone_id}");
    let mut plan = PlanV1::draft(
        "profile",
        "account",
        "sha256:catalog",
        capability,
        json!({"zone_id":"zone"}),
    )
    .expect("draft plan");
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"zone_id":"zone"}),
        query: json!({}),
        body: None,
        ..CallInput::default()
    })
    .expect("input");
    plan.refresh_hash().expect("refresh hash");
    plan.approve(true, None).expect("approve");
    let executor = Executor::new(reqwest::Client::new(), "http://127.0.0.1:9").expect("executor");
    let error = executor
        .execute_consumed_plan(
            &mut plan,
            "sha256:catalog",
            &AuthCredential::Bearer {
                token: "token".to_owned(),
            },
        )
        .await
        .expect_err("unconsumed plan must fail before network");
    assert!(
        error
            .to_string()
            .contains("durably persisted consumed plan")
    );
}

#[tokio::test]
async fn executor_rejects_a_grafted_verifier_before_the_mutation_boundary() {
    let mut capability = CapabilityV1::new(
        "widgets-create",
        "Create widget",
        "POST",
        "/accounts/{account_id}/widgets",
    );
    capability.verification.strategy =
        "api_token_details_match_created_id_and_active_status".to_owned();
    let mut plan = PlanV1::draft(
        "profile",
        "account",
        "sha256:catalog",
        capability,
        json!({}),
    )
    .expect("draft plan");
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account"}),
        query: json!({}),
        body: Some(json!({"name":"test"})),
        ..CallInput::default()
    })
    .expect("input");
    plan.refresh_hash().expect("refresh hash");
    plan.approve(true, None).expect("approve");
    plan.mark_consumed().expect("consume");
    let executor = Executor::new(reqwest::Client::new(), "http://127.0.0.1:9").expect("executor");

    let error = executor
        .execute_consumed_plan(
            &mut plan,
            "sha256:catalog",
            &AuthCredential::Bearer {
                token: "token".to_owned(),
            },
        )
        .await
        .expect_err("unsupported verifier must fail before network");

    assert!(matches!(
        error,
        CloudflareError::UnsupportedVerificationStrategy(strategy)
            if strategy == "api_token_details_match_created_id_and_active_status"
    ));
}

#[tokio::test]
async fn executor_collects_all_cloudflare_result_pages() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let mut requests = Vec::new();
        for page in 1..=2 {
            let (mut stream, _) = listener.accept().await.expect("accept request");
            let mut buffer = vec![0_u8; 8192];
            let read = stream.read(&mut buffer).await.expect("read request");
            requests.push(String::from_utf8_lossy(&buffer[..read]).to_string());
            let body = format!(
                r#"{{"success":true,"result":[{{"id":"zone-{page}"}}],"errors":[],"result_info":{{"page":{page},"total_pages":2,"total_count":2}}}}"#
            );
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nETag: page-{page}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write response");
        }
        requests
    });
    let capability = CapabilityV1::new("zones-list", "List zones", "GET", "/zones");
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");
    let response = executor
        .execute_read(
            &capability,
            &CallInput::default(),
            &AuthCredential::Bearer {
                token: "token".to_owned(),
            },
        )
        .await
        .expect("paginated response");
    assert_eq!(response.result.as_array().expect("result array").len(), 2);
    assert_eq!(response.etag.as_deref(), Some("page-2"));
    let requests = server.await.expect("server joins");
    assert_eq!(requests.len(), 2);
    assert!(requests[1].contains("page=2"));
}

#[tokio::test]
async fn email_routing_rules_read_returns_one_bounded_typed_projection() {
    let (address, server) = json_response_sequence_server(vec![
        r#"{"success":true,"result":[{"enabled":true,"matchers":[{"type":"literal","field":"to","value":"security@example.com"}],"actions":[{"type":"worker","value":["maildesk-router"]}]},{"enabled":true,"matchers":[{"type":"all"}],"actions":[{"type":"forward","value":["operator@example.com"]}]}],"errors":[],"result_info":{"page":1,"per_page":50,"total_count":2}}"#,
        r#"{"success":true,"result":[],"errors":[],"result_info":{"page":2,"per_page":50,"total_count":2}}"#,
    ])
    .await;
    let mut capability = CapabilityV1::new(
        "email-routing-routing-rules-list-routing-rules",
        "List routing rules",
        "GET",
        "/zones/{zone_id}/email/routing/rules",
    );
    capability.selectors = vec![
        SelectorV1 {
            name: "zone_id".to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        },
        SelectorV1 {
            name: "page".to_owned(),
            location: "query".to_owned(),
            required: false,
            value_type: "number".to_owned(),
            description: None,
            contract: None,
        },
        SelectorV1 {
            name: "per_page".to_owned(),
            location: "query".to_owned(),
            required: false,
            value_type: "number".to_owned(),
            description: None,
            contract: None,
        },
    ];
    capability.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".to_owned()],
        success_media_types: vec!["application/json".to_owned()],
        body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
    });
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");
    let response = executor
        .execute_read(
            &capability,
            &CallInput {
                selectors: json!({"zone_id":"zone-example"}),
                query: json!({"page":1,"per_page":50}),
                ..CallInput::default()
            },
            &AuthCredential::Bearer {
                token: "token".to_owned(),
            },
        )
        .await
        .expect("typed Email Routing response");

    assert!(response.success);
    assert_eq!(response.result["schema_version"], 1);
    assert_eq!(response.result["complete"], true);
    assert_eq!(response.result["rule_count"], 2);
    assert_eq!(response.result["rules"][0]["matchers"][0]["field"], "to");
    assert_eq!(
        response.result["rules"][0]["matchers"][0]["value_sha256"],
        "sha256:786906db96ef646937f205d3e7398630ce2e97df5364baf31b81ef84f1386c3f"
    );
    assert_eq!(
        response.result["rules"][0]["actions"][0]["worker_targets"],
        json!(["maildesk-router"])
    );
    assert_eq!(response.result["rules"][1]["actions"][0]["value_count"], 1);
    let serialized = serde_json::to_string(&response.result).expect("serialize projection");
    assert!(!serialized.contains("operator@example.com"));
    assert!(!serialized.contains("security@example.com"));

    let requests = server.await.expect("server joins");
    assert_eq!(requests.len(), 2);
    assert!(requests[0].contains("page=1"));
    assert!(requests[0].contains("per_page=50"));
    assert!(requests[1].contains("page=2"));
}

#[tokio::test]
async fn email_routing_rules_read_rejects_shape_drift_without_echoing_values() {
    let (address, server) = json_response_sequence_server(vec![
        r#"{"success":true,"result":[{"enabled":true,"matchers":[{"type":"literal","field":"to"}],"actions":[{"type":"forward","value":["operator@example.com"]}]}],"errors":[]}"#,
        r#"{"success":true,"result":[],"errors":[]}"#,
    ])
    .await;
    let mut capability = CapabilityV1::new(
        "email-routing-routing-rules-list-routing-rules",
        "List routing rules",
        "GET",
        "/zones/{zone_id}/email/routing/rules",
    );
    capability.selectors = vec![SelectorV1 {
        name: "zone_id".to_owned(),
        location: "path".to_owned(),
        required: true,
        value_type: "string".to_owned(),
        description: None,
        contract: None,
    }];
    capability.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".to_owned()],
        success_media_types: vec!["application/json".to_owned()],
        body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
    });
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");
    let response = executor
        .execute_read(
            &capability,
            &CallInput {
                selectors: json!({"zone_id":"zone-example"}),
                ..CallInput::default()
            },
            &AuthCredential::Bearer {
                token: "token".to_owned(),
            },
        )
        .await
        .expect("safe rejected projection");

    assert!(!response.success);
    assert_eq!(response.result["complete"], false);
    assert_eq!(
        response.result["diagnostic"]["code"],
        "matcher_pair_incomplete"
    );
    assert_eq!(response.result["diagnostic"]["component"], "matcher");
    let serialized = serde_json::to_string(&response).expect("serialize rejection");
    assert!(!serialized.contains("operator@example.com"));
    assert!(!serialized.contains("zone-example"));

    let requests = server.await.expect("server joins");
    assert_eq!(requests.len(), 2);
}

#[tokio::test]
async fn email_routing_rules_read_suppresses_failed_page_values_after_a_boundary() {
    let (address, server) = json_response_sequence_server(vec![
        r#"{"success":true,"result":[{"enabled":true,"matchers":[{"type":"literal","field":"to","value":"security@example.com"}],"actions":[{"type":"worker","value":["maildesk-router"]}]}],"errors":[]}"#,
        r#"{"success":false,"result":[{"actions":[{"type":"forward","value":["operator@example.com"]}]}],"errors":[{"message":"operator@example.com"}]}"#,
    ])
    .await;
    let capability = email_routing_rules_test_capability();
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");
    let response = executor
        .execute_read(
            &capability,
            &CallInput {
                selectors: json!({"zone_id":"zone-example"}),
                ..CallInput::default()
            },
            &AuthCredential::Bearer {
                token: "token".to_owned(),
            },
        )
        .await
        .expect("safe failed-page projection");

    assert!(!response.success);
    assert_eq!(
        response.result["diagnostic"]["code"],
        "provider_page_unsuccessful"
    );
    let serialized = serde_json::to_string(&response).expect("serialize rejection");
    assert!(!serialized.contains("operator@example.com"));
    assert!(!serialized.contains("security@example.com"));
    assert_eq!(server.await.expect("server joins").len(), 2);
}

#[tokio::test]
async fn email_routing_rules_read_rejects_provider_errors_on_a_success_envelope() {
    let (address, server) = json_response_sequence_server(vec![
        r#"{"success":true,"result":[{"enabled":true,"matchers":[{"type":"literal","field":"to","value":"security@example.com"}],"actions":[{"type":"forward","value":["operator@example.com"]}]}],"errors":[{"message":"operator@example.com"}]}"#,
    ])
    .await;
    let capability = email_routing_rules_test_capability();
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");
    let response = executor
        .execute_read(
            &capability,
            &CallInput {
                selectors: json!({"zone_id":"zone-example"}),
                ..CallInput::default()
            },
            &AuthCredential::Bearer {
                token: "token".to_owned(),
            },
        )
        .await
        .expect("safe provider-error projection");

    assert!(!response.success);
    assert_eq!(
        response.result["diagnostic"]["code"],
        "provider_errors_present"
    );
    let serialized = serde_json::to_string(&response).expect("serialize rejection");
    assert!(!serialized.contains("operator@example.com"));
    assert!(!serialized.contains("security@example.com"));
    assert_eq!(server.await.expect("server joins").len(), 1);
}

fn email_routing_rules_test_capability() -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        "email-routing-routing-rules-list-routing-rules",
        "List routing rules",
        "GET",
        "/zones/{zone_id}/email/routing/rules",
    );
    capability.selectors = vec![SelectorV1 {
        name: "zone_id".to_owned(),
        location: "path".to_owned(),
        required: true,
        value_type: "string".to_owned(),
        description: None,
        contract: None,
    }];
    capability.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".to_owned()],
        success_media_types: vec!["application/json".to_owned()],
        body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
    });
    capability
}

#[tokio::test]
async fn consumed_mutation_carries_plan_id_as_idempotency_key() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept request");
        let mut buffer = vec![0_u8; 8192];
        let read = stream.read(&mut buffer).await.expect("read request");
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let body = r#"{"success":true,"result":{"id":"record-1"},"errors":[]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCF-Ray: test-ray\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write response");
        request
    });
    let mut capability =
        CapabilityV1::new("zone-delete", "Delete zone", "DELETE", "/zones/{zone_id}");
    capability.verification.strategy = "same_resource_returns_not_found_after_delete".to_owned();
    capability.same_path_read = Some(SamePathReadContractV1 {
        path: "/zones/{zone_id}".to_owned(),
        read_capability_id: "zone-get".to_owned(),
        verified_response_fields: Vec::new(),
    });
    let mut plan = PlanV1::draft(
        "profile",
        "account",
        "sha256:catalog",
        capability,
        json!({}),
    )
    .expect("draft plan");
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"zone_id":"zone-1"}),
        query: json!({}),
        body: None,
        ..CallInput::default()
    })
    .expect("serialize input");
    plan.refresh_hash().expect("refresh hash");
    plan.approve(true, None).expect("approve");
    plan.mark_consumed().expect("consume");
    let operation_id = plan.operation_id.clone();
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");
    let response = executor
        .execute_consumed_plan(
            &mut plan,
            "sha256:catalog",
            &AuthCredential::Bearer {
                token: "token".to_owned(),
            },
        )
        .await
        .expect("mutation response");
    assert_eq!(response.cf_ray.as_deref(), Some("test-ray"));
    let request = server.await.expect("server joins");
    assert!(request.contains(&format!("idempotency-key: {operation_id}")));
}

#[tokio::test]
async fn account_token_creation_is_verified_by_id_and_active_readback() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let read = stream.read(&mut buffer).await.expect("read verification");
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let body = r#"{"success":true,"result":{"id":"token-1","status":"active"},"errors":[]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
        request
    });
    let plan = token_plan(
        "account-api-tokens-create-token",
        "POST",
        "/accounts/{account_id}/tokens",
        "api_token_details_match_created_id_and_active_status",
        json!({"account_id":"account-1"}),
    );
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"token-1","status":"active","value":"one-time-secret"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");
    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed);
    assert!(verification.basis.contains("token-1"));
    let request = server.await.expect("server joins");
    assert!(
        request.starts_with("GET /client/v4/accounts/account-1/tokens/token-1 "),
        "{request}"
    );
    assert!(request.contains("authorization: Bearer governing-token"));
}

#[tokio::test]
async fn account_token_revocation_is_verified_by_not_found_readback() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let read = stream.read(&mut buffer).await.expect("read verification");
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let body =
            r#"{"success":false,"result":null,"errors":[{"code":1001,"message":"not found"}]}"#;
        let response = format!(
            "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
        request
    });
    let plan = token_plan(
        "account-api-tokens-delete-token",
        "DELETE",
        "/accounts/{account_id}/tokens/{token_id}",
        "api_token_details_returns_not_found_after_revoke",
        json!({"account_id":"account-1", "token_id":"token-1"}),
    );
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"token-1"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed);
    let request = server.await.expect("server joins");
    assert!(
        request.starts_with("GET /client/v4/accounts/account-1/tokens/token-1 "),
        "{request}"
    );
}

#[tokio::test]
async fn dns_record_creation_is_verified_by_created_id_and_planned_fields() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let read = stream.read(&mut buffer).await.expect("read verification");
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let body = r#"{"success":true,"result":{"id":"record-1","type":"A","name":"www.example.com","content":"192.0.2.1","ttl":300},"errors":[]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
        request
    });
    let planned_fields = json!({
        "type":"A",
        "name":"www.example.com",
        "content":"192.0.2.1",
        "ttl":300
    });
    let plan = dns_record_plan(
        "dns-records-for-a-zone-create-dns-record",
        "POST",
        "/zones/{zone_id}/dns_records",
        "dns_record_details_match_created_id_and_planned_fields",
        json!({"zone_id":"zone-1"}),
        Some(planned_fields.clone()),
    );
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"record-1", "type":"A", "name":"www.example.com", "content":"192.0.2.1", "ttl":300}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed, "{}", verification.basis);
    let request = server.await.expect("server joins");
    assert!(
        request.starts_with("GET /client/v4/zones/zone-1/dns_records/record-1 "),
        "{request}"
    );
}

#[tokio::test]
async fn dns_record_deletion_is_verified_by_not_found_readback() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let read = stream.read(&mut buffer).await.expect("read verification");
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let body =
            r#"{"success":false,"result":null,"errors":[{"code":81044,"message":"not found"}]}"#;
        let response = format!(
            "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
        request
    });
    let plan = dns_record_plan(
        "dns-records-for-a-zone-delete-dns-record",
        "DELETE",
        "/zones/{zone_id}/dns_records/{dns_record_id}",
        "dns_record_details_returns_not_found_after_delete",
        json!({"zone_id":"zone-1", "dns_record_id":"record-1"}),
        None,
    );
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"record-1"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed, "{}", verification.basis);
    let request = server.await.expect("server joins");
    assert!(
        request.starts_with("GET /client/v4/zones/zone-1/dns_records/record-1 "),
        "{request}"
    );
}

#[tokio::test]
async fn exact_resource_deletion_is_verified_by_same_path_not_found_readback() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let read = stream.read(&mut buffer).await.expect("read verification");
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let body =
            r#"{"success":false,"result":null,"errors":[{"code":1001,"message":"not found"}]}"#;
        let response = format!(
            "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
        request
    });
    let mut plan = dns_record_plan(
        "widgets-delete",
        "DELETE",
        "/accounts/{account_id}/widgets/{widget_id}",
        "same_resource_returns_not_found_after_delete",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        None,
    );
    "R2 Bucket".clone_into(&mut plan.capability.product);
    plan.capability.selectors.push(SelectorV1 {
        name: "cf-r2-jurisdiction".to_owned(),
        location: "header".to_owned(),
        required: false,
        value_type: "string".to_owned(),
        description: None,
        contract: None,
    });
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({
            "account_id":"account-1",
            "widget_id":"widget-1",
            "cf-r2-jurisdiction":"eu"
        }),
        query: json!({}),
        body: None,
        if_match: Some("mutation-only-etag".to_owned()),
        ..CallInput::default()
    })
    .expect("input");
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"widget-1"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed, "{}", verification.basis);
    let request = server.await.expect("server joins");
    assert!(
        request.starts_with("GET /client/v4/accounts/account-1/widgets/widget-1 "),
        "{request}"
    );
    assert!(!request.contains("mutation-only"));
    assert!(request.contains("cf-r2-jurisdiction: eu\r\n"));
}

#[tokio::test]
async fn exact_resource_deletion_rejects_a_still_present_readback_without_echoing_values() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let _ = stream.read(&mut buffer).await.expect("read verification");
        let body = r#"{"success":true,"result":{"id":"secret-widget-id"},"errors":[]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
    });
    let plan = dns_record_plan(
        "widgets-delete",
        "DELETE",
        "/accounts/{account_id}/widgets/{widget_id}",
        "same_resource_returns_not_found_after_delete",
        json!({"account_id":"account-1", "widget_id":"secret-widget-id"}),
        None,
    );
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"secret-widget-id"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(!verification.passed);
    assert!(verification.basis.contains("readback HTTP 200"));
    assert!(!verification.basis.contains("secret-widget-id"));
    server.await.expect("server joins");
}

#[tokio::test]
async fn exact_resource_deletion_is_verified_by_complete_parent_collection_absence() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let mut requests = Vec::new();
        for page in 1..=2 {
            let (mut stream, _) = listener.accept().await.expect("accept verification");
            let mut buffer = vec![0_u8; 8192];
            let read = stream.read(&mut buffer).await.expect("read verification");
            requests.push(String::from_utf8_lossy(&buffer[..read]).to_string());
            let body = if page == 1 {
                r#"{"success":true,"result":[{"id":"widget-2"}],"result_info":{"page":1,"total_pages":2}}"#
            } else {
                r#"{"success":true,"result":[{"id":"widget-3"}],"result_info":{"page":2,"total_pages":2}}"#
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write verification");
        }
        requests
    });
    let mut plan = dns_record_plan(
        "widgets-delete",
        "DELETE",
        "/accounts/{account_id}/widgets/{widget_id}",
        "parent_collection_omits_deleted_resource_id",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        None,
    );
    plan.capability.deleted_resource = Some(DeletedResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        requires_page_number_completion: true,
    });
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"widget-1"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed, "{}", verification.basis);
    let requests = server.await.expect("server joins");
    assert!(requests[0].starts_with("GET /client/v4/accounts/account-1/widgets "));
    assert!(requests[1].starts_with("GET /client/v4/accounts/account-1/widgets?page=2 "));
    assert!(requests.iter().all(|request| !request.contains("widget-1")));
}

#[tokio::test]
async fn parent_collection_deletion_uses_the_hash_bound_selector_identity_pointer() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let read = stream.read(&mut buffer).await.expect("read verification");
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let body = r#"{"success":true,"result":[{"slug":"other-widget"}]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
        request
    });
    let mut plan = dns_record_plan(
        "widgets-delete",
        "DELETE",
        "/accounts/{account_id}/widgets/{slug}",
        "parent_collection_omits_deleted_resource_id",
        json!({"account_id":"account-1", "slug":"target-widget"}),
        None,
    );
    plan.capability.deleted_resource = Some(DeletedResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "slug".to_owned(),
        response_item_identity_pointer: "/slug".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        requires_page_number_completion: false,
    });
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed, "{}", verification.basis);
    let request = server.await.expect("server joins");
    assert!(request.starts_with("GET /client/v4/accounts/account-1/widgets "));
    assert!(!request.contains("target-widget"));
}

#[tokio::test]
async fn paginated_parent_collection_verification_requires_live_completion_metadata() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let _ = stream.read(&mut buffer).await.expect("read verification");
        let body = r#"{"success":true,"result":[{"id":"widget-2"}]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
    });
    let mut plan = dns_record_plan(
        "widgets-delete",
        "DELETE",
        "/accounts/{account_id}/widgets/{widget_id}",
        "parent_collection_omits_deleted_resource_id",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        None,
    );
    plan.capability.deleted_resource = Some(DeletedResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        requires_page_number_completion: true,
    });
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"widget-1"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(!verification.passed);
    assert!(verification.basis.contains("pagination complete=false"));
    assert!(verification.basis.contains("deleted identity absent=true"));
    server.await.expect("server joins");
}

#[tokio::test]
async fn parent_collection_verifier_rejects_a_present_deleted_identity_without_echoing_it() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let _ = stream.read(&mut buffer).await.expect("read verification");
        let body = r#"{"success":true,"result":[{"id":"secret-widget-id"}]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
    });
    let mut plan = dns_record_plan(
        "widgets-delete",
        "DELETE",
        "/accounts/{account_id}/widgets/{widget_id}",
        "parent_collection_omits_deleted_resource_id",
        json!({"account_id":"account-1", "widget_id":"secret-widget-id"}),
        None,
    );
    plan.capability.deleted_resource = Some(DeletedResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        requires_page_number_completion: false,
    });
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"secret-widget-id"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(!verification.passed);
    assert!(verification.basis.contains("deleted identity absent=false"));
    assert!(!verification.basis.contains("secret-widget-id"));
    server.await.expect("server joins");
}

#[tokio::test]
async fn exact_resource_update_is_verified_by_complete_parent_collection_fields() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let mut requests = Vec::new();
        for page in 1..=2 {
            let (mut stream, _) = listener.accept().await.expect("accept verification");
            let mut buffer = vec![0_u8; 8192];
            let read = stream.read(&mut buffer).await.expect("read verification");
            requests.push(String::from_utf8_lossy(&buffer[..read]).to_string());
            let body = if page == 1 {
                r#"{"success":true,"result":[{"id":"widget-2","name":"other","enabled":false}],"result_info":{"page":1,"total_pages":2}}"#
            } else {
                r#"{"success":true,"result":[{"id":"widget-1","name":"after","enabled":true}],"result_info":{"page":2,"total_pages":2}}"#
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write verification");
        }
        requests
    });
    let mut plan = dns_record_plan(
        "widgets-update",
        "PATCH",
        "/accounts/{account_id}/widgets/{widget_id}",
        "parent_collection_item_contains_planned_fields_after_update",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        Some(json!({"name":"after", "enabled":true})),
    );
    plan.capability.updated_resource = Some(UpdatedResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        verified_response_fields: vec!["enabled".to_owned(), "name".to_owned()],
        requires_page_number_completion: true,
    });
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed, "{}", verification.basis);
    let requests = server.await.expect("server joins");
    assert!(requests[0].starts_with("GET /client/v4/accounts/account-1/widgets "));
    assert!(requests[1].starts_with("GET /client/v4/accounts/account-1/widgets?page=2 "));
    assert!(requests.iter().all(|request| !request.contains("widget-1")));
}

#[tokio::test]
async fn parent_collection_update_rejects_field_drift_without_echoing_values() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let _ = stream.read(&mut buffer).await.expect("read verification");
        let body =
            r#"{"success":true,"result":[{"id":"widget-1","name":"unexpected-live-value"}]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
    });
    let mut plan = dns_record_plan(
        "widgets-update",
        "PATCH",
        "/accounts/{account_id}/widgets/{widget_id}",
        "parent_collection_item_contains_planned_fields_after_update",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        Some(json!({"name":"planned-secret-like-value"})),
    );
    plan.capability.updated_resource = Some(UpdatedResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
        requires_page_number_completion: false,
    });
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(!verification.passed);
    assert!(verification.basis.contains("planned fields match=false"));
    assert!(!verification.basis.contains("planned-secret-like-value"));
    assert!(!verification.basis.contains("unexpected-live-value"));
    server.await.expect("server joins");
}

#[tokio::test]
async fn parent_collection_update_rejects_unbound_fields_before_the_mutation_boundary() {
    let mut plan = dns_record_plan(
        "widgets-update",
        "PATCH",
        "/accounts/{account_id}/widgets/{widget_id}",
        "parent_collection_item_contains_planned_fields_after_update",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        Some(json!({"name":"planned"})),
    );
    plan.capability.updated_resource = Some(UpdatedResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
        requires_page_number_completion: false,
    });
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-1", "widget_id":"widget-1"}),
        query: json!({}),
        body: Some(json!({"name":"planned", "hidden":true})),
        ..CallInput::default()
    })
    .expect("input");
    plan.status = PlanStatus::Consumed;
    let input: CallInput = serde_json::from_value(plan.input.clone()).expect("input");
    let catalog_hash = plan.catalog_hash.clone();
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .execute_consumed_plan_with_input(
            &mut plan,
            &catalog_hash,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
            &input,
        )
        .await
        .expect_err("unbound field must fail before network execution")
        .to_string();

    assert!(error.contains("outside the hash-bound collection readback fields"));
    assert_eq!(plan.status, PlanStatus::Consumed);
}

#[tokio::test]
async fn parent_collection_update_rejects_query_controls_before_the_mutation_boundary() {
    let mut plan = dns_record_plan(
        "widgets-update",
        "PATCH",
        "/accounts/{account_id}/widgets/{widget_id}",
        "parent_collection_item_contains_planned_fields_after_update",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        Some(json!({"name":"planned"})),
    );
    plan.capability.updated_resource = Some(UpdatedResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
        requires_page_number_completion: false,
    });
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-1", "widget_id":"widget-1"}),
        query: json!({"mode":"must-not-cross-boundary"}),
        body: Some(json!({"name":"planned"})),
        ..CallInput::default()
    })
    .expect("input");
    plan.status = PlanStatus::Consumed;
    let input: CallInput = serde_json::from_value(plan.input.clone()).expect("input");
    let catalog_hash = plan.catalog_hash.clone();
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .execute_consumed_plan_with_input(
            &mut plan,
            &catalog_hash,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
            &input,
        )
        .await
        .expect_err("query controls must fail before network execution")
        .to_string();

    assert!(error.contains("query controls outside the hash-bound collection readback contract"));
    assert!(!error.contains("must-not-cross-boundary"));
    assert_eq!(plan.status, PlanStatus::Consumed);
}

#[tokio::test]
async fn parent_collection_delete_rejects_broadening_inputs_before_the_mutation_boundary() {
    let mut plan = dns_record_plan(
        "widgets-delete",
        "DELETE",
        "/accounts/{account_id}/widgets/{widget_id}",
        "parent_collection_omits_deleted_resource_id",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        None,
    );
    plan.capability.deleted_resource = Some(DeletedResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        requires_page_number_completion: false,
    });
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-1", "widget_id":"widget-1"}),
        query: json!({"cascade":true}),
        body: Some(json!({"reason":"must-not-cross-boundary"})),
        ..CallInput::default()
    })
    .expect("input");
    plan.status = PlanStatus::Consumed;
    let input: CallInput = serde_json::from_value(plan.input.clone()).expect("input");
    let catalog_hash = plan.catalog_hash.clone();
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .execute_consumed_plan_with_input(
            &mut plan,
            &catalog_hash,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
            &input,
        )
        .await
        .expect_err("broadening inputs must fail before network execution")
        .to_string();

    assert!(error.contains("outside the hash-bound collection readback contract"));
    assert!(!error.contains("must-not-cross-boundary"));
    assert_eq!(plan.status, PlanStatus::Consumed);
}

#[tokio::test]
async fn created_resource_is_verified_through_a_complete_parent_collection() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let mut requests = Vec::new();
        for page in 1..=2 {
            let (mut stream, _) = listener.accept().await.expect("accept verification");
            let mut buffer = vec![0_u8; 8192];
            let read = stream.read(&mut buffer).await.expect("read verification");
            requests.push(String::from_utf8_lossy(&buffer[..read]).to_string());
            let body = if page == 1 {
                r#"{"success":true,"result":[{"slug":"widget-other","name":"other","enabled":false}],"result_info":{"page":1,"total_pages":2}}"#
            } else {
                r#"{"success":true,"result":[{"slug":"secret-created-slug","name":"planned-secret-like-name","enabled":true}],"result_info":{"page":2,"total_pages":2}}"#
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write verification");
        }
        requests
    });
    let mut plan = dns_record_plan(
        "widgets-create",
        "POST",
        "/accounts/{account_id}/widgets",
        "parent_collection_contains_created_resource_id_and_planned_fields",
        json!({"account_id":"account-1"}),
        Some(json!({"name":"planned-secret-like-name", "enabled":true})),
    );
    plan.capability.created_collection_resource = Some(CreatedCollectionResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "slug".to_owned(),
        response_result_identity_pointer: "/slug".to_owned(),
        response_item_identity_pointer: "/slug".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        delete_capability_id: "widgets-delete".to_owned(),
        verified_response_fields: vec!["enabled".to_owned(), "name".to_owned()],
        requires_page_number_completion: true,
    });
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-1"}),
        query: json!({}),
        body: Some(json!({"name":"planned-secret-like-name", "enabled":true})),
        if_match: Some("mutation-etag".to_owned()),
        ..CallInput::default()
    })
    .expect("input");
    let apply = CloudflareResponseV1 {
        status: 201,
        success: true,
        result: json!({"slug":"secret-created-slug"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed, "{}", verification.basis);
    let requests = server.await.expect("server joins");
    assert!(requests[0].starts_with("GET /client/v4/accounts/account-1/widgets "));
    assert!(requests[1].starts_with("GET /client/v4/accounts/account-1/widgets?page=2 "));
    assert!(requests.iter().all(|request| {
        !request.contains("secret-created-slug")
            && !request.contains("planned-secret-like-name")
            && !request.contains("mutation_mode")
            && !request.contains("mutation-etag")
    }));
}

fn worker_tail_create_plan(body: Option<Value>) -> PlanV1 {
    let mut plan = dns_record_plan(
        "worker-tail-logs-start-tail",
        "POST",
        "/accounts/{account_id}/workers/scripts/{script_name}/tails",
        "worker_tail_collection_contains_created_lease_id",
        json!({"account_id":"account-1", "script_name":"edge-worker"}),
        body,
    );
    "Worker Tail Logs".clone_into(&mut plan.capability.product);
    "account".clone_into(&mut plan.capability.account_scope);
    plan.capability.permissions = vec![
        "Workers Tail Read".to_owned(),
        "Workers Scripts Write".to_owned(),
    ];
    plan.capability.selectors = ["account_id", "script_name"]
        .into_iter()
        .map(|name| SelectorV1 {
            name: name.to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        })
        .collect();
    plan.capability.risk = RiskClass::SecretSensitive;
    plan.capability.effect = EffectClass::ReversibleWrite;
    plan.capability.created_collection_resource = Some(CreatedCollectionResourceContractV1 {
        collection_path: plan.capability.path.clone(),
        identity_selector: "id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "worker-tail-logs-list-tails".to_owned(),
        delete_capability_id: "worker-tail-logs-delete-tail".to_owned(),
        verified_response_fields: Vec::new(),
        requires_page_number_completion: false,
    });
    plan.capability.rollback.supported = true;
    plan.capability.rollback.strategy = Some("delete_created_resource_by_returned_id".to_owned());
    plan
}

#[tokio::test]
async fn worker_tail_create_verifies_exact_lease_identity_without_a_fabricated_body() {
    let body = r#"{"success":true,"result":[{"id":"tail-lease-1","expires_at":"2026-07-21T18:00:00Z","url":"wss://tail.example.invalid/private-token"}],"errors":[]}"#;
    let (address, server) = json_response_sequence_server(vec![body]).await;
    let plan = worker_tail_create_plan(None);
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({
            "id":"tail-lease-1",
            "expires_at":"2026-07-21T18:00:00Z",
            "url":"wss://tail.example.invalid/private-token"
        }),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("tail verification result");

    assert!(verification.passed, "{}", verification.basis);
    assert!(verification.basis.contains("exactly one lease"));
    assert!(!verification.basis.contains("private-token"));
    let requests = server.await.expect("server joins");
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0]
            .starts_with("GET /client/v4/accounts/account-1/workers/scripts/edge-worker/tails ")
    );
    assert!(!requests[0].contains("private-token"));
}

#[tokio::test]
async fn worker_tail_create_fails_closed_on_identity_absence_or_any_body() {
    let body = r#"{"success":true,"result":[{"id":"different-tail"}],"errors":[]}"#;
    let (address, server) = json_response_sequence_server(vec![body]).await;
    let plan = worker_tail_create_plan(None);
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({
            "id":"tail-lease-1",
            "expires_at":"2026-07-21T18:00:00Z",
            "url":"wss://tail.example.invalid/private-token"
        }),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");
    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("tail verification result");
    assert!(!verification.passed);
    assert!(verification.basis.contains("identity matches=0"));
    assert!(!verification.basis.contains("tail-lease-1"));
    assert!(!verification.basis.contains("private-token"));
    server.await.expect("server joins");

    let body_plan = worker_tail_create_plan(Some(json!({"unsafe":"input"})));
    let offline = Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4")
        .expect("offline executor");
    let error = offline
        .verify_plan(
            &body_plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect_err("tail body must fail before network")
        .to_string();
    assert!(error.contains("Worker tail lease verification target is malformed"));
    assert!(!error.contains("private-token"));
}

fn async_list_plan(create: bool, body: Value) -> PlanV1 {
    let id = if create {
        "security-response-add-expiring-list-member"
    } else {
        "security-response-remove-expired-list-member"
    };
    let method = if create { "POST" } else { "DELETE" };
    let strategy = if create {
        "async_list_operation_completes_and_correlated_member_exists"
    } else {
        "async_list_operation_completes_and_members_absent"
    };
    let mut capability = CapabilityV1::new(
        id,
        id,
        method,
        "/accounts/{account_id}/rules/lists/{list_id}/items",
    );
    "Lists".clone_into(&mut capability.product);
    "account".clone_into(&mut capability.account_scope);
    capability.permissions = vec![
        "Account Filter Lists Edit".to_owned(),
        "Account Filter Lists Read".to_owned(),
    ];
    capability.selectors = ["account_id", "list_id"]
        .into_iter()
        .map(|name| SelectorV1 {
            name: name.to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        })
        .collect();
    capability.risk = RiskClass::IdentityOrOwnership;
    capability.effect = if create {
        EffectClass::ReversibleWrite
    } else {
        EffectClass::Destructive
    };
    strategy.clone_into(&mut capability.verification.strategy);
    capability.async_collection_mutation = Some(AsyncCollectionMutationContractV1 {
        operation_status_path: "/accounts/{account_id}/rules/lists/bulk_operations/{operation_id}"
            .to_owned(),
        operation_status_capability_id: "lists-get-bulk-operation-status".to_owned(),
        operation_id_selector: "operation_id".to_owned(),
        apply_operation_id_pointer: "/operation_id".to_owned(),
        status_operation_id_pointer: "/id".to_owned(),
        status_state_pointer: "/status".to_owned(),
        pending_states: vec!["pending".to_owned(), "running".to_owned()],
        completed_state: "completed".to_owned(),
        failed_state: "failed".to_owned(),
        max_poll_attempts: 30,
        poll_interval_ms: 1_000,
        collection_path: "/accounts/{account_id}/rules/lists/{list_id}/items".to_owned(),
        collection_capability_id: "lists-get-list-items".to_owned(),
        collection_metadata_path: "/accounts/{account_id}/rules/lists/{list_id}".to_owned(),
        collection_metadata_capability_id: "lists-get-a-list".to_owned(),
        collection_item_identity_pointer: "/id".to_owned(),
        correlation_field: create.then(|| "comment".to_owned()),
        remove_capability_id: create
            .then(|| "security-response-remove-expired-list-member".to_owned()),
        requires_cursor_completion: true,
    });
    let mut plan = PlanV1::draft(
        "profile",
        "account-1",
        "sha256:catalog",
        capability,
        json!({}),
    )
    .expect("plan");
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({
            "account_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "list_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        }),
        query: json!({}),
        body: Some(body),
        ..CallInput::default()
    })
    .expect("input");
    plan
}

#[tokio::test]
async fn async_list_add_polls_and_correlates_across_complete_cursor_pagination() {
    let comment = r#"{"cfctl_list_security_v1":{"evidence_ref":"sha256:redacted"}}"#;
    let plan = async_list_plan(true, json!([{"comment":comment,"ip":"203.0.113.17"}]));
    let operation_id = "bulk-operation-1";
    let member_id = "cccccccccccccccccccccccccccccccc";
    let bodies = vec![
        format!(r#"{{"success":true,"result":{{"id":"{operation_id}","status":"pending"}}}}"#),
        format!(r#"{{"success":true,"result":{{"id":"{operation_id}","completed":"2026-07-21T17:30:00Z","status":"completed"}}}}"#),
        r#"{"success":true,"result":[{"id":"dddddddddddddddddddddddddddddddd","comment":"other","ip":"198.51.100.1"}],"result_info":{"cursors":{"after":"cursor-2"}}}"#.to_owned(),
        format!(r#"{{"success":true,"result":[{{"id":"{member_id}","comment":{},"ip":"203.0.113.17"}}],"result_info":{{"cursors":{{"after":null}}}}}}"#, serde_json::to_string(comment).expect("comment JSON")),
    ];
    let (address, server) = json_response_sequence_server(bodies).await;
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"operation_id":operation_id}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("async List verification");

    assert!(verification.passed, "{}", verification.basis);
    assert_eq!(verification.correlated_resource_id, Some(json!(member_id)));
    let receipt = verification.readback.result.to_string();
    assert!(!receipt.contains("203.0.113.17"));
    assert!(!receipt.contains("evidence_ref"));
    let requests = server.await.expect("server joins");
    assert_eq!(requests.len(), 4);
    assert!(requests[0].contains(&format!("bulk_operations/{operation_id}")));
    assert!(
        requests[2].contains("/rules/lists/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/items?per_page=500")
    );
    assert!(requests[3].contains("cursor=cursor-2"));
    assert!(requests[3].contains("per_page=500"));
}

#[tokio::test]
async fn async_list_remove_requires_terminal_completion_and_complete_absence() {
    let member_id = "cccccccccccccccccccccccccccccccc";
    let plan = async_list_plan(false, json!({"items":[{"id":member_id}]}));
    let operation_id = "bulk-operation-delete";
    let bodies = vec![
        format!(r#"{{"success":true,"result":{{"id":"{operation_id}","status":"completed"}}}}"#),
        r#"{"success":true,"result":[{"id":"dddddddddddddddddddddddddddddddd","comment":"other","ip":"198.51.100.1"}],"result_info":{"cursors":{"after":null}}}"#.to_owned(),
    ];
    let (address, server) = json_response_sequence_server(bodies).await;
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"operation_id":operation_id}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");
    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("async List removal verification");
    assert!(verification.passed, "{}", verification.basis);
    assert!(verification.correlated_resource_id.is_none());
    let requests = server.await.expect("server joins");
    assert_eq!(requests.len(), 2);
}

#[tokio::test]
async fn async_list_failure_is_terminal_redacted_and_never_reads_the_collection() {
    let plan = async_list_plan(
        true,
        json!([{"comment":"sensitive-correlation","ip":"203.0.113.17"}]),
    );
    let operation_id = "bulk-operation-failed";
    let body = format!(
        r#"{{"success":true,"result":{{"id":"{operation_id}","status":"failed","error":"target 203.0.113.17 rejected"}}}}"#
    );
    let (address, server) = json_response_sequence_server(vec![body]).await;
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"operation_id":operation_id}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");
    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("terminal failure receipt");
    assert!(!verification.passed);
    assert!(
        !verification
            .readback
            .result
            .to_string()
            .contains("203.0.113.17")
    );
    assert!(
        !verification
            .readback
            .result
            .to_string()
            .contains("sensitive-correlation")
    );
    assert_eq!(server.await.expect("server joins").len(), 1);
}

#[tokio::test]
async fn nested_resource_creation_is_correlated_in_apply_and_live_parent_readback() {
    let body = r#"{"success":true,"result":{"id":"ruleset-1","rules":[{"id":"rule-1","action":"managed_challenge","description":"bounded action","enabled":true,"expression":"ip.src eq 1.1.1.1","ref":"cfctl_security_0123456789abcdef01234567"}]},"errors":[]}"#;
    let (address, server) = json_response_sequence_server(vec![body]).await;
    let planned_body = json!({
        "action":"managed_challenge",
        "description":"bounded action",
        "enabled":true,
        "expression":"ip.src eq 1.1.1.1",
        "ref":"cfctl_security_0123456789abcdef01234567"
    });
    let mut plan = dns_record_plan(
        "ruleset-rule-create",
        "POST",
        "/zones/{zone_id}/rulesets/{ruleset_id}/rules",
        "parent_object_contains_created_nested_resource_by_correlation",
        json!({"zone_id":"zone-1", "ruleset_id":"ruleset-1"}),
        Some(planned_body.clone()),
    );
    plan.capability.request_schema = Some(json!({
        "type":"object",
        "properties":{
            "action":{"type":"string"},
            "description":{"type":"string"},
            "enabled":{"type":"boolean"},
            "expression":{"type":"string"},
            "ref":{"type":"string"}
        }
    }));
    plan.capability.created_nested_resource = Some(CreatedNestedResourceContractV1 {
        parent_path: "/zones/{zone_id}/rulesets/{ruleset_id}".to_owned(),
        items_pointer: "/rules".to_owned(),
        identity_selector: "rule_id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        correlation_field: "ref".to_owned(),
        read_capability_id: "ruleset-get".to_owned(),
        delete_capability_id: "ruleset-rule-delete".to_owned(),
        delete_path: "/zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}".to_owned(),
        verified_response_fields: vec![
            "action".to_owned(),
            "description".to_owned(),
            "enabled".to_owned(),
            "expression".to_owned(),
            "ref".to_owned(),
        ],
    });
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({
            "id":"ruleset-1",
            "rules":[{
                "id":"rule-1",
                "action":"managed_challenge",
                "description":"bounded action",
                "enabled":true,
                "expression":"ip.src eq 1.1.1.1",
                "ref":"cfctl_security_0123456789abcdef01234567"
            }]
        }),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed, "{}", verification.basis);
    let requests = server.await.expect("server joins");
    let request = &requests[0];
    assert!(request.starts_with("GET /client/v4/zones/zone-1/rulesets/ruleset-1 HTTP/1.1"));
    assert!(!request.contains("rule-1"));
    assert!(!request.contains("cfctl_security_0123456789abcdef01234567"));
}

#[tokio::test]
async fn nested_resource_creation_rejects_ambiguous_apply_correlation() {
    let body = r#"{"success":true,"result":{"rules":[{"id":"rule-1","action":"managed_challenge","ref":"duplicate-ref"}]},"errors":[]}"#;
    let (address, server) = json_response_sequence_server(vec![body]).await;
    let mut plan = dns_record_plan(
        "ruleset-rule-create",
        "POST",
        "/zones/{zone_id}/rulesets/{ruleset_id}/rules",
        "parent_object_contains_created_nested_resource_by_correlation",
        json!({"zone_id":"zone-1", "ruleset_id":"ruleset-1"}),
        Some(json!({"action":"managed_challenge", "ref":"duplicate-ref"})),
    );
    plan.capability.request_schema = Some(json!({
        "type":"object",
        "properties":{"action":{"type":"string"}, "ref":{"type":"string"}}
    }));
    plan.capability.created_nested_resource = Some(CreatedNestedResourceContractV1 {
        parent_path: "/zones/{zone_id}/rulesets/{ruleset_id}".to_owned(),
        items_pointer: "/rules".to_owned(),
        identity_selector: "rule_id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        correlation_field: "ref".to_owned(),
        read_capability_id: "ruleset-get".to_owned(),
        delete_capability_id: "ruleset-rule-delete".to_owned(),
        delete_path: "/zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}".to_owned(),
        verified_response_fields: vec!["action".to_owned(), "ref".to_owned()],
    });
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"rules":[
            {"id":"rule-1", "action":"managed_challenge", "ref":"duplicate-ref"},
            {"id":"rule-2", "action":"managed_challenge", "ref":"duplicate-ref"}
        ]}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(!verification.passed);
    assert!(verification.basis.contains("apply matches=2"));
    assert!(!verification.basis.contains("duplicate-ref"));
    server.await.expect("server joins");
}

#[tokio::test]
async fn exact_nested_resource_deletion_is_verified_by_parent_object_absence() {
    let body =
        r#"{"success":true,"result":{"id":"ruleset-1","rules":[{"id":"rule-2"}]},"errors":[]}"#;
    let (address, server) = json_response_sequence_server(vec![body]).await;
    let mut plan = dns_record_plan(
        "ruleset-rule-delete",
        "DELETE",
        "/zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}",
        "parent_object_omits_deleted_nested_resource_id",
        json!({"zone_id":"zone-1", "ruleset_id":"ruleset-1", "rule_id":"rule-1"}),
        None,
    );
    plan.capability.deleted_nested_resource = Some(DeletedNestedResourceContractV1 {
        parent_path: "/zones/{zone_id}/rulesets/{ruleset_id}".to_owned(),
        collection_path: "/zones/{zone_id}/rulesets/{ruleset_id}/rules".to_owned(),
        items_pointer: "/rules".to_owned(),
        identity_selector: "rule_id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "ruleset-get".to_owned(),
    });
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"ruleset-1", "rules":[{"id":"rule-2"}]}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed, "{}", verification.basis);
    let requests = server.await.expect("server joins");
    let request = &requests[0];
    assert!(request.starts_with("GET /client/v4/zones/zone-1/rulesets/ruleset-1 HTTP/1.1"));
    assert!(!request.contains("rule-1"));
}

#[tokio::test]
async fn web_analytics_rule_creation_is_verified_through_the_sibling_rule_list() {
    let body = r#"{"success":true,"result":{"rules":[{"id":"rum-rule-1","host":"example.com","inclusive":true,"paths":["/app/*"]}],"ruleset":{"id":"rum-ruleset-1"}},"errors":[]}"#;
    let (address, server) = json_response_sequence_server(vec![body]).await;
    let mut plan = dns_record_plan(
        "web-analytics-create-rule",
        "POST",
        "/accounts/{account_id}/rum/v2/{ruleset_id}/rule",
        "web_analytics_rule_list_contains_created_id_and_planned_fields",
        json!({"account_id":"account-1", "ruleset_id":"rum-ruleset-1"}),
        Some(json!({"host":"example.com", "inclusive":true, "paths":["/app/*"]})),
    );
    plan.capability.permissions = vec![
        "Account Settings Read".to_owned(),
        "Account Settings Write".to_owned(),
    ];
    plan.capability.request_schema = Some(json!({
        "type":"object",
        "properties":{
            "host":{"type":"string"},
            "inclusive":{"type":"boolean"},
            "is_paused":{"type":"boolean"},
            "paths":{"type":"array","items":{"type":"string"}}
        }
    }));
    plan.capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: "/accounts/{account_id}/rum/v2/{ruleset_id}/rule/{rule_id}".to_owned(),
        identity_selector: "rule_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        read_capability_id: "web-analytics-list-rules".to_owned(),
        delete_capability_id: "web-analytics-delete-rule".to_owned(),
        verified_response_fields: vec![
            "host".to_owned(),
            "inclusive".to_owned(),
            "is_paused".to_owned(),
            "paths".to_owned(),
        ],
    });
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({
            "id":"rum-rule-1",
            "host":"example.com",
            "inclusive":true,
            "paths":["/app/*"]
        }),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed, "{}", verification.basis);
    let requests = server.await.expect("server joins");
    assert!(
        requests[0]
            .starts_with("GET /client/v4/accounts/account-1/rum/v2/rum-ruleset-1/rules HTTP/1.1")
    );
    assert!(!requests[0].contains("rum-rule-1"));
}

#[tokio::test]
async fn web_analytics_rule_deletion_is_verified_by_sibling_list_absence() {
    let body = r#"{"success":true,"result":{"rules":[{"id":"rum-rule-2"}],"ruleset":{"id":"rum-ruleset-1"}},"errors":[]}"#;
    let (address, server) = json_response_sequence_server(vec![body]).await;
    let mut plan = dns_record_plan(
        "web-analytics-delete-rule",
        "DELETE",
        "/accounts/{account_id}/rum/v2/{ruleset_id}/rule/{rule_id}",
        "web_analytics_rule_list_omits_deleted_id",
        json!({
            "account_id":"account-1",
            "ruleset_id":"rum-ruleset-1",
            "rule_id":"rum-rule-1"
        }),
        None,
    );
    plan.capability.permissions = vec![
        "Account Settings Read".to_owned(),
        "Account Settings Write".to_owned(),
    ];
    plan.capability.same_path_read = Some(SamePathReadContractV1 {
        path: "/accounts/{account_id}/rum/v2/{ruleset_id}/rules".to_owned(),
        read_capability_id: "web-analytics-list-rules".to_owned(),
        verified_response_fields: Vec::new(),
    });
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"rum-rule-1"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed, "{}", verification.basis);
    let requests = server.await.expect("server joins");
    assert!(
        requests[0]
            .starts_with("GET /client/v4/accounts/account-1/rum/v2/rum-ruleset-1/rules HTTP/1.1")
    );
    assert!(!requests[0].contains("rum-rule-1"));
}

#[tokio::test]
async fn parent_collection_create_rejects_field_drift_without_echoing_values() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let _ = stream.read(&mut buffer).await.expect("read verification");
        let body = r#"{"success":true,"result":[{"id":"secret-created-id","name":"unexpected-live-value"}]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
    });
    let mut plan = dns_record_plan(
        "widgets-create",
        "POST",
        "/accounts/{account_id}/widgets",
        "parent_collection_contains_created_resource_id_and_planned_fields",
        json!({"account_id":"account-1"}),
        Some(json!({"name":"planned-secret-like-name"})),
    );
    plan.capability.created_collection_resource = Some(CreatedCollectionResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        delete_capability_id: "widgets-delete".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
        requires_page_number_completion: false,
    });
    let apply = CloudflareResponseV1 {
        status: 201,
        success: true,
        result: json!({"id":"secret-created-id"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(!verification.passed);
    assert!(verification.basis.contains("planned fields match=false"));
    assert!(!verification.basis.contains("secret-created-id"));
    assert!(!verification.basis.contains("planned-secret-like-name"));
    assert!(!verification.basis.contains("unexpected-live-value"));
    server.await.expect("server joins");
}

#[tokio::test]
async fn parent_collection_create_rejects_unbound_fields_before_the_mutation_boundary() {
    let mut plan = dns_record_plan(
        "widgets-create",
        "POST",
        "/accounts/{account_id}/widgets",
        "parent_collection_contains_created_resource_id_and_planned_fields",
        json!({"account_id":"account-1"}),
        Some(json!({"hidden":true})),
    );
    plan.capability.created_collection_resource = Some(CreatedCollectionResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        delete_capability_id: "widgets-delete".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
        requires_page_number_completion: false,
    });
    plan.status = PlanStatus::Consumed;
    let input: CallInput = serde_json::from_value(plan.input.clone()).expect("input");
    let catalog_hash = plan.catalog_hash.clone();
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .execute_consumed_plan_with_input(
            &mut plan,
            &catalog_hash,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
            &input,
        )
        .await
        .expect_err("unbound field must fail before network execution")
        .to_string();

    assert!(error.contains("outside the hash-bound collection readback fields"));
    assert_eq!(plan.status, PlanStatus::Consumed);
}

#[tokio::test]
async fn exact_resource_update_is_verified_by_same_path_planned_fields() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let read = stream.read(&mut buffer).await.expect("read verification");
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let body = r#"{"success":true,"result":{"id":"widget-1","name":"after","settings":{"enabled":true,"mode":"strict"},"server_default":"kept"},"errors":[]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
        request
    });
    let mut plan = dns_record_plan(
        "widgets-update",
        "PATCH",
        "/accounts/{account_id}/widgets/{widget_id}",
        "same_resource_contains_planned_fields_after_update",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        Some(json!({
            "name":"after",
            "settings":{"enabled":true,"mode":"strict"},
            "secret":"must-not-be-returned"
        })),
    );
    plan.capability.request_schema = Some(all_of_update_request_schema());
    plan.capability
        .same_path_read
        .as_mut()
        .expect("same-path readback")
        .verified_response_fields = vec!["name".to_owned(), "settings".to_owned()];
    plan.capability.product = "R2 Object".to_owned();
    plan.capability.selectors.push(SelectorV1 {
        name: "cf-r2-jurisdiction".to_owned(),
        location: "header".to_owned(),
        required: false,
        value_type: "string".to_owned(),
        description: None,
        contract: None,
    });
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({
            "account_id":"account-1",
            "widget_id":"widget-1",
            "cf-r2-jurisdiction":"fedramp"
        }),
        query: json!({}),
        body: Some(json!({
            "name":"after",
            "settings":{"enabled":true,"mode":"strict"},
            "secret":"must-not-be-returned"
        })),
        if_match: Some("mutation-etag".to_owned()),
        ..CallInput::default()
    })
    .expect("input");
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"widget-1"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed, "{}", verification.basis);
    let request = server.await.expect("server joins");
    assert!(request.starts_with("GET /client/v4/accounts/account-1/widgets/widget-1 "));
    assert!(!request.contains("mutation_mode"));
    assert!(!request.contains("mutation-etag"));
    assert!(!verification.basis.contains("must-not-be-returned"));
    assert!(request.contains("cf-r2-jurisdiction: fedramp\r\n"));
}

fn all_of_update_request_schema() -> Value {
    json!({
        "allOf": [
            {
                "type":"object",
                "properties": {
                    "name":{"type":"string"},
                    "secret":{"type":"string", "writeOnly":true}
                }
            },
            {
                "properties": {
                    "settings":{
                        "type":"object",
                        "properties": {
                            "enabled":{"type":"boolean"},
                            "mode":{"type":"string"}
                        }
                    }
                }
            }
        ]
    })
}

#[tokio::test]
async fn exact_resource_update_projects_branch_local_write_only_inputs() {
    let (address, server) = json_response_sequence_server(vec![
        r#"{"success":true,"result":{"id":"widget-1","name":"after","config":{"client_id":"public-id"}},"errors":[]}"#,
    ])
    .await;
    let mut plan = dns_record_plan(
        "widgets-update",
        "PATCH",
        "/accounts/{account_id}/widgets/{widget_id}",
        "same_resource_contains_planned_fields_after_update",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        Some(json!({
            "name":"after",
            "secret":"must-not-be-returned",
            "config":{
                "client_id":"public-id",
                "client_secret":"nested-must-not-be-returned"
            }
        })),
    );
    plan.capability.request_schema = Some(json!({
        "oneOf": [
            {
                "type":"object",
                "required":["name", "secret", "config"],
                "properties": {
                    "name":{"type":"string"},
                    "secret":{"type":"string", "writeOnly":true},
                    "config":{
                        "type":"object",
                        "required":["client_id", "client_secret"],
                        "properties":{
                            "client_id":{"type":"string"},
                            "client_secret":{"type":"string", "writeOnly":true}
                        }
                    }
                }
            },
            {
                "type":"object",
                "required":["enabled"],
                "properties":{"enabled":{"type":"boolean"}}
            }
        ]
    }));
    plan.capability
        .same_path_read
        .as_mut()
        .expect("same-path readback")
        .verified_response_fields =
        vec!["config".to_owned(), "enabled".to_owned(), "name".to_owned()];
    let input = CallInput {
        selectors: json!({"account_id":"account-1", "widget_id":"widget-1"}),
        body: Some(json!({
            "name":"after",
            "secret":"must-not-be-returned",
            "config":{
                "client_id":"public-id",
                "client_secret":"nested-must-not-be-returned"
            }
        })),
        ..CallInput::default()
    };
    RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("builder")
        .build_unchecked(&plan.capability, &input)
        .expect("hash-bound body should match exactly one request branch");
    plan.input = serde_json::to_value(input).expect("input");
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"widget-1"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("branch-local write-only input should remain outside readback");

    assert!(verification.passed, "{}", verification.basis);
    assert!(!verification.basis.contains("must-not-be-returned"));
    assert!(!verification.basis.contains("nested-must-not-be-returned"));
    let requests = server.await.expect("server joins");
    assert_eq!(requests.len(), 1);
}

#[tokio::test]
async fn created_resource_is_read_back_by_hash_bound_identity_and_planned_fields() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let read = stream.read(&mut buffer).await.expect("read verification");
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let body = r#"{"success":true,"result":{"slug":"widget-one","name":"created","settings":{"enabled":true},"server_default":"kept"},"errors":[]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
        request
    });
    let mut plan = dns_record_plan(
        "widgets-create",
        "POST",
        "/accounts/{account_id}/widgets",
        "created_resource_contains_planned_fields_by_returned_id",
        json!({"account_id":"account-1"}),
        Some(json!({"name":"created", "settings":{"enabled":true}})),
    );
    plan.capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: "/accounts/{account_id}/widgets/{slug}".to_owned(),
        identity_selector: "slug".to_owned(),
        response_result_identity_pointer: "/slug".to_owned(),
        read_capability_id: "widgets-get".to_owned(),
        delete_capability_id: "widgets-delete".to_owned(),
        verified_response_fields: vec!["name".to_owned(), "settings".to_owned()],
    });
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-1"}),
        query: json!({}),
        body: Some(json!({"name":"created", "settings":{"enabled":true}})),
        if_match: Some("mutation-etag".to_owned()),
        ..CallInput::default()
    })
    .expect("input");
    let apply = CloudflareResponseV1 {
        status: 201,
        success: true,
        result: json!({"slug":"widget-one"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed, "{}", verification.basis);
    let request = server.await.expect("server joins");
    assert!(request.starts_with("GET /client/v4/accounts/account-1/widgets/widget-one "));
    assert!(!request.contains("mutation_mode"));
    assert!(!request.contains("mutation-etag"));
    assert!(!request.contains("\"name\":\"created\""));
}

fn pages_production_deployment_plan() -> PlanV1 {
    let mut plan = dns_record_plan(
        "pages-deployment-create-deployment",
        "POST",
        "/accounts/{account_id}/pages/projects/{project_name}/deployments",
        "pages_production_deployment_succeeds_by_returned_id",
        json!({"account_id":"account-1","project_name":"aos-web"}),
        None,
    );
    plan.capability.adapter_status = AdapterStatus::DynamicApi;
    "Pages Deployment".clone_into(&mut plan.capability.product);
    "account".clone_into(&mut plan.capability.account_scope);
    plan.capability.permissions = vec!["Pages Write".to_owned()];
    plan.capability.risk = RiskClass::CrossConfig;
    plan.capability.effect = EffectClass::ReversibleWrite;
    plan.capability.request_schema = None;
    plan.capability.selectors = ["account_id", "project_name"]
        .map(|name| SelectorV1 {
            name: name.to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        })
        .to_vec();
    plan.capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path:
            "/accounts/{account_id}/pages/projects/{project_name}/deployments/{deployment_id}"
                .to_owned(),
        identity_selector: "deployment_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        read_capability_id: "pages-deployment-get-deployment-info".to_owned(),
        delete_capability_id: "pages-deployment-delete-deployment".to_owned(),
        verified_response_fields: vec!["environment".to_owned(), "project_name".to_owned()],
    });
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-1","project_name":"aos-web"}),
        query: json!({}),
        body: None,
        ..CallInput::default()
    })
    .expect("input");
    plan
}

#[tokio::test]
async fn pages_production_deployment_polls_exact_returned_id_to_success() {
    let (address, server) = json_response_sequence_server(vec![
        r#"{"success":true,"result":{"id":"f64788e9-fccd-4d4a-a28a-cb84f88f6","project_name":"aos-web","environment":"production","latest_stage":{"status":"active"}},"errors":[]}"#,
        r#"{"success":true,"result":{"id":"f64788e9-fccd-4d4a-a28a-cb84f88f6","project_name":"aos-web","environment":"production","latest_stage":{"status":"success"}},"errors":[]}"#,
    ])
    .await;
    let plan = pages_production_deployment_plan();
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"f64788e9-fccd-4d4a-a28a-cb84f88f6"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("Pages verification");

    assert!(verification.passed, "{}", verification.basis);
    let requests = server.await.expect("server joins");
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with(
        "GET /client/v4/accounts/account-1/pages/projects/aos-web/deployments/f64788e9-fccd-4d4a-a28a-cb84f88f6 "
    ));
}

#[tokio::test]
async fn pages_production_deployment_rejects_wrong_project_or_failed_stage() {
    let (address, server) = json_response_sequence_server(vec![
        r#"{"success":true,"result":{"id":"f64788e9-fccd-4d4a-a28a-cb84f88f6","project_name":"different-project","environment":"production","latest_stage":{"status":"failure"}},"errors":[]}"#,
    ])
    .await;
    let plan = pages_production_deployment_plan();
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"f64788e9-fccd-4d4a-a28a-cb84f88f6"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("Pages verification receipt");

    assert!(!verification.passed);
    assert!(verification.basis.contains("project match=false"));
    assert!(
        verification
            .basis
            .contains("terminal stage=Some(\"failure\")")
    );
    assert_eq!(server.await.expect("server joins").len(), 1);
}

fn oauth_client_create_plan() -> PlanV1 {
    let body = json!({
        "client_name":"cfctl",
        "grant_types":["authorization_code","refresh_token"],
        "redirect_uris":["https://cfctl.com/oauth/callback"],
        "response_types":["code"],
        "scopes":["account:read"],
        "token_endpoint_auth_method":"none"
    });
    let mut plan = dns_record_plan(
        "oauth-clients-create",
        "POST",
        "/accounts/{account_id}/oauth_clients",
        "created_resource_contains_planned_fields_by_returned_id",
        json!({"account_id":"account-1"}),
        Some(body),
    );
    "OAuth Clients".clone_into(&mut plan.capability.product);
    "account".clone_into(&mut plan.capability.account_scope);
    plan.capability.permissions = vec![
        "OAuth Client Write".to_owned(),
        "OAuth Client Read".to_owned(),
    ];
    plan.capability.selectors = vec![SelectorV1 {
        name: "account_id".to_owned(),
        location: "path".to_owned(),
        required: true,
        value_type: "string".to_owned(),
        description: None,
        contract: None,
    }];
    plan.capability.request_schema = Some(json!({
        "type":"object",
        "additionalProperties":false,
        "x-cfctl-body-required":true,
        "required":[
            "client_name",
            "grant_types",
            "redirect_uris",
            "response_types",
            "scopes",
            "token_endpoint_auth_method"
        ],
        "properties":{
            "allowed_cors_origins":{"type":"array","items":{"type":"string"}},
            "client_name":{"type":"string"},
            "client_uri":{"type":"string"},
            "grant_types":{"type":"array","items":{"type":"string"}},
            "logo_uri":{"type":"string"},
            "policy_uri":{"type":"string"},
            "post_logout_redirect_uris":{"type":"array","items":{"type":"string"}},
            "redirect_uris":{"type":"array","items":{"type":"string"}},
            "response_types":{"type":"array","items":{"type":"string"}},
            "scopes":{"type":"array","items":{"type":"string"}},
            "token_endpoint_auth_method":{"type":"string","enum":["none","client_secret_basic","client_secret_post"]},
            "tos_uri":{"type":"string"}
        }
    }));
    plan.capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: "/accounts/{account_id}/oauth_clients/{oauth_client_id}".to_owned(),
        identity_selector: "oauth_client_id".to_owned(),
        response_result_identity_pointer: "/client_id".to_owned(),
        read_capability_id: "oauth-clients-get".to_owned(),
        delete_capability_id: "oauth-clients-delete".to_owned(),
        verified_response_fields: vec![
            "allowed_cors_origins".to_owned(),
            "client_name".to_owned(),
            "client_uri".to_owned(),
            "grant_types".to_owned(),
            "logo_uri".to_owned(),
            "policy_uri".to_owned(),
            "post_logout_redirect_uris".to_owned(),
            "redirect_uris".to_owned(),
            "response_types".to_owned(),
            "scopes".to_owned(),
            "token_endpoint_auth_method".to_owned(),
            "tos_uri".to_owned(),
        ],
    });
    plan.capability.rollback.supported = false;
    plan.capability.rollback.strategy = None;
    plan.capability.rollback.warning =
        Some("deletion requires a separately reviewed destructive plan".to_owned());
    plan
}

#[tokio::test]
async fn oauth_client_create_uses_returned_client_id_for_exact_non_secret_readback() {
    let plan = oauth_client_create_plan();
    assert!(plan.capability.verification_contract_supported());
    let input: CallInput = serde_json::from_value(plan.input.clone()).expect("plan input");
    let prepared = RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("request builder")
        .build_unchecked(&plan.capability, &input)
        .expect("OAuth client create request");
    assert_eq!(prepared.method, "POST");
    assert_eq!(
        prepared.url.as_str(),
        "https://api.cloudflare.com/client/v4/accounts/account-1/oauth_clients"
    );
    assert_eq!(prepared.body, input.body);
    assert!(
        !prepared
            .body
            .expect("request body")
            .to_string()
            .contains("secret")
    );

    let body = r#"{"success":true,"result":{"client_id":"oauth-client-1","client_name":"cfctl","grant_types":["authorization_code","refresh_token"],"redirect_uris":["https://cfctl.com/oauth/callback"],"response_types":["code"],"scopes":["account:read"],"token_endpoint_auth_method":"none","visibility":"private"},"errors":[]}"#;
    let (address, server) = json_response_sequence_server(vec![body]).await;
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({
            "client_id":"oauth-client-1",
            "client_secret":"one-time-response-only"
        }),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let verification = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .verify_plan(
        &plan,
        &apply,
        &AuthCredential::Bearer {
            token: "governing-token".to_owned(),
        },
    )
    .await
    .expect("OAuth client verification");

    assert!(verification.passed, "{}", verification.basis);
    assert!(!verification.basis.contains("one-time-response-only"));
    let requests = server.await.expect("server joins");
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0].starts_with("GET /client/v4/accounts/account-1/oauth_clients/oauth-client-1 ")
    );
    assert!(!requests[0].contains("one-time-response-only"));
}

fn worker_domain_attach_plan() -> PlanV1 {
    let body = json!({
        "hostname": "cfctl.com",
        "service": "cfctl-site",
        "zone_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    });
    let mut plan = dns_record_plan(
        "workers.domains.update",
        "PUT",
        "/accounts/{account_id}/workers/domains",
        "created_resource_contains_planned_fields_by_returned_id",
        json!({"account_id":"account-1"}),
        Some(body),
    );
    "Domains".clone_into(&mut plan.capability.product);
    "account".clone_into(&mut plan.capability.account_scope);
    plan.capability.permissions = vec!["Workers Scripts Write".to_owned()];
    plan.capability.selectors = vec![SelectorV1 {
        name: "account_id".to_owned(),
        location: "path".to_owned(),
        required: true,
        value_type: "string".to_owned(),
        description: None,
        contract: None,
    }];
    plan.capability.request_schema = Some(json!({
        "type": "object",
        "additionalProperties": false,
        "x-cfctl-body-required": true,
        "required": ["hostname", "service", "zone_id"],
        "properties": {
            "hostname": {"type": "string", "minLength": 1, "maxLength": 253},
            "service": {"type": "string", "minLength": 1},
            "zone_id": {"type": "string", "minLength": 32, "maxLength": 32}
        }
    }));
    plan.capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: "/accounts/{account_id}/workers/domains/{domain_id}".to_owned(),
        identity_selector: "domain_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        read_capability_id: "workers.domains.get".to_owned(),
        delete_capability_id: "workers.domains.delete".to_owned(),
        verified_response_fields: vec![
            "hostname".to_owned(),
            "service".to_owned(),
            "zone_id".to_owned(),
        ],
    });
    plan.capability.rollback.supported = true;
    plan.capability.rollback.strategy = Some("delete_created_resource_by_returned_id".to_owned());
    plan.capability.rollback.warning = Some("separate reviewed detach plan".to_owned());
    plan
}

#[tokio::test]
async fn worker_domain_put_is_built_exactly_and_verified_by_returned_domain_id() {
    let plan = worker_domain_attach_plan();
    assert!(plan.capability.verification_contract_supported());
    assert!(plan.capability.rollback_contract_supported());
    let input: CallInput = serde_json::from_value(plan.input.clone()).expect("plan input");
    let prepared = RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("request builder")
        .build_unchecked(&plan.capability, &input)
        .expect("Worker domain attach request");
    assert_eq!(prepared.method, "PUT");
    assert_eq!(
        prepared.url.as_str(),
        "https://api.cloudflare.com/client/v4/accounts/account-1/workers/domains"
    );
    assert_eq!(
        prepared.body,
        Some(json!({
            "hostname": "cfctl.com",
            "service": "cfctl-site",
            "zone_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }))
    );

    let body = r#"{"success":true,"result":{"id":"domain-1","hostname":"cfctl.com","service":"cfctl-site","zone_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"errors":[]}"#;
    let (address, server) = json_response_sequence_server(vec![body]).await;
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"domain-1"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let verification = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .verify_plan(
        &plan,
        &apply,
        &AuthCredential::Bearer {
            token: "governing-token".to_owned(),
        },
    )
    .await
    .expect("Worker domain verification");

    assert!(verification.passed, "{}", verification.basis);
    let requests = server.await.expect("server joins");
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("GET /client/v4/accounts/account-1/workers/domains/domain-1 "));
    assert!(!requests[0].contains("cfctl.com"));
}

fn access_application_create_plan(body: serde_json::Value) -> PlanV1 {
    let mut plan = dns_record_plan(
        "access-applications-add-an-application",
        "POST",
        "/accounts/{account_id}/access/apps",
        "created_access_application_contains_planned_fields_by_returned_id",
        json!({"account_id":"account-1"}),
        Some(body),
    );
    "Access applications".clone_into(&mut plan.capability.product);
    plan.capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: "/accounts/{account_id}/access/apps/{app_id}".to_owned(),
        identity_selector: "app_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        read_capability_id: "access-applications-get-an-access-application".to_owned(),
        delete_capability_id: "access-applications-delete-an-access-application".to_owned(),
        verified_response_fields: vec!["name".to_owned(), "type".to_owned()],
    });
    plan
}

#[tokio::test]
async fn access_application_create_verifies_only_the_fields_a_variant_actually_sends() {
    // A saas app plans no `domain`, yet the curated contract lists only
    // `name`/`type`; verification must pass on the readback echoing them and
    // must not fault the absent variant-only field.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let read = stream.read(&mut buffer).await.expect("read verification");
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let body =
            r#"{"success":true,"result":{"id":"app-1","name":"SSO","type":"saas"},"errors":[]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
        request
    });
    let plan = access_application_create_plan(json!({"name":"SSO","type":"saas"}));
    let apply = CloudflareResponseV1 {
        status: 201,
        success: true,
        result: json!({"id":"app-1"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed, "{}", verification.basis);
    let request = server.await.expect("server joins");
    assert!(request.starts_with("GET /client/v4/accounts/account-1/access/apps/app-1 "));
}

#[tokio::test]
async fn access_application_create_faults_when_a_planned_field_drifts() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let _ = stream.read(&mut buffer).await.expect("read verification");
        // Readback reports a different name than planned.
        let body = r#"{"success":true,"result":{"id":"app-1","name":"WRONG","type":"self_hosted"},"errors":[]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
    });
    let plan = access_application_create_plan(
        json!({"name":"real","type":"self_hosted","domain":"x.example.com"}),
    );
    let apply = CloudflareResponseV1 {
        status: 201,
        success: true,
        result: json!({"id":"app-1"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(!verification.passed, "{}", verification.basis);
    server.await.expect("server joins");
}

fn r2_bucket_create_plan() -> PlanV1 {
    let mut plan = dns_record_plan(
        "r2-create-bucket",
        "POST",
        "/accounts/{account_id}/r2/buckets",
        "created_resource_contains_planned_fields_by_returned_id",
        json!({"account_id":"account-1", "cf-r2-jurisdiction":"eu"}),
        Some(json!({
            "name":"smoke-bucket",
            "locationHint":"weur",
            "storageClass":"InfrequentAccess"
        })),
    );
    "R2 Bucket".clone_into(&mut plan.capability.product);
    plan.capability.selectors = vec![
        SelectorV1 {
            name: "account_id".to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        },
        SelectorV1 {
            name: "cf-r2-jurisdiction".to_owned(),
            location: "header".to_owned(),
            required: false,
            value_type: "string".to_owned(),
            description: None,
            contract: Some(SelectorContractV1 {
                schema: json!({"enum":["default","eu","fedramp"],"type":"string"}),
                query: None,
            }),
        },
    ];
    plan.capability.request_schema = Some(json!({
        "type":"object",
        "required":["name"],
        "properties":{
            "locationHint":{
                "enum":["apac","eeur","enam","weur","wnam","oc"],
                "type":"string",
                "x-cfctl-verification-observable":false
            },
            "name":{"minLength":3,"maxLength":64,"type":"string"},
            "storageClass":{
                "enum":["Standard","InfrequentAccess"],
                "type":"string",
                "x-cfctl-verification-response-field":"storage_class"
            }
        },
        "x-cfctl-body-required":true
    }));
    plan.capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: "/accounts/{account_id}/r2/buckets/{bucket_name}".to_owned(),
        identity_selector: "bucket_name".to_owned(),
        response_result_identity_pointer: "/name".to_owned(),
        read_capability_id: "r2-get-bucket".to_owned(),
        delete_capability_id: "r2-delete-bucket".to_owned(),
        verified_response_fields: vec!["name".to_owned(), "storageClass".to_owned()],
    });
    assert!(plan.capability.verification_contract_supported());
    plan
}

#[tokio::test]
async fn r2_bucket_create_preserves_jurisdiction_and_verifies_storage_class_mapping() {
    let (address, server) = json_response_sequence_server(vec![
        r#"{"success":true,"result":{"name":"smoke-bucket","jurisdiction":"eu","location":"weur","storage_class":"InfrequentAccess"},"errors":[]}"#,
        r#"{"success":true,"result":{"name":"smoke-bucket","jurisdiction":"eu","location":"weur","storage_class":"Standard"},"errors":[]}"#,
        r#"{"success":true,"result":{"name":"smoke-bucket","jurisdiction":"eu","location":"weur","storage_class":"Standard","forged_storage_class":"InfrequentAccess"},"errors":[]}"#,
    ])
    .await;
    let plan = r2_bucket_create_plan();
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"name":"smoke-bucket"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verified = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("R2 bucket verification");
    assert!(verified.passed, "{}", verified.basis);
    let drifted = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("storage-class drift is a failed verification");
    assert!(!drifted.passed, "{}", drifted.basis);
    assert!(drifted.basis.contains("storageClass"));
    let mut forged_mapping = plan.clone();
    forged_mapping
        .capability
        .request_schema
        .as_mut()
        .expect("request schema")["properties"]["storageClass"]["x-cfctl-verification-response-field"] =
        json!("forged_storage_class");
    assert!(forged_mapping.capability.verification_contract_supported());
    let forged = executor
        .verify_plan(
            &forged_mapping,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("forged response-field mapping fails closed");
    assert!(!forged.passed, "{}", forged.basis);
    assert!(forged.basis.contains("storageClass"));
    let requests = server.await.expect("server joins");
    assert!(requests.iter().all(|request| {
        request.starts_with("GET /client/v4/accounts/account-1/r2/buckets/smoke-bucket ")
            && request
                .to_ascii_lowercase()
                .contains("cf-r2-jurisdiction: eu")
    }));
}

#[tokio::test]
async fn created_resource_verification_projects_write_only_request_values() {
    let (address, server) = json_response_sequence_server(vec![
            r#"{"success":true,"result":{"id":"widget-1","name":"created","credentials":{"username":"operator"},"headers":[{"name":"Authorization"}]},"errors":[]}"#,
            r#"{"success":true,"result":{"id":"widget-1","name":"created","credentials":{"username":"different"},"headers":[{"name":"Authorization"}]},"errors":[]}"#,
        ])
        .await;
    let mut plan = dns_record_plan(
        "widgets-create",
        "POST",
        "/accounts/{account_id}/widgets",
        "created_resource_contains_planned_fields_by_returned_id",
        json!({"account_id":"account-1"}),
        Some(json!({
            "name":"created",
            "secret":"must-not-be-returned",
            "credentials":{"username":"operator","password":"must-not-be-returned"},
            "headers":[{"name":"Authorization","value":"must-not-be-returned"}]
        })),
    );
    plan.capability.request_schema = Some(json!({
        "type":"object",
        "properties": {
            "name":{"type":"string"},
            "secret":{"type":"string","writeOnly":true},
            "credentials":{
                "type":"object",
                "properties":{
                    "username":{"type":"string"},
                    "password":{"type":"string","writeOnly":true}
                }
            },
            "headers":{
                "type":"array",
                "items":{
                    "type":"object",
                    "properties":{
                        "name":{"type":"string"},
                        "value":{"type":"string","writeOnly":true}
                    }
                }
            }
        }
    }));
    plan.capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: "/accounts/{account_id}/widgets/{widget_id}".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-get".to_owned(),
        delete_capability_id: "widgets-delete".to_owned(),
        verified_response_fields: vec!["credentials", "headers", "name"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
    });
    let apply = CloudflareResponseV1 {
        status: 201,
        success: true,
        result: json!({"id":"widget-1"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("write-only inputs should not be required in a readback");
    assert!(verification.passed, "{}", verification.basis);
    assert!(!verification.basis.contains("must-not-be-returned"));
    let drifted = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("observable sibling drift should produce a failed verification result");
    assert!(!drifted.passed, "{}", drifted.basis);
    assert!(drifted.basis.contains("credentials"), "{}", drifted.basis);
    assert!(!drifted.basis.contains("must-not-be-returned"));
    let requests = server.await.expect("server joins");
    assert_eq!(requests.len(), 2);
    assert!(
        requests
            .iter()
            .all(|request| request
                .starts_with("GET /client/v4/accounts/account-1/widgets/widget-1 "))
    );
}

#[tokio::test]
async fn created_resource_verification_fails_closed_without_returned_identity() {
    let mut plan = dns_record_plan(
        "widgets-create",
        "POST",
        "/accounts/{account_id}/widgets",
        "created_resource_contains_planned_fields_by_returned_id",
        json!({"account_id":"account-1"}),
        Some(json!({"name":"secret-like-planned-name"})),
    );
    plan.capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: "/accounts/{account_id}/widgets/{widget_id}".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-get".to_owned(),
        delete_capability_id: "widgets-delete".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
    });
    let apply = CloudflareResponseV1 {
        status: 201,
        success: true,
        result: json!({"name":"secret-like-live-name"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect_err("missing identity must fail closed")
        .to_string();

    assert!(error.contains("identity"));
    assert!(!error.contains("secret-like-planned-name"));
    assert!(!error.contains("secret-like-live-name"));
}

#[tokio::test]
async fn created_resource_without_planned_fields_is_rejected_before_the_mutation_boundary() {
    let mut plan = dns_record_plan(
        "widgets-create",
        "POST",
        "/accounts/{account_id}/widgets",
        "created_resource_contains_planned_fields_by_returned_id",
        json!({"account_id":"account-1"}),
        Some(json!({})),
    );
    plan.capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: "/accounts/{account_id}/widgets/{widget_id}".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-get".to_owned(),
        delete_capability_id: "widgets-delete".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
    });
    plan.status = PlanStatus::Consumed;
    let input: CallInput = serde_json::from_value(plan.input.clone()).expect("input");
    let catalog_hash = plan.catalog_hash.clone();
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .execute_consumed_plan_with_input(
            &mut plan,
            &catalog_hash,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
            &input,
        )
        .await
        .expect_err("empty planned fields must fail before network execution")
        .to_string();

    assert!(error.contains("planned create body"));
    assert_eq!(plan.status, PlanStatus::Consumed);
}

#[tokio::test]
async fn created_resource_with_an_unbound_field_is_rejected_before_the_mutation_boundary() {
    let mut plan = dns_record_plan(
        "widgets-create",
        "POST",
        "/accounts/{account_id}/widgets",
        "created_resource_contains_planned_fields_by_returned_id",
        json!({"account_id":"account-1"}),
        Some(json!({"name":"created", "secret":"must-not-cross-boundary"})),
    );
    plan.capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: "/accounts/{account_id}/widgets/{widget_id}".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-get".to_owned(),
        delete_capability_id: "widgets-delete".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
    });
    plan.status = PlanStatus::Consumed;
    let input: CallInput = serde_json::from_value(plan.input.clone()).expect("input");
    let catalog_hash = plan.catalog_hash.clone();
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .execute_consumed_plan_with_input(
            &mut plan,
            &catalog_hash,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
            &input,
        )
        .await
        .expect_err("an unbound field must fail before network execution")
        .to_string();

    assert!(error.contains("outside the hash-bound exact readback fields"));
    assert!(!error.contains("must-not-cross-boundary"));
    assert_eq!(plan.status, PlanStatus::Consumed);
}

#[tokio::test]
async fn exact_create_rejects_query_controls_before_the_mutation_boundary() {
    let mut plan = dns_record_plan(
        "widgets-create",
        "POST",
        "/accounts/{account_id}/widgets",
        "created_resource_contains_planned_fields_by_returned_id",
        json!({"account_id":"account-1"}),
        Some(json!({"name":"created"})),
    );
    plan.capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: "/accounts/{account_id}/widgets/{widget_id}".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-get".to_owned(),
        delete_capability_id: "widgets-delete".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
    });
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-1"}),
        query: json!({"deploy":"must-not-cross-boundary"}),
        body: Some(json!({"name":"created"})),
        ..CallInput::default()
    })
    .expect("input");
    plan.status = PlanStatus::Consumed;
    let input: CallInput = serde_json::from_value(plan.input.clone()).expect("input");
    let catalog_hash = plan.catalog_hash.clone();
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .execute_consumed_plan_with_input(
            &mut plan,
            &catalog_hash,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
            &input,
        )
        .await
        .expect_err("query controls must fail before network execution")
        .to_string();

    assert!(error.contains("query controls outside the hash-bound exact readback contract"));
    assert!(!error.contains("must-not-cross-boundary"));
    assert_eq!(plan.status, PlanStatus::Consumed);
}

#[tokio::test]
async fn collection_create_rejects_query_controls_before_the_mutation_boundary() {
    let mut plan = dns_record_plan(
        "widgets-create",
        "POST",
        "/accounts/{account_id}/widgets",
        "parent_collection_contains_created_resource_id_and_planned_fields",
        json!({"account_id":"account-1"}),
        Some(json!({"name":"created"})),
    );
    plan.capability.created_collection_resource = Some(CreatedCollectionResourceContractV1 {
        collection_path: "/accounts/{account_id}/widgets".to_owned(),
        identity_selector: "widget_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        response_item_identity_pointer: "/id".to_owned(),
        read_capability_id: "widgets-list".to_owned(),
        delete_capability_id: "widgets-delete".to_owned(),
        verified_response_fields: vec!["name".to_owned()],
        requires_page_number_completion: false,
    });
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-1"}),
        query: json!({"mode":"must-not-cross-boundary"}),
        body: Some(json!({"name":"created"})),
        ..CallInput::default()
    })
    .expect("input");
    plan.status = PlanStatus::Consumed;
    let input: CallInput = serde_json::from_value(plan.input.clone()).expect("input");
    let catalog_hash = plan.catalog_hash.clone();
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .execute_consumed_plan_with_input(
            &mut plan,
            &catalog_hash,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
            &input,
        )
        .await
        .expect_err("query controls must fail before network execution")
        .to_string();

    assert!(error.contains("query controls outside the hash-bound collection readback contract"));
    assert!(!error.contains("must-not-cross-boundary"));
    assert_eq!(plan.status, PlanStatus::Consumed);
}

#[tokio::test]
async fn same_path_delete_rejects_broadening_inputs_before_the_mutation_boundary() {
    let mut plan = dns_record_plan(
        "widgets-delete",
        "DELETE",
        "/accounts/{account_id}/widgets/{widget_id}",
        "same_resource_returns_not_found_after_delete",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        None,
    );
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-1", "widget_id":"widget-1"}),
        query: json!({"cascade":true}),
        body: Some(json!({"reason":"must-not-cross-boundary"})),
        ..CallInput::default()
    })
    .expect("input");
    plan.status = PlanStatus::Consumed;
    let input: CallInput = serde_json::from_value(plan.input.clone()).expect("input");
    let catalog_hash = plan.catalog_hash.clone();
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .execute_consumed_plan_with_input(
            &mut plan,
            &catalog_hash,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
            &input,
        )
        .await
        .expect_err("broadening delete inputs must fail before network execution")
        .to_string();

    assert!(error.contains("outside its hash-bound same-path readback contract"));
    assert!(!error.contains("must-not-cross-boundary"));
    assert_eq!(plan.status, PlanStatus::Consumed);
}

#[tokio::test]
async fn same_path_delete_accepts_only_its_hash_bound_required_empty_body() {
    let (address, server) =
        json_response_sequence_server(vec![r#"{"success":true,"result":null,"errors":[]}"#]).await;
    let mut plan = dns_record_plan(
        "widgets-delete",
        "DELETE",
        "/accounts/{account_id}/widgets/{widget_id}",
        "same_resource_returns_not_found_after_delete",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        Some(json!({})),
    );
    plan.capability.request_schema = Some(json!({
        "type":"object",
        "properties":{},
        "additionalProperties":false,
        "x-cfctl-body-required":true
    }));
    plan.status = PlanStatus::Consumed;
    let input: CallInput = serde_json::from_value(plan.input.clone()).expect("input");
    let catalog_hash = plan.catalog_hash.clone();
    let response = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .execute_consumed_plan_with_input(
        &mut plan,
        &catalog_hash,
        &AuthCredential::Bearer {
            token: "governing-token".to_owned(),
        },
        &input,
    )
    .await
    .expect("strict empty body reaches the boundary");

    assert!(response.success);
    let requests = server.await.expect("server joins");
    assert!(requests[0].starts_with("DELETE /client/v4/accounts/account-1/widgets/widget-1 "));
    assert!(requests[0].ends_with("{}"));

    let mut broadened = dns_record_plan(
        "widgets-delete",
        "DELETE",
        "/accounts/{account_id}/widgets/{widget_id}",
        "same_resource_returns_not_found_after_delete",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        Some(json!({"cascade":"must-not-cross-boundary"})),
    );
    broadened.capability.request_schema = Some(json!({
        "type":"object",
        "properties":{},
        "additionalProperties":false,
        "x-cfctl-body-required":true
    }));
    broadened.status = PlanStatus::Consumed;
    let input: CallInput = serde_json::from_value(broadened.input.clone()).expect("input");
    let catalog_hash = broadened.catalog_hash.clone();
    let error = Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4")
        .expect("executor")
        .execute_consumed_plan_with_input(
            &mut broadened,
            &catalog_hash,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
            &input,
        )
        .await
        .expect_err("non-empty body must fail before the network boundary")
        .to_string();
    assert!(error.contains("hash-bound required empty body"));
    assert!(!error.contains("must-not-cross-boundary"));
    assert_eq!(broadened.status, PlanStatus::Consumed);
}

#[tokio::test]
async fn same_path_delete_rejects_query_controls_before_the_mutation_boundary() {
    let mut plan = dns_record_plan(
        "widgets-delete",
        "DELETE",
        "/accounts/{account_id}/widgets/{widget_id}",
        "same_resource_returns_not_found_after_delete",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        None,
    );
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-1", "widget_id":"widget-1"}),
        query: json!({"cascade":"must-not-cross-boundary"}),
        ..CallInput::default()
    })
    .expect("input");
    plan.status = PlanStatus::Consumed;
    let input: CallInput = serde_json::from_value(plan.input.clone()).expect("input");
    let catalog_hash = plan.catalog_hash.clone();
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .execute_consumed_plan_with_input(
            &mut plan,
            &catalog_hash,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
            &input,
        )
        .await
        .expect_err("query controls must fail before network execution")
        .to_string();

    assert!(error.contains("query controls outside the hash-bound same-path readback contract"));
    assert!(!error.contains("must-not-cross-boundary"));
    assert_eq!(plan.status, PlanStatus::Consumed);
}

#[tokio::test]
async fn same_path_update_rejects_unbound_fields_before_the_mutation_boundary() {
    let mut plan = dns_record_plan(
        "widgets-update",
        "PATCH",
        "/accounts/{account_id}/widgets/{widget_id}",
        "same_resource_contains_planned_fields_after_update",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        Some(json!({"name":"planned"})),
    );
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-1", "widget_id":"widget-1"}),
        query: json!({}),
        body: Some(json!({"name":"planned", "secret":"must-not-cross-boundary"})),
        ..CallInput::default()
    })
    .expect("input");
    plan.status = PlanStatus::Consumed;
    let input: CallInput = serde_json::from_value(plan.input.clone()).expect("input");
    let catalog_hash = plan.catalog_hash.clone();
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .execute_consumed_plan_with_input(
            &mut plan,
            &catalog_hash,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
            &input,
        )
        .await
        .expect_err("an unbound update field must fail before network execution")
        .to_string();

    assert!(error.contains("outside the hash-bound same-path readback fields"));
    assert!(!error.contains("must-not-cross-boundary"));
    assert_eq!(plan.status, PlanStatus::Consumed);
}

#[tokio::test]
async fn same_path_update_rejects_query_controls_before_the_mutation_boundary() {
    let mut plan = dns_record_plan(
        "widgets-update",
        "PATCH",
        "/accounts/{account_id}/widgets/{widget_id}",
        "same_resource_contains_planned_fields_after_update",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        Some(json!({"name":"planned"})),
    );
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"account_id":"account-1", "widget_id":"widget-1"}),
        query: json!({"mode":"must-not-cross-boundary"}),
        body: Some(json!({"name":"planned"})),
        ..CallInput::default()
    })
    .expect("input");
    plan.status = PlanStatus::Consumed;
    let input: CallInput = serde_json::from_value(plan.input.clone()).expect("input");
    let catalog_hash = plan.catalog_hash.clone();
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .execute_consumed_plan_with_input(
            &mut plan,
            &catalog_hash,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
            &input,
        )
        .await
        .expect_err("query controls must fail before network execution")
        .to_string();

    assert!(error.contains("query controls outside the hash-bound same-path readback contract"));
    assert!(!error.contains("must-not-cross-boundary"));
    assert_eq!(plan.status, PlanStatus::Consumed);
}

#[tokio::test]
async fn exact_resource_update_rejects_field_drift_without_echoing_values() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let _ = stream.read(&mut buffer).await.expect("read verification");
        let body = r#"{"success":true,"result":{"settings":{"mode":"unexpected-live-value"}},"errors":[]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
    });
    let plan = dns_record_plan(
        "widgets-update",
        "PUT",
        "/accounts/{account_id}/widgets/{widget_id}",
        "same_resource_contains_planned_fields_after_update",
        json!({"account_id":"account-1", "widget_id":"widget-1"}),
        Some(json!({"settings":{"mode":"planned-secret-like-value"}})),
    );
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(!verification.passed);
    assert!(verification.basis.contains("settings"));
    assert!(!verification.basis.contains("planned-secret-like-value"));
    assert!(!verification.basis.contains("unexpected-live-value"));
    server.await.expect("server joins");
}

#[tokio::test]
async fn same_path_object_update_verifies_schema_proven_fields_with_a_clean_get() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let read = stream.read(&mut buffer).await.expect("read verification");
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let body = r#"{"success":true,"result":{"mode":"strict","nested":{"enabled":true},"server_default":"kept"},"errors":[]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
        request
    });
    let mut plan = dns_record_plan(
        "settings-update",
        "PUT",
        "/zones/{zone_id}/settings/example",
        "same_path_result_contains_planned_fields_after_update",
        json!({"zone_id":"zone-1"}),
        Some(json!({"mode":"strict", "nested":{"enabled":true}})),
    );
    plan.capability.request_schema = Some(json!({
        "type":"object",
        "properties":{"mode":{"type":"string"},"nested":{"type":"object"}}
    }));
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({"zone_id":"zone-1"}),
        query: json!({}),
        body: Some(json!({"mode":"strict", "nested":{"enabled":true}})),
        if_match: Some("mutation-etag".to_owned()),
        ..CallInput::default()
    })
    .expect("input");
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed, "{}", verification.basis);
    let request = server.await.expect("server joins");
    assert!(request.starts_with("GET /client/v4/zones/zone-1/settings/example "));
    assert!(!request.contains("mutation_mode"));
    assert!(!request.contains("mutation-etag"));
}

#[tokio::test]
async fn same_path_post_mutation_omits_an_audit_only_field_from_clean_readback() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let read = stream.read(&mut buffer).await.expect("read verification");
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let body = r#"{"success":true,"result":{"disconnect":true},"errors":[]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
        request
    });
    let mut plan = dns_record_plan(
        "settings-apply",
        "POST",
        "/accounts/{account_id}/settings/example",
        "same_path_result_contains_planned_fields_after_mutation",
        json!({"account_id":"account-1"}),
        Some(json!({
            "disconnect":true,
            "justification":"planned-audit-only-value"
        })),
    );
    plan.capability.request_schema = Some(json!({
        "type":"object",
        "properties":{
            "disconnect":{"type":"boolean"},
            "justification":{
                "type":"string",
                "x-cfctl-verification-observable":false
            }
        }
    }));
    plan.capability
        .same_path_read
        .as_mut()
        .expect("same-path readback")
        .verified_response_fields = vec!["disconnect".to_owned()];
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed, "{}", verification.basis);
    assert!(verification.basis.contains("planned mutation field"));
    assert!(!verification.basis.contains("planned update field"));
    assert!(!verification.basis.contains("planned-audit-only-value"));
    let request = server.await.expect("server joins");
    assert!(request.starts_with("GET /client/v4/accounts/account-1/settings/example "));
}

#[tokio::test]
async fn dns_record_verification_rejects_live_field_drift_without_echoing_values() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let _ = stream.read(&mut buffer).await.expect("read verification");
        let body = r#"{"success":true,"result":{"id":"record-1","type":"TXT","name":"www.example.com","content":"unexpected-live-value","ttl":300},"errors":[]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
    });
    let plan = dns_record_plan(
        "dns-records-for-a-zone-patch-dns-record",
        "PATCH",
        "/zones/{zone_id}/dns_records/{dns_record_id}",
        "dns_record_details_match_planned_id_and_fields",
        json!({"zone_id":"zone-1", "dns_record_id":"record-1"}),
        Some(json!({
            "type":"TXT",
            "name":"www.example.com",
            "content":"planned-secret-like-value",
            "ttl":300
        })),
    );
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({
            "id":"record-1",
            "type":"TXT",
            "name":"www.example.com",
            "content":"planned-secret-like-value",
            "ttl":300
        }),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(!verification.passed);
    assert!(verification.basis.contains("content"));
    assert!(!verification.basis.contains("planned-secret-like-value"));
    assert!(!verification.basis.contains("unexpected-live-value"));
    server.await.expect("server joins");
}

#[tokio::test]
async fn oauth_client_rotation_verifies_two_secret_overlap_without_echoing_secret() {
    let (address, server) = json_response_sequence_server(vec![
        r#"{"success":true,"result":{"client_id":"oauth-client-1","has_rotated_secret":true},"errors":[]}"#,
    ])
    .await;
    let plan = oauth_client_secret_plan(
        "oauth-clients-rotate-secret",
        "POST",
        "oauth_client_reports_rotated_secret_after_value_roll",
    );
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"client_secret":"one-time-secret-must-not-echo"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("rotation verification");

    assert!(verification.passed, "{}", verification.basis);
    assert!(!verification.basis.contains("one-time-secret-must-not-echo"));
    assert!(
        !verification
            .readback
            .result
            .to_string()
            .contains("one-time-secret")
    );
    let requests = server.await.expect("server joins");
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0].starts_with("GET /client/v4/accounts/account-1/oauth_clients/oauth-client-1 ")
    );
}

#[tokio::test]
async fn workers_secret_put_verifies_exact_name_and_type_without_echoing_value() {
    let (address, server) = json_response_sequence_server(vec![
        r#"{"success":true,"result":{"name":"DATABASE_TOKEN","type":"secret_text"},"errors":[]}"#,
    ])
    .await;
    let mut plan = workers_secret_put_plan(json!({
        "name":"DATABASE_TOKEN",
        "type":"secret_text",
        "text":"must-never-appear-in-proof"
    }));
    let execution_input: CallInput =
        serde_json::from_value(plan.input.clone()).expect("resolved execution input");
    plan.input = serde_json::to_value(CallInput {
        selectors: execution_input.selectors.clone(),
        query: json!({}),
        body: Some(json!({
            "$cfctl_secret_body_ref":"plan-input/test-reference",
            "content_hash":"sha256:test"
        })),
        ..CallInput::default()
    })
    .expect("value-free durable input");
    assert!(
        !plan
            .input
            .to_string()
            .contains("must-never-appear-in-proof")
    );
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"name":"DATABASE_TOKEN","type":"secret_text"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan_with_input(
            &plan,
            &apply,
            &execution_input,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("secret verification");

    assert!(verification.passed, "{}", verification.basis);
    assert!(!verification.basis.contains("must-never-appear-in-proof"));
    assert!(
        !verification
            .readback
            .result
            .to_string()
            .contains("must-never-appear-in-proof")
    );
    let requests = server.await.expect("server joins");
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with(
        "GET /client/v4/accounts/account-1/workers/scripts/example-worker/secrets/DATABASE_TOKEN "
    ));
}

#[tokio::test]
async fn workers_secret_put_accepts_the_201_cloudflare_actually_returns() {
    // Cloudflare answers a successful secret put with 201 Created, though its
    // OpenAPI declares only 200. Requiring 200 failed every genuine success
    // live: the secret was created and cfctl reported verification failure
    // while its own basis printed a truthful "apply HTTP 201".
    let (address, server) = json_response_sequence_server(vec![
        r#"{"success":true,"result":{"name":"DATABASE_TOKEN","type":"secret_text"},"errors":[]}"#,
    ])
    .await;
    let plan = workers_secret_put_plan(json!({
        "name":"DATABASE_TOKEN",
        "type":"secret_text",
        "text":"must-never-appear-in-proof"
    }));
    let apply = CloudflareResponseV1 {
        status: 201,
        success: true,
        result: json!({"name":"DATABASE_TOKEN","type":"secret_text"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("secret verification");

    assert!(
        verification.passed,
        "201 Created is a successful put: {}",
        verification.basis
    );
    // The status must be reported as a match, not just echoed as a value —
    // printing it as a bare number is what hid the failing condition.
    assert!(verification.basis.contains("apply HTTP 201 accepted=true"));
    assert!(
        verification
            .basis
            .contains("readback HTTP 200 accepted=true")
    );
    assert!(!verification.basis.contains("must-never-appear-in-proof"));
    server.await.expect("server joins");
}

#[tokio::test]
async fn workers_secret_put_still_rejects_an_unexpected_success_status() {
    let (address, server) = json_response_sequence_server(vec![
        r#"{"success":true,"result":{"name":"DATABASE_TOKEN","type":"secret_text"},"errors":[]}"#,
    ])
    .await;
    let plan = workers_secret_put_plan(json!({
        "name":"DATABASE_TOKEN",
        "type":"secret_text",
        "text":"must-never-appear-in-proof"
    }));
    let apply = CloudflareResponseV1 {
        status: 202,
        success: true,
        result: json!({"name":"DATABASE_TOKEN","type":"secret_text"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("secret verification");

    assert!(
        !verification.passed,
        "widening to the observed statuses must not accept any success status"
    );
    assert!(verification.basis.contains("apply HTTP 202 accepted=false"));
    server.await.expect("server joins");
}

#[tokio::test]
async fn workers_secret_put_rejects_apply_or_readback_identity_drift_without_echoing_value() {
    let (address, server) = json_response_sequence_server(vec![
        r#"{"success":true,"result":{"name":"DATABASE_TOKEN","type":"secret_key"},"errors":[]}"#,
    ])
    .await;
    let plan = workers_secret_put_plan(json!({
        "name":"DATABASE_TOKEN",
        "type":"secret_text",
        "text":"must-never-appear-in-proof"
    }));
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"name":"DIFFERENT_SECRET","type":"secret_text"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("secret verification");

    assert!(!verification.passed);
    assert!(verification.basis.contains("apply name matches=false"));
    assert!(verification.basis.contains("readback type matches=false"));
    assert!(!verification.basis.contains("must-never-appear-in-proof"));
    server.await.expect("server joins");
}

#[tokio::test]
async fn workers_secret_put_rejects_a_grafted_or_broadened_target_before_network() {
    let mut plan = workers_secret_put_plan(json!({
        "name":"DATABASE_TOKEN",
        "type":"secret_text",
        "text":"must-not-cross-boundary"
    }));
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({
            "account_id":"account-1",
            "script_name":"example-worker",
            "secret_name":"grafted-secret"
        }),
        query: json!({}),
        body: Some(json!({
            "name":"DATABASE_TOKEN",
            "type":"secret_text",
            "text":"must-not-cross-boundary"
        })),
        ..CallInput::default()
    })
    .expect("input");
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"name":"DATABASE_TOKEN","type":"secret_text"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect_err("a broadened secret target must fail before network")
        .to_string();

    assert!(error.contains("broader than the exact account and script target"));
    assert!(!error.contains("must-not-cross-boundary"));
}

#[tokio::test]
async fn access_service_token_refresh_verifies_exact_identity_and_expiration_readback() {
    let (address, server) = json_response_sequence_server(vec![
        r#"{"success":true,"result":{"id":"service-token-1","expires_at":"2099-07-15T22:00:00Z"},"errors":[]}"#,
    ])
    .await;
    let plan = access_service_token_refresh_plan();
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({
            "id":"service-token-1",
            "expires_at":"2099-07-15T22:00:00Z"
        }),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("refresh verification");

    assert!(verification.passed, "{}", verification.basis);
    assert!(verification.basis.contains("expiration matches=true"));
    assert!(!verification.basis.contains("2099-07-15"));
    let requests = server.await.expect("server joins");
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0].starts_with(
            "GET /client/v4/accounts/account-1/access/service_tokens/service-token-1 "
        )
    );
}

#[tokio::test]
async fn access_service_token_refresh_rejects_expiration_readback_drift_without_echoing_values() {
    let (address, server) = json_response_sequence_server(vec![
        r#"{"success":true,"result":{"id":"service-token-1","expires_at":"2098-07-15T22:00:00Z"},"errors":[]}"#,
    ])
    .await;
    let plan = access_service_token_refresh_plan();
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({
            "id":"service-token-1",
            "expires_at":"2099-07-15T22:00:00Z"
        }),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("refresh verification");

    assert!(!verification.passed);
    assert!(verification.basis.contains("expiration matches=false"));
    assert!(!verification.basis.contains("2099-07-15"));
    assert!(!verification.basis.contains("2098-07-15"));
    server.await.expect("server joins");
}

#[tokio::test]
async fn access_service_token_refresh_rejects_a_grafted_permission_before_network() {
    let mut plan = access_service_token_refresh_plan();
    plan.capability.permissions = vec!["Account Settings Write".to_owned()];
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({
            "id":"service-token-1",
            "expires_at":"2099-07-15T22:00:00Z"
        }),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect_err("a grafted refresh verifier must fail before network")
        .to_string();

    assert!(error.contains("not implemented"));
    assert!(!error.contains("2099-07-15"));
}

#[tokio::test]
async fn oauth_client_old_secret_delete_verifies_one_secret_state() {
    let (address, server) = json_response_sequence_server(vec![
        r#"{"success":true,"result":{"client_id":"oauth-client-1","has_rotated_secret":false},"errors":[]}"#,
    ])
    .await;
    let plan = oauth_client_secret_plan(
        "oauth-clients-delete-rotated-secret",
        "DELETE",
        "oauth_client_reports_no_rotated_secret_after_old_secret_delete",
    );
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"oauth-client-1"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("old-secret deletion verification");

    assert!(verification.passed, "{}", verification.basis);
    let requests = server.await.expect("server joins");
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0].starts_with("GET /client/v4/accounts/account-1/oauth_clients/oauth-client-1 ")
    );
}

#[tokio::test]
async fn oauth_client_rotation_rejects_a_readback_without_two_secret_overlap() {
    let (address, server) = json_response_sequence_server(vec![
        r#"{"success":true,"result":{"client_id":"oauth-client-1","has_rotated_secret":false},"errors":[]}"#,
    ])
    .await;
    let plan = oauth_client_secret_plan(
        "oauth-clients-rotate-secret",
        "POST",
        "oauth_client_reports_rotated_secret_after_value_roll",
    );
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"client_secret":"one-time-secret-must-not-echo"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("rotation verification");

    assert!(!verification.passed);
    assert!(verification.basis.contains("has_rotated_secret=true"));
    assert!(!verification.basis.contains("one-time-secret-must-not-echo"));
    server.await.expect("server joins");
}

#[tokio::test]
async fn oauth_client_rotation_rejects_an_apply_outside_the_exact_success_status() {
    let (address, server) = json_response_sequence_server(vec![
        r#"{"success":true,"result":{"client_id":"oauth-client-1","has_rotated_secret":true},"errors":[]}"#,
    ])
    .await;
    let plan = oauth_client_secret_plan(
        "oauth-clients-rotate-secret",
        "POST",
        "oauth_client_reports_rotated_secret_after_value_roll",
    );
    let apply = CloudflareResponseV1 {
        status: 201,
        success: true,
        result: json!({"client_secret":"one-time-secret-must-not-echo"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("rotation verification");

    assert!(!verification.passed);
    assert!(verification.basis.contains("apply HTTP 201"));
    assert!(!verification.basis.contains("one-time-secret-must-not-echo"));
    server.await.expect("server joins");
}

#[tokio::test]
async fn oauth_client_old_secret_delete_rejects_a_different_result_identity() {
    let (address, server) = json_response_sequence_server(vec![
        r#"{"success":true,"result":{"client_id":"oauth-client-1","has_rotated_secret":false},"errors":[]}"#,
    ])
    .await;
    let plan = oauth_client_secret_plan(
        "oauth-clients-delete-rotated-secret",
        "DELETE",
        "oauth_client_reports_no_rotated_secret_after_old_secret_delete",
    );
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"different-oauth-client"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("old-secret deletion verification");

    assert!(!verification.passed);
    assert!(verification.basis.contains("apply identity matches=false"));
    server.await.expect("server joins");
}

#[tokio::test]
async fn oauth_client_verifier_rejects_a_grafted_permission_before_network() {
    let mut plan = oauth_client_secret_plan(
        "oauth-clients-rotate-secret",
        "POST",
        "oauth_client_reports_rotated_secret_after_value_roll",
    );
    plan.capability.permissions = vec!["Account Settings Write".to_owned()];
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"client_secret":"must-not-cross-boundary"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor =
        Executor::new(reqwest::Client::new(), "http://127.0.0.1:9/client/v4").expect("executor");

    let error = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect_err("a grafted OAuth verifier must fail before network")
        .to_string();

    assert!(error.contains("not implemented"));
    assert!(!error.contains("must-not-cross-boundary"));
}

fn dns_record_plan(
    id: &str,
    method: &str,
    path: &str,
    verification_strategy: &str,
    selectors: serde_json::Value,
    body: Option<serde_json::Value>,
) -> PlanV1 {
    let mut capability = CapabilityV1::new(id, id, method, path);
    verification_strategy.clone_into(&mut capability.verification.strategy);
    if matches!(
        verification_strategy,
        "same_resource_returns_not_found_after_delete"
    ) {
        capability.same_path_read = Some(SamePathReadContractV1 {
            path: path.to_owned(),
            read_capability_id: format!("{id}-readback"),
            verified_response_fields: Vec::new(),
        });
    } else if matches!(
        verification_strategy,
        "same_resource_contains_planned_fields_after_update"
            | "same_path_result_contains_planned_fields_after_update"
            | "same_path_result_contains_planned_fields_after_mutation"
            | "parent_collection_item_contains_planned_fields_after_update"
    ) {
        let mut fields = body
            .as_ref()
            .and_then(serde_json::Value::as_object)
            .map(|body| body.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        fields.sort();
        fields.dedup();
        let properties = fields
            .iter()
            .map(|field| (field.clone(), json!({})))
            .collect::<serde_json::Map<_, _>>();
        capability.request_schema = Some(json!({
            "type":"object",
            "properties": properties
        }));
        capability.same_path_read = Some(SamePathReadContractV1 {
            path: path.to_owned(),
            read_capability_id: format!("{id}-readback"),
            verified_response_fields: fields,
        });
    }
    let mut plan = PlanV1::draft(
        "profile",
        "account-1",
        "sha256:catalog",
        capability,
        json!({}),
    )
    .expect("plan");
    plan.input = serde_json::to_value(CallInput {
        selectors,
        query: json!({}),
        body,
        ..CallInput::default()
    })
    .expect("input");
    plan
}

fn worker_script_delete_plan(selectors: serde_json::Value) -> PlanV1 {
    let mut capability = CapabilityV1::new(
        "worker-script-delete-worker",
        "Delete Worker",
        "DELETE",
        "/accounts/{account_id}/workers/scripts/{script_name}",
    );
    "Worker Script".clone_into(&mut capability.product);
    capability.permissions = vec!["Workers Scripts Write".to_owned()];
    "worker_script_settings_returns_not_found_after_delete"
        .clone_into(&mut capability.verification.strategy);
    capability.selectors = ["account_id", "script_name"]
        .iter()
        .map(|name| SelectorV1 {
            name: (*name).to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        })
        .collect();
    capability.same_path_read = Some(SamePathReadContractV1 {
        path: "/accounts/{account_id}/workers/scripts/{script_name}/settings".to_owned(),
        read_capability_id: "worker-script-get-settings".to_owned(),
        verified_response_fields: Vec::new(),
    });
    let mut plan = PlanV1::draft(
        "profile",
        "account-1",
        "sha256:catalog",
        capability,
        json!({}),
    )
    .expect("plan");
    plan.input = serde_json::to_value(CallInput {
        selectors,
        query: json!({}),
        body: None,
        ..CallInput::default()
    })
    .expect("input");
    plan
}

#[tokio::test]
async fn worker_script_deletion_is_verified_by_settings_not_found_readback() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let read = stream.read(&mut buffer).await.expect("read verification");
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let body =
            r#"{"success":false,"result":null,"errors":[{"code":10007,"message":"not found"}]}"#;
        let response = format!(
            "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
        request
    });
    let plan = worker_script_delete_plan(json!({
        "account_id":"account-1",
        "script_name":"scratch-worker"
    }));
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"scratch-worker"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(verification.passed, "{}", verification.basis);
    assert!(verification.basis.contains("settings sub-path"));
    // The readback must hit the settings sub-path, not the raw script GET.
    let request = server.await.expect("server joins");
    assert!(
        request.starts_with(
            "GET /client/v4/accounts/account-1/workers/scripts/scratch-worker/settings "
        ),
        "{request}"
    );
}

#[tokio::test]
async fn worker_script_deletion_refuses_a_still_present_script() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let address = listener.local_addr().expect("fake server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept verification");
        let mut buffer = vec![0_u8; 8192];
        let _ = stream.read(&mut buffer).await.expect("read verification");
        let body = r#"{"success":true,"result":{"script":"still here"},"errors":[]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write verification");
    });
    let plan = worker_script_delete_plan(json!({
        "account_id":"account-1",
        "script_name":"scratch-worker"
    }));
    let apply = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"id":"scratch-worker"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let executor = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor");

    let verification = executor
        .verify_plan(
            &plan,
            &apply,
            &AuthCredential::Bearer {
                token: "governing-token".to_owned(),
            },
        )
        .await
        .expect("verification result");

    assert!(!verification.passed);
    assert!(verification.basis.contains("settings readback HTTP 200"));
    server.await.expect("server joins");
}

#[test]
fn worker_script_delete_refuses_the_force_selector_as_undeclared() {
    // The classifier strips `force` from the declared selectors, so the
    // builder must refuse it as undeclared input — the bypass is
    // unexpressable through cfctl, not merely discouraged.
    let plan = worker_script_delete_plan(json!({
        "account_id":"account-1",
        "script_name":"scratch-worker"
    }));
    // Selector validation is the layer that owns this refusal; the builder's
    // approved-plan guard would otherwise mask it for a mutating capability.
    let error = validate_request_contract(
        &plan.capability,
        &CallInput {
            selectors: json!({
                "account_id":"account-1",
                "script_name":"scratch-worker",
                "force":"true"
            }),
            ..CallInput::default()
        },
    )
    .expect_err("force must be refused as an undeclared selector");
    assert!(error.to_string().contains("force"), "{error}");

    let accepted = validate_request_contract(
        &plan.capability,
        &CallInput {
            selectors: json!({
                "account_id":"account-1",
                "script_name":"scratch-worker"
            }),
            ..CallInput::default()
        },
    );
    assert!(accepted.is_ok(), "path-only selectors remain valid");
}

fn oauth_client_secret_plan(id: &str, method: &str, verification_strategy: &str) -> PlanV1 {
    let mut capability = CapabilityV1::new(
        id,
        id,
        method,
        "/accounts/{account_id}/oauth_clients/{oauth_client_id}/rotate_secret",
    );
    "OAuth Clients".clone_into(&mut capability.product);
    capability.permissions = vec![
        "OAuth Client Write".to_owned(),
        "OAuth Client Read".to_owned(),
    ];
    verification_strategy.clone_into(&mut capability.verification.strategy);
    capability.selectors = vec![
        SelectorV1 {
            name: "account_id".to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        },
        SelectorV1 {
            name: "oauth_client_id".to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        },
    ];
    capability.same_path_read = Some(SamePathReadContractV1 {
        path: "/accounts/{account_id}/oauth_clients/{oauth_client_id}".to_owned(),
        read_capability_id: "oauth-clients-get".to_owned(),
        verified_response_fields: vec!["client_id".to_owned(), "has_rotated_secret".to_owned()],
    });
    let mut plan = PlanV1::draft(
        "profile",
        "account-1",
        "sha256:catalog",
        capability,
        json!({}),
    )
    .expect("plan");
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({
            "account_id":"account-1",
            "oauth_client_id":"oauth-client-1"
        }),
        query: json!({}),
        body: None,
        ..CallInput::default()
    })
    .expect("input");
    plan
}

fn workers_secret_put_plan(body: Value) -> PlanV1 {
    let mut capability = CapabilityV1::new(
        "worker-put-script-secret",
        "Add script secret",
        "PUT",
        "/accounts/{account_id}/workers/scripts/{script_name}/secrets",
    );
    "Worker Script".clone_into(&mut capability.product);
    capability.permissions = vec!["Workers Scripts Write".to_owned()];
    capability.selectors = [
        ("account_id", json!({"maxLength":32,"type":"string"})),
        ("script_name", json!({"type":"string"})),
    ]
    .into_iter()
    .map(|(name, schema)| SelectorV1 {
        name: name.to_owned(),
        location: "path".to_owned(),
        required: true,
        value_type: "string".to_owned(),
        description: None,
        contract: Some(SelectorContractV1 {
            schema,
            query: None,
        }),
    })
    .collect();
    capability.request_schema = Some(json!({
        "type":"object",
        "oneOf":[
            {
                "type":"object",
                "required":["name","type","text"],
                "properties":{
                    "name":{"type":"string"},
                    "type":{"type":"string","enum":["secret_text"]},
                    "text":{"type":"string","writeOnly":true}
                }
            },
            {
                "type":"object",
                "required":["name","type","format","algorithm","usages"],
                "properties":{
                    "name":{"type":"string"},
                    "type":{"type":"string","enum":["secret_key"]},
                    "format":{"type":"string","enum":["raw","pkcs8","spki","jwk"]},
                    "algorithm":{"type":"object"},
                    "usages":{"type":"array","items":{"type":"string","enum":["encrypt","decrypt","sign","verify","deriveKey","deriveBits","wrapKey","unwrapKey"]}},
                    "key_base64":{"type":"string","writeOnly":true},
                    "key_jwk":{"type":"object","writeOnly":true}
                }
            }
        ],
        "x-cfctl-body-required":true
    }));
    "worker_script_secret_reports_planned_name_and_type_after_put"
        .clone_into(&mut capability.verification.strategy);
    capability.same_path_read = Some(SamePathReadContractV1 {
        path: "/accounts/{account_id}/workers/scripts/{script_name}/secrets/{secret_name}"
            .to_owned(),
        read_capability_id: "worker-get-script-secret".to_owned(),
        verified_response_fields: vec!["name".to_owned(), "type".to_owned()],
    });
    assert!(
        capability.verification_contract_supported(),
        "test fixture must carry the exact Workers secret verifier contract: {}",
        serde_json::to_string(&capability).expect("serialize capability")
    );
    let mut plan = PlanV1::draft(
        "profile",
        "account-1",
        "sha256:catalog",
        capability,
        json!({}),
    )
    .expect("plan");
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({
            "account_id":"account-1",
            "script_name":"example-worker"
        }),
        query: json!({}),
        body: Some(body),
        ..CallInput::default()
    })
    .expect("input");
    plan
}

fn access_service_token_refresh_plan() -> PlanV1 {
    let mut capability = CapabilityV1::new(
        "access-service-tokens-refresh-a-service-token",
        "Refresh a service token",
        "POST",
        "/accounts/{account_id}/access/service_tokens/{service_token_id}/refresh",
    );
    "Access service tokens".clone_into(&mut capability.product);
    capability.permissions = vec!["Access: Service Tokens Write".to_owned()];
    capability.selectors = vec![
        SelectorV1 {
            name: "service_token_id".to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: Some(SelectorContractV1 {
                schema: json!({"maxLength":36,"type":"string"}),
                query: None,
            }),
        },
        SelectorV1 {
            name: "account_id".to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: Some(SelectorContractV1 {
                schema: json!({"maxLength":32,"type":"string"}),
                query: None,
            }),
        },
    ];
    "access_service_token_reports_refreshed_expiration"
        .clone_into(&mut capability.verification.strategy);
    capability.same_path_read = Some(SamePathReadContractV1 {
        path: "/accounts/{account_id}/access/service_tokens/{service_token_id}".to_owned(),
        read_capability_id: "access-service-tokens-get-a-service-token".to_owned(),
        verified_response_fields: vec!["expires_at".to_owned(), "id".to_owned()],
    });
    let mut plan = PlanV1::draft(
        "profile",
        "account-1",
        "sha256:catalog",
        capability,
        json!({}),
    )
    .expect("plan");
    plan.input = serde_json::to_value(CallInput {
        selectors: json!({
            "account_id":"account-1",
            "service_token_id":"service-token-1"
        }),
        query: json!({}),
        body: None,
        ..CallInput::default()
    })
    .expect("input");
    plan
}

fn token_plan(
    id: &str,
    method: &str,
    path: &str,
    verification_strategy: &str,
    selectors: serde_json::Value,
) -> PlanV1 {
    let mut capability = CapabilityV1::new(id, id, method, path);
    verification_strategy.clone_into(&mut capability.verification.strategy);
    let mut plan = PlanV1::draft(
        "profile",
        "account-1",
        "sha256:catalog",
        capability,
        json!({}),
    )
    .expect("plan");
    plan.input = serde_json::to_value(CallInput {
        selectors,
        query: json!({}),
        body: Some(json!({})),
        ..CallInput::default()
    })
    .expect("input");
    plan
}

fn d1_schema_introspection_capability() -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        "d1-schema-introspection",
        "Assert bounded D1 schema state",
        "POST",
        "/accounts/{account_id}/d1/database/{database_id}/query",
    );
    "D1".clone_into(&mut capability.product);
    "cfctl native D1 schema assertion adapter".clone_into(&mut capability.source);
    capability.permissions = vec!["D1 Read".to_owned()];
    capability.mutating = false;
    capability.risk = RiskClass::Read;
    capability.effect = EffectClass::ReadOnly;
    capability.adapter_status = AdapterStatus::Native;
    capability.verification.required = true;
    "not_applicable".clone_into(&mut capability.verification.strategy);
    capability.rollback.warning = None;
    capability.selectors = ["account_id", "database_id"]
        .map(|name| SelectorV1 {
            name: name.to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: Some(SelectorContractV1 {
                schema: if name == "account_id" {
                    json!({"type":"string","minLength":32,"maxLength":32})
                } else {
                    json!({"type":"string","minLength":36,"maxLength":36})
                },
                query: None,
            }),
        })
        .to_vec();
    let name = json!({"type":"string","minLength":1,"maxLength":255});
    capability.request_schema = Some(json!({
        "type":"object",
        "x-cfctl-body-required":true,
        "oneOf":[
            {"type":"object","additionalProperties":false,"required":["assertion","table"],"properties":{"assertion":{"type":"string","enum":["table_exists"]},"table":name}},
            {"type":"object","additionalProperties":false,"required":["assertion","table","column"],"properties":{"assertion":{"type":"string","enum":["column_exists"]},"table":name,"column":name}},
            {"type":"object","additionalProperties":false,"required":["assertion","index"],"properties":{"assertion":{"type":"string","enum":["index_exists"]},"index":name}},
            {"type":"object","additionalProperties":false,"required":["assertion","trigger"],"properties":{"assertion":{"type":"string","enum":["trigger_exists"]},"trigger":name}},
            {"type":"object","additionalProperties":false,"required":["assertion","object_type","name","fragment"],"properties":{"assertion":{"type":"string","enum":["schema_contains"]},"object_type":{"type":"string","enum":["table","index","trigger"]},"name":name,"fragment":{"type":"string","minLength":1,"maxLength":512}}},
            {"type":"object","additionalProperties":false,"required":["assertion"],"properties":{"assertion":{"type":"string","enum":["foreign_key_check_empty"]}}}
        ]
    }));
    capability.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".to_owned()],
        success_media_types: vec!["application/json".to_owned()],
        body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
    });
    capability.d1_schema_introspection = Some(D1SchemaIntrospectionContractV1 {
        max_rows: 1,
        max_bytes: 64 * 1024,
        max_timeout_seconds: 10,
    });
    capability
}

fn d1_full_export_capability() -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        "d1-full-export",
        "Export full D1 database to SQL",
        "POST",
        "/accounts/{account_id}/d1/database/{database_id}/export",
    );
    "D1".clone_into(&mut capability.product);
    "cfctl native governed D1 full-export adapter".clone_into(&mut capability.source);
    "account".clone_into(&mut capability.account_scope);
    capability.permissions = vec!["D1 Read".to_owned()];
    capability.mutating = false;
    capability.risk = RiskClass::Read;
    capability.effect = EffectClass::ReadOnly;
    capability.adapter_status = AdapterStatus::Native;
    capability.verification.required = true;
    "same_output_file_exists_and_sha256_matches".clone_into(&mut capability.verification.strategy);
    capability.selectors = ["account_id", "database_id"]
        .map(|name| SelectorV1 {
            name: name.to_owned(),
            location: "path".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: Some(SelectorContractV1 {
                schema: if name == "account_id" {
                    json!({"type":"string","minLength":32,"maxLength":32})
                } else {
                    json!({"type":"string","minLength":36,"maxLength":36})
                },
                query: None,
            }),
        })
        .to_vec();
    capability.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".to_owned()],
        success_media_types: vec!["application/json".to_owned()],
        body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
    });
    capability.d1_full_export = Some(D1FullExportContractV1 {
        max_bytes: 1024 * 1024,
        max_poll_response_bytes: 64 * 1024,
        max_poll_attempts: 3,
        max_timeout_seconds: 5,
        max_download_seconds: 5,
        requires_new_mode_0600_file: true,
    });
    capability
}

fn d1_full_export_input() -> CallInput {
    CallInput {
        selectors: json!({
            "account_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "database_id":"11111111-2222-3333-4444-555555555555"
        }),
        query: json!({}),
        ..CallInput::default()
    }
}

#[test]
fn d1_full_export_builds_only_fixed_polling_body_and_rejects_caller_controls() {
    let capability = d1_full_export_capability();
    let prepared = RequestBuilder::new("https://api.cloudflare.com/client/v4")
        .expect("builder")
        .build(&capability, &d1_full_export_input())
        .expect("closed export request");
    assert_eq!(prepared.body, Some(json!({"output_format":"polling"})));
    assert_eq!(
        prepared
            .query_receipt
            .as_ref()
            .and_then(|value| value.get("scope")),
        Some(&json!("full_schema_and_data"))
    );
    for input in [
        CallInput {
            body: Some(json!({"sql":"SELECT 1"})),
            ..d1_full_export_input()
        },
        CallInput {
            body: Some(json!({"dump_options":{"tables":["users"]}})),
            ..d1_full_export_input()
        },
        CallInput {
            query: json!({"bookmark":"caller-controlled"}),
            ..d1_full_export_input()
        },
    ] {
        assert!(validate_request_contract(&capability, &input).is_err());
    }
}

#[test]
fn d1_full_export_rejects_every_execution_relevant_identity_drift() {
    let input = d1_full_export_input();
    let mut drifted = Vec::new();

    let mut capability = d1_full_export_capability();
    capability.account_scope = "zone".to_owned();
    drifted.push(capability);

    let mut capability = d1_full_export_capability();
    capability.adapter_status = AdapterStatus::DynamicApi;
    drifted.push(capability);

    let mut capability = d1_full_export_capability();
    capability.selectors.push(SelectorV1 {
        name: "x-grafted".to_owned(),
        location: "header".to_owned(),
        required: false,
        value_type: "string".to_owned(),
        description: None,
        contract: None,
    });
    drifted.push(capability);

    let mut capability = d1_full_export_capability();
    capability.selectors.swap(0, 1);
    drifted.push(capability);

    let mut capability = d1_full_export_capability();
    capability.selectors[0].required = false;
    drifted.push(capability);

    let mut capability = d1_full_export_capability();
    capability.selectors[1]
        .contract
        .as_mut()
        .expect("selector contract")
        .schema = json!({"type":"string"});
    drifted.push(capability);

    let builder = RequestBuilder::new("https://api.cloudflare.com/client/v4").expect("builder");
    for capability in drifted {
        assert!(validate_request_contract(&capability, &input).is_err());
        assert!(builder.build(&capability, &input).is_err());
    }
}

#[cfg(unix)]
#[tokio::test]
async fn d1_full_export_rejects_unsafe_paths_before_server_contact() {
    use std::os::unix::fs::symlink;

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("address");
    let root = tempfile::tempdir().expect("root");
    let root = std::fs::canonicalize(root.path()).expect("canonical root");
    let target = root.join("target");
    std::fs::create_dir(&target).expect("target");
    let linked = root.join("linked");
    symlink(&target, &linked).expect("symlink");

    for output in [
        root.join("nested/../snapshot.sql"),
        root.join("missing/snapshot.sql"),
        linked.join("snapshot.sql"),
    ] {
        let error = Executor::new(
            reqwest::Client::new(),
            &format!("http://{address}/client/v4"),
        )
        .expect("executor")
        .execute_read_to_file(
            &d1_full_export_capability(),
            &d1_full_export_input(),
            &AuthCredential::Bearer {
                token: "selected-token".to_owned(),
            },
            &output,
        )
        .await
        .expect_err("unsafe path fails closed");
        assert!(matches!(error, CloudflareError::OutputFile { .. }));
        assert!(!output.exists());
    }
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
            .await
            .is_err(),
        "path validation must happen before server contact"
    );
}

#[tokio::test]
async fn d1_full_export_polls_streams_and_verifies_same_path_hash() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("address");
    let server = tokio::spawn(async move {
        let mut requests = Vec::new();
        for response in [
            r#"{"success":true,"result":{"type":"export","success":true,"at_bookmark":"bookmark-42"}}"#
                .to_owned(),
            format!(
                r#"{{"success":true,"result":{{"type":"export","status":"complete","success":true,"at_bookmark":"bookmark-42","result":{{"filename":"snapshot.sql","signed_url":"http://{address}/download"}}}}}}"#
            ),
            "CREATE TABLE users(id INTEGER);\nINSERT INTO users VALUES (1);\n".to_owned(),
        ] {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];
            let read = socket.read(&mut buffer).await.expect("read");
            request.extend_from_slice(&buffer[..read]);
            requests.push(String::from_utf8_lossy(&request).into_owned());
            let content_type = if response.starts_with('{') {
                "application/json"
            } else {
                "application/sql"
            };
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
                        response.len()
                    )
                    .as_bytes(),
                )
                .await
                .expect("write");
        }
        requests
    });
    let output_root = tempfile::tempdir().expect("output root");
    let output = std::fs::canonicalize(output_root.path())
        .expect("canonical output root")
        .join("snapshot.sql");
    let response = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .execute_read_to_file(
        &d1_full_export_capability(),
        &d1_full_export_input(),
        &AuthCredential::Bearer {
            token: "selected-token".to_owned(),
        },
        &output,
    )
    .await
    .expect("full export");
    assert!(response.success);
    assert_eq!(
        response.result["database"]["database_id"],
        "11111111-2222-3333-4444-555555555555"
    );
    assert_eq!(response.result["provider"]["at_bookmark"], "bookmark-42");
    assert_eq!(response.result["output_file"]["bytes"], 62);
    assert_eq!(response.result["output_file"]["exists"], true);
    assert_eq!(response.result["output_file"]["hash_matches"], true);
    assert_eq!(
        std::fs::read_to_string(&output).expect("export file"),
        "CREATE TABLE users(id INTEGER);\nINSERT INTO users VALUES (1);\n"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&output)
                .expect("export metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let requests = server.await.expect("server");
    assert_eq!(requests.len(), 3);
    assert!(requests[0].contains("\"output_format\":\"polling\""));
    assert!(!requests[0].contains("sql"));
    assert!(requests[1].contains("\"current_bookmark\":\"bookmark-42\""));
}

#[cfg(unix)]
#[tokio::test]
async fn d1_full_export_rejects_existing_file_or_final_symlink_without_changes_or_contact() {
    use std::os::unix::fs::symlink;

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("address");
    let root = tempfile::tempdir().expect("root");
    let root = std::fs::canonicalize(root.path()).expect("canonical root");
    let existing = root.join("existing.sql");
    std::fs::write(&existing, "keep").expect("existing file");
    let target = root.join("target.sql");
    std::fs::write(&target, "target").expect("target file");
    let linked = root.join("linked.sql");
    symlink(&target, &linked).expect("final symlink");

    for output in [&existing, &linked] {
        Executor::new(
            reqwest::Client::new(),
            &format!("http://{address}/client/v4"),
        )
        .expect("executor")
        .execute_read_to_file(
            &d1_full_export_capability(),
            &d1_full_export_input(),
            &AuthCredential::Bearer {
                token: "selected-token".to_owned(),
            },
            output,
        )
        .await
        .expect_err("existing output fails closed");
    }
    assert_eq!(std::fs::read_to_string(existing).expect("existing"), "keep");
    assert_eq!(std::fs::read_to_string(target).expect("target"), "target");
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
            .await
            .is_err(),
        "existing output validation must happen before server contact"
    );
}

#[tokio::test]
async fn d1_full_export_removes_new_file_after_partial_stream_or_byte_overflow() {
    for (download, declared_length, max_bytes) in [
        ("partial", 100_usize, 1024_u64),
        ("overflow", 8_usize, 4_u64),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            for (index, response) in [
                format!(
                    r#"{{"success":true,"result":{{"type":"export","status":"complete","success":true,"at_bookmark":"bookmark-42","result":{{"filename":"snapshot.sql","signed_url":"http://{address}/download"}}}}}}"#
                ),
                download.to_owned(),
            ]
            .into_iter()
            .enumerate()
            {
                let (mut socket, _) = listener.accept().await.expect("accept");
                let mut buffer = [0_u8; 4096];
                let _read = socket.read(&mut buffer).await.expect("read");
                let length = if index == 0 {
                    response.len()
                } else {
                    declared_length
                };
                let content_type = if index == 0 {
                    "application/json"
                } else {
                    "application/octet-stream"
                };
                socket
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n{response}"
                        )
                        .as_bytes(),
                    )
                    .await
                    .expect("write");
            }
        });
        let root = tempfile::tempdir().expect("root");
        let output = std::fs::canonicalize(root.path())
            .expect("canonical root")
            .join("snapshot.sql");
        let mut capability = d1_full_export_capability();
        capability
            .d1_full_export
            .as_mut()
            .expect("export contract")
            .max_bytes = max_bytes;
        capability
            .d1_full_export
            .as_mut()
            .expect("export contract")
            .max_poll_attempts = 1;
        Executor::new(
            reqwest::Client::new(),
            &format!("http://{address}/client/v4"),
        )
        .expect("executor")
        .execute_read_to_file(
            &capability,
            &d1_full_export_input(),
            &AuthCredential::Bearer {
                token: "selected-token".to_owned(),
            },
            &output,
        )
        .await
        .expect_err("failed stream must not retain output");
        assert!(!output.exists(), "partial output must be removed");
        server.await.expect("server");
    }
}

fn d1_schema_input(body: Value) -> CallInput {
    CallInput {
        selectors: json!({
            "account_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "database_id":"11111111-2222-3333-4444-555555555555"
        }),
        query: json!({}),
        body: Some(body),
        ..CallInput::default()
    }
}

#[test]
fn d1_schema_introspection_compiles_closed_assertions_without_caller_sql() {
    let capability = d1_schema_introspection_capability();
    let builder = RequestBuilder::new("https://api.cloudflare.com/client/v4").expect("builder");
    let injection = "advisor_equity_instrument'); DROP TABLE users; --";
    let prepared = builder
        .build(
            &capability,
            &d1_schema_input(json!({
                "assertion":"schema_contains",
                "object_type":"table",
                "name":"equity_issuance_evidence_links",
                "fragment":injection
            })),
        )
        .expect("closed schema assertion");

    assert_eq!(prepared.method, "POST");
    assert_eq!(
        prepared.url.as_str(),
        "https://api.cloudflare.com/client/v4/accounts/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/d1/database/11111111-2222-3333-4444-555555555555/query"
    );
    assert_eq!(prepared.max_rows, 1);
    assert_eq!(prepared.max_bytes, 64 * 1024);
    assert_eq!(prepared.timeout_seconds, 10);
    let wire = prepared.body.expect("compiler-owned body");
    let sql = wire["sql"].as_str().expect("fixed SQL");
    assert_eq!(
        sql,
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = ?1 AND name = ?2 AND instr(COALESCE(sql, ''), ?3) > 0) AS present"
    );
    assert!(!sql.contains(injection));
    assert_eq!(wire["params"][2], injection);
    assert_eq!(
        prepared
            .query_receipt
            .as_ref()
            .and_then(|receipt| receipt.get("caller_sql"))
            .and_then(Value::as_bool),
        Some(false)
    );
}

#[test]
fn d1_schema_introspection_supports_every_closed_migration_assertion() {
    let capability = d1_schema_introspection_capability();
    let builder = RequestBuilder::new("https://api.cloudflare.com/client/v4").expect("builder");
    for body in [
        json!({"assertion":"table_exists","table":"document_render_jobs"}),
        json!({"assertion":"column_exists","table":"document_render_jobs","column":"claim_generation"}),
        json!({"assertion":"index_exists","index":"idx_document_render_jobs_claim"}),
        json!({"assertion":"trigger_exists","trigger":"document_render_jobs_terminal_generation_guard"}),
        json!({"assertion":"schema_contains","object_type":"table","name":"equity_issuance_evidence_links","fragment":"advisor_equity_instrument"}),
        json!({"assertion":"foreign_key_check_empty"}),
    ] {
        let prepared = builder
            .build(&capability, &d1_schema_input(body))
            .expect("supported assertion");
        let wire = prepared.body.expect("compiler-owned D1 body");
        assert!(wire["sql"].as_str().is_some_and(|sql| {
            sql.starts_with("SELECT ") && !sql.contains(';') && !sql.contains("--")
        }));
        assert!(wire["params"].is_array());
    }
}

#[test]
fn d1_schema_introspection_rejects_raw_sql_and_contract_drift() {
    let capability = d1_schema_introspection_capability();
    let raw_sql = d1_schema_input(json!({
        "assertion":"table_exists",
        "table":"users",
        "sql":"DROP TABLE users"
    }));
    assert!(matches!(
        validate_request_contract(&capability, &raw_sql),
        Err(CloudflareError::InvalidRequestBody(_))
    ));

    let arbitrary = d1_schema_input(json!({"assertion":"pragma","name":"writable_schema"}));
    assert!(matches!(
        validate_request_contract(&capability, &arbitrary),
        Err(CloudflareError::InvalidRequestBody(_))
    ));

    let mut drifted = capability;
    drifted.permissions = vec!["D1 Write".to_owned()];
    assert!(matches!(
        validate_request_contract(
            &drifted,
            &d1_schema_input(json!({"assertion":"foreign_key_check_empty"}))
        ),
        Err(CloudflareError::InvalidAnalyticsQuery(_))
    ));
}

#[test]
fn d1_schema_introspection_rejects_missing_or_permissive_request_schema_drift() {
    let input = d1_schema_input(json!({"assertion":"foreign_key_check_empty"}));

    let mut missing = d1_schema_introspection_capability();
    missing.request_schema = None;
    assert!(matches!(
        validate_request_contract(&missing, &input),
        Err(CloudflareError::InvalidAnalyticsQuery(_))
    ));

    let mut permissive = d1_schema_introspection_capability();
    permissive
        .request_schema
        .as_mut()
        .and_then(|schema| schema.pointer_mut("/oneOf/0"))
        .and_then(Value::as_object_mut)
        .expect("first assertion schema")
        .remove("additionalProperties");
    assert!(matches!(
        validate_request_contract(&permissive, &input),
        Err(CloudflareError::InvalidAnalyticsQuery(_))
    ));
}

#[tokio::test]
async fn d1_schema_introspection_executes_as_one_bounded_read_only_post() {
    let capability = d1_schema_introspection_capability();
    let input = d1_schema_input(json!({
        "assertion":"trigger_exists",
        "trigger":"document_render_jobs_terminal_generation_guard"
    }));
    let (address, server) = json_response_sequence_server(vec![
        r#"{"success":true,"errors":[],"messages":[],"result":[{"results":[{"present":1}],"success":true,"meta":{"rows_read":1,"rows_written":0}}]}"#,
    ])
    .await;
    let response = Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .execute_read(
        &capability,
        &input,
        &AuthCredential::Bearer {
            token: "selected-token".to_owned(),
        },
    )
    .await
    .expect("bounded D1 schema read");
    assert!(response.success);
    assert_eq!(
        response.result.pointer("/0/results/0/present"),
        Some(&json!(1))
    );
    assert_eq!(
        response
            .result_info
            .as_ref()
            .and_then(|info| info.pointer("/query/kind")),
        Some(&json!("d1_schema_introspection"))
    );
    assert_eq!(
        response
            .result_info
            .as_ref()
            .and_then(|info| info.pointer("/coverage/classification")),
        Some(&json!("complete_assertion_response"))
    );
    assert_eq!(
        response
            .result_info
            .as_ref()
            .and_then(|info| info.pointer("/output/byte_limit")),
        Some(&json!(64 * 1024))
    );

    let requests = server.await.expect("server joins");
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with(
        "POST /client/v4/accounts/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/d1/database/11111111-2222-3333-4444-555555555555/query "
    ));
    assert!(
        requests[0].contains("\"params\":[\"document_render_jobs_terminal_generation_guard\"]")
    );
    assert!(requests[0].contains(
        "\"sql\":\"SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'trigger' AND name = ?1) AS present\""
    ));
    assert!(!requests[0].contains("DROP TABLE"));
}

#[tokio::test]
async fn d1_schema_introspection_rejects_non_boolean_or_write_reporting_responses() {
    let capability = d1_schema_introspection_capability();
    let input = d1_schema_input(json!({"assertion":"foreign_key_check_empty"}));
    for body in [
        r#"{"success":true,"result":[{"results":[{"present":"yes"}],"success":true,"meta":{"rows_written":0}}]}"#,
        r#"{"success":true,"result":[{"results":[{"present":1}],"success":true,"meta":{"rows_written":1}}]}"#,
        r#"{"success":true,"result":[{"results":[{"present":1},{"present":0}],"success":true,"meta":{"rows_written":0}}]}"#,
    ] {
        let (address, server) = json_response_sequence_server(vec![body]).await;
        let error = Executor::new(
            reqwest::Client::new(),
            &format!("http://{address}/client/v4"),
        )
        .expect("executor")
        .execute_read(
            &capability,
            &input,
            &AuthCredential::Bearer {
                token: "selected-token".to_owned(),
            },
        )
        .await
        .expect_err("malformed or write-reporting response must fail closed");
        assert!(matches!(
            error,
            CloudflareError::InvalidResponseEnvelope { status: 200 }
        ));
        assert_eq!(server.await.expect("server joins").len(), 1);
    }
}
