//! Private R2 upload and recovery capability boundaries.
use super::{
    AdapterStatus, BTreeMap, CapabilityV1, EffectClass, R2_OBJECT_PATH, ResponseBodyModeV1,
    RiskClass, official_reference, refresh_dynamic_mutation_contract, zero_direct_usage_cost,
};
use cfctl_core::r2_recovery::{CAPTURE_ID, OBJECTS_PATH, VERIFY_ID};
use cfctl_core::{
    R2PrivateFileUploadContractV1, ResponseContractV1, SelectorContractV1, SelectorV1,
};
use serde_json::json;

pub(super) fn capture_capability() -> CapabilityV1 {
    let mut cap = CapabilityV1::new(
        CAPTURE_ID,
        "Capture a bounded private R2 bucket snapshot",
        "GET",
        OBJECTS_PATH,
    );
    cap.description = Some("Capture the entire bucket to a new private directory with --out. Version 2 requires fresh authenticated account-token identity and account-scoped R2 read-policy evidence. Two explicit-terminal S3 ListObjectsV2 inventories share ten pages of 100 objects (at most 500 objects in two passes); REST exact-member reads preserve and compare all returned metadata before and after body capture. P+3N requests are bounded at 3010 attempts, with 2 MiB per XML/metadata response, 20 MiB aggregate XML and 40 MiB aggregate metadata; all object reads share 300000000 bytes and a caller-bound window of at most 900 seconds. Retains all returned metadata privately and checks ETag, size and population drift. No retries, truncation, public bytes, restore, or writer/retention/D1 qualification.".into());
    cap.product = "R2 Object".into();
    cap.source = "cfctl native private R2 capture adapter".into();
    cap.account_scope = "account".into();
    cap.permissions = vec!["Workers R2 Storage Read".into()];
    cap.mutating = false;
    cap.risk = RiskClass::Read;
    cap.effect = EffectClass::ReadOnly;
    cap.adapter_status = AdapterStatus::Native;
    cap.blocked_reason = None;
    cap.entitlement.available = Some(true);
    cap.verification.required = true;
    cap.verification.strategy = "r2_private_capture".into();
    cap.rollback.supported = false;
    cap.rollback.warning = Some("Capture integrity does not qualify retention, writer exclusion, D1 recovery or conditional restore. Private files persist after incomplete capture; absence of a complete authenticated receipt is a hold.".into());
    cap.selectors = ["account_id", "bucket_name"].map(|name| SelectorV1 {
        name: name.into(), location: "path".into(), required: true,
        value_type: "string".into(), description: None,
        contract: Some(SelectorContractV1 { schema: if name == "account_id" {
            json!({"type":"string","pattern":"^[a-f0-9]{32}$"})
        } else {
            json!({"type":"string","minLength":3,"maxLength":63,"pattern":"^[a-z0-9][a-z0-9-]*[a-z0-9]$"})
        }, query: None }),
    }).to_vec();
    cap.request_schema = Some(json!({
        "type":"object", "additionalProperties":false,
        "required":["schema_version","window","token_verification_evidence_hash","token_policy_evidence_hash"],
        "properties":{
            "schema_version":{"const":2},
            "token_verification_evidence_hash":{"type":"string","pattern":"^sha256:[a-f0-9]{64}$"},
            "token_policy_evidence_hash":{"type":"string","pattern":"^sha256:[a-f0-9]{64}$"},
            "window":{"type":"object","additionalProperties":false,
                "required":["window_id","opened_at","expires_at","recovery_binding_sha256"],
                "properties":{
                    "window_id":{"type":"string","format":"uuid"},
                    "opened_at":{"type":"string","format":"date-time"},
                    "expires_at":{"type":"string","format":"date-time"},
                    "recovery_binding_sha256":{"type":"string","pattern":"^[a-f0-9]{64}$"}
                }
            }
        }
    }));
    cap.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".into()],
        success_media_types: vec!["application/json".into()],
        body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
    });
    zero_direct_usage_cost(
        &mut cap,
        "P S3 list + 2N REST metadata + N body reads (P+3N, at most 3010 attempts) incur ordinary R2 Class A/B operation and applicable retrieval usage; no provider configuration or storage creation",
        vec![official_reference(
            "R2 pricing",
            "https://developers.cloudflare.com/r2/pricing/",
        )],
    );
    cap
}

pub(super) fn verify_capability() -> CapabilityV1 {
    let mut cap = capture_capability();
    cap.id = VERIFY_ID.into();
    cap.title = "Verify an authenticated private R2 capture locally".into();
    cap.description = Some("Read the private snapshot directory supplied by --source-file and compare every byte and metadata record with the authenticated native capture receipt identified by capture_evidence_hash and capture_run_id. No provider requests. This verifies capture integrity only; combined D1/window/retention and conditional restore qualification remain separate.".into());
    cap.permissions.clear();
    cap.verification.strategy = "private_capture_authenticated_local_integrity".into();
    cap.request_schema = Some(json!({"type":"object","additionalProperties":false,
    "required":["capture_evidence_hash","capture_run_id"],"properties":{
        "capture_evidence_hash":{"type":"string","pattern":"^sha256:[a-f0-9]{64}$"},
        "capture_run_id":{"type":"string","format":"uuid"}
    }}));
    zero_direct_usage_cost(
        &mut cap,
        "local authenticated evidence and private file reads only",
        vec![],
    );
    cap
}

pub(super) fn restore_capability() -> CapabilityV1 {
    let mut cap = capture_capability();
    cap.id = cfctl_core::r2_restore::RESTORE_ID.into();
    cap.title = "Conditionally restore one authenticated private R2 capture member".into();
    cap.source = "cfctl native private R2 restore adapter".into();
    cap.method = "PUT".into();
    cap.description = Some("Use --source-file for a private declaration of original and current capture directories. Native authenticated capture members, current account-token identity/policy evidence and managed private copies bind the existing PlanV2 approval and one-use execution. The compiled S3 endpoint uses the exact account and default jurisdiction. At most one conditional PUT, bounded private reads and metadata readback; no replay or extra-key deletion. If-Match binds content ETag, not atomic semantic metadata. Combined writer/D1/retention recovery remains unqualified.".into());
    cap.permissions = vec!["Workers R2 Storage Write".into()];
    cap.mutating = true;
    cap.risk = RiskClass::ScopedWrite;
    cap.effect = EffectClass::DataWrite;
    cap.verification.strategy = cfctl_core::r2_restore::STRATEGY.into();
    cap.rollback.warning = Some("Displaced bytes and both authenticated snapshots remain privately staged. An uncertain write or failed verification requires read-only plans rectify; it never replays PUT. This primitive cannot prove atomic metadata comparison, writer exclusion, full database/object recovery or retention, and must not release application writers.".into());
    let capture_ref = json!({"type":"object","additionalProperties":false,
        "required":["evidence_hash","run_id"],"properties":{
            "evidence_hash":{"type":"string","pattern":"^sha256:[a-f0-9]{64}$"},
            "run_id":{"type":"string","format":"uuid"}}});
    cap.request_schema = Some(json!({"type":"object","additionalProperties":false,
    "required":["source_capture","source_object_index","current_capture","expected_current","token_verification_evidence_hash","token_policy_evidence_hash"],
    "properties":{
        "source_capture":capture_ref,"current_capture":capture_ref,
        "source_object_index":{"type":"integer","minimum":0,"maximum":999},
        "expected_current":{"oneOf":[
            {"type":"object","additionalProperties":false,"required":["state"],"properties":{"state":{"const":"absent"}}},
            {"type":"object","additionalProperties":false,"required":["state","object_index"],"properties":{"state":{"const":"present"},"object_index":{"type":"integer","minimum":0,"maximum":999}}}
        ]},
        "token_verification_evidence_hash":{"type":"string","pattern":"^sha256:[a-f0-9]{64}$"},
        "token_policy_evidence_hash":{"type":"string","pattern":"^sha256:[a-f0-9]{64}$"}
    }}));
    zero_direct_usage_cost(
        &mut cap,
        "one R2 Class A write and bounded Class A/B observations use ordinary operation, storage and applicable Infrequent Access retrieval rates; this creates no bucket or retention policy",
        vec![official_reference(
            "R2 pricing",
            "https://developers.cloudflare.com/r2/pricing/",
        )],
    );
    cap
}

pub(super) fn finalize_r2_private_file_upload_contract(
    capabilities: &mut BTreeMap<String, CapabilityV1>,
) {
    let read_supported = capabilities
        .get("r2-get-object")
        .is_some_and(|capability| capability.method == "GET" && capability.path == R2_OBJECT_PATH);
    let delete_supported = capabilities
        .get("r2-delete-object")
        .is_some_and(|capability| {
            capability.method == "DELETE"
                && capability.path == R2_OBJECT_PATH
                && capability.permissions == ["Workers R2 Storage Write"]
        });
    let Some(capability) = capabilities.get_mut("r2-put-object") else {
        return;
    };
    let operation_supported = capability.method == "PUT"
        && capability.path == R2_OBJECT_PATH
        && capability.product == "R2 Object"
        && capability.request_schema.is_none()
        && capability
            .response_contract
            .as_ref()
            .is_some_and(|response| {
                response.success_statuses == ["200"]
                    && response.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
            })
        && capability.selectors.iter().any(|selector| {
            selector.name == "object_key"
                && selector.location == "path"
                && selector.required
                && selector
                    .description
                    .as_deref()
                    .is_some_and(|description| description.contains("MUST NOT be percent-encoded"))
        });
    if !operation_supported || !read_supported || !delete_supported {
        capability.adapter_status = AdapterStatus::Blocked;
        capability.blocked_reason = Some(
            "R2 create-only private-file upload, conditional readback, or exact delete contract drifted"
                .to_owned(),
        );
        return;
    }
    let Some(content_type) = capability
        .selectors
        .iter_mut()
        .find(|selector| selector.name == "Content-Type" && selector.location == "header")
    else {
        capability.adapter_status = AdapterStatus::Blocked;
        capability.blocked_reason = Some("R2 upload Content-Type selector drifted".to_owned());
        return;
    };
    content_type.required = true;
    capability.permissions = vec!["Workers R2 Storage Write".to_owned()];
    capability.risk = RiskClass::ScopedWrite;
    capability.effect = EffectClass::ReversibleWrite;
    zero_direct_usage_cost(
        capability,
        "the upload is one R2 Class A operation with no direct configuration charge; retained bytes and later reads incur ordinary R2 storage and operation usage",
        vec![official_reference(
            "R2 pricing",
            "https://developers.cloudflare.com/r2/pricing/",
        )],
    );
    capability.entitlement.source =
        Some("https://developers.cloudflare.com/r2/platform/limits/".to_owned());
    capability.verification.required = true;
    "r2_private_file_upload_etag_and_conditional_read"
        .clone_into(&mut capability.verification.strategy);
    capability.rollback.supported = false;
    capability.rollback.strategy = None;
    capability.rollback.warning = Some(
        "the immutable upload is create-only; rollback is a separately reviewed exact-object delete plan, while replacement requires a new digest-addressed key"
            .to_owned(),
    );
    capability.r2_private_file_upload = Some(R2PrivateFileUploadContractV1 {
        max_source_bytes: 300_000_000,
        allowed_content_types: vec![
            "application/json".to_owned(),
            "application/octet-stream".to_owned(),
        ],
        require_if_none_match_star: true,
        read_capability_id: "r2-get-object".to_owned(),
        delete_capability_id: "r2-delete-object".to_owned(),
        etag_algorithm: "md5".to_owned(),
    });
    refresh_dynamic_mutation_contract(capability);
}
