#![allow(clippy::wildcard_imports, reason = "white-box domain tests")]
#![allow(clippy::expect_used)]

use cfctl_auth::MemorySecretStore;
use cfctl_core::{
    AdapterStatus, EffectClass, R2PrivateFileUploadContractV1, RiskClass, SelectorV1,
};
use cfctl_storage::RuntimePaths;

use super::*;

#[test]
fn private_stage_keeps_path_and_bytes_out_of_plan_json() {
    let root = tempfile::tempdir_in("/private/tmp").expect("temporary root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let source = root.path().join("policy.json");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&source).expect("private source");
    file.write_all(br#"{"operator":"operator@example.com"}"#)
        .expect("write source");
    file.sync_all().expect("sync source");

    let mut capability = CapabilityV1::new(
        "r2-put-object",
        "Upload Object",
        "PUT",
        "/accounts/{account_id}/r2/buckets/{bucket_name}/objects/{object_key}",
    );
    capability.mutating = true;
    capability.adapter_status = AdapterStatus::DynamicApi;
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
        .into_iter()
        .chain([SelectorV1 {
            name: "Content-Type".to_owned(),
            location: "header".to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        }])
        .collect();
    capability.r2_private_file_upload = Some(R2PrivateFileUploadContractV1 {
        max_source_bytes: 300_000_000,
        allowed_content_types: vec!["application/json".to_owned()],
        require_if_none_match_star: true,
        read_capability_id: "r2-get-object".to_owned(),
        delete_capability_id: "r2-delete-object".to_owned(),
        etag_algorithm: "md5".to_owned(),
    });
    let input = CallInput {
        selectors: json!({
            "account_id":"account",
            "bucket_name":"policy-bucket",
            "object_key":"config/policy/digest.json",
            "Content-Type":"application/json"
        }),
        if_none_match: Some("*".to_owned()),
        ..CallInput::default()
    };
    let secrets = MemorySecretStore::default();
    let target = prepare_plan_target(&store, &secrets, &capability, &input, &source)
        .expect("target")
        .expect("upload target");
    let stage_ref = required_string(&target, "stage_ref")
        .expect("stage ref")
        .to_owned();
    let mut plan =
        PlanV1::draft("profile", "account", "catalog", capability, json!({})).expect("plan");
    plan.input = serde_json::to_value(&input).expect("input");
    plan.targets = json!({"adapter":{"r2_private_file_upload":target}});
    let encoded = serde_json::to_string(&plan).expect("plan JSON");
    assert!(!encoded.contains(&source.display().to_string()));
    assert!(!encoded.contains("operator@example.com"));
    validate_bound_plan(&store, &plan, &secrets).expect("bound plan");
    let loaded = load(&store, &plan, &secrets).expect("managed bytes");
    assert_eq!(loaded.bytes, br#"{"operator":"operator@example.com"}"#);
    let rectification =
        rectification_target(&store, &plan, &secrets).expect("rectification target");
    assert_eq!(
        rectification.rectification_read_capability_id,
        "r2-get-private-object-digest"
    );
    assert_eq!(
        rectification.input.selectors,
        json!({
            "account_id":"account",
            "bucket_name":"policy-bucket",
            "object_key":"config/policy/digest.json"
        })
    );
    assert_eq!(rectification.source_bytes, loaded.bytes.len() as u64);
    let stage_dir = load_binding(&secrets, &target)
        .expect("binding before discard")
        .path
        .parent()
        .expect("stage directory")
        .to_path_buf();
    discard(&store, &plan, &secrets).expect("discard stage");
    assert!(secrets.get(&stage_ref).expect("secret read").is_none());
    assert!(!stage_dir.exists());
}

#[test]
fn caller_cannot_override_derived_content_length() {
    let root = tempfile::tempdir_in("/private/tmp").expect("temporary root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let source = root.path().join("policy.json");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&source).expect("private source");
    file.write_all(br#"{"routes":141}"#).expect("write source");
    file.sync_all().expect("sync source");
    let mut capability = CapabilityV1::new(
        "r2-put-object",
        "Upload Object",
        "PUT",
        "/accounts/{account_id}/r2/buckets/{bucket_name}/objects/{object_key}",
    );
    capability.r2_private_file_upload = Some(R2PrivateFileUploadContractV1 {
        max_source_bytes: 300_000_000,
        allowed_content_types: vec!["application/json".to_owned()],
        require_if_none_match_star: true,
        read_capability_id: "r2-get-object".to_owned(),
        delete_capability_id: "r2-delete-object".to_owned(),
        etag_algorithm: "md5".to_owned(),
    });
    let input = CallInput {
        selectors: json!({
            "Content-Type":"application/json",
            "Content-Length":"1"
        }),
        if_none_match: Some("*".to_owned()),
        ..CallInput::default()
    };
    let error = prepare_plan_target(
        &store,
        &MemorySecretStore::default(),
        &capability,
        &input,
        &source,
    )
    .expect_err("caller-provided content length must fail");
    assert!(error.to_string().contains("Content-Length is derived"));
}
