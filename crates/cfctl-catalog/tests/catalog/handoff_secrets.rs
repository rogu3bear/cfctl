use super::{turnstile_widget_update_fixture, workers_script_secret_fixture};
use cfctl_catalog::normalize_openapi;
use cfctl_core::{AdapterStatus, RiskClass, turnstile_secret};
use serde_json::json;

#[test]
fn handoff_current_single_secret_put_retains_closed_contract() {
    let mut doc = workers_script_secret_fixture();
    let put =
        &mut doc["paths"]["/accounts/{account_id}/workers/scripts/{script_name}/secrets"]["put"];
    put["summary"] = json!("Add a secret to a Worker script");
    put["description"] = json!(
        "Add a secret to a Worker script by creating a new version with that secret.\n\nWhen changing more than one secret at a time, prefer the \"Patch multiple\nscript secrets\" API instead of changing many secrets individually.\n"
    );
    let get = &mut doc["paths"]["/accounts/{account_id}/workers/scripts/{script_name}/secrets/{secret_name}"]
        ["get"];
    get["summary"] = json!("Get a secret binding");
    get["description"] = json!("Get a given secret binding (value omitted) on a Worker script.");
    let catalog = normalize_openapi(&doc).expect("current schema");
    let cap = catalog.get("worker-put-script-secret").expect("put");
    assert_eq!(
        cap.adapter_status,
        AdapterStatus::DynamicApi,
        "{:?}",
        cap.blocked_reason
    );
    assert_eq!(cap.risk, RiskClass::SecretSensitive);
    assert!(cap.verification_contract_supported());
    assert!(
        cap.rollback
            .warning
            .as_deref()
            .expect("warning")
            .contains("new Worker version")
    );
    doc["paths"]["/accounts/{account_id}/workers/scripts/{script_name}/secrets"]["put"]["description"] =
        json!("Replace all secrets and code.");
    let catalog = normalize_openapi(&doc).expect("drifted schema");
    assert_eq!(
        catalog
            .get("worker-put-script-secret")
            .expect("put")
            .adapter_status,
        AdapterStatus::Blocked
    );
}

#[test]
fn handoff_widget_read_is_secret_sensitive_and_rejects_permission_drift() {
    let mut doc = turnstile_widget_update_fixture();
    let path = "/accounts/{account_id}/challenges/widgets/{sitekey}";
    doc["paths"][path]["get"]["x-api-token-group"] = json!([
        "Turnstile Sites Write",
        "Turnstile Sites Read",
        "Account Settings Write",
        "Account Settings Read"
    ]);
    let catalog = normalize_openapi(&doc).expect("widget schema");
    let cap = catalog.get(turnstile_secret::ID).expect("widget");
    assert_eq!(
        cap.adapter_status,
        AdapterStatus::DynamicApi,
        "{:?}",
        cap.blocked_reason
    );
    assert_eq!(cap.risk, RiskClass::SecretSensitive);
    assert_eq!(cap.verification.strategy, turnstile_secret::VERIFY);
    assert!(!cap.mutating);
    doc["paths"][path]["get"]["x-api-token-group"] = json!(["Account Settings Read"]);
    let catalog = normalize_openapi(&doc).expect("drifted schema");
    assert_eq!(
        catalog
            .get(turnstile_secret::ID)
            .expect("widget")
            .adapter_status,
        AdapterStatus::Blocked
    );
}
