use super::*;

const COLLECTION: &str = "/accounts/{account_id}/storage/kv/namespaces";

#[test]
fn official_referenced_json_bodies_restore_validation_without_inventing_authority() {
    let document: Value =
        serde_json::from_str(include_str!("../fixtures/referenced-json-operations.json")).unwrap();
    let snapshot = normalize_openapi(&document).unwrap();
    for (id, field) in [
        ("updateUrlNormalization", "scope"),
        ("updateManagedTransforms", "managed_request_headers"),
    ] {
        let capability = snapshot.get(id).unwrap();
        let schema = capability.request_schema.as_ref().unwrap();
        assert_eq!(schema["x-cfctl-body-required"], true);
        assert!(schema["properties"].get(field).is_some());
        assert_eq!(capability.adapter_status, AdapterStatus::Blocked);
        assert!(!capability.cost.known);
    }
}

#[test]
fn queue_metrics_negotiates_only_the_declared_json_envelope() {
    let document: Value =
        serde_json::from_str(include_str!("../fixtures/referenced-json-operations.json")).unwrap();
    let snapshot = normalize_openapi(&document).unwrap();
    let metrics = snapshot.get("queues-get-metrics").unwrap();
    assert_eq!(metrics.adapter_status, AdapterStatus::DynamicApi);
    let response = metrics.response_contract.as_ref().unwrap();
    assert_eq!(
        response.body_mode,
        ResponseBodyModeV1::CloudflareJsonEnvelope
    );
    assert_eq!(response.success_media_types, ["application/json"]);
    assert_eq!(response.success_statuses, ["200"]);
    assert!(!metrics.mutating);
}

#[test]
fn entitlement_cancellation_is_not_an_empty_success_and_schema_drift_stays_blocked() {
    let mut document: Value =
        serde_json::from_str(include_str!("../fixtures/referenced-json-operations.json")).unwrap();
    let snapshot = normalize_openapi(&document).unwrap();
    for id in [
        "entitlements-get-account-entitlements",
        "entitlements-get-zone-entitlements",
    ] {
        let capability = snapshot.get(id).unwrap();
        assert_eq!(capability.adapter_status, AdapterStatus::DynamicApi);
        let response = capability.response_contract.as_ref().unwrap();
        assert_eq!(response.success_statuses, ["200"]);
        assert_eq!(
            response.body_mode,
            ResponseBodyModeV1::CloudflareJsonEnvelope
        );
        assert!(!capability.mutating);
    }
    document["paths"]["/accounts/{account_id}/entitlements"]["get"]["responses"]["204"]["description"] =
        json!("Empty successful entitlement list");
    assert_eq!(
        normalize_openapi(&document)
            .unwrap()
            .get("entitlements-get-account-entitlements")
            .unwrap()
            .adapter_status,
        AdapterStatus::Blocked
    );
}

#[test]
fn referenced_request_bodies_preserve_inline_lifecycle_contracts() {
    let mut document = workers_kv_namespace_fixture();
    let inline = normalize_openapi(&document).expect("inline catalog");
    document["components"]["requestBodies"]["Namespace"] =
        document["paths"][COLLECTION]["post"]["requestBody"].take();
    document["components"]["requestBodies"]["Alias"] =
        json!({"$ref":"#/components/requestBodies/Namespace"});
    document["paths"][COLLECTION]["post"]["requestBody"] =
        json!({"$ref":"#/components/requestBodies/Alias"});
    let referenced = normalize_openapi(&document).expect("referenced catalog");
    assert_eq!(
        serde_json::to_value(&inline.capabilities).unwrap(),
        serde_json::to_value(&referenced.capabilities).unwrap(),
        "reference indirection must retain required bodies, permissions, costs and recovery"
    );
}

#[test]
fn request_body_references_fail_closed_on_invalid_or_unbounded_targets() {
    for reference in [
        json!("https://example.invalid/body.json"),
        json!("#/components/requestBodies/Missing"),
        json!(false),
        json!("#/components/requestBodies/Cycle"),
    ] {
        let mut document = workers_kv_namespace_fixture();
        document["components"]["requestBodies"]["Cycle"] =
            json!({"$ref":"#/components/requestBodies/Cycle"});
        document["paths"][COLLECTION]["post"]["requestBody"] = json!({"$ref":reference});
        assert!(normalize_openapi(&document).is_err(), "{reference}");
    }
}

#[test]
fn malformed_reference_targets_cannot_erase_a_request_body() {
    for body in [
        json!(null),
        json!(true),
        json!([]),
        json!({}),
        json!({"content":true}),
        json!({"content":{"application/json":{"schema":{"type":"object"}}},"required":"true"}),
    ] {
        let mut document = workers_kv_namespace_fixture();
        document["components"]["requestBodies"]["Malformed"] = body;
        document["paths"][COLLECTION]["post"]["requestBody"] =
            json!({"$ref":"#/components/requestBodies/Malformed"});
        assert!(normalize_openapi(&document).is_err());
    }
}

#[test]
fn request_body_reference_depth_is_bounded_without_changing_schema_depth() {
    let mut document = workers_kv_namespace_fixture();
    let body = document["paths"][COLLECTION]["post"]["requestBody"].take();
    for index in 0..16 {
        document["components"]["requestBodies"][format!("Body{index}")] =
            json!({"$ref":format!("#/components/requestBodies/Body{}", index + 1)});
    }
    document["components"]["requestBodies"]["Body16"] = body;
    document["paths"][COLLECTION]["post"]["requestBody"] =
        json!({"$ref":"#/components/requestBodies/Body1"});
    let bounded = normalize_openapi(&document).expect("sixteen references");
    assert_eq!(
        bounded
            .get("workers-kv-namespace-create-a-namespace")
            .unwrap()
            .adapter_status,
        AdapterStatus::DynamicApi
    );
    document["paths"][COLLECTION]["post"]["requestBody"] =
        json!({"$ref":"#/components/requestBodies/Body0"});
    assert!(
        normalize_openapi(&document).is_err(),
        "seventeen references"
    );
}

#[test]
fn referenced_responses_preserve_inline_verification_and_recovery_contracts() {
    let mut document = workers_kv_namespace_fixture();
    let inline = normalize_openapi(&document).expect("inline catalog");
    let paths = document["paths"].as_object_mut().unwrap();
    let mut responses = serde_json::Map::new();
    for (path_index, (_, path_item)) in paths.iter_mut().enumerate() {
        for (method, operation) in path_item.as_object_mut().unwrap() {
            for (status, response) in operation["responses"].as_object_mut().unwrap() {
                let name = format!("Response{path_index}{method}{status}");
                responses.insert(name.clone(), response.take());
                *response = json!({"$ref":format!("#/components/responses/{name}")});
            }
        }
    }
    document["components"]["responses"] = Value::Object(responses);
    let referenced = normalize_openapi(&document).expect("referenced catalog");
    assert_eq!(
        serde_json::to_value(&inline.capabilities).unwrap(),
        serde_json::to_value(&referenced.capabilities).unwrap(),
        "the response decoder and lifecycle classifiers must resolve the same response"
    );
}
