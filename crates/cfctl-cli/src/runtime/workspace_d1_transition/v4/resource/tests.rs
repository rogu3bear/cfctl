#![allow(clippy::expect_used, clippy::wildcard_imports)]
use super::*;
use serde_json::json;

fn response() -> CloudflareResponseV1 {
    serde_json::from_value(json!({"status":200,"success":true,
        "result":{"uuid":"22222222-2222-4222-8222-222222222222","name":"team-case"},
        "errors":[],"result_info":null,"etag":null,"cf_ray":null}))
    .expect("response")
}

#[test]
fn qualification_create_uuid_requires_success_and_exact_native_readback() {
    let apply = response();
    let verification = OperationVerificationV1 {
        strategy: "created_resource_contains_planned_fields_by_returned_id".into(),
        passed: true,
        basis: "fixture".into(),
        readback: response(),
        correlated_resource_id: None,
    };
    assert_eq!(
        created_uuid(&apply, &verification, "team-case").expect("native pair"),
        "22222222-2222-4222-8222-222222222222"
    );
    for mutation in 0..7 {
        let mut apply = apply.clone();
        let mut verification = verification.clone();
        match mutation {
            0 => {
                verification.readback.result["uuid"] =
                    json!("33333333-3333-4333-8333-333333333333");
            }
            1 => verification.readback.result["name"] = json!("other-case"),
            2 => apply.success = false,
            3 => apply.status = 500,
            4 => verification.passed = false,
            5 => apply.result["uuid"] = json!("caller-supplied-name"),
            _ => verification.readback.status = 404,
        }
        assert!(created_uuid(&apply, &verification, "team-case").is_err());
    }
}
