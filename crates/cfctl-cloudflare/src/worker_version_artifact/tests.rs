#![allow(clippy::expect_used)]
use super::*;
const VERSION: &str = "11111111-1111-4111-8111-111111111111";
fn fixture() -> Value {
    json!({"id":VERSION,"main_module":"index.js","assets":{"jwt":"private-jwt"},
            "modules":[{"name":"index.js","content_type":"application/javascript", "content_base64":STANDARD.encode("private module text")}]})
}
#[test]
fn retains_only_version_bound_digests() {
    let projected = project(&fixture(), VERSION).expect("valid bounded test fixture");
    let text = projected.to_string();
    assert!(!text.contains("private"));
    assert!(!text.contains(&STANDARD.encode("private module text")));
    assert_eq!(
        projected["manifest"]["modules"][0]["sha256"],
        digest(b"private module text")
    );
    assert_eq!(projected["complete"], true);
    assert_eq!(projected["static_asset_bytes_verified"], false);
}
#[test]
fn rejects_partial_ambiguous_or_malformed_modules() {
    for change in 0..7 {
        let mut value = fixture();
        match change {
            0 => value["id"] = json!("22222222-2222-4222-8222-222222222222"),
            1 => value["modules"] = json!([]),
            2 => {
                value["modules"] =
                    json!([value["modules"][0].clone(), value["modules"][0].clone()]);
            }
            3 => value["modules"][0]["content_base64"] = json!("invalid!"),
            4 => value["main_module"] = json!("missing.js"),
            5 => value["modules"][0]["name"] = json!("../index.js"),
            _ => value["modules"] = Value::Null,
        }
        assert!(project(&value, VERSION).is_err());
    }
    assert!(project(&fixture(), "latest").is_err());
}
#[test]
fn manifest_is_order_independent_and_bounds_module_count() {
    let mut value = fixture();
    value["modules"].as_array_mut().expect("valid bounded test fixture").push(json!({
            "name":"module.wasm","content_type":"application/wasm","content_base64":STANDARD.encode([0,97,115,109])
        }));
    let first = project(&value, VERSION).expect("valid bounded test fixture");
    value["modules"]
        .as_array_mut()
        .expect("valid bounded test fixture")
        .reverse();
    assert_eq!(
        first,
        project(&value, VERSION).expect("valid bounded test fixture")
    );
    value["modules"] = json!(vec![value["modules"][0].clone(); MAX_MODULES + 1]);
    assert!(project(&value, VERSION).is_err());
}

fn capability() -> CapabilityV1 {
    use cfctl_core::{
        AdapterStatus, EffectClass, ResponseBodyModeV1, ResponseContractV1, RiskClass, SelectorV1,
    };
    let mut cap = CapabilityV1::new(
        WORKER_VERSION_ARTIFACT_DIGEST_ID,
        "Digest",
        "GET",
        WORKER_VERSION_ARTIFACT_PATH,
    );
    cap.adapter_status = AdapterStatus::Native;
    cap.risk = RiskClass::Read;
    cap.effect = EffectClass::ReadOnly;
    cap.permissions = vec!["Workers Scripts Read".to_owned()];
    cap.verification.required = true;
    cap.verification.strategy = "worker_version_artifact_digest".to_owned();
    cap.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".to_owned()],
        success_media_types: vec!["application/json".to_owned()],
        body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
    });
    cap.selectors = ["account_id", "worker_id", "version_id", "include"]
        .into_iter()
        .map(|name| SelectorV1 {
            name: name.to_owned(),
            location: if name == "include" { "query" } else { "path" }.to_owned(),
            required: name != "include",
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        })
        .collect();
    cap
}

#[tokio::test]
async fn provider_boundary_never_returns_code_or_private_metadata() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
    };
    for wrong_version in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").expect("valid bounded test fixture");
        let address = listener.local_addr().expect("valid bounded test fixture");
        let mut result = fixture();
        if wrong_version {
            result["id"] = json!("22222222-2222-4222-8222-222222222222");
        }
        let body = json!({"success":true,"errors":[],"result":result}).to_string();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("valid bounded test fixture");
            let mut request = [0_u8; 8192];
            let size = stream
                .read(&mut request)
                .expect("valid bounded test fixture");
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(),body).expect("valid bounded test fixture");
            String::from_utf8_lossy(&request[..size]).into_owned()
        });
        let executor = Executor::new(reqwest::Client::new(), &format!("http://{address}"))
            .expect("valid bounded test fixture")
            .with_max_retries(0);
        let input = CallInput {
            selectors: json!({"account_id":"a".repeat(32),"worker_id":"example-worker","version_id":VERSION}),
            query: json!({}),
            body: None,
            if_match: None,
            if_none_match: None,
        };
        let response = executor
            .execute_read(
                &capability(),
                &input,
                &AuthCredential::Bearer {
                    token: "fixture".to_owned(),
                },
            )
            .await
            .expect("valid bounded test fixture");
        let request = server.join().expect("valid bounded test fixture");
        assert!(request.contains("include=modules"));
        assert!(request.contains(VERSION));
        assert_eq!(response.success, !wrong_version);
        if wrong_version {
            assert_eq!(response.result["diagnostic"], "version_binding_mismatch");
        }
        let retained = serde_json::to_string(&response).expect("valid bounded test fixture");
        assert!(!retained.contains("private-jwt"));
        assert!(!retained.contains(&STANDARD.encode("private module text")));
    }
}

#[tokio::test]
async fn refuses_nonexact_inputs_before_network() {
    let executor = Executor::new(reqwest::Client::new(), "http://127.0.0.1:1")
        .expect("valid bounded test fixture")
        .with_max_retries(0);
    for change in 0..5 {
        let mut cap = capability();
        let mut input = CallInput {
            selectors: json!({"account_id":"a".repeat(32),"worker_id":"example-worker","version_id":VERSION}),
            query: json!({}),
            body: None,
            if_match: None,
            if_none_match: None,
        };
        match change {
            0 => input.selectors["version_id"] = json!("latest"),
            1 => input.query = json!({"include":"other"}),
            2 => input.body = Some(json!({})),
            3 => cap.method = "DELETE".to_owned(),
            _ => input.if_none_match = Some("*".to_owned()),
        }
        let error = executor
            .execute_read(
                &cap,
                &input,
                &AuthCredential::Bearer {
                    token: "fixture".to_owned(),
                },
            )
            .await
            .expect_err("invalid input must fail before network");
        assert!(matches!(error, CloudflareError::InvalidRequestBody(_)));
    }
}

#[test]
fn preserves_wrangler_relative_module_names_and_rejects_alias_collisions() {
    let mut value = fixture();
    let wasm = json!({"name":"./module.wasm","content_type":"application/wasm","content_base64":STANDARD.encode([0,97,115,109])});
    value["modules"]
        .as_array_mut()
        .expect("modules array")
        .push(wasm.clone());
    let projected = project(&value, VERSION).expect("Wrangler relative module name");
    assert_eq!(projected["manifest"]["modules"][0]["name"], "./module.wasm");
    let mut alias = wasm;
    alias["name"] = json!("module.wasm");
    value["modules"]
        .as_array_mut()
        .expect("modules array")
        .push(alias);
    assert_eq!(project(&value, VERSION), Err("module_duplicate_name"));
    for name in ["./../module.wasm", "././module.wasm", ".//module.wasm"] {
        let mut unsafe_value = fixture();
        unsafe_value["modules"][0]["name"] = json!(name);
        assert_eq!(project(&unsafe_value, VERSION), Err("module_name_invalid"));
    }
}
