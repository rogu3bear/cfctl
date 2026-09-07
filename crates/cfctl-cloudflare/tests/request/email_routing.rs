use super::json_response_sequence_server;
use cfctl_auth::AuthCredential;
use cfctl_cloudflare::{CallInput, Executor};
use cfctl_core::{CapabilityV1, ResponseBodyModeV1, ResponseContractV1, SelectorV1};
use serde_json::json;

#[tokio::test]
async fn email_routing_rules_read_returns_one_bounded_typed_projection() {
    let (address, server) = json_response_sequence_server(vec![
        r#"{"success":true,"result":[{"tag":"rule-001","enabled":true,"matchers":[{"type":"literal","field":"to","value":"security@example.com"}],"actions":[{"type":"worker","value":["maildesk-router"]}]}],"errors":[],"result_info":{"page":1,"per_page":1,"count":1,"total_pages":3,"total_count":3}}"#,
        r#"{"success":true,"result":[{"tag":"rule-002","enabled":true,"matchers":[{"type":"all"}],"actions":[{"type":"drop"}]}],"errors":[],"result_info":{"page":2,"per_page":1,"count":1,"total_pages":3,"total_count":3}}"#,
        r#"{"success":true,"result":[{"tag":"rule-003","enabled":true,"matchers":[{"type":"literal","field":"to","value":"info@example.com"}],"actions":[{"type":"forward","value":["operator@example.com"]}]}],"errors":[],"result_info":{"page":3,"per_page":1,"count":1,"total_pages":3,"total_count":3}}"#,
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
    assert_eq!(response.result["page_size"], 1);
    assert_eq!(response.result["rule_count"], 3);
    assert_eq!(response.result["rules"][0]["rule_identifier"], "rule-001");
    assert_eq!(response.result["rules"][0]["matchers"][0]["field"], "to");
    assert_eq!(
        response.result["rules"][0]["matchers"][0]["value_sha256"],
        "sha256:786906db96ef646937f205d3e7398630ce2e97df5364baf31b81ef84f1386c3f"
    );
    assert_eq!(
        response.result["rules"][0]["actions"][0]["worker_targets"],
        json!(["maildesk-router"])
    );
    assert_eq!(response.result["rules"][1]["actions"][0]["value_count"], 0);
    assert_eq!(response.result["rules"][2]["actions"][0]["value_count"], 1);
    assert!(response.result["rules"][2]["actions"][0]["worker_targets"].is_null());
    let serialized = serde_json::to_string(&response.result).expect("serialize projection");
    assert!(!serialized.contains("operator@example.com"));
    assert!(!serialized.contains("security@example.com"));

    let requests = server.await.expect("server joins");
    assert_eq!(requests.len(), 3);
    assert!(requests[0].contains("page=1"));
    assert!(requests[0].contains("per_page=50"));
    assert!(requests[1].contains("page=2"));
    assert!(requests[2].contains("page=3"));
}

#[tokio::test]
async fn account_email_routing_rules_read_paginates_and_retains_only_hashed_rule_domain() {
    let (address, server) = json_response_sequence_server(vec![
        r#"{"success":true,"result":[{"id":"rule-001","enabled":true,"zone":{"name":"reply.example.com","tag":"parent-zone-tag"},"matchers":[{"type":"all"}],"actions":[{"type":"worker","value":["maildesk-router"]}]}],"errors":[],"result_info":{"page":1,"per_page":1,"count":1,"total_pages":2,"total_count":2}}"#,
        r#"{"success":true,"result":[{"id":"rule-002","enabled":false,"zone":{"name":"reply.example.net","tag":"other-zone-tag"},"matchers":[{"type":"all"}],"actions":[{"type":"worker","value":["other-router"]}]}],"errors":[],"result_info":{"page":2,"per_page":1,"count":1,"total_pages":2,"total_count":2}}"#,
    ])
    .await;
    let mut capability = CapabilityV1::new(
        cfctl_core::EMAIL_ROUTING_ACCOUNT_RULES_LIST_CAPABILITY_ID,
        "List account routing rules",
        "GET",
        cfctl_core::EMAIL_ROUTING_ACCOUNT_RULES_LIST_PATH,
    );
    capability.selectors = vec![SelectorV1 {
        name: "account_id".to_owned(),
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
                selectors: json!({"account_id":"private-account"}),
                ..CallInput::default()
            },
            &AuthCredential::Bearer {
                token: "token".to_owned(),
            },
        )
        .await
        .expect("typed account Email Routing response");

    assert!(response.success);
    assert_eq!(response.result["complete"], true);
    assert_eq!(response.result["page_size"], 1);
    assert_eq!(
        response.result["rules"][0]["zone_name_sha256"],
        "sha256:ee551193ff63e4819a1f4333a425488c2980fe91b67f1d6b3d66faaa24f4e708"
    );
    let serialized = serde_json::to_string(&response).expect("serialize projection");
    assert!(!serialized.contains("reply.example.com"));
    assert!(!serialized.contains("parent-zone-tag"));
    let requests = server.await.expect("server joins");
    assert_eq!(requests.len(), 2);
    assert!(requests[0].contains("/accounts/private-account/email/routing/rules"));
}

#[tokio::test]
async fn account_email_routing_rules_read_rejects_incoherent_page_metadata_body_free() {
    let first_page = (0..50)
        .map(|index| json!({"id":format!("rule-{index:03}")}))
        .collect::<Vec<_>>();
    let unstable_first = serde_json::to_string(&json!({
        "success":true,
        "result":first_page,
        "errors":[],
        "result_info":{"page":1,"per_page":50,"count":50,"total_pages":2,"total_count":51}
    }))
    .expect("unstable first page");
    let cases = vec![
        vec![
            r#"{"success":true,"result":[{"id":"rule-001"}],"errors":[],"result_info":{"cursors":{"after":"private-cursor"}}}"#.to_owned(),
        ],
        vec![
            r#"{"success":true,"result":[{"id":"rule-001"}],"errors":[],"result_info":{"page":2,"per_page":50,"count":1,"total_pages":2,"total_count":51}}"#.to_owned(),
        ],
        vec![
            r#"{"success":true,"result":[{"id":"rule-001"}],"errors":[],"result_info":{"page":1,"per_page":20,"count":1,"total_pages":1,"total_count":1}}"#.to_owned(),
        ],
        vec![
            r#"{"success":true,"result":[{"id":"rule-001"}],"errors":[],"result_info":{"page":1,"per_page":50,"count":2,"total_pages":1,"total_count":1}}"#.to_owned(),
        ],
        vec![
            unstable_first,
            r#"{"success":true,"result":[{"id":"rule-050"}],"errors":[],"result_info":{"page":2,"per_page":50,"count":1,"total_pages":2,"total_count":100}}"#.to_owned(),
        ],
    ];
    for bodies in cases {
        let (address, server) = json_response_sequence_server(bodies).await;
        let mut capability = CapabilityV1::new(
            cfctl_core::EMAIL_ROUTING_ACCOUNT_RULES_LIST_CAPABILITY_ID,
            "List account routing rules",
            "GET",
            cfctl_core::EMAIL_ROUTING_ACCOUNT_RULES_LIST_PATH,
        );
        capability.selectors = vec![SelectorV1 {
            name: "account_id".to_owned(),
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
                    selectors: json!({"account_id":"private-account"}),
                    ..CallInput::default()
                },
                &AuthCredential::Bearer {
                    token: "token".to_owned(),
                },
            )
            .await
            .expect("typed fail-closed response");
        assert!(!response.success);
        assert_eq!(response.result["complete"], false);
        let serialized = serde_json::to_string(&response).expect("body-free rejection");
        assert!(!serialized.contains("private-cursor"));
        assert!(!serialized.contains("rule-001"));
        assert!(!serialized.contains("rule-002"));
        server.await.expect("server joins");
    }
}

#[tokio::test]
async fn email_routing_rules_read_rejects_shape_drift_without_echoing_values() {
    let (address, server) = json_response_sequence_server(vec![
        r#"{"success":true,"result":[{"tag":"rule-001","enabled":true,"matchers":[{"type":"literal","field":"to"}],"actions":[{"type":"forward","value":["operator@example.com"]}]}],"errors":[]}"#,
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
