use super::*;

async fn read(address: &str, query: Value) -> Result<CloudflareResponseV1, CloudflareError> {
    let mut capability = paginated_workers_capability();
    "workers.domains.list".clone_into(&mut capability.id);
    "/accounts/{account_id}/workers/domains".clone_into(&mut capability.path);
    // Keep pagination selectors in this fixture to prove the endpoint exception
    // cannot admit them even if a future catalog declares broader inputs.
    for name in [
        "environment",
        "hostname",
        "service",
        "zone_id",
        "zone_name",
        "cursor",
    ] {
        capability.selectors.push(SelectorV1 {
            name: name.to_owned(),
            location: "query".to_owned(),
            required: false,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        });
    }
    Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .execute_read(
        &capability,
        &CallInput {
            selectors: json!({"account_id":"account-1"}),
            query,
            ..CallInput::default()
        },
        &AuthCredential::Bearer {
            token: "token".to_owned(),
        },
    )
    .await
}

fn empty_response() -> Value {
    json!({"success":true,"errors":[],"result":[],
        "result_info":{"page":1,"per_page":0,"count":0,"total_count":0}})
}

#[tokio::test]
async fn worker_domains_accepts_observed_empty_zero_size_single_page() {
    for query in [
        json!({}),
        json!({"hostname":"example.com"}),
        json!({"service":"worker-1"}),
    ] {
        let (address, server) =
            json_response_sequence_server(vec![empty_response().to_string()]).await;
        let response = read(&address, query)
            .await
            .expect("complete empty domain inventory");
        assert_eq!(response.result, json!([]));
        let info = response.result_info.expect("completion metadata");
        assert_eq!(info["per_page"], 0, "retain the provider's actual metadata");
        assert_eq!(info["cfctl_single_page_complete"], true);
        assert_eq!(info["cfctl_pages"], 1);
        assert_eq!(server.await.expect("server").len(), 1);
    }
}

#[tokio::test]
async fn worker_domains_accepts_consistent_explicit_empty_totals() {
    for total_pages in [0, 1] {
        let mut body = empty_response();
        body["result_info"]["total_pages"] = json!(total_pages);
        let (address, server) = json_response_sequence_server(vec![body.to_string()]).await;
        let response = read(&address, json!({}))
            .await
            .expect("complete empty inventory");
        assert_eq!(
            response.result_info.unwrap()["cfctl_single_page_complete"],
            true
        );
        assert_eq!(server.await.expect("server").len(), 1);
    }
}

#[tokio::test]
async fn worker_domains_rejects_inconsistent_empty_or_ambiguous_nonempty_metadata() {
    for (field, value) in [
        ("page", json!(0)),
        ("page", json!(2)),
        ("page", json!(null)),
        ("per_page", json!("0")),
        ("count", json!(1)),
        ("count", json!(null)),
        ("total_count", json!(1)),
        ("total_count", json!(null)),
        ("total_pages", json!(2)),
        ("total_pages", json!(null)),
        ("cursor", json!("next")),
        ("cursors", json!({})),
    ] {
        let mut body = empty_response();
        body["result_info"][field] = value;
        assert_rejected(body, json!({"hostname":"example.com"})).await;
    }
    let mut nonempty = empty_response();
    nonempty["result"] = json!([{"hostname":"example.com"}]);
    assert_rejected(nonempty, json!({})).await;
    let mut nonarray = empty_response();
    nonarray["result"] = json!({});
    assert_rejected(nonarray, json!({})).await;
}

async fn assert_rejected(body: Value, query: Value) {
    let (address, server) = json_response_sequence_server(vec![body.to_string()]).await;
    let error = read(&address, query)
        .await
        .expect_err("incomplete inventory must fail closed");
    assert_eq!(
        error.read_error_class(),
        CloudflareReadErrorClass::PaginationContract
    );
    assert_eq!(server.await.expect("server").len(), 1);
}

#[tokio::test]
async fn worker_domains_does_not_admit_undocumented_pagination_queries() {
    for query in [
        json!({"page":2}),
        json!({"cursor":"next"}),
        json!({"per_page":0}),
    ] {
        assert_rejected(empty_response(), query).await;
    }
}

#[tokio::test]
async fn worker_domains_empty_exception_does_not_change_other_endpoints() {
    let (address, server) = json_response_sequence_server(vec![empty_response().to_string()]).await;
    let error = execute_paginated_workers_read(&address)
        .await
        .expect_err("Workers still requires valid pagination");
    assert!(matches!(error, CloudflareError::PaginationMetadataInvalid));
    assert_eq!(server.await.expect("server").len(), 1);
}
