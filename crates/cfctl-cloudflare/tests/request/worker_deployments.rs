use super::*;

async fn read(address: &str, query: Value) -> Result<CloudflareResponseV1, CloudflareError> {
    let mut capability = worker_versions_capability();
    "worker-deployments-list-deployments".clone_into(&mut capability.id);
    "/accounts/{account_id}/workers/scripts/{script_name}/deployments"
        .clone_into(&mut capability.path);
    capability.response_contract = Some(ResponseContractV1 {
        success_statuses: vec!["200".to_owned()],
        success_media_types: vec!["application/json".to_owned()],
        body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
    });
    capability
        .selectors
        .retain(|selector| selector.name != "deployable");
    Executor::new(
        reqwest::Client::new(),
        &format!("http://{address}/client/v4"),
    )
    .expect("executor")
    .execute_read(
        &capability,
        &CallInput {
            selectors: json!({"account_id":"account-1","script_name":"worker-1"}),
            query,
            ..CallInput::default()
        },
        &AuthCredential::Bearer {
            token: "token".to_owned(),
        },
    )
    .await
}

fn page(number: u64, total: u64, deployments: Value) -> String {
    json!({
        "success":true,"errors":[],"result":{"deployments":deployments},
        "result_info":{"page":number,"per_page":1,"count":1,"total_count":total}
    })
    .to_string()
}

#[tokio::test]
async fn worker_deployments_collects_nested_pages_preserving_result_shape() {
    let (address, server) = json_response_sequence_server(vec![
        page(1, 2, json!([{"id":"deployment-1"}])),
        page(2, 2, json!([{"id":"deployment-2"}])),
    ])
    .await;
    let response = read(&address, json!({}))
        .await
        .expect("complete deployments");
    assert_eq!(
        response.result,
        json!({"deployments":[{"id":"deployment-1"},{"id":"deployment-2"}]})
    );
    let info = response.result_info.expect("completion metadata");
    assert_eq!(info["count"], 2);
    assert_eq!(info["cfctl_page_complete"], true);
    let requests = server.await.expect("server");
    assert_eq!(requests.len(), 2);
    assert!(requests[1].contains("page=2"));
}

#[tokio::test]
async fn worker_deployments_accepts_one_nested_page() {
    let (address, server) =
        json_response_sequence_server(vec![page(1, 1, json!([{"id":"deployment-1"}]))]).await;
    let response = read(&address, json!({})).await.expect("single page");
    assert_eq!(response.result["deployments"][0]["id"], "deployment-1");
    assert_eq!(response.result_info.unwrap()["cfctl_page_complete"], true);
    assert_eq!(server.await.expect("server").len(), 1);
}

#[tokio::test]
async fn worker_deployments_preserves_legacy_unpaginated_response() {
    let (address, server) = json_response_sequence_server(vec![
        json!({
            "success":true,"errors":[],"result":{"deployments":[{"id":"deployment-1"}]}
        })
        .to_string(),
    ])
    .await;
    let response = read(&address, json!({})).await.expect("legacy response");
    assert_eq!(response.result["deployments"][0]["id"], "deployment-1");
    assert!(response.result_info.is_none());
    server.await.expect("server");
}

#[tokio::test]
async fn worker_deployments_rejects_count_disagreement() {
    let (address, server) = json_response_sequence_server(vec![page(1, 1, json!([]))]).await;
    assert!(matches!(
        read(&address, json!({})).await,
        Err(CloudflareError::PaginationCountMismatch { .. })
    ));
    server.await.expect("server");
}

#[tokio::test]
async fn worker_deployments_rejects_later_page_metadata_drift() {
    let (address, server) = json_response_sequence_server(vec![
        page(1, 2, json!([{"id":"deployment-1"}])),
        page(2, 3, json!([{"id":"deployment-2"}])),
    ])
    .await;
    assert!(matches!(
        read(&address, json!({})).await,
        Err(CloudflareError::PaginationMetadataInvalid)
    ));
    server.await.expect("server");
}

#[tokio::test]
async fn worker_deployments_rejects_malformed_nested_collection() {
    for deployments in [Value::Null, json!({}), json!("bad")] {
        let (address, server) = json_response_sequence_server(vec![page(1, 1, deployments)]).await;
        assert!(matches!(
            read(&address, json!({})).await,
            Err(CloudflareError::InvalidResponseEnvelope { .. })
        ));
        server.await.expect("server");
    }
}

#[tokio::test]
async fn worker_deployments_still_requires_success_boolean() {
    let (address, server) = json_response_sequence_server(vec![json!({
        "result":{"deployments":[]},"result_info":{"page":1,"per_page":1,"count":0,"total_count":0}
    }).to_string()])
    .await;
    assert!(matches!(
        read(&address, json!({})).await,
        Err(CloudflareError::InvalidResponseEnvelope { .. })
    ));
    server.await.expect("server");
}
