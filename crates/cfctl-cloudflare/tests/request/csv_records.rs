use super::*;

#[tokio::test]
async fn analytics_csv_counts_complete_eof_records_and_preserves_limits() {
    for (body, limit, max_bytes, rows, truncated, success) in [
        ("row,value\n1,a", 1, 1024, 1, false, true),
        ("row,value\n1,\"a\nb\"", 1, 1024, 1, false, true),
        ("row,value\r\n1,a", 1, 1024, 1, false, true),
        ("row,value", 1, 1024, 0, false, true),
        ("row,value\n1,a\n2,b", 1, 1024, 1, true, true),
        ("row,value\n1,a\n2,b", 2, 1024, 2, false, true),
        ("row,value\n1,\"a", 1, 1024, 0, false, false),
        ("row,value\n1,a", 1, 12, 0, true, true),
    ] {
        let mut capability = structured_sql_capability();
        capability
            .analytics_query
            .as_mut()
            .expect("analytics")
            .max_bytes = max_bytes;
        let (address, server) = single_raw_response_server("200 OK", "text/csv", body).await;
        let response = Executor::new(
            reqwest::Client::new(),
            &format!("http://{address}/client/v4"),
        )
        .expect("executor")
        .execute_read(
            &capability,
            &CallInput {
                selectors: json!({"account_id":"account-1"}),
                body: Some(bounded_query_body("csv", limit)),
                ..CallInput::default()
            },
            &AuthCredential::Bearer {
                token: "local-fixture-token".into(),
            },
        )
        .await
        .expect("CSV response");
        server.await.expect("fixture complete");
        let info = response.result_info.expect("output receipt");
        assert_eq!(info.pointer("/output/rows"), Some(&json!(rows)), "{body:?}");
        assert_eq!(
            info.pointer("/output/truncated"),
            Some(&json!(truncated)),
            "{body:?}"
        );
        assert_eq!(response.success, success, "{body:?}");
        if rows == limit && truncated {
            assert_eq!(response.result, json!("row,value\n1,a\n"));
        } else if !truncated {
            assert_eq!(response.result, json!(body));
        }
    }
}
