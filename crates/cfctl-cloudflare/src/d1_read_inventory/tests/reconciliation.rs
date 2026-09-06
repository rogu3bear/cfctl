use super::*;

fn reconciliation() -> D1ReadInventoryV1 {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../cfctl-workspace/tests/fixtures/d1-reads/reconciliation-inventory.json"
    )))
    .expect("synthetic reconciliation inventory")
}

#[test]
fn declared_json_patch_preserves_last_member_projection_in_the_bundled_compiler() {
    let mut fixture = reconciliation();
    fixture
        .functions
        .extend(["json_patch".into(), "json_extract".into()]);
    for (json, expected) in [
        (r#"{"field":"first","field":"last"}"#, Some("last")),
        (r#"{"field":"first","field":null}"#, None),
    ] {
        let query = &mut fixture.queries[1];
        query.parameters.clear();
        query.sql =
            format!("SELECT json_extract(json_patch('{{}}', '{json}'), '$.field') AS label;");
        query.sha256 = sha256(query.sql.as_bytes());
        query.output.columns[0].nullable = true;
        validate_inventory(&fixture).expect("declared pure projection");
        let connection = compile_schema(&fixture).expect("private empty compiler");
        let actual: Option<String> = connection
            .query_row(&fixture.queries[1].sql, [], |row| row.get(0))
            .expect("synthetic scalar projection only");
        assert_eq!(actual.as_deref(), expected);
    }
}

fn responses(id: &str, count: Value) -> Vec<(u16, Value)> {
    vec![
        (200, provider(json!([{"id":id}]))),
        (200, provider(json!([{"label":"example label"}]))),
        (200, provider(count)),
    ]
}

#[test]
fn complete_parameter_schema_is_prepared_before_any_credentials() {
    validate_inventory(&reconciliation()).expect("numbered source-derived parameters");
    for sql in [
        "SELECT label FROM items WHERE owner_id=?;",
        "SELECT label FROM items WHERE owner_id=:id;",
        "SELECT label FROM items WHERE owner_id=?2;",
        "SELECT label FROM items WHERE owner_id=?1 OR owner_id=?2;",
        "SELECT label FROM items;",
    ] {
        let mut fixture = reconciliation();
        fixture.queries[1].sql = sql.into();
        fixture.queries[1].sha256 = sha256(sql.as_bytes());
        assert!(validate_inventory(&fixture).is_err(), "{sql}");
    }
    for edit in 0..7 {
        let mut fixture = reconciliation();
        let parameter = &mut fixture.queries[1].parameters[0];
        match edit {
            0 => parameter.from_query = "q3".into(),
            1 => parameter.column = "absent".into(),
            2 => parameter.row_index = 1,
            3 => parameter.kind = D1ReadValueKindV1::Integer,
            4 => parameter.index = 2,
            5 => parameter.max_bytes = Some(257),
            _ => parameter.max_bytes = None,
        }
        assert!(
            validate_inventory(&fixture).is_err(),
            "parameter edit {edit}"
        );
    }
    let (capability, input) = prepared(reconciliation());
    for key in [
        "params",
        "parameters",
        "results",
        "sql",
        "database_id",
        "queries",
    ] {
        let mut changed = input.clone();
        changed.body.as_mut().expect("body")[key] = json!(["CALLER_REPLACEMENT"]);
        assert!(validate(&capability, &changed).is_err(), "caller {key}");
    }
    let mut bad_final = reconciliation();
    bad_final.queries[2].sql = "DELETE FROM items WHERE owner_id=?1;".into();
    bad_final.queries[2].sha256 = sha256(bad_final.queries[2].sql.as_bytes());
    assert!(validate_inventory(&bad_final).is_err());
}

#[tokio::test]
async fn qualified_parameters_are_bound_as_values_with_digest_only_provenance() {
    let fixture = reconciliation();
    let (capability, input) = prepared(fixture.clone());
    let validated = validate(&capability, &input).expect("complete preflight");
    let server = server(responses(
        "\u{feff}  organization-example  \n",
        json!([{"c":0}]),
    ))
    .await;
    let executor = crate::Executor::new(reqwest::Client::new(), &server.url).expect("executor");
    let result = executor
        .execute_d1_read_inventory(
            &validated,
            &AuthCredential::Bearer {
                token: "synthetic-token".into(),
            },
            || Ok(()),
        )
        .await
        .expect("run");
    assert!(result.read_complete);
    assert_eq!(result.attempted_queries, 3);
    {
        let requests = server.requests.lock().expect("captured bodies");
        assert_eq!(requests[0]["params"], json!([]));
        for i in 1..3 {
            assert_eq!(requests[i]["sql"], fixture.queries[i].sql);
            assert_eq!(requests[i]["params"], json!(["organization-example"]));
            let provenance = &result.results[i].parameter_provenance;
            assert_eq!(provenance.len(), 1);
            assert_eq!(provenance[0].from_query, "q1");
            assert_eq!(provenance[0].from_query_sha256, fixture.queries[0].sha256);
            assert_eq!(
                provenance[0].value_sha256,
                cfctl_core::hash_value(&json!("organization-example")).expect("scalar digest")
            );
            assert!(
                !serde_json::to_string(provenance)
                    .expect("provenance")
                    .contains("organization-example")
            );
        }
    }
    validate_result(&validated, &result).expect("durable-boundary requalification");
    let mut tampered = result.clone();
    tampered.results[1].parameter_provenance[0].value_sha256 = sha256(b"replacement");
    assert!(validate_result(&validated, &tampered).is_err());
    let mut tampered = result;
    tampered.results[0].receipt.as_mut().expect("receipt")["result"][0]["results"][0]["id"] =
        json!("changed-qualified-value");
    assert!(validate_result(&validated, &tampered).is_err());
    server.handle.abort();
}

#[tokio::test]
async fn missing_invalid_or_oversized_source_values_leave_dependents_unattempted() {
    for rows in [
        json!([]),
        json!([{"id":" \u{feff}\n"}]),
        json!([{"id":null}]),
        json!([{"id":7}]),
        json!([{"id":"x".repeat(257)}]),
        json!([{"id":"a"},{"id":"b"}]),
    ] {
        let result = run(reconciliation(), vec![(200, provider(rows))]).await;
        assert!(!result.read_complete);
        assert_eq!(result.attempted_queries, 1);
        assert_eq!(result.unattempted_queries, 2);
        for dependent in &result.results[1..] {
            assert_eq!(dependent.status, D1ReadStatusV1::Unattempted);
            assert!(dependent.parameter_provenance.is_empty());
            assert!(dependent.receipt.is_none());
        }
    }
    let mut fixture = reconciliation();
    fixture.queries[1].parameters[0].max_bytes = Some(3);
    fixture.queries[2].parameters[0].max_bytes = Some(3);
    let result = run(fixture, vec![(200, provider(json!([{"id":"longer"}])))]).await;
    assert_eq!(
        result.results[1].classification,
        "parameter_source_unsatisfied"
    );
}

#[tokio::test]
async fn count_requires_one_nonnegative_bounded_integer_row() {
    for count in [
        json!([]),
        json!([{"c":0},{"c":0}]),
        json!([{"c":-1}]),
        json!([{"c":9_007_199_254_740_992_i64}]),
        json!([{"c":0.0}]),
        json!([{"c":"0"}]),
        json!([{"c":null}]),
    ] {
        let result = run(reconciliation(), responses("organization-example", count)).await;
        assert_eq!(result.attempted_queries, 3);
        assert!(!result.read_complete);
        assert_eq!(result.results[2].status, D1ReadStatusV1::Rejected);
        assert!(result.results[2].receipt.is_none());
    }
    let result = run(
        reconciliation(),
        responses("organization-example", json!([{"c":0}])),
    )
    .await;
    assert!(result.read_complete);
}

#[tokio::test]
async fn source_or_generation_drift_prevents_parameterized_dispatch() {
    let (capability, input) = prepared(reconciliation());
    let validated = validate(&capability, &input).expect("preflight");
    let server = server(vec![(
        200,
        provider(json!([{"id":"organization-example"}])),
    )])
    .await;
    let executor = crate::Executor::new(reqwest::Client::new(), &server.url).expect("executor");
    let mut checks = 0;
    let result = executor
        .execute_d1_read_inventory(
            &validated,
            &AuthCredential::Bearer {
                token: "synthetic-token".into(),
            },
            || {
                checks += 1;
                if checks > 2 {
                    Err(invalid("source or generation changed"))
                } else {
                    Ok(())
                }
            },
        )
        .await
        .expect("bounded result");
    assert_eq!(server.count.load(Ordering::SeqCst), 1);
    assert_eq!(
        result.results[1].classification,
        "source_or_credential_drift"
    );
    assert!(result.results[1].parameter_provenance.is_empty());
    server.handle.abort();
}
