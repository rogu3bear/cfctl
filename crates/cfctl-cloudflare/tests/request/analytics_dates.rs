use super::*;

fn date_input() -> CallInput {
    let today = Utc::now().date_naive().format("%Y-%m-%d").to_string();
    CallInput {
        selectors: json!({"zone_id":"zone-1"}),
        body: Some(json!({
            "dataset":"httpRequests1dGroups", "start":today, "end":today, "limit":1
        })),
        ..CallInput::default()
    }
}

#[test]
fn analytics_date_errors_keep_the_typed_diagnostic_for_both_bounds() {
    let capability = graphql_daily_unique_ips_capability();
    assert!(validate_request_contract(&capability, &date_input()).is_ok());
    for field in ["start", "end"] {
        for invalid in [
            "2026-07-01T00:00:00Z",
            "2026-02-29",
            "1900-02-29",
            "2026-04-31",
            "2026-7-01",
            "+2026-07-01",
            " 2026-07-01",
            "2026-07-01 ",
            "２０２６-07-01",
            "",
        ] {
            let mut input = date_input();
            input.body.as_mut().unwrap()[field] = json!(invalid);
            assert!(
                matches!(
                    validate_request_contract(&capability, &input),
                    Err(CloudflareError::InvalidAnalyticsQuery(message))
                        if message.contains("YYYY-MM-DD")
                ),
                "{field}={invalid}"
            );
        }
    }
}

#[test]
fn analytics_date_preflight_preserves_structural_and_other_schema_errors() {
    let capability = graphql_daily_unique_ips_capability();
    let mut missing = date_input();
    missing.body = None;
    assert!(matches!(
        validate_request_contract(&capability, &missing),
        Err(CloudflareError::MissingRequestBody(_))
    ));
    for invalid in [json!(null), json!(42), json!([]), json!({})] {
        let mut input = date_input();
        input.body.as_mut().unwrap()["start"] = invalid;
        assert!(matches!(
            validate_request_contract(&capability, &input),
            Err(CloudflareError::InvalidRequestBody(_))
        ));
    }
    let mut absent = date_input();
    absent
        .body
        .as_mut()
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove("start");
    assert!(matches!(
        validate_request_contract(&capability, &absent),
        Err(CloudflareError::InvalidRequestBody(_))
    ));
    let mut unknown = date_input();
    unknown.body.as_mut().unwrap()["undeclared"] = json!(true);
    assert!(matches!(
        validate_request_contract(&capability, &unknown),
        Err(CloudflareError::InvalidRequestBody(_))
    ));
    let mut invalid_limit = date_input();
    invalid_limit.body.as_mut().unwrap()["limit"] = json!(0);
    assert!(matches!(
        validate_request_contract(&capability, &invalid_limit),
        Err(CloudflareError::InvalidRequestBody(_))
    ));
    invalid_limit.body.as_mut().unwrap()["start"] = json!("2026-02-29");
    assert!(matches!(
        validate_request_contract(&capability, &invalid_limit),
        Err(CloudflareError::InvalidAnalyticsQuery(message))
            if message.contains("YYYY-MM-DD")
    ));
    for invalid_contract in [
        {
            let mut cap = capability.clone();
            cap.mutating = true;
            cap
        },
        {
            let mut cap = capability.clone();
            cap.analytics_query.as_mut().unwrap().read_only = false;
            cap
        },
    ] {
        assert!(matches!(
            validate_request_contract(&invalid_contract, &invalid_limit),
            Err(CloudflareError::InvalidRequestBody(_))
        ));
    }
    let mut unrelated = CapabilityV1::new("date-only", "Date-only", "POST", "/date");
    unrelated.request_schema = Some(json!({
        "type":"object", "properties":{"start":{"type":"string","format":"date"}}
    }));
    assert!(matches!(
        validate_request_contract(
            &unrelated,
            &CallInput {
                body: Some(json!({"start":"2026-07-01T00:00:00Z"})),
                ..CallInput::default()
            }
        ),
        Err(CloudflareError::InvalidRequestBody(_))
    ));
}
