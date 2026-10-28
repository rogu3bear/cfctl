//! Offline catalog-to-request coverage for legacy and v2 bounded audit dates.

use cfctl_catalog::{CatalogSnapshot, normalize_openapi};
use cfctl_cloudflare::{CallInput, CloudflareError, RequestBuilder};
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const OPERATIONS: [(&str, &str); 6] = [
    ("audit-logs-get-user-audit-logs", "/user/audit_logs"),
    (
        "audit-logs-get-account-audit-logs",
        "/accounts/{account_id}/audit_logs",
    ),
    (
        "audit-logs-v2-get-account-audit-logs",
        "/accounts/{account_id}/logs/audit",
    ),
    (
        "audit-logs-v2-get-account-audit-log-history",
        "/accounts/{account_id}/logs/audit/{id}/history",
    ),
    (
        "audit-logs-v2-get-organization-audit-logs",
        "/organizations/{organization_id}/logs/audit",
    ),
    (
        "audit-logs-v2-get-organization-audit-log-history",
        "/organizations/{organization_id}/logs/audit/{id}/history",
    ),
];

fn catalog() -> Result<CatalogSnapshot, cfctl_catalog::CatalogError> {
    let mut paths = serde_json::Map::new();
    for (id, path) in OPERATIONS {
        let v2 = id.starts_with("audit-logs-v2-");
        let mut parameters = Vec::new();
        for name in ["account_id", "organization_id", "id"] {
            if path.contains(&format!("{{{name}}}")) {
                parameters.push(
                    json!({"in":"path","name":name,"required":true,"schema":{"type":"string"}}),
                );
            }
        }
        for (name, comparison) in [("since", "newer"), ("before", "older")] {
            let schema = if v2 {
                json!({"type":"string","format":"date"})
            } else {
                json!({"oneOf":[{"type":"string","format":"date"},{"type":"string","format":"date-time"}]})
            };
            parameters.push(json!({
                "in":"query","name":name,"required":v2,"schema":schema,
                "description":format!("Limits the returned results to logs {comparison} than the specified date. This can be a date string 2019-04-30 (interpreted in UTC) or an absolute timestamp that conforms to RFC3339.")
            }));
        }
        if v2 {
            parameters.push(json!({"in":"query","name":"limit","schema":{"type":"integer","minimum":1,"maximum":1000}}));
            parameters.push(json!({"in":"query","name":"cursor","schema":{"type":"string"}}));
        } else {
            parameters.push(json!({"in":"query","name":"per_page","schema":{"type":"integer","minimum":1,"maximum":1000}}));
            parameters
                .push(json!({"in":"query","name":"page","schema":{"type":"integer","minimum":1}}));
        }
        if path.ends_with("/history") {
            parameters.push(json!({"in":"query","name":"action_time","required":true,"schema":{"type":"string","format":"date-time"}}));
        }
        paths.insert(path.into(), json!({"get":{
            "operationId":id,"tags":["Audit Logs"],"parameters":parameters,
            "x-api-token-group":["Account Settings Read"],
            "responses":{"200":{"description":"Audit envelope","content":{"application/json":{"schema":{
                "type":"object","required":["success","result"],"properties":{
                    "success":{"type":"boolean"},"result":{"type":"array","items":{"type":"object"}}
                }
            }}}}}
        }}));
    }
    normalize_openapi(
        &json!({"openapi":"3.0.3","info":{"title":"Audit fixture","version":"1"},"paths":paths}),
    )
}

fn input(id: &str, value: &str) -> CallInput {
    let mut query = json!({"since":value,"before":value});
    if id.starts_with("audit-logs-v2-") {
        query["limit"] = json!(10);
        query["cursor"] = json!("after:1");
    } else {
        query["per_page"] = json!(10);
        query["page"] = json!(2);
    }
    if id.ends_with("-history") {
        query["action_time"] = json!("2026-10-27T00:00:00Z");
    }
    let path = OPERATIONS
        .iter()
        .find(|(candidate, _)| *candidate == id)
        .map_or("", |(_, path)| *path);
    let mut selectors = json!({});
    for name in ["account_id", "organization_id", "id"] {
        if path.contains(&format!("{{{name}}}")) {
            selectors[name] = json!("11111111111111111111111111111111");
        }
    }
    CallInput {
        selectors,
        query,
        ..CallInput::default()
    }
}

#[test]
fn audit_dates_normalized_legacy_and_v2_preserve_valid_date_and_timestamp_queries() -> TestResult {
    let catalog = catalog()?;
    let builder = RequestBuilder::new("https://example.invalid/client/v4")?;
    for (id, _) in OPERATIONS {
        let cap = catalog.get(id).ok_or("missing audit capability")?;
        assert_eq!(cap.permissions, ["Account Settings Read"]);
        for value in [
            "0000-01-01",
            "2000-02-29",
            "2026-10-27",
            "2026-10-27T01:02:03Z",
            "2026-10-27T01:02:03.123+05:30",
            "2026-10-27T01:02:03-04:00",
        ] {
            let input = input(id, value);
            let request = builder.build(cap, &input)?;
            let actual: std::collections::BTreeMap<_, _> =
                request.url.query_pairs().into_owned().collect();
            for (name, expected) in input.query.as_object().ok_or("query object")? {
                let expected = expected
                    .as_str()
                    .map_or_else(|| expected.to_string(), str::to_owned);
                assert_eq!(actual.get(name), Some(&expected), "{id} / {name}");
            }
            assert_eq!(
                actual.len(),
                input.query.as_object().ok_or("query object")?.len()
            );
        }
    }
    Ok(())
}

#[test]
fn audit_dates_reject_invalid_full_dates_and_timestamps_before_request_construction() -> TestResult
{
    let catalog = catalog()?;
    let builder = RequestBuilder::new("https://example.invalid/client/v4")?;
    for (id, _) in OPERATIONS {
        let cap = catalog.get(id).ok_or("audit capability")?;
        for name in ["since", "before"] {
            for invalid in [
                "",
                "x",
                "1900-02-29",
                "2026-02-29",
                "2026-04-31",
                "2026-00-10",
                "2026-13-01",
                "2026-10-00",
                "2026-1-01",
                "+2026-10-27",
                " 2026-10-27",
                "2026-10-27 ",
                "2026-10-27Z",
                "２０２６-10-27",
                "2026-10-27T01:02:03",
            ] {
                let mut input = input(id, "2026-10-27");
                input.query[name] = json!(invalid);
                assert!(
                    matches!(builder.build(cap, &input), Err(CloudflareError::InvalidQuerySelectorSchema { name: actual, .. }) if actual == name),
                    "{id}: {name}={invalid}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn audit_dates_keep_pagination_required_controls_and_history_time_constraints() -> TestResult {
    let catalog = catalog()?;
    let builder = RequestBuilder::new("https://example.invalid/client/v4")?;
    for (id, _) in OPERATIONS {
        let cap = catalog.get(id).ok_or("audit capability")?;
        let v2 = id.starts_with("audit-logs-v2-");
        for invalid in [0, 1001] {
            let mut input = input(id, "2026-10-27");
            input.query[if v2 { "limit" } else { "per_page" }] = json!(invalid);
            assert!(matches!(
                builder.build(cap, &input),
                Err(CloudflareError::InvalidQuerySelectorSchema { .. })
            ));
        }
        if v2 {
            for name in ["since", "before"] {
                let mut input = input(id, "2026-10-27");
                input
                    .query
                    .as_object_mut()
                    .ok_or("query object")?
                    .remove(name);
                assert!(
                    matches!(builder.build(cap, &input), Err(CloudflareError::MissingQuerySelector(actual)) if actual == name)
                );
            }
        }
        if id.ends_with("-history") {
            let mut input = input(id, "2026-10-27");
            input.query["action_time"] = json!("2026-10-27");
            assert!(
                matches!(builder.build(cap, &input), Err(CloudflareError::InvalidQuerySelectorSchema { name, .. }) if name == "action_time")
            );
        }
    }
    Ok(())
}

#[test]
fn audit_dates_keep_unrelated_date_only_and_unknown_formats_distinct() -> TestResult {
    let catalog = catalog()?;
    let mut cap = catalog
        .get(OPERATIONS[0].0)
        .ok_or("audit capability")?
        .clone();
    cap.id = "unrelated-date-only-fixture".into();
    let selector = cap
        .selectors
        .iter_mut()
        .find(|s| s.name == "before")
        .ok_or("before")?;
    selector.contract.as_mut().ok_or("contract")?.schema = json!({"type":"string","format":"date"});
    let builder = RequestBuilder::new("https://example.invalid/client/v4")?;
    assert!(builder.build(&cap, &input(&cap.id, "2026-10-27")).is_ok());
    assert!(
        matches!(builder.build(&cap, &input(&cap.id, "2026-10-27T01:02:03Z")), Err(CloudflareError::InvalidQuerySelectorSchema { name, .. }) if name == "before")
    );
    let selector = cap
        .selectors
        .iter_mut()
        .find(|s| s.name == "before")
        .ok_or("before")?;
    selector.contract.as_mut().ok_or("contract")?.schema =
        json!({"type":"string","format":"future-format"});
    let mut input = input(&cap.id, "2026-10-27");
    input.query["before"] = json!("opaque-provider-value");
    assert!(builder.build(&cap, &input).is_ok());
    Ok(())
}
