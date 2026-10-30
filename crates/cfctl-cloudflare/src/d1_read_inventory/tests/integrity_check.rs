//! Direct full-integrity grammar; local acceptance does not prove D1 support.
use super::*;

fn diagnostic(sql: &str, column: &str) -> D1ReadInventoryV1 {
    let mut fixture = inventory();
    let query = &mut fixture.queries[1];
    query.sql = sql.into();
    query.sha256 = sha256(sql.as_bytes());
    query.output.min_rows = 1;
    query.output.max_rows = 1;
    query.output.columns = vec![D1ReadColumnV1 {
        name: column.into(),
        kind: D1ReadValueKindV1::Text,
        nullable: false,
        max_bytes: Some(2),
        allowed_values: Some(vec![json!("ok")]),
        min_integer: None,
        max_integer: None,
    }];
    fixture
}

#[test]
fn direct_integrity_check_has_exact_output_name_and_no_arguments() {
    assert_eq!(D1_READ_COMPILER_VERSION, 5);
    for sql in [
        "PRAGMA integrity_check;",
        "PRAGMA main.integrity_check;",
        "pragma INTEGRITY_CHECK",
    ] {
        let fixture = diagnostic(sql, "integrity_check");
        validate_inventory(&fixture).expect("bounded full integrity read");
        let connection = compile_schema(&fixture).expect("empty local compiler");
        let value: String = connection
            .query_row(sql, [], |row| row.get(0))
            .expect("local SQLite diagnostic");
        assert_eq!(value, "ok");
    }
    assert!(validate_inventory(&diagnostic("PRAGMA integrity_check;", "quick_check")).is_err());
}

#[test]
fn direct_integrity_check_rejects_arguments_mutation_and_extra_statements() {
    for sql in [
        "PRAGMA integrity_check(1);",
        "PRAGMA integrity_check(0);",
        "PRAGMA integrity_check('items');",
        "PRAGMA integrity_check=1;",
        "PRAGMA main.integrity_check(1);",
        "PRAGMA temp.integrity_check;",
        "PRAGMA other.integrity_check;",
        "PRAGMA integrity_check; SELECT 1;",
        "PRAGMA integrity_check; PRAGMA quick_check;",
        "PRAGMA writable_schema=ON;",
    ] {
        assert!(
            validate_inventory(&diagnostic(sql, "integrity_check")).is_err(),
            "accepted {sql}"
        );
    }
}

#[tokio::test]
async fn direct_integrity_check_receipts_keep_exact_success_and_compiler_version() {
    let fixture = diagnostic("PRAGMA integrity_check;", "integrity_check");
    let (capability, input) = prepared(fixture.clone());
    let validated = validate(&capability, &input).expect("validated inventory");
    let mut result = run(
        fixture.clone(),
        vec![
            (200, provider(json!([{"name":"items"}]))),
            (200, provider(json!([{"integrity_check":"ok"}]))),
        ],
    )
    .await;
    assert!(result.read_complete);
    assert_eq!(result.compiler_version, 5);
    validate_result(&validated, &result).expect("current result");
    result.compiler_version = 4;
    assert!(validate_result(&validated, &result).is_err());
    for rows in [
        json!([]),
        json!([{"integrity_check":"ok"},{"integrity_check":"ok"}]),
        json!([{"integrity_check":null}]),
        json!([{"integrity_check":"OK"}]),
        json!([{"integrity_check":"ok "}]),
        json!([{"integrity_check":"corrupt"}]),
        json!([{"quick_check":"ok"}]),
        json!([{"integrity_check":"ok","unexpected":true}]),
        json!([{"integrity_check":"x".repeat(9000)}]),
    ] {
        let result = run(
            fixture.clone(),
            vec![
                (200, provider(json!([{"name":"items"}]))),
                (200, provider(rows)),
            ],
        )
        .await;
        assert!(!result.read_complete);
        assert_eq!(result.attempted_queries, 2);
    }
}
