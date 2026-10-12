//! A partial storage diagnostic, never a full-integrity gate replacement.
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
fn no_argument_quick_check_is_a_read_with_its_own_exact_result_name() {
    validate_inventory(&diagnostic("PRAGMA quick_check;", "quick_check"))
        .expect("read-only whole-database quick check");
    assert!(validate_inventory(&diagnostic("PRAGMA quick_check;", "integrity_check")).is_err());
}

#[test]
fn quick_check_does_not_admit_arguments_assignments_other_schemas_or_extra_statements() {
    for sql in [
        "PRAGMA quick_check(1);",
        "PRAGMA quick_check('items');",
        "PRAGMA quick_check=1;",
        "PRAGMA temp.quick_check;",
        "PRAGMA quick_check; SELECT 1;",
        "PRAGMA ignore_check_constraints=ON;",
    ] {
        assert!(
            validate_inventory(&diagnostic(sql, "quick_check")).is_err(),
            "accepted {sql}"
        );
    }
}

#[test]
fn quick_check_output_cannot_qualify_error_empty_null_or_normalized_success() {
    let fixture = diagnostic("PRAGMA quick_check;", "quick_check");
    let column = &fixture.queries[1].output.columns[0];
    assert!(value_allowed(column, &json!("ok")));
    for value in [
        json!(null),
        json!(""),
        json!("OK"),
        json!("ok "),
        json!("corrupt"),
    ] {
        assert!(!value_allowed(column, &value));
    }
}
