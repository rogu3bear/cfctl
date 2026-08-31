use super::{d1_schema_introspection_caller_sql, render_d1_schema_introspection_body};
use rusqlite::{Connection, params};
use serde_json::json;

#[test]
fn renderer_rejects_unknown_fields_for_every_assertion_without_schema_help() {
    for body in [
        json!({"assertion":"table_exists","table":"users","sql":"SELECT 1"}),
        json!({"assertion":"column_exists","table":"users","column":"id","params":[]}),
        json!({"assertion":"index_exists","index":"idx_users","unexpected":true}),
        json!({"assertion":"trigger_exists","trigger":"users_guard","unexpected":true}),
        json!({"assertion":"schema_contains","object_type":"table","name":"users","fragment":"id","unexpected":true}),
        json!({"assertion":"foreign_key_check_empty","unexpected":true}),
        json!({"assertion":"migration_ledger_equals","migrations":["0001_init.sql"],"sql":"SELECT 1"}),
    ] {
        assert!(render_d1_schema_introspection_body(&body).is_err());
    }
}

#[test]
fn migration_ledger_renderer_accepts_only_one_bounded_unique_ordered_filename_set() {
    let rendered = render_d1_schema_introspection_body(&json!({
        "assertion":"migration_ledger_equals",
        "migrations":["0001_init.sql","0002_routes.sql"],
    }))
    .expect("closed migration ledger assertion");
    assert!(rendered["sql"].as_str().is_some_and(|sql| {
        sql.contains("d1_migrations") && sql.contains("ROW_NUMBER() OVER (ORDER BY id)")
    }));
    assert_eq!(
        rendered["params"],
        json!(["0001_init.sql", "0002_routes.sql"])
    );

    for migrations in [
        json!([]),
        json!(["0001_init.sql", "0001_init.sql"]),
        json!(["../0001_init.sql"]),
        json!(["not-sql.txt"]),
    ] {
        assert!(
            render_d1_schema_introspection_body(&json!({
                "assertion":"migration_ledger_equals",
                "migrations":migrations,
            }))
            .is_err()
        );
    }
}

#[test]
fn migration_ledger_assertion_requires_the_exact_ordered_remote_ledger() {
    let rendered = render_d1_schema_introspection_body(&json!({
        "assertion":"migration_ledger_equals",
        "migrations":["0001_init.sql","0002_routes.sql"],
    }))
    .expect("closed migration ledger assertion");
    let sql = rendered["sql"].as_str().unwrap_or_default();
    let connection = Connection::open_in_memory().expect("in-memory D1 model");
    connection
            .execute_batch(
                "CREATE TABLE d1_migrations (id INTEGER PRIMARY KEY, name TEXT NOT NULL);\
                 INSERT INTO d1_migrations(id,name) VALUES (1,'0001_init.sql'),(2,'0002_routes.sql');",
            )
            .expect("exact ledger");
    let present = connection
        .query_row(sql, params!["0001_init.sql", "0002_routes.sql"], |row| {
            row.get::<_, i64>(0)
        })
        .expect("exact assertion");
    assert_eq!(present, 1);

    connection
        .execute("DELETE FROM d1_migrations", [])
        .expect("clear ledger");
    connection
        .execute_batch(
            "INSERT INTO d1_migrations(id,name) VALUES (1,'0002_routes.sql'),(2,'0001_init.sql');",
        )
        .expect("reordered ledger");
    let present = connection
        .query_row(sql, params!["0001_init.sql", "0002_routes.sql"], |row| {
            row.get::<_, i64>(0)
        })
        .expect("reordered assertion");
    assert_eq!(present, 0);
}

#[test]
fn migration_ledger_assertion_scales_to_the_advertised_sixty_four_rows() {
    for count in [56_usize, 64] {
        let names = (1..=count)
            .map(|sequence| format!("{sequence:04}_migration.sql"))
            .collect::<Vec<_>>();
        let rendered = render_d1_schema_introspection_body(&json!({
            "assertion":"migration_ledger_equals",
            "migrations":names,
        }))
        .expect("bounded ledger assertion");
        let sql = rendered["sql"].as_str().expect("compiled SQL");
        let params = rendered["params"].as_array().expect("bound filenames");
        assert_eq!(params.len(), count);
        assert!(sql.contains(&format!("({count}, ?{count})")));
        assert!(!sql.contains(&format!("?{}", count + 1)));
        assert!(!sql.contains("?101"));
        assert!(!sql.contains("?112"));

        let connection = Connection::open_in_memory().expect("in-memory D1 model");
        connection
            .execute_batch(
                "CREATE TABLE d1_migrations (id INTEGER PRIMARY KEY, name TEXT NOT NULL);",
            )
            .expect("ledger table");
        for (index, name) in names.iter().enumerate() {
            connection
                .execute(
                    "INSERT INTO d1_migrations(id,name) VALUES (?1,?2)",
                    params![i64::try_from(index + 1).expect("bounded ordinal"), name],
                )
                .expect("ledger row");
        }
        let bound = params
            .iter()
            .map(|value| value.as_str().expect("filename"))
            .collect::<Vec<_>>();
        let present = connection
            .query_row(sql, rusqlite::params_from_iter(bound.iter()), |row| {
                row.get::<_, i64>(0)
            })
            .expect("exact assertion");
        assert_eq!(present, 1);

        connection
            .execute(
                "UPDATE d1_migrations SET name = 'reordered.sql' WHERE id = 1",
                [],
            )
            .expect("reorder");
        let present = connection
            .query_row(sql, rusqlite::params_from_iter(bound.iter()), |row| {
                row.get::<_, i64>(0)
            })
            .expect("reordered assertion");
        assert_eq!(present, 0);

        connection
            .execute("DELETE FROM d1_migrations WHERE id = 1", [])
            .expect("missing row");
        let present = connection
            .query_row(sql, rusqlite::params_from_iter(bound.iter()), |row| {
                row.get::<_, i64>(0)
            })
            .expect("missing assertion");
        assert_eq!(present, 0);

        connection
            .execute(
                "INSERT INTO d1_migrations(id,name) VALUES (?1,'extra.sql')",
                params![i64::try_from(count + 1).expect("bounded ordinal")],
            )
            .expect("extra row");
        let present = connection
            .query_row(sql, rusqlite::params_from_iter(bound.iter()), |row| {
                row.get::<_, i64>(0)
            })
            .expect("extra assertion");
        assert_eq!(present, 0);
    }

    let too_many = (1..=65)
        .map(|sequence| format!("{sequence:04}_migration.sql"))
        .collect::<Vec<_>>();
    assert!(
        render_d1_schema_introspection_body(&json!({
            "assertion":"migration_ledger_equals",
            "migrations":too_many,
        }))
        .is_err()
    );
}

#[test]
fn caller_sql_receipt_fact_reflects_actual_body_field_presence() {
    assert!(!d1_schema_introspection_caller_sql(
        &json!({"assertion":"foreign_key_check_empty"})
    ));
    assert!(d1_schema_introspection_caller_sql(
        &json!({"assertion":"foreign_key_check_empty","sql":"SELECT 1"})
    ));
}

#[test]
fn mln_0142_renderer_owns_the_exact_trigger_definition_and_ignores_no_lineage_field() {
    let body = serde_json::json!({
        "assertion":"mln_0142_trigger_definition",
        "import_operation_id":"11111111-1111-4111-8111-111111111111",
        "import_boundary_evidence_hash":format!("sha256:{}", "a".repeat(64)),
        "import_source_sha256":format!("sha256:{}", "b".repeat(64)),
        "import_plan_hash":format!("sha256:{}", "c".repeat(64)),
        "final_bookmark_hash":format!("sha256:{}", "d".repeat(64)),
        "trigger_definition_sha256":format!("sha256:{}", "e".repeat(64)),
    });
    let rendered = render_d1_schema_introspection_body(&body).unwrap_or_default();
    assert_eq!(
        rendered["sql"],
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'trigger' AND name = 'document_render_jobs_terminal_generation_guard' AND sql = ?1) AS present"
    );
    assert_eq!(rendered["params"].as_array().map(Vec::len), Some(1));
    assert!(rendered["params"][0].as_str().is_some_and(|definition| {
        definition.starts_with("CREATE TRIGGER document_render_jobs_terminal_generation_guard")
    }));
    let encoded = serde_json::to_string(&rendered).unwrap_or_default();
    for graftable in ["11111111", &"a".repeat(16), &"c".repeat(16)] {
        assert!(!encoded.contains(graftable));
    }
}
