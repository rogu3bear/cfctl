#![allow(clippy::wildcard_imports, reason = "white-box domain tests")]

use super::*;
use cfctl_core::{EvidenceClass, WorkspaceD1MigrationFileV1, WorkspaceD1SchemaAssertionV1};
use cfctl_storage::RuntimePaths;

#[cfg(any(unix, windows))]
async fn wait_for_process_fixture(path: &Path) {
    for _ in 0..500 {
        if path.is_file() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!(
        "process-tree fixture did not reach its startup handshake at {}",
        path.display()
    );
}

#[test]
fn workspace_d1_preserves_query_and_apply_timeout_bounds() {
    assert_eq!(QUERY_TIMEOUT, Duration::from_mins(2));
    assert_eq!(APPLY_TIMEOUT, Duration::from_mins(5));
}

#[cfg(unix)]
#[tokio::test]
async fn workspace_d1_timeout_terminates_and_reaps_the_full_wrangler_process_tree() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = tempfile::tempdir().expect("D1 process-tree root");
    let program = root.path().join("wrangler-timeout-probe.sh");
    let pid_file = root.path().join("pids");
    fs::write(
        &program,
        "#!/bin/sh\nsleep 30 &\nprintf '%s %s\\n' \"$$\" \"$!\" > \"$1\"\nwait\n",
    )
    .expect("timeout probe source");
    let mut permissions = fs::metadata(&program)
        .expect("timeout probe metadata")
        .permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&program, permissions).expect("timeout probe permissions");
    let cache = root.path().join("cache");
    fs::create_dir(&cache).expect("cache root");

    let task_program = program.clone();
    let task_pid_file = pid_file.clone();
    let task_root = root.path().to_owned();
    let task_cache = cache.clone();
    let execution = tokio::spawn(async move {
        run_wrangler_program(
            &task_program,
            &[task_pid_file.to_string_lossy().into_owned()],
            &task_root,
            &AuthCredential::Bearer {
                token: "fixture-token".to_owned(),
            },
            "fixture-account",
            &task_cache,
            Duration::from_secs(5),
        )
        .await
    });
    wait_for_process_fixture(&pid_file).await;
    let error = execution
        .await
        .expect("D1 Wrangler timeout task")
        .expect_err("D1 Wrangler process tree must time out");
    assert!(matches!(
        error,
        CliError::SubprocessTimeout {
            timeout_seconds: 5,
            ..
        }
    ));

    let pids = fs::read_to_string(&pid_file).expect("recorded process IDs");
    for pid in pids.split_whitespace() {
        let mut alive = true;
        for _ in 0..100 {
            alive = std::process::Command::new("kill")
                .args(["-0", pid])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .expect("process probe")
                .success();
            if !alive {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!alive, "timed-out D1 Wrangler process {pid} survived");
    }
}

#[cfg(windows)]
#[tokio::test]
async fn workspace_d1_timeout_windows_job_contains_the_full_wrangler_tree() {
    let root = tempfile::tempdir().expect("Windows D1 process-tree root");
    let program = root.path().join("wrangler-timeout-probe.ps1");
    let pid_file = root.path().join("pids");
    fs::write(
        &program,
        "$child = Start-Process powershell.exe -NoNewWindow -ArgumentList '-NoLogo','-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 30' -PassThru; Set-Content -NoNewline -LiteralPath $args[0] -Value \"$PID $($child.Id)\"; $child.WaitForExit()",
    )
    .expect("Windows timeout probe source");
    let cache = root.path().join("cache");
    fs::create_dir(&cache).expect("cache root");

    let task_program = program.clone();
    let task_pid_file = pid_file.clone();
    let task_root = root.path().to_owned();
    let task_cache = cache.clone();
    let execution = tokio::spawn(async move {
        run_wrangler_program(
            Path::new("powershell.exe"),
            &[
                "-NoLogo".to_owned(),
                "-NoProfile".to_owned(),
                "-NonInteractive".to_owned(),
                "-File".to_owned(),
                task_program.to_string_lossy().into_owned(),
                task_pid_file.to_string_lossy().into_owned(),
            ],
            &task_root,
            &AuthCredential::Bearer {
                token: "fixture-token".to_owned(),
            },
            "fixture-account",
            &task_cache,
            Duration::from_secs(5),
        )
        .await
    });
    wait_for_process_fixture(&pid_file).await;
    let error = execution
        .await
        .expect("D1 Windows timeout task")
        .expect_err("D1 Windows process tree must time out");
    assert!(matches!(
        error,
        CliError::SubprocessTimeout {
            timeout_seconds: 5,
            ..
        }
    ));

    let pids = fs::read_to_string(&pid_file).expect("recorded process IDs");
    for pid in pids.split_whitespace() {
        let mut alive = true;
        for _ in 0..100 {
            alive = std::process::Command::new("powershell.exe")
                .args([
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    &format!(
                        "if (Get-Process -Id {pid} -ErrorAction SilentlyContinue) {{ exit 0 }} else {{ exit 1 }}"
                    ),
                ])
                .status()
                .expect("descendant process probe")
                .success();
            if !alive {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!alive, "timed-out D1 Wrangler process {pid} survived");
    }
}

#[test]
fn ledger_must_be_an_exact_prefix() {
    let declared = vec!["0001.sql".to_owned(), "0002.sql".to_owned()];
    assert!(is_prefix(&[], &declared));
    assert!(is_prefix(&["0001.sql".to_owned()], &declared));
    assert!(!is_prefix(&["0002.sql".to_owned()], &declared));
    assert!(!is_prefix(
        &[
            "0001.sql".to_owned(),
            "0002.sql".to_owned(),
            "0003.sql".to_owned()
        ],
        &declared
    ));
}

#[test]
fn query_rows_require_successful_closed_json() {
    let rows = parse_query_rows(r#"[{"results":[{"name":"0001.sql"}],"success":true,"meta":{}}]"#)
        .expect("rows");
    assert_eq!(rows[0]["name"], "0001.sql");
    assert!(parse_query_rows(r#"[{"results":[],"success":false}]"#).is_err());
}

#[test]
fn assertion_readback_requires_the_exact_unique_label_set() {
    let valid = parse_query_rows(
        r#"[{"results":[{"assertion":"assertion_0","passed":1},{"assertion":"assertion_1","passed":1}],"success":true}]"#,
    )
    .expect("valid assertion rows");
    assert!(assertion_rows_pass(&valid, 2));

    let duplicate = parse_query_rows(
        r#"[{"results":[{"assertion":"assertion_0","passed":1},{"assertion":"assertion_0","passed":1}],"success":true}]"#,
    )
    .expect("duplicate assertion rows");
    assert!(!assertion_rows_pass(&duplicate, 2));

    let unknown = parse_query_rows(
        r#"[{"results":[{"assertion":"assertion_0","passed":1},{"assertion":"assertion_2","passed":1}],"success":true}]"#,
    )
    .expect("unknown assertion rows");
    assert!(!assertion_rows_pass(&unknown, 2));

    let failed = parse_query_rows(
        r#"[{"results":[{"assertion":"assertion_0","passed":1},{"assertion":"assertion_1","passed":0}],"success":true}]"#,
    )
    .expect("failed assertion rows");
    assert!(!assertion_rows_pass(&failed, 2));
}

#[test]
fn rectification_preserves_recovery_identity_without_weakening_fresh_plan_admission() {
    let root = tempfile::tempdir().expect("runtime root");
    let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("state store");
    let evidence = json!({
        "status":200,
        "success":true,
        "result":{"bookmark":"bookmark-a"}
    });
    let receipt = store
        .write_evidence(EvidenceClass::LiveRead, &evidence)
        .expect("bookmark evidence");
    let now = Utc::now();
    let observed_at = now - ChronoDuration::hours(2);
    let target = json!({
        "profile_id":"profile-a",
        "account_id":"account-a",
        "credential_generation_id":"generation-a",
        "recovery":{
            "capability_id":"d1-time-travel-get-bookmark",
            "observed_at":observed_at,
            "evidence_hash":receipt.content_hash,
            "bookmark":"bookmark-a",
            "bookmark_hash":hash_value(&json!("bookmark-a")).expect("bookmark hash"),
            "catalog_hash":"catalog-a",
            "input_hash":format!("sha256:{}", "a".repeat(64)),
            "profile_id":"profile-a",
            "account_id":"account-a",
            "credential_generation_id":"generation-a"
        }
    });
    let target = target.as_object().expect("target");

    assert!(
        validate_recovery_target(&store, target, "catalog-a", 600, now).is_err(),
        "ordinary plan admission must reject an aged recovery bookmark"
    );
    assert!(
        validate_recovery_target_identity(&store, target, "catalog-a", now).is_ok(),
        "rectification may reuse only the still-exact immutable bookmark identity"
    );
}

#[test]
fn query_failure_diagnostics_are_bounded_and_content_addressed() {
    let failed = WranglerOutput {
        success: false,
        exit_status: Some(1),
        stdout: "provider output".to_owned(),
        stderr: "private diagnostic detail".to_owned(),
    };
    let diagnostic = QueryFailureDiagnostic::from(&failed);
    assert_eq!(diagnostic.exit_status, "1");
    assert_eq!(diagnostic.stdout_hash, sha256(b"provider output"));
    assert_eq!(diagnostic.stderr_hash, sha256(b"private diagnostic detail"));
    let rendered = format!("{diagnostic:?}");
    assert!(!rendered.contains("provider output"));
    assert!(!rendered.contains("private diagnostic detail"));
}

#[test]
fn assertion_compiler_accepts_only_closed_identifiers() {
    let sql = compile_assertion_sql(&[
        WorkspaceD1SchemaAssertionV1 {
            kind: "column_exists".to_owned(),
            table: Some("todos".to_owned()),
            column: Some("session_id".to_owned()),
            index: None,
        },
        WorkspaceD1SchemaAssertionV1 {
            kind: "foreign_key_check_empty".to_owned(),
            table: None,
            column: None,
            index: None,
        },
    ])
    .expect("SQL");
    assert!(sql.contains("pragma_table_info('todos')"));
    assert!(sql.contains("pragma_foreign_key_check"));
    assert!(sql.starts_with("WITH assertions(assertion, passed) AS (VALUES "));
    assert!(!sql.contains("UNION ALL"));
    assert!(!sql.contains(';'));
    assert!(identifier(Some("todos'; DROP TABLE todos;--")).is_err());
}

#[test]
fn assertion_compiler_executes_eleven_checks_without_compound_selects() {
    let tables = [
        "policy_revisions",
        "runtime_state",
        "policy_projection_state",
        "reply_relays",
        "relay_attempts",
        "route_health",
        "route_proofs",
        "route_proof_coverage",
        "inbound_deliveries",
        "inbound_recipient_deliveries",
    ];
    let mut assertions = tables
        .iter()
        .map(|table| WorkspaceD1SchemaAssertionV1 {
            kind: "table_exists".to_owned(),
            table: Some((*table).to_owned()),
            column: None,
            index: None,
        })
        .collect::<Vec<_>>();
    assertions.push(WorkspaceD1SchemaAssertionV1 {
        kind: "foreign_key_check_empty".to_owned(),
        table: None,
        column: None,
        index: None,
    });
    let sql = compile_assertion_sql(&assertions).expect("SQL");
    assert!(!sql.contains("UNION ALL"));
    for index in 0..11 {
        assert!(sql.contains(&format!("'assertion_{index}'")));
    }

    let database = rusqlite::Connection::open_in_memory().expect("database");
    for table in tables {
        database
            .execute(
                &format!("CREATE TABLE {table} (id INTEGER PRIMARY KEY)"),
                [],
            )
            .expect("create assertion fixture table");
    }
    let mut statement = database.prepare(&sql).expect("prepare assertions");
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .expect("query assertions")
        .collect::<std::result::Result<Vec<_>, _>>()
        .expect("collect assertion rows");
    assert_eq!(rows.len(), 11);
    assert!(rows.iter().all(|(_, passed)| *passed == 1));

    database
        .execute("DROP TABLE route_health", [])
        .expect("drop one fixture table");
    let mut statement = database.prepare(&sql).expect("prepare assertions");
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .expect("query assertions")
        .collect::<std::result::Result<Vec<_>, _>>()
        .expect("collect assertion rows");
    assert_eq!(rows[5], ("assertion_5".to_owned(), 0));
    assert!(
        rows.iter()
            .enumerate()
            .all(|(index, (_, passed))| index == 5 || *passed == 1)
    );
}

#[test]
fn migration_names_are_filename_only() {
    let contract = cfctl_core::WorkspaceD1MigrationContractV1 {
        repository_root: "/repo".to_owned(),
        repository_head: "a".repeat(40),
        repository_origin: "https://example.com/repo.git".to_owned(),
        operation_pack_path: ".cfctl/operations/d1.toml".to_owned(),
        operation_pack_sha256: format!("sha256:{}", "a".repeat(64)),
        config_template_path: "wrangler.toml".to_owned(),
        config_template_sha256: format!("sha256:{}", "b".repeat(64)),
        production_config_path: "wrangler.production.toml".to_owned(),
        migrations_dir: "migrations".to_owned(),
        database_binding: "DB".to_owned(),
        wrangler_version: "4.120.1".to_owned(),
        migrations: vec![WorkspaceD1MigrationFileV1 {
            path: "migrations/0001_init.sql".to_owned(),
            sha256: format!("sha256:{}", "c".repeat(64)),
        }],
        assertions: Vec::new(),
        recovery_capability_id: "d1-time-travel-get-bookmark".to_owned(),
        recovery_max_age_seconds: 600,
        rollback_capability_id: "d1-restore-exact-bookmark".to_owned(),
    };
    assert_eq!(
        declared_migration_names(&contract).expect("names"),
        ["0001_init.sql"]
    );
}

#[test]
fn wrangler_version_is_exact_semver() {
    assert_eq!(
        parse_wrangler_version("wrangler 4.120.1").expect("version"),
        "4.120.1"
    );
    assert!(parse_wrangler_version("wrangler latest").is_err());
}

#[test]
fn production_config_normalizes_worker_d1_sender_identity_and_split_relay_activation() {
    let template: toml::Value = toml::from_str(
        r#"
name = "template"
main = "build/_worker.js"

send_email = [
  { name = "EMAIL" }
]

[observability]
enabled = true

[vars]
MAILDESK_INBOUND_RELAY_MODE = "disabled"
MAILDESK_REPLY_RELAY_MODE = "disabled"

[[d1_databases]]
binding = "DB"
database_name = "template-db"
database_id = "00000000-0000-0000-0000-000000000000"
preview_database_id = "00000000-0000-0000-0000-000000000000"
"#,
    )
    .expect("template");
    let mut production: toml::Value = toml::from_str(
        r#"
name = "production-worker"
main = "build/_worker.js"

send_email = [
  { name = "EMAIL", allowed_sender_addresses = ["security@example.com"] }
]

[observability]
enabled = true

[vars]
MAILDESK_INBOUND_RELAY_MODE = "enabled"
MAILDESK_REPLY_RELAY_MODE = "disabled"

[[d1_databases]]
binding = "DB"
database_name = "production-db"
database_id = "11111111-1111-4111-8111-111111111111"
preview_database_id = "11111111-1111-4111-8111-111111111111"
"#,
    )
    .expect("production");
    let identity = production_identity(&production, "DB").expect("identity");
    assert_eq!(identity.0, "production-db");
    normalize_production_identity(&mut production, &template, "DB").expect("normalize");
    assert_eq!(production, template);

    production["main"] = toml::Value::String("other.js".to_owned());
    normalize_production_identity(&mut production, &template, "DB").expect("normalize");
    assert_ne!(production, template);
}

#[test]
fn production_relay_activation_rejects_invalid_values_and_legacy_authority() {
    let template: toml::Value = toml::from_str(
        r#"
[vars]
MAILDESK_INBOUND_RELAY_MODE = "disabled"
MAILDESK_REPLY_RELAY_MODE = "disabled"
"#,
    )
    .expect("template");

    for invalid in [
        toml::Value::String("preview".to_owned()),
        toml::Value::Boolean(true),
        toml::Value::Integer(1),
    ] {
        let mut production = template.clone();
        production["vars"]["MAILDESK_INBOUND_RELAY_MODE"] = invalid;
        assert!(normalize_relay_activation(&mut production, &template).is_err());
    }

    let mut legacy = template.clone();
    legacy["vars"].as_table_mut().expect("vars table").insert(
        "MAILDESK_RELAY_PROCESSING_MODE".to_owned(),
        toml::Value::String("enabled".to_owned()),
    );
    normalize_relay_activation(&mut legacy, &template).expect("normalize allowed fields");
    assert_ne!(
        legacy, template,
        "legacy combined activation must remain forbidden drift"
    );
}

#[test]
fn production_sender_identity_rejects_malformed_or_unbounded_addresses() {
    for addresses in [
        toml::Value::Array(Vec::new()),
        toml::Value::Array(vec![toml::Value::String("not-an-address".to_owned())]),
        toml::Value::Array(vec![toml::Value::String(
            "bad address@example.com".to_owned(),
        )]),
        toml::Value::String("security@example.com".to_owned()),
    ] {
        assert!(validate_sender_addresses(&addresses).is_err());
    }
    assert!(
        validate_sender_addresses(&toml::Value::Array(vec![toml::Value::String(
            "security@example.com".to_owned()
        )]))
        .is_ok()
    );
}

#[test]
fn production_identity_accepts_a_preview_free_production_binding() {
    let production: toml::Value = toml::from_str(
        r#"
name = "production-worker"

[[d1_databases]]
binding = "DB"
database_name = "production-db"
database_id = "11111111-1111-4111-8111-111111111111"
"#,
    )
    .expect("production");

    assert_eq!(
        production_identity(&production, "DB").expect("preview-free identity"),
        (
            "production-db".to_owned(),
            "11111111-1111-4111-8111-111111111111".to_owned()
        )
    );
}

#[test]
fn production_identity_rejects_a_distinct_or_malformed_inline_preview_binding() {
    for preview in [
        "22222222-2222-4222-8222-222222222222",
        "not-a-canonical-uuid",
    ] {
        let production: toml::Value = toml::from_str(&format!(
            r#"
name = "production-worker"

[[d1_databases]]
binding = "DB"
database_name = "production-db"
database_id = "11111111-1111-4111-8111-111111111111"
preview_database_id = "{preview}"
"#
        ))
        .expect("production");
        assert!(production_identity(&production, "DB").is_err());
    }
}
