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
            None,
            None,
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
            None,
            None,
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
        provider_output_retained: true,
        private_config_sha256: None,
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
fn private_query_projection_rejects_token_and_structural_smuggling() {
    let assertion_sql = "WITH assertions(assertion, passed) AS (VALUES ('assertion_0', 1)) SELECT assertion, passed FROM assertions";
    let arguments = vec!["--command".to_owned(), assertion_sql.to_owned()];
    let valid = br#"[{"success":true,"results":[{"assertion":"assertion_0","passed":1}]}]"#;
    assert!(project_private_json_query(valid, &arguments).is_ok());

    for rejected in [
        br#"[{"success":true,"results":[{"assertion":"assertion_0","passed":1,"name":"73656e6465722e707269766174652e6578616d706c65"}]}]"#.as_slice(),
        br#"[{"success":true,"results":[{"assertion":"assertion_0","passed":1,"extra":{"private":"value"}}]}]"#.as_slice(),
        br#"[{"success":true,"results":[{"assertion":"assertion_0","passed":1,"extra":["value"]}]}]"#.as_slice(),
        br#"[{"success":true,"results":[{"assertion":"assertion_0","passed":"1"}]}]"#.as_slice(),
    ] {
        assert!(
            project_private_json_query(rejected, &arguments).is_err(),
            "unowned fields and wrong typed values must fail closed"
        );
    }

    let unknown = vec![
        "--command".to_owned(),
        "SELECT arbitrary FROM private".to_owned(),
    ];
    assert!(project_private_json_query(valid, &unknown).is_err());

    let ledger = vec![
        "--command".to_owned(),
        "SELECT name FROM d1_migrations ORDER BY id".to_owned(),
    ];
    assert!(
        project_private_json_query(
            br#"[{"success":true,"results":[{"name":"0001_create_mail.sql"}]}]"#,
            &ledger,
        )
        .is_ok()
    );
    assert!(
        project_private_json_query(
            br#"[{"success":true,"results":[{"name":"73656e6465722e707269766174652e6578616d706c65"}]}]"#,
            &ledger,
        )
        .is_err(),
        "private-shaped values may not escape under the owned ledger field"
    );
}

#[cfg(unix)]
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one private-D1 boundary regression binds immutable config staging to query, apply, failure, collision, and pre-launch drift assertions without allowing raw provider output between phases"
)]
async fn private_workspace_d1_output_is_projected_before_return() {
    use std::os::unix::fs::PermissionsExt as _;

    const PRIVATE_D1: &str = "11111111-1111-4111-8111-111111111111";
    const PRIVATE_SENDER: &str = "security@private.example";
    const PRIVATE_DOMAIN_32: &str = "aaaaaaaaaaaaaaaaaaaaaaaa.example";
    const PRIVATE_DOMAIN_32_HEX: &str =
        "6161616161616161616161616161616161616161616161612e6578616d706c65";
    const PRIVATE_DOMAINS: &str =
        "sender.private.example,relay.private.example,aaaaaaaaaaaaaaaaaaaaaaaa.example";
    let root = tempfile::tempdir().expect("private D1 root");
    let template = root.path().join("wrangler.toml");
    let production = root.path().join("wrangler.production.toml");
    fs::write(
        &template,
        r#"name = "relay-router"
main = "worker.js"
send_email = [{ name = "EMAIL" }]
[vars]
MAILDESK_INBOUND_RELAY_MODE = "disabled"
MAILDESK_REPLY_RELAY_MODE = "disabled"
MAILDESK_VERIFIED_SENDER_DOMAINS = ""
[[d1_databases]]
binding = "DB"
database_name = "maildesk"
database_id = "00000000-0000-4000-8000-000000000000"
"#,
    )
    .expect("tracked D1 template");
    fs::write(
        &production,
        format!(
            r#"name = "relay-router"
main = "worker.js"
send_email = [{{ name = "EMAIL", allowed_sender_addresses = ["{PRIVATE_SENDER}"] }}]
[vars]
MAILDESK_INBOUND_RELAY_MODE = "enabled"
MAILDESK_REPLY_RELAY_MODE = "disabled"
MAILDESK_VERIFIED_SENDER_DOMAINS = "{PRIVATE_DOMAINS}"
[[d1_databases]]
binding = "DB"
database_name = "maildesk"
database_id = "{PRIVATE_D1}"
"#
        ),
    )
    .expect("private D1 config");
    fs::set_permissions(&production, fs::Permissions::from_mode(0o600)).expect("private D1 mode");
    let expected_sha256 = sha256(&fs::read(&production).expect("private D1 bytes"));
    let expected_sha256 = expected_sha256
        .strip_prefix("sha256:")
        .unwrap_or(&expected_sha256)
        .to_owned();
    let expected_template_sha256 = sha256(&fs::read(&template).expect("template D1 bytes"));
    let cache = root.path().join("cache");
    fs::create_dir(&cache).expect("private D1 cache");
    let invoked_config = root.path().join("invoked-config");
    let program = root.path().join("fake-wrangler-query.sh");
    fs::write(
        &program,
        format!(
            r#"#!/bin/sh
previous=''
for argument in "$@"; do
  if [ "$previous" = '--config' ]; then printf '%s' "$argument" > '{}'; fi
  previous="$argument"
done
printf '%s\n' '[{{"success":true,"results":[{{"present":1}}],"nested":"MAILDESK_INBOUND_RELAY_MODE=enabled","encoded":"c2VuZGVyLnByaXZhdGUuZXhhbXBsZQ=="}}]'
printf '%s\n' '{PRIVATE_SENDER}' '{PRIVATE_DOMAINS}' 'enabled' '73656e6465722e707269766174652e6578616d706c65' >&2
"#,
            invoked_config.display()
        ),
    )
    .expect("fake D1 Wrangler");
    fs::set_permissions(&program, fs::Permissions::from_mode(0o700))
        .expect("fake D1 Wrangler mode");
    let arguments = [
        "d1".to_owned(),
        "execute".to_owned(),
        "maildesk".to_owned(),
        "--remote".to_owned(),
        "--config".to_owned(),
        production.display().to_string(),
        "--command".to_owned(),
        "SELECT COUNT(*) AS present FROM sqlite_schema WHERE type = 'table' AND name = 'd1_migrations'".to_owned(),
        "--json".to_owned(),
    ];
    let output = run_wrangler_program(
        &program,
        &arguments,
        root.path(),
        &AuthCredential::Bearer {
            token: "fixture-token".to_owned(),
        },
        "fixture-account",
        &cache,
        QUERY_TIMEOUT,
        Some(&expected_sha256),
        Some(&expected_template_sha256),
    )
    .await
    .expect("typed private D1 projection");
    assert!(output.success);
    assert!(!output.provider_output_retained);
    assert_eq!(
        output.private_config_sha256.as_deref(),
        Some(expected_sha256.as_str())
    );
    assert_eq!(output.stderr, "");
    assert_eq!(
        parse_query_rows(&output.stdout).expect("projected D1 rows"),
        vec![Map::from_iter([("present".to_owned(), json!(1))])]
    );
    let rendered = format!("{output:?}");
    for private in [
        PRIVATE_D1,
        PRIVATE_SENDER,
        PRIVATE_DOMAINS,
        "enabled",
        "c2VuZGVyLnByaXZhdGUuZXhhbXBsZQ==",
        "73656e6465722e707269766174652e6578616d706c65",
    ] {
        assert!(
            !rendered.contains(private),
            "typed D1 output retained private material"
        );
    }

    let collision_program = root
        .path()
        .join("fake-wrangler-representation-collision.sh");
    fs::write(
        &collision_program,
        format!(
            "#!/bin/sh\nprintf '%s\\n' '[{{\"success\":true,\"results\":[{{\"state_key\":\"active_policy_sha256\",\"state_value\":\"{PRIVATE_DOMAIN_32_HEX}\"}}]}}]'\n"
        ),
    )
    .expect("private-representation collision fixture");
    fs::set_permissions(&collision_program, fs::Permissions::from_mode(0o700))
        .expect("private-representation collision fixture mode");
    let collision_arguments = [
        "d1".to_owned(),
        "execute".to_owned(),
        "maildesk".to_owned(),
        "--remote".to_owned(),
        "--config".to_owned(),
        production.display().to_string(),
        "--command".to_owned(),
        "SELECT state_key AS state_key, state_value AS state_value FROM runtime_state WHERE state_key IN ('active_policy_sha256','desired_state_sha256','semantic_projection_sha256') ORDER BY state_key".to_owned(),
        "--json".to_owned(),
    ];
    let collision = run_wrangler_program(
        &collision_program,
        &collision_arguments,
        root.path(),
        &AuthCredential::Bearer {
            token: "fixture-token".to_owned(),
        },
        "fixture-account",
        &cache,
        QUERY_TIMEOUT,
        Some(&expected_sha256),
        Some(&expected_template_sha256),
    )
    .await
    .expect("private-representation collision projection");
    assert!(!collision.success);
    assert_eq!(collision.stdout, "");
    assert_eq!(collision.stderr, "");
    assert!(!collision.provider_output_retained);
    let collision_debug = format!("{collision:?}");
    for private in [PRIVATE_DOMAIN_32, PRIVATE_DOMAIN_32_HEX] {
        assert!(
            !collision_debug.contains(private),
            "encoded private value survived the typed projection boundary"
        );
    }
    let invoked = fs::read_to_string(&invoked_config).expect("invoked config path");
    assert_ne!(invoked, production.display().to_string());
    assert!(
        !Path::new(&invoked).exists(),
        "staged config must be removed after child reaping"
    );

    let apply_arguments = [
        "d1".to_owned(),
        "migrations".to_owned(),
        "apply".to_owned(),
        "maildesk".to_owned(),
        "--remote".to_owned(),
        "--config".to_owned(),
        production.display().to_string(),
    ];
    let apply = run_wrangler_program(
        &program,
        &apply_arguments,
        root.path(),
        &AuthCredential::Bearer {
            token: "fixture-token".to_owned(),
        },
        "fixture-account",
        &cache,
        APPLY_TIMEOUT,
        Some(&expected_sha256),
        Some(&expected_template_sha256),
    )
    .await
    .expect("private D1 apply projection");
    assert!(apply.success);
    assert_eq!(apply.stdout, "");
    assert_eq!(apply.stderr, "");
    assert!(!apply.provider_output_retained);
    for private in [PRIVATE_D1, PRIVATE_SENDER, PRIVATE_DOMAINS, "enabled"] {
        assert!(!format!("{apply:?}").contains(private));
    }

    let failure_program = root.path().join("fake-wrangler-failure.sh");
    fs::write(
        &failure_program,
        format!(
            "#!/bin/sh\nprintf '%s\\n' '{PRIVATE_D1}' '{PRIVATE_SENDER}' '{PRIVATE_DOMAINS}' 'enabled' 'c2VuZGVyLnByaXZhdGUuZXhhbXBsZQ==' >&2\nexit 7\n"
        ),
    )
    .expect("failing D1 Wrangler");
    fs::set_permissions(&failure_program, fs::Permissions::from_mode(0o700))
        .expect("failing D1 Wrangler mode");
    let failed = run_wrangler_program(
        &failure_program,
        &apply_arguments,
        root.path(),
        &AuthCredential::Bearer {
            token: "fixture-token".to_owned(),
        },
        "fixture-account",
        &cache,
        APPLY_TIMEOUT,
        Some(&expected_sha256),
        Some(&expected_template_sha256),
    )
    .await
    .expect("private D1 failure projection");
    assert!(!failed.success);
    assert_eq!(failed.exit_status, Some(7));
    assert_eq!(failed.stdout, "");
    assert_eq!(failed.stderr, "");
    assert!(!failed.provider_output_retained);
    for private in [
        PRIVATE_D1,
        PRIVATE_SENDER,
        PRIVATE_DOMAINS,
        "enabled",
        "c2VuZGVyLnByaXZhdGUuZXhhbXBsZQ==",
    ] {
        assert!(!format!("{failed:?}").contains(private));
    }

    let marker = root.path().join("unexpected-execution");
    let drift_program = root.path().join("must-not-run.sh");
    fs::write(
        &drift_program,
        format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
    )
    .expect("drift probe");
    fs::set_permissions(&drift_program, fs::Permissions::from_mode(0o700))
        .expect("drift probe mode");
    let error = run_wrangler_program(
        &drift_program,
        &arguments,
        root.path(),
        &AuthCredential::Bearer {
            token: "fixture-token".to_owned(),
        },
        "fixture-account",
        &cache,
        QUERY_TIMEOUT,
        Some("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        Some(&expected_template_sha256),
    )
    .await
    .expect_err("persistent config identity drift must fail before launch");
    assert!(error.to_string().contains("reviewed content identity"));
    assert!(
        !marker.exists(),
        "identity drift crossed the subprocess boundary"
    );
    let template_error = run_wrangler_program(
        &drift_program,
        &arguments,
        root.path(),
        &AuthCredential::Bearer {
            token: "fixture-token".to_owned(),
        },
        "fixture-account",
        &cache,
        QUERY_TIMEOUT,
        Some(&expected_sha256),
        Some("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    )
    .await
    .expect_err("persistent template identity drift must fail before launch");
    assert!(template_error.to_string().contains("template"));
    assert!(!marker.exists(), "template drift reached subprocess launch");
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
MAILDESK_VERIFIED_SENDER_DOMAINS = ""

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
MAILDESK_VERIFIED_SENDER_DOMAINS = "sender.example.com,relay.example.org"

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
    production["vars"]
        .as_table_mut()
        .expect("production vars")
        .insert(
            "MAILDESK_VERIFIED_SENDER_DOMAINS".to_owned(),
            toml::Value::String("sender.example.com,relay.example.org".to_owned()),
        );
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
fn workspace_d1_uses_the_worker_verified_sender_domain_authority_without_disclosure() {
    let template: toml::Value = toml::from_str(
        r#"
[vars]
MAILDESK_VERIFIED_SENDER_DOMAINS = ""
"#,
    )
    .expect("template");
    let production = |allowlist: &str| {
        let mut document = template.clone();
        document["vars"]["MAILDESK_VERIFIED_SENDER_DOMAINS"] =
            toml::Value::String(allowlist.to_owned());
        document
    };

    for allowlist in ["sender.example.com", "sender.example.com,relay.example.org"] {
        let mut allowed = production(allowlist);
        normalize_verified_sender_domains(&mut allowed, &template)
            .expect("normalize workspace D1 allowlist");
        assert_eq!(allowed, template);
        assert!(validate_maildesk_verified_sender_domains(allowlist).is_ok());
    }

    for invalid in [
        "",
        "*.example.com",
        "sender.example.com,sender.example.com",
        "sender.example.com,SENDER.EXAMPLE.COM",
        "bad_label.example.com",
        "https://sender.example.com",
        "sender.example.com/path",
        "security@sender.example.com",
        "sender.example.com:443",
        "sender.example.com, relay.example.org",
        "sender.example.com\n",
        ".sender.example.com",
        "sender.example.com.",
        "sender.example.com,,relay.example.org",
    ] {
        let mut rejected = production(invalid);
        let error = normalize_verified_sender_domains(&mut rejected, &template)
            .expect_err("invalid workspace D1 allowlist must fail")
            .to_string();
        assert!(
            validate_maildesk_verified_sender_domains(invalid).is_err(),
            "both consumers must share rejection semantics"
        );
        if !invalid.is_empty() {
            assert!(
                !error.contains(invalid),
                "private allowlist escaped in error"
            );
        }
    }

    let mut missing_key_template = template.clone();
    missing_key_template["vars"]
        .as_table_mut()
        .expect("template vars")
        .remove("MAILDESK_VERIFIED_SENDER_DOMAINS");
    assert!(
        normalize_verified_sender_domains(
            &mut production("sender.example.com"),
            &missing_key_template,
        )
        .is_err()
    );

    let mut unrelated = production("sender.example.com");
    unrelated["vars"]
        .as_table_mut()
        .expect("production vars")
        .insert(
            "UNRELATED_PRIVATE_VAR".to_owned(),
            toml::Value::String("forbidden".to_owned()),
        );
    normalize_verified_sender_domains(&mut unrelated, &template)
        .expect("normalize only the closed domain overlay");
    assert_ne!(
        unrelated, template,
        "unrelated private drift must remain visible"
    );
}

#[test]
fn malformed_private_production_config_error_does_not_echo_source() {
    let private = br#"[vars]
MAILDESK_VERIFIED_SENDER_DOMAINS = "private.example.com
"#;
    let error = parse_private_production_config(private)
        .expect_err("malformed private TOML must fail")
        .to_string();
    assert!(error.contains("production Wrangler config is invalid"));
    assert!(!error.contains("private.example.com"));
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
