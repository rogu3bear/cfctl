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
    let store = super::super::tests::authenticated_test_store(RuntimePaths::from_root(root.path()));
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
        r#"name = "tracked-role-template"
main = "worker.js"
send_email = [{ name = "EMAIL" }]
[vars]
MAILDESK_INBOUND_RELAY_MODE = "disabled"
MAILDESK_REPLY_RELAY_MODE = "disabled"
MAILDESK_VERIFIED_SENDER_DOMAINS = ""
[[d1_databases]]
binding = "DB"
database_name = "tracked-template-database"
database_id = "00000000-0000-4000-8000-000000000000"
preview_database_id = "00000000-0000-4000-8000-000000000000"
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
preview_database_id = "{PRIVATE_D1}"
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
        Some("DB"),
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
        Some("DB"),
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
        Some("DB"),
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
        Some("DB"),
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
        Some("DB"),
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
        Some("DB"),
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
            exact_object: None,
        },
        WorkspaceD1SchemaAssertionV1 {
            kind: "foreign_key_check_empty".to_owned(),
            table: None,
            column: None,
            index: None,
            exact_object: None,
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
fn assertion_compiler_requires_the_exact_trigger_definition() {
    let definition =
        "CREATE TRIGGER users_guard BEFORE INSERT ON users BEGIN SELECT RAISE(ABORT, 'guard'); END";
    let assertion = WorkspaceD1SchemaAssertionV1 {
        kind: "object_definition_equals".to_owned(),
        table: None,
        column: None,
        index: None,
        exact_object: Some(cfctl_core::WorkspaceD1ExactObjectAssertionV1 {
            object_type: "trigger".to_owned(),
            name: "users_guard".to_owned(),
            table: Some("users".to_owned()),
            definition: definition.to_owned(),
            definition_sha256: sha256(definition.as_bytes()),
        }),
    };
    let sql = compile_assertion_sql(std::slice::from_ref(&assertion)).expect("exact assertion SQL");
    assert!(sql.contains("sql = 'CREATE TRIGGER users_guard"));
    assert!(!sql.contains("instr("));

    let database = rusqlite::Connection::open_in_memory().expect("database");
    database
        .execute_batch(
            "CREATE TABLE users(id INTEGER); CREATE TRIGGER users_guard BEFORE INSERT ON users BEGIN SELECT RAISE(ABORT, 'guard'); END;",
        )
        .expect("schema");
    assert_eq!(
        database
            .query_row(&sql, [], |row| row.get::<_, i64>(1))
            .expect("assertion result"),
        1
    );

    let mut drifted = assertion;
    drifted
        .exact_object
        .as_mut()
        .expect("exact object")
        .definition
        .push_str(" -- drift");
    assert!(compile_assertion_sql(&[drifted]).is_err());
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
            exact_object: None,
        })
        .collect::<Vec<_>>();
    assertions.push(WorkspaceD1SchemaAssertionV1 {
        kind: "foreign_key_check_empty".to_owned(),
        table: None,
        column: None,
        index: None,
        exact_object: None,
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
        transition: None,
        manifest_migration: None,
    };
    assert_eq!(
        declared_migration_names(&contract).expect("names"),
        ["0001_init.sql"]
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn manifest_migration_distinguishes_remote_baseline_from_the_sole_local_target() {
    let baseline = (116_u64..=171)
        .map(|sequence| cfctl_core::WorkspaceD1MigrationLedgerEntryV1 {
            sequence,
            name: format!("{sequence:04}_baseline.sql"),
            sha256: format!("sha256:{}", "a".repeat(64)),
        })
        .collect::<Vec<_>>();
    let contract = cfctl_core::WorkspaceD1MigrationContractV1 {
        repository_root: "/repo".to_owned(),
        repository_head: "a".repeat(40),
        repository_origin: "https://example.com/mln-web.git".to_owned(),
        operation_pack_path: ".cfctl/operations/d1-migrations.toml".to_owned(),
        operation_pack_sha256: format!("sha256:{}", "a".repeat(64)),
        config_template_path: "workers/founder/wrangler.toml".to_owned(),
        config_template_sha256: format!("sha256:{}", "b".repeat(64)),
        production_config_path: "workers/founder/wrangler.production.toml".to_owned(),
        migrations_dir: "crates/founder/migrations/d1".to_owned(),
        database_binding: "FOUNDER_DB".to_owned(),
        wrangler_version: "4.100.0".to_owned(),
        migrations: vec![WorkspaceD1MigrationFileV1 {
            path: "crates/founder/migrations/d1/0172_target.sql".to_owned(),
            sha256: format!("sha256:{}", "c".repeat(64)),
        }],
        assertions: Vec::new(),
        recovery_capability_id: "d1-time-travel-get-bookmark".to_owned(),
        recovery_max_age_seconds: 600,
        rollback_capability_id: "d1-restore-exact-bookmark".to_owned(),
        transition: None,
        manifest_migration: Some(cfctl_core::WorkspaceD1ManifestMigrationContractV1 {
            manifest_path: ".control-plane/d1_migration_manifest.json".to_owned(),
            manifest_sha256: format!("sha256:{}", "d".repeat(64)),
            account_id: "account".to_owned(),
            profile_id: "profile".to_owned(),
            database_name: "founder".to_owned(),
            database_id: "7c282983-2e48-4ea4-9f0d-09b0d718fe65".to_owned(),
            baseline_start_sequence: 116,
            baseline_end_sequence: 171,
            baseline,
            baseline_digest: format!("sha256:{}", "e".repeat(64)),
            target_sequence: 172,
            target_git_blob_oid: "1".repeat(40),
            migrations_pattern: "crates/founder/migrations/d1/0172_target.sql".to_owned(),
            ledger_table: "d1_migrations".to_owned(),
            ledger_name: "0172_target.sql".to_owned(),
            wrangler_cli_sha256: format!("sha256:{}", "f".repeat(64)),
            full_export_capability_id: "d1-full-export".to_owned(),
            require_exact_post_ledger: true,
            forbidden_future_sequences: vec![173, 174],
            require_exact_schema_sql: true,
            require_foreign_key_check_empty: true,
            require_integrity_check_ok: true,
            require_unchanged_worker_identity: true,
            require_old_worker_compatibility: true,
        }),
    };
    let before = expected_ledger_before(&contract).expect("baseline");
    let after = declared_migration_names(&contract).expect("post ledger");
    assert_eq!(before.len(), 56);
    assert_eq!(after.len(), 57);
    assert_eq!(after.last().map(String::as_str), Some("0172_target.sql"));
    assert!(!before.contains(&"0172_target.sql".to_owned()));
    let blocked = require_manifest_production_eligibility(&contract, None)
        .expect_err("manifest migration is blocked before canonical evidence joins exist");
    assert!(blocked.to_string().contains("provider-isolated atomicity"));
    assert!(blocked.to_string().contains("old-Worker compatibility"));

    let joins = cfctl_core::WorkspaceD1EvidenceJoinsV1 {
        atomicity_qualification_evidence_hash: format!("sha256:{}", "1".repeat(64)),
        old_worker_canary_evidence_hash: format!("sha256:{}", "2".repeat(64)),
        worker_deployments_evidence_hash: format!("sha256:{}", "3".repeat(64)),
        worker_version_evidence_hash: format!("sha256:{}", "4".repeat(64)),
        worker_settings_evidence_hash: format!("sha256:{}", "5".repeat(64)),
        worker_deployment_plan_hash: format!("sha256:{}", "6".repeat(64)),
    };
    require_manifest_production_eligibility(&contract, Some(&joins))
        .expect("closed manifest and six distinct joins are production eligible");

    let mut duplicate = joins.clone();
    duplicate.worker_settings_evidence_hash = duplicate.worker_version_evidence_hash.clone();
    assert!(
        require_manifest_production_eligibility(&contract, Some(&duplicate))
            .expect_err("duplicate joins are rejected")
            .to_string()
            .contains("six distinct canonical SHA-256")
    );

    for requirement in [
        "post_ledger",
        "schema_sql",
        "foreign_keys",
        "integrity",
        "worker_identity",
        "old_worker",
    ] {
        let mut incomplete = contract.clone();
        let manifest = incomplete.manifest_migration.as_mut().expect("manifest");
        match requirement {
            "post_ledger" => manifest.require_exact_post_ledger = false,
            "schema_sql" => manifest.require_exact_schema_sql = false,
            "foreign_keys" => manifest.require_foreign_key_check_empty = false,
            "integrity" => manifest.require_integrity_check_ok = false,
            "worker_identity" => manifest.require_unchanged_worker_identity = false,
            "old_worker" => manifest.require_old_worker_compatibility = false,
            _ => unreachable!(),
        }
        assert!(
            require_manifest_production_eligibility(&incomplete, Some(&joins)).is_err(),
            "the `{requirement}` production requirement is mandatory"
        );
    }

    for malformed in [
        "sha256:ABCDEF",
        "sha256:1234",
        "not-sha256",
        "sha256:gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
    ] {
        let mut invalid = joins.clone();
        invalid.worker_settings_evidence_hash = malformed.to_owned();
        assert!(require_manifest_production_eligibility(&contract, Some(&invalid)).is_err());
    }
}

#[test]
fn staged_manifest_execution_config_selects_exactly_one_migration() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().expect("fixture");
    let template = root.path().join("wrangler.founder.toml");
    let production = root.path().join("wrangler.founder.production.toml");
    let template_source = r#"name = "founder"
[vars]
MAILDESK_VERIFIED_SENDER_DOMAINS = ""
[[d1_databases]]
binding = "FOUNDER_DB"
database_name = "founder"
database_id = "7c282983-2e48-4ea4-9f0d-09b0d718fe65"
"#;
    let production_source = template_source.replace(
        "MAILDESK_VERIFIED_SENDER_DOMAINS = \"\"",
        "MAILDESK_VERIFIED_SENDER_DOMAINS = \"sender.example.com\"",
    );
    fs::write(&template, template_source).expect("template");
    fs::write(&production, &production_source).expect("production");
    fs::set_permissions(&production, fs::Permissions::from_mode(0o600)).expect("private mode");
    let mut bound = worker_deployment::bind_workspace_d1_private_config_for_execution(
        &production,
        &template,
        Some(&sha256(production_source.as_bytes())),
        Some(&sha256(template_source.as_bytes())),
        "FOUNDER_DB",
    )
    .expect("bound migration config");
    stage_migration_selection(
        &mut bound,
        "FOUNDER_DB",
        &MigrationSelection {
            dir: "/repo/crates/founder/migrations/d1".to_owned(),
            pattern: "/repo/crates/founder/migrations/d1/0172_target.sql".to_owned(),
            table: "d1_migrations".to_owned(),
        },
    )
    .expect("stage selection");
    let staged = fs::read_to_string(bound.path()).expect("staged config");
    let staged: toml::Value = toml::from_str(&staged).expect("staged TOML");
    let database = &staged["d1_databases"][0];
    assert_eq!(
        database["migrations_dir"].as_str(),
        Some("/repo/crates/founder/migrations/d1")
    );
    assert_eq!(
        database["migrations_pattern"].as_str(),
        Some("/repo/crates/founder/migrations/d1/0172_target.sql")
    );
    assert_eq!(database["migrations_table"].as_str(), Some("d1_migrations"));
    assert_eq!(
        bound.content_sha256(),
        sha256(production_source.as_bytes()).trim_start_matches("sha256:")
    );
}

#[test]
fn atomic_migration_model_rolls_back_ddl_and_ledger_failures() {
    let mut success = rusqlite::Connection::open_in_memory().expect("success database");
    success
        .execute(
            "CREATE TABLE d1_migrations(id INTEGER PRIMARY KEY, name TEXT NOT NULL)",
            [],
        )
        .expect("ledger");
    {
        let transaction = success.transaction().expect("transaction");
        transaction
            .execute_batch("CREATE TABLE governed(id INTEGER PRIMARY KEY);")
            .expect("DDL");
        transaction
            .execute(
                "INSERT INTO d1_migrations(name) VALUES (?1)",
                ["0172_target.sql"],
            )
            .expect("ledger insert");
        transaction.commit().expect("commit");
    }
    assert_eq!(
        success
            .query_row("SELECT COUNT(*) FROM governed", [], |row| row
                .get::<_, i64>(0))
            .expect("schema"),
        0
    );
    assert_eq!(
        success
            .query_row("SELECT COUNT(*) FROM d1_migrations", [], |row| row
                .get::<_, i64>(0))
            .expect("ledger count"),
        1
    );

    for ledger_failure in [false, true] {
        let mut database = rusqlite::Connection::open_in_memory().expect("failure database");
        database
            .execute(
                "CREATE TABLE d1_migrations(id INTEGER PRIMARY KEY, name TEXT NOT NULL)",
                [],
            )
            .expect("ledger");
        if ledger_failure {
            database
                .execute_batch("CREATE TRIGGER reject_ledger BEFORE INSERT ON d1_migrations BEGIN SELECT RAISE(ABORT, 'reject'); END;")
                .expect("ledger failure trigger");
        }
        let transaction = database.transaction().expect("transaction");
        let result = if ledger_failure {
            transaction
                .execute_batch("CREATE TABLE governed(id INTEGER PRIMARY KEY);")
                .and_then(|()| {
                    transaction
                        .execute(
                            "INSERT INTO d1_migrations(name) VALUES (?1)",
                            ["0172_target.sql"],
                        )
                        .map(|_| ())
                })
        } else {
            transaction.execute_batch("CREATE TABLE governed(id INTEGER PRIMARY KEY); INVALID SQL;")
        };
        assert!(result.is_err());
        drop(transaction);
        assert_eq!(
            database
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name='governed'",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .expect("schema count"),
            0
        );
        assert_eq!(
            database
                .query_row("SELECT COUNT(*) FROM d1_migrations", [], |row| row
                    .get::<_, i64>(0))
                .expect("ledger count"),
            0
        );
    }
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
    let production: toml::Value = toml::from_str(
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
    let template = serde_json::to_value(template).expect("template JSON");
    let production = serde_json::to_value(production).expect("production JSON");
    let mut normalized = production.clone();
    let identity =
        worker_deployment::normalize_workspace_d1_private_config(&mut normalized, &template, "DB")
            .expect("normalize");
    assert_eq!(identity.database_name, "production-db");
    assert_eq!(normalized, template);

    let mut drifted = production;
    drifted["main"] = json!("other.js");
    drifted["vars"]["MAILDESK_VERIFIED_SENDER_DOMAINS"] =
        json!("sender.example.com,relay.example.org");
    worker_deployment::normalize_workspace_d1_private_config(&mut drifted, &template, "DB")
        .expect("normalize");
    assert_ne!(drifted, template);
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

fn workspace_d1_overlay_documents() -> (Value, Value) {
    let parse = |text: &str| {
        let document: toml::Value = toml::from_str(text).expect("Wrangler TOML");
        serde_json::to_value(document).expect("Wrangler JSON")
    };
    let template = parse(
        r#"name = "tracked-role"
main = "worker.js"
send_email = [{ name = "EMAIL" }]
[vars]
MAILDESK_INBOUND_RELAY_MODE = "disabled"
MAILDESK_REPLY_RELAY_MODE = "disabled"
MAILDESK_VERIFIED_SENDER_DOMAINS = ""
[[d1_databases]]
binding = "DB"
database_name = "tracked-db"
database_id = "00000000-0000-4000-8000-000000000000"
"#,
    );
    let production = parse(
        r#"name = "production-role"
main = "worker.js"
send_email = [{ name = "EMAIL", allowed_sender_addresses = ["security@example.com"] }]
[vars]
MAILDESK_INBOUND_RELAY_MODE = "enabled"
MAILDESK_REPLY_RELAY_MODE = "disabled"
MAILDESK_VERIFIED_SENDER_DOMAINS = "sender.example.com,relay.example.org"
[[d1_databases]]
binding = "DB"
database_name = "production-db"
database_id = "11111111-1111-4111-8111-111111111111"
"#,
    );
    (template, production)
}

#[test]
fn workspace_d1_shared_overlay_preserves_closed_private_field_rules() {
    let (template, production) = workspace_d1_overlay_documents();
    let mut allowed = production.clone();
    let identity =
        worker_deployment::normalize_workspace_d1_private_config(&mut allowed, &template, "DB")
            .expect("closed workspace-D1 overlay");
    assert_eq!(identity.database_name, "production-db");
    assert_eq!(identity.database_id, "11111111-1111-4111-8111-111111111111");
    assert_eq!(allowed, template);

    let mut absent_template = template.clone();
    absent_template["vars"]
        .as_object_mut()
        .expect("template vars")
        .remove("MAILDESK_VERIFIED_SENDER_DOMAINS");
    let mut absent_production = production.clone();
    absent_production["vars"]
        .as_object_mut()
        .expect("production vars")
        .remove("MAILDESK_VERIFIED_SENDER_DOMAINS");
    assert!(
        worker_deployment::normalize_workspace_d1_private_config(
            &mut absent_production,
            &absent_template,
            "DB",
        )
        .is_err()
    );

    let mut template_only_production = production.clone();
    template_only_production["vars"]
        .as_object_mut()
        .expect("production vars")
        .remove("MAILDESK_VERIFIED_SENDER_DOMAINS");
    assert!(
        worker_deployment::normalize_workspace_d1_private_config(
            &mut template_only_production,
            &template,
            "DB"
        )
        .is_err()
    );

    let mut production_only = production.clone();
    assert!(
        worker_deployment::normalize_workspace_d1_private_config(
            &mut production_only,
            &absent_template,
            "DB"
        )
        .is_err()
    );

    for invalid in [json!("preview"), json!(true), Value::Null] {
        let mut rejected = production.clone();
        rejected["vars"]["MAILDESK_INBOUND_RELAY_MODE"] = invalid;
        assert!(
            worker_deployment::normalize_workspace_d1_private_config(
                &mut rejected,
                &template,
                "DB"
            )
            .is_err()
        );
    }
    for invalid in [json!([]), json!(["not-an-address"])] {
        let mut rejected = production.clone();
        rejected["send_email"][0]["allowed_sender_addresses"] = invalid;
        assert!(
            worker_deployment::normalize_workspace_d1_private_config(
                &mut rejected,
                &template,
                "DB"
            )
            .is_err()
        );
    }

    let mut unrelated = production;
    unrelated["vars"]["UNRELATED_PRIVATE_VAR"] = json!("forbidden");
    worker_deployment::normalize_workspace_d1_private_config(&mut unrelated, &template, "DB")
        .expect("normalize only closed fields");
    assert_ne!(unrelated, template);
}

#[test]
fn workspace_d1_shared_overlay_rejects_bad_domains_without_disclosure() {
    let (template, production) = workspace_d1_overlay_documents();
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
        let mut rejected = production.clone();
        rejected["vars"]["MAILDESK_VERIFIED_SENDER_DOMAINS"] = json!(invalid);
        let error = worker_deployment::normalize_workspace_d1_private_config(
            &mut rejected,
            &template,
            "DB",
        )
        .expect_err("invalid domain overlay must fail")
        .to_string();
        assert!(invalid.is_empty() || !error.contains(invalid));
    }
}

#[test]
fn workspace_d1_shared_overlay_closes_selected_identity_shape() {
    let (template, production) = workspace_d1_overlay_documents();
    let mut preview_free = production.clone();
    assert!(
        worker_deployment::normalize_workspace_d1_private_config(
            &mut preview_free,
            &template,
            "DB"
        )
        .is_ok()
    );

    for preview in [
        "22222222-2222-4222-8222-222222222222",
        "not-a-canonical-uuid",
    ] {
        let mut rejected = production.clone();
        rejected["d1_databases"][0]["preview_database_id"] = json!(preview);
        assert!(
            worker_deployment::normalize_workspace_d1_private_config(
                &mut rejected,
                &template,
                "DB"
            )
            .is_err()
        );
    }

    let mut extra = production;
    extra["d1_databases"][0]["unowned"] = json!(true);
    worker_deployment::normalize_workspace_d1_private_config(&mut extra, &template, "DB")
        .expect("validate selected identity without hiding extras");
    assert_ne!(extra, template);
}
