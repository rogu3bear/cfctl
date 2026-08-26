use super::*;

#[cfg(any(unix, windows))]
pub(super) async fn wait_for_delegated_process_fixture(path: &Path) {
    for _ in 0..500 {
        if path.is_file() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!(
        "delegated process-tree fixture did not reach its startup handshake at {}",
        path.display()
    );
}

pub(super) fn guide_json(capability: &CapabilityV1) -> Value {
    serde_json::to_value(guide_document(capability)).expect("typed capability guide JSON")
}

#[test]
pub(super) fn reply_subdomain_fresh_precondition_failure_is_not_promoted_to_a_partial_mutation() {
    let capability = CapabilityV1::new(
        "star-maildesk-cf.reply-subdomain-ingress-activate",
        "Activate reply ingress",
        "POST",
        "workspace maildesk reply-subdomain ingress activation",
    );
    let plan = PlanV1::draft(
        "maildesk-deploy",
        "account-a",
        "sha256:catalog",
        capability,
        json!({}),
    )
    .expect("plan");
    let receipt = json!({
        "adapter":"workspace_reply_subdomain_ingress_activation_apply_v1",
        "success":false,
        "boundary_crossed":false,
        "failure_code":"CFCTL_WORKSPACE_REPLY_SUBDOMAIN_FRESH_PRECONDITION_FAILED",
        "status":"fresh_account_plan_drifted",
        "provider_output_retained":false,
        "body_returned":false,
    });
    let envelope = super::reply_subdomain_fresh_precondition_failure_envelope(
        &plan,
        receipt,
        EvidenceV1::new(EvidenceClass::Apply, "sha256:evidence", "evidence.json"),
    );
    assert!(!envelope.ok);
    assert!(!envelope.performed);
    assert_eq!(
        envelope.operation_id.as_deref(),
        Some(plan.operation_id.as_str())
    );
    let error = envelope.error.expect("typed error");
    assert_eq!(
        error.code,
        "CFCTL_WORKSPACE_REPLY_SUBDOMAIN_FRESH_PRECONDITION_FAILED"
    );
    assert!(error.message.contains("was not attempted"));
    assert!(!error.message.contains("subprocess"));
    assert!(!error.message.contains("partial mutation"));
    let next_step = error.next_step.expect("next step");
    assert!(next_step.contains("must not be replayed"));
    assert!(next_step.contains(&plan.operation_id));
    assert!(next_step.contains("create a fresh PlanV2"));
}

#[test]
pub(super) fn r2_lifecycle_prior_state_materializes_the_provider_default_empty_prefix() {
    let live = json!({
        "rules": [{
            "id": "Default Multipart Abort Rule",
            "enabled": true,
            "conditions": {},
            "abortMultipartUploadsTransition": {"condition": {"maxAge": 604_800}}
        }]
    });

    let normalized =
        super::normalize_same_path_prior_state("r2-put-bucket-lifecycle-configuration", live);
    assert_eq!(normalized["rules"][0]["conditions"]["prefix"], "");

    let custom_empty_conditions = json!({
        "rules": [{
            "id": "custom-abort-rule",
            "enabled": true,
            "conditions": {},
            "abortMultipartUploadsTransition": {"condition": {"maxAge": 604_800}}
        }]
    });
    assert_eq!(
        super::normalize_same_path_prior_state(
            "r2-put-bucket-lifecycle-configuration",
            custom_empty_conditions.clone(),
        ),
        custom_empty_conditions
    );

    let drifted_default = json!({
        "rules": [{
            "id": "Default Multipart Abort Rule",
            "enabled": true,
            "conditions": {},
            "abortMultipartUploadsTransition": {"condition": {"maxAge": 86_400}}
        }]
    });
    assert_eq!(
        super::normalize_same_path_prior_state(
            "r2-put-bucket-lifecycle-configuration",
            drifted_default.clone(),
        ),
        drifted_default
    );

    let malformed = json!({
        "rules": [{
            "id": "missing-conditions",
            "enabled": true,
            "abortMultipartUploadsTransition": {"condition": {"maxAge": 604_800}}
        }]
    });
    assert_eq!(
        super::normalize_same_path_prior_state(
            "r2-put-bucket-lifecycle-configuration",
            malformed.clone(),
        ),
        malformed
    );
}

pub(super) fn pages_source_test_input() -> CallInput {
    CallInput {
        selectors: json!({"account_id":"account-a"}),
        body: Some(json!({
            "name":"site-project",
            "production_branch":"main",
            "source": {
                "type":"github",
                "config": {
                    "owner":"example-owner",
                    "repo_name":"site-source",
                    "production_branch":"main"
                }
            }
        })),
        ..CallInput::default()
    }
}

pub(super) fn pages_create_test_capability() -> CapabilityV1 {
    CapabilityV1::new(
        PROJECT_CREATE_CAPABILITY_ID,
        "Create Pages project",
        "POST",
        "/accounts/{account_id}/pages/projects",
    )
}

#[test]
pub(super) fn pages_project_creation_requires_an_exact_live_absence_receipt() {
    let capability = pages_create_test_capability();
    assert!(should_bind_pages_project_absence(&capability));
    let mut drifted_capability = capability.clone();
    drifted_capability.method = "PUT".to_owned();
    assert!(!should_bind_pages_project_absence(&drifted_capability));
    assert!(workspace_resource_keys(&drifted_capability, &pages_source_test_input()).is_empty());
    let absent = CloudflareResponseV1 {
        status: 404,
        success: false,
        result: Value::Null,
        errors: vec![CloudflareApiErrorV1 {
            code: Some(8_000_007),
            message: "Project not found".to_owned(),
        }],
        result_info: None,
        etag: None,
        cf_ray: Some("ray-a".to_owned()),
    };
    let receipt = apply_pages_project_absence_response("account-a", "site-project", &absent)
        .expect("the exact Pages not-found response proves target absence");
    assert_eq!(receipt["project_name"], "site-project");
    assert_eq!(receipt["http_status"], 404);
    assert_eq!(receipt["absent"], true);

    let exists = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"name":"site-project"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    assert!(
        apply_pages_project_absence_response("account-a", "site-project", &exists)
            .expect_err("an existing project blocks creation")
            .to_string()
            .contains("already exists")
    );

    for ambiguous in [
        CloudflareResponseV1 {
            status: 403,
            success: false,
            result: Value::Null,
            errors: Vec::new(),
            result_info: None,
            etag: None,
            cf_ray: None,
        },
        CloudflareResponseV1 {
            status: 404,
            success: false,
            result: Value::Null,
            errors: vec![CloudflareApiErrorV1 {
                code: Some(10_000),
                message: "Unknown route".to_owned(),
            }],
            result_info: None,
            etag: None,
            cf_ray: None,
        },
    ] {
        assert!(
            apply_pages_project_absence_response("account-a", "site-project", &ambiguous)
                .expect_err("non-exact read failure cannot prove target absence")
                .to_string()
                .contains("cannot prove")
        );
    }
    assert!(is_live_plan_precondition_hash(PROJECT_ABSENCE_PRECONDITION));
}

#[test]
pub(super) fn pages_absence_receipt_binds_the_selected_account_and_target() {
    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-a",
        pages_create_test_capability(),
        json!({}),
    )
    .expect("Pages plan");
    plan.input = serde_json::to_value(pages_source_test_input()).expect("Pages input");
    let receipt = json!({
        "schema_version": 1,
        "source_capability_id": PROJECT_READ_CAPABILITY_ID,
        "source_path": PROJECT_DETAIL_PATH,
        "target_capability_id": PROJECT_CREATE_CAPABILITY_ID,
        "target_path": "/accounts/{account_id}/pages/projects",
        "target_scope": "account",
        "account_id": "account-a",
        "project_name": "site-project",
        "http_status": 404,
        "absent": true,
    });
    validate_pages_project_absence_receipt(&plan, &receipt).expect("exact Pages absence receipt");

    plan.account_id = "account-b".to_owned();
    assert!(validate_pages_project_absence_receipt(&plan, &receipt).is_err());
    plan.account_id = "account-a".to_owned();
    plan.input["body"]["name"] = json!("different-project");
    assert!(validate_pages_project_absence_receipt(&plan, &receipt).is_err());
}

#[test]
pub(super) fn pages_remote_head_requires_one_exact_lowercase_sha_and_ref() {
    let commit = "a".repeat(40);
    let exact = format!("{commit}\trefs/heads/main\n");
    assert_eq!(
        parse_pages_remote_head(&exact, "main").expect("exact remote row"),
        commit
    );
    for malformed in [
        format!("{} refs/heads/main\n", "a".repeat(40)),
        format!("{}\trefs/heads/main\n", "a".repeat(39)),
        format!("{}\trefs/heads/main\n", "A".repeat(40)),
        format!("{}\trefs/heads/other\n", "a".repeat(40)),
        format!(
            "{}\trefs/heads/main\n{}\trefs/heads/main\n",
            "a".repeat(40),
            "b".repeat(40)
        ),
    ] {
        assert!(parse_pages_remote_head(&malformed, "main").is_err());
    }
}

#[test]
pub(super) fn pages_github_identity_and_matching_url_rewrites_fail_closed() {
    for remote in [
        "https://github.com/Example-Owner/site-source.git",
        "ssh://git@github.com/Example-Owner/site-source.git",
        "git@github.com:Example-Owner/site-source.git",
    ] {
        assert_eq!(
            github_remote_identity(remote),
            Some(("example-owner".to_owned(), "site-source".to_owned()))
        );
    }
    for rejected in [
        "https://git@github.com/example-owner/site-source.git",
        "https://github.com:444/example-owner/site-source.git",
        "https://github.com/example-owner/site-source/extra.git",
        "https://gitlab.com/example-owner/site-source.git",
    ] {
        assert_eq!(github_remote_identity(rejected), None);
    }

    let canonical = "https://github.com/example-owner/site-source.git";
    let scp = "git@github.com:example-owner/site-source.git";
    assert!(
        matching_git_url_rewrite(
            "url.file:///tmp/mirror/.insteadof https://github.com/\n",
            &[canonical, scp],
        )
        .expect("well-formed rewrite")
    );
    assert!(
        matching_git_url_rewrite(
            "url.ssh://mirror/.insteadof git@github.com:\n",
            &[canonical, scp],
        )
        .expect("well-formed scp rewrite")
    );
    assert!(
        !matching_git_url_rewrite(
            "url.file:///tmp/mirror/.insteadof https://example.invalid/\n",
            &[canonical, scp],
        )
        .expect("unrelated rewrite")
    );
    assert!(matching_git_url_rewrite("malformed-row\n", &[canonical]).is_err());
}

#[test]
pub(super) fn pages_source_requires_exactly_one_raw_effective_origin() {
    let root = tempfile::tempdir().expect("repository root");
    init_pages_scope_repository(root.path(), "name = \"site-project\"\n");
    assert!(
        StdCommand::new("git")
            .args([
                "remote",
                "add",
                "origin",
                "https://github.com/example-owner/site-source.git",
            ])
            .current_dir(root.path())
            .status()
            .expect("source origin")
            .success()
    );
    assert_eq!(
        configured_origin(root.path()).expect("one raw origin"),
        Some("https://github.com/example-owner/site-source.git".to_owned())
    );
    assert!(
        StdCommand::new("git")
            .args([
                "config",
                "--add",
                "remote.origin.url",
                "https://github.com/example-owner/different-source.git",
            ])
            .current_dir(root.path())
            .status()
            .expect("second source origin")
            .success()
    );
    assert!(configured_origin(root.path()).is_err());

    let linked_root = tempfile::tempdir().expect("linked-worktree root");
    let common = linked_root.path().join("common");
    let linked = linked_root.path().join("linked");
    init_pages_scope_repository(&common, "name = \"site-project\"\n");
    assert!(
        StdCommand::new("git")
            .args([
                "remote",
                "add",
                "origin",
                "https://github.com/example-owner/site-source.git",
            ])
            .current_dir(&common)
            .status()
            .expect("common source origin")
            .success()
    );
    assert!(
        StdCommand::new("git")
            .args(["config", "extensions.worktreeConfig", "true"])
            .current_dir(&common)
            .status()
            .expect("enable worktree config")
            .success()
    );
    assert!(
        StdCommand::new("git")
            .args(["worktree", "add", "--quiet", "--detach"])
            .arg(&linked)
            .current_dir(&common)
            .status()
            .expect("linked worktree")
            .success()
    );
    assert!(
        StdCommand::new("git")
            .args([
                "config",
                "--worktree",
                "remote.origin.url",
                "https://github.com/example-owner/substituted-source.git",
            ])
            .current_dir(&linked)
            .status()
            .expect("worktree source override")
            .success()
    );
    assert!(configured_origin(&linked).is_err());
}

#[test]
pub(super) fn pages_source_receipt_is_categorical_and_remote_drift_changes_its_hash() {
    let input = pages_source_test_input();
    let first = pages_source_remote_receipt(&input, &"a".repeat(40)).expect("first source receipt");
    let second =
        pages_source_remote_receipt(&input, &"b".repeat(40)).expect("drifted source receipt");
    assert_eq!(first.as_object().expect("object").len(), 7);
    assert_eq!(first["provider"], "github");
    assert_eq!(first["repository"], "site-source");
    assert!(first.get("remote_url").is_none());
    assert_ne!(
        hash_value(&first).expect("first hash"),
        hash_value(&second).expect("second hash")
    );

    let mut plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-a",
        pages_create_test_capability(),
        json!({}),
    )
    .expect("Pages plan");
    plan.input = serde_json::to_value(input).expect("Pages input");
    validate_pages_source_remote_receipt(&plan, &first).expect("exact source receipt");
    let mut drifted_identity = first;
    drifted_identity["repository"] = json!("different-source");
    assert!(validate_pages_source_remote_receipt(&plan, &drifted_identity).is_err());
}

#[test]
pub(super) fn wrangler_deploy_has_a_bounded_extended_timeout_without_broadening_other_cli_calls() {
    assert_eq!(
        super::governed_delegated_cli_timeout("wrangler.deploy"),
        Duration::from_mins(10)
    );
    for capability_id in [
        "wrangler.versions-upload",
        "wrangler.versions-deploy",
        "wrangler.pages-deploy",
        "arbitrary.delegated-cli",
    ] {
        assert_eq!(
            super::governed_delegated_cli_timeout(capability_id),
            Duration::from_mins(2),
            "{capability_id} must retain the generic bound"
        );
    }
}

#[test]
pub(super) fn subprocess_timeout_reports_each_actual_governed_bound() {
    for seconds in [120, 300, 600] {
        let error = CliError::SubprocessTimeout {
            label: "bounded tool".to_owned(),
            timeout_seconds: seconds,
        };
        assert!(
            error
                .to_string()
                .contains(&format!("{seconds}-second governed timeout"))
        );
        assert_eq!(error.code(), "CFCTL_SUBPROCESS_TIMEOUT");
        let next_step = error.next_step().expect("typed timeout guidance");
        assert!(next_step.contains("plans status"));
        assert!(next_step.contains("do not assume the plan was consumed"));
        assert!(next_step.contains("replay the mutation"));
        assert!(!next_step.contains("plans rectify"));
    }
}

#[cfg(unix)]
#[tokio::test]
pub(super) async fn governed_delegated_timeout_terminates_the_full_build_process_tree() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = tempfile::tempdir().expect("delegated process-tree root");
    let program = root.path().join("wrangler-timeout-probe.sh");
    let pid_file = root.path().join("pids");
    fs::write(
        &program,
        "#!/bin/sh\nsleep 30 &\nprintf '%s %s\\n' \"$$\" \"$!\" > \"$2\"\nwait\n",
    )
    .expect("timeout probe source");
    let mut permissions = fs::metadata(&program)
        .expect("timeout probe metadata")
        .permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&program, permissions).expect("timeout probe permissions");
    let cache = root.path().join("cache");
    fs::create_dir(&cache).expect("cache root");
    let mut capability =
        CapabilityV1::new("wrangler.deploy", "deploy Worker", "CLI", "wrangler deploy");
    capability.method = "CLI".to_owned();
    capability.adapter_status = AdapterStatus::DelegatedCli;

    let task_program = program.clone();
    let task_pid_file = pid_file.clone();
    let task_cache = cache.clone();
    let execution = tokio::spawn(async move {
        super::run_delegated_cli_with_timeout(
            &capability,
            &CallInput {
                selectors: json!({}),
                query: json!({"argument":task_pid_file}),
                ..CallInput::default()
            },
            &cfctl_auth::AuthCredential::Bearer {
                token: "fixture-token".to_owned(),
            },
            Some("fixture-account"),
            &task_cache,
            Some(&task_program),
            Some(Path::new("/bin/sh")),
            Duration::from_secs(5),
        )
        .await
    });
    wait_for_delegated_process_fixture(&pid_file).await;
    let error = execution
        .await
        .expect("delegated timeout task")
        .expect_err("delegated process tree must time out");
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
            alive = StdCommand::new("kill")
                .args(["-0", pid])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .expect("process probe")
                .success();
            if !alive {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(!alive, "timed-out delegated process {pid} survived");
    }
}

#[tokio::test]
pub(super) async fn delegated_launch_failure_is_typed_as_not_started() {
    let root = tempfile::tempdir().expect("delegated launch-failure root");
    let cache = root.path().join("cache");
    fs::create_dir(&cache).expect("cache root");
    let mut capability =
        CapabilityV1::new("wrangler.deploy", "deploy Worker", "CLI", "wrangler deploy");
    capability.method = "CLI".to_owned();
    capability.adapter_status = AdapterStatus::DelegatedCli;
    let missing_program = root.path().join("missing-wrangler");

    let error = super::run_delegated_cli_with_timeout(
        &capability,
        &CallInput {
            selectors: json!({}),
            query: json!({}),
            ..CallInput::default()
        },
        &AuthCredential::Bearer {
            token: "fixture-token".to_owned(),
        },
        Some("fixture-account"),
        &cache,
        Some(&missing_program),
        None,
        Duration::from_secs(1),
    )
    .await
    .expect_err("missing delegated executable must fail before launch");

    assert!(
        matches!(&error, CliError::SubprocessNotStarted { .. }),
        "unexpected launch classification: {error}"
    );
    assert_eq!(error.code(), "CFCTL_DELEGATED_MUTATION_NOT_ATTEMPTED");
}

#[cfg(windows)]
#[tokio::test]
pub(super) async fn governed_delegated_timeout_windows_job_contains_the_full_build_tree() {
    let root = tempfile::tempdir().expect("Windows delegated process-tree root");
    let program = root.path().join("wrangler-timeout-probe.ps1");
    let pid_file = root.path().join("pids");
    fs::write(
            &program,
            "$child = Start-Process powershell.exe -NoNewWindow -ArgumentList '-NoLogo','-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 30' -PassThru; Set-Content -NoNewline -LiteralPath $args[1] -Value \"$PID $($child.Id)\"; $child.WaitForExit()",
        )
        .expect("Windows timeout probe source");
    let cache = root.path().join("cache");
    fs::create_dir(&cache).expect("cache root");
    let mut capability =
        CapabilityV1::new("wrangler.deploy", "deploy Worker", "CLI", "wrangler deploy");
    capability.method = "CLI".to_owned();
    capability.adapter_status = AdapterStatus::DelegatedCli;

    let task_program = program.clone();
    let task_pid_file = pid_file.clone();
    let task_cache = cache.clone();
    let execution = tokio::spawn(async move {
        super::run_delegated_cli_with_timeout(
            &capability,
            &CallInput {
                selectors: json!({}),
                query: json!({"argument":task_pid_file}),
                ..CallInput::default()
            },
            &cfctl_auth::AuthCredential::Bearer {
                token: "fixture-token".to_owned(),
            },
            Some("fixture-account"),
            &task_cache,
            Some(&task_program),
            Some(Path::new("powershell.exe")),
            Duration::from_secs(5),
        )
        .await
    });
    wait_for_delegated_process_fixture(&pid_file).await;
    let error = execution
        .await
        .expect("delegated Windows timeout task")
        .expect_err("delegated Windows process tree must time out");
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
            alive = StdCommand::new("powershell.exe")
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
            thread::sleep(Duration::from_millis(10));
        }
        assert!(!alive, "timed-out delegated process {pid} survived");
    }
}

#[cfg(unix)]
#[test]
pub(super) fn pages_git_proof_is_prompt_free_bounded_and_terminates_its_process_group() {
    use std::os::unix::fs::PermissionsExt as _;

    fn executable_script(root: &Path, name: &str, source: &str) -> PathBuf {
        let path = root.join(name);
        fs::write(&path, source).expect("script source");
        let mut permissions = fs::metadata(&path).expect("script metadata").permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).expect("script permissions");
        path
    }

    let root = tempfile::tempdir().expect("script root");
    let prompt_probe = executable_script(
        root.path(),
        "prompt-probe.sh",
        "#!/bin/sh\n[ \"$GIT_TERMINAL_PROMPT\" = 0 ] || exit 9\n[ -z \"$GIT_ASKPASS\" ] || exit 10\n[ -z \"$SSH_ASKPASS\" ] || exit 11\n[ \"$SSH_ASKPASS_REQUIRE\" = never ] || exit 12\n[ \"$GCM_INTERACTIVE\" = Never ] || exit 13\nif IFS= read -r value; then exit 14; fi\nprintf prompt-free\n",
    );
    let prompt_output =
        run_bounded_pages_git_program(&prompt_probe, None, &[], Duration::from_secs(5))
            .expect("prompt-free subprocess");
    assert!(prompt_output.success);
    assert_eq!(prompt_output.stdout, "prompt-free");

    let askpass_marker = root.path().join("askpass-ran");
    let _askpass_probe = executable_script(
        root.path(),
        "cfctl-askpass-is-disabled",
        "#!/bin/sh\nprintf invoked > \"$CFCTL_ASKPASS_MARKER\"\n",
    );
    let credential_probe = executable_script(
        root.path(),
        "credential-probe.sh",
        "#!/bin/sh\nPATH=\"$1:$PATH\" CFCTL_ASKPASS_MARKER=\"$2\" git -c credential.helper= -c core.askPass=cfctl-askpass-is-disabled credential fill <<'EOF'\nprotocol=https\nhost=example.invalid\nusername=test\n\nEOF\n",
    );
    let credential_output = run_bounded_pages_git_program(
        &credential_probe,
        None,
        &[
            root.path().to_str().expect("UTF-8 sentinel path"),
            askpass_marker.to_str().expect("UTF-8 marker path"),
        ],
        Duration::from_secs(5),
    )
    .expect("credential probe");
    assert!(!credential_output.success);
    assert!(!askpass_marker.exists(), "PATH askpass sentinel executed");

    let secret_failure = executable_script(
        root.path(),
        "secret-failure.sh",
        "#!/bin/sh\nprintf super-secret-provider-body >&2\nexit 7\n",
    );
    let failed = run_bounded_pages_git_program(&secret_failure, None, &[], Duration::from_secs(5))
        .expect("bounded failure receipt");
    assert!(!failed.success);
    assert_eq!(failed.code, Some(7));
    assert!(failed.stdout.is_empty());

    let output_flood = executable_script(
        root.path(),
        "output-flood.sh",
        "#!/bin/sh\ni=0\nwhile [ \"$i\" -lt 8193 ]; do printf x; i=$((i + 1)); done\n",
    );
    let error = run_bounded_pages_git_program(&output_flood, None, &[], Duration::from_secs(5))
        .expect_err("oversized output must fail closed");
    assert!(matches!(error, CliError::Input(message) if message.contains("fixed bound")));

    let pid_file = root.path().join("pids");
    let timeout_probe = executable_script(
        root.path(),
        "timeout-probe.sh",
        "#!/bin/sh\nsleep 30 &\nprintf '%s %s\\n' \"$$\" \"$!\" > \"$1\"\nwait\n",
    );
    let pid_file_argument = pid_file.to_str().expect("UTF-8 pid path");
    let error = run_bounded_pages_git_program(
        &timeout_probe,
        None,
        &[pid_file_argument],
        // Match the bounded local Git configuration lane so a contended
        // full-suite worker has time to start and record the process tree
        // before the timeout verifies group termination.
        super::GIT_CONFIG_TIMEOUT,
    )
    .expect_err("timeout must fail closed");
    assert!(matches!(error, CliError::SubprocessTimeout { .. }));

    let pids = fs::read_to_string(&pid_file).expect("recorded process IDs");
    for pid in pids.split_whitespace() {
        let mut alive = true;
        for _ in 0..100 {
            alive = StdCommand::new("kill")
                .args(["-0", pid])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .expect("process probe")
                .success();
            if !alive {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(!alive, "timed-out Pages Git process {pid} survived");
    }
}

#[cfg(windows)]
#[test]
pub(super) fn pages_git_proof_windows_job_contains_an_immediate_descendant() {
    let root = tempfile::tempdir().expect("Windows process-tree root");
    let pid_file = root.path().join("descendant-pid");
    let started = std::time::Instant::now();
    let error = run_bounded_pages_git_program(
            Path::new("powershell.exe"),
            None,
            &[
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "$child = Start-Process powershell.exe -NoNewWindow -ArgumentList '-NoLogo','-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 30' -PassThru; Set-Content -NoNewline -LiteralPath $args[0] -Value $child.Id; $child.WaitForExit()",
                pid_file.to_str().expect("UTF-8 descendant PID path"),
            ],
            Duration::from_secs(1),
        )
        .expect_err("descendant-held pipe must time out");
    assert!(matches!(
        error,
        CliError::SubprocessTimeout {
            timeout_seconds: 1,
            ..
        }
    ));
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "Windows Pages Git timeout exceeded its fixed teardown bound"
    );
    let pid = fs::read_to_string(&pid_file).expect("recorded descendant PID");
    let mut alive = true;
    for _ in 0..100 {
        alive = StdCommand::new("powershell.exe")
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
        thread::sleep(Duration::from_millis(10));
    }
    assert!(!alive, "timed-out Pages Git descendant {pid} survived");
}

pub(super) fn init_pages_scope_repository(path: &Path, wrangler: &str) {
    fs::create_dir_all(path).expect("repository root");
    assert!(
        StdCommand::new("git")
            .args(["init", "--quiet", "--initial-branch=main"])
            .current_dir(path)
            .status()
            .expect("git init")
            .success()
    );
    fs::write(path.join("wrangler.toml"), wrangler).expect("wrangler fixture");
    fs::write(path.join("README.md"), "fixture\n").expect("source fixture");
    assert!(
        StdCommand::new("git")
            .args(["add", "."])
            .current_dir(path)
            .status()
            .expect("git add")
            .success()
    );
    assert!(
        StdCommand::new("git")
            .args([
                "-c",
                "user.name=cfctl test",
                "-c",
                "user.email=cfctl-test@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "fixture",
            ])
            .current_dir(path)
            .status()
            .expect("git commit")
            .success()
    );
}

#[test]
pub(super) fn pages_plan_scope_adds_the_exact_source_without_broadening_generic_preconditions() {
    let state = tempfile::tempdir().expect("state root");
    let repositories = tempfile::tempdir().expect("repository root");
    let store = StateStore::open(RuntimePaths::from_root(state.path())).expect("state store");
    let source = repositories.path().join("site-source");
    let unrelated = repositories.path().join("unrelated");
    init_pages_scope_repository(
        &source,
        "name = \"site-project\"\npages_build_output_dir = \"dist\"\n",
    );
    init_pages_scope_repository(
        &unrelated,
        "name = \"unrelated-worker\"\nmain = \"src/index.js\"\n",
    );
    assert!(
        StdCommand::new("git")
            .args([
                "remote",
                "add",
                "origin",
                "https://github.com/example-owner/site-source.git",
            ])
            .current_dir(&source)
            .status()
            .expect("source origin")
            .success()
    );
    assert!(
        StdCommand::new("git")
            .args([
                "remote",
                "add",
                "origin",
                "https://github.com/example-owner/unrelated-source.git",
            ])
            .current_dir(&unrelated)
            .status()
            .expect("unrelated origin")
            .success()
    );
    assert!(
        StdCommand::new("git")
            .args([
                "config",
                "--add",
                "remote.origin.url",
                "https://github.com/example-owner/ambiguous-unrelated-source.git",
            ])
            .current_dir(&unrelated)
            .status()
            .expect("ambiguous unrelated origin")
            .success()
    );
    store
        .register_workspace(&source, Some("account-a".to_owned()))
        .expect("register source");
    store
        .register_workspace(&unrelated, Some("account-a".to_owned()))
        .expect("register unrelated");
    let source = source.canonicalize().expect("canonical source");
    let unrelated = unrelated.canonicalize().expect("canonical unrelated");

    let input = pages_source_test_input();
    let impact = plan_impact(&store, &pages_create_test_capability(), &input, "account-a")
        .expect("Pages impact");
    assert_eq!(
        impact.affected_repositories,
        vec![source.display().to_string()]
    );
    assert!(
        impact
            .affected_resources
            .contains(&"pages_project:site-project".to_owned())
    );

    let before =
        workspace_precondition_hashes_for_scope(&store, &impact.affected_repositories, &[])
            .expect("scoped generic preconditions");
    fs::write(unrelated.join("README.md"), "unrelated drift\n").expect("unrelated drift");
    let after_unrelated =
        workspace_precondition_hashes_for_scope(&store, &impact.affected_repositories, &[])
            .expect("unrelated repository remains outside scope");
    assert_eq!(before, after_unrelated);

    fs::write(source.join("README.md"), "source drift\n").expect("source drift");
    let after_source =
        workspace_precondition_hashes_for_scope(&store, &impact.affected_repositories, &[])
            .expect("source repository remains bound");
    assert_ne!(before, after_source);
}
