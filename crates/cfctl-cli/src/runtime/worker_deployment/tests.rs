#![allow(clippy::wildcard_imports, reason = "white-box domain tests")]

use super::*;
use cfctl_cloudflare::CloudflareApiErrorV1;
use cfctl_core::{AdapterStatus, EffectClass, PlanStatus, RiskClass};
use cfctl_workspace::RegisteredRoot;
use std::process::Command;

#[test]
fn every_local_worker_traffic_mutation_resolves_to_one_shared_lock_target() {
    let adapter = json!({"worker_deployment":{"service_name":"drop"}});
    for capability_id in [
        "wrangler.deploy",
        "wrangler.versions-deploy",
        ROLLBACK_CAPABILITY_ID,
    ] {
        let capability = CapabilityV1::new(capability_id, "Worker write", "CLI", "worker");
        assert!(mutates_traffic(&capability));
        assert_eq!(service_name(&adapter).expect("shared lock target"), "drop");
    }
    let upload = CapabilityV1::new(
        "wrangler.versions-upload",
        "Upload Worker version",
        "CLI",
        "worker",
    );
    assert!(binds_live_state(&upload));
    assert!(!mutates_traffic(&upload));
}

#[test]
#[cfg(unix)]
fn config_selector_rejects_symlink_provenance_before_canonicalization() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().expect("repository root");
    fs::create_dir(root.path().join(".git")).expect("repository marker");
    let config = root.path().join("wrangler.mail-router.production.toml");
    fs::write(&config, "name = \"root-worker\"\nmain = \"worker.js\"\n").expect("root role config");
    assert!(
        Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(root.path())
            .status()
            .expect("git init")
            .success()
    );
    let ordinary = CallInput {
        query: json!({"config": config}),
        ..CallInput::default()
    };
    assert_eq!(
        canonical_config(&ordinary).expect("ordinary config"),
        config.canonicalize().expect("canonical ordinary config")
    );

    let leaf_alias = root.path().join("wrangler.alias.production.toml");
    symlink(&config, &leaf_alias).expect("leaf config symlink");
    let leaf_input = CallInput {
        query: json!({"config": leaf_alias}),
        ..CallInput::default()
    };
    assert!(
        canonical_config(&leaf_input).is_err(),
        "accepted leaf symlink selector"
    );

    let outside = tempfile::tempdir().expect("intermediate target");
    symlink(outside.path(), root.path().join("intermediate-link"))
        .expect("intermediate directory symlink");
    let intermediate = root
        .path()
        .join("intermediate-link")
        .join("wrangler.mail-router.production.toml");
    fs::write(
        outside.path().join("wrangler.mail-router.production.toml"),
        "name = \"outside-worker\"\nmain = \"worker.js\"\n",
    )
    .expect("outside role config");
    let intermediate_input = CallInput {
        query: json!({"config": intermediate}),
        ..CallInput::default()
    };
    assert!(
        canonical_config(&intermediate_input).is_err(),
        "accepted intermediate symlink selector"
    );

    let parent_component = root
        .path()
        .join("intermediate-link")
        .join("..")
        .join("wrangler.mail-router.production.toml");
    let parent_input = CallInput {
        query: json!({"config": parent_component}),
        ..CallInput::default()
    };
    assert!(
        canonical_config(&parent_input).is_err(),
        "accepted selector that concealed a symlink behind `..`"
    );

    let interior_dot = PathBuf::from(format!(
        "{}/./wrangler.mail-router.production.toml",
        root.path().display()
    ));
    let interior_dot_input = CallInput {
        query: json!({"config": interior_dot}),
        ..CallInput::default()
    };
    assert!(
        canonical_config(&interior_dot_input).is_err(),
        "accepted selector containing an interior `.` component"
    );
}

#[test]
fn artifact_hash_matches_the_repository_shell_contract() {
    let root = tempfile::tempdir().expect("artifact root");
    let build = root.path().join("build");
    let site = root.path().join("target/site");
    fs::create_dir_all(&build).expect("build directory");
    fs::create_dir_all(&site).expect("site directory");
    fs::write(build.join("worker.js"), "worker\n").expect("worker");
    fs::write(site.join("index.html"), "site\n").expect("site");
    let digest = artifact_set_sha256(root.path(), &[build, site]).expect("artifact digest");
    let manifest = format!(
        "{}  build/worker.js\n{}  target/site/index.html\n",
        hex::encode(Sha256::digest(b"worker\n")),
        hex::encode(Sha256::digest(b"site\n"))
    );
    assert_eq!(digest, hex::encode(Sha256::digest(manifest.as_bytes())));
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one executable repository fixture proves upload and promotion projections share exact source authority"
)]
fn target_binds_clean_source_config_service_and_complete_artifact() {
    let root = tempfile::tempdir().expect("repository root");
    let worker = root.path().join("cloudflare/site");
    let build = worker.join("build");
    let site = root.path().join("target/site");
    fs::create_dir_all(&build).expect("build directory");
    fs::create_dir_all(&site).expect("site directory");
    fs::write(build.join("_worker.js"), "worker\n").expect("worker");
    fs::write(build.join("index.wasm"), b"wasm").expect("wasm");
    fs::write(site.join("index.html"), "site\n").expect("site");
    let config = worker.join("wrangler.toml");
    let config_text = "name = \"cfctl-site\"\nmain = \"build/_worker.js\"\n[assets]\ndirectory = \"../../target/site\"\n";
    fs::write(&config, config_text).expect("config");
    assert!(
        Command::new("git")
            .args(["init", "--quiet", "--initial-branch=main"])
            .current_dir(root.path())
            .status()
            .expect("git init")
            .success()
    );
    assert!(
        Command::new("git")
            .args(["add", "."])
            .current_dir(root.path())
            .status()
            .expect("git add")
            .success()
    );
    assert!(
        Command::new("git")
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
            .current_dir(root.path())
            .status()
            .expect("git commit")
            .success()
    );
    let source_sha = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(root.path())
        .output()
        .expect("git head");
    let source_sha = String::from_utf8(source_sha.stdout)
        .expect("UTF-8 head")
        .trim()
        .to_owned();
    let artifact_sha256 =
        artifact_set_sha256(root.path(), &[build.clone(), site.clone()]).expect("hash");
    let graph =
        WorkspaceGraph::discover(&[RegisteredRoot::new(root.path())]).expect("workspace graph");
    let mut capability =
        CapabilityV1::new("wrangler.deploy", "Deploy Worker", "CLI", "wrangler deploy");
    capability.mutating = true;
    capability.adapter_status = AdapterStatus::DelegatedCli;
    capability.risk = RiskClass::CrossConfig;
    capability.effect = EffectClass::ReversibleWrite;
    let input = CallInput {
        query: json!({
            "config": config.canonicalize().expect("canonical config"),
            "name": "cfctl-site",
            "message": format!("source={source_sha} artifact-sha256={artifact_sha256}"),
        }),
        ..CallInput::default()
    };
    let projection = prepare_target(&graph, &capability, &input)
        .expect("projection")
        .expect("Worker projection");
    assert_eq!(projection["service_name"], "cfctl-site");
    assert_eq!(projection["source_sha"], source_sha);
    assert_eq!(projection["artifact"]["sha256"], artifact_sha256);
    assert!(projection["config"]["settings_sha256"].as_str().is_some());
    assert!(projection["config"]["bindings_sha256"].as_str().is_some());
    assert_eq!(projection["execution"]["supported"], true);
    assert_eq!(
        projection["post_deploy_verification"]["steps"][0]["capability_id"],
        DEPLOYMENTS_CAPABILITY_ID
    );
    assert_eq!(
        projection["post_deploy_verification"]["steps"][1]["capability_id"],
        VERSION_CAPABILITY_ID
    );
    assert_eq!(
        projection["post_deploy_verification"]["steps"][2]["capability_id"],
        SETTINGS_CAPABILITY_ID
    );
    assert_eq!(
        projection["rollback"]["capability_id"],
        ROLLBACK_CAPABILITY_ID
    );
    assert_eq!(
        projection["artifact"]["roots"],
        json!([build.canonicalize().unwrap(), site.canonicalize().unwrap()])
    );

    let mut missing_blob_graph = graph.clone();
    let config_source = missing_blob_graph
        .repositories
        .iter_mut()
        .flat_map(|repository| repository.configs.iter_mut())
        .find(|source| source.path == config.canonicalize().unwrap())
        .expect("config source");
    config_source.head_content_hash = None;
    let missing_blob = prepare_target(&missing_blob_graph, &capability, &input)
        .expect_err("config without an exact HEAD blob must fail")
        .to_string();
    assert!(missing_blob.contains("does not match an exact Git HEAD blob"));

    fs::write(&config, format!("# changed after discovery\n{config_text}"))
        .expect("mutate config after workspace discovery");
    let post_discovery_drift = prepare_target(&graph, &capability, &input)
        .expect_err("post-discovery config drift must not inherit a stale clean snapshot")
        .to_string();
    assert!(post_discovery_drift.contains("does not match an exact Git HEAD blob"));
    fs::write(&config, config_text).expect("restore exact HEAD config");

    let version_id = "11111111-2222-4333-8444-555555555555";
    let mut promotion = capability.clone();
    promotion.id = "wrangler.versions-deploy".to_owned();
    let promotion_input = CallInput {
        query: json!({
            "argument": format!("{version_id}@100"),
            "config": config.canonicalize().expect("canonical config"),
            "message": format!("promote release {source_sha}"),
        }),
        ..CallInput::default()
    };
    let promotion_projection = prepare_target(&graph, &promotion, &promotion_input)
        .expect("promotion projection")
        .expect("Worker promotion projection");
    assert_eq!(promotion_projection["service_name"], "cfctl-site");
    assert_eq!(promotion_projection["source_sha"], source_sha);
    assert_eq!(promotion_projection["promotion"]["version_id"], version_id);
    assert_eq!(promotion_projection["promotion"]["traffic_percentage"], 100);
    assert!(promotion_projection.get("artifact").is_none());
    assert!(binds_live_state(&promotion));

    let adapter_targets = json!({"worker_deployment": promotion_projection});
    validate_current_target(&graph, &promotion, &promotion_input, &adapter_targets)
        .expect("unchanged promotion target remains executable");
    let mut promotion_plan = PlanV1::draft(
        "profile-a",
        "account-a",
        "catalog-sha",
        promotion.clone(),
        json!({"adapter": adapter_targets}),
    )
    .expect("promotion plan");
    promotion_plan.approve(true, None).expect("approve plan");
    let configless_input = delegated_execution_input(
        &promotion,
        &promotion_input,
        promotion_plan
            .targets
            .get("adapter")
            .expect("adapter targets"),
    )
    .expect("derive immutable promotion boundary");
    assert!(configless_input.query.get("config").is_none());
    assert_eq!(configless_input.query["name"], "cfctl-site");
    assert!(requires_configless_working_directory(
        &promotion,
        &configless_input
    ));
    fs::write(
            &config,
            "name = \"retargeted-service\"\nmain = \"build/_worker.js\"\n[assets]\ndirectory = \"../../target/site\"\n",
        )
        .expect("retarget config after approval");
    let mut delegated_boundary_crossed = false;
    let result = validate_current_target(
        &graph,
        &promotion,
        &promotion_input,
        promotion_plan
            .targets
            .get("adapter")
            .expect("adapter targets"),
    );
    if result.is_ok() {
        promotion_plan.mark_consumed().expect("consume plan");
        delegated_boundary_crossed = true;
    }
    assert!(result.is_err());
    assert!(!delegated_boundary_crossed);
    assert_eq!(promotion_plan.status, PlanStatus::Approved);
    assert_eq!(configless_input.query["name"], "cfctl-site");
    assert!(configless_input.query.get("config").is_none());
    fs::write(
            &config,
            "name = \"cfctl-site\"\nmain = \"build/_worker.js\"\n[assets]\ndirectory = \"../../target/site\"\n",
        )
        .expect("restore config for artifact drift proof");

    fs::write(site.join("index.html"), "drift\n").expect("artifact drift");
    let error = prepare_target(&graph, &capability, &input)
        .expect_err("stale artifact identity must fail")
        .to_string();
    assert!(error.contains("message must be exactly"));
}

#[test]
#[cfg(unix)]
#[expect(
    clippy::too_many_lines,
    reason = "one Git fixture proves private overlay admission, target binding, and execution-time drift rejection"
)]
fn target_accepts_mode_0600_private_config_with_bounded_runtime_overlays() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().expect("repository root");
    let build = root.path().join("build");
    fs::create_dir_all(&build).expect("build directory");
    fs::write(build.join("worker.js"), "worker\n").expect("worker");
    let template = root.path().join("wrangler.mail-router.toml");
    let private = root.path().join("wrangler.mail-router.production.toml");
    let template_text = r#"name = "relay-router"
main = "build/worker.js"

[vars]
MAILDESK_INBOUND_RELAY_MODE = "disabled"
MAILDESK_REPLY_RELAY_MODE = "disabled"

[[d1_databases]]
binding = "MAILDESK_DB"
database_name = "relay-db"
database_id = "00000000-0000-4000-8000-000000000000"
"#;
    let private_text = template_text
        .replace(
            "00000000-0000-4000-8000-000000000000",
            "11111111-1111-4111-8111-111111111111",
        )
        .replace(
            "MAILDESK_INBOUND_RELAY_MODE = \"disabled\"",
            "MAILDESK_INBOUND_RELAY_MODE = \"enabled\"",
        );
    fs::write(&template, template_text).expect("tracked template");
    fs::write(&private, &private_text).expect("private config");
    fs::set_permissions(&private, fs::Permissions::from_mode(0o600))
        .expect("private config permissions");
    fs::write(
        root.path().join(".gitignore"),
        "wrangler.mail-router.production.toml\n",
    )
    .expect("gitignore");
    assert!(
        Command::new("git")
            .args(["init", "--quiet", "--initial-branch=main"])
            .current_dir(root.path())
            .status()
            .expect("git init")
            .success()
    );
    assert!(
        Command::new("git")
            .args(["add", "."])
            .current_dir(root.path())
            .status()
            .expect("git add")
            .success()
    );
    assert!(
        Command::new("git")
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
            .current_dir(root.path())
            .status()
            .expect("git commit")
            .success()
    );
    let source_sha = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(root.path())
        .output()
        .expect("git head");
    let source_sha = String::from_utf8(source_sha.stdout)
        .expect("UTF-8 head")
        .trim()
        .to_owned();
    let artifact_sha256 =
        artifact_set_sha256(root.path(), std::slice::from_ref(&build)).expect("hash");
    let graph =
        WorkspaceGraph::discover(&[RegisteredRoot::new(root.path())]).expect("workspace graph");
    let private_source = graph.repositories[0]
        .configs
        .iter()
        .find(|source| source.path == private.canonicalize().expect("canonical private"))
        .expect("private config source");
    assert!(private_source.head_content_hash.is_none());
    assert!(!private_source.dirty);

    let mut capability =
        CapabilityV1::new("wrangler.deploy", "Deploy Worker", "CLI", "wrangler deploy");
    capability.mutating = true;
    capability.adapter_status = AdapterStatus::DelegatedCli;
    capability.risk = RiskClass::CrossConfig;
    capability.effect = EffectClass::ReversibleWrite;
    let input = CallInput {
        query: json!({
            "config": private.canonicalize().expect("canonical private"),
            "name": "relay-router",
            "message": format!("source={source_sha} artifact-sha256={artifact_sha256}"),
        }),
        ..CallInput::default()
    };
    let projection = prepare_target(&graph, &capability, &input)
        .expect("private production projection")
        .expect("Worker projection");
    assert_eq!(projection["source_sha"], source_sha);
    assert_eq!(
        projection["config"]["authority"],
        "private_d1_identity_overlay"
    );
    assert_eq!(
        projection["config"]["template_path"],
        json!(template.canonicalize().expect("canonical template"))
    );
    assert!(
        !serde_json::to_string(&projection)
            .expect("projection JSON")
            .contains("11111111-1111-4111-8111-111111111111"),
        "private D1 identity escaped into the plan target"
    );

    let adapter_targets = json!({"worker_deployment": projection.clone()});
    fs::write(
        &private,
        template_text.replace(
            "00000000-0000-4000-8000-000000000000",
            "22222222-2222-4222-8222-222222222222",
        ),
    )
    .expect("drift private D1 identity");
    let error = validate_current_target(&graph, &capability, &input, &adapter_targets)
        .expect_err("private config whose hash drifted after planning must fail")
        .to_string();
    assert!(error.contains("drifted after workspace discovery"));

    fs::write(
        &private,
        private_text.replace("[vars]\n", "[vars]\nEXTRA = \"forbidden\"\n"),
    )
    .expect("add forbidden private field");
    let forbidden_graph = WorkspaceGraph::discover(&[RegisteredRoot::new(root.path())])
        .expect("forbidden-field graph");
    let error = prepare_target(&forbidden_graph, &capability, &input)
        .expect_err("private config with extra field must fail")
        .to_string();
    assert!(error.contains(
        "outside canonical D1 identity, sender restriction, and split relay activation fields"
    ));

    for mode in [0o644, 0o400] {
        fs::write(&private, &private_text).expect("restore private config");
        fs::set_permissions(&private, fs::Permissions::from_mode(mode))
            .expect("change private config permissions");
        let mode_graph =
            WorkspaceGraph::discover(&[RegisteredRoot::new(root.path())]).expect("mode graph");
        let error = prepare_target(&mode_graph, &capability, &input)
            .expect_err("non-0600 private config must fail")
            .to_string();
        assert!(error.contains("must have mode 0600"));
    }
}

#[test]
fn private_config_normalizes_only_canonical_d1_ids_and_split_relay_activation() {
    let parse = |text: &str| {
        let document: toml::Value = toml::from_str(text).expect("Wrangler TOML");
        serde_json::to_value(document).expect("Wrangler JSON")
    };
    let template = parse(
        r#"name = "relay-router"
main = "build/worker.js"

[observability]
enabled = true

[vars]
MAILDESK_INBOUND_RELAY_MODE = "disabled"
MAILDESK_REPLY_RELAY_MODE = "disabled"

[[d1_databases]]
binding = "MAILDESK_DB"
database_name = "relay-db"
database_id = "00000000-0000-4000-8000-000000000000"
"#,
    );
    let production_text = r#"name = "relay-router"
main = "build/worker.js"

[observability]
enabled = true

[vars]
MAILDESK_INBOUND_RELAY_MODE = "enabled"
MAILDESK_REPLY_RELAY_MODE = "disabled"

[[d1_databases]]
binding = "MAILDESK_DB"
database_name = "relay-db"
database_id = "11111111-1111-4111-8111-111111111111"
"#;
    let mut allowed = parse(production_text);
    normalize_private_d1_identity(&mut allowed, &template).expect("normalize D1 ID");
    assert_eq!(allowed, template);

    for (pointer, value) in [
        ("/main", json!("other.js")),
        ("/observability/enabled", json!(false)),
        ("/d1_databases/0/database_name", json!("other-db")),
    ] {
        let mut rejected = parse(production_text);
        *rejected
            .pointer_mut(pointer)
            .expect("existing mutation pointer") = value;
        normalize_private_d1_identity(&mut rejected, &template).expect("normalize D1 ID");
        assert_ne!(
            rejected, template,
            "normalized forbidden drift at {pointer}"
        );
    }

    for invalid in [
        "not-a-uuid",
        "11111111-1111-4111-8111-11111111111A",
        "{11111111-1111-4111-8111-111111111111}",
    ] {
        let mut rejected = parse(production_text);
        rejected["d1_databases"][0]["database_id"] = json!(invalid);
        assert!(normalize_private_d1_identity(&mut rejected, &template).is_err());
    }

    for invalid in [json!("preview"), json!(true), Value::Null] {
        let mut rejected = parse(production_text);
        rejected["vars"]["MAILDESK_INBOUND_RELAY_MODE"] = invalid;
        assert!(normalize_private_d1_identity(&mut rejected, &template).is_err());
    }

    let mut legacy = parse(production_text);
    legacy["vars"]["MAILDESK_RELAY_PROCESSING_MODE"] = json!("enabled");
    normalize_private_d1_identity(&mut legacy, &template).expect("normalize allowed fields");
    assert_ne!(
        legacy, template,
        "legacy combined activation must remain forbidden drift"
    );
}

#[test]
fn private_config_normalizes_bounded_sender_identity_without_exposing_it() {
    let parse = |text: &str| {
        let document: toml::Value = toml::from_str(text).expect("Wrangler TOML");
        serde_json::to_value(document).expect("Wrangler JSON")
    };
    let template = parse(
        r#"name = "relay-router"
main = "build/worker.js"

send_email = [
  { name = "EMAIL" }
]

[[d1_databases]]
binding = "MAILDESK_DB"
database_name = "relay-db"
database_id = "00000000-0000-4000-8000-000000000000"
"#,
    );
    let production = parse(
        r#"name = "relay-router"
main = "build/worker.js"

send_email = [
  { name = "EMAIL", allowed_sender_addresses = ["security@example.com"] }
]

[[d1_databases]]
binding = "MAILDESK_DB"
database_name = "relay-db"
database_id = "11111111-1111-4111-8111-111111111111"
"#,
    );

    let mut allowed = production.clone();
    normalize_private_d1_identity(&mut allowed, &template).expect("normalize private identity");
    assert_eq!(allowed, template);

    for invalid in [
        json!([]),
        json!(["not-an-address"]),
        json!(["security@example.com", "security@example.com"]),
    ] {
        let mut rejected = production.clone();
        rejected["send_email"][0]["allowed_sender_addresses"] = invalid;
        assert!(normalize_private_d1_identity(&mut rejected, &template).is_err());
    }

    let mut forbidden = production;
    forbidden["send_email"][0]["remote"] = json!(true);
    normalize_private_d1_identity(&mut forbidden, &template)
        .expect("normalize otherwise valid private identity");
    assert_ne!(
        forbidden, template,
        "unrelated binding drift must remain visible"
    );
}

#[test]
fn send_email_drift_is_bound_as_a_binding_not_a_setting() {
    let parse = |text: &str| {
        let document: toml::Value = toml::from_str(text).expect("Wrangler TOML");
        serde_json::to_value(document).expect("Wrangler JSON")
    };
    let baseline = parse(
        r#"name = "relay-router"
main = "build/worker.js"

send_email = [
  { name = "EMAIL" }
]
"#,
    );
    let changed = parse(
        r#"name = "relay-router"
main = "build/worker.js"

send_email = [
  { name = "OUTBOUND" }
]
"#,
    );

    assert_eq!(
        deployment_config_section_hash(&baseline, false).expect("baseline settings hash"),
        deployment_config_section_hash(&changed, false).expect("changed settings hash"),
        "send_email-only drift must not change settings_sha256"
    );
    assert_ne!(
        deployment_config_section_hash(&baseline, true).expect("baseline bindings hash"),
        deployment_config_section_hash(&changed, true).expect("changed bindings hash"),
        "send_email-only drift must change bindings_sha256"
    );
    assert_ne!(
        hash_value(&baseline).expect("baseline configuration hash"),
        hash_value(&changed).expect("changed configuration hash"),
        "send_email-only drift must remain bound by the complete configuration hash"
    );
}

#[test]
fn private_config_template_path_is_role_specific() {
    assert_eq!(
        private_config_template_path(Path::new("/repo/wrangler.mail-router.production.toml")),
        Some(PathBuf::from("/repo/wrangler.mail-router.toml"))
    );
    assert_eq!(
        private_config_template_path(Path::new("/repo/wrangler.production.toml")),
        None
    );
    assert_eq!(
        private_config_template_path(Path::new("/repo/wrangler.mail-router.toml")),
        None
    );
}

#[test]
fn target_rejects_artifact_that_canonicalizes_outside_registered_repository() {
    let root = tempfile::tempdir().expect("repository root");
    let outside = tempfile::tempdir().expect("outside artifact root");
    let worker = root.path().join("cloudflare/site");
    let build = worker.join("build");
    fs::create_dir_all(&build).expect("build directory");
    fs::write(build.join("_worker.js"), "worker\n").expect("worker");
    fs::write(outside.path().join("index.html"), "outside\n").expect("outside artifact");
    let config = worker.join("wrangler.toml");
    fs::write(
        &config,
        format!(
            "name = \"cfctl-site\"\nmain = \"build/_worker.js\"\n[assets]\ndirectory = {:?}\n",
            outside.path()
        ),
    )
    .expect("config");
    assert!(
        Command::new("git")
            .args(["init", "--quiet", "--initial-branch=main"])
            .current_dir(root.path())
            .status()
            .expect("git init")
            .success()
    );
    assert!(
        Command::new("git")
            .args(["add", "."])
            .current_dir(root.path())
            .status()
            .expect("git add")
            .success()
    );
    assert!(
        Command::new("git")
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
            .current_dir(root.path())
            .status()
            .expect("git commit")
            .success()
    );
    let graph =
        WorkspaceGraph::discover(&[RegisteredRoot::new(root.path())]).expect("workspace graph");
    let mut capability =
        CapabilityV1::new("wrangler.deploy", "Deploy Worker", "CLI", "wrangler deploy");
    capability.mutating = true;
    capability.adapter_status = AdapterStatus::DelegatedCli;
    capability.risk = RiskClass::CrossConfig;
    capability.effect = EffectClass::ReversibleWrite;
    let input = CallInput {
        query: json!({
            "config": config.canonicalize().expect("canonical config"),
            "name": "cfctl-site",
            "message": "untrusted",
        }),
        ..CallInput::default()
    };
    let error = prepare_target(&graph, &capability, &input)
        .expect_err("outside artifact must fail before planning")
        .to_string();
    assert!(error.contains("must be owned by the config repository"));
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "two independently committed repository fixtures prove deepest-owner rejection"
)]
fn target_rejects_artifact_tree_containing_nested_registered_repository() {
    let root = tempfile::tempdir().expect("repository root");
    let worker = root.path().join("cloudflare/site");
    let build = worker.join("build");
    let shared = root.path().join("shared");
    let nested = shared.join("child-repo");
    let nested_dist = nested.join("dist");
    fs::create_dir_all(&build).expect("build directory");
    fs::create_dir_all(&nested_dist).expect("nested artifact directory");
    fs::write(build.join("_worker.js"), "worker\n").expect("worker");
    fs::write(shared.join("outer.txt"), "outer\n").expect("outer artifact");
    fs::write(nested_dist.join("index.html"), "nested\n").expect("nested artifact");
    assert!(
        Command::new("git")
            .args(["init", "--quiet", "--initial-branch=main"])
            .current_dir(&nested)
            .status()
            .expect("nested git init")
            .success()
    );
    assert!(
        Command::new("git")
            .args(["add", "."])
            .current_dir(&nested)
            .status()
            .expect("nested git add")
            .success()
    );
    assert!(
        Command::new("git")
            .args([
                "-c",
                "user.name=cfctl test",
                "-c",
                "user.email=cfctl-test@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "nested fixture",
            ])
            .current_dir(&nested)
            .status()
            .expect("nested git commit")
            .success()
    );
    let config = worker.join("wrangler.toml");
    fs::write(
            &config,
            "name = \"cfctl-site\"\nmain = \"build/_worker.js\"\n[assets]\ndirectory = \"../../shared\"\n",
        )
        .expect("config");
    assert!(
        Command::new("git")
            .args(["init", "--quiet", "--initial-branch=main"])
            .current_dir(root.path())
            .status()
            .expect("outer git init")
            .success()
    );
    assert!(
        Command::new("git")
            .args(["add", "."])
            .current_dir(root.path())
            .status()
            .expect("outer git add")
            .success()
    );
    assert!(
        Command::new("git")
            .args([
                "-c",
                "user.name=cfctl test",
                "-c",
                "user.email=cfctl-test@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "outer fixture",
            ])
            .current_dir(root.path())
            .status()
            .expect("outer git commit")
            .success()
    );
    let graph =
        WorkspaceGraph::discover(&[RegisteredRoot::new(root.path())]).expect("workspace graph");
    assert_eq!(
        graph.repositories.len(),
        2,
        "nested repository must be registered"
    );
    let mut capability =
        CapabilityV1::new("wrangler.deploy", "Deploy Worker", "CLI", "wrangler deploy");
    capability.mutating = true;
    capability.adapter_status = AdapterStatus::DelegatedCli;
    capability.risk = RiskClass::CrossConfig;
    capability.effect = EffectClass::ReversibleWrite;
    let input = CallInput {
        query: json!({
            "config": config.canonicalize().expect("canonical config"),
            "name": "cfctl-site",
            "message": "untrusted",
        }),
        ..CallInput::default()
    };
    let error = prepare_target(&graph, &capability, &input)
        .expect_err("artifact tree containing a nested repository must fail before planning")
        .to_string();
    assert!(error.contains("is not owned by config repository"));
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "independently committed ignored artifact repository proves traversal does not rely on the filtered workspace graph"
)]
fn target_rejects_nested_repository_inside_ignored_artifact_directory() {
    let root = tempfile::tempdir().expect("repository root");
    let worker = root.path().join("cloudflare/site");
    let build = worker.join("build");
    let ignored_artifacts = root.path().join("dist");
    let nested = ignored_artifacts.join("child");
    fs::create_dir_all(&build).expect("build directory");
    fs::create_dir_all(&nested).expect("nested artifact directory");
    fs::write(build.join("_worker.js"), "worker\n").expect("worker");
    fs::write(nested.join("index.html"), "nested\n").expect("nested artifact");
    assert!(
        Command::new("git")
            .args(["init", "--quiet", "--initial-branch=main"])
            .current_dir(&nested)
            .status()
            .expect("nested git init")
            .success()
    );
    assert!(
        Command::new("git")
            .args(["add", "."])
            .current_dir(&nested)
            .status()
            .expect("nested git add")
            .success()
    );
    assert!(
        Command::new("git")
            .args([
                "-c",
                "user.name=cfctl test",
                "-c",
                "user.email=cfctl-test@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "nested fixture",
            ])
            .current_dir(&nested)
            .status()
            .expect("nested git commit")
            .success()
    );
    let config = worker.join("wrangler.toml");
    fs::write(
            &config,
            "name = \"cfctl-site\"\nmain = \"build/_worker.js\"\n[assets]\ndirectory = \"../../dist\"\n",
        )
        .expect("config");
    fs::write(root.path().join(".gitignore"), "dist/\n").expect("ignore generated artifacts");
    let nested_git = nested.join(".git");
    let intermediate_git = nested.join(".git-case-rename");
    fs::rename(&nested_git, &intermediate_git).expect("stage nested Git metadata rename");
    fs::rename(&intermediate_git, nested.join(".GIT"))
        .expect("use a case-variant nested Git metadata marker");
    assert!(
        Command::new("git")
            .args(["init", "--quiet", "--initial-branch=main"])
            .current_dir(root.path())
            .status()
            .expect("outer git init")
            .success()
    );
    assert!(
        Command::new("git")
            .args(["add", "."])
            .current_dir(root.path())
            .status()
            .expect("outer git add")
            .success()
    );
    assert!(
        Command::new("git")
            .args([
                "-c",
                "user.name=cfctl test",
                "-c",
                "user.email=cfctl-test@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "outer fixture",
            ])
            .current_dir(root.path())
            .status()
            .expect("outer git commit")
            .success()
    );
    let graph =
        WorkspaceGraph::discover(&[RegisteredRoot::new(root.path())]).expect("workspace graph");
    assert_eq!(
        graph.repositories.len(),
        1,
        "ignored artifact repository must remain absent from discovery"
    );
    let mut capability =
        CapabilityV1::new("wrangler.deploy", "Deploy Worker", "CLI", "wrangler deploy");
    capability.mutating = true;
    capability.adapter_status = AdapterStatus::DelegatedCli;
    capability.risk = RiskClass::CrossConfig;
    capability.effect = EffectClass::ReversibleWrite;
    let input = CallInput {
        query: json!({
            "config": config.canonicalize().expect("canonical config"),
            "name": "cfctl-site",
            "message": "untrusted",
        }),
        ..CallInput::default()
    };
    let error = prepare_target(&graph, &capability, &input)
        .expect_err("ignored artifact tree containing a nested repository must fail")
        .to_string();
    assert!(error.contains("nested Git repository metadata"));
}

#[test]
fn live_state_receipts_distinguish_absence_from_redacted_existing_state() {
    let absent = CloudflareResponseV1 {
        status: 404,
        success: false,
        result: Value::Null,
        errors: vec![CloudflareApiErrorV1 {
            code: Some(NOT_FOUND_ERROR_CODE),
            message: "This Worker does not exist on your account.".to_owned(),
        }],
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let absent =
        apply_state_responses("account-a", "cfctl-site", &absent, None, true).expect("absence");
    assert_eq!(absent["exists"], false);
    assert!(absent.get("redacted_settings_hash").is_none());
    assert!(absent.get("redacted_deployments_hash").is_none());

    let ambiguous = CloudflareResponseV1 {
        status: 404,
        success: false,
        result: Value::Null,
        errors: vec![CloudflareApiErrorV1 {
            code: Some(9_999),
            message: "ambiguous not found".to_owned(),
        }],
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    assert!(apply_state_responses("account-a", "cfctl-site", &ambiguous, None, true).is_err());

    let existing = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"compatibility_date": "2026-08-05", "secret_text": "hidden"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let deployment_a = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!([{"id": "deployment-a", "versions": [{"version_id": "version-a", "percentage": 100}]}]),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let deployment_b = CloudflareResponseV1 {
        result: json!([{"id": "deployment-b", "versions": [{"version_id": "version-b", "percentage": 100}]}]),
        ..deployment_a.clone()
    };
    let existing_a = apply_state_responses(
        "account-a",
        "cfctl-site",
        &existing,
        Some(&deployment_a),
        true,
    )
    .expect("existing");
    let existing_b = apply_state_responses(
        "account-a",
        "cfctl-site",
        &existing,
        Some(&deployment_b),
        true,
    )
    .expect("drifted deployment");
    let existing = existing_a;
    assert_eq!(existing["exists"], true);
    assert_eq!(existing["current_active"]["deployment_id"], "deployment-a");
    assert_eq!(existing["current_active"]["version_id"], "version-a");
    assert_eq!(existing["current_active"]["traffic_percentage"], 100);
    assert!(existing["redacted_settings_hash"].as_str().is_some());
    assert!(existing["redacted_deployments_hash"].as_str().is_some());
    assert_ne!(existing, existing_b);
    assert!(!existing.to_string().contains("hidden"));
}

#[test]
fn split_traffic_cannot_supply_a_truthful_prior_active_rollback_identity() {
    let settings = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"compatibility_date": "2026-08-05"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let deployments = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"deployments":[{"id":"deployment-a","versions":[
            {"version_id":"version-a","percentage":50},
            {"version_id":"version-b","percentage":50}
        ]}]}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let legacy = apply_state_responses(
        "account-a",
        "relay-router",
        &settings,
        Some(&deployments),
        false,
    )
    .expect("legacy deploy/upload lanes retain split-traffic planning");
    assert!(legacy.get("current_active").is_none());
    let error = apply_state_responses(
        "account-a",
        "relay-router",
        &settings,
        Some(&deployments),
        true,
    )
    .expect_err("split traffic has no sole rollback identity")
    .to_string();
    assert!(error.contains("one current version serving exactly 100 percent"));
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one preflight contract test covers valid history plus current, missing, split, partial, and wire-shape drift"
)]
fn rollback_preflight_binds_current_and_prior_versions_and_rejects_drift() {
    let current_deployment = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    let current_version = "11111111-2222-4333-8444-555555555555";
    let target_version = "66666666-7777-4888-8999-aaaaaaaaaaaa";
    let prior_deployment = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff";
    let target = json!({
        "schema_version":1,
        "service_name":"drop",
        "rollback":{
            "target_version_id":target_version,
            "expected_current_deployment_id":current_deployment,
            "message":"restore known good",
            "traffic_percentage":100,
            "force":false,
        }
    });
    let settings = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"compatibility_date":"2026-08-25"}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let deployments = CloudflareResponseV1 {
        result: json!({"deployments":[
            {"id":current_deployment,"versions":[{"version_id":current_version,"percentage":100}]},
            {"id":prior_deployment,"versions":[{"version_id":target_version,"percentage":100}]}
        ]}),
        ..settings.clone()
    };
    let version = CloudflareResponseV1 {
        result: json!({"id":target_version,"metadata":{"created_on":"2026-08-24T00:00:00Z"}}),
        ..settings.clone()
    };
    let receipt = apply_rollback_state_responses(
        "account-a",
        "drop",
        &target,
        &settings,
        &deployments,
        &version,
    )
    .expect("exact rollback preflight");
    assert_eq!(receipt["current_deployment_id"], current_deployment);
    assert_eq!(receipt["current_version_id"], current_version);
    assert_eq!(receipt["target_version_id"], target_version);
    assert_eq!(receipt["target_prior_deployment_id"], prior_deployment);
    assert_eq!(receipt["force"], false);
    assert_eq!(receipt["traffic_percentage"], 100);

    let drifted_target = json!({
        "schema_version":1,
        "service_name":"drop",
        "rollback":{
            "target_version_id":target_version,
            "expected_current_deployment_id":"cccccccc-dddd-4eee-8fff-000000000000",
            "message":"restore known good",
            "traffic_percentage":100,
            "force":false,
        }
    });
    assert!(
        apply_rollback_state_responses(
            "account-a",
            "drop",
            &drifted_target,
            &settings,
            &deployments,
            &version,
        )
        .is_err()
    );
    let missing_history = CloudflareResponseV1 {
        result: json!({"deployments":[
            {"id":current_deployment,"versions":[{"version_id":current_version,"percentage":100}]},
            {"id":prior_deployment,"versions":[{"version_id":"dddddddd-eeee-4fff-8000-111111111111","percentage":100}]}
        ]}),
        ..settings.clone()
    };
    assert!(
        apply_rollback_state_responses(
            "account-a",
            "drop",
            &target,
            &settings,
            &missing_history,
            &version,
        )
        .is_err()
    );
    let split_prior = CloudflareResponseV1 {
        result: json!({"deployments":[
            {"id":current_deployment,"versions":[{"version_id":current_version,"percentage":100}]},
            {"id":prior_deployment,"versions":[
                {"version_id":target_version,"percentage":50},
                {"version_id":"dddddddd-eeee-4fff-8000-111111111111","percentage":50}
            ]}
        ]}),
        ..settings.clone()
    };
    assert!(
        apply_rollback_state_responses(
            "account-a",
            "drop",
            &target,
            &settings,
            &split_prior,
            &version,
        )
        .is_err()
    );
    let partial_prior = CloudflareResponseV1 {
        result: json!({"deployments":[
            {"id":current_deployment,"versions":[{"version_id":current_version,"percentage":100}]},
            {"id":prior_deployment,"versions":[{"version_id":target_version,"percentage":99}]}
        ]}),
        ..settings.clone()
    };
    assert!(
        apply_rollback_state_responses(
            "account-a",
            "drop",
            &target,
            &settings,
            &partial_prior,
            &version,
        )
        .is_err()
    );
    let undocumented_bare_array = CloudflareResponseV1 {
        result: deployments.result["deployments"].clone(),
        ..settings
    };
    assert!(
        apply_rollback_state_responses(
            "account-a",
            "drop",
            &target,
            &undocumented_bare_array,
            &undocumented_bare_array,
            &version,
        )
        .is_err()
    );
}
