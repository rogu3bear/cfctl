//! The real-tool fixture uses the existing subprocess seam, not a Wrangler mock.
use super::*;

#[cfg(target_os = "macos")]
mod real_wrangler {
    use super::*;
    use crate::runtime::{worker_deployment, worker_deployment_artifact};
    use cfctl_workspace::{RegisteredRoot, WorkspaceGraph};
    use sha2::Sha256;
    use std::{collections::BTreeMap, os::unix::fs::symlink};

    struct Fixture {
        root: tempfile::TempDir,
        repository: std::path::PathBuf,
        config: std::path::PathBuf,
        marker: std::path::PathBuf,
        output: std::path::PathBuf,
        multipart: std::path::PathBuf,
        observed_config: std::path::PathBuf,
        observed_assets: std::path::PathBuf,
        observed_runtime: std::path::PathBuf,
        producer_paths: std::path::PathBuf,
        real_stdout: std::path::PathBuf,
        real_stderr: std::path::PathBuf,
        staged_path_receipt: std::path::PathBuf,
        launcher: std::path::PathBuf,
        original: BTreeMap<std::path::PathBuf, Vec<u8>>,
    }

    fn quote(path: &Path) -> String {
        format!(
            "'{}'",
            path.to_str()
                .expect("UTF-8 fixture path")
                .replace('\'', "'\\''")
        )
    }

    fn executable(path: &Path, contents: &str) {
        fs::write(path, contents).expect("fixture executable");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .expect("fixture executable mode");
    }

    fn fixture() -> Fixture {
        fixture_with("", &[])
    }

    fn write_fixture_artifact(build: &Path, assets: &Path) {
        fs::write(
            build.join("index.js"),
            concat!(
                "import { WorkerEntrypoint } from 'cloudflare:workers';\n",
                "import wasm from './index_bg.wasm';\n",
                "export default class extends WorkerEntrypoint {\n",
                "  fetch() { return new Response(String(wasm instanceof WebAssembly.Module)); }\n",
                "}\n//# sourceMappingURL=index.js.map\n",
            ),
        )
        .expect("already-built JS module");
        fs::write(build.join("index_bg.wasm"), b"\0asm\x01\0\0\0")
            .expect("already-built Wasm module");
        fs::write(
            build.join("index.js.map"),
            r#"{"version":3,"file":"index.js","sources":[],"names":[],"mappings":""}"#,
        )
        .expect("bound source map");
        fs::write(build.join("package.json"), r#"{"type":"module"}"#)
            .expect("bound module metadata");
        fs::write(
            assets.join("index.html"),
            "<!doctype html><title>Frozen</title>",
        )
        .expect("first frozen asset");
        fs::write(assets.join("client.js"), "document.title = 'Frozen';\n")
            .expect("second frozen asset");
    }

    fn bind_fixture_source(repository: &Path) {
        for arguments in [
            vec!["init", "--quiet"],
            vec![
                "add",
                ".gitignore",
                "web/wrangler.toml",
                "build-sentinel.sh",
            ],
            vec![
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgSign=false",
                "-c",
                "core.hooksPath=/dev/null",
                "commit",
                "--quiet",
                "-m",
                "Bind fixture source",
            ],
        ] {
            assert!(
                std::process::Command::new("git")
                    .args(arguments)
                    .current_dir(repository)
                    .status()
                    .expect("fixture Git command")
                    .success()
            );
        }
    }

    fn write_fixture_transport(fixture: &Fixture, wrangler: &Path) {
        let private_home = fixture.root.path().join("home");
        fs::create_dir(&private_home).expect("isolated Wrangler home");
        let observer = fixture.root.path().join("observe-staged-input.cjs");
        fs::write(&observer, format!(
            "const fs=require('node:fs'),p=require('node:path');\n\
             const args=process.argv.slice(2), config=args[args.indexOf('--config')+1];\n\
             fs.writeFileSync({},config,{{mode:0o600}});\n\
             fs.writeFileSync({},JSON.stringify({{execPath:process.execPath}}),{{mode:0o600}});\n\
             fs.copyFileSync(config,{});\n\
             if(config.endsWith('.json')){{const c=JSON.parse(fs.readFileSync(config,'utf8'));\n\
             if(c.assets)fs.cpSync(p.resolve(p.dirname(config),c.assets.directory),{},{{recursive:true}});}}\n",
            serde_json::to_string(&fixture.staged_path_receipt).expect("JSON path"),
            serde_json::to_string(&fixture.observed_runtime).expect("JSON path"),
            serde_json::to_string(&fixture.observed_config).expect("JSON path"),
            serde_json::to_string(&fixture.observed_assets).expect("JSON path"),
        )).expect("local input observer");
        let node = which::which("node").expect("real Wrangler Node interpreter");
        fs::write(
            &fixture.producer_paths,
            format!("{}\n{}\n", node.display(), wrangler.display()),
        )
        .expect("ordinary transport producer paths");
        executable(
            &fixture.launcher,
            &format!(
                "#!/bin/sh\nset -eu\numask 077\nexport WRANGLER_SEND_METRICS=false\nexport HOME={}\nexport XDG_CONFIG_HOME={}\n\
             exec 3< {}\nIFS= read -r node <&3\nIFS= read -r wrangler <&3\nexec 3<&-\n\
             \"$node\" {} \"$@\"\n\
             status=0\n/usr/bin/sandbox-exec -p '(version 1)(allow default)(deny network*)' \
             \"$node\" \"$wrangler\" \"$@\" --dry-run --outdir {} --outfile {} > {} 2> {} || status=$?\n\
             /bin/cat {}\n/bin/cat {} >&2\nexit \"$status\"\n",
                quote(&private_home),
                quote(&private_home),
                quote(&fixture.producer_paths),
                quote(&observer),
                quote(&fixture.output),
                quote(&fixture.multipart),
                quote(&fixture.real_stdout),
                quote(&fixture.real_stderr),
                quote(&fixture.real_stdout),
                quote(&fixture.real_stderr),
            ),
        );
    }

    fn write_fixture_config(config: &Path, config_suffix: &str) {
        fs::write(
            config,
            concat!(
                "name = \"frozen-upload-fixture\"\nmain = \"build/index.js\"\n",
                "compatibility_date = \"2026-06-29\"\ncompatibility_flags = [\"nodejs_compat\"]\n",
                "upload_source_maps = true\nworkers_dev = false\n",
                "[vars]\nPUBLIC_SITE_URL = \"https://fixture.invalid\"\n",
                "[assets]\ndirectory = \"./target/site\"\nbinding = \"ASSETS\"\n",
                "[[d1_databases]]\nbinding = \"DB\"\ndatabase_name = \"fixture\"\n",
                "database_id = \"11111111-2222-4333-8444-555555555555\"\n",
                "[[r2_buckets]]\nbinding = \"BUCKET\"\nbucket_name = \"fixture-bucket\"\n",
                "[[routes]]\npattern = \"fixture.invalid\"\ncustom_domain = true\n",
                "[triggers]\ncrons = [\"17 * * * *\"]\n",
                "[build]\ncommand = \"../build-sentinel.sh\"\n",
            ),
        )
        .expect("canonical config with a real custom build hook");
        let mut config_bytes = fs::read(config).expect("fixture config");
        config_bytes.extend_from_slice(config_suffix.as_bytes());
        fs::write(config, config_bytes).expect("extended fixture config");
    }

    fn fixture_with(config_suffix: &str, additional_files: &[(&str, &[u8])]) -> Fixture {
        let wrangler = which::which("wrangler")
            .expect("real Wrangler is required; a missing producer is not a passed test");
        assert!(
            Path::new("/usr/bin/sandbox-exec").is_file(),
            "network-denial tool required"
        );
        let root = tempfile::tempdir().expect("real Wrangler fixture root");
        let repository = fs::canonicalize(root.path())
            .expect("canonical fixture root")
            .join("source");
        let web = repository.join("web");
        let build = web.join("build");
        let assets = web.join("target/site");
        fs::create_dir_all(&build).expect("built Worker directory");
        fs::create_dir_all(&assets).expect("asset directory");
        let marker = root.path().join("custom-build-invoked");
        let hook = repository.join("build-sentinel.sh");
        executable(
            &hook,
            &format!("#!/bin/sh\nprintf invoked > {}\nexit 73\n", quote(&marker)),
        );
        let config = web.join("wrangler.toml");
        write_fixture_config(&config, config_suffix);
        write_fixture_artifact(&build, &assets);
        fs::write(
            repository.join(".gitignore"),
            "/web/build/\n/web/target/\n/web/.wrangler/\n",
        )
        .expect("generated artifact exclusions");
        for (relative, bytes) in additional_files {
            let path = build.join(relative);
            fs::create_dir_all(path.parent().expect("extra artifact parent"))
                .expect("extra artifact directory");
            fs::write(path, bytes).expect("extra built module");
        }
        bind_fixture_source(&repository);
        let output = root.path().join("actual-wrangler-output");
        let multipart = root.path().join("actual-wrangler-form.bin");
        let observed_config = root.path().join("observed-config");
        let observed_assets = root.path().join("observed-assets");
        let observed_runtime = root.path().join("observed-runtime.json");
        let producer_paths = root.path().join("producer-paths");
        let real_stdout = root.path().join("real-wrangler.stdout");
        let real_stderr = root.path().join("real-wrangler.stderr");
        let staged_path_receipt = root.path().join("staged-config-path");
        let launcher = root.path().join("wrangler-local-only.sh");
        let original = [
            config.clone(),
            hook,
            build.join("index.js"),
            build.join("index_bg.wasm"),
            build.join("index.js.map"),
            build.join("package.json"),
            assets.join("index.html"),
            assets.join("client.js"),
        ]
        .into_iter()
        .chain(
            additional_files
                .iter()
                .map(|(relative, _)| build.join(relative)),
        )
        .map(|path| {
            let bytes = fs::read(&path).expect("original fixture bytes");
            (path, bytes)
        })
        .collect();
        let fixture = Fixture {
            root,
            repository,
            config,
            marker,
            output,
            multipart,
            observed_config,
            observed_assets,
            observed_runtime,
            producer_paths,
            real_stdout,
            real_stderr,
            staged_path_receipt,
            launcher,
            original,
        };
        write_fixture_transport(&fixture, &wrangler);
        fixture
    }

    fn admission_input(fixture: &Fixture) -> (CapabilityV1, WorkspaceGraph, CallInput) {
        let mut capability = CapabilityV1::new(
            "wrangler.versions-upload",
            "Worker upload",
            "CLI",
            "wrangler versions upload",
        );
        capability.adapter_status = AdapterStatus::DelegatedCli;
        capability.source = "wrangler 4.107.0 versions upload help".to_owned();
        let sha = StdCommand::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&fixture.repository)
            .output()
            .expect("fixture Git identity");
        assert!(sha.status.success());
        let sha = String::from_utf8(sha.stdout)
            .expect("source SHA")
            .trim()
            .to_owned();
        let artifact_sha = worker_deployment_artifact::artifact_set_sha256(
            &fixture.repository,
            &[
                fixture.repository.join("web/build"),
                fixture.repository.join("web/target/site"),
            ],
        )
        .expect("release artifact digest");
        let input = CallInput {
            selectors: json!({}),
            query: json!({
                "config": fixture.config,
                "name": "frozen-upload-fixture",
                "message": format!("source={sha} artifact-sha256={artifact_sha}"),
                "artifact_mode": "frozen-artifact",
            }),
            ..CallInput::default()
        };
        let graph = WorkspaceGraph::discover(&[RegisteredRoot::new(&fixture.repository)])
            .expect("registered fixture graph");
        (capability, graph, input)
    }

    fn admitted(fixture: &Fixture) -> (PlanV1, CallInput) {
        admitted_with_selectors(fixture, json!({}))
    }

    fn admitted_with_selectors(fixture: &Fixture, selectors: Value) -> (PlanV1, CallInput) {
        let (capability, graph, mut input) = admission_input(fixture);
        input.selectors = selectors;
        let target = worker_deployment::prepare_target(&graph, &capability, &input)
            .expect("actual immutable frozen admission")
            .expect("Worker target");
        let mut plan = PlanV1::draft(
            "local-fixture",
            "00000000000000000000000000000000",
            "sha256:local-fixture-catalog",
            capability,
            json!({"adapter": {"worker_deployment": target}}),
        )
        .expect("immutable plan");
        plan.input = serde_json::to_value(&input).expect("bound original input");
        plan.refresh_hash().expect("bind complete admission");
        (plan, input)
    }

    fn credential() -> AuthCredential {
        AuthCredential::Bearer {
            token: "local-test-token-not-a-credential".to_owned(),
        }
    }

    async fn execute(fixture: &Fixture, plan: &PlanV1, input: &CallInput) -> Result<Value> {
        if let Some(producer) = plan
            .targets
            .pointer("/adapter/worker_deployment/frozen_artifact/producer")
        {
            fs::write(
                &fixture.producer_paths,
                format!(
                    "{}\n{}\n",
                    producer["interpreter"]["path"]
                        .as_str()
                        .expect("bound runtime path"),
                    producer["executable"]
                        .as_str()
                        .expect("bound Wrangler path")
                ),
            )
            .expect("real transport uses the admitted producer, including its interpreter");
        }
        let store = StateStore::open(RuntimePaths::from_root(&fixture.root.path().join("state")))
            .expect("local fixture store");
        FROZEN_TRANSPORT_TEST_LAUNCHER
            .scope(
                fixture.launcher.clone(),
                run_delegated_plan_boundary(&store, plan, input, &credential()),
            )
            .await
    }

    async fn run(frozen: bool) -> (Fixture, Value, Option<PlanV1>) {
        let fixture = fixture();
        let (result, plan) = if frozen {
            let (plan, input) = admitted(&fixture);
            let result = execute(&fixture, &plan, &input)
                .await
                .expect("real Wrangler local execution receipt");
            (result, Some(plan))
        } else {
            let mut capability = CapabilityV1::new(
                "wrangler.versions-upload",
                "Worker upload",
                "CLI",
                "wrangler versions upload",
            );
            capability.adapter_status = AdapterStatus::DelegatedCli;
            let input = CallInput {
                selectors: json!({}),
                query: json!({"config": fixture.config,
                "name": "frozen-upload-fixture", "message": "local ordinary-build control"}),
                ..CallInput::default()
            };
            let result = run_delegated_cli_with_timeout(
                &capability,
                &input,
                &credential(),
                Some("00000000000000000000000000000000"),
                fixture.root.path(),
                Some(&fixture.launcher),
                None,
                Duration::from_mins(1),
            )
            .await
            .expect("ordinary control receipt");
            (result, None)
        };
        for (path, expected) in &fixture.original {
            assert_eq!(
                &fs::read(path).expect("preserved original input"),
                expected,
                "original input changed: {}",
                path.display()
            );
        }
        assert!(fixture.repository.is_dir());
        (fixture, result, plan)
    }

    fn multipart_parts(bytes: &[u8]) -> BTreeMap<String, (String, Vec<u8>)> {
        let first_line = bytes
            .windows(2)
            .position(|pair| pair == b"\r\n")
            .expect("multipart boundary");
        let delimiter = &bytes[..first_line];
        let positions = bytes
            .windows(delimiter.len())
            .enumerate()
            .filter_map(|(index, window)| (window == delimiter).then_some(index))
            .collect::<Vec<_>>();
        let mut parts = BTreeMap::new();
        for pair in positions.windows(2) {
            let part = &bytes[pair[0] + delimiter.len() + 2..pair[1] - 2];
            let split = part
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .expect("multipart headers");
            let headers = std::str::from_utf8(&part[..split]).expect("header text");
            let name = headers
                .split("name=\"")
                .nth(1)
                .expect("part name")
                .split('"')
                .next()
                .expect("name end");
            let content_type = headers
                .lines()
                .find_map(|line| line.strip_prefix("Content-Type: "))
                .unwrap_or("")
                .trim()
                .to_owned();
            assert!(
                parts
                    .insert(name.to_owned(), (content_type, part[split + 4..].to_vec()))
                    .is_none(),
                "duplicate multipart part"
            );
        }
        parts
    }

    fn assert_frozen_payload(fixture: &Fixture, plan: &PlanV1, receipt: &Value) {
        assert!(
            !fixture.marker.exists(),
            "frozen-artifact invoked the configured custom build hook"
        );
        assert_eq!(
            receipt["exit_status"],
            0,
            "real local transport failed: {receipt}; synthetic-fixture diagnostics: {} {}",
            fs::read_to_string(&fixture.real_stdout).unwrap_or_default(),
            fs::read_to_string(&fixture.real_stderr).unwrap_or_default()
        );
        // A dry run intentionally has no provider version UUID. It must not
        // manufacture an upload success or silently skip that production check.
        assert_eq!(receipt["success"], false);
        assert!(
            receipt["structured_output_error"]
                .as_str()
                .expect("missing local-only UUID disposition")
                .contains("required typed version identity")
        );
        assert_eq!(receipt["stdout"], "");
        assert_eq!(receipt["stderr"], "");
        let target = &plan.targets["adapter"]["worker_deployment"]["frozen_artifact"];
        let runtime: Value = serde_json::from_slice(
            &fs::read(&fixture.observed_runtime).expect("actual runtime observation"),
        )
        .expect("runtime JSON");
        assert_eq!(
            runtime["execPath"], target["producer"]["interpreter"]["path"],
            "real local transport must use the admitted interpreter, not rediscover an ambient shim"
        );
        let executable = Path::new(runtime["execPath"].as_str().expect("runtime path"));
        assert_eq!(
            hex::encode(Sha256::digest(
                fs::read(executable).expect("actual runtime bytes")
            )),
            target["producer"]["interpreter"]["sha256"]
        );
        let multipart = multipart_parts(
            &fs::read(&fixture.multipart).expect("actual Wrangler multipart bytes"),
        );
        let expected_parts = target["module_graph"]["modules"]
            .as_array()
            .expect("selected module identities")
            .iter()
            .chain(
                target["module_graph"]["source_maps"]
                    .as_array()
                    .expect("source map identities"),
            );
        let mut names = vec!["metadata".to_owned()];
        for module in expected_parts {
            let name = module["name"].as_str().expect("module name");
            names.push(name.to_owned());
            let (content_type, bytes) = multipart
                .get(name)
                .expect("Wrangler emitted the admitted module");
            assert_eq!(
                hex::encode(Sha256::digest(bytes)),
                module["sha256"].as_str().expect("module digest")
            );
            assert_eq!(
                bytes.len() as u64,
                module["size"].as_u64().expect("module byte size")
            );
            let expected_type = match module["type"].as_str().expect("module type") {
                "esm" => "application/javascript+module",
                "commonjs" => "application/javascript",
                "compiled-wasm" => "application/wasm",
                "buffer" => "application/octet-stream",
                "text" => "text/plain",
                "source-map" => "application/source-map",
                other => panic!("unexpected module type {other}"),
            };
            assert_eq!(content_type, expected_type);
        }
        names.sort();
        assert_eq!(multipart.keys().cloned().collect::<Vec<_>>(), names);
        assert_eq!(
            fs::read(fixture.output.join("index.js")).expect("real emitted entrypoint"),
            fixture.original[&fixture.repository.join("web/build/index.js")]
        );
        let observed: Value = serde_json::from_slice(
            &fs::read(&fixture.observed_config).expect("actual config argument bytes"),
        )
        .expect("projected JSON");
        assert!(observed["build"].get("command").is_none());
        assert_eq!(observed["no_bundle"], true);
        assert_eq!(observed["compatibility_flags"], json!(["nodejs_compat"]));
        assert_eq!(observed["triggers"]["crons"], json!(["17 * * * *"]));
        assert_eq!(observed["routes"][0]["custom_domain"], true);
        assert_eq!(observed["d1_databases"][0]["binding"], "DB");
        assert_eq!(observed["r2_buckets"][0]["binding"], "BUCKET");
        for relative in ["index.html", "client.js"] {
            assert_eq!(
                fs::read(fixture.observed_assets.join(relative))
                    .expect("asset bytes at actual config argument"),
                fixture.original[&fixture.repository.join("web/target/site").join(relative)]
            );
        }
        assert_stage_removed(fixture);
    }

    fn assert_stage_removed(fixture: &Fixture) {
        let staged =
            fs::read_to_string(&fixture.staged_path_receipt).expect("staged path observation");
        assert!(staged.starts_with("/private/") || !std::env::temp_dir().starts_with("/var/"));
        let stage_root = Path::new(&staged)
            .parent()
            .expect("payload")
            .parent()
            .expect("stage root");
        assert!(
            !stage_root.exists(),
            "completed or cancelled process left its private stage behind"
        );
    }

    #[tokio::test]
    #[ignore = "requires real Wrangler and macOS network denial; run explicitly for frozen-upload qualification"]
    async fn frozen_worker_upload_real_transport_never_invokes_custom_build() {
        let (fixture, receipt, plan) = run(true).await;
        assert_frozen_payload(&fixture, &plan.expect("immutable admission"), &receipt);
    }

    #[tokio::test]
    #[ignore = "requires real Wrangler and macOS network denial; run explicitly for frozen-upload qualification"]
    async fn frozen_worker_upload_real_transport_preserves_default_build_behavior() {
        let (fixture, receipt, _) = run(false).await;
        assert!(
            fixture.marker.is_file(),
            "default mode no longer executes the configured build"
        );
        assert_eq!(
            receipt["success"], false,
            "sentinel exit 73 must fail the default upload"
        );
    }

    #[tokio::test]
    #[ignore = "requires real Wrangler and macOS network denial; run explicitly for frozen-upload qualification"]
    async fn frozen_worker_upload_real_transport_preserves_configured_module_rules_and_names() {
        let fixture = fixture_with(concat!(
            "[[rules]]\ntype = \"ESModule\"\nglobs = [\"**/*.js\"]\n",
            "[[rules]]\ntype = \"Text\"\nglobs = [\"extras/*.data\"]\nfallthrough = true\n",
        ), &[
            ("index.js", concat!(
                "import helper from './helper.js';\nimport text from './extras/message.data';\n",
                "import wasm from './index_bg.wasm';\n",
                "export default { fetch() { return new Response(helper(text, wasm)); } };\n",
                "//# sourceMappingURL=index.js.map\n",
            ).as_bytes()),
            ("helper.js", b"export default (text, wasm) => text + String(wasm instanceof WebAssembly.Module);\n"),
            ("extras/message.data", b"frozen custom-rule text\n"),
            ("default.txt", b"default rule retained by fallthrough\n"),
                ("bytes.bin", b"\x00\x01\xff"),
                ("index.js.map", br#"{"version":3,"file":"old.js","sourceRoot":"../src","sources":["../../entry.ts"],"sourcesContent":["export default {};"],"names":[],"mappings":""}"#),
        ]);
        // CallInput::default uses null for absent selectors. Admission treats
        // this as the same empty selector set as the CLI's explicit object.
        let (plan, input) = admitted_with_selectors(&fixture, Value::Null);
        let receipt = execute(&fixture, &plan, &input)
            .await
            .expect("real configured-rule transport");
        assert_frozen_payload(&fixture, &plan, &receipt);
        let modules = plan
            .targets
            .pointer("/adapter/worker_deployment/frozen_artifact/module_graph/modules")
            .and_then(Value::as_array)
            .expect("admitted modules");
        let names = modules
            .iter()
            .map(|module| module["name"].as_str().expect("module name"))
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            [
                "bytes.bin",
                "default.txt",
                "extras/message.data",
                "helper.js",
                "index.js",
                "index_bg.wasm"
            ]
        );
    }

    async fn assert_rejected_before_launch(fixture: &Fixture, plan: &PlanV1, input: &CallInput) {
        let error = execute(fixture, plan, input)
            .await
            .expect_err("drift must reject before transport");
        assert!(!error.to_string().contains("PRIVATE-DRIFT-VALUE"));
        assert!(
            !fixture.staged_path_receipt.exists(),
            "rejected input reached the process launcher"
        );
        assert!(
            !fixture.marker.exists(),
            "rejected input reached the custom build hook"
        );
    }

    #[tokio::test]
    #[ignore = "requires bound real Wrangler admission; run explicitly for frozen-upload qualification"]
    async fn frozen_worker_upload_immutable_boundary_rejects_source_artifact_and_input_drift() {
        if let Some(selection) = std::env::var_os("CFCTL_TEST_FROZEN_NODE_SELECTION") {
            owned_interpreter_drift_child(Path::new(&selection)).await;
            return;
        }
        let fixture = fixture();
        let (plan, input) = admitted(&fixture);
        for path in [
            &fixture.config,
            &fixture.repository.join("web/build/index.js"),
        ] {
            let original = fs::read(path).expect("original admitted bytes");
            let mut changed = original.clone();
            changed.extend_from_slice(b"\n// PRIVATE-DRIFT-VALUE\n");
            fs::write(path, changed).expect("owned source drift");
            assert_rejected_before_launch(&fixture, &plan, &input).await;
            fs::write(path, original).expect("restore exact fixture bytes");
        }
        for relative in ["web/build/added.txt", "web/target/site/.env"] {
            let added = fixture.repository.join(relative);
            fs::write(&added, "PRIVATE-DRIFT-VALUE").expect("extra artifact fixture");
            assert_rejected_before_launch(&fixture, &plan, &input).await;
            fs::remove_file(added).expect("remove owned drift");
        }
        let removed = fixture.repository.join("web/build/index.js.map");
        let original = fs::read(&removed).expect("bound source map");
        fs::remove_file(&removed).expect("owned removal drift");
        assert_rejected_before_launch(&fixture, &plan, &input).await;
        fs::write(&removed, original).expect("restore admitted source map");
        let build = fixture.repository.join("web/build");
        let detached = fixture.root.path().join("detached-build");
        fs::rename(&build, &detached).expect("owned ancestor rebinding fixture");
        symlink(&detached, &build).expect("rebound artifact root");
        assert_rejected_before_launch(&fixture, &plan, &input).await;
        fs::remove_file(&build).expect("remove owned alias");
        fs::rename(&detached, &build).expect("restore original root");
        for (key, value) in [
            ("name", json!("another-worker")),
            ("message", json!("another-version")),
            ("main", json!("PRIVATE-DRIFT-VALUE")),
            ("artifact_mode", json!("frozen")),
        ] {
            let mut changed = input.clone();
            changed.query[key] = value;
            assert_rejected_before_launch(&fixture, &plan, &changed).await;
        }
        let mut downgraded = input.clone();
        downgraded
            .query
            .as_object_mut()
            .expect("query")
            .remove("artifact_mode");
        assert_rejected_before_launch(&fixture, &plan, &downgraded).await;
        for mutation in ["absent", "schema", "producer"] {
            let mut changed = plan.clone();
            let target = &mut changed.targets["adapter"]["worker_deployment"];
            match mutation {
                "absent" => {
                    target
                        .as_object_mut()
                        .expect("target")
                        .remove("frozen_artifact");
                }
                "schema" => target["frozen_artifact"]["schema_version"] = json!(2),
                _ => {
                    target["frozen_artifact"]["producer"]["version"] = json!("unadmitted-producer");
                }
            }
            assert_rejected_before_launch(&fixture, &changed, &input).await;
        }
        assert!(
            StdCommand::new("git")
                .args([
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                    "-c",
                    "commit.gpgSign=false",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "commit",
                    "--quiet",
                    "--allow-empty",
                    "-m",
                    "Advance source identity",
                ])
                .current_dir(&fixture.repository)
                .status()
                .expect("owned source advance")
                .success()
        );
        assert_rejected_before_launch(&fixture, &plan, &input).await;
        prove_owned_interpreter_drift(&fixture, &plan).await;
    }

    async fn owned_interpreter_drift_child(selection: &Path) {
        let first = fs::read_to_string(selection).expect("first selected runtime");
        let first = Path::new(first.trim());
        let second =
            std::env::var_os("CFCTL_TEST_FROZEN_NODE_SECOND").expect("second owned runtime");
        let second = Path::new(&second);
        let fixture = fixture();
        let (plan, input) = admitted(&fixture);
        assert_eq!(
            plan.targets
                .pointer("/adapter/worker_deployment/frozen_artifact/producer/interpreter/path")
                .and_then(Value::as_str),
            first.to_str(),
            "admission must resolve the shim to its real selected runtime"
        );
        // Keep the immutable plan, source and artifacts unchanged while the
        // isolated shim actually selects another complete Node executable.
        fs::write(selection, format!("{}\n", second.display()))
            .expect("owned runtime selection drift");
        let error = execute(&fixture, &plan, &input)
            .await
            .expect_err("changed interpreter selection must reject");
        assert!(
            error.to_string().contains("dependency closure drifted"),
            "unexpected producer disposition: {error}"
        );
        assert!(!fixture.staged_path_receipt.exists());
        // Restore that selection, then change only the owned executable's
        // bytes. No installed interpreter or global PATH is modified.
        fs::write(selection, format!("{}\n", first.display())).expect("restore selected path");
        fs::write(first, b"invalid-owned-runtime\n").expect("owned executable-byte drift");
        let error = execute(&fixture, &plan, &input)
            .await
            .expect_err("changed executable bytes must reject");
        assert!(
            error.to_string().contains("producer discovery"),
            "unexpected producer disposition: {error}"
        );
        assert!(!fixture.staged_path_receipt.exists());
        assert!(!fixture.marker.exists());
    }

    async fn prove_owned_interpreter_drift(fixture: &Fixture, plan: &PlanV1) {
        let bin = fs::canonicalize(fixture.root.path())
            .expect("owned runtime fixture root")
            .join("runtime-drift");
        fs::create_dir(&bin).expect("private runtime fixture directory");
        let original = Path::new(
            plan.targets
                .pointer("/adapter/worker_deployment/frozen_artifact/producer/interpreter/path")
                .and_then(Value::as_str)
                .expect("admitted actual Node path"),
        );
        let first = bin.join("node-first");
        let second = bin.join("node-second");
        for copy in [&first, &second] {
            fs::copy(original, copy).expect("copy actual Node into the owned drift fixture");
            fs::set_permissions(copy, fs::Permissions::from_mode(0o700))
                .expect("owned runtime mode");
        }
        let selection = bin.join("selected-runtime");
        fs::write(&selection, format!("{}\n", first.display())).expect("initial runtime selection");
        let manager = bin.join("mise");
        executable(
            &manager,
            &format!(
                "#!/bin/sh\nset -eu\nIFS= read -r selected < {}\n\
             if [ \"${{0##*/}}\" = node ]; then exec \"$selected\" \"$@\"; fi\n\
             [ \"$#\" -eq 2 ] && [ \"$1\" = which ] && [ \"$2\" = node ] || exit 77\n\
             [ \"$MISE_AUTO_INSTALL\" = false ] && [ \"$MISE_OFFLINE\" = true ] || exit 78\n\
             [ \"$MISE_NO_HOOKS\" = true ] && [ \"$MISE_NO_ENV\" = true ] || exit 79\n\
             printf '%s\\n' \"$selected\"\n",
                quote(&selection)
            ),
        );
        symlink(&manager, bin.join("node")).expect("argv0-dispatched Node shim");
        let mut paths = vec![bin];
        paths.extend(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_default(),
        ));
        let path = std::env::join_paths(paths).expect("isolated child PATH");
        let output = processkit::Command::new("/usr/bin/sandbox-exec")
            .args(["-p", "(version 1)(allow default)(deny network*)"])
            .arg(std::env::current_exe().expect("current native test executable"))
            .args(["--ignored", "--exact", "runtime::tests::worker_frozen_upload::real_wrangler::frozen_worker_upload_immutable_boundary_rejects_source_artifact_and_input_drift", "--test-threads=1", "--nocapture"])
            .env_clear().env("PATH", path).env("HOME", fixture.root.path())
            .env("CFCTL_TEST_FROZEN_NODE_SELECTION", &selection)
            .env("CFCTL_TEST_FROZEN_NODE_SECOND", &second)
            .timeout(Duration::from_mins(2))
            .start().await.expect("isolated native drift proof started")
            .output_bytes().await.expect("isolated native drift proof receipt");
        assert!(
            output.is_success(),
            "isolated runtime drift proof failed: {} {}",
            String::from_utf8_lossy(output.stdout()),
            output.stderr()
        );
        assert!(
            String::from_utf8_lossy(output.stdout()).contains("1 passed; 0 failed; 0 ignored"),
            "the isolated native child must execute its exact selected case"
        );
    }

    #[test]
    #[ignore = "requires bound real Wrangler parser; run explicitly for frozen-upload qualification"]
    fn frozen_worker_upload_admission_rejects_unclosed_imports_and_source_maps() {
        for source in [
            "import x from '../../unadmitted.js'; export default x;",
            "import x from 'unadmitted-package'; export default x;",
            "const name = globalThis.name; export default import(name);",
            "const name = globalThis.name; export default require(name);",
            "export default {};\n//# sourceMappingURL=https://fixture.invalid/external.map\n",
        ] {
            let fixture = fixture_with("", &[("index.js", source.as_bytes())]);
            let (capability, graph, input) = admission_input(&fixture);
            let error = worker_deployment::prepare_target(&graph, &capability, &input)
                .expect_err("unclosed module graph was admitted");
            assert!(
                error
                    .to_string()
                    .contains("module imports or source maps are not closed"),
                "fixture or producer failure cannot count as a module rejection: {error}"
            );
            assert!(!fixture.marker.exists());
        }
        for map in [
            r#"{"version":3,"sources":["../outside.ts"],"names":[],"mappings":""}"#,
            r#"{"version":3,"sources":[],"sections":[{"url":"https://fixture.invalid/map"}]}"#,
        ] {
            let fixture = fixture_with("", &[("index.js.map", map.as_bytes())]);
            let (capability, graph, input) = admission_input(&fixture);
            let error = worker_deployment::prepare_target(&graph, &capability, &input)
                .expect_err("unclosed source map was admitted");
            assert!(
                error
                    .to_string()
                    .contains("module imports or source maps are not closed"),
                "fixture or producer failure cannot count as a map rejection: {error}"
            );
            assert!(!fixture.marker.exists());
        }
    }

    fn control_launcher(fixture: &Fixture, wait: bool) -> std::path::PathBuf {
        let pids = fixture.root.path().join("process-ids");
        let script = format!(
            "#!/bin/sh\nset -eu\numask 077\n\
             while [ \"$#\" -gt 0 ]; do\n\
             if [ \"$1\" = --config ]; then shift; printf '%s' \"$1\" > {}; break; fi\nshift\ndone\n{}\n",
            quote(&fixture.staged_path_receipt),
            if wait {
                format!(
                    "/bin/sleep 30 &\nprintf '%s %s\\n' \"$$\" \"$!\" > {}\nwait",
                    quote(&pids)
                )
            } else {
                "printf PRIVATE-PROCESS-OUTPUT\nprintf PRIVATE-PROCESS-ERROR >&2\nexit 29"
                    .to_owned()
            },
        );
        executable(&fixture.launcher, &script);
        pids
    }

    async fn wait_for_process_ids(path: &Path) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while !path.is_file() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "transport did not record its process tree"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn assert_processes_removed(path: &Path) {
        for value in fs::read_to_string(path)
            .expect("process identity receipt")
            .split_whitespace()
        {
            let pid = rustix::process::Pid::from_raw(value.parse().expect("fixture PID"))
                .expect("positive PID");
            let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
            while rustix::process::test_kill_process(pid).is_ok() {
                if tokio::time::Instant::now() >= deadline {
                    let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
                    panic!("completed transport left process {value} alive");
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }

    #[tokio::test]
    #[ignore = "requires bound real Wrangler admission; run explicitly for frozen-upload qualification"]
    async fn frozen_worker_upload_boundary_removes_private_stage_on_failure_timeout_and_cancellation()
     {
        let fixture = fixture();
        let (plan, input) = admitted(&fixture);
        fs::set_permissions(&fixture.launcher, fs::Permissions::from_mode(0o600))
            .expect("non-executable launch fixture");
        let error = FROZEN_TRANSPORT_TEST_STAGE_RECEIPT
            .scope(
                fixture.staged_path_receipt.clone(),
                execute(&fixture, &plan, &input),
            )
            .await
            .expect_err("spawn failure must return without leaking the private stage");
        assert!(matches!(error, CliError::SubprocessNotStarted { .. }));
        assert_stage_removed(&fixture);
        control_launcher(&fixture, false);
        let receipt = execute(&fixture, &plan, &input)
            .await
            .expect("failing process receipt");
        assert_eq!(receipt["exit_status"], 29);
        assert_eq!(receipt["success"], false);
        assert_eq!(receipt["stdout"], "");
        assert_eq!(receipt["stderr"], "");
        assert!(!receipt.to_string().contains("PRIVATE-PROCESS"));
        assert_stage_removed(&fixture);
        let pids = control_launcher(&fixture, true);
        let error = FROZEN_TRANSPORT_TEST_TIMEOUT
            .scope(Duration::from_secs(2), execute(&fixture, &plan, &input))
            .await
            .expect_err("owned transport times out");
        assert!(matches!(error, CliError::SubprocessTimeout { .. }));
        assert_stage_removed(&fixture);
        assert_processes_removed(&pids).await;
        fs::remove_file(&pids).expect("remove completed process receipt");
        {
            let execution = execute(&fixture, &plan, &input);
            tokio::pin!(execution);
            tokio::select! {
                result = &mut execution => panic!("cancellation probe ended early: {result:?}"),
                () = wait_for_process_ids(&pids) => {},
            }
            // Dropping the actual boundary future cancels its owned process.
        }
        assert_stage_removed(&fixture);
        assert_processes_removed(&pids).await;
        assert!(!fixture.marker.exists());
    }
}
