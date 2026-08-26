#![allow(clippy::wildcard_imports, reason = "white-box domain tests")]

use super::*;
use cfctl_core::AdapterStatus;

fn direct_upload() -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        DIRECT_UPLOAD_CAPABILITY_ID,
        "deploy Pages artifact",
        "POST",
        "wrangler pages deploy",
    );
    capability.method = "CLI".to_owned();
    capability.adapter_status = AdapterStatus::DelegatedCli;
    capability
}

#[test]
fn manifest_binds_path_size_hash_and_rejects_wrangler_omissions() {
    let root = tempfile::tempdir().expect("artifact");
    fs::write(root.path().join("index.html"), b"hello").expect("asset");
    fs::write(root.path().join("_headers"), b"/*\n  X-Test: yes\n").expect("control");
    let value = manifest(root.path()).expect("manifest");
    assert_eq!(value["asset_count"], 1);
    assert_eq!(value["entry_count"], 2);
    assert_eq!(value["entries"][0]["path"], "_headers");
    assert_eq!(value["entries"][0]["role"], "multipart_control");
    assert_eq!(value["entries"][1]["path"], "index.html");
    assert_eq!(value["entries"][1]["size"], 5);
    assert_eq!(
        value["entries"][1]["sha256"],
        hex::encode(Sha256::digest(b"hello"))
    );

    fs::create_dir(root.path().join("node_modules")).expect("ignored dir");
    fs::write(root.path().join("node_modules/hidden.js"), b"hidden").expect("ignored file");
    assert!(manifest(root.path()).is_err());
}

#[test]
fn manifest_changes_with_content_and_rejects_nested_symlinks() {
    let root = tempfile::tempdir().expect("artifact");
    let asset = root.path().join("index.html");
    fs::write(&asset, b"first").expect("first asset");
    let first = manifest(root.path()).expect("first manifest");
    fs::write(&asset, b"second-version").expect("changed asset");
    let second = manifest(root.path()).expect("second manifest");
    assert_ne!(first["content_hash"], second["content_hash"]);
    assert_ne!(first["entries"][0]["size"], second["entries"][0]["size"]);
    assert_ne!(
        first["entries"][0]["sha256"],
        second["entries"][0]["sha256"]
    );

    #[cfg(unix)]
    {
        let alias = root.path().join("alias.html");
        std::os::unix::fs::symlink(&asset, &alias).expect("nested symlink");
        assert!(manifest(root.path()).is_err());
    }
}

#[test]
fn worker_metafile_accepts_only_hash_bound_artifact_inputs() {
    let parent = tempfile::tempdir().expect("worker project");
    let artifact = parent.path().join("dist");
    fs::create_dir(&artifact).expect("artifact root");
    fs::write(
        artifact.join("_worker.js"),
        b"import './worker-support.js'; export default {};",
    )
    .expect("worker");
    fs::write(
        artifact.join("worker-support.js"),
        b"export const ok = true;",
    )
    .expect("support");
    fs::write(artifact.join("index.html"), b"ok").expect("asset");
    let admitted = manifest(&artifact).expect("admitted manifest");
    let local = json!({
        "inputs": {
            "_worker.js": {"bytes": 51, "imports": []},
            "worker-support.js": {"bytes": 23, "imports": []}
        },
        "outputs": {
            "/tmp/bundle.js": {"imports": []}
        }
    });
    let bound =
        validate_worker_metafile(&artifact, &admitted, &local).expect("closed local worker graph");
    assert_eq!(bound.as_array().expect("inputs").len(), 2);

    let external = parent.path().join("node_modules/some-package");
    fs::create_dir_all(&external).expect("ambient package");
    fs::write(external.join("index.js"), b"export default 'drift';").expect("ambient input");
    let escaped = json!({
        "inputs": {
            "_worker.js": {"bytes": 51, "imports": []},
            "../node_modules/some-package/index.js": {"bytes": 23, "imports": []}
        },
        "outputs": {
            "/tmp/bundle.js": {"imports": []}
        }
    });
    let error = validate_worker_metafile(&artifact, &admitted, &escaped)
        .expect_err("ancestor dependency must fail closed");
    assert!(
        error
            .to_string()
            .contains("outside the admitted artifact root")
    );

    let unresolved = json!({
        "inputs": {"_worker.js": {"bytes": 51, "imports": []}},
        "outputs": {
            "/tmp/bundle.js": {"imports": [{"path":"some-package","external":true}]}
        }
    });
    assert!(validate_worker_metafile(&artifact, &admitted, &unresolved).is_err());
}

#[cfg(unix)]
#[test]
fn staged_worker_is_the_planned_closed_bundle() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().expect("worker artifact");
    let artifact_root = root.path().join("site");
    fs::create_dir(&artifact_root).expect("artifact root");
    fs::write(
        artifact_root.join("_worker.js"),
        b"import './worker-support.js'; export default {};",
    )
    .expect("worker");
    fs::write(
        artifact_root.join("worker-support.js"),
        b"export const ok = true;",
    )
    .expect("support");
    fs::write(artifact_root.join("index.html"), b"ok").expect("asset");
    let artifact_root = artifact_root.canonicalize().expect("canonical artifact");
    let esbuild_root = root.path().join("producer/esbuild");
    fs::create_dir_all(esbuild_root.join("bin")).expect("esbuild bin");
    let esbuild = esbuild_root.join("bin/esbuild");
    fs::write(
            &esbuild,
            r#"#!/bin/sh
for arg in "$@"; do
  case "$arg" in
    --metafile=*) metafile="${arg#--metafile=}" ;;
    --outfile=*) outfile="${arg#--outfile=}" ;;
  esac
done
printf 'closed-worker-bundle' > "$outfile"
printf '%s' '{"inputs":{"_worker.js":{"bytes":51,"imports":[]},"worker-support.js":{"bytes":23,"imports":[]}},"outputs":{"bundle":{"imports":[]}}}' > "$metafile"
"#,
        )
        .expect("fake esbuild");
    let mut permissions = fs::metadata(&esbuild)
        .expect("fake esbuild metadata")
        .permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&esbuild, permissions).expect("fake esbuild mode");
    let artifact = manifest(&artifact_root).expect("artifact manifest");
    let producer = json!({
        "interpreter": {"path":"/bin/sh"},
        "execution_closure": {"roots":[{"component":"esbuild","root":esbuild_root}]}
    });
    let (bundle, _bytes) = build_worker_bundle(&artifact_root, &artifact, &producer)
        .expect("worker build")
        .expect("worker bundle");
    let expected_transport = transport_manifest(&artifact, Some(&bundle)).expect("transport");
    let targets = json!({
        "pages_deployment": {
            "artifact": artifact,
            "provider_request": {
                "producer": producer,
                "worker_bundle": bundle,
                "transport_manifest": expected_transport
            }
        }
    });
    let mut input = CallInput {
        query: json!({"argument":artifact_root}),
        ..CallInput::default()
    };
    let stage = stage_bound_artifact(&targets, &mut input).expect("staged artifact");
    let staged = input.query["argument"].as_str().expect("staged path");
    assert!(Path::new(staged).starts_with(stage.path()));
    assert_eq!(
        fs::read(Path::new(staged).join("_worker.js")).expect("staged worker"),
        b"closed-worker-bundle"
    );
    assert_eq!(
        fs::read(Path::new(staged).join("worker-support.js")).expect("staged support"),
        b"export const ok = true;"
    );
    assert_staged_transport_drift_rejected(&targets, &input, Path::new(staged));

    fs::write(
            &esbuild,
            r#"#!/bin/sh
for arg in "$@"; do
  case "$arg" in
    --metafile=*) metafile="${arg#--metafile=}" ;;
    --outfile=*) outfile="${arg#--outfile=}" ;;
  esac
done
printf 'var p="./worker-support.js"; export default {fetch(){return import(p)}}' > "$outfile"
printf '%s' '{"inputs":{"_worker.js":{"bytes":51,"imports":[]}},"outputs":{"bundle":{"imports":[]}}}' > "$metafile"
"#,
        )
        .expect("dynamic-import esbuild");
    assert!(
        build_worker_bundle(&artifact_root, &artifact, &producer)
            .expect_err("metafile omission cannot admit a runtime import")
            .to_string()
            .contains("runtime dynamic import")
    );
}

fn assert_staged_transport_drift_rejected(targets: &Value, input: &CallInput, staged: &Path) {
    validate_staged_artifact(targets, input).expect("exact staged transport");
    fs::write(staged.join("index.html"), b"drifted").expect("drift staged asset");
    let error = validate_staged_artifact(targets, input)
        .expect_err("staged drift must fail before the provider process");
    assert!(
        error
            .to_string()
            .contains("no provider process was started")
    );
}

#[test]
fn project_mode_separates_bodyless_git_trigger_from_direct_upload() {
    let response = CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({"name":"aos-web","production_branch":"main","source":null}),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    };
    let direct_receipt =
        apply_project_response(&direct_upload(), "acct", "aos-web", Some("main"), &response)
            .expect("explicit null remains direct upload");
    assert_eq!(direct_receipt["source_mode_basis"], "explicit_null_source");
    assert!(receipt_source_mode_is_bound(
        &direct_receipt,
        "direct_upload"
    ));
    let mut bodyless = CapabilityV1::new(
        GIT_TRIGGER_CAPABILITY_ID,
        "trigger Git build",
        "POST",
        DEPLOYMENT_LIST_PATH,
    );
    bodyless.adapter_status = AdapterStatus::DynamicApi;
    assert!(apply_project_response(&bodyless, "acct", "aos-web", None, &response).is_err());

    let git_project = CloudflareResponseV1 {
        result: json!({
            "name":"aos-web",
            "production_branch":"main",
            "source":{"type":"github","config":{}}
        }),
        ..response.clone()
    };
    let git_receipt = apply_project_response(&bodyless, "acct", "aos-web", None, &git_project)
        .expect("populated Git source remains Git integrated");
    assert_eq!(git_receipt["source_mode_basis"], "explicit_git_source");
    assert!(receipt_source_mode_is_bound(&git_receipt, "git_integrated"));
    assert!(
        apply_project_response(
            &direct_upload(),
            "acct",
            "aos-web",
            Some("main"),
            &git_project
        )
        .is_err()
    );

    let unknown = CloudflareResponseV1 {
        result: json!({"name":"aos-web","production_branch":"main"}),
        ..response
    };
    assert!(apply_project_response(&bodyless, "acct", "aos-web", None, &unknown).is_err());
}

fn omitted_source_project(canonical: Value, latest: Value) -> CloudflareResponseV1 {
    CloudflareResponseV1 {
        status: 200,
        success: true,
        result: json!({
            "name":"aos-web",
            "production_branch":"main",
            "build_config":{
                "build_command":null,
                "destination_dir":"target/site",
                "root_dir":null
            },
            "canonical_deployment":canonical,
            "latest_deployment":latest
        }),
        errors: Vec::new(),
        result_info: None,
        etag: None,
        cf_ray: None,
    }
}

fn direct_deployment(id: &str) -> Value {
    json!({
        "id":id,
        "project_name":"aos-web",
        "environment":"production",
        "deployment_trigger":{
            "type":"ad_hoc",
            "metadata":{
                "branch":"main",
                "commit_hash":"0a2c0165ab176f744539be371314dea086b80933"
            }
        },
        "latest_stage":{"name":"deploy","status":"success"},
        "stages":[
            {"name":"queued","status":"success"},
            {"name":"initialize","status":"success"},
            {"name":"clone_repo","status":"idle"},
            {"name":"build","status":"idle"},
            {"name":"deploy","status":"success"}
        ],
        "url":"https://ff88ab4a.aos-web-183.pages.dev"
    })
}

#[test]
fn omitted_project_source_requires_consistent_direct_deployment_evidence() {
    let id = "ff88ab4a-f284-4f06-86e0-c8ae3b459b60";
    let exact = omitted_source_project(direct_deployment(id), direct_deployment(id));
    let receipt = apply_project_response(&direct_upload(), "acct", "aos-web", Some("main"), &exact)
        .expect("omitted project source is compatible only with exact direct-upload evidence");
    assert_eq!(receipt["source_mode"], "direct_upload");
    assert_eq!(
        receipt["source_mode_basis"],
        "omitted_source_exact_direct_deployment"
    );
    assert_eq!(receipt["corroborating_deployment_id"], id);
    assert!(receipt_source_mode_is_bound(&receipt, "direct_upload"));
    let mut unbound = receipt.clone();
    unbound["corroborating_deployment_id"] = json!("not-a-uuid");
    assert!(!receipt_source_mode_is_bound(&unbound, "direct_upload"));

    let only_one = omitted_source_project(direct_deployment(id), Value::Null);
    assert!(
        apply_project_response(&direct_upload(), "acct", "aos-web", Some("main"), &only_one)
            .is_err(),
        "one deployment projection cannot authorize an omitted project source"
    );

    let different = omitted_source_project(
        direct_deployment(id),
        direct_deployment("22222222-2222-4222-8222-222222222222"),
    );
    assert!(
        apply_project_response(
            &direct_upload(),
            "acct",
            "aos-web",
            Some("main"),
            &different
        )
        .is_err(),
        "different canonical/latest identities remain ambiguous"
    );

    let mut manual_git_upload = direct_deployment(id);
    manual_git_upload["source"] = json!({
        "type":"github",
        "config":{
            "owner":"MLNavigator",
            "repo_name":"aos-web",
            "repo_id":"123456789",
            "production_branch":"main",
            "production_deployments_enabled":false,
            "preview_deployment_setting":"none"
        }
    });
    let git_evidence = omitted_source_project(manual_git_upload.clone(), manual_git_upload);
    assert!(
        apply_project_response(
            &direct_upload(),
            "acct",
            "aos-web",
            Some("main"),
            &git_evidence
        )
        .is_err(),
        "a manual Wrangler deployment to a Git project remains Git-integrated"
    );

    let mut clone_stage = direct_deployment(id);
    clone_stage["stages"] = json!([
        {"name":"clone_repo","status":"success"},
        {"name":"deploy","status":"success"}
    ]);
    let git_pipeline = omitted_source_project(clone_stage.clone(), clone_stage);
    assert!(
        apply_project_response(
            &direct_upload(),
            "acct",
            "aos-web",
            Some("main"),
            &git_pipeline
        )
        .is_err(),
        "a repository pipeline cannot be normalized as direct upload"
    );

    let mut repository_build = exact.result.clone();
    repository_build["build_config"]["build_command"] = json!("npm run build");
    let repository_build = CloudflareResponseV1 {
        result: repository_build,
        ..exact
    };
    assert!(
        apply_project_response(
            &direct_upload(),
            "acct",
            "aos-web",
            Some("main"),
            &repository_build
        )
        .is_err(),
        "a configured repository build cannot be normalized as direct upload"
    );
}

#[test]
fn omitted_project_source_rejects_partial_or_duplicate_stage_evidence() {
    let id = "ff88ab4a-f284-4f06-86e0-c8ae3b459b60";
    for (missing_stage, retained_repository_stage) in
        [("clone_repo", "build"), ("build", "clone_repo")]
    {
        let mut partial_stages = direct_deployment(id);
        partial_stages["stages"] = json!([
            {"name":"queued","status":"active"},
            {"name":"initialize","status":"idle"},
            {"name":retained_repository_stage,"status":"idle"},
            {"name":"deploy","status":"success"}
        ]);
        let partial_evidence = omitted_source_project(partial_stages.clone(), partial_stages);
        assert!(
            apply_project_response(
                &direct_upload(),
                "acct",
                "aos-web",
                Some("main"),
                &partial_evidence
            )
            .is_err(),
            "missing {missing_stage} stage evidence remains ambiguous"
        );
    }

    let mut duplicate_build = direct_deployment(id);
    duplicate_build["stages"]
        .as_array_mut()
        .expect("stages array")
        .push(json!({"name":"build","status":"idle"}));
    let duplicate_evidence = omitted_source_project(duplicate_build.clone(), duplicate_build);
    assert!(
        apply_project_response(
            &direct_upload(),
            "acct",
            "aos-web",
            Some("main"),
            &duplicate_evidence
        )
        .is_err(),
        "duplicate repository-stage evidence remains ambiguous"
    );
}

#[test]
fn collection_identity_matches_only_new_exact_deployments() {
    let old = "11111111-1111-4111-8111-111111111111";
    let new = "22222222-2222-4222-8222-222222222222";
    let deployment = |id| {
        json!({
            "id": id,
            "project_name": "aos-web",
            "environment": "production",
            "deployment_trigger": {"metadata":{"branch":"main","commit_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
            "latest_stage":{"status":"active"}
        })
    };
    let prior = BTreeSet::from([old.to_owned()]);
    let single = json!([deployment(old), deployment(new)]);
    assert_eq!(
        matching_deployment_ids(
            &single,
            &prior,
            "aos-web",
            "main",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ),
        BTreeSet::from([new.to_owned()])
    );
    assert!(deployment_matches_returned_id(
        &single,
        new,
        "aos-web",
        "main",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ));
    assert!(!deployment_matches_returned_id(
        &single,
        old,
        "aos-web",
        "preview",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ));
    assert_eq!(
        matching_deployment_ids(
            &json!([
                deployment(new),
                deployment("33333333-3333-4333-8333-333333333333")
            ]),
            &prior,
            "aos-web",
            "main",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
        .len(),
        2,
        "replay admission must observe every exact-identity deployment"
    );
}

#[cfg(unix)]
#[test]
fn producer_identity_binds_exact_executable_hash_and_catalog_version() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().expect("producer root");
    let executable = root.path().join("wrangler");
    fs::write(&executable, "#!/bin/sh\nprintf '4.107.0\\n'\n").expect("producer");
    let mut permissions = fs::metadata(&executable)
        .expect("producer metadata")
        .permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&executable, permissions).expect("producer mode");

    let mut capability = direct_upload();
    capability.source = "wrangler 4.107.0 pages deploy help".to_owned();
    let producer = wrangler_producer_at(&capability, &executable).expect("bound producer");
    let canonical = executable.canonicalize().expect("canonical producer");
    assert_eq!(producer["executable"].as_str(), canonical.to_str());
    assert_eq!(producer["version"], "4.107.0");
    assert_eq!(producer["execution_closure"]["kind"], "single_file");
    assert_eq!(producer["execution_closure"]["file_count"], 1);
    assert_eq!(producer["interpreter"]["path"], "/bin/sh");
    assert_eq!(
        producer["executable_sha256"],
        hex::encode(Sha256::digest(
            fs::read(&executable).expect("producer bytes")
        ))
    );
    let targets = json!({
        "pages_deployment": {
            "provider_request": {"producer": producer}
        }
    });
    assert_eq!(
        bound_wrangler_executable(&targets).expect("bound path"),
        canonical
    );
    assert_eq!(
        bound_wrangler_interpreter(&targets).expect("bound interpreter"),
        Some(PathBuf::from("/bin/sh"))
    );

    capability.source = "wrangler 4.106.0 pages deploy help".to_owned();
    assert!(wrangler_producer_at(&capability, &executable).is_err());
}

#[cfg(unix)]
#[test]
fn producer_identity_rejects_unchanged_launcher_with_drifted_asset_hasher() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().expect("producer root");
    let node_modules = root.path().join("node_modules");
    let package = node_modules.join("wrangler");
    let bin = package.join("bin");
    let distribution = package.join("wrangler-dist");
    fs::create_dir_all(&bin).expect("bin");
    fs::create_dir_all(&distribution).expect("distribution");
    fs::write(
            package.join("package.json"),
            r#"{"name":"wrangler","version":"4.107.0","dependencies":{"blake3-wasm":"2.1.5","esbuild":"0.28.1"}}"#,
        )
        .expect("package metadata");
    let executable = bin.join("wrangler.js");
    fs::write(&executable, "#!/bin/sh\nprintf '4.107.0\\n'\n").expect("launcher");
    let mut permissions = fs::metadata(&executable)
        .expect("launcher metadata")
        .permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&executable, permissions).expect("launcher mode");
    fs::write(
        distribution.join("cli.js"),
        "require('blake3-wasm'); require('esbuild')",
    )
    .expect("payload");
    let blake3 = node_modules.join("blake3-wasm");
    fs::create_dir_all(blake3.join("dist")).expect("hasher package");
    fs::write(
        blake3.join("package.json"),
        r#"{"name":"blake3-wasm","version":"2.1.5"}"#,
    )
    .expect("hasher metadata");
    let hasher = blake3.join("dist/index.js");
    fs::write(&hasher, "hash-v1").expect("asset hasher");
    let esbuild = node_modules.join("esbuild");
    fs::create_dir_all(esbuild.join("lib")).expect("esbuild package");
    fs::write(
            esbuild.join("package.json"),
            r#"{"name":"esbuild","version":"0.28.1","optionalDependencies":{"@esbuild/darwin-arm64":"0.28.1"}}"#,
        )
        .expect("esbuild metadata");
    fs::write(esbuild.join("lib/main.js"), "builder-v1").expect("esbuild runtime");
    let platform = node_modules.join("@esbuild/darwin-arm64");
    fs::create_dir_all(platform.join("bin")).expect("platform package");
    fs::write(
        platform.join("package.json"),
        r#"{"name":"@esbuild/darwin-arm64","version":"0.28.1"}"#,
    )
    .expect("platform metadata");
    let native = platform.join("bin/esbuild");
    fs::write(&native, "native-v1").expect("native builder");

    let mut capability = direct_upload();
    capability.source = "wrangler 4.107.0 pages deploy help".to_owned();
    let planned = wrangler_producer_at(&capability, &executable).expect("planned producer");
    let targets = json!({
        "pages_deployment": {
            "provider_request": {"producer": planned.clone()}
        }
    });
    validate_bound_producer_at(&capability, &targets, &executable)
        .expect("unchanged producer at execution boundary");
    let components = planned["execution_closure"]["files"]
        .as_array()
        .expect("closure files")
        .iter()
        .filter_map(|file| file.get("component").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    assert!(components.contains("wrangler"));
    assert!(components.contains("blake3-wasm"));
    assert!(components.contains("esbuild"));
    assert!(components.contains("@esbuild/darwin-arm64"));
    fs::write(&hasher, "hash-v2").expect("drifted asset hasher");
    let boundary_error = validate_bound_producer_at(&capability, &targets, &executable)
        .expect_err("post-admission producer drift must stop before subprocess creation");
    assert!(
        boundary_error
            .to_string()
            .contains("no provider process was started")
    );
    let current = wrangler_producer_at(&capability, &executable).expect("current producer");

    assert_ne!(
        planned, current,
        "the bound producer must change when an unmodified Wrangler package delegates Pages asset hashing to drifted external bytes"
    );
    assert_eq!(planned["executable_sha256"], current["executable_sha256"]);
    assert_ne!(
        planned["execution_closure"]["manifest_sha256"],
        current["execution_closure"]["manifest_sha256"]
    );
}

#[test]
fn wrangler_output_requires_one_consistent_provider_returned_id() {
    let id = "22222222-2222-4222-8222-222222222222";
    let commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let output = format!(
        "{{\"type\":\"pages-deploy\",\"version\":1,\"pages_project\":\"aos-web\",\"deployment_id\":\"{id}\",\"url\":\"https://example.pages.dev\"}}\n{{\"type\":\"pages-deploy-detailed\",\"version\":1,\"pages_project\":\"aos-web\",\"deployment_id\":\"{id}\",\"url\":\"https://example.pages.dev\",\"environment\":\"production\",\"production_branch\":\"main\",\"deployment_trigger\":{{\"metadata\":{{\"commit_hash\":\"{commit}\"}}}}}}\n"
    );
    let parsed = parse_wrangler_output(&output).expect("exact output");
    assert_eq!(parsed["deployment_id"], id);
    assert!(structured_output_matches(
        &parsed, "aos-web", "main", commit
    ));
    assert!(!structured_output_matches(&parsed, "other", "main", commit));
    assert!(parse_wrangler_output("{}").is_err());
    assert!(parse_wrangler_output(&format!("{output}{output}")).is_err());
}
