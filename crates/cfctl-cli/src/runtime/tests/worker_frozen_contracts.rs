use super::*;
use crate::runtime::{
    worker_deployment_artifact, worker_frozen_config, worker_frozen_files as files,
    worker_frozen_upload,
};
use std::path::PathBuf;

struct ArtifactFixture {
    _owner: tempfile::TempDir,
    repository: PathBuf,
    config: PathBuf,
    roots: Vec<PathBuf>,
}

fn artifact_fixture() -> ArtifactFixture {
    let owner = tempfile::tempdir().expect("artifact fixture");
    let repository = fs::canonicalize(owner.path()).expect("canonical native temp root");
    let build = repository.join("web/build");
    let assets = repository.join("web/site");
    fs::create_dir_all(&build).expect("build directory");
    fs::create_dir_all(&assets).expect("assets directory");
    fs::write(
        build.join("index.js"),
        "export default { fetch() { return new Response('ok'); } };\n",
    )
    .expect("Worker bytes");
    fs::write(build.join("index_bg.wasm"), b"\0asm\x01\0\0\0").expect("Wasm bytes");
    fs::write(
        assets.join("index.html"),
        "<!doctype html><title>Frozen</title>",
    )
    .expect("asset bytes");
    let config = repository.join("web/wrangler.toml");
    fs::write(&config, "name = \"fixture\"\nmain = \"build/index.js\"\n[assets]\ndirectory = \"site\"\n[build]\ncommand = \"exit 73\"\n").expect("canonical config");
    ArtifactFixture {
        _owner: owner,
        repository,
        config,
        roots: vec![build, assets],
    }
}

#[test]
fn frozen_manifest_preserves_the_existing_release_digest_and_complete_membership() {
    let fixture = artifact_fixture();
    fs::create_dir(fixture.roots[0].join("empty")).expect("empty artifact directory");
    let captured = files::capture(&fixture.repository, &fixture.roots).expect("capture");
    assert_eq!(
        captured.manifest.sha256,
        worker_deployment_artifact::artifact_set_sha256(&fixture.repository, &fixture.roots)
            .expect("existing release digest")
    );
    assert_eq!(
        captured
            .manifest
            .entries
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<Vec<_>>(),
        [
            "web/build/index.js",
            "web/build/index_bg.wasm",
            "web/site/index.html"
        ]
    );
    assert_eq!(captured.manifest.entries[1].size, 8);
    assert!(
        captured
            .manifest
            .directories
            .contains(&"web/build/empty".to_owned())
    );
    assert_eq!(captured.manifest.roots, ["web/build", "web/site"]);
    fs::write(fixture.roots[1].join("added.txt"), b"new").expect("added artifact");
    assert_ne!(
        files::capture(&fixture.repository, &fixture.roots)
            .expect("new capture")
            .manifest,
        captured.manifest
    );
    fs::remove_file(fixture.roots[1].join("added.txt")).expect("remove owned addition");
    fs::remove_dir(fixture.roots[0].join("empty")).expect("remove owned empty directory");
    let changed =
        files::capture(&fixture.repository, &fixture.roots).expect("removed directory capture");
    assert_eq!(changed.manifest.sha256, captured.manifest.sha256);
    assert_ne!(
        changed.manifest, captured.manifest,
        "directory drift is bound beyond the legacy file digest"
    );
}

#[test]
fn frozen_projection_changes_only_transport_paths_bundle_policy_and_custom_command() {
    let fixture = artifact_fixture();
    let document = json!({
        "name": "fixture", "main": "build/index.js", "compatibility_date": "2026-06-29",
        "compatibility_flags": ["nodejs_compat"], "workers_dev": false, "upload_source_maps": true,
        "build": {"command": "../scripts/custom.sh", "cwd": "../", "watch_dir": "src"},
        "assets": {"directory": "site", "binding": "ASSETS", "run_worker_first": ["/api/*"], "not_found_handling": "single-page-application"},
        "routes": [{"pattern": "fixture.invalid", "custom_domain": true}],
        "vars": {"PRIVATE_TEST_VALUE": "must-stay-private"}, "triggers": {"crons": ["17 * * * *"]},
        "d1_databases": [{"binding": "DB", "database_name": "fixture", "database_id": "11111111-2222-4333-8444-555555555555"}],
        "r2_buckets": [{"binding": "BUCKET", "bucket_name": "fixture"}],
        "rules": [{"type": "CompiledWasm", "globs": ["**/*.wasm"], "fallthrough": false}],
    });
    let original_bytes = fs::read(&fixture.config).expect("original config");
    let manifest = files::capture(&fixture.repository, &fixture.roots)
        .expect("manifest")
        .manifest;
    let projection =
        worker_frozen_config::project(&fixture.repository, &fixture.config, &document, &manifest)
            .expect("closed projection");
    let projected: Value = serde_json::from_slice(&projection.bytes).expect("private config JSON");
    let mut expected = document;
    expected["build"]
        .as_object_mut()
        .expect("build object")
        .remove("command");
    expected["main"] = json!("web/build/index.js");
    expected["base_dir"] = json!("web/build");
    expected["assets"]["directory"] = json!("web/site");
    expected["no_bundle"] = json!(true);
    assert_eq!(projected, expected);
    assert!(projection.custom_build_suppressed);
    assert_eq!(
        fs::read(&fixture.config).expect("preserved original config"),
        original_bytes
    );
}

#[test]
fn frozen_projection_rejects_unmodelled_and_out_of_manifest_file_inputs() {
    let fixture = artifact_fixture();
    let manifest = files::capture(&fixture.repository, &fixture.roots)
        .expect("manifest")
        .manifest;
    for field in ["env", "tsconfig", "alias", "site", "unsafe", "secrets"] {
        let mut document = json!({"main": "build/index.js", "assets": {"directory": "site"}});
        document[field] = json!({"private": "DO-NOT-RETAIN"});
        let error = worker_frozen_config::project(
            &fixture.repository,
            &fixture.config,
            &document,
            &manifest,
        )
        .err()
        .expect("unmodelled field rejected")
        .to_string();
        assert!(!error.contains("DO-NOT-RETAIN"));
    }
    assert!(
        worker_frozen_config::project(
            &fixture.repository,
            &fixture.config,
            &json!({"assets": {"directory": "site"}}),
            &manifest
        )
        .is_err(),
        "missing main cannot admit an implicit producer template outside the artifact"
    );
    fs::write(fixture.repository.join("outside.wasm"), b"unadmitted")
        .expect("outside-root fixture");
    let document =
        json!({"main": "build/index.js", "wasm_modules": {"UNBOUND": "../outside.wasm"}});
    assert!(
        worker_frozen_config::project(&fixture.repository, &fixture.config, &document, &manifest)
            .is_err()
    );
}

#[test]
fn frozen_file_capture_rejects_symlinks_ambiguous_names_and_ambient_controls() {
    use std::ffi::OsString;
    use std::os::unix::{ffi::OsStringExt as _, fs::symlink};
    let fixture = artifact_fixture();
    for name in [OsString::from("line\nbreak"), OsString::from("back\\slash")] {
        let path = fixture.roots[0].join(name);
        fs::write(&path, b"ambiguous").expect("ambiguous file fixture");
        assert!(files::capture(&fixture.repository, &fixture.roots).is_err());
        fs::remove_file(path).expect("remove owned ambiguous fixture");
    }
    let invalid_name = OsString::from_vec(vec![0xff]);
    let invalid_root = fixture.repository.join(&invalid_name);
    let error = files::capture(&fixture.repository, &[invalid_root])
        .err()
        .expect("production root admission rejects non-UTF-8 before opening it");
    assert!(error.to_string().contains("paths must be valid UTF-8"));
    let invalid_entry = fixture.roots[0].join(&invalid_name);
    match fs::write(&invalid_entry, b"ambiguous") {
        Ok(()) => {
            assert!(files::capture(&fixture.repository, &fixture.roots).is_err());
            fs::remove_file(invalid_entry).expect("remove owned non-UTF-8 fixture");
        }
        Err(error) => {
            // APFS refuses this entry at creation. Other filesystems exercise
            // directory-entry rejection as well as the deterministic root seam.
            assert_eq!(
                error.raw_os_error(),
                Some(rustix::io::Errno::ILSEQ.raw_os_error())
            );
        }
    }
    for name in [
        ".env",
        ".env.production",
        ".dev.vars",
        "wrangler.json",
        "tsconfig.json",
        ".git",
    ] {
        let path = fixture.roots[0].join(name);
        fs::write(&path, b"ambient").expect("ambient fixture");
        assert!(files::capture(&fixture.repository, &fixture.roots).is_err());
        fs::remove_file(path).expect("remove owned ambient fixture");
    }
    let alias = fixture.roots[0].join("alias.js");
    symlink("index.js", &alias).expect("symlink fixture");
    assert!(files::capture(&fixture.repository, &fixture.roots).is_err());
    fs::remove_file(alias).expect("remove owned symlink");
    let ancestor = fixture.repository.join("alias");
    symlink(fixture.repository.join("web"), &ancestor).expect("ancestor alias");
    assert!(files::capture(&fixture.repository, &[ancestor.join("build")]).is_err());
}

#[test]
fn frozen_mode_is_explicit_and_not_a_generic_wrangler_switch() {
    let capability = CapabilityV1::new(
        "wrangler.versions-upload",
        "Upload",
        "CLI",
        "wrangler versions upload",
    );
    assert!(
        !worker_frozen_upload::requested(&capability, &CallInput::default())
            .expect("ordinary mode")
    );
    for value in [json!("frozen"), json!(true), Value::Null] {
        let input = CallInput {
            query: json!({"artifact_mode": value}),
            ..CallInput::default()
        };
        assert!(worker_frozen_upload::requested(&capability, &input).is_err());
    }
    let input = CallInput {
        query: json!({"artifact_mode": "frozen-artifact"}),
        ..CallInput::default()
    };
    assert!(worker_frozen_upload::requested(&capability, &input).expect("explicit supported mode"));
    let other = CapabilityV1::new("wrangler.deploy", "Deploy", "CLI", "wrangler deploy");
    assert!(worker_frozen_upload::requested(&other, &input).is_err());
}
