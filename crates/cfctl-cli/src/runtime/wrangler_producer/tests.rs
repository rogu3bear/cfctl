#![allow(clippy::expect_used, clippy::wildcard_imports)]
use super::{test_support::BinFixture, *};
use std::os::unix::fs::symlink;

#[test]
fn producer_bin_alias_binds_declared_target_and_literal_mapping() {
    let fixture = BinFixture::new(true);
    let first = producer_closure(&fixture.executable).expect("declared bin alias");
    let entries = first["files"].as_array().expect("files");
    let alias = entries
        .iter()
        .find(|entry| entry["kind"] == "package_bin_alias")
        .expect("alias");
    assert_eq!(alias["binding"]["owner"], "wrangler");
    assert_eq!(alias["binding"]["target_component"], "miniflare");
    assert_eq!(alias["binding"]["target_path"], "bootstrap.js");
    assert_eq!(alias["binding"]["link_text"], "../miniflare/bootstrap.js");
    fixture.retarget("../miniflare/./bootstrap.js");
    let changed = producer_closure(&fixture.executable).expect("same target, distinct link text");
    assert_ne!(first["manifest_sha256"], changed["manifest_sha256"]);
}

#[test]
fn producer_bin_alias_rejects_nondeclared_or_unsafe_targets() {
    for target in [
        "../miniflare/missing.js",
        "../miniflare",
        "../../package.json",
        "/etc/hosts",
        "../miniflare/bootstrap.js/",
        "../miniflare/bootstrap.js/.",
    ] {
        let fixture = BinFixture::new(true);
        fixture.retarget(target);
        assert!(producer_closure(&fixture.executable).is_err(), "{target}");
    }
    let fixture = BinFixture::new(true);
    fs::write(
        fixture.dependency.join("other.js"),
        "export const fixture = true;",
    )
    .expect("same bytes");
    fixture.retarget("../miniflare/other.js");
    assert!(producer_closure(&fixture.executable).is_err());
    let fixture = BinFixture::new(true);
    fs::rename(&fixture.alias, fixture.package.join("unexpected-link")).expect("move alias");
    assert!(producer_closure(&fixture.executable).is_err());
}

#[test]
fn producer_bin_alias_rejects_chains_and_symlinked_target_directories() {
    let fixture = BinFixture::new(true);
    fs::rename(
        fixture.dependency.join("bootstrap.js"),
        fixture.dependency.join("real.js"),
    )
    .expect("move target");
    symlink("real.js", fixture.dependency.join("bootstrap.js")).expect("target chain");
    assert!(producer_closure(&fixture.executable).is_err());
    let fixture = BinFixture::new(true);
    fs::create_dir(fixture.dependency.join("real")).expect("directory");
    fs::rename(
        fixture.dependency.join("bootstrap.js"),
        fixture.dependency.join("real/start.js"),
    )
    .expect("move target");
    symlink("real", fixture.dependency.join("linked")).expect("directory chain");
    fs::write(
        fixture.dependency.join("package.json"),
        r#"{"name":"miniflare","bin":{"miniflare":"linked/start.js"}}"#,
    )
    .expect("bin metadata");
    fixture.retarget("../miniflare/linked/start.js");
    assert!(producer_closure(&fixture.executable).is_err());

    let fixture = BinFixture::new(true);
    fs::create_dir(fixture.dependency.join("real")).expect("directory");
    symlink("real", fixture.dependency.join("linked")).expect("directory chain");
    fixture.retarget("../miniflare/linked/../bootstrap.js");
    assert!(producer_closure(&fixture.executable).is_err());
}

#[test]
fn producer_bin_alias_uses_actual_owner_inside_overlapping_package_walks() {
    let fixture = BinFixture::new(true);
    let helper = fixture.dependency.join("node_modules/helper");
    fs::create_dir_all(&helper).expect("helper");
    fs::create_dir_all(fixture.dependency.join("node_modules/.bin")).expect("nested bin");
    fs::write(
        helper.join("package.json"),
        r#"{"name":"helper","bin":{"helper":"run.js"}}"#,
    )
    .expect("helper metadata");
    fs::write(helper.join("run.js"), "helper").expect("helper entry");
    fs::write(
        fixture.dependency.join("package.json"),
        r#"{"name":"miniflare","bin":{"miniflare":"bootstrap.js"},"dependencies":{"helper":"1"}}"#,
    )
    .expect("nested owner");
    symlink(
        "../helper/run.js",
        fixture.dependency.join("node_modules/.bin/helper"),
    )
    .expect("nested alias");
    let closure = producer_closure(&fixture.executable).expect("nested owner");
    let records = closure["files"]
        .as_array()
        .expect("files")
        .iter()
        .filter(|entry| {
            entry["kind"] == "package_bin_alias" && entry["binding"]["bin_name"] == "helper"
        })
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 2, "both overlapping walks retain coverage");
    assert!(
        records
            .iter()
            .all(|entry| entry["binding"]["owner"] == "miniflare")
    );

    // The target is admitted, but Wrangler itself did not declare helper.
    fixture.retarget("../miniflare/node_modules/helper/run.js");
    fs::write(
        helper.join("package.json"),
        r#"{"name":"helper","bin":{"miniflare":"run.js"}}"#,
    )
    .expect("matching name in nondependency");
    assert!(producer_closure(&fixture.executable).is_err());
}

#[test]
fn producer_bin_alias_requires_declared_owner_dependency_and_bin_shape() {
    for metadata in [
        r#"{"name":"wrangler","version":"4.100.0"}"#,
        r#"{"name":"wrangler","dependencies":{"different":"1"}}"#,
    ] {
        let fixture = BinFixture::new(true);
        fs::write(fixture.package.join("package.json"), metadata).expect("owner metadata");
        assert!(producer_closure(&fixture.executable).is_err());
    }
    for bin in [
        json!(true),
        json!({"miniflare":17}),
        json!({"other":"bootstrap.js"}),
        json!({"miniflare":"../outside.js"}),
        json!({"miniflare":"bootstrap.js/"}),
        json!({"miniflare":"bootstrap.js/."}),
    ] {
        let fixture = BinFixture::new(true);
        fs::write(
            fixture.dependency.join("package.json"),
            json!({"name":"miniflare","bin":bin}).to_string(),
        )
        .expect("bin metadata");
        assert!(producer_closure(&fixture.executable).is_err());
    }
    let fixture = BinFixture::new(true);
    fs::write(
        fixture.dependency.join("package.json"),
        r#"{"name":"miniflare","bin":"bootstrap.js"}"#,
    )
    .expect("string bin");
    assert!(producer_closure(&fixture.executable).is_ok());
}

#[test]
fn producer_bin_alias_counts_toward_existing_entry_and_byte_limits() {
    let fixture = BinFixture::new(true);
    let plain = BinFixture::new(false);
    let count = usize::try_from(
        producer_closure(&plain.executable).expect("plain fixture")["file_count"]
            .as_u64()
            .expect("count"),
    )
    .expect("bounded count");
    assert!(producer_closure_with_limits(&fixture.executable, count, MAX_PRODUCER_BYTES).is_err());
    assert!(producer_closure_with_limits(&plain.executable, count, MAX_PRODUCER_BYTES).is_ok());
    let closure = producer_closure(&fixture.executable).expect("fixture");
    let bytes = closure["total_bytes"].as_u64().expect("bytes");
    assert!(
        producer_closure_with_limits(&fixture.executable, MAX_PRODUCER_FILE_COUNT, bytes - 1)
            .is_err()
    );
    assert!(
        producer_closure_with_limits(&fixture.executable, MAX_PRODUCER_FILE_COUNT, bytes).is_ok()
    );
}

#[test]
fn producer_bin_alias_free_manifest_keeps_original_record_shape() {
    let fixture = BinFixture::new(false);
    let actual = producer_closure(&fixture.executable).expect("plain fixture");
    let mut expected = Vec::new();
    let roots = producer_package_roots(&fixture.package).expect("roots");
    for (component, root) in roots {
        let mut paths = WalkDir::new(&root)
            .into_iter()
            .map(|entry| entry.expect("entry").into_path())
            .filter(|path| path.is_file())
            .collect::<Vec<_>>();
        paths.sort();
        for path in paths {
            let bytes = fs::read(&path).expect("bytes");
            expected.push(json!({"component":component,"path":path.strip_prefix(&root).expect("relative").to_string_lossy().replace('\\',"/"),"size":bytes.len(),"sha256":hex::encode(Sha256::digest(bytes))}));
        }
    }
    assert_eq!(actual["files"], json!(expected));
    assert_eq!(
        actual["manifest_sha256"],
        hash_value(&json!(expected)).expect("original digest")
    );
}

#[test]
#[ignore = "requires an explicitly selected installed Bun package, no provider command"]
#[expect(
    clippy::print_stdout,
    reason = "explicit installed-fixture qualification emits its bound identity"
)]
fn producer_bin_alias_installed_bun_layout() {
    let executable =
        PathBuf::from(env::var_os("CFCTL_TEST_WRANGLER").expect("explicit installed Wrangler"))
            .canonicalize()
            .expect("installed launcher");
    let pages = snapshot_at(
        &BinFixture::capability("pages deploy"),
        &executable,
        "pages deploy",
    )
    .expect("installed Pages producer closure and interpreter");
    let worker = snapshot_at(
        &BinFixture::capability("versions upload"),
        &executable,
        "versions upload",
    )
    .expect("installed Worker producer closure and interpreter");
    assert_eq!(pages["execution_closure"], worker["execution_closure"]);
    assert_eq!(pages["interpreter"], worker["interpreter"]);
    assert_eq!(pages["version"], "4.100.0");
    let closure = &pages["execution_closure"];
    assert!(
        closure["files"]
            .as_array()
            .expect("files")
            .iter()
            .any(|entry| entry["kind"] == "package_bin_alias"
                && entry["binding"]["bin_name"] == "miniflare")
    );
    println!(
        "installed producer: {}",
        json!({
            "version": pages["version"],
            "file_count": closure["file_count"],
            "total_bytes": closure["total_bytes"],
            "manifest_sha256": closure["manifest_sha256"],
            "interpreter": pages["interpreter"],
        })
    );
}
