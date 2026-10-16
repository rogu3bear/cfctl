use super::*;

/// These same cases run through each consumer's actual config call before and
/// after extraction. The source fixture is committed; private config is ignored.
#[expect(
    clippy::too_many_lines,
    reason = "The four real consumers run the same accepted source and independent custody refusal cases."
)]
pub(in crate::runtime) fn characterize(mut bind: impl FnMut(Value, &CallInput) -> Result<String>) {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    let root = tempfile::tempdir().expect("source fixture");
    let root_path = root.path().canonicalize().expect("root");
    fs::create_dir_all(root_path.join(".cfctl/operations")).expect("pack parent");
    let pack = ".cfctl/operations/test.toml";
    fs::write(root_path.join(pack), "schema_version = 1\n").expect("pack");
    fs::write(
        root_path.join(".gitignore"),
        "wrangler.production.toml\nalias.toml\n",
    )
    .expect("ignore private input");
    let template = "name = \"tracked-worker\"\nmain = \"worker.js\"\nsend_email = [{ name = \"EMAIL\" }]\n[vars]\nMAILDESK_INBOUND_RELAY_MODE = \"disabled\"\nMAILDESK_REPLY_RELAY_MODE = \"disabled\"\nMAILDESK_VERIFIED_SENDER_DOMAINS = \"\"\n[[d1_databases]]\nbinding = \"DB\"\ndatabase_name = \"tracked-db\"\ndatabase_id = \"00000000-0000-4000-8000-000000000000\"\n";
    let production = template
        .replace(
            "MAILDESK_VERIFIED_SENDER_DOMAINS = \"\"",
            "MAILDESK_VERIFIED_SENDER_DOMAINS = \"sender.example.com\"",
        )
        .replace("tracked-worker", "actual-worker")
        .replace("tracked-db", "actual-db")
        .replace(
            "00000000-0000-4000-8000-000000000000",
            "11111111-1111-4111-8111-111111111111",
        );
    let template_path = root_path.join("wrangler.toml");
    let config_path = root_path.join("wrangler.production.toml");
    fs::write(&template_path, template).expect("template");
    fs::write(&config_path, &production).expect("config");
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).expect("mode");
    let git = |args: &[&str]| {
        let output = StdCommand::new("git")
            .arg("-C")
            .arg(&root_path)
            .args(args)
            .output()
            .expect("git");
        assert!(
            output.status.success(),
            "fixture git: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("UTF-8")
            .trim()
            .to_owned()
    };
    git(&["init", "-q"]);
    git(&["config", "user.name", "Fixture"]);
    git(&["config", "user.email", "fixture@example.invalid"]);
    git(&[
        "remote",
        "add",
        "origin",
        "https://example.invalid/fixture.git",
    ]);
    git(&["add", "."]);
    git(&["commit", "-qm", "fixture"]);
    let common = json!({
        "repository_root": root_path, "repository_head": git(&["rev-parse", "HEAD"]),
        "repository_origin": "https://example.invalid/fixture.git",
        "operation_pack_path": pack,
        "operation_pack_sha256": format!("sha256:{}", hex::encode(Sha256::digest(b"schema_version = 1\n"))),
        "config_template_path":"wrangler.toml",
        "config_template_sha256":format!("sha256:{}", hex::encode(Sha256::digest(template.as_bytes()))),
        "production_config_path":"wrangler.production.toml", "database_binding":"DB", "wrangler_version":"4.120.1"
    });
    let input = CallInput {
        selectors: json!({"database_id":"11111111-1111-4111-8111-111111111111"}),
        query: json!({"config":config_path}),
        ..CallInput::default()
    };
    let expected = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(production.as_bytes()))
    );
    assert_eq!(
        bind(common.clone(), &input).expect("accepted config"),
        expected
    );
    for field in [
        "repository_head",
        "repository_origin",
        "repository_root",
        "operation_pack_sha256",
    ] {
        let mut changed = common.clone();
        changed[field] = json!("different-source-identity");
        assert!(bind(changed, &input).is_err(), "source field {field}");
    }
    fs::write(root_path.join("unrelated-dirty.txt"), "dirty").expect("dirty source");
    assert!(bind(common.clone(), &input).is_err());
    fs::remove_file(root_path.join("unrelated-dirty.txt")).expect("remove owned fixture");
    let mut wrong_selector = input.clone();
    wrong_selector.selectors["database_id"] = json!("22222222-2222-4222-8222-222222222222");
    assert!(bind(common.clone(), &wrong_selector).is_err());
    fs::write(
        &config_path,
        format!("{production}unrecognized_private_setting = true\n"),
    )
    .expect("extra overlay");
    assert!(bind(common.clone(), &input).is_err());
    fs::write(&config_path, &production).expect("restore private fixture");
    fs::write(&template_path, template.replace("worker.js", "changed.js")).expect("template drift");
    assert!(bind(common.clone(), &input).is_err());
    fs::write(&template_path, template).expect("restore template");
    let alias = root_path.join("alias.toml");
    symlink(&config_path, &alias).expect("config alias");
    let mut alias_input = input;
    alias_input.query["config"] = json!(alias);
    assert!(
        bind(common, &alias_input).is_err(),
        "a config alias must not be canonicalized into authority"
    );
}

pub(in crate::runtime) fn extend(mut common: Value, extra: Value) -> Value {
    common
        .as_object_mut()
        .expect("common")
        .extend(extra.as_object().expect("extra").clone());
    common
}
