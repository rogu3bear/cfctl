//! Exercise the real checker against Git history and malformed metadata fixtures.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Command, Output},
};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("cfctl-attribution-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).expect("fixture directory");
        let fixture = Self(root);
        fixture.git(&["init", "-q"]);
        fixture.git(&["config", "user.name", "Human Maintainer"]);
        fixture.git(&["config", "user.email", "human@example.com"]);
        fixture.commit("initial", None);
        fixture
    }

    fn git(&self, args: &[&str]) -> String {
        let output = self.command("git").args(args).output().expect("git");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("git UTF-8")
            .trim()
            .to_owned()
    }

    fn command(&self, program: &str) -> Command {
        let mut command = Command::new(program);
        command.current_dir(&self.0);
        for (name, _) in std::env::vars().filter(|(name, _)| name.starts_with("GIT_")) {
            command.env_remove(name);
        }
        command
    }

    fn commit(&self, message: &str, identity: Option<(&str, &str)>) {
        let mut command = self.command("git");
        command.args([
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            message,
        ]);
        if let Some((key, value)) = identity {
            command.env(key, value);
        }
        let output = command.output().expect("commit");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn check(&self, base: &str) -> Output {
        self.command("bash")
            .arg(
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.githooks/check-attribution.sh"),
            )
            .args([base, "HEAD"])
            .output()
            .expect("checker")
    }

    fn check_fields(&self, fields: &[&str]) -> Output {
        // Supply read-only Git output instead of creating forbidden-authorship
        // commits or disabling the operator's global commit hooks.
        let bin = self.0.join("mock-bin");
        fs::create_dir_all(&bin).expect("mock directory");
        let git = bin.join("git");
        fs::write(
            &git,
            r#"#!/bin/sh
case "$1" in
  rev-parse)
    case "$4" in HEAD*) printf '%040d\n' 2 ;; *) printf '%040d\n' 1 ;; esac ;;
  rev-list) printf '%040d\n' 2 ;;
  show) cat "$CFCTL_TEST_COMMIT_FIELDS" ;;
  *) exit 2 ;;
esac
"#,
        )
        .expect("mock Git");
        fs::set_permissions(&git, fs::Permissions::from_mode(0o755)).expect("executable mock");
        let metadata = self.0.join("fields.txt");
        fs::write(&metadata, fields.join("\n")).expect("metadata fixture");
        let mut paths = vec![bin];
        paths.extend(std::env::split_paths(
            &std::env::var_os("PATH").expect("PATH"),
        ));
        self.command("bash")
            .env("PATH", std::env::join_paths(paths).expect("mock PATH"))
            .env("CFCTL_TEST_COMMIT_FIELDS", metadata)
            .arg(
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.githooks/check-attribution.sh"),
            )
            .args(["base", "HEAD"])
            .output()
            .expect("checker")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove owned Git fixture");
    }
}

#[test]
fn attribution_binds_success_to_the_exact_range_and_checker() {
    let fixture = Fixture::new();
    let base = fixture.git(&["rev-parse", "HEAD"]);
    fixture.commit("fix: ordinary change", None);
    let output = fixture.check(&base);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let receipt: serde_json::Value = serde_json::from_slice(&output.stdout).expect("receipt");
    assert_eq!(receipt["base_sha"], base);
    assert_eq!(receipt["head_sha"], fixture.git(&["rev-parse", "HEAD"]));
    assert_eq!(receipt["commit_count"], 1);
    assert_eq!(receipt["execution"], "local");
    assert_eq!(receipt["script_sha256"].as_str().unwrap().len(), 64);
}

#[test]
fn attribution_checks_every_identity_and_message_field() {
    let fixture = Fixture::new();
    for (index, forbidden) in [
        "Cursor",
        "agent@cursor.com",
        "Cursor Agent",
        "agent@cursor.com",
        "Made with Cursor",
        "Co-authored-by: Cursor <agent@example.com>",
    ]
    .into_iter()
    .enumerate()
    {
        let mut fields = [
            "Human",
            "human@example.com",
            "Human",
            "human@example.com",
            "ordinary",
            "body",
        ];
        fields[index] = forbidden;
        let output = fixture.check_fields(&fields);
        assert!(
            !output.status.success(),
            "must reject field {index}: {forbidden}"
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("FORBIDDEN"));
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn attribution_fails_closed_on_invalid_git_base() {
    let fixture = Fixture::new();
    let output = fixture.check("does-not-exist");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}
