#![cfg(unix)]
#![allow(clippy::expect_used)]

use std::{
    fs,
    io::Write as _,
    os::unix::fs::PermissionsExt as _,
    path::Path,
    process::{Command, Stdio},
};

fn clean_command(program: &str) -> Command {
    let mut command = Command::new(program);
    for (key, _) in std::env::vars() {
        if key.starts_with("GIT_") || key == "CFCTL_PRE_PUSH_GATE" {
            command.env_remove(key);
        }
    }
    command
}

fn git(root: &Path, args: &[&str]) -> String {
    let output = clean_command("git")
        .current_dir(root)
        .args(args)
        .output()
        .expect("git fixture");
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("utf8")
        .trim()
        .to_owned()
}

#[test]
#[allow(clippy::too_many_lines)]
fn pre_push_gate_binds_canonical_source_and_cleans_git_environment() {
    for scenario in [
        "success",
        "wrong_ref",
        "wrong_oid",
        "head_drift",
        "dirty",
        "drift",
        "verify_failure",
        "bypass",
        "tag",
        "lightweight_tag",
    ] {
        let temp = tempfile::tempdir().expect("fixture");
        let root = temp.path().join("repo");
        let bin = temp.path().join("bin");
        fs::create_dir(&root).expect("repo");
        fs::create_dir(&bin).expect("bin");
        git(&root, &["init", "-q"]);
        git(&root, &["config", "user.email", "test@example.com"]);
        git(&root, &["config", "user.name", "Test"]);
        git(&root, &["config", "core.hooksPath", "/dev/null"]);
        fs::write(root.join("source"), "one").expect("source");
        git(&root, &["add", "source"]);
        git(&root, &["commit", "-qm", "fixture"]);
        let head = git(&root, &["rev-parse", "HEAD"]);
        let branch = git(&root, &["symbolic-ref", "HEAD"]);
        let cargo = bin.join("cargo");
        fs::write(
            &cargo,
            r#"#!/bin/bash
set -eu
[ "$*" = "xtask verify" ]
if env | grep -q '^GIT_'; then exit 78; fi
printf invoked > "$FIXTURE_MARKER"
case "$FIXTURE_BEHAVIOR" in
  drift) printf changed > source ;;
  head_drift) git -c core.hooksPath=/dev/null commit --allow-empty -qm drift ;;
  verify_failure) exit 9 ;;
esac
"#,
        )
        .expect("cargo fixture");
        fs::set_permissions(&cargo, fs::Permissions::from_mode(0o755)).expect("executable");
        if scenario == "dirty" {
            fs::write(root.join("dirt"), "preserve").expect("dirty fixture");
        }
        let mut local_ref = branch.clone();
        let mut local_oid = head.clone();
        let mut remote_ref = branch;
        if scenario == "wrong_ref" {
            local_ref = "refs/heads/other".to_owned();
        }
        if scenario == "tag" || scenario == "lightweight_tag" {
            if scenario == "tag" {
                git(&root, &["tag", "-a", "v-test", "-m", "release"]);
            } else {
                git(&root, &["tag", "v-test"]);
            }
            local_ref = "refs/tags/v-test".to_owned();
            remote_ref = local_ref.clone();
            local_oid = git(&root, &["rev-parse", &local_ref]);
        }
        if scenario == "wrong_oid" {
            local_oid = "f".repeat(40);
        }
        let marker = temp.path().join("ran");
        let gate = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.githooks/pre-push-gate.sh");
        let mut command = clean_command("bash");
        command
            .current_dir(&root)
            .arg(gate)
            .env(
                "PATH",
                format!("{}:{}", bin.display(), std::env::var("PATH").expect("PATH")),
            )
            .env("GIT_DIR", root.join(".git"))
            .env("GIT_WORK_TREE", &root)
            .env("GIT_TRACE_PACKET", "1")
            .env("FIXTURE_BEHAVIOR", scenario)
            .env("FIXTURE_MARKER", &marker)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if scenario == "bypass" {
            command.env("CFCTL_PRE_PUSH_GATE", "off");
        }
        let mut child = command.spawn().expect("hook");
        writeln!(
            child.stdin.take().expect("stdin"),
            "{local_ref} {local_oid} {remote_ref} {}",
            "0".repeat(40)
        )
        .expect("protocol");
        let output = child.wait_with_output().expect("hook result");
        assert_eq!(
            output.status.success(),
            matches!(scenario, "success" | "tag"),
            "{scenario}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        if scenario != "head_drift" {
            assert_eq!(git(&root, &["rev-parse", "HEAD"]), head);
        }
        assert_eq!(
            git(&root, &["worktree", "list", "--porcelain"])
                .matches("worktree ")
                .count(),
            1
        );
        if matches!(
            scenario,
            "wrong_ref" | "wrong_oid" | "dirty" | "bypass" | "lightweight_tag"
        ) {
            assert!(!marker.exists());
        } else {
            assert!(marker.exists());
        }
    }
}
