//! Canonical pre-push object, proof and clean-source admission regressions.
#![allow(clippy::expect_used)]

use super::repository_root;
use std::{
    fs,
    io::Write as _,
    os::unix::fs::PermissionsExt as _,
    path::Path,
    process::{Command, Output, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
#[allow(clippy::too_many_lines)]
fn pre_push_gate_proves_only_one_clean_checked_out_branch_object() {
    fn git(repo: &Path, arguments: &[&str]) -> Output {
        let output = Command::new("git")
            .args(arguments)
            .current_dir(repo)
            .output()
            .expect("git fixture command starts");
        assert!(
            output.status.success(),
            "git {arguments:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    fn run_hook(
        repo: &Path,
        fake_bin: &Path,
        cargo_log: &Path,
        update: &str,
        mutation_path: Option<&Path>,
        fail_git_status: bool,
    ) -> Output {
        let mut search_path = vec![fake_bin.to_path_buf()];
        search_path.extend(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_default(),
        ));
        let search_path = std::env::join_paths(search_path).expect("fixture PATH is valid");
        let mut command = Command::new("bash");
        command
            .arg(".githooks/pre-push-gate.sh")
            .current_dir(repo)
            .env("PATH", search_path)
            .env("FAKE_CARGO_LOG", cargo_log)
            .env("CARGO_BUILD_TARGET", "fixture-cross")
            .env("CARGO_TARGET_DIR", repo.join("target with spaces"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(path) = mutation_path {
            command.env("FAKE_CARGO_MUTATE_PATH", path);
        }
        if fail_git_status {
            command.env("FAKE_GIT_STATUS_FAIL", "1");
        }
        let mut child = command.spawn().expect("pre-push fixture starts");
        child
            .stdin
            .as_mut()
            .expect("fixture stdin is piped")
            .write_all(update.as_bytes())
            .expect("fixture update is written");
        child.wait_with_output().expect("pre-push fixture exits")
    }

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock follows Unix epoch")
        .as_nanos();
    let fixture_root = std::env::temp_dir().join(format!(
        "cfctl-pre-push-object-binding-{}-{nonce}",
        std::process::id()
    ));
    let repo = fixture_root.join("repo");
    let fake_bin = fixture_root.join("bin");
    let cargo_log = fixture_root.join("cargo.log");
    fs::create_dir_all(repo.join(".githooks")).expect("fixture hook directory is created");
    fs::create_dir_all(&fake_bin).expect("fixture binary directory is created");

    let hook = fs::read_to_string(
        repository_root()
            .expect("repository root is available")
            .join(".githooks/pre-push-gate.sh"),
    )
    .expect("tracked pre-push gate is readable");
    fs::write(repo.join(".githooks/pre-push-gate.sh"), hook)
        .expect("fixture pre-push gate is written");
    let fake_cargo = fake_bin.join("cargo");
    fs::write(
            &fake_cargo,
            r#"#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$FAKE_CARGO_LOG"
[ "$#" = 8 ] && [ "$1 $2 $3 $4 $5 $6 $7" = 'build --locked -p xtask --target fixture-native --target-dir' ] || exit 71
[ ! -f "$FAKE_CARGO_LOG.build-fail" ] || exit 72
mkdir -p "$8/$6/debug"
cat > "$8/$6/debug/xtask" <<'VERIFIER'
#!/bin/sh
set -eu
printf 'xtask %s\n' "$*" >> "$FAKE_CARGO_LOG"
[ "$*" = verify ] || exit 74
[ ! -f "$FAKE_CARGO_LOG.verify-fail" ] || exit 75
if [ -n "${FAKE_CARGO_MUTATE_PATH:-}" ]; then
  printf 'mutated\n' > "$FAKE_CARGO_MUTATE_PATH"
fi
VERIFIER
chmod +x "$8/$6/debug/xtask"
"#,
        )
        .expect("fake cargo is written");
    fs::set_permissions(&fake_cargo, fs::Permissions::from_mode(0o755))
        .expect("fake cargo is executable");
    let fake_rustc = fake_bin.join("rustc");
    fs::write(&fake_rustc, "#!/bin/sh\necho 'host: fixture-native'\n")
        .expect("fake rustc is written");
    fs::set_permissions(&fake_rustc, fs::Permissions::from_mode(0o755))
        .expect("fake rustc is executable");
    let fake_git = fake_bin.join("git");
    fs::write(
        &fake_git,
        "#!/bin/sh\n\
             if [ \"${FAKE_GIT_STATUS_FAIL:-}\" = 1 ]; then\n\
               case \" $* \" in\n\
                 *' status --porcelain=v1 --untracked-files=all '*)\n\
                   echo 'fixture status observation failed' >&2\n\
                   exit 73\n\
                   ;;\n\
               esac\n\
             fi\n\
             PATH=${PATH#*:} exec git \"$@\"\n",
    )
    .expect("fake git is written");
    fs::set_permissions(&fake_git, fs::Permissions::from_mode(0o755))
        .expect("fake git is executable");

    git(&repo, &["init", "-q", "-b", "main"]);
    git(&repo, &["config", "user.name", "cfctl test"]);
    git(
        &repo,
        &["config", "user.email", "cfctl-test@example.invalid"],
    );
    fs::write(repo.join("tracked.txt"), "clean\n").expect("tracked fixture is written");
    fs::write(repo.join(".gitignore"), "/target with spaces/\n").expect("build output is ignored");
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-q", "-m", "clean fixture"]);
    let clean_oid = String::from_utf8(git(&repo, &["rev-parse", "HEAD"]).stdout)
        .expect("fixture oid is UTF-8")
        .trim()
        .to_owned();
    let zero_oid = "0".repeat(clean_oid.len());
    let clean_update = format!("refs/heads/main {clean_oid} refs/heads/main {zero_oid}\n");
    let expected_build = format!(
        "build --locked -p xtask --target fixture-native --target-dir {}\n",
        repo.join("target with spaces").display()
    );
    let expected_proof = format!("{expected_build}xtask verify\n");
    let clean = run_hook(&repo, &fake_bin, &cargo_log, &clean_update, None, false);
    assert!(
        clean.status.success(),
        "one clean checked-out branch object must pass: {}",
        String::from_utf8_lossy(&clean.stderr)
    );
    assert_eq!(
        fs::read_to_string(&cargo_log).expect("fake cargo ran"),
        expected_proof
    );

    for (stage, expected_log) in [
        ("build", expected_build.as_str()),
        ("verify", expected_proof.as_str()),
    ] {
        fs::remove_file(&cargo_log).expect("fixture log is reset");
        let failure = cargo_log.with_extension(format!("log.{stage}-fail"));
        fs::write(&failure, "fail\n").expect("failure is injected");
        let failed = run_hook(&repo, &fake_bin, &cargo_log, &clean_update, None, false);
        assert!(!failed.status.success(), "{stage} failure must refuse push");
        assert!(
            String::from_utf8_lossy(&failed.stderr).contains("xtask build or verification exited")
        );
        assert_eq!(
            fs::read_to_string(&cargo_log).expect("fixture commands were logged"),
            expected_log,
            "a failed build must never execute even an existing verifier"
        );
        fs::remove_file(&failure).expect("injected failure is removed");
    }

    fs::remove_file(&cargo_log).expect("fake cargo log is reset");
    let unobservable = run_hook(&repo, &fake_bin, &cargo_log, &clean_update, None, true);
    assert!(
        !unobservable.status.success(),
        "a failed cleanliness observation must fail closed"
    );
    assert!(
        String::from_utf8_lossy(&unobservable.stderr)
            .contains("could not observe checked-out source cleanliness"),
        "unexpected status-observation error: {}",
        String::from_utf8_lossy(&unobservable.stderr)
    );
    assert!(
        !cargo_log.exists(),
        "an initial status failure must stop before cargo"
    );

    let tracked_path = repo.join("tracked.txt");
    let raced = run_hook(
        &repo,
        &fake_bin,
        &cargo_log,
        &clean_update,
        Some(&tracked_path),
        false,
    );
    assert!(
        !raced.status.success(),
        "source mutation during verification must fail closed"
    );
    assert!(
        String::from_utf8_lossy(&raced.stderr).contains("source changed during verification"),
        "unexpected verification-race error: {}",
        String::from_utf8_lossy(&raced.stderr)
    );
    assert_eq!(
        fs::read_to_string(&cargo_log).expect("fake cargo ran before final rebind"),
        expected_proof
    );
    fs::write(&tracked_path, "clean\n").expect("raced fixture is restored");

    fs::remove_file(&cargo_log).expect("fake cargo log is reset");
    fs::create_dir_all(repo.join(".github/workflows"))
        .expect("workflow fixture directory is created");
    fs::write(
        repo.join(".github/workflows/hosted.yml"),
        "name: forbidden-hosted-proof\n",
    )
    .expect("workflow fixture is written");
    git(&repo, &["add", ".github/workflows/hosted.yml"]);
    git(&repo, &["commit", "-q", "-m", "workflow fixture"]);
    let workflow_oid = String::from_utf8(git(&repo, &["rev-parse", "HEAD"]).stdout)
        .expect("fixture oid is UTF-8")
        .trim()
        .to_owned();
    fs::remove_file(repo.join(".github/workflows/hosted.yml"))
        .expect("workflow is deleted only from the worktree");
    let dirty_update = format!("refs/heads/main {workflow_oid} refs/heads/main {clean_oid}\n");
    let dirty = run_hook(&repo, &fake_bin, &cargo_log, &dirty_update, None, false);
    assert!(!dirty.status.success(), "dirty deletion must fail closed");
    assert!(
        String::from_utf8_lossy(&dirty.stderr).contains("source must be clean"),
        "unexpected dirty-tree error: {}",
        String::from_utf8_lossy(&dirty.stderr)
    );
    assert!(!cargo_log.exists(), "dirty source must fail before cargo");

    fs::write(
        repo.join(".github/workflows/hosted.yml"),
        "name: forbidden-hosted-proof\n",
    )
    .expect("workflow fixture is restored");
    let non_head_update = format!("refs/heads/other {workflow_oid} refs/heads/other {zero_oid}\n");
    let non_head = run_hook(&repo, &fake_bin, &cargo_log, &non_head_update, None, false);
    assert!(
        !non_head.status.success(),
        "non-HEAD refspec must fail closed"
    );
    assert!(
        String::from_utf8_lossy(&non_head.stderr).contains("must equal checked-out HEAD"),
        "unexpected non-HEAD error: {}",
        String::from_utf8_lossy(&non_head.stderr)
    );
    assert!(!cargo_log.exists(), "non-HEAD ref must fail before cargo");

    let multiple_updates = format!(
        "refs/heads/main {workflow_oid} refs/heads/main {clean_oid}\n\
             refs/heads/other {clean_oid} refs/heads/other {zero_oid}\n"
    );
    let multiple = run_hook(&repo, &fake_bin, &cargo_log, &multiple_updates, None, false);
    assert!(
        !multiple.status.success(),
        "multiple distinct pushed objects must fail closed"
    );
    assert!(
        String::from_utf8_lossy(&multiple.stderr).contains("expected exactly one pushed ref"),
        "unexpected multi-ref error: {}",
        String::from_utf8_lossy(&multiple.stderr)
    );
    assert!(!cargo_log.exists(), "multiple refs must fail before cargo");

    fs::remove_dir_all(&fixture_root).expect("fixture is removed");
}
