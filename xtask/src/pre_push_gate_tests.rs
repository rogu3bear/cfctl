#![allow(clippy::expect_used)]

use std::{
    fs,
    io::Write as _,
    os::unix::fs::PermissionsExt as _,
    path::Path,
    process::{Command, Output, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

use super::repository_root;

#[test]
#[allow(clippy::too_many_lines)]
fn pre_push_gate_proves_only_one_clean_checked_out_branch_object() {
    struct Fixture {
        repo: std::path::PathBuf,
        fake_bin: std::path::PathBuf,
        cargo_log: std::path::PathBuf,
        git_log: std::path::PathBuf,
        git_local_env_file: std::path::PathBuf,
        common_git_dir: std::path::PathBuf,
        worktree_git_dir: std::path::PathBuf,
        head_oid: String,
        zero_oid: String,
    }

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

    fn fixture(parent: &Path, name: &str, hook: &str) -> Fixture {
        let root = parent.join(name);
        let repo = root.join("repo");
        let fake_bin = root.join("bin");
        let cargo_log = root.join("cargo.log");
        let git_log = root.join("git.log");
        let git_local_env_file = root.join("git-local-env-vars.txt");
        let common_git_dir = root.join("common-git");
        let worktree_git_dir = root.join("worktree-git");
        fs::create_dir_all(repo.join(".githooks")).expect("fixture hook directory is created");
        fs::create_dir_all(&fake_bin).expect("fixture binary directory is created");
        fs::create_dir_all(&common_git_dir).expect("fixture common Git directory is created");
        fs::create_dir_all(&worktree_git_dir).expect("fixture worktree Git directory is created");
        fs::write(repo.join(".githooks/pre-push-gate.sh"), hook)
            .expect("fixture pre-push gate is written");

        let fake_cargo = fake_bin.join("cargo");
        fs::write(
            &fake_cargo,
            "#!/bin/sh\n\
                 printf '%s\\n' \"$*\" >> \"$FAKE_CARGO_LOG\"\n\
                 while IFS= read -r git_local_name; do\n\
                   if env | grep -q \"^${git_local_name}=\"; then\n\
                     echo \"fixture detected leaked Git local env: $git_local_name\" >&2\n\
                     exit 41\n\
                   fi\n\
                 done < \"$FAKE_GIT_LOCAL_ENV_FILE\"\n\
                 case \"${FAKE_CARGO_ACTION:-pass}\" in\n\
                   pass) ;;\n\
                   fail) echo 'fixture verify failed' >&2; exit 42 ;;\n\
                   dirty) printf 'mutated\\n' > \"$FAKE_REPO_TRACKED\" ;;\n\
                   post-lock) : > \"$FAKE_POST_GIT_MARKER\" ;;\n\
               head-drift)\n\
                 printf 'committed drift\\n' > \"$FAKE_REPO_TRACKED\"\n\
                 PATH=${PATH#*:} git add tracked.txt\n\
                 PATH=${PATH#*:} git commit -q -m 'proof drift'\n\
                 ;;\n\
               *) echo \"unknown fake cargo action: $FAKE_CARGO_ACTION\" >&2; exit 97 ;;\n\
             esac\n",
        )
        .expect("fake cargo is written");
        fs::set_permissions(&fake_cargo, fs::Permissions::from_mode(0o755))
            .expect("fake cargo is executable");

        let fake_git = fake_bin.join("git");
        fs::write(
            &fake_git,
            "#!/bin/sh\n\
                 printf '%s\\n' \"$*\" >> \"$FAKE_GIT_LOG\"\n\
                 if [ \"${FAKE_GIT_DISTINCT_PLANES:-0}\" = 1 ] &&\n\
                    [ \"${1:-}\" = rev-parse ] &&\n\
                    [ \"${2:-}\" = --path-format=absolute ]; then\n\
                   case \"${3:-}\" in\n\
                     --git-dir) printf '%s\\n' \"$FAKE_GIT_WORKTREE_DIR\"; exit 0 ;;\n\
                     --git-common-dir) printf '%s\\n' \"$FAKE_GIT_COMMON_DIR\"; exit 0 ;;\n\
                     --git-path) printf '%s/%s\\n' \"$FAKE_GIT_WORKTREE_DIR\" \"${4:-}\"; exit 0 ;;\n\
                   esac\n\
                 fi\n\
             case \"${1:-}\" in\n\
               worktree|checkout|switch|stash|reset|clean)\n\
                 echo \"fixture rejected forbidden git mutator: $1\" >&2\n\
                 exit 86\n\
                 ;;\n\
             esac\n\
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
        git(&repo, &["add", ".githooks/pre-push-gate.sh", "tracked.txt"]);
        git(&repo, &["commit", "-q", "-m", "clean fixture"]);
        let head_oid = String::from_utf8(git(&repo, &["rev-parse", "HEAD"]).stdout)
            .expect("fixture oid is UTF-8")
            .trim()
            .to_owned();
        let zero_oid = "0".repeat(head_oid.len());
        let mut local_env_vars =
            String::from_utf8(git(&repo, &["rev-parse", "--local-env-vars"]).stdout)
                .expect("Git local environment names are UTF-8");
        local_env_vars.push_str("GIT_QUARANTINE_PATH\nGIT_CEILING_DIRECTORIES\n");
        fs::write(&git_local_env_file, local_env_vars)
            .expect("Git local environment contract is written");

        Fixture {
            repo,
            fake_bin,
            cargo_log,
            git_log,
            git_local_env_file,
            common_git_dir,
            worktree_git_dir,
            head_oid,
            zero_oid,
        }
    }

    fn update(local_ref: &str, local_oid: &str, remote_ref: &str, remote_oid: &str) -> String {
        format!("{local_ref} {local_oid} {remote_ref} {remote_oid}\n")
    }

    fn run_hook(fixture: &Fixture, update: &str, cargo_action: &str) -> Output {
        run_hook_with_planes(fixture, update, cargo_action, false)
    }

    fn run_hook_with_planes(
        fixture: &Fixture,
        update: &str,
        cargo_action: &str,
        distinct_git_planes: bool,
    ) -> Output {
        let mut search_path = vec![fixture.fake_bin.clone()];
        search_path.extend(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_default(),
        ));
        let search_path = std::env::join_paths(search_path).expect("fixture PATH is valid");
        let mut command = Command::new("bash");
        command
            .arg(".githooks/pre-push-gate.sh")
            .current_dir(&fixture.repo)
            .env("PATH", search_path)
            .env("FAKE_CARGO_LOG", &fixture.cargo_log)
            .env("FAKE_CARGO_ACTION", cargo_action)
            .env("FAKE_GIT_LOG", &fixture.git_log)
            .env("FAKE_GIT_LOCAL_ENV_FILE", &fixture.git_local_env_file)
            .env("FAKE_REPO_TRACKED", fixture.repo.join("tracked.txt"))
            .env(
                "FAKE_POST_GIT_MARKER",
                fixture.repo.join(".git/during-proof.lock"),
            )
            .env("GIT_CONFIG_COUNT", "0")
            .env("GIT_IMPLICIT_WORK_TREE", "1")
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env("GIT_REPLACE_REF_BASE", "refs/replace/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if distinct_git_planes {
            command
                .env("FAKE_GIT_DISTINCT_PLANES", "1")
                .env("FAKE_GIT_COMMON_DIR", &fixture.common_git_dir)
                .env("FAKE_GIT_WORKTREE_DIR", &fixture.worktree_git_dir);
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

    fn assert_refused_before_cargo(output: &Output, fixture: &Fixture, reason: &str) {
        assert!(
            !output.status.success(),
            "{reason} must fail closed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !fixture.cargo_log.exists(),
            "{reason} must be rejected before cargo"
        );
    }

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock follows Unix epoch")
        .as_nanos();
    let fixture_root = std::env::temp_dir().join(format!(
        "cfctl-pre-push-object-binding-{}-{nonce}",
        std::process::id()
    ));
    let hook = fs::read_to_string(
        repository_root()
            .expect("repository root is available")
            .join(".githooks/pre-push-gate.sh"),
    )
    .expect("tracked pre-push gate is readable");
    let local_env_contract = git(
        &fixture(&fixture_root, "env-contract", &hook).repo,
        &["rev-parse", "--local-env-vars"],
    );
    let local_env_contract = String::from_utf8(local_env_contract.stdout)
        .expect("Git local environment contract is UTF-8");
    for representative in [
        "GIT_CONFIG_COUNT",
        "GIT_IMPLICIT_WORK_TREE",
        "GIT_NO_REPLACE_OBJECTS",
        "GIT_REPLACE_REF_BASE",
    ] {
        assert!(
            local_env_contract
                .lines()
                .any(|name| name == representative),
            "representative omitted variable {representative} must come from Git"
        );
    }

    let clean_fixture = fixture(&fixture_root, "clean", &hook);
    let clean_update = update(
        "refs/heads/main",
        &clean_fixture.head_oid,
        "refs/heads/main",
        &clean_fixture.zero_oid,
    );
    let clean = run_hook(&clean_fixture, &clean_update, "pass");
    assert!(
        clean.status.success(),
        "one clean checked-out branch object must pass: {}",
        String::from_utf8_lossy(&clean.stderr)
    );
    assert_eq!(
        fs::read_to_string(&clean_fixture.cargo_log).expect("fake cargo ran"),
        "xtask verify\n"
    );
    let git_calls = fs::read_to_string(&clean_fixture.git_log).expect("fake git log exists");
    for forbidden in ["worktree", "checkout", "switch", "stash", "reset", "clean"] {
        assert!(
            !git_calls
                .lines()
                .any(|line| line.split_whitespace().next() == Some(forbidden)),
            "clean proof invoked forbidden git mutator {forbidden}: {git_calls}"
        );
    }

    let empty_fixture = fixture(&fixture_root, "empty-stdin", &hook);
    let empty = run_hook(&empty_fixture, "", "pass");
    assert_refused_before_cargo(&empty, &empty_fixture, "empty pre-push input");
    assert!(
        String::from_utf8_lossy(&empty.stderr).contains("expected exactly one pushed ref"),
        "unexpected empty-input error: {}",
        String::from_utf8_lossy(&empty.stderr)
    );

    let malformed_fixture = fixture(&fixture_root, "malformed-stdin", &hook);
    let malformed_update = format!(
        "{} extra-field\n",
        update(
            "refs/heads/main",
            &malformed_fixture.head_oid,
            "refs/heads/main",
            &malformed_fixture.zero_oid,
        )
        .trim_end()
    );
    let malformed = run_hook(&malformed_fixture, &malformed_update, "pass");
    assert_refused_before_cargo(&malformed, &malformed_fixture, "malformed pre-push input");
    assert!(
        String::from_utf8_lossy(&malformed.stderr).contains("malformed pre-push ref update"),
        "unexpected malformed-input error: {}",
        String::from_utf8_lossy(&malformed.stderr)
    );

    let detached_fixture = fixture(&fixture_root, "detached-head", &hook);
    git(
        &detached_fixture.repo,
        &[
            "update-ref",
            "--no-deref",
            "HEAD",
            &detached_fixture.head_oid,
        ],
    );
    let detached_update = update(
        "refs/heads/main",
        &detached_fixture.head_oid,
        "refs/heads/main",
        &detached_fixture.zero_oid,
    );
    let detached = run_hook(&detached_fixture, &detached_update, "pass");
    assert_refused_before_cargo(&detached, &detached_fixture, "detached HEAD");
    assert!(
        String::from_utf8_lossy(&detached.stderr).contains("must equal the checked-out HEAD"),
        "unexpected detached-HEAD error: {}",
        String::from_utf8_lossy(&detached.stderr)
    );

    let dirty_fixture = fixture(&fixture_root, "dirty", &hook);
    fs::write(dirty_fixture.repo.join("untracked.txt"), "dirty\n")
        .expect("dirty fixture is written");
    let dirty_update = update(
        "refs/heads/main",
        &dirty_fixture.head_oid,
        "refs/heads/main",
        &dirty_fixture.zero_oid,
    );
    let dirty = run_hook(&dirty_fixture, &dirty_update, "pass");
    assert_refused_before_cargo(&dirty, &dirty_fixture, "dirty checkout");
    assert!(
        String::from_utf8_lossy(&dirty.stderr).contains("source must be clean"),
        "unexpected dirty-tree error: {}",
        String::from_utf8_lossy(&dirty.stderr)
    );

    let mismatch_fixture = fixture(&fixture_root, "mismatch", &hook);
    let unproved_oid = "1".repeat(mismatch_fixture.head_oid.len());
    let mismatch_update = update(
        "refs/heads/main",
        &unproved_oid,
        "refs/heads/main",
        &mismatch_fixture.zero_oid,
    );
    let mismatch = run_hook(&mismatch_fixture, &mismatch_update, "pass");
    assert_refused_before_cargo(&mismatch, &mismatch_fixture, "unproved source object");
    assert!(
        String::from_utf8_lossy(&mismatch.stderr).contains("must equal the checked-out HEAD"),
        "unexpected source-object error: {}",
        String::from_utf8_lossy(&mismatch.stderr)
    );

    let verify_failure_fixture = fixture(&fixture_root, "verify-failure", &hook);
    let verify_failure_update = update(
        "refs/heads/main",
        &verify_failure_fixture.head_oid,
        "refs/heads/main",
        &verify_failure_fixture.zero_oid,
    );
    let verify_failure = run_hook(&verify_failure_fixture, &verify_failure_update, "fail");
    assert!(
        !verify_failure.status.success(),
        "verification failure must fail closed"
    );
    assert!(
        String::from_utf8_lossy(&verify_failure.stderr).contains("cargo xtask verify exited 42"),
        "unexpected verification error: {}",
        String::from_utf8_lossy(&verify_failure.stderr)
    );
    assert_eq!(
        fs::read_to_string(&verify_failure_fixture.cargo_log).expect("failed fake cargo ran once"),
        "xtask verify\n"
    );

    for (name, cargo_action) in [("dirt-drift", "dirty"), ("head-drift", "head-drift")] {
        let drift_fixture = fixture(&fixture_root, name, &hook);
        let drift_update = update(
            "refs/heads/main",
            &drift_fixture.head_oid,
            "refs/heads/main",
            &drift_fixture.zero_oid,
        );
        let drift = run_hook(&drift_fixture, &drift_update, cargo_action);
        assert!(
            !drift.status.success(),
            "post-proof {name} must fail closed"
        );
        assert!(
            String::from_utf8_lossy(&drift.stderr)
                .contains("checked-out HEAD, tree, or source changed during verification"),
            "unexpected {name} error: {}",
            String::from_utf8_lossy(&drift.stderr)
        );
        assert_eq!(
            fs::read_to_string(&drift_fixture.cargo_log)
                .expect("fake cargo ran before post-proof rebind"),
            "xtask verify\n"
        );
    }

    let post_lock_fixture = fixture(&fixture_root, "post-proof-lock", &hook);
    let post_lock_update = update(
        "refs/heads/main",
        &post_lock_fixture.head_oid,
        "refs/heads/main",
        &post_lock_fixture.zero_oid,
    );
    let post_lock = run_hook(&post_lock_fixture, &post_lock_update, "post-lock");
    assert!(
        !post_lock.status.success(),
        "a lock introduced during proof must fail closed"
    );
    assert!(
        String::from_utf8_lossy(&post_lock.stderr).contains("Git operation or lock is active"),
        "unexpected post-proof lock error: {}",
        String::from_utf8_lossy(&post_lock.stderr)
    );
    assert_eq!(
        fs::read_to_string(&post_lock_fixture.cargo_log)
            .expect("fake cargo ran before post-proof lock check"),
        "xtask verify\n"
    );

    for (name, marker) in [("lock", "index.lock"), ("operation", "MERGE_HEAD")] {
        let blocked_fixture = fixture(&fixture_root, name, &hook);
        fs::write(
            blocked_fixture.repo.join(".git").join(marker),
            format!("{}\n", blocked_fixture.head_oid),
        )
        .expect("Git blocker marker is written");
        let blocked_update = update(
            "refs/heads/main",
            &blocked_fixture.head_oid,
            "refs/heads/main",
            &blocked_fixture.zero_oid,
        );
        let blocked = run_hook(&blocked_fixture, &blocked_update, "pass");
        assert_refused_before_cargo(&blocked, &blocked_fixture, name);
        assert!(
            String::from_utf8_lossy(&blocked.stderr).contains("Git operation or lock is active"),
            "unexpected {name} error: {}",
            String::from_utf8_lossy(&blocked.stderr)
        );
    }

    for (name, common_plane) in [
        ("distinct-common-lock", true),
        ("distinct-worktree-lock", false),
    ] {
        let plane_fixture = fixture(&fixture_root, name, &hook);
        let lock_dir = if common_plane {
            &plane_fixture.common_git_dir
        } else {
            &plane_fixture.worktree_git_dir
        };
        fs::write(lock_dir.join("held.lock"), "held\n")
            .expect("distinct Git-plane lock is written");
        let plane_update = update(
            "refs/heads/main",
            &plane_fixture.head_oid,
            "refs/heads/main",
            &plane_fixture.zero_oid,
        );
        let plane_blocked = run_hook_with_planes(&plane_fixture, &plane_update, "pass", true);
        assert_refused_before_cargo(&plane_blocked, &plane_fixture, name);
        assert!(
            String::from_utf8_lossy(&plane_blocked.stderr)
                .contains("Git operation or lock is active"),
            "unexpected {name} error: {}",
            String::from_utf8_lossy(&plane_blocked.stderr)
        );
    }

    let deletion_fixture = fixture(&fixture_root, "deletion", &hook);
    let deletion_update = update(
        "(delete)",
        &deletion_fixture.zero_oid,
        "refs/heads/main",
        &deletion_fixture.head_oid,
    );
    let deletion = run_hook(&deletion_fixture, &deletion_update, "pass");
    assert_refused_before_cargo(&deletion, &deletion_fixture, "branch deletion");

    let multiple_fixture = fixture(&fixture_root, "multiple", &hook);
    let multiple_updates = format!(
        "{}{}",
        update(
            "refs/heads/main",
            &multiple_fixture.head_oid,
            "refs/heads/main",
            &multiple_fixture.zero_oid,
        ),
        update(
            "refs/heads/other",
            &multiple_fixture.head_oid,
            "refs/heads/other",
            &multiple_fixture.zero_oid,
        )
    );
    let multiple = run_hook(&multiple_fixture, &multiple_updates, "pass");
    assert_refused_before_cargo(&multiple, &multiple_fixture, "multiple pushed refs");
    assert!(
        String::from_utf8_lossy(&multiple.stderr).contains("expected exactly one pushed ref"),
        "unexpected multi-ref error: {}",
        String::from_utf8_lossy(&multiple.stderr)
    );

    let tag_fixture = fixture(&fixture_root, "annotated-tag", &hook);
    git(&tag_fixture.repo, &["tag", "-a", "v1", "-m", "fixture tag"]);
    let tag_oid = String::from_utf8(git(&tag_fixture.repo, &["rev-parse", "v1"]).stdout)
        .expect("annotated tag oid is UTF-8")
        .trim()
        .to_owned();
    let tag_update = update(
        "refs/tags/v1",
        &tag_oid,
        "refs/tags/v1",
        &tag_fixture.zero_oid,
    );
    let tag = run_hook(&tag_fixture, &tag_update, "pass");
    assert_refused_before_cargo(&tag, &tag_fixture, "annotated tag push");

    for forbidden in [
        "git worktree",
        "git checkout",
        "git switch",
        "git stash",
        "git reset",
        "git clean",
    ] {
        assert!(
            !hook.contains(forbidden),
            "pre-push gate contains forbidden mutator {forbidden}"
        );
    }

    fs::remove_dir_all(&fixture_root).expect("fixture is removed");
}
