//! Canonical pre-push object, proof and preserved-residue admission regressions.
#![allow(clippy::expect_used)]

use super::repository_root;
use sha2::{Digest, Sha256};
use std::{
    fmt::Write as _,
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
        if cargo_log.with_extension("log.gate-off").exists() {
            command.env("CFCTL_PRE_PUSH_GATE", "off");
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

    fn declare_residue(repo: &Path, paths: &[&str]) {
        let tree = git(repo, &["ls-tree", "--full-tree", "-r", "-z", "HEAD"]);
        let mut bound = Vec::new();
        for record in tree
            .stdout
            .split(|byte| *byte == 0)
            .filter(|r| !r.is_empty())
        {
            let (_, path) = record.split_at(
                record
                    .iter()
                    .position(|b| *b == b'\t')
                    .expect("tree path tab")
                    + 1,
            );
            if path != b".githooks/pre-push-residue.tsv" {
                bound.extend_from_slice(record);
                bound.push(0);
            }
        }
        let mut declaration = format!(
            "source-tree-sha256 {}\n",
            hex::encode(Sha256::digest(&bound))
        );
        for path in paths {
            let bytes = fs::read(repo.join(path)).expect("fixture residue is readable");
            writeln!(
                declaration,
                "{} {} 644 {path}",
                hex::encode(Sha256::digest(&bytes)),
                bytes.len()
            )
            .expect("format fixture declaration");
        }
        fs::write(repo.join(".githooks/pre-push-residue.tsv"), declaration)
            .expect("fixture residue declaration is written");
        git(repo, &["add", ".githooks/pre-push-residue.tsv"]);
        git(repo, &["commit", "-q", "-m", "classify fixture residue"]);
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
    for path in [
        ".githooks/pre-push-source.sh",
        ".githooks/pre-push-residue.tsv",
    ] {
        fs::copy(repository_root().expect("root").join(path), repo.join(path))
            .expect("fixture source policy is copied");
    }
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
        r#"#!/bin/sh
if [ "${FAKE_GIT_STATUS_FAIL:-}" = 1 ]; then
  case " $* " in
    *' status --porcelain=v1 -z --untracked-files=all '*)
      echo 'fixture status observation failed' >&2; exit 73 ;;
  esac
fi
case " $* " in
  *' ls-tree --full-tree -r -z HEAD '*)
    [ ! -f "$FAKE_CARGO_LOG.tree-fail" ] || exit 76
    [ ! -f "$FAKE_CARGO_LOG.tree-empty" ] || exit 0
    if [ -f "$FAKE_CARGO_LOG.tree-partial" ]; then printf 'incomplete'; exit 0; fi
    if [ -f "$FAKE_CARGO_LOG.tree-malformed" ]; then printf 'malformed\0'; exit 0; fi
    ;;
esac
PATH=${PATH#*:} exec git "$@"
"#,
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

    // These are the real classified paths, with synthetic fixture contents.
    // Their own ignore rule must not conceal an extra input from admission.
    let residue_paths = [
        "experiments/ai-search/.gitignore",
        "experiments/ai-search/README.md",
        "experiments/ai-search/captures.empty.json",
        "experiments/ai-search/cases.json",
        "experiments/ai-search/evaluate.ts",
        "experiments/ai-search/external.ts",
        "experiments/ai-search/pilot.test.ts",
        "experiments/ai-search/search.ts",
        "experiments/ai-search/wrangler.fragment.jsonc",
    ];
    fs::create_dir_all(repo.join("experiments/ai-search")).expect("fixture residue root");
    for path in &residue_paths {
        fs::write(repo.join(path), format!("fixture {path}\n")).expect("fixture residue");
        fs::set_permissions(repo.join(path), fs::Permissions::from_mode(0o644))
            .expect("fixture mode");
    }
    fs::write(repo.join(residue_paths[0]), "reports/\n").expect("fixture ignore rule");
    declare_residue(&repo, &residue_paths);
    let residue_oid = String::from_utf8(git(&repo, &["rev-parse", "HEAD"]).stdout)
        .expect("fixture HEAD")
        .trim()
        .to_owned();
    let residue_update = format!("refs/heads/main {residue_oid} refs/heads/main {zero_oid}\n");
    let preserved: Vec<_> = residue_paths
        .iter()
        .map(|p| fs::read(repo.join(p)).expect("preimage"))
        .collect();
    fs::remove_file(&cargo_log).expect("reset proof log");
    let classified = run_hook(&repo, &fake_bin, &cargo_log, &residue_update, None, false);
    assert!(
        classified.status.success(),
        "exact classified residue: {}",
        String::from_utf8_lossy(&classified.stderr)
    );
    assert_eq!(
        fs::read_to_string(&cargo_log).expect("proof ran"),
        expected_proof
    );
    assert!(String::from_utf8_lossy(&classified.stdout).contains("not a clean checkout"));
    for (path, bytes) in residue_paths.iter().zip(&preserved) {
        assert_eq!(&fs::read(repo.join(path)).expect("postimage"), bytes);
    }

    for failure in [
        "tree-fail",
        "tree-empty",
        "tree-partial",
        "tree-malformed",
        "gate-off",
    ] {
        fs::remove_file(&cargo_log).expect("reset proof log");
        let marker = cargo_log.with_extension(format!("log.{failure}"));
        fs::write(&marker, "fail\n").expect("observation failure marker");
        let rejected = run_hook(&repo, &fake_bin, &cargo_log, &residue_update, None, false);
        assert!(!rejected.status.success(), "{failure} must refuse");
        assert!(!cargo_log.exists(), "{failure} must stop before cargo");
        fs::remove_file(marker).expect("remove owned marker");
        // Supply a log for the next iteration's reset without running Cargo.
        fs::write(&cargo_log, "reset\n").expect("reset marker");
    }
    fs::remove_file(&cargo_log).expect("reset proof log");
    fs::write(&tracked_path, "staged input\n").expect("stage fixture dirt");
    git(&repo, &["add", "tracked.txt"]);
    fs::write(&tracked_path, "clean\n").expect("restore only worktree");
    assert!(
        !run_hook(&repo, &fake_bin, &cargo_log, &residue_update, None, false)
            .status
            .success()
    );
    assert!(
        !cargo_log.exists(),
        "index dirt must stop before cargo even when worktree equals HEAD"
    );
    git(&repo, &["add", "tracked.txt"]);

    let declaration_path = repo.join(".githooks/pre-push-residue.tsv");
    let valid_declaration = fs::read_to_string(&declaration_path).expect("valid declaration");
    let first_entry = valid_declaration.lines().nth(1).expect("first entry");
    for invalid in [
        format!("{valid_declaration}source-tree-sha256 bad\n"),
        format!("{valid_declaration}{first_entry}\n"),
        valid_declaration.replacen(" 644 ", " 755 ", 1),
        valid_declaration.replacen("source-tree-sha256", "unknown-schema", 1),
        valid_declaration.replacen("source-tree-sha256 ", "source-tree-sha256 malformed", 1),
        valid_declaration.replacen("experiments/ai-search/.gitignore", "../outside", 1),
    ] {
        fs::write(&declaration_path, invalid).expect("invalid fixture declaration");
        git(&repo, &["add", ".githooks/pre-push-residue.tsv"]);
        git(
            &repo,
            &["commit", "-q", "-m", "invalid declaration fixture"],
        );
        let oid = String::from_utf8(git(&repo, &["rev-parse", "HEAD"]).stdout)
            .expect("HEAD")
            .trim()
            .to_owned();
        let update = format!("refs/heads/main {oid} refs/heads/main {zero_oid}\n");
        assert!(
            !run_hook(&repo, &fake_bin, &cargo_log, &update, None, false)
                .status
                .success()
        );
        assert!(
            !cargo_log.exists(),
            "malformed declarations stop before cargo"
        );
    }
    fs::write(&declaration_path, valid_declaration).expect("restore valid declaration");
    git(&repo, &["add", ".githooks/pre-push-residue.tsv"]);
    git(
        &repo,
        &["commit", "-q", "-m", "restore fixture declaration"],
    );
    let residue_oid = String::from_utf8(git(&repo, &["rev-parse", "HEAD"]).stdout)
        .expect("HEAD")
        .trim()
        .to_owned();
    let residue_update = format!("refs/heads/main {residue_oid} refs/heads/main {zero_oid}\n");
    fs::write(&cargo_log, "reset\n").expect("reset marker");

    // Each failure must stop before even the verifier build.
    for extra in [
        "untracked.rs",
        "experiments/ai-search/extra.ts",
        "experiments/ai-search/reports/hidden.json",
    ] {
        let extra = repo.join(extra);
        fs::create_dir_all(extra.parent().expect("extra parent")).expect("extra directory");
        fs::write(&extra, "undeclared\n").expect("extra fixture");
        if cargo_log.exists() {
            fs::remove_file(&cargo_log).expect("reset proof log");
        }
        let rejected = run_hook(&repo, &fake_bin, &cargo_log, &residue_update, None, false);
        assert!(
            !rejected.status.success(),
            "extra path must fail: {}",
            extra.display()
        );
        assert!(!cargo_log.exists(), "extra input must stop before cargo");
        fs::remove_file(&extra).expect("remove owned extra");
        if extra.parent().expect("parent").ends_with("reports") {
            fs::remove_dir(extra.parent().expect("parent")).expect("remove owned extra directory");
        }
    }
    let residue_path = repo.join(residue_paths[1]);
    let special = repo.join("experiments/ai-search/special");
    assert!(
        Command::new("mkfifo")
            .arg(&special)
            .status()
            .expect("fixture FIFO")
            .success()
    );
    assert!(
        !run_hook(&repo, &fake_bin, &cargo_log, &residue_update, None, false)
            .status
            .success()
    );
    assert!(!cargo_log.exists(), "special file stops before hash/build");
    fs::remove_file(special).expect("remove owned FIFO");
    for changed in [b"changed\n".as_slice(), b"".as_slice()] {
        fs::write(&residue_path, changed).expect("alter fixture content");
        assert!(
            !run_hook(&repo, &fake_bin, &cargo_log, &residue_update, None, false)
                .status
                .success()
        );
        assert!(!cargo_log.exists());
    }
    fs::remove_file(&residue_path).expect("remove owned fixture");
    assert!(
        !run_hook(&repo, &fake_bin, &cargo_log, &residue_update, None, false)
            .status
            .success()
    );
    fs::write(&residue_path, &preserved[1]).expect("restore fixture");
    fs::set_permissions(&residue_path, fs::Permissions::from_mode(0o600))
        .expect("alter fixture mode");
    assert!(
        !run_hook(&repo, &fake_bin, &cargo_log, &residue_update, None, false)
            .status
            .success()
    );
    fs::set_permissions(&residue_path, fs::Permissions::from_mode(0o644))
        .expect("restore fixture mode");
    fs::remove_file(&residue_path).expect("replace owned fixture with link");
    std::os::unix::fs::symlink(repo.join(residue_paths[2]), &residue_path)
        .expect("fixture symlink");
    assert!(
        !run_hook(&repo, &fake_bin, &cargo_log, &residue_update, None, false)
            .status
            .success()
    );
    fs::remove_file(&residue_path).expect("remove owned symlink");
    fs::write(&residue_path, &preserved[1]).expect("restore fixture");
    assert!(
        !cargo_log.exists(),
        "all residue mismatch cases stop before cargo"
    );

    fs::rename(
        repo.join("experiments"),
        fixture_root.join("held-experiments"),
    )
    .expect("hold only fixture directory");
    std::os::unix::fs::symlink(
        fixture_root.join("held-experiments"),
        repo.join("experiments"),
    )
    .expect("fixture root symlink");
    assert!(
        !run_hook(&repo, &fake_bin, &cargo_log, &residue_update, None, false)
            .status
            .success()
    );
    assert!(!cargo_log.exists(), "root symlink must not be traversed");
    fs::remove_file(repo.join("experiments")).expect("remove owned root symlink");
    fs::rename(
        fixture_root.join("held-experiments"),
        repo.join("experiments"),
    )
    .expect("restore only fixture directory");

    let drifted = run_hook(
        &repo,
        &fake_bin,
        &cargo_log,
        &residue_update,
        Some(&residue_path),
        false,
    );
    assert!(
        !drifted.status.success(),
        "residue content drift during proof must fail"
    );
    assert_eq!(
        fs::read_to_string(&cargo_log).expect("proof ran"),
        expected_proof
    );
    fs::write(&residue_path, &preserved[1]).expect("restore fixture bytes");

    // Only the declaration is excluded from its own tree pin. Helper changes
    // are bound even when they are harmless comments and all residue matches.
    let helper_path = repo.join(".githooks/pre-push-source.sh");
    let helper = fs::read_to_string(&helper_path).expect("fixture helper");
    fs::write(&helper_path, format!("{helper}\n# changed helper input\n")).expect("change helper");
    git(&repo, &["add", ".githooks/pre-push-source.sh"]);
    git(
        &repo,
        &["commit", "-q", "-m", "change bound helper fixture"],
    );
    let oid = String::from_utf8(git(&repo, &["rev-parse", "HEAD"]).stdout)
        .expect("HEAD")
        .trim()
        .to_owned();
    let update = format!("refs/heads/main {oid} refs/heads/main {zero_oid}\n");
    fs::remove_file(&cargo_log).expect("reset proof log");
    let rejected = run_hook(&repo, &fake_bin, &cargo_log, &update, None, false);
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("proof input tree changed"));
    assert!(!cargo_log.exists(), "helper must stay bound by the pin");
    fs::write(&helper_path, helper).expect("restore helper");
    git(&repo, &["add", ".githooks/pre-push-source.sh"]);
    git(
        &repo,
        &["commit", "-q", "-m", "restore bound helper fixture"],
    );
    fs::write(&cargo_log, "reset\n").expect("reset marker");

    // The pin prevents a future root-wide test runner or import/include from
    // silently consuming files admitted under the reviewed old discovery graph.
    fs::write(&tracked_path, "changed input graph\n").expect("change tracked input");
    git(&repo, &["add", "tracked.txt"]);
    git(&repo, &["commit", "-q", "-m", "change proof input graph"]);
    let changed_oid = String::from_utf8(git(&repo, &["rev-parse", "HEAD"]).stdout)
        .expect("HEAD")
        .trim()
        .to_owned();
    let changed_update = format!("refs/heads/main {changed_oid} refs/heads/main {zero_oid}\n");
    fs::remove_file(&cargo_log).expect("reset proof log");
    let rejected = run_hook(&repo, &fake_bin, &cargo_log, &changed_update, None, false);
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("proof input tree changed"));
    assert!(
        !cargo_log.exists(),
        "new tracked inputs invalidate classification before build"
    );

    // Return to the strict no-residue path for the existing object-binding cases.
    fs::remove_dir_all(repo.join("experiments")).expect("remove only owned fixture residue");

    if cargo_log.exists() {
        fs::remove_file(&cargo_log).expect("fake cargo log is reset");
    }
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
