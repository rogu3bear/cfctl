//! Local verification and release orchestration for cfctl.

mod local_adapters;
mod local_guidance;

use local_adapters::LOCAL_OPERATOR_ADAPTERS;
use local_guidance::verify_active_guidance_has_no_v1_commands;
use std::{
    collections::BTreeSet,
    env,
    fmt::Write as _,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
    time::{SystemTime, UNIX_EPOCH},
};

use cfctl_core::{
    GuideTopicV1, PUBLIC_V2_COMMAND_TREE, PUBLIC_V2_SUBCOMMANDS, RETIRED_V1_PUBLIC_VERBS,
    RETIRED_V1_SURFACES, render_guide_topic_markdown,
};
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use thiserror::Error;

const RELEASE_TARGETS: [&str; 4] = [
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "aarch64-unknown-linux-musl",
    "x86_64-unknown-linux-musl",
];
const MACOS_RELEASE_TARGETS: [&str; 2] = ["aarch64-apple-darwin", "x86_64-apple-darwin"];
/// The Linux target `verify` cross-builds. One representative musl arch is
/// enough to prove libc/dependency portability of a change (the code is
/// arch-independent; the libc is the variable); `release` still builds both
/// musl arches reproducibly. Must be one of `RELEASE_TARGETS`.
const VERIFY_CROSS_TARGET: &str = "x86_64-unknown-linux-musl";
const CARGO_AUDITABLE_VERSION: &str = "0.7.5";
const GITHUB_REPOSITORY: &str = "rogu3bear/cfctl";
#[derive(Debug, Parser)]
#[command(name = "cargo xtask")]
struct Arguments {
    #[command(subcommand)]
    command: Task,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReleaseTrustRoots {
    macos_signing_identity: String,
    macos_team_identifier: String,
    macos_certificate_sha1: String,
    macos_certificate_sha256: String,
    certificate_identity: String,
    certificate_oidc_issuer: String,
}

#[derive(Debug, Subcommand)]
enum Task {
    /// Run the complete local source proof lane.
    Verify,
    /// Build reproducible binaries, SBOMs, provenance, and installers without signing.
    Assemble {
        #[arg(long = "target", value_delimiter = ',')]
        targets: Vec<String>,
    },
    /// Build, inventory, checksum, sign, and identity-verify all four platforms.
    Release {
        #[arg(long)]
        certificate_identity: String,
        #[arg(long)]
        certificate_oidc_issuer: String,
        #[arg(long)]
        macos_signing_identity: String,
        #[arg(long)]
        apple_notary_profile: String,
    },
    /// Upload already-built signed artifacts to an existing GitHub release.
    Publish {
        #[arg(long)]
        tag: String,
        #[arg(long)]
        certificate_identity: String,
        #[arg(long)]
        certificate_oidc_issuer: String,
        #[arg(long)]
        macos_signing_identity: String,
    },
}

#[derive(Debug, Error)]
enum TaskError {
    #[error("command failed: {0}")]
    Command(String),
    #[error("I/O failed for {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("clock is before the Unix epoch")]
    Clock,
    #[error("no release artifacts exist under dist/")]
    MissingArtifacts,
    #[error("release build for {target} was not reproducible: {first} != {second}")]
    ReproducibilityMismatch {
        target: String,
        first: String,
        second: String,
    },
    #[error("Homebrew formula template still contains an unresolved placeholder")]
    FormulaPlaceholder,
    #[error("Linux installer template is invalid: {0}")]
    InstallerTemplate(String),
    #[error("release target `{0}` is not one of the four reviewed platforms")]
    UnsupportedReleaseTarget(String),
    #[error("release target `{0}` was requested more than once")]
    DuplicateReleaseTarget(String),
    #[error("Rust standard library for release target `{0}` is not installed")]
    MissingRustTarget(String),
    #[error("SOURCE_DATE_EPOCH must be an unsigned Unix timestamp, got `{0}`")]
    InvalidSourceDateEpoch(String),
    #[error("release signing requires a clean source tree; commit or remove these changes:\n{0}")]
    UncleanSourceTree(String),
    #[error(
        "signed release artifact set is incomplete or contaminated; missing: [{missing}]; unexpected: [{unexpected}]"
    )]
    ReleaseArtifactSet { missing: String, unexpected: String },
    #[error("SHA256SUMS does not exactly match the release artifacts")]
    ChecksumManifestMismatch,
    #[error("release artifact must be a regular file: {0}")]
    InvalidReleaseArtifact(String),
    #[error("release provenance is invalid: {0}")]
    InvalidProvenance(String),
    #[error("macOS distribution signature is invalid: {0}")]
    InvalidMacosSignature(String),
    #[error("Apple notarization receipt is invalid: {0}")]
    InvalidNotarizationReceipt(String),
    #[error("release tag `{actual}` must exactly match `{expected}`")]
    ReleaseTagMismatch { actual: String, expected: String },
    #[error(
        "release tag `{tag}` resolves to {tag_commit}, but provenance binds {provenance_commit}"
    )]
    ReleaseCommitMismatch {
        tag: String,
        tag_commit: String,
        provenance_commit: String,
    },
    #[error("GitHub release `{0}` must remain a draft while artifacts are uploaded")]
    ReleaseMustBeDraft(String),
    #[error("GitHub draft release `{tag}` already has assets: {assets}")]
    ReleaseAlreadyHasAssets { tag: String, assets: String },
    #[error("release upload failed: {upload}; compensation failures: {rollback}")]
    PublishFailed { upload: String, rollback: String },
    #[error("source contract is invalid: {0}")]
    InvalidSourceContract(String),
}

fn main() -> ExitCode {
    match execute(Arguments::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _result = writeln!(std::io::stderr(), "xtask: {error}");
            ExitCode::FAILURE
        }
    }
}

fn execute(arguments: Arguments) -> Result<(), TaskError> {
    match arguments.command {
        Task::Verify => verify(),
        Task::Assemble { targets } => assemble(&targets),
        Task::Release {
            certificate_identity,
            certificate_oidc_issuer,
            macos_signing_identity,
            apple_notary_profile,
        } => release(
            &certificate_identity,
            &certificate_oidc_issuer,
            &macos_signing_identity,
            &apple_notary_profile,
        ),
        Task::Publish {
            tag,
            certificate_identity,
            certificate_oidc_issuer,
            macos_signing_identity,
        } => publish(
            &tag,
            &certificate_identity,
            &certificate_oidc_issuer,
            &macos_signing_identity,
        ),
    }
}

fn verify() -> Result<(), TaskError> {
    run("cargo", &["fmt", "--all", "--", "--check"])?;
    run(
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    )?;
    run(
        "cargo",
        &["test", "--workspace", "--all-targets", "--locked"],
    )?;
    run(
        "cargo",
        &[
            "test",
            "-p",
            "cfctl-cloudflare",
            "--test",
            "request",
            "--locked",
        ],
    )?;
    verify_site()?;
    verify_event_ingress_bridge()?;
    verify_security_contract()?;
    verify_source_contract()?;
    verify_cross_target()?;
    report_pre_push_registration();
    Ok(())
}

fn verify_site() -> Result<(), TaskError> {
    let root = repository_root()?.join("site");

    let mut fmt = Command::new("cargo");
    fmt.args(["fmt", "--", "--check"]).current_dir(&root);
    run_command(&mut fmt, "cargo fmt -- --check (site)")?;

    let mut clippy = Command::new("cargo");
    clippy
        .args([
            "clippy",
            "--all-targets",
            "--features",
            "ssr",
            "--locked",
            "--",
            "-D",
            "warnings",
        ])
        .current_dir(&root);
    run_command(
        &mut clippy,
        "cargo clippy --all-targets --features ssr --locked -- -D warnings (site)",
    )?;

    let mut test = Command::new("cargo");
    test.args(["test", "--all-targets", "--features", "ssr", "--locked"])
        .current_dir(&root);
    run_command(
        &mut test,
        "cargo test --all-targets --features ssr --locked (site)",
    )?;

    let mut live_verifier = Command::new("bun");
    live_verifier
        .args(["test", "./scripts/"])
        .current_dir(&root);
    run_command(
        &mut live_verifier,
        "bun test site asset and live verification contracts (site)",
    )?;

    let mut edge = Command::new("bash");
    edge.arg("./scripts/verify-reproducible-edge.sh")
        .current_dir(&root);
    run_command(
        &mut edge,
        "bash ./scripts/verify-reproducible-edge.sh (site)",
    )
}

fn verify_event_ingress_bridge() -> Result<(), TaskError> {
    let root = repository_root()?.join("bridge/event-ingress");
    let mut install = Command::new("bun");
    install
        .args(["install", "--frozen-lockfile"])
        .current_dir(&root);
    run_command(
        &mut install,
        "bun install --frozen-lockfile (bridge/event-ingress)",
    )?;
    let mut check = Command::new("bun");
    check.args(["run", "check"]).current_dir(&root);
    run_command(&mut check, "bun run check (bridge/event-ingress)")
}

/// Cross-build the Linux (musl) ship target so a change that compiles on the
/// macOS host but breaks the shipped Linux artifact is caught by `verify`, not
/// at `release` on someone else's machine.
///
/// The rest of `verify` runs only host-native checks. The most dangerous blind
/// spot that leaves is the credential layer: `cfctl-auth` selects a different
/// keyring backend per OS (`apple-native` on macOS, `dbus-secret-service` on
/// Linux), so its Linux path — including the vendored dbus C — never touches a
/// compiler during a macOS-only `verify`. Remote CI is intentionally absent, so
/// this local build is the only mechanism that proves the Linux target compiles
/// and links before it ships.
///
/// Fails closed when the cross toolchain is missing. For a control plane that
/// holds production credentials, "verified" must mean "verified on the targets
/// it ships to"; a silently skipped cross-build would reintroduce exactly the
/// gap this check exists to close. This proves the build, not runtime Secret
/// Service behavior, which still requires a real Linux host.
fn verify_cross_target() -> Result<(), TaskError> {
    let installed = output("rustup", &["target", "list", "--installed"])?;
    if !installed.lines().any(|line| line == VERIFY_CROSS_TARGET) {
        return Err(TaskError::MissingRustTarget(VERIFY_CROSS_TARGET.to_owned()));
    }
    // cargo-zigbuild supplies the cross linker and C compiler (zig) that the
    // vendored dbus build in cfctl-auth's Linux backend needs. Absent it, this
    // check cannot run — and must not be quietly skipped.
    output("cargo", &["zigbuild", "--help"]).map_err(|_| {
        TaskError::Command(
            "verify requires cargo-zigbuild for the Linux cross-target build; install it with \
             `cargo install cargo-zigbuild --locked` and ensure `zig` is on PATH"
                .to_owned(),
        )
    })?;
    run(
        "cargo",
        &[
            "zigbuild",
            "--locked",
            "-p",
            "cfctl-cli",
            "--bin",
            "cfctl",
            "--target",
            VERIFY_CROSS_TARGET,
        ],
    )
}

/// Whether this checkout's tracked pre-push hook will actually run.
///
/// The hook ships with the repository but only executes when the machine's
/// agentOS allowlist pins its digest, and an unregistered repo is passed over
/// in silence. A clone therefore has an inert gate with nothing to say so.
/// `verify` is the documented local-proof entry point, so it is where the
/// operator finds out.
#[derive(Debug, PartialEq)]
enum PrePushRegistration {
    /// The delegation mechanism is not present; nothing to report.
    MechanismAbsent,
    Registered,
    NotRegistered,
    /// Registered under a digest that no longer matches the hook on disk.
    DigestStale,
}

fn classify_pre_push_registration(
    allowlist: Option<&str>,
    repository_root: &Path,
    hook_digest: Option<&str>,
) -> PrePushRegistration {
    let (Some(allowlist), Some(hook_digest)) = (allowlist, hook_digest) else {
        return PrePushRegistration::MechanismAbsent;
    };
    let root = repository_root.to_string_lossy();
    for line in allowlist.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let mut fields = line.split_whitespace();
        if fields.next() != Some(root.as_ref()) {
            continue;
        }
        for field in fields {
            if let Some(pinned) = field.strip_prefix("pre-push=") {
                return if pinned == hook_digest {
                    PrePushRegistration::Registered
                } else {
                    PrePushRegistration::DigestStale
                };
            }
        }
    }
    PrePushRegistration::NotRegistered
}

fn report_pre_push_registration() {
    let Ok(repository_root) = repository_root() else {
        return;
    };
    let hook = repository_root.join(".githooks/pre-push");
    if !hook.exists() {
        return;
    }
    let Some(home) = env::var_os("HOME").map(PathBuf::from) else {
        return;
    };
    let delegate = home.join(".agent/hooks/delegate-repo-hook.sh");
    if !delegate.exists() {
        return;
    }
    let allowlist = fs::read_to_string(home.join(".agent/repo-hook-allowlist")).ok();
    let digest = sha256_file(&hook).ok();
    let state =
        classify_pre_push_registration(allowlist.as_deref(), repository_root, digest.as_deref());
    let advice = match state {
        PrePushRegistration::Registered | PrePushRegistration::MechanismAbsent => return,
        PrePushRegistration::NotRegistered => {
            "is not registered on this machine, so it will not run"
        }
        PrePushRegistration::DigestStale => {
            "is registered under a stale digest, so every push will be blocked"
        }
    };
    let digest = digest.unwrap_or_default();
    let mut stderr = std::io::stderr();
    let _result = writeln!(stderr, "xtask: notice: .githooks/pre-push {advice}.");
    let _result = writeln!(
        stderr,
        "xtask: notice: add or update this line in ~/.agent/repo-hook-allowlist, then re-run:"
    );
    let _result = writeln!(
        stderr,
        "xtask: notice:   {} pre-push={digest}",
        repository_root.display()
    );
}

fn security_proof_commands() -> [(&'static str, &'static [&'static str]); 2] {
    [
        ("cargo", &["deny", "check"]),
        (
            "gitleaks",
            &["detect", "--source", ".", "--no-banner", "--redact"],
        ),
    ]
}

fn verify_security_contract() -> Result<(), TaskError> {
    for (program, arguments) in security_proof_commands() {
        run(program, arguments)?;
    }
    Ok(())
}

fn verify_source_contract() -> Result<(), TaskError> {
    run(
        "sh",
        &[
            "-n",
            "bootstrap.sh",
            "cfctl",
            "packaging/install.sh",
            "tests/account-backed-smoke.sh",
            "tests/bootstrap-cleanliness.sh",
        ],
    )?;

    run("sh", &["tests/bootstrap-cleanliness.sh"])?;

    verify_xtask_alias_contract()?;
    verify_bootstrap_contract()?;
    verify_local_only_ci_contract()?;
    verify_workspace_contract()?;
    verify_v1_cutover_contract()?;
    verify_public_domain_contract()?;
    verify_managed_agent_documents()?;
    local_adapters::verify()?;
    verify_documented_contracts()
}

const EXPECTED_XTASK_ALIAS: [&str; 5] = ["run", "--locked", "-p", "xtask", "--"];

fn verify_xtask_alias_contract() -> Result<(), TaskError> {
    let path = Path::new(".cargo/config.toml");
    let source = fs::read_to_string(path).map_err(|source| io_error(path, source))?;
    validate_xtask_alias_contract(&source)
}

fn validate_xtask_alias_contract(source: &str) -> Result<(), TaskError> {
    let document: toml::Value = toml::from_str(source).map_err(|error| {
        TaskError::InvalidSourceContract(format!(".cargo/config.toml must be valid TOML: {error}"))
    })?;

    let assignments = count_semantic_key(&document, "xtask");
    if assignments != 1 {
        return Err(TaskError::InvalidSourceContract(format!(
            ".cargo/config.toml must define exactly one semantic `xtask` key, found {assignments}"
        )));
    }

    let tokens = document
        .get("alias")
        .and_then(toml::Value::as_table)
        .and_then(|aliases| aliases.get("xtask"))
        .and_then(toml::Value::as_array)
        .ok_or_else(|| {
            TaskError::InvalidSourceContract(
                ".cargo/config.toml alias.xtask must be an array of canonical Cargo tokens"
                    .to_owned(),
            )
        })?;

    let exact = tokens.len() == EXPECTED_XTASK_ALIAS.len()
        && tokens
            .iter()
            .zip(EXPECTED_XTASK_ALIAS)
            .all(|(value, expected)| value.as_str() == Some(expected));
    if !exact {
        return Err(TaskError::InvalidSourceContract(format!(
            ".cargo/config.toml alias.xtask must equal {EXPECTED_XTASK_ALIAS:?}"
        )));
    }

    Ok(())
}

fn count_semantic_key(value: &toml::Value, expected: &str) -> usize {
    if let Some(table) = value.as_table() {
        return table
            .iter()
            .map(|(key, value)| usize::from(key == expected) + count_semantic_key(value, expected))
            .sum();
    }
    value.as_array().map_or(0, |values| {
        values
            .iter()
            .map(|value| count_semantic_key(value, expected))
            .sum()
    })
}

fn verify_public_domain_contract() -> Result<(), TaskError> {
    let repository_root = repository_root()?;
    for path in tracked_files(repository_root)? {
        if path.starts_with("compat/v1/") || path.starts_with("crates/cfctl-agent/tests/fixtures/")
        {
            continue;
        }
        let absolute_path = repository_root.join(&path);
        let bytes = fs::read(&absolute_path).map_err(|source| io_error(&absolute_path, source))?;
        let Ok(content) = std::str::from_utf8(&bytes) else {
            continue;
        };
        if contains_retired_public_domain(content) {
            return Err(TaskError::InvalidSourceContract(format!(
                "{path} contains the retired public domain; cfctl.com is the only active public domain"
            )));
        }
    }

    // Gitignored guidance is invisible to `git ls-files`, so scan it by name.
    for path in local_guidance::paths() {
        let absolute_path = repository_root.join(path);
        if !absolute_path.is_file() {
            continue;
        }
        let content = fs::read_to_string(&absolute_path)
            .map_err(|source| io_error(&absolute_path, source))?;
        if contains_retired_public_domain(&content) {
            return Err(TaskError::InvalidSourceContract(format!(
                "{path} contains the retired public domain; cfctl.com is the only active public domain"
            )));
        }
    }

    for (path, required_anchor) in [
        (
            "crates/cfctl-auth/src/lib.rs",
            "pub const CFCTL_CALLBACK_URL: &str = \"https://cfctl.com/oauth/callback\";",
        ),
        (
            "packaging/homebrew/cfctl.rb.in",
            "homepage \"https://cfctl.com\"",
        ),
        (
            "README.md",
            "`cfctl.com` site publication, publisher-domain verification",
        ),
        (
            "crates/cfctl-cli/src/runtime/health_commands.rs",
            "disabled pending a later explicit OAuth promotion transaction; cfctl.com ownership, site publication, and domain verification do not enable OAuth",
        ),
    ] {
        let absolute_path = repository_root.join(path);
        let content = fs::read_to_string(&absolute_path)
            .map_err(|source| io_error(&absolute_path, source))?;
        validate_public_domain_anchor(path, &content, required_anchor)?;
    }
    Ok(())
}

fn contains_retired_public_domain(content: &str) -> bool {
    content
        .to_ascii_lowercase()
        .contains(&["cfctl", ".io"].concat())
}

fn validate_public_domain_anchor(
    path: &str,
    content: &str,
    required_anchor: &str,
) -> Result<(), TaskError> {
    if !content.contains(required_anchor) {
        return Err(TaskError::InvalidSourceContract(format!(
            "{path} does not carry the exact cfctl.com public identity anchor `{required_anchor}`"
        )));
    }
    Ok(())
}

fn verify_local_only_ci_contract() -> Result<(), TaskError> {
    let workflow_root = Path::new(".github/workflows");
    let workflow_paths = collect_workflow_paths(fs::read_dir(workflow_root), workflow_root)?;
    let contributing = fs::read_to_string("CONTRIBUTING.md").map_err(|error| TaskError::Io {
        path: "CONTRIBUTING.md".to_owned(),
        source: error,
    })?;
    let readme = fs::read_to_string("README.md").map_err(|error| TaskError::Io {
        path: "README.md".to_owned(),
        source: error,
    })?;
    validate_local_only_ci_contract(&workflow_paths, &contributing, &readme)
}

fn collect_workflow_paths(
    entries: std::io::Result<fs::ReadDir>,
    workflow_root: &Path,
) -> Result<Vec<String>, TaskError> {
    let entries = match entries {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(TaskError::Io {
                path: workflow_root.display().to_string(),
                source: error,
            });
        }
    };
    entries
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| TaskError::Io {
            path: workflow_root.display().to_string(),
            source: error,
        })
        .map(|entries| {
            entries
                .into_iter()
                .map(|entry| entry.path())
                .filter(|path| {
                    path.extension().is_some_and(|extension| {
                        extension.eq_ignore_ascii_case("yml")
                            || extension.eq_ignore_ascii_case("yaml")
                    })
                })
                .map(|path| path.display().to_string())
                .collect()
        })
}

fn validate_local_only_ci_contract(
    workflow_paths: &[String],
    contributing: &str,
    readme: &str,
) -> Result<(), TaskError> {
    if !workflow_paths.is_empty() {
        return Err(TaskError::InvalidSourceContract(format!(
            "local-only CI forbids GitHub Actions workflows: {}",
            workflow_paths.join(", ")
        )));
    }
    let contributing = contributing
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let readme = readme.split_whitespace().collect::<Vec<_>>().join(" ");
    if !contributing
        .contains("The repository does not require GitHub Actions or another hosted CI service.")
    {
        return Err(TaskError::InvalidSourceContract(
            "CONTRIBUTING.md must declare the local-only CI authority".to_owned(),
        ));
    }
    if !readme.contains("no GitHub Actions workflow or hosted CI service is required") {
        return Err(TaskError::InvalidSourceContract(
            "README.md must declare that hosted CI is not required".to_owned(),
        ));
    }
    Ok(())
}

fn verify_bootstrap_contract() -> Result<(), TaskError> {
    let source = fs::read_to_string("bootstrap.sh").map_err(|error| {
        TaskError::InvalidSourceContract(format!("bootstrap.sh could not be read: {error}"))
    })?;
    validate_bootstrap_contract(&source)
}

fn validate_bootstrap_contract(source: &str) -> Result<(), TaskError> {
    if source.contains("cargo run --locked -p xtask -- verify") {
        return Err(TaskError::InvalidSourceContract(
            "bootstrap.sh must not hold a Cargo run gate around the nested xtask verifier"
                .to_owned(),
        ));
    }
    if !source.contains("cargo xtask verify") {
        return Err(TaskError::InvalidSourceContract(
            "bootstrap.sh must invoke the repository's cargo xtask verify entrypoint".to_owned(),
        ));
    }
    if !source.contains("status --porcelain=v1 --untracked-files=normal") {
        return Err(TaskError::InvalidSourceContract(
            "bootstrap.sh must use the build identity resolver's tracked-and-untracked cleanliness invariant"
                .to_owned(),
        ));
    }
    Ok(())
}

fn verify_workspace_contract() -> Result<(), TaskError> {
    let metadata: serde_json::Value = serde_json::from_str(&output(
        "cargo",
        &["metadata", "--locked", "--no-deps", "--format-version", "1"],
    )?)
    .map_err(|error| TaskError::InvalidSourceContract(format!("cargo metadata: {error}")))?;
    let members = metadata
        .get("workspace_members")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            TaskError::InvalidSourceContract("workspace_members must be an array".to_owned())
        })?;
    if members.len() != 11 {
        return Err(TaskError::InvalidSourceContract(format!(
            "expected 11 workspace members, found {}",
            members.len()
        )));
    }
    let package_names = metadata
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| TaskError::InvalidSourceContract("packages must be an array".to_owned()))?
        .iter()
        .filter_map(|package| package.get("name").and_then(serde_json::Value::as_str))
        .collect::<BTreeSet<_>>();
    for required in [
        "cfctl-cli",
        "cfctl-core",
        "cfctl-cloudflare",
        "cfctl-registry",
        "cfctl-workspace",
        "xtask",
    ] {
        if !package_names.contains(required) {
            return Err(TaskError::InvalidSourceContract(format!(
                "workspace is missing {required}"
            )));
        }
    }
    verify_workspace_dependency_versions()
}

/// The intra-workspace version pins must equal the workspace version exactly.
///
/// Cargo will not catch this: a pin left at the previous version is a semver
/// requirement the bumped crate still satisfies, so a forgotten pin builds
/// clean, resolves clean, and ships a lie about which version the workspace
/// depends on. Only an equality check bites.
fn verify_workspace_dependency_versions() -> Result<(), TaskError> {
    const EXPECTED_PINS: usize = 10;

    let manifest_path = repository_root()?.join("Cargo.toml");
    let manifest =
        fs::read_to_string(&manifest_path).map_err(|source| io_error(&manifest_path, source))?;
    let expected = env!("CARGO_PKG_VERSION");
    let mut checked = 0;

    for line in manifest.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("cfctl-") || !trimmed.contains("path = \"crates/") {
            continue;
        }
        let Some(pinned) = trimmed
            .split_once("version = \"")
            .and_then(|(_, rest)| rest.split_once('"'))
            .map(|(version, _)| version)
        else {
            return Err(TaskError::InvalidSourceContract(format!(
                "workspace dependency has no version pin: {trimmed}"
            )));
        };
        if pinned != expected {
            return Err(TaskError::InvalidSourceContract(format!(
                "workspace dependency pins {pinned} but the workspace version is {expected}: {trimmed}"
            )));
        }
        checked += 1;
    }

    if checked != EXPECTED_PINS {
        return Err(TaskError::InvalidSourceContract(format!(
            "expected {EXPECTED_PINS} intra-workspace version pins, checked {checked}"
        )));
    }
    Ok(())
}

fn verify_v1_cutover_contract() -> Result<(), TaskError> {
    let repository_root = repository_root()?;
    for forbidden in ["catalog", "commands", "lib", "scripts", "state"] {
        if repository_root.join(forbidden).exists() {
            return Err(TaskError::InvalidSourceContract(format!(
                "archived v1 runtime path still exists: {forbidden}/"
            )));
        }
    }

    let audit_path = repository_root.join("compat/v1-parity-audit.json");
    let audit: serde_json::Value = serde_json::from_slice(
        &fs::read(&audit_path).map_err(|source| io_error(&audit_path, source))?,
    )
    .map_err(|error| TaskError::InvalidSourceContract(format!("v1 parity audit: {error}")))?;
    let removed_root_count = audit
        .pointer("/removed_estate/roots")
        .and_then(serde_json::Value::as_array)
        .map(|roots| {
            roots
                .iter()
                .filter_map(|root| root.get("count").and_then(serde_json::Value::as_u64))
                .sum::<u64>()
        });
    let script_family_count = audit
        .get("script_family_outcomes")
        .and_then(serde_json::Value::as_array)
        .map(|families| {
            families
                .iter()
                .filter_map(|family| family.get("paths").and_then(serde_json::Value::as_u64))
                .sum::<u64>()
        });
    if audit
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        != Some(1)
        || audit
            .pointer("/removed_estate/total_paths")
            .and_then(serde_json::Value::as_u64)
            != Some(147)
        || audit
            .pointer("/archive/runtime_tar_sha256")
            .and_then(serde_json::Value::as_str)
            != Some("10c8b5fe9d0e9a98c7d97fe9fe28d320d470785207a565ff080188225e626dcb")
        || audit
            .pointer("/archive/all_removed_paths_present")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
        || removed_root_count != Some(147)
        || script_family_count != Some(127)
        || audit
            .pointer("/conclusion/unmapped_v1_public_commands")
            .and_then(serde_json::Value::as_array)
            .is_none_or(|commands| !commands.is_empty())
        || audit
            .pointer("/conclusion/remaining_v1_executables")
            .and_then(serde_json::Value::as_array)
            .is_none_or(|paths| !paths.is_empty())
    {
        return Err(TaskError::InvalidSourceContract(
            "v1 parity audit does not bind the reviewed 147-path archive".to_owned(),
        ));
    }
    verify_v1_quarantine_manifest()?;
    verify_quarantine_code_consumers()?;
    verify_tracked_cfctl_command_references()?;
    verify_active_guidance_has_no_v1_commands()?;
    local_guidance::verify()
}

fn repository_root() -> Result<&'static Path, TaskError> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| {
            TaskError::InvalidSourceContract("xtask has no repository parent".to_owned())
        })
}

fn verify_v1_quarantine_manifest() -> Result<(), TaskError> {
    let repository_root = repository_root()?;
    let manifest_path = repository_root.join("compat/v1/manifest.json");
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(&manifest_path).map_err(|source| io_error(&manifest_path, source))?,
    )
    .map_err(|error| {
        TaskError::InvalidSourceContract(format!("v1 quarantine manifest: {error}"))
    })?;
    let expected_roots = serde_json::json!([
        {
            "path": "compat/v1/catalog",
            "kind": "static_catalog",
            "consumer": null
        },
        {
            "path": "compat/v1/state",
            "kind": "desired_state",
            "consumer": "cfctl migrate v1"
        }
    ]);
    let retired_verbs = manifest
        .get("retired_public_verbs")
        .and_then(serde_json::Value::as_array)
        .map(|verbs| {
            verbs
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect::<Vec<_>>()
        });
    let retired_surfaces = manifest
        .get("retired_surfaces")
        .and_then(serde_json::Value::as_array)
        .map(|surfaces| {
            surfaces
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect::<Vec<_>>()
        });
    if manifest
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        != Some(1)
        || manifest
            .get("executable")
            .and_then(serde_json::Value::as_bool)
            != Some(false)
        || manifest.get("roots") != Some(&expected_roots)
        || retired_verbs.as_deref() != Some(RETIRED_V1_PUBLIC_VERBS)
        || retired_surfaces.as_deref() != Some(RETIRED_V1_SURFACES)
    {
        return Err(TaskError::InvalidSourceContract(
            "compat/v1/manifest.json must exactly bind the inert roots and retired verb inventory"
                .to_owned(),
        ));
    }
    for root in ["compat/v1/catalog", "compat/v1/state"] {
        if !repository_root.join(root).is_dir() {
            return Err(TaskError::InvalidSourceContract(format!(
                "quarantined v1 root is missing: {root}"
            )));
        }
    }
    let declared_roots = ["compat/v1/catalog", "compat/v1/state"];
    for path in tracked_files(repository_root)? {
        if path.starts_with("compat/v1/") && !is_declared_quarantine_path(&path, &declared_roots) {
            return Err(TaskError::InvalidSourceContract(format!(
                "tracked path is outside the declared v1 quarantine roots: {path}"
            )));
        }
    }
    verify_frozen_v1_catalog_contract(repository_root)
}

fn is_declared_quarantine_path(path: &str, declared_roots: &[&str]) -> bool {
    matches!(path, "compat/v1/README.md" | "compat/v1/manifest.json")
        || declared_roots.iter().any(|root| {
            path == *root
                || path
                    .strip_prefix(root)
                    .is_some_and(|suffix| suffix.starts_with('/'))
        })
}

fn verify_frozen_v1_catalog_contract(repository_root: &Path) -> Result<(), TaskError> {
    let runtime_path = repository_root.join("compat/v1/catalog/runtime.json");
    let runtime: serde_json::Value = serde_json::from_slice(
        &fs::read(&runtime_path).map_err(|source| io_error(&runtime_path, source))?,
    )
    .map_err(|error| {
        TaskError::InvalidSourceContract(format!("frozen v1 runtime catalog: {error}"))
    })?;
    let catalog_retired_verbs = runtime
        .get("public_verbs")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            TaskError::InvalidSourceContract(
                "frozen v1 runtime catalog has no public_verbs".to_owned(),
            )
        })?
        .iter()
        .filter_map(serde_json::Value::as_str)
        .filter(|verb| !PUBLIC_V2_SUBCOMMANDS.contains(verb))
        .collect::<BTreeSet<_>>();
    if catalog_retired_verbs != RETIRED_V1_PUBLIC_VERBS.iter().copied().collect() {
        return Err(TaskError::InvalidSourceContract(
            "retired verb contract drifted from the frozen v1 runtime catalog".to_owned(),
        ));
    }

    let surfaces_path = repository_root.join("compat/v1/catalog/surfaces.json");
    let surfaces: serde_json::Value = serde_json::from_slice(
        &fs::read(&surfaces_path).map_err(|source| io_error(&surfaces_path, source))?,
    )
    .map_err(|error| {
        TaskError::InvalidSourceContract(format!("frozen v1 surface catalog: {error}"))
    })?;
    let catalog_surfaces = surfaces
        .get("surfaces")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            TaskError::InvalidSourceContract(
                "frozen v1 surface catalog has no surfaces object".to_owned(),
            )
        })?
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if catalog_surfaces != RETIRED_V1_SURFACES.iter().copied().collect() {
        return Err(TaskError::InvalidSourceContract(
            "retired surface contract drifted from the frozen v1 surface catalog".to_owned(),
        ));
    }
    Ok(())
}

fn tracked_files(repository_root: &Path) -> Result<Vec<String>, TaskError> {
    let result = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(repository_root)
        .output()
        .map_err(|source| io_error(Path::new("git ls-files"), source))?;
    if !result.status.success() {
        return Err(TaskError::Command(format!(
            "git ls-files exited {:?}",
            result.status.code()
        )));
    }
    Ok(result
        .stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .map(|path| String::from_utf8_lossy(path).into_owned())
        .collect())
}

fn verify_quarantine_code_consumers() -> Result<(), TaskError> {
    let repository_root = repository_root()?;
    for path in tracked_files(repository_root)? {
        let absolute_path = repository_root.join(&path);
        let bytes = fs::read(&absolute_path).map_err(|source| io_error(&absolute_path, source))?;
        let Ok(content) = std::str::from_utf8(&bytes) else {
            continue;
        };
        if is_forbidden_quarantine_consumer(&path, content) {
            return Err(TaskError::InvalidSourceContract(format!(
                "{path} consumes a quarantined v1 root outside its declared boundary"
            )));
        }
    }
    Ok(())
}

fn is_forbidden_quarantine_consumer(path: &str, content: &str) -> bool {
    let source_extension = Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "bash"
                    | "cjs"
                    | "fish"
                    | "go"
                    | "java"
                    | "js"
                    | "jsx"
                    | "kt"
                    | "kts"
                    | "mjs"
                    | "pl"
                    | "py"
                    | "rb"
                    | "rs"
                    | "sh"
                    | "swift"
                    | "ts"
                    | "tsx"
                    | "zsh"
            )
        });
    if !source_extension && !content.starts_with("#!") {
        return false;
    }

    let consumes_state = content.contains("compat/v1/state");
    let consumes_catalog = content.contains("compat/v1/catalog");
    if !consumes_state && !consumes_catalog {
        return false;
    }

    match path {
        "crates/cfctl-cli/src/runtime/v1_migration.rs" => consumes_catalog,
        "crates/cfctl-cli/tests/cli.rs" | "xtask/src/main.rs" => false,
        _ => true,
    }
}

fn verify_tracked_cfctl_command_references() -> Result<(), TaskError> {
    let repository_root = repository_root()?;
    for path in tracked_files(repository_root)? {
        if path.starts_with("compat/v1/") {
            continue;
        }
        // SHA-pinned frozen migration fixtures are inert evidence like
        // compat/v1: their bytes authorize legacy-skill deletion and must
        // never change to satisfy the live command lint.
        if path.starts_with("crates/cfctl-agent/tests/fixtures/") {
            continue;
        }
        let absolute_path = repository_root.join(&path);
        let bytes = fs::read(&absolute_path).map_err(|source| io_error(&absolute_path, source))?;
        let Ok(content) = std::str::from_utf8(&bytes) else {
            continue;
        };
        validate_command_refs(&path, content)?;
    }
    Ok(())
}

/// Validates every `cfctl` reference in one file against the single-sourced
/// command tree, walking the full token chain rather than stopping at the
/// second token.
fn validate_command_refs(path: &str, content: &str) -> Result<(), TaskError> {
    validate_extracted_command_refs(path, extract_cfctl_command_refs(path, content))
}

/// The managed agent instructions are the most consequential thing cfctl
/// teaches — they are installed into four agent harnesses and read as
/// authority — but they live in Rust source, which the tracked-file lint does
/// not scan. This binds the commands they teach to the same command tree.
fn verify_managed_agent_documents() -> Result<(), TaskError> {
    for (label, document) in cfctl_agent::managed_documents() {
        validate_extracted_command_refs(label, extract_prose_command_refs(document, true, false))?;
    }
    Ok(())
}

fn validate_extracted_command_refs(
    path: &str,
    references: Vec<CfctlReference>,
) -> Result<(), TaskError> {
    for reference in references {
        let verb = &reference.verb;
        if verb != "help" && !PUBLIC_V2_SUBCOMMANDS.contains(&verb.as_str()) {
            return Err(TaskError::InvalidSourceContract(format!(
                "{path} teaches non-v2 command `cfctl {verb}` outside compat/v1"
            )));
        }
        // Flags are checked for every verb, including the leaf verbs the tree
        // does not model — those carry a third of the flag surface.
        validate_flags(path, &reference)?;
        // Verbs absent from the tree (`call`, `guide`, `resolve`, and the other
        // leaf verbs) take arguments rather than subcommands, so their trailing
        // tokens are not validated.
        let Some(mut node) = PUBLIC_V2_COMMAND_TREE
            .iter()
            .find(|node| node.name == verb.as_str())
        else {
            continue;
        };
        let mut walked = Vec::new();
        for token in &reference.path {
            // A node with no declared children is final: everything after it is
            // a free argument, not a subcommand.
            if node.subcommands.is_empty() {
                break;
            }
            let Some(child) = node
                .subcommands
                .iter()
                .find(|child| child.name == token.as_str())
            else {
                walked.push(token.as_str());
                return Err(TaskError::InvalidSourceContract(format!(
                    "{path} teaches unknown subcommand `cfctl {verb} {}` outside compat/v1",
                    walked.join(" ")
                )));
            };
            walked.push(child.name);
            node = child;
        }
    }
    Ok(())
}

/// Validates the long flags a document teaches against the real clap parser.
///
/// Flags are checked against the parser rather than a declared list on purpose.
/// Restating 33 flags across 30 nodes would be one more hand-synced copy of
/// something clap already knows — and a third of them sit on verbs
/// (`call`, `guide`, `resolve`, `update`) that the command tree deliberately
/// does not model, because they take arguments rather than subcommands.
fn validate_flags(path: &str, reference: &CfctlReference) -> Result<(), TaskError> {
    use clap::CommandFactory as _;

    if reference.flags.is_empty() {
        return Ok(());
    }
    let root = cfctl_cli::Cli::command();
    let Some(mut command) = root.find_subcommand(reference.verb.as_str()) else {
        return Ok(());
    };
    // Descend as far as the tokens actually name subcommands; the rest are
    // arguments, and their flags belong to the deepest command reached.
    for token in &reference.path {
        match command.find_subcommand(token.as_str()) {
            Some(child) => command = child,
            None => break,
        }
    }

    let mut known: Vec<&str> = command
        .get_arguments()
        .filter_map(clap::Arg::get_long)
        .collect();
    // Root-level globals are legal everywhere but only live on the root of an
    // unbuilt command tree, so they have to be added explicitly.
    known.extend(
        root.get_arguments()
            .filter(|argument| argument.is_global_set())
            .filter_map(clap::Arg::get_long),
    );
    known.extend(["help", "version"]);

    for flag in &reference.flags {
        if !known.contains(&flag.as_str()) {
            let command_path = if reference.path.is_empty() {
                reference.verb.clone()
            } else {
                format!("{} {}", reference.verb, reference.path.join(" "))
            };
            return Err(TaskError::InvalidSourceContract(format!(
                "{path} teaches unknown flag `--{flag}` for `cfctl {command_path}` outside compat/v1"
            )));
        }
    }
    Ok(())
}

/// One extracted `cfctl` command reference: the top-level verb and, when the
/// reference is a real invocation (not loose prose), the run of following
/// tokens that plausibly name subcommands. The tree walk decides how many of
/// those tokens are subcommands and where free arguments begin.
struct CfctlReference {
    verb: String,
    path: Vec<String>,
    flags: Vec<String>,
}

#[cfg(test)]
fn extract_cfctl_command_references(path: &str, content: &str) -> Vec<String> {
    extract_cfctl_command_refs(path, content)
        .into_iter()
        .map(|reference| reference.verb)
        .collect()
}

fn extract_cfctl_command_refs(path: &str, content: &str) -> Vec<CfctlReference> {
    if path_has_extension(path, "json") {
        let mut references = Vec::new();
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(content) {
            collect_json_command_references(&value, false, &mut references);
        }
        return references;
    }

    let markdown = path_has_extension(path, "md");
    let shell = path_has_extension(path, "sh") || content.starts_with("#!");
    if !markdown && !shell {
        return Vec::new();
    }
    extract_prose_command_refs(content, markdown, shell)
}

/// Extracts command references from markdown or shell text. Split out from the
/// path-driven entry point so in-memory documents — the managed agent
/// instructions, which live in Rust source and therefore have no path — bind to
/// the same extractor rather than a second copy of these rules.
fn extract_prose_command_refs(content: &str, markdown: bool, shell: bool) -> Vec<CfctlReference> {
    let mut references = Vec::new();
    let mut in_fence = false;
    let mut in_front_matter = false;
    for (index, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        // YAML front matter is document metadata, not command examples. A
        // description reading "Use cfctl as the universal control plane" is a
        // sentence, and scanning it for commands finds `cfctl as`.
        if markdown && trimmed == "---" {
            if index == 0 {
                in_front_matter = true;
                continue;
            }
            if in_front_matter {
                in_front_matter = false;
                continue;
            }
        }
        if in_front_matter {
            continue;
        }
        if markdown && trimmed.starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if (shell || in_fence)
            && let Some(reference) = cfctl_command_ref(trimmed)
        {
            references.push(reference);
        }
        if markdown && !in_fence {
            if let Some(reference) = cfctl_command_ref_in_prose(trimmed) {
                references.push(reference);
            }
            for (index, inline) in line.split('`').enumerate() {
                if index % 2 == 1
                    && let Some(reference) = cfctl_command_ref(inline)
                {
                    references.push(reference);
                }
            }
        }
    }
    references
}

fn path_has_extension(path: &str, expected: &str) -> bool {
    Path::new(path)
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case(expected))
}

fn collect_json_command_references(
    value: &serde_json::Value,
    command_context: bool,
    references: &mut Vec<CfctlReference>,
) {
    match value {
        serde_json::Value::String(value) => {
            let reference = if command_context {
                cfctl_command_ref(value)
            } else {
                cfctl_command_ref_in_prose(value)
            };
            if let Some(reference) = reference {
                references.push(reference);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_json_command_references(value, command_context, references);
            }
        }
        serde_json::Value::Object(values) => {
            for (key, value) in values {
                if is_json_argv_reference_key(key)
                    && let Some(command) = json_argv_command(value)
                    && let Some(reference) = cfctl_command_ref(&command)
                {
                    references.push(reference);
                    continue;
                }
                collect_json_command_references(
                    value,
                    command_context || is_json_command_reference_key(key),
                    references,
                );
            }
        }
        _ => {}
    }
}

fn is_json_argv_reference_key(key: &str) -> bool {
    key.eq_ignore_ascii_case("argv")
}

fn json_argv_command(value: &serde_json::Value) -> Option<String> {
    let arguments = value
        .as_array()?
        .iter()
        .map(serde_json::Value::as_str)
        .collect::<Option<Vec<_>>>()?;
    (!arguments.is_empty()).then(|| arguments.join(" "))
}

fn is_json_command_reference_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    [
        "action",
        "argv",
        "command",
        "entrypoint",
        "example",
        "invocation",
        "next",
    ]
    .iter()
    .any(|fragment| key.contains(fragment))
}

fn cfctl_command_ref(command: &str) -> Option<CfctlReference> {
    cfctl_command_ref_with_context(command, true)
}

fn cfctl_command_ref_in_prose(command: &str) -> Option<CfctlReference> {
    cfctl_command_ref_with_context(command, false)
}

fn cfctl_command_ref_with_context(command: &str, command_context: bool) -> Option<CfctlReference> {
    let command = command
        .trim()
        .trim_start_matches(['$', '>', '-'])
        .trim_start();
    let tokens = command.split_whitespace().collect::<Vec<_>>();
    let command_index = tokens
        .iter()
        .position(|token| matches!(*token, "cfctl" | "./cfctl"))?;
    let mut arguments = tokens.iter().skip(command_index + 1).copied();
    let mut verb = arguments.next()?;
    let mut flags = Vec::new();
    while verb == "--json" {
        flags.push("json".to_owned());
        verb = arguments.next()?;
    }
    if verb.starts_with(['\"', '\'', '<', '{']) || verb == "\\" {
        return None;
    }
    let verb = verb
        .trim_matches(|character: char| !character.is_ascii_alphanumeric() && character != '-')
        .to_owned();
    // Tokens after the verb are only treated as subcommands inside a real
    // command context (a fence, a shell line, an inline command span, or a
    // structured argv), and only while they are plausibly subcommand tokens
    // rather than flags, placeholders, quoted arguments, or prose words. The
    // chain stops at the first token that is not — a capability id trailing
    // `cfctl call` reads as a plausible token, so the tree walk, not this
    // scanner, is what decides where arguments begin.
    // Subcommand tokens run until the first token that is not one; every
    // long flag on the line is collected regardless of where it appears, since
    // flags may precede, follow, or be interleaved with arguments.
    let mut path = Vec::new();
    if command_context {
        let mut in_subcommand_prefix = true;
        for token in arguments {
            if let Some(flag) = long_flag_token(token) {
                // The first flag ends the subcommand prefix: what follows is
                // that flag's value, not a deeper subcommand.
                in_subcommand_prefix = false;
                flags.push(flag);
                continue;
            }
            if in_subcommand_prefix {
                match plausible_subcommand_token(token) {
                    Some(sub) => path.push(sub),
                    None => in_subcommand_prefix = false,
                }
            }
        }
    }

    let mut explicit_command_context = false;
    if command_index > 0 {
        let prefix = &tokens[..command_index];
        let previous = prefix.last().copied().unwrap_or_default();
        let shell_boundary = matches!(
            previous,
            "|" | "||" | "&&" | ";" | "exec" | "env" | "command" | "sudo"
        );
        let environment_prefix = prefix.iter().all(|token| token.contains('='));
        let instructional_prefix = matches!(
            previous
                .trim_matches(|character: char| !character.is_ascii_alphabetic())
                .to_ascii_lowercase()
                .as_str(),
            "execute" | "invoke" | "run" | "try" | "use"
        );
        explicit_command_context = shell_boundary || environment_prefix || instructional_prefix;
        if !explicit_command_context {
            return None;
        }
    }
    if !command_context && matches!(verb.as_str(), "it" | "itself" | "that" | "this") {
        return None;
    }
    if !command_context
        && !explicit_command_context
        && verb != "help"
        && !PUBLIC_V2_SUBCOMMANDS.contains(&verb.as_str())
        && !RETIRED_V1_PUBLIC_VERBS.contains(&verb.as_str())
    {
        return None;
    }
    Some(CfctlReference { verb, path, flags })
}

/// Returns the token when it is plausibly a subcommand: a lowercase word of
/// ASCII letters, digits, and hyphens. Flags (`--json`), placeholders (`<id>`),
/// quoted arguments, dotted state paths, and prose punctuation are rejected so
/// the second-token check never false-positives on non-subcommand tokens.
/// Returns the flag name when the token is a long flag, so `--max-cost` and
/// `--max-cost=USD:5` both yield `max-cost`. A bare `--` ends option parsing
/// and names nothing; short flags do not exist on this surface.
fn long_flag_token(token: &str) -> Option<String> {
    let name = token.strip_prefix("--")?;
    let name = name.split('=').next().unwrap_or_default();
    let name = name.trim_matches(|character: char| {
        !character.is_ascii_lowercase() && !character.is_ascii_digit() && character != '-'
    });
    if name.is_empty() {
        return None;
    }
    Some(name.to_owned())
}

fn plausible_subcommand_token(token: &str) -> Option<String> {
    let first = token.chars().next()?;
    if !first.is_ascii_lowercase() {
        return None;
    }
    token
        .chars()
        .all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
        .then(|| token.to_owned())
}

fn verify_documented_contracts() -> Result<(), TaskError> {
    let repository_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| {
            TaskError::InvalidSourceContract("xtask has no repository parent".to_owned())
        })?;
    for (path, phrase) in [
        ("README.md", "hash-chained transaction journal"),
        ("SECURITY.md", "full-history Gitleaks scan"),
        ("CONTRIBUTING.md", "Do not reintroduce the archived v1"),
        ("docs/v2-security.md", "operation-specific verification"),
        ("docs/v2-architecture.md", "Wrangler TOML/JSONC, Terraform"),
        ("docs/runbooks/cfctl.md", "## Launch support triage"),
        (
            "docs/runbooks/cfctl.md",
            "request or accept credential values",
        ),
        ("docs/runbooks/cfctl.md", "Do not replay `plans run`"),
    ] {
        let absolute_path = repository_root.join(path);
        let content = fs::read_to_string(&absolute_path)
            .map_err(|source| io_error(&absolute_path, source))?;
        if !content.contains(phrase) {
            return Err(TaskError::InvalidSourceContract(format!(
                "{path} omits required contract text `{phrase}`"
            )));
        }
    }
    verify_generated_guidance_section(
        &repository_root.join("README.md"),
        "system-guide",
        &render_guide_topic_markdown(GuideTopicV1::System),
    )?;
    verify_generated_guidance_section(
        &repository_root.join("QUICKSTART.md"),
        "standing-authority-guide",
        &render_guide_topic_markdown(GuideTopicV1::StandingAuthority),
    )?;
    verify_quickstart_pins_the_release_version(repository_root)?;
    verify_signed_release_posture_contract(repository_root)?;
    Ok(())
}

fn verify_signed_release_posture_contract(repository_root: &Path) -> Result<(), TaskError> {
    let paths = [
        "README.md",
        "QUICKSTART.md",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "site/docs/LAUNCH_CHECKLIST.md",
    ];
    let documents = paths
        .iter()
        .map(|path| {
            let absolute_path = repository_root.join(path);
            fs::read_to_string(&absolute_path)
                .map(|content| (*path, content))
                .map_err(|source| io_error(&absolute_path, source))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let borrowed = documents
        .iter()
        .map(|(path, content)| (*path, content.as_str()))
        .collect::<Vec<_>>();
    validate_signed_release_posture_contract(&borrowed)?;
    let security = borrowed
        .iter()
        .find_map(|(path, content)| (*path == "SECURITY.md").then_some(*content))
        .ok_or_else(|| {
            TaskError::InvalidSourceContract(
                "signed release posture does not observe SECURITY.md".to_owned(),
            )
        })?;
    parse_release_trust_roots(security)?;
    Ok(())
}

fn validate_signed_release_posture_contract(documents: &[(&str, &str)]) -> Result<(), TaskError> {
    for (path, required) in [
        (
            "README.md",
            "Prebuilt release artifacts must not be published unless both macOS binaries",
        ),
        (
            "QUICKSTART.md",
            "Prebuilt binaries may ship from the GitHub release only after that release is signed",
        ),
        (
            "SECURITY.md",
            "Prebuilt release artifacts must not be published unless both macOS binaries",
        ),
        (
            "CONTRIBUTING.md",
            "The prebuilt v1.3.0 operator posture requires the identity-bearing lane.",
        ),
        ("CONTRIBUTING.md", "create `v1.3.0` as a new annotated tag"),
        (
            "CONTRIBUTING.md",
            "Create an empty draft GitHub release from the verified tag",
        ),
        (
            "site/docs/LAUNCH_CHECKLIST.md",
            "The prebuilt v1.3.0 CLI posture requires signed and notarized publication",
        ),
        (
            "SECURITY.md",
            "The exact Developer ID authority, TeamIdentifier, certificate fingerprints, Sigstore certificate identity, and OIDC issuer must be committed here before publication.",
        ),
    ] {
        let content = documents
            .iter()
            .find_map(|(candidate, content)| (*candidate == path).then_some(*content))
            .ok_or_else(|| {
                TaskError::InvalidSourceContract(format!(
                    "signed release posture does not observe required document `{path}`"
                ))
            })?;
        let normalized_content = content.split_whitespace().collect::<Vec<_>>().join(" ");
        let normalized_required = required.split_whitespace().collect::<Vec<_>>().join(" ");
        if !normalized_content.contains(&normalized_required) {
            return Err(TaskError::InvalidSourceContract(format!(
                "{path} omits signed v1.3.0 release posture anchor `{required}`"
            )));
        }
    }

    for (path, content) in documents {
        let normalized_content = content.split_whitespace().collect::<Vec<_>>().join(" ");
        for retired in [
            "Published releases are unsigned by operator decision",
            "Releases are unsigned by operator decision",
            "unsigned posture versus the signed-only",
        ] {
            if normalized_content.contains(retired) {
                return Err(TaskError::InvalidSourceContract(format!(
                    "{path} retains retired unsigned release posture `{retired}`"
                )));
            }
        }
    }
    Ok(())
}

/// The install instructions must point at this version's release assets.
///
/// A stale download URL is not a cosmetic doc lag: it hands the reader a
/// binary from the previous release while the page around it documents this
/// one, and nothing else in the tree notices.
fn verify_quickstart_pins_the_release_version(repository_root: &Path) -> Result<(), TaskError> {
    let path = repository_root.join("QUICKSTART.md");
    let content = fs::read_to_string(&path).map_err(|source| io_error(&path, source))?;
    let expected = format!("download/v{}/", env!("CARGO_PKG_VERSION"));
    if !content.contains(&expected) {
        return Err(TaskError::InvalidSourceContract(format!(
            "QUICKSTART.md does not pin the current release download path `{expected}`"
        )));
    }
    Ok(())
}

fn verify_generated_guidance_section(
    path: &Path,
    key: &str,
    expected: &str,
) -> Result<(), TaskError> {
    let content = fs::read_to_string(path).map_err(|source| io_error(path, source))?;
    verify_generated_guidance_section_text(&content, key, expected)
        .map_err(|error| TaskError::InvalidSourceContract(format!("{}: {error}", path.display())))
}

fn verify_generated_guidance_section_text(
    content: &str,
    key: &str,
    expected: &str,
) -> Result<(), TaskError> {
    let start = format!("<!-- BEGIN CFCTL GENERATED: {key} -->");
    let end = format!("<!-- END CFCTL GENERATED: {key} -->");
    if content.matches(&start).count() != 1 || content.matches(&end).count() != 1 {
        return Err(TaskError::InvalidSourceContract(format!(
            "generated guidance section `{key}` must have exactly one start and end marker"
        )));
    }
    let (_, after_start) = content.split_once(&start).ok_or_else(|| {
        TaskError::InvalidSourceContract(format!(
            "generated guidance section `{key}` has no start marker"
        ))
    })?;
    let after_start = after_start.strip_prefix('\n').ok_or_else(|| {
        TaskError::InvalidSourceContract(format!(
            "generated guidance section `{key}` must start on the line after its marker"
        ))
    })?;
    let (actual, _) = after_start.split_once(&end).ok_or_else(|| {
        TaskError::InvalidSourceContract(format!(
            "generated guidance section `{key}` has no end marker"
        ))
    })?;
    let actual = actual.strip_suffix('\n').unwrap_or(actual);
    let expected = expected.strip_suffix('\n').unwrap_or(expected);
    if actual != expected {
        return Err(TaskError::InvalidSourceContract(format!(
            "generated guidance section `{key}` drifted from the executable projection"
        )));
    }
    Ok(())
}

fn release_trust_roots() -> Result<ReleaseTrustRoots, TaskError> {
    let path = repository_root()?.join("SECURITY.md");
    let content = fs::read_to_string(&path).map_err(|source| io_error(&path, source))?;
    parse_release_trust_roots(&content)
}

fn release_trust_roots_at_commit(commit: &str) -> Result<ReleaseTrustRoots, TaskError> {
    if !is_full_git_object_id(commit) {
        return Err(TaskError::InvalidProvenance(
            "git_commit must be a full hexadecimal object ID".to_owned(),
        ));
    }
    let revision = format!("{commit}:SECURITY.md");
    let content = output("git", &["--no-replace-objects", "show", &revision])?;
    parse_release_trust_roots(&content)
}

fn is_full_git_object_id(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn parse_release_trust_roots(content: &str) -> Result<ReleaseTrustRoots, TaskError> {
    Ok(ReleaseTrustRoots {
        macos_signing_identity: parse_release_trust_root(
            content,
            "Developer ID Application identity",
        )?,
        macos_team_identifier: parse_release_trust_root(content, "Developer ID TeamIdentifier")?,
        macos_certificate_sha1: parse_release_trust_root(
            content,
            "Developer ID certificate SHA-1",
        )?,
        macos_certificate_sha256: parse_release_trust_root(
            content,
            "Developer ID certificate SHA-256",
        )?,
        certificate_identity: parse_release_trust_root(content, "Sigstore certificate identity")?,
        certificate_oidc_issuer: parse_release_trust_root(content, "Sigstore OIDC issuer")?,
    })
}

fn parse_release_trust_root(content: &str, label: &str) -> Result<String, TaskError> {
    let prefix = format!("- {label}: `");
    let values = content
        .lines()
        .filter_map(|line| {
            line.strip_prefix(&prefix)
                .and_then(|value| value.strip_suffix('`'))
        })
        .collect::<Vec<_>>();
    if values.len() != 1 || values[0].trim().is_empty() {
        return Err(TaskError::InvalidSourceContract(format!(
            "SECURITY.md must contain exactly one non-empty `{label}` trust root"
        )));
    }
    Ok(values[0].to_owned())
}

fn validate_release_identity_inputs(
    trust_roots: &ReleaseTrustRoots,
    certificate_identity: &str,
    certificate_oidc_issuer: &str,
    macos_signing_identity: &str,
) -> Result<(), TaskError> {
    for (label, committed, supplied) in [
        (
            "Developer ID Application identity",
            trust_roots.macos_signing_identity.as_str(),
            macos_signing_identity,
        ),
        (
            "Sigstore certificate identity",
            trust_roots.certificate_identity.as_str(),
            certificate_identity,
        ),
        (
            "Sigstore OIDC issuer",
            trust_roots.certificate_oidc_issuer.as_str(),
            certificate_oidc_issuer,
        ),
    ] {
        if committed == "UNBOUND" || committed != supplied {
            return Err(TaskError::InvalidSourceContract(format!(
                "release {label} must be bound in SECURITY.md and exactly match the supplied non-secret identity"
            )));
        }
    }
    if trust_roots.macos_team_identifier == "UNBOUND" {
        return Err(TaskError::InvalidSourceContract(
            "release Developer ID TeamIdentifier must be bound in SECURITY.md".to_owned(),
        ));
    }
    validate_hex_fingerprint(
        "Developer ID certificate SHA-1",
        &trust_roots.macos_certificate_sha1,
        40,
    )?;
    validate_hex_fingerprint(
        "Developer ID certificate SHA-256",
        &trust_roots.macos_certificate_sha256,
        64,
    )?;
    Ok(())
}

fn validate_hex_fingerprint(label: &str, value: &str, length: usize) -> Result<(), TaskError> {
    if value == "UNBOUND"
        || value.len() != length
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(TaskError::InvalidSourceContract(format!(
            "release {label} must be bound in SECURITY.md as exactly {length} hexadecimal characters"
        )));
    }
    Ok(())
}

fn release(
    certificate_identity: &str,
    certificate_oidc_issuer: &str,
    macos_signing_identity: &str,
    apple_notary_profile: &str,
) -> Result<(), TaskError> {
    let trust_roots = release_trust_roots()?;
    validate_release_identity_inputs(
        &trust_roots,
        certificate_identity,
        certificate_oidc_issuer,
        macos_signing_identity,
    )?;
    ensure_clean_source_tree()?;
    run("cosign", &["version"])?;
    run("xcrun", &["notarytool", "--version"])?;
    assemble(&[])?;
    sign_and_notarize_macos_artifacts(
        macos_signing_identity,
        &trust_roots.macos_certificate_sha1,
        &trust_roots.macos_certificate_sha256,
        apple_notary_profile,
        certificate_identity,
        certificate_oidc_issuer,
    )?;
    sign_release_artifacts()?;
    verify_signed_release(
        certificate_identity,
        certificate_oidc_issuer,
        macos_signing_identity,
        &trust_roots,
    )?;
    Ok(())
}

fn assemble(requested_targets: &[String]) -> Result<(), TaskError> {
    verify()?;
    run("syft", &["version"])?;
    let targets = validated_release_targets(requested_targets)?;
    ensure_release_build_tools(&targets)?;
    let source_date_epoch = release_source_date_epoch()?;
    let git_commit = output("git", &["--no-replace-objects", "rev-parse", "HEAD"])?;
    let git_tree = output("git", &["--no-replace-objects", "rev-parse", "HEAD^{tree}"])?;
    let source_tree_clean = source_tree_status()?.is_empty();
    let dist = PathBuf::from("dist");
    remove_directory_if_present(&dist)?;
    fs::create_dir_all(&dist).map_err(|source| io_error(&dist, source))?;
    let mut artifacts = Vec::new();
    for target in &targets {
        let first_target_dir = PathBuf::from("target/release-proof").join(format!("{target}-1"));
        let second_target_dir = PathBuf::from("target/release-proof").join(format!("{target}-2"));
        remove_directory_if_present(&first_target_dir)?;
        remove_directory_if_present(&second_target_dir)?;
        let first =
            build_release_target(target, &first_target_dir, &source_date_epoch, &git_commit)?;
        let second =
            build_release_target(target, &second_target_dir, &source_date_epoch, &git_commit)?;
        let first_hash = sha256_file(&first)?;
        let second_hash = sha256_file(&second)?;
        if first_hash != second_hash {
            return Err(TaskError::ReproducibilityMismatch {
                target: target.to_owned(),
                first: first_hash,
                second: second_hash,
            });
        }
        let artifact = dist.join(format!("cfctl-{target}"));
        fs::copy(&first, &artifact).map_err(|source| io_error(&artifact, source))?;
        run(
            "syft",
            &[
                &format!("file:{}", artifact.display()),
                "-o",
                &format!("spdx-json={}.spdx.json", artifact.display()),
            ],
        )?;
        artifacts.push(artifact.clone());
        artifacts.push(PathBuf::from(format!("{}.spdx.json", artifact.display())));
    }
    if targets
        .iter()
        .any(|target| target == "aarch64-unknown-linux-musl")
        && targets
            .iter()
            .any(|target| target == "x86_64-unknown-linux-musl")
    {
        let installer_path = render_linux_installer(&dist, None)?;
        artifacts.push(installer_path);
    }
    if targets
        .iter()
        .any(|target| target == "aarch64-apple-darwin")
        && targets.iter().any(|target| target == "x86_64-apple-darwin")
    {
        let formula_path = render_homebrew_formula(&dist)?;
        artifacts.push(formula_path);
    }
    let generated_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TaskError::Clock)?
        .as_secs();
    let provenance = serde_json::json!({
        "schema_version": 1,
        "generated_at_unix": generated_at,
        "source_date_epoch": source_date_epoch,
        "git_commit": git_commit,
        "git_tree": git_tree,
        "source_tree_clean": source_tree_clean,
        "rustc": output("rustc", &["--version", "--verbose"] )?,
        "cargo_auditable": format!("cargo-auditable {CARGO_AUDITABLE_VERSION}"),
        "syft": output("syft", &["version"] )?,
        "targets": targets,
        "artifacts": artifact_file_names(&artifacts)?,
        "hosted_builds": false,
    });
    let provenance_path = dist.join("provenance.json");
    fs::write(
        &provenance_path,
        serde_json::to_vec_pretty(&provenance)
            .map_err(|error| TaskError::Command(format!("serialize provenance: {error}")))?,
    )
    .map_err(|source| io_error(&provenance_path, source))?;
    artifacts.push(provenance_path);
    artifacts.sort();
    let sums_path = dist.join("SHA256SUMS");
    write_checksums(&sums_path, &artifacts)
}

fn sign_release_artifacts() -> Result<(), TaskError> {
    run(
        "cosign",
        &[
            "sign-blob",
            "--yes",
            "--bundle",
            "dist/SHA256SUMS.sigstore.json",
            "dist/SHA256SUMS",
        ],
    )?;
    run(
        "cosign",
        &[
            "sign-blob",
            "--yes",
            "--bundle",
            "dist/provenance.sigstore.json",
            "dist/provenance.json",
        ],
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct VerifiedArtifact {
    path: PathBuf,
    digest: String,
    size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct VerifiedRelease {
    commit: String,
    artifacts: Vec<VerifiedArtifact>,
}

fn snapshot_release_artifacts(paths: &[PathBuf]) -> Result<Vec<VerifiedArtifact>, TaskError> {
    paths
        .iter()
        .map(|path| {
            Ok(VerifiedArtifact {
                path: path.clone(),
                digest: sha256_file(path)?,
                size: fs::metadata(path)
                    .map_err(|source| io_error(path, source))?
                    .len(),
            })
        })
        .collect()
}

fn verify_signed_release(
    certificate_identity: &str,
    certificate_oidc_issuer: &str,
    macos_signing_identity: &str,
    trust_roots: &ReleaseTrustRoots,
) -> Result<VerifiedRelease, TaskError> {
    let artifacts = release_files()?;
    let verified_artifacts = snapshot_release_artifacts(&artifacts)?;
    validate_signed_release_file_set(&artifacts)?;
    verify_checksum_manifest()?;
    let team_identifier = verify_macos_distribution(
        macos_signing_identity,
        &trust_roots.macos_certificate_sha1,
        &trust_roots.macos_certificate_sha256,
    )?;
    if team_identifier != trust_roots.macos_team_identifier {
        return Err(TaskError::InvalidSourceContract(format!(
            "signed macOS TeamIdentifier `{team_identifier}` does not match SECURITY.md `{}`",
            trust_roots.macos_team_identifier
        )));
    }
    let commit = validate_release_provenance(
        macos_signing_identity,
        &team_identifier,
        &trust_roots.macos_certificate_sha1,
        &trust_roots.macos_certificate_sha256,
    )?;
    for (bundle, blob) in [
        ("dist/SHA256SUMS.sigstore.json", "dist/SHA256SUMS"),
        ("dist/provenance.sigstore.json", "dist/provenance.json"),
    ] {
        run(
            "cosign",
            &[
                "verify-blob",
                "--bundle",
                bundle,
                "--certificate-identity",
                certificate_identity,
                "--certificate-oidc-issuer",
                certificate_oidc_issuer,
                blob,
            ],
        )?;
    }
    if snapshot_release_artifacts(&artifacts)? != verified_artifacts {
        return Err(TaskError::Command(
            "release artifact bytes changed while verification was in progress".to_owned(),
        ));
    }
    Ok(VerifiedRelease {
        commit,
        artifacts: verified_artifacts,
    })
}

fn source_tree_status() -> Result<String, TaskError> {
    output(
        "git",
        &["status", "--porcelain=v1", "--untracked-files=normal"],
    )
}

fn ensure_clean_source_tree() -> Result<(), TaskError> {
    let status = source_tree_status()?;
    if status.is_empty() {
        Ok(())
    } else {
        Err(TaskError::UncleanSourceTree(status))
    }
}

fn validated_release_targets(requested_targets: &[String]) -> Result<Vec<String>, TaskError> {
    let targets = if requested_targets.is_empty() {
        RELEASE_TARGETS.iter().map(ToString::to_string).collect()
    } else {
        requested_targets.to_vec()
    };
    let mut seen = BTreeSet::new();
    for target in &targets {
        if !RELEASE_TARGETS.contains(&target.as_str()) {
            return Err(TaskError::UnsupportedReleaseTarget(target.clone()));
        }
        if !seen.insert(target.clone()) {
            return Err(TaskError::DuplicateReleaseTarget(target.clone()));
        }
    }
    Ok(targets)
}

fn ensure_release_build_tools(targets: &[String]) -> Result<(), TaskError> {
    let installed = output("rustup", &["target", "list", "--installed"])?;
    for target in targets {
        if !installed.lines().any(|installed| installed == target) {
            return Err(TaskError::MissingRustTarget(target.clone()));
        }
    }
    if targets.iter().any(|target| is_linux_musl(target)) {
        let _help = output("cargo", &["zigbuild", "--help"])?;
    }
    let installed_cargo_extensions = output("cargo", &["install", "--list"])?;
    let expected = format!("cargo-auditable v{CARGO_AUDITABLE_VERSION}:");
    if !installed_cargo_extensions
        .lines()
        .any(|line| line == expected)
    {
        return Err(TaskError::Command(format!(
            "release requires exactly {expected} install it with `cargo install cargo-auditable --version {CARGO_AUDITABLE_VERSION} --locked`"
        )));
    }
    Ok(())
}

fn release_source_date_epoch() -> Result<String, TaskError> {
    let value = match env::var("SOURCE_DATE_EPOCH") {
        Ok(value) => value,
        Err(_) => output(
            "git",
            &["--no-replace-objects", "show", "-s", "--format=%ct", "HEAD"],
        )?,
    };
    value
        .parse::<u64>()
        .map_err(|_| TaskError::InvalidSourceDateEpoch(value.clone()))?;
    Ok(value)
}

fn is_linux_musl(target: &str) -> bool {
    target.ends_with("-unknown-linux-musl")
}

fn release_build_subcommand(target: &str) -> &'static str {
    if is_linux_musl(target) {
        "zigbuild"
    } else {
        "build"
    }
}

fn release_build_driver(target: &str) -> [&'static str; 2] {
    ["auditable", release_build_subcommand(target)]
}

fn build_release_target(
    target: &str,
    target_dir: &Path,
    source_date_epoch: &str,
    git_commit: &str,
) -> Result<PathBuf, TaskError> {
    let mut command = Command::new("cargo");
    command.args(release_build_driver(target)).args([
        "--release",
        "--locked",
        "-p",
        "cfctl-cli",
        "--target",
        target,
        "--target-dir",
    ]);
    command
        .arg(target_dir)
        .env("SOURCE_DATE_EPOCH", source_date_epoch)
        .env("CFCTL_BUILD_GIT_COMMIT", git_commit)
        .env("CARGO_INCREMENTAL", "0")
        .env("TZ", "UTC");
    run_command(
        &mut command,
        &format!(
            "cargo auditable {} release build for {target}",
            release_build_subcommand(target)
        ),
    )?;
    Ok(target_dir.join(target).join("release/cfctl"))
}

fn remove_directory_if_present(path: &Path) -> Result<(), TaskError> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error(path, source)),
    }
}

fn render_homebrew_formula(dist: &Path) -> Result<PathBuf, TaskError> {
    let template_path = Path::new("packaging/homebrew/cfctl.rb.in");
    let template =
        fs::read_to_string(template_path).map_err(|source| io_error(template_path, source))?;
    let arm_hash = sha256_file(&dist.join("cfctl-aarch64-apple-darwin"))?;
    let intel_hash = sha256_file(&dist.join("cfctl-x86_64-apple-darwin"))?;
    let rendered = template
        .replace("@VERSION@", env!("CARGO_PKG_VERSION"))
        .replace("@AARCH64_APPLE_SHA256@", &arm_hash)
        .replace("@X86_64_APPLE_SHA256@", &intel_hash);
    if rendered.contains('@') {
        return Err(TaskError::FormulaPlaceholder);
    }
    let path = dist.join("cfctl.rb");
    fs::write(&path, rendered).map_err(|source| io_error(&path, source))?;
    Ok(path)
}

fn render_linux_installer(
    dist: &Path,
    sigstore_identity: Option<(&str, &str)>,
) -> Result<PathBuf, TaskError> {
    let template_path = Path::new("packaging/install.sh");
    let template =
        fs::read_to_string(template_path).map_err(|source| io_error(template_path, source))?;
    let rendered = render_linux_installer_text(
        &template,
        &sha256_file(&dist.join("cfctl-aarch64-unknown-linux-musl"))?,
        &sha256_file(&dist.join("cfctl-x86_64-unknown-linux-musl"))?,
        sigstore_identity,
    )?;
    let path = dist.join("install.sh");
    fs::write(&path, rendered).map_err(|source| io_error(&path, source))?;
    Ok(path)
}

fn render_linux_installer_text(
    template: &str,
    aarch64_hash: &str,
    x86_64_hash: &str,
    sigstore_identity: Option<(&str, &str)>,
) -> Result<String, TaskError> {
    for (name, hash) in [
        ("aarch64 Linux SHA-256", aarch64_hash),
        ("x86_64 Linux SHA-256", x86_64_hash),
    ] {
        if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(TaskError::InstallerTemplate(format!(
                "{name} must be a 64-character hexadecimal digest"
            )));
        }
    }
    let (identity, issuer) = match sigstore_identity {
        Some((identity, issuer)) => {
            validate_installer_identity_value("Sigstore certificate identity", identity)?;
            validate_installer_identity_value("Sigstore OIDC issuer", issuer)?;
            (
                shell_single_quote_fragment(identity),
                shell_single_quote_fragment(issuer),
            )
        }
        None => (
            "UNSIGNED_ASSEMBLY".to_owned(),
            "UNSIGNED_ASSEMBLY".to_owned(),
        ),
    };
    let rendered = template
        .replace("@AARCH64_LINUX_SHA256@", aarch64_hash)
        .replace("@X86_64_LINUX_SHA256@", x86_64_hash)
        .replace("@SIGSTORE_IDENTITY@", &identity)
        .replace("@SIGSTORE_OIDC_ISSUER@", &issuer);
    for placeholder in [
        "@AARCH64_LINUX_SHA256@",
        "@X86_64_LINUX_SHA256@",
        "@SIGSTORE_IDENTITY@",
        "@SIGSTORE_OIDC_ISSUER@",
    ] {
        if rendered.contains(placeholder) {
            return Err(TaskError::InstallerTemplate(format!(
                "unresolved placeholder {placeholder}"
            )));
        }
    }
    Ok(rendered)
}

fn validate_installer_identity_value(name: &str, value: &str) -> Result<(), TaskError> {
    if value.trim().is_empty() || value.contains(['\0', '\n', '\r']) {
        return Err(TaskError::InstallerTemplate(format!(
            "{name} must be non-empty and single-line"
        )));
    }
    Ok(())
}

fn shell_single_quote_fragment(value: &str) -> String {
    value.replace('\'', "'\"'\"'")
}

fn sign_and_notarize_macos_artifacts(
    signing_identity: &str,
    signing_certificate_sha1: &str,
    signing_certificate_sha256: &str,
    notary_profile: &str,
    sigstore_identity: &str,
    sigstore_issuer: &str,
) -> Result<(), TaskError> {
    if !signing_identity.starts_with("Developer ID Application: ") {
        return Err(TaskError::InvalidMacosSignature(
            "the selected identity must be a Developer ID Application certificate".to_owned(),
        ));
    }
    if notary_profile.trim().is_empty() {
        return Err(TaskError::InvalidNotarizationReceipt(
            "the Keychain notary profile name must not be empty".to_owned(),
        ));
    }
    let mut team_identifiers = BTreeSet::new();
    for target in MACOS_RELEASE_TARGETS {
        let artifact = Path::new("dist").join(format!("cfctl-{target}"));
        let artifact_text = path_text(&artifact)?;
        run(
            "codesign",
            &[
                "--force",
                "--sign",
                signing_certificate_sha1,
                "--options",
                "runtime",
                "--timestamp",
                artifact_text,
            ],
        )?;
        run(
            "codesign",
            &["--verify", "--strict", "--verbose=4", artifact_text],
        )?;
        let details = output_combined("codesign", &["-dvvv", artifact_text])?;
        team_identifiers.insert(validate_codesign_details(&details, signing_identity)?);
        verify_macos_signing_certificate(
            &artifact,
            target,
            signing_certificate_sha1,
            signing_certificate_sha256,
        )?;
    }
    if team_identifiers.len() != 1 {
        return Err(TaskError::InvalidMacosSignature(
            "the two macOS binaries were not signed by the same team".to_owned(),
        ));
    }
    let team_identifier = team_identifiers
        .into_iter()
        .next()
        .ok_or_else(|| TaskError::InvalidMacosSignature("missing TeamIdentifier".to_owned()))?;
    for target in MACOS_RELEASE_TARGETS {
        let artifact = Path::new("dist").join(format!("cfctl-{target}"));
        notarize_macos_artifact(target, &artifact, notary_profile)?;
    }
    refresh_macos_distribution_metadata(
        signing_identity,
        &team_identifier,
        signing_certificate_sha1,
        signing_certificate_sha256,
        sigstore_identity,
        sigstore_issuer,
    )
}

fn notarize_macos_artifact(
    target: &str,
    artifact: &Path,
    notary_profile: &str,
) -> Result<(), TaskError> {
    let work = Path::new("target/release-proof/notary").join(target);
    fs::create_dir_all(&work).map_err(|source| io_error(&work, source))?;
    let archive = work.join(format!("cfctl-{target}.zip"));
    remove_file_if_present(&archive)?;
    run(
        "ditto",
        &[
            "-c",
            "-k",
            "--keepParent",
            path_text(artifact)?,
            path_text(&archive)?,
        ],
    )?;
    let submission_text = output(
        "xcrun",
        &[
            "notarytool",
            "submit",
            path_text(&archive)?,
            "--keychain-profile",
            notary_profile,
            "--no-progress",
            "--output-format",
            "json",
        ],
    )?;
    let submission: serde_json::Value =
        serde_json::from_str(&submission_text).map_err(|error| {
            TaskError::InvalidNotarizationReceipt(format!(
                "notarytool returned invalid JSON for {target}: {error}"
            ))
        })?;
    let submission_id = submission
        .get("id")
        .and_then(serde_json::Value::as_str)
        .filter(|id| !id.trim().is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            TaskError::InvalidNotarizationReceipt(format!(
                "notarytool submit omitted the submission id for {target}"
            ))
        })?;
    let artifact_hash = sha256_file(artifact)?;
    let pending_receipt =
        notary_receipt_document(target, &artifact_hash, &submission_id, submission);
    write_notary_receipt(target, &work, &pending_receipt)?;
    let completed_text = output(
        "xcrun",
        &[
            "notarytool",
            "wait",
            &submission_id,
            "--keychain-profile",
            notary_profile,
            "--timeout",
            "1h",
            "--no-progress",
            "--output-format",
            "json",
        ],
    )?;
    let completed: serde_json::Value = serde_json::from_str(&completed_text).map_err(|error| {
        TaskError::InvalidNotarizationReceipt(format!(
            "notarytool wait returned invalid JSON for {target}: {error}"
        ))
    })?;
    let receipt = notary_receipt_document(target, &artifact_hash, &submission_id, completed);
    write_notary_receipt(target, &work, &receipt)?;
    validate_notary_receipt_value(&receipt, target, &artifact_hash)
}

fn notary_receipt_document(
    target: &str,
    artifact_hash: &str,
    submission_id: &str,
    submission: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "target": target,
        "artifact": format!("cfctl-{target}"),
        "artifact_sha256": artifact_hash,
        "submission_id": submission_id,
        "submission": submission,
    })
}

fn write_notary_receipt(
    target: &str,
    work: &Path,
    receipt: &serde_json::Value,
) -> Result<(), TaskError> {
    let bytes = serde_json::to_vec_pretty(receipt).map_err(|error| {
        TaskError::InvalidNotarizationReceipt(format!("serialize receipt for {target}: {error}"))
    })?;
    let receipt_path = notary_receipt_path(target);
    fs::write(&receipt_path, &bytes).map_err(|source| io_error(&receipt_path, source))?;
    let durable_path = work.join("receipt.json");
    fs::write(&durable_path, bytes).map_err(|source| io_error(&durable_path, source))
}

fn refresh_macos_distribution_metadata(
    signing_identity: &str,
    team_identifier: &str,
    signing_certificate_sha1: &str,
    signing_certificate_sha256: &str,
    sigstore_identity: &str,
    sigstore_issuer: &str,
) -> Result<(), TaskError> {
    for target in MACOS_RELEASE_TARGETS {
        let artifact = Path::new("dist").join(format!("cfctl-{target}"));
        run(
            "syft",
            &[
                &format!("file:{}", artifact.display()),
                "-o",
                &format!("spdx-json={}.spdx.json", artifact.display()),
            ],
        )?;
    }
    let _formula = render_homebrew_formula(Path::new("dist"))?;
    let _installer = render_linux_installer(
        Path::new("dist"),
        Some((sigstore_identity, sigstore_issuer)),
    )?;
    let provenance_path = Path::new("dist/provenance.json");
    let mut provenance: serde_json::Value = serde_json::from_slice(
        &fs::read(provenance_path).map_err(|source| io_error(provenance_path, source))?,
    )
    .map_err(|error| TaskError::InvalidProvenance(error.to_string()))?;
    provenance["artifacts"] = serde_json::json!(
        expected_unsigned_release_file_names()
            .into_iter()
            .filter(|name| name != "provenance.json")
            .collect::<Vec<_>>()
    );
    provenance["macos_distribution"] = serde_json::json!({
        "signing_identity": signing_identity,
        "team_identifier": team_identifier,
        "certificate_sha1": signing_certificate_sha1,
        "certificate_sha256": signing_certificate_sha256,
        "hardened_runtime": true,
        "secure_timestamp": true,
        "notarization_receipts": MACOS_RELEASE_TARGETS
            .iter()
            .map(|target| format!("notary-{target}.json"))
            .collect::<Vec<_>>(),
    });
    fs::write(
        provenance_path,
        serde_json::to_vec_pretty(&provenance)
            .map_err(|error| TaskError::InvalidProvenance(error.to_string()))?,
    )
    .map_err(|source| io_error(provenance_path, source))?;
    write_checksums(
        Path::new("dist/SHA256SUMS"),
        &unsigned_release_artifact_paths(),
    )
}

fn verify_macos_distribution(
    expected_identity: &str,
    expected_certificate_sha1: &str,
    expected_certificate_sha256: &str,
) -> Result<String, TaskError> {
    let mut team_identifiers = BTreeSet::new();
    for target in MACOS_RELEASE_TARGETS {
        let artifact = Path::new("dist").join(format!("cfctl-{target}"));
        let artifact_text = path_text(&artifact)?;
        run(
            "codesign",
            &["--verify", "--strict", "--verbose=4", artifact_text],
        )?;
        let details = output_combined("codesign", &["-dvvv", artifact_text])?;
        team_identifiers.insert(validate_codesign_details(&details, expected_identity)?);
        verify_macos_signing_certificate(
            &artifact,
            target,
            expected_certificate_sha1,
            expected_certificate_sha256,
        )?;
        let receipt_path = notary_receipt_path(target);
        let receipt: serde_json::Value = serde_json::from_slice(
            &fs::read(&receipt_path).map_err(|source| io_error(&receipt_path, source))?,
        )
        .map_err(|error| TaskError::InvalidNotarizationReceipt(error.to_string()))?;
        validate_notary_receipt_value(&receipt, target, &sha256_file(&artifact)?)?;
    }
    if team_identifiers.len() != 1 {
        return Err(TaskError::InvalidMacosSignature(
            "the two macOS artifacts do not bind the same TeamIdentifier".to_owned(),
        ));
    }
    team_identifiers
        .into_iter()
        .next()
        .ok_or_else(|| TaskError::InvalidMacosSignature("missing TeamIdentifier".to_owned()))
}

fn verify_macos_signing_certificate(
    artifact: &Path,
    target: &str,
    expected_certificate_sha1: &str,
    expected_certificate_sha256: &str,
) -> Result<(), TaskError> {
    let directory = Path::new("target/release-proof/signature");
    fs::create_dir_all(directory).map_err(|source| io_error(directory, source))?;
    let prefix = directory.join(format!("{target}-certificate-"));
    for index in 0..=3 {
        remove_file_if_present(&PathBuf::from(format!("{}{index}", prefix.display())))?;
    }
    let extract_argument = format!("--extract-certificates={}", path_text(&prefix)?);
    run("codesign", &["-d", &extract_argument, path_text(artifact)?])?;
    let leaf = PathBuf::from(format!("{}0", prefix.display()));
    let actual_sha1 = output("shasum", &["-a", "1", path_text(&leaf)?])?
        .split_whitespace()
        .next()
        .filter(|value| value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            TaskError::InvalidMacosSignature(
                "shasum did not return a valid signing certificate SHA-1".to_owned(),
            )
        })?;
    let actual_sha256 = sha256_file(&leaf)?;
    validate_macos_certificate_fingerprints(
        &actual_sha1,
        &actual_sha256,
        expected_certificate_sha1,
        expected_certificate_sha256,
    )
}

fn validate_macos_certificate_fingerprints(
    actual_sha1: &str,
    actual_sha256: &str,
    expected_sha1: &str,
    expected_sha256: &str,
) -> Result<(), TaskError> {
    if !actual_sha1.eq_ignore_ascii_case(expected_sha1) {
        return Err(TaskError::InvalidMacosSignature(format!(
            "signing certificate SHA-1 `{actual_sha1}` does not match SECURITY.md `{expected_sha1}`"
        )));
    }
    if !actual_sha256.eq_ignore_ascii_case(expected_sha256) {
        return Err(TaskError::InvalidMacosSignature(format!(
            "signing certificate SHA-256 `{actual_sha256}` does not match SECURITY.md `{expected_sha256}`"
        )));
    }
    Ok(())
}

fn validate_codesign_details(details: &str, expected_identity: &str) -> Result<String, TaskError> {
    if !expected_identity.starts_with("Developer ID Application: ") {
        return Err(TaskError::InvalidMacosSignature(
            "expected identity is not a Developer ID Application certificate".to_owned(),
        ));
    }
    let authority = details
        .lines()
        .find_map(|line| line.strip_prefix("Authority="))
        .ok_or_else(|| TaskError::InvalidMacosSignature("Authority is missing".to_owned()))?;
    if authority != expected_identity {
        return Err(TaskError::InvalidMacosSignature(format!(
            "Authority `{authority}` does not match `{expected_identity}`"
        )));
    }
    let flags = details
        .lines()
        .find(|line| line.starts_with("CodeDirectory "))
        .ok_or_else(|| TaskError::InvalidMacosSignature("CodeDirectory is missing".to_owned()))?;
    if !flags
        .split(['(', ')', ','])
        .any(|component| component.trim() == "runtime")
    {
        return Err(TaskError::InvalidMacosSignature(
            "hardened runtime flag is missing".to_owned(),
        ));
    }
    if !details.lines().any(|line| {
        line.strip_prefix("Timestamp=")
            .is_some_and(|value| !value.is_empty())
    }) {
        return Err(TaskError::InvalidMacosSignature(
            "secure timestamp is missing".to_owned(),
        ));
    }
    details
        .lines()
        .find_map(|line| line.strip_prefix("TeamIdentifier="))
        .filter(|value| !value.is_empty() && *value != "not set")
        .map(ToOwned::to_owned)
        .ok_or_else(|| TaskError::InvalidMacosSignature("TeamIdentifier is missing".to_owned()))
}

fn validate_notary_receipt_value(
    receipt: &serde_json::Value,
    expected_target: &str,
    expected_hash: &str,
) -> Result<(), TaskError> {
    let invalid = |message: &str| TaskError::InvalidNotarizationReceipt(message.to_owned());
    if receipt
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        != Some(1)
    {
        return Err(invalid("schema_version must be 1"));
    }
    if receipt.get("target").and_then(serde_json::Value::as_str) != Some(expected_target) {
        return Err(invalid("target does not match the macOS artifact"));
    }
    let expected_artifact = format!("cfctl-{expected_target}");
    if receipt.get("artifact").and_then(serde_json::Value::as_str)
        != Some(expected_artifact.as_str())
    {
        return Err(invalid("artifact name does not match the macOS target"));
    }
    if receipt
        .get("artifact_sha256")
        .and_then(serde_json::Value::as_str)
        != Some(expected_hash)
    {
        return Err(invalid("artifact_sha256 does not match the signed binary"));
    }
    let submission = receipt
        .get("submission")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| invalid("submission object is missing"))?;
    let submission_id = receipt
        .get("submission_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| invalid("submission_id is missing"))?;
    if uuid::Uuid::parse_str(submission_id).is_err() {
        return Err(invalid("submission_id is not a UUID"));
    }
    if submission.get("id").and_then(serde_json::Value::as_str) != Some(submission_id) {
        return Err(invalid(
            "notary service result does not match the submitted operation id",
        ));
    }
    if submission.get("status").and_then(serde_json::Value::as_str) != Some("Accepted") {
        return Err(invalid("notary service status is not Accepted"));
    }
    Ok(())
}

fn notary_receipt_path(target: &str) -> PathBuf {
    Path::new("dist").join(format!("notary-{target}.json"))
}

fn path_text(path: &Path) -> Result<&str, TaskError> {
    path.to_str().ok_or_else(|| {
        TaskError::Command(format!(
            "release path is not valid UTF-8: {}",
            path.display()
        ))
    })
}

fn remove_file_if_present(path: &Path) -> Result<(), TaskError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error(path, source)),
    }
}

fn release_tag_is_exact_version(tag: &str) -> bool {
    tag == format!("v{}", env!("CARGO_PKG_VERSION"))
}

fn publish(
    tag: &str,
    certificate_identity: &str,
    certificate_oidc_issuer: &str,
    macos_signing_identity: &str,
) -> Result<(), TaskError> {
    ensure_canonical_github_origin()?;
    let expected_tag = format!("v{}", env!("CARGO_PKG_VERSION"));
    if !release_tag_is_exact_version(tag) {
        return Err(TaskError::ReleaseTagMismatch {
            actual: tag.to_owned(),
            expected: expected_tag,
        });
    }
    let provenance_commit = release_provenance_commit()?;
    let tag_commit = remote_tag_commit(tag)?;
    if tag_commit != provenance_commit {
        return Err(TaskError::ReleaseCommitMismatch {
            tag: tag.to_owned(),
            tag_commit,
            provenance_commit,
        });
    }
    let trust_roots = release_trust_roots_at_commit(&provenance_commit)?;
    validate_release_identity_inputs(
        &trust_roots,
        certificate_identity,
        certificate_oidc_issuer,
        macos_signing_identity,
    )?;
    let verified_release = verify_signed_release(
        certificate_identity,
        certificate_oidc_issuer,
        macos_signing_identity,
        &trust_roots,
    )?;
    if verified_release.commit != provenance_commit {
        return Err(TaskError::ReleaseCommitMismatch {
            tag: tag.to_owned(),
            tag_commit: provenance_commit,
            provenance_commit: verified_release.commit,
        });
    }
    let draft = ensure_empty_draft_release(tag)?;
    let mut uploaded_assets = Vec::new();
    for artifact in verified_release.artifacts {
        upload_release_asset(&draft, &mut uploaded_assets, &artifact)?;
    }
    Ok(())
}

fn upload_release_asset(
    draft: &BoundDraftRelease,
    uploaded_assets: &mut Vec<ReleaseAsset>,
    artifact: &VerifiedArtifact,
) -> Result<(), TaskError> {
    ensure_same_draft_release(draft, uploaded_assets)
        .map_err(|error| publish_failure(error, draft, uploaded_assets))?;
    let Some(artifact_name) = artifact.path.file_name().and_then(std::ffi::OsStr::to_str) else {
        return Err(publish_failure(
            TaskError::Command(format!(
                "release artifact has no UTF-8 file name: {}",
                artifact.path.display()
            )),
            draft,
            uploaded_assets,
        ));
    };
    let observed_digest = sha256_file(&artifact.path)
        .map_err(|error| publish_failure(error, draft, uploaded_assets))?;
    let observed_size = fs::metadata(&artifact.path)
        .map_err(|source| {
            publish_failure(io_error(&artifact.path, source), draft, uploaded_assets)
        })?
        .len();
    if observed_digest != artifact.digest || observed_size != artifact.size {
        return Err(publish_failure(
            TaskError::Command(format!(
                "release artifact `{}` drifted after signed verification",
                artifact.path.display()
            )),
            draft,
            uploaded_assets,
        ));
    }
    let mut command = Command::new("gh");
    command.args(["release", "upload", &draft.tag, "--repo", GITHUB_REPOSITORY]);
    command.arg(&artifact.path);
    run_command(
        &mut command,
        &format!(
            "gh release upload {} {}",
            draft.tag,
            artifact.path.display()
        ),
    )
    .map_err(|error| publish_failure(error, draft, uploaded_assets))?;
    let release = github_release_state(&draft.tag)
        .and_then(|release| validate_bound_draft_release(draft, &release))
        .map_err(|error| publish_failure(error, draft, uploaded_assets))?;
    let asset = bind_new_uploaded_asset(
        &release,
        artifact_name,
        &artifact.digest,
        artifact.size,
        uploaded_assets,
    )
    .map_err(|error| publish_failure(error, draft, uploaded_assets))?;
    uploaded_assets.push(asset);
    ensure_same_draft_release(draft, uploaded_assets)
        .map_err(|error| publish_failure(error, draft, uploaded_assets))
}

fn publish_failure(
    error: TaskError,
    draft: &BoundDraftRelease,
    uploaded_assets: &[ReleaseAsset],
) -> TaskError {
    let rollback_failures = rollback_draft_release_assets(draft, uploaded_assets);
    TaskError::PublishFailed {
        upload: error.to_string(),
        rollback: if rollback_failures.is_empty() {
            "none; all previously identity-bound assets from this attempt were removed; an interrupted current upload still requires readback".to_owned()
        } else {
            rollback_failures.join("; ")
        },
    }
}

fn ensure_canonical_github_origin() -> Result<(), TaskError> {
    let origin = output("git", &["remote", "get-url", "origin"])?;
    if is_canonical_github_origin(&origin) {
        Ok(())
    } else {
        Err(TaskError::Command(format!(
            "origin `{origin}` does not match canonical GitHub repository `{GITHUB_REPOSITORY}`"
        )))
    }
}

fn is_canonical_github_origin(origin: &str) -> bool {
    matches!(
        origin,
        "https://github.com/rogu3bear/cfctl.git"
            | "https://github.com/rogu3bear/cfctl"
            | "git@github.com:rogu3bear/cfctl.git"
            | "ssh://git@github.com/rogu3bear/cfctl.git"
    )
}

fn remote_tag_commit(tag: &str) -> Result<String, TaskError> {
    let direct = format!("refs/tags/{tag}");
    let peeled = format!("{direct}^{{}}");
    let remote = output("git", &["ls-remote", "origin", &direct, &peeled])?;
    parse_remote_tag_commit(&remote, tag).ok_or_else(|| {
        TaskError::Command(format!(
            "origin does not expose an annotated release tag `{tag}` and its peeled commit"
        ))
    })
}

fn parse_remote_tag_commit(remote: &str, tag: &str) -> Option<String> {
    let direct = format!("refs/tags/{tag}");
    let peeled = format!("{direct}^{{}}");
    let mut direct_object = None;
    let mut peeled_commit = None;
    for line in remote.lines() {
        let (object, reference) = line.split_once('\t')?;
        if reference == peeled {
            peeled_commit = Some(object.to_owned());
        }
        if reference == direct {
            direct_object = Some(object.to_owned());
        }
    }
    match (direct_object, peeled_commit) {
        (Some(tag_object), Some(commit)) if tag_object != commit => Some(commit),
        _ => None,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReleaseAsset {
    id: String,
    name: String,
    api_path: String,
    digest: String,
    size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BoundDraftRelease {
    id: String,
    tag: String,
    assets: Vec<ReleaseAsset>,
}

fn github_release_state(tag: &str) -> Result<serde_json::Value, TaskError> {
    let release = output(
        "gh",
        &[
            "release",
            "view",
            tag,
            "--repo",
            GITHUB_REPOSITORY,
            "--json",
            "id,assets,isDraft,tagName",
        ],
    )?;
    serde_json::from_str(&release)
        .map_err(|error| TaskError::Command(format!("parse GitHub release state: {error}")))
}

fn release_assets(release: &serde_json::Value) -> Result<Vec<ReleaseAsset>, TaskError> {
    let mut assets = release
        .get("assets")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| TaskError::Command("GitHub release assets are missing".to_owned()))?
        .iter()
        .map(|asset| {
            asset
                .get("name")
                .and_then(serde_json::Value::as_str)
                .zip(asset.get("id").and_then(serde_json::Value::as_str))
                .zip(asset.get("apiUrl").and_then(serde_json::Value::as_str))
                .zip(asset.get("digest").and_then(serde_json::Value::as_str))
                .zip(asset.get("size").and_then(serde_json::Value::as_u64))
                .map(|((((name, id), api_url), digest), size)| ReleaseAsset {
                    id: id.to_owned(),
                    name: name.to_owned(),
                    api_path: api_url.to_owned(),
                    digest: digest.to_owned(),
                    size,
                })
                .ok_or_else(|| {
                    TaskError::Command("GitHub release asset identity is missing".to_owned())
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    assets.sort_by(|left, right| left.name.cmp(&right.name));
    for asset in &mut assets {
        let expected_prefix =
            format!("https://api.github.com/repos/{GITHUB_REPOSITORY}/releases/assets/");
        let Some(asset_database_id) = asset.api_path.strip_prefix(&expected_prefix) else {
            return Err(TaskError::Command(format!(
                "GitHub release asset `{}` points outside canonical repository",
                asset.name
            )));
        };
        if asset_database_id.is_empty()
            || !asset_database_id.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(TaskError::Command(format!(
                "GitHub release asset `{}` has a noncanonical database ID",
                asset.name
            )));
        }
        asset.api_path = format!("repos/{GITHUB_REPOSITORY}/releases/assets/{asset_database_id}");
    }
    Ok(assets)
}

fn rollback_draft_release_assets(
    draft: &BoundDraftRelease,
    uploaded_assets: &[ReleaseAsset],
) -> Vec<String> {
    let mut failures = Vec::new();
    for (index, asset) in uploaded_assets.iter().enumerate().rev() {
        let state = match github_release_state(&draft.tag)
            .and_then(|release| validate_bound_draft_release(draft, &release))
        {
            Ok(state) => state,
            Err(error) => {
                failures.push(error.to_string());
                break;
            }
        };
        if state.assets != uploaded_assets[..=index] {
            failures.push(format!(
                "refusing to compensate drifted release asset set before deleting `{}`",
                asset.name
            ));
            break;
        }
        if let Err(error) = run("gh", &["api", "--method", "DELETE", &asset.api_path]) {
            failures.push(error.to_string());
            break;
        }
        let readback = github_release_state(&draft.tag).and_then(|release| {
            validate_rollback_readback(draft, &release, &uploaded_assets[..index])
        });
        if let Err(error) = readback {
            failures.push(format!(
                "release asset `{}` DELETE lacked identity-bound post-delete readback: {error}",
                asset.name
            ));
            break;
        }
    }
    failures
}

fn validate_rollback_readback(
    draft: &BoundDraftRelease,
    release: &serde_json::Value,
    remaining_assets: &[ReleaseAsset],
) -> Result<(), TaskError> {
    let state = validate_bound_draft_release(draft, release)?;
    if state.assets == remaining_assets {
        Ok(())
    } else {
        Err(TaskError::Command(format!(
            "GitHub draft release `{}` asset set did not match the post-delete denominator",
            draft.tag
        )))
    }
}

fn ensure_empty_draft_release(tag: &str) -> Result<BoundDraftRelease, TaskError> {
    let release = github_release_state(tag)?;
    let draft = parse_bound_draft_release(&release)?;
    if release.get("isDraft").and_then(serde_json::Value::as_bool) != Some(true) {
        return Err(TaskError::ReleaseMustBeDraft(tag.to_owned()));
    }
    if draft.tag != tag {
        return Err(TaskError::ReleaseTagMismatch {
            actual: draft.tag,
            expected: tag.to_owned(),
        });
    }
    if draft.assets.is_empty() {
        Ok(draft)
    } else {
        Err(TaskError::ReleaseAlreadyHasAssets {
            tag: tag.to_owned(),
            assets: draft
                .assets
                .iter()
                .map(|asset| asset.name.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        })
    }
}

fn parse_bound_draft_release(release: &serde_json::Value) -> Result<BoundDraftRelease, TaskError> {
    Ok(BoundDraftRelease {
        id: release
            .get("id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| TaskError::Command("GitHub release ID is missing".to_owned()))?
            .to_owned(),
        tag: release
            .get("tagName")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| TaskError::Command("GitHub release tag is missing".to_owned()))?
            .to_owned(),
        assets: release_assets(release)?,
    })
}

fn validate_bound_draft_release(
    expected: &BoundDraftRelease,
    release: &serde_json::Value,
) -> Result<BoundDraftRelease, TaskError> {
    if release.get("isDraft").and_then(serde_json::Value::as_bool) != Some(true) {
        return Err(TaskError::ReleaseMustBeDraft(expected.tag.clone()));
    }
    let actual = parse_bound_draft_release(release)?;
    if actual.id != expected.id || actual.tag != expected.tag {
        return Err(TaskError::Command(format!(
            "GitHub draft release identity drifted from {}/{} to {}/{}",
            expected.id, expected.tag, actual.id, actual.tag
        )));
    }
    Ok(actual)
}

fn ensure_same_draft_release(
    expected: &BoundDraftRelease,
    uploaded_assets: &[ReleaseAsset],
) -> Result<(), TaskError> {
    let release = github_release_state(&expected.tag)?;
    let actual = validate_bound_draft_release(expected, &release)?;
    if actual.assets != uploaded_assets {
        return Err(TaskError::Command(format!(
            "GitHub draft release `{}` asset set drifted",
            expected.tag
        )));
    }
    Ok(())
}

fn bind_new_uploaded_asset(
    release: &BoundDraftRelease,
    expected_name: &str,
    expected_digest: &str,
    expected_size: u64,
    known_assets: &[ReleaseAsset],
) -> Result<ReleaseAsset, TaskError> {
    let matching = release
        .assets
        .iter()
        .filter(|asset| asset.name == expected_name)
        .collect::<Vec<_>>();
    let expected_digest = format!("sha256:{expected_digest}");
    if matching.len() != 1
        || known_assets.iter().any(|known| known.id == matching[0].id)
        || matching[0].digest != expected_digest
        || matching[0].size != expected_size
    {
        return Err(TaskError::Command(format!(
            "GitHub did not expose one new identity-bound asset named `{expected_name}`"
        )));
    }
    Ok(matching[0].clone())
}

fn release_files() -> Result<Vec<PathBuf>, TaskError> {
    let dist = Path::new("dist");
    let mut files = Vec::new();
    for entry in fs::read_dir(dist).map_err(|source| io_error(dist, source))? {
        let entry = entry.map_err(|source| io_error(dist, source))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|source| io_error(&path, source))?;
        if !metadata.file_type().is_file() {
            return Err(TaskError::InvalidReleaseArtifact(
                path.display().to_string(),
            ));
        }
        files.push(path);
    }
    files.sort();
    if files.is_empty() {
        return Err(TaskError::MissingArtifacts);
    }
    Ok(files)
}

fn expected_unsigned_release_file_names() -> BTreeSet<String> {
    let mut names = BTreeSet::from([
        "cfctl.rb".to_owned(),
        "install.sh".to_owned(),
        "notary-aarch64-apple-darwin.json".to_owned(),
        "notary-x86_64-apple-darwin.json".to_owned(),
        "provenance.json".to_owned(),
    ]);
    for target in RELEASE_TARGETS {
        names.insert(format!("cfctl-{target}"));
        names.insert(format!("cfctl-{target}.spdx.json"));
    }
    names
}

fn expected_signed_release_file_names() -> BTreeSet<String> {
    let mut names = expected_unsigned_release_file_names();
    names.extend([
        "SHA256SUMS".to_owned(),
        "SHA256SUMS.sigstore.json".to_owned(),
        "provenance.sigstore.json".to_owned(),
    ]);
    names
}

fn artifact_file_names(artifacts: &[PathBuf]) -> Result<Vec<String>, TaskError> {
    artifacts
        .iter()
        .map(|artifact| {
            artifact
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .map(ToOwned::to_owned)
                .ok_or_else(|| {
                    TaskError::Command(format!(
                        "release artifact name is not UTF-8: {}",
                        artifact.display()
                    ))
                })
        })
        .collect()
}

fn validate_signed_release_file_set(artifacts: &[PathBuf]) -> Result<(), TaskError> {
    let expected = expected_signed_release_file_names();
    let actual: BTreeSet<String> = artifact_file_names(artifacts)?.into_iter().collect();
    let missing = expected.difference(&actual).cloned().collect::<Vec<_>>();
    let unexpected = actual.difference(&expected).cloned().collect::<Vec<_>>();
    if missing.is_empty() && unexpected.is_empty() {
        Ok(())
    } else {
        Err(TaskError::ReleaseArtifactSet {
            missing: missing.join(", "),
            unexpected: unexpected.join(", "),
        })
    }
}

fn unsigned_release_artifact_paths() -> Vec<PathBuf> {
    expected_unsigned_release_file_names()
        .into_iter()
        .map(|name| Path::new("dist").join(name))
        .collect()
}

fn verify_checksum_manifest() -> Result<(), TaskError> {
    let expected = checksum_contents(&unsigned_release_artifact_paths())?;
    let path = Path::new("dist/SHA256SUMS");
    let actual = fs::read_to_string(path).map_err(|source| io_error(path, source))?;
    if actual == expected {
        Ok(())
    } else {
        Err(TaskError::ChecksumManifestMismatch)
    }
}

fn release_provenance_commit() -> Result<String, TaskError> {
    let path = Path::new("dist/provenance.json");
    let bytes = fs::read(path).map_err(|source| io_error(path, source))?;
    let provenance: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| TaskError::InvalidProvenance(error.to_string()))?;
    let commit = provenance
        .get("git_commit")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| TaskError::InvalidProvenance("git_commit is missing".to_owned()))?;
    if !is_full_git_object_id(commit) {
        return Err(TaskError::InvalidProvenance(
            "git_commit must be a full hexadecimal object ID".to_owned(),
        ));
    }
    Ok(commit.to_owned())
}

fn validate_release_provenance(
    expected_macos_identity: &str,
    expected_team_identifier: &str,
    expected_certificate_sha1: &str,
    expected_certificate_sha256: &str,
) -> Result<String, TaskError> {
    let path = Path::new("dist/provenance.json");
    let bytes = fs::read(path).map_err(|source| io_error(path, source))?;
    let provenance: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| TaskError::InvalidProvenance(error.to_string()))?;
    if provenance
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        != Some(1)
    {
        return Err(TaskError::InvalidProvenance(
            "schema_version must be 1".to_owned(),
        ));
    }
    if provenance
        .get("generated_at_unix")
        .and_then(serde_json::Value::as_u64)
        .is_none()
    {
        return Err(TaskError::InvalidProvenance(
            "generated_at_unix must be an unsigned timestamp".to_owned(),
        ));
    }
    let source_date_epoch = provenance
        .get("source_date_epoch")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| TaskError::InvalidProvenance("source_date_epoch is missing".to_owned()))?;
    source_date_epoch.parse::<u64>().map_err(|_| {
        TaskError::InvalidProvenance("source_date_epoch must be an unsigned timestamp".to_owned())
    })?;
    if provenance
        .get("source_tree_clean")
        .and_then(serde_json::Value::as_bool)
        != Some(true)
    {
        return Err(TaskError::InvalidProvenance(
            "source_tree_clean must be true".to_owned(),
        ));
    }
    if provenance
        .get("hosted_builds")
        .and_then(serde_json::Value::as_bool)
        != Some(false)
    {
        return Err(TaskError::InvalidProvenance(
            "hosted_builds must be false".to_owned(),
        ));
    }
    validate_provenance_artifact_contract(&provenance)?;
    validate_macos_provenance(
        &provenance,
        expected_macos_identity,
        expected_team_identifier,
        expected_certificate_sha1,
        expected_certificate_sha256,
    )?;
    let commit = provenance
        .get("git_commit")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| TaskError::InvalidProvenance("git_commit is missing".to_owned()))?
        .to_owned();
    let revision = format!("{commit}^{{tree}}");
    let actual_tree = output("git", &["--no-replace-objects", "rev-parse", &revision])?;
    let bound_tree = provenance
        .get("git_tree")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| TaskError::InvalidProvenance("git_tree is missing".to_owned()))?;
    if actual_tree != bound_tree {
        return Err(TaskError::InvalidProvenance(
            "git_tree does not match git_commit".to_owned(),
        ));
    }
    Ok(commit)
}

fn validate_macos_provenance(
    provenance: &serde_json::Value,
    expected_identity: &str,
    expected_team_identifier: &str,
    expected_certificate_sha1: &str,
    expected_certificate_sha256: &str,
) -> Result<(), TaskError> {
    let macos = provenance
        .get("macos_distribution")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| TaskError::InvalidProvenance("macos_distribution is missing".to_owned()))?;
    if macos
        .get("signing_identity")
        .and_then(serde_json::Value::as_str)
        != Some(expected_identity)
    {
        return Err(TaskError::InvalidProvenance(
            "macOS signing identity does not match the expected identity".to_owned(),
        ));
    }
    for (field, expected) in [
        ("certificate_sha1", expected_certificate_sha1),
        ("certificate_sha256", expected_certificate_sha256),
    ] {
        if macos.get(field).and_then(serde_json::Value::as_str) != Some(expected) {
            return Err(TaskError::InvalidProvenance(format!(
                "macOS {field} does not match the expected certificate fingerprint"
            )));
        }
    }
    if macos
        .get("team_identifier")
        .and_then(serde_json::Value::as_str)
        != Some(expected_team_identifier)
    {
        return Err(TaskError::InvalidProvenance(
            "macOS TeamIdentifier does not match the signed artifacts".to_owned(),
        ));
    }
    for field in ["hardened_runtime", "secure_timestamp"] {
        if macos.get(field).and_then(serde_json::Value::as_bool) != Some(true) {
            return Err(TaskError::InvalidProvenance(format!(
                "macos_distribution.{field} must be true"
            )));
        }
    }
    let expected_receipts = MACOS_RELEASE_TARGETS
        .iter()
        .map(|target| format!("notary-{target}.json"))
        .collect::<Vec<_>>();
    let actual_receipts = macos
        .get("notarization_receipts")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            TaskError::InvalidProvenance(
                "macos_distribution.notarization_receipts must be an array".to_owned(),
            )
        })?
        .iter()
        .map(|value| value.as_str().map(ToOwned::to_owned))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| {
            TaskError::InvalidProvenance(
                "every macOS notarization receipt must be a string".to_owned(),
            )
        })?;
    if actual_receipts != expected_receipts {
        return Err(TaskError::InvalidProvenance(
            "macOS notarization receipts are not the canonical two-target set".to_owned(),
        ));
    }
    Ok(())
}

fn validate_provenance_artifact_contract(provenance: &serde_json::Value) -> Result<(), TaskError> {
    let target_values = provenance
        .get("targets")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| TaskError::InvalidProvenance("targets must be an array".to_owned()))?;
    let targets = target_values
        .iter()
        .map(|target| {
            target.as_str().ok_or_else(|| {
                TaskError::InvalidProvenance("every target must be a string".to_owned())
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if targets != RELEASE_TARGETS {
        return Err(TaskError::InvalidProvenance(
            "targets must contain the four reviewed platforms in canonical order".to_owned(),
        ));
    }
    let expected_materials = expected_unsigned_release_file_names()
        .into_iter()
        .filter(|name| name != "provenance.json")
        .collect::<BTreeSet<_>>();
    let material_values = provenance
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| TaskError::InvalidProvenance("artifacts must be an array".to_owned()))?;
    let materials = material_values
        .iter()
        .map(|material| {
            material.as_str().map(ToOwned::to_owned).ok_or_else(|| {
                TaskError::InvalidProvenance("every artifact must be a string".to_owned())
            })
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if materials.len() != material_values.len() {
        return Err(TaskError::InvalidProvenance(
            "artifacts must not contain duplicate names".to_owned(),
        ));
    }
    if materials != expected_materials {
        return Err(TaskError::InvalidProvenance(
            "artifacts do not bind the complete unsigned material set".to_owned(),
        ));
    }
    Ok(())
}

fn write_checksums(path: &Path, artifacts: &[PathBuf]) -> Result<(), TaskError> {
    let lines = checksum_contents(artifacts)?;
    fs::write(path, lines).map_err(|source| io_error(path, source))
}

fn checksum_contents(artifacts: &[PathBuf]) -> Result<String, TaskError> {
    let mut lines = String::new();
    for artifact in artifacts {
        let digest = sha256_file(artifact)?;
        let name = artifact
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .ok_or_else(|| TaskError::Command("release artifact name is not UTF-8".to_owned()))?;
        let _result = writeln!(lines, "{digest}  {name}");
    }
    Ok(lines)
}

fn sha256_file(path: &Path) -> Result<String, TaskError> {
    let bytes = fs::read(path).map_err(|source| io_error(path, source))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn output(program: &str, arguments: &[&str]) -> Result<String, TaskError> {
    let result = Command::new(program)
        .args(arguments)
        .output()
        .map_err(|source| io_error(Path::new(program), source))?;
    if !result.status.success() {
        return Err(TaskError::Command(format!(
            "{program} {} exited {:?}",
            arguments.join(" "),
            result.status.code()
        )));
    }
    Ok(String::from_utf8_lossy(&result.stdout).trim().to_owned())
}

fn output_combined(program: &str, arguments: &[&str]) -> Result<String, TaskError> {
    let result = Command::new(program)
        .args(arguments)
        .output()
        .map_err(|source| io_error(Path::new(program), source))?;
    if !result.status.success() {
        return Err(TaskError::Command(format!(
            "{program} {} exited {:?}",
            arguments.join(" "),
            result.status.code()
        )));
    }
    let mut combined = String::from_utf8_lossy(&result.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&result.stderr));
    Ok(combined.trim().to_owned())
}

fn run(program: &str, arguments: &[&str]) -> Result<(), TaskError> {
    let mut command = Command::new(program);
    command.args(arguments);
    run_command(&mut command, &format!("{program} {}", arguments.join(" ")))
}

fn run_command(command: &mut Command, label: &str) -> Result<(), TaskError> {
    let status = command
        .status()
        .map_err(|source| io_error(Path::new(label), source))?;
    if status.success() {
        Ok(())
    } else {
        Err(TaskError::Command(format!(
            "{label} exited {:?}",
            status.code()
        )))
    }
}

fn io_error(path: &Path, source: std::io::Error) -> TaskError {
    TaskError::Io {
        path: path.display().to_string(),
        source,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::{
        fs,
        io::Write as _,
        os::unix::fs::PermissionsExt as _,
        path::Path,
        process::{Command, Output, Stdio},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{
        PrePushRegistration, RELEASE_TARGETS, VERIFY_CROSS_TARGET, bind_new_uploaded_asset,
        classify_pre_push_registration, collect_workflow_paths, contains_retired_public_domain,
        expected_signed_release_file_names, extract_cfctl_command_references,
        extract_cfctl_command_refs, extract_prose_command_refs, is_canonical_github_origin,
        is_declared_quarantine_path, is_forbidden_quarantine_consumer, is_full_git_object_id,
        is_linux_musl, parse_bound_draft_release, parse_release_trust_roots,
        parse_remote_tag_commit, release_build_driver, release_build_subcommand,
        release_tag_is_exact_version, render_linux_installer_text, repository_root,
        security_proof_commands, validate_bootstrap_contract, validate_bound_draft_release,
        validate_codesign_details, validate_command_refs, validate_extracted_command_refs,
        validate_local_only_ci_contract, validate_macos_certificate_fingerprints,
        validate_macos_provenance, validate_notary_receipt_value, validate_public_domain_anchor,
        validate_release_identity_inputs, validate_rollback_readback,
        validate_signed_release_file_set, validate_signed_release_posture_contract,
        validate_xtask_alias_contract, validated_release_targets,
        verify_active_guidance_has_no_v1_commands, verify_documented_contracts,
        verify_generated_guidance_section_text, verify_managed_agent_documents,
        verify_public_domain_contract, verify_quickstart_pins_the_release_version,
        verify_signed_release_posture_contract, verify_tracked_cfctl_command_references,
        verify_v1_cutover_contract, verify_workspace_dependency_versions,
    };

    #[test]
    fn bootstrap_does_not_hold_an_outer_cargo_gate_around_xtask() {
        validate_bootstrap_contract(
            "git status --porcelain=v1 --untracked-files=normal\n(cd \"$root\" && cargo xtask verify)\n",
        )
            .expect("the public xtask entrypoint is safe for nested Cargo commands");

        let error = validate_bootstrap_contract(
            "(cd \"$root\" && cargo run --locked -p xtask -- verify)\n",
        )
        .expect_err("an outer cargo run gate would deadlock nested proof commands");
        assert!(
            error.to_string().contains("must not hold a Cargo run gate"),
            "unexpected error: {error}"
        );

        let error = validate_bootstrap_contract("(cd \"$root\" && cargo xtask verify)\n")
            .expect_err("bootstrap must reject untracked compiler inputs before installation");
        assert!(
            error
                .to_string()
                .contains("tracked-and-untracked cleanliness invariant"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn xtask_alias_contract_rejects_toml_lookalikes() {
        validate_xtask_alias_contract(include_str!("../../.cargo/config.toml"))
            .expect("repository xtask alias is canonical");

        for (name, source) in [
            (
                "relocated assignment",
                include_str!("../../tests/fixtures/xtask-alias-relocated.toml"),
            ),
            (
                "single-quoted relocated duplicate",
                include_str!("../../tests/fixtures/xtask-alias-single-quoted-relocated.toml"),
            ),
            (
                "multiline string lookalike",
                include_str!("../../tests/fixtures/xtask-alias-multiline-string.toml"),
            ),
        ] {
            let error = validate_xtask_alias_contract(source)
                .expect_err("TOML lookalike must not satisfy alias.xtask");
            assert!(
                error.to_string().contains("xtask"),
                "unexpected {name} error: {error}"
            );
        }
    }

    #[test]
    fn xtask_alias_contract_rejects_wrong_semantic_shapes() {
        for (name, source) in [
            ("absence", "[alias]\nother = [\"run\"]\n"),
            (
                "wrong type",
                "[alias]\nxtask = \"run --locked -p xtask --\"\n",
            ),
            (
                "wrong value",
                "[alias]\nxtask = [\"run\", \"-p\", \"xtask\", \"--\"]\n",
            ),
            (
                "duplicate",
                concat!(
                    "[alias]\n",
                    "xtask = [\"run\", \"--locked\", \"-p\", \"xtask\", \"--\"]\n",
                    "'xtask' = [\"run\", \"--locked\", \"-p\", \"xtask\", \"--\"]\n",
                ),
            ),
        ] {
            let error = validate_xtask_alias_contract(source)
                .expect_err("noncanonical semantic shape must fail closed");
            assert!(
                error.to_string().contains("xtask") || error.to_string().contains("valid TOML"),
                "unexpected {name} error: {error}"
            );
        }
    }

    #[test]
    fn active_sources_use_only_the_cfctl_com_public_domain() {
        verify_public_domain_contract().expect("active sources use only cfctl.com");

        let callback_anchor =
            "pub const CFCTL_CALLBACK_URL: &str = \"https://cfctl.com/oauth/callback\";";
        let wrong_domain = callback_anchor.replace("cfctl.com", "cfctl.net");
        let error = validate_public_domain_anchor(
            "crates/cfctl-auth/src/lib.rs",
            &wrong_domain,
            callback_anchor,
        )
        .expect_err("a different public domain must fail closed");
        assert!(
            error
                .to_string()
                .contains("exact cfctl.com public identity")
        );

        assert!(
            contains_retired_public_domain(&["https://CFCTL", ".IO/oauth/callback"].concat()),
            "the active-source scan must normalize retired-domain case"
        );
    }

    #[test]
    fn local_only_ci_rejects_hosted_workflows_and_policy_drift() {
        const CONTRIBUTING: &str =
            "The repository does not require GitHub Actions or another hosted CI service.";
        const README: &str = "no GitHub Actions workflow or hosted CI service is required";

        validate_local_only_ci_contract(&[], CONTRIBUTING, README)
            .expect("the declared local-only contract is valid");

        let error = validate_local_only_ci_contract(
            &[".github/workflows/hosted-proof.yml".to_owned()],
            CONTRIBUTING,
            README,
        )
        .expect_err("a hosted workflow would reintroduce the forbidden purchase dependency");
        assert!(error.to_string().contains("local-only CI forbids"));

        let error = validate_local_only_ci_contract(&[], "hosted proof required", README)
            .expect_err("contributor guidance may not drift back to hosted authority");
        assert!(error.to_string().contains("CONTRIBUTING.md"));

        let error = validate_local_only_ci_contract(&[], CONTRIBUTING, "hosted proof required")
            .expect_err("README guidance may not drift back to hosted authority");
        assert!(error.to_string().contains("README.md"));
    }

    #[test]
    fn local_only_ci_distinguishes_absent_from_unobservable_workflow_roots() {
        let root = Path::new(".github/workflows");
        let absent = collect_workflow_paths(
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "absent fixture",
            )),
            root,
        )
        .expect("an absent workflow root is the intended local-only state");
        assert!(absent.is_empty());

        let error = collect_workflow_paths(
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "unobservable fixture",
            )),
            root,
        )
        .expect_err("an unobservable workflow root must block proof");
        assert!(error.to_string().contains(".github/workflows"));
    }

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
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$FAKE_CARGO_LOG\"\n\
             if [ -n \"${FAKE_CARGO_MUTATE_PATH:-}\" ]; then\n\
               printf 'mutated\\n' > \"$FAKE_CARGO_MUTATE_PATH\"\n\
             fi\n",
        )
        .expect("fake cargo is written");
        fs::set_permissions(&fake_cargo, fs::Permissions::from_mode(0o755))
            .expect("fake cargo is executable");
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
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-q", "-m", "clean fixture"]);
        let clean_oid = String::from_utf8(git(&repo, &["rev-parse", "HEAD"]).stdout)
            .expect("fixture oid is UTF-8")
            .trim()
            .to_owned();
        let zero_oid = "0".repeat(clean_oid.len());
        let clean_update = format!("refs/heads/main {clean_oid} refs/heads/main {zero_oid}\n");
        let clean = run_hook(&repo, &fake_bin, &cargo_log, &clean_update, None, false);
        assert!(
            clean.status.success(),
            "one clean checked-out branch object must pass: {}",
            String::from_utf8_lossy(&clean.stderr)
        );
        assert_eq!(
            fs::read_to_string(&cargo_log).expect("fake cargo ran"),
            "xtask verify\n"
        );

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
            "xtask verify\n"
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
        let non_head_update =
            format!("refs/heads/other {workflow_oid} refs/heads/other {zero_oid}\n");
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

    #[test]
    fn command_reference_extraction_is_structural_and_ignores_prose() {
        let markdown = concat!(
            "cfctl persists managed state without teaching a command.\n",
            "To compare the desired state, run cfctl diff dns.record before approval.\n",
            "`cfctl catalog search \"dns\" --json`\n",
            "```bash\n",
            "./cfctl diff dns.record\n",
            "```\n",
        );
        assert_eq!(
            extract_cfctl_command_references("docs/example.md", markdown),
            vec!["diff".to_owned(), "catalog".to_owned(), "diff".to_owned()]
        );

        let json = r#"{"commands":["cfctl guide --topic system","not a command"],"description":"cfctl persists managed state","next_action":"Run cfctl hostname verify now"}"#;
        assert_eq!(
            extract_cfctl_command_references("example.json", json),
            vec!["guide".to_owned(), "hostname".to_owned()]
        );

        let structured_argv = r#"{"next_action":{"argv":["cfctl","diff","dns.record"]}}"#;
        assert_eq!(
            extract_cfctl_command_references("example.json", structured_argv),
            vec!["diff".to_owned()]
        );
    }

    #[test]
    fn subcommand_references_are_extracted_only_in_command_context() {
        let markdown = concat!(
            "```bash\n",
            "cfctl catalog show dns-records-list\n",
            "cfctl keys policy approve authority-1\n",
            "cfctl call dns-records-list\n",
            "cfctl catalog search \"dns\"\n",
            "cfctl resolve \"list dns records\"\n",
            "cfctl migrate v1\n",
            "```\n",
            "Prose mentioning cfctl workspace discovery must not be checked.\n",
        );
        let pairs = extract_cfctl_command_refs("docs/example.md", markdown)
            .into_iter()
            .map(|reference| (reference.verb, reference.path))
            .collect::<Vec<_>>();
        assert_eq!(
            pairs,
            vec![
                // Extraction runs the whole plausible-token chain; separating
                // subcommands from arguments is the tree walk's job.
                (
                    "catalog".to_owned(),
                    vec!["show".to_owned(), "dns-records-list".to_owned()]
                ),
                (
                    "keys".to_owned(),
                    vec![
                        "policy".to_owned(),
                        "approve".to_owned(),
                        "authority-1".to_owned()
                    ]
                ),
                // `call` is not a command group, so its trailing token is
                // extracted but never checked against a tree.
                ("call".to_owned(), vec!["dns-records-list".to_owned()]),
                // A trailing quoted argument stops the chain.
                ("catalog".to_owned(), vec!["search".to_owned()]),
                // A quoted argument in the subcommand position is not plausible.
                ("resolve".to_owned(), Vec::new()),
                ("migrate".to_owned(), vec!["v1".to_owned()]),
            ],
            "prose `workspace discovery` must not appear as a checked subcommand"
        );
    }

    #[test]
    fn managed_agent_documents_teach_only_real_commands() {
        verify_managed_agent_documents().expect("managed agent documents bind to the command tree");
    }

    #[test]
    fn front_matter_is_metadata_not_command_examples() {
        // "Use cfctl as …" reads as an instructional prefix plus a verb, so a
        // description sentence would otherwise be linted as `cfctl as`.
        let document = concat!(
            "---\n",
            "name: cfctl\n",
            "description: Use cfctl as the universal governed Cloudflare control plane.\n",
            "---\n\n",
            "Run `cfctl doctor --json` to orient.\n",
        );
        let references = extract_prose_command_refs(document, true, false);
        assert_eq!(references.len(), 1, "only the body command should extract");
        assert_eq!(references[0].verb, "doctor");
    }

    #[test]
    fn flags_are_validated_against_the_real_parser() {
        // A flag that does not exist must fail, including on the leaf verbs the
        // command tree does not model.
        for teaching in [
            "```bash\ncfctl plans approve op-1 --yolo\n```\n",
            "```bash\ncfctl call some-capability --selektor a=b\n```\n",
        ] {
            let error = validate_command_refs("docs/example.md", teaching)
                .expect_err("an undeclared flag must be rejected");
            assert!(
                error.to_string().contains("unknown flag"),
                "unexpected error: {error}"
            );
        }

        // Real flags pass, in every form docs actually use them: attached
        // values, the global before the verb, and flags on a leaf verb.
        let valid = concat!(
            "```bash\n",
            "cfctl plans approve op-1 --yes --max-cost=USD:5.00\n",
            "cfctl --json catalog search \"dns\" --limit 5\n",
            "cfctl call some-capability --selector zone_id=z --value-out ./secret\n",
            "cfctl keys mint --account acct --permission group --user\n",
            "cfctl guide --topic system\n",
            "```\n",
        );
        validate_command_refs("docs/example.md", valid).expect("real flags must pass");
    }

    #[test]
    fn managed_agent_document_gate_rejects_an_unknown_subcommand() {
        // The gate is only worth having if it fails on a document that teaches
        // a command the tree does not declare, so prove that directly.
        let taught = concat!(
            "# Managed instructions\n\n",
            "Run with `cfctl plans frobnicate <operation-id>`.\n",
        );
        let error = validate_extracted_command_refs(
            "managed document fixture",
            extract_prose_command_refs(taught, true, false),
        )
        .expect_err("an undeclared subcommand must be rejected");
        assert!(
            error.to_string().contains("plans frobnicate"),
            "error must name the offending command: {error}"
        );
    }

    #[test]
    fn deep_subcommand_references_bind_to_the_full_tree() {
        // Depth 3 is real surface (`keys policy approve`), so a typo there has
        // to fail rather than pass because the linter stopped looking at depth 2.
        let typo = concat!("```bash\n", "cfctl keys policy frobnicate\n", "```\n");
        let error = validate_command_refs("docs/example.md", typo)
            .expect_err("depth-3 typo must be rejected");
        assert!(
            error.to_string().contains("keys policy frobnicate"),
            "error must name the full path: {error}"
        );

        // Arguments after a leaf are free text, not subcommands: `show` is a
        // leaf, so a capability id following it must not be validated.
        let arguments_after_a_leaf = concat!(
            "```bash\n",
            "cfctl catalog show dns-records-list\n",
            "cfctl keys policy approve authority-1\n",
            "cfctl call dns-records-list\n",
            "```\n",
        );
        assert!(validate_command_refs("docs/example.md", arguments_after_a_leaf).is_ok());
    }

    #[test]
    fn workspace_dependency_versions_match_the_package_version() {
        verify_workspace_dependency_versions().expect("intra-workspace pins match the version");
    }

    #[test]
    fn quickstart_pins_the_current_release_download_path() {
        let repository_root = repository_root().expect("repository root");
        verify_quickstart_pins_the_release_version(repository_root)
            .expect("QUICKSTART pins this version");
    }

    #[test]
    fn quickstart_release_download_path_fails_closed_on_version_drift() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock follows Unix epoch")
            .as_nanos();
        let fixture_root = std::env::temp_dir().join(format!(
            "cfctl-quickstart-version-drift-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&fixture_root).expect("fixture directory is created");
        fs::write(
            fixture_root.join("QUICKSTART.md"),
            "Download https://github.com/rogu3bear/cfctl/releases/download/v0.0.0/cfctl\n",
        )
        .expect("drifted QUICKSTART fixture is written");

        let error = verify_quickstart_pins_the_release_version(&fixture_root)
            .expect_err("a stale release download path must fail closed");
        let expected = format!("download/v{}/", env!("CARGO_PKG_VERSION"));
        assert!(
            error.to_string().contains(&expected),
            "error must name the required release path: {error}"
        );

        fs::remove_dir_all(&fixture_root).expect("fixture directory is removed");
    }

    #[test]
    fn tracked_subcommand_references_bind_to_the_command_tree() {
        let result = verify_tracked_cfctl_command_references();
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn instructional_unknown_command_references_are_not_treated_as_description() {
        assert_eq!(
            extract_cfctl_command_references(
                "docs/example.md",
                concat!(
                    "When you invoke cfctl that way, use a file.\n",
                    "To inspect the legacy edge, run cfctl frobnicate now.\n",
                ),
            ),
            vec!["frobnicate".to_owned()]
        );
    }

    #[test]
    fn quarantine_consumers_cover_tracked_source_and_executable_files() {
        assert!(is_forbidden_quarantine_consumer(
            "tools/replay.sh",
            "jq . compat/v1/catalog/runtime.json"
        ));
        assert!(!is_forbidden_quarantine_consumer(
            "docs/v1-parity.md",
            "The compat/v1/catalog tree is inert migration evidence."
        ));
        assert!(!is_forbidden_quarantine_consumer(
            "crates/cfctl-cli/src/runtime/v1_migration.rs",
            "let retained_repo_state = \"compat/v1/state\";"
        ));
        assert!(is_forbidden_quarantine_consumer(
            "crates/cfctl-cli/src/runtime/health_commands.rs",
            "let retained_repo_state = \"compat/v1/state\";"
        ));
        assert!(is_forbidden_quarantine_consumer(
            "crates/cfctl-cli/src/runtime/v1_migration.rs",
            "let retired_catalog = \"compat/v1/catalog\";"
        ));
    }

    #[test]
    fn quarantine_manifest_does_not_exempt_undeclared_subtrees() {
        let roots = ["compat/v1/catalog", "compat/v1/state"];
        assert!(is_declared_quarantine_path(
            "compat/v1/catalog/runtime.json",
            &roots
        ));
        assert!(is_declared_quarantine_path("compat/v1/README.md", &roots));
        assert!(is_declared_quarantine_path(
            "compat/v1/manifest.json",
            &roots
        ));
        assert!(!is_declared_quarantine_path(
            "compat/v1/undeclared/run.sh",
            &roots
        ));
    }

    #[test]
    fn v1_quarantine_manifest_and_tracked_commands_are_bound() {
        let result = verify_v1_cutover_contract();
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn pre_push_registration_reports_only_a_gate_that_will_not_run() {
        let root = Path::new("/Users/star/dev/cloudflare");
        let digest = "a".repeat(64);
        let other = "b".repeat(64);
        let allowlist = format!(
            "# comment\n\
             /Users/star/dev/adapter-os pre-commit={other} pre-push={other}\n\
             /Users/star/dev/cloudflare pre-push={digest}\n"
        );

        assert_eq!(
            classify_pre_push_registration(Some(&allowlist), root, Some(&digest)),
            PrePushRegistration::Registered
        );
        assert_eq!(
            classify_pre_push_registration(Some(&allowlist), root, Some(&other)),
            PrePushRegistration::DigestStale,
            "a pinned digest that no longer matches blocks every push"
        );
        assert_eq!(
            classify_pre_push_registration(
                Some(&allowlist),
                Path::new("/Users/star/dev/unlisted"),
                Some(&digest)
            ),
            PrePushRegistration::NotRegistered,
            "an unregistered repo is passed over in silence and must be reported"
        );
        assert_eq!(
            classify_pre_push_registration(None, root, Some(&digest)),
            PrePushRegistration::MechanismAbsent,
            "a machine without the allowlist gets no advice it cannot act on"
        );
        // A repo whose prefix matches another entry must not be mistaken for it.
        assert_eq!(
            classify_pre_push_registration(
                Some(&allowlist),
                Path::new("/Users/star/dev/cloud"),
                Some(&digest)
            ),
            PrePushRegistration::NotRegistered
        );
    }

    #[test]
    fn local_proof_includes_dependency_policy_and_full_history_secret_scan() {
        assert_eq!(
            security_proof_commands(),
            [
                ("cargo", &["deny", "check"][..]),
                (
                    "gitleaks",
                    &["detect", "--source", ".", "--no-banner", "--redact"][..],
                ),
            ]
        );
    }

    #[test]
    fn active_guidance_does_not_reteach_archived_v1_commands() {
        let result = verify_active_guidance_has_no_v1_commands();
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn generated_guidance_sections_require_an_exact_projection_match() {
        let content = concat!(
            "before\n",
            "<!-- BEGIN CFCTL GENERATED: system-guide -->\n",
            "canonical body\n",
            "<!-- END CFCTL GENERATED: system-guide -->\n",
            "after\n",
        );
        assert!(
            verify_generated_guidance_section_text(content, "system-guide", "canonical body")
                .is_ok()
        );
        assert!(
            verify_generated_guidance_section_text(content, "system-guide", "drifted body")
                .is_err()
        );
        assert!(
            verify_generated_guidance_section_text(
                "<!-- BEGIN CFCTL GENERATED: system-guide -->\ncanonical body\n",
                "system-guide",
                "canonical body",
            )
            .is_err()
        );
    }

    #[test]
    fn checked_in_guidance_matches_the_executable_projection() {
        let result = verify_documented_contracts();
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn signed_release_posture_is_consistent_across_authority_and_consumers() {
        let repository_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask has a repository parent");
        let result = verify_signed_release_posture_contract(repository_root);
        assert!(result.is_ok(), "{result:?}");

        let paths = [
            "README.md",
            "QUICKSTART.md",
            "SECURITY.md",
            "CONTRIBUTING.md",
            "site/docs/LAUNCH_CHECKLIST.md",
        ];
        let mut documents = paths
            .iter()
            .map(|path| {
                (
                    *path,
                    fs::read_to_string(repository_root.join(path)).expect("read posture document"),
                )
            })
            .collect::<Vec<_>>();
        documents
            .iter_mut()
            .find(|(path, _)| *path == "README.md")
            .expect("README document")
            .1
            .push_str("\nPublished releases are unsigned by operator decision\n");
        let borrowed = documents
            .iter()
            .map(|(path, content)| (*path, content.as_str()))
            .collect::<Vec<_>>();
        let error = validate_signed_release_posture_contract(&borrowed)
            .expect_err("retired unsigned posture must fail closed");
        assert!(
            error
                .to_string()
                .contains("retired unsigned release posture")
        );
    }

    #[test]
    fn publication_receiver_is_bound_to_origin_and_one_draft_identity() {
        assert!(is_canonical_github_origin(
            "https://github.com/rogu3bear/cfctl.git"
        ));
        assert!(is_canonical_github_origin(
            "git@github.com:rogu3bear/cfctl.git"
        ));
        assert!(!is_canonical_github_origin(
            "https://github.com/example/cfctl.git"
        ));

        let release = serde_json::json!({
            "id": "RELEASE_1",
            "tagName": "v1.3.0",
            "isDraft": true,
            "assets": [{
                "id": "ASSET_1",
                "name": "SHA256SUMS",
                "apiUrl": "https://api.github.com/repos/rogu3bear/cfctl/releases/assets/1",
                "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "size": 42
            }]
        });
        let bound = parse_bound_draft_release(&release).expect("bound draft");
        assert!(validate_bound_draft_release(&bound, &release).is_ok());
        let uploaded = bind_new_uploaded_asset(
            &bound,
            "SHA256SUMS",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            42,
            &[],
        )
        .expect("one new identity-bound asset");
        assert!(bind_new_uploaded_asset(&bound, "missing", "a", 42, &[]).is_err());
        assert!(
            bind_new_uploaded_asset(&bound, "SHA256SUMS", "b", 42, &[]).is_err(),
            "provider digest drift must fail closed"
        );
        assert!(
            bind_new_uploaded_asset(
                &bound,
                "SHA256SUMS",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                41,
                &[],
            )
            .is_err(),
            "provider size drift must fail closed"
        );
        assert!(
            bind_new_uploaded_asset(
                &bound,
                "SHA256SUMS",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                42,
                &[uploaded],
            )
            .is_err()
        );

        let mut changed_id = release.clone();
        changed_id["id"] = serde_json::json!("RELEASE_2");
        assert!(validate_bound_draft_release(&bound, &changed_id).is_err());

        let mut published = release.clone();
        published["isDraft"] = serde_json::json!(false);
        assert!(validate_bound_draft_release(&bound, &published).is_err());

        let empty_readback = serde_json::json!({
            "id": "RELEASE_1",
            "tagName": "v1.3.0",
            "isDraft": true,
            "assets": []
        });
        assert!(validate_rollback_readback(&bound, &empty_readback, &[]).is_ok());
        assert!(
            validate_rollback_readback(&bound, &release, &[]).is_err(),
            "a residual asset must keep compensation unresolved"
        );
        let invalid_readback = serde_json::json!({
            "tagName": "v1.3.0",
            "isDraft": true,
            "assets": []
        });
        assert!(
            validate_rollback_readback(&bound, &invalid_readback, &[]).is_err(),
            "a readback without the bound release identity must fail closed"
        );

        let mut crossed_repository = release;
        crossed_repository["assets"][0]["apiUrl"] =
            serde_json::json!("https://api.github.com/repos/example/cfctl/releases/assets/1");
        assert!(parse_bound_draft_release(&crossed_repository).is_err());
    }

    #[test]
    fn release_inputs_must_match_committed_non_secret_trust_roots() {
        let content = concat!(
            "- Developer ID Application identity: `Developer ID Application: Example (TEAM123)`\n",
            "- Developer ID TeamIdentifier: `TEAM123`\n",
            "- Developer ID certificate SHA-1: `0123456789abcdef0123456789abcdef01234567`\n",
            "- Developer ID certificate SHA-256: `0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef`\n",
            "- Sigstore certificate identity: `release@example.com`\n",
            "- Sigstore OIDC issuer: `https://issuer.example`\n",
        );
        let roots = parse_release_trust_roots(content).expect("parse trust roots");
        assert!(
            validate_release_identity_inputs(
                &roots,
                "release@example.com",
                "https://issuer.example",
                "Developer ID Application: Example (TEAM123)",
            )
            .is_ok()
        );
        assert!(
            validate_release_identity_inputs(
                &roots,
                "attacker@example.com",
                "https://issuer.example",
                "Developer ID Application: Example (TEAM123)",
            )
            .is_err()
        );

        let unbound = parse_release_trust_roots(
            &content.replace("Developer ID Application: Example (TEAM123)", "UNBOUND"),
        )
        .expect("parse unbound marker");
        assert!(
            validate_release_identity_inputs(
                &unbound,
                "release@example.com",
                "https://issuer.example",
                "UNBOUND",
            )
            .is_err()
        );
        let malformed_sha1 = parse_release_trust_roots(&content.replace(
            "0123456789abcdef0123456789abcdef01234567",
            "0123456789abcdef0123456789abcdef0123456g",
        ))
        .expect("parse malformed fingerprint");
        assert!(
            validate_release_identity_inputs(
                &malformed_sha1,
                "release@example.com",
                "https://issuer.example",
                "Developer ID Application: Example (TEAM123)",
            )
            .is_err()
        );
        let malformed_sha256 = parse_release_trust_roots(&content.replace(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg",
        ))
        .expect("parse malformed fingerprint");
        assert!(
            validate_release_identity_inputs(
                &malformed_sha256,
                "release@example.com",
                "https://issuer.example",
                "Developer ID Application: Example (TEAM123)",
            )
            .is_err()
        );
        assert!(is_full_git_object_id(
            "2ca2ebb98fc0a19b34afdc39d668c12ebfc5db70"
        ));
        assert!(!is_full_git_object_id("HEAD"));
        assert!(!is_full_git_object_id(
            "-ca2ebb98fc0a19b34afdc39d668c12ebfc5db70"
        ));
    }

    #[test]
    fn linux_musl_release_builds_use_the_zig_cross_linker() {
        assert_eq!(
            release_build_driver("aarch64-unknown-linux-musl"),
            ["auditable", "zigbuild"]
        );
        assert_eq!(
            release_build_driver("aarch64-apple-darwin"),
            ["auditable", "build"]
        );
        assert_eq!(
            release_build_subcommand("aarch64-unknown-linux-musl"),
            "zigbuild"
        );
        assert_eq!(
            release_build_subcommand("x86_64-unknown-linux-musl"),
            "zigbuild"
        );
        assert_eq!(release_build_subcommand("aarch64-apple-darwin"), "build");
        assert_eq!(release_build_subcommand("x86_64-apple-darwin"), "build");
    }

    #[test]
    fn verify_cross_target_is_a_real_musl_release_target() {
        // The verify-time cross-build must exercise a genuinely shipped Linux
        // target through the zig cross-linker; otherwise it proves nothing about
        // what release produces.
        assert!(
            RELEASE_TARGETS.contains(&VERIFY_CROSS_TARGET),
            "verify cross target must be a release target"
        );
        assert!(
            is_linux_musl(VERIFY_CROSS_TARGET),
            "verify cross target must be a Linux musl target"
        );
        assert_eq!(release_build_subcommand(VERIFY_CROSS_TARGET), "zigbuild");
    }

    #[test]
    fn release_target_selection_rejects_unreviewed_platforms_and_duplicates() {
        assert!(validated_release_targets(&["x86_64-pc-windows-msvc".to_owned()]).is_err());
        assert!(
            validated_release_targets(&[
                "aarch64-apple-darwin".to_owned(),
                "aarch64-apple-darwin".to_owned(),
            ])
            .is_err()
        );
        assert_eq!(
            validated_release_targets(&[
                "aarch64-apple-darwin".to_owned(),
                "x86_64-unknown-linux-musl".to_owned(),
            ])
            .expect("reviewed targets"),
            vec!["aarch64-apple-darwin", "x86_64-unknown-linux-musl"]
        );
    }

    #[test]
    fn signed_release_requires_the_exact_four_platform_artifact_set() {
        let names = expected_signed_release_file_names();
        assert_eq!(names.len(), 16);
        for target in super::RELEASE_TARGETS {
            assert!(names.contains(&format!("cfctl-{target}")));
            assert!(names.contains(&format!("cfctl-{target}.spdx.json")));
        }
        assert!(names.contains("SHA256SUMS"));
        assert!(names.contains("SHA256SUMS.sigstore.json"));
        assert!(names.contains("provenance.sigstore.json"));
        assert!(names.contains("notary-aarch64-apple-darwin.json"));
        assert!(names.contains("notary-x86_64-apple-darwin.json"));
    }

    #[test]
    fn publish_tag_must_match_the_package_version_exactly() {
        assert!(release_tag_is_exact_version(&format!(
            "v{}",
            env!("CARGO_PKG_VERSION")
        )));
        assert!(!release_tag_is_exact_version("latest"));
        assert!(!release_tag_is_exact_version(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn signed_release_rejects_missing_and_poisoned_files() {
        let mut paths = expected_signed_release_file_names()
            .into_iter()
            .map(|name| std::path::Path::new("dist").join(name))
            .collect::<Vec<_>>();
        assert!(validate_signed_release_file_set(&paths).is_ok());
        paths.pop();
        paths.push(std::path::Path::new("dist/poison.txt").to_owned());
        assert!(validate_signed_release_file_set(&paths).is_err());
    }

    #[test]
    fn annotated_remote_release_tags_resolve_to_the_peeled_commit() {
        let output = concat!(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\trefs/tags/v2.0.0-alpha.1\n",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\trefs/tags/v2.0.0-alpha.1^{}\n",
        );
        assert_eq!(
            parse_remote_tag_commit(output, "v2.0.0-alpha.1").expect("peeled tag"),
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
    }

    #[test]
    fn lightweight_remote_release_tags_are_rejected() {
        let output = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\trefs/tags/v1.3.0\n";
        assert!(parse_remote_tag_commit(output, "v1.3.0").is_none());
    }

    #[test]
    fn macos_distribution_signature_binds_developer_id_runtime_and_timestamp() {
        let identity = "Developer ID Application: Example Corp (TEAM123456)";
        let valid = concat!(
            "CodeDirectory v=20500 size=123 flags=0x10000(runtime) hashes=1+0 location=embedded\n",
            "Authority=Developer ID Application: Example Corp (TEAM123456)\n",
            "Authority=Developer ID Certification Authority\n",
            "Authority=Apple Root CA\n",
            "Timestamp=Jul 14, 2026 at 10:30:00 PM\n",
            "TeamIdentifier=TEAM123456\n",
        );
        assert_eq!(
            validate_codesign_details(valid, identity).expect("valid Developer ID signature"),
            "TEAM123456"
        );
        assert!(validate_codesign_details(valid, "Apple Development: Example").is_err());
        assert!(validate_codesign_details(&valid.replace("runtime", "adhoc"), identity).is_err());
        assert!(
            validate_codesign_details(&valid.replace("Timestamp=", "NoTimestamp="), identity)
                .is_err()
        );
    }

    #[test]
    fn macos_provenance_binds_both_certificate_fingerprints() {
        let mut provenance = serde_json::json!({
            "macos_distribution": {
                "signing_identity": "Developer ID Application: Example Corp (TEAM123456)",
                "team_identifier": "TEAM123456",
                "certificate_sha1": "0123456789abcdef0123456789abcdef01234567",
                "certificate_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "hardened_runtime": true,
                "secure_timestamp": true,
                "notarization_receipts": [
                    "notary-aarch64-apple-darwin.json",
                    "notary-x86_64-apple-darwin.json"
                ]
            }
        });
        let result = validate_macos_provenance(
            &provenance,
            "Developer ID Application: Example Corp (TEAM123456)",
            "TEAM123456",
            "0123456789abcdef0123456789abcdef01234567",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
        assert!(result.is_ok());
        provenance["macos_distribution"]["certificate_sha256"] = serde_json::json!("drifted");
        assert!(
            validate_macos_provenance(
                &provenance,
                "Developer ID Application: Example Corp (TEAM123456)",
                "TEAM123456",
                "0123456789abcdef0123456789abcdef01234567",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )
            .is_err()
        );
    }

    #[test]
    fn macos_leaf_certificate_must_match_both_committed_fingerprints() {
        let sha1 = "0123456789abcdef0123456789abcdef01234567";
        let sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(validate_macos_certificate_fingerprints(sha1, sha256, sha1, sha256).is_ok());
        assert!(validate_macos_certificate_fingerprints("drifted", sha256, sha1, sha256).is_err());
        assert!(validate_macos_certificate_fingerprints(sha1, "drifted", sha1, sha256).is_err());
    }

    #[test]
    fn notarization_receipt_must_be_accepted_and_bind_the_signed_binary_hash() {
        let receipt = serde_json::json!({
            "schema_version": 1,
            "target": "aarch64-apple-darwin",
            "artifact": "cfctl-aarch64-apple-darwin",
            "artifact_sha256": "abc123",
            "submission_id": "2efe2717-52ef-43a5-96dc-0797e4ca1041",
            "submission": {
                "id": "2efe2717-52ef-43a5-96dc-0797e4ca1041",
                "status": "Accepted",
                "message": "Processing complete"
            }
        });
        assert!(validate_notary_receipt_value(&receipt, "aarch64-apple-darwin", "abc123").is_ok());
        let mut rejected = receipt.clone();
        rejected["submission"]["status"] = serde_json::json!("Invalid");
        assert!(
            validate_notary_receipt_value(&rejected, "aarch64-apple-darwin", "abc123").is_err()
        );
        assert!(
            validate_notary_receipt_value(&receipt, "aarch64-apple-darwin", "different").is_err()
        );
        let mut wrong_operation = receipt.clone();
        wrong_operation["submission"]["id"] =
            serde_json::json!("11111111-1111-1111-1111-111111111111");
        assert!(
            validate_notary_receipt_value(&wrong_operation, "aarch64-apple-darwin", "abc123")
                .is_err()
        );
    }

    #[test]
    fn linux_installer_requires_identity_bound_manifest_and_embedded_hashes() {
        let template = include_str!("../../packaging/install.sh");
        let rendered = render_linux_installer_text(
            template,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            Some(("release'owner@example.com", "https://issuer.example")),
        )
        .expect("rendered installer");
        assert!(rendered.contains("cosign verify-blob"));
        assert!(rendered.contains("SHA256SUMS.sigstore.json"));
        assert!(
            rendered.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        assert!(
            rendered.contains("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        );
        assert!(rendered.contains("release'\"'\"'owner@example.com"));
        assert!(!rendered.contains("@SIGSTORE_IDENTITY@"));
        assert!(!rendered.contains("@X86_64_LINUX_SHA256@"));
        let mut syntax = Command::new("sh")
            .arg("-n")
            .stdin(Stdio::piped())
            .spawn()
            .expect("spawn shell syntax check");
        syntax
            .stdin
            .take()
            .expect("shell stdin")
            .write_all(rendered.as_bytes())
            .expect("write installer to shell");
        assert!(syntax.wait().expect("shell syntax status").success());

        let preview = render_linux_installer_text(
            template,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            None,
        )
        .expect("assembly preview");
        assert!(preview.contains("UNSIGNED_ASSEMBLY"));
        let preview_run = Command::new("sh")
            .arg("-c")
            .arg(&preview)
            .output()
            .expect("run unsigned assembly preview");
        assert!(!preview_run.status.success());
        assert!(String::from_utf8_lossy(&preview_run.stderr).contains("unsigned assembly"));
        assert!(render_linux_installer_text(template, "bad", "bad", Some(("", "issuer"))).is_err());
    }
}
