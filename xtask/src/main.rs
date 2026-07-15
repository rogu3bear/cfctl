//! Local verification and release orchestration for cfctl.

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

use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use thiserror::Error;

const RELEASE_TARGETS: [&str; 4] = [
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "aarch64-unknown-linux-musl",
    "x86_64-unknown-linux-musl",
];
const CARGO_AUDITABLE_VERSION: &str = "0.7.5";

#[derive(Debug, Parser)]
#[command(name = "cargo xtask")]
struct Arguments {
    #[command(subcommand)]
    command: Task,
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
    },
    /// Upload already-built signed artifacts to an existing GitHub release.
    Publish {
        #[arg(long)]
        tag: String,
        #[arg(long)]
        certificate_identity: String,
        #[arg(long)]
        certificate_oidc_issuer: String,
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
        } => release(&certificate_identity, &certificate_oidc_issuer),
        Task::Publish {
            tag,
            certificate_identity,
            certificate_oidc_issuer,
        } => publish(&tag, &certificate_identity, &certificate_oidc_issuer),
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
    run("bash", &["scripts/verify_static_contract.sh"])?;
    Ok(())
}

fn release(certificate_identity: &str, certificate_oidc_issuer: &str) -> Result<(), TaskError> {
    ensure_clean_source_tree()?;
    run("cosign", &["version"])?;
    assemble(&[])?;
    sign_release_artifacts()?;
    verify_signed_release(certificate_identity, certificate_oidc_issuer)
}

fn assemble(requested_targets: &[String]) -> Result<(), TaskError> {
    verify()?;
    run("syft", &["version"])?;
    let targets = validated_release_targets(requested_targets)?;
    ensure_release_build_tools(&targets)?;
    let source_date_epoch = release_source_date_epoch()?;
    let git_commit = output("git", &["rev-parse", "HEAD"])?;
    let git_tree = output("git", &["rev-parse", "HEAD^{tree}"])?;
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
        let first = build_release_target(target, &first_target_dir, &source_date_epoch)?;
        let second = build_release_target(target, &second_target_dir, &source_date_epoch)?;
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
    let installer_path = dist.join("install.sh");
    fs::copy("packaging/install.sh", &installer_path)
        .map_err(|source| io_error(&installer_path, source))?;
    artifacts.push(installer_path);
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

fn verify_signed_release(
    certificate_identity: &str,
    certificate_oidc_issuer: &str,
) -> Result<(), TaskError> {
    let artifacts = release_files()?;
    validate_signed_release_file_set(&artifacts)?;
    verify_checksum_manifest()?;
    let _commit = validate_release_provenance()?;
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
    Ok(())
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
        Err(_) => output("git", &["show", "-s", "--format=%ct", "HEAD"])?,
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

fn release_tag_is_exact_version(tag: &str) -> bool {
    tag == format!("v{}", env!("CARGO_PKG_VERSION"))
}

fn publish(
    tag: &str,
    certificate_identity: &str,
    certificate_oidc_issuer: &str,
) -> Result<(), TaskError> {
    let expected_tag = format!("v{}", env!("CARGO_PKG_VERSION"));
    if !release_tag_is_exact_version(tag) {
        return Err(TaskError::ReleaseTagMismatch {
            actual: tag.to_owned(),
            expected: expected_tag,
        });
    }
    verify_signed_release(certificate_identity, certificate_oidc_issuer)?;
    let provenance_commit = validate_release_provenance()?;
    let tag_commit = remote_tag_commit(tag)?;
    if tag_commit != provenance_commit {
        return Err(TaskError::ReleaseCommitMismatch {
            tag: tag.to_owned(),
            tag_commit,
            provenance_commit,
        });
    }
    ensure_empty_draft_release(tag)?;
    let artifacts = release_files()?;
    for artifact in artifacts {
        let mut command = Command::new("gh");
        command.args(["release", "upload", tag]);
        command.arg(&artifact);
        if let Err(error) = run_command(
            &mut command,
            &format!("gh release upload {tag} {}", artifact.display()),
        ) {
            let rollback_failures = rollback_draft_release_assets(tag);
            return Err(TaskError::PublishFailed {
                upload: error.to_string(),
                rollback: if rollback_failures.is_empty() {
                    "none; all newly uploaded assets were removed".to_owned()
                } else {
                    rollback_failures.join("; ")
                },
            });
        }
    }
    Ok(())
}

fn remote_tag_commit(tag: &str) -> Result<String, TaskError> {
    let direct = format!("refs/tags/{tag}");
    let peeled = format!("{direct}^{{}}");
    let remote = output("git", &["ls-remote", "origin", &direct, &peeled])?;
    parse_remote_tag_commit(&remote, tag).ok_or_else(|| {
        TaskError::Command(format!(
            "origin does not expose a commit for release tag `{tag}`"
        ))
    })
}

fn parse_remote_tag_commit(remote: &str, tag: &str) -> Option<String> {
    let direct = format!("refs/tags/{tag}");
    let peeled = format!("{direct}^{{}}");
    let mut direct_commit = None;
    for line in remote.lines() {
        let (object, reference) = line.split_once('\t')?;
        if reference == peeled {
            return Some(object.to_owned());
        }
        if reference == direct {
            direct_commit = Some(object.to_owned());
        }
    }
    direct_commit
}

fn github_release_state(tag: &str) -> Result<serde_json::Value, TaskError> {
    let release = output(
        "gh",
        &["release", "view", tag, "--json", "assets,isDraft,tagName"],
    )?;
    serde_json::from_str(&release)
        .map_err(|error| TaskError::Command(format!("parse GitHub release state: {error}")))
}

fn release_asset_names(release: &serde_json::Value) -> Result<Vec<String>, TaskError> {
    release
        .get("assets")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| TaskError::Command("GitHub release assets are missing".to_owned()))?
        .iter()
        .map(|asset| {
            asset
                .get("name")
                .and_then(serde_json::Value::as_str)
                .map(ToOwned::to_owned)
                .ok_or_else(|| {
                    TaskError::Command("GitHub release asset name is missing".to_owned())
                })
        })
        .collect()
}

fn rollback_draft_release_assets(tag: &str) -> Vec<String> {
    let expected = expected_signed_release_file_names();
    let names = match github_release_state(tag).and_then(|release| release_asset_names(&release)) {
        Ok(names) => names,
        Err(error) => return vec![error.to_string()],
    };
    let mut failures = Vec::new();
    for name in names.into_iter().filter(|name| expected.contains(name)) {
        if let Err(error) = run("gh", &["release", "delete-asset", tag, &name, "--yes"]) {
            failures.push(error.to_string());
        }
    }
    failures
}

fn ensure_empty_draft_release(tag: &str) -> Result<(), TaskError> {
    let release = github_release_state(tag)?;
    if release.get("isDraft").and_then(serde_json::Value::as_bool) != Some(true) {
        return Err(TaskError::ReleaseMustBeDraft(tag.to_owned()));
    }
    if release.get("tagName").and_then(serde_json::Value::as_str) != Some(tag) {
        return Err(TaskError::ReleaseTagMismatch {
            actual: release
                .get("tagName")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("<missing>")
                .to_owned(),
            expected: tag.to_owned(),
        });
    }
    let assets = release_asset_names(&release)?;
    if assets.is_empty() {
        Ok(())
    } else {
        Err(TaskError::ReleaseAlreadyHasAssets {
            tag: tag.to_owned(),
            assets: assets.join(", "),
        })
    }
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

fn validate_release_provenance() -> Result<String, TaskError> {
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
    let commit = provenance
        .get("git_commit")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| TaskError::InvalidProvenance("git_commit is missing".to_owned()))?
        .to_owned();
    let revision = format!("{commit}^{{tree}}");
    let actual_tree = output("git", &["rev-parse", &revision])?;
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
    use super::{
        expected_signed_release_file_names, parse_remote_tag_commit, release_build_driver,
        release_build_subcommand, release_tag_is_exact_version, validate_signed_release_file_set,
        validated_release_targets,
    };

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
        assert_eq!(names.len(), 14);
        for target in super::RELEASE_TARGETS {
            assert!(names.contains(&format!("cfctl-{target}")));
            assert!(names.contains(&format!("cfctl-{target}.spdx.json")));
        }
        assert!(names.contains("SHA256SUMS"));
        assert!(names.contains("SHA256SUMS.sigstore.json"));
        assert!(names.contains("provenance.sigstore.json"));
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
}
