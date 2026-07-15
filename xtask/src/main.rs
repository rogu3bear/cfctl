//! Local verification and release orchestration for cfctl.

use std::{
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
    /// Build, inventory, checksum, and sign all release artifacts.
    Release {
        #[arg(long = "target", value_delimiter = ',')]
        targets: Vec<String>,
    },
    /// Upload already-built signed artifacts to an existing GitHub release.
    Publish {
        #[arg(long)]
        tag: String,
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
        Task::Release { targets } => release(&targets),
        Task::Publish { tag } => publish(&tag),
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

fn release(requested_targets: &[String]) -> Result<(), TaskError> {
    verify()?;
    for tool in ["syft", "cosign"] {
        run(tool, &["version"])?;
    }
    let targets: Vec<&str> = if requested_targets.is_empty() {
        RELEASE_TARGETS.to_vec()
    } else {
        requested_targets.iter().map(String::as_str).collect()
    };
    let dist = PathBuf::from("dist");
    fs::create_dir_all(&dist).map_err(|source| io_error(&dist, source))?;
    let mut artifacts = Vec::new();
    for &target in &targets {
        let first_target_dir = PathBuf::from("target/release-proof").join(format!("{target}-1"));
        let second_target_dir = PathBuf::from("target/release-proof").join(format!("{target}-2"));
        remove_directory_if_present(&first_target_dir)?;
        remove_directory_if_present(&second_target_dir)?;
        let first = build_release_target(target, &first_target_dir)?;
        let second = build_release_target(target, &second_target_dir)?;
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
    let generated_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TaskError::Clock)?
        .as_secs();
    let provenance = serde_json::json!({
        "schema_version": 1,
        "generated_at_unix": generated_at,
        "source_date_epoch": env::var("SOURCE_DATE_EPOCH").ok(),
        "rustc": output("rustc", &["--version", "--verbose"] )?,
        "targets": targets,
        "artifacts": artifacts,
        "hosted_builds": false,
    });
    let provenance_path = dist.join("provenance.json");
    fs::write(
        &provenance_path,
        serde_json::to_vec_pretty(&provenance)
            .map_err(|error| TaskError::Command(format!("serialize provenance: {error}")))?,
    )
    .map_err(|source| io_error(&provenance_path, source))?;
    artifacts.push(provenance_path.clone());
    let installer_path = dist.join("install.sh");
    fs::copy("packaging/install.sh", &installer_path)
        .map_err(|source| io_error(&installer_path, source))?;
    artifacts.push(installer_path);
    if targets.contains(&"aarch64-apple-darwin") && targets.contains(&"x86_64-apple-darwin") {
        let formula_path = render_homebrew_formula(&dist)?;
        artifacts.push(formula_path);
    }
    artifacts.sort();
    let sums_path = dist.join("SHA256SUMS");
    write_checksums(&sums_path, &artifacts)?;
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

fn build_release_target(target: &str, target_dir: &Path) -> Result<PathBuf, TaskError> {
    let mut command = Command::new("cargo");
    command.args([
        "build",
        "--release",
        "--locked",
        "-p",
        "cfctl-cli",
        "--target",
        target,
        "--target-dir",
    ]);
    command.arg(target_dir);
    run_command(&mut command, &format!("cargo release build for {target}"))?;
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

fn publish(tag: &str) -> Result<(), TaskError> {
    let artifacts = release_files()?;
    let mut command = Command::new("gh");
    command.args(["release", "upload", tag, "--clobber"]);
    command.args(artifacts);
    run_command(&mut command, &format!("gh release upload {tag}"))
}

fn release_files() -> Result<Vec<PathBuf>, TaskError> {
    let dist = Path::new("dist");
    let mut files: Vec<PathBuf> = fs::read_dir(dist)
        .map_err(|source| io_error(dist, source))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .collect();
    files.sort();
    if files.is_empty() {
        return Err(TaskError::MissingArtifacts);
    }
    Ok(files)
}

fn write_checksums(path: &Path, artifacts: &[PathBuf]) -> Result<(), TaskError> {
    let mut lines = String::new();
    for artifact in artifacts {
        let digest = sha256_file(artifact)?;
        let name = artifact
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .ok_or_else(|| TaskError::Command("release artifact name is not UTF-8".to_owned()))?;
        let _result = writeln!(lines, "{digest}  {name}");
    }
    fs::write(path, lines).map_err(|source| io_error(path, source))
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
