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

use cfctl_core::{
    GuideTopicV1, PUBLIC_V2_SUBCOMMANDS, RETIRED_V1_PUBLIC_VERBS, RETIRED_V1_SURFACES,
    render_guide_topic_markdown,
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
    verify_security_contract()?;
    verify_source_contract()?;
    Ok(())
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
        ],
    )?;

    verify_workspace_contract()?;
    verify_v1_cutover_contract()?;
    verify_documented_contracts()
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
    if members.len() != 10 {
        return Err(TaskError::InvalidSourceContract(format!(
            "expected 10 workspace members, found {}",
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
        "cfctl-workspace",
        "xtask",
    ] {
        if !package_names.contains(required) {
            return Err(TaskError::InvalidSourceContract(format!(
                "workspace is missing {required}"
            )));
        }
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
    verify_active_guidance_has_no_v1_commands()
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
        "crates/cfctl-cli/src/runtime.rs" => consumes_catalog,
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
        let absolute_path = repository_root.join(&path);
        let bytes = fs::read(&absolute_path).map_err(|source| io_error(&absolute_path, source))?;
        let Ok(content) = std::str::from_utf8(&bytes) else {
            continue;
        };
        for verb in extract_cfctl_command_references(&path, content) {
            if verb != "help" && !PUBLIC_V2_SUBCOMMANDS.contains(&verb.as_str()) {
                return Err(TaskError::InvalidSourceContract(format!(
                    "{path} teaches non-v2 command `cfctl {verb}` outside compat/v1"
                )));
            }
        }
    }
    Ok(())
}

fn extract_cfctl_command_references(path: &str, content: &str) -> Vec<String> {
    let mut verbs = Vec::new();
    if path_has_extension(path, "json") {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(content) {
            collect_json_command_references(&value, false, &mut verbs);
        }
        return verbs;
    }

    let markdown = path_has_extension(path, "md");
    let shell = path_has_extension(path, "sh") || content.starts_with("#!");
    if !markdown && !shell {
        return verbs;
    }

    let mut in_fence = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if markdown && trimmed.starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if (shell || in_fence)
            && let Some(verb) = cfctl_command_verb(trimmed)
        {
            verbs.push(verb);
        }
        if markdown && !in_fence {
            if let Some(verb) = cfctl_command_verb_in_prose(trimmed) {
                verbs.push(verb);
            }
            for (index, inline) in line.split('`').enumerate() {
                if index % 2 == 1
                    && let Some(verb) = cfctl_command_verb(inline)
                {
                    verbs.push(verb);
                }
            }
        }
    }
    verbs
}

fn path_has_extension(path: &str, expected: &str) -> bool {
    Path::new(path)
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case(expected))
}

fn collect_json_command_references(
    value: &serde_json::Value,
    command_context: bool,
    verbs: &mut Vec<String>,
) {
    match value {
        serde_json::Value::String(value) => {
            let verb = if command_context {
                cfctl_command_verb(value)
            } else {
                cfctl_command_verb_in_prose(value)
            };
            if let Some(verb) = verb {
                verbs.push(verb);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_json_command_references(value, command_context, verbs);
            }
        }
        serde_json::Value::Object(values) => {
            for (key, value) in values {
                if is_json_argv_reference_key(key)
                    && let Some(command) = json_argv_command(value)
                    && let Some(verb) = cfctl_command_verb(&command)
                {
                    verbs.push(verb);
                    continue;
                }
                collect_json_command_references(
                    value,
                    command_context || is_json_command_reference_key(key),
                    verbs,
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

fn cfctl_command_verb(command: &str) -> Option<String> {
    cfctl_command_verb_with_context(command, true)
}

fn cfctl_command_verb_in_prose(command: &str) -> Option<String> {
    cfctl_command_verb_with_context(command, false)
}

fn cfctl_command_verb_with_context(command: &str, command_context: bool) -> Option<String> {
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
    while verb == "--json" {
        verb = arguments.next()?;
    }
    if verb.starts_with(['\"', '\'', '<', '{']) || verb == "\\" {
        return None;
    }
    let verb = verb
        .trim_matches(|character: char| !character.is_ascii_alphanumeric() && character != '-')
        .to_owned();

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
    Some(verb)
}

fn verify_active_guidance_has_no_v1_commands() -> Result<(), TaskError> {
    let repository_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| {
            TaskError::InvalidSourceContract("xtask has no repository parent".to_owned())
        })?;
    // First-load agent doctrine must not re-teach archived v1 verbs or layout.
    // Historical material below compat/v1 is governed by the quarantine manifest instead.
    // Tracked public guidance is always required. Local strategy files are gitignored for
    // public releases but, when present in a private checkout, must stay v2-aligned.
    let required_guidance = [
        "CFCTL_PROMPT.md",
        "docs/agent-landing.md",
        "skills/cfctl-operator/SKILL.md",
        "CONTRIBUTING.md",
        "SECURITY.md",
    ];
    let optional_local_guidance = [
        "AGENTS.md",
        "CLAUDE.md",
        "ANCHOR.md",
        "NORTH_STAR.md",
        "LAYERS.md",
    ];
    let stale_v1_guidance = [
        // Archived public verbs / auth lanes
        "./scripts/",
        "--ack-plan",
        "CF_DEV_TOKEN",
        "cfctl surfaces",
        "cfctl ownership",
        "cfctl skills",
        "cloudflare-api-mcp",
        // Archived shell-runtime layout taught as live repo shape
        "lib/runtime/",
        "lib/backends/",
        "`commands/` owns",
        "`commands/` contains",
        "`commands/`: ",
        "`lib/runtime/`",
        "`lib/backends/`",
        "`scripts/`: ",
        "verify_static_contract.sh",
        "verify_public_contract.sh",
        "cfctl standards audit",
        "cfctl admin authorize-backend",
        // Branch or PR lifecycle text must not survive into active guidance.
        "pending merge",
    ];
    for path in required_guidance {
        verify_guidance_file_has_no_stale_v1(repository_root, path, &stale_v1_guidance)?;
    }
    for path in optional_local_guidance {
        let absolute_path = repository_root.join(path);
        if absolute_path.is_file() {
            verify_guidance_file_has_no_stale_v1(repository_root, path, &stale_v1_guidance)?;
        }
    }
    Ok(())
}

fn verify_guidance_file_has_no_stale_v1(
    repository_root: &Path,
    path: &str,
    stale_v1_guidance: &[&str],
) -> Result<(), TaskError> {
    let absolute_path = repository_root.join(path);
    let content =
        fs::read_to_string(&absolute_path).map_err(|source| io_error(&absolute_path, source))?;
    for phrase in stale_v1_guidance {
        if content.contains(phrase) {
            return Err(TaskError::InvalidSourceContract(format!(
                "{path} still teaches archived v1 guidance `{phrase}`"
            )));
        }
    }
    Ok(())
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

fn release(
    certificate_identity: &str,
    certificate_oidc_issuer: &str,
    macos_signing_identity: &str,
    apple_notary_profile: &str,
) -> Result<(), TaskError> {
    ensure_clean_source_tree()?;
    run("cosign", &["version"])?;
    run("xcrun", &["notarytool", "--version"])?;
    assemble(&[])?;
    sign_and_notarize_macos_artifacts(
        macos_signing_identity,
        apple_notary_profile,
        certificate_identity,
        certificate_oidc_issuer,
    )?;
    sign_release_artifacts()?;
    verify_signed_release(
        certificate_identity,
        certificate_oidc_issuer,
        macos_signing_identity,
    )?;
    Ok(())
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

fn verify_signed_release(
    certificate_identity: &str,
    certificate_oidc_issuer: &str,
    macos_signing_identity: &str,
) -> Result<String, TaskError> {
    let artifacts = release_files()?;
    validate_signed_release_file_set(&artifacts)?;
    verify_checksum_manifest()?;
    let team_identifier = verify_macos_distribution(macos_signing_identity)?;
    let commit = validate_release_provenance(macos_signing_identity, &team_identifier)?;
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
    Ok(commit)
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
                signing_identity,
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

fn verify_macos_distribution(expected_identity: &str) -> Result<String, TaskError> {
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
    let expected_tag = format!("v{}", env!("CARGO_PKG_VERSION"));
    if !release_tag_is_exact_version(tag) {
        return Err(TaskError::ReleaseTagMismatch {
            actual: tag.to_owned(),
            expected: expected_tag,
        });
    }
    let provenance_commit = verify_signed_release(
        certificate_identity,
        certificate_oidc_issuer,
        macos_signing_identity,
    )?;
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

fn validate_release_provenance(
    expected_macos_identity: &str,
    expected_team_identifier: &str,
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
    )?;
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

fn validate_macos_provenance(
    provenance: &serde_json::Value,
    expected_identity: &str,
    expected_team_identifier: &str,
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
        io::Write as _,
        process::{Command, Stdio},
    };

    use super::{
        expected_signed_release_file_names, extract_cfctl_command_references,
        is_declared_quarantine_path, is_forbidden_quarantine_consumer, parse_remote_tag_commit,
        release_build_driver, release_build_subcommand, release_tag_is_exact_version,
        render_linux_installer_text, security_proof_commands, validate_codesign_details,
        validate_notary_receipt_value, validate_signed_release_file_set, validated_release_targets,
        verify_active_guidance_has_no_v1_commands, verify_documented_contracts,
        verify_generated_guidance_section_text, verify_v1_cutover_contract,
    };

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
            "crates/cfctl-cli/src/runtime.rs",
            "let retained_repo_state = \"compat/v1/state\";"
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
