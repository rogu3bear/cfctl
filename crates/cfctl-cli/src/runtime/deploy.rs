//! One Worker upload plan from a committed `cfctl.toml`.
//!
//! The file names the target. This module resolves that name into the call
//! input `wrangler.versions-upload` already pins. It does not approve, run,
//! select a profile, or invent a second plan target.

use std::path::Component;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use super::call_command::call_command;
use super::prelude::{
    CallArgs, CallInput, CapabilityV1, CliError, DeployArgs, Deserialize, OpenOptions, Path,
    PathBuf, ProfilesConfig, Read, Result, ResultEnvelopeV2, StateStore, StdCommand, Value, env,
    fs, json,
};
use super::worker_deployment::expected_upload_message;
use super::workspace_state::discover_registered;

const FILE_NAME: &str = "cfctl.toml";
const MAX_FILE_BYTES: u64 = 1024 * 1024;
const WORKER_LANE: &str = "worker";
const UPLOAD_CAPABILITY_ID: &str = "wrangler.versions-upload";

const FORBIDDEN_FIELDS: &[&str] = &[
    "approval",
    "approve",
    "authority",
    "cost",
    "hash",
    "max_cost",
    "message",
    "percentage",
    "permission",
    "permissions",
    "risk",
    "secret",
    "secrets",
    "sha256",
    "standing_authority",
    "token",
    "tokens",
    "traffic",
    "traffic_percentage",
    "version",
    "version_id",
    "yes",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeployFile {
    schema_version: u8,
    target: std::collections::BTreeMap<String, DeployTarget>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeployTarget {
    lane: String,
    name: String,
    config: String,
    profile_id: String,
    account_id: String,
}

pub(super) async fn deploy_command(
    store: &StateStore,
    arguments: DeployArgs,
) -> Result<ResultEnvelopeV2> {
    if arguments.target.is_empty() || arguments.target.chars().any(char::is_whitespace) {
        return Err(CliError::guided(
            "CFCTL_USAGE",
            "cfctl deploy requires the target name from [target.<name>]",
            "Run `cfctl deploy <target> --json`. `cfctl deploy --help` shows the argument.",
        ));
    }
    let cwd = env::current_dir().map_err(|source| CliError::Io {
        path: ".".to_owned(),
        source,
    })?;
    #[cfg(test)]
    let cwd = TEST_CWD.try_with(Clone::clone).unwrap_or(cwd);
    let root = deploy_root(&cwd, &store.workspace_roots()?)?;
    let file_path = root.join(FILE_NAME);
    let (file, control_bytes) = read_deploy_file(&file_path)?;
    let target = select_target(&file, &file_path, &arguments.target)?;
    admit_worker_lane(&arguments.target, &target.lane)?;
    let config = resolve_config(&root, &target.config)?;
    let profiles = ProfilesConfig::load(store)?;
    let profile = profiles.selected(None)?;
    enforce_profile_pins(
        &arguments.target,
        &target.profile_id,
        &target.account_id,
        &profile.id,
        profile.account_id.as_deref(),
    )?;
    let control_head = require_committed_control(&root, &control_bytes)?;
    if git_top_level(config.parent().unwrap_or(&root))? != root {
        return Err(CliError::Input(
            "deploy config must belong to the control file's Git repository".to_owned(),
        ));
    }
    let graph = discover_registered(store)?;
    let capability = upload_capability();
    let config_text = path_text(&config)?;
    let message = expected_upload_message(
        &graph,
        &capability,
        &upload_input(&config_text, &target.name, None),
    )?;
    require_control_head(&message, &control_head)?;
    #[cfg(test)]
    let _ = BEFORE_CALL_TEST_HOOK.try_with(|hook| hook(store));
    let mut envelope = Box::pin(call_command(
        store,
        CallArgs {
            capability_id: UPLOAD_CAPABILITY_ID.to_owned(),
            max_pages: None,
            source_checkout: crate::source_checkout::SourceCheckoutArgs::default(),
            selectors: Vec::new(),
            query: vec![
                ("config".to_owned(), config_text),
                ("name".to_owned(), target.name.clone()),
                ("message".to_owned(), message),
            ],
            body_json: None,
            body_stdin: false,
            profile: Some(target.profile_id.clone()),
            account: Some(target.account_id.clone()),
            if_match: None,
            if_none_match: None,
            value_out: None,
            credential_in: None,
            out: None,
            source_file: None,
        },
    ))
    .await?;
    "deploy".clone_into(&mut envelope.command);
    if let Some(operation_id) = envelope
        .result
        .pointer("/plan/operation_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
    {
        envelope.operation_id = Some(operation_id.clone());
        if let Some(result) = envelope.result.as_object_mut() {
            result.insert(
                "message".to_owned(),
                json!(format!(
                    "Upload plan {operation_id} created. Review it, then `cfctl plans approve {operation_id} --yes`."
                )),
            );
        }
    }
    Ok(envelope)
}

/// Local upload projection. Profile pins are evaluated before `prepare_target`.
#[cfg(test)]
fn upload_projection(
    graph: &super::prelude::WorkspaceGraph,
    capability: &CapabilityV1,
    root: &Path,
    target_name: &str,
    selected_profile_id: &str,
    selected_account_id: Option<&str>,
) -> Result<Value> {
    let file_path = root.join(FILE_NAME);
    let (file, control_bytes) = read_deploy_file(&file_path)?;
    let target = select_target(&file, &file_path, target_name)?;
    admit_worker_lane(target_name, &target.lane)?;
    let config = resolve_config(root, &target.config)?;
    enforce_profile_pins(
        target_name,
        &target.profile_id,
        &target.account_id,
        selected_profile_id,
        selected_account_id,
    )?;
    let control_head = require_committed_control(root, &control_bytes)?;
    let config_text = path_text(&config)?;
    let message = expected_upload_message(
        graph,
        capability,
        &upload_input(&config_text, &target.name, None),
    )?;
    require_control_head(&message, &control_head)?;
    super::worker_deployment::prepare_target(
        graph,
        capability,
        &upload_input(&config_text, &target.name, Some(&message)),
    )?
    .ok_or_else(|| CliError::Input("Worker deployment target could not be derived".to_owned()))
}

fn parse_deploy_file(text: &str) -> Result<DeployFile> {
    if text.len() as u64 > MAX_FILE_BYTES {
        return Err(CliError::Input(format!(
            "cfctl.toml must be a non-empty file no larger than {MAX_FILE_BYTES} bytes"
        )));
    }
    let document: toml::Value = toml::from_str(text).map_err(|error| {
        CliError::Input(format!(
            "cfctl.toml could not be parsed: {}",
            error.message()
        ))
    })?;
    reject_forbidden_fields(&document, "")?;
    let file: DeployFile = document.try_into().map_err(|error: toml::de::Error| {
        CliError::Input(format!(
            "cfctl.toml could not be parsed: {}",
            error.message()
        ))
    })?;
    if file.schema_version != 1 {
        return Err(CliError::Input(format!(
            "cfctl.toml schema_version must be 1, found {}",
            file.schema_version
        )));
    }
    if file.target.is_empty() {
        return Err(CliError::Input(
            "cfctl.toml must declare at least one [target.<name>]".to_owned(),
        ));
    }
    for (name, target) in &file.target {
        if name.is_empty() || name.chars().any(char::is_whitespace) {
            return Err(CliError::Input(
                "cfctl.toml target names must be non-empty and contain no whitespace".to_owned(),
            ));
        }
        if target.lane.is_empty()
            || target.name.is_empty()
            || target.config.is_empty()
            || target.profile_id.is_empty()
            || target.account_id.is_empty()
        {
            return Err(CliError::Input(format!(
                "deploy target `{name}` requires lane, name, config, profile_id, and account_id"
            )));
        }
    }
    Ok(file)
}

fn deploy_root(cwd: &Path, registered_roots: &[PathBuf]) -> Result<PathBuf> {
    let cwd = fs::canonicalize(cwd).map_err(|source| CliError::Io {
        path: cwd.display().to_string(),
        source,
    })?;
    let mut containing = Vec::new();
    for registered in registered_roots {
        let Ok(root) = fs::canonicalize(registered) else {
            continue;
        };
        if cwd.starts_with(&root) {
            containing.push(root);
        }
    }
    let root = match containing.len() {
        1 => containing.remove(0),
        0 => {
            return Err(CliError::Input(
                "working directory is not inside exactly one registered workspace root".to_owned(),
            ));
        }
        _ => {
            return Err(CliError::Input(
                "working directory is inside more than one registered workspace root".to_owned(),
            ));
        }
    };
    let top = git_top_level(&cwd)?;
    if top != root {
        return Err(CliError::Input(
            "the registered workspace root must be the git top level of this working directory"
                .to_owned(),
        ));
    }
    Ok(root)
}

fn select_target<'a>(
    file: &'a DeployFile,
    file_path: &Path,
    target_name: &str,
) -> Result<&'a DeployTarget> {
    file.target.get(target_name).ok_or_else(|| {
        CliError::Input(format!(
            "deploy target `{target_name}` is not declared in `{}`",
            file_path.display()
        ))
    })
}

fn admit_worker_lane(target_name: &str, lane: &str) -> Result<()> {
    if lane == WORKER_LANE {
        return Ok(());
    }
    Err(CliError::guided(
        "CFCTL_USAGE",
        format!(
            "deploy target `{target_name}` lane `{lane}` is not admitted; `cfctl deploy` plans only lane \"worker\""
        ),
        "Set `lane = \"worker\"` for an upload plan. Pages and promotion stay separate governed calls.",
    ))
}

fn enforce_profile_pins(
    target_name: &str,
    pinned_profile_id: &str,
    pinned_account_id: &str,
    selected_profile_id: &str,
    selected_account_id: Option<&str>,
) -> Result<()> {
    if pinned_profile_id != selected_profile_id {
        return Err(CliError::guided(
            "CFCTL_DEPLOY_PROFILE",
            format!(
                "deploy target `{target_name}` pins profile `{pinned_profile_id}` but the selected profile is `{selected_profile_id}`"
            ),
            format!(
                "Select that profile with `cfctl auth use {pinned_profile_id}`, then run `cfctl deploy {target_name}` again. The file does not select a profile."
            ),
        ));
    }
    match selected_account_id {
        Some(account) if account == pinned_account_id => Ok(()),
        Some(account) => Err(CliError::guided(
            "CFCTL_DEPLOY_PROFILE",
            format!(
                "deploy target `{target_name}` pins account `{pinned_account_id}` but the selected profile pins `{account}`"
            ),
            format!(
                "Select a profile whose account is `{pinned_account_id}`, then run `cfctl deploy {target_name}` again."
            ),
        )),
        None => Err(CliError::guided(
            "CFCTL_DEPLOY_PROFILE",
            format!("selected profile `{selected_profile_id}` has no account pin"),
            format!(
                "Import an account-pinned profile for `{pinned_account_id}`, then run `cfctl deploy {target_name}` again."
            ),
        )),
    }
}

fn resolve_config(root: &Path, raw: &str) -> Result<PathBuf> {
    if raw.is_empty() || raw.chars().any(char::is_control) {
        return Err(CliError::Input(
            "deploy config must be a non-empty repository-relative path".to_owned(),
        ));
    }
    let relative = Path::new(raw);
    if relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(CliError::Input(
            "deploy config must be a repository-relative path inside the registered repository"
                .to_owned(),
        ));
    }
    let root = fs::canonicalize(root).map_err(|source| CliError::Io {
        path: root.display().to_string(),
        source,
    })?;
    let joined = root.join(relative);
    if !joined.exists() {
        return Err(CliError::Input(format!(
            "deploy config `{raw}` is not a file inside the repository"
        )));
    }
    let canonical = fs::canonicalize(&joined).map_err(|source| CliError::Io {
        path: joined.display().to_string(),
        source,
    })?;
    if !canonical.starts_with(&root) {
        return Err(CliError::Input(format!(
            "deploy config `{raw}` escapes the registered repository"
        )));
    }
    if !canonical.is_file() {
        return Err(CliError::Input(format!(
            "deploy config `{raw}` is not a file inside the repository"
        )));
    }
    Ok(canonical)
}

fn read_deploy_file(path: &Path) -> Result<(DeployFile, Vec<u8>)> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            return Err(CliError::Input(format!(
                "deploy control file `{}` is missing",
                path.display()
            )));
        }
        Err(source) => {
            return Err(CliError::Io {
                path: path.display().to_string(),
                source,
            });
        }
    };
    let metadata = file.metadata().map_err(|source| CliError::Io {
        path: path.display().to_string(),
        source,
    })?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > MAX_FILE_BYTES {
        return Err(CliError::Input(format!(
            "deploy control file `{}` must be a non-empty regular file no larger than {MAX_FILE_BYTES} bytes",
            path.display()
        )));
    }
    #[cfg(test)]
    let _ = AFTER_METADATA_TEST_HOOK.try_with(|hook| hook(path));
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| CliError::Io {
            path: path.display().to_string(),
            source,
        })?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(CliError::Input(
            "deploy control file exceeded its streamed byte bound".to_owned(),
        ));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| CliError::Input("deploy control file is not UTF-8".to_owned()))?;
    Ok((parse_deploy_file(text)?, bytes))
}

/// Read the immutable object named by one HEAD, rather than allowing an
/// ignored or untracked control file to influence a plan citing another tree.
fn require_committed_control(root: &Path, captured: &[u8]) -> Result<String> {
    let git = |args: &[&str]| -> Result<Vec<u8>> {
        let output = StdCommand::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .map_err(|source| CliError::Io {
                path: root.display().to_string(),
                source,
            })?;
        if !output.status.success() {
            return Err(CliError::Input(
                "deploy control file must be committed in the selected repository HEAD".to_owned(),
            ));
        }
        Ok(output.stdout)
    };
    let head = String::from_utf8(git(&["rev-parse", "--verify", "HEAD"])?)
        .map_err(|_| CliError::Input("deploy HEAD is not UTF-8".to_owned()))?;
    let head = head.trim().to_owned();
    if head.len() != 40 || !head.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(CliError::Input(
            "deploy HEAD is not a complete Git identity".to_owned(),
        ));
    }
    let object = format!("{head}:{FILE_NAME}");
    let size = String::from_utf8(git(&["cat-file", "-s", &object])?)
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok());
    if size != Some(captured.len() as u64) {
        return Err(CliError::Input(
            "deploy control file differs from its committed HEAD bytes".to_owned(),
        ));
    }
    // The size belongs to this immutable object, so this read cannot grow
    // after the bound check even if another process moves HEAD.
    if git(&["cat-file", "blob", &object])? != captured {
        return Err(CliError::Input(
            "deploy control file differs from its committed HEAD bytes".to_owned(),
        ));
    }
    Ok(head)
}

fn require_control_head(message: &str, head: &str) -> Result<()> {
    if !message.starts_with(&format!("source={head} artifact-sha256=")) {
        return Err(CliError::Input(
            "deploy source HEAD changed after the control file was captured".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
tokio::task_local! {
    pub(super) static BEFORE_CALL_TEST_HOOK: fn(&StateStore);
    pub(super) static TEST_CWD: PathBuf;
    static AFTER_METADATA_TEST_HOOK: fn(&Path);
}

fn reject_forbidden_fields(value: &toml::Value, location: &str) -> Result<()> {
    match value {
        toml::Value::Table(table) => {
            for (key, child) in table {
                if FORBIDDEN_FIELDS.contains(&key.as_str()) {
                    return Err(CliError::Input(format!(
                        "cfctl.toml field `{location}{key}` is not allowed"
                    )));
                }
                let next = format!("{location}{key}.");
                reject_forbidden_fields(child, &next)?;
            }
            Ok(())
        }
        toml::Value::Array(items) => {
            for item in items {
                reject_forbidden_fields(item, location)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn git_top_level(cwd: &Path) -> Result<PathBuf> {
    let output = StdCommand::new("git")
        .arg("-C")
        .arg(cwd)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|source| CliError::Io {
            path: cwd.display().to_string(),
            source,
        })?;
    if !output.status.success() {
        return Err(CliError::Input(
            "working directory is not inside a git work tree".to_owned(),
        ));
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|_| CliError::Input("git top level was not UTF-8".to_owned()))?;
    let path = PathBuf::from(text.trim_end());
    fs::canonicalize(&path).map_err(|source| CliError::Io {
        path: path.display().to_string(),
        source,
    })
}

fn upload_capability() -> CapabilityV1 {
    CapabilityV1::new(
        UPLOAD_CAPABILITY_ID,
        "Upload an inert Cloudflare Worker version",
        "CLI",
        "wrangler versions upload",
    )
}

fn upload_input(config: &str, name: &str, message: Option<&str>) -> CallInput {
    let mut query = json!({
        "config": config,
        "name": name,
    });
    if let Some(message) = message {
        query["message"] = json!(message);
    }
    CallInput {
        query,
        ..CallInput::default()
    }
}

fn path_text(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| CliError::Input("deploy config path must be UTF-8".to_owned()))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::super::prelude::WorkspaceGraph;
    use super::{
        FILE_NAME, admit_worker_lane, deploy_root, parse_deploy_file, path_text, read_deploy_file,
        require_committed_control, require_control_head, resolve_config, select_target,
        upload_input, upload_projection,
    };
    use crate::Cli;
    use cfctl_core::{AdapterStatus, CapabilityV1, EffectClass, RiskClass};
    use cfctl_workspace::RegisteredRoot;
    use clap::Parser as _;
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    const PROFILE_ID: &str = "cfctl-site-release-example";
    const ACCOUNT_ID: &str = "0123456789abcdef0123456789abcdef";

    fn valid_file() -> String {
        format!(
            r#"schema_version = 1

[target.site]
lane = "worker"
name = "cfctl-site"
config = "wrangler.toml"
profile_id = "{PROFILE_ID}"
account_id = "{ACCOUNT_ID}"
"#
        )
    }

    fn upload_capability() -> CapabilityV1 {
        let mut capability = super::upload_capability();
        capability.mutating = true;
        capability.adapter_status = AdapterStatus::DelegatedCli;
        capability.risk = RiskClass::CrossConfig;
        capability.effect = EffectClass::ReversibleWrite;
        capability.execution_supported = true;
        capability
    }

    fn git(root: &Path, args: &[&str]) {
        let status = Command::new("git")
            .args(args)
            .current_dir(root)
            .status()
            .expect("git");
        assert!(status.success(), "git {args:?}");
    }

    fn commit_fixture(root: &Path) {
        git(root, &["init", "--quiet", "--initial-branch=main"]);
        git(root, &["add", "."]);
        git(
            root,
            &[
                "-c",
                "user.name=cfctl test",
                "-c",
                "user.email=cfctl-test@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "fixture",
            ],
        );
    }

    #[test]
    fn valid_file_parses_and_parser_requires_a_target_name() {
        let file = parse_deploy_file(&valid_file()).expect("valid file");
        assert_eq!(file.schema_version, 1);
        assert_eq!(file.target["site"].lane, "worker");
        assert_eq!(file.target["site"].config, "wrangler.toml");
        assert!(Cli::try_parse_from(["cfctl", "deploy"]).is_err());
        assert!(Cli::try_parse_from(["cfctl", "deploy", "site", "--yes"]).is_err());
        let parsed = Cli::try_parse_from(["cfctl", "--json", "deploy", "site"]).expect("deploy");
        match parsed.command {
            Some(crate::Command::Deploy(arguments)) => assert_eq!(arguments.target, "site"),
            other => panic!("expected deploy, got {other:?}"),
        }
    }

    #[test]
    fn unknown_forbidden_schema_absolute_and_escape_fail_closed() {
        let unknown = parse_deploy_file(&format!("{}\nextra = true\n", valid_file()))
            .expect_err("unknown key")
            .to_string();
        assert!(unknown.contains("unknown field"), "{unknown}");

        for field in [
            "message",
            "yes",
            "token",
            "standing_authority",
            "max_cost",
            "risk",
        ] {
            let text = format!("{field} = \"no\"\n{}", valid_file());
            let error = parse_deploy_file(&text).expect_err(field).to_string();
            assert!(
                error.contains(&format!("field `{field}` is not allowed")),
                "{field}: {error}"
            );
        }

        let schema =
            parse_deploy_file(&valid_file().replace("schema_version = 1", "schema_version = 2"))
                .expect_err("schema")
                .to_string();
        assert!(schema.contains("schema_version must be 1"), "{schema}");

        let root = tempfile::tempdir().expect("root");
        let error = resolve_config(root.path(), "/tmp/wrangler.toml")
            .expect_err("absolute")
            .to_string();
        assert!(error.contains("repository-relative"), "{error}");
        let error = resolve_config(root.path(), "../wrangler.toml")
            .expect_err("escape")
            .to_string();
        assert!(error.contains("repository-relative"), "{error}");
    }

    #[test]
    fn symlink_escape_unknown_target_missing_file_and_other_lanes_fail_closed() {
        let root = tempfile::tempdir().expect("root");
        let outside = tempfile::tempdir().expect("outside");
        let outside_config = outside.path().join("wrangler.toml");
        fs::write(&outside_config, "name = \"cfctl-site\"\n").expect("outside config");
        std::os::unix::fs::symlink(&outside_config, root.path().join("escape.toml"))
            .expect("symlink");
        fs::write(
            root.path().join(FILE_NAME),
            valid_file().replace("config = \"wrangler.toml\"", "config = \"escape.toml\""),
        )
        .expect("control file");
        let error = resolve_config(root.path(), "escape.toml")
            .expect_err("symlink escape")
            .to_string();
        assert!(
            error.contains("escapes the registered repository"),
            "{error}"
        );

        let file = parse_deploy_file(&valid_file()).expect("file");
        let missing = select_target(&file, &root.path().join(FILE_NAME), "missing")
            .expect_err("unknown target")
            .to_string();
        assert!(missing.contains("is not declared"), "{missing}");

        let absent = read_deploy_file(&root.path().join("nested").join(FILE_NAME))
            .expect_err("missing")
            .to_string();
        assert!(absent.contains("is missing"), "{absent}");
        assert!(!absent.contains(".cfctl/operations"), "{absent}");

        let lane = admit_worker_lane("site", "pages")
            .expect_err("lane")
            .to_string();
        assert!(lane.contains("not admitted"), "{lane}");
        assert_eq!(
            admit_worker_lane("site", "pages")
                .expect_err("lane code")
                .code(),
            "CFCTL_USAGE"
        );
    }

    #[test]
    fn deploy_root_requires_one_registered_git_top() {
        let root = tempfile::tempdir().expect("root");
        fs::write(root.path().join("README"), "fixture\n").expect("readme");
        commit_fixture(root.path());
        let nested = root.path().join("workers");
        fs::create_dir(&nested).expect("nested");
        let found = deploy_root(&nested, &[root.path().to_path_buf()]).expect("git top");
        assert_eq!(found, root.path().canonicalize().expect("canonical root"));

        let error = deploy_root(&nested, std::slice::from_ref(&nested))
            .expect_err("subdirectory is not the git top")
            .to_string();
        assert!(error.contains("git top level"), "{error}");

        let parent = root.path().parent().expect("parent");
        let error = deploy_root(
            root.path(),
            &[parent.to_path_buf(), root.path().to_path_buf()],
        )
        .expect_err("two roots")
        .to_string();
        assert!(error.contains("more than one"), "{error}");

        let elsewhere = tempfile::tempdir().expect("elsewhere");
        let error = deploy_root(root.path(), &[elsewhere.path().to_path_buf()])
            .expect_err("unregistered")
            .to_string();
        assert!(error.contains("not inside exactly one"), "{error}");
    }

    #[test]
    fn profile_or_account_mismatch_fails_before_a_plan() {
        let root = tempfile::tempdir().expect("root");
        fs::write(root.path().join(FILE_NAME), valid_file()).expect("control file");
        fs::write(root.path().join("wrangler.toml"), "name = \"cfctl-site\"\n").expect("config");
        let capability = upload_capability();
        let graph = WorkspaceGraph::default();
        let profile = upload_projection(
            &graph,
            &capability,
            root.path(),
            "site",
            "other-profile",
            Some(ACCOUNT_ID),
        )
        .expect_err("profile")
        .to_string();
        assert!(profile.contains("pins profile"), "{profile}");
        assert!(!profile.contains("dirty"), "{profile}");

        let account = upload_projection(
            &graph,
            &capability,
            root.path(),
            "site",
            PROFILE_ID,
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        )
        .expect_err("account")
        .to_string();
        assert!(account.contains("pins account"), "{account}");
    }

    #[test]
    fn file_plans_the_same_versions_upload_target_as_the_direct_call() {
        let root = tempfile::tempdir().expect("root");
        let build = root.path().join("build");
        fs::create_dir(&build).expect("build");
        fs::write(build.join("worker.js"), "worker\n").expect("worker");
        fs::write(
            root.path().join("wrangler.toml"),
            "name = \"cfctl-site\"\nmain = \"build/worker.js\"\n",
        )
        .expect("wrangler");
        fs::write(root.path().join(FILE_NAME), valid_file()).expect("control file");
        commit_fixture(root.path());
        let source_sha = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(root.path())
            .output()
            .expect("head");
        let source_sha = String::from_utf8(source_sha.stdout)
            .expect("utf-8")
            .trim()
            .to_owned();
        let repository = root.path().canonicalize().expect("canonical root");
        let artifact_root = build.canonicalize().expect("canonical build");
        let artifact_sha256 = super::super::worker_deployment_artifact::artifact_set_sha256(
            &repository,
            &[artifact_root],
        )
        .expect("artifact hash");
        let message = format!("source={source_sha} artifact-sha256={artifact_sha256}");
        let graph = WorkspaceGraph::discover(&[RegisteredRoot::new(root.path())]).expect("graph");
        let capability = upload_capability();
        let from_file = upload_projection(
            &graph,
            &capability,
            root.path(),
            "site",
            PROFILE_ID,
            Some(ACCOUNT_ID),
        )
        .expect("file projection");
        let config = repository.join("wrangler.toml");
        let from_call = super::super::worker_deployment::prepare_target(
            &graph,
            &capability,
            &upload_input(
                &path_text(&config).expect("config text"),
                "cfctl-site",
                Some(&message),
            ),
        )
        .expect("call projection")
        .expect("projection");
        assert_eq!(from_file, from_call);
        assert_eq!(from_file["service_name"], "cfctl-site");
        assert_eq!(from_file["source_sha"], source_sha);
        assert_eq!(from_file["version_message"], message);
        assert_eq!(from_file["config"]["path"].as_str(), config.to_str());
        assert!(
            from_file["config"]["sha256"]
                .as_str()
                .is_some_and(|hash| hash.len() == 64)
        );

        fs::write(
            root.path().join(FILE_NAME),
            valid_file().replace("name = \"cfctl-site\"", "name = \"other\""),
        )
        .expect("mismatched name");
        commit_fixture(root.path());
        let graph = WorkspaceGraph::discover(&[RegisteredRoot::new(root.path())]).expect("graph");
        let mismatch = upload_projection(
            &graph,
            &capability,
            root.path(),
            "site",
            PROFILE_ID,
            Some(ACCOUNT_ID),
        )
        .expect_err("service name")
        .to_string();
        assert!(
            mismatch.contains("differs from reviewed config name `cfctl-site`"),
            "{mismatch}"
        );
    }

    #[test]
    fn dirty_repository_fails_with_the_worker_deployment_error() {
        let root = tempfile::tempdir().expect("root");
        let build = root.path().join("build");
        fs::create_dir(&build).expect("build");
        fs::write(build.join("worker.js"), "worker\n").expect("worker");
        fs::write(
            root.path().join("wrangler.toml"),
            "name = \"cfctl-site\"\nmain = \"build/worker.js\"\n",
        )
        .expect("wrangler");
        fs::write(root.path().join(FILE_NAME), valid_file()).expect("control file");
        commit_fixture(root.path());
        fs::write(root.path().join("notes.txt"), "dirty\n").expect("dirty file");
        let graph = WorkspaceGraph::discover(&[RegisteredRoot::new(root.path())]).expect("graph");
        let error = upload_projection(
            &graph,
            &upload_capability(),
            root.path(),
            "site",
            PROFILE_ID,
            Some(ACCOUNT_ID),
        )
        .expect_err("dirty")
        .to_string();
        let repository = root.path().canonicalize().expect("canonical root");
        assert_eq!(
            error,
            format!(
                "Worker deployment repository `{}` is dirty; commit the reviewed source before planning",
                repository.display()
            )
        );
    }

    #[test]
    fn ignored_and_untracked_control_files_cannot_borrow_another_head() {
        for ignored in [false, true] {
            let root = tempfile::tempdir().expect("root");
            fs::write(root.path().join("README"), "fixture").expect("source");
            if ignored {
                fs::write(root.path().join(".gitignore"), "cfctl.toml\n").expect("ignore");
            }
            commit_fixture(root.path());
            fs::write(root.path().join(FILE_NAME), valid_file()).expect("control");
            let (_, captured) = read_deploy_file(&root.path().join(FILE_NAME)).expect("read");
            let error = require_committed_control(root.path(), &captured)
                .expect_err("uncommitted control must fail");
            assert!(error.to_string().contains("must be committed"), "{error}");
        }
    }

    #[test]
    fn control_bytes_and_planned_head_are_both_bound() {
        let root = tempfile::tempdir().expect("root");
        fs::write(root.path().join(FILE_NAME), valid_file()).expect("control");
        commit_fixture(root.path());
        let (_, captured) = read_deploy_file(&root.path().join(FILE_NAME)).expect("read");
        let head = require_committed_control(root.path(), &captured).expect("committed");
        assert!(
            require_control_head(&format!("source={head} artifact-sha256=fixture"), &head).is_ok()
        );
        assert!(require_control_head("source=other artifact-sha256=fixture", &head).is_err());
        let mut changed = captured;
        changed[0] = b'S';
        let error = require_committed_control(root.path(), &changed).expect_err("changed bytes");
        assert!(
            error.to_string().contains("committed HEAD bytes"),
            "{error}"
        );
    }

    #[test]
    fn control_growth_after_opened_metadata_is_still_bounded() {
        use std::io::Write as _;
        fn grow(path: &Path) {
            fs::OpenOptions::new()
                .append(true)
                .open(path)
                .expect("open owned fixture")
                .write_all(&vec![
                    b' ';
                    usize::try_from(super::MAX_FILE_BYTES)
                        .expect("fixture limit fits usize")
                ])
                .expect("grow owned fixture");
        }
        let root = tempfile::tempdir().expect("root");
        let path = root.path().join(FILE_NAME);
        fs::write(&path, valid_file()).expect("control");
        let error = super::AFTER_METADATA_TEST_HOOK
            .sync_scope(grow as fn(&Path), || read_deploy_file(&path))
            .expect_err("growth after metadata must fail");
        assert!(error.to_string().contains("streamed byte bound"), "{error}");
    }
}
