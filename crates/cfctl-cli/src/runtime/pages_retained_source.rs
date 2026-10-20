//! Retained artifact provenance, clean procedure checkout, and provider branch
//! are separate identities. This mode authenticates no earlier build receipt.

use super::{CliError, Result, pages_deployment, pages_immutable, pages_source};
use cfctl_cloudflare::CallInput;
use cfctl_core::{CapabilityV1, pages_deployment::PagesDeploymentEnvironmentV1};
use cfctl_workspace::WorkspaceGraph;
use serde_json::{Value, json};
use std::{fs, path::Path};

fn rejected(reason: &str) -> CliError {
    CliError::Input(format!("Pages retained-artifact source refused: {reason}"))
}

pub(super) fn requested(
    capability: &CapabilityV1,
    input: &CallInput,
    environment: PagesDeploymentEnvironmentV1,
) -> Result<bool> {
    if !["checkout_commit", "checkout_branch"]
        .iter()
        .any(|name| input.query.get(name).is_some())
    {
        return Ok(false);
    }
    if !pages_deployment::binds_artifact(capability)
        || environment != PagesDeploymentEnvironmentV1::Production
        || pages_immutable::requested(input)
    {
        return Err(rejected(
            "checkout selectors require production direct upload without artifact_receipt",
        ));
    }
    for (name, schema) in [
        (
            "checkout_commit",
            json!({"type":"string","pattern":"^[0-9a-f]{40}$"}),
        ),
        ("checkout_branch", json!({"type":"string","minLength":1})),
    ] {
        let mut selectors = capability.selectors.iter().filter(|s| s.name == name);
        let declared = selectors.next().is_some_and(|s| {
            s.location == "query"
                && s.value_type == "string"
                && !s.required
                && s.contract.as_ref().is_some_and(|c| c.schema == schema)
        }) && selectors.next().is_none();
        if !declared {
            return Err(rejected("bound catalog lacks the paired checkout contract"));
        }
        let value = required(input, name)?;
        let valid = if name == "checkout_commit" {
            pages_source::is_canonical_git_sha1(value)
        } else {
            pages_source::git_branch_name_is_safe(value)
        };
        if !valid {
            return Err(rejected(
                "checkout selectors must be canonical and nonempty",
            ));
        }
    }
    Ok(true)
}

fn required<'a>(input: &'a CallInput, name: &str) -> Result<&'a str> {
    input
        .query
        .get(name)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| rejected("both checkout selectors and commit_hash must be nonempty strings"))
}

fn git(root: &Path, args: &[&str], allow_no_match: bool) -> Result<String> {
    let mut arguments = vec![
        "--no-lazy-fetch",
        "--no-replace-objects",
        "--no-optional-locks",
        "-c",
        "core.fsmonitor=false",
    ];
    arguments.extend_from_slice(args);
    pages_source::pages_git_output(
        Some(root),
        &arguments,
        pages_source::GIT_CONFIG_TIMEOUT,
        allow_no_match,
    )
}

fn object(root: &Path, revision: &str, kind: &str) -> Result<String> {
    let expression = format!("{revision}^{{{kind}}}");
    let output = git(
        root,
        &["rev-parse", "--verify", "--end-of-options", &expression],
        false,
    )?;
    let value = output.trim_end_matches('\n');
    if !pages_source::is_canonical_git_sha1(value) {
        return Err(rejected(
            "local Git object did not resolve to one canonical identity",
        ));
    }
    Ok(value.to_owned())
}

pub(super) fn source(graph: &WorkspaceGraph, input: &CallInput, artifact: &Path) -> Result<Value> {
    let repository = pages_deployment::repository_owning_path(graph, artifact)
        .ok_or_else(|| rejected("artifact has no registered owning repository"))?;
    let root = &repository.path;
    pages_deployment::reject_symlink_components(root)?;
    if !root.is_absolute()
        || fs::canonicalize(root).map_err(|_| rejected("repository is unavailable"))? != *root
    {
        return Err(rejected(
            "registered repository must be its canonical physical root",
        ));
    }
    let actual_root = git(root, &["rev-parse", "--show-toplevel"], false)?;
    if Path::new(actual_root.trim_end_matches('\n')) != root {
        return Err(rejected(
            "registered root is not the exact Git checkout root",
        ));
    }
    let checkout_commit = required(input, "checkout_commit")?;
    let checkout_branch = required(input, "checkout_branch")?;
    let artifact_commit = required(input, "commit_hash")?;
    if !pages_source::is_canonical_git_sha1(artifact_commit) {
        return Err(rejected(
            "commit_hash must be a canonical full artifact source commit",
        ));
    }
    let head = object(root, "HEAD", "commit")?;
    let branch = git(root, &["symbolic-ref", "--quiet", "HEAD"], false)?;
    if repository.git.dirty
        || repository.git.head.as_deref() != Some(checkout_commit)
        || repository.git.branch.as_deref() != Some(checkout_branch)
        || head != checkout_commit
        || branch.trim_end_matches('\n') != format!("refs/heads/{checkout_branch}")
        || !git(
            root,
            &["status", "--porcelain=v1", "--untracked-files=normal"],
            false,
        )?
        .is_empty()
    {
        return Err(rejected(
            "current clean registered checkout must equal both checkout selectors",
        ));
    }
    // Legacy grafts can substitute ancestry independently of replacement refs.
    let graft_path = git(root, &["rev-parse", "--git-path", "info/grafts"], false)?;
    if root
        .join(graft_path.trim_end_matches('\n'))
        .try_exists()
        .map_err(|_| rejected("graft state unavailable"))?
    {
        return Err(rejected(
            "legacy Git grafts cannot establish canonical ancestry",
        ));
    }
    if object(root, artifact_commit, "commit")? != artifact_commit {
        return Err(rejected(
            "artifact source commit is not a local canonical commit",
        ));
    }
    git(
        root,
        &[
            "merge-base",
            "--is-ancestor",
            artifact_commit,
            checkout_commit,
        ],
        false,
    )?;
    let origin = pages_source::configured_origin(root)?
        .filter(|s| pages_source::github_remote_identity(s).is_some())
        .ok_or_else(|| rejected("one safe GitHub origin without credentials is required"))?;
    let rewrites = git(
        root,
        &["config", "--get-regexp", "^url\\..*\\.insteadof$"],
        true,
    )?;
    if pages_source::matching_git_url_rewrite(&rewrites, &[&origin])? {
        return Err(rejected(
            "origin is subject to a configured URL substitution",
        ));
    }
    Ok(json!({
        "mode": "retained_artifact_v1",
        "repository": root,
        "origin": origin,
        "artifact_source": {"commit": artifact_commit, "tree": object(root, artifact_commit, "tree")?},
        "checkout": {"commit": checkout_commit, "tree": object(root, checkout_commit, "tree")?, "branch": checkout_branch},
    }))
}

#[cfg(test)]
#[path = "pages_retained_source/tests.rs"]
mod tests;
