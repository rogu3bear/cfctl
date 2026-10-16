//! Protected production and provider-returned preview URL identity.
use super::CliError;
use cfctl_core::pages_deployment::{PagesDeploymentEnvironmentV1, PagesDeploymentVerificationV1};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use url::Url;

fn rejected(reason: &str) -> CliError {
    CliError::Input(format!("Pages preview identity is not proven: {reason}"))
}

fn pages_url(raw: &str, domain: &str) -> Result<Url, CliError> {
    let url = Url::parse(raw).map_err(|_| rejected("invalid provider URL"))?;
    let suffix = format!(".{domain}");
    let host = url.host_str().ok_or_else(|| rejected("URL omitted host"))?;
    let prefix = host
        .strip_suffix(&suffix)
        .filter(|value| !value.is_empty() && !value.contains('.'));
    if url.scheme() != "https"
        || prefix.is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(rejected(
            "URL is not one HTTPS deployment/alias in the authenticated project subdomain",
        ));
    }
    Ok(url)
}

fn project_domain(project: &Value) -> Result<&str, CliError> {
    let domain = project
        .get("subdomain")
        .and_then(Value::as_str)
        .filter(|value| value.ends_with(".pages.dev") && value.len() > ".pages.dev".len())
        .ok_or_else(|| rejected("project omitted its Pages subdomain"))?;
    let parsed = Url::parse(&format!("https://{domain}"))
        .map_err(|_| rejected("project Pages subdomain is invalid"))?;
    if parsed.host_str() != Some(domain)
        || parsed.path() != "/"
        || parsed.port().is_some()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(rejected("project Pages subdomain contains URL controls"));
    }
    Ok(domain)
}

pub(super) fn protected_snapshot(
    project: &Value,
    project_name: &str,
    production_branch: &str,
) -> Result<Value, CliError> {
    if project.get("name").and_then(Value::as_str) != Some(project_name)
        || project.get("production_branch").and_then(Value::as_str) != Some(production_branch)
    {
        return Err(rejected("protected project or production branch differs"));
    }
    let domain = project_domain(project)?;
    let canonical = match project.get("canonical_deployment") {
        Some(Value::Null) => Value::Null,
        Some(value) if value.is_object() => {
            let id = value
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| uuid::Uuid::parse_str(id).is_ok())
                .ok_or_else(|| rejected("canonical production deployment ID is invalid"))?;
            let branch = value
                .pointer("/deployment_trigger/metadata/branch")
                .and_then(Value::as_str);
            let commit = value
                .pointer("/deployment_trigger/metadata/commit_hash")
                .and_then(Value::as_str)
                .filter(|value| super::pages_deployment::full_git_sha(value))
                .ok_or_else(|| rejected("canonical production commit is missing"))?;
            let url = value
                .get("url")
                .and_then(Value::as_str)
                .ok_or_else(|| rejected("canonical production URL is missing"))?;
            pages_url(url, domain)?;
            if value.get("project_name").and_then(Value::as_str) != Some(project_name)
                || value.get("environment").and_then(Value::as_str) != Some("production")
                || branch != Some(production_branch)
            {
                return Err(rejected(
                    "canonical production projection has a different scope",
                ));
            }
            json!({"id":id,"branch":production_branch,"commit_hash":commit,"url":url})
        }
        _ => return Err(rejected("canonical production projection is unavailable")),
    };
    Ok(
        json!({"schema_version":1,"production_branch":production_branch,
        "pages_subdomain":domain,"canonical_deployment":canonical}),
    )
}

#[expect(
    clippy::too_many_lines,
    reason = "one safe projection joins exact preview identity, returned URLs and protected production"
)]
pub(super) fn verified_identity(
    expected: &ExpectedDeployment<'_>,
    structured: &Value,
    readback: &Value,
    protected: &Value,
    observed_project: &Value,
) -> Result<PagesDeploymentVerificationV1, CliError> {
    let ExpectedDeployment {
        account,
        project,
        deployment_id,
        branch,
        commit,
    } = *expected;
    let domain = protected
        .get("pages_subdomain")
        .and_then(Value::as_str)
        .ok_or_else(|| rejected("protected Pages subdomain is missing"))?;
    let production_branch = protected
        .get("production_branch")
        .and_then(Value::as_str)
        .ok_or_else(|| rejected("protected production branch is missing"))?;
    if account.is_empty()
        || !super::pages_deployment::full_git_sha(commit)
        || !uuid::Uuid::parse_str(deployment_id)
            .is_ok_and(|id| id.hyphenated().to_string() == deployment_id)
        || structured["deployment_id"].as_str() != Some(deployment_id)
        || !super::pages_deployment::structured_output_matches_for_environment(
            structured,
            project,
            production_branch,
            commit,
            PagesDeploymentEnvironmentV1::Preview,
        )
    {
        return Err(rejected("requested or helper identity is invalid"));
    }
    if &protected_snapshot(observed_project, project, production_branch)? != protected {
        return Err(rejected(
            "canonical production deployment or production branch changed",
        ));
    }
    let url = readback
        .get("url")
        .and_then(Value::as_str)
        .ok_or_else(|| rejected("immutable deployment URL is missing"))?;
    let immutable = pages_url(url, domain)?;
    if branch == production_branch
        || readback.get("id").and_then(Value::as_str) != Some(deployment_id)
        || readback.get("project_name").and_then(Value::as_str) != Some(project)
        || readback.get("environment").and_then(Value::as_str) != Some("preview")
        || readback
            .pointer("/deployment_trigger/metadata/branch")
            .and_then(Value::as_str)
            != Some(branch)
        || readback
            .pointer("/deployment_trigger/metadata/commit_hash")
            .and_then(Value::as_str)
            != Some(commit)
        || readback
            .pointer("/latest_stage/name")
            .and_then(Value::as_str)
            != Some("deploy")
        || readback
            .pointer("/latest_stage/status")
            .and_then(Value::as_str)
            != Some("success")
        || structured.get("url").and_then(Value::as_str) != Some(url)
    {
        return Err(rejected(
            "exact deployment/branch/commit/URL/terminal identity differs",
        ));
    }
    let values = readback
        .get("aliases")
        .and_then(Value::as_array)
        .filter(|values| !values.is_empty() && values.len() <= 32)
        .ok_or_else(|| rejected("bounded provider alias list is unavailable"))?;
    let mut aliases = BTreeSet::new();
    for value in values {
        let raw = value
            .as_str()
            .ok_or_else(|| rejected("alias is not a URL string"))?;
        let alias = pages_url(raw, domain)?;
        if alias.host_str() == immutable.host_str() || !aliases.insert(raw.to_owned()) {
            return Err(rejected(
                "alias duplicates the immutable URL or another alias",
            ));
        }
    }
    let alias = match structured.get("alias") {
        Some(Value::String(alias)) if aliases.contains(alias) => Some(alias.clone()),
        None | Some(Value::Null) if aliases.len() == 1 => aliases.first().cloned(),
        _ => {
            return Err(rejected(
                "helper alias is not one exact provider-returned alias",
            ));
        }
    };
    Ok(PagesDeploymentVerificationV1 {
        schema_version: 1,
        account_id: account.to_owned(),
        project_name: project.to_owned(),
        deployment_id: deployment_id.to_owned(),
        environment: PagesDeploymentEnvironmentV1::Preview,
        branch: branch.to_owned(),
        commit_hash: commit.to_owned(),
        production_branch: production_branch.to_owned(),
        immutable_url: url.to_owned(),
        aliases: aliases.into_iter().collect(),
        branch_alias: alias,
        canonical_production_preserved: true,
    })
}

pub(super) struct ExpectedDeployment<'a> {
    pub account: &'a str,
    pub project: &'a str,
    pub deployment_id: &'a str,
    pub branch: &'a str,
    pub commit: &'a str,
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests;
