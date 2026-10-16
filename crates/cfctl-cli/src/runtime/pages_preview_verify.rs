//! Exact preview verification, without persisting provider environment values.
use super::pages_preview::ExpectedDeployment;
use super::prelude::{
    AdapterStatus, AuthCredential, CallInput, CapabilityV1, CatalogSnapshot, CliError, Duration,
    Executor, PlanV1, Result, Value, json,
};
use super::{pages_deployment, pages_preview};
use cfctl_core::pages_deployment::PagesDeploymentEnvironmentV1;

pub(super) async fn verify(
    catalog: &CatalogSnapshot,
    plan: &PlanV1,
    receipt: &Value,
    credential: &AuthCredential,
) -> Value {
    let result = async {
        let executor = Executor::new(
            super::support::http_client()?,
            super::cloudflare_api::BASE_URL,
        )?;
        verify_with_executor(catalog, plan, receipt, credential, &executor).await
    }
    .await;
    match result {
        Ok(identity) => json!({
            "passed":true,
            "basis":"the exact new preview deployment reached success; provider URLs and the unchanged canonical production projection were verified",
            "deployment_id":identity.deployment_id,
            "verified_deployment":identity,
        }),
        Err(error) => json!({
            "passed":false,
            "basis":format!("Pages preview verification failed after the upload boundary: {error}"),
        }),
    }
}

fn read_contract<'a>(
    catalog: &'a CatalogSnapshot,
    id: &str,
    path: &str,
) -> Result<&'a CapabilityV1> {
    catalog
        .get(id)
        .filter(|capability| {
            capability.method == "GET"
                && capability.path == path
                && !capability.mutating
                && matches!(
                    capability.adapter_status,
                    AdapterStatus::Native | AdapterStatus::DynamicApi
                )
        })
        .ok_or_else(|| {
            CliError::Input(format!(
                "exact Pages read contract {id} is absent or drifted"
            ))
        })
}

fn required_string<'a>(value: &'a Value, pointer: &str) -> Result<&'a str> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CliError::Input(format!("Pages preview omitted {pointer}")))
}

#[expect(
    clippy::too_many_lines,
    reason = "one bounded read lifecycle joins exact preview identity with protected production"
)]
pub(super) async fn verify_with_executor(
    catalog: &CatalogSnapshot,
    plan: &PlanV1,
    receipt: &Value,
    credential: &AuthCredential,
    executor: &Executor,
) -> Result<cfctl_core::pages_deployment::PagesDeploymentVerificationV1> {
    super::preconditions_core::required_pages_deployment_project_state_precondition(plan)?;
    let input: CallInput = serde_json::from_value(plan.input.clone())?;
    if super::pages_intent::requested(&plan.capability, &input)?
        != PagesDeploymentEnvironmentV1::Preview
    {
        return Err(CliError::Input(
            "preview verifier requires explicit preview intent".to_owned(),
        ));
    }
    let project = pages_deployment::project_name(&plan.capability, &input)?;
    let branch = required_string(&input.query, "/branch")?;
    let commit = required_string(&input.query, "/commit_hash")?;
    let admission = plan
        .targets
        .pointer(&format!(
            "/live_preconditions/{}",
            pages_deployment::PROJECT_STATE_PRECONDITION
        ))
        .ok_or_else(|| CliError::Input("preview project admission is missing".to_owned()))?;
    let protected = &admission["protected_production"];
    let production_branch = required_string(protected, "/production_branch")?;
    let structured = &receipt["structured_output"];
    let deployment_id = required_string(structured, "/deployment_id")?;
    if !uuid::Uuid::parse_str(deployment_id)
        .is_ok_and(|id| id.hyphenated().to_string() == deployment_id)
        || !pages_deployment::structured_output_matches_for_environment(
            structured,
            project,
            production_branch,
            commit,
            PagesDeploymentEnvironmentV1::Preview,
        )
    {
        return Err(CliError::Input(
            "helper returned a different preview deployment identity".to_owned(),
        ));
    }
    let prior = admission["prior_deployment_ids"]
        .as_array()
        .ok_or_else(|| CliError::Input("prior deployment identity set is missing".to_owned()))?;
    if prior.iter().any(|id| {
        id.as_str()
            .is_none_or(|id| uuid::Uuid::parse_str(id).is_err() || id == deployment_id)
    }) {
        return Err(CliError::Input(
            "returned preview ID existed before upload or prior set is malformed".to_owned(),
        ));
    }
    let details = read_contract(
        catalog,
        pages_deployment::DEPLOYMENT_READ_CAPABILITY_ID,
        pages_deployment::DEPLOYMENT_DETAIL_PATH,
    )?;
    let project_read = read_contract(
        catalog,
        pages_deployment::PROJECT_READ_CAPABILITY_ID,
        pages_deployment::PROJECT_DETAIL_PATH,
    )?;
    let expected = ExpectedDeployment {
        account: &plan.account_id,
        project,
        deployment_id,
        branch,
        commit,
    };
    // Discovery and terminal progress have separate finite bounds. No mutation
    // or collection-based identity substitution is permitted during polling.
    for attempt in 0..150 {
        let response = executor.execute_read(details, &CallInput {
            selectors: json!({"account_id":plan.account_id,"project_name":project,"deployment_id":deployment_id}),
            ..CallInput::default()
        }, credential).await?;
        if response.status == 404 && attempt < 29 {
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }
        if !response.success || response.status != 200 {
            return Err(CliError::Input(format!(
                "exact preview read returned HTTP {}",
                response.status
            )));
        }
        let value = &response.result;
        if value["id"].as_str() != Some(deployment_id)
            || value["project_name"].as_str() != Some(project)
            || value["environment"].as_str() != Some("preview")
            || value
                .pointer("/deployment_trigger/metadata/branch")
                .and_then(Value::as_str)
                != Some(branch)
            || value
                .pointer("/deployment_trigger/metadata/commit_hash")
                .and_then(Value::as_str)
                != Some(commit)
        {
            return Err(CliError::Input(
                "exact preview read has a different identity".to_owned(),
            ));
        }
        match value.pointer("/latest_stage/status").and_then(Value::as_str) {
            Some("success") => {
                let observed = executor.execute_read(project_read, &CallInput {
                    selectors: json!({"account_id":plan.account_id,"project_name":project}),
                    ..CallInput::default()
                }, credential).await?;
                if !observed.success || observed.status != 200 {
                    return Err(CliError::Input(format!("protected project read returned HTTP {}", observed.status)));
                }
                return pages_preview::verified_identity(&expected, structured, value, protected, &observed.result);
            }
            Some("active" | "idle") if attempt < 149 => tokio::time::sleep(Duration::from_secs(1)).await,
            _ => return Err(CliError::Input("exact preview did not reach terminal deploy success within the bounded read window".to_owned())),
        }
    }
    Err(CliError::Input(
        "preview verification exhausted its finite read window".to_owned(),
    ))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests;
