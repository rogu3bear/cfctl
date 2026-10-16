//! Keep requested deployment intent separate from the provider production branch.

use super::{CliError, pages_deployment, pages_immutable};
use cfctl_cloudflare::CallInput;
use cfctl_core::{CapabilityV1, pages_deployment::PagesDeploymentEnvironmentV1};
use serde_json::{Value, json};

pub(super) fn requested(
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<PagesDeploymentEnvironmentV1, CliError> {
    let environment = input
        .query
        .get("environment")
        .map(|value| {
            serde_json::from_value::<PagesDeploymentEnvironmentV1>(value.clone()).map_err(|_| {
                CliError::Input(
                    "Pages environment must be exactly `production` or `preview`".to_owned(),
                )
            })
        })
        .transpose()?
        .unwrap_or_default();
    if environment == PagesDeploymentEnvironmentV1::Preview {
        let mut selectors = capability
            .selectors
            .iter()
            .filter(|selector| selector.name == "environment");
        let declared = selectors.next().is_some_and(|selector| {
            selector.location == "query"
                && selector.value_type == "string"
                && !selector.required
                && selector.contract.as_ref().is_some_and(|contract| {
                    contract.schema["type"] == "string"
                        && contract.schema["enum"] == json!(["production", "preview"])
                        && contract.schema["default"] == "production"
                })
        }) && selectors.next().is_none();
        if !pages_deployment::binds_artifact(capability) || !declared {
            return Err(CliError::Input(
                "Pages preview requires the qualified direct-upload environment contract in the bound catalog"
                    .to_owned(),
            ));
        }
        if pages_immutable::requested(input) {
            return Err(CliError::Input(
                "The current immutable Pages reproduction receipt supports production only; preview requires a qualified clean-checkout artifact"
                    .to_owned(),
            ));
        }
    }
    Ok(environment)
}

pub(super) fn validate_branch(
    environment: PagesDeploymentEnvironmentV1,
    branch: &str,
    production_branch: &str,
) -> Result<(), CliError> {
    let valid = !branch.is_empty()
        && !production_branch.is_empty()
        && match environment {
            PagesDeploymentEnvironmentV1::Production => branch == production_branch,
            PagesDeploymentEnvironmentV1::Preview => branch != production_branch,
        };
    if !valid {
        return Err(CliError::Input(format!(
            "Pages {} branch `{branch}` is incompatible with authenticated production branch `{production_branch}`; the deployment boundary was not crossed",
            environment.as_str()
        )));
    }
    Ok(())
}

pub(super) fn receipt_matches(
    capability: &CapabilityV1,
    input: &CallInput,
    receipt: &Value,
) -> Result<bool, CliError> {
    let environment = requested(capability, input)?;
    if !pages_deployment::binds_artifact(capability) {
        return Ok(environment == PagesDeploymentEnvironmentV1::Production);
    }
    let Some(branch) = input.query.get("branch").and_then(Value::as_str) else {
        return Ok(false);
    };
    let Some(production_branch) = receipt.get("production_branch").and_then(Value::as_str) else {
        return Ok(false);
    };
    if validate_branch(environment, branch, production_branch).is_err() {
        return Ok(false);
    }
    Ok(match environment {
        PagesDeploymentEnvironmentV1::Production => receipt
            .get("deployment_environment")
            .is_none_or(|value| value == "production"),
        PagesDeploymentEnvironmentV1::Preview => {
            receipt["deployment_environment"] == "preview"
                && receipt["requested_branch"].as_str() == Some(branch)
                && receipt["protected_production"].is_object()
        }
    })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{PagesDeploymentEnvironmentV1, requested, validate_branch};
    use cfctl_cloudflare::CallInput;
    use cfctl_core::{CapabilityV1, SelectorContractV1, SelectorV1};
    use serde_json::json;

    #[test]
    fn explicit_preview_cannot_target_the_production_branch() {
        assert!(validate_branch(PagesDeploymentEnvironmentV1::Preview, "main", "main").is_err());
        assert!(validate_branch(PagesDeploymentEnvironmentV1::Preview, "stage", "main").is_ok());
        assert!(
            validate_branch(PagesDeploymentEnvironmentV1::Production, "stage", "main").is_err()
        );
        assert!(validate_branch(PagesDeploymentEnvironmentV1::Production, "main", "main").is_ok());
    }

    #[test]
    fn old_catalog_or_archive_cannot_silently_gain_preview_authority() {
        let capability = CapabilityV1::new(
            super::pages_deployment::DIRECT_UPLOAD_CAPABILITY_ID,
            "Pages upload",
            "CLI",
            "wrangler pages deploy",
        );
        let mut input = CallInput {
            query: json!({"environment":"preview"}),
            ..CallInput::default()
        };
        assert!(requested(&capability, &input).is_err());
        input.query = json!({});
        assert_eq!(
            requested(&capability, &input).expect("legacy production default"),
            PagesDeploymentEnvironmentV1::Production
        );
        input.query = json!({"environment":null});
        assert!(requested(&capability, &input).is_err());
    }

    #[test]
    fn preview_requires_the_closed_selector_and_rejects_production_only_archive_proof() {
        let mut capability = CapabilityV1::new(
            super::pages_deployment::DIRECT_UPLOAD_CAPABILITY_ID,
            "Pages",
            "CLI",
            "wrangler pages deploy",
        );
        capability.adapter_status = cfctl_core::AdapterStatus::DelegatedCli;
        capability.selectors.push(SelectorV1 {
            name:"environment".to_owned(), location:"query".to_owned(), required:false,
            value_type:"string".to_owned(), description:None,
            contract:Some(SelectorContractV1 {schema:json!({"type":"string","enum":["production","preview"],"default":"production"}),query:None}),
        });
        let mut input = CallInput {
            query: json!({"environment":"preview"}),
            ..CallInput::default()
        };
        assert_eq!(
            requested(&capability, &input).expect("explicit preview"),
            PagesDeploymentEnvironmentV1::Preview
        );
        input.query["artifact_receipt"] = json!("sha256:archive");
        assert!(requested(&capability, &input).is_err());
        input.query = json!({"environment":"preview"});
        capability.selectors[0].required = true;
        assert!(requested(&capability, &input).is_err());
    }
}
