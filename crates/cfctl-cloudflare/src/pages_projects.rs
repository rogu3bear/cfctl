//! Bounded Pages setup validation and exact native project readback.
use super::{
    AuthCredential, CallInput, CapabilityV1, CloudflareError, CloudflareResponseV1, Executor,
    OperationVerificationV1, PlanV1, Result, same_path_verification_capability,
};
use cfctl_core::{hash_value, pages_projects as contract};
use serde_json::{Value, json};

pub const STATE_PRECONDITION: &str = "pages_production_variables_state";

fn invalid(message: &str) -> CloudflareError {
    CloudflareError::InvalidRequestBody(message.to_owned())
}

fn valid_hash(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(cfctl_core::valid_sha256_identity)
}

pub(super) fn validate(capability: &CapabilityV1, input: &CallInput) -> Result<()> {
    if !matches!(
        capability.id.as_str(),
        contract::CREATE_ID | contract::VARIABLES_ID
    ) {
        return Ok(());
    }
    if !contract::contract_supported(capability)
        || !input
            .query
            .as_object()
            .is_some_and(serde_json::Map::is_empty)
        || input.if_match.is_some()
        || input.if_none_match.is_some()
    {
        return Err(invalid(
            "bounded Pages setup capability or request contract drifted",
        ));
    }
    let body = input
        .body
        .as_ref()
        .ok_or_else(|| invalid("Pages setup requires a body"))?;
    let name = if capability.id == contract::CREATE_ID {
        body.get("name").and_then(Value::as_str)
    } else {
        input.selectors.get("project_name").and_then(Value::as_str)
    };
    if !name.is_some_and(contract::valid_project_name) {
        return Err(invalid("Pages setup requires a valid exact project name"));
    }
    if capability.id == contract::VARIABLES_ID {
        variable_target(body)?;
    }
    Ok(())
}

/// Derived before protected input is replaced with its credential-store ref.
/// Only names, types and a commitment to the complete body become plan data.
pub fn variable_target(body: &Value) -> Result<Value> {
    let vars = contract::requested_variables(body)
        .filter(|vars| !vars.is_empty() && vars.len() <= 100)
        .ok_or_else(|| invalid("Pages variables require one bounded production env_vars object"))?;
    if vars.iter().any(|(name, entry)| {
        !contract::valid_variable_name(name)
            || !entry.as_object().is_some_and(|fields| {
                fields.len() == 2
                    && matches!(
                        entry.get("type").and_then(Value::as_str),
                        Some("plain_text" | "secret_text")
                    )
                    && entry
                        .get("value")
                        .and_then(Value::as_str)
                        .is_some_and(|value| !value.is_empty() && value.len() <= 5120)
            })
    }) {
        return Err(invalid(
            "Pages variables require valid names and nonempty typed string values; deletion and unknown fields are not admitted",
        ));
    }
    let names = vars
        .iter()
        .map(|(name, entry)| json!({"name":name,"type":entry["type"]}))
        .collect::<Vec<_>>();
    Ok(json!({"requested_variables":names,"body_hash":hash_value(body)?}))
}

pub fn variable_state_receipt(
    account_id: &str,
    project_name: &str,
    target: &Value,
    response: &CloudflareResponseV1,
) -> Result<Value> {
    let names = target
        .get("requested_variables")
        .and_then(Value::as_array)
        .filter(|names| !names.is_empty() && names.len() <= 100)
        .ok_or_else(|| invalid("Pages variable name/type target is missing"))?;
    if names.iter().any(|entry| {
        entry.as_object().is_none_or(|fields| fields.len() != 2)
            || !entry["name"]
                .as_str()
                .is_some_and(contract::valid_variable_name)
            || !matches!(entry["type"].as_str(), Some("plain_text" | "secret_text"))
    }) || names
        .iter()
        .filter_map(|entry| entry["name"].as_str())
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        != names.len()
        || target.as_object().is_none_or(|target| target.len() != 2)
        || !valid_hash(&target["body_hash"])
        || !response.success
        || !(200..300).contains(&response.status)
        || !response.errors.is_empty()
        || !contract::project_is_direct(&response.result, project_name)
    {
        return Err(invalid(
            "Pages variables need a successful exact direct-project read and a bound input target",
        ));
    }
    let production = response
        .result
        .pointer("/deployment_configs/production")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("Pages production configuration is not observable"))?;
    let current = production.get("env_vars");
    if current.is_some_and(|vars| !vars.is_object()) {
        return Err(invalid(
            "Pages production variable inventory is not an object",
        ));
    }
    if names.iter().any(|entry| {
        entry["name"]
            .as_str()
            .is_some_and(|name| current.is_some_and(|vars| vars.get(name).is_some()))
    }) {
        return Err(invalid(
            "a requested Pages production variable already exists; add-only setup cannot overwrite or delete it",
        ));
    }
    Ok(json!({
        "schema_version":1,"source_capability_id":contract::READ_ID,"source_path":contract::DETAIL,
        "target_capability_id":contract::VARIABLES_ID,"account_id":account_id,
        "project_name":project_name,"project_id":response.result["id"],
        "configuration_hash":contract::configuration_hash(&response.result, &[])?,
        "input_target":target,
    }))
}

/// Validate the reviewed join even when called outside the CLI's live reader.
pub fn validate_variable_plan_state<'a>(plan: &'a PlanV1, input: &CallInput) -> Result<&'a Value> {
    let receipt = plan
        .targets
        .pointer("/live_preconditions/pages_production_variables_state")
        .ok_or_else(|| invalid("Pages variable plan omitted its project state receipt"))?;
    let expected = plan
        .precondition_hashes
        .get(STATE_PRECONDITION)
        .ok_or_else(|| invalid("Pages variable plan omitted its project state hash"))?;
    let body = input
        .body
        .as_ref()
        .ok_or_else(|| invalid("Pages variable input is absent"))?;
    let target = variable_target(body)?;
    let exact = receipt.as_object().is_some_and(|fields| fields.len() == 9)
        && receipt["schema_version"] == 1
        && receipt["source_capability_id"] == contract::READ_ID
        && receipt["source_path"] == contract::DETAIL
        && receipt["target_capability_id"] == contract::VARIABLES_ID
        && receipt["account_id"] == plan.account_id
        && receipt.get("project_name") == input.selectors.get("project_name")
        && receipt["project_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty())
        && valid_hash(&receipt["configuration_hash"])
        && receipt["input_target"] == target
        && plan.targets.pointer("/adapter/pages_production_variables") == Some(&target)
        && hash_value(receipt)? == *expected;
    if !exact {
        return Err(invalid(
            "Pages variable plan state, identity or protected input commitment drifted",
        ));
    }
    Ok(receipt)
}

fn accepted(response: &CloudflareResponseV1) -> bool {
    response.success && (200..300).contains(&response.status) && response.errors.is_empty()
}

fn projected(response: &CloudflareResponseV1) -> CloudflareResponseV1 {
    let mut response = response.clone();
    response.result = contract::redact_response(&response.result);
    response.result_info = response.result_info.as_ref().map(contract::redact_response);
    for error in &mut response.errors {
        "[REDACTED]".clone_into(&mut error.message);
    }
    response
}

impl Executor {
    pub(super) async fn verify_pages_setup(
        &self,
        plan: &PlanV1,
        apply: &CloudflareResponseV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<OperationVerificationV1> {
        validate(&plan.capability, input)?;
        let creating = plan.capability.id == contract::CREATE_ID;
        let state = if creating {
            None
        } else {
            Some(validate_variable_plan_state(plan, input)?)
        };
        let name = if creating {
            input.body.as_ref().and_then(|body| body.get("name"))
        } else {
            input.selectors.get("project_name")
        }
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("Pages project name is absent"))?;
        let applied_identity = accepted(apply)
            && contract::project_is_direct(&apply.result, name)
            && state.is_none_or(|state| apply.result["id"] == state["project_id"]);
        if !applied_identity {
            return Ok(OperationVerificationV1 {
                strategy: plan.capability.verification.strategy.clone(), passed:false,
                basis:"Pages setup response did not prove the exact accepted project identity and direct-upload configuration".to_owned(),
                readback: projected(apply), correlated_resource_id: None,
            });
        }
        let details = same_path_verification_capability(
            &plan.capability,
            contract::READ_ID,
            "Pages setup exact project verification",
            contract::DETAIL,
        );
        let request = self.builder.build(
            &details,
            &CallInput {
                selectors: json!({"account_id":plan.account_id,"project_name":name}),
                query: json!({}),
                ..CallInput::default()
            },
        )?;
        let readback = self.send(&request, credential).await?;
        let same_identity = accepted(&readback)
            && contract::project_is_direct(&readback.result, name)
            && readback.result["id"] == apply.result["id"];
        let (passed, basis) = if creating {
            (
                same_identity,
                "the accepted project ID, exact name and main branch match native GET with no Git source or build configuration",
            )
        } else {
            let state = state.ok_or_else(|| invalid("Pages variable state is absent"))?;
            let vars = input
                .body
                .as_ref()
                .and_then(contract::requested_variables)
                .ok_or_else(|| invalid("Pages variable body is absent"))?;
            let added = vars.keys().cloned().collect::<Vec<_>>();
            let preserved = contract::configuration_hash(&readback.result, &added)?
                == state["configuration_hash"];
            let matched = vars.iter().all(|(name, expected)| {
                readback
                    .result
                    .pointer("/deployment_configs/production/env_vars")
                    .and_then(|current| current.get(name))
                    .is_some_and(|current| {
                        current.get("type") == expected.get("type")
                            && (expected["type"] == "secret_text"
                                || current.get("value") == expected.get("value"))
                    })
            });
            (
                same_identity && preserved && matched,
                "provider acceptance and native project GET confirm added names/types, exact plain-text values and unchanged sibling configuration; secret values are write-only and application usability is not established",
            )
        };
        Ok(OperationVerificationV1 {
            strategy: plan.capability.verification.strategy.clone(),
            passed,
            basis: if passed {
                basis.to_owned()
            } else {
                "Pages setup verification failed: project identity, added variables or preserved configuration did not match the reviewed operation".to_owned()
            },
            readback: projected(&readback),
            correlated_resource_id: None,
        })
    }
}
