//! Native Pages variable admission. Values stay in the existing protected input store.
use super::cloudflare_api::BASE_URL as API_BASE_URL;
use super::prelude::{
    AdapterStatus, AuthCredential, CallInput, CapabilityV1, CatalogSnapshot, CliError,
    EvidenceClass, EvidenceV1, Executor, PlanV1, Result, StateStore, Value, json,
};
use super::support::{capability_missing, http_client};
use cfctl_cloudflare::pages_projects::{validate_variable_plan_state, variable_state_receipt};
use cfctl_core::{hash_value, pages_projects as contract};

pub(super) use cfctl_cloudflare::pages_projects::STATE_PRECONDITION;

pub(super) fn applies(capability: &CapabilityV1) -> bool {
    capability.id == contract::VARIABLES_ID
}

pub(super) fn persist_ambiguous_response(
    store: &StateStore,
    plan: &mut PlanV1,
    response: &super::prelude::CloudflareResponseV1,
) -> Result<Option<super::api_boundary::ApiVerificationOutcome>> {
    if !matches!(
        plan.capability.id.as_str(),
        contract::CREATE_ID | contract::VARIABLES_ID
    ) || response.success
        || !(response.status == 429 || response.status >= 500)
    {
        return Ok(None);
    }
    plan.status = super::prelude::PlanStatus::RectificationRequired;
    super::plan_commands::persist_transaction_stage(
        store,
        plan,
        super::prelude::TransactionStageV1::VerificationAttemptPersisted,
    )?;
    let outcome = super::api_boundary::ApiVerificationOutcome {
        state: super::prelude::VerificationState::Pending,
        basis: format!(
            "Cloudflare returned HTTP {} after the one permitted Pages setup attempt; the remote outcome is unknown and requires exact-project GET rectification without replay",
            response.status
        ),
        evidence: None,
        error: Some(super::prelude::ErrorV1 {
            code: "CFCTL_PAGES_SETUP_OUTCOME_AMBIGUOUS".to_owned(),
            message:
                "The Pages setup response does not prove whether the project change was committed"
                    .to_owned(),
            next_step: Some(format!(
                "Inspect `cfctl plans rectify {}` and the exact project with native GET; never replay this plan.",
                plan.operation_id
            )),
        }),
        correlated_resource_id: None,
    };
    super::plan_commands::persist_transaction_stage_with_artifact(
        store,
        plan,
        super::prelude::TransactionStageV1::VerificationResponsePersisted,
        super::api_boundary::verification_response_artifact(&outcome)?,
    )?;
    Ok(Some(outcome))
}

pub(super) async fn prepare(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    adapter: &Value,
    account_id: &str,
    credential: Option<&AuthCredential>,
) -> Result<Option<(Value, EvidenceV1)>> {
    if !applies(capability) {
        return Ok(None);
    }
    if !contract::contract_supported(capability)
        || input.selectors.get("account_id").and_then(Value::as_str) != Some(account_id)
    {
        return Err(CliError::Input(
            "Pages variable setup identity drifted".to_owned(),
        ));
    }
    let target = adapter.get("pages_production_variables").ok_or_else(|| {
        CliError::Input("Pages variable setup requires a protected input target".to_owned())
    })?;
    if adapter.get("secret_body_hash") != target.get("body_hash")
        || adapter
            .get("secret_body_ref")
            .and_then(Value::as_str)
            .is_none()
    {
        return Err(CliError::Input(
            "Pages variable input must be bound to its protected body reference and hash"
                .to_owned(),
        ));
    }
    let name = input
        .selectors
        .get("project_name")
        .and_then(Value::as_str)
        .filter(|name| contract::valid_project_name(name))
        .ok_or_else(|| {
            CliError::Input("Pages variable setup requires an exact project name".to_owned())
        })?;
    let source = catalog
        .get(contract::READ_ID)
        .ok_or_else(|| capability_missing(contract::READ_ID))?;
    if source.method != "GET"
        || source.path != contract::DETAIL
        || source.mutating
        || !matches!(
            source.adapter_status,
            AdapterStatus::Native | AdapterStatus::DynamicApi
        )
        || source.account_scope != "account"
        || source.product != "Pages Project"
    {
        return Err(CliError::Input(
            "Pages variable setup read contract drifted".to_owned(),
        ));
    }
    let credential = credential.ok_or_else(|| {
        CliError::Input("Pages variable setup needs scoped credentials".to_owned())
    })?;
    let response = Executor::new(http_client()?, API_BASE_URL)?
        .execute_read(
            source,
            &CallInput {
                selectors: json!({"account_id":account_id,"project_name":name}),
                query: json!({}),
                ..CallInput::default()
            },
            credential,
        )
        .await?;
    let receipt = variable_state_receipt(account_id, name, target, &response)?;
    let evidence = store.write_observation_evidence(EvidenceClass::LiveRead, &receipt)?;
    Ok(Some((receipt, evidence)))
}

pub(super) async fn validate_live(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    plan: &PlanV1,
    input: &CallInput,
    credential: &AuthCredential,
) -> Result<Option<EvidenceV1>> {
    if !applies(&plan.capability) {
        return Ok(None);
    }
    cfctl_cloudflare::validate_request_contract(&plan.capability, input)?;
    let receipt = validate_variable_plan_state(plan, input)?;
    let (fresh, evidence) = prepare(
        store,
        catalog,
        &plan.capability,
        input,
        plan.targets.get("adapter").unwrap_or(&Value::Null),
        &plan.account_id,
        Some(credential),
    )
    .await?
    .ok_or_else(|| CliError::Input("Pages variable state is missing".to_owned()))?;
    if hash_value(&fresh)? != hash_value(receipt)? {
        return Err(CliError::Input("Pages project or configuration changed after planning; the mutation boundary was not crossed".to_owned()));
    }
    Ok(Some(evidence))
}
