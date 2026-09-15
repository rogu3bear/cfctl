//! Reuse the existing pinned prior-state lifecycle for one targeted PATCH.
use super::prelude::{
    AuthCredential, CallInput, CapabilityV1, CatalogSnapshot, CliError, EvidenceClass, EvidenceV1,
    Executor, PlanV1, Result, StateStore, Value,
};
use cfctl_core::response_header_rule as rule;
fn rejected() -> CliError {
    CliError::Input("targeted response-header rule requires exact parent snapshot, supported policy and fresh plan".into())
}
pub(super) async fn read_prior(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    cap: &CapabilityV1,
    input: &CallInput,
    account: &str,
    credential: &AuthCredential,
) -> Result<(Value, EvidenceV1)> {
    if !rule::supported(cap)
        || !catalog.get(rule::READ_ID).is_some_and(|r| {
            r.method == "GET"
                && r.path == rule::READ_PATH
                && !r.mutating
                && r.adapter_status != cfctl_core::AdapterStatus::Blocked
        })
    {
        return Err(rejected());
    }
    let executor = Executor::new(
        super::support::private_capture_http_client()?,
        super::cloudflare_api::BASE_URL,
    )?
    .with_max_retries(0);
    let response = executor
        .read_response_header_parent(cap, input, credential)
        .await?;
    let receipt = rule::receipt(
        cap,
        &input.selectors,
        account,
        &response.result,
        input.body.as_ref().ok_or_else(rejected)?,
    )
    .map_err(|_| rejected())?;
    let evidence = store.write_observation_evidence(EvidenceClass::LiveRead, &receipt)?;
    Ok((receipt, evidence))
}
pub(super) fn restore_definition(plan: &PlanV1, receipt: &Value) -> Result<Value> {
    let input: CallInput = serde_json::from_value(plan.input.clone())?;
    let parent = rule::prior(
        plan,
        &input.selectors,
        input.body.as_ref().ok_or_else(rejected)?,
    )
    .map_err(|_| rejected())?;
    if receipt.get("prior_state") != Some(parent) {
        return Err(rejected());
    }
    rule::definition(rule::target(parent, &input.selectors).map_err(|_| rejected())?)
        .map_err(|_| rejected())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::{CallInput, CapabilityV1, PlanV1, rule};
    use cfctl_core::{
        AdapterStatus, EffectClass, ResponseBodyModeV1, ResponseContractV1, RiskClass,
        SamePathReadContractV1, SelectorV1, hash_value,
    };
    use serde_json::json;
    fn capability() -> CapabilityV1 {
        let mut cap = CapabilityV1::new(rule::ID, "Header rule", "PATCH", rule::PATH);
        cap.account_scope = "zone".into();
        cap.permissions = vec![
            "Zone Transform Rules Read".into(),
            "Zone Transform Rules Write".into(),
        ];
        cap.adapter_status = AdapterStatus::DynamicApi;
        cap.risk = RiskClass::CrossConfig;
        cap.effect = EffectClass::ReversibleWrite;
        cap.request_schema = Some(rule::request_schema());
        cap.verification.required = true;
        cap.verification.strategy = rule::VERIFY.into();
        cap.rollback.supported = true;
        cap.rollback.strategy = Some(rule::ROLLBACK.into());
        cap.same_path_read = Some(SamePathReadContractV1 {
            path: rule::READ_PATH.into(),
            read_capability_id: rule::READ_ID.into(),
            verified_response_fields: rule::FIELDS.map(str::to_owned).to_vec(),
        });
        cap.selectors = ["zone_id", "ruleset_id", "rule_id"]
            .map(|name| SelectorV1 {
                name: name.into(),
                location: "path".into(),
                required: true,
                value_type: "string".into(),
                description: None,
                contract: None,
            })
            .to_vec();
        cap.response_contract = Some(ResponseContractV1 {
            success_statuses: vec!["200".into()],
            success_media_types: vec!["application/json".into()],
            body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
        });
        cap
    }

    #[test]
    fn pinned_parent_drift_is_rejected_and_compensation_restores_only_target_fields() {
        let cap = capability();
        let selectors =
            json!({"zone_id":"a".repeat(32),"ruleset_id":"b".repeat(32),"rule_id":"c".repeat(32)});
        let body = json!({"action":"rewrite","action_parameters":{"headers":{"Cache-Control":{"operation":"set","value":"no-store"}}},"description":"policy","enabled":false,"expression":"true","ref":"ref"});
        let mut target = body.clone();
        target["id"] = selectors["rule_id"].clone();
        target["version"] = json!("5");
        target["enabled"] = json!(true);
        let parent = json!({"id":selectors["ruleset_id"],"kind":"zone","phase":"http_response_headers_transform","version":"11","rules":[target]});
        let input = CallInput {
            selectors,
            query: json!({}),
            body: Some(body),
            ..CallInput::default()
        };
        let receipt = rule::receipt(
            &cap,
            &input.selectors,
            &"e".repeat(32),
            &parent,
            input.body.as_ref().unwrap(),
        )
        .unwrap();
        let hash = hash_value(&receipt).unwrap();
        let mut plan = PlanV1::draft(
            "fixture",
            &"e".repeat(32),
            "catalog",
            cap,
            json!({"live_preconditions":{"same_path_prior_state":receipt}}),
        )
        .unwrap();
        plan.input = serde_json::to_value(&input).unwrap();
        plan.precondition_hashes
            .insert(rule::PRECONDITION.into(), hash.clone());
        assert!(
            super::super::live_state_contracts::should_bind_same_path_prior_state(&plan.capability)
        );
        assert_eq!(
            super::super::preconditions_extended::required_same_path_prior_state_precondition(
                &plan
            )
            .unwrap(),
            Some(hash.as_str())
        );
        let compensation =
            super::super::compensation::operation_specific_compensation_request(&plan)
                .unwrap()
                .unwrap();
        assert_eq!(compensation.capability_id, rule::ID);
        assert_eq!(compensation.expected_method, "PATCH");
        assert_eq!(compensation.input.body.as_ref().unwrap()["enabled"], true);
        assert_eq!(compensation.input.selectors, input.selectors);
        assert!(
            compensation
                .input
                .body
                .as_ref()
                .unwrap()
                .get("rules")
                .is_none()
        );
        let mut changed = receipt.clone();
        changed["prior_state"]["version"] = json!("12");
        assert!(super::super::preconditions_extended::validate_same_path_prior_state_receipt_precondition(&hash,&changed).is_err());
        plan.targets["live_preconditions"]["same_path_prior_state"] = changed;
        assert!(
            super::super::preconditions_extended::required_same_path_prior_state_precondition(
                &plan
            )
            .is_err()
        );
    }
}
