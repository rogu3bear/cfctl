//! Reuse the existing pinned prior-state lifecycle for one targeted PATCH.
use super::prelude::{
    AuthCredential, CallInput, CapabilityV1, CatalogSnapshot, CliError, EvidenceClass, EvidenceV1,
    Executor, PlanV1, Result, StateStore, Value,
};
use cfctl_core::custom_challenge_rule as rule;
fn rejected() -> CliError {
    CliError::Input("custom challenge expression requires exact parent snapshot and authenticated apply/readback evidence; inspect live state and reconcile missing or drifted evidence without replay".into())
}
pub(super) fn needs_reconciliation(
    plan: &PlanV1,
    response: &cfctl_cloudflare::CloudflareResponseV1,
) -> bool {
    plan.capability.id == rule::ID
        && !response.success
        && (response.status == 429 || response.status >= 500)
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
        .read_custom_challenge_parent(cap, input, credential)
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
pub(super) fn validate_receipt(plan: &PlanV1, receipt: &Value) -> Result<Value> {
    let input: CallInput = serde_json::from_value(plan.input.clone())?;
    let body = input.body.as_ref().ok_or_else(rejected)?;
    let parent = rule::prior(plan, &input.selectors, body).map_err(|_| rejected())?;
    if receipt.get("prior_state") != Some(parent) {
        return Err(rejected());
    }
    Ok(body.clone())
}

pub(super) fn compensation(
    store: &StateStore,
    plan: &PlanV1,
) -> Result<Option<super::compensation::CompensationRequest>> {
    use super::prelude::{OperationVerificationV1, PlanStatus, TransactionStageV1};
    if !matches!(
        plan.status,
        PlanStatus::Consumed | PlanStatus::Running | PlanStatus::RectificationRequired
    ) {
        return Ok(None);
    }
    if !rule::supported(&plan.capability) {
        return Err(rejected());
    }
    let boundary = plan
        .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
        .ok_or_else(rejected)?;
    if boundary["success"] != true || boundary["http_status"] != 200 {
        return Err(rejected());
    }
    let hash = boundary["apply_evidence_hash"]
        .as_str()
        .ok_or_else(rejected)?;
    let (evidence, value) = store.load_evidence_value(hash)?;
    if evidence.class != EvidenceClass::Apply {
        return Err(rejected());
    }
    let applied: cfctl_cloudflare::CloudflareResponseV1 = serde_json::from_value(value)?;
    if !applied.success || applied.status != 200 || !applied.errors.is_empty() {
        return Err(rejected());
    }
    let reference = plan
        .transaction_artifact(TransactionStageV1::VerificationResponsePersisted)
        .ok_or_else(rejected)?;
    let hash = reference["evidence_hash"].as_str().ok_or_else(rejected)?;
    let (evidence, value) = store.load_evidence_value(hash)?;
    if evidence.class != EvidenceClass::PostChangeVerification {
        return Err(rejected());
    }
    let verification: OperationVerificationV1 = serde_json::from_value(value)?;
    if verification.strategy != rule::VERIFY
        || !verification.readback.success
        || verification.readback.status != 200
        || !verification.readback.errors.is_empty()
    {
        return Err(rejected());
    }
    let input: CallInput = serde_json::from_value(plan.input.clone())?;
    let body = input.body.as_ref().ok_or_else(rejected)?;
    let before = rule::prior(plan, &input.selectors, body).map_err(|_| rejected())?;
    let restore = rule::recovery_body(
        before,
        &applied.result,
        &verification.readback.result,
        &input.selectors,
        body,
    )
    .map_err(|_| rejected())?;
    Ok(Some(super::compensation::CompensationRequest {
        capability_id: rule::ID.into(),
        expected_method: "PATCH".into(),
        expected_path: rule::PATH.into(),
        input: CallInput {
            selectors: input.selectors,
            query: serde_json::json!({}),
            body: Some(restore),
            ..CallInput::default()
        },
        requested_account: Some(plan.account_id.clone()),
        adapter_targets: serde_json::json!({}),
    }))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::compensation;
    use crate::runtime::prelude::{
        CallInput, CapabilityV1, EvidenceClass, PlanV1, StateStore, Value,
    };
    use cfctl_cloudflare::{CloudflareResponseV1, OperationVerificationV1};
    use cfctl_core::{
        AdapterStatus, EffectClass, PlanStatus, ResponseBodyModeV1, ResponseContractV1, RiskClass,
        SamePathReadContractV1, SelectorV1, TransactionStageV1, custom_challenge_rule as rule,
        hash_value,
    };
    use serde_json::json;
    fn capability() -> CapabilityV1 {
        let mut cap = CapabilityV1::new(rule::ID, "Header rule", "PATCH", rule::PATH);
        cap.account_scope = "zone".into();
        cap.permissions = vec!["Zone WAF Read".into(), "Zone WAF Write".into()];
        cap.adapter_status = AdapterStatus::DynamicApi;
        cap.risk = RiskClass::IdentityOrOwnership;
        cap.effect = EffectClass::ReversibleWrite;
        cap.request_schema = Some(rule::request_schema());
        cap.verification.required = true;
        cap.verification.strategy = rule::VERIFY.into();
        cap.rollback.supported = true;
        cap.rollback.strategy = Some(rule::ROLLBACK.into());
        cap.same_path_read = Some(SamePathReadContractV1 {
            path: rule::READ_PATH.into(),
            read_capability_id: rule::READ_ID.into(),
            verified_response_fields: vec!["expression".into()],
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

    pub(super) fn fixture() -> (PlanV1, Value) {
        let selectors =
            json!({"zone_id":"a".repeat(32),"ruleset_id":"b".repeat(32),"rule_id":"c".repeat(32)});
        let definition = json!({"action":"managed_challenge","expression":"true","enabled":true,"description":"entry wall","ref":"wall"});
        let mut target = definition.clone();
        target["id"] = selectors["rule_id"].clone();
        target["version"] = json!("11");
        let before = json!({"id":selectors["ruleset_id"],"kind":"zone","phase":"http_request_firewall_custom","version":"14","rules":[target,{"id":"d".repeat(32),"action":"block","version":"3"}]});
        let body = json!({"expression":"false","expected_expression":"true","expected_rule_version":"11","expected_ruleset_version":"14","expected_definition":definition});
        let receipt =
            rule::receipt(&capability(), &selectors, &"e".repeat(32), &before, &body).unwrap();
        let mut plan = PlanV1::draft(
            "fixture",
            &"e".repeat(32),
            "catalog",
            capability(),
            json!({"live_preconditions":{"same_path_prior_state":receipt}}),
        )
        .unwrap();
        plan.input = serde_json::to_value(CallInput {
            selectors,
            query: json!({}),
            body: Some(body),
            ..CallInput::default()
        })
        .unwrap();
        plan.precondition_hashes
            .insert(rule::PRECONDITION.into(), hash_value(&receipt).unwrap());
        let mut after = before;
        after["version"] = json!("15");
        after["rules"][0]["version"] = json!("12");
        after["rules"][0]["expression"] = json!("false");
        (plan, after)
    }
    fn response(result: Value) -> CloudflareResponseV1 {
        CloudflareResponseV1 {
            status: 200,
            success: true,
            result,
            errors: vec![],
            result_info: None,
            etag: None,
            cf_ray: None,
        }
    }
    #[test]
    fn pre_execution_snapshot_is_required_and_every_parent_change_invalidates_it() {
        let (mut plan, _) = fixture();
        let expected = plan.precondition_hashes[rule::PRECONDITION].clone();
        assert_eq!(
            super::super::preconditions_extended::required_same_path_prior_state_precondition(
                &plan
            )
            .unwrap(),
            Some(expected.as_str())
        );
        assert!(
            super::super::compensation::operation_specific_compensation_request(&plan).is_err()
        );
        let mut changed = plan.targets["live_preconditions"][rule::PRECONDITION].clone();
        changed["prior_state"]["rules"][1]["action"] = json!("skip");
        assert!(super::super::preconditions_extended::validate_same_path_prior_state_receipt_precondition(&expected,&changed).is_err());
        plan.targets["live_preconditions"][rule::PRECONDITION] = changed;
        assert!(
            super::super::preconditions_extended::required_same_path_prior_state_precondition(
                &plan
            )
            .is_err()
        );
    }
    #[test]
    fn recovery_requires_apply_and_readback_evidence_and_returns_an_unapproved_inverse() {
        use cfctl_auth::{EvidenceKeyManager, MemorySecretStore, SecretBackend};
        use std::sync::Arc;
        let root =
            tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
        let initial =
            StateStore::open(cfctl_storage::RuntimePaths::from_root(root.path())).unwrap();
        let manager = Arc::new(
            EvidenceKeyManager::new(
                Arc::new(MemorySecretStore::default()),
                initial.evidence_location_identity(),
                SecretBackend::Memory,
            )
            .unwrap(),
        );
        let identity = format!("sha256:{}", "a".repeat(64));
        manager.initialize(&identity).unwrap();
        initial
            .initialize_evidence_root_identity(&identity)
            .unwrap();
        let store = initial.with_evidence_authenticator(manager).unwrap();
        let (mut plan, after) = fixture();
        plan.status = PlanStatus::RectificationRequired;
        assert!(compensation(&store, &plan).is_err());
        let apply = store
            .write_observation_evidence(
                EvidenceClass::Apply,
                &serde_json::to_value(response(after.clone())).unwrap(),
            )
            .unwrap();
        plan.transaction_artifacts.insert(
            TransactionStageV1::BoundaryResponsePersisted
                .as_str()
                .into(),
            json!({"success":true,"http_status":200,"apply_evidence_hash":apply.content_hash}),
        );
        assert!(compensation(&store, &plan).is_err());
        let verification = OperationVerificationV1 {
            strategy: rule::VERIFY.into(),
            passed: false,
            basis: "other rule drift".into(),
            readback: response(after.clone()),
            correlated_resource_id: None,
        };
        let evidence = store
            .write_observation_evidence(
                EvidenceClass::PostChangeVerification,
                &serde_json::to_value(&verification).unwrap(),
            )
            .unwrap();
        plan.transaction_artifacts.insert(
            TransactionStageV1::VerificationResponsePersisted
                .as_str()
                .into(),
            json!({"evidence_hash":evidence.content_hash}),
        );
        let inverse = compensation(&store, &plan).unwrap().unwrap();
        assert_eq!(inverse.capability_id, rule::ID);
        assert_eq!(inverse.input.body.as_ref().unwrap()["expression"], "true");
        assert_eq!(
            inverse.input.body.as_ref().unwrap()["expected_rule_version"],
            "12"
        );
        assert_eq!(plan.status, PlanStatus::RectificationRequired);
        let mut later = verification;
        later.readback.result["rules"][0]["version"] = json!("13");
        let evidence = store
            .write_observation_evidence(
                EvidenceClass::PostChangeVerification,
                &serde_json::to_value(&later).unwrap(),
            )
            .unwrap();
        plan.transaction_artifacts.insert(
            TransactionStageV1::VerificationResponsePersisted
                .as_str()
                .into(),
            json!({"evidence_hash":evidence.content_hash}),
        );
        assert!(compensation(&store, &plan).is_err());
        plan.transaction_artifacts.insert(
            TransactionStageV1::VerificationResponsePersisted
                .as_str()
                .into(),
            json!({"evidence_hash":apply.content_hash}),
        );
        assert!(compensation(&store, &plan).is_err());
    }
}

#[cfg(test)]
mod ambiguity_tests;
