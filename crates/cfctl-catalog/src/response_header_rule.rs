//! Enable only the executable targeted response-header rule correction contract.
use super::{
    CatalogSnapshot, official_reference, refresh_dynamic_mutation_contract, zero_direct_usage_cost,
};
use cfctl_core::{EffectClass, RiskClass, SamePathReadContractV1, response_header_rule as rule};
pub(super) fn finalize(snapshot: &mut CatalogSnapshot) {
    if !snapshot
        .get(rule::READ_ID)
        .is_some_and(|cap| cap.method == "GET" && cap.path == rule::READ_PATH && !cap.mutating)
    {
        return;
    }
    let Some(cap) = snapshot.capabilities.get_mut(rule::ID) else {
        return;
    };
    if cap.method != "PATCH" || cap.path != rule::PATH {
        return;
    }
    cap.selectors.retain(|s| s.location == "path");
    cap.risk = RiskClass::CrossConfig;
    cap.effect = EffectClass::ReversibleWrite;
    cap.permissions = vec![
        "Zone Transform Rules Read".into(),
        "Zone Transform Rules Write".into(),
    ];
    cap.request_schema = Some(rule::request_schema());
    cap.verification.required = true;
    cap.verification.strategy = rule::VERIFY.into();
    cap.rollback.supported = true;
    cap.rollback.strategy = Some(rule::ROLLBACK.into());
    cap.rollback.warning = Some("Security and cache policy changes require exact approval. Recovery creates a separate approved PATCH from the captured prior rule definition; it never replays the consumed operation or restores the whole ruleset. A pre-write snapshot comparison is not provider-atomic CAS; observed post-write collateral drift remains rectification required.".into());
    cap.same_path_read = Some(SamePathReadContractV1 {
        path: rule::READ_PATH.into(),
        read_capability_id: rule::READ_ID.into(),
        verified_response_fields: rule::FIELDS.map(str::to_owned).to_vec(),
    });
    cap.description = Some("Update only enabled/expression on an existing zone response-header rewrite rule. Submit all six authored fields unchanged except those two. Captures and rechecks the complete parent/version before PATCH, then reads the parent to prove the exact rule plus unchanged unrelated fields, rules and order. No position, dry_run, header-definition edit, other phase, broad replacement or automatic recovery.".into());
    zero_direct_usage_cost(
        cap,
        "editing an existing response-header transform rule has no incremental plan/configuration charge; this does not create rules, change plan entitlements, or authorize traffic usage",
        vec![
            official_reference(
                "Response Header Transform Rules",
                "https://developers.cloudflare.com/rules/transform/response-header-modification/",
            ),
            official_reference(
                "Update an existing rule",
                "https://developers.cloudflare.com/ruleset-engine/rulesets-api/update-rule/",
            ),
        ],
    );
    refresh_dynamic_mutation_contract(cap);
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;
    use cfctl_core::{
        AdapterStatus, CapabilityV1, ResponseBodyModeV1, ResponseContractV1, SelectorV1,
    };
    use std::collections::BTreeMap;
    #[test]
    fn admits_only_closed_patch_with_executable_verification_and_compensation() {
        let mut cap = CapabilityV1::new(rule::ID, "Update rule", "PATCH", rule::PATH);
        cap.account_scope = "zone".into();
        cap.adapter_status = AdapterStatus::DynamicApi;
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
        let read = CapabilityV1::new(rule::READ_ID, "Read", "GET", rule::READ_PATH);
        let mut catalog = CatalogSnapshot {
            schema_version: 1,
            generated_at: chrono::Utc::now(),
            source_url: "fixture".into(),
            source_hash: String::new(),
            schema_hash: String::new(),
            capabilities: BTreeMap::from([(cap.id.clone(), cap), (read.id.clone(), read)]),
        };
        finalize(&mut catalog);
        let cap = catalog.get(rule::ID).expect("rule");
        assert!(
            cap.verification_contract_supported(),
            "{:?}",
            cap.mutation_contract_gaps()
        );
        assert!(cap.rollback_contract_supported());
        assert_eq!(
            cap.adapter_status,
            AdapterStatus::DynamicApi,
            "{:?}",
            cap.blocked_reason
        );
        assert_eq!(cap.request_schema, Some(rule::request_schema()));
        let mut wrong = cap.clone();
        wrong.method = "PUT".into();
        assert!(!wrong.verification_contract_supported());
    }
}
