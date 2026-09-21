//! Bounded custom challenge expression update, separate from header rewrites.
use super::{
    CatalogSnapshot, official_reference, refresh_dynamic_mutation_contract, zero_direct_usage_cost,
};
use cfctl_core::{EffectClass, RiskClass, SamePathReadContractV1, custom_challenge_rule as rule};

pub(super) fn finalize(snapshot: &mut CatalogSnapshot) {
    if !snapshot
        .get(rule::READ_ID)
        .is_some_and(|c| c.method == "GET" && c.path == rule::READ_PATH && !c.mutating)
    {
        return;
    }
    let Some(mut cap) = snapshot.get(cfctl_core::response_header_rule::ID).cloned() else {
        return;
    };
    if cap.method != "PATCH" || cap.path != rule::PATH {
        return;
    }
    cap.id = rule::ID.into();
    cap.title = "Update only an existing custom challenge rule expression".into();
    cap.aliases = vec![
        "repair existing custom WAF challenge expression".into(),
        "correct a challenge on an API endpoint".into(),
    ];
    cap.risk = RiskClass::IdentityOrOwnership;
    cap.effect = EffectClass::ReversibleWrite;
    cap.permissions = vec!["Zone WAF Read".into(), "Zone WAF Write".into()];
    cap.request_schema = Some(rule::request_schema());
    cap.verification.required = true;
    cap.verification.strategy = rule::VERIFY.into();
    cap.rollback.supported = true;
    cap.rollback.strategy = Some(rule::ROLLBACK.into());
    cap.rollback.warning = Some("Exact security-plan approval required. Recovery drafts a separate expression-only plan from authenticated post-write readback and captured prior expression; later version/expression drift is rejected. Missing readback requires reconciliation, never replay. Full parent pre-read is not provider-atomic CAS; a race before PATCH remains possible and collateral drift fails verification.".into());
    cap.same_path_read = Some(SamePathReadContractV1 {
        path: rule::READ_PATH.into(),
        read_capability_id: rule::READ_ID.into(),
        verified_response_fields: vec!["expression".into()],
    });
    cap.description = Some("Change only the expression of one existing managed_challenge or js_challenge rule in a zone http_request_firewall_custom ruleset. Require expected current expression, complete supported authored definition, rule version and ruleset version. Capture/recheck the complete parent before PATCH; send that definition with only expression changed to Cloudflare. Verify exact expression, advancing versions, unchanged actions, enablement, other fields, rules and order. No creation, skip rule, action change, reordering, whole-ruleset replacement or automatic recovery.".into());
    zero_direct_usage_cost(
        &mut cap,
        "updating an existing custom rule expression creates no rule or plan entitlement; traffic volume and usage may change with the new matching expression and are not authorized as spend by this operation",
        vec![
            official_reference(
                "Update an existing rule",
                "https://developers.cloudflare.com/ruleset-engine/rulesets-api/update-rule/",
            ),
            official_reference(
                "Custom rules",
                "https://developers.cloudflare.com/waf/custom-rules/",
            ),
        ],
    );
    refresh_dynamic_mutation_contract(&mut cap);
    snapshot.capabilities.insert(cap.id.clone(), cap);
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
        let mut cap = CapabilityV1::new(
            cfctl_core::response_header_rule::ID,
            "Update rule",
            "PATCH",
            rule::PATH,
        );
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
        super::super::response_header_rule::finalize(&mut catalog);
        finalize(&mut catalog);
        let cap = catalog.get(rule::ID).expect("rule");
        assert!(
            cap.verification_contract_supported(),
            "{:?}",
            cap.mutation_contract_gaps()
        );
        assert!(cap.rollback_contract_supported());
        assert_eq!(cap.risk, RiskClass::IdentityOrOwnership);
        assert!(cfctl_core::response_header_rule::supported(
            catalog
                .get(cfctl_core::response_header_rule::ID)
                .expect("header stays bounded")
        ));
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
