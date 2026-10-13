use cfctl_core::{
    AdapterStatus, CapabilityAuthorityScopeV1, CapabilityV1, EffectClass, RiskClass,
    workspace_d1::transition::application::PRODUCER_ID,
};
use serde_json::json;

#[must_use]
pub fn proof_capability() -> CapabilityV1 {
    let mut capability = CapabilityV1::new(
        PRODUCER_ID,
        "Produce an authenticated native D1 transition proof",
        "POST",
        "/cfctl/d1/transition/proof",
    );
    capability.description = Some("Derive typed application verification, synthetic population, case, writer, poll or aggregate receipts from exact authenticated native plans, source and read evidence. Application verification closes only its pending native plan after every proof passes. Local only: no credential access, SQL, provider requests, plan approval, replay, or live capability enablement. Missing, drifted, incomplete and generic success receipts are refused.".into());
    capability.source = "cfctl native D1 transition evidence".into();
    capability.product = "D1".into();
    capability.account_scope = "local_authenticated_evidence".into();
    capability.authority_scope = Some(CapabilityAuthorityScopeV1::CfctlProduct);
    capability.adapter_status = AdapterStatus::Native;
    capability.mutating = false;
    capability.risk = RiskClass::Read;
    capability.effect = EffectClass::ReadOnly;
    capability.entitlement.available = Some(true);
    capability.request_schema = Some(json!({
        "type":"object","x-cfctl-body-required":true,
        "required":["action"],"properties":{"action":{"type":"string",
        "enum":["application","population","case","writer","poll","aggregate"]}}
    }));
    capability
}
