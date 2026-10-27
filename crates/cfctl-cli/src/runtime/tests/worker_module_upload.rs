use super::*;

#[test]
fn worker_module_upload_guide_names_transport_before_pricing() {
    let mut cap = CapabilityV1::new(
        cfctl_core::worker_module_upload::ID,
        "Upload Worker Module",
        "PUT",
        "/accounts/{account_id}/workers/scripts/{script_name}",
    );
    cap.adapter_status = AdapterStatus::DynamicApi;
    cap.risk = RiskClass::CrossConfig;
    cap.effect = EffectClass::ReversibleWrite;
    cap.cost.known = false;
    cap.verification.required = true;
    cap.verification.strategy = "worker_script_settings_id_matches_upload_response".into();
    let guide = guide_document(&cap);
    assert!(guide.call_argv.is_none());
    assert_eq!(
        guide.contract_state,
        cfctl_core::GuideContractStateV1::Blocked
    );
    assert!(guide.next_action.argv.is_empty());
    assert!(guide.next_action.summary.contains("multipart"));
    assert!(
        guide
            .next_action
            .summary
            .contains("uncertain-write recovery")
    );
    assert!(guide.next_action.summary.contains("Pricing lookup"));
}
