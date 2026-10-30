use cfctl_core::{
    AdapterStatus, BillingModelV1, CapabilityAuthorityScopeV1, CapabilityV1, CostExposureV1,
    CostV1, EffectClass, EntitlementV1, Maturity, ReplyContainmentOperationV3, RiskClass,
    SelectorV1, WorkspaceD1ReplyContainmentContractV3,
};

use super::declaration::Operation;

pub(super) fn from_declaration(
    operation: &Operation,
    contract: WorkspaceD1ReplyContainmentContractV3,
) -> CapabilityV1 {
    let apply = contract.operation_kind == ReplyContainmentOperationV3::Apply;
    let mut capability = CapabilityV1::new(
        &operation.id,
        &operation.title,
        if apply { "POST" } else { "GET" },
        "workspace:maildesk-reply-containment-v3",
    );
    capability.description = Some(operation.description.clone());
    capability.authority_scope = Some(CapabilityAuthorityScopeV1::WorkspaceOwned);
    "workspace-operation-pack-v1".clone_into(&mut capability.source);
    "D1".clone_into(&mut capability.product);
    "account".clone_into(&mut capability.account_scope);
    capability.maturity = Maturity::Beta;
    capability.entitlement = EntitlementV1 {
        available: Some(true),
        source: Some(
            "requires the existing provider-read D1 database bound by the workspace contract"
                .into(),
        ),
        ..EntitlementV1::default()
    };
    capability.cost=CostV1{incremental:false,currency:None,maximum:None,basis:Some("fixed bounded D1 reads and containment row writes; usage is charged under the existing D1 plan".into()),known:true,billing_model:BillingModelV1::UsageBased,exposure:CostExposureV1::DownstreamUsage,references:Vec::new()};
    capability.selectors = ["account_id", "database_id", "config"]
        .into_iter()
        .chain(operation.parameters.iter().map(String::as_str))
        .map(|name| SelectorV1 {
            name: name.to_owned(),
            location: if name == "account_id" || name == "database_id" {
                "path"
            } else {
                "query"
            }
            .to_owned(),
            required: true,
            value_type: "string".to_owned(),
            description: None,
            contract: None,
        })
        .collect();
    capability.permissions = if apply {
        vec!["D1 Read".to_owned(), "D1 Write".to_owned()]
    } else {
        vec!["D1 Read".to_owned()]
    };
    capability.risk = if apply {
        RiskClass::IdentityOrOwnership
    } else {
        RiskClass::Read
    };
    capability.effect = if apply {
        EffectClass::IdentityOrOwnership
    } else {
        EffectClass::ReadOnly
    };
    capability.verification.required = true;
    match contract.operation_kind {
        ReplyContainmentOperationV3::PreRead => "workspace_d1_reply_containment_pre_read_v3",
        ReplyContainmentOperationV3::Apply => "workspace_d1_reply_containment_apply_v3",
        ReplyContainmentOperationV3::Read => "workspace_d1_reply_containment_readback_v3",
    }
    .clone_into(&mut capability.verification.strategy);
    capability.rollback.supported = false;
    capability.rollback.warning = Some("The atomic D1 import temporarily makes database queries unavailable. A consumed containment plan must not be replayed. Database restore requires separate authorization and preservation of accepted or unknown-send history.".to_owned());
    capability.execution_supported = true;
    capability.adapter_status = AdapterStatus::DelegatedCli;
    capability.blocked_reason = None;
    capability.workspace_d1_reply_admission = Some(contract.into());
    capability
}
