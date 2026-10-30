use super::super::guide_generation::{argv, capability_call_argv};
use cfctl_core::{
    CapabilityV1, GuideActionV1, GuideStage, ReplyContainmentOperationV3 as Operation,
};

fn call(capability: &CapabilityV1, kind: Operation) -> Vec<String> {
    if capability
        .reply_containment_contract()
        .is_some_and(|c| c.operation_kind == kind)
    {
        let mut command = capability_call_argv(capability);
        if kind != Operation::Read {
            let label = if kind == Operation::Apply {
                "<mode-0600-request-with-pre-read-json>"
            } else {
                "<mode-0600-v3-request-json>"
            };
            if let Some(index) = command.iter().position(|arg| arg == "--source-file") {
                command[index + 1] = label.into();
            }
        }
        return command;
    }
    let mut command = argv(&[
        "cfctl",
        "call",
        kind.capability_id(),
        "--profile",
        "<profile>",
        "--account",
        "<account-id>",
        "--selector",
        "account_id=<account-id>",
        "--selector",
        "database_id=<database-id>",
        "--query",
        "config=<absolute-private-config-path>",
    ]);
    if kind == Operation::Read {
        for pair in [
            "containment_transaction_sha256=<transaction-hash>",
            "semantic_bundle_sha256=<bundle-hash>",
            "plan_content_hash=<PlanV2-content-hash>",
            "containment_operation_id=<operation-id>",
        ] {
            command.extend(["--query".into(), pair.into()]);
        }
    } else {
        command.extend(["--source-file".into(), "<mode-0600-v3-request-json>".into()]);
    }
    command.push("--json".into());
    command
}
pub(in crate::runtime) fn guide_next_action(
    capability: &CapabilityV1,
    ready: bool,
) -> Option<GuideActionV1> {
    let kind = capability.reply_containment_contract()?.operation_kind;
    if !ready {
        return None;
    }
    let (summary, next) = match kind {
        Operation::PreRead => (
            "Use the unchanged V3 locator request in a private file. Retain the successful native envelope exactly; its observed state is required to plan containment.",
            Operation::PreRead,
        ),
        Operation::Apply => (
            "First obtain the native containment pre-read and a fresh D1 recovery bookmark for the same profile, account, database, generation and catalog. Attach the unchanged pre-read envelope to the V3 request as pre_read, then use BuildPlan. Approval and execution remain separate.",
            Operation::PreRead,
        ),
        Operation::Read => (
            "Use the original approved, consumed plan and its bound transaction/bundle hashes. The stored wrapper is result; a successful complete post-read supplies replacement lineage, while ambiguity never authorizes replay.",
            Operation::Read,
        ),
    };
    Some(GuideActionV1 {
        summary: summary.into(),
        argv: call(capability, next),
    })
}
pub(in crate::runtime) fn guide_commands(
    stage: GuideStage,
    capability: &CapabilityV1,
    available: bool,
) -> Option<Vec<Vec<String>>> {
    let kind = capability.reply_containment_contract()?.operation_kind;
    let commands = match (kind, stage) {
        (Operation::Apply, GuideStage::InspectCurrentState) => vec![
            call(capability, Operation::PreRead),
            argv(&[
                "cfctl",
                "call",
                "d1-time-travel-get-bookmark",
                "--profile",
                "<profile>",
                "--account",
                "<account-id>",
                "--selector",
                "account_id=<account-id>",
                "--selector",
                "database_id=<database-id>",
                "--json",
            ]),
        ],
        (Operation::Apply, GuideStage::BuildPlan) => vec![call(capability, Operation::Apply)],
        (Operation::Apply, GuideStage::Verify | GuideStage::CloseWithEvidence) => vec![
            argv(&["cfctl", "plans", "status", "<operation-id>", "--json"]),
            call(capability, Operation::Read),
        ],
        (Operation::PreRead | Operation::Read, GuideStage::BuildPlan | GuideStage::Verify) => {
            Vec::new()
        }
        _ => return None,
    };
    Some(if available { commands } else { Vec::new() })
}
pub(in crate::runtime) fn guide_summary(
    stage: GuideStage,
    capability: &CapabilityV1,
) -> Option<String> {
    let kind = capability.reply_containment_contract()?.operation_kind;
    let text = match (kind, stage) {
        (Operation::Apply, GuideStage::InspectCurrentState) => {
            "Obtain the native pre-read envelope and the fresh recovery bookmark with identical profile/account/database/generation/catalog. The raw V3 request has locators only; the apply file adds that exact envelope as pre_read."
        }
        (Operation::Apply, GuideStage::BuildPlan) => {
            "Compile the private V3 request plus authenticated pre_read into an immutable PlanV2. No write occurs; review temporary D1 query unavailability and the separate explicit approval."
        }
        (Operation::Apply, GuideStage::Verify | GuideStage::CloseWithEvidence) => {
            "Read the original plan outcome, then obtain the separately stored native containment readback. Its result wrapper and authenticated storage hash supply future replacement lineage; never substitute a bundle or PlanV2 hash."
        }
        (Operation::PreRead, GuideStage::BuildPlan | GuideStage::Verify) => {
            "This read creates no mutation plan. Preserve the returned native envelope unchanged for the apply input; current state is observed rather than supplied by the caller."
        }
        (Operation::Read, GuideStage::BuildPlan | GuideStage::Verify) => {
            "This read creates no mutation plan. Inspect result.envelope and its distinct storage content_hash; incomplete or uncertain outcomes remain non-replayable."
        }
        _ => return None,
    };
    Some(text.into())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)] // Missing expected guide stages must fail the test.
    use super::Operation;
    use cfctl_core::{
        AdapterStatus, CapabilityAuthorityScopeV1, CapabilityV1, EffectClass, GuideContractStateV1,
        GuideStage, RiskClass,
    };
    #[test]
    fn all_three_guides_keep_inputs_and_proof_stages_distinct() {
        for kind in [Operation::PreRead, Operation::Apply, Operation::Read] {
            let mut contract = super::super::test_support::contract();
            contract.operation_kind = kind;
            let apply = kind == Operation::Apply;
            let mut cap = CapabilityV1::new(
                kind.capability_id(),
                "Containment",
                if apply { "POST" } else { "GET" },
                "workspace",
            );
            cap.authority_scope = Some(CapabilityAuthorityScopeV1::WorkspaceOwned);
            cap.adapter_status = AdapterStatus::DelegatedCli;
            cap.risk = if apply {
                RiskClass::IdentityOrOwnership
            } else {
                RiskClass::Read
            };
            cap.effect = if apply {
                EffectClass::IdentityOrOwnership
            } else {
                EffectClass::ReadOnly
            };
            cap.cost.known = true;
            cap.rollback.warning = Some("no automatic replay".into());
            cap.entitlement.available = Some(true);
            cap.verification.strategy = match kind {
                Operation::PreRead => "workspace_d1_reply_containment_pre_read_v3",
                Operation::Apply => "workspace_d1_reply_containment_apply_v3",
                Operation::Read => "workspace_d1_reply_containment_readback_v3",
            }
            .into();
            cap.workspace_d1_reply_admission = Some(contract.into());
            let guide = super::super::super::guide_generation::guide_document(&cap);
            assert_eq!(guide.contract_state, GuideContractStateV1::Available);
            let call = guide.call_argv.as_ref().expect("available call");
            assert!(!call.iter().any(|v| v == "--body-stdin"));
            assert_eq!(
                call.iter().any(|v| v == "--source-file"),
                kind != Operation::Read
            );
            if apply {
                let inspect = guide
                    .stages
                    .iter()
                    .find(|s| s.name == GuideStage::InspectCurrentState)
                    .expect("inspect stage");
                assert_eq!(inspect.commands.len(), 2);
                assert_eq!(inspect.commands[0][2], Operation::PreRead.capability_id());
                assert_eq!(inspect.commands[1][2], "d1-time-travel-get-bookmark");
                assert!(guide.next_action.summary.contains("pre_read"));
                let verify = guide
                    .stages
                    .iter()
                    .find(|s| s.name == GuideStage::Verify)
                    .expect("verify stage");
                assert_eq!(verify.commands[1][2], Operation::Read.capability_id());
            }
        }
    }
}
