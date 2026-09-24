//! Qualify a secret-bearing read before it can enter the ordinary read lane.
use super::{AdapterStatus, BTreeMap, CapabilityV1, EffectClass, RiskClass, Value};
use cfctl_core::turnstile_secret as widget;

pub(super) fn finalize(document: &Value, capabilities: &mut BTreeMap<String, CapabilityV1>) {
    let Some(cap) = capabilities.get_mut(widget::ID) else {
        return;
    };
    cap.risk = RiskClass::SecretSensitive;
    let response =
        document.pointer("/paths/~1accounts~1{account_id}~1challenges~1widgets~1{sitekey}/get");
    if !widget::supported(cap)
        || !response.is_some_and(|op| {
            super::success_response_declares_result_fields(document, op, &["secret", "sitekey"])
        })
    {
        cap.adapter_status = AdapterStatus::Blocked;
        cap.blocked_reason = Some("Turnstile widget secret read contract drifted; requalify exact identity, permissions, selectors and secret-bearing response before reading".into());
        return;
    }
    cap.adapter_status = AdapterStatus::DynamicApi;
    cap.blocked_reason = None;
    cap.effect = EffectClass::ReadOnly;
    cap.verification.required = true;
    cap.verification.strategy = widget::VERIFY.into();
    cap.description = Some("Read one existing widget and write its current secret only to a new mode-0600 --value-out outside Git. Verify the returned sitekey; retain only non-secret outcome metadata in stdout and evidence. Does not rotate the secret.".into());
}
