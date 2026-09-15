use cfctl_core::{
    AdapterStatus, CapabilityAuthorityScopeV1, CapabilityV1, EffectClass, RiskClass,
    d1_reconciliation::{DIAGNOSTIC_ID, RECONCILE_ID, STRATEGY},
};
use serde_json::json;

pub(super) fn capabilities() -> Vec<CapabilityV1> {
    let hash = json!({"type":"string","pattern":"^sha256:[0-9a-f]{64}$"});
    let uuid = json!({"type":"string","format":"uuid"});
    let bare_hash = json!({"type":"string","pattern":"^[0-9a-f]{64}$"});
    let git = json!({"type":"string","pattern":"^[0-9a-f]{40}$"});
    let mut reconcile = base(
        RECONCILE_ID,
        "Reconcile historical same-checkpoint D1 restore content",
    );
    reconcile.description = Some("Authenticate the original failed restore and three complete export identities, compare their present private SQL bytes, and bind a fresh release window. The original failed verification is immutable. This local proof grants no writes, changed-state rollback, application admission, or continuous closure across the historical gap.".into());
    reconcile.verification.required = true;
    reconcile.verification.strategy = STRATEGY.into();
    reconcile.request_schema = Some(json!({
        "type":"object","additionalProperties":false,"x-cfctl-body-required":true,
        "required":["restore_operation_id","historical_post_export_evidence_hash","current_export_evidence_hash","release_binding"],
        "properties":{
            "restore_operation_id":uuid,"historical_post_export_evidence_hash":hash,"current_export_evidence_hash":hash,
            "release_binding":{"type":"object","additionalProperties":false,
                "required":["commit","tree","deploy_artifact_digest","declaration_sha256","window"],
                "properties":{"commit":git,"tree":git,"deploy_artifact_digest":bare_hash,"declaration_sha256":bare_hash,
                    "window":{"type":"object","additionalProperties":false,"required":["window_id","opened_at","expires_at"],
                        "properties":{"window_id":uuid,"opened_at":{"type":"string","format":"date-time"},"expires_at":{"type":"string","format":"date-time"}}}}}
        }
    }));
    let mut diagnostic = base(
        DIAGNOSTIC_ID,
        "Diagnose one exact rejected registered D1 read",
    );
    diagnostic.description = Some("Authenticate a failed registered inventory observation and issue only its exact unchanged non-parameterized rejected query once under the current explicitly selected account/profile/generation. Requires a new private --out file for bounded provider diagnostic bytes. Output is diagnostic, never complete readiness proof; no arbitrary SQL, redirects, retries, or population replay.".into());
    diagnostic.account_scope = "account".into();
    diagnostic.permissions = vec!["D1 Read".into()];
    diagnostic.request_schema = Some(json!({
        "type":"object","additionalProperties":false,"x-cfctl-body-required":true,
        "required":["failed_evidence_hash","capability_id","query_id","expected_credential_generation_id"],
        "properties":{"failed_evidence_hash":hash,"capability_id":{"type":"string","minLength":1,"maxLength":200},
            "query_id":{"type":"string","minLength":1,"maxLength":200},"expected_credential_generation_id":uuid}
    }));
    vec![reconcile, diagnostic]
}

fn base(id: &str, title: &str) -> CapabilityV1 {
    let mut capability = CapabilityV1::new(id, title, "POST", &format!("/cfctl/d1/{id}"));
    capability.product = "D1".into();
    capability.source = "cfctl native governed D1 reconciliation".into();
    capability.account_scope = "local_authenticated_evidence".into();
    capability.authority_scope = Some(CapabilityAuthorityScopeV1::ProviderGeneric);
    capability.adapter_status = AdapterStatus::Native;
    capability.mutating = false;
    capability.risk = RiskClass::Read;
    capability.effect = EffectClass::ReadOnly;
    capability.entitlement.available = Some(true);
    capability
}
