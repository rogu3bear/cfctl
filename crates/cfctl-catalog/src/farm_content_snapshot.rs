//! Farm's narrowly pinned private snapshot reader.
use super::{AdapterStatus, CapabilityV1, EffectClass, RiskClass};
use cfctl_core::farm_content_snapshot::{ACCOUNT_ID, CAPABILITY_ID, DATABASE_ID};

#[must_use]
pub fn capability() -> CapabilityV1 {
    let mut cap = CapabilityV1::new(
        CAPABILITY_ID,
        "Read Farm content and complete revision provenance privately",
        "GET",
        "/cfctl/farm/content-provenance-snapshot",
    );
    cap.product = "Cloudflare D1".into();
    cap.account_scope = "account".into();
    cap.source = "cfctl native fixed Farm snapshot v1".into();
    cap.description = Some(format!(
        "Read only site_content and site_content_revisions in account {ACCOUNT_ID}, database {DATABASE_ID}. Requires an explicit account-matched API-token profile with D1 Read and --out <new-file> in an owned mode-0700 directory. Output is mode-0600; stdout/evidence retain metadata and content hash only. One fixed SQL statement provides a consistent snapshot, current CAS version and ordered complete history. Maximum 1000 revisions, 8 MiB provider response and 15 seconds; overflow, gaps, malformed data or truncation fail closed without a completed snapshot. No caller SQL, selectors, query controls, body, pagination, retry or database write. Client limits do not guarantee a hard provider scan or currency ceiling."
    ));
    cap.adapter_status = AdapterStatus::Native;
    cap.mutating = false;
    cap.risk = RiskClass::Read;
    cap.effect = EffectClass::ReadOnly;
    cap.blocked_reason = None;
    cap.permissions = vec!["D1 Read".into()];
    cap.entitlement.available = Some(true);
    cap.verification.required = true;
    cap.verification.strategy = "farm_complete_private_snapshot_v1".into();
    cap
}
