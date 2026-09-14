//! Discoverable local reproduction and the explicit archive deployment input.
use super::{AdapterStatus, CapabilityV1, EffectClass, RiskClass, SelectorV1};
use cfctl_core::pages_artifact::PRODUCER_ID;
use serde_json::json;

#[must_use]
pub fn capability() -> CapabilityV1 {
    let mut cap = CapabilityV1::new(
        PRODUCER_ID,
        "Reproduce one immutable Pages artifact locally",
        "GET",
        "/cfctl/pages/artifact/reproduce",
    );
    cap.product = "Cloudflare Pages".into();
    cap.source = "cfctl native fixed Pages reproduction v1".into();
    cap.description = Some("Fresh local reproduction of the exact copy-public/esbuild 0.28.2 recipe from registered Git objects. Requires the admitted script/package/lock hashes, a local integrity-verified darwin-arm64 esbuild package, and complete retained artifact equality. Executes no repository script, dependency installer or provider request. Returns authenticated LocalProof; this does not authenticate a historical build or approve deployment. Supply its evidence hash as artifact_receipt to wrangler.pages-deploy. Other recipes/platforms fail closed.".into());
    cap.adapter_status = AdapterStatus::Native;
    cap.mutating = false;
    cap.risk = RiskClass::Read;
    cap.effect = EffectClass::ReadOnly;
    cap.blocked_reason = None;
    cap.permissions.clear();
    cap.entitlement.available = Some(true);
    cap.verification.required = true;
    cap.verification.strategy = "pages_fresh_reproduction_exact_manifest_v1".into();
    super::zero_direct_usage_cost(
        &mut cap,
        "local bounded reproduction only; no provider requests or dependency installation",
        vec![],
    );
    let names = [
        "repository",
        "commit",
        "tree",
        "account_id",
        "project_name",
        "branch",
        "artifact_directory",
        "artifact_manifest_sha256",
        "esbuild_package",
    ];
    let properties = names
        .iter()
        .map(|n| ((*n).to_owned(), json!({"type":"string","minLength":1})))
        .collect::<serde_json::Map<_, _>>();
    cap.request_schema = Some(
        json!({"type":"object", "additionalProperties":false, "required":names, "properties":properties}),
    );
    cap
}

pub(super) fn add_archive_selector(cap: &mut CapabilityV1) {
    cap.selectors.push(SelectorV1 {
        name: "artifact_receipt".into(), location: "query".into(), required: false,
        value_type: "string".into(), contract: None,
        description: Some("Authenticated pages-artifact-reproduce evidence hash. Explicit immutable mode; binds logical repository, exact commit/tree, production target and complete artifact independently of current checkout HEAD. Missing or unqualified proof is rejected.".into()),
    });
}
