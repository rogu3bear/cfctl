//! Exact helper-backed Pages deployment discovery.
use super::{
    CatalogSnapshot, PAGES_DEPLOYMENT_DELETE_CAPABILITY_ID, PAGES_DEPLOYMENT_DETAIL_PATH,
    PAGES_DEPLOYMENT_READ_CAPABILITY_ID, pages_artifact,
};
use cfctl_core::{
    AdapterStatus, BillingModelV1, CapabilityV1, CostExposureV1, CreatedResourceContractV1,
    EffectClass, KnowledgeReferenceV1, RiskClass, SelectorContractV1, SelectorV1,
};

/// Add the exact Wrangler Pages upload command only when the installed
/// Wrangler help proves that command and every selector cfctl relies on are
/// present. The top-level Wrangler help exposes only the aggregate `pages`
/// command, which is not specific enough to govern a deployment.
#[expect(
    clippy::too_many_lines,
    reason = "one helper-backed capability owns its cost, selectors, verification and recovery declaration"
)]
pub fn ingest_wrangler_pages_deploy_help(
    snapshot: &mut CatalogSnapshot,
    version: &str,
    help: &str,
) {
    if ![
        "wrangler pages deploy [directory]",
        "--project-name",
        "--branch",
        "--commit-hash",
        "--commit-message",
    ]
    .iter()
    .all(|marker| help.contains(marker))
    {
        return;
    }

    let mut capability = CapabilityV1::new(
        "wrangler.pages-deploy",
        "Deploy a directory to Cloudflare Pages",
        "POST",
        "wrangler pages deploy",
    );
    capability.source = format!("wrangler {version} pages deploy help");
    "CLI".clone_into(&mut capability.method);
    "Cloudflare Pages".clone_into(&mut capability.product);
    capability.adapter_status = AdapterStatus::DelegatedCli;
    capability.risk = RiskClass::CrossConfig;
    capability.effect = EffectClass::ReversibleWrite;
    capability.cost.known = true;
    capability.cost.incremental = false;
    capability.cost.billing_model = BillingModelV1::UsageBased;
    capability.cost.exposure = CostExposureV1::DownstreamUsage;
    capability.cost.maximum = Some(0.0);
    capability.cost.basis = Some(
        "uploading a Pages deployment has no direct per-deployment charge; the deployed site can create plan-specific Functions and bandwidth usage"
            .to_owned(),
    );
    capability.cost.references = vec![KnowledgeReferenceV1 {
        title: "Cloudflare Pages Functions pricing".to_owned(),
        url: "https://developers.cloudflare.com/pages/functions/pricing/".to_owned(),
        source: "official Cloudflare docs".to_owned(),
    }];
    capability.verification.required = true;
    "wrangler_pages_new_deployment_succeeds_by_returned_id"
        .clone_into(&mut capability.verification.strategy);
    capability.created_resource = Some(CreatedResourceContractV1 {
        detail_path: PAGES_DEPLOYMENT_DETAIL_PATH.to_owned(),
        identity_selector: "deployment_id".to_owned(),
        response_result_identity_pointer: "/id".to_owned(),
        read_capability_id: PAGES_DEPLOYMENT_READ_CAPABILITY_ID.to_owned(),
        delete_capability_id: PAGES_DEPLOYMENT_DELETE_CAPABILITY_ID.to_owned(),
        verified_response_fields: vec!["environment".to_owned(), "project_name".to_owned()],
    });
    capability.rollback.supported = false;
    capability.rollback.warning = Some(
        "automatic rollback is not implemented; restoration requires a separate reviewed Pages deployment plan for a known prior artifact and commit, does not erase the failed deployment or Functions side effects, and cannot refund usage"
            .to_owned(),
    );
    capability.selectors = [
        (
            "argument",
            true,
            "Absolute or workspace-relative directory containing the built Pages artifact",
        ),
        (
            "project_name",
            true,
            "Existing Cloudflare Pages project name",
        ),
        (
            "branch",
            true,
            "Exact source branch; production matches the project production branch, preview must differ",
        ),
        (
            "commit_hash",
            true,
            "Exact source commit recorded on and verified against the deployment",
        ),
        (
            "commit_message",
            false,
            "Optional source commit message recorded on the deployment",
        ),
    ]
    .into_iter()
    .map(|(name, required, description)| SelectorV1 {
        name: name.to_owned(),
        location: "query".to_owned(),
        required,
        value_type: "string".to_owned(),
        description: Some(description.to_owned()),
        contract: None,
    })
    .collect();
    capability.selectors.push(SelectorV1 {
        name: "environment".to_owned(),
        location: "query".to_owned(),
        required: false,
        value_type: "string".to_owned(),
        description: Some(
            "cfctl deployment intent: production by default; preview requires an explicit non-production source branch. This control is not a Wrangler flag."
                .to_owned(),
        ),
        contract: Some(SelectorContractV1 {
            schema: serde_json::json!({"type":"string","enum":["production","preview"],"default":"production"}),
            query: None,
        }),
    });
    pages_artifact::add_archive_selector(&mut capability);
    snapshot
        .capabilities
        .insert(capability.id.clone(), capability);
}
