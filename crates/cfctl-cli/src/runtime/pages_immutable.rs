//! Authenticated archive mode and logical workspace impact, separate from HEAD.
use super::{Result, pages_reproduction as producer, pages_reproduction_process::rejected};
use cfctl_cloudflare::CallInput;
use cfctl_core::{
    EvidenceClass,
    pages_artifact::{self as contract, ReproductionReceiptV1},
};
use cfctl_storage::StateStore;
use cfctl_workspace::WorkspaceGraph;
use serde_json::{Value, json};
use std::path::Path;

pub(super) fn requested(input: &CallInput) -> bool {
    input.query.get("artifact_receipt").is_some()
}

pub(super) fn receipt(
    store: &StateStore,
    graph: &WorkspaceGraph,
    input: &CallInput,
) -> Result<ReproductionReceiptV1> {
    let hash = input.query["artifact_receipt"]
        .as_str()
        .ok_or_else(rejected)?;
    let (evidence, value) = store.load_evidence_value(hash)?;
    let receipt: ReproductionReceiptV1 = serde_json::from_value(value)?;
    if evidence.class != EvidenceClass::LocalProof
        || evidence.metadata != json!({"native_producer":contract::PRODUCER_ID,"version":1})
        || receipt.schema_version != 1
        || receipt.kind != contract::PRODUCER_ID
        || receipt.recipe != contract::RECIPE
        || receipt.build_identity_hash != producer::build_hash()?
        || receipt.producer_contract_hash != producer::producer_hash()?
        || receipt.completed_at < receipt.started_at
        || receipt.completed_at > evidence.generated_at
        || receipt.environment != producer::environment()
        || !producer::hex_string(&receipt.esbuild_sha256, 64)
        || !receipt.helper_tools.as_object().is_some_and(|tools| {
            tools.len() == 2
                && tools.iter().all(|(p, h)| {
                    Path::new(p).is_absolute()
                        && h.as_str().is_some_and(|s| producer::hex_string(s, 64))
                })
        })
        || !receipt
            .materials_hash
            .strip_prefix("sha256:")
            .is_some_and(|h| producer::hex_string(h, 64))
        || uuid::Uuid::parse_str(&receipt.run_id).is_err()
        || input.query["commit_hash"].as_str() != Some(receipt.request.commit.as_str())
        || input.query["branch"].as_str() != Some(receipt.request.branch.as_str())
        || input.query["project_name"].as_str() != Some(receipt.request.project_name.as_str())
        || input.query["argument"].as_str() != Some(receipt.request.artifact_directory.as_str())
        || input
            .selectors
            .get("account_id")
            .is_some_and(|v| v.as_str() != Some(receipt.request.account_id.as_str()))
    {
        return Err(rejected());
    }
    producer::validate_source(graph, &receipt.request)?;
    let root = Path::new(&receipt.request.artifact_directory);
    producer::canonical_path(root)?;
    if producer::portable_manifest(root)? != receipt.artifact
        || producer::retained_digest(&receipt.artifact)? != receipt.request.artifact_manifest_sha256
    {
        return Err(rejected());
    }
    Ok(receipt)
}

pub(super) fn source(
    store: &StateStore,
    graph: &WorkspaceGraph,
    input: &CallInput,
) -> Result<Value> {
    let proof = receipt(store, graph, input)?;
    Ok(
        json!({"repository":proof.request.repository,"commit":proof.request.commit,"tree":proof.request.tree,"branch":proof.request.branch,
        "mode":"immutable_artifact_v1","receipt":input.query["artifact_receipt"],"account_id":proof.request.account_id,
        "project_name":proof.request.project_name,"environment":"production","recipe":proof.recipe,"materials_hash":proof.materials_hash,
        "build_identity_hash":proof.build_identity_hash,"artifact_manifest_sha256":proof.request.artifact_manifest_sha256}),
    )
}

pub(super) fn validate_account(targets: &Value, account: &str) -> Result<()> {
    if let Some(source) = targets.pointer("/pages_deployment/source")
        && source["mode"] == "immutable_artifact_v1"
        && source["account_id"].as_str() != Some(account)
    {
        return Err(rejected());
    }
    Ok(())
}

pub(super) fn plan_repository(plan: &cfctl_core::PlanV1) -> Option<&str> {
    let source = plan.targets.pointer("/adapter/pages_deployment/source")?;
    (source["mode"] == "immutable_artifact_v1")
        .then(|| source["repository"].as_str())
        .flatten()
}

pub(super) fn for_impact(
    store: &StateStore,
    graph: &WorkspaceGraph,
    cap: &cfctl_core::CapabilityV1,
    input: &CallInput,
    account: &str,
) -> Result<Option<ReproductionReceiptV1>> {
    if !super::pages_deployment::binds_artifact(cap) || !requested(input) {
        return Ok(None);
    }
    let proof = receipt(store, graph, input)?;
    if proof.request.account_id != account {
        return Err(rejected());
    }
    Ok(Some(proof))
}

pub(super) fn artifact_repository(
    graph: &WorkspaceGraph,
    path: &Path,
    archive: Option<&ReproductionReceiptV1>,
) -> Result<String> {
    if let Some(proof) = archive {
        return Ok(proof.request.repository.clone());
    }
    super::pages_source::repository_owning_path(graph, path)
        .map(|r| r.path.display().to_string())
        .ok_or_else(|| {
            super::CliError::Input(format!(
                "local deployment artifact `{}` is not owned by a registered repository",
                path.display()
            ))
        })
}

pub(super) fn append_impact_diffs(
    graph: &WorkspaceGraph,
    paths: &[std::path::PathBuf],
    input: &CallInput,
    archive: Option<&ReproductionReceiptV1>,
    diffs: &mut Vec<Value>,
) -> Result<()> {
    if let Some(proof) = archive {
        diffs.retain(|d| d["repository"].as_str() != Some(proof.request.repository.as_str()));
        diffs.push(json!({"repository":proof.request.repository,"path":proof.request.artifact_directory,
            "kind":"immutable_deployment_artifact","content_hash":proof.artifact["content_hash"],
            "source_commit":proof.request.commit,"source_tree":proof.request.tree,"receipt":input.query["artifact_receipt"],"dirty":false}));
        Ok(())
    } else {
        super::pages_source::append_local_artifact_diffs(graph, paths, diffs)
    }
}
