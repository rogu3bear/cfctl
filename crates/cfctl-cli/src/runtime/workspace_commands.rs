use super::prelude::{
    BTreeSet, CatalogSnapshot, OperationalProofOutcomeV1, OperationalProofV1, ProfilesConfig,
    Result, ResultEnvelopeV2, StateStore, Value, WorkspaceCommand, json,
};
use super::support::cli_io;
use super::support::workspace_graph_file;
use super::workspace_state::discover_registered;
use crate::telemetry_product::{
    OPERATIONAL_PROOF_PROJECTION_LIMIT, operational_proof_projection_json,
};

pub(super) fn workspace_command(
    store: &StateStore,
    command: WorkspaceCommand,
) -> Result<ResultEnvelopeV2> {
    match command {
        WorkspaceCommand::Add(arguments) => {
            store.register_workspace(&arguments.path, arguments.account)?;
            Ok(ResultEnvelopeV2::success(
                "workspace add",
                json!({"path": arguments.path, "message": "Workspace root registered; discovery remains bounded to registered roots."}),
            ))
        }
        WorkspaceCommand::Remove(arguments) => {
            let (path, removed, account_pin_removed) =
                store.unregister_workspace(&arguments.path)?;
            Ok(ResultEnvelopeV2::success(
                "workspace remove",
                json!({
                    "path": path,
                    "removed": removed,
                    "account_pin_removed": account_pin_removed,
                    "message": "Workspace root retired from future discovery; historical graphs and evidence were preserved."
                }),
            ))
        }
        WorkspaceCommand::Discover => {
            let graph = discover_registered(store)?;
            store.write_json(&workspace_graph_file(store), &graph)?;
            Ok(ResultEnvelopeV2::success(
                "workspace discover",
                serde_json::to_value(graph)?,
            ))
        }
        WorkspaceCommand::Graph => {
            let graph = discover_registered(store)?;
            Ok(ResultEnvelopeV2::success(
                "workspace graph",
                serde_json::to_value(graph)?,
            ))
        }
        WorkspaceCommand::Audit => {
            let graph = discover_registered(store)?;
            let account_pins = store.workspace_manifest()?.account_pins();
            let proof_page =
                store.list_recent_operational_proofs(OPERATIONAL_PROOF_PROJECTION_LIMIT)?;
            let proofs = &proof_page.proofs;
            let profiles = ProfilesConfig::load(store)?;
            let current_catalog_hash = store
                .paths()
                .catalog_file()
                .is_file()
                .then(|| CatalogSnapshot::load(&store.paths().catalog_file()))
                .transpose()?
                .map(|catalog| catalog.schema_hash);
            let mut repositories = Vec::new();
            for repository in &graph.repositories {
                let output = std::process::Command::new("git")
                    .args([
                        "-C",
                        &repository.path.display().to_string(),
                        "status",
                        "--porcelain",
                    ])
                    .output()
                    .map_err(|source| cli_io(&repository.path, source))?;
                let account_id = account_pins
                    .iter()
                    .filter(|(root, _)| repository.path.starts_with(root))
                    .max_by_key(|(root, _)| root.components().count())
                    .map(|(_, account)| account.as_str());
                repositories.push(json!({
                    "name": repository.name,
                    "path": repository.path,
                    "dirty": !output.stdout.is_empty(),
                    "cloudflare_configs": repository.cloudflare_configs,
                    "account_id": account_id,
                    "operational_proof": workspace_operational_proof_posture(
                        proofs,
                        &profiles,
                        account_id,
                        current_catalog_hash.as_deref(),
                    ),
                }));
            }
            Ok(ResultEnvelopeV2::success(
                "workspace audit",
                json!({
                    "repositories": repositories,
                    "resource_count": graph.resources.len(),
                    "operational_proof_projection": operational_proof_projection_json(&proof_page),
                    "truth_boundary": "Repository configuration is source-config evidence. The operational-proof overlay contains account-scoped live-read receipts and remains separate from edge verification or desired-state convergence."
                }),
            ))
        }
    }
}

pub(super) fn workspace_operational_proof_posture(
    proofs: &[OperationalProofV1],
    profiles: &ProfilesConfig,
    account_id: Option<&str>,
    current_catalog_hash: Option<&str>,
) -> Value {
    let Some(account_id) = account_id else {
        return json!({
            "state": "unscoped",
            "proof_count": 0,
            "next_action": "Register the root with an explicit account pin before joining local configuration to operational proof."
        });
    };
    let scoped = proofs
        .iter()
        .filter(|proof| proof.account_id.as_deref() == Some(account_id))
        .collect::<Vec<_>>();
    let capabilities = scoped
        .iter()
        .map(|proof| proof.capability_id.as_str())
        .collect::<BTreeSet<_>>();
    let current_catalog_successes = current_catalog_hash.map_or(0, |catalog_hash| {
        scoped
            .iter()
            .filter(|proof| {
                proof.catalog_hash == catalog_hash
                    && proof
                        .profile_id
                        .as_deref()
                        .and_then(|profile_id| profiles.profiles.get(profile_id))
                        .and_then(|profile| profile.credential_generation_id.as_deref())
                        == proof.credential_generation_id.as_deref()
                    && proof.credential_generation_id.is_some()
                    && proof.outcome == OperationalProofOutcomeV1::Succeeded
            })
            .count()
    });
    let current_catalog_failures = current_catalog_hash.map_or(0, |catalog_hash| {
        scoped
            .iter()
            .filter(|proof| {
                proof.catalog_hash == catalog_hash
                    && proof
                        .profile_id
                        .as_deref()
                        .and_then(|profile_id| profiles.profiles.get(profile_id))
                        .and_then(|profile| profile.credential_generation_id.as_deref())
                        == proof.credential_generation_id.as_deref()
                    && proof.credential_generation_id.is_some()
                    && proof.outcome == OperationalProofOutcomeV1::Failed
            })
            .count()
    });
    json!({
        "state": if scoped.is_empty() { "not_recorded" } else { "recorded" },
        "account_id": account_id,
        "proof_count": scoped.len(),
        "capabilities_observed": capabilities,
        "latest_observed_at": scoped.iter().map(|proof| proof.observed_at).max(),
        "current_catalog_hash": current_catalog_hash,
        "current_catalog_successes": current_catalog_successes,
        "current_catalog_failures": current_catalog_failures,
        "catalog_drifted_or_unclassified": scoped.len().saturating_sub(current_catalog_successes + current_catalog_failures),
        "credential_unbound_or_drifted": scoped.iter().filter(|proof| {
            proof.credential_generation_id.is_none()
                || proof.profile_id.as_deref()
                    .and_then(|profile_id| profiles.profiles.get(profile_id))
                    .and_then(|profile| profile.credential_generation_id.as_deref())
                    != proof.credential_generation_id.as_deref()
        }).count(),
        "freshness_policy": "Select a governed workflow to evaluate time freshness; workspace audit does not invent a universal window."
    })
}
