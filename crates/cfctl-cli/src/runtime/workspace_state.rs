use super::credential_resolution::platform_secrets;
use super::entitlement_state::should_bind_pages_project_absence;
use super::import_planning::SECURITY_ACTION_STATE_PRECONDITION;
use super::pages_deployment::PROJECT_ABSENCE_PRECONDITION;
use super::pages_source::SOURCE_REMOTE_PRECONDITION;
use super::pages_source::pages_github_source;
use super::plan_prepare::prepare_pages_source_remote_precondition;
use super::plan_secret::CLOUDFLARE_TUNNEL_CONFIGURATION_STATE_PRECONDITION;
use super::plan_secret::D1_EMPTY_DATABASE_PRECONDITION;
use super::plan_secret::D1_READ_REPLICATION_PRECONDITION;
use super::plan_secret::DNS_RECORD_STATE_PRECONDITION;
use super::plan_secret::OAUTH_CLIENT_KEY_OVERLAP_PRECONDITION;
use super::plan_secret::OAUTH_CLIENT_UPDATE_STATE_PRECONDITION;
use super::plan_secret::SAME_PATH_PRIOR_STATE_PRECONDITION;
use super::plan_secret::WARP_CONNECTOR_CONFIGURATION_STATE_PRECONDITION;
use super::plan_secret::WEB_ANALYTICS_RUM_STATE_PRECONDITION;
use super::prelude::fs;
use super::prelude::{
    BTreeMap, BTreeSet, CallInput, CliError, Digest, Path, PathBuf, PlanV1, RegisteredRoot, Result,
    Sha256, StateStore, Utc, Value, WalkDir, WorkspaceGraph, json,
};
use super::r2_credentials::R2_PARENT_TOKEN_PRECONDITION;
use super::support::cli_io;
use super::{
    pages_deployment, r2_private_upload, worker_custom_domain, worker_deployment,
    workspace_d1_migration, workspace_d1_projection, workspace_d1_qualification,
    workspace_d1_reply_admission, workspace_reply_subdomain_ingress,
};
use cfctl_core::hash_value;

pub(super) fn discover_registered(store: &StateStore) -> Result<WorkspaceGraph> {
    let roots: Vec<RegisteredRoot> = store
        .workspace_roots()?
        .iter()
        .map(|path| RegisteredRoot::new(path))
        .collect();
    Ok(WorkspaceGraph::discover(&roots)?)
}

pub(super) fn workspace_precondition_hashes_for_scope(
    store: &StateStore,
    affected_repositories: &[String],
    local_artifact_paths: &[PathBuf],
) -> Result<BTreeMap<String, String>> {
    let graph = discover_registered(store)?;
    let repository_ids = affected_repositories
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let repositories = graph
        .repositories
        .iter()
        .filter(|repository| repository_ids.contains(&repository.path.display().to_string()))
        .collect::<Vec<_>>();
    if repositories.len() != repository_ids.len() {
        return Err(CliError::Input(
            "an affected repository is no longer present in the registered workspace graph"
                .to_owned(),
        ));
    }
    let resources = graph
        .resources
        .iter()
        .filter(|resource| {
            graph.links.get(&resource.key).is_some_and(|linked| {
                linked
                    .iter()
                    .any(|repository| repository_ids.contains(repository))
            })
        })
        .collect::<Vec<_>>();
    let links = graph
        .links
        .iter()
        .filter_map(|(resource, linked)| {
            let scoped = linked
                .iter()
                .filter(|repository| repository_ids.contains(*repository))
                .cloned()
                .collect::<BTreeSet<_>>();
            (!scoped.is_empty()).then_some((resource.clone(), scoped))
        })
        .collect::<BTreeMap<_, _>>();
    let mut hashes = BTreeMap::new();
    hashes.insert(
        "workspace_graph".to_owned(),
        hash_value(&json!({
            "repositories": repositories,
            "resources": resources,
            "links": links,
        }))?,
    );
    for path in repositories
        .into_iter()
        .flat_map(|repository| &repository.cloudflare_configs)
    {
        let content = fs::read_to_string(path).map_err(|source| cli_io(path, source))?;
        hashes.insert(
            format!("source_config:{}", path.display()),
            hash_value(&Value::String(content))?,
        );
    }
    for path in local_artifact_paths {
        hashes.insert(
            format!("source_artifact:{}", path.display()),
            hash_directory_artifact(path)?,
        );
    }
    Ok(hashes)
}

pub(super) fn hash_directory_artifact(root: &Path) -> Result<String> {
    let canonical = fs::canonicalize(root).map_err(|source| cli_io(root, source))?;
    if !canonical.is_dir() {
        return Err(CliError::Input(format!(
            "deployment artifact `{}` is not a directory",
            canonical.display()
        )));
    }
    let mut manifest = Vec::new();
    for entry in WalkDir::new(&canonical).follow_links(false) {
        let entry = entry.map_err(|source| {
            CliError::Input(format!(
                "failed to inspect deployment artifact `{}`: {source}",
                canonical.display()
            ))
        })?;
        if entry.path() == canonical || entry.file_type().is_dir() {
            continue;
        }
        if !entry.file_type().is_file() {
            return Err(CliError::Input(format!(
                "deployment artifact contains unsupported non-file entry `{}`",
                entry.path().display()
            )));
        }
        let relative = entry.path().strip_prefix(&canonical).map_err(|_| {
            CliError::Input(format!(
                "deployment artifact entry `{}` escaped its root",
                entry.path().display()
            ))
        })?;
        let bytes = fs::read(entry.path()).map_err(|source| cli_io(entry.path(), source))?;
        manifest.push(json!({
            "path": relative.to_string_lossy(),
            "sha256": hex::encode(Sha256::digest(&bytes)),
        }));
    }
    manifest.sort_by_key(|entry| entry["path"].as_str().unwrap_or_default().to_owned());
    Ok(hash_value(&Value::Array(manifest))?)
}

pub(super) fn validate_pages_source_remote_receipt(plan: &PlanV1, receipt: &Value) -> Result<()> {
    let input: CallInput = serde_json::from_value(plan.input.clone())?;
    let (owner, repository, branch) = pages_github_source(&input)?;
    let owner = owner.to_ascii_lowercase();
    let repository = repository.to_ascii_lowercase();
    let remote_ref = format!("refs/heads/{branch}");
    let commit = receipt.get("remote_commit").and_then(Value::as_str);
    let exact = receipt.as_object().is_some_and(|object| object.len() == 7)
        && receipt.get("schema_version").and_then(Value::as_u64) == Some(1)
        && receipt.get("provider").and_then(Value::as_str) == Some("github")
        && receipt.get("owner").and_then(Value::as_str) == Some(owner.as_str())
        && receipt.get("repository").and_then(Value::as_str) == Some(repository.as_str())
        && receipt.get("branch").and_then(Value::as_str) == Some(branch)
        && receipt.get("remote_ref").and_then(Value::as_str) == Some(remote_ref.as_str())
        && commit.is_some_and(|commit| {
            commit.len() == 40
                && commit
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        });
    if !exact {
        return Err(CliError::Input(
            "Pages source remote receipt has an invalid repository, branch, or commit shape; create a new plan"
                .to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn current_pages_source_remote_precondition(
    store: &StateStore,
    plan: &PlanV1,
) -> Result<Option<String>> {
    if !should_bind_pages_project_absence(&plan.capability) {
        return Ok(None);
    }
    let expected = plan
        .precondition_hashes
        .get(SOURCE_REMOTE_PRECONDITION)
        .ok_or_else(|| {
            CliError::Input(
                "Pages project creation plan predates the exact source-remote contract; create a new plan"
                    .to_owned(),
            )
        })?;
    let receipt = plan
        .targets
        .pointer(&format!(
            "/source_preconditions/{SOURCE_REMOTE_PRECONDITION}"
        ))
        .ok_or_else(|| {
            CliError::Input(
                "Pages project creation plan omitted its source-remote receipt; create a new plan"
                    .to_owned(),
            )
        })?;
    validate_pages_source_remote_receipt(plan, receipt)?;
    if &hash_value(receipt)? != expected {
        return Err(CliError::Input(
            "Pages source-remote receipt does not match its precondition hash; create a new plan"
                .to_owned(),
        ));
    }
    let input: CallInput = serde_json::from_value(plan.input.clone())?;
    let current = prepare_pages_source_remote_precondition(store, &plan.capability, &input)?
        .ok_or_else(|| {
            CliError::Input(
                "Pages source-remote precondition could not be recomputed; create a new plan"
                    .to_owned(),
            )
        })?;
    Ok(Some(hash_value(&current)?))
}

pub(super) fn validate_plan_preconditions(store: &StateStore, plan: &PlanV1) -> Result<()> {
    workspace_reply_subdomain_ingress::validate_bound_plan(store, plan)?;
    workspace_d1_migration::validate_bound_plan(store, plan)?;
    workspace_d1_projection::validate_bound_plan(store, plan)?;
    workspace_d1_reply_admission::validate_bound_plan(store, plan)?;
    r2_private_upload::validate_bound_plan(store, plan, &platform_secrets(store))?;
    let input: CallInput = serde_json::from_value(plan.input.clone())?;
    let graph = discover_registered(store)?;
    pages_deployment::validate_bound_plan(&graph, plan, &input)?;
    let local_artifact_paths = plan
        .precondition_hashes
        .keys()
        .filter_map(|name| name.strip_prefix("source_artifact:"))
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    let mut current = workspace_precondition_hashes_for_scope(
        store,
        &plan.affected_repositories,
        &local_artifact_paths,
    )?;
    if let Some(source_remote) = current_pages_source_remote_precondition(store, plan)? {
        current.insert(SOURCE_REMOTE_PRECONDITION.to_owned(), source_remote);
    }
    current.extend(workspace_d1_qualification::current_plan_evidence_hashes(
        store,
        plan,
        Utc::now(),
    )?);
    for (name, expected) in &plan.precondition_hashes {
        if is_live_plan_precondition_hash(name) {
            continue;
        }
        if current.get(name) != Some(expected) {
            return Err(CliError::Input(format!(
                "precondition `{name}` drifted after planning; create a new plan"
            )));
        }
    }
    Ok(())
}

pub(super) fn validate_worker_deployment_local_authority(
    store: &StateStore,
    plan: &PlanV1,
    input: &CallInput,
) -> Result<()> {
    let adapter = plan.targets.get("adapter").unwrap_or(&Value::Null);
    if !worker_deployment::binds_live_state(&plan.capability)
        && worker_deployment::target(adapter).is_none()
    {
        return Ok(());
    }
    if plan.capability.id == worker_deployment::ROLLBACK_CAPABILITY_ID {
        return worker_deployment::validate_current_rollback_target(
            &plan.capability,
            input,
            adapter,
        );
    }
    let graph = discover_registered(store)?;
    worker_deployment::validate_current_target(&graph, &plan.capability, input, adapter)
}

pub(super) fn is_live_plan_precondition_hash(name: &str) -> bool {
    matches!(
        name,
        "catalog"
            | "request_input"
            | "entitlement"
            | "zone_account"
            | PROJECT_ABSENCE_PRECONDITION
            | pages_deployment::PROJECT_STATE_PRECONDITION
            | "global_warp_override_state"
            | D1_READ_REPLICATION_PRECONDITION
            | D1_EMPTY_DATABASE_PRECONDITION
            | CLOUDFLARE_TUNNEL_CONFIGURATION_STATE_PRECONDITION
            | WARP_CONNECTOR_CONFIGURATION_STATE_PRECONDITION
            | WEB_ANALYTICS_RUM_STATE_PRECONDITION
            | DNS_RECORD_STATE_PRECONDITION
            | SAME_PATH_PRIOR_STATE_PRECONDITION
            | SECURITY_ACTION_STATE_PRECONDITION
            | OAUTH_CLIENT_KEY_OVERLAP_PRECONDITION
            | OAUTH_CLIENT_UPDATE_STATE_PRECONDITION
            | worker_custom_domain::WORKER_CUSTOM_DOMAIN_STATE_PRECONDITION
            | worker_deployment::STATE_PRECONDITION
            | R2_PARENT_TOKEN_PRECONDITION
    )
}
