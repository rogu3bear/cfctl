use std::{
    collections::BTreeSet,
    fs,
    fs::OpenOptions,
    io::Read,
    path::{Component, Path, PathBuf},
};

use cfctl_core::{
    DeploymentPlanSetChildV1, DeploymentPlanSetRepositoryV1, DeploymentPlanSetV1, EvidenceClass,
    PlanStatus, PlanV2, ResultEnvelopeV2, VerificationState, hash_value,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use super::{
    CallInput, CatalogSnapshot, CliError, ProfilesConfig, Result, StateStore,
    active_admission_policy, catalog_is_stale, current_build_info, ensure_catalog,
    fresh_credential, git_authority_output, normalize_reviewed_git_repository_id, platform_secrets,
    prepend_live_precondition_evidence, resolved_plan_input,
    validate_live_plan_precondition_evidence, validate_plan_preconditions,
    validate_plan_v2_runtime_pins, validate_worker_deployment_local_authority,
};
use crate::{DeploymentPlanSetCreateArgs, DeploymentPlanSetSelector};

const MAX_SPEC_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanSetSpecV1 {
    schema_version: u8,
    name: String,
    repositories: Vec<PlanSetRepositorySpecV1>,
    children: Vec<PlanSetChildSpecV1>,
    explicit_exclusions: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanSetRepositorySpecV1 {
    root: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanSetChildSpecV1 {
    operation_id: String,
    #[serde(default)]
    depends_on: Vec<String>,
}

pub(super) fn create(
    store: &StateStore,
    arguments: &DeploymentPlanSetCreateArgs,
) -> Result<ResultEnvelopeV2> {
    let (spec, source_spec_sha256) = read_private_spec(&arguments.source_file)?;
    validate_spec_shape(&spec)?;
    if catalog_is_stale(store) {
        return Err(CliError::guided(
            "CFCTL_PLAN_SET_CATALOG_STALE",
            "the local catalog is stale and cannot anchor a deployment plan set",
            "Run `cfctl catalog sync`, recreate any affected child plan, then compile a new bundle.",
        ));
    }
    let catalog = CatalogSnapshot::load(&store.paths().catalog_file())?;
    let repositories = compile_repositories(store, &spec.repositories)?;
    let profiles = ProfilesConfig::load(store)?;
    let mut children = Vec::with_capacity(spec.children.len());
    let mut account_ids = BTreeSet::new();
    let mut shared: Option<PlanSetSharedPins> = None;
    let mut admission_policy_hashes = Vec::with_capacity(spec.children.len());
    let mut workspace_graph_hashes = Vec::with_capacity(spec.children.len());
    for (index, child_spec) in spec.children.iter().enumerate() {
        let plan_v2 = load_initial_child(store, &child_spec.operation_id)?;
        let profile = profiles.selected(Some(&plan_v2.plan.profile_id))?;
        validate_plan_v2_runtime_pins(store, &plan_v2.plan, profile)?;
        validate_plan_preconditions(store, &plan_v2.plan)?;
        if plan_v2.plan.catalog_hash != catalog.schema_hash {
            return Err(CliError::Input(format!(
                "child plan `{}` no longer matches the current catalog; create a new child plan",
                plan_v2.plan.operation_id
            )));
        }
        let current = PlanSetSharedPins::from_plan(&plan_v2)?;
        if let Some(expected) = &shared {
            if expected != &current {
                return Err(CliError::Input(
                    "all deployment plan-set children must share one profile, build, catalog, and credential generation"
                        .to_owned(),
                ));
            }
        } else {
            shared = Some(current);
        }
        admission_policy_hashes.push(plan_v2.pins.admission_policy_hash.clone());
        workspace_graph_hashes.push(plan_v2.pins.workspace_graph_hash.clone());
        account_ids.insert(plan_v2.plan.account_id.clone());
        children.push(compile_child(
            u32::try_from(index + 1)
                .map_err(|_| CliError::Input("too many child plans".to_owned()))?,
            &plan_v2,
            child_spec.depends_on.clone(),
        )?);
    }
    let shared = shared.ok_or_else(|| CliError::Input("plan set has no children".to_owned()))?;
    let admission_policy_hash = aggregate_admission_policy_hash(&admission_policy_hashes)?;
    let workspace_graph_hash =
        aggregate_sha256_pins("child_workspace_graph_hashes", &workspace_graph_hashes)?;
    let current_build_hash = hash_value(&serde_json::to_value(current_build_info())?)?;
    if current_build_hash != shared.build_identity_hash {
        return Err(CliError::Input(
            "the running cfctl build no longer matches the child-plan build pin".to_owned(),
        ));
    }
    let mut explicit_exclusions = spec.explicit_exclusions;
    explicit_exclusions.sort();
    explicit_exclusions.dedup();
    let plan_set = DeploymentPlanSetV1::new(
        spec.name,
        source_spec_sha256,
        shared.profile_id,
        account_ids.into_iter().collect(),
        shared.build_identity_hash,
        shared.catalog_hash,
        shared.credential_generation_id,
        admission_policy_hash,
        workspace_graph_hash,
        repositories,
        children,
        explicit_exclusions,
    )?;
    store.create_deployment_plan_set(&plan_set)?;
    let receipt = receipt(store, &plan_set, "prepared");
    let evidence = store.write_evidence(EvidenceClass::Preview, &receipt)?;
    let mut envelope =
        ResultEnvelopeV2::success("plans bundle create", receipt).with_evidence(evidence);
    envelope.verification.state = VerificationState::Pending;
    Ok(envelope)
}

pub(super) fn show(
    store: &StateStore,
    selector: &DeploymentPlanSetSelector,
) -> Result<ResultEnvelopeV2> {
    let plan_set = store.load_deployment_plan_set(&selector.bundle_id)?;
    let mut envelope = ResultEnvelopeV2::success(
        "plans bundle show",
        receipt(store, &plan_set, "not_revalidated"),
    );
    envelope.verification.state = VerificationState::Pending;
    Ok(envelope)
}

/// Revalidates every authority pin and provider precondition using reads only.
/// It never approves or executes a child plan and refuses bundles whose child
/// status has crossed the provider boundary.
pub(super) async fn verify(
    store: &StateStore,
    selector: &DeploymentPlanSetSelector,
) -> Result<ResultEnvelopeV2> {
    let plan_set = store.load_deployment_plan_set(&selector.bundle_id)?;
    if chrono::Utc::now() > plan_set.expires_at {
        return Err(CliError::guided(
            "CFCTL_PLAN_SET_EXPIRED",
            "the deployment plan set has expired",
            "Cancel any still-active child plans and prepare a new complete bundle from fresh reads.",
        ));
    }
    verify_repositories(store, &plan_set.repositories)?;
    let catalog = ensure_catalog(store).await?;
    if catalog.schema_hash != plan_set.catalog_hash {
        return Err(CliError::guided(
            "CFCTL_PLAN_SET_CATALOG_DRIFT",
            "the current catalog no longer matches the deployment plan-set pin",
            "Cancel and recreate the complete bundle from fresh child plans.",
        ));
    }
    let current_build_hash = hash_value(&serde_json::to_value(current_build_info())?)?;
    if current_build_hash != plan_set.build_identity_hash {
        return Err(CliError::guided(
            "CFCTL_PLAN_SET_BUILD_DRIFT",
            "the running build identity no longer matches the deployment plan set",
            "Install the exact reviewed cfctl build or recreate the complete bundle.",
        ));
    }
    let profiles = ProfilesConfig::load(store)?;
    let profile = profiles.selected(Some(&plan_set.profile_id))?;
    if profile.credential_generation_id.as_deref()
        != Some(plan_set.credential_generation_id.as_str())
    {
        return Err(CliError::guided(
            "CFCTL_PLAN_SET_CREDENTIAL_DRIFT",
            "the selected credential generation no longer matches the deployment plan set",
            "Re-authenticate and recreate the complete bundle from fresh child plans.",
        ));
    }
    validate_plan_set_policy_presence(store, &plan_set)?;
    let mut child_admission_policy_hashes = Vec::with_capacity(plan_set.children.len());
    let mut child_workspace_graph_hashes = Vec::with_capacity(plan_set.children.len());
    for child in &plan_set.children {
        let plan_v2 = store.load_plan_v2(&child.operation_id)?;
        validate_current_child(&plan_set, child, &plan_v2)?;
        validate_plan_v2_runtime_pins(store, &plan_v2.plan, profile)?;
        validate_plan_preconditions(store, &plan_v2.plan)?;
        child_admission_policy_hashes.push(plan_v2.pins.admission_policy_hash.clone());
        child_workspace_graph_hashes.push(plan_v2.pins.workspace_graph_hash.clone());
    }
    validate_child_aggregate_pins(
        &plan_set,
        &child_admission_policy_hashes,
        &child_workspace_graph_hashes,
    )?;
    let secrets = platform_secrets(store);
    let credential = fresh_credential(profile, &secrets).await?;
    let mut evidence = Vec::new();
    for child in &plan_set.children {
        let plan_v2 = store.load_plan_v2(&child.operation_id)?;
        let input = resolved_plan_input(&plan_v2.plan, &secrets)?;
        validate_worker_deployment_local_authority(store, &plan_v2.plan, &input)?;
        let live = validate_live_plan_precondition_evidence(
            store,
            &catalog,
            &plan_v2.plan,
            &input,
            &credential,
            None,
        )
        .await?;
        let mut child_envelope = ResultEnvelopeV2::success("plans bundle verify child", json!({}));
        prepend_live_precondition_evidence(&mut child_envelope, live);
        evidence.extend(child_envelope.evidence);
    }
    let receipt = receipt(store, &plan_set, "fresh_and_coherent");
    let bundle_evidence = store.write_evidence(EvidenceClass::Preview, &receipt)?;
    evidence.push(bundle_evidence);
    let mut envelope = ResultEnvelopeV2::success("plans bundle verify", receipt);
    envelope.evidence = evidence;
    envelope.verification.state = VerificationState::Passed;
    envelope.verification.basis = Some(
        "all source, build, catalog, profile, credential, policy, child-plan, local, and live provider preconditions match; no child was approved or executed by this command"
            .to_owned(),
    );
    Ok(envelope)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PlanSetSharedPins {
    profile_id: String,
    build_identity_hash: String,
    catalog_hash: String,
    credential_generation_id: String,
}

impl PlanSetSharedPins {
    fn from_plan(plan: &PlanV2) -> Result<Self> {
        if plan.pins.authority_hash.is_some() {
            return Err(CliError::Input(
                "deployment plan-set children cannot carry standing authority".to_owned(),
            ));
        }
        Ok(Self {
            profile_id: plan.plan.profile_id.clone(),
            build_identity_hash: plan.pins.build_identity_hash.clone(),
            catalog_hash: plan.pins.catalog_hash.clone(),
            credential_generation_id: plan.pins.credential_generation_id.clone(),
        })
    }
}

fn aggregate_admission_policy_hash(hashes: &[String]) -> Result<String> {
    let canonical = canonical_pin_set(hashes, "admission policy")?;
    if canonical.len() == 1 {
        return Ok(canonical[0].clone());
    }
    if canonical.iter().all(|hash| hash.starts_with("compiled:")) {
        return Ok(format!(
            "compiled:{}",
            hash_value(&json!({"child_admission_policy_hashes": canonical}))?
        ));
    }
    Err(CliError::Input(
        "deployment plan-set children disagree on the active admission policy bundle".to_owned(),
    ))
}

fn aggregate_sha256_pins(label: &str, hashes: &[String]) -> Result<String> {
    let canonical = canonical_pin_set(hashes, label)?;
    if canonical.len() == 1 {
        return Ok(canonical[0].clone());
    }
    hash_value(&json!({"pin_scope": label, "hashes": canonical})).map_err(Into::into)
}

fn canonical_pin_set(hashes: &[String], label: &str) -> Result<Vec<String>> {
    if hashes.is_empty() || hashes.iter().any(|hash| hash.trim().is_empty()) {
        return Err(CliError::Input(format!(
            "deployment plan-set {label} pins must be non-empty"
        )));
    }
    let mut canonical = hashes.to_vec();
    canonical.sort();
    canonical.dedup();
    Ok(canonical)
}

fn validate_child_aggregate_pins(
    plan_set: &DeploymentPlanSetV1,
    admission_policy_hashes: &[String],
    workspace_graph_hashes: &[String],
) -> Result<()> {
    if aggregate_admission_policy_hash(admission_policy_hashes)? == plan_set.admission_policy_hash
        && aggregate_sha256_pins("child_workspace_graph_hashes", workspace_graph_hashes)?
            == plan_set.workspace_graph_hash
    {
        return Ok(());
    }
    Err(CliError::guided(
        "CFCTL_PLAN_SET_CHILD_DRIFT",
        "the deployment plan-set aggregate pins no longer match its child plans",
        "Cancel and recreate the complete deployment bundle from fresh child plans.",
    ))
}

fn validate_plan_set_policy_presence(
    store: &StateStore,
    plan_set: &DeploymentPlanSetV1,
) -> Result<()> {
    let current_policy_hash = active_admission_policy(store)?.map_or_else(
        || None,
        |bundle| Some(format!("bundle:{}", bundle.content_hash)),
    );
    if plan_set.admission_policy_hash.starts_with("bundle:")
        && current_policy_hash.as_deref() != Some(plan_set.admission_policy_hash.as_str())
    {
        return Err(CliError::guided(
            "CFCTL_PLAN_SET_POLICY_DRIFT",
            "the active admission bundle no longer matches the deployment plan set",
            "Recreate every child and the complete bundle under the current admission policy.",
        ));
    }
    if plan_set.admission_policy_hash.starts_with("compiled:") && current_policy_hash.is_some() {
        return Err(CliError::guided(
            "CFCTL_PLAN_SET_POLICY_DRIFT",
            "the deployment plan set used the compiled safety floor but an admission bundle is now active",
            "Recreate every child and the complete bundle under the active admission policy.",
        ));
    }
    Ok(())
}

fn load_initial_child(store: &StateStore, operation_id: &str) -> Result<PlanV2> {
    let plan = store.load_plan_v2(operation_id)?;
    plan.validate()?;
    if plan.plan.status != PlanStatus::Draft
        || plan.plan.approval.is_some()
        || plan.plan.cancelled_at.is_some()
        || chrono::Utc::now() > plan.plan.expires_at
    {
        return Err(CliError::Input(format!(
            "child plan `{operation_id}` must be unexpired, draft, unapproved, and unconsumed when the bundle is compiled"
        )));
    }
    Ok(plan)
}

fn compile_child(
    sequence: u32,
    plan: &PlanV2,
    mut depends_on: Vec<String>,
) -> Result<DeploymentPlanSetChildV1> {
    let input: CallInput = serde_json::from_value(plan.plan.input.clone())?;
    let mut zone_ids = input
        .selectors
        .get("zone_id")
        .and_then(Value::as_str)
        .map(|zone| vec![zone.to_owned()])
        .unwrap_or_default();
    zone_ids.sort();
    zone_ids.dedup();
    depends_on.sort();
    depends_on.dedup();
    let mut affected_resources = plan.plan.affected_resources.clone();
    affected_resources.sort();
    affected_resources.dedup();
    let mut permissions = plan.plan.capability.permissions.clone();
    permissions.sort();
    permissions.dedup();
    let mut warnings = plan.plan.non_reversible_warnings.clone();
    if let Some(warning) = &plan.plan.capability.rollback.warning {
        warnings.push(warning.clone());
    }
    warnings.sort();
    warnings.dedup();
    let provider_snapshot_hashes = target_scoped_provider_snapshot_hashes(
        &plan.plan.targets,
        &plan.pins.resource_observation_hashes,
    )?;
    Ok(DeploymentPlanSetChildV1 {
        sequence,
        operation_id: plan.plan.operation_id.clone(),
        plan_content_hash: plan.plan.content_hash.clone(),
        pins_hash: hash_value(&serde_json::to_value(&plan.pins)?)?,
        capability_id: plan.plan.capability.id.clone(),
        account_id: plan.plan.account_id.clone(),
        zone_ids,
        expires_at: plan.plan.expires_at,
        initial_status: plan.plan.status,
        depends_on,
        affected_resources,
        permissions,
        risk: plan.plan.capability.risk,
        effect: plan.plan.capability.effect,
        cost: plan.plan.capability.cost.clone(),
        warnings,
        rollback: plan.plan.capability.rollback.clone(),
        compensation_steps: plan.plan.compensation_steps.clone(),
        provider_snapshot_hashes,
    })
}

/// A Worker deployment observation is local to one exact Worker service, while
/// the remaining observation keys intentionally retain their bundle-global
/// identity. Without this projection, unrelated Worker children collide on the
/// generic `worker_deployment_state` key even though they observed different
/// resources. Same-service children still receive the same projected key, so
/// contradictory snapshots continue to fail closed in the core union.
fn target_scoped_provider_snapshot_hashes(
    targets: &Value,
    source: &std::collections::BTreeMap<String, String>,
) -> Result<std::collections::BTreeMap<String, String>> {
    let mut projected = source.clone();
    let Some(worker_state) = projected.remove("worker_deployment_state") else {
        return Ok(projected);
    };
    let Some(service_name) = targets
        .pointer("/adapter/worker_deployment/service_name")
        .and_then(Value::as_str)
    else {
        projected.insert("worker_deployment_state".to_owned(), worker_state);
        return Ok(projected);
    };
    if service_name.is_empty() {
        return Err(CliError::Input(
            "Worker deployment snapshot has an empty service target".to_owned(),
        ));
    }
    let scoped_key = format!("worker_deployment_state:{service_name}");
    if projected.insert(scoped_key.clone(), worker_state).is_some() {
        return Err(CliError::Input(format!(
            "Worker deployment snapshot collides with target-scoped key `{scoped_key}`"
        )));
    }
    Ok(projected)
}

fn validate_current_child(
    plan_set: &DeploymentPlanSetV1,
    child: &DeploymentPlanSetChildV1,
    plan: &PlanV2,
) -> Result<()> {
    plan.validate()?;
    let current = compile_child(child.sequence, plan, child.depends_on.clone())?;
    if !matches!(plan.plan.status, PlanStatus::Draft | PlanStatus::Approved)
        || plan.plan.content_hash != child.plan_content_hash
        || hash_value(&serde_json::to_value(&plan.pins)?)? != child.pins_hash
        || current.capability_id != child.capability_id
        || current.account_id != child.account_id
        || current.zone_ids != child.zone_ids
        || current.affected_resources != child.affected_resources
        || current.permissions != child.permissions
        || current.risk != child.risk
        || current.effect != child.effect
        || current.cost != child.cost
        || current.warnings != child.warnings
        || current.rollback != child.rollback
        || current.compensation_steps != child.compensation_steps
        || current.provider_snapshot_hashes != child.provider_snapshot_hashes
        || plan.plan.profile_id != plan_set.profile_id
        || plan.pins.build_identity_hash != plan_set.build_identity_hash
        || plan.pins.catalog_hash != plan_set.catalog_hash
        || plan.pins.credential_generation_id != plan_set.credential_generation_id
    {
        return Err(CliError::guided(
            "CFCTL_PLAN_SET_CHILD_DRIFT",
            format!(
                "child plan `{}` changed, expired, failed, was consumed, or no longer matches the bundle",
                child.operation_id
            ),
            "Cancel and recreate the complete deployment bundle from fresh child plans.",
        ));
    }
    Ok(())
}

fn compile_repositories(
    store: &StateStore,
    sources: &[PlanSetRepositorySpecV1],
) -> Result<Vec<DeploymentPlanSetRepositoryV1>> {
    let registered = store.workspace_roots()?;
    let mut repositories = sources
        .iter()
        .map(|source| compile_repository(&registered, &source.root))
        .collect::<Result<Vec<_>>>()?;
    repositories.sort_by(|left, right| left.repository_id.cmp(&right.repository_id));
    if repositories
        .windows(2)
        .any(|pair| pair[0].repository_id == pair[1].repository_id)
    {
        return Err(CliError::Input(
            "plan-set repository identities must be unique".to_owned(),
        ));
    }
    Ok(repositories)
}

fn compile_repository(
    registered: &[PathBuf],
    root: &Path,
) -> Result<DeploymentPlanSetRepositoryV1> {
    if !root.is_absolute()
        || root
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(CliError::Input(
            "plan-set repository roots must be absolute normalized paths".to_owned(),
        ));
    }
    let canonical = root.canonicalize().map_err(|source| CliError::Io {
        path: root.display().to_string(),
        source,
    })?;
    if !registered.contains(&canonical) {
        return Err(CliError::Input(format!(
            "plan-set repository `{}` is not an exact registered workspace root",
            canonical.display()
        )));
    }
    let top = git_authority_output(&canonical, &["rev-parse", "--show-toplevel"])?;
    if Path::new(&top).canonicalize().ok().as_deref() != Some(canonical.as_path()) {
        return Err(CliError::Input(
            "plan-set repository root is not the exact Git top level".to_owned(),
        ));
    }
    if !git_authority_output(&canonical, &["status", "--porcelain=v1"])?.is_empty() {
        return Err(CliError::Input(format!(
            "plan-set repository `{}` is dirty",
            canonical.display()
        )));
    }
    let remote = git_authority_output(&canonical, &["config", "--get", "remote.origin.url"])?;
    let repository_id = normalize_reviewed_git_repository_id(&remote)?;
    Ok(DeploymentPlanSetRepositoryV1 {
        repository_id: repository_id.clone(),
        root_sha256: hash_value(&json!(canonical.display().to_string()))?,
        origin_identity: repository_id,
        head: git_authority_output(&canonical, &["rev-parse", "HEAD"])?,
        tree: git_authority_output(&canonical, &["rev-parse", "HEAD^{tree}"])?,
    })
}

fn verify_repositories(
    store: &StateStore,
    expected: &[DeploymentPlanSetRepositoryV1],
) -> Result<()> {
    let registered = store.workspace_roots()?;
    for repository in expected {
        let root = registered.iter().find(|root| {
            hash_value(&json!(root.display().to_string()))
                .is_ok_and(|digest| digest == repository.root_sha256)
        });
        let current = root
            .map(|root| compile_repository(&registered, root))
            .transpose()?;
        if current.as_ref() != Some(repository) {
            return Err(CliError::guided(
                "CFCTL_PLAN_SET_SOURCE_DRIFT",
                format!(
                    "repository `{}` no longer matches its clean origin, HEAD, tree, or registered-root pin",
                    repository.repository_id
                ),
                "Cancel and recreate the complete deployment bundle from the current exact source heads.",
            ));
        }
    }
    Ok(())
}

fn receipt(store: &StateStore, plan_set: &DeploymentPlanSetV1, state: &str) -> Value {
    let children = plan_set
        .children
        .iter()
        .map(|child| {
            let current_status = store.load_plan(&child.operation_id).map_or_else(
                |_| "unavailable".to_owned(),
                |plan| format!("{:?}", plan.status).to_ascii_lowercase(),
            );
            let current_pins = store.load_plan_v2(&child.operation_id).ok().map(|plan| plan.pins);
            json!({
                "sequence":child.sequence,
                "operation_id":child.operation_id,
                "plan_content_hash":child.plan_content_hash,
                "pins_hash":child.pins_hash,
                "admission_policy_hash":current_pins.as_ref().map(|pins| &pins.admission_policy_hash),
                "workspace_graph_hash":current_pins.as_ref().map(|pins| &pins.workspace_graph_hash),
                "capability_id":child.capability_id,
                "account_id":child.account_id,
                "zone_ids":child.zone_ids,
                "depends_on":child.depends_on,
                "permissions":child.permissions,
                "risk":child.risk,
                "effect":child.effect,
                "cost":child.cost,
                "warnings":child.warnings,
                "rollback":child.rollback,
                "compensation_steps":child.compensation_steps,
                "provider_snapshot_hashes":child.provider_snapshot_hashes,
                "current_status":current_status,
                "approval_is_independent":true,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "schema_version":1,
        "bundle_id":plan_set.bundle_id,
        "name":plan_set.name,
        "created_at":plan_set.created_at,
        "expires_at":plan_set.expires_at,
        "content_hash":plan_set.content_hash,
        "source_spec_sha256":plan_set.source_spec_sha256,
        "profile_id":plan_set.profile_id,
        "account_ids":plan_set.account_ids,
        "build_identity_hash":plan_set.build_identity_hash,
        "catalog_hash":plan_set.catalog_hash,
        "credential_generation_id":plan_set.credential_generation_id,
        "admission_policy_hash":plan_set.admission_policy_hash,
        "workspace_graph_hash":plan_set.workspace_graph_hash,
        "repositories":plan_set.repositories,
        "provider_snapshot_hashes":plan_set.provider_snapshot_hashes,
        "children":children,
        "explicit_exclusions":plan_set.explicit_exclusions,
        "coherence_state":state,
        "bundle_can_approve_children":false,
        "bundle_can_run_children":false,
        "next_step":"review each child independently; this bundle never propagates approval",
    })
}

fn read_private_spec(path: &Path) -> Result<(PlanSetSpecV1, String)> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(CliError::Input(
            "deployment plan-set source must be an absolute normalized path".to_owned(),
        ));
    }
    reject_symlink_components(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let mut file = options.open(path).map_err(|source| CliError::Io {
        path: path.display().to_string(),
        source,
    })?;
    let metadata = file.metadata().map_err(|source| CliError::Io {
        path: path.display().to_string(),
        source,
    })?;
    #[cfg(unix)]
    let private_mode = metadata.permissions().mode() & 0o777 == 0o600;
    #[cfg(not(unix))]
    let private_mode = true;
    if !metadata.is_file()
        || !private_mode
        || metadata.len() == 0
        || metadata.len() > MAX_SPEC_BYTES
    {
        return Err(CliError::Input(format!(
            "deployment plan-set source must be a non-empty regular mode-0600 file no larger than {MAX_SPEC_BYTES} bytes"
        )));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|source| CliError::Io {
            path: path.display().to_string(),
            source,
        })?;
    if bytes.len() as u64 != metadata.len() {
        return Err(CliError::Input(
            "deployment plan-set source changed while it was read".to_owned(),
        ));
    }
    let spec = serde_json::from_slice(&bytes)?;
    Ok((
        spec,
        format!("sha256:{}", hex::encode(Sha256::digest(&bytes))),
    ))
}

fn validate_spec_shape(spec: &PlanSetSpecV1) -> Result<()> {
    if spec.schema_version != 1
        || spec.name.trim().is_empty()
        || spec.name.len() > 128
        || spec.repositories.is_empty()
        || spec.children.is_empty()
        || spec.explicit_exclusions.is_empty()
        || spec.repositories.len() > 32
        || spec.children.len() > 256
        || spec.explicit_exclusions.len() > 64
        || spec
            .explicit_exclusions
            .iter()
            .any(|value| value.trim().is_empty() || value.len() > 256)
    {
        return Err(CliError::Input(
            "deployment plan-set source has an unsupported schema, empty required set, or exceeds bounded counts"
                .to_owned(),
        ));
    }
    Ok(())
}

fn reject_symlink_components(path: &Path) -> Result<()> {
    let mut cursor = PathBuf::new();
    for component in path.components() {
        cursor.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&cursor).map_err(|source| CliError::Io {
            path: cursor.display().to_string(),
            source,
        })?;
        if metadata.file_type().is_symlink() {
            return Err(CliError::Input(format!(
                "deployment plan-set source has symlink component `{}`",
                cursor.display()
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::collections::BTreeMap;

    use serde_json::json;

    use super::{
        aggregate_admission_policy_hash, aggregate_sha256_pins,
        target_scoped_provider_snapshot_hashes,
    };

    fn provider_hash(value: char) -> String {
        format!("sha256:{}", value.to_string().repeat(64))
    }

    #[test]
    fn worker_state_snapshots_are_namespaced_by_exact_service_target() {
        let source = BTreeMap::from([
            ("source_config".to_owned(), provider_hash('a')),
            ("worker_deployment_state".to_owned(), provider_hash('b')),
        ]);

        let router = target_scoped_provider_snapshot_hashes(
            &json!({"adapter":{"worker_deployment":{"service_name":"relay-router"}}}),
            &source,
        )
        .expect("router snapshot identity");
        let outbound = target_scoped_provider_snapshot_hashes(
            &json!({"adapter":{"worker_deployment":{"service_name":"relay-outbound"}}}),
            &source,
        )
        .expect("outbound snapshot identity");

        assert_eq!(router.get("source_config"), source.get("source_config"));
        assert_eq!(outbound.get("source_config"), source.get("source_config"));
        assert_eq!(
            router.get("worker_deployment_state:relay-router"),
            source.get("worker_deployment_state")
        );
        assert_eq!(
            outbound.get("worker_deployment_state:relay-outbound"),
            source.get("worker_deployment_state")
        );
        assert!(!router.contains_key("worker_deployment_state"));
        assert!(!outbound.contains_key("worker_deployment_state"));
    }

    #[test]
    fn non_worker_snapshot_keys_keep_global_conflict_identity() {
        let source = BTreeMap::from([("provider_state".to_owned(), provider_hash('c'))]);

        let normalized = target_scoped_provider_snapshot_hashes(&json!({}), &source)
            .expect("ordinary snapshot identity");

        assert_eq!(normalized, source);
    }

    #[test]
    fn plan_set_cli_surface_has_no_bundle_approval_or_run_command() {
        let command = <crate::Cli as clap::CommandFactory>::command();
        let plans = command.find_subcommand("plans").expect("plans command");
        let bundle = plans.find_subcommand("bundle").expect("bundle command");
        let names = bundle
            .get_subcommands()
            .map(clap::Command::get_name)
            .collect::<Vec<_>>();
        assert_eq!(names, ["create", "show", "verify"]);
    }

    #[test]
    fn mixed_compiled_policy_and_workspace_pins_aggregate_deterministically() {
        let policy_a =
            "compiled:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let policy_b =
            "compiled:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let graph_a = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let graph_b = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

        let forward_policy =
            aggregate_admission_policy_hash(&[policy_a.to_owned(), policy_b.to_owned()])
                .expect("mixed compiled policy pins");
        let reverse_policy =
            aggregate_admission_policy_hash(&[policy_b.to_owned(), policy_a.to_owned()])
                .expect("reordered mixed compiled policy pins");
        let forward_graph = aggregate_sha256_pins(
            "child_workspace_graph_hashes",
            &[graph_a.to_owned(), graph_b.to_owned()],
        )
        .expect("mixed workspace pins");
        let reverse_graph = aggregate_sha256_pins(
            "child_workspace_graph_hashes",
            &[graph_b.to_owned(), graph_a.to_owned()],
        )
        .expect("reordered mixed workspace pins");

        assert_eq!(forward_policy, reverse_policy);
        assert!(forward_policy.starts_with("compiled:sha256:"));
        assert_eq!(forward_graph, reverse_graph);
        assert!(forward_graph.starts_with("sha256:"));
    }

    #[test]
    fn distinct_active_admission_bundles_fail_closed() {
        let first =
            "bundle:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let second =
            "bundle:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        let error = aggregate_admission_policy_hash(&[first.to_owned(), second.to_owned()])
            .expect_err("different active bundles must not aggregate");

        assert!(error.to_string().contains("active admission policy bundle"));
    }
}
