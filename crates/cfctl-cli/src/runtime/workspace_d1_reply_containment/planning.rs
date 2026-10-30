use super::super::{
    prelude::{CallInput, CapabilityV1, CatalogSnapshot, ProfileMetadata, Result, StateStore},
    workspace_d1_config, workspace_d1_recovery,
};
use super::{
    authority,
    compiler::BoundCompiler,
    config_value, contract, rebind_source, rejected,
    stage::{self, PrivateStage},
    transport,
};
use cfctl_core::reply_lifecycle::containment::{
    CompiledReplyContainmentV3, ReplyContainmentRequestV3,
    evidence::{NativeContainmentReadV3, NativeReadPhaseV3},
};
use cfctl_core::{PlanV1, ReplyContainmentOperationV3};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredCandidate {
    prepared_at: DateTime<Utc>,
    request: ReplyContainmentRequestV3,
    pre_read: Value,
    compiled: Value,
}
pub(super) struct BoundPlan {
    pub candidate: CompiledReplyContainmentV3,
    pub stage: PrivateStage,
    pub config: workspace_d1_config::ValidatedConfig,
    pub producer: Value,
}

pub(in crate::runtime) fn prepare_plan_target(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    profile: &ProfileMetadata,
    account: &str,
    source: &std::path::Path,
) -> Result<Value> {
    let c = contract(capability)?;
    if c.operation_kind != ReplyContainmentOperationV3::Apply {
        return Err(rejected());
    }
    rebind_source(store, capability)?;
    if input.body.is_some() || input.query.as_object().is_none_or(|v| v.len() != 1) {
        return Err(rejected());
    }
    let config = workspace_d1_config::validated_config(c.into(), input)?;
    let mut value: Value = serde_json::from_slice(&stage::read_input(source)?)?;
    let pre_read = value
        .as_object_mut()
        .and_then(|v| v.remove("pre_read"))
        .ok_or_else(rejected)?;
    authenticate_pre_read(store, &pre_read)?;
    let request = ReplyContainmentRequestV3::from_value(value).map_err(|_| rejected())?;
    validate_request_authority(&request, c, profile, account, &config.database_id)?;
    let bound_compiler = BoundCompiler::new(store, c)?;
    let mut compiler_input = serde_json::to_value(&request)?;
    compiler_input
        .as_object_mut()
        .ok_or_else(rejected)?
        .insert("pre_read".into(), pre_read.clone());
    let compiled = bound_compiler.compile(&compiler_input, false)?;
    let now = Utc::now();
    CompiledReplyContainmentV3::bind(request.clone(), &pre_read, &compiled, now)
        .map_err(|_| rejected())?;
    let stored = StoredCandidate {
        prepared_at: now,
        request,
        pre_read,
        compiled,
    };
    let private_stage = stage::write(store, &serde_json::to_value(stored)?)?;
    let generation = super::super::read_execution::credential_generation_for_read(profile)?;
    let recovery = workspace_d1_recovery::fresh_recovery_proof(
        store,
        catalog,
        input,
        &profile.id,
        account,
        &generation,
        c.recovery_max_age_seconds,
        now,
    )?;
    with_recovery_identity(
        json!({"schema_version":3,"config":config_value(&config),"authority":authority(profile,account,&config.database_id)?,
        "compiler":bound_compiler.identity(),"producer":transport::producer(c)?,"private_stage":private_stage,"recovery":recovery}),
        &profile.id,
        account,
        &generation,
    )
}

fn with_recovery_identity(
    mut target: Value,
    profile: &str,
    account: &str,
    generation: &str,
) -> Result<Value> {
    let fields = target.as_object_mut().ok_or_else(rejected)?;
    fields.insert("profile_id".into(), json!(profile));
    fields.insert("account_id".into(), json!(account));
    fields.insert("credential_generation_id".into(), json!(generation));
    Ok(target)
}

fn authenticate_pre_read(store: &StateStore, value: &Value) -> Result<()> {
    let read = NativeContainmentReadV3::from_value(value.clone()).map_err(|_| rejected())?;
    let hash = read.storage_content_hash().map_err(|_| rejected())?;
    let stored = store.load_reply_containment_read(&hash, NativeReadPhaseV3::PreRead)?;
    if stored.body() != value {
        return Err(rejected());
    }
    Ok(())
}

pub(super) fn validate_request_authority(
    request: &ReplyContainmentRequestV3,
    c: &cfctl_core::WorkspaceD1ReplyContainmentContractV3,
    profile: &ProfileMetadata,
    account: &str,
    database: &str,
) -> Result<()> {
    if request.candidate.head != c.repository_head
        || request.candidate.tree != c.repository_tree
        || request.control_plane != authority(profile, account, database)?
    {
        return Err(rejected());
    }
    Ok(())
}

pub(super) fn target(plan: &PlanV1) -> Result<&Value> {
    plan.targets
        .pointer("/adapter/workspace_d1_reply_containment")
        .ok_or_else(rejected)
}
pub(super) fn historical_candidate(
    store: &StateStore,
    plan: &PlanV1,
) -> Result<(CompiledReplyContainmentV3, PrivateStage)> {
    let stage: PrivateStage = serde_json::from_value(target(plan)?["private_stage"].clone())?;
    let stored: StoredCandidate = serde_json::from_value(stage::load(store, &stage)?)?;
    authenticate_pre_read(store, &stored.pre_read)?;
    let candidate = CompiledReplyContainmentV3::bind(
        stored.request,
        &stored.pre_read,
        &stored.compiled,
        stored.prepared_at,
    )
    .map_err(|_| rejected())?;
    Ok((candidate, stage))
}

pub(super) fn rebind(store: &StateStore, plan: &PlanV1, fresh: bool) -> Result<BoundPlan> {
    let c = contract(&plan.capability)?;
    rebind_source(store, &plan.capability)?;
    let input: CallInput = serde_json::from_value(plan.input.clone())?;
    let config = workspace_d1_config::validated_config(c.into(), &input)?;
    let profiles = crate::profiles::ProfilesConfig::load(store)?;
    let profile = profiles.selected(Some(&plan.profile_id))?;
    let target = target(plan)?;
    let bound_compiler = BoundCompiler::new(store, c)?;
    let producer = transport::producer(c)?;
    if target["schema_version"] != 3
        || target["profile_id"] != profile.id
        || target["account_id"] != plan.account_id
        || target["credential_generation_id"]
            != super::super::read_execution::credential_generation_for_read(profile)?
        || target["config"] != config_value(&config)
        || target["compiler"] != *bound_compiler.identity()
        || target["producer"] != producer
        || target["authority"]
            != serde_json::to_value(authority(profile, &plan.account_id, &config.database_id)?)?
    {
        return Err(rejected());
    }
    let (candidate, stage) = historical_candidate(store, plan)?;
    validate_request_authority(
        candidate.request(),
        c,
        profile,
        &plan.account_id,
        &config.database_id,
    )?;
    if fresh {
        candidate
            .request()
            .validate_fresh(Utc::now())
            .map_err(|_| rejected())?;
        workspace_d1_recovery::validate_recovery_target(
            store,
            target.as_object().ok_or_else(rejected)?,
            &plan.catalog_hash,
            c.recovery_max_age_seconds,
            Utc::now(),
        )?;
    }
    Ok(BoundPlan {
        candidate,
        stage,
        config,
        producer,
    })
}
pub(in crate::runtime) fn validate_bound_plan(store: &StateStore, plan: &PlanV1) -> Result<()> {
    if plan.capability.reply_containment_contract().is_some() {
        rebind(store, plan, true)?;
    }
    Ok(())
}

/// Reacquire local authority after the provider pre-read and producer probe.
/// Avoid another compiler/probe delay; the final checks are clock-bound below.
pub(super) fn validate_dispatch(store: &StateStore, plan: &PlanV1) -> Result<()> {
    if Utc::now() > plan.expires_at {
        return Err(rejected());
    }
    let c = contract(&plan.capability)?;
    let current = cfctl_workspace::load_workspace_d1_reply_containment_capability(
        &store.workspace_roots()?,
        &plan.capability.id,
    )?
    .ok_or_else(rejected)?;
    let observed_source = contract(&current)?;
    let input: CallInput = serde_json::from_value(plan.input.clone())?;
    let config = workspace_d1_config::validated_config(observed_source.into(), &input)?;
    let target = target(plan)?;
    if target["config"] != config_value(&config) {
        return Err(rejected());
    }
    let profiles = crate::profiles::ProfilesConfig::load(store)?;
    let profile = profiles.selected(Some(&plan.profile_id))?;
    let observed_authority = authority(profile, &plan.account_id, &config.database_id)?;
    let (candidate, _) = historical_candidate(store, plan)?;
    dispatch_values(
        candidate.request(),
        c,
        observed_source,
        &observed_authority,
        Utc::now(),
    )?;
    workspace_d1_recovery::validate_recovery_target(
        store,
        target.as_object().ok_or_else(rejected)?,
        &plan.catalog_hash,
        c.recovery_max_age_seconds,
        Utc::now(),
    )?;
    if Utc::now() > plan.expires_at {
        return Err(rejected());
    }
    candidate
        .request()
        .validate_fresh(Utc::now())
        .map_err(|_| rejected())
}

fn dispatch_values(
    request: &ReplyContainmentRequestV3,
    expected: &cfctl_core::WorkspaceD1ReplyContainmentContractV3,
    current: &cfctl_core::WorkspaceD1ReplyContainmentContractV3,
    authority: &cfctl_core::reply_lifecycle::containment::ReplyContainmentAuthorityV3,
    now: DateTime<Utc>,
) -> Result<()> {
    if expected != current || &request.control_plane != authority {
        return Err(rejected());
    }
    request.validate_fresh(now).map_err(|_| rejected())
}

#[cfg(test)]
mod tests {
    use super::super::test_support;
    use super::{dispatch_values, with_recovery_identity};
    use crate::runtime::workspace_d1_recovery;
    use cfctl_core::reply_lifecycle::containment::ReplyContainmentRequestV3;
    use cfctl_storage::StateStore;
    use chrono::{DateTime, Utc};
    use serde_json::json;

    #[test]
    fn containment_target_joins_actual_shared_recovery_evidence()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        use cfctl_auth::{EvidenceKeyManager, MemorySecretStore, SecretBackend};
        use std::sync::Arc;
        let root = tempfile::tempdir()?;
        let store = StateStore::open(super::super::super::prelude::RuntimePaths::from_root(
            &root.path().canonicalize()?,
        ))?;
        let manager = Arc::new(EvidenceKeyManager::new(
            Arc::new(MemorySecretStore::default()),
            store.evidence_location_identity(),
            SecretBackend::Memory,
        )?);
        let identity = format!("sha256:{}", "f".repeat(64));
        manager.initialize(&identity)?;
        store.initialize_evidence_root_identity(&identity)?;
        let store = store.with_evidence_authenticator(manager)?;
        let now = Utc::now();
        let bookmark = "fixture-bookmark";
        let evidence = store.write_evidence(
            cfctl_core::EvidenceClass::LiveRead,
            &json!({"status":200,"success":true,"result":{"bookmark":bookmark}}),
        )?;
        let recovery = json!({"observed_at":now-chrono::Duration::seconds(1),"evidence_hash":evidence.content_hash,"catalog_hash":"catalog",
            "profile_id":"profile","account_id":"account","credential_generation_id":"generation","bookmark":bookmark,
            "bookmark_hash":cfctl_core::hash_value(&json!(bookmark))?});
        let target = with_recovery_identity(
            json!({"recovery":recovery}),
            "profile",
            "account",
            "generation",
        )?;
        workspace_d1_recovery::validate_recovery_target(
            &store,
            target.as_object().ok_or("target")?,
            "catalog",
            600,
            now,
        )?;
        for field in ["profile_id", "account_id", "credential_generation_id"] {
            let mut wrong = target.clone();
            wrong[field] = json!("wrong");
            assert!(
                workspace_d1_recovery::validate_recovery_target(
                    &store,
                    wrong.as_object().ok_or("target")?,
                    "catalog",
                    600,
                    now
                )
                .is_err()
            );
        }
        assert!(
            workspace_d1_recovery::validate_recovery_target(
                &store,
                target.as_object().ok_or("target")?,
                "catalog",
                600,
                now + chrono::Duration::seconds(601)
            )
            .is_err()
        );
        Ok(())
    }
    #[test]
    fn final_dispatch_gate_rejects_time_source_and_generation_drift()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let fixture = test_support::fixture()?;
        let request = ReplyContainmentRequestV3::from_value(fixture["request"].clone())?;
        let now: DateTime<Utc> = serde_json::from_value(fixture["now"].clone())?;
        let expected = test_support::contract();
        assert!(
            dispatch_values(&request, &expected, &expected, &request.control_plane, now).is_ok()
        );
        assert!(
            dispatch_values(
                &request,
                &expected,
                &expected,
                &request.control_plane,
                now + chrono::Duration::minutes(5)
            )
            .is_err()
        );
        let mut current = expected.clone();
        current.repository_head = "c".repeat(40);
        assert!(
            dispatch_values(&request, &expected, &current, &request.control_plane, now).is_err()
        );
        let mut authority = request.control_plane.clone();
        authority.credential_generation_sha256 = format!("sha256:{}", "f".repeat(64));
        assert!(dispatch_values(&request, &expected, &expected, &authority, now).is_err());
        Ok(())
    }
}
