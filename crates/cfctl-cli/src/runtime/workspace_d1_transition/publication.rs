//! Join already-authenticated publication effects to the application's exact source and D1.
use std::path::Path;

use cfctl_cloudflare::CloudflareResponseV1;
use cfctl_core::workspace_d1::transition::{PublicationRef, lower_hex};
use cfctl_workspace::load_wrangler_config_snapshot;
use serde_json::json;

use super::{
    CallInput, DateTime, Duration, EffectRef, PlanV2, ProofRef, Result, Scope, StateStore, Utc,
    Value, WorkspaceD1MigrationContractV1, effect, hash_value, invalid, read,
};
use crate::runtime::worker_deployment;

fn text<'a>(value: &'a Value, pointer: &str) -> Result<&'a str> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| invalid("publication omitted a required identity"))
}

fn target<'a>(plan: &'a PlanV2, contract: &WorkspaceD1MigrationContractV1) -> Result<&'a Value> {
    let target = plan
        .plan
        .targets
        .pointer("/adapter/worker_deployment")
        .ok_or_else(|| invalid("publication has no native Worker target"))?;
    let path = Path::new(&contract.repository_root).join(&contract.config_template_path);
    let (config_path, config_hash) = match text(target, "/config/authority")? {
        "exact_head_blob" => ("/config/path", "/config/sha256"),
        "private_d1_identity_overlay" => ("/config/template_path", "/config/template_sha256"),
        _ => {
            return Err(invalid(
                "publication configuration authority is unsupported",
            ));
        }
    };
    if text(target, "/repository")? != contract.repository_root
        || text(target, "/source_sha")? != contract.repository_head
        || Path::new(text(target, config_path)?) != path
        || format!("sha256:{}", text(target, config_hash)?) != contract.config_template_sha256
    {
        return Err(invalid(
            "publication repository, source or configuration differs",
        ));
    }
    Ok(target)
}

fn verified_version(
    store: &StateStore,
    reference: &EffectRef,
    now: DateTime<Utc>,
) -> Result<(String, DateTime<Utc>)> {
    let evidence = store.load_evidence(&reference.evidence_hash)?;
    let value = store.read_evidence_value(&reference.evidence_hash)?;
    let version = text(&value, "/version_id")?;
    if value.get("passed").and_then(Value::as_bool) != Some(true)
        || !worker_deployment::canonical_worker_version_id(version)
        || evidence.generated_at >= now
    {
        return Err(invalid(
            "publication lacks successful native version verification",
        ));
    }
    Ok((version.to_owned(), evidence.generated_at))
}

fn artifact_message(target: &Value, contract: &WorkspaceD1MigrationContractV1) -> Result<String> {
    let digest = text(target, "/artifact/sha256")?;
    let expected = format!(
        "source={} artifact-sha256={digest}",
        contract.repository_head
    );
    if !lower_hex(digest, 64) || text(target, "/version_message")? != expected {
        return Err(invalid("publication artifact or source message differs"));
    }
    Ok(expected)
}

fn publication_message(
    store: &StateStore,
    plan: &PlanV2,
    contract: &WorkspaceD1MigrationContractV1,
    reference: &PublicationRef,
    scope: &Scope<'_>,
    now: DateTime<Utc>,
) -> Result<(String, String, DateTime<Utc>)> {
    let target = target(plan, contract)?;
    let (version, at) = verified_version(store, &reference.effect, now)?;
    let message = match (plan.plan.capability.id.as_str(), &reference.upload) {
        ("wrangler.deploy", None) => artifact_message(target, contract)?,
        ("wrangler.versions-deploy", Some(upload)) => {
            let uploaded = effect(store, upload, scope)?;
            let upload_target = target_for_upload(&uploaded, contract, target)?;
            let (uploaded_version, uploaded_at) = verified_version(store, upload, now)?;
            if uploaded_version != version
                || uploaded_at >= at
                || text(target, "/promotion/version_id")? != version
                || target
                    .pointer("/promotion/traffic_percentage")
                    .and_then(Value::as_u64)
                    != Some(100)
            {
                return Err(invalid(
                    "promotion does not follow the exact verified upload",
                ));
            }
            artifact_message(upload_target, contract)?
        }
        _ => {
            return Err(invalid(
                "publication requires deploy or verified upload and promotion",
            ));
        }
    };
    Ok((version, message, at))
}

fn target_for_upload<'a>(
    uploaded: &'a PlanV2,
    contract: &WorkspaceD1MigrationContractV1,
    promoted: &Value,
) -> Result<&'a Value> {
    let target = target(uploaded, contract)?;
    if uploaded.plan.capability.id != "wrangler.versions-upload"
        || target.get("service_name") != promoted.get("service_name")
        || target.get("config") != promoted.get("config")
    {
        return Err(invalid(
            "upload and promotion target different Workers or configuration",
        ));
    }
    Ok(target)
}

fn response(
    store: &StateStore,
    reference: &ProofRef,
    scope: &Scope<'_>,
    capability: &str,
    selectors: Value,
    after: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<(CloudflareResponseV1, DateTime<Utc>)> {
    let proof = read(store, reference, scope, now)?;
    let input = CallInput {
        selectors,
        query: json!({}),
        ..CallInput::default()
    };
    if proof.capability_id != capability
        || proof.input_hash != hash_value(&serde_json::to_value(input)?)?
        || proof.observed_at < after.max(now - Duration::seconds(600))
        || proof.evidence.generated_at < after
    {
        return Err(invalid(
            "publication read target or observation time differs",
        ));
    }
    let body: CloudflareResponseV1 =
        serde_json::from_value(store.read_evidence_value(&reference.evidence_hash)?)
            .map_err(|_| invalid("publication read body is malformed"))?;
    if !body.success || !(200..300).contains(&body.status) || !body.errors.is_empty() {
        return Err(invalid("publication provider read did not succeed"));
    }
    Ok((body, proof.observed_at.max(proof.evidence.generated_at)))
}

fn database_binding(value: &Value, pointer: &str, name: &str, database: &str) -> Result<()> {
    let bindings = value
        .pointer(pointer)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("publication read omitted Worker bindings"))?;
    let matching: Vec<_> = bindings
        .iter()
        .filter(|b| b.get("name").and_then(Value::as_str) == Some(name))
        .collect();
    if matching.len() != 1
        || matching[0].get("type").and_then(Value::as_str) != Some("d1")
        || matching[0].get("id").and_then(Value::as_str) != Some(database)
    {
        return Err(invalid(
            "published Worker D1 binding differs from migration target",
        ));
    }
    Ok(())
}

pub(super) fn validate(
    store: &StateStore,
    contract: &WorkspaceD1MigrationContractV1,
    reference: &PublicationRef,
    migration_scope: &Scope<'_>,
    now: DateTime<Utc>,
) -> Result<DateTime<Utc>> {
    let published = store.load_plan_v2(&reference.effect.operation_id)?;
    // Worker and D1 credentials have different permissions; authenticate each in its own lane.
    let scope = Scope {
        profile: &published.plan.profile_id,
        generation: &published.pins.credential_generation_id,
        ..*migration_scope
    };
    let published = effect(store, &reference.effect, &scope)?;
    let target = target(&published, contract)?;
    let config = load_wrangler_config_snapshot(
        &Path::new(&contract.repository_root).join(&contract.config_template_path),
    )?;
    let name = text(&config.document, "/name")?;
    if config.content_hash != contract.config_template_sha256
        || text(target, "/service_name")? != name
    {
        return Err(invalid(
            "published Worker differs from the committed configuration",
        ));
    }
    let (version, message, after) =
        publication_message(store, &published, contract, reference, &scope, now)?;
    let selectors = json!({"account_id":scope.account,"script_name":name});
    let (deployments, deployment_at) = response(
        store,
        &reference.verification,
        &scope,
        worker_deployment::DEPLOYMENTS_CAPABILITY_ID,
        selectors.clone(),
        after,
        now,
    )?;
    let (_, active) = worker_deployment::current_active_deployment_identity(&deployments.result)?;
    let (detail, version_at) = response(
        store,
        &reference.version,
        &scope,
        worker_deployment::VERSION_CAPABILITY_ID,
        json!({"account_id":scope.account,"script_name":name,"version_id":version}),
        after,
        now,
    )?;
    if active != version
        || !crate::runtime::delegated_execution::wrangler_version_readback_matches(
            &detail.result,
            &version,
            &message,
        )
    {
        return Err(invalid(
            "active Worker version or artifact annotation differs",
        ));
    }
    let (settings, settings_at) = response(
        store,
        &reference.settings,
        &scope,
        worker_deployment::SETTINGS_CAPABILITY_ID,
        selectors,
        after,
        now,
    )?;
    let declaration = &contract
        .transition
        .as_ref()
        .ok_or_else(|| invalid("transition missing"))?
        .declaration;
    database_binding(
        &detail.result,
        "/resources/bindings",
        &declaration.database_binding,
        &declaration.database_id,
    )?;
    database_binding(
        &settings.result,
        "/bindings",
        &declaration.database_binding,
        &declaration.database_id,
    )?;
    Ok(deployment_at.max(version_at).max(settings_at))
}

#[cfg(test)]
mod tests;
