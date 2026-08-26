use super::entitlement_state::pages_project_name;
use super::entitlement_state::read_live_pages_project_absence;
use super::entitlement_state::should_bind_pages_project_absence;
use super::live_state_contracts::is_cloudflare_tunnel_configuration_mutation;
use super::live_state_contracts::is_d1_database_delete;
use super::live_state_contracts::is_d1_read_replication_mutation;
use super::live_state_contracts::is_global_warp_override_mutation;
use super::live_state_contracts::should_bind_cloudflare_tunnel_configuration_state;
use super::live_state_contracts::should_bind_d1_empty_database_state;
use super::live_state_contracts::should_bind_d1_read_replication_state;
use super::live_state_contracts::should_bind_global_warp_override_state;
use super::pages_deployment::{
    PROJECT_ABSENCE_PRECONDITION, PROJECT_CREATE_CAPABILITY_ID, PROJECT_DETAIL_PATH,
    PROJECT_READ_CAPABILITY_ID,
};
use super::plan_create::read_live_pages_deployment_project_state;
use super::plan_create::read_live_worker_deployment_state;
use super::plan_secret::CLOUDFLARE_TUNNEL_CONFIGURATION_PATH;
use super::plan_secret::CLOUDFLARE_TUNNEL_CONFIGURATION_READ_CAPABILITY_ID;
use super::plan_secret::CLOUDFLARE_TUNNEL_CONFIGURATION_STATE_PRECONDITION;
use super::plan_secret::D1_DATABASE_CREATE_CAPABILITY_ID;
use super::plan_secret::D1_DATABASE_DELETE_CAPABILITY_ID;
use super::plan_secret::D1_EMPTY_DATABASE_PRECONDITION;
use super::plan_secret::D1_READ_REPLICATION_PATH;
use super::plan_secret::D1_READ_REPLICATION_PRECONDITION;
use super::plan_secret::D1_READ_REPLICATION_READ_CAPABILITY_ID;
use super::plan_secret::GLOBAL_WARP_OVERRIDE_MUTATION_CAPABILITY_ID;
use super::plan_secret::GLOBAL_WARP_OVERRIDE_PATH;
use super::plan_secret::GLOBAL_WARP_OVERRIDE_READ_CAPABILITY_ID;
use super::prelude::{
    AuthCredential, CallInput, CatalogSnapshot, CliError, EvidenceV1, PlanV1, Result, StateStore,
    Value, json,
};
use super::provider_state::read_live_cloudflare_tunnel_configuration_state;
use super::provider_state::read_live_d1_empty_database_state;
use super::provider_state::read_live_d1_read_replication_state;
use super::provider_state::read_live_global_warp_override_state;
use super::r2_credentials::R2_PARENT_TOKEN_PRECONDITION;
use super::r2_credentials::R2_PARENT_TOKEN_VERIFY_CAPABILITY_ID;
use super::r2_credentials::R2_PARENT_TOKEN_VERIFY_PATH;
use super::r2_credentials::is_r2_temporary_credentials_operation_identity;
use super::r2_credentials::preflight_call_input;
use super::r2_credentials::r2_delegated_scope;
use super::r2_credentials::r2_parent_permission_contract;
use super::r2_credentials::read_live_r2_parent_token;
use super::r2_credentials::should_bind_r2_parent_token;
use super::{pages_deployment, worker_deployment};
use cfctl_core::hash_value;

pub(super) async fn validate_live_r2_parent_token_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    plan: &PlanV1,
    input: &CallInput,
    credential: &AuthCredential,
) -> Result<Option<EvidenceV1>> {
    let Some(expected_hash) = required_r2_parent_token_precondition(plan)? else {
        return Ok(None);
    };
    let mut current_input = input.clone();
    let (receipt, evidence) = read_live_r2_parent_token(
        store,
        catalog,
        &plan.capability,
        &mut current_input,
        &plan.account_id,
        credential,
    )
    .await?;
    if hash_value(&receipt)? != expected_hash {
        return Err(CliError::Input(
            "active R2 parent-token identity or status drifted after planning; the mutation boundary was not crossed and a new plan is required"
                .to_owned(),
        ));
    }
    Ok(Some(evidence))
}

pub(super) fn validate_r2_parent_token_receipt(plan: &PlanV1, receipt: &Value) -> Result<()> {
    let input: CallInput = serde_json::from_value(plan.input.clone())?;
    let parent_access_key_id = input
        .body
        .as_ref()
        .and_then(|body| body.get("parentAccessKeyId"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "R2 temporary credential plan omitted its derived parent access-key id; create a new plan"
                    .to_owned(),
            )
        })?;
    let delegated_scope = r2_delegated_scope(&input)?;
    let permission = delegated_scope
        .get("permission")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "R2 temporary credential plan omitted its delegated permission; create a new plan"
                    .to_owned(),
            )
        })?;
    let expected_permission_contract = r2_parent_permission_contract(permission)?;
    let exact = receipt.as_object().is_some_and(|object| object.len() == 12)
        && receipt.get("schema_version").and_then(Value::as_u64) == Some(1)
        && receipt.get("source_capability_id").and_then(Value::as_str)
            == Some(R2_PARENT_TOKEN_VERIFY_CAPABILITY_ID)
        && receipt.get("source_path").and_then(Value::as_str) == Some(R2_PARENT_TOKEN_VERIFY_PATH)
        && receipt.get("target_capability_id").and_then(Value::as_str)
            == Some(plan.capability.id.as_str())
        && receipt.get("target_method").and_then(Value::as_str)
            == Some(plan.capability.method.as_str())
        && receipt.get("target_path").and_then(Value::as_str)
            == Some(plan.capability.path.as_str())
        && receipt.get("target_scope").and_then(Value::as_str) == Some("account")
        && receipt.get("account_id").and_then(Value::as_str) == Some(plan.account_id.as_str())
        && receipt.get("parent_access_key_id").and_then(Value::as_str)
            == Some(parent_access_key_id)
        && receipt.get("token_status").and_then(Value::as_str) == Some("active")
        && receipt.get("delegated_scope") == Some(&delegated_scope)
        && receipt.get("parent_permission_contract") == Some(&expected_permission_contract);
    if !exact {
        return Err(CliError::Input(
            "R2 temporary credential parent-token receipt has an invalid source, account, scope, permission, or active-token shape; create a new plan"
                .to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn required_r2_parent_token_precondition(plan: &PlanV1) -> Result<Option<&str>> {
    if !is_r2_temporary_credentials_operation_identity(&plan.capability) {
        return Ok(None);
    }
    if !should_bind_r2_parent_token(&plan.capability) || plan.permission_lane != "api_token" {
        return Err(CliError::Input(
            "R2 temporary credential plan is inconsistent with its hash-bound scoped API-token parent contract; create a new plan"
                .to_owned(),
        ));
    }
    let expected_hash = plan
        .precondition_hashes
        .get(R2_PARENT_TOKEN_PRECONDITION)
        .map(String::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "plan predates the live R2 parent-token contract; create a new plan".to_owned(),
            )
        })?;
    let receipt = plan
        .targets
        .pointer("/live_preconditions/r2_parent_token")
        .ok_or_else(|| {
            CliError::Input(
                "plan predates the hash-bound R2 parent-token receipt; create a new plan"
                    .to_owned(),
            )
        })?;
    validate_r2_parent_token_receipt(plan, receipt)?;
    if hash_value(receipt)? != expected_hash {
        return Err(CliError::Input(
            "plan R2 parent-token receipt does not match its precondition hash; create a new plan"
                .to_owned(),
        ));
    }
    Ok(Some(expected_hash))
}

pub(super) fn validate_pages_project_absence_receipt(plan: &PlanV1, receipt: &Value) -> Result<()> {
    let input: CallInput = serde_json::from_value(plan.input.clone())?;
    let project_name = pages_project_name(&input)?;
    let exact = receipt.as_object().is_some_and(|object| object.len() == 10)
        && receipt.get("schema_version").and_then(Value::as_u64) == Some(1)
        && receipt.get("source_capability_id").and_then(Value::as_str)
            == Some(PROJECT_READ_CAPABILITY_ID)
        && receipt.get("source_path").and_then(Value::as_str) == Some(PROJECT_DETAIL_PATH)
        && receipt.get("target_capability_id").and_then(Value::as_str)
            == Some(PROJECT_CREATE_CAPABILITY_ID)
        && receipt.get("target_path").and_then(Value::as_str)
            == Some("/accounts/{account_id}/pages/projects")
        && receipt.get("target_scope").and_then(Value::as_str) == Some("account")
        && receipt.get("account_id").and_then(Value::as_str) == Some(plan.account_id.as_str())
        && receipt.get("project_name").and_then(Value::as_str) == Some(project_name)
        && receipt.get("http_status").and_then(Value::as_u64) == Some(404)
        && receipt.get("absent").and_then(Value::as_bool) == Some(true);
    if !exact {
        return Err(CliError::Input(
            "Pages project absence receipt has an invalid source, target, account, or absence shape; create a new plan"
                .to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn required_worker_deployment_state_precondition(plan: &PlanV1) -> Result<Option<&str>> {
    let adapter = plan.targets.get("adapter").unwrap_or(&Value::Null);
    if worker_deployment::target(adapter).is_none() {
        return Ok(None);
    }
    if !worker_deployment::binds_live_state(&plan.capability) {
        return Err(CliError::Input(
            "Worker deployment target is attached to an unrelated capability".to_owned(),
        ));
    }
    let expected_hash = plan
        .precondition_hashes
        .get(worker_deployment::STATE_PRECONDITION)
        .map(String::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "Worker deployment plan predates the exact live-state contract; create a new plan"
                    .to_owned(),
            )
        })?;
    let receipt = plan
        .targets
        .pointer(&format!(
            "/live_preconditions/{}",
            worker_deployment::STATE_PRECONDITION
        ))
        .ok_or_else(|| {
            CliError::Input(
                "Worker deployment plan omitted its hash-bound live-state receipt; create a new plan"
                    .to_owned(),
            )
        })?;
    worker_deployment::validate_state_receipt(plan, receipt)?;
    if hash_value(receipt)? != expected_hash {
        return Err(CliError::Input(
            "Worker deployment state receipt does not match its precondition hash; create a new plan"
                .to_owned(),
        ));
    }
    Ok(Some(expected_hash))
}

pub(super) async fn validate_live_worker_deployment_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    plan: &PlanV1,
    credential: &AuthCredential,
) -> Result<Option<EvidenceV1>> {
    let Some(expected_hash) = required_worker_deployment_state_precondition(plan)? else {
        return Ok(None);
    };
    let adapter = plan.targets.get("adapter").unwrap_or(&Value::Null);
    let (receipt, evidence) = read_live_worker_deployment_state(
        store,
        catalog,
        &plan.capability,
        adapter,
        &plan.account_id,
        credential,
    )
    .await?;
    validate_current_worker_deployment_state(expected_hash, &receipt)?;
    Ok(Some(evidence))
}

pub(super) fn validate_current_worker_deployment_state(
    expected_hash: &str,
    receipt: &Value,
) -> Result<()> {
    if hash_value(receipt)? != expected_hash {
        return Err(CliError::Input(
            "live Worker service state drifted after planning; the deployment boundary was not crossed and a new plan is required"
                .to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn required_pages_project_absence_precondition(plan: &PlanV1) -> Result<Option<&str>> {
    if !should_bind_pages_project_absence(&plan.capability) {
        return Ok(None);
    }
    let expected_hash = plan
        .precondition_hashes
        .get(PROJECT_ABSENCE_PRECONDITION)
        .map(String::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "Pages project creation plan predates the live exact-target absence contract; create a new plan"
                    .to_owned(),
            )
        })?;
    let receipt = plan
        .targets
        .pointer(&format!(
            "/live_preconditions/{PROJECT_ABSENCE_PRECONDITION}"
        ))
        .ok_or_else(|| {
            CliError::Input(
                "Pages project creation plan omitted its hash-bound target-absence receipt; create a new plan"
                    .to_owned(),
            )
        })?;
    validate_pages_project_absence_receipt(plan, receipt)?;
    if hash_value(receipt)? != expected_hash {
        return Err(CliError::Input(
            "Pages project target-absence receipt does not match its precondition hash; create a new plan"
                .to_owned(),
        ));
    }
    Ok(Some(expected_hash))
}

pub(super) async fn validate_live_pages_project_absence_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    plan: &PlanV1,
    input: &CallInput,
    credential: &AuthCredential,
) -> Result<Option<EvidenceV1>> {
    let Some(expected_hash) = required_pages_project_absence_precondition(plan)? else {
        return Ok(None);
    };
    let (receipt, evidence) = read_live_pages_project_absence(
        store,
        catalog,
        &plan.capability,
        input,
        &plan.account_id,
        credential,
    )
    .await?;
    if hash_value(&receipt)? != expected_hash {
        return Err(CliError::Input(
            "live Pages project target state drifted after planning; the creation boundary was not crossed and a new plan is required"
                .to_owned(),
        ));
    }
    Ok(Some(evidence))
}

pub(super) fn required_pages_deployment_project_state_precondition(
    plan: &PlanV1,
) -> Result<Option<&str>> {
    if !pages_deployment::binds_project_state(&plan.capability) {
        return Ok(None);
    }
    let expected_hash = plan
        .precondition_hashes
        .get(pages_deployment::PROJECT_STATE_PRECONDITION)
        .map(String::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "Pages deployment plan predates exact project-mode admission; create a new plan"
                    .to_owned(),
            )
        })?;
    let receipt = plan
        .targets
        .pointer(&format!(
            "/live_preconditions/{}",
            pages_deployment::PROJECT_STATE_PRECONDITION
        ))
        .ok_or_else(|| {
            CliError::Input(
                "Pages deployment plan omitted its hash-bound project-mode receipt; create a new plan"
                    .to_owned(),
            )
        })?;
    let input: CallInput = serde_json::from_value(plan.input.clone())?;
    let project_name = pages_deployment::project_name(&plan.capability, &input)?;
    let expected_mode = if pages_deployment::binds_artifact(&plan.capability) {
        "direct_upload"
    } else {
        "git_integrated"
    };
    if receipt.get("schema_version").and_then(Value::as_u64) != Some(1)
        || receipt.get("source_capability_id").and_then(Value::as_str)
            != Some(pages_deployment::PROJECT_READ_CAPABILITY_ID)
        || receipt.get("target_capability_id").and_then(Value::as_str)
            != Some(plan.capability.id.as_str())
        || receipt.get("account_id").and_then(Value::as_str) != Some(plan.account_id.as_str())
        || receipt.get("project_name").and_then(Value::as_str) != Some(project_name)
        || !pages_deployment::receipt_source_mode_is_bound(receipt, expected_mode)
        || (pages_deployment::binds_artifact(&plan.capability)
            && receipt
                .get("prior_exact_identity_count")
                .and_then(Value::as_u64)
                != Some(0))
    {
        return Err(CliError::Input(
            "Pages deployment project-mode receipt has an invalid identity or replay shape; create a new plan"
                .to_owned(),
        ));
    }
    if hash_value(receipt)? != expected_hash {
        return Err(CliError::Input(
            "Pages deployment project-mode receipt does not match its precondition hash; create a new plan"
                .to_owned(),
        ));
    }
    Ok(Some(expected_hash))
}

pub(super) async fn validate_live_pages_deployment_project_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    plan: &PlanV1,
    input: &CallInput,
    credential: &AuthCredential,
) -> Result<Option<EvidenceV1>> {
    let Some(expected_hash) = required_pages_deployment_project_state_precondition(plan)? else {
        return Ok(None);
    };
    let (receipt, evidence) = read_live_pages_deployment_project_state(
        store,
        catalog,
        &plan.capability,
        input,
        &plan.account_id,
        credential,
    )
    .await?;
    if hash_value(&receipt)? != expected_hash {
        return Err(CliError::Input(
            "live Pages project mode or deployment identity set drifted after planning; the provider boundary was not crossed and a new plan is required"
                .to_owned(),
        ));
    }
    Ok(Some(evidence))
}

pub(super) async fn validate_live_global_warp_override_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    plan: &PlanV1,
    input: &CallInput,
    credential: &AuthCredential,
) -> Result<Option<EvidenceV1>> {
    let Some(expected_hash) = required_global_warp_override_state_precondition(plan)? else {
        return Ok(None);
    };
    let (receipt, evidence) = read_live_global_warp_override_state(
        store,
        catalog,
        &plan.capability,
        input,
        &plan.account_id,
        credential,
    )
    .await?;
    validate_global_warp_override_state_receipt_precondition(expected_hash, &receipt)?;
    Ok(Some(evidence))
}

pub(super) fn validate_global_warp_override_state_receipt_precondition(
    expected_hash: &str,
    receipt: &Value,
) -> Result<()> {
    if hash_value(receipt)? != expected_hash {
        return Err(CliError::Input(
            "live Global WARP override state drifted after planning; the mutation boundary was not crossed and a new plan is required"
                .to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn validate_global_warp_override_prior_state_receipt(
    plan: &PlanV1,
    receipt: &Value,
) -> Result<bool> {
    let exact_identity = receipt.as_object().is_some_and(|object| object.len() == 7)
        && receipt.get("schema_version").and_then(Value::as_u64) == Some(1)
        && receipt.get("source_capability_id").and_then(Value::as_str)
            == Some(GLOBAL_WARP_OVERRIDE_READ_CAPABILITY_ID)
        && receipt.get("source_path").and_then(Value::as_str) == Some(GLOBAL_WARP_OVERRIDE_PATH)
        && receipt.get("target_capability_id").and_then(Value::as_str)
            == Some(GLOBAL_WARP_OVERRIDE_MUTATION_CAPABILITY_ID)
        && receipt.get("target_scope").and_then(Value::as_str) == Some("account")
        && receipt.get("target_id").and_then(Value::as_str) == Some(plan.account_id.as_str());
    let disconnect = receipt.get("disconnect").and_then(Value::as_bool);
    if !exact_identity || disconnect.is_none() {
        return Err(CliError::Input(
            "plan Global WARP override prior-state receipt has an invalid account, source, or state shape; create a new plan"
                .to_owned(),
        ));
    }
    disconnect.ok_or_else(|| {
        CliError::Input(
            "plan Global WARP override prior-state receipt omitted boolean `disconnect`; create a new plan"
                .to_owned(),
        )
    })
}

pub(super) fn required_global_warp_override_state_precondition(
    plan: &PlanV1,
) -> Result<Option<&str>> {
    if !is_global_warp_override_mutation(&plan.capability) {
        return Ok(None);
    }
    if !should_bind_global_warp_override_state(&plan.capability) {
        return Err(CliError::Input(
            "Global WARP override plan is inconsistent with its hash-bound prior-state contract; create a new plan"
                .to_owned(),
        ));
    }
    let expected_hash = plan
        .precondition_hashes
        .get("global_warp_override_state")
        .map(String::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "plan predates the live Global WARP override prior-state contract; create a new plan"
                    .to_owned(),
            )
        })?;
    let receipt = plan
        .targets
        .pointer("/live_preconditions/global_warp_override_state")
        .ok_or_else(|| {
            CliError::Input(
                "plan predates the hash-bound Global WARP override prior-state receipt; create a new plan"
                    .to_owned(),
            )
        })?;
    validate_global_warp_override_prior_state_receipt(plan, receipt)?;
    if hash_value(receipt)? != expected_hash {
        return Err(CliError::Input(
            "plan Global WARP override prior-state receipt does not match its precondition hash; create a new plan"
                .to_owned(),
        ));
    }
    Ok(Some(expected_hash))
}

pub(super) fn global_warp_override_prior_disconnect_state(plan: &PlanV1) -> Result<bool> {
    required_global_warp_override_state_precondition(plan)?.ok_or_else(|| {
        CliError::Input(
            "Global WARP override compensation requires a hash-bound prior-state precondition"
                .to_owned(),
        )
    })?;
    let receipt = plan
        .targets
        .pointer("/live_preconditions/global_warp_override_state")
        .ok_or_else(|| {
            CliError::Input(
                "Global WARP override compensation requires a hash-bound prior-state receipt"
                    .to_owned(),
            )
        })?;
    validate_global_warp_override_prior_state_receipt(plan, receipt)
}

pub(super) async fn validate_live_d1_read_replication_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    plan: &PlanV1,
    input: &CallInput,
    credential: &AuthCredential,
) -> Result<Option<EvidenceV1>> {
    let Some(expected_hash) = required_d1_read_replication_state_precondition(plan)? else {
        return Ok(None);
    };
    let (receipt, evidence) = read_live_d1_read_replication_state(
        store,
        catalog,
        &plan.capability,
        input,
        &plan.account_id,
        credential,
    )
    .await?;
    if hash_value(&receipt)? != expected_hash {
        return Err(CliError::Input(
            "live D1 read-replication state drifted after planning; the mutation boundary was not crossed and a new plan is required"
                .to_owned(),
        ));
    }
    Ok(Some(evidence))
}

pub(super) fn validate_d1_empty_database_state_receipt(
    plan: &PlanV1,
    receipt: &Value,
) -> Result<()> {
    let adapter_targets = plan.targets.get("adapter").unwrap_or(&Value::Null);
    let database_id = plan
        .targets
        .pointer("/selectors/database_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "D1 compensation plan omitted its hash-bound database selector; create a new plan"
                    .to_owned(),
            )
        })?;
    let source_operation_id = adapter_targets
        .get("compensates_operation_id")
        .and_then(Value::as_str);
    let source_receipt_hash = adapter_targets
        .get("source_receipt_hash")
        .and_then(Value::as_str);
    let exact = receipt.as_object().is_some_and(|object| object.len() == 16)
        && receipt.get("schema_version").and_then(Value::as_u64) == Some(1)
        && receipt.get("source_capability_id").and_then(Value::as_str)
            == Some(D1_READ_REPLICATION_READ_CAPABILITY_ID)
        && receipt.get("source_path").and_then(Value::as_str) == Some(D1_READ_REPLICATION_PATH)
        && receipt.get("target_capability_id").and_then(Value::as_str)
            == Some(D1_DATABASE_DELETE_CAPABILITY_ID)
        && receipt.get("target_method").and_then(Value::as_str) == Some("DELETE")
        && receipt.get("target_path").and_then(Value::as_str) == Some(D1_READ_REPLICATION_PATH)
        && receipt.get("target_scope").and_then(Value::as_str) == Some("account")
        && receipt.get("account_id").and_then(Value::as_str) == Some(plan.account_id.as_str())
        && receipt.get("database_id").and_then(Value::as_str) == Some(database_id)
        && receipt
            .get("database_name")
            .and_then(Value::as_str)
            .is_some_and(|name| !name.is_empty())
        && receipt.get("num_tables").and_then(Value::as_u64) == Some(0)
        && receipt.get("file_size").and_then(Value::as_u64).is_some()
        && receipt
            .get("jurisdiction")
            .is_some_and(|value| value.is_null() || value.is_string())
        && receipt
            .pointer("/read_replication/mode")
            .and_then(Value::as_str)
            .is_some_and(|mode| matches!(mode, "auto" | "disabled"))
        && receipt
            .get("read_replication")
            .and_then(Value::as_object)
            .is_some_and(|state| state.len() == 1)
        && receipt
            .get("compensates_operation_id")
            .and_then(Value::as_str)
            == source_operation_id
        && receipt
            .get("source_create_receipt_hash")
            .and_then(Value::as_str)
            == source_receipt_hash;
    if !exact {
        return Err(CliError::Input(
            "plan D1 empty-state receipt has an invalid source create receipt, account, database, table count, or state shape; create a new plan"
                .to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn required_d1_empty_database_state_precondition(plan: &PlanV1) -> Result<Option<&str>> {
    let adapter_targets = plan.targets.get("adapter").unwrap_or(&Value::Null);
    if !is_d1_database_delete(&plan.capability)
        || adapter_targets
            .get("compensates_capability_id")
            .and_then(Value::as_str)
            != Some(D1_DATABASE_CREATE_CAPABILITY_ID)
    {
        return Ok(None);
    }
    if !should_bind_d1_empty_database_state(&plan.capability, adapter_targets) {
        return Err(CliError::Input(
            "D1 compensation plan is inconsistent with its hash-bound empty-database contract; create a new plan"
                .to_owned(),
        ));
    }
    let expected_hash = plan
        .precondition_hashes
        .get(D1_EMPTY_DATABASE_PRECONDITION)
        .map(String::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "D1 compensation plan predates the live empty-state contract; create a new plan"
                    .to_owned(),
            )
        })?;
    let receipt = plan
        .targets
        .pointer("/live_preconditions/d1_empty_database_state")
        .ok_or_else(|| {
            CliError::Input(
                "D1 compensation plan omitted its hash-bound empty-state receipt; create a new plan"
                    .to_owned(),
            )
        })?;
    validate_d1_empty_database_state_receipt(plan, receipt)?;
    if hash_value(receipt)? != expected_hash {
        return Err(CliError::Input(
            "plan D1 empty-state receipt does not match its precondition hash; create a new plan"
                .to_owned(),
        ));
    }
    Ok(Some(expected_hash))
}

pub(super) async fn validate_live_d1_empty_database_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    plan: &PlanV1,
    input: &CallInput,
    credential: &AuthCredential,
) -> Result<Option<EvidenceV1>> {
    let Some(expected_hash) = required_d1_empty_database_state_precondition(plan)? else {
        return Ok(None);
    };
    let adapter_targets = plan.targets.get("adapter").unwrap_or(&Value::Null);
    let (receipt, evidence) = read_live_d1_empty_database_state(
        store,
        catalog,
        &plan.capability,
        input,
        adapter_targets,
        &plan.account_id,
        credential,
    )
    .await?;
    if hash_value(&receipt)? != expected_hash {
        return Err(CliError::Input(
            "live D1 empty-database state drifted after planning; the delete boundary was not crossed and a new compensation review is required"
                .to_owned(),
        ));
    }
    Ok(Some(evidence))
}

pub(super) fn validate_d1_read_replication_prior_state_receipt(
    plan: &PlanV1,
    receipt: &Value,
) -> Result<String> {
    let database_id = plan
        .targets
        .pointer("/selectors/database_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "D1 plan omitted its hash-bound database selector; create a new plan".to_owned(),
            )
        })?;
    let exact_identity = receipt.as_object().is_some_and(|object| object.len() == 9)
        && receipt.get("schema_version").and_then(Value::as_u64) == Some(1)
        && receipt.get("source_capability_id").and_then(Value::as_str)
            == Some(D1_READ_REPLICATION_READ_CAPABILITY_ID)
        && receipt.get("source_path").and_then(Value::as_str) == Some(D1_READ_REPLICATION_PATH)
        && receipt.get("target_capability_id").and_then(Value::as_str)
            == Some(plan.capability.id.as_str())
        && receipt.get("target_method").and_then(Value::as_str)
            == Some(plan.capability.method.as_str())
        && receipt.get("target_scope").and_then(Value::as_str) == Some("account")
        && receipt.get("account_id").and_then(Value::as_str) == Some(plan.account_id.as_str())
        && receipt.get("database_id").and_then(Value::as_str) == Some(database_id);
    let replication = receipt.get("read_replication").and_then(Value::as_object);
    let mode = replication
        .and_then(|state| state.get("mode"))
        .and_then(Value::as_str)
        .filter(|mode| matches!(*mode, "auto" | "disabled"));
    if !exact_identity || replication.is_none_or(|state| state.len() != 1) || mode.is_none() {
        return Err(CliError::Input(
            "plan D1 prior-state receipt has an invalid account, database, source, method, or mode shape; create a new plan"
                .to_owned(),
        ));
    }
    mode.map(str::to_owned).ok_or_else(|| {
        CliError::Input(
            "plan D1 prior-state receipt omitted its bounded mode; create a new plan".to_owned(),
        )
    })
}

pub(super) fn required_d1_read_replication_state_precondition(
    plan: &PlanV1,
) -> Result<Option<&str>> {
    if !is_d1_read_replication_mutation(&plan.capability) {
        return Ok(None);
    }
    if !should_bind_d1_read_replication_state(&plan.capability) {
        return Err(CliError::Input(
            "D1 plan is inconsistent with its hash-bound prior-state contract; create a new plan"
                .to_owned(),
        ));
    }
    let expected_hash = plan
        .precondition_hashes
        .get(D1_READ_REPLICATION_PRECONDITION)
        .map(String::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "plan predates the live D1 prior-state contract; create a new plan".to_owned(),
            )
        })?;
    let receipt = plan
        .targets
        .pointer("/live_preconditions/d1_read_replication_state")
        .ok_or_else(|| {
            CliError::Input(
                "plan predates the hash-bound D1 prior-state receipt; create a new plan".to_owned(),
            )
        })?;
    validate_d1_read_replication_prior_state_receipt(plan, receipt)?;
    if hash_value(receipt)? != expected_hash {
        return Err(CliError::Input(
            "plan D1 prior-state receipt does not match its precondition hash; create a new plan"
                .to_owned(),
        ));
    }
    Ok(Some(expected_hash))
}

pub(super) fn d1_read_replication_prior_mode(plan: &PlanV1) -> Result<String> {
    required_d1_read_replication_state_precondition(plan)?.ok_or_else(|| {
        CliError::Input("D1 compensation requires a hash-bound prior-state precondition".to_owned())
    })?;
    let receipt = plan
        .targets
        .pointer("/live_preconditions/d1_read_replication_state")
        .ok_or_else(|| {
            CliError::Input("D1 compensation requires a hash-bound prior-state receipt".to_owned())
        })?;
    validate_d1_read_replication_prior_state_receipt(plan, receipt)
}

pub(super) async fn validate_live_cloudflare_tunnel_configuration_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    plan: &PlanV1,
    input: &CallInput,
    credential: &AuthCredential,
) -> Result<Option<EvidenceV1>> {
    let Some(expected_hash) = required_cloudflare_tunnel_configuration_state_precondition(plan)?
    else {
        return Ok(None);
    };
    let (receipt, evidence) = read_live_cloudflare_tunnel_configuration_state(
        store,
        catalog,
        &plan.capability,
        input,
        &plan.account_id,
        credential,
    )
    .await?;
    if hash_value(&receipt)? != expected_hash {
        return Err(CliError::Input(
            "live Tunnel configuration drifted after planning; the mutation boundary was not crossed and a new plan is required"
                .to_owned(),
        ));
    }
    Ok(Some(evidence))
}

pub(super) fn validate_cloudflare_tunnel_configuration_prior_state_receipt(
    plan: &PlanV1,
    receipt: &Value,
) -> Result<Value> {
    let tunnel_id = plan
        .targets
        .pointer("/selectors/tunnel_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "Tunnel configuration plan omitted its hash-bound Tunnel selector; create a new plan"
                    .to_owned(),
            )
        })?;
    let exact_identity = receipt.as_object().is_some_and(|object| object.len() == 10)
        && receipt.get("schema_version").and_then(Value::as_u64) == Some(1)
        && receipt.get("source_capability_id").and_then(Value::as_str)
            == Some(CLOUDFLARE_TUNNEL_CONFIGURATION_READ_CAPABILITY_ID)
        && receipt.get("source_path").and_then(Value::as_str)
            == Some(CLOUDFLARE_TUNNEL_CONFIGURATION_PATH)
        && receipt.get("target_capability_id").and_then(Value::as_str)
            == Some(plan.capability.id.as_str())
        && receipt.get("target_method").and_then(Value::as_str)
            == Some(plan.capability.method.as_str())
        && receipt.get("target_path").and_then(Value::as_str)
            == Some(plan.capability.path.as_str())
        && receipt.get("target_scope").and_then(Value::as_str) == Some("account")
        && receipt.get("account_id").and_then(Value::as_str) == Some(plan.account_id.as_str())
        && receipt.get("tunnel_id").and_then(Value::as_str) == Some(tunnel_id);
    let prior_config = receipt
        .get("prior_config")
        .filter(|config| config.is_object())
        .cloned();
    if !exact_identity || prior_config.is_none() {
        return Err(CliError::Input(
            "plan Tunnel configuration prior-state receipt has an invalid account, Tunnel, source, method, path, or state shape; create a new plan"
                .to_owned(),
        ));
    }
    let prior_config = prior_config.ok_or_else(|| {
        CliError::Input(
            "plan Tunnel configuration prior-state receipt omitted an object configuration; create a new plan"
                .to_owned(),
        )
    })?;
    let restore_input = CallInput {
        selectors: json!({"account_id": plan.account_id, "tunnel_id": tunnel_id}),
        body: Some(json!({"config": prior_config})),
        ..CallInput::default()
    };
    preflight_call_input(&plan.capability, &restore_input, None).map_err(|error| {
        CliError::Input(format!(
            "plan Tunnel configuration prior-state receipt is outside the exact restorable request contract; create a new plan: {error}"
        ))
    })?;
    restore_input
        .body
        .and_then(|body| body.get("config").cloned())
        .ok_or_else(|| {
            CliError::Input(
                "plan Tunnel configuration prior-state receipt omitted its validated configuration; create a new plan"
                    .to_owned(),
            )
        })
}

pub(super) fn required_cloudflare_tunnel_configuration_state_precondition(
    plan: &PlanV1,
) -> Result<Option<&str>> {
    if !is_cloudflare_tunnel_configuration_mutation(&plan.capability) {
        return Ok(None);
    }
    if !should_bind_cloudflare_tunnel_configuration_state(&plan.capability) {
        return Err(CliError::Input(
            "Tunnel configuration plan is inconsistent with its hash-bound prior-state contract; create a new plan"
                .to_owned(),
        ));
    }
    let expected_hash = plan
        .precondition_hashes
        .get(CLOUDFLARE_TUNNEL_CONFIGURATION_STATE_PRECONDITION)
        .map(String::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "plan predates the live Tunnel configuration prior-state contract; create a new plan"
                    .to_owned(),
            )
        })?;
    let receipt = plan
        .targets
        .pointer("/live_preconditions/cloudflare_tunnel_configuration_state")
        .ok_or_else(|| {
            CliError::Input(
                "plan predates the hash-bound Tunnel configuration prior-state receipt; create a new plan"
                    .to_owned(),
            )
        })?;
    validate_cloudflare_tunnel_configuration_prior_state_receipt(plan, receipt)?;
    if hash_value(receipt)? != expected_hash {
        return Err(CliError::Input(
            "plan Tunnel configuration prior-state receipt does not match its precondition hash; create a new plan"
                .to_owned(),
        ));
    }
    Ok(Some(expected_hash))
}

pub(super) fn cloudflare_tunnel_configuration_prior_snapshot(plan: &PlanV1) -> Result<Value> {
    required_cloudflare_tunnel_configuration_state_precondition(plan)?.ok_or_else(|| {
        CliError::Input(
            "Tunnel configuration compensation requires a hash-bound prior-state precondition"
                .to_owned(),
        )
    })?;
    let receipt = plan
        .targets
        .pointer("/live_preconditions/cloudflare_tunnel_configuration_state")
        .ok_or_else(|| {
            CliError::Input(
                "Tunnel configuration compensation requires a hash-bound prior-state receipt"
                    .to_owned(),
            )
        })?;
    validate_cloudflare_tunnel_configuration_prior_state_receipt(plan, receipt)
}
