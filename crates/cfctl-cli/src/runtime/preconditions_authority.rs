use super::access_ownership::read_live_access_operator_group_policy_ownership;
use super::access_policy::access_operator_group_policy_identity;
use super::access_policy::is_access_operator_group_policy_create;
use super::access_policy::is_access_operator_group_policy_update;
use super::cloudflare_api::BASE_URL as API_BASE_URL;
use super::entitlement_state::read_live_entitlement_probe;
use super::entitlement_state::read_live_zone_account;
use super::entitlement_state::read_live_zone_entitlement;
use super::import_planning::SECURITY_ACTION_STATE_PRECONDITION;
use super::import_planning::SECURITY_IP_RULE_COLLECTION_PATH;
use super::import_planning::SECURITY_IP_RULE_STATE_CAPABILITY_ID;
use super::keys_commands::validate_selected_permission_groups;
use super::plan_prepare::token_permission_inventory_contract;
use super::plan_secret::ACCESS_OPERATOR_GROUP_POLICY_OWNERSHIP_PRECONDITION;
use super::plan_secret::ACCESS_POLICY_COLLECTION_PATH;
use super::plan_secret::ACCESS_POLICY_LIST_CAPABILITY_ID;
use super::prelude::{
    AuthCredential, CallInput, CapabilityV1, CatalogSnapshot, CliError, EvidenceClass, EvidenceV1,
    Executor, PlanV1, Result, StandingAuthorityV1, StateStore, Value, json,
};
use super::security_action_state::read_live_security_action_state;
use super::security_action_state::should_bind_security_action_state;
use super::support::http_client;
use cfctl_core::hash_value;

pub(super) fn validate_access_operator_group_policy_ownership_receipt(
    plan: &PlanV1,
    receipt: &Value,
) -> Result<()> {
    let input: CallInput = serde_json::from_value(plan.input.clone())?;
    let (name, group_id) = access_operator_group_policy_identity(&input)?;
    let app_id = input
        .selectors
        .get("app_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty());
    let create = is_access_operator_group_policy_create(&plan.capability);
    let update = is_access_operator_group_policy_update(&plan.capability);
    let selected_policy_matches = if create {
        receipt.get("selected_policy_id") == Some(&Value::Null)
    } else {
        receipt.get("selected_policy_id") == input.selectors.get("policy_id")
    };
    let valid = (create || update)
        && receipt.as_object().is_some_and(|object| object.len() == 15)
        && receipt.get("schema_version").and_then(Value::as_u64) == Some(1)
        && receipt.get("source_capability_id").and_then(Value::as_str)
            == Some(ACCESS_POLICY_LIST_CAPABILITY_ID)
        && receipt.get("source_path").and_then(Value::as_str)
            == Some(ACCESS_POLICY_COLLECTION_PATH)
        && receipt.get("target_capability_id").and_then(Value::as_str)
            == Some(plan.capability.id.as_str())
        && receipt.get("target_method").and_then(Value::as_str)
            == Some(plan.capability.method.as_str())
        && receipt.get("target_path").and_then(Value::as_str)
            == Some(plan.capability.path.as_str())
        && receipt.get("account_id").and_then(Value::as_str) == Some(plan.account_id.as_str())
        && receipt.get("app_id").and_then(Value::as_str) == app_id
        && selected_policy_matches
        && receipt.get("policy_name").and_then(Value::as_str) == Some(name)
        && receipt.get("operator_group_id").and_then(Value::as_str) == Some(group_id)
        && receipt.get("candidate_count").and_then(Value::as_u64) == Some(u64::from(!create))
        && receipt
            .get("collection_count")
            .and_then(Value::as_u64)
            .is_some()
        && receipt
            .get("collection_digest")
            .and_then(Value::as_str)
            .is_some_and(|digest| {
                digest.len() == 71
                    && digest.starts_with("sha256:")
                    && digest[7..]
                        .chars()
                        .all(|character| character.is_ascii_hexdigit())
            })
        && receipt.get("terminal_pagination").and_then(Value::as_bool) == Some(true);
    if !valid {
        return Err(CliError::Input(
            "operator-group Access policy ownership receipt has an invalid source, target, identity, or collection shape; create a new plan"
                .to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn required_access_operator_group_policy_ownership_precondition(
    plan: &PlanV1,
) -> Result<Option<&str>> {
    if !is_access_operator_group_policy_create(&plan.capability)
        && !is_access_operator_group_policy_update(&plan.capability)
    {
        return Ok(None);
    }
    let expected_hash = plan
        .precondition_hashes
        .get(ACCESS_OPERATOR_GROUP_POLICY_OWNERSHIP_PRECONDITION)
        .map(String::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "operator-group Access policy plan predates the ownership contract; create a new plan"
                    .to_owned(),
            )
        })?;
    let receipt = plan
        .targets
        .pointer("/live_preconditions/access_operator_group_policy_ownership")
        .ok_or_else(|| {
            CliError::Input(
                "operator-group Access policy plan omitted its ownership receipt; create a new plan"
                    .to_owned(),
            )
        })?;
    validate_access_operator_group_policy_ownership_receipt(plan, receipt)?;
    if hash_value(receipt)? != expected_hash {
        return Err(CliError::Input(
            "operator-group Access policy ownership receipt does not match its precondition hash; create a new plan"
                .to_owned(),
        ));
    }
    Ok(Some(expected_hash))
}

pub(super) async fn validate_live_access_operator_group_policy_ownership_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    plan: &PlanV1,
    input: &CallInput,
    credential: &AuthCredential,
) -> Result<Option<EvidenceV1>> {
    let Some(expected_hash) = required_access_operator_group_policy_ownership_precondition(plan)?
    else {
        return Ok(None);
    };
    let (receipt, evidence) = read_live_access_operator_group_policy_ownership(
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
            "live operator-group Access policy ownership drifted after planning; the mutation boundary was not crossed and a new plan is required"
                .to_owned(),
        ));
    }
    Ok(Some(evidence))
}

pub(super) fn validate_security_action_state_receipt(plan: &PlanV1, receipt: &Value) -> Result<()> {
    let input: CallInput = serde_json::from_value(plan.input.clone())?;
    let metadata = plan
        .targets
        .pointer("/adapter/security_action")
        .ok_or_else(|| {
            CliError::Input(
                "security-action plan omitted its hash-bound governance receipt".to_owned(),
            )
        })?;
    let zone_id = input
        .selectors
        .get("zone_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input("security-action plan omitted its zone selector".to_owned())
        })?;
    let identity_matches = receipt.get("schema_version").and_then(Value::as_u64) == Some(1)
        && receipt.get("source_capability_id").and_then(Value::as_str)
            == Some(SECURITY_IP_RULE_STATE_CAPABILITY_ID)
        && receipt.get("source_path").and_then(Value::as_str)
            == Some(SECURITY_IP_RULE_COLLECTION_PATH)
        && receipt.get("target_capability_id").and_then(Value::as_str)
            == Some(plan.capability.id.as_str())
        && receipt.get("target_method").and_then(Value::as_str)
            == Some(plan.capability.method.as_str())
        && receipt.get("target_path").and_then(Value::as_str)
            == Some(plan.capability.path.as_str())
        && receipt.get("account_id").and_then(Value::as_str) == Some(plan.account_id.as_str())
        && receipt.get("zone_id").and_then(Value::as_str) == Some(zone_id)
        && receipt.get("kind") == metadata.get("kind")
        && receipt.get("evidence_ref") == metadata.get("evidence_ref")
        && receipt.get("expires_at") == metadata.get("expires_at");
    let state_matches = match metadata.get("kind").and_then(Value::as_str) {
        Some("create_expiring") => {
            receipt
                .pointer("/state/matching_rule_count")
                .and_then(Value::as_u64)
                == Some(0)
                && receipt.pointer("/state/target") == metadata.get("target")
                && receipt.pointer("/state/action") == metadata.get("action")
        }
        Some("remove_expired") => {
            receipt
                .pointer("/state/matching_rule_count")
                .and_then(Value::as_u64)
                == Some(1)
                && receipt.pointer("/state/rule_id") == input.selectors.get("rule_id")
                && receipt.pointer("/state/source_operation_id")
                    == metadata.get("source_operation_id")
                && receipt
                    .pointer("/state/live_rule_hash")
                    .and_then(Value::as_str)
                    .is_some_and(|value| value.starts_with("sha256:"))
        }
        _ => false,
    };
    if !identity_matches || !state_matches {
        return Err(CliError::Input(
            "security-action current-state receipt has an invalid source, target, governance binding, or duplicate/removal state; create a new plan"
                .to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn required_security_action_state_precondition(plan: &PlanV1) -> Result<Option<&str>> {
    if plan.capability.security_action.is_none() {
        return Ok(None);
    }
    let adapter = plan.targets.pointer("/adapter").ok_or_else(|| {
        CliError::Input(
            "security-action plan omitted adapter targets; create a new plan".to_owned(),
        )
    })?;
    if !should_bind_security_action_state(&plan.capability, adapter) {
        return Err(CliError::Input(
            "security-action plan is inconsistent with its live current-state contract; create a new plan"
                .to_owned(),
        ));
    }
    let expected_hash = plan
        .precondition_hashes
        .get(SECURITY_ACTION_STATE_PRECONDITION)
        .map(String::as_str)
        .ok_or_else(|| {
            CliError::Input(
                "security-action plan predates the live duplicate/removal-state contract; create a new plan"
                    .to_owned(),
            )
        })?;
    let receipt = plan
        .targets
        .pointer("/live_preconditions/security_action_state")
        .ok_or_else(|| {
            CliError::Input(
                "security-action plan omitted its hash-bound current-state receipt; create a new plan"
                    .to_owned(),
            )
        })?;
    validate_security_action_state_receipt(plan, receipt)?;
    if hash_value(receipt)? != expected_hash {
        return Err(CliError::Input(
            "security-action current-state receipt does not match its precondition hash; create a new plan"
                .to_owned(),
        ));
    }
    Ok(Some(expected_hash))
}

pub(super) async fn validate_live_security_action_state_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    plan: &PlanV1,
    input: &CallInput,
    credential: &AuthCredential,
) -> Result<Option<EvidenceV1>> {
    let Some(expected_hash) = required_security_action_state_precondition(plan)? else {
        return Ok(None);
    };
    let adapter = plan.targets.pointer("/adapter").ok_or_else(|| {
        CliError::Input("security-action plan omitted adapter targets".to_owned())
    })?;
    let (receipt, evidence) = read_live_security_action_state(
        store,
        catalog,
        &plan.capability,
        input,
        adapter,
        &plan.account_id,
        credential,
    )
    .await?;
    if hash_value(&receipt)? != expected_hash {
        return Err(CliError::Input(
            "live security-action duplicate or removal state drifted after planning; the mutation boundary was not crossed and a new plan is required"
                .to_owned(),
        ));
    }
    Ok(Some(evidence))
}

pub(super) async fn validate_live_zone_account_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    plan: &PlanV1,
    input: &CallInput,
    credential: &AuthCredential,
) -> Result<Option<EvidenceV1>> {
    let Some(expected_hash) = required_zone_account_precondition(plan)? else {
        return Ok(None);
    };
    let (receipt, evidence) = read_live_zone_account(
        store,
        catalog,
        &plan.capability,
        input,
        &plan.account_id,
        credential,
    )
    .await?;
    validate_zone_account_receipt_precondition(expected_hash, &receipt)?;
    Ok(Some(evidence))
}

pub(super) fn validate_zone_account_receipt_precondition(
    expected_hash: &str,
    receipt: &Value,
) -> Result<()> {
    if hash_value(receipt)? != expected_hash {
        return Err(CliError::Input(
            "live zone-account ownership drifted after planning; the mutation boundary was not crossed and a new plan is required"
                .to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn required_zone_account_precondition(plan: &PlanV1) -> Result<Option<&str>> {
    if !plan.capability.mutating || plan.capability.account_scope != "zone" {
        return Ok(None);
    }
    plan.precondition_hashes
        .get("zone_account")
        .map(String::as_str)
        .map(Some)
        .ok_or_else(|| {
            CliError::Input(
                "plan predates the live zone-account ownership contract; create a new plan"
                    .to_owned(),
            )
        })
}

pub(super) async fn validate_live_entitlement_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    plan: &PlanV1,
    input: &CallInput,
    credential: &AuthCredential,
) -> Result<Option<EvidenceV1>> {
    let Some(expected_hash) = required_entitlement_precondition(plan)? else {
        return Ok(None);
    };
    let mut capability = plan.capability.clone();
    let (receipt, evidence) = if capability.entitlement.probe.is_some() {
        read_live_entitlement_probe(store, catalog, &mut capability, input, credential).await?
    } else {
        read_live_zone_entitlement(store, catalog, &mut capability, input, credential).await?
    };
    validate_entitlement_receipt_precondition(expected_hash, &capability, &receipt)?;
    Ok(Some(evidence))
}

pub(super) fn required_entitlement_precondition(plan: &PlanV1) -> Result<Option<&str>> {
    if !plan.capability.entitlement.requires_live_resolution {
        return Ok(None);
    }
    let scope_supported = plan.capability.account_scope == "zone"
        || (plan.capability.account_scope == "account"
            && plan.capability.entitlement.probe.is_some());
    if !scope_supported || plan.capability.entitlement.available != Some(true) {
        return Err(CliError::Input(
            "plan entitlement precondition is inconsistent with its hash-bound capability; create a new plan"
                .to_owned(),
        ));
    }
    plan.precondition_hashes
        .get("entitlement")
        .map(String::as_str)
        .map(Some)
        .ok_or_else(|| {
            CliError::Input(
                "plan predates the live zone-entitlement contract; create a new plan".to_owned(),
            )
        })
}

pub(super) fn validate_entitlement_receipt_precondition(
    expected_hash: &str,
    capability: &CapabilityV1,
    receipt: &Value,
) -> Result<()> {
    let actual_hash = hash_value(receipt)?;
    if actual_hash != expected_hash || capability.entitlement.available != Some(true) {
        return Err(CliError::Input(
            "live entitlement drifted after planning; the mutation boundary was not crossed and a new plan is required"
                .to_owned(),
        ));
    }
    Ok(())
}

pub(super) async fn validate_live_permission_inventory_precondition(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    plan: &PlanV1,
    credential: &AuthCredential,
    standing_authority: Option<&StandingAuthorityV1>,
) -> Result<Option<EvidenceV1>> {
    let Some(expected_inventory) = token_permission_inventory_contract(&plan.capability.id) else {
        return Ok(None);
    };
    let inventory_contract = plan
        .targets
        .pointer("/adapter/permission_inventory")
        .ok_or_else(|| {
            CliError::Input(
                "token mint plan predates the live permission-inventory contract; create a new plan"
                    .to_owned(),
            )
        })?;
    let source_capability_id = inventory_contract
        .get("source_capability_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input("token mint permission-inventory capability is missing".to_owned())
        })?;
    let source_capability = catalog.get(source_capability_id).ok_or_else(|| {
        CliError::Input(format!(
            "token mint permission-inventory capability `{source_capability_id}` no longer exists"
        ))
    })?;
    if source_capability.id != expected_inventory.capability_id
        || source_capability.method != "GET"
        || source_capability.path != expected_inventory.path
    {
        return Err(CliError::Input(
            "token mint permission-inventory capability drifted from its governed owner-specific read"
                .to_owned(),
        ));
    }
    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let response = executor
        .execute_read(
            source_capability,
            &CallInput {
                selectors: if expected_inventory.account_selector {
                    json!({"account_id": plan.account_id})
                } else {
                    json!({})
                },
                query: json!({}),
                body: None,
                ..CallInput::default()
            },
            credential,
        )
        .await?;
    if !response.success {
        return Err(CliError::Input(
            "Cloudflare rejected the permission-inventory precondition read; the token mint boundary was not crossed"
                .to_owned(),
        ));
    }
    validate_current_permission_groups(inventory_contract, &response.result)?;
    if let Some(authority) = standing_authority {
        validate_standing_authority_permission_inventory(authority, &response.result)?;
    }
    let evidence =
        store.write_evidence(EvidenceClass::LiveRead, &serde_json::to_value(&response)?)?;
    Ok(Some(evidence))
}

pub(super) fn validate_current_permission_groups(
    inventory_contract: &Value,
    current: &Value,
) -> Result<()> {
    let selected_groups = inventory_contract
        .get("selected_groups")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CliError::Input("token mint selected permission groups are missing".to_owned())
        })?;
    let selected_ids = selected_groups
        .iter()
        .map(|group| {
            group
                .get("id")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| {
                    CliError::Input(
                        "token mint selected permission group is missing an ID".to_owned(),
                    )
                })
        })
        .collect::<Result<Vec<_>>>()?;
    let expected_hash = inventory_contract
        .get("selected_groups_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::Input("token mint selected permission-group hash is missing".to_owned())
        })?;
    let current_groups = validate_selected_permission_groups(&selected_ids, current)?;
    let current_hash = hash_value(&serde_json::to_value(&current_groups)?)?;
    if current_hash != expected_hash {
        return Err(CliError::Input(
            "selected permission-group metadata drifted after planning; create and review a new token mint plan"
                .to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn validate_standing_authority_permission_inventory(
    authority: &StandingAuthorityV1,
    current: &Value,
) -> Result<()> {
    let current_allowlist =
        validate_selected_permission_groups(&authority.permission_group_ids, current)?;
    authority.validate_permission_inventory(&Value::Array(current_allowlist))?;
    Ok(())
}
