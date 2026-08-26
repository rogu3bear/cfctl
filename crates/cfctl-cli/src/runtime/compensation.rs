use super::import_planning::SECURITY_LIST_MEMBER_COLLECTION_PATH;
use super::import_planning::SECURITY_LIST_MEMBER_CREATE_ID;
use super::import_planning::SECURITY_LIST_MEMBER_REMOVE_ID;
use super::live_state_contracts::is_cloudflare_tunnel_configuration_mutation;
use super::live_state_contracts::is_d1_read_replication_mutation;
use super::live_state_contracts::is_dns_record_update_mutation;
use super::live_state_contracts::is_warp_connector_configuration_mutation;
use super::live_state_contracts::is_web_analytics_rum_mutation;
use super::live_state_contracts::should_bind_same_path_prior_state;
use super::plan_commands::load_validated_plan;
use super::plan_commands::run_plan;
use super::plan_commands::show_plan;
use super::plan_secret::CLOUDFLARE_TUNNEL_CONFIGURATION_MUTATION_CAPABILITY_ID;
use super::plan_secret::CLOUDFLARE_TUNNEL_CONFIGURATION_PATH;
use super::plan_secret::D1_DATABASE_CREATE_CAPABILITY_ID;
use super::plan_secret::D1_EMPTY_DATABASE_COMPENSATION_STRATEGY;
use super::plan_secret::D1_READ_REPLICATION_PATH;
use super::plan_secret::DNS_RECORD_DETAIL_PATH;
use super::plan_secret::DNS_RECORD_RESTORE_CAPABILITY_ID;
use super::plan_secret::GLOBAL_WARP_OVERRIDE_MUTATION_CAPABILITY_ID;
use super::plan_secret::GLOBAL_WARP_OVERRIDE_PATH;
use super::plan_secret::WARP_CONNECTOR_CONFIGURATION_MUTATION_CAPABILITY_ID;
use super::plan_secret::WARP_CONNECTOR_CONFIGURATION_PATH;
use super::plan_secret::WEB_ANALYTICS_RUM_MUTATION_CAPABILITY_ID;
use super::plan_secret::WEB_ANALYTICS_RUM_PATH;
use super::preconditions_core::cloudflare_tunnel_configuration_prior_snapshot;
use super::preconditions_core::d1_read_replication_prior_mode;
use super::preconditions_core::global_warp_override_prior_disconnect_state;
use super::preconditions_extended::dns_record_prior_snapshot;
use super::preconditions_extended::same_path_prior_snapshot;
use super::preconditions_extended::warp_connector_configuration_prior_snapshot;
use super::preconditions_extended::web_analytics_rum_prior_value;
use super::prelude::{
    CallInput, CapabilityV1, CliError, PlanSelector, PlanStatus, PlanV1, Result, ResultEnvelopeV2,
    StateStore, TransactionStageV1, Value, json,
};

pub(super) async fn resume_plan(
    store: &StateStore,
    selector: &PlanSelector,
) -> Result<ResultEnvelopeV2> {
    let plan = load_validated_plan(store, &selector.operation_id)?;
    match plan.status {
        PlanStatus::Draft | PlanStatus::Approved => Box::pin(run_plan(store, selector)).await,
        PlanStatus::Consumed | PlanStatus::Running => Err(CliError::Input(
            "the operation may have crossed the Cloudflare boundary; replay is blocked until rectification proves current state"
                .to_owned(),
        )),
        PlanStatus::Verified | PlanStatus::Rectified => show_plan(store, selector),
        _ => Err(CliError::Input(format!(
            "operation is {:?}; use `cfctl plans rectify {}`",
            plan.status, plan.operation_id
        ))),
    }
}

pub(super) struct CompensationRequest {
    pub(super) capability_id: String,
    pub(super) expected_method: String,
    pub(super) expected_path: String,
    pub(super) input: CallInput,
    pub(super) requested_account: Option<String>,
    pub(super) adapter_targets: Value,
}

pub(super) struct CompensationTarget {
    pub(super) capability_id: String,
    pub(super) expected_method: String,
    pub(super) expected_path: String,
    pub(super) selectors: Value,
    pub(super) body: Option<Value>,
}

pub(super) fn validate_compensation_contract(capability: &CapabilityV1) -> Result<()> {
    if capability.rollback_contract_supported() {
        return Ok(());
    }
    Err(CliError::Input(format!(
        "rollback strategy `{}` is not implemented for capability `{}`; inspect live state before compensating",
        capability
            .rollback
            .strategy
            .as_deref()
            .unwrap_or("<missing>"),
        capability.id
    )))
}

pub(super) fn global_warp_override_compensation_request(
    plan: &PlanV1,
) -> Result<CompensationRequest> {
    Ok(CompensationRequest {
        capability_id: GLOBAL_WARP_OVERRIDE_MUTATION_CAPABILITY_ID.to_owned(),
        expected_method: "POST".to_owned(),
        expected_path: GLOBAL_WARP_OVERRIDE_PATH.to_owned(),
        input: CallInput {
            selectors: json!({"account_id": plan.account_id}),
            query: json!({}),
            body: Some(json!({
                "disconnect": global_warp_override_prior_disconnect_state(plan)?,
            })),
            ..CallInput::default()
        },
        requested_account: Some(plan.account_id.clone()),
        adapter_targets: json!({}),
    })
}

pub(super) fn d1_read_replication_compensation_request(
    plan: &PlanV1,
) -> Result<CompensationRequest> {
    let database_id = plan
        .targets
        .pointer("/selectors/database_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input("D1 compensation requires a hash-bound database selector".to_owned())
        })?;
    Ok(CompensationRequest {
        capability_id: plan.capability.id.clone(),
        expected_method: plan.capability.method.clone(),
        expected_path: D1_READ_REPLICATION_PATH.to_owned(),
        input: CallInput {
            selectors: json!({
                "account_id": plan.account_id,
                "database_id": database_id,
            }),
            query: json!({}),
            body: Some(json!({
                "read_replication": {
                    "mode": d1_read_replication_prior_mode(plan)?,
                },
            })),
            ..CallInput::default()
        },
        requested_account: Some(plan.account_id.clone()),
        adapter_targets: json!({}),
    })
}

pub(super) fn cloudflare_tunnel_configuration_compensation_request(
    plan: &PlanV1,
) -> Result<CompensationRequest> {
    let tunnel_id = plan
        .targets
        .pointer("/selectors/tunnel_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "Tunnel configuration compensation requires a hash-bound Tunnel selector"
                    .to_owned(),
            )
        })?;
    Ok(CompensationRequest {
        capability_id: CLOUDFLARE_TUNNEL_CONFIGURATION_MUTATION_CAPABILITY_ID.to_owned(),
        expected_method: "PUT".to_owned(),
        expected_path: CLOUDFLARE_TUNNEL_CONFIGURATION_PATH.to_owned(),
        input: CallInput {
            selectors: json!({
                "account_id": plan.account_id,
                "tunnel_id": tunnel_id,
            }),
            query: json!({}),
            body: Some(json!({
                "config": cloudflare_tunnel_configuration_prior_snapshot(plan)?,
            })),
            ..CallInput::default()
        },
        requested_account: Some(plan.account_id.clone()),
        adapter_targets: json!({}),
    })
}

pub(super) fn warp_connector_configuration_compensation_request(
    plan: &PlanV1,
) -> Result<CompensationRequest> {
    let tunnel_id = plan
        .targets
        .pointer("/selectors/tunnel_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "WARP Connector compensation requires a hash-bound Tunnel selector".to_owned(),
            )
        })?;
    Ok(CompensationRequest {
        capability_id: WARP_CONNECTOR_CONFIGURATION_MUTATION_CAPABILITY_ID.to_owned(),
        expected_method: "PUT".to_owned(),
        expected_path: WARP_CONNECTOR_CONFIGURATION_PATH.to_owned(),
        input: CallInput {
            selectors: json!({
                "account_id": plan.account_id,
                "tunnel_id": tunnel_id,
            }),
            query: json!({}),
            body: Some(warp_connector_configuration_prior_snapshot(plan)?),
            ..CallInput::default()
        },
        requested_account: Some(plan.account_id.clone()),
        adapter_targets: json!({}),
    })
}

pub(super) fn web_analytics_rum_compensation_request(plan: &PlanV1) -> Result<CompensationRequest> {
    let zone_id = plan
        .targets
        .pointer("/selectors/zone_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "Web Analytics RUM compensation requires a hash-bound zone selector".to_owned(),
            )
        })?;
    Ok(CompensationRequest {
        capability_id: WEB_ANALYTICS_RUM_MUTATION_CAPABILITY_ID.to_owned(),
        expected_method: "PATCH".to_owned(),
        expected_path: WEB_ANALYTICS_RUM_PATH.to_owned(),
        input: CallInput {
            selectors: json!({"zone_id": zone_id}),
            query: json!({}),
            body: Some(json!({"value": web_analytics_rum_prior_value(plan)?})),
            ..CallInput::default()
        },
        requested_account: Some(plan.account_id.clone()),
        adapter_targets: json!({}),
    })
}

pub(super) fn dns_record_compensation_request(plan: &PlanV1) -> Result<CompensationRequest> {
    let zone_id = plan
        .targets
        .pointer("/selectors/zone_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "DNS record compensation requires a hash-bound zone selector".to_owned(),
            )
        })?;
    let dns_record_id = plan
        .targets
        .pointer("/selectors/dns_record_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "DNS record compensation requires a hash-bound record selector".to_owned(),
            )
        })?;
    Ok(CompensationRequest {
        capability_id: DNS_RECORD_RESTORE_CAPABILITY_ID.to_owned(),
        expected_method: "PUT".to_owned(),
        expected_path: DNS_RECORD_DETAIL_PATH.to_owned(),
        input: CallInput {
            selectors: json!({
                "zone_id": zone_id,
                "dns_record_id": dns_record_id,
            }),
            query: json!({}),
            body: Some(dns_record_prior_snapshot(plan)?),
            ..CallInput::default()
        },
        requested_account: Some(plan.account_id.clone()),
        adapter_targets: json!({}),
    })
}

pub(super) fn same_path_prior_state_compensation_request(
    plan: &PlanV1,
) -> Result<CompensationRequest> {
    let input: CallInput = serde_json::from_value(plan.input.clone())?;
    Ok(CompensationRequest {
        capability_id: plan.capability.id.clone(),
        expected_method: plan.capability.method.clone(),
        expected_path: plan.capability.path.clone(),
        input: CallInput {
            selectors: input.selectors,
            query: json!({}),
            body: Some(same_path_prior_snapshot(plan)?),
            ..CallInput::default()
        },
        requested_account: Some(plan.account_id.clone()),
        adapter_targets: json!({}),
    })
}

pub(super) fn async_list_member_compensation_request(plan: &PlanV1) -> Result<CompensationRequest> {
    let member_id = plan
        .transaction_artifact(TransactionStageV1::VerificationResponsePersisted)
        .and_then(|artifact| artifact.get("resource_id"))
        .and_then(Value::as_str)
        .filter(|identity| identity.len() == 32)
        .ok_or_else(|| {
            CliError::Input(
                "the List add crossed the boundary, but no exact correlated member identity is present in its verification receipt; inspect live List state before compensating"
                    .to_owned(),
            )
        })?;
    let account_id = plan
        .targets
        .pointer("/selectors/account_id")
        .and_then(Value::as_str)
        .filter(|identity| !identity.is_empty())
        .ok_or_else(|| {
            CliError::Input("List compensation omitted its account selector".to_owned())
        })?;
    let list_id = plan
        .targets
        .pointer("/selectors/list_id")
        .and_then(Value::as_str)
        .filter(|identity| !identity.is_empty())
        .ok_or_else(|| CliError::Input("List compensation omitted its list selector".to_owned()))?;
    let source = plan
        .targets
        .pointer("/adapter/security_action")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CliError::Input(
                "List compensation omitted its hash-bound security-action receipt".to_owned(),
            )
        })?;
    let security_action = json!({
        "schema_version":1,
        "kind":"remove_expired_list_member",
        "actor":source.get("actor").cloned().unwrap_or(Value::String("cfctl-compensation".to_owned())),
        "evidence_ref":source.get("evidence_ref").cloned().unwrap_or(Value::Null),
        "expires_at":source.get("expires_at").cloned().unwrap_or(Value::Null),
        "reason":"explicit rollback of the exact correlated List member",
        "source_operation_id":plan.operation_id,
        "member_id":member_id,
        "rollback_override":true,
        "anonymous_identity_inferred":false,
    });
    Ok(CompensationRequest {
        capability_id: SECURITY_LIST_MEMBER_REMOVE_ID.to_owned(),
        expected_method: "DELETE".to_owned(),
        expected_path: SECURITY_LIST_MEMBER_COLLECTION_PATH.to_owned(),
        input: CallInput {
            selectors: json!({"account_id":account_id,"list_id":list_id}),
            query: json!({}),
            body: Some(json!({"items":[{"id":member_id}]})),
            ..CallInput::default()
        },
        requested_account: Some(plan.account_id.clone()),
        adapter_targets: json!({"security_action":security_action}),
    })
}

pub(super) fn compensation_resource_id(artifact: &Value) -> Result<&Value> {
    artifact
        .get("resource_id")
        .filter(|identity| {
            identity.as_str().is_some_and(|value| !value.is_empty())
                || identity.as_u64().is_some()
                || identity.as_i64().is_some()
        })
        .ok_or_else(|| {
            CliError::Input(
                "the creation response is recorded, but its hash-bound receipt has no string or integer resource id; inspect live resource state before compensating"
                    .to_owned(),
            )
        })
}

pub(super) fn string_compensation_resource_id<'a>(
    plan: &PlanV1,
    resource_id: &'a Value,
) -> Result<&'a str> {
    resource_id.as_str().filter(|value| !value.is_empty()).ok_or_else(|| {
        CliError::Input(format!(
            "the `{}` compensation contract requires a string resource identity, but the hash-bound creation receipt has a different scalar type",
            plan.capability.id
        ))
    })
}

pub(super) fn operation_specific_compensation_request(
    plan: &PlanV1,
) -> Result<Option<CompensationRequest>> {
    let request = if plan.capability.id == GLOBAL_WARP_OVERRIDE_MUTATION_CAPABILITY_ID {
        global_warp_override_compensation_request(plan)?
    } else if is_d1_read_replication_mutation(&plan.capability) {
        d1_read_replication_compensation_request(plan)?
    } else if is_cloudflare_tunnel_configuration_mutation(&plan.capability) {
        cloudflare_tunnel_configuration_compensation_request(plan)?
    } else if is_warp_connector_configuration_mutation(&plan.capability) {
        warp_connector_configuration_compensation_request(plan)?
    } else if is_web_analytics_rum_mutation(&plan.capability) {
        web_analytics_rum_compensation_request(plan)?
    } else if is_dns_record_update_mutation(&plan.capability) {
        dns_record_compensation_request(plan)?
    } else if should_bind_same_path_prior_state(&plan.capability) {
        same_path_prior_state_compensation_request(plan)?
    } else if plan.capability.id == SECURITY_LIST_MEMBER_CREATE_ID {
        async_list_member_compensation_request(plan)?
    } else {
        return Ok(None);
    };
    Ok(Some(request))
}

pub(super) fn compensation_request(plan: &PlanV1) -> Result<Option<CompensationRequest>> {
    if !matches!(
        plan.status,
        PlanStatus::Consumed | PlanStatus::Running | PlanStatus::RectificationRequired
    ) || !plan.capability.rollback.supported
    {
        return Ok(None);
    }
    validate_compensation_contract(&plan.capability)?;
    let Some(artifact) = plan.transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
    else {
        return Ok(None);
    };
    if artifact.get("success").and_then(Value::as_bool) != Some(true) {
        return Ok(None);
    }
    if let Some(request) = operation_specific_compensation_request(plan)? {
        return Ok(Some(request));
    }
    let resource_id = compensation_resource_id(artifact)?;
    let Some(target) = created_resource_compensation_target(plan, resource_id)? else {
        return Ok(None);
    };
    Ok(Some(CompensationRequest {
        capability_id: target.capability_id,
        expected_method: target.expected_method,
        expected_path: target.expected_path,
        input: CallInput {
            selectors: target.selectors,
            query: json!({}),
            body: target.body,
            ..CallInput::default()
        },
        requested_account: Some(plan.account_id.clone()),
        adapter_targets: json!({}),
    }))
}

pub(super) fn created_resource_compensation_target(
    plan: &PlanV1,
    resource_id: &Value,
) -> Result<Option<CompensationTarget>> {
    let (capability_id, expected_method, expected_path, selectors, body) = match plan
        .capability
        .id
        .as_str()
    {
        "account-api-tokens-create-token" => (
            "account-api-tokens-delete-token".to_owned(),
            "DELETE".to_owned(),
            "/accounts/{account_id}/tokens/{token_id}".to_owned(),
            json!({"account_id": plan.account_id, "token_id": string_compensation_resource_id(plan, resource_id)?}),
            None,
        ),
        "user-api-tokens-create-token" => (
            "user-api-tokens-delete-token".to_owned(),
            "DELETE".to_owned(),
            "/user/tokens/{token_id}".to_owned(),
            json!({"token_id": string_compensation_resource_id(plan, resource_id)?}),
            None,
        ),
        "dns-records-for-a-zone-create-dns-record" => {
            let resource_id = string_compensation_resource_id(plan, resource_id)?;
            let input: CallInput = serde_json::from_value(plan.input.clone())?;
            let zone_id = input
                .selectors
                .get("zone_id")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    CliError::Input(
                        "the DNS record creation receipt is valid, but its source plan has no zone_id selector; inspect live DNS state before compensating"
                            .to_owned(),
                    )
                })?;
            (
                "dns-records-for-a-zone-delete-dns-record".to_owned(),
                "DELETE".to_owned(),
                DNS_RECORD_DETAIL_PATH.to_owned(),
                json!({"zone_id": zone_id, "dns_record_id": resource_id}),
                None,
            )
        }
        D1_DATABASE_CREATE_CAPABILITY_ID => {
            if plan.capability.rollback.strategy.as_deref()
                != Some(D1_EMPTY_DATABASE_COMPENSATION_STRATEGY)
            {
                return Ok(None);
            }
            let (capability_id, expected_path, selectors) =
                generic_created_resource_compensation(plan, resource_id)?;
            (
                capability_id,
                "DELETE".to_owned(),
                expected_path,
                selectors,
                None,
            )
        }
        _ => {
            if plan.capability.rollback.strategy.as_deref()
                != Some("delete_created_resource_by_returned_id")
            {
                return Ok(None);
            }
            let (capability_id, expected_path, selectors) =
                generic_created_resource_compensation(plan, resource_id)?;
            (
                capability_id,
                "DELETE".to_owned(),
                expected_path,
                selectors,
                None,
            )
        }
    };
    Ok(Some(CompensationTarget {
        capability_id,
        expected_method,
        expected_path,
        selectors,
        body,
    }))
}

pub(super) fn generic_created_resource_compensation(
    plan: &PlanV1,
    resource_id: &Value,
) -> Result<(String, String, Value)> {
    let input: CallInput = serde_json::from_value(plan.input.clone())?;
    let mut selectors = input.selectors.as_object().cloned().ok_or_else(|| {
        CliError::Input(
            "the creation receipt is valid, but its source selectors are not an object; inspect live resource state before compensating"
                .to_owned(),
        )
    })?;
    let (identity_selector, delete_capability_id, expected_path) = if let Some(target) =
        plan.capability.created_resource.as_ref()
    {
        (
            target.identity_selector.as_str(),
            target.delete_capability_id.clone(),
            target.detail_path.clone(),
        )
    } else if let Some(target) = plan.capability.created_collection_resource.as_ref() {
        (
            target.identity_selector.as_str(),
            target.delete_capability_id.clone(),
            format!(
                "{}/{{{}}}",
                target.collection_path.trim_end_matches('/'),
                target.identity_selector
            ),
        )
    } else if let Some(target) = plan.capability.created_nested_resource.as_ref() {
        (
            target.identity_selector.as_str(),
            target.delete_capability_id.clone(),
            target.delete_path.clone(),
        )
    } else {
        return Err(CliError::Input(
                "the rollback strategy names created-resource deletion, but the hash-bound resource target is absent"
                    .to_owned(),
            ));
    };
    selectors.insert(identity_selector.to_owned(), resource_id.clone());
    Ok((
        delete_capability_id,
        expected_path,
        Value::Object(selectors),
    ))
}

pub(super) fn bind_required_empty_compensation_body(
    request: &mut CompensationRequest,
    capability: &cfctl_core::CapabilityV1,
) {
    if request.expected_method == "DELETE"
        && capability.method == request.expected_method
        && capability.path == request.expected_path
        && request.input.body.is_none()
        && capability.required_empty_request_body_contract()
    {
        request.input.body = Some(json!({}));
    }
}
