use std::{collections::BTreeSet, path::PathBuf};

use cfctl_auth::{AuthCredential, ProfileKind, ProfileMetadata};
use cfctl_catalog::CatalogSnapshot;
use cfctl_cloudflare::{CallInput, CloudflareResponseV1, Executor};
use cfctl_core::{
    AdapterStatus, CapabilityV1, EffectClass, EvidenceClass, PlanStatus, PlanV1,
    ResponseBodyModeV1, RiskClass, hash_value,
};
use cfctl_storage::StateStore;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{API_BASE_URL, CliError, ProfilesConfig, Result, http_client};

const ZONE_LIST_PATH: &str = "/zones";
const ZONE_LIST_ID: &str = "zones-get";
const SUBDOMAIN_DNS_ID: &str = "email-routing-settings-email-routing-dns-settings";
const SUBDOMAIN_DNS_PATH: &str = "/zones/{zone_id}/email/routing/dns";
const WORKERS_LIST_ID: &str = "listWorkers";
const WORKERS_LIST_PATH: &str = "/accounts/{account_id}/workers/workers";
const ACCOUNT_PLAN_ID: &str = "email-routing-routing-rules-plan-account-routing-rules";
const ACCOUNT_PLAN_PATH: &str = "/accounts/{account_id}/email/routing/rules/plan";
const CATCH_ALL_GET_ID: &str = "email-routing-routing-rules-get-catch-all-rule";
const CATCH_ALL_GET_PATH: &str = "/zones/{zone_id}/email/routing/rules/catch_all";
const CATCH_ALL_UPDATE_ID: &str = "email-routing-routing-rules-update-catch-all-rule";
const CATCH_ALL_UPDATE_PATH: &str = "/zones/{zone_id}/email/routing/rules/catch_all";
const ACTIVATION_PLAN_PROJECTION: &str = "workspace_reply_subdomain_ingress_activation_plan_v1";
const ACTIVATION_APPLY_PROJECTION: &str = "workspace_reply_subdomain_ingress_activation_apply_v1";
const ROUTING_SCOPE: &str = "parent_zone_catch_all_to_worker_covering_exact_reply_subdomain";
const CANONICAL_MX: [&str; 3] = [
    "route1.mx.cloudflare.net",
    "route2.mx.cloudflare.net",
    "route3.mx.cloudflare.net",
];
const RESULT_KEYS: [&str; 12] = [
    "adapter",
    "success",
    "boundary_crossed",
    "schema_version",
    "reply_domain_sha256",
    "worker_target_sha256",
    "dns_scope",
    "routing_scope",
    "dns",
    "routing_rule",
    "provider_output_retained",
    "body_returned",
];
const DNS_RESULT_INFO_KEYS: [&str; 7] = [
    "page",
    "per_page",
    "total_pages",
    "count",
    "total_count",
    "cfctl_pages",
    "cfctl_page_complete",
];

pub(super) fn load(store: &StateStore, id: &str) -> Result<Option<CapabilityV1>> {
    Ok(
        cfctl_workspace::load_workspace_reply_subdomain_ingress_capability(
            &store.workspace_roots()?,
            id,
        )?,
    )
}

pub(super) fn receipt_is_complete(receipt: &Value) -> bool {
    let Some(object) = receipt.as_object() else {
        return false;
    };
    object.len() == RESULT_KEYS.len()
        && RESULT_KEYS.iter().all(|key| object.contains_key(*key))
        && receipt.get("adapter").and_then(Value::as_str)
            == Some(cfctl_workspace::MAILDESK_REPLY_SUBDOMAIN_INGRESS_PROJECTION)
        && receipt.get("success").and_then(Value::as_bool) == Some(true)
        && receipt.get("boundary_crossed").and_then(Value::as_bool) == Some(true)
        && receipt.get("schema_version").and_then(Value::as_u64) == Some(1)
        && ["reply_domain_sha256", "worker_target_sha256"]
            .iter()
            .all(|key| {
                receipt
                    .get(*key)
                    .and_then(Value::as_str)
                    .is_some_and(is_sha256)
            })
        && receipt.get("dns_scope").and_then(Value::as_str) == Some("exact_reply_subdomain")
        && receipt.get("routing_scope").and_then(Value::as_str) == Some(ROUTING_SCOPE)
        && ["dns", "routing_rule"].iter().all(|key| {
            matches!(
                receipt.get(*key).and_then(Value::as_str),
                Some("ok" | "drift" | "missing")
            )
        })
        && receipt
            .get("provider_output_retained")
            .and_then(Value::as_bool)
            == Some(false)
        && receipt.get("body_returned").and_then(Value::as_bool) == Some(false)
}

pub(super) fn is_unperformed_fresh_precondition_failure(receipt: &Value) -> bool {
    receipt.get("adapter").and_then(Value::as_str) == Some(ACTIVATION_APPLY_PROJECTION)
        && receipt.get("success").and_then(Value::as_bool) == Some(false)
        && receipt.get("boundary_crossed").and_then(Value::as_bool) == Some(false)
        && receipt.get("failure_code").and_then(Value::as_str)
            == Some("CFCTL_WORKSPACE_REPLY_SUBDOMAIN_FRESH_PRECONDITION_FAILED")
        && receipt
            .get("status")
            .and_then(Value::as_str)
            .is_some_and(|status| !status.is_empty())
        && receipt
            .get("provider_output_retained")
            .and_then(Value::as_bool)
            == Some(false)
        && receipt.get("body_returned").and_then(Value::as_bool) == Some(false)
}

#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the exact workspace, profile, account, credential generation, provider catalog, and live planning reads remain one fail-closed admission boundary"
)]
pub(super) async fn prepare_activation_target(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    credential: &AuthCredential,
    profile: &ProfileMetadata,
    account_id: &str,
    requested_account: Option<&str>,
    credential_generation_id: &str,
) -> Result<Value> {
    let contract = capability
        .workspace_reply_subdomain_ingress
        .as_ref()
        .filter(|contract| contract.operation_kind == "activate")
        .ok_or_else(|| {
            CliError::Input("reply-subdomain ingress activation contract missing".to_owned())
        })?;
    let current = load(store, &capability.id)?.ok_or_else(|| {
        CliError::Input(
            "reply-subdomain ingress activation authority is no longer uniquely available"
                .to_owned(),
        )
    })?;
    if current.workspace_reply_subdomain_ingress.as_ref() != Some(contract) {
        return Err(CliError::Input(
            "reply-subdomain ingress activation repository authority drifted".to_owned(),
        ));
    }
    if !profile_is_bound_for_read(
        profile,
        account_id,
        requested_account,
        credential_generation_id,
    ) {
        return Err(CliError::Input(
            "reply-subdomain ingress activation profile, account, or credential generation binding drifted"
                .to_owned(),
        ));
    }
    let target = target(input, account_id)?;
    let zone_capability = exact_zone_list_capability(catalog)?;
    let workers = catalog.get(WORKERS_LIST_ID).ok_or_else(|| {
        CliError::Input("complete Worker inventory source is unavailable".to_owned())
    })?;
    let account_plan = catalog.get(ACCOUNT_PLAN_ID).ok_or_else(|| {
        CliError::Input("Email Routing account-plan source is unavailable".to_owned())
    })?;
    let catch_all_get = catalog.get(CATCH_ALL_GET_ID).ok_or_else(|| {
        CliError::Input("Email Routing catch-all observation source is unavailable".to_owned())
    })?;
    let catch_all = catalog.get(CATCH_ALL_UPDATE_ID).ok_or_else(|| {
        CliError::Input("Email Routing catch-all update source is unavailable".to_owned())
    })?;
    validate_activation_provider_contracts(
        zone_capability,
        workers,
        account_plan,
        catch_all_get,
        catch_all,
    )?;
    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let parent_zone = match resolve_active_parent_zone_id(
        &executor,
        zone_capability,
        &target,
        credential,
    )
    .await
    {
        Ok(zone_id) => zone_id,
        Err(receipt) => return activation_preflight_failure(store, receipt),
    };
    let catch_all_state = match observe_catch_all(
        &executor,
        catch_all_get,
        &parent_zone.id,
        &target,
        credential,
    )
    .await
    {
        Ok(observation) => observation,
        Err(receipt) => return activation_preflight_failure(store, receipt),
    };
    let worker_tag = match observe_worker_tag(&executor, workers, &target, credential).await {
        Ok(worker_tag) => worker_tag,
        Err(receipt) => return activation_preflight_failure(store, receipt),
    };
    let provider_request = activation_provider_request(&target, &worker_tag);
    let planned = match observe_activation_plan(
        &executor,
        account_plan,
        account_id,
        &target,
        &parent_zone,
        &provider_request,
        credential,
    )
    .await
    {
        Ok(planned) => planned,
        Err(receipt) => return activation_preflight_failure(store, receipt),
    };
    if planned.zone_id != parent_zone.id {
        return activation_preflight_failure(
            store,
            failure(
                "account_plan_parent_zone_mismatch",
                "account_plan",
                true,
                Some(1),
            ),
        );
    }
    let apply_body = activation_apply_body(&target.worker_script_name, &worker_tag);
    let planning_receipt = json!({
        "adapter":ACTIVATION_PLAN_PROJECTION,
        "success":true,
        "boundary_crossed":true,
        "schema_version":1,
        "reply_domain_sha256":sha256(target.reply_domain.as_bytes()),
        "worker_target_sha256":sha256(target.worker_script_name.as_bytes()),
        "worker_tag_sha256":sha256(worker_tag.as_bytes()),
        "parent_zone_sha256":sha256(parent_zone.id.as_bytes()),
        "catch_all_state_sha256":catch_all_state.state_sha256,
        "zone_target_sha256":sha256(planned.zone_id.as_bytes()),
        "provider_request_sha256":hash_value(&provider_request)?,
        "apply_body_sha256":hash_value(&apply_body)?,
        "change_type":planned.change_type,
        "provider_output_retained":false,
        "body_returned":false,
    });
    let evidence = store.write_evidence(EvidenceClass::LiveRead, &planning_receipt)?;
    Ok(json!({
        "repository_head":contract.repository_head,
        "surface_sha256":contract.surface_sha256,
        "consumer_contract_sha256":contract.consumer_contract_sha256,
        "account_id":account_id,
        "reply_domain":target.reply_domain,
        "worker_script_name":target.worker_script_name,
        "zone_id":planned.zone_id,
        "worker_tag_sha256":planning_receipt["worker_tag_sha256"],
        "parent_zone_sha256":planning_receipt["parent_zone_sha256"],
        "catch_all_state_sha256":planning_receipt["catch_all_state_sha256"],
        "change_type":planning_receipt["change_type"],
        "provider_request_sha256":planning_receipt["provider_request_sha256"],
        "apply_body_sha256":planning_receipt["apply_body_sha256"],
        "planning_evidence_sha256":evidence.content_hash,
        "provider_output_retained":false,
        "body_returned":false,
    }))
}

fn activation_preflight_failure(store: &StateStore, receipt: Value) -> Result<Value> {
    let status = receipt
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let evidence = store.write_evidence(EvidenceClass::LiveRead, &receipt)?;
    Err(CliError::guided(
        "CFCTL_WORKSPACE_REPLY_SUBDOMAIN_ACTIVATION_PREFLIGHT_FAILED",
        format!("reply-subdomain activation stopped at typed provider state `{status}`"),
        format!(
            "Preserve body-free evidence {}; repair exactly `{status}`; do not replay, take over a conflicting rule, or target the parent-zone catch-all.",
            evidence.content_hash
        ),
    ))
}

#[derive(Debug, PartialEq, Eq)]
struct CatchAllObservation {
    state_sha256: String,
    desired_shape: bool,
    source_wrangler: bool,
}

async fn observe_catch_all(
    executor: &Executor,
    capability: &CapabilityV1,
    zone_id: &str,
    target: &Target,
    credential: &AuthCredential,
) -> std::result::Result<CatchAllObservation, Value> {
    let response = executor
        .execute_read(
            capability,
            &CallInput {
                selectors: json!({"zone_id":zone_id}),
                ..CallInput::default()
            },
            credential,
        )
        .await
        .map_err(|_| failure("catch_all_read_failed", "catch_all", true, None))?;
    project_catch_all(&response, target)
}

#[expect(
    clippy::too_many_lines,
    reason = "the exact catch-all identity, matcher, action, source, and body-free hash checks remain one fail-closed projection boundary"
)]
fn project_catch_all(
    response: &CloudflareResponseV1,
    target: &Target,
) -> std::result::Result<CatchAllObservation, Value> {
    if !response.success || response.status != 200 || !response.errors.is_empty() {
        return Err(failure(
            "catch_all_read_incomplete",
            "catch_all",
            true,
            None,
        ));
    }
    let Some(rule) = response.result.as_object() else {
        return Err(failure(
            "catch_all_projection_malformed",
            "catch_all",
            true,
            None,
        ));
    };
    let Some(id) = rule
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| lower_hex(id, 32))
    else {
        return Err(failure(
            "catch_all_projection_malformed",
            "catch_all",
            true,
            Some(1),
        ));
    };
    let Some(enabled) = rule.get("enabled").and_then(Value::as_bool) else {
        return Err(failure(
            "catch_all_projection_malformed",
            "catch_all",
            true,
            Some(1),
        ));
    };
    let Some(source) = rule
        .get("source")
        .and_then(Value::as_str)
        .filter(|source| matches!(*source, "api" | "wrangler"))
    else {
        return Err(failure(
            "catch_all_projection_malformed",
            "catch_all",
            true,
            Some(1),
        ));
    };
    let Some(name) = rule
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| name.len() <= 256)
    else {
        return Err(failure(
            "catch_all_projection_malformed",
            "catch_all",
            true,
            Some(1),
        ));
    };
    let Some(matchers) = rule.get("matchers").and_then(Value::as_array) else {
        return Err(failure(
            "catch_all_projection_malformed",
            "catch_all",
            true,
            Some(1),
        ));
    };
    let Some(actions) = rule.get("actions").and_then(Value::as_array) else {
        return Err(failure(
            "catch_all_projection_malformed",
            "catch_all",
            true,
            Some(1),
        ));
    };
    let matcher_exact = matchers.len() == 1
        && matchers[0].as_object().is_some_and(|matcher| {
            matcher.len() == 1 && matcher.get("type").and_then(Value::as_str) == Some("all")
        });
    let action = actions.first().filter(|_| actions.len() == 1);
    let action_type = action
        .and_then(|action| action.get("type"))
        .and_then(Value::as_str);
    let action_values = action
        .and_then(|action| action.get("value"))
        .and_then(Value::as_array);
    let action_valid = match action_type {
        Some("drop") => action_values.is_none_or(Vec::is_empty),
        Some("forward" | "worker") => action_values.is_some_and(|values| {
            values.len() == 1
                && values[0]
                    .as_str()
                    .is_some_and(|value| !value.is_empty() && value.len() <= 255)
        }),
        _ => false,
    };
    if !matcher_exact || !action_valid {
        return Err(failure(
            "catch_all_projection_malformed",
            "catch_all",
            true,
            Some(1),
        ));
    }
    let state = json!({
        "id":id,
        "enabled":enabled,
        "source":source,
        "name":name,
        "matchers":matchers,
        "actions":actions,
    });
    let state_sha256 = hash_value(&state)
        .map_err(|_| failure("catch_all_projection_malformed", "catch_all", true, Some(1)))?;
    let desired_shape = enabled
        && matcher_exact
        && action_type == Some("worker")
        && action_values.is_some_and(|values| {
            values.len() == 1 && values[0].as_str() == Some(target.worker_script_name.as_str())
        });
    Ok(CatchAllObservation {
        state_sha256,
        desired_shape,
        source_wrangler: source == "wrangler",
    })
}

async fn observe_worker_tag(
    executor: &Executor,
    workers: &CapabilityV1,
    target: &Target,
    credential: &AuthCredential,
) -> std::result::Result<String, Value> {
    let response = executor
        .execute_read(
            workers,
            &CallInput {
                selectors: json!({"account_id":target.account_id}),
                query: json!({"page":1,"per_page":100}),
                ..CallInput::default()
            },
            credential,
        )
        .await
        .map_err(|_| {
            failure(
                "worker_inventory_read_failed",
                "worker_inventory",
                true,
                None,
            )
        })?;
    project_worker_tag(&response, target)
}

fn activation_provider_request(target: &Target, worker_tag: &str) -> Value {
    json!({
        "owner_worker_tag":worker_tag,
        "rules":[],
        "catch_all_rules":[{
            "target":format!("*@{}",target.reply_domain),
            "rule":{
                "matchers":[{"type":"all"}],
                "actions":[{"type":"worker","value":[target.worker_script_name.clone()]}]
            }
        }]
    })
}

async fn observe_activation_plan(
    executor: &Executor,
    account_plan: &CapabilityV1,
    account_id: &str,
    target: &Target,
    parent_zone: &ParentZone,
    provider_request: &Value,
    credential: &AuthCredential,
) -> std::result::Result<ActivationPlan, Value> {
    let mut plan_read = account_plan.clone();
    plan_read.mutating = false;
    plan_read.risk = RiskClass::Read;
    plan_read.effect = EffectClass::ReadOnly;
    plan_read.adapter_status = AdapterStatus::DynamicApi;
    plan_read.blocked_reason = None;
    let response = executor
        .execute_read(
            &plan_read,
            &CallInput {
                selectors: json!({"account_id":account_id}),
                body: Some(provider_request.clone()),
                ..CallInput::default()
            },
            credential,
        )
        .await
        .map_err(|_| failure("account_plan_read_failed", "account_plan", true, None))?;
    project_activation_account_plan(&response, target, parent_zone)
}

pub(super) fn local_artifact_paths(capability: &CapabilityV1) -> Option<Vec<PathBuf>> {
    let contract = capability
        .workspace_reply_subdomain_ingress
        .as_ref()
        .filter(|contract| contract.operation_kind == "activate")?;
    let root = PathBuf::from(&contract.repository_root);
    Some(vec![
        root.join(&contract.surface_path).parent()?.to_path_buf(),
        root.join(&contract.consumer_contract_path)
            .parent()?
            .to_path_buf(),
    ])
}

pub(super) fn acquire_activation_target_lock(
    store: &StateStore,
    plan: &PlanV1,
    input: &CallInput,
) -> Result<Option<cfctl_storage::EmailRoutingCatchAllLock>> {
    let zone_id = if plan
        .capability
        .workspace_reply_subdomain_ingress
        .as_ref()
        .is_some_and(|contract| contract.operation_kind == "activate")
    {
        activation_target(plan)?.get("zone_id")
    } else if plan.capability.id == CATCH_ALL_UPDATE_ID
        && plan.capability.method == "PUT"
        && plan.capability.path == CATCH_ALL_UPDATE_PATH
        && plan.capability.mutating
    {
        input.selectors.get("zone_id")
    } else {
        return Ok(None);
    }
    .and_then(Value::as_str)
    .filter(|zone_id| lower_hex(zone_id, 32))
    .ok_or_else(|| {
        CliError::Input(
            "Email Routing catch-all lock target omitted its exact provider zone identity"
                .to_owned(),
        )
    })?;
    if input
        .selectors
        .get("account_id")
        .and_then(Value::as_str)
        .is_some_and(|account_id| account_id != plan.account_id)
    {
        return Err(CliError::Input(
            "Email Routing catch-all lock account identity drifted".to_owned(),
        ));
    }
    Ok(Some(
        store
            .lock_email_routing_catch_all(&plan.account_id, zone_id)
            .map_err(CliError::Storage)?,
    ))
}

pub(super) fn validate_bound_plan(store: &StateStore, plan: &PlanV1) -> Result<()> {
    let Some(contract) = plan
        .capability
        .workspace_reply_subdomain_ingress
        .as_ref()
        .filter(|contract| contract.operation_kind == "activate")
    else {
        return Ok(());
    };
    let current = load(store, &plan.capability.id)?.ok_or_else(|| {
        CliError::Input(
            "reply-subdomain ingress activation is no longer uniquely available; create a new plan"
                .to_owned(),
        )
    })?;
    if current.workspace_reply_subdomain_ingress.as_ref() != Some(contract) {
        return Err(CliError::Input(
            "reply-subdomain ingress activation repository authority drifted; create a new plan"
                .to_owned(),
        ));
    }
    let input: CallInput = serde_json::from_value(plan.input.clone())?;
    let desired = target(&input, &plan.account_id)?;
    let bound = activation_target(plan)?;
    for (key, expected) in [
        ("repository_head", contract.repository_head.as_str()),
        ("surface_sha256", contract.surface_sha256.as_str()),
        (
            "consumer_contract_sha256",
            contract.consumer_contract_sha256.as_str(),
        ),
        ("account_id", plan.account_id.as_str()),
        ("reply_domain", desired.reply_domain.as_str()),
        ("worker_script_name", desired.worker_script_name.as_str()),
    ] {
        if bound.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(CliError::Input(format!(
                "reply-subdomain activation target `{key}` drifted; create a new plan"
            )));
        }
    }
    if !matches!(
        bound.get("change_type").and_then(Value::as_str),
        Some("added" | "updated")
    ) {
        return Err(CliError::Input(
            "reply-subdomain activation plan is no longer one non-destructive provider change"
                .to_owned(),
        ));
    }
    let zone_id = bound
        .get("zone_id")
        .and_then(Value::as_str)
        .filter(|value| lower_hex(value, 32))
        .ok_or_else(|| {
            CliError::Input(
                "reply-subdomain activation target omitted its exact provider zone identity"
                    .to_owned(),
            )
        })?;
    if bound.get("parent_zone_sha256").and_then(Value::as_str)
        != Some(sha256(zone_id.as_bytes()).as_str())
        || !bound
            .get("worker_tag_sha256")
            .and_then(Value::as_str)
            .is_some_and(is_sha256)
        || !bound
            .get("catch_all_state_sha256")
            .and_then(Value::as_str)
            .is_some_and(is_sha256)
        || !bound
            .get("provider_request_sha256")
            .and_then(Value::as_str)
            .is_some_and(is_sha256)
        || !bound
            .get("apply_body_sha256")
            .and_then(Value::as_str)
            .is_some_and(is_sha256)
        || !bound
            .get("planning_evidence_sha256")
            .and_then(Value::as_str)
            .is_some_and(is_sha256)
        || bound
            .get("provider_output_retained")
            .and_then(Value::as_bool)
            != Some(false)
        || bound.get("body_returned").and_then(Value::as_bool) != Some(false)
        || zone_id.is_empty()
    {
        return Err(CliError::Input(
            "reply-subdomain activation provider-plan binding drifted; create a new plan"
                .to_owned(),
        ));
    }
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "fresh parent-zone, Worker, provider-plan, payload, and single-attempt mutation checks remain visible in one execution boundary"
)]
pub(super) async fn run(
    store: &StateStore,
    plan: &PlanV1,
    credential: &AuthCredential,
) -> Result<Value> {
    validate_bound_plan(store, plan)?;
    let catalog = super::ensure_catalog(store).await?;
    let zone_capability = exact_zone_list_capability(&catalog)?;
    let catch_all = catalog.get(CATCH_ALL_UPDATE_ID).ok_or_else(|| {
        CliError::Input("Email Routing catch-all update source is unavailable".to_owned())
    })?;
    let workers = catalog.get(WORKERS_LIST_ID).ok_or_else(|| {
        CliError::Input("complete Worker inventory source is unavailable".to_owned())
    })?;
    let account_plan = catalog.get(ACCOUNT_PLAN_ID).ok_or_else(|| {
        CliError::Input("Email Routing account-plan source is unavailable".to_owned())
    })?;
    let catch_all_get = catalog.get(CATCH_ALL_GET_ID).ok_or_else(|| {
        CliError::Input("Email Routing catch-all observation source is unavailable".to_owned())
    })?;
    validate_activation_provider_contracts(
        zone_capability,
        workers,
        account_plan,
        catch_all_get,
        catch_all,
    )?;
    let input: CallInput = serde_json::from_value(plan.input.clone())?;
    let desired = target(&input, &plan.account_id)?;
    let bound = activation_target(plan)?;
    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let parent_zone =
        match resolve_active_parent_zone_id(&executor, zone_capability, &desired, credential).await
        {
            Ok(zone_id) => zone_id,
            Err(receipt) => {
                return Ok(activation_precondition_receipt(
                    plan,
                    &desired,
                    receipt_status(&receipt),
                ));
            }
        };
    let catch_all_state = match observe_catch_all(
        &executor,
        catch_all_get,
        &parent_zone.id,
        &desired,
        credential,
    )
    .await
    {
        Ok(observation) => observation,
        Err(receipt) => {
            return Ok(activation_precondition_receipt(
                plan,
                &desired,
                receipt_status(&receipt),
            ));
        }
    };
    if bound.get("catch_all_state_sha256").and_then(Value::as_str)
        != Some(catch_all_state.state_sha256.as_str())
    {
        return Ok(activation_precondition_receipt(
            plan,
            &desired,
            "fresh_catch_all_state_drifted",
        ));
    }
    let worker_tag = match observe_worker_tag(&executor, workers, &desired, credential).await {
        Ok(worker_tag) => worker_tag,
        Err(receipt) => {
            return Ok(activation_precondition_receipt(
                plan,
                &desired,
                receipt_status(&receipt),
            ));
        }
    };
    let provider_request = activation_provider_request(&desired, &worker_tag);
    let fresh_plan = match observe_activation_plan(
        &executor,
        account_plan,
        &plan.account_id,
        &desired,
        &parent_zone,
        &provider_request,
        credential,
    )
    .await
    {
        Ok(fresh_plan) => fresh_plan,
        Err(receipt) => {
            return Ok(activation_precondition_receipt(
                plan,
                &desired,
                receipt_status(&receipt),
            ));
        }
    };
    let apply_body = activation_apply_body(&desired.worker_script_name, &worker_tag);
    if let Some(status) = fresh_activation_state_drift(
        bound,
        &parent_zone.id,
        &worker_tag,
        &provider_request,
        &apply_body,
        &fresh_plan,
    ) {
        return Ok(activation_precondition_receipt(plan, &desired, status));
    }
    let provider_input = CallInput {
        selectors: json!({"zone_id":parent_zone.id}),
        body: Some(apply_body),
        ..CallInput::default()
    };
    let mut provider_plan = plan.clone();
    provider_plan.capability = catch_all.clone();
    provider_plan.input = serde_json::to_value(&provider_input)?;
    provider_plan.status = PlanStatus::Consumed;
    provider_plan.refresh_hash()?;
    let mutation_executor = executor.with_max_retries(0);
    let Ok(response) = mutation_executor
        .execute_consumed_plan_with_input(
            &mut provider_plan,
            &plan.catalog_hash,
            credential,
            &provider_input,
        )
        .await
    else {
        return Ok(activation_apply_receipt(plan, &desired, false, None, true));
    };
    Ok(activation_apply_receipt(
        plan,
        &desired,
        response.success,
        Some(response.status),
        true,
    ))
}

pub(super) async fn verify(
    store: &StateStore,
    plan: &PlanV1,
    credential: &AuthCredential,
) -> Value {
    match verify_inner(store, plan, credential).await {
        Ok(value) => value,
        Err(error) => json!({
            "passed":false,
            "basis":format!("reply-subdomain activation readback failed closed: {error}"),
            "provider_output_retained":false,
            "body_returned":false,
        }),
    }
}

async fn verify_inner(
    store: &StateStore,
    plan: &PlanV1,
    credential: &AuthCredential,
) -> Result<Value> {
    validate_bound_plan(store, plan)?;
    let catalog = super::ensure_catalog(store).await?;
    let profiles = ProfilesConfig::load(store)?;
    let profile = profiles.selected(Some(&plan.profile_id))?;
    let generation = profile.credential_generation_id.as_deref().ok_or_else(|| {
        CliError::Input("reply-subdomain activation credential generation is missing".to_owned())
    })?;
    let input: CallInput = serde_json::from_value(plan.input.clone())?;
    let desired = target(&input, &plan.account_id)?;
    let zone_capability = exact_zone_list_capability(&catalog)?;
    let workers = catalog.get(WORKERS_LIST_ID).ok_or_else(|| {
        CliError::Input("complete Worker inventory source is unavailable".to_owned())
    })?;
    let account_plan = catalog.get(ACCOUNT_PLAN_ID).ok_or_else(|| {
        CliError::Input("Email Routing account-plan source is unavailable".to_owned())
    })?;
    let catch_all_get = catalog.get(CATCH_ALL_GET_ID).ok_or_else(|| {
        CliError::Input("Email Routing catch-all observation source is unavailable".to_owned())
    })?;
    let catch_all = catalog.get(CATCH_ALL_UPDATE_ID).ok_or_else(|| {
        CliError::Input("Email Routing catch-all update source is unavailable".to_owned())
    })?;
    validate_activation_provider_contracts(
        zone_capability,
        workers,
        account_plan,
        catch_all_get,
        catch_all,
    )?;
    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let parent_zone =
        resolve_active_parent_zone_id(&executor, zone_capability, &desired, credential)
            .await
            .map_err(|receipt| {
                CliError::Input(format!(
                    "reply-subdomain activation parent-zone readback stopped at `{}`",
                    receipt_status(&receipt)
                ))
            })?;
    let catch_all_observation = observe_catch_all(
        &executor,
        catch_all_get,
        &parent_zone.id,
        &desired,
        credential,
    )
    .await
    .map_err(|receipt| {
        CliError::Input(format!(
            "reply-subdomain activation catch-all readback stopped at `{}`",
            receipt_status(&receipt)
        ))
    })?;
    let receipt = read(
        store,
        &catalog,
        &plan.capability,
        &input,
        credential,
        profile,
        &plan.account_id,
        Some(&plan.account_id),
        generation,
    )
    .await?;
    let passed = receipt_is_complete(&receipt)
        && receipt.get("dns").and_then(Value::as_str) == Some("ok")
        && receipt.get("routing_rule").and_then(Value::as_str) == Some("ok")
        && catch_all_observation.desired_shape
        && catch_all_observation.source_wrangler;
    Ok(json!({
        "passed":passed,
        "basis":if passed {
            "the exact reply-subdomain DNS, direct catch-all shape/source, and one exact account-inventory all-matcher Worker rule passed body-free readback"
        } else {
            "the exact reply-subdomain body-free readback did not prove DNS, direct catch-all shape/source, and account-inventory routing readiness"
        },
        "readback":receipt,
        "catch_all_readback":{
            "state_sha256":catch_all_observation.state_sha256,
            "desired_shape":catch_all_observation.desired_shape,
            "source_wrangler":catch_all_observation.source_wrangler,
        },
        "provider_output_retained":false,
        "body_returned":false,
    }))
}

fn activation_target(plan: &PlanV1) -> Result<&serde_json::Map<String, Value>> {
    plan.targets
        .pointer("/adapter/workspace_reply_subdomain_ingress_activation")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CliError::Input(
                "reply-subdomain activation plan omitted its bound provider target".to_owned(),
            )
        })
}

fn receipt_status(receipt: &Value) -> &str {
    receipt
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("fresh_provider_precondition_unproved")
}

fn fresh_activation_state_drift(
    bound: &serde_json::Map<String, Value>,
    parent_zone_id: &str,
    worker_tag: &str,
    provider_request: &Value,
    apply_body: &Value,
    fresh_plan: &ActivationPlan,
) -> Option<&'static str> {
    if bound.get("zone_id").and_then(Value::as_str) != Some(parent_zone_id)
        || fresh_plan.zone_id != parent_zone_id
        || bound.get("parent_zone_sha256").and_then(Value::as_str)
            != Some(sha256(parent_zone_id.as_bytes()).as_str())
    {
        return Some("fresh_parent_zone_drifted");
    }
    if bound.get("worker_tag_sha256").and_then(Value::as_str)
        != Some(sha256(worker_tag.as_bytes()).as_str())
    {
        return Some("fresh_worker_identity_drifted");
    }
    if bound.get("provider_request_sha256").and_then(Value::as_str)
        != hash_value(provider_request).ok().as_deref()
        || bound.get("apply_body_sha256").and_then(Value::as_str)
            != hash_value(apply_body).ok().as_deref()
    {
        return Some("fresh_activation_payload_drifted");
    }
    if bound.get("change_type").and_then(Value::as_str) != Some(fresh_plan.change_type.as_str()) {
        return Some("fresh_account_plan_drifted");
    }
    None
}

fn activation_precondition_receipt(plan: &PlanV1, target: &Target, status: &str) -> Value {
    json!({
        "adapter":ACTIVATION_APPLY_PROJECTION,
        "success":false,
        "boundary_crossed":false,
        "schema_version":1,
        "cfctl_operation_id":plan.operation_id,
        "reply_domain_sha256":sha256(target.reply_domain.as_bytes()),
        "worker_target_sha256":sha256(target.worker_script_name.as_bytes()),
        "status":status,
        "provider_status":Value::Null,
        "failure_code":"CFCTL_WORKSPACE_REPLY_SUBDOMAIN_FRESH_PRECONDITION_FAILED",
        "provider_output_retained":false,
        "body_returned":false,
    })
}

fn activation_apply_receipt(
    plan: &PlanV1,
    target: &Target,
    success: bool,
    status: Option<u16>,
    boundary_crossed: bool,
) -> Value {
    json!({
        "adapter":ACTIVATION_APPLY_PROJECTION,
        "success":success,
        "boundary_crossed":boundary_crossed,
        "schema_version":1,
        "cfctl_operation_id":plan.operation_id,
        "reply_domain_sha256":sha256(target.reply_domain.as_bytes()),
        "worker_target_sha256":sha256(target.worker_script_name.as_bytes()),
        "provider_status":status,
        "failure_code":if success { Value::Null } else { Value::String("CFCTL_WORKSPACE_REPLY_SUBDOMAIN_PROVIDER_RESULT_AMBIGUOUS".to_owned()) },
        "provider_output_retained":false,
        "body_returned":false,
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "profile, account, credential generation, catalog, credential, and workspace contract stay explicit at the composed provider-read boundary"
)]
pub(super) async fn read(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    credential: &AuthCredential,
    profile: &ProfileMetadata,
    account_id: &str,
    requested_account: Option<&str>,
    credential_generation_id: &str,
) -> Result<Value> {
    let contract = capability
        .workspace_reply_subdomain_ingress
        .as_ref()
        .ok_or_else(|| CliError::Input("reply-subdomain ingress contract missing".to_owned()))?;
    let current = load(store, &capability.id)?.ok_or_else(|| {
        CliError::Input(
            "reply-subdomain ingress authority is no longer uniquely available".to_owned(),
        )
    })?;
    if current.workspace_reply_subdomain_ingress.as_ref() != Some(contract) {
        return Err(CliError::Input(
            "reply-subdomain ingress repository authority drifted".to_owned(),
        ));
    }
    if !profile_is_bound_for_read(
        profile,
        account_id,
        requested_account,
        credential_generation_id,
    ) {
        return Err(CliError::Input(
            "reply-subdomain ingress profile, account, or credential generation binding drifted"
                .to_owned(),
        ));
    }
    let target = target(input, account_id)?;
    let zone_capability = exact_zone_list_capability(catalog)?;
    let dns_capability = exact_capability(catalog, SUBDOMAIN_DNS_ID, SUBDOMAIN_DNS_PATH)?;
    let catch_all_capability = exact_capability(catalog, CATCH_ALL_GET_ID, CATCH_ALL_GET_PATH)?;
    validate_provider_contracts(zone_capability, dns_capability, catch_all_capability)?;

    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let parent_zone = match resolve_active_parent_zone_id(
        &executor,
        zone_capability,
        &target,
        credential,
    )
    .await
    {
        Ok(zone) => zone,
        Err(receipt) => return Ok(receipt),
    };

    let Ok(dns) = executor
        .execute_read(
            dns_capability,
            &CallInput {
                selectors: json!({"zone_id":parent_zone.id}),
                query: json!({"subdomain":target.reply_domain}),
                ..CallInput::default()
            },
            credential,
        )
        .await
    else {
        return Ok(failure("dns_read_failed", "dns", true, None));
    };
    let dns_state = match project_subdomain_dns(&dns, &target.reply_domain) {
        Ok(state) => state,
        Err(receipt) => return Ok(receipt),
    };
    let routing_state = match observe_catch_all(
        &executor,
        catch_all_capability,
        &parent_zone.id,
        &target,
        credential,
    )
    .await
    {
        Ok(observation) if observation.desired_shape => "ok",
        Ok(_) => "drift",
        Err(receipt) => return Ok(receipt),
    };
    Ok(success(&target, dns_state, routing_state))
}

fn profile_is_bound_for_read(
    profile: &ProfileMetadata,
    account_id: &str,
    requested_account: Option<&str>,
    credential_generation_id: &str,
) -> bool {
    let account_is_bound = match profile.kind {
        ProfileKind::GlobalKey => {
            profile.emergency_only
                && profile.account_id.is_none()
                && requested_account == Some(account_id)
        }
        _ => profile.account_id.as_deref() == Some(account_id),
    };
    account_is_bound
        && profile.credential_generation_id.as_deref() == Some(credential_generation_id)
}

#[derive(Debug)]
struct Target {
    account_id: String,
    reply_domain: String,
    worker_script_name: String,
}

fn target(input: &CallInput, account_id: &str) -> Result<Target> {
    let selectors = input.selectors.as_object().ok_or_else(|| {
        CliError::Input("reply-subdomain ingress requires exact selectors".to_owned())
    })?;
    if input.body.is_some()
        || input
            .query
            .as_object()
            .is_none_or(|query| !query.is_empty())
        || selectors.len() != 3
        || selectors.get("account_id").and_then(Value::as_str) != Some(account_id)
    {
        return Err(CliError::Input(
            "reply-subdomain ingress accepts only exact account_id, reply_domain, and worker_script_name selectors"
                .to_owned(),
        ));
    }
    let reply_domain = selectors
        .get("reply_domain")
        .and_then(Value::as_str)
        .and_then(normalize_domain)
        .ok_or_else(|| CliError::Input("reply_domain is not a valid exact DNS name".to_owned()))?;
    let worker_script_name = selectors
        .get("worker_script_name")
        .and_then(Value::as_str)
        .filter(|value| valid_worker_name(value))
        .ok_or_else(|| CliError::Input("worker_script_name is invalid".to_owned()))?
        .to_owned();
    Ok(Target {
        account_id: account_id.to_owned(),
        reply_domain,
        worker_script_name,
    })
}

#[derive(Debug, PartialEq, Eq)]
enum ZoneState {
    Missing,
    Drift,
    Active(ParentZone),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParentZone {
    id: String,
    name: String,
}

async fn resolve_active_parent_zone_id(
    executor: &Executor,
    zone_capability: &CapabilityV1,
    target: &Target,
    credential: &AuthCredential,
) -> std::result::Result<ParentZone, Value> {
    for parent_zone in parent_zone_candidates(&target.reply_domain) {
        let zone = executor
            .execute_read(
                zone_capability,
                &CallInput {
                    query: json!({
                        "account.id":target.account_id,
                        "name":parent_zone,
                        "page":1,
                        "per_page":50,
                    }),
                    ..CallInput::default()
                },
                credential,
            )
            .await
            .map_err(|_| failure("parent_zone_read_failed", "parent_zone", true, None))?;
        match project_zone(&zone, &target.account_id, &parent_zone)? {
            ZoneState::Missing => {}
            ZoneState::Drift => {
                return Err(failure(
                    "parent_zone_inactive",
                    "parent_zone",
                    true,
                    Some(1),
                ));
            }
            ZoneState::Active(zone) => return Ok(zone),
        }
    }
    Err(failure("parent_zone_missing", "parent_zone", true, Some(0)))
}

fn project_zone(
    response: &CloudflareResponseV1,
    account_id: &str,
    expected_zone: &str,
) -> std::result::Result<ZoneState, Value> {
    if !successful_complete_page(response) {
        return Err(failure("zone_read_incomplete", "zone", true, None));
    }
    let Some(zones) = response.result.as_array() else {
        return Err(failure("zone_projection_malformed", "zone", true, None));
    };
    if zones.is_empty() {
        return Ok(ZoneState::Missing);
    }
    if zones.len() != 1 {
        return Err(failure(
            "zone_cardinality_ambiguous",
            "zone",
            true,
            Some(zones.len()),
        ));
    }
    let zone = &zones[0];
    let exact = zone
        .get("name")
        .and_then(Value::as_str)
        .and_then(normalize_domain)
        .as_deref()
        == Some(expected_zone)
        && zone.pointer("/account/id").and_then(Value::as_str) == Some(account_id)
        && zone
            .get("id")
            .and_then(Value::as_str)
            .is_some_and(|id| !id.is_empty())
        && zone.get("status").and_then(Value::as_str).is_some();
    if !exact {
        return Err(failure("zone_projection_malformed", "zone", true, Some(1)));
    }
    if zone.get("status").and_then(Value::as_str) != Some("active") {
        return Ok(ZoneState::Drift);
    }
    Ok(ZoneState::Active(ParentZone {
        id: zone
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        name: expected_zone.to_owned(),
    }))
}

fn project_subdomain_dns(
    response: &CloudflareResponseV1,
    reply_domain: &str,
) -> std::result::Result<&'static str, Value> {
    if !response.success || response.status != 200 || !response.errors.is_empty() {
        return Err(failure("dns_read_incomplete", "dns", true, None));
    }
    let records = if let Some(records) = response.result.as_array() {
        records
    } else if let Some(result) = response.result.as_object() {
        match result.get("errors") {
            None | Some(Value::Null) => {}
            Some(Value::Array(errors)) if errors.is_empty() => {}
            Some(Value::Array(_)) => return Ok("drift"),
            Some(_) => return Err(failure("dns_projection_malformed", "dns", true, None)),
        }
        let singular = result.get("record");
        let plural = result.get("records");
        match (singular, plural) {
            (Some(Value::Array(records)), None) | (None, Some(Value::Array(records))) => records,
            _ => return Err(failure("dns_projection_malformed", "dns", true, None)),
        }
    } else {
        return Err(failure("dns_projection_malformed", "dns", true, None));
    };
    if !coherent_optional_result_info(response.result_info.as_ref(), records.len()) {
        return Err(failure("dns_read_incomplete", "dns", true, None));
    }
    if records.is_empty() {
        return Ok("missing");
    }
    let mut observed = BTreeSet::new();
    let mut mx_count = 0_usize;
    let mut duplicate_mx = false;
    for record in records {
        let Some(record_type) = record.get("type").and_then(Value::as_str) else {
            return Err(failure(
                "dns_projection_malformed",
                "dns",
                true,
                Some(records.len()),
            ));
        };
        if record_type != "MX" {
            continue;
        }
        mx_count += 1;
        let exact = record
            .get("name")
            .and_then(Value::as_str)
            .and_then(normalize_domain)
            .as_deref()
            == Some(reply_domain);
        let Some(content) = record
            .get("content")
            .and_then(Value::as_str)
            .and_then(normalize_domain)
        else {
            return Err(failure(
                "dns_projection_malformed",
                "dns",
                true,
                Some(records.len()),
            ));
        };
        if !exact {
            return Err(failure(
                "dns_projection_malformed",
                "dns",
                true,
                Some(records.len()),
            ));
        }
        duplicate_mx |= !observed.insert(content);
    }
    let expected = CANONICAL_MX.into_iter().map(str::to_owned).collect();
    Ok(
        if mx_count == CANONICAL_MX.len() && !duplicate_mx && observed == expected {
            "ok"
        } else {
            "drift"
        },
    )
}

fn coherent_optional_result_info(result_info: Option<&Value>, record_count: usize) -> bool {
    let Some(info) = result_info else {
        return true;
    };
    let Some(info) = info.as_object() else {
        return false;
    };
    if info
        .keys()
        .any(|key| !DNS_RESULT_INFO_KEYS.contains(&key.as_str()))
    {
        return false;
    }
    let count = record_count as u64;
    let provider_complete = info.get("page").and_then(Value::as_u64) == Some(1)
        && info.get("total_pages").and_then(Value::as_u64) == Some(1)
        && info.get("count").and_then(Value::as_u64) == Some(count)
        && info.get("total_count").and_then(Value::as_u64) == Some(count);
    let cfctl_complete = match (info.get("cfctl_pages"), info.get("cfctl_page_complete")) {
        (None, None) => true,
        (Some(pages), Some(complete)) => {
            pages.as_u64() == Some(1) && complete.as_bool() == Some(true)
        }
        _ => false,
    };
    provider_complete
        && cfctl_complete
        && info.get("per_page").is_none_or(|value| {
            value
                .as_u64()
                .is_some_and(|per_page| per_page > 0 && count <= per_page)
        })
}

fn parent_zone_candidates(reply_domain: &str) -> Vec<String> {
    let labels = reply_domain.split('.').collect::<Vec<_>>();
    (1..labels.len().saturating_sub(1))
        .map(|index| labels[index..].join("."))
        .collect()
}

fn success(target: &Target, dns: &str, routing_rule: &str) -> Value {
    json!({
        "adapter":cfctl_workspace::MAILDESK_REPLY_SUBDOMAIN_INGRESS_PROJECTION,
        "success":true,
        "boundary_crossed":true,
        "schema_version":1,
        "reply_domain_sha256":sha256(target.reply_domain.as_bytes()),
        "worker_target_sha256":sha256(target.worker_script_name.as_bytes()),
        "dns_scope":"exact_reply_subdomain",
        "routing_scope":ROUTING_SCOPE,
        "dns":dns,
        "routing_rule":routing_rule,
        "provider_output_retained":false,
        "body_returned":false,
    })
}

fn project_worker_tag(
    response: &CloudflareResponseV1,
    target: &Target,
) -> std::result::Result<String, Value> {
    if !successful_complete_page(response) {
        return Err(failure(
            "worker_inventory_incomplete",
            "worker_inventory",
            true,
            None,
        ));
    }
    let Some(workers) = response.result.as_array() else {
        return Err(failure(
            "worker_inventory_malformed",
            "worker_inventory",
            true,
            None,
        ));
    };
    let matches = workers
        .iter()
        .filter(|worker| {
            worker.get("name").and_then(Value::as_str) == Some(target.worker_script_name.as_str())
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(failure(
            "worker_cardinality_ambiguous",
            "worker_inventory",
            true,
            Some(matches.len()),
        ));
    }
    matches[0]
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| lower_hex(id, 32))
        .map(str::to_owned)
        .ok_or_else(|| {
            failure(
                "worker_inventory_malformed",
                "worker_inventory",
                true,
                Some(1),
            )
        })
}

#[derive(Debug, PartialEq, Eq)]
struct ActivationPlan {
    zone_id: String,
    change_type: String,
}

#[expect(
    clippy::too_many_lines,
    reason = "every provider-plan cardinality and exact-target branch remains visible at the body-free projection boundary"
)]
fn project_activation_account_plan(
    response: &CloudflareResponseV1,
    target: &Target,
    parent_zone: &ParentZone,
) -> std::result::Result<ActivationPlan, Value> {
    if !response.success || response.status != 200 || !response.errors.is_empty() {
        return Err(failure(
            "account_plan_incomplete",
            "account_plan",
            true,
            None,
        ));
    }
    let Some(zones) = response.result.get("zones").and_then(Value::as_array) else {
        return Err(failure(
            "account_plan_malformed",
            "account_plan",
            true,
            None,
        ));
    };
    if zones.is_empty() {
        return Err(failure(
            "account_plan_no_change",
            "account_plan",
            true,
            Some(0),
        ));
    }
    if zones.len() != 1 {
        return Err(failure(
            "account_plan_cardinality_ambiguous",
            "account_plan",
            true,
            Some(zones.len()),
        ));
    }
    let zone = &zones[0];
    let Some(zone_id) = zone
        .get("zone_id")
        .and_then(Value::as_str)
        .filter(|id| lower_hex(id, 32))
    else {
        return Err(failure(
            "account_plan_malformed",
            "account_plan",
            true,
            Some(1),
        ));
    };
    if zone_id != parent_zone.id
        || (zone.get("zone_name").is_some()
            && zone
                .get("zone_name")
                .and_then(Value::as_str)
                .and_then(normalize_domain)
                .as_deref()
                != Some(parent_zone.name.as_str()))
    {
        return Err(failure(
            "account_plan_target_mismatch",
            "account_plan",
            true,
            Some(1),
        ));
    }
    let Some(changes) = zone.get("changes").and_then(Value::as_array) else {
        return Err(failure(
            "account_plan_malformed",
            "account_plan",
            true,
            Some(1),
        ));
    };
    if changes.is_empty() {
        return Err(failure(
            "account_plan_no_change",
            "account_plan",
            true,
            Some(0),
        ));
    }
    if changes.len() != 1 {
        return Err(failure(
            "account_plan_cardinality_ambiguous",
            "account_plan",
            true,
            Some(changes.len()),
        ));
    }
    let change = &changes[0];
    let expected_target = format!("*@{}", target.reply_domain);
    if change.get("target").and_then(Value::as_str) != Some(expected_target.as_str()) {
        return Err(failure(
            "account_plan_target_mismatch",
            "account_plan",
            true,
            Some(1),
        ));
    }
    let change_type = change.get("type").and_then(Value::as_str);
    if !matches!(change_type, Some("added" | "updated")) {
        return Err(failure(
            "account_plan_change_not_additive",
            "account_plan",
            true,
            Some(1),
        ));
    }
    Ok(ActivationPlan {
        zone_id: zone_id.to_owned(),
        change_type: change_type.unwrap_or_default().to_owned(),
    })
}

fn failure(status: &str, stage: &str, boundary_crossed: bool, match_count: Option<usize>) -> Value {
    json!({
        "adapter":cfctl_workspace::MAILDESK_REPLY_SUBDOMAIN_INGRESS_PROJECTION,
        "success":false,
        "boundary_crossed":boundary_crossed,
        "schema_version":1,
        "status":status,
        "stage":stage,
        "match_count":match_count,
        "provider_output_retained":false,
        "body_returned":false,
    })
}

fn successful_complete_page(response: &CloudflareResponseV1) -> bool {
    let result_count = response.result.as_array().map(Vec::len);
    response.success
        && response.status == 200
        && response.errors.is_empty()
        && response.result_info.as_ref().is_some_and(|info| {
            info.get("cfctl_page_complete").and_then(Value::as_bool) == Some(true)
                && info
                    .get("page")
                    .and_then(Value::as_u64)
                    .is_some_and(|page| {
                        page > 0
                            && info.get("total_pages").and_then(Value::as_u64) == Some(page)
                            && info.get("cfctl_pages").and_then(Value::as_u64) == Some(page)
                    })
                && result_count.is_some_and(|count| {
                    info.get("count").and_then(Value::as_u64) == Some(count as u64)
                        && info.get("total_count").and_then(Value::as_u64) == Some(count as u64)
                })
        })
}

fn exact_zone_list_capability(catalog: &CatalogSnapshot) -> Result<&CapabilityV1> {
    exact_capability(catalog, ZONE_LIST_ID, ZONE_LIST_PATH)
}

fn exact_capability<'a>(
    catalog: &'a CatalogSnapshot,
    id: &str,
    path: &str,
) -> Result<&'a CapabilityV1> {
    catalog
        .get(id)
        .filter(|capability| capability.method == "GET" && capability.path == path)
        .ok_or_else(|| {
            CliError::Input(format!(
                "reply-subdomain ingress provider source `{id}` is unavailable or drifted"
            ))
        })
}

fn validate_provider_contracts(
    zone: &CapabilityV1,
    dns: &CapabilityV1,
    catch_all: &CapabilityV1,
) -> Result<()> {
    let common = |capability: &CapabilityV1| {
        !capability.mutating
            && capability.request_schema.is_none()
            && matches!(
                capability.adapter_status,
                AdapterStatus::Native | AdapterStatus::DynamicApi
            )
            && capability
                .response_contract
                .as_ref()
                .is_some_and(|contract| {
                    contract.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
                        && contract.success_statuses == ["200"]
                        && contract.success_media_types == ["application/json"]
                })
    };
    let selector = |capability: &CapabilityV1, name: &str, location: &str| {
        capability
            .selectors
            .iter()
            .any(|selector| selector.name == name && selector.location == location)
    };
    let zone_ok = common(zone)
        && zone
            .permissions
            .iter()
            .any(|permission| permission == "Zone Zone Read")
        && ["name", "account.id", "page", "per_page"]
            .iter()
            .all(|name| selector(zone, name, "query"));
    let dns_ok = common(dns)
        && dns
            .permissions
            .iter()
            .any(|permission| permission == "Zone Settings Read")
        && selector(dns, "zone_id", "path")
        && selector(dns, "subdomain", "query");
    let catch_all_ok = common(catch_all)
        && catch_all.id == CATCH_ALL_GET_ID
        && catch_all.path == CATCH_ALL_GET_PATH
        && catch_all
            .permissions
            .iter()
            .any(|permission| permission == "Email Routing Rules Read")
        && selector(catch_all, "zone_id", "path");
    if !zone_ok || !dns_ok || !catch_all_ok {
        return Err(CliError::Input(
            "reply-subdomain ingress parent-zone, subdomain DNS, or parent-zone catch-all source contract drifted"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_activation_provider_contracts(
    zone: &CapabilityV1,
    workers: &CapabilityV1,
    account_plan: &CapabilityV1,
    catch_all_get: &CapabilityV1,
    catch_all: &CapabilityV1,
) -> Result<()> {
    let selector = |capability: &CapabilityV1, name: &str, location: &str| {
        capability
            .selectors
            .iter()
            .any(|selector| selector.name == name && selector.location == location)
    };
    let envelope = |capability: &CapabilityV1| {
        capability
            .response_contract
            .as_ref()
            .is_some_and(|contract| {
                contract.body_mode == ResponseBodyModeV1::CloudflareJsonEnvelope
                    && contract.success_statuses == ["200"]
                    && contract.success_media_types == ["application/json"]
            })
    };
    let zone_ok = zone.id == ZONE_LIST_ID
        && zone.method == "GET"
        && zone.path == ZONE_LIST_PATH
        && !zone.mutating
        && zone
            .permissions
            .iter()
            .any(|permission| permission == "Zone Zone Read")
        && ["name", "account.id", "page", "per_page"]
            .iter()
            .all(|name| selector(zone, name, "query"))
        && envelope(zone);
    let workers_ok = workers.id == WORKERS_LIST_ID
        && workers.method == "GET"
        && workers.path == WORKERS_LIST_PATH
        && !workers.mutating
        && workers
            .permissions
            .iter()
            .any(|permission| permission == "Workers Scripts Read")
        && selector(workers, "account_id", "path")
        && ["page", "per_page"]
            .iter()
            .all(|name| selector(workers, name, "query"))
        && envelope(workers);
    let account_plan_ok = account_plan.id == ACCOUNT_PLAN_ID
        && account_plan.method == "POST"
        && account_plan.path == ACCOUNT_PLAN_PATH
        && account_plan
            .request_schema
            .as_ref()
            .is_some_and(|schema| {
                schema.get("x-cfctl-body-required") == Some(&Value::Bool(true))
                    && schema.pointer("/properties/owner_worker_tag/writeOnly")
                        == Some(&Value::Bool(true))
                    && schema.pointer("/properties/catch_all_rules/items/properties/target/type")
                        .and_then(Value::as_str)
                        == Some("string")
                    && schema
                        .pointer("/properties/catch_all_rules/items/properties/rule/properties/matchers/items/properties/type/enum/0")
                        .and_then(Value::as_str)
                        == Some("all")
            })
        && selector(account_plan, "account_id", "path")
        && envelope(account_plan);
    let catch_all_get_ok = catch_all_get.id == CATCH_ALL_GET_ID
        && catch_all_get.method == "GET"
        && catch_all_get.path == CATCH_ALL_GET_PATH
        && !catch_all_get.mutating
        && catch_all_get
            .permissions
            .iter()
            .any(|permission| permission == "Email Routing Rules Read")
        && selector(catch_all_get, "zone_id", "path")
        && envelope(catch_all_get);
    let catch_all_ok = catch_all.id == CATCH_ALL_UPDATE_ID
        && catch_all.method == "PUT"
        && catch_all.path == CATCH_ALL_UPDATE_PATH
        && catch_all.mutating
        && catch_all.effect == EffectClass::ReversibleWrite
        && catch_all
            .permissions
            .iter()
            .any(|permission| permission == "Email Routing Rules Write")
        && selector(catch_all, "zone_id", "path")
        && catch_all
            .request_schema
            .as_ref()
            .is_some_and(activation_apply_schema_supported)
        && envelope(catch_all);
    if !zone_ok || !workers_ok || !account_plan_ok || !catch_all_get_ok || !catch_all_ok {
        return Err(CliError::Input(
            "reply-subdomain activation Worker inventory, account-plan, or catch-all update source contract drifted"
                .to_owned(),
        ));
    }
    Ok(())
}

fn activation_apply_schema_supported(schema: &Value) -> bool {
    let enum_contains = |pointer: &str, expected: &str| {
        schema
            .pointer(pointer)
            .and_then(Value::as_array)
            .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(expected)))
    };
    let required = schema.get("required").and_then(Value::as_array);
    schema.get("x-cfctl-body-required") == Some(&Value::Bool(true))
        && schema
            .pointer("/properties/owner_worker_tag/type")
            .and_then(Value::as_str)
            == Some("string")
        && schema.pointer("/properties/owner_worker_tag/writeOnly") == Some(&Value::Bool(true))
        && schema
            .pointer("/properties/owner_worker_tag/maxLength")
            .and_then(Value::as_u64)
            == Some(32)
        && enum_contains("/properties/source/enum", "wrangler")
        && schema
            .pointer("/properties/enabled/enum")
            .and_then(Value::as_array)
            .is_some_and(|values| values.contains(&Value::Bool(true)))
        && enum_contains("/properties/matchers/items/properties/type/enum", "all")
        && enum_contains("/properties/actions/items/properties/type/enum", "worker")
        && schema
            .pointer("/properties/actions/minItems")
            .and_then(Value::as_u64)
            == Some(1)
        && schema
            .pointer("/properties/actions/maxItems")
            .and_then(Value::as_u64)
            == Some(1)
        && schema
            .pointer("/properties/actions/items/properties/value/maxItems")
            .and_then(Value::as_u64)
            == Some(1)
        && ["actions", "matchers"].iter().all(|field| {
            required.is_some_and(|values| values.iter().any(|value| value.as_str() == Some(field)))
        })
}

fn activation_apply_body(worker_script_name: &str, worker_tag: &str) -> Value {
    json!({
        "matchers":[{"type":"all"}],
        "actions":[{"type":"worker","value":[worker_script_name]}],
        "enabled":true,
        "source":"wrangler",
        "owner_worker_tag":worker_tag,
    })
}

fn normalize_domain(value: &str) -> Option<String> {
    let normalized = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.len() > 253
        || !normalized.contains('.')
        || normalized.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        None
    } else {
        Some(normalized)
    }
}

fn valid_worker_name(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn is_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use cfctl_cloudflare::CloudflareApiErrorV1;
    use serde_json::json;

    use super::*;

    fn response(result: Value, count: usize) -> CloudflareResponseV1 {
        CloudflareResponseV1 {
            status: 200,
            success: true,
            result,
            errors: Vec::new(),
            result_info: Some(json!({
                "page":1,
                "total_pages":1,
                "total_count":count,
                "count":count,
                "cfctl_pages":1,
                "cfctl_page_complete":true,
            })),
            etag: None,
            cf_ray: None,
        }
    }

    fn target() -> Target {
        Target {
            account_id: "private-account".to_owned(),
            reply_domain: "reply.example.com".to_owned(),
            worker_script_name: "maildesk-relay-router".to_owned(),
        }
    }

    #[test]
    fn exact_subdomain_dns_and_parent_zone_catch_all_form_one_body_free_ingress_proof() {
        let target = target();
        let zone = response(
            json!([{"id":"private-zone","name":"example.com","status":"active","account":{"id":"private-account"}}]),
            1,
        );
        assert_eq!(
            project_zone(&zone, &target.account_id, "example.com").expect("zone"),
            ZoneState::Active(ParentZone {
                id: "private-zone".to_owned(),
                name: "example.com".to_owned(),
            })
        );
        let dns = CloudflareResponseV1 {
            result: json!({
                "errors":[],
                "record":CANONICAL_MX.map(|content| json!({
                    "type":"MX","name":"reply.example.com","content":content,
                })),
            }),
            result_info: None,
            ..response(Value::Null, 0)
        };
        assert_eq!(
            project_subdomain_dns(&dns, &target.reply_domain).expect("dns"),
            "ok"
        );
        let catch_all = CloudflareResponseV1 {
            result: json!({
                "id":"0123456789abcdef0123456789abcdef",
                "enabled":true,
                "source":"api",
                "name":"",
                "matchers":[{"type":"all"}],
                "actions":[{"type":"worker","value":[target.worker_script_name.clone()]}],
            }),
            result_info: None,
            ..response(Value::Null, 0)
        };
        assert!(
            project_catch_all(&catch_all, &target)
                .expect("parent-zone catch-all")
                .desired_shape
        );
        let receipt = success(&target, "ok", "ok");
        assert!(receipt_is_complete(&receipt));
        let serialized = serde_json::to_string(&receipt).expect("receipt");
        assert!(!serialized.contains("reply.example.com"));
        assert!(!serialized.contains("maildesk-relay-router"));
        assert!(!serialized.contains("private-zone"));
        assert!(!serialized.contains("private-account"));
    }

    #[test]
    fn documented_dns_response_variants_project_with_coherent_optional_metadata() {
        let target = target();
        let records = CANONICAL_MX.map(|content| {
            json!({
                "type":"MX",
                "name":"reply.example.com",
                "content":content,
            })
        });
        let collection = CloudflareResponseV1 {
            result: json!(records),
            result_info: Some(json!({
                "page":1,
                "per_page":20,
                "total_pages":1,
                "total_count":3,
                "count":3,
            })),
            ..response(Value::Null, 0)
        };
        assert_eq!(
            project_subdomain_dns(&collection, &target.reply_domain).expect("collection"),
            "ok"
        );

        let object_without_optional_errors = CloudflareResponseV1 {
            result: json!({"record":records}),
            result_info: None,
            ..response(Value::Null, 0)
        };
        assert_eq!(
            project_subdomain_dns(&object_without_optional_errors, &target.reply_domain)
                .expect("object response"),
            "ok"
        );

        let live_object_variant = CloudflareResponseV1 {
            result: json!({"errors":null,"records":records}),
            result_info: None,
            ..response(Value::Null, 0)
        };
        assert_eq!(
            project_subdomain_dns(&live_object_variant, &target.reply_domain)
                .expect("live object response"),
            "ok"
        );
    }

    #[test]
    fn dns_object_variants_reject_ambiguous_or_malformed_collection_keys() {
        let target = target();
        let records = CANONICAL_MX.map(|content| {
            json!({
                "type":"MX",
                "name":"reply.example.com",
                "content":content,
            })
        });
        for result in [
            json!({"errors":{},"records":records}),
            json!({"errors":null,"records":{}}),
            json!({"errors":null,"record":records,"records":records}),
            json!({"errors":null}),
        ] {
            let response = CloudflareResponseV1 {
                result,
                result_info: None,
                ..response(Value::Null, 0)
            };
            let failure =
                project_subdomain_dns(&response, &target.reply_domain).expect_err("malformed");
            assert_eq!(failure["status"], "dns_projection_malformed");
            assert_eq!(failure["provider_output_retained"], false);
        }
    }

    #[test]
    fn collection_dns_metadata_conflicts_and_unknown_cursors_fail_closed() {
        let target = target();
        let records = CANONICAL_MX.map(|content| {
            json!({
                "type":"MX",
                "name":"reply.example.com",
                "content":content,
            })
        });
        for result_info in [
            json!({}),
            json!({
                "page":1,
                "count":3,
            }),
            json!({
                "page":1,
                "per_page":20,
                "total_pages":2,
                "total_count":3,
                "count":3,
            }),
            json!({
                "page":1,
                "per_page":20,
                "total_pages":1,
                "total_count":4,
                "count":3,
            }),
            json!({
                "page":1,
                "per_page":20,
                "total_pages":1,
                "total_count":3,
                "count":3,
                "cursor":"private-provider-cursor",
            }),
            json!({
                "page":1,
                "per_page":20,
                "total_pages":1,
                "total_count":3,
                "count":3,
                "cfctl_pages":1,
            }),
        ] {
            let response = CloudflareResponseV1 {
                result: json!(records),
                result_info: Some(result_info),
                ..response(Value::Null, 0)
            };
            let failure =
                project_subdomain_dns(&response, &target.reply_domain).expect_err("incomplete");
            assert_eq!(failure["status"], "dns_read_incomplete");
            let serialized = serde_json::to_string(&failure).expect("body-free failure");
            assert!(!serialized.contains("provider-cursor"));
            assert_eq!(failure["provider_output_retained"], false);
        }
    }

    #[test]
    fn typed_missing_and_drift_remain_distinct_from_ambiguous_or_incomplete_reads() {
        let target = target();
        assert_eq!(
            project_zone(&response(json!([]), 0), &target.account_id, "example.com")
                .expect("missing"),
            ZoneState::Missing
        );
        let ambiguous = project_zone(
            &response(
                json!([
                    {"id":"one","name":"example.com","status":"active","account":{"id":"private-account"}},
                    {"id":"two","name":"example.com","status":"active","account":{"id":"private-account"}},
                ]),
                2,
            ),
            &target.account_id,
            "example.com",
        )
        .expect_err("ambiguous");
        assert_eq!(ambiguous["status"], "zone_cardinality_ambiguous");
        assert_eq!(ambiguous["match_count"], 2);
        assert!(!receipt_is_complete(&ambiguous));

        let mut incomplete = response(json!({"errors":[],"record":[]}), 0);
        incomplete.success = false;
        let failure =
            project_subdomain_dns(&incomplete, &target.reply_domain).expect_err("incomplete");
        assert_eq!(failure["status"], "dns_read_incomplete");
        assert_eq!(failure["provider_output_retained"], false);
    }

    #[test]
    fn noncanonical_subdomain_mx_is_drift_without_provider_retention() {
        let target = target();
        let dns = CloudflareResponseV1 {
            result: json!({"errors":[],"record":[
                {"type":"MX","name":"reply.example.com","content":"route1.mx.cloudflare.net"},
                {"type":"MX","name":"reply.example.com","content":"wrong.mx.example.net"}
            ]}),
            result_info: None,
            ..response(Value::Null, 0)
        };
        assert_eq!(
            project_subdomain_dns(&dns, &target.reply_domain).expect("dns"),
            "drift"
        );
        let receipt = success(&target, "drift", "ok");
        assert!(receipt_is_complete(&receipt));
        assert!(
            !serde_json::to_string(&receipt)
                .expect("receipt")
                .contains("wrong")
        );
    }

    #[test]
    fn provider_errors_and_malformed_rows_fail_closed_body_free() {
        let target = target();
        let mut denied = response(json!([{"private":"provider-payload"}]), 1);
        denied.success = false;
        denied.errors = vec![CloudflareApiErrorV1 {
            code: Some(9109),
            message: "private provider marker".to_owned(),
        }];
        let failure = project_zone(&denied, &target.account_id, "example.com").expect_err("denied");
        let serialized = serde_json::to_string(&failure).expect("failure");
        assert!(!serialized.contains("provider-payload"));
        assert!(!serialized.contains("provider marker"));
        assert_eq!(failure["provider_output_retained"], false);
        assert_eq!(failure["body_returned"], false);

        let mut expanded = json!({
            "adapter":cfctl_workspace::MAILDESK_REPLY_SUBDOMAIN_INGRESS_PROJECTION,
            "success":true,
            "boundary_crossed":true,
            "schema_version":1,
            "reply_domain_sha256":sha256(target.reply_domain.as_bytes()),
            "worker_target_sha256":sha256(target.worker_script_name.as_bytes()),
            "dns_scope":"exact_reply_subdomain",
            "routing_scope":"parent_zone_catch_all_to_worker_covering_exact_reply_subdomain",
            "dns":"ok",
            "routing_rule":"ok",
            "provider_output_retained":false,
            "body_returned":false,
        });
        assert!(receipt_is_complete(&expanded));
        expanded["routing_scope"] = json!("exact_reply_subdomain_catch_all_to_worker");
        assert!(!receipt_is_complete(&expanded));
        expanded["routing_scope"] =
            json!("parent_zone_catch_all_to_worker_covering_exact_reply_subdomain");
        expanded["provider_payload"] = json!({"raw":true});
        assert!(!receipt_is_complete(&expanded));
    }

    #[test]
    fn incomplete_dns_metadata_and_duplicate_mx_fail_closed() {
        let target = target();
        let records = CANONICAL_MX
            .map(|content| json!({"type":"MX","name":"reply.example.com","content":content}));
        let mut incomplete = CloudflareResponseV1 {
            result: json!({"errors":[],"record":records}),
            result_info: Some(json!({
                "page":1,
                "total_pages":2,
                "total_count":3,
                "count":3,
                "cfctl_pages":1,
                "cfctl_page_complete":false,
            })),
            ..response(Value::Null, 0)
        };
        let failure =
            project_subdomain_dns(&incomplete, &target.reply_domain).expect_err("incomplete");
        assert_eq!(failure["status"], "dns_read_incomplete");
        assert_eq!(failure["provider_output_retained"], false);

        incomplete.result_info = Some(json!({
            "page":2,
            "total_pages":2,
            "total_count":3,
            "count":3,
            "cfctl_pages":2,
            "cfctl_page_complete":true,
        }));
        let later_page =
            project_subdomain_dns(&incomplete, &target.reply_domain).expect_err("later page");
        assert_eq!(later_page["status"], "dns_read_incomplete");
        assert_eq!(later_page["provider_output_retained"], false);

        incomplete.result_info = None;
        incomplete.result = json!({"errors":[],"record":[
            {"type":"MX","name":"reply.example.com","content":"route1.mx.cloudflare.net"},
            {"type":"MX","name":"reply.example.com","content":"route1.mx.cloudflare.net"},
            {"type":"MX","name":"reply.example.com","content":"route2.mx.cloudflare.net"},
            {"type":"MX","name":"reply.example.com","content":"route3.mx.cloudflare.net"}
        ]});
        assert_eq!(
            project_subdomain_dns(&incomplete, &target.reply_domain).expect("duplicate drift"),
            "drift"
        );
    }

    #[test]
    fn subdomain_dns_permission_drift_is_rejected_by_preflight_contract() {
        let mut zone = provider_capability(
            ZONE_LIST_ID,
            ZONE_LIST_PATH,
            &["Zone Zone Read"],
            &[
                ("name", "query"),
                ("account.id", "query"),
                ("page", "query"),
                ("per_page", "query"),
            ],
        );
        let mut dns = provider_capability(
            SUBDOMAIN_DNS_ID,
            SUBDOMAIN_DNS_PATH,
            &["Zone Settings Read"],
            &[("zone_id", "path"), ("subdomain", "query")],
        );
        let mut catch_all = provider_capability(
            CATCH_ALL_GET_ID,
            CATCH_ALL_GET_PATH,
            &["Email Routing Rules Read"],
            &[("zone_id", "path")],
        );
        assert!(validate_provider_contracts(&zone, &dns, &catch_all).is_ok());
        dns.permissions.clear();
        assert!(validate_provider_contracts(&zone, &dns, &catch_all).is_err());
        zone.permissions.clear();
        dns.permissions.push("Zone Settings Read".to_owned());
        assert!(validate_provider_contracts(&zone, &dns, &catch_all).is_err());
        zone.permissions.push("Zone Zone Read".to_owned());
        catch_all.permissions.clear();
        assert!(validate_provider_contracts(&zone, &dns, &catch_all).is_err());
    }

    #[test]
    fn parent_candidates_exclude_reply_domain() {
        assert_eq!(
            parent_zone_candidates("reply.mail.example.com"),
            ["mail.example.com", "example.com"]
        );
    }

    #[test]
    fn profile_binding_admits_only_exact_account_or_explicit_emergency_global_key() {
        let generation = "11111111-1111-4111-8111-111111111111";
        let mut account_token =
            ProfileMetadata::new("account-token", ProfileKind::ApiToken, Some("account-a"));
        account_token.credential_generation_id = Some(generation.to_owned());
        assert!(profile_is_bound_for_read(
            &account_token,
            "account-a",
            None,
            generation
        ));
        assert!(!profile_is_bound_for_read(
            &account_token,
            "account-b",
            Some("account-b"),
            generation
        ));

        let mut emergency = ProfileMetadata::new("emergency-read", ProfileKind::GlobalKey, None);
        emergency.credential_generation_id = Some(generation.to_owned());
        assert!(profile_is_bound_for_read(
            &emergency,
            "explicit-account",
            Some("explicit-account"),
            generation
        ));
        assert!(!profile_is_bound_for_read(
            &emergency,
            "explicit-account",
            None,
            generation
        ));
        assert!(!profile_is_bound_for_read(
            &emergency,
            "explicit-account",
            Some("another-account"),
            generation
        ));
        emergency.emergency_only = false;
        assert!(!profile_is_bound_for_read(
            &emergency,
            "explicit-account",
            Some("explicit-account"),
            generation
        ));

        emergency.account_id = Some("explicit-account".to_owned());
        assert!(!profile_is_bound_for_read(
            &emergency,
            "explicit-account",
            Some("explicit-account"),
            generation
        ));
        emergency.emergency_only = true;
        assert!(!profile_is_bound_for_read(
            &emergency,
            "explicit-account",
            Some("explicit-account"),
            generation
        ));

        let mut unbound_token = ProfileMetadata::new("unbound-token", ProfileKind::ApiToken, None);
        unbound_token.credential_generation_id = Some(generation.to_owned());
        assert!(!profile_is_bound_for_read(
            &unbound_token,
            "explicit-account",
            Some("explicit-account"),
            generation
        ));
        assert!(!profile_is_bound_for_read(
            &account_token,
            "account-a",
            Some("account-a"),
            "22222222-2222-4222-8222-222222222222"
        ));
    }

    #[test]
    fn activation_worker_inventory_requires_one_exact_complete_script_tag() {
        let target = target();
        let workers = response(
            json!([{
                "name":target.worker_script_name,
                "id":"0123456789abcdef0123456789abcdef"
            }]),
            1,
        );
        assert_eq!(
            project_worker_tag(&workers, &target).expect("exact worker"),
            "0123456789abcdef0123456789abcdef"
        );

        let ambiguous = response(
            json!([
                {"name":target.worker_script_name,"id":"0123456789abcdef0123456789abcdef"},
                {"name":target.worker_script_name,"id":"fedcba9876543210fedcba9876543210"}
            ]),
            2,
        );
        let failure = project_worker_tag(&ambiguous, &target).expect_err("ambiguous");
        assert_eq!(failure["status"], "worker_cardinality_ambiguous");
        assert_eq!(failure["match_count"], 2);
        let serialized = serde_json::to_string(&failure).expect("body-free");
        assert!(!serialized.contains("0123456789abcdef"));
        assert!(!serialized.contains(&target.worker_script_name));
    }

    #[test]
    fn catch_all_projection_binds_state_and_proves_shape_without_retaining_provider_rule() {
        let target = target();
        let current = CloudflareResponseV1 {
            result: json!({
                "id":"0123456789abcdef0123456789abcdef",
                "enabled":false,
                "source":"api",
                "name":"",
                "matchers":[{"type":"all"}],
                "actions":[{"type":"drop"}],
            }),
            result_info: None,
            ..response(Value::Null, 0)
        };
        let projected = project_catch_all(&current, &target).expect("canonical default");
        assert!(is_sha256(&projected.state_sha256));
        assert!(!projected.desired_shape);
        assert!(!projected.source_wrangler);

        let desired = CloudflareResponseV1 {
            result: json!({
                "id":"0123456789abcdef0123456789abcdef",
                "enabled":true,
                "source":"wrangler",
                "name":"",
                "matchers":[{"type":"all"}],
                "actions":[{"type":"worker","value":[target.worker_script_name]}],
            }),
            result_info: None,
            ..response(Value::Null, 0)
        };
        let projected = project_catch_all(&desired, &target).expect("desired catch-all");
        assert!(projected.desired_shape);
        assert!(projected.source_wrangler);
        let serialized = json!({
            "state_sha256":projected.state_sha256,
            "desired_shape":projected.desired_shape,
            "source_wrangler":projected.source_wrangler,
        })
        .to_string();
        assert!(!serialized.contains("0123456789abcdef"));
        assert!(!serialized.contains(&target.worker_script_name));

        let mut ambiguous = desired;
        ambiguous.result["actions"] = json!([
            {"type":"worker","value":[target.worker_script_name.clone()]},
            {"type":"drop"}
        ]);
        let failure = project_catch_all(&ambiguous, &target).expect_err("ambiguous actions");
        assert_eq!(failure["status"], "catch_all_projection_malformed");
    }

    #[test]
    fn catalog_native_catch_all_update_uses_the_same_provider_zone_lock() {
        let root = tempfile::tempdir().expect("temporary state root");
        let store = StateStore::open(cfctl_storage::RuntimePaths::from_root(root.path()))
            .expect("state store");
        let account = "a".repeat(32);
        let zone = "b".repeat(32);
        let mut capability = CapabilityV1::new(
            CATCH_ALL_UPDATE_ID,
            "Update catch-all",
            "PUT",
            CATCH_ALL_UPDATE_PATH,
        );
        capability.mutating = true;
        let plan = PlanV1::draft("profile", &account, "catalog", capability, json!({}))
            .expect("draft direct catch-all plan");
        let input = CallInput {
            selectors: json!({"zone_id":zone}),
            ..CallInput::default()
        };
        let lock = acquire_activation_target_lock(&store, &plan, &input)
            .expect("lock resolution")
            .expect("direct catch-all lock");
        assert!(matches!(
            store.lock_email_routing_catch_all(&account, &"b".repeat(32)),
            Err(cfctl_storage::StorageError::EmailRoutingCatchAllLocked { .. })
        ));
        drop(lock);
        assert!(
            store
                .lock_email_routing_catch_all(&account, &"b".repeat(32))
                .is_ok()
        );
    }

    #[test]
    fn activation_account_plan_accepts_only_one_exact_non_destructive_catch_all() {
        let target = target();
        let parent_zone = ParentZone {
            id: "0123456789abcdef0123456789abcdef".to_owned(),
            name: "example.com".to_owned(),
        };
        let exact = CloudflareResponseV1 {
            result: json!({"zones":[{
                "zone_id":parent_zone.id,
                "zone_name":parent_zone.name,
                "changes":[{
                    "type":"added",
                    "target":format!("*@{}",target.reply_domain)
                }]
            }]}),
            result_info: None,
            ..response(Value::Null, 0)
        };
        let projected = project_activation_account_plan(&exact, &target, &parent_zone)
            .expect("exact parent-zone plan");
        assert_eq!(projected.change_type, "added");
        assert_eq!(projected.zone_id, "0123456789abcdef0123456789abcdef");
        let updated_without_optional_zone_name = CloudflareResponseV1 {
            result: json!({"zones":[{
                "zone_id":"0123456789abcdef0123456789abcdef",
                "changes":[{
                    "type":"updated",
                    "target":format!("*@{}",target.reply_domain)
                }]
            }]}),
            result_info: None,
            ..response(Value::Null, 0)
        };
        assert_eq!(
            project_activation_account_plan(
                &updated_without_optional_zone_name,
                &target,
                &parent_zone,
            )
            .expect("provider-declared non-destructive update")
            .change_type,
            "updated"
        );

        for (status, zones) in [
            ("account_plan_no_change", json!([])),
            (
                "account_plan_change_not_additive",
                json!([{
                    "zone_id":"0123456789abcdef0123456789abcdef",
                    "zone_name":parent_zone.name,
                    "changes":[{
                        "type":"conflict",
                        "target":format!("*@{}",target.reply_domain),
                        "remote":{"private":"must-not-retain"}
                    }]
                }]),
            ),
            (
                "account_plan_cardinality_ambiguous",
                json!([
                    {"zone_id":"0123456789abcdef0123456789abcdef","zone_name":parent_zone.name,"changes":[]},
                    {"zone_id":"fedcba9876543210fedcba9876543210","zone_name":parent_zone.name,"changes":[]}
                ]),
            ),
        ] {
            let provider = CloudflareResponseV1 {
                result: json!({"zones":zones}),
                result_info: None,
                ..response(Value::Null, 0)
            };
            let failure = project_activation_account_plan(&provider, &target, &parent_zone)
                .expect_err("unsafe plan must fail closed");
            assert_eq!(failure["status"], status);
            let serialized = serde_json::to_string(&failure).expect("body-free");
            assert!(!serialized.contains("must-not-retain"));
            assert!(!serialized.contains(&target.reply_domain));
        }
    }

    #[test]
    fn activation_execution_rebinds_zone_owner_plan_and_exact_apply_payload() {
        let target = target();
        let parent_zone_id = "0123456789abcdef0123456789abcdef";
        let worker_tag = "fedcba9876543210fedcba9876543210";
        let provider_request = activation_provider_request(&target, worker_tag);
        let apply_body = activation_apply_body(&target.worker_script_name, worker_tag);
        assert_eq!(apply_body["source"], "wrangler");
        assert_eq!(apply_body["owner_worker_tag"], worker_tag);
        assert!(apply_body.get("name").is_none());

        let bound_value = json!({
            "zone_id":parent_zone_id,
            "parent_zone_sha256":sha256(parent_zone_id.as_bytes()),
            "worker_tag_sha256":sha256(worker_tag.as_bytes()),
            "provider_request_sha256":hash_value(&provider_request).expect("request hash"),
            "apply_body_sha256":hash_value(&apply_body).expect("apply hash"),
            "change_type":"added",
        });
        let bound = bound_value.as_object().expect("bound target");
        let plan = ActivationPlan {
            zone_id: parent_zone_id.to_owned(),
            change_type: "added".to_owned(),
        };
        assert_eq!(
            fresh_activation_state_drift(
                bound,
                parent_zone_id,
                worker_tag,
                &provider_request,
                &apply_body,
                &plan,
            ),
            None
        );

        assert_eq!(
            fresh_activation_state_drift(
                bound,
                parent_zone_id,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                &provider_request,
                &apply_body,
                &plan,
            ),
            Some("fresh_worker_identity_drifted")
        );
        let changed_plan = ActivationPlan {
            zone_id: parent_zone_id.to_owned(),
            change_type: "updated".to_owned(),
        };
        assert_eq!(
            fresh_activation_state_drift(
                bound,
                parent_zone_id,
                worker_tag,
                &provider_request,
                &apply_body,
                &changed_plan,
            ),
            Some("fresh_account_plan_drifted")
        );
        let wrong_zone_plan = ActivationPlan {
            zone_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            change_type: "added".to_owned(),
        };
        assert_eq!(
            fresh_activation_state_drift(
                bound,
                parent_zone_id,
                worker_tag,
                &provider_request,
                &apply_body,
                &wrong_zone_plan,
            ),
            Some("fresh_parent_zone_drifted")
        );

        let failure_receipt = json!({
            "adapter":ACTIVATION_APPLY_PROJECTION,
            "success":false,
            "boundary_crossed":false,
            "schema_version":1,
            "cfctl_operation_id":"00000000-0000-4000-8000-000000000000",
            "reply_domain_sha256":sha256(target.reply_domain.as_bytes()),
            "worker_target_sha256":sha256(target.worker_script_name.as_bytes()),
            "status":"fresh_account_plan_drifted",
            "provider_status":Value::Null,
            "failure_code":"CFCTL_WORKSPACE_REPLY_SUBDOMAIN_FRESH_PRECONDITION_FAILED",
            "provider_output_retained":false,
            "body_returned":false,
        });
        assert!(is_unperformed_fresh_precondition_failure(&failure_receipt));
        let mut promoted = failure_receipt.clone();
        promoted["boundary_crossed"] = Value::Bool(true);
        assert!(!is_unperformed_fresh_precondition_failure(&promoted));
    }

    #[test]
    fn activation_apply_schema_must_preserve_owner_source_and_exact_rule_shape() {
        let schema = json!({
            "type":"object",
            "x-cfctl-body-required":true,
            "required":["actions","matchers"],
            "properties":{
                "actions":{
                    "minItems":1,
                    "maxItems":1,
                    "items":{"properties":{
                        "type":{"enum":["drop","forward","worker"]},
                        "value":{"maxItems":1}
                    }}
                },
                "matchers":{"items":{"properties":{"type":{"enum":["all"]}}}},
                "enabled":{"enum":[true,false]},
                "source":{"enum":["api","wrangler"]},
                "owner_worker_tag":{"type":"string","maxLength":32,"writeOnly":true}
            }
        });
        assert!(activation_apply_schema_supported(&schema));
        for pointer in [
            "/properties/owner_worker_tag",
            "/properties/source",
            "/properties/enabled",
            "/properties/actions/items/properties/type",
            "/properties/matchers/items/properties/type",
        ] {
            let mut drifted = schema.clone();
            *drifted.pointer_mut(pointer).expect("schema pointer") = Value::Null;
            assert!(
                !activation_apply_schema_supported(&drifted),
                "drifted schema pointer {pointer} must fail closed"
            );
        }
    }

    fn provider_capability(
        id: &str,
        path: &str,
        permissions: &[&str],
        selectors: &[(&str, &str)],
    ) -> CapabilityV1 {
        let mut capability = CapabilityV1::new(id, id, "GET", path);
        capability.adapter_status = AdapterStatus::DynamicApi;
        capability.permissions = permissions
            .iter()
            .map(|permission| (*permission).to_owned())
            .collect();
        capability.selectors = selectors
            .iter()
            .map(|(name, location)| cfctl_core::SelectorV1 {
                name: (*name).to_owned(),
                location: (*location).to_owned(),
                required: true,
                value_type: "string".to_owned(),
                description: None,
                contract: None,
            })
            .collect();
        capability.response_contract = Some(cfctl_core::ResponseContractV1 {
            success_statuses: vec!["200".to_owned()],
            success_media_types: vec!["application/json".to_owned()],
            body_mode: ResponseBodyModeV1::CloudflareJsonEnvelope,
        });
        capability
    }
}
