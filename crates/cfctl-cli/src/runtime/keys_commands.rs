use super::call_command::call_command;
use super::credential_resolution::ensure_catalog;
use super::credential_resolution::platform_secrets;
use super::plan_commands::load_validated_plan;
use super::plan_commands::recover_standing_lineage;
use super::plan_commands::run_plan_under_standing_authority;
use super::plan_create::create_plan;
use super::plan_prepare::TokenPolicyBinding;
use super::plan_prepare::build_mint_policy_body;
use super::plan_prepare::resolve_mint_token_bindings;
use super::plan_prepare::resolve_mint_token_scope;
use super::plan_prepare::token_permission_inventory_contract;
use super::plan_prepare::validate_standing_authority_group_scopes;
use super::plan_prepare::validate_zone_id;
use super::prelude::{
    BTreeMap, CallArgs, CallInput, ChronoDuration, CliError, CloudflareResponseV1, DateTime,
    ErrorV1, EvidenceClass, EvidenceV1, KeyMutationArgs, KeyPermissionArgs, KeyPolicyApproveArgs,
    KeyPolicyCommand, KeyPolicyCreateArgs, KeyPolicySelector, KeyRenewAnalyticsProfileArgs,
    KeyRevokeArgs, KeyRotateArgs, KeysCommand, ManagedApiTokenV1, Map, PlanStatus, ProfileKind,
    ProfileMetadata, ProfilesConfig, Result, ResultEnvelopeV2, SecretStore, StandingAuthorityV1,
    StateStore, Utc, Uuid, Value, VerificationState, json,
};
use super::prelude::{Datelike, PermissionsExt, fs};
use super::support::capability_missing;
use super::support::cli_io;
use super::support::read_private_secret_file;
use cfctl_core::hash_value;

pub(super) async fn keys_command(
    store: &StateStore,
    command: KeysCommand,
) -> Result<ResultEnvelopeV2> {
    match command {
        KeysCommand::Permissions(arguments) => Box::pin(key_permissions(store, &arguments)).await,
        KeysCommand::Mint(arguments) => {
            preflight_standing_authority(store, arguments.under_policy.as_deref())?;
            let plan = Box::pin(key_mint(store, &arguments)).await?;
            Box::pin(finish_standing_run(
                store,
                plan,
                arguments.under_policy.as_deref(),
            ))
            .await
        }
        KeysCommand::Rotate(arguments) => Box::pin(key_rotate(store, &arguments)).await,
        KeysCommand::RenewAnalyticsProfile(arguments) => {
            Box::pin(key_renew_analytics_profile(store, &arguments)).await
        }
        KeysCommand::Revoke(arguments) => {
            preflight_standing_authority(store, arguments.under_policy.as_deref())?;
            let plan = Box::pin(key_revoke(store, &arguments)).await?;
            Box::pin(finish_standing_run(
                store,
                plan,
                arguments.under_policy.as_deref(),
            ))
            .await
        }
        KeysCommand::Policy(arguments) => Box::pin(key_policy(store, arguments.command)).await,
    }
}

/// Fails a standing run closed before any live read or plan creation when
/// the named authority is missing, unapproved, revoked, or expired.
pub(super) fn preflight_standing_authority(
    store: &StateStore,
    under_policy: Option<&str>,
) -> Result<()> {
    if let Some(authority_id) = under_policy {
        recover_standing_lineage(store, authority_id)?;
        store.load_authority(authority_id)?.ensure_operational()?;
    }
    Ok(())
}

/// When `--under-policy` names a standing authority, the freshly created plan
/// is immediately validated against the authority's bounds and executed in
/// the same invocation; otherwise the plan envelope is returned for the
/// ordinary per-operation approval ceremony.
pub(super) async fn finish_standing_run(
    store: &StateStore,
    plan_envelope: ResultEnvelopeV2,
    under_policy: Option<&str>,
) -> Result<ResultEnvelopeV2> {
    let Some(authority_id) = under_policy else {
        return Ok(plan_envelope);
    };
    let Some(operation_id) = plan_envelope.operation_id.clone() else {
        return Err(CliError::Input(
            "a standing run requires the plan envelope to carry an operation id".to_owned(),
        ));
    };
    Box::pin(run_plan_under_standing_authority(
        store,
        &operation_id,
        authority_id,
    ))
    .await
}

pub(super) async fn key_policy(
    store: &StateStore,
    command: KeyPolicyCommand,
) -> Result<ResultEnvelopeV2> {
    match command {
        KeyPolicyCommand::Create(arguments) => Box::pin(key_policy_create(store, &arguments)).await,
        KeyPolicyCommand::List => key_policy_list(store),
        KeyPolicyCommand::Approve(arguments) => key_policy_approve(store, &arguments),
        KeyPolicyCommand::Revoke(selector) => key_policy_revoke(store, &selector),
    }
}

pub(super) async fn key_policy_create(
    store: &StateStore,
    arguments: &KeyPolicyCreateArgs,
) -> Result<ResultEnvelopeV2> {
    if arguments.permissions.is_empty() {
        return Err(CliError::Input(
            "a standing authority requires at least one allowlisted permission group; use `cfctl keys permissions --account <id>`"
                .to_owned(),
        ));
    }
    if arguments.name_prefix.trim().is_empty() {
        return Err(CliError::Input(
            "a standing authority requires a non-empty `--name-prefix` lineage bound".to_owned(),
        ));
    }
    if arguments.max_child_ttl_hours == 0 || arguments.max_runs_per_day == 0 {
        return Err(CliError::Input(
            "`--max-child-ttl-hours` and `--max-runs-per-day` must both be at least 1".to_owned(),
        ));
    }
    let inventory = Box::pin(key_permissions(
        store,
        &KeyPermissionArgs {
            profile: arguments.profile.clone(),
            account: arguments.account.clone(),
            user: false,
        },
    ))
    .await?;
    if !inventory.ok
        || !inventory.performed
        || inventory.account_id.as_deref() != Some(arguments.account.as_str())
    {
        return Err(CliError::Input(
            "fresh account-bound permission inventory did not produce a live-read receipt"
                .to_owned(),
        ));
    }
    let selected_groups = validate_selected_permission_groups(
        &arguments.permissions,
        inventory.result.get("result").unwrap_or(&Value::Null),
    )?;
    let zone_id = arguments
        .zone
        .as_deref()
        .map(str::trim)
        .filter(|zone| !zone.is_empty());
    if let Some(zone_id) = zone_id {
        validate_zone_id(zone_id)?;
    }
    validate_standing_authority_group_scopes(&selected_groups, zone_id)?;
    let selected_group_ids = selected_groups
        .iter()
        .filter_map(|group| group.get("id").and_then(Value::as_str))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let selected_groups_hash = hash_value(&serde_json::to_value(&selected_groups)?)?;
    let expires_at = Utc::now() + ChronoDuration::days(i64::from(arguments.expires_days));
    let authority = StandingAuthorityV1::draft(
        &arguments.account,
        zone_id,
        vec![
            "account-api-tokens-create-token".to_owned(),
            "account-api-tokens-delete-token".to_owned(),
        ],
        selected_group_ids,
        &selected_groups_hash,
        arguments.max_child_ttl_hours,
        &arguments.name_prefix,
        arguments.max_runs_per_day,
        expires_at,
    )?;
    store.create_authority(&authority)?;
    let mut envelope = ResultEnvelopeV2::success(
        "keys policy create",
        json!({
            "authority_id": authority.authority_id,
            "status": authority.status.as_str(),
            "account_id": authority.account_id,
            "zone_id": authority.zone_id,
            "bound_resources": authority.allowed_token_resources(),
            "capability_ids": authority.capability_ids,
            "name_prefix": authority.name_prefix,
            "max_child_ttl_hours": authority.max_child_ttl_hours,
            "max_runs_per_day": authority.max_runs_per_day,
            "expires_at": authority.expires_at,
            "resolved_permission_groups": selected_groups,
            "permission_inventory_hash": authority.permission_inventory_hash,
            "approval_command": format!(
                "cfctl keys policy approve {} --yes",
                authority.authority_id
            ),
            "message": "Standing authority drafted from a fresh live permission inventory. Review the resolved groups and bounds, then approve the exact authority ID."
        }),
    );
    envelope.account_id = Some(arguments.account.clone());
    envelope.evidence = inventory.evidence;
    Ok(envelope)
}

pub(super) fn key_policy_list(store: &StateStore) -> Result<ResultEnvelopeV2> {
    let now = Utc::now();
    let authorities: Vec<Value> = store
        .list_authorities()?
        .iter()
        .map(|authority| {
            let effective_status = authority.effective_status(now);
            let runs_last_24h = authority.runs_in_last_day(now);
            let runs_remaining_24h = usize::try_from(authority.max_runs_per_day)
                .unwrap_or(usize::MAX)
                .saturating_sub(runs_last_24h);
            let next_action = match effective_status {
                "pending_approval" => format!(
                    "Review the bounds, then run `cfctl keys policy approve {} --yes`.",
                    authority.authority_id
                ),
                "active" if runs_remaining_24h == 0 => format!(
                    "The rolling run budget is exhausted; wait for budget to age out or revoke with `cfctl keys policy revoke {}`.",
                    authority.authority_id
                ),
                "active" => format!(
                    "Use `--under-policy {}` only for a matching mint or lineage-bound revoke; list again to inspect the resulting budget and lineage.",
                    authority.authority_id
                ),
                "expired" => {
                    "This authority is effectively expired; create and explicitly approve a new policy if recurring work must continue."
                        .to_owned()
                }
                "revoked" => {
                    "This authority is revoked and cannot admit new runs; individually revoke any surviving child tokens when needed."
                        .to_owned()
                }
                _ => "Inspect the authority document before taking another action.".to_owned(),
            };
            json!({
                "authority_id": authority.authority_id,
                "status": effective_status,
                "account_id": authority.account_id,
                "zone_id": authority.zone_id,
                "bound_resources": authority.allowed_token_resources(),
                "capability_ids": authority.capability_ids,
                "name_prefix": authority.name_prefix,
                "permission_group_count": authority.permission_group_ids.len(),
                "max_child_ttl_hours": authority.max_child_ttl_hours,
                "max_runs_per_day": authority.max_runs_per_day,
                "runs_last_24h": runs_last_24h,
                "runs_remaining_24h": runs_remaining_24h,
                "minted_tokens": authority.minted_token_ids.len(),
                "minted_token_ids": authority.minted_token_ids,
                "created_at": authority.created_at,
                "expires_at": authority.expires_at,
                "next_action": next_action,
            })
        })
        .collect();
    Ok(ResultEnvelopeV2::success(
        "keys policy list",
        json!({"authorities": authorities}),
    ))
}

pub(super) fn key_policy_approve(
    store: &StateStore,
    arguments: &KeyPolicyApproveArgs,
) -> Result<ResultEnvelopeV2> {
    let guard = store.lock_authority(&arguments.authority_id)?;
    let mut authority = store.load_authority(&arguments.authority_id)?;
    authority.approve(arguments.yes)?;
    store.save_authority_guarded(&authority, &guard)?;
    Ok(ResultEnvelopeV2::success(
        "keys policy approve",
        json!({
            "authority_id": authority.authority_id,
            "status": authority.status.as_str(),
            "approved_content_hash": authority.approval.as_ref().map(|approval| approval.approved_content_hash.clone()),
            "expires_at": authority.expires_at,
            "message": "Standing authority is active. Unattended runs under it are bounded, rate-limited, attributable, and revocable with `cfctl keys policy revoke`."
        }),
    ))
}

pub(super) fn key_policy_revoke(
    store: &StateStore,
    selector: &KeyPolicySelector,
) -> Result<ResultEnvelopeV2> {
    let guard = store.lock_authority(&selector.authority_id)?;
    let mut authority = store.load_authority(&selector.authority_id)?;
    authority.revoke();
    store.save_authority_guarded(&authority, &guard)?;
    Ok(ResultEnvelopeV2::success(
        "keys policy revoke",
        json!({
            "authority_id": authority.authority_id,
            "status": authority.status.as_str(),
            "message": "Standing authority revoked. Runs not yet durably admitted fail closed; an already-admitted boundary attempt may finish, and later lineage reconciliation cannot reactivate the grant. Already-minted child tokens are unaffected and can be revoked individually."
        }),
    ))
}

pub(super) async fn key_permissions(
    store: &StateStore,
    arguments: &KeyPermissionArgs,
) -> Result<ResultEnvelopeV2> {
    let envelope = Box::pin(call_command(store, permission_inventory_call(arguments))).await?;
    Ok(permission_inventory_envelope(envelope))
}

pub(super) fn permission_inventory_call(arguments: &KeyPermissionArgs) -> CallArgs {
    let capability_id = if arguments.user {
        "permission-groups-list-permission-groups"
    } else {
        "account-api-tokens-list-permission-groups"
    };
    let mut selectors = Vec::new();
    if !arguments.user {
        selectors.push(("account_id".to_owned(), arguments.account.clone()));
    }
    CallArgs {
        capability_id: capability_id.to_owned(),
        selectors,
        query: Vec::new(),
        body_json: None,
        body_stdin: false,
        profile: arguments.profile.clone(),
        account: Some(arguments.account.clone()),
        if_match: None,
        if_none_match: None,
        value_out: None,
        credential_in: None,
        out: None,
        source_file: None,
    }
}

pub(super) fn permission_inventory_envelope(mut envelope: ResultEnvelopeV2) -> ResultEnvelopeV2 {
    "keys permissions".clone_into(&mut envelope.command);
    let forbidden = serde_json::from_value::<CloudflareResponseV1>(envelope.result.clone())
        .is_ok_and(|response| {
            !response.success
                && (response.status == 403
                    || response.errors.iter().any(|error| error.code == Some(9109)))
        });
    if forbidden {
        envelope.ok = false;
        envelope.verification.state = VerificationState::Failed;
        envelope.error = Some(ErrorV1 {
            code: "CFCTL_PERMISSION_INVENTORY_FORBIDDEN".to_owned(),
            message: "Cloudflare denied the permission-group inventory. The selected API token requires the `Account API Tokens Read` or `Account API Tokens Write` grant for the explicit account."
                .to_owned(),
            next_step: Some(
                "Grant the selected token Account API Tokens Read or Write, then retry the same account-bound inventory command."
                    .to_owned(),
            ),
        });
    }
    envelope
}

pub(super) async fn key_mint(
    store: &StateStore,
    arguments: &KeyMutationArgs,
) -> Result<ResultEnvelopeV2> {
    let account = arguments.account.as_deref().ok_or_else(|| {
        CliError::Input("token minting requires `--account` for explicit resource scope".to_owned())
    })?;
    let value_out = arguments.value_out.as_ref().ok_or_else(|| {
        CliError::Input("token minting requires the sink-only `--value-out <path>`".to_owned())
    })?;
    if arguments.permissions.is_empty() {
        return Err(CliError::Input(if arguments.user {
            "at least one permission group ID or exact name is required; use `cfctl keys permissions --user --account <id>`"
                    .to_owned()
        } else {
            "at least one permission group ID or exact name is required; use `cfctl keys permissions --account <id>`"
                    .to_owned()
        }));
    }
    // Resolve the requested scope before any network I/O. This is pure
    // argument validation, and running it after the inventory read reported a
    // contradiction like `--user --zone` as an inventory failure — naming the
    // wrong problem, after spending a live call to find it. The same resolution
    // runs again inside the binding partition below; it is idempotent.
    resolve_mint_token_scope(arguments, account)?;
    let inventory = Box::pin(key_permissions(
        store,
        &KeyPermissionArgs {
            profile: arguments.profile.clone(),
            account: account.to_owned(),
            user: arguments.user,
        },
    ))
    .await?;
    if !inventory.ok || !inventory.performed || inventory.account_id.as_deref() != Some(account) {
        return Err(CliError::Input(
            "fresh owner-specific permission inventory did not produce an account-bound live-read receipt"
                .to_owned(),
        ));
    }
    let selected_groups = validate_selected_permission_groups(
        &arguments.permissions,
        inventory.result.get("result").unwrap_or(&Value::Null),
    )?;
    let permission_bindings = resolve_mint_token_bindings(arguments, account, &selected_groups)?;
    let selected_groups_hash = hash_value(&serde_json::to_value(&selected_groups)?)?;
    let inventory_evidence_hashes = inventory
        .evidence
        .iter()
        .map(|evidence| evidence.content_hash.clone())
        .collect::<Vec<_>>();
    let body = build_mint_policy_body(&arguments.name, &permission_bindings, arguments.ttl_hours);
    let catalog = ensure_catalog(store).await?;
    let capability_id = if arguments.user {
        "user-api-tokens-create-token"
    } else {
        "account-api-tokens-create-token"
    };
    let inventory_contract = token_permission_inventory_contract(capability_id)
        .ok_or_else(|| capability_missing(capability_id))?;
    let capability = catalog
        .get(capability_id)
        .cloned()
        .ok_or_else(|| capability_missing(capability_id))?;
    let mut plan = Box::pin(create_plan(
        store,
        &catalog,
        capability,
        CallInput {
            selectors: if arguments.user {
                json!({})
            } else {
                json!({"account_id": account})
            },
            query: json!({}),
            body: Some(body),
            ..CallInput::default()
        },
        arguments.profile.as_deref(),
        Some(account),
        json!({
            "value_out": value_out,
            "permission_inventory": {
                "source_capability_id": inventory_contract.capability_id,
                "selected_groups": selected_groups,
                "selected_groups_hash": selected_groups_hash,
                "permission_bindings": permission_bindings.iter().map(TokenPolicyBinding::as_json).collect::<Vec<_>>(),
                "evidence_hashes": inventory_evidence_hashes,
            }
        }),
    ))
    .await?;
    plan.evidence.splice(0..0, inventory.evidence);
    Ok(plan)
}

pub(super) fn validate_selected_permission_groups(
    requested_selectors: &[String],
    inventory: &Value,
) -> Result<Vec<Value>> {
    if requested_selectors.is_empty() {
        return Err(CliError::Input(
            "at least one permission group ID or exact name must be selected".to_owned(),
        ));
    }
    let groups = inventory.as_array().ok_or_else(|| {
        CliError::Input("live permission inventory result is not an array".to_owned())
    })?;
    let mut requested_selectors = requested_selectors.to_vec();
    requested_selectors.sort();
    requested_selectors.dedup();
    let mut resolved = BTreeMap::<String, &Value>::new();
    for requested_selector in requested_selectors {
        let matches = groups
            .iter()
            .filter(|group| {
                group.get("id").and_then(Value::as_str) == Some(&requested_selector)
                    || group.get("name").and_then(Value::as_str) == Some(&requested_selector)
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(CliError::Input(format!(
                "permission group selector `{requested_selector}` is not unique in the fresh account inventory (matched {})",
                matches.len()
            )));
        }
        let group = matches[0];
        let resolved_id = group
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.trim().is_empty())
            .ok_or_else(|| {
                CliError::Input(format!(
                    "permission group `{requested_selector}` has no auditable ID in the fresh account inventory"
                ))
            })?;
        let id_matches = groups
            .iter()
            .filter(|candidate| candidate.get("id").and_then(Value::as_str) == Some(resolved_id))
            .count();
        if id_matches != 1 {
            return Err(CliError::Input(format!(
                "permission group `{resolved_id}` is not unique in the fresh account inventory (matched {id_matches})"
            )));
        }
        resolved.insert(resolved_id.to_owned(), group);
    }
    let mut selected = Vec::with_capacity(resolved.len());
    for (resolved_id, group) in resolved {
        let name = group
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.trim().is_empty())
            .ok_or_else(|| {
                CliError::Input(format!(
                    "permission group `{resolved_id}` has no auditable name in the fresh account inventory"
                ))
            })?;
        let mut scopes = group
            .get("scopes")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                CliError::Input(format!(
                    "permission group `{resolved_id}` has no auditable scope list in the fresh account inventory"
                ))
            })?
            .iter()
            .map(|scope| {
                scope.as_str().map(str::to_owned).ok_or_else(|| {
                    CliError::Input(format!(
                        "permission group `{resolved_id}` contains a non-string scope"
                    ))
                })
            })
            .collect::<Result<Vec<_>>>()?;
        scopes.sort();
        scopes.dedup();
        if scopes.is_empty() {
            return Err(CliError::Input(format!(
                "permission group `{resolved_id}` has an empty scope list"
            )));
        }
        let mut normalized = Map::from_iter([
            ("id".to_owned(), Value::String(resolved_id)),
            ("name".to_owned(), Value::String(name.to_owned())),
            ("scopes".to_owned(), serde_json::to_value(scopes)?),
        ]);
        if let Some(category) = group.get("category").and_then(Value::as_str) {
            normalized.insert("category".to_owned(), Value::String(category.to_owned()));
        }
        selected.push(Value::Object(normalized));
    }
    Ok(selected)
}

pub(super) async fn key_rotate(
    store: &StateStore,
    arguments: &KeyRotateArgs,
) -> Result<ResultEnvelopeV2> {
    let catalog = ensure_catalog(store).await?;
    let capability_id = if arguments.user {
        "user-api-tokens-roll-token"
    } else {
        "account-api-tokens-roll-token"
    };
    let capability = catalog
        .get(capability_id)
        .cloned()
        .ok_or_else(|| capability_missing(capability_id))?;
    Box::pin(create_plan(
        store,
        &catalog,
        capability,
        CallInput {
            selectors: if arguments.user {
                json!({"token_id": arguments.id})
            } else {
                json!({"account_id": arguments.account, "token_id": arguments.id})
            },
            query: json!({}),
            body: Some(json!({})),
            ..CallInput::default()
        },
        None,
        Some(&arguments.account),
        json!({"value_out": arguments.value_out}),
    ))
    .await
}

pub(super) async fn analytics_rotation_reads(
    store: &StateStore,
    profile: &str,
    account: &str,
    zone: &str,
    hostname: &str,
) -> Result<Vec<ResultEnvelopeV2>> {
    let today = Utc::now().date_naive();
    let month_start = today.with_day(1).ok_or_else(|| {
        CliError::Input("could not derive the current UTC month boundary".to_owned())
    })?;
    let limit = i64::from(today.day());
    let calls = [
        CallArgs {
            capability_id: "graphql-analytics-account-rum-dataset-settings".to_owned(),
            selectors: vec![("account_id".to_owned(), account.to_owned())],
            query: Vec::new(),
            body_json: Some("{}".to_owned()),
            body_stdin: false,
            profile: Some(profile.to_owned()),
            account: Some(account.to_owned()),
            if_match: None,
            if_none_match: None,
            value_out: None,
            credential_in: None,
            out: None,
            source_file: None,
        },
        CallArgs {
            capability_id: "graphql-analytics-zone-dataset-settings".to_owned(),
            selectors: vec![("zone_id".to_owned(), zone.to_owned())],
            query: Vec::new(),
            body_json: Some("{}".to_owned()),
            body_stdin: false,
            profile: Some(profile.to_owned()),
            account: Some(account.to_owned()),
            if_match: None,
            if_none_match: None,
            value_out: None,
            credential_in: None,
            out: None,
            source_file: None,
        },
        CallArgs {
            capability_id: "graphql-analytics-account-rum-pageload-visits".to_owned(),
            selectors: vec![("account_id".to_owned(), account.to_owned())],
            query: Vec::new(),
            body_json: Some(
                json!({
                    "dataset":"rumPageloadEventsAdaptiveGroups",
                    "hostname":hostname,
                    "start":month_start.format("%Y-%m-%d").to_string(),
                    "end":today.format("%Y-%m-%d").to_string(),
                    "limit":limit,
                })
                .to_string(),
            ),
            body_stdin: false,
            profile: Some(profile.to_owned()),
            account: Some(account.to_owned()),
            if_match: None,
            if_none_match: None,
            value_out: None,
            credential_in: None,
            out: None,
            source_file: None,
        },
    ];
    let mut envelopes = Vec::with_capacity(calls.len());
    for call in calls {
        let envelope = Box::pin(call_command(store, call)).await?;
        let succeeded = envelope.ok && envelope.performed;
        envelopes.push(envelope);
        if !succeeded {
            break;
        }
    }
    Ok(envelopes)
}

pub(super) fn analytics_reads_passed(envelopes: &[ResultEnvelopeV2]) -> bool {
    envelopes.len() == 3
        && envelopes
            .iter()
            .all(|envelope| envelope.ok && envelope.performed)
}

pub(super) fn remove_staged_rotation_profile(
    store: &StateStore,
    secrets: &dyn SecretStore,
    staging_profile_id: &str,
    slot_id: &str,
) -> Result<()> {
    let mut profiles = ProfilesConfig::load(store)?;
    profiles.profiles.remove(staging_profile_id);
    profiles.save(store)?;
    secrets.delete_api_token_slot(slot_id)?;
    Ok(())
}

pub(super) async fn revoke_rotation_child(
    store: &StateStore,
    minter_profile: &str,
    account: &str,
    token_id: &str,
    authority_id: &str,
) -> Result<ResultEnvelopeV2> {
    preflight_standing_authority(store, Some(authority_id))?;
    let plan = Box::pin(key_revoke(
        store,
        &KeyRevokeArgs {
            profile: Some(minter_profile.to_owned()),
            user: false,
            id: token_id.to_owned(),
            account: Some(account.to_owned()),
            under_policy: Some(authority_id.to_owned()),
        },
    ))
    .await?;
    Box::pin(finish_standing_run(store, plan, Some(authority_id))).await
}

pub(super) fn rotation_failure(
    code: &str,
    message: impl Into<String>,
    next_step: impl Into<String>,
    evidence: Vec<EvidenceV1>,
    result: Value,
) -> ResultEnvelopeV2 {
    let mut envelope = ResultEnvelopeV2::success("keys renew-analytics-profile", result);
    envelope.ok = false;
    envelope.performed = true;
    envelope.verification.state = VerificationState::Failed;
    envelope.error = Some(ErrorV1 {
        code: code.to_owned(),
        message: message.into(),
        next_step: Some(next_step.into()),
    });
    envelope.evidence = evidence;
    envelope
}

#[expect(
    clippy::too_many_lines,
    reason = "the governed rotation keeps mint, staged reads, atomic activation, post-activation reads, rollback, and lineage-bound revocation in one fail-closed owner"
)]
pub(super) async fn key_renew_analytics_profile(
    store: &StateStore,
    arguments: &KeyRenewAnalyticsProfileArgs,
) -> Result<ResultEnvelopeV2> {
    validate_zone_id(&arguments.zone)?;
    if arguments.permissions.is_empty() {
        return Err(CliError::Input(
            "analytics profile renewal requires explicit permission groups".to_owned(),
        ));
    }
    if arguments.ttl_hours == 0 || arguments.renew_before_hours >= arguments.ttl_hours {
        return Err(CliError::Input(
            "`--ttl-hours` must be positive and greater than `--renew-before-hours`".to_owned(),
        ));
    }
    if arguments.profile == arguments.minter_profile {
        return Err(CliError::Input(
            "the publisher and minter profiles must be distinct".to_owned(),
        ));
    }
    let authority = store.load_authority(&arguments.under_policy)?;
    authority.ensure_operational()?;
    if authority.account_id != arguments.account
        || authority.zone_id.as_deref() != Some(arguments.zone.as_str())
    {
        return Err(CliError::Input(
            "standing authority account or zone does not match the requested publisher rotation"
                .to_owned(),
        ));
    }
    let profiles = ProfilesConfig::load(store)?;
    let mut old_profile = profiles
        .profiles
        .get(&arguments.profile)
        .cloned()
        .ok_or_else(|| {
            CliError::Input(format!(
                "publisher profile `{}` does not exist",
                arguments.profile
            ))
        })?;
    if old_profile.kind != ProfileKind::ApiToken
        || old_profile.account_id.as_deref() != Some(arguments.account.as_str())
    {
        return Err(CliError::Input(
            "publisher profile must be an API token pinned to the requested account".to_owned(),
        ));
    }
    let minter = profiles
        .profiles
        .get(&arguments.minter_profile)
        .ok_or_else(|| {
            CliError::Input(format!(
                "minter profile `{}` does not exist",
                arguments.minter_profile
            ))
        })?;
    if minter.kind != ProfileKind::ApiToken
        || minter.account_id.as_deref() != Some(arguments.account.as_str())
    {
        return Err(CliError::Input(
            "minter profile must be an API token pinned to the requested account".to_owned(),
        ));
    }
    if let Some(pending_token_id) = old_profile.managed_api_token.as_ref().and_then(|managed| {
        (managed.pending_revoke_operation_id.is_none())
            .then(|| managed.pending_revoke_token_id.clone())
            .flatten()
    }) {
        let revoke_plan = match Box::pin(key_revoke(
            store,
            &KeyRevokeArgs {
                profile: Some(arguments.minter_profile.clone()),
                user: false,
                id: pending_token_id.clone(),
                account: Some(arguments.account.clone()),
                under_policy: None,
            },
        ))
        .await
        {
            Ok(plan) => plan,
            Err(error) => {
                let mut pending = rotation_failure(
                    "CFCTL_ANALYTICS_ROTATION_REVOKE_PLAN_FAILED",
                    format!(
                        "the active child remains healthy, but governed old-child revoke-plan creation is still failing: {error}"
                    ),
                    "Repair the explicit minter-profile planning failure; later hourly runs keep retrying only plan creation and refuse another mint.",
                    Vec::new(),
                    json!({
                        "profile":arguments.profile,
                        "state":"active_old_revoke_plan_pending",
                        "active_token_id":old_profile
                            .managed_api_token
                            .as_ref()
                            .map(|managed| managed.token_id.as_str()),
                        "old_token_id":pending_token_id,
                        "observable_failure_signal":"nonzero process exit with CFCTL_ANALYTICS_ROTATION_REVOKE_PLAN_FAILED",
                    }),
                );
                pending.profile_id = Some(arguments.profile.clone());
                pending.account_id = Some(arguments.account.clone());
                return Ok(pending);
            }
        };
        let revoke_operation_id = revoke_plan.operation_id.clone().ok_or_else(|| {
            CliError::Input("bootstrap revoke plan omitted its operation ID".to_owned())
        })?;
        let mut repaired_profile = old_profile.clone();
        let repaired_managed = repaired_profile
            .managed_api_token
            .as_mut()
            .ok_or_else(|| CliError::Input("managed profile binding disappeared".to_owned()))?;
        repaired_managed.pending_revoke_operation_id = Some(revoke_operation_id);
        let mut repaired_profiles = profiles.clone();
        repaired_profiles
            .profiles
            .insert(arguments.profile.clone(), repaired_profile.clone());
        repaired_profiles.save(store)?;
        old_profile = repaired_profile;
    }
    if let Some(managed) = old_profile.managed_api_token.as_ref()
        && let (Some(pending_token_id), Some(pending_operation_id)) = (
            managed.pending_revoke_token_id.as_deref(),
            managed.pending_revoke_operation_id.as_deref(),
        )
    {
        let pending_plan = load_validated_plan(store, pending_operation_id)?;
        let pending_matches = pending_plan.capability.id == "account-api-tokens-delete-token"
            && pending_plan.account_id == arguments.account
            && pending_plan
                .input
                .pointer("/selectors/token_id")
                .and_then(Value::as_str)
                == Some(pending_token_id);
        if !pending_matches || pending_plan.status != PlanStatus::Verified {
            let mut pending = rotation_failure(
                "CFCTL_ANALYTICS_ROTATION_OLD_REVOKE_PENDING",
                "a prior analytics rotation still has an unverified old-child revocation",
                format!(
                    "Approve and run operation `{pending_operation_id}`; the hourly renewal check stays failed until its exact not-found verification is durable."
                ),
                Vec::new(),
                json!({
                    "profile":arguments.profile,
                    "state":"active_old_revoke_pending",
                    "active_token_id":managed.token_id,
                    "old_token_id":pending_token_id,
                    "revoke_operation_id":pending_operation_id,
                    "observable_failure_signal":"nonzero process exit with CFCTL_ANALYTICS_ROTATION_OLD_REVOKE_PENDING",
                }),
            );
            pending.operation_id = Some(pending_operation_id.to_owned());
            pending.profile_id = Some(arguments.profile.clone());
            pending.account_id = Some(arguments.account.clone());
            return Ok(pending);
        }
        let retired_slot = managed.pending_revoke_slot_id.clone();
        let mut reconciled_profile = old_profile.clone();
        let reconciled_managed = reconciled_profile
            .managed_api_token
            .as_mut()
            .ok_or_else(|| CliError::Input("managed profile binding disappeared".to_owned()))?;
        reconciled_managed.pending_revoke_token_id = None;
        reconciled_managed.pending_revoke_operation_id = None;
        reconciled_managed.pending_revoke_slot_id = None;
        let mut reconciled_profiles = profiles.clone();
        reconciled_profiles
            .profiles
            .insert(arguments.profile.clone(), reconciled_profile.clone());
        reconciled_profiles.save(store)?;
        let secrets = platform_secrets(store);
        if let Some(slot_id) = retired_slot.as_deref() {
            secrets.delete_api_token_slot(slot_id)?;
        } else {
            secrets.delete_api_token(&arguments.profile)?;
        }
        old_profile = reconciled_profile;
    }
    let old_token_id = match (
        old_profile.managed_api_token.as_ref(),
        arguments.current_token_id.as_deref(),
    ) {
        (Some(managed), Some(provided)) if managed.token_id != provided => {
            return Err(CliError::Input(
                "`--current-token-id` conflicts with the profile's managed child identity"
                    .to_owned(),
            ));
        }
        (Some(managed), _) => managed.token_id.clone(),
        (None, Some(provided)) if !provided.trim().is_empty() => provided.to_owned(),
        (None, _) => {
            return Err(CliError::Input(
                "the first managed renewal requires `--current-token-id`; later runs use the profile's durable managed-child identity"
                    .to_owned(),
            ));
        }
    };
    if !arguments.force
        && let Some(managed) = old_profile.managed_api_token.as_ref()
    {
        let renew_at =
            managed.expires_at - ChronoDuration::hours(i64::from(arguments.renew_before_hours));
        if Utc::now() < renew_at {
            let active_reads = Box::pin(analytics_rotation_reads(
                store,
                &arguments.profile,
                &arguments.account,
                &arguments.zone,
                &arguments.hostname,
            ))
            .await?;
            if !analytics_reads_passed(&active_reads) {
                return Ok(rotation_failure(
                    "CFCTL_ANALYTICS_PROFILE_READ_FAILED",
                    "the active managed analytics profile failed its settings or hostname-bound RUM read",
                    "Inspect the redacted live-read receipts and restore credential-store access before the next scheduled attempt.",
                    active_reads
                        .into_iter()
                        .flat_map(|envelope| envelope.evidence)
                        .collect(),
                    json!({
                        "profile":arguments.profile,
                        "state":"active_read_failed",
                    }),
                ));
            }
            let secrets = platform_secrets(store);
            secrets.delete_api_token(&arguments.profile)?;
            let mut envelope = ResultEnvelopeV2::success(
                "keys renew-analytics-profile",
                json!({
                    "profile":arguments.profile,
                    "state":"healthy_not_due",
                    "active_token_id":managed.token_id,
                    "expires_at":managed.expires_at,
                    "renew_at":renew_at,
                    "legacy_profile_credential_cleanup":"completed_idempotently",
                    "observable_failure_signal":"nonzero process exit with ResultEnvelopeV2 error",
                    "message":"Managed analytics child is outside its renewal window and passed account settings, zone settings, and exact-hostname RUM reads."
                }),
            );
            envelope.profile_id = Some(arguments.profile.clone());
            envelope.account_id = Some(arguments.account.clone());
            envelope.evidence = active_reads
                .into_iter()
                .flat_map(|read| read.evidence)
                .collect();
            return Ok(envelope);
        }
    }

    preflight_standing_authority(store, Some(&arguments.under_policy))?;
    let rotation_id = Uuid::new_v4();
    let child_name = format!(
        "{}{}-{}",
        arguments.name_prefix,
        Utc::now().format("%Y%m%d%H%M%S"),
        &rotation_id.simple().to_string()[..8]
    );
    if !child_name.starts_with(&authority.name_prefix) {
        return Err(CliError::Input(
            "generated child name is outside the standing authority prefix".to_owned(),
        ));
    }
    let staging_root = store.paths().data_dir.join("credential-rotation-staging");
    fs::create_dir_all(&staging_root).map_err(|source| cli_io(&staging_root, source))?;
    #[cfg(unix)]
    fs::set_permissions(&staging_root, fs::Permissions::from_mode(0o700))
        .map_err(|source| cli_io(&staging_root, source))?;
    let sink_path = staging_root.join(format!("{rotation_id}.token"));
    let mint_plan = Box::pin(key_mint(
        store,
        &KeyMutationArgs {
            profile: Some(arguments.minter_profile.clone()),
            user: false,
            name: child_name,
            permissions: arguments.permissions.clone(),
            account: Some(arguments.account.clone()),
            zone: Some(arguments.zone.clone()),
            ttl_hours: Some(arguments.ttl_hours),
            value_out: Some(sink_path.clone()),
            under_policy: Some(arguments.under_policy.clone()),
        },
    ))
    .await?;
    let mint = Box::pin(finish_standing_run(
        store,
        mint_plan,
        Some(&arguments.under_policy),
    ))
    .await?;
    if !mint.ok || !mint.performed {
        return Ok(rotation_failure(
            "CFCTL_ANALYTICS_ROTATION_MINT_FAILED",
            "the standing-authority mint did not complete",
            "Inspect the mint operation receipt; do not retry if the boundary may have been crossed without lineage reconciliation.",
            mint.evidence,
            json!({"profile":arguments.profile,"state":"mint_failed"}),
        ));
    }
    let new_token_id = mint
        .result
        .pointer("/result/id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::Input(
                "successful child mint omitted its non-secret token identity; do not replay"
                    .to_owned(),
            )
        })?
        .to_owned();
    let token = read_private_secret_file(&sink_path, "internal rotation sink")?;
    fs::remove_file(&sink_path).map_err(|source| cli_io(&sink_path, source))?;
    let expires_at = mint
        .result
        .pointer("/result/expires_on")
        .and_then(Value::as_str)
        .and_then(|raw| DateTime::parse_from_rfc3339(raw).ok())
        .map_or_else(
            || Utc::now() + ChronoDuration::hours(i64::from(arguments.ttl_hours)),
            |value| value.with_timezone(&Utc),
        );

    let secrets = platform_secrets(store);
    let slot_id = Uuid::new_v4().to_string();
    secrets.store_api_token_slot(&slot_id, token.trim())?;
    let staging_profile_id = format!("__cfctl_rotation_{rotation_id}");
    let mut staging_profile = ProfileMetadata::new(
        &staging_profile_id,
        ProfileKind::ApiToken,
        Some(&arguments.account),
    );
    staging_profile.api_token_slot_id = Some(slot_id.clone());
    let mut staged_profiles = ProfilesConfig::load(store)?;
    staged_profiles
        .profiles
        .insert(staging_profile_id.clone(), staging_profile.clone());
    if let Err(error) = staged_profiles.save(store) {
        let _ = secrets.delete_api_token_slot(&slot_id);
        return Err(error);
    }

    let staged_reads = Box::pin(analytics_rotation_reads(
        store,
        &staging_profile_id,
        &arguments.account,
        &arguments.zone,
        &arguments.hostname,
    ))
    .await?;
    if !analytics_reads_passed(&staged_reads) {
        let mut evidence = mint.evidence;
        evidence.extend(
            staged_reads
                .into_iter()
                .flat_map(|envelope| envelope.evidence),
        );
        let cleanup = Box::pin(revoke_rotation_child(
            store,
            &arguments.minter_profile,
            &arguments.account,
            &new_token_id,
            &arguments.under_policy,
        ))
        .await?;
        evidence.extend(cleanup.evidence);
        remove_staged_rotation_profile(store, &secrets, &staging_profile_id, &slot_id)?;
        return Ok(rotation_failure(
            "CFCTL_ANALYTICS_ROTATION_STAGED_READ_FAILED",
            "the fresh child failed its staged settings or hostname-bound RUM read",
            "The prior publisher profile remains active. Inspect the redacted live-read and cleanup receipts before the next scheduled attempt.",
            evidence,
            json!({
                "profile":arguments.profile,
                "state":"staged_read_failed",
                "new_child_revoked":cleanup.ok,
            }),
        ));
    }

    let mut activation_profiles = ProfilesConfig::load(store)?;
    let current = activation_profiles
        .profiles
        .get(&arguments.profile)
        .ok_or_else(|| {
            CliError::Input("publisher profile disappeared during rotation".to_owned())
        })?;
    if current.credential_generation_id != old_profile.credential_generation_id
        || current.api_token_slot_id != old_profile.api_token_slot_id
    {
        let _ = revoke_rotation_child(
            store,
            &arguments.minter_profile,
            &arguments.account,
            &new_token_id,
            &arguments.under_policy,
        )
        .await;
        remove_staged_rotation_profile(store, &secrets, &staging_profile_id, &slot_id)?;
        return Err(CliError::Input(
            "publisher credential generation changed during rotation; the fresh child was not activated"
                .to_owned(),
        ));
    }
    let mut activated_profile = old_profile.clone();
    activated_profile.credential_generation_id = staging_profile.credential_generation_id.clone();
    activated_profile.api_token_slot_id = Some(slot_id.clone());
    activated_profile.managed_api_token = Some(ManagedApiTokenV1 {
        schema_version: 1,
        token_id: new_token_id.clone(),
        expires_at,
        standing_authority_id: arguments.under_policy.clone(),
        pending_revoke_token_id: None,
        pending_revoke_operation_id: None,
        pending_revoke_slot_id: None,
    });
    activation_profiles.profiles.remove(&staging_profile_id);
    activation_profiles
        .profiles
        .insert(arguments.profile.clone(), activated_profile.clone());
    activation_profiles.save(store)?;
    let activation_evidence = store.write_evidence(
        EvidenceClass::PostChangeVerification,
        &json!({
            "profile":arguments.profile,
            "account_id":arguments.account,
            "zone_id":arguments.zone,
            "old_credential_generation_id":old_profile.credential_generation_id,
            "new_credential_generation_id":activated_profile.credential_generation_id,
            "new_token_id":new_token_id,
            "expires_at":expires_at,
            "activation":"atomic_profile_metadata_switch",
            "secret_material_recorded":false,
        }),
    )?;

    let active_reads = Box::pin(analytics_rotation_reads(
        store,
        &arguments.profile,
        &arguments.account,
        &arguments.zone,
        &arguments.hostname,
    ))
    .await?;
    if !analytics_reads_passed(&active_reads) {
        let mut rollback_profiles = ProfilesConfig::load(store)?;
        rollback_profiles
            .profiles
            .insert(arguments.profile.clone(), old_profile.clone());
        rollback_profiles.save(store)?;
        let cleanup = Box::pin(revoke_rotation_child(
            store,
            &arguments.minter_profile,
            &arguments.account,
            &new_token_id,
            &arguments.under_policy,
        ))
        .await?;
        secrets.delete_api_token_slot(&slot_id)?;
        let mut evidence = mint.evidence;
        evidence.push(activation_evidence);
        evidence.extend(
            active_reads
                .into_iter()
                .flat_map(|envelope| envelope.evidence),
        );
        evidence.extend(cleanup.evidence);
        return Ok(rotation_failure(
            "CFCTL_ANALYTICS_ROTATION_ACTIVE_READ_FAILED",
            "the atomically activated profile failed its live read and was rolled back",
            "The prior profile generation is active again. Inspect the redacted read, rollback, and fresh-child revocation receipts.",
            evidence,
            json!({
                "profile":arguments.profile,
                "state":"rolled_back",
                "new_child_revoked":cleanup.ok,
            }),
        ));
    }

    let refreshed_authority = store.load_authority(&arguments.under_policy)?;
    let old_is_lineage_bound = refreshed_authority
        .minted_token_ids
        .iter()
        .any(|token_id| token_id == &old_token_id);
    let mut evidence = mint.evidence;
    evidence.push(activation_evidence);
    evidence.extend(
        staged_reads
            .into_iter()
            .chain(active_reads)
            .flat_map(|envelope| envelope.evidence),
    );
    if !old_is_lineage_bound {
        let revoke_plan = match Box::pin(key_revoke(
            store,
            &KeyRevokeArgs {
                profile: Some(arguments.minter_profile.clone()),
                user: false,
                id: old_token_id.clone(),
                account: Some(arguments.account.clone()),
                under_policy: None,
            },
        ))
        .await
        {
            Ok(plan) => plan,
            Err(error) => {
                let mut pending_profiles = ProfilesConfig::load(store)?;
                let pending_profile = pending_profiles
                    .profiles
                    .get_mut(&arguments.profile)
                    .ok_or_else(|| {
                        CliError::Input("activated publisher profile disappeared".to_owned())
                    })?;
                let managed = pending_profile.managed_api_token.as_mut().ok_or_else(|| {
                    CliError::Input(
                        "activated publisher profile lost its managed binding".to_owned(),
                    )
                })?;
                managed.pending_revoke_token_id = Some(old_token_id.clone());
                managed.pending_revoke_operation_id = None;
                managed
                    .pending_revoke_slot_id
                    .clone_from(&old_profile.api_token_slot_id);
                pending_profiles.save(store)?;
                return Ok(rotation_failure(
                    "CFCTL_ANALYTICS_ROTATION_REVOKE_PLAN_FAILED",
                    format!(
                        "the fresh child is active and verified, but the old-child revoke plan could not be prepared: {error}"
                    ),
                    "The overlap is durably pending. A later hourly run retries only governed revoke-plan creation before permitting another mint.",
                    evidence,
                    json!({
                        "profile":arguments.profile,
                        "state":"active_old_revoke_plan_pending",
                        "active_token_id":new_token_id,
                        "old_token_id":old_token_id,
                        "observable_failure_signal":"nonzero process exit with CFCTL_ANALYTICS_ROTATION_REVOKE_PLAN_FAILED",
                    }),
                ));
            }
        };
        evidence.extend(revoke_plan.evidence.clone());
        let revoke_operation_id = revoke_plan.operation_id.clone().ok_or_else(|| {
            CliError::Input("bootstrap revoke plan omitted its operation ID".to_owned())
        })?;
        let mut pending_profiles = ProfilesConfig::load(store)?;
        let pending_profile = pending_profiles
            .profiles
            .get_mut(&arguments.profile)
            .ok_or_else(|| CliError::Input("activated publisher profile disappeared".to_owned()))?;
        let managed = pending_profile.managed_api_token.as_mut().ok_or_else(|| {
            CliError::Input("activated publisher profile lost its managed binding".to_owned())
        })?;
        managed.pending_revoke_token_id = Some(old_token_id.clone());
        managed.pending_revoke_operation_id = Some(revoke_operation_id.clone());
        managed
            .pending_revoke_slot_id
            .clone_from(&old_profile.api_token_slot_id);
        pending_profiles.save(store)?;
        let mut pending = rotation_failure(
            "CFCTL_ANALYTICS_ROTATION_BOOTSTRAP_REVOKE_APPROVAL_REQUIRED",
            "the fresh child is active and verified, but the pre-existing child is outside standing-authority lineage",
            format!(
                "Approve and run operation `{}` once. Future renewals revoke their lineage-bound prior child automatically.",
                revoke_plan.operation_id.as_deref().unwrap_or("missing")
            ),
            evidence,
            json!({
                "profile":arguments.profile,
                "state":"active_old_revoke_pending",
                "active_token_id":new_token_id,
                "expires_at":expires_at,
                "old_token_id":old_token_id,
                "revoke_operation_id":revoke_operation_id.clone(),
                "observable_failure_signal":"nonzero process exit with CFCTL_ANALYTICS_ROTATION_BOOTSTRAP_REVOKE_APPROVAL_REQUIRED",
            }),
        );
        pending.operation_id = Some(revoke_operation_id);
        pending.profile_id = Some(arguments.profile.clone());
        pending.account_id = Some(arguments.account.clone());
        return Ok(pending);
    }

    let revoke = Box::pin(revoke_rotation_child(
        store,
        &arguments.minter_profile,
        &arguments.account,
        &old_token_id,
        &arguments.under_policy,
    ))
    .await?;
    evidence.extend(revoke.evidence);
    if !revoke.ok || revoke.verification.state != VerificationState::Passed {
        let revoke_operation_id = revoke.operation_id.clone().ok_or_else(|| {
            CliError::Input(
                "failed old-child revocation omitted its operation ID; the active profile remains cut over but requires manual overlap reconciliation"
                    .to_owned(),
            )
        })?;
        let mut pending_profiles = ProfilesConfig::load(store)?;
        let pending_profile = pending_profiles
            .profiles
            .get_mut(&arguments.profile)
            .ok_or_else(|| CliError::Input("activated publisher profile disappeared".to_owned()))?;
        let managed = pending_profile.managed_api_token.as_mut().ok_or_else(|| {
            CliError::Input("activated publisher profile lost its managed binding".to_owned())
        })?;
        managed.pending_revoke_token_id = Some(old_token_id.clone());
        managed.pending_revoke_operation_id = Some(revoke_operation_id.clone());
        managed
            .pending_revoke_slot_id
            .clone_from(&old_profile.api_token_slot_id);
        pending_profiles.save(store)?;
        return Ok(rotation_failure(
            "CFCTL_ANALYTICS_ROTATION_OLD_REVOKE_FAILED",
            "the fresh child is active and verified, but old-child revocation was not proven",
            format!(
                "Reconcile operation `{revoke_operation_id}` to Verified. Every later hourly check stays failed and refuses another mint until this overlap is closed."
            ),
            evidence,
            json!({
                "profile":arguments.profile,
                "state":"active_old_revoke_failed",
                "active_token_id":new_token_id,
                "old_token_id":old_token_id,
                "revoke_operation_id":revoke_operation_id,
                "observable_failure_signal":"nonzero process exit with CFCTL_ANALYTICS_ROTATION_OLD_REVOKE_PENDING",
            }),
        ));
    }
    if let Some(old_slot_id) = old_profile.api_token_slot_id.as_deref() {
        secrets.delete_api_token_slot(old_slot_id)?;
    } else {
        secrets.delete_api_token(&arguments.profile)?;
    }
    let mut envelope = ResultEnvelopeV2::success(
        "keys renew-analytics-profile",
        json!({
            "profile":arguments.profile,
            "state":"rotated",
            "active_token_id":new_token_id,
            "revoked_token_id":old_token_id,
            "expires_at":expires_at,
            "renew_at":expires_at - ChronoDuration::hours(i64::from(arguments.renew_before_hours)),
            "verification_capabilities":[
                "graphql-analytics-account-rum-dataset-settings",
                "graphql-analytics-zone-dataset-settings",
                "graphql-analytics-account-rum-pageload-visits",
            ],
            "observable_failure_signal":"nonzero process exit with ResultEnvelopeV2 error",
            "message":"Fresh analytics child was staged, verified, atomically activated, re-verified through the publisher profile, and the lineage-bound prior child was revoked."
        }),
    );
    envelope.performed = true;
    envelope.profile_id = Some(arguments.profile.clone());
    envelope.account_id = Some(arguments.account.clone());
    envelope.verification.state = VerificationState::Passed;
    envelope.verification.basis = Some(
        "staged and active account RUM settings, zone settings, and exact-host RUM reads passed before lineage-bound old-child revocation"
            .to_owned(),
    );
    envelope.evidence = evidence;
    Ok(envelope)
}

pub(super) async fn key_revoke(
    store: &StateStore,
    arguments: &KeyRevokeArgs,
) -> Result<ResultEnvelopeV2> {
    let account = arguments.account.as_deref().ok_or_else(|| {
        CliError::Input("token revocation requires `--account` for explicit ownership".to_owned())
    })?;
    let catalog = ensure_catalog(store).await?;
    let capability_id = if arguments.user {
        "user-api-tokens-delete-token"
    } else {
        "account-api-tokens-delete-token"
    };
    let capability = catalog
        .get(capability_id)
        .cloned()
        .ok_or_else(|| capability_missing(capability_id))?;
    Box::pin(create_plan(
        store,
        &catalog,
        capability,
        CallInput {
            selectors: if arguments.user {
                json!({"token_id": arguments.id})
            } else {
                json!({"account_id": account, "token_id": arguments.id})
            },
            query: json!({}),
            body: None,
            ..CallInput::default()
        },
        arguments.profile.as_deref(),
        Some(account),
        Value::Null,
    ))
    .await
}
