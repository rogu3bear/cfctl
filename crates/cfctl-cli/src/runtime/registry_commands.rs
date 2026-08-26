use super::prelude::fs;
use super::prelude::{
    AdapterStatus, BTreeSet, CapabilityV1, CatalogSnapshot, CliError, DesiredResourceV1,
    InventoryProviderV1, OperationIndexRecordV1, OwnershipRecordV1, Path, ProfilesConfig, Registry,
    RegistryCommand, RegistryDeclarationsCommand, RegistryOwnershipCommand, RegistryScopeArgs,
    RegistryScopeKindArg, RegistryScopesCommand, ResourceRefV1, Result, ResultEnvelopeV2,
    ScopeKindV1, ScopeRefV1, StateStore, Value, json,
};
use super::support::cli_io;
use super::workspace_state::discover_registered;
use crate::telemetry_product::OPERATIONAL_PROOF_PROJECTION_LIMIT;

#[expect(
    clippy::too_many_lines,
    reason = "the public registry subcommand dispatcher keeps every read-only projection and local declaration action explicit"
)]
pub(super) fn registry_command(
    store: &StateStore,
    command: RegistryCommand,
) -> Result<ResultEnvelopeV2> {
    let mut registry = Registry::open(&store.paths().data_dir)?;
    match command {
        RegistryCommand::Scopes(arguments) => match arguments.command {
            RegistryScopesCommand::List => Ok(ResultEnvelopeV2::success(
                "registry scopes list",
                json!({"scopes": registry.list_scopes()?}),
            )),
            RegistryScopesCommand::Discover => {
                let profiles = ProfilesConfig::load(store)?;
                let scopes = profiles
                    .profiles
                    .values()
                    .filter_map(|profile| profile.account_id.as_deref())
                    .map(|account| ScopeRefV1::new(ScopeKindV1::Account, account, None))
                    .collect::<BTreeSet<_>>();
                Ok(ResultEnvelopeV2::success(
                    "registry scopes discover",
                    json!({
                        "scopes": scopes,
                        "source": "configured credential profile metadata",
                        "adopted": false,
                        "next_action": "Review each scope, then use `cfctl registry scopes adopt --kind account --id <account-id>` or run `cfctl registry sync` to adopt configured account scopes."
                    }),
                ))
            }
            RegistryScopesCommand::Adopt(arguments) => {
                let scope = registry_scope(&arguments);
                registry.adopt_scope(&scope)?;
                Ok(ResultEnvelopeV2::success(
                    "registry scopes adopt",
                    json!({"scope": scope, "message": "Scope adopted for local registry synchronization; no Cloudflare boundary was crossed."}),
                ))
            }
            RegistryScopesCommand::Remove(arguments) => {
                let scope = registry_scope(&arguments);
                let removed = registry.remove_scope(&scope)?;
                Ok(ResultEnvelopeV2::success(
                    "registry scopes remove",
                    json!({"scope": scope, "removed": removed, "message": "Scope retired from future registry synchronization; immutable evidence remains authoritative."}),
                ))
            }
        },
        RegistryCommand::Sync => registry_sync(store, &mut registry),
        RegistryCommand::Status => Ok(ResultEnvelopeV2::success(
            "registry status",
            serde_json::to_value(registry.status()?)?,
        )),
        RegistryCommand::Coverage => Ok(ResultEnvelopeV2::success(
            "registry coverage",
            serde_json::to_value(registry.coverage()?)?,
        )),
        RegistryCommand::List(arguments) => Ok(ResultEnvelopeV2::success(
            "registry list",
            json!({"resources": registry.list_resources(arguments.kind.as_deref())?}),
        )),
        RegistryCommand::Get(arguments) => {
            let resource = registry.get_resource(&arguments.resource)?;
            let desired = registry
                .list_desired_resources()?
                .into_iter()
                .find(|candidate| candidate.resource.key() == arguments.resource);
            let ownership = registry
                .list_ownership()?
                .into_iter()
                .find(|candidate| candidate.resource.key() == arguments.resource);
            let observation = registry
                .observation_history(&arguments.resource)?
                .into_iter()
                .next();
            Ok(ResultEnvelopeV2::success(
                "registry get",
                json!({
                    "resource": resource,
                    "latest_observation": observation,
                    "desired": desired,
                    "ownership": ownership,
                    "found": resource.is_some(),
                }),
            ))
        }
        RegistryCommand::Graph => Ok(ResultEnvelopeV2::success(
            "registry graph",
            json!({
                "scopes": registry.list_scopes()?,
                "resources": registry.list_resources(None)?,
                "ownership": registry.list_ownership()?,
                "truth_boundary": "Scope and relationship rows are a rebuildable projection; desired declarations, live-read evidence, and Cloudflare state retain separate authority."
            }),
        )),
        RegistryCommand::Diff(arguments) => registry_diff_envelope(
            &registry,
            "registry diff",
            arguments.resource.as_deref(),
            false,
        ),
        RegistryCommand::History(arguments) => Ok(ResultEnvelopeV2::success(
            "registry history",
            json!({
                "resource": arguments.resource,
                "observations": registry.observation_history(&arguments.resource)?,
            }),
        )),
        RegistryCommand::Export => Ok(ResultEnvelopeV2::success(
            "registry export",
            serde_json::to_value(registry.export()?)?,
        )),
        RegistryCommand::Rebuild => {
            let backup = registry.rebuild_projection()?;
            let sync = registry_sync_result(store, &mut registry)?;
            Ok(ResultEnvelopeV2::success(
                "registry rebuild",
                json!({
                    "backup": backup,
                    "sync": sync,
                    "message": "The rebuildable projection was backed up, cleared, reconstructed from configured sources, and integrity-checked."
                }),
            ))
        }
        RegistryCommand::Declarations(arguments) => match arguments.command {
            RegistryDeclarationsCommand::Validate => {
                let declarations = load_registry_declarations(store)?;
                Ok(ResultEnvelopeV2::success(
                    "registry declarations validate",
                    json!({
                        "valid": true,
                        "declaration_count": declarations.len(),
                        "declarations": declarations,
                    }),
                ))
            }
            RegistryDeclarationsCommand::Diff(arguments) => registry_diff_envelope(
                &registry,
                "registry declarations diff",
                arguments.resource.as_deref(),
                false,
            ),
            RegistryDeclarationsCommand::Plan(arguments) => registry_diff_envelope(
                &registry,
                "registry declarations plan",
                arguments.resource.as_deref(),
                true,
            ),
        },
        RegistryCommand::Ownership(arguments) => match arguments.command {
            RegistryOwnershipCommand::List => Ok(ResultEnvelopeV2::success(
                "registry ownership list",
                json!({"ownership": registry.list_ownership()?}),
            )),
            RegistryOwnershipCommand::Get(arguments) => {
                let ownership = registry
                    .list_ownership()?
                    .into_iter()
                    .find(|candidate| candidate.resource.key() == arguments.resource);
                Ok(ResultEnvelopeV2::success(
                    "registry ownership get",
                    json!({"resource": arguments.resource, "ownership": ownership, "found": ownership.is_some()}),
                ))
            }
            RegistryOwnershipCommand::Check => {
                let desired = registry.list_desired_resources()?;
                let ownership = registry.list_ownership()?;
                let missing = desired
                    .iter()
                    .filter(|item| {
                        !ownership
                            .iter()
                            .any(|owner| owner.resource.key() == item.resource.key())
                    })
                    .map(|item| item.resource.key())
                    .collect::<Vec<_>>();
                Ok(ResultEnvelopeV2::success(
                    "registry ownership check",
                    json!({
                        "valid": missing.is_empty(),
                        "missing_ownership": missing,
                        "duplicate_owners": [],
                        "note": "The SQLite uniqueness constraint rejects duplicate resource owners at import time."
                    }),
                ))
            }
        },
    }
}

pub(super) fn registry_scope(arguments: &RegistryScopeArgs) -> ScopeRefV1 {
    let parent = arguments
        .parent_kind
        .zip(arguments.parent_id.as_deref())
        .map(|(kind, id)| ScopeRefV1::new(registry_scope_kind(kind), id, None));
    ScopeRefV1::new(
        registry_scope_kind(arguments.kind),
        arguments.id.clone(),
        parent,
    )
}

pub(super) const fn registry_scope_kind(kind: RegistryScopeKindArg) -> ScopeKindV1 {
    match kind {
        RegistryScopeKindArg::Organization => ScopeKindV1::Organization,
        RegistryScopeKindArg::Account => ScopeKindV1::Account,
        RegistryScopeKindArg::Zone => ScopeKindV1::Zone,
        RegistryScopeKindArg::Resource => ScopeKindV1::Resource,
    }
}

pub(super) fn registry_sync(
    store: &StateStore,
    registry: &mut Registry,
) -> Result<ResultEnvelopeV2> {
    Ok(ResultEnvelopeV2::success(
        "registry sync",
        registry_sync_result(store, registry)?,
    ))
}

#[expect(
    clippy::too_many_lines,
    reason = "registry rebuild, provider coverage, source-config separation, and historical evidence indexing form one deterministic sync projection"
)]
pub(super) fn registry_sync_result(store: &StateStore, registry: &mut Registry) -> Result<Value> {
    let profiles = ProfilesConfig::load(store)?;
    let mut adopted_accounts = BTreeSet::new();
    for account in profiles
        .profiles
        .values()
        .filter_map(|profile| profile.account_id.as_deref())
    {
        registry.adopt_scope(&ScopeRefV1::new(ScopeKindV1::Account, account, None))?;
        adopted_accounts.insert(account.to_owned());
    }

    let mut operation_count = 0_usize;
    let mut catalog_hash = None;
    if store.paths().catalog_file().is_file() {
        let catalog = CatalogSnapshot::load(&store.paths().catalog_file())?;
        catalog_hash = Some(catalog.schema_hash.clone());
        for capability in catalog.capabilities.values() {
            let gaps = capability.mutation_contract_gaps();
            let blocker = capability
                .blocked_reason
                .clone()
                .or_else(|| (!gaps.is_empty()).then(|| gaps.join("; ")));
            registry.upsert_operation(&OperationIndexRecordV1 {
                schema_version: 1,
                capability_id: capability.id.clone(),
                product: capability.product.clone(),
                method: capability.method.clone(),
                path: capability.path.clone(),
                adapter_status: adapter_status_label(capability.adapter_status).to_owned(),
                maturity: operation_maturity(capability, &gaps).to_owned(),
                blocker,
                catalog_hash: catalog.schema_hash.clone(),
            })?;
            operation_count += 1;
        }
    }

    let declarations = load_registry_declarations(store)?;
    for desired in &declarations {
        registry.upsert_desired_resource(desired)?;
        let repository = Path::new(&desired.source_path)
            .parent()
            .unwrap_or_else(|| Path::new(&desired.source_path))
            .display()
            .to_string();
        registry.upsert_ownership(&OwnershipRecordV1 {
            schema_version: 1,
            resource: desired.resource.clone(),
            owner: desired.owner.clone(),
            repository,
            deploy_lane: desired.deploy_lane.clone(),
            verifier: desired.verifier.clone(),
            allowed_change_path: desired.allowed_change_path.clone(),
        })?;
    }

    let account_pins = store.workspace_manifest()?.account_pins();
    let graph = discover_registered(store)?;
    let mut source_resources = 0_usize;
    let mut unscoped_source_resources = Vec::new();
    let mut source_kinds = BTreeSet::new();
    for resource in &graph.resources {
        let accounts = graph
            .links
            .get(&resource.key)
            .into_iter()
            .flatten()
            .filter_map(|repository| {
                let repository = Path::new(repository);
                account_pins
                    .iter()
                    .filter(|(root, _)| repository.starts_with(root))
                    .max_by_key(|(root, _)| root.components().count())
                    .map(|(_, account)| account.clone())
            })
            .collect::<BTreeSet<_>>();
        if accounts.len() != 1 {
            unscoped_source_resources.push(resource.key.clone());
            continue;
        }
        let account = accounts.into_iter().next().ok_or_else(|| {
            CliError::Input("account scope selection unexpectedly became empty".to_owned())
        })?;
        let id = resource
            .key
            .split_once(':')
            .map_or_else(|| resource.key.clone(), |(_, id)| id.to_owned());
        registry.upsert_resource(
            &ResourceRefV1::new(
                ScopeRefV1::new(ScopeKindV1::Account, account, None),
                resource.kind.clone(),
                id,
            ),
            "source_config",
        )?;
        source_kinds.insert(resource.kind.clone());
        source_resources += 1;
    }
    for kind in source_kinds {
        registry.upsert_provider(&InventoryProviderV1 {
            schema_version: 1,
            resource_kind: kind.clone(),
            scope_kind: "account_or_zone".to_owned(),
            list_capability_id: String::new(),
            detail_capability_id: None,
            pagination: "unbound".to_owned(),
            normalization_rule: format!(
                "source-config kind `{kind}` requires an explicit live response identity mapping"
            ),
            freshness_seconds: 0,
            permissions: Vec::new(),
            status: "blocked".to_owned(),
            blocker: Some(format!(
                "{kind} source configuration is indexed, but no live normalization provider is bound"
            )),
        })?;
    }
    let proof_page = store.list_recent_operational_proofs(OPERATIONAL_PROOF_PROJECTION_LIMIT)?;
    for proof in &proof_page.proofs {
        registry.record_unindexable_evidence(
            &proof.evidence.content_hash,
            "operational proof receipt has no normalized resource-state payload",
        )?;
    }
    registry.mark_sync_complete()?;
    Ok(json!({
        "catalog_hash": catalog_hash,
        "operation_count": operation_count,
        "adopted_accounts": adopted_accounts,
        "desired_resource_count": declarations.len(),
        "source_config_resource_count": source_resources,
        "unscoped_source_resources": unscoped_source_resources,
        "unindexable_evidence": registry.unindexable_evidence()?,
        "unindexable_evidence_projection_truncated": proof_page.truncated,
        "coverage": registry.coverage()?,
        "truth_boundary": "This sync indexes catalog and local source/desired state. Only successful, evidence-backed inventory-provider reads may create live observations; events and source config never do so."
    }))
}

pub(super) fn operation_maturity(capability: &CapabilityV1, gaps: &[String]) -> &'static str {
    if capability.adapter_status == AdapterStatus::Blocked {
        "indexed"
    } else if !capability.mutating {
        "observable"
    } else if gaps.is_empty() {
        "verifiable"
    } else {
        "typed"
    }
}

pub(super) const fn adapter_status_label(status: AdapterStatus) -> &'static str {
    match status {
        AdapterStatus::Native => "native",
        AdapterStatus::DynamicApi => "dynamic_api",
        AdapterStatus::DelegatedCli => "delegated_cli",
        AdapterStatus::GovernedUi => "governed_ui",
        AdapterStatus::Blocked => "blocked",
    }
}

pub(super) fn load_registry_declarations(store: &StateStore) -> Result<Vec<DesiredResourceV1>> {
    let directory = store.paths().config_dir.join("registry/declarations");
    if !directory.is_dir() {
        return Ok(Vec::new());
    }
    let mut paths = fs::read_dir(&directory)
        .map_err(|source| cli_io(&directory, source))?
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|source| cli_io(&directory, source))
        })
        .collect::<Result<Vec<_>>>()?;
    paths.retain(|path| {
        path.extension()
            .is_some_and(|extension| extension == "json")
    });
    paths.sort();
    let mut declarations = Vec::new();
    for path in paths {
        let value: Value = store.read_json(&path)?;
        if value.is_array() {
            declarations.extend(serde_json::from_value::<Vec<DesiredResourceV1>>(value)?);
        } else {
            declarations.push(serde_json::from_value::<DesiredResourceV1>(value)?);
        }
    }
    if let Some(invalid) = declarations
        .iter()
        .find(|declaration| declaration.schema_version != 1)
    {
        return Err(CliError::Input(format!(
            "desired resource `{}` uses unsupported schema version {}",
            invalid.resource.key(),
            invalid.schema_version
        )));
    }
    Ok(declarations)
}

pub(super) fn registry_diff_envelope(
    registry: &Registry,
    command: &'static str,
    selected_resource: Option<&str>,
    planning: bool,
) -> Result<ResultEnvelopeV2> {
    let diffs = registry
        .list_desired_resources()?
        .into_iter()
        .filter(|desired| {
            selected_resource.is_none_or(|selected| desired.resource.key() == selected)
        })
        .map(|desired| {
            let resource_key = desired.resource.key();
            let observation = registry
                .observation_history(&resource_key)?
                .into_iter()
                .next();
            let state = observation.as_ref().map_or("unobserved", |observed| {
                if observed.state_hash == desired.manifest_hash {
                    "converged"
                } else {
                    "drifted"
                }
            });
            Ok(json!({
                "resource": desired.resource,
                "state": state,
                "desired_hash": desired.manifest_hash,
                "observed_hash": observation.as_ref().map(|item| &item.state_hash),
                "observation": observation,
                "next_action": if state == "converged" {
                    Value::Null
                } else {
                    json!(format!("cfctl resolve \"reconcile {}\" --json", resource_key))
                },
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(ResultEnvelopeV2::success(
        command,
        json!({
            "diffs": diffs,
            "aggregate_plan_created": false,
            "planning_requested": planning,
            "message": if planning {
                "Registry planning never aggregates mutation approvals. Resolve and create one governed child plan per drifted resource after a fresh live read."
            } else {
                "Desired declarations were compared only with the latest successful live observations; unobserved resources remain unknown."
            }
        }),
    ))
}
