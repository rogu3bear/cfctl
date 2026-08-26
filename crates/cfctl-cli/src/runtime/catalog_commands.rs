use super::access_policy::caller_facing_capability;
use super::credential_resolution::ensure_catalog;
use super::credential_resolution::refresh_oauth_scopes_if_authenticated;
use super::guide_generation::guide_document;
use super::prelude::{
    CatalogCommand, CatalogIndex, CatalogSnapshot, CliError, EvidenceClass, GuideArgs,
    GuideTopicArg, GuideTopicV1, Path, Result, ResultEnvelopeV2, StateStore, Value, json,
};
use super::support::capability_missing;
use super::support::catalog_index_file;
use super::support::cli_io;
use super::support::docs_file;
use super::support::http_client;
use super::support::load_workspace_capability;
use crate::telemetry_product::operational_proof_coverage;
use cfctl_catalog::{
    attach_official_product_knowledge, fetch_official, fetch_official_text_feeds, ingest_cli_help,
    ingest_governed_ui_capabilities, ingest_native_control_capabilities,
    ingest_telemetry_capabilities, ingest_wrangler_pages_deploy_help,
    ingest_wrangler_worker_versions_help,
};
use cfctl_core::guide_topic_document;

pub(super) async fn catalog_command(
    store: &StateStore,
    command: CatalogCommand,
) -> Result<ResultEnvelopeV2> {
    match command {
        CatalogCommand::Sync => sync_catalog(store).await,
        CatalogCommand::Search(arguments) => {
            let catalog = ensure_catalog(store).await?;
            let results: Vec<_> = catalog
                .search(&arguments.query)
                .into_iter()
                .take(arguments.limit)
                .map(caller_facing_capability)
                .collect();
            Ok(ResultEnvelopeV2::success(
                "catalog search",
                serde_json::to_value(results)?,
            ))
        }
        CatalogCommand::Show(selector) => {
            let catalog = ensure_catalog(store).await?;
            let capability = if let Some(capability) = catalog.get(&selector.capability_id) {
                capability.clone()
            } else {
                load_workspace_capability(store, &selector.capability_id)?
                    .ok_or_else(|| capability_missing(&selector.capability_id))?
            };
            Ok(ResultEnvelopeV2::success(
                "catalog show",
                serde_json::to_value(caller_facing_capability(&capability))?,
            ))
        }
        CatalogCommand::Changes => {
            let current = ensure_catalog(store).await?;
            let previous_path = store.paths().catalog_previous_file();
            let changes = if previous_path.is_file() {
                CatalogSnapshot::diff(&CatalogSnapshot::load(&previous_path)?, &current)
            } else {
                Vec::new()
            };
            Ok(ResultEnvelopeV2::success(
                "catalog changes",
                json!({"current_schema_hash": current.schema_hash, "changes": changes, "has_previous_snapshot": previous_path.is_file()}),
            ))
        }
        CatalogCommand::Coverage => {
            let catalog = ensure_catalog(store).await?;
            let mut coverage = serde_json::to_value(catalog.coverage())?;
            if let Some(object) = coverage.as_object_mut() {
                object.insert(
                    "operational_proof".to_owned(),
                    operational_proof_coverage(store, &catalog)?,
                );
            }
            Ok(ResultEnvelopeV2::success("catalog coverage", coverage))
        }
    }
}

pub(super) async fn sync_catalog(store: &StateStore) -> Result<ResultEnvelopeV2> {
    let client = http_client()?;
    let (mut catalog, feeds) =
        tokio::try_join!(fetch_official(&client), fetch_official_text_feeds(&client))?;
    ingest_telemetry_capabilities(&mut catalog)?;
    ingest_native_control_capabilities(&mut catalog)?;
    attach_official_product_knowledge(&mut catalog, &feeds)?;
    for (program, version_argument) in [("wrangler", "--version"), ("cloudflared", "version")] {
        if which::which(program).is_ok() {
            let help = std::process::Command::new(program)
                .arg("--help")
                .output()
                .map_err(|source| cli_io(Path::new(program), source))?;
            let version = std::process::Command::new(program)
                .arg(version_argument)
                .output()
                .map_err(|source| cli_io(Path::new(program), source))?;
            ingest_cli_help(
                &mut catalog,
                program,
                String::from_utf8_lossy(&version.stdout).trim(),
                &String::from_utf8_lossy(&help.stdout),
            );
            if program == "wrangler" {
                let pages_deploy_help = std::process::Command::new(program)
                    .args(["pages", "deploy", "--help"])
                    .output()
                    .map_err(|source| cli_io(Path::new(program), source))?;
                if pages_deploy_help.status.success() {
                    ingest_wrangler_pages_deploy_help(
                        &mut catalog,
                        String::from_utf8_lossy(&version.stdout).trim(),
                        &String::from_utf8_lossy(&pages_deploy_help.stdout),
                    );
                }
                let versions_upload_help = std::process::Command::new(program)
                    .args(["versions", "upload", "--help"])
                    .output()
                    .map_err(|source| cli_io(Path::new(program), source))?;
                let versions_deploy_help = std::process::Command::new(program)
                    .args(["versions", "deploy", "--help"])
                    .output()
                    .map_err(|source| cli_io(Path::new(program), source))?;
                if versions_upload_help.status.success() && versions_deploy_help.status.success() {
                    ingest_wrangler_worker_versions_help(
                        &mut catalog,
                        String::from_utf8_lossy(&version.stdout).trim(),
                        &String::from_utf8_lossy(&versions_upload_help.stdout),
                        &String::from_utf8_lossy(&versions_deploy_help.stdout),
                    );
                }
            }
        }
    }
    ingest_governed_ui_capabilities(&mut catalog);
    catalog.refresh_hash()?;
    let oauth_scope_status = match refresh_oauth_scopes_if_authenticated(store).await {
        Ok(Some(snapshot)) => json!({
            "status": "refreshed",
            "schema_hash": snapshot.get("schema_hash"),
            "count": snapshot.pointer("/scopes").and_then(Value::as_array).map(Vec::len),
        }),
        Ok(None) => json!({"status": "not_refreshed", "reason": "no active authenticated profile"}),
        Err(error) => json!({"status": "not_refreshed", "reason": error.to_string()}),
    };
    let current_path = store.paths().catalog_file();
    let previous_catalog = preserve_previous_catalog(store)?;
    store.write_json(&current_path, &catalog)?;
    store.write_json(&docs_file(store), &feeds)?;
    let index_path = catalog_index_file(store);
    CatalogIndex::rebuild(&index_path, &catalog)?;
    let evidence = store.write_evidence(
        EvidenceClass::LiveRead,
        &json!({
            "source": catalog.source_url,
            "schema_hash": catalog.schema_hash,
            "capability_count": catalog.capabilities.len(),
            "docs_index_url": feeds.docs_index_url,
            "changelog_url": feeds.changelog_url,
            "oauth_scope_inventory": oauth_scope_status.clone(),
            "previous_catalog": previous_catalog.clone(),
        }),
    )?;
    Ok(ResultEnvelopeV2::success(
        "catalog sync",
        json!({
            "coverage": catalog.coverage(),
            "docs_fetched_at": feeds.fetched_at,
            "oauth_scope_inventory": oauth_scope_status,
            "previous_catalog": previous_catalog,
            "message": format!("Catalog synced: {} API, CLI, and governed UI capabilities indexed.", catalog.capabilities.len())
        }),
    )
    .with_evidence(evidence))
}

pub(super) fn preserve_previous_catalog(store: &StateStore) -> Result<Value> {
    let current_path = store.paths().catalog_file();
    if !current_path.is_file() {
        return Ok(json!({"status": "absent"}));
    }

    match CatalogSnapshot::load(&current_path) {
        Ok(current) => {
            let schema_hash = current.schema_hash.clone();
            store.write_json(&store.paths().catalog_previous_file(), &current)?;
            Ok(json!({
                "status": "preserved",
                "schema_hash": schema_hash,
            }))
        }
        Err(error) => Ok(json!({
            "status": "discarded_invalid",
            "reason": error.to_string(),
        })),
    }
}

pub(super) async fn guide_command(
    store: &StateStore,
    arguments: &GuideArgs,
) -> Result<ResultEnvelopeV2> {
    if let Some(topic) = arguments.topic {
        return guide_topic_envelope(topic);
    }
    let capability_id = arguments.capability_id.as_deref().ok_or_else(|| {
        CliError::Input("guide requires one capability ID or `--topic`".to_owned())
    })?;
    let catalog = ensure_catalog(store).await?;
    let capability = if let Some(capability) = catalog.get(capability_id) {
        capability.clone()
    } else {
        load_workspace_capability(store, capability_id)?
            .ok_or_else(|| capability_missing(capability_id))?
    };
    Ok(ResultEnvelopeV2::success(
        "guide",
        serde_json::to_value(guide_document(&capability))?,
    ))
}

pub(super) fn guide_topic_envelope(topic: GuideTopicArg) -> Result<ResultEnvelopeV2> {
    let topic = match topic {
        GuideTopicArg::System => GuideTopicV1::System,
        GuideTopicArg::StandingAuthority => GuideTopicV1::StandingAuthority,
    };
    Ok(ResultEnvelopeV2::success(
        "guide",
        serde_json::to_value(guide_topic_document(topic))?,
    ))
}
