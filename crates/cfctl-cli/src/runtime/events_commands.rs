use super::policy_commands::EVENT_BRIDGE_WORKER_SOURCE;
use super::policy_commands::EVENT_BRIDGE_WRANGLER_SOURCE;
use super::policy_commands::EVENT_SCHEMA_REFERENCE;
use super::policy_commands::QUEUE_PULL_REFERENCE;
use super::policy_commands::REALTIMEKIT_WEBHOOK_REFERENCE;
use super::prelude::fs;
use super::prelude::{
    CliError, EventBridgeCommand, EventHistoryArgs, EventReconcileArgs, EventsCommand, Registry,
    Result, ResultEnvelopeV2, StateStore, Value, json,
};
use super::support::cli_io;
use cfctl_core::hash_value;

pub(super) fn events_command(
    store: &StateStore,
    command: EventsCommand,
) -> Result<ResultEnvelopeV2> {
    let mut registry = Registry::open(&store.paths().data_dir)?;
    match command {
        EventsCommand::Sources => Ok(ResultEnvelopeV2::success(
            "events sources",
            json!({
                "schema_version": 1,
                "verified_at": "2026-07-22",
                "documentation_last_updated": "2026-07-15",
                "documentation": EVENT_SCHEMA_REFERENCE,
                "sources": [
                    {"family":"Access","source_ids":["access"]},
                    {"family":"Artifacts","source_ids":["artifacts","artifacts.repo"]},
                    {"family":"Email Sending","source_ids":["email.sending"]},
                    {"family":"R2","source_ids":["r2"]},
                    {"family":"Super Slurper","source_ids":["superSlurper","superSlurper.job"]},
                    {"family":"Vectorize","source_ids":["vectorize"]},
                    {"family":"Workers AI","source_ids":["workersAi.model"]},
                    {"family":"Workers Builds","source_ids":["workersBuilds.worker"]},
                    {"family":"Workers KV","source_ids":["kv"]},
                    {"family":"Workflows","source_ids":["workflows.workflow"]}
                ],
                "truth_boundary": "This is a versioned local documentation snapshot. Use catalog/docs drift checks before changing Event Subscription request schemas."
            }),
        )),
        EventsCommand::Status => Ok(ResultEnvelopeV2::success(
            "events status",
            json!({
                "ledger": registry.event_status()?,
                "reconciliation_jobs": registry.reconciliation_jobs()?,
                "queue_pull_contract": QUEUE_PULL_REFERENCE,
                "truth_boundary": "Events and queued reconciliation jobs are durable local evidence. They are not observed Cloudflare resource state."
            }),
        )),
        EventsCommand::History(EventHistoryArgs { limit }) => Ok(ResultEnvelopeV2::success(
            "events history",
            json!({"events": registry.event_history(limit)?, "limit": limit}),
        )),
        EventsCommand::Reconcile(EventReconcileArgs { resource }) => {
            let resource_ref = registry.get_resource(&resource)?.ok_or_else(|| {
                CliError::Input(format!(
                    "registry resource `{resource}` was not found; run `cfctl registry sync` and inspect `cfctl registry list --json`"
                ))
            })?;
            let job = registry.enqueue_reconciliation(resource_ref)?;
            Ok(ResultEnvelopeV2::success(
                "events reconcile",
                json!({
                    "job": job,
                    "live_read_executed": false,
                    "next_action": "Resolve the resource kind to its registered inventory provider and execute the bounded live read; only a successful evidence-backed read may record an observation."
                }),
            ))
        }
        EventsCommand::Bridge(arguments) => event_bridge_command(store, arguments.command),
    }
}

pub(super) fn event_bridge_command(
    store: &StateStore,
    command: EventBridgeCommand,
) -> Result<ResultEnvelopeV2> {
    let manifest_path = store
        .paths()
        .config_dir
        .join("events/bridge/event-ingress.json");
    let template = json!({
        "schema_version": 1,
        "worker_name": "cfctl-event-ingress",
        "worker_source_hash": hash_value(&json!(EVENT_BRIDGE_WORKER_SOURCE))?,
        "wrangler_source_hash": hash_value(&json!(EVENT_BRIDGE_WRANGLER_SOURCE))?,
        "queue_binding": "EVENT_QUEUE",
        "realtimekit": {
            "signature_header": "rtk-signature",
            "delivery_id_header": "rtk-uuid",
            "webhook_id_header": "rtk-webhook-id",
            "algorithm": "RSA-SHA256",
            "public_key_url": "https://api.realtime.cloudflare.com/.well-known/webhooks.json",
            "documentation": REALTIMEKIT_WEBHOOK_REFERENCE
        },
        "deployment_state": "not_applied"
    });
    match command {
        EventBridgeCommand::Inspect => Ok(ResultEnvelopeV2::success(
            "events bridge inspect",
            json!({"template": template, "manifest_path": manifest_path}),
        )),
        EventBridgeCommand::Prepare => {
            let parent = manifest_path.parent().ok_or_else(|| {
                CliError::Input("event bridge manifest has no parent directory".to_owned())
            })?;
            fs::create_dir_all(parent).map_err(|source| cli_io(parent, source))?;
            store.write_json(&manifest_path, &template)?;
            Ok(ResultEnvelopeV2::success(
                "events bridge prepare",
                json!({
                    "manifest_path": manifest_path,
                    "manifest": template,
                    "cloudflare_applied": false,
                    "next_action": "Resolve and plan the exact Worker, Queue, and Event Subscription capabilities separately. This command stages local configuration only and grants no Cloudflare mutation authority."
                }),
            ))
        }
        EventBridgeCommand::Status => {
            let manifest: Option<Value> = manifest_path
                .is_file()
                .then(|| store.read_json(&manifest_path))
                .transpose()?;
            Ok(ResultEnvelopeV2::success(
                "events bridge status",
                json!({
                    "prepared": manifest.is_some(),
                    "manifest_path": manifest_path,
                    "manifest": manifest,
                    "cloudflare_apply_proven": false
                }),
            ))
        }
    }
}
