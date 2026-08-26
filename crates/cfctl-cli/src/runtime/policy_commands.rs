use super::prelude::fs;
use super::prelude::{
    AdmissionPolicyBundleStatusV1, AdmissionPolicyBundleV1, AdmissionPolicyCommand,
    AdmissionPolicyRuleV1, CliError, CloudflarePolicyCommand, Deserialize, PolicyCommand, Registry,
    Result, ResultEnvelopeV2, StateStore, Value, json,
};
use super::registry_commands::registry_diff_envelope;
use super::support::cli_io;

#[derive(Debug, Deserialize)]
pub(super) struct AdmissionPolicyStageInput {
    pub(super) name: String,
    pub(super) rules: Vec<AdmissionPolicyRuleV1>,
}

pub(super) fn policy_command(
    store: &StateStore,
    command: PolicyCommand,
) -> Result<ResultEnvelopeV2> {
    match command {
        PolicyCommand::Admission(command) => admission_policy_command(store, command.command),
        PolicyCommand::Cloudflare(command) => cloudflare_policy_command(store, command.command),
    }
}

pub(super) fn admission_policy_command(
    store: &StateStore,
    command: AdmissionPolicyCommand,
) -> Result<ResultEnvelopeV2> {
    match command {
        AdmissionPolicyCommand::Stage(arguments) => {
            let value: Value = serde_json::from_slice(
                &fs::read(&arguments.file).map_err(|source| cli_io(&arguments.file, source))?,
            )?;
            let bundle = if value.get("schema_version").is_some() {
                serde_json::from_value::<AdmissionPolicyBundleV1>(value)?
            } else {
                let input: AdmissionPolicyStageInput = serde_json::from_value(value)?;
                AdmissionPolicyBundleV1::pending(input.name, input.rules)?
            };
            if bundle.status != AdmissionPolicyBundleStatusV1::Pending {
                return Err(CliError::Input(
                    "only a pending admission bundle may be staged".to_owned(),
                ));
            }
            bundle.validate()?;
            store.create_admission_bundle(&bundle)?;
            Ok(ResultEnvelopeV2::success(
                "policy admission stage",
                json!({
                    "bundle": bundle,
                    "approval_command": format!("cfctl policy admission approve {} --yes", bundle.bundle_id),
                    "message": "Admission bundle staged. It has no effect until separately approved and atomically activated."
                }),
            ))
        }
        AdmissionPolicyCommand::List => Ok(ResultEnvelopeV2::success(
            "policy admission list",
            json!({
                "bundles": store.list_admission_bundles()?,
                "active_bundle_id": store.active_admission_bundle_id()?,
            }),
        )),
        AdmissionPolicyCommand::Show(arguments) => {
            let bundle = store.load_admission_bundle(&arguments.bundle_id)?;
            Ok(ResultEnvelopeV2::success(
                "policy admission show",
                serde_json::to_value(bundle)?,
            ))
        }
        AdmissionPolicyCommand::Diff(arguments) => {
            let candidate = store.load_admission_bundle(&arguments.bundle_id)?;
            let active = active_admission_policy(store)?;
            Ok(ResultEnvelopeV2::success(
                "policy admission diff",
                json!({
                    "candidate": candidate,
                    "active": active,
                    "rules_changed": active.as_ref().is_none_or(|active| active.rules != candidate.rules),
                    "safety_floor": "Compiled ambiguity, incomplete-contract, cost, secret, stale-observation, and drift blockers remain non-overridable."
                }),
            ))
        }
        AdmissionPolicyCommand::Approve(arguments) => {
            let bundle = store.approve_admission_bundle(&arguments.bundle_id, arguments.yes)?;
            Ok(ResultEnvelopeV2::success(
                "policy admission approve",
                json!({
                    "bundle_id": bundle.bundle_id,
                    "content_hash": bundle.content_hash,
                    "status": bundle.status,
                    "activate_command": format!("cfctl policy admission activate {}", bundle.bundle_id),
                    "message": "The exact bundle is approved but is not active."
                }),
            ))
        }
        AdmissionPolicyCommand::Activate(arguments) => {
            activate_admission_bundle(store, &arguments.bundle_id, false)
        }
        AdmissionPolicyCommand::Rollback(arguments) => {
            activate_admission_bundle(store, &arguments.bundle_id, true)
        }
    }
}

pub(super) fn cloudflare_policy_command(
    store: &StateStore,
    command: CloudflarePolicyCommand,
) -> Result<ResultEnvelopeV2> {
    let registry = Registry::open(&store.paths().data_dir)?;
    match command {
        CloudflarePolicyCommand::List => {
            let policies = registry
                .list_resources(None)?
                .into_iter()
                .filter(|resource| is_policy_resource_kind(&resource.kind))
                .collect::<Vec<_>>();
            Ok(ResultEnvelopeV2::success(
                "policy cloudflare list",
                json!({"resources": policies, "coverage": registry.coverage()?}),
            ))
        }
        CloudflarePolicyCommand::Get(arguments) => {
            let resource = registry.get_resource(&arguments.resource)?;
            Ok(ResultEnvelopeV2::success(
                "policy cloudflare get",
                json!({
                    "resource": resource,
                    "observations": registry.observation_history(&arguments.resource)?,
                    "found": resource.is_some(),
                }),
            ))
        }
        CloudflarePolicyCommand::Diff(arguments) => registry_diff_envelope(
            &registry,
            "policy cloudflare diff",
            arguments.resource.as_deref(),
            false,
        ),
        CloudflarePolicyCommand::Plan(arguments) => registry_diff_envelope(
            &registry,
            "policy cloudflare plan",
            arguments.resource.as_deref(),
            true,
        ),
    }
}

pub(super) fn is_policy_resource_kind(kind: &str) -> bool {
    let kind = kind.to_ascii_lowercase();
    [
        "access",
        "gateway",
        "notification",
        "policy",
        "ruleset",
        "waf",
    ]
    .iter()
    .any(|term| kind.contains(term))
}

pub(super) fn active_admission_policy(
    store: &StateStore,
) -> Result<Option<AdmissionPolicyBundleV1>> {
    store.active_admission_policy().map_err(CliError::from)
}

pub(super) fn activate_admission_bundle(
    store: &StateStore,
    bundle_id: &str,
    rollback: bool,
) -> Result<ResultEnvelopeV2> {
    let activation = store.activate_admission_bundle(bundle_id)?;
    let target = activation.bundle;
    let previous_id = activation.previous_bundle_id;
    Ok(ResultEnvelopeV2::success(
        if rollback {
            "policy admission rollback"
        } else {
            "policy admission activate"
        },
        json!({
            "bundle": target,
            "previous_bundle_id": previous_id,
            "message": if rollback {
                "Previously approved bundle atomically selected as active; compiled safety floor remains authoritative."
            } else {
                "Approved bundle atomically selected as active; compiled safety floor remains authoritative."
            }
        }),
    ))
}

pub(super) const EVENT_SCHEMA_REFERENCE: &str =
    "https://developers.cloudflare.com/queues/event-subscriptions/events-schemas/";
pub(super) const QUEUE_PULL_REFERENCE: &str =
    "https://developers.cloudflare.com/queues/configuration/pull-consumers/";
pub(super) const REALTIMEKIT_WEBHOOK_REFERENCE: &str =
    "https://developers.cloudflare.com/realtime/realtimekit/webhooks/";
pub(super) const EVENT_BRIDGE_WORKER_SOURCE: &str =
    include_str!("../../../../bridge/event-ingress/src/index.ts");
pub(super) const EVENT_BRIDGE_WRANGLER_SOURCE: &str =
    include_str!("../../../../bridge/event-ingress/wrangler.jsonc");
