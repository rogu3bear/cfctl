use super::access_policy::caller_facing_capability;
use super::credential_resolution::ensure_catalog;
use super::entitlement_state::should_bind_zone_account;
use super::entitlement_state::should_resolve_entitlement_probe;
use super::entitlement_state::should_resolve_zone_entitlement;
use super::live_state_contracts::should_bind_cloudflare_tunnel_configuration_state;
use super::live_state_contracts::should_bind_d1_read_replication_state;
use super::live_state_contracts::should_bind_dns_record_state;
use super::live_state_contracts::should_bind_global_warp_override_state;
use super::live_state_contracts::should_bind_warp_connector_configuration_state;
use super::live_state_contracts::should_bind_web_analytics_rum_state;
use super::oauth_state::should_bind_oauth_client_secret_state;
use super::oauth_state::should_bind_oauth_client_update_state;
use super::plan_secret::CLOUDFLARE_TUNNEL_CONFIGURATION_READ_CAPABILITY_ID;
use super::plan_secret::D1_READ_REPLICATION_READ_CAPABILITY_ID;
use super::plan_secret::DNS_RECORD_DETAIL_READ_CAPABILITY_ID;
use super::plan_secret::GLOBAL_WARP_OVERRIDE_READ_CAPABILITY_ID;
use super::plan_secret::OAUTH_CLIENT_DETAIL_READ_CAPABILITY_ID;
use super::plan_secret::WARP_CONNECTOR_CONFIGURATION_READ_CAPABILITY_ID;
use super::plan_secret::WEB_ANALYTICS_RUM_READ_CAPABILITY_ID;
use super::prelude::{
    AdapterStatus, BTreeSet, CapabilityGuideStageV1, CapabilityGuideV1, CapabilityV1, CliError,
    ErrorV1, EvidenceClass, GuideActionV1, GuideContractStateV1, ResolveArgs, Result,
    ResultEnvelopeV2, StateStore, Value, json,
};
use super::r2_credentials::is_r2_temporary_credentials_operation_identity;
use super::secret_io::is_access_service_token_create_capability;
use super::secret_io::is_secret_output_capability;
use super::secret_io::is_worker_tail_create_capability;
use super::support::load_workspace_capability;
use super::worker_custom_domain;
use cfctl_core::guide_stages;

pub(super) fn stage_required(
    stage: cfctl_core::GuideStage,
    capability: &cfctl_core::CapabilityV1,
) -> bool {
    use cfctl_core::GuideStage;
    if capability.workflow.is_some() {
        return matches!(
            stage,
            GuideStage::Discover
                | GuideStage::InspectCurrentState
                | GuideStage::LoadStandards
                | GuideStage::Execute
                | GuideStage::CloseWithEvidence
        );
    }
    match stage {
        GuideStage::RequestApproval | GuideStage::Rectify => capability.mutating,
        GuideStage::CalculateCost => capability.cost.incremental || !capability.cost.known,
        GuideStage::Verify => capability.verification.required,
        _ => true,
    }
}

pub(super) fn guide_document(capability: &CapabilityV1) -> CapabilityGuideV1 {
    let blocking_gaps = capability.mutation_contract_gaps();
    let contract_ready =
        capability.adapter_status != AdapterStatus::Blocked && blocking_gaps.is_empty();
    let post_resolution_call_argv = capability_call_argv(capability);
    let call_argv = contract_ready.then(|| post_resolution_call_argv.clone());
    let stages = guide_stages()
        .iter()
        .enumerate()
        .map(|(index, stage)| {
            guide_stage_document(
                index + 1,
                *stage,
                capability,
                contract_ready,
                &blocking_gaps,
                Some(&post_resolution_call_argv),
            )
        })
        .collect::<Vec<_>>();
    let blocked_reason = capability.blocked_reason.clone();
    let next_action =
        guide_next_action(capability, contract_ready, Some(&post_resolution_call_argv));
    let capability = caller_facing_capability(capability);

    CapabilityGuideV1 {
        capability,
        contract_state: if contract_ready {
            GuideContractStateV1::Available
        } else {
            GuideContractStateV1::Blocked
        },
        blocking_gaps,
        blocked_reason,
        call_argv,
        post_resolution_call_argv: post_resolution_call_argv.clone(),
        next_action,
        stages,
    }
}

/// Minimum top score for the resolver to commit to a single capability.
/// A hit below this is a description-only near-miss; the resolver reports
/// candidates but refuses to emit a call string.
pub(super) const RESOLVE_MIN_CONFIDENT_SCORE: usize = 6;

/// Deterministically map a natural-language intent to a capability and the exact
/// governed commands to run. Read-only: it never mutates Cloudflare and never
/// launches an agent (that is `execute_natural_language`). It fails closed —
/// emitting only disambiguation guidance — when nothing matches confidently or
/// the top match does not clearly beat the runner-up.
pub(super) async fn resolve_command(
    store: &StateStore,
    arguments: ResolveArgs,
) -> Result<ResultEnvelopeV2> {
    let intent = arguments.intent.trim();
    if intent.is_empty() {
        return Err(CliError::guided(
            "CFCTL_RESOLVE_EMPTY",
            "resolve needs a natural-language intent",
            "Describe the goal, e.g. `cfctl resolve \"enable email routing on example.com\"`.",
        ));
    }
    let catalog = ensure_catalog(store).await?;
    // Workspace loaders resolve exact operation IDs, not natural-language
    // provider searches. An unrelated dirty registered application must not
    // prevent discovering a provider capability.
    let workspace = if catalog.get(intent).is_some() || intent.chars().any(char::is_whitespace) {
        None
    } else {
        load_workspace_capability(store, intent)?
    };
    let ranked = workspace.as_ref().map_or_else(
        || catalog.search_scored(intent),
        |capability| vec![(capability, usize::MAX)],
    );
    let (result, error) = resolve_result(
        intent,
        &ranked,
        arguments.account.as_deref(),
        arguments.limit,
    );
    let mut envelope = ResultEnvelopeV2::success("resolve", result);
    // `error: Some` is a fail-closed resolve: mark it not-ok and surface the
    // recovery hint at the canonical envelope level, matching every other
    // failure surface. `None` means a capability was actionably resolved.
    envelope.ok = error.is_none();
    if envelope.ok {
        envelope.capability_id = envelope
            .result
            .pointer("/resolved/capability_id")
            .and_then(Value::as_str)
            .map(str::to_owned);
    }
    envelope.error = error;
    Ok(envelope)
}

/// Pure decision core for `resolve`: given the ranked catalog hits, produce the
/// result JSON and an optional `ErrorV1`. `Some(error)` means the resolve failed
/// closed (not actionable) and carries the canonical envelope-level `next_step`;
/// `None` means an actionable capability was resolved. Deterministic and
/// side-effect-free so the fail-closed gating is unit-testable without a store.
#[expect(
    clippy::too_many_lines,
    reason = "resolution keeps ambiguity, broad telemetry overviews, selector discrimination, and dangerous-mutation fail-closed behavior in one deterministic decision boundary"
)]
pub(super) fn resolve_result(
    intent: &str,
    ranked: &[(&CapabilityV1, usize)],
    account: Option<&str>,
    limit: usize,
) -> (Value, Option<ErrorV1>) {
    let limit = limit.clamp(1, 25);
    let candidates: Vec<Value> = ranked
        .iter()
        .take(limit)
        .map(|(capability, score)| resolve_candidate_json(capability, *score))
        .collect();

    if is_broad_telemetry_intent(intent) {
        let telemetry_ranked = rank_telemetry_overview(intent, ranked);
        let reads = telemetry_ranked
            .iter()
            .filter(|(capability, _)| !capability.mutating && capability.workflow.is_none())
            .take(limit)
            .map(|(capability, score)| resolve_candidate_json(capability, *score))
            .collect::<Vec<_>>();
        let workflows = telemetry_ranked
            .iter()
            .filter(|(capability, _)| capability.workflow.is_some())
            .take(limit)
            .map(|(capability, score)| resolve_candidate_json(capability, *score))
            .collect::<Vec<_>>();
        let mutations = telemetry_ranked
            .iter()
            .filter(|(capability, _)| {
                capability.mutating
                    && capability.adapter_status != AdapterStatus::Blocked
                    && capability.mutation_contract_gaps().is_empty()
            })
            .take(limit)
            .map(|(capability, score)| resolve_candidate_json(capability, *score))
            .collect::<Vec<_>>();
        let blocked_gaps = telemetry_ranked
            .iter()
            .filter(|(capability, _)| {
                capability.mutating
                    && (capability.adapter_status == AdapterStatus::Blocked
                        || !capability.mutation_contract_gaps().is_empty())
            })
            .take(limit)
            .map(|(capability, score)| resolve_candidate_json(capability, *score))
            .collect::<Vec<_>>();
        return (
            json!({
                "intent": intent,
                "matched": candidates,
                "resolved": {
                    "kind": "telemetry_domain_overview",
                    "domains": ["analytics", "logs_observability", "security_response", "data_governance"],
                    "ranked_reads": reads,
                    "governed_workflows": workflows,
                    "mutation_candidates": mutations,
                    "blocked_or_unclassified_gaps": blocked_gaps,
                    "mutation_selection": "withheld_until_a_specific_capability_is_resolved_and_guided",
                    "discovery_argv": {
                        "coverage": ["cfctl", "catalog", "coverage", "--json"],
                        "search": ["cfctl", "catalog", "search", intent, "--json"]
                    }
                },
                "ambiguous": false,
                "guidance": "Broad telemetry language returns workflow-first, domain-aware discovery. Choose and inspect one typed capability; cfctl never selects an enforcement or configuration mutation from this overview, and blocked mutations remain labeled contract gaps.",
            }),
            None,
        );
    }

    // No positive-scoring capability: fail closed with discovery guidance.
    let Some((top_capability, top_score)) = ranked.first().map(|(cap, score)| (*cap, *score))
    else {
        let next_step = "Broaden the query, or run `cfctl catalog search \"<keywords>\" --json`. If the catalog is stale, run `cfctl catalog sync`.";
        let result = json!({
            "intent": intent,
            "matched": [],
            "resolved": Value::Null,
            "ambiguous": true,
            "reason": "no catalog capability matched the intent terms",
            "next_step": next_step,
            "disambiguation": {
                "search_argv": ["cfctl", "catalog", "search", intent, "--json"],
                "coverage_argv": ["cfctl", "catalog", "coverage", "--json"],
            },
        });
        let error = ErrorV1 {
            code: "CFCTL_RESOLVE_NO_MATCH".to_owned(),
            message: "no catalog capability matched the intent terms".to_owned(),
            next_step: Some(next_step.to_owned()),
        };
        return (result, Some(error));
    };

    let runner_up = ranked.get(1).map_or(0, |(_, score)| *score);
    // Commit only to a confident, unambiguous top match: score above the floor
    // and at least 1.2x the runner-up (or a sole match). Integer test avoids
    // float rounding: top/runner >= 6/5. The 1.2x margin is evidence-backed: a
    // 28-intent live-catalog study showed the top candidate is correct in ~93%
    // of cases, yet a 1.5x gate committed only 7% because near-duplicate
    // capabilities cluster; 1.2x commits clearly-dominant matches while exact
    // and near ties (below 1.2x) still fail closed.
    let confident = top_score >= RESOLVE_MIN_CONFIDENT_SCORE
        && (runner_up == 0 || top_score * 5 >= runner_up * 6);

    if !confident {
        let reason = if top_score < RESOLVE_MIN_CONFIDENT_SCORE {
            format!(
                "top match `{}` scored only {top_score}; too weak to commit",
                top_capability.id
            )
        } else {
            format!(
                "top match `{}` (score {top_score}) does not clearly beat `{}` (score {runner_up})",
                top_capability.id, ranked[1].0.id,
            )
        };
        let next_step = "Pick a candidate and inspect it: `cfctl catalog show <capability-id> --json`, then `cfctl guide <capability-id>`.";
        let result = json!({
            "intent": intent,
            "matched": candidates,
            "resolved": Value::Null,
            "ambiguous": true,
            "reason": reason.clone(),
            "next_step": next_step,
        });
        let error = ErrorV1 {
            code: "CFCTL_RESOLVE_AMBIGUOUS".to_owned(),
            message: reason,
            next_step: Some(next_step.to_owned()),
        };
        return (result, Some(error));
    }

    let (resolved, guidance) = resolve_actionable(top_capability, intent, account);
    let result = json!({
        "intent": intent,
        "matched": candidates,
        "resolved": resolved,
        "ambiguous": false,
        "guidance": guidance,
    });
    (result, None)
}

pub(super) fn rank_telemetry_overview<'a>(
    intent: &str,
    ranked: &[(&'a CapabilityV1, usize)],
) -> Vec<(&'a CapabilityV1, usize)> {
    let terms = intent
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|term| !term.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<BTreeSet<_>>();
    let asks_for_audit = ["audit", "coverage", "overview", "discover"]
        .iter()
        .any(|term| terms.contains(*term));
    let mut reranked = ranked
        .iter()
        .map(|(capability, score)| {
            let mut adjusted = *score;
            if capability.workflow.is_some() {
                adjusted += 24;
            }
            if asks_for_audit {
                adjusted += match capability.id.as_str() {
                    "workflow.telemetry.audit-account" => 64,
                    "workflow.telemetry.audit-governance" => 56,
                    "workflow.telemetry.export-evidence-packet" => 48,
                    "workflow.telemetry.verify-freshness" => 40,
                    _ => 0,
                };
            }
            if capability.adapter_status == AdapterStatus::Blocked {
                adjusted = adjusted.saturating_sub(8);
            }
            (*capability, adjusted)
        })
        .collect::<Vec<_>>();
    reranked.sort_by(|(left, left_score), (right, right_score)| {
        right_score
            .cmp(left_score)
            .then_with(|| left.id.cmp(&right.id))
    });
    reranked
}

pub(super) fn is_broad_telemetry_intent(intent: &str) -> bool {
    let terms = intent
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|term| !term.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<BTreeSet<_>>();
    let has_domain = ["telemetry", "analytics", "observability", "logs"]
        .iter()
        .any(|term| terms.contains(*term));
    let has_specific_discriminator = [
        "access", "bot", "browser", "cache", "ddos", "dns", "engine", "firewall", "graphql",
        "hostname", "ip", "logpull", "logpush", "pages", "rate", "rum", "security", "tail",
        "trace", "waf", "web", "worker", "zero",
    ]
    .iter()
    .any(|term| terms.contains(*term));
    let asks_for_overview = ["audit", "coverage", "discover", "overview"]
        .iter()
        .any(|term| terms.contains(*term));
    has_domain && !has_specific_discriminator && (asks_for_overview || terms.len() <= 4)
}

/// Build the `resolved` object for a confident top match: capability metadata,
/// the governed command set, and (when applicable) the zone hint and account.
/// Returns the resolved JSON and the human-facing guidance summary.
pub(super) fn resolve_actionable(
    capability: &CapabilityV1,
    intent: &str,
    account: Option<&str>,
) -> (Value, String) {
    let gaps = capability.mutation_contract_gaps();
    let contract_ready = capability.adapter_status != AdapterStatus::Blocked && gaps.is_empty();
    let call_argv = capability_call_argv(capability);
    let next_action = guide_next_action(capability, contract_ready, Some(&call_argv));

    // Contract-ready: emit the exact governed command sequence. Blocked or
    // gap-incomplete: reuse guide_next_action's fail-closed guidance instead of
    // fabricating a call the agent must not run.
    let commands = if contract_ready {
        let mut commands = json!({ "draft_argv": call_argv });
        if capability.mutating {
            commands["approve_argv"] = json!(approval_command_argv(capability, "<operation-id>"));
            commands["run_argv"] = json!(["cfctl", "plans", "run", "<operation-id>", "--json"]);
            commands["status_argv"] =
                json!(["cfctl", "plans", "status", "<operation-id>", "--json"]);
        }
        commands
    } else {
        json!({
            "blocked": true,
            "blocking_gaps": gaps,
            "next_action": next_action.clone(),
        })
    };

    let mut resolved = json!({
        "capability_id": capability.id,
        "title": capability.title,
        "product": capability.product,
        "mutating": capability.mutating,
        "contract_ready": contract_ready,
        "adapter_status": capability.adapter_status,
        "required_selectors": required_selectors_json(capability),
        "needs_request_body": capability_has_meaningful_request_body(capability),
        "permission_lane": capability.permissions,
        "commands": commands,
    });
    if let Some(hint) = resolve_zone_hint(capability, intent) {
        resolved["zone_resolution_hint"] = hint;
    }
    if let Some(account) = account {
        resolved["account"] = json!(account);
    }
    (resolved, next_action.summary)
}

pub(super) fn resolve_candidate_json(capability: &CapabilityV1, score: usize) -> Value {
    let contract_ready = capability.adapter_status != AdapterStatus::Blocked
        && capability.mutation_contract_gaps().is_empty();
    json!({
        "capability_id": capability.id,
        "score": score,
        "title": capability.title,
        "product": capability.product,
        "mutating": capability.mutating,
        "adapter_status": capability.adapter_status,
        "contract_ready": contract_ready,
        "show_argv": catalog_show_argv(&capability.id),
        "guide_argv": ["cfctl", "guide", capability.id.as_str(), "--json"],
    })
}

pub(crate) fn required_selectors_json(capability: &CapabilityV1) -> Vec<Value> {
    capability
        .selectors
        .iter()
        .filter(|selector| selector.required)
        .map(|selector| {
            json!({
                "name": selector.name,
                "location": selector.location,
                "value_type": selector.value_type,
                "description": selector.description,
            })
        })
        .collect()
}

/// When a capability requires a zone path selector, emit a resolve-first hint:
/// cfctl has no inline domain->zone_id resolver, so an agent must read the zone
/// id from a `/zones` list before calling. Never guesses a zone id.
pub(super) fn resolve_zone_hint(capability: &CapabilityV1, intent: &str) -> Option<Value> {
    let needs_zone = capability.selectors.iter().any(|selector| {
        selector.required
            && selector.location == "path"
            && selector.name.to_ascii_lowercase().contains("zone")
    });
    if !needs_zone {
        return None;
    }
    let domain = extract_domain(intent);
    let domain_token = domain.as_deref().unwrap_or("<domain>");
    Some(json!({
        "reason": "This capability needs a 32-hex Cloudflare zone id, not a domain name.",
        "resolve_first": "Find the zone-list capability, then read the zone id from its result.",
        "search_argv": ["cfctl", "catalog", "search", "list zones", "--json"],
        "example_read_argv": [
            "cfctl", "call", "<zone-list-capability-id>", "--query", format!("name={domain_token}"), "--json"
        ],
        "use_field": "result[0].id",
    }))
}

/// Extract the first domain-like token from an intent, for zone-hint examples.
/// Deliberately conservative: no dependency on the regex crate.
pub(super) fn extract_domain(intent: &str) -> Option<String> {
    intent
        .split(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '(' | ')' | ','))
        .map(|token| token.trim_matches(|c: char| !c.is_ascii_alphanumeric()))
        .find(|token| is_domain_like(token))
        .map(str::to_ascii_lowercase)
}

pub(super) fn is_domain_like(token: &str) -> bool {
    if token.len() < 3 || !token.contains('.') {
        return false;
    }
    let labels: Vec<&str> = token.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let last = labels.last().copied().unwrap_or_default();
    if last.len() < 2 || !last.chars().all(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    labels.iter().all(|label| {
        !label.is_empty() && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

pub(crate) fn capability_call_argv(capability: &CapabilityV1) -> Vec<String> {
    if matches!(
        capability.id.as_str(),
        "account-api-tokens-create-token" | "user-api-tokens-create-token"
    ) {
        let mut argv = vec!["cfctl", "keys", "mint"];
        if capability.id == "user-api-tokens-create-token" {
            argv.push("--user");
        }
        argv.extend([
            "--name",
            "<token-name>",
            "--permission",
            "<permission-group-id>",
            "--account",
            "<account_id>",
            "--value-out",
            "<new-mode-0600-path>",
            "--json",
        ]);
        return argv.into_iter().map(str::to_owned).collect();
    }

    let mut argv = vec!["cfctl".to_owned(), "call".to_owned(), capability.id.clone()];
    for selector in capability
        .selectors
        .iter()
        .filter(|selector| selector.required)
    {
        argv.push(
            if selector.location == "query" {
                "--query"
            } else {
                "--selector"
            }
            .to_owned(),
        );
        argv.push(format!("{}=<{}>", selector.name, selector.name));
    }
    if capability_has_meaningful_request_body(capability) {
        argv.push("--body-stdin".to_owned());
    }
    if is_secret_output_capability(capability) {
        let sink = if is_access_service_token_create_capability(capability)
            || is_r2_temporary_credentials_operation_identity(capability)
            || is_worker_tail_create_capability(capability)
        {
            "<new-mode-0600-json-path>"
        } else {
            "<new-mode-0600-path>"
        };
        argv.extend(["--value-out".to_owned(), sink.to_owned()]);
    }
    if capability.d1_full_export.is_some() {
        argv.extend(["--out".to_owned(), "<new-mode-0600-sql-path>".to_owned()]);
    }
    argv.push("--json".to_owned());
    argv
}

pub(crate) fn capability_has_meaningful_request_body(capability: &CapabilityV1) -> bool {
    let Some(schema) = capability.request_schema.as_ref() else {
        return false;
    };
    if schema.get("x-cfctl-body-required").and_then(Value::as_bool) == Some(true) {
        return true;
    }
    if capability
        .request_object_fields()
        .is_some_and(|fields| !fields.is_empty())
    {
        return true;
    }
    schema
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|value_type| value_type != "object")
}

pub(super) fn guide_next_action(
    capability: &CapabilityV1,
    contract_ready: bool,
    call_argv: Option<&[String]>,
) -> GuideActionV1 {
    if contract_ready {
        let summary = if capability.mutating {
            "Create the preview plan with the exact generated argv; no Cloudflare mutation occurs until the resulting operation is run."
        } else {
            "Run the exact generated argv to produce a redacted live-read receipt."
        };
        return GuideActionV1 {
            summary: summary.to_owned(),
            argv: call_argv.unwrap_or_default().to_vec(),
        };
    }

    let gaps = capability.mutation_contract_gaps();
    let blocked_text = format!(
        "{} {}",
        capability.blocked_reason.as_deref().unwrap_or_default(),
        gaps.join(" ")
    )
    .to_ascii_lowercase();
    let (summary, argv) = if should_resolve_entitlement_probe(capability) {
        (
            "Run the exact call to perform the declared read-only product probe. A successful read is hash-bound and rechecked before execution; a rejected read leaves authorization, plan entitlement, and account configuration explicitly unresolved.",
            call_argv.unwrap_or_default().to_vec(),
        )
    } else if should_resolve_zone_entitlement(capability) {
        (
            "Run the exact call to perform the governed live zone-subscription read. cfctl creates a plan only when the active plan is allowed by the official matrix, then binds and rechecks that entitlement before execution.",
            call_argv.unwrap_or_default().to_vec(),
        )
    } else if blocked_text.contains("product-scoped subscription join key") {
        (
            "cfctl cannot safely map the account's product-scoped subscriptions to this operation's generic plan matrix because the official schema supplies no product-scoped subscription join key. Keep the operation blocked; do not treat any active account subscription as proof of entitlement.",
            vec![
                "cfctl".to_owned(),
                "docs".to_owned(),
                "search".to_owned(),
                format!("{} plans subscriptions", capability.product),
                "--json".to_owned(),
            ],
        )
    } else if blocked_text.contains("cost") {
        (
            "Resolve and bind the operation's official pricing contract before planning it.",
            vec![
                "cfctl".to_owned(),
                "docs".to_owned(),
                "search".to_owned(),
                format!("{} pricing", capability.product),
                "--json".to_owned(),
            ],
        )
    } else if blocked_text.contains("entitlement") {
        (
            "Review the official plan gate, then obtain an account-backed entitlement result before planning. Documentation identifies requirements but does not prove the selected account is entitled.",
            vec![
                "cfctl".to_owned(),
                "docs".to_owned(),
                "search".to_owned(),
                format!("{} plans", capability.product),
                "--json".to_owned(),
            ],
        )
    } else if blocked_text.contains("permission inventory")
        || blocked_text.contains("permission lane")
    {
        (
            "Inspect the fresh account permission inventory. Inventory alone does not prove that a permission group authorizes this operation; token creation must use the governed keys workflow.",
            [
                "cfctl",
                "keys",
                "permissions",
                "--account",
                "<account_id>",
                "--json",
            ]
            .map(str::to_owned)
            .to_vec(),
        )
    } else {
        (
            "Inspect the exact blocked adapter and contract metadata; do not attempt execution until every named gap is resolved.",
            vec![
                "cfctl".to_owned(),
                "catalog".to_owned(),
                "show".to_owned(),
                capability.id.clone(),
                "--json".to_owned(),
            ],
        )
    };
    GuideActionV1 {
        summary: summary.to_owned(),
        argv,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum GuideLiveRead {
    ZoneAccount,
    ZoneEntitlement,
    ProductEntitlementProbe,
    GlobalWarpOverrideState,
    D1ReadReplicationState,
    CloudflareTunnelConfigurationState,
    WarpConnectorConfigurationState,
    WebAnalyticsRumState,
    DnsRecordState,
    OAuthClientSecretState,
    WorkerCustomDomainState,
}

pub(super) fn guide_live_reads(capability: &CapabilityV1) -> Vec<GuideLiveRead> {
    [
        (
            should_bind_zone_account(capability),
            GuideLiveRead::ZoneAccount,
        ),
        (
            should_resolve_zone_entitlement(capability),
            GuideLiveRead::ZoneEntitlement,
        ),
        (
            should_resolve_entitlement_probe(capability),
            GuideLiveRead::ProductEntitlementProbe,
        ),
        (
            should_bind_global_warp_override_state(capability),
            GuideLiveRead::GlobalWarpOverrideState,
        ),
        (
            should_bind_d1_read_replication_state(capability),
            GuideLiveRead::D1ReadReplicationState,
        ),
        (
            should_bind_cloudflare_tunnel_configuration_state(capability),
            GuideLiveRead::CloudflareTunnelConfigurationState,
        ),
        (
            should_bind_warp_connector_configuration_state(capability),
            GuideLiveRead::WarpConnectorConfigurationState,
        ),
        (
            should_bind_web_analytics_rum_state(capability),
            GuideLiveRead::WebAnalyticsRumState,
        ),
        (
            should_bind_dns_record_state(capability),
            GuideLiveRead::DnsRecordState,
        ),
        (
            should_bind_oauth_client_secret_state(capability),
            GuideLiveRead::OAuthClientSecretState,
        ),
        (
            worker_custom_domain::should_bind_state(capability),
            GuideLiveRead::WorkerCustomDomainState,
        ),
    ]
    .into_iter()
    .filter_map(|(required, read)| required.then_some(read))
    .collect()
}

pub(super) fn guide_stage_contract_state(
    stage: cfctl_core::GuideStage,
    capability: &CapabilityV1,
    contract_ready: bool,
    blocking_gaps: &[String],
    live_reads: &[GuideLiveRead],
) -> GuideContractStateV1 {
    use cfctl_core::GuideStage;

    if capability.workflow.is_some() {
        return if matches!(
            stage,
            GuideStage::Discover
                | GuideStage::InspectCurrentState
                | GuideStage::LoadStandards
                | GuideStage::Execute
                | GuideStage::CloseWithEvidence
        ) {
            GuideContractStateV1::Available
        } else {
            GuideContractStateV1::NotApplicable
        };
    }

    let entitlement_blocked = capability.entitlement.available == Some(false)
        || blocking_gaps.iter().any(|gap| gap.contains("entitlement"));
    let entitlement_unresolved = capability.mutating
        && capability.entitlement.available != Some(true)
        && capability.entitlement.plans.is_empty();
    match stage {
        GuideStage::SelectAccount if live_reads.contains(&GuideLiveRead::ZoneAccount) => {
            GuideContractStateV1::LiveReadRequired
        }
        GuideStage::CheckEntitlement
            if live_reads.contains(&GuideLiveRead::ZoneEntitlement)
                || live_reads.contains(&GuideLiveRead::ProductEntitlementProbe) =>
        {
            GuideContractStateV1::LiveReadRequired
        }
        GuideStage::InspectCurrentState
            if live_reads.iter().any(|read| {
                matches!(
                    read,
                    GuideLiveRead::GlobalWarpOverrideState
                        | GuideLiveRead::D1ReadReplicationState
                        | GuideLiveRead::CloudflareTunnelConfigurationState
                        | GuideLiveRead::WarpConnectorConfigurationState
                        | GuideLiveRead::WebAnalyticsRumState
                        | GuideLiveRead::DnsRecordState
                        | GuideLiveRead::OAuthClientSecretState
                        | GuideLiveRead::WorkerCustomDomainState
                )
            }) =>
        {
            GuideContractStateV1::LiveReadRequired
        }
        GuideStage::CheckEntitlement if entitlement_blocked => GuideContractStateV1::Blocked,
        GuideStage::CheckEntitlement if entitlement_unresolved => {
            GuideContractStateV1::ManualReview
        }
        GuideStage::CalculateCost if capability.mutating && !capability.cost.known => {
            GuideContractStateV1::Blocked
        }
        GuideStage::CalculateCost
        | GuideStage::BuildPlan
        | GuideStage::RequestApproval
        | GuideStage::AcquireLocks
        | GuideStage::Rectify
            if !capability.mutating =>
        {
            GuideContractStateV1::NotApplicable
        }
        GuideStage::BuildPlan
        | GuideStage::RequestApproval
        | GuideStage::AcquireLocks
        | GuideStage::Execute
            if !contract_ready =>
        {
            GuideContractStateV1::Blocked
        }
        GuideStage::Verify
            if !capability.verification_contract_declared()
                || !capability.verification_contract_supported() =>
        {
            GuideContractStateV1::Blocked
        }
        GuideStage::Verify if !capability.verification.required => {
            GuideContractStateV1::NotApplicable
        }
        GuideStage::Rectify
            if !capability.rollback_contract_declared()
                || !capability.rollback_contract_supported() =>
        {
            GuideContractStateV1::Blocked
        }
        GuideStage::CloseWithEvidence if capability.mutating && !contract_ready => {
            GuideContractStateV1::Blocked
        }
        _ => GuideContractStateV1::Available,
    }
}

pub(super) fn guide_live_read_summary(
    stage: cfctl_core::GuideStage,
    live_reads: &[GuideLiveRead],
) -> Option<&'static str> {
    use cfctl_core::GuideStage;

    match stage {
        GuideStage::SelectAccount if live_reads.contains(&GuideLiveRead::ZoneAccount) => Some(
            "Read the exact live zone details and require its account ID to match the selected account.",
        ),
        GuideStage::CheckEntitlement if live_reads.contains(&GuideLiveRead::ZoneEntitlement) => {
            Some(
                "Read the exact live zone subscription and evaluate its active plan against the official availability matrix.",
            )
        }
        GuideStage::CheckEntitlement
            if live_reads.contains(&GuideLiveRead::ProductEntitlementProbe) =>
        {
            Some(
                "Run the declared read-only product capability. A successful response proves present API access; a rejection remains ambiguous between token permission, plan entitlement, and account configuration.",
            )
        }
        GuideStage::InspectCurrentState
            if live_reads.contains(&GuideLiveRead::GlobalWarpOverrideState) =>
        {
            Some(
                "Read and bind the exact live account-wide disconnect state; execution repeats this read and rejects drift before crossing the mutation boundary.",
            )
        }
        GuideStage::InspectCurrentState
            if live_reads.contains(&GuideLiveRead::D1ReadReplicationState) =>
        {
            Some(
                "Read and bind the exact live database read-replication mode; execution repeats this read and rejects drift before crossing the mutation boundary.",
            )
        }
        GuideStage::InspectCurrentState
            if live_reads.contains(&GuideLiveRead::CloudflareTunnelConfigurationState) =>
        {
            Some(
                "Read and bind the exact live remotely managed Tunnel routing configuration; execution repeats this read and rejects drift before replacing any ingress rule.",
            )
        }
        GuideStage::InspectCurrentState
            if live_reads.contains(&GuideLiveRead::WarpConnectorConfigurationState) =>
        {
            Some(
                "Read and bind the exact live WARP Connector high-availability mode and provider configuration; execution repeats this read and rejects drift before changing Cloudflare Mesh failover behavior.",
            )
        }
        GuideStage::InspectCurrentState
            if live_reads.contains(&GuideLiveRead::WebAnalyticsRumState) =>
        {
            Some(
                "Read and bind the exact live editable Web Analytics RUM on/off value; execution repeats this read and rejects manual state or drift before changing zone-wide data collection.",
            )
        }
        GuideStage::InspectCurrentState if live_reads.contains(&GuideLiveRead::DnsRecordState) => {
            Some(
                "Read and bind the exact live writable DNS record state; execution repeats this read and rejects drift before crossing the mutation boundary.",
            )
        }
        GuideStage::InspectCurrentState
            if live_reads.contains(&GuideLiveRead::WorkerCustomDomainState) =>
        {
            Some(
                "Read and bind the active zone and exact Worker settings, then require the hostname to be absent from both Worker custom domains and DNS records; execution repeats all four reads and rejects drift before attachment.",
            )
        }
        _ => None,
    }
}

pub(super) fn guide_stage_uses_live_read(
    stage: cfctl_core::GuideStage,
    live_reads: &[GuideLiveRead],
) -> bool {
    use cfctl_core::GuideStage;

    match stage {
        GuideStage::SelectAccount => live_reads.contains(&GuideLiveRead::ZoneAccount),
        GuideStage::CheckEntitlement => {
            live_reads.contains(&GuideLiveRead::ZoneEntitlement)
                || live_reads.contains(&GuideLiveRead::ProductEntitlementProbe)
        }
        GuideStage::InspectCurrentState => live_reads.iter().any(|read| {
            matches!(
                read,
                GuideLiveRead::GlobalWarpOverrideState
                    | GuideLiveRead::D1ReadReplicationState
                    | GuideLiveRead::CloudflareTunnelConfigurationState
                    | GuideLiveRead::WarpConnectorConfigurationState
                    | GuideLiveRead::WebAnalyticsRumState
                    | GuideLiveRead::DnsRecordState
                    | GuideLiveRead::WorkerCustomDomainState
            )
        }),
        _ => false,
    }
}

pub(super) fn guide_stage_document(
    number: usize,
    stage: cfctl_core::GuideStage,
    capability: &CapabilityV1,
    contract_ready: bool,
    blocking_gaps: &[String],
    call_argv: Option<&[String]>,
) -> CapabilityGuideStageV1 {
    let live_reads = guide_live_reads(capability);
    let contract_state = guide_stage_contract_state(
        stage,
        capability,
        contract_ready,
        blocking_gaps,
        &live_reads,
    );
    let summary = guide_live_read_summary(stage, &live_reads)
        .unwrap_or_else(|| guide_stage_summary(stage, capability));
    let evidence_class = if capability.workflow.is_some() {
        if matches!(
            stage,
            cfctl_core::GuideStage::Discover | cfctl_core::GuideStage::LoadStandards
        ) {
            EvidenceClass::SourceConfig
        } else {
            EvidenceClass::AgentAction
        }
    } else if guide_stage_uses_live_read(stage, &live_reads) {
        EvidenceClass::LiveRead
    } else {
        guide_stage_evidence_class(stage, capability.mutating)
    };
    CapabilityGuideStageV1 {
        stage: number,
        name: stage,
        capability_id: capability.id.clone(),
        required: stage_required(stage, capability),
        contract_state,
        summary: summary.to_owned(),
        evidence_class,
        commands: guide_stage_commands(stage, capability, contract_state, call_argv),
    }
}

pub(super) fn guide_stage_summary(
    stage: cfctl_core::GuideStage,
    capability: &CapabilityV1,
) -> &'static str {
    use cfctl_core::GuideStage;

    if capability.workflow.is_some() {
        return match stage {
            GuideStage::Discover => {
                "Inspect the workflow outcome, component graph, selector handoffs, and component approval boundaries."
            }
            GuideStage::InspectCurrentState => {
                "Preview the workflow against the local operational-proof index; no Cloudflare boundary is crossed."
            }
            GuideStage::LoadStandards => {
                "Load current official product documentation for the workflow's component capabilities."
            }
            GuideStage::Execute => {
                "Generate the workflow preview and exact component commands. Run bounded reads individually; mutations remain separate plans."
            }
            GuideStage::CloseWithEvidence => {
                "Use the preview receipt and any exported receipt-only manifest without treating artifact presence as verification."
            }
            _ => "This generic capability stage does not apply to a preview-only native workflow.",
        };
    }

    let mutating = capability.mutating;

    match stage {
        GuideStage::Discover => {
            "Inspect the catalog contract and adapter classification selected for this capability."
        }
        GuideStage::Authenticate => {
            "Confirm that the selected profile has a usable credential without exposing its value."
        }
        GuideStage::SelectAccount => {
            "Reconcile the explicit account, profile pin, and registered workspace pin; ambiguity fails closed."
        }
        GuideStage::CheckEntitlement => {
            "Inspect the official plan matrix. When live resolution is required, catalog metadata alone does not prove the selected account's entitlement."
        }
        GuideStage::InspectCurrentState if mutating => {
            "Audit registered-workspace state before deriving impact; use an operation-specific Cloudflare read or verifier rather than infer live state from local configuration."
        }
        GuideStage::InspectCurrentState => {
            "Run the capability as a redacted live read to inspect current Cloudflare state."
        }
        GuideStage::LoadStandards => {
            "Load current official product documentation and changelog context."
        }
        GuideStage::MapDependencies => {
            "Map exact local IaC references and affected registered repositories."
        }
        GuideStage::CalculateCost => {
            "Use the bound cost model and official pricing references; unknown or unbounded cost remains blocked."
        }
        GuideStage::BuildPlan => {
            "Create a hash-bound preview plan from the exact selectors, request body, workspace impact, and safety contracts."
        }
        GuideStage::RequestApproval => {
            "Review the plan, then bind approval and any cost ceiling to its exact operation ID."
        }
        GuideStage::AcquireLocks => {
            "Revalidate catalog, account, request, and workspace hashes before acquiring execution locks."
        }
        GuideStage::Execute if mutating => {
            "Cross the Cloudflare write boundary only through the exact durable operation ID."
        }
        GuideStage::Execute => {
            "Perform the redacted live read through the catalog-selected adapter."
        }
        GuideStage::Verify
            if capability.verification.strategy == "sink_write_and_source_response_status" =>
        {
            "Treat Cloudflare success plus the durable sink-only secret receipt as the terminal verification; no readback can prove the new credential value."
        }
        GuideStage::Verify => {
            "Require operation-specific post-change verification before declaring success."
        }
        GuideStage::Rectify => {
            "Use only the declared compensation contract and hash-bound boundary receipts."
        }
        GuideStage::CloseWithEvidence => {
            "Close only with final durable status and content-addressed evidence."
        }
    }
}

pub(super) fn guide_stage_evidence_class(
    stage: cfctl_core::GuideStage,
    mutating: bool,
) -> EvidenceClass {
    use cfctl_core::GuideStage;

    match stage {
        GuideStage::Discover
        | GuideStage::CheckEntitlement
        | GuideStage::LoadStandards
        | GuideStage::MapDependencies
        | GuideStage::CalculateCost => EvidenceClass::SourceConfig,
        GuideStage::InspectCurrentState | GuideStage::Execute if !mutating => {
            EvidenceClass::LiveRead
        }
        GuideStage::Authenticate
        | GuideStage::SelectAccount
        | GuideStage::InspectCurrentState
        | GuideStage::AcquireLocks
        | GuideStage::CloseWithEvidence => EvidenceClass::LocalProof,
        GuideStage::BuildPlan | GuideStage::RequestApproval => EvidenceClass::Preview,
        GuideStage::Execute | GuideStage::Rectify => EvidenceClass::Apply,
        GuideStage::Verify => EvidenceClass::PostChangeVerification,
    }
}

pub(super) fn operation_specific_current_state_command(
    capability: &CapabilityV1,
) -> Option<Vec<String>> {
    if worker_custom_domain::should_bind_state(capability) {
        return Some(worker_custom_domain::current_state_command());
    }
    if should_bind_global_warp_override_state(capability) {
        return Some(vec![
            "cfctl".to_owned(),
            "call".to_owned(),
            GLOBAL_WARP_OVERRIDE_READ_CAPABILITY_ID.to_owned(),
            "--selector".to_owned(),
            "account_id=<account_id>".to_owned(),
            "--json".to_owned(),
        ]);
    }
    if should_bind_d1_read_replication_state(capability) {
        return Some(vec![
            "cfctl".to_owned(),
            "call".to_owned(),
            D1_READ_REPLICATION_READ_CAPABILITY_ID.to_owned(),
            "--selector".to_owned(),
            "account_id=<account_id>".to_owned(),
            "--selector".to_owned(),
            "database_id=<database_id>".to_owned(),
            "--json".to_owned(),
        ]);
    }
    if should_bind_cloudflare_tunnel_configuration_state(capability) {
        return Some(vec![
            "cfctl".to_owned(),
            "call".to_owned(),
            CLOUDFLARE_TUNNEL_CONFIGURATION_READ_CAPABILITY_ID.to_owned(),
            "--selector".to_owned(),
            "account_id=<account_id>".to_owned(),
            "--selector".to_owned(),
            "tunnel_id=<tunnel_id>".to_owned(),
            "--json".to_owned(),
        ]);
    }
    if should_bind_warp_connector_configuration_state(capability) {
        return Some(vec![
            "cfctl".to_owned(),
            "call".to_owned(),
            WARP_CONNECTOR_CONFIGURATION_READ_CAPABILITY_ID.to_owned(),
            "--selector".to_owned(),
            "account_id=<account_id>".to_owned(),
            "--selector".to_owned(),
            "tunnel_id=<tunnel_id>".to_owned(),
            "--json".to_owned(),
        ]);
    }
    if should_bind_web_analytics_rum_state(capability) {
        return Some(vec![
            "cfctl".to_owned(),
            "call".to_owned(),
            WEB_ANALYTICS_RUM_READ_CAPABILITY_ID.to_owned(),
            "--selector".to_owned(),
            "zone_id=<zone_id>".to_owned(),
            "--json".to_owned(),
        ]);
    }
    if should_bind_dns_record_state(capability) {
        return Some(vec![
            "cfctl".to_owned(),
            "call".to_owned(),
            DNS_RECORD_DETAIL_READ_CAPABILITY_ID.to_owned(),
            "--selector".to_owned(),
            "zone_id=<zone_id>".to_owned(),
            "--selector".to_owned(),
            "dns_record_id=<dns_record_id>".to_owned(),
            "--json".to_owned(),
        ]);
    }
    (should_bind_oauth_client_secret_state(capability)
        || should_bind_oauth_client_update_state(capability))
    .then(|| {
        vec![
            "cfctl".to_owned(),
            "call".to_owned(),
            OAUTH_CLIENT_DETAIL_READ_CAPABILITY_ID.to_owned(),
            "--selector".to_owned(),
            "account_id=<account_id>".to_owned(),
            "--selector".to_owned(),
            "oauth_client_id=<oauth_client_id>".to_owned(),
            "--json".to_owned(),
        ]
    })
}

pub(super) fn guide_stage_commands(
    stage: cfctl_core::GuideStage,
    capability: &CapabilityV1,
    contract_state: GuideContractStateV1,
    call_argv: Option<&[String]>,
) -> Vec<Vec<String>> {
    use cfctl_core::GuideStage;

    let available = contract_state == GuideContractStateV1::Available;
    let conditional =
        |command: Option<Vec<String>>| available.then_some(command).flatten().into_iter().collect();
    if capability.workflow.is_some() {
        return match stage {
            GuideStage::Discover => vec![catalog_show_argv(&capability.id)],
            GuideStage::InspectCurrentState | GuideStage::Execute => {
                conditional(call_argv.map(<[String]>::to_vec))
            }
            GuideStage::LoadStandards => vec![vec![
                "cfctl".to_owned(),
                "docs".to_owned(),
                "search".to_owned(),
                capability.product.clone(),
                "--json".to_owned(),
            ]],
            _ => Vec::new(),
        };
    }
    match stage {
        GuideStage::SelectAccount | GuideStage::CheckEntitlement
            if contract_state == GuideContractStateV1::LiveReadRequired =>
        {
            call_argv.map(<[String]>::to_vec).into_iter().collect()
        }
        GuideStage::Discover | GuideStage::CheckEntitlement | GuideStage::CalculateCost => {
            vec![catalog_show_argv(&capability.id)]
        }
        GuideStage::Authenticate => vec![argv(&["cfctl", "auth", "status", "default", "--json"])],
        GuideStage::SelectAccount => vec![
            argv(&["cfctl", "auth", "profiles", "--json"]),
            argv(&["cfctl", "workspace", "graph", "--json"]),
        ],
        GuideStage::InspectCurrentState if !capability.mutating => {
            conditional(call_argv.map(<[String]>::to_vec))
        }
        GuideStage::InspectCurrentState => operation_specific_current_state_command(capability)
            .map_or_else(
                || vec![argv(&["cfctl", "workspace", "audit", "--json"])],
                |command| vec![command],
            ),
        GuideStage::LoadStandards => vec![vec![
            "cfctl".to_owned(),
            "docs".to_owned(),
            "search".to_owned(),
            capability.product.clone(),
            "--json".to_owned(),
        ]],
        GuideStage::MapDependencies => {
            vec![argv(&["cfctl", "workspace", "graph", "--json"])]
        }
        GuideStage::RequestApproval => {
            conditional(Some(approval_command_argv(capability, "<operation-id>")))
        }
        GuideStage::AcquireLocks => conditional(Some(argv(&[
            "cfctl",
            "plans",
            "show",
            "<operation-id>",
            "--json",
        ]))),
        GuideStage::Execute if capability.mutating => conditional(Some(argv(&[
            "cfctl",
            "plans",
            "run",
            "<operation-id>",
            "--json",
        ]))),
        GuideStage::BuildPlan | GuideStage::Execute => {
            conditional(call_argv.map(<[String]>::to_vec))
        }
        GuideStage::Verify => conditional(Some(argv(&[
            "cfctl",
            "plans",
            "status",
            "<operation-id>",
            "--json",
        ]))),
        GuideStage::Rectify => conditional(Some(argv(&[
            "cfctl",
            "plans",
            "rectify",
            "<operation-id>",
            "--json",
        ]))),
        GuideStage::CloseWithEvidence if capability.mutating => conditional(Some(argv(&[
            "cfctl",
            "plans",
            "status",
            "<operation-id>",
            "--json",
        ]))),
        GuideStage::CloseWithEvidence => Vec::new(),
    }
}

pub(super) fn approval_command_argv(capability: &CapabilityV1, operation_id: &str) -> Vec<String> {
    let mut command = ["cfctl", "plans", "approve"].map(str::to_owned).to_vec();
    command.extend([operation_id.to_owned(), "--yes".to_owned()]);
    if capability.cost.incremental
        && capability.cost.known
        && let (Some(currency), Some(maximum)) =
            (&capability.cost.currency, capability.cost.maximum)
    {
        command.extend([
            "--max-cost".to_owned(),
            format!("{}:{maximum}", currency.to_ascii_uppercase()),
        ]);
    }
    command.push("--json".to_owned());
    command
}

pub(super) fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

pub(super) fn catalog_show_argv(capability_id: &str) -> Vec<String> {
    vec![
        "cfctl".to_owned(),
        "catalog".to_owned(),
        "show".to_owned(),
        capability_id.to_owned(),
        "--json".to_owned(),
    ]
}
