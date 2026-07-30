//! Investigation-first telemetry orchestration.
//!
//! This module owns the product slice that joins catalog contracts, durable
//! operational proof, workflow previews, and coverage. It deliberately does
//! not own HTTP execution or mutation authority; those remain behind the
//! existing runtime and plan lifecycle boundaries.

use std::collections::{BTreeMap, BTreeSet};

use cfctl_catalog::CatalogSnapshot;
use cfctl_cloudflare::CallInput;
use cfctl_core::{
    AdapterStatus, CapabilityV1, D1FullExportGovernedExecutionBindingV1, EvidenceClass,
    Mln0142GovernedExecutionBindingV1, Mln0143GovernedExecutionBindingV1,
    OperationalProofFreshnessV1, OperationalProofOutcomeV1, OperationalProofScopeV1,
    OperationalProofV1, PlanStatus, PlanV1, ResultEnvelopeV2, TransactionStageV1,
    VerificationState, hash_value,
};
use cfctl_storage::{OperationalProofPageV1, StateStore};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::profiles::ProfilesConfig;
use crate::runtime::{
    CliError, Result, capability_call_argv, capability_has_meaningful_request_body,
    required_selectors_json, verification_for_status,
};

pub(crate) const OPERATIONAL_PROOF_PROJECTION_LIMIT: usize = 512;

pub(crate) fn operational_proof_coverage(
    store: &StateStore,
    catalog: &CatalogSnapshot,
) -> Result<Value> {
    let proof_page = store.list_recent_operational_proofs(OPERATIONAL_PROOF_PROJECTION_LIMIT)?;
    let proofs = &proof_page.proofs;
    let profiles = ProfilesConfig::load(store)?;
    let targeted_mutations = catalog
        .coverage()
        .telemetry_ledger
        .into_iter()
        .filter(|entry| entry.operation_kind == "mutation")
        .filter_map(|entry| entry.capability_id)
        .collect::<BTreeSet<_>>();
    let mutation_plans = store
        .list_plans()?
        .into_iter()
        .filter(|plan| targeted_mutations.contains(&plan.capability.id))
        .collect::<Vec<_>>();
    let mut latest = BTreeMap::<String, &OperationalProofV1>::new();
    for proof in proofs {
        let key = format!(
            "{}\u{0}{}\u{0}{}\u{0}{}\u{0}{}",
            proof.capability_id,
            proof.profile_id.as_deref().unwrap_or("unscoped"),
            proof.account_id.as_deref().unwrap_or("unscoped"),
            proof
                .credential_generation_id
                .as_deref()
                .unwrap_or("unbound"),
            proof.input_hash
        );
        latest
            .entry(key)
            .and_modify(|current| {
                if proof.observed_at > current.observed_at {
                    *current = proof;
                }
            })
            .or_insert(proof);
    }
    let latest_rows = latest
        .values()
        .map(|proof| {
            json!({
                "capability_id": proof.capability_id,
                "account_id": proof.account_id,
                "profile_id": proof.profile_id,
                "credential_generation_id": proof.credential_generation_id,
                "credential_generation_current": credential_generation_current(proof, &profiles),
                "input_hash": proof.input_hash,
                "catalog_hash": proof.catalog_hash,
                "catalog_current": proof.catalog_hash == catalog.schema_hash,
                "outcome": proof.outcome,
                "observed_at": proof.observed_at,
                "evidence": proof.evidence,
            })
        })
        .collect::<Vec<_>>();
    let current_catalog_successes = proofs
        .iter()
        .filter(|proof| {
            proof.catalog_hash == catalog.schema_hash
                && credential_generation_current(proof, &profiles)
                && proof.outcome == OperationalProofOutcomeV1::Succeeded
        })
        .count();
    let current_catalog_failures = proofs
        .iter()
        .filter(|proof| {
            proof.catalog_hash == catalog.schema_hash
                && credential_generation_current(proof, &profiles)
                && proof.outcome == OperationalProofOutcomeV1::Failed
        })
        .count();
    let mutation_lifecycle = mutation_lifecycle_coverage(&mutation_plans, catalog);
    Ok(json!({
        "source": "local_redacted_evidence_index",
        "proof_projection": operational_proof_projection_json(&proof_page),
        "proof_count": proofs.len(),
        "latest_scoped_observations": latest_rows,
        "current_catalog_successes": current_catalog_successes,
        "current_catalog_failures": current_catalog_failures,
        "catalog_drifted_observations": proofs.iter().filter(|proof| proof.catalog_hash != catalog.schema_hash).count(),
        "credential_drifted_observations": proofs.iter().filter(|proof| proof.credential_generation_id.is_some() && !credential_generation_current(proof, &profiles)).count(),
        "credential_unbound_observations": proofs.iter().filter(|proof| proof.credential_generation_id.is_none()).count(),
        "mutation_lifecycle": mutation_lifecycle,
        "freshness_policy": "evaluated by each workflow; catalog coverage never invents a universal freshness window",
        "boundary": "A recorded successful read proves that exact bounded call crossed the Cloudflare read boundary. It does not prove dataset completeness, current freshness for every workflow, or mutation readiness."
    }))
}

fn current_credential_generation<'a>(
    proof: &OperationalProofV1,
    profiles: &'a ProfilesConfig,
) -> Option<&'a str> {
    proof
        .profile_id
        .as_deref()
        .and_then(|profile_id| profiles.profiles.get(profile_id))
        .and_then(|profile| profile.credential_generation_id.as_deref())
}

fn credential_generation_current(proof: &OperationalProofV1, profiles: &ProfilesConfig) -> bool {
    proof.credential_generation_id.as_deref() == current_credential_generation(proof, profiles)
        && proof.credential_generation_id.is_some()
}

fn mutation_lifecycle_coverage(plans: &[PlanV1], catalog: &CatalogSnapshot) -> Value {
    let observations = plans
        .iter()
        .map(|plan| {
            json!({
                "operation_id": plan.operation_id,
                "capability_id": plan.capability.id,
                "account_id": plan.account_id,
                "catalog_hash": plan.catalog_hash,
                "catalog_current": plan.catalog_hash == catalog.schema_hash,
                "status": plan.status,
                "transaction_stage": plan.transaction_stage,
                "verification": verification_for_status(plan.status),
                "created_at": plan.created_at,
                "expires_at": plan.expires_at,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "observations": observations,
        "verified": plans.iter().filter(|plan| plan.status == PlanStatus::Verified).count(),
        "rectified": plans.iter().filter(|plan| plan.status == PlanStatus::Rectified).count(),
        "uncertain": plans.iter().filter(|plan| plan.status == PlanStatus::RectificationRequired).count(),
        "boundary": "A stored plan lifecycle is operational evidence for that exact operation. It is not automatically a disposable canary, standing authority, or proof that every mutation in the family has been drilled."
    })
}

pub(crate) fn operational_proof_projection_json(page: &OperationalProofPageV1) -> Value {
    json!({
        "retained_count": page.proofs.len(),
        "total_index_rows": page.total_count,
        "limit": OPERATIONAL_PROOF_PROJECTION_LIMIT,
        "truncated": page.truncated,
        "boundary": "Counts and observations cover only the bounded most-recently-indexed projection when truncated is true."
    })
}

#[expect(
    clippy::too_many_lines,
    reason = "proof recording validates and binds one complete governed execution"
)]
pub(crate) fn record_operational_proof(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    credential_generation_id: Option<&str>,
    envelope: &ResultEnvelopeV2,
) -> Result<()> {
    if !envelope.performed || capability.workflow.is_some() {
        return Ok(());
    }
    let evidence = envelope
        .evidence
        .iter()
        .find(|evidence| evidence.class == EvidenceClass::LiveRead)
        .cloned()
        .ok_or_else(|| {
            CliError::Input(format!(
                "performed read `{}` did not produce live-read evidence and cannot enter the operational proof index",
                capability.id
            ))
        })?;
    let input_hash = hash_value(&serde_json::to_value(input)?)?;
    let mut proof = OperationalProofV1::new(
        envelope.generated_at,
        &capability.id,
        &catalog.schema_hash,
        &input_hash,
        OperationalProofScopeV1::new(
            envelope.profile_id.as_deref(),
            envelope.account_id.as_deref(),
            credential_generation_id,
        ),
        if envelope.ok {
            OperationalProofOutcomeV1::Succeeded
        } else {
            OperationalProofOutcomeV1::Failed
        },
        evidence,
    );
    if capability.d1_full_export.is_some() {
        let account_id = input
            .selectors
            .get("account_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CliError::Input("D1 full export omitted its account selector".to_owned())
            })?;
        let database_id = input
            .selectors
            .get("database_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CliError::Input("D1 full export omitted its database selector".to_owned())
            })?;
        let output_sha256 = envelope
            .result
            .pointer("/output_file/sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CliError::Input("D1 full export omitted the verified output hash".to_owned())
            })?;
        let at_bookmark = envelope
            .result
            .pointer("/provider/at_bookmark")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                CliError::Input("D1 full export omitted its captured provider bookmark".to_owned())
            })?;
        if !envelope.ok
            || envelope
                .result
                .pointer("/output_file/complete")
                .and_then(Value::as_bool)
                != Some(true)
            || envelope
                .result
                .pointer("/output_file/hash_matches")
                .and_then(Value::as_bool)
                != Some(true)
            || envelope.account_id.as_deref() != Some(account_id)
        {
            return Err(CliError::Input(
                "D1 full export is not a completed same-file verified snapshot".to_owned(),
            ));
        }
        let profile_id = envelope.profile_id.as_deref().ok_or_else(|| {
            CliError::Input("D1 full export proof requires a profile identity".to_owned())
        })?;
        let credential_generation_id = credential_generation_id.ok_or_else(|| {
            CliError::Input("D1 full export proof requires a credential generation".to_owned())
        })?;
        proof.bind_d1_full_export_governed_execution(D1FullExportGovernedExecutionBindingV1 {
            schema_version: 1,
            operation_id: Uuid::new_v4().to_string(),
            capability_id: capability.id.clone(),
            catalog_hash: catalog.schema_hash.clone(),
            target_scope_hash: hash_value(&json!({
                "account_id": account_id,
                "database_id": database_id,
            }))?,
            output_file_sha256: output_sha256.to_owned(),
            at_bookmark_hash: hash_value(&Value::String(at_bookmark.to_owned()))?,
            manifest_evidence_hash: proof.evidence.content_hash.clone(),
            request_hash: input_hash.clone(),
            profile_id: profile_id.to_owned(),
            credential_generation_id: credential_generation_id.to_owned(),
            completion_status: "completed".to_owned(),
            completed_at: envelope.generated_at,
        })?;
    }
    if let Some(contract) = capability.mln_0143_data_invariants.as_ref() {
        let manifest = envelope.result.get("result").unwrap_or(&envelope.result);
        let phase = input
            .body
            .as_ref()
            .and_then(|body| body.get("phase"))
            .and_then(Value::as_str)
            .ok_or_else(|| CliError::Input("MLN 0143 runtime phase is missing".to_owned()))?;
        let target_scope_hash = hash_value(&json!({
            "account_id": contract.account_id,
            "database_id": contract.database_id,
        }))?;
        if !envelope.ok
            || manifest.get("complete").and_then(Value::as_bool) != Some(true)
            || manifest.get("capability_id").and_then(Value::as_str) != Some(capability.id.as_str())
            || manifest.get("capability_version").and_then(Value::as_u64)
                != Some(u64::from(contract.capability_version))
            || manifest
                .get("validator_contract_hash")
                .and_then(Value::as_str)
                != Some(contract.validator_contract_hash.as_str())
            || manifest.get("phase").and_then(Value::as_str) != Some(phase)
            || manifest.get("target_scope_hash").and_then(Value::as_str)
                != Some(target_scope_hash.as_str())
            || manifest.pointer("/query/sha256").and_then(Value::as_str)
                != Some(contract.fixed_query_sha256.as_str())
            || manifest
                .pointer("/query/bounds_saturated")
                .and_then(Value::as_bool)
                != Some(false)
        {
            return Err(CliError::Input(
                "MLN 0143 runtime result is not a completed validated manifest".to_owned(),
            ));
        }
        let profile_id = envelope.profile_id.as_deref().ok_or_else(|| {
            CliError::Input("MLN 0143 runtime proof requires a profile identity".to_owned())
        })?;
        let credential_generation_id = credential_generation_id.ok_or_else(|| {
            CliError::Input("MLN 0143 runtime proof requires a credential generation".to_owned())
        })?;
        proof.bind_mln_0143_governed_execution(Mln0143GovernedExecutionBindingV1 {
            schema_version: 1,
            operation_id: Uuid::new_v4().to_string(),
            capability_id: capability.id.clone(),
            capability_version: contract.capability_version,
            validator_contract_hash: contract.validator_contract_hash.clone(),
            fixed_query_sha256: contract.fixed_query_sha256.clone(),
            catalog_hash: catalog.schema_hash.clone(),
            target_scope_hash,
            phase: phase.to_owned(),
            manifest_evidence_hash: proof.evidence.content_hash.clone(),
            request_hash: input_hash.clone(),
            profile_identity_hash: hash_value(&json!({
                "profile_id": profile_id,
                "credential_generation_id": credential_generation_id,
            }))?,
            credential_generation_id: credential_generation_id.to_owned(),
            completion_status: "completed".to_owned(),
            completed_at: envelope.generated_at,
            cross_operation_lineage_hash: (phase != "pre_import")
                .then(|| {
                    manifest
                        .get("lineage")
                        .ok_or_else(|| {
                            CliError::Input(
                                "MLN post-phase manifest omitted cross-operation lineage"
                                    .to_owned(),
                            )
                        })
                        .and_then(|lineage| hash_value(lineage).map_err(CliError::from))
                })
                .transpose()?,
        })?;
    }
    if let Some(contract) = capability.mln_0142_post_import_schema.as_ref() {
        let body = input
            .body
            .as_ref()
            .and_then(Value::as_object)
            .ok_or_else(|| CliError::Input("MLN 0142 proof body is missing".to_owned()))?;
        let field = |name: &str| {
            body.get(name)
                .and_then(Value::as_str)
                .ok_or_else(|| CliError::Input(format!("MLN 0142 proof requires `{name}`")))
        };
        let present = envelope
            .result
            .pointer("/result/0/results/0/present")
            .is_some_and(|value| value == &Value::Bool(true) || value.as_u64() == Some(1));
        let receipt = envelope
            .result
            .pointer("/result_info/query/mln_0142")
            .ok_or_else(|| CliError::Input("MLN 0142 runtime receipt is missing".to_owned()))?;
        if !envelope.ok
            || !present
            || receipt.get("import_operation_id").and_then(Value::as_str)
                != Some(field("import_operation_id")?)
            || receipt
                .get("import_boundary_evidence_hash")
                .and_then(Value::as_str)
                != Some(field("import_boundary_evidence_hash")?)
            || receipt.get("trigger_name").and_then(Value::as_str)
                != Some(contract.trigger_name.as_str())
            || receipt
                .get("trigger_definition_sha256")
                .and_then(Value::as_str)
                != Some(contract.trigger_definition_sha256.as_str())
        {
            return Err(CliError::Input(
                "MLN 0142 runtime result is not the exact completed trigger proof".to_owned(),
            ));
        }
        let credential_generation_id = credential_generation_id.ok_or_else(|| {
            CliError::Input("MLN 0142 runtime proof requires a credential generation".to_owned())
        })?;
        proof.bind_mln_0142_governed_execution(Mln0142GovernedExecutionBindingV1 {
            schema_version: 1,
            operation_id: Uuid::new_v4().to_string(),
            capability_id: capability.id.clone(),
            capability_version: contract.capability_version,
            catalog_hash: catalog.schema_hash.clone(),
            target_scope_hash: hash_value(&json!({
                "account_id":contract.account_id,
                "database_id":contract.database_id,
            }))?,
            import_operation_id: field("import_operation_id")?.to_owned(),
            import_boundary_evidence_hash: field("import_boundary_evidence_hash")?.to_owned(),
            import_source_sha256: field("import_source_sha256")?.to_owned(),
            import_plan_hash: field("import_plan_hash")?.to_owned(),
            final_bookmark_hash: field("final_bookmark_hash")?.to_owned(),
            trigger_name: contract.trigger_name.clone(),
            trigger_definition_sha256: contract.trigger_definition_sha256.clone(),
            manifest_evidence_hash: proof.evidence.content_hash.clone(),
            request_hash: input_hash,
            credential_generation_id: credential_generation_id.to_owned(),
            completion_status: "completed".to_owned(),
            completed_at: envelope.generated_at,
        })?;
    }
    store.record_operational_proof(&proof)?;
    Ok(())
}

pub(crate) fn execute_native_workflow(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
) -> Result<ResultEnvelopeV2> {
    let workflow = capability.workflow.as_ref().ok_or_else(|| {
        CliError::Input("native workflow capability is missing its recipe".to_owned())
    })?;
    let proof_page = store.list_recent_operational_proofs(OPERATIONAL_PROOF_PROJECTION_LIMIT)?;
    let proofs = &proof_page.proofs;
    let profiles = ProfilesConfig::load(store)?;
    let now = Utc::now();
    let steps = workflow
        .steps
        .iter()
        .map(|step| {
            workflow_step_preview(
                catalog,
                step,
                proofs,
                &profiles,
                now,
                workflow.proof_freshness_seconds,
                &mut BTreeSet::new(),
            )
        })
        .collect::<Vec<_>>();
    let mut receipt = json!({
        "kind": "workflow_preview_v1",
        "workflow_id": capability.id,
        "catalog_hash": catalog.schema_hash,
        "purpose": workflow.purpose,
        "preserves_component_approval": workflow.preserves_component_approval,
        "exports_evidence_packet": workflow.exports_evidence_packet,
        "proof_freshness_seconds": workflow.proof_freshness_seconds,
        "freshness_boundary": "Freshness is evaluated against this workflow policy and current catalog hash. It does not prove upstream retention, sampling completeness, or mutation readiness.",
        "performed": false,
        "cloudflare_boundary_crossed": false,
        "proof_projection": operational_proof_projection_json(&proof_page),
        "steps": steps,
        "next_action": "Run only components with `available:true` and a non-null `call_argv`. Resolve every blocking gap through the component guide first. Every mutating component remains a separate hash-bound plan that must be approved, run, and verified through its own operation ID."
    });
    if workflow.exports_evidence_packet {
        let plans = store.list_plans()?;
        receipt["evidence_packet"] = workflow_evidence_packet(
            catalog,
            capability,
            &proof_page,
            &plans,
            &profiles,
            now,
            workflow.proof_freshness_seconds,
        );
    }
    let evidence = store.write_evidence(EvidenceClass::AgentAction, &receipt)?;
    let mut envelope = ResultEnvelopeV2::success("call", receipt).with_evidence(evidence);
    envelope.capability_id = Some(capability.id.clone());
    envelope.performed = false;
    envelope.verification.state = VerificationState::NotApplicable;
    envelope.verification.basis = Some(
        "native workflow composition only; no Cloudflare boundary or mutation was crossed"
            .to_owned(),
    );
    Ok(envelope)
}

fn workflow_step_preview(
    catalog: &CatalogSnapshot,
    step: &cfctl_core::WorkflowStepV1,
    proofs: &[OperationalProofV1],
    profiles: &ProfilesConfig,
    now: DateTime<Utc>,
    proof_freshness_seconds: u64,
    ancestors: &mut BTreeSet<String>,
) -> Value {
    let Some(component) = catalog.get(&step.capability_id) else {
        return json!({
            "id": step.id,
            "capability_id": step.capability_id,
            "purpose": step.purpose,
            "mutating": step.mutating,
            "depends_on": step.depends_on,
            "available": false,
            "call_argv": Value::Null,
            "guide_argv": ["cfctl", "guide", step.capability_id, "--json"],
            "proof": {"state": OperationalProofFreshnessV1::NotRecorded},
            "blocking_gaps": ["component is absent from the current catalog"]
        });
    };
    let contract_gaps = component.mutation_contract_gaps();
    let mut blocking_gaps = Vec::new();
    if let Some(reason) = component
        .blocked_reason
        .as_deref()
        .filter(|_| component.adapter_status == AdapterStatus::Blocked)
    {
        blocking_gaps.push(reason.to_owned());
    }
    if component.mutating {
        blocking_gaps.extend(contract_gaps.iter().cloned());
    }
    let available = component.adapter_status != AdapterStatus::Blocked && blocking_gaps.is_empty();
    let call_argv = available.then(|| capability_call_argv(component));
    let mut preview = json!({
        "id": step.id,
        "capability_id": step.capability_id,
        "purpose": step.purpose,
        "mutating": step.mutating,
        "depends_on": step.depends_on,
        "available": available,
        "adapter_status": component.adapter_status,
        "blocked_reason": component.blocked_reason,
        "contract_gaps": contract_gaps,
        "blocking_gaps": blocking_gaps,
        "required_selectors": required_selectors_json(component),
        "needs_request_body": capability_has_meaningful_request_body(component),
        "call_argv": call_argv,
        "guide_argv": ["cfctl", "guide", component.id, "--json"],
        "approval_boundary": if component.mutating {
            "Calling this component creates a plan only; approval, run, and verification remain separate."
        } else {
            "This component is a bounded read."
        },
        "proof": workflow_component_proof(
            proofs,
            profiles,
            component,
            now,
            &catalog.schema_hash,
            proof_freshness_seconds,
        ),
    });
    if let Some(nested) = component.workflow.as_ref() {
        if !ancestors.insert(component.id.clone()) {
            preview["available"] = json!(false);
            preview["call_argv"] = Value::Null;
            preview["blocking_gaps"] = json!(["workflow composition cycle detected"]);
            return preview;
        }
        preview["nested_steps"] = Value::Array(
            nested
                .steps
                .iter()
                .map(|nested_step| {
                    workflow_step_preview(
                        catalog,
                        nested_step,
                        proofs,
                        profiles,
                        now,
                        proof_freshness_seconds,
                        ancestors,
                    )
                })
                .collect(),
        );
        ancestors.remove(&component.id);
    }
    preview
}

fn workflow_component_proof(
    proofs: &[OperationalProofV1],
    profiles: &ProfilesConfig,
    component: &CapabilityV1,
    now: DateTime<Utc>,
    catalog_hash: &str,
    proof_freshness_seconds: u64,
) -> Value {
    if component.workflow.is_some() || component.mutating {
        return json!({
            "state": OperationalProofFreshnessV1::NotRecorded,
            "reason": if component.mutating {
                "mutation readiness is never inferred from a prior read receipt"
            } else {
                "workflow previews are agent-action evidence, not live-read proof"
            }
        });
    }
    let mut latest = BTreeMap::<String, &OperationalProofV1>::new();
    for proof in proofs
        .iter()
        .filter(|proof| proof.capability_id == component.id)
    {
        let key = format!(
            "{}\u{0}{}\u{0}{}\u{0}{}",
            proof.profile_id.as_deref().unwrap_or("unscoped"),
            proof.account_id.as_deref().unwrap_or("unscoped"),
            proof
                .credential_generation_id
                .as_deref()
                .unwrap_or("unbound"),
            proof.input_hash
        );
        latest
            .entry(key)
            .and_modify(|current| {
                if proof.observed_at > current.observed_at {
                    *current = proof;
                }
            })
            .or_insert(proof);
    }
    if latest.is_empty() {
        return json!({"state": OperationalProofFreshnessV1::NotRecorded});
    }
    let observations = latest
        .values()
        .map(|proof| {
            json!({
                "state": proof.freshness(
                    now,
                    catalog_hash,
                    proof_freshness_seconds,
                    current_credential_generation(proof, profiles),
                ),
                "observed_at": proof.observed_at,
                "account_id": proof.account_id,
                "profile_id": proof.profile_id,
                "credential_generation_id": proof.credential_generation_id,
                "credential_generation_current": credential_generation_current(proof, profiles),
                "input_hash": proof.input_hash,
                "outcome": proof.outcome,
                "evidence": proof.evidence,
            })
        })
        .collect::<Vec<_>>();
    json!({"state": "scoped_observations", "observations": observations})
}

fn workflow_evidence_packet(
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    proof_page: &OperationalProofPageV1,
    plans: &[PlanV1],
    profiles: &ProfilesConfig,
    now: DateTime<Utc>,
    proof_freshness_seconds: u64,
) -> Value {
    let proofs = &proof_page.proofs;
    let mut component_ids = BTreeSet::new();
    let mut ancestors = BTreeSet::new();
    collect_workflow_leaf_capabilities(catalog, capability, &mut component_ids, &mut ancestors);
    let read_receipts = proofs
        .iter()
        .filter(|proof| component_ids.contains(&proof.capability_id))
        .map(|proof| {
            json!({
                "capability_id": proof.capability_id,
                "account_id": proof.account_id,
                "profile_id": proof.profile_id,
                "credential_generation_id": proof.credential_generation_id,
                "credential_generation_current": credential_generation_current(proof, profiles),
                "input_hash": proof.input_hash,
                "catalog_hash": proof.catalog_hash,
                "observed_at": proof.observed_at,
                "outcome": proof.outcome,
                "freshness": proof.freshness(
                    now,
                    &catalog.schema_hash,
                    proof_freshness_seconds,
                    current_credential_generation(proof, profiles),
                ),
                "evidence": proof.evidence,
            })
        })
        .collect::<Vec<_>>();
    let targeted_mutations = catalog
        .coverage()
        .telemetry_ledger
        .into_iter()
        .filter(|entry| entry.operation_kind == "mutation")
        .filter_map(|entry| entry.capability_id)
        .collect::<BTreeSet<_>>();
    let mutation_lifecycle_receipts = plans
        .iter()
        .filter(|plan| targeted_mutations.contains(&plan.capability.id))
        .map(|plan| mutation_lifecycle_receipt(plan, catalog))
        .collect::<Vec<_>>();
    json!({
        "schema_version": 2,
        "generated_at": now,
        "catalog_hash": catalog.schema_hash,
        "workflow_id": capability.id,
        "component_capability_ids": component_ids,
        "proof_projection": operational_proof_projection_json(proof_page),
        "read_receipts": read_receipts,
        "mutation_lifecycle_receipts": mutation_lifecycle_receipts,
        "contains_raw_telemetry": false,
        "contains_plan_inputs": false,
        "contains_transaction_artifacts": false,
        "boundary": "This manifest exports redacted read-receipt identities and mutation lifecycle checkpoint metadata. It never exports plan inputs, targets, transaction artifacts, or raw telemetry. Missing lifecycle classes remain missing evidence; receipt presence is not verification or dataset completeness."
    })
}

fn mutation_lifecycle_receipt(plan: &PlanV1, catalog: &CatalogSnapshot) -> Value {
    let receipt_classes = plan
        .transaction_journal
        .iter()
        .map(|checkpoint| transaction_stage_class(checkpoint.stage))
        .collect::<BTreeSet<_>>();
    let checkpoints = plan
        .transaction_journal
        .iter()
        .map(|checkpoint| {
            json!({
                "stage": checkpoint.stage,
                "receipt_class": transaction_stage_class(checkpoint.stage),
                "recorded_at": checkpoint.recorded_at,
                "plan_content_hash": checkpoint.plan_content_hash,
                "plan_status": checkpoint.plan_status,
                "previous_checkpoint_hash": checkpoint.previous_checkpoint_hash,
                "artifact_hash": checkpoint.artifact_hash,
                "checkpoint_hash": checkpoint.checkpoint_hash,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "operation_id": plan.operation_id,
        "capability_id": plan.capability.id,
        "profile_id": plan.profile_id,
        "account_id": plan.account_id,
        "catalog_hash": plan.catalog_hash,
        "catalog_current": plan.catalog_hash == catalog.schema_hash,
        "created_at": plan.created_at,
        "expires_at": plan.expires_at,
        "cancelled_at": plan.cancelled_at,
        "status": plan.status,
        "verification": verification_for_status(plan.status),
        "content_hash": plan.content_hash,
        "approval": plan.approval.as_ref().map(|approval| json!({
            "approved_at": approval.approved_at,
            "approved_content_hash": approval.approved_content_hash,
            "max_cost": approval.max_cost,
        })),
        "transaction_stage": plan.transaction_stage,
        "receipt_classes": receipt_classes,
        "checkpoints": checkpoints,
    })
}

const fn transaction_stage_class(stage: TransactionStageV1) -> &'static str {
    match stage {
        TransactionStageV1::PlanPrepared => "plan",
        TransactionStageV1::ApprovalPersisted => "approval",
        TransactionStageV1::ConsumptionPersisted => "execution_admission",
        TransactionStageV1::BoundaryAttemptPersisted
        | TransactionStageV1::BoundaryResponsePersisted
        | TransactionStageV1::SecretSinkPersisted => "apply",
        TransactionStageV1::VerificationAttemptPersisted
        | TransactionStageV1::VerificationResponsePersisted => "verification",
        TransactionStageV1::CompensationAttemptPersisted
        | TransactionStageV1::CompensationResponsePersisted => "compensation",
        TransactionStageV1::Closed => "closure",
    }
}

fn collect_workflow_leaf_capabilities(
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    component_ids: &mut BTreeSet<String>,
    ancestors: &mut BTreeSet<String>,
) {
    let Some(workflow) = capability.workflow.as_ref() else {
        component_ids.insert(capability.id.clone());
        return;
    };
    if !ancestors.insert(capability.id.clone()) {
        return;
    }
    for step in &workflow.steps {
        if let Some(component) = catalog.get(&step.capability_id) {
            collect_workflow_leaf_capabilities(catalog, component, component_ids, ancestors);
        } else {
            component_ids.insert(step.capability_id.clone());
        }
    }
    ancestors.remove(&capability.id);
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{mutation_lifecycle_receipt, transaction_stage_class};
    use cfctl_catalog::CatalogSnapshot;
    use cfctl_core::{CapabilityV1, PlanStatus, PlanV1, TransactionStageV1};
    use chrono::Utc;
    use serde_json::json;

    #[test]
    fn lifecycle_receipt_classes_cover_every_transaction_stage() {
        let cases = [
            (TransactionStageV1::PlanPrepared, "plan"),
            (TransactionStageV1::ApprovalPersisted, "approval"),
            (
                TransactionStageV1::ConsumptionPersisted,
                "execution_admission",
            ),
            (TransactionStageV1::BoundaryAttemptPersisted, "apply"),
            (TransactionStageV1::BoundaryResponsePersisted, "apply"),
            (TransactionStageV1::SecretSinkPersisted, "apply"),
            (
                TransactionStageV1::VerificationAttemptPersisted,
                "verification",
            ),
            (
                TransactionStageV1::VerificationResponsePersisted,
                "verification",
            ),
            (
                TransactionStageV1::CompensationAttemptPersisted,
                "compensation",
            ),
            (
                TransactionStageV1::CompensationResponsePersisted,
                "compensation",
            ),
            (TransactionStageV1::Closed, "closure"),
        ];
        for (stage, expected) in cases {
            assert_eq!(transaction_stage_class(stage), expected);
        }
    }

    #[test]
    fn lifecycle_receipt_exports_durable_classes_without_plan_or_artifact_payloads()
    -> Result<(), Box<dyn std::error::Error>> {
        let capability = CapabilityV1::new(
            "security-response-create-expiring-ip-access-rule",
            "Create expiring IP Access rule",
            "POST",
            "/zones/{zone_id}/firewall/access_rules/rules",
        );
        let mut plan = PlanV1::draft(
            "profile-a",
            "account-a",
            "sha256:catalog",
            capability,
            json!({"zone_id":"zone-a","sensitive_target":"omitted"}),
        )?;
        plan.input = json!({"body":{"mode":"challenge"}});
        plan.refresh_hash()?;
        plan.approve(true, None)?;
        plan.mark_consumed()?;
        plan.record_transaction_stage(TransactionStageV1::BoundaryAttemptPersisted)?;
        plan.record_transaction_stage_with_artifact(
            TransactionStageV1::BoundaryResponsePersisted,
            json!({"success":true,"resource_id":"rule-a"}),
        )?;
        plan.record_transaction_stage(TransactionStageV1::VerificationAttemptPersisted)?;
        plan.record_transaction_stage_with_artifact(
            TransactionStageV1::VerificationResponsePersisted,
            json!({"state":"passed","resource_id":"rule-a"}),
        )?;
        plan.record_transaction_stage(TransactionStageV1::CompensationAttemptPersisted)?;
        plan.record_transaction_stage_with_artifact(
            TransactionStageV1::CompensationResponsePersisted,
            json!({"state":"removed","resource_id":"rule-a"}),
        )?;
        plan.status = PlanStatus::Rectified;
        plan.record_transaction_stage(TransactionStageV1::Closed)?;
        plan.validate_transaction_journal()?;

        let catalog = CatalogSnapshot {
            schema_version: 1,
            generated_at: Utc::now(),
            source_url: "test://lifecycle-receipt".to_owned(),
            source_hash: "sha256:source".to_owned(),
            schema_hash: "sha256:catalog".to_owned(),
            capabilities: BTreeMap::new(),
        };
        let receipt = mutation_lifecycle_receipt(&plan, &catalog);
        let classes = receipt["receipt_classes"]
            .as_array()
            .ok_or_else(|| std::io::Error::other("receipt classes"))?;
        for expected in [
            "plan",
            "approval",
            "execution_admission",
            "apply",
            "verification",
            "compensation",
            "closure",
        ] {
            assert!(classes.iter().any(|class| class == expected));
        }
        assert_eq!(
            receipt["checkpoints"].as_array().map(Vec::len),
            Some(plan.transaction_journal.len())
        );
        let encoded = serde_json::to_string(&receipt)?;
        assert!(!encoded.contains("sensitive_target"));
        assert!(!encoded.contains("\"targets\":"));
        assert!(!encoded.contains("\"input\":"));
        assert!(!encoded.contains("\"transaction_artifacts\":"));
        assert!(!encoded.contains("rule-a"));
        Ok(())
    }
}
