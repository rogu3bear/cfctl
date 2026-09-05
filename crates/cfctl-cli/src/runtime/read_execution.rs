use super::api_boundary::blocked_capability_envelope;
use super::call_input::resolve_account_id;
use super::cloudflare_api::BASE_URL as API_BASE_URL;
use super::credential_resolution::fresh_credential;
use super::credential_resolution::platform_secrets;
use super::delegated_read;
use super::error::{
    email_routing_contract_diagnostic, live_read_availability,
    live_read_failure_guidance_for_response,
};
use super::import_lineage::exact_durable_provider_complete_boundary;
use super::import_planning::D1RecoveryAnchorExpectation;
use super::import_planning::validate_exact_d1_recovery_anchor;
use super::prelude::{
    AdapterStatus, CallInput, CapabilityV1, CatalogSnapshot, CliError, CloudflareError, ErrorV1,
    EvidenceClass, Executor, Path, PlanStatus, ProfileMetadata, ProfilesConfig,
    R2LogRetrievalCredentials, Result, ResultEnvelopeV2, StateStore, StoredPlanRecord,
    TransactionStageV1, Utc, Uuid, Value, VerificationState, json,
};
use super::secret_io::redact_response_for_capability;
use super::support::configured_agent;
use super::support::http_client;
use crate::telemetry_product::execute_native_workflow;
use cfctl_agent::build_ui_action;
use cfctl_core::hash_value;

#[cfg(test)]
#[derive(Clone)]
pub(super) struct TestD1SchemaReadV1 {
    pub response: cfctl_cloudflare::CloudflareResponseV1,
    pub profile_id: String,
    pub account_id: String,
    pub credential_generation_id: String,
}

#[cfg(test)]
tokio::task_local! {
    static TEST_D1_SCHEMA_READ: TestD1SchemaReadV1;
}

#[cfg(test)]
pub(super) async fn with_test_d1_schema_read<F: std::future::Future>(
    fixture: TestD1SchemaReadV1,
    future: F,
) -> F::Output {
    TEST_D1_SCHEMA_READ.scope(fixture, future).await
}

#[derive(Debug)]
pub(super) struct ExecutedRead {
    pub(super) envelope: ResultEnvelopeV2,
    pub(super) credential_generation_id: Option<String>,
}

#[expect(
    clippy::too_many_lines,
    reason = "the versioned parent evidence contract stays explicit and auditable as one fail-closed gate"
)]
pub(super) fn mln_0143_parent_manifests(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
) -> Result<Vec<(String, Value)>> {
    let Some(contract) = capability.mln_0143_data_invariants.as_ref() else {
        return Ok(Vec::new());
    };
    if contract.capability_version != 5
        || !contract
            .expected_validator_contract_hash()
            .is_ok_and(|hash| hash == contract.validator_contract_hash)
    {
        return Err(CliError::Input(
            "MLN 0143 validator contract is stale or internally inconsistent".to_owned(),
        ));
    }
    let body = input
        .body
        .as_ref()
        .and_then(Value::as_object)
        .ok_or_else(|| CliError::Input("MLN 0143 invariant input must be an object".to_owned()))?;
    let phase = body
        .get("phase")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("MLN 0143 invariant phase is missing".to_owned()))?;
    validate_mln_cross_operation_lineage(store, contract, input, phase)?;
    let required: &[(&str, &str)] = match phase {
        "pre_import" => &[],
        "post_import" => &[("pre_import_evidence_hash", "pre_import")],
        "post_restore" => &[
            ("pre_import_evidence_hash", "pre_import"),
            ("post_import_evidence_hash", "post_import"),
        ],
        _ => {
            return Err(CliError::Input(
                "MLN 0143 invariant phase is unsupported".to_owned(),
            ));
        }
    };
    let target_scope_hash = hash_value(&json!({
        "account_id":contract.account_id,
        "database_id":contract.database_id,
    }))?;
    required
        .iter()
        .map(|(field, expected_phase)| {
            let evidence_hash = body.get(*field).and_then(Value::as_str).ok_or_else(|| {
                CliError::Input(format!("MLN 0143 `{phase}` requires `{field}`"))
            })?;
            let matching_proofs = store
                .list_operational_proofs()?
                .into_iter()
                .filter(|proof| {
                    proof.evidence.content_hash == evidence_hash
                        && proof.mln_0143_governed_execution().is_some_and(|binding| {
                            binding.capability_id == capability.id
                                && binding.capability_version == contract.capability_version
                                && binding.validator_contract_hash
                                    == contract.validator_contract_hash
                                && binding.fixed_query_sha256 == contract.fixed_query_sha256
                                && binding.catalog_hash == catalog.schema_hash
                                && binding.target_scope_hash == target_scope_hash
                                && binding.phase == *expected_phase
                                && binding.manifest_evidence_hash == evidence_hash
                                && binding.completion_status == "completed"
                        })
                })
                .collect::<Vec<_>>();
            if matching_proofs.len() != 1 {
                return Err(CliError::Input(format!(
                    "MLN 0143 parent evidence `{field}` requires exactly one matching completed governed execution proof"
                )));
            }
            let stored = store.read_evidence_value(evidence_hash)?;
            let manifest = stored.get("result").unwrap_or(&stored);
            let expected_table_hash = if *expected_phase == "post_import" {
                contract.post_table_definition_hash.as_str()
            } else {
                contract.pre_table_definition_hash.as_str()
            };
            let assertions = manifest.get("assertions").and_then(Value::as_object);
            let exact_assertions = [
                "old_table_absent",
                "unique_hash_index_present",
                "event_index_exact_non_unique_shape",
                "document_index_exact_non_unique_shape",
                "foreign_key_check_empty",
                "duplicate_hash_groups_zero",
                "invalid_evidence_kinds_zero",
                "invalid_advanced_events_zero",
                "prior_0142_terminal_trigger_present",
            ];
            let expected_trigger_hashes = if *expected_phase == "pre_import" {
                json!([])
            } else {
                json!(contract.trigger_definition_hashes)
            };
            let projection = manifest.get("projection").and_then(Value::as_object);
            let query = manifest.get("query").and_then(Value::as_object);
            let valid = manifest.get("capability_id").and_then(Value::as_str)
                == Some("mln-0143-data-invariants")
                && manifest.get("capability_version").and_then(Value::as_u64)
                    == Some(u64::from(contract.capability_version))
                && manifest.get("migration_id").and_then(Value::as_str) == Some("0143")
                && manifest.get("migration_sha256").and_then(Value::as_str)
                    == Some(contract.migration_sha256.as_str())
                && manifest
                    .get("validator_contract_hash")
                    .and_then(Value::as_str)
                    == Some(contract.validator_contract_hash.as_str())
                && manifest.get("target_scope_hash").and_then(Value::as_str)
                    == Some(target_scope_hash.as_str())
                && manifest.get("phase").and_then(Value::as_str) == Some(*expected_phase)
                && manifest.get("complete").and_then(Value::as_bool) == Some(true)
                && manifest.get("semantic_schema_hash").and_then(Value::as_str)
                    == Some(expected_table_hash)
                && manifest.get("packet_hash").and_then(Value::as_str).is_some()
                && manifest.get("packet_count").and_then(Value::as_u64).is_some()
                && manifest
                    .get("packet_non_target_hash")
                    .and_then(Value::as_str)
                    .is_some()
                && manifest
                    .get("packet_non_target_count")
                    .and_then(Value::as_u64)
                    .is_some()
                && manifest
                    .get("prior_0142_trigger_definition_hash")
                    .and_then(Value::as_str)
                    == Some(contract.prior_0142_trigger_definition_hash.as_str())
                && assertions.is_some_and(|assertions| {
                    assertions.len() == exact_assertions.len()
                        && exact_assertions.iter().all(|field| {
                            assertions.get(*field).and_then(Value::as_bool) == Some(true)
                        })
                })
                && projection.is_some_and(|projection| {
                    projection.len() == 3
                        && projection.get("digest").and_then(Value::as_str).is_some()
                        && projection.get("count").and_then(Value::as_u64).is_some()
                        && projection
                            .get("counts_by_kind")
                            .is_some_and(Value::is_array)
                })
                && manifest.get("trigger_definition_hashes") == Some(&expected_trigger_hashes)
                && query.is_some_and(|query| {
                    query.len() == 9
                        && query.get("sha256").and_then(Value::as_str)
                            == Some(contract.fixed_query_sha256.as_str())
                        && [
                            "row_limit",
                            "probe_rows",
                            "byte_limit",
                            "timeout_seconds",
                            "received_rows",
                            "provider_rows_read",
                        ]
                        .iter()
                        .all(|field| query.get(*field).and_then(Value::as_u64).is_some())
                        && query
                            .get("provider_duration")
                            .and_then(Value::as_f64)
                            .is_some()
                        && query.get("bounds_saturated").and_then(Value::as_bool)
                            == Some(false)
                })
                && manifest.pointer("/query/sha256").and_then(Value::as_str)
                    == Some(contract.fixed_query_sha256.as_str())
                && manifest.pointer("/query/bounds_saturated").and_then(Value::as_bool)
                    == Some(false);
            if !valid {
                return Err(CliError::Input(format!(
                    "MLN 0143 parent evidence `{field}` does not match the required capability, migration, target, completeness, or phase"
                )));
            }
            Ok((evidence_hash.to_owned(), manifest.clone()))
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Mln0143RestoreAnchorJoin {
    pub(super) input_source_operation_id: String,
    pub(super) receipt_source_operation_id: String,
    pub(super) input_source_evidence_hash: String,
    pub(super) receipt_source_evidence_hash: String,
    pub(super) input_target_bookmark_hash: String,
    pub(super) requested_bookmark_hash: String,
    pub(super) observed_bookmark_hash: String,
    pub(super) account_id: String,
    pub(super) profile_id: String,
    pub(super) catalog_hash: String,
    pub(super) credential_generation_id: String,
    pub(super) anchor_completed_at: chrono::DateTime<Utc>,
    pub(super) restore_created_at: chrono::DateTime<Utc>,
}

pub(super) fn mln_0143_restore_anchor_matches(
    observed: &Mln0143RestoreAnchorJoin,
    expected: &Mln0143RestoreAnchorJoin,
) -> bool {
    observed == expected && observed.anchor_completed_at < observed.restore_created_at
}

#[expect(
    clippy::too_many_lines,
    reason = "cross-operation import and restore joins are one fail-closed lineage gate"
)]
pub(super) fn validate_mln_cross_operation_lineage(
    store: &StateStore,
    contract: &cfctl_core::Mln0143DataInvariantsContractV1,
    input: &CallInput,
    phase: &str,
) -> Result<()> {
    if phase == "pre_import" {
        return Ok(());
    }
    let body = input
        .body
        .as_ref()
        .and_then(Value::as_object)
        .ok_or_else(|| CliError::Input("MLN lineage body is missing".to_owned()))?;
    let field = |name: &str| {
        body.get(name)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| CliError::Input(format!("MLN lineage requires `{name}`")))
    };
    let import_operation_id = field("import_operation_id")?;
    let boundary_hash = field("import_boundary_evidence_hash")?;
    let import_source_sha256 = field("import_source_sha256")?;
    let import_plan_hash = field("import_plan_hash")?;
    let import_plan = store.load_plan(import_operation_id)?;
    let import_input: CallInput = serde_json::from_value(import_plan.input.clone())?;
    let StoredPlanRecord::Current(import_plan_v2) =
        store.load_stored_plan_record(import_operation_id)?
    else {
        return Err(CliError::Input(
            "MLN lineage import operation is not a current immutable PlanV2".to_owned(),
        ));
    };
    let exact_plan = import_plan.capability.id == "d1-import-approved-mln-migration"
        && import_plan.status == PlanStatus::Verified
        && import_plan.transaction_stage == TransactionStageV1::Closed
        && import_plan.account_id == contract.account_id
        && import_plan.content_hash == import_plan_hash
        && import_plan_v2.plan.content_hash == import_plan.content_hash
        && import_input.selectors == input.selectors
        && import_input
            .body
            .as_ref()
            .and_then(|body| body.get("migration_id"))
            .and_then(Value::as_str)
            == Some("0143");
    let boundary = exact_durable_provider_complete_boundary(store, import_operation_id)?;
    let boundary_matches = boundary.evidence_hash == boundary_hash
        && boundary
            .checkpoint
            .pointer("/receipt/source_sha256")
            .and_then(Value::as_str)
            == Some(import_source_sha256);
    if !exact_plan
        || import_source_sha256
            != "sha256:9b089ead4c284fe92f8a9f81296ac34aa98702585305e36b5c4f345fe774871d"
        || !boundary_matches
    {
        return Err(CliError::Input(
            "post-import lineage does not resolve to exactly one same-target approved 0143 provider-complete boundary"
                .to_owned(),
        ));
    }
    if phase != "post_restore" {
        return Ok(());
    }
    let restore_operation_id = field("restore_operation_id")?;
    let restore_evidence_hash = field("restore_evidence_hash")?;
    let restore_plan = store.load_plan(restore_operation_id)?;
    let StoredPlanRecord::Current(restore_plan_v2) =
        store.load_stored_plan_record(restore_operation_id)?
    else {
        return Err(CliError::Input(
            "post_restore operation is not a current immutable PlanV2".to_owned(),
        ));
    };
    let restore_input: CallInput = serde_json::from_value(restore_plan.input.clone())?;
    let import_body = import_input
        .body
        .as_ref()
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CliError::Input("0143 import lost its closed prerequisite body".to_owned())
        })?;
    let import_field = |name: &str| {
        import_body
            .get(name)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| CliError::Input(format!("0143 import omitted `{name}`")))
    };
    let anchor_operation_id = import_field("post_0142_anchor_operation_id")?;
    let anchor_evidence_hash = import_field("post_0142_anchor_evidence_hash")?;
    let anchor_bookmark_hash = import_field("post_0142_anchor_bookmark_hash")?;
    let prior_0142_operation_id = import_field("prior_0142_operation_id")?;
    let prior_0142_plan = store.load_plan(prior_0142_operation_id)?;
    let prior_0142_closed_at = prior_0142_plan
        .transaction_journal
        .iter()
        .find(|checkpoint| checkpoint.stage == TransactionStageV1::Closed)
        .map(|checkpoint| checkpoint.recorded_at)
        .ok_or_else(|| CliError::Input("0142 import lost its Closed checkpoint".to_owned()))?;
    let target_scope_hash = hash_value(&json!({
        "account_id":contract.account_id,
        "database_id":contract.database_id,
    }))?;
    let anchor_request_hash = hash_value(&serde_json::to_value(CallInput {
        selectors: input.selectors.clone(),
        query: json!({}),
        ..CallInput::default()
    })?)?;
    let anchor_completed_at = validate_exact_d1_recovery_anchor(
        store,
        &D1RecoveryAnchorExpectation {
            operation_id: anchor_operation_id,
            evidence_hash: anchor_evidence_hash,
            output_sha256: None,
            bookmark_hash: anchor_bookmark_hash,
            catalog_hash: &import_plan.catalog_hash,
            request_hash: &anchor_request_hash,
            target_scope_hash: &target_scope_hash,
            account_id: &contract.account_id,
            profile_id: &import_plan.profile_id,
            credential_generation_id: Some(import_plan_v2.pins.credential_generation_id.as_str()),
            after: Some(prior_0142_closed_at),
            before: import_plan.created_at,
        },
    )?;
    let restore_evidence = store.read_evidence_value(restore_evidence_hash)?;
    let receipt = restore_evidence
        .pointer("/result/_cfctl")
        .or_else(|| restore_evidence.pointer("/result/result/_cfctl"))
        .ok_or_else(|| {
            CliError::Input("restore evidence omitted the exact bookmark receipt".to_owned())
        })?;
    let hash_bookmark = |value: Option<&str>| {
        value
            .map(|value| hash_value(&Value::String(value.to_owned())))
            .transpose()
    };
    let previous_hash = hash_bookmark(receipt.get("previous_bookmark").and_then(Value::as_str))?
        .ok_or_else(|| CliError::Input("restore previous bookmark is missing".to_owned()))?;
    let requested_hash = hash_bookmark(receipt.get("target_bookmark").and_then(Value::as_str))?
        .ok_or_else(|| CliError::Input("restore requested bookmark is missing".to_owned()))?;
    let observed_hash = hash_bookmark(receipt.get("returned_bookmark").and_then(Value::as_str))?
        .ok_or_else(|| CliError::Input("restore observed bookmark is missing".to_owned()))?;
    let receipt_source_operation_id = receipt.get("source_operation_id").and_then(Value::as_str);
    let receipt_source_evidence_hash = receipt.get("source_evidence_hash").and_then(Value::as_str);
    let restore_body = restore_input.body.as_ref();
    let observed_anchor_join = Mln0143RestoreAnchorJoin {
        input_source_operation_id: restore_body
            .and_then(|body| body.get("source_operation_id"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        receipt_source_operation_id: receipt_source_operation_id.unwrap_or_default().to_owned(),
        input_source_evidence_hash: restore_body
            .and_then(|body| body.get("source_evidence_hash"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        receipt_source_evidence_hash: receipt_source_evidence_hash.unwrap_or_default().to_owned(),
        input_target_bookmark_hash: restore_body
            .and_then(|body| body.get("target_bookmark"))
            .and_then(Value::as_str)
            .and_then(|bookmark| hash_value(&Value::String(bookmark.to_owned())).ok())
            .unwrap_or_default(),
        requested_bookmark_hash: requested_hash.clone(),
        observed_bookmark_hash: observed_hash.clone(),
        account_id: restore_plan.account_id.clone(),
        profile_id: restore_plan.profile_id.clone(),
        catalog_hash: restore_plan.catalog_hash.clone(),
        credential_generation_id: restore_plan_v2.pins.credential_generation_id.clone(),
        anchor_completed_at,
        restore_created_at: restore_plan.created_at,
    };
    let expected_anchor_join = Mln0143RestoreAnchorJoin {
        input_source_operation_id: anchor_operation_id.to_owned(),
        receipt_source_operation_id: anchor_operation_id.to_owned(),
        input_source_evidence_hash: anchor_evidence_hash.to_owned(),
        receipt_source_evidence_hash: anchor_evidence_hash.to_owned(),
        input_target_bookmark_hash: anchor_bookmark_hash.to_owned(),
        requested_bookmark_hash: anchor_bookmark_hash.to_owned(),
        observed_bookmark_hash: anchor_bookmark_hash.to_owned(),
        account_id: import_plan.account_id.clone(),
        profile_id: import_plan.profile_id.clone(),
        catalog_hash: import_plan.catalog_hash.clone(),
        credential_generation_id: import_plan_v2.pins.credential_generation_id.clone(),
        anchor_completed_at,
        restore_created_at: restore_plan.created_at,
    };
    let boundary_evidence_matches = restore_plan
        .transaction_artifact(TransactionStageV1::BoundaryResponsePersisted)
        .and_then(|artifact| artifact.get("apply_evidence_hash"))
        .and_then(Value::as_str)
        == Some(restore_evidence_hash);
    let exact_restore = restore_plan.capability.id == "d1-restore-exact-bookmark"
        && restore_plan.status == PlanStatus::Verified
        && restore_plan.transaction_stage == TransactionStageV1::Closed
        && restore_plan.account_id == contract.account_id
        && restore_plan.profile_id == import_plan.profile_id
        && restore_plan.catalog_hash == import_plan.catalog_hash
        && restore_plan_v2.plan.content_hash == restore_plan.content_hash
        && restore_plan_v2.pins.catalog_hash == import_plan_v2.pins.catalog_hash
        && mln_0143_restore_anchor_matches(&observed_anchor_join, &expected_anchor_join)
        && restore_input.selectors == input.selectors
        && boundary_evidence_matches
        && previous_hash == field("restore_previous_bookmark_hash")?
        && requested_hash == field("restore_requested_bookmark_hash")?
        && observed_hash == field("restore_observed_bookmark_hash")?;
    if !exact_restore {
        return Err(CliError::Input(
            "post_restore lineage does not resolve to the exact approved verified bookmark restore and import boundary"
                .to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn validate_mln_0143_lineage_result(
    input: &CallInput,
    current: &Value,
    parents: &[(String, Value)],
) -> Result<()> {
    let Some(phase) = input
        .body
        .as_ref()
        .and_then(|body| body.get("phase"))
        .and_then(Value::as_str)
    else {
        return Ok(());
    };
    if phase == "pre_import" {
        return Ok(());
    }
    let (_, pre) = parents.first().ok_or_else(|| {
        CliError::Input("MLN 0143 post phase omitted its pre-import parent".to_owned())
    })?;
    for pointer in [
        "/projection/digest",
        "/projection/count",
        "/projection/counts_by_kind",
    ] {
        if current.pointer(pointer) != pre.pointer(pointer) {
            return Err(CliError::Input(
                "MLN 0143 evidence projection drifted from the bound pre-import baseline"
                    .to_owned(),
            ));
        }
    }
    if phase == "post_import"
        && (current.get("packet_non_target_hash") != pre.get("packet_non_target_hash")
            || current.get("packet_non_target_count") != pre.get("packet_non_target_count"))
    {
        return Err(CliError::Input(
            "MLN 0143 packet configuration drifted outside the authorized advisor delta".to_owned(),
        ));
    }
    if phase == "post_restore" {
        if current.get("packet_hash") != pre.get("packet_hash")
            || current.get("packet_count") != pre.get("packet_count")
        {
            return Err(CliError::Input(
                "MLN 0143 restored packet configuration differs from the pre-import baseline"
                    .to_owned(),
            ));
        }
        let (post_hash, post) = parents.get(1).ok_or_else(|| {
            CliError::Input("MLN 0143 post-restore omitted its post-import parent".to_owned())
        })?;
        let pre_hash = &parents[0].0;
        if post
            .pointer("/lineage/pre_import_evidence_hash")
            .and_then(Value::as_str)
            != Some(pre_hash)
            || input
                .body
                .as_ref()
                .and_then(|body| body.get("post_import_evidence_hash"))
                .and_then(Value::as_str)
                != Some(post_hash)
        {
            return Err(CliError::Input(
                "MLN 0143 post-import evidence does not name the same pre-import baseline"
                    .to_owned(),
            ));
        }
        for pointer in ["/semantic_schema_hash", "/packet_hash"] {
            if current.pointer(pointer) != pre.pointer(pointer) {
                return Err(CliError::Input(
                    "MLN 0143 restored schema or packet digest differs from the pre-import baseline"
                        .to_owned(),
                ));
            }
        }
    }
    Ok(())
}

impl ExecutedRead {
    pub(super) fn without_credential(envelope: ResultEnvelopeV2) -> Self {
        Self {
            envelope,
            credential_generation_id: None,
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "read execution receives explicit catalog, selector, credential generation, private retrieval, and file-output inputs so no authority or destination is hidden in ambient state"
)]
pub(super) async fn execute_read(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &cfctl_core::CapabilityV1,
    input: &CallInput,
    requested_profile: Option<&str>,
    requested_account: Option<&str>,
    output_path: Option<&Path>,
    r2_credentials: Option<&R2LogRetrievalCredentials>,
    reply_admission_source: Option<&Path>,
) -> Result<ExecutedRead> {
    if capability.id == super::workspace_d1_qualification::OBSERVER_CAPABILITY_ID {
        return Ok(ExecutedRead::without_credential(
            super::workspace_d1_qualification::observe(store, catalog, input)?,
        ));
    }
    if capability.id == super::workspace_d1_qualification::PRODUCER_CAPABILITY_ID {
        return Ok(ExecutedRead::without_credential(
            super::workspace_d1_qualification::produce(store, catalog, input)?,
        ));
    }
    #[cfg(test)]
    if capability.id == "d1-schema-introspection"
        && let Ok(fixture) = TEST_D1_SCHEMA_READ.try_with(Clone::clone)
    {
        let prepared =
            cfctl_cloudflare::RequestBuilder::new(API_BASE_URL)?.build(capability, input)?;
        let mut response = fixture.response;
        response.result_info = Some(json!({
            "query": prepared.query_receipt.ok_or_else(|| {
                CliError::Input("test D1 schema read lacks its canonical query receipt".into())
            })?,
        }));
        let mut sanitized =
            redact_response_for_capability(capability, &serde_json::to_value(&response)?);
        if let Some(object) = sanitized.as_object_mut() {
            object.insert(
                "availability".to_owned(),
                live_read_availability(capability, &response),
            );
        }
        let evidence = store.write_observation_evidence(EvidenceClass::LiveRead, &sanitized)?;
        let mut envelope = ResultEnvelopeV2::success("call", sanitized).with_evidence(evidence);
        envelope.capability_id = Some(capability.id.clone());
        envelope.profile_id = Some(fixture.profile_id);
        envelope.account_id = Some(fixture.account_id);
        envelope.ok = response.success;
        envelope.performed = true;
        return Ok(ExecutedRead {
            envelope,
            credential_generation_id: Some(fixture.credential_generation_id),
        });
    }
    if capability.workflow.is_some() {
        return Ok(ExecutedRead::without_credential(execute_native_workflow(
            store, catalog, capability,
        )?));
    }
    match capability.adapter_status {
        AdapterStatus::DelegatedCli => {
            return delegated_read::execute(delegated_read::Request {
                store,
                catalog,
                capability,
                input,
                requested_profile,
                requested_account,
                reply_admission_source,
            })
            .await;
        }
        AdapterStatus::GovernedUi => {
            return Ok(ExecutedRead::without_credential(execute_governed_ui_read(
                store,
                catalog,
                capability,
                input,
                requested_profile,
                requested_account,
            )?));
        }
        AdapterStatus::Blocked => {
            return Ok(ExecutedRead::without_credential(
                blocked_capability_envelope(
                    "call",
                    capability,
                    capability
                        .blocked_reason
                        .as_deref()
                        .unwrap_or("no executable adapter is available"),
                ),
            ));
        }
        AdapterStatus::Native | AdapterStatus::DynamicApi => {}
    }
    let mln_0143_parents = mln_0143_parent_manifests(store, catalog, capability, input)?;
    let profiles = ProfilesConfig::load(store)?;
    let profile = profiles.selected(requested_profile)?;
    let credential_generation_id = credential_generation_for_read(profile)?;
    let account_id = resolve_account_id(store, profile, requested_account, input)?;
    let credential = fresh_credential(profile, &platform_secrets(store)).await?;
    let executor = Executor::new(http_client()?, API_BASE_URL)?;
    let response = if capability.id == cfctl_core::WORKER_VERSION_ARTIFACT_DIGEST_ID {
        if output_path.is_some() {
            return Err(CloudflareError::InvalidRequestBody(
                "Worker module bytes cannot be written to an output file".to_owned(),
            )
            .into());
        }
        executor
            .execute_read(capability, input, &credential)
            .await?
    } else if capability.r2_private_object_digest.is_some() {
        executor
            .execute_r2_private_object_digest(capability, input, &credential)
            .await?
    } else if capability.r2_log_retrieval.is_some() {
        let output_path = output_path.ok_or(CloudflareError::R2LogOutputFileRequired)?;
        let r2_credentials = r2_credentials.ok_or(CloudflareError::R2LogCredentialsRequired)?;
        executor
            .execute_r2_log_retrieval_to_file(
                capability,
                input,
                &credential,
                r2_credentials,
                output_path,
            )
            .await?
    } else if let Some(output_path) = output_path {
        executor
            .execute_read_to_file(capability, input, &credential, output_path)
            .await?
    } else {
        executor
            .execute_read(capability, input, &credential)
            .await?
    };
    if capability.mln_0143_data_invariants.is_some() {
        validate_mln_0143_lineage_result(input, &response.result, &mln_0143_parents)?;
    }
    let mut sanitized =
        redact_response_for_capability(capability, &serde_json::to_value(&response)?);
    if let Some(object) = sanitized.as_object_mut() {
        object.insert(
            "availability".to_owned(),
            live_read_availability(capability, &response),
        );
    }
    let evidence = store.write_observation_evidence(EvidenceClass::LiveRead, &sanitized)?;
    let mut envelope = ResultEnvelopeV2::success("call", sanitized).with_evidence(evidence);
    envelope.capability_id = Some(capability.id.clone());
    envelope.profile_id = Some(profile.id.clone());
    envelope.account_id = account_id;
    envelope.ok = response.success;
    envelope.performed = true;
    let email_routing_contract_rejected =
        email_routing_contract_diagnostic(capability, &response).is_some();
    if capability.mln_0143_data_invariants.is_some() {
        let verified = response.result.get("complete").and_then(Value::as_bool) == Some(true)
            && response
                .result
                .pointer("/query/bounds_saturated")
                .and_then(Value::as_bool)
                == Some(false);
        envelope.verification.state = if verified {
            VerificationState::Passed
        } else {
            VerificationState::Failed
        };
        envelope.verification.basis =
            Some("closed MLN 0143 phase assertions and bounded completeness manifest".to_owned());
    } else if capability.id == cfctl_core::WORKER_VERSION_ARTIFACT_DIGEST_ID {
        let verified = response.success
            && response.result["complete"] == true
            && response.result["body_returned"] == false;
        envelope.verification.state = if verified {
            VerificationState::Passed
        } else {
            VerificationState::Failed
        };
        envelope.verification.basis = Some("exact immutable version and complete bounded module digest manifest; static assets not qualified".to_owned());
    } else if capability.r2_private_object_digest.is_some() {
        let verified = response
            .result
            .get("body_returned")
            .and_then(Value::as_bool)
            == Some(false)
            && response
                .result
                .get("byte_count")
                .and_then(Value::as_u64)
                .is_some()
            && response
                .result
                .get("sha256")
                .and_then(Value::as_str)
                .is_some_and(|value| value.starts_with("sha256:") && value.len() == 71)
            && response
                .result
                .get("etag")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty());
        envelope.verification.state = if verified {
            VerificationState::Passed
        } else {
            VerificationState::Failed
        };
        envelope.verification.basis = Some(
            "exact private object identity, bounded streamed SHA-256, ETag, byte count, and body_returned:false"
                .to_owned(),
        );
    } else if capability.d1_full_export.is_some() {
        let verified = response
            .result
            .pointer("/output_file/hash_matches")
            .and_then(Value::as_bool)
            == Some(true)
            && response
                .result
                .pointer("/output_file/exists")
                .and_then(Value::as_bool)
                == Some(true);
        envelope.verification.state = if verified {
            VerificationState::Passed
        } else {
            VerificationState::Failed
        };
        envelope.verification.basis =
            Some("same output file exists and its SHA-256 matches the streamed receipt".to_owned());
    } else if email_routing_contract_rejected {
        envelope.verification.state = VerificationState::Failed;
        envelope.verification.basis = Some(
            "cfctl rejected the Email Routing provider response before consumer projection"
                .to_owned(),
        );
    } else {
        envelope.verification.state = VerificationState::NotApplicable;
        envelope.verification.basis = Some(format!(
            "live Cloudflare read pinned to catalog {}",
            catalog.schema_hash
        ));
    }
    // A non-2xx Cloudflare response is `Ok` at the transport layer but a failure
    // to the agent. Without an ErrorV1 it would surface as `ok:false` with no
    // guidance; attach a status-specific next step so the agent knows the move.
    if !response.success {
        let (code, next_step) = live_read_failure_guidance_for_response(capability, &response);
        envelope.error = Some(ErrorV1 {
            code: code.to_owned(),
            message: if email_routing_contract_rejected {
                format!(
                    "the performed Cloudflare read failed the normalized response contract for capability `{}`",
                    capability.id
                )
            } else {
                format!(
                    "the Cloudflare read did not succeed (HTTP {}) for capability `{}`",
                    response.status, capability.id
                )
            },
            next_step: Some(next_step),
        });
    }
    Ok(ExecutedRead {
        envelope,
        credential_generation_id: Some(credential_generation_id),
    })
}

pub(super) fn credential_generation_for_read(profile: &ProfileMetadata) -> Result<String> {
    let generation = profile.credential_generation_id.as_deref().ok_or_else(|| {
        CliError::Input(format!(
            "profile `{}` has no credential generation; re-import or log in again",
            profile.id
        ))
    })?;
    Uuid::parse_str(generation).map_err(|_| {
        CliError::Input(format!(
            "profile `{}` has an invalid credential generation; re-import or log in again",
            profile.id
        ))
    })?;
    Ok(generation.to_owned())
}

pub(super) fn apply_operational_proof_index_result(
    envelope: &mut ResultEnvelopeV2,
    proof_result: Result<()>,
) {
    if let Err(error) = proof_result {
        envelope.ok = false;
        if envelope.error.is_some() {
            if envelope.result.is_null() {
                envelope.result = json!({ "operational_proof_indexed": false });
            } else if let Some(result) = envelope.result.as_object_mut() {
                result.insert("operational_proof_indexed".to_owned(), Value::Bool(false));
            }
            return;
        }
        envelope.error = Some(ErrorV1 {
            code: "CFCTL_OPERATIONAL_PROOF_INDEX_FAILED".to_owned(),
            message: format!(
                "the bounded read completed, but its operational-proof index row was not durably recorded: {error}"
            ),
            next_step: Some(
                "Preserve the live-read evidence receipt, repair the local cfctl data directory, and repeat the bounded read before relying on workflow freshness or catalog operational-proof coverage."
                    .to_owned(),
            ),
        });
    }
}

pub(super) fn execute_governed_ui_read(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    requested_profile: Option<&str>,
    requested_account: Option<&str>,
) -> Result<ResultEnvelopeV2> {
    let profiles = ProfilesConfig::load(store)?;
    let profile = profiles.selected(requested_profile)?;
    let account_id = resolve_account_id(store, profile, requested_account, input)?;
    let agent = configured_agent()?;
    let target = json!({
        "capability_id": capability.id,
        "url": capability.path,
        "selectors": input.selectors,
        "query": input.query,
        "catalog_hash": catalog.schema_hash,
    });
    let action = build_ui_action(
        agent,
        None,
        account_id.as_deref(),
        target,
        &format!(
            "Observe only: {}. Use the authenticated Cloudflare dashboard only after confirming API and CLI coverage cannot answer it. Capture redacted before evidence and do not mutate state.",
            capability.title
        ),
        false,
    )?;
    let evidence =
        store.write_evidence(EvidenceClass::AgentAction, &serde_json::to_value(&action)?)?;
    let mut envelope = ResultEnvelopeV2::success(
        "call",
        json!({
            "agent_action": action,
            "performed": false,
            "message": "Governed UI observation handoff created. The action is target-bound evidence, not authority or proof that the UI was inspected."
        }),
    )
    .with_evidence(evidence);
    envelope.capability_id = Some(capability.id.clone());
    envelope.profile_id = Some(profile.id.clone());
    envelope.account_id = account_id;
    envelope.verification.state = VerificationState::Pending;
    envelope.verification.basis =
        Some("awaiting hash-bound before/after UI evidence from the configured agent".to_owned());
    Ok(envelope)
}
