use std::{
    collections::BTreeSet,
    fs,
    fs::OpenOptions,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    process::{Command, Output, Stdio},
    thread,
    time::{Duration as StdDuration, Instant},
};

use cfctl_core::WorkspaceD1ReplyAdmissionContractV1;
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tokio::time::Duration;

use super::{
    AuthCredential, CallInput, CapabilityV1, CatalogSnapshot, CliError, PlanV1, ProfileMetadata,
    Result, StateStore, credential_generation_for_read, workspace_d1_migration,
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

const TARGET_KEY: &str = "workspace_d1_reply_admission";
const TIMEOUT: Duration = Duration::from_mins(2);
const MAX_CANDIDATE_BYTES: u64 = 1024 * 1024;
const RECORD_COLUMNS: &[&str] = &[
    "id",
    "schema_version",
    "transaction_sha256",
    "correlation_sha256",
    "candidate_sha256",
    "scope_manifest_sha256",
    "inbound_delivery_id",
    "relay_id",
    "thread_id",
    "route_id",
    "policy_sha256",
    "desired_state_sha256",
    "operator_set_sha256",
    "admitted_operator_ref",
    "public_identity",
    "sender_domain",
    "identity_profile_ref",
    "identity_profile_sha256",
    "display_name",
    "signature_profile_ref",
    "signature_sha256",
    "sender_adapter",
    "configured_policy_receipt_sha256",
    "edge_activation_receipt_sha256",
    "sender_domain_receipt_sha256",
    "inbound_acceptance_receipt_sha256",
    "apple_mail_inbox_receipt_sha256",
    "operator_authorization_receipt_sha256",
    "opaque_relay_receipt_sha256",
    "evidence_bundle_sha256",
    "evidence_observed_at",
    "admitted_at",
    "expires_at",
    "status",
];
const PROJECTION_KEYS: &[&str] = &[
    "schema_version",
    "transaction_sha256",
    "candidate",
    "candidate_sha256",
    "control_plane",
    "correlation_sha256",
    "scope_manifest_sha256",
    "inbound_delivery_id",
    "relay_id",
    "thread_id",
    "route_id",
    "policy_sha256",
    "desired_state_sha256",
    "operator_set_sha256",
    "admitted_operator_sha256",
    "public_identity",
    "sender_domain",
    "identity_profile_ref",
    "identity_profile_sha256",
    "display_name",
    "signature_profile_ref",
    "signature_sha256",
    "sender_adapter",
    "prerequisites",
    "evidence_bundle_sha256",
    "evidence_observed_at",
    "admitted_at",
    "expires_at",
];
const PREREQUISITE_KEYS: &[&str] = &[
    "configured_policy",
    "edge_activation",
    "sender_domain",
    "inbound_acceptance",
    "apple_mail_inbox",
    "operator_authorization",
    "opaque_relay",
];
const SOURCE_RECEIPT_KEYS: &[&str] = &[
    "adapter",
    "authority_sha256",
    "binding",
    "body_free",
    "body_returned",
    "candidate_sha256",
    "capability_id",
    "control_plane_sha256",
    "expires_at",
    "kind",
    "match_count",
    "observed_at",
    "operation_id",
    "performed",
    "provider_output_retained",
    "result",
    "schema_version",
    "success",
];
const SOURCE_BINDING_KEYS: &[&str] = &[
    "correlation_sha256",
    "scope_manifest_sha256",
    "inbound_delivery_id",
    "relay_id",
    "thread_id",
    "route_id",
    "policy_sha256",
    "desired_state_sha256",
    "operator_set_sha256",
    "admitted_operator_sha256",
    "identity_profile_sha256",
];

pub(super) fn load(store: &StateStore, id: &str) -> Result<Option<CapabilityV1>> {
    Ok(
        cfctl_workspace::load_workspace_d1_reply_admission_capability(
            &store.workspace_roots()?,
            id,
        )?,
    )
}

pub(super) fn prepare_plan_target(
    store: &StateStore,
    catalog: &CatalogSnapshot,
    capability: &CapabilityV1,
    input: &CallInput,
    profile: &ProfileMetadata,
    account_id: &str,
    source: &Path,
) -> Result<Option<Value>> {
    let Some(contract) = capability.workspace_d1_reply_admission.as_ref() else {
        return Ok(None);
    };
    let config = workspace_d1_migration::validated_config(&config_contract(contract), input)?;
    let compiler_runtime = compiler_runtime(store, contract)?;
    let bytes = compile_private_candidate(store, contract, source, &compiler_runtime)?;
    let candidate = validate_candidate_bytes(&bytes)?;
    validate_candidate_fresh(&candidate, Utc::now())?;
    let generation = credential_generation_for_read(profile)?;
    validate_control_plane_binding(&candidate, profile, account_id, &generation)?;
    let stage = stage_private_candidate(store, &bytes)?;
    let recovery = workspace_d1_migration::fresh_recovery_proof(
        store,
        catalog,
        input,
        &profile.id,
        account_id,
        &generation,
        contract.recovery_max_age_seconds,
        Utc::now(),
    )?;
    Ok(Some(json!({
        "schema_version":1,"repository_root":contract.repository_root,"repository_head":contract.repository_head,
        "operation_pack_sha256":contract.operation_pack_sha256,"production_config":config.path,
        "production_config_sha256":config.sha256,"database_binding":contract.database_binding,
        "database_name":config.database_name,"database_id":config.database_id,"account_id":account_id,
        "profile_id":profile.id,"credential_generation_id":generation,"private_stage":stage,
        "compiler_runtime_path_sha256":compiler_runtime.path_sha256,
        "compiler_runtime_sha256":compiler_runtime.executable_sha256,
        "compiler_runtime_version":compiler_runtime.version,
        "source_sha256":candidate.source_sha256,"compiled_candidate_sha256":candidate.compiled_candidate_sha256,
        "activation_record_sha256":candidate.activation_record_sha256,
        "pre_send_identity_projection_sha256":candidate.projection_sha256,
        "transaction_sha256":candidate.transaction_sha256,
        "logical_activation_id":candidate.logical_activation_id,
        "activation_operation_id":candidate.activation_operation_id,
        "candidate_cfctl_build_sha256":candidate.cfctl_build_sha256,
        "candidate_profile_sha256":candidate.profile_sha256,
        "candidate_account_sha256":candidate.account_sha256,
        "candidate_credential_generation_sha256":candidate.credential_generation_sha256,
        "recovery":recovery,
    })))
}

pub(super) fn local_artifact_paths(capability: &CapabilityV1) -> Result<Option<Vec<PathBuf>>> {
    let Some(c) = capability.workspace_d1_reply_admission.as_ref() else {
        return Ok(None);
    };
    Ok(Some(vec![
        Path::new(&c.repository_root)
            .join(&c.operation_pack_path)
            .parent()
            .ok_or_else(|| CliError::Input("reply-admission pack has no parent".to_owned()))?
            .to_path_buf(),
    ]))
}

#[expect(
    clippy::too_many_lines,
    reason = "one validation boundary rebinds repository, compiler runtime, private stage, candidate, control plane, and recovery proof"
)]
pub(super) fn validate_bound_plan(store: &StateStore, plan: &PlanV1) -> Result<()> {
    let Some(contract) = plan.capability.workspace_d1_reply_admission.as_ref() else {
        return Ok(());
    };
    let current = load(store, &plan.capability.id)?.ok_or_else(|| {
        CliError::Input(
            "reply-admission operation is no longer uniquely available; create a new plan"
                .to_owned(),
        )
    })?;
    if current.workspace_d1_reply_admission.as_ref() != Some(contract) {
        return Err(CliError::Input(
            "reply-admission repository authority drifted; create a new plan".to_owned(),
        ));
    }
    let input: CallInput = serde_json::from_value(plan.input.clone())?;
    let config = workspace_d1_migration::validated_config(&config_contract(contract), &input)?;
    let target = target(plan)?;
    for (k, v) in [
        ("repository_head", contract.repository_head.as_str()),
        (
            "operation_pack_sha256",
            contract.operation_pack_sha256.as_str(),
        ),
        ("production_config", config.path.as_str()),
        ("production_config_sha256", config.sha256.as_str()),
        ("database_id", config.database_id.as_str()),
        ("account_id", plan.account_id.as_str()),
    ] {
        require(target, k, v)?;
    }
    let compiler_runtime = compiler_runtime(store, contract)?;
    for (key, expected) in [
        (
            "compiler_runtime_path_sha256",
            compiler_runtime.path_sha256.as_str(),
        ),
        (
            "compiler_runtime_sha256",
            compiler_runtime.executable_sha256.as_str(),
        ),
        (
            "compiler_runtime_version",
            compiler_runtime.version.as_str(),
        ),
    ] {
        require(target, key, expected)?;
    }
    validate_private_stage(store, target)?;
    let stage = stage(target)?;
    let bytes = read_private_candidate(&private_stage_path(store, stage)?)?;
    let candidate = validate_candidate_bytes(&bytes)?;
    validate_candidate_fresh(&candidate, Utc::now())?;
    for (k, v) in [
        ("source_sha256", candidate.source_sha256.as_str()),
        (
            "compiled_candidate_sha256",
            candidate.compiled_candidate_sha256.as_str(),
        ),
        (
            "activation_record_sha256",
            candidate.activation_record_sha256.as_str(),
        ),
        (
            "pre_send_identity_projection_sha256",
            candidate.projection_sha256.as_str(),
        ),
        ("transaction_sha256", candidate.transaction_sha256.as_str()),
        (
            "logical_activation_id",
            candidate.logical_activation_id.as_str(),
        ),
        (
            "activation_operation_id",
            candidate.activation_operation_id.as_str(),
        ),
        (
            "candidate_cfctl_build_sha256",
            candidate.cfctl_build_sha256.as_str(),
        ),
        (
            "candidate_profile_sha256",
            candidate.profile_sha256.as_str(),
        ),
        (
            "candidate_account_sha256",
            candidate.account_sha256.as_str(),
        ),
        (
            "candidate_credential_generation_sha256",
            candidate.credential_generation_sha256.as_str(),
        ),
    ] {
        require(target, k, v)?;
    }
    workspace_d1_migration::validate_recovery_target(
        store,
        target,
        &plan.catalog_hash,
        contract.recovery_max_age_seconds,
        Utc::now(),
    )
}

pub(super) async fn run(
    store: &StateStore,
    plan: &PlanV1,
    credential: &AuthCredential,
) -> Result<Value> {
    validate_bound_plan(store, plan)?;
    let contract = plan
        .capability
        .workspace_d1_reply_admission
        .as_ref()
        .ok_or_else(|| CliError::Input("reply-admission contract missing".to_owned()))?;
    let target = target(plan)?;
    let root = Path::new(&contract.repository_root);
    let config = string(target, "production_config")?;
    let db = string(target, "database_name")?;
    let bytes = read_private_candidate(&private_stage_path(store, stage(target)?)?)?;
    let candidate = validate_candidate_bytes(&bytes)?;
    validate_candidate_fresh(&candidate, Utc::now())?;
    let version = workspace_d1_migration::run_wrangler(
        &["--version".to_owned()],
        root,
        credential,
        &plan.account_id,
        &store.paths().cache_dir,
        TIMEOUT,
    )
    .await
    .map_err(CliError::delegated_mutation_not_attempted)?;
    let observed_version = workspace_d1_migration::parse_wrangler_version(&version.stdout)?;
    if !version.success || observed_version != contract.wrangler_version {
        return Err(CliError::Input(format!(
            "workspace reply admission requires Wrangler {}, observed {observed_version}",
            contract.wrangler_version
        )));
    }
    let sql = insert_sql(&contract.admission_table, &candidate.record)?;
    let sql_path = private_sql(store, &sql)?;
    let result = workspace_d1_migration::run_wrangler(
        &[
            "d1".into(),
            "execute".into(),
            db.into(),
            "--remote".into(),
            "--config".into(),
            config.into(),
            "--file".into(),
            sql_path.display().to_string(),
        ],
        root,
        credential,
        &plan.account_id,
        &store.paths().cache_dir,
        TIMEOUT,
    )
    .await;
    let _ = fs::remove_file(&sql_path);
    let result = match result {
        Ok(result) => result,
        Err(
            error @ (CliError::SubprocessNotStarted { .. }
            | CliError::DelegatedMutationNotAttempted { .. }),
        ) => return Err(error),
        Err(_) => {
            return Ok(json!({
            "adapter":"workspace_d1_reply_admission_v1",
            "success":false,
            "boundary_crossed":true,
            "failure_code":"CFCTL_WORKSPACE_D1_REPLY_ADMISSION_PROVIDER_RESULT_AMBIGUOUS",
            "failure_stage":"provider_write",
            "source_sha256":candidate.source_sha256,
            "activation_record_sha256":candidate.activation_record_sha256,
            "transaction_sha256":candidate.transaction_sha256,
            "logical_activation_id":candidate.logical_activation_id,
            "activation_operation_id":candidate.activation_operation_id,
            "cfctl_operation_id":plan.operation_id,
            "provider_output_retained":false,
            "record_content_retained":false,
            "body_returned":false,
            }));
        }
    };
    Ok(
        json!({"adapter":"workspace_d1_reply_admission_v1","success":result.success,"exit_status":result.exit_status,"boundary_crossed":true,
        "source_sha256":candidate.source_sha256,"compiled_candidate_sha256":candidate.compiled_candidate_sha256,
        "activation_record_sha256":candidate.activation_record_sha256,"transaction_sha256":candidate.transaction_sha256,
        "logical_activation_id":candidate.logical_activation_id,"activation_operation_id":candidate.activation_operation_id,"cfctl_operation_id":plan.operation_id,
        "wrangler_version":observed_version,"provider_output_retained":false,"record_content_retained":false,
        "body_returned":false,"recovery":target.get("recovery")}),
    )
}

pub(super) async fn verify(
    store: &StateStore,
    plan: &PlanV1,
    credential: &AuthCredential,
) -> Value {
    match verify_inner(store, plan, credential).await {
        Ok(v) => v,
        Err(e) => {
            json!({"passed":false,"basis":format!("reply-admission readback failed closed: {e}")})
        }
    }
}

pub(super) fn read_receipt_is_complete(receipt: &Value) -> bool {
    let Some(object) = receipt.as_object() else {
        return false;
    };
    if object.keys().map(String::as_str).collect::<BTreeSet<_>>()
        != [
            "activation_operation_id",
            "activation_record_sha256",
            "adapter",
            "account_sha256",
            "body_returned",
            "boundary_crossed",
            "cfctl_build_sha256",
            "credential_generation_sha256",
            "expires_at",
            "match_count",
            "observed_at",
            "pre_send_identity_projection",
            "pre_send_identity_projection_sha256",
            "provider_output_retained",
            "profile_sha256",
            "record_content_retained",
            "status",
            "success",
            "transaction_sha256",
            "wrangler_version",
        ]
        .into_iter()
        .collect()
    {
        return false;
    }
    let projection_digest_matches = receipt
        .get("pre_send_identity_projection")
        .filter(|projection| projection.is_object())
        .zip(
            receipt
                .get("pre_send_identity_projection_sha256")
                .and_then(Value::as_str),
        )
        .is_some_and(|(projection, expected)| hash_json(projection) == expected);
    let control_plane_matches = [
        "account_sha256",
        "cfctl_build_sha256",
        "credential_generation_sha256",
        "profile_sha256",
    ]
    .iter()
    .all(|key| {
        receipt.get(*key)
            == receipt.pointer(&format!(
                "/pre_send_identity_projection/control_plane/{key}"
            ))
    }) && receipt.get("activation_operation_id")
        == receipt.pointer("/pre_send_identity_projection/control_plane/activation_operation_id");
    receipt.get("adapter").and_then(Value::as_str) == Some("workspace_reply_admission_read_v1")
        && receipt.get("success").and_then(Value::as_bool) == Some(true)
        && receipt.get("boundary_crossed").and_then(Value::as_bool) == Some(true)
        && receipt.get("status").and_then(Value::as_str) == Some("active")
        && receipt.get("match_count").and_then(Value::as_u64) == Some(1)
        && receipt
            .get("provider_output_retained")
            .and_then(Value::as_bool)
            == Some(false)
        && receipt
            .get("record_content_retained")
            .and_then(Value::as_bool)
            == Some(false)
        && receipt.get("body_returned").and_then(Value::as_bool) == Some(false)
        && projection_digest_matches
        && control_plane_matches
        && receipt
            .get("activation_operation_id")
            .and_then(Value::as_str)
            .is_some_and(safe_ref)
        && [
            "transaction_sha256",
            "activation_record_sha256",
            "pre_send_identity_projection_sha256",
        ]
        .iter()
        .all(|key| {
            receipt
                .get(*key)
                .and_then(Value::as_str)
                .is_some_and(|value| {
                    value
                        .strip_prefix("sha256:")
                        .is_some_and(|digest| lower_hex(digest, 64))
                })
        })
}

#[expect(
    clippy::too_many_lines,
    reason = "the closed read boundary keeps compiler binding, exact selectors, provider projection, and body-free failure translation visibly contiguous"
)]
pub(super) async fn read(
    store: &StateStore,
    capability: &CapabilityV1,
    input: &CallInput,
    credential: &AuthCredential,
    profile: &ProfileMetadata,
    account_id: &str,
    source: &Path,
) -> Result<Value> {
    let contract = capability
        .workspace_d1_reply_admission
        .as_ref()
        .ok_or_else(|| CliError::Input("reply-admission read contract missing".to_owned()))?;
    if contract.operation_kind != "read"
        || contract.read_projection.as_deref() != Some("maildesk_reply_admission_read_v1")
    {
        return Err(CliError::Input(
            "reply-admission read projection is not the closed workspace contract".to_owned(),
        ));
    }
    let current = load(store, &capability.id)?.ok_or_else(|| {
        CliError::Input("reply-admission read operation is no longer uniquely available".to_owned())
    })?;
    if current.workspace_d1_reply_admission.as_ref() != Some(contract) {
        return Err(CliError::Input(
            "reply-admission read repository authority drifted".to_owned(),
        ));
    }
    if input.body.is_some() || input.query.as_object().is_none_or(|query| query.len() != 5) {
        return Err(CliError::Input(
            "reply-admission read accepts only the exact config and four digest/operation selectors"
                .to_owned(),
        ));
    }
    let config = workspace_d1_migration::validated_config(&config_contract(contract), input)?;
    let runtime = compiler_runtime(store, contract)?;
    let bytes = compile_private_candidate(store, contract, source, &runtime)?;
    let candidate = validate_candidate_bytes(&bytes)?;
    validate_candidate_fresh(&candidate, Utc::now())?;
    let generation = credential_generation_for_read(profile)?;
    validate_control_plane_binding(&candidate, profile, account_id, &generation)?;
    for (key, expected) in [
        ("transaction_sha256", candidate.transaction_sha256.as_str()),
        (
            "activation_record_sha256",
            candidate.activation_record_sha256.as_str(),
        ),
        (
            "pre_send_identity_projection_sha256",
            candidate.projection_sha256.as_str(),
        ),
        (
            "activation_operation_id",
            candidate.activation_operation_id.as_str(),
        ),
    ] {
        if input.query.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(CliError::Input(format!(
                "reply-admission read selector `{key}` does not match the compiler-owned candidate"
            )));
        }
    }
    let version = workspace_d1_migration::run_wrangler(
        &["--version".to_owned()],
        Path::new(&contract.repository_root),
        credential,
        account_id,
        &store.paths().cache_dir,
        TIMEOUT,
    )
    .await?;
    let observed_version = workspace_d1_migration::parse_wrangler_version(&version.stdout)?;
    if !version.success || observed_version != contract.wrangler_version {
        return Err(CliError::Input(format!(
            "workspace reply-admission read requires Wrangler {}, observed {observed_version}",
            contract.wrangler_version
        )));
    }
    let sql = format!(
        "SELECT {} FROM {} WHERE id = '{}' AND transaction_sha256 = '{}' LIMIT 2",
        RECORD_COLUMNS.join(","),
        identifier(&contract.admission_table)?,
        escape(candidate.record["id"].as_str().unwrap_or_default()),
        escape(candidate.transaction_sha256.trim_start_matches("sha256:")),
    );
    let rows = workspace_d1_migration::execute_json_query(
        &config.database_name,
        &config.path,
        &sql,
        Path::new(&contract.repository_root),
        credential,
        account_id,
        &store.paths().cache_dir,
    )
    .await;
    let observed_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let Ok(rows) = rows else {
        return Ok(json!({
            "adapter":"workspace_reply_admission_read_v1",
            "success":false,
            "boundary_crossed":true,
            "status":"provider_read_failed",
            "match_count":Value::Null,
            "transaction_sha256":candidate.transaction_sha256,
            "activation_record_sha256":candidate.activation_record_sha256,
            "pre_send_identity_projection_sha256":candidate.projection_sha256,
            "activation_operation_id":candidate.activation_operation_id,
            "cfctl_build_sha256":candidate.cfctl_build_sha256,
            "profile_sha256":candidate.profile_sha256,
            "account_sha256":candidate.account_sha256,
            "credential_generation_sha256":candidate.credential_generation_sha256,
            "observed_at":observed_at,
            "expires_at":candidate.expires_at.to_rfc3339_opts(SecondsFormat::Millis, true),
            "wrangler_version":observed_version,
            "failure_code":"CFCTL_WORKSPACE_D1_REPLY_ADMISSION_PROVIDER_READ_FAILED",
            "provider_output_retained":false,
            "record_content_retained":false,
            "body_returned":false,
        }));
    };
    Ok(project_read_receipt(
        &candidate,
        &rows,
        &observed_at,
        &observed_version,
    ))
}

fn project_read_receipt(
    candidate: &Candidate,
    rows: &[Map<String, Value>],
    observed_at: &str,
    observed_version: &str,
) -> Value {
    let match_count = rows.len();
    let exact = match_count == 1
        && rows[0].get("status").and_then(Value::as_str) == Some("admitted")
        && hash_json(&Value::Object(rows[0].clone())) == candidate.activation_record_sha256;
    let status = match match_count {
        0 => "missing",
        1 if exact => "active",
        1 => "invalid",
        _ => "ambiguous",
    };
    let mut receipt = json!({
        "adapter":"workspace_reply_admission_read_v1",
        "success":exact,
        "boundary_crossed":true,
        "status":status,
        "match_count":match_count,
        "transaction_sha256":candidate.transaction_sha256,
        "activation_record_sha256":candidate.activation_record_sha256,
        "pre_send_identity_projection_sha256":candidate.projection_sha256,
        "activation_operation_id":candidate.activation_operation_id,
        "cfctl_build_sha256":candidate.cfctl_build_sha256,
        "profile_sha256":candidate.profile_sha256,
        "account_sha256":candidate.account_sha256,
        "credential_generation_sha256":candidate.credential_generation_sha256,
        "observed_at":observed_at,
        "expires_at":candidate.expires_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "wrangler_version":observed_version,
        "provider_output_retained":false,
        "record_content_retained":false,
        "body_returned":false,
    });
    if exact {
        receipt["pre_send_identity_projection"] = candidate.projection.clone();
    } else {
        receipt["failure_code"] = Value::String(
            match status {
                "missing" => "CFCTL_WORKSPACE_D1_REPLY_ADMISSION_READ_NO_MATCH",
                "ambiguous" => "CFCTL_WORKSPACE_D1_REPLY_ADMISSION_READ_AMBIGUOUS",
                _ => "CFCTL_WORKSPACE_D1_REPLY_ADMISSION_READ_BINDING_MISMATCH",
            }
            .to_owned(),
        );
    }
    receipt
}

async fn verify_inner(
    store: &StateStore,
    plan: &PlanV1,
    credential: &AuthCredential,
) -> Result<Value> {
    validate_bound_plan(store, plan)?;
    let contract = plan
        .capability
        .workspace_d1_reply_admission
        .as_ref()
        .ok_or_else(|| CliError::Input("reply-admission contract missing".to_owned()))?;
    let target = target(plan)?;
    let id = candidate_id(store, target)?;
    let sql = format!(
        "SELECT {} FROM {} WHERE id = '{}' LIMIT 2",
        RECORD_COLUMNS.join(","),
        identifier(&contract.admission_table)?,
        escape(&id)
    );
    let rows = workspace_d1_migration::execute_json_query(
        string(target, "database_name")?,
        string(target, "production_config")?,
        &sql,
        Path::new(&contract.repository_root),
        credential,
        &plan.account_id,
        &store.paths().cache_dir,
    )
    .await?;
    let exact = rows.len() == 1
        && hash_json(&Value::Object(rows[0].clone()))
            == string(target, "activation_record_sha256")?;
    Ok(
        json!({"passed":exact,"basis":if exact{"exactly one admitted reply record matched the immutable activation record"}else{"reply admission cardinality or activation-record digest did not match"},
        "match_count":rows.len(),"activation_record_sha256":string(target,"activation_record_sha256")?,"transaction_sha256":string(target,"transaction_sha256")?,
        "logical_activation_id":string(target,"logical_activation_id")?,"cfctl_operation_id":plan.operation_id,"body_returned":false,"provider_output_retained":false,"record_content_retained":false}),
    )
}

struct Candidate {
    source_sha256: String,
    compiled_candidate_sha256: String,
    activation_record_sha256: String,
    projection_sha256: String,
    transaction_sha256: String,
    logical_activation_id: String,
    activation_operation_id: String,
    cfctl_build_sha256: String,
    profile_sha256: String,
    account_sha256: String,
    credential_generation_sha256: String,
    admitted_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    record: Map<String, Value>,
    projection: Value,
}

struct CompilerRuntime {
    executable_bytes: Vec<u8>,
    path_sha256: String,
    executable_sha256: String,
    version: String,
}
#[expect(
    clippy::too_many_lines,
    reason = "the closed candidate boundary keeps envelope, hash, authority, record, and freshness admission visibly contiguous"
)]
fn validate_candidate_bytes(bytes: &[u8]) -> Result<Candidate> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_CANDIDATE_BYTES {
        return Err(CliError::Input(
            "reply-admission candidate exceeds 1 MiB".to_owned(),
        ));
    }
    let v: Value = serde_json::from_slice(bytes)
        .map_err(|_| CliError::Input("reply-admission candidate is not valid JSON".to_owned()))?;
    let o = v
        .as_object()
        .ok_or_else(|| CliError::Input("reply-admission candidate must be an object".to_owned()))?;
    exact_keys(
        o,
        &[
            "kind",
            "schema_version",
            "transaction_sha256",
            "activation_record_sha256",
            "pre_send_identity_projection_sha256",
            "pre_send_identity_projection",
            "source_prerequisites",
            "activation",
            "body_free",
        ],
    )?;
    if o.get("kind").and_then(Value::as_str) != Some("maildesk_reply_admission_candidate")
        || o.get("schema_version").and_then(Value::as_u64) != Some(1)
        || o.get("body_free").and_then(Value::as_bool) != Some(true)
    {
        return Err(CliError::Input(
            "reply-admission candidate envelope is invalid".to_owned(),
        ));
    }
    let source_prerequisites = o
        .get("source_prerequisites")
        .and_then(Value::as_object)
        .ok_or_else(|| CliError::Input("source prerequisites are missing".to_owned()))?;
    exact_keys(source_prerequisites, PREREQUISITE_KEYS)?;
    validate_source_prerequisites(source_prerequisites)?;
    if contains_forbidden_evidence(o.get("source_prerequisites").unwrap_or(&Value::Null)) {
        return Err(CliError::Input(
            "reply-admission source prerequisites contain forbidden content or private identity material"
                .to_owned(),
        ));
    }
    let transaction = digest(o, "transaction_sha256")?;
    let activation_hash = digest(o, "activation_record_sha256")?;
    let projection_hash = digest(o, "pre_send_identity_projection_sha256")?;
    let projection = o
        .get("pre_send_identity_projection")
        .and_then(Value::as_object)
        .ok_or_else(|| CliError::Input("pre-send identity projection missing".to_owned()))?;
    exact_keys(projection, PROJECTION_KEYS)?;
    if projection.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err(CliError::Input(
            "pre-send identity projection schema is invalid".to_owned(),
        ));
    }
    if hash_json(&Value::Object(projection.clone())) != projection_hash {
        return Err(CliError::Input(
            "pre-send identity projection digest mismatch".to_owned(),
        ));
    }
    if projection.get("transaction_sha256").and_then(Value::as_str) != Some(transaction.as_str()) {
        return Err(CliError::Input("transaction binding mismatch".to_owned()));
    }
    let candidate = projection
        .get("candidate")
        .and_then(Value::as_object)
        .ok_or_else(|| CliError::Input("compiled candidate identity missing".to_owned()))?;
    exact_keys(candidate, &["dirty", "head", "tree"])?;
    if candidate.get("dirty") != Some(&Value::Bool(false)) {
        return Err(CliError::Input(
            "compiled candidate is not clean".to_owned(),
        ));
    }
    for k in ["head", "tree"] {
        let s = candidate.get(k).and_then(Value::as_str).unwrap_or("");
        if !lower_hex(s, 40) {
            return Err(CliError::Input(
                "compiled candidate Git identity is invalid".to_owned(),
            ));
        }
    }
    let candidate_hash = projection
        .get("candidate_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("compiled candidate digest missing".to_owned()))?;
    if bare_hex_sha(&canonical_json_bytes(&Value::Object(candidate.clone()))) != candidate_hash {
        return Err(CliError::Input(
            "compiled candidate digest mismatch".to_owned(),
        ));
    }
    let cp = projection
        .get("control_plane")
        .and_then(Value::as_object)
        .ok_or_else(|| CliError::Input("control-plane binding missing".to_owned()))?;
    exact_keys(
        cp,
        &[
            "account_sha256",
            "activation_operation_id",
            "cfctl_build_sha256",
            "credential_generation_sha256",
            "profile_sha256",
        ],
    )?;
    let account_sha256 = digest(cp, "account_sha256")?;
    let cfctl_build_sha256 = digest(cp, "cfctl_build_sha256")?;
    let credential_generation_sha256 = digest(cp, "credential_generation_sha256")?;
    let profile_sha256 = digest(cp, "profile_sha256")?;
    let activation_operation_id = cp
        .get("activation_operation_id")
        .and_then(Value::as_str)
        .filter(|s| safe_ref(s))
        .ok_or_else(|| CliError::Input("activation operation identity is invalid".to_owned()))?
        .to_owned();
    let activation = o
        .get("activation")
        .and_then(Value::as_object)
        .ok_or_else(|| CliError::Input("activation envelope missing".to_owned()))?;
    exact_keys(activation, &["capability_id", "effect", "record"])?;
    if activation.get("capability_id").and_then(Value::as_str)
        != Some("star-maildesk-cf.reply-admission-activate")
        || activation.get("effect").and_then(Value::as_str) != Some("plan_v2_required")
    {
        return Err(CliError::Input(
            "activation authority is invalid".to_owned(),
        ));
    }
    let record = activation
        .get("record")
        .and_then(Value::as_object)
        .ok_or_else(|| CliError::Input("activation record missing".to_owned()))?
        .clone();
    exact_keys(&record, RECORD_COLUMNS)?;
    if hash_json(&Value::Object(record.clone())) != activation_hash {
        return Err(CliError::Input(
            "activation record digest mismatch".to_owned(),
        ));
    }
    if record.get("transaction_sha256").and_then(Value::as_str)
        != Some(transaction.trim_start_matches("sha256:"))
    {
        return Err(CliError::Input(
            "activation record transaction mismatch".to_owned(),
        ));
    }
    validate_record(&record)?;
    let logical_activation_id = record
        .get("id")
        .and_then(Value::as_str)
        .filter(|value| safe_ref(value))
        .ok_or_else(|| CliError::Input("logical activation identity is invalid".to_owned()))?
        .to_owned();
    validate_projection_record_bindings(projection, &record, &transaction)?;
    let admitted_at = timestamp(record.get("admitted_at"), "admitted_at")?;
    let expires_at = timestamp(record.get("expires_at"), "expires_at")?;
    let evidence_observed_at =
        timestamp(record.get("evidence_observed_at"), "evidence_observed_at")?;
    if evidence_observed_at > admitted_at
        || expires_at <= admitted_at
        || expires_at.signed_duration_since(admitted_at).num_seconds() > 15 * 60
    {
        return Err(CliError::Input(
            "reply-admission candidate time ordering is invalid".to_owned(),
        ));
    }
    Ok(Candidate {
        source_sha256: hex_sha(bytes),
        compiled_candidate_sha256: candidate_hash.to_owned(),
        activation_record_sha256: activation_hash,
        projection_sha256: projection_hash,
        transaction_sha256: transaction,
        logical_activation_id,
        activation_operation_id,
        cfctl_build_sha256,
        profile_sha256,
        account_sha256,
        credential_generation_sha256,
        admitted_at,
        expires_at,
        record,
        projection: Value::Object(projection.clone()),
    })
}

fn validate_candidate_fresh(candidate: &Candidate, now: DateTime<Utc>) -> Result<()> {
    if candidate.admitted_at > now + chrono::Duration::seconds(60) || candidate.expires_at <= now {
        return Err(CliError::Input(
            "reply-admission candidate is not inside its admitted lifetime".to_owned(),
        ));
    }
    Ok(())
}

fn validate_source_prerequisites(prerequisites: &Map<String, Value>) -> Result<()> {
    for plane in PREREQUISITE_KEYS {
        let receipt = prerequisites
            .get(*plane)
            .and_then(Value::as_object)
            .ok_or_else(|| {
                CliError::Input(format!(
                    "reply-admission `{plane}` source receipt is missing"
                ))
            })?;
        exact_keys(receipt, SOURCE_RECEIPT_KEYS)?;
        if receipt.get("schema_version").and_then(Value::as_u64) != Some(1)
            || receipt.get("performed").and_then(Value::as_bool) != Some(true)
            || receipt.get("success").and_then(Value::as_bool) != Some(true)
            || receipt.get("body_free").and_then(Value::as_bool) != Some(true)
            || receipt.get("body_returned").and_then(Value::as_bool) != Some(false)
            || receipt
                .get("provider_output_retained")
                .and_then(Value::as_bool)
                != Some(false)
            || receipt.get("match_count").and_then(Value::as_u64) != Some(1)
        {
            return Err(CliError::Input(format!(
                "reply-admission `{plane}` source receipt is not one successful body-free proof"
            )));
        }
        let binding = receipt
            .get("binding")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                CliError::Input(format!(
                    "reply-admission `{plane}` source binding is missing"
                ))
            })?;
        exact_keys(binding, SOURCE_BINDING_KEYS)?;
        let result = receipt
            .get("result")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                CliError::Input(format!(
                    "reply-admission `{plane}` source result is missing"
                ))
            })?;
        let result_keys: &[&str] = match *plane {
            "configured_policy" => &["desired_state_sha256", "policy_sha256", "status"],
            "edge_activation" => &["edge_state_sha256", "status"],
            "sender_domain" => &["sender_domain_sha256", "status"],
            "inbound_acceptance" => &["inbound_delivery_id", "provider_accepted_at", "status"],
            "apple_mail_inbox" => &["inbox_message_id_sha256", "status"],
            "operator_authorization" => {
                &["admitted_operator_sha256", "operator_set_sha256", "status"]
            }
            "opaque_relay" => &["opaque_relay_recipient_sha256", "relay_id", "status"],
            _ => unreachable!("closed prerequisite plane"),
        };
        exact_keys(result, result_keys)?;
    }
    Ok(())
}

fn validate_record(record: &Map<String, Value>) -> Result<()> {
    if record.get("schema_version").and_then(Value::as_u64) != Some(1)
        || record.get("status").and_then(Value::as_str) != Some("admitted")
    {
        return Err(CliError::Input(
            "reply-admission activation state is invalid".to_owned(),
        ));
    }
    for key in [
        "transaction_sha256",
        "correlation_sha256",
        "candidate_sha256",
        "scope_manifest_sha256",
        "policy_sha256",
        "desired_state_sha256",
        "operator_set_sha256",
        "admitted_operator_ref",
        "identity_profile_sha256",
        "signature_sha256",
        "configured_policy_receipt_sha256",
        "edge_activation_receipt_sha256",
        "sender_domain_receipt_sha256",
        "inbound_acceptance_receipt_sha256",
        "apple_mail_inbox_receipt_sha256",
        "operator_authorization_receipt_sha256",
        "opaque_relay_receipt_sha256",
        "evidence_bundle_sha256",
    ] {
        let value = record.get(key).and_then(Value::as_str).unwrap_or_default();
        if !lower_hex(value, 64) {
            return Err(CliError::Input(format!(
                "reply-admission activation field `{key}` is not a bare SHA-256"
            )));
        }
    }
    for key in [
        "id",
        "inbound_delivery_id",
        "relay_id",
        "thread_id",
        "route_id",
        "identity_profile_ref",
        "signature_profile_ref",
    ] {
        if !record
            .get(key)
            .and_then(Value::as_str)
            .is_some_and(safe_ref)
        {
            return Err(CliError::Input(format!(
                "reply-admission activation reference `{key}` is invalid"
            )));
        }
    }
    let public_identity = record
        .get("public_identity")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let sender_domain = record
        .get("sender_domain")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if public_identity != public_identity.to_ascii_lowercase()
        || sender_domain != sender_domain.to_ascii_lowercase()
        || !valid_domain(sender_domain)
        || !public_identity
            .strip_suffix(sender_domain)
            .is_some_and(|local| local.ends_with('@') && local.len() > 1)
        || public_identity
            .bytes()
            .any(|byte| matches!(byte, b'\r' | b'\n'))
    {
        return Err(CliError::Input(
            "reply-admission public identity is invalid".to_owned(),
        ));
    }
    let display_name = record
        .get("display_name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if display_name.is_empty()
        || display_name.len() > 160
        || display_name.trim() != display_name
        || display_name
            .bytes()
            .any(|byte| matches!(byte, b'\r' | b'\n'))
    {
        return Err(CliError::Input(
            "reply-admission display name is invalid".to_owned(),
        ));
    }
    if !matches!(
        record.get("sender_adapter").and_then(Value::as_str),
        Some("cloudflare_email_service" | "resend")
    ) {
        return Err(CliError::Input(
            "reply-admission sender adapter is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn validate_projection_record_bindings(
    projection: &Map<String, Value>,
    record: &Map<String, Value>,
    transaction: &str,
) -> Result<()> {
    let expected_id = format!("reply-admission:{}", &transaction[7..39]);
    if record.get("id").and_then(Value::as_str) != Some(expected_id.as_str()) {
        return Err(CliError::Input(
            "reply-admission activation ID is not derived from its transaction".to_owned(),
        ));
    }
    for (record_key, projection_key) in [
        ("candidate_sha256", "candidate_sha256"),
        ("inbound_delivery_id", "inbound_delivery_id"),
        ("relay_id", "relay_id"),
        ("thread_id", "thread_id"),
        ("route_id", "route_id"),
        ("public_identity", "public_identity"),
        ("sender_domain", "sender_domain"),
        ("identity_profile_ref", "identity_profile_ref"),
        ("display_name", "display_name"),
        ("signature_profile_ref", "signature_profile_ref"),
        ("sender_adapter", "sender_adapter"),
        ("evidence_observed_at", "evidence_observed_at"),
        ("admitted_at", "admitted_at"),
        ("expires_at", "expires_at"),
    ] {
        if record.get(record_key) != projection.get(projection_key) {
            return Err(CliError::Input(format!(
                "reply-admission `{record_key}` projection binding mismatch"
            )));
        }
    }
    for (record_key, projection_key) in [
        ("transaction_sha256", "transaction_sha256"),
        ("correlation_sha256", "correlation_sha256"),
        ("scope_manifest_sha256", "scope_manifest_sha256"),
        ("policy_sha256", "policy_sha256"),
        ("desired_state_sha256", "desired_state_sha256"),
        ("operator_set_sha256", "operator_set_sha256"),
        ("admitted_operator_ref", "admitted_operator_sha256"),
        ("identity_profile_sha256", "identity_profile_sha256"),
        ("signature_sha256", "signature_sha256"),
        ("evidence_bundle_sha256", "evidence_bundle_sha256"),
    ] {
        let projected = projection
            .get(projection_key)
            .and_then(Value::as_str)
            .and_then(|value| value.strip_prefix("sha256:"));
        if record.get(record_key).and_then(Value::as_str) != projected {
            return Err(CliError::Input(format!(
                "reply-admission `{record_key}` digest binding mismatch"
            )));
        }
    }
    let prerequisites = projection
        .get("prerequisites")
        .and_then(Value::as_object)
        .ok_or_else(|| CliError::Input("reply-admission prerequisites are missing".to_owned()))?;
    exact_keys(prerequisites, PREREQUISITE_KEYS)?;
    for (plane, record_key) in [
        ("configured_policy", "configured_policy_receipt_sha256"),
        ("edge_activation", "edge_activation_receipt_sha256"),
        ("sender_domain", "sender_domain_receipt_sha256"),
        ("inbound_acceptance", "inbound_acceptance_receipt_sha256"),
        ("apple_mail_inbox", "apple_mail_inbox_receipt_sha256"),
        (
            "operator_authorization",
            "operator_authorization_receipt_sha256",
        ),
        ("opaque_relay", "opaque_relay_receipt_sha256"),
    ] {
        let receipt = prerequisites
            .get(plane)
            .and_then(Value::as_object)
            .ok_or_else(|| CliError::Input(format!("reply-admission `{plane}` receipt missing")))?;
        exact_keys(
            receipt,
            &[
                "receipt_kind",
                "receipt_sha256",
                "observed_at",
                "expires_at",
                "binding",
            ],
        )?;
        let receipt_sha = receipt
            .get("receipt_sha256")
            .and_then(Value::as_str)
            .and_then(|value| value.strip_prefix("sha256:"));
        if record.get(record_key).and_then(Value::as_str) != receipt_sha {
            return Err(CliError::Input(format!(
                "reply-admission `{plane}` receipt digest binding mismatch"
            )));
        }
    }
    Ok(())
}

fn timestamp(value: Option<&Value>, label: &str) -> Result<DateTime<Utc>> {
    let text = value
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input(format!("reply-admission {label} timestamp is missing")))?;
    let parsed = DateTime::parse_from_rfc3339(text)
        .map_err(|_| CliError::Input(format!("reply-admission {label} timestamp is invalid")))?
        .with_timezone(&Utc);
    if parsed.to_rfc3339_opts(chrono::SecondsFormat::Millis, true) != text {
        return Err(CliError::Input(format!(
            "reply-admission {label} timestamp is not canonical"
        )));
    }
    Ok(parsed)
}

fn validate_control_plane_binding(
    candidate: &Candidate,
    profile: &ProfileMetadata,
    account_id: &str,
    generation: &str,
) -> Result<()> {
    let executable = std::env::current_exe().map_err(|error| {
        CliError::Input(format!("cfctl executable identity is unavailable: {error}"))
    })?;
    let executable_bytes =
        fs::read(&executable).map_err(|error| super::cli_io(&executable, error))?;
    for (label, actual, expected) in [
        (
            "cfctl build",
            hex_sha(&executable_bytes),
            candidate.cfctl_build_sha256.as_str(),
        ),
        (
            "profile",
            hex_sha(profile.id.as_bytes()),
            candidate.profile_sha256.as_str(),
        ),
        (
            "account",
            hex_sha(account_id.as_bytes()),
            candidate.account_sha256.as_str(),
        ),
        (
            "credential generation",
            hex_sha(generation.as_bytes()),
            candidate.credential_generation_sha256.as_str(),
        ),
    ] {
        if actual != expected {
            return Err(CliError::Input(format!(
                "reply-admission candidate {label} binding does not match the selected control plane"
            )));
        }
    }
    Ok(())
}
fn insert_sql(table: &str, record: &Map<String, Value>) -> Result<String> {
    let values = RECORD_COLUMNS
        .iter()
        .map(|k| {
            sql_value(
                record
                    .get(*k)
                    .ok_or_else(|| CliError::Input("activation record field missing".to_owned()))?,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(format!(
        "INSERT INTO {} ({}) VALUES ({});",
        identifier(table)?,
        RECORD_COLUMNS.join(","),
        values.join(",")
    ))
}

fn compiler_runtime(
    store: &StateStore,
    contract: &WorkspaceD1ReplyAdmissionContractV1,
) -> Result<CompilerRuntime> {
    if contract.compiler_runtime != "bun" {
        return Err(CliError::Input(
            "reply-admission compiler runtime is not supported".to_owned(),
        ));
    }
    let discovered = which::which(&contract.compiler_runtime).map_err(|_| {
        CliError::Input("reply-admission compiler runtime is unavailable".to_owned())
    })?;
    let executable =
        fs::canonicalize(&discovered).map_err(|error| super::cli_io(&discovered, error))?;
    let metadata = fs::metadata(&executable).map_err(|error| super::cli_io(&executable, error))?;
    if !metadata.is_file() {
        return Err(CliError::Input(
            "reply-admission compiler runtime is not a regular file".to_owned(),
        ));
    }
    let executable_bytes =
        fs::read(&executable).map_err(|error| super::cli_io(&executable, error))?;
    let executable_sha256 = hex_sha(&executable_bytes);
    if executable_sha256 != contract.compiler_runtime_sha256 {
        return Err(CliError::Input(
            "reply-admission compiler runtime digest drifted".to_owned(),
        ));
    }
    let version_directory = store
        .paths()
        .data_dir
        .join("private-operation-stages")
        .join(uuid::Uuid::new_v4().to_string());
    fs::create_dir_all(&version_directory)
        .map_err(|error| super::cli_io(&version_directory, error))?;
    #[cfg(unix)]
    fs::set_permissions(&version_directory, fs::Permissions::from_mode(0o700))
        .map_err(|error| super::cli_io(&version_directory, error))?;
    let staged_runtime = version_directory.join("bun");
    let version_output = (|| {
        write_private_executable(&staged_runtime, &executable_bytes)?;
        bounded_output(
            Command::new(&staged_runtime).env_clear().arg("--version"),
            "compiler runtime version",
        )
    })();
    let _ = fs::remove_file(&staged_runtime);
    let _ = fs::remove_dir(&version_directory);
    let version_output = version_output?;
    if !version_output.status.success() || version_output.stdout.len() > 64 {
        return Err(CliError::Input(
            "reply-admission compiler runtime version is invalid".to_owned(),
        ));
    }
    let version = std::str::from_utf8(&version_output.stdout)
        .map_err(|_| {
            CliError::Input("reply-admission compiler runtime version is invalid".to_owned())
        })?
        .trim()
        .to_owned();
    if version != contract.compiler_runtime_version {
        return Err(CliError::Input(format!(
            "reply-admission compiler requires {} {}, observed {version}",
            contract.compiler_runtime, contract.compiler_runtime_version
        )));
    }
    Ok(CompilerRuntime {
        path_sha256: hex_sha(executable.as_os_str().as_encoded_bytes()),
        executable_sha256,
        executable_bytes,
        version,
    })
}

fn compile_private_candidate(
    store: &StateStore,
    contract: &WorkspaceD1ReplyAdmissionContractV1,
    source: &Path,
    runtime: &CompilerRuntime,
) -> Result<Vec<u8>> {
    let source_bytes = read_private_candidate(source)?;
    let input_stage = stage_private_candidate(store, &source_bytes)?;
    let input_stage = input_stage
        .as_object()
        .ok_or_else(|| CliError::Input("private compiler input stage is invalid".to_owned()))?;
    let input_path = private_stage_path(store, input_stage)?;
    let directory = input_path
        .parent()
        .ok_or_else(|| CliError::Input("private compiler stage has no directory".to_owned()))?
        .to_path_buf();
    let output_path = directory.join("d1-reply-admission-compiled.json");
    let staged_compiler_path = directory.join("reply-admission-compiler.ts");
    let staged_runtime_path = directory.join("bun");
    let compiled = (|| {
        let compiler_path = Path::new(&contract.repository_root).join(&contract.compiler_path);
        let compiler_bytes = read_compiler_bytes(&compiler_path, &contract.compiler_sha256)?;
        write_private_file(&staged_compiler_path, &compiler_bytes)?;
        write_private_executable(&staged_runtime_path, &runtime.executable_bytes)?;
        let result = bounded_output(
            Command::new(&staged_runtime_path)
                .env_clear()
                .env("NO_COLOR", "1")
                .current_dir(&contract.repository_root)
                .arg(&staged_compiler_path)
                .arg("--input")
                .arg(&input_path)
                .arg("--out")
                .arg(&output_path),
            "compiler execution",
        );
        match result {
            Ok(output) if output.status.success() => read_private_candidate(&output_path),
            Ok(_) => Err(CliError::Input(
                "reply-admission compiler rejected the private input".to_owned(),
            )),
            Err(_) => Err(CliError::Input(
                "reply-admission compiler could not be executed".to_owned(),
            )),
        }
    })();
    let _ = fs::remove_file(&output_path);
    let _ = fs::remove_file(&staged_compiler_path);
    let _ = fs::remove_file(&staged_runtime_path);
    let _ = fs::remove_file(&input_path);
    let _ = fs::remove_dir(&directory);
    compiled
}

fn read_compiler_bytes(path: &Path, expected_sha256: &str) -> Result<Vec<u8>> {
    reject_symlink_components(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let mut file = options
        .open(path)
        .map_err(|error| super::cli_io(path, error))?;
    let metadata = file
        .metadata()
        .map_err(|error| super::cli_io(path, error))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_CANDIDATE_BYTES {
        return Err(CliError::Input(
            "reply-admission compiler must be a non-empty regular file of at most 1 MiB".to_owned(),
        ));
    }
    let mut bytes =
        Vec::with_capacity(usize::try_from(metadata.len()).map_err(|_| {
            CliError::Input("reply-admission compiler exceeds this host".to_owned())
        })?);
    file.read_to_end(&mut bytes)
        .map_err(|error| super::cli_io(path, error))?;
    if bytes.len() as u64 != metadata.len() || hex_sha(&bytes) != expected_sha256 {
        return Err(CliError::Input(
            "reply-admission compiler bytes drifted before private staging".to_owned(),
        ));
    }
    Ok(bytes)
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    write_private_file_with_mode(path, bytes, 0o600)
}

fn write_private_executable(path: &Path, bytes: &[u8]) -> Result<()> {
    write_private_file_with_mode(path, bytes, 0o700)
}

fn write_private_file_with_mode(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(mode).custom_flags(libc::O_NOFOLLOW);
    let mut file = options
        .open(path)
        .map_err(|error| super::cli_io(path, error))?;
    file.write_all(bytes)
        .map_err(|error| super::cli_io(path, error))?;
    file.sync_all().map_err(|error| super::cli_io(path, error))
}

fn bounded_output(command: &mut Command, label: &str) -> Result<Output> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|_| CliError::Input(format!("reply-admission {label} could not be started")))?;
    let deadline = Instant::now() + StdDuration::from_secs(10);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                return child.wait_with_output().map_err(|_| {
                    CliError::Input(format!("reply-admission {label} could not be collected"))
                });
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(StdDuration::from_millis(10)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(CliError::Input(format!(
                    "reply-admission {label} exceeded 10 seconds"
                )));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(CliError::Input(format!(
                    "reply-admission {label} status is unavailable"
                )));
            }
        }
    }
}

fn sql_value(v: &Value) -> Result<String> {
    match v {
        Value::String(s) => Ok(format!("'{}'", escape(s))),
        Value::Number(n) => Ok(n.to_string()),
        _ => Err(CliError::Input(
            "activation record contains a non-scalar field".to_owned(),
        )),
    }
}
fn private_sql(store: &StateStore, sql: &str) -> Result<PathBuf> {
    let p = store
        .paths()
        .cache_dir
        .join(format!("reply-admission-{}.sql", uuid::Uuid::new_v4()));
    let mut o = std::fs::OpenOptions::new();
    o.write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW);
    let mut file = o.open(&p).map_err(|e| super::cli_io(&p, e))?;
    std::io::Write::write_all(&mut file, sql.as_bytes()).map_err(|e| super::cli_io(&p, e))?;
    file.sync_all().map_err(|e| super::cli_io(&p, e))?;
    if fs::metadata(&p)
        .map_err(|e| super::cli_io(&p, e))?
        .permissions()
        .mode()
        & 0o077
        != 0
    {
        return Err(CliError::Input(
            "private SQL stage permissions drifted".to_owned(),
        ));
    }
    Ok(p)
}

fn read_private_candidate(path: &Path) -> Result<Vec<u8>> {
    reject_symlink_components(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let mut file = options
        .open(path)
        .map_err(|error| super::cli_io(path, error))?;
    let metadata = file
        .metadata()
        .map_err(|error| super::cli_io(path, error))?;
    #[cfg(unix)]
    let private_mode = metadata.permissions().mode() & 0o777 == 0o600;
    #[cfg(not(unix))]
    let private_mode = true;
    if !metadata.is_file()
        || !private_mode
        || metadata.len() == 0
        || metadata.len() > MAX_CANDIDATE_BYTES
    {
        return Err(CliError::Input(format!(
            "reply-admission candidate must be a non-empty mode-0600 regular file of at most {MAX_CANDIDATE_BYTES} bytes"
        )));
    }
    let mut bytes =
        Vec::with_capacity(usize::try_from(metadata.len()).map_err(|_| {
            CliError::Input("reply-admission candidate exceeds this host".to_owned())
        })?);
    file.read_to_end(&mut bytes)
        .map_err(|error| super::cli_io(path, error))?;
    if bytes.len() as u64 != metadata.len() {
        return Err(CliError::Input(
            "reply-admission candidate changed while it was read".to_owned(),
        ));
    }
    Ok(bytes)
}

fn stage_private_candidate(store: &StateStore, bytes: &[u8]) -> Result<Value> {
    let stage_id = uuid::Uuid::new_v4().to_string();
    let directory = store
        .paths()
        .data_dir
        .join("private-operation-stages")
        .join(&stage_id);
    fs::create_dir_all(&directory).map_err(|error| super::cli_io(&directory, error))?;
    #[cfg(unix)]
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .map_err(|error| super::cli_io(&directory, error))?;
    let path = directory.join("d1-reply-admission-candidate.json");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    let mut file = options
        .open(&path)
        .map_err(|error| super::cli_io(&path, error))?;
    file.write_all(bytes)
        .map_err(|error| super::cli_io(&path, error))?;
    file.sync_all()
        .map_err(|error| super::cli_io(&path, error))?;
    let stage = json!({
        "schema_version":1,
        "stage_id":stage_id,
        "sha256":hex_sha(bytes),
        "bytes":bytes.len(),
        "unix_mode":if cfg!(unix) { Value::String("0600".to_owned()) } else { Value::Null },
        "content_in_plan":false,
        "path_in_plan":false,
    });
    validate_private_stage_object(
        store,
        stage
            .as_object()
            .ok_or_else(|| CliError::Input("private candidate stage is invalid".to_owned()))?,
    )?;
    Ok(stage)
}

fn validate_private_stage(store: &StateStore, target: &Map<String, Value>) -> Result<()> {
    validate_private_stage_object(store, stage(target)?)
}

fn validate_private_stage_object(store: &StateStore, stage: &Map<String, Value>) -> Result<()> {
    exact_keys(
        stage,
        &[
            "schema_version",
            "stage_id",
            "sha256",
            "bytes",
            "unix_mode",
            "content_in_plan",
            "path_in_plan",
        ],
    )?;
    if stage.get("schema_version").and_then(Value::as_u64) != Some(1)
        || stage.get("content_in_plan").and_then(Value::as_bool) != Some(false)
        || stage.get("path_in_plan").and_then(Value::as_bool) != Some(false)
    {
        return Err(CliError::Input(
            "private reply-admission stage contract is invalid".to_owned(),
        ));
    }
    let bytes = read_private_candidate(&private_stage_path(store, stage)?)?;
    if stage.get("bytes").and_then(Value::as_u64) != Some(bytes.len() as u64)
        || stage.get("sha256").and_then(Value::as_str) != Some(hex_sha(&bytes).as_str())
    {
        return Err(CliError::Input(
            "private reply-admission stage digest drifted; create a new plan".to_owned(),
        ));
    }
    Ok(())
}

fn private_stage_path(store: &StateStore, stage: &Map<String, Value>) -> Result<PathBuf> {
    let stage_id = string(stage, "stage_id")?;
    let parsed = uuid::Uuid::parse_str(stage_id)
        .map_err(|_| CliError::Input("private reply-admission stage ID is invalid".to_owned()))?;
    if parsed.hyphenated().to_string() != stage_id {
        return Err(CliError::Input(
            "private reply-admission stage ID is not canonical".to_owned(),
        ));
    }
    Ok(store
        .paths()
        .data_dir
        .join("private-operation-stages")
        .join(stage_id)
        .join("d1-reply-admission-candidate.json"))
}

fn reject_symlink_components(path: &Path) -> Result<()> {
    let mut cursor = PathBuf::new();
    for component in path.components() {
        if matches!(component, Component::ParentDir | Component::CurDir) {
            return Err(CliError::Input(
                "reply-admission candidate path is not normalized".to_owned(),
            ));
        }
        cursor.push(component.as_os_str());
        let metadata =
            fs::symlink_metadata(&cursor).map_err(|error| super::cli_io(&cursor, error))?;
        if metadata.file_type().is_symlink() {
            return Err(CliError::Input(format!(
                "reply-admission candidate path has symlink component `{}`",
                cursor.display()
            )));
        }
    }
    Ok(())
}

fn candidate_id(store: &StateStore, target: &Map<String, Value>) -> Result<String> {
    let b = read_private_candidate(&private_stage_path(store, stage(target)?)?)?;
    Ok(validate_candidate_bytes(&b)?
        .record
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input("activation id missing".to_owned()))?
        .to_owned())
}
fn target(p: &PlanV1) -> Result<&Map<String, Value>> {
    p.targets
        .get("adapter")
        .and_then(|v| v.get(TARGET_KEY))
        .and_then(Value::as_object)
        .ok_or_else(|| CliError::Input("reply-admission plan target missing".to_owned()))
}
fn stage(t: &Map<String, Value>) -> Result<&Map<String, Value>> {
    t.get("private_stage")
        .and_then(Value::as_object)
        .ok_or_else(|| CliError::Input("private reply-admission stage missing".to_owned()))
}
fn require(t: &Map<String, Value>, k: &str, e: &str) -> Result<()> {
    if t.get(k).and_then(Value::as_str) == Some(e) {
        Ok(())
    } else {
        Err(CliError::Input(format!(
            "reply-admission plan {k} drifted; create a new plan"
        )))
    }
}
fn string<'a>(t: &'a Map<String, Value>, k: &str) -> Result<&'a str> {
    t.get(k)
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Input(format!("reply-admission target omitted {k}")))
}
fn exact_keys(o: &Map<String, Value>, keys: &[&str]) -> Result<()> {
    if o.keys().map(String::as_str).collect::<BTreeSet<_>>() == keys.iter().copied().collect() {
        Ok(())
    } else {
        Err(CliError::Input(
            "reply-admission object shape is invalid".to_owned(),
        ))
    }
}
fn digest(o: &Map<String, Value>, k: &str) -> Result<String> {
    let s = o.get(k).and_then(Value::as_str).unwrap_or("");
    if s.len() != 71 || !s.starts_with("sha256:") || !lower_hex(&s[7..], 64) {
        Err(CliError::Input(format!("reply-admission {k} is invalid")))
    } else {
        Ok(s.to_owned())
    }
}
fn hash_json(v: &Value) -> String {
    hex_sha(&canonical_json_bytes(v))
}
fn hex_sha(b: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(b)))
}
fn bare_hex_sha(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
fn canonical_json_bytes(value: &Value) -> Vec<u8> {
    fn append(value: &Value, output: &mut String) {
        match value {
            Value::Object(object) => {
                output.push('{');
                for (index, key) in object
                    .keys()
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .enumerate()
                {
                    if index > 0 {
                        output.push(',');
                    }
                    output.push_str(&serde_json::to_string(key).unwrap_or_default());
                    output.push(':');
                    append(&object[key], output);
                }
                output.push('}');
            }
            Value::Array(values) => {
                output.push('[');
                for (index, item) in values.iter().enumerate() {
                    if index > 0 {
                        output.push(',');
                    }
                    append(item, output);
                }
                output.push(']');
            }
            _ => output.push_str(&serde_json::to_string(value).unwrap_or_default()),
        }
    }
    let mut output = String::new();
    append(value, &mut output);
    output.into_bytes()
}
fn lower_hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn safe_ref(s: &str) -> bool {
    (1..=240).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'.' | b'_' | b'-' | b'/'))
}
fn valid_domain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && !value.starts_with('.')
        && !value.ends_with('.')
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
}
fn contains_forbidden_evidence(value: &Value) -> bool {
    const FORBIDDEN_KEYS: &[&str] = &[
        "subject",
        "body",
        "attachments",
        "raw_mime",
        "message_id",
        "private_address",
        "operator_address",
        "workspace_address",
        "api_token",
        "token",
        "password",
    ];
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            FORBIDDEN_KEYS.contains(&key.as_str()) || contains_forbidden_evidence(value)
        }),
        Value::Array(values) => values.iter().any(contains_forbidden_evidence),
        Value::String(value) => value.contains('@'),
        _ => false,
    }
}
fn identifier(s: &str) -> Result<&str> {
    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        Ok(s)
    } else {
        Err(CliError::Input(
            "unsafe reply-admission identifier".to_owned(),
        ))
    }
}
fn escape(s: &str) -> String {
    s.replace('\'', "''")
}
fn config_contract(
    c: &cfctl_core::WorkspaceD1ReplyAdmissionContractV1,
) -> cfctl_core::WorkspaceD1MigrationContractV1 {
    cfctl_core::WorkspaceD1MigrationContractV1 {
        repository_root: c.repository_root.clone(),
        repository_head: c.repository_head.clone(),
        repository_origin: c.repository_origin.clone(),
        operation_pack_path: c.operation_pack_path.clone(),
        operation_pack_sha256: c.operation_pack_sha256.clone(),
        config_template_path: c.config_template_path.clone(),
        config_template_sha256: c.config_template_sha256.clone(),
        production_config_path: c.production_config_path.clone(),
        migrations_dir: String::new(),
        database_binding: c.database_binding.clone(),
        wrangler_version: c.wrangler_version.clone(),
        migrations: vec![],
        assertions: vec![],
        recovery_capability_id: c.recovery_capability_id.clone(),
        recovery_max_age_seconds: c.recovery_max_age_seconds,
        rollback_capability_id: c.rollback_capability_id.clone(),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::super::RuntimePaths;

    use super::*;

    fn prefixed(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the fixture intentionally spells the complete closed Maildesk candidate contract"
    )]
    fn candidate() -> Value {
        let transaction = prefixed('1');
        let candidate = json!({"dirty":false,"head":"a".repeat(40),"tree":"b".repeat(40)});
        let candidate_sha = bare_hex_sha(&canonical_json_bytes(&candidate));
        let receipt = |byte: char| {
            json!({
                "receipt_kind":"body_free_test_receipt",
                "receipt_sha256":prefixed(byte),
                "observed_at":"2030-01-01T00:00:00.000Z",
                "expires_at":"2030-01-01T00:15:00.000Z",
                "binding":{},
            })
        };
        let prerequisites = json!({
            "configured_policy":receipt('a'),
            "edge_activation":receipt('b'),
            "sender_domain":receipt('c'),
            "inbound_acceptance":receipt('d'),
            "apple_mail_inbox":receipt('e'),
            "operator_authorization":receipt('f'),
            "opaque_relay":receipt('0'),
        });
        let projection = json!({
            "schema_version":1,
            "transaction_sha256":transaction,
            "candidate":candidate,
            "candidate_sha256":candidate_sha,
            "control_plane":{
                "account_sha256":prefixed('2'),
                "activation_operation_id":"controller:activation:one",
                "cfctl_build_sha256":prefixed('3'),
                "credential_generation_sha256":prefixed('4'),
                "profile_sha256":prefixed('5'),
            },
            "correlation_sha256":prefixed('6'),
            "scope_manifest_sha256":prefixed('7'),
            "inbound_delivery_id":"inbound:one",
            "relay_id":"relay:one",
            "thread_id":"thread:one",
            "route_id":"route:one",
            "policy_sha256":prefixed('8'),
            "desired_state_sha256":prefixed('9'),
            "operator_set_sha256":prefixed('a'),
            "admitted_operator_sha256":prefixed('b'),
            "public_identity":"security@example.com",
            "sender_domain":"example.com",
            "identity_profile_ref":"identity:one",
            "identity_profile_sha256":prefixed('c'),
            "display_name":"Example Security",
            "signature_profile_ref":"signature:one",
            "signature_sha256":prefixed('d'),
            "sender_adapter":"cloudflare_email_service",
            "prerequisites":prerequisites,
            "evidence_bundle_sha256":prefixed('e'),
            "evidence_observed_at":"2030-01-01T00:00:00.000Z",
            "admitted_at":"2030-01-01T00:01:00.000Z",
            "expires_at":"2030-01-01T00:15:00.000Z",
        });
        let record = json!({
            "id":format!("reply-admission:{}", "1".repeat(32)),
            "schema_version":1,
            "transaction_sha256":"1".repeat(64),
            "correlation_sha256":"6".repeat(64),
            "candidate_sha256":candidate_sha,
            "scope_manifest_sha256":"7".repeat(64),
            "inbound_delivery_id":"inbound:one",
            "relay_id":"relay:one",
            "thread_id":"thread:one",
            "route_id":"route:one",
            "policy_sha256":"8".repeat(64),
            "desired_state_sha256":"9".repeat(64),
            "operator_set_sha256":"a".repeat(64),
            "admitted_operator_ref":"b".repeat(64),
            "public_identity":"security@example.com",
            "sender_domain":"example.com",
            "identity_profile_ref":"identity:one",
            "identity_profile_sha256":"c".repeat(64),
            "display_name":"Example Security",
            "signature_profile_ref":"signature:one",
            "signature_sha256":"d".repeat(64),
            "sender_adapter":"cloudflare_email_service",
            "configured_policy_receipt_sha256":"a".repeat(64),
            "edge_activation_receipt_sha256":"b".repeat(64),
            "sender_domain_receipt_sha256":"c".repeat(64),
            "inbound_acceptance_receipt_sha256":"d".repeat(64),
            "apple_mail_inbox_receipt_sha256":"e".repeat(64),
            "operator_authorization_receipt_sha256":"f".repeat(64),
            "opaque_relay_receipt_sha256":"0".repeat(64),
            "evidence_bundle_sha256":"e".repeat(64),
            "evidence_observed_at":"2030-01-01T00:00:00.000Z",
            "admitted_at":"2030-01-01T00:01:00.000Z",
            "expires_at":"2030-01-01T00:15:00.000Z",
            "status":"admitted",
        });
        let source_binding = json!({
            "correlation_sha256":prefixed('6'),"scope_manifest_sha256":prefixed('7'),
            "inbound_delivery_id":"inbound:one","relay_id":"relay:one","thread_id":"thread:one",
            "route_id":"route:one","policy_sha256":prefixed('8'),"desired_state_sha256":prefixed('9'),
            "operator_set_sha256":prefixed('a'),"admitted_operator_sha256":prefixed('b'),
            "identity_profile_sha256":prefixed('c'),
        });
        let source_receipt = |plane: &str, result: Value| {
            json!({
                "adapter":format!("workspace_{plane}_v1"),"authority_sha256":prefixed('1'),
                "binding":source_binding,"body_free":true,"body_returned":false,
                "candidate_sha256":candidate_sha,"capability_id":format!("maildesk.{plane}"),
                "control_plane_sha256":prefixed('2'),"expires_at":"2030-01-01T00:15:00.000Z",
                "kind":format!("maildesk_{plane}_receipt"),"match_count":1,
                "observed_at":"2030-01-01T00:00:00.000Z","operation_id":format!("operation:{plane}"),
                "performed":true,"provider_output_retained":false,"result":result,
                "schema_version":1,"success":true,
            })
        };
        let source_prerequisites = json!({
            "configured_policy":source_receipt("configured_policy",json!({"desired_state_sha256":prefixed('9'),"policy_sha256":prefixed('8'),"status":"configured"})),
            "edge_activation":source_receipt("edge_activation",json!({"edge_state_sha256":prefixed('3'),"status":"active"})),
            "sender_domain":source_receipt("sender_domain",json!({"sender_domain_sha256":prefixed('4'),"status":"verified"})),
            "inbound_acceptance":source_receipt("inbound_acceptance",json!({"inbound_delivery_id":"inbound:one","provider_accepted_at":"2030-01-01T00:00:00.000Z","status":"accepted"})),
            "apple_mail_inbox":source_receipt("apple_mail_inbox",json!({"inbox_message_id_sha256":prefixed('5'),"status":"received"})),
            "operator_authorization":source_receipt("operator_authorization",json!({"admitted_operator_sha256":prefixed('b'),"operator_set_sha256":prefixed('a'),"status":"authorized"})),
            "opaque_relay":source_receipt("opaque_relay",json!({"opaque_relay_recipient_sha256":prefixed('0'),"relay_id":"relay:one","status":"authorized"})),
        });
        json!({
            "kind":"maildesk_reply_admission_candidate","schema_version":1,
            "transaction_sha256":transaction,
            "activation_record_sha256":hash_json(&record),
            "pre_send_identity_projection_sha256":hash_json(&projection),
            "pre_send_identity_projection":projection,"source_prerequisites":source_prerequisites,
            "activation":{"capability_id":"star-maildesk-cf.reply-admission-activate","effect":"plan_v2_required","record":record},
            "body_free":true,
        })
    }

    #[test]
    fn compiled_candidate_binds_distinct_logical_activation_and_hashes() {
        let bytes = serde_json::to_vec(&candidate()).expect("candidate bytes");
        let admitted = validate_candidate_bytes(&bytes).expect("valid candidate");
        assert_eq!(
            admitted.logical_activation_id,
            format!("reply-admission:{}", "1".repeat(32))
        );
        assert_eq!(
            admitted.activation_operation_id,
            "controller:activation:one"
        );
        assert_ne!(
            admitted.logical_activation_id,
            "00000000-0000-4000-8000-000000000000"
        );
        assert_eq!(admitted.source_sha256, hex_sha(&bytes));
        let sql = insert_sql("reply_admissions", &admitted.record).expect("compiler SQL");
        assert!(sql.starts_with("INSERT INTO reply_admissions"));
        assert!(!sql.contains("controller:activation:one"));
    }

    #[test]
    fn candidate_tampering_and_caller_sql_fail_closed() {
        let mut value = candidate();
        value["activation"]["record"]["status"] = Value::String("revoked".to_owned());
        assert!(validate_candidate_bytes(&serde_json::to_vec(&value).expect("bytes")).is_err());
        let mut value = candidate();
        value["sql"] = Value::String("DELETE FROM reply_admissions".to_owned());
        assert!(validate_candidate_bytes(&serde_json::to_vec(&value).expect("bytes")).is_err());

        let mut value = candidate();
        value["pre_send_identity_projection"]["candidate_sha256"] = Value::String(prefixed('f'));
        value["pre_send_identity_projection_sha256"] =
            Value::String(hash_json(&value["pre_send_identity_projection"]));
        assert!(validate_candidate_bytes(&serde_json::to_vec(&value).expect("bytes")).is_err());

        let mut value = candidate();
        value["source_prerequisites"]["configured_policy"]["private_address"] =
            Value::String("operator@example.net".to_owned());
        assert!(validate_candidate_bytes(&serde_json::to_vec(&value).expect("bytes")).is_err());
    }

    #[test]
    fn read_projection_requires_one_exact_active_record_and_retains_no_provider_row() {
        let bytes = serde_json::to_vec(&candidate()).expect("candidate bytes");
        let admitted = validate_candidate_bytes(&bytes).expect("valid candidate");
        let exact_row = admitted.record.clone();
        let success = project_read_receipt(
            &admitted,
            std::slice::from_ref(&exact_row),
            "2030-01-01T00:02:00.000Z",
            "4.120.1",
        );
        assert!(read_receipt_is_complete(&success));
        assert_eq!(success["status"], "active");
        assert_eq!(success["match_count"], 1);
        assert_eq!(
            success["activation_operation_id"],
            "controller:activation:one"
        );
        assert_eq!(success["provider_output_retained"], false);
        assert_eq!(success["record_content_retained"], false);
        assert_eq!(success["body_returned"], false);
        let encoded = success.to_string();
        assert!(!encoded.contains("claimed_attempt_id"));
        assert!(!encoded.contains("provider_boundary_at"));
        let mut expanded = success.clone();
        expanded["provider_payload"] = json!({"forbidden":true});
        assert!(!read_receipt_is_complete(&expanded));

        let missing = project_read_receipt(&admitted, &[], "2030-01-01T00:02:00.000Z", "4.120.1");
        assert!(!read_receipt_is_complete(&missing));
        assert_eq!(missing["status"], "missing");
        assert_eq!(missing["match_count"], 0);
        assert!(missing.get("pre_send_identity_projection").is_none());

        let multiple = project_read_receipt(
            &admitted,
            &[exact_row.clone(), exact_row],
            "2030-01-01T00:02:00.000Z",
            "4.120.1",
        );
        assert!(!read_receipt_is_complete(&multiple));
        assert_eq!(multiple["status"], "ambiguous");
        assert_eq!(multiple["match_count"], 2);
        assert!(multiple.get("pre_send_identity_projection").is_none());
    }

    #[test]
    fn read_projection_rejects_one_mismatched_or_non_active_record() {
        let bytes = serde_json::to_vec(&candidate()).expect("candidate bytes");
        let admitted = validate_candidate_bytes(&bytes).expect("valid candidate");
        let mut drifted = admitted.record.clone();
        drifted.insert(
            "display_name".to_owned(),
            Value::String("Wrong Identity".to_owned()),
        );
        let mismatch =
            project_read_receipt(&admitted, &[drifted], "2030-01-01T00:02:00.000Z", "4.120.1");
        assert_eq!(mismatch["status"], "invalid");
        assert!(!read_receipt_is_complete(&mismatch));

        let mut claimed = admitted.record.clone();
        claimed.insert("status".to_owned(), Value::String("claimed".to_owned()));
        let terminal =
            project_read_receipt(&admitted, &[claimed], "2030-01-01T00:02:00.000Z", "4.120.1");
        assert_eq!(terminal["status"], "invalid");
        assert!(!read_receipt_is_complete(&terminal));
    }

    #[cfg(unix)]
    #[test]
    fn private_candidate_stage_is_body_free_mode_0600_and_digest_bound() {
        let root = tempfile::tempdir().expect("state root");
        // macOS exposes its temporary directory through the `/var` compatibility
        // symlink. Bind the test store to the resolved root so the assertion
        // exercises caller-controlled symlink rejection, not that system alias.
        let resolved_root = root.path().canonicalize().expect("resolved state root");
        let store = StateStore::open(RuntimePaths::from_root(&resolved_root)).expect("state store");
        let bytes = serde_json::to_vec(&candidate()).expect("candidate bytes");
        let stage = stage_private_candidate(&store, &bytes).expect("private stage");
        assert_eq!(stage["content_in_plan"], false);
        assert_eq!(stage["path_in_plan"], false);
        assert!(!stage.to_string().contains("security@example.com"));
        let object = stage.as_object().expect("stage object");
        let path = private_stage_path(&store, object).expect("stage path");
        assert_eq!(
            fs::metadata(path).expect("metadata").permissions().mode() & 0o777,
            0o600
        );
        validate_private_stage_object(&store, object).expect("valid stage");
    }
}
