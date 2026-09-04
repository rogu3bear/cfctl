use super::access_application::is_access_application_login_methods_mutation;
use super::access_application::validate_access_application_login_methods_desired_input;
use super::access_policy::is_access_application_owned_whole_host_mutation;
use super::access_policy::is_access_human_policy_mutation;
use super::access_policy::is_access_operator_group_policy_create;
use super::access_policy::is_access_operator_group_policy_update;
use super::access_policy::validate_access_application_owned_whole_host_input;
use super::access_policy::validate_access_human_policy_desired_input;
use super::access_policy::validate_access_operator_group_policy_input;
use super::call_input::call_input;
use super::call_input::resolve_account_id;
use super::credential_resolution::ensure_catalog;
use super::credential_resolution::fresh_credential;
use super::credential_resolution::platform_secrets;
use super::import_planning::ImportPrerequisiteContext;
use super::import_planning::stage_approved_mln_migration;
use super::import_planning::validate_approved_mln_import_prerequisites;
use super::import_planning::validate_mln_0142_post_import_schema_input;
use super::import_resume::validate_and_derive_resume_poll_authority;
use super::plan_create::create_plan;
use super::prelude::SecretStore;
use super::prelude::{
    CallArgs, CliError, Map, ProfilesConfig, Result, ResultEnvelopeV2, StateStore, Utc, Value, json,
};
use super::r2_credentials::preflight_call_input;
use super::r2_credentials::prepare_r2_temporary_credentials_input;
use super::read_execution::apply_operational_proof_index_result;
use super::read_execution::credential_generation_for_read;
use super::read_execution::execute_read;
use super::secret_io::is_secret_output_capability;
use super::security_action_input::prepare_security_action_input;
use super::support::capability_missing;
use super::support::load_workspace_capability;
use super::support::read_r2_log_retrieval_credentials;
use super::workspace_state::discover_registered;
use super::{
    pages_deployment, r2_private_upload, worker_deployment, workspace_d1_migration,
    workspace_d1_projection, workspace_d1_reply_admission, workspace_reply_subdomain_ingress,
};
use crate::telemetry_product::record_operational_proof;
use cfctl_core::hash_value;

#[expect(
    clippy::too_many_lines,
    reason = "the public call boundary must visibly sequence catalog validation, selectors, authorization, governed reads, and immutable mutation planning"
)]
pub(super) async fn call_command(
    store: &StateStore,
    arguments: CallArgs,
) -> Result<ResultEnvelopeV2> {
    let catalog = ensure_catalog(store).await?;
    let capability = if let Some(capability) = catalog.get(&arguments.capability_id) {
        capability.clone()
    } else {
        load_workspace_capability(store, &arguments.capability_id)?
            .ok_or_else(|| capability_missing(&arguments.capability_id))?
    };
    if is_secret_output_capability(&capability) && arguments.value_out.is_none() {
        return Err(CliError::Input(
            "secret-producing capabilities require `--value-out <new-path>`; the value is never written to stdout or evidence"
                .to_owned(),
        ));
    }
    let is_r2_log_retrieval = capability.r2_log_retrieval.is_some();
    let is_d1_full_export = capability.d1_full_export.is_some();
    let is_d1_approved_mln_import = capability.d1_approved_mln_import.is_some();
    let is_workspace_d1_projection = capability.workspace_d1_policy_projection.is_some();
    let is_workspace_d1_reply_admission = capability.workspace_d1_reply_admission.is_some();
    let is_r2_private_file_upload = capability.r2_private_file_upload.is_some();
    let is_d1_approved_mln_import_poll_resume =
        capability.d1_approved_mln_import_poll_resume.is_some();
    if (is_d1_approved_mln_import
        || is_workspace_d1_projection
        || is_workspace_d1_reply_admission
        || is_r2_private_file_upload)
        != arguments.source_file.is_some()
    {
        return Err(CliError::Input(
            "governed D1 imports, workspace policy projections, reply-admission activation/read, and create-only private R2 uploads require exactly one private `--source-file`; no other capability accepts it"
                .to_owned(),
        ));
    }
    if is_d1_approved_mln_import_poll_resume && arguments.source_file.is_some() {
        return Err(CliError::Input(
            "D1 import poll continuation derives source authority from its parent and never accepts `--source-file`"
                .to_owned(),
        ));
    }
    if arguments.credential_in.is_some() && !is_r2_log_retrieval {
        return Err(CliError::Input(
            "`--credential-in` is accepted only by the governed R2 log retrieval capability"
                .to_owned(),
        ));
    }
    if is_r2_log_retrieval && arguments.credential_in.is_none() {
        return Err(CliError::Input(
            "R2 log retrieval requires `--credential-in <mode-0600-json-path>`; credentials are never accepted as selectors or argv values"
                .to_owned(),
        ));
    }
    if is_r2_log_retrieval && arguments.out.is_none() {
        return Err(CliError::Input(
            "R2 log retrieval requires `--out <new-path>`; retained logs are never written to stdout or evidence"
                .to_owned(),
        ));
    }
    if is_r2_log_retrieval && arguments.value_out.is_some() {
        return Err(CliError::Input(
            "R2 log retrieval uses `--out` for retrieved logs; `--value-out` is reserved for one-time secret-producing mutations"
                .to_owned(),
        ));
    }
    if is_d1_full_export && arguments.out.is_none() {
        return Err(CliError::Input(
            "D1 full export requires `--out <new-path>`; the SQL dump is never written to stdout or evidence"
                .to_owned(),
        ));
    }
    if is_d1_full_export
        && (arguments.body_json.is_some() || arguments.body_stdin || !arguments.query.is_empty())
    {
        return Err(CliError::Input(
            "D1 full export accepts only account_id and database_id selectors plus `--out`; caller SQL and export filters are not supported"
                .to_owned(),
        ));
    }
    if arguments.out.is_some()
        && capability.analytics_query.is_none()
        && !is_r2_log_retrieval
        && !is_d1_full_export
    {
        return Err(CliError::Input(
            "`--out` is restricted to bounded analytics, governed R2 log retrieval, and D1 full export"
                .to_owned(),
        ));
    }
    if arguments.out.is_some() && capability.mutating {
        return Err(CliError::Input(
            "mutations cannot stream results with `--out`; create and review a plan instead"
                .to_owned(),
        ));
    }
    let mut prepared = call_input(&capability, &arguments)?;
    if is_d1_approved_mln_import {
        let profiles = ProfilesConfig::load(store)?;
        let profile = profiles.selected(arguments.profile.as_deref())?;
        validate_approved_mln_import_prerequisites(
            store,
            &capability,
            &prepared.input,
            ImportPrerequisiteContext {
                profile_id: &profile.id,
                credential_generation_id: profile.credential_generation_id.as_deref(),
                catalog_hash: &catalog.schema_hash,
                import_operation_id: None,
                before: Utc::now(),
            },
        )?;
    }
    if capability.mln_0142_post_import_schema.is_some() {
        validate_mln_0142_post_import_schema_input(store, &capability, &prepared.input)?;
    }
    let import_stage = if is_d1_approved_mln_import {
        arguments
            .source_file
            .as_deref()
            .map(|source| stage_approved_mln_migration(store, &capability, &prepared.input, source))
            .transpose()?
    } else {
        None
    };
    let resume_poll_authority = if is_d1_approved_mln_import_poll_resume {
        let profiles = ProfilesConfig::load(store)?;
        let profile = profiles.selected(arguments.profile.as_deref())?;
        Some(validate_and_derive_resume_poll_authority(
            store,
            &capability,
            &prepared.input,
            &profile.id,
            profile.credential_generation_id.as_deref(),
            &catalog.schema_hash,
            Utc::now(),
            None,
        )?)
    } else {
        None
    };
    prepare_r2_temporary_credentials_input(&capability, &mut prepared.input)?;
    let security_action = prepare_security_action_input(&capability, &mut prepared.input)?;
    if is_access_operator_group_policy_create(&capability)
        || is_access_operator_group_policy_update(&capability)
    {
        validate_access_operator_group_policy_input(&capability, &prepared.input)?;
    } else if is_access_application_owned_whole_host_mutation(&capability) {
        validate_access_application_owned_whole_host_input(&capability, &prepared.input)?;
    } else if is_access_application_login_methods_mutation(&capability) {
        validate_access_application_login_methods_desired_input(&capability, &prepared.input)?;
    } else if is_access_human_policy_mutation(&capability) {
        validate_access_human_policy_desired_input(&capability, &prepared.input)?;
    } else {
        preflight_call_input(&capability, &prepared.input, prepared.secret_body.as_ref())?;
    }
    if !capability.mutating {
        if prepared.secret_body.is_some() {
            return Err(CliError::Input(
                "read operations cannot accept secret request bodies".to_owned(),
            ));
        }
        let r2_credentials = arguments
            .credential_in
            .as_deref()
            .map(read_r2_log_retrieval_credentials)
            .transpose()?;
        let attestation = super::plan_commands::observation_attestation(store, &capability)?;
        let scoped_store = store.with_observation_attestation(&attestation);
        let executed = execute_read(
            &scoped_store,
            &catalog,
            &capability,
            &prepared.input,
            arguments.profile.as_deref(),
            arguments.account.as_deref(),
            arguments.out.as_deref(),
            r2_credentials.as_ref(),
            arguments.source_file.as_deref(),
        )
        .await?;
        let mut envelope = executed.envelope;
        envelope.attestation = Some(attestation.clone());
        if attestation.state == cfctl_core::AttestationStateV1::UnattestedReversibleEffect {
            if let Some(result) = envelope.result.as_object_mut() {
                result.insert("operational_proof_indexed".to_owned(), json!(false));
            }
            return Ok(envelope);
        }
        let proof_result = record_operational_proof(
            store,
            &catalog,
            &capability,
            &prepared.input,
            executed.credential_generation_id.as_deref(),
            &envelope,
        );
        apply_operational_proof_index_result(&mut envelope, proof_result);
        return Ok(envelope);
    }
    let secrets = platform_secrets(store);
    let mut secret_ref = None;
    let mut r2_stage_ref = None;
    let mut adapter_targets = Map::new();
    if pages_deployment::binds_artifact(&capability) {
        let graph = discover_registered(store)?;
        let target = pages_deployment::prepare_target(&graph, &capability, &prepared.input)?
            .ok_or_else(|| {
                CliError::Input("Pages deployment target could not be derived".to_owned())
            })?;
        adapter_targets.insert("pages_deployment".to_owned(), target);
    }
    if worker_deployment::binds_live_state(&capability) {
        let target = if capability.id == worker_deployment::ROLLBACK_CAPABILITY_ID {
            worker_deployment::prepare_rollback_target(&capability, &prepared.input)?
        } else {
            let graph = discover_registered(store)?;
            worker_deployment::prepare_target(&graph, &capability, &prepared.input)?.ok_or_else(
                || CliError::Input("Worker deployment target could not be derived".to_owned()),
            )?
        };
        adapter_targets.insert("worker_deployment".to_owned(), target);
    }
    if capability
        .workspace_reply_subdomain_ingress
        .as_ref()
        .is_some_and(|contract| contract.operation_kind == "activate")
    {
        let profiles = ProfilesConfig::load(store)?;
        let profile = profiles.selected(arguments.profile.as_deref())?;
        let account_id = resolve_account_id(
            store,
            profile,
            arguments.account.as_deref(),
            &prepared.input,
        )?
        .ok_or_else(|| {
            CliError::Input(
                "workspace reply-subdomain activation requires an explicit account pin or --account"
                    .to_owned(),
            )
        })?;
        let credential_generation_id = credential_generation_for_read(profile)?;
        let credential = fresh_credential(profile, &secrets).await?;
        let target = Box::pin(
            workspace_reply_subdomain_ingress::prepare_activation_target(
                store,
                &catalog,
                &capability,
                &prepared.input,
                &credential,
                profile,
                &account_id,
                arguments.account.as_deref(),
                &credential_generation_id,
            ),
        )
        .await?;
        adapter_targets.insert(
            "workspace_reply_subdomain_ingress_activation".to_owned(),
            target,
        );
    }
    if let Some(security_action) = security_action {
        adapter_targets.insert("security_action".to_owned(), security_action);
    }
    if let Some(secret_body) = &prepared.secret_body {
        let reference = format!("plan-input/{}", uuid::Uuid::new_v4());
        let content_hash = hash_value(secret_body)?;
        secrets.put(&reference, &serde_json::to_string(secret_body)?)?;
        prepared.input.body = Some(json!({
            "$cfctl_secret_body_ref": reference,
            "content_hash": content_hash,
        }));
        secret_ref = Some(reference.clone());
        adapter_targets.insert("secret_body_ref".to_owned(), Value::String(reference));
        adapter_targets.insert("secret_body_hash".to_owned(), Value::String(content_hash));
    }
    if let Some(value_out) = &arguments.value_out {
        adapter_targets.insert(
            "value_out".to_owned(),
            Value::String(value_out.display().to_string()),
        );
    }
    if let Some(import_stage) = import_stage {
        adapter_targets.insert("approved_mln_import".to_owned(), import_stage);
    }
    if let Some(authority) = resume_poll_authority {
        adapter_targets.insert("approved_mln_import_poll_resume".to_owned(), authority);
    }
    if capability.workspace_d1_migration.is_some() {
        let profiles = ProfilesConfig::load(store)?;
        let profile = profiles.selected(arguments.profile.as_deref())?;
        let account_id = resolve_account_id(
            store,
            profile,
            arguments.account.as_deref(),
            &prepared.input,
        )?
        .ok_or_else(|| {
            CliError::Input(
                "workspace D1 migration requires an explicit account pin or --account".to_owned(),
            )
        })?;
        let target = workspace_d1_migration::prepare_plan_target(
            store,
            &catalog,
            &capability,
            &prepared.input,
            profile,
            &account_id,
        )?
        .ok_or_else(|| {
            CliError::Input("workspace D1 migration target could not be derived".to_owned())
        })?;
        adapter_targets.insert("workspace_d1_migration".to_owned(), target);
    }
    if capability.workspace_d1_policy_projection.is_some() {
        let profiles = ProfilesConfig::load(store)?;
        let profile = profiles.selected(arguments.profile.as_deref())?;
        let account_id = resolve_account_id(
            store,
            profile,
            arguments.account.as_deref(),
            &prepared.input,
        )?
        .ok_or_else(|| {
            CliError::Input(
                "workspace D1 policy projection requires an explicit account pin or --account"
                    .to_owned(),
            )
        })?;
        let source = arguments.source_file.as_deref().ok_or_else(|| {
            CliError::Input("workspace D1 policy projection source is missing".to_owned())
        })?;
        let target = workspace_d1_projection::prepare_plan_target(
            store,
            &catalog,
            &capability,
            &prepared.input,
            profile,
            &account_id,
            source,
        )?
        .ok_or_else(|| {
            CliError::Input("workspace D1 policy projection target could not be derived".to_owned())
        })?;
        adapter_targets.insert("workspace_d1_policy_projection".to_owned(), target);
    }
    if capability.workspace_d1_reply_admission.is_some() {
        let profiles = ProfilesConfig::load(store)?;
        let profile = profiles.selected(arguments.profile.as_deref())?;
        let account_id = resolve_account_id(
            store,
            profile,
            arguments.account.as_deref(),
            &prepared.input,
        )?
        .ok_or_else(|| {
            CliError::Input(
                "workspace reply admission requires an explicit account pin or --account"
                    .to_owned(),
            )
        })?;
        let source = arguments.source_file.as_deref().ok_or_else(|| {
            CliError::Input("workspace reply-admission source is missing".to_owned())
        })?;
        let target = workspace_d1_reply_admission::prepare_plan_target(
            store,
            &catalog,
            &capability,
            &prepared.input,
            profile,
            &account_id,
            source,
        )?
        .ok_or_else(|| {
            CliError::Input("workspace reply-admission target could not be derived".to_owned())
        })?;
        adapter_targets.insert("workspace_d1_reply_admission".to_owned(), target);
    }
    if capability.r2_private_file_upload.is_some() {
        let source = arguments
            .source_file
            .as_deref()
            .ok_or_else(|| CliError::Input("private R2 upload source is missing".to_owned()))?;
        let target = r2_private_upload::prepare_plan_target(
            store,
            &secrets,
            &capability,
            &prepared.input,
            source,
        )?
        .ok_or_else(|| {
            CliError::Input("private R2 upload target could not be derived".to_owned())
        })?;
        r2_stage_ref = target
            .get("stage_ref")
            .and_then(Value::as_str)
            .map(str::to_owned);
        adapter_targets.insert("r2_private_file_upload".to_owned(), target);
    }
    let result = Box::pin(create_plan(
        store,
        &catalog,
        capability,
        prepared.input,
        arguments.profile.as_deref(),
        arguments.account.as_deref(),
        Value::Object(adapter_targets),
    ))
    .await;
    if result.is_err()
        && let Some(reference) = secret_ref
    {
        secrets.delete(&reference)?;
    }
    if result.is_err()
        && let Some(reference) = r2_stage_ref
    {
        r2_private_upload::discard_reference(store, &reference, &secrets)?;
    }
    result
}
