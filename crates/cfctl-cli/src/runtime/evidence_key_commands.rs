use super::prelude::{
    CliError, EvidenceKeyCommand, EvidenceKeyManager, EvidenceKeyRecoverArgs,
    EvidenceKeyRecoverPlanCommand, EvidenceKeyRecoverPlanSelector, EvidenceKeyRetireArgs,
    EvidenceKeyStatusV1, EvidenceMacProvider as _, Result, ResultEnvelopeV2, Sha256, StateStore,
    Uuid, json,
};
use crate::{EvidenceKeyAdoptPlanCommand, EvidenceKeyAdoptPlanSelector};
use cfctl_auth::{
    EVIDENCE_KEY_ADOPTION_PROTOCOL_ID, EvidenceKeyAdoptionAcceptanceV1, EvidenceKeyAdoptionClockV1,
    EvidenceKeyAdoptionError, EvidenceKeyAdoptionObservationV1, EvidenceKeyAdoptionPlanV1,
    EvidenceKeyAdoptionRuntimeIdentityV1,
};
use sha2::Digest as _;

const ADOPTION_LINEAGE_BOUNDARY: &str = "adopted the exact sole canonical valid authority; original initialization lineage is not proven";

pub(super) fn evidence_key_command(
    store: &StateStore,
    command: EvidenceKeyCommand,
) -> Result<ResultEnvelopeV2> {
    if matches!(
        command,
        EvidenceKeyCommand::AdoptPlan(crate::EvidenceKeyAdoptPlanArgs {
            command: EvidenceKeyAdoptPlanCommand::Create,
        }) | EvidenceKeyCommand::Adopt(_)
    ) {
        return Err(cfctl_auth::AuthError::from(
            EvidenceKeyAdoptionError::InstalledIdentityReceiptRequired,
        )
        .into());
    }
    let manager = store.platform_evidence_key_manager()?;
    match command {
        EvidenceKeyCommand::AdoptPreview => adoption_preview(store, &manager),
        EvidenceKeyCommand::AdoptPlan(arguments) => match arguments.command {
            EvidenceKeyAdoptPlanCommand::Create => Err(cfctl_auth::AuthError::from(
                EvidenceKeyAdoptionError::InstalledIdentityReceiptRequired,
            )
            .into()),
            EvidenceKeyAdoptPlanCommand::Current => adoption_plan_current(store, &manager),
            EvidenceKeyAdoptPlanCommand::Status(selector) => {
                adoption_plan_status(store, &manager, &selector)
            }
            EvidenceKeyAdoptPlanCommand::Revoke(selector) => {
                adoption_plan_revoke(store, &manager, &selector)
            }
        },
        EvidenceKeyCommand::Adopt(_) => Err(cfctl_auth::AuthError::from(
            EvidenceKeyAdoptionError::InstalledIdentityReceiptRequired,
        )
        .into()),
        EvidenceKeyCommand::InitPreview => initialization_preview(store, &manager),
        EvidenceKeyCommand::Init => initialize(store, &manager),
        EvidenceKeyCommand::Status => status(store, &manager),
        EvidenceKeyCommand::Rotate => rotate(store, &manager),
        EvidenceKeyCommand::Retire(arguments) => retire(store, &manager, &arguments),
        EvidenceKeyCommand::RecoverPreview => recovery_preview(store, &manager),
        EvidenceKeyCommand::RecoverPlan(arguments) => match arguments.command {
            EvidenceKeyRecoverPlanCommand::Create => recovery_plan_create(store, &manager),
            EvidenceKeyRecoverPlanCommand::Status(selector) => {
                recovery_plan_status(&manager, &selector)
            }
            EvidenceKeyRecoverPlanCommand::Revoke(arguments) => {
                recovery_plan_revoke(store, &manager, &arguments)
            }
        },
        EvidenceKeyCommand::Recover(arguments) => recover(store, &manager, &arguments),
    }
}

fn runtime_result(
    acceptance: &EvidenceKeyAdoptionAcceptanceV1,
    provider: &str,
    validation: &str,
) -> EvidenceKeyAdoptionRuntimeIdentityV1 {
    EvidenceKeyAdoptionRuntimeIdentityV1 {
        validation_provider: provider.to_owned(),
        requirement_text: acceptance.requirement_text.clone(),
        requirement_sha256: acceptance.requirement_sha256.clone(),
        dynamic_self_validation: validation.to_owned(),
        protocol_identity: EVIDENCE_KEY_ADOPTION_PROTOCOL_ID.to_owned(),
    }
}

fn classify_native_self_validation(
    requirement_parsed: bool,
    self_code_available: bool,
    requirement_satisfied: bool,
) -> &'static str {
    if !requirement_parsed || !self_code_available {
        "indeterminate"
    } else if requirement_satisfied {
        "satisfied"
    } else {
        "not_satisfied"
    }
}

#[cfg(target_os = "macos")]
fn current_adoption_runtime_identity(
    acceptance: &EvidenceKeyAdoptionAcceptanceV1,
) -> EvidenceKeyAdoptionRuntimeIdentityV1 {
    use security_framework::os::macos::code_signing::{Flags, SecCode, SecRequirement};

    let Ok(requirement) = acceptance.requirement_text.parse::<SecRequirement>() else {
        return runtime_result(
            acceptance,
            "macos_security_framework_dynamic_seccode",
            classify_native_self_validation(false, false, false),
        );
    };
    let Ok(code) = SecCode::for_self(Flags::NONE) else {
        return runtime_result(
            acceptance,
            "macos_security_framework_dynamic_seccode",
            classify_native_self_validation(true, false, false),
        );
    };
    let validation = classify_native_self_validation(
        true,
        true,
        code.check_validity(Flags::NONE, &requirement).is_ok(),
    );
    runtime_result(
        acceptance,
        "macos_security_framework_dynamic_seccode",
        validation,
    )
}

#[cfg(target_os = "linux")]
fn current_adoption_runtime_identity(
    acceptance: &EvidenceKeyAdoptionAcceptanceV1,
) -> EvidenceKeyAdoptionRuntimeIdentityV1 {
    use std::io::Read as _;

    let validation = (|| -> std::io::Result<bool> {
        let mut executable = std::fs::File::open("/proc/self/exe")?;
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 32 * 1024];
        loop {
            let count = executable.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
        }
        Ok(format!("sha256:{}", hex::encode(digest.finalize()))
            == acceptance.installed_artifact_identity)
    })();
    runtime_result(
        acceptance,
        "linux_proc_self_exe_descriptor_sha256",
        match validation {
            Ok(true) => "satisfied",
            Ok(false) => "not_satisfied",
            Err(_) => "indeterminate",
        },
    )
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn current_adoption_runtime_identity(
    acceptance: &EvidenceKeyAdoptionAcceptanceV1,
) -> EvidenceKeyAdoptionRuntimeIdentityV1 {
    runtime_result(acceptance, "unsupported", "indeterminate")
}

#[allow(
    clippy::unnecessary_wraps,
    reason = "the test seam is infallible while production platform clock acquisition fails closed"
)]
fn current_adoption_clock() -> Result<EvidenceKeyAdoptionClockV1> {
    #[cfg(test)]
    return Ok(EvidenceKeyAdoptionClockV1 {
        boot_identity: "test-boot-session".to_owned(),
        monotonic_ns: 1_000_000_000,
        wall_at: chrono::Utc::now(),
    });
    #[cfg(not(test))]
    Ok(EvidenceKeyAdoptionClockV1 {
        boot_identity: platform_boot_identity()?,
        monotonic_ns: cfctl_auth::platform_adoption_monotonic_ns()?,
        wall_at: chrono::Utc::now(),
    })
}

fn parse_macos_boot_time(raw: &[u8]) -> Result<String> {
    let bytes: &[u8; 16] = raw.try_into().map_err(|_| {
        CliError::Input("kern.boottime returned an unexpected structure length".to_owned())
    })?;
    let seconds = i64::from_ne_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]);
    let microseconds = i32::from_ne_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    if seconds <= 0 || !(0..1_000_000).contains(&microseconds) {
        return Err(CliError::Input(
            "kern.boottime returned an invalid calendar tripwire".to_owned(),
        ));
    }
    Ok(format!("macos-kern-boottime:{seconds}.{microseconds:06}"))
}

#[cfg(all(not(test), target_os = "macos"))]
fn platform_boot_identity() -> Result<String> {
    use sysctl::{Ctl, CtlValue, Sysctl as _};

    let value = Ctl::new("kern.boottime")
        .and_then(|control| control.value())
        .map_err(|_| CliError::Input("kern.boottime is unavailable".to_owned()))?;
    let CtlValue::Struct(raw) = value else {
        return Err(CliError::Input(
            "kern.boottime returned a non-structure value".to_owned(),
        ));
    };
    parse_macos_boot_time(&raw)
}

#[cfg(all(not(test), target_os = "linux"))]
fn platform_boot_identity() -> Result<String> {
    use std::io::Read as _;

    let mut boot = String::new();
    std::fs::File::open("/proc/sys/kernel/random/boot_id")
        .and_then(|mut file| file.read_to_string(&mut boot))
        .map_err(|_| CliError::Input("Linux boot identity is unavailable".to_owned()))?;
    let canonical = boot.trim();
    let parsed = Uuid::parse_str(canonical)
        .map_err(|_| CliError::Input("Linux boot identity is malformed".to_owned()))?;
    if parsed.to_string() != canonical {
        return Err(CliError::Input(
            "Linux boot identity is not canonical".to_owned(),
        ));
    }
    Ok(format!("linux-boot-id:{canonical}"))
}

#[cfg(all(not(test), not(any(target_os = "macos", target_os = "linux"))))]
fn platform_boot_identity() -> Result<String> {
    Err(CliError::Input(
        "supported boot-session discriminator is unavailable".to_owned(),
    ))
}

fn adoption_observation(
    marker: Option<String>,
    descriptor_count: usize,
    proof_count: usize,
    runtime: &EvidenceKeyAdoptionRuntimeIdentityV1,
) -> Result<EvidenceKeyAdoptionObservationV1> {
    Ok(adoption_observation_at(
        marker,
        descriptor_count,
        proof_count,
        runtime,
        current_adoption_clock()?,
    ))
}

fn adoption_observation_at(
    marker: Option<String>,
    descriptor_count: usize,
    proof_count: usize,
    runtime: &EvidenceKeyAdoptionRuntimeIdentityV1,
    clock: EvidenceKeyAdoptionClockV1,
) -> EvidenceKeyAdoptionObservationV1 {
    EvidenceKeyAdoptionObservationV1 {
        marker_identity: marker,
        authenticated_descriptor_count: descriptor_count,
        authenticated_proof_count: proof_count,
        runtime: runtime.clone(),
        clock,
    }
}

fn adoption_preview(store: &StateStore, manager: &EvidenceKeyManager) -> Result<ResultEnvelopeV2> {
    let lifecycle = store.lock_evidence_lifecycle()?;
    let marker = store.evidence_root_identity()?;
    let counts = store.authenticated_evidence_artifact_counts(&lifecycle)?;
    let runtime = EvidenceKeyAdoptionRuntimeIdentityV1 {
        validation_provider: "not_evaluated_for_preview".to_owned(),
        requirement_text: String::new(),
        requirement_sha256: format!("sha256:{}", hex::encode(Sha256::digest([]))),
        dynamic_self_validation: "indeterminate".to_owned(),
        protocol_identity: EVIDENCE_KEY_ADOPTION_PROTOCOL_ID.to_owned(),
    };
    let observation = adoption_observation(
        marker.clone(),
        counts.descriptor_count,
        counts.proof_count,
        &runtime,
    )?;
    let status = manager.adoption_preview(&observation)?;
    Ok(ResultEnvelopeV2::success(
        "auth evidence-key adopt-preview",
        json!({
            "performed": false,
            "preview": {
                "canonical_location_identity": manager.location_identity(),
                "resource_class": "local_evidence_integrity_authority",
                "backend": "platform_keyring",
                "status": status,
                "marker_present": marker.is_some(),
                "authenticated_descriptor_count": counts.descriptor_count,
                "authenticated_proof_count": counts.proof_count,
                "allowed_effect": "create_matching_filesystem_marker_only",
                "lineage_boundary": ADOPTION_LINEAGE_BOUNDARY,
            },
            "secret_or_private_values_exposed": false,
            "next_action": "Preserve this read-only classification. Signed publication and installation may proceed independently, but adoption plan creation and marker crossing remain unavailable until authenticated, independently reviewed installed-identity receipt support lands.",
        }),
    ))
}

fn adoption_plan_current(
    store: &StateStore,
    manager: &EvidenceKeyManager,
) -> Result<ResultEnvelopeV2> {
    let lifecycle = store.lock_evidence_lifecycle()?;
    let plan_id = manager
        .current_adoption_plan_id()?
        .ok_or_else(|| CliError::Input("no adoption plan is discoverable".to_owned()))?;
    let selector = EvidenceKeyAdoptPlanSelector { plan_id };
    adoption_plan_status_after_lock(
        store,
        manager,
        &selector,
        &lifecycle,
        "auth evidence-key adopt-plan current",
    )
}

fn adoption_plan_status(
    store: &StateStore,
    manager: &EvidenceKeyManager,
    selector: &EvidenceKeyAdoptPlanSelector,
) -> Result<ResultEnvelopeV2> {
    let lifecycle = store.lock_evidence_lifecycle()?;
    adoption_plan_status_after_lock(
        store,
        manager,
        selector,
        &lifecycle,
        "auth evidence-key adopt-plan status",
    )
}

fn adoption_plan_status_after_lock(
    store: &StateStore,
    manager: &EvidenceKeyManager,
    selector: &EvidenceKeyAdoptPlanSelector,
    lifecycle: &cfctl_storage::EvidenceLifecycleLock,
    command: &'static str,
) -> Result<ResultEnvelopeV2> {
    let acceptance = manager.adoption_plan_acceptance(&selector.plan_id)?;
    let runtime = current_adoption_runtime_identity(&acceptance);
    let marker = store.evidence_root_identity()?;
    let counts = store.authenticated_evidence_artifact_counts(lifecycle)?;
    let observation = adoption_observation(
        marker,
        counts.descriptor_count,
        counts.proof_count,
        &runtime,
    )?;
    let plan = manager.adoption_plan_status(&selector.plan_id, &observation)?;
    Ok(adoption_plan_status_envelope(
        command,
        manager.location_identity(),
        plan,
    ))
}

fn adoption_plan_status_envelope(
    command: &'static str,
    canonical_location_identity: &str,
    plan: EvidenceKeyAdoptionPlanV1,
) -> ResultEnvelopeV2 {
    ResultEnvelopeV2::success(
        command,
        json!({
            "plan": plan,
            "canonical_location_identity": canonical_location_identity,
            "backend": "platform_keyring",
            "performed": false,
            "lineage_boundary": ADOPTION_LINEAGE_BOUNDARY,
            "secret_or_private_values_exposed": false,
        }),
    )
}

fn adoption_plan_revoke(
    store: &StateStore,
    manager: &EvidenceKeyManager,
    selector: &EvidenceKeyAdoptPlanSelector,
) -> Result<ResultEnvelopeV2> {
    let lifecycle = store.lock_evidence_lifecycle()?;
    let acceptance = manager.adoption_plan_acceptance(&selector.plan_id)?;
    let runtime = current_adoption_runtime_identity(&acceptance);
    let marker = store.evidence_root_identity()?;
    let counts = store.authenticated_evidence_artifact_counts(&lifecycle)?;
    let observation = adoption_observation(
        marker,
        counts.descriptor_count,
        counts.proof_count,
        &runtime,
    )?;
    let plan = manager.revoke_adoption_plan(&selector.plan_id, &observation)?;
    let mut envelope = ResultEnvelopeV2::success(
        "auth evidence-key adopt-plan revoke",
        json!({
            "plan": plan,
            "canonical_location_identity": manager.location_identity(),
            "backend": "platform_keyring",
            "lineage_boundary": ADOPTION_LINEAGE_BOUNDARY,
            "secret_or_private_values_exposed": false,
        }),
    );
    envelope.performed = true;
    Ok(envelope)
}

fn recovery_preview(store: &StateStore, manager: &EvidenceKeyManager) -> Result<ResultEnvelopeV2> {
    let lifecycle = store.lock_evidence_lifecycle()?;
    let marker_present = store.evidence_root_identity()?.is_some();
    let counts = store.authenticated_evidence_artifact_counts(&lifecycle)?;
    let preview =
        manager.recover_preview(marker_present, counts.descriptor_count, counts.proof_count)?;
    Ok(ResultEnvelopeV2::success(
        "auth evidence-key recover-preview",
        json!({
            "performed": false,
            "preview": preview,
            "historical_legacy_evidence": "preserved_and_nonqualifying",
            "quarantine_custody": "platform_keyring_only_byte_exact_readback_required",
            "recovery_direction": "after quarantine custody begins, resume forward; never restore malformed bytes to the canonical identity",
            "secret_key_bytes_exposed": false,
            "next_action": "Run `cfctl auth evidence-key recover-plan create --json` to create a short-lived private intent with a random opaque public identity.",
        }),
    ))
}

fn recovery_plan_create(
    store: &StateStore,
    manager: &EvidenceKeyManager,
) -> Result<ResultEnvelopeV2> {
    let lifecycle = store.lock_evidence_lifecycle()?;
    let marker_present = store.evidence_root_identity()?.is_some();
    let counts = store.authenticated_evidence_artifact_counts(&lifecycle)?;
    let plan = manager.create_recovery_plan(
        marker_present,
        counts.descriptor_count,
        counts.proof_count,
    )?;
    let mut envelope = ResultEnvelopeV2::success(
        "auth evidence-key recover-plan create",
        json!({
            "plan": plan,
            "private_binding": "platform_keyring_only_non_exportable_through_cfctl",
            "secret_or_secret_derived_values_exposed": false,
            "execution_command": format!(
                "cfctl auth evidence-key recover {} --yes --json",
                plan.plan_id
            ),
        }),
    );
    envelope.performed = true;
    Ok(envelope)
}

fn recovery_plan_status(
    manager: &EvidenceKeyManager,
    selector: &EvidenceKeyRecoverPlanSelector,
) -> Result<ResultEnvelopeV2> {
    let status = manager.recovery_plan_status(&selector.plan_id)?;
    Ok(ResultEnvelopeV2::success(
        "auth evidence-key recover-plan status",
        json!({
            "status": status,
            "performed": false,
            "secret_or_secret_derived_values_exposed": false,
        }),
    ))
}

fn recovery_plan_revoke(
    store: &StateStore,
    manager: &EvidenceKeyManager,
    arguments: &EvidenceKeyRecoverPlanSelector,
) -> Result<ResultEnvelopeV2> {
    let _lifecycle = store.lock_evidence_lifecycle()?;
    let status = manager.revoke_recovery_plan(&arguments.plan_id)?;
    let mut envelope = ResultEnvelopeV2::success(
        "auth evidence-key recover-plan revoke",
        json!({
            "status": status,
            "secret_or_secret_derived_values_exposed": false,
        }),
    );
    envelope.performed = true;
    Ok(envelope)
}

fn recover(
    store: &StateStore,
    manager: &EvidenceKeyManager,
    arguments: &EvidenceKeyRecoverArgs,
) -> Result<ResultEnvelopeV2> {
    if !arguments.yes {
        return Err(CliError::Input(
            "evidence-key recovery requires --yes for the exact opaque plan identity".to_owned(),
        ));
    }
    let lifecycle = store.lock_evidence_lifecycle()?;
    let marker = store.evidence_root_identity()?;
    let counts = store.authenticated_evidence_artifact_counts(&lifecycle)?;
    let status = manager.resume_malformed_registry(
        &arguments.plan_id,
        marker.as_deref(),
        counts.descriptor_count,
        counts.proof_count,
    )?;
    let state_root_identity = status.state_root_identity.as_deref().ok_or_else(|| {
        CliError::Input("recovered evidence authority omitted its private root binding".to_owned())
    })?;
    if marker.is_none()
        && let Err(marker_error) = store.initialize_evidence_root_identity(state_root_identity)
    {
        match store.evidence_root_identity() {
            Ok(Some(readback)) if readback == state_root_identity => {}
            Ok(None) => {
                return Err(CliError::Input(format!(
                    "recovered platform authority is published, but local marker creation did not cross; rerun the same recovery plan to resume forward: {marker_error}"
                )));
            }
            Ok(Some(_)) => {
                return Err(CliError::Input(format!(
                    "recovered platform authority is published, but marker readback conflicts; preserve private custody and stop: {marker_error}"
                )));
            }
            Err(readback_error) => {
                return Err(CliError::Input(format!(
                    "recovered platform authority is published and marker state is indeterminate; preserve private custody and inspect before resuming: write={marker_error}; readback={readback_error}"
                )));
            }
        }
    }
    let readback = manager.status(Some(state_root_identity))?;
    if readback != status {
        return Err(CliError::Input(
            "malformed registry recovery final status drifted; preserve authority and quarantine and do not replay"
                .to_owned(),
        ));
    }
    let recovery = manager.complete_recovery_plan(&arguments.plan_id, state_root_identity)?;
    let mut envelope = ResultEnvelopeV2::success(
        "auth evidence-key recover",
        json!({
            "recovery_performed": true,
            "recovery_plan": recovery,
            "status": status,
            "historical_legacy_evidence": "preserved_and_nonqualifying",
            "secret_or_secret_derived_values_exposed": false,
            "quarantine_retirement": "separate_explicit_lifecycle",
        }),
    );
    envelope.performed = true;
    Ok(envelope)
}

fn initialization_preview(
    store: &StateStore,
    manager: &EvidenceKeyManager,
) -> Result<ResultEnvelopeV2> {
    let _lifecycle = store.lock_evidence_lifecycle()?;
    let marker = store.evidence_root_identity()?;
    let status = manager.status(marker.as_deref())?;
    let state = match (marker.is_some(), status.initialized) {
        (false, false) => "ready",
        (true, true) => "already_initialized",
        _ => "split_authority_blocked",
    };
    Ok(ResultEnvelopeV2::success(
        "auth evidence-key init-preview",
        json!({
            "performed": false,
            "initialization_state": state,
            "current_status": status,
            "backend": "platform_keyring",
            "generated_key_custody": "platform_keyring_only_non_exportable_through_cfctl",
            "local_marker_custody": "canonical_state_root_non_secret_identity_marker",
            "state_root_transition": "absent_to_random_content_addressed_identity",
            "verification_generation_behavior": "initial_generation_signs_and_verifies; rotation makes older generations verification-only",
            "recoverability": {
                "before_marker_write": "a conclusively absent marker permits rollback of only the exact fresh platform authority",
                "after_marker_write_or_uncertainty": "preserve both sides, inspect status, and never replay initialization blindly",
                "split_authority": "blocked; initialization will not overwrite either side"
            },
            "secret_key_bytes_exposed": false,
            "execution_command": "cfctl auth evidence-key init --json",
            "message": "This preview is read-only. It creates no key or state-root marker and discloses no secret key material."
        }),
    ))
}

fn initialize(store: &StateStore, manager: &EvidenceKeyManager) -> Result<ResultEnvelopeV2> {
    initialize_with_marker_write(store, manager, |state_root_identity| {
        store.initialize_evidence_root_identity(state_root_identity)
    })
}

fn initialize_with_marker_write(
    store: &StateStore,
    manager: &EvidenceKeyManager,
    write_marker: impl FnOnce(&str) -> cfctl_storage::Result<()>,
) -> Result<ResultEnvelopeV2> {
    let lifecycle = store.lock_evidence_lifecycle()?;
    let marker = store.evidence_root_identity()?;
    let status = manager.status(marker.as_deref())?;
    // A registry with no marker is only resumable when this installation published
    // the intent that names it, and nothing has been authenticated under it yet.
    // Anything else is an authority of unknown provenance and remains an adoption
    // question, not an initialization one.
    if marker.is_none() && status.initialized {
        let counts = store.authenticated_evidence_artifact_counts(&lifecycle)?;
        if counts.descriptor_count == 0
            && counts.proof_count == 0
            && let Some(interrupted_root) = manager.interrupted_initialization()?
        {
            write_marker(&interrupted_root).map_err(|marker_error| {
                CliError::Input(format!(
                    "an interrupted evidence-key initialization was identified, but resuming its marker did not cross; the exact platform authority was preserved and the same initialization may be resumed again: {marker_error}"
                ))
            })?;
            let resumed = store
                .evidence_root_identity()?
                .filter(|resumed| *resumed == interrupted_root)
                .ok_or_else(|| {
                    CliError::Input(
                        "the resumed evidence-root marker did not read back as the exact interrupted state root; the platform authority was preserved. Inspect `cfctl auth evidence-key status --json`"
                            .to_owned(),
                    )
                })?;
            manager.clear_initialization_intent()?;
            let resumed_status = manager.status(Some(&resumed))?;
            return Ok(status_envelope(
                "auth evidence-key init",
                resumed_status,
                "An interrupted initialization was resumed forward. The exact platform authority was preserved and only its missing state-root marker was created.",
            ));
        }
    }
    if marker.is_some() || status.initialized {
        return Err(CliError::Input(
            "evidence key initialization requires both the state-root marker and platform authority to be absent; inspect `cfctl auth evidence-key status --json`"
                .to_owned(),
        ));
    }
    let state_root_identity = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(Uuid::new_v4().as_bytes()))
    );
    manager.publish_initialization_intent(&state_root_identity)?;
    let initialized = match manager.initialize(&state_root_identity) {
        Ok(initialized) => initialized,
        Err(initialization_error) => match manager.status(None) {
            Ok(status)
                if status.initialized
                    && status.state_root_identity.as_deref()
                        == Some(state_root_identity.as_str()) =>
            {
                status
            }
            Ok(status) if !status.initialized => return Err(initialization_error.into()),
            Ok(_) => {
                return Err(CliError::Input(format!(
                    "evidence authority initialization failed and readback found a conflicting platform registry; no filesystem marker was created and the registry was preserved. Inspect cfctl auth evidence-key status --json: {initialization_error}"
                )));
            }
            Err(readback_error) => {
                return Err(CliError::Input(format!(
                    "evidence authority initialization may have crossed, but exact platform readback is indeterminate; no filesystem marker was created and destructive rollback is unsafe. Inspect the platform credential store before retrying. Initialization error: {initialization_error}; readback error: {readback_error}"
                )));
            }
        },
    };
    if let Err(marker_error) = write_marker(&state_root_identity) {
        return match store.evidence_root_identity() {
            Ok(None) => {
                manager.rollback_initialize(&state_root_identity)?;
                Err(marker_error.into())
            }
            Ok(Some(marker)) if marker == state_root_identity => Err(CliError::Input(format!(
                "evidence-root marker creation reported an uncertain result, but exact marker readback succeeded; the platform authority was preserved and must not be recreated. Inspect cfctl auth evidence-key status --json before retrying: {marker_error}"
            ))),
            Ok(Some(_)) => Err(CliError::Input(format!(
                "evidence-root marker creation failed and readback found a conflicting marker; the platform authority was preserved because destructive rollback is unsafe. Inspect cfctl auth evidence-key status --json: {marker_error}"
            ))),
            Err(readback_error) => Err(CliError::Input(format!(
                "evidence-root marker creation failed and exact marker readback is indeterminate; the platform authority was preserved because the write may have crossed. Inspect cfctl auth evidence-key status --json before retrying. Marker error: {marker_error}; readback error: {readback_error}"
            ))),
        };
    }
    manager.clear_initialization_intent()?;
    Ok(status_envelope(
        "auth evidence-key init",
        initialized,
        "The platform-held evidence authority is initialized for this exact canonical state root.",
    ))
}

fn status(store: &StateStore, manager: &EvidenceKeyManager) -> Result<ResultEnvelopeV2> {
    let _lifecycle = store.lock_evidence_lifecycle()?;
    let marker = store.evidence_root_identity()?;
    let status = manager.status(marker.as_deref())?;
    if marker.is_some() != status.initialized {
        return Err(CliError::Input(
            "the filesystem evidence-root marker and platform-held authority are split; qualification is blocked and initialization will not overwrite either side"
                .to_owned(),
        ));
    }
    Ok(status_envelope(
        "auth evidence-key status",
        status,
        "Evidence-key status is read-only and contains no secret key material.",
    ))
}

fn rotate(store: &StateStore, manager: &EvidenceKeyManager) -> Result<ResultEnvelopeV2> {
    let _lifecycle = store.lock_evidence_lifecycle()?;
    let root = require_consistent_root(store, manager)?;
    let status = manager.rotate(&root)?;
    Ok(status_envelope(
        "auth evidence-key rotate",
        status,
        "A new signing generation is active; older generations remain verification-only.",
    ))
}

fn retire(
    store: &StateStore,
    manager: &EvidenceKeyManager,
    arguments: &EvidenceKeyRetireArgs,
) -> Result<ResultEnvelopeV2> {
    let generation_id = Uuid::parse_str(&arguments.generation_id)
        .ok()
        .filter(|generation| generation.to_string() == arguments.generation_id)
        .ok_or_else(|| {
            CliError::Input(
                "evidence-key retirement requires one canonical lowercase hyphenated generation UUID"
                    .to_owned(),
            )
        })?
        .to_string();
    let lifecycle = store.lock_evidence_lifecycle()?;
    let root = require_consistent_root(store, manager)?;
    let before = manager.status(Some(&root))?;
    if before.active_generation_id.as_deref() == Some(generation_id.as_str()) {
        return Err(CliError::Input(
            "the active evidence-key generation cannot be retired; rotate first".to_owned(),
        ));
    }
    if !before
        .verification_generation_ids
        .iter()
        .any(|generation| generation == &generation_id)
    {
        return Err(CliError::Input(format!(
            "evidence-key generation `{generation_id}` is not an inactive generation of this authority"
        )));
    }
    let usage = store.evidence_key_generation_usage(&lifecycle, &generation_id)?;
    if !arguments.yes {
        return Ok(ResultEnvelopeV2::success(
            "auth evidence-key retire",
            json!({
                "status": before,
                "retirement_performed": false,
                "generation_id": generation_id,
                "authenticated_artifact_count": usage,
                "message": "No key was removed. Review this exact impact, then repeat with --yes; confirmation rescans usage under the lifecycle lock."
            }),
        ));
    }
    let status = manager.retire(&root, &generation_id, usage)?;
    Ok(ResultEnvelopeV2::success(
        "auth evidence-key retire",
        json!({
            "status": status,
            "retirement_performed": true,
            "retired_generation_id": generation_id,
            "authenticated_artifact_count": usage,
            "message": "The unused inactive evidence-key generation was removed from the platform credential store."
        }),
    ))
}

fn require_consistent_root(store: &StateStore, manager: &EvidenceKeyManager) -> Result<String> {
    let root = store.evidence_root_identity()?.ok_or_else(|| {
        CliError::Input(
            "evidence key authority is not initialized; run `cfctl auth evidence-key init --json`"
                .to_owned(),
        )
    })?;
    let status = manager.status(Some(&root))?;
    if !status.initialized {
        return Err(CliError::Input(
            "the evidence state-root marker exists without its platform-held authority; refusing repair by overwrite"
                .to_owned(),
        ));
    }
    Ok(root)
}

fn status_envelope(
    command: &'static str,
    status: EvidenceKeyStatusV1,
    message: &'static str,
) -> ResultEnvelopeV2 {
    ResultEnvelopeV2::success(command, json!({"status": status, "message": message}))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::sync::{
        Arc, Barrier,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use std::thread;

    use cfctl_auth::{
        AuthError, EvidenceMacProvider as _, MemorySecretStore, SecretBackend, SecretStore,
    };
    use cfctl_storage::{RuntimePaths, StorageError};
    use sha2::{Digest as _, Sha256};

    use super::{
        EvidenceKeyManager, StateStore, initialization_preview, initialize,
        initialize_with_marker_write, recover, recovery_plan_create, recovery_plan_status,
        recovery_preview,
    };
    use crate::{EvidenceKeyRecoverArgs, EvidenceKeyRecoverPlanSelector};

    fn memory_manager(store: &StateStore) -> EvidenceKeyManager {
        EvidenceKeyManager::new(
            Arc::new(MemorySecretStore::default()),
            store.evidence_location_identity(),
            SecretBackend::Memory,
        )
        .expect("memory evidence manager")
    }

    #[derive(Default)]
    struct PlatformMemorySecretStore {
        inner: MemorySecretStore,
        put_attempts: AtomicUsize,
        delete_attempts: AtomicUsize,
        fail_next_get: AtomicBool,
    }

    impl SecretStore for PlatformMemorySecretStore {
        fn put(&self, key: &str, value: &str) -> cfctl_auth::Result<()> {
            self.put_attempts.fetch_add(1, Ordering::AcqRel);
            self.inner.put(key, value)
        }

        fn get(&self, key: &str) -> cfctl_auth::Result<Option<String>> {
            if self.fail_next_get.swap(false, Ordering::AcqRel) {
                return Err(AuthError::SecretStore(
                    "injected indeterminate platform read".to_owned(),
                ));
            }
            self.inner.get(key)
        }

        fn delete(&self, key: &str) -> cfctl_auth::Result<()> {
            self.delete_attempts.fetch_add(1, Ordering::AcqRel);
            self.inner.delete(key)
        }

        fn locate(&self, key: &str) -> cfctl_auth::Result<Option<SecretBackend>> {
            Ok(self.inner.get(key)?.map(|_| SecretBackend::PlatformKeyring))
        }
    }

    #[test]
    fn initialization_preview_discloses_custody_and_recovery_without_performing_transition() {
        let root = tempfile::tempdir().expect("temporary storage root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("storage opens");
        let manager = memory_manager(&store);

        let envelope = initialization_preview(&store, &manager).expect("preview succeeds");

        assert!(!envelope.performed);
        assert_eq!(
            envelope
                .result
                .get("initialization_state")
                .and_then(serde_json::Value::as_str),
            Some("ready")
        );
        assert_eq!(
            envelope
                .result
                .get("secret_key_bytes_exposed")
                .and_then(serde_json::Value::as_bool),
            Some(false)
        );
        assert!(
            store
                .evidence_root_identity()
                .expect("marker reads")
                .is_none()
        );
        assert!(!manager.status(None).expect("status reads").initialized);
    }

    #[test]
    fn recovery_plan_keeps_preview_read_only_and_finalizes_marker_once() {
        let root = tempfile::tempdir().expect("temporary storage root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("storage opens");
        let secrets = Arc::new(PlatformMemorySecretStore::default());
        let manager = EvidenceKeyManager::new(
            secrets.clone(),
            store.evidence_location_identity(),
            SecretBackend::PlatformKeyring,
        )
        .expect("platform-memory evidence manager");
        let registry_key = format!(
            "evidence-integrity/location/{}/registry-v1",
            store.evidence_location_identity()
        );
        let malformed = "{".repeat(128);
        secrets
            .inner
            .put(&registry_key, &malformed)
            .expect("malformed registry seeds");

        let preview = recovery_preview(&store, &manager).expect("preview succeeds");
        assert!(!preview.performed);
        let preview_json = preview.result.to_string();
        let malformed_digest = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(malformed.as_bytes()))
        );
        assert!(!preview_json.contains(&malformed));
        assert!(!preview_json.contains(&malformed_digest));
        assert!(
            store
                .evidence_root_identity()
                .expect("marker reads")
                .is_none()
        );

        let plan = recovery_plan_create(&store, &manager).expect("private plan creates");
        assert!(plan.performed);
        let plan_id = plan.result["plan"]["plan_id"]
            .as_str()
            .expect("opaque plan id")
            .to_owned();
        let status = recovery_plan_status(
            &manager,
            &EvidenceKeyRecoverPlanSelector {
                plan_id: plan_id.clone(),
            },
        )
        .expect("plan status reads");
        assert_eq!(status.result["status"]["state"], "prepared");

        let recovered = recover(
            &store,
            &manager,
            &EvidenceKeyRecoverArgs {
                plan_id: plan_id.clone(),
                yes: true,
            },
        )
        .expect("plan recovers and finalizes marker");
        assert!(recovered.performed);
        assert_eq!(recovered.result["recovery_plan"]["state"], "completed");
        let marker = store
            .evidence_root_identity()
            .expect("marker reads")
            .expect("marker finalized");
        manager
            .status(Some(&marker))
            .expect("marker and replacement authority agree");
        assert!(
            recover(
                &store,
                &manager,
                &EvidenceKeyRecoverArgs { plan_id, yes: true },
            )
            .is_err(),
            "completed plan is single-use"
        );
    }

    #[derive(Default)]
    struct PutThenLocateFailsOnceSecretStore {
        inner: MemorySecretStore,
        fail_next_locate: AtomicBool,
    }

    impl SecretStore for PutThenLocateFailsOnceSecretStore {
        fn put(&self, key: &str, value: &str) -> cfctl_auth::Result<()> {
            self.inner.put(key, value)?;
            // Arm only on the registry write this fixture is named for. Initialization
            // publishes its intent first, and that write must not consume the fault.
            if key.ends_with("/registry-v1") {
                self.fail_next_locate.store(true, Ordering::Release);
            }
            Ok(())
        }

        fn get(&self, key: &str) -> cfctl_auth::Result<Option<String>> {
            self.inner.get(key)
        }

        fn delete(&self, key: &str) -> cfctl_auth::Result<()> {
            self.inner.delete(key)
        }

        fn locate(&self, key: &str) -> cfctl_auth::Result<Option<SecretBackend>> {
            if self.fail_next_locate.swap(false, Ordering::AcqRel) {
                return Err(AuthError::SecretStore(
                    "injected locate failure after registry publication".to_owned(),
                ));
            }
            self.inner.locate(key)
        }
    }

    #[test]
    fn initialization_reconciles_registry_when_put_crossed_before_status_failed() {
        let root = tempfile::tempdir().expect("temporary storage root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("storage opens");
        let manager = EvidenceKeyManager::new(
            Arc::new(PutThenLocateFailsOnceSecretStore::default()),
            store.evidence_location_identity(),
            SecretBackend::Memory,
        )
        .expect("fault-injected evidence manager");

        initialize(&store, &manager).expect("exact registry readback reconciles initialization");

        let marker = store
            .evidence_root_identity()
            .expect("marker reads")
            .expect("marker exists");
        let status = manager
            .status(Some(&marker))
            .expect("registry and marker agree");
        assert!(status.initialized);
        assert_eq!(status.state_root_identity.as_deref(), Some(marker.as_str()));
    }

    #[test]
    fn interrupted_initialization_resumes_the_same_authority_forward() {
        let root = tempfile::tempdir().expect("temporary storage root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("storage opens");
        let manager = memory_manager(&store);

        // Initialization crosses the platform registry and the filesystem marker in
        // that order. Model process death between them: the intent and the registry
        // exist, the marker never does, and no compensation code runs.
        let state_root_identity = format!("sha256:{}", "a".repeat(64));
        manager
            .publish_initialization_intent(&state_root_identity)
            .expect("intent publishes before the authority it names");
        let crossed = manager
            .initialize(&state_root_identity)
            .expect("platform authority crosses");
        assert_eq!(
            store.evidence_root_identity().expect("marker readback"),
            None
        );

        let envelope = initialize(&store, &manager).expect("interrupted initialization resumes");

        assert!(envelope.ok);
        let marker = store
            .evidence_root_identity()
            .expect("marker readback")
            .expect("resumed marker exists");
        assert_eq!(marker, state_root_identity);
        let status = manager.status(Some(&marker)).expect("status");
        assert!(status.initialized);
        // Resumption finishes the original crossing; it must not mint a replacement.
        assert_eq!(
            status.active_generation_id, crossed.active_generation_id,
            "resume must preserve the exact interrupted authority"
        );
        // The intent is retired, so the resumed authority is now an ordinary one.
        let error = initialize(&store, &manager).expect_err("a complete authority blocks init");
        assert!(
            error.to_string().contains(
                "requires both the state-root marker and platform authority to be absent"
            )
        );
    }

    #[test]
    fn a_registry_without_a_published_intent_is_not_resumable() {
        let root = tempfile::tempdir().expect("temporary storage root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("storage opens");
        let manager = memory_manager(&store);

        // An authority this installation cannot attribute to its own interrupted
        // crossing stays an adoption question. Resumption must not become a
        // receipt-free path to inheriting an unattributable signing authority.
        let state_root_identity = format!("sha256:{}", "b".repeat(64));
        manager
            .initialize(&state_root_identity)
            .expect("an unattributable authority exists");

        let error =
            initialize(&store, &manager).expect_err("unattributable authority fails closed");

        assert!(
            error.to_string().contains(
                "requires both the state-root marker and platform authority to be absent"
            )
        );
        assert_eq!(
            store.evidence_root_identity().expect("marker readback"),
            None,
            "a failed resume must not create a marker"
        );
    }

    #[test]
    fn an_intent_that_disagrees_with_the_registry_fails_closed() {
        let root = tempfile::tempdir().expect("temporary storage root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("storage opens");
        let manager = memory_manager(&store);

        let intended = format!("sha256:{}", "c".repeat(64));
        let actual = format!("sha256:{}", "d".repeat(64));
        manager
            .publish_initialization_intent(&intended)
            .expect("intent publishes");
        manager
            .initialize(&actual)
            .expect("a different authority crosses");

        let error = initialize(&store, &manager).expect_err("disagreement is never guessed away");

        assert!(error.to_string().contains("different state root"));
        assert_eq!(
            store.evidence_root_identity().expect("marker readback"),
            None
        );
    }

    #[test]
    fn a_completed_initialization_leaves_no_resumable_intent() {
        let root = tempfile::tempdir().expect("temporary storage root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("storage opens");
        let manager = memory_manager(&store);

        initialize(&store, &manager).expect("initialization succeeds");

        assert_eq!(
            manager
                .interrupted_initialization()
                .expect("intent inspection"),
            None,
            "a completed crossing must retire its intent"
        );
    }

    #[test]
    fn initialization_preserves_platform_authority_when_exact_marker_crossed_before_error() {
        let root = tempfile::tempdir().expect("temporary storage root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("storage opens");
        let manager = memory_manager(&store);

        let error = initialize_with_marker_write(&store, &manager, |state_root_identity| {
            store.initialize_evidence_root_identity(state_root_identity)?;
            Err(StorageError::WriteDurabilityUnknown {
                path: store
                    .paths()
                    .data_dir
                    .join("evidence-root-v1.json")
                    .display()
                    .to_string(),
                source: std::io::Error::other(
                    "injected directory sync failure after the final marker link crossed",
                ),
            })
        })
        .expect_err("uncertain marker durability remains an error");

        assert!(
            error
                .to_string()
                .contains("platform authority was preserved")
        );
        assert!(error.to_string().contains("evidence-key status"));
        let marker = store
            .evidence_root_identity()
            .expect("marker readback")
            .expect("crossed marker remains");
        let status = manager.status(Some(&marker)).expect("authority remains");
        assert!(status.initialized);
        assert_eq!(status.state_root_identity.as_deref(), Some(marker.as_str()));
    }

    #[test]
    fn initialization_rolls_back_platform_authority_when_marker_is_conclusively_absent() {
        let root = tempfile::tempdir().expect("temporary storage root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("storage opens");
        let manager = memory_manager(&store);

        initialize_with_marker_write(&store, &manager, |_state_root_identity| {
            Err(StorageError::Io {
                path: "evidence-root-v1.json".to_owned(),
                source: std::io::Error::other("injected failure before marker creation"),
            })
        })
        .expect_err("missing marker returns the original failure");

        assert_eq!(
            store.evidence_root_identity().expect("marker readback"),
            None
        );
        assert!(!manager.status(None).expect("status").initialized);
    }

    #[test]
    fn concurrent_initialization_serializes_to_one_consistent_authority() {
        let root = tempfile::tempdir().expect("temporary storage root");
        let store = StateStore::open(RuntimePaths::from_root(root.path())).expect("storage opens");
        let manager = memory_manager(&store);
        let barrier = Arc::new(Barrier::new(2));
        let mut attempts = Vec::new();
        for _ in 0..2 {
            let store = store.clone();
            let manager = manager.clone();
            let barrier = barrier.clone();
            attempts.push(thread::spawn(move || {
                barrier.wait();
                initialize(&store, &manager)
            }));
        }

        let results = attempts
            .into_iter()
            .map(|attempt| attempt.join().expect("initializer joins"))
            .collect::<Vec<_>>();
        assert_eq!(
            results.iter().filter(|result| result.is_ok()).count(),
            1,
            "exactly one serialized initializer succeeds"
        );
        let marker = store
            .evidence_root_identity()
            .expect("marker reads")
            .expect("winning marker exists");
        let status = manager
            .status(Some(&marker))
            .expect("winning authority matches marker");
        assert!(status.initialized);
        assert_eq!(status.state_root_identity.as_deref(), Some(marker.as_str()));
    }
}

#[cfg(test)]
#[path = "evidence_key_adoption_tests.rs"]
mod adoption_rework_tests;
