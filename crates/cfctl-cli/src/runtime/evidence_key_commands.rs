use super::prelude::{
    CliError, EvidenceKeyCommand, EvidenceKeyManager, EvidenceKeyRecoverArgs,
    EvidenceKeyRecoverPlanCommand, EvidenceKeyRecoverPlanSelector, EvidenceKeyRetireArgs,
    EvidenceKeyStatusV1, EvidenceMacProvider as _, Result, ResultEnvelopeV2, Sha256, StateStore,
    Uuid, json,
};
use sha2::Digest as _;

pub(super) fn evidence_key_command(
    store: &StateStore,
    command: EvidenceKeyCommand,
) -> Result<ResultEnvelopeV2> {
    let manager = store.platform_evidence_key_manager()?;
    match command {
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
    let _lifecycle = store.lock_evidence_lifecycle()?;
    let marker = store.evidence_root_identity()?;
    let status = manager.status(marker.as_deref())?;
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
        atomic::{AtomicBool, Ordering},
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
    }

    impl SecretStore for PlatformMemorySecretStore {
        fn put(&self, key: &str, value: &str) -> cfctl_auth::Result<()> {
            self.inner.put(key, value)
        }

        fn get(&self, key: &str) -> cfctl_auth::Result<Option<String>> {
            self.inner.get(key)
        }

        fn delete(&self, key: &str) -> cfctl_auth::Result<()> {
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
            self.fail_next_locate.store(true, Ordering::Release);
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
