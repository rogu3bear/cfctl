use super::{
    AuthError, LegacyV1State, LifecycleBoundary, MacosKeychainAdapter, Result, classify_legacy_v1,
    delete_raw_exact, get_unmanaged, get_with, put_unlocked, read_inventory,
};

pub(super) fn recover_malformed_with(
    adapter: &dyn MacosKeychainAdapter,
    service: &str,
    key: &str,
    expected_value: &str,
    quarantine_key: &str,
    replacement_value: &str,
) -> Result<()> {
    if key == quarantine_key {
        return Err(AuthError::SecretStore(
            "malformed registry and quarantine identities must differ".to_owned(),
        ));
    }
    let _source_guard = adapter.acquire_mutation_lock(service, key)?;
    let _quarantine_guard = adapter.acquire_mutation_lock(service, quarantine_key)?;
    let quarantine = get_with(adapter, service, quarantine_key)?;
    if quarantine
        .as_deref()
        .is_some_and(|value| value != expected_value)
    {
        return Err(AuthError::SecretStore(
            "malformed registry quarantine differs from the private recovery binding".to_owned(),
        ));
    }
    let current = get_with(adapter, service, key)?;
    if current.as_deref() == Some(replacement_value)
        && quarantine.as_deref() == Some(expected_value)
    {
        return Ok(());
    }
    if quarantine.is_none() {
        if read_inventory(adapter, service, key)?.is_some()
            || !matches!(
                classify_legacy_v1(adapter, service, key)?,
                LegacyV1State::Unmanaged
            )
            || get_unmanaged(adapter, service, key)?.as_deref() != Some(expected_value)
        {
            return Err(AuthError::SecretStore(
                "malformed registry drifted before quarantine or gained managed transition state"
                    .to_owned(),
            ));
        }
        if let Err(quarantine_error) =
            put_unlocked(adapter, service, quarantine_key, expected_value)
        {
            match get_with(adapter, service, quarantine_key) {
                Ok(Some(readback)) if readback == expected_value => {}
                Ok(None) => return Err(quarantine_error),
                Ok(Some(_)) => {
                    return Err(AuthError::SecretStore(
                        "malformed registry quarantine publication drifted; source was preserved"
                            .to_owned(),
                    ));
                }
                Err(readback_error) => {
                    return Err(AuthError::SecretStore(format!(
                        "malformed registry quarantine publication is indeterminate; source was preserved: write={quarantine_error}; readback={readback_error}"
                    )));
                }
            }
        }
    }
    if get_with(adapter, service, quarantine_key)?.as_deref() != Some(expected_value) {
        return Err(AuthError::SecretStore(
            "malformed registry quarantine failed byte-exact readback".to_owned(),
        ));
    }
    match get_with(adapter, service, key)? {
        Some(current) if current == replacement_value => return Ok(()),
        Some(current) if current == expected_value => delete_raw_exact(adapter, service, key)?,
        None => {}
        Some(_) => {
            return Err(AuthError::SecretStore(
                "malformed registry canonical identity contains a third state".to_owned(),
            ));
        }
    }
    if let Err(delete_checkpoint_error) = adapter.checkpoint(LifecycleBoundary::RootDelete) {
        return Err(AuthError::SecretStore(format!(
            "malformed registry recovery stopped after verified quarantine and source removal; resume forward without restoring malformed bytes: {delete_checkpoint_error}"
        )));
    }
    match put_unlocked(adapter, service, key, replacement_value) {
        Ok(()) if get_with(adapter, service, key)?.as_deref() == Some(replacement_value) => Ok(()),
        Ok(()) => Err(AuthError::SecretStore(
            "malformed registry replacement failed exact readback".to_owned(),
        )),
        Err(replacement_error) => match get_with(adapter, service, key) {
            Ok(Some(readback)) if readback == replacement_value => Ok(()),
            Ok(_) => Err(AuthError::SecretStore(format!(
                "malformed registry replacement is not confirmed; preserve quarantine and resume forward: {replacement_error}"
            ))),
            Err(readback_error) => Err(AuthError::SecretStore(format!(
                "malformed registry replacement is indeterminate; preserve quarantine and resume only after readback: replacement={replacement_error}; readback={readback_error}"
            ))),
        },
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::{
        collections::BTreeMap,
        sync::{
            Mutex,
            atomic::{AtomicBool, Ordering},
        },
    };

    use super::*;

    #[derive(Default)]
    struct RecoveryAdapter {
        values: Mutex<BTreeMap<(String, String), String>>,
        fail_root_delete: AtomicBool,
    }

    impl MacosKeychainAdapter for RecoveryAdapter {
        fn put_raw(&self, service: &str, key: &str, value: &str) -> Result<()> {
            self.values
                .lock()
                .expect("value lock")
                .insert((service.to_owned(), key.to_owned()), value.to_owned());
            Ok(())
        }

        fn get_raw(&self, service: &str, key: &str) -> Result<Option<String>> {
            Ok(self
                .values
                .lock()
                .expect("value lock")
                .get(&(service.to_owned(), key.to_owned()))
                .cloned())
        }

        fn delete_raw(&self, service: &str, key: &str) -> Result<()> {
            self.values
                .lock()
                .expect("value lock")
                .remove(&(service.to_owned(), key.to_owned()));
            Ok(())
        }

        fn checkpoint(&self, boundary: LifecycleBoundary) -> Result<()> {
            if boundary == LifecycleBoundary::RootDelete
                && self.fail_root_delete.swap(false, Ordering::AcqRel)
            {
                return Err(AuthError::SecretStore(
                    "injected post-delete checkpoint failure".to_owned(),
                ));
            }
            Ok(())
        }
    }

    #[test]
    fn quarantine_is_preserved_and_same_intent_resumes_forward_after_delete_failure() {
        let adapter = RecoveryAdapter::default();
        let malformed = "{".repeat(128);
        adapter
            .put_raw("service", "registry", &malformed)
            .expect("malformed registry seeds");
        adapter.fail_root_delete.store(true, Ordering::Release);

        let error = recover_malformed_with(
            &adapter,
            "service",
            "registry",
            &malformed,
            "registry-quarantine",
            r#"{"schema_version":1}"#,
        )
        .expect_err("post-delete checkpoint stops recovery");
        assert!(
            error
                .to_string()
                .contains("resume forward without restoring malformed bytes")
        );
        assert!(
            get_with(&adapter, "service", "registry")
                .expect("canonical identity reads")
                .is_none()
        );
        assert_eq!(
            get_with(&adapter, "service", "registry-quarantine")
                .expect("quarantine reads")
                .as_deref(),
            Some(malformed.as_str())
        );

        recover_malformed_with(
            &adapter,
            "service",
            "registry",
            &malformed,
            "registry-quarantine",
            r#"{"schema_version":1}"#,
        )
        .expect("same private intent resumes forward");
        assert_eq!(
            get_with(&adapter, "service", "registry")
                .expect("replacement reads")
                .as_deref(),
            Some(r#"{"schema_version":1}"#)
        );
    }
}
