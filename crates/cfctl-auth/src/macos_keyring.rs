use std::io::{Read as _, Write as _};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::{AuthError, Result};

const PROMPT_SAFE_VALUE_BYTES: usize = 96;
const PROMPT_MAX_VALUE_BYTES: usize = 127;
const CHUNK_SOURCE_BYTES: usize = 72;
const CHUNK_MANIFEST_PREFIX: &str = "cfctl:keyring:v1:";
const CHUNK_KEY_PREFIX: &str = "__cfctl_internal__/keyring-chunk/v1";
const CHUNK_MANIFEST_VERSION: u8 = 1;
const CHUNK_MANIFEST_BYTES: usize = 65;

pub(super) fn put(service: &str, key: &str, value: &str) -> Result<()> {
    put_with(&SecurityCommandAdapter, service, key, value)
}

pub(super) fn get(service: &str, key: &str) -> Result<Option<String>> {
    get_with(&SecurityCommandAdapter, service, key)
}

pub(super) fn delete(service: &str, key: &str) -> Result<()> {
    delete_with(&SecurityCommandAdapter, service, key)
}

trait MacosKeychainAdapter {
    fn put_raw(&self, service: &str, key: &str, value: &str) -> Result<()>;
    fn get_raw(&self, service: &str, key: &str) -> Result<Option<String>>;
    fn delete_raw(&self, service: &str, key: &str) -> Result<()>;
}

struct SecurityCommandAdapter;

impl MacosKeychainAdapter for SecurityCommandAdapter {
    fn put_raw(&self, service: &str, key: &str, value: &str) -> Result<()> {
        security_command_put(service, key, value)
    }

    fn get_raw(&self, service: &str, key: &str) -> Result<Option<String>> {
        security_command_get(service, key)
    }

    fn delete_raw(&self, service: &str, key: &str) -> Result<()> {
        security_command_delete(service, key)
    }
}

fn put_with(
    adapter: &dyn MacosKeychainAdapter,
    service: &str,
    key: &str,
    value: &str,
) -> Result<()> {
    if value.contains(['\n', '\r']) {
        return Err(AuthError::SecretStore(
            "macOS Keychain credentials cannot contain line breaks".to_owned(),
        ));
    }
    let previous_manifest = adapter
        .get_raw(service, key)?
        .as_deref()
        .map(parse_chunk_manifest)
        .transpose()?
        .flatten();
    if value.len() <= PROMPT_SAFE_VALUE_BYTES && !value.starts_with(CHUNK_MANIFEST_PREFIX) {
        put_raw_exact(adapter, service, key, value)?;
        return cleanup_previous_chunks(adapter, service, key, previous_manifest.as_ref());
    }

    let encoded_chunks = value
        .as_bytes()
        .chunks(CHUNK_SOURCE_BYTES)
        .map(|chunk| URL_SAFE_NO_PAD.encode(chunk))
        .collect::<Vec<_>>();
    let manifest = ChunkManifest {
        write_id: *Uuid::new_v4().as_bytes(),
        chunk_count: encoded_chunks.len(),
        value_len: value.len(),
        value_digest: Sha256::digest(value.as_bytes()).into(),
    };
    for (index, chunk) in encoded_chunks.iter().enumerate() {
        put_raw_exact(
            adapter,
            service,
            &chunk_key(key, &manifest.write_id, index),
            chunk,
        )?;
    }
    let encoded_manifest = manifest.encode()?;
    if encoded_manifest.len() > PROMPT_MAX_VALUE_BYTES {
        return Err(AuthError::SecretStore(
            "platform keyring chunk manifest exceeds its prompt-safe bound".to_owned(),
        ));
    }
    put_raw_exact(adapter, service, key, &encoded_manifest)?;
    get_with(adapter, service, key)?.ok_or_else(|| {
        AuthError::SecretStore("platform keyring exact readback is missing".to_owned())
    })?;
    cleanup_previous_chunks(adapter, service, key, previous_manifest.as_ref())
}

fn get_with(
    adapter: &dyn MacosKeychainAdapter,
    service: &str,
    key: &str,
) -> Result<Option<String>> {
    let Some(stored) = adapter.get_raw(service, key)? else {
        return Ok(None);
    };
    let Some(manifest) = parse_chunk_manifest(&stored)? else {
        return Ok(Some(stored));
    };
    let mut decoded = Vec::with_capacity(manifest.value_len);
    for index in 0..manifest.chunk_count {
        let encoded = adapter
            .get_raw(service, &chunk_key(key, &manifest.write_id, index))?
            .ok_or_else(|| {
                AuthError::SecretStore(
                    "platform keyring chunked credential readback is incomplete".to_owned(),
                )
            })?;
        let chunk = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| {
            AuthError::SecretStore(
                "platform keyring chunked credential contains invalid encoding".to_owned(),
            )
        })?;
        decoded.extend_from_slice(&chunk);
    }
    let readback_digest: [u8; 32] = Sha256::digest(&decoded).into();
    if decoded.len() != manifest.value_len || readback_digest != manifest.value_digest {
        return Err(AuthError::SecretStore(
            "platform keyring chunked credential failed exact digest readback".to_owned(),
        ));
    }
    String::from_utf8(decoded).map(Some).map_err(|_| {
        AuthError::SecretStore("platform keyring chunked credential is not valid UTF-8".to_owned())
    })
}

fn delete_with(adapter: &dyn MacosKeychainAdapter, service: &str, key: &str) -> Result<()> {
    let manifest = adapter
        .get_raw(service, key)?
        .as_deref()
        .map(parse_chunk_manifest)
        .transpose()?
        .flatten();
    adapter.delete_raw(service, key)?;
    cleanup_previous_chunks(adapter, service, key, manifest.as_ref())
}

#[derive(Debug)]
struct ChunkManifest {
    write_id: [u8; 16],
    chunk_count: usize,
    value_len: usize,
    value_digest: [u8; 32],
}

impl ChunkManifest {
    fn encode(&self) -> Result<String> {
        let chunk_count = u64::try_from(self.chunk_count).map_err(|_| invalid_manifest())?;
        let value_len = u64::try_from(self.value_len).map_err(|_| invalid_manifest())?;
        let mut encoded = Vec::with_capacity(CHUNK_MANIFEST_BYTES);
        encoded.push(CHUNK_MANIFEST_VERSION);
        encoded.extend_from_slice(&self.write_id);
        encoded.extend_from_slice(&chunk_count.to_be_bytes());
        encoded.extend_from_slice(&value_len.to_be_bytes());
        encoded.extend_from_slice(&self.value_digest);
        Ok(format!(
            "{CHUNK_MANIFEST_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(encoded)
        ))
    }
}

fn parse_chunk_manifest(value: &str) -> Result<Option<ChunkManifest>> {
    let Some(encoded) = value.strip_prefix(CHUNK_MANIFEST_PREFIX) else {
        return Ok(None);
    };
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| invalid_manifest())?;
    if decoded.len() != CHUNK_MANIFEST_BYTES || decoded[0] != CHUNK_MANIFEST_VERSION {
        return Err(invalid_manifest());
    }
    let mut write_id = [0_u8; 16];
    write_id.copy_from_slice(&decoded[1..17]);
    let mut chunk_count_bytes = [0_u8; 8];
    chunk_count_bytes.copy_from_slice(&decoded[17..25]);
    let mut value_len_bytes = [0_u8; 8];
    value_len_bytes.copy_from_slice(&decoded[25..33]);
    let Some(chunk_count) = usize::try_from(u64::from_be_bytes(chunk_count_bytes)).ok() else {
        return Err(invalid_manifest());
    };
    let Some(value_len) = usize::try_from(u64::from_be_bytes(value_len_bytes)).ok() else {
        return Err(invalid_manifest());
    };
    let mut value_digest = [0_u8; 32];
    value_digest.copy_from_slice(&decoded[33..65]);
    let valid =
        chunk_count > 0 && value_len > 0 && chunk_count == value_len.div_ceil(CHUNK_SOURCE_BYTES);
    if !valid {
        return Err(invalid_manifest());
    }
    Ok(Some(ChunkManifest {
        write_id,
        chunk_count,
        value_len,
        value_digest,
    }))
}

fn invalid_manifest() -> AuthError {
    AuthError::SecretStore("platform keyring chunk manifest is invalid".to_owned())
}

fn chunk_key(key: &str, write_id: &[u8; 16], index: usize) -> String {
    let key_digest = URL_SAFE_NO_PAD.encode(Sha256::digest(key.as_bytes()));
    let write_id = URL_SAFE_NO_PAD.encode(write_id);
    format!("{CHUNK_KEY_PREFIX}/{key_digest}/{write_id}/{index}")
}

fn cleanup_previous_chunks(
    adapter: &dyn MacosKeychainAdapter,
    service: &str,
    key: &str,
    manifest: Option<&ChunkManifest>,
) -> Result<()> {
    let Some(manifest) = manifest else {
        return Ok(());
    };
    for index in 0..manifest.chunk_count {
        adapter.delete_raw(service, &chunk_key(key, &manifest.write_id, index))?;
    }
    Ok(())
}

fn put_raw_exact(
    adapter: &dyn MacosKeychainAdapter,
    service: &str,
    key: &str,
    value: &str,
) -> Result<()> {
    let write_result = adapter.put_raw(service, key, value);
    match adapter.get_raw(service, key) {
        Ok(Some(readback)) if readback == value => Ok(()),
        Ok(Some(_) | None) => match write_result {
            Ok(()) => Err(AuthError::SecretStore(
                "platform keyring credential write was not byte-exact".to_owned(),
            )),
            Err(write_error) => Err(write_error),
        },
        Err(readback_error) => {
            let write_state = match write_result {
                Ok(()) => "reported success".to_owned(),
                Err(write_error) => format!("reported failure ({write_error})"),
            };
            Err(AuthError::SecretStore(format!(
                "platform keyring credential write {write_state}, but exact readback is indeterminate ({readback_error})"
            )))
        }
    }
}

fn security_write_arguments(service: &str, key: &str) -> Vec<String> {
    [
        "add-generic-password",
        "-U",
        "-a",
        key,
        "-s",
        service,
        "-T",
        "/usr/bin/security",
        "-w",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn security_command_put(service: &str, key: &str, value: &str) -> Result<()> {
    if value.contains(['\n', '\r']) {
        return Err(AuthError::SecretStore(
            "macOS Keychain credentials cannot contain line breaks".to_owned(),
        ));
    }
    let mut child = std::process::Command::new("/usr/bin/security")
        .args(security_write_arguments(service, key))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|error| AuthError::SecretStore(error.to_string()))?;
    {
        let stdin = child.stdin.as_mut().ok_or_else(|| {
            AuthError::SecretStore(
                "platform keyring credential write produced no input sink".to_owned(),
            )
        })?;
        stdin
            .write_all(value.as_bytes())
            .and_then(|()| stdin.write_all(b"\n"))
            .and_then(|()| stdin.write_all(value.as_bytes()))
            .and_then(|()| stdin.write_all(b"\n"))
            .map_err(|error| AuthError::SecretStore(error.to_string()))?;
    }
    drop(child.stdin.take());
    let status = wait_for_child(&mut child)?;
    if status.success() {
        Ok(())
    } else {
        Err(AuthError::SecretStore(format!(
            "platform keyring credential write failed with exit status {status}"
        )))
    }
}

fn security_command_get(service: &str, key: &str) -> Result<Option<String>> {
    let mut child = std::process::Command::new("/usr/bin/security")
        .args(["find-generic-password", "-s", service, "-a", key, "-w"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|error| AuthError::SecretStore(error.to_string()))?;
    let status = wait_for_child(&mut child)?;
    if status.code() == Some(44) {
        return Ok(None);
    }
    if !status.success() {
        return Err(AuthError::SecretStore(format!(
            "platform keyring credential read failed with exit status {status}"
        )));
    }
    let mut value = String::new();
    child
        .stdout
        .take()
        .ok_or_else(|| {
            AuthError::SecretStore("platform keyring credential read produced no sink".to_owned())
        })?
        .read_to_string(&mut value)
        .map_err(|error| AuthError::SecretStore(error.to_string()))?;
    while value.ends_with(['\n', '\r']) {
        value.pop();
    }
    Ok(Some(value))
}

fn security_command_delete(service: &str, key: &str) -> Result<()> {
    let mut child = std::process::Command::new("/usr/bin/security")
        .args(["delete-generic-password", "-s", service, "-a", key])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|error| AuthError::SecretStore(error.to_string()))?;
    let status = wait_for_child(&mut child)?;
    if status.success() || status.code() == Some(44) {
        Ok(())
    } else {
        Err(AuthError::SecretStore(format!(
            "platform keyring credential deletion failed with exit status {status}"
        )))
    }
}

fn wait_for_child(child: &mut std::process::Child) -> Result<std::process::ExitStatus> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match child
            .try_wait()
            .map_err(|error| AuthError::SecretStore(error.to_string()))?
        {
            Some(status) => return Ok(status),
            None if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(AuthError::SecretStore(
                    "platform keyring operation timed out after 5 seconds; unlock the login keychain and retry"
                        .to_owned(),
                ));
            }
            None => std::thread::sleep(std::time::Duration::from_millis(25)),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::{collections::BTreeMap, sync::Mutex};

    use serde_json::json;

    use super::*;

    const PROMPT_VALUE_LIMIT: usize = 127;

    #[derive(Default)]
    struct PromptLimitedAdapter {
        values: Mutex<BTreeMap<(String, String), String>>,
        write_arguments: Mutex<Vec<Vec<String>>>,
    }

    impl MacosKeychainAdapter for PromptLimitedAdapter {
        fn put_raw(&self, service: &str, key: &str, value: &str) -> Result<()> {
            self.write_arguments
                .lock()
                .expect("write-argument lock")
                .push(security_write_arguments(service, key));
            let truncated = &value.as_bytes()[..value.len().min(PROMPT_VALUE_LIMIT)];
            let truncated = String::from_utf8(truncated.to_vec())
                .expect("test registry and envelopes are ASCII");
            self.values
                .lock()
                .expect("prompt-limited value lock")
                .insert((service.to_owned(), key.to_owned()), truncated);
            Ok(())
        }

        fn get_raw(&self, service: &str, key: &str) -> Result<Option<String>> {
            Ok(self
                .values
                .lock()
                .expect("prompt-limited value lock")
                .get(&(service.to_owned(), key.to_owned()))
                .cloned())
        }

        fn delete_raw(&self, service: &str, key: &str) -> Result<()> {
            self.values
                .lock()
                .expect("prompt-limited value lock")
                .remove(&(service.to_owned(), key.to_owned()));
            Ok(())
        }
    }

    impl PromptLimitedAdapter {
        fn chunk_manifest(&self, service: &str, key: &str) -> ChunkManifest {
            let encoded = self
                .get_raw(service, key)
                .expect("manifest read")
                .expect("stored manifest");
            parse_chunk_manifest(&encoded)
                .expect("manifest parse")
                .expect("chunk manifest")
        }
    }

    struct CrossingErrorAdapter {
        inner: PromptLimitedAdapter,
    }

    impl MacosKeychainAdapter for CrossingErrorAdapter {
        fn put_raw(&self, service: &str, key: &str, value: &str) -> Result<()> {
            self.inner.put_raw(service, key, value)?;
            Err(AuthError::SecretStore(
                "injected platform status failure after write".to_owned(),
            ))
        }

        fn get_raw(&self, service: &str, key: &str) -> Result<Option<String>> {
            self.inner.get_raw(service, key)
        }

        fn delete_raw(&self, service: &str, key: &str) -> Result<()> {
            self.inner.delete_raw(service, key)
        }
    }

    fn registry(active: &str, key_material: &str) -> String {
        json!({
            "schema_version": 1,
            "state_root_identity": "state-root-identity",
            "active_generation_id": active,
            "generations": {
                (active): key_material,
                "22222222-2222-4222-8222-222222222222": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
            }
        })
        .to_string()
    }

    #[test]
    fn long_registry_round_trips_byte_exactly_without_secret_arguments() {
        let adapter = PromptLimitedAdapter::default();
        let registry = registry(
            "11111111-1111-4111-8111-111111111111",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );
        assert!(registry.len() > PROMPT_VALUE_LIMIT);

        put_with(&adapter, "service", "registry", &registry).expect("platform adapter write");
        let readback = get_with(&adapter, "service", "registry")
            .expect("platform adapter read")
            .expect("stored platform value");

        assert!(
            readback == registry,
            "long registry readback was not byte-exact"
        );
        let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(registry.as_bytes()));
        let arguments = adapter.write_arguments.lock().expect("write-argument lock");
        assert!(
            arguments.iter().flatten().all(|argument| {
                !argument.contains(&registry)
                    && !argument.contains("11111111-1111-4111-8111-111111111111")
                    && !argument.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                    && !argument.contains(&digest)
            }),
            "secret bytes or their digest entered the command arguments"
        );
    }

    #[test]
    fn chunked_update_and_delete_remove_superseded_internal_items() {
        let adapter = PromptLimitedAdapter::default();
        let first = registry(
            "11111111-1111-4111-8111-111111111111",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );
        let second = registry(
            "33333333-3333-4333-8333-333333333333",
            "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
        );
        put_with(&adapter, "service", "registry", &first).expect("first chunked write");
        let first_manifest = adapter.chunk_manifest("service", "registry");
        let first_chunk_keys = (0..first_manifest.chunk_count)
            .map(|index| chunk_key("registry", &first_manifest.write_id, index))
            .collect::<Vec<_>>();

        put_with(&adapter, "service", "registry", &second).expect("second chunked write");
        assert!(
            get_with(&adapter, "service", "registry")
                .expect("second readback")
                .is_some_and(|readback| readback == second),
            "updated registry was not byte-exact"
        );
        {
            let values = adapter.values.lock().expect("prompt-limited value lock");
            assert!(first_chunk_keys.iter().all(|key| {
                !values
                    .keys()
                    .any(|(service, stored_key)| service == "service" && stored_key == key)
            }));
        }

        delete_with(&adapter, "service", "registry").expect("chunked delete");
        assert!(
            get_with(&adapter, "service", "registry")
                .expect("deleted readback")
                .is_none()
        );
        assert!(
            adapter
                .values
                .lock()
                .expect("prompt-limited value lock")
                .is_empty()
        );
    }

    #[test]
    fn chunk_reassembly_rejects_tampering_without_disclosing_the_registry() {
        let adapter = PromptLimitedAdapter::default();
        let registry = registry(
            "11111111-1111-4111-8111-111111111111",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );
        put_with(&adapter, "service", "registry", &registry).expect("chunked write");
        let manifest = adapter.chunk_manifest("service", "registry");
        adapter
            .values
            .lock()
            .expect("prompt-limited value lock")
            .insert(
                (
                    "service".to_owned(),
                    chunk_key("registry", &manifest.write_id, 0),
                ),
                URL_SAFE_NO_PAD.encode(b"tampered"),
            );

        let error = get_with(&adapter, "service", "registry")
            .expect_err("tampered chunk must fail closed")
            .to_string();
        assert!(error.contains("exact digest"));
        assert!(!error.contains(&registry));
        assert!(!error.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
    }

    #[test]
    fn legacy_raw_and_reserved_prefix_values_remain_unambiguous() {
        let adapter = PromptLimitedAdapter::default();
        adapter
            .put_raw("service", "legacy", "legacy-value")
            .expect("legacy raw seed");
        assert_eq!(
            get_with(&adapter, "service", "legacy").expect("legacy raw read"),
            Some("legacy-value".to_owned())
        );

        let reserved = format!("{CHUNK_MANIFEST_PREFIX}not-a-manifest");
        put_with(&adapter, "service", "reserved", &reserved).expect("reserved prefix write");
        assert!(
            get_with(&adapter, "service", "reserved")
                .expect("reserved prefix read")
                .is_some_and(|readback| readback == reserved)
        );
    }

    #[test]
    fn exact_readback_reconciles_a_write_that_crossed_before_status_failed() {
        let adapter = CrossingErrorAdapter {
            inner: PromptLimitedAdapter::default(),
        };
        let registry = registry(
            "11111111-1111-4111-8111-111111111111",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );

        put_with(&adapter, "service", "registry", &registry)
            .expect("exact readback reconciles crossed writes");
        assert!(
            get_with(&adapter, "service", "registry")
                .expect("reconciled readback")
                .is_some_and(|readback| readback == registry)
        );
    }
}
