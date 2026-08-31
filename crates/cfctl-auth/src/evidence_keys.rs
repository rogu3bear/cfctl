use std::{collections::BTreeMap, fmt, sync::Arc};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac as _};
use serde::{Deserialize, Serialize};
use sha2_compat::Sha256;
use uuid::Uuid;

use crate::{AuthError, KeyringSecretStore, Result, SecretBackend, SecretStore};

pub const EVIDENCE_HMAC_ALGORITHM: &str = "hmac-sha256";
const REGISTRY_SCHEMA_VERSION: u8 = 1;
const REGISTRY_KEY_PREFIX: &str = "evidence-integrity/location";
const MAC_DOMAIN_PREFIX: &[u8] = b"cfctl-evidence-authentication-v1\0";

#[derive(Debug, thiserror::Error)]
pub enum EvidenceKeyLifecycleError {
    #[error(
        "evidence-key {action} did not change the exact platform registry; the operation may be retried after status readback: {cause}"
    )]
    Unchanged { action: String, cause: String },
    #[error(
        "evidence-key {action} may have changed the platform registry, but exact readback is indeterminate; do not replay this operation until the registry is inspected: {cause}; readback: {readback}"
    )]
    Indeterminate {
        action: String,
        cause: String,
        readback: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceAuthenticationV1 {
    pub algorithm: String,
    pub key_generation_id: String,
    pub tag: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceKeyStatusV1 {
    pub initialized: bool,
    pub state_root_identity: Option<String>,
    pub active_generation_id: Option<String>,
    pub verification_generation_ids: Vec<String>,
    pub backend: Option<SecretBackend>,
}

pub trait EvidenceMacProvider: Send + Sync {
    fn location_identity(&self) -> &str;
    fn status(&self, state_root_identity: Option<&str>) -> Result<EvidenceKeyStatusV1>;
    fn authenticate(
        &self,
        state_root_identity: &str,
        domain: &str,
        payload: &[u8],
    ) -> Result<EvidenceAuthenticationV1>;
    fn verify(
        &self,
        state_root_identity: &str,
        domain: &str,
        payload: &[u8],
        authentication: &EvidenceAuthenticationV1,
    ) -> Result<()>;
}

#[derive(Clone)]
pub struct EvidenceKeyManager {
    store: Arc<dyn SecretStore>,
    location_identity: String,
    required_backend: SecretBackend,
}

impl fmt::Debug for EvidenceKeyManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvidenceKeyManager")
            .field("store", &"[platform keyring]")
            .field("location_identity", &self.location_identity)
            .field("required_backend", &self.required_backend)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceKeyRegistryV1 {
    schema_version: u8,
    state_root_identity: String,
    active_generation_id: String,
    generations: BTreeMap<String, String>,
}

impl fmt::Debug for EvidenceKeyRegistryV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvidenceKeyRegistryV1")
            .field("schema_version", &self.schema_version)
            .field("state_root_identity", &self.state_root_identity)
            .field("active_generation_id", &self.active_generation_id)
            .field(
                "generation_ids",
                &self.generations.keys().collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl EvidenceKeyManager {
    pub fn platform(location_identity: impl Into<String>) -> Result<Self> {
        Self::new(
            Arc::new(KeyringSecretStore),
            location_identity,
            SecretBackend::PlatformKeyring,
        )
    }

    pub fn new(
        store: Arc<dyn SecretStore>,
        location_identity: impl Into<String>,
        required_backend: SecretBackend,
    ) -> Result<Self> {
        let location_identity = location_identity.into();
        validate_identity("evidence state location", &location_identity)?;
        Ok(Self {
            store,
            location_identity,
            required_backend,
        })
    }

    pub fn initialize(&self, state_root_identity: &str) -> Result<EvidenceKeyStatusV1> {
        validate_identity("evidence state root", state_root_identity)?;
        if self.load_registry()?.is_some() {
            return Err(AuthError::SecretStore(
                "evidence key authority is already initialized for this state location".to_owned(),
            ));
        }
        let generation_id = Uuid::new_v4().to_string();
        let mut key = [0_u8; 32];
        rand::fill(&mut key);
        let registry = EvidenceKeyRegistryV1 {
            schema_version: REGISTRY_SCHEMA_VERSION,
            state_root_identity: state_root_identity.to_owned(),
            active_generation_id: generation_id.clone(),
            generations: BTreeMap::from([(generation_id, URL_SAFE_NO_PAD.encode(key))]),
        };
        self.save_registry(&registry)?;
        self.status(Some(state_root_identity))
    }

    pub fn rotate(&self, state_root_identity: &str) -> Result<EvidenceKeyStatusV1> {
        let before = self.require_registry(state_root_identity)?;
        let mut intended_after = before.clone();
        let generation_id = Uuid::new_v4().to_string();
        let mut key = [0_u8; 32];
        rand::fill(&mut key);
        intended_after
            .generations
            .insert(generation_id.clone(), URL_SAFE_NO_PAD.encode(key));
        intended_after.active_generation_id = generation_id;
        self.commit_registry_transition("rotation", &before, &intended_after)
    }

    pub fn rollback_initialize(&self, state_root_identity: &str) -> Result<()> {
        let Some(registry) = self.load_registry()? else {
            return Ok(());
        };
        if registry.state_root_identity != state_root_identity || registry.generations.len() != 1 {
            return Err(AuthError::SecretStore(
                "refusing to roll back an evidence authority that is not the exact fresh initialization"
                    .to_owned(),
            ));
        }
        self.store.delete(&self.registry_key())?;
        if self.load_registry()?.is_some() {
            return Err(AuthError::SecretStore(
                "fresh evidence authority rollback did not remove the platform registry".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn retire(
        &self,
        state_root_identity: &str,
        generation_id: &str,
        authenticated_artifact_count: usize,
    ) -> Result<EvidenceKeyStatusV1> {
        let before = self.require_registry(state_root_identity)?;
        if before.active_generation_id == generation_id {
            return Err(AuthError::SecretStore(
                "the active evidence key cannot be retired; rotate first".to_owned(),
            ));
        }
        if authenticated_artifact_count != 0 {
            return Err(AuthError::SecretStore(format!(
                "evidence key generation `{generation_id}` authenticates {authenticated_artifact_count} local artifacts and cannot be retired"
            )));
        }
        let mut intended_after = before.clone();
        if intended_after.generations.remove(generation_id).is_none() {
            return Err(AuthError::SecretStore(format!(
                "evidence key generation `{generation_id}` does not exist"
            )));
        }
        self.commit_registry_transition("retirement", &before, &intended_after)
    }

    fn registry_key(&self) -> String {
        format!(
            "{REGISTRY_KEY_PREFIX}/{}/registry-v1",
            self.location_identity
        )
    }

    fn load_registry(&self) -> Result<Option<EvidenceKeyRegistryV1>> {
        let key = self.registry_key();
        let Some(encoded) = self.store.get(&key)? else {
            return Ok(None);
        };
        let backend = self.store.locate(&key)?;
        if backend != Some(self.required_backend) {
            return Err(AuthError::SecretStore(format!(
                "evidence key authority must use {:?}, found {backend:?}",
                self.required_backend
            )));
        }
        let registry: EvidenceKeyRegistryV1 = serde_json::from_str(&encoded)?;
        validate_registry(&registry)?;
        Ok(Some(registry))
    }

    fn require_registry(&self, state_root_identity: &str) -> Result<EvidenceKeyRegistryV1> {
        let registry = self.load_registry()?.ok_or_else(|| {
            AuthError::SecretStore(
                "evidence key authority is not initialized; run `cfctl auth evidence-key init`"
                    .to_owned(),
            )
        })?;
        if registry.state_root_identity != state_root_identity {
            return Err(AuthError::SecretStore(
                "evidence state-root identity differs from the platform-held authority".to_owned(),
            ));
        }
        Ok(registry)
    }

    fn save_registry(&self, registry: &EvidenceKeyRegistryV1) -> Result<()> {
        validate_registry(registry)?;
        let key = self.registry_key();
        self.store.put(&key, &serde_json::to_string(registry)?)?;
        if self.store.locate(&key)? != Some(self.required_backend) {
            return Err(AuthError::SecretStore(
                "evidence key authority was not stored in the required backend".to_owned(),
            ));
        }
        let readback = self.load_registry()?.ok_or_else(|| {
            AuthError::SecretStore("evidence key authority readback is missing".to_owned())
        })?;
        if readback.state_root_identity != registry.state_root_identity
            || readback.active_generation_id != registry.active_generation_id
            || readback.generations != registry.generations
        {
            return Err(AuthError::SecretStore(
                "evidence key authority readback differs from the written registry".to_owned(),
            ));
        }
        Ok(())
    }
    fn commit_registry_transition(
        &self,
        action: &str,
        before: &EvidenceKeyRegistryV1,
        intended_after: &EvidenceKeyRegistryV1,
    ) -> Result<EvidenceKeyStatusV1> {
        validate_registry(before)?;
        validate_registry(intended_after)?;
        match self.save_registry(intended_after) {
            Ok(()) => Ok(self.status_from_registry(intended_after)),
            Err(cause) => match self.load_registry() {
                Ok(Some(readback)) if readback == *intended_after => {
                    Ok(self.status_from_registry(intended_after))
                }
                Ok(Some(readback)) if readback == *before => {
                    Err(EvidenceKeyLifecycleError::Unchanged {
                        action: action.to_owned(),
                        cause: cause.to_string(),
                    }
                    .into())
                }
                Ok(Some(_)) => Err(EvidenceKeyLifecycleError::Indeterminate {
                    action: action.to_owned(),
                    cause: cause.to_string(),
                    readback: "a valid third registry state differs from both exact prestate and intended poststate"
                        .to_owned(),
                }
                .into()),
                Ok(None) => Err(EvidenceKeyLifecycleError::Indeterminate {
                    action: action.to_owned(),
                    cause: cause.to_string(),
                    readback: "the platform registry is missing".to_owned(),
                }
                .into()),
                Err(readback) => Err(EvidenceKeyLifecycleError::Indeterminate {
                    action: action.to_owned(),
                    cause: cause.to_string(),
                    readback: readback.to_string(),
                }
                .into()),
            },
        }
    }

    fn status_from_registry(&self, registry: &EvidenceKeyRegistryV1) -> EvidenceKeyStatusV1 {
        let mut verification_generation_ids = registry
            .generations
            .keys()
            .filter(|generation| **generation != registry.active_generation_id)
            .cloned()
            .collect::<Vec<_>>();
        verification_generation_ids.sort();
        EvidenceKeyStatusV1 {
            initialized: true,
            state_root_identity: Some(registry.state_root_identity.clone()),
            active_generation_id: Some(registry.active_generation_id.clone()),
            verification_generation_ids,
            backend: Some(self.required_backend),
        }
    }
}

impl EvidenceMacProvider for EvidenceKeyManager {
    fn location_identity(&self) -> &str {
        &self.location_identity
    }

    fn status(&self, state_root_identity: Option<&str>) -> Result<EvidenceKeyStatusV1> {
        let key = self.registry_key();
        let backend = self.store.locate(&key)?;
        let Some(registry) = self.load_registry()? else {
            return Ok(EvidenceKeyStatusV1 {
                initialized: false,
                state_root_identity: None,
                active_generation_id: None,
                verification_generation_ids: Vec::new(),
                backend,
            });
        };
        if let Some(expected) = state_root_identity
            && registry.state_root_identity != expected
        {
            return Err(AuthError::SecretStore(
                "evidence state-root marker differs from the platform-held authority".to_owned(),
            ));
        }
        let mut status = self.status_from_registry(&registry);
        status.backend = backend;
        Ok(status)
    }

    fn authenticate(
        &self,
        state_root_identity: &str,
        domain: &str,
        payload: &[u8],
    ) -> Result<EvidenceAuthenticationV1> {
        let registry = self.require_registry(state_root_identity)?;
        let generation_id = registry.active_generation_id;
        let key = registry.generations.get(&generation_id).ok_or_else(|| {
            AuthError::SecretStore("active evidence key generation is missing".to_owned())
        })?;
        Ok(EvidenceAuthenticationV1 {
            algorithm: EVIDENCE_HMAC_ALGORITHM.to_owned(),
            key_generation_id: generation_id.clone(),
            tag: calculate_tag(key, state_root_identity, &generation_id, domain, payload)?,
        })
    }

    fn verify(
        &self,
        state_root_identity: &str,
        domain: &str,
        payload: &[u8],
        authentication: &EvidenceAuthenticationV1,
    ) -> Result<()> {
        if authentication.algorithm != EVIDENCE_HMAC_ALGORITHM {
            return Err(AuthError::SecretStore(
                "evidence authentication algorithm is unsupported".to_owned(),
            ));
        }
        let registry = self.require_registry(state_root_identity)?;
        let key = registry
            .generations
            .get(&authentication.key_generation_id)
            .ok_or_else(|| {
                AuthError::SecretStore(format!(
                    "evidence key generation `{}` is unavailable",
                    authentication.key_generation_id
                ))
            })?;
        let key = decode_key(key)?;
        let supplied_tag = hex::decode(&authentication.tag).map_err(|_| {
            AuthError::SecretStore("evidence authentication tag is not valid hex".to_owned())
        })?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&key)
            .map_err(|_| AuthError::SecretStore("evidence MAC key is invalid".to_owned()))?;
        update_mac(
            &mut mac,
            state_root_identity,
            &authentication.key_generation_id,
            domain,
            payload,
        );
        mac.verify_slice(&supplied_tag).map_err(|_| {
            AuthError::SecretStore("evidence authentication tag did not verify".to_owned())
        })
    }
}

fn validate_registry(registry: &EvidenceKeyRegistryV1) -> Result<()> {
    validate_identity("evidence state root", &registry.state_root_identity)?;
    if registry.schema_version != REGISTRY_SCHEMA_VERSION
        || Uuid::parse_str(&registry.active_generation_id).is_err()
        || !registry
            .generations
            .contains_key(&registry.active_generation_id)
        || registry.generations.is_empty()
        || registry.generations.iter().any(|(generation, key)| {
            Uuid::parse_str(generation).is_err() || decode_key(key).is_err()
        })
    {
        return Err(AuthError::SecretStore(
            "evidence key registry is malformed".to_owned(),
        ));
    }
    Ok(())
}

fn validate_identity(label: &str, value: &str) -> Result<()> {
    let valid = value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    });
    if valid {
        Ok(())
    } else {
        Err(AuthError::SecretStore(format!(
            "{label} must be a canonical lowercase sha256 identity"
        )))
    }
}

fn decode_key(encoded: &str) -> Result<Vec<u8>> {
    let key = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| AuthError::SecretStore("evidence MAC key is malformed".to_owned()))?;
    if key.len() != 32 {
        return Err(AuthError::SecretStore(
            "evidence MAC key must contain exactly 256 bits".to_owned(),
        ));
    }
    Ok(key)
}

fn calculate_tag(
    encoded_key: &str,
    state_root_identity: &str,
    generation_id: &str,
    domain: &str,
    payload: &[u8],
) -> Result<String> {
    let key = decode_key(encoded_key)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&key)
        .map_err(|_| AuthError::SecretStore("evidence MAC key is invalid".to_owned()))?;
    update_mac(
        &mut mac,
        state_root_identity,
        generation_id,
        domain,
        payload,
    );
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn update_mac(
    mac: &mut Hmac<Sha256>,
    state_root_identity: &str,
    generation_id: &str,
    domain: &str,
    payload: &[u8],
) {
    for component in [
        MAC_DOMAIN_PREFIX,
        state_root_identity.as_bytes(),
        generation_id.as_bytes(),
        domain.as_bytes(),
        payload,
    ] {
        mac.update(&(component.len() as u64).to_be_bytes());
        mac.update(component);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    use sha2::{Digest as _, Sha256 as Sha256V11};

    use super::*;
    use crate::MemorySecretStore;

    fn identity(label: &str) -> String {
        format!(
            "sha256:{}",
            hex::encode(Sha256V11::digest(label.as_bytes()))
        )
    }
    #[derive(Clone, Copy, Debug)]
    enum TransitionFault {
        RejectPut,
        CommitThenPutError,
        LocateOnceAfterCommit,
        ReadOnceAfterCommit,
        ReadAlwaysAfterCommit,
    }

    #[derive(Default)]
    struct TransitionFaultStore {
        inner: MemorySecretStore,
        next_fault: Mutex<Option<TransitionFault>>,
        fail_next_locate: AtomicBool,
        fail_next_get: AtomicBool,
        fail_all_gets: AtomicBool,
        delete_attempts: AtomicUsize,
        put_attempts: AtomicUsize,
    }

    impl TransitionFaultStore {
        fn arm(&self, fault: TransitionFault) {
            *self.next_fault.lock().expect("fault lock") = Some(fault);
        }

        fn put_attempts(&self) -> usize {
            self.put_attempts.load(Ordering::Acquire)
        }

        fn delete_attempts(&self) -> usize {
            self.delete_attempts.load(Ordering::Acquire)
        }

        fn raw_registry(&self, manager: &EvidenceKeyManager) -> EvidenceKeyRegistryV1 {
            let encoded = self
                .inner
                .get(&manager.registry_key())
                .expect("raw registry read")
                .expect("raw registry exists");
            serde_json::from_str(&encoded).expect("raw registry decodes")
        }
    }

    impl SecretStore for TransitionFaultStore {
        fn put(&self, key: &str, value: &str) -> Result<()> {
            self.put_attempts.fetch_add(1, Ordering::AcqRel);
            let fault = self.next_fault.lock().expect("fault lock").take();
            match fault {
                Some(TransitionFault::RejectPut) => Err(AuthError::SecretStore(
                    "injected failure before registry publication".to_owned(),
                )),
                Some(TransitionFault::CommitThenPutError) => {
                    self.inner.put(key, value)?;
                    Err(AuthError::SecretStore(
                        "injected put error after registry publication".to_owned(),
                    ))
                }
                Some(TransitionFault::LocateOnceAfterCommit) => {
                    self.inner.put(key, value)?;
                    self.fail_next_locate.store(true, Ordering::Release);
                    Ok(())
                }
                Some(TransitionFault::ReadOnceAfterCommit) => {
                    self.inner.put(key, value)?;
                    self.fail_next_get.store(true, Ordering::Release);
                    Ok(())
                }
                Some(TransitionFault::ReadAlwaysAfterCommit) => {
                    self.inner.put(key, value)?;
                    self.fail_all_gets.store(true, Ordering::Release);
                    Ok(())
                }
                None => self.inner.put(key, value),
            }
        }

        fn get(&self, key: &str) -> Result<Option<String>> {
            if self.fail_all_gets.load(Ordering::Acquire)
                || self.fail_next_get.swap(false, Ordering::AcqRel)
            {
                return Err(AuthError::SecretStore(
                    "injected registry readback failure".to_owned(),
                ));
            }
            self.inner.get(key)
        }

        fn delete(&self, key: &str) -> Result<()> {
            self.delete_attempts.fetch_add(1, Ordering::AcqRel);
            self.inner.delete(key)
        }

        fn locate(&self, key: &str) -> Result<Option<SecretBackend>> {
            if self.fail_next_locate.swap(false, Ordering::AcqRel) {
                return Err(AuthError::SecretStore(
                    "injected backend-location failure".to_owned(),
                ));
            }
            self.inner.locate(key)
        }
    }

    fn fault_manager(label: &str) -> (Arc<TransitionFaultStore>, EvidenceKeyManager, String) {
        let store = Arc::new(TransitionFaultStore::default());
        let manager = EvidenceKeyManager::new(
            store.clone(),
            identity(&format!("location-{label}")),
            SecretBackend::Memory,
        )
        .expect("fault manager");
        let root = identity(&format!("root-{label}"));
        manager.initialize(&root).expect("initialize");
        (store, manager, root)
    }

    #[test]
    fn rotation_preserves_verification_and_retirement_is_impact_gated() {
        let manager = EvidenceKeyManager::new(
            Arc::new(MemorySecretStore::default()),
            identity("location"),
            SecretBackend::Memory,
        )
        .expect("manager");
        let root = identity("root");
        let initialized = manager.initialize(&root).expect("initialize");
        let old_generation = initialized.active_generation_id.expect("active generation");
        let old_tag = manager
            .authenticate(&root, "descriptor-v2", b"payload")
            .expect("authenticate");
        let rotated = manager.rotate(&root).expect("rotate");
        assert_ne!(
            rotated.active_generation_id.as_deref(),
            Some(old_generation.as_str())
        );
        manager
            .verify(&root, "descriptor-v2", b"payload", &old_tag)
            .expect("old generation remains verification-only");
        assert!(manager.retire(&root, &old_generation, 1).is_err());
        manager
            .retire(&root, &old_generation, 0)
            .expect("unused old key retires");
        assert!(
            manager
                .verify(&root, "descriptor-v2", b"payload", &old_tag)
                .is_err()
        );
    }
    #[test]
    fn rotation_reconciles_committed_put_location_and_readback_faults() {
        for (index, fault) in [
            TransitionFault::CommitThenPutError,
            TransitionFault::LocateOnceAfterCommit,
            TransitionFault::ReadOnceAfterCommit,
        ]
        .into_iter()
        .enumerate()
        {
            let (store, manager, root) = fault_manager(&format!("rotate-reconcile-{index}"));
            let before = manager.status(Some(&root)).expect("status before rotation");
            let old_generation = before.active_generation_id.expect("old generation");
            let put_attempts = store.put_attempts();
            store.arm(fault);

            let rotated = manager.rotate(&root).expect("exact poststate reconciles");

            assert_ne!(
                rotated.active_generation_id.as_deref(),
                Some(old_generation.as_str())
            );
            assert_eq!(
                rotated.verification_generation_ids,
                vec![old_generation],
                "the exact old generation remains verification-only"
            );
            assert_eq!(store.put_attempts(), put_attempts + 1);
            assert_eq!(store.delete_attempts(), 0);
        }
    }

    #[test]
    fn retirement_reconciles_committed_put_location_and_readback_faults() {
        for (index, fault) in [
            TransitionFault::CommitThenPutError,
            TransitionFault::LocateOnceAfterCommit,
            TransitionFault::ReadOnceAfterCommit,
        ]
        .into_iter()
        .enumerate()
        {
            let (store, manager, root) = fault_manager(&format!("retire-reconcile-{index}"));
            let initialized = manager.status(Some(&root)).expect("initialized status");
            let old_generation = initialized.active_generation_id.expect("old generation");
            manager
                .rotate(&root)
                .expect("rotation creates inactive generation");
            let put_attempts = store.put_attempts();
            store.arm(fault);

            let retired = manager
                .retire(&root, &old_generation, 0)
                .expect("exact poststate reconciles");

            assert!(
                !retired
                    .verification_generation_ids
                    .contains(&old_generation),
                "the retired generation is conclusively absent"
            );
            assert_eq!(store.put_attempts(), put_attempts + 1);
            assert_eq!(store.delete_attempts(), 0);
        }
    }

    #[test]
    fn rejected_rotation_and_retirement_are_exact_unchanged_failures() {
        let (rotation_store, rotation_manager, rotation_root) = fault_manager("rotate-unchanged");
        let rotation_before = rotation_manager
            .status(Some(&rotation_root))
            .expect("rotation prestate");
        rotation_store.arm(TransitionFault::RejectPut);
        assert!(matches!(
            rotation_manager.rotate(&rotation_root),
            Err(AuthError::EvidenceKeyLifecycle(EvidenceKeyLifecycleError::Unchanged { ref action, .. }))
                if action == "rotation"
        ));
        assert_eq!(
            rotation_manager
                .status(Some(&rotation_root))
                .expect("unchanged rotation readback"),
            rotation_before
        );

        let (retirement_store, retirement_manager, retirement_root) =
            fault_manager("retire-unchanged");
        let old_generation = retirement_manager
            .status(Some(&retirement_root))
            .expect("retirement initialized status")
            .active_generation_id
            .expect("old generation");
        retirement_manager
            .rotate(&retirement_root)
            .expect("rotation creates inactive generation");
        let retirement_before = retirement_manager
            .status(Some(&retirement_root))
            .expect("retirement prestate");
        retirement_store.arm(TransitionFault::RejectPut);
        assert!(matches!(
            retirement_manager.retire(&retirement_root, &old_generation, 0),
            Err(AuthError::EvidenceKeyLifecycle(EvidenceKeyLifecycleError::Unchanged { ref action, .. }))
                if action == "retirement"
        ));
        assert_eq!(
            retirement_manager
                .status(Some(&retirement_root))
                .expect("unchanged retirement readback"),
            retirement_before
        );
    }

    #[test]
    fn unreadable_rotation_and_retirement_are_non_replayable_without_compensation() {
        let (rotation_store, rotation_manager, rotation_root) =
            fault_manager("rotate-indeterminate");
        let rotation_before = rotation_store.raw_registry(&rotation_manager);
        let rotation_puts = rotation_store.put_attempts();
        rotation_store.arm(TransitionFault::ReadAlwaysAfterCommit);
        assert!(matches!(
            rotation_manager.rotate(&rotation_root),
            Err(AuthError::EvidenceKeyLifecycle(EvidenceKeyLifecycleError::Indeterminate { ref action, .. }))
                if action == "rotation"
        ));
        let rotation_after = rotation_store.raw_registry(&rotation_manager);
        assert_ne!(
            rotation_after, rotation_before,
            "the crossed rotation remains"
        );
        assert_eq!(rotation_store.put_attempts(), rotation_puts + 1);
        assert_eq!(rotation_store.delete_attempts(), 0);

        let (retirement_store, retirement_manager, retirement_root) =
            fault_manager("retire-indeterminate");
        let old_generation = retirement_manager
            .status(Some(&retirement_root))
            .expect("retirement initialized status")
            .active_generation_id
            .expect("old generation");
        retirement_manager
            .rotate(&retirement_root)
            .expect("rotation creates inactive generation");
        let retirement_puts = retirement_store.put_attempts();
        retirement_store.arm(TransitionFault::ReadAlwaysAfterCommit);
        assert!(matches!(
            retirement_manager.retire(&retirement_root, &old_generation, 0),
            Err(AuthError::EvidenceKeyLifecycle(EvidenceKeyLifecycleError::Indeterminate { ref action, .. }))
                if action == "retirement"
        ));
        let retirement_after = retirement_store.raw_registry(&retirement_manager);
        assert!(
            !retirement_after.generations.contains_key(&old_generation),
            "read-only reconciliation must never recreate a possibly retired generation"
        );
        assert_eq!(retirement_store.put_attempts(), retirement_puts + 1);
        assert_eq!(retirement_store.delete_attempts(), 0);
    }

    #[test]
    fn authentication_binds_root_generation_domain_and_payload() {
        let manager = EvidenceKeyManager::new(
            Arc::new(MemorySecretStore::default()),
            identity("location"),
            SecretBackend::Memory,
        )
        .expect("manager");
        let root = identity("root");
        manager.initialize(&root).expect("initialize");
        let tag = manager
            .authenticate(&root, "descriptor-v2", b"payload")
            .expect("authenticate");
        manager
            .verify(&root, "descriptor-v2", b"payload", &tag)
            .expect("exact binding verifies");
        assert!(manager.verify(&root, "proof-v2", b"payload", &tag).is_err());
        assert!(
            manager
                .verify(&root, "descriptor-v2", b"changed", &tag)
                .is_err()
        );
        assert!(
            manager
                .verify(&identity("other-root"), "descriptor-v2", b"payload", &tag)
                .is_err()
        );
    }

    #[test]
    fn registry_and_authentication_are_strict_and_debug_is_redacted() {
        let manager = EvidenceKeyManager::new(
            Arc::new(MemorySecretStore::default()),
            identity("strict-location"),
            SecretBackend::Memory,
        )
        .expect("manager");
        let root = identity("strict-root");
        manager.initialize(&root).expect("initialize");
        let authentication = manager
            .authenticate(&root, "descriptor-v2", b"payload")
            .expect("authenticate");
        let mut authentication_json =
            serde_json::to_value(&authentication).expect("authentication JSON");
        authentication_json["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<EvidenceAuthenticationV1>(authentication_json).is_err());

        let registry = manager
            .load_registry()
            .expect("registry reads")
            .expect("registry");
        let mut registry_json = serde_json::to_value(&registry).expect("registry JSON");
        registry_json["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<EvidenceKeyRegistryV1>(registry_json).is_err());
        let debug = format!("{registry:?}");
        assert!(
            registry
                .generations
                .values()
                .all(|key| !debug.contains(key))
        );
    }
}
