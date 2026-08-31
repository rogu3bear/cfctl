use std::{collections::BTreeMap, fmt, sync::Arc};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac as _};
use serde::{Deserialize, Serialize};
use sha2_compat::{Digest as _, Sha256};
use uuid::Uuid;

use crate::{AuthError, KeyringSecretStore, Result, SecretBackend, SecretStore};

pub const EVIDENCE_HMAC_ALGORITHM: &str = "hmac-sha256";
const REGISTRY_SCHEMA_VERSION: u8 = 1;
const RECOVERY_INTENT_SCHEMA_VERSION: u8 = 1;
const RECOVERY_PLAN_TTL_MINUTES: i64 = 15;
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceKeyRecoveryPreviewV1 {
    pub location_identity: String,
    pub registry_byte_count: usize,
    pub malformed_class: String,
    pub authenticated_descriptor_count: usize,
    pub authenticated_proof_count: usize,
    pub backend: SecretBackend,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceKeyRecoveryPlanV1 {
    pub plan_id: String,
    pub location_identity: String,
    pub registry_byte_count: usize,
    pub malformed_class: String,
    pub authenticated_descriptor_count: usize,
    pub authenticated_proof_count: usize,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub state: String,
    pub backend: SecretBackend,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceKeyRecoveryPlanStatusV1 {
    pub plan_id: String,
    pub location_identity: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub state: String,
    pub next_action: String,
    pub backend: SecretBackend,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RecoveryIntentStateV1 {
    Prepared,
    ReplacementPublished,
    Completed,
    Revoked,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceKeyRecoveryIntentV1 {
    schema_version: u8,
    plan_id: String,
    location_identity: String,
    registry_byte_count: usize,
    registry_sha256: String,
    malformed_class: String,
    authenticated_descriptor_count: usize,
    authenticated_proof_count: usize,
    quarantine_identity: String,
    replacement_registry: String,
    state_root_identity: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    state: RecoveryIntentStateV1,
}

impl fmt::Debug for EvidenceKeyRecoveryIntentV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvidenceKeyRecoveryIntentV1")
            .field("plan_id", &self.plan_id)
            .field("location_identity", &self.location_identity)
            .field("registry_byte_count", &self.registry_byte_count)
            .field("malformed_class", &self.malformed_class)
            .field(
                "authenticated_descriptor_count",
                &self.authenticated_descriptor_count,
            )
            .field("authenticated_proof_count", &self.authenticated_proof_count)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
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

    pub fn recover_preview(
        &self,
        marker_present: bool,
        authenticated_descriptor_count: usize,
        authenticated_proof_count: usize,
    ) -> Result<EvidenceKeyRecoveryPreviewV1> {
        if marker_present {
            return Err(AuthError::SecretStore(
                "malformed-registry recovery requires the evidence-root marker to be absent"
                    .to_owned(),
            ));
        }
        if authenticated_descriptor_count != 0 || authenticated_proof_count != 0 {
            return Err(AuthError::SecretStore(
                "malformed-registry recovery requires zero authenticated local artifacts"
                    .to_owned(),
            ));
        }
        let registry_key = self.registry_key();
        let encoded = self
            .store
            .recoverable_unmanaged_value(&registry_key)?
            .ok_or_else(|| {
                AuthError::SecretStore(
                    "malformed-registry recovery requires exactly one canonical registry item"
                        .to_owned(),
                )
            })?;
        if self.store.locate(&registry_key)? != Some(self.required_backend)
            || self.required_backend != SecretBackend::PlatformKeyring
        {
            return Err(AuthError::SecretStore(
                "malformed-registry recovery is restricted to the direct platform keyring"
                    .to_owned(),
            ));
        }
        let malformed_class = classify_malformed_registry(&encoded)?;
        Ok(EvidenceKeyRecoveryPreviewV1 {
            location_identity: self.location_identity.clone(),
            registry_byte_count: encoded.len(),
            malformed_class: malformed_class.to_owned(),
            authenticated_descriptor_count,
            authenticated_proof_count,
            backend: self.required_backend,
        })
    }

    pub fn create_recovery_plan(
        &self,
        marker_present: bool,
        authenticated_descriptor_count: usize,
        authenticated_proof_count: usize,
    ) -> Result<EvidenceKeyRecoveryPlanV1> {
        self.create_recovery_plan_at(
            marker_present,
            authenticated_descriptor_count,
            authenticated_proof_count,
            Utc::now(),
        )
    }

    fn create_recovery_plan_at(
        &self,
        marker_present: bool,
        authenticated_descriptor_count: usize,
        authenticated_proof_count: usize,
        now: DateTime<Utc>,
    ) -> Result<EvidenceKeyRecoveryPlanV1> {
        let preview = self.recover_preview(
            marker_present,
            authenticated_descriptor_count,
            authenticated_proof_count,
        )?;
        let registry_key = self.registry_key();
        let encoded = self
            .store
            .recoverable_unmanaged_value(&registry_key)?
            .ok_or_else(|| {
                AuthError::SecretStore(
                    "malformed-registry recovery plan requires the previewed registry".to_owned(),
                )
            })?;
        if encoded.len() != preview.registry_byte_count
            || classify_malformed_registry(&encoded)? != preview.malformed_class
        {
            return Err(AuthError::SecretStore(
                "malformed registry drifted while the private recovery plan was created".to_owned(),
            ));
        }
        let plan_id = Uuid::new_v4().to_string();
        let intent_key = self.recovery_intent_key(&plan_id)?;
        if self.store.get(&intent_key)?.is_some() {
            return Err(AuthError::SecretStore(
                "opaque recovery plan identity already exists".to_owned(),
            ));
        }
        let state_root_identity = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(Uuid::new_v4().as_bytes()))
        );
        let generation_id = Uuid::new_v4().to_string();
        let mut key = [0_u8; 32];
        rand::fill(&mut key);
        let replacement = EvidenceKeyRegistryV1 {
            schema_version: REGISTRY_SCHEMA_VERSION,
            state_root_identity: state_root_identity.clone(),
            active_generation_id: generation_id.clone(),
            generations: BTreeMap::from([(generation_id, URL_SAFE_NO_PAD.encode(key))]),
        };
        let expires_at = now + Duration::minutes(RECOVERY_PLAN_TTL_MINUTES);
        let intent = EvidenceKeyRecoveryIntentV1 {
            schema_version: RECOVERY_INTENT_SCHEMA_VERSION,
            plan_id: plan_id.clone(),
            location_identity: self.location_identity.clone(),
            registry_byte_count: encoded.len(),
            registry_sha256: format!("sha256:{}", hex::encode(Sha256::digest(encoded.as_bytes()))),
            malformed_class: preview.malformed_class.clone(),
            authenticated_descriptor_count,
            authenticated_proof_count,
            quarantine_identity: format!(
                "{REGISTRY_KEY_PREFIX}/{}/recovery-quarantine/{plan_id}",
                self.location_identity
            ),
            replacement_registry: serde_json::to_string(&replacement)?,
            state_root_identity,
            created_at: now,
            expires_at,
            state: RecoveryIntentStateV1::Prepared,
        };
        self.save_recovery_intent(&intent)?;
        Ok(self.public_recovery_plan(&intent))
    }

    pub fn recovery_plan_status(&self, plan_id: &str) -> Result<EvidenceKeyRecoveryPlanStatusV1> {
        let intent = self.load_recovery_intent(plan_id)?;
        Ok(self.public_recovery_plan_status(&intent))
    }

    pub fn revoke_recovery_plan(&self, plan_id: &str) -> Result<EvidenceKeyRecoveryPlanStatusV1> {
        let mut intent = self.load_recovery_intent(plan_id)?;
        if intent.state != RecoveryIntentStateV1::Prepared {
            return Err(AuthError::SecretStore(
                "only an unused prepared recovery plan can be revoked".to_owned(),
            ));
        }
        if self.store.get(&intent.quarantine_identity)?.is_some() {
            return Err(AuthError::SecretStore(
                "recovery already crossed into quarantine custody and must be resumed, not revoked"
                    .to_owned(),
            ));
        }
        intent.state = RecoveryIntentStateV1::Revoked;
        self.save_recovery_intent(&intent)?;
        Ok(self.public_recovery_plan_status(&intent))
    }

    pub fn resume_malformed_registry(
        &self,
        plan_id: &str,
        marker_identity: Option<&str>,
        authenticated_descriptor_count: usize,
        authenticated_proof_count: usize,
    ) -> Result<EvidenceKeyStatusV1> {
        let mut intent = self.load_recovery_intent(plan_id)?;
        match intent.state {
            RecoveryIntentStateV1::Completed => {
                return Err(AuthError::SecretStore(
                    "recovery plan is already completed and cannot be replayed".to_owned(),
                ));
            }
            RecoveryIntentStateV1::Revoked => {
                return Err(AuthError::SecretStore(
                    "recovery plan is revoked".to_owned(),
                ));
            }
            RecoveryIntentStateV1::Prepared | RecoveryIntentStateV1::ReplacementPublished => {}
        }
        if authenticated_descriptor_count != intent.authenticated_descriptor_count
            || authenticated_proof_count != intent.authenticated_proof_count
            || authenticated_descriptor_count != 0
            || authenticated_proof_count != 0
        {
            return Err(AuthError::SecretStore(
                "authenticated local artifact custody drifted after recovery planning".to_owned(),
            ));
        }
        if marker_identity.is_some_and(|marker| marker != intent.state_root_identity) {
            return Err(AuthError::SecretStore(
                "evidence-root marker conflicts with the private recovery intent".to_owned(),
            ));
        }
        let quarantine = self.store.get(&intent.quarantine_identity)?;
        if quarantine.is_none() && Utc::now() >= intent.expires_at {
            return Err(AuthError::SecretStore(
                "unused recovery plan expired before any protected transition".to_owned(),
            ));
        }
        let registry_key = self.registry_key();
        let current = self.store.get(&registry_key)?;
        let original = match quarantine.as_deref() {
            Some(value) => value.to_owned(),
            None => current.clone().ok_or_else(|| {
                AuthError::SecretStore(
                    "planned malformed registry disappeared before quarantine".to_owned(),
                )
            })?,
        };
        if original.len() != intent.registry_byte_count
            || format!(
                "sha256:{}",
                hex::encode(Sha256::digest(original.as_bytes()))
            ) != intent.registry_sha256
            || classify_malformed_registry(&original)? != intent.malformed_class
        {
            return Err(AuthError::SecretStore(
                "private recovery binding does not match the current or quarantined registry"
                    .to_owned(),
            ));
        }
        if current.as_deref() != Some(intent.replacement_registry.as_str()) {
            self.store.recover_malformed_value(
                &registry_key,
                &original,
                &intent.quarantine_identity,
                &intent.replacement_registry,
            )?;
        }
        let status = self.status(Some(&intent.state_root_identity))?;
        intent.state = RecoveryIntentStateV1::ReplacementPublished;
        self.save_recovery_intent(&intent)?;
        Ok(status)
    }

    pub fn complete_recovery_plan(
        &self,
        plan_id: &str,
        marker_identity: &str,
    ) -> Result<EvidenceKeyRecoveryPlanStatusV1> {
        let mut intent = self.load_recovery_intent(plan_id)?;
        if marker_identity != intent.state_root_identity {
            return Err(AuthError::SecretStore(
                "recovery completion marker does not match the private recovery intent".to_owned(),
            ));
        }
        match intent.state {
            RecoveryIntentStateV1::ReplacementPublished => {}
            RecoveryIntentStateV1::Prepared => {
                return Err(AuthError::SecretStore(
                    "recovery plan has not published its replacement authority".to_owned(),
                ));
            }
            RecoveryIntentStateV1::Completed => {
                return Err(AuthError::SecretStore(
                    "recovery plan is already completed and cannot be replayed".to_owned(),
                ));
            }
            RecoveryIntentStateV1::Revoked => {
                return Err(AuthError::SecretStore(
                    "revoked recovery plan cannot be completed".to_owned(),
                ));
            }
        }
        self.status(Some(marker_identity))?;
        intent.state = RecoveryIntentStateV1::Completed;
        self.save_recovery_intent(&intent)?;
        Ok(self.public_recovery_plan_status(&intent))
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

    fn recovery_intent_key(&self, plan_id: &str) -> Result<String> {
        let canonical = Uuid::parse_str(plan_id)
            .ok()
            .filter(|candidate| candidate.to_string() == plan_id)
            .ok_or_else(|| {
                AuthError::SecretStore(
                    "recovery plan identity must be one canonical lowercase hyphenated UUID"
                        .to_owned(),
                )
            })?;
        Ok(format!(
            "{REGISTRY_KEY_PREFIX}/{}/recovery-intent-v1/{canonical}",
            self.location_identity
        ))
    }

    fn load_recovery_intent(&self, plan_id: &str) -> Result<EvidenceKeyRecoveryIntentV1> {
        let key = self.recovery_intent_key(plan_id)?;
        let encoded = self.store.get(&key)?.ok_or_else(|| {
            AuthError::SecretStore("recovery plan does not exist in private custody".to_owned())
        })?;
        if self.store.locate(&key)? != Some(self.required_backend)
            || self.required_backend != SecretBackend::PlatformKeyring
        {
            return Err(AuthError::SecretStore(
                "recovery plan must remain in the direct platform keyring".to_owned(),
            ));
        }
        let intent: EvidenceKeyRecoveryIntentV1 = serde_json::from_str(&encoded)?;
        self.validate_recovery_intent(&intent)?;
        if intent.plan_id != plan_id {
            return Err(AuthError::SecretStore(
                "private recovery intent identity differs from its lookup identity".to_owned(),
            ));
        }
        Ok(intent)
    }

    fn save_recovery_intent(&self, intent: &EvidenceKeyRecoveryIntentV1) -> Result<()> {
        self.validate_recovery_intent(intent)?;
        let key = self.recovery_intent_key(&intent.plan_id)?;
        let encoded = serde_json::to_string(intent)?;
        self.store.put(&key, &encoded)?;
        if self.store.locate(&key)? != Some(self.required_backend) {
            return Err(AuthError::SecretStore(
                "private recovery intent was not stored in the required backend".to_owned(),
            ));
        }
        let readback = self.store.get(&key)?.ok_or_else(|| {
            AuthError::SecretStore("private recovery intent readback is missing".to_owned())
        })?;
        let readback: EvidenceKeyRecoveryIntentV1 = serde_json::from_str(&readback)?;
        if readback != *intent {
            return Err(AuthError::SecretStore(
                "private recovery intent readback differs from the intended state".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_recovery_intent(&self, intent: &EvidenceKeyRecoveryIntentV1) -> Result<()> {
        let canonical_plan_id = Uuid::parse_str(&intent.plan_id)
            .ok()
            .filter(|candidate| candidate.to_string() == intent.plan_id)
            .is_some();
        let digest_is_canonical =
            intent
                .registry_sha256
                .strip_prefix("sha256:")
                .is_some_and(|digest| {
                    digest.len() == 64
                        && digest
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                });
        let expected_quarantine = format!(
            "{REGISTRY_KEY_PREFIX}/{}/recovery-quarantine/{}",
            self.location_identity, intent.plan_id
        );
        let replacement: EvidenceKeyRegistryV1 =
            serde_json::from_str(&intent.replacement_registry)?;
        validate_registry(&replacement)?;
        if intent.schema_version != RECOVERY_INTENT_SCHEMA_VERSION
            || !canonical_plan_id
            || intent.location_identity != self.location_identity
            || !digest_is_canonical
            || !matches!(
                intent.malformed_class.as_str(),
                "invalid_json_registry" | "invalid_registry_contract"
            )
            || intent.authenticated_descriptor_count != 0
            || intent.authenticated_proof_count != 0
            || intent.quarantine_identity != expected_quarantine
            || replacement.state_root_identity != intent.state_root_identity
            || intent.created_at >= intent.expires_at
        {
            return Err(AuthError::SecretStore(
                "private recovery intent is malformed or bound to another authority".to_owned(),
            ));
        }
        Ok(())
    }

    fn public_recovery_plan(
        &self,
        intent: &EvidenceKeyRecoveryIntentV1,
    ) -> EvidenceKeyRecoveryPlanV1 {
        EvidenceKeyRecoveryPlanV1 {
            plan_id: intent.plan_id.clone(),
            location_identity: intent.location_identity.clone(),
            registry_byte_count: intent.registry_byte_count,
            malformed_class: intent.malformed_class.clone(),
            authenticated_descriptor_count: intent.authenticated_descriptor_count,
            authenticated_proof_count: intent.authenticated_proof_count,
            created_at: intent.created_at,
            expires_at: intent.expires_at,
            state: recovery_intent_state_name(intent.state).to_owned(),
            backend: self.required_backend,
        }
    }

    fn public_recovery_plan_status(
        &self,
        intent: &EvidenceKeyRecoveryIntentV1,
    ) -> EvidenceKeyRecoveryPlanStatusV1 {
        let next_action = match intent.state {
            RecoveryIntentStateV1::Prepared => "recover_with_confirmation_before_expiry",
            RecoveryIntentStateV1::ReplacementPublished => {
                "resume_recovery_to_finalize_local_marker"
            }
            RecoveryIntentStateV1::Completed => "none_completed_single_use",
            RecoveryIntentStateV1::Revoked => "none_revoked",
        };
        EvidenceKeyRecoveryPlanStatusV1 {
            plan_id: intent.plan_id.clone(),
            location_identity: intent.location_identity.clone(),
            created_at: intent.created_at,
            expires_at: intent.expires_at,
            state: recovery_intent_state_name(intent.state).to_owned(),
            next_action: next_action.to_owned(),
            backend: self.required_backend,
        }
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

fn classify_malformed_registry(encoded: &str) -> Result<&'static str> {
    if let Ok(registry) = serde_json::from_str::<EvidenceKeyRegistryV1>(encoded)
        && validate_registry(&registry).is_ok()
    {
        return Err(AuthError::SecretStore(
            "canonical evidence registry is valid; malformed recovery is not applicable".to_owned(),
        ));
    }
    if serde_json::from_str::<serde_json::Value>(encoded).is_ok() {
        Ok("invalid_registry_contract")
    } else {
        Ok("invalid_json_registry")
    }
}

fn recovery_intent_state_name(state: RecoveryIntentStateV1) -> &'static str {
    match state {
        RecoveryIntentStateV1::Prepared => "prepared",
        RecoveryIntentStateV1::ReplacementPublished => "replacement_published",
        RecoveryIntentStateV1::Completed => "completed",
        RecoveryIntentStateV1::Revoked => "revoked",
    }
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

    #[derive(Default)]
    struct PlatformMemorySecretStore {
        inner: MemorySecretStore,
        put_attempts: AtomicUsize,
        delete_attempts: AtomicUsize,
    }

    impl SecretStore for PlatformMemorySecretStore {
        fn put(&self, key: &str, value: &str) -> Result<()> {
            self.put_attempts.fetch_add(1, Ordering::AcqRel);
            self.inner.put(key, value)
        }

        fn get(&self, key: &str) -> Result<Option<String>> {
            self.inner.get(key)
        }

        fn delete(&self, key: &str) -> Result<()> {
            self.delete_attempts.fetch_add(1, Ordering::AcqRel);
            self.inner.delete(key)
        }

        fn locate(&self, key: &str) -> Result<Option<SecretBackend>> {
            Ok(self.inner.get(key)?.map(|_| SecretBackend::PlatformKeyring))
        }
    }

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
    fn malformed_registry_recovery_is_plan_bound_quarantined_and_non_disclosing() {
        let store = Arc::new(PlatformMemorySecretStore::default());
        let manager = EvidenceKeyManager::new(
            store.clone(),
            identity("recovery-location"),
            SecretBackend::PlatformKeyring,
        )
        .expect("manager");
        let malformed = "{".repeat(128);
        store
            .inner
            .put(&manager.registry_key(), &malformed)
            .expect("malformed registry seeds");

        let preview = manager
            .recover_preview(false, 0, 0)
            .expect("exact malformed state previews");
        assert_eq!(preview.registry_byte_count, 128);
        assert_eq!(preview.malformed_class, "invalid_json_registry");
        let serialized = serde_json::to_string(&preview).expect("preview serializes");
        let secret_digest = format!(
            "sha256:{}",
            hex::encode(Sha256V11::digest(malformed.as_bytes()))
        );
        assert!(!serialized.contains(&malformed));
        assert!(
            !serialized.contains(&secret_digest),
            "public recovery preview must not expose a secret-derived digest oracle"
        );
        assert_eq!(
            store.put_attempts.load(Ordering::Acquire),
            0,
            "recovery preview must remain strictly read-only"
        );
        assert_eq!(
            store.delete_attempts.load(Ordering::Acquire),
            0,
            "recovery preview must not delete platform state"
        );
        assert!(manager.recover_preview(true, 0, 0).is_err());
        assert!(manager.recover_preview(false, 1, 0).is_err());
        assert!(manager.recover_preview(false, 0, 1).is_err());

        let plan = manager
            .create_recovery_plan(false, 0, 0)
            .expect("private recovery plan creates");
        assert!(Uuid::parse_str(&plan.plan_id).is_ok());
        assert_eq!(plan.state, "prepared");
        let public_plan = serde_json::to_string(&plan).expect("public plan serializes");
        assert!(!public_plan.contains(&malformed));
        assert!(!public_plan.contains(&secret_digest));
        let intent = manager
            .load_recovery_intent(&plan.plan_id)
            .expect("private intent reads");
        assert!(intent.registry_sha256.contains(&secret_digest));
        assert!(!public_plan.contains(&intent.quarantine_identity));
        assert!(!public_plan.contains(&intent.state_root_identity));
        let private_debug = format!("{intent:?}");
        assert!(!private_debug.contains(&malformed));
        assert!(!private_debug.contains(&secret_digest));
        assert!(!private_debug.contains(&intent.quarantine_identity));
        assert!(!private_debug.contains(&intent.replacement_registry));
        assert!(!private_debug.contains(&intent.state_root_identity));

        let status = manager
            .resume_malformed_registry(&plan.plan_id, None, 0, 0)
            .expect("exact private plan recovers");
        let root = status
            .state_root_identity
            .as_deref()
            .expect("recovery publishes bound root");
        assert_eq!(root, intent.state_root_identity);
        assert_eq!(
            store
                .get(&intent.quarantine_identity)
                .expect("quarantine reads")
                .as_deref(),
            Some(malformed.as_str())
        );
        let completed = manager
            .complete_recovery_plan(&plan.plan_id, root)
            .expect("marker-bound recovery completes");
        assert_eq!(completed.state, "completed");
        assert!(
            manager
                .resume_malformed_registry(&plan.plan_id, Some(root), 0, 0)
                .is_err(),
            "consumed recovery cannot replay"
        );
    }

    #[test]
    fn recovery_plan_expiry_revocation_and_custody_drift_fail_closed() {
        let expired_store = Arc::new(PlatformMemorySecretStore::default());
        let expired_manager = EvidenceKeyManager::new(
            expired_store.clone(),
            identity("expired-recovery-location"),
            SecretBackend::PlatformKeyring,
        )
        .expect("expired manager");
        let malformed = "{".repeat(64);
        expired_store
            .inner
            .put(&expired_manager.registry_key(), &malformed)
            .expect("expired malformed registry seeds");
        let old_now = Utc::now() - Duration::minutes(RECOVERY_PLAN_TTL_MINUTES + 1);
        let expired = expired_manager
            .create_recovery_plan_at(false, 0, 0, old_now)
            .expect("expired plan creates at controlled clock");
        assert!(
            expired_manager
                .resume_malformed_registry(&expired.plan_id, None, 0, 0)
                .is_err()
        );
        assert_eq!(
            expired_store
                .get(&expired_manager.registry_key())
                .expect("expired canonical reads")
                .as_deref(),
            Some(malformed.as_str())
        );

        let revoked_store = Arc::new(PlatformMemorySecretStore::default());
        let revoked_manager = EvidenceKeyManager::new(
            revoked_store.clone(),
            identity("revoked-recovery-location"),
            SecretBackend::PlatformKeyring,
        )
        .expect("revoked manager");
        revoked_store
            .inner
            .put(&revoked_manager.registry_key(), &malformed)
            .expect("revoked malformed registry seeds");
        let revoked = revoked_manager
            .create_recovery_plan(false, 0, 0)
            .expect("revocable plan creates");
        assert_eq!(
            revoked_manager
                .revoke_recovery_plan(&revoked.plan_id)
                .expect("unused plan revokes")
                .state,
            "revoked"
        );
        assert!(
            revoked_manager
                .resume_malformed_registry(&revoked.plan_id, None, 0, 0)
                .is_err()
        );

        let drift_store = Arc::new(PlatformMemorySecretStore::default());
        let drift_manager = EvidenceKeyManager::new(
            drift_store.clone(),
            identity("drift-recovery-location"),
            SecretBackend::PlatformKeyring,
        )
        .expect("drift manager");
        drift_store
            .inner
            .put(&drift_manager.registry_key(), &malformed)
            .expect("drift malformed registry seeds");
        let drift = drift_manager
            .create_recovery_plan(false, 0, 0)
            .expect("drift-bound plan creates");
        drift_store
            .inner
            .put(&drift_manager.registry_key(), &format!("{malformed}x"))
            .expect("canonical state drifts");
        assert!(
            drift_manager
                .resume_malformed_registry(&drift.plan_id, None, 0, 0)
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
