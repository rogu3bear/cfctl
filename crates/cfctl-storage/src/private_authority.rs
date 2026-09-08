//! Explicit recovery of an existing private registry after macOS device-number
//! drift. A signed, create-only address binding retains every other location
//! input. Nothing scans for a usable key, changes a key, or attaches an authority
//! solely because its root marker matches.
use crate::evidence::{AuthenticatedHistoryV1, evidence_location_identity};
use crate::{EvidenceLifecycleLock, PrivateFileSecretStore, Result, StateStore, StorageError};
use cfctl_auth::{
    EvidenceAuthenticationV1, EvidenceKeyManager, EvidenceKeyStatusV1, EvidenceMacProvider,
    SecretBackend, SecretStore,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::sync::Arc;

const BINDING_PREFIX: &str = "private-authority-binding-v1-";
const BINDING_DOMAIN: &str = "private-authority-location-binding-v1";

fn failure(message: impl Into<String>) -> StorageError {
    StorageError::EvidenceAuthentication(message.into())
}

fn auth_error(error: cfctl_auth::AuthError) -> StorageError {
    failure(error.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocationV1 {
    canonical_data_path: String,
    device_id: u64,
    /// Ordered data, lifecycle lock, bodies, descriptors, and proofs identities.
    object_identities: Vec<String>,
    location_identity: String,
}

impl LocationV1 {
    fn at_device(&self, device_id: u64) -> Result<String> {
        if device_id > u64::from(u32::MAX) || self.object_identities.len() != 5 {
            return Err(failure("invalid macOS device or evidence-location inputs"));
        }
        let prefix = format!("dev:{}:", self.device_id);
        let identities = self
            .object_identities
            .iter()
            .map(|identity| {
                identity
                    .strip_prefix(&prefix)
                    .map(|remaining| format!("dev:{device_id}:{remaining}"))
                    .ok_or_else(|| {
                        failure(
                            "device rebinding requires all five custody objects on the same device",
                        )
                    })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(evidence_location_identity(
            &self.canonical_data_path,
            identities[0].as_bytes(),
            identities[1].as_bytes(),
            identities[2].as_bytes(),
            identities[3].as_bytes(),
            identities[4].as_bytes(),
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewV1 {
    schema_version: u8,
    epoch_id: String,
    current_location: LocationV1,
    previous_device_id: u64,
    original_location_identity: String,
    original_authority: EvidenceKeyStatusV1,
    history: AuthenticatedHistoryV1,
}

impl ReviewV1 {
    fn digest(&self) -> Result<String> {
        Ok(format!(
            "sha256:{}",
            hex::encode(Sha256::digest(serde_json::to_vec(self)?))
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingV1 {
    review: ReviewV1,
    authentication: EvidenceAuthenticationV1,
}

#[derive(Debug, Serialize)]
pub struct PrivateAuthorityRebindPreviewV1 {
    pub review_digest: String,
    pub already_bound: bool,
    pub secret_key_bytes_exposed: bool,
    pub recovery_effect: &'static str,
    review: ReviewV1,
}

impl StateStore {
    fn private_secret_store(&self) -> PrivateFileSecretStore {
        PrivateFileSecretStore::new(self.paths.data_dir.join("private-authority"))
    }

    fn raw_private_manager(&self, location: &str) -> Result<EvidenceKeyManager> {
        EvidenceKeyManager::new(
            Arc::new(self.private_secret_store()),
            location,
            SecretBackend::PrivateFile,
        )
        .map_err(auth_error)
    }

    #[cfg(target_os = "macos")]
    fn private_location(&self) -> Result<LocationV1> {
        let directories = &self.evidence_directories;
        let object_identities = [
            &directories.data_identity,
            &directories.lock_identity,
            &directories.bodies_identity,
            &directories.descriptors_identity,
            &directories.proofs_identity,
        ]
        .into_iter()
        .map(|identity| {
            String::from_utf8(identity.clone())
                .map_err(|_| failure("invalid macOS location identity"))
        })
        .collect::<Result<Vec<_>>>()?;
        let device_id = object_identities[0]
            .strip_prefix("dev:")
            .and_then(|identity| identity.split(':').next())
            .and_then(|device| device.parse::<u64>().ok())
            .ok_or_else(|| failure("invalid macOS evidence device identity"))?;
        let canonical = self
            .paths
            .data_dir
            .canonicalize()
            .map_err(|source| crate::io_error(&self.paths.data_dir, source))?;
        let location = LocationV1 {
            canonical_data_path: canonical
                .to_str()
                .ok_or_else(|| failure("state path is not UTF-8"))?
                .to_owned(),
            device_id,
            object_identities,
            location_identity: self.evidence_location_identity().to_owned(),
        };
        if location.at_device(device_id)? != location.location_identity {
            return Err(failure(
                "private location reconstruction differs from current evidence custody",
            ));
        }
        Ok(location)
    }

    #[cfg(not(target_os = "macos"))]
    fn private_location(&self) -> Result<LocationV1> {
        Err(failure(
            "private device-number rebinding is supported only for macOS location identities",
        ))
    }

    fn binding_name(&self) -> Result<String> {
        let digest = self
            .evidence_location_identity()
            .strip_prefix("sha256:")
            .filter(|digest| {
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            })
            .ok_or_else(|| failure("invalid current evidence location identity"))?;
        Ok(format!("{BINDING_PREFIX}{digest}.json"))
    }

    fn read_private_binding(&self) -> Result<Option<BindingV1>> {
        let name = self.binding_name()?;
        let encoded = crate::read_optional_capability_file(
            &self.evidence_directories.data,
            &name,
            &self.paths.data_dir.join(&name),
        )?;
        encoded
            .map(|bytes| {
                serde_json::from_slice(&bytes).map_err(|_| {
                    failure("private authority binding is malformed; it was preserved")
                })
            })
            .transpose()
    }

    fn original_private_manager(&self, location: &str, root: &str) -> Result<EvidenceKeyManager> {
        let registry_key = format!("evidence-integrity/location/{location}/registry-v1");
        if !self
            .private_secret_store()
            .contains_only(&registry_key)
            .map_err(auth_error)?
        {
            return Err(failure(
                "the exact original private registry is missing or its custody contains additional entries; no registry was selected",
            ));
        }
        let original = self.raw_private_manager(location)?;
        let status = original.status(Some(root)).map_err(auth_error)?;
        if !status.initialized || status.backend != Some(SecretBackend::PrivateFile) {
            return Err(failure(
                "the exact original private registry is unavailable",
            ));
        }
        Ok(original)
    }

    fn validate_private_binding(&self, binding: &BindingV1) -> Result<EvidenceKeyManager> {
        let origin = self
            .private_origin()
            .ok_or_else(|| failure("an active private runtime is required"))?;
        let location = self.private_location()?;
        let root = self
            .evidence_root_identity()?
            .ok_or_else(|| failure("the existing evidence-root marker is required"))?;
        let review = &binding.review;
        if review.schema_version != 1
            || review.epoch_id != origin.epoch_id
            || review.current_location != location
            || review.previous_device_id == location.device_id
            || location.at_device(review.previous_device_id)? != review.original_location_identity
            || review.original_authority.state_root_identity.as_deref() != Some(root.as_str())
        {
            return Err(failure(
                "private authority binding does not match the exact current path, epoch, five custody objects and original root",
            ));
        }
        self.verify_private_binding_signature(binding, &root)
    }

    fn verify_private_binding_signature(
        &self,
        binding: &BindingV1,
        root: &str,
    ) -> Result<EvidenceKeyManager> {
        let original =
            self.original_private_manager(&binding.review.original_location_identity, root)?;
        original
            .verify(
                root,
                BINDING_DOMAIN,
                &serde_json::to_vec(&binding.review)?,
                &binding.authentication,
            )
            .map_err(auth_error)?;
        Ok(original)
    }

    pub(crate) fn private_evidence_key_manager(&self) -> Result<EvidenceKeyManager> {
        let current = self.raw_private_manager(self.evidence_location_identity())?;
        let Some(binding) = self.read_private_binding()? else {
            return Ok(current);
        };
        let _lifecycle = self.lock_evidence_lifecycle()?;
        if current.status(None).map_err(auth_error)?.initialized {
            return Err(failure(
                "both current and rebound private registries are present; authority is ambiguous",
            ));
        }
        self.validate_private_binding(&binding)?;
        // The filesystem identity remains current. Only the secret-store address
        // follows the explicit original-key-authenticated binding.
        EvidenceKeyManager::new(
            Arc::new(BoundPrivateRegistry {
                store: self.private_secret_store(),
                requested_prefix: format!(
                    "evidence-integrity/location/{}/",
                    self.evidence_location_identity()
                ),
                original_prefix: format!(
                    "evidence-integrity/location/{}/",
                    binding.review.original_location_identity
                ),
            }),
            self.evidence_location_identity(),
            SecretBackend::PrivateFile,
        )
        .map_err(auth_error)
    }

    fn review_private_rebind(
        &self,
        previous_device_id: u64,
        lifecycle: &EvidenceLifecycleLock,
    ) -> Result<(ReviewV1, EvidenceKeyManager)> {
        let origin = self
            .private_origin()
            .ok_or_else(|| failure("an active private runtime is required"))?;
        let location = self.private_location()?;
        if previous_device_id == location.device_id {
            return Err(failure(
                "the previous device number must differ from the current one; ordinary initialization or attachment is not rebinding",
            ));
        }
        let root = self.evidence_root_identity()?.ok_or_else(|| {
            failure(
                "the original evidence-root marker is required; it will not be created or replaced",
            )
        })?;
        if self
            .raw_private_manager(self.evidence_location_identity())?
            .status(None)
            .map_err(auth_error)?
            .initialized
        {
            return Err(failure(
                "a current-location private registry already exists; rebinding cannot replace it",
            ));
        }
        if let Some(binding) = self.read_private_binding()? {
            self.validate_private_binding(&binding)?;
        }
        let original_location_identity = location.at_device(previous_device_id)?;
        let original = self.original_private_manager(&original_location_identity, &root)?;
        let original_authority = original.status(Some(&root)).map_err(auth_error)?;
        let mut inspection = self.clone();
        // This private local value can only verify. It cannot authenticate new
        // evidence, escape this method, or become the runtime's authority.
        inspection.evidence_authenticator = Some(Arc::new(HistoryVerifier(original.clone())));
        let history = inspection.authenticated_history(lifecycle)?;
        if history.descriptor_count == 0 || history.proof_count == 0 {
            return Err(failure(
                "original-key continuity requires retained authenticated descriptors and operational proofs; empty or partial history cannot establish recovery",
            ));
        }
        Ok((
            ReviewV1 {
                schema_version: 1,
                epoch_id: origin.epoch_id.clone(),
                current_location: location,
                previous_device_id,
                original_location_identity,
                original_authority,
                history,
            },
            original,
        ))
    }

    /// Reads the original registry and every retained authenticated descriptor,
    /// referenced body and proof. No key, binding, marker or evidence is written.
    pub fn private_authority_rebind_preview(
        &self,
        previous_device_id: u64,
    ) -> Result<PrivateAuthorityRebindPreviewV1> {
        let lifecycle = self.lock_evidence_lifecycle()?;
        let (review, _) = self.review_private_rebind(previous_device_id, &lifecycle)?;
        Ok(PrivateAuthorityRebindPreviewV1 {
            review_digest: review.digest()?,
            already_bound: self.read_private_binding()?.is_some(),
            secret_key_bytes_exposed: false,
            recovery_effect: "create one signed non-secret address binding; preserve original registry, marker, epoch and history",
            review,
        })
    }

    /// The CLI requires explicit confirmation and the exact reviewed digest.
    /// The original registry and existing marker are never modified here.
    pub fn rebind_private_authority(
        &self,
        previous_device_id: u64,
        expected_digest: &str,
    ) -> Result<PrivateAuthorityRebindPreviewV1> {
        self.rebind_private_authority_with_publish(
            previous_device_id,
            expected_digest,
            |store, name, bytes| {
                crate::atomic_create_capability_file(
                    &store.evidence_directories.data,
                    name,
                    bytes,
                    &store.paths.data_dir.join(name),
                )
            },
        )
    }

    fn rebind_private_authority_with_publish(
        &self,
        previous_device_id: u64,
        expected_digest: &str,
        publish: impl FnOnce(&Self, &str, &[u8]) -> Result<()>,
    ) -> Result<PrivateAuthorityRebindPreviewV1> {
        let lifecycle = self.lock_evidence_lifecycle()?;
        let (review, original) = self.review_private_rebind(previous_device_id, &lifecycle)?;
        let digest = review.digest()?;
        if digest != expected_digest {
            return Err(failure(
                "private authority recovery inputs or authenticated history changed; inspect a new preview before confirming",
            ));
        }
        let already_bound = if let Some(existing) = self.read_private_binding()? {
            self.validate_private_binding(&existing)?;
            if existing.review != review {
                return Err(failure(
                    "an existing private binding differs from this review; it was preserved",
                ));
            }
            crate::sync_capability_directory(&self.evidence_directories.data)
                .map_err(|source| crate::write_durability_unknown(&self.paths.data_dir, source))?;
            true
        } else {
            let root = review
                .original_authority
                .state_root_identity
                .as_deref()
                .ok_or_else(|| failure("original authority has no root"))?;
            let authentication = original
                .authenticate(root, BINDING_DOMAIN, &serde_json::to_vec(&review)?)
                .map_err(auth_error)?;
            let binding = BindingV1 {
                review: review.clone(),
                authentication,
            };
            publish(
                self,
                &self.binding_name()?,
                &serde_json::to_vec_pretty(&binding)?,
            )?;
            let readback = self.read_private_binding()?.ok_or_else(|| failure("private binding publication has no readback; preserve all state and inspect status"))?;
            self.validate_private_binding(&readback)?;
            if readback.review != review {
                return Err(failure(
                    "published private binding differs from the reviewed input; preserve it and inspect status",
                ));
            }
            false
        };
        Ok(PrivateAuthorityRebindPreviewV1 {
            review_digest: digest,
            already_bound,
            secret_key_bytes_exposed: false,
            recovery_effect: "original registry retained in place; exact current location bound by its existing key",
            review,
        })
    }

    /// Signed address bindings are also dependents of their signing generation.
    /// Retirement must preserve them even after all ordinary evidence ages out.
    pub(crate) fn private_binding_generation_usage(&self, generation_id: &str) -> Result<usize> {
        if self.private_origin().is_none() {
            return Ok(0);
        }
        let mut count = 0;
        for entry in self
            .evidence_directories
            .data
            .entries()
            .map_err(|source| crate::io_error(&self.paths.data_dir, source))?
        {
            let entry = entry.map_err(|source| crate::io_error(&self.paths.data_dir, source))?;
            let name = entry.file_name();
            let Some(name) = name
                .to_str()
                .filter(|name| name.starts_with(BINDING_PREFIX))
            else {
                continue;
            };
            let path = std::path::Path::new(name);
            let canonical_name = path.extension() == Some(std::ffi::OsStr::new("json"))
                && path
                    .file_stem()
                    .and_then(std::ffi::OsStr::to_str)
                    .and_then(|stem| stem.strip_prefix(BINDING_PREFIX))
                    .is_some_and(|digest| {
                        digest.len() == 64
                            && digest
                                .bytes()
                                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                    });
            if !canonical_name {
                return Err(failure(
                    "private binding history has a noncanonical name; retirement is blocked",
                ));
            }
            let bytes = crate::read_optional_capability_file(
                &self.evidence_directories.data,
                name,
                &self.paths.data_dir.join(name),
            )?
            .ok_or_else(|| failure("private binding disappeared during generation inventory"))?;
            let binding: BindingV1 = serde_json::from_slice(&bytes).map_err(|_| {
                failure("private binding history is malformed; retirement is blocked")
            })?;
            let location = self.private_location()?;
            let root = self
                .evidence_root_identity()?
                .ok_or_else(|| failure("private binding history has no current root"))?;
            let origin = self
                .private_origin()
                .ok_or_else(|| failure("private binding history has no active epoch"))?;
            let review = &binding.review;
            // Earlier bindings remain retirement dependents only when their
            // same path and five incarnations still match and their MAC verifies.
            // This check never attaches an earlier device as current authority.
            if review.schema_version != 1
                || review.epoch_id != origin.epoch_id
                || review.original_authority.state_root_identity.as_deref() != Some(root.as_str())
                || location.at_device(review.current_location.device_id)?
                    != review.current_location.location_identity
                || review
                    .current_location
                    .at_device(review.current_location.device_id)?
                    != review.current_location.location_identity
                || location.at_device(review.previous_device_id)?
                    != review.original_location_identity
            {
                return Err(failure(
                    "private binding history differs from the retained epoch and custody; retirement is blocked",
                ));
            }
            self.verify_private_binding_signature(&binding, &root)?;
            if binding.authentication.key_generation_id == generation_id {
                count += 1;
            }
        }
        Ok(count)
    }
}

/// This address adapter is constructed only after validating a signed binding.
/// It keeps existing lifecycle records in their original private namespace.
struct BoundPrivateRegistry {
    store: PrivateFileSecretStore,
    requested_prefix: String,
    original_prefix: String,
}

impl BoundPrivateRegistry {
    fn original_key(&self, key: &str) -> cfctl_auth::Result<String> {
        key.strip_prefix(&self.requested_prefix)
            .map(|suffix| format!("{}{suffix}", self.original_prefix))
            .ok_or_else(|| {
                cfctl_auth::AuthError::SecretStore(
                    "private registry address is outside the authenticated binding".to_owned(),
                )
            })
    }
}

impl SecretStore for BoundPrivateRegistry {
    fn get(&self, key: &str) -> cfctl_auth::Result<Option<String>> {
        self.store.get(&self.original_key(key)?)
    }
    fn put(&self, key: &str, value: &str) -> cfctl_auth::Result<()> {
        self.store.put(&self.original_key(key)?, value)
    }
    fn delete(&self, key: &str) -> cfctl_auth::Result<()> {
        self.store.delete(&self.original_key(key)?)
    }
    fn locate(&self, key: &str) -> cfctl_auth::Result<Option<SecretBackend>> {
        self.store.locate(&self.original_key(key)?)
    }
}

struct HistoryVerifier(EvidenceKeyManager);
impl EvidenceMacProvider for HistoryVerifier {
    fn location_identity(&self) -> &str {
        self.0.location_identity()
    }
    fn status(&self, _root: Option<&str>) -> cfctl_auth::Result<EvidenceKeyStatusV1> {
        Err(cfctl_auth::AuthError::SecretStore(
            "history inspection cannot qualify an attached runtime authority".to_owned(),
        ))
    }
    fn authenticate(
        &self,
        _root: &str,
        _domain: &str,
        _payload: &[u8],
    ) -> cfctl_auth::Result<EvidenceAuthenticationV1> {
        Err(cfctl_auth::AuthError::SecretStore(
            "history inspection cannot authenticate new records".to_owned(),
        ))
    }
    fn verify(
        &self,
        root: &str,
        domain: &str,
        payload: &[u8],
        authentication: &EvidenceAuthenticationV1,
    ) -> cfctl_auth::Result<()> {
        self.0.verify(root, domain, payload, authentication)
    }
}

#[cfg(all(test, target_os = "macos"))]
#[path = "private_authority_tests.rs"]
mod tests;
