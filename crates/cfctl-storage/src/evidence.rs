//! Storage-owned immutable evidence bodies, descriptors, and operational-proof joins.

use std::{
    cmp::Reverse,
    collections::BinaryHeap,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
};

use cap_std::{ambient_authority, fs::Dir, time::SystemTime};
use cfctl_auth::{EVIDENCE_HMAC_ALGORITHM, EvidenceAuthenticationV1};
use cfctl_core::{
    EvidenceClass, EvidenceV1, OperationalProofOutcomeV1, OperationalProofV1, hash_value,
    redact_json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{
    AuthenticatedEvidenceArtifactCountsV1, EvidenceDirectoryCapabilities, EvidenceLifecycleLock,
    OperationalProofFailureV1, OperationalProofPageV1, Result, RuntimePaths, StateStore,
    StorageError, io_error, same_filesystem_identity, set_private_file_permissions,
    sync_capability_directory, unsafe_managed_document, write_durability_unknown,
};

const DESCRIPTOR_MAC_DOMAIN: &str = "evidence-descriptor-v2";
const PROOF_MAC_DOMAIN: &str = "operational-proof-v2";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceDescriptorV1 {
    schema_version: u8,
    generated_at: DateTime<Utc>,
    class: EvidenceClass,
    content_hash: String,
    path: String,
    metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedEnvelopeV2<T> {
    storage_schema_version: u8,
    state_root_identity: String,
    payload: T,
    authentication: EvidenceAuthenticationV1,
}

type AuthenticatedEvidenceDescriptorV2 = AuthenticatedEnvelopeV2<EvidenceDescriptorV1>;
type AuthenticatedOperationalProofV2 = AuthenticatedEnvelopeV2<OperationalProofV1>;

impl EvidenceDescriptorV1 {
    fn from_evidence(evidence: &EvidenceV1) -> Self {
        Self {
            schema_version: evidence.schema_version,
            generated_at: evidence.generated_at,
            class: evidence.class,
            content_hash: evidence.content_hash.clone(),
            path: evidence.path.clone(),
            metadata: evidence.metadata.clone(),
        }
    }

    fn into_evidence(self) -> EvidenceV1 {
        EvidenceV1 {
            schema_version: self.schema_version,
            generated_at: self.generated_at,
            class: self.class,
            content_hash: self.content_hash,
            path: self.path,
            metadata: self.metadata,
        }
    }
}

impl StateStore {
    /// Requires the filesystem marker and attached evidence authenticator to
    /// name one initialized authority before a protected provider boundary.
    pub fn require_qualifying_evidence_authority(&self) -> Result<()> {
        self.require_canonical_evidence_data_root()?;
        let state_root_identity = self.require_evidence_root_identity()?;
        let status = self
            .require_evidence_authenticator()?
            .status(Some(&state_root_identity))
            .map_err(authentication_error)?;
        if !status.initialized
            || status.state_root_identity.as_deref() != Some(state_root_identity.as_str())
        {
            return Err(StorageError::EvidenceAuthentication(
                "filesystem evidence-root identity and platform evidence authority are inconsistent; refusing to cross a provider boundary"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Writes a redacted immutable body and a separately content-addressed
    /// descriptor. Existing body hashes and paths remain stable. Repeated
    /// writes of the same body reuse the first immutable descriptor; a caller
    /// cannot relabel identical bytes under a different evidence class.
    pub fn write_evidence(&self, class: EvidenceClass, value: &Value) -> Result<EvidenceV1> {
        let _lifecycle = self.lock_evidence_lifecycle()?;
        let (evidence, body_digest) = self.write_evidence_body(class, value)?;
        let content_hash = evidence.content_hash.clone();

        let descriptor_path = evidence_descriptor_path(&self.paths, &body_digest);
        let descriptor_name = format!("{body_digest}.json");
        if capability_file_exists(
            &self.evidence_directories.descriptors,
            &descriptor_name,
            &descriptor_path,
        )? {
            return confirm_exact_existing_immutable(
                &self.evidence_directories.descriptors,
                &descriptor_path,
                || {
                    self.load_matching_evidence_descriptor(
                        &content_hash,
                        class,
                        &evidence,
                        &descriptor_path,
                        "immutable evidence descriptor conflicts with the requested evidence identity",
                    )
                },
            );
        }
        let descriptor = EvidenceDescriptorV1::from_evidence(&evidence);
        let authenticator = self.require_evidence_authenticator()?;
        let state_root_identity = self.require_evidence_root_identity()?;
        let payload = serde_json::to_vec(&descriptor)?;
        let authentication = authenticator
            .authenticate(&state_root_identity, DESCRIPTOR_MAC_DOMAIN, &payload)
            .map_err(authentication_error)?;
        let descriptor_bytes = serde_json::to_vec_pretty(&AuthenticatedEvidenceDescriptorV2 {
            storage_schema_version: 2,
            state_root_identity,
            payload: descriptor,
            authentication,
        })?;
        reconcile_evidence_descriptor_publication_with_sync(
            self,
            atomic_create_capability_file(
                &self.evidence_directories.descriptors,
                &descriptor_name,
                &descriptor_bytes,
                &descriptor_path,
            ),
            evidence,
            &descriptor_path,
            sync_capability_directory,
        )
    }

    /// Writes only the historical redacted body. This audit lane creates no
    /// descriptor or proof and can never qualify future authority.
    pub fn write_audit_evidence(&self, class: EvidenceClass, value: &Value) -> Result<EvidenceV1> {
        self.write_evidence_body(class, value)
            .map(|(evidence, _)| evidence)
    }

    fn load_matching_evidence_descriptor(
        &self,
        content_hash: &str,
        class: EvidenceClass,
        evidence: &EvidenceV1,
        descriptor_path: &Path,
        conflict: &'static str,
    ) -> Result<EvidenceV1> {
        let stored = self.load_evidence_descriptor(content_hash)?;
        if stored.class != class
            || stored.content_hash != content_hash
            || stored.path != evidence.path
        {
            return Err(unsafe_managed_document(descriptor_path, conflict));
        }
        Ok(stored)
    }

    fn write_evidence_body(
        &self,
        class: EvidenceClass,
        value: &Value,
    ) -> Result<(EvidenceV1, String)> {
        let redacted = redact_json(value);
        let body_bytes = serde_json::to_vec_pretty(&redacted)?;
        let body_digest = hex::encode(Sha256::digest(&body_bytes));
        let content_hash = format!("sha256:{body_digest}");
        let body_path = evidence_body_path(&self.paths, &body_digest);
        create_or_validate_immutable_capability(
            &self.evidence_directories.bodies,
            &format!("{body_digest}.json"),
            &body_path,
            &body_bytes,
            &body_digest,
        )?;
        let evidence = EvidenceV1::new(class, &content_hash, &body_path.display().to_string());
        Ok((evidence, body_digest))
    }

    /// Loads one authenticated descriptor and joins it to its exact body.
    pub fn load_evidence(&self, content_hash: &str) -> Result<EvidenceV1> {
        let _lifecycle = self.lock_evidence_lifecycle()?;
        self.load_evidence_descriptor(content_hash)
    }

    /// Loads one authenticated descriptor and payload under one lifecycle lock.
    pub fn load_evidence_value(&self, content_hash: &str) -> Result<(EvidenceV1, Value)> {
        let _lifecycle = self.lock_evidence_lifecycle()?;
        let evidence = self.load_evidence_descriptor(content_hash)?;
        let value = self.read_audit_evidence_value(content_hash)?;
        Ok((evidence, value))
    }

    /// Loads one independently addressed descriptor and joins it to its exact
    /// content-addressed body. A body without this descriptor remains readable
    /// only through the explicit audit lane and is never qualification evidence.
    fn load_evidence_descriptor(&self, content_hash: &str) -> Result<EvidenceV1> {
        Ok(self
            .load_authenticated_evidence_descriptor(content_hash)?
            .payload
            .into_evidence())
    }

    fn load_authenticated_evidence_descriptor(
        &self,
        content_hash: &str,
    ) -> Result<AuthenticatedEvidenceDescriptorV2> {
        let body_digest = canonical_digest(content_hash, "evidence body")?;
        let descriptor_path = evidence_descriptor_path(&self.paths, body_digest);
        let descriptor_bytes = read_required_capability_file(
            &self.evidence_directories.descriptors,
            &format!("{body_digest}.json"),
            &descriptor_path,
        )?;
        let envelope: AuthenticatedEvidenceDescriptorV2 =
            serde_json::from_slice(&descriptor_bytes).map_err(|_| {
                StorageError::InvalidOperationalProof(
                    "legacy or malformed evidence descriptor is readable only as historical body evidence and cannot qualify"
                        .to_owned(),
                )
            })?;
        if envelope.storage_schema_version != 2 {
            return Err(StorageError::InvalidOperationalProof(
                "evidence descriptor authentication envelope version is unsupported".to_owned(),
            ));
        }
        let authenticator = self.require_evidence_authenticator()?;
        let expected_root = self.require_evidence_root_identity()?;
        if envelope.state_root_identity != expected_root
            || envelope.authentication.algorithm != EVIDENCE_HMAC_ALGORITHM
        {
            return Err(StorageError::InvalidOperationalProof(
                "evidence descriptor is bound to a different root or algorithm".to_owned(),
            ));
        }
        let payload = serde_json::to_vec(&envelope.payload)?;
        authenticator
            .verify(
                &expected_root,
                DESCRIPTOR_MAC_DOMAIN,
                &payload,
                &envelope.authentication,
            )
            .map_err(authentication_error)?;
        if envelope.payload.content_hash != content_hash {
            return Err(unsafe_managed_document(
                &descriptor_path,
                "evidence descriptor content identity differs from its filename",
            ));
        }
        let body_path = evidence_body_path(&self.paths, body_digest);
        validate_descriptor(&envelope.payload, &body_path)?;
        read_hashed_capability_file(
            &self.evidence_directories.bodies,
            &format!("{body_digest}.json"),
            &body_path,
            body_digest,
        )?;
        Ok(envelope)
    }

    /// Loads an authenticated evidence payload and rejects body-only history.
    pub fn read_evidence_value(&self, content_hash: &str) -> Result<Value> {
        let (_evidence, value) = self.load_evidence_value(content_hash)?;
        Ok(value)
    }

    /// Loads a body by historical content identity without qualification.
    pub fn read_audit_evidence_value(&self, content_hash: &str) -> Result<Value> {
        let digest = canonical_digest(content_hash, "evidence body")?;
        let path = evidence_body_path(&self.paths, digest);
        let bytes = read_hashed_capability_file(
            &self.evidence_directories.bodies,
            &format!("{digest}.json"),
            &path,
            digest,
        )?;
        serde_json::from_slice(&bytes).map_err(StorageError::Json)
    }

    /// Indexes a live-read proof only after independently resolving and exactly
    /// matching its evidence descriptor and body.
    pub fn record_operational_proof(&self, proof: &OperationalProofV1) -> Result<()> {
        let _lifecycle = self.lock_evidence_lifecycle()?;
        validate_operational_proof(proof, true)?;
        validate_operational_evidence(self, proof)?;
        let value = serde_json::to_value(proof)?;
        if redact_json(&value) != value {
            return Err(StorageError::SensitiveData);
        }
        let encoded = serde_json::to_vec_pretty(proof)?;
        let digest = hex::encode(Sha256::digest(&encoded));
        let path = operational_proof_path(&self.paths, &digest);
        let name = format!("{digest}.json");
        if capability_file_exists(&self.evidence_directories.proofs, &name, &path)? {
            return confirm_exact_existing_immutable(
                &self.evidence_directories.proofs,
                &path,
                || {
                    let stored = read_operational_proof_index(self, &name)?;
                    if stored != *proof {
                        return Err(StorageError::InvalidOperationalProof(
                            "content-addressed index entry does not match its stored document"
                                .to_owned(),
                        ));
                    }
                    Ok(())
                },
            );
        }
        let state_root_identity = self.require_evidence_root_identity()?;
        let authentication = self
            .require_evidence_authenticator()?
            .authenticate(&state_root_identity, PROOF_MAC_DOMAIN, &encoded)
            .map_err(authentication_error)?;
        let envelope = AuthenticatedOperationalProofV2 {
            storage_schema_version: 2,
            state_root_identity,
            payload: proof.clone(),
            authentication,
        };
        reconcile_immutable_publication(
            atomic_create_capability_file(
                &self.evidence_directories.proofs,
                &name,
                &serde_json::to_vec_pretty(&envelope)?,
                &path,
            ),
            &self.evidence_directories.proofs,
            &path,
            || {
                let stored = read_operational_proof_index(self, &name)?;
                if stored == *proof {
                    Ok(())
                } else {
                    Err(StorageError::InvalidOperationalProof(
                        "concurrent content-addressed index entry did not match".to_owned(),
                    ))
                }
            },
        )
    }

    /// Returns the exact content identity of a proof whose nested evidence is
    /// already descriptor-qualified.
    pub fn operational_proof_hash(&self, proof: &OperationalProofV1) -> Result<String> {
        validate_operational_proof(proof, false)?;
        validate_operational_evidence(self, proof)?;
        let encoded = serde_json::to_vec_pretty(proof)?;
        Ok(format!("sha256:{}", hex::encode(Sha256::digest(encoded))))
    }

    /// Loads one exact proof identity for a qualification boundary. Historical
    /// proof rows lacking a durable evidence descriptor are deliberately
    /// rejected here.
    pub fn load_operational_proof(&self, proof_hash: &str) -> Result<OperationalProofV1> {
        let digest = canonical_digest(proof_hash, "operational proof").map_err(|_| {
            StorageError::InvalidOperationalProof(
                "proof identity must be canonical lowercase sha256".to_owned(),
            )
        })?;
        read_operational_proof_index(self, &format!("{digest}.json"))
    }

    /// Lists only proof rows eligible for current qualification. Body-only
    /// legacy rows fail closed rather than entering a fresh decision.
    pub fn list_operational_proofs(&self) -> Result<Vec<OperationalProofV1>> {
        let mut proofs = Vec::new();
        for entry in self
            .evidence_directories
            .proofs
            .entries()
            .map_err(|source| io_error(&self.paths.data_dir.join("evidence-index"), source))?
        {
            let entry = entry
                .map_err(|source| io_error(&self.paths.data_dir.join("evidence-index"), source))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if Path::new(&name)
                .extension()
                .and_then(std::ffi::OsStr::to_str)
                != Some("json")
            {
                continue;
            }
            proofs.push(read_operational_proof_index(self, &name)?);
        }
        proofs.sort_by_key(|proof| proof.observed_at);
        Ok(proofs)
    }

    /// Preserves historical classification while retaining only the newest
    /// qualifying storage-v2 proofs. Exact raw V1 rows remain immutable and
    /// nonqualifying; authenticated proofs retain verified account scope, while
    /// unauthenticated candidate failures are unscoped and globally relevant.
    pub fn list_recent_operational_proofs(&self, limit: usize) -> Result<OperationalProofPageV1> {
        let directory = self.paths.data_dir.join("evidence-index");
        let mut newest = BinaryHeap::<Reverse<(SystemTime, String)>>::new();
        let mut total_count = 0_usize;
        let mut legacy_nonqualifying_count = 0_usize;
        let mut failures = Vec::new();
        for entry in self
            .evidence_directories
            .proofs
            .entries()
            .map_err(|source| io_error(&directory, source))?
        {
            let entry = entry.map_err(|source| io_error(&directory, source))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if Path::new(&name)
                .extension()
                .and_then(std::ffi::OsStr::to_str)
                != Some("json")
            {
                continue;
            }
            validate_proof_index_filename(&PathBuf::from(&name))?;
            total_count = total_count.saturating_add(1);
            let metadata = self
                .evidence_directories
                .proofs
                .symlink_metadata(&name)
                .map_err(|source| io_error(&directory.join(&name), source))?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(unsafe_managed_document(
                    &directory.join(&name),
                    "proof index entry must be a regular non-symlink file",
                ));
            }
            let modified = metadata
                .modified()
                .map_err(|source| io_error(&directory.join(&name), source))?;
            let path = directory.join(&name);
            let encoded =
                read_required_capability_file(&self.evidence_directories.proofs, &name, &path)?;
            if serde_json::from_slice::<OperationalProofV1>(&encoded)
                .is_ok_and(|proof| proof.schema_version == 1)
            {
                legacy_nonqualifying_count = legacy_nonqualifying_count.saturating_add(1);
                continue;
            }
            serde_json::from_slice::<Value>(&encoded).map_err(|_| {
                StorageError::InvalidOperationalProof(
                    "malformed operational-proof document is nonqualifying".to_owned(),
                )
            })?;
            if let Err(error) = read_operational_proof_index(self, &name) {
                failures.push(OperationalProofFailureV1 {
                    account_id: None,
                    proof_identity: format!(
                        "sha256:{}",
                        path.file_stem()
                            .and_then(std::ffi::OsStr::to_str)
                            .unwrap_or_default()
                    ),
                    reason: error.to_string(),
                });
                continue;
            }
            if limit == 0 {
                continue;
            }
            newest.push(Reverse((modified, name)));
            if newest.len() > limit {
                newest.pop();
            }
        }
        let mut proofs = newest
            .into_iter()
            .map(|Reverse((_, name))| read_operational_proof_index(self, &name))
            .collect::<Result<Vec<_>>>()?;
        proofs.sort_by_key(|proof| proof.observed_at);
        Ok(OperationalProofPageV1 {
            truncated: total_count > proofs.len() + legacy_nonqualifying_count + failures.len(),
            total_count,
            legacy_nonqualifying_count,
            failures,
            proofs,
        })
    }

    pub fn evidence_key_generation_usage(
        &self,
        _lifecycle: &EvidenceLifecycleLock,
        generation_id: &str,
    ) -> Result<usize> {
        let mut count = 0_usize;
        let descriptor_display = self.paths.data_dir.join("evidence-descriptors");
        for entry in self
            .evidence_directories
            .descriptors
            .entries()
            .map_err(|source| io_error(&descriptor_display, source))?
        {
            let entry = entry.map_err(|source| io_error(&descriptor_display, source))?;
            let name = strict_managed_entry_name(entry.file_name(), &descriptor_display)?;
            let content_hash =
                content_hash_from_managed_name(&name, &descriptor_display, "evidence descriptor")?;
            let envelope = self.load_authenticated_evidence_descriptor(&content_hash)?;
            if envelope.authentication.key_generation_id == generation_id {
                count = count.saturating_add(1);
            }
        }

        let proof_display = self.paths.data_dir.join("evidence-index");
        for entry in self
            .evidence_directories
            .proofs
            .entries()
            .map_err(|source| io_error(&proof_display, source))?
        {
            let entry = entry.map_err(|source| io_error(&proof_display, source))?;
            let name = strict_managed_entry_name(entry.file_name(), &proof_display)?;
            content_hash_from_managed_name(&name, &proof_display, "operational proof")?;
            let envelope = read_authenticated_operational_proof_index(self, &name)?;
            if envelope.authentication.key_generation_id == generation_id {
                count = count.saturating_add(1);
            }
        }
        Ok(count)
    }

    /// Counts storage-v2 candidates without requiring the unavailable key.
    /// Recovery treats any candidate envelope as dependent authority and holds.
    pub fn authenticated_evidence_artifact_counts(
        &self,
        _lifecycle: &EvidenceLifecycleLock,
    ) -> Result<AuthenticatedEvidenceArtifactCountsV1> {
        let descriptor_count = count_authenticated_candidates(
            &self.evidence_directories.descriptors,
            &self.paths.data_dir.join("evidence-descriptors"),
        )?;
        let proof_count = count_authenticated_candidates(
            &self.evidence_directories.proofs,
            &self.paths.data_dir.join("evidence-index"),
        )?;
        Ok(AuthenticatedEvidenceArtifactCountsV1 {
            descriptor_count,
            proof_count,
        })
    }

    fn require_evidence_authenticator(&self) -> Result<&dyn cfctl_auth::EvidenceMacProvider> {
        self.evidence_authenticator.as_deref().ok_or_else(|| {
            StorageError::EvidenceAuthentication(
                "qualifying evidence requires an initialized platform evidence key".to_owned(),
            )
        })
    }

    fn require_evidence_root_identity(&self) -> Result<String> {
        self.evidence_root_identity()?.ok_or_else(|| {
            StorageError::EvidenceAuthentication(
                "evidence state-root identity is missing; run `cfctl auth evidence-key init`"
                    .to_owned(),
            )
        })
    }
}

fn count_authenticated_candidates(directory: &Dir, display: &Path) -> Result<usize> {
    let mut count = 0_usize;
    for entry in directory
        .entries()
        .map_err(|source| io_error(display, source))?
    {
        let entry = entry.map_err(|source| io_error(display, source))?;
        let name = strict_managed_entry_name(entry.file_name(), display)?;
        let path = display.join(&name);
        let bytes = read_required_capability_file(directory, &name, &path)?;
        let value = serde_json::from_slice::<Value>(&bytes).map_err(|_| {
            StorageError::InvalidOperationalProof(format!(
                "managed evidence artifact `{name}` is malformed"
            ))
        })?;
        if value.get("storage_schema_version").is_some() || value.get("authentication").is_some() {
            count = count.saturating_add(1);
        }
    }
    Ok(count)
}

pub(super) fn open_evidence_directories(
    paths: &RuntimePaths,
) -> Result<EvidenceDirectoryCapabilities> {
    let data_metadata = fs::symlink_metadata(&paths.data_dir)
        .map_err(|source| io_error(&paths.data_dir, source))?;
    if data_metadata.file_type().is_symlink() || !data_metadata.is_dir() {
        return Err(unsafe_managed_document(
            &paths.data_dir,
            "managed data root must be a real directory, not a symbolic link",
        ));
    }
    let canonical_data =
        fs::canonicalize(&paths.data_dir).map_err(|source| io_error(&paths.data_dir, source))?;
    let canonical_data_text = canonical_data.to_str().ok_or_else(|| {
        unsafe_managed_document(&paths.data_dir, "canonical state root is not valid UTF-8")
    })?;
    let data = Dir::open_ambient_dir(&canonical_data, ambient_authority())
        .map_err(|source| io_error(&paths.data_dir, source))?;
    let opened_data_metadata = data
        .dir_metadata()
        .map_err(|source| io_error(&paths.data_dir, source))?;
    if !same_ambient_and_capability_identity(&data_metadata, &opened_data_metadata) {
        return Err(unsafe_managed_document(
            &paths.data_dir,
            "managed data root changed while its directory capability was opened",
        ));
    }
    let locks = open_managed_capability_directory(&data, "locks", &paths.data_dir)?;
    let lifecycle_lock_path = paths.data_dir.join("locks").join("evidence-lifecycle.lock");
    let lifecycle_lock =
        open_or_create_capability_lock(&locks, "evidence-lifecycle.lock", &lifecycle_lock_path)?;
    let data_file = data
        .try_clone()
        .map_err(|source| io_error(&paths.data_dir, source))?
        .into_std_file();
    let data_identity = durable_filesystem_identity(&data_file, &paths.data_dir)?;
    let lock_file = lifecycle_lock
        .try_clone()
        .map_err(|source| io_error(&lifecycle_lock_path, source))?
        .into_std();
    let bodies = open_managed_capability_directory(&data, "evidence", &paths.data_dir)?;
    let descriptors =
        open_managed_capability_directory(&data, "evidence-descriptors", &paths.data_dir)?;
    let proofs = open_managed_capability_directory(&data, "evidence-index", &paths.data_dir)?;
    let bodies_path = paths.data_dir.join("evidence");
    let descriptors_path = paths.data_dir.join("evidence-descriptors");
    let proofs_path = paths.data_dir.join("evidence-index");
    let bodies_identity = durable_directory_identity(&bodies, &bodies_path)?;
    let descriptors_identity = durable_directory_identity(&descriptors, &descriptors_path)?;
    let proofs_identity = durable_directory_identity(&proofs, &proofs_path)?;
    let location_identity = evidence_location_identity(
        canonical_data_text,
        &data_identity,
        &durable_filesystem_identity(&lock_file, &lifecycle_lock_path)?,
        &bodies_identity,
        &descriptors_identity,
        &proofs_identity,
    );
    Ok(EvidenceDirectoryCapabilities {
        data,
        data_identity,
        locks,
        lifecycle_lock,
        bodies,
        bodies_identity,
        descriptors,
        descriptors_identity,
        proofs,
        proofs_identity,
        location_identity,
    })
}

fn open_or_create_capability_lock(
    directory: &Dir,
    name: &str,
    display_path: &Path,
) -> Result<cap_std::fs::File> {
    use cap_std::fs::OpenOptions;

    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    let file = directory
        .open_with(name, &options)
        .map_err(|source| io_error(display_path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| io_error(display_path, source))?;
    require_same_capability_entry(directory, name, &metadata, display_path)?;
    if !metadata.is_file() {
        return Err(unsafe_managed_document(
            display_path,
            "evidence lifecycle lock must be a regular file",
        ));
    }
    let standard_file = file
        .try_clone()
        .map_err(|source| io_error(display_path, source))?
        .into_std();
    set_private_file_permissions(&standard_file, display_path)?;
    Ok(file)
}

pub(super) fn require_same_capability_entry(
    directory: &Dir,
    name: &str,
    pinned: &cap_std::fs::Metadata,
    display_path: &Path,
) -> Result<()> {
    let entry = directory
        .symlink_metadata(name)
        .map_err(|source| io_error(display_path, source))?;
    if entry.file_type().is_symlink()
        || !entry.is_file()
        || !same_filesystem_identity(pinned, &entry)
    {
        return Err(unsafe_managed_document(
            display_path,
            "evidence lifecycle lock identity changed after the state authority was opened",
        ));
    }
    Ok(())
}

pub(super) fn require_same_capability_directory(
    parent: &Dir,
    name: &str,
    held: &Dir,
    pinned_identity: &[u8],
    display_path: &Path,
) -> Result<()> {
    let entry = parent
        .symlink_metadata(name)
        .map_err(|source| io_error(display_path, source))?;
    let held_metadata = held
        .dir_metadata()
        .map_err(|source| io_error(display_path, source))?;
    if entry.file_type().is_symlink()
        || !entry.is_dir()
        || !same_filesystem_identity(&held_metadata, &entry)
    {
        return Err(unsafe_managed_document(
            display_path,
            "managed evidence directory identity changed after the state authority was opened",
        ));
    }
    let reopened = parent
        .open_dir(name)
        .map_err(|source| io_error(display_path, source))?;
    let reopened_metadata = reopened
        .dir_metadata()
        .map_err(|source| io_error(display_path, source))?;
    if !same_filesystem_identity(&entry, &reopened_metadata)
        || durable_directory_identity(&reopened, display_path)? != pinned_identity
    {
        return Err(unsafe_managed_document(
            display_path,
            "managed evidence directory identity changed while lifecycle authority was acquired",
        ));
    }
    Ok(())
}

pub(super) fn require_same_canonical_data_root(
    display_path: &Path,
    held: &Dir,
    pinned_identity: &[u8],
) -> Result<()> {
    let ambient_metadata =
        fs::symlink_metadata(display_path).map_err(|source| io_error(display_path, source))?;
    if ambient_metadata.file_type().is_symlink() || !ambient_metadata.is_dir() {
        return Err(unsafe_managed_document(
            display_path,
            "canonical evidence data root must remain a real directory",
        ));
    }
    let canonical =
        fs::canonicalize(display_path).map_err(|source| io_error(display_path, source))?;
    let reopened = Dir::open_ambient_dir(&canonical, ambient_authority())
        .map_err(|source| io_error(display_path, source))?;
    let reopened_metadata = reopened
        .dir_metadata()
        .map_err(|source| io_error(display_path, source))?;
    let held_metadata = held
        .dir_metadata()
        .map_err(|source| io_error(display_path, source))?;
    if !same_ambient_and_capability_identity(&ambient_metadata, &reopened_metadata)
        || !same_filesystem_identity(&held_metadata, &reopened_metadata)
        || durable_directory_identity(&reopened, display_path)? != pinned_identity
    {
        return Err(unsafe_managed_document(
            display_path,
            "canonical evidence data-root identity changed after the state authority was opened",
        ));
    }
    Ok(())
}

fn evidence_location_identity(
    canonical_path: &str,
    data_identity: &[u8],
    lock_identity: &[u8],
    bodies_identity: &[u8],
    descriptors_identity: &[u8],
    proofs_identity: &[u8],
) -> String {
    format!(
        "sha256:{}",
        hex::encode(Sha256::digest(
            [
                b"cfctl-evidence-location-v2\0".as_slice(),
                canonical_path.as_bytes(),
                data_identity,
                lock_identity,
                bodies_identity,
                descriptors_identity,
                proofs_identity,
            ]
            .concat()
        ))
    )
}

fn durable_directory_identity(directory: &Dir, display_path: &Path) -> Result<Vec<u8>> {
    let file = directory
        .try_clone()
        .map_err(|source| io_error(display_path, source))?
        .into_std_file();
    durable_filesystem_identity(&file, display_path)
}

#[cfg(target_os = "macos")]
fn durable_filesystem_identity(file: &fs::File, display_path: &Path) -> Result<Vec<u8>> {
    use std::os::{macos::fs::MetadataExt as _, unix::fs::MetadataExt as _};

    let metadata = file
        .metadata()
        .map_err(|source| io_error(display_path, source))?;
    Ok(format!(
        "dev:{}:ino:{}:birth:{}:{}",
        metadata.dev(),
        metadata.ino(),
        metadata.st_birthtime(),
        metadata.st_birthtime_nsec()
    )
    .into_bytes())
}

#[cfg(target_os = "linux")]
fn durable_filesystem_identity(file: &fs::File, display_path: &Path) -> Result<Vec<u8>> {
    use rustix::fs::{AtFlags, StatxFlags};

    let stat = rustix::fs::statx(
        file,
        "",
        AtFlags::EMPTY_PATH,
        StatxFlags::BASIC_STATS | StatxFlags::BTIME,
    )
    .map_err(|source| io_error(display_path, source.into()))?;
    let present = StatxFlags::from_bits_retain(stat.stx_mask);
    if !present.contains(StatxFlags::BTIME) {
        return Err(StorageError::EvidenceAuthentication(format!(
            "filesystem does not expose a durable birth identity for {}; refusing evidence authority initialization or attachment",
            display_path.display()
        )));
    }
    Ok(format!(
        "dev:{}:{}:ino:{}:birth:{}:{}:mount:{}",
        stat.stx_dev_major,
        stat.stx_dev_minor,
        stat.stx_ino,
        stat.stx_btime.tv_sec,
        stat.stx_btime.tv_nsec,
        stat.stx_mnt_id
    )
    .into_bytes())
}

#[cfg(windows)]
fn durable_filesystem_identity(file: &fs::File, display_path: &Path) -> Result<Vec<u8>> {
    use std::os::windows::fs::MetadataExt as _;

    let metadata = file
        .metadata()
        .map_err(|source| io_error(display_path, source))?;
    let volume = metadata.volume_serial_number().ok_or_else(|| {
        StorageError::EvidenceAuthentication(format!(
            "filesystem does not expose a volume identity for {}; refusing evidence authority initialization or attachment",
            display_path.display()
        ))
    })?;
    let index = metadata.file_index().ok_or_else(|| {
        StorageError::EvidenceAuthentication(format!(
            "filesystem does not expose a file incarnation for {}; refusing evidence authority initialization or attachment",
            display_path.display()
        ))
    })?;
    let created = metadata.creation_time();
    if created == 0 {
        return Err(StorageError::EvidenceAuthentication(format!(
            "filesystem does not expose a nonzero file birth identity for {}; refusing evidence authority initialization or attachment",
            display_path.display()
        )));
    }
    Ok(format!("volume:{volume}:index:{index}:created:{}", created).into_bytes())
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn durable_filesystem_identity(_file: &fs::File, display_path: &Path) -> Result<Vec<u8>> {
    Err(StorageError::EvidenceAuthentication(format!(
        "platform does not expose a durable filesystem incarnation for {}; refusing evidence authority initialization or attachment",
        display_path.display()
    )))
}

#[cfg(unix)]
fn same_ambient_and_capability_identity(
    ambient: &fs::Metadata,
    capability: &cap_std::fs::Metadata,
) -> bool {
    use cap_std::fs::MetadataExt as _;
    use std::os::unix::fs::MetadataExt as _;

    ambient.dev() == capability.dev() && ambient.ino() == capability.ino()
}

#[cfg(windows)]
fn same_ambient_and_capability_identity(
    ambient: &fs::Metadata,
    capability: &cap_std::fs::Metadata,
) -> bool {
    use cap_std::fs::MetadataExt as _;
    use std::os::windows::fs::MetadataExt as _;

    stable_windows_identity_matches(
        (
            ambient.volume_serial_number(),
            ambient.file_index(),
            ambient.creation_time(),
        ),
        (
            capability.volume_serial_number(),
            capability.file_index(),
            capability.creation_time(),
        ),
    )
}

#[cfg(any(windows, test))]
fn stable_windows_identity_matches(
    first: (Option<u32>, Option<u64>, u64),
    second: (Option<u32>, Option<u64>, u64),
) -> bool {
    matches!(
        (first, second),
        ((Some(first_volume), Some(first_index), first_created), (Some(second_volume), Some(second_index), second_created))
            if first_volume == second_volume
                && first_index == second_index
                && first_created != 0
                && second_created != 0
                && first_created == second_created
    )
}

#[cfg(not(any(unix, windows)))]
fn same_ambient_and_capability_identity(
    ambient: &fs::Metadata,
    capability: &cap_std::fs::Metadata,
) -> bool {
    ambient.file_type().is_dir() == capability.file_type().is_dir()
        && ambient.len() == capability.len()
}

fn open_managed_capability_directory(
    parent: &Dir,
    name: &str,
    display_parent: &Path,
) -> Result<Dir> {
    let display_path = display_parent.join(name);
    let metadata = match parent.symlink_metadata(name) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            parent
                .create_dir(name)
                .map_err(|source| io_error(&display_path, source))?;
            parent
                .symlink_metadata(name)
                .map_err(|source| io_error(&display_path, source))?
        }
        Err(source) => return Err(io_error(&display_path, source)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(unsafe_managed_document(
            &display_path,
            "managed evidence directory must not be a symbolic link",
        ));
    }
    let opened = parent
        .open_dir(name)
        .map_err(|source| io_error(&display_path, source))?;
    let opened_metadata = opened
        .dir_metadata()
        .map_err(|source| io_error(&display_path, source))?;
    if !same_filesystem_identity(&metadata, &opened_metadata) {
        return Err(unsafe_managed_document(
            &display_path,
            "managed evidence directory changed while its capability was opened",
        ));
    }
    Ok(opened)
}

pub(super) fn read_optional_capability_file(
    directory: &Dir,
    name: &str,
    display_path: &Path,
) -> Result<Option<Vec<u8>>> {
    use std::io::Read as _;

    let metadata = match directory.symlink_metadata(name) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(io_error(display_path, source)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(unsafe_managed_document(
            display_path,
            "managed evidence entry must be a regular non-symlink file",
        ));
    }
    let mut file = directory
        .open(name)
        .map_err(|source| io_error(display_path, source))?;
    let opened_metadata = file
        .metadata()
        .map_err(|source| io_error(display_path, source))?;
    if !same_filesystem_identity(&metadata, &opened_metadata) {
        return Err(unsafe_managed_document(
            display_path,
            "managed evidence entry changed while it was opened",
        ));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|source| io_error(display_path, source))?;
    Ok(Some(bytes))
}

pub(super) fn atomic_create_capability_file(
    directory: &Dir,
    name: &str,
    bytes: &[u8],
    display_path: &Path,
) -> Result<()> {
    atomic_create_capability_file_with_hooks(
        directory,
        name,
        bytes,
        display_path,
        |_| Ok(()),
        |directory, temporary| directory.remove_file(temporary),
        sync_capability_directory,
    )
}

fn atomic_create_capability_file_with_hooks<Observe, Remove, Sync>(
    directory: &Dir,
    name: &str,
    bytes: &[u8],
    display_path: &Path,
    observe_after_open: Observe,
    remove_temporary: Remove,
    sync_directory: Sync,
) -> Result<()>
where
    Observe: FnOnce(&fs::File) -> Result<()>,
    Remove: FnOnce(&Dir, &str) -> std::io::Result<()>,
    Sync: FnOnce(&Dir) -> std::io::Result<()>,
{
    use cap_std::fs::OpenOptions;

    let temporary = format!(".{name}.tmp-{}", Uuid::new_v4());
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = directory
        .open_with(&temporary, &options)
        .map_err(|source| io_error(display_path, source))?;
    let permission_file = match file.try_clone() {
        Ok(permission_file) => permission_file.into_std(),
        Err(source) => {
            let _ = directory.remove_file(&temporary);
            return Err(io_error(display_path, source));
        }
    };
    if let Err(error) = observe_after_open(&permission_file) {
        let _ = directory.remove_file(&temporary);
        return Err(error);
    }
    if let Err(error) = set_private_file_permissions(&permission_file, display_path) {
        let _ = directory.remove_file(&temporary);
        return Err(error);
    }
    if let Err(source) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        let _ = directory.remove_file(&temporary);
        return Err(io_error(display_path, source));
    }
    drop(file);
    if let Err(source) = directory.hard_link(&temporary, directory, name) {
        if let Err(cleanup_source) = remove_temporary(directory, &temporary)
            && source.kind() == std::io::ErrorKind::AlreadyExists
        {
            let directory_durability = match sync_directory(directory) {
                Ok(()) => "confirmed with the pre-existing final entry".to_owned(),
                Err(sync_error) => format!("not confirmed: {sync_error}"),
            };
            return Err(StorageError::CapabilityPublicationCleanupFailed {
                path: display_path.display().to_string(),
                temporary_name: temporary,
                directory_durability,
                source: cleanup_source,
            });
        }
        return Err(io_error(display_path, source));
    }
    if let Err(source) = remove_temporary(directory, &temporary) {
        let directory_durability = match sync_directory(directory) {
            Ok(()) => "confirmed after the final hard link".to_owned(),
            Err(sync_error) => format!("not confirmed: {sync_error}"),
        };
        return Err(StorageError::CapabilityPublicationCleanupFailed {
            path: display_path.display().to_string(),
            temporary_name: temporary,
            directory_durability,
            source,
        });
    }
    sync_directory(directory).map_err(|source| StorageError::WriteDurabilityUnknown {
        path: display_path.display().to_string(),
        source,
    })?;
    Ok(())
}

fn validate_descriptor(descriptor: &EvidenceDescriptorV1, expected_body_path: &Path) -> Result<()> {
    if descriptor.schema_version != 1
        || Path::new(&descriptor.path) != expected_body_path
        || descriptor.metadata != Value::Null
    {
        return Err(unsafe_managed_document(
            expected_body_path,
            "evidence descriptor identity does not match its content-addressed body",
        ));
    }
    Ok(())
}

fn confirm_exact_existing_immutable<T, Validate>(
    directory: &cap_std::fs::Dir,
    display_path: &Path,
    validate: Validate,
) -> Result<T>
where
    Validate: FnOnce() -> Result<T>,
{
    confirm_exact_existing_immutable_with_sync(
        directory,
        display_path,
        validate,
        sync_capability_directory,
    )
}

fn confirm_exact_existing_immutable_with_sync<T, Validate, Sync>(
    directory: &cap_std::fs::Dir,
    display_path: &Path,
    validate: Validate,
    sync_directory: Sync,
) -> Result<T>
where
    Validate: FnOnce() -> Result<T>,
    Sync: FnOnce(&cap_std::fs::Dir) -> std::io::Result<()>,
{
    let validated = validate()?;
    sync_directory(directory).map_err(|source| write_durability_unknown(display_path, source))?;
    Ok(validated)
}

fn reconcile_evidence_descriptor_publication_with_sync<Sync>(
    store: &StateStore,
    publication: Result<()>,
    proposed: EvidenceV1,
    descriptor_path: &Path,
    sync_directory: Sync,
) -> Result<EvidenceV1>
where
    Sync: FnOnce(&cap_std::fs::Dir) -> std::io::Result<()>,
{
    match publication {
        Ok(()) => Ok(proposed),
        Err(StorageError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::AlreadyExists =>
        {
            confirm_exact_existing_immutable_with_sync(
                &store.evidence_directories.descriptors,
                descriptor_path,
                || {
                    store.load_matching_evidence_descriptor(
                        &proposed.content_hash,
                        proposed.class,
                        &proposed,
                        descriptor_path,
                        "concurrent immutable evidence descriptor conflicts with the requested evidence identity",
                    )
                },
                sync_directory,
            )
        }
        Err(error) => Err(error),
    }
}

fn reconcile_immutable_publication<Validate>(
    publication: Result<()>,
    directory: &cap_std::fs::Dir,
    display_path: &Path,
    validate: Validate,
) -> Result<()>
where
    Validate: FnOnce() -> Result<()>,
{
    reconcile_immutable_publication_with_sync(
        publication,
        directory,
        display_path,
        validate,
        sync_capability_directory,
    )
}

fn reconcile_immutable_publication_with_sync<Validate, Sync>(
    publication: Result<()>,
    directory: &cap_std::fs::Dir,
    display_path: &Path,
    validate: Validate,
    sync_directory: Sync,
) -> Result<()>
where
    Validate: FnOnce() -> Result<()>,
    Sync: FnOnce(&cap_std::fs::Dir) -> std::io::Result<()>,
{
    match publication {
        Ok(()) => Ok(()),
        Err(StorageError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::AlreadyExists =>
        {
            confirm_exact_existing_immutable_with_sync(
                directory,
                display_path,
                validate,
                sync_directory,
            )
        }
        Err(error) => Err(error),
    }
}

fn create_or_validate_immutable_capability(
    directory: &cap_std::fs::Dir,
    name: &str,
    display_path: &Path,
    expected: &[u8],
    digest: &str,
) -> Result<()> {
    reconcile_immutable_publication(
        atomic_create_capability_file(directory, name, expected, display_path),
        directory,
        display_path,
        || {
            let stored = read_hashed_capability_file(directory, name, display_path, digest)?;
            if stored == expected {
                Ok(())
            } else {
                Err(unsafe_managed_document(
                    display_path,
                    "existing immutable document differs from its expected bytes",
                ))
            }
        },
    )
}

fn read_hashed_capability_file(
    directory: &cap_std::fs::Dir,
    name: &str,
    display_path: &Path,
    expected_digest: &str,
) -> Result<Vec<u8>> {
    let bytes = read_required_capability_file(directory, name, display_path)?;
    if hex::encode(Sha256::digest(&bytes)) != expected_digest {
        return Err(unsafe_managed_document(
            display_path,
            "managed evidence bytes do not match their content identity",
        ));
    }
    Ok(bytes)
}

fn read_required_capability_file(
    directory: &cap_std::fs::Dir,
    name: &str,
    display_path: &Path,
) -> Result<Vec<u8>> {
    read_optional_capability_file(directory, name, display_path)?.ok_or_else(|| {
        io_error(
            display_path,
            std::io::Error::from(std::io::ErrorKind::NotFound),
        )
    })
}

fn capability_file_exists(
    directory: &cap_std::fs::Dir,
    name: &str,
    display_path: &Path,
) -> Result<bool> {
    Ok(read_optional_capability_file(directory, name, display_path)?.is_some())
}

fn canonical_digest<'a>(identity: &'a str, label: &str) -> Result<&'a str> {
    identity
        .strip_prefix("sha256:")
        .filter(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or_else(|| StorageError::UnsafeManagedDocument {
            path: label.to_owned(),
            reason: format!("{label} hash must be canonical lowercase sha256"),
        })
}

fn evidence_body_path(paths: &RuntimePaths, digest: &str) -> PathBuf {
    paths
        .data_dir
        .join("evidence")
        .join(format!("{digest}.json"))
}

fn evidence_descriptor_path(paths: &RuntimePaths, digest: &str) -> PathBuf {
    paths
        .data_dir
        .join("evidence-descriptors")
        .join(format!("{digest}.json"))
}

fn operational_proof_path(paths: &RuntimePaths, digest: &str) -> PathBuf {
    paths
        .data_dir
        .join("evidence-index")
        .join(format!("{digest}.json"))
}

fn validate_operational_proof(
    proof: &OperationalProofV1,
    require_credential_generation: bool,
) -> Result<()> {
    if proof.schema_version != 1 {
        return Err(StorageError::InvalidOperationalProof(format!(
            "unsupported schema version {}",
            proof.schema_version
        )));
    }
    if proof.capability_id.trim().is_empty() {
        return Err(StorageError::InvalidOperationalProof(
            "capability identity must be non-empty".to_owned(),
        ));
    }
    validate_sha256_identity("catalog", &proof.catalog_hash)?;
    validate_sha256_identity("input", &proof.input_hash)?;
    validate_optional_scope("profile", proof.profile_id.as_deref())?;
    validate_optional_scope("account", proof.account_id.as_deref())?;
    validate_optional_scope(
        "credential generation",
        proof.credential_generation_id.as_deref(),
    )?;
    if proof.credential_generation_id.is_some() && proof.profile_id.is_none() {
        return Err(StorageError::InvalidOperationalProof(
            "credential generation requires a profile scope".to_owned(),
        ));
    }
    if require_credential_generation
        && (proof.profile_id.is_none() || proof.credential_generation_id.is_none())
    {
        return Err(StorageError::InvalidOperationalProof(
            "new operational proof requires profile and credential-generation scope".to_owned(),
        ));
    }
    if let Some(generation) = proof.credential_generation_id.as_deref()
        && Uuid::parse_str(generation).is_err()
    {
        return Err(StorageError::InvalidOperationalProof(
            "credential generation must be a UUID".to_owned(),
        ));
    }
    if proof.evidence.class != EvidenceClass::LiveRead {
        return Err(StorageError::InvalidOperationalProof(
            "only live-read evidence can enter the operational proof index".to_owned(),
        ));
    }
    validate_sha256_identity("evidence", &proof.evidence.content_hash)?;
    validate_d1_full_export_execution_binding(proof)?;
    validate_mln_0142_execution_binding(proof)?;
    validate_mln_0143_execution_binding(proof)?;
    Ok(())
}

fn validate_d1_full_export_execution_binding(proof: &OperationalProofV1) -> Result<()> {
    let binding = proof.d1_full_export_governed_execution();
    if proof.capability_id == "d1-full-export" && binding.is_none() {
        return Err(StorageError::InvalidOperationalProof(
            "D1 full-export operational proof requires governed-execution provenance".to_owned(),
        ));
    }
    let Some(binding) = binding else {
        return Ok(());
    };
    for (label, value) in [
        ("binding catalog", binding.catalog_hash.as_str()),
        ("target scope", binding.target_scope_hash.as_str()),
        ("output file", binding.output_file_sha256.as_str()),
        ("captured bookmark", binding.at_bookmark_hash.as_str()),
        ("manifest evidence", binding.manifest_evidence_hash.as_str()),
        ("request", binding.request_hash.as_str()),
    ] {
        validate_sha256_identity(label, value)?;
    }
    if binding.schema_version != 1
        || binding.capability_id != "d1-full-export"
        || proof.capability_id != binding.capability_id
        || proof.catalog_hash != binding.catalog_hash
        || proof.input_hash != binding.request_hash
        || proof.evidence.content_hash != binding.manifest_evidence_hash
        || proof.profile_id.as_deref() != Some(binding.profile_id.as_str())
        || proof.credential_generation_id.as_deref()
            != Some(binding.credential_generation_id.as_str())
        || Uuid::parse_str(&binding.operation_id).is_err()
        || Uuid::parse_str(&binding.credential_generation_id).is_err()
        || binding.profile_id.trim().is_empty()
        || binding.completion_status != "completed"
        || proof.outcome != OperationalProofOutcomeV1::Succeeded
        || proof.observed_at != binding.completed_at
    {
        return Err(StorageError::InvalidOperationalProof(
            "D1 full-export binding drifted from its immutable completed proof".to_owned(),
        ));
    }
    Ok(())
}

fn validate_mln_0142_execution_binding(proof: &OperationalProofV1) -> Result<()> {
    let binding = proof.mln_0142_governed_execution();
    if proof.capability_id == "mln-0142-post-import-schema" && binding.is_none() {
        return Err(StorageError::InvalidOperationalProof(
            "MLN 0142 operational proof requires governed-execution provenance".to_owned(),
        ));
    }
    let Some(binding) = binding else {
        return Ok(());
    };
    for (label, value) in [
        ("binding catalog", binding.catalog_hash.as_str()),
        ("target scope", binding.target_scope_hash.as_str()),
        (
            "import boundary",
            binding.import_boundary_evidence_hash.as_str(),
        ),
        ("import source", binding.import_source_sha256.as_str()),
        ("import plan", binding.import_plan_hash.as_str()),
        ("final bookmark", binding.final_bookmark_hash.as_str()),
        (
            "trigger definition",
            binding.trigger_definition_sha256.as_str(),
        ),
        ("manifest evidence", binding.manifest_evidence_hash.as_str()),
        ("request", binding.request_hash.as_str()),
    ] {
        validate_sha256_identity(label, value)?;
    }
    let credential_generation_id = proof.credential_generation_id.as_deref().ok_or_else(|| {
        StorageError::InvalidOperationalProof(
            "MLN 0142 execution binding requires a credential generation".to_owned(),
        )
    })?;
    if binding.schema_version != 1
        || Uuid::parse_str(&binding.operation_id).is_err()
        || Uuid::parse_str(&binding.import_operation_id).is_err()
        || binding.capability_id != proof.capability_id
        || binding.capability_version != 1
        || binding.catalog_hash != proof.catalog_hash
        || binding.manifest_evidence_hash != proof.evidence.content_hash
        || binding.request_hash != proof.input_hash
        || binding.credential_generation_id != credential_generation_id
        || binding.trigger_name != "document_render_jobs_terminal_generation_guard"
        || binding.trigger_definition_sha256
            != "sha256:cb32c4ed1b14799465b90693ac73cf03d4650c3db573f080acc3d3b4cc436c2b"
        || binding.completion_status != "completed"
        || binding.completed_at != proof.observed_at
    {
        return Err(StorageError::InvalidOperationalProof(
            "MLN 0142 governed-execution provenance is incomplete or does not match its operational proof"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_mln_0143_execution_binding(proof: &OperationalProofV1) -> Result<()> {
    let binding = proof.mln_0143_governed_execution();
    if proof.capability_id == "mln-0143-data-invariants" && binding.is_none() {
        return Err(StorageError::InvalidOperationalProof(
            "MLN 0143 operational proof requires governed-execution provenance".to_owned(),
        ));
    }
    let Some(binding) = binding else {
        return Ok(());
    };
    let profile_id = proof.profile_id.as_deref().ok_or_else(|| {
        StorageError::InvalidOperationalProof(
            "MLN 0143 execution binding requires a profile identity".to_owned(),
        )
    })?;
    let credential_generation_id = proof.credential_generation_id.as_deref().ok_or_else(|| {
        StorageError::InvalidOperationalProof(
            "MLN 0143 execution binding requires a credential generation".to_owned(),
        )
    })?;
    for (label, value) in [
        (
            "validator contract",
            binding.validator_contract_hash.as_str(),
        ),
        ("fixed query", binding.fixed_query_sha256.as_str()),
        ("binding catalog", binding.catalog_hash.as_str()),
        ("target scope", binding.target_scope_hash.as_str()),
        ("manifest evidence", binding.manifest_evidence_hash.as_str()),
        ("request", binding.request_hash.as_str()),
        ("profile identity", binding.profile_identity_hash.as_str()),
    ] {
        validate_sha256_identity(label, value)?;
    }
    if let Some(lineage_hash) = binding.cross_operation_lineage_hash.as_deref() {
        validate_sha256_identity("cross-operation lineage", lineage_hash)?;
    }
    let expected_profile_identity = hash_value(&json!({
        "profile_id": profile_id,
        "credential_generation_id": credential_generation_id,
    }))
    .map_err(|error| StorageError::InvalidOperationalProof(error.to_string()))?;
    if binding.schema_version != 1
        || Uuid::parse_str(&binding.operation_id).is_err()
        || binding.capability_id != proof.capability_id
        || binding.capability_version != 5
        || binding.catalog_hash != proof.catalog_hash
        || binding.manifest_evidence_hash != proof.evidence.content_hash
        || binding.request_hash != proof.input_hash
        || binding.profile_identity_hash != expected_profile_identity
        || binding.credential_generation_id != credential_generation_id
        || !matches!(
            binding.phase.as_str(),
            "pre_import" | "post_import" | "post_restore"
        )
        || binding.completion_status != "completed"
        || binding.completed_at != proof.observed_at
        || (binding.phase == "pre_import") != binding.cross_operation_lineage_hash.is_none()
    {
        return Err(StorageError::InvalidOperationalProof(
            "MLN 0143 governed-execution provenance is incomplete or does not match its operational proof"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_sha256_identity(label: &str, identity: &str) -> Result<()> {
    let digest = canonical_digest(identity, label).map_err(|_| {
        StorageError::InvalidOperationalProof(format!(
            "{label} identity must be an exact lowercase sha256 digest"
        ))
    })?;
    debug_assert_eq!(digest.len(), 64);
    Ok(())
}

fn validate_optional_scope(label: &str, value: Option<&str>) -> Result<()> {
    if value.is_some_and(|value| value.trim().is_empty()) {
        return Err(StorageError::InvalidOperationalProof(format!(
            "{label} scope must be non-empty when present"
        )));
    }
    Ok(())
}

fn validate_operational_evidence(store: &StateStore, proof: &OperationalProofV1) -> Result<()> {
    let body_digest =
        canonical_digest(&proof.evidence.content_hash, "evidence body").map_err(|_| {
            StorageError::InvalidOperationalProof(
                "evidence content identity is not canonical lowercase sha256".to_owned(),
            )
        })?;
    let expected_body = evidence_body_path(&store.paths, body_digest);
    if Path::new(&proof.evidence.path) != expected_body {
        return Err(StorageError::InvalidOperationalProof(
            "evidence path is not the content-addressed file in this state store".to_owned(),
        ));
    }
    let stored = store.load_evidence_descriptor(&proof.evidence.content_hash)?;
    if stored != proof.evidence {
        return Err(StorageError::InvalidOperationalProof(
            "nested evidence descriptor differs from its immutable storage-owned descriptor"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_proof_index_filename(path: &Path) -> Result<()> {
    let Some(stem) = path.file_stem().and_then(std::ffi::OsStr::to_str) else {
        return Err(unsafe_managed_document(
            path,
            "proof-index filename is not valid UTF-8",
        ));
    };
    canonical_digest(&format!("sha256:{stem}"), "operational proof")?;
    Ok(())
}

fn read_operational_proof_index(store: &StateStore, name: &str) -> Result<OperationalProofV1> {
    Ok(read_authenticated_operational_proof_index(store, name)?.payload)
}

fn read_authenticated_operational_proof_index(
    store: &StateStore,
    name: &str,
) -> Result<AuthenticatedOperationalProofV2> {
    let path = store.paths.data_dir.join("evidence-index").join(name);
    validate_proof_index_filename(&path)?;
    let filename_digest = path
        .file_stem()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| unsafe_managed_document(&path, "proof-index filename is not valid UTF-8"))?;
    let encoded = read_required_capability_file(&store.evidence_directories.proofs, name, &path)?;
    let envelope: AuthenticatedOperationalProofV2 =
        serde_json::from_slice(&encoded).map_err(|_| {
            StorageError::InvalidOperationalProof(
                "legacy or malformed operational proof is nonqualifying".to_owned(),
            )
        })?;
    if envelope.storage_schema_version != 2 {
        return Err(StorageError::InvalidOperationalProof(
            "operational-proof authentication envelope version is unsupported".to_owned(),
        ));
    }
    let proof_bytes = serde_json::to_vec_pretty(&envelope.payload)?;
    if hex::encode(Sha256::digest(&proof_bytes)) != filename_digest {
        return Err(StorageError::InvalidOperationalProof(
            "proof-index filename does not match the exact public proof bytes".to_owned(),
        ));
    }
    let expected_root = store.require_evidence_root_identity()?;
    if envelope.state_root_identity != expected_root {
        return Err(StorageError::InvalidOperationalProof(
            "operational proof is bound to a different state root".to_owned(),
        ));
    }
    store
        .require_evidence_authenticator()?
        .verify(
            &expected_root,
            PROOF_MAC_DOMAIN,
            &proof_bytes,
            &envelope.authentication,
        )
        .map_err(authentication_error)?;
    validate_operational_proof(&envelope.payload, false)?;
    validate_operational_evidence(store, &envelope.payload)?;
    Ok(envelope)
}

fn strict_managed_entry_name(name: std::ffi::OsString, directory: &Path) -> Result<String> {
    name.into_string().map_err(|_| {
        unsafe_managed_document(
            directory,
            "retirement cannot classify a managed entry whose name is not valid UTF-8",
        )
    })
}

fn content_hash_from_managed_name(
    name: &str,
    directory: &Path,
    kind: &'static str,
) -> Result<String> {
    let path = Path::new(name);
    if path.extension().and_then(std::ffi::OsStr::to_str) != Some("json")
        || path.file_name().and_then(std::ffi::OsStr::to_str) != Some(name)
    {
        return Err(unsafe_managed_document(
            &directory.join(name),
            "retirement requires every managed authentication record to have one canonical JSON filename",
        ));
    }
    let stem = path
        .file_stem()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| {
            unsafe_managed_document(
                &directory.join(name),
                "managed authentication-record filename is not valid UTF-8",
            )
        })?;
    canonical_digest(&format!("sha256:{stem}"), kind)?;
    Ok(format!("sha256:{stem}"))
}

fn authentication_error(error: cfctl_auth::AuthError) -> StorageError {
    StorageError::EvidenceAuthentication(error.to_string())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod durability_reconciliation_tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use cap_std::{ambient_authority, fs::Dir};
    use cfctl_auth::{EvidenceKeyManager, MemorySecretStore, SecretBackend};
    use tempfile::tempdir;

    use super::atomic_create_capability_file_with_hooks;
    use super::*;

    #[test]
    fn windows_identity_requires_complete_stable_incarnation() {
        assert!(stable_windows_identity_matches(
            (Some(1), Some(2), 3),
            (Some(1), Some(2), 3)
        ));
        for changed in [
            (Some(1), Some(4), 3),
            (None, Some(2), 3),
            (Some(1), Some(2), 0),
        ] {
            assert!(!stable_windows_identity_matches(
                (Some(1), Some(2), 3),
                changed
            ));
        }
        assert!(!stable_windows_identity_matches(
            (None, Some(2), 3),
            (None, Some(2), 3)
        ));
        assert!(!stable_windows_identity_matches(
            (Some(1), Some(2), 0),
            (Some(1), Some(2), 0)
        ));
    }

    #[test]
    fn location_identity_binds_directory_incarnations() {
        let identity = |data: &[u8], index: &[u8]| {
            evidence_location_identity("/state", data, b"descriptor", b"body", index, b"lock")
        };
        let original = identity(b"data-birth-1", b"index-birth-1");
        assert_ne!(original, identity(b"data-birth-2", b"index-birth-1"));
        assert_ne!(original, identity(b"data-birth-1", b"index-birth-2"));
    }

    fn authenticated_descriptor_test_store(root: &Path) -> StateStore {
        let store = StateStore::open(RuntimePaths::from_root(root)).expect("storage opens");
        let manager = Arc::new(
            EvidenceKeyManager::new(
                Arc::new(MemorySecretStore::default()),
                store.evidence_location_identity(),
                SecretBackend::Memory,
            )
            .expect("test evidence authority"),
        );
        let state_root_identity = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(b"descriptor-race-test-root"))
        );
        manager
            .initialize(&state_root_identity)
            .expect("test evidence key initializes");
        store
            .initialize_evidence_root_identity(&state_root_identity)
            .expect("test root marker initializes");
        store
            .with_evidence_authenticator(manager)
            .expect("authenticated store opens")
    }

    #[test]
    fn descriptor_race_reconciles_authenticated_identity_before_directory_sync() {
        let root = tempdir().expect("temporary directory");
        let store = authenticated_descriptor_test_store(root.path());
        let winner = store
            .write_evidence(EvidenceClass::SourceConfig, &json!({"source": "fixture"}))
            .expect("authenticated descriptor seeds");
        let descriptor_path = evidence_descriptor_path(&store.paths, &winner.content_hash[7..]);
        let mut proposed = winner.clone();
        proposed.generated_at += chrono::Duration::nanoseconds(1);
        assert_ne!(
            proposed, winner,
            "the racing writer must have a distinct identity"
        );
        let already_exists = || -> Result<()> {
            Err(io_error(
                &descriptor_path,
                std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "injected concurrent descriptor publication",
                ),
            ))
        };

        let ordinary_sync_called = AtomicBool::new(false);
        let ordinary = reconcile_evidence_descriptor_publication_with_sync(
            &store,
            Ok(()),
            proposed.clone(),
            &descriptor_path,
            |_| {
                ordinary_sync_called.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .expect("ordinary creation returns its proposed identity");
        assert_eq!(ordinary, proposed);
        assert!(!ordinary_sync_called.load(Ordering::SeqCst));

        let successful_sync_called = AtomicBool::new(false);
        let reconciled = reconcile_evidence_descriptor_publication_with_sync(
            &store,
            already_exists(),
            proposed.clone(),
            &descriptor_path,
            |_| {
                successful_sync_called.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .expect("raced descriptor returns the authenticated winner after sync");
        assert!(successful_sync_called.load(Ordering::SeqCst));
        assert_eq!(reconciled, winner);
        assert_ne!(reconciled, proposed);

        let validation_before_failed_sync = AtomicBool::new(false);
        let failed_sync = reconcile_evidence_descriptor_publication_with_sync(
            &store,
            already_exists(),
            proposed.clone(),
            &descriptor_path,
            |_| {
                validation_before_failed_sync.store(true, Ordering::SeqCst);
                Err(std::io::Error::other(
                    "injected descriptor directory sync failure",
                ))
            },
        )
        .expect_err("failed descriptor directory sync remains indeterminate");
        assert!(validation_before_failed_sync.load(Ordering::SeqCst));
        assert!(matches!(
            failed_sync,
            StorageError::WriteDurabilityUnknown { .. }
        ));

        let mismatch_sync_called = AtomicBool::new(false);
        let mut mismatched = proposed;
        mismatched.class = EvidenceClass::Apply;
        let mismatch = reconcile_evidence_descriptor_publication_with_sync(
            &store,
            already_exists(),
            mismatched,
            &descriptor_path,
            |_| {
                mismatch_sync_called.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .expect_err("mismatched raced descriptor fails before sync");
        assert!(matches!(
            mismatch,
            StorageError::UnsafeManagedDocument { .. }
        ));
        assert!(!mismatch_sync_called.load(Ordering::SeqCst));
    }

    #[test]
    fn crossed_publication_retry_requires_successful_held_directory_sync() {
        let root = tempdir().expect("temporary directory");
        let directory = Dir::open_ambient_dir(root.path(), ambient_authority())
            .expect("open capability directory");
        let name = "immutable.json";
        let display_path = root.path().join(name);
        let expected = br#"{"schema_version":1}"#;
        let digest = hex::encode(Sha256::digest(expected));

        let crossed = atomic_create_capability_file_with_hooks(
            &directory,
            name,
            expected,
            &display_path,
            |_| Ok(()),
            |directory, temporary| directory.remove_file(temporary),
            |_| Err(std::io::Error::other("injected publication sync failure")),
        )
        .expect_err("crossed publication is durability-indeterminate");
        assert!(matches!(
            crossed,
            StorageError::WriteDurabilityUnknown { .. }
        ));
        assert_eq!(
            read_hashed_capability_file(&directory, name, &display_path, &digest)
                .expect("published exact entry remains visible"),
            expected
        );

        let failed_sync_called = Arc::new(AtomicBool::new(false));
        let failed_sync_observer = Arc::clone(&failed_sync_called);
        let retry = confirm_exact_existing_immutable_with_sync(
            &directory,
            &display_path,
            || {
                let stored = read_hashed_capability_file(&directory, name, &display_path, &digest)?;
                (stored == expected)
                    .then_some(())
                    .ok_or_else(|| unsafe_managed_document(&display_path, "exact bytes changed"))
            },
            move |_| {
                failed_sync_observer.store(true, Ordering::SeqCst);
                Err(std::io::Error::other("injected retry sync failure"))
            },
        )
        .expect_err("visible exact entry alone does not prove durability");
        assert!(failed_sync_called.load(Ordering::SeqCst));
        assert!(matches!(retry, StorageError::WriteDurabilityUnknown { .. }));

        let successful_sync_called = Arc::new(AtomicBool::new(false));
        let successful_sync_observer = Arc::clone(&successful_sync_called);
        confirm_exact_existing_immutable_with_sync(
            &directory,
            &display_path,
            || {
                let stored = read_hashed_capability_file(&directory, name, &display_path, &digest)?;
                (stored == expected)
                    .then_some(())
                    .ok_or_else(|| unsafe_managed_document(&display_path, "exact bytes changed"))
            },
            move |_| {
                successful_sync_observer.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .expect("exact entry qualifies only after retry sync succeeds");
        assert!(successful_sync_called.load(Ordering::SeqCst));
    }

    #[test]
    fn body_and_proof_cleanup_failures_never_enter_existing_reconciliation() {
        let root = tempdir().expect("temporary directory");
        let directory = Dir::open_ambient_dir(root.path(), ambient_authority())
            .expect("open capability directory");

        for relative_path in ["evidence/body.json", "evidence-index/proof.json"] {
            let display_path = root.path().join(relative_path);
            let validation_called = AtomicBool::new(false);
            let error = reconcile_immutable_publication(
                Err(StorageError::CapabilityPublicationCleanupFailed {
                    path: display_path.display().to_string(),
                    temporary_name: ".residual.tmp-test".to_owned(),
                    directory_durability: "confirmed with the pre-existing final entry".to_owned(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "injected cleanup failure",
                    ),
                }),
                &directory,
                &display_path,
                || {
                    validation_called.store(true, Ordering::SeqCst);
                    Ok(())
                },
            )
            .expect_err("cleanup failure is not exact-existing reconciliation");
            assert!(matches!(
                error,
                StorageError::CapabilityPublicationCleanupFailed { .. }
            ));
            assert!(!validation_called.load(Ordering::SeqCst));
        }
    }

    #[test]
    fn existing_immutable_mismatch_rejects_before_directory_sync() {
        let root = tempdir().expect("temporary directory");
        let directory = Dir::open_ambient_dir(root.path(), ambient_authority())
            .expect("open capability directory");
        let display_path = root.path().join("immutable.json");
        let sync_called = AtomicBool::new(false);

        let byte_mismatch = confirm_exact_existing_immutable_with_sync(
            &directory,
            &display_path,
            || {
                Err::<(), _>(unsafe_managed_document(
                    &display_path,
                    "existing immutable document differs from expected bytes",
                ))
            },
            |_| {
                sync_called.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .expect_err("byte mismatch must fail closed");
        assert!(matches!(
            byte_mismatch,
            StorageError::UnsafeManagedDocument { .. }
        ));
        assert!(!sync_called.load(Ordering::SeqCst));

        let authentication_mismatch = confirm_exact_existing_immutable_with_sync(
            &directory,
            &display_path,
            || {
                Err::<(), _>(StorageError::InvalidOperationalProof(
                    "authentication mismatch".to_owned(),
                ))
            },
            |_| {
                sync_called.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .expect_err("authentication mismatch must fail closed");
        assert!(matches!(
            authentication_mismatch,
            StorageError::InvalidOperationalProof(_)
        ));
        assert!(!sync_called.load(Ordering::SeqCst));
    }
}
