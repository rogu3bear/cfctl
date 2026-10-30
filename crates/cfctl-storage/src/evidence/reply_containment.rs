use super::super::{Result, StateStore, StorageError};
use cfctl_core::reply_lifecycle::containment::evidence::{
    NativeContainmentReadV3, NativeReadPhaseV3,
};
use cfctl_core::{EvidenceClass, EvidenceV1};
use serde_json::Value;

pub(super) fn known_origin(value: &Value) -> bool {
    [NativeReadPhaseV3::PreRead, NativeReadPhaseV3::Readback]
        .iter()
        .any(|phase| &phase.origin() == value)
}

impl StateStore {
    /// Only the native containment read boundary stamps this fixed origin.
    /// Generic/imported evidence with identical bytes cannot be relabeled.
    pub fn write_reply_containment_read(
        &self,
        read: &NativeContainmentReadV3,
    ) -> Result<EvidenceV1> {
        let evidence = self.write_evidence_with_origin(
            EvidenceClass::LiveRead,
            read.body(),
            read.phase().origin(),
        )?;
        let expected = read
            .storage_content_hash()
            .map_err(|error| StorageError::EvidenceAuthentication(error.to_string()))?;
        if evidence.content_hash != expected {
            return Err(StorageError::EvidenceAuthentication(
                "native containment evidence serialization changed".into(),
            ));
        }
        Ok(evidence)
    }

    /// Authenticates both descriptor and exact body before checking the native
    /// phase. A matching body digest alone never proves producer provenance.
    pub fn load_reply_containment_read(
        &self,
        content_hash: &str,
        phase: NativeReadPhaseV3,
    ) -> Result<NativeContainmentReadV3> {
        let (evidence, value) = self.load_evidence_value(content_hash)?;
        if evidence.class != EvidenceClass::LiveRead || evidence.metadata != phase.origin() {
            return Err(StorageError::EvidenceAuthentication(
                "containment read lacks the exact native phase origin".into(),
            ));
        }
        let read = NativeContainmentReadV3::from_value(value)
            .map_err(|error| StorageError::EvidenceAuthentication(error.to_string()))?;
        if read.phase() != phase
            || read
                .storage_content_hash()
                .map_err(|error| StorageError::EvidenceAuthentication(error.to_string()))?
                != content_hash
        {
            return Err(StorageError::EvidenceAuthentication(
                "containment native read identity changed".into(),
            ));
        }
        Ok(read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RuntimePaths;
    use cfctl_auth::{EvidenceKeyManager, MemorySecretStore, SecretBackend};
    use std::sync::Arc;

    fn store(root: &std::path::Path) -> Result<StateStore> {
        let store = StateStore::open(RuntimePaths::from_root(root))?;
        let manager = Arc::new(
            EvidenceKeyManager::new(
                Arc::new(MemorySecretStore::default()),
                store.evidence_location_identity(),
                SecretBackend::Memory,
            )
            .map_err(|error| StorageError::EvidenceAuthentication(error.to_string()))?,
        );
        let identity = format!("sha256:{}", "9".repeat(64));
        manager
            .initialize(&identity)
            .map_err(|error| StorageError::EvidenceAuthentication(error.to_string()))?;
        store.initialize_evidence_root_identity(&identity)?;
        store.with_evidence_authenticator(manager)
    }

    fn read() -> std::result::Result<NativeContainmentReadV3, Box<dyn std::error::Error>> {
        let value: Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../cfctl-core/src/reply_lifecycle/containment/tests/fixtures/pre_send_rollback.json"
        )))?;
        let envelope: cfctl_core::ResultEnvelopeV2 =
            serde_json::from_value(value["pre_read"].clone())?;
        Ok(NativeContainmentReadV3::new(&envelope)?)
    }

    #[test]
    fn native_round_trip_is_phase_and_exact_serialization_bound()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let store = store(root.path())?;
        let read = read()?;
        let evidence = store.write_reply_containment_read(&read)?;
        assert_eq!(evidence.content_hash, read.storage_content_hash()?);
        let loaded = store
            .load_reply_containment_read(&evidence.content_hash, NativeReadPhaseV3::PreRead)?;
        assert_eq!(loaded.body(), read.body());
        assert!(
            store
                .load_reply_containment_read(&evidence.content_hash, NativeReadPhaseV3::Readback)
                .is_err()
        );
        assert!(
            store
                .write_evidence(EvidenceClass::LiveRead, read.body())
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn imported_equal_bytes_cannot_become_native_provenance()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let store = store(root.path())?;
        let read = read()?;
        let evidence = store.write_evidence(EvidenceClass::LiveRead, read.body())?;
        assert!(
            store
                .load_reply_containment_read(&evidence.content_hash, NativeReadPhaseV3::PreRead)
                .is_err()
        );
        assert!(store.write_reply_containment_read(&read).is_err());
        Ok(())
    }
}
