//! One complete, authenticated history walk for retirement and private recovery.
use super::{
    Deserialize, Digest, EvidenceLifecycleLock, Result, Serialize, Sha256, StateStore,
    content_hash_from_managed_name, io_error, read_authenticated_operational_proof_index,
    strict_managed_entry_name,
};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthenticatedHistoryV1 {
    pub descriptor_count: usize,
    pub proof_count: usize,
    pub generation_usage: BTreeMap<String, usize>,
    /// Commits to sorted canonical envelopes. Descriptor verification also hashes
    /// every referenced body; body-only audit artifacts are never promoted.
    pub inventory_sha256: String,
}

impl StateStore {
    pub(crate) fn authenticated_history(
        &self,
        _lifecycle: &EvidenceLifecycleLock,
    ) -> Result<AuthenticatedHistoryV1> {
        let mut result = AuthenticatedHistoryV1 {
            descriptor_count: 0,
            proof_count: 0,
            generation_usage: BTreeMap::new(),
            inventory_sha256: String::new(),
        };
        let mut inventory = BTreeMap::new();
        let descriptors = self.paths.data_dir.join("evidence-descriptors");
        for entry in self
            .evidence_directories
            .descriptors
            .entries()
            .map_err(|source| io_error(&descriptors, source))?
        {
            let entry = entry.map_err(|source| io_error(&descriptors, source))?;
            let name = strict_managed_entry_name(entry.file_name(), &descriptors)?;
            let content_hash =
                content_hash_from_managed_name(&name, &descriptors, "evidence descriptor")?;
            let envelope = self.load_authenticated_evidence_descriptor(&content_hash)?;
            *result
                .generation_usage
                .entry(envelope.authentication.key_generation_id.clone())
                .or_default() += 1;
            inventory.insert(format!("descriptor:{name}"), serde_json::to_vec(&envelope)?);
            result.descriptor_count += 1;
        }
        let proofs = self.paths.data_dir.join("evidence-index");
        for entry in self
            .evidence_directories
            .proofs
            .entries()
            .map_err(|source| io_error(&proofs, source))?
        {
            let entry = entry.map_err(|source| io_error(&proofs, source))?;
            let name = strict_managed_entry_name(entry.file_name(), &proofs)?;
            content_hash_from_managed_name(&name, &proofs, "operational proof")?;
            let envelope = read_authenticated_operational_proof_index(self, &name)?;
            *result
                .generation_usage
                .entry(envelope.authentication.key_generation_id.clone())
                .or_default() += 1;
            inventory.insert(format!("proof:{name}"), serde_json::to_vec(&envelope)?);
            result.proof_count += 1;
        }
        result.inventory_sha256 = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(serde_json::to_vec(&inventory)?))
        );
        Ok(result)
    }
}
