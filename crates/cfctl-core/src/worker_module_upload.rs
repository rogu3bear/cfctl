//! The generic Worker module endpoint has no governed multipart transport.
//!
//! JSON request construction cannot carry a frozen multipart artifact, and the
//! settings GET does not expose the uploaded module identity. Keep this exact
//! operation closed even when an older catalog supplies complete metadata.

pub const ID: &str = "worker-script-upload-worker-module";
pub const BLOCKING_GAP: &str = "Worker module upload requires a governed multipart source, transport, and module/settings readback contract; generic JSON execution is unsupported";

#[cfg(test)]
mod tests {
    use super::{BLOCKING_GAP, ID};
    use crate::{CapabilityV1, EffectClass, RiskClass};

    #[test]
    fn complete_legacy_metadata_cannot_admit_missing_multipart_transport() {
        let mut cap = CapabilityV1::new(
            ID,
            "Upload Worker Module",
            "PUT",
            "/accounts/{account_id}/workers/scripts/{script_name}",
        );
        cap.risk = RiskClass::CrossConfig;
        cap.effect = EffectClass::ReversibleWrite;
        cap.cost.known = true;
        cap.cost.incremental = false;
        cap.verification.required = true;
        cap.verification.strategy = "worker_script_settings_id_matches_upload_response".into();
        cap.rollback.warning = Some("separate reviewed version rollback".into());
        assert!(
            cap.mutation_contract_gaps()
                .iter()
                .any(|gap| gap == BLOCKING_GAP)
        );
        assert!(!cap.verification_contract_supported());
    }
}
