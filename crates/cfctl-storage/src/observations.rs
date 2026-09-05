//! Explicit nonqualifying observations for an already-admitted operation.
use super::{Result, StateStore};
use cfctl_core::{AttestationStateV1, AttestationStatusV1, EvidenceClass, EvidenceV1};
use serde_json::{Value, json};

impl StateStore {
    /// Selects observation persistence only. This does not change strict evidence
    /// writes, authenticated reads, authority admission, or proof qualification.
    #[must_use]
    pub fn with_observation_attestation(&self, attestation: &AttestationStatusV1) -> Self {
        let mut scoped = self.clone();
        scoped.observation_attestation = Some(attestation.clone());
        scoped
    }

    /// Callers use this only for observed state, never a grant or proof. With a
    /// healthy admission it remains the authenticated writer. An explicit
    /// unattested admission uses the historical audit lane and creates no MAC,
    /// descriptor, or qualifying proof. Storage failures are never swallowed.
    pub fn write_observation_evidence(
        &self,
        class: EvidenceClass,
        value: &Value,
    ) -> Result<EvidenceV1> {
        if let Some(attestation) = &self.observation_attestation
            && attestation.state == AttestationStateV1::UnattestedReversibleEffect
            && matches!(
                class,
                EvidenceClass::LiveRead
                    | EvidenceClass::Preview
                    | EvidenceClass::Apply
                    | EvidenceClass::PostChangeVerification
            )
        {
            let mut evidence = self.write_audit_evidence(class, value)?;
            evidence.metadata = json!({"qualifying":false, "attestation":attestation});
            return Ok(evidence);
        }
        self.write_evidence(class, value)
    }
}
