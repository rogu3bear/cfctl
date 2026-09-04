use thiserror::Error;

/// Stable public dispositions for evidence-authority adoption.
///
/// These variants are deliberately independent of any future installed-identity
/// receipt representation. Until that authenticated contract exists, the
/// consequential adoption entry points fail closed with
/// [`Self::InstalledIdentityReceiptRequired`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EvidenceKeyAdoptionError {
    #[error("an authenticated independently reviewed installed-identity receipt is required")]
    InstalledIdentityReceiptRequired,
    #[error("adoption plan `{plan_id}` expired before its protected crossing")]
    PlanExpired { plan_id: String },
    #[error("adoption plan `{plan_id}` does not match the current runtime identity")]
    RuntimeIdentityConflict { plan_id: String },
    #[error("adoption plan `{plan_id}` has an incomplete marker crossing")]
    CrossingIncomplete { plan_id: String },
    #[error("adoption plan `{plan_id}` lost a response before a protected effect was proven")]
    ResponseLossUnchanged { plan_id: String },
    #[error("adoption plan `{plan_id}` must be reconciled forward using that same plan")]
    SamePlanReconciliationRequired { plan_id: String },
}
